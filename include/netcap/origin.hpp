// netcap - choosing which address of a multi-homed origin to talk to.
//
// A CDN host name usually resolves to several addresses, and their round trip
// times differ by a lot (different edge nodes, different routes, one of them
// being rate limited).  `getaddrinfo()` returns them in an order that has
// nothing to do with which one is closest to *this* machine, and a proxy that
// walks the list in order therefore picks its upstream latency by luck.
//
// What this module adds:
//   * `origin_resolve()` - every address the resolver knows about, both
//     families, de-duplicated, in resolver order.
//   * `OriginPicker` - remembers how long each address took, so the winner is
//     dialled first next time, and re-measures when that memory is stale or the
//     winner stops answering.  Connecting to several addresses at once (Happy
//     Eyeballs style, staggered) is what produces the first measurement.
//
// The picker itself never touches a socket: it is a pure function of
// (candidate state, now), which is what lets the self-test drive it with a fake
// clock and the proxy feed it real connects.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

struct OriginAddress {
  int family = 0;          // AF_INET / AF_INET6
  std::string text;        // "93.184.216.34" or "2606:2800:220:1:248:1893:25c8:1946"
  std::vector<u8> bytes;   // network order, as the socket wants it
  std::uint16_t port = 0;
};

// Resolves every address of `host` (both families, de-duplicated).  False plus
// `error` when the name cannot be resolved at all.
bool origin_resolve(const std::string& host, std::uint16_t port,
                    std::vector<OriginAddress>* out, std::string* error);

// How many addresses a single host is allowed to contribute.  A host name with
// hundreds of A records (or a hostile resolver) must not turn one connection
// into hundreds.
std::size_t origin_max_addresses();

// Fills `storage` (a sockaddr_storage, passed as void* so this header does not
// have to drag in the socket headers) with a sockaddr for `address`, and stores
// its length in `*length`.  False when the address family is not one we know.
bool origin_sockaddr(const OriginAddress& address, void* storage, std::size_t* length);

// "ipv4" / "ipv6" / "?", for logs.
std::string origin_family_name(int family);

// A readable name for a `getaddrinfo()` failure code.  Windows hands back an
// empty string from `gai_strerrorA()` for several of the codes that matter
// (WSAHOST_NOT_FOUND, WSANO_DATA), which is what used to turn a real resolver
// failure into an empty pair of parentheses in the log.  This never returns "".
std::string origin_gai_text(int gai);

// True when this machine has a usable global IPv6 address on an interface that is
// up; link-local, loopback and deprecated addresses do not count.  A name whose
// only record is AAAA cannot be reached without one, so callers use this to say
// why a connection failed instead of reporting a flat "unreachable".
bool machine_has_ipv6();
struct OriginCandidate {
  std::string address;
  i64 rtt_us = -1;         // -1 = never measured
  i64 measured_us = 0;     // when that rtt was taken
  int failures = 0;        // consecutive failed connects
  i64 dead_until_us = 0;   // do not try before this (set after a failure)
};

enum class OriginPolicy : std::uint8_t {
  First = 0,  // dial the first address the resolver returned (the old behaviour)
  Best,       // remember the fastest address and dial that first
};

const char* origin_policy_name(OriginPolicy policy);
// Accepts "first" / "best" (case-insensitive, also "1"/"0").  False keeps `out`.
bool origin_policy_parse(const std::string& text, OriginPolicy* out);

class OriginPicker {
 public:
  OriginPicker();
  OriginPicker(OriginPolicy policy, std::size_t max_race, i64 stagger_us, i64 ttl_us,
               i64 max_backoff_us);

  void set_addresses(const std::vector<std::string>& addresses);
  bool empty() const { return candidates_.empty(); }
  std::size_t size() const { return candidates_.size(); }
  OriginPolicy policy() const { return policy_; }
  std::size_t max_race() const { return max_race_; }
  i64 ttl_us() const { return ttl_us_; }
  const std::vector<OriginCandidate>& candidates() const { return candidates_; }

  // Addresses to try, best first: measured ones by round trip time, then the
  // ones never measured (resolver order), then the ones in backoff.
  std::vector<std::string> order(i64 now_us) const;
  // The fastest address we know of, or "" when nothing has been measured.
  std::string best(i64 now_us) const;
  // True when the winner is too old to be trusted (or nothing was measured),
  // which is when a connection should measure again instead of dialling blind.
  bool stale(i64 now_us) const;

  // Racing: `begin_race()` forgets the previous race, `next_batch()` returns the
  // addresses to start right now and how long to wait before asking again
  // (wait_us = 0 means "ask again immediately", a negative value means "nothing
  // left to start"), `report()` feeds back what happened.  The first batch of a
  // race comes back in one go up to `max_race()` addresses: they share a starting
  // line, so whoever finishes first is the fastest one.  Later batches follow one
  // at a time, `stagger_us` apart.
  void begin_race();
  std::vector<std::string> next_batch(i64 now_us, i64* wait_us);
  void report(const std::string& address, bool ok, i64 rtt_us, i64 now_us);
  std::size_t in_flight() const { return in_flight_.size(); }

  std::string describe() const;

 private:
  OriginCandidate* find(const std::string& address);
  const OriginCandidate* find(const std::string& address) const;

  OriginPolicy policy_ = OriginPolicy::Best;
  std::size_t max_race_ = 2;
  i64 stagger_us_ = 250 * 1000;
  i64 ttl_us_ = 300 * 1000 * 1000;
  i64 max_backoff_us_ = 60 * 1000 * 1000;
  std::vector<OriginCandidate> candidates_;
  std::vector<std::string> in_flight_;
  std::vector<std::string> attempted_;  // started during the current race
  i64 last_start_us_ = 0;
  bool started_ = false;  // a start happened during this race (the clock may be 0)
};

}  // namespace netcap
