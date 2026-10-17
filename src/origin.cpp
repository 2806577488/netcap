#include "netcap/origin.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

namespace netcap {
namespace {

bool contains_address(const std::vector<OriginAddress>& list, const std::string& text) {
  for (const OriginAddress& address : list) {
    if (address.text == text) return true;
  }
  return false;
}

// Every module that touches sockets has to make sure Winsock is up: the CLI
// starts the proxy, the DNS sink and the TUN relay in different orders, and a
// resolver call that happens first would otherwise fail with WSANOTINITIALISED.
void ensure_winsock() {
#if defined(_WIN32)
  static const bool started = []() {
    WSADATA data;
    return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  (void)started;
#endif
}

std::string address_text(const sockaddr* sa) {
  char buffer[INET6_ADDRSTRLEN + 1] = {0};
  if (sa->sa_family == AF_INET) {
    const sockaddr_in* in = reinterpret_cast<const sockaddr_in*>(sa);
    if (::inet_ntop(AF_INET, &in->sin_addr, buffer, sizeof(buffer) - 1) == nullptr) return {};
    return std::string(buffer);
  }
  if (sa->sa_family == AF_INET6) {
    const sockaddr_in6* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
    if (::inet_ntop(AF_INET6, &in6->sin6_addr, buffer, sizeof(buffer) - 1) == nullptr) return {};
    return std::string(buffer);
  }
  return {};
}

std::vector<u8> address_bytes(const sockaddr* sa) {
  std::vector<u8> out;
  if (sa->sa_family == AF_INET) {
    const sockaddr_in* in = reinterpret_cast<const sockaddr_in*>(sa);
    const u8* raw = reinterpret_cast<const u8*>(&in->sin_addr);
    out.assign(raw, raw + 4);
  } else if (sa->sa_family == AF_INET6) {
    const sockaddr_in6* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
    const u8* raw = reinterpret_cast<const u8*>(&in6->sin6_addr);
    out.assign(raw, raw + 16);
  }
  return out;
}

bool contains(const std::vector<std::string>& list, const std::string& text) {
  return std::find(list.begin(), list.end(), text) != list.end();
}

void erase(std::vector<std::string>* list, const std::string& text) {
  list->erase(std::remove(list->begin(), list->end(), text), list->end());
}

std::string millis(i64 micros) {
  if (micros < 0) return "-";
  char buffer[48];
  std::snprintf(buffer, sizeof(buffer), "%.2f ms", static_cast<double>(micros) / 1000.0);
  return std::string(buffer);
}

}  // namespace

std::size_t origin_max_addresses() { return 16; }

bool origin_sockaddr(const OriginAddress& address, void* storage, std::size_t* length) {
  if (storage == nullptr || length == nullptr) return false;
  if (address.family == AF_INET && address.bytes.size() == 4) {
    sockaddr_in in;
    std::memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(address.port);
    std::memcpy(&in.sin_addr, address.bytes.data(), 4);
    std::memcpy(storage, &in, sizeof(in));
    *length = sizeof(in);
    return true;
  }
  if (address.family == AF_INET6 && address.bytes.size() == 16) {
    sockaddr_in6 in6;
    std::memset(&in6, 0, sizeof(in6));
    in6.sin6_family = AF_INET6;
    in6.sin6_port = htons(address.port);
    std::memcpy(&in6.sin6_addr, address.bytes.data(), 16);
    std::memcpy(storage, &in6, sizeof(in6));
    *length = sizeof(in6);
    return true;
  }
  return false;
}

std::string origin_gai_text(int gai) {
  if (gai == 0) return "no address";
#if defined(_WIN32)
  // Windows answers an empty string from gai_strerrorA() for exactly the codes
  // that turn up here, which is how a real resolver failure became "()" in the
  // log.  Spelled as numbers, with the names in comments, so it does not depend
  // on which of the EAI_*/WSA* spellings this SDK happens to define.
  switch (gai) {
    case 11001:  // WSAHOST_NOT_FOUND / EAI_NONAME
      return "the name has no address record (WSAHOST_NOT_FOUND)";
    case 11002:  // WSATRY_AGAIN / EAI_AGAIN
      return "the resolver is temporarily unavailable (WSATRY_AGAIN)";
    case 11003:  // WSANO_RECOVERY / EAI_FAIL
      return "the resolver failed unrecoverably (WSANO_RECOVERY)";
    case 11004:  // WSANO_DATA / EAI_NODATA
      return "the name exists but has no record of the requested type (WSANO_DATA), "
             "which is what an IPv6-only name looks like where IPv6 cannot be used";
    default:
      break;
  }
#else
  const char* text = gai_strerror(gai);
  if (text != nullptr && *text != '\0') return text;
#endif
  return "resolver error " + std::to_string(gai);
}

bool machine_has_ipv6() {
#if defined(_WIN32)
  ensure_winsock();
  constexpr unsigned long kSoftwareLoopback = 24;  // IF_TYPE_SOFTWARE_LOOPBACK
  constexpr unsigned long kUp = 1;                 // IfOperStatusUp
  constexpr unsigned long kDadDeprecated = 3;      // IpDadStateDeprecated
  const ULONG flags =
      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG size = 16 * 1024;
  std::vector<u8> buf;
  ULONG rc = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 6; ++attempt) {
    buf.assign(size, 0);
    rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                              reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    if (rc != ERROR_BUFFER_OVERFLOW) break;
  }
  // An API failure is not evidence that IPv6 is missing: answer "yes" and leave
  // the caller's behaviour exactly as it was.
  if (rc != NO_ERROR) return true;
  for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a;
       a = a->Next) {
    if (a->OperStatus != kUp || a->IfType == kSoftwareLoopback) continue;
    for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u; u = u->Next) {
      if (u->Address.lpSockaddr == nullptr) continue;
      if (u->Address.lpSockaddr->sa_family != AF_INET6) continue;
      const sockaddr_in6* in6 = reinterpret_cast<const sockaddr_in6*>(u->Address.lpSockaddr);
      if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) continue;
      if (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) continue;
      if (IN6_IS_ADDR_SITELOCAL(&in6->sin6_addr)) continue;
      if (u->DadState == kDadDeprecated) continue;  // fe80::%... on a dead link
      return true;
    }
  }
  return false;
#else
  // Everywhere else the socket layer can try, and a failure is reported honestly
  // by the connect itself.
  return true;
#endif
}

bool origin_resolve(const std::string& host, std::uint16_t port,
                    std::vector<OriginAddress>* out, std::string* error) {
  if (out == nullptr) return false;
  out->clear();
  if (host.empty()) {
    if (error != nullptr) *error = "no host to resolve";
    return false;
  }
  ensure_winsock();
  addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* list = nullptr;
  const std::string service = std::to_string(static_cast<unsigned>(port));
  const int gai = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &list);
  if (gai != 0 || list == nullptr) {
    std::string detail = gai != 0 ? origin_gai_text(gai) : std::string("no address");
    if (!machine_has_ipv6()) {
      // AAAA-only names (the Windows IPv6 connectivity probe is one) fail here on
      // a machine with no usable IPv6.  Saying so is the difference between
      // "netcap broke it" and "this machine cannot reach it".
      detail += "; this machine has no usable IPv6 address";
    }
    if (error != nullptr) *error = "cannot resolve " + host + " (" + detail + ")";
    if (list != nullptr) ::freeaddrinfo(list);
    return false;
  }
  for (addrinfo* it = list; it != nullptr; it = it->ai_next) {
    if (out->size() >= origin_max_addresses()) break;
    if (it->ai_addr == nullptr) continue;
    if (it->ai_family != AF_INET && it->ai_family != AF_INET6) continue;
    OriginAddress address;
    address.family = it->ai_family;
    address.text = address_text(it->ai_addr);
    if (address.text.empty()) continue;
    address.bytes = address_bytes(it->ai_addr);
    address.port = port;
    if (contains_address(*out, address.text)) continue;
    out->push_back(std::move(address));
  }
  ::freeaddrinfo(list);
  if (out->empty()) {
    if (error != nullptr) *error = "no usable address for " + host;
    return false;
  }
  return true;
}

const char* origin_policy_name(OriginPolicy policy) {
  return policy == OriginPolicy::First ? "first" : "best";
}

bool origin_policy_parse(const std::string& text, OriginPolicy* out) {
  if (out == nullptr) return false;
  std::string lower;
  lower.reserve(text.size());
  for (char ch : text) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  if (lower == "first" || lower == "old" || lower == "0") {
    *out = OriginPolicy::First;
    return true;
  }
  if (lower == "best" || lower == "fastest" || lower == "1" || lower == "race") {
    *out = OriginPolicy::Best;
    return true;
  }
  return false;
}

OriginPicker::OriginPicker() = default;

OriginPicker::OriginPicker(OriginPolicy policy, std::size_t max_race, i64 stagger_us, i64 ttl_us,
                           i64 max_backoff_us)
    : policy_(policy),
      max_race_(max_race == 0 ? 1 : max_race),
      stagger_us_(stagger_us <= 0 ? 1 : stagger_us),
      ttl_us_(ttl_us <= 0 ? 1 : ttl_us),
      max_backoff_us_(max_backoff_us <= 0 ? 1 : max_backoff_us) {}

void OriginPicker::set_addresses(const std::vector<std::string>& addresses) {
  std::vector<OriginCandidate> next;
  next.reserve(addresses.size());
  for (const std::string& address : addresses) {
    if (address.empty()) continue;
    OriginCandidate fresh;
    fresh.address = address;
    // Keep what we already learned about this address: re-resolving a host must
    // not throw away the measurement that makes the next connection fast.
    for (const OriginCandidate& old : candidates_) {
      if (old.address == address) {
        fresh = old;
        break;
      }
    }
    bool duplicate = false;
    for (const OriginCandidate& entry : next) {
      if (entry.address == address) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate) next.push_back(std::move(fresh));
  }
  candidates_ = std::move(next);
  in_flight_.clear();
  attempted_.clear();
  last_start_us_ = 0;
  started_ = false;
}

OriginCandidate* OriginPicker::find(const std::string& address) {
  for (OriginCandidate& candidate : candidates_) {
    if (candidate.address == address) return &candidate;
  }
  return nullptr;
}

const OriginCandidate* OriginPicker::find(const std::string& address) const {
  for (const OriginCandidate& candidate : candidates_) {
    if (candidate.address == address) return &candidate;
  }
  return nullptr;
}

std::vector<std::string> OriginPicker::order(i64 now_us) const {
  // rank 0: measured and usable, by round trip time
  // rank 1: never measured, in resolver order
  // rank 2: in backoff after a failure
  std::vector<std::size_t> index;
  index.reserve(candidates_.size());
  for (std::size_t i = 0; i < candidates_.size(); ++i) index.push_back(i);
  const auto rank = [this, now_us](std::size_t i) {
    const OriginCandidate& candidate = candidates_[i];
    if (candidate.dead_until_us > now_us) return 2;
    if (candidate.rtt_us < 0) return 1;
    return 0;
  };
  std::stable_sort(index.begin(), index.end(), [this, &rank](std::size_t a, std::size_t b) {
    const int ra = rank(a);
    const int rb = rank(b);
    if (ra != rb) return ra < rb;
    if (ra == 0 && candidates_[a].rtt_us != candidates_[b].rtt_us) {
      return candidates_[a].rtt_us < candidates_[b].rtt_us;
    }
    return false;  // stable_sort keeps resolver order inside a rank
  });
  std::vector<std::string> out;
  out.reserve(index.size());
  for (std::size_t i : index) out.push_back(candidates_[i].address);
  return out;
}

std::string OriginPicker::best(i64 now_us) const {
  if (candidates_.empty()) return {};
  for (const std::string& address : order(now_us)) {
    const OriginCandidate* candidate = find(address);
    if (candidate != nullptr && candidate->rtt_us >= 0 && candidate->dead_until_us <= now_us) {
      return candidate->address;
    }
  }
  return {};
}

bool OriginPicker::stale(i64 now_us) const {
  const std::string winner = best(now_us);
  if (winner.empty()) return true;
  const OriginCandidate* candidate = find(winner);
  if (candidate == nullptr) return true;
  return now_us - candidate->measured_us > ttl_us_;
}

void OriginPicker::begin_race() {
  in_flight_.clear();
  attempted_.clear();
  last_start_us_ = 0;
  started_ = false;
}

std::vector<std::string> OriginPicker::next_batch(i64 now_us, i64* wait_us) {
  if (wait_us != nullptr) *wait_us = 0;
  if (candidates_.empty()) {
    if (wait_us != nullptr) *wait_us = -1;
    return {};
  }
  if (in_flight_.size() >= max_race_) {
    // The caller is already waiting on more connects than we allow; it should
    // come back as soon as one of them finishes.
    if (wait_us != nullptr) *wait_us = stagger_us_;
    return {};
  }
  if (started_ && now_us - last_start_us_ < stagger_us_) {
    if (wait_us != nullptr) *wait_us = stagger_us_ - (now_us - last_start_us_);
    return {};
  }
  const std::vector<std::string> preference = order(now_us);
  // The first batch of a race starts together: every address in it gets the same
  // starting line, so the one that finishes first really is the fastest one and
  // not merely the one that happened to be dialled first.  Later batches are
  // staggered, which is what keeps one broken address from delaying the others.
  std::vector<std::string> batch;
  const std::size_t room = max_race_ - in_flight_.size();
  const std::size_t want = started_ ? 1 : room;
  // First pass: anything we have not started in this race and that is not in
  // backoff.  Second pass: ignore the backoff, because a host whose every
  // address failed once must still be reachable.
  for (int pass = 0; pass < 2 && batch.size() < want; ++pass) {
    for (const std::string& address : preference) {
      if (batch.size() >= want) break;
      if (contains(attempted_, address)) continue;
      if (contains(in_flight_, address)) continue;
      const OriginCandidate* candidate = find(address);
      if (pass == 0 && candidate != nullptr && candidate->dead_until_us > now_us) continue;
      attempted_.push_back(address);
      in_flight_.push_back(address);
      batch.push_back(address);
    }
  }
  if (batch.empty()) {
    if (wait_us != nullptr) *wait_us = -1;
    return {};
  }
  last_start_us_ = now_us;
  started_ = true;
  return batch;
}

void OriginPicker::report(const std::string& address, bool ok, i64 rtt_us, i64 now_us) {
  erase(&in_flight_, address);
  OriginCandidate* candidate = find(address);
  if (candidate == nullptr) return;
  if (ok) {
    candidate->rtt_us = rtt_us > 0 ? rtt_us : 1;
    candidate->measured_us = now_us;
    candidate->failures = 0;
    candidate->dead_until_us = 0;
    return;
  }
  ++candidate->failures;
  i64 backoff = 1000 * 1000;
  for (int i = 1; i < candidate->failures && backoff < max_backoff_us_; ++i) backoff *= 2;
  candidate->dead_until_us = now_us + std::min(backoff, max_backoff_us_);
}

std::string OriginPicker::describe() const {
  std::size_t measured = 0;
  std::size_t backing_off = 0;
  i64 fastest = -1;
  std::string fastest_address;
  for (const OriginCandidate& candidate : candidates_) {
    if (candidate.rtt_us >= 0) {
      ++measured;
      if (fastest < 0 || candidate.rtt_us < fastest) {
        fastest = candidate.rtt_us;
        fastest_address = candidate.address;
      }
    }
    if (candidate.dead_until_us > 0) ++backing_off;
  }
  std::string text = "pick ";
  text += origin_policy_name(policy_);
  text += " of " + std::to_string(candidates_.size()) + " address(es)";
  text += ", " + std::to_string(measured) + " measured";
  if (fastest >= 0) text += ", fastest " + fastest_address + " " + millis(fastest);
  if (backing_off > 0) text += ", " + std::to_string(backing_off) + " in backoff";
  return text;
}

std::string origin_family_name(int family) {
  if (family == AF_INET) return "ipv4";
  if (family == AF_INET6) return "ipv6";
  return "?";
}

}  // namespace netcap
