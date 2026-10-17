// A tiny DNS sink hole: the second half of the "block it for the whole machine"
// story.  Point the system resolver at this server and every name on the rule
// list is answered with 0.0.0.0 / :: locally, while everything else is forwarded
// to the real upstream resolver unchanged.
//
// The wire helpers are exported because a DNS bug is much easier to find in a
// unit test than through a browser: dns_parse_question() digs the question out
// of a packet, dns_build_sink_answer() writes the reply that makes a name go
// nowhere, and both are exercised by --selftest on their own.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/rules.hpp"

namespace netcap {

// DNS record types are already named by common.hpp (dns_type_name).

struct DnsSinkConfig {
  std::string bind_address = "127.0.0.1";
  u16 port = 53;                 // 53 needs Administrator; 5353 works for testing
  std::string upstream;          // "host:port"; empty means the system resolver
  std::string sink_ipv4 = "0.0.0.0";
  std::string sink_ipv6 = "::";
  u32 ttl = 60;
  int timeout_ms = 1000;
  std::size_t max_queries = 0;   // 0 = no limit (serve_once ignores it anyway)
  bool verbose = false;
};

struct DnsQueryEvent {
  i64 ts_us = 0;
  std::string client;
  std::string name;      // lower case, no trailing dot
  u16 qtype = 0;
  u16 qclass = 0;
  bool blocked = false;
  std::string action;    // "sink" | "forward" | "error" | "malformed"
  std::string detail;
  int rcode = 0;
};

struct DnsSinkStats {
  u64 queries = 0;
  u64 blocked = 0;
  u64 forwarded = 0;
  u64 errors = 0;
  u64 malformed = 0;
  u64 answers_sent = 0;
};

// Digs the first question out of a DNS message.  `*after` receives the offset
// just past the question.  Returns false on anything that is not a well formed
// single-question query.
bool dns_parse_question(const u8* data, std::size_t len, std::string* name, u16* qtype,
                        u16* qclass, std::size_t* after);

// Builds the reply that sends a name nowhere: the original question is echoed
// back with QR=1 and either an A/AAAA record pointing at the sink address or,
// for other record types, an empty NOERROR answer.
std::size_t dns_build_sink_answer(const u8* query, std::size_t len, const std::string& sink_ipv4,
                                  const std::string& sink_ipv6, u32 ttl, std::vector<u8>* out);

// The upstream resolver the operating system uses, as "ip:53".  Empty when it
// cannot be determined.
std::string system_dns_upstream();

class DnsSink {
 public:
  DnsSink();
  ~DnsSink();
  DnsSink(const DnsSink&) = delete;
  DnsSink& operator=(const DnsSink&) = delete;

  // `rules` may be null, in which case nothing is blocked and everything is
  // forwarded.  The rule set must stay alive for as long as the sink runs.
  bool start(const DnsSinkConfig& config, const RuleSet* rules, std::string* error);
  void stop();

  bool running() const;
  u16 port() const;
  const std::string& bound_endpoint() const;
  const std::string& upstream() const;
  const std::string& error() const;

  // Handles at most one datagram; returns true when one was dealt with.  Tests
  // drive the server with this so that nothing depends on thread timing.
  bool serve_once(int timeout_ms);
  // Serves until stop() is called.  Used by the command line.
  void run();

  std::vector<DnsQueryEvent> events() const;
  DnsSinkStats stats() const;
  std::string report() const;
  std::string describe() const;

 private:
  struct Impl;
  Impl* impl_;
};

}  // namespace netcap
