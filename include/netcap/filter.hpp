// netcap - filter.hpp
// A tcpdump-inspired filter expression, compiled once into a predicate tree.
//
// This is a *userspace* filter: it runs after dissection, so it can express
// things classic kernel BPF cannot (TLS SNI, HTTP Host, URL substrings). For
// live capture the kernel still does the cheap coarse work (VLAN/ethertype
// handling, snaplen), and `--bpf-offload` is not needed because we never install
// a kernel filter.
//
// Grammar (tokens are whitespace separated; parentheses group; precedence
// not > and > or; `&&`/`||`/`!` are accepted as aliases):
//
//   or_expr   := and_expr { ("or" | "||") and_expr }
//   and_expr  := unary { [("and" | "&&")] unary }
//   unary     := ("not" | "!") unary | primary
//   primary   := "(" or_expr ")" | primitive
//   primitive := proto | [dir] "host" <addr> | [dir] "port" <num>
//              | "portrange" <a> "-" <b> | "net" <cidr> | "vlan" <num>
//              | "hostname" <substr> | "url" <substr> | "payload" <substr>
//              | "tcpflags" <flags> | "len" <op> <num> | "ttl" <op> <num>
//   proto     := ip | ip4 | ip6 | tcp | udp | icmp | icmp6 | arp | vlan
//              | http | https | tls | dns | quic | ssh | dhcp | mdns | fragment
//   dir       := src | dst
//   op        := "<" | "<=" | ">" | ">=" | "=" | "!="
//
// Examples:
//   "tcp and port 443"
//   "hostname contains" is not a thing -> use: hostname example.com
//   "tls and hostname .bank. and not host 10.0.0.0/8"
//   "http and url /login"
//   "udp port 53 or tcp port 80"
//   "tcpflags syn and portrange 1-1024"
#pragma once

#include <memory>
#include <string>

#include "netcap/app.hpp"

namespace netcap {

// Which program owns a packet; only needed by the `proc` / `pid` primitives.
struct ProcessInfo;
// Which program is really behind a packet that a local proxy carried; only
// needed by `proxied`, `via` and `origin`.
struct ProxyLink;

class Filter {
 public:
  /// Empty filter: matches every packet.
  Filter();
  ~Filter();
  Filter(const Filter&);
  Filter& operator=(const Filter&);
  Filter(Filter&&) noexcept;
  Filter& operator=(Filter&&) noexcept;

  /// Compiles `text`. On failure the returned filter matches nothing and
  /// `*error` (when non-null) explains why, including the offending token.
  static Filter parse(const std::string& text, std::string* error);

  /// Evaluates the predicate. `app` may be null; app-level primitives
  /// (http/tls/dns/hostname/url) then fall back to a port-based guess.
  /// `origin` is the proxy link of this packet, when one was correlated.
  bool match(const PacketInfo& pi, const AppInfo* app = nullptr,
             const ProcessInfo* proc = nullptr, const ProxyLink* origin = nullptr) const;

  /// True when this filter accepts everything (an empty expression).
  bool match_all() const;
  const std::string& text() const { return text_; }
  bool parse_failed() const { return failed_; }

  /// Opaque predicate node. Public only so the parser in filter.cpp can build
  /// the tree; callers should treat it as private.
  struct Node;

 private:
  std::shared_ptr<const Node> root_;
  std::string text_;
  bool failed_ = false;
};

/// Convenience: lists the supported primitive keywords (for --help).
std::string filter_syntax_help();

}  // namespace netcap
