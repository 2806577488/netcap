// Local proxy correlation: who really asked for this connection?
//
// A翻墙 client (Clash, v2rayN, sing-box, ...) sits between the applications and
// the network.  The operating system only reports the proxy process for the
// outbound socket, so packet level attribution stops at "clash-win64.exe" and
// the real program (the browser) is invisible.
//
// This module rebuilds the missing half from the OS endpoint table:
//
//   application -> proxy      (client half: an app socket whose peer is the
//                              proxy's listening port)
//   proxy -> real server      (outbound half: a socket the proxy opened)
//
// The two halves are matched either exactly (when a host name is known from
// both sides: the CONNECT/SNI the application asked for and the SNI the proxy
// put on the wire) or by first-sighting order, which is a *guess* and is
// labelled as one.  Nothing here ever claims more certainty than it has.

#ifndef NETCAP_PROXY_HPP
#define NETCAP_PROXY_HPP

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/proc.hpp"

namespace netcap {

/// True for image names that are, in practice, local proxy clients.
bool name_looks_like_proxy(const std::string& image_name);

/// True for the ports local proxies listen on (7890, 1080, 10808, ...).
bool port_looks_like_proxy(u16 port);

enum class ProxyConfidence : u8 {
  None = 0,   // nothing claimed
  Order = 1,  // matched by first-sighting order: a guess, say so
  Host = 2,   // the same host name was seen on both halves
};

const char* proxy_confidence_name(ProxyConfidence c);
const char* proxy_confidence_text(ProxyConfidence c);

/// A listening socket of a proxy process.
struct ProxyEndpoint {
  u32 pid = 0;
  std::string name;
  int family = 4;
  u8 addr[16] = {0};   // wildcard (0.0.0.0 / ::) means "any local address"
  u16 port = 0;
};

/// Application -> proxy half.
struct ProxyClient {
  u32 pid = 0;
  std::string name;
  int family = 4;
  u8 addr[16] = {0};   // the application's local address
  u16 port = 0;        // and port
  u8 paddr[16] = {0};  // the proxy it is talking to
  u16 pport = 0;
  std::string host;    // host it asked for, when we could see it
  u64 order = 0;       // first sighting order
};

/// Proxy -> real server half.
struct ProxyOutbound {
  u32 pid = 0;
  std::string name;
  int family = 4;
  u8 raddr[16] = {0};  // the real server
  u16 rport = 0;
  u16 lport = 0;       // the proxy's local port
  u64 order = 0;
  std::string host;    // learned from the wire (TLS SNI / HTTP Host)
  bool paired = false;
};

/// The answer: this outbound connection was really asked for by `origin_pid`.
struct ProxyLink {
  u32 origin_pid = 0;
  std::string origin_name;
  u32 proxy_pid = 0;
  std::string proxy_name;
  int family = 4;
  u8 raddr[16] = {0};
  u16 rport = 0;
  ProxyConfidence confidence = ProxyConfidence::None;
  std::string basis;   // one sentence: why we believe this
};

/// Rebuilds the client/outbound halves from the OS endpoint table and pairs
/// them.  Portable on purpose: the pairing rules are the interesting part and
/// they are exercised by the self-test with synthetic endpoint tables.
class ProxyTable {
 public:
  void set_enabled(bool on) { enabled_ = on; }
  bool enabled() const { return enabled_; }

  /// Analyse one snapshot of the endpoint table.  `now_us` is the monotonic
  /// clock (packet timestamps are replay timestamps and must never be used).
  void rebuild(const std::vector<ProcEndpoint>& rows, const ProcessTable& procs, i64 now_us);

  /// Host names seen on the wire: on an outbound connection (what the proxy
  /// asked for) and on the application->proxy connection (what the application
  /// asked for).  Both raise the confidence of a pair from Order to Host.
  void note_outbound_host(int family, const u8* raddr, u16 rport, const std::string& host);
  void note_client_host(int family, const u8* addr, u16 port, const std::string& host);

  /// The link covering one proxy->server connection, or null.
  const ProxyLink* link(int family, const u8* raddr, u16 rport) const;

  bool is_proxy_pid(u32 pid) const;
  std::size_t proxy_processes() const { return proxy_names_.size(); }
  const std::string* proxy_name(u32 pid) const;
  const std::vector<ProxyEndpoint>& endpoints() const { return endpoints_; }
  const std::vector<ProxyClient>& clients() const { return clients_; }
  const std::vector<ProxyOutbound>& outbounds() const { return outbounds_; }
  std::size_t paired() const { return links_.size(); }
  u64 rebuilds() const { return rebuilds_; }
  void clear();

  /// One line for the log, e.g. "2 proxy process(es), 7 client socket(s), 6 of 9
  /// outbound connection(s) matched".
  std::string describe() const;

  /// The detail block printed by the CLI summary.
  std::string report() const;

 private:
  std::string why(const std::string& key);

  bool enabled_ = true;
  std::vector<ProxyEndpoint> endpoints_;
  std::vector<ProxyClient> clients_;
  std::vector<ProxyOutbound> outbounds_;
  std::map<u32, std::string> proxy_names_;
  std::map<std::string, ProxyLink> links_;             // outbound endpoint -> link
  std::map<std::string, std::string> outbound_hosts_;  // outbound endpoint -> host
  std::map<std::string, std::string> client_hosts_;    // client endpoint -> host
  std::map<std::string, u64> seen_;                    // endpoint key -> first order
  u64 clock_ = 0;
  u64 rebuilds_ = 0;
};

}  // namespace netcap

#endif  // NETCAP_PROXY_HPP
