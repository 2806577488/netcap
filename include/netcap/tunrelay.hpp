// Decision layer for the userspace tunnel: it looks at the opening bytes of a
// client -> server stream that the packet engine reassembled and answers the
// only question the relay needs before it dials anything:
//
//   "may this connection go out, and if not, what do we tell the application?"
//
// HTTP requests are decided by full URL, TLS client hellos by SNI (the tunnel
// sees the handshake in the clear, so domain blocking does not need the
// certificate to be installed), and everything else is passed through.
//
// The socket plumbing lives in tunrelay.cpp and is deliberately separate: this
// header stays byte-in / verdict-out so it can be tested without networking.
#ifndef NETCAP_TUNRELAY_HPP
#define NETCAP_TUNRELAY_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"  // Bytes
#include "netcap/rules.hpp"

namespace netcap {

enum class RelayVerdict {
  NeedMore,  ///< the head is not complete yet: buffer and ask again
  Forward,   ///< connect to the original destination and relay
  Block,     ///< answer locally with a block page (HTTP only) or reset the flow
  Redirect,  ///< answer locally with a redirect
  Reset,     ///< nothing to send: tear the flow down
};

const char* tunrelay_verdict_name(RelayVerdict v);

struct RelayDecision {
  RelayVerdict verdict = RelayVerdict::NeedMore;
  std::string url;      ///< what we decided on (absolute URL for HTTP, host for TLS)
  std::string host;     ///< host name (SNI or Host header)
  std::string reason;   ///< the matching rule / why we are here
  std::string target;   ///< Location for Redirect
  int status = 0;       ///< status code of the local answer
  std::string body;     ///< body of the local answer
  std::string content_type;
  bool is_tls = false;  ///< the stream looked like TLS rather than HTTP
  std::string describe() const;
};

/// Inspects the beginning of a stream. `consumed` receives the number of bytes
/// that formed the head (0 while the verdict is NeedMore, all bytes otherwise,
/// because a forwarded stream must be replayed in full).
///
/// `port` selects the protocol family: 80/8000/8080/8888 are read as HTTP, 443/
/// 8443/9443 as TLS, anything else is forwarded untouched. A stream that does not
/// look like the protocol its port promised is forwarded as well - guessing wrong
/// costs the user their network, so the default is always "let it through".
RelayDecision tunrelay_inspect(const RuleSet* rules, u16 port, const Bytes& bytes,
                               std::size_t* consumed, std::size_t max_head = 16384);

/// True when this port is expected to carry HTTP (and therefore can be blocked by
/// URL rather than by domain).
bool tunrelay_port_is_http(u16 port);
/// True when this port is expected to carry TLS.
bool tunrelay_port_is_tls(u16 port);

/// The block page: self-contained HTML, so it renders without any network.
std::string tunrelay_block_page(const RelayDecision& d);
/// A minimal local HTTP answer ("HTTP/1.1 403 ...\r\n\r\n<body>").
std::string tunrelay_http_response(int status, const std::string& content_type,
                                   const std::string& body, const std::string& location = std::string());

}  // namespace netcap

#endif  // NETCAP_TUNRELAY_HPP
