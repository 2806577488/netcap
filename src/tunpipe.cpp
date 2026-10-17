#include "netcap/tunpipe.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

#include "netcap/quic.hpp"
#include "netcap/quic_rewrite.hpp"
#include "netcap/tunrelay.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace netcap {
namespace {

#ifdef _WIN32
using sock_t = SOCKET;
const sock_t kNoSock = INVALID_SOCKET;
#else
using sock_t = int;
const sock_t kNoSock = -1;
#endif

const std::size_t kIoChunk = 16384;
const std::size_t kMaxUndecided = 1u << 20;  ///< client bytes held before we give up
const std::size_t kMaxQuicStream = 64u << 10;  ///< bytes reassembled per HTTP/3 request stream

std::string socket_error_text() {
#ifdef _WIN32
  return "Win32 error " + std::to_string(static_cast<int>(::WSAGetLastError()));
#else
  return std::strerror(errno);
#endif
}

/// Pin a UDP socket to one adapter.  While the tunnel owns the default route a
/// plain send() on an unbound socket would aim the datagram back at the tunnel,
/// so the exit interface has to be named explicitly before connect().
bool pin_udp_interface(sock_t fd, int ip_version, std::uint32_t ifindex, std::string* error) {
#ifdef _WIN32
  // IPv4 wants the index in network byte order, IPv6 in host order; getting this
  // backwards silently sends nothing.
  if (ip_version == 6) {
    const DWORD index = static_cast<DWORD>(ifindex);
    if (::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<const char*>(&index),
                     static_cast<int>(sizeof index)) != 0) {
      *error = "cannot pin udp to interface " + std::to_string(ifindex) + ": " +
               socket_error_text();
      return false;
    }
    return true;
  }
  const DWORD index = htonl(static_cast<DWORD>(ifindex));
  if (::setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char*>(&index),
                   static_cast<int>(sizeof index)) != 0) {
    *error =
        "cannot pin udp to interface " + std::to_string(ifindex) + ": " + socket_error_text();
    return false;
  }
  return true;
#else
  const unsigned int index = static_cast<unsigned int>(ifindex);
  if (ip_version == 6) {
    if (::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &index, sizeof index) != 0) {
      *error =
          "cannot pin udp to interface " + std::to_string(ifindex) + ": " + socket_error_text();
      return false;
    }
    return true;
  }
#ifdef SO_BINDTOIFINDEX
  if (::setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &index, sizeof index) != 0) {
    *error = "cannot pin udp to interface " + std::to_string(ifindex) + ": " + socket_error_text();
    return false;
  }
  return true;
#else
  (void)fd;
  *error = "this platform cannot name the interface a udp socket should leave through";
  return false;
#endif
#endif
}

void close_sock(sock_t fd) {
  if (fd == kNoSock) return;
#ifdef _WIN32
  ::closesocket(fd);
#else
  ::close(fd);
#endif
}

void shutdown_send(sock_t fd) {
  if (fd == kNoSock) return;
#ifdef _WIN32
  ::shutdown(fd, SD_SEND);
#else
  ::shutdown(fd, SHUT_WR);
#endif
}

bool set_nonblocking(sock_t fd) {
#ifdef _WIN32
  u_long on = 1;
  return ::ioctlsocket(fd, FIONBIO, &on) == 0;
#else
  const int flags = ::fcntl(fd, F_GETFL, 0);
  return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool would_block() {
#ifdef _WIN32
  const int e = ::WSAGetLastError();
  return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
#else
  return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY;
#endif
}

/// SO_ERROR, right after a non-blocking connect.
int socket_error_code(sock_t fd) {
  int err = 0;
#ifdef _WIN32
  int len = static_cast<int>(sizeof err);
#else
  socklen_t len = sizeof err;
#endif
  if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) return -1;
  return err;
}

std::string ip_text(const Endpoint& e) {
  char buf[64] = {0};
  if (e.ip_version == 6) {
    ::inet_ntop(AF_INET6, e.addr, buf, sizeof buf);
  } else {
    ::inet_ntop(AF_INET, e.addr, buf, sizeof buf);
  }
  return buf[0] != 0 ? std::string(buf) : std::string("?");
}

bool make_addr(int version, const u8* addr, u16 port, sockaddr_storage* out, int* out_len) {
  std::memset(out, 0, sizeof *out);
  if (version == 6) {
    sockaddr_in6 a{};
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(port);
    std::memcpy(&a.sin6_addr, addr, 16);
    std::memcpy(out, &a, sizeof a);
    *out_len = static_cast<int>(sizeof a);
    return true;
  }
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  std::memcpy(&a.sin_addr, addr, 4);
  std::memcpy(out, &a, sizeof a);
  *out_len = static_cast<int>(sizeof a);
  return true;
}

sock_t open_socket(int version, int type) {
  return ::socket(version == 6 ? AF_INET6 : AF_INET, type, 0);
}

/// Replace the target of the first request line with the path of a rewritten
/// URL (today only `$removeparam` gets us here).
Bytes rewrite_request_target(const Bytes& head, const std::string& new_url) {
  const std::string text(head.begin(), head.end());
  const std::size_t eol = text.find("\r\n");
  if (eol == std::string::npos) return head;
  const std::size_t sp1 = text.find(' ');
  if (sp1 == std::string::npos || sp1 > eol) return head;
  const std::size_t sp2 = text.find(' ', sp1 + 1);
  if (sp2 == std::string::npos || sp2 > eol) return head;

  std::string target;
  const std::size_t scheme = new_url.find("://");
  if (scheme != std::string::npos) {
    const std::size_t slash = new_url.find('/', scheme + 3);
    target = slash == std::string::npos ? std::string("/") : new_url.substr(slash);
  } else {
    target = new_url;
  }
  const std::string out = text.substr(0, sp1 + 1) + target + text.substr(sp2);
  return Bytes(out.begin(), out.end());
}

std::string connect_target(const std::string& host_for_chain, const Endpoint& server) {
  return host_for_chain.empty() ? ip_text(server) : host_for_chain;
}

}  // namespace

struct Pipe {
  u64 flow = 0;
  FlowProto proto = FlowProto::Tcp;
  Endpoint client;
  Endpoint server;
  sock_t fd = kNoSock;

  enum class Stage { Deciding, Connecting, Chaining, Relaying, Done };
  Stage stage = Stage::Deciding;

  Bytes client_buf;    ///< bytes read from the client, not yet moved upstream
  Bytes to_upstream;   ///< bytes owed to the origin
  std::size_t sent = 0;

  std::string chain_reply;
  std::string chain_request;
  bool chain_sent = false;
  bool client_eof = false;
  bool upstream_eof = false;
  bool sent_fin = false;
  i64 deadline_us = 0;
  std::string host_for_chain;
  std::string last_verdict;
  std::string note;

  // QUIC only.  `quic_dcid` is the connection id from the first Initial (the key
  // log is keyed by exactly that); the key sets come from RelayConfig::quic_keys.
  Bytes quic_dcid;
  bool quic_keys_tried = false;
  bool quic_keys_ready = false;
  u16 quic_suite = 0;
  QuicKeyset quic_client;
  QuicKeyset quic_server;
  u64 quic_largest_pn = 0;
  bool quic_decided = false;
  std::map<u64, Bytes> quic_streams;
};

struct TunPipe::Impl {
  explicit Impl(const RelayConfig& c) : cfg(c) {
    PacketEngineConfig pc;
    pc.version = cfg.version;
    pc.mtu = cfg.mtu;
    pc.max_flows = cfg.max_flows;
    pc.answer_icmp_echo = cfg.answer_icmp_echo;
    std::memcpy(pc.local, cfg.local, sizeof pc.local);
    engine.set_config(pc);
  }

  RelayConfig cfg;
  PacketEngine engine;
  std::map<u64, Pipe> pipes;
  RelayStats stats;

  Pipe* find(u64 flow) {
    const auto it = pipes.find(flow);
    return it == pipes.end() ? nullptr : &it->second;
  }

  void drop(u64 flow) {
    const auto it = pipes.find(flow);
    if (it == pipes.end()) return;
    if (it->second.fd != kNoSock) close_sock(it->second.fd);
    pipes.erase(it);
  }

  void fail(Pipe& p, i64 now_us, std::vector<Packet>* out, const std::string& why) {
    p.note = why;
    ++stats.upstream_failed;
    engine.abort_flow(p.flow, now_us, out);
    if (p.fd != kNoSock) {
      close_sock(p.fd);
      p.fd = kNoSock;
    }
    p.stage = Pipe::Stage::Done;
  }

  /// Dial the origin directly (no DNS: we already hold the address) or the
  /// chain, which is named and therefore needs the resolver.
  bool dial(Pipe& p, bool chained, i64 now_us) {
    std::string why;
    sock_t fd = kNoSock;
    if (chained) {
      addrinfo hints{};
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;
      addrinfo* res = nullptr;
      const std::string port_text = std::to_string(cfg.chain_port);
      if (::getaddrinfo(cfg.chain_host.c_str(), port_text.c_str(), &hints, &res) != 0 || res == nullptr) {
        p.note = "cannot resolve the chain host " + cfg.chain_host;
        return false;
      }
      for (addrinfo* it = res; it != nullptr && fd == kNoSock; it = it->ai_next) {
        fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == kNoSock) continue;
        if (!set_nonblocking(fd)) {
          close_sock(fd);
          fd = kNoSock;
          continue;
        }
        if (::connect(fd, it->ai_addr, static_cast<int>(it->ai_addrlen)) != 0 && !would_block()) {
          close_sock(fd);
          fd = kNoSock;
        }
      }
      ::freeaddrinfo(res);
      if (fd == kNoSock) {
        p.note = "cannot reach the chain " + cfg.chain_host + ":" + port_text + " (" + socket_error_text() + ")";
        return false;
      }
    } else {
      sockaddr_storage ss{};
      int sslen = 0;
      make_addr(p.server.ip_version, p.server.addr, p.server.port, &ss, &sslen);
      fd = open_socket(p.server.ip_version, SOCK_STREAM);
      if (fd == kNoSock) {
        p.note = "socket() failed: " + socket_error_text();
        return false;
      }
      if (!set_nonblocking(fd)) {
        close_sock(fd);
        p.note = "cannot make the socket non-blocking";
        return false;
      }
      if (::connect(fd, reinterpret_cast<sockaddr*>(&ss), sslen) != 0 && !would_block()) {
        p.note = "connect to " + ip_text(p.server) + ":" + std::to_string(p.server.port) + " failed: " + socket_error_text();
        close_sock(fd);
        return false;
      }
    }
    (void)why;
    p.fd = fd;
    p.deadline_us = now_us + cfg.connect_timeout_us;
    p.stage = Pipe::Stage::Connecting;
    ++stats.upstream_opened;
    return true;
  }

  bool open_upstream(Pipe& p, i64 now_us) {
    if (p.proto == FlowProto::Udp) {
      if (!cfg.forward_udp) {
        // Deliberately off: see RelayConfig::forward_udp.
        p.note = "udp is not forwarded while the tunnel owns the default route";
        ++stats.dropped;
        return false;
      }
      if (cfg.physical_ifindex == 0 || cfg.physical_ifindex == cfg.tunnel_ifindex) {
        // Nothing to aim at: without a physical interface an unbound datagram
        // would go straight back into the tunnel, so it is dropped instead.
        p.note = cfg.physical_ifindex == 0 ? "no physical interface to aim udp at"
                                           : "the only interface to aim udp at is the tunnel itself";
        ++stats.dropped;
        return false;
      }
      sockaddr_storage ss{};
      int sslen = 0;
      make_addr(p.server.ip_version, p.server.addr, p.server.port, &ss, &sslen);
      const sock_t fd = open_socket(p.server.ip_version, SOCK_DGRAM);
      if (fd == kNoSock) {
        p.note = "udp socket() failed: " + socket_error_text();
        return false;
      }
      if (!set_nonblocking(fd)) {
        close_sock(fd);
        p.note = "cannot make the udp socket non-blocking";
        return false;
      }
      {
        std::string pin_error;
        if (!pin_udp_interface(fd, p.server.ip_version, cfg.physical_ifindex, &pin_error)) {
          close_sock(fd);
          p.note = pin_error;
          ++stats.dropped;
          return false;
        }
      }
      if (::connect(fd, reinterpret_cast<sockaddr*>(&ss), sslen) != 0) {
        p.note = "udp connect failed: " + socket_error_text();
        close_sock(fd);
        return false;
      }
      p.fd = fd;
      p.stage = Pipe::Stage::Relaying;
      ++stats.upstream_opened;
      if (!flush(p, now_us, nullptr)) return false;
      return true;
    }
    const bool chained = !cfg.chain_host.empty() && cfg.chain_port != 0;
    if (!dial(p, chained, now_us)) return false;
    return true;
  }

  /// Push as much of to_upstream as the socket takes.
  bool flush(Pipe& p, i64 now_us, std::vector<Packet>* out) {
    (void)now_us;
    (void)out;
    while (p.sent < p.to_upstream.size()) {
      const std::size_t want = p.to_upstream.size() - p.sent;
      const int n = ::send(p.fd, reinterpret_cast<const char*>(p.to_upstream.data() + p.sent),
                           static_cast<int>(std::min<std::size_t>(want, kIoChunk)), 0);
      if (n > 0) {
        p.sent += static_cast<std::size_t>(n);
        stats.bytes_up += static_cast<std::size_t>(n);
        continue;
      }
      if (n < 0 && would_block()) return true;
      p.note = "upstream write failed: " + socket_error_text();
      return false;
    }
    if (p.sent == p.to_upstream.size()) {
      p.to_upstream.clear();
      p.sent = 0;
    }
    return true;
  }

  void decide(Pipe& p, i64 now_us, std::vector<Packet>* out) {
    std::size_t consumed = 0;
    const RelayDecision d = tunrelay_inspect(cfg.rules, p.server.port, p.client_buf, &consumed, 16384);
    if (p.last_verdict.empty()) p.last_verdict = tunrelay_verdict_name(d.verdict);
    if (d.verdict == RelayVerdict::NeedMore) {
      ++stats.undecided;
      return;
    }
    ++stats.flows;
    if (p.proto == FlowProto::Udp && cfg.quic_keys != nullptr && p.quic_dcid.empty() &&
        !p.client_buf.empty()) {
      // The key log is keyed by the connection id of the first Initial, and that
      // is the only place it appears: later packets are short headers with no
      // DCID.  The field sits in the clear, so read it here -- deriving Initial
      // keys just to get it would be circular.
      const Bytes& b = p.client_buf;
      const bool long_header = (b[0] & 0x80u) != 0;
      const bool initial = long_header && (b[0] & 0x30u) == 0x00u;
      if (initial && b.size() >= 7) {
        const std::size_t dcid_len = b[5];
        if (dcid_len <= 20 && b.size() >= 6 + dcid_len) {
          p.quic_dcid.assign(b.begin() + 6, b.begin() + 6 + dcid_len);
        }
      }
    }
    if (d.is_tls) {
      ++stats.tls_inspected;
    } else if (!d.url.empty()) {
      ++stats.http_inspected;
    }
    p.host_for_chain = d.host;

    if (d.verdict == RelayVerdict::Block) {
      const int status = d.status > 0 ? d.status : 403;
      const std::string body = tunrelay_block_page(d);
      const std::string resp = tunrelay_http_response(status, "text/html; charset=utf-8", body);
      if (engine.write(p.flow, Bytes(resp.begin(), resp.end()), now_us, out)) {
        engine.close_flow(p.flow, now_us, out);
      }
      ++stats.blocked;
      p.stage = Pipe::Stage::Done;
      p.note = d.reason;
      return;
    }
    if (d.verdict == RelayVerdict::Redirect) {
      const std::string resp = tunrelay_http_response(d.status > 0 ? d.status : 302,
                                                     "text/plain; charset=utf-8", "", d.target);
      if (engine.write(p.flow, Bytes(resp.begin(), resp.end()), now_us, out)) {
        engine.close_flow(p.flow, now_us, out);
      }
      ++stats.redirected;
      p.stage = Pipe::Stage::Done;
      p.note = d.reason;
      return;
    }
    if (d.verdict == RelayVerdict::Reset) {
      engine.abort_flow(p.flow, now_us, out);
      ++stats.reset;
      p.stage = Pipe::Stage::Done;
      p.note = d.reason;
      return;
    }

    // Forward: the request head (possibly rewritten) is what goes upstream.
    if (!d.is_tls && !d.target.empty() && d.target != d.url) {
      p.client_buf = rewrite_request_target(p.client_buf, d.target);
      p.note = "request target rewritten";
    }
    p.to_upstream = p.client_buf;
    p.client_buf.clear();
    p.sent = 0;
    if (!open_upstream(p, now_us)) {
      fail(p, now_us, out, p.note.empty() ? "cannot reach the origin" : p.note);
      return;
    }
    ++stats.forwarded;
  }

  /// Open one 1-RTT datagram and judge the HTTP/3 request inside it.  Returns
  /// true when the datagram must NOT be forwarded.  Anything we cannot open is
  /// forwarded untouched: guessing here would silently break QUIC.
  bool quic_filter(Pipe& p, Bytes& chunk) {
    if (cfg.quic_keys == nullptr) return false;
    if (!p.quic_keys_tried) {
      p.quic_keys_tried = true;
      std::string why;
      p.quic_keys_ready =
          !p.quic_dcid.empty() && cfg.quic_keys->keys_for(p.quic_dcid, &p.quic_suite,
                                                         &p.quic_client, &p.quic_server, &why);
      if (!p.quic_keys_ready && std::getenv("NETCAP_QUIC_TRACE") != nullptr) {
        std::fprintf(stderr, "netcap: quic: no 1-RTT keys for this connection (%s)\n",
                     why.c_str());
      }
    }
    if (!p.quic_keys_ready) return false;
    // A rewrite needs the largest packet number seen *before* this packet: the
    // decoder reconstructs a truncated number from it, so handing it this
    // packet's own number would move the header-protection sample and nothing
    // would authenticate.
    const u64 largest_before = p.quic_largest_pn;
    QuicShortHeader hdr;
    std::string why;
    if (!quic_decrypt_short_full(p.quic_client, p.quic_dcid.data(), p.quic_dcid.size(),
                                 chunk.data(), chunk.size(), p.quic_largest_pn, &hdr, &why)) {
      return false;  // not something we can open: forward it unchanged
    }
    ++stats.quic_inspected;
    if (hdr.packet_number > p.quic_largest_pn) p.quic_largest_pn = hdr.packet_number;
    std::vector<QuicFrameInfo> frames;
    if (!quic_parse_frames_rtt(hdr.payload.data(), hdr.payload.size(), &frames, &why)) {
      return false;
    }
    bool blocked = false;
    for (const QuicFrameInfo& f : frames) {
      if (f.type < 0x08 || f.type > 0x0f) continue;  // STREAM frames only
      const u64 id = f.stream.stream_id;
      if ((id & 0x03u) != 0x00u) continue;  // client-initiated bidirectional only
      const std::size_t offset = static_cast<std::size_t>(f.stream.offset);
      const std::size_t end = offset + f.stream.data.size();
      if (end > kMaxQuicStream) continue;
      Bytes& buf = p.quic_streams[id];
      if (buf.size() < end) buf.resize(end, 0);
      std::copy(f.stream.data.begin(), f.stream.data.end(), buf.begin() + offset);
      if (p.quic_decided) continue;
      H3Request req;
      std::string herr;
      if (!h3_request_from_stream(buf, true, &req, &herr)) continue;  // not complete yet
      p.quic_decided = true;
      const std::string url = (req.scheme.empty() ? std::string("https") : req.scheme) + "://" +
                              req.authority + req.path;
      p.note = "HTTP/3 " + url;
      if (cfg.rules == nullptr) continue;
      const RuleDecision d =
          cfg.rules->decide(rule_request_from_url(url, "", ResourceType::Document));
      p.last_verdict = "quic " + d.explain();
      if (d.action == RuleAction::Block || d.action == RuleAction::Redirect) {
        p.note = "HTTP/3 " + url + " -> " + d.explain();
        ++stats.quic_blocked;
        blocked = true;
      } else if (d.action == RuleAction::Modify) {
        // The datagram keeps its length and its packet number; only the request
        // inside it changes (see `include/netcap/quic_rewrite.hpp`).  When the
        // edit does not fit, the request is left exactly as the client wrote it.
        Bytes replacement;
        QuicRewriteResult rewritten;
        std::string rerr;
        if (!quic_rewrite_request(p.quic_client, p.quic_dcid.size(), chunk.data(), chunk.size(),
                                  largest_before, *cfg.rules, &replacement, &rewritten, &rerr)) {
          p.note = "HTTP/3 " + url + ": cannot rewrite (" + rerr + ")";
        } else if (rewritten.rewritten) {
          chunk = replacement;
          ++stats.quic_rewritten;
          p.note = "HTTP/3 " + url + " -> " + rewritten.note;
        } else {
          p.note = "HTTP/3 " + url + ": " + rewritten.note;
        }
      }
      break;
    }
    return blocked;
  }

  void drain(i64 now_us, std::vector<Packet>* out) {
    const std::vector<PacketEngine::FlowView> flows = engine.flows();
    for (const PacketEngine::FlowView& v : flows) {
      Pipe* p = find(v.id);
      if (p == nullptr) {
        Pipe fresh;
        fresh.flow = v.id;
        fresh.proto = v.proto;
        fresh.client = v.client;
        fresh.server = v.server;
        pipes.emplace(v.id, fresh);
        p = find(v.id);
        if (p == nullptr) continue;
      }
      Bytes chunk;
      while (p->stage != Pipe::Stage::Done && engine.read(v.id, &chunk)) {
        if (chunk.empty()) break;
        if (p->stage == Pipe::Stage::Deciding) {
          p->client_buf.insert(p->client_buf.end(), chunk.begin(), chunk.end());
          if (p->client_buf.size() > kMaxUndecided) {
            engine.abort_flow(v.id, now_us, out);
            p->note = "the request head never completed";
            ++stats.dropped;
            p->stage = Pipe::Stage::Done;
            break;
          }
          decide(*p, now_us, out);
          if (p->stage == Pipe::Stage::Done) break;
          if (p->stage == Pipe::Stage::Deciding) break;  // still waiting for more bytes
        } else {
          if (p->proto == FlowProto::Udp && quic_filter(*p, chunk)) {
            // Answering a blocked HTTP/3 request with silence is all UDP offers;
            // the flow stops here, so the browser retries or falls back to TCP.
            p->stage = Pipe::Stage::Done;
            break;
          }
          p->to_upstream.insert(p->to_upstream.end(), chunk.begin(), chunk.end());
          if (!flush(*p, now_us, out)) {
            fail(*p, now_us, out, p->note);
            break;
          }
        }
      }
      if (p->stage == Pipe::Stage::Relaying && v.closed && !p->sent_fin) {
        shutdown_send(p->fd);
        p->sent_fin = true;
        p->client_eof = true;
      }
    }
  }

  void poll_sockets(int timeout_ms, i64 now_us, std::vector<Packet>* out) {
    if (pipes.empty()) return;
    fd_set rf;
    fd_set wf;
    FD_ZERO(&rf);
    FD_ZERO(&wf);
    sock_t maxfd = 0;
    bool any = false;
    for (const auto& kv : pipes) {
      const Pipe& p = kv.second;
      if (p.fd == kNoSock || p.stage == Pipe::Stage::Done) continue;
      FD_SET(p.fd, &rf);
      FD_SET(p.fd, &wf);
      maxfd = any ? std::max(maxfd, p.fd) : p.fd;
      any = true;
    }
    if (!any) return;
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
#ifdef _WIN32
    const int n = ::select(0, &rf, &wf, nullptr, &tv);
#else
    const int n = ::select(static_cast<int>(maxfd) + 1, &rf, &wf, nullptr, &tv);
#endif
    if (n <= 0) return;

    std::vector<u64> dead;
    for (auto& kv : pipes) {
      Pipe& p = kv.second;
      if (p.fd == kNoSock || p.stage == Pipe::Stage::Done) continue;
      const bool r = FD_ISSET(p.fd, &rf) != 0;
      const bool w = FD_ISSET(p.fd, &wf) != 0;
      if (!r && !w) continue;

      if (p.stage == Pipe::Stage::Connecting) {
        const int err = socket_error_code(p.fd);
        if (err != 0) {
          fail(p, now_us, out, "connect failed (" + std::to_string(err) + ")");
          dead.push_back(kv.first);
          continue;
        }
        const bool chained = p.proto == FlowProto::Tcp && !cfg.chain_host.empty() && cfg.chain_port != 0;
        if (chained) {
          const std::string target = connect_target(p.host_for_chain, p.server) + ":" + std::to_string(p.server.port);
          p.chain_request = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Connection: keep-alive\r\n\r\n";
          p.stage = Pipe::Stage::Chaining;
        } else {
          p.stage = Pipe::Stage::Relaying;
          if (!flush(p, now_us, out)) {
            fail(p, now_us, out, p.note);
            dead.push_back(kv.first);
          }
        }
        continue;
      }

      if (p.stage == Pipe::Stage::Chaining) {
        if (w && !p.chain_sent) {
          const int n = ::send(p.fd, p.chain_request.data(), static_cast<int>(p.chain_request.size()), 0);
          if (n == static_cast<int>(p.chain_request.size())) {
            p.chain_sent = true;
          } else if (n < 0 && !would_block()) {
            fail(p, now_us, out, "chain write failed: " + socket_error_text());
            dead.push_back(kv.first);
            continue;
          }
        }
        if (r) {
          char buf[2048];
          const int n = ::recv(p.fd, buf, static_cast<int>(sizeof buf), 0);
          if (n > 0) {
            p.chain_reply.append(buf, static_cast<std::size_t>(n));
          } else if (n == 0) {
            fail(p, now_us, out, "the chain closed during CONNECT");
            dead.push_back(kv.first);
            continue;
          } else if (!would_block()) {
            fail(p, now_us, out, "chain read failed: " + socket_error_text());
            dead.push_back(kv.first);
            continue;
          }
          const std::size_t end = p.chain_reply.find("\r\n\r\n");
          if (end != std::string::npos) {
            const bool ok = p.chain_reply.size() > 12 && p.chain_reply.compare(0, 5, "HTTP/") == 0 &&
                            p.chain_reply[9] == '2';
            if (!ok) {
              fail(p, now_us, out, "the chain refused the tunnel: " + p.chain_reply.substr(0, p.chain_reply.find("\r\n")));
              dead.push_back(kv.first);
              continue;
            }
            p.stage = Pipe::Stage::Relaying;
            if (!flush(p, now_us, out)) {
              fail(p, now_us, out, p.note);
              dead.push_back(kv.first);
            }
          }
        }
        continue;
      }

      if (p.stage == Pipe::Stage::Relaying) {
        if (w && !flush(p, now_us, out)) {
          fail(p, now_us, out, p.note);
          dead.push_back(kv.first);
          continue;
        }
        if (r) {
          char buf[kIoChunk];
          const int n = ::recv(p.fd, buf, static_cast<int>(sizeof buf), 0);
          if (n > 0) {
            const u8* first = reinterpret_cast<const u8*>(buf);
            Bytes data(first, first + n);
            if (!engine.write(p.flow, data, now_us, out)) {
              p.note = "the client flow is gone";
              dead.push_back(kv.first);
              continue;
            }
            stats.bytes_down += static_cast<std::size_t>(n);
          } else if (n == 0) {
            ++stats.upstream_eof;
            engine.close_flow(p.flow, now_us, out);
            dead.push_back(kv.first);
          } else if (!would_block()) {
            fail(p, now_us, out, "upstream read failed: " + socket_error_text());
            dead.push_back(kv.first);
          }
        }
        continue;
      }
    }
    for (u64 id : dead) drop(id);
  }

  void tick_pipes(i64 now_us, std::vector<Packet>* out) {
    engine.tick(now_us, out);
    std::vector<u64> dead;
    for (auto& kv : pipes) {
      Pipe& p = kv.second;
      if (p.stage == Pipe::Stage::Connecting || p.stage == Pipe::Stage::Chaining) {
        if (p.deadline_us != 0 && now_us >= p.deadline_us) {
          ++stats.connect_timeouts;
          engine.abort_flow(p.flow, now_us, out);
          p.note = "connect timed out";
          dead.push_back(kv.first);
        }
      }
    }
    for (u64 id : dead) drop(id);
    for (auto it = pipes.begin(); it != pipes.end();) {
      PacketEngine::FlowView v;
      if (it->second.stage == Pipe::Stage::Done || !engine.flow(it->first, &v)) {
        if (it->second.fd != kNoSock) close_sock(it->second.fd);
        it = pipes.erase(it);
        continue;
      }
      ++it;
    }
  }
};

std::string RelayStats::describe() const {
  std::string s;
  s += "flows " + std::to_string(flows) + " (forwarded " + std::to_string(forwarded) + ", blocked " +
       std::to_string(blocked) + ", redirected " + std::to_string(redirected) + ", reset " +
       std::to_string(reset) + ")";
  s += ", inspected " + std::to_string(http_inspected) + " http / " + std::to_string(tls_inspected) + " tls";
  if (quic_inspected != 0 || quic_blocked != 0) {
    s += " / " + std::to_string(quic_inspected) + " quic (" + std::to_string(quic_blocked) +
         " blocked)";
  }
  s += ", undecided " + std::to_string(undecided);
  s += ", bytes up " + std::to_string(bytes_up) + " down " + std::to_string(bytes_down);
  s += ", upstream opened " + std::to_string(upstream_opened) + " failed " + std::to_string(upstream_failed) +
       " eof " + std::to_string(upstream_eof);
  if (connect_timeouts != 0) s += ", connect timeouts " + std::to_string(connect_timeouts);
  if (dropped != 0) s += ", dropped " + std::to_string(dropped);
  return s;
}

namespace {
void ensure_winsock();  // defined at the end of this file
}  // namespace

TunPipe::TunPipe(const RelayConfig& config) : impl_(new Impl(config)) { ensure_winsock(); }
TunPipe::~TunPipe() { stop(); }

void TunPipe::on_packet(const u8* ip, std::size_t len, i64 now_us, std::vector<Packet>* out) {
  impl_->engine.feed(ip, len, now_us, out);
  impl_->drain(now_us, out);
}

void TunPipe::poll(int timeout_ms, i64 now_us, std::vector<Packet>* out) {
  impl_->poll_sockets(timeout_ms, now_us, out);
  impl_->drain(now_us, out);
}

void TunPipe::tick(i64 now_us, std::vector<Packet>* out) { impl_->tick_pipes(now_us, out); }

void TunPipe::stop() {
  for (auto& kv : impl_->pipes) {
    if (kv.second.fd != kNoSock) close_sock(kv.second.fd);
    kv.second.fd = kNoSock;
  }
  impl_->pipes.clear();
}

const RelayStats& TunPipe::stats() const { return impl_->stats; }
const PacketEngine& TunPipe::engine() const { return impl_->engine; }
PacketEngine& TunPipe::engine() { return impl_->engine; }
std::size_t TunPipe::pipe_count() const { return impl_->pipes.size(); }

std::string TunPipe::describe() const {
  return impl_->stats.describe() + "; pipes " + std::to_string(impl_->pipes.size()) + "; engine " +
         impl_->engine.describe();
}

namespace {

/// Winsock has to be started before the first socket(): the capture layer does
/// that for its own paths, but a TUN takeover talks to the network through this
/// file alone (no capture socket is ever opened), so it has to be sure itself.
/// WSAStartup is reference counted and the process cleans up at exit, so one
/// lazy call is enough.
void ensure_winsock() {
#ifdef _WIN32
  static const bool started = []() {
    WSADATA data;
    return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  (void)started;
#endif
}

}  // namespace

bool tunpipe_chain_reachable(const std::string& host, std::uint16_t port, int timeout_ms) {
  ensure_winsock();
  if (host.empty() || port == 0) return false;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* res = nullptr;
  const std::string port_text = std::to_string(port);
  if (::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &res) != 0 || res == nullptr) {
    return false;
  }
  bool reachable = false;
  for (addrinfo* it = res; it != nullptr && !reachable; it = it->ai_next) {
    const sock_t fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (fd == kNoSock) continue;
    if (!set_nonblocking(fd)) {
      close_sock(fd);
      continue;
    }
    if (::connect(fd, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0) {
      reachable = true;
    } else if (would_block()) {
      fd_set writable;
      FD_ZERO(&writable);
      FD_SET(fd, &writable);
      timeval tv{};
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = static_cast<long>(timeout_ms % 1000) * 1000;
      if (::select(0, nullptr, &writable, nullptr, &tv) > 0 && FD_ISSET(fd, &writable) &&
          socket_error_code(fd) == 0) {
        reachable = true;
      }
    }
    close_sock(fd);
  }
  ::freeaddrinfo(res);
  return reachable;
}

}  // namespace netcap
