// tunpipe.hpp - the piece that makes a TUN takeover useful: it terminates the
// connections that arrive on the tunnel in user space (pktflow) and relays them
// to the real world through ordinary sockets, asking the rule set first.
//
// Design:
//   * one thread, no threads at all: the caller feeds packets and calls poll()
//   * the client side never sees a socket; pktflow answers handshakes and ACKs
//   * the upstream side is a plain non-blocking socket, optionally chained
//     through an HTTP CONNECT proxy (that is how a takeover survives on a
//     machine whose internet access goes through Clash or a corporate proxy)
//   * a flow is only decided once we have something to decide on (an HTTP
//     request head or a TLS client hello), and an undecidable stream is always
//     forwarded rather than blocked
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/h3.hpp"
#include "netcap/packet.hpp"
#include "netcap/pktflow.hpp"
#include "netcap/rules.hpp"

namespace netcap {

struct RelayStats {
  u64 flows = 0;           ///< flows that carried data and were looked at
  u64 forwarded = 0;       ///< opened an upstream connection
  u64 blocked = 0;         ///< answered locally with the block page
  u64 redirected = 0;      ///< answered locally with a redirect
  u64 reset = 0;           ///< killed with a reset (TLS streams cannot be shown a page)
  u64 undecided = 0;       ///< still waiting to see the first complete request
  u64 http_inspected = 0;  ///< decisions made on a cleartext request head
  u64 tls_inspected = 0;   ///< decisions made on a TLS client hello
  u64 quic_inspected = 0;  ///< 1-RTT QUIC packets opened with a key-log secret
  u64 quic_blocked = 0;    ///< HTTP/3 requests a URL rule refused
  u64 quic_rewritten = 0;  ///< HTTP/3 requests edited inside the same datagram
  u64 bytes_up = 0;        ///< bytes sent towards the origin
  u64 bytes_down = 0;      ///< bytes sent back to the client
  u64 upstream_opened = 0;
  u64 upstream_failed = 0;  ///< connect refused, DNS-free failure, chain error
  u64 upstream_eof = 0;
  u64 connect_timeouts = 0;
  u64 dropped = 0;  ///< UDP (or an aborted flow) we answered by silence
  std::string describe() const;
};

/// Supplies the 1-RTT secrets of a QUIC connection, keyed by the connection id
/// its first Initial carried.  Implemented in main.cpp on top of the browser key
/// log (`quickeys`); tunpipe only needs this interface, so it stays testable
/// without a browser and without touching the user's environment.
class QuicKeysProvider {
 public:
  virtual ~QuicKeysProvider() = default;

  /// Fills the client-side and server-side 1-RTT key sets for `original_dcid`.
  /// False means "this connection is not in the log (yet)": the packet is then
  /// forwarded untouched rather than guessed at.
  virtual bool keys_for(const Bytes& original_dcid, u16* suite, QuicKeyset* client,
                        QuicKeyset* server, std::string* why) = 0;
};

struct RelayConfig {
  int version = 4;                 ///< 4 or 6, the family of the tunnel address
  u8 local[16] = {0};              ///< our address on the tunnel
  std::size_t mtu = 1500;          ///< MSS is derived from this
  std::size_t max_flows = 4096;    ///< engine table size
  const RuleSet* rules = nullptr;  ///< may be null: then nothing is ever blocked
  std::string chain_host;          ///< optional upstream HTTP proxy (CONNECT)
  u16 chain_port = 0;
  i64 connect_timeout_us = 10000000;  ///< 10 s to reach the origin or the chain
  bool answer_icmp_echo = true;       ///< ping on the tunnel interface
  bool chain_udp = false;             ///< reserved: UDP is never chained today
  /// Forward UDP straight to its destination.  Only safe while the default route
  /// still points at the physical network: once a TUN owns that route, a plain
  /// UDP socket aims at the tunnel itself and the datagram comes back, so the
  /// takeover switches this off and drops UDP instead (counted in stats).
  bool forward_udp = true;
  /// Interface forwarded UDP has to leave through.  Once the tunnel owns the
  /// default route, an unbound UDP socket aims its datagram straight back into
  /// the tunnel, so the socket is pinned (IP_UNICAST_IF / IPV6_UNICAST_IF, or
  /// SO_BINDTOIFINDEX) before it is connected.  0 means "unknown", in which case
  /// UDP is dropped - never looped.
  std::uint32_t physical_ifindex = 0;
  /// Our own tunnel interface; pinning UDP to it would loop.
  std::uint32_t tunnel_ifindex = 0;
  /// Optional: where the 1-RTT QUIC secrets come from (the browser key log).
  /// Null means QUIC is forwarded without being inspected, like before.
  QuicKeysProvider* quic_keys = nullptr;
};

class TunPipe {
 public:
  explicit TunPipe(const RelayConfig& config);
  ~TunPipe();
  TunPipe(const TunPipe&) = delete;
  TunPipe& operator=(const TunPipe&) = delete;

  /// One IP packet that arrived from the tunnel. Answers are appended to `out`.
  void on_packet(const u8* ip, std::size_t len, i64 now_us, std::vector<Packet>* out);

  /// Wait up to timeout_ms for upstream sockets and move bytes both ways.
  /// Returns immediately when there is nothing upstream to wait for.
  void poll(int timeout_ms, i64 now_us, std::vector<Packet>* out);

  /// Retransmits, idle expiry and connect timeouts. Call this even when no
  /// packet arrived.
  void tick(i64 now_us, std::vector<Packet>* out);

  void stop();

  const RelayStats& stats() const;
  const PacketEngine& engine() const;
  PacketEngine& engine();
  std::size_t pipe_count() const;
  std::string describe() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

/// Opens one TCP connection to `host:port` and closes it again: true when
/// something answers there.  The takeover refuses to point the default route at
/// the tunnel unless the chain answers, because a TUN with a dead upstream
/// leaves the machine without a network.
bool tunpipe_chain_reachable(const std::string& host, std::uint16_t port, int timeout_ms);

}  // namespace netcap
