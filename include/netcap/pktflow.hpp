// Userspace IP packet engine: the piece that turns the raw IP packets coming out
// of a Wintun tunnel into flows an application can read and write.
//
// Design rules, because this is the layer that decides whether a machine keeps
// its network:
//   * No OS sockets are involved: IPv4/IPv6, TCP and UDP are built and parsed here.
//   * No wall clock of its own - the caller passes `now_us`, so timers are
//     testable without sleeping.
//   * Fixed tables and byte caps: the tunnel is fed by whatever the machine (or
//     an attacker on it) decides to send, so nothing here may grow unbounded.
//   * Checksums are always written, and (optionally) verified on the way in.
//
// Deliberately NOT implemented yet, and each one is a hard boundary rather than
// an oversight: TCP options on our segments (no MSS/window-scale/timestamps),
// window scaling, SACK, path MTU discovery, out-of-order reassembly (a gap is
// ACKed and the peer retransmits), and IPv6 fragments/extension-header chains
// beyond the header walk in ip_parse().
#ifndef NETCAP_PKTFLOW_HPP
#define NETCAP_PKTFLOW_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/dissect.hpp"  // TCP_FIN/TCP_SYN/... (declared there, not repeated here)
#include "netcap/flow.hpp"
#include "netcap/packet.hpp"

namespace netcap {

// crypto.hpp declares the same alias; it is repeated here so that this header
// stays free of any dependency on the crypto stack.
using Bytes = std::vector<u8>;

std::string tcp_flags_text(std::uint8_t flags);

// ---------------------------------------------------------------------------
// Sequence arithmetic: all of it modulo 2^32 (RFC 1982 style), so a flow that
// crosses the wrap point keeps working.
// ---------------------------------------------------------------------------
inline bool seq_lt(u32 a, u32 b) noexcept { return static_cast<std::int32_t>(a - b) < 0; }
inline bool seq_le(u32 a, u32 b) noexcept { return static_cast<std::int32_t>(a - b) <= 0; }
inline bool seq_gt(u32 a, u32 b) noexcept { return static_cast<std::int32_t>(a - b) > 0; }
inline bool seq_ge(u32 a, u32 b) noexcept { return static_cast<std::int32_t>(a - b) >= 0; }
inline u32 seq_add(u32 seq, std::size_t n) noexcept { return seq + static_cast<u32>(n); }
/// Distance from `a` to `b` assuming `b` is ahead of `a` (0 when it is behind).
inline u32 seq_distance(u32 a, u32 b) noexcept { return static_cast<u32>(b - a); }

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------
struct IpHeader {
  int version = 0;
  std::uint8_t protocol = 0;
  std::uint8_t ttl = 0;
  std::uint8_t src[16] = {};
  std::uint8_t dst[16] = {};
  std::size_t header_len = 0;   ///< 20 for IPv4 (with options), 40+ for IPv6
  std::size_t total_len = 0;    ///< bytes the packet claims, clamped to what we got
  std::size_t payload_len = 0;  ///< total_len - header_len
  std::uint16_t id = 0;         ///< IPv4 identification
  std::uint8_t traffic_class = 0;
  std::uint32_t flow_label = 0;
  std::string source() const;
  std::string destination() const;
};

struct TcpHeader {
  std::uint16_t sport = 0;
  std::uint16_t dport = 0;
  u32 seq = 0;
  u32 ack = 0;
  std::uint8_t flags = 0;
  std::uint16_t window = 0;
  std::uint16_t urgent = 0;
  std::size_t header_len = 0;
};

struct UdpHeader {
  std::uint16_t sport = 0;
  std::uint16_t dport = 0;
  std::uint16_t length = 0;
};

std::size_t ip_header_len(int version) noexcept;  // 20 / 40, 0 when unknown
/// Parses an IPv4 or IPv6 header. Rejects truncation and nonsense lengths.
bool ip_parse(const std::uint8_t* data, std::size_t len, IpHeader* out);
bool tcp_parse(const std::uint8_t* data, std::size_t len, TcpHeader* out);
bool udp_parse(const std::uint8_t* data, std::size_t len, UdpHeader* out);

/// RFC 1071 checksum of one IP header (called with the checksum field zeroed).
u16 ip_checksum_v4(const std::uint8_t* header, std::size_t len);
/// TCP/UDP checksum over the pseudo header plus the segment. A correct packet
/// verifies to 0, so inbound packets are checked with `!= 0`.
u16 transport_checksum(const std::uint8_t* src, const std::uint8_t* dst, int version,
                       std::uint8_t protocol, const std::uint8_t* segment, std::size_t len);

/// Builders. `out`/`cap` are checked; they return the number of bytes written
/// (0 when the buffer is too small).
std::size_t ipv4_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[4],
                       const std::uint8_t dst[4], std::uint8_t protocol, u16 id,
                       const std::uint8_t* payload, std::size_t payload_len);
std::size_t ipv6_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[16],
                       const std::uint8_t dst[16], std::uint8_t protocol,
                       const std::uint8_t* payload, std::size_t payload_len);
/// Writes a TCP segment (header + payload) with a correct checksum.
std::size_t tcp_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[16],
                      const std::uint8_t dst[16], int version, u16 sport, u16 dport,
                      u32 seq, u32 ack, std::uint8_t flags, u16 window,
                      const std::uint8_t* payload, std::size_t payload_len);
/// Writes a UDP datagram (header + payload) with a correct checksum. Per RFC 768
/// a computed zero is transmitted as 0xffff.
std::size_t udp_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[16],
                      const std::uint8_t dst[16], int version, u16 sport, u16 dport,
                      const std::uint8_t* payload, std::size_t payload_len);
/// Turns an ICMPv4/v6 echo request into its reply (same body, type flipped).
std::size_t icmp_echo_reply(std::uint8_t* out, std::size_t cap, const std::uint8_t* icmp,
                            std::size_t len);
int icmp_echo_type(int version, bool reply);  // 8/0 or 128/129

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------
// Endpoints and the canonical connection key already exist for the capture
// analyzer; the engine reuses them instead of inventing a second spelling of
// "address + port" (see flow.hpp). `FlowKey` is the sorted pair, so both
// directions of a connection land on one record; the direction we care about
// (who opened the flow) is kept next to it in `client` / `server`.
enum class FlowProto : std::uint8_t { Tcp = 6, Udp = 17 };

const char* flow_proto_name(FlowProto p);

enum class TcpState : std::uint8_t {
  SynReceived,  ///< we sent SYN|ACK, the client has not confirmed yet
  Established,
  PeerClosed,   ///< the client sent FIN, we still may send
  Closing,      ///< both sides sent FIN
  TimeWait,
  Reset,
};

const char* tcp_state_name(TcpState s);

struct FlowStats {
  u64 packets_in = 0;
  u64 packets_out = 0;
  u64 bytes_in = 0;
  u64 bytes_out = 0;
  u64 retransmits = 0;
  u64 duplicates = 0;     ///< data we had already seen
  u64 out_of_order = 0;   ///< gaps: ACKed but dropped, the peer retransmits
  u64 resets = 0;
};

struct EngineStats {
  u64 packets_in = 0;
  u64 packets_out = 0;
  u64 bytes_in = 0;
  u64 bytes_out = 0;
  u64 malformed = 0;      ///< header/length garbage
  u64 bad_checksum = 0;   ///< dropped because the checksum did not verify
  u64 unsupported = 0;    ///< protocol we do not carry (ICMP when disabled, ...)
  u64 refused = 0;        ///< a flow we would not open (no SYN / table full)
  u64 icmp_replies = 0;
  u64 tcp_opened = 0;
  u64 tcp_established = 0;
  u64 tcp_closed = 0;
  u64 udp_opened = 0;
  u64 expired = 0;        ///< idle or out of retries
  u64 retransmits = 0;
  std::string describe() const;
};

struct PacketEngineConfig {
  int version = 4;           ///< the tunnel's address family
  std::uint8_t local[16] = {};  ///< our address on the tunnel (where packets are addressed to)
  std::size_t mtu = 1500;
  std::size_t max_flows = 4096;
  std::size_t max_flow_buffer = 1u << 20;  ///< bytes held per flow (receive + send)
  i64 tcp_idle_us = 300ll * 1000000ll;
  i64 udp_idle_us = 60ll * 1000000ll;
  i64 retransmit_us = 300000;  ///< 300 ms
  int max_retries = 8;
  bool verify_checksums = true;
  bool answer_icmp_echo = true;
  u16 window = 65535;        ///< what we advertise (no window scaling)
};

class PacketEngine {
 public:
  explicit PacketEngine(const PacketEngineConfig& cfg = PacketEngineConfig());

  void reset();
  const PacketEngineConfig& config() const { return cfg_; }
  void set_config(const PacketEngineConfig& cfg) { cfg_ = cfg; }

  /// One inbound IP packet straight from the tunnel. Packets we want to send
  /// back are appended to `out` (nothing appended means "no answer").
  void feed(const std::uint8_t* ip, std::size_t len, i64 now_us, std::vector<Packet>* out);
  /// Timers: retransmissions and idle expiry. Call it on every read timeout.
  void tick(i64 now_us, std::vector<Packet>* out);

  /// What an application needs to know about one flow.
  struct FlowView {
    u64 id = 0;
    Endpoint client;
    Endpoint server;
    FlowProto proto = FlowProto::Tcp;
    TcpState state = TcpState::SynReceived;
    bool established = false;
    bool closed = false;
    std::size_t buffered = 0;   ///< receive bytes waiting for a read()
    std::size_t unsent = 0;     ///< bytes written but not yet acknowledged
    FlowStats stats;
    i64 created_us = 0;
    i64 last_us = 0;
    std::string text() const;  ///< "10.0.0.5:51000 -> 93.184.216.34:443 tcp"
    std::string describe() const;
  };

  std::vector<FlowView> flows() const;
  bool flow(u64 id, FlowView* out) const;
  std::size_t flow_count() const;

  /// Reads and clears the buffered receive bytes of one flow.
  bool read(u64 id, Bytes* out);
  /// Queues bytes towards the client: segments them by MTU and emits the packets.
  bool write(u64 id, const Bytes& data, i64 now_us, std::vector<Packet>* out);
  /// Half-close: emits FIN.
  bool close_flow(u64 id, i64 now_us, std::vector<Packet>* out);
  /// Emits RST and forgets the flow.
  bool abort_flow(u64 id, i64 now_us, std::vector<Packet>* out);

  const EngineStats& stats() const { return stats_; }
  std::string describe() const;

  /// Payload bytes we will put in one segment, given the MTU.
  std::size_t max_segment_payload() const;

 private:
  struct Segment {
    u32 seq = 0;
    Bytes data;
    i64 next_try_us = 0;
    int tries = 0;
    bool syn = false;
    bool fin = false;
  };
  struct TcpFlow {
    u64 id = 0;
    FlowKey key;          ///< canonical (sorted) key used for the lookup
    Endpoint client;      ///< whoever sent the SYN
    Endpoint server;      ///< us, on the tunnel address
    TcpState state = TcpState::SynReceived;
    u32 isn = 0;       ///< our initial sequence number (the SYN consumes it)
    u32 snd_una = 0;   ///< oldest byte we are still waiting to see acknowledged
    u32 snd_nxt = 0;
    u32 rcv_nxt = 0;
    u16 peer_window = 0;
    Bytes rx;
    std::vector<Segment> unacked;
    bool we_fin = false;
    bool peer_fin = false;
    FlowStats stats;
    i64 created_us = 0;
    i64 last_us = 0;
    std::size_t unsent_bytes() const;
  };
  struct UdpFlow {
    u64 id = 0;
    FlowKey key;
    Endpoint client;
    Endpoint server;
    Bytes rx;
    FlowStats stats;
    i64 created_us = 0;
    i64 last_us = 0;
  };

  void handle_tcp(const IpHeader& h, const std::uint8_t* segment, std::size_t len,
                  i64 now_us, std::vector<Packet>* out);
  void handle_udp(const IpHeader& h, const std::uint8_t* datagram, std::size_t len,
                  i64 now_us, std::vector<Packet>* out);
  void handle_icmp(const IpHeader& h, const std::uint8_t* message, std::size_t len,
                   i64 now_us, std::vector<Packet>* out);

  void emit_tcp(TcpFlow& f, u32 seq, u32 ack, std::uint8_t flags,
                const std::uint8_t* payload, std::size_t payload_len, i64 now_us,
                std::vector<Packet>* out);
  void emit_udp(UdpFlow& f, const std::uint8_t* payload, std::size_t payload_len,
                i64 now_us, std::vector<Packet>* out);
  std::size_t wrap_and_emit(const std::uint8_t* l4, std::size_t l4_len, std::uint8_t protocol,
                            const std::uint8_t* src, const std::uint8_t* dst, i64 now_us,
                            std::vector<Packet>* out);
  /// RFC 793 RST for a segment that does not belong to any flow: the sequence
  /// number is the peer's acknowledgement (or zero when it did not acknowledge
  /// anything), and we acknowledge everything it sent.
  void emit_rst(const IpHeader& h, const TcpHeader& t, std::size_t payload_len, i64 now_us,
                std::vector<Packet>* out);
  void queue_segment(TcpFlow& f, u32 seq, const std::uint8_t* payload, std::size_t len,
                     bool syn, bool fin, i64 now_us);
  u32 next_isn() noexcept { return isn_ += 0x9e3779b9u; }

  PacketEngineConfig cfg_;
  EngineStats stats_;
  u64 next_flow_id_ = 1;
  u32 isn_ = 0x1f2e3d4cu;
  u16 ip_id_ = 0;
  std::map<FlowKey, TcpFlow> tcp_;
  std::map<FlowKey, UdpFlow> udp_;
  std::vector<std::uint8_t> scratch_;
};

}  // namespace netcap

#endif  // NETCAP_PKTFLOW_HPP
