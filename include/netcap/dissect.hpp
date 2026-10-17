// netcap - dissect.hpp
// Hand-written protocol dissector: link layer -> L3 -> L4 -> opaque payload.
//
// The dissector is allocation-free on the fast path except when reassembling
// IPv4 fragments; it never throws and always reports malformed input rather
// than trusting length fields.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "netcap/packet.hpp"

namespace netcap {

/// Transport protocol identity for the packets we care about.
enum class L4 : u8 {
  None = 0,
  Icmp = 1,
  Igmp = 2,
  Tcp = 6,
  Udp = 17,
  Gre = 47,
  Esp = 50,
  Ah = 51,
  Icmpv6 = 58,
  Sctp = 132,
  Other = 255,
};

inline u8 l4_number(L4 p) { return static_cast<u8>(p); }
const char* l4_name(L4 p);

// TCP control bits.
enum : u8 {
  TCP_FIN = 0x01,
  TCP_SYN = 0x02,
  TCP_RST = 0x04,
  TCP_PSH = 0x08,
  TCP_ACK = 0x10,
  TCP_URG = 0x20,
  TCP_ECE = 0x40,
  TCP_CWR = 0x80,
};

struct TcpInfo {
  u32 seq = 0;
  u32 ack = 0;
  u16 window = 0;
  u16 urgent = 0;
  u8 flags = 0;
  u16 header_len = 20;
  u16 mss = 0;
  bool has_mss = false;
  u8 window_scale = 0;
  bool has_window_scale = false;
  bool sack_permitted = false;
  bool has_timestamp = false;
  u32 ts_val = 0;
  u32 ts_ecr = 0;
};

struct IcmpInfo {
  u8 type = 0;
  u8 code = 0;
  u32 rest = 0;  // echo id/seq or the 4-byte "unused/next-hop" word
};

/// Everything the dissector learned about one frame.
struct PacketInfo {
  // ---- link layer ----
  bool has_eth = false;
  u8 dst_mac[6]{};
  u8 src_mac[6]{};
  u16 ethertype = 0;
  bool has_vlan = false;
  u16 vlan_id = 0;
  u16 vlan_priority = 0;
  u16 inner_ethertype = 0;

  // ---- network layer ----
  int ip_version = 0;  // 0, 4 or 6
  u8 src_ip[16]{};
  u8 dst_ip[16]{};
  u8 l3_proto = 0;
  u8 l3_hoplimit = 0;  // TTL (v4) / hop limit (v6)
  u8 l3_tos = 0;       // TOS / traffic class
  u16 l3_len = 0;      // payload+header length claimed by the IP header
  u16 l3_id = 0;       // IPv4 identification
  bool l3_df = false;
  bool l3_mf = false;
  u16 l3_frag_off = 0;  // in 8-byte units, raw header value
  bool is_fragment = false;
  bool reassembled = false;
  u8 ipv6_next_header = 0;

  // ---- ARP ----
  bool is_arp = false;
  u16 arp_op = 0;
  u8 arp_sha[6]{};
  u8 arp_tha[6]{};
  u32 arp_spa = 0;
  u32 arp_tpa = 0;

  // ---- transport layer ----
  L4 l4 = L4::None;
  u16 src_port = 0;
  u16 dst_port = 0;
  TcpInfo tcp{};
  IcmpInfo icmp{};
  bool has_ports = false;

  // ---- payload ----
  const u8* payload = nullptr;  ///< bytes after the transport header
  std::size_t payload_len = 0;
  std::size_t frame_len = 0;  ///< captured frame length as seen at the link layer
  std::size_t l2_offset = 0;
  std::size_t l3_offset = 0;
  std::size_t l4_offset = 0;

  bool malformed = false;
  const char* malformed_reason = nullptr;

  /// "src" or "dst" relative to the local side is not known here; callers label.
  std::string src_addr() const { return format_ip(ip_version, src_ip); }
  std::string dst_addr() const { return format_ip(ip_version, dst_ip); }

  bool is_tcp() const { return l4 == L4::Tcp; }
  bool is_udp() const { return l4 == L4::Udp; }
};

/// Result of feeding a possibly-fragmented datagram to the dissector.
enum class DissectResult {
  Ok,         ///< fully parsed a whole datagram (or a non-IP frame)
  Fragment,   ///< partial IPv4 datagram stored for reassembly
  Malformed,  ///< structurally invalid; PacketInfo explains why
  Unsupported,
};

/// Stateful dissector. One instance per capture stream: it owns the IPv4
/// fragment reassembly table, which is why it must not be shared across
/// threads without external synchronisation.
class Dissector {
 public:
  bool dissect(const PacketView& pkt, PacketInfo& out);
  DissectResult last_result() const { return last_result_; }

  /// Fragment reassembly (on by default). Disabling it makes every fragment
  /// surface as an independent L3 packet with no L4 payload.
  void set_reassembly(bool on) { reassembly_ = on; }
  bool reassembly_enabled() const { return reassembly_; }

  u64 fragments_seen() const { return frag_seen_; }
  u64 fragments_completed() const { return frag_completed_; }
  u64 fragments_dropped() const { return frag_dropped_; }
  std::size_t pending_fragments() const { return frags_.size(); }

  /// Expire reassembly state older than `timeout_us` (default 30 s).
  void gc(i64 now_us);

  void set_fragment_limits(std::size_t max_entries, std::size_t max_datagram_bytes) {
    max_entries_ = max_entries;
    max_datagram_ = max_datagram_bytes;
  }

  /// Scratch buffer holding the last reassembled datagram, valid until the
  /// next dissect() call. Exposed for tests.
  const std::vector<u8>& scratch() const { return scratch_; }

 private:
  struct FragEntry {
    std::vector<u8> buf;   ///< reassembled datagram bytes (L3 payload only)
    std::vector<u8> have;  ///< one flag byte per 8-byte block
    std::size_t total = 0;
    std::size_t filled = 0;
    /// True once the fragment carrying MF=0 has arrived, i.e. once `total`
    /// is authoritative. Without it a lone first fragment would look complete.
    bool have_last = false;
    i64 first_us = 0;
    i64 last_us = 0;
  };

  bool dissect_link(const PacketView& pkt, PacketInfo& out);
  bool dissect_ethernet(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_sll(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_null(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_l3(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_ipv4(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_ipv6(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_arp(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_l4(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_tcp(const u8* p, std::size_t len, PacketInfo& out);
  bool dissect_udp(const u8* p, std::size_t len, PacketInfo& out);
  void dissect_tcp_options(const u8* p, std::size_t len, TcpInfo& t);

  /// Feeds one IPv4 fragment. Returns true when the datagram is now complete,
  /// in which case scratch_ holds the reassembled L3 payload.
  bool feed_fragment(const u8* frag, std::size_t frag_len, u16 frag_off_units, bool more,
                     const PacketInfo& out, i64 now_us);
  static std::string frag_key(const PacketInfo& pi);

  bool reassembly_ = true;
  std::map<std::string, FragEntry> frags_;
  std::vector<u8> scratch_;
  std::size_t max_entries_ = 1024;
  std::size_t max_datagram_ = 1u << 20;  // 1 MiB
  DissectResult last_result_ = DissectResult::Ok;
  u64 frag_seen_ = 0;
  u64 frag_completed_ = 0;
  u64 frag_dropped_ = 0;
  i64 frag_timeout_us_ = 30 * 1000 * 1000;
};

}  // namespace netcap
