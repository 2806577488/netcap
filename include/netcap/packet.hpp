// netcap - packet.hpp
// Packet representations and link-layer type constants.
#pragma once

#include <utility>

#include "netcap/common.hpp"

namespace netcap {

// LINKTYPE_* values from the libpcap/tcpdump registry. We keep the same numeric
// values so files we write are readable by Wireshark/tcpdump and vice versa.
enum : int {
  DLT_NULL = 0,       // BSD loopback: 4-byte host-order AF_ value
  DLT_EN10MB = 1,     // Ethernet II
  DLT_RAW = 12,       // bare IP header (Windows SIO_RCVALL, some VPN tunnels)
  DLT_LINUX_SLL = 113,  // Linux "cooked" v1 (the "any" pseudo-device)
  DLT_IEEE802_11 = 105,
  DLT_LINUX_SLL2 = 276,
  DLT_IPV4 = 228,
  DLT_IPV6 = 229,
};

/// A non-owning view of one captured frame. The pointed-to bytes stay valid only
/// until the next read from the same source, which is what makes zero-copy
/// capture (mmap ring, reused recv buffer) possible.
struct PacketView {
  const u8* data = nullptr;
  std::size_t len = 0;      ///< captured bytes available in `data`
  std::size_t origlen = 0;  ///< bytes on the wire (may exceed len: snaplen cut)
  i64 ts_us = 0;            ///< microseconds since the Unix epoch
  int linktype = DLT_EN10MB;
  u32 ifindex = 0;
  bool truncated = false;   ///< snaplen clipped this frame

  const u8* begin() const { return data; }
  const u8* end() const { return data + len; }
  bool empty() const { return len == 0 || data == nullptr; }
  /// Bytes lost to snaplen truncation.
  std::size_t missing() const { return origlen > len ? origlen - len : 0; }
};

/// Owning packet, used by the offline (pcap file) path where each frame can be
/// handed to the caller independently of the read buffer.
struct Packet {
  std::vector<u8> data;
  std::size_t origlen = 0;
  i64 ts_us = 0;
  int linktype = DLT_EN10MB;
  u32 ifindex = 0;

  PacketView view() const {
    PacketView v;
    v.data = data.data();
    v.len = data.size();
    v.origlen = origlen ? origlen : data.size();
    v.ts_us = ts_us;
    v.linktype = linktype;
    v.ifindex = ifindex;
    v.truncated = v.origlen > v.len;
    return v;
  }
};

/// Human-readable link type name.
const char* linktype_name(int lt);

/// Application protocol guessed by the dissector / app classifier.
enum class AppKind : u8 {
  Unknown = 0,
  Http,
  Tls,
  Dns,
  Quic,
  Ssh,
  Dhcp,
  Mdns,
};

const char* app_kind_name(AppKind k);
/// Uppercase tag used in one-line output, e.g. "HTTP", "TLS", "DNS".
const char* app_kind_tag(AppKind k);

}  // namespace netcap
