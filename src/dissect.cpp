#include "netcap/dissect.hpp"

#include <cstring>

namespace netcap {

namespace {

constexpr u16 ETH_IPV4 = 0x0800;
constexpr u16 ETH_ARP = 0x0806;
constexpr u16 ETH_RARP = 0x8035;
constexpr u16 ETH_IPV6 = 0x86dd;
constexpr u16 ETH_VLAN = 0x8100;
constexpr u16 ETH_QINQ = 0x88a8;
constexpr u16 ETH_VLAN_9100 = 0x9100;

// IPv6 extension headers that carry a "next header" chain.
bool ipv6_ext_header(u8 nh) {
  switch (nh) {
    case 0:    // hop-by-hop options
    case 43:   // routing
    case 44:   // fragment
    case 51:   // authentication header
    case 60:   // destination options
    case 135:  // mobility
      return true;
    default:
      return false;
  }
}

}  // namespace

const char* l4_name(L4 p) {
  switch (p) {
    case L4::None: return "NONE";
    case L4::Icmp: return "ICMP";
    case L4::Igmp: return "IGMP";
    case L4::Tcp: return "TCP";
    case L4::Udp: return "UDP";
    case L4::Gre: return "GRE";
    case L4::Esp: return "ESP";
    case L4::Ah: return "AH";
    case L4::Icmpv6: return "ICMPv6";
    case L4::Sctp: return "SCTP";
    default: return "IP";
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

bool Dissector::dissect(const PacketView& pkt, PacketInfo& out) {
  out = PacketInfo();
  out.frame_len = pkt.len;
  last_result_ = DissectResult::Ok;
  if (pkt.empty()) {
    out.malformed = true;
    out.malformed_reason = "empty capture";
    last_result_ = DissectResult::Malformed;
    return false;
  }
  const bool ok = dissect_link(pkt, out);
  if (out.malformed) last_result_ = DissectResult::Malformed;
  else if (out.is_fragment && !out.reassembled) last_result_ = DissectResult::Fragment;
  return ok;
}

bool Dissector::dissect_link(const PacketView& pkt, PacketInfo& out) {
  const u8* p = pkt.data;
  const std::size_t len = pkt.len;
  switch (pkt.linktype) {
    case DLT_EN10MB:
      return dissect_ethernet(p, len, out);
    case DLT_RAW:
    case DLT_IPV4:
    case DLT_IPV6:
      out.l3_offset = 0;
      return dissect_l3(p, len, out);
    case DLT_NULL:
      return dissect_null(p, len, out);
    case DLT_LINUX_SLL:
    case DLT_LINUX_SLL2:
      return dissect_sll(p, len, out);
    default:
      out.malformed = true;
      out.malformed_reason = "unsupported link type";
      return false;
  }
}

bool Dissector::dissect_ethernet(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 14) {
    out.malformed = true;
    out.malformed_reason = "runt ethernet frame";
    return false;
  }
  out.has_eth = true;
  std::memcpy(out.dst_mac, p, 6);
  std::memcpy(out.src_mac, p + 6, 6);
  u16 type = rd16be(p + 12);
  std::size_t off = 14;

  // Up to two stacked VLAN tags (802.1Q / 802.1ad) then the real ethertype.
  if (type == ETH_VLAN || type == ETH_QINQ || type == ETH_VLAN_9100) {
    if (len < off + 4) {
      out.malformed = true;
      out.malformed_reason = "truncated vlan tag";
      return false;
    }
    const u16 tci = rd16be(p + off);
    out.has_vlan = true;
    out.vlan_priority = u16((tci >> 13) & 0x7);
    out.vlan_id = u16(tci & 0x0fff);
    type = rd16be(p + off + 2);
    out.inner_ethertype = type;
    off += 4;

    if (type == ETH_VLAN || type == ETH_QINQ || type == ETH_VLAN_9100) {
      if (len < off + 4) {
        out.malformed = true;
        out.malformed_reason = "truncated inner vlan tag";
        return false;
      }
      type = rd16be(p + off + 2);
      out.inner_ethertype = type;
      off += 4;
    }
  }
  out.ethertype = type;
  out.l3_offset = off;

  switch (type) {
    case ETH_ARP:
    case ETH_RARP:
      return dissect_arp(p + off, len - off, out);
    case ETH_IPV4:
    case ETH_IPV6:
      return dissect_l3(p + off, len - off, out);
    default:
      out.malformed = true;
      out.malformed_reason = "non-IP ethertype";
      return false;
  }
}

bool Dissector::dissect_sll(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 16) {
    out.malformed = true;
    out.malformed_reason = "runt cooked header";
    return false;
  }
  // DLT_LINUX_SLL: pkttype(2) hatype(2) halen(2) addr(8) protocol(2)
  const u16 halen = rd16be(p + 4);
  if (halen == 6) std::memcpy(out.src_mac, p + 6, 6);
  const u16 proto = rd16be(p + 14);
  out.ethertype = proto;
  out.l3_offset = 16;
  if (proto == ETH_IPV4 || proto == ETH_IPV6) return dissect_l3(p + 16, len - 16, out);
  if (proto == ETH_ARP) return dissect_arp(p + 16, len - 16, out);
  out.malformed = true;
  out.malformed_reason = "non-IP cooked frame";
  return false;
}

bool Dissector::dissect_null(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 4) {
    out.malformed = true;
    out.malformed_reason = "runt null header";
    return false;
  }
  const u32 le = rd32le(p);
  const u32 be = rd32be(p);
  u32 fam = le;
  auto known = [](u32 f) { return f == 2 || f == 10 || f == 23 || f == 24 || f == 28 || f == 30; };
  if (!known(le) && known(be)) fam = be;
  out.l3_offset = 4;
  if (fam == 2) return dissect_l3(p + 4, len - 4, out);
  if (fam == 10 || fam == 23 || fam == 24 || fam == 28 || fam == 30) return dissect_l3(p + 4, len - 4, out);
  out.malformed = true;
  out.malformed_reason = "unknown loopback family";
  return false;
}

bool Dissector::dissect_l3(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 1) {
    out.malformed = true;
    out.malformed_reason = "empty L3";
    return false;
  }
  const u8 version = u8(p[0] >> 4);
  if (version == 4) return dissect_ipv4(p, len, out);
  if (version == 6) return dissect_ipv6(p, len, out);
  out.malformed = true;
  out.malformed_reason = "unknown IP version";
  return false;
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

bool Dissector::dissect_ipv4(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 20) {
    out.malformed = true;
    out.malformed_reason = "runt IPv4 header";
    return false;
  }
  const std::size_t ihl = std::size_t(p[0] & 0x0f) * 4;
  if (ihl < 20 || ihl > len) {
    out.malformed = true;
    out.malformed_reason = "bad IPv4 IHL";
    return false;
  }
  out.ip_version = 4;
  out.l3_tos = p[1];
  const u16 total = rd16be(p + 2);
  out.l3_len = total;
  out.l3_id = rd16be(p + 4);
  const u16 ff = rd16be(p + 6);
  out.l3_df = (ff & 0x4000) != 0;
  out.l3_mf = (ff & 0x2000) != 0;
  out.l3_frag_off = u16(ff & 0x1fff);
  out.l3_hoplimit = p[8];
  out.l3_proto = p[9];
  std::memcpy(out.src_ip, p + 12, 4);
  std::memcpy(out.dst_ip, p + 16, 4);

  // Trust whichever is smaller: the wire length or the header's own claim.
  std::size_t avail = len - ihl;
  if (total >= ihl) {
    const std::size_t claimed = std::size_t(total) - ihl;
    if (claimed < avail) avail = claimed;
  } else {
    out.malformed = true;
    out.malformed_reason = "IPv4 total length < header length";
    return false;
  }
  const u8* payload = p + ihl;
  out.l4_offset = out.l3_offset + ihl;

  const bool frag = out.l3_mf || out.l3_frag_off != 0;
  if (frag) {
    out.is_fragment = true;
    if (!reassembly_) {
      out.malformed = false;
      return true;
    }
    const i64 now = now_monotonic_us();
    if (feed_fragment(payload, avail, out.l3_frag_off, out.l3_mf, out, now)) {
      out.reassembled = true;
      out.payload = nullptr;
      out.payload_len = 0;
      return dissect_l4(scratch_.data(), scratch_.size(), out);
    }
    return true;  // stored, waiting for the rest
  }

  return dissect_l4(payload, avail, out);
}

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

bool Dissector::dissect_ipv6(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 40) {
    out.malformed = true;
    out.malformed_reason = "runt IPv6 header";
    return false;
  }
  out.ip_version = 6;
  const u32 fl = rd32be(p);
  out.l3_tos = u8((fl >> 20) & 0xff);
  out.l3_len = rd16be(p + 4);
  u8 nh = p[6];
  out.ipv6_next_header = nh;
  out.l3_hoplimit = p[7];
  std::memcpy(out.src_ip, p + 8, 16);
  std::memcpy(out.dst_ip, p + 24, 16);

  std::size_t off = 40;
  std::size_t limit = len;
  if (out.l3_len != 0) {
    const std::size_t claimed = std::size_t(out.l3_len) + 40;
    if (claimed < limit) limit = claimed;
  }

  // Walk the extension header chain.
  int guard = 0;
  while (ipv6_ext_header(nh) && ++guard < 16) {
    if (off + 2 > limit) {
      out.malformed = true;
      out.malformed_reason = "truncated IPv6 extension header";
      return false;
    }
    const u8 next = p[off];
    std::size_t ext_len;
    if (nh == 51) {  // AH: length in 4-byte units, excluding the first 8 bytes
      ext_len = (std::size_t(p[off + 1]) + 2) * 4;
    } else if (nh == 44) {  // fragment header: fixed 8 bytes
      ext_len = 8;
      if (off + 8 > limit) {
        out.malformed = true;
        out.malformed_reason = "truncated IPv6 fragment header";
        return false;
      }
      const u16 fo = rd16be(p + off + 2);
      const u16 frag_off = u16((fo >> 3) & 0x1fff);
      const bool more = (fo & 0x1) != 0;
      out.l3_frag_off = frag_off;
      out.l3_mf = more;
      out.is_fragment = true;
      if (!reassembly_) return true;
      const std::size_t plen = limit - (off + 8);
      const i64 now = now_monotonic_us();
      if (feed_fragment(p + off + 8, plen, frag_off, more, out, now)) {
        out.reassembled = true;
        return dissect_l4(scratch_.data(), scratch_.size(), out);
      }
      return true;
    } else {  // hop-by-hop / routing / destination options: (len+1)*8
      ext_len = (std::size_t(p[off + 1]) + 1) * 8;
    }
    if (ext_len < 8 || off + ext_len > limit) {
      out.malformed = true;
      out.malformed_reason = "bad IPv6 extension header length";
      return false;
    }
    nh = next;
    off += ext_len;
  }
  out.l3_proto = nh;
  out.l4_offset = out.l3_offset + off;
  return dissect_l4(p + off, limit - off, out);
}

// ---------------------------------------------------------------------------
// ARP
// ---------------------------------------------------------------------------

bool Dissector::dissect_arp(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 28) {
    out.malformed = true;
    out.malformed_reason = "runt ARP";
    return false;
  }
  const u16 htype = rd16be(p);
  const u16 ptype = rd16be(p + 2);
  const u8 hlen = p[4];
  const u8 plen = p[5];
  out.arp_op = rd16be(p + 6);
  out.is_arp = true;
  if (htype == 1 && ptype == ETH_IPV4 && hlen == 6 && plen == 4) {
    std::memcpy(out.arp_sha, p + 8, 6);
    out.arp_spa = rd32be(p + 14);
    std::memcpy(out.arp_tha, p + 18, 6);
    out.arp_tpa = rd32be(p + 24);
  }
  out.ip_version = 0;
  out.l4 = L4::None;
  return true;
}

// ---------------------------------------------------------------------------
// L4 dispatch
// ---------------------------------------------------------------------------

bool Dissector::dissect_l4(const u8* p, std::size_t len, PacketInfo& out) {
  out.payload = nullptr;
  out.payload_len = 0;
  switch (out.l3_proto) {
    case 6:
      out.l4 = L4::Tcp;
      return dissect_tcp(p, len, out);
    case 17:
      out.l4 = L4::Udp;
      return dissect_udp(p, len, out);
    case 1:
      out.l4 = L4::Icmp;
      break;
    case 58:
      out.l4 = L4::Icmpv6;
      break;
    case 2:
      out.l4 = L4::Igmp;
      break;
    case 47:
      out.l4 = L4::Gre;
      break;
    case 50:
      out.l4 = L4::Esp;
      break;
    case 51:
      out.l4 = L4::Ah;
      break;
    case 132:
      out.l4 = L4::Sctp;
      break;
    default:
      out.l4 = L4::Other;
      break;
  }
  if (out.l4 == L4::Icmp || out.l4 == L4::Icmpv6) {
    if (len < 4) {
      out.malformed = true;
      out.malformed_reason = "runt ICMP";
      return false;
    }
    out.icmp.type = p[0];
    out.icmp.code = p[1];
    if (len >= 8) out.icmp.rest = rd32be(p + 4);
    // Only error/echo messages carry a meaningful embedded payload.
    if ((out.l4 == L4::Icmp && (p[0] == 3 || p[0] == 5 || p[0] == 11 || p[0] == 12)) ||
        (out.l4 == L4::Icmpv6 && p[0] < 128)) {
      out.payload = p + 8;
      out.payload_len = len - 8;
    }
    return true;
  }
  if (len > 0) {
    out.payload = p;
    out.payload_len = len;
  }
  return true;
}

bool Dissector::dissect_tcp(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 20) {
    out.malformed = true;
    out.malformed_reason = "runt TCP header";
    return false;
  }
  out.has_ports = true;
  out.src_port = rd16be(p);
  out.dst_port = rd16be(p + 2);
  out.tcp.seq = rd32be(p + 4);
  out.tcp.ack = rd32be(p + 8);
  const std::size_t doff = std::size_t(p[12] >> 4) * 4;
  out.tcp.header_len = u16(doff);
  out.tcp.flags = p[13];
  out.tcp.window = rd16be(p + 14);
  out.tcp.urgent = rd16be(p + 18);

  if (doff > len) {
    out.malformed = true;
    out.malformed_reason = "TCP data offset beyond segment";
    // Still expose the fixed header, but no payload.
    return false;
  }
  if (doff > 20) dissect_tcp_options(p + 20, doff - 20, out.tcp);
  out.payload = p + doff;
  out.payload_len = len - doff;
  return true;
}

void Dissector::dissect_tcp_options(const u8* p, std::size_t len, TcpInfo& t) {
  std::size_t i = 0;
  while (i < len) {
    const u8 kind = p[i];
    if (kind == 0) break;  // EOL
    if (kind == 1) {       // NOP
      ++i;
      continue;
    }
    if (i + 1 >= len) break;
    const u8 olen = p[i + 1];
    if (olen < 2 || i + olen > len) break;
    switch (kind) {
      case 2:  // MSS
        if (olen == 4) {
          t.mss = rd16be(p + i + 2);
          t.has_mss = true;
        }
        break;
      case 3:  // window scale
        if (olen == 3) {
          t.window_scale = p[i + 2];
          t.has_window_scale = true;
        }
        break;
      case 4:  // SACK permitted
        t.sack_permitted = true;
        break;
      case 8:  // timestamps
        if (olen == 10) {
          t.ts_val = rd32be(p + i + 2);
          t.ts_ecr = rd32be(p + i + 6);
          t.has_timestamp = true;
        }
        break;
      default:
        break;
    }
    i += olen;
  }
}

bool Dissector::dissect_udp(const u8* p, std::size_t len, PacketInfo& out) {
  if (len < 8) {
    out.malformed = true;
    out.malformed_reason = "runt UDP header";
    return false;
  }
  out.has_ports = true;
  out.src_port = rd16be(p);
  out.dst_port = rd16be(p + 2);
  const u16 ulen = rd16be(p + 4);
  std::size_t plen = len - 8;
  if (ulen >= 8 && std::size_t(ulen) - 8 < plen) plen = std::size_t(ulen) - 8;
  out.payload = p + 8;
  out.payload_len = plen;
  return true;
}

// ---------------------------------------------------------------------------
// IPv4 fragment reassembly
// ---------------------------------------------------------------------------

std::string Dissector::frag_key(const PacketInfo& pi) {
  std::string k;
  k.resize(1 + 1 + 2 + 16 + 16);
  std::size_t i = 0;
  k[i++] = char(pi.ip_version);
  k[i++] = char(pi.l3_proto);
  k[i++] = char(pi.l3_id >> 8);
  k[i++] = char(pi.l3_id & 0xff);
  std::memcpy(&k[i], pi.src_ip, 16);
  i += 16;
  std::memcpy(&k[i], pi.dst_ip, 16);
  return k;
}

bool Dissector::feed_fragment(const u8* frag, std::size_t frag_len, u16 frag_off_units,
                              bool more, const PacketInfo& out, i64 now_us) {
  const std::size_t offset = std::size_t(frag_off_units) * 8;
  if (frag_len == 0 || offset + frag_len > max_datagram_) {
    ++frag_dropped_;
    return false;
  }

  const std::string key = frag_key(out);
  auto it = frags_.find(key);
  if (it == frags_.end()) {
    if (frags_.size() >= max_entries_) {
      // Evict the oldest entry rather than growing without bound.
      auto oldest = frags_.begin();
      for (auto i2 = frags_.begin(); i2 != frags_.end(); ++i2) {
        if (i2->second.last_us < oldest->second.last_us) oldest = i2;
      }
      frags_.erase(oldest);
      ++frag_dropped_;
    }
    FragEntry e;
    e.first_us = now_us;
    it = frags_.emplace(key, std::move(e)).first;
    ++frag_seen_;
  }
  FragEntry& e = it->second;
  e.last_us = now_us;

  const std::size_t end = offset + frag_len;
  std::size_t total = e.total;
  if (!more) {
    total = end;  // last fragment nails the datagram length
    e.have_last = true;
  } else if (end > total) {
    total = end;
  }
  if (total > max_datagram_) {
    frags_.erase(it);
    ++frag_dropped_;
    return false;
  }
  if (e.buf.size() < total) {
    e.buf.resize(total, 0);
    e.have.resize((total + 7) / 8, 0);
  }
  e.total = total;

  std::memcpy(e.buf.data() + offset, frag, frag_len);
  const std::size_t first_block = offset / 8;
  const std::size_t nblocks = (frag_len + 7) / 8;
  for (std::size_t b = 0; b < nblocks; ++b) {
    const std::size_t idx = first_block + b;
    if (idx < e.have.size()) e.have[idx] = 1;
  }

  const std::size_t need_blocks = (total + 7) / 8;
  bool complete = e.have_last;
  for (std::size_t b = 0; complete && b < need_blocks; ++b) {
    if (!e.have[b]) {
      complete = false;
      break;
    }
  }
  if (!complete) return false;

  scratch_.assign(e.buf.begin(), e.buf.begin() + static_cast<std::ptrdiff_t>(total));
  frags_.erase(it);
  ++frag_completed_;
  return true;
}

void Dissector::gc(i64 now_us) {
  for (auto it = frags_.begin(); it != frags_.end();) {
    if (now_us - it->second.last_us > frag_timeout_us_) {
      it = frags_.erase(it);
      ++frag_dropped_;
    } else {
      ++it;
    }
  }
}

}  // namespace netcap
