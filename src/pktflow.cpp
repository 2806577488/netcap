#include "netcap/pktflow.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace netcap {

namespace {

std::uint16_t p16be(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((std::uint16_t(p[0]) << 8) | p[1]);
}

std::uint32_t p32be(const std::uint8_t* p) noexcept {
  return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) |
         std::uint32_t(p[3]);
}

void put16be(std::uint8_t* p, std::uint16_t v) noexcept {
  p[0] = std::uint8_t(v >> 8);
  p[1] = std::uint8_t(v);
}

void put32be(std::uint8_t* p, std::uint32_t v) noexcept {
  p[0] = std::uint8_t(v >> 24);
  p[1] = std::uint8_t(v >> 16);
  p[2] = std::uint8_t(v >> 8);
  p[3] = std::uint8_t(v);
}

std::string fmt_ip(int version, const std::uint8_t* a) {
  char buf[96];
  if (version == 6) {
    // Compress the longest run of zero groups, the way everyone prints v6.
    std::uint16_t g[8];
    for (int i = 0; i < 8; ++i) g[i] = p16be(a + 2 * i);
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;) {
      if (g[i] != 0) {
        ++i;
        continue;
      }
      int j = i;
      while (j < 8 && g[j] == 0) ++j;
      if (j - i > best_len) {
        best_len = j - i;
        best = i;
      }
      i = j;
    }
    if (best_len < 2) best = -1;
    std::string out;
    for (int i = 0; i < 8;) {
      if (i == best) {
        out += (i == 0) ? "::" : ":";
        i += best_len;
        continue;
      }
      char part[8];
    std::snprintf(part, sizeof(part), "%x", g[i]);
      out += part;
      if (i + 1 < 8 && (best < 0 || i + 1 != best + 0)) {
        if (!(best >= 0 && i + 1 == best)) out += ":";
      }
      ++i;
    }
    return out;
  }
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  return buf;
}

bool same_addr(int version, const std::uint8_t* a, const std::uint8_t* b) noexcept {
  return std::memcmp(a, b, static_cast<std::size_t>(version == 6 ? 16 : 4)) == 0;
}

}  // namespace

std::string tcp_flags_text(std::uint8_t flags) {
  std::string out;
  const struct {
    std::uint8_t bit;
    const char* name;
  } kBits[] = {
      {TCP_SYN, "SYN"}, {TCP_ACK, "ACK"}, {TCP_FIN, "FIN"}, {TCP_RST, "RST"},
      {TCP_PSH, "PSH"}, {TCP_URG, "URG"}, {TCP_ECE, "ECE"}, {TCP_CWR, "CWR"},
  };
  for (const auto& b : kBits) {
    if ((flags & b.bit) == 0) continue;
    if (!out.empty()) out += ',';
    out += b.name;
  }
  return out.empty() ? std::string("-") : out;
}

const char* tcp_state_name(TcpState s) {
  switch (s) {
    case TcpState::SynReceived: return "syn-received";
    case TcpState::Established: return "established";
    case TcpState::PeerClosed: return "peer-closed";
    case TcpState::Closing: return "closing";
    case TcpState::TimeWait: return "time-wait";
    case TcpState::Reset: return "reset";
  }
  return "?";
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

std::size_t ip_header_len(int version) noexcept {
  if (version == 4) return 20;
  if (version == 6) return 40;
  return 0;
}

std::string IpHeader::source() const { return fmt_ip(version, src); }
std::string IpHeader::destination() const { return fmt_ip(version, dst); }

bool ip_parse(const std::uint8_t* data, std::size_t len, IpHeader* out) {
  if (data == nullptr || out == nullptr || len < 1) return false;
  const int version = static_cast<int>(data[0] >> 4);
  if (version == 4) {
    if (len < 20) return false;
    const std::size_t ihl = static_cast<std::size_t>(data[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return false;
    std::size_t total = p16be(data + 2);
    if (total == 0) total = len;  // offloaded packets sometimes carry zero
    if (total < ihl) return false;
    if (total > len) total = len;
    *out = IpHeader();
    out->version = 4;
    out->header_len = ihl;
    out->total_len = total;
    out->payload_len = total - ihl;
    out->protocol = data[9];
    out->ttl = data[8];
    out->id = p16be(data + 4);
    out->traffic_class = static_cast<std::uint8_t>(data[1] >> 4);
    std::memcpy(out->src, data + 12, 4);
    std::memcpy(out->dst, data + 16, 4);
    return true;
  }
  if (version == 6) {
    if (len < 40) return false;
    std::size_t total = 40 + static_cast<std::size_t>(p16be(data + 4));
    if (total > len) total = len;
    *out = IpHeader();
    out->version = 6;
    out->header_len = 40;
    out->total_len = total;
    out->payload_len = total - 40;
    out->traffic_class = static_cast<std::uint8_t>(((data[0] & 0x0f) << 4) | (data[1] >> 4));
    out->flow_label = (std::uint32_t(data[1] & 0x0f) << 16) | (std::uint32_t(data[2]) << 8) | data[3];
    out->protocol = data[6];
    out->ttl = data[7];
    std::memcpy(out->src, data + 8, 16);
    std::memcpy(out->dst, data + 24, 16);
    return true;
  }
  return false;
}

bool tcp_parse(const std::uint8_t* data, std::size_t len, TcpHeader* out) {
  if (data == nullptr || out == nullptr || len < 20) return false;
  const std::size_t hdr = static_cast<std::size_t>(data[12] >> 4) * 4;
  if (hdr < 20 || hdr > len) return false;
  *out = TcpHeader();
  out->sport = p16be(data);
  out->dport = p16be(data + 2);
  out->seq = p32be(data + 4);
  out->ack = p32be(data + 8);
  out->flags = data[13];
  out->window = p16be(data + 14);
  out->urgent = p16be(data + 18);
  out->header_len = hdr;
  return true;
}

bool udp_parse(const std::uint8_t* data, std::size_t len, UdpHeader* out) {
  if (data == nullptr || out == nullptr || len < 8) return false;
  *out = UdpHeader();
  out->sport = p16be(data);
  out->dport = p16be(data + 2);
  out->length = p16be(data + 4);
  return true;
}

u16 ip_checksum_v4(const std::uint8_t* header, std::size_t len) {
  if (header == nullptr || len < 20) return 0;
  return internet_checksum(header, len, 0);
}

u16 transport_checksum(const std::uint8_t* src, const std::uint8_t* dst, int version,
                       std::uint8_t protocol, const std::uint8_t* segment, std::size_t len) {
  if (src == nullptr || dst == nullptr || segment == nullptr) return 0;
  u32 sum = 0;
  if (version == 6) {
    for (int i = 0; i < 16; i += 2) sum += p16be(src + i);
    for (int i = 0; i < 16; i += 2) sum += p16be(dst + i);
    sum += static_cast<u32>(len >> 16);
    sum += static_cast<u32>(len & 0xffffu);
    sum += protocol;
  } else {
    for (int i = 0; i < 4; i += 2) sum += p16be(src + i);
    for (int i = 0; i < 4; i += 2) sum += p16be(dst + i);
    sum += protocol;  // the pseudo header's zero byte sits above the protocol byte
    sum += static_cast<u32>(len & 0xffffu);
  }
  return internet_checksum(segment, len, sum);
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

std::size_t ipv4_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[4],
                       const std::uint8_t dst[4], std::uint8_t protocol, u16 id,
                       const std::uint8_t* payload, std::size_t payload_len) {
  const std::size_t total = 20 + payload_len;
  if (out == nullptr || cap < total || (payload_len > 0 && payload == nullptr)) return 0;
  if (total > 0xffffu) return 0;
  std::memset(out, 0, 20);
  out[0] = 0x45;
  out[1] = 0;
  put16be(out + 2, static_cast<u16>(total));
  put16be(out + 4, id);
  put16be(out + 6, 0x4000);  // don't fragment
  out[8] = 64;               // hop limit
  out[9] = protocol;
  std::memcpy(out + 12, src, 4);
  std::memcpy(out + 16, dst, 4);
  put16be(out + 10, ip_checksum_v4(out, 20));
  if (payload_len > 0) std::memcpy(out + 20, payload, payload_len);
  return total;
}

std::size_t ipv6_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[16],
                       const std::uint8_t dst[16], std::uint8_t protocol,
                       const std::uint8_t* payload, std::size_t payload_len) {
  const std::size_t total = 40 + payload_len;
  if (out == nullptr || cap < total || (payload_len > 0 && payload == nullptr)) return 0;
  if (payload_len > 0xffffu) return 0;
  std::memset(out, 0, 40);
  out[0] = 0x60;
  put16be(out + 4, static_cast<u16>(payload_len));
  out[6] = protocol;
  out[7] = 64;
  std::memcpy(out + 8, src, 16);
  std::memcpy(out + 24, dst, 16);
  if (payload_len > 0) std::memcpy(out + 40, payload, payload_len);
  return total;
}

std::size_t tcp_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[16],
                      const std::uint8_t dst[16], int version, u16 sport, u16 dport, u32 seq,
                      u32 ack, std::uint8_t flags, u16 window, const std::uint8_t* payload,
                      std::size_t payload_len) {
  const std::size_t seg = 20 + payload_len;
  if (out == nullptr || cap < seg || (payload_len > 0 && payload == nullptr)) return 0;
  put16be(out, sport);
  put16be(out + 2, dport);
  put32be(out + 4, seq);
  put32be(out + 8, ack);
  out[12] = 0x50;  // 20-byte header, no options
  out[13] = flags;
  put16be(out + 14, window);
  put16be(out + 16, 0);  // checksum placeholder
  put16be(out + 18, 0);  // urgent pointer
  if (payload_len > 0) std::memcpy(out + 20, payload, payload_len);
  put16be(out + 16, transport_checksum(src, dst, version, 6, out, seg));
  return seg;
}

std::size_t udp_build(std::uint8_t* out, std::size_t cap, const std::uint8_t src[16],
                      const std::uint8_t dst[16], int version, u16 sport, u16 dport,
                      const std::uint8_t* payload, std::size_t payload_len) {
  const std::size_t dgram = 8 + payload_len;
  if (out == nullptr || cap < dgram || (payload_len > 0 && payload == nullptr)) return 0;
  if (dgram > 0xffffu) return 0;
  put16be(out, sport);
  put16be(out + 2, dport);
  put16be(out + 4, static_cast<u16>(dgram));
  put16be(out + 6, 0);
  if (payload_len > 0) std::memcpy(out + 8, payload, payload_len);
  u16 c = transport_checksum(src, dst, version, 17, out, dgram);
  if (c == 0) c = 0xffff;  // RFC 768: a computed zero is sent as all ones
  put16be(out + 6, c);
  return dgram;
}

int icmp_echo_type(int version, bool reply) {
  if (version == 6) return reply ? 129 : 128;
  return reply ? 0 : 8;
}

std::size_t icmp_echo_reply(std::uint8_t* out, std::size_t cap, const std::uint8_t* icmp,
                            std::size_t len) {
  if (out == nullptr || icmp == nullptr || len < 8 || cap < len) return 0;
  const std::uint8_t type = icmp[0];
  if (type != 8 && type != 128) return 0;
  std::memcpy(out, icmp, len);
  out[0] = static_cast<std::uint8_t>(type == 8 ? 0 : 129);
  out[2] = 0;
  out[3] = 0;
  put16be(out + 2, internet_checksum(out, len, 0));
  return len;
}

// ---------------------------------------------------------------------------
// Endpoints and keys (the types come from flow.hpp; only the direction-aware
// helpers live here)
// ---------------------------------------------------------------------------

const char* flow_proto_name(FlowProto p) { return p == FlowProto::Udp ? "udp" : "tcp"; }

namespace {

Endpoint make_endpoint(int version, const std::uint8_t* addr, u16 port) {
  Endpoint e;
  std::memcpy(e.addr, addr, static_cast<std::size_t>(version == 6 ? 16 : 4));
  e.port = port;
  e.ip_version = static_cast<std::uint8_t>(version);
  return e;
}

/// flow.hpp keeps the key sorted so both directions of a connection map to one
/// record; the engine feeds both directions through this helper.
FlowKey make_key(FlowProto proto, const Endpoint& a, const Endpoint& b) {
  FlowKey k;
  k.proto = static_cast<std::uint8_t>(proto);
  k.ifindex = 0;
  if (a < b) {
    k.lo = a;
    k.hi = b;
  } else {
    k.lo = b;
    k.hi = a;
  }
  return k;
}

}  // namespace

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

std::string EngineStats::describe() const {
  char buf[512];
  std::snprintf(buf, sizeof(buf),
                "packets %llu in / %llu out, bytes %llu in / %llu out, flows: %llu tcp opened "
                "(%llu established, %llu closed), %llu udp, %llu icmp replies, %llu retransmits, "
                "%llu expired, %llu malformed, %llu bad checksum, %llu unsupported, %llu refused",
                static_cast<unsigned long long>(packets_in), static_cast<unsigned long long>(packets_out),
                static_cast<unsigned long long>(bytes_in), static_cast<unsigned long long>(bytes_out),
                static_cast<unsigned long long>(tcp_opened), static_cast<unsigned long long>(tcp_established),
                static_cast<unsigned long long>(tcp_closed), static_cast<unsigned long long>(udp_opened),
                static_cast<unsigned long long>(icmp_replies), static_cast<unsigned long long>(retransmits),
                static_cast<unsigned long long>(expired), static_cast<unsigned long long>(malformed),
                static_cast<unsigned long long>(bad_checksum), static_cast<unsigned long long>(unsupported),
                static_cast<unsigned long long>(refused));
  return buf;
}

std::string PacketEngine::FlowView::text() const {
  return client.to_string() + " -> " + server.to_string() + " " + flow_proto_name(proto);
}

std::string PacketEngine::FlowView::describe() const {
  char buf[256];
  std::snprintf(buf, sizeof(buf),
                "#%llu %s %s, rx %zu buffered, %zu unacked, in %llu pkt/%llu B, "
                "out %llu pkt/%llu B",
                static_cast<unsigned long long>(id), text().c_str(), tcp_state_name(state),
                buffered, unsent, static_cast<unsigned long long>(stats.packets_in),
                static_cast<unsigned long long>(stats.bytes_in),
                static_cast<unsigned long long>(stats.packets_out),
                static_cast<unsigned long long>(stats.bytes_out));
  return buf;
}

std::size_t PacketEngine::TcpFlow::unsent_bytes() const {
  std::size_t n = 0;
  for (const auto& s : unacked) n += s.data.size() + (s.syn ? 1u : 0u) + (s.fin ? 1u : 0u);
  return n;
}

PacketEngine::PacketEngine(const PacketEngineConfig& cfg) : cfg_(cfg) {
  scratch_.resize(4096);
}

void PacketEngine::reset() {
  tcp_.clear();
  udp_.clear();
  stats_ = EngineStats();
  next_flow_id_ = 1;
}

std::size_t PacketEngine::max_segment_payload() const {
  const std::size_t hdr = ip_header_len(cfg_.version) + 20;
  if (cfg_.mtu <= hdr + 1) return 64;
  return cfg_.mtu - hdr;
}

std::size_t PacketEngine::flow_count() const { return tcp_.size() + udp_.size(); }

void PacketEngine::feed(const std::uint8_t* ip, std::size_t len, i64 now_us,
                        std::vector<Packet>* out) {
  ++stats_.packets_in;
  stats_.bytes_in += len;
  IpHeader h;
  if (!ip_parse(ip, len, &h)) {
    ++stats_.malformed;
    return;
  }
  if (h.version != cfg_.version) {
    ++stats_.unsupported;
    return;
  }
  const std::uint8_t* payload = ip + h.header_len;
  const std::size_t plen = h.payload_len;
  switch (h.protocol) {
    case 6:
      handle_tcp(h, payload, plen, now_us, out);
      break;
    case 17:
      handle_udp(h, payload, plen, now_us, out);
      break;
    case 1:
    case 58:
      handle_icmp(h, payload, plen, now_us, out);
      break;
    default:
      ++stats_.unsupported;
      break;
  }
}

void PacketEngine::handle_tcp(const IpHeader& h, const std::uint8_t* segment, std::size_t len,
                             i64 now_us, std::vector<Packet>* out) {
  TcpHeader t;
  if (!tcp_parse(segment, len, &t)) {
    ++stats_.malformed;
    return;
  }
  if (cfg_.verify_checksums &&
      transport_checksum(h.src, h.dst, h.version, 6, segment, len) != 0) {
    ++stats_.bad_checksum;
    return;
  }
  // Two directions belong to the engine: traffic the host sent out (the routing
  // table pushed it into the tunnel, so the source is our tunnel address) and
  // traffic coming back to us.  A takeover only ever sees the first kind, so
  // insisting on the second kind would drop every packet the host originates.
  if (!same_addr(h.version, h.dst, cfg_.local) && !same_addr(h.version, h.src, cfg_.local)) {
    ++stats_.unsupported;  // not addressed to or from the tunnel address we own
    return;
  }
  const std::uint8_t* data = segment + t.header_len;
  const std::size_t dlen = len - t.header_len;

  const Endpoint client = make_endpoint(h.version, h.src, t.sport);
  const Endpoint server = make_endpoint(h.version, h.dst, t.dport);
  const FlowKey key = make_key(FlowProto::Tcp, client, server);

  auto it = tcp_.find(key);  if (it == tcp_.end()) {
    const bool opening = (t.flags & TCP_SYN) != 0 && (t.flags & TCP_ACK) == 0;
    if (!opening || flow_count() >= cfg_.max_flows) {
      ++stats_.refused;
      emit_rst(h, t, dlen, now_us, out);
      return;
    }
    TcpFlow f;
    f.id = next_flow_id_++;
    f.key = key;
    f.client = client;
    f.server = server;
    f.state = TcpState::SynReceived;
    f.isn = next_isn();
    f.snd_una = f.isn;
    f.snd_nxt = f.isn;
    f.rcv_nxt = t.seq + 1;
    f.peer_window = t.window;
    f.created_us = f.last_us = now_us;
    emit_tcp(f, f.snd_nxt, f.rcv_nxt, TCP_SYN | TCP_ACK, nullptr, 0, now_us, out);
    queue_segment(f, f.snd_nxt, nullptr, 0, true, false, now_us);
    f.snd_nxt += 1;
    tcp_.emplace(key, std::move(f));
    ++stats_.tcp_opened;
    return;
  }

  TcpFlow& f = it->second;
  f.last_us = now_us;
  ++f.stats.packets_in;
  if ((t.flags & TCP_RST) != 0) {
    ++f.stats.resets;
    ++stats_.tcp_closed;
    tcp_.erase(it);
    return;
  }

  if ((t.flags & TCP_ACK) != 0) {
    f.peer_window = t.window;
    while (!f.unacked.empty()) {
      const Segment& s = f.unacked.front();
      const u32 end = s.seq + static_cast<u32>(s.data.size()) + (s.syn ? 1u : 0u) +
                      (s.fin ? 1u : 0u);
      if (!seq_le(end, t.ack)) break;
      f.snd_una = end;
      f.unacked.erase(f.unacked.begin());
    }
    if (f.state == TcpState::SynReceived && f.snd_una != f.isn) {
      f.state = TcpState::Established;
      ++stats_.tcp_established;
    }
  }

  bool need_ack = false;
  if (dlen > 0) {
    f.stats.bytes_in += dlen;
    if (t.seq == f.rcv_nxt) {
      if (f.rx.size() + dlen > cfg_.max_flow_buffer) {
        // The application is not draining the flow; reset instead of growing.
        emit_tcp(f, f.snd_nxt, f.rcv_nxt, TCP_RST | TCP_ACK, nullptr, 0, now_us, out);
        ++f.stats.resets;
        ++stats_.tcp_closed;
        tcp_.erase(it);
        return;
      }
      f.rx.insert(f.rx.end(), data, data + dlen);
      f.rcv_nxt += static_cast<u32>(dlen);
      need_ack = true;
    } else if (seq_lt(t.seq, f.rcv_nxt)) {
      ++f.stats.duplicates;  // already seen: re-acknowledge
      need_ack = true;
    } else {
      ++f.stats.out_of_order;  // a gap we do not reassemble: ack and let the peer retry
      need_ack = true;
    }
  }

  if ((t.flags & TCP_FIN) != 0) {
    if (!f.peer_fin) {
      f.peer_fin = true;
      f.rcv_nxt += 1;
    }
    f.state = f.we_fin ? TcpState::Closing : TcpState::PeerClosed;
    need_ack = true;
  }

  if (need_ack) emit_tcp(f, f.snd_nxt, f.rcv_nxt, TCP_ACK, nullptr, 0, now_us, out);
}

void PacketEngine::handle_udp(const IpHeader& h, const std::uint8_t* datagram, std::size_t len,
                             i64 now_us, std::vector<Packet>* out) {
  (void)out;
  UdpHeader u;
  if (!udp_parse(datagram, len, &u)) {
    ++stats_.malformed;
    return;
  }
  if (!same_addr(h.version, h.dst, cfg_.local) && !same_addr(h.version, h.src, cfg_.local)) {
    ++stats_.unsupported;
    return;
  }
  std::size_t dlen = len - 8;
  if (u.length >= 8 && static_cast<std::size_t>(u.length) - 8 < dlen) {
    dlen = static_cast<std::size_t>(u.length) - 8;
  }
  const std::uint8_t* data = datagram + 8;
  if (p16be(datagram + 6) != 0 && cfg_.verify_checksums &&
      transport_checksum(h.src, h.dst, h.version, 17, datagram, len) != 0) {
    ++stats_.bad_checksum;
    return;
  }

  const Endpoint client = make_endpoint(h.version, h.src, u.sport);
  const Endpoint server = make_endpoint(h.version, h.dst, u.dport);
  const FlowKey key = make_key(FlowProto::Udp, client, server);

  auto it = udp_.find(key);
  if (it == udp_.end()) {
    if (flow_count() >= cfg_.max_flows) {
      ++stats_.refused;
      return;
    }
    UdpFlow f;
    f.id = next_flow_id_++;
    f.key = key;
    f.client = client;
    f.server = server;
    f.created_us = f.last_us = now_us;
    it = udp_.emplace(key, std::move(f)).first;
    ++stats_.udp_opened;
  }
  UdpFlow& f = it->second;
  f.last_us = now_us;
  ++f.stats.packets_in;
  if (dlen > 0) {
    if (f.rx.size() + dlen > cfg_.max_flow_buffer) f.rx.clear();  // drop the backlog, keep the flow
    f.rx.insert(f.rx.end(), data, data + dlen);
    f.stats.bytes_in += dlen;
  }
}

void PacketEngine::handle_icmp(const IpHeader& h, const std::uint8_t* message, std::size_t len,
                               i64 now_us, std::vector<Packet>* out) {
  if (!cfg_.answer_icmp_echo || out == nullptr) {
    ++stats_.unsupported;
    return;
  }
  if (!same_addr(h.version, h.dst, cfg_.local)) {
    ++stats_.unsupported;
    return;
  }
  if (len + 40 > scratch_.size()) scratch_.resize(len + 64);
  const std::size_t n = icmp_echo_reply(scratch_.data(), scratch_.size(), message, len);
  if (n == 0) {
    ++stats_.unsupported;  // not an echo request
    return;
  }
  if (wrap_and_emit(scratch_.data(), n, static_cast<std::uint8_t>(h.version == 6 ? 58 : 1),
                    h.dst, h.src, now_us, out) != 0) {
    ++stats_.icmp_replies;
  }
}

void PacketEngine::emit_tcp(TcpFlow& f, u32 seq, u32 ack, std::uint8_t flags,
                            const std::uint8_t* payload, std::size_t payload_len, i64 now_us,
                            std::vector<Packet>* out) {
  if (out == nullptr) return;
  const std::size_t need = 64 + payload_len;
  if (scratch_.size() < need) scratch_.resize(need);
  const Endpoint& src = f.server;  // we are the server side of the flow
  const Endpoint& dst = f.client;
  const std::size_t seg =
      tcp_build(scratch_.data(), scratch_.size(), src.addr, dst.addr, cfg_.version, src.port,
                dst.port, seq, ack, flags, cfg_.window, payload, payload_len);
  if (seg == 0) return;
  if (wrap_and_emit(scratch_.data(), seg, 6, src.addr, dst.addr, now_us, out) == 0) return;
  ++f.stats.packets_out;
  f.stats.bytes_out += payload_len;
}

void PacketEngine::emit_udp(UdpFlow& f, const std::uint8_t* payload, std::size_t payload_len,
                            i64 now_us, std::vector<Packet>* out) {
  if (out == nullptr) return;
  const std::size_t need = 64 + payload_len;
  if (scratch_.size() < need) scratch_.resize(need);
  const Endpoint& src = f.server;
  const Endpoint& dst = f.client;
  const std::size_t dgram =
      udp_build(scratch_.data(), scratch_.size(), src.addr, dst.addr, cfg_.version, src.port,
                dst.port, payload, payload_len);
  if (dgram == 0) return;
  if (wrap_and_emit(scratch_.data(), dgram, 17, src.addr, dst.addr, now_us, out) == 0) return;
  ++f.stats.packets_out;
  f.stats.bytes_out += payload_len;
}

std::size_t PacketEngine::wrap_and_emit(const std::uint8_t* l4, std::size_t l4_len,
                                        std::uint8_t protocol, const std::uint8_t* src,
                                        const std::uint8_t* dst, i64 now_us,
                                        std::vector<Packet>* out) {
  if (out == nullptr) return 0;
  const std::size_t hdr = ip_header_len(cfg_.version);
  if (hdr == 0) return 0;
  Packet p;
  p.data.resize(hdr + l4_len);
  const std::size_t total =
      cfg_.version == 6
          ? ipv6_build(p.data.data(), p.data.size(), src, dst, protocol, l4, l4_len)
          : ipv4_build(p.data.data(), p.data.size(), src, dst, protocol, ++ip_id_, l4, l4_len);
  if (total == 0) return 0;
  p.data.resize(total);
  p.origlen = total;
  p.ts_us = now_us;
  p.linktype = DLT_RAW;
  p.ifindex = 0;
  ++stats_.packets_out;
  stats_.bytes_out += total;
  out->push_back(std::move(p));
  return total;
}

void PacketEngine::emit_rst(const IpHeader& h, const TcpHeader& t, std::size_t payload_len,
                            i64 now_us, std::vector<Packet>* out) {
  if (out == nullptr) return;
  const std::size_t need = 128;
  if (scratch_.size() < need) scratch_.resize(need);
  const std::uint8_t* src = h.dst;
  const std::uint8_t* dst = h.src;
  const u32 seq = (t.flags & TCP_ACK) != 0 ? t.ack : 0u;
  const u32 ack = t.seq + static_cast<u32>(payload_len) + ((t.flags & TCP_SYN) ? 1u : 0u) +
                  ((t.flags & TCP_FIN) ? 1u : 0u);
  const std::size_t seg =
      tcp_build(scratch_.data(), scratch_.size(), src, dst, h.version, t.dport, t.sport, seq, ack,
                TCP_RST | TCP_ACK, 0, nullptr, 0);
  if (seg == 0) return;
  wrap_and_emit(scratch_.data(), seg, 6, src, dst, now_us, out);
}

void PacketEngine::queue_segment(TcpFlow& f, u32 seq, const std::uint8_t* payload,
                                 std::size_t len, bool syn, bool fin, i64 now_us) {
  if (f.unsent_bytes() + len > cfg_.max_flow_buffer) return;
  Segment s;
  s.seq = seq;
  s.syn = syn;
  s.fin = fin;
  if (len > 0 && payload != nullptr) s.data.assign(payload, payload + len);
  s.next_try_us = now_us + cfg_.retransmit_us;
  f.unacked.push_back(std::move(s));
}

void PacketEngine::tick(i64 now_us, std::vector<Packet>* out) {
  for (auto it = tcp_.begin(); it != tcp_.end();) {
    TcpFlow& f = it->second;
    bool give_up = false;
    for (auto& s : f.unacked) {
      if (now_us < s.next_try_us) continue;
      if (s.tries >= cfg_.max_retries) {
        give_up = true;
        break;
      }
      ++s.tries;
      std::uint8_t flags = TCP_ACK;
      if (s.syn) flags |= TCP_SYN;
      if (s.fin) flags |= TCP_FIN;
      if (!s.data.empty()) flags |= TCP_PSH;
      emit_tcp(f, s.seq, f.rcv_nxt, flags, s.data.data(), s.data.size(), now_us, out);
      s.next_try_us = now_us + cfg_.retransmit_us * (1 + s.tries);
      ++f.stats.retransmits;
      ++stats_.retransmits;
    }
    if (give_up) {
      emit_tcp(f, f.snd_nxt, f.rcv_nxt, TCP_RST | TCP_ACK, nullptr, 0, now_us, out);
      ++stats_.expired;
      ++stats_.tcp_closed;
      it = tcp_.erase(it);
      continue;
    }
    if (now_us - f.last_us > cfg_.tcp_idle_us) {
      ++stats_.expired;
      ++stats_.tcp_closed;
      it = tcp_.erase(it);
      continue;
    }
    ++it;
  }
  for (auto it = udp_.begin(); it != udp_.end();) {
    if (now_us - it->second.last_us > cfg_.udp_idle_us) {
      ++stats_.expired;
      it = udp_.erase(it);
    } else {
      ++it;
    }
  }
}

std::vector<PacketEngine::FlowView> PacketEngine::flows() const {
  std::vector<FlowView> out;
  out.reserve(tcp_.size() + udp_.size());
  for (const auto& kv : tcp_) {
    const TcpFlow& f = kv.second;
    FlowView v;
    v.id = f.id;
    v.client = f.client;
    v.server = f.server;
    v.proto = FlowProto::Tcp;
    v.state = f.state;
    v.established = f.state == TcpState::Established || f.state == TcpState::PeerClosed ||
                    f.state == TcpState::Closing;
    v.closed = f.peer_fin;
    v.buffered = f.rx.size();
    v.unsent = f.unsent_bytes();
    v.stats = f.stats;
    v.created_us = f.created_us;
    v.last_us = f.last_us;
    out.push_back(std::move(v));
  }
  for (const auto& kv : udp_) {
    const UdpFlow& f = kv.second;
    FlowView v;
    v.id = f.id;
    v.client = f.client;
    v.server = f.server;
    v.proto = FlowProto::Udp;
    v.established = true;
    v.buffered = f.rx.size();
    v.stats = f.stats;
    v.created_us = f.created_us;
    v.last_us = f.last_us;
    out.push_back(std::move(v));
  }
  return out;
}

bool PacketEngine::flow(u64 id, FlowView* out) const {
  const std::vector<FlowView> all = flows();
  for (const auto& v : all) {
    if (v.id == id) {
      if (out != nullptr) *out = v;
      return true;
    }
  }
  return false;
}

bool PacketEngine::read(u64 id, Bytes* out) {
  if (out == nullptr) return false;
  for (auto& kv : tcp_) {
    if (kv.second.id != id) continue;
    out->swap(kv.second.rx);
    return true;
  }
  for (auto& kv : udp_) {
    if (kv.second.id != id) continue;
    out->swap(kv.second.rx);
    return true;
  }
  return false;
}

bool PacketEngine::write(u64 id, const Bytes& data, i64 now_us, std::vector<Packet>* out) {
  if (out == nullptr) return false;
  for (auto& kv : tcp_) {
    if (kv.second.id != id) continue;
    TcpFlow& f = kv.second;
    if (data.empty()) return true;
    const std::size_t mss = max_segment_payload();
    std::size_t off = 0;
    while (off < data.size()) {
      const std::size_t n = std::min(mss, data.size() - off);
      if (f.unsent_bytes() + n > cfg_.max_flow_buffer) return false;  // backpressure
      emit_tcp(f, f.snd_nxt, f.rcv_nxt, TCP_ACK | TCP_PSH, data.data() + off, n, now_us, out);
      queue_segment(f, f.snd_nxt, data.data() + off, n, false, false, now_us);
      f.snd_nxt += static_cast<u32>(n);
      off += n;
    }
    return true;
  }
  for (auto& kv : udp_) {
    if (kv.second.id != id) continue;
    emit_udp(kv.second, data.data(), data.size(), now_us, out);
    return true;
  }
  return false;
}

bool PacketEngine::close_flow(u64 id, i64 now_us, std::vector<Packet>* out) {
  if (out == nullptr) return false;
  for (auto it = tcp_.begin(); it != tcp_.end(); ++it) {
    if (it->second.id != id) continue;
    TcpFlow& f = it->second;
    if (f.we_fin) return true;
    emit_tcp(f, f.snd_nxt, f.rcv_nxt, TCP_FIN | TCP_ACK, nullptr, 0, now_us, out);
    queue_segment(f, f.snd_nxt, nullptr, 0, false, true, now_us);
    f.snd_nxt += 1;
    f.we_fin = true;
    if (f.peer_fin) f.state = TcpState::Closing;
    return true;
  }
  for (auto it = udp_.begin(); it != udp_.end(); ++it) {
    if (it->second.id != id) continue;
    udp_.erase(it);  // datagrams have nothing to close
    return true;
  }
  return false;
}

bool PacketEngine::abort_flow(u64 id, i64 now_us, std::vector<Packet>* out) {
  for (auto it = tcp_.begin(); it != tcp_.end(); ++it) {
    if (it->second.id != id) continue;
    emit_tcp(it->second, it->second.snd_nxt, it->second.rcv_nxt, TCP_RST | TCP_ACK, nullptr, 0,
             now_us, out);
    it->second.state = TcpState::Reset;
    ++stats_.tcp_closed;
    tcp_.erase(it);
    return true;
  }
  for (auto it = udp_.begin(); it != udp_.end(); ++it) {
    if (it->second.id != id) continue;
    udp_.erase(it);
    return true;
  }
  return false;
}

std::string PacketEngine::describe() const {
  char buf[512];
  std::snprintf(buf, sizeof(buf),
                "packet engine: %s, %zu flow(s) tracked (max %zu), mtu %zu, segment payload %zu, "
                "verify checksums %s, icmp echo %s",
                cfg_.version == 6 ? "IPv6" : "IPv4", flow_count(), cfg_.max_flows, cfg_.mtu,
                max_segment_payload(), cfg_.verify_checksums ? "on" : "off",
                cfg_.answer_icmp_echo ? "on" : "off");
  return buf;
}

}  // namespace netcap
