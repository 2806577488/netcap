// Self-test suite plus the synthetic traffic generator.
//
// Every packet used here is built byte by byte in memory, so the dissector can
// be exercised (and the whole tool demonstrated) on a machine that is not
// allowed to open a raw socket.
#include "netcap/selftest.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <vector>

#include "netcap/app.hpp"
#include "netcap/analyze.hpp"
#include "netcap/block.hpp"
#include "netcap/capture.hpp"
#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/dissect.hpp"
#include "netcap/filter.hpp"
#include "netcap/flow.hpp"
#include "netcap/http.hpp"
#include "netcap/tls.hpp"
#include "netcap/http2.hpp"
#include "netcap/httpframe.hpp"
#include "netcap/origin.hpp"
#include "netcap/picker.hpp"
#include "netcap/packet.hpp"
#include "netcap/pcap.hpp"
#include "netcap/pktflow.hpp"
#include "netcap/tunrelay.hpp"
#include "netcap/tunpipe.hpp"
#include "netcap/proc.hpp"
#include "netcap/proxy.hpp"
#include "netcap/rules.hpp"
#include "netcap/blocker.hpp"
#include "netcap/hosts.hpp"
#include "netcap/dnssink.hpp"
#include "netcap/wfp.hpp"
#include "netcap/sysproxy.hpp"
#include "netcap/sysenv.hpp"
#include "netcap/tun.hpp"
#include "netcap/p256.hpp"
#include "netcap/p521.hpp"
#include "netcap/x509.hpp"
#include "netcap/tls13.hpp"
#include "netcap/tls12.hpp"
#include "netcap/rsa.hpp"  // rsa_selfcheck: RSA origins are verified by CNG
#include "netcap/x25519.hpp"
#include "netcap/brotli.hpp"  // brotli_selfcheck and the real-stream decode assertions
#include "netcap/brotli_encode.hpp"  // the inverse: a `br` body that still fits goes back out as `br`
#include "netcap/quic.hpp"    // QUIC Initials: the TUN path blocks a name without any keys
#include "netcap/h3.hpp"      // HTTP/3 over QUIC 1-RTT: what a QUIC request is really asking for
#include "netcap/h3_write.hpp"
#include "netcap/quic_rewrite.hpp"  // and how a response goes back out (QPACK writer, static table only)
#include "netcap/quickeys.hpp"  // QUIC key logs: 1-RTT secrets and an equal-length rewrite
#include <atomic>
#include <fstream>
#include <sstream>
#include <thread>
#include "netcap/split.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#endif

namespace netcap {

namespace {

// ---------------------------------------------------------------------------
// Byte builder
// ---------------------------------------------------------------------------

struct Buf {
  std::vector<u8> v;

  Buf& u8v(u8 x) {
    v.push_back(x);
    return *this;
  }
  Buf& be16(u16 x) {
    u8 t[2];
    wr16be(t, x);
    v.insert(v.end(), t, t + 2);
    return *this;
  }
  Buf& be32(u32 x) {
    u8 t[4];
    wr32be(t, x);
    v.insert(v.end(), t, t + 4);
    return *this;
  }
  Buf& raw(const void* p, std::size_t n) {
    const u8* b = static_cast<const u8*>(p);
    v.insert(v.end(), b, b + n);
    return *this;
  }
  Buf& raw(const std::vector<u8>& o) { return raw(o.data(), o.size()); }
  Buf& str(const char* s) { return raw(s, std::strlen(s)); }
  Buf& zeros(std::size_t n) {
    v.insert(v.end(), n, 0);
    return *this;
  }
};

std::vector<u8> mac_of(const char* text) {
  std::vector<u8> m;
  const char* p = text;
  while (p && *p && m.size() < 6) {
    unsigned x = 0;
    if (std::sscanf(p, "%x", &x) != 1) break;
    m.push_back(u8(x));
    const char* colon = std::strchr(p, ':');
    if (!colon) break;
    p = colon + 1;
  }
  return m;
}

std::vector<u8> eth_frame(const char* dst, const char* src, u16 type,
                          const std::vector<u8>& payload) {
  Buf b;
  b.raw(mac_of(dst));
  b.raw(mac_of(src));
  b.be16(type);
  b.raw(payload);
  return b.v;
}

std::vector<u8> eth_vlan(const char* dst, const char* src, u16 vlan_id, u16 inner_type,
                         const std::vector<u8>& payload) {
  Buf b;
  b.raw(mac_of(dst));
  b.raw(mac_of(src));
  b.be16(0x8100);
  b.be16(u16(vlan_id & 0x0fff));
  b.be16(inner_type);
  b.raw(payload);
  return b.v;
}

struct Ip4Opts {
  const char* src = "10.0.0.1";
  const char* dst = "10.0.0.2";
  u8 proto = 6;
  u8 ttl = 64;
  u8 tos = 0;
  u16 id = 0x1234;
  bool df = false;
  bool mf = false;
  u16 frag_off = 0;  // in 8-byte units
};

std::vector<u8> ipv4_packet(const Ip4Opts& o, const std::vector<u8>& payload) {
  Buf b;
  b.u8v(0x45).u8v(o.tos);
  b.be16(u16(20 + payload.size()));
  b.be16(o.id);
  u16 flags_frag = u16(o.frag_off & 0x1fff);
  if (o.df) flags_frag |= 0x4000;
  if (o.mf) flags_frag |= 0x2000;
  b.be16(flags_frag);
  b.u8v(o.ttl).u8v(o.proto);
  b.be16(0);  // checksum placeholder
  u8 sa[16] = {0}, da[16] = {0};
  int sv = 0, dv = 0;
  parse_ip(o.src, &sv, sa);
  parse_ip(o.dst, &dv, da);
  b.raw(sa, 4);
  b.raw(da, 4);
  b.raw(payload);
  wr16be(b.v.data() + 10, internet_checksum(b.v.data(), 20));
  return b.v;
}

std::vector<u8> ipv6_packet(const char* src, const char* dst, u8 next_header, u8 hop_limit,
                            const std::vector<u8>& payload) {
  Buf b;
  b.be32(0x60000000u);
  b.be16(u16(payload.size()));
  b.u8v(next_header).u8v(hop_limit);
  u8 sa[16] = {0}, da[16] = {0};
  int sv = 0, dv = 0;
  parse_ip(src, &sv, sa);
  parse_ip(dst, &dv, da);
  b.raw(sa, 16);
  b.raw(da, 16);
  b.raw(payload);
  return b.v;
}

std::vector<u8> tcp_segment(u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, u16 window,
                            const std::vector<u8>& payload, u16 mss = 0) {
  Buf b;
  b.be16(sport).be16(dport).be32(seq).be32(ack);
  b.u8v(u8(mss ? (6 << 4) : (5 << 4))).u8v(flags);
  b.be16(window).be16(0).be16(0);
  if (mss) b.u8v(2).u8v(4).be16(mss);  // 4 option bytes => 24-byte header
  b.raw(payload);
  return b.v;
}

std::vector<u8> udp_datagram(u16 sport, u16 dport, const std::vector<u8>& payload) {
  Buf b;
  b.be16(sport).be16(dport).be16(u16(8 + payload.size())).be16(0);
  b.raw(payload);
  return b.v;
}

std::vector<u8> icmp_message(u8 type, u8 code, u16 id, u16 seq, const std::vector<u8>& payload) {
  Buf b;
  b.u8v(type).u8v(code).be16(0).be16(id).be16(seq);
  b.raw(payload);
  wr16be(b.v.data() + 2, internet_checksum(b.v.data(), b.v.size()));
  return b.v;
}

std::vector<u8> tls_client_hello(const char* sni) {
  const std::string name = sni;
  Buf ext;
  {
    Buf list;
    list.be16(u16(name.size() + 3));
    list.u8v(0);
    list.be16(u16(name.size()));
    list.raw(name.data(), name.size());
    ext.be16(0x0000).be16(u16(list.v.size())).raw(list.v);
  }
  {
    Buf sv;
    sv.u8v(2).be16(0x0304);
    ext.be16(0x002b).be16(u16(sv.v.size())).raw(sv.v);
  }
  Buf body;
  body.be16(0x0303);
  for (int i = 0; i < 32; ++i) body.u8v(u8(0xa0 + i));
  body.u8v(0);  // session id length
  body.be16(2).be16(0x1301);
  body.u8v(1).u8v(0);  // one compression method: null
  body.be16(u16(ext.v.size())).raw(ext.v);

  Buf hs;
  hs.u8v(0x01);
  hs.u8v(u8(body.v.size() >> 16)).u8v(u8(body.v.size() >> 8)).u8v(u8(body.v.size()));
  hs.raw(body.v);

  Buf rec;
  rec.u8v(0x16).be16(0x0301).be16(u16(hs.v.size())).raw(hs.v);
  return rec.v;
}

std::vector<u8> dns_query(u16 id, const char* qname, u16 qtype) {
  Buf b;
  b.be16(id).be16(0x0100).be16(1).be16(0).be16(0).be16(0);
  std::string name = qname;
  std::size_t start = 0;
  while (start < name.size()) {
    const std::size_t dot = name.find('.', start);
    const std::string label = name.substr(start, dot == std::string::npos ? std::string::npos
                                                                          : dot - start);
    b.u8v(u8(label.size()));
    b.raw(label.data(), label.size());
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  b.u8v(0).be16(qtype).be16(1);
  return b.v;
}

std::vector<u8> dns_response(u16 id, const char* qname, u32 answer_ip) {
  std::vector<u8> q = dns_query(id, qname, 1);
  std::vector<u8> r = q;
  wr16be(r.data() + 2, 0x8180);  // response, recursion desired+available
  const u8 counts[8] = {0, 1, 0, 0, 0, 0, 0, 0};  // ancount = 1
  std::memcpy(r.data() + 6, counts, 4);
  Buf a;
  a.be16(0xc00c);      // pointer to the question name
  a.be16(1).be16(1);   // type A, class IN
  a.be32(60);          // ttl
  a.be16(4).be32(answer_ip);
  r.insert(r.end(), a.v.begin(), a.v.end());
  return r;
}

std::vector<u8> ssh_banner() {
  Buf b;
  b.str("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
  return b.v;
}

std::vector<u8> quic_initial() {
  Buf b;
  b.u8v(0xc0);  // long header, fixed bit, Initial
  b.be32(0x00000001);
  b.u8v(0x00);
  b.u8v(0x00);
  b.zeros(20);  // stand-in DCID/SCID bytes
  b.zeros(64);  // stand-in crypto payload
  return b.v;
}

std::vector<u8> arp_request() {
  Buf b;
  b.be16(1).be16(0x0800).u8v(6).u8v(4);
  b.be16(1);  // opcode: request
  b.raw(mac_of("00:11:22:33:44:55"));
  u8 spa[16] = {0};
  int v = 0;
  parse_ip("10.0.0.5", &v, spa);
  b.raw(spa, 4);
  b.raw(mac_of("00:00:00:00:00:00"));
  u8 tpa[16] = {0};
  parse_ip("10.0.0.1", &v, tpa);
  b.raw(tpa, 4);
  return b.v;
}

const char* kHttpGet =
    "GET /index.html HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "User-Agent: netcap-selftest/1.0\r\n"
    "Accept: */*\r\n"
    "\r\n";

const char* kHttpResponse =
    "HTTP/1.1 200 OK\r\n"
    "Server: netcap-selftest\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 13\r\n"
    "\r\n"
    "Hello, world!";

std::vector<u8> bytes_of(const char* s) {
  Buf b;
  b.str(s);
  return b.v;
}

// ---------------------------------------------------------------------------
// Canonical sample traffic (shared by the self-test and the generator)
// ---------------------------------------------------------------------------

constexpr i64 kBaseTs = 1700000000ll * 1000000ll;  // 2023-11-14 22:13:20 UTC

void add(std::vector<Packet>& out, std::vector<u8> frame, i64 ts_us) {
  Packet p;
  p.data = std::move(frame);
  p.origlen = p.data.size();
  p.ts_us = ts_us;
  p.linktype = DLT_EN10MB;
  p.ifindex = 1;
  out.push_back(std::move(p));
}

// The HTTPS session appended to the sample capture (defined with the TLS
// helpers further down).
void append_tls_conversation(std::vector<Packet>& out, i64& ts);

std::vector<Packet> build_sample_packets() {
  std::vector<Packet> out;
  i64 ts = kBaseTs;

  // 1. ARP "who has 10.0.0.1"
  add(out, eth_frame("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0806, arp_request()),
      ts += 120);

  // 2. TCP SYN carrying a TLS ClientHello with SNI example.com
  add(out,
      eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                ipv4_packet({.src = "10.0.0.5", .dst = "93.184.216.34", .proto = 6, .ttl = 64,
                             .id = 0x1a2b, .df = true},
                            tcp_segment(51000, 443, 0x9f1c0000, 0, TCP_SYN, 64240,
                                        tls_client_hello("example.com"), 1460))),
      ts += 431);

  // 3. SYN-ACK from the server
  add(out,
      eth_frame("00:11:22:33:44:55", "52:54:00:12:34:56", 0x0800,
                ipv4_packet({.src = "93.184.216.34", .dst = "10.0.0.5", .proto = 6, .ttl = 55,
                             .id = 0x77aa, .df = true},
                            tcp_segment(443, 51000, 0x40a10000, 0x9f1c0001,
                                        u8(TCP_SYN | TCP_ACK), 65535, {}, 1400))),
      ts += 21890);

  // 4. HTTP GET request
  add(out,
      eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                ipv4_packet({.src = "10.0.0.5", .dst = "93.184.216.34", .proto = 6, .ttl = 64,
                             .id = 0x1a2c, .df = true},
                            tcp_segment(51000, 80, 0x9f1c0001, 0x40a10001,
                                        u8(TCP_ACK | TCP_PSH), 64240, bytes_of(kHttpGet)))),
      ts += 1500);

  // 5. HTTP response
  add(out,
      eth_frame("00:11:22:33:44:55", "52:54:00:12:34:56", 0x0800,
                ipv4_packet({.src = "93.184.216.34", .dst = "10.0.0.5", .proto = 6, .ttl = 55,
                             .id = 0x77ab},
                            tcp_segment(80, 51000, 0x40a10001, 0x9f1c0057, u8(TCP_ACK | TCP_PSH),
                                        65535, bytes_of(kHttpResponse)))),
      ts += 31200);

  // 6. DNS query for www.example.com
  add(out,
      eth_frame("52:54:00:00:00:53", "00:11:22:33:44:55", 0x0800,
                ipv4_packet({.src = "10.0.0.5", .dst = "10.0.0.1", .proto = 17, .ttl = 64,
                             .id = 0x2b01},
                            udp_datagram(40000, 53, dns_query(0xbeef, "www.example.com", 1)))),
      ts += 640);

  // 7. DNS response (compressed answer name)
  add(out,
      eth_frame("00:11:22:33:44:55", "52:54:00:00:00:53", 0x0800,
                ipv4_packet({.src = "10.0.0.1", .dst = "10.0.0.5", .proto = 17, .ttl = 64,
                             .id = 0x2b02},
                            udp_datagram(53, 40000,
                                         dns_response(0xbeef, "www.example.com", 0x5db8d822)))),
      ts += 12400);

  // 8. IPv6 DNS query to a public resolver
  add(out,
      eth_frame("52:54:00:00:00:53", "00:11:22:33:44:55", 0x86dd,
                ipv6_packet("2001:db8::5", "2001:4860:4860::8888", 17, 64,
                            udp_datagram(40001, 53, dns_query(0x1001, "ipv6.example.com", 28)))),
      ts += 900);

  // 9. VLAN 100 tagged ICMP echo request
  add(out,
      eth_vlan("52:54:00:aa:bb:cc", "00:11:22:33:44:55", 100, 0x0800,
               ipv4_packet({.src = "192.168.100.10", .dst = "192.168.100.1", .proto = 1, .ttl = 64,
                            .id = 0x3c01},
                           icmp_message(8, 0, 0x1234, 1, bytes_of("netcap-selftest")))) ,
      ts += 300);

  // 10. Fragmented UDP datagram: two 16-byte fragments of the IP payload
  {
    Buf payload;
    for (int i = 0; i < 32; ++i) payload.u8v(u8('A' + (i % 26)));
    const std::vector<u8> dgram = udp_datagram(5000, 5001, payload.v);
    std::vector<u8> f1(dgram.begin(), dgram.begin() + 16);
    std::vector<u8> f2(dgram.begin() + 16, dgram.end());
    add(out,
        eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                  ipv4_packet({.src = "10.1.1.1", .dst = "10.1.1.2", .proto = 17, .ttl = 64,
                               .id = 0x4444, .mf = true, .frag_off = 0},
                              f1)),
        ts += 210);
    add(out,
        eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                  ipv4_packet({.src = "10.1.1.1", .dst = "10.1.1.2", .proto = 17, .ttl = 64,
                               .id = 0x4444, .frag_off = 2},
                              f2)),
        ts += 340);
  }

  // 11. SSH banner
  add(out,
      eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                ipv4_packet({.src = "10.0.0.9", .dst = "10.0.0.5", .proto = 6, .ttl = 64,
                             .id = 0x5a01},
                            tcp_segment(22, 51001, 0x1000, 0x2000, u8(TCP_ACK | TCP_PSH), 65535,
                                        ssh_banner()))),
      ts += 760);

  // 12. QUIC-looking UDP/443 Initial
  add(out,
      eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x86dd,
                ipv6_packet("2001:db8::5", "2606:4700:4700::1111", 17, 64,
                            udp_datagram(51234, 443, quic_initial()))),
      ts += 1180);

  // 13. IPv6 ICMPv6 echo request
  add(out,
      eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x86dd,
                ipv6_packet("2001:db8::5", "2001:db8::1", 58, 64,
                            icmp_message(128, 0, 0x2222, 7, bytes_of("ping6")))) ,
      ts += 420);

  // 14. DHCP discover
  {
    Buf d;
    d.u8v(1).u8v(1).u8v(6).u8v(0);   // op, htype, hlen, hops
    d.be32(0x3903f326);              // transaction id
    d.be16(0).be16(0x8000);          // seconds, flags (broadcast)
    d.zeros(4);                      // ciaddr
    d.zeros(4);                      // yiaddr
    d.zeros(4);                      // siaddr
    d.zeros(4);                      // giaddr
    d.raw(mac_of("00:11:22:33:44:55"));
    d.zeros(10);                     // chaddr padding to 16 bytes
    d.zeros(64);                     // sname
    d.zeros(128);                    // file
    d.be32(0x63825363);              // magic cookie
    d.u8v(53).u8v(1).u8v(1);         // option 53: DHCP message type = discover
    d.u8v(255);                      // option end
    add(out,
        eth_frame("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0800,
                  ipv4_packet({.src = "0.0.0.0", .dst = "255.255.255.255", .proto = 17, .ttl = 64,
                               .id = 0x6001},
                              udp_datagram(68, 67, d.v))),
        ts += 250);
  }

  // 15-24. A complete HTTPS session (TLS 1.3) whose secrets are in the key log
  // written beside the capture.
  append_tls_conversation(out, ts);

  return out;
}

// ---------------------------------------------------------------------------
// Check harness
// ---------------------------------------------------------------------------

struct Ctx {
  int checks = 0;
  int failures = 0;
  bool verbose = false;
  std::string log;

  void ok(bool cond, const std::string& what) {
    ++checks;
    if (cond) {
      if (verbose) log += "  ok   " + what + "\n";
      return;
    }
    ++failures;
    log += "  FAIL " + what + "\n";
  }

  void eq_u64(u64 got, u64 want, const std::string& what) {
    ++checks;
    if (got == want) {
      if (verbose) log += "  ok   " + what + "\n";
      return;
    }
    ++failures;
    log += "  FAIL " + what + " (got " + std::to_string(got) + ", want " + std::to_string(want) +
           ")\n";
  }

  void eq_str(const std::string& got, const std::string& want, const std::string& what) {
    ++checks;
    if (got == want) {
      if (verbose) log += "  ok   " + what + "\n";
      return;
    }
    ++failures;
    log += "  FAIL " + what + " (got \"" + got + "\", want \"" + want + "\")\n";
  }

  // Byte-level comparison: the hex form is what a failing vector prints.
  void eq_hex(const Bytes& got, const std::string& want_hex, const std::string& what) {
    const std::string hex = to_hex(got);
    ++checks;
    if (hex == want_hex) {
      if (verbose) log += "  ok   " + what + "\n";
      return;
    }
    ++failures;
    log += "  FAIL " + what + "\n         got  " + hex + "\n         want " + want_hex + "\n";
  }

  void section(const std::string& name) { log += "-- " + name + "\n"; }
};

PacketView view_of(const Packet& p) { return p.view(); }

bool dissect_packet(Dissector& d, const Packet& p, PacketInfo& pi) {
  return d.dissect(view_of(p), pi);
}

// ---------------------------------------------------------------------------

void test_primitives(Ctx& c) {
  c.section("endian readers and writers");
  const u8 raw[4] = {0x01, 0x02, 0x03, 0x04};
  c.eq_u64(rd16be(raw), 0x0102, "rd16be");
  c.eq_u64(rd16le(raw), 0x0201, "rd16le");
  c.eq_u64(rd24be(raw), 0x010203, "rd24be");
  c.eq_u64(rd32be(raw), 0x01020304u, "rd32be");
  c.eq_u64(rd32le(raw), 0x04030201u, "rd32le");
  u8 w[8] = {0};
  wr32be(w, 0xdeadbeefu);
  c.eq_u64(rd32be(w), 0xdeadbeefu, "wr32be/rd32be round trip");
  wr32le(w, 0xdeadbeefu);
  c.eq_u64(rd32le(w), 0xdeadbeefu, "wr32le/rd32le round trip");
  wr64be(w, 0x0123456789abcdefull);
  c.eq_u64(rd64be(w), 0x0123456789abcdefull, "wr64be/rd64be round trip");

  c.section("address formatting and parsing");
  c.eq_str(format_ipv4(0x0a000001u), "10.0.0.1", "format_ipv4");
  c.eq_str(format_mac(mac_of("aa:bb:cc:00:11:22").data()), "aa:bb:cc:00:11:22", "format_mac");

  u32 be = 0;
  c.ok(parse_ipv4("192.168.1.77", &be), "parse_ipv4 accepts dotted quad");
  c.eq_u64(be, 0xc0a8014du, "parse_ipv4 value");
  c.ok(!parse_ipv4("192.168.1.256", &be), "parse_ipv4 rejects out-of-range octet");
  c.ok(!parse_ipv4("192.168.1", &be), "parse_ipv4 rejects short form");

  u8 a16[16] = {0};
  int ver = 0;
  c.ok(parse_ip("2001:db8::1", &ver, a16), "parse_ipv6 with :: compression");
  c.eq_u64(ver, 6, "parse_ip version for IPv6 literal");
  c.eq_str(format_ipv6(a16), "2001:db8::1", "format_ipv6 canonical form");
  c.ok(parse_ip("::1", &ver, a16), "parse_ipv6 loopback");
  c.eq_str(format_ipv6(a16), "::1", "format_ipv6 loopback");
  std::memset(a16, 0, sizeof(a16));
  c.eq_str(format_ipv6(a16), "::", "format_ipv6 unspecified");
  c.ok(parse_ip("::ffff:192.168.1.1", &ver, a16), "parse_ipv6 embedded IPv4");
  c.eq_str(format_ipv6(a16), "::ffff:192.168.1.1", "format_ipv6 embedded IPv4");
  c.ok(parse_ip("10.0.0.1", &ver, a16), "parse_ip accepts IPv4");
  c.eq_u64(ver, 4, "parse_ip version for IPv4 literal");

  int bits = 0;
  u8 prefix[16] = {0};
  c.ok(parse_cidr("192.168.1.0/24", &ver, prefix, &bits), "parse_cidr /24");
  c.eq_u64(ver, 4, "parse_cidr version");
  c.eq_u64(bits, 24, "parse_cidr bits");
  u8 inside[16] = {0};
  int iv = 0;
  parse_ip("192.168.1.55", &iv, inside);
  c.ok(cidr_match(4, inside, prefix, bits), "cidr_match inside prefix");
  u8 outside[16] = {0};
  parse_ip("192.168.2.55", &iv, outside);
  c.ok(!cidr_match(4, outside, prefix, bits), "cidr_match outside prefix");
  c.ok(parse_cidr("10.0.0.0", &ver, prefix, &bits), "parse_cidr without explicit width");
  c.eq_u64(bits, 32, "parse_cidr defaults to the family width");
  c.ok(parse_cidr("2001:db8::/32", &ver, prefix, &bits), "parse_cidr IPv6");
  c.eq_u64(bits, 32, "parse_cidr IPv6 bits");

  c.section("miscellaneous helpers");
  c.eq_str(to_lower("AbC"), "abc", "to_lower");
  c.ok(iequals("Eth0", "eth0"), "iequals");
  c.ok(icontains_lower("Example.COM", "example"), "icontains_lower");
  c.ok(!icontains_lower("Example.COM", "absent"), "icontains_lower negative");
  c.ok(!hexdump(raw, 4, 0, "").empty(), "hexdump produces output");
  c.ok(hexdump(nullptr, 0, 0, "").empty(), "hexdump of empty input yields nothing and is safe");
  c.ok(std::string(ip_proto_name(6)) == "TCP" || !std::string(ip_proto_name(6)).empty(),
       "ip_proto_name(6)");

  c.section("internet checksum");
  {
    Ip4Opts o;
    o.src = "10.0.0.5";
    o.dst = "93.184.216.34";
    std::vector<u8> pkt = ipv4_packet(o, tcp_segment(1, 2, 0, 0, TCP_SYN, 100, {}));
    c.eq_u64(internet_checksum(pkt.data(), 20), 0, "IPv4 header checksum verifies to zero");
  }
}

void test_dissector(Ctx& c, const std::vector<Packet>& samples) {
  c.section("link layer and IPv4/IPv6");
  Dissector d;
  PacketInfo pi;

  c.ok(dissect_packet(d, samples[0], pi), "ARP frame dissects");
  c.eq_u64(pi.ethertype, 0x0806, "ARP ethertype");
  c.ok(pi.is_arp, "ARP flag");
  c.eq_u64(pi.arp_op, 1, "ARP opcode request");
  c.eq_str(format_ipv4(pi.arp_spa), "10.0.0.5", "ARP sender protocol address");
  c.eq_str(format_ipv4(pi.arp_tpa), "10.0.0.1", "ARP target protocol address");
  c.eq_str(format_mac(pi.src_mac), "00:11:22:33:44:55", "ARP sender MAC");
  c.eq_u64(pi.frame_len, samples[0].data.size(), "frame_len equals captured length");

  c.ok(dissect_packet(d, samples[1], pi), "TLS-over-TCP SYN dissects");
  c.eq_u64(pi.ip_version, 4, "IPv4 version");
  c.eq_str(format_ip(pi.ip_version, pi.src_ip), "10.0.0.5", "IPv4 source");
  c.eq_str(format_ip(pi.ip_version, pi.dst_ip), "93.184.216.34", "IPv4 destination");
  c.eq_u64(u64(pi.l4), u64(L4::Tcp), "L4 is TCP");
  c.eq_u64(pi.src_port, 51000, "TCP source port");
  c.eq_u64(pi.dst_port, 443, "TCP destination port");
  c.ok((pi.tcp.flags & TCP_SYN) != 0, "TCP SYN flag");
  c.ok((pi.tcp.flags & TCP_ACK) == 0, "TCP SYN has no ACK");
  c.ok(pi.tcp.has_mss, "TCP MSS option parsed");
  c.eq_u64(pi.tcp.mss, 1460, "TCP MSS value");
  c.eq_u64(pi.tcp.header_len, 24, "TCP header length with options");
  c.ok(pi.l3_df, "IPv4 DF bit");
  c.eq_u64(pi.l3_hoplimit, 64, "IPv4 TTL");
  c.ok(!pi.is_fragment, "DF packet is not a fragment");

  // VLAN
  c.ok(dissect_packet(d, samples[8], pi), "VLAN tagged frame dissects");
  c.ok(pi.has_vlan, "VLAN present");
  c.eq_u64(pi.vlan_id, 100, "VLAN id");
  c.eq_u64(pi.ip_version, 4, "inner IPv4 after VLAN");
  c.eq_u64(u64(pi.l4), u64(L4::Icmp), "inner ICMP after VLAN");
  c.eq_u64(pi.icmp.type, 8, "ICMP echo request");
  c.eq_str(format_ip(pi.ip_version, pi.src_ip), "192.168.100.10", "inner IPv4 source");

  // IPv6
  c.ok(dissect_packet(d, samples[7], pi), "IPv6/UDP DNS dissects");
  c.eq_u64(pi.ip_version, 6, "IPv6 version");
  c.eq_str(format_ip(6, pi.dst_ip), "2001:4860:4860::8888", "IPv6 destination");
  c.eq_u64(u64(pi.l4), u64(L4::Udp), "IPv6 L4 is UDP");
  c.eq_u64(pi.dst_port, 53, "IPv6 UDP port 53");
  c.eq_u64(pi.l3_hoplimit, 64, "IPv6 hop limit");
  c.ok(pi.has_ports, "has_ports set for UDP");
  c.eq_u64(pi.payload_len, samples[7].data.size() - 14 - 40 - 8, "UDP payload length");

  c.section("IPv4 fragment reassembly");
  {
    Dissector f;
    PacketInfo f1;
    const bool ok1 = f.dissect(view_of(samples[9]), f1);
    (void)ok1;
    c.eq_u64(u64(f.last_result()), u64(DissectResult::Fragment), "first fragment is held back");
    c.ok(f1.is_fragment, "first fragment flagged as fragment");
    c.eq_u64(f.pending_fragments(), 1, "one fragment pending");
    c.eq_u64(f.fragments_seen(), 1, "fragments_seen after first fragment");

    PacketInfo f2;
    c.ok(f.dissect(view_of(samples[10]), f2), "second fragment completes the datagram");
    c.eq_u64(u64(f.last_result()), u64(DissectResult::Ok), "reassembled result is Ok");
    c.eq_u64(f.fragments_completed(), 1, "fragments_completed");
    c.eq_u64(f.pending_fragments(), 0, "no fragments pending after completion");
    c.eq_u64(u64(f2.l4), u64(L4::Udp), "reassembled L4 is UDP");
    c.eq_u64(f2.src_port, 5000, "reassembled UDP source port");
    c.eq_u64(f2.dst_port, 5001, "reassembled UDP destination port");
    c.eq_u64(f2.payload_len, 32, "reassembled UDP payload length");
    c.ok(f2.reassembled, "reassembled flag set");
    c.ok(f2.payload && f2.payload[0] == u8('A'), "reassembled payload content");
  }

  c.section("malformed input handling");
  {
    Dissector md;
    PacketInfo mi;
    Packet runt;
    runt.data = {0x00, 0x01, 0x02};
    runt.linktype = DLT_EN10MB;
    c.ok(!md.dissect(runt.view(), mi), "runt Ethernet frame is rejected");
    c.eq_u64(u64(md.last_result()), u64(DissectResult::Malformed), "runt frame reported malformed");
    c.ok(mi.malformed, "malformed flag set");
    c.ok(mi.malformed_reason != nullptr && *mi.malformed_reason != '\0',
         "malformed reason is populated");

    Packet empty;
    empty.linktype = DLT_EN10MB;
    c.ok(!md.dissect(empty.view(), mi), "empty capture is rejected");

    // Truncated IPv4: header claims more payload than was captured.
    Packet cut;
    cut.linktype = DLT_EN10MB;
    std::vector<u8> full = samples[1].data;
    cut.data.assign(full.begin(), full.begin() + 20);
    cut.origlen = full.size();
    c.ok(!md.dissect(cut.view(), mi) || mi.malformed, "truncated IPv4 frame is flagged");
  }

  c.section("raw IP link type");
  {
    Dissector rd;
    PacketInfo ri;
    Packet raw;
    std::vector<u8> ip = ipv4_packet({.src = "172.16.0.1", .dst = "172.16.0.2", .proto = 6},
                                     tcp_segment(1234, 80, 1, 2, u8(TCP_ACK), 512, {}));
    raw.data = ip;
    raw.linktype = DLT_RAW;
    c.ok(rd.dissect(raw.view(), ri), "DLT_RAW packet dissects from the IP header");
    c.eq_u64(ri.ip_version, 4, "DLT_RAW IPv4 version");
    c.eq_u64(ri.dst_port, 80, "DLT_RAW TCP destination port");
    c.ok(ri.has_eth == false, "DLT_RAW has no Ethernet header");
  }
}

void test_application_layer(Ctx& c, const std::vector<Packet>& samples) {
  c.section("application layer");
  Dissector d;
  PacketInfo pi;
  AppInfo app;

  c.ok(dissect_packet(d, samples[1], pi), "TLS packet dissects");
  classify_app(pi, app);
  c.ok(app.kind == AppKind::Tls, "TLS classified from ClientHello signature");
  c.ok(app.tls.is_client_hello, "ClientHello recognised");
  c.eq_str(app.tls.sni, "example.com", "TLS SNI extracted");
  c.eq_u64(app.tls.cipher_count, 1, "TLS cipher suite count");
  c.ok(app.tls.has_supported_versions, "TLS supported_versions extension seen");
  c.eq_u64(app.tls.supported_version, 0x0304, "TLS 1.3 offered");
  c.eq_str(app_hostname(app), "example.com", "app_hostname falls back to SNI");

  c.ok(dissect_packet(d, samples[3], pi), "HTTP request dissects");
  classify_app(pi, app);
  c.ok(app.kind == AppKind::Http, "HTTP classified");
  c.ok(app.http.is_request, "HTTP request flag");
  c.eq_str(app.http.method, "GET", "HTTP method");
  c.eq_str(app.http.uri, "/index.html", "HTTP request target");
  c.eq_str(app.http.host, "example.com", "HTTP Host header");
  c.eq_str(app.http.user_agent, "netcap-selftest/1.0", "HTTP User-Agent");
  c.eq_u64(app.http.version_major, 1, "HTTP major version");
  c.eq_u64(app.http.version_minor, 1, "HTTP minor version");
  c.ok(app.http.header_count >= 3, "HTTP header count");
  c.eq_str(app_hostname(app), "example.com", "app_hostname prefers HTTP Host");

  c.ok(dissect_packet(d, samples[4], pi), "HTTP response dissects");
  classify_app(pi, app);
  c.ok(app.http.is_response, "HTTP response flag");
  c.eq_u64(app.http.status, 200, "HTTP status code");
  c.eq_str(app.http.reason, "OK", "HTTP reason phrase");
  c.eq_str(app.http.server, "netcap-selftest", "HTTP Server header");
  c.ok(app.http.has_content_length, "HTTP Content-Length seen");
  c.eq_u64(app.http.content_length, 13, "HTTP Content-Length value");
  c.eq_str(app.http.content_type, "text/html", "HTTP Content-Type");
  {
    Dissector hd;
    PacketInfo hp;
    hd.dissect(view_of(samples[4]), hp);
    AppInfo ha;
    classify_app(hp, ha);
    const std::size_t body = http_body_offset(ha.http);
    c.ok(body <= hp.payload_len, "HTTP body offset within payload");
    const std::string body_text(reinterpret_cast<const char*>(hp.payload + body),
                                hp.payload_len - body);
    c.eq_str(body_text, "Hello, world!", "HTTP body located correctly");
  }

  c.ok(dissect_packet(d, samples[5], pi), "DNS query dissects");
  classify_app(pi, app);
  c.ok(app.kind == AppKind::Dns, "DNS classified");
  c.ok(app.dns.valid, "DNS header valid");
  c.ok(!app.dns.is_response, "DNS query direction");
  c.eq_u64(app.dns.qtype, 1, "DNS query type A");
  c.eq_str(app.dns.qname, "www.example.com", "DNS question name");
  c.eq_str(app_hostname(app), "www.example.com", "app_hostname falls back to DNS qname");

  c.ok(dissect_packet(d, samples[6], pi), "DNS response dissects");
  classify_app(pi, app);
  c.ok(app.dns.is_response, "DNS response direction");
  c.eq_u64(app.dns.ancount, 1, "DNS answer count");
  c.eq_u64(app.dns.rcode, 0, "DNS rcode NOERROR");
  c.eq_str(app.dns.qname, "www.example.com", "DNS response question name");

  c.ok(dissect_packet(d, samples[11], pi), "SSH banner dissects");
  classify_app(pi, app);
  c.ok(app.kind == AppKind::Ssh, "SSH classified from banner");

  c.ok(dissect_packet(d, samples[12], pi), "QUIC-looking packet dissects");
  classify_app(pi, app);
  c.ok(app.kind == AppKind::Quic, "QUIC classified from UDP/443 long header");

  c.ok(dissect_packet(d, samples[14], pi), "DHCP discover dissects");
  classify_app(pi, app);
  c.ok(app.kind == AppKind::Dhcp, "DHCP classified from ports 68->67");

  c.ok(dissect_packet(d, samples[13], pi), "ICMPv6 dissects");
  c.eq_u64(u64(pi.l4), u64(L4::Icmpv6), "ICMPv6 protocol number");
  c.eq_u64(pi.icmp.type, 128, "ICMPv6 echo request type");
}

void test_filter(Ctx& c, const std::vector<Packet>& samples) {
  c.section("filter engine");
  Dissector d;
  std::vector<PacketInfo> infos(samples.size());
  std::vector<AppInfo> apps(samples.size());
  for (std::size_t i = 0; i < samples.size(); ++i) {
    d.dissect(view_of(samples[i]), infos[i]);
    classify_app(infos[i], apps[i]);
  }
  const std::size_t kTls = 1, kHttp = 3, kDns = 5, kArp = 0, kVlan = 8, kSsh = 11, kQuic = 12;

  auto matches = [&](const char* expr, std::size_t idx, bool use_app = true) {
    std::string err;
    Filter f = Filter::parse(expr, &err);
    if (f.parse_failed()) return false;
    return f.match(infos[idx], use_app ? &apps[idx] : nullptr);
  };

  auto parses = [&](const char* expr) {
    std::string err;
    Filter f = Filter::parse(expr, &err);
    return !f.parse_failed();
  };

  c.ok(parses("tcp"), "parses 'tcp'");
  c.ok(parses("tcp and dst port 443 and not net 10.0.0.0/8"), "parses a compound expression");
  c.ok(parses("(udp or icmp) and not vlan"), "parses parentheses");
  c.ok(parses("tcp port 80 or tcp port 443"), "parses implicit and with explicit or");
  c.ok(parses(""), "parses the empty filter as match-all");
  c.ok(!parses("tcp and"), "rejects a dangling operator");
  c.ok(!parses("hostname"), "rejects a primitive without a value");
  c.ok(!parses("host not-an-ip"), "rejects a non-literal host");
  c.ok(!parses("tcpflags bogus"), "rejects an invalid flag set");
  c.ok(!parses("payload \"unterminated"), "rejects an unterminated string");
  c.ok(!parses("frobnicate"), "rejects an unknown primitive");
  c.ok(!parses("(tcp"), "rejects a missing close parenthesis");

  c.ok(matches("tcp", kTls), "tcp matches the TLS packet");
  c.ok(!matches("tcp", kArp), "tcp does not match ARP");
  c.ok(matches("udp", kDns), "udp matches the DNS packet");
  c.ok(matches("arp", kArp), "arp matches the ARP packet");
  c.ok(matches("ip6", kQuic), "ip6 matches the IPv6 packet");
  c.ok(!matches("ip6", kHttp), "ip6 does not match the IPv4 packet");

  c.ok(matches("dst port 443", kTls), "dst port 443");
  c.ok(matches("src port 51000", kTls), "src port 51000");
  c.ok(!matches("dst port 443", kHttp), "dst port 443 does not match HTTP");
  c.ok(matches("port 53", kDns), "port 53 matches DNS");
  c.ok(matches("portrange 440-450", kTls), "portrange");
  c.ok(matches("host 93.184.216.34", kTls), "host matches the remote address");
  c.ok(!matches("host 93.184.216.34 and src host 93.184.216.34", kTls),
       "src host excludes the client-to-server packet");
  c.ok(matches("net 93.184.216.0/24", kTls), "net /24");
  c.ok(matches("net 10.0.0.0/8", kTls), "net matches either endpoint");
  c.ok(!matches("net 203.0.113.0/24", kTls), "net does not match an unrelated prefix");
  c.ok(matches("vlan 100", kVlan), "vlan id match");
  c.ok(!matches("vlan 200", kVlan), "vlan id mismatch");
  c.ok(!matches("vlan 100", kHttp), "untagged packet has no vlan");
  c.ok(matches("tcpflags syn", kTls), "tcpflags syn");
  c.ok(!matches("tcpflags syn", kHttp), "tcpflags syn excludes plain ACK/PSH");
  c.ok(matches("tcpflags syn-ack", 2), "tcpflags syn-ack");
  c.ok(matches("tcpflags 0x02/0xff", kTls), "tcpflags numeric form");
  c.ok(!matches("tcpflags 0x12/0xff", kTls), "tcpflags numeric mismatch");
  c.ok(matches("len > 100", kTls), "len comparison");
  c.ok(matches("ttl = 64", kTls), "ttl comparison");
  c.ok(!matches("ttl > 100", kTls), "ttl comparison negative");

  c.ok(matches("http", kHttp), "http primitive via classification");
  c.ok(matches("tls", kTls), "tls primitive via classification");
  c.ok(matches("https", kTls), "https is an alias of tls");
  c.ok(matches("ssh", kSsh), "ssh primitive");
  c.ok(matches("quic", kQuic), "quic primitive");
  c.ok(matches("dns", kDns), "dns primitive");
  c.ok(matches("hostname example.com", kTls), "hostname matches the TLS SNI");
  c.ok(matches("hostname example", kTls), "hostname substring match");
  c.ok(matches("hostname EXAMPLE.COM", kTls), "hostname match is case-insensitive");
  c.ok(!matches("hostname cloudflare.com", kTls), "hostname mismatch");
  c.ok(matches("url /index.html", kHttp), "url substring against the request target");
  c.ok(!matches("url /missing", kHttp), "url mismatch");
  c.ok(matches("payload \"GET /index\"", kHttp), "payload substring");
  c.ok(matches("tcp and dst port 443 and (tls or quic)", kTls), "compound expression end to end");
  c.ok(!matches("tcp and dst port 443 and (tls or quic)", kHttp), "compound expression negative");

  {
    Filter none = Filter::parse("", nullptr);
    c.ok(none.match(infos[kArp], &apps[kArp]), "empty filter matches everything");
    c.ok(none.match_all(), "MatchAll flag for an empty filter");
  }
  {
    std::string err;
    Filter bad = Filter::parse("tcp and", &err);
    c.ok(bad.parse_failed(), "failed parse is remembered");
    c.ok(!err.empty(), "failed parse reports a reason");
    c.ok(!bad.match(infos[kTls], &apps[kTls]), "failed filter matches nothing");
  }
  // Process primitives.  The filter only sees a ProcessInfo when the caller
  // passes one in, so an unattributed packet never satisfies them.
  {
    ProcessInfo chrome;
    chrome.pid = 1234;
    chrome.name = "chrome.exe";
    chrome.key = "chrome.exe";
    chrome.path = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

    Filter by_name = Filter::parse("proc chrome", nullptr);
    c.ok(!by_name.parse_failed(), "proc name parses");
    c.ok(by_name.match(infos[kTls], &apps[kTls], &chrome), "proc matches the process name");
    c.ok(!by_name.match(infos[kTls], &apps[kTls], nullptr), "proc matches nothing without attribution");

    Filter by_pid = Filter::parse("pid 1234", nullptr);
    c.ok(by_pid.match(infos[kTls], &apps[kTls], &chrome), "pid matches the attributed process");
    Filter other_pid = Filter::parse("pid 4321", nullptr);
    c.ok(!other_pid.match(infos[kTls], &apps[kTls], &chrome), "pid mismatch");

    Filter bare = Filter::parse("proc", nullptr);
    c.ok(bare.match(infos[kTls], &apps[kTls], &chrome), "bare proc means attributed to some process");
    c.ok(!bare.match(infos[kTls], &apps[kTls], nullptr), "bare proc fails when unattributed");

    Filter by_path = Filter::parse("proc google", nullptr);
    c.ok(by_path.match(infos[kTls], &apps[kTls], &chrome), "proc matches the image path");
    c.ok(!by_path.match(infos[kTls], &apps[kTls], nullptr), "path match needs attribution too");

    Filter combined = Filter::parse("proc chrome and dst port 443", nullptr);
    c.ok(combined.match(infos[kTls], &apps[kTls], &chrome), "proc combined with a port");

    std::string perr;
    Filter bad_pid = Filter::parse("pid abc", &perr);
    c.ok(bad_pid.parse_failed() && !perr.empty(), "a pid that is not a number is rejected");
    Filter missing_pid = Filter::parse("pid", &perr);
    c.ok(missing_pid.parse_failed(), "pid without a value is rejected");

    // Proxy correlation primitives: proxied / via <proxy> / origin <app>.
    ProxyLink link;
    link.proxy_pid = 900;
    link.proxy_name = "clash-win64.exe";
    link.origin_pid = 1234;
    link.origin_name = "chrome.exe";
    link.family = 4;
    link.confidence = ProxyConfidence::Order;

    Filter proxied = Filter::parse("proxied", nullptr);
    c.ok(!proxied.parse_failed(), "proxied parses");
    c.ok(proxied.match(infos[kTls], &apps[kTls], &chrome, &link), "proxied matches a correlated packet");
    c.ok(!proxied.match(infos[kTls], &apps[kTls], &chrome, nullptr), "proxied fails without a link");

    Filter via = Filter::parse("via clash", nullptr);
    c.ok(via.match(infos[kTls], &apps[kTls], &chrome, &link), "via matches the proxy name");
    c.ok(!via.match(infos[kTls], &apps[kTls], &chrome, nullptr), "via needs a link");
    Filter via_pid = Filter::parse("via 900", nullptr);
    c.ok(via_pid.match(infos[kTls], &apps[kTls], &chrome, &link), "via matches the proxy pid");
    Filter via_other = Filter::parse("via 901", nullptr);
    c.ok(!via_other.match(infos[kTls], &apps[kTls], &chrome, &link), "via pid mismatch");

    Filter origin = Filter::parse("origin chrome", nullptr);
    c.ok(origin.match(infos[kTls], &apps[kTls], &chrome, &link), "origin matches the real application");
    c.ok(!origin.match(infos[kTls], &apps[kTls], &chrome, nullptr), "origin needs a link");
    Filter origin_pid = Filter::parse("origin 1234", nullptr);
    c.ok(origin_pid.match(infos[kTls], &apps[kTls], &chrome, &link), "origin matches the real pid");
    c.ok(origin.match(infos[kTls], &apps[kTls], nullptr, &link),
         "origin does not need the proxy process to be named too");

    Filter behind = Filter::parse("origin chrome and dst port 443", nullptr);
    c.ok(behind.match(infos[kTls], &apps[kTls], &chrome, &link), "origin combines with other primitives");
    Filter no_value = Filter::parse("origin", &perr);
    c.ok(no_value.parse_failed() && !perr.empty(), "origin without a value is rejected");
  }
  c.ok(!filter_syntax_help().empty(), "syntax help is available");
}

void test_pcap(Ctx& c, const std::vector<Packet>& samples) {
  c.section("pcap writer and reader");
  const std::string path = "netcap_selftest_tmp.pcap";
  std::string err;
  {
    PcapWriter w;
    c.ok(w.open(path, DLT_EN10MB, 262144, false, &err), "pcap writer opens: " + err);
    for (std::size_t i = 0; i < samples.size() && i < 6; ++i) {
      c.ok(w.write(samples[i], &err), "pcap write record: " + err);
    }
    c.eq_u64(w.packets_written(), 6, "packets_written");
    c.ok(w.bytes_written() > 0, "bytes_written");
    w.close();
  }
  {
    PcapReader r;
    c.ok(r.open(path, &err), "pcap reader opens: " + err);
    c.eq_u64(u64(r.linktype()), u64(DLT_EN10MB), "round-tripped linktype");
    c.eq_u64(r.snaplen(), 262144, "round-tripped snaplen");
    c.eq_u64(r.version_major(), 2, "round-tripped major version");
    c.eq_u64(r.version_minor(), 4, "round-tripped minor version");
    c.ok(!r.nanosecond(), "microsecond magic detected");
    c.ok(!r.big_endian(), "little-endian file detected");
    int n = 0;
    Packet p;
    while (r.next(p)) {
      if (std::size_t(n) < samples.size() && n < 6) {
        c.eq_u64(p.data.size(), samples[n].data.size(), "round-tripped record length " +
                                                           std::to_string(n));
        c.eq_u64(u64(p.ts_us), u64(samples[n].ts_us), "round-tripped timestamp " +
                                                          std::to_string(n));
        c.ok(p.data == samples[n].data, "round-tripped bytes " + std::to_string(n));
        c.eq_u64(u64(p.linktype), u64(DLT_EN10MB), "round-tripped packet linktype");
      }
      ++n;
    }
    c.eq_u64(n, 6, "reader yielded every record");
    c.ok(r.eof(), "reader reports EOF");
    c.ok(!r.failed(), "reader reports no error at EOF");
    r.close();
  }
  std::remove(path.c_str());

  // A hand-built big-endian file must be decoded as well.
  const std::string be_path = "netcap_selftest_be.pcap";
  {
    std::FILE* f = std::fopen(be_path.c_str(), "wb");
    c.ok(f != nullptr, "big-endian fixture created");
    if (f) {
      u8 h[24] = {0};
      wr32be(h + 0, 0xa1b2c3d4u);
      wr16be(h + 4, 2);
      wr16be(h + 6, 4);
      wr32be(h + 16, 65535);
      wr32be(h + 20, 1);
      std::fwrite(h, 1, sizeof(h), f);
      u8 rh[16] = {0};
      wr32be(rh + 0, 1700000123u);
      wr32be(rh + 4, 456789u);
      wr32be(rh + 8, u32(samples[0].data.size()));
      wr32be(rh + 12, u32(samples[0].data.size()));
      std::fwrite(rh, 1, sizeof(rh), f);
      std::fwrite(samples[0].data.data(), 1, samples[0].data.size(), f);
      std::fclose(f);
    }
  }
  {
    PcapReader r;
    c.ok(r.open(be_path, &err), "big-endian file opens: " + err);
    c.ok(r.big_endian(), "big-endian byte order detected");
    Packet p;
    c.ok(r.next(p), "big-endian record read");
    c.eq_u64(u64(p.ts_us), 1700000123456789ll, "big-endian timestamp decoded");
    c.eq_u64(p.data.size(), samples[0].data.size(), "big-endian record length");
    c.ok(p.data == samples[0].data, "big-endian payload bytes");
  }
  std::remove(be_path.c_str());

  // Garbage and pcapng must produce a useful error, not a crash.
  const std::string junk = "netcap_selftest_junk.bin";
  {
    std::FILE* f = std::fopen(junk.c_str(), "wb");
    if (f) {
      const char text[] = "not a capture file at all, but long enough to read a header";
      std::fwrite(text, 1, sizeof(text) - 1, f);
      std::fclose(f);
    }
  }
  {
    PcapReader r;
    std::string e2;
    c.ok(!r.open(junk, &e2), "garbage file is rejected");
    c.ok(!e2.empty(), "garbage file reports a reason");
  }
  std::remove(junk.c_str());

  const std::string ng = "netcap_selftest_ng.bin";
  {
    std::FILE* f = std::fopen(ng.c_str(), "wb");
    if (f) {
      u8 b[64] = {0x0a, 0x0d, 0x0d, 0x0a};
      std::fwrite(b, 1, sizeof(b), f);
      std::fclose(f);
    }
  }
  {
    PcapReader r;
    std::string e3;
    c.ok(!r.open(ng, &e3), "pcapng file is rejected");
    c.ok(e3.find("pcapng") != std::string::npos, "pcapng error explains the format problem");
  }
  std::remove(ng.c_str());

  c.section("nanosecond pcap");
  {
    const std::string ns_path = "netcap_selftest_ns.pcap";
    PcapWriter w;
    std::string e4;
    c.ok(w.open(ns_path, DLT_RAW, 65535, true, &e4), "nanosecond writer opens");
    Packet p;
    p.data = ipv4_packet({.src = "10.9.9.9", .dst = "10.9.9.10"}, tcp_segment(1, 2, 0, 0, 0, 0, {}));
    p.origlen = p.data.size();
    p.ts_us = 1700000000123456ll;
    p.linktype = DLT_RAW;
    c.ok(w.write(p, &e4), "nanosecond record written");
    w.close();
    PcapReader r;
    c.ok(r.open(ns_path, &e4), "nanosecond file opens");
    c.ok(r.nanosecond(), "nanosecond magic detected");
    Packet q;
    c.ok(r.next(q), "nanosecond record read");
    c.eq_u64(u64(q.ts_us), 1700000000123456ll, "nanosecond timestamp preserved to microseconds");
    c.eq_u64(u64(q.linktype), u64(DLT_RAW), "DLT_RAW preserved");
    r.close();
    std::remove(ns_path.c_str());
  }
}

void test_capture_layer(Ctx& c) {
  c.section("capture layer");
  std::string note;
  c.ok(live_capture_supported(&note), "live capture is implemented on this platform");
  c.ok(!note.empty(), "live capture mechanism is described");
  c.ok(!live_capture_requirement().empty(), "privilege requirement is documented");

  std::vector<DeviceInfo> devs;
  std::string err;
  const bool ok = list_devices(devs, &err);
  if (!ok) {
    c.log += "  note device enumeration unavailable: " + err + "\n";
  }
  for (const DeviceInfo& d : devs) {
    c.ok(!d.name.empty(), "enumerated device has a name");
  }
  c.log += "  note " + std::to_string(devs.size()) + " device(s) enumerated\n";

  std::unique_ptr<CaptureBackend> file = make_file_backend();
  c.ok(file != nullptr, "file backend can be constructed");

  c.section("capture layer: device selection");
  {
    DeviceInfo lan;
    lan.name = "WLAN";
    lan.description = "Intel(R) Wi-Fi 6 AX201 160MHz";
    lan.address = "192.168.0.24";
    lan.mac = "1e:00:45:70:e5:9d";
    lan.ifindex = 22;
    lan.family = 4;
    lan.up = true;
    lan.is_default = true;

    DeviceInfo eth;
    eth.name = "Ethernet";
    eth.description = "Realtek PCIe GbE Family Controller";
    eth.address = "10.1.2.3";
    eth.ifindex = 14;
    eth.family = 4;
    eth.up = true;

    DeviceInfo tap;
    tap.name = "cfw-tap";
    tap.description = "TAP-Windows Adapter V9";
    tap.address = "10.0.0.1";
    tap.ifindex = 17;
    tap.family = 4;
    tap.up = true;
    tap.tunnel = device_looks_like_tunnel(tap.name, tap.description);

    DeviceInfo wg;
    wg.name = "wg0";
    wg.description = "WireGuard Tunnel";
    wg.address = "10.7.0.2";
    wg.ifindex = 31;
    wg.family = 4;
    wg.up = true;
    wg.tunnel = device_looks_like_tunnel(wg.name, wg.description);

    DeviceInfo v6only;
    v6only.name = "Ethernet 3";
    v6only.description = "USB Ethernet";
    v6only.address = "fe80::1";
    v6only.ifindex = 9;
    v6only.family = 6;
    v6only.up = true;

    DeviceInfo downTap;
    downTap.name = "cfw-tap";  // same adapter, not up: --with-tunnel must skip it
    downTap.description = "TAP-Windows Adapter V9";
    downTap.address = "10.0.0.1";
    downTap.ifindex = 18;
    downTap.family = 4;
    downTap.up = false;
    downTap.tunnel = device_looks_like_tunnel(downTap.name, downTap.description);

    c.ok(device_looks_like_tunnel("cfw-tap", "TAP-Windows Adapter V9"),
         "cfw-tap is recognised as a tunnel");
    c.ok(device_looks_like_tunnel("wg0", "WireGuard Tunnel"), "wg0 is a tunnel");
    c.ok(!device_looks_like_tunnel("WLAN", "Intel(R) Wi-Fi 6 AX201 160MHz"),
         "the Wi-Fi adapter is not a tunnel");
    c.ok(!device_looks_like_tunnel("Ethernet", "Realtek PCIe GbE Family Controller"),
         "a wired adapter is not a tunnel");
    c.ok(!device_looks_like_tunnel("以太网", "Realtek USB GbE"), "a non-ASCII name is fine");

    const std::vector<DeviceInfo> all = {lan, eth, tap, wg, v6only};
    // find_device returns a pointer into `all`, never into the locals above.
    c.ok(find_device(all, "", nullptr) == &all[0], "an empty request prefers the default route");
    c.ok(find_device(all, "Ethernet", nullptr) == &all[1], "an exact name matches");
    c.ok(find_device(all, "wlan", nullptr) == &all[0], "a name matches case-insensitively");
    c.ok(find_device(all, "22", nullptr) == &all[0], "a decimal index matches");
    c.ok(find_device(all, "10.0.0.1", nullptr) == &all[2], "an address matches");
    c.ok(find_device(all, "realtek pcie", nullptr) == &all[1],
         "a description substring matches too");
    c.ok(find_device(all, "cfw", nullptr) == &all[2], "a name substring matches");
    std::string derr = "untouched";
    c.ok(find_device(all, "nope", &derr) == nullptr, "an unknown name finds nothing");
    c.ok(derr.find("no interface matches") != std::string::npos, "and says so");

    CaptureConfig cfg;
    std::vector<DeviceInfo> chosen;
    std::string serr;
    c.ok(select_devices(all, cfg, &chosen, &serr), "selecting with an empty config works");
    c.eq_u64(chosen.size(), 1, "an empty request selects exactly one interface");
    c.eq_u64(chosen.front().ifindex, 22, "and it is the default route");

    cfg.device = "all";
    c.ok(select_devices(all, cfg, &chosen, &serr), "'-i all' works");
    c.eq_u64(chosen.size(), 4, "'-i all' takes every up IPv4 interface (incl. tunnels)");
    c.eq_u64(chosen.back().ifindex, 31, "in enumeration order");
    cfg.device.clear();

    cfg.device = "Ethernet";
    cfg.extra_devices = {"cfw-tap"};
    c.ok(select_devices(all, cfg, &chosen, &serr), "a primary plus an extra interface works");
    c.eq_u64(chosen.size(), 2, "both interfaces are opened");
    c.eq_u64(chosen.front().ifindex, 14, "the first -i stays first");
    c.eq_u64(chosen.back().ifindex, 17, "the extra follows");
    cfg.extra_devices = {"cfw-tap", "14"};
    c.ok(select_devices(all, cfg, &chosen, &serr), "naming the same interface twice works");
    c.eq_u64(chosen.size(), 2, "duplicates are removed");
    cfg.extra_devices = {"nosuchif"};
    c.ok(!select_devices(all, cfg, &chosen, &serr), "an unknown extra interface is fatal");
    c.ok(serr.find("no interface matches") != std::string::npos, "with a clear error");
    cfg.extra_devices.clear();

    cfg.device = "Ethernet 3";
    c.ok(!select_devices(all, cfg, &chosen, &serr), "an IPv6-only interface is refused");
    c.ok(serr.find("no IPv4 address") != std::string::npos, "for the right reason");
    cfg.device.clear();

    cfg.device = "Ethernet";
    cfg.with_tunnel = true;
    c.ok(select_devices(all, cfg, &chosen, &serr), "--with-tunnel works");
    c.eq_u64(chosen.size(), 3, "--with-tunnel appends a second tunnel adapter");
    c.eq_u64(chosen[1].ifindex, 17, "cfw-tap comes along with the physical NIC");
    c.eq_u64(chosen[2].ifindex, 31, "so does the WireGuard adapter");

    const std::vector<DeviceInfo> withDown = {lan, downTap};
    cfg.device.clear();
    cfg.with_tunnel = true;
    c.ok(select_devices(withDown, cfg, &chosen, &serr), "selecting with a down tunnel works");
    c.eq_u64(chosen.size(), 1, "a tunnel that is down is not opened");
    c.ok(chosen.front().tunnel == false, "and the physical interface is the one asked for");
  }
}

// ---------------------------------------------------------------------------
// Cryptography (TLS decryption support)
// ---------------------------------------------------------------------------

Bytes bstr(const char* s) { return Bytes(s, s + std::strlen(s)); }

void test_crypto(Ctx& c) {
  const Bytes abc = bstr("abc");

  c.section("crypto: hex helpers");
  c.eq_str(to_hex(from_hex("00ff 10:20-30")), "00ff102030", "from_hex ignores separators");
  c.eq_str(to_hex(from_hex("deadBEEF")), "deadbeef", "from_hex accepts upper case");
  c.eq_hex(from_hex("zz"), "", "from_hex drops non-hex characters");

  c.section("crypto: SHA-2 (FIPS 180-4)");
  c.eq_hex(sha256(Bytes{}),
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "sha256 of the empty string");
  c.eq_hex(sha256(abc), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "sha256(\"abc\")");
  c.eq_hex(sha256(bstr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
           "sha256 of the 56 byte sample");
  c.eq_hex(sha256(bstr("The quick brown fox jumps over the lazy dog")),
           "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
           "sha256 of a sentence");
  c.eq_hex(sha256(Bytes(1000000, 'a')),
           "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
           "sha256 of one million 'a' (multi block padding)");
  c.eq_hex(sha384(abc),
           "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
           "8086072ba1e7cc2358baeca134c825a7",
           "sha384(\"abc\")");
  c.eq_hex(sha512(abc),
           "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
           "sha512(\"abc\")");

  c.section("crypto: HMAC-SHA256 (RFC 4231)");
  c.eq_hex(hmac_sha256(Bytes(20, 0x0b), bstr("Hi There")),
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
           "HMAC-SHA256 case 1");
  c.eq_hex(hmac_sha256(bstr("Jefe"), bstr("what do ya want for nothing?")),
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
           "HMAC-SHA256 case 2");
  c.eq_hex(hmac_sha256(Bytes(20, 0xaa), Bytes(50, 0xdd)),
           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
           "HMAC-SHA256 case 3 (binary key and data)");

  c.section("crypto: HKDF (RFC 5869)");
  {
    Bytes ikm(22, 0x0b);
    Bytes salt = from_hex("000102030405060708090a0b0c");
    Bytes info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    Bytes prk = hkdf_extract(salt, ikm, false);
    c.eq_hex(prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
             "HKDF-Extract test case 1 PRK");
    c.eq_hex(hkdf_expand(prk, info, 42, false),
             "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
             "34007208d5b887185865",
             "HKDF-Expand test case 1 OKM");
    Bytes prk3 = hkdf_extract(Bytes{}, ikm, false);
    c.eq_hex(hkdf_expand(prk3, Bytes{}, 42, false),
             "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
             "9d201395faa4b61a96c8",
             "HKDF test case 3 (empty salt and info)");
  }

  c.section("crypto: TLS 1.3 HKDF-Expand-Label");
  {
    // The label is prefixed with "tls13 " and wrapped in the RFC 8446 struct.
    Bytes secret(32, 0x01);
    Bytes a = hkdf_expand_label(secret, "key", Bytes{}, 16, false);
    Bytes info;
    const std::string full = "tls13 key";
    info.push_back(0x00);
    info.push_back(0x10);
    info.push_back(u8(full.size()));
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0x00);
    c.eq_hex(a, to_hex(hkdf_expand(secret, info, 16, false)),
             "expand_label matches the hand built HkdfLabel");
    c.eq_u64(a.size(), 16, "expand_label honours the requested length");
    // A different length changes the HkdfLabel struct, so the output differs;
    // the longer one must still match its own hand built info block.
    Bytes b = hkdf_expand_label(secret, "key", Bytes{}, 32, false);
    c.ok(a != b, "a different requested length gives a different output");
    Bytes info2 = info;
    info2[0] = 0x00;
    info2[1] = 0x20;
    c.eq_hex(b, to_hex(hkdf_expand(secret, info2, 32, false)),
             "expand_label matches the 32 byte HkdfLabel");
  }

  c.section("crypto: AES (FIPS-197)");
  {
    const std::string pt = "00112233445566778899aabbccddeeff";
    struct Tv {
      const char* key;
      const char* ct;
    } tvs[3] = {
        {"000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"},
        {"000102030405060708090a0b0c0d0e0f1011121314151617",
         "dda97ca4864cdfe06eaf70a0ec0d7191"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"},
    };
    for (int i = 0; i < 3; ++i) {
      Aes aes;
      Bytes key = from_hex(tvs[i].key);
      c.ok(aes.set_key(key), std::string("AES-") + std::to_string(key.size() * 8) + " key setup");
      c.eq_u64(u64(aes.rounds()), key.size() == 16 ? 10 : (key.size() == 24 ? 12 : 14),
               "round count follows the key length");
      u8 in[16], out[16], back[16];
      std::memcpy(in, from_hex(pt).data(), 16);
      aes.encrypt_block(in, out);
      c.eq_hex(Bytes(out, out + 16), tvs[i].ct, std::string("AES-") +
                                                   std::to_string(key.size() * 8) + " encrypt");
      aes.decrypt_block(out, back);
      c.eq_hex(Bytes(back, back + 16), pt, std::string("AES-") +
                                            std::to_string(key.size() * 8) + " decrypt");
    }
    Aes bad;
    c.ok(!bad.set_key(Bytes(15, 0)), "a 15 byte key is rejected");
  }

  c.section("crypto: AES-CTR and AES-CBC");
  {
    Aes aes;
    aes.set_key(from_hex("2b7e151628aed2a6abf7158809cf4f3c"));
    // FIPS-197 appendix B style round trip plus the CBC chaining check.
    Bytes plain = bstr("The quick brown fox jumps over the lazy dog!!");  // 45 bytes
    Bytes ctr = plain;
    aes_ctr_xor(aes, from_hex("f0f1f2f3f4f5f6f7f8f9fafb").data(), 1, ctr.data(), ctr.size());
    c.ok(ctr != plain, "CTR output differs from the plaintext");
    aes_ctr_xor(aes, from_hex("f0f1f2f3f4f5f6f7f8f9fafb").data(), 1, ctr.data(), ctr.size());
    c.eq_str(std::string(ctr.begin(), ctr.end()), std::string(plain.begin(), plain.end()),
             "CTR is its own inverse (including the trailing partial block)");

    Bytes block = from_hex("6bc1bee22e409f96e93d7e117393172a");
    Bytes iv = from_hex("000102030405060708090a0b0c0d0e0f");
    Bytes enc(16), dec(16);
    aes_cbc_encrypt(aes, iv.data(), block.data(), 16, enc.data());
    // NIST SP 800-38A F.2.1 CBC-AES128 vector.
    c.eq_hex(enc, "7649abac8119b246cee98e9b12e9197d", "AES-128-CBC NIST vector");
    aes_cbc_decrypt(aes, iv.data(), enc.data(), 16, dec.data());
    c.eq_hex(dec, to_hex(block), "AES-128-CBC decrypt round trip");
  }

  c.section("crypto: AES-GCM (NIST vectors)");
  {
    AeadResult r = aes_gcm_encrypt(Bytes(16, 0), Bytes(12, 0), Bytes{}, Bytes{});
    c.ok(r.ok, "encrypting an empty message succeeds");
    c.eq_hex(r.tag, "58e2fccefa7e3061367f1d57a4e7455a", "GCM test case 1 tag");

    r = aes_gcm_encrypt(Bytes(16, 0), Bytes(12, 0), Bytes{}, Bytes(16, 0));
    c.eq_hex(r.ciphertext, "0388dace60b6a392f328c2b971b2fe78", "GCM test case 2 ciphertext");
    c.eq_hex(r.tag, "ab6e47d42cec13bdf53a67b21257bddf", "GCM test case 2 tag");

    r = aes_gcm_encrypt(Bytes(32, 0), Bytes(12, 0), Bytes{}, Bytes(16, 0));
    c.eq_hex(r.ciphertext, "cea7403d4d606b6e074ec5d3baf39d18", "GCM test case 4 ciphertext");
    c.eq_hex(r.tag, "d0d1c8a799996bf0265b98b5d48ab919", "GCM test case 4 tag");

    // With additional data, and an authentication failure path.
    Bytes key = from_hex("feffe9928665731c6d6a8f9467308308");
    Bytes nonce = from_hex("cafebabefacedbaddecaf888");
    Bytes aad = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    Bytes pt = bstr("HTTP/1.1 200 OK\r\n\r\nsecret");
    AeadResult e = aes_gcm_encrypt(key, nonce, aad, pt);
    c.ok(e.ok && e.ciphertext.size() == pt.size(), "GCM with AAD produces a ciphertext");
    Bytes back;
    c.ok(aes_gcm_decrypt(key, nonce, aad, e.ciphertext, e.tag, &back), "GCM decrypt accepts the tag");
    c.eq_hex(back, to_hex(pt), "GCM round trip returns the plaintext");
    c.ok(!aes_gcm_decrypt(key, nonce, from_hex("00"), e.ciphertext, e.tag, &back),
         "a different AAD fails authentication");
    Bytes tampered = e.ciphertext;
    tampered[0] ^= 0x01;
    c.ok(!aes_gcm_decrypt(key, nonce, aad, tampered, e.tag, &back),
         "a flipped ciphertext bit fails authentication");
    Bytes badtag = e.tag;
    badtag[15] ^= 0x80;
    c.ok(!aes_gcm_decrypt(key, nonce, aad, e.ciphertext, badtag, &back),
         "a wrong tag fails authentication");
  }

  c.section("crypto: ChaCha20-Poly1305 (RFC 8439)");
  {
    Bytes key = from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    Bytes nonce = from_hex("070000004041424344454647");
    Bytes aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    Bytes pt = bstr(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it.");
    AeadResult r = chacha20_poly1305_encrypt(key, nonce, aad, pt);
    c.ok(r.ok, "ChaCha20-Poly1305 encrypt succeeds");
    c.eq_str(to_hex(r.ciphertext).substr(0, 32), "d31a8d34648e60db7b86afbc53ef7ec2",
             "AEAD ciphertext prefix");
    c.eq_hex(r.tag, "1ae10b594f09e26a7e902ecbd0600691", "AEAD tag");
    Bytes back;
    c.ok(chacha20_poly1305_decrypt(key, nonce, aad, r.ciphertext, r.tag, &back),
         "AEAD decrypt accepts the tag");
    c.eq_hex(back, to_hex(pt), "AEAD round trip returns the plaintext");
    c.ok(!chacha20_poly1305_decrypt(key, nonce, aad, r.ciphertext, from_hex("00"), &back),
         "a short tag is rejected");

    // Poly1305 alone (RFC 8439 section 2.5.2).
    c.eq_hex(poly1305(from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                      bstr("Cryptographic Forum Research Group")),
             "a8061dc1305136c6c22b8baf0c0127a9", "Poly1305 test vector");
    // The four-block SSE2 path has to agree with the scalar loop at every
    // length, including the ones that straddle a 64-byte group boundary.
    {
      const Bytes pkey = from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
      bool agree = true;
      std::size_t bad_len = 0;
      for (const std::size_t len : {std::size_t(0), std::size_t(1), std::size_t(15), std::size_t(16),
                                    std::size_t(17), std::size_t(63), std::size_t(64), std::size_t(65),
                                    std::size_t(127), std::size_t(128), std::size_t(129),
                                    std::size_t(1000), std::size_t(16384)}) {
        Bytes msg(len);
        for (std::size_t i2 = 0; i2 < len; ++i2) msg[i2] = static_cast<u8>((i2 * 37 + len) & 0xff);
        Poly1305 bulk;
        bulk.init(pkey);
        bulk.update(msg);
        const Bytes fast = bulk.finish();
        // 15 bytes at a time never fills a 64-byte group, so this stays scalar.
        Poly1305 slow;
        slow.init(pkey);
        for (std::size_t off = 0; off < len; off += 15) {
          const std::size_t take = len - off < 15 ? len - off : 15;
          slow.update(msg.data() + off, take);
        }
        const Bytes want = slow.finish();
        if (fast != want) {
          agree = false;
          bad_len = len;
        }
      }
      c.ok(agree, std::string("the vectorised Poly1305 agrees with the scalar loop at every length") +
                      (agree ? std::string() : " (first mismatch at " + std::to_string(bad_len) + ")"));
    }

    // The ChaCha20 keystream itself (RFC 8439 section 2.4.2 first block).
    Bytes ks = chacha20_xor(from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                            from_hex("000000090000004a00000000"), 1, Bytes(64, 0));
    c.eq_str(to_hex(ks).substr(0, 64), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
             "ChaCha20 block function output");
  }

  c.section("crypto: key log parsing");
  {
    const std::string text =
        "# SSL key log generated by a browser\r\n"
        "CLIENT_RANDOM 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
        "0102030405060708090a0b0c0d0e0f10\r\n"
        "\r\n"
        "SERVER_HANDSHAKE_TRAFFIC_SECRET "
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 "
        "ffeeddccbbaa99887766554433221100\n"
        "garbage line without enough fields\n";
    std::vector<KeyLogEntry> entries = parse_keylog(text);
    c.eq_u64(entries.size(), 2, "comments, blanks and malformed lines are skipped");
    c.eq_str(entries[0].label, "CLIENT_RANDOM", "first label");
    c.eq_u64(entries[0].client_random.size(), 32, "client random is 32 bytes");
    c.eq_u64(entries[0].secret.size(), 16, "master secret is 16 bytes");
    c.eq_str(entries[1].label, "SERVER_HANDSHAKE_TRAFFIC_SECRET", "second label");
    c.eq_hex(entries[1].secret, "ffeeddccbbaa99887766554433221100", "traffic secret bytes");
  }

  c.section("crypto: SHA-1 (RFC 3174)");
  c.eq_hex(sha1(Bytes{}), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1 of the empty string");
  c.eq_hex(sha1(abc), "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1(\"abc\")");
  c.eq_hex(sha1(bstr("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
           "84983e441c3bd26ebaae4aa1f95129e5e54670f1", "sha1 of the 56 byte sample");
  c.eq_hex(sha1(Bytes(1000000, 'a')), "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
           "sha1 of one million 'a' (multi block padding)");

  c.section("crypto: MD5 (RFC 1321)");
  c.eq_hex(md5(Bytes{}), "d41d8cd98f00b204e9800998ecf8427e", "md5 of the empty string");
  c.eq_hex(md5(abc), "900150983cd24fb0d6963f7d28e17f72", "md5(\"abc\")");
  c.eq_hex(md5(bstr("message digest")), "f96b697d7cb7938d525a2f31aaf161d0",
           "md5(\"message digest\")");
  c.eq_hex(md5(bstr("abcdefghijklmnopqrstuvwxyz")), "c3fcd3d76192e4007dfb496cca67e13b",
           "md5 of the alphabet");

  c.section("crypto: HMAC-SHA1 and HMAC-MD5 (RFC 2202)");
  c.eq_hex(hmac_sha1(Bytes(20, 0x0b), bstr("Hi There")),
           "b617318655057264e28bc0b6fb378c8ef146be00", "HMAC-SHA1 case 1");
  c.eq_hex(hmac_sha1(bstr("Jefe"), bstr("what do ya want for nothing?")),
           "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", "HMAC-SHA1 case 2");
  c.eq_hex(hmac_md5(Bytes(16, 0x0b), bstr("Hi There")), "9294727a3638bb1c13f48ef8158bfc9d",
           "HMAC-MD5 case 1");
  c.eq_hex(hmac_md5(bstr("Jefe"), bstr("what do ya want for nothing?")),
           "750c783e6ab0b503eaa86e310a5db738", "HMAC-MD5 case 2");
}

// ---------------------------------------------------------------------------
// TCP stream reassembly
// ---------------------------------------------------------------------------

PacketInfo mk_tcp(const char* src, const char* dst, u16 sport, u16 dport, u32 seq, u32 ack,
                  u8 flags, const std::string& payload) {
  PacketInfo pi;
  int v = 4;
  u8 a[16];
  if (parse_ip(src, &v, a)) std::memcpy(pi.src_ip, a, 16);
  v = 4;
  if (parse_ip(dst, &v, a)) std::memcpy(pi.dst_ip, a, 16);
  pi.ip_version = 4;
  pi.l3_proto = 6;
  pi.l4 = L4::Tcp;
  pi.src_port = sport;
  pi.dst_port = dport;
  pi.has_ports = true;
  pi.tcp.seq = seq;
  pi.tcp.ack = ack;
  pi.tcp.flags = flags;
  pi.payload = reinterpret_cast<const u8*>(payload.data());
  pi.payload_len = payload.size();
  return pi;
}

std::string text_of(const std::vector<u8>& v) { return std::string(v.begin(), v.end()); }

void test_flow(Ctx& c) {
  c.section("flow: in-order delivery");
  {
    FlowTable t;
    const std::string a = "GET / HTTP/1.1\r\n";
    const std::string b = "Host: example.com\r\n";
    FlowUpdate u = t.add(mk_tcp("10.0.0.5", "93.184.216.34", 51000, 80, 1000, 0, TCP_SYN, ""), 1);
    c.ok(u.new_stream, "the SYN opens a stream");
    c.ok(u.syn && !u.ack, "the SYN is reported");
    c.eq_u64(t.size(), 1, "one stream in the table");
    u = t.add(mk_tcp("93.184.216.34", "10.0.0.5", 80, 51000, 5000, 1001, TCP_SYN | TCP_ACK, ""), 2);
    c.ok(u.new_stream == false, "the SYN+ACK lands in the same stream");
    c.eq_str(conn_state_name(u.stream->state), "ESTABLISHED", "SYN+ACK establishes the connection");
    c.eq_u64(t.streams()[0]->client().port, 51000, "the SYN sender is the client");
    c.eq_u64(t.streams()[0]->server().port, 80, "the peer is the server");

    u = t.add(mk_tcp("10.0.0.5", "93.184.216.34", 51000, 80, 1001, 0, TCP_ACK | TCP_PSH, a), 3);
    c.eq_u64(u.delivered, a.size(), "the first data segment is delivered");
    u = t.add(mk_tcp("10.0.0.5", "93.184.216.34", 51000, 80, 1001 + u32(a.size()), 0,
                     TCP_ACK | TCP_PSH, b),
              4);
    c.eq_u64(u.delivered, b.size(), "the second data segment is delivered");
    c.eq_str(text_of(t.streams()[0]->client_to_server().data()), a + b,
             "the client stream is the concatenation");
    TcpStream* st = t.streams()[0].get();
    c.eq_u64(st->client_to_server().stats().delivered, a.size() + b.size(), "delivered counter");
    c.eq_u64(st->payload_bytes, a.size() + b.size(), "stream payload bytes");
    c.eq_u64(st->packets, 4, "packets counted");
    c.eq_u64(t.stats().retransmits, 0, "no retransmissions yet");
    c.ok(!st->client_to_server().has_gap(), "no gap in an ordered stream");
  }

  c.section("flow: out-of-order, retransmission and overlap");
  {
    FlowTable t;
    const std::string s1 = "AAAAAAAAAA";  // data seq 101..111 (the SYN took 100)
    const std::string s2 = "BBBBBBBBBB";  // data seq 111..121
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1111, 2222, 100, 0, TCP_SYN, ""), 1);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1111, 2222, 111, 0, TCP_ACK, s2), 2);
    c.eq_u64(t.streams()[0]->client_to_server().data().size(), 0,
             "a segment with a hole ahead of it is held back");
    c.ok(t.streams()[0]->client_to_server().has_gap(), "the hole is reported");
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1111, 2222, 101, 0, TCP_ACK, s1), 3);
    c.eq_str(text_of(t.streams()[0]->client_to_server().data()), s1 + s2,
             "the held segment is released once the hole is filled");
    c.ok(!t.streams()[0]->client_to_server().has_gap(), "the hole closes");
    const HalfStats& h = t.streams()[0]->client_to_server().stats();
    c.eq_u64(h.out_of_order, 1, "one out-of-order segment");
    c.eq_u64(h.gaps, 1, "one gap observed");
    c.eq_u64(h.retransmits, 0, "no retransmission yet");

    // A full retransmission of the first segment changes nothing.
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1111, 2222, 101, 0, TCP_ACK, s1), 4);
    const HalfStats& h2 = t.streams()[0]->client_to_server().stats();
    c.eq_u64(h2.retransmits, 1, "the retransmission is counted");
    c.eq_u64(h2.duplicate_bytes, s1.size(), "duplicate bytes are counted");
    c.eq_str(text_of(t.streams()[0]->client_to_server().data()), s1 + s2,
             "a retransmission does not duplicate data");

    // An overlapping segment that starts inside delivered data.
    const std::string s3 = "CCCCCCCCCC";  // seq 116..126 overlaps s2's tail
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1111, 2222, 116, 0, TCP_ACK, s3), 5);
    const HalfStats& h3 = t.streams()[0]->client_to_server().stats();
    c.eq_u64(h3.overlaps, 1, "the overlap is counted");
    c.eq_u64(h3.delivered, s1.size() + s2.size() + 5, "only the new tail is delivered");
    c.eq_str(text_of(t.streams()[0]->client_to_server().data()), s1 + s2 + "CCCCC",
             "the overlapping prefix is not repeated");
    c.eq_u64(t.stats().out_of_order, 1, "table level out-of-order counter");
    c.eq_u64(t.stats().gaps, 1, "table level gap counter");
  }

  c.section("flow: sequence wraparound");
  {
    FlowTable t;
    const u32 isn = 0xffffff00u;  // data starts at 0xffffff01 and wraps
    const std::string s1 = "0123456789abcdef";  // 16 bytes
    const std::string s2 = "FEDCBA98";          // 8 bytes
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 5, 6, isn, 0, TCP_SYN, ""), 1);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 5, 6, isn + 1, 0, TCP_ACK, s1), 2);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 5, 6, isn + 1 + u32(s1.size()), 0, TCP_ACK, s2), 3);
    c.eq_str(text_of(t.streams()[0]->client_to_server().data()), s1 + s2,
             "bytes reassemble across the 32-bit wrap");
    c.eq_u64(t.streams()[0]->client_to_server().stats().gaps, 0, "no gap at the wrap");
    // The wrapped direction still recognises a retransmission.
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 5, 6, isn + 1, 0, TCP_ACK, s1), 4);
    c.eq_u64(t.streams()[0]->client_to_server().stats().retransmits, 1,
             "a retransmission is recognised across the wrap");
  }

  c.section("flow: FIN and close");
  {
    FlowTable t;
    const std::string body = "hello body";
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 7, 8, 200, 0, TCP_SYN, ""), 1);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 7, 8, 201, 0, TCP_ACK, body), 2);
    TcpStream* st = t.streams()[0].get();
    c.ok(!st->client_to_server().complete(), "an open direction is not complete");
    // The FIN arrives before the final data segment (a reorder around the close):
    // the body ended at sequence 211, the FIN announces the end at 221.
    const std::string tail = "0123456789";
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 7, 8, 221, 0, TCP_FIN | TCP_ACK, ""), 3);
    c.ok(!st->client_to_server().complete(), "the FIN is not complete before its data arrives");
    c.eq_u64(st->client_to_server().stats().gaps, 0, "a FIN ahead of data is not a data gap");
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 7, 8, 211, 0, TCP_ACK, tail), 4);
    c.ok(st->client_to_server().complete(), "the initiator direction completes at the FIN");
    c.eq_str(text_of(st->client_to_server().data()), body + tail,
             "the segment held behind the FIN is still delivered");
    t.add(mk_tcp("10.0.0.6", "10.0.0.5", 8, 7, 900, 0, TCP_FIN | TCP_ACK, ""), 5);
    c.ok(st->server_to_client().stats().saw_fin, "the responder direction also saw a FIN");
    c.eq_str(conn_state_name(st->state), "CLOSED", "both FINs close the connection");

    FlowTable t2;
    t2.add(mk_tcp("10.0.0.5", "10.0.0.6", 7, 8, 1, 0, TCP_SYN, ""), 1);
    t2.add(mk_tcp("10.0.0.6", "10.0.0.5", 8, 7, 1, 2, TCP_RST, ""), 2);
    c.eq_str(conn_state_name(t2.streams()[0]->state), "RESET", "RST marks the stream reset");
  }

  c.section("flow: two directions and key symmetry");
  {
    FlowTable t;
    const std::string req = "GET /x HTTP/1.1\r\n\r\n";
    const std::string rsp = "HTTP/1.1 204 No Content\r\n\r\n";
    t.add(mk_tcp("192.168.1.10", "10.0.0.1", 40000, 80, 10, 0, TCP_SYN, ""), 1);
    t.add(mk_tcp("10.0.0.1", "192.168.1.10", 80, 40000, 500, 11, TCP_SYN | TCP_ACK, ""), 2);
    t.add(mk_tcp("192.168.1.10", "10.0.0.1", 40000, 80, 11, 501, TCP_ACK, req), 3);
    t.add(mk_tcp("10.0.0.1", "192.168.1.10", 80, 40000, 501, 11 + u32(req.size()), TCP_ACK, rsp), 4);
    TcpStream* st = t.streams()[0].get();
    c.eq_u64(t.size(), 1, "one stream for both directions");
    c.eq_str(st->client().to_string(), "192.168.1.10:40000", "client endpoint");
    c.eq_str(st->server().to_string(), "10.0.0.1:80", "server endpoint");
    c.eq_str(text_of(st->client_to_server().data()), req, "request direction");
    c.eq_str(text_of(st->server_to_client().data()), rsp, "response direction");
    c.ok(st->handshake_seen, "the handshake was seen");
    c.ok(st->server_seen, "the responder spoke");
    c.ok(st->duration_us() == 3.0, "duration spans the first to the last packet");

    const FlowKey k1 = flow_key_of(mk_tcp("10.0.0.1", "10.0.0.2", 1, 2, 0, 0, 0, ""));
    const FlowKey k2 = flow_key_of(mk_tcp("10.0.0.2", "10.0.0.1", 2, 1, 0, 0, 0, ""));
    c.ok(k1 == k2, "the flow key is direction independent");
    c.eq_str(k1.to_string(), "10.0.0.1:1 <-> 10.0.0.2:2", "canonical key string");
    // The response direction of the real stream resolves to the same object.
    const FlowKey rev = flow_key_of(mk_tcp("10.0.0.1", "192.168.1.10", 80, 40000, 0, 0, 0, ""));
    c.ok(t.find(rev) == st, "lookup by the reversed direction finds the stream");
  }

  c.section("flow: limits");
  {
    FlowConfig cfg;
    cfg.max_stream_bytes = 8;
    FlowTable t(cfg);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 1, 0, TCP_SYN, ""), 1);
    const std::string big = "0123456789ABCDEFGHIJ";  // 20 bytes, cap is 8
    FlowUpdate u = t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 2, 0, TCP_ACK, big), 2);
    c.eq_u64(u.delivered, 8, "delivery stops at the stream cap");
    c.ok(t.streams()[0]->client_to_server().stats().truncated, "the direction is marked truncated");
    c.eq_u64(t.streams()[0]->client_to_server().next_seq(), 21,
             "the sequence number still advances past the dropped bytes");
    // Later bytes are dropped as well, but never mistaken for a gap.
    u = t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 22, 0, TCP_ACK, "tail"), 3);
    c.eq_u64(u.delivered, 0, "nothing more is stored");
    c.eq_u64(t.streams()[0]->client_to_server().stats().gaps, 0, "no gap is invented");
  }
  {
    FlowConfig cfg;
    cfg.max_pending_bytes = 100;
    FlowTable t(cfg);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 1000, 0, TCP_SYN, ""), 1);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 1001, 0, TCP_ACK, std::string(10, 'x')), 2);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 1050, 0, TCP_ACK, std::string(80, 'a')), 3);
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 1200, 0, TCP_ACK, std::string(80, 'b')), 4);
    c.eq_u64(t.streams()[0]->client_to_server().stats().dropped_pending, 80,
             "the furthest out-of-order segment is dropped at the pending cap");
    // Filling the hole releases the segment that was kept.
    t.add(mk_tcp("10.0.0.5", "10.0.0.6", 1, 2, 1011, 0, TCP_ACK, std::string(39, 'y')), 5);
    const HalfStream& h = t.streams()[0]->client_to_server();
    c.eq_u64(h.data().size(), 10 + 39 + 80, "the kept segment is delivered after the hole");
    c.eq_u64(h.data()[10], 'y', "hole filler bytes come first");
    c.eq_u64(h.data()[49], 'a', "held bytes follow the filler");
    c.eq_u64(h.stats().gaps, 1, "one gap was recorded");
  }

  c.section("flow: table housekeeping");
  {
    FlowTable t;
    PacketInfo arp;
    arp.is_arp = true;
    arp.ip_version = 0;
    FlowUpdate u = t.add(arp, 1);
    c.ok(u.stream == nullptr, "a non-TCP packet is ignored");
    c.eq_u64(t.stats().non_tcp, 1, "non-TCP packets are counted");

    FlowConfig cfg;
    cfg.max_streams = 1;
    FlowTable small(cfg);
    small.add(mk_tcp("10.0.0.1", "10.0.0.2", 1, 2, 1, 0, TCP_SYN, ""), 1);
    small.add(mk_tcp("10.0.0.3", "10.0.0.4", 3, 4, 1, 0, TCP_SYN, ""), 2);
    c.eq_u64(small.size(), 1, "the stream cap is respected");
    c.eq_u64(small.stats().evicted, 1, "the eviction is counted");
    c.ok(small.find(flow_key_of(mk_tcp("10.0.0.1", "10.0.0.2", 1, 2, 1, 0, TCP_SYN, ""))) == nullptr,
         "the evicted stream is gone from the index");

    FlowConfig idle;
    idle.idle_timeout_us = 1000;
    FlowTable gc_table(idle);
    gc_table.add(mk_tcp("10.0.0.1", "10.0.0.2", 1, 2, 1, 0, TCP_SYN, ""), 10);
    c.eq_u64(gc_table.gc(1000), 0, "a fresh stream survives gc");
    c.eq_u64(gc_table.gc(5000), 1, "an idle stream is collected");
    c.eq_u64(gc_table.size(), 0, "the table is empty after gc");
  }
}

// ---------------------------------------------------------------------------
// HTTP/1.x over reassembled streams
// ---------------------------------------------------------------------------

void feed_str(HttpAnalyzer& a, bool from_client, const std::string& s, i64 ts_us) {
  const u8* p = reinterpret_cast<const u8*>(s.data());
  if (from_client) {
    a.feed_client_to_server(p, s.size(), ts_us);
  } else {
    a.feed_server_to_client(p, s.size(), ts_us);
  }
}

void test_http(Ctx& c) {
  c.section("http: request and response pairing");
  {
    HttpAnalyzer a;
    const std::string req =
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netcap/1.0\r\n"
        "Accept: */*\r\n\r\n";
    const std::string rsp =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 13\r\n"
        "Server: nginx\r\n\r\nHello, world!";
    feed_str(a, true, req, 1000);
    c.eq_u64(a.requests(), 1, "one request parsed");
    c.eq_u64(a.responses(), 0, "no response yet");
    c.ok(a.transactions()[0].has_request && !a.transactions()[0].has_response,
         "the request is not yet answered");
    feed_str(a, false, rsp, 2000);
    const HttpTransaction& t = a.transactions()[0];
    c.eq_u64(a.transactions().size(), 1, "the response joins the existing transaction");
    c.ok(t.has_response, "the response is paired");
    c.eq_u64(t.response.status, 200, "status code");
    c.eq_str(t.response.reason, "OK", "reason phrase");
    c.eq_str(t.request.host(), "example.com", "host header");
    c.eq_str(t.url(), "http://example.com/index.html", "absolute url");
    c.eq_str(t.request.method, "GET", "method");
    c.eq_str(t.request.target, "/index.html", "target");
    c.eq_str(t.request.summary(), "GET /index.html", "request summary");
    c.eq_str(t.request.start_line(), "GET /index.html HTTP/1.1", "request start line");
    c.eq_str(t.response.start_line(), "HTTP/1.1 200 OK", "response start line");
    c.eq_str(t.response.body, "Hello, world!", "body from Content-Length");
    c.eq_u64(t.response.content_length, 13, "content length");
    c.ok(t.response.has_content_length, "content length flag");
    c.eq_str(t.response.header("content-type"), "text/html; charset=utf-8",
             "header lookup is case insensitive");
    c.eq_str(t.response.server(), "nginx", "server header");
    c.eq_u64(t.request.header_bytes, req.size(), "header byte count");
    c.eq_u64(t.request.raw_bytes, req.size(), "a request without a body is fully consumed");
    c.ok(t.request.keep_alive, "HTTP/1.1 defaults to keep-alive");
    c.ok(a.saw_http(), "the analyzer saw HTTP");
    c.ok(!a.saw_http2() && !a.saw_tls(), "neither TLS nor HTTP/2");
    c.ok(t.duration_ms() == 1.0, "transaction duration");
    c.ok(t.response.body.size() == t.response.content_length, "body length matches the header");
  }

  c.section("http: incremental parsing");
  {
    const std::string req =
        "GET /frag HTTP/1.1\r\nHost: example.org\r\nX-Pad: 0123456789\r\n\r\n";
    HttpParser p;
    std::vector<HttpMessage> out;
    const std::size_t mid = req.find("Host") + 3;  // split inside a header name
    p.feed(reinterpret_cast<const u8*>(req.data()), mid, 10, &out);
    c.eq_u64(out.size(), 0, "a half header produces nothing");
    c.ok(p.buffered() == mid, "the partial bytes are buffered");
    p.feed(reinterpret_cast<const u8*>(req.data()) + mid, req.size() - mid, 20, &out);
    c.eq_u64(out.size(), 1, "the message completes once the tail arrives");
    c.eq_str(out[0].target, "/frag", "target from the split message");
    c.eq_str(out[0].header("X-Pad"), "0123456789", "a header repeated across segments");
    c.ok(!p.failed(), "the parser is healthy");
    // Byte at a time, the slowest possible arrival pattern.
    HttpParser q;
    std::vector<HttpMessage> out2;
    for (std::size_t i = 0; i < req.size(); ++i) {
      q.feed(reinterpret_cast<const u8*>(req.data()) + i, 1, i64(i), &out2);
    }
    c.eq_u64(out2.size(), 1, "a byte-at-a-time message is parsed once");
    c.eq_str(out2[0].target, "/frag", "target from the byte-at-a-time message");
  }

  c.section("http: chunked bodies");
  {
    const std::string rsp =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    HttpParser p;
    std::vector<HttpMessage> out;
    p.feed(reinterpret_cast<const u8*>(rsp.data()), rsp.size(), 5, &out);
    c.eq_u64(out.size(), 1, "the chunked response is parsed");
    c.ok(out[0].chunked, "chunked flag");
    c.eq_str(out[0].body, "hello world", "chunks are de-framed");
    c.ok(!out[0].truncated, "not truncated");
    // Chunk extension and trailer headers.
    const std::string with_trailer =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "3;ext=1\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n";
    HttpParser p2;
    std::vector<HttpMessage> out2;
    p2.feed(reinterpret_cast<const u8*>(with_trailer.data()), with_trailer.size(), 6, &out2);
    c.eq_u64(out2.size(), 1, "a chunk extension and trailer still parse");
    c.eq_str(out2[0].body, "abc", "chunk extension does not leak into the body");
    // Chunked, delivered in fragments.
    const std::string rsp2 =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789ABCDEF\r\n0\r\n\r\n";
    HttpParser p3;
    std::vector<HttpMessage> out3;
    p3.feed(reinterpret_cast<const u8*>(rsp2.data()), rsp2.size() - 3, 7, &out3);
    c.eq_u64(out3.size(), 0, "an unfinished chunked body waits");
    p3.feed(reinterpret_cast<const u8*>(rsp2.data()) + rsp2.size() - 3, 3, 8, &out3);
    c.eq_u64(out3.size(), 1, "the chunked body completes on the last bytes");
    c.eq_str(out3[0].body, "0123456789ABCDEF", "the fragmented chunk is complete");
  }

  c.section("http: pipelining, continue, and streaming bodies");
  {
    HttpAnalyzer a;
    feed_str(a, true, "GET /a HTTP/1.1\r\nHost: h\r\n\r\n", 1);
    feed_str(a, true, "GET /b HTTP/1.1\r\nHost: h\r\n\r\n", 2);
    c.eq_u64(a.requests(), 2, "two pipelined requests");
    feed_str(a, false, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none", 3);
    feed_str(a, false, "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\ntwo", 4);
    c.eq_u64(a.transactions().size(), 2, "two transactions");
    c.eq_str(a.transactions()[0].request.target, "/a", "first request");
    c.eq_str(a.transactions()[0].response.body, "one", "responses pair in order");
    c.eq_str(a.transactions()[1].request.target, "/b", "second request");
    c.eq_u64(a.transactions()[1].response.status, 404, "second status");
    c.eq_str(a.transactions()[1].response.body, "two", "second body");
  }
  {
    HttpAnalyzer a;
    feed_str(a, true,
             "POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello", 1);
    c.eq_str(a.transactions()[0].request.body, "hello", "request body from Content-Length");
    feed_str(a, false, "HTTP/1.1 100 Continue\r\n\r\n", 2);
    feed_str(a, false, "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok", 3);
    const HttpTransaction& t = a.transactions()[0];
    c.eq_u64(t.informational.size(), 1, "the 100 Continue is recorded separately");
    c.eq_u64(t.informational[0].status, 100, "informational status");
    c.ok(t.has_response, "the final response still pairs with the request");
    c.eq_u64(t.response.status, 201, "final status");
    c.eq_str(t.response.body, "ok", "final body");
    c.eq_u64(a.responses(), 2, "both responses are counted");
    c.eq_u64(a.requests(), 1, "still one request");
  }
  {
    HttpParser p;
    std::vector<HttpMessage> out;
    const std::string rsp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                            "data: one\n\ndata: two\n\n";
    p.feed(reinterpret_cast<const u8*>(rsp.data()), rsp.size(), 9, &out);
    c.eq_u64(out.size(), 1, "an unframed response is parsed");
    c.ok(out[0].body_to_close, "the body is flagged as running to connection close");
    c.eq_str(out[0].body, "data: one\n\ndata: two\n\n", "the whole tail is the body");
  }
  {
    // A response to HEAD advertises a length but sends no body; the next
    // response on the same connection must still be parsed.
    HttpAnalyzer a;
    feed_str(a, true, "HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n", 1);
    feed_str(a, true, "GET /y HTTP/1.1\r\nHost: h\r\n\r\n", 2);
    feed_str(a, false, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 3);
    feed_str(a, false, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 4);
    c.eq_u64(a.transactions().size(), 2, "two transactions for HEAD and GET");
    c.eq_u64(a.transactions()[0].response.content_length, 100, "the HEAD response keeps its length");
    c.ok(a.transactions()[0].response.body.empty(), "the HEAD response has no body");
    c.eq_str(a.transactions()[1].response.body, "hi", "the next response is not eaten");
  }

  c.section("http: upgrade, mid-stream captures and non-HTTP streams");
  {
    HttpAnalyzer a;
    feed_str(a, true,
             "GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
             1);
    feed_str(a, false,
             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
             2);
    c.ok(a.websocket(), "the upgrade is recognised");
    c.eq_u64(a.transactions()[0].response.status, 101, "101 status");
  }
  {
    HttpAnalyzer a;
    feed_str(a, false, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody", 1);
    c.eq_u64(a.transactions().size(), 1, "a response with no captured request");
    c.ok(!a.transactions()[0].has_request, "the transaction is response only");
    c.eq_u64(a.requests(), 0, "no requests");
    c.eq_u64(a.responses(), 1, "one response");
  }
  {
    HttpParser p;
    std::vector<HttpMessage> out;
    const u8 tls_bytes[] = {0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28};
    p.feed(tls_bytes, sizeof(tls_bytes), 1, &out);
    c.eq_u64(out.size(), 0, "no message from a TLS record");
    c.ok(p.failed(), "the parser gives up on binary data");
    c.ok(p.saw_tls(), "the bytes are recognised as TLS");
    c.eq_u64(p.passthrough().size(), sizeof(tls_bytes), "the bytes are handed over");
    c.ok(!p.saw_http(), "no HTTP was seen");
  }
  {
    HttpParser p;
    std::vector<HttpMessage> out;
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    p.feed(reinterpret_cast<const u8*>(preface.data()), preface.size(), 1, &out);
    c.eq_u64(out.size(), 0, "the h2 preface is not an HTTP/1 message");
    c.ok(p.saw_http2_preface(), "the h2 preface is recognised");
    c.eq_u64(p.passthrough().size(), preface.size(), "the preface is handed over");
    // The same preface split across two feeds.
    HttpParser q;
    std::vector<HttpMessage> out2;
    q.feed(reinterpret_cast<const u8*>(preface.data()), 18, 1, &out2);
    q.feed(reinterpret_cast<const u8*>(preface.data()) + 18, preface.size() - 18, 2, &out2);
    c.ok(q.saw_http2_preface(), "a split h2 preface is recognised");
    c.eq_u64(out2.size(), 0, "a split preface produces no message");
  }
  {
    HttpParser p;
    std::vector<HttpMessage> out;
    const std::string req = "\r\nGET /x HTTP/1.1\r\nHost: h\r\n\r\n";
    p.feed(reinterpret_cast<const u8*>(req.data()), req.size(), 1, &out);
    c.eq_u64(out.size(), 1, "a leading blank line is tolerated");
    c.eq_str(out[0].target, "/x", "the request after the blank line");
    c.ok(HttpParser::looks_like_http(reinterpret_cast<const u8*>("GET / HTTP/1.1\r\n"), 16),
         "looks_like_http accepts a request");
    c.ok(!HttpParser::looks_like_http(reinterpret_cast<const u8*>("\x16\x03\x01\x00"), 4),
         "looks_like_http rejects a TLS record");
  }
}

// ---------------------------------------------------------------------------
// TLS record layer and key log decryption
// ---------------------------------------------------------------------------

void tls_put16(Bytes& v, u16 x) {
  v.push_back(u8(x >> 8));
  v.push_back(u8(x & 0xff));
}

void tls_put24(Bytes& v, u32 x) {
  v.push_back(u8((x >> 16) & 0xff));
  v.push_back(u8((x >> 8) & 0xff));
  v.push_back(u8(x & 0xff));
}

Bytes tls_text(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes tls_seq_bytes(u8 first, std::size_t n) {
  Bytes v;
  for (std::size_t i = 0; i < n; ++i) v.push_back(u8(first + i));
  return v;
}

void tls_put_ext(Bytes& exts, u16 type, const Bytes& data) {
  tls_put16(exts, type);
  tls_put16(exts, u16(data.size()));
  exts.insert(exts.end(), data.begin(), data.end());
}

void tls_xor_seq(Bytes* nonce, u64 seq) {
  const std::size_t off = nonce->size() - 8;
  for (int i = 0; i < 8; ++i) (*nonce)[off + std::size_t(i)] ^= u8((seq >> (8 * (7 - i))) & 0xff);
}

// seq(8) || type || version || length: the TLS 1.2 MAC / AEAD associated data.
Bytes tls12_header_bytes(u64 seq, u8 type, u16 version, std::size_t len) {
  Bytes a(13, 0);
  for (int i = 0; i < 8; ++i) a[std::size_t(i)] = u8((seq >> (8 * (7 - i))) & 0xff);
  a[8] = type;
  wr16be(a.data() + 9, version);
  wr16be(a.data() + 11, u16(len));
  return a;
}

Bytes tls_hello_body(const std::string& sni, const std::vector<u16>& suites, bool server,
                     u16 cipher, const Bytes& random, bool version_ext = true,
                     const std::string& alpn = "h2") {
  Bytes b;
  tls_put16(b, 0x0303);
  b.insert(b.end(), random.begin(), random.end());
  b.push_back(0);  // empty session id
  if (server) {
    tls_put16(b, cipher);
    b.push_back(0);  // null compression
  } else {
    tls_put16(b, u16(suites.size() * 2));
    for (u16 s : suites) tls_put16(b, s);
    b.push_back(1);
    b.push_back(0);
  }
  Bytes exts;
  if (!server && !sni.empty()) {
    Bytes sn;
    tls_put16(sn, u16(sni.size() + 3));
    sn.push_back(0);
    tls_put16(sn, u16(sni.size()));
    sn.insert(sn.end(), sni.begin(), sni.end());
    tls_put_ext(exts, 0x0000, sn);
  }
  if (!alpn.empty()) {
    Bytes list;
    list.push_back(u8(alpn.size()));
    list.insert(list.end(), alpn.begin(), alpn.end());
    Bytes alpn_ext;
    tls_put16(alpn_ext, u16(list.size()));
    alpn_ext.insert(alpn_ext.end(), list.begin(), list.end());
    tls_put_ext(exts, 0x0010, alpn_ext);
  }
  if (version_ext) {
    Bytes sv;
    if (server) {
      tls_put16(sv, 2);
      tls_put16(sv, 0x0304);
    } else {
      sv.push_back(2);
      tls_put16(sv, 0x0304);
    }
    tls_put_ext(exts, 0x002b, sv);
    Bytes ks;
    if (server) {
      tls_put16(ks, 29);
      tls_put16(ks, 32);
      const Bytes k = tls_seq_bytes(0x60, 32);
      ks.insert(ks.end(), k.begin(), k.end());
    } else {
      Bytes share;
      tls_put16(share, 29);
      tls_put16(share, 32);
      const Bytes k = tls_seq_bytes(0x40, 32);
      share.insert(share.end(), k.begin(), k.end());
      tls_put16(ks, u16(share.size()));
      ks.insert(ks.end(), share.begin(), share.end());
    }
    tls_put_ext(exts, 0x0033, ks);
  }
  tls_put16(b, u16(exts.size()));
  b.insert(b.end(), exts.begin(), exts.end());
  return b;
}

Bytes tls_handshake_message(u8 hs_type, const Bytes& body) {
  Bytes msg;
  msg.push_back(hs_type);
  tls_put24(msg, u32(body.size()));
  msg.insert(msg.end(), body.begin(), body.end());
  return msg;
}

Bytes tls_record(u8 type, u16 version, const Bytes& payload) {
  Bytes rec;
  rec.push_back(type);
  tls_put16(rec, version);
  tls_put16(rec, u16(payload.size()));
  rec.insert(rec.end(), payload.begin(), payload.end());
  return rec;
}

Bytes tls_handshake_record(u8 hs_type, const Bytes& body) {
  return tls_record(22, 0x0303, tls_handshake_message(hs_type, body));
}

// Seals one TLS 1.3 record, exactly as a real endpoint would: the inner content
// type and the padding are hidden inside the AEAD payload.
Bytes tls13_seal(const Bytes& secret, u64 seq, u8 inner_type, const Bytes& content, u16 cipher,
                 bool sha384, bool pad) {
  const TlsCipherSuite* s = tls_cipher_suite(cipher);
  const Bytes key =
      hkdf_expand_label(secret, "key", Bytes(), std::size_t(s ? s->key_len : 16), sha384);
  const Bytes iv = hkdf_expand_label(secret, "iv", Bytes(), 12, sha384);
  Bytes inner = content;
  inner.push_back(inner_type);
  if (pad) inner.push_back(0);
  Bytes hdr;
  hdr.push_back(23);
  tls_put16(hdr, 0x0303);
  tls_put16(hdr, u16(inner.size() + 16));
  Bytes nonce = iv;
  tls_xor_seq(&nonce, seq);
  const AeadResult r = (s && s->mode == TlsCipherSuite::Mode::Chacha20Poly1305)
                           ? chacha20_poly1305_encrypt(key, nonce, hdr, inner)
                           : aes_gcm_encrypt(key, nonce, hdr, inner);
  Bytes rec = hdr;
  rec.insert(rec.end(), r.ciphertext.begin(), r.ciphertext.end());
  rec.insert(rec.end(), r.tag.begin(), r.tag.end());
  return rec;
}

Bytes tls12_gcm_record(const Bytes& key, const Bytes& fixed_iv, u64 seq, u8 type,
                       const Bytes& content) {
  const Bytes explicit_nonce = tls_seq_bytes(u8(0xa0 + seq), 8);
  const Bytes aad = tls12_header_bytes(seq, type, 0x0303, content.size());
  Bytes nonce = fixed_iv;
  nonce.insert(nonce.end(), explicit_nonce.begin(), explicit_nonce.end());
  const AeadResult r = aes_gcm_encrypt(key, nonce, aad, content);
  Bytes payload = explicit_nonce;
  payload.insert(payload.end(), r.ciphertext.begin(), r.ciphertext.end());
  payload.insert(payload.end(), r.tag.begin(), r.tag.end());
  return tls_record(type, 0x0303, payload);
}

Bytes tls12_cbc_record(const Aes& aes, const Bytes& mac_key, const Bytes& iv, u64 seq, u8 type,
                       const Bytes& content, bool sha384) {
  const Bytes mac_in = [&] {
    Bytes v = tls12_header_bytes(seq, type, 0x0303, content.size());
    v.insert(v.end(), content.begin(), content.end());
    return v;
  }();
  const Bytes mac = sha384 ? hmac_sha384(mac_key, mac_in) : hmac_sha256(mac_key, mac_in);
  Bytes plain = content;
  plain.insert(plain.end(), mac.begin(), mac.end());
  const std::size_t pad = (16 - ((plain.size() + 1) % 16)) % 16;
  plain.insert(plain.end(), pad, u8(pad));
  plain.push_back(u8(pad));
  Bytes out(plain.size(), 0);
  aes_cbc_encrypt(aes, iv.data(), plain.data(), plain.size(), out.data());
  return tls_record(type, 0x0303, out);
}

// ---------------------------------------------------------------------------
// The HTTPS conversation in the sample capture
// ---------------------------------------------------------------------------
//
// A complete TLS 1.3 session whose secrets are known, so the generated capture
// can be decrypted offline: the key log is written next to it. The response
// record is deliberately split across two segments with the second half sent
// first, so the bytes have to be reassembled before the record can be decrypted.

Bytes sample_client_random() { return tls_seq_bytes(0x11, 32); }
Bytes sample_server_random() { return tls_seq_bytes(0x22, 32); }
Bytes sample_c_hs_secret() { return tls_seq_bytes(0x33, 32); }
Bytes sample_s_hs_secret() { return tls_seq_bytes(0x44, 32); }
Bytes sample_c_ap_secret() { return tls_seq_bytes(0x55, 32); }
Bytes sample_s_ap_secret() { return tls_seq_bytes(0x66, 32); }

const char* kHttpsRequest =
    "GET /secure HTTP/1.1\r\n"
    "Host: secure.example.com\r\n"
    "User-Agent: netcap-selftest/1.0\r\n"
    "\r\n";

const char* kHttpsResponse =
    "HTTP/1.1 200 OK\r\n"
    "Server: netcap-selftest\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 11\r\n"
    "\r\n"
    "Hello, TLS!";

void append_tls_conversation(std::vector<Packet>& out, i64& ts) {
  const char* cli_mac = "52:54:00:12:34:56";
  const char* srv_mac = "00:11:22:33:44:55";
  u32 cseq = 0x11110000;  // client initial sequence number
  u32 sseq = 0x22220000;  // server initial sequence number

  auto client = [&](std::vector<u8> tcp, i64 dt) {
    add(out,
        eth_frame(srv_mac, cli_mac, 0x0800,
                  ipv4_packet({.src = "10.0.0.5", .dst = "93.184.216.34", .proto = 6, .ttl = 64,
                               .id = 0x3300, .df = true},
                              std::move(tcp))),
        ts += dt);
  };
  auto server = [&](std::vector<u8> tcp, i64 dt) {
    add(out,
        eth_frame(cli_mac, srv_mac, 0x0800,
                  ipv4_packet({.src = "93.184.216.34", .dst = "10.0.0.5", .proto = 6, .ttl = 55,
                               .id = 0x4400, .df = true},
                              std::move(tcp))),
        ts += dt);
  };

  // Handshake
  client(tcp_segment(52000, 443, cseq, 0, TCP_SYN, 64240, {}, 1460), 110);
  ++cseq;
  server(tcp_segment(443, 52000, sseq, cseq, TCP_SYN | TCP_ACK, 65535, {}, 1460), 130);
  ++sseq;
  client(tcp_segment(52000, 443, cseq, sseq, TCP_ACK, 64240, {}), 60);

  {
    const Bytes rec = tls_handshake_record(
        1, tls_hello_body("secure.example.com", {0x1301}, false, 0, sample_client_random(), true,
                          "http/1.1"));
    client(tcp_segment(52000, 443, cseq, sseq, TCP_PSH | TCP_ACK, 64240, rec), 210);
    cseq += u32(rec.size());
  }
  {
    Bytes payload = tls_handshake_record(
        2, tls_hello_body("", {}, true, 0x1301, sample_server_random(), true, "http/1.1"));
    const Bytes ccs = tls_record(20, 0x0303, Bytes{1});
    payload.insert(payload.end(), ccs.begin(), ccs.end());
    const Bytes ee = tls13_seal(sample_s_hs_secret(), 0, 22,
                                tls_handshake_message(8, Bytes{0, 0, 0, 0}), 0x1301, false, false);
    payload.insert(payload.end(), ee.begin(), ee.end());
    server(tcp_segment(443, 52000, sseq, cseq, TCP_PSH | TCP_ACK, 65535, payload), 270);
    sseq += u32(payload.size());
  }

  // The encrypted request
  {
    const Bytes rec =
        tls13_seal(sample_c_ap_secret(), 0, 23, tls_text(kHttpsRequest), 0x1301, false, false);
    client(tcp_segment(52000, 443, cseq, sseq, TCP_PSH | TCP_ACK, 64240, rec), 190);
    cseq += u32(rec.size());
  }

  // The encrypted response, split across two segments with the tail sent first:
  // the reassembler has to close the gap before the record can be decrypted.
  {
    const Bytes rec = tls13_seal(sample_s_ap_secret(), 0, 23, tls_text(kHttpsResponse), 0x1301,
                                 false, false);
    const std::size_t half = rec.size() / 2;
    const Bytes first(rec.begin(), rec.begin() + std::ptrdiff_t(half));
    const Bytes second(rec.begin() + std::ptrdiff_t(half), rec.end());
    server(tcp_segment(443, 52000, sseq + u32(first.size()), cseq, TCP_PSH | TCP_ACK, 65535,
                       second),
           90);
    server(tcp_segment(443, 52000, sseq, cseq, TCP_PSH | TCP_ACK, 65535, first), 120);
    sseq += u32(rec.size());
  }

  // Teardown
  server(tcp_segment(443, 52000, sseq, cseq, TCP_FIN | TCP_ACK, 65535, {}), 150);
  ++sseq;
  client(tcp_segment(52000, 443, cseq, sseq, TCP_FIN | TCP_ACK, 64240, {}), 80);
  ++cseq;
}

std::string sample_tls_keylog() {
  const Bytes cr = sample_client_random();
  std::string s;
  s += "# netcap sample key log for the TLS 1.3 session in the sample capture\n";
  s += "# format: <label> <client_random> <secret>\n";
  s += "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + to_hex(cr) + " " + to_hex(sample_c_hs_secret()) + "\n";
  s += "SERVER_HANDSHAKE_TRAFFIC_SECRET " + to_hex(cr) + " " + to_hex(sample_s_hs_secret()) + "\n";
  s += "CLIENT_TRAFFIC_SECRET_0 " + to_hex(cr) + " " + to_hex(sample_c_ap_secret()) + "\n";
  s += "SERVER_TRAFFIC_SECRET_0 " + to_hex(cr) + " " + to_hex(sample_s_ap_secret()) + "\n";
  return s;
}

void test_tls(Ctx& c) {
  c.section("tls: cipher suites and record framing");
  {
    const TlsCipherSuite* s = tls_cipher_suite(0x1301);
    c.ok(s != nullptr, "TLS_AES_128_GCM_SHA256 is known");
    c.eq_u64(s ? u64(s->key_len) : 0, 16, "AES-128 key length");
    c.ok(s && s->tls13 && s->mode == TlsCipherSuite::Mode::AesGcm, "TLS 1.3 AES-GCM mode");
    c.ok(tls_cipher_suite(0x1302) && tls_cipher_suite(0x1302)->sha384, "TLS 1.3 SHA-384 suite");
    c.ok(tls_cipher_suite(0x1303) &&
             tls_cipher_suite(0x1303)->mode == TlsCipherSuite::Mode::Chacha20Poly1305,
         "ChaCha20-Poly1305 suite");
    const TlsCipherSuite* cbc = tls_cipher_suite(0xc027);
    c.ok(cbc && cbc->mode == TlsCipherSuite::Mode::AesCbc && cbc->mac_len == 32,
         "CBC-SHA256 suite");
    c.ok(tls_cipher_suite(0x002f) == nullptr, "SHA-1 CBC suites stay unsupported");
    c.eq_str(tls_cipher_suite_name(0x002f), "TLS_RSA_WITH_AES_128_CBC_SHA",
             "an unimplemented suite keeps its name");
    c.eq_str(tls_cipher_suite_name(0x9999), "0x9999", "an unknown suite prints its id");
    const u8 rec[] = {0x17, 0x03, 0x03, 0x00, 0x2a};
    TlsRecordHeader h;
    c.eq_u64(tls_parse_record_header(rec, 5, &h), 5, "a record header is 5 bytes");
    c.eq_u64(h.type, 23, "record type");
    c.eq_u64(h.version, 0x0303, "record version");
    c.eq_u64(h.length, 42, "record length");
    c.eq_u64(tls_parse_record_header(rec, 4, &h), 0, "a short header needs more bytes");
    const char* http_line = "GET /index.html HTTP/1.1\r\n";
    c.eq_u64(tls_parse_record_header(reinterpret_cast<const u8*>(http_line), 26, &h), 0,
             "an HTTP request line is not a TLS record");
    const char* ssh_banner = "SSH-2.0-OpenSSH_9.0\r\n";
    c.eq_u64(tls_parse_record_header(reinterpret_cast<const u8*>(ssh_banner), 21, &h), 0,
             "an SSH banner is not a TLS record");
  }

  c.section("tls: handshake parsing");
  {
    const Bytes cr = tls_seq_bytes(0x01, 32);
    const Bytes body = tls_hello_body("Example.COM", {0x1301, 0x1302, 0xc02f}, false, 0, cr);
    TlsClientHelloInfo ch;
    std::string err;
    c.ok(tls_parse_client_hello(body.data(), body.size(), &ch, &err), "the ClientHello parses");
    c.eq_u64(ch.random.size(), 32, "client random length");
    c.eq_hex(ch.random, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
             "client random bytes");
    c.eq_str(ch.sni, "example.com", "the SNI is lower cased");
    c.eq_u64(ch.supported_version, 0x0304, "the offered version");
    c.eq_u64(ch.cipher_suites.size(), 3, "three cipher suites offered");
    c.eq_u64(ch.cipher_suites[2], 0xc02f, "the last cipher suite");
    c.eq_u64(ch.alpn.size(), 1, "one ALPN protocol");
    c.eq_str(ch.alpn.empty() ? "" : ch.alpn[0], "h2", "the ALPN protocol");
    c.eq_u64(ch.key_share_groups.size(), 1, "one key share");
    c.eq_u64(ch.key_share_groups[0], 29, "x25519 key share");
    TlsClientHelloInfo bad;
    c.ok(!tls_parse_client_hello(body.data(), 20, &bad, &err), "a truncated ClientHello is refused");

    const Bytes sr = tls_seq_bytes(0x80, 32);
    const Bytes shb = tls_hello_body("", {}, true, 0x1301, sr);
    TlsServerHelloInfo sh;
    c.ok(tls_parse_server_hello(shb.data(), shb.size(), &sh, &err), "the ServerHello parses");
    c.eq_u64(sh.cipher_suite, 0x1301, "the chosen cipher suite");
    c.eq_u64(sh.supported_version, 0x0304, "the selected version");
    c.ok(sh.has_key_share && sh.key_share_group == 29, "the server key share group");
    c.eq_str(sh.alpn.empty() ? "" : sh.alpn[0], "h2", "the negotiated ALPN");
  }

  c.section("tls: key log store");
  {
    const Bytes cr = tls_seq_bytes(0x01, 32);
    KeyLogStore store;
    c.ok(!store.knows(cr.data()), "an empty store knows nothing");
    KeyLogEntry e;
    e.label = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    e.client_random = cr;
    e.secret = tls_seq_bytes(0xa0, 32);
    store.add(e);
    KeyLogEntry e2;
    e2.label = "CLIENT_TRAFFIC_SECRET_0";
    e2.client_random = cr;
    e2.secret = tls_seq_bytes(0xc0, 32);
    store.add(e2);
    c.eq_u64(store.size(), 2, "two secrets stored");
    c.eq_u64(store.client_randoms(), 1, "one client random");
    c.ok(store.knows(cr.data()), "the client random is known");
    const Bytes* got = store.secret("CLIENT_TRAFFIC_SECRET_0", cr.data());
    c.ok(got != nullptr, "the traffic secret is found");
    if (got) {
      c.eq_hex(*got, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
               "the secret bytes");
    }
    c.eq_u64(store.labels_for(cr.data()).size(), 2, "both labels are listed");
    c.ok(store.secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET", cr.data()) == nullptr,
         "a missing label returns null");
    c.ok(!store.knows(tls_seq_bytes(0x55, 32).data()), "an unrelated client random is unknown");

    const std::string kpath = "netcap_selftest_keylog.txt";
    {
      std::FILE* f = std::fopen(kpath.c_str(), "wb");
      if (f) {
        const std::string text = "# a comment\nSERVER_HANDSHAKE_TRAFFIC_SECRET " + to_hex(cr) + " " +
                                 to_hex(e.secret) + "\n";
        std::fwrite(text.data(), 1, text.size(), f);
        std::fclose(f);
      }
    }
    KeyLogStore from_file;
    std::string kerr;
    c.ok(from_file.load_file(kpath, &kerr), "the key log file loads");
    c.eq_u64(from_file.size(), 1, "one secret from the file");
    c.ok(from_file.secret("SERVER_HANDSHAKE_TRAFFIC_SECRET", cr.data()) != nullptr,
         "the file secret is usable");
    c.ok(!from_file.load_file("netcap_selftest_missing_keylog.txt", &kerr),
         "a missing key log file fails");
    std::remove(kpath.c_str());
  }

  c.section("tls: 1.3 decryption from a key log");
  {
    const Bytes cr = tls_seq_bytes(0x01, 32);
    const Bytes sr = tls_seq_bytes(0x80, 32);
    const Bytes c_hs = tls_seq_bytes(0x30, 32);
    const Bytes s_hs = tls_seq_bytes(0xa0, 32);
    const Bytes c_ap = tls_seq_bytes(0x50, 32);
    const Bytes s_ap = tls_seq_bytes(0xc0, 32);
    auto store = std::make_shared<KeyLogStore>();
    const std::pair<const char*, Bytes> secrets[] = {
        {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", c_hs},
        {"SERVER_HANDSHAKE_TRAFFIC_SECRET", s_hs},
        {"CLIENT_TRAFFIC_SECRET_0", c_ap},
        {"SERVER_TRAFFIC_SECRET_0", s_ap},
    };
    for (const auto& kv : secrets) {
      KeyLogEntry e;
      e.label = kv.first;
      e.client_random = cr;
      e.secret = kv.second;
      store->add(e);
    }

    TlsSession s;
    s.set_keylog(store);
    c.ok(!s.is_tls(), "a fresh session is not TLS");
    const Bytes ch_rec = tls_handshake_record(1, tls_hello_body("example.com", {0x1301}, false, 0, cr));
    s.feed(0, ch_rec.data(), ch_rec.size(), 100);
    c.ok(s.client_hello() != nullptr, "the ClientHello is parsed");
    c.eq_str(s.client_hello() ? s.client_hello()->sni : "", "example.com", "the SNI is captured");
    c.ok(!s.has_keys(), "no keys before the ServerHello");
    c.ok(s.is_tls(), "the session is recognised as TLS");
    const Bytes sh_rec = tls_handshake_record(2, tls_hello_body("", {}, true, 0x1301, sr));
    s.feed(1, sh_rec.data(), sh_rec.size(), 200);
    c.ok(s.server_hello() != nullptr, "the ServerHello is parsed");
    c.ok(s.has_keys(), "the key log provides traffic keys");
    c.eq_u64(s.stats().decrypted_records, 0, "nothing decrypted yet");
    c.eq_u64(s.stats().records, 2, "two records framed");
    c.ok(s.describe().find("TLS 1.3") != std::string::npos, "describe() names the version");
    c.ok(s.describe().find("TLS_AES_128_GCM_SHA256") != std::string::npos,
         "describe() names the cipher suite");
    c.ok(s.describe().find("example.com") != std::string::npos, "describe() carries the SNI");

    // A handshake record sealed with the server handshake key, sequence 0.
    const Bytes ee_msg = tls_handshake_message(8, Bytes{0, 0, 0, 0});
    const Bytes ee_rec = tls13_seal(s_hs, 0, 22, ee_msg, 0x1301, false, false);
    s.feed(1, ee_rec.data(), ee_rec.size(), 300);
    c.ok(s.records().back().decrypted, "a handshake record decrypts with the handshake key");
    c.eq_u64(s.records().back().epoch, 1, "the handshake epoch is reported");
    c.eq_u64(s.records().back().inner_type, 22, "the inner content type is recovered");
    c.eq_u64(s.stats().handshake_messages, 3, "the encrypted handshake message is parsed");

    // Application data, padded the way real stacks pad it.
    const std::string http_rsp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    const Bytes ap_rec = tls13_seal(s_ap, 0, 23, tls_text(http_rsp), 0x1301, false, true);
    s.feed(1, ap_rec.data(), ap_rec.size(), 400);
    c.ok(s.records().back().decrypted, "an application record decrypts with the app key");
    c.eq_u64(s.records().back().epoch, 2, "the session switched to the application epoch");
    c.eq_u64(s.records().back().inner_type, 23, "inner type application data");
    c.eq_str(text_of(s.plaintext(1)), http_rsp, "the HTTP response is recovered");
    c.eq_u64(s.stats().application_bytes, http_rsp.size(), "the application byte count");

    const std::string req2 = "GET /two HTTP/1.1\r\n";
    const Bytes ap2 = tls13_seal(s_ap, 1, 23, tls_text(req2), 0x1301, false, false);
    s.feed(1, ap2.data(), ap2.size(), 500);
    c.ok(s.records().back().decrypted, "the next application record uses sequence 1");
    c.eq_u64(s.records().back().epoch, 2, "still the application epoch");

    // A tampered record must fail authentication without disturbing the sequence.
    Bytes bad = tls13_seal(s_ap, 2, 23, tls_text("secret"), 0x1301, false, false);
    bad[bad.size() - 1] ^= 0xff;
    s.feed(1, bad.data(), bad.size(), 600);
    c.ok(!s.records().back().decrypted, "a tampered record is refused");
    c.ok(s.records().back().auth_failed, "the authentication failure is recorded");
    const std::size_t before = s.plaintext(1).size();
    const std::string after = "after tamper";
    const Bytes good = tls13_seal(s_ap, 2, 23, tls_text(after), 0x1301, false, false);
    s.feed(1, good.data(), good.size(), 700);
    c.ok(s.records().back().decrypted, "the sequence number survived the failure");
    c.eq_u64(s.plaintext(1).size() - before, after.size(), "the recovered bytes");

    // The client direction uses its own secrets.
    const std::string creq = "GET / HTTP/1.1\r\n";
    const Bytes cl = tls13_seal(c_ap, 0, 23, tls_text(creq), 0x1301, false, false);
    s.feed(0, cl.data(), cl.size(), 800);
    c.ok(s.records().back().decrypted, "the client direction decrypts with its own key");
    c.eq_str(text_of(s.plaintext(0)), creq, "the client plaintext");

    // A record split across two feeds, then two records in one feed.
    const std::string split_txt = "split record";
    const Bytes split = tls13_seal(s_ap, 3, 23, tls_text(split_txt), 0x1301, false, false);
    const std::size_t nrec = s.records().size();
    s.feed(1, split.data(), 7, 900);
    c.eq_u64(s.records().size(), nrec, "a partial record produces nothing");
    s.feed(1, split.data() + 7, split.size() - 7, 901);
    c.eq_u64(s.records().size(), nrec + 1, "the rest of the record completes it");
    c.ok(s.records().back().decrypted, "the split record decrypts");
    const std::string third = "alert-ish";
    const Bytes two = [&] {
      Bytes v = tls13_seal(s_ap, 4, 23, tls_text("first"), 0x1301, false, false);
      const Bytes b2 = tls13_seal(s_ap, 5, 23, tls_text(third), 0x1301, false, false);
      v.insert(v.end(), b2.begin(), b2.end());
      return v;
    }();
    s.feed(1, two.data(), two.size(), 1000);
    c.eq_u64(s.records().size(), nrec + 3, "two records in one feed are both framed");
    c.ok(s.records().back().decrypted, "the second record of the pair decrypts");

    // The recovered plaintext is ordinary HTTP as far as the HTTP parser cares.
    {
      HttpParser p;
      std::vector<HttpMessage> out;
      p.feed(s.plaintext(1).data(), http_rsp.size(), 1, &out);
      c.eq_u64(out.size(), 1, "the decrypted response parses as HTTP");
      c.eq_u64(out[0].status, 200, "the status from the decrypted stream");
      c.eq_str(out[0].body, "hello", "the body from the decrypted stream");
    }
    c.ok(s.decrypted_anything(), "the session reports decrypted traffic");
  }

  c.section("tls: 1.3 with ChaCha20-Poly1305");
  {
    const Bytes cr = tls_seq_bytes(0x11, 32);
    const Bytes sr = tls_seq_bytes(0x91, 32);
    const Bytes s_ap = tls_seq_bytes(0x77, 32);
    auto store = std::make_shared<KeyLogStore>();
    KeyLogEntry e;
    e.label = "SERVER_TRAFFIC_SECRET_0";
    e.client_random = cr;
    e.secret = s_ap;
    store->add(e);
    TlsSession s;
    s.set_keylog(store);
    const Bytes ch_rec = tls_handshake_record(1, tls_hello_body("c.example", {0x1303}, false, 0, cr));
    s.feed(0, ch_rec.data(), ch_rec.size(), 10);
    const Bytes sh_rec = tls_handshake_record(2, tls_hello_body("", {}, true, 0x1303, sr));
    s.feed(1, sh_rec.data(), sh_rec.size(), 20);
    c.ok(s.has_keys(), "ChaCha20 keys are derived");
    const std::string txt = "chacha protected payload";
    const Bytes rec = tls13_seal(s_ap, 0, 23, tls_text(txt), 0x1303, false, false);
    s.feed(1, rec.data(), rec.size(), 30);
    c.ok(s.records().back().decrypted, "the ChaCha20-Poly1305 record decrypts");
    c.eq_str(text_of(s.plaintext(1)), txt, "the ChaCha20 plaintext");
  }

  c.section("tls: 1.3 without a key log");
  {
    const Bytes cr = tls_seq_bytes(0x21, 32);
    const Bytes sr = tls_seq_bytes(0xa1, 32);
    const Bytes s_ap = tls_seq_bytes(0x88, 32);
    TlsSession s;
    const Bytes ch_rec = tls_handshake_record(1, tls_hello_body("nokey.example", {0x1301}, false, 0, cr));
    s.feed(0, ch_rec.data(), ch_rec.size(), 10);
    const Bytes sh_rec = tls_handshake_record(2, tls_hello_body("", {}, true, 0x1301, sr));
    s.feed(1, sh_rec.data(), sh_rec.size(), 20);
    c.ok(!s.has_keys(), "no keys without a key log");
    const Bytes rec = tls13_seal(s_ap, 0, 23, tls_text("hidden"), 0x1301, false, false);
    s.feed(1, rec.data(), rec.size(), 30);
    c.ok(!s.records().back().decrypted, "the record stays encrypted");
    c.ok(s.records().back().note.find("no keys") != std::string::npos,
         "the record says why it was not decrypted");
    c.eq_u64(s.plaintext(1).size(), 0, "no plaintext is produced");
    c.ok(!s.decrypted_anything(), "the session reports no decryption");
  }

  c.section("tls: 1.2 AES-GCM decryption");
  {
    const Bytes cr = tls_seq_bytes(0x31, 32);
    const Bytes sr = tls_seq_bytes(0xb1, 32);
    const Bytes master = tls_seq_bytes(0x11, 48);
    auto store = std::make_shared<KeyLogStore>();
    KeyLogEntry e;
    e.label = "CLIENT_RANDOM";
    e.client_random = cr;
    e.secret = master;
    store->add(e);
    TlsSession s;
    s.set_keylog(store);
    const Bytes ch_rec =
        tls_handshake_record(1, tls_hello_body("gcm.example", {0xc02f}, false, 0, cr, false));
    s.feed(0, ch_rec.data(), ch_rec.size(), 10);
    const Bytes sh_rec = tls_handshake_record(2, tls_hello_body("", {}, true, 0xc02f, sr, false));
    s.feed(1, sh_rec.data(), sh_rec.size(), 20);
    c.ok(s.server_hello() != nullptr, "the 1.2 ServerHello is parsed");
    c.eq_u64(s.server_hello() ? s.server_hello()->supported_version : 0, 0x0303,
             "a 1.2 ServerHello reports its legacy version");
    const Bytes ccs = tls_record(20, 0x0303, Bytes{1});
    s.feed(0, ccs.data(), ccs.size(), 30);
    s.feed(1, ccs.data(), ccs.size(), 31);
    c.ok(s.has_keys(), "the master secret yields TLS 1.2 keys");
    c.ok(s.describe().find("TLS 1.2") != std::string::npos, "describe() names TLS 1.2");

    // Derive the same key block the session derived and seal a response with it.
    Bytes seed = sr;
    seed.insert(seed.end(), cr.begin(), cr.end());
    const Bytes kb = tls12_prf(master, "key expansion", seed, 2 * (0 + 16 + 4), false);
    c.eq_u64(kb.size(), 40, "the key block length for AES-128-GCM");
    const Bytes server_key(kb.begin() + 16, kb.begin() + 32);
    const Bytes server_iv(kb.begin() + 36, kb.begin() + 40);
    const std::string rsp = "HTTP/1.1 204 No Content\r\n\r\n";
    const Bytes rec = tls12_gcm_record(server_key, server_iv, 0, 23, tls_text(rsp));
    s.feed(1, rec.data(), rec.size(), 40);
    c.ok(s.records().back().decrypted, "the TLS 1.2 GCM record decrypts");
    c.eq_u64(s.records().back().inner_type, 23, "the 1.2 inner type");
    c.eq_str(text_of(s.plaintext(1)), rsp, "the TLS 1.2 plaintext");
    const Bytes rec2 = tls12_gcm_record(server_key, server_iv, 1, 23, tls_text("HTTP/1.1 404 X\r\n\r\n"));
    s.feed(1, rec2.data(), rec2.size(), 50);
    c.ok(s.records().back().decrypted, "the second record uses sequence 1");
    c.eq_u64(s.stats().decrypted_records, 2, "two records decrypted");
    // A tampered record: the tag no longer matches.
    Bytes bad = tls12_gcm_record(server_key, server_iv, 2, 23, tls_text("bad"));
    bad[8] ^= 0x01;
    s.feed(1, bad.data(), bad.size(), 60);
    c.ok(!s.records().back().decrypted, "a tampered GCM record is refused");
    c.ok(s.records().back().note.find("AEAD") != std::string::npos, "the AEAD failure is reported");
  }

  c.section("tls: 1.2 AES-CBC with HMAC");
  {
    const Bytes cr = tls_seq_bytes(0x41, 32);
    const Bytes sr = tls_seq_bytes(0xc1, 32);
    const Bytes master = tls_seq_bytes(0x22, 48);
    auto store = std::make_shared<KeyLogStore>();
    KeyLogEntry e;
    e.label = "CLIENT_RANDOM";
    e.client_random = cr;
    e.secret = master;
    store->add(e);
    TlsSession s;
    s.set_keylog(store);
    const Bytes ch_rec =
        tls_handshake_record(1, tls_hello_body("cbc.example", {0xc027}, false, 0, cr, false));
    s.feed(0, ch_rec.data(), ch_rec.size(), 10);
    const Bytes sh_rec = tls_handshake_record(2, tls_hello_body("", {}, true, 0xc027, sr, false));
    s.feed(1, sh_rec.data(), sh_rec.size(), 20);
    const Bytes ccs = tls_record(20, 0x0303, Bytes{1});
    s.feed(0, ccs.data(), ccs.size(), 30);
    s.feed(1, ccs.data(), ccs.size(), 31);
    c.ok(s.has_keys(), "CBC keys are derived from the master secret");

    Bytes seed = sr;
    seed.insert(seed.end(), cr.begin(), cr.end());
    const Bytes kb = tls12_prf(master, "key expansion", seed, 2 * (32 + 16 + 16), false);
    c.eq_u64(kb.size(), 128, "the key block length for AES-128-CBC-SHA256");
    const Bytes server_mac(kb.begin() + 32, kb.begin() + 64);
    const Bytes server_key(kb.begin() + 80, kb.begin() + 96);
    const Bytes server_iv(kb.begin() + 112, kb.begin() + 128);
    Aes aes;
    c.ok(aes.set_key(server_key), "the record key is usable");
    const std::string body = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    const Bytes rec = tls12_cbc_record(aes, server_mac, server_iv, 0, 23, tls_text(body), false);
    s.feed(1, rec.data(), rec.size(), 40);
    c.ok(s.records().back().decrypted, "the CBC record decrypts");
    c.eq_str(text_of(s.plaintext(1)), body, "the CBC plaintext after padding is stripped");

    // Corrupting the ciphertext must be caught by the MAC.
    Bytes bad = rec;
    bad[6] ^= 0x01;
    s.feed(1, bad.data(), bad.size(), 50);
    c.ok(!s.records().back().decrypted, "a corrupted CBC record is refused");
    c.ok(s.records().back().note.find("MAC") != std::string::npos,
         "the CBC failure mentions the MAC");
  }

  c.section("tls: non-TLS input");
  {
    TlsSession s;
    const std::string junk = "this is not a TLS record at all, just text";
    s.feed(0, reinterpret_cast<const u8*>(junk.data()), junk.size(), 1);
    c.eq_u64(s.records().size(), 0, "no record is framed from junk");
    c.ok(!s.is_tls(), "junk is not TLS");
  }
}

// ---------------------------------------------------------------------------
// HTTP/2 frames and HPACK
// ---------------------------------------------------------------------------

Bytes h2_frame(u8 type, u8 flags, u32 stream_id, const Bytes& payload) {
  Bytes f;
  f.push_back(u8((payload.size() >> 16) & 0xff));
  f.push_back(u8((payload.size() >> 8) & 0xff));
  f.push_back(u8(payload.size() & 0xff));
  f.push_back(type);
  f.push_back(flags);
  f.push_back(u8((stream_id >> 24) & 0xff));
  f.push_back(u8((stream_id >> 16) & 0xff));
  f.push_back(u8((stream_id >> 8) & 0xff));
  f.push_back(u8(stream_id & 0xff));
  f.insert(f.end(), payload.begin(), payload.end());
  return f;
}

Bytes h2_setting_bytes(u16 id, u32 value) {
  Bytes p;
  p.push_back(u8(id >> 8));
  p.push_back(u8(id & 0xff));
  p.push_back(u8((value >> 24) & 0xff));
  p.push_back(u8((value >> 16) & 0xff));
  p.push_back(u8((value >> 8) & 0xff));
  p.push_back(u8(value & 0xff));
  return p;
}

// RFC 7541 C.4.1: :method GET, :scheme http, :path /, :authority
// www.example.com with the authority Huffman coded.
Bytes h2_request_block() {
  const u8 b[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
                  0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
  return Bytes(b, b + sizeof(b));
}

// :status 200 plus content-type: text/plain.
Bytes h2_response_block() {
  const u8 b[] = {0x88, 0x5f, 0x0a, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n'};
  return Bytes(b, b + sizeof(b));
}

// -- HTTP response framing ----------------------------------------------------
// The framer decides where a response ends, which is what makes upstream
// keep-alive safe: reuse is only allowed when the end of the body followed from
// the head itself.  It is fed the bytes exactly as TLS records deliver them, so
// every case below is also checked across hostile splits.
// Every document that goes through the proxy now carries the picker bootstrap
// (that is the channel the interface button uses on already-open pages), so
// tests that compare a rewritten body byte for byte have to take it out again.
std::string strip_picker_bootstrap(std::string body) {
  const std::string boot = picker_bootstrap_script();
  const std::string wrapped = "<script>" + boot + "</script>";
  std::size_t at = body.find(wrapped);
  if (at != std::string::npos) {
    body.erase(at, wrapped.size());
    return body;
  }
  at = body.find(boot);
  if (at != std::string::npos) body.erase(at, boot.size());
  return body;
}

void test_picker(Ctx& c) {
  c.section("element picker");

  // The page asks us for exactly this one path; everything else is traffic.
  c.ok(picker_is_pick_path("/__netcap/pick"), "the picker path is recognised");
  c.ok(picker_is_pick_path("/__netcap/pick?h=a.com&s=.ad"), "…with a query string too");
  c.ok(!picker_is_pick_path("/__netcap/picker"), "a lookalike path is not the picker");
  c.ok(!picker_is_pick_path("/index.html"), "an ordinary path is not the picker");

  // The two control routes have to stay distinct from the pick route: the page
  // asks the first one "are we picking?" long before anything is picked.
  c.ok(picker_is_ctl_path("/__netcap/ctl"), "the control path is recognised");
  c.ok(picker_is_ctl_path("/__netcap/ctl?t=123"), "…with a cache-busting query too");
  c.ok(!picker_is_ctl_path(kPickerPath), "the pick path is not the control path");
  c.ok(!picker_is_ctl_path("/__netcap/ctlx"), "a lookalike path is not the control path");
  c.ok(picker_is_script_path("/__netcap/picker.js"), "the script path is recognised");
  c.ok(!picker_is_script_path("/__netcap/picker.jsx"), "a lookalike path is not the script");
  c.ok(!picker_is_script_path(kPickerPath), "the pick path is not the script path");

  // What the script sends: host, selector and the page it was picked on.
  std::string host, selector, url;
  const bool parsed = picker_parse_pick(
      "/__netcap/pick?h=WWW.Example.com&s=%23ad-slot%20.banner&u=http%3A%2F%2Fexample.com%2Fa%3Fb%3D1",
      &host, &selector, &url);
  c.ok(parsed, "a pick request parses");
  c.eq_str(host, "www.example.com", "…lowercased, because a rule line is lowercased too");
  c.eq_str(selector, "#ad-slot .banner", "…and decoding the selector");
  c.eq_str(url, "http://example.com/a?b=1", "…and the page URL");
  c.ok(!picker_parse_pick("/__netcap/pick?h=a.com", &host, &selector, &url),
       "a pick without a selector is refused");
  c.ok(!picker_parse_pick("/__netcap/pick?s=.ad", &host, &selector, &url),
       "a pick without a host is refused");

  // A selector ends up inside a <style>, so anything that could escape it is out.
  std::string why;
  c.ok(picker_selector_ok("#ad-slot .banner > a"), "an ordinary selector is accepted");
  c.ok(picker_selector_ok("a[data-x=\"1\"]:not(.keep)"), "…including attributes and :not()");
  c.ok(!picker_selector_ok(""), "an empty selector is refused");
  c.ok(!picker_selector_ok("a { color: red }"), "a selector carrying braces is refused");
  c.ok(!picker_selector_ok("</style><script>x</script>"),
       "a selector trying to close the style tag is refused");
  c.ok(!picker_selector_ok(std::string(400, 'a')), "an absurdly long selector is refused");
  c.ok(!picker_selector_ok("a/*"), "a selector opening a comment is refused");
  c.ok(!picker_selector_ok("a*/"), "a selector closing a comment is refused");
  c.ok(!picker_selector_ok(std::string("a") + '\x01' + "b"), "a control character is refused");
  c.ok(!picker_selector_ok("a{color:red}", &why) && !why.empty(), "the reason is reported");

  // The appended line has to be a rule the rule engine would accept back.
  c.eq_str(picker_rule_line("WWW.Example.com", ".ad"), "www.example.com##.ad",
           "a rule line lowercases the host");
  c.eq_str(picker_rule_line("example.com", "#promo"), "example.com###promo",
           "an id selector keeps its hash");
  c.ok(picker_rule_line("", ".ad").empty(), "a rule without a host is refused");
  c.ok(picker_rule_line("not a host", ".ad").empty(), "a host with a space is refused");
  c.eq_str(picker_rule_line("localhost", ".ad"), "localhost##.ad", "localhost is allowed");
  c.ok(picker_rule_line(std::string(300, 'a') + ".com", ".ad").empty(),
       "an over-long host is refused");

  // A rule belongs to the page it was picked on, and to its subdomains.
  c.ok(picker_host_matches("example.com", "example.com"), "a rule matches its own host");
  c.ok(picker_host_matches("example.com", "www.example.com"), "…and a subdomain of it");
  c.ok(picker_host_matches("WWW.Example.com", "www.example.com"), "…case-insensitively");
  c.ok(!picker_host_matches("example.com", "notexample.com"),
       "a longer label is not a subdomain");
  c.ok(!picker_host_matches("example.com", "example.com.evil.net"),
       "a host that merely ends in the name does not match");
  c.ok(!picker_host_matches("example.com", ""), "an unknown document host matches nothing");

  // Appending the rule is what makes a pick survive a restart.
  std::string dir = ".";
  if (const char* tmp = std::getenv("TEMP")) dir = tmp;
  else if (const char* tmp = std::getenv("TMP")) dir = tmp;
  const std::string path = dir + "/netcap_picker_selftest.txt";
  std::remove(path.c_str());
  std::string error;
  c.ok(picker_append_rule(path, "example.com##.ad", "http://example.com/", &error),
       "a pick is appended to the rule file");
  c.ok(error.empty(), "…without an error");
  std::string text;
  {
    std::ifstream in(path.c_str());
    std::string line;
    while (std::getline(in, line)) text += line + "\n";
  }
  c.ok(text.find("example.com##.ad") != std::string::npos, "…and the rule is in the file");
  c.ok(text.find("http://example.com/") != std::string::npos,
       "…together with the page it came from");
  c.ok(picker_append_rule(path, "example.com##.two", "http://example.com/", &error),
       "a second pick appends instead of replacing");
  text.clear();
  {
    std::ifstream in(path.c_str());
    std::string line;
    while (std::getline(in, line)) text += line + "\n";
  }
  c.ok(text.find(".ad") != std::string::npos && text.find(".two") != std::string::npos,
       "…and both rules are there");
  std::remove(path.c_str());
  const std::string deep = dir + "/netcap_picker_dir/sub/rules.txt";
  c.ok(picker_append_rule(deep, "example.com##.deep", "http://example.com/", &error),
       "a missing directory is created on the way");
  std::remove(deep.c_str());
  std::remove((dir + "/netcap_picker_dir/sub").c_str());
  std::remove((dir + "/netcap_picker_dir").c_str());
  c.ok(!picker_append_rule("", "example.com##.ad", "http://example.com/", &error),
       "no rule file means the pick cannot be kept");

  // The script is what the user actually clicks on.  The interaction mirrors
  // uBlock Origin: hover to outline, click to open a panel with suggestions, two
  // sliders, an editable field, and 创建 / 选择 / 放弃.
  const std::string script = picker_script();
  c.ok(!script.empty(), "the picker script is not empty");
  c.ok(script.find(kPickerPath) != std::string::npos, "…and reports back to the picker path");
  c.ok(script.find("data-nc-hover") != std::string::npos, "…and highlights what is under the cursor");
  c.ok(script.find("cursor:crosshair") != std::string::npos,
       "…and turns the mouse into a crosshair while picking");
  c.ok(script.find("nc-pick-panel") != std::string::npos, "…and opens a rule panel");
  c.ok(script.find("nc-pick-sug") != std::string::npos, "…that lists suggested selectors");
  c.ok(script.find("nc-pick-depth") != std::string::npos && script.find("nc-pick-spec") != std::string::npos,
       "…with the two sliders (how far up the tree, how much it pins down)");
  c.ok(script.find("创建") != std::string::npos && script.find("选择") != std::string::npos &&
           script.find("放弃") != std::string::npos,
       "…and the 创建 / 选择 / 放弃 buttons");
  // The bootstrap calls this when picking is switched off from the interface,
  // which is what makes the button work on a page that is already open.
  c.ok(script.find("window.__ncPickerOff=stop") != std::string::npos,
       "…and can be switched off from outside");

  const std::string bootstrap = picker_bootstrap_script();
  c.ok(!bootstrap.empty(), "the bootstrap script is not empty");
  c.ok(bootstrap.find(kPickerCtlPath) != std::string::npos, "…and asks the control path");
  c.ok(bootstrap.find(kPickerScriptPath) != std::string::npos, "…and pulls in the picker script");
  c.ok(bootstrap.find("__ncPickerOff") != std::string::npos,
       "…and hands the page back to normal when picking ends");
  c.ok(bootstrap.find("setTimeout(poll") != std::string::npos, "…and keeps polling");
  c.ok(bootstrap.size() < 1300, "…while staying small (it is in every document; it says what it is doing in the console)");
  c.ok(script.find("data-nc-mark") != std::string::npos, "…and previews a suggestion on the page");
  c.ok(script.find("Escape") != std::string::npos, "…and can be left with the keyboard");
}

void test_origin(Ctx& c) {
  c.section("origin addresses and the picker");
  std::vector<OriginAddress> addresses;
  std::string why;
  // The call is made before the message is built: function arguments are
  // evaluated in an unspecified order, so `c.ok(f(&why), "…" + why)` would
  // sometimes report the previous (empty) text.
  const bool resolved = origin_resolve("localhost", 443, &addresses, &why);
  c.ok(resolved, "localhost resolves (" + why + ")");
  c.ok(!addresses.empty(), "localhost has at least one address");
  bool ports_ok = true;
  bool shapes_ok = true;
  for (const OriginAddress& address : addresses) {
    if (address.port != 443) ports_ok = false;
    if (address.text.empty()) shapes_ok = false;
    if (address.family == AF_INET && address.bytes.size() != 4) shapes_ok = false;
    if (address.family == AF_INET6 && address.bytes.size() != 16) shapes_ok = false;
    if (address.family != AF_INET && address.family != AF_INET6) shapes_ok = false;
  }
  c.ok(ports_ok, "every address carries the port it was resolved for");
  c.ok(shapes_ok, "every address has text and the right number of bytes");
  c.ok(origin_family_name(AF_INET) == "ipv4" && origin_family_name(AF_INET6) == "ipv6",
       "families have names");

  std::vector<OriginAddress> missing;
  why.clear();
  const bool refused = origin_resolve("not a valid host name", 80, &missing, &why);
  c.ok(!refused, "a name the resolver refuses is reported as a failure");
  c.ok(missing.empty(), "and no address is invented");
  c.ok(!why.empty(), "with a reason: " + why);
#ifdef _WIN32
  // That reason has to be readable text.  gai_strerror() is empty for
  // WSAHOST_NOT_FOUND on Windows, which is how a 502 whose detail ended in an
  // empty pair of parentheses - "cannot resolve X ()" - came about.
  c.eq_str(origin_gai_text(0), "no address", "an empty resolver list explains itself");
  c.ok(origin_gai_text(11001).find("WSAHOST_NOT_FOUND") != std::string::npos,
       "WSAHOST_NOT_FOUND is spelled out: " + origin_gai_text(11001));
  c.ok(origin_gai_text(11004).find("WSANO_DATA") != std::string::npos,
       "WSANO_DATA - an AAAA-only name where IPv6 cannot be used - is spelled out: " +
           origin_gai_text(11004));
  c.ok(!origin_gai_text(9999).empty(),
       "an unknown resolver error still says something: " + origin_gai_text(9999));
#endif
  why.clear();
  origin_resolve(std::string(300, 'a') + ".example", 80, &missing, &why);
  c.ok(missing.size() <= origin_max_addresses(),
       "one host can never contribute more than the cap");

  OriginPolicy policy = OriginPolicy::First;
  c.ok(origin_policy_parse("BEST", &policy) && policy == OriginPolicy::Best,
       "policy names parse case-insensitively");
  c.ok(origin_policy_parse("first", &policy) && policy == OriginPolicy::First, "first is accepted");
  c.ok(!origin_policy_parse("sideways", &policy) && policy == OriginPolicy::First,
       "an unknown policy is rejected and leaves the old value alone");
  c.ok(std::string(origin_policy_name(OriginPolicy::Best)) == "best", "and the names print");

  const i64 stagger = 250 * 1000;
  const i64 ttl = 60 * 1000 * 1000;
  OriginPicker picker(OriginPolicy::Best, 2, stagger, ttl, 8 * 1000 * 1000);
  picker.set_addresses({"a", "b", "c"});
  c.eq_u64(picker.size(), 3, "the picker keeps every address");
  c.ok(picker.stale(0), "nothing measured yet means the decision is stale");
  c.ok(picker.best(0).empty(), "and there is no winner yet");
  std::vector<std::string> order = picker.order(0);
  c.ok(order.size() == 3 && order[0] == "a" && order[1] == "b" && order[2] == "c",
       "unmeasured addresses keep the resolver order");

  picker.begin_race();
  i64 wait = 123;
  std::vector<std::string> batch = picker.next_batch(0, &wait);
  c.ok(batch.size() == 2 && batch[0] == "a" && batch[1] == "b",
       "the first batch of a race starts together, so the winner is the fastest "
       "address rather than the one that was dialled first");
  c.eq_u64(static_cast<u64>(wait), 0, "with no wait for the caller");
  batch = picker.next_batch(0, &wait);
  c.ok(batch.empty(), "while both are in flight nothing else starts");
  c.eq_u64(static_cast<u64>(wait), static_cast<u64>(stagger), "and the caller is told how long to wait");
  picker.report("a", false, -1, 1000);
  batch = picker.next_batch(1000, &wait);
  c.ok(batch.empty(), "a replacement is refused before the stagger elapses");
  c.eq_u64(static_cast<u64>(wait), static_cast<u64>(stagger) - 1000, "and the caller is told the remainder");
  batch = picker.next_batch(stagger, &wait);
  c.ok(batch.size() == 1 && batch[0] == "c", "after the stagger the next address starts");
  picker.report("b", true, 12 * 1000, stagger + 2000);
  c.ok(picker.best(stagger + 3000) == "b", "the address that answered becomes the winner");
  order = picker.order(stagger + 3000);
  c.ok(order[0] == "b", "and it is ordered first");
  c.ok(order[1] == "c", "then the addresses never measured");
  c.ok(order[2] == "a", "and the one that failed goes last");
  c.ok(!picker.stale(stagger + 3000), "a fresh measurement is trusted");
  c.ok(picker.stale(stagger + 3000 + ttl + 1), "an old one is not, so it is measured again");
  const std::string text = picker.describe();
  c.ok(text.find("fastest b") != std::string::npos, "describe names the winner: " + text);
  c.ok(text.find("in backoff") != std::string::npos, "and counts the backoff: " + text);

  // The first failure costs a second, then it doubles up to the ceiling.
  OriginPicker growing(OriginPolicy::Best, 2, stagger, ttl, 8000 * 1000);
  growing.set_addresses({"x", "y"});
  const auto dead_until = [&growing](const std::string& name) {
    for (const OriginCandidate& candidate : growing.candidates()) {
      if (candidate.address == name) return candidate.dead_until_us;
    }
    return static_cast<i64>(-1);
  };
  const auto failures = [&growing](const std::string& name) {
    for (const OriginCandidate& candidate : growing.candidates()) {
      if (candidate.address == name) return candidate.failures;
    }
    return -1;
  };
  growing.report("x", false, -1, 0);
  c.eq_u64(static_cast<u64>(dead_until("x")), 1000 * 1000, "the first failure backs off for a second");
  growing.report("x", false, -1, 0);
  c.eq_u64(static_cast<u64>(dead_until("x")), 2000 * 1000, "the second one doubles it");
  growing.report("x", false, -1, 0);
  c.eq_u64(static_cast<u64>(dead_until("x")), 4000 * 1000, "and it keeps doubling");
  growing.report("x", false, -1, 0);
  c.eq_u64(static_cast<u64>(dead_until("x")), 8000 * 1000, "until the ceiling");
  growing.report("x", false, -1, 0);
  c.eq_u64(static_cast<u64>(dead_until("x")), 8000 * 1000, "which then holds");
  c.eq_u64(static_cast<u64>(failures("x")), 5, "every failure is counted");
  growing.report("x", true, 7000, 4000);
  c.eq_u64(static_cast<u64>(dead_until("x")), 0, "a success clears the backoff");
  c.eq_u64(static_cast<u64>(failures("x")), 0, "and the failure count");
  c.ok(growing.best(4000) == "x", "so it is usable again");
  growing.report("y", false, -1, 5000);
  growing.begin_race();
  batch = growing.next_batch(5000, &wait);
  c.ok(batch.size() == 2, "a race starts something even when every address is in backoff");
  c.ok(batch[0] == "x", "preferring the one that is not in backoff: " + (batch.empty() ? std::string("none") : batch[0]));

  OriginPicker first(OriginPolicy::First, 2, stagger, ttl, 1000);
  first.set_addresses({"a", "b"});
  first.report("b", true, 9000, 0);
  c.ok(first.best(1) == "b", "even in first mode the measurement is kept for the log");
  c.ok(first.order(1)[0] == "b", "and the order is still fastest-first");
  c.ok(first.describe().find("pick first") != std::string::npos,
       "but describe says which policy is in force");

  picker.set_addresses({"c", "b", "a"});
  c.ok(picker.best(stagger + 3000) == "b", "re-resolving keeps what was learned about an address");
  c.eq_u64(picker.size(), 3, "while honouring the new address list");
}

void test_httpframe(Ctx& c) {
  c.section("HTTP response framing");
  const std::string ok_head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";

  {
    HttpResponseFramer f("GET");
    std::string why;
    const std::string text = ok_head + "hello";
    std::size_t used = 0;
    c.ok(f.feed(text.data(), text.size(), &used, &why), "a Content-Length response is framed");
    c.ok(f.done(), "the framer knows where it ended");
    c.ok(f.reusable(), "and the connection can be reused");
    c.eq_u64(static_cast<u64>(f.status()), 200, "the status line was read");
    c.eq_u64(f.body_bytes(), 5, "the body length was counted");
    c.eq_u64(used, text.size(), "every byte belonged to the message");
    c.ok(!f.describe().empty(), "the framer describes itself");

    HttpResponseFramer g("GET");
    std::string part_why;
    std::size_t total = 0;
    bool all = true;
    for (char ch : text) {
      std::size_t part = 0;
      if (!g.feed(&ch, 1, &part, &part_why)) all = false;
      total += part;
    }
    c.ok(all, "the same response survives being fed one byte at a time");
    c.ok(g.done() && g.reusable(), "and ends at the same place");
    c.eq_u64(total, text.size(), "the consumed bytes add up");
  }

  {
    HttpResponseFramer f("GET");
    std::string why;
    const std::string text = ok_head + "helloGET /two HTTP/1.1\r\n";
    std::size_t used = 0;
    c.ok(f.feed(text.data(), text.size(), &used, &why),
         "a response followed by another message is framed");
    c.eq_u64(used, ok_head.size() + 5, "it stops exactly at the end of its own message");
  }

  {
    const std::string text =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5;note=1\r\nhello\r\n"
        "6\r\n world\r\n"
        "0\r\nX-Sum: 11\r\n\r\n";
    HttpResponseFramer f("GET");
    std::string why;
    std::size_t used = 0;
    c.ok(f.feed(text.data(), text.size(), &used, &why), "a chunked response is framed");
    c.ok(f.done() && f.reusable(), "a chunked response ends at the last trailer line");
    c.eq_u64(f.body_bytes(), 11, "chunk sizes and CRLFs are not counted as body");
    c.eq_u64(used, text.size(), "the whole chunked message was consumed");

    HttpResponseFramer g("GET");
    std::string part_why;
    std::size_t at = 0;
    std::size_t step = 1;
    bool all = true;
    while (at < text.size()) {
      const std::size_t left = text.size() - at;
      const std::size_t n = step < left ? step : left;
      std::size_t part = 0;
      if (!g.feed(text.data() + at, n, &part, &part_why)) all = false;
      at += n;
      ++step;
    }
    c.ok(all && g.done() && g.reusable(), "growing feeds reach the same end");
  }

  {
    HttpResponseFramer f("GET");
    std::string why;
    const std::string text = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
    std::size_t used = 0;
    c.ok(!f.feed(text.data(), text.size(), &used, &why), "a chunk size that is not hex is refused");
    c.ok(f.failed() && !why.empty(), "and the framer reports why");

    HttpResponseFramer g("GET");
    std::string why2;
    const std::string bad = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX";
    std::size_t used2 = 0;
    c.ok(!g.feed(bad.data(), bad.size(), &used2, &why2), "a chunk without its CRLF is refused");
    c.eq_u64(g.body_bytes(), 5, "the good part of the body was still counted");
  }

  {
    std::string why;
    std::size_t used = 0;
    HttpResponseFramer head("HEAD");
    const std::string text = "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
    c.ok(head.feed(text.data(), text.size(), &used, &why), "a HEAD response has no body");
    c.ok(head.done() && head.reusable() && head.body_bytes() == 0, "and ends at the head");

    HttpResponseFramer none("GET");
    const std::string nc = "HTTP/1.1 204 No Content\r\n\r\n";
    c.ok(none.feed(nc.data(), nc.size(), &used, &why) && none.done() && none.reusable(),
         "204 ends at the head as well");

    HttpResponseFramer not_modified("GET");
    const std::string nm = "HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n";
    c.ok(not_modified.feed(nm.data(), nm.size(), &used, &why) && not_modified.done() &&
             not_modified.reusable(),
         "304 keeps its Content-Length out of the body");

    HttpResponseFramer cont("GET");
    const std::string interim = "HTTP/1.1 100 Continue\r\n\r\n";
    c.ok(cont.feed(interim.data(), interim.size(), &used, &why) && cont.done() && cont.reusable(),
         "1xx is framed as a message of its own (the caller will see the next one as leftover)");

    HttpResponseFramer empty("GET");
    const std::string zero = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    c.ok(empty.feed(zero.data(), zero.size(), &used, &why) && empty.done() && empty.reusable(),
         "Content-Length: 0 is an empty body");
  }

  {
    HttpResponseFramer f("GET");
    std::string why;
    const std::string text = "HTTP/1.1 200 OK\r\n\r\nsome bytes";
    std::size_t used = 0;
    c.ok(f.feed(text.data(), text.size(), &used, &why), "a response without framing is relayed");
    c.ok(f.ends_at_close() && !f.done(), "it ends at close, not at a message boundary");
    c.ok(!f.reusable(), "so the connection cannot be reused");
    c.eq_u64(f.body_bytes(), 10, "everything after the head counts as body");
    c.eq_u64(static_cast<u64>(f.status()), 200, "and the status was still read");

    HttpResponseFramer g("GET");
    std::string why2;
    const std::string junk = "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nbody";
    std::size_t used2 = 0;
    c.ok(g.feed(junk.data(), junk.size(), &used2, &why2),
         "an unparsable Content-Length falls back to close");
    c.ok(g.ends_at_close() && !g.reusable(), "and is not treated as a boundary");
  }

  {
    HttpResponseFramer f("GET");
    std::string why;
    const std::string text = "not http at all\r\n\r\n";
    std::size_t used = 0;
    c.ok(!f.feed(text.data(), text.size(), &used, &why), "a non-HTTP head is refused");
    c.ok(f.failed() && !why.empty(), "with a reason");

    HttpResponseFramer g("GET");
    std::string why2;
    const std::string line(4096, 'a');
    bool refused = false;
    for (int i = 0; i < 20 && !refused; ++i) {
      std::size_t part = 0;
      if (!g.feed(line.data(), line.size(), &part, &why2)) refused = true;
    }
    c.ok(refused, "a head that never ends is refused instead of buffered forever");
  }
}

// RFC 9001 A.5 is a ChaCha20-Poly1305 short-header packet, and it is the test that
// catches the classic header-protection mistake: unmasking four bits of the first
// byte where a short header protects five.
void test_quickeys(Ctx& c) {
  c.section("quickeys: the browser key log, and the RFC 9001 A.5 packet");
  std::string why;
  const bool selfcheck = quickeys_selfcheck(&why);
  c.ok(selfcheck, "the key-log and rewrite module passes its own checks" +
                      (why.empty() ? std::string() : (": " + why)));

  const u8 secret_bytes[32] = {0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42,
                              0x27, 0x48, 0xad, 0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0,
                              0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b};
  const u8 a5_packet[21] = {0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6,
                            0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb};
  const Bytes secret(secret_bytes, secret_bytes + 32);
  const Bytes packet(a5_packet, a5_packet + sizeof(a5_packet));
  c.eq_hex(secret, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
           "the A.5 secret matches the RFC");
  c.eq_hex(packet, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
           "the A.5 packet matches the RFC");

  QuicKeyset keys;
  const bool derived = quic_keyset_from_secret(kH3TlsChacha20Poly1305Sha256, secret, &keys, &why);
  c.ok(derived, "the A.5 traffic secret expands into a 1-RTT key set" +
                    (why.empty() ? std::string() : (": " + why)));
  c.eq_hex(keys.key, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
           "the derived key matches the RFC");
  c.eq_hex(keys.iv, "e0459b3474bdd0e44a41c144", "the derived iv matches the RFC");
  c.eq_hex(keys.hp, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
           "the derived header protection key matches the RFC");

  why.clear();
  QuicShortHeader h3_header;
  const bool opened = quic_decrypt_short_full(keys, nullptr, 0, a5_packet, sizeof(a5_packet),
                                              654360563, &h3_header, &why);
  c.ok(opened, "h3 opens the A.5 packet, so a short header protects five bits, not four" +
                   (why.empty() ? std::string() : (": " + why)));
  c.eq_u64(h3_header.packet_number, 654360564, "the A.5 packet number decodes to the RFC's value");
  c.eq_u64(h3_header.payload.size(), 1, "the A.5 payload is the single PING byte");
  c.eq_u64(h3_header.payload.empty() ? 0 : static_cast<u64>(h3_header.payload[0]), 0x01,
           "and that byte is 0x01");
  c.eq_hex(h3_header.header, "4200bff4", "the unprotected header matches the RFC");

  why.clear();
  QuicShortHeader qk_header;
  Bytes qk_payload;
  const bool cross = quic_open_short(keys, packet, 0, 654360563, &qk_header, &qk_payload, &why);
  c.ok(cross, "the key-log opener agrees on the same packet" +
                  (why.empty() ? std::string() : (": " + why)));
  c.eq_u64(qk_header.packet_number, 654360564, "both openers reconstruct the same packet number");
  c.eq_hex(qk_payload, "01", "both openers return the same plaintext");

  why.clear();
  Bytes resealed;
  const Bytes replacement(1, 0x01);
  const bool same = quic_reseal_same_pn(keys, packet, replacement, &resealed, &why, 654360563);
  c.ok(same, "an equal-length rewrite re-seals the A.5 packet" +
                 (why.empty() ? std::string() : (": " + why)));
  c.eq_u64(resealed.size(), sizeof(a5_packet), "and the packet keeps its exact length");
  c.eq_hex(resealed, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
           "re-sealing the original plaintext reproduces the RFC bytes");

  why.clear();
  const Bytes too_long(2, 0x01);
  c.ok(!quic_reseal_same_pn(keys, packet, too_long, &resealed, &why, 654360563),
       "a longer plaintext is refused instead of moving the packet number");
}

/// The writer side of HTTP/3: QPACK with the static table only.  The heavy
/// lifting lives in h3_write_selfcheck(), which walks the RFC 9204 B.1 and
/// RFC 7541 C.4 vectors byte for byte; here we only make sure it is wired into
/// the suite and that a round trip through our own reader still works.
/// Rewriting a request inside a 1-RTT datagram without moving the packet
/// number: the heavy lifting lives in quic_rewrite_selfcheck().
void test_quic_rewrite(Ctx& c) {
  c.section("quic: same-length rewrite");
  std::string report;
  c.ok(quic_rewrite_selfcheck(&report),
       "a request can be edited inside a datagram that keeps its length");
  if (c.verbose) c.log += report;
}

void test_h3write(Ctx& c) {
  c.section("http/3 writer");
  std::string why;
  c.ok(h3_write_selfcheck(&why), "the QPACK writer agrees with the RFC vectors" + why);
  std::vector<H3Field> fields;
  H3Field method;
  method.name = ":method";
  method.value = "GET";
  fields.push_back(method);
  H3Field path;
  path.name = ":path";
  path.value = "/index.html";
  fields.push_back(path);
  std::string encoded;
  c.ok(qpack_encode_field_section(fields, QpackHuffman::kNever, &encoded, &why),
       "a field section encodes" + why);
  c.ok(!encoded.empty(), "and it is not empty");
  std::vector<std::pair<std::string, std::string>> decoded;
  c.ok(h3_decode_field_section(reinterpret_cast<const u8*>(encoded.data()), encoded.size(),
                               &decoded, &why),
       "our reader decodes what the writer produced" + why);
  c.eq_u64(decoded.size(), 2, "both fields survive the round trip");
}

void test_h3(Ctx& c) {
  c.section("http/3: 1-RTT keys, QPACK and a request line");
  std::string report;
  c.ok(h3_selfcheck(&report), "h3_selfcheck passes: " + report);

  const auto from_hex = [](const std::string& hex) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
      out.push_back(static_cast<u8>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
  };

  // RFC 9204 B.1's own :path, with :method/:scheme/:authority built here.
  const Bytes stream =
      from_hex("0001250000d1510b2f696e6465782e68746d6c500b6578616d706c652e636f6d5f08056874747073");
  H3Request req;
  std::string err;
  c.ok(h3_request_from_stream(stream, true, &req, &err), "the sample request stream decodes: " + err);
  c.eq_str(req.method, "GET", "the method is GET");
  c.eq_str(req.scheme, "https", "the scheme is https");
  c.eq_str(req.authority, "example.com", "the authority is example.com");
  c.eq_str(req.path, "/index.html", "the path is RFC 9204 B.1's own :path");
  c.ok(req.has_pseudo, "all four pseudo-headers were seen");

  // Anything that needs the dynamic QPACK table has to be refused by name: a
  // silent guess here would hand the rule engine a wrong URL.
  const Bytes dynamic = from_hex("0001020100");
  H3Request bad;
  err.clear();
  c.ok(!h3_request_from_stream(dynamic, true, &bad, &err), "a dynamic table reference is refused");
  c.ok(err.find("dynamic table") != std::string::npos, "the error names the dynamic table");

  // A 1-RTT packet is not an Initial, and must never be read as one.
  const Bytes short_header = from_hex("4200bff4");
  std::string sni, alpn;
  err.clear();
  c.ok(!quic_parse_initial(short_header.data(), short_header.size(), &sni, &alpn, &err),
       "a short header packet is refused by the Initial parser");
}

void test_http2(Ctx& c) {
  c.section("hpack: static table and RFC 7541 vectors");
  {
    HpackDecoder d;
    std::vector<H2HeaderField> f;
    std::string err;
    const u8 get[] = {0x82};
    c.ok(d.decode(get, 1, &f, &err), "the indexed :method GET decodes");
    c.eq_u64(f.size(), 1, "one field");
    c.eq_str(f.empty() ? "" : f[0].name, ":method", "the field name");
    c.eq_str(f.empty() ? "" : f[0].value, "GET", "the field value");
    f.clear();
    const u8 status[] = {0x88};
    c.ok(d.decode(status, 1, &f, &err), ":status 200 decodes from the static table");
    c.eq_str(f.empty() ? "" : f[0].value, "200", "the status value");

    // RFC 7541 C.3.1
    d.reset();
    f.clear();
    const u8 c31[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a',
                      'm',  'p',  'l',  'e',  '.',  'c',  'o', 'm'};
    c.ok(d.decode(c31, sizeof(c31), &f, &err), "RFC 7541 C.3.1 decodes");
    c.eq_u64(f.size(), 4, "C.3.1 yields four fields");
    c.eq_str(f.size() == 4 ? f[3].name : "", ":authority", "C.3.1 authority name");
    c.eq_str(f.size() == 4 ? f[3].value : "", "www.example.com", "C.3.1 authority value");
    c.eq_u64(d.table_entries(), 1, "C.3.1 added one dynamic entry");
    c.ok(!d.used_huffman(), "C.3.1 is not Huffman coded");

    // RFC 7541 C.3.2: 0xbe is dynamic index 62, the entry C.3.1 just added.
    f.clear();
    const u8 c32[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e'};
    c.ok(d.decode(c32, sizeof(c32), &f, &err), "RFC 7541 C.3.2 decodes");
    c.eq_u64(f.size(), 5, "C.3.2 yields five fields");
    c.eq_str(f.size() == 5 ? f[1].value : "", "http", "C.3.2 scheme");
    c.eq_str(f.size() == 5 ? f[3].value : "", "www.example.com", "C.3.2 reuses the dynamic entry");
    c.eq_str(f.size() == 5 ? f[4].name : "", "cache-control", "C.3.2 trailer name");
    c.eq_str(f.size() == 5 ? f[4].value : "", "no-cache", "C.3.2 trailer value");
    c.ok(d.used_dynamic_table(), "the dynamic table was used");
    c.eq_u64(d.table_entries(), 2, "two dynamic entries");

    // RFC 7541 C.3.3 continues with the dynamic table built by C.3.1/C.3.2.
    f.clear();
    const u8 c33[] = {0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-',
                      'k',  'e',  'y',  0x0c, 'c',  'u',  's', 't', 'o', 'm', '-', 'v', 'a',
                      'l',  'u',  'e'};
    c.ok(d.decode(c33, sizeof(c33), &f, &err), "RFC 7541 C.3.3 decodes");
    c.eq_u64(f.size(), 5, "C.3.3 yields five fields");
    c.eq_str(f.size() == 5 ? f[2].value : "", "/index.html", "C.3.3 path");
    c.eq_str(f.size() == 5 ? f[4].name : "", "custom-key", "C.3.3 custom name");
    c.eq_str(f.size() == 5 ? f[4].value : "", "custom-value", "C.3.3 custom value");
  }

  c.section("hpack: Huffman coded strings");
  {
    HpackDecoder d;
    std::vector<H2HeaderField> f;
    std::string err;
    const Bytes block = h2_request_block();
    c.ok(d.decode(block.data(), block.size(), &f, &err), "RFC 7541 C.4.1 decodes");
    c.eq_u64(f.size(), 4, "C.4.1 yields four fields");
    c.eq_str(f.size() == 4 ? f[3].value : "", "www.example.com", "the Huffman authority");
    c.ok(d.used_huffman(), "Huffman coding was detected");
    f.clear();
    const u8 c42[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    c.ok(d.decode(c42, sizeof(c42), &f, &err), "RFC 7541 C.4.2 decodes");
    c.eq_u64(f.size(), 5, "C.4.2 yields five fields");
    c.eq_str(f.size() == 5 ? f[4].value : "", "no-cache", "the Huffman cache-control value");
    c.ok(d.describe().find("HPACK") != std::string::npos, "describe() names HPACK");
  }

  c.section("hpack: the Huffman row for '>' really is the twelve bit code");
  {
    // RFC 7541 Appendix B gives '>' as (4091, 12) = 1111 1111 1011. This table
    // once carried (0x00ff, 8) for it. An eight bit 11111111 is the prefix of
    // about a hundred and fifty other codes, so every '>' inside a Huffman
    // string decoded as one extra symbol and shifted the rest of the string --
    // including HTTP/2 requests, which is where it was finally noticed.
    HpackDecoder d;
    std::vector<H2HeaderField> f;
    std::string err;
    // Literal header field, new name "x", Huffman value ">a":
    // '>' = 111111111011 (12 bits), 'a' = 00011 (5 bits), padded with ones.
    const u8 block[] = {0x00, 0x01, 'x', 0x83, 0xff, 0xb1, 0xff};
    c.ok(d.decode(block, sizeof(block), &f, &err), "a Huffman value that starts with '>' decodes");
    c.eq_u64(f.size(), 1, "exactly one field came out");
    c.eq_str(f.size() == 1 ? f[0].name : "", "x", "the literal name survived");
    c.eq_str(f.size() == 1 ? f[0].value : "", ">a", "the value is '>a', not '>' plus junk");
  }

  c.section("hpack: table size updates and eviction");
  {
    HpackDecoder d;
    std::vector<H2HeaderField> f;
    std::string err;
    c.eq_u64(d.max_size(), 4096, "the default dynamic table size");
    const u8 update[] = {0x3f, 0xe1, 0x1f};  // RFC 7541 C.5.1: 4096 with a five bit prefix
    c.ok(d.decode(update, sizeof(update), &f, &err), "a dynamic table size update decodes");
    c.eq_u64(d.max_size(), 4096, "the table size stayed 4096");
    const u8 zero[] = {0x20};
    c.ok(d.decode(zero, 1, &f, &err), "a size update to zero decodes");
    c.eq_u64(d.max_size(), 0, "the table is now zero sized");
    HpackDecoder e;
    e.set_max_allowed(100);
    const u8 add[] = {0x40, 0x01, 'a', 0x01, 'b'};
    c.ok(e.decode(add, sizeof(add), &f, &err), "a small literal decodes");
    c.eq_u64(e.table_entries(), 1, "one entry in the table");
    c.eq_u64(e.table_bytes(), 34, "the entry size includes the 32 byte overhead");
    c.ok(e.decode(zero, 1, &f, &err), "shrinking the table decodes");
    c.eq_u64(e.table_entries(), 0, "shrinking evicted every entry");
    c.eq_u64(e.max_allowed(), 100, "the negotiated limit is remembered");
  }

  c.section("hpack: malformed blocks");
  {
    HpackDecoder d;
    std::vector<H2HeaderField> f;
    std::string err;
    const u8 bad_index[] = {0xbe};
    c.ok(!d.decode(bad_index, 1, &f, &err), "an index beyond the table is refused");
    c.ok(err.find("dynamic table") != std::string::npos, "the error names the dynamic table");
    err.clear();
    const u8 trunc[] = {0x41, 0x20, 'a'};
    c.ok(!d.decode(trunc, sizeof(trunc), &f, &err), "a string past the block end is refused");
    err.clear();
    HpackDecoder e;
    e.set_max_allowed(0);
    const u8 big[] = {0x3f, 0xe1, 0x1f};
    c.ok(!e.decode(big, sizeof(big), &f, &err),
         "a table size above the negotiated limit is refused");
    c.ok(err.find("limit") != std::string::npos, "the error mentions the limit");
    err.clear();
    const u8 bad_huff[] = {0x00, 0x81, 0x00};
    c.ok(!d.decode(bad_huff, sizeof(bad_huff), &f, &err), "bad Huffman padding is refused");
    c.ok(err.find("huffman") != std::string::npos, "the error mentions Huffman");
  }

  c.section("http/2: frames and a full exchange");
  {
    H2Connection h;
    c.ok(!h.is_http2(), "a fresh connection is not confirmed");
    const Bytes pre = tls_text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    h.feed(0, pre.data(), pre.size(), 1);
    c.ok(h.preface_seen(), "the client preface is recognised");
    c.ok(!h.is_http2(), "the preface alone does not confirm HTTP/2");

    const Bytes settings =
        h2_frame(H2_SETTINGS, 0, 0, h2_setting_bytes(H2_SETTING_MAX_FRAME_SIZE, 16384));
    h.feed(0, settings.data(), settings.size(), 2);
    c.ok(h.is_http2(), "a SETTINGS frame confirms HTTP/2");
    c.eq_u64(h.stats().settings_frames, 1, "one SETTINGS frame");
    c.eq_u64(h.frames().size(), 1, "one frame recorded");
    c.eq_str(h.frames()[0].note, "1 setting(s)", "the SETTINGS note");
    c.eq_u64(h.frames()[0].settings_id, H2_SETTING_MAX_FRAME_SIZE, "the first setting id");
    c.eq_u64(h.frames()[0].settings_value, 16384, "the first setting value");

    const Bytes req = h2_request_block();
    const Bytes headers = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, req);
    h.feed(0, headers.data(), headers.size(), 3);
    c.eq_u64(h.stats().header_frames, 1, "one HEADERS frame");
    c.eq_u64(h.messages().size(), 1, "one stream");
    c.eq_u64(h.messages()[0].stream_id, 1, "stream 1");
    c.ok(h.messages()[0].is_request, "the stream is a request");
    c.eq_str(h.messages()[0].method, "GET", "the method");
    c.eq_str(h.messages()[0].path, "/", "the path");
    c.eq_str(h.messages()[0].authority, "www.example.com", "the authority");
    c.eq_str(h.messages()[0].scheme, "http", "the scheme");
    c.ok(h.messages()[0].request_complete, "END_STREAM closed the request");
    c.eq_u64(h.messages()[0].request_headers.size(), 4, "four request header fields");
    c.ok(h.stats().huffman_used, "the connection noted Huffman coding");

    const Bytes ack = h2_frame(H2_SETTINGS, H2_FLAG_ACK, 0, Bytes());
    h.feed(1, ack.data(), ack.size(), 4);
    c.ok(h.frames().back().ack, "the SETTINGS ack is flagged");
    c.eq_str(h.frames().back().note, "acknowledged", "the ack note");

    const Bytes rsp = h2_response_block();
    const Bytes rheaders = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, rsp);
    h.feed(1, rheaders.data(), rheaders.size(), 5);
    const Bytes body = tls_text("hello");
    const Bytes data = h2_frame(H2_DATA, H2_FLAG_END_STREAM, 1, body);
    h.feed(1, data.data(), data.size(), 6);
    c.eq_str(h.messages()[0].status, "200", "the response status");
    c.eq_str(h.messages()[0].content_type, "text/plain", "the response content type");
    c.eq_u64(h.messages()[0].response_headers.size(), 2, "two response header fields");
    c.ok(h.messages()[0].response_complete, "the DATA frame ended the response");
    c.eq_str(text_of(h.messages()[0].response_body), "hello", "the response body");
    c.eq_u64(h.messages()[0].response_body_bytes, 5, "the body byte count");
    c.eq_u64(h.messages()[0].summary().find("GET / -> 200"), 0, "the summary line");
    c.eq_u64(h.stats().data_frames, 1, "one DATA frame");
    c.eq_u64(h.stats().body_bytes, 5, "five body bytes");
    c.eq_u64(h.stats().streams, 1, "one stream counted");

    Bytes wu_payload(4, 0);
    wr32be(wu_payload.data(), 1024);
    const Bytes wu = h2_frame(H2_WINDOW_UPDATE, 0, 0, wu_payload);
    h.feed(1, wu.data(), wu.size(), 7);
    c.eq_u64(h.frames().back().increment, 1024, "the window increment");
    Bytes goaway_payload(8, 0);
    wr32be(goaway_payload.data(), 1);
    wr32be(goaway_payload.data() + 4, 0);
    const Bytes goaway = h2_frame(H2_GOAWAY, 0, 0, goaway_payload);
    h.feed(1, goaway.data(), goaway.size(), 8);
    c.eq_u64(h.stats().goaway_frames, 1, "one GOAWAY frame");
    c.ok(h.frames().back().note.find("NO_ERROR") != std::string::npos, "the GOAWAY reason");
    c.ok(h.describe().find("HTTP/2") != std::string::npos, "describe() names HTTP/2");
    c.ok(h.describe().find("huffman") != std::string::npos, "describe() mentions Huffman");
  }

  c.section("http/2: continuation, padding and priority");
  {
    H2Connection h;
    const Bytes pre = tls_text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    h.feed(0, pre.data(), pre.size(), 1);
    const Bytes req = h2_request_block();
    // The header block arrives split: HEADERS without END_HEADERS, then a
    // CONTINUATION frame that finishes it.
    const Bytes head = h2_frame(H2_HEADERS, 0, 1, Bytes(req.begin(), req.begin() + 4));
    h.feed(0, head.data(), head.size(), 2);
    c.eq_u64(h.messages().size(), 0, "an incomplete header block is not decoded yet");
    const Bytes cont_payload(req.begin() + 4, req.end());
    const Bytes cont = h2_frame(H2_CONTINUATION, H2_FLAG_END_HEADERS, 1, cont_payload);
    h.feed(0, cont.data(), cont.size(), 3);
    c.eq_u64(h.stats().continuation_frames, 1, "one CONTINUATION frame");
    c.eq_u64(h.messages().size(), 1, "the stream appears after CONTINUATION");
    c.eq_str(h.messages()[0].method, "GET", "the method from the split block");
    c.eq_u64(h.frames().back().headers.size(), 4, "the CONTINUATION frame carries the fields");

    H2Connection g;
    g.feed(0, pre.data(), pre.size(), 1);
    Bytes payload;
    payload.push_back(3);  // pad length
    for (int i = 0; i < 5; ++i) payload.push_back(0);  // priority fields
    const Bytes block = h2_request_block();
    payload.insert(payload.end(), block.begin(), block.end());
    payload.insert(payload.end(), 3, 0);  // the padding itself
    const Bytes padded =
        h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_PADDED | H2_FLAG_PRIORITY, 1, payload);
    g.feed(0, padded.data(), padded.size(), 2);
    c.eq_u64(g.messages().size(), 1, "the padded HEADERS frame decodes");
    c.eq_str(g.messages()[0].authority, "www.example.com", "the authority of the padded frame");
    c.ok(g.frames().back().padded, "the frame is marked as padded");
    const Bytes rsp = h2_response_block();
    const Bytes rh = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, rsp);
    g.feed(1, rh.data(), rh.size(), 3);
    c.eq_str(g.messages()[0].status, "200", "the response status after priority decoding");
  }

  c.section("http/2: split feeds, settings limits and rejection");
  {
    H2Connection h;
    const Bytes pre = tls_text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    const Bytes req = h2_request_block();
    const Bytes frame = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, req);
    Bytes all = pre;
    all.insert(all.end(), frame.begin(), frame.end());
    for (std::size_t i = 0; i + 1 < all.size(); ++i) h.feed(0, all.data() + i, 1, i64(i));
    c.eq_u64(h.messages().size(), 0, "a partial frame produces nothing");
    h.feed(0, all.data() + all.size() - 1, 1, 999);
    c.eq_u64(h.messages().size(), 1, "the frame completes on the final byte");
    c.ok(h.preface_seen(), "the preface was assembled byte by byte");

    H2Connection s;
    s.feed(0, pre.data(), pre.size(), 1);
    const Bytes small =
        h2_frame(H2_SETTINGS, 0, 0, h2_setting_bytes(H2_SETTING_HEADER_TABLE_SIZE, 512));
    s.feed(0, small.data(), small.size(), 2);
    c.eq_u64(s.decoder(0).max_allowed(), 512, "the decoder honours the announced table size");
    c.eq_u64(s.decoder(1).max_allowed(), 4096, "the other direction is unaffected");
    const u8 bad_update[] = {0x3f, 0xe1, 0x1f, 0x82};
    const Bytes bad =
        h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, Bytes(bad_update, bad_update + sizeof(bad_update)));
    s.feed(0, bad.data(), bad.size(), 3);
    c.eq_u64(s.stats().decode_errors, 1, "a table size above the limit is a decode error");
    c.ok(s.stats().last_error.find("limit") != std::string::npos, "the error mentions the limit");
    c.ok(s.messages()[0].note.find("limit") != std::string::npos, "the stream carries the error");

    H2Connection t;
    t.feed(0, pre.data(), pre.size(), 1);
    t.feed(0, small.data(), small.size(), 2);
    const u8 ok_update[] = {0x20, 0x82};  // table size 0, then :method GET
    const Bytes ok = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, Bytes(ok_update, ok_update + 2));
    t.feed(0, ok.data(), ok.size(), 3);
    c.eq_u64(t.stats().decode_errors, 0, "a table size within the limit is accepted");
    c.eq_u64(t.stats().header_table_size, 0, "the announced table size is reported");
    c.eq_str(t.messages().size() == 1 ? t.messages()[0].method : "", "GET",
             "the header after the size update");

    H2Connection r;
    const std::string http1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    r.feed(0, reinterpret_cast<const u8*>(http1.data()), http1.size(), 1);
    c.ok(r.rejected(), "plain HTTP/1.1 is rejected");
    c.ok(!r.is_http2(), "the connection is not HTTP/2");
    c.ok(r.error().find("preface") != std::string::npos, "the reason is the missing preface");
    c.eq_u64(r.messages().size(), 0, "no streams are invented");

    H2Connection u;
    u.feed(0, pre.data(), pre.size(), 1);
    const Bytes unknown = h2_frame(0x2f, 0, 0, Bytes());
    u.feed(0, unknown.data(), unknown.size(), 2);
    c.eq_u64(u.stats().unknown_frames, 1, "an unknown frame type is counted");
    c.ok(u.is_http2(), "an unknown frame does not break the connection");
    c.eq_str(u.frames().back().note, "unknown frame type", "the unknown frame note");
  }
}


void test_analyze(Ctx& c) {
  c.section("analyze: reassembly, decryption and HTTP extraction");
  const std::string path = "netcap_selftest_analyze.pcap";
  const std::string kpath = sample_keylog_path(path);
  c.eq_str(kpath, "netcap_selftest_analyze.keys", "the key log path follows the capture");
  int written = 0;
  std::string err;
  c.eq_u64(write_sample_pcap(path, &written, &err), 0, "the sample capture is written");
  c.eq_u64(written, 25, "the sample capture holds 25 packets");

  auto keys = std::make_shared<KeyLogStore>();
  c.ok(keys->load_file(kpath, &err), "the generated key log loads");
  c.eq_u64(keys->size(), 4, "four secrets in the key log");

  PcapReader r;
  c.ok(r.open(path, &err), "the capture reads back");
  Dissector d;
  d.set_reassembly(true);
  Analyzer a;
  a.set_keylog(keys);
  int n = 0;
  for (Packet p; r.next(p);) {
    PacketInfo pi;
    d.dissect(p.view(), pi);
    a.feed(pi, p.ts_us);
    ++n;
  }
  a.finish();
  c.eq_u64(n, 25, "every packet was read and analysed");
  c.ok(a.stats().keys_loaded, "the analyser knows it has keys");
  c.eq_u64(a.stats().keylog_entries, 4, "the analyser reports the key log size");

  const StreamReport* https = nullptr;
  for (const StreamReport& s : a.streams()) {
    if (s.sni == "secure.example.com") https = &s;
  }
  c.ok(https != nullptr, "the HTTPS stream is reported");
  if (https) {
    c.ok(https->tls, "the stream is TLS");
    c.ok(https->decrypted, "the stream was decrypted");
    c.eq_str(https->protocol(), "HTTPS/1.1", "the stream protocol");
    c.eq_u64(https->tls_version, 0x0304, "the negotiated TLS version");
    c.eq_u64(https->cipher_suite, 0x1301, "the negotiated cipher suite");
    c.eq_str(https->alpn, "http/1.1", "the negotiated ALPN");
    c.eq_u64(https->transactions, 1, "one HTTP transaction on the stream");
    c.ok(https->out_of_order > 0 || https->gaps > 0, "the split segment was seen out of order");
    c.ok(https->plaintext_bytes >= std::strlen(kHttpsRequest) + std::strlen(kHttpsResponse),
         "both directions contributed plaintext");
    c.ok(https->describe().find("secure.example.com") != std::string::npos,
         "describe() names the stream");
  }

  // Regression guard: a plaintext HTTP/1.1 flow must be classified as HTTP. It
  // used to be mistaken for TLS because its first payload is longer than a record
  // header and the record parser accepted any five bytes.
  const StreamReport* http80 = nullptr;
  for (const StreamReport& s : a.streams()) {
    if (s.server_endpoint.port == 80) http80 = &s;
  }
  c.ok(http80 != nullptr, "the plaintext HTTP stream is reported");
  if (http80) {
    c.ok(!http80->tls, "the plaintext stream is not TLS");
    c.eq_str(http80->protocol(), "HTTP/1.1", "the plaintext stream is HTTP/1.1");
    c.eq_u64(http80->transactions, 1, "one transaction on the plaintext stream");
  }
  const HttpRecord* plain_rec = nullptr;
  for (const HttpRecord& h : a.http()) {
    if (h.host == "example.com") plain_rec = &h;
  }
  c.ok(plain_rec != nullptr, "the plaintext HTTP transaction is reported");
  if (plain_rec) {
    c.ok(!plain_rec->decrypted, "the plaintext transaction is not decrypted");
    c.eq_str(plain_rec->method, "GET", "the plaintext method");
    c.eq_str(plain_rec->target, "/index.html", "the plaintext target");
    c.eq_u64(plain_rec->status, 200, "the plaintext status");
  }

  const HttpRecord* rec = nullptr;
  for (const HttpRecord& h : a.http()) {
    if (h.host == "secure.example.com") rec = &h;
  }
  c.ok(rec != nullptr, "the decrypted transaction is reported");
  if (rec) {
    c.ok(rec->decrypted, "the transaction came out of a decrypted stream");
    c.ok(!rec->http2, "it is HTTP/1.1");
    c.eq_str(rec->method, "GET", "the method");
    c.eq_str(rec->target, "/secure", "the target");
    c.eq_u64(rec->status, 200, "the status code");
    c.eq_str(rec->content_type, "text/plain", "the content type");
    c.ok(rec->transport().find("decrypted") != std::string::npos,
         "the transport reports decryption");
    c.ok(rec->status_line().find("200") != std::string::npos, "the status line");
    c.ok(rec->url().find("secure.example.com") != std::string::npos, "the URL");
    c.ok(rec->request_complete && rec->response_complete, "both halves finished");
    c.ok(rec->summary().find("GET") != std::string::npos, "the summary line");
  }
  c.ok(a.stats().decrypted_streams >= 1, "the stats count the decrypted stream");
  c.ok(a.stats().decrypted_transactions >= 1, "the stats count the decrypted transaction");
  c.ok(a.stats().reassembled_bytes > 0, "the stats count reassembled bytes");
  c.ok(a.describe().find("decrypted") != std::string::npos, "describe() mentions decryption");

  // Without the key log the same capture yields the same streams, but nothing
  // decrypted.
  PcapReader r2;
  c.ok(r2.open(path, &err), "the capture opens a second time");
  Analyzer plain;
  for (Packet p; r2.next(p);) {
    PacketInfo pi;
    d.dissect(p.view(), pi);
    plain.feed(pi, p.ts_us);
  }
  plain.finish();
  c.eq_u64(plain.stats().decrypted_streams, 0, "without a key log nothing is decrypted");
  c.eq_u64(plain.stats().transactions, 1, "the plaintext HTTP transaction needs no keys");
  bool saw_tls = false;
  for (const StreamReport& s : plain.streams()) {
    if (s.sni == "secure.example.com") saw_tls = s.tls;
  }
  c.ok(saw_tls, "the TLS stream is still reported without keys");

  // ---------------------------------------------------------------------
  // The same chain for HTTP/2. HPACK and the frame layer are unit-tested
  // above; this proves that encrypted h2 bytes survive TCP reassembly, TLS
  // decryption and the analyzer, and come out as one transaction.
  // ---------------------------------------------------------------------
  {
    const Bytes cr2 = tls_seq_bytes(0x77, 32);
    const Bytes c_hs2 = tls_seq_bytes(0x88, 32);
    const Bytes s_hs2 = tls_seq_bytes(0x99, 32);
    const Bytes c_ap2 = tls_seq_bytes(0xaa, 32);
    const Bytes s_ap2 = tls_seq_bytes(0xbb, 32);

    const std::string h2keys = "netcap_selftest_h2.keys";
    {
      std::FILE* f = std::fopen(h2keys.c_str(), "wb");
      c.ok(f != nullptr, "the HTTP/2 key log is writable");
      if (f) {
        const std::string cr_hex = to_hex(cr2);
        std::string text;
        text += "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + cr_hex + " " + to_hex(c_hs2) + "\n";
        text += "SERVER_HANDSHAKE_TRAFFIC_SECRET " + cr_hex + " " + to_hex(s_hs2) + "\n";
        text += "CLIENT_TRAFFIC_SECRET_0 " + cr_hex + " " + to_hex(c_ap2) + "\n";
        text += "SERVER_TRAFFIC_SECRET_0 " + cr_hex + " " + to_hex(s_ap2) + "\n";
        std::fwrite(text.data(), 1, text.size(), f);
        std::fclose(f);
      }
    }

    std::vector<Packet> h2pkts;
    i64 t2 = kBaseTs;
    u32 c2seq = 0x33330000;
    u32 s2seq = 0x44440000;
    auto c2 = [&](std::vector<u8> tcp, i64 dt) {
      add(h2pkts,
          eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                    ipv4_packet({.src = "10.0.0.7", .dst = "151.101.1.69", .proto = 6, .ttl = 64,
                                 .id = 0x5500, .df = true},
                                std::move(tcp))),
          t2 += dt);
    };
    auto s2 = [&](std::vector<u8> tcp, i64 dt) {
      add(h2pkts,
          eth_frame("00:11:22:33:44:55", "52:54:00:12:34:56", 0x0800,
                    ipv4_packet({.src = "151.101.1.69", .dst = "10.0.0.7", .proto = 6, .ttl = 55,
                                 .id = 0x6600, .df = true},
                                std::move(tcp))),
          t2 += dt);
    };

    c2(tcp_segment(53000, 443, c2seq, 0, TCP_SYN, 64240, {}, 1460), 100);
    ++c2seq;
    s2(tcp_segment(443, 53000, s2seq, c2seq, TCP_SYN | TCP_ACK, 65535, {}, 1460), 120);
    ++s2seq;
    c2(tcp_segment(53000, 443, c2seq, s2seq, TCP_ACK, 64240, {}), 50);

    {  // ClientHello advertising h2
      const Bytes rec = tls_handshake_record(
          1, tls_hello_body("h2.example.com", {0x1301}, false, 0, cr2, true, "h2"));
      c2(tcp_segment(53000, 443, c2seq, s2seq, TCP_PSH | TCP_ACK, 64240, rec), 150);
      c2seq += u32(rec.size());
    }
    {  // ServerHello + CCS + EncryptedExtensions
      Bytes payload =
          tls_handshake_record(2, tls_hello_body("", {}, true, 0x1301, sample_server_random(), true, "h2"));
      const Bytes ccs = tls_record(20, 0x0303, Bytes{1});
      payload.insert(payload.end(), ccs.begin(), ccs.end());
      const Bytes ee =
          tls13_seal(s_hs2, 0, 22, tls_handshake_message(8, Bytes{0, 0, 0, 0}), 0x1301, false, false);
      payload.insert(payload.end(), ee.begin(), ee.end());
      s2(tcp_segment(443, 53000, s2seq, c2seq, TCP_PSH | TCP_ACK, 65535, payload), 210);
      s2seq += u32(payload.size());
    }
    {  // preface + SETTINGS + request HEADERS, sealed with the application key
      Bytes plain = tls_text("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
      const Bytes settings = h2_frame(H2_SETTINGS, 0, 0, Bytes());
      plain.insert(plain.end(), settings.begin(), settings.end());
      const Bytes headers =
          h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, h2_request_block());
      plain.insert(plain.end(), headers.begin(), headers.end());
      const Bytes rec = tls13_seal(c_ap2, 0, 23, plain, 0x1301, false, false);
      c2(tcp_segment(53000, 443, c2seq, s2seq, TCP_PSH | TCP_ACK, 64240, rec), 170);
      c2seq += u32(rec.size());
    }
    {  // SETTINGS ack + response HEADERS + DATA
      Bytes plain = h2_frame(H2_SETTINGS, H2_FLAG_ACK, 0, Bytes());
      const Bytes headers = h2_frame(H2_HEADERS, H2_FLAG_END_HEADERS, 1, h2_response_block());
      plain.insert(plain.end(), headers.begin(), headers.end());
      const Bytes data = h2_frame(H2_DATA, H2_FLAG_END_STREAM, 1, tls_text("hi"));
      plain.insert(plain.end(), data.begin(), data.end());
      const Bytes rec = tls13_seal(s_ap2, 0, 23, plain, 0x1301, false, false);
      s2(tcp_segment(443, 53000, s2seq, c2seq, TCP_PSH | TCP_ACK, 65535, rec), 230);
      s2seq += u32(rec.size());
    }
    c2(tcp_segment(53000, 443, c2seq, s2seq, TCP_FIN | TCP_ACK, 64240, {}), 90);
    s2(tcp_segment(443, 53000, s2seq, c2seq, TCP_FIN | TCP_ACK, 65535, {}), 90);

    auto keys2 = std::make_shared<KeyLogStore>();
    std::string kerr2;
    c.ok(keys2->load_file(h2keys, &kerr2), "the HTTP/2 key log loads");
    Analyzer h2;
    h2.set_keylog(keys2);
    Dissector dh;
    for (const Packet& p : h2pkts) {
      PacketInfo pi;
      dh.dissect(p.view(), pi);
      h2.feed(pi, p.ts_us);
    }
    h2.finish();

    bool saw_h2_stream = false;
    for (const StreamReport& s : h2.streams()) {
      if (s.sni == "h2.example.com") {
        saw_h2_stream = true;
        c.ok(s.tls, "the HTTP/2 connection is TLS");
        c.ok(s.decrypted, "the HTTP/2 connection decrypts");
        c.ok(s.http2, "the connection is recognised as HTTP/2");
        c.eq_str(s.protocol(), "HTTPS/2", "the HTTP/2 transport name");
        c.eq_str(s.alpn, "h2", "ALPN reports h2");
      }
    }
    c.ok(saw_h2_stream, "the HTTP/2 connection is reported");

    const HttpRecord* hrec = nullptr;
    for (const HttpRecord& r : h2.http()) {
      if (r.host == "www.example.com") hrec = &r;
    }
    c.ok(hrec != nullptr, "the HTTP/2 request is decoded");
    if (hrec) {
      c.ok(hrec->http2, "the transaction is HTTP/2");
      c.ok(hrec->decrypted, "the transaction is decrypted");
      c.eq_str(hrec->method, "GET", "the HTTP/2 method");
      c.eq_str(hrec->target, "/", "the HTTP/2 path");
      c.eq_u64(u64(hrec->status), 200, "the HTTP/2 status");
      c.eq_u64(hrec->request_body_bytes, 0, "a HEADERS-only request has no body");
      c.eq_u64(hrec->response_body_bytes, 2, "the DATA payload is counted");
      c.ok(hrec->request_complete && hrec->response_complete, "the HTTP/2 exchange finished");
      c.ok(hrec->transport().find("decrypted") != std::string::npos,
           "the HTTP/2 transport notes decryption");
    }
    c.ok(h2.stats().http2_streams >= 1, "the stats count the HTTP/2 connection");
    c.ok(h2.stats().http2_transactions >= 1, "the stats count the HTTP/2 transaction");
    std::remove(h2keys.c_str());
  }

  // ---------------------------------------------------------------------
  // Once more for TLS 1.2: the keys come from a CLIENT_RANDOM line and the
  // records use the 1.2 format (explicit nonce, no inner content type).
  // ---------------------------------------------------------------------
  {
    const Bytes cr3 = tls_seq_bytes(0xcc, 32);
    const Bytes sr3 = tls_seq_bytes(0xdd, 32);
    const Bytes master3 = tls_seq_bytes(0xee, 48);

    auto store3 = std::make_shared<KeyLogStore>();
    {
      KeyLogEntry e;
      e.label = "CLIENT_RANDOM";
      e.client_random = cr3;
      e.secret = master3;
      store3->add(e);
    }
    Bytes seed = sr3;
    seed.insert(seed.end(), cr3.begin(), cr3.end());
    const Bytes kb = tls12_prf(master3, "key expansion", seed, 2 * (0 + 16 + 4), false);
    c.eq_u64(kb.size(), 40, "the TLS 1.2 key block for AES-128-GCM");
    const Bytes client_key(kb.begin(), kb.begin() + 16);
    const Bytes server_key(kb.begin() + 16, kb.begin() + 32);
    const Bytes client_iv(kb.begin() + 32, kb.begin() + 36);
    const Bytes server_iv(kb.begin() + 36, kb.begin() + 40);

    std::vector<Packet> pkts3;
    i64 t3 = kBaseTs;
    u32 c3seq = 0x55550000;
    u32 s3seq = 0x66660000;
    auto c3 = [&](std::vector<u8> tcp, i64 dt) {
      add(pkts3,
          eth_frame("52:54:00:12:34:56", "00:11:22:33:44:55", 0x0800,
                    ipv4_packet({.src = "10.0.0.11", .dst = "10.0.0.12", .proto = 6, .ttl = 64,
                                 .id = 0x7700, .df = true},
                                std::move(tcp))),
          t3 += dt);
    };
    auto s3 = [&](std::vector<u8> tcp, i64 dt) {
      add(pkts3,
          eth_frame("00:11:22:33:44:55", "52:54:00:12:34:56", 0x0800,
                    ipv4_packet({.src = "10.0.0.12", .dst = "10.0.0.11", .proto = 6, .ttl = 64,
                                 .id = 0x8800, .df = true},
                                std::move(tcp))),
          t3 += dt);
    };

    c3(tcp_segment(54000, 80, c3seq, 0, TCP_SYN, 64240, {}, 1460), 80);
    ++c3seq;
    s3(tcp_segment(80, 54000, s3seq, c3seq, TCP_SYN | TCP_ACK, 65535, {}, 1460), 90);
    ++s3seq;
    c3(tcp_segment(54000, 80, c3seq, s3seq, TCP_ACK, 64240, {}), 40);
    {
      const Bytes rec = tls_handshake_record(
          1, tls_hello_body("gcm.example.com", {0xc02f}, false, 0, cr3, false, "http/1.1"));
      c3(tcp_segment(54000, 80, c3seq, s3seq, TCP_PSH | TCP_ACK, 64240, rec), 120);
      c3seq += u32(rec.size());
    }
    {
      const Bytes rec =
          tls_handshake_record(2, tls_hello_body("", {}, true, 0xc02f, sr3, false, "http/1.1"));
      s3(tcp_segment(80, 54000, s3seq, c3seq, TCP_PSH | TCP_ACK, 65535, rec), 140);
      s3seq += u32(rec.size());
    }
    {
      const Bytes ccs = tls_record(20, 0x0303, Bytes{1});
      c3(tcp_segment(54000, 80, c3seq, s3seq, TCP_PSH | TCP_ACK, 64240, ccs), 50);
      c3seq += u32(ccs.size());
      s3(tcp_segment(80, 54000, s3seq, c3seq, TCP_PSH | TCP_ACK, 65535, ccs), 60);
      s3seq += u32(ccs.size());
    }
    {
      const Bytes rec =
          tls12_gcm_record(client_key, client_iv, 0, 23,
                           tls_text("GET /legacy HTTP/1.1\r\nHost: gcm.example.com\r\n\r\n"));
      c3(tcp_segment(54000, 80, c3seq, s3seq, TCP_PSH | TCP_ACK, 64240, rec), 100);
      c3seq += u32(rec.size());
    }
    {
      const Bytes rec = tls12_gcm_record(
          server_key, server_iv, 0, 23,
          tls_text("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
      s3(tcp_segment(80, 54000, s3seq, c3seq, TCP_PSH | TCP_ACK, 65535, rec), 130);
      s3seq += u32(rec.size());
    }
    c3(tcp_segment(54000, 80, c3seq, s3seq, TCP_FIN | TCP_ACK, 64240, {}), 70);
    s3(tcp_segment(80, 54000, s3seq, c3seq, TCP_FIN | TCP_ACK, 65535, {}), 70);

    Analyzer a12;
    a12.set_keylog(store3);
    Dissector d12;
    for (const Packet& p : pkts3) {
      PacketInfo pi;
      d12.dissect(p.view(), pi);
      a12.feed(pi, p.ts_us);
    }
    a12.finish();

    bool saw12 = false;
    for (const StreamReport& s : a12.streams()) {
      if (s.sni == "gcm.example.com") {
        saw12 = true;
        c.ok(s.tls && s.decrypted, "the TLS 1.2 connection decrypts end to end");
        c.eq_u64(s.tls_version, 0x0303, "the connection reports TLS 1.2");
        c.eq_u64(s.cipher_suite, 0xc02f, "the connection reports its TLS 1.2 suite");
        c.eq_str(s.protocol(), "HTTPS/1.1", "HTTP/1.1 over TLS 1.2");
      }
    }
    c.ok(saw12, "the TLS 1.2 connection is reported");

    bool saw12_rec = false;
    for (const HttpRecord& r : a12.http()) {
      if (r.host == "gcm.example.com") {
        saw12_rec = true;
        c.ok(r.decrypted && !r.http2, "the TLS 1.2 transaction is decrypted HTTP/1.1");
        c.eq_str(r.method, "GET", "the TLS 1.2 request method");
        c.eq_str(r.target, "/legacy", "the TLS 1.2 request target");
        c.eq_u64(u64(r.status), 200, "the TLS 1.2 response status");
        c.eq_u64(r.response_body_bytes, 5, "the TLS 1.2 response body is counted");
        c.ok(r.request_complete && r.response_complete, "the TLS 1.2 exchange finished");
      }
    }
    c.ok(saw12_rec, "the TLS 1.2 request/response pair is reported");
    c.eq_u64(a12.stats().decrypted_streams, 1, "one decrypted TLS 1.2 stream");
  }

  // Windows refuses to delete a file while a handle still holds it open, so the
  // two readers opened above have to be closed before cleaning up; otherwise
  // every --selftest run leaves netcap_selftest_analyze.pcap behind.
  r.close();
  r2.close();
  std::remove(path.c_str());
  std::remove(kpath.c_str());
}

}  // namespace

std::string sample_keylog_path(const std::string& capture_path) {
  std::string p = capture_path;
  static const char* const kSuffixes[] = {".pcapng", ".pcap", ".cap"};
  for (const char* s : kSuffixes) {
    const std::size_t n = std::strlen(s);
    if (p.size() > n && p.compare(p.size() - n, n, s) == 0) {
      p.erase(p.size() - n);
      break;
    }
  }
  return p + ".keys";
}

int write_sample_pcap(const std::string& path, int* packets_written, std::string* error) {
  PcapWriter w;
  if (!w.open(path, DLT_EN10MB, 262144, false, error)) return -1;
  const std::vector<Packet> packets = build_sample_packets();
  for (const Packet& p : packets) {
    if (!w.write(p, error)) {
      w.close();
      return -1;
    }
  }
  if (packets_written) *packets_written = int(w.packets_written());
  w.close();

  // The key log for the HTTPS session in the capture, written beside it so the
  // traffic can be decrypted offline.
  const std::string kpath = sample_keylog_path(path);
  if (std::FILE* f = std::fopen(kpath.c_str(), "wb")) {
    const std::string text = sample_tls_keylog();
    std::fwrite(text.data(), 1, text.size(), f);
    std::fclose(f);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Process attribution
// ---------------------------------------------------------------------------

void test_proc(Ctx& c) {
  c.section("process attribution");

  // --- names ---------------------------------------------------------------
  c.eq_str(proc_sanitize_name("chrome.exe"), "chrome.exe", "a plain image name survives sanitising");
  c.eq_str(proc_sanitize_name("My App/1.0"), "My_App_1.0", "spaces and slashes become underscores");
  c.eq_str(proc_sanitize_name("..."), "unknown", "a name of only dots falls back to unknown");
  c.eq_u64(proc_sanitize_name(std::string(200, 'x')).size(), 64, "a long name is truncated to 64");

  ProcessInfo chrome;
  chrome.pid = 1234;
  chrome.name = "chrome.exe";
  chrome.key = "chrome.exe";
  c.eq_str(chrome.label(), "chrome.exe (1234)", "a named process reports name and pid");
  ProcessInfo nameless;
  nameless.pid = 77;
  c.eq_str(nameless.label(), "pid 77", "an unnamed process reports its pid");

  // --- table container (filled by injection here, by the OS in a live run) --
  u8 local_ip[16] = {0}, remote_ip[16] = {0}, any_ip[16] = {0}, other_ip[16] = {0};
  int v4 = 0;
  parse_ip("10.0.0.5", &v4, local_ip);
  parse_ip("93.184.216.34", &v4, remote_ip);
  parse_ip("10.9.9.9", &v4, other_ip);

  ProcessTable table;
  table.add_process(chrome);
  table.add_endpoint(4, local_ip, 51000, 6, 1234);
  ProcessInfo service;
  service.pid = 4242;
  service.name = "svc.exe";
  service.key = "svc.exe";
  table.add_process(service);
  table.add_endpoint(4, any_ip, 80, 6, 4242);   // a wildcard bind

  const ProcessInfo* owner = table.owner(4, local_ip, 51000, 6);
  c.ok(owner && owner->pid == 1234, "an exact local endpoint maps to its process");
  c.ok(table.owner(4, local_ip, 51000, 17) == nullptr, "TCP and UDP endpoints do not mix");
  c.ok(table.owner(4, local_ip, 51001, 6) == nullptr, "an unknown port stays unattributed");
  const ProcessInfo* wild = table.owner(4, other_ip, 80, 6);
  c.ok(wild && wild->pid == 4242, "a wildcard bind owns traffic to any local address");
  c.ok(table.by_name("CHROME.EXE") != nullptr, "process lookup by name ignores case");
  c.eq_u64(table.owners().size(), 2, "both endpoint owners are listed once each");

  PacketInfo pi;
  pi.ip_version = 4;
  pi.l4 = L4::Tcp;
  pi.has_ports = true;
  std::memcpy(pi.src_ip, local_ip, 16);
  std::memcpy(pi.dst_ip, remote_ip, 16);
  pi.src_port = 51000;
  pi.dst_port = 443;
  int dir = -1;
  const ProcessInfo* who = table.owner_of(pi, &dir);
  c.ok(who && who->pid == 1234 && dir == 0, "an outbound packet is owned by its local source");
  PacketInfo inbound = pi;
  std::memcpy(inbound.src_ip, remote_ip, 16);
  std::memcpy(inbound.dst_ip, local_ip, 16);
  inbound.src_port = 443;
  inbound.dst_port = 51000;
  dir = -1;
  who = table.owner_of(inbound, &dir);
  c.ok(who && who->pid == 1234 && dir == 1, "an inbound packet is owned by its local destination");
  PacketInfo portless = pi;
  portless.has_ports = false;
  c.ok(table.owner_of(portless, nullptr) == nullptr, "a packet without ports is not attributed");

  // --- per-flow memory -----------------------------------------------------
  ProcAttributor attributor;
  attributor.set_table(&table);   // injected: the caller owns table refreshes
  ProcAttrConfig cfg;
  cfg.table_ttl_us = 3600LL * 1000000;   // pretend a fresh table for the whole test
  attributor.set_config(cfg);

  const ProcOwnership& first = attributor.attribute(pi, 0);
  c.ok(first.known && first.proc.pid == 1234 && first.dir == 0, "the first packet is looked up");
  c.ok(!first.from_cache, "the first packet was not answered from memory");
  const ProcOwnership& second = attributor.attribute(pi, 0);
  c.ok(second.known && second.proc.pid == 1234 && second.from_cache,
       "the next packet of the same flow comes from memory");
  c.eq_u64(attributor.cache_hits(), 1, "flow memory counted one hit");
  c.eq_u64(attributor.hits(), 2, "both packets counted as hits");

  PacketInfo stranger = pi;
  stranger.src_port = 51888;
  const ProcOwnership& miss = attributor.attribute(stranger, 0);
  c.ok(!miss.known && miss.why != nullptr && *miss.why != '\0',
       "an unattributed packet carries a reason");
  c.eq_u64(attributor.misses(), 1, "the miss was counted");

  attributor.set_enabled(false);
  c.ok(!attributor.attribute(pi, 0).known, "attribution can be switched off");
  attributor.set_enabled(true);
  attributor.clear_cache();
  c.eq_u64(attributor.cache_size(), 0, "the flow memory can be cleared");

  // --- per-process counters ------------------------------------------------
  ProcessInfo firefox;
  firefox.pid = 4321;
  firefox.name = "firefox.exe";
  ProcTotals totals;
  totals.add_packet(chrome, 100);
  totals.add_packet(chrome, 50);
  totals.add_flow(chrome);
  totals.add_packet(firefox, 400);
  totals.add_transaction(firefox);
  totals.add_decrypted_stream(firefox);
  c.eq_u64(totals.size(), 2, "two processes are tracked");
  c.eq_u64(totals.total_bytes(), 550, "byte totals add up");
  c.eq_u64(totals.total_packets(), 3, "packet totals add up");
  const std::vector<ProcCounters> ranked = totals.sorted();
  c.ok(ranked.size() == 2 && ranked[0].name == "firefox.exe", "the heaviest process sorts first");
  c.ok(ranked.size() == 2 && ranked[0].decrypted_streams == 1, "per-process detail is kept");
  totals.clear();
  c.ok(totals.empty(), "the counters can be cleared");

  // --- platform availability ----------------------------------------------
  std::string note;
  const bool available = proc_attribution_available(&note);
  c.ok(!note.empty(), "the platform explains how attribution is implemented");
  c.ok(!proc_platform_note().empty(), "the platform reports its mechanism");
#ifdef _WIN32
  c.ok(available, "Windows can attribute packets to processes");
#else
  c.ok(!available, "this platform reports attribution as unavailable");
#endif

#ifdef _WIN32
  // --- the real thing ------------------------------------------------------
  // One loopback connection, then ask the OS endpoint table who owns the local
  // socket.  This is the check that proves the table rows are walked at the
  // right offsets: a wrong offset cannot produce our own PID for our own port.
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool bound = srv != INVALID_SOCKET && bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
                 listen(srv, 1) == 0;
    int listen_port = 0;
    if (bound) {
      sockaddr_in me;
      std::memset(&me, 0, sizeof(me));
      int me_len = int(sizeof(me));
      if (getsockname(srv, reinterpret_cast<sockaddr*>(&me), &me_len) == 0)
        listen_port = ntohs(me.sin_port);
    }
    SOCKET cli = INVALID_SOCKET;
    if (bound && listen_port != 0) {
      cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      sockaddr_in dst;
      std::memset(&dst, 0, sizeof(dst));
      dst.sin_family = AF_INET;
      dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      dst.sin_port = htons(static_cast<u_short>(listen_port));
      if (cli != INVALID_SOCKET &&
          connect(cli, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0) {
        closesocket(cli);
        cli = INVALID_SOCKET;
      }
    }
    int local_port = 0;
    if (cli != INVALID_SOCKET) {
      sockaddr_in me;
      std::memset(&me, 0, sizeof(me));
      int me_len = int(sizeof(me));
      if (getsockname(cli, reinterpret_cast<sockaddr*>(&me), &me_len) == 0)
        local_port = ntohs(me.sin_port);
    }
    c.ok(local_port != 0, "a loopback TCP connection was established for the live check");

    ProcessTable live;
    std::string err;
    const bool read = live.refresh(&err);
    c.ok(read, std::string("the Windows endpoint table can be read") +
                   (err.empty() ? std::string() : std::string(": ") + err));

    if (read && local_port != 0) {
      PacketInfo self;
      self.ip_version = 4;
      self.l4 = L4::Tcp;
      self.has_ports = true;
      int v = 0;
      parse_ip("127.0.0.1", &v, self.src_ip);
      parse_ip("127.0.0.1", &v, self.dst_ip);
      self.src_port = static_cast<u16>(local_port);
      self.dst_port = static_cast<u16>(listen_port);
      int self_dir = -1;
      const ProcessInfo* self_owner = live.owner_of(self, &self_dir);
      const u32 self_pid = static_cast<u32>(GetCurrentProcessId());
      c.ok(self_owner && self_owner->pid == self_pid && self_dir == 0,
           "our own loopback socket is attributed to this process");
      c.ok(self_owner && self_owner->path.find("netcap") != std::string::npos,
           "the owning image path is the test binary");
      c.ok(self_owner && !self_owner->name.empty(), "the owner has an image name");
      if (self_owner && self_owner->pid == self_pid) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "  live: pid %lu '%s'", static_cast<unsigned long>(self_pid),
                      self_owner->name.c_str());
        c.log += buf;
        c.log += "\n";
      }
    }
    // The name of a process is what the user actually reads.  The endpoint table
    // only gives a PID, so the Toolhelp snapshot is the fallback for PIDs that
    // OpenProcess refuses (protected processes, other sessions).
    std::map<u32, std::string> names;
    const bool listed = proc_collect_process_names(&names);
    c.ok(listed, "the running process list can be read");
    c.ok(names.size() > 3, "the process list names more than a few processes");
    const auto mine = names.find(static_cast<u32>(GetCurrentProcessId()));
    c.ok(mine != names.end() && mine->second.find("netcap") != std::string::npos,
         "the process list names this test binary");

    if (cli != INVALID_SOCKET) closesocket(cli);
    if (srv != INVALID_SOCKET) closesocket(srv);
    WSACleanup();
  } else {
    c.ok(false, "WSAStartup for the live attribution check");
  }
#endif
}

// The split writer is what turns "record everything" into "one file per process
// or per application".  Files are opened lazily, and the least recently used one
// is closed and appended to when its key comes back -- without losing a packet.
void test_split(Ctx& c, const std::vector<Packet>& samples) {
  c.section("split writer");
  const std::string dir = "netcap_selftest_split";
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);

  SplitMode mode = SplitMode::Off;
  c.ok(split_mode_from_string("proc", &mode) && mode == SplitMode::Proc, "--split-by proc parses");
  c.ok(split_mode_from_string("APPLICATION", &mode) && mode == SplitMode::App,
       "--split-by app parses (case-insensitive)");
  c.ok(!split_mode_from_string("bogus", &mode), "an unknown split mode is rejected");

  ProcessInfo chrome;
  chrome.pid = 4321;
  chrome.name = "chrome.exe";
  c.ok(split_key_proc(&chrome) == "proc-chrome.exe-4321", "process keys carry the pid");
  c.ok(split_key_proc(nullptr) == "proc-unattributed", "unattributed packets get their own file");
  c.ok(split_key_app(AppKind::Unknown) == "app-other", "an unknown application keys as other");
  c.ok(split_key_app(AppKind::Tls) == "app-TLS", "application keys use the app tag");

  // --split-by origin: the program behind a local proxy gets the file, not the
  // proxy.  Traffic that never touched a proxy keeps its own process.
  c.ok(split_mode_from_string("origin", &mode) && mode == SplitMode::Origin,
       "--split-by origin parses");
  c.ok(split_mode_from_string("REAL", &mode) && mode == SplitMode::Origin,
       "--split-by real is an alias for origin");
  c.ok(std::string(split_mode_name(SplitMode::Origin)) == "origin",
       "the origin split mode has a stable name");
  ProxyLink link;
  link.origin_pid = 4321;
  link.origin_name = "chrome.exe";
  link.proxy_pid = 99;
  link.proxy_name = "clash-win64.exe";
  c.ok(split_key_origin(&link, nullptr) == "origin-chrome.exe-4321",
       "the origin key names the real application");
  link.origin_name.clear();
  c.ok(split_key_origin(&link, nullptr) == "origin-pid-4321",
       "an unnamed origin still gets its own file");
  c.ok(split_key_origin(nullptr, &chrome) == "origin-direct-chrome.exe-4321",
       "direct traffic keys as the process that sent it");
  c.ok(split_key_origin(nullptr, nullptr) == "origin-unattributed",
       "unattributed traffic has a home");
  ProcessInfo unnamed;
  unnamed.pid = 777;
  c.ok(split_key_proc(&unnamed) == "proc-pid-777", "a named-less process keys by pid");

  SplitWriter sw;
  sw.set_mode(SplitMode::App);
  std::string err;
  c.ok(sw.open(dir, DLT_EN10MB, 262144, false, 2, &err), "the split writer creates its directory");
  c.ok(sw.is_open() && sw.key_count() == 0, "a fresh split writer has no keys");

  // Three keys through a two-file window forces an eviction and an append.
  const char* keys[3] = {"app-a", "app-b", "app-c"};
  for (std::size_t i = 0; i < samples.size(); ++i) {
    const std::size_t k = i % 3;
    if (!sw.write(keys[k], samples[i].view(), &err)) break;
  }
  c.ok(sw.reopen_events() > 0, "the LRU window forces files to be reopened");
  c.ok(sw.key_count() == 3, "three keys produced three files");
  c.ok(sw.packets() == samples.size(), "every packet was counted");
  c.ok(sw.open_files() <= 2, "no more than max_open files stay open");

  bool all_good = true;
  sw.flush();  // files are buffered while they are open
  for (const SplitEntry& e : sw.entries()) {
    PcapReader r;
    std::string rerr;
    if (!r.open((std::filesystem::path(dir) / e.file).string(), &rerr)) {
      all_good = false;
      continue;
    }
    Packet pkt;
    u64 n = 0, bytes = 0;
    while (r.next(pkt)) {
      ++n;
      bytes += pkt.data.size();
    }
    r.close();
    if (n != e.packets || bytes != e.bytes) all_good = false;
  }
  c.ok(all_good, "each split file holds exactly the packets it counted");

  c.ok(sw.close(&err), "the split writer closes and writes its manifest");
  c.ok(!sw.is_open(), "a closed split writer is not open");
  {
    const std::string manifest = (std::filesystem::path(dir) / "index.json").string();
    std::string text;
    if (std::FILE* f = std::fopen(manifest.c_str(), "rb")) {
      char buf[1024];
      const std::size_t n = std::fread(buf, 1, sizeof(buf), f);
      text.assign(buf, n);
      std::fclose(f);
    }
    c.ok(text.find("\"split\":\"app\"") != std::string::npos, "the manifest records the split mode");
    c.ok(text.find("app-a") != std::string::npos, "the manifest lists the keys");
  }

  // A second run over the same directory starts clean instead of mixing runs.
  c.ok(sw.open(dir, DLT_EN10MB, 262144, false, 4, &err), "the split writer can be reopened");
  c.ok(sw.write(keys[0], samples[0].view(), &err) && sw.entries().size() == 1,
       "the second run starts a fresh index");
  c.ok(sw.close(&err), "the second run closes");
  {
    PcapReader r;
    std::string rerr;
    Packet pkt;
    u64 n = 0;
    if (r.open((std::filesystem::path(dir) / "app-a.pcap").string(), &rerr)) {
      while (r.next(pkt)) ++n;
      r.close();
    }
    c.ok(n == 1, "the second run truncated the previous file");
  }

  // PcapWriter::open_append continues a file instead of truncating it.
  {
    const std::string ap = dir + "-append.pcap";
    std::filesystem::remove(ap, ec);
    PcapWriter w;
    std::string werr;
    c.ok(w.open(ap, DLT_EN10MB, 262144, false, &werr) && w.write(samples[0].view(), &werr),
         "append mode writes the first record");
    w.close();
    c.ok(w.open_append(ap, DLT_EN10MB, 262144, false, &werr) && w.write(samples[1].view(), &werr),
         "append mode reopens an existing file");
    w.close();
    PcapReader r;
    std::string rerr;
    Packet pkt;
    u64 n = 0;
    if (r.open(ap, &rerr)) {
      while (r.next(pkt)) ++n;
      r.close();
    }
    c.ok(n == 2, "append mode keeps the earlier records");
    std::filesystem::remove(ap, ec);
  }

  std::filesystem::remove_all(dir, ec);
}

// Interception touches the machine, so the decision layer is tested with an
// injected action: guards, cap and cooldown are all checked without cutting a
// real connection or killing a real process.  The platform call itself is only
// probed against a connection that cannot exist (TEST-NET-1 addresses).
void test_block(Ctx& c) {
  c.section("interception");
  BlockMode m = BlockMode::CutTcp;
  c.ok(block_mode_from_string("dry-run", &m) && m == BlockMode::DryRun, "--block-mode dry-run parses");
  c.ok(block_mode_from_string("CUT", &m) && m == BlockMode::CutTcp, "--block-mode cut parses");
  c.ok(block_mode_from_string("kill", &m) && m == BlockMode::KillProcess, "kill parses");
  c.ok(block_mode_from_string("both", &m) && m == BlockMode::Both, "both parses");
  c.ok(!block_mode_from_string("bogus", &m), "an unknown block mode is rejected");
  c.ok(std::string(block_mode_name(BlockMode::Both)) == "cut+kill", "block modes have names");

  const PacketInfo tcp = mk_tcp("10.0.0.5", "93.184.216.34", 51000, 443, 1, 0, 0x02, std::string());
  ProcessInfo proc;
  proc.pid = 4242;
  proc.name = "chrome.exe";
  c.ok(Blocker::observable(tcp), "a TCP packet with ports is actionable");
  PacketInfo udp = tcp;
  udp.l4 = L4::Udp;
  c.ok(!Blocker::observable(udp), "a UDP packet is not actionable");

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::DryRun;
    b.set_config(cfg);
    const BlockDecision d = b.act(tcp, &proc, 0, 1000);
    c.ok(d.matched && d.action && !d.performed && d.reason.find("dry run") != std::string::npos,
         "dry run reports the decision without acting");
    c.ok(b.matched() == 1 && b.attempts() == 0, "dry run never reaches the platform call");
  }

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::DryRun;
    b.set_config(cfg);
    const BlockDecision d = b.act(udp, &proc, 0, 10);
    c.ok(d.skipped && d.reason.find("only TCP") != std::string::npos,
         "even a dry run refuses a flow that could not be cut");
  }

  int calls = 0;
  const BlockActor actor = [&calls](const PacketInfo&, int, const ProcessInfo*, std::string* err) {
    ++calls;
    if (err) err->clear();
    return true;
  };

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::CutTcp;
    cfg.cooldown_us = 1000000;
    b.set_config(cfg);
    b.set_actor(actor);
    const BlockDecision d1 = b.act(tcp, &proc, 0, 1000);
    c.ok(d1.performed && d1.reason.find("cut") != std::string::npos, "cut mode cuts the connection");
    const BlockDecision d2 = b.act(tcp, &proc, 0, 1000 + 500000);
    c.ok(d2.skipped && d2.reason.find("already acted") != std::string::npos,
         "a retransmit inside the cooldown is not cut again");
    c.ok(calls == 1, "the platform action ran exactly once");
    c.ok(b.attempts() == 1 && b.successes() == 1 && b.failures() == 0,
         "attempts and successes are counted");
  }

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::CutTcp;
    cfg.max_actions = 1;
    cfg.cooldown_us = 0;
    b.set_config(cfg);
    b.set_actor(actor);
    const PacketInfo other = mk_tcp("10.0.0.5", "1.1.1.1", 51001, 80, 1, 0, 0x02, std::string());
    c.ok(b.act(tcp, &proc, 0, 10).performed, "the first action is allowed");
    const BlockDecision d = b.act(other, &proc, 0, 20);
    c.ok(d.skipped && d.reason.find("action limit") != std::string::npos,
         "--block-max stops further actions");
  }

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::KillProcess;
    cfg.guard_pid = 4242;
    b.set_config(cfg);
    b.set_actor(actor);
    const BlockDecision d = b.act(tcp, &proc, 0, 10);
    c.ok(d.skipped && d.reason.find("capture process") != std::string::npos,
         "the capture process itself is never killed");
  }

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::KillProcess;
    b.set_config(cfg);
    b.set_actor(actor);
    const BlockDecision d = b.act(tcp, nullptr, 0, 10);
    c.ok(d.skipped && d.reason.find("no process") != std::string::npos,
         "kill mode needs a known process");
  }

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::CutTcp;
    cfg.include_loopback = false;
    b.set_config(cfg);
    b.set_actor(actor);
    const PacketInfo lo = mk_tcp("127.0.0.1", "127.0.0.1", 5000, 6000, 1, 0, 0x02, std::string());
    const BlockDecision d = b.act(lo, &proc, 0, 10);
    c.ok(d.skipped && d.reason.find("loopback") != std::string::npos, "loopback can be excluded");
  }

  {
    Blocker b;
    BlockConfig cfg;
    cfg.mode = BlockMode::Both;
    b.set_config(cfg);
    b.set_actor(actor);
    const BlockDecision d = b.act(tcp, &proc, 1, 10);
    c.ok(d.performed && d.mode == "cut+kill", "both mode cuts and kills");
  }

  std::string note;
  c.ok(block_platform_available(&note) && !note.empty(), "the platform says how it intercepts");
  c.ok(!block_platform_note().empty(), "the platform has a one-line note");
  c.ok(!block_mode_help().empty(), "the block help text is not empty");

  // A real platform call, aimed at a connection that cannot exist (TEST-NET-1):
  // it must either succeed or explain itself, and never crash.
  std::string err;
  const PacketInfo bogus = mk_tcp("192.0.2.1", "192.0.2.2", 1, 2, 1, 0, 0x02, std::string());
  const bool cut = block_cut_tcp(bogus, 0, &err);
  c.ok(cut || !err.empty(), "a real cut attempt either succeeds or explains the failure");
  if (!cut) {
    c.log += "  platform: ";
    c.log += err;
    c.log += "\n";
  }
}

// --- proxy correlation -----------------------------------------------------

ProcEndpoint mk_ep(const char* addr, u16 port, u32 pid, u8 state, const char* raddr, u16 rport) {
  ProcEndpoint r;
  r.family = 4;
  r.proto = 6;
  r.pid = pid;
  r.port = port;
  r.state = state;
  r.rport = rport;
  int v = 0;
  parse_ip(addr, &v, r.addr);
  parse_ip(raddr, &v, r.raddr);
  return r;
}

const u8* ip_of(const char* text) {
  static u8 buf[16];
  int v = 0;
  std::memset(buf, 0, sizeof(buf));
  parse_ip(text, &v, buf);
  return buf;
}

void test_proxy(Ctx& c) {
  c.section("proxy correlation");

  c.ok(name_looks_like_proxy("clash-win64.exe"), "clash is recognised as a local proxy");
  c.ok(name_looks_like_proxy("mihomo.exe"), "mihomo is recognised as a local proxy");
  c.ok(name_looks_like_proxy("v2rayN.exe"), "v2ray is recognised as a local proxy");
  c.ok(name_looks_like_proxy("sing-box.exe"), "sing-box is recognised as a local proxy");
  c.ok(!name_looks_like_proxy("chrome.exe"), "a browser is not a proxy");
  c.ok(!name_looks_like_proxy("MicrosoftEdge.exe"), "Edge is not a proxy");
  c.ok(!name_looks_like_proxy(""), "an empty name is not a proxy");
  c.ok(port_looks_like_proxy(7890), "7890 is a proxy port");
  c.ok(port_looks_like_proxy(10808), "10808 is a proxy port");
  c.ok(port_looks_like_proxy(1080), "1080 is a proxy port");
  c.ok(!port_looks_like_proxy(443), "443 is not a proxy port");
  c.ok(!port_looks_like_proxy(22), "22 is not a proxy port");
  c.ok(std::string(proxy_confidence_name(ProxyConfidence::Order)) == "order", "order confidence is named");
  c.ok(std::string(proxy_confidence_name(ProxyConfidence::Host)) == "host", "host confidence is named");
  c.ok(std::string(proxy_confidence_text(ProxyConfidence::Order)).find("hint") != std::string::npos,
       "order confidence is described as a hint, not as proof");
  c.ok(std::string(proxy_confidence_text(ProxyConfidence::Host)).find("host name") != std::string::npos,
       "host confidence says why it is stronger");

  ProcessTable procs;
  ProcessInfo clash;
  clash.pid = 100;
  clash.name = "clash-win64.exe";
  procs.add_process(clash);
  ProcessInfo chrome;
  chrome.pid = 200;
  chrome.name = "chrome.exe";
  procs.add_process(chrome);
  ProcessInfo firefox;
  firefox.pid = 300;
  firefox.name = "firefox.exe";
  procs.add_process(firefox);

  std::vector<ProcEndpoint> rows;
  rows.push_back(mk_ep("127.0.0.1", 7890, 100, 2, "0.0.0.0", 0));               // proxy listener
  rows.push_back(mk_ep("192.168.0.24", 51234, 100, 5, "93.184.216.34", 443));   // outbound 1
  rows.push_back(mk_ep("192.168.0.24", 51235, 100, 5, "1.1.1.1", 443));         // outbound 2
  rows.push_back(mk_ep("127.0.0.1", 54321, 200, 5, "127.0.0.1", 7890));         // chrome -> proxy
  rows.push_back(mk_ep("127.0.0.1", 54322, 300, 5, "127.0.0.1", 7890));         // firefox -> proxy
  rows.push_back(mk_ep("192.168.0.24", 60001, 200, 5, "203.0.113.9", 80));      // chrome direct

  ProxyTable pt;
  pt.rebuild(rows, procs, 0);
  c.eq_u64(pt.endpoints().size(), 1, "the proxy listener is found");
  c.eq_u64(pt.clients().size(), 2, "both applications talking to the proxy are found");
  c.eq_u64(pt.outbounds().size(), 2, "the proxy's own outbound connections are found");
  c.eq_u64(pt.paired(), 2, "every application half is paired with an outbound half");
  c.ok(pt.is_proxy_pid(100), "the proxy pid is flagged");
  c.ok(!pt.is_proxy_pid(200), "an application pid is not flagged as a proxy");
  c.ok(pt.proxy_name(100) != nullptr && *pt.proxy_name(100) == "clash-win64.exe",
       "the proxy name is available by pid");
  c.ok(pt.proxy_name(999) == nullptr, "an unknown pid has no proxy name");

  const ProxyLink* l1 = pt.link(4, ip_of("93.184.216.34"), 443);
  c.ok(l1 != nullptr, "the first outbound connection is linked");
  c.ok(l1 && l1->origin_pid == 200, "the first application that appeared owns it");
  c.ok(l1 && l1->proxy_pid == 100, "the link names the proxy process");
  c.ok(l1 && l1->confidence == ProxyConfidence::Order, "the link is marked as order-based");
  c.ok(l1 && !l1->basis.empty(), "the link explains itself");
  const ProxyLink* l2 = pt.link(4, ip_of("1.1.1.1"), 443);
  c.ok(l2 && l2->origin_pid == 300, "the second application owns the second outbound connection");
  c.ok(pt.link(4, ip_of("203.0.113.9"), 80) == nullptr,
       "a direct connection is not turned into a proxy link");
  c.ok(pt.link(6, ip_of("1.1.1.1"), 443) == nullptr, "an unknown address has no link");

  // A host name on both halves upgrades the pair from a guess to a fact.
  pt.note_outbound_host(4, ip_of("1.1.1.1"), 443, "Example.COM");
  pt.note_client_host(4, ip_of("127.0.0.1"), 54322, "example.com");
  pt.rebuild(rows, procs, 0);
  const ProxyLink* l2b = pt.link(4, ip_of("1.1.1.1"), 443);
  c.ok(l2b && l2b->confidence == ProxyConfidence::Host, "the same host on both halves upgrades the link");
  c.ok(l2b && l2b->origin_pid == 300, "the host match still points at the right application");
  c.ok(l2b && l2b->basis.find("example.com") != std::string::npos, "the host match says which host matched");
  const ProxyLink* l1b = pt.link(4, ip_of("93.184.216.34"), 443);
  c.ok(l1b && l1b->origin_pid == 200 && l1b->confidence == ProxyConfidence::Order,
       "the other pair stays order-based");

  // Port-only detection: a proxy whose image name we do not know.
  ProcessTable p2;
  ProcessInfo unnamed;
  unnamed.pid = 400;
  p2.add_process(unnamed);
  std::vector<ProcEndpoint> r2;
  r2.push_back(mk_ep("127.0.0.1", 7891, 400, 2, "0.0.0.0", 0));
  ProxyTable pt2;
  pt2.rebuild(r2, p2, 0);
  c.eq_u64(pt2.endpoints().size(), 1, "a listener on a proxy port is a proxy even without a known name");
  c.ok(pt2.is_proxy_pid(400), "its pid is flagged");

  // The same port bound to a LAN address is a server, not a proxy.
  std::vector<ProcEndpoint> r3;
  r3.push_back(mk_ep("192.168.0.24", 7890, 500, 2, "0.0.0.0", 0));
  ProxyTable pt3;
  pt3.rebuild(r3, p2, 0);
  c.eq_u64(pt3.endpoints().size(), 0, "a proxy port bound to a LAN address is not treated as a proxy");

  // A proxy with no visible listener still contributes its outbound halves.
  std::vector<ProcEndpoint> r4;
  r4.push_back(mk_ep("192.168.0.24", 51234, 100, 5, "93.184.216.34", 443));
  ProxyTable pt4;
  pt4.rebuild(r4, procs, 0);
  c.eq_u64(pt4.outbounds().size(), 1, "a proxy without a listener still shows outbound connections");
  c.eq_u64(pt4.paired(), 0, "with no application half nothing is paired");
  c.ok(pt4.describe().find("no local proxy") == std::string::npos,
       "the summary knows a proxy process is running");

  // Disabled means disabled.
  ProxyTable pt5;
  pt5.set_enabled(false);
  pt5.rebuild(rows, procs, 0);
  c.eq_u64(pt5.paired(), 0, "correlation is off when it is disabled");
  c.ok(pt5.describe().find("off") != std::string::npos, "and says so");

  const std::string rep = pt.report();
  c.ok(rep.find("clash-win64.exe (100)") != std::string::npos, "the report names the proxy process");
  c.ok(rep.find("firefox.exe (300)") != std::string::npos, "the report names the origin application");
  c.ok(rep.find("127.0.0.1:7890") != std::string::npos, "the report shows where the proxy listens");
  c.ok(rep.find("matched") != std::string::npos, "the report distinguishes matched from unmatched");
}

// ---------------------------------------------------------------------------
// Filter lists: the rule engine an ad blocker lives on
// ---------------------------------------------------------------------------

// The interception proxy: request targets, query rewriting and a real
// loopback run of block / rewrite / pass / tunnel.
void test_blocker(Ctx& c) {
  c.section("interception: per-application HTTPS policy");
  {
    // The list syntax is shared by --mitm-skip and --mitm-only: it comes from a
    // text field, so separators, spaces and empty entries are all tolerated.
    const std::vector<std::string> names = split_name_list(" chrome.exe , firefox.exe|pinapp ; ");
    c.eq_u64(names.size(), 3, "the process list keeps three names");
    if (names.size() == 3) {
      c.eq_str(names[0], "chrome.exe", "the first name is trimmed");
      c.eq_str(names[1], "firefox.exe", "a pipe separates names too");
      c.eq_str(names[2], "pinapp", "a semicolon separates names too");
    }
    c.eq_u64(split_name_list("").size(), 0, "an empty list has no names");
    c.eq_u64(split_name_list(" , | ").size(), 0, "empty entries are dropped");

    c.ok(name_matches_any(names, "C:\\Program Files\\Mozilla Firefox\\firefox.exe"),
         "a full path matches a bare image name");
    c.ok(name_matches_any(names, "FIREFOX.EXE"), "matching ignores case");
    c.ok(!name_matches_any(names, "msedge.exe"), "an unrelated image does not match");
    c.ok(!name_matches_any(std::vector<std::string>(), "chrome.exe"),
         "an empty pattern list matches nothing");

    MitmPolicy policy;
    c.ok(policy.empty(), "the default policy is empty");
    c.ok(!policy.wants("chrome.exe"), "an empty policy decrypts nothing");
    c.ok(!policy.wants(""), "an unnamed client is not decrypted by default");

    policy.global_on = true;
    c.ok(policy.wants("chrome.exe"), "with the switch on every application is decrypted");
    c.ok(policy.wants(""), "the switch also covers clients we could not name");

    policy.skip = split_name_list("bank.exe,pinapp");
    c.ok(!policy.wants("bank.exe"), "a skipped application keeps its own TLS");
    c.ok(!policy.wants("C:\\Apps\\PINAPP.EXE"), "skipping ignores case and paths");
    c.ok(policy.wants("chrome.exe"), "everyone else is still decrypted");
    c.ok(!policy.reason("bank.exe").empty(), "the policy explains a skip");
    c.ok(policy.describe().find("skipping") != std::string::npos,
         "the description lists the skipped applications");
    c.ok(!policy.empty(), "a configured policy is not empty");

    // An `only` list is a whitelist that the global switch cannot widen: the
    // HTTPS settings page generates `--mitm --mitm-only <common programs>` for
    // its recommended mode, and while the switch used to win there, an
    // unlisted application (a game client, say) was decrypted anyway -- the
    // opposite of what that page shows the user.
    policy.only = split_name_list("bank.exe");
    c.ok(policy.wants("bank.exe"), "an 'only' entry wins over a 'skip' entry for the same name");
    c.ok(!policy.wants("chrome.exe"), "'only' restricts even while the global switch is on");
    c.ok(!policy.wants("pinapp"), "a name in neither list is not decrypted once 'only' is set");
    c.ok(policy.reason("chrome.exe").find("--mitm-only") != std::string::npos,
         "the policy explains a name that is missing from 'only'");

    MitmPolicy only_policy;
    only_policy.only = split_name_list("chrome");
    c.ok(only_policy.wants("chrome.exe"), "'only' decrypts without the global switch");
    c.ok(!only_policy.wants("firefox.exe"), "'only' leaves other applications alone");
    c.ok(!only_policy.wants(""), "'only' never matches a nameless client");
    c.ok(only_policy.describe().find("only") != std::string::npos,
         "the description explains an 'only' policy");
    c.ok(only_policy.describe().find("chrome") != std::string::npos,
         "the description names what the whitelist opens");

    // The exact combination the settings page writes for "common programs".
    MitmPolicy common;
    common.global_on = true;
    common.only = split_name_list("msedge.exe,chrome.exe,WeChat.exe");
    c.ok(common.wants("chrome.exe"), "a listed application is decrypted");
    c.ok(!common.wants("steam.exe"), "--mitm does not widen --mitm-only back to every application");
    c.ok(!common.wants(""), "an unnamed client fails the whitelist closed");
  }

  c.section("interception: request targets");
  {
    const RequestTarget connect = parse_request_target("CONNECT", "ads.example.com:443", "");
    c.eq_str(connect.url, "https://ads.example.com/", "CONNECT becomes an https URL");
    c.eq_str(connect.host, "ads.example.com", "CONNECT host");
    c.eq_u64(connect.port, 443, "CONNECT default port");
    const RequestTarget other = parse_request_target("CONNECT", "example.com:8443", "");
    c.eq_str(other.url, "https://example.com:8443/", "a non-default CONNECT port is kept");

    const RequestTarget absolute =
        parse_request_target("GET", "http://ads.example.com/a.js?x=1", "ignored.example");
    c.eq_str(absolute.url, "http://ads.example.com/a.js?x=1", "absolute form keeps the URL");
    c.eq_str(absolute.path, "/a.js?x=1", "absolute form keeps the path");
    c.ok(!absolute.secure, "plain http is not marked secure");
    const RequestTarget secure = parse_request_target("GET", "https://a.example/b", "");
    c.ok(secure.secure, "an https URL is marked secure");

    const RequestTarget origin = parse_request_target("GET", "/pixel.gif", "tracker.example:8080");
    c.eq_str(origin.url, "http://tracker.example:8080/pixel.gif", "origin form uses the Host header");
    c.eq_u64(origin.port, 8080, "the Host header port is used");
    c.eq_str(origin.host, "tracker.example", "the Host header host is lowercased");
    const RequestTarget shouted = parse_request_target("GET", "/x", "ADS.Example.COM");
    c.eq_str(shouted.url, "http://ads.example.com/x", "the authority is lowercased");
  }

  c.section("interception: query rewriting");
  {
    std::string path = "/page?utm_source=x&id=7&utm_medium=y";
    c.ok(strip_query_parameters(&path, "*"), "the tracking list rewrites a URL");
    c.eq_str(path, "/page?id=7", "only the tracking parameters are removed");
    std::string named = "/page?a=1&b=2&c=3";
    c.ok(strip_query_parameters(&named, "a|c"), "named parameters are removed");
    c.eq_str(named, "/page?b=2", "the named parameters are gone");
    std::string clean = "/page?id=7";
    c.ok(!strip_query_parameters(&clean, "*"), "nothing to remove reports false");
    std::string nowhere = "/page";
    c.ok(!strip_query_parameters(&nowhere, "*"), "a URL without a query is left alone");
    std::string last = "/p?utm_source=x";
    c.ok(strip_query_parameters(&last, "utm_source") && last == "/p",
         "removing the last parameter leaves no '?'");
    std::size_t count = 0;
    const char* const* names = tracker_parameter_names(&count);
    c.ok(count > 10 && names != nullptr, "the built-in tracker list is populated");
  }

  c.section("interception: third-party cookies");
  {
    const std::string referer =
        "GET /a.js HTTP/1.1\r\nHost: ads.example.com\r\n"
        "Referer: https://news.example.org/article?id=1\r\n"
        "Cookie: sid=1; uid=2\r\nAccept: */*\r\n\r\n";
    c.eq_str(request_document_host(referer), "news.example.org",
             "the document host comes from Referer");
    const std::string origin =
        "GET /a.js HTTP/1.1\r\nHost: ads.example.com\r\nOrigin: https://shop.example.net:8443\r\n\r\n";
    c.eq_str(request_document_host(origin), "shop.example.net",
             "Origin is used when there is no Referer, and its port is dropped");
    const std::string opaque = "GET / HTTP/1.1\r\nHost: example.com\r\nOrigin: null\r\n\r\n";
    c.ok(request_document_host(opaque).empty(), "an opaque origin ('null') is not a host");
    const std::string bare = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    c.ok(request_document_host(bare).empty(), "no Referer and no Origin means no document host");
    const std::string userinfo =
        "GET /x HTTP/1.1\r\nHost: a.example\r\nReferer: https://user:pw@a.example.org/p\r\n\r\n";
    c.eq_str(request_document_host(userinfo), "a.example.org", "userinfo in a Referer is skipped");
    c.ok(!RuleRequest::same_site("ads.example.com", "news.example.org"),
         "a different registrable domain is third party");
    c.ok(RuleRequest::same_site("cdn.example.org", "news.example.org"),
         "a sibling subdomain is first party");
    const std::string shouted =
        "GET /x HTTP/1.1\r\nHost: ads.example.com\r\nReferer: https://NEWS.Example.ORG/Article\r\n\r\n";
    c.eq_str(request_document_host(shouted), "news.example.org",
             "the document host is lower-cased before it is compared");
    const BlockerConfig fresh;
    c.ok(!fresh.block_third_party_cookies, "third-party cookie stripping is off by default");

    std::string head = referer;
    c.eq_u64(strip_header(&head, "cookie"), 1, "strip_header removes the Cookie line");
    c.ok(head.find("sid=1") == std::string::npos, "the cookie value is gone from the head");
    c.ok(head.find("Referer: https://news.example.org/article?id=1\r\n") != std::string::npos,
         "the other headers survive");
    c.ok(head.find("\r\n\r\n") != std::string::npos, "the head still ends with a blank line");
    c.eq_str(head.substr(0, head.find("\r\n")), "GET /a.js HTTP/1.1", "the request line survives");
    std::string with_body =
        "POST /p HTTP/1.1\r\nHost: a.example\r\nCOOKIE: x=1\r\nContent-Length: 4\r\n\r\nBODY";
    c.eq_u64(strip_header(&with_body, "cookie"), 1, "header names are matched case-insensitively");
    c.eq_str(with_body.substr(with_body.size() - 4), "BODY", "the request body is preserved");
    std::string untouched = bare;
    c.eq_u64(strip_header(&untouched, "cookie"), 0, "a head without the header reports 0");
    c.eq_str(untouched, bare, "an untouched head is handed back unchanged");
    std::string lookalike = "GET / HTTP/1.1\r\nHost: a.example\r\nX-Cookie-Monster: 1\r\n\r\n";
    c.eq_u64(strip_header(&lookalike, "cookie"), 0, "a name that merely ends in 'cookie' is kept");
    c.ok(lookalike.find("X-Cookie-Monster: 1") != std::string::npos, "the lookalike header is still there");
  }

#ifdef _WIN32
  c.section("interception: live proxy on loopback");  {
    // A one-shot origin server: accepts one connection, remembers what it was
    // asked for and answers with a fixed reply.
    struct Origin {
      SOCKET listener = INVALID_SOCKET;
      u16 port = 0;
      std::string request;
      std::string reply;
      bool raw = false;
      std::thread worker;

      bool start(const std::string& answer, bool raw_mode) {
        reply = answer;
        raw = raw_mode;
        listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return false;
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
        if (::listen(listener, 4) != 0) return false;
        int len = sizeof(addr);
        if (getsockname(listener, (sockaddr*)&addr, &len) != 0) return false;
        port = ntohs(addr.sin_port);
        worker = std::thread([this]() {
          SOCKET client = ::accept(listener, nullptr, nullptr);
          if (client == INVALID_SOCKET) return;
          DWORD tv = 3000;
          setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
          char buf[2048];
          std::string have;
          if (raw) {
            int rc = ::recv(client, buf, sizeof(buf), 0);
            if (rc > 0) have.append(buf, (size_t)rc);
          } else {
            while (have.find("\r\n\r\n") == std::string::npos) {
              int rc = ::recv(client, buf, sizeof(buf), 0);
              if (rc <= 0) break;
              have.append(buf, (size_t)rc);
            }
          }
          request = have;
          ::send(client, reply.data(), (int)reply.size(), 0);
          ::shutdown(client, SD_SEND);
          closesocket(client);
        });
        return true;
      }

      ~Origin() {
        if (listener != INVALID_SOCKET) closesocket(listener);
        if (worker.joinable()) worker.join();
      }
    };

    // Talks to the proxy; in tunnel mode it waits for the 200 first and then
    // pushes a payload through the established tunnel.
    struct Talk {
      static std::string run(u16 port, const std::string& request, bool tunnel) {
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return "<socket failed>";
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (::connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
          closesocket(s);
          return "<connect failed>";
        }
        DWORD tv = 4000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        ::send(s, request.data(), (int)request.size(), 0);
        std::string got;
        char buf[1024];
        if (tunnel) {
          while (got.find("\r\n\r\n") == std::string::npos) {
            int rc = ::recv(s, buf, sizeof(buf), 0);
            if (rc <= 0) break;
            got.append(buf, (size_t)rc);
          }
          ::send(s, "PING", 4, 0);
        }
        for (;;) {
          int rc = ::recv(s, buf, sizeof(buf), 0);
          if (rc <= 0) break;
          got.append(buf, (size_t)rc);
        }
        closesocket(s);
        return got;
      }
    };

    RuleSet rs;
    rs.load_text(
        "||ads.example.com^\n"
        "||127.0.0.1^$removeparam=utm_source\n"
        "||blocked.example^\n");
    c.ok(rs.size() == 3, "the proxy rule list parsed");

    BlockerConfig cfg;
    cfg.port = 0;
    cfg.io_timeout_ms = 4000;
    cfg.connect_timeout_ms = 4000;
    cfg.log_limit = 64;
    InterceptProxy proxy;
    std::string error;
    const bool started = proxy.start(cfg, &rs, &error);
    c.ok(started, "the interception proxy starts on loopback");
    if (started) {
      c.ok(proxy.port() != 0, "the proxy reports the port the OS picked");
      c.ok(proxy.running(), "the proxy reports that it is running");
      c.ok(proxy.bound_endpoint().find("127.0.0.1:") == 0, "the proxy bound a loopback address");

      // 1. blocked: answered locally, the origin is never contacted
      {
        Origin origin;
        c.ok(origin.start("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO", false),
             "the test origin server listens");
        std::string seen;
        std::thread client([&]() {
          seen = Talk::run(proxy.port(),
                           "GET http://ads.example.com/banner.js HTTP/1.1\r\nHost: ads.example.com\r\n\r\n",
                           false);
        });
        const bool served = proxy.serve_once(4000);
        client.join();
        c.ok(served, "the proxy served the blocked request");
        c.ok(seen.find("403") != std::string::npos, "a blocked document gets 403");
        c.ok(seen.find("banner.js") != std::string::npos, "the block page names the URL");
      }

      // 2. rewritten: the tracking parameter never reaches the origin
      {
        Origin origin;
        c.ok(origin.start("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO", false),
             "the test origin server listens again");
        const std::string host_port = "127.0.0.1:" + std::to_string(origin.port);
        std::string seen;
        std::thread client([&]() {
          seen = Talk::run(proxy.port(),
                           "GET http://" + host_port + "/page?utm_source=x&id=7 HTTP/1.1\r\nHost: " +
                               host_port + "\r\n\r\n",
                           false);
        });
        const bool served = proxy.serve_once(4000);
        client.join();
        c.ok(served, "the proxy served the rewrite request");
        c.ok(origin.request.find("utm_source") == std::string::npos,
             "the tracking parameter was stripped before forwarding");
        c.ok(origin.request.find("/page?id=7") != std::string::npos,
             "the remaining parameters survived the rewrite");
        c.ok(seen.find("HELLO") != std::string::npos, "the rewritten response reaches the client");
      }

      // 3. passed: relayed byte for byte
      {
        Origin origin;
        c.ok(origin.start("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO", false),
             "the test origin server listens a third time");
        const std::string host_port = "127.0.0.1:" + std::to_string(origin.port);
        std::string seen;
        std::thread client([&]() {
          seen = Talk::run(proxy.port(),
                           "GET http://" + host_port + "/plain?a=b HTTP/1.1\r\nHost: " + host_port +
                               "\r\n\r\n",
                           false);
        });
        const bool served = proxy.serve_once(4000);
        client.join();
        c.ok(served, "the proxy served the plain request");
        c.ok(origin.request.find("/plain?a=b") != std::string::npos,
             "an unmatched URL is forwarded untouched");
        c.ok(seen.find("HELLO") != std::string::npos, "the upstream response is relayed");
      }

      // 4. CONNECT to a blocked host: refused without touching the network
      {
        std::string seen;
        std::thread client([&]() {
          seen = Talk::run(proxy.port(), "CONNECT blocked.example:443 HTTP/1.1\r\n\r\n", false);
        });
        const bool served = proxy.serve_once(4000);
        client.join();
        c.ok(served, "the proxy served the blocked CONNECT");
        c.ok(seen.find("403") != std::string::npos, "a blocked CONNECT is refused with 403");
      }

      // 5. CONNECT tunnel: bytes flow both ways and are never inspected
      {
        Origin origin;
        c.ok(origin.start("PONG", true), "the tunnel target listens");
        const u16 target = origin.port;
        std::string seen;
        std::thread client([&]() {
          seen = Talk::run(proxy.port(),
                           "CONNECT 127.0.0.1:" + std::to_string(target) + " HTTP/1.1\r\n\r\n", true);
        });
        const bool served = proxy.serve_once(6000);
        client.join();
        c.ok(served, "the proxy served the CONNECT tunnel");
        c.ok(seen.find("200 Connection Established") != std::string::npos,
             "a tunnel is established for a host that is not blocked");
        c.ok(seen.find("PONG") != std::string::npos, "tunnelled bytes come back to the client");
        c.ok(origin.request == "PING", "the tunnel carried the payload to the target");
      }

      // 5b. upstream chaining: with an upstream proxy configured every origin is
      //     reached through a CONNECT tunnel into that proxy.  This is the piece
      //     that stops a system-proxy takeover from cutting the machine off.
      {
        struct FakeProxy {
          SOCKET listener = INVALID_SOCKET;
          u16 port = 0;
          std::string connect_head;
          std::string tunnelled_request;
          bool start() {
            listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) return false;
            sockaddr_in name;
            std::memset(&name, 0, sizeof(name));
            name.sin_family = AF_INET;
            name.sin_port = 0;
            name.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::bind(listener, reinterpret_cast<sockaddr*>(&name), sizeof(name)) != 0 ||
                ::listen(listener, 4) != 0) {
              return false;
            }
            int len = static_cast<int>(sizeof(name));
            if (::getsockname(listener, reinterpret_cast<sockaddr*>(&name), &len) != 0) return false;
            port = ntohs(name.sin_port);
            return port != 0;
          }
          static bool read_head(SOCKET s, std::string* out) {
            char buf[512];
            while (out->find("\r\n\r\n") == std::string::npos) {
              const int rc = ::recv(s, buf, sizeof(buf), 0);
              if (rc <= 0) return false;
              out->append(buf, static_cast<std::size_t>(rc));
            }
            return true;
          }
          void serve() {
            const SOCKET s = ::accept(listener, nullptr, nullptr);
            if (s == INVALID_SOCKET) return;
            if (read_head(s, &connect_head)) {
              static const char kEstablished[] = "HTTP/1.1 200 Connection established\r\n\r\n";
              ::send(s, kEstablished, static_cast<int>(sizeof(kEstablished) - 1), 0);
              if (read_head(s, &tunnelled_request)) {
                static const char kBody[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nCHAIN";
                ::send(s, kBody, static_cast<int>(sizeof(kBody) - 1), 0);
              }
            }
            ::closesocket(s);
          }
        };

        FakeProxy fake;
        c.ok(fake.start(), "the fake upstream proxy listens");
        BlockerConfig chain_cfg = cfg;
        chain_cfg.upstream_proxy = "127.0.0.1:" + std::to_string(fake.port);
        InterceptProxy chain_proxy;
        std::string chain_error;
        if (chain_proxy.start(chain_cfg, &rs, &chain_error)) {
          std::thread fake_thread([&fake]() { fake.serve(); });
          std::string seen;
          std::thread client([&]() {
            seen = Talk::run(chain_proxy.port(),
                             "GET http://upstream.test/page HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
                             false);
          });
          const bool served = chain_proxy.serve_once(8000);
          client.join();
          fake_thread.join();
          c.ok(served, "the proxy served a request through the upstream proxy");
          c.ok(fake.connect_head.find("CONNECT upstream.test:80") == 0,
               "the origin is opened with a CONNECT into the upstream proxy");
          c.ok(fake.tunnelled_request.find("GET /page HTTP/1.1") != std::string::npos,
               "the request travels inside the upstream tunnel");
          c.ok(seen.find("CHAIN") != std::string::npos,
               "the response comes back through the upstream proxy");
        } else {
          c.ok(false, "the proxy with an upstream proxy starts: " + chain_error);
        }
        chain_proxy.stop();
        if (fake.listener != INVALID_SOCKET) ::closesocket(fake.listener);
      }

      // 6. third-party cookie: forwarded without the Cookie header, in its own
      //    proxy so the counters of the main one stay comparable.
      {
        Origin origin;
        c.ok(origin.start("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO", false),
             "the test origin server listens for the cookie test");
        BlockerConfig cookie_cfg = cfg;
        cookie_cfg.block_third_party_cookies = true;
        InterceptProxy cookie_proxy;
        std::string cookie_error;
        if (cookie_proxy.start(cookie_cfg, &rs, &cookie_error)) {
          const std::string host_port = "127.0.0.1:" + std::to_string(origin.port);
          std::thread client([&]() {
            Talk::run(cookie_proxy.port(),
                      "GET http://" + host_port + "/pixel.gif HTTP/1.1\r\nHost: " + host_port +
                          "\r\nReferer: http://news.example.org/article\r\n"
                          "Cookie: sid=1; uid=2\r\n\r\n",
                      false);
          });
          const bool served = cookie_proxy.serve_once(4000);
          client.join();
          c.ok(served, "the cookie proxy served the request");
          c.ok(origin.request.find("sid=1") == std::string::npos,
               "a third-party cookie never reaches the origin");
          c.ok(origin.request.find("Referer: http://news.example.org/article") != std::string::npos,
               "the other headers still reach the origin");
          c.ok(origin.request.find("/pixel.gif") != std::string::npos, "the path is untouched");
          const std::vector<InterceptEvent> cookie_events = cookie_proxy.events();
          c.eq_u64(cookie_events.size(), 1, "the cookie request produced one event");
          if (!cookie_events.empty()) {
            c.eq_str(intercept_action_name(cookie_events[0].action), "modify",
                     "the cookie request is reported as a rewrite");
            c.ok(cookie_events[0].detail.find("third-party cookie") != std::string::npos,
                 "the event says why the request was rewritten");
            c.ok(cookie_events[0].rule.find("third-party cookies") != std::string::npos,
                 "the event names the switch that did it, not an empty rule column (" +
                     cookie_events[0].rule + ")");
          }
          c.eq_u64(cookie_proxy.stats().modified, 1, "the cookie rewrite is counted");
          c.eq_u64(cookie_proxy.stats().passed, 0, "nothing was passed through untouched");
          cookie_proxy.stop();
        } else {
          c.ok(false, "the cookie proxy starts (" + cookie_error + ")");
        }
      }

      // 7. the logged status is the origin's, not a hard-coded 200: the proxy
      //    relays bytes verbatim, so it reads the status line on the way past.
      {
        Origin origin;
        c.ok(origin.start("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nno!", false),
             "the test origin server answers 404");
        BlockerConfig status_cfg = cfg;
        InterceptProxy status_proxy;
        // The `应用` column is filled for every method, not only for CONNECT: the
        // resolver is installed here so the plain GET below has to be attributed.
        status_proxy.set_client_resolver(
            [](const std::string&, std::uint16_t) { return std::string("status-client.exe"); });
        std::string status_error;
        if (status_proxy.start(status_cfg, &rs, &status_error)) {
          const std::string host_port = "127.0.0.1:" + std::to_string(origin.port);
          std::thread client([&]() {
            Talk::run(status_proxy.port(),
                      "GET http://" + host_port + "/missing HTTP/1.1\r\nHost: " + host_port +
                          "\r\n\r\n",
                      false);
          });
          const bool served = status_proxy.serve_once(4000);
          client.join();
          c.ok(served, "the proxy served the request for the status test");
          const std::vector<InterceptEvent> se = status_proxy.events();
          c.eq_u64(se.size(), 1, "the status test produced one event");
          if (!se.empty()) {
            c.eq_u64(static_cast<u64>(se[0].status), 404,
                     "the event carries the status code the origin sent");
            c.eq_str(intercept_action_name(se[0].action), "pass",
                     "an untouched 404 is still reported as a pass");
            c.eq_str(se[0].client_proc, "status-client.exe",
                     "a plain HTTP request is attributed to its process too");
          }
          status_proxy.stop();
        } else {
          c.ok(false, "the status proxy starts (" + status_error + ")");
        }
      }

      // 8. response rewriting: the whole response is read before it is sent on,
      //    so a rule can change headers and the body (and the framing has to be
      //    fixed up).  One option per rule: an option that takes free text eats
      //    the rest of its line.
      {
        const std::string page =
            "<html><head><title>t</title></head><body>Hello</body></html>";
        Origin origin;
        c.ok(origin.start("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
                              std::to_string(page.size()) +
                              "\r\nSet-Cookie: sid=1\r\nx-drop: yes\r\n\r\n" + page,
                          false),
             "the test origin server serves HTML");
        RuleSet rw_rules;
        std::string rw_error;
        const bool rw_loaded = rw_rules.load_text(
            "||127.0.0.1^$replace=/Hello/Goodbye/\n"
            "||127.0.0.1^$removeheader=x-drop,removecookie\n"
            "||127.0.0.1^$header=x-netcap: yes\n"
            "||127.0.0.1^$css=body{color:red}\n"
            "||127.0.0.1^$script=console.log(1)\n",
            &rw_error);
        c.ok(rw_loaded, "the response rewrite rules parsed (" + rw_error + ")");
        c.eq_u64(rw_rules.stats().response_rules, 5, "all five are response rules");
        c.eq_u64(rw_rules.stats().block_rules, 0, "a response rule does not block anything");

        InterceptProxy rw_proxy;
        std::string rw_start_error;
        if (rw_proxy.start(cfg, &rw_rules, &rw_start_error)) {
          const std::string host_port = "127.0.0.1:" + std::to_string(origin.port);
          std::string seen;
          std::thread client([&]() {
            seen = Talk::run(rw_proxy.port(),
                             "GET http://" + host_port + "/page.html HTTP/1.1\r\nHost: " + host_port +
                                 "\r\nCookie: sid=1\r\n\r\n",
                             false);
          });
          const bool served = rw_proxy.serve_once(4000);
          client.join();
          c.ok(served, "the rewrite proxy served the request");
          c.ok(seen.find("Goodbye") != std::string::npos, "the body replace reached the client");
          c.ok(seen.find("Hello") == std::string::npos, "the replaced text is gone");
          c.ok(seen.find("x-netcap: yes") != std::string::npos, "a header was added to the response");
          c.ok(seen.find("x-drop") == std::string::npos, "a header was removed from the response");
          c.ok(seen.find("Set-Cookie") == std::string::npos, "the response cookie was dropped");
          c.ok(seen.find("body{color:red}") != std::string::npos, "the stylesheet was injected");
          c.ok(seen.find("console.log(1)") != std::string::npos, "the script was injected");
          c.ok(seen.find("body{color:red}") < seen.find("console.log(1)"),
               "style goes in before script");

          // The framing has to match the new body: read the head back and count
          // what actually followed it.
          const std::size_t split = seen.find("\r\n\r\n");
          c.ok(split != std::string::npos, "the rewritten response has a head");
          if (split != std::string::npos) {
            const std::string head = seen.substr(0, split);
            const std::string body = seen.substr(split + 4);
            const std::string want = "Content-Length: " + std::to_string(body.size());
            c.ok(head.find(want) != std::string::npos,
                 "the rewritten Content-Length matches the rewritten body (" + want + ")");
            c.ok(body.find("</head>") != std::string::npos &&
                     body.find("body{color:red}") < body.find("</head>"),
                 "the injection landed inside the head element");
          }

          const std::vector<InterceptEvent> rw_events = rw_proxy.events();
          c.eq_u64(rw_events.size(), 1, "the rewritten response produced one event");
          if (!rw_events.empty()) {
            c.eq_str(intercept_action_name(rw_events[0].action), "modify",
                     "the event is reported as a rewrite");
            c.eq_u64(static_cast<u64>(rw_events[0].status), 200, "the origin's status is kept");
            c.ok(!rw_events[0].detail.empty(), "the event explains what was rewritten");
            // A rewrite is always the work of a rule, and the log has to say
            // which one: an empty 规则 column made it look self-inflicted.
            c.ok(rw_events[0].rule.find("||127.0.0.1^$replace=/Hello/Goodbye/") == 0,
                 "the event names the rule that asked for the rewrite (" + rw_events[0].rule + ")");
            c.ok(rw_events[0].rule.find("(+5)") != std::string::npos,
                 "and reports the five other things that joined in (the four other rules plus the "
                 "element-picker hook) (" + rw_events[0].rule + ")");
          }
          c.eq_u64(rw_proxy.stats().modified, 1, "the response rewrite is counted as a modify");
          rw_proxy.stop();
        } else {
          c.ok(false, "the rewrite proxy starts (" + rw_start_error + ")");
        }

        // 8b. a chunked response has to be put back together before it can be
        //     edited, and then reframed: leaving the chunk sizes in place would
        //     describe bytes that no longer exist.
        {
          const std::string body =
              "<html><head><title>t</title></head><body>Hello</body></html>";
          const std::string chunks = [&body]() {
            std::string out;
            std::size_t at = 0;
            while (at < body.size()) {
              const std::size_t take = std::min<std::size_t>(17, body.size() - at);
              char size[16];
              std::snprintf(size, sizeof(size), "%zx", take);
              out += size;
              out += "\r\n";
              out += body.substr(at, take);
              out += "\r\n";
              at += take;
            }
            out += "0\r\n\r\n";
            return out;
          }();

          Origin chunked_origin;
          c.ok(chunked_origin.start(
                   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n" +
                       chunks,
                   false),
               "the test origin server answers with chunked framing");
          InterceptProxy chunked_proxy;
          std::string chunked_error;
          if (chunked_proxy.start(cfg, &rw_rules, &chunked_error)) {
            const std::string host_port = "127.0.0.1:" + std::to_string(chunked_origin.port);
            std::string seen;
            std::thread client([&]() {
              seen = Talk::run(chunked_proxy.port(),
                               "GET http://" + host_port + "/chunked.html HTTP/1.1\r\nHost: " +
                                   host_port + "\r\n\r\n",
                               false);
            });
            const bool served = chunked_proxy.serve_once(4000);
            client.join();
            c.ok(served, "the proxy served the chunked response");
            const std::size_t split = seen.find("\r\n\r\n");
            c.ok(split != std::string::npos, "the rewritten chunked response has a head");
            if (split != std::string::npos) {
              const std::string head = seen.substr(0, split);
              const std::string raw = seen.substr(split + 4);
              const std::string got = strip_picker_bootstrap(raw);
              c.eq_str(got,
                       "<html><head><title>t</title><style>body{color:red}</style>"
                       "<script>console.log(1)</script></head><body>Goodbye</body></html>",
                       "the chunked body is decoded, edited and sent as one piece");
              c.ok(head.find("Transfer-Encoding") == std::string::npos,
                   "the chunked framing is dropped once the body is a single piece");
              c.ok(head.find("Content-Length: " + std::to_string(raw.size())) != std::string::npos,
                   "the reframed response carries a Content-Length of its own");
            }
            chunked_proxy.stop();
          } else {
            c.ok(false, "the chunked rewrite proxy starts (" + chunked_error + ")");
          }
        }

        // 8c. chunked *over* gzip: the chunks have to be joined before the gzip
        //     stream can be inflated, which is the order real servers send it in.
        {
          const Bytes gzipped = from_hex(
              "1f8b080000000000020ab3c928c9cdb1b3c9484d4cb1b329c92cc949b52bb1d187306cf421c249f929957"
              "61ea93939f936fa60365002a40b0047d3017e3c000000");
          std::string framed;
          std::size_t at = 0;
          while (at < gzipped.size()) {
            const std::size_t take = std::min<std::size_t>(13, gzipped.size() - at);
            char size[16];
            std::snprintf(size, sizeof(size), "%zx", take);
            framed += size;
            framed += "\r\n";
            framed.append(reinterpret_cast<const char*>(gzipped.data() + at), take);
            framed += "\r\n";
            at += take;
          }
          framed += "0\r\n\r\n";

          Origin gz_origin;
          c.ok(gz_origin.start("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                               "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" +
                                   framed,
                               false),
               "the test origin server answers with chunked gzip");
          InterceptProxy gz_proxy;
          std::string gz_error;
          if (gz_proxy.start(cfg, &rw_rules, &gz_error)) {
            const std::string host_port = "127.0.0.1:" + std::to_string(gz_origin.port);
            std::string seen;
            std::thread client([&]() {
              seen = Talk::run(gz_proxy.port(),
                               "GET http://" + host_port + "/gz.html HTTP/1.1\r\nHost: " + host_port +
                                   "\r\nAccept-Encoding: gzip\r\n\r\n",
                               false);
            });
            const bool served = gz_proxy.serve_once(4000);
            client.join();
            c.ok(served, "the proxy served the chunked gzip response");
            const std::size_t split = seen.find("\r\n\r\n");
            c.ok(split != std::string::npos, "the rewritten chunked gzip response has a head");
            if (split != std::string::npos) {
              const std::string head = seen.substr(0, split);
              const std::string raw = seen.substr(split + 4);
              const std::string got = strip_picker_bootstrap(raw);
              c.eq_str(got,
                       "<html><head><title>t</title><style>body{color:red}</style>"
                       "<script>console.log(1)</script></head><body>Goodbye</body></html>",
                       "the gzip inside the chunks is inflated and then edited");
              c.ok(head.find("Content-Encoding") == std::string::npos,
                   "the body is no longer compressed, so the header is gone");
              c.ok(head.find("Transfer-Encoding") == std::string::npos,
                   "the body is one piece again, so the chunked framing is gone");
              c.ok(head.find("Content-Length: " + std::to_string(raw.size())) != std::string::npos,
                   "the reframed response carries a Content-Length of its own");
            }
            const std::vector<InterceptEvent> gz_events = gz_proxy.events();
            if (!gz_events.empty()) {
              c.ok(gz_events[0].detail.find("encoding dropped") != std::string::npos,
                   "the event says the content encoding was dropped");
            }
            gz_proxy.stop();
          } else {
            c.ok(false, "the chunked gzip rewrite proxy starts (" + gz_error + ")");
          }
        }
      }

      const BlockerStats stats = proxy.stats();
      c.eq_u64(stats.blocked, 2, "the statistics counted both blocks");
      c.eq_u64(stats.modified, 1, "the statistics counted the rewrite");
      c.eq_u64(stats.passed, 1, "the statistics counted the relayed request");
      c.eq_u64(stats.tunnels, 1, "the statistics counted the tunnel");
      c.eq_u64(stats.requests, 5, "the statistics counted every request");
      c.ok(stats.bytes_out > 0 && stats.bytes_in > 0, "both directions moved bytes");

      const std::vector<InterceptEvent> events = proxy.events();
      c.eq_u64(events.size(), 5, "one event was recorded per request");
      if (events.size() == 5) {
        c.eq_str(intercept_action_name(events[0].action), "block", "the first event is a block");
        c.ok(!events[0].rule.empty(), "the blocking rule is recorded on the event");
        c.eq_str(intercept_action_name(events[1].action), "modify", "the second event is a rewrite");
        c.eq_str(intercept_action_name(events[2].action), "pass", "the third event is a pass");
        c.eq_str(intercept_action_name(events[3].action), "block", "the fourth event is a block");
        c.eq_str(intercept_action_name(events[4].action), "tunnel", "the fifth event is a tunnel");
        c.ok(events[1].detail.find("utm_source") != std::string::npos,
             "the rewrite event explains what was removed");
        c.ok(events[1].url.find("http://127.0.0.1:") == 0 &&
                 events[1].url.find("utm_source") != std::string::npos,
             "the rewrite event keeps the URL the rules decided on");
      }
      c.ok(proxy.report().find("interception proxy") != std::string::npos,
           "the report describes the proxy");
      c.ok(proxy.report().find("most used rules") != std::string::npos,
           "the report lists the rules that fired");

      // 9. per-application policy on a live CONNECT: an application on the skip
      //    list keeps a plain tunnel even while the HTTPS switch is on.
      {
        Origin origin;
        c.ok(origin.start("PONG", true), "the skipped tunnel target listens");
        const u16 target = origin.port;
        BlockerConfig skip_cfg = cfg;
        skip_cfg.mitm = true;
        skip_cfg.mitm_skip = split_name_list("netcap");
        // --mitm refuses to start without a CA on disk, and this case is about a
        // skipped application never reaching that CA, so write a throwaway one.
        CaBundle skip_ca;
        std::string skip_ca_error;
        const std::string skip_ca_crt = "netcap_selftest_mitm_skip.crt";
        const std::string skip_ca_key = "netcap_selftest_mitm_skip.key";
        X509Subject skip_subject;
        skip_subject.common_name = "netcap selftest skip CA";
        skip_subject.organization = "netcap selftest";
        skip_subject.country = "XX";
        const bool skip_ca_ready = ca_create(skip_subject, 30, &skip_ca, &skip_ca_error) &&
                                   ca_write_files(skip_ca, skip_ca_crt, skip_ca_key, &skip_ca_error);
        c.ok(skip_ca_ready, "the skip case has a CA on disk (" + skip_ca_error + ")");
        skip_cfg.ca_cert_path = skip_ca_crt;
        skip_cfg.ca_key_path = skip_ca_key;
        InterceptProxy skip_proxy;
        // The naming hook stands in for the OS endpoint table, so this case is
        // deterministic; on a real machine the selftest binary is netcap.exe and
        // would be matched by the same list.
        skip_proxy.set_client_resolver([](const std::string&, std::uint16_t) {
          return std::string("netcap.exe");
        });
        std::string skip_error;
        if (skip_proxy.start(skip_cfg, &rs, &skip_error)) {
          std::string seen;
          std::thread client([&]() {
            seen = Talk::run(skip_proxy.port(),
                             "CONNECT 127.0.0.1:" + std::to_string(target) + " HTTP/1.1\r\n\r\n",
                             true);
          });
          const bool served = skip_proxy.serve_once(6000);
          client.join();
          c.ok(served, "the skip proxy served the CONNECT");
          c.ok(seen.find("200 Connection Established") != std::string::npos,
               "a skipped application still gets its tunnel");
          c.ok(seen.find("PONG") != std::string::npos,
               "the skipped tunnel is transparent: our bytes reach the target and come back");
          c.ok(origin.request == "PING", "the skipped tunnel carried the payload untouched");
          const std::vector<InterceptEvent> skip_events = skip_proxy.events();
          c.eq_u64(skip_events.size(), 1, "the skipped CONNECT produced one event");
          if (!skip_events.empty()) {
            c.eq_str(skip_events[0].mitm, "skip", "the event says the policy left it alone");
            c.eq_str(skip_events[0].client_proc, "netcap.exe", "the event names the client");
            c.eq_str(intercept_action_name(skip_events[0].action), "tunnel",
                     "a skipped CONNECT stays a tunnel");
          }
          c.eq_u64(skip_proxy.stats().mitm_skipped, 1, "the skip is counted");
          c.eq_u64(skip_proxy.stats().decrypted, 0, "nothing was decrypted for a skipped app");
          skip_proxy.stop();
        } else {
          c.ok(false, "the skip proxy starts (" + skip_error + ")");
        }
        std::remove(skip_ca_crt.c_str());
        std::remove(skip_ca_key.c_str());
      }

      // 11. a client that refuses our certificate twice is remembered: from the
      //     third connection on that (application, host) pair is tunnelled
      //     without decryption, so the application keeps working instead of
      //     failing on every single request.
      {
        Origin origin;
        c.ok(origin.start("PONG", true), "the refusal target listens");
        const u16 target = origin.port;
        BlockerConfig refuse_cfg = cfg;
        refuse_cfg.mitm = true;
        CaBundle refuse_ca;
        std::string refuse_ca_error;
        const std::string refuse_ca_crt = "netcap_selftest_mitm_refuse.crt";
        const std::string refuse_ca_key = "netcap_selftest_mitm_refuse.key";
        X509Subject refuse_subject;
        refuse_subject.common_name = "netcap selftest refusal CA";
        refuse_subject.organization = "netcap selftest";
        refuse_subject.country = "XX";
        const bool refuse_ca_ready =
            ca_create(refuse_subject, 30, &refuse_ca, &refuse_ca_error) &&
            ca_write_files(refuse_ca, refuse_ca_crt, refuse_ca_key, &refuse_ca_error);
        c.ok(refuse_ca_ready, "the refusal case has a CA on disk (" + refuse_ca_error + ")");
        refuse_cfg.ca_cert_path = refuse_ca_crt;
        refuse_cfg.ca_key_path = refuse_ca_key;
        // A client that asks for the tunnel and then walks away without ever
        // answering our handshake: this is what a client with its own trust store
        // looks like from here (the one in the field is Node, inside the harness).
        auto knock = [](u16 proxy_port, u16 target_port) {
          return Talk::run(proxy_port,
                           "CONNECT 127.0.0.1:" + std::to_string(target_port) +
                               " HTTP/1.1\r\n\r\n",
                           false);
        };
        InterceptProxy refuse_proxy;
        refuse_proxy.set_client_resolver([](const std::string&, std::uint16_t) {
          return std::string("refuser.exe");
        });
        // The client-facing handshake runs only when the origin is believed to
        // speak TLS, and this target is a plain TCP server, so state the verdict.
        refuse_proxy.set_origin_tls_ability("127.0.0.1", target, 1);
        std::string refuse_error;
        if (refuse_proxy.start(refuse_cfg, &rs, &refuse_error)) {
          knock(refuse_proxy.port(), target);
          c.ok(refuse_proxy.serve_once(6000), "the refusal proxy served the first CONNECT");
          c.eq_u64(refuse_proxy.stats().mitm_client_refusals, 0,
                   "one refusal is not a pattern yet");
          knock(refuse_proxy.port(), target);
          c.ok(refuse_proxy.serve_once(6000), "the refusal proxy served the second CONNECT");
          c.eq_u64(refuse_proxy.stats().mitm_client_refusals, 1,
                   "the second refusal retires the pair");
          std::string seen;
          std::thread client([&]() {
            seen = Talk::run(refuse_proxy.port(),
                             "CONNECT 127.0.0.1:" + std::to_string(target) +
                                 " HTTP/1.1\r\n\r\n",
                             true);
          });
          const bool served_three = refuse_proxy.serve_once(6000);
          client.join();
          c.ok(served_three, "the refusal proxy served the third CONNECT");
          c.ok(seen.find("200 Connection Established") != std::string::npos,
               "the refused application still gets its tunnel");
          c.ok(seen.find("PONG") != std::string::npos,
               "the remembered pair is tunnelled blind: its payload reaches the target");
          const std::vector<InterceptEvent> refuse_events = refuse_proxy.events();
          c.eq_u64(refuse_events.size(), 2, "the two silent refusals are not two events");
          if (refuse_events.size() >= 2) {
            c.eq_str(intercept_action_name(refuse_events[0].action), "error",
                     "the retiring refusal is reported once");
            c.ok(refuse_events[0].detail.find("does not trust netcap's certificate") !=
                     std::string::npos,
                 "the event says why the pair was retired");
            c.eq_str(refuse_events[1].mitm, "skip",
                     "the pair is tunnelled without decryption from then on");
            c.eq_str(intercept_action_name(refuse_events[1].action), "tunnel",
                     "and what the client gets is a plain tunnel");
          }
          c.eq_u64(refuse_proxy.stats().decrypted, 2,
                   "only the two refused attempts were ever decrypted");
          refuse_proxy.stop();
        } else {
          c.ok(false, "the refusal proxy starts (" + refuse_error + ")");
        }

        // 11b. --mitm-strict makes no such trade: the same client keeps failing
        //      and nothing is remembered.
        {
          BlockerConfig strict_cfg = refuse_cfg;
          strict_cfg.mitm_strict = true;
          InterceptProxy strict_proxy;
          strict_proxy.set_client_resolver([](const std::string&, std::uint16_t) {
            return std::string("refuser.exe");
          });
          strict_proxy.set_origin_tls_ability("127.0.0.1", target, 1);
          std::string strict_error;
          if (strict_proxy.start(strict_cfg, &rs, &strict_error)) {
            for (int i = 0; i < 3; ++i) {
              knock(strict_proxy.port(), target);
              c.ok(strict_proxy.serve_once(6000), "the strict proxy served a CONNECT");
            }
            c.eq_u64(strict_proxy.stats().mitm_client_refusals, 0,
                     "--mitm-strict never retires a pair");
            const std::vector<InterceptEvent> strict_events = strict_proxy.events();
            bool any_skip = false;
            for (const InterceptEvent& event : strict_events) {
              if (event.mitm == "skip") any_skip = true;
            }
            c.ok(!any_skip, "--mitm-strict never tunnels the pair instead");
            strict_proxy.stop();
          } else {
            c.ok(false, "the strict proxy starts (" + strict_error + ")");
          }
        }
        std::remove(refuse_ca_crt.c_str());
        std::remove(refuse_ca_key.c_str());
      }

      // 12. a document whose only edit is the picker hook is still a rewrite, and
      //     the log has to name what did it: an empty rule column is what made a
      //     real `modify` row read as "it rewrote this without any rule".
      {
        const std::string doc = "<html><head><title>t</title></head><body>hi</body></html>";
        Origin hook_origin;
        c.ok(hook_origin.start("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
                                   std::to_string(doc.size()) + "\r\n\r\n" + doc,
                               false),
             "the picker-hook origin answers with a document");
        RuleSet hook_rules;
        hook_rules.load_text("||never-matches.invalid^\n");
        InterceptProxy hook_proxy;
        std::string hook_error;
        if (hook_proxy.start(cfg, &hook_rules, &hook_error)) {
          const std::string host_port = "127.0.0.1:" + std::to_string(hook_origin.port);
          std::thread client([&]() {
            Talk::run(hook_proxy.port(),
                      "GET http://" + host_port + "/page.html HTTP/1.1\r\nHost: " + host_port +
                          "\r\n\r\n",
                      false);
          });
          const bool served = hook_proxy.serve_once(4000);
          client.join();
          c.ok(served, "the picker-hook proxy served the document");
          const std::vector<InterceptEvent> hook_events = hook_proxy.events();
          c.eq_u64(hook_events.size(), 1, "one document is one event");
          if (!hook_events.empty()) {
            c.eq_str(intercept_action_name(hook_events[0].action), "modify",
                     "carrying the picker hook is what made this a rewrite");
            c.ok(hook_events[0].rule.find("picker") != std::string::npos,
                 "the rewrite names the picker hook instead of leaving the rule column empty "
                 "(got \"" +
                     hook_events[0].rule + "\")");
          }
          hook_proxy.stop();
        } else {
          c.ok(false, "the picker-hook proxy starts (" + hook_error + ")");
        }
      }

      // 13. `$third-party` and `$domain=` ask "which page asked for this?", and
      //     the proxy used to decide with an empty document, so neither option
      //     could ever match a proxied request.  The page host comes out of
      //     `Referer` (then `Origin`); without one, nothing is known and the
      //     request is left alone.
      {
        RuleSet tp_rules;
        tp_rules.load_text("/pixel.gif$third-party\n/only.gif$domain=example.com\n");
        InterceptProxy tp_proxy;
        std::string tp_error;
        if (tp_proxy.start(cfg, &tp_rules, &tp_error)) {
          // One request through the proxy, answered by a fresh one-shot origin.
          auto fetch = [&](const std::string& path, const std::string& referer,
                           std::string* seen) -> InterceptEvent {
            Origin origin;
            const std::string body = "<html><body>hit</body></html>";
            // `text/plain` on purpose: this case is about the rule decision, and
            // an HTML document would also collect the element-picker hook and be
            // reported as a rewrite instead of a plain pass.
            c.ok(origin.start("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
                                  std::to_string(body.size()) + "\r\n\r\n" + body,
                              false),
                 "the " + path + " origin answers");
            const std::string host_port = "127.0.0.1:" + std::to_string(origin.port);
            std::thread client([&]() {
              *seen = Talk::run(tp_proxy.port(),
                                "GET http://" + host_port + path + " HTTP/1.1\r\nHost: " + host_port +
                                    "\r\nReferer: " + referer + "\r\n\r\n",
                                false);
            });
            const bool served = tp_proxy.serve_once(4000);
            client.join();
            if (!served) return InterceptEvent();
            const std::vector<InterceptEvent> all = tp_proxy.events();
            return all.empty() ? InterceptEvent() : all.back();
          };

          std::string cross_reply;
          const InterceptEvent cross = fetch("/pixel.gif", "http://example.com/page.html", &cross_reply);
          c.eq_str(intercept_action_name(cross.action), "block",
                   "a $third-party rule fires for a subresource from another site");
          c.eq_str(cross.rule, "/pixel.gif$third-party", "the cross-site block names its rule");
          c.ok(cross_reply.find("hit") == std::string::npos,
               "a third-party block never reaches the origin");

          std::string same_reply;
          const InterceptEvent same = fetch("/pixel.gif", "http://127.0.0.1:9999/page.html", &same_reply);
          c.eq_str(intercept_action_name(same.action), "pass",
                   "the same $third-party rule leaves a same-site subresource alone");
          c.ok(same_reply.find("hit") != std::string::npos,
               "the same-site request is answered by the origin");

          std::string domain_reply;
          const InterceptEvent domain = fetch("/only.gif", "http://example.com/page.html", &domain_reply);
          c.eq_str(intercept_action_name(domain.action), "block",
                   "a $domain= rule fires on the site it names");
          c.eq_str(domain.rule, "/only.gif$domain=example.com", "the domain block names its rule");

          std::string other_reply;
          const InterceptEvent other =
              fetch("/only.gif", "http://other.example.org/page.html", &other_reply);
          c.eq_str(intercept_action_name(other.action), "pass",
                   "the same $domain= rule stays out of another site");
          c.ok(other_reply.find("hit") != std::string::npos, "the other site is answered by the origin");

          const BlockerStats tp_stats = tp_proxy.stats();
          c.eq_u64(tp_stats.blocked, 2, "exactly the two cross-site requests were blocked");
          c.eq_u64(tp_stats.passed, 2, "and exactly two were passed");
          tp_proxy.stop();
        } else {
          c.ok(false, "the third-party proxy starts (" + tp_error + ")");
        }
      }

      // 10. with no policy at all the same tunnel is reported as "off", so the
      //     interface can tell "the switch is off" from "this app is excluded".
      {
        Origin origin;
        c.ok(origin.start("PONG", true), "the second tunnel target listens");
        const u16 target = origin.port;
        BlockerConfig off_cfg = cfg;
        InterceptProxy off_proxy;
        off_proxy.set_client_resolver([](const std::string&, std::uint16_t) {
          return std::string("chrome.exe");
        });
        std::string off_error;
        if (off_proxy.start(off_cfg, &rs, &off_error)) {
          std::string seen;
          std::thread client([&]() {
            seen = Talk::run(off_proxy.port(),
                             "CONNECT 127.0.0.1:" + std::to_string(target) + " HTTP/1.1\r\n\r\n",
                             true);
          });
          const bool served = off_proxy.serve_once(6000);
          client.join();
          c.ok(served, "the plain proxy served the CONNECT");
          const std::vector<InterceptEvent> off_events = off_proxy.events();
          c.eq_u64(off_events.size(), 1, "the plain CONNECT produced one event");
          if (!off_events.empty()) {
            c.eq_str(off_events[0].mitm, "off",
                     "with no policy the event says HTTPS decryption is off");
            c.eq_str(off_events[0].client_proc, "chrome.exe", "the client is still named");
          }
          off_proxy.stop();
        } else {
          c.ok(false, "the plain proxy starts (" + off_error + ")");
        }
      }

      proxy.stop();
      c.ok(!proxy.running(), "the proxy stops");
    }
    c.ok(!error.empty() || started, "starting the proxy either works or explains why not");
  }
#endif
}

void test_rules(Ctx& c) {
  c.section("filter lists: parsing");
  {
    RuleSet rs;
    std::string why;
    c.ok(rs.add_line("||ads.example.com^", &why), "a domain-anchored rule parses");
    c.ok(rs.rules()[0].domain_anchor, "the rule is domain anchored");
    c.ok(rs.rules()[0].action() == RuleAction::Block, "an ordinary rule blocks");
    c.ok(!rs.add_line("! a comment", &why), "a comment is not a rule");
    c.ok(!rs.add_line("[Adblock Plus 2.0]", &why), "a list header is not a rule");
    c.ok(!rs.add_line("", &why), "an empty line is not a rule");
    c.ok(!rs.add_line("example.com##.ad-banner", &why), "an element hiding rule is not enforced");
    c.ok(rs.stats().element_hide == 1, "the cosmetic rule is counted");
    c.ok(!rs.add_line("/regex[0-9]+/", &why), "a regular expression pattern is refused");
    c.eq_str(why, "regular expression patterns are not supported",
             "the reason names the unsupported feature");
    c.ok(!rs.add_line("||example.com^$bogusopt", &why), "an unknown $option is refused");
    c.ok(why.find("unknown $bogusopt") != std::string::npos, "the reason names the option");
    c.eq_u64(rs.stats().skipped, 2, "both refusals are counted as skipped");
    c.eq_u64(rs.size(), 1, "only the one good rule is in the set");

    // Cosmetic rules: hiding an element is not blocking a request.  What they are
    // for is the CSS they produce for the page that carries the element.
    {
      RuleSet cos;
      std::string hide_why;
      c.ok(!cos.add_line("blog.csdn.net##.simple-ad-slot", &hide_why),
           "a host scoped hide rule is not a network rule");
      c.ok(!cos.add_line("##.generic-ad", &hide_why), "a generic hide rule is not a network rule");
      c.ok(!cos.add_line("blog.csdn.net#@#.keep-me", &hide_why), "an exception hide rule parses");
      c.ok(!cos.add_line("blog.csdn.net#?#.procedural:has(> .ad)", &hide_why),
           "a procedural #?# rule parses instead of being turned away");
      c.ok(hide_why.empty(), "and nothing is left to report (" + hide_why + ")");
      c.eq_u64(cos.stats().element_hide, 4, "all four cosmetic rules were taken");
      c.eq_u64(cos.stats().skipped, 0, "none of them is a refusal");
      c.eq_u64(cos.cosmetics().size(), 2, "the two plain hide rules stay CSS");
      c.eq_u64(cos.cosmetic_exceptions().size(), 1, "one exception is stored");
      c.eq_u64(cos.procedural().size(), 1, "the #?# rule is stored as a program instead");
      c.eq_u64(cos.procedural_exceptions().size(), 0, "with no procedural exception");

      const std::string csdn = cos.cosmetic_css("blog.csdn.net");
      c.ok(csdn.find(".simple-ad-slot{display:none !important}") != std::string::npos,
           "the selector becomes hiding CSS");
      c.ok(csdn.find(".generic-ad{display:none !important}") != std::string::npos,
           "a generic rule applies everywhere");
      c.ok(csdn.find(".keep-me") == std::string::npos, "the exception is not hidden");
      c.ok(cos.cosmetic_css("example.com").find(".simple-ad-slot") == std::string::npos,
           "a host scoped rule stays off other sites");
      c.ok(cos.cosmetic_css("example.com").find(".generic-ad") != std::string::npos,
           "the generic rule still applies there");
      c.ok(cos.cosmetic_css("www.blog.csdn.net").find(".simple-ad-slot") != std::string::npos,
           "a subdomain of the listed host matches");
      // Proxied origins on an explicit port (every local test server) must still
      // match domain-scoped hiding rules.
      c.ok(cos.cosmetic_css("blog.csdn.net:8443").find(".simple-ad-slot") != std::string::npos,
           "an explicit port does not break element hiding");
      c.ok(cos.cosmetic_css("example.com:8080").find(".simple-ad-slot") == std::string::npos,
           "and the rule still stays off other sites");
      // A reply that cannot render a page only needs the site-scoped rules: the
      // generic ones would be injected into every API call for nothing.
      c.ok(cos.cosmetic_css("blog.csdn.net", nullptr, false).find(".simple-ad-slot") != std::string::npos,
           "a host scoped hide rule is applied to any reply");
      c.ok(cos.cosmetic_css("blog.csdn.net", nullptr, false).find(".generic-ad") == std::string::npos,
           "a generic hide rule is left out when the reply is not a page");
      c.ok(cos.cosmetic_css("blog.csdn.net").find(".generic-ad") != std::string::npos,
           "and it is back on by default");
      // The same page's procedural half: it is not CSS, so it is handed over as a
      // compiled program instead, and only to the host the rule names.
      {
        std::string program_source;
        const std::vector<CosmeticProgram> programs =
            cos.procedural_programs("blog.csdn.net", &program_source);
        c.eq_u64(programs.size(), 1, "the program goes to the host that asked for it");
        c.ok(programs[0].base == ".procedural", "its static half is the base (" + programs[0].base + ")");
        c.eq_u64(programs[0].ops.size(), 1, "one operator came along");
        c.ok(programs[0].ops[0].kind == CosmeticOp::Kind::Has, "and it is the :has()");
        c.ok(programs[0].ops[0].arg == ":scope > .ad",
             "a relative argument is anchored to the element (" + programs[0].ops[0].arg + ")");
        c.ok(program_source.find("blog.csdn.net##.procedural:has(") != std::string::npos,
             "the log names it the way the list writes it (" + program_source + ")");
        c.eq_u64(cos.procedural_programs("example.com").size(), 0, "another host gets nothing");
      }
      // `:has()` hides a container based on what it *contains*, and whether that
      // container is an ad or the page's own results is not something the proxy
      // can check.  EasyList's two Bing rules hid every organic result on
      // cn.bing.com, so those selectors never go into the CSS: the page runs them
      // instead, where the engine can be told which of the two rules it is.
      {
        RuleSet has_set;
        std::string why;
        has_set.add_line("bing.com##.b_algo:has(.b_lineclamp2):not(:has([data-rslinkclamp-iid]))", &why);
        has_set.add_line("bing.com##.b_ad", &why);
        c.eq_u64(has_set.cosmetics().size(), 1, "the plain hide rule stays CSS");
        c.eq_u64(has_set.procedural().size(), 1, "the :has() rule becomes a program");
        const std::string css = has_set.cosmetic_css("cn.bing.com");
        c.ok(css.find(":has(") == std::string::npos, "a :has() selector is still kept out of the CSS");
        c.ok(css.find(".b_ad{display:none !important}") != std::string::npos,
             "a plain hide rule on the same host still applies");
        std::string program_source;
        const std::vector<CosmeticProgram> programs =
            has_set.procedural_programs("cn.bing.com", &program_source);
        c.eq_u64(programs.size(), 1, "the program goes to the host the rule names");
        c.ok(programs[0].base == ".b_algo", "the base is the plain part (" + programs[0].base + ")");
        c.eq_u64(programs[0].ops.size(), 2, "both operators came along");
        c.ok(programs[0].ops[0].kind == CosmeticOp::Kind::Has, "the first is :has(...)");
        c.ok(programs[0].ops[1].kind == CosmeticOp::Kind::Not, "the second is :not(...)");
        c.eq_u64(programs[0].ops[1].nested.size(), 1, "and the :not() carries a nested operator");
        c.ok(program_source.find("cn.bing.com##.b_algo:has(") != std::string::npos,
             "the log names it the way the list writes it (" + program_source + ")");
        // `#@?#` switches a program off exactly like `#@#` does for the CSS.
        RuleSet excepted;
        excepted.add_line("cn.bing.com#?#.procedural:has(> .ad)", &why);
        c.eq_u64(excepted.procedural_programs("cn.bing.com").size(), 1, "a #?# rule is live");
        excepted.add_line("cn.bing.com#@?#.procedural:has(> .ad)", &why);
        c.eq_u64(excepted.procedural_programs("cn.bing.com").size(), 0,
                 "a #@?# exception switches it off again");
        // A reply that cannot render a page gets no domain-less programs either.
        RuleSet generic_programs;
        generic_programs.add_line("#?#.ad:has(> .x)", &why);
        c.eq_u64(generic_programs.procedural_programs("example.com").size(), 1,
                 "a generic program applies everywhere");
        c.eq_u64(generic_programs.procedural_programs("example.com", nullptr, false).size(), 0,
                 "unless the reply cannot render a page");
      }
      // The compiler and the engine the page runs.  These are strings in and
      // strings out on purpose: every operator is checked here, without a browser.
      {
        std::string why;
        CosmeticProgram program;
        c.ok(cosmetic_compile(".ad:has(> .x)", &program, &why), "a :has() selector compiles");
        c.ok(program.base == ".ad", "its base is what comes before the operator (" + program.base + ")");
        c.eq_u64(program.ops.size(), 1, "one operator came out");
        c.ok(program.ops[0].arg == ":scope > .x",
             "a relative :has() argument is anchored (" + program.ops[0].arg + ")");
        c.ok(cosmetic_selector_is_procedural(".ad:has(> .x)"), "and it is procedural");
        c.ok(!cosmetic_selector_is_procedural(".ad"), "a plain selector is not");
        c.eq_str(cosmetic_operators_in(".ad:has(> .x):upward(2)"), "has, upward",
                 "the operators have names, for the log");
        c.ok(!cosmetic_compile(".ad:matches-media(screen)", &program, &why),
             "an operator we do not run is refused");
        c.ok(why.find("matches-media") != std::string::npos, "and the reason names it (" + why + ")");
        c.ok(cosmetic_compile(":upward(2)", &program, &why), ":upward() alone compiles");
        c.ok(program.base == "*", "with no base left, the engine starts from everything");
        c.ok(program.ops[0].kind == CosmeticOp::Kind::Upward && program.ops[0].number == 2,
             ":upward(2) carries the count with it");
        c.ok(cosmetic_compile(".ad", &program, &why) && program.ops.empty(),
             "a selector without an operator has no program");
        // The JSON the page receives.  A selector that carries `<`, `>` or `&`
        // must not be able to close the <script> it is inlined into.
        std::vector<CosmeticProgram> escaped;
        CosmeticProgram special;
        special.base = "a[href*=\"<\"] > b";
        special.raw = special.base;
        escaped.push_back(special);
        const std::string json = cosmetic_program_json(escaped);
        c.ok(json.find('<') == std::string::npos && json.find('>') == std::string::npos,
             "the JSON escapes them (" + json + ")");
        c.ok(json.find("\\u003c") != std::string::npos, "as \\u003c");
        CosmeticProgram removal;
        removal.base = ".card";
        removal.remove = true;
        removal.raw = ".card";
        const std::string removal_json = cosmetic_program_json({removal});
        c.ok(removal_json.find("\"a\":\"remove\"") != std::string::npos,
             "`{ remove: true; }` travels as an action (" + removal_json + ")");
        const std::string engine = cosmetic_engine_script();
        c.ok(engine.size() > 1000,
             "the engine script is substantial (" + std::to_string(engine.size()) + " bytes)");
        c.ok(engine.find("__ncCos") != std::string::npos, "it reads what the bootstrap left");
        c.ok(engine.find("MutationObserver") != std::string::npos, "it watches for late elements");
        c.ok(engine.find("</script") == std::string::npos, "and cannot end the <script> it sits in");
        c.ok(engine.find("=>") == std::string::npos, "it is plain ES5, no arrow functions");
        const std::string bootstrap = cosmetic_bootstrap_script(json);
        c.ok(bootstrap.find("__ncCos") != std::string::npos, "the bootstrap carries the programs");
        c.ok(bootstrap.find(kCosmeticScriptPath) != std::string::npos, "and pulls in the engine");
        c.ok(cosmetic_bootstrap_script("").empty(), "with no programs nothing is injected at all");
        c.ok(cosmetic_is_script_path("/__netcap/cosmetic.js?v=3"), "the engine route takes a query");
        c.ok(!cosmetic_is_script_path("/__netcap/picker.js"), "and it is not the picker's route");
      }
      // `#$#` declarations and `{ remove: true; }`: the first is still CSS, the
      // second needs the DOM.  `#%#` (scriptlet injection) is a different feature
      // and is now skipped by name instead of read as a broken network rule.
      {
        std::string why;
        RuleSet decl;
        c.ok(!decl.add_line("example.com#$#.ad { display: block; }", &why), "a #$# rule parses");
        c.ok(decl.cosmetic_css("example.com").find(".ad{display: block;}") != std::string::npos,
             "its declarations replace the hiding (" + decl.cosmetic_css("example.com") + ")");
        c.eq_u64(decl.procedural().size(), 0, "and it does not need the engine");
        RuleSet removal;
        c.ok(!removal.add_line("example.com#$#.card { remove: true; }", &why), "a remove:true rule parses");
        c.eq_u64(removal.procedural().size(), 1, "it needs the engine");
        const std::vector<CosmeticProgram> removals = removal.procedural_programs("example.com");
        c.eq_u64(removals.size(), 1, "and it is handed over");
        c.ok(removals[0].remove, "as a removal, not a hiding");
        RuleSet scriptlet;
        std::string scriptlet_why;
        scriptlet.add_line("example.com#%#window.x=1", &scriptlet_why);
        c.ok(scriptlet_why.find("scriptlet") != std::string::npos,
             "a #%# scriptlet is skipped by name (" + scriptlet_why + ")");
        c.eq_u64(scriptlet.stats().skipped, 1, "and it is counted, not silently dropped");
      }
      // The CSS alone does not say *which* rule hid the element; the source list
      // does, and it is spelled the way it would be written in the list file.
      std::string cosmetic_source;
      cos.cosmetic_css("blog.csdn.net", &cosmetic_source);
      c.ok(cosmetic_source.find("blog.csdn.net##.simple-ad-slot") != std::string::npos,
           "the cosmetic source names the host scoped rule (" + cosmetic_source + ")");
      c.ok(cosmetic_source.find("##.generic-ad") == std::string::npos,
           "a generic rule is not named when the site has rules of its own");
      c.ok(cosmetic_source.find(" more)") != std::string::npos,
           "the generic half is counted instead (" + cosmetic_source + ")");
      c.ok(cosmetic_source.find(".keep-me") == std::string::npos,
           "an excepted selector is not named");
      // --rules-extra / --check-rule plumbing (the rules page in the interface uses
      // both): several lists stack into one RuleSet, and validating a single line
      // reports a reason exactly when the engine would skip it.
      {
        RuleSet stacked;
        std::string why;
        stacked.load_text("||first.example^\n", &why);
        const std::size_t first = stacked.rules().size();
        stacked.load_text("||second.example^\n! a comment\n", &why);
        c.eq_u64(stacked.rules().size(), first + 1, "a second list stacks onto the first");
        why.clear();
        c.ok(stacked.add_line("||third.example^$script=alert(1)", &why) && why.empty(),
             "a good rule is accepted without a reason");
        why.clear();
        c.ok(!stacked.add_line("! just a comment", &why) && why.empty(),
             "a comment is accepted and carries no reason");
        why.clear();
        const bool rejected = stacked.add_line(std::string(20000, 'x'), &why);
        c.ok(!rejected && !why.empty(), "an over-long line is rejected with a reason (" + why + ")");
      }

      // Same idea for the network rules: the plan carries the rule that made it.
      RuleSet rw_src;
      rw_src.add_line("||example.com^$css=body{color:red}");
      ResponseRewrite plan;
      c.ok(rw_src.collect_response_rewrite(
               rule_request_from_url("https://example.com/a.js", "", ResourceType::Script), &plan),
           "the response rule produces a plan");
      c.eq_str(plan.source, "||example.com^$css=body{color:red}", "the plan names its rule");
      c.eq_u64(plan.source_count, 1, "one rule contributed");

      // HTTP/3: the browser only learns about it from Alt-Svc, and an HTTP proxy
      // can never follow the UDP that follows - so the header goes away.
      const std::string with_alt =
          "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
          "Alt-Svc: h3=\":443\"; ma=86400, h3-29=\":443\"\r\nContent-Length: 3\r\n\r\n";
      const std::string stripped = strip_alt_svc_header(with_alt);
      c.ok(stripped.find("Alt-Svc") == std::string::npos, "Alt-Svc is removed from the head");
      c.ok(stripped.find("h3=") == std::string::npos, "and its value goes with it");
      c.ok(stripped.find("Content-Type: text/html") != std::string::npos &&
               stripped.find("Content-Length: 3") != std::string::npos,
           "every other header is left alone, in order");
      c.ok(stripped.size() > 4 && stripped.compare(stripped.size() - 4, 4, "\r\n\r\n") == 0,
           "the head keeps its terminating CRLFCRLF");
      c.eq_str(strip_alt_svc_header("HTTP/1.1 204 No Content\r\n\r\n"),
               "HTTP/1.1 204 No Content\r\n\r\n", "a head without Alt-Svc is unchanged");

      RuleSet cancelled;
      cancelled.add_line("blog.csdn.net##.ad");
      cancelled.add_line("blog.csdn.net#@#.ad");
      c.ok(cancelled.cosmetic_css("blog.csdn.net").empty(), "#@# cancels the hide rule there");
      c.ok(!cancelled.cosmetic_css("news.example.com").empty() == false, "and only there");

      RuleSet listed;
      listed.add_line("~news.example.com,blog.csdn.net##.ad");
      c.ok(!listed.cosmetic_css("blog.csdn.net").empty(), "the include list matches");
      c.ok(listed.cosmetic_css("news.example.com").empty(), "a ~ entry excludes a host");

      // And the CSS really does reach the page: the same injection path that $css
      // uses carries it into the document.
      ResponseRewrite inject;
      inject.inject_css.push_back(cos.cosmetic_css("blog.csdn.net"));
      ResponseHead page_head;
      const std::string raw_head =
          "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 52\r\n\r\n";
      std::string head_why;
      c.ok(parse_response_head(raw_head, &page_head, &head_why), "the synthetic response head parses");
      std::string page = "<html><head><title>t</title></head><body>hello</body></html>";
      ResponseRewriteReport report;
      c.ok(apply_response_rewrite(inject, &page_head, &page, &report, &head_why),
           "the cosmetic CSS is injected into the page");
      c.ok(page.find(".simple-ad-slot{display:none !important}") != std::string::npos,
           "the document carries the hiding rule");
      c.ok(page.find("<style") != std::string::npos, "…inside a style element");
      c.ok(report.changed, "an injected style is a real change");

      // A reply that cannot render a page must not be reported as rewritten just
      // because a cosmetic rule matched it: the bytes are the origin's.
      ResponseRewrite json_only;
      json_only.inject_css.push_back(cos.cosmetic_css("blog.csdn.net"));
      ResponseHead json_head;
      c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n",
                               &json_head, &head_why),
           "the JSON head parses");
      std::string json_body = "{\"a\":1}";
      ResponseRewriteReport json_report;
      c.ok(apply_response_rewrite(json_only, &json_head, &json_body, &json_report, &head_why),
           "the pass itself still succeeds");
      c.ok(!json_report.changed, "but a JSON reply counts as unchanged");
      c.eq_str(json_body, "{\"a\":1}", "and its body is exactly what the origin sent");

      // EasyList's generic half is a few hundred selectors long, and every one of
      // them applies to every document: naming all of them in the log buried the
      // rule a reader wanted and turned a 13-line export into 1.2 MB.  The CSS
      // still carries every selector; only the attribution is summarised.
      RuleSet many;
      for (int i = 0; i < 12; ++i) many.add_line("##.generic-ad-" + std::to_string(i));
      std::string many_source;
      const std::string many_css = many.cosmetic_css("example.com", &many_source, true);
      c.ok(many_css.find("generic-ad-11") != std::string::npos,
           "every generic selector still reaches the CSS");
      c.ok(many_source.find("##.generic-ad-0") != std::string::npos,
           "the log still names the first selectors");
      c.ok(many_source.find("generic-ad-11") == std::string::npos,
           "but it does not paste the whole list into the entry");
      c.ok(many_source.find("(+6 more)") != std::string::npos, "and it says how many it left out");

      // A site's own rules are what a reader is looking for.  EasyList's generic
      // half matched first in file order and used to be the only thing named, so
      // a page cleaned up by `onlinedown.net##.m-con-right` read as if `###AC_ad`
      // had done it.
      RuleSet mixed;
      for (int i = 0; i < 12; ++i) mixed.add_line("##.generic-ad-" + std::to_string(i));
      mixed.add_line("onlinedown.net##.m-con-right");
      std::string mixed_source;
      const std::string mixed_css = mixed.cosmetic_css("www.onlinedown.net", &mixed_source, true);
      c.ok(mixed_css.find("m-con-right") != std::string::npos, "the site rule reaches the CSS");
      c.ok(mixed_source.find("www.onlinedown.net##.m-con-right") != std::string::npos,
           "and the site rule is the one named in the log");
      c.ok(mixed_source.find("generic-ad-0") == std::string::npos,
           "the generic half is not named once a site rule applies");
      c.ok(mixed_source.find("(+12 more)") != std::string::npos,
           "the unnamed generic rules are still counted");
      c.eq_str(intercept_action_name(InterceptAction::Cancelled), "cancelled",
               "a client that hangs up gets its own action instead of error");

      // A chunked image matched by two hundred generic hiding rules used to be
      // reported as `改写`: the body was taken apart to inject a <style> that a
      // PNG cannot carry.  Nothing about it should be touched now.
      ResponseRewrite png_only;
      png_only.inject_css.push_back(cos.cosmetic_css("blog.csdn.net"));
      ResponseHead png_head;
      c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
                               "Transfer-Encoding: chunked\r\n\r\n",
                               &png_head, &head_why),
           "the chunked PNG head parses");
      std::string png_body = "4\r\nabcd\r\n0\r\n\r\n";
      const std::string png_original = png_body;
      ResponseRewriteReport png_report;
      c.ok(apply_response_rewrite(png_only, &png_head, &png_body, &png_report, &head_why),
           "the pass itself still succeeds for an image");
      c.ok(!png_report.changed, "but a chunked PNG counts as unchanged");
      c.ok(png_report.skipped_no_body, "and says there was no body it could edit");
      c.ok(png_report.note.find("media type") != std::string::npos,
           "naming the media type as the reason");
      c.eq_str(png_body, png_original, "the chunked bytes are exactly what the origin sent");
      c.ok(png_head.serialize().find("Transfer-Encoding: chunked") != std::string::npos,
           "and the framing is left alone");

      // A $replace that matches nothing is the same story.
      ResponseRewrite miss;
      RewriteReplace no_hit;
      no_hit.pattern = "nothing-like-this";
      no_hit.replacement = "x";
      miss.replaces.push_back(no_hit);
      ResponseHead miss_head;
      c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 27\r\n\r\n",
                               &miss_head, &head_why),
           "the second head parses");
      std::string miss_body = "<html><body>hi</body></html>";
      ResponseRewriteReport miss_report;
      c.ok(apply_response_rewrite(miss, &miss_head, &miss_body, &miss_report, &head_why),
           "the pass succeeds");
      c.ok(!miss_report.changed, "a $replace that matched nothing is not a change");

      ResponseRewrite hit;
      RewriteReplace matched;
      matched.pattern = "hi";
      matched.replacement = "ho";
      hit.replaces.push_back(matched);
      ResponseHead hit_head;
      c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 27\r\n\r\n",
                               &hit_head, &head_why),
           "the third head parses");
      std::string hit_body = "<html><body>hi</body></html>";
      ResponseRewriteReport hit_report;
      c.ok(apply_response_rewrite(hit, &hit_head, &hit_body, &hit_report, &head_why),
           "the hit pass succeeds");
      c.ok(hit_report.changed, "a $replace that matched is a change");
      c.ok(hit_body.find("ho") != std::string::npos, "and the body carries the replacement");

      // A compressed body must not be inflated just because a cosmetic rule is in
      // scope.  A `br` script is not `text/html`, so nothing can be injected into
      // it: inflating it would send the client several times the origin's bytes
      // (and report a rewrite of bytes that never moved).
      const std::string script = "var a = 1; var b = 2;";
      std::string packed;
      c.ok(brotli_compress_stored(reinterpret_cast<const u8*>(script.data()), script.size(),
                                  &packed, &head_why),
           "a stored brotli stream is built");
      ResponseRewrite br_css;
      br_css.inject_css.push_back(cos.cosmetic_css("blog.csdn.net"));
      ResponseHead br_head;
      c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                               "Content-Encoding: br\r\nContent-Length: " +
                                   std::to_string(packed.size()) + "\r\n\r\n",
                               &br_head, &head_why),
           "the brotli script head parses");
      std::string br_body = packed;
      ResponseRewriteReport br_report;
      c.ok(apply_response_rewrite(br_css, &br_head, &br_body, &br_report, &head_why),
           "the pass succeeds");
      c.ok(!br_report.changed, "a compressed script that nothing can edit is not a change");
      c.ok(!br_report.decoded, "and it is not inflated");
      c.ok(br_head.find("content-encoding") != nullptr, "its Content-Encoding survives");
      c.eq_str(br_body, packed, "its bytes are exactly what the origin sent");
      c.ok(br_report.note.find("stays br") != std::string::npos, "and the note says why");

      // The same kind of body with an edit that really can apply is inflated.
      const std::string script2 = "var a = 1; var b = 2;";
      std::string packed2;
      c.ok(brotli_compress_stored(reinterpret_cast<const u8*>(script2.data()), script2.size(),
                                  &packed2, &head_why),
           "a second stream is built");
      ResponseRewrite br_replace;
      RewriteReplace swap;
      swap.pattern = "var b = 2";
      swap.replacement = "var b = 3";
      br_replace.replaces.push_back(swap);
      ResponseHead br_head2;
      c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                               "Content-Encoding: br\r\nContent-Length: " +
                                   std::to_string(packed2.size()) + "\r\n\r\n",
                               &br_head2, &head_why),
           "the second brotli head parses");
      std::string br_body2 = packed2;
      ResponseRewriteReport br_report2;
      c.ok(apply_response_rewrite(br_replace, &br_head2, &br_body2, &br_report2, &head_why),
           "the replace pass succeeds");
      c.ok(br_report2.changed && br_report2.decoded, "a $replace on a text body is inflated");
      c.ok(br_body2.find("var b = 3") != std::string::npos, "and the replacement landed");

      // A page is the case the gate must let through: the same compressed body,
      // but `text/html` with a cosmetic rule in scope, has to be inflated and
      // edited.
      {
        RuleSet generic;
        // add_line() reports false for a cosmetic line: it parsed, but it is not
        // a network rule, so the count is the assertion.
        generic.add_line("##.ad-box");
        c.eq_u64(generic.cosmetics().size(), 1, "a site wide cosmetic rule parses");
        const std::string css = generic.cosmetic_css("example.com", nullptr, true);
        c.ok(css.find(".ad-box{display:none !important}") != std::string::npos,
             "it produces CSS for any host");
        const std::string page = "<html><head><title>t</title></head><body>ok</body></html>";
        std::string packed_page;
        c.ok(brotli_compress_stored(reinterpret_cast<const u8*>(page.data()), page.size(),
                                    &packed_page, &head_why),
             "the page is compressed");
        ResponseRewrite page_rewrite;
        page_rewrite.inject_css.push_back(css);
        ResponseHead page_br_head;
        c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                                 "Content-Encoding: br\r\nContent-Length: " +
                                     std::to_string(packed_page.size()) + "\r\n\r\n",
                                 &page_br_head, &head_why),
             "the compressed page head parses");
        std::string page_body = packed_page;
        ResponseRewriteReport page_report;
        c.ok(apply_response_rewrite(page_rewrite, &page_br_head, &page_body, &page_report,
                                    &head_why),
             "the page pass succeeds");
        c.ok(page_report.decoded && page_report.changed, "a compressed page is inflated and edited");
        c.ok(page_br_head.find("content-encoding") == nullptr,
             "and the encoding header is gone once the body is identity");
        c.ok(page_body.find(".ad-box{display:none !important}") != std::string::npos,
             "the page carries the hiding rule");
      }

      // The same page, but this time the edit makes it much smaller: the encoder
      // has to notice that the result still fits in the bytes the origin spent and
      // put it back out as `br` instead of identity.  That is the property the QUIC
      // path needs -- a packet cannot grow -- and it is the "deletion" tier of a
      // rewrite.
      {
        std::string big = "<html><head><title>t</title></head><body>";
        big.append(100000, 'a');
        big += "</body></html>";
        std::string packed_big;
        // The origin's bytes come from the decoder side's stored writer on purpose:
        // this case is about putting an edited body *back* into a `br` slot, not
        // about how well the encoder compresses.
        c.ok(brotli_compress_stored(reinterpret_cast<const u8*>(big.data()), big.size(), &packed_big,
                                    &head_why),
             "the long page has a valid br body");
        RuleSet shrink;
        shrink.add_line("||127.0.0.1^$replace=/aaaa+/b/");
        RuleRequest req = rule_request_from_url("http://127.0.0.1:8899/page.html", "",
                                                ResourceType::Document);
        ResponseRewrite plan;
        std::string plan_why;
        c.ok(shrink.collect_response_rewrite(req, &plan),
             "the shrink rule plans a rewrite");
        ResponseHead shrink_head;
        c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                                 "Content-Encoding: br\r\nContent-Length: " +
                                     std::to_string(packed_big.size()) + "\r\n\r\n",
                                 &shrink_head, &head_why),
             "the long page head parses");
        std::string shrink_body = packed_big;
        ResponseRewriteReport shrink_report;
        c.ok(apply_response_rewrite(plan, &shrink_head, &shrink_body, &shrink_report, &head_why),
             "the shrink pass succeeds");
        c.ok(shrink_report.decoded && shrink_report.body_changed, "the page was inflated and edited");
        c.ok(shrink_body.size() <= packed_big.size(), "what we send is no larger than the origin");
        // Two legal outcomes: the encoder fitted the edited page back into the
        // origin's byte budget (then it must be a `br` stream we can read), or it
        // did not and the page goes out as identity.  What must never happen is a
        // body that claims `br` and does not decode.
        std::string unpacked;
        if (shrink_head.find("content-encoding") != nullptr) {
          c.ok(brotli_decompress(shrink_body, &unpacked, &head_why),
               "a body we put back as br decodes");
        } else {
          unpacked = shrink_body;
          c.ok(!shrink_report.dropped_encoding || shrink_body.size() < packed_big.size(),
               "the body went out as identity");
        }
        // `bytes_out` is what goes on the wire, which may be the compressed form;
        // the claim to check is about the decoded bytes: the edit really shrank
        // the page and it is still the same document.
        c.ok(unpacked.size() < big.size() / 2 && unpacked.find("</body>") != std::string::npos,
             "and it is the edited page");
        // Tier three: an edit that makes the page *bigger*.  It may only go back
        // out as `br` while the encoder still fits it into the origin's budget;
        // otherwise the client gets identity.  What it must never get is a
        // compressed stream that does not decode.
        {
          std::string noisy;
          noisy.reserve(1100);
          std::uint32_t seed = 12345;
          for (int i = 0; i < 1000; ++i) {
            seed = seed * 1103515245u + 12345u;
            noisy.push_back(static_cast<char>(33 + (seed >> 16) % 90));
          }
          const std::string grow_page =
              "<html><head><title>grow</title></head><body><p>" + noisy + "</p></body></html>";
          std::string grow_packed;
          c.ok(brotli_compress_stored(reinterpret_cast<const u8*>(grow_page.data()),
                                      grow_page.size(), &grow_packed, &head_why),
               "the growing page has a valid br body");
          RuleSet grow_rules;
          grow_rules.add_line("||127.0.0.1^$css=.extra{display:none!important}");
          RuleRequest grow_req = rule_request_from_url("http://127.0.0.1:8899/grow.html", "",
                                                       ResourceType::Document);
          ResponseRewrite grow_plan;
          std::string grow_plan_why;
          c.ok(grow_rules.collect_response_rewrite(grow_req, &grow_plan),
               "the injection rule plans a rewrite");
          ResponseHead grow_head;
          c.ok(parse_response_head("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                                   "Content-Encoding: br\r\nContent-Length: " +
                                       std::to_string(grow_packed.size()) + "\r\n\r\n",
                                   &grow_head, &head_why),
               "the growing page head parses");
          std::string grow_body = grow_packed;
          ResponseRewriteReport grow_report;
          c.ok(apply_response_rewrite(grow_plan, &grow_head, &grow_body, &grow_report, &head_why),
               "the growing pass succeeds");
          c.ok(grow_body.size() <= grow_packed.size(), "we never send more than the origin spent");
          std::string grow_check;
          if (grow_head.find("content-encoding") != nullptr) {
            c.ok(brotli_decompress(grow_body, &grow_check, &head_why),
                 "a br reply we send back decodes");
          } else {
            grow_check = grow_body;
          }
          c.ok(grow_check.find(".extra{display:none") != std::string::npos,
               "and the injection reaches the client either way");
        }
      }
    }

    RuleSet host;
    c.ok(host.add_line("0.0.0.0 ads.tracker.com"), "a hosts line parses");
    c.ok(host.add_line("0.0.0.0 a.tracker.com b.tracker.com"), "a hosts line may carry two names");
    c.ok(host.add_line("ads2.tracker.com"), "a single-column hosts line parses");
    c.eq_u64(host.size(), 4, "four host rules");
    c.eq_u64(host.stats().host_rules, 4, "all four are indexed by host name");
    c.ok(host.host_blocked("ads.tracker.com"), "the host is blocked");
    c.ok(host.host_blocked("sub.ads.tracker.com"), "subdomains are blocked too");
    c.ok(!host.host_blocked("tracker.com"), "the parent domain alone is not blocked");
    c.ok(!host.host_blocked("notads.tracker.com"), "an unrelated host is not blocked");
    c.ok(host.host_rule("a.tracker.com") != nullptr, "the host rule can be looked up");
    c.ok(host.host_rule("nope.tracker.com") == nullptr, "an unknown host has no rule");
  }

  c.section("filter lists: matching");
  {
    RuleSet rs;
    rs.load_text(
        "||ads.example.com^\n"
        "||example.com^\n"
        "||track.io^$third-party\n"
        "||cdn.io/lib.js$script\n"
        "||example.com/*/ads.js\n"
        "-advertisement-\n"
        "|http://track.test.net/\n"
        "/banner.gif|\n");
    const RuleRequest js = rule_request_from_url("https://ads.example.com/banner.js", "news.org");
    const RuleDecision dec = rs.decide(js);
    c.ok(dec.action == RuleAction::Block, "a domain-anchored rule blocks the URL");
    c.ok(dec.rule != nullptr && dec.rule->domain_anchor,
         "the blocking rule is the domain-anchored one");
    c.ok(dec.rule != nullptr && dec.rule->line == 1, "the first matching rule is reported");
    const RuleRequest other = rule_request_from_url("https://other.example/banner.js", "news.org");
    c.ok(rs.decide(other).action == RuleAction::None, "an unrelated URL is not blocked");
    const RuleRequest suffix = rule_request_from_url("https://example.com.evil.net/x", "news.org");
    c.ok(rs.decide(suffix).action == RuleAction::None,
         "^ refuses to match a longer host name");
    const RuleRequest deep = rule_request_from_url("https://a.b.ads.example.com/x", "news.org");
    c.ok(rs.decide(deep).action == RuleAction::Block, "a deep subdomain is still matched");
    const RuleRequest wild = rule_request_from_url("https://example.com/a/b/ads.js", "news.org");
    c.ok(rs.decide(wild).action == RuleAction::Block, "* matches across path segments");
    const RuleRequest substr = rule_request_from_url("https://x.net/-advertisement-/a", "news.org");
    c.ok(rs.decide(substr).action == RuleAction::Block, "a plain substring rule matches");
    const RuleRequest substr_no = rule_request_from_url("https://x.net/advertisement/a", "news.org");
    c.ok(rs.decide(substr_no).action == RuleAction::None, "the substring must match exactly");
    const RuleRequest start =
        rule_request_from_url("http://track.test.net/pixel", "news.org");
    c.ok(rs.decide(start).action == RuleAction::Block, "a start-anchored rule matches its prefix");
    c.ok(rs.decide(start).rule != nullptr && rs.decide(start).rule->line == 7,
         "the start-anchored rule is the one that matched");
    const RuleRequest start_no =
        rule_request_from_url("https://track.test.net/pixel", "news.org");
    c.ok(rs.decide(start_no).action == RuleAction::None, "a start-anchored rule needs the prefix");
    const RuleRequest end = rule_request_from_url("https://x.net/img/banner.gif", "news.org");
    c.ok(rs.decide(end).action == RuleAction::Block, "an end-anchored rule matches its suffix");
    const RuleRequest end_no = rule_request_from_url("https://x.net/img/banner.gif?v=2", "news.org");
    c.ok(rs.decide(end_no).action == RuleAction::None, "an end-anchored rule needs the URL to end");

    const RuleRequest same_site = rule_request_from_url("https://track.io/x", "track.io");
    c.ok(rs.decide(same_site).action == RuleAction::None,
         "$third-party does not fire for a first-party request");
    const RuleRequest third = rule_request_from_url("https://track.io/x", "news.org");
    c.ok(rs.decide(third).action == RuleAction::Block, "$third-party fires for a third party");

    RuleRequest img = rule_request_from_url("https://cdn.io/lib.js", "news.org", ResourceType::Image);
    c.ok(rs.decide(img).action == RuleAction::None, "$script ignores an image");
    RuleRequest script =
        rule_request_from_url("https://cdn.io/lib.js", "news.org", ResourceType::Script);
    c.ok(rs.decide(script).action == RuleAction::Block, "$script blocks a script");
  }

  c.section("filter lists: exceptions, rewriting and options");
  {
    RuleSet rs;
    rs.load_text(
        "||ads.example.com^\n"
        "@@||ads.example.com/allowed.js\n"
        "@@||safe.example.com^\n"
        "||safe.example.com^\n"
        "$important\n"
        "||pinned.io^$important\n"
        "@@||pinned.io^\n"
        "||utm.io^$removeparam=utm_source\n"
        "||stub.io^$redirect=noop.js\n"
        "||dom.io^$domain=good.com|~bad.com\n"
        "Foo/Bar$match-case\n");
    const RuleRequest allowed =
        rule_request_from_url("https://ads.example.com/allowed.js", "news.org");
    c.ok(rs.decide(allowed).action == RuleAction::Allow, "an exception rule allows the URL");
    c.ok(rs.decide(allowed).allowed_by_exception, "the decision says it was an exception");
    const RuleRequest still =
        rule_request_from_url("https://ads.example.com/other.js", "news.org");
    c.ok(rs.decide(still).action == RuleAction::Block, "the exception is path specific");
    const RuleRequest important = rule_request_from_url("https://pinned.io/x", "news.org");
    c.ok(rs.decide(important).action == RuleAction::Block, "$important beats an exception");
    const RuleRequest rewritten = rule_request_from_url("https://utm.io/x", "news.org");
    c.ok(rs.decide(rewritten).action == RuleAction::Modify, "$removeparam rewrites instead");
    c.eq_str(rs.decide(rewritten).value, "utm_source", "the parameter to strip is reported");
    const RuleRequest stub = rule_request_from_url("https://stub.io/x", "news.org");
    c.ok(rs.decide(stub).action == RuleAction::Redirect, "$redirect is reported as a redirect");
    c.eq_str(rs.decide(stub).value, "noop.js", "the redirect target is reported");
    const RuleRequest dom_ok = rule_request_from_url("https://dom.io/x", "good.com");
    c.ok(rs.decide(dom_ok).action == RuleAction::Block, "$domain=good.com matches");
    const RuleRequest dom_no = rule_request_from_url("https://dom.io/x", "bad.com");
    c.ok(rs.decide(dom_no).action == RuleAction::None, "$domain=~bad.com excludes it");
    const RuleRequest dom_other = rule_request_from_url("https://dom.io/x", "other.com");
    c.ok(rs.decide(dom_other).action == RuleAction::None, "an unlisted site is not affected");
    const RuleRequest case_ok = rule_request_from_url("https://x.net/Foo/Bar", "news.org");
    c.ok(rs.decide(case_ok).action == RuleAction::Block, "$match-case matches the exact case");
    const RuleRequest case_no = rule_request_from_url("https://x.net/foo/bar", "news.org");
    c.ok(rs.decide(case_no).action == RuleAction::None, "$match-case refuses other cases");

    c.ok(rs.decide(allowed).explain().find("allow") != std::string::npos,
         "the explanation names the action");
    c.ok(rs.decide(rule_request_from_url("https://nothing.io/x", "news.org")).explain() ==
             "no rule matched",
         "an unmatched request explains itself");
  }

  c.section("filter lists: reports and helpers");
  {
    RuleSet rs;
    rs.load_text("||a.io^\n@@||b.io^\n/c/\n0.0.0.0 hosts.io\n! comment\n");
    c.eq_u64(rs.stats().lines, 5, "every line is counted");
    c.eq_u64(rs.stats().block_rules, 2, "two block rules");
    c.eq_u64(rs.stats().allow_rules, 1, "one exception rule");
    c.eq_u64(rs.stats().host_rules, 3, "three rules are keyed by host name");
    RuleSet one_path;
    one_path.load_text("||c.io/path\n");
    c.eq_u64(one_path.stats().generic_rules, 1, "a path rule is generic, not host keyed");
    c.eq_u64(rs.stats().generic_rules, 0, "a host-only list has no generic rule");
    c.ok(rs.describe().find("rule(s)") != std::string::npos, "the description summarises the set");
    c.ok(rs.describe().find("skipped") != std::string::npos, "the description mentions skips");
    c.ok(rs.skipped_report().find("line 3") != std::string::npos,
         "the skip report names the offending line");
    c.ok(rs.skipped()[0].reason.find("regular expression") != std::string::npos,
         "the skip reason is kept");

    // AdGuard / ABP extensions that the big lists lean on.  `$badfilter` in
    // particular ships by the thousand in uBlock's fix lists, and reading it as a
    // normal block rule is worse than skipping it.
    {
      RuleSet ads;
      ads.load_text(
          "||cancel.example^\n"
          "||cancel.example^$badfilter\n"
          "$image,third-party,domain=site.test\n"
          "||stub.test/x$rewrite=abp-resource:blank-mp3\n"
          "||ip.test^$network\n");
      c.eq_u64(ads.stats().badfilter_rules, 1, "$badfilter is counted, not loaded as a rule");
      c.eq_u64(ads.stats().block_rules, 4, "and the other four lines are the block rules");
      const RuleDecision cancelled =
          ads.decide(rule_request_from_url("https://cancel.example/a.gif", "news.org"));
      c.ok(cancelled.action == RuleAction::None, "$badfilter switches off the rule it names");
      const RuleDecision image =
          ads.decide(rule_request_from_url("https://cdn.test/a.gif", "site.test", ResourceType::Image));
      c.ok(image.action == RuleAction::Block, "a rule with options and no pattern blocks");
      const RuleDecision same_site =
          ads.decide(rule_request_from_url("https://cdn.test/a.gif", "cdn.test", ResourceType::Image));
      c.ok(same_site.action == RuleAction::None, "but only for a third party");
      const RuleDecision other_type =
          ads.decide(rule_request_from_url("https://cdn.test/a.js", "site.test", ResourceType::Script));
      c.ok(other_type.action == RuleAction::None, "and only for the type it names");
      const RuleDecision rewrite = ads.decide(rule_request_from_url("https://stub.test/x", "news.org"));
      c.ok(rewrite.action == RuleAction::Redirect, "$rewrite=abp-resource: is a redirect");
      const RuleDecision network = ads.decide(rule_request_from_url("https://ip.test/x", "news.org"));
      c.ok(network.action == RuleAction::Block, "$network does not restrict the type");
    }

    c.ok(resource_type_from_path("/a/b.JS") == ResourceType::Script, "a .js path is a script");
    c.ok(resource_type_from_path("x", "text/css") == ResourceType::Stylesheet,
         "a CSS content type is a stylesheet");
    c.ok(resource_type_from_path("/logo.png") == ResourceType::Image, "a .png path is an image");
    c.ok(resource_type_from_path("/index.html") == ResourceType::Document, "an .html path is a page");
    c.ok(resource_type_from_path("/x.bin") == ResourceType::Other, "an unknown path is other");
    ResourceType type = ResourceType::Other;
    c.ok(resource_type_from_string("XHR", &type) && type == ResourceType::XmlHttpRequest,
         "the xhr alias is recognised");
    c.ok(!resource_type_from_string("banana", &type), "an unknown type name is refused");

    const RuleRequest r =
        rule_request_from_url("https://User@Example.COM:8443/a/b?x=1&y=2", "news.org");
    c.eq_str(r.host, "example.com", "the host is lowercased and the port stripped");
    c.eq_str(r.scheme, "https", "the scheme is parsed");
    c.eq_str(r.path, "/a/b", "the path is parsed");
    c.eq_str(r.query, "x=1&y=2", "the query is parsed");
    c.ok(r.third_party(), "another site is a third party");
    c.ok(RuleRequest::same_site("a.example.co.uk", "b.example.co.uk"),
         "co.uk sites with the same registrable domain are first party");
    c.ok(!RuleRequest::same_site("a.example.co.uk", "b.example.com"),
         "different registrable domains are third parties");
    c.ok(rule_syntax_help().find("||domain^") != std::string::npos,
         "the syntax help explains the domain anchor");

    RuleSet empty;
    c.ok(empty.decide(rule_request_from_url("https://x.io/a")).action == RuleAction::None,
         "an empty rule set blocks nothing");
    c.eq_u64(empty.size(), 0, "an empty rule set has no rules");

    // A negative type option ($~script) and the literal index that keeps a real
    // 100k-line list usable.  The index is the one piece of the engine that can
    // silently drop a match, so it is compared against a full scan.
    {
      RuleSet typed;
      std::string why;
      c.ok(typed.add_line("||ads.example.com^$~script", &why),
           "a negative type option is understood, not skipped: " + why);
      c.ok(typed.add_line("-ad-manager/$~stylesheet", &why),
           "EasyList's $~stylesheet spelling is understood too: " + why);
      c.eq_u64(typed.stats().skipped, 0, "neither line is skipped");
      const RuleDecision as_image = typed.decide(rule_request_from_url(
          "https://ads.example.com/pixel.gif", "news.org", ResourceType::Image));
      c.ok(as_image.action == RuleAction::Block, "a $~script rule still blocks an image");
      const RuleDecision as_script = typed.decide(rule_request_from_url(
          "https://ads.example.com/a.js", "news.org", ResourceType::Script));
      c.ok(as_script.action == RuleAction::None, "but it never blocks a script");
      const RuleDecision as_page = typed.decide(rule_request_from_url(
          "https://ads.example.com/", "news.org", ResourceType::Document));
      c.ok(as_page.action == RuleAction::Block, "and the page itself is not a script either");
    }

    {
      RuleSet listed;
      std::string why;
      const char* lines[] = {
          "||ads.example.com^$third-party",
          "||tracker.net^$~third-party",
          "@@||ads.example.com^$image",
          "-advertisement-",
          "/banner/*/img^",
          "|https://cdn.example.com/ads",
          "example.com/ads.js|",
          "*pixel.gif",
          "^ad^",
          "||metrics.example.com^$~script,~stylesheet",
      };
      for (const char* line : lines) {
        c.ok(listed.add_line(line, &why), std::string("the list takes ") + line + ": " + why);
      }
      // Enough rules that the index has something to skip.
      for (int i = 0; i < 100; ++i) {
        c.ok(listed.add_line("||cdn" + std::to_string(i) + ".example.com^$script", &why),
             "the list takes a generated rule " + std::to_string(i));
      }
      const char* urls[] = {
          "https://ads.example.com/x.gif",
          "https://ads.example.com/a.js",
          "https://cdn.ads.example.com/deep/x.css",
          "https://tracker.net/x",
          "https://sub.tracker.net/x",
          "https://cdn.example.com/banner/300x250/img",
          "https://example.com/ads.js",
          "https://other.org/ad/thing.png",
          "https://x.org/pixel.gif",
          "https://metrics.example.com/a.json",
          "https://metrics.example.com/a.js",
          "https://cdn7.example.com/app.js",
          "https://plain.example.net/ok.png",
      };
      const ResourceType types[] = {ResourceType::Image, ResourceType::Script,
                                    ResourceType::Stylesheet, ResourceType::XmlHttpRequest};
      std::size_t compared = 0;
      bool same = true;
      for (const char* url : urls) {
        for (const ResourceType type : types) {
          const RuleRequest request = rule_request_from_url(url, "news.org", type);
          listed.set_literal_index(true);
          const RuleDecision indexed = listed.decide(request);
          listed.set_literal_index(false);
          const RuleDecision scanned = listed.decide(request);
          ++compared;
          const bool agree = indexed.action == scanned.action &&
                             (indexed.rule == nullptr) == (scanned.rule == nullptr) &&
                             (indexed.rule == nullptr || indexed.rule->raw == scanned.rule->raw);
          if (!agree) {
            same = false;
            c.ok(false, std::string("the index and a full scan disagree on ") + url);
          }
        }
      }
      c.ok(same, "the literal index gives the same answers as a full scan");
      c.eq_u64(compared, sizeof(urls) / sizeof(urls[0]) * (sizeof(types) / sizeof(types[0])),
               "every URL and type combination was compared");
      listed.set_literal_index(true);
      const RuleDecision ordinary = listed.decide(rule_request_from_url(
          "https://plain.example.net/ok.png", "news.org", ResourceType::Image));
      c.ok(ordinary.action == RuleAction::None, "an ordinary asset is left alone");
      // The index is a property of the set, not of one request: turning it back on
      // must not have lost anything.
      const RuleDecision blocked = listed.decide(
          rule_request_from_url("https://ads.example.com/x.gif", "news.org", ResourceType::Image));
      c.ok(blocked.action == RuleAction::Allow, "the exception for images still wins");
    }
  }
}

// ------------------------------------------------------------ hosts files

void test_hosts(Ctx& c) {
  c.section("hosts file planning");
  const std::string Base =
      "# my own hosts\n"
      "127.0.0.1 localhost\n"
      "0.0.0.0 ads.example.com\n"
      "\n"
      "# netcap blocklist\n"
      "0.0.0.0 old.example.com\n"
      "# netcap blocklist end\n"
      "\n"
      "10.0.0.5 nas.local  nas  # my nas\n";
  HostsFile hf;
  std::string herr;
  c.ok(parse_hosts(Base, &hf, &herr), "a normal hosts file parses");
  c.eq_u64(hf.entries.size(), 5, "every address/name pair is collected");
  c.eq_u64(hf.comments.size(), 3, "pure comment lines are collected");
  c.eq_u64(hf.blank_lines, 2, "blank lines are counted");
  c.ok(hf.has_name("localhost"), "names are found");
  c.ok(hf.has_name("NAS.LOCAL"), "lookup is case insensitive");
  c.ok(!hf.has_name("example.org"), "an unknown name is not found");
  const HostsEntry* nas = hf.find("nas");
  c.ok(nas != nullptr && nas->address == "10.0.0.5", "a trailing name keeps its address");
  c.ok(nas != nullptr && nas->comment == "my nas", "an inline comment is kept");
  c.ok(nas != nullptr && nas->line == 9, "the line number is remembered");
  c.ok(hf.describe().find("5 entr") != std::string::npos, "describe() counts entries");

  HostsFile bad;
  std::string berr;
  c.ok(!parse_hosts("this line has no name\n", &bad, &berr), "a line without a name is reported");
  c.ok(berr.find("hosts line 1") != std::string::npos, "the complaint carries the line number");
  c.eq_u64(bad.entries.size(), 0, "the bad line is not turned into an entry");
  c.ok(parse_hosts("# only a comment\n", &bad, &berr), "a comment only file is fine");
  c.eq_u64(bad.entries.size(), 0, "a comment only file has no entries");

  const std::vector<std::string> blocked = {"ads.example.com", "doubleclick.net", "track.test.net"};
  const HostsPlan p1 = plan_hosts(Base, blocked);
  c.ok(p1.changed(), "a fresh block changes the file");
  c.eq_u64(p1.added.size(), 2, "only names that are not blocked yet are added");
  c.eq_u64(p1.present.size(), 1, "a name already mapped to the sink is reported as present");
  c.eq_u64(p1.removed.size(), 1, "the name dropped from the list is reported");
  c.ok(!p1.removed.empty() && p1.removed[0] == "old.example.com", "the dropped name is the old one");
  c.ok(p1.text.find("0.0.0.0 ads.example.com") != std::string::npos, "present entries are kept");
  c.ok(p1.text.find("0.0.0.0 doubleclick.net") != std::string::npos, "new names are written");
  c.ok(p1.text.find("old.example.com") == std::string::npos, "the old block is replaced");
  c.ok(p1.text.find("127.0.0.1 localhost") != std::string::npos, "user entries survive");
  c.ok(p1.text.find("10.0.0.5 nas.local") != std::string::npos, "the last user entry survives");
  c.ok(p1.text.find("# my own hosts") != std::string::npos, "user comments survive");
  c.eq_u64(p1.kept_entries, 4, "kept entries exclude the old block");

  const HostsPlan p2 = plan_hosts(p1.text, blocked);
  c.ok(!p2.changed(), "planning again changes nothing");
  c.eq_u64(p2.added.size(), 0, "no name is added twice");
  c.eq_u64(p2.removed.size(), 0, "nothing is removed on a second run");
  c.eq_u64(p2.present.size(), 1, "present only counts entries outside the managed block");
  c.ok(p2.text.find("0.0.0.0 doubleclick.net") != std::string::npos,
       "the second run still blocks the added name");
  c.ok(p2.text.find("0.0.0.0 track.test.net") != std::string::npos,
       "the second run still blocks the third name");
  c.ok(p2.text.find(kHostsMarkerBegin) == p1.text.find(kHostsMarkerBegin),
       "the marked block stays where it was");

  const HostsPlan p3 = plan_hosts(p1.text, {"ads.example.com"});
  c.eq_u64(p3.removed.size(), 2, "names that are no longer blocked leave the block");
  c.ok(p3.changed(), "shrinking the list is a change");

  const HostsPlan p4 = plan_hosts("", {"ads.example.com"}, "127.0.0.1");
  c.ok(p4.text.find("127.0.0.1 ads.example.com") != std::string::npos, "the sink address is honoured");
  c.eq_u64(p4.kept_entries, 0, "an empty file keeps nothing");
  c.ok(p4.text.find(kHostsMarkerEnd) != std::string::npos, "an empty file still gets a closed block");

  const HostsPlan p5 = plan_hosts("0.0.0.0 ads.example.com\n", {"ads.example.com"});
  c.ok(p5.text.find("0.0.0.0 ads.example.com") != std::string::npos, "a manual block survives");
  c.eq_u64(p5.added.size(), 0, "a manual block is not duplicated");
  c.eq_u64(p5.present.size(), 1, "a manual block counts as already blocked");

  const std::string path = "netcap_selftest_hosts.txt";
  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());
  std::string werr;
  c.ok(write_hosts_file(path, p1.text, &werr, true), "the plan can be written");
  {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream buf;
    buf << in.rdbuf();
    c.eq_str(buf.str(), p1.text, "the file contains exactly the planned text");
  }
  c.ok(!std::ifstream(path + ".netcap.tmp").good(), "no temporary file is left behind");
  c.ok(!std::ifstream(path + ".bak").good(), "no backup when there was no file before");
  c.ok(write_hosts_file(path, p2.text, &werr, true), "the file can be replaced");
  c.ok(std::ifstream(path + ".bak").good(), "the previous file is kept as .bak");
  {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream buf;
    buf << in.rdbuf();
    c.eq_str(buf.str(), p2.text, "the replacement holds the new text");
  }
  c.ok(!write_hosts_file("", "x", &werr, false), "an empty path is refused");
  c.ok(werr.find("no hosts file path") != std::string::npos, "the refusal explains itself");
  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());
  std::remove((path + ".netcap.tmp").c_str());

#ifdef _WIN32
  c.ok(!platform_hosts_path().empty(), "Windows reports where its hosts file lives");
  c.ok(platform_hosts_path().find("System32") != std::string::npos,
       "the Windows hosts path points into System32");
#endif
}

// ---------------------------------------------------------------- dns sink

void test_dnssink(Ctx& c) {
  c.section("dns sink hole");
  auto make_query = [](const std::string& name, u16 qtype, u16 id) {
    std::vector<u8> b;
    b.push_back(static_cast<u8>(id >> 8));
    b.push_back(static_cast<u8>(id & 0xff));
    b.push_back(0x01);  // RD
    b.push_back(0x00);
    b.push_back(0x00);
    b.push_back(0x01);  // one question
    for (int i = 0; i < 6; ++i) b.push_back(0x00);
    std::size_t start = 0;
    while (true) {
      const std::size_t dot = name.find('.', start);
      const std::string label =
          name.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
      b.push_back(static_cast<u8>(label.size()));
      for (char ch : label) b.push_back(static_cast<u8>(ch));
      if (dot == std::string::npos) break;
      start = dot + 1;
    }
    b.push_back(0x00);
    b.push_back(static_cast<u8>(qtype >> 8));
    b.push_back(static_cast<u8>(qtype & 0xff));
    b.push_back(0x00);
    b.push_back(0x01);
    return b;
  };

  const std::vector<u8> q = make_query("Ads.Example.COM", 1, 0x1234);
  std::string qname;
  u16 qtype = 0;
  u16 qclass = 0;
  std::size_t after = 0;
  c.ok(dns_parse_question(q.data(), q.size(), &qname, &qtype, &qclass, &after),
       "a question is parsed out of a query");
  c.eq_str(qname, "ads.example.com", "the name is lower case without a trailing dot");
  c.eq_u64(qtype, 1, "the query type is read");
  c.eq_u64(qclass, 1, "the query class is read");
  c.eq_u64(after, q.size(), "the question ends at the end of the packet");
  c.ok(!dns_parse_question(q.data(), 8, &qname, &qtype, &qclass, &after),
       "a runt packet is refused");
  {
    std::vector<u8> two = q;
    two[5] = 2;  // two questions
    c.ok(!dns_parse_question(two.data(), two.size(), &qname, &qtype, &qclass, &after),
         "a query with two questions is refused");
  }
  c.eq_str(dns_type_name(1), "A", "type 1 is A");
  c.eq_str(dns_type_name(28), "AAAA", "type 28 is AAAA");
  c.eq_str(dns_type_name(16), "TXT", "type 16 is TXT");

  std::vector<u8> sink_reply;
  c.eq_u64(dns_build_sink_answer(q.data(), q.size(), "0.0.0.0", "::", 60, &sink_reply),
           static_cast<u64>(after + 12 + 4), "an A answer is a header, a question and 16 bytes");
  c.eq_u64(sink_reply[2] & 0x80, 0x80, "the answer has the response bit set");
  c.eq_u64(sink_reply[3] & 0x0f, 0, "the answer claims success");
  c.eq_u64(sink_reply[6], 0, "one answer is announced");
  c.eq_u64(sink_reply[7], 1, "one answer is announced");
  c.eq_u64(rd16be(sink_reply.data() + 4), 1, "the question is kept");
  c.ok(std::equal(q.begin() + 12, q.begin() + static_cast<std::ptrdiff_t>(after),
                  sink_reply.begin() + 12),
       "the question is echoed back byte for byte");
  c.eq_u64(rd16be(sink_reply.data() + after + 2), 1, "the record type is A");
  c.eq_u64(rd16be(sink_reply.data() + after + 10), 4, "an A record carries four bytes");
  c.eq_str(format_ipv4(rd32be(sink_reply.data() + after + 12)), "0.0.0.0",
           "the sink address is 0.0.0.0");
  c.eq_u64(rd16be(sink_reply.data()), 0x1234, "the transaction id is kept");

  std::vector<u8> sink6;
  const std::vector<u8> q6 = make_query("ads.example.com", 28, 0x4321);
  dns_build_sink_answer(q6.data(), q6.size(), "0.0.0.0", "::", 60, &sink6);
  c.eq_u64(rd16be(sink6.data() + after + 10), 16, "an AAAA record carries sixteen bytes");
  c.ok(sink6.size() == after + 12 + 16, "the AAAA answer has the right length");

  std::vector<u8> txt;
  const std::vector<u8> qt = make_query("ads.example.com", 16, 0x9999);
  dns_build_sink_answer(qt.data(), qt.size(), "0.0.0.0", "::", 60, &txt);
  c.eq_u64(rd16be(txt.data() + 6), 0, "a TXT query is answered without records");
  c.eq_u64(txt.size(), after, "a TXT answer is just the header and the question");
  c.eq_u64(dns_build_sink_answer(qt.data(), 4, "0.0.0.0", "::", 60, &txt), 0,
           "a runt query builds no answer");

#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);

  // A stand-in for the real resolver: it answers A queries for anything with
  // 93.184.216.34, which is a value the sink hole itself would never produce.
  SOCKET stub = socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in stub_addr;
  std::memset(&stub_addr, 0, sizeof(stub_addr));
  stub_addr.sin_family = AF_INET;
  stub_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  stub_addr.sin_port = 0;
  bind(stub, reinterpret_cast<sockaddr*>(&stub_addr), sizeof(stub_addr));
  int stub_len = sizeof(stub_addr);
  getsockname(stub, reinterpret_cast<sockaddr*>(&stub_addr), &stub_len);
  const u16 stub_port = ntohs(stub_addr.sin_port);
  int stub_timeout = 300;
  setsockopt(stub, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&stub_timeout),
             sizeof(stub_timeout));
  std::atomic<int> stub_queries{0};
  std::atomic<bool> stub_stop{false};
  std::thread stub_thread([&]() {
    while (!stub_stop.load()) {
      u8 buffer[2048];
      sockaddr_in from;
      int from_len = sizeof(from);
      std::memset(&from, 0, sizeof(from));
      const int got = recvfrom(stub, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                               reinterpret_cast<sockaddr*>(&from), &from_len);
      if (got <= 0) continue;
      ++stub_queries;
      std::vector<u8> reply;
      dns_build_sink_answer(buffer, static_cast<std::size_t>(got), "93.184.216.34", "::", 30,
                            &reply);
      if (!reply.empty()) {
        sendto(stub, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0,
               reinterpret_cast<sockaddr*>(&from), from_len);
      }
    }
  });

  RuleSet rules;
  std::string rule_error;
  rules.load_text("||ads.example.com^\n", &rule_error);
  DnsSinkConfig cfg;
  cfg.bind_address = "127.0.0.1";
  cfg.port = 0;  // let the operating system pick a free port
  cfg.upstream = "127.0.0.1:" + std::to_string(stub_port);
  cfg.timeout_ms = 1500;
  DnsSink sink;
  std::string sink_error;
  c.ok(sink.start(cfg, &rules, &sink_error), "the sink hole starts on a loopback port");
  c.ok(sink.running(), "the sink hole reports that it is running");
  c.ok(sink.port() != 0, "an ephemeral port was assigned");
  c.ok(sink.upstream() == cfg.upstream, "the upstream resolver is remembered");
  c.ok(sink.describe().find("dns sink hole") != std::string::npos, "describe() names the server");

  SOCKET client = socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in sink_addr;
  std::memset(&sink_addr, 0, sizeof(sink_addr));
  sink_addr.sin_family = AF_INET;
  sink_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sink_addr.sin_port = htons(sink.port());
  int client_timeout = 2000;
  setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&client_timeout),
             sizeof(client_timeout));
  auto ask = [&](const std::vector<u8>& query, std::vector<u8>* reply, int timeout_ms) {
    sendto(client, reinterpret_cast<const char*>(query.data()),
           static_cast<int>(query.size()), 0, reinterpret_cast<sockaddr*>(&sink_addr),
           sizeof(sink_addr));
    sink.serve_once(timeout_ms);
    u8 buffer[4096];
    sockaddr_in from;
    int from_len = sizeof(from);
    std::memset(&from, 0, sizeof(from));
    const int got = recvfrom(client, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
    if (got <= 0) return false;
    reply->assign(buffer, buffer + got);
    return true;
  };

  std::vector<u8> reply;
  const std::vector<u8> blocked_query = make_query("Ads.Example.COM", 1, 0x0abc);
  c.ok(ask(blocked_query, &reply, 1500), "a blocked name is answered locally");
  c.eq_u64(stub_queries.load(), 0, "a blocked name never reaches the upstream resolver");
  c.eq_u64(rd16be(reply.data()), 0x0abc, "the blocked answer keeps the transaction id");
  c.ok(std::equal(blocked_query.begin() + 12, blocked_query.end(), reply.begin() + 12),
       "the blocked answer echoes the question");
  {
    std::size_t qend = 0;
    std::string echoed;
    dns_parse_question(reply.data(), reply.size(), &echoed, &qtype, &qclass, &qend);
    c.eq_str(echoed, "ads.example.com", "the blocked answer repeats the name");
    c.eq_u64(rd16be(reply.data() + qend + 10), 4, "the blocked answer carries an A record");
    c.eq_str(format_ipv4(rd32be(reply.data() + qend + 12)), "0.0.0.0",
             "the blocked name resolves to 0.0.0.0");
  }

  const std::vector<u8> allowed_query = make_query("example.com", 1, 0x0def);
  c.ok(ask(allowed_query, &reply, 1500), "an allowed name is answered as well");
  c.eq_u64(stub_queries.load(), 1, "an allowed name is forwarded to the upstream resolver");
  {
    std::size_t qend = 0;
    std::string echoed;
    dns_parse_question(reply.data(), reply.size(), &echoed, &qtype, &qclass, &qend);
    c.eq_str(format_ipv4(rd32be(reply.data() + qend + 12)), "93.184.216.34",
             "the upstream answer is relayed untouched");
  }

  const std::vector<u8> junk = {0x01, 0x02, 0x03};
  c.ok(!ask(junk, &reply, 800), "a malformed datagram gets no answer");

  const DnsSinkStats st = sink.stats();
  c.eq_u64(st.queries, 3, "three queries were seen");
  c.eq_u64(st.blocked, 1, "one of them was blocked");
  c.eq_u64(st.forwarded, 1, "one of them was forwarded");
  c.eq_u64(st.malformed, 1, "one of them was malformed");
  c.eq_u64(st.answers_sent, 2, "two answers were sent");
  const std::vector<DnsQueryEvent> events = sink.events();
  c.eq_u64(events.size(), 3, "every query leaves an event");
  c.ok(!events.empty() && events[0].action == "sink", "the first event is a sink answer");
  c.ok(!events.empty() && events[0].blocked, "the blocked event says so");
  c.ok(!events.empty() && events[0].name == "ads.example.com", "the event carries the name");
  c.ok(events.size() > 1 && events[1].action == "forward", "the second event is a forward");
  c.ok(events.size() > 2 && events[2].action == "malformed", "the third event is malformed");
  c.ok(!events.empty() && !events[0].client.empty(), "the client address is recorded");
  c.ok(sink.report().find("ads.example.com") != std::string::npos,
       "the report names what was blocked");
  c.ok(sink.report().find("1 blocked") != std::string::npos, "the report counts blocked names");

  sink.stop();
  c.ok(!sink.running(), "a stopped sink hole says so");
  stub_stop.store(true);
  stub_thread.join();
  closesocket(client);
  closesocket(stub);
#else
  (void)make_query;
#endif
}

void test_wfp(Ctx& c) {
  c.section("wfp blocking filters (Windows Filtering Platform)");

  WfpSpec spec;
  std::string err;

  c.ok(wfp_parse_spec("203.0.113.5", &spec, &err), "wfp spec: a bare IPv4 address is accepted");
  c.eq_u64(u64(spec.family), 4, "wfp spec: an IPv4 address selects the IPv4 family");
  c.eq_str(spec.remote_ip, "203.0.113.5", "wfp spec: the address is kept verbatim");
  c.eq_u64(spec.remote_port, 0, "wfp spec: no port means every port");
  c.eq_u64(spec.protocol, 0, "wfp spec: no protocol means every protocol");
  c.ok(spec.specific() && !spec.empty(), "wfp spec: an address is a specific filter");

  c.ok(wfp_parse_spec("203.0.113.5:443/tcp", &spec, &err), "wfp spec: address:port/protocol parses");
  c.eq_u64(spec.remote_port, 443, "wfp spec: the port is 443");
  c.eq_u64(u64(spec.protocol), 6, "wfp spec: /tcp selects TCP");

  c.ok(wfp_parse_spec("[2001:db8::1]:5353/udp", &spec, &err), "wfp spec: a bracketed IPv6 endpoint parses");
  c.eq_u64(u64(spec.family), 6, "wfp spec: a bracketed IPv6 address selects the IPv6 family");
  c.eq_str(spec.remote_ip, "2001:db8::1", "wfp spec: the IPv6 address is normalised");
  c.eq_u64(spec.remote_port, 5353, "wfp spec: the IPv6 port is 5353");
  c.eq_u64(u64(spec.protocol), 17, "wfp spec: /udp selects UDP");

  c.ok(wfp_parse_spec("port=53/udp", &spec, &err), "wfp spec: port=<n>/<proto> is accepted");
  c.eq_u64(spec.remote_port, 53, "wfp spec: port=53/udp sets the port");
  c.eq_u64(u64(spec.protocol), 17, "wfp spec: port=53/udp sets the protocol too");
  c.ok(!wfp_parse_spec("port=53/ftp", &spec, &err), "wfp spec: port=53/ftp is refused");

  c.ok(wfp_parse_spec("port=8080 in", &spec, &err), "wfp spec: key=value pieces combine with words");
  c.eq_u64(spec.remote_port, 8080, "wfp spec: port=8080 is picked up");
  c.ok(spec.direction == WfpDirection::Inbound, "wfp spec: 'in' switches to the inbound layer");
  c.ok(spec.remote_ip.empty(), "wfp spec: an inbound port filter needs no address");

  c.ok(wfp_parse_spec("app=C:\\games\\thing.exe tcp out", &spec, &err), "wfp spec: an app path is accepted");
  c.eq_str(spec.app_path, "C:\\games\\thing.exe", "wfp spec: the path is kept verbatim (paths are case sensitive)");
  c.eq_u64(u64(spec.protocol), 6, "wfp spec: a protocol word still applies with an app path");

  c.ok(wfp_parse_spec("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", &spec, &err),
       "wfp spec: a bare image path is accepted without the app= key");
  c.eq_str(spec.app_path, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
           "wfp spec: the bare path is kept verbatim");
  c.ok(spec.describe().find("from C:\\Program Files") != std::string::npos,
       "wfp describe: a bare path shows up in the description");
  c.ok(!wfp_parse_spec("Files\\Google\\chrome.exe", &spec, &err),
       "wfp spec: a shell-split path fragment is refused as a host name");
  c.ok(err.find("quoted argument") != std::string::npos,
       "wfp spec: the refusal explains that a path with spaces must be one quoted argument");

  c.ok(!wfp_parse_spec("", &spec, &err), "wfp spec: an empty spec is refused");
  c.ok(err.find("matches every packet") != std::string::npos, "wfp spec: an empty spec says why");
  c.ok(!wfp_parse_spec("ads.example.com", &spec, &err), "wfp spec: a host name is refused (WFP matches addresses)");
  c.ok(!wfp_parse_spec("port=99999", &spec, &err), "wfp spec: an out of range port is refused");
  c.ok(!wfp_parse_spec("colour=red", &spec, &err), "wfp spec: an unknown key is refused");
  c.ok(err.find("unknown --wfp key") != std::string::npos, "wfp spec: the unknown key is named");
  c.ok(!wfp_parse_spec("203.0.113.5:443/ftp", &spec, &err), "wfp spec: an unknown protocol is refused");
  c.ok(!wfp_parse_spec("[2001:db8::1", &spec, &err), "wfp spec: an unterminated bracket is refused");

  c.ok(wfp_parse_spec("203.0.113.5:443/tcp", &spec, &err), "wfp spec: re-parsed for the description");
  c.eq_str(spec.describe(), "block tcp outbound to 203.0.113.5:443", "wfp describe: address, port and protocol");
  c.ok(wfp_parse_spec("app=C:\\x.exe out", &spec, &err), "wfp spec: re-parsed for an app description");
  c.eq_str(spec.describe(), "block any outbound to any address from C:\\x.exe", "wfp describe: an app-only filter");
  c.eq_str(wfp_direction_name(WfpDirection::Inbound), "inbound", "wfp direction: inbound is named");
  c.eq_str(wfp_direction_name(WfpDirection::Outbound), "outbound", "wfp direction: outbound is named");
  c.ok(wfp_help().find("--wfp-apply") != std::string::npos, "wfp help: explains --wfp-apply");

  WfpEngine engine;
  c.ok(!engine.opened(), "wfp engine: starts closed");
  c.eq_u64(engine.filters(), 0, "wfp engine: holds no filters before it is opened");
  c.ok(wfp_parse_spec("192.0.2.1:443", &spec, &err), "wfp spec: the TEST-NET-1 probe spec parses");
  u64 filter_id = 0;
  c.ok(!engine.add_block(spec, &filter_id, &err), "wfp engine: adding a filter without opening it fails");
  c.ok(err.find("not open") != std::string::npos, "wfp engine: the error says the engine is not open");
  c.eq_u64(engine.filters(), 0, "wfp engine: the refused filter is not counted");
  c.ok(engine.describe().find("closed") != std::string::npos, "wfp engine: describe() reports a closed engine");
  c.ok(engine.report().find("wfp engine") != std::string::npos, "wfp engine: report() has an engine line");

  std::string note;
  const bool available = WfpEngine::available(&note);
  c.ok(!note.empty(), "wfp availability: explains the platform and the privilege it needs");
  c.ok(!wfp_platform_note().empty(), "wfp platform note: not empty");

#ifdef _WIN32
  c.ok(available, "wfp availability: the Windows Filtering Platform exists on Windows");
  c.ok(note.find("Administrator") != std::string::npos, "wfp availability: mentions the Administrator requirement");

  // 192.0.2.0/24 is TEST-NET-1: never routed, so a filter against it is inert.
  WfpEngine live;
  std::string open_error;
  if (live.open(&open_error)) {
    c.ok(true, "wfp engine: the BFE session opened (this run is elevated)");
    u64 live_id = 0;
    std::string add_error;
    if (live.add_block(spec, &live_id, &add_error)) {
      c.ok(true, "wfp engine: a block filter for TEST-NET-1 was installed");
      c.ok(live_id != 0, "wfp engine: the BFE returned a filter id");
      c.eq_u64(live.filters(), 1, "wfp engine: counts the installed filter");
      c.ok(live.report().find("wfp filter") != std::string::npos, "wfp engine: report() lists the filter");
      std::string remove_error;
      c.ok(live.remove(live_id, &remove_error), "wfp engine: removes the filter again");
      c.eq_u64(live.filters(), 0, "wfp engine: no filters are left");
      std::string again;
      c.ok(!live.remove(live_id, &again), "wfp engine: removing it twice fails");
    } else {
      c.ok(add_error.find("Win32 error") != std::string::npos,
           "wfp engine: a refused filter carries the Win32 error code");
      if (!wfp_platform_elevated()) {
        c.ok(add_error.find("Administrator") != std::string::npos,
             "wfp engine: an unelevated run says Administrator is required");
      }
    }
    live.close();
    c.ok(!live.opened(), "wfp engine: close() leaves the engine closed");
  } else {
    c.ok(open_error.find("Administrator") != std::string::npos,
         "wfp engine: an unelevated run says Administrator is required");
    c.ok(open_error.find("Win32 error") != std::string::npos, "wfp engine: the refusal carries the Win32 code");
  }
#else
  c.ok(!available, "wfp availability: not available off Windows");
#endif
}

// ---------------------------------------------------------------- system proxy

// The takeover itself must never run inside a self test - it would change the
// settings of whoever runs it.  What is pinned here is the snapshot format,
// the endpoint validation, and the rule that a snapshot which cannot be
// written aborts *before* the registry is touched.
// -------------------------------------------------------------- packet engine

// The engine is the layer that decides whether a machine keeps its network, so
// it is driven the way the tunnel drives it: byte-exact packets in, byte-exact
// packets out, and every clock reading supplied by the caller (no sleeping).
void test_pktflow(Ctx& c) {
  c.section("packet engine: IPv4/IPv6, TCP and UDP building blocks");

  const u8 client_ip[4] = {10, 0, 0, 5};
  const u8 server_ip[4] = {10, 7, 0, 1};
  u8 caddr[16] = {};
  u8 saddr[16] = {};
  std::memcpy(caddr, client_ip, 4);
  std::memcpy(saddr, server_ip, 4);

  u8 seg[1024];
  const char* body = "hello";
  const std::size_t body_len = 5;
  const std::size_t seg_len = tcp_build(seg, sizeof(seg), caddr, saddr, 4, 51000, 80, 1000, 7, TCP_SYN,
                                        65535, reinterpret_cast<const u8*>(body), body_len);
  c.eq_u64(seg_len, 25, "tcp_build writes a 20 byte header plus the payload");
  TcpHeader th;
  c.ok(tcp_parse(seg, seg_len, &th), "the segment parses back");
  c.eq_u64(th.sport, 51000, "the source port survives the round trip");
  c.eq_u64(th.dport, 80, "the destination port survives the round trip");
  c.eq_u64(th.seq, 1000, "the sequence number survives the round trip");
  c.eq_u64(th.ack, 7, "the acknowledgement number survives the round trip");
  c.ok((th.flags & TCP_SYN) != 0, "the SYN bit is set");
  c.eq_u64(transport_checksum(caddr, saddr, 4, 6, seg, seg_len), 0,
           "a built TCP segment verifies to zero");
  c.eq_str(tcp_flags_text(TCP_SYN | TCP_ACK), "SYN,ACK", "flag text names every bit that is set");
  c.eq_str(tcp_flags_text(0), "-", "and says so when nothing is set");
  c.ok(std::string(tcp_state_name(TcpState::Established)).find("estab") != std::string::npos,
       "connection states have readable names");
  c.eq_str(flow_proto_name(FlowProto::Udp), "udp", "protocol names are spelled out");

  u8 ipbuf[1200];
  const std::size_t ip_len = ipv4_build(ipbuf, sizeof(ipbuf), client_ip, server_ip, 6, 0x1234, seg, seg_len);
  c.eq_u64(ip_len, seg_len + 20, "ipv4_build prepends a 20 byte header");
  IpHeader ih;
  c.ok(ip_parse(ipbuf, ip_len, &ih), "the packet parses back");
  c.eq_u64(ih.version, 4, "the version field is parsed");
  c.eq_u64(ih.protocol, 6, "the protocol field is parsed");
  c.eq_u64(ih.total_len, ip_len, "the total length is parsed");
  c.eq_u64(ih.payload_len, seg_len, "the payload length is the total minus the header");
  c.eq_str(ih.source(), "10.0.0.5", "the source address formats as a dotted quad");
  c.eq_str(ih.destination(), "10.7.0.1", "the destination address formats as a dotted quad");
  c.eq_u64(ip_checksum_v4(ipbuf, 20), 0, "a built IPv4 header verifies to zero");
  c.ok(!ip_parse(ipbuf, 19, &ih), "a truncated IP header is rejected");
  ipbuf[0] = 0x55;
  c.ok(!ip_parse(ipbuf, ip_len, &ih), "an impossible version is rejected");
  ipbuf[0] = 0x45;

  u8 dgram[512];
  const std::size_t dgram_len = udp_build(dgram, sizeof(dgram), caddr, saddr, 4, 40000, 53,
                                          reinterpret_cast<const u8*>("dns"), 3);
  c.eq_u64(dgram_len, 11, "udp_build writes an 8 byte header plus the payload");
  UdpHeader uh;
  c.ok(udp_parse(dgram, dgram_len, &uh), "the datagram parses back");
  c.eq_u64(uh.sport, 40000, "the UDP source port survives the round trip");
  c.eq_u64(uh.length, 11, "the UDP length field covers header and payload");
  c.eq_u64(transport_checksum(caddr, saddr, 4, 17, dgram, dgram_len), 0,
           "a built UDP datagram verifies to zero");

  u8 icmp[8] = {8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01};
  const u16 icmp_sum = internet_checksum(icmp, sizeof(icmp), 0);
  icmp[2] = static_cast<u8>(icmp_sum >> 8);
  icmp[3] = static_cast<u8>(icmp_sum & 0xff);
  u8 echo[64];
  const std::size_t echo_len = icmp_echo_reply(echo, sizeof(echo), icmp, sizeof(icmp));
  c.eq_u64(echo_len, sizeof(icmp), "an echo request turns into a reply of the same size");
  c.eq_u64(echo[0], icmp_echo_type(4, true), "the reply flips the ICMP type");
  c.eq_u64(internet_checksum(echo, echo_len, 0), 0, "the reply checksum is recomputed");
  c.eq_u64(icmp_echo_type(4, false), 8, "IPv4 echo requests are type 8");
  c.eq_u64(icmp_echo_type(6, true), 129, "IPv6 echo replies are type 129");
  c.eq_u64(ip_header_len(6), 40, "IPv6 header length is 40");
  c.eq_u64(ip_header_len(4), 20, "IPv4 header length is 20");

  c.ok(seq_lt(0xffffffffu, 0u), "sequence numbers compare across the wrap");
  c.ok(seq_gt(0u, 0xffffffffu), "and in the other direction");
  c.ok(seq_le(5u, 5u), "equal sequence numbers are not greater");
  c.eq_u64(seq_add(0xffffffffu, 1), 0, "seq_add wraps at 2^32");
  c.eq_u64(seq_distance(4u, 10u), 6, "seq_distance measures the forward gap");

  c.section("packet engine: handshake, data, teardown and timers");

  PacketEngineConfig cfg;
  cfg.version = 4;
  cfg.local[0] = 10;
  cfg.local[1] = 7;
  cfg.local[2] = 0;
  cfg.local[3] = 1;
  PacketEngine engine(cfg);
  c.eq_u64(engine.max_segment_payload(), 1460, "a 1500 byte MTU leaves 1460 bytes of payload");

  i64 now = 1000000;
  std::vector<Packet> out;
  const u16 client_port = 51000;

  auto send_tcp = [&](u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, const std::string& text) {
    u8 s[1200];
    const std::size_t n = tcp_build(s, sizeof(s), caddr, saddr, 4, sport, dport, seq, ack, flags, 65535,
                                    reinterpret_cast<const u8*>(text.data()), text.size());
    u8 p[1400];
    const std::size_t m = ipv4_build(p, sizeof(p), client_ip, server_ip, 6, 0x4242, s, n);
    out.clear();
    engine.feed(p, m, now, &out);
  };

  send_tcp(client_port, 80, 1000, 0, TCP_SYN, "");
  c.eq_u64(engine.flow_count(), 1, "a SYN opens one flow");
  c.eq_u64(out.size(), 1, "and gets one answer");
  c.eq_u64(engine.stats().tcp_opened, 1, "the engine counts the opened flow");
  const u64 flow_id = engine.flows().at(0).id;
  IpHeader rih;
  TcpHeader rth;
  bool answered = false;
  if (!out.empty() && ip_parse(out[0].data.data(), out[0].data.size(), &rih)) {
    answered = tcp_parse(out[0].data.data() + rih.header_len, rih.payload_len, &rth);
  }
  c.ok(answered, "the answer is a parsable IP/TCP packet");
  c.ok((rth.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK), "it is a SYN|ACK");
  c.eq_u64(rth.sport, 80, "the answer comes from the port the client dialled");
  c.eq_u64(rth.dport, client_port, "and goes back to the client port");
  c.eq_u64(rth.ack, 1001, "the SYN consumes one sequence number");
  c.eq_u64(out[0].linktype, DLT_RAW, "tunnel packets are link-type RAW");
  const u32 our_isn = rth.seq;

  c.ok(!engine.flows().at(0).established, "the flow is not established before the ACK arrives");
  send_tcp(client_port, 80, 1001, our_isn + 1, TCP_ACK, "");
  c.eq_u64(out.size(), 0, "a bare ACK needs no answer");
  c.ok(engine.flows().at(0).established, "the ACK establishes the connection");
  c.eq_u64(engine.stats().tcp_established, 1, "and is counted");

  const Bytes request = bstr("GET / HTTP/1.0\r\n\r\n");
  const u64 wire_out_before = engine.stats().bytes_out;
  out.clear();
  c.ok(engine.write(flow_id, request, now, &out), "an application can write to the flow");
  c.eq_u64(out.size(), 1, "the write is emitted as one segment");
  answered = false;
  if (!out.empty() && ip_parse(out[0].data.data(), out[0].data.size(), &rih)) {
    answered = tcp_parse(out[0].data.data() + rih.header_len, rih.payload_len, &rth);
  }
  c.ok(answered, "the data segment parses back");
  c.ok((rth.flags & TCP_PSH) != 0, "the data segment pushes");
  c.eq_u64(out[0].data.size() - rih.header_len - rth.header_len, request.size(),
           "the payload reaches the wire unchanged");
  c.eq_u64(engine.stats().bytes_out - wire_out_before, 58,
           "the write puts 20 IP + 20 TCP + 18 payload bytes on the wire");

  const u64 wire_in_before = engine.stats().bytes_in;
  send_tcp(client_port, 80, 1001, our_isn + 1 + static_cast<u32>(request.size()), TCP_ACK | TCP_PSH,
           "answer");
  c.eq_u64(out.size(), 1, "inbound data is acknowledged");
  Bytes received;
  c.ok(engine.read(flow_id, &received), "the application can read the flow");
  c.eq_str(text_of(received), "answer", "and gets exactly the bytes that arrived");
  c.eq_u64(engine.flows().at(0).stats.bytes_in, 6, "the flow counts the payload it received");
  c.eq_u64(engine.stats().bytes_in - wire_in_before, 46,
           "the engine counts the whole inbound packet (20 IP + 20 TCP + 6)");

  // The client's sequence space only moves with the client's own bytes: what we
  // wrote towards it consumes *our* sequence numbers, not its.
  const u32 client_next = 1001 + 6;
  send_tcp(client_port, 80, 1001, our_isn + 1, TCP_ACK | TCP_PSH, "answer");
  c.ok(engine.flows().at(0).stats.duplicates >= 1, "a repeat of data we already have is counted");
  send_tcp(client_port, 80, client_next + 100, our_isn + 1, TCP_ACK | TCP_PSH, "gap");
  c.ok(engine.flows().at(0).stats.out_of_order >= 1, "a gap is counted instead of buffered");
  c.eq_u64(engine.stats().packets_in, 5, "every feed is counted on the way in");
  c.ok(!engine.stats().describe().empty(), "the engine can describe itself");
  c.ok(engine.describe().find("51000") != std::string::npos ||
           engine.flows().at(0).text().find("51000") != std::string::npos,
       "the flow view names the client port");

  out.clear();
  c.ok(engine.write(flow_id, bstr("second"), now, &out), "writing again is allowed");
  c.ok(out.size() >= 1, "which emits another segment");
  const u64 before_retransmit = engine.stats().retransmits;
  now += cfg.retransmit_us + 1;
  out.clear();
  engine.tick(now, &out);
  c.ok(out.size() >= 1, "an unacknowledged segment is retransmitted on the next tick");
  c.ok(engine.stats().retransmits > before_retransmit, "and counted as a retransmission");

  send_tcp(client_port, 80, client_next, our_isn + 1, TCP_RST, "");
  PacketEngine::FlowView after;
  const bool gone = !engine.flow(flow_id, &after);
  c.ok(gone || after.state == TcpState::Reset || after.closed, "a RST tears the flow down");

  c.section("packet engine: UDP, ICMP and limits");

  PacketEngine udp_engine(cfg);
  u8 udp_seg[600];
  const std::size_t udp_len = udp_build(udp_seg, sizeof(udp_seg), caddr, saddr, 4, 5353, 53,
                                        reinterpret_cast<const u8*>("query"), 5);
  u8 udp_ip[700];
  const std::size_t udp_ip_len = ipv4_build(udp_ip, sizeof(udp_ip), client_ip, server_ip, 17, 1, udp_seg, udp_len);
  std::vector<Packet> uout;
  udp_engine.feed(udp_ip, udp_ip_len, now, &uout);
  c.eq_u64(udp_engine.stats().udp_opened, 1, "a UDP datagram opens a flow without a handshake");
  c.eq_u64(uout.size(), 0, "and is not answered on its own");
  const u64 udp_id = udp_engine.flows().at(0).id;
  Bytes udp_in;
  c.ok(udp_engine.read(udp_id, &udp_in), "the datagram payload is readable");
  c.eq_str(text_of(udp_in), "query", "and is exactly what was sent");
  uout.clear();
  c.ok(udp_engine.write(udp_id, bstr("reply"), now, &uout), "a UDP flow can be written to");
  c.eq_u64(uout.size(), 1, "which emits one datagram");
  UdpHeader ruh;
  bool udp_ok = false;
  if (!uout.empty() && ip_parse(uout[0].data.data(), uout[0].data.size(), &rih)) {
    udp_ok = udp_parse(uout[0].data.data() + rih.header_len, rih.payload_len, &ruh);
  }
  c.ok(udp_ok, "the reply datagram parses back");
  c.eq_u64(ruh.sport, 53, "the reply comes from the server port");
  c.eq_u64(ruh.dport, 5353, "and goes to the client port");
  c.eq_u64(transport_checksum(saddr, caddr, 4, 17, uout[0].data.data() + rih.header_len,
                              rih.payload_len),
           0, "the reply checksum is correct for the swapped addresses");

  PacketEngine icmp_engine(cfg);
  u8 icmp_req[16] = {8, 0, 0, 0, 0x00, 0x01, 0x00, 0x02, 'p', 'i', 'n', 'g'};
  const u16 icmp_req_sum = internet_checksum(icmp_req, 12, 0);
  icmp_req[2] = static_cast<u8>(icmp_req_sum >> 8);
  icmp_req[3] = static_cast<u8>(icmp_req_sum & 0xff);
  u8 icmp_ip[80];
  const std::size_t icmp_ip_len = ipv4_build(icmp_ip, sizeof(icmp_ip), client_ip, server_ip, 1, 7,
                                             icmp_req, 12);
  std::vector<Packet> iout;
  icmp_engine.feed(icmp_ip, icmp_ip_len, now, &iout);
  c.eq_u64(iout.size(), 1, "an echo request is answered");
  c.eq_u64(icmp_engine.stats().icmp_replies, 1, "and counted");
  bool echo_ok = false;
  if (!iout.empty() && ip_parse(iout[0].data.data(), iout[0].data.size(), &rih)) {
    echo_ok = rih.payload_len >= 8 && iout[0].data[rih.header_len] == icmp_echo_type(4, true);
  }
  c.ok(echo_ok, "the answer is an echo reply to the same address");

  PacketEngineConfig no_echo = cfg;
  no_echo.answer_icmp_echo = false;
  PacketEngine quiet(no_echo);
  uout.clear();
  quiet.feed(icmp_ip, icmp_ip_len, now, &uout);
  c.eq_u64(uout.size(), 0, "echo replies can be switched off");

  PacketEngine bad(cfg);
  u8 broken_seg[600];
  const std::size_t broken_len = tcp_build(broken_seg, sizeof(broken_seg), caddr, saddr, 4, 52000, 80,
                                           1, 0, TCP_SYN, 65535, nullptr, 0);
  broken_seg[16] ^= 0xff;  // the TCP checksum field
  u8 broken_ip[700];
  const std::size_t broken_ip_len =
      ipv4_build(broken_ip, sizeof(broken_ip), client_ip, server_ip, 6, 9, broken_seg, broken_len);
  std::vector<Packet> bout;
  bad.feed(broken_ip, broken_ip_len, now, &bout);
  c.eq_u64(bad.stats().bad_checksum, 1, "a packet with a broken checksum is dropped");
  c.eq_u64(bad.flow_count(), 0, "and opens nothing");

  u8 garbage[24] = {0x60, 0x00, 0x00, 0x00};
  bout.clear();
  bad.feed(garbage, sizeof(garbage), now, &bout);
  c.ok(bad.stats().malformed >= 1, "a truncated IPv6 header is counted as malformed");

  PacketEngine small(cfg);
  small.set_config([] {
    PacketEngineConfig c2 = PacketEngineConfig();
    c2.local[0] = 10;
    c2.local[1] = 7;
    c2.local[2] = 0;
    c2.local[3] = 1;
    c2.max_flows = 1;
    return c2;
  }());
  auto syn_from = [&](u16 sport, i64 when) {
    u8 s[64];
    const std::size_t n = tcp_build(s, sizeof(s), caddr, saddr, 4, sport, 80, 5, 0, TCP_SYN, 65535, nullptr, 0);
    u8 p[128];
    const std::size_t m = ipv4_build(p, sizeof(p), client_ip, server_ip, 6, 0, s, n);
    std::vector<Packet> sink;
    small.feed(p, m, when, &sink);
  };
  syn_from(40001, now);
  syn_from(40002, now);
  c.eq_u64(small.flow_count(), 1, "the flow table honours its limit");
  c.ok(small.stats().refused >= 1, "and counts what it had to refuse");

  i64 later = now + cfg.tcp_idle_us + 1000000;
  std::vector<Packet> tout;
  const u64 expired_before = small.stats().expired;
  small.tick(later, &tout);
  c.ok(small.stats().expired > expired_before, "an idle flow expires");
  c.eq_u64(small.flow_count(), 0, "and leaves the table");
}

// ---------------------------------------------------------------- tunnel relay

// The relay's decision layer answers "may this connection go out, and if not,
// what do we say instead". Everything here is byte-exact and socket-free.
void test_tunrelay(Ctx& c) {
  c.section("tunnel relay: ports, verdicts and local answers");

  c.ok(tunrelay_port_is_http(80), "port 80 is HTTP");
  c.ok(tunrelay_port_is_http(8080), "port 8080 is HTTP");
  c.ok(!tunrelay_port_is_http(443), "port 443 is not HTTP");
  c.ok(tunrelay_port_is_tls(443), "port 443 is TLS");
  c.ok(tunrelay_port_is_tls(8443), "port 8443 is TLS");
  c.ok(!tunrelay_port_is_tls(22), "port 22 is neither");
  c.eq_str(tunrelay_verdict_name(RelayVerdict::NeedMore), "need-more", "verdicts have names");
  c.eq_str(tunrelay_verdict_name(RelayVerdict::Forward), "forward", "including forward");
  c.eq_str(tunrelay_verdict_name(RelayVerdict::Block), "block", "and block");
  c.eq_str(tunrelay_verdict_name(RelayVerdict::Reset), "reset", "and reset");

  const std::string response = tunrelay_http_response(403, "text/html", "<b>x</b>");
  c.ok(response.compare(0, 15, "HTTP/1.1 403 Fo") == 0, "a local answer starts with a status line");
  c.ok(response.find("Content-Length: 8") != std::string::npos, "and carries the body length");
  c.ok(response.find("X-Netcap: blocked") != std::string::npos, "and says who answered");
  c.ok(tunrelay_http_response(302, "text/plain", "", "https://example.com/x").find(
           "Location: https://example.com/x") != std::string::npos,
       "a redirect carries its target");

  RuleSet rules;
  std::string err;
  const bool loaded = rules.load_text(
      "||ads.example.com^\n"
      "@@||ads.example.com/ok^\n"
      "||tracker.example.com^$removeparam=utm_source\n"
      "||go.example.com^$redirect=https://example.com/blocked\n",
      &err);
  c.ok(loaded, "the test rule set loads (" + err + ")");

  c.section("tunnel relay: HTTP decisions");

  Bytes head = bstr("GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nUser-Agent: x\r\n\r\n");
  std::size_t consumed = 0;
  RelayDecision d = tunrelay_inspect(&rules, 80, head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "block", "a blocked host is answered locally");
  c.eq_str(d.url, "http://ads.example.com/ad.js", "the decision carries the absolute URL");
  c.eq_str(d.host, "ads.example.com", "and the host name");
  c.eq_u64(consumed, head.size(), "the whole head was inspected");
  const std::string page = tunrelay_block_page(d);
  c.ok(page.find("ads.example.com") != std::string::npos, "the block page names the host");
  c.ok(page.find("已拦截") != std::string::npos, "and explains itself in the user's language");
  c.ok(page.find("<img") == std::string::npos && page.find("src=") == std::string::npos &&
           page.find("<link") == std::string::npos,
       "the block page needs nothing from the network");

  Bytes ok_head = bstr("GET /ok HTTP/1.1\r\nHost: ads.example.com\r\n\r\n");
  d = tunrelay_inspect(&rules, 80, ok_head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "an @@ exception lets the request through");

  Bytes pass_head = bstr("GET / HTTP/1.1\r\nHost: news.example.com\r\n\r\n");
  d = tunrelay_inspect(&rules, 80, pass_head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "an unmatched host is forwarded");

  Bytes track_head = bstr("GET /a?utm_source=x&id=7 HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n");
  d = tunrelay_inspect(&rules, 80, track_head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "a modify rule still forwards");
  c.eq_str(d.target, "http://tracker.example.com/a?id=7", "with the tracking parameter stripped");

  Bytes go_head = bstr("GET / HTTP/1.1\r\nHost: go.example.com\r\n\r\n");
  d = tunrelay_inspect(&rules, 80, go_head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "redirect", "a redirect rule is answered locally");
  c.eq_str(d.target, "https://example.com/blocked", "with the configured target");

  Bytes absolute = bstr("GET http://ads.example.com/x HTTP/1.1\r\n\r\n");
  d = tunrelay_inspect(&rules, 80, absolute, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "block", "an absolute request target is decided too");
  c.eq_str(d.host, "ads.example.com", "and its host is recovered from the URL");

  Bytes partial = bstr("GET /ad.js HTTP/1.1\r\nHost: ads.exa");
  d = tunrelay_inspect(&rules, 80, partial, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "need-more", "an incomplete head waits for more bytes");
  c.eq_u64(consumed, 0, "and consumes nothing");
  d = tunrelay_inspect(&rules, 80, head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "block", "the same request decides once it is complete");

  Bytes nonsense = bstr("hello there\r\n\r\n");
  d = tunrelay_inspect(&rules, 80, nonsense, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "a stream that is not HTTP is passed through");

  Bytes huge = bstr("GET /");
  huge.resize(4096, 'a');
  d = tunrelay_inspect(&rules, 80, huge, &consumed, 256);
  c.eq_str(tunrelay_verdict_name(d.verdict), "reset", "a head that never ends is reset");
  d = tunrelay_inspect(nullptr, 80, head, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "no rule set means no blocking");

  c.section("tunnel relay: TLS decisions");

  const Bytes hello = tls_client_hello("ads.example.com");
  d = tunrelay_inspect(&rules, 443, hello, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "reset", "a blocked SNI resets the TLS flow");
  c.eq_str(d.host, "ads.example.com", "the SNI is what we decided on");
  c.ok(d.is_tls, "and the decision knows it was TLS");

  const Bytes clean = tls_client_hello("news.example.com");
  d = tunrelay_inspect(&rules, 443, clean, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "an unlisted SNI goes out");

  RuleSet allow_ads;
  allow_ads.load_text("||ads.example.com^\n@@||ads.example.com^\n", &err);
  d = tunrelay_inspect(&allow_ads, 443, hello, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "an exception also applies to TLS");

  d = tunrelay_inspect(&rules, 443, Bytes(clean.begin(), clean.begin() + 6), &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "need-more", "a partial client hello waits");

  Bytes not_tls = bstr("GET / HTTP/1.1\r\n\r\n");
  d = tunrelay_inspect(&rules, 443, not_tls, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "non-TLS bytes on 443 are passed through");

  Bytes appdata = {23, 3, 3, 0, 1, 0};
  d = tunrelay_inspect(&rules, 443, appdata, &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "application data is not inspected");

  d = tunrelay_inspect(&rules, 22, bstr("SSH-2.0-OpenSSH_9.0\r\n"), &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "other ports are relayed as they are");

  d = tunrelay_inspect(&rules, 80, Bytes(), &consumed);
  c.eq_str(tunrelay_verdict_name(d.verdict), "need-more", "an empty stream has nothing to decide");

  c.section("tunnel relay: QUIC Initials");
  {
    // A synthetic but RFC-shaped client Initial: one CRYPTO frame carrying a
    // ClientHello, padded to the 1200-byte minimum with PADDING frames.  The
    // Initial keys come from the DCID alone, so a name can be blocked without
    // holding a single secret.
    auto initial_for = [](const std::string& sni) {
      Bytes hello;
      std::string why;
      if (!quic_build_client_hello(sni, "h3", 0, &hello, &why)) return Bytes();
      Bytes frames;
      frames.push_back(0x06);  // CRYPTO
      quic_varint_put(&frames, 0);
      quic_varint_put(&frames, hello.size());
      frames.insert(frames.end(), hello.begin(), hello.end());
      while (frames.size() < 1200) frames.push_back(0x00);
      const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
      Bytes packet;
      if (!quic_build_initial(dcid, sizeof(dcid), 0x00000001, 2, 4, frames.data(), frames.size(),
                             &packet, &why)) {
        return Bytes();
      }
      return packet;
    };

    const Bytes quic_blocked = initial_for("ads.example.com");
    const Bytes quic_allowed = initial_for("news.example.com");
    c.ok(!quic_blocked.empty() && !quic_allowed.empty(), "a synthetic QUIC Initial can be built");

    std::size_t quic_used = 0;
    d = tunrelay_inspect(&rules, 443, quic_blocked, &quic_used);
    c.eq_str(tunrelay_verdict_name(d.verdict), "reset", "a blocked name in a QUIC Initial is dropped");
    c.eq_str(d.host, "ads.example.com", "the QUIC SNI became the host");
    c.eq_str(d.url, "https://ads.example.com/", "the URL is built from the SNI");
    c.ok(d.is_tls, "a QUIC flow is marked as encrypted");
    c.eq_u64(quic_used, quic_blocked.size(), "the whole datagram counts as consumed");

    d = tunrelay_inspect(&rules, 443, quic_allowed, &quic_used);
    c.eq_str(tunrelay_verdict_name(d.verdict), "forward", "an allowed QUIC name goes out");

    Bytes quic_short(64, 0x00);
    quic_short[0] = 0x40;  // short header: 1-RTT, nothing to read a name from
    d = tunrelay_inspect(&rules, 443, quic_short, &quic_used);
    c.ok(d.verdict != RelayVerdict::Reset, "a 1-RTT packet is not dropped by name");
  }
}

// ------------------------------------------------------- tunnel relay, live

// The decision layer is tested byte by byte above; this drives the part that
// actually moves bytes: hand-built IP packets in, a one-shot origin on
// loopback out, and the answer coming back through the user-space engine.
void test_tunpipe(Ctx& c) {
#ifdef _WIN32
  c.section("tunnel relay: live loopback forwarding");  {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
      c.ok(false, "WSAStartup for the live relay check");
      return;
    }

    // One-shot origin: accepts a single connection, records the request and
    // answers with a fixed reply.
    struct OneShot {
      SOCKET listener = INVALID_SOCKET;
      u16 port = 0;
      std::string request;
      std::string reply;
      std::thread worker;

      bool start(const std::string& answer) {
        reply = answer;
        listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return false;
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
        if (::listen(listener, 4) != 0) return false;
        int len = sizeof(addr);
        if (getsockname(listener, (sockaddr*)&addr, &len) != 0) return false;
        port = ntohs(addr.sin_port);
        worker = std::thread([this]() {
          SOCKET client = ::accept(listener, nullptr, nullptr);
          if (client == INVALID_SOCKET) return;
          DWORD tv = 3000;
          setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
          char buf[2048];
          std::string have;
          while (have.find("\r\n\r\n") == std::string::npos) {
            const int rc = ::recv(client, buf, (int)sizeof(buf), 0);
            if (rc <= 0) break;
            have.append(buf, (size_t)rc);
          }
          request = have;
          ::send(client, reply.data(), (int)reply.size(), 0);
          ::shutdown(client, SD_SEND);
          closesocket(client);
        });
        return true;
      }

      ~OneShot() {
        if (listener != INVALID_SOCKET) closesocket(listener);
        if (worker.joinable()) worker.join();
      }
    };

    const u8 c4[4] = {10, 0, 0, 5};
    const u8 s4[4] = {127, 0, 0, 1};
    u8 c16[16] = {0};
    u8 s16[16] = {0};
    std::memcpy(c16, c4, 4);
    std::memcpy(s16, s4, 4);
    const u16 client_port = 40000;
    const u32 client_isn = 1000;

    // Everything the relay sent towards the client, as payload text.
    auto payloads = [](const std::vector<Packet>& packets) {
      std::string text;
      for (const Packet& p : packets) {
        IpHeader h;
        if (!ip_parse(p.data.data(), p.data.size(), &h)) continue;
        if (h.protocol != 6) continue;
        TcpHeader t;
        if (!tcp_parse(p.data.data() + h.header_len, h.payload_len, &t)) continue;
        const std::size_t off = h.header_len + t.header_len;
        if (off < p.data.size()) text.append((const char*)p.data.data() + off, p.data.size() - off);
      }
      return text;
    };
    auto syn_ack_seq = [](const std::vector<Packet>& packets, u32* out) {
      for (const Packet& p : packets) {
        IpHeader h;
        if (!ip_parse(p.data.data(), p.data.size(), &h)) continue;
        if (h.protocol != 6) continue;
        TcpHeader t;
        if (!tcp_parse(p.data.data() + h.header_len, h.payload_len, &t)) continue;
        if ((t.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
          *out = t.seq;
          return true;
        }
      }
      return false;
    };
    auto client_packet = [&](u32 seq, u32 ack, u8 flags, const std::string& body, u16 dport) {
      Bytes seg(2048);
      const std::size_t seg_len = tcp_build(seg.data(), seg.size(), c16, s16, 4, client_port, dport, seq, ack,
                                           flags, 65535, (const u8*)body.data(), body.size());
      Bytes ip(2048);
      const std::size_t ip_len =
          ipv4_build(ip.data(), ip.size(), c4, s4, 6, 0x1234, seg.data(), seg_len);
      ip.resize(ip_len);
      return ip;
    };

    // --- a request that must reach a real origin -------------------------
    OneShot origin;
    const bool up = origin.start("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello relay");
    c.ok(up, "the one-shot origin listens on loopback");
    // The takeover refuses to touch the routing table unless the chain answers,
    // so the probe that decides that has to be right in both directions.  It gets
    // its own one-shot listener: connecting to `origin` would spend the single
    // connection that the relay test below needs.
    {
      OneShot probe_origin;
      const bool probe_up = probe_origin.start("HTTP/1.1 204 No Content\r\n\r\n");
      c.ok(probe_up && tunpipe_chain_reachable("127.0.0.1", probe_origin.port, 500),
           "the chain probe finds a listener on loopback");
    }
    c.ok(!tunpipe_chain_reachable("127.0.0.1", 1, 300),
         "and reports a dead port as unreachable");
    c.ok(!tunpipe_chain_reachable("", 7890, 300), "an empty chain host is never reachable");

    RelayConfig cfg;
    cfg.version = 4;
    cfg.mtu = 1500;
    std::memcpy(cfg.local, s4, 4);
    RuleSet rules;
    std::string rule_err;
    rules.load_text("||ads.test^\n", &rule_err);
    cfg.rules = &rules;

    TunPipe pipe(cfg);
    std::vector<Packet> out;
    i64 now = 1000000;
    Bytes syn = client_packet(client_isn, 0, TCP_SYN, "", origin.port);
    pipe.on_packet(syn.data(), syn.size(), now, &out);
    u32 server_isn = 0;
    c.ok(syn_ack_seq(out, &server_isn), "the user-space engine answers the SYN");
    c.eq_u64(pipe.engine().stats().tcp_opened, 1, "and the flow exists");

    out.clear();
    Bytes ack = client_packet(client_isn + 1, server_isn + 1, TCP_ACK, "", origin.port);
    pipe.on_packet(ack.data(), ack.size(), now += 1000, &out);

    out.clear();
    Bytes req = client_packet(client_isn + 1, server_isn + 1, TCP_ACK | TCP_PSH,
                              "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", origin.port);
    pipe.on_packet(req.data(), req.size(), now += 1000, &out);

    std::string seen;
    for (int i = 0; i < 200 && seen.find("hello relay") == std::string::npos; ++i) {
      now += 20000;
      pipe.tick(now, &out);
      pipe.poll(20, now, &out);
      seen = payloads(out);
    }
    c.ok(seen.find("HTTP/1.1 200 OK") != std::string::npos, "the origin's status line reaches the client");
    c.ok(seen.find("hello relay") != std::string::npos, "and so does its body");
    c.ok(origin.request.find("GET / HTTP/1.1") != std::string::npos, "the origin saw the request");
    c.eq_u64(pipe.stats().forwarded, 1, "exactly one flow was forwarded");
    c.eq_u64(pipe.stats().blocked, 0, "and nothing was blocked");
    c.ok(pipe.stats().bytes_up > 0 && pipe.stats().bytes_down > 0, "bytes moved both ways");
    pipe.stop();

    // --- a request the rules block ---------------------------------------
    RelayConfig blocked_cfg = cfg;
    TunPipe blocked(blocked_cfg);
    std::vector<Packet> out2;
    i64 now2 = 2000000;
    Bytes syn2 = client_packet(5000, 0, TCP_SYN, "", 80);
    blocked.on_packet(syn2.data(), syn2.size(), now2, &out2);
    u32 server_isn2 = 0;
    c.ok(syn_ack_seq(out2, &server_isn2), "a second flow completes its handshake");
    out2.clear();
    Bytes ack2 = client_packet(5001, server_isn2 + 1, TCP_ACK, "", 80);
    blocked.on_packet(ack2.data(), ack2.size(), now2 += 1000, &out2);
    out2.clear();
    Bytes req2 = client_packet(5001, server_isn2 + 1, TCP_ACK | TCP_PSH,
                               "GET /ad.js HTTP/1.1\r\nHost: ads.test\r\n\r\n", 80);
    blocked.on_packet(req2.data(), req2.size(), now2 += 1000, &out2);
    blocked.tick(now2, &out2);
    const std::string page = payloads(out2);
    c.ok(page.find("403") != std::string::npos, "the blocked request is answered with 403");
    c.ok(page.find("ads.test") != std::string::npos, "and the page names the host");
    c.eq_u64(blocked.stats().blocked, 1, "the block is counted");
    c.eq_u64(blocked.stats().upstream_opened, 0, "and no upstream socket was opened");
    blocked.stop();
  }
#else
  (void)c;
#endif
}

void test_tun(Ctx& c) {
  c.section("TUN adapter and default routes");

  // The routing snapshot is the only thing that makes a takeover undoable, so it
  // has to survive a byte-exact round trip.
  std::vector<TunRoute> routes;
  TunRoute first;
  first.destination = "0.0.0.0";
  first.prefix_len = 0;
  first.next_hop = "192.168.0.1";
  first.luid = 0x47008000000000ull;
  first.ifindex = 22;
  first.metric = 0;
  routes.push_back(first);
  TunRoute second;
  second.destination = "0.0.0.0";
  second.prefix_len = 0;
  second.next_hop = "10.0.0.0";
  second.luid = 0x6008007000000ull;
  second.ifindex = 17;
  second.metric = 1;
  routes.push_back(second);

  const std::string text = tun_routes_text(routes);
  c.ok(text.rfind("netcap-tun-routes 1", 0) == 0,
       "tun snapshot: starts with its format header");
  c.ok(text.find("route 0.0.0.0/0 via 192.168.0.1 luid=0x47008000000000 ifindex=22 metric=0") !=
           std::string::npos,
       "tun snapshot: a default route is written with its LUID in hex");
  c.ok(text.find("route 0.0.0.0/0 via 10.0.0.0 luid=0x6008007000000 ifindex=17 metric=1") !=
           std::string::npos,
       "tun snapshot: the second default route is written too");

  std::vector<TunRoute> parsed;
  std::string error;
  c.ok(tun_routes_parse(text, &parsed, &error), "tun snapshot: round trips (" + error + ")");
  c.eq_u64(parsed.size(), 2, "tun snapshot: both routes come back");
  if (parsed.size() == 2) {
    c.eq_str(parsed[0].next_hop, "192.168.0.1", "tun snapshot: next hop survives");
    c.eq_u64(parsed[0].prefix_len, 0, "tun snapshot: prefix length survives");
    c.eq_u64(parsed[0].luid, 0x47008000000000ull, "tun snapshot: LUID survives");
    c.eq_u64(parsed[0].ifindex, 22, "tun snapshot: interface index survives");
    c.eq_u64(parsed[1].metric, 1, "tun snapshot: metric survives");
  }

  std::vector<TunRoute> rejected;
  error.clear();
  c.ok(!tun_routes_parse("netcap-tun-routes 2\n", &rejected, &error),
       "tun snapshot: an unknown format version is rejected (" + error + ")");
  error.clear();
  c.ok(!tun_routes_parse("netcap-tun-routes 1\nroute 0.0.0.0/33 via 1.2.3.4 luid=0x1 ifindex=1 metric=0\n",
                         &rejected, &error),
       "tun snapshot: a bad prefix length is rejected (" + error + ")");
  error.clear();
  c.ok(!tun_routes_parse("netcap-tun-routes 1\nroute 0.0.0.0/0 via 1.2.3.4 luid=0x1 ifindex=1 metric=0 hops=9\n",
                         &rejected, &error),
       "tun snapshot: an unknown attribute is rejected (" + error + ")");
  error.clear();
  c.ok(tun_routes_parse("netcap-tun-routes 1\n", &rejected, &error) && rejected.empty(),
       "tun snapshot: an empty snapshot parses to no routes (" + error + ")");

  // A takeover plan carries everything an undo needs: the routes that were
  // there, the interface metrics the takeover lowered, and the route it added.
  TunTakeoverPlan plan;
  plan.routes = routes;
  TunInterfaceMetric metric_one;
  metric_one.luid = 0x47008000000000ull;
  metric_one.ifindex = 22;
  metric_one.metric = 35;
  plan.ifmetrics.push_back(metric_one);
  TunInterfaceMetric metric_two;
  metric_two.luid = 0x6008007000000ull;
  metric_two.ifindex = 17;
  metric_two.metric = 0;
  plan.ifmetrics.push_back(metric_two);
  TunRoute ours;
  ours.destination = "0.0.0.0";
  ours.prefix_len = 0;
  ours.next_hop = "0.0.0.0";
  ours.luid = 0x1234;
  ours.ifindex = 52;
  ours.metric = 0;
  plan.taken.push_back(ours);

  const std::string plan_text = tun_plan_text(plan);
  c.ok(plan_text.rfind("netcap-tun-plan 2", 0) == 0,
       "tun plan: it has its own format header");
  c.ok(plan_text.find("ifmetric luid=0x47008000000000 ifindex=22 metric=35") != std::string::npos,
       "tun plan: the interface metric that was lowered is recorded");
  c.ok(plan_text.find("taken 0.0.0.0/0 via 0.0.0.0 luid=0x1234 ifindex=52 metric=0") !=
           std::string::npos,
       "tun plan: the route the takeover added is recorded");

  TunTakeoverPlan back;
  error.clear();
  c.ok(tun_plan_parse(plan_text, &back, &error), "tun plan: round trips (" + error + ")");
  c.eq_u64(back.routes.size(), 2, "tun plan: the previous default routes come back");
  c.eq_u64(back.ifmetrics.size(), 2, "tun plan: both interface metrics come back");
  c.eq_u64(back.taken.size(), 1, "tun plan: the taken route comes back");
  if (back.ifmetrics.size() == 2) {
    c.eq_u64(back.ifmetrics[0].metric, 35, "tun plan: the metric value survives");
  }
  if (back.taken.size() == 1) {
    c.eq_u64(back.taken[0].ifindex, 52, "tun plan: the taken route keeps its interface");
    c.eq_u64(back.taken[0].metric, 0, "tun plan: the taken route keeps its metric");
  }
  error.clear();
  c.ok(tun_plan_parse(text, &back, &error) && back.taken.empty() && back.routes.size() == 2,
       "tun plan: an old route-only snapshot parses with nothing to delete (" + error + ")");
  error.clear();
  c.ok(!tun_plan_parse("netcap-tun-plan 2\nifmetric luid=0x1 ifindex=2\n", &back, &error),
       "tun plan: an incomplete interface metric line is rejected (" + error + ")");
  error.clear();
  c.ok(!tun_plan_parse("netcap-tun-plan 2\nnonsense\n", &back, &error),
       "tun plan: junk lines are rejected (" + error + ")");

  // Effective metric = route metric + interface metric.  The takeover only wins
  // if nothing else already sits at 0, which is exactly what tun_takeover_is_safe
  // decides before a single route is touched.
  c.eq_u64(tun_effective_metric(0, 35), 35, "tun metric: the interface part counts");
  c.eq_u64(tun_effective_metric(1, 0), 1, "tun metric: the route part counts");
  std::string why;
  c.ok(tun_takeover_is_safe(routes, plan.ifmetrics, 0x1234, &why),
       "tun takeover: safe when every other route sits above 0 (" + why + ")");
  why.clear();
  std::vector<TunInterfaceMetric> zero_metrics;
  TunInterfaceMetric zero_one;
  zero_one.luid = 0x47008000000000ull;
  zero_one.ifindex = 22;
  zero_one.metric = 0;
  zero_metrics.push_back(zero_one);
  TunInterfaceMetric zero_two;
  zero_two.luid = 0x6008007000000ull;
  zero_two.ifindex = 17;
  zero_two.metric = 1;
  zero_metrics.push_back(zero_two);
  c.ok(!tun_takeover_is_safe(routes, zero_metrics, 0x1234, &why),
       "tun takeover: refused when another route is already at effective metric 0 (" + why + ")");
  c.ok(why.find("effective metric of 0") != std::string::npos,
       "tun takeover: the refusal says why");
  why.clear();
  c.ok(!tun_takeover_is_safe(routes, {}, 0x1234, &why),
       "tun takeover: an unreadable interface metric is treated as 0 and refused (" + why + ")");
  why.clear();
  c.ok(tun_takeover_is_safe({}, {}, 0x1234, &why), "tun takeover: an empty table is safe");
  why.clear();
  c.ok(tun_takeover_is_safe(routes, plan.ifmetrics, 0x47008000000000ull, &why),
       "tun takeover: our own leftover route is ignored (" + why + ")");

  // Forwarded UDP has to leave through a real adapter: the picker skips our own
  // tunnel interface and takes the lowest effective metric.
  {
    std::vector<TunRoute> udp_routes;
    TunRoute wifi;
    wifi.destination = "0.0.0.0";
    wifi.prefix_len = 0;
    wifi.next_hop = "192.168.0.1";
    wifi.luid = 0x47008000000000ull;
    wifi.ifindex = 22;
    wifi.metric = 0;
    TunRoute tap;
    tap.destination = "0.0.0.0";
    tap.prefix_len = 0;
    tap.next_hop = "10.0.0.1";
    tap.luid = 0x6008007000000ull;
    tap.ifindex = 17;
    tap.metric = 0;
    udp_routes.push_back(wifi);
    udp_routes.push_back(tap);
    std::vector<TunInterfaceMetric> udp_metrics;
    TunInterfaceMetric wifi_metric;
    wifi_metric.luid = wifi.luid;
    wifi_metric.ifindex = wifi.ifindex;
    wifi_metric.metric = 5;
    TunInterfaceMetric tap_metric;
    tap_metric.luid = tap.luid;
    tap_metric.ifindex = tap.ifindex;
    tap_metric.metric = 1;
    udp_metrics.push_back(wifi_metric);
    udp_metrics.push_back(tap_metric);
    c.eq_u64(tun_pick_physical_ifindex(udp_routes, udp_metrics, 99), 17,
             "udp exit: the lowest effective metric wins (0+1 beats 0+5)");
    c.eq_u64(tun_pick_physical_ifindex(udp_routes, udp_metrics, 17), 22,
             "udp exit: our own tunnel index is skipped");
    c.eq_u64(tun_pick_physical_ifindex(udp_routes, udp_metrics, 22), 17,
             "udp exit: skipping one adapter still finds the other");
    c.eq_u64(tun_pick_physical_ifindex(udp_routes, {}, 99), 22,
             "udp exit: an unreadable interface metric counts as 0");
    c.eq_u64(tun_pick_physical_ifindex({}, {}, 7), 0,
             "udp exit: an empty routing table leaves nothing to aim at");
    const std::vector<TunRoute> only_ours = {tap};
    c.eq_u64(tun_pick_physical_ifindex(only_ours, udp_metrics, 17), 0,
             "udp exit: when the only route is ours, udp stays dropped");
  }

  c.eq_str(tun_mask_from_prefix(0), "0.0.0.0", "tun mask: /0 is the all-zero mask");
  c.eq_str(tun_mask_from_prefix(24), "255.255.255.0", "tun mask: /24 is the class C mask");
  c.eq_str(tun_mask_from_prefix(32), "255.255.255.255", "tun mask: /32 is all ones");
  c.eq_str(tun_mask_from_prefix(20), "255.255.240.0", "tun mask: /20 crosses a byte boundary");
  c.eq_str(tun_mask_from_prefix(33), "", "tun mask: /33 is out of range");
  c.eq_str(tun_mask_from_prefix(-1), "", "tun mask: a negative prefix is out of range");

  c.eq_str(tun_default_name(), "netcap", "tun: the default adapter name is netcap");
  const std::vector<std::string> search = tun_dll_search_paths();
  c.ok(search.size() >= 4, "tun: several places are searched for wintun.dll");
  bool has_third_party = false;
  for (const std::string& candidate : search) {
    if (candidate.find("wintun.dll") != std::string::npos) has_third_party = true;
  }
  c.ok(has_third_party, "tun: the search paths name wintun.dll explicitly");

  const std::string help = tun_help();
  c.ok(help.find("--tun") != std::string::npos, "tun help: mentions the --tun switches");
  c.ok(help.find("--tun-takeover") != std::string::npos, "tun help: mentions --tun-takeover");
  c.ok(help.find('\n') != std::string::npos, "tun help: is more than one line long");

  std::string detail;
  tun_available(&detail);
  c.ok(!detail.empty(), "tun: tun_available always produces a printable line");

  // File round trip for the snapshot (this is what --tun-takeover / --tun-restore
  // exchange).
  const std::string snapshot_path = "netcap_selftest_tun_routes.txt";
  error.clear();
  c.ok(tun_write_file(snapshot_path, text, &error), "tun snapshot: written to disk (" + error + ")");
  std::string reloaded;
  error.clear();
  c.ok(tun_read_file(snapshot_path, &reloaded, &error), "tun snapshot: read back (" + error + ")");
  c.eq_str(reloaded, text, "tun snapshot: the file content is byte identical");
  std::remove(snapshot_path.c_str());
  error.clear();
  c.ok(!tun_read_file(snapshot_path, &reloaded, &error),
       "tun snapshot: reading a missing file fails with a message (" + error + ")");
  c.ok(!error.empty(), "tun snapshot: the failure explains itself");

  // A closed device must be refused everywhere: touching the routing table without
  // a working tunnel is how a machine loses its network.
  TunDevice closed;
  c.ok(!closed.is_open(), "tun: a fresh device is closed");
  error.clear();
  std::string snapshot_text;
  c.ok(!tun_takeover_default_routes(closed, &snapshot_text, &error),
       "tun: a takeover without an open tunnel is refused (" + error + ")");
  c.ok(error.find("not open") != std::string::npos,
       "tun: the refusal says the tunnel is not open");
  error.clear();
  c.ok(tun_restore_default_routes("", &error),
       "tun: restoring an empty snapshot is a no-op, not an error (" + error + ")");
  c.ok(!closed.write_packet(nullptr, 0, &error), "tun: writing to a closed tunnel fails");
  c.eq_u64(static_cast<std::uint64_t>(closed.read_packet(nullptr, 0, 0, &error)), 0xffffffffffffffffull,
           "tun: reading from a closed tunnel reports an error");

#ifdef _WIN32
  // Reading the live default routes is read-only and needs no privileges.
  error.clear();
  std::string live;
  c.ok(tun_default_routes(&live, &error), "tun: the live default routes can be read (" + error + ")");
  std::vector<TunRoute> live_routes;
  c.ok(tun_routes_parse(live, &live_routes, &error),
       "tun: the live snapshot parses back (" + error + ")");
  c.ok(!live_routes.empty(), "tun: this machine has at least one default route");
  for (const TunRoute& route : live_routes) {
    c.eq_u64(route.prefix_len, 0, "tun: a snapshot entry is a default route");
    c.ok(route.ifindex != 0, "tun: a snapshot entry names its interface index");
  }
#endif
}

// ------------------------------------------------------------------- sysenv
//
// The registry half of this module is exercised by tools/sysenv_probe.exe
// --selfcheck (nineteen checks, scratch variable NETCAP_SYSENV_PROBE, machine
// left as found).  What runs here is the part that must never lie: the snapshot
// format, and the refusal to guess when the snapshot is damaged.
void test_sysenv(Ctx& c) {
  c.section("sysenv: snapshots and the per-user environment");

  SysEnvState state;
  state.active = true;
  state.name = "NETCAP_SELFTEST_VAR";
  state.value = "%USERPROFILE%\\keys.log";
  state.previous = "C:\\old keys\\keys.log";
  state.had_previous = true;
  state.state_file = "netcap_selftest_sysenv.state";
  state.note = "set for programs started after the broadcast";

  const std::string text = sysenv_state_text(state, true);
  SysEnvState parsed;
  bool expandable = false;
  std::string why;
  c.ok(sysenv_state_parse(text, &parsed, &expandable, &why),
       "a snapshot round-trips through its text form: " + why);
  c.eq_str(parsed.name, state.name, "the name survives the round trip");
  c.eq_str(parsed.value, state.value, "the value survives the round trip");
  c.eq_str(parsed.previous, state.previous, "the previous value survives the round trip");
  c.ok(parsed.had_previous, "and the snapshot still remembers that there was one");
  c.ok(expandable, "a REG_EXPAND_SZ previous value is remembered as such");

  // Without had_previous there is no way to know whether restoring means
  // "write this back" or "delete the value", so the snapshot must be refused.
  const std::string crippled = "netcap-sysenv 1\nname=NETCAP_SELFTEST_VAR\nvalue=x\n";
  c.ok(!sysenv_state_parse(crippled, &parsed, nullptr, &why) && !why.empty(),
       "a snapshot without had_previous is refused");

  const std::string path = "netcap_selftest_sysenv.state";
  c.ok(sysenv_state_write(path, state, false, &why), "the snapshot is written atomically: " + why);
  SysEnvState read_back;
  bool found = false;
  bool expandable_back = true;
  c.ok(sysenv_state_read(path, &read_back, &expandable_back, &found, &why) && found,
       "and read back: " + why);
  c.eq_str(read_back.value, state.value, "with the same value");
  c.ok(!expandable_back, "and the expandable flag is not invented");
  c.ok(sysenv_state_remove(path, &why), "the snapshot is removed: " + why);
  found = true;
  c.ok(sysenv_state_read(path, &read_back, nullptr, &found, &why) && !found,
       "and is gone afterwards");

  // sysenv_current reads HKCU\Environment only, and a name nobody ever set is a
  // plain exists=false -- not an error.
  std::string value;
  bool exists = true;
  c.ok(sysenv_current("NETCAP_SELFTEST_SURELY_UNSET", &value, &exists, &why) && !exists,
       "an unset per-user variable reports exists=false instead of an error: " + why);

  // Purging the key log: zeros then unlink, and a missing file already counts as
  // purged (the session may end twice).
  {
    std::ofstream out("netcap_selftest_sysenv.keylog", std::ios::binary);
    out << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 0011223344556677 "
           "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    out.close();
    c.ok(sysenv_purge_file("netcap_selftest_sysenv.keylog", &why), "a key log is purged: " + why);
    c.ok(!std::filesystem::exists("netcap_selftest_sysenv.keylog"), "and the file is gone");
    c.ok(sysenv_purge_file("netcap_selftest_sysenv.keylog", &why),
         "purging an already purged key log succeeds: " + why);
  }
}

void test_sysproxy(Ctx& c) {
  c.section("system proxy takeover");

  SystemProxyState state;
  state.enable_present = true;
  state.enable = 1;
  state.server_present = true;
  state.server = "http=127.0.0.1:8080;https=127.0.0.1:8080";
  state.override_present = true;
  state.override_list = "<local>";
  state.auto_config_present = false;

  const std::string text = system_proxy_snapshot_text(state);
  c.ok(text.rfind("netcap-system-proxy 1", 0) == 0,
       "system proxy snapshot: starts with its format header");
  c.ok(text.find("proxy_server=http=127.0.0.1:8080;https=127.0.0.1:8080") != std::string::npos,
       "system proxy snapshot: '=' and ';' inside the server value are kept verbatim");
  c.ok(text.find("!auto_config_url") != std::string::npos,
       "system proxy snapshot: an absent value is marked with '!'");

  SystemProxyState parsed;
  std::string error;
  c.ok(system_proxy_snapshot_parse(text, &parsed, &error),
       "system proxy snapshot: round trips through the parser (" + error + ")");
  c.ok(parsed.enable_present && parsed.enabled(), "system proxy snapshot: the enable flag survives");
  c.eq_u64(parsed.enable, 1, "system proxy snapshot: the enable value survives");
  c.eq_str(parsed.server, state.server, "system proxy snapshot: the server survives");
  c.eq_str(parsed.override_list, "<local>", "system proxy snapshot: the bypass list survives");
  c.ok(!parsed.auto_config_present, "system proxy snapshot: an absent value stays absent");

  // The one name a takeover must not swallow on a machine that cannot reach it.
  // The probe has AAAA records only, so where there is no usable global IPv6 it
  // would come back as a 502 from us - the failure has to stay with the machine,
  // not with the proxy.
  c.eq_str(system_proxy_bypass_auto("", true), "",
           "system proxy bypass: a machine with usable IPv6 gets no extra bypass");
  c.eq_str(system_proxy_bypass_auto("<local>", true), "<local>",
           "system proxy bypass: with usable IPv6 the operator's list is passed through");
  c.eq_str(system_proxy_bypass_auto("", false), "<local>;ipv6.msftncsi.com",
           "system proxy bypass: without IPv6 the probe is appended to the default list");
  c.eq_str(system_proxy_bypass_auto("10.*;172.16-31.*", false),
           "10.*;172.16-31.*;ipv6.msftncsi.com",
           "system proxy bypass: an explicit list keeps its entries and gets a separator");
  c.eq_str(system_proxy_bypass_auto("<local>;ipv6.msftncsi.com", false),
           "<local>;ipv6.msftncsi.com", "system proxy bypass: the probe is never listed twice");

  // Escapes: a PAC URL or bypass list can contain separators, and a registry
  // value can in principle contain a backslash.
  SystemProxyState exotic;
  exotic.enable_present = true;
  exotic.enable = 0;
  exotic.server_present = true;
  exotic.server = "back\\slash\ttab";
  exotic.override_present = false;
  exotic.auto_config_present = true;
  exotic.auto_config_url = "one\ntwo";
  SystemProxyState exotic_parsed;
  error.clear();
  c.ok(system_proxy_snapshot_parse(system_proxy_snapshot_text(exotic), &exotic_parsed, &error),
       "system proxy snapshot: escapes round trip (" + error + ")");
  c.eq_str(exotic_parsed.server, exotic.server,
           "system proxy snapshot: a backslash and a tab survive");
  c.eq_str(exotic_parsed.auto_config_url, "one\ntwo",
           "system proxy snapshot: a newline inside a value survives");
  c.ok(!exotic_parsed.override_present, "system proxy snapshot: the absent bypass stays absent");
  c.ok(!exotic_parsed.enabled(), "system proxy snapshot: enable=0 reads back as off");

  c.ok(state.describe().find("on -> ") == 0, "system proxy state: describe() names the server");
  c.ok(state.describe().find("bypass <local>") != std::string::npos,
       "system proxy state: describe() mentions the bypass list");
  SystemProxyState off;
  c.eq_str(off.describe(), "off", "system proxy state: a fresh state describes itself as off");

  // Corrupt snapshots must be refused, never half applied.
  SystemProxyState junk;
  std::string bad;
  c.ok(!system_proxy_snapshot_parse("", &junk, &bad), "system proxy snapshot: an empty file is refused");
  c.ok(bad.find("empty") != std::string::npos, "system proxy snapshot: the emptiness is named");
  c.ok(!system_proxy_snapshot_parse("something else\n", &junk, &bad),
       "system proxy snapshot: a foreign file is refused");
  c.ok(bad.find("not a netcap system proxy snapshot") != std::string::npos,
       "system proxy snapshot: a foreign file says what it expected");
  c.ok(!system_proxy_snapshot_parse("netcap-system-proxy 1\ncolour=red\n", &junk, &bad),
       "system proxy snapshot: an unknown key is refused");
  c.ok(bad.find("unknown key") != std::string::npos, "system proxy snapshot: the unknown key is named");
  c.ok(!system_proxy_snapshot_parse("netcap-system-proxy 1\nproxy_enable=yes\n", &junk, &bad),
       "system proxy snapshot: a non-numeric enable flag is refused");
  c.ok(!system_proxy_snapshot_parse("netcap-system-proxy 1\nproxy_server\n", &junk, &bad),
       "system proxy snapshot: a value without '=' is refused");
  c.ok(!system_proxy_snapshot_parse("netcap-system-proxy 1\nproxy_server=a\\\n", &junk, &bad),
       "system proxy snapshot: a trailing backslash is refused");

  // Endpoints.
  u16 port = 0;
  std::string normalized;
  std::string why;
  c.ok(system_proxy_endpoint_ok("127.0.0.1:8080", &port, &normalized, &why),
       "system proxy endpoint: host:port is accepted (" + why + ")");
  c.eq_u64(port, 8080, "system proxy endpoint: the port is parsed");
  c.eq_str(normalized, "127.0.0.1:8080", "system proxy endpoint: the endpoint is normalized");
  c.ok(system_proxy_endpoint_ok("localhost", &port, &normalized, &why),
       "system proxy endpoint: a bare host is accepted");
  c.eq_u64(port, 0, "system proxy endpoint: a bare host has no port");
  c.eq_str(normalized, "localhost", "system proxy endpoint: a bare host is echoed back");
  c.ok(system_proxy_endpoint_ok("[::1]:1080", &port, &normalized, &why),
       "system proxy endpoint: a bracketed IPv6 literal with a port is accepted");
  c.eq_u64(port, 1080, "system proxy endpoint: the IPv6 port is parsed");
  c.ok(!system_proxy_endpoint_ok("::1", &port, &normalized, &why),
       "system proxy endpoint: a bare IPv6 address is refused");
  c.ok(why.find("[ ]") != std::string::npos, "system proxy endpoint: the refusal explains the brackets");
  c.ok(!system_proxy_endpoint_ok(":8080", &port, &normalized, &why),
       "system proxy endpoint: a missing host is refused");
  c.ok(!system_proxy_endpoint_ok("host:0", &port, &normalized, &why),
       "system proxy endpoint: port 0 is refused");
  c.ok(!system_proxy_endpoint_ok("host:70000", &port, &normalized, &why),
       "system proxy endpoint: an out of range port is refused");
  c.ok(!system_proxy_endpoint_ok("", &port, &normalized, &why),
       "system proxy endpoint: an empty endpoint is refused");

  // Snapshot files.
  const std::string path = "netcap_selftest_sysproxy.state";
  std::string file_error;
  c.ok(system_proxy_snapshot_write(state, path, &file_error),
       "system proxy snapshot: writes a file (" + file_error + ")");
  c.ok(system_proxy_snapshot_exists(path), "system proxy snapshot: the file exists");
  SystemProxyState from_file;
  file_error.clear();
  c.ok(system_proxy_snapshot_load(path, &from_file, &file_error), "system proxy snapshot: loads it back");
  c.eq_str(from_file.server, state.server, "system proxy snapshot: the file keeps the server");
  c.ok(system_proxy_snapshot_remove(path), "system proxy snapshot: removes the file");
  c.ok(!system_proxy_snapshot_exists(path), "system proxy snapshot: the file is gone");
  c.ok(!system_proxy_snapshot_write(state, "", &file_error),
       "system proxy snapshot: refuses to write without a path");

  std::string note;
  const bool available = system_proxy_available(&note);
  c.ok(!note.empty(), "system proxy availability: explains the platform");
  c.ok(!system_proxy_note().empty(), "system proxy platform note: not empty");

#ifdef _WIN32
  c.ok(available, "system proxy availability: the WinINET settings exist on Windows");
  c.ok(note.find("Internet Settings") != std::string::npos,
       "system proxy availability: names the registry key it uses");

  // Read-only: a self test is allowed to look, never to write.
  SystemProxyState live;
  std::string read_error;
  c.ok(system_proxy_read(&live, &read_error),
       "system proxy: the live settings are readable (" + read_error + ")");
  c.ok(!live.describe().empty(), "system proxy: the live settings describe themselves");
  c.ok(system_proxy_report().find("ProxyEnable") != std::string::npos,
       "system proxy report: lists the registry values");

  // The safety invariant: if the snapshot cannot be written, nothing may be
  // touched - so a take-over is attempted with a path inside a directory that
  // does not exist and the live settings are compared across the call.
  SystemProxyState saved;
  std::string enable_error;
  const bool taken = system_proxy_enable("127.0.0.1:65000", "<local>",
                                         "_netcap_no_such_dir_/sysproxy.state", &saved,
                                         &enable_error);
  c.ok(!taken, "system proxy: a takeover with an unwritable snapshot is refused");
  c.ok(!enable_error.empty(), "system proxy: the refusal carries a reason");
  SystemProxyState after;
  std::string after_error;
  if (system_proxy_read(&after, &after_error)) {
    c.eq_u64(after.enable, live.enable, "system proxy: a refused takeover left ProxyEnable alone");
    c.eq_str(after.server, live.server, "system proxy: a refused takeover left ProxyServer alone");
    c.eq_str(after.override_list, live.override_list,
             "system proxy: a refused takeover left ProxyOverride alone");
    c.eq_str(after.auto_config_url, live.auto_config_url,
             "system proxy: a refused takeover left AutoConfigURL alone");
  } else {
    c.ok(false, "system proxy: the settings are still readable after the refusal");
  }

  // Restoring with no snapshot is a no-op, not an error: that is what a second
  // `--system-proxy restore` and a clean shutdown both do.
  SystemProxyState restored;
  bool had = true;
  std::string restore_error;
  c.ok(system_proxy_restore("netcap_selftest_no_such_snapshot.state", &restored, &had,
                            &restore_error),
       "system proxy: restoring without a snapshot succeeds (" + restore_error + ")");
  c.ok(!had, "system proxy: restoring without a snapshot says there was nothing to do");

  // A definitely-foreign endpoint is not the current proxy, and reading it does
  // not disturb anything.
  c.ok(!system_proxy_active("203.0.113.9:9"),
       "system proxy: TEST-NET-3 is not the current system proxy");

  // Chaining: the upstream handed to the blocker is what keeps the machine
  // online after a takeover, so how it is picked is pinned here.
  {
    std::string upstream;
    std::string chain_error;
    c.ok(system_proxy_upstream_from_server("127.0.0.1:7890", &upstream, &chain_error) &&
             upstream == "127.0.0.1:7890",
         "system proxy: a plain host:port is accepted as the upstream");
    upstream.clear();
    c.ok(system_proxy_upstream_from_server("http=127.0.0.1:7890;https=127.0.0.1:7891", &upstream,
                                           &chain_error) &&
             upstream == "127.0.0.1:7890",
         "system proxy: a per-scheme list yields the http entry");
    c.ok(!system_proxy_upstream_from_server("socks=127.0.0.1:1080", &upstream, &chain_error),
         "system proxy: a SOCKS-only value cannot be chained through");
    c.ok(chain_error.find("SOCKS") != std::string::npos,
         "system proxy: that refusal says chaining is HTTP only");
    c.ok(!system_proxy_upstream_from_server("", &upstream, &chain_error),
         "system proxy: an empty server value is refused");

    SystemProxyState configured;
    configured.server_present = true;
    configured.server = "http=127.0.0.1:26561";
    const std::vector<std::string> candidates = system_proxy_candidate_upstreams(configured);
    c.ok(!candidates.empty() && candidates[0] == "127.0.0.1:26561",
         "system proxy: the configured proxy is the first chaining candidate");
    bool has_local_proxy_port = false;
    bool duplicated = false;
    for (std::size_t i = 0; i < candidates.size(); ++i) {
      if (candidates[i] == "127.0.0.1:7890") has_local_proxy_port = true;
      for (std::size_t j = i + 1; j < candidates.size(); ++j) {
        if (candidates[i] == candidates[j]) duplicated = true;
      }
    }
    c.ok(has_local_proxy_port, "system proxy: the usual local proxy ports are tried as well");
    c.ok(!duplicated, "system proxy: the candidate list has no duplicates");

    // The probe is a liveness check, so both answers are pinned: a listener
    // answers, and the same port once the listener is gone does not.
    SOCKET probe_listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (probe_listener != INVALID_SOCKET) {
      sockaddr_in name;
      std::memset(&name, 0, sizeof(name));
      name.sin_family = AF_INET;
      name.sin_port = 0;
      name.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      const bool bound = ::bind(probe_listener, reinterpret_cast<sockaddr*>(&name), sizeof(name)) == 0 &&
                         ::listen(probe_listener, 4) == 0;
      int name_len = static_cast<int>(sizeof(name));
      u16 probe_port = 0;
      if (bound && ::getsockname(probe_listener, reinterpret_cast<sockaddr*>(&name), &name_len) == 0) {
        probe_port = ntohs(name.sin_port);
      }
      std::string probe_error;
      c.ok(bound && probe_port != 0 &&
               system_proxy_probe("127.0.0.1:" + std::to_string(probe_port), 1500, &probe_error),
           "system proxy: the probe finds a live endpoint");
      if (bound) ::closesocket(probe_listener);
      probe_error.clear();
      c.ok(!system_proxy_probe("127.0.0.1:" + std::to_string(probe_port), 300, &probe_error),
           "system proxy: the probe reports a dead port as dead");
      c.ok(!probe_error.empty(), "system proxy: a failed probe explains itself");
    } else {
      c.ok(false, "system proxy: a listener for the probe test could be created");
    }
  }
#else
  c.ok(!available, "system proxy availability: not available off Windows");
#endif
}

// ------------------------------------------------------------ P-256 / X.509

// The third ECDHE group.  It exists because a client was measured offering a
// secp521r1 key share and nothing this stack could use, and a curve that only
// one rare client exercises is a curve nobody would notice breaking -- so the
// arithmetic is pinned to vectors from an independent implementation.
void test_p521(Ctx& c) {
  c.section("P-521 arithmetic");

  std::string why;
  const bool kat = p521_selfcheck(&why);
  c.ok(kat, "p521_selfcheck passes: " + why);

  P521Point zero_point;
  zero_point.infinity = false;
  zero_point.x.assign(66, 0);
  zero_point.y.assign(66, 0);
  c.ok(!p521_valid_public(zero_point), "the point (0,0) is not a P-521 public key");
  P521Point infinity;
  c.ok(!p521_valid_public(infinity), "the point at infinity is not a P-521 public key");

  P521Key ours;
  c.ok(p521_generate(&ours), "an ephemeral secp521r1 key is generated");
  c.ok(ours.d.size() == 66 && p521_valid_public(ours.q),
       "the generated P-521 key has a 66 byte scalar and a point on the curve");
  const Bytes encoded = p521_serialize_uncompressed(ours.q);
  c.ok(encoded.size() == 133 && encoded[0] == 4,
       "a P-521 key share is 133 bytes of SEC 1 uncompressed point");
  P521Point back;
  c.ok(p521_parse_point(encoded.data(), encoded.size(), &back) && back.x == ours.q.x &&
           back.y == ours.q.y,
       "a P-521 key share survives the round trip through its wire encoding");

  P521Key peer;
  c.ok(p521_generate(&peer), "a second ephemeral P-521 key is generated");
  Bytes mine;
  Bytes theirs;
  c.ok(p521_ecdh(ours, peer.q, &mine) && p521_ecdh(peer, ours.q, &theirs) && mine == theirs,
       "two fresh P-521 keys derive the same shared secret in both directions");
  c.ok(mine.size() == 66, "the P-521 shared secret is the 66 byte x coordinate");
}

// The curve that both signs our MITM certificates and carries the TLS 1.3 key
// share. Checked against the published RFC 6979 vectors so the arithmetic, the
// hashing and the nonce derivation are all pinned to something external.
void test_p256(Ctx& c) {
  c.section("P-256 arithmetic");

  // The fast field engine (4-limb Montgomery + wNAF) is cross-checked against
  // the plain big-integer path it replaced: a wrong carry shows up right here
  // rather than as an occasional handshake failure.
  {
    // Call first, assert second: the message has to carry the report, and
    // building it as an argument would read `why` before the call fills it.
    std::string why;
    const bool engine_ok = p256_selfcheck(&why);
    c.ok(engine_ok, "the fast field engine agrees with the big-integer path" +
                        (why.empty() ? std::string() : ": " + why));
  }

  // Most origins hold an RSA key, so the RSA verifier is on the critical path:
  // prove the blob layout and the padding flags against the platform signer.
  {
    std::string why;
    const bool rsa_ok = rsa_selfcheck(&why);
    c.ok(rsa_ok, "the RSA verifier agrees with the platform signer" +
                     (why.empty() ? std::string() : ": " + why));
  }

  // d = 1 has to land exactly on the generator.
  {
    Bytes d(32, 0);
    d[31] = 1;
    P256Key k;
    c.ok(p256_from_private(d, &k), "d=1 derives a key");
    c.eq_hex(k.q.x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "1*G x");
    c.eq_hex(k.q.y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", "1*G y");
    c.ok(!k.q.infinity, "the generator is not the point at infinity");
  }

  // RFC 6979 A.2.5: ECDSA P-256 + SHA-256 over the message "sample".
  {
    const Bytes d = from_hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    const std::string msg = "sample";
    const Bytes digest = sha256(reinterpret_cast<const u8*>(msg.data()), msg.size());
    c.eq_hex(digest, "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf", "SHA-256(\"sample\")");
    Bytes r;
    Bytes s;
    c.ok(p256_ecdsa_sign(d, digest.data(), &r, &s), "signing succeeds");
    c.eq_hex(r, "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", "r matches RFC 6979 A.2.5");
    c.eq_hex(s, "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", "s matches RFC 6979 A.2.5");
    P256Key pub;
    c.ok(p256_from_private(d, &pub), "the public key derives");
    c.ok(p256_ecdsa_verify(pub.q, digest.data(), r, s), "the signature verifies");
    Bytes bad = r;
    bad[31] ^= 1;
    c.ok(!p256_ecdsa_verify(pub.q, digest.data(), bad, s), "a tampered r is rejected");
    Bytes other = digest;
    other[0] ^= 1;
    c.ok(!p256_ecdsa_verify(pub.q, other.data(), r, s), "a different digest is rejected");
  }

  // Two sides of an ECDH exchange must agree.
  {
    P256Key a;
    P256Key b;
    c.ok(p256_generate(&a), "key generation a");
    c.ok(p256_generate(&b), "key generation b");
    c.ok(a.d != b.d, "two generated keys differ");
    Bytes ab;
    Bytes ba;
    c.ok(p256_ecdh(a, b.q, &ab), "ecdh a*b");
    c.ok(p256_ecdh(b, a.q, &ba), "ecdh b*a");
    c.ok(ab == ba && ab.size() == 32, "both sides derive the same shared x");
  }

  // Point encodings, and the rejection of a point that is not on the curve.
  {
    P256Key k;
    c.ok(p256_generate(&k), "key generation for encodings");
    const Bytes uncompressed = p256_serialize_uncompressed(k.q);
    const Bytes compressed = p256_serialize_compressed(k.q);
    c.eq_u64(uncompressed.size(), 65, "uncompressed encoding is 65 bytes");
    c.eq_u64(compressed.size(), 33, "compressed encoding is 33 bytes");
    c.ok(uncompressed[0] == 0x04, "uncompressed starts with 0x04");
    c.ok(compressed[0] == 0x02 || compressed[0] == 0x03, "compressed keeps the y parity");
    P256Point p1;
    P256Point p2;
    c.ok(p256_parse_point(uncompressed.data(), uncompressed.size(), &p1) && p1.x == k.q.x && p1.y == k.q.y,
         "uncompressed round trip");
    c.ok(p256_parse_point(compressed.data(), compressed.size(), &p2) && p2.y == k.q.y, "compressed round trip");
    c.ok(p256_valid_public(k.q), "a generated point is valid");
    Bytes junk(65, 0);
    junk[0] = 0x04;
    c.ok(!p256_parse_point(junk.data(), junk.size(), &p1), "a point off the curve is rejected");
  }
}

// Mints a CA, issues a leaf for a host, then reloads both from PEM. The same
// files are checked with OpenSSL from the test runner's verification steps.
void test_x509(Ctx& c) {
  c.section("X.509 certificates");

  // A DER INTEGER is a signed big-endian value, so a modulus whose top bit is
  // set carries a leading 0x00 that is not part of the number.  Keeping it made
  // a 2048-bit key look like 2056 bits, every RSA ClientKeyExchange one byte too
  // long, and every RSA origin answered `decrypt_error`.
  {
    const u8 padded[] = {0x00, 0x80, 0x01};
    const Bytes v = der_integer_value(padded, sizeof padded);
    c.eq_u64(v.size(), 2, "the DER sign byte is stripped off an INTEGER");
    c.eq_u64(v[0], 0x80, "the value behind the sign byte survives");
    const u8 plain[] = {0x7f, 0xff};
    c.eq_u64(der_integer_value(plain, sizeof plain).size(), 2,
             "a value whose top bit is clear keeps its length");
    const u8 several[] = {0x00, 0x00, 0x01};
    c.eq_u64(der_integer_value(several, sizeof several).size(), 1, "every leading zero goes, not just one");
    const u8 zero_only[] = {0x00, 0x00};
    c.eq_u64(der_integer_value(zero_only, sizeof zero_only).size(), 1, "zero itself stays one byte");
  }

  const std::string crt = "netcap_selftest_ca.crt";
  const std::string key = "netcap_selftest_ca.key";
  std::string error;

  CaBundle ca;
  c.ok(ca_create(X509Subject{"netcap Selftest CA", "netcap", "CN"}, 3650, &ca, &error),
       "a certificate authority can be minted");
  if (!ca.valid()) {
    c.ok(false, std::string("the minted CA is unusable: ") + error);
    return;
  }
  c.eq_str(ca.cert.subject_cn, "netcap Selftest CA", "CA subject CN round-trips");
  c.eq_str(ca.cert.issuer_cn, "netcap Selftest CA", "the CA is self-issued");
  c.ok(ca.cert.is_ca, "basicConstraints says CA:TRUE");
  c.eq_u64(ca.cert.sha256.size(), 32, "the CA fingerprint is a SHA-256");
  c.ok(ca.cert_pem.find("BEGIN CERTIFICATE") != std::string::npos, "the CA exports as PEM");
  c.ok(ca.key_pem.find("BEGIN PRIVATE KEY") != std::string::npos, "the CA key exports as PKCS#8 PEM");
  c.ok(x509_verify_signature(ca.cert, ca.cert), "the CA signature verifies against itself");
  c.ok(ca.cert.public_key.x == ca.key.q.x && ca.cert.public_key.y == ca.key.q.y,
       "the certificate carries the CA public key");
  c.eq_hex(ca.cert.public_key.x, to_hex(ca.key.q.x), "the certificate x coordinate is the key's");

  c.ok(ca_write_files(ca, crt, key, &error), "the CA can be written to disk");
  if (!error.empty()) c.ok(false, std::string("ca_write_files: ") + error);

  P256Key leaf_key;
  X509Cert leaf;
  LeafRequest req;
  req.host = "example.com";
  req.extra_dns.push_back("www.example.com");
  req.ip_addresses.push_back("127.0.0.1");
  c.ok(leaf_issue(ca, req, &leaf_key, &leaf, &error), "a leaf for example.com can be issued");
  c.eq_str(leaf.subject_cn, "example.com", "the leaf subject CN is the host");
  c.eq_str(leaf.issuer_cn, "netcap Selftest CA", "the leaf issuer is the CA");
  c.ok(!leaf.is_ca, "the leaf is not a CA");
  c.ok(leaf.issuer == ca.cert.subject, "the leaf repeats the CA subject DN byte for byte");
  c.eq_u64(leaf.dns_names.size(), 2, "the leaf carries both DNS names");
  c.eq_u64(leaf.ip_names.size(), 1, "the leaf carries the IP SAN");
  c.ok(leaf.sha256_hex().size() == 64, "the leaf fingerprint is hex encoded");
  c.ok(x509_verify_signature(leaf, ca.cert), "the leaf signature verifies against the CA");
  c.ok(leaf_key.q.x == leaf.public_key.x, "the leaf public key matches its private key");
  c.ok(x509_matches_host(leaf, "example.com"), "the leaf matches example.com");
  c.ok(x509_matches_host(leaf, "www.example.com"), "the leaf matches www.example.com");
  c.ok(!x509_matches_host(leaf, "example.org"), "the leaf does not match example.org");
  c.ok(!x509_matches_host(leaf, "www.example.org"), "the leaf does not match www.example.org");

  // Reload the CA from disk: PEM plus PKCS#8 round trip.
  CaBundle reread;
  c.ok(ca_read_files(crt, key, &reread, &error), "the CA reloads from PEM");
  c.ok(reread.valid(), "the reloaded CA is usable");
  c.ok(reread.key.d == ca.key.d, "the reloaded CA key matches");
  c.ok(reread.cert.der == ca.cert.der, "the reloaded CA certificate matches");
  c.ok(x509_verify_signature(leaf, reread.cert), "the leaf still verifies against the reloaded CA");

  // A leaf whose tbsCertificate was touched must not verify.
  {
    X509Cert copy = leaf;
    copy.tbs[copy.tbs.size() / 2] ^= 0x01;
    c.ok(!x509_verify_signature(copy, ca.cert), "a tampered leaf is rejected");
  }

  // Host matching for a wildcard and for an embedded IPv4 address.
  {
    P256Key wild_key;
    X509Cert wild;
    LeafRequest wreq;
    wreq.host = "*.example.net";
    c.ok(leaf_issue(ca, wreq, &wild_key, &wild, &error), "a wildcard leaf can be issued");
    c.ok(x509_matches_host(wild, "a.example.net"), "a wildcard matches one label");
    c.ok(x509_matches_host(wild, "A.EXAMPLE.NET"), "host matching ignores case");
    c.ok(!x509_matches_host(wild, "a.b.example.net"), "a wildcard does not match two labels");
    c.ok(!x509_matches_host(wild, "example.net"), "a wildcard does not match the bare domain");
  }

  // Hostile server names.  The host here is whatever a ClientHello SNI carried,
  // and a name must never make the certificate builder throw: an exception
  // escaping a connection thread is std::terminate, and a proxy that dies
  // mid-session leaves the machine with a dead proxy address.
  {
    std::vector<std::string> hosts;
    hosts.push_back(std::string(300, 'a'));
    hosts.push_back(std::string(63, 'b'));
    hosts.push_back(std::string(1, 'c') + std::string("\0\1\2", 3) + ".example.com");
    hosts.push_back("...");
    hosts.push_back(std::string(4096, 'd') + ".example.com");
    hosts.push_back("");
    bool survived = true;
    std::string threw;
    for (const std::string& hostile : hosts) {
      try {
        P256Key hostile_key;
        X509Cert hostile_leaf;
        std::string hostile_error;
        LeafRequest hostile_req;
        hostile_req.host = hostile;
        leaf_issue(ca, hostile_req, &hostile_key, &hostile_leaf, &hostile_error);
      } catch (const std::exception& e) {
        survived = false;
        threw = e.what();
        break;
      } catch (...) {
        survived = false;
        threw = "unknown";
        break;
      }
    }
    c.ok(survived, std::string("a hostile server name cannot make the leaf issuer throw") +
                       (threw.empty() ? std::string() : std::string(" (") + threw + ")"));
    P256Key again_key;
    X509Cert again_leaf;
    std::string again_error;
    LeafRequest again_req;
    again_req.host = "after-hostile.example";
    c.ok(leaf_issue(ca, again_req, &again_key, &again_leaf, &again_error),
         "the CA still issues leaves after the hostile names");
  }

  std::remove(crt.c_str());
  std::remove(key.c_str());
}

// X25519 is what carries the TLS 1.3 key share, so it gets the RFC 7748
// vectors as well as a round trip through the base point.
void test_x25519(Ctx& c) {
  c.section("X25519 key exchange");

  // RFC 7748 §5.2: one iteration of the loop starting from u = 9.
  {
    Bytes k(32, 0);
    k[0] = 9;
    Bytes out;
    c.ok(x25519(k, k, &out), "one iteration runs");
    c.eq_hex(out, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", "RFC 7748 §5.2 iteration");
  }

  // RFC 7748 §6.1: the published Diffie-Hellman exchange.
  {
    const Bytes alice_priv = from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const Bytes bob_priv = from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    Bytes alice_pub;
    Bytes bob_pub;
    c.ok(x25519_public(alice_priv, &alice_pub), "alice derives a public key");
    c.eq_hex(alice_pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "alice public");
    c.ok(x25519_public(bob_priv, &bob_pub), "bob derives a public key");
    c.eq_hex(bob_pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "bob public");
    Bytes shared_a;
    Bytes shared_b;
    c.ok(x25519(alice_priv, bob_pub, &shared_a), "alice computes the secret");
    c.ok(x25519(bob_priv, alice_pub, &shared_b), "bob computes the secret");
    c.eq_hex(shared_a, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "shared secret");
    c.ok(shared_a == shared_b, "both sides agree");
  }

  // The raw entry point on a clamped scalar, straight from §5.2.
  {
    Bytes k = from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    const Bytes u = from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    Bytes out;
    c.ok(x25519_scalar_mult(k, u, &out), "raw scalar multiplication runs");
    c.eq_hex(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "RFC 7748 §5.2 vector");
  }

  // Low order inputs must be refused: an all-zero secret would silently weaken
  // the handshake.
  {
    const Bytes alice_priv = from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    Bytes zero(32, 0);
    Bytes out;
    c.ok(!x25519(alice_priv, zero, &out), "an all-zero peer key is rejected");
    c.ok(x25519_is_zero(zero), "the zero test recognises zeroes");
    Bytes one(32, 0);
    one[0] = 1;
    c.ok(!x25519_is_zero(one), "the zero test is not fooled by a one");
  }

  // Fresh keys, clamping, and agreement.
  {
    X25519Key a;
    X25519Key b;
    c.ok(x25519_keypair(&a), "keypair a");
    c.ok(x25519_keypair(&b), "keypair b");
    c.ok(a.priv.size() == 32 && a.pub.size() == 32, "key material is 32 bytes wide");
    c.ok((a.priv[0] & 7) == 0 && (a.priv[31] & 128) == 0 && (a.priv[31] & 64) != 0,
         "the private key is clamped as RFC 7748 §5 requires");
    c.ok(a.priv != b.priv, "two key pairs differ");
    Bytes ab;
    Bytes ba;
    c.ok(x25519(a.priv, b.pub, &ab), "a derives the shared secret");
    c.ok(x25519(b.priv, a.pub, &ba), "b derives the shared secret");
    c.ok(ab == ba && ab.size() == 32, "generated keys agree");
    c.ok(!x25519_describe(a.pub).empty(), "describe works");
  }
}

#ifdef _WIN32
// Adapts a connected socket to the TLS engine's transport hooks: `read` fills
// exactly the number of bytes it was asked for, `write` sends all of them.
Tls13Io tls13_io_from_socket(SOCKET s) {
  Tls13Io io;
  io.read = [s](u8* out, std::size_t want, std::size_t* got) -> bool {
    *got = 0;
    while (*got < want) {
      const int rc =
          ::recv(s, reinterpret_cast<char*>(out) + *got, static_cast<int>(want - *got), 0);
      if (rc <= 0) return false;
      *got += static_cast<std::size_t>(rc);
    }
    return true;
  };
  io.write = [s](const u8* data, std::size_t len) -> bool {
    std::size_t sent = 0;
    while (sent < len) {
      const int rc = ::send(s, reinterpret_cast<const char*>(data) + sent,
                            static_cast<int>(len - sent), 0);
      if (rc <= 0) return false;
      sent += static_cast<std::size_t>(rc);
    }
    return true;
  };
  return io;
}
#endif

// --------------------------------------------------------------- TLS 1.3
// The interception proxy speaks TLS 1.3 itself, so the engine is exercised
// here for real: records and the key schedule first, then a loopback handshake
// between our own server side and our own client side, with a certificate
// issued on the fly by a throw-away CA.
// The TLS 1.2 upstream client: the key schedule, the record layer and the
// Finished computation are exercised here; the handshake itself needs a 1.2
// server, which the live proxy tests cover.
void test_tls12(Ctx& c) {
  c.section("TLS 1.2 client (upstream leg)");
  std::string why;
  const bool ok = tls12_selfcheck(&why);
  c.ok(ok, "the TLS 1.2 key schedule, record layer and Finished agree" + (why.empty() ? std::string() : " — " + why));
  c.eq_u64(tls12_offered_suites(0x0303).size(), 17, "the client offers 17 suites to a TLS 1.2 origin");
  // GCM and ChaCha20-Poly1305 were defined for 1.2, and the SHA-256 CBC suites
  // arrived with 1.2 as well, so a 1.0/1.1 hello still has something to offer.
  c.eq_u64(tls12_offered_suites(0x0301).size(), 6, "a TLS 1.0 ClientHello offers the six SHA-1 CBC suites");
  c.eq_u64(tls12_offered_suites(0x0302).size(), 6, "TLS 1.1 gets the same list as 1.0");
  c.ok(tls12_suite(0xC02B) != nullptr, "ECDHE-ECDSA-AES128-GCM-SHA256 is in the table");
  c.ok(tls12_suite(0xCCA9) != nullptr, "ECDHE-ECDSA-CHACHA20-POLY1305 is in the table");
  c.ok(tls12_suite(0x002F) != nullptr && tls12_suite(0x002F)->cbc && tls12_suite(0x002F)->rsa_key_exchange &&
           tls12_suite(0x002F)->mac_len == 20,
       "RSA-AES128-CBC-SHA is a CBC suite with an RSA key exchange and a 20 byte MAC");
  c.ok(tls12_suite(0xC027) != nullptr && tls12_suite(0xC027)->cbc && !tls12_suite(0xC027)->rsa_key_exchange &&
           tls12_suite(0xC027)->mac_len == 32,
       "ECDHE-RSA-AES128-CBC-SHA256 is ECDHE with a 32 byte MAC");
  c.eq_str(tls12_suite_name(0xC02F), "ECDHE-RSA-AES128-GCM-SHA256", "suite names are spelled out");
  c.eq_str(tls12_suite_name(0x1301), "0x1301", "a TLS 1.3 suite is not in the 1.2 table");

  // Known answers for the PRF itself (RFC 5246 §5).  The inputs are a real capture and
  // the expected values were cross-checked with an independent implementation; the
  // first version of tls12_prf() left the label out of A(0), which made every TLS 1.2
  // key wrong and every origin answer with a plaintext bad_record_mac.
  {
    const Bytes pms = from_hex("49dd73917a4ffc68f05d1d4a8b01a479782bd5b46e25d767e6406c299a698749");
    const Bytes client_random = from_hex("1acbcbf07eada2acf18b6608ed26b9bd341ed2c9a6b5dcd6288242471115d490");
    const Bytes server_random = from_hex("d7dceebce0026d808af772f3cfdb14d77a4c70d5cb18ced376ef8b9df78d9e5e");
    Bytes master_seed = client_random;
    master_seed.insert(master_seed.end(), server_random.begin(), server_random.end());
    const Bytes master = tls12_prf(pms, "master secret", master_seed, 48);
    c.eq_hex(master, "4bc5f1aa3b9ffe3c242a8d6fc88cad316b92413d84e8c827a00c17e6b74413c46ebe50d11d3921e772714a4048c13931",
             "the TLS 1.2 PRF matches its known answer (label inside A(0))");
    Bytes expand_seed = server_random;
    expand_seed.insert(expand_seed.end(), client_random.begin(), client_random.end());
    const Bytes block = tls12_prf(master, "key expansion", expand_seed, 40);
    c.eq_hex(Bytes(block.begin(), block.begin() + 16), "a1f577ef5505e8e7828cf056560e0efb",
             "key expansion yields the recorded client key");
    c.eq_hex(Bytes(block.begin() + 32, block.begin() + 36), "f2524b2c",
             "key expansion yields the recorded client IV");
  }

  // TLS 1.0/1.1 use a different PRF (RFC 2246 §5: P_MD5(S1) XOR P_SHA1(S2)), so it
  // gets its own known answers from an independent implementation (Python hmac).
  {
    const Bytes pms = from_hex("49dd73917a4ffc68f05d1d4a8b01a479782bd5b46e25d767e6406c299a698749");
    const Bytes client_random = from_hex("1acbcbf07eada2acf18b6608ed26b9bd341ed2c9a6b5dcd6288242471115d490");
    const Bytes server_random = from_hex("d7dceebce0026d808af772f3cfdb14d77a4c70d5cb18ced376ef8b9df78d9e5e");
    Bytes seed = client_random;
    seed.insert(seed.end(), server_random.begin(), server_random.end());
    c.eq_hex(tls_prf_legacy(pms, "master secret", seed, 48),
             "dd1bc5a38fca764d7a32fd49e35a7527c2a025176bfd969cafae7a51488ac0ac43c9932843cbd86ec2d65c864167cda2",
             "the TLS 1.0/1.1 PRF (MD5 xor SHA1) matches its known answer");
    c.eq_hex(tls_prf_legacy(Bytes(48, 0x5a), "client finished", seed, 12), "d73edc5c42cdcb69c780c151",
             "the legacy PRF keeps the label outside A(0) for Finished as well");
    c.eq_hex(tls_prf_legacy(Bytes(48, 0x5a), "server finished", seed, 12), "ea759a9084091403afccefa5",
             "and the server label produces the server value");
    c.ok(tls_prf_legacy(pms, "master secret", seed, 48) != tls12_prf(pms, "master secret", seed, 48),
         "the legacy PRF and the 1.2 PRF disagree, so the version really picks one");
    c.ok(tls12_finished_data_legacy(Bytes(48, 0x5a), false, seed) !=
             tls12_finished_data(Bytes(48, 0x5a), false, sha256(seed)),
         "the 1.0/1.1 Finished is not simply the 1.2 Finished");
  }

  // Suites that differ in key length, IV length, MAC construction and protocol
  // version must all round trip through the record layer.
  struct RecordCase {
    u16 id;
    int version;
  };
  for (const RecordCase& tc : {RecordCase{0xC02B, 0x0303}, RecordCase{0xCCA9, 0x0303},
                               RecordCase{0xC027, 0x0303}, RecordCase{0x002F, 0x0301},
                               RecordCase{0x009C, 0x0303}}) {
    const u16 id = tc.id;
    Tls12Secrets secrets;
    secrets.suite = id;
    secrets.version = tc.version;
    secrets.client_random.assign(32, 0x11);
    secrets.server_random.assign(32, 0x22);
    std::string error;
    if (!tls12_derive_keys(&secrets, Bytes(48, 0x5a), Bytes(), &error)) {
      c.ok(false, "key schedule for " + tls12_suite_name(id) + ": " + error);
      continue;
    }
    Tls12Secrets peer = secrets;
    peer.server_key = secrets.client_key;
    peer.server_iv = secrets.client_iv;
    peer.server_mac = secrets.client_mac;
    const Bytes message = Bytes(200, 0x41);
    Bytes record;
    if (!tls12_seal(&secrets, 0, 23, message, &record, &error)) {
      c.ok(false, "sealing with " + tls12_suite_name(id) + ": " + error);
      continue;
    }
    u8 type = 0;
    Bytes plain;
    const bool opened = tls12_open(&peer, 1, record, &type, &plain, &error);
    c.ok(opened && plain == message && type == 23,
         "a 200 byte application record round trips with " + tls12_suite_name(id));
    if (opened) {
      record[record.size() - 1] ^= 0x01;
      u8 t2 = 0;
      Bytes p2;
      const u64 before = peer.server_seq;
      const bool accepted = tls12_open(&peer, 1, record, &t2, &p2, &error);
      c.ok(!accepted && peer.server_seq == before, "a tampered record is rejected without moving the sequence number");
    }
  }
}

void test_tls13(Ctx& c) {
  c.section("TLS 1.3 records and key schedule");  {
    const Bytes msg = tls13_handshake(1, Bytes{0xaa, 0xbb});
    c.eq_u64(msg.size(), 6, "a handshake message is a type plus a 3 byte length");
    c.eq_hex(msg, "01000002aabb", "the handshake header carries the length big endian");

    std::size_t off = 0;
    u8 type = 0;
    Bytes got;
    c.ok(tls13_next_handshake(msg, &off, &type, &got), "the message can be read back");
    c.eq_u64(type, 1, "the handshake type survives the round trip");
    c.eq_hex(got, "01000002aabb", "the reader hands back the whole message");
    c.eq_u64(off, msg.size(), "the offset lands at the end of the message");

    Bytes two = msg;
    two.insert(two.end(), msg.begin(), msg.end());
    off = 0;
    const bool first = tls13_next_handshake(two, &off, &type, &got);
    c.ok(first && off == msg.size(), "two messages back to back are consumed one at a time");
    c.ok(tls13_next_handshake(two, &off, &type, &got) && off == two.size(),
         "the second message is consumed as well");

    Bytes cut = msg;
    cut.pop_back();
    off = 0;
    c.ok(!tls13_next_handshake(cut, &off, &type, &got), "a truncated message is refused");

    // The key schedule is deterministic, so the same inputs must give the same
    // secret and a different label must not.
    const Bytes secret(32, 0x0b);
    const Bytes context{'h', 'e', 'l', 'l', 'o'};
    const Bytes ctx = sha256(context.data(), context.size());
    const Bytes a = tls13_expand_label(secret, "c hs traffic", ctx, 32);
    const Bytes b = tls13_expand_label(secret, "c hs traffic", ctx, 32);
    c.eq_u64(a.size(), 32, "HKDF-Expand-Label produces the requested length");
    c.eq_hex(a, to_hex(b), "the same inputs always produce the same secret");
    const Bytes other = tls13_expand_label(secret, "s hs traffic", ctx, 32);
    c.ok(to_hex(a) != to_hex(other), "a different label produces a different secret");
    c.eq_u64(tls13_expand_label(secret, "key", Bytes{}, 16).size(), 16,
             "a 16 byte record key can be derived");

    // Record protection. The sender and the receiver keep their own sequence
    // numbers, exactly as the two directions of a connection do.
    Tls13Traffic shared;
    shared.key = tls13_expand_label(secret, "key", Bytes{}, 16);
    shared.iv = tls13_expand_label(secret, "iv", Bytes{}, 12);
    shared.ready = true;
    Tls13Traffic tx = shared;
    Tls13Traffic rx = shared;
    Bytes record;
    c.ok(tls13_seal(&tx, TLS13_APPDATA, Bytes{'h', 'i'}, &record), "a record can be sealed");
    c.eq_u64(tx.seq, 1, "sealing advances the sequence number");
    c.eq_u64(record[0], TLS13_APPDATA, "the outer record type is application data");
    c.eq_u64(rd16be(record.data() + 3), record.size() - 5, "the outer length covers the body");
    c.ok(record.size() > 5 + 16, "an AEAD record carries a tag beyond the plaintext");

    u8 inner = 0;
    Bytes plain;
    std::string err;
    c.ok(tls13_open(&rx, record, &inner, &plain, &err), "the record can be opened again");
    c.eq_u64(inner, TLS13_APPDATA, "the inner content type is restored");
    c.eq_hex(plain, "6869", "the plaintext comes back byte for byte");
    c.eq_u64(rx.seq, 1, "a successful record advances the receiver");

    Bytes tampered = record;
    tampered[8] ^= 0x40;
    c.ok(!tls13_open(&rx, tampered, &inner, &plain, &err), "a tampered record is rejected");
    c.ok(!err.empty(), "the rejection carries a reason");
    c.eq_u64(rx.seq, 1, "a rejected record does not advance the receiver");

    Bytes short_record(4, 0);
    c.ok(!tls13_open(&rx, short_record, &inner, &plain, &err), "a runt record is rejected");

    c.ok(tls13_cipher_name(TLS13_AES_128_GCM_SHA256).find("AES_128_GCM") != std::string::npos,
         "AES-128-GCM has a name");
    c.ok(tls13_cipher_name(TLS13_CHACHA20_POLY1305).find("CHACHA20") != std::string::npos,
         "ChaCha20-Poly1305 has a name");
    c.ok(tls13_group_name(TLS13_GROUP_X25519).find("25519") != std::string::npos,
         "the x25519 group has a name");
    c.ok(tls13_group_name(0x11ec) == "X25519MLKEM768",
         "the hybrid post-quantum group (sent first by OpenSSL 3.5 and Chrome) has a name");
    c.ok(!tls13_alert_text(0).empty(), "close_notify has a description");
    c.ok(to_hex(tls13_finished_data(secret, ctx)) != to_hex(tls13_finished_data(other, ctx)),
         "Finished data depends on the traffic secret");
  }

  c.section("TLS 1.3 certificates and handshake");  {
    X509Subject subject;
    subject.common_name = "netcap selftest CA";
    subject.organization = "netcap selftest";
    subject.country = "XX";
    CaBundle ca;
    std::string err;
    const bool made = ca_create(subject, 3650, &ca, &err);
    c.ok(made, "a throw-away CA can be created" + (made ? std::string() : ": " + err));
    if (!made) return;
    c.ok(ca.valid(), "the CA bundle holds both a key and a certificate");
    c.ok(ca.cert.is_ca, "the CA certificate is marked as one");
    c.ok(ca.cert.der.size() > 200, "the CA certificate has DER bytes");

    LeafRequest req;
    req.host = "example.test";
    P256Key key;
    X509Cert leaf;
    const bool issued = leaf_issue(ca, req, &key, &leaf, &err);
    c.ok(issued, "a leaf can be issued for a host" + (issued ? std::string() : ": " + err));
    if (!issued) return;
    c.ok(x509_matches_host(leaf, "example.test"), "the leaf matches the host it was issued for");
    c.ok(!x509_matches_host(leaf, "other.test"), "the leaf does not match another host");
    c.ok(x509_verify_signature(leaf, ca.cert), "the CA signature over the leaf verifies");
    c.eq_str(leaf.issuer_cn, ca.cert.subject_cn, "the leaf repeats the CA subject as its issuer");
    c.ok(!leaf.is_ca, "the leaf is not itself a CA");

#ifdef _WIN32
    // One connection over loopback, with the server side in its own thread: the
    // proxy does exactly this, once per intercepted CONNECT tunnel.
    struct TestServer {
      SOCKET listener = INVALID_SOCKET;
      u16 port = 0;
      X509Cert cert;
      P256Key key;
      std::string request, error;
      Tls13ServerInfo info;
      bool ok = false;
      std::thread worker;

      bool start(const X509Cert& cert_in, const P256Key& key_in) {
        cert = cert_in;
        key = key_in;
        listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return false;
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
        DWORD tv = 5000;
        setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener, (sockaddr*)&addr, sizeof(addr)) != 0) return false;
        if (::listen(listener, 4) != 0) return false;
        int len = sizeof(addr);
        if (getsockname(listener, (sockaddr*)&addr, &len) != 0) return false;
        port = ntohs(addr.sin_port);
        worker = std::thread([this]() {
          SOCKET s = ::accept(listener, nullptr, nullptr);
          if (s == INVALID_SOCKET) return;
          DWORD tv_client = 5000;
          setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_client, sizeof(tv_client));
          const Tls13Io io = tls13_io_from_socket(s);
          Tls13Server server;
          std::string why;
          if (!server.accept(io, cert, key, "fallback.test", &info, &why)) {
            error = why;
            closesocket(s);
            return;
          }
          Bytes got;
          if (!server.read_app(io, &got, &why)) error = why;
          request.assign(got.begin(), got.end());
          server.write_app(io, Bytes{'o', 'k'}, &why);
          // A real page is far larger than one TLS record, and a reader rejects
          // a record whose length field is too big: this proves the split.
          server.write_app(io, Bytes(40000, 'x'), &why);
          server.send_close_notify(io, &why);
          ok = true;
          closesocket(s);
        });
        return true;
      }

      // Wait for the worker before reading ok/error/info/request.  The client
      // finishes its handshake as soon as the server's Finished arrives, which
      // is before the worker has read the request, written its reply and set
      // `ok` -- so asserting without joining is a race, not a crypto check.
      void join() {
        if (worker.joinable()) worker.join();
      }

      ~TestServer() {
        if (listener != INVALID_SOCKET) closesocket(listener);
        if (worker.joinable()) worker.join();
      }
    };

    // Runs one client connection against a listening test server.
    struct TestClient {
      static SOCKET dial(u16 port) {
        SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        if (::connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
          closesocket(s);
          return INVALID_SOCKET;
        }
        DWORD tv = 5000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        return s;
      }
    };

    TestServer server;
    c.ok(server.start(leaf, key), "the test server is listening on loopback");
    Tls13ClientInfo ci;
    std::string cerr;
    bool connected = false;
    {
      SOCKET s = TestClient::dial(server.port);
      if (s == INVALID_SOCKET) {
        c.ok(false, "the test client could connect to the test server");
      } else {
        const Tls13Io io = tls13_io_from_socket(s);
        Tls13Client client;
        connected = client.connect(io, "example.test", "http/1.1", false, &ci, &cerr);
        if (connected) {
          std::string why;
          if (!client.write_app(io, Bytes{'G', 'E', 'T'}, &why)) cerr = why;
          Bytes reply;
          if (client.read_app(io, &reply, &why)) {
            c.eq_str(std::string(reply.begin(), reply.end()), "ok",
                     "the server's application record is readable");
            Bytes big;
            Bytes chunk;
            std::size_t rounds = 0;
            while (big.size() < 40000 && client.read_app(io, &chunk, &why)) {
              big.insert(big.end(), chunk.begin(), chunk.end());
              ++rounds;
            }
            c.eq_u64(big.size(), 40000, "a 40000 byte reply arrives whole (records are split)");
            c.ok(rounds >= 2, "the large reply needed more than one record (got " +
                                  std::to_string(rounds) + ")");
          } else {
            c.ok(false, "the client could read the server's reply: " + why);
          }
          client.send_close_notify(io, &why);
        }
        closesocket(s);
      }
    }
    server.join();
    c.ok(connected, "our own client completes a TLS 1.3 handshake" +
                        (connected ? std::string() : ": " + cerr));
    c.eq_str(ci.host, "example.test", "the client remembers the host it asked for");
    c.ok(ci.certificate_seen, "the client saw a certificate");
    c.ok(ci.certificate_signature_verified, "the CertificateVerify signature checks out");
    c.ok(ci.certificate_host_matched, "the certificate matches the requested host");
    c.ok(ci.certificate_dates_ok, "the certificate is inside its validity window");
    c.ok(ci.server_finished_ok, "the server Finished verifies");
    c.ok(ci.warning.empty(), "a certificate we issued ourselves produces no warning");
    c.eq_u64(ci.cipher_suite, TLS13_CHACHA20_POLY1305,
             "the server picks ChaCha20-Poly1305 when we offer it (got " +
                 tls13_cipher_name(ci.cipher_suite) + ")");
    c.eq_str(ci.alpn, "http/1.1", "ALPN agreed on HTTP/1.1");
    c.eq_str(server.info.sni, "example.test", "the server side saw the SNI");
    c.eq_str(server.info.alpn, "http/1.1", "the server side agreed on the same ALPN");
    c.ok(server.info.client_finished_ok, "the server verified the client's Finished");
    c.eq_str(server.request, "GET", "the server decrypted the bytes the client sent");
    c.ok(server.ok, "the server side finished without an error" +
                        (server.error.empty() ? std::string() : ": " + server.error));

    // A certificate for a different host must not be accepted silently: this is
    // the check that keeps the proxy from being a man in the middle everywhere.
    TestServer strict;
    c.ok(strict.start(leaf, key), "a second test server is listening");
    Tls13ClientInfo bad;
    std::string berr;
    bool refused = false;
    {
      SOCKET s = TestClient::dial(strict.port);
      if (s == INVALID_SOCKET) {
        c.ok(false, "the test client could connect to the second server");
      } else {
        const Tls13Io io = tls13_io_from_socket(s);
        Tls13Client client;
        refused = !client.connect(io, "wrong.test", "http/1.1", false, &bad, &berr);
        closesocket(s);
      }
    }
    strict.join();
    c.ok(refused, "a certificate issued for another host is refused");
    c.ok(!bad.certificate_host_matched, "the client records that the host name did not match");
    c.ok(!berr.empty(), "the refusal says why");
#endif
  }
}

// Brotli (RFC 7932): the hand-built streams inside brotli_selfcheck() plus real
// streams produced by the reference encoder.  The real streams cover the fast
// path of quality 0/1 (several meta-blocks, the trivial compressed header), the
// context-modelling path of quality 5/11, and the static dictionary.
void test_brotli(Ctx& c) {
  c.section("brotli");
  {
    std::string report;
    const bool ok = brotli_selfcheck(&report);
    c.ok(ok, "brotli_selfcheck passes" + (report.empty() ? std::string() : " (" + report + ")"));
  }

  // "hello hello hello world", compressed at quality 5 (15 bytes) and 11 (23).
  const u8 kHelloQ5[] = {0x1b, 0x16, 0x00, 0x00, 0x24, 0x40, 0x6a, 0x90, 0x64, 0xf2, 0xa8,
                         0x3c, 0x4f, 0x47, 0x01};
  const u8 kHelloQ11[] = {0x1b, 0x16, 0x00, 0xf8, 0x8d, 0x94, 0x6e, 0xde, 0x44, 0x55, 0x86,
                          0x96, 0x6c, 0x20, 0x6f, 0x35, 0x48, 0x3c, 0x75, 0x40, 0x09, 0x89, 0x23};
  for (const auto& sample : {std::make_pair(kHelloQ5, sizeof(kHelloQ5)),
                             std::make_pair(kHelloQ11, sizeof(kHelloQ11))}) {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(sample.first, sample.second, &out, &why);
    c.ok(ok && out == "hello hello hello world",
         std::string("a real ") + std::to_string(sample.second) +
             " byte stream decodes to \"hello hello hello world\" (" + why + ", got " +
             std::to_string(out.size()) + " bytes)");
  }

  // 200000 zero bytes at quality 0 (144 bytes) and quality 1 (47 bytes): the
  // quality 0/1 encoder writes several meta-blocks, so the header after a
  // non-last meta-block is exercised here.
  const u8 kZerosQ0[] = {
      0xab, 0xff, 0xbf, 0x00, 0x00, 0xa8, 0xaa, 0xaa, 0xaa, 0xfe, 0x31, 0x72, 0x5d, 0xb7, 0xf5,
      0xff, 0xae, 0xfa, 0xf7, 0xdc, 0x5b, 0xdd, 0x33, 0xaa, 0xcb, 0xdb, 0x18, 0xee, 0x8a, 0x17,
      0x0b, 0x0b, 0x0b, 0x1b, 0x1b, 0xab, 0x7a, 0x99, 0x51, 0x1d, 0x7c, 0xf8, 0xf0, 0x63, 0x30,
      0x18, 0x8c, 0xe3, 0x4c, 0x56, 0xd5, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x83, 0x39, 0xd4, 0x19,
      0x91, 0x8a, 0xd2, 0x28, 0x1c, 0x16, 0xda, 0x49, 0xf6, 0x9e, 0xc0, 0x6d, 0x7e, 0xbf, 0xbd,
      0x0b, 0x70, 0xfa, 0x69, 0x0c, 0x00, 0x80, 0xaa, 0xaa, 0xaa, 0xea, 0x1f, 0x23, 0xd7, 0x75,
      0x5b, 0xa7, 0x6e, 0xde, 0xff, 0x37, 0x54, 0xc7, 0x62, 0x98, 0x8f, 0x61, 0x18, 0x86, 0x61,
      0x38, 0x96, 0x6a, 0x18, 0x86, 0x61, 0x18, 0x86, 0x39, 0xb6, 0x5f, 0x35, 0x0c, 0xc3, 0x30,
      0x0c, 0xc3, 0x06, 0xe7, 0x2d, 0x44, 0xfa, 0x00, 0xb1, 0x71, 0x00, 0x40, 0x6e, 0xef, 0x02,
      0x00, 0x36, 0x0e, 0x00, 0xc8, 0x3d, 0x01, 0x00, 0x18};
  const u8 kZerosQ1[] = {0xab, 0xff, 0xff, 0x00, 0x00, 0x02, 0x80, 0x0d, 0xe0, 0xc0, 0x35, 0x9c,
                         0xd4, 0x66, 0x03, 0xb8, 0x00, 0x87, 0xe5, 0xdb, 0xfb, 0x00, 0xfa, 0x69,
                         0x08, 0x00, 0x20, 0x00, 0xd8, 0x00, 0x0e, 0x5c, 0xc3, 0x49, 0x6d, 0x36,
                         0x80, 0x4b, 0x60, 0xe1, 0x3d, 0x00, 0xf0, 0x3d, 0x41, 0x80, 0x01};
  for (const auto& sample : {std::make_pair(kZerosQ0, sizeof(kZerosQ0)),
                             std::make_pair(kZerosQ1, sizeof(kZerosQ1))}) {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(sample.first, sample.second, &out, &why);
    c.ok(ok && out.size() == 200000 && out.find_first_not_of('\0') == std::string::npos,
         std::string("a real ") + std::to_string(sample.second) +
             " byte stream decodes to 200000 zero bytes (" + why + ", got " +
             std::to_string(out.size()) + " bytes)");
  }

  // A 14570 byte document, compressed at quality 0 (153 bytes), 1 (105) and 5
  // (68).  Quality 0 and 1 exercise the fast path, quality 5 the full one.
  std::string html = "<!doctype html><html><head><title>x</title></head><body>";
  for (int i = 0; i < 500; ++i) html += "<div class='ad'>buy now</div>";
  html += "</body></html>";
  const u8 kHtmlQ0[] = {
      0x8b, 0x74, 0x1c, 0x00, 0x80, 0xaa, 0xaa, 0xaa, 0xea, 0xff, 0x74, 0x95, 0x3a, 0xc9, 0x51,
      0x0f, 0x17, 0x51, 0x39, 0xdd, 0x45, 0x95, 0x1d, 0xc0, 0x05, 0x40, 0x42, 0x35, 0x01, 0xc4,
      0x55, 0xb4, 0xf4, 0xff, 0xae, 0xfa, 0xf7, 0xdc, 0x5b, 0xdd, 0x33, 0xaa, 0xcb, 0xdb, 0x18,
      0xee, 0x8a, 0x17, 0x0b, 0x0b, 0x0b, 0x1b, 0x1b, 0xab, 0x7a, 0x99, 0x51, 0x1d, 0x7c, 0xf8,
      0xf0, 0x63, 0x30, 0x18, 0x8c, 0xe3, 0x4c, 0x56, 0xd5, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x83,
      0x39, 0xd4, 0x19, 0x91, 0x8a, 0xd2, 0x28, 0x1c, 0x16, 0xda, 0x49, 0xf6, 0x9e, 0xe0, 0x53,
      0xf9, 0x0f, 0x7b, 0xfe, 0xde, 0xbf, 0x0f, 0x7d, 0x7f, 0x7f, 0xa1, 0x72, 0x94, 0x3e, 0xf9,
      0x18, 0x54, 0x7e, 0xfe, 0x8b, 0x8f, 0xfe, 0x2f, 0xed, 0x04, 0x43, 0xda, 0x2d, 0xfc, 0xf6,
      0xb1, 0xf1, 0x54, 0xe0, 0x45, 0x33, 0x2c, 0xb3, 0xb3, 0x81, 0x75, 0x9c, 0x47, 0x6b, 0x5f,
      0x69, 0xf0, 0xf2, 0xf0, 0x7b, 0x10, 0x0c, 0x80, 0xbb, 0xdf, 0xc6, 0xc6, 0x53, 0x69, 0xdf,
      0xdf, 0x5f, 0xe8};
  const u8 kHtmlQ1[] = {
      0x8b, 0x74, 0x1c, 0x00, 0x80, 0xaa, 0xaa, 0xaa, 0xea, 0xff, 0x74, 0x55, 0x3b, 0xe9, 0x51,
      0x0e, 0x17, 0x36, 0x39, 0xdd, 0x55, 0x55, 0x14, 0x40, 0x15, 0x40, 0xd4, 0xc4, 0x00, 0x54,
      0x6c, 0x11, 0xa7, 0xdc, 0xfe, 0x83, 0x4b, 0x18, 0x06, 0x86, 0x61, 0x80, 0x01, 0xda, 0x61,
      0x07, 0xac, 0xb1, 0x83, 0x88, 0x43, 0xac, 0x79, 0xdc, 0x3d, 0x0d, 0x5f, 0xca, 0xb0, 0x0b,
      0xbd, 0x08, 0xc3, 0xa7, 0x6b, 0xe7, 0x1f, 0x14, 0x56, 0xa0, 0x31, 0x4d, 0x5f, 0x4d, 0x82,
      0x21, 0xf3, 0x4d, 0x4d, 0xcb, 0xde, 0x67, 0x2e, 0x92, 0xb9, 0x3e, 0x91, 0x2e, 0xfb, 0x40,
      0x32, 0xdf, 0xc3, 0x07, 0xc1, 0x00, 0xe0, 0xa9, 0x9a, 0x04, 0x83, 0x86, 0x2f, 0xe5, 0x01};
  const u8 kHtmlQ5[] = {
      0x1b, 0xe9, 0x38, 0x00, 0xc4, 0xce, 0x96, 0xaa, 0x26, 0x0a, 0xe5, 0x76, 0xa9, 0x33, 0x2a,
      0xc9, 0xfc, 0xbb, 0xc1, 0x09, 0x40, 0x25, 0x18, 0x49, 0x54, 0xa0, 0xba, 0xcb, 0xe0, 0x31,
      0x3c, 0xf5, 0x2b, 0x39, 0xbe, 0x91, 0x8c, 0x20, 0x97, 0x27, 0xa3, 0xf5, 0x9e, 0xc2, 0x1a,
      0xdd, 0x43, 0x90, 0xe0, 0x46, 0x3d, 0x95, 0xb1, 0x5f, 0x7a, 0x0e, 0xa3, 0xad, 0xdf, 0x03,
      0x03, 0x10, 0xa0, 0xe1, 0x8a, 0x30, 0xb0, 0x11};
  for (const auto& sample :
       {std::make_pair(kHtmlQ0, sizeof(kHtmlQ0)), std::make_pair(kHtmlQ1, sizeof(kHtmlQ1)),
        std::make_pair(kHtmlQ5, sizeof(kHtmlQ5))}) {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(sample.first, sample.second, &out, &why);
    c.ok(ok && out == html,
         std::string("a real ") + std::to_string(sample.second) +
             " byte stream decodes to the 14570 byte document (" + why + ", got " +
             std::to_string(out.size()) + " bytes)");
  }

  // The same stream cut in half must be refused with a reason, never decoded
  // into wrong bytes.
  {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(kHtmlQ5, sizeof(kHtmlQ5) / 2, &out, &why);
    c.ok(!ok && !why.empty(), "a truncated real stream is refused with a reason (" + why + ")");
  }

  // The shape real encoders emit and python's brotli.compress never does: an
  // empty metadata meta-block (MNIBBLES == 0, MSKIPBYTES == 0) between two
  // compressed meta-blocks.  Leaving its fill bits unread shifts every following
  // meta-block header, which is what the captured origin bodies hit.
  const u8 kEmptyMetadata[] = {0x50, 0x00, 0x00, 0x00, 0x44, 0x50, 0x2c, 0x12, 0x10, 0x03,
                               0x28, 0x00, 0x00, 0x00, 0x22, 0x28, 0x16, 0x09, 0xc8};
  {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(kEmptyMetadata, sizeof(kEmptyMetadata), &out, &why);
    c.ok(ok && out == "AAAAAAAAAAAA",
         "an empty metadata meta-block between two compressed ones is skipped (" + why +
             ", got " + std::to_string(out.size()) + " bytes)");
  }

  // A metadata meta-block with a payload, which is skipped and never appended.
  const u8 kMetadataPayload[] = {0xac, 0x00, 0x4d, 0x44, 0x28, 0x00, 0x00,
                                 0x00, 0x22, 0x28, 0x16, 0x09, 0xc8};
  {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(kMetadataPayload, sizeof(kMetadataPayload), &out, &why);
    c.ok(ok && out == "AAAAAA",
         "a metadata meta-block payload is skipped (" + why + ", got \"" + out + "\")");
  }

  // A one in the fill bits of that metadata header is invalid.
  const u8 kBadMetadataFill[] = {0x50, 0x00, 0x00, 0x00, 0x44, 0x50, 0x2c, 0x12, 0x10,
                                 0xe3, 0x28, 0x00, 0x00, 0x00, 0x22, 0x28, 0x16, 0x09, 0xc8};
  {
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(kBadMetadataFill, sizeof(kBadMetadataFill), &out, &why);
    c.ok(!ok && !why.empty(), "nonzero metadata fill bits are refused (" + why + ")");
  }
}

int run_selftest(bool verbose, std::string* report) {
  Ctx c;
  c.verbose = verbose;
  c.log = "netcap self-test\n";

  const std::vector<Packet> samples = build_sample_packets();
  c.ok(samples.size() >= 14, "sample traffic generated");

  test_primitives(c);
  test_crypto(c);
test_p256(c);
test_p521(c);
test_x25519(c);
test_x509(c);
  test_flow(c);
  test_http(c);
  test_tls(c);
  test_http2(c);
  test_httpframe(c);
  test_picker(c);
  test_origin(c);
  test_dissector(c, samples);
  test_application_layer(c, samples);
  test_filter(c, samples);
  test_pcap(c, samples);
  test_capture_layer(c);
  test_proc(c);
  test_proxy(c);
  test_split(c, samples);
  test_rules(c);
  test_blocker(c);
  test_hosts(c);
  test_dnssink(c);
  test_wfp(c);
  test_sysproxy(c);
  test_sysenv(c);
  test_pktflow(c);
  test_tunrelay(c);
  test_tunpipe(c);
  test_tun(c);
  test_tls13(c);
  test_tls12(c);
  test_block(c);
  test_analyze(c);
  test_brotli(c);
  test_h3(c);
  test_h3write(c);
  test_quic_rewrite(c);
  test_quickeys(c);

  c.log += "\n";
  c.log += std::to_string(c.checks - c.failures) + "/" + std::to_string(c.checks) +
           " checks passed";
  c.log += c.failures ? ("\n" + std::to_string(c.failures) + " FAILED\n") : " (all good)\n";
  if (report) *report = c.log;
  return c.failures;
}

}  // namespace netcap
