#include "netcap/common.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace netcap {

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

i64 now_unix_us() noexcept {
  using namespace std::chrono;
  return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

i64 now_monotonic_us() noexcept {
  using namespace std::chrono;
  return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

namespace {

std::tm gmtime_utc(i64 ts_sec) {
  std::time_t t = static_cast<std::time_t>(ts_sec);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  return tm;
}

}  // namespace

std::string format_time_us(i64 ts_us) {
  i64 sec = ts_us / 1000000;
  i64 us = ts_us % 1000000;
  if (us < 0) {
    us += 1000000;
    sec -= 1;
  }
  std::tm tm = gmtime_utc(sec);
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06d", tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<int>(us));
  return buf;
}

std::string format_datetime_us(i64 ts_us) {
  i64 sec = ts_us / 1000000;
  std::tm tm = gmtime_utc(sec);
  char buf[48];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

// ---------------------------------------------------------------------------
// Address formatting
// ---------------------------------------------------------------------------

std::string format_mac(const u8* mac6) {
  char buf[24];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac6[0], mac6[1], mac6[2],
                mac6[3], mac6[4], mac6[5]);
  return buf;
}

std::string format_ipv4(u32 a) {
  char buf[20];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", unsigned((a >> 24) & 0xff),
                unsigned((a >> 16) & 0xff), unsigned((a >> 8) & 0xff), unsigned(a & 0xff));
  return buf;
}

std::string format_ipv6(const u8* a) {
  // RFC 5952 5.: IPv4-mapped addresses keep their dotted-quad tail, so
  // ::ffff:192.168.1.1 is preferred over ::ffff:c0a8:101.
  bool v4_tail = true;
  for (int i = 0; i < 10 && v4_tail; ++i) {
    if (a[i] != 0) v4_tail = false;
  }
  if (v4_tail && a[10] == 0xff && a[11] == 0xff) {
    return "::ffff:" + format_ipv4(rd32be(a + 12));
  }

  u16 g[8];
  for (int i = 0; i < 8; ++i) g[i] = rd16be(a + 2 * i);

  // Longest run of >= 2 zero groups wins (first one on a tie, per RFC 5952).
  int best = -1, best_len = 0;
  for (int i = 0; i < 8;) {
    if (g[i] == 0) {
      int j = i;
      while (j < 8 && g[j] == 0) ++j;
      if (j - i > best_len && j - i >= 2) {
        best_len = j - i;
        best = i;
      }
      i = j;
    } else {
      ++i;
    }
  }

  std::string out;
  char buf[8];
  for (int i = 0; i < 8;) {
    if (i == best) {
      out += "::";
      i += best_len;
      continue;
    }
    if (!out.empty() && out.back() != ':') out += ':';
    std::snprintf(buf, sizeof(buf), "%x", g[i]);
    out += buf;
    ++i;
  }
  if (out.empty()) out = "::";
  return out;
}

std::string format_ip(int version, const u8* addr) {
  if (version == 4) return format_ipv4(rd32be(addr));
  if (version == 6) return format_ipv6(addr);
  return "?";
}

// ---------------------------------------------------------------------------
// Address parsing
// ---------------------------------------------------------------------------

bool parse_ipv4(const std::string& s, u32* out_be) {
  u32 part[4];
  int n = 0;
  std::size_t i = 0;
  while (n < 4) {
    if (i >= s.size()) return false;
    u32 v = 0;
    int digits = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
      v = v * 10u + u32(s[i] - '0');
      if (v > 255) return false;
      ++i;
      ++digits;
    }
    if (digits == 0) return false;
    part[n++] = v;
    if (i < s.size()) {
      if (s[i] != '.') return false;
      ++i;
    } else {
      break;
    }
  }
  if (n != 4 || i != s.size()) return false;
  if (out_be) *out_be = (part[0] << 24) | (part[1] << 16) | (part[2] << 8) | part[3];
  return true;
}

namespace {

bool parse_hex_group(const std::string& t, u16* v) {
  if (t.empty() || t.size() > 4) return false;
  u32 x = 0;
  for (char c : t) {
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return false;
    x = x * 16u + u32(d);
  }
  *v = u16(x);
  return true;
}

void split_colon(const std::string& part, std::vector<std::string>& out) {
  out.clear();
  if (part.empty()) return;
  std::size_t start = 0;
  for (;;) {
    std::size_t c = part.find(':', start);
    if (c == std::string::npos) {
      out.push_back(part.substr(start));
      break;
    }
    out.push_back(part.substr(start, c - start));
    start = c + 1;
  }
}

bool convert_groups(const std::vector<std::string>& toks, std::vector<u16>& out) {
  for (std::size_t i = 0; i < toks.size(); ++i) {
    if (toks[i].empty()) return false;
    if (toks[i].find('.') != std::string::npos) {
      // Embedded IPv4 must be the final token and consumes two groups.
      if (i + 1 != toks.size()) return false;
      u32 a = 0;
      if (!parse_ipv4(toks[i], &a)) return false;
      out.push_back(u16(a >> 16));
      out.push_back(u16(a & 0xffffu));
    } else {
      u16 x = 0;
      if (!parse_hex_group(toks[i], &x)) return false;
      out.push_back(x);
    }
  }
  return true;
}

}  // namespace

bool parse_ipv6(const std::string& in, u8 out16[16]) {
  std::string s = in;
  std::size_t pct = s.find('%');
  if (pct != std::string::npos) s = s.substr(0, pct);
  if (s.empty()) return false;

  std::size_t dc = s.find("::");
  const bool has_dc = dc != std::string::npos;
  std::string left = has_dc ? s.substr(0, dc) : s;
  std::string right = has_dc ? s.substr(dc + 2) : std::string();
  if (has_dc && right.find("::") != std::string::npos) return false;

  std::vector<std::string> lt, rt;
  split_colon(left, lt);
  split_colon(right, rt);

  std::vector<u16> lg, rg;
  if (!convert_groups(lt, lg)) return false;
  if (!convert_groups(rt, rg)) return false;

  const std::size_t total = lg.size() + rg.size();
  if (has_dc) {
    if (total > 7) return false;
  } else if (total != 8) {
    return false;
  }

  std::vector<u16> full;
  full.reserve(8);
  full.insert(full.end(), lg.begin(), lg.end());
  if (has_dc) full.insert(full.end(), 8 - total, u16(0));
  full.insert(full.end(), rg.begin(), rg.end());
  if (full.size() != 8) return false;

  for (int i = 0; i < 8; ++i) wr16be(out16 + 2 * i, full[static_cast<std::size_t>(i)]);
  return true;
}

bool parse_ip(const std::string& s, int* version, u8 out16[16]) {
  if (s.find(':') != std::string::npos) {
    if (!parse_ipv6(s, out16)) return false;
    if (version) *version = 6;
    return true;
  }
  u32 a = 0;
  if (!parse_ipv4(s, &a)) return false;
  if (out16) {
    std::memset(out16, 0, 16);
    wr32be(out16, a);
  }
  if (version) *version = 4;
  return true;
}

bool parse_cidr(const std::string& s, int* version, u8 out16[16], int* bits) {
  std::string addr = s;
  int mask = -1;
  std::size_t slash = s.find('/');
  if (slash != std::string::npos) {
    addr = s.substr(0, slash);
    std::string m = s.substr(slash + 1);
    if (m.empty() || m.size() > 3) return false;
    int v = 0;
    for (char c : m) {
      if (c < '0' || c > '9') return false;
      v = v * 10 + (c - '0');
    }
    mask = v;
  }
  int ver = 0;
  u8 buf[16] = {0};
  if (!parse_ip(addr, &ver, buf)) return false;
  if (mask < 0) mask = (ver == 4) ? 32 : 128;
  if (mask > ((ver == 4) ? 32 : 128)) return false;
  if (ver == 4) {
    // Zero host bits so the prefix behaves as a real network.
    u32 a = rd32be(buf);
    u32 m = (mask == 0) ? 0u : (0xffffffffu << (32 - mask));
    wr32be(buf, a & m);
  } else if (mask < 128) {
    int full = mask / 8, rem = mask % 8;
    if (rem) {
      buf[full] = u8(buf[full] & (0xffu << (8 - rem)));
      ++full;
    }
    for (int i = full; i < 16; ++i) buf[i] = 0;
  }
  if (out16) std::memcpy(out16, buf, 16);
  if (version) *version = ver;
  if (bits) *bits = mask;
  return true;
}

bool cidr_match(int version, const u8* addr, const u8* prefix, int bits) {
  const int width = (version == 4) ? 32 : 128;
  if (bits > width) return false;
  const int bytes = bits / 8;
  const int rem = bits % 8;
  if (bytes > 16) return false;
  if (std::memcmp(addr, prefix, static_cast<std::size_t>(bytes)) != 0) return false;
  if (rem) {
    const u8 mask = u8(0xffu << (8 - rem));
    if ((addr[bytes] & mask) != (prefix[bytes] & mask)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

std::string to_lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
  }
  return s;
}

bool iequals(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x = char(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = char(y - 'A' + 'a');
    if (x != y) return false;
  }
  return true;
}

bool icontains_lower(const char* hay, const char* lower_needle) {
  if (!hay || !lower_needle || !*lower_needle) return false;
  const std::size_t n = std::strlen(lower_needle);
  for (const char* p = hay; *p; ++p) {
    std::size_t i = 0;
    while (i < n && p[i]) {
      char c = p[i];
      if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
      if (c != lower_needle[i]) break;
      ++i;
    }
    if (i == n) return true;
  }
  return false;
}

bool icontains(const std::string& hay, const std::string& needle) {
  if (needle.empty()) return false;
  const std::string n = to_lower(needle);
  return icontains_lower(hay.c_str(), n.c_str());
}

std::string hexdump(const u8* data, std::size_t len, std::size_t max_bytes,
                    const std::string& indent) {
  std::string out;
  if (!data) return out;
  const std::size_t n = (max_bytes == 0 || max_bytes > len) ? len : max_bytes;
  char buf[16];
  for (std::size_t off = 0; off < n; off += 16) {
    out += indent;
    std::snprintf(buf, sizeof(buf), "%04zx  ", off);
    out += buf;
    std::string ascii;
    for (std::size_t i = 0; i < 16; ++i) {
      if (off + i < n) {
        const unsigned b = data[off + i];
        std::snprintf(buf, sizeof(buf), "%02x ", b);
        out += buf;
        ascii += (b >= 0x20 && b < 0x7f) ? char(b) : '.';
      } else {
        out += "   ";
      }
      if (i == 7) out += ' ';
    }
    out += " |";
    out += ascii;
    out += "|\n";
  }
  if (n < len) {
    std::snprintf(buf, sizeof(buf), "%zu", len - n);
    out += indent;
    out += "... (";
    out += buf;
    out += " more bytes)\n";
  }
  return out;
}

// ---------------------------------------------------------------------------
// Protocol name tables
// ---------------------------------------------------------------------------

const char* ip_proto_name(u8 proto) {
  switch (proto) {
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 4: return "IPIP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6";
    case 47: return "GRE";
    case 50: return "ESP";
    case 51: return "AH";
    case 58: return "ICMPv6";
    case 89: return "OSPF";
    case 103: return "PIM";
    case 112: return "VRRP";
    case 132: return "SCTP";
    default: return "IP";
  }
}

const char* service_name(u16 port, u8 ip_proto) {
  if (ip_proto == 6) {
    switch (port) {
      case 20: return "ftp-data";
      case 21: return "ftp";
      case 22: return "ssh";
      case 23: return "telnet";
      case 25: return "smtp";
      case 53: return "domain";
      case 80: return "http";
      case 110: return "pop3";
      case 143: return "imap";
      case 179: return "bgp";
      case 443: return "https";
      case 445: return "microsoft-ds";
      case 465: return "smtps";
      case 587: return "submission";
      case 993: return "imaps";
      case 995: return "pop3s";
      case 1433: return "ms-sql-s";
      case 1521: return "oracle";
      case 3306: return "mysql";
      case 3389: return "ms-wbt-server";
      case 5432: return "postgresql";
      case 6379: return "redis";
      case 8000: return "http-alt";
      case 8080: return "http-alt";
      case 8443: return "https-alt";
      case 27017: return "mongod";
      default: return "";
    }
  }
  if (ip_proto == 17) {
    switch (port) {
      case 53: return "domain";
      case 67: return "bootps";
      case 68: return "bootpc";
      case 69: return "tftp";
      case 123: return "ntp";
      case 137: return "netbios-ns";
      case 161: return "snmp";
      case 162: return "snmptrap";
      case 443: return "https";
      case 500: return "isakmp";
      case 514: return "syslog";
      case 1900: return "ssdp";
      case 4500: return "ipsec-nat-t";
      case 5353: return "mdns";
      case 5355: return "llmnr";
      default: return "";
    }
  }
  return "";
}

std::string tcp_flags_str(u8 f) {
  std::string s;
  s += (f & 0x01) ? 'F' : '.';
  s += (f & 0x02) ? 'S' : '.';
  s += (f & 0x04) ? 'R' : '.';
  s += (f & 0x08) ? 'P' : '.';
  s += (f & 0x10) ? 'A' : '.';
  s += (f & 0x20) ? 'U' : '.';
  s += (f & 0x40) ? 'E' : '.';
  s += (f & 0x80) ? 'C' : '.';
  return s;
}

const char* icmp_type_name(u8 t) {
  switch (t) {
    case 0: return "echo reply";
    case 3: return "dest unreachable";
    case 4: return "source quench";
    case 5: return "redirect";
    case 8: return "echo request";
    case 9: return "router advertisement";
    case 10: return "router solicitation";
    case 11: return "time exceeded";
    case 12: return "parameter problem";
    case 13: return "timestamp request";
    case 14: return "timestamp reply";
    case 17: return "address mask request";
    case 18: return "address mask reply";
    default: return "icmp";
  }
}

const char* icmpv6_type_name(u8 t) {
  switch (t) {
    case 1: return "dest unreachable";
    case 2: return "packet too big";
    case 3: return "time exceeded";
    case 4: return "parameter problem";
    case 128: return "echo request";
    case 129: return "echo reply";
    case 133: return "router solicitation";
    case 134: return "router advertisement";
    case 135: return "neighbor solicitation";
    case 136: return "neighbor advertisement";
    case 137: return "redirect";
    default: return "icmp6";
  }
}

const char* dns_type_name(u16 t) {
  switch (t) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 43: return "DS";
    case 46: return "RRSIG";
    case 47: return "NSEC";
    case 48: return "DNSKEY";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: return "TYPE";
  }
}

const char* tls_version_name(u16 v) {
  switch (v) {
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default: return "TLS";
  }
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

u16 checksum_fold(u32 sum) noexcept {
  while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
  return u16(~sum & 0xffffu);
}

u16 internet_checksum(const u8* data, std::size_t len, u32 init) {
  u32 sum = init;
  std::size_t i = 0;
  for (; i + 1 < len; i += 2) sum += (u32(data[i]) << 8) | u32(data[i + 1]);
  if (i < len) sum += (u32(data[i]) << 8);  // trailing byte is padded with zero
  return checksum_fold(sum);
}

}  // namespace netcap
