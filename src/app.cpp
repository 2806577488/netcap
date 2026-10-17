#include "netcap/app.hpp"

#include <cstring>

namespace netcap {

namespace {

std::size_t bounded_copy(char* dst, std::size_t dstsz, const char* src, std::size_t n) {
  if (dstsz == 0) return 0;
  const std::size_t m = (n < dstsz - 1) ? n : dstsz - 1;
  if (m) std::memcpy(dst, src, m);
  dst[m] = '\0';
  return m;
}

/// Trims leading/trailing spaces, tabs and CR from an in-place string.
void trim_inplace(char* s) {
  std::size_t n = std::strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) s[--n] = '\0';
  std::size_t lead = 0;
  while (s[lead] == ' ' || s[lead] == '\t') ++lead;
  if (lead) std::memmove(s, s + lead, n - lead + 1);
}

void lowercase_inplace(char* s) {
  for (; *s; ++s) {
    if (*s >= 'A' && *s <= 'Z') *s = char(*s - 'A' + 'a');
  }
}

/// Finds the end of the line starting at `from`; `*next` receives the start of
/// the following line. Returns the index of the line terminator (or `len`).
std::size_t find_line_end(const u8* p, std::size_t len, std::size_t from, std::size_t* next) {
  std::size_t i = from;
  while (i < len && p[i] != '\n') ++i;
  std::size_t end = i;
  if (end > from && p[end - 1] == '\r') --end;
  *next = (i < len) ? i + 1 : len;
  return end;
}

bool is_token_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
         c == '_';
}

bool is_http_method(const char* s, std::size_t n) {
  static const char* kMethods[] = {"GET",     "POST",  "HEAD",    "PUT",    "DELETE",
                                   "OPTIONS", "TRACE", "CONNECT", "PATCH",  "PROPFIND",
                                   "PRI",     "COPY",  "MOVE",    "REPORT", "LOCK"};
  for (const char* m : kMethods) {
    const std::size_t ml = std::strlen(m);
    if (ml == n && std::memcmp(s, m, n) == 0) return true;
  }
  return false;
}

}  // namespace

std::size_t http_body_offset(const HttpInfo& h) { return h.body_offset; }

// ---------------------------------------------------------------------------
// HTTP/1.x
// ---------------------------------------------------------------------------

bool parse_http(const u8* p, std::size_t len, HttpInfo& out) {
  std::size_t i = 0;
  while (i < len && (p[i] == '\r' || p[i] == '\n')) ++i;  // tolerate leading CRLF
  if (len - i < 5) return false;

  // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  if (len - i >= 24 && std::memcmp(p + i, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) {
    out.http2_preface = true;
    out.is_request = true;
    std::memcpy(out.method, "PRI", 4);
    std::memcpy(out.uri, "*", 2);
    out.version_major = 2;
    out.version_minor = 0;
    out.body_offset = i + 24;
    return true;
  }

  std::size_t next = i;
  const std::size_t line_end = find_line_end(p, len, i, &next);
  const std::size_t line_len = line_end - i;
  if (line_len < 5) return false;

  const char* line = reinterpret_cast<const char*>(p + i);
  if (std::memcmp(line, "HTTP/", 5) == 0) {
    // Response status line: HTTP/1.1 200 OK
    if (line_len < 12 && line_len < 9) return false;
    out.is_response = true;
    if (line[5] >= '0' && line[5] <= '9') out.version_major = line[5] - '0';
    if (line[7] >= '0' && line[7] <= '9') out.version_minor = line[7] - '0';
    std::size_t k = 8;
    while (k < line_len && line[k] == ' ') ++k;
    int status = 0;
    std::size_t digits = 0;
    while (k < line_len && line[k] >= '0' && line[k] <= '9' && digits < 4) {
      status = status * 10 + (line[k] - '0');
      ++k;
      ++digits;
    }
    if (digits != 3) return false;
    out.status = status;
    while (k < line_len && line[k] == ' ') ++k;
    bounded_copy(out.reason, sizeof(out.reason), line + k, line_len - k);
    trim_inplace(out.reason);
  } else {
    // Request line: METHOD SP request-target SP HTTP/x.y
    std::size_t sp1 = 0;
    while (sp1 < line_len && line[sp1] != ' ') ++sp1;
    if (sp1 == 0 || sp1 >= line_len || sp1 > 15) return false;
    for (std::size_t k = 0; k < sp1; ++k) {
      if (!is_token_char(line[k])) return false;
    }
    if (!is_http_method(line, sp1)) return false;
    bounded_copy(out.method, sizeof(out.method), line, sp1);
    std::size_t sp2 = sp1 + 1;
    while (sp2 < line_len && line[sp2] != ' ') ++sp2;
    if (sp2 <= sp1 + 1) return false;
    bounded_copy(out.uri, sizeof(out.uri), line + sp1 + 1, sp2 - sp1 - 1);
    if (sp2 < line_len) {
      if (line_len - sp2 >= 8 && std::memcmp(line + sp2 + 1, "HTTP/", 5) == 0) {
        if (line[sp2 + 6] >= '0' && line[sp2 + 6] <= '9') out.version_major = line[sp2 + 6] - '0';
        if (line[sp2 + 8] >= '0' && line[sp2 + 8] <= '9') out.version_minor = line[sp2 + 8] - '0';
      }
    }
    out.is_request = true;
  }

  // Header block.
  i = next;
  char name[64];
  char value[512];
  int guard = 0;
  while (i < len && ++guard < 128) {
    std::size_t n2 = i;
    const std::size_t le = find_line_end(p, len, i, &n2);
    if (le == i) {
      i = n2;
      break;
    }
    const char* hl = reinterpret_cast<const char*>(p + i);
    const std::size_t hl_len = le - i;
    std::size_t colon = 0;
    while (colon < hl_len && hl[colon] != ':') ++colon;
    if (colon == 0 || colon >= hl_len) {
      i = n2;
      continue;
    }
    bounded_copy(name, sizeof(name), hl, colon);
    std::size_t vstart = colon + 1;
    while (vstart < hl_len && (hl[vstart] == ' ' || hl[vstart] == '\t')) ++vstart;
    bounded_copy(value, sizeof(value), hl + vstart, hl_len - vstart);
    trim_inplace(value);
    ++out.header_count;

    if (iequals(name, "host")) {
      bounded_copy(out.host, sizeof(out.host), value, std::strlen(value));
      lowercase_inplace(out.host);
    } else if (iequals(name, "user-agent")) {
      bounded_copy(out.user_agent, sizeof(out.user_agent), value, std::strlen(value));
    } else if (iequals(name, "content-type")) {
      bounded_copy(out.content_type, sizeof(out.content_type), value, std::strlen(value));
    } else if (iequals(name, "server")) {
      bounded_copy(out.server, sizeof(out.server), value, std::strlen(value));
    } else if (iequals(name, "upgrade")) {
      bounded_copy(out.upgrade, sizeof(out.upgrade), value, std::strlen(value));
    } else if (iequals(name, "accept-encoding")) {
      bounded_copy(out.accept_encoding, sizeof(out.accept_encoding), value, std::strlen(value));
    } else if (iequals(name, "content-length")) {
      u64 v = 0;
      bool ok = *value != '\0';
      for (const char* c = value; *c; ++c) {
        if (*c < '0' || *c > '9') {
          ok = false;
          break;
        }
        v = v * 10 + u64(*c - '0');
      }
      if (ok) {
        out.has_content_length = true;
        out.content_length = v;
      }
    } else if (iequals(name, "transfer-encoding")) {
      if (icontains_lower(value, "chunked")) out.chunked = true;
    } else if (iequals(name, "connection")) {
      if (icontains_lower(value, "close")) out.connection_close = true;
    }
    i = n2;
  }
  out.body_offset = i;
  return true;
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

bool parse_tls(const u8* p, std::size_t len, TlsInfo& out) {
  if (len < 5) return false;
  const u8 ct = p[0];
  if (ct < 20 || ct > 24) return false;
  if (p[1] != 0x03) return false;  // TLS record major version
  out.is_record = true;
  out.record_type = ct;
  out.record_version = rd16be(p + 1);
  out.record_length = rd16be(p + 3);

  std::size_t limit = len;
  if (out.record_length != 0 && std::size_t(out.record_length) + 5 < limit) {
    limit = std::size_t(out.record_length) + 5;
  }
  if (ct != 22) return true;  // not a handshake record

  if (limit < 9 || p[5] != 1) return true;  // not a ClientHello
  out.is_client_hello = true;
  const std::size_t hs_len = rd24be(p + 6);
  std::size_t pos = 9;
  std::size_t hs_end = pos + hs_len;
  if (hs_end > limit) hs_end = limit;

  if (pos + 2 > hs_end) return true;
  out.client_version = rd16be(p + pos);
  pos += 2 + 32;  // legacy_version + random

  if (pos >= hs_end) return true;
  pos += 1 + std::size_t(p[pos]);  // legacy_session_id

  if (pos + 2 > hs_end) return true;
  const std::size_t cs = rd16be(p + pos);
  pos += 2;
  out.cipher_count = u16(cs / 2);
  pos += cs;

  if (pos >= hs_end) return true;
  const std::size_t comp = p[pos];
  pos += 1;
  out.compression_count = u8(comp);
  pos += comp;

  if (pos + 2 > hs_end) return true;
  const std::size_t ext_total = rd16be(p + pos);
  pos += 2;
  out.has_extensions = true;
  std::size_t ext_end = pos + ext_total;
  if (ext_end > hs_end) ext_end = hs_end;

  while (pos + 4 <= ext_end) {
    const u16 et = rd16be(p + pos);
    const u16 el = rd16be(p + pos + 2);
    const std::size_t edata = pos + 4;
    if (edata + el > ext_end) break;

    if (et == 0x0000 && el >= 2) {  // server_name
      std::size_t q = edata;
      const std::size_t list_len = rd16be(p + q);
      q += 2;
      std::size_t list_end = q + list_len;
      if (list_end > edata + el) list_end = edata + el;
      while (q + 3 <= list_end) {
        const u8 ntype = p[q];
        const u16 nlen = rd16be(p + q + 1);
        q += 3;
        if (q + nlen > list_end) break;
        if (ntype == 0 && out.sni[0] == '\0') {
          bounded_copy(out.sni, sizeof(out.sni), reinterpret_cast<const char*>(p + q), nlen);
          lowercase_inplace(out.sni);
        }
        q += nlen;
      }
    } else if (et == 0x0010 && el >= 2) {  // ALPN
      std::size_t q = edata;
      const std::size_t list_len = rd16be(p + q);
      q += 2;
      std::size_t list_end = q + list_len;
      if (list_end > edata + el) list_end = edata + el;
      std::size_t used = 0;
      while (q < list_end) {
        const u8 pl = p[q];
        ++q;
        if (q + pl > list_end) break;
        if (used + pl + 2 < sizeof(out.alpn)) {
          if (used) {
            out.alpn[used++] = ',';
          }
          std::memcpy(out.alpn + used, p + q, pl);
          used += pl;
          out.alpn[used] = '\0';
        }
        q += pl;
      }
    } else if (et == 0x002b && el >= 3) {  // supported_versions
      const u8 vlen = p[edata];
      if (std::size_t(vlen) + 1 <= el && vlen >= 2) {
        out.has_supported_versions = true;
        // Highest offered version is the first entry in practice.
        out.supported_version = rd16be(p + edata + 1);
      }
    }
    pos = edata + el;
  }
  return true;
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

namespace {

bool dns_read_name(const u8* p, std::size_t len, std::size_t off, char* out, std::size_t outsz,
                   std::size_t* after) {
  std::size_t pos = off;
  std::size_t used = 0;
  int jumps = 0;
  bool jumped = false;
  if (outsz) out[0] = '\0';
  for (;;) {
    if (pos >= len) return false;
    const u8 lab = p[pos];
    if (lab == 0) {
      ++pos;
      break;
    }
    if ((lab & 0xc0) == 0xc0) {
      if (pos + 1 >= len) return false;
      const std::size_t ptr = (std::size_t(lab & 0x3f) << 8) | p[pos + 1];
      if (!jumped) *after = pos + 2;
      jumped = true;
      if (++jumps > 32 || ptr >= len) return false;
      pos = ptr;
      continue;
    }
    if ((lab & 0xc0) != 0) return false;  // reserved label type
    if (pos + 1 + lab > len) return false;
    if (used + lab + 2 >= outsz) return false;  // name too long for our buffer
    if (used) out[used++] = '.';
    std::memcpy(out + used, p + pos + 1, lab);
    used += lab;
    out[used] = '\0';
    pos += 1 + lab;
  }
  if (!jumped) *after = pos;
  return true;
}

}  // namespace

bool parse_dns(const u8* p, std::size_t len, DnsInfo& out) {
  // DNS over TCP is length-prefixed; detect and skip the prefix.
  if (len >= 14) {
    const u16 claimed = rd16be(p);
    if (std::size_t(claimed) + 2 == len && claimed >= 12) {
      p += 2;
      len -= 2;
    }
  }
  if (len < 12) return false;
  const u16 flags = rd16be(p + 2);
  out.is_response = (flags & 0x8000) != 0;
  out.opcode = u8((flags >> 11) & 0xf);
  out.rcode = u8(flags & 0xf);
  out.truncated = (flags & 0x0200) != 0;
  out.qdcount = rd16be(p + 4);
  out.ancount = rd16be(p + 6);
  if (out.qdcount == 0) {
    out.valid = true;
    return true;
  }
  std::size_t after = 0;
  if (!dns_read_name(p, len, 12, out.qname, sizeof(out.qname), &after)) return false;
  if (after + 4 > len) {
    out.valid = true;
    return true;
  }
  out.qtype = rd16be(p + after);
  out.qclass = rd16be(p + after + 2);
  lowercase_inplace(out.qname);
  out.valid = true;
  return true;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

const char* app_hostname(const AppInfo& a) {
  if (a.http.host[0]) return a.http.host;
  if (a.tls.sni[0]) return a.tls.sni;
  if (a.dns.qname[0]) return a.dns.qname;
  return "";
}

AppKind classify_app(const PacketInfo& pi, AppInfo& out) {
  out = AppInfo();
  if (!pi.has_ports || pi.payload == nullptr || pi.payload_len == 0) {
    // Still recognise the well-known ports so filters like `tcp port 443` are
    // meaningful on empty segments such as pure ACKs.
    if (pi.is_tcp() && (pi.src_port == 443 || pi.dst_port == 443)) {
      out.kind = AppKind::Tls;
      out.note = "tls port, no payload";
    }
    return out.kind;
  }

  const u8* p = pi.payload;
  const std::size_t n = pi.payload_len;
  const bool tcp = pi.is_tcp();
  const bool udp = pi.is_udp();

  // Signature-first detection, so a service on a non-standard port still works.
  if (tcp) {
    std::size_t i = 0;
    while (i < n && (p[i] == '\r' || p[i] == '\n')) ++i;
    bool httpish = false;
    if (n - i >= 5 && std::memcmp(p + i, "HTTP/", 5) == 0) {
      httpish = true;
    } else {
      std::size_t sp = i;
      while (sp < n && p[sp] != ' ') ++sp;
      if (sp < n && sp > i && sp - i <= 15) httpish = is_http_method(reinterpret_cast<const char*>(p + i), sp - i);
    }
    if (httpish && parse_http(p, n, out.http)) {
      out.kind = AppKind::Http;
      out.detected = true;
      return out.kind;
    }
    if (n >= 5 && p[1] == 0x03 && p[0] >= 20 && p[0] <= 24) {
      if (parse_tls(p, n, out.tls)) {
        out.kind = AppKind::Tls;
        out.detected = true;
        return out.kind;
      }
    }
  }

  if (udp || tcp) {
    const bool dns_port = (pi.src_port == 53 || pi.dst_port == 53);
    const bool mdns_port = (pi.src_port == 5353 || pi.dst_port == 5353);
    if (dns_port || mdns_port) {
      if (parse_dns(p, n, out.dns)) {
        out.kind = mdns_port ? AppKind::Mdns : AppKind::Dns;
        out.detected = true;
        return out.kind;
      }
    }
  }

  if (udp && (pi.src_port == 67 || pi.dst_port == 67 || pi.src_port == 68 || pi.dst_port == 68)) {
    out.kind = AppKind::Dhcp;
    out.detected = true;
    return out.kind;
  }

  if (udp && (pi.src_port == 443 || pi.dst_port == 443) && n >= 5 && (p[0] & 0x80) != 0) {
    out.kind = AppKind::Quic;
    out.detected = true;
    return out.kind;
  }

  if (tcp && (pi.src_port == 22 || pi.dst_port == 22) && n >= 4 && std::memcmp(p, "SSH-", 4) == 0) {
    out.kind = AppKind::Ssh;
    out.detected = true;
    return out.kind;
  }

  // Port-based fallback: name the protocol even when this segment holds no
  // recognisable header (very common with segment-level capture).
  if (tcp) {
    const u16 port = pi.dst_port ? pi.dst_port : pi.src_port;
    switch (port) {
      case 443:
      case 8443:
      case 993:
      case 995:
      case 465:
      case 990:
        out.kind = AppKind::Tls;
        out.note = "tls port, payload not a TLS record in this segment";
        return out.kind;
      case 80:
      case 8080:
      case 8000:
      case 8008:
      case 3128:
      case 8888:
        out.kind = AppKind::Http;
        out.note = "http port, payload not a complete header in this segment";
        return out.kind;
      default:
        break;
    }
  }
  return out.kind;
}

}  // namespace netcap
