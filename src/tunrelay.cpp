// Decision layer for the tunnel relay: bytes in, verdict out. See tunrelay.hpp
// for why this is separate from the socket plumbing.
#include "netcap/tunrelay.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "netcap/quic.hpp"
#include "netcap/tls.hpp"

namespace netcap {
namespace {

std::string lower(std::string s) {
  for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return s;
}

/// Case-insensitive search, used for header names only.
std::size_t find_ci(const std::string& hay, const std::string& needle, std::size_t from = 0) {
  if (needle.empty() || hay.size() < needle.size()) return std::string::npos;
  const std::string h = lower(hay);
  const std::string n = lower(needle);
  return h.find(n, from);
}

std::string trim(const std::string& s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
  return s.substr(b, e - b);
}

/// "example.com:8080" -> "example.com"; "[::1]:80" -> "::1".
std::string strip_port(const std::string& host) {
  if (!host.empty() && host[0] == '[') {
    const std::size_t close = host.find(']');
    return close == std::string::npos ? host : host.substr(1, close - 1);
  }
  const std::size_t colon = host.rfind(':');
  if (colon == std::string::npos) return host;
  // Only strip when what follows the colon is a port number (never part of an
  // IPv6 address, which is why the bracket form is handled above).
  for (std::size_t i = colon + 1; i < host.size(); ++i) {
    if (!std::isdigit(static_cast<unsigned char>(host[i]))) return host;
  }
  return host.substr(0, colon);
}

std::size_t header_end(const Bytes& bytes, std::size_t* head_len) {
  const std::string s(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  std::size_t crlf = s.find("\r\n\r\n");
  if (crlf != std::string::npos) {
    *head_len = crlf + 4;
    return crlf;
  }
  const std::size_t lf = s.find("\n\n");
  if (lf != std::string::npos) {
    *head_len = lf + 2;
    return lf;
  }
  return std::string::npos;
}

bool method_like(const std::string& word) {
  static const char* kMethods[] = {"GET",     "POST",  "HEAD",   "PUT",   "DELETE", "OPTIONS",
                                   "TRACE",   "PATCH", "CONNECT", "PRI",  "PROPFIND"};
  for (const char* m : kMethods) {
    if (word == m) return true;
  }
  return false;
}

RelayDecision blocked(const std::string& url, const std::string& host, const std::string& reason,
                      bool is_tls) {
  RelayDecision d;
  d.verdict = is_tls ? RelayVerdict::Reset : RelayVerdict::Block;
  d.url = url;
  d.host = host;
  d.reason = reason;
  d.is_tls = is_tls;
  d.status = 403;
  d.content_type = "text/html; charset=utf-8";
  return d;
}

}  // namespace

const char* tunrelay_verdict_name(RelayVerdict v) {
  switch (v) {
    case RelayVerdict::NeedMore: return "need-more";
    case RelayVerdict::Forward: return "forward";
    case RelayVerdict::Block: return "block";
    case RelayVerdict::Redirect: return "redirect";
    case RelayVerdict::Reset: return "reset";
  }
  return "?";
}

bool tunrelay_port_is_http(u16 port) {
  switch (port) {
    case 80:
    case 8000:
    case 8008:
    case 8080:
    case 8888:
      return true;
    default:
      return false;
  }
}

bool tunrelay_port_is_tls(u16 port) {
  switch (port) {
    case 443:
    case 8443:
    case 9443:
      return true;
    default:
      return false;
  }
}

std::string RelayDecision::describe() const {
  std::string s = tunrelay_verdict_name(verdict);
  if (!url.empty()) s += " " + url;
  if (!reason.empty()) s += " (" + reason + ")";
  if (verdict == RelayVerdict::Redirect && !target.empty()) s += " -> " + target;
  return s;
}

std::string tunrelay_http_response(int status, const std::string& content_type,
                                   const std::string& body, const std::string& location) {
  const char* reason = "Blocked";
  switch (status) {
    case 200: reason = "OK"; break;
    case 204: reason = "No Content"; break;
    case 302: reason = "Found"; break;
    case 307: reason = "Temporary Redirect"; break;
    case 403: reason = "Forbidden"; break;
    case 404: reason = "Not Found"; break;
    case 502: reason = "Bad Gateway"; break;
    default: break;
  }
  char head[512];
  std::snprintf(head, sizeof(head),
                "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                "Cache-Control: no-store\r\nConnection: close\r\n",
                status, reason, content_type.c_str(), body.size());
  std::string out = head;
  if (!location.empty()) out += "Location: " + location + "\r\n";
  out += "X-Netcap: blocked\r\n\r\n";
  out += body;
  return out;
}

std::string tunrelay_block_page(const RelayDecision& d) {
  std::string host = d.host.empty() ? d.url : d.host;
  std::string html =
      "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">"
      "<title>已拦截</title></head><body style=\"margin:0;font:15px/1.6 system-ui,"
      "'Segoe UI',sans-serif;background:#12141a;color:#e6e8ee\">"
      "<div style=\"max-width:640px;margin:12vh auto;padding:0 24px\">"
      "<div style=\"font-size:44px;line-height:1\">&#128737;</div>"
      "<h1 style=\"font-size:22px;margin:16px 0 4px\">已拦截这个请求</h1>"
      "<p style=\"color:#9aa4b2;margin:0 0 18px\">netcap 在用户态隧道里拦下了它，"
      "没有任何数据离开这台机器。</p>"
      "<table style=\"border-collapse:collapse;font-size:14px\">"
      "<tr><td style=\"padding:3px 14px 3px 0;color:#8b93a1\">目标</td><td>";
  html += host;
  html += "</td></tr><tr><td style=\"padding:3px 14px 3px 0;color:#8b93a1\">完整地址</td><td>";
  html += d.url;
  html += "</td></tr><tr><td style=\"padding:3px 14px 3px 0;color:#8b93a1\">命中规则</td><td>";
  html += d.reason.empty() ? std::string("(未记录)") : d.reason;
  html += "</td></tr></table>"
          "<p style=\"color:#6f7887;font-size:13px;margin-top:22px\">"
          "要放行它，把对应规则删掉或加一条 <code style=\"color:#c9d1d9\">@@</code> 例外，"
          "然后重启代理即可。</p></div></body></html>";
  return html;
}

// `$removeparam` is a request-side rewrite: the rule engine only reports the
// parameter spec (pipe separated names, `*` wildcards, empty or "*" meaning
// every parameter). Rebuilding the query string belongs to whoever owns the
// request line, which is this file.
bool strip_parameters(std::string* url, const std::string& spec) {
  const std::size_t q = url->find('?');
  if (q == std::string::npos) return false;
  const std::string head = url->substr(0, q);
  const std::string query = url->substr(q + 1);
  const bool all = spec.empty() || spec == "*";
  std::string kept;
  std::size_t begin = 0;
  while (begin <= query.size()) {
    std::size_t end = query.find('&', begin);
    if (end == std::string::npos) end = query.size();
    const std::string pair = query.substr(begin, end - begin);
    const std::size_t eq = pair.find('=');
    const std::string name = lower(eq == std::string::npos ? pair : pair.substr(0, eq));
    bool drop = all;
    if (!drop && !name.empty()) {
      std::size_t p = 0;
      while (p <= spec.size()) {
        std::size_t bar = spec.find('|', p);
        if (bar == std::string::npos) bar = spec.size();
        const std::string want = lower(spec.substr(p, bar - p));
        if (!want.empty()) {
          const bool wild = want.back() == '*';
          const std::string stem = wild ? want.substr(0, want.size() - 1) : want;
          if (name.size() >= stem.size() && name.compare(0, stem.size(), stem) == 0 &&
              (wild || name.size() == stem.size())) {
            drop = true;
            break;
          }
        }
        if (bar >= spec.size()) break;
        p = bar + 1;
      }
    }
    if (!drop && !pair.empty()) {
      if (!kept.empty()) kept += '&';
      kept += pair;
    }
    if (end >= query.size()) break;
    begin = end + 1;
  }
  *url = kept.empty() ? head : head + "?" + kept;
  return true;
}

RelayDecision tunrelay_inspect(const RuleSet* rules, u16 port, const Bytes& bytes,
                               std::size_t* consumed, std::size_t max_head) {
  RelayDecision d;
  if (consumed != nullptr) *consumed = 0;
  if (bytes.empty()) return d;

  const std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());

  // ----------------------------------------------------------------- QUIC
  // A QUIC Initial is a long-header datagram, and its payload keys are derived
  // from the connection ID with the well-known salt (RFC 9001 section 5.2) --
  // so the ClientHello inside it, and therefore the SNI, is readable without
  // any secret from either endpoint. That is the *only* part of QUIC we can
  // judge by name today: 1-RTT packets need the handshake traffic secrets.
  //
  // UDP has no RST, so a blocked flow is dropped: the client retries or falls
  // back to TCP, where the rest of the pipeline can see the whole URL.
  if (tunrelay_port_is_tls(port)) {
    std::string quic_sni;
    std::string quic_alpn;
    std::string quic_err;
    if (quic_parse_initial(bytes.data(), bytes.size(), &quic_sni, &quic_alpn, &quic_err) &&
        !quic_sni.empty()) {
      d.is_tls = true;
      d.host = quic_sni;
      d.url = "https://" + quic_sni + "/";
      if (consumed != nullptr) *consumed = bytes.size();
      const std::string alpn_note = quic_alpn.empty() ? std::string() : (" (alpn " + quic_alpn + ")");
      if (rules == nullptr) {
        d.verdict = RelayVerdict::Forward;
        d.reason = "QUIC Initial" + alpn_note + ": no rules loaded";
        return d;
      }
      const RuleDecision qd = rules->decide(rule_request_from_url(d.url, "", ResourceType::Document));
      if (qd.action == RuleAction::Allow) {
        d.verdict = RelayVerdict::Forward;
        d.reason = qd.explain();
        return d;
      }
      if (qd.action == RuleAction::Block) {
        d.reason = qd.explain().empty() ? ("QUIC Initial for " + quic_sni + " is blocked" + alpn_note)
                                        : (qd.explain() + alpn_note);
        d.verdict = RelayVerdict::Reset;
        return d;
      }
      if (qd.action == RuleAction::Redirect) {
        // Nothing to answer with: a UDP flow cannot be redirected by name.
        d.verdict = RelayVerdict::Reset;
        d.reason = "redirect rule on a QUIC flow: " + qd.explain();
        return d;
      }
      d.verdict = RelayVerdict::Forward;
      d.reason = qd.explain();
      return d;
    }
  }

  // ------------------------------------------------------------------ TLS
  if (tunrelay_port_is_tls(port)) {
    d.is_tls = true;
    TlsRecordHeader rh;
    const std::size_t hdr = tls_parse_record_header(bytes.data(), bytes.size(), &rh);
    if (hdr == 0) {
      // Either not enough bytes for a record header, or not TLS at all. The
      // second case must be forwarded: a port number is not proof of protocol.
      if (bytes.size() >= 5) {
        d.verdict = RelayVerdict::Forward;
        d.reason = "not a TLS record";
        if (consumed != nullptr) *consumed = bytes.size();
      } else if (bytes.size() >= max_head) {
        d.verdict = RelayVerdict::Reset;
        d.reason = "TLS record header never arrived";
      }
      return d;
    }
    if (rh.type != TLS_HANDSHAKE) {
      d.verdict = RelayVerdict::Forward;
      d.reason = "TLS record is not a handshake";
      if (consumed != nullptr) *consumed = bytes.size();
      return d;
    }
    if (bytes.size() < 5u + rh.length) {
      if (bytes.size() >= max_head) {
        d.verdict = RelayVerdict::Reset;
        d.reason = "client hello did not fit in the inspection buffer";
      }
      return d;
    }
    // Handshake message: type(1) length(3) body
    if (5u + rh.length < 9u || bytes[5] != 1) {
      d.verdict = RelayVerdict::Forward;
      d.reason = "first handshake message is not a client hello";
      if (consumed != nullptr) *consumed = bytes.size();
      return d;
    }
    const std::size_t hs_len =
        (static_cast<std::size_t>(bytes[6]) << 16) | (static_cast<std::size_t>(bytes[7]) << 8) | bytes[8];
    if (hs_len + 9u > 5u + rh.length) {
      d.verdict = RelayVerdict::Forward;
      d.reason = "client hello length disagrees with the record";
      if (consumed != nullptr) *consumed = bytes.size();
      return d;
    }
    TlsClientHelloInfo info;
    std::string err;
    if (!tls_parse_client_hello(bytes.data() + 9, hs_len, &info, &err) || info.sni.empty()) {
      // No SNI (or an unparsable hello): we cannot judge it by name, so it goes
      // out. Blocking here would be guesswork.
      d.verdict = RelayVerdict::Forward;
      d.reason = info.sni.empty() && err.empty() ? "client hello carries no SNI" : "client hello: " + err;
      if (consumed != nullptr) *consumed = bytes.size();
      return d;
    }
    d.host = info.sni;
    d.url = "https://" + info.sni + "/";
    if (consumed != nullptr) *consumed = bytes.size();
    if (rules == nullptr) {
      d.verdict = RelayVerdict::Forward;
      return d;
    }
    const RuleDecision rd = rules->decide(rule_request_from_url(d.url, "", ResourceType::Document));
    if (rd.action == RuleAction::Allow) {
      d.verdict = RelayVerdict::Forward;
      d.reason = rd.explain();
      return d;
    }
    if (rd.action == RuleAction::Block) {
      d.reason = rd.explain().empty() ? ("SNI " + info.sni + " is blocked") : rd.explain();
      return blocked(d.url, d.host, d.reason, true);
    }
    if (rd.action == RuleAction::Redirect) {
      // A TLS flow cannot be redirected without decrypting it; resetting is the
      // honest answer, and the event log says why.
      d.verdict = RelayVerdict::Reset;
      d.reason = "redirect rule on a TLS flow: " + rd.explain();
      return d;
    }
    d.verdict = RelayVerdict::Forward;
    d.reason = rd.explain();
    return d;
  }

  // ----------------------------------------------------------------- HTTP
  if (!tunrelay_port_is_http(port)) {
    d.verdict = RelayVerdict::Forward;
    d.reason = "not an HTTP port";
    if (consumed != nullptr) *consumed = bytes.size();
    return d;
  }

  // RFC 7230 allows empty lines before the request line.
  std::size_t start = 0;
  while (start < text.size() && (text[start] == '\r' || text[start] == '\n')) ++start;
  const std::string rest = text.substr(start);
  const std::size_t eol = rest.find('\n');
  if (eol == std::string::npos) {
    if (bytes.size() >= max_head) {
      d.verdict = RelayVerdict::Reset;
      d.reason = "HTTP request line never ended";
    }
    return d;
  }
  std::string line = trim(rest.substr(0, eol));
  const std::size_t sp1 = line.find(' ');
  if (sp1 == std::string::npos) {
    d.verdict = RelayVerdict::Forward;
    d.reason = "no request target";
    if (consumed != nullptr) *consumed = bytes.size();
    return d;
  }
  const std::string method = line.substr(0, sp1);
  const std::size_t sp2 = line.find(' ', sp1 + 1);
  const std::string target = sp2 == std::string::npos ? line.substr(sp1 + 1) : line.substr(sp1 + 1, sp2 - sp1 - 1);
  if (!method_like(method)) {
    d.verdict = RelayVerdict::Forward;
    d.reason = "not an HTTP request line";
    if (consumed != nullptr) *consumed = bytes.size();
    return d;
  }

  std::size_t head_len = 0;
  if (header_end(bytes, &head_len) == std::string::npos) {
    if (bytes.size() >= max_head) {
      d.verdict = RelayVerdict::Reset;
      d.reason = "HTTP request head exceeded the inspection buffer";
    }
    return d;
  }
  if (consumed != nullptr) *consumed = head_len;

  // Host header (the request target may also be absolute when a proxy is in
  // front, which happens whenever the browser was configured by hand).
  std::string host;
  const std::size_t host_at = find_ci(text, "\nhost:");
  if (host_at != std::string::npos) {
    const std::size_t value_at = host_at + 6;
    const std::size_t end = text.find('\n', value_at);
    host = strip_port(trim(text.substr(value_at, end == std::string::npos ? std::string::npos : end - value_at)));
  }

  std::string url;
  if (target.compare(0, 7, "http://") == 0 || target.compare(0, 8, "https://") == 0) {
    url = target;
    if (host.empty()) {
      const std::size_t scheme = target.find("://") + 3;
      const std::size_t slash = target.find('/', scheme);
      host = strip_port(target.substr(scheme, slash == std::string::npos ? std::string::npos : slash - scheme));
    }
  } else if (!host.empty()) {
    url = "http://" + host + target;
  } else {
    d.verdict = RelayVerdict::Forward;
    d.reason = "no Host header and a relative target";
    return d;
  }
  d.host = host;
  d.url = url;

  if (rules == nullptr) {
    d.verdict = RelayVerdict::Forward;
    return d;
  }
  const RuleDecision rd = rules->decide(rule_request_from_url(url, "", ResourceType::Document));
  if (rd.action == RuleAction::Block) {
    d.reason = rd.explain().empty() ? ("blocked by rule") : rd.explain();
    RelayDecision b = blocked(url, host, d.reason, false);
    return b;
  }
  if (rd.action == RuleAction::Allow) {
    d.verdict = RelayVerdict::Forward;
    d.reason = rd.explain();
    return d;
  }
  if (rd.action == RuleAction::Redirect && !rd.value.empty()) {
    d.verdict = RelayVerdict::Redirect;
    d.reason = rd.explain();
    d.target = rd.value;
    d.status = 302;
    return d;
  }
  if (rd.action == RuleAction::Modify) {
    // A request rewrite (today: `$removeparam`). The relay must not quietly
    // send the parameter upstream anyway, so the rewritten URL is what the
    // caller forwards.
    d.verdict = RelayVerdict::Forward;
    const std::string spec =
        rd.rule != nullptr && !rd.rule->removeparam.empty() ? rd.rule->removeparam : rd.value;
    std::string rewritten = url;
    if (!spec.empty() && strip_parameters(&rewritten, spec) && rewritten != url) {
      d.target = rewritten;
      d.reason = rd.explain() + " (query string rewritten)";
    } else {
      d.target = url;
      d.reason = rd.explain();
    }
    return d;
  }
  d.verdict = RelayVerdict::Forward;
  d.reason = rd.explain();
  return d;
}

}  // namespace netcap
