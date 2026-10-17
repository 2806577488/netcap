// netcap - local interception proxy (see include/netcap/blocker.hpp).

#include "netcap/blocker.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "netcap/p256.hpp"
#include "netcap/rules.hpp"
#include "netcap/tls13.hpp"
#include "netcap/tls12.hpp"
#include "netcap/httpframe.hpp"
#include "netcap/origin.hpp"
#include "netcap/picker.hpp"
#include <utility>
#include "netcap/x509.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace netcap {

namespace {

// Where a connection currently is.  Every connection runs on its own thread, so
// when something throws we can say which phase it was in and which request it
// was working on, not just the peer address.
//
// These are plain character buffers on purpose.  They used to be thread_local
// std::string objects, and a thread_local std::string has a destructor, so the
// runtime destroyed it from the thread's TLS callback when the worker exited:
// that destructor ran against a control block that was already corrupt and the
// process died with 0xC0000374 (STATUS_HEAP_CORRUPTION) inside
// ~basic_string <- tls_callback.  Character arrays have no destructor, so
// nothing at all runs at thread exit.
thread_local char g_stage[64] = {0};
thread_local char g_target[192] = {0};

// Cheap enough to call unconditionally at the start of each phase.
void stage(const char* what) {
  std::snprintf(g_stage, sizeof(g_stage), "%s", what ? what : "");
}

void set_target(const std::string& what) {
  std::snprintf(g_target, sizeof(g_target), "%s", what.c_str());
}

#if defined(_WIN32)
using socket_t = SOCKET;
const socket_t kBadSocket = INVALID_SOCKET;

struct WinsockGuard {
  WinsockGuard() {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
  ~WinsockGuard() { WSACleanup(); }
};

void ensure_winsock() {
  static WinsockGuard guard;
  (void)guard;
}

bool socket_would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
using socket_t = int;
const socket_t kBadSocket = -1;

void ensure_winsock() {
  static bool once = []() {
    signal(SIGPIPE, SIG_IGN);
    return true;
  }();
  (void)once;
}

bool socket_would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

bool socket_valid(socket_t s) { return s != kBadSocket; }

void socket_close(socket_t s) {
  if (!socket_valid(s)) return;
#if defined(_WIN32)
  closesocket(s);
#else
  close(s);
#endif
}

int last_socket_error() {
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

// A receive/send timeout expressed in milliseconds, in whichever form the
// platform wants.
bool set_socket_timeout(socket_t s, int ms) {
  if (ms <= 0) return true;
#if defined(_WIN32)
  DWORD value = static_cast<DWORD>(ms);
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&value),
                    sizeof(value)) == 0 &&
         setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&value),
                    sizeof(value)) == 0;
#else
  timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
         setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

// Small writes (TLS records, HTTP heads) have to leave at once. Without
// TCP_NODELAY, Nagle plus the peer's delayed ACK costs ~200 ms per small write on
// loopback, which is where the MITM path used to lose about a second per request.
bool set_tcp_nodelay(socket_t s) {
  int one = 1;
  return setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one),
                    sizeof(one)) == 0;
}

// NETCAP_MITM_TRACE=1 prints one line per phase of the MITM path to stderr, so a
// slow request can be attributed without rebuilding a profiler.
bool mitm_trace_on() {
  static const bool on = []() {
    const char* value = std::getenv("NETCAP_MITM_TRACE");
    return value != nullptr && *value != '\0' && std::string(value) != "0";
  }();
  return on;
}

void mitm_trace(const char* phase, i64 since_us) {
  if (!mitm_trace_on()) return;
  const double ms = static_cast<double>(now_unix_us() - since_us) / 1000.0;
  std::fprintf(stderr, "netcap: mitm %-16s %8.2f ms\n", phase, ms);
  std::fflush(stderr);
}

// The TLS engine's words for "the client itself ended the handshake".  An alert
// is the client answering our flight out loud (a certificate it will not accept
// reads as "unknown ca"); a client that closes the socket instead of alerting is
// indistinguishable from an abandoned preconnect, which is why the refusal
// memory needs a repeat before it believes it.
bool is_client_refusal(const std::string& why) {
  return why.find("the client rejected the handshake") != std::string::npos ||
         why.find("the client sent an alert") != std::string::npos;
}

bool set_nonblocking(socket_t s, bool on) {
#if defined(_WIN32)
  u_long mode = on ? 1 : 0;
  return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(s, F_GETFL, 0);
  if (flags < 0) return false;
  if (on) {
    flags |= O_NONBLOCK;
  } else {
    flags &= ~O_NONBLOCK;
  }
  return fcntl(s, F_SETFL, flags) == 0;
#endif
}

int socket_error_state(socket_t s) {
  int err = 0;
#if defined(_WIN32)
  int len = sizeof(err);
  if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0) {
    return WSAGetLastError();
  }
#else
  socklen_t len = sizeof(err);
  if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len) != 0) return errno;
#endif
  return err;
}

std::string lowercase(std::string text) {
  for (char& c : text) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return text;
}

bool wait_readable(socket_t s, int timeout_ms) {
  if (!socket_valid(s)) return false;
  fd_set set;
  FD_ZERO(&set);
  FD_SET(s, &set);
  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  const int rc = select(static_cast<int>(s) + 1, &set, nullptr, nullptr, &tv);
  return rc > 0;
}

bool wait_writable(socket_t s, int timeout_ms) {
  if (!socket_valid(s)) return false;
  fd_set set;
  FD_ZERO(&set);
  FD_SET(s, &set);
  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  const int rc = select(static_cast<int>(s) + 1, nullptr, &set, nullptr, &tv);
  return rc > 0;
}

// Which of `sockets` finished connecting (or failed) within `timeout_ms`.  The
// exception set is checked too: a refused connection is reported there on some
// platforms and only in the write set on others.  `FD_SETSIZE` is 64 on Windows
// and the candidate list is capped well below it (see origin_max_addresses()).
std::vector<socket_t> wait_writable_any(const std::vector<socket_t>& sockets, int timeout_ms) {
  std::vector<socket_t> ready;
  fd_set wr;
  fd_set ex;
  FD_ZERO(&wr);
  FD_ZERO(&ex);
  socket_t highest = 0;
  for (socket_t s : sockets) {
    if (!socket_valid(s)) continue;
    FD_SET(s, &wr);
    FD_SET(s, &ex);
    if (s > highest) highest = s;
  }
  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  const int rc = select(static_cast<int>(highest) + 1, nullptr, &wr, &ex, &tv);
  if (rc <= 0) return ready;
  for (socket_t s : sockets) {
    if (socket_valid(s) && (FD_ISSET(s, &wr) || FD_ISSET(s, &ex))) ready.push_back(s);
  }
  return ready;
}

// The entry of `list` whose text is `text`, or null.
const OriginAddress* find_address(const std::vector<OriginAddress>& list, const std::string& text) {
  for (const OriginAddress& address : list) {
    if (address.text == text) return &address;
  }
  return nullptr;
}

// NETCAP_ORIGIN_TRACE=1 prints every upstream address decision to stderr: which
// addresses were racy, which one won and what it cost.  Off by default because
// a busy page makes this very chatty.
bool origin_trace_enabled() {
  const char* value = std::getenv("NETCAP_ORIGIN_TRACE");
  return value != nullptr && *value != '\0' && std::strcmp(value, "0") != 0;
}

void origin_trace(const std::string& key, const std::string& address, i64 rtt_us, const char* how) {
  if (!origin_trace_enabled()) return;
  if (rtt_us >= 0) {
    std::fprintf(stderr, "netcap: origin %-28s %-40s %s %.2f ms\n", key.c_str(), address.c_str(), how,
                 static_cast<double>(rtt_us) / 1000.0);
  } else {
    std::fprintf(stderr, "netcap: origin %-28s %-40s %s\n", key.c_str(), address.c_str(), how);
  }
}

// ---------------------------------------------------------------- HTTP bits

struct HeaderLine {
  std::string name;   // original case
  std::string lower;  // lowercase, for comparisons
  std::string value;
};

struct RequestHead {
  std::string method;
  std::string target;
  std::string version;
  std::vector<HeaderLine> headers;
  std::string host;
  std::string body;         // body bytes read together with the head
  bool keep_alive = false;
  bool chunked_body = false;

  const std::string* find(const std::string& lower_name) const {
    for (const HeaderLine& h : headers) {
      if (h.lower == lower_name) return &h.value;
    }
    return nullptr;
  }
};

std::string trim_copy(const std::string& text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) ++begin;
  while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' || text[end - 1] == '\r')) --end;
  return text.substr(begin, end - begin);
}

bool parse_head(const std::string& head, RequestHead* out, std::string* error) {
  const std::size_t line_end = head.find("\r\n");
  if (line_end == std::string::npos) {
    *error = "no complete request line";
    return false;
  }
  const std::string request_line = head.substr(0, line_end);
  const std::size_t first = request_line.find(' ');
  if (first == std::string::npos) {
    *error = "malformed request line";
    return false;
  }
  const std::size_t second = request_line.find(' ', first + 1);
  if (second == std::string::npos) {
    *error = "malformed request line (no version)";
    return false;
  }
  out->method = request_line.substr(0, first);
  out->target = request_line.substr(first + 1, second - first - 1);
  out->version = trim_copy(request_line.substr(second + 1));
  if (out->version.empty()) out->version = "HTTP/1.1";

  std::size_t pos = line_end + 2;
  while (pos < head.size()) {
    const std::size_t next = head.find("\r\n", pos);
    if (next == std::string::npos || next == pos) break;
    const std::string line = head.substr(pos, next - pos);
    const std::size_t colon = line.find(':');
    if (colon != std::string::npos) {
      HeaderLine h;
      h.name = trim_copy(line.substr(0, colon));
      h.lower = lowercase(h.name);
      h.value = trim_copy(line.substr(colon + 1));
      if (h.lower == "host" && out->host.empty()) out->host = h.value;
      out->headers.push_back(h);
    }
    pos = next + 2;
  }

  const std::string* connection = out->find("proxy-connection");
  if (connection == nullptr) connection = out->find("connection");
  if (connection != nullptr) {
    out->keep_alive = lowercase(*connection).find("close") == std::string::npos;
  } else {
    out->keep_alive = out->version == "HTTP/1.1";
  }
  const std::string* te = out->find("transfer-encoding");
  out->chunked_body = te != nullptr && lowercase(*te).find("chunked") != std::string::npos;
  return true;
}

std::string split_host_port(const std::string& host, std::uint16_t* port) {
  const std::size_t colon = host.rfind(':');
  if (colon != std::string::npos && host.find(':') == colon) {
    const std::string digits = host.substr(colon + 1);
    bool numeric = !digits.empty();
    for (char c : digits) {
      if (c < '0' || c > '9') numeric = false;
    }
    if (numeric) {
      *port = static_cast<std::uint16_t>(std::strtoul(digits.c_str(), nullptr, 10));
      return host.substr(0, colon);
    }
  }
  return host;
}

std::string head_to_string(const RequestHead& req, const std::string& target,
                           bool keep_alive = false) {
  std::string text = req.method + " " + target + " " + (req.version.empty() ? "HTTP/1.1" : req.version) + "\r\n";
  for (const HeaderLine& h : req.headers) {
    if (h.lower == "proxy-connection") continue;
    if (h.lower == "connection") continue;
    text += h.name + ": " + h.value + "\r\n";
  }
  // The client's own connection header was dropped just above, so this is the
  // only one the origin sees.  `close` used to be written unconditionally: it
  // let the relay stop at the origin's EOF instead of framing the response, and
  // it made one origin connection per request mandatory.  Asking for keep-alive
  // is what lets the socket go back to the pool, and the relay below frames the
  // response so it still knows where the message ends.
  text += keep_alive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";
  return text;
}

}  // namespace

// ------------------------------------------------------- exported helpers

const char* intercept_action_name(InterceptAction action) {
  switch (action) {
    case InterceptAction::Pass: return "pass";
    case InterceptAction::Block: return "block";
    case InterceptAction::Modify: return "modify";
    case InterceptAction::Redirect: return "redirect";
    case InterceptAction::Tunnel: return "tunnel";
    case InterceptAction::Error: return "error";
    case InterceptAction::Cancelled: return "cancelled";
  }
  return "?";
}

RequestTarget parse_request_target(const std::string& method, const std::string& target,
                                  const std::string& host) {
  RequestTarget out;
  if (lowercase(method) == "connect") {
    out.secure = true;
    out.port = 443;
    std::string name = target;
    const std::size_t colon = target.rfind(':');
    if (colon != std::string::npos) {
      name = target.substr(0, colon);
      out.port = static_cast<std::uint16_t>(std::strtoul(target.substr(colon + 1).c_str(), nullptr, 10));
    }
    out.host = lowercase(name);
    out.path = "/";
    out.url = "https://" + out.host;
    if (out.port != 443) out.url += ":" + std::to_string(out.port);
    out.url += "/";
    return out;
  }

  const std::string lower_target = lowercase(target);
  if (lower_target.rfind("http://", 0) == 0 || lower_target.rfind("https://", 0) == 0) {
    const bool secure = lower_target.rfind("https://", 0) == 0;
    const std::size_t scheme_end = target.find("://") + 3;
    const std::size_t slash = target.find('/', scheme_end);
    std::string authority = slash == std::string::npos ? target.substr(scheme_end)
                                                      : target.substr(scheme_end, slash - scheme_end);
    std::uint16_t port = secure ? 443 : 80;
    out.host = lowercase(split_host_port(authority, &port));
    out.port = port;
    out.secure = secure;
    out.path = slash == std::string::npos ? "/" : target.substr(slash);
    out.url = (secure ? "https://" : "http://") + out.host;
    if ((secure && port != 443) || (!secure && port != 80)) out.url += ":" + std::to_string(port);
    out.url += out.path;
    return out;
  }

  // Origin form: the Host header supplies the authority.
  std::uint16_t port = 80;
  const std::string name = split_host_port(host, &port);
  out.host = lowercase(name);
  out.port = port == 0 ? 80 : port;
  out.secure = false;
  out.path = target.empty() ? "/" : target;
  out.url = "http://" + out.host;
  if (out.port != 80) out.url += ":" + std::to_string(out.port);
  out.url += out.path;
  return out;
}

const char* const kTrackerParameters[] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "utm_name",   "utm_reader", "utm_viz_id",   "fbclid",   "gclid",       "dclid",
    "gbraid",     "wbraid",     "msclkid",      "yclid",    "igshid",      "mc_eid",
    "mc_cid",     "_hsenc",     "_hsmi",        "ref_src",  "spm",         "scm",
    "si",         "vero_id",    "twclid",       "ttclid",   "li_fat_id",   "s_kwcid",
    "wickedid",   "epik",       "icid",
};

const char* const* tracker_parameter_names(std::size_t* count) {
  if (count != nullptr) *count = sizeof(kTrackerParameters) / sizeof(kTrackerParameters[0]);
  return kTrackerParameters;
}

bool strip_query_parameters(std::string* path, const std::string& spec) {
  if (path == nullptr) return false;
  const std::size_t question = path->find('?');
  if (question == std::string::npos) return false;

  std::vector<std::string> remove;
  const bool everything = spec.empty() || spec == "*";
  if (everything) {
    std::size_t count = 0;
    const char* const* names = tracker_parameter_names(&count);
    for (std::size_t i = 0; i < count; ++i) remove.push_back(names[i]);
  } else {
    std::size_t begin = 0;
    while (begin <= spec.size()) {
      const std::size_t bar = spec.find('|', begin);
      const std::string piece = spec.substr(begin, bar == std::string::npos ? std::string::npos : bar - begin);
      if (!piece.empty()) remove.push_back(lowercase(piece));
      if (bar == std::string::npos) break;
      begin = bar + 1;
    }
  }
  if (remove.empty()) return false;

  const std::string query = path->substr(question + 1);
  std::string kept;
  bool changed = false;
  std::size_t begin = 0;
  while (begin <= query.size()) {
    const std::size_t amp = query.find('&', begin);
    const std::string pair = query.substr(begin, amp == std::string::npos ? std::string::npos : amp - begin);
    if (!pair.empty()) {
      const std::size_t equals = pair.find('=');
      const std::string name = lowercase(pair.substr(0, equals));
      if (std::find(remove.begin(), remove.end(), name) != remove.end()) {
        changed = true;
      } else {
        if (!kept.empty()) kept += "&";
        kept += pair;
      }
    }
    if (amp == std::string::npos) break;
    begin = amp + 1;
  }
  if (!changed) return false;
  *path = path->substr(0, question);
  if (!kept.empty()) *path += "?" + kept;
  return true;
}

std::size_t strip_header(std::string* head, const std::string& lower_name) {
  if (head == nullptr || lower_name.empty()) return 0;
  const std::size_t head_end = head->find("\r\n\r\n");
  const std::size_t limit = head_end == std::string::npos ? head->size() : head_end;
  const std::size_t first_end = head->find("\r\n");
  if (first_end == std::string::npos || first_end >= limit) return 0;

  std::string out = head->substr(0, first_end + 2);  // request line stays
  std::size_t pos = first_end + 2;
  std::size_t removed = 0;
  while (pos < limit) {
    const std::size_t next = head->find("\r\n", pos);
    if (next == std::string::npos || next > limit) break;
    const std::string line = head->substr(pos, next - pos);
    const std::size_t colon = line.find(':');
    const bool drop = colon != std::string::npos && lowercase(line.substr(0, colon)) == lower_name;
    if (drop) {
      ++removed;
    } else {
      out += line;
      out += "\r\n";
    }
    pos = next + 2;
  }
  if (removed == 0) return 0;

  out += "\r\n";  // the blank line that ends the head
  if (limit < head->size()) out += head->substr(limit + 4);
  *head = out;
  return removed;
}

// The page host out of a `Referer`/`Origin` value: scheme, userinfo, port and
// path are dropped, so `https://news.example.org:8443/a?b` becomes
// `news.example.org`.  `null` is what a browser sends on a privacy-sensitive
// request and is not a host at all.
std::string document_host_from_field(const std::string& raw) {
  std::string text = lowercase(raw);
  if (text.empty() || text == "null") return std::string();
  const std::size_t scheme = text.find("://");
  if (scheme != std::string::npos) text = text.substr(scheme + 3);
  const std::size_t at = text.find('@');  // userinfo may contain a colon
  if (at != std::string::npos) text = text.substr(at + 1);
  const std::size_t slash = text.find('/');
  if (slash != std::string::npos) text = text.substr(0, slash);
  std::uint16_t port = 0;
  return split_host_port(text, &port);
}

// The same, read straight out of a request that has already been parsed.  The
// rule decision needs it for `$third-party`, `$first-party` and `$domain=`:
// leaving it empty meant those rules could never match a proxied request.
std::string document_host_from_request(const RequestHead& req) {
  for (const char* name : {"referer", "origin"}) {
    const std::string* value = req.find(name);
    if (value == nullptr) continue;
    const std::string host = document_host_from_field(*value);
    if (!host.empty()) return host;
  }
  return std::string();
}

std::string request_document_host(const std::string& head) {
  const std::size_t head_end = head.find("\r\n\r\n");
  const std::size_t limit = head_end == std::string::npos ? head.size() : head_end;
  const std::size_t first_end = head.find("\r\n");
  if (first_end == std::string::npos) return std::string();

  auto field = [&](const char* want) -> std::string {
    std::size_t pos = first_end + 2;
    while (pos < limit) {
      const std::size_t next = head.find("\r\n", pos);
      if (next == std::string::npos || next > limit) break;
      const std::string line = head.substr(pos, next - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string::npos && lowercase(line.substr(0, colon)) == want) {
        return trim_copy(line.substr(colon + 1));
      }
      pos = next + 2;
    }
    return std::string();
  };

  for (const char* name : {"referer", "origin"}) {
    const std::string host = document_host_from_field(field(name));
    if (!host.empty()) return host;
  }
  return std::string();
}

// Chrome/Edge announce what a request is for.  Generic cosmetic rules (`##.ad`)
// are only worth injecting into something that can carry a <style> and actually
// renders a page: a JSON/API reply cannot hold an ad slot, and injecting the
// whole generic selector list into every response turned every row into a
// "rewrite" while changing nothing a user could see.  Host-scoped rules
// (`blog.csdn.net##…`) are always injected — they are aimed at one site.
bool request_wants_generic_cosmetics(const std::string& head) {
  const std::string lower_head = lowercase(head);
  const std::size_t at = lower_head.find("\nsec-fetch-dest:");
  if (at == std::string::npos) return true;  // no hint: keep injecting them
  std::size_t start = at + 16;
  while (start < lower_head.size() && lower_head[start] == ' ') ++start;
  std::size_t end = start;
  while (end < lower_head.size() && lower_head[end] != '\r' && lower_head[end] != '\n') ++end;
  const std::string value = lower_head.substr(start, end - start);
  return value == "document" || value == "iframe" || value == "frame";
}

// `HTTP/1.1 404 Not Found\r\n` -> 404, and 0 while the status line is still
// incomplete (or when what arrived is not an HTTP response at all).
int status_from_response_head(const char* data, std::size_t len) {
  if (len < 5) return 0;
  if (std::strncmp(data, "HTTP/", 5) != 0) return -1;  // not an HTTP response
  std::size_t i = 5;
  while (i < len && data[i] != ' ') ++i;  // "1.1"
  while (i < len && data[i] == ' ') ++i;
  if (i + 3 > len) return 0;  // the digits have not arrived yet
  const char* d = data + i;
  const bool digits = d[0] >= '0' && d[0] <= '9' && d[1] >= '0' && d[1] <= '9' &&
                      d[2] >= '0' && d[2] <= '9';
  if (!digits) return -1;
  return (d[0] - '0') * 100 + (d[1] - '0') * 10 + (d[2] - '0');
}

// ------------------------------------------------- response body reading

// A response is rewritten as a whole, so it has to be read as a whole: the head
// to know how the body is framed, then the body itself.  Both limits are there
// to keep a hostile or enormous response from eating memory; the relay path is
// still there for anything that does not fit.
constexpr std::size_t kMaxResponseHead = 64 * 1024;
constexpr std::size_t kMaxResponseBody = 8 * 1024 * 1024;
// Same idea for request bodies.  A declared Content-Length is not a promise:
// without a ceiling a client can make the proxy read until memory runs out.
constexpr std::size_t kMaxRequestBody = 8 * 1024 * 1024;

/// True when the client asked to be told "go ahead" before it sends the body.
/// Chromium does this for some POSTs.  A proxying middle has to answer it (and
/// keep the header away from the origin), or the client waits for a 100, the
/// origin waits for a body, and the app reports a failure and retries.
bool wants_continue(const RequestHead& req) {
  const std::string* expect = req.find("expect");
  return expect != nullptr && lowercase(*expect).find("100-continue") != std::string::npos;
}

/// True when `data` holds a complete chunked body (last chunk plus trailers).
bool chunked_complete(const std::string& data) {
  std::size_t pos = 0;
  while (true) {
    const std::size_t eol = data.find("\r\n", pos);
    if (eol == std::string::npos) return false;
    const std::string line = data.substr(pos, eol - pos);
    std::size_t size = 0;
    bool any = false;
    for (const char c : line) {
      if (c == ';') break;  // chunk extension: ignored
      int v = -1;
      if (c >= '0' && c <= '9') {
        v = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        v = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        v = c - 'A' + 10;
      } else {
        return false;
      }
      size = size * 16 + static_cast<std::size_t>(v);
      any = true;
    }
    if (!any) return false;
    pos = eol + 2;
    if (size == 0) {
      while (true) {  // the trailer section ends with an empty line
        const std::size_t t = data.find("\r\n", pos);
        if (t == std::string::npos) return false;
        if (t == pos) return true;
        pos = t + 2;
      }
    }
    if (data.size() < pos + size + 2) return false;
    pos += size + 2;
  }
}

/// `pull` appends whatever arrived to the buffer and returns the number of
/// bytes, 0 when nothing came (a timeout: keep trying) and -1 on EOF or error.
///
/// Returns false only when there is no usable head at all.  `complete` says
/// whether the body was framed properly: a truncated body is still handed back
/// so the caller can pass the bytes through untouched instead of guessing.
bool read_full_response(const std::function<int(std::string*)>& pull, const std::string& method,
                        std::string* head, std::string* body, int* status, bool* complete,
                        std::string* why) {
  stage("reading the whole response");
  *complete = false;
  std::string buf;
  std::size_t head_end = std::string::npos;
  int idle = 0;
  while (true) {
    head_end = buf.find("\r\n\r\n");
    if (head_end != std::string::npos) break;
    if (buf.size() > kMaxResponseHead) {
      *why = "the response head is larger than 64 KiB";
      return false;
    }
    const int rc = pull(&buf);
    if (rc < 0) {
      *why = "the origin closed before the response head was complete";
      return false;
    }
    idle = rc == 0 ? idle + 1 : 0;
    if (idle > 2) {
      *why = "the origin stopped sending the response head";
      return false;
    }
  }

  const std::string raw_head = buf.substr(0, head_end + 4);
  ResponseHead parsed;
  std::string error;
  if (!parse_response_head(raw_head, &parsed, &error)) {
    *why = error;
    return false;
  }
  *head = raw_head;
  if (status != nullptr) *status = parsed.status;

  std::string rest = buf.substr(head_end + 4);
  const bool no_body = method == "HEAD" || parsed.status == 204 || parsed.status == 304 ||
                       (parsed.status >= 100 && parsed.status < 200);
  if (no_body) {
    *body = rest;
    *complete = true;
    return true;
  }

  bool framed = true;
  while (true) {
    if (parsed.chunked) {
      if (chunked_complete(rest)) break;
    } else if (parsed.has_content_length) {
      if (rest.size() >= parsed.content_length) break;
    }
    if (rest.size() > kMaxResponseBody) {
      *why = "the response body is larger than 8 MiB";
      framed = false;
      break;
    }
    const int rc = pull(&rest);
    if (rc <= 0) {
      // Either the origin closed (which frames a close-delimited body) or it
      // went quiet.  Only the first case counts as complete.
      framed = rc < 0 && !parsed.chunked && !parsed.has_content_length;
      if (rc > 0) continue;
      break;
    }
  }
  if (rest.size() > kMaxResponseBody) framed = false;
  *complete = framed;
  *body = rest;
  return true;
}

// ------------------------------------------------------------- the blocker

std::vector<std::string> split_name_list(const std::string& text) {
  std::vector<std::string> out;
  std::string current;
  for (const char c : text) {
    if (c == ',' || c == '|' || c == ';') {
      if (!current.empty()) out.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(c);
  }
  if (!current.empty()) out.push_back(current);
  for (std::string& part : out) {
    std::size_t begin = 0;
    while (begin < part.size() && (part[begin] == ' ' || part[begin] == '\t')) ++begin;
    std::size_t end = part.size();
    while (end > begin && (part[end - 1] == ' ' || part[end - 1] == '\t')) --end;
    part = part.substr(begin, end - begin);
  }
  out.erase(std::remove_if(out.begin(), out.end(), [](const std::string& s) { return s.empty(); }),
            out.end());
  return out;
}

bool name_matches_any(const std::vector<std::string>& patterns, const std::string& name) {
  if (name.empty()) return false;
  const std::string lower_name = to_lower(name);
  for (const std::string& pattern : patterns) {
    if (pattern.empty()) continue;
    const std::string lower_pattern = to_lower(pattern);
    if (lower_name.find(lower_pattern) != std::string::npos) return true;
  }
  return false;
}

bool MitmPolicy::wants(const std::string& proc_name) const {
  // A non-empty `only` list is a whitelist that decides on its own, whether or
  // not the global switch is on.  The HTTPS settings page emits the two flags
  // together (`--mitm --mitm-only <common programs>`, "common programs" is its
  // recommended mode), and there `--mitm` only means "decryption is on at all";
  // letting the switch widen `only` back to every application would decrypt
  // exactly what the user just narrowed -- a game client, for instance, whose
  // own TLS never asked to be opened.
  if (!only.empty()) return name_matches_any(only, proc_name);
  // With the global switch off nothing else is decrypted, even unnamed clients.
  if (!global_on) return false;
  if (name_matches_any(skip, proc_name)) return false;
  return true;
}

std::string MitmPolicy::reason(const std::string& proc_name) const {
  const std::string who = proc_name.empty() ? std::string("an unknown application") : proc_name;
  if (name_matches_any(only, proc_name)) {
    return "decrypt: " + who + " is in --mitm-only";
  }
  if (!only.empty()) {
    return "tunnel: " + who + " is not in --mitm-only";
  }
  if (!global_on) {
    return "tunnel: HTTPS decryption is off (only --mitm-only applications are decrypted)";
  }
  if (name_matches_any(skip, proc_name)) {
    return "tunnel: " + who + " is in --mitm-skip";
  }
  if (proc_name.empty()) return "decrypt: every application is decrypted while the switch is on";
  return "decrypt: " + who + " is not excluded";
}

std::string MitmPolicy::describe() const {
  // A non-empty `only` list is the whole answer -- the switch cannot widen it,
  // so saying "on" next to it would describe a policy that is not in force.
  if (!only.empty()) {
    std::string out = "only ";
    for (std::size_t i = 0; i < only.size(); ++i) {
      if (i != 0) out += ",";
      out += only[i];
    }
    return out;
  }
  std::string out = global_on ? "on" : "off";
  if (!skip.empty()) {
    out += ", skipping ";
    for (std::size_t i = 0; i < skip.size(); ++i) {
      if (i != 0) out += ",";
      out += skip[i];
    }
  }
  return out;
}

struct InterceptProxy::Impl {
  BlockerConfig cfg;
  const RuleSet* rules = nullptr;
  socket_t listener = kBadSocket;
  std::uint16_t port = 0;
  std::string error;
  std::atomic<bool> running{false};
  std::atomic<int> active{0};
  mutable std::mutex mu;
  std::vector<InterceptEvent> events;
  BlockerStats stats;
  std::map<std::string, u64> rule_hits;

  // ---- element picker ----------------------------------------------------
  //
  // `picker` is flipped at runtime by the serve loop (it watches
  // `cfg.picker_flag`), so the interface can turn picking on without restarting
  // anything.  `picked` keeps what this session collected ("host" -> selectors)
  // so a pick hides the element in the very next response; the durable record
  // is the rule file the picker appends to.  Both guarded by mu.
  bool picker = false;
  std::vector<std::pair<std::string, std::string>> picked;

  // ---- man-in-the-middle state -------------------------------------------
  //
  // One leaf certificate per host name, issued on first use and cached for the
  // lifetime of the proxy: signing costs about 100 ms of scalar multiplication,
  // which is fine once per host and far too slow once per connection.
  struct LeafEntry {
    X509Cert cert;
    P256Key key;
  };
  CaBundle ca;
  bool ca_ready = false;
  std::map<std::string, std::shared_ptr<LeafEntry>> leaf_cache;
  // Clients that refuse our leaf, keyed by "application|host name".  An
  // application whose own trust store does not know our CA hangs up as soon as
  // it has seen the certificate, and no number of retries changes that: while
  // netcap is the system proxy, those retries are a broken application rather
  // than a filtering decision.  The first refusal is remembered silently (a
  // browser's cancelled preconnect looks the same from here); a second one for
  // the same host name retires the pair from decryption - see
  // `note_client_refusal()` and `mitm_retired()`.  The CA fingerprint is stored
  // with the entry, so a freshly created CA is tried again instead of
  // inheriting the verdict.  Guarded by mu.
  struct RefusalEntry {
    int strikes = 0;
    i64 first_us = 0;    // start of the current strike window
    i64 retired_us = 0;  // when the pair was retired; 0 while it is not
    std::string ca_id;   // fingerprint of the CA the client refused
    std::string why;     // what the TLS engine said, for the event detail
  };
  std::map<std::string, RefusalEntry> client_refusals;
  // Two strikes make a pattern: a cancelled preconnect happens once, a client
  // that will not accept our certificate repeats deterministically.
  static constexpr int kRefusalStrikes = 2;
  static constexpr i64 kRefusalWindowUs = 120LL * 1000 * 1000;
  static constexpr std::size_t kRefusalLimit = 512;
  // host:port -> 1 when our own TLS client can terminate the origin, 2 when it
  // cannot (TLS 1.2 only, for example) and the connection must go relayed blind.
  std::map<std::string, int> origin_tls_probe;
  // Self-test only: host:port -> verdict.  The client-facing handshake runs only
  // when the origin is believed to speak TLS, and the self-test cannot make a
  // real origin present a certificate our own probe would accept, so it pins the
  // verdict here instead of dialling anything.
  std::map<std::string, int> test_tls_ability;
  // ---- upstream keep-alive pool ------------------------------------------
  //
  // Every request used to dial the origin and run a fresh TLS handshake: two
  // round trips per request, while one page pulls dozens of resources from the
  // same host.  A connection whose response was fully framed comes back here and
  // the next request for the same host:port picks it up.  Guarded by mu.
  struct PooledOrigin {
    socket_t sock = kBadSocket;
    Tls13Secrets secrets;
    i64 idle_since = 0;
  };
  std::map<std::string, std::vector<PooledOrigin>> origin_pool;
  static constexpr std::size_t kPoolPerOrigin = 4;
  static constexpr i64 kPoolIdleUs = 20 * 1000 * 1000;  // 20 s, like a browser
  // How long a client socket that has already been answered waits for its next
  // request.  The first request gets the full I/O timeout -- a client may open a
  // socket and think about it, and that behaviour must not change -- while an
  // idle connection that has done its work is given back after this.  A browser
  // that wanted it again simply opens another one.
  static constexpr int kClientIdleMs = 5000;

  // The origin leg is either our TLS 1.3 client or the TLS 1.2 one.  Everything
  // after the handshake (framing, rewriting, pooling) does not care which, so
  // the two live behind this one call surface.
  struct OriginLink {
    Tls13Client* t13 = nullptr;
    Tls12Client* t12 = nullptr;
    const Tls13Io* io = nullptr;
    /// Which version the TLS 1.2 client should offer first.  The origin probe
    /// already found out how far down this origin goes (0x0303/0x0302/0x0301),
    /// so the real handshake does not have to walk down again.
    int version_hint = 0x0303;
    bool tls12() const { return t12 != nullptr; }
    bool connect(const std::string& host, const std::string& alpn, bool allow_unverified,
                 Tls13ClientInfo* info, std::string* error) {
      if (t12 != nullptr) {
        Tls12ClientInfo info12;
        const bool ok = t12->connect(*io, host, alpn, allow_unverified, &info12, error, version_hint);
        // The facts have to be copied even when the handshake failed: the caller
        // decides between "relay this blind" and "give up" from them, and a
        // certificate the user has not allowed must not turn into a 502 page.
        if (info != nullptr) {
          info->host = info12.host;
          info->alpn = info12.alpn;
          info->cipher_suite = info12.cipher_suite;
          info->certificate_seen = info12.certificate_seen;
          info->certificate_host_matched = info12.certificate_host_matched;
          info->certificate_dates_ok = info12.certificate_dates_ok;
          // The 1.2 client reports one flag for "the chain verified".  A
          // self-signed or incomplete chain lands in the certificate_problem
          // branch below and gets relayed blind, which is what we want.
          info->certificate_signature_verified = info12.certificate_chain_checked;
          info->certificate_subject = info12.certificate_subject;
          info->certificate_issuer = info12.certificate_issuer;
          info->server_finished_ok = info12.server_finished_ok;
          info->warning = info12.warning;
        }
        return ok;
      }
      return t13->connect(*io, host, alpn, allow_unverified, info, error);
    }
    bool read(Bytes* out, std::string* error) {
      return t12 != nullptr ? t12->read_app(*io, out, error) : t13->read_app(*io, out, error);
    }
    bool write(const Bytes& data, std::string* error) {
      return t12 != nullptr ? t12->write_app(*io, data, error) : t13->write_app(*io, data, error);
    }
    bool close_notify(std::string* error) {
      return t12 != nullptr ? t12->send_close_notify(*io, error) : t13->send_close_notify(*io, error);
    }
  };
  // ---- multi-address origin selection ------------------------------------
  //
  // host:port -> the addresses the resolver returned, and host:port -> what has
  // been measured about them.  Both are guarded by mu, but only ever read or
  // written as a copy: the measuring itself (connecting, waiting) happens
  // outside the lock.  Two threads racing on the same host may therefore lose
  // one of their measurements, which costs a probe and never a correctness.
  std::map<std::string, std::vector<OriginAddress>> origin_addresses;  std::map<std::string, OriginPicker> origin_pickers;
  // Per-application decision, rebuilt from the config on every start().
  MitmPolicy policy;
  // Optional hook: peer "127.0.0.1:53211" -> image name of the owning process.
  // The UI and the CLI install one so the per-app policy can work; without it
  // every client is anonymous and the global switch alone decides.
  std::function<std::string(const std::string& address, std::uint16_t port)> client_resolver;

  // ---- small helpers -----------------------------------------------------

  bool send_all(socket_t s, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
      const int rc = ::send(s, data.data() + sent, static_cast<int>(data.size() - sent), 0);
      if (rc <= 0) return false;
      sent += static_cast<std::size_t>(rc);
    }
    return true;
  }

  // Reads from `from` and writes to `to` until the peer closes, the timeout
  // expires or an error appears.  `counted` accumulates the transferred bytes.
  // When `first_status` is given, the status code of the first HTTP response in
  // the stream is reported through it: the proxy relays bytes verbatim, so
  // reading the head on the way past is the only honest way to tell a 404 from
  // a 200 in the event log.
  void pump(socket_t from, socket_t to, u64* counted, int* first_status = nullptr) {
    std::vector<char> buf(16384);
    std::vector<char> head;
    bool head_done = false;
    for (;;) {
      if (!running.load() && !socket_valid(listener)) break;
      if (!wait_readable(from, cfg.io_timeout_ms)) break;
      const int rc = ::recv(from, buf.data(), static_cast<int>(buf.size()), 0);
      if (rc <= 0) break;
      if (counted != nullptr) *counted += static_cast<u64>(rc);
      if (first_status != nullptr && !head_done) {
        const std::size_t room = head.size() < 512 ? 512 - head.size() : 0;
        const std::size_t take = std::min<std::size_t>(room, static_cast<std::size_t>(rc));
        head.insert(head.end(), buf.data(), buf.data() + take);
        const int code = status_from_response_head(head.data(), head.size());
        if (code > 0) {
          *first_status = code;
          head_done = true;
        } else if (head.size() >= 512 ||
                   std::search(head.begin(), head.end(), "\r\n", "\r\n" + 2) != head.end()) {
          head_done = true;  // a head that is not an HTTP response: stop looking
        }
      }
      std::size_t sent = 0;
      while (sent < static_cast<std::size_t>(rc)) {
        const int w = ::send(to, buf.data() + sent, rc - static_cast<int>(sent), 0);
        if (w <= 0) return;
        sent += static_cast<std::size_t>(w);
      }
    }
  }

  // "host:port", "[::1]:1080" or a bare host (then the default port is used).
  bool split_endpoint(const std::string& endpoint, std::string* host, std::uint16_t* port) {
    std::string text = endpoint;
    const std::size_t colon = text.rfind(':');
    if (colon == std::string::npos) {
      *host = text;
      return !host->empty();
    }
    // A bare IPv6 literal has more than one ':' and no port.
    if (text.find(':') != colon) return false;
    *host = text.substr(0, colon);
    const long value = std::strtol(text.c_str() + colon + 1, nullptr, 10);
    if (value <= 0 || value > 65535) return false;
    *port = static_cast<std::uint16_t>(value);
    return !host->empty();
  }

  // One CONNECT handshake on an already connected socket.  The upstream proxy is
  // only used to reach the origin; everything above this stays unchanged, which
  // is why chaining covers plain HTTP, tunnelled CONNECT and MITM alike.
  bool proxy_connect(socket_t s, const std::string& host, std::uint16_t port, std::string* why) {
    const std::string authority = host + ":" + std::to_string(port);
    std::string head = "CONNECT " + authority + " HTTP/1.1\r\n";
    head += "Host: " + authority + "\r\n";
    head += "Proxy-Connection: keep-alive\r\n\r\n";
    if (!send_all(s, head)) {
      *why = "the upstream proxy did not accept the CONNECT request";
      return false;
    }
    std::string got;
    // One byte at a time on purpose: a proxy answers the CONNECT with a head and
    // nothing else, and the socket is handed to the caller as a raw stream, so
    // any byte read past the blank line would be lost for good.
    char byte = 0;
    while (got.find("\r\n\r\n") == std::string::npos) {
      if (!wait_readable(s, cfg.connect_timeout_ms)) {
        *why = "the upstream proxy did not answer the CONNECT within " +
               std::to_string(cfg.connect_timeout_ms) + " ms";
        return false;
      }
      const int rc = ::recv(s, &byte, 1, 0);
      if (rc <= 0) {
        *why = "the upstream proxy closed the connection during CONNECT";
        return false;
      }
      got.push_back(byte);
      if (got.size() > 8192) {
        *why = "the upstream proxy sent an oversized CONNECT response";
        return false;
      }
    }
    const std::size_t space = got.find(' ');
    const int status = space == std::string::npos ? 0 : std::atoi(got.c_str() + space + 1);
    if (status != 200) {
      const std::size_t eol = got.find("\r\n");
      *why = "the upstream proxy refused the CONNECT (" + got.substr(0, eol) + ")";
      return false;
    }
    return true;
  }

  socket_t dial_direct(const std::string& host, std::uint16_t port, std::string* why) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* list = nullptr;
    const std::string service = std::to_string(port);
    const int gai = getaddrinfo(host.c_str(), service.c_str(), &hints, &list);
    if (gai != 0 || list == nullptr) {
      *why = "cannot resolve " + host + ": " + origin_gai_text(gai);
      return kBadSocket;
    }
    socket_t out = kBadSocket;
    std::string last = "no address";
    for (addrinfo* it = list; it != nullptr; it = it->ai_next) {
      socket_t s = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
      if (!socket_valid(s)) {
        last = "socket() failed (" + std::to_string(last_socket_error()) + ")";
        continue;
      }
      set_nonblocking(s, true);
      const int rc = ::connect(s, it->ai_addr, static_cast<int>(it->ai_addrlen));
      bool ok = rc == 0;
      if (!ok && socket_would_block()) {
        if (wait_writable(s, cfg.connect_timeout_ms)) {
          ok = socket_error_state(s) == 0;
        } else {
          last = "connect timed out after " + std::to_string(cfg.connect_timeout_ms) + " ms";
        }
      } else if (!ok) {
        last = "connect failed (" + std::to_string(last_socket_error()) + ")";
      }
      if (ok) {
        set_nonblocking(s, false);
        set_tcp_nodelay(s);
        out = s;
        break;
      }
      socket_close(s);
    }
    freeaddrinfo(list);
    if (!socket_valid(out)) *why = last;
    return out;
  }

  // ---- choosing between the addresses of one host ------------------------

  // Starts a connect without waiting for it.  Returns a socket that is still
  // connecting (kBadSocket plus a reason when the call failed outright, which is
  // a real error: no route, address family not available, ...).
  socket_t start_connect(const OriginAddress& address, std::string* why) {
    sockaddr_storage storage;
    std::memset(&storage, 0, sizeof(storage));
    std::size_t length = 0;
    if (!origin_sockaddr(address, &storage, &length)) {
      *why = "unsupported address for " + address.text;
      return kBadSocket;
    }
    socket_t s = ::socket(address.family, SOCK_STREAM, IPPROTO_TCP);
    if (!socket_valid(s)) {
      *why = "socket() failed (" + std::to_string(last_socket_error()) + ")";
      return kBadSocket;
    }
    set_nonblocking(s, true);
    const int rc = ::connect(s, reinterpret_cast<sockaddr*>(&storage), static_cast<int>(length));
    if (rc != 0 && !socket_would_block()) {
      *why = "connect(" + address.text + ") failed (" + std::to_string(last_socket_error()) + ")";
      socket_close(s);
      return kBadSocket;
    }
    return s;
  }

  // One address, waited for: how long the connect took, or why it did not work.
  socket_t dial_address(const OriginAddress& address, int timeout_ms, i64* rtt_us, std::string* why) {
    const i64 started = now_monotonic_us();
    socket_t s = start_connect(address, why);
    if (!socket_valid(s)) return kBadSocket;
    if (!wait_writable(s, timeout_ms)) {
      *why = "connect to " + address.text + " timed out after " + std::to_string(timeout_ms) + " ms";
      socket_close(s);
      return kBadSocket;
    }
    const int state = socket_error_state(s);
    if (state != 0) {
      *why = "connect to " + address.text + " failed (" + std::to_string(state) + ")";
      socket_close(s);
      return kBadSocket;
    }
    if (rtt_us != nullptr) *rtt_us = now_monotonic_us() - started;
    set_nonblocking(s, false);
    set_tcp_nodelay(s);
    return s;
  }

  OriginPicker picker_copy(const std::string& key) {
    std::lock_guard<std::mutex> lock(mu);
    const auto it = origin_pickers.find(key);
    if (it != origin_pickers.end()) return it->second;
    return OriginPicker(cfg.origin_policy,
                        cfg.origin_race < 1 ? 1u : static_cast<std::size_t>(cfg.origin_race),
                        static_cast<i64>(cfg.origin_stagger_ms) * 1000,
                        static_cast<i64>(cfg.origin_ttl_s) * 1000000,
                        60 * 1000 * 1000);
  }

  void picker_store(const std::string& key, const OriginPicker& picker) {
    std::lock_guard<std::mutex> lock(mu);
    origin_pickers[key] = picker;
  }

  std::vector<OriginAddress> address_copy(const std::string& key) {
    std::lock_guard<std::mutex> lock(mu);
    const auto it = origin_addresses.find(key);
    return it == origin_addresses.end() ? std::vector<OriginAddress>() : it->second;
  }

  // The address the picker would dial right now, "" when nothing is measured.
  std::string preferred_address(const std::string& key) {
    std::lock_guard<std::mutex> lock(mu);
    const auto it = origin_pickers.find(key);
    if (it == origin_pickers.end()) return {};
    if (it->second.policy() != OriginPolicy::Best) return {};
    return it->second.best(now_monotonic_us());
  }

  // Pool keys carry the address: a parked connection to a slow edge node is not
  // a substitute for one to the fast node, even though both answer for the name.
  static std::string pool_key_for(const std::string& host_key, const std::string& address) {
    return address.empty() ? host_key : host_key + "#" + address;
  }

  // Connects to `host`, choosing which of its addresses to use.  With `Best`
  // the first attempt goes to the address that measured fastest last time; when
  // there is no such memory (first request, stale measurement, or the winner
  // stopped answering) the candidates are raced - attempts are started a
  // stagger apart and the first one to complete wins - and the winner's round
  // trip time is remembered for the next request.  With `First` the resolver
  // order is kept and nothing is measured, which is what a skeptical user wants
  // when they would rather have predictable behaviour than a faster one.
  socket_t dial_origin(const std::string& host, std::uint16_t port, OriginAddress* chosen, i64* rtt_us, std::string* why) {
    const std::string key = host + ":" + std::to_string(static_cast<unsigned>(port));
    OriginPicker picker = picker_copy(key);
    std::vector<OriginAddress> list = address_copy(key);
    const i64 now = now_monotonic_us();
    if (list.empty() || picker.stale(now)) {
      std::string resolve_error;
      if (!origin_resolve(host, port, &list, &resolve_error) || list.empty()) {
        *why = resolve_error.empty() ? ("cannot resolve " + host) : resolve_error;
        return kBadSocket;
      }
      std::vector<std::string> texts;
      texts.reserve(list.size());
      for (const OriginAddress& address : list) texts.push_back(address.text);
      picker.set_addresses(texts);
      {
        std::lock_guard<std::mutex> lock(mu);
        ++stats.origin_resolves;
        origin_addresses[key] = list;
      }
    }

    const int timeout_ms = cfg.connect_timeout_ms;
    std::string last_error;

    if (picker.policy() == OriginPolicy::First) {
      for (const std::string& text : picker.order(now)) {
        const OriginAddress* address = find_address(list, text);
        if (address == nullptr) continue;
        i64 rtt = -1;
        std::string attempt_error;
        socket_t s = dial_address(*address, timeout_ms, &rtt, &attempt_error);
        picker.report(text, socket_valid(s), rtt, now_monotonic_us());
        if (socket_valid(s)) {
          if (chosen != nullptr) *chosen = *address;
          if (rtt_us != nullptr) *rtt_us = rtt;
          origin_trace(key, text, rtt, "resolver order");
          picker_store(key, picker);
          return s;
        }
        origin_trace(key, text, -1, "failed");
        last_error = attempt_error;
      }
      picker_store(key, picker);
      *why = last_error.empty() ? ("no address of " + host + " answered") : last_error;
      return kBadSocket;
    }

    // 1. Something has been measured already: one connection, no race.
    const std::string favourite = picker.best(now);
    if (!favourite.empty()) {
      const OriginAddress* address = find_address(list, favourite);
      if (address != nullptr) {
        i64 rtt = -1;
        std::string attempt_error;
        socket_t s = dial_address(*address, timeout_ms, &rtt, &attempt_error);
        picker.report(favourite, socket_valid(s), rtt, now_monotonic_us());
        if (socket_valid(s)) {
          if (chosen != nullptr) *chosen = *address;
          if (rtt_us != nullptr) *rtt_us = rtt;
          origin_trace(key, favourite, rtt, "remembered best");
          picker_store(key, picker);
          return s;
        }
        origin_trace(key, favourite, -1, "remembered best failed");
        {
          std::lock_guard<std::mutex> lock(mu);
          ++stats.origin_failovers;
        }
        last_error = attempt_error;
      }
    }

    // 2. Measure: start the candidates a stagger apart, first one to answer wins.
    picker.begin_race();
    {
      std::lock_guard<std::mutex> lock(mu);
      ++stats.origin_races;
    }
    std::map<socket_t, std::pair<std::string, i64>> pending;  // socket -> text, started
    socket_t winner = kBadSocket;
    std::string winner_text;
    i64 winner_rtt = -1;
    const i64 deadline = now_monotonic_us() + static_cast<i64>(timeout_ms) * 1000;
    i64 wait_us = -1;
    while (!socket_valid(winner)) {
      const i64 loop_now = now_monotonic_us();
      if (loop_now >= deadline) break;
      for (const std::string& text : picker.next_batch(loop_now, &wait_us)) {
        const OriginAddress* address = find_address(list, text);
        std::string start_error;
        socket_t s = address == nullptr ? kBadSocket : start_connect(*address, &start_error);
        if (!socket_valid(s)) {
          picker.report(text, false, -1, now_monotonic_us());
          if (!start_error.empty()) last_error = start_error;
          continue;
        }
        pending[s] = {text, now_monotonic_us()};
      }
      if (pending.empty()) break;
      int slice_ms = 50;  // poll often enough for the stagger to mean something
      if (wait_us >= 0 && wait_us / 1000 < static_cast<i64>(slice_ms)) {
        slice_ms = static_cast<int>(wait_us / 1000);
      }
      if (slice_ms < 1) slice_ms = 1;
      std::vector<socket_t> waiting;
      waiting.reserve(pending.size());
      for (const auto& kv : pending) waiting.push_back(kv.first);
      for (socket_t s : wait_writable_any(waiting, slice_ms)) {
        const auto it = pending.find(s);
        if (it == pending.end()) continue;
        const std::string text = it->second.first;
        const i64 started = it->second.second;
        pending.erase(it);
        const int state = socket_error_state(s);
        if (state != 0) {
          picker.report(text, false, -1, now_monotonic_us());
          last_error = "connect to " + text + " failed (" + std::to_string(state) + ")";
          continue;
        }
        const i64 rtt = now_monotonic_us() - started;
        picker.report(text, true, rtt, now_monotonic_us());
        {
          std::lock_guard<std::mutex> lock(mu);
          ++stats.origin_measured;
        }
        if (!socket_valid(winner)) {
          winner = s;
          winner_text = text;
          winner_rtt = rtt;
        } else {
          socket_close(s);
        }
      }
    }
    // Give the addresses that lost the race a moment to finish anyway: their
    // round trip time is worth having, because the next connection to this host
    // then goes straight to the fastest one without racing at all.  The wait is
    // bounded, and it only happens while something is still pending.
    if (!pending.empty()) {
      std::vector<socket_t> rest;
      rest.reserve(pending.size());
      for (const auto& kv : pending) rest.push_back(kv.first);
      for (socket_t s : wait_writable_any(rest, 20)) {
        const auto it = pending.find(s);
        if (it == pending.end()) continue;
        const std::string text = it->second.first;
        const i64 rtt = now_monotonic_us() - it->second.second;
        if (socket_error_state(s) == 0) {
          picker.report(text, true, rtt, now_monotonic_us());
          {
            std::lock_guard<std::mutex> lock(mu);
            ++stats.origin_measured;
          }
          origin_trace(key, text, rtt, "race runner-up");
        } else {
          picker.report(text, false, -1, now_monotonic_us());
        }
        pending.erase(it);
      }
    }
    // Losers of a race that is over: measured if they answered, closed either way.
    for (const auto& kv : pending) socket_close(kv.first);
    picker_store(key, picker);
    if (!socket_valid(winner)) {
      *why = last_error.empty() ? ("no address of " + host + " answered") : last_error;
      return kBadSocket;
    }
    set_nonblocking(winner, false);
    set_tcp_nodelay(winner);
    const OriginAddress* picked = find_address(list, winner_text);
    if (chosen != nullptr && picked != nullptr) *chosen = *picked;
    if (rtt_us != nullptr) *rtt_us = winner_rtt;
    origin_trace(key, winner_text, winner_rtt, "race winner");
    return winner;
  }

  // Either the origin (direct) or the origin reached through the configured
  // upstream proxy.  The caller cannot tell the difference, which is the point.
  // `origin` receives the address the connection really went to; it stays empty
  // when an upstream proxy is used, because then the proxy resolves the name.
  socket_t connect_upstream(const std::string& host, std::uint16_t port, OriginAddress* origin, i64* origin_rtt_us, std::string* why) {
    stage("connecting upstream");
    if (cfg.upstream_proxy.empty()) return dial_origin(host, port, origin, origin_rtt_us, why);
    std::string proxy_host;
    std::uint16_t proxy_port = 0;
    if (!split_endpoint(cfg.upstream_proxy, &proxy_host, &proxy_port) || proxy_port == 0) {
      *why = "the upstream proxy must be host:port (got '" + cfg.upstream_proxy + "')";
      return kBadSocket;
    }
    socket_t s = dial_direct(proxy_host, proxy_port, why);
    if (!socket_valid(s)) {
      *why = "the upstream proxy " + cfg.upstream_proxy + " is unreachable: " + *why;
      return kBadSocket;
    }
    std::string tunnel_error;
    if (!proxy_connect(s, host, port, &tunnel_error)) {
      socket_close(s);
      *why = "through the upstream proxy " + cfg.upstream_proxy + ": " + tunnel_error;
      return kBadSocket;
    }
    return s;
  }

  void record(const InterceptEvent& event) {
    std::lock_guard<std::mutex> lock(mu);
    if (cfg.log_limit > 0 && events.size() >= cfg.log_limit) {
      events.erase(events.begin(), events.begin() + static_cast<std::ptrdiff_t>(events.size() - cfg.log_limit + 1));
    }
    events.push_back(event);
    ++stats.requests;
    switch (event.action) {
      case InterceptAction::Block: ++stats.blocked; break;
      case InterceptAction::Modify: ++stats.modified; break;
      case InterceptAction::Redirect: ++stats.redirected; break;
      case InterceptAction::Pass: ++stats.passed; break;
      case InterceptAction::Tunnel: ++stats.tunnels; break;
      case InterceptAction::Error: ++stats.errors; break;
      case InterceptAction::Cancelled: ++stats.cancelled; break;
    }
    stats.bytes_in += event.request_bytes;
    stats.bytes_out += event.response_bytes;
    if (!event.rule.empty()) ++rule_hits[event.rule];
  }

  std::string local_response(int status, const std::string& reason, const std::string& body,
                             const std::string& extra_header, const std::string& content_type,
                             bool keep_alive = false) {
    std::string text = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    if (!extra_header.empty()) text += extra_header + "\r\n";
    text += "Content-Type: " + content_type + "\r\n";
    text += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    text += "X-Blocked-By: netcap\r\n";
    // A page netcap writes itself is framed with a Content-Length, so it can be
    // followed by another request on the same socket -- but only when the caller
    // says the connection is staying open.  A `close` here is a promise, and it
    // is kept: the callers that pass false close the socket right after.
    text += keep_alive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";
    text += body;
    return text;
  }

  // Is this request one of the picker's own routes?  If so it is answered here:
  // never forwarded upstream, never matched against the rules.  Returns true
  // when the request was ours (the caller then returns immediately).
  //
  //   /__netcap/picker.js  the picker script itself (the bootstrap pulls it in)
  //   /__netcap/ctl        "is picking on right now?" — see below
  //   /__netcap/pick       a concrete pick: writes the rule
  //
  // The first two work even while picking is off, because that is exactly how
  // the interface button reaches a page that is already open: the page keeps a
  // cheap poll running and flips into picking mode within a second or so.  They
  // are also *not* recorded as decisions — one every 1.5 s per open tab would
  // bury the table the user actually reads.
  bool handle_pick(const RequestTarget& target, socket_t client, Tls13Server* tls,
                   const Tls13Io* tls_io, InterceptEvent* event) {
    // Over HTTPS the client socket is not a socket any more — it is a TLS session,
    // so raw bytes written into it are garbage inside the tunnel: the page's poll
    // never parses an answer, picking never turns on, and the cursor never changes
    // (that was the bug behind "点了后 鼠标没变化" on HTTPS pages; the plaintext
    // path kept working, which is why the first end-to-end test missed it).
    // `tls` is null on the plaintext path.
    auto reply = [&](int status, const std::string& reason, const std::string& body,
                     const std::string& content_type) {
      if (tls != nullptr && tls_io != nullptr) {
        tls_send_local(tls, *tls_io, status, reason, body, content_type, "Cache-Control: no-store");
        // Say goodbye properly: the response is complete, and a bare TCP close
        // after a hand-built reply made curl give up with "bad function argument"
        // (43) even though the bytes were right.  Browsers are more forgiving, but
        // there is no reason to leave a truncated record sequence behind.
        std::string bye;
        tls->send_close_notify(*tls_io, &bye);
      } else {
        send_all(client, local_response(status, reason, body, "Cache-Control: no-store", content_type));
      }
      socket_close(client);
    };
    // The cosmetic engine the injected bootstrap pulls in.  Answered here, from
    // the proxy, and never forwarded upstream: it only ever exists inside a
    // document netcap rewrote, which is also why it does not need the picker
    // switch to be on (a page carrying `:has()` rules needs it either way).
    if (cosmetic_is_script_path(target.path)) {
      const std::string body = cosmetic_engine_script();
      event->action = InterceptAction::Pass;
      event->method = "GET";
      event->host = target.host;
      event->url = target.url;
      event->detail = "netcap: cosmetic engine";
      event->status = 200;
      event->response_bytes = body.size();
      reply(200, "OK", body, "application/javascript; charset=utf-8");
      record(*event);
      return true;
    }
    if (picker_is_script_path(target.path)) {
      reply(200, "OK", picker_script(), "application/javascript; charset=utf-8");
      return true;
    }
    if (picker_is_ctl_path(target.path)) {
      bool on = false;
      std::size_t count = 0;
      {
        std::lock_guard<std::mutex> lock(mu);
        on = picker;
        count = picked.size();
      }
      const std::string body = std::string("{\"picker\":") + (on ? "true" : "false") +
                               ",\"picked\":" + std::to_string(count) + "}\n";
      reply(200, "OK", body, "application/json; charset=utf-8");
      return true;
    }
    if (!picker) return false;
    if (!picker_is_pick_path(target.path)) return false;

    std::string host, selector, url;
    if (!picker_parse_pick(target.path, &host, &selector, &url)) {
      const std::string body = "{\"ok\":false,\"error\":\"unusable pick request\"}\n";
      event->action = InterceptAction::Error;
      event->host = target.host;
      event->url = target.url;
      event->detail = "element picker: the request carried no usable host/selector";
      event->status = 400;
      event->response_bytes = body.size();
      reply(400, "Bad Request", body, "application/json; charset=utf-8");
      record(*event);
      return true;
    }

    const std::string rule = picker_rule_line(host, selector);
    std::string error;
    const bool written = !rule.empty() && picker_append_rule(cfg.picker_rules, rule, url, &error);
    if (!written && error.empty()) error = "the picker has no rule file to write to";
    if (written) {
      std::lock_guard<std::mutex> lock(mu);
      picked.emplace_back(host, selector);
    }
    const std::string body =
        written ? "{\"ok\":true,\"rule\":\"" + rule + "\"}\n"
                : "{\"ok\":false,\"error\":\"" + error + "\"}\n";
    event->action = written ? InterceptAction::Pass : InterceptAction::Error;
    event->method = "GET";
    event->host = host.empty() ? target.host : host;
    event->url = url.empty() ? target.url : url;
    event->rule = rule;
    event->detail = written ? ("element picker: added " + rule)
                            : ("element picker: " + error);
    event->status = written ? 200 : 500;
    event->response_bytes = body.size();
    reply(event->status, written ? "OK" : "Internal Server Error", body,
          "application/json; charset=utf-8");
    record(*event);
    return true;
  }

  // Every document carries the bootstrap script while the proxy runs, so the
  // interface can arm picking on a page that is already open; while picking is
  // actually on it also carries the picker script, and anything already picked
  // for this host is hidden in the same response (so the element disappears on
  // the next reload instead of after a restart).
  //
  // Returns 0 when nothing was added, 1 when only the bootstrap went in, and 2
  // when the picker script or a picked hide-rule was added.
  //
  // `what` is filled in with the name of whatever went in.  The hook is a rule
  // like any other -- it rewrote the response -- and a `modify` row whose rule
  // column is empty reads as "netcap rewrote this with no rule at all", which is
  // exactly how it was reported.
  int add_picker_rewrites(const std::string& document_host, ResponseRewrite* rewrite,
                          std::string* what) {
    std::vector<std::string> selectors;
    bool active = false;
    {
      std::lock_guard<std::mutex> lock(mu);
      active = picker;
      if (active) {
        for (const auto& entry : picked) {
          if (picker_host_matches(entry.first, document_host)) selectors.push_back(entry.second);
        }
      }
    }
    rewrite->inject_script.push_back(picker_bootstrap_script());
    if (what != nullptr) *what = "netcap: element picker hook";
    if (!active) return 1;
    rewrite->inject_script.push_back(picker_script());
    if (what != nullptr) {
      // Spelled the way the picked rule is written in the list file, so the row
      // can be traced back to the line that causes it.
      *what = "netcap: element picker";
      std::size_t shown = 0;
      for (const std::string& selector : selectors) {
        *what += "  " + (document_host.empty() ? std::string("*") : document_host) + "##" + selector;
        if (++shown >= 6) break;
      }
    }
    for (const std::string& selector : selectors) {
      rewrite->inject_css.push_back(selector + "{display:none!important}");
    }
    return 2;
  }

  // The cosmetic rules no stylesheet can express: `:has()`, `:upward()`,
  // `:contains()`, `#$#selector { remove: true; }`.  They are compiled here and
  // shipped to the page as one inline bootstrap plus a `<script src>` back to
  // `/__netcap/cosmetic.js` — the same channel the picker bootstrap uses.
  //
  // Returns the number of programs handed over, 0 when this host has none.
  int add_cosmetic_programs(const std::string& document_host, ResponseRewrite* rewrite,
                            std::string* what) {
    if (rules == nullptr || !cfg.procedural_cosmetics) return 0;
    std::string programs_source;
    const std::vector<CosmeticProgram> programs =
        rules->procedural_programs(document_host, &programs_source);
    if (programs.empty()) return 0;
    rewrite->inject_script.push_back(cosmetic_bootstrap_script(cosmetic_program_json(programs)));
    if (what != nullptr) {
      // Named like every other rule that edits a response, so the `modify` row
      // points at the selector that did it.
      *what = "netcap: cosmetic engine  " + programs_source;
    }
    return static_cast<int>(programs.size());
  }

  bool read_head(socket_t client, std::string* head) {
    return read_head_within(client, head, cfg.io_timeout_ms);
  }

  // Same, with an explicit idle wait.  A connection that has already served a
  // request must not hold a thread for the whole I/O timeout while the client
  // decides whether it has anything else to ask for.
  bool read_head_within(socket_t client, std::string* head, int timeout_ms) {
    std::size_t total = 0;
    for (;;) {
      if (head->find("\r\n\r\n") != std::string::npos) return true;
      if (head->size() >= cfg.max_head_bytes) return false;
      if (!wait_readable(client, timeout_ms)) return false;
      char buf[4096];
      const int rc = ::recv(client, buf, sizeof(buf), 0);
      if (rc <= 0) return false;
      head->append(buf, static_cast<std::size_t>(rc));
      total += static_cast<std::size_t>(rc);
      if (total > cfg.max_head_bytes) return false;
    }
  }

  void handle(socket_t client, const std::string& peer) {
    ++stats.connections;
    set_socket_timeout(client, cfg.io_timeout_ms);
    set_tcp_nodelay(client);
    set_target(peer);
    // One client socket, as many requests as it wants to send on it.  It used to
    // be exactly one: the second request on the same connection was answered by
    // closing the socket, and since the response header did not say so, the
    // client read that as "connection aborted" ([WinError 10053] on Windows) --
    // and every resource paid another TCP connect, which under `--mitm` also
    // means another TLS handshake.  The loop hands the socket back only when one
    // of the two sides is finished with it.  `carry` holds bytes of the *next*
    // request that arrived together with the one being served (pipelining).
    std::string carry;
    bool first = true;
    while (handle_request(client, peer, &carry, first)) first = false;
  }

  // Serves one request on `client`; returns true when the connection may carry
  // another one.  Every path that returns false has already closed the socket
  // (that is this file's convention: the code that ends the request owns the
  // close), so nobody may close it twice.
  bool handle_request(socket_t client, const std::string& peer, std::string* carry, bool first) {
    stage("reading the request head");
    std::string head = *carry;
    carry->clear();
    InterceptEvent event;
    event.ts_us = now_unix_us();
    event.client = peer;
    if (head.find("\r\n\r\n") == std::string::npos &&
        !read_head_within(client, &head, first ? cfg.io_timeout_ms : kClientIdleMs)) {
      // An idle keep-alive connection is not a request and not a failure: the
      // client let it go, so it is closed without a word.  A client that sent
      // half a head and then went quiet *is* malformed, and that is answered.
      if (first || !head.empty()) {
        event.action = InterceptAction::Error;
        event.detail = "no complete request head";
        send_all(client, local_response(400, "Bad Request", "netcap: malformed request\n", "", "text/plain"));
        event.status = 400;
        record(event);
      }
      socket_close(client);
      return false;
    }

    const std::size_t end = head.find("\r\n\r\n");
    std::string header_text = head.substr(0, end + 2);
    event.request_bytes = end + 4;

    RequestHead req;
    std::string why;
    if (!parse_head(header_text, &req, &why)) {
      event.action = InterceptAction::Error;
      event.detail = why;
      send_all(client, local_response(400, "Bad Request", "netcap: " + why + "\n", "", "text/plain"));
      event.status = 400;
      record(event);
      socket_close(client);
      return false;
    }
    // Whether this socket stays open after the answer.  `parse_head` already
    // knows: HTTP/1.1 keeps it unless `Connection: close` says otherwise,
    // HTTP/1.0 has the opposite default, and `Proxy-Connection` wins over both.
    const bool client_keep_alive = req.keep_alive;
    event.method = req.method;
    event.host = req.host;

    const RequestTarget target = parse_request_target(req.method, req.target, req.host);
    event.url = target.url;
    if (event.host.empty()) event.host = target.host;

    // The picker script talks to us through the page's own origin; answer it
    // here so it never reaches the rule engine or the network.
    if (handle_pick(target, client, nullptr, nullptr, &event)) return false;

    // A request whose bytes end at the head is one netcap can answer itself (a
    // block page, a redirect) and still leave the connection at a message
    // boundary: nothing of the client's is still in flight, so the next request
    // starts exactly where this head ended.  Without that check a blocked POST
    // would have its own body read as the next request head.
    const bool bodyless = !req.chunked_body && req.find("content-length") == nullptr &&
                          !wants_continue(req);
    const bool keep_open = client_keep_alive && bodyless;

    // Who is asking?  Every row in the UI carries this, and the per-application
    // MITM policy needs it for CONNECT.  The endpoint table does not care which
    // method arrived, so it is resolved once here: doing it only for CONNECT left
    // the `应用` column empty for every plain-HTTP request.
    std::string client_proc;
    {
      const std::size_t colon = peer.rfind(':');
      if (client_resolver && colon != std::string::npos) {
        const std::string address = peer.substr(0, colon);
        const std::uint16_t peer_port =
            static_cast<std::uint16_t>(std::strtoul(peer.c_str() + colon + 1, nullptr, 10));
        client_proc = client_resolver(address, peer_port);
      }
      event.client_proc = client_proc;
    }

    // ---- decide ----------------------------------------------------------
    RuleDecision decision;
    bool have_decision = false;
    RuleRequest request;  // kept alive: the response rewrite below needs it too
    bool have_request = false;
    if (rules != nullptr) {
      const ResourceType type = resource_type_from_path(target.path);
      // Which page asked.  `$third-party`, `$first-party` and `$domain=` read
      // this, and it used to be hard-coded empty here, so in proxy mode those
      // rules could not match anything at all.
      request = rule_request_from_url(target.url, document_host_from_request(req), type);
      request.host = target.host.empty() ? request.host : target.host;
      decision = rules->decide(request);
      have_decision = true;
      have_request = true;
    }

    if (have_decision && decision.action == RuleAction::Block) {
      event.action = InterceptAction::Block;
      event.rule = decision.rule != nullptr ? decision.rule->raw : std::string();
      const bool document = decision.rule == nullptr || decision.rule->types.empty() ||
                            std::find(decision.rule->types.begin(), decision.rule->types.end(),
                                      ResourceType::Document) != decision.rule->types.end();
      if (document) {
        std::string body = cfg.stub_body;
        if (body.empty()) {
          body = "<!doctype html><meta charset=\"utf-8\"><title>blocked by netcap</title>"
                 "<h1>Blocked by netcap</h1><p>" + target.url + "</p>";
          if (decision.rule != nullptr) body += "<pre>" + decision.rule->raw + "</pre>";
        }
        const std::string response =
            local_response(403, "Forbidden", body, "", "text/html; charset=utf-8", keep_open);
        send_all(client, response);
        event.status = 403;
        event.response_bytes = response.size();
      } else {
        const std::string response =
            local_response(204, "No Content", "", "", "text/plain", keep_open);
        send_all(client, response);
        event.status = 204;
        event.response_bytes = response.size();
      }
      record(event);
      // A page netcap wrote itself is framed with a Content-Length, so the
      // connection can carry the next request: a blocked image no longer costs
      // the client a new TCP connect (and, under `--mitm`, a new handshake).
      if (keep_open) {
        // Whatever followed this head is the next request, already in hand.
        if (end + 4 < head.size()) *carry = head.substr(end + 4);
        return true;
      }
      socket_close(client);
      return false;
    }

    if (have_decision && decision.action == RuleAction::Redirect && !decision.value.empty()) {
      std::string location = decision.value;
      if (location.find("://") == std::string::npos && location[0] != '/') location = "data:,";
      const std::string response =
          local_response(302, "Found", "", "Location: " + location, "text/plain", keep_open);
      send_all(client, response);
      event.action = InterceptAction::Redirect;
      event.rule = decision.rule != nullptr ? decision.rule->raw : std::string();
      event.detail = "-> " + location;
      event.status = 302;
      event.response_bytes = response.size();
      record(event);
      if (keep_open) {
        if (end + 4 < head.size()) *carry = head.substr(end + 4);
        return true;
      }
      socket_close(client);
      return false;
    }

    // ---- CONNECT ----------------------------------------------------------
    if (lowercase(req.method) == "connect") {
      // `client_proc` was resolved above, before the method was even known: the
      // per-application policy needs it to decide whether this tunnel is
      // decrypted, and the event has carried it since.
      const bool policy_wants = policy.wants(client_proc);
      std::string refusal_why;
      const bool retired = policy_wants && !cfg.mitm_strict &&
                           mitm_retired(client_proc, target.host, &refusal_why);
      if (policy_wants && !retired) {
        // Terminate the tunnel ourselves so the rule engine sees the full URL.
        // The decrypted connection has its own request loop; it closes the
        // socket when it is done with it.
        handle_mitm(client, peer, target.host, target.port, client_proc);
        return false;
      }
      const bool policy_says_no = policy.global_on || !policy.only.empty();
      event.client_proc = client_proc;
      event.mitm = policy_says_no ? "skip" : "off";
      if (retired) {
        // Decrypting again would only fail again: this application showed it
        // cannot verify our leaf, and while netcap is the system proxy that is a
        // broken application rather than a missing filter.
        event.detail = "this application refused netcap's certificate for this host name (" +
                       refusal_why + "); tunnelled without decryption so it keeps working";
      }
      if (policy_says_no || !client_proc.empty()) {
        std::lock_guard<std::mutex> lock(mu);
        ++stats.mitm_skipped;
      }
      OriginAddress origin;
      i64 origin_rtt = -1;
      socket_t upstream = connect_upstream(target.host, target.port, &origin, &origin_rtt, &why);
      event.origin_ip = origin.text;
      event.origin_rtt_us = origin_rtt;
      if (!socket_valid(upstream)) {
        event.action = InterceptAction::Error;
        event.detail = why;
        send_all(client, local_response(502, "Bad Gateway", "netcap: " + why + "\n", "", "text/plain"));
        event.status = 502;
        record(event);
        socket_close(client);
        return false;
      }
      relay_blind(client, upstream, &event);
      return false;
    }

    // ---- plain HTTP: rewrite the target when the rules ask for it ---------
    std::string path = target.path;
    if (have_decision && decision.action == RuleAction::Modify) {
      std::string spec = decision.value.empty() ? std::string("*") : decision.value;
      if (strip_query_parameters(&path, spec)) {
        event.action = InterceptAction::Modify;
        event.rule = decision.rule != nullptr ? decision.rule->raw : std::string();
        event.detail = "removed " + (spec == "*" ? std::string("tracking parameters") : spec);
      }
    }

    // A client that waits for `100 Continue` sends the head and then nothing
    // until somebody answers (Chromium does this for some POSTs).  Answering it
    // here, and dropping the header before the origin sees it, is what keeps
    // those requests from stalling until the app gives up and retries.
    const bool expects_continue = wants_continue(req);
    if (expects_continue) {
      const std::string go = "HTTP/1.1 100 Continue\r\n\r\n";
      send_all(client, go);
    }

    // A body is read completely before it is forwarded — whether it was sized
    // with Content-Length or streamed as chunked.  A chunked request carries no
    // Content-Length, so it has to be handled outside that branch: otherwise the
    // head went to the origin with `Transfer-Encoding: chunked` and no body, the
    // origin waited, and the whole thing ended as a 502 the client could only
    // answer by retrying.
    std::string body;
    if (req.chunked_body) {
      body = head.substr(end + 4);
      while (!chunked_complete(body)) {
        if (body.size() > kMaxRequestBody) {
          const std::string response = local_response(
              413, "Payload Too Large", "netcap: request body too large to relay\n", "", "text/plain");
          send_all(client, response);
          event.action = InterceptAction::Error;
          event.detail = "a chunked request body of more than " + std::to_string(kMaxRequestBody) +
                         " bytes is refused";
          event.status = 413;
          record(event);
          socket_close(client);
          return false;
        }
        if (!wait_readable(client, cfg.io_timeout_ms)) break;
        char buf[4096];
        const int rc = ::recv(client, buf, sizeof(buf), 0);
        if (rc <= 0) break;
        body.append(buf, static_cast<std::size_t>(rc));
      }
      event.request_bytes += body.size();
    } else if (const std::string* length = req.find("content-length")) {
      const std::size_t want = static_cast<std::size_t>(std::strtoull(length->c_str(), nullptr, 10));
      if (want > 0) {
        if (want > kMaxRequestBody) {
          const std::string response =
              local_response(413, "Payload Too Large", "netcap: request body too large to relay\n", "",
                             "text/plain");
          send_all(client, response);
          event.action = InterceptAction::Error;
          event.detail = "a request body of " + std::to_string(want) + " bytes is refused";
          event.status = 413;
          record(event);
          socket_close(client);
          return false;
        }
        std::string have = head.substr(end + 4);
        while (have.size() < want) {
          if (!wait_readable(client, cfg.io_timeout_ms)) break;
          char buf[4096];
          const int rc = ::recv(client, buf, sizeof(buf), 0);
          if (rc <= 0) break;
          have.append(buf, static_cast<std::size_t>(rc));
        }
        body = have;
        event.request_bytes += body.size();
      }
    }

    // Plain HTTP gets the parked-connection treatment the decrypted path has had
    // for a while: the request asks the origin to keep the socket open, the relay
    // below frames the response so it still knows where the message ends, and the
    // socket goes back to the pool instead of being thrown away.  The key carries
    // a `plain|` prefix so a socket with no traffic secrets attached can never be
    // handed to the decryption path (or the other way round): both pools are one
    // map, and this prefix is the only thing keeping them apart.
    const std::string host_key =
        target.host + ":" + std::to_string(static_cast<unsigned>(target.port));
    const std::string plain_key = "plain|" + pool_key_for(host_key, preferred_address(host_key));
    OriginAddress origin;
    i64 origin_rtt = -1;
    socket_t upstream = pool_take(plain_key, nullptr);
    const bool pooled = socket_valid(upstream);
    if (!pooled) {
      upstream = connect_upstream(target.host, target.port, &origin, &origin_rtt, &why);
      event.origin_ip = origin.text;
      event.origin_rtt_us = origin_rtt;
      if (!socket_valid(upstream)) {
        event.action = InterceptAction::Error;
        event.detail = why;
        send_all(client, local_response(502, "Bad Gateway", "netcap: " + why + "\n", "", "text/plain"));
        event.status = 502;
        record(event);
        socket_close(client);
        return false;
      }
    }
    set_socket_timeout(upstream, cfg.io_timeout_ms);

    // Third-party cookies: a request whose site differs from the page that
    // asked for it does not get to carry one.  Referer/Origin is the only hint
    // a proxy has, so an unknown document host means "send it through".
    std::string outgoing_head = head_to_string(req, path, client_keep_alive);
    // We already answered `Expect: 100-continue` above, so the origin must not
    // see the header: it would wait for a body it was never told to expect while
    // the client waits for a 100 that is not coming.
    if (expects_continue) strip_header(&outgoing_head, "expect");
    if (cfg.block_third_party_cookies) {
      const std::string document = request_document_host(outgoing_head);
      if (!document.empty() && !RuleRequest::same_site(target.host, document)) {
        if (strip_header(&outgoing_head, "cookie") > 0) {
          event.action = InterceptAction::Modify;
          // The switch, not a list rule, made this edit -- and it is still a rule,
          // so it gets named instead of leaving the rule column empty.
          if (event.rule.empty()) event.rule = "netcap: third-party cookies";
          event.detail = "third-party cookie (" + document + ")";
        }
      }
    }
    const std::string outgoing = outgoing_head + body;
    bool sent = send_all(upstream, outgoing);
    if (!sent && pooled) {
      // A parked socket can only be reused until the first byte is written: the
      // origin may have closed it while it sat idle, and a FIN that has not
      // arrived yet is invisible to the pool's liveness check.  Nothing reached
      // the origin, so the request is simply sent again on a fresh connection.
      socket_close(upstream);
      upstream = connect_upstream(target.host, target.port, &origin, &origin_rtt, &why);
      event.origin_ip = origin.text;
      event.origin_rtt_us = origin_rtt;
      if (socket_valid(upstream)) sent = send_all(upstream, outgoing);
    }
    if (!sent) {
      event.action = InterceptAction::Error;
      event.detail = "the upstream connection closed before the request was sent";
      event.status = 502;
      record(event);
      socket_close(upstream);
      socket_close(client);
      return false;
    }

    // A response can only be rewritten once it has been read as a whole, so ask
    // the rules first: with no rewrite to apply the bytes are relayed straight
    // through, exactly as before.
    // Did this request already get edited on its way out (a stripped tracking
    // parameter, a dropped cookie)?  Only then may the row stay a Modify when
    // the response turns out to be untouchable -- a planned cosmetic rewrite
    // that could not be applied is a Pass, not an edit.
    const bool request_edited = event.action == InterceptAction::Modify;
    ResponseRewrite rewrite;
    bool rewrite_wanted = have_request && rules != nullptr &&
                          rules->collect_response_rewrite(request, &rewrite) && !rewrite.empty();
    // Cosmetic rules (`##selector`) hide elements instead of blocking requests.
    // Only a document can carry a <style>, so the selector list for this host is
    // handed to the same rewriting pass that `$css` uses; `apply_response_rewrite`
    // drops it again for anything that is not text.
    if (have_request && rules != nullptr) {
      std::string cosmetic_source;
      const std::string cosmetic =
          rules->cosmetic_css(request.host, &cosmetic_source,
                              request_wants_generic_cosmetics(head));
      if (!cosmetic.empty()) {
        rewrite.inject_css.push_back(cosmetic);
        rewrite_wanted = true;
        if (rewrite.source.empty()) rewrite.source = cosmetic_source;
        ++rewrite.source_count;
      }
    }
    // Element picker: the bootstrap script rides along in every document (that
    // is the channel the interface button uses on already-open pages) and, while
    // picking is on, the picker script plus whatever was already picked on this
    // host.  The rule itself is durable (appended to the list file).
    if (have_request) {
      std::string picker_what;
      const int picker_added = add_picker_rewrites(request.host, &rewrite, &picker_what);
      if (picker_added > 0) {
        rewrite_wanted = true;
        // Whatever went in is named, the bootstrap included: it *is* the rule
        // that edited this response, and an unnamed edit is what used to make a
        // `modify` row look like it fired without any rule.
        if (rewrite.source.empty()) rewrite.source = picker_what;
        ++rewrite.source_count;
      }
    }
    // Procedural cosmetics: a selector with `:has()`/`:upward()` or a
    // `{ remove: true; }` cannot be a stylesheet, so the page's own engine runs
    // it.  One inline bootstrap pulls the engine script from this proxy.
    if (have_request) {
      std::string cosmetic_js_what;
      const int cosmetic_added = add_cosmetic_programs(request.host, &rewrite, &cosmetic_js_what);
      if (cosmetic_added > 0) {
        rewrite_wanted = true;
        if (rewrite.source.empty()) rewrite.source = cosmetic_js_what;
        ++rewrite.source_count;
      }
    }
    // Which rule asked for this rewrite.  It is written into the event only in
    // the Modify branch below, so a Pass row never claims a rule it did not use.
    const std::string rewrite_rule =
        rewrite.source.empty()
            ? std::string()
            : (rewrite.source_count > 1
                   ? rewrite.source + "  (+" + std::to_string(rewrite.source_count - 1) + ")"
                   : rewrite.source);

    u64 relayed = 0;
    int upstream_status = 0;
    // Whether either side may be used again.  The two are independent: an origin
    // that closes its socket after a perfectly framed response is no reason to
    // hang up on the client.
    bool origin_reusable = false;
    bool client_reusable = false;
    if (!rewrite_wanted) {
      const RelayEnd end = relay_framed_plain(upstream, client, req.method, client_keep_alive,
                                              &upstream_status, &relayed, &origin_reusable,
                                              &client_reusable, &why);
      event.response_bytes += relayed;
      // 200 is only the fallback: whatever the origin answered is what the client
      // got, and the event log should say so.
      event.status = upstream_status > 0 ? upstream_status : 200;
      if (event.action != InterceptAction::Modify) event.action = InterceptAction::Pass;
      if (end == RelayEnd::ClientGone) {
        event.action = InterceptAction::Cancelled;
        event.detail += event.detail.empty() ? "the client closed before the response was sent"
                                             : "; the client closed before the response was sent";
      } else if (upstream_status == 0) {
        event.action = InterceptAction::Error;
        event.detail = why.empty() ? std::string("no response head arrived") : why;
        event.status = 502;
      }
    } else {
      const std::function<int(std::string*)> pull = [&](std::string* into) -> int {
        if (!wait_readable(upstream, cfg.io_timeout_ms)) return 0;
        char buf[16384];
        const int got = ::recv(upstream, buf, sizeof(buf), 0);
        if (got <= 0) return -1;
        into->append(buf, static_cast<std::size_t>(got));
        return got;
      };
      std::string head, body, read_why;
      bool complete = false;
      int origin_status = 0;
      if (!read_full_response(pull, req.method, &head, &body, &origin_status, &complete, &read_why)) {
        event.action = InterceptAction::Error;
        event.detail = read_why;
        event.status = 502;
        send_all(client, local_response(502, "Bad Gateway", "netcap: " + read_why + "\n", "", "text/plain"));
        record(event);
        socket_close(upstream);
        socket_close(client);
        return false;
      }
      ResponseHead head_parsed;
      ResponseRewriteReport report;
      std::string rewrite_why;
      std::string outgoing;
      // HTTP/3 is invisible to an HTTP proxy, so drop the Alt-Svc advertisement.
      // The head goes out as it arrived: QUIC stays available to the browser,
      // and an unwanted QUIC connection is stopped at its Initial packet.
      if (complete && parse_response_head(head, &head_parsed, &rewrite_why) &&
          apply_response_rewrite(rewrite, &head_parsed, &body, &report, &rewrite_why)) {
        outgoing = head_parsed.serialize() + body;
        event.status = head_parsed.status;
        // Only a response whose bytes really moved is a Modify: a cosmetic rule
        // that matched a JSON reply, or a $replace that never hit, leaves the
        // event log claiming netcap edited something it only looked at.
        if (report.changed) {
          event.action = InterceptAction::Modify;
          // Named, and never dropped: the request may already have named one rule
          // (a `$removeparam`, a stripped cookie) and the response edit is a
          // second one, so the row says both instead of silently keeping the first.
          if (!rewrite_rule.empty()) {
            event.rule = event.rule.empty() ? rewrite_rule : event.rule + "  + " + rewrite_rule;
          }
        } else if (!request_edited) {
          // Nothing moved: the rule asked for a <style> we could not inject
          // (a Brotli body, a JSON reply) or a $replace that never matched.
          event.action = InterceptAction::Pass;
        }
        const std::string text = report.describe();
        event.detail = event.detail.empty() ? text : event.detail + "; " + text;
      } else {
        // Anything that could not be rewritten goes out exactly as it arrived.
        outgoing = head + body;
        event.status = origin_status > 0 ? origin_status : 200;
        event.action = request_edited ? InterceptAction::Modify : InterceptAction::Pass;
        const std::string text =
            !rewrite_why.empty() ? rewrite_why
                                 : (complete ? std::string()
                                             : std::string("the response body was not fully framed"));
        if (!text.empty()) event.detail = event.detail.empty() ? text : event.detail + "; " + text;
      }
      // A response the origin framed by closing the connection can never be
      // handed to a client that keeps it: the client would read whatever arrives
      // next as part of this message.  Neither can a body that was cut short
      // (larger than the relay is willing to buffer): the client is still waiting
      // for the bytes its Content-Length promised, so the connection has to end.
      // This is the honest half of the keep-alive work, and the half that was
      // missing: the proxy used to close a socket its own head advertised as
      // reusable, and the client read the close as an aborted request.
      const bool reusable_head = response_framing_reusable(req.method, head);
      const bool framed_ok = reusable_head && complete;
      if (is_upgrade_head(head)) {
        // A protocol switch is not an HTTP message any more (a WebSocket, say),
        // so nothing here may be reframed and the connection ends with it.
        origin_reusable = false;
        client_reusable = false;
      } else if (framed_ok) {
        // The whole message is in hand, so this side is the one that knows
        // whether the connection can go on -- and it says so, instead of leaving
        // the client to guess from an origin header that described a socket
        // netcap was about to close.
        if (client_keep_alive) force_connection_keep_alive(&outgoing);
        else force_connection_close(&outgoing);
        origin_reusable = true;
        client_reusable = client_keep_alive;
      } else {
        force_connection_close(&outgoing);
        origin_reusable = false;
        client_reusable = false;
      }
      relayed = outgoing.size();
      event.response_bytes += relayed;
      if (!send_all(client, outgoing)) {
        event.action = InterceptAction::Cancelled;
        event.detail += event.detail.empty() ? "the client closed before the response was sent"
                                             : "; the client closed before the response was sent";
      }
    }
    record(event);
    if (origin_reusable) {
      pool_put(plain_key, upstream, Tls13Secrets());
    } else {
      socket_close(upstream);
    }
    if (!client_reusable) {
      socket_close(client);
      return false;
    }
    // Bytes of a request that was already pipelined behind this one: the next
    // turn reads them instead of going back to the socket.  A chunked request is
    // the exception -- the tail of its body cannot be told apart from what
    // followed it -- so nothing is carried over and a client that pipelines
    // behind one waits for its answer, exactly as it did before.
    if (!req.chunked_body) {
      const std::size_t consumed = end + 4 + body.size();
      if (consumed < head.size()) *carry = head.substr(consumed);
    }
    return true;
  }

  // ------------------------------------------------------------ MITM mode

  std::shared_ptr<LeafEntry> leaf_for(const std::string& host, std::string* why) {
    {
      std::lock_guard<std::mutex> lock(mu);
      const auto it = leaf_cache.find(host);
      if (it != leaf_cache.end()) return it->second;
    }
    auto entry = std::make_shared<LeafEntry>();
    LeafRequest req;
    req.host = host;
    if (!leaf_issue(ca, req, &entry->key, &entry->cert, why)) return nullptr;
    {
      std::lock_guard<std::mutex> lock(mu);
      leaf_cache[host] = entry;
    }
    return entry;
  }

  static std::string refusal_key(const std::string& proc, const std::string& host) {
    return (proc.empty() ? std::string("<unattributed>") : proc) + "|" + host;
  }

  std::string ca_identity() const { return ca.cert.sha256_hex(); }

  // "This client hangs up on our certificate" is worth acting on, so remember
  // it.  Returns true when that retires the pair from decryption, which is the
  // one case the caller reports in the event table: an application that cannot
  // be decrypted is a fact the user has to be able to see, because content
  // filtering stops applying to it.  `definitive` is set when the client said
  // so out loud (an alert instead of a Finished), which needs no second strike.
  bool note_client_refusal(const std::string& proc, const std::string& host, const std::string& why,
                           bool definitive) {
    const std::string key = refusal_key(proc, host);
    const std::string ca_id = ca_identity();
    const i64 now = now_unix_us();
    std::lock_guard<std::mutex> lock(mu);
    RefusalEntry& entry = client_refusals[key];
    if (entry.first_us == 0 || now - entry.first_us > kRefusalWindowUs) {
      entry.first_us = now;
      entry.strikes = 0;
    }
    entry.strikes += 1;
    entry.ca_id = ca_id;
    entry.why = why;
    if (entry.retired_us != 0) return false;  // already retired: nothing new to say
    if (!definitive && entry.strikes < kRefusalStrikes) return false;
    entry.retired_us = now;
    ++stats.mitm_client_refusals;
    prune_refusals_locked(now);
    return true;
  }

  bool mitm_retired(const std::string& proc, const std::string& host, std::string* why) const {
    const std::string ca_id = ca_identity();
    std::lock_guard<std::mutex> lock(mu);
    const auto it = client_refusals.find(refusal_key(proc, host));
    if (it == client_refusals.end() || it->second.retired_us == 0) return false;
    if (it->second.ca_id != ca_id) return false;  // a new CA gets a fresh try
    if (why != nullptr) *why = it->second.why;
    return true;
  }

  // Bounded memory: first forget strikes for pairs that never repeated, then the
  // oldest retirements.  The caller holds mu.
  void prune_refusals_locked(i64 now) {
    if (client_refusals.size() <= kRefusalLimit) return;
    for (auto it = client_refusals.begin(); it != client_refusals.end();) {
      const bool stale = it->second.retired_us == 0 && now - it->second.first_us > kRefusalWindowUs;
      if (stale) {
        it = client_refusals.erase(it);
      } else {
        ++it;
      }
    }
    while (client_refusals.size() > kRefusalLimit) {
      auto oldest = client_refusals.begin();
      for (auto it = client_refusals.begin(); it != client_refusals.end(); ++it) {
        if (it->second.retired_us < oldest->second.retired_us) oldest = it;
      }
      client_refusals.erase(oldest);
    }
  }

  // A Tls13Io over a plain socket: the TLS engines ask for exact lengths.
  Tls13Io io_for(socket_t s) {
    Tls13Io io;
    io.read = [s](u8* buf, std::size_t len, std::size_t* got) {
      std::size_t n = 0;
      while (n < len) {
        const int rc = ::recv(s, reinterpret_cast<char*>(buf) + n, static_cast<int>(len - n), 0);
        if (rc <= 0) break;
        n += static_cast<std::size_t>(rc);
      }
      *got = n;
      return n == len;
    };
    io.write = [this, s](const u8* data, std::size_t len) {
      return send_all(s, std::string(reinterpret_cast<const char*>(data), len));
    };
    return io;
  }

  bool tls_read_until(Tls13Server* server, const Tls13Io& io, std::string* buf,
                      const std::string& needle, std::size_t max, std::string* why) {
    while (buf->find(needle) == std::string::npos) {
      if (buf->size() >= max) {
        *why = "the request head is larger than " + std::to_string(max) + " bytes";
        return false;
      }
      Bytes chunk;
      if (!server->read_app(io, &chunk, why)) return false;
      buf->append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    }
    return true;
  }

  bool tls_read_exact(Tls13Server* server, const Tls13Io& io, std::string* buf, std::size_t want,
                      std::string* why) {
    while (buf->size() < want) {
      Bytes chunk;
      if (!server->read_app(io, &chunk, why)) return false;
      buf->append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    }
    return true;
  }

  bool tls_send_local(Tls13Server* server, const Tls13Io& io, int status, const std::string& reason,
                      const std::string& body, const std::string& content_type,
                      const std::string& extra_header = std::string()) {
    std::string why;
    // Build the page once and keep it alive: `Bytes(first.begin(), second.end())`
    // with two separate temporaries would hand the vector two unrelated pointers,
    // and a reversed pair makes the vector throw `length_error`.  That happened
    // on the 502 path (the origin could not be verified) and killed the whole
    // proxy while the system pointed at it.
    const std::string response = local_response(status, reason, body, extra_header, content_type);
    const Bytes payload(response.begin(), response.end());
    return server->write_app(io, payload, &why);
  }

  // netcap's own word about the connection it is about to use.  The two helpers
  // sit together because they are opposites, and every exit from the MITM loop
  // now picks one explicitly: `Connection: close` is a promise to close, so
  // whoever writes it must also close the socket, and a connection that is put
  // back in a pool must be advertised as reusable.
  void force_connection_close(std::string* head) {
    strip_header(head, "connection");
    strip_header(head, "proxy-connection");
    const std::size_t at = head->find("\r\n\r\n");
    if (at == std::string::npos) return;
    head->insert(at + 2, "Connection: close\r\n");
  }

  // The man-in-the-middle path asks the origin to keep the connection open and
  // then frames the response itself (relay_framed_response below), so the
  // connection can go back to the pool instead of being thrown away.
  void force_connection_keep_alive(std::string* head) {
    strip_header(head, "connection");
    strip_header(head, "proxy-connection");
    const std::size_t at = head->find("\r\n\r\n");
    if (at == std::string::npos) return;
    head->insert(at + 2, "Connection: keep-alive\r\n");
  }

  // A blind tunnel: the client's own TLS session runs end to end to the real
  // origin through this pair of sockets, so nothing here can be inspected.  It
  // is what a tunnel gets when the per-application policy says "do not decrypt
  // this program", and also the fallback for an origin whose TLS we cannot
  // terminate (a TLS-1.2-only server answers our ClientHello with a
  // protocol_version alert, and pretending to be it would answer every request
  // with 502).  `established` is true when the caller already sent the 200.
  void relay_blind(socket_t client, socket_t upstream, InterceptEvent* event, bool established = false) {
    const std::string ok = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: netcap\r\n\r\n";
    if (!established && !send_all(client, ok)) {
      socket_close(upstream);
      socket_close(client);
      return;
    }
    event->action = InterceptAction::Tunnel;
    event->status = 200;
    event->response_bytes = ok.size();
    std::thread up_to_down([this, upstream, client]() {
      u64 moved = 0;
      pump(upstream, client, &moved);
      std::lock_guard<std::mutex> lock(mu);
      stats.bytes_out += moved;
    });
    u64 sent = 0;
    pump(client, upstream, &sent);
    {
      std::lock_guard<std::mutex> lock(mu);
      stats.bytes_in += sent;
    }
    socket_close(client);
    socket_close(upstream);
    up_to_down.join();
    record(*event);
  }

  // How can our TLS client talk to this origin?  Asked once per host and
  // remembered: 1 = our TLS 1.3 client terminates it, 0x0303/0x0302/0x0301 = only
  // that version of the 1.2 family works so the TLS 1.2 client must be pointed
  // at it, 0 = none of them, so the connection has to be relayed blind.
  static std::string tls_version_text(int v) {
    if (v == 0x0303) return "TLS 1.2";
    if (v == 0x0302) return "TLS 1.1";
    if (v == 0x0301) return "TLS 1.0";
    return "TLS 1.3";
  }
  int origin_tls_ability(const std::string& host, std::uint16_t port, std::string* why) {
    const std::string key = host + ":" + std::to_string(static_cast<unsigned>(port));
    {
      std::lock_guard<std::mutex> lock(mu);
      const auto pinned = test_tls_ability.find(key);
      if (pinned != test_tls_ability.end()) {
        if (why != nullptr) {
          *why = pinned->second == 0
                     ? "the origin does not speak TLS (pinned by the self-test)"
                     : "the origin speaks " + tls_version_text(pinned->second) +
                           " (pinned by the self-test)";
        }
        return pinned->second;
      }
    }
    {
      std::lock_guard<std::mutex> lock(mu);
      const auto it = origin_tls_probe.find(key);
      if (it != origin_tls_probe.end()) {
        if (why != nullptr) {
          *why = it->second == 0
                     ? "this origin already refused our TLS handshake"
                     : "this origin speaks " + tls_version_text(it->second);
        }
        return it->second;
      }
    }
    auto probe_with = [&](int version, std::string* tls_why) -> bool {
      OriginAddress where;
      i64 rtt = -1;
      std::string dial_why;
      socket_t sock = connect_upstream(host, port, &where, &rtt, &dial_why);
      if (!socket_valid(sock)) {
        // A network problem is not a verdict about the origin: do not cache it.
        if (tls_why != nullptr) *tls_why = "the origin could not be reached: " + dial_why;
        return false;
      }
      set_socket_timeout(sock, cfg.io_timeout_ms);
      const Tls13Io io = io_for(sock);
      bool ok = false;
      if (version != 1) {
        Tls12Client probe12;
        Tls12ClientInfo info12;
        ok = probe12.connect(io, host, "http/1.1", true, &info12, tls_why, version);
        if (ok && tls_why != nullptr) {
          *tls_why = "this origin speaks " + tls_version_text(version) + " (" +
                     tls12_suite_name(info12.cipher_suite) + ")";
        }
      } else {
        Tls13Client probe13;
        Tls13ClientInfo info13;
        ok = probe13.connect(io, host, "http/1.1", true, &info13, tls_why);
      }
      socket_close(sock);
      return ok;
    };
    std::string why13, why12;
    int ability = probe_with(1, &why13) ? 1 : 0;
    if (ability == 0) {
      // Walk down the 1.2 family: a server that only does 1.1 or 1.0 is rare but
      // it exists, and one extra handshake only happens when 1.2 already failed.
      for (int version : {0x0303, 0x0302, 0x0301}) {
        if (probe_with(version, &why12)) {
          ability = version;
          break;
        }
      }
    }
    if (why != nullptr) {
      if (ability == 0) {
        *why = "TLS 1.3 probe: " + why13 + "; TLS 1.2 probe: " + why12;
      } else if (ability == 1) {
        *why = why13;
      } else {
        *why = why12;
      }
    }
    {
      std::lock_guard<std::mutex> lock(mu);
      origin_tls_probe[key] = ability;
    }
    return ability;
  }
  void handle_mitm(socket_t client, const std::string& peer, const std::string& host,
                   std::uint16_t port, const std::string& client_proc) {
    InterceptEvent event;
    event.ts_us = now_unix_us();
    event.client = peer;
    event.host = host;
    event.method = "CONNECT";
    event.decrypted = true;
    event.client_proc = client_proc;
    event.mitm = "on";
    stage("decrypting the client connection");
    set_target(host + ":" + std::to_string(static_cast<unsigned>(port)));

    const std::string ok = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: netcap\r\n\r\n";
    if (!send_all(client, ok)) {
      socket_close(client);
      return;
    }
    {
      std::lock_guard<std::mutex> lock(mu);
      ++stats.decrypted;
      stats.bytes_out += ok.size();
    }

    const i64 trace_t0 = now_unix_us();
    i64 trace_t = trace_t0;
    if (!ca_ready) {
      event.action = InterceptAction::Error;
      event.detail = "no local CA is loaded; create one with 'netcap --ca-init'";
      record(event);
      socket_close(client);
      return;
    }
    std::string why;
    const std::shared_ptr<LeafEntry> leaf = leaf_for(host, &why);
    if (!leaf) {
      event.action = InterceptAction::Error;
      event.detail = "could not issue a certificate for " + host + ": " + why;
      record(event);
      socket_close(client);
      return;
    }

    mitm_trace("ca+leaf", trace_t);
    trace_t = now_unix_us();
    // Ask the origin before we pretend to be it: TLS 1.3 when it speaks it, the
    // TLS 1.2 client when that is all it has, and a blind relay when it has
    // neither (the page keeps working, it just is not decrypted).
    const int tls_ability = origin_tls_ability(host, port, &why);
    if (tls_ability == 0) {
      OriginAddress blind_origin;
      i64 blind_rtt = -1;
      std::string blind_why;
      socket_t plain = connect_upstream(host, port, &blind_origin, &blind_rtt, &blind_why);
      if (socket_valid(plain)) {
        event.decrypted = false;
        event.mitm = "blind";
        event.origin_ip = blind_origin.text;
        event.origin_rtt_us = blind_rtt;
        event.detail = "this origin does not speak the TLS our client does; relaying without decryption";
        if (!why.empty()) event.detail += " (" + why + ")";
        {
          std::lock_guard<std::mutex> lock(mu);
          if (stats.decrypted > 0) --stats.decrypted;
          ++stats.mitm_skipped;
        }
        relay_blind(client, plain, &event, true);
        return;
      }
      event.action = InterceptAction::Error;
      event.detail = "the origin could not be reached: " + blind_why;
      record(event);
      socket_close(client);
      return;
    }
    set_socket_timeout(client, cfg.io_timeout_ms);
    set_tcp_nodelay(client);
    const Tls13Io cio = io_for(client);
    Tls13Server server;
    Tls13ServerInfo sinfo;
    if (!server.accept(cio, leaf->cert, leaf->key, host, &sinfo, &why)) {
      // A browser opens speculative connections and abandons the ones it does
      // not need *before* sending anything.  Nothing was attempted and nothing
      // failed on either side, so a lone one of those must not show up as an
      // error in the table (users read those rows as "the blocker is broken").
      //
      // A client that will not accept our certificate looks exactly the same
      // from here: a runtime with its own trust store (Node.js, Go, ...) drops
      // the socket the moment it has seen the leaf instead of sending an alert.
      // The two are told apart by repetition - see `note_client_refusal()`: one
      // abandoned connection stays silent, while a second one for the same host
      // name retires this application from decryption, because retrying is what
      // breaks it while netcap holds the system proxy.
      const bool closed = why == "connection closed";
      const bool refused = closed || is_client_refusal(why);
      const bool retired =
          refused && !cfg.mitm_strict && note_client_refusal(client_proc, host, why, !closed);
      if (closed && !retired) {
        std::lock_guard<std::mutex> lock(mu);
        ++stats.mitm_preconnect;
        socket_close(client);
        return;
      }
      // A client whose key exchange this proxy cannot do -- a lone secp521r1 key
      // share, and no x25519 or secp256r1 anywhere in its supported_groups -- is
      // not a client we can decrypt, but it is also not a reason to break the
      // connection: nothing of ours is on the wire yet and the ClientHello is
      // still in hand, so replay it to the origin and get out of the way.  The
      // application keeps working; only content filtering stops applying to it,
      // exactly like the origin that does not speak our TLS (see above).
      if (!cfg.mitm_strict && !server.wrote_anything() && !server.read_prefix().empty()) {
        OriginAddress blind_origin;
        i64 blind_rtt = -1;
        std::string blind_why;
        socket_t plain = connect_upstream(host, port, &blind_origin, &blind_rtt, &blind_why);
        const std::string prefix(reinterpret_cast<const char*>(server.read_prefix().data()),
                                 server.read_prefix().size());
        if (socket_valid(plain) && send_all(plain, prefix)) {
          if (std::getenv("NETCAP_TLS_DEBUG") != nullptr) {
            // A connection that stops being filtered is exactly the kind of thing
            // a debug log has to explain, so print the reason the handshake failed
            // rather than leaving the degradation to be guessed at.
            std::fprintf(stderr, "[tls] blind relay (the client handshake failed): %s\n",
                         why.c_str());
          }
          event.action = InterceptAction::Tunnel;
          event.mitm = "blind";
          event.decrypted = false;
          event.origin_ip = blind_origin.text;
          event.origin_rtt_us = blind_rtt;
          event.detail =
              "this client's key exchange (" + why +
              ") is not one netcap's TLS server can do; relaying without decryption so it keeps "
              "working (content filtering no longer applies to it)";
          {
            std::lock_guard<std::mutex> lock(mu);
            if (stats.decrypted > 0) --stats.decrypted;
            ++stats.mitm_skipped;
          }
          relay_blind(client, plain, &event, true);
          return;
        }
        if (socket_valid(plain)) socket_close(plain);
      }
      event.action = InterceptAction::Error;
      {
        std::lock_guard<std::mutex> lock(mu);
        ++stats.mitm_failures;
      }
      if (retired) {
        event.detail =
            closed
                ? "the client dropped the TLS handshake twice for this host name without "
                  "answering, which is what a client that does not trust netcap's certificate "
                  "does; this application is tunnelled without decryption from now on so it "
                  "keeps working (content filtering no longer applies to it)"
                : "the client refused netcap's certificate for this host name (" + why +
                  "); this application is tunnelled without decryption from now on so it keeps "
                  "working (content filtering no longer applies to it)";
      } else {
        event.detail = "TLS handshake with the client failed: " + why;
      }
      record(event);
      socket_close(client);
      return;
    }

    mitm_trace("client tls", trace_t);
    trace_t = now_unix_us();
    // Read the request *before* touching the origin: a request that a rule
    // rejects never needs an upstream socket at all, and that also means a
    // block still works when the origin cannot be handshaked with.
    // A decrypted tunnel carries as many requests as the client wants to send on
    // it -- which is what a browser expects of an HTTPS connection, and what the
    // per-resource handshake was paid for: this used to serve exactly one
    // request, send a close_notify and stop, so every image, script and style
    // sheet on a page bought its own handshake again (a fixed ~4 ms each).  The
    // client's TLS session is reused for the next request here; the origin side
    // is reused through the pool, exactly as it already was.
    std::string carry;  // first bytes of the next request, if they arrived early
    bool first = true;
    for (;;) {
      if (!first) {
        // A second request on the same tunnel is a row of its own: the tunnel's
        // identity stays (client, host, decryption) and what the previous request
        // filled in is dropped.
        event.ts_us = now_unix_us();
        event.method = "CONNECT";
        event.url.clear();
        event.rule.clear();
        event.detail.clear();
        event.action = InterceptAction::Pass;
        event.status = 0;
        event.request_bytes = 0;
        event.response_bytes = 0;
      }
      // Whether this is the tunnel's first request decides how a socket that
      // closes without asking for anything is accounted for.
      const bool first_request = first;
      first = false;
      // The head starts with whatever the previous turn already read: a TLS
      // record is not a message boundary.
      std::string head = carry;
      carry.clear();
        if (!tls_read_until(&server, cio, &head, "\r\n\r\n", cfg.max_head_bytes, &why)) {
          // The other half of the preconnect story: a browser often finishes the
          // TLS handshake (it wants the certificate and the ALPN answer) and then
          // drops the socket without ever sending a request.  That is not a
          // failure - nothing was asked for and nothing was refused - so it gets
          // counted, not printed as an error (a user read those rows as "the
          // blocker is broken", and they were right to).
          if (why == "connection closed") {
            if (first_request) {
              // A browser opens speculative connections and abandons the ones it
              // does not need before ever asking for anything.  A tunnel that has
              // already served a request and is closed cleanly now is the same
              // kind of "nothing to report" -- it must not land in the error
              // column, nor in the preconnect count twice.
              std::lock_guard<std::mutex> lock(mu);
              ++stats.mitm_preconnect;
            }
            socket_close(client);
            return;
          }
          event.action = InterceptAction::Error;
          event.detail = "no complete request head: " + why;
          record(event);
          socket_close(client);
          return;
        }
        mitm_trace("read request", trace_t);
        trace_t = now_unix_us();
        const std::size_t end = head.find("\r\n\r\n");
        event.request_bytes = end + 4;
        RequestHead req;
        if (!parse_head(head.substr(0, end + 2), &req, &why)) {
          event.action = InterceptAction::Error;
          event.detail = why;
          tls_send_local(&server, cio, 400, "Bad Request", "netcap: " + why + "\n", "text/plain");
          event.status = 400;
          record(event);
          socket_close(client);
          return;
        }
        event.method = req.method;
        const RequestTarget target = parse_request_target(req.method, req.target, host);
        event.url = target.url;
        if (event.host.empty()) event.host = target.host;

        // Same as the plaintext path: a pick never reaches the rules or the origin.
        if (handle_pick(target, client, &server, &cio, &event)) return;

        RuleDecision decision;
        bool have_decision = false;
        RuleRequest request;  // kept alive: the response rewrite below needs it too
        bool have_request = false;
        if (rules != nullptr) {
          const ResourceType type = resource_type_from_path(target.path);
          // Which page asked.  `$third-party`, `$first-party` and `$domain=` read
          // this, and it used to be hard-coded empty here, so in proxy mode those
          // rules could not match anything at all.
          request = rule_request_from_url(target.url, document_host_from_request(req), type);
          request.host = target.host.empty() ? request.host : target.host;
          decision = rules->decide(request);
          have_decision = true;
          have_request = true;
        }

        // A request whose bytes end at the head is one netcap can answer itself (a
        // block page, a redirect, a rewritten `204`) and still leave the connection
        // at a message boundary: there is no body the client is still sending, so
        // the next request starts where this head ended.  That matters in both
        // directions -- a page with forty blocked resources used to pay forty fresh
        // TLS handshakes for them.
        const bool bodyless = !req.chunked_body && req.find("content-length") == nullptr &&
                              !wants_continue(req);
        const bool keep_open = req.keep_alive && bodyless;

        if (have_decision && decision.action == RuleAction::Block) {
          event.action = InterceptAction::Block;
          event.rule = decision.rule != nullptr ? decision.rule->raw : std::string();
          const bool document = decision.rule == nullptr || decision.rule->types.empty() ||
                                std::find(decision.rule->types.begin(), decision.rule->types.end(),
                                          ResourceType::Document) != decision.rule->types.end();
          if (document) {
            std::string body = cfg.stub_body;
            if (body.empty()) {
              body = "<!doctype html><meta charset=\"utf-8\"><title>blocked by netcap</title>"
                     "<h1>Blocked by netcap</h1><p>" + target.url + "</p>";
              if (decision.rule != nullptr) body += "<pre>" + decision.rule->raw + "</pre>";
            }
            const std::string page = local_response(403, "Forbidden", body, "",
                                                    "text/html; charset=utf-8", keep_open);
            server.write_app(cio, Bytes(page.begin(), page.end()), &why);
            event.status = 403;
            event.response_bytes = page.size();
          } else {
            const std::string page = local_response(204, "No Content", "", "", "text/plain", keep_open);
            server.write_app(cio, Bytes(page.begin(), page.end()), &why);
            event.status = 204;
            event.response_bytes = page.size();
          }
          record(event);
          if (keep_open) {
            carry = head.substr(end + 4);
            continue;
          }
          server.send_close_notify(cio, nullptr);
          socket_close(client);
          return;
        }

        if (have_decision && decision.action == RuleAction::Redirect && !decision.value.empty()) {
          std::string location = decision.value;
          if (location.find("://") == std::string::npos && location[0] != '/') location = "data:,";
          const std::string page =
              local_response(302, "Found", "", "Location: " + location, "text/plain", keep_open);
          server.write_app(cio, Bytes(page.begin(), page.end()), &why);
          event.action = InterceptAction::Redirect;
          event.rule = decision.rule != nullptr ? decision.rule->raw : std::string();
          event.detail = "-> " + location;
          event.status = 302;
          event.response_bytes = page.size();
          record(event);
          if (keep_open) {
            carry = head.substr(end + 4);
            continue;
          }
          server.send_close_notify(cio, nullptr);
          socket_close(client);
          return;
        }

            // A parked connection to this origin saves both round trips; the traffic
        // secrets travel with it, so the next record simply continues the old
        // sequence numbers instead of running another handshake.
        const std::string host_key = host + ":" + std::to_string(static_cast<unsigned>(port));
        const std::string origin_key = pool_key_for(host_key, preferred_address(host_key));
        Tls13Secrets pooled_secrets;
        socket_t upstream = pool_take(origin_key, &pooled_secrets);
        const bool pooled = socket_valid(upstream);
        if (pooled) {
          mitm_trace("upstream pooled", trace_t);
          trace_t = now_unix_us();
        } else {
          OriginAddress picked_origin;
          i64 origin_rtt = -1;
          upstream = connect_upstream(host, port, &picked_origin, &origin_rtt, &why);
          event.origin_ip = picked_origin.text;
          event.origin_rtt_us = origin_rtt;
          if (!socket_valid(upstream)) {
            event.action = InterceptAction::Error;
            event.detail = why;
            record(event);
            socket_close(client);
            return;
          }
          mitm_trace("upstream tcp", trace_t);
          trace_t = now_unix_us();
        }
        set_socket_timeout(upstream, cfg.io_timeout_ms);
        Tls13Io uio = io_for(upstream);
        Tls13Client origin;
        Tls12Client origin12;
        OriginLink link;
        link.t13 = &origin;
        if (tls_ability != 1 && tls_ability != 0) {
          link.t12 = &origin12;
          link.version_hint = tls_ability;
        }
        link.io = &uio;
        const bool use_tls12 = link.tls12();
        if (pooled) origin.resume(pooled_secrets);
        Tls13ClientInfo uinfo;
        if (!pooled && !link.connect(host, "http/1.1", cfg.mitm_insecure, &uinfo, &why)) {
          // A certificate netcap will not accept (self-signed, incomplete chain,
          // wrong name) is not a reason to break the page.  Hand the connection to
          // the blind relay so it still loads, and let the event carry the reason:
          // that is the honest counterpart of `--mitm-insecure`, which decrypts
          // exactly these origins when the user asks for it.
          //
          // "We saw a certificate and the handshake still failed" is the signal:
          // the check must not depend on which of the flags tripped, because a
          // single-cert chain reports none of them as false while the origin is
          // still one netcap cannot vouch for.
          const bool certificate_problem = uinfo.certificate_seen;
          socket_close(upstream);
          if (certificate_problem) {
            OriginAddress blind_origin;
            i64 blind_rtt = -1;
            std::string blind_why;
            socket_t plain = connect_upstream(host, port, &blind_origin, &blind_rtt, &blind_why);
            if (socket_valid(plain)) {
              event.decrypted = false;
              event.mitm = "blind";
              event.origin_ip = blind_origin.text;
              event.origin_rtt_us = blind_rtt;
              event.detail =
                  "the origin's certificate is not one netcap can verify; relaying without decryption (" + why + ")";
              {
                std::lock_guard<std::mutex> lock(mu);
                if (stats.decrypted > 0) --stats.decrypted;
                ++stats.mitm_skipped;
              }
              relay_blind(client, plain, &event, true);
              return;
            }
          }
          {
            std::lock_guard<std::mutex> lock(mu);
            ++stats.mitm_failures;
          }
          event.action = InterceptAction::Error;
          event.detail = "the origin could not be verified: " + why;
          const std::string page =
              "<!doctype html><meta charset=\"utf-8\"><title>netcap</title>"
              "<h1>netcap could not verify " + host + "</h1><p>The request was not sent. Use "
              "<code>--mitm-insecure</code> to forward it anyway.</p><pre>" + why + "</pre>";
          tls_send_local(&server, cio, 502, "Bad Gateway", page, "text/html; charset=utf-8");
          event.status = 502;
          record(event);
          socket_close(client);
          return;
        }
        if (!pooled) {
          mitm_trace("upstream tls", trace_t);
          trace_t = now_unix_us();
        }
        if (!uinfo.warning.empty()) event.detail = uinfo.warning;

        std::string path = target.path;
        if (have_decision && decision.action == RuleAction::Modify) {
          std::string spec = decision.value.empty() ? std::string("*") : decision.value;
          if (strip_query_parameters(&path, spec)) {
            event.action = InterceptAction::Modify;
            event.rule = decision.rule != nullptr ? decision.rule->raw : std::string();
            event.detail = "removed " + (spec == "*" ? std::string("tracking parameters") : spec);
          }
        }

        // A client waiting for `100 Continue` sends nothing after the head until
        // somebody answers.  This middle answers (and drops the header below, so the
        // origin never waits for a body it was not told about).
        const bool expects_continue = wants_continue(req);
        if (expects_continue) {
          std::string ignored;
          const std::string go = "HTTP/1.1 100 Continue\r\n\r\n";
          server.write_app(cio, Bytes(go.begin(), go.end()), &ignored);
        }

        // A chunked request has no Content-Length, so it can never be reached from
        // inside the declared-length branch: the head used to go out with
        // `Transfer-Encoding: chunked` and no body, the origin waited, and the call
        // ended as a 502 that the client could only answer by retrying.  Read it
        // here until the terminating chunk instead.
        std::string body;
        // Where the *next* request starts inside the bytes already in hand.  A TLS
        // record is not a message boundary, so the head read and the body read can
        // both have swallowed the first bytes of a following request; they are
        // carried into the next turn of the loop instead of being dropped.
        std::string leftover = head.substr(end + 4);
        bool carryable = !req.chunked_body;  // a chunked terminator is not offset-tracked
        if (req.chunked_body) {
          body = head.substr(end + 4);
          while (!chunked_complete(body)) {
            if (body.size() > kMaxRequestBody) {
              event.action = InterceptAction::Error;
              event.detail = "a chunked request body of more than " + std::to_string(kMaxRequestBody) +
                             " bytes is refused";
              tls_send_local(&server, cio, 413, "Payload Too Large",
                             "netcap: request body too large to relay\n", "text/plain");
              event.status = 413;
              record(event);
              socket_close(upstream);
              socket_close(client);
              return;
            }
            Bytes chunk;
            if (!server.read_app(cio, &chunk, &why)) {
              event.action = InterceptAction::Error;
              event.detail = "the request body is incomplete: " + why;
              record(event);
              socket_close(upstream);
              socket_close(client);
              return;
            }
            body.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
          }
          event.request_bytes += body.size();
        } else if (const std::string* length = req.find("content-length")) {
          const std::size_t want = static_cast<std::size_t>(std::strtoull(length->c_str(), nullptr, 10));
          if (want > 0) {
            if (want > kMaxRequestBody) {
              event.action = InterceptAction::Error;
              event.detail = "a request body of " + std::to_string(want) + " bytes is refused";
              tls_send_local(&server, cio, 413, "Payload Too Large",
                             "netcap: request body too large to relay\n", "text/plain");
              event.status = 413;
              record(event);
              socket_close(upstream);
              socket_close(client);
              return;
            }
            body = head.substr(end + 4);
            if (!tls_read_exact(&server, cio, &body, want, &why)) {
              event.action = InterceptAction::Error;
              event.detail = "the request body is incomplete: " + why;
              record(event);
              socket_close(upstream);
              socket_close(client);
              return;
            }
            event.request_bytes += body.size();
            leftover = body.substr(want);
          }
        }

        std::string outgoing_head = head_to_string(req, path);
        // The 100 was already sent above; the origin must not see the header.
        if (expects_continue) strip_header(&outgoing_head, "expect");
        if (cfg.block_third_party_cookies) {
          const std::string document = request_document_host(outgoing_head);
          if (!document.empty() && !RuleRequest::same_site(target.host, document)) {
            if (strip_header(&outgoing_head, "cookie") > 0) {
              event.action = InterceptAction::Modify;
              // The switch, not a list rule, made this edit -- and it is still a rule,
              // so it gets named instead of leaving the rule column empty.
              if (event.rule.empty()) event.rule = "netcap: third-party cookies";
              event.detail = "third-party cookie (" + document + ")";
            }
          }
        }
        force_connection_keep_alive(&outgoing_head);
        const std::string outgoing = outgoing_head + body;
        if (!link.write(Bytes(outgoing.begin(), outgoing.end()), &why)) {
          event.action = InterceptAction::Error;
          event.detail = "the origin went away before the request was sent: " + why;
          event.status = 502;
          record(event);
          socket_close(upstream);
          socket_close(client);
          return;
        }

        mitm_trace("send request", trace_t);
        trace_t = now_unix_us();
        // Same shape as the plaintext path: the response is only buffered as a whole
        // when a rule actually wants to change something in it.  Otherwise it is
        // streamed with its framing understood on the way past, which is what lets
        // the origin connection go back to the pool.
        // Same as the plaintext path: remember whether the *request* was edited,
        // because a response we cannot touch must not keep the row on Modify.
        const bool request_edited = event.action == InterceptAction::Modify;
        ResponseRewrite rewrite;
        bool rewrite_wanted = have_request && rules != nullptr &&
                              rules->collect_response_rewrite(request, &rewrite) && !rewrite.empty();
        // Same cosmetic injection as the plaintext path: the page's ad slots are
        // hidden with one <style>, and everything that is not text is left alone.
        if (have_request && rules != nullptr) {
          std::string cosmetic_source;
          const std::string cosmetic =
              rules->cosmetic_css(request.host, &cosmetic_source,
                                  request_wants_generic_cosmetics(head));
          if (!cosmetic.empty()) {
            rewrite.inject_css.push_back(cosmetic);
            rewrite_wanted = true;
            if (rewrite.source.empty()) rewrite.source = cosmetic_source;
            ++rewrite.source_count;
          }
        }
        // Element picker: the bootstrap script rides along in every document (that
        // is the channel the interface button uses on already-open pages) and, while
        // picking is on, the picker script plus whatever was already picked on this
        // host.  The rule itself is durable (appended to the list file).
        if (have_request) {
          std::string picker_what;
          const int picker_added = add_picker_rewrites(request.host, &rewrite, &picker_what);
          if (picker_added > 0) {
            rewrite_wanted = true;
            // Whatever went in is named, the bootstrap included: it *is* the rule
            // that edited this response, and an unnamed edit is what used to make a
            // `modify` row look like it fired without any rule.
            if (rewrite.source.empty()) rewrite.source = picker_what;
            ++rewrite.source_count;
          }
        }
        // Procedural cosmetics: same injection as the plaintext path — the
        // selectors a stylesheet cannot express are run by the page's engine.
        if (have_request) {
          std::string cosmetic_js_what;
          const int cosmetic_added =
              add_cosmetic_programs(request.host, &rewrite, &cosmetic_js_what);
          if (cosmetic_added > 0) {
            rewrite_wanted = true;
            if (rewrite.source.empty()) rewrite.source = cosmetic_js_what;
            ++rewrite.source_count;
          }
        }
        // Which rule asked for this rewrite.  It is written into the event only in
        // the Modify branch below, so a Pass row never claims a rule it did not use.
        const std::string rewrite_rule =
            rewrite.source.empty()
                ? std::string()
                : (rewrite.source_count > 1
                       ? rewrite.source + "  (+" + std::to_string(rewrite.source_count - 1) + ")"
                       : rewrite.source);

        u64 relayed = 0;
        int status = 0;
        bool reusable = false;
        // Whether the *client* may send another request on this tunnel once this
        // response is out.  It is not the same question as `reusable`, which is about
        // the origin connection: the client only ever learns what the head netcap
        // sends it says.
        bool client_reusable = false;
        mitm_trace("relay start", trace_t);
        trace_t = now_unix_us();
        if (!rewrite_wanted) {
          const RelayEnd end =
              relay_framed_response(&link, &server, cio, req.method, &status, &relayed, &why);
          reusable = end == RelayEnd::Keep && !use_tls12;
          // This branch streams the head exactly as the origin wrote it (and the
          // request went out with `Connection: keep-alive`), so a message boundary
          // here is what the client was already told.
          client_reusable = end == RelayEnd::Keep && req.keep_alive;
          if (end == RelayEnd::ClientGone) {
            event.action = InterceptAction::Cancelled;
            event.detail = event.detail.empty()
                               ? "the client closed before the response was sent"
                               : event.detail + "; the client closed before the response was sent";
          } else if (status == 0) {
            event.action = InterceptAction::Error;
            event.detail = why.empty() ? std::string("no response head arrived") : why;
          } else {
            event.status = status;
            if (event.action != InterceptAction::Modify) event.action = InterceptAction::Pass;
          }
          if (event.status == 0) event.status = 502;
        } else {
          const std::function<int(std::string*)> pull = [&](std::string* into) -> int {
            Bytes part;
            std::string read_why;
            if (!link.read(&part, &read_why)) return -1;
            if (part.empty()) return 0;
            into->append(reinterpret_cast<const char*>(part.data()), part.size());
            return static_cast<int>(part.size());
          };
          std::string head, body, read_why;
          bool complete = false;
          int origin_status = 0;
          if (!read_full_response(pull, req.method, &head, &body, &origin_status, &complete, &read_why)) {
            event.action = InterceptAction::Error;
            event.detail = read_why;
            event.status = 502;
            tls_send_local(&server, cio, 502, "Bad Gateway", "netcap: " + read_why + "\n", "text/plain");
          } else {
            ResponseHead head_parsed;
            ResponseRewriteReport report;
            std::string rewrite_why;
            std::string outgoing_response;
            // The whole message is in memory here, so the head the client receives
            // carries netcap's own connection decision instead of the origin's: a
            // body that ran to the close, a body cut off at the 8 MiB ceiling, a head
            // that cannot be parsed or a protocol switch all end the connection and
            // must say so.  Everything else may be announced as reusable, which is
            // exactly what the loop below then honours.
            const bool framed_ok = complete && response_framing_reusable(req.method, head) &&
                                   !is_upgrade_head(head);
            // HTTP/3 is invisible to an HTTP proxy, so drop the Alt-Svc advertisement.
          // The head goes out as it arrived: QUIC stays available to the browser,
          // and an unwanted QUIC connection is stopped at its Initial packet.
          if (complete && parse_response_head(head, &head_parsed, &rewrite_why) &&
                apply_response_rewrite(rewrite, &head_parsed, &body, &report, &rewrite_why)) {
              outgoing_response = head_parsed.serialize() + body;
              if (framed_ok && req.keep_alive) {
                force_connection_keep_alive(&outgoing_response);
              } else {
                force_connection_close(&outgoing_response);
              }
              event.status = head_parsed.status;
              // Same rule as the plaintext path: an untouched response is a Pass.
              if (report.changed) {
                event.action = InterceptAction::Modify;
                // Same as the plaintext path: every contributor is named.
                if (!rewrite_rule.empty()) {
                  event.rule = event.rule.empty() ? rewrite_rule : event.rule + "  + " + rewrite_rule;
                }
              } else if (!request_edited) {
                event.action = InterceptAction::Pass;
              }
              const std::string text = report.describe();
              event.detail = event.detail.empty() ? text : event.detail + "; " + text;
            } else {
              // Anything that could not be rewritten goes out exactly as it arrived.
              outgoing_response = head + body;
              if (framed_ok && req.keep_alive) {
                force_connection_keep_alive(&outgoing_response);
              } else {
                force_connection_close(&outgoing_response);
              }
              event.status = origin_status > 0 ? origin_status : 200;
              event.action = request_edited ? InterceptAction::Modify : InterceptAction::Pass;
              const std::string text =
                  !rewrite_why.empty() ? rewrite_why
                                       : (complete ? std::string()
                                                   : std::string("the response body was not fully framed"));
              if (!text.empty()) event.detail = event.detail.empty() ? text : event.detail + "; " + text;
            }
            relayed = outgoing_response.size();
            const Bytes bytes(outgoing_response.begin(), outgoing_response.end());
            if (!server.write_app(cio, bytes, &why)) {
              event.action = InterceptAction::Cancelled;
              event.detail += event.detail.empty() ? "the client closed before the response was sent"
                                                   : "; the client closed before the response was sent";
            } else {
              // The whole message was consumed and honestly framed, so both sockets
              // sit on a message boundary.
              reusable = framed_ok;
              client_reusable = framed_ok && req.keep_alive;
            }
          }
        }
      event.response_bytes = relayed;
      mitm_trace("relay done", trace_t);
      {
        std::lock_guard<std::mutex> lock(mu);
        stats.bytes_in += event.request_bytes;
        stats.bytes_out += relayed;
      }
      record(event);
      if (reusable && !use_tls12) {
        pool_put(pool_key_for(host_key, event.origin_ip), upstream, origin.secrets());
      } else {
        socket_close(upstream);
      }
      // Another request on the same decrypted session -- the whole point of this
      // loop -- is served only when the head that just went out announced that it
      // may come, when the client asked for it, and when this request ended where
      // the parser believes it did (a chunked body's terminator is not tracked).
      if (client_reusable && carryable) {
        carry = leftover;
        continue;
      }
      server.send_close_notify(cio, nullptr);
      socket_close(client);
      return;
    }
  }

  // ---- upstream keep-alive pool -------------------------------------------

  // Takes a parked connection for `key`, or kBadSocket when there is none that
  // still looks alive.  The caller owns the socket afterwards.
  socket_t pool_take(const std::string& key, Tls13Secrets* secrets) {
    std::lock_guard<std::mutex> lock(mu);
    const auto it = origin_pool.find(key);
    if (it == origin_pool.end()) return kBadSocket;
    std::vector<PooledOrigin>& list = it->second;
    const i64 now = now_unix_us();
    socket_t sock = kBadSocket;
    while (!list.empty()) {
      PooledOrigin back = list.back();
      list.pop_back();
      // Expired, or the origin closed it while it sat idle: a readable socket
      // with nothing to read is EOF or an error, and neither is worth a request.
      if (now - back.idle_since > kPoolIdleUs || !socket_valid(back.sock) ||
          wait_readable(back.sock, 0)) {
        socket_close(back.sock);
        continue;
      }
      sock = back.sock;
      if (secrets != nullptr) *secrets = back.secrets;
      break;
    }
    if (list.empty()) origin_pool.erase(it);
    return sock;
  }

  void pool_put(const std::string& key, socket_t sock, const Tls13Secrets& secrets) {
    if (!socket_valid(sock)) return;
    std::lock_guard<std::mutex> lock(mu);
    std::vector<PooledOrigin>& list = origin_pool[key];
    PooledOrigin entry;
    entry.sock = sock;
    entry.secrets = secrets;
    entry.idle_since = now_unix_us();
    list.push_back(entry);
    while (list.size() > kPoolPerOrigin) {
      socket_close(list.front().sock);
      list.erase(list.begin());
    }
  }

  void pool_flush_locked() {
    for (auto& entry : origin_pool) {
      for (PooledOrigin& conn : entry.second) socket_close(conn.sock);
    }
    origin_pool.clear();
  }

  void pool_flush() {
    std::lock_guard<std::mutex> lock(mu);
    pool_flush_locked();
  }

  // ---- response framing ---------------------------------------------------

  enum class RelayEnd { Keep, Close, ClientGone };

  // Streams one HTTP/1.1 response from the origin to the client and stops
  // exactly at the end of the message body, so the origin connection can go
  // back to the keep-alive pool.  Keep means HttpResponseFramer found a message
  // boundary (Content-Length, chunked, or a method and status that rule out a
  // body) and that not one byte of a following message was swallowed.  Anything
  // else means close the origin connection.  The body is never buffered whole:
  // at most one TLS record sits in memory.
  RelayEnd relay_framed_response(OriginLink* link, Tls13Server* server,
                                 const Tls13Io& cio, const std::string& method, int* status,
                                 u64* relayed, std::string* why) {
    stage("framing the response");
    HttpResponseFramer framer(method);
    while (!framer.done()) {
      Bytes part;
      std::string read_why;
      if (!link->read(&part, &read_why)) {
        // EOF.  A body delimited by the close is complete at this point, and
        // either way the connection is finished.
        if (framer.status() > 0 && status != nullptr) *status = framer.status();
        if (!framer.ends_at_close()) {
          *why = read_why.empty() ? std::string("the origin closed inside the response") : read_why;
        }
        return RelayEnd::Close;
      }
      std::size_t used = 0;
      std::string frame_why;
      const bool framed =
          framer.feed(reinterpret_cast<const char*>(part.data()), part.size(), &used, &frame_why);
      if (used > 0) {
        // Forwarded exactly as it arrived. We used to take Alt-Svc out here to
        // keep browsers on TCP, but that breaks HTTP/3 for every site (see the
        // QUIC notes in the README): QUIC is meant to keep working, and the
        // place to stop an unwanted QUIC connection is its Initial packet.
        Bytes out(part.begin(), part.begin() + static_cast<std::ptrdiff_t>(used));
        if (!server->write_app(cio, out, why)) return RelayEnd::ClientGone;
        *relayed += used;
      }
      if (framer.status() > 0 && status != nullptr) *status = framer.status();
      if (!framed) {
        *why = frame_why.empty() ? std::string("the response body could not be framed") : frame_why;
        return RelayEnd::Close;
      }
      if (used < part.size()) {
        // Bytes of a following message already arrived, so this connection is
        // not at a message boundary any more: relay what we have and close.
        return RelayEnd::Close;
      }
    }
    return framer.reusable() ? RelayEnd::Keep : RelayEnd::Close;
  }

  // Can another response follow these bytes on the same connection?  A
  // Content-Length, the chunked terminator (checked once the body is in) or a
  // method and status that rule out a body say yes; a body that ends at the
  // connection close says no, and so does a head we cannot parse.
  static bool response_framing_reusable(const std::string& method, const std::string& head_text) {
    ResponseHead parsed;
    std::string error;
    if (!parse_response_head(head_text, &parsed, &error)) return false;
    const bool no_body = method == "HEAD" || parsed.status == 204 || parsed.status == 304 ||
                         (parsed.status >= 100 && parsed.status < 200);
    if (no_body) return true;
    return parsed.chunked || parsed.has_content_length;
  }

  // A 101, or any answer that carries `Upgrade`, is the start of a protocol
  // switch: what follows is not HTTP any more, so it is neither framed nor
  // advertised as a connection that can carry another request.
  static bool is_upgrade_head(const std::string& head_text) {
    ResponseHead parsed;
    std::string error;
    if (!parse_response_head(head_text, &parsed, &error)) return false;
    if (parsed.status == 101) return true;
    if (parsed.has("upgrade")) return true;
    const std::string* connection = parsed.find("connection");
    return connection != nullptr && lowercase(*connection).find("upgrade") != std::string::npos;
  }

  // The plaintext counterpart of relay_framed_response: the same framing rules
  // over a raw socket, plus the one thing the decrypted path does not need -- the
  // head the *client* receives carries netcap's own connection decision instead
  // of the origin's.  That is what the proxy used to get wrong: it closed the
  // socket after one request while passing on a head that said (by HTTP/1.1
  // default) "reusable", so the client's second request died as an aborted
  // connection ([WinError 10053]) instead of a clean close.
  RelayEnd relay_framed_plain(socket_t upstream, socket_t client, const std::string& method,
                              bool keep_client, int* status, u64* relayed, bool* origin_reusable,
                              bool* client_reusable, std::string* why) {
    stage("framing the response");
    *origin_reusable = false;
    *client_reusable = false;
    HttpResponseFramer framer(method);
    std::string pending;  // every byte read while the head was still incomplete
    bool head_sent = false;
    while (!framer.done()) {
      if (!running.load() && !socket_valid(listener)) {
        *why = "shutting down";
        return RelayEnd::Close;
      }
      if (!wait_readable(upstream, cfg.io_timeout_ms)) {
        *why = "the origin stopped answering inside the response";
        return RelayEnd::Close;
      }
      char buf[16384];
      const int rc = ::recv(upstream, buf, sizeof(buf), 0);
      if (rc <= 0) {
        // EOF.  A body delimited by the close is complete at this point, and
        // either way this connection is finished.
        if (framer.status() > 0 && status != nullptr) *status = framer.status();
        if (framer.status() > 0 && !framer.ends_at_close() && why->empty()) {
          *why = "the origin closed inside the response";
        }
        return RelayEnd::Close;
      }
      const std::size_t size = static_cast<std::size_t>(rc);
      std::size_t used = 0;
      std::string frame_why;
      const bool framed = framer.feed(buf, size, &used, &frame_why);
      if (framer.status() > 0 && status != nullptr) *status = framer.status();
      if (!head_sent) {
        pending.append(buf, size);
        const std::string& head = framer.head();
        if (!framer.failed() && head.empty()) continue;  // still inside the head
        if (framer.failed()) {
          // Not an HTTP response we can read: relay the bytes verbatim and stop
          // pretending to understand this stream.
          if (!send_all(client, pending)) return RelayEnd::ClientGone;
          *relayed += pending.size();
          pending.clear();
          pump(upstream, client, relayed, nullptr);
          return RelayEnd::Close;
        }
        std::string outgoing = head;
        const bool upgrade = is_upgrade_head(head);
        // A response whose body ends at the close must say so: the client reads
        // the same bytes we do, and it has to know to stop here too.
        const bool close_delimited = framer.ends_at_close();
        if (!upgrade) {
          if (keep_client && !close_delimited) force_connection_keep_alive(&outgoing);
          else force_connection_close(&outgoing);
        }
        if (!send_all(client, outgoing)) return RelayEnd::ClientGone;
        *relayed += outgoing.size();
        const std::string tail = pending.substr(head.size());
        if (!tail.empty()) {
          if (!send_all(client, tail)) return RelayEnd::ClientGone;
          *relayed += tail.size();
        }
        pending.clear();
        head_sent = true;
        if (upgrade) {
          // Whatever follows belongs to the client's own protocol (a WebSocket,
          // say).  It is relayed the way it always was, and both connections are
          // finished when it ends.
          pump(upstream, client, relayed, nullptr);
          return RelayEnd::Close;
        }
      } else if (used > 0) {
        if (!send_all(client, std::string(buf, used))) return RelayEnd::ClientGone;
        *relayed += used;
      }
      if (!framed) {
        *why = frame_why.empty() ? std::string("the response body could not be framed") : frame_why;
        return RelayEnd::Close;
      }
      if (head_sent && used < size) {
        // Bytes of a following message already arrived, so this connection is not
        // at a message boundary any more and is finished.  What the client was
        // promised has been delivered in full, so its side is unaffected.
        return RelayEnd::Close;
      }
    }
    *origin_reusable = framer.reusable();
    *client_reusable = keep_client && framer.reusable();
    return framer.reusable() ? RelayEnd::Keep : RelayEnd::Close;
  }

  bool accept_one(int timeout_ms, socket_t* out, std::string* peer) {
    if (!socket_valid(listener)) return false;
    if (!wait_readable(listener, timeout_ms)) return false;
    sockaddr_in from;
    std::memset(&from, 0, sizeof(from));
#if defined(_WIN32)
    int from_len = sizeof(from);
#else
    socklen_t from_len = sizeof(from);
#endif
    const socket_t client = ::accept(listener, reinterpret_cast<sockaddr*>(&from), &from_len);
    if (!socket_valid(client)) return false;
    char text[64];
    const char* ip = inet_ntop(AF_INET, &from.sin_addr, text, sizeof(text));
    *peer = (ip != nullptr ? std::string(ip) : std::string("?")) + ":" + std::to_string(ntohs(from.sin_port));
    *out = client;
    return true;
  }
};

InterceptProxy::InterceptProxy() : impl_(new Impl()) {}

InterceptProxy::~InterceptProxy() {
  stop();
  delete impl_;
}

void InterceptProxy::set_client_resolver(
    std::function<std::string(const std::string& address, std::uint16_t port)> resolver) {
  impl_->client_resolver = std::move(resolver);
}

bool InterceptProxy::start(const BlockerConfig& cfg, const RuleSet* rules, std::string* error) {
  ensure_winsock();
  stop();
  impl_->cfg = cfg;
  impl_->picker = cfg.picker;
  impl_->rules = rules;
  impl_->error.clear();
  impl_->ca_ready = false;
  impl_->policy.global_on = cfg.mitm;
  impl_->policy.skip = cfg.mitm_skip;
  impl_->policy.only = cfg.mitm_only;
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->leaf_cache.clear();
    impl_->client_refusals.clear();
    impl_->pool_flush_locked();
  }
  if (cfg.mitm || !cfg.mitm_only.empty()) {
    std::string ca_error;
    if (!ca_read_files(cfg.ca_cert_path, cfg.ca_key_path, &impl_->ca, &ca_error)) {
      const std::string why = "man-in-the-middle mode needs a local CA: " + ca_error +
                              " (create one with 'netcap --ca-init')";
      impl_->error = why;
      if (error != nullptr) *error = why;
      return false;
    }
    if (!impl_->ca.valid()) {
      const std::string why = "the CA loaded from " + cfg.ca_cert_path + " is not usable";
      impl_->error = why;
      if (error != nullptr) *error = why;
      return false;
    }
    impl_->ca_ready = true;
  }
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->events.clear();
    impl_->stats = BlockerStats();
    impl_->rule_hits.clear();
  }

  socket_t listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (!socket_valid(listener)) {
    const std::string why = "socket() failed (" + std::to_string(last_socket_error()) + ")";
    impl_->error = why;
    if (error != nullptr) *error = why;
    return false;
  }
  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));

  sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg.port);
  if (inet_pton(AF_INET, cfg.bind_address.c_str(), &addr.sin_addr) != 1) {
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
  if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    const std::string why = "bind(" + cfg.bind_address + ":" + std::to_string(cfg.port) +
                            ") failed (" + std::to_string(last_socket_error()) + ")";
    socket_close(listener);
    impl_->error = why;
    if (error != nullptr) *error = why;
    return false;
  }
  if (::listen(listener, 32) != 0) {
    const std::string why = "listen() failed (" + std::to_string(last_socket_error()) + ")";
    socket_close(listener);
    impl_->error = why;
    if (error != nullptr) *error = why;
    return false;
  }

  sockaddr_in bound;
  std::memset(&bound, 0, sizeof(bound));
#if defined(_WIN32)
  int bound_len = sizeof(bound);
#else
  socklen_t bound_len = sizeof(bound);
#endif
  if (getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
    impl_->port = ntohs(bound.sin_port);
  } else {
    impl_->port = cfg.port;
  }
  impl_->listener = listener;
  impl_->running.store(true);
  return true;
}

void InterceptProxy::stop() {
  if (impl_ == nullptr) return;
  const bool was_running = impl_->running.exchange(false);
  if (socket_valid(impl_->listener)) {
    socket_close(impl_->listener);
    impl_->listener = kBadSocket;
  }
  if (!was_running) return;
  // Give the workers a moment to notice; they all use short socket timeouts.
  for (int i = 0; i < 200 && impl_->active.load() > 0; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

bool InterceptProxy::running() const { return impl_->running.load(); }

bool InterceptProxy::set_picker(bool on) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  const bool was = impl_->picker;
  impl_->picker = on;
  return was;
}

bool InterceptProxy::picker() const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  return impl_->picker;
}

void InterceptProxy::set_origin_tls_ability(const std::string& host, std::uint16_t port,
                                            int ability) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  const std::string key = host + ":" + std::to_string(static_cast<unsigned>(port));
  if (ability < 0) {
    impl_->test_tls_ability.erase(key);
    impl_->origin_tls_probe.erase(key);
    return;
  }
  impl_->test_tls_ability[key] = ability;
}

std::vector<std::string> InterceptProxy::picked_elements() const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  std::vector<std::string> out;
  out.reserve(impl_->picked.size());
  for (const auto& entry : impl_->picked) out.push_back(entry.first + "##" + entry.second);
  return out;
}

std::uint16_t InterceptProxy::port() const { return impl_->port; }

std::string InterceptProxy::bound_endpoint() const {
  return impl_->cfg.bind_address + ":" + std::to_string(impl_->port);
}

const std::string& InterceptProxy::error() const { return impl_->error; }

bool InterceptProxy::serve_once(int timeout_ms) {
  socket_t client = kBadSocket;
  std::string peer;
  if (!impl_->accept_one(timeout_ms, &client, &peer)) return false;
  impl_->handle(client, peer);
  return true;
}

void InterceptProxy::run() {
  while (impl_->running.load()) {
    socket_t client = kBadSocket;
    std::string peer;
    if (!impl_->accept_one(200, &client, &peer)) continue;
    if (!impl_->running.load()) {
      socket_close(client);
      break;
    }
    if (impl_->active.load() >= static_cast<int>(impl_->cfg.max_clients)) {
      impl_->send_all(client, impl_->local_response(503, "Service Unavailable",
                                                    "netcap: too many connections\n", "", "text/plain"));
      socket_close(client);
      continue;
    }
    impl_->active.fetch_add(1);
    std::thread worker([this, client, peer]() {
      // One bad connection must never take the whole proxy down.  A proxy the
      // system is pointed at has to stay up: an exception escaping this thread
      // calls std::terminate, and the machine is left with a dead proxy
      // address, which looks exactly like "the network broke".
      try {
        impl_->handle(client, peer);
      } catch (const std::exception& e) {
        std::fprintf(stderr, "netcap: dropping the connection from %s: %s (stage '%s', target '%s')\n",
                     peer.c_str(), e.what(), g_stage, g_target);
        std::fflush(stderr);
        socket_close(client);
      } catch (...) {
        std::fprintf(stderr, "netcap: dropping the connection from %s: unknown error (stage '%s', target '%s')\n",
                     peer.c_str(), g_stage, g_target);
        std::fflush(stderr);
        socket_close(client);
      }
      impl_->active.fetch_sub(1);
    });
    worker.detach();
  }
}

std::vector<InterceptEvent> InterceptProxy::events() const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  return impl_->events;
}

BlockerStats InterceptProxy::stats() const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  return impl_->stats;
}

std::string InterceptProxy::url_for_event(std::size_t index) const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  if (index >= impl_->events.size()) return std::string();
  return impl_->events[index].url;
}

std::string InterceptProxy::report() const {
  BlockerStats s;
  std::map<std::string, u64> hits;
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    s = impl_->stats;
    hits = impl_->rule_hits;
  }
  char line[512];
  std::string text;
  std::snprintf(line, sizeof(line), "interception proxy  : http://%s  (%s)\n", bound_endpoint().c_str(),
                impl_->rules != nullptr ? impl_->rules->describe().c_str() : "no rule list loaded");
  text += line;
  std::snprintf(line, sizeof(line),
                "requests            : %llu (%llu blocked, %llu rewritten, %llu redirected, %llu passed, "
                "%llu tunnel(s), %llu error(s))\n",
                static_cast<unsigned long long>(s.requests), static_cast<unsigned long long>(s.blocked),
                static_cast<unsigned long long>(s.modified), static_cast<unsigned long long>(s.redirected),
                static_cast<unsigned long long>(s.passed), static_cast<unsigned long long>(s.tunnels),
                static_cast<unsigned long long>(s.errors));
  text += line;
  if (s.decrypted > 0 || s.mitm_failures > 0 || s.mitm_skipped > 0 || s.mitm_client_refusals > 0 ||
      impl_->cfg.mitm || !impl_->policy.empty()) {
    std::snprintf(line, sizeof(line),
                  "https decryption    : %llu tunnel(s) terminated, %llu handshake failure(s), "
                  "%llu left alone by the per-app policy, %llu pair(s) tunnelled after refusing "
                  "our certificate, policy %s, ca %s\n",
                  static_cast<unsigned long long>(s.decrypted),
                  static_cast<unsigned long long>(s.mitm_failures),
                  static_cast<unsigned long long>(s.mitm_skipped),
                  static_cast<unsigned long long>(s.mitm_client_refusals),
                  impl_->policy.describe().c_str(), impl_->ca_ready ? "loaded" : "missing");
    text += line;
  }
  std::snprintf(line, sizeof(line), "relayed bytes       : %llu in, %llu out\n",
                static_cast<unsigned long long>(s.bytes_in), static_cast<unsigned long long>(s.bytes_out));
  text += line;
  if (!hits.empty()) {
    text += "most used rules     :\n";
    std::vector<std::pair<u64, std::string>> ordered;
    for (const auto& item : hits) ordered.push_back({item.second, item.first});
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
      if (a.first != b.first) return a.first > b.first;
      return a.second < b.second;
    });
    std::size_t shown = 0;
    for (const auto& item : ordered) {
      if (shown++ >= 8) break;
      std::snprintf(line, sizeof(line), "  %6llu  %s\n", static_cast<unsigned long long>(item.first),
                    item.second.c_str());
      text += line;
    }
  }
  return text;
}

std::string InterceptProxy::describe() const {
  if (!running()) return "interception proxy is not running";
  if (impl_->cfg.mitm) {
    std::string out = "local interception proxy on " + bound_endpoint() +
                      " \xe2\x80\x94 HTTPS is decrypted with the local CA, so rules see the full URL";
    if (!impl_->policy.skip.empty()) {
      out += ", except ";
      for (std::size_t i = 0; i < impl_->policy.skip.size(); ++i) {
        if (i != 0) out += ", ";
        out += impl_->policy.skip[i];
      }
    }
    return out;
  }
  if (!impl_->cfg.mitm_only.empty()) {
    std::string out = "local interception proxy on " + bound_endpoint() +
                      " \xe2\x80\x94 HTTPS is decrypted only for ";
    for (std::size_t i = 0; i < impl_->cfg.mitm_only.size(); ++i) {
      if (i != 0) out += ", ";
      out += impl_->cfg.mitm_only[i];
    }
    return out;
  }
  return "local interception proxy on " + bound_endpoint() + " — HTTP is filtered by URL, HTTPS by host name";
}

}  // namespace netcap
