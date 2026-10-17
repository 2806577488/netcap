// HTTP/1.x parsing over reassembled streams.
#include "netcap/http.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace netcap {

namespace {

const char* kMethods[] = {"GET",   "POST",   "HEAD",    "PUT",     "DELETE", "OPTIONS",
                          "TRACE", "CONNECT", "PATCH",  "PRI",     "PROPFIND", "COPY",
                          "MOVE",  "REPORT", "LOCK",    "UNLOCK",  "MKCOL",  "SEARCH",
                          "PURGE", "LINK",   "UNLINK",  "BIND",    "REBIND", "NOTIFY"};

bool ascii_equal_ci(const std::string& a, const char* b) {
  std::size_t i = 0;
  for (; i < a.size() && b[i]; ++i) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') x = char(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = char(y - 'A' + 'a');
    if (x != y) return false;
  }
  return i == a.size() && b[i] == '\0';
}

std::string lower_ascii(const std::string& s) {
  std::string r = s;
  for (char& c : r) {
    if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
  }
  return r;
}

// Strips surrounding whitespace, including the CR and LF of a line terminator:
// callers hand in whole lines, so a leftover '\n' would corrupt every value it
// touches (chunk sizes, Content-Length, header values, reason phrases).
bool is_blank(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

void trim(std::string* s) {
  std::size_t b = 0;
  while (b < s->size() && is_blank(s->at(b))) ++b;
  std::size_t e = s->size();
  while (e > b && is_blank(s->at(e - 1))) --e;
  *s = s->substr(b, e - b);
}

int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Finds the end of the line starting at `from`; `next` receives the index just
// past the terminator. Accepts CRLF and a bare LF.
bool find_line_end(const std::vector<u8>& b, std::size_t from, std::size_t* next) {
  for (std::size_t i = from; i < b.size(); ++i) {
    if (b[i] == '\n') {
      *next = i + 1;
      return true;
    }
  }
  return false;
}

// Finds the blank line that ends a header block.
bool find_head_end(const std::vector<u8>& b, std::size_t from, std::size_t* after) {
  for (std::size_t i = from; i + 1 < b.size(); ++i) {
    if (b[i] == '\r' && b[i + 1] == '\n') {
      if (i + 3 < b.size() && b[i + 2] == '\r' && b[i + 3] == '\n') {
        *after = i + 4;
        return true;
      }
      if (i + 2 < b.size() && b[i + 2] == '\n') {  // "\r\n\n"
        *after = i + 3;
        return true;
      }
    }
    if (b[i] == '\n' && b[i + 1] == '\n') {
      *after = i + 2;
      return true;
    }
  }
  return false;
}

bool has_method_prefix(const std::vector<u8>& b) {
  const std::string s(reinterpret_cast<const char*>(b.data()), b.size());
  for (const char* m : kMethods) {
    const std::size_t n = std::strlen(m);
    if (s.size() <= n) {
      if (std::strncmp(s.c_str(), m, s.size()) == 0) return true;  // still typing
    } else if (std::strncmp(s.c_str(), m, n) == 0 && s[n] == ' ') {
      return true;
    }
  }
  const char* http = "HTTP/";
  const std::size_t n = std::strlen(http);
  return std::strncmp(s.c_str(), http, std::min(s.size(), n)) == 0;
}

enum class ChunkResult { Complete, NeedMore, Bad };

ChunkResult parse_chunks(const std::vector<u8>& b, std::size_t pos, std::string* body,
                         std::size_t* end_pos) {
  std::size_t p = pos;
  while (true) {
    std::size_t line_end = 0;
    if (!find_line_end(b, p, &line_end)) return ChunkResult::NeedMore;
    std::string line(reinterpret_cast<const char*>(b.data()) + p, line_end - p);
    trim(&line);
    const std::size_t semi = line.find(';');
    if (semi != std::string::npos) line = line.substr(0, semi);
    trim(&line);
    if (line.empty()) return ChunkResult::Bad;
    u64 size = 0;
    for (char c : line) {
      const int d = hex_val(c);
      if (d < 0) return ChunkResult::Bad;
      size = size * 16 + u64(d);
      if (size > (u64(1) << 40)) return ChunkResult::Bad;
    }
    p = line_end;
    if (size == 0) {
      // The final chunk may be followed by trailer headers and a blank line.
      if (p >= b.size()) return ChunkResult::NeedMore;
      if (b[p] == '\r') {
        if (p + 1 >= b.size()) return ChunkResult::NeedMore;
        if (b[p + 1] == '\n') {
          *end_pos = p + 2;
          return ChunkResult::Complete;
        }
      } else if (b[p] == '\n') {
        *end_pos = p + 1;
        return ChunkResult::Complete;
      }
      std::size_t trailers_end = 0;
      if (!find_head_end(b, p, &trailers_end)) return ChunkResult::NeedMore;
      *end_pos = trailers_end;
      return ChunkResult::Complete;
    }
    if (p + size > b.size()) return ChunkResult::NeedMore;
    body->append(reinterpret_cast<const char*>(b.data()) + p, std::size_t(size));
    p += std::size_t(size);
    if (p >= b.size()) return ChunkResult::NeedMore;  // the CRLF after the data
    if (b[p] == '\r') {
      if (p + 1 >= b.size()) return ChunkResult::NeedMore;
      if (b[p + 1] != '\n') return ChunkResult::Bad;
      p += 2;
    } else if (b[p] == '\n') {
      p += 1;
    } else {
      return ChunkResult::Bad;
    }
  }
}

}  // namespace

// ------------------------------------------------------------------ message

const std::string* HttpMessage::find(const std::string& name) const {
  for (const HttpHeader& h : headers) {
    if (ascii_equal_ci(h.name, name.c_str())) return &h.value;
  }
  return nullptr;
}

std::string HttpMessage::header(const std::string& name) const {
  const std::string* v = find(name);
  return v ? *v : std::string();
}

std::string HttpMessage::header_or(const std::string& name, const std::string& fallback) const {
  const std::string* v = find(name);
  return v ? *v : fallback;
}

std::string HttpMessage::version_text() const {
  return "HTTP/" + std::to_string(version_major) + "." + std::to_string(version_minor);
}

std::string HttpMessage::start_line() const {
  if (is_request) return method + " " + target + " " + version_text();
  return version_text() + " " + std::to_string(status) + (reason.empty() ? "" : " " + reason);
}

std::string HttpMessage::host() const {
  std::string h = header("Host");
  if (h.empty()) h = header(":authority");
  return h;
}

std::string HttpMessage::content_type() const { return header("Content-Type"); }
std::string HttpMessage::user_agent() const { return header("User-Agent"); }
std::string HttpMessage::server() const { return header("Server"); }

std::string HttpMessage::summary() const {
  if (is_request) return method + " " + target;
  std::string s = std::to_string(status);
  if (!reason.empty()) s += " " + reason;
  const std::string ct = content_type();
  if (!ct.empty()) {
    const std::size_t semi = ct.find(';');
    s += "  " + (semi == std::string::npos ? ct : ct.substr(0, semi));
  }
  return s;
}

// ------------------------------------------------------------------ parser

void HttpParser::reset() {
  buf_.clear();
  passthrough_.clear();
  failed_ = false;
  saw_http_ = false;
  http2_preface_ = false;
  tls_ = false;
  buf_first_us_ = 0;
}

bool HttpParser::is_http2_preface(const u8* d, std::size_t n) {
  static const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  const std::size_t want = sizeof(kPreface) - 1;
  if (n < 5) return false;  // not enough to tell yet; compared as a prefix below
  const std::size_t take = n < want ? n : want;
  return std::memcmp(d, kPreface, take) == 0 && n >= 5;
}

bool HttpParser::looks_like_http(const u8* d, std::size_t n) {
  if (n == 0) return false;
  std::vector<u8> head(d, d + (n < 16 ? n : 16));
  return has_method_prefix(head);
}

void HttpParser::feed(const u8* data, std::size_t len, i64 ts_us, std::vector<HttpMessage>* out) {
  if (len == 0) return;
  if (buf_.empty()) buf_first_us_ = ts_us;
  if (failed_ || http2_preface_ || tls_) {
    passthrough_.insert(passthrough_.end(), data, data + len);
    return;
  }
  buf_.insert(buf_.end(), data, data + len);

  // A 24 byte run of the HTTP/2 client preface means this stream is h2, not
  // HTTP/1.x: hand the bytes over untouched.
  static const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  const std::size_t kPrefaceLen = sizeof(kPreface) - 1;
  if (buf_.size() >= kPrefaceLen && std::memcmp(buf_.data(), kPreface, kPrefaceLen) == 0) {
    http2_preface_ = true;
    passthrough_.insert(passthrough_.end(), buf_.begin(), buf_.end());
    buf_.clear();
    return;
  }

  while (!buf_.empty()) {
    if (!try_parse(out, ts_us)) break;
  }
  if (buf_.size() > max_message_) {
    // Whatever this is, it is not a sane HTTP message: stop parsing it.
    failed_ = true;
    passthrough_.insert(passthrough_.end(), buf_.begin(), buf_.end());
    buf_.clear();
  }
}

bool HttpParser::try_parse(std::vector<HttpMessage>* out, i64 ts_us) {
  // Tolerate stray blank lines before a message: some servers and proxies emit
  // a CRLF ahead of a response.
  std::size_t blanks = 0;
  while (blanks < buf_.size() && (buf_[blanks] == '\r' || buf_[blanks] == '\n')) ++blanks;
  if (blanks > 0) {
    if (blanks == buf_.size()) {
      buf_.clear();  // nothing but blank lines so far
      return false;
    }
    buf_.erase(buf_.begin(), buf_.begin() + std::ptrdiff_t(blanks));
  }

  // Decide whether this can be HTTP at all before waiting for a full header.
  if (!has_method_prefix(buf_)) {
    if (buf_.size() < 8 && HttpParser::is_http2_preface(buf_.data(), buf_.size())) {
      return false;  // could still turn into the h2 preface
    }
    if (buf_.size() < 4) return false;  // "GET" alone is ambiguous
    failed_ = true;
    tls_ = buf_.size() >= 3 && buf_[0] == 0x16 && buf_[1] == 0x03;
    passthrough_.insert(passthrough_.end(), buf_.begin(), buf_.end());
    buf_.clear();
    return false;
  }

  std::size_t head_end = 0;
  if (!find_head_end(buf_, 0, &head_end)) return false;  // wait for more bytes

  HttpMessage m;
  m.first_us = buf_first_us_;
  m.last_us = ts_us;

  std::size_t line_end = 0;
  if (!find_line_end(buf_, 0, &line_end)) return false;
  std::string start(reinterpret_cast<const char*>(buf_.data()), line_end);
  trim(&start);
  if (start.empty()) {
    // Tolerate leading blank lines.
    buf_.erase(buf_.begin(), buf_.begin() + std::ptrdiff_t(line_end));
    return true;
  }

  if (start.rfind("HTTP/", 0) == 0) {
    m.is_request = false;
    if (start.size() < 12) {
      failed_ = true;
      return false;
    }
    m.version_major = start[5] - '0';
    m.version_minor = start[7] - '0';
    const std::string code = start.substr(9, 3);
    m.status = std::atoi(code.c_str());
    const std::size_t rsp = start.find(' ', 9);  // the space after the status code
    if (rsp != std::string::npos) m.reason = start.substr(rsp + 1);
  } else {
    m.is_request = true;
    const std::size_t sp1 = start.find(' ');
    const std::size_t sp2 = sp1 == std::string::npos ? std::string::npos : start.find(' ', sp1 + 1);
    if (sp1 == std::string::npos) {
      failed_ = true;
      passthrough_.insert(passthrough_.end(), buf_.begin(), buf_.end());
      buf_.clear();
      return false;
    }
    m.method = start.substr(0, sp1);
    m.target = sp2 == std::string::npos ? start.substr(sp1 + 1) : start.substr(sp1 + 1, sp2 - sp1 - 1);
    if (m.method == "PRI" && m.target == "*") {
      // The HTTP/2 client preface, split across segments: hand the bytes over.
      http2_preface_ = true;
      passthrough_.insert(passthrough_.end(), buf_.begin(), buf_.end());
      buf_.clear();
      return false;
    }
    if (sp2 != std::string::npos) {
      const std::string v = start.substr(sp2 + 1);
      if (v.size() >= 8 && v.rfind("HTTP/", 0) == 0) {
        m.version_major = v[5] - '0';
        m.version_minor = v[7] - '0';
      }
    }
  }

  // Header lines.
  std::size_t pos = line_end;
  while (pos < head_end) {
    std::size_t eol = 0;
    if (!find_line_end(buf_, pos, &eol)) break;
    std::string line(reinterpret_cast<const char*>(buf_.data()) + pos, eol - pos);
    trim(&line);
    if (line.empty()) break;
    const std::size_t colon = line.find(':');
    if (colon != std::string::npos) {
      HttpHeader h;
      h.name = line.substr(0, colon);
      h.value = line.substr(colon + 1);
      trim(&h.value);
      m.headers.push_back(std::move(h));
    }
    pos = eol;
  }

  const std::string te = lower_ascii(m.header("Transfer-Encoding"));
  m.chunked = te.find("chunked") != std::string::npos;
  const std::string cl = m.header("Content-Length");
  if (!cl.empty()) {
    u64 v = 0;
    bool ok = true;
    for (char c : cl) {
      if (c < '0' || c > '9') {
        ok = false;
        break;
      }
      v = v * 10 + u64(c - '0');
    }
    if (ok) {
      m.has_content_length = true;
      m.content_length = v;
    }
  }
  const std::string conn = lower_ascii(m.header("Connection"));
  if (conn.find("close") != std::string::npos) m.keep_alive = false;
  if (conn.find("upgrade") != std::string::npos) {
    if (ascii_equal_ci(m.header("Upgrade"), "websocket")) m.upgrade_websocket = true;
  }

  // Does this message even have a body?
  bool body_expected = true;
  if (m.is_request) {
    body_expected = m.has_content_length || m.chunked;
  } else {
    if ((m.status >= 100 && m.status < 200) || m.status == 204 || m.status == 304) {
      body_expected = false;
    }
  }
  if (m.method == "HEAD" || m.method == "CONNECT") {
    // Responses to HEAD/CONNECT carry no body: the parser cannot know that from
    // the response alone, so treat a missing framing as no body.
    if (!m.has_content_length && !m.chunked) body_expected = false;
  }
  if (!m.is_request && next_no_body_) {
    body_expected = false;  // the response to a HEAD request
    next_no_body_ = false;
  }

  std::size_t consumed = 0;
  if (!body_expected) {
    consumed = head_end;
  } else if (m.chunked) {
    std::size_t end = 0;
    const ChunkResult r = parse_chunks(buf_, head_end, &m.body, &end);
    if (r == ChunkResult::NeedMore) {
      if (m.body.size() > max_message_) {
        m.truncated = true;
        consumed = buf_.size();
      } else {
        return false;  // keep waiting
      }
    } else if (r == ChunkResult::Bad) {
      failed_ = true;
      passthrough_.insert(passthrough_.end(), buf_.begin(), buf_.end());
      buf_.clear();
      return false;
    } else {
      consumed = end;
    }
  } else if (m.has_content_length) {
    if (buf_.size() < head_end + m.content_length) {
      if (m.content_length > max_message_) {
        m.body.assign(reinterpret_cast<const char*>(buf_.data()) + head_end, buf_.size() - head_end);
        m.truncated = true;
        consumed = buf_.size();
      } else {
        return false;  // keep waiting
      }
    } else {
      m.body.assign(reinterpret_cast<const char*>(buf_.data()) + head_end,
                    std::size_t(m.content_length));
      consumed = head_end + std::size_t(m.content_length);
    }
  } else if (!m.is_request) {
    // Unframed response body: it runs until the connection closes, so take
    // everything we have. `body_to_close` tells callers the body may be short.
    m.body_to_close = true;
    m.body.assign(reinterpret_cast<const char*>(buf_.data()) + head_end, buf_.size() - head_end);
    consumed = buf_.size();
  } else {
    consumed = head_end;
  }

  m.header_bytes = head_end;
  m.raw_bytes = consumed;
  buf_.erase(buf_.begin(), buf_.begin() + std::ptrdiff_t(consumed));
  if (!buf_.empty()) buf_first_us_ = ts_us;
  saw_http_ = true;
  if (out) out->push_back(std::move(m));
  return true;
}

// ------------------------------------------------------------------ transaction

std::string HttpTransaction::url() const {
  if (!has_request) return std::string();
  const std::string& t = request.target;
  if (t.rfind("http://", 0) == 0 || t.rfind("https://", 0) == 0) return t;
  const std::string h = request.host();
  if (h.empty()) return t;
  return "http://" + h + t;
}

std::string HttpTransaction::status_line() const {
  return has_response ? response.start_line() : std::string();
}

std::string HttpTransaction::summary() const {
  std::string s;
  if (has_request) {
    s = request.method + " " + request.target;
  }
  if (has_response) {
    if (!s.empty()) s += "  ->  ";
    s += std::to_string(response.status);
    if (!response.reason.empty()) s += " " + response.reason;
    if (response.has_content_length) s += "  " + std::to_string(response.content_length) + "B";
    else if (!response.body.empty()) s += "  " + std::to_string(response.body.size()) + "B";
  }
  return s;
}

// ------------------------------------------------------------------ analyzer

void HttpAnalyzer::set_max_message_bytes(std::size_t n) {
  c2s_.set_max_message_bytes(n);
  s2c_.set_max_message_bytes(n);
}

void HttpAnalyzer::reset() {
  c2s_.reset();
  s2c_.reset();
  tx_.clear();
  awaiting_response_.clear();
  saw_http_ = false;
}

void HttpAnalyzer::feed_client_to_server(const u8* data, std::size_t len, i64 ts_us) {
  std::vector<HttpMessage> msgs;
  c2s_.feed(data, len, ts_us, &msgs);
  saw_http_ = saw_http_ || c2s_.saw_http();
  for (HttpMessage& m : msgs) {
    const bool head_request = m.method == "HEAD" || m.method == "CONNECT";
    HttpTransaction t;
    t.has_request = true;
    t.request = std::move(m);
    t.start_us = t.request.first_us;
    t.end_us = t.request.last_us;
    if (head_request) s2c_.expect_no_body_for_next_response();
    tx_.push_back(std::move(t));
    awaiting_response_.push_back(tx_.size() - 1);
  }
}

void HttpAnalyzer::feed_server_to_client(const u8* data, std::size_t len, i64 ts_us) {
  std::vector<HttpMessage> msgs;
  s2c_.feed(data, len, ts_us, &msgs);
  saw_http_ = saw_http_ || s2c_.saw_http();
  for (HttpMessage& m : msgs) {
    // 1xx responses are interim: they belong to the pending request but do not
    // complete it. 101 Switching Protocols is the exception: it ends the HTTP
    // exchange (the connection becomes WebSocket or similar), so it is recorded
    // as the final response of the transaction.
    if (m.status >= 100 && m.status < 200 && m.status != 101 && !awaiting_response_.empty()) {
      // Informational responses (100 Continue) belong to the pending request
      // without completing it.
      HttpTransaction& t = tx_[awaiting_response_.front()];
      t.informational.push_back(std::move(m));
      t.end_us = t.informational.back().last_us;
      continue;
    }
    if (!awaiting_response_.empty()) {
      const std::size_t idx = awaiting_response_.front();
      awaiting_response_.erase(awaiting_response_.begin());
      HttpTransaction& t = tx_[idx];
      t.has_response = true;
      t.response = std::move(m);
      if (t.start_us == 0) t.start_us = t.response.first_us;
      t.end_us = t.response.last_us;
    } else {
      // A response with no captured request (the capture started mid-stream).
      HttpTransaction t;
      t.has_response = true;
      t.response = std::move(m);
      t.start_us = t.response.first_us;
      t.end_us = t.response.last_us;
      tx_.push_back(std::move(t));
    }
  }
}

bool HttpAnalyzer::websocket() const {
  for (const HttpTransaction& t : tx_) {
    if (t.has_response && t.response.status == 101) return true;
    if (t.has_request && t.request.upgrade_websocket) return true;
    if (t.has_response && t.response.upgrade_websocket) return true;
  }
  return false;
}

std::size_t HttpAnalyzer::requests() const {
  std::size_t n = 0;
  for (const HttpTransaction& t : tx_) {
    if (t.has_request) ++n;
  }
  return n;
}

std::size_t HttpAnalyzer::responses() const {
  std::size_t n = 0;
  for (const HttpTransaction& t : tx_) {
    if (t.has_response) ++n;
    n += t.informational.size();
  }
  return n;
}

}  // namespace netcap
