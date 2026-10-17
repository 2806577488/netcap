// HTTP/1.x over reassembled TCP streams.
//
// The parser is incremental: bytes arrive in whatever chunks the reassembler
// produced, headers may be split across segments, bodies may be framed by
// Content-Length or by chunked transfer encoding, and the two directions are
// paired into transactions (with pipelining support).
//
// Deliberately out of scope here: HTTP/2 frames and HPACK (see h2.hpp) and
// anything after a WebSocket upgrade, which is no longer an HTTP message.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

struct HttpHeader {
  std::string name;
  std::string value;
};

struct HttpMessage {
  bool is_request = false;
  int version_major = 1;
  int version_minor = 1;
  std::string method;  // requests
  std::string target;  // requests
  std::string reason;  // responses
  int status = 0;      // responses

  std::vector<HttpHeader> headers;
  bool chunked = false;
  bool has_content_length = false;
  u64 content_length = 0;
  bool keep_alive = true;
  bool upgrade_websocket = false;

  std::string body;  // de-chunked
  bool truncated = false;
  bool body_to_close = false;  // no framing headers: the body ends at connection close

  std::size_t header_bytes = 0;
  std::size_t raw_bytes = 0;
  i64 first_us = 0;
  i64 last_us = 0;

  // Case-insensitive header lookup.
  const std::string* find(const std::string& name) const;
  bool has(const std::string& name) const { return find(name) != nullptr; }
  std::string header(const std::string& name) const;
  std::string header_or(const std::string& name, const std::string& fallback) const;

  std::string version_text() const;  // "HTTP/1.1"
  std::string start_line() const;    // "GET /index.html HTTP/1.1" / "HTTP/1.1 200 OK"
  std::string host() const;
  std::string content_type() const;
  std::string user_agent() const;
  std::string server() const;
  std::string summary() const;  // short one-liner for a UI column
};

// Parses one direction of one connection.
class HttpParser {
 public:
  void set_max_message_bytes(std::size_t n) { max_message_ = n; }
  void reset();

  // Feed bytes in order. Completed messages are appended to `out`.
  void feed(const u8* data, std::size_t len, i64 ts_us, std::vector<HttpMessage>* out);

  std::size_t buffered() const { return buf_.size(); }
  bool failed() const { return failed_; }
  bool saw_http() const { return saw_http_; }
  bool saw_http2_preface() const { return http2_preface_; }
  bool saw_tls() const { return tls_; }
  // Bytes the parser decided are not HTTP (binary, TLS, HTTP/2 frames after the
  // preface). Handed over instead of being parsed.
  const std::vector<u8>& passthrough() const { return passthrough_; }

  // Cheap pre-check used to decide whether a stream is worth parsing at all.
  static bool looks_like_http(const u8* data, std::size_t len);
  static bool is_http2_preface(const u8* data, std::size_t len);

  // A response to HEAD carries no body even though it may advertise a
  // Content-Length; the analyzer tells the parser about it after seeing the
  // request. Applies to the next response only.
  void expect_no_body_for_next_response() { next_no_body_ = true; }

 private:
  bool try_parse(std::vector<HttpMessage>* out, i64 ts_us);

  std::vector<u8> buf_;
  std::vector<u8> passthrough_;
  std::size_t max_message_ = 16u << 20;
  i64 buf_first_us_ = 0;
  bool failed_ = false;
  bool saw_http_ = false;
  bool http2_preface_ = false;
  bool tls_ = false;
  bool next_no_body_ = false;
};

struct HttpTransaction {
  bool has_request = false;
  bool has_response = false;
  HttpMessage request;
  HttpMessage response;
  std::vector<HttpMessage> informational;  // 1xx responses, in order
  i64 start_us = 0;
  i64 end_us = 0;

  double duration_ms() const { return double(end_us - start_us) / 1000.0; }
  std::string url() const;      // absolute URL when the host is known
  std::string status_line() const;
  std::string summary() const;
};

// Pairs both directions of one connection into transactions.
class HttpAnalyzer {
 public:
  void set_max_message_bytes(std::size_t n);

  void feed_client_to_server(const u8* data, std::size_t len, i64 ts_us);
  void feed_server_to_client(const u8* data, std::size_t len, i64 ts_us);

  const std::vector<HttpTransaction>& transactions() const { return tx_; }
  bool saw_http() const { return saw_http_; }
  bool saw_http2() const { return c2s_.saw_http2_preface() || s2c_.saw_http2_preface(); }
  bool saw_tls() const { return c2s_.saw_tls() || s2c_.saw_tls(); }
  bool websocket() const;
  bool parsed_ok() const { return !c2s_.failed() && !s2c_.failed(); }
  std::size_t requests() const;
  std::size_t responses() const;
  void reset();

  HttpParser& client_parser() { return c2s_; }
  HttpParser& server_parser() { return s2c_; }

 private:
  HttpParser c2s_;
  HttpParser s2c_;
  std::vector<HttpTransaction> tx_;
  std::vector<std::size_t> awaiting_response_;
  bool saw_http_ = false;
};

}  // namespace netcap
