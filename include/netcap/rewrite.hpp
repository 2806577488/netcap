// Response-side rewriting: the pieces the interception proxy needs in order to
// change a response instead of blindly relaying it.
//
// Everything here works on bytes already in memory, so it can be tested without
// a socket.  The proxy still relays verbatim when a rule asks for no rewrite;
// only a matching rule pays for buffering and decoding.
//
// What is supported (the scope the user picked):
//   * response headers: $csp, $removeheader, $header, $removecookie
//   * text bodies:      $replace=/re/repl/, $css, $script
//   * Content-Encoding: gzip and deflate (zlib and raw), decoded and then
//                       dropped, so the client gets identity bytes
//   * framing:          Content-Length and chunked; the head is rewritten to
//                       match whatever we actually send
// What is deliberately not supported, and why:
//   * brotli / zstd bodies - would need a second and third decompressor; the
//     rule is skipped and the body relayed untouched
//   * 206 partial content, 304 not modified - there is no full body to edit
//   * streaming responses (SSE, multipart/x-mixed-replace) and WebSocket 101 -
//     buffering them would break the stream
//   * HTTP/2 responses - the proxy only speaks HTTP/1.1

#ifndef NETCAP_REWRITE_HPP
#define NETCAP_REWRITE_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

// --------------------------------------------------------------- the head

struct ResponseHeader {
  std::string name;
  std::string value;
};

// A parsed status line plus headers.  The original spelling of every header is
// kept (case included) so that a response we do not touch serialises back to
// byte-identical bytes.
struct ResponseHead {
  std::string version = "HTTP/1.1";
  int status = 0;
  std::string reason;
  std::vector<ResponseHeader> headers;

  bool chunked = false;
  bool close_delimited = false;
  bool has_content_length = false;
  std::size_t content_length = 0;
  std::string content_encoding;  // lower-cased token, empty when absent
  std::string content_type;      // lower-cased media type, empty when absent

  // Returns the first value for `name` (case-insensitive), or nullptr.
  const std::string* find(const std::string& name) const;
  bool has(const std::string& name) const;
  void set(const std::string& name, const std::string& value);  // replaces every copy
  bool remove(const std::string& name);
  std::size_t remove_all(const std::string& name);
  std::size_t count(const std::string& name) const;
  std::string serialize() const;  // status line + headers + blank line
  std::size_t header_count() const { return headers.size(); }
};

// Parses "HTTP/1.1 200 OK\r\nName: value\r\n...\r\n\r\n".  Returns false and
// sets `error` when the bytes are not a response head.
bool parse_response_head(const std::string& raw, ResponseHead* out, std::string* error);

// Parses one "Name: value" line (used by $header rules).
bool parse_header_line(const std::string& line, std::string* name, std::string* value);

// --------------------------------------------------------------- the rules

// One $replace=/pattern/replacement/ entry.  `case_insensitive` comes from a
// (?i) prefix in the pattern.
struct RewriteReplace {
  std::string pattern;
  std::string replacement;
  bool case_insensitive = false;
  std::string raw;  // exactly as the rule spelled it, for reports
};

// Everything the rules asked for on one response.
struct ResponseRewrite {
  std::vector<std::string> set_headers;     // "Content-Security-Policy: ..."
  std::vector<std::string> remove_headers;  // lower-cased header names
  std::vector<std::string> remove_cookies;  // cookie names
  std::vector<RewriteReplace> replaces;
  std::vector<std::string> inject_css;
  std::vector<std::string> inject_script;
  /// Which rule asked for this rewrite, exactly as it is spelled in the list
  /// ("||example.com^$replace=/a/b/"), and how many rules contributed.  Without
  /// it the event log showed an empty 规则 column for every rewrite, which reads
  /// like "something changed the page without a rule" — the rule is the reason
  /// the response is touched at all, so it belongs in the log.
  std::string source;
  std::size_t source_count = 0;

  bool empty() const;
  std::size_t size() const;
  std::string describe() const;
};

struct ResponseRewriteReport {
  bool head_changed = false;
  bool body_changed = false;
  bool decoded = false;
  /// True only when the bytes sent to the client really differ from what the
  /// origin sent (body edit, injected <style>/<script>, a $replace that matched,
  /// a header added/removed, or a body that had to be reframed).  `head_changed`
  /// cannot answer that on its own: every rebuilt response gets its framing
  /// written back, so a cosmetic rule that changed nothing still looked like an
  /// edit in the event log.
  bool changed = false;
  bool dropped_encoding = false;
  bool skipped_unsupported_encoding = false;
  bool skipped_no_body = false;
  std::size_t replaces = 0;
  std::size_t injected_css = 0;
  std::size_t injected_script = 0;
  std::size_t bytes_in = 0;
  std::size_t bytes_out = 0;
  std::string note;
  std::string describe() const;
};

// ------------------------------------------------------------- the decoders

// Decodes a chunked body (without the terminating CRLF handling subtleties -
// trailers are parsed and dropped).  The trailing CRLF after each chunk is
// required, and a truncated body is an error.
bool chunked_decode(const std::string& in, std::string* out, std::string* error);

// RFC 1951 inflate, with the RFC 1952 (gzip) and RFC 1950 (zlib) wrappers
// peeled off first.  `encoding` is the lower-cased Content-Encoding token:
// "gzip", "x-gzip", "deflate" (zlib or raw, both accepted) or "" (raw deflate).
// Output is capped at 32 MiB so that a hostile stream cannot exhaust memory.
bool inflate_body(const std::string& encoding, const std::string& in, std::string* out,
                  std::string* error);

// True when a body of this media type may be rewritten as text.
bool response_body_is_text(const ResponseHead& head);

// Applies `rw` to a parsed head and its (already de-chunked) body.  The head is
// rewritten to match: Content-Length is corrected, Content-Encoding dropped if
// the body was inflated, ETag/Last-Modified/Content-MD5/Digest removed because
// they no longer describe what is sent.
bool apply_response_rewrite(const ResponseRewrite& rw, ResponseHead* head, std::string* body,
                            ResponseRewriteReport* report, std::string* error);

// Human-readable list of what a body rewrite refuses to touch.
std::string response_rewrite_limits();

/// Remove every `Alt-Svc` header line from a raw response head.
///
/// An HTTP proxy never sees HTTP/3: the browser learns about it from this
/// header and then talks UDP 443 *directly to the origin*, which means the
/// traffic silently stops going through the interceptor (and on a network
/// where UDP 443 is blocked the page simply stays blank).  Dropping the header
/// keeps the browser on TCP, which we do see.  Everything else - including the
/// terminating CRLFCRLF and the header order - is left byte for byte alone.
std::string strip_alt_svc_header(const std::string& head);

}  // namespace netcap

#endif  // NETCAP_REWRITE_HPP
