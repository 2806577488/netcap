// HTTP/1.1 response framing, as a byte driven state machine.
//
// An intercepting proxy has to know where a response ends for two reasons: to
// decide whether the origin connection may go back to a keep-alive pool, and to
// tell a complete response from a truncated one on a tunnel.  The rules are the
// ones in RFC 9112 section 6: a response has no body when the method was HEAD or
// the status is 1xx, 204 or 304; otherwise it is delimited by Content-Length, by
// the chunked transfer coding, or -- when neither is present -- by the origin
// closing the connection.
//
// The framer is fed the bytes exactly as they arrive, so it does not care how
// TLS records, TCP segments or a test fixture split them.
#pragma once

#include <cstddef>
#include <string>

namespace netcap {

class HttpResponseFramer {
 public:
  explicit HttpResponseFramer(std::string method = "GET");

  // Feeds the next piece of the response, in order.  Returns false when the
  // stream is malformed (unparsable head, bad chunk size, a chunk that does not
  // end with CRLF, a head or a chunk line that never ends).  `consumed` always
  // receives how many bytes of this piece belong to the message: on success it
  // is either the whole piece, or -- when done() became true inside it -- the
  // exact length of the message, leaving the rest to the caller.  `consumed` may
  // be null.
  bool feed(const char* data, std::size_t len, std::size_t* consumed, std::string* error);

  bool done() const { return state_ == State::Done; }
  bool failed() const { return state_ == State::Failed; }
  // True when the end of the body follows from the head alone, so the
  // connection sits at a message boundary and may carry another request.
  bool reusable() const { return reusable_; }
  // True while the body is delimited by the origin closing the connection: the
  // caller must treat EOF as "message complete, connection finished".
  bool ends_at_close() const { return state_ == State::UntilClose; }
  int status() const { return status_; }
  const std::string& head() const { return head_; }
  // Bytes of body seen so far (chunk sizes and CRLFs are not counted).
  std::size_t body_bytes() const { return body_bytes_; }
  std::string describe() const;

 private:
  enum class State { Head, Fixed, ChunkSize, ChunkData, ChunkCrlf, Trailer, UntilClose, Done, Failed };

  bool parse_head(std::string* error);
  bool take_chunk_size(std::string* error);
  void fail(const std::string& why, std::string* error);

  std::string method_;
  State state_ = State::Head;
  std::string head_;
  int status_ = 0;
  bool reusable_ = false;
  std::size_t remaining_ = 0;   // Content-Length or chunk bytes still expected
  std::size_t body_bytes_ = 0;
  std::string line_;            // partial chunk-size or trailer line
  bool crlf_seen_ = false;      // half of the CRLF after a chunk
};

}  // namespace netcap
