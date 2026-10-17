// HTTP/2 frame decoding and HPACK header decompression (RFC 7540 / RFC 7541).
//
// The decoder works on a single direction of one TCP connection at a time, so
// it is normally fed from a reassembled stream (see flow.hpp) or from the
// plaintext recovered by tls.hpp. Header blocks are decoded with the HPACK
// dynamic table, including its eviction rules and Huffman-coded strings.
#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"

namespace netcap {

// Frame types (RFC 7540 section 6).
constexpr u8 H2_DATA = 0x0;
constexpr u8 H2_HEADERS = 0x1;
constexpr u8 H2_PRIORITY = 0x2;
constexpr u8 H2_RST_STREAM = 0x3;
constexpr u8 H2_SETTINGS = 0x4;
constexpr u8 H2_PUSH_PROMISE = 0x5;
constexpr u8 H2_PING = 0x6;
constexpr u8 H2_GOAWAY = 0x7;
constexpr u8 H2_WINDOW_UPDATE = 0x8;
constexpr u8 H2_CONTINUATION = 0x9;

// Frame flags that are shared between several frame types.
constexpr u8 H2_FLAG_ACK = 0x1;
constexpr u8 H2_FLAG_END_STREAM = 0x1;
constexpr u8 H2_FLAG_END_HEADERS = 0x4;
constexpr u8 H2_FLAG_PADDED = 0x8;
constexpr u8 H2_FLAG_PRIORITY = 0x20;

// Settings identifiers we reason about.
constexpr u16 H2_SETTING_HEADER_TABLE_SIZE = 0x1;
constexpr u16 H2_SETTING_ENABLE_PUSH = 0x2;
constexpr u16 H2_SETTING_MAX_CONCURRENT_STREAMS = 0x3;
constexpr u16 H2_SETTING_INITIAL_WINDOW_SIZE = 0x4;
constexpr u16 H2_SETTING_MAX_FRAME_SIZE = 0x5;
constexpr u16 H2_SETTING_MAX_HEADER_LIST_SIZE = 0x6;

const char* h2_frame_type_name(u8 type);
const char* h2_error_name(u32 code);

struct H2HeaderField {
  std::string name;
  std::string value;
};

// One decoded frame. Only the fields that apply to the frame type are filled.
struct H2FrameInfo {
  u8 type = 0;
  u8 flags = 0;
  u32 stream_id = 0;
  u32 length = 0;
  i64 ts_us = 0;
  std::string note;
  std::vector<H2HeaderField> headers;  // HEADERS / CONTINUATION / PUSH_PROMISE
  u32 error_code = 0;                  // RST_STREAM / GOAWAY
  u32 settings_id = 0;                 // first SETTINGS entry
  u32 settings_value = 0;
  u32 increment = 0;                   // WINDOW_UPDATE
  std::size_t data_len = 0;            // DATA payload (without padding)
  bool end_stream = false;
  bool end_headers = false;
  bool ack = false;
  bool padded = false;
};

// One request/response exchange on a stream.
struct H2Message {
  u32 stream_id = 0;
  bool is_request = false;
  std::string method, path, authority, scheme, status, content_type;
  std::vector<H2HeaderField> request_headers, response_headers;
  Bytes request_body, response_body;
  std::size_t request_body_bytes = 0, response_body_bytes = 0;
  bool request_complete = false, response_complete = false;
  bool truncated = false;  // a body was longer than the capture limit
  i64 first_us = 0, last_us = 0;
  std::string note;
  std::string summary() const;
};

struct H2Stats {
  u64 frames = 0, data_frames = 0, header_frames = 0, continuation_frames = 0;
  u64 settings_frames = 0, ping_frames = 0, goaway_frames = 0, rst_frames = 0;
  u64 window_update_frames = 0, priority_frames = 0, push_frames = 0, unknown_frames = 0;
  u64 header_bytes = 0, body_bytes = 0, streams = 0;
  u64 decode_errors = 0, stream_errors = 0;
  bool preface_seen = false, huffman_used = false, dynamic_table_used = false;
  std::size_t header_table_size = 4096, dynamic_table_entries = 0;
  u32 last_error_code = 0;
  std::string last_error;
  std::size_t bytes_in = 0;
};

// HPACK decoder for one direction of a connection.
class HpackDecoder {
 public:
  HpackDecoder();

  // Decodes one complete header block fragment list.
  bool decode(const u8* data, std::size_t len, std::vector<H2HeaderField>* out,
              std::string* error);
  void reset();

  // SETTINGS_HEADER_TABLE_SIZE: the largest table the peer may ask for.
  void set_max_allowed(std::size_t bytes);
  std::size_t max_allowed() const { return max_allowed_; }
  std::size_t max_size() const { return max_size_; }
  std::size_t table_entries() const { return table_.size(); }
  std::size_t table_bytes() const { return table_bytes_; }
  bool used_huffman() const { return used_huffman_; }
  bool used_dynamic_table() const { return used_dynamic_; }
  std::string describe() const;

 private:
  bool lookup(std::size_t index, H2HeaderField* out, std::string* error) const;
  void add_to_table(const H2HeaderField& f);
  void evict();

  std::vector<H2HeaderField> table_;  // newest first; index 62 is table_[0]
  std::size_t table_bytes_ = 0;
  std::size_t max_size_ = 4096;
  std::size_t max_allowed_ = 4096;
  bool used_huffman_ = false;
  bool used_dynamic_ = false;
};

// Decodes the HTTP/2 connection layer. Feed it the bytes of each direction as
// they become available (in order); it keeps the frame and HPACK state.
class H2Connection {
 public:
  H2Connection();

  void reset();
  void feed(int dir, const u8* data, std::size_t len, i64 ts_us);

  bool preface_seen() const { return stats_.preface_seen; }
  bool is_http2() const { return confirmed_; }
  bool rejected() const { return rejected_; }
  const std::string& error() const { return error_; }
  const std::vector<H2FrameInfo>& frames() const { return frames_; }
  const std::vector<H2Message>& messages() const { return messages_; }
  const H2Stats& stats() const { return stats_; }
  const HpackDecoder& decoder(int dir) const { return dec_[dir == 1 ? 1 : 0]; }

  void set_max_body(std::size_t bytes) { max_body_ = bytes; }
  void set_max_frames(std::size_t frames) { max_frames_ = frames; }

  std::string describe() const;

 private:
  void parse(int dir, i64 ts_us);
  void handle_frame(int dir, H2FrameInfo* frame, const u8* payload, i64 ts_us);
  void handle_header_block(int dir, u32 stream_id, bool end_stream, i64 ts_us,
                           std::vector<H2HeaderField>* fields);

  H2Message& message_for(u32 stream_id, i64 ts_us);
  void apply_headers(H2Message& m, int dir, const std::vector<H2HeaderField>& fields);
  void note_error(const std::string& text, u32 code);

  std::vector<u8> buf_[2];
  std::map<u32, Bytes> fragment_[2];
  std::map<u32, bool> fragment_end_stream_[2];
  HpackDecoder dec_[2];
  std::vector<H2FrameInfo> frames_;
  std::vector<H2Message> messages_;
  std::map<u32, std::size_t> message_index_;
  H2Stats stats_;
  std::size_t max_body_ = 65536;
  std::size_t max_frames_ = 100000;
  bool confirmed_ = false;
  bool rejected_ = false;
  std::string error_;
};

}  // namespace netcap
