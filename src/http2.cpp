#include "netcap/http2.hpp"

#include <algorithm>
#include <cstring>

namespace netcap {

const char* h2_frame_type_name(u8 type) {
  switch (type) {
    case H2_DATA: return "DATA";
    case H2_HEADERS: return "HEADERS";
    case H2_PRIORITY: return "PRIORITY";
    case H2_RST_STREAM: return "RST_STREAM";
    case H2_SETTINGS: return "SETTINGS";
    case H2_PUSH_PROMISE: return "PUSH_PROMISE";
    case H2_PING: return "PING";
    case H2_GOAWAY: return "GOAWAY";
    case H2_WINDOW_UPDATE: return "WINDOW_UPDATE";
    case H2_CONTINUATION: return "CONTINUATION";
    default: return "UNKNOWN";
  }
}

const char* h2_error_name(u32 code) {
  switch (code) {
    case 0x0: return "NO_ERROR";
    case 0x1: return "PROTOCOL_ERROR";
    case 0x2: return "INTERNAL_ERROR";
    case 0x3: return "FLOW_CONTROL_ERROR";
    case 0x4: return "SETTINGS_TIMEOUT";
    case 0x5: return "STREAM_CLOSED";
    case 0x6: return "FRAME_SIZE_ERROR";
    case 0x7: return "REFUSED_STREAM";
    case 0x8: return "CANCEL";
    case 0x9: return "COMPRESSION_ERROR";
    case 0xa: return "CONNECT_ERROR";
    case 0xb: return "ENHANCE_YOUR_CALM";
    case 0xc: return "INADEQUATE_SECURITY";
    case 0xd: return "HTTP_1_1_REQUIRED";
    default: return "UNKNOWN_ERROR";
  }
}

std::string H2Message::summary() const {
  std::string s;
  if (!method.empty()) {
    s = method;
    if (!path.empty()) s += " " + path;
  }
  if (!status.empty()) {
    if (!s.empty()) s += " -> ";
    s += status;
  }
  if (s.empty()) s = "stream " + std::to_string(stream_id);
  if (request_body_bytes) s += " [" + std::to_string(request_body_bytes) + "B body]";
  if (response_body_bytes) s += " [" + std::to_string(response_body_bytes) + "B response]";
  return s;
}

// ---------------------------------------------------------------- HPACK

namespace {

// RFC 7541 Appendix A: the static table, 1-based (entry 0 unused).
struct HpackStaticEntry {
  const char* name;
  const char* value;  // null means "no value in the static table"
};

const HpackStaticEntry kHpackStatic[] = {
    {nullptr, nullptr},
    {":authority", nullptr},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", nullptr},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", nullptr},
    {"accept-ranges", nullptr},
    {"accept", nullptr},
    {"access-control-allow-origin", nullptr},
    {"age", nullptr},
    {"allow", nullptr},
    {"authorization", nullptr},
    {"cache-control", nullptr},
    {"content-disposition", nullptr},
    {"content-encoding", nullptr},
    {"content-language", nullptr},
    {"content-length", nullptr},
    {"content-location", nullptr},
    {"content-range", nullptr},
    {"content-type", nullptr},
    {"cookie", nullptr},
    {"date", nullptr},
    {"etag", nullptr},
    {"expect", nullptr},
    {"expires", nullptr},
    {"from", nullptr},
    {"host", nullptr},
    {"if-match", nullptr},
    {"if-modified-since", nullptr},
    {"if-none-match", nullptr},
    {"if-range", nullptr},
    {"if-unmodified-since", nullptr},
    {"last-modified", nullptr},
    {"link", nullptr},
    {"location", nullptr},
    {"max-forwards", nullptr},
    {"proxy-authenticate", nullptr},
    {"proxy-authorization", nullptr},
    {"range", nullptr},
    {"referer", nullptr},
    {"refresh", nullptr},
    {"retry-after", nullptr},
    {"server", nullptr},
    {"set-cookie", nullptr},
    {"strict-transport-security", nullptr},
    {"transfer-encoding", nullptr},
    {"user-agent", nullptr},
    {"vary", nullptr},
    {"via", nullptr},
    {"www-authenticate", nullptr},
};

constexpr std::size_t kHpackStaticCount = 61;

// RFC 7541 Appendix B: the Huffman code table. Symbol 256 is EOS.
struct HpackHuffCode {
  u32 code;
  u8 bits;
};

const HpackHuffCode kHpackHuff[257] = {
    {0x1ff8, 13},     {0x7fffd8, 23},   {0xfffffe2, 28},  {0xfffffe3, 28},  {0xfffffe4, 28},
    {0xfffffe5, 28},  {0xfffffe6, 28},  {0xfffffe7, 28},  {0xfffffe8, 28},  {0xffffea, 24},
    {0x3ffffffc, 30}, {0xfffffe9, 28},  {0xfffffea, 28},  {0x3ffffffd, 30}, {0xfffffeb, 28},
    {0xfffffec, 28},  {0xfffffed, 28},  {0xfffffee, 28},  {0xfffffef, 28},  {0xffffff0, 28},
    {0xffffff1, 28},  {0xffffff2, 28},  {0x3ffffffe, 30}, {0xffffff3, 28},  {0xffffff4, 28},
    {0xffffff5, 28},  {0xffffff6, 28},  {0xffffff7, 28},  {0xffffff8, 28},  {0xffffff9, 28},
    {0xffffffa, 28},  {0xffffffb, 28},  {0x14, 6},        {0x3f8, 10},      {0x3f9, 10},
    {0xffa, 12},      {0x1ff9, 13},     {0x15, 6},        {0xf8, 8},        {0x7fa, 11},
    {0x3fa, 10},      {0x3fb, 10},      {0xf9, 8},        {0x7fb, 11},      {0xfa, 8},
    {0x16, 6},        {0x17, 6},        {0x18, 6},        {0x0, 5},         {0x1, 5},
    {0x2, 5},         {0x19, 6},        {0x1a, 6},        {0x1b, 6},        {0x1c, 6},
    {0x1d, 6},        {0x1e, 6},        {0x1f, 6},        {0x5c, 7},        {0xfb, 8},
    {0x7ffc, 15},     {0x20, 6},        {0xffb, 12},      {0x3fc, 10},      {0x1ffa, 13},
    {0x21, 6},        {0x5d, 7},        {0x5e, 7},        {0x5f, 7},        {0x60, 7},
    {0x61, 7},        {0x62, 7},        {0x63, 7},        {0x64, 7},        {0x65, 7},
    {0x66, 7},        {0x67, 7},        {0x68, 7},        {0x69, 7},        {0x6a, 7},
    {0x6b, 7},        {0x6c, 7},        {0x6d, 7},        {0x6e, 7},        {0x6f, 7},
    {0x70, 7},        {0x71, 7},        {0x72, 7},        {0xfc, 8},        {0x73, 7},
    {0xfd, 8},        {0x1ffb, 13},     {0x7fff0, 19},    {0x1ffc, 13},     {0x3ffc, 14},
    {0x22, 6},        {0x7ffd, 15},     {0x3, 5},         {0x23, 6},        {0x4, 5},
    {0x24, 6},        {0x5, 5},         {0x25, 6},        {0x26, 6},        {0x27, 6},
    {0x6, 5},         {0x74, 7},        {0x75, 7},        {0x28, 6},        {0x29, 6},
    {0x2a, 6},        {0x7, 5},         {0x2b, 6},        {0x76, 7},        {0x2c, 6},
    {0x8, 5},         {0x9, 5},         {0x2d, 6},        {0x77, 7},        {0x78, 7},
    {0x79, 7},        {0x7a, 7},        {0x7b, 7},        {0x7ffe, 15},     {0x7fc, 11},
    {0x3ffd, 14},     {0x1ffd, 13},     {0xffffffc, 28},  {0xfffe6, 20},    {0x3fffd2, 22},
    {0xfffe7, 20},    {0xfffe8, 20},    {0x3fffd3, 22},   {0x3fffd4, 22},   {0x3fffd5, 22},
    {0x7fffd9, 23},   {0x3fffd6, 22},   {0x7fffda, 23},   {0x7fffdb, 23},   {0x7fffdc, 23},
    {0x7fffdd, 23},   {0x7fffde, 23},   {0xffffeb, 24},   {0x7fffdf, 23},   {0xffffec, 24},
    {0xffffed, 24},   {0x3fffd7, 22},   {0x7fffe0, 23},   {0xffffee, 24},   {0x7fffe1, 23},
    {0x7fffe2, 23},   {0x7fffe3, 23},   {0x7fffe4, 23},   {0x1fffdc, 21},   {0x3fffd8, 22},
    {0x7fffe5, 23},   {0x3fffd9, 22},   {0x7fffe6, 23},   {0x7fffe7, 23},   {0xffffef, 24},
    {0x3fffda, 22},   {0x1fffdd, 21},   {0xfffe9, 20},    {0x3fffdb, 22},   {0x3fffdc, 22},
    {0x7fffe8, 23},   {0x7fffe9, 23},   {0x1fffde, 21},   {0x7fffea, 23},   {0x3fffdd, 22},
    {0x3fffde, 22},   {0xfffff0, 24},   {0x1fffdf, 21},   {0x3fffdf, 22},   {0x7fffeb, 23},
    {0x7fffec, 23},   {0x1fffe0, 21},   {0x1fffe1, 21},   {0x3fffe0, 22},   {0x1fffe2, 21},
    {0x7fffed, 23},   {0x3fffe1, 22},   {0x7fffee, 23},   {0x7fffef, 23},   {0xfffea, 20},
    {0x3fffe2, 22},   {0x3fffe3, 22},   {0x3fffe4, 22},   {0x7ffff0, 23},   {0x3fffe5, 22},
    {0x3fffe6, 22},   {0x7ffff1, 23},   {0x3ffffe0, 26},  {0x3ffffe1, 26},  {0xfffeb, 20},
    {0x7fff1, 19},    {0x3fffe7, 22},   {0x7ffff2, 23},   {0x3fffe8, 22},   {0x1ffffec, 25},
    {0x3ffffe2, 26},  {0x3ffffe3, 26},  {0x3ffffe4, 26},  {0x7ffffde, 27},  {0x7ffffdf, 27},
    {0x3ffffe5, 26},  {0xfffff1, 24},   {0x1ffffed, 25},  {0x7fff2, 19},    {0x1fffe3, 21},
    {0x3ffffe6, 26},  {0x7ffffe0, 27},  {0x7ffffe1, 27},  {0x3ffffe7, 26},  {0x7ffffe2, 27},
    {0xfffff2, 24},   {0x1fffe4, 21},   {0x1fffe5, 21},   {0x3ffffe8, 26},  {0x3ffffe9, 26},
    {0xffffffd, 28},  {0x7ffffe3, 27},  {0x7ffffe4, 27},  {0x7ffffe5, 27},  {0xfffec, 20},
    {0xfffff3, 24},   {0xfffed, 20},    {0x1fffe6, 21},   {0x3fffe9, 22},   {0x1fffe7, 21},
    {0x1fffe8, 21},   {0x7ffff3, 23},   {0x3fffea, 22},   {0x3fffeb, 22},   {0x1ffffee, 25},
    {0x1ffffef, 25},  {0xfffff4, 24},   {0xfffff5, 24},   {0x3ffffea, 26},  {0x7ffff4, 23},
    {0x3ffffeb, 26},  {0x7ffffe6, 27},  {0x3ffffec, 26},  {0x3ffffed, 26},  {0x7ffffe7, 27},
    {0x7ffffe8, 27},  {0x7ffffe9, 27},  {0x7ffffea, 27},  {0x7ffffeb, 27},  {0xffffffe, 28},
    {0x7ffffec, 27},  {0x7ffffed, 27},  {0x7ffffee, 27},  {0x7ffffef, 27},  {0x7fffff0, 27},
    {0x3ffffee, 26},  {0x3fffffff, 30},
};

int huffman_symbol(u32 code, int bits) {
  for (int i = 0; i < 257; ++i) {
    if (kHpackHuff[i].bits == bits && kHpackHuff[i].code == code) return i;
  }
  return -1;
}

bool huffman_decode(const u8* in, std::size_t len, std::string* out, std::string* error) {
  u32 code = 0;
  int bits = 0;
  for (std::size_t i = 0; i < len; ++i) {
    const u8 b = in[i];
    for (int k = 7; k >= 0; --k) {
      code = (code << 1) | u32((b >> k) & 1);
      ++bits;
      if (bits > 30) {
        *error = "hpack: huffman code longer than 30 bits";
        return false;
      }
      const int sym = huffman_symbol(code, bits);
      if (sym >= 0) {
        if (sym == 256) {
          *error = "hpack: huffman EOS symbol inside a string";
          return false;
        }
        out->push_back(char(sym));
        code = 0;
        bits = 0;
      }
    }
  }
  // Trailing bits must be a prefix of the EOS code, which is all ones.
  if (bits > 7) {
    *error = "hpack: truncated huffman code";
    return false;
  }
  if (bits > 0 && code != ((1u << bits) - 1)) {
    *error = "hpack: bad huffman padding";
    return false;
  }
  return true;
}

// RFC 7541 section 5.1: prefixed integer.
bool hpack_read_int(const u8* p, std::size_t len, std::size_t* pos, int prefix_bits, u64* out,
                    std::string* error) {
  if (*pos >= len) {
    *error = "hpack: truncated integer";
    return false;
  }
  const u32 mask = (1u << prefix_bits) - 1;
  u64 v = p[*pos] & mask;
  ++*pos;
  if (v < mask) {
    *out = v;
    return true;
  }
  int shift = 0;
  for (;;) {
    if (*pos >= len) {
      *error = "hpack: truncated integer";
      return false;
    }
    const u8 b = p[(*pos)++];
    v += u64(b & 0x7f) << shift;
    shift += 7;
    if (shift > 56) {
      *error = "hpack: integer overflow";
      return false;
    }
    if ((b & 0x80) == 0) break;
  }
  *out = v;
  return true;
}

// RFC 7541 section 5.2: length-prefixed string, optionally Huffman coded.
bool hpack_read_string(const u8* p, std::size_t len, std::size_t* pos, std::string* out,
                       bool* huffman, std::string* error) {
  if (*pos >= len) {
    *error = "hpack: truncated string";
    return false;
  }
  const bool huff = (p[*pos] & 0x80) != 0;
  u64 n = 0;
  if (!hpack_read_int(p, len, pos, 7, &n, error)) return false;
  if (n > len - *pos) {
    *error = "hpack: string length past the end of the block";
    return false;
  }
  if (huff) {
    if (!huffman_decode(p + *pos, std::size_t(n), out, error)) return false;
  } else {
    out->assign(reinterpret_cast<const char*>(p + *pos), std::size_t(n));
  }
  *pos += std::size_t(n);
  if (huffman) *huffman = huff;
  return true;
}

}  // namespace

HpackDecoder::HpackDecoder() { reset(); }

void HpackDecoder::reset() {
  table_.clear();
  table_bytes_ = 0;
  max_size_ = 4096;
  max_allowed_ = 4096;
  used_huffman_ = false;
  used_dynamic_ = false;
}

void HpackDecoder::set_max_allowed(std::size_t bytes) {
  max_allowed_ = bytes;
  if (max_size_ > max_allowed_) {
    max_size_ = max_allowed_;
    evict();
  }
}

bool HpackDecoder::lookup(std::size_t index, H2HeaderField* out, std::string* error) const {
  if (index == 0) {
    *error = "hpack: header index 0 is invalid";
    return false;
  }
  if (index <= kHpackStaticCount) {
    const HpackStaticEntry& e = kHpackStatic[index];
    out->name = e.name ? e.name : "";
    out->value = e.value ? e.value : "";
    return true;
  }
  const std::size_t dyn = index - kHpackStaticCount - 1;
  if (dyn >= table_.size()) {
    *error = "hpack: header index " + std::to_string(index) + " is beyond the dynamic table";
    return false;
  }
  *out = table_[dyn];
  return true;
}

void HpackDecoder::add_to_table(const H2HeaderField& f) {
  const std::size_t size = f.name.size() + f.value.size() + 32;
  if (size > max_size_) {
    // RFC 7541 section 4.4: an entry larger than the table empties the table.
    table_.clear();
    table_bytes_ = 0;
    return;
  }
  table_.insert(table_.begin(), f);
  table_bytes_ += size;
  evict();
  used_dynamic_ = true;
}

void HpackDecoder::evict() {
  while (table_bytes_ > max_size_ && !table_.empty()) {
    table_bytes_ -= table_.back().name.size() + table_.back().value.size() + 32;
    table_.pop_back();
  }
}

bool HpackDecoder::decode(const u8* data, std::size_t len, std::vector<H2HeaderField>* out,
                          std::string* error) {
  std::size_t pos = 0;
  while (pos < len) {
    const u8 b = data[pos];
    if (b & 0x80) {
      // Indexed header field.
      u64 index = 0;
      if (!hpack_read_int(data, len, &pos, 7, &index, error)) return false;
      H2HeaderField f;
      if (!lookup(std::size_t(index), &f, error)) return false;
      out->push_back(f);
      continue;
    }
    const bool incremental = (b & 0xc0) == 0x40;
    const bool table_update = (b & 0xe0) == 0x20;
    if (table_update) {
      u64 size = 0;
      if (!hpack_read_int(data, len, &pos, 5, &size, error)) return false;
      if (size > max_allowed_) {
        *error = "hpack: dynamic table size " + std::to_string(size) +
                 " exceeds the negotiated limit " + std::to_string(max_allowed_);
        return false;
      }
      max_size_ = std::size_t(size);
      evict();
      continue;
    }
    // Literal header field: with incremental indexing (01), without (0000) or
    // never indexed (0001).
    const int prefix = incremental ? 6 : 4;
    u64 index = 0;
    if (!hpack_read_int(data, len, &pos, prefix, &index, error)) return false;
    H2HeaderField f;
    if (index != 0) {
      if (!lookup(std::size_t(index), &f, error)) return false;
    } else {
      bool huff = false;
      if (!hpack_read_string(data, len, &pos, &f.name, &huff, error)) return false;
      if (huff) used_huffman_ = true;
    }
    bool huff = false;
    if (!hpack_read_string(data, len, &pos, &f.value, &huff, error)) return false;
    if (huff) used_huffman_ = true;
    if (incremental) add_to_table(f);
    out->push_back(f);
  }
  return true;
}

std::string HpackDecoder::describe() const {
  std::string s = "HPACK table " + std::to_string(table_.size()) + " ent/" +
                  std::to_string(table_bytes_) + "B of " + std::to_string(max_size_) + "B";
  if (used_huffman_) s += ", huffman";
  if (used_dynamic_) s += ", indexed";
  return s;
}

// ------------------------------------------------------------ H2Connection

H2Connection::H2Connection() { reset(); }

void H2Connection::reset() {
  buf_[0].clear();
  buf_[1].clear();
  fragment_[0].clear();
  fragment_[1].clear();
  fragment_end_stream_[0].clear();
  fragment_end_stream_[1].clear();
  dec_[0].reset();
  dec_[1].reset();
  frames_.clear();
  messages_.clear();
  message_index_.clear();
  stats_ = H2Stats();
  confirmed_ = false;
  rejected_ = false;
  error_.clear();
}

void H2Connection::note_error(const std::string& text, u32 code) {
  error_ = text;
  stats_.last_error = text;
  stats_.last_error_code = code;
  ++stats_.decode_errors;
}

void H2Connection::feed(int dir, const u8* data, std::size_t len, i64 ts_us) {
  if (rejected_ || dir < 0 || dir > 1) return;
  if (len) buf_[dir].insert(buf_[dir].end(), data, data + len);
  parse(dir, ts_us);
}

void H2Connection::parse(int dir, i64 ts_us) {
  std::vector<u8>& b = buf_[dir];

  // The client connection preface (RFC 7540 section 3.5). It is also sent on
  // TLS connections, inside the encrypted stream.
  if (dir == 0 && !stats_.preface_seen) {
    static const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const std::size_t plen = sizeof(kPreface) - 1;
    const std::size_t n = std::min(b.size(), plen);
    if (std::memcmp(b.data(), kPreface, n) != 0) {
      // Not the preface: only keep going if what we have still looks like a
      // frame header, otherwise this is not HTTP/2 at all.
      if (b.size() >= 9) {
        const u32 len = (u32(b[0]) << 16) | (u32(b[1]) << 8) | b[2];
        if (len > 16384 || b[3] > H2_CONTINUATION) {
          rejected_ = true;
          error_ = "not HTTP/2 (no client preface)";
          b.clear();
          return;
        }
      } else {
        return;  // wait for more bytes
      }
    } else if (b.size() < plen) {
      return;  // a prefix of the preface so far
    } else {
      stats_.preface_seen = true;
      b.erase(b.begin(), b.begin() + std::ptrdiff_t(plen));
    }
  }

  std::size_t pos = 0;
  while (b.size() - pos >= 9) {
    const u8* p = b.data() + pos;
    H2FrameInfo fi;
    fi.length = (u32(p[0]) << 16) | (u32(p[1]) << 8) | p[2];
    fi.type = p[3];
    fi.flags = p[4];
    fi.stream_id = ((u32(p[5]) << 24) | (u32(p[6]) << 16) | (u32(p[7]) << 8) | p[8]) & 0x7fffffffu;
    fi.ts_us = ts_us;
    fi.end_stream = (fi.flags & H2_FLAG_END_STREAM) != 0;
    fi.end_headers = (fi.flags & H2_FLAG_END_HEADERS) != 0;
    fi.ack = (fi.flags & H2_FLAG_ACK) != 0;
    fi.padded = (fi.flags & H2_FLAG_PADDED) != 0;
    if (fi.length > 16384) {
      rejected_ = true;
      note_error("frame length " + std::to_string(fi.length) + " above 16384", 0x6);
      break;
    }
    if (b.size() - pos < 9 + std::size_t(fi.length)) break;  // wait for the whole frame
    const u8* payload = p + 9;
    ++stats_.frames;
    stats_.bytes_in += 9 + std::size_t(fi.length);
    confirmed_ = true;
    handle_frame(dir, &fi, payload, ts_us);
    frames_.push_back(fi);
    if (frames_.size() > max_frames_) frames_.erase(frames_.begin());
    pos += 9 + std::size_t(fi.length);
  }
  if (pos > 0) b.erase(b.begin(), b.begin() + std::ptrdiff_t(pos));
}

void H2Connection::handle_frame(int dir, H2FrameInfo* frame, const u8* payload, i64 ts_us) {
  H2FrameInfo& f = *frame;
  const std::size_t len = f.length;
  switch (f.type) {
    case H2_DATA: {
      ++stats_.data_frames;
      std::size_t off = 0;
      std::size_t dlen = len;
      if (f.padded) {
        if (len < 1) {
          f.note = "short padded DATA";
          break;
        }
        const std::size_t pad = payload[0];
        off = 1;
        if (pad + 1 > len) {
          f.note = "padding past the end of DATA";
          break;
        }
        dlen = len - 1 - pad;
      }
      f.data_len = dlen;
      stats_.body_bytes += dlen;
      H2Message& m = message_for(f.stream_id, ts_us);
      Bytes& body = dir == 0 ? m.request_body : m.response_body;
      if (dir == 0) {
        m.request_body_bytes += dlen;
      } else {
        m.response_body_bytes += dlen;
      }
      const std::size_t room = body.size() < max_body_ ? max_body_ - body.size() : 0;
      const std::size_t take = std::min(room, dlen);
      if (take) body.insert(body.end(), payload + off, payload + off + take);
      if (take < dlen) m.truncated = true;
      if (f.end_stream) {
        if (dir == 0) {
          m.request_complete = true;
        } else {
          m.response_complete = true;
        }
      }
      m.last_us = ts_us;
      break;
    }
    case H2_HEADERS: {
      ++stats_.header_frames;
      std::size_t off = 0;
      std::size_t hlen = len;
      if (f.padded) {
        if (len < 1) {
          f.note = "short padded HEADERS";
          break;
        }
        const std::size_t pad = payload[0];
        off = 1;
        if (pad + 1 > len) {
          f.note = "padding past the end of HEADERS";
          break;
        }
        hlen = len - 1 - pad;
      }
      if (f.flags & H2_FLAG_PRIORITY) {
        if (hlen < 5) {
          f.note = "short HEADERS priority fields";
          break;
        }
        off += 5;
        hlen -= 5;
      }
      Bytes& frag = fragment_[dir][f.stream_id];
      frag.insert(frag.end(), payload + off, payload + off + hlen);
      fragment_end_stream_[dir][f.stream_id] = f.end_stream;
      stats_.header_bytes += hlen;
      if (f.end_headers) handle_header_block(dir, f.stream_id, f.end_stream, ts_us, &f.headers);
      break;
    }
    case H2_CONTINUATION: {
      ++stats_.continuation_frames;
      Bytes& frag = fragment_[dir][f.stream_id];
      frag.insert(frag.end(), payload, payload + len);
      stats_.header_bytes += len;
      const bool end_stream = fragment_end_stream_[dir].count(f.stream_id)
                                  ? fragment_end_stream_[dir][f.stream_id]
                                  : false;
      if (f.end_headers) handle_header_block(dir, f.stream_id, end_stream, ts_us, &f.headers);
      break;
    }
    case H2_PUSH_PROMISE: {
      ++stats_.push_frames;
      std::size_t off = 0;
      std::size_t hlen = len;
      if (f.padded) {
        if (len < 1) {
          f.note = "short padded PUSH_PROMISE";
          break;
        }
        const std::size_t pad = payload[0];
        off = 1;
        if (pad + 1 > len) {
          f.note = "padding past the end of PUSH_PROMISE";
          break;
        }
        hlen = len - 1 - pad;
      }
      if (hlen < 4) {
        f.note = "short PUSH_PROMISE";
        break;
      }
      const u32 promised = rd32be(payload + off) & 0x7fffffffu;
      off += 4;
      hlen -= 4;
      f.note = "promised stream " + std::to_string(promised);
      Bytes& frag = fragment_[dir][promised];
      frag.insert(frag.end(), payload + off, payload + off + hlen);
      fragment_end_stream_[dir][promised] = f.end_stream;
      stats_.header_bytes += hlen;
      if (f.end_headers) handle_header_block(dir, promised, f.end_stream, ts_us, &f.headers);
      break;
    }
    case H2_SETTINGS: {
      ++stats_.settings_frames;
      if (f.ack) {
        f.note = "acknowledged";
        break;
      }
      if (len % 6 != 0) {
        f.note = "SETTINGS length is not a multiple of 6";
        note_error("malformed SETTINGS frame", 0x6);
        break;
      }
      bool first = true;
      for (std::size_t i = 0; i + 6 <= len; i += 6) {
        const u16 id = rd16be(payload + i);
        const u32 value = rd32be(payload + i + 2);
        if (first) {
          f.settings_id = id;
          f.settings_value = value;
          first = false;
        }
        if (id == H2_SETTING_HEADER_TABLE_SIZE) {
          // The sender of this SETTINGS frame caps the table its own headers
          // may be encoded with, which is the table we decode that direction.
          dec_[dir].set_max_allowed(value);
        }
      }
      f.note = std::to_string(len / 6) + " setting(s)";
      break;
    }
    case H2_RST_STREAM: {
      ++stats_.rst_frames;
      if (len < 4) {
        f.note = "short RST_STREAM";
        break;
      }
      f.error_code = rd32be(payload);
      ++stats_.stream_errors;
      stats_.last_error_code = f.error_code;
      H2Message& m = message_for(f.stream_id, ts_us);
      m.note = std::string("stream reset: ") + h2_error_name(f.error_code);
      m.request_complete = true;
      m.response_complete = true;
      m.last_us = ts_us;
      break;
    }
    case H2_GOAWAY: {
      ++stats_.goaway_frames;
      if (len < 8) {
        f.note = "short GOAWAY";
        break;
      }
      const u32 last = rd32be(payload) & 0x7fffffffu;
      f.error_code = rd32be(payload + 4);
      stats_.last_error_code = f.error_code;
      f.note = "last stream " + std::to_string(last) + ", " + h2_error_name(f.error_code);
      break;
    }
    case H2_PING: {
      ++stats_.ping_frames;
      f.note = f.ack ? "acknowledged" : "ping";
      break;
    }
    case H2_WINDOW_UPDATE: {
      ++stats_.window_update_frames;
      if (len < 4) {
        f.note = "short WINDOW_UPDATE";
        break;
      }
      f.increment = rd32be(payload) & 0x7fffffffu;
      break;
    }
    case H2_PRIORITY: {
      ++stats_.priority_frames;
      break;
    }
    default: {
      ++stats_.unknown_frames;
      f.note = "unknown frame type";
      break;
    }
  }
}

void H2Connection::handle_header_block(int dir, u32 stream_id, bool end_stream, i64 ts_us,
                                       std::vector<H2HeaderField>* out_fields) {
  Bytes& frag = fragment_[dir][stream_id];
  std::vector<H2HeaderField> fields;
  std::string err;
  const bool ok = dec_[dir].decode(frag.data(), frag.size(), &fields, &err);
  frag.clear();
  fragment_end_stream_[dir].erase(stream_id);
  H2Message& m = message_for(stream_id, ts_us);
  if (!ok) {
    // Once a header block fails to decode the compression context is off the
    // rails, so nothing after it can be trusted for this direction.
    note_error(err, 0x9);
    if (m.note.empty()) m.note = err;
    return;
  }
  if (dec_[dir].used_huffman()) stats_.huffman_used = true;
  if (dec_[dir].used_dynamic_table()) stats_.dynamic_table_used = true;
  stats_.header_table_size = dec_[dir].max_size();
  stats_.dynamic_table_entries = dec_[dir].table_entries();
  apply_headers(m, dir, fields);
  if (end_stream) {
    if (dir == 0) {
      m.request_complete = true;
    } else {
      m.response_complete = true;
    }
  }
  m.last_us = ts_us;
  if (out_fields) *out_fields = fields;
}

void H2Connection::apply_headers(H2Message& m, int dir, const std::vector<H2HeaderField>& fields) {
  std::vector<H2HeaderField>& dst = dir == 0 ? m.request_headers : m.response_headers;
  for (const H2HeaderField& f : fields) {
    if (!f.name.empty() && f.name[0] == ':') {
      if (f.name == ":method") {
        m.method = f.value;
        m.is_request = true;
      } else if (f.name == ":path") {
        m.path = f.value;
      } else if (f.name == ":authority") {
        m.authority = f.value;
      } else if (f.name == ":scheme") {
        m.scheme = f.value;
      } else if (f.name == ":status") {
        m.status = f.value;
        if (m.method.empty()) m.is_request = false;
      }
    } else if (f.name == "content-type" && m.content_type.empty()) {
      m.content_type = f.value;
    }
    dst.push_back(f);
  }
}

H2Message& H2Connection::message_for(u32 stream_id, i64 ts_us) {
  const auto it = message_index_.find(stream_id);
  if (it != message_index_.end()) return messages_[it->second];
  H2Message m;
  m.stream_id = stream_id;
  m.is_request = (stream_id % 2) == 1;  // client initiated streams are odd
  m.first_us = ts_us;
  m.last_us = ts_us;
  messages_.push_back(m);
  message_index_[stream_id] = messages_.size() - 1;
  ++stats_.streams;
  return messages_.back();
}

std::string H2Connection::describe() const {
  std::string s = "HTTP/2";
  if (!confirmed_) s += " (no frames yet)";
  s += ", " + std::to_string(stats_.frames) + " frame(s), " + std::to_string(stats_.streams) +
       " stream(s)";
  if (stats_.preface_seen) s += ", preface";
  if (stats_.huffman_used) s += ", huffman";
  if (stats_.dynamic_table_used) {
    s += ", hpack " + std::to_string(stats_.dynamic_table_entries) + " ent/" +
         std::to_string(stats_.header_table_size) + "B";
  }
  if (stats_.decode_errors) s += ", " + std::to_string(stats_.decode_errors) + " decode error(s)";
  if (stats_.stream_errors) s += ", " + std::to_string(stats_.stream_errors) + " stream error(s)";
  return s;
}

}  // namespace netcap
