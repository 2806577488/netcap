#include "netcap/rewrite.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "netcap/regex.hpp"
#include "netcap/brotli.hpp"
#include "netcap/brotli_encode.hpp"  // a `br` body that still fits goes back out as `br`

namespace netcap {
namespace {

std::string lower(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::string trim(const std::string& s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
  return s.substr(b, e - b);
}

std::string media_type(const std::string& value) {
  std::string v = lower(trim(value));
  const std::size_t semi = v.find(';');
  if (semi != std::string::npos) v = trim(v.substr(0, semi));
  return v;
}

bool is_hex_digit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string number(std::size_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%zu", v);
  return std::string(buf);
}

// ------------------------------------------------------------------ inflate

constexpr std::size_t kMaxInflate = 32u * 1024u * 1024u;

struct BitReader {
  const u8* data = nullptr;
  std::size_t len = 0;
  std::size_t pos = 0;
  u32 buf = 0;
  int have = 0;
  bool bad = false;

  bool fill(int need) {
    while (have < need) {
      if (pos >= len) {
        bad = true;
        return false;
      }
      buf |= static_cast<u32>(data[pos++]) << have;
      have += 8;
    }
    return true;
  }

  u32 bits(int count) {
    if (count == 0) return 0;
    if (!fill(count)) return 0;
    const u32 v = buf & ((1u << count) - 1u);
    buf >>= count;
    have -= count;
    return v;
  }

  void align() {
    const int drop = have % 8;
    buf >>= drop;
    have -= drop;
  }
};

// Canonical Huffman decoding: the count of codes per length plus the symbols in
// canonical order, exactly as RFC 1951 section 3.2.2 describes.
struct Huffman {
  u16 counts[16] = {0};
  std::vector<u16> symbols;

  bool build(const std::vector<u8>& lengths, std::string* error) {
    for (int i = 0; i < 16; ++i) counts[i] = 0;
    for (u8 l : lengths) {
      if (l > 15) {
        if (error != nullptr) *error = "a Huffman code length is larger than 15";
        return false;
      }
      counts[l]++;
    }
    counts[0] = 0;
    // Kraft inequality: an over-subscribed code cannot be decoded.
    int left = 1;
    for (int len = 1; len <= 15; ++len) {
      left <<= 1;
      left -= counts[len];
      if (left < 0) {
        if (error != nullptr) *error = "the Huffman code lengths are over-subscribed";
        return false;
      }
    }
    std::vector<u16> offsets(16, 0);
    for (int len = 1; len < 15; ++len) offsets[len + 1] = static_cast<u16>(offsets[len] + counts[len]);
    symbols.assign(static_cast<std::size_t>(offsets[15] + counts[15]), 0);
    std::size_t written = 0;
    for (std::size_t sym = 0; sym < lengths.size(); ++sym) {
      if (lengths[sym] != 0) {
        symbols[offsets[lengths[sym]]++] = static_cast<u16>(sym);
        ++written;
      }
    }
    return true;
  }

  int decode(BitReader& br) const {
    int code = 0;
    int first = 0;
    int index = 0;
    for (int len = 1; len <= 15; ++len) {
      code |= static_cast<int>(br.bits(1));
      if (br.bad) return -1;
      const int count = counts[len];
      if (code - first < count) return symbols[static_cast<std::size_t>(index + (code - first))];
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    return -1;
  }
};

const u16 kLengthBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                             31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const u8 kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                             2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const u16 kDistBase[30] = {1,    2,    3,    4,    5,    7,     9,     13,    17,   25,
                           33,   49,   65,   97,   129,  193,   257,   385,   513,  769,
                           1025, 1537, 2049, 3073, 4097, 6145,  8193,  12289, 16385, 24577};
const u8 kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                           6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
const u8 kCodeLengthOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

bool build_fixed(Huffman* lit, Huffman* dist, std::string* error) {
  std::vector<u8> lit_lengths(288, 0);
  for (int i = 0; i < 144; ++i) lit_lengths[static_cast<std::size_t>(i)] = 8;
  for (int i = 144; i < 256; ++i) lit_lengths[static_cast<std::size_t>(i)] = 9;
  for (int i = 256; i < 280; ++i) lit_lengths[static_cast<std::size_t>(i)] = 7;
  for (int i = 280; i < 288; ++i) lit_lengths[static_cast<std::size_t>(i)] = 8;
  if (!lit->build(lit_lengths, error)) return false;
  std::vector<u8> dist_lengths(30, 5);
  return dist->build(dist_lengths, error);
}

bool inflate_raw(const u8* data, std::size_t len, std::string* out, std::string* error) {
  BitReader br;
  br.data = data;
  br.len = len;
  out->clear();
  for (;;) {
    const u32 final_block = br.bits(1);
    const u32 type = br.bits(2);
    if (br.bad) {
      if (error != nullptr) *error = "the deflate stream ended in the middle of a block header";
      return false;
    }
    if (type == 0) {
      br.align();
      if (!br.fill(32)) {
        if (error != nullptr) *error = "the deflate stream ended in a stored block header";
        return false;
      }
      const u32 stored_len = br.bits(16);
      const u32 stored_inv = br.bits(16);
      if ((stored_len ^ 0xffffu) != stored_inv) {
        if (error != nullptr) *error = "a stored block has mismatched length fields";
        return false;
      }
      for (u32 i = 0; i < stored_len; ++i) {
        if (!br.fill(8)) {
          if (error != nullptr) *error = "a stored block is shorter than its length field";
          return false;
        }
        out->push_back(static_cast<char>(br.bits(8)));
      }
    } else if (type == 1 || type == 2) {
      Huffman lit;
      Huffman dist;
      if (type == 1) {
        if (!build_fixed(&lit, &dist, error)) return false;
      } else {
        const u32 hlit = br.bits(5) + 257;
        const u32 hdist = br.bits(5) + 1;
        const u32 hclen = br.bits(4) + 4;
        if (br.bad || hlit > 286 || hdist > 30) {
          if (error != nullptr) *error = "a dynamic block declares an impossible code count";
          return false;
        }
        std::vector<u8> code_lengths(19, 0);
        for (u32 i = 0; i < hclen; ++i) {
          code_lengths[kCodeLengthOrder[i]] = static_cast<u8>(br.bits(3));
        }
        Huffman code_len;
        if (!code_len.build(code_lengths, error)) return false;
        std::vector<u8> lengths;
        lengths.reserve(hlit + hdist);
        while (lengths.size() < hlit + hdist) {
          const int sym = code_len.decode(br);
          if (sym < 0) {
            if (error != nullptr) *error = "a dynamic block has an invalid code-length code";
            return false;
          }
          if (sym < 16) {
            lengths.push_back(static_cast<u8>(sym));
          } else if (sym == 16) {
            if (lengths.empty()) {
              if (error != nullptr) *error = "a code-length repeat has nothing to repeat";
              return false;
            }
            const u8 prev = lengths.back();
            const u32 repeat = 3 + br.bits(2);
            for (u32 i = 0; i < repeat; ++i) lengths.push_back(prev);
          } else if (sym == 17) {
            const u32 repeat = 3 + br.bits(3);
            for (u32 i = 0; i < repeat; ++i) lengths.push_back(0);
          } else {
            const u32 repeat = 11 + br.bits(7);
            for (u32 i = 0; i < repeat; ++i) lengths.push_back(0);
          }
        }
        std::vector<u8> lit_lengths(lengths.begin(), lengths.begin() + hlit);
        std::vector<u8> dist_lengths(lengths.begin() + hlit, lengths.end());
        if (!lit.build(lit_lengths, error)) return false;
        if (!dist.build(dist_lengths, error)) return false;
      }
      for (;;) {
        const int sym = lit.decode(br);
        if (sym < 0) {
          if (error != nullptr) *error = "an invalid literal/length code was read";
          return false;
        }
        if (sym < 256) {
          out->push_back(static_cast<char>(sym));
        } else if (sym == 256) {
          break;
        } else {
          const int li = sym - 257;
          if (li >= 29) {
            if (error != nullptr) *error = "a length code outside the deflate tables was read";
            return false;
          }
          const u32 length = kLengthBase[li] + br.bits(kLengthExtra[li]);
          const int dsym = dist.decode(br);
          if (dsym < 0 || dsym >= 30) {
            if (error != nullptr) *error = "an invalid distance code was read";
            return false;
          }
          const u32 back = kDistBase[dsym] + br.bits(kDistExtra[dsym]);
          if (back == 0 || back > out->size()) {
            if (error != nullptr) *error = "a distance reaches before the start of the output";
            return false;
          }
          const std::size_t start = out->size() - back;
          for (u32 i = 0; i < length; ++i) out->push_back((*out)[start + i]);
        }
        if (out->size() > kMaxInflate) {
          if (error != nullptr) *error = "the inflated body is larger than 32 MiB";
          return false;
        }
        if (br.bad) {
          if (error != nullptr) *error = "the deflate stream ended inside a compressed block";
          return false;
        }
      }
    } else {
      if (error != nullptr) *error = "the deflate stream uses a reserved block type";
      return false;
    }
    if (final_block != 0) break;
    if (out->size() > kMaxInflate) {
      if (error != nullptr) *error = "the inflated body is larger than 32 MiB";
      return false;
    }
  }
  return true;
}

u32 crc32_bytes(const u8* data, std::size_t len) {
  static u32 table[256];
  static bool ready = false;
  if (!ready) {
    for (u32 i = 0; i < 256; ++i) {
      u32 c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
      table[i] = c;
    }
    ready = true;
  }
  u32 c = 0xffffffffu;
  for (std::size_t i = 0; i < len; ++i) c = table[(c ^ data[i]) & 0xffu] ^ (c >> 8);
  return c ^ 0xffffffffu;
}

u32 adler32_bytes(const u8* data, std::size_t len) {
  u32 a = 1;
  u32 b = 0;
  for (std::size_t i = 0; i < len; ++i) {
    a = (a + data[i]) % 65521u;
    b = (b + a) % 65521u;
  }
  return (b << 16) | a;
}

u32 rd32(const u8* p) { return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24); }

bool inflate_gzip(const u8* data, std::size_t len, std::string* out, std::string* error) {
  if (len < 18) {
    if (error != nullptr) *error = "a gzip stream is shorter than its header and trailer";
    return false;
  }
  if (data[0] != 0x1f || data[1] != 0x8b) {
    if (error != nullptr) *error = "a gzip stream does not start with 1f 8b";
    return false;
  }
  if (data[2] != 8) {
    if (error != nullptr) *error = "a gzip stream uses a compression method other than deflate";
    return false;
  }
  const u8 flags = data[3];
  std::size_t pos = 10;
  const auto need = [&](std::size_t n) { return pos + n <= len - 8; };
  if ((flags & 0x04) != 0) {  // FEXTRA
    if (!need(2)) {
      if (error != nullptr) *error = "a gzip extra field is truncated";
      return false;
    }
    const std::size_t xlen = static_cast<std::size_t>(data[pos]) | (static_cast<std::size_t>(data[pos + 1]) << 8);
    pos += 2;
    if (pos + xlen > len - 8) {
      if (error != nullptr) *error = "a gzip extra field is truncated";
      return false;
    }
    pos += xlen;
  }
  if ((flags & 0x08) != 0) {  // FNAME
    while (need(1) && data[pos] != 0) ++pos;
    if (!need(1)) {
      if (error != nullptr) *error = "a gzip file name is not terminated";
      return false;
    }
    ++pos;
  }
  if ((flags & 0x10) != 0) {  // FCOMMENT
    while (need(1) && data[pos] != 0) ++pos;
    if (!need(1)) {
      if (error != nullptr) *error = "a gzip comment is not terminated";
      return false;
    }
    ++pos;
  }
  if ((flags & 0x02) != 0) {  // FHCRC
    if (!need(2)) {
      if (error != nullptr) *error = "a gzip header CRC is truncated";
      return false;
    }
    pos += 2;
  }
  const std::size_t body_len = len - 8 - pos;
  if (!inflate_raw(data + pos, body_len, out, error)) return false;
  const u32 want_crc = rd32(data + len - 8);
  const u32 want_size = rd32(data + len - 4);
  if (want_size != static_cast<u32>(out->size() % 4294967296ull)) {
    if (error != nullptr) *error = "the gzip trailer length does not match the inflated size";
    return false;
  }
  const u32 got_crc = crc32_bytes(reinterpret_cast<const u8*>(out->data()), out->size());
  if (got_crc != want_crc) {
    if (error != nullptr) *error = "the gzip CRC does not match the inflated bytes";
    return false;
  }
  return true;
}

bool inflate_zlib(const u8* data, std::size_t len, std::string* out, std::string* error) {
  if (len < 6) {
    if (error != nullptr) *error = "a zlib stream is shorter than its header and trailer";
    return false;
  }
  if ((data[0] & 0x0f) != 8) {
    if (error != nullptr) *error = "a zlib stream uses a compression method other than deflate";
    return false;
  }
  if (((static_cast<u32>(data[0]) << 8) | data[1]) % 31 != 0) {
    if (error != nullptr) *error = "a zlib header fails its check value";
    return false;
  }
  if ((data[1] & 0x20) != 0) {
    if (error != nullptr) *error = "a zlib stream with a preset dictionary is not supported";
    return false;
  }
  if (!inflate_raw(data + 2, len - 6, out, error)) return false;
  // The zlib trailer is big-endian (RFC 1950 section 2.2), unlike the gzip one.
  const u32 want = (static_cast<u32>(data[len - 4]) << 24) | (static_cast<u32>(data[len - 3]) << 16) |
                   (static_cast<u32>(data[len - 2]) << 8) | static_cast<u32>(data[len - 1]);
  const u32 got = adler32_bytes(reinterpret_cast<const u8*>(out->data()), out->size());
  if (want != got) {
    if (error != nullptr) *error = "the zlib Adler-32 does not match the inflated bytes";
    return false;
  }
  return true;
}

}  // namespace

// ------------------------------------------------------------------- head

const std::string* ResponseHead::find(const std::string& name) const {
  const std::string want = lower(name);
  for (const ResponseHeader& h : headers) {
    if (lower(h.name) == want) return &h.value;
  }
  return nullptr;
}

bool ResponseHead::has(const std::string& name) const { return find(name) != nullptr; }

std::size_t ResponseHead::count(const std::string& name) const {
  const std::string want = lower(name);
  std::size_t n = 0;
  for (const ResponseHeader& h : headers) {
    if (lower(h.name) == want) ++n;
  }
  return n;
}

namespace {

// Recomputes the derived flags from the header list, so that editing a head
// keeps `content_length`, `chunked` and friends consistent with the headers
// that will actually be serialised.
void refresh_derived(ResponseHead* head) {
  head->chunked = false;
  head->has_content_length = false;
  head->content_length = 0;
  head->content_encoding.clear();
  head->content_type.clear();
  for (const ResponseHeader& h : head->headers) {
    const std::string lname = lower(h.name);
    if (lname == "transfer-encoding" && lower(h.value).find("chunked") != std::string::npos) {
      head->chunked = true;
    } else if (lname == "content-length") {
      bool digits = !h.value.empty();
      std::size_t parsed = 0;
      for (char c : h.value) {
        if (c < '0' || c > '9') {
          digits = false;
          break;
        }
        parsed = parsed * 10 + static_cast<std::size_t>(c - '0');
      }
      if (digits) {
        head->has_content_length = true;
        head->content_length = parsed;
      }
    } else if (lname == "content-encoding") {
      head->content_encoding = lower(trim(h.value));
    } else if (lname == "content-type") {
      head->content_type = media_type(h.value);
    }
  }
}

}  // namespace

void ResponseHead::set(const std::string& name, const std::string& value) {
  const std::string want = lower(name);
  bool replaced = false;
  std::vector<ResponseHeader> kept;
  kept.reserve(headers.size() + 1);
  for (const ResponseHeader& h : headers) {
    if (lower(h.name) == want) {
      if (!replaced) {
        ResponseHeader copy = h;
        copy.value = value;
        kept.push_back(copy);
        replaced = true;
      }
      continue;  // duplicate copies collapse into one
    }
    kept.push_back(h);
  }
  if (!replaced) {
    ResponseHeader h;
    h.name = name;
    h.value = value;
    kept.push_back(h);
  }
  headers.swap(kept);
  refresh_derived(this);
}

bool ResponseHead::remove(const std::string& name) { return remove_all(name) > 0; }

std::size_t ResponseHead::remove_all(const std::string& name) {
  const std::string want = lower(name);
  const std::size_t before = headers.size();
  headers.erase(std::remove_if(headers.begin(), headers.end(),
                               [&want](const ResponseHeader& h) { return lower(h.name) == want; }),
                headers.end());
  const std::size_t removed = before - headers.size();
  if (removed != 0) refresh_derived(this);
  return removed;
}

std::string ResponseHead::serialize() const {
  std::string out;
  out.reserve(64 + headers.size() * 48);
  out += version;
  out.push_back(' ');
  out += number(static_cast<std::size_t>(status));
  if (!reason.empty()) {
    out.push_back(' ');
    out += reason;
  }
  out += "\r\n";
  for (const ResponseHeader& h : headers) {
    out += h.name;
    out += ": ";
    out += h.value;
    out += "\r\n";
  }
  out += "\r\n";
  return out;
}

bool parse_header_line(const std::string& line, std::string* name, std::string* value) {
  const std::size_t colon = line.find(':');
  if (colon == std::string::npos) return false;
  const std::string n = trim(line.substr(0, colon));
  if (n.empty()) return false;
  if (name != nullptr) *name = n;
  if (value != nullptr) *value = trim(line.substr(colon + 1));
  return true;
}

bool parse_response_head(const std::string& raw, ResponseHead* out, std::string* error) {
  if (out == nullptr) return false;
  *out = ResponseHead();
  const std::size_t head_end = raw.find("\r\n\r\n");
  if (head_end == std::string::npos) {
    if (error != nullptr) *error = "the response head does not end with a blank line";
    return false;
  }
  const std::string head = raw.substr(0, head_end);
  std::size_t pos = 0;
  bool first = true;
  while (pos <= head.size()) {
    std::size_t nl = head.find("\r\n", pos);
    if (nl == std::string::npos) nl = head.size();
    const std::string line = head.substr(pos, nl - pos);
    pos = nl + 2;
    if (first) {
      first = false;
      const std::size_t sp1 = line.find(' ');
      if (line.compare(0, 5, "HTTP/") != 0 || sp1 == std::string::npos) {
        if (error != nullptr) *error = "the response does not start with a status line";
        return false;
      }
      out->version = line.substr(0, sp1);
      const std::size_t sp2 = line.find(' ', sp1 + 1);
      const std::string code = sp2 == std::string::npos ? line.substr(sp1 + 1) : line.substr(sp1 + 1, sp2 - sp1 - 1);
      if (code.size() != 3 || !std::isdigit(static_cast<unsigned char>(code[0])) ||
          !std::isdigit(static_cast<unsigned char>(code[1])) ||
          !std::isdigit(static_cast<unsigned char>(code[2]))) {
        if (error != nullptr) *error = "the status line does not carry a three digit status code";
        return false;
      }
      out->status = (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
      if (sp2 != std::string::npos) out->reason = line.substr(sp2 + 1);
      continue;
    }
    if (line.empty()) continue;
    std::string name;
    std::string value;
    if (!parse_header_line(line, &name, &value)) {
      if (error != nullptr) *error = "a response header line has no colon: '" + line + "'";
      return false;
    }
    ResponseHeader h;
    h.name = name;
    h.value = value;
    out->headers.push_back(h);
    const std::string lname = lower(name);
    if (lname == "transfer-encoding" && lower(value).find("chunked") != std::string::npos) {
      out->chunked = true;
    } else if (lname == "content-length") {
      bool digits = !value.empty();
      std::size_t parsed = 0;
      for (char c : value) {
        if (c < '0' || c > '9') {
          digits = false;
          break;
        }
        parsed = parsed * 10 + static_cast<std::size_t>(c - '0');
      }
      if (digits) {
        out->has_content_length = true;
        out->content_length = parsed;
      }
    } else if (lname == "content-encoding") {
      out->content_encoding = lower(trim(value));
    } else if (lname == "content-type") {
      out->content_type = media_type(value);
    } else if (lname == "connection") {
      if (lower(value).find("close") != std::string::npos) out->close_delimited = true;
    }
  }
  if (out->version == "HTTP/1.0") out->close_delimited = true;
  if (!out->chunked && !out->has_content_length && out->status != 204 && out->status != 304 &&
      out->status >= 200) {
    out->close_delimited = true;
  }
  return true;
}

// -------------------------------------------------------------- the rules

bool ResponseRewrite::empty() const {
  return set_headers.empty() && remove_headers.empty() && remove_cookies.empty() &&
         replaces.empty() && inject_css.empty() && inject_script.empty();
}

std::size_t ResponseRewrite::size() const {
  return set_headers.size() + remove_headers.size() + remove_cookies.size() + replaces.size() +
         inject_css.size() + inject_script.size();
}

std::string ResponseRewrite::describe() const {
  std::string s;
  const auto add = [&s](const std::string& what) {
    if (!s.empty()) s += ", ";
    s += what;
  };
  if (!set_headers.empty()) add(number(set_headers.size()) + " header(s) set");
  if (!remove_headers.empty()) add(number(remove_headers.size()) + " header(s) removed");
  if (!remove_cookies.empty()) add(number(remove_cookies.size()) + " cookie(s) stripped");
  if (!replaces.empty()) add(number(replaces.size()) + " body replace(s)");
  if (!inject_css.empty()) add(number(inject_css.size()) + " style injection(s)");
  if (!inject_script.empty()) add(number(inject_script.size()) + " script injection(s)");
  return s.empty() ? "nothing" : s;
}

std::string ResponseRewriteReport::describe() const {
  std::string s;
  if (head_changed) s += "head";
  if (body_changed) {
    if (!s.empty()) s += "+";
    s += "body";
  }
  if (s.empty()) s = "unchanged";
  s += " (" + number(replaces) + " replace(s)";
  if (injected_css != 0) s += ", " + number(injected_css) + " style(s)";
  if (injected_script != 0) s += ", " + number(injected_script) + " script(s)";
  s += ")";
  if (dropped_encoding) s += " [encoding dropped]";
  if (skipped_unsupported_encoding) s += " [encoding not supported]";
  if (skipped_no_body) s += " [no body to edit]";
  if (!note.empty()) s += " - " + note;
  return s;
}

// ------------------------------------------------------------- the decoders

bool chunked_decode(const std::string& in, std::string* out, std::string* error) {
  out->clear();
  std::size_t pos = 0;
  for (;;) {
    const std::size_t nl = in.find("\r\n", pos);
    if (nl == std::string::npos) {
      if (error != nullptr) *error = "a chunk size line is not terminated";
      return false;
    }
    const std::string line = in.substr(pos, nl - pos);
    std::size_t semi = line.find(';');
    std::string size_text = trim(semi == std::string::npos ? line : line.substr(0, semi));
    if (size_text.empty() || size_text.size() > 8) {
      if (error != nullptr) *error = "a chunk size is empty or absurdly long";
      return false;
    }
    std::size_t size = 0;
    for (char c : size_text) {
      if (!is_hex_digit(c)) {
        if (error != nullptr) *error = "a chunk size is not hexadecimal";
        return false;
      }
      size = size * 16 + static_cast<std::size_t>(hex_value(c));
    }
    pos = nl + 2;
    if (size == 0) {
      // Trailers run until the blank line.
      for (;;) {
        const std::size_t tnl = in.find("\r\n", pos);
        if (tnl == std::string::npos) {
          if (error != nullptr) *error = "a chunked body ends without its final blank line";
          return false;
        }
        if (tnl == pos) return true;
        pos = tnl + 2;
      }
    }
    if (pos + size + 2 > in.size()) {
      if (error != nullptr) *error = "a chunk is shorter than its size says";
      return false;
    }
    out->append(in, pos, size);
    pos += size;
    if (in.compare(pos, 2, "\r\n") != 0) {
      if (error != nullptr) *error = "a chunk is not followed by CRLF";
      return false;
    }
    pos += 2;
    if (out->size() > kMaxInflate) {
      if (error != nullptr) *error = "the decoded body is larger than 32 MiB";
      return false;
    }
  }
}

bool inflate_body(const std::string& encoding, const std::string& in, std::string* out,
                  std::string* error) {
  const u8* data = reinterpret_cast<const u8*>(in.data());
  const std::size_t len = in.size();
  if (encoding == "gzip" || encoding == "x-gzip") {
    return inflate_gzip(data, len, out, error);
  }
  if (encoding == "deflate") {
    // Servers send both the zlib-wrapped and the bare stream; sniff the header.
    if (len >= 2 && (data[0] & 0x0f) == 8 && (((static_cast<u32>(data[0]) << 8) | data[1]) % 31) == 0) {
      return inflate_zlib(data, len, out, error);
    }
    return inflate_raw(data, len, out, error);
  }
  if (encoding == "br") {
    // Brotli (RFC 7932).  The decoder reports exactly what it cannot do yet in
    // *error; the caller then keeps the body exactly as it arrived instead of
    // pretending it was rewritten.
    return brotli_decompress(data, len, out, error);
  }
  return inflate_raw(data, len, out, error);
}

bool response_body_is_text(const ResponseHead& head) {
  if (head.content_type.empty()) return false;
  const std::string& t = head.content_type;
  return t.compare(0, 5, "text/") == 0 || t == "application/json" || t == "application/javascript" ||
         t == "application/x-javascript" || t == "application/xml" || t == "application/xhtml+xml" ||
         t == "application/rss+xml" || t == "application/atom+xml" || t == "image/svg+xml" ||
         t == "application/x-www-form-urlencoded";
}

std::string strip_alt_svc_header(const std::string& head) {
  std::string out;
  out.reserve(head.size());
  std::size_t pos = 0;
  while (pos < head.size()) {
    const std::size_t nl = head.find("\r\n", pos);
    const std::size_t end = (nl == std::string::npos) ? head.size() : nl + 2;
    const std::string line = head.substr(pos, end - pos);
    const std::size_t colon = line.find(':');
    std::string name = colon == std::string::npos ? std::string() : line.substr(0, colon);
    for (char& ch : name) {
      if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    if (name != "alt-svc") out += line;
    pos = end;
  }
  return out;
}

std::string response_rewrite_limits() {
  return "response rewriting skips zstd bodies, 206 and 304 responses, streaming bodies "
         "(SSE, multipart) and HTTP/2";
}

// ------------------------------------------------------------- the rewriting

namespace {

// Injects `markup` just before the closing tag of `tag` ("head" or "body").
// Returns true when the markup was inserted.
bool inject_before_close(std::string* html, const char* tag, const std::string& markup) {
  const std::string lowered = lower(*html);
  const std::string needle = std::string("</") + tag + ">";
  std::size_t at = std::string::npos;
  for (std::size_t pos = 0;;) {
    const std::size_t found = lowered.find(needle, pos);
    if (found == std::string::npos) break;
    at = found;  // the last closing tag wins
    pos = found + 1;
  }
  if (at == std::string::npos) return false;
  html->insert(at, markup);
  return true;
}

}  // namespace

bool apply_response_rewrite(const ResponseRewrite& rw, ResponseHead* head, std::string* body,
                            ResponseRewriteReport* report, std::string* error) {
  if (head == nullptr || body == nullptr) return false;
  ResponseRewriteReport rep;
  rep.bytes_in = body->size();

  // ---- headers ($csp, $header, $removeheader, $removecookie)
  for (const std::string& line : rw.set_headers) {
    std::string name;
    std::string value;
    if (!parse_header_line(line, &name, &value)) {
      if (error != nullptr) *error = "a $header value is not a 'Name: value' line: '" + line + "'";
      return false;
    }
    head->set(name, value);
    rep.head_changed = true;
  }
  for (const std::string& name : rw.remove_headers) {
    if (head->remove_all(name) > 0) rep.head_changed = true;
  }
  if (!rw.remove_cookies.empty()) {
    const std::string* sc = head->find("set-cookie");
    if (sc != nullptr) {
      std::vector<std::string> kept;
      std::size_t index = 0;
      for (;;) {
        const std::string* value = nullptr;
        std::size_t seen = 0;
        for (const ResponseHeader& h : head->headers) {
          if (lower(h.name) != "set-cookie") continue;
          if (seen == index) {
            value = &h.value;
            break;
          }
          ++seen;
        }
        if (value == nullptr) break;
        const std::size_t eq = value->find('=');
        const std::string cookie = trim(eq == std::string::npos ? *value : value->substr(0, eq));
        bool drop = false;
        for (const std::string& want : rw.remove_cookies) {
          if (want == "*") {  // a bare $removecookie drops every Set-Cookie
            drop = true;
            break;
          }
          if (lower(want) == lower(cookie)) {
            drop = true;
            break;
          }
        }
        if (!drop) kept.push_back(*value);
        ++index;
      }
      if (kept.size() != index) {
        head->remove_all("set-cookie");
        for (const std::string& value : kept) {
          ResponseHeader h;
          h.name = "Set-Cookie";
          h.value = value;
          head->headers.push_back(h);
        }
        rep.head_changed = true;
      }
    }
  }

  // ---- body
  bool wants_body = !rw.replaces.empty() || !rw.inject_css.empty() || !rw.inject_script.empty();
  if (wants_body && rw.replaces.empty() && (!rw.inject_css.empty() || !rw.inject_script.empty()) &&
      !response_body_is_text(*head)) {
    // Element hiding is one <style> inside a document.  A PNG cannot carry it, so
    // do not even take the framing apart: doing that to a chunked image made the
    // event read as `改写` with two hundred element hiding rules beside it, when
    // the only thing that had actually happened was a chunked body being
    // re-framed for an injection that could never apply.
    rep.skipped_no_body = true;
    rep.note = "element hiding rules do not apply to this media type";
    wants_body = false;
  }
  bool reframed = false;  // the body was reassembled: the framing has to follow
  // For a `br` body: what the origin called it and how many bytes it spent, so a
  // replacement that fits can go back out in the same shape instead of identity.
  std::string original_encoding;
  std::size_t original_encoded_size = 0;
  if (wants_body) {
    const bool hard_status = head->status == 206 || head->status == 304 || head->status == 101 ||
                             head->status == 204 || head->status < 200 || head->status == 100;
    if (hard_status) {
      rep.skipped_no_body = true;
      rep.note = "status " + number(static_cast<std::size_t>(head->status)) +
                 " carries no complete body to edit";
    } else {
      // A chunked body has to be put back together first: the chunk sizes
      // describe bytes that are about to disappear, and the content encoding is
      // applied to the decoded body (chunked over gzip is common).
      if (head->chunked) {
        std::string decoded;
        std::string why;
        if (!chunked_decode(*body, &decoded, &why)) {
          rep.skipped_unsupported_encoding = true;
          rep.note = "the chunked body could not be decoded: " + why;
        } else {
          *body = decoded;
          reframed = true;
        }
      }
      if (!rep.skipped_unsupported_encoding) {
        if (!head->content_encoding.empty() && head->content_encoding != "identity" &&
            head->content_encoding != "gzip" && head->content_encoding != "x-gzip" &&
            head->content_encoding != "br" && head->content_encoding != "deflate") {
          rep.skipped_unsupported_encoding = true;
          rep.note = "Content-Encoding: " + head->content_encoding + " is not supported";
        } else if (!head->content_encoding.empty() && head->content_encoding != "identity") {
          // Inflating costs CPU and, more importantly, decides how many bytes go
          // out: a body we inflated is sent as `identity`, which for a `br`
          // origin reply is several times the original size.  So only pay it
          // when a rule can actually edit this body -- `$replace` needs a text
          // media type, injection needs `text/html` specifically.  A `br`
          // JavaScript or JSON reply that a cosmetic rule happened to match used
          // to be inflated, sent out as identity and reported as `改写` while no
          // byte of it changed.
          const bool body_editable =
              response_body_is_text(*head) &&
              (!rw.replaces.empty() || head->content_type == "text/html");
          if (!body_editable) {
            rep.note = "the body stays " + head->content_encoding +
                       ": nothing in our rules edits this media type" +
                       (head->content_type.empty() ? std::string() : " (" + head->content_type + ")");
          } else {
            original_encoding = head->content_encoding;
            original_encoded_size = body->size();
            std::string inflated;
            std::string why;
            if (!inflate_body(head->content_encoding, *body, &inflated, &why)) {
              rep.note = "the compressed body could not be inflated: " + why;
              rep.skipped_unsupported_encoding = true;
            } else {
              *body = inflated;
              rep.decoded = true;
              head->remove_all("content-encoding");
              head->remove_all("content-length");
              rep.dropped_encoding = true;
              rep.note = "inflated " + head->content_encoding + " body";
            }
          }
        }
      }
    }

    // Whatever we do (or refuse to do) to the body, the head has to describe the
    // bytes that actually leave this process.  Once the chunk framing has been
    // taken off, a `Transfer-Encoding: chunked` header in front of the unframed
    // body makes the browser throw the whole response away -- that is the blank
    // page this fixes, and it used to happen on every response we skipped the
    // rewrite of (every Brotli body, for instance).
    if (reframed) {
      head->remove_all("content-length");
      head->remove_all("etag");
      head->remove_all("last-modified");
      head->remove_all("content-md5");
      head->remove_all("digest");
      head->remove_all("accept-ranges");
      head->chunked = false;
      head->remove_all("transfer-encoding");
    }

    if (!rep.skipped_no_body && !rep.skipped_unsupported_encoding) {
      const bool text = response_body_is_text(*head);
      if (!text && !head->content_type.empty()) {
        rep.note = "media type " + head->content_type + " is not text";
      } else {
        if (!text && head->content_type.empty() && (!rw.inject_css.empty() || !rw.inject_script.empty())) {
          rep.note = "no Content-Type, so nothing was injected";
        }
        std::string out = *body;
        for (const RewriteReplace& rr : rw.replaces) {
          // The engine spells case-insensitivity as a leading (?i), the way the
          // filter list spells it as a trailing `i` flag.
          std::string pattern = rr.case_insensitive ? "(?i)" + rr.pattern : rr.pattern;
          std::string repl = rr.replacement;
          std::string why;
          Regex re = Regex::compiled(pattern, &why);
          if (!re.valid()) {
            if (error != nullptr) *error = "$replace pattern '" + pattern + "' is not valid: " + why;
            return false;
          }
          std::size_t made = 0;
          out = re.replace_all(out, repl, &made);
          rep.replaces += made;
        }
        if ((!rw.inject_css.empty() || !rw.inject_script.empty()) && response_body_is_text(*head) &&
            head->content_type == "text/html") {
          std::string markup;
          for (const std::string& css : rw.inject_css) {
            markup += "<style>" + css + "</style>";
            ++rep.injected_css;
          }
          for (const std::string& js : rw.inject_script) {
            markup += "<script>" + js + "</script>";
            ++rep.injected_script;
          }
          if (!markup.empty()) {
            std::string target = out;
            if (!inject_before_close(&target, "head", markup)) {
              if (!inject_before_close(&target, "body", markup)) {
                target += markup;  // no closing tag: append, still before </html> ideally
              }
            }
            out.swap(target);
          }
        } else if ((!rw.inject_css.empty() || !rw.inject_script.empty()) && !text) {
          rep.note = "injection needs an HTML body";
        }
        const bool changed = out != *body;
        if (changed) {
          *body = out;
          rep.body_changed = true;
        }
        if (changed || reframed) {
          head->remove_all("content-length");
          // Validators describe the bytes that used to be sent.
          head->remove_all("etag");
          head->remove_all("last-modified");
          head->remove_all("content-md5");
          head->remove_all("digest");
          head->remove_all("accept-ranges");
          head->chunked = false;
          head->remove_all("transfer-encoding");
        }
      }
    }
  }

  // Putting a `br` body back into its own shape.  The origin's encoded length is
  // the budget: when the edited body compresses into it we restore the header and
  // send the same bytes' worth as before; when it does not (an injected stylesheet
  // usually grows the body) identity is the honest answer -- correct, just larger.
  // The QUIC path needs exactly this property, because a packet cannot grow.
  if (rep.dropped_encoding && original_encoding == "br") {
    // Three tiers of change land here and they differ only in how much room they
    // need: a deletion shrinks the page (but identity would still be ~ten times
    // larger than the origin's `br`), an equal-length rewrite needs the same byte
    // count, and an injection has to grow the page *and* still fit.  So the rule
    // is one rule for all three: keep the origin's byte budget, try the cheap
    // quality first, escalate only while there is budget pressure, and never ship
    // a stream we cannot read back.
    const int qualities[3] = {5, 9, 11};
    std::string packed;
    std::string why;
    int used_quality = 0;
    for (int i = 0; i < 3 && used_quality == 0; ++i) {
      BrotliEncoderOptions options;
      options.quality = qualities[i];
      options.allow_stored_fallback = false;  // a stored stream is bigger than most inputs
      options.limit = original_encoded_size;  // the packet cannot grow, so neither can this
      std::string check;
      std::string check_why;
      if (!brotli_encode(reinterpret_cast<const u8*>(body->data()), body->size(), &packed, &why,
                         options)) {
        continue;
      }
      if (packed.size() > original_encoded_size) continue;
      if (!brotli_decompress(packed, &check, &check_why) || check != *body) continue;
      used_quality = options.quality;
    }
    if (used_quality != 0) {
      *body = packed;
      head->set("Content-Encoding", "br");
      rep.dropped_encoding = false;
      rep.note += "; re-encoded as br (" + number(static_cast<std::size_t>(packed.size())) + " of " +
                  number(original_encoded_size) + " bytes, q" +
                  number(static_cast<std::size_t>(used_quality)) + ")";
    } else {
      rep.note += "; sent as identity (it does not fit back into " +
                  number(original_encoded_size) + " br bytes)";
    }
  }

  if (!head->chunked && !head->close_delimited) {
    head->set("Content-Length", number(body->size()));
    // Writing the length back is only a real change when the framing had to
    // follow a body we reassembled (de-chunked or inflated); otherwise the
    // header keeps the value it already had.
    if (reframed) rep.head_changed = true;
  } else if (head->chunked) {
    // The caller re-chunks payloads it sends, so the length header must go.
    head->remove_all("content-length");
  }

  rep.bytes_out = body->size();
  // A response whose bytes did not move must not be reported as a rewrite: an
  // API/JSON reply that a cosmetic rule matched, or a $replace that never hit,
  // reached the client exactly as the origin sent it.
  rep.changed = rep.body_changed || rep.replaces > 0 || rep.injected_css > 0 ||
                rep.injected_script > 0 || rep.dropped_encoding || reframed || rep.head_changed;
  if (report != nullptr) *report = rep;
  return true;
}

}  // namespace netcap
