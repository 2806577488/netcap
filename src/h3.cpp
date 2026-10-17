// HTTP/3 over QUIC 1-RTT -- see `include/netcap/h3.hpp` for the contract.
//
// Two things in this file are copied rather than linked, and both are
// deliberate:
//
//   * the RFC 7541 Huffman code (`kH3Huff`) and the RFC 9204 static table
//     (`kH3Static`), because `http2.cpp` keeps the HPACK machinery, including
//     its Huffman table, in an anonymous namespace (`src/http2.cpp:62-298`), so
//     none of it has external linkage.  The Huffman table is byte-for-byte the
//     one at `src/http2.cpp:143-196`; QPACK reuses the HPACK code verbatim
//     (RFC 9204 section 4.1.2), so a second, independent transcription would be
//     a liability rather than a check.  `_h3/gen_static_table.py` regenerates
//     the static table from the RFC 9204 Appendix A text.
//
// Nothing here modifies `http2.cpp`; that file is owned elsewhere.
#include "netcap/h3.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace netcap {
namespace {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// A short header is at least a first byte, an 8-byte DCID and a PN, plus an
// AEAD tag.  RFC 9000 section 17.2 allows a zero-length connection ID, so only
// the tag is strictly mandatory; this floor just keeps the arithmetic honest.
constexpr std::size_t kShortHeaderMin = 5;
constexpr std::size_t kAeadTagLen = 16;

struct H3StaticEntry {
  const char* name;
  const char* value;
};

// RFC 7541 appendix B, copied from the file-local table at src/http2.cpp:143-196
// (it has internal linkage there and cannot be linked to).  RFC 9204 section
// 4.1.2 makes QPACK reuse this exact code.
//
// One entry is deliberately *not* the copy's value: src/http2.cpp records '>'
// (symbol 62) as {0xff, 8}, but RFC 7541 appendix B gives it as 0xffb over 12
// bits.  The 8-bit value is a prefix of about 150 other codes, so it is not a
// legal Huffman code at all and it silently corrupts every string containing
// '>' -- the self-check's round trip below catches exactly that.  `_h3/check_huffman_rfc.py`
// compares all 257 rows against the RFC text and reports this as the only
// difference, so this is a deliberate one-row correction, not a transcription
// slip.  `http2.cpp` is left alone: it is another session's file.
//
// `h3_huffman_code` (below, public) hands this same table to the writer in
// `src/h3_write.cpp`, so the two directions cannot disagree about a row.
const H3HuffmanCode kH3Huff[257] = {
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
// Generated by _h3/gen_static_table.py from the RFC 9204 Appendix A text.

const H3StaticEntry kH3Static[99] = {

    {":authority", ""},

    {":path", "/"},

    {"age", "0"},

    {"content-disposition", ""},

    {"content-length", "0"},

    {"cookie", ""},

    {"date", ""},

    {"etag", ""},

    {"if-modified-since", ""},

    {"if-none-match", ""},

    {"last-modified", ""},

    {"link", ""},

    {"location", ""},

    {"referer", ""},

    {"set-cookie", ""},

    {":method", "CONNECT"},

    {":method", "DELETE"},

    {":method", "GET"},

    {":method", "HEAD"},

    {":method", "OPTIONS"},

    {":method", "POST"},

    {":method", "PUT"},

    {":scheme", "http"},

    {":scheme", "https"},

    {":status", "103"},

    {":status", "200"},

    {":status", "304"},

    {":status", "404"},

    {":status", "503"},

    {"accept", "*/*"},

    {"accept", "application/dns-message"},

    {"accept-encoding", "gzip, deflate, br"},

    {"accept-ranges", "bytes"},

    {"access-control-allow-headers", "cache-control"},

    {"access-control-allow-headers", "content-type"},

    {"access-control-allow-origin", "*"},

    {"cache-control", "max-age=0"},

    {"cache-control", "max-age=2592000"},

    {"cache-control", "max-age=604800"},

    {"cache-control", "no-cache"},

    {"cache-control", "no-store"},

    {"cache-control", "public, max-age=31536000"},

    {"content-encoding", "br"},

    {"content-encoding", "gzip"},

    {"content-type", "application/dns-message"},

    {"content-type", "application/javascript"},

    {"content-type", "application/json"},

    {"content-type", "application/x-www-form-urlencoded"},

    {"content-type", "image/gif"},

    {"content-type", "image/jpeg"},

    {"content-type", "image/png"},

    {"content-type", "text/css"},

    {"content-type", "text/html;charset=utf-8"},

    {"content-type", "text/plain"},

    {"content-type", "text/plain;charset=utf-8"},

    {"range", "bytes=0-"},

    {"strict-transport-security", "max-age=31536000"},

    {"strict-transport-security", "max-age=31536000;includesubdomains"},

    {"strict-transport-security", "max-age=31536000;includesubdomains;preload"},

    {"vary", "accept-encoding"},

    {"vary", "origin"},

    {"x-content-type-options", "nosniff"},

    {"x-xss-protection", "1; mode=block"},

    {":status", "100"},

    {":status", "204"},

    {":status", "206"},

    {":status", "302"},

    {":status", "400"},

    {":status", "403"},

    {":status", "421"},

    {":status", "425"},

    {":status", "500"},

    {"accept-language", ""},

    {"access-control-allow-credentials", "FALSE"},

    {"access-control-allow-credentials", "TRUE"},

    {"access-control-allow-headers", "*"},

    {"access-control-allow-methods", "get"},

    {"access-control-allow-methods", "get, post, options"},

    {"access-control-allow-methods", "options"},

    {"access-control-expose-headers", "content-length"},

    {"access-control-request-headers", "content-type"},

    {"access-control-request-method", "get"},

    {"access-control-request-method", "post"},

    {"alt-svc", "clear"},

    {"authorization", ""},

    {"content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"},

    {"early-data", "1"},

    {"expect-ct", ""},

    {"forwarded", ""},

    {"if-range", ""},

    {"origin", ""},

    {"purpose", "prefetch"},

    {"server", ""},

    {"timing-allow-origin", "*"},

    {"upgrade-insecure-requests", "1"},

    {"user-agent", ""},

    {"x-forwarded-for", ""},

    {"x-frame-options", "deny"},

    {"x-frame-options", "sameorigin"},

};

// RFC 7541 section 5.2 / Appendix B, same algorithm and same error strings as
// `src/http2.cpp:205`.
bool h3_huffman_decode(const u8* in, std::size_t len, std::string* out, std::string* error) {
  out->clear();
  u32 code = 0;
  int bits = 0;
  for (std::size_t i = 0; i < len; ++i) {
    for (int b = 7; b >= 0; --b) {
      code = (code << 1) | ((in[i] >> b) & 1u);
      ++bits;
      if (bits > 30) {
        *error = "hpack: huffman code longer than 30 bits";
        return false;
      }
      for (int sym = 0; sym < 257; ++sym) {
        if (kH3Huff[sym].bits != bits || kH3Huff[sym].code != code) continue;
        if (sym == 256) {
          *error = "hpack: huffman EOS symbol inside a string";
          return false;
        }
        out->push_back(char(u8(sym)));
        code = 0;
        bits = 0;
        break;
      }
    }
  }
  if (bits > 7) {
    *error = "hpack: truncated huffman code";
    return false;
  }
  if (bits > 0 && code != ((1u << bits) - 1u)) {
    *error = "hpack: bad huffman padding";
    return false;
  }
  return true;
}

// RFC 7541 section 5.1 / RFC 9204 section 4.1.1 -- the same prefix integer
// encoding QPACK inherits from HPACK.  `shift > 56` cannot happen in QUIC,
// where every integer is at most 62 bits, so reaching it means the input is
// malformed rather than merely large.
bool h3_read_int(const u8* p, std::size_t len, std::size_t* pos, int prefix_bits, u64* out,
                 std::string* error) {
  if (*pos >= len) {
    *error = "hpack: truncated integer";
    return false;
  }
  const u64 mask = (prefix_bits == 8) ? 0xffu : ((u64(1) << prefix_bits) - 1u);
  u64 value = u64(p[*pos]) & mask;
  ++*pos;
  if (value < mask) {
    *out = value;
    return true;
  }
  u64 shift = 0;
  for (;;) {
    if (*pos >= len) {
      *error = "hpack: truncated integer";
      return false;
    }
    if (shift > 56) {
      *error = "hpack: integer overflow";
      return false;
    }
    const u8 byte = p[*pos];
    ++*pos;
    value += u64(byte & 0x7fu) << shift;
    shift += 7;
    if ((byte & 0x80u) == 0) break;
  }
  *out = value;
  return true;
}

// A QPACK/HPACK string literal: a length with a prefix, whose high bit of that
// prefix says the bytes are Huffman-coded (RFC 9204 section 4.1.2).  The prefix
// width is not uniform: a value uses 7 bits with the Huffman flag above them,
// while the name of a "literal field line with literal name" uses only 3 bits
// with the Huffman flag at 0x08 (RFC 9204 section 4.5.6), so both call sites
// share this helper rather than duplicating the length/Huffman dance.
bool h3_read_string_prefix(const u8* p, std::size_t len, std::size_t* pos, int prefix_bits,
                           u8 huffman_flag, std::string* out, std::string* error) {
  if (*pos >= len) {
    *error = "hpack: truncated string";
    return false;
  }
  const bool huffman = (p[*pos] & huffman_flag) != 0;
  u64 slen = 0;
  if (!h3_read_int(p, len, pos, prefix_bits, &slen, error)) return false;
  if (slen > len - *pos) {
    *error = "hpack: string length past the end of the block";
    return false;
  }
  if (huffman) {
    if (!h3_huffman_decode(p + *pos, std::size_t(slen), out, error)) return false;
  } else {
    out->assign(reinterpret_cast<const char*>(p + *pos), std::size_t(slen));
  }
  *pos += std::size_t(slen);
  return true;
}

bool h3_read_string(const u8* p, std::size_t len, std::size_t* pos, std::string* out,
                    std::string* error) {
  return h3_read_string_prefix(p, len, pos, 7, 0x80u, out, error);
}

const char* suite_name(u16 suite) {
  switch (suite) {
    case kH3TlsAes128GcmSha256:
      return "TLS_AES_128_GCM_SHA256";
    case kH3TlsAes256GcmSha384:
      return "TLS_AES_256_GCM_SHA384";
    case kH3TlsChacha20Poly1305Sha256:
      return "TLS_CHACHA20_POLY1305_SHA256";
    default:
      return "unknown";
  }
}

// ---------------------------------------------------------------------------
// RFC 9001 section 5.1 -- traffic secret -> key / iv / hp
// ---------------------------------------------------------------------------

// The suite decides two lengths: the AEAD key, and the header protection key.
// For ChaCha20 the HP key is 32 bytes and the AEAD key is 32 bytes; for both AES
// suites the HP key is the 16-byte AES key, so an AES-256 keyset has a 32-byte
// AEAD key and a 16-byte HP key (RFC 9001 section 5.1).
bool suite_lengths(u16 suite, std::size_t* key_len, std::size_t* hp_len,
                   std::size_t* secret_len, std::string* error) {
  switch (suite) {
    case kH3TlsAes128GcmSha256:
      *key_len = 16;
      *hp_len = 16;
      *secret_len = 32;  // SHA-256
      return true;
    case kH3TlsAes256GcmSha384:
      *key_len = 32;
      *hp_len = 16;
      *secret_len = 48;  // SHA-384
      return true;
    case kH3TlsChacha20Poly1305Sha256:
      *key_len = 32;
      *hp_len = 32;
      *secret_len = 32;
      return true;
    default:
      *error = "quic: cipher suite " + std::to_string(suite) +
               " is not one of the three TLS 1.3 AEADs (RFC 8446 appendix B.4)";
      return false;
  }
}

// ---------------------------------------------------------------------------
// RFC 9000 section 17.1 -- partial packet number -> full packet number
// ---------------------------------------------------------------------------

u64 decode_packet_number(u64 largest_pn, u64 truncated, int pn_length) {
  const u64 expected = largest_pn + 1;
  const u64 window = u64(1) << (pn_length * 8);
  const u64 half = window / 2;
  const u64 mask = window - 1;
  u64 candidate = (expected & ~mask) | truncated;
  if (candidate + half <= expected && candidate + window < (u64(1) << 62)) {
    candidate += window;
  } else if (candidate > expected + half && candidate >= window) {
    candidate -= window;
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// RFC 9001 section 5.4 -- header protection
// ---------------------------------------------------------------------------

// The sample is taken 4 bytes after the (still protected) packet number offset
// and is always 16 bytes long (RFC 9001 section 5.4.2).
bool hp_mask(const QuicKeyset& keys, const u8* sample, u8 out[5], std::string* error) {
  if (keys.is_chacha20()) {
    // RFC 9001 section 5.4.4: the first four sample bytes are the ChaCha20
    // block counter in little-endian order and the remaining twelve are the
    // nonce -- not the other way round, and not a truncation of either.
    const u32 counter = u32(sample[0]) | (u32(sample[1]) << 8) | (u32(sample[2]) << 16) |
                        (u32(sample[3]) << 24);
    const Bytes nonce(sample + 4, sample + 16);
    const Bytes zero(16, 0);
    const Bytes ks = chacha20_xor(keys.hp, nonce, counter, zero);
    if (ks.size() < 5) {
      *error = "quic: chacha20 header protection produced a short keystream";
      return false;
    }
    std::memcpy(out, ks.data(), 5);
    return true;
  }
  Aes aes;
  if (!aes.set_key(keys.hp)) {
    *error = "quic: header protection key is not a valid AES key length";
    return false;
  }
  u8 block[16];
  aes.encrypt_block(sample, block);
  std::memcpy(out, block, 5);
  return true;
}

const u8* hp_sample(const u8* packet, std::size_t len, std::size_t pn_offset,
                    std::string* error) {
  const std::size_t at = pn_offset + 4;
  if (at + kQuicHpSampleLen > len) {
    *error = "quic: packet is too short to hold a 16-byte header protection sample";
    return nullptr;
  }
  return packet + at;
}

// ---------------------------------------------------------------------------
// AEAD open
// ---------------------------------------------------------------------------

bool aead_open(const QuicKeyset& keys, const Bytes& nonce, const Bytes& aad,
               const u8* ciphertext, std::size_t ct_len, const u8* tag, Bytes* out,
               std::string* error) {
  const Bytes ct(ciphertext, ciphertext + ct_len);
  const Bytes tag_bytes(tag, tag + kAeadTagLen);
  bool ok = false;
  if (keys.is_chacha20()) {
    ok = chacha20_poly1305_decrypt(keys.key, nonce, aad, ct, tag_bytes, out);
  } else {
    ok = aes_gcm_decrypt(keys.key, nonce, aad, ct, tag_bytes, out);
  }
  if (!ok) {
    *error = "quic: packet failed to authenticate -- wrong secret, wrong keyset, or a "
             "key update this decoder has not followed (RFC 9001 section 5.3)";
    return false;
  }
  return true;
}

// nonce = iv XOR (packet number as a 12-byte big-endian integer), RFC 9001 5.3.
Bytes make_nonce(const Bytes& iv, u64 pn) {
  Bytes nonce = iv;
  for (int i = 0; i < 8; ++i) {
    const std::size_t idx = nonce.size() - 1 - std::size_t(i);
    if (idx < nonce.size()) nonce[idx] ^= u8(pn >> (8 * i));
  }
  return nonce;
}

// ---------------------------------------------------------------------------
// QUIC frame helpers
// ---------------------------------------------------------------------------

bool frame_varint(const u8* data, std::size_t len, std::size_t* pos, u64* out,
                  std::string* error) {
  std::size_t used = 0;
  if (!quic_varint(data + *pos, len - *pos, out, &used)) {
    *error = "quic: truncated variable-length integer inside a frame";
    return false;
  }
  *pos += used;
  return true;
}

const char* quic_frame_name(u8 type) {
  if (type >= 0x08 && type <= 0x0f) return "STREAM";
  switch (type) {
    case 0x00:
      return "PADDING";
    case 0x01:
      return "PING";
    case 0x02:
      return "ACK";
    case 0x03:
      return "ACK_ECN";
    case 0x04:
      return "RESET_STREAM";
    case 0x05:
      return "STOP_SENDING";
    case 0x06:
      return "CRYPTO";
    case 0x07:
      return "NEW_TOKEN";
    case 0x10:
      return "MAX_DATA";
    case 0x11:
      return "MAX_STREAM_DATA";
    case 0x12:
      return "MAX_STREAMS";
    case 0x13:
      return "MAX_STREAMS";
    case 0x14:
      return "DATA_BLOCKED";
    case 0x15:
      return "STREAM_DATA_BLOCKED";
    case 0x16:
      return "STREAMS_BLOCKED";
    case 0x17:
      return "STREAMS_BLOCKED";
    case 0x18:
      return "NEW_CONNECTION_ID";
    case 0x19:
      return "RETIRE_CONNECTION_ID";
    case 0x1a:
      return "PATH_CHALLENGE";
    case 0x1b:
      return "PATH_RESPONSE";
    case 0x1c:
    case 0x1d:
      return "CONNECTION_CLOSE";
    case 0x1e:
      return "HANDSHAKE_DONE";
    default:
      return nullptr;
  }
}

// ---------------------------------------------------------------------------
// HTTP/3 helpers
// ---------------------------------------------------------------------------

const char* h3_frame_name(u64 type) {
  switch (type) {
    case kH3FrameData:
      return "DATA";
    case kH3FrameHeaders:
      return "HEADERS";
    case kH3FrameCancelPush:
      return "CANCEL_PUSH";
    case kH3FrameSettings:
      return "SETTINGS";
    case kH3FramePushPromise:
      return "PUSH_PROMISE";
    case kH3FrameGoaway:
      return "GOAWAY";
    case kH3FrameMaxPushId:
      return "MAX_PUSH_ID";
    default:
      return nullptr;
  }
}

void append_hex(std::string* out, u64 value) {
  static const char* kDigits = "0123456789abcdef";
  char buf[17];
  int n = 0;
  do {
    buf[n++] = kDigits[value & 0xf];
    value >>= 4;
  } while (value != 0);
  while (n > 0) out->push_back(buf[--n]);
}

// The QPACK static table is indexed from **zero** (RFC 9204 appendix A entry 0
// is `:authority`), unlike HPACK's, whose index 0 is invalid.  kH3Static holds
// all 99 entries in that order, so the index is used directly.
const H3StaticEntry* static_by_index(u64 index) {
  if (index >= kH3StaticTableSize) return nullptr;
  return &kH3Static[index];
}

}  // namespace

// ===========================================================================
// Public: key derivation
// ===========================================================================

bool quic_keyset_from_secret(u16 suite, const Bytes& traffic_secret, QuicKeyset* out,
                             std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "quic: quic_keyset_from_secret was given a null output";
    return false;
  }
  *out = QuicKeyset();
  std::size_t key_len = 0;
  std::size_t hp_len = 0;
  std::size_t secret_len = 0;
  if (!suite_lengths(suite, &key_len, &hp_len, &secret_len, error)) return false;
  if (traffic_secret.size() != secret_len) {
    if (error) {
      *error = "quic: a " + std::string(suite_name(suite)) + " traffic secret is " +
               std::to_string(secret_len) + " bytes, not " +
               std::to_string(traffic_secret.size());
    }
    return false;
  }
  if (traffic_secret.empty()) {
    if (error) *error = "quic: traffic secret is empty";
    return false;
  }
  // hkdf_expand_label already prepends the "tls13 " prefix (src/crypto.cpp:635),
  // so the QUIC labels are passed bare.
  const bool sha384 = (suite == kH3TlsAes256GcmSha384);
  out->suite = suite;
  out->secret = traffic_secret;
  out->key = hkdf_expand_label(traffic_secret, "quic key", Bytes(), key_len, sha384);
  out->iv = hkdf_expand_label(traffic_secret, "quic iv", Bytes(), 12, sha384);
  out->hp = hkdf_expand_label(traffic_secret, "quic hp", Bytes(), hp_len, sha384);
  if (out->key.size() != key_len || out->iv.size() != 12 || out->hp.size() != hp_len) {
    if (error) *error = "quic: HKDF-Expand-Label returned the wrong length for a quic label";
    *out = QuicKeyset();
    return false;
  }
  out->ready = true;
  return true;
}

bool quic_next_secret(const Bytes& traffic_secret, Bytes* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "quic: quic_next_secret was given a null output";
    return false;
  }
  if (traffic_secret.size() != 32 && traffic_secret.size() != 48) {
    if (error) {
      *error = "quic: key update needs a 32- or 48-byte traffic secret, not " +
               std::to_string(traffic_secret.size());
    }
    return false;
  }
  const bool sha384 = (traffic_secret.size() == 48);
  *out = hkdf_expand_label(traffic_secret, "quic ku", Bytes(), traffic_secret.size(), sha384);
  if (out->size() != traffic_secret.size()) {
    if (error) *error = "quic: HKDF-Expand-Label returned the wrong length for quic ku";
    return false;
  }
  return true;
}

// ===========================================================================
// Public: short header decryption
// ===========================================================================

bool quic_decrypt_short_full(const QuicKeyset& keys, const u8* dcid, std::size_t dcid_len,
                             const u8* packet, std::size_t len, u64 largest_pn,
                             QuicShortHeader* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "quic: quic_decrypt_short_full was given a null output";
    return false;
  }
  *out = QuicShortHeader();
  if (!keys.ready) {
    if (error) *error = "quic: keyset is not ready -- derive it first with quic_keyset_from_secret";
    return false;
  }
  if (packet == nullptr || len < kShortHeaderMin) {
    if (error) *error = "quic: packet is too short to be a 1-RTT packet";
    return false;
  }
  if ((packet[0] & 0x80u) != 0) {
    if (error) {
      *error = "quic: packet has the long header bit set, so it is not a 1-RTT packet "
               "(RFC 9000 section 17.2)";
    }
    return false;
  }
  if (dcid_len > 20) {
    if (error) {
      *error = "quic: connection ID is longer than the 20 bytes RFC 9000 section 17.2 allows";
    }
    return false;
  }
  if (dcid_len > 0 && dcid == nullptr) {
    if (error) *error = "quic: connection ID length is non-zero but the pointer is null";
    return false;
  }

  // The short header does not encode its length, and it is the last packet of a
  // datagram, so the datagram's end is this packet's end (RFC 9000 section
  // 12.2).  The caller is expected to pass exactly one packet.
  out->first_byte = packet[0];
  out->pn_offset = 1 + dcid_len;

  const u8* sample = hp_sample(packet, len, out->pn_offset, error);
  if (sample == nullptr) return false;
  u8 mask[5];
  if (!hp_mask(keys, sample, mask, error)) return false;

  u8 first = packet[0];
  // RFC 9001 section 5.4.1: a short header protects the low FIVE bits of the
  // first byte (long headers protect four).  Using four here cannot open the
  // RFC 9001 A.5 vector: the packet-number length comes out wrong and the AEAD
  // sample offset with it.  Found while integrating the key-log module.
  first ^= (mask[0] & 0x1f);
  const int pn_length = int(first & 0x03u) + 1;
  if (out->pn_offset + std::size_t(pn_length) >= len) {
    if (error) *error = "quic: packet ends inside its protected packet number";
    return false;
  }
  u8 pn_bytes[4] = {0, 0, 0, 0};
  std::memcpy(pn_bytes, packet + out->pn_offset, std::size_t(pn_length));
  for (int i = 0; i < pn_length; ++i) pn_bytes[i] ^= mask[1 + i];

  u64 truncated = 0;
  for (int i = 0; i < pn_length; ++i) truncated = (truncated << 8) | pn_bytes[i];
  out->packet_number = decode_packet_number(largest_pn, truncated, pn_length);
  out->pn_length = pn_length;
  out->first_byte_unprotected = first;
  out->key_phase = (first & 0x04u) != 0;  // RFC 9000 section 17.3.1
  out->spin = (first & 0x20u) != 0;

  // AAD is the header with protection removed and its packet number in the
  // clear (RFC 9001 section 5.3).
  Bytes header(packet, packet + out->pn_offset);
  header[0] = first;
  for (int i = 0; i < pn_length; ++i) header.push_back(pn_bytes[i]);
  out->header = header;
  out->header_end = out->pn_offset + std::size_t(pn_length);

  if (len < out->header_end + kAeadTagLen) {
    if (error) *error = "quic: packet is too short to hold a 16-byte AEAD tag";
    return false;
  }
  const std::size_t ct_len = len - out->header_end - kAeadTagLen;
  out->ciphertext_length = ct_len;
  out->tag_length = kAeadTagLen;

  const Bytes nonce = make_nonce(keys.iv, out->packet_number);
  Bytes plain;
  if (!aead_open(keys, nonce, header, packet + out->header_end, ct_len,
                 packet + out->header_end + ct_len, &plain, error)) {
    return false;
  }
  out->payload = std::move(plain);
  out->ok = true;
  return true;
}

bool quic_decrypt_short(const QuicKeyset& keys, const u8* dcid, std::size_t dcid_len,
                        const u8* packet, std::size_t len, u64 largest_pn, u64* pn,
                        Bytes* payload, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  QuicShortHeader header;
  if (!quic_decrypt_short_full(keys, dcid, dcid_len, packet, len, largest_pn, &header, error)) {
    return false;
  }
  if (pn != nullptr) *pn = header.packet_number;
  if (payload != nullptr) *payload = header.payload;
  return true;
}

// ===========================================================================
// Public: 1-RTT frame walking
// ===========================================================================

bool quic_parse_frames_rtt(const u8* data, std::size_t len, std::vector<QuicFrameInfo>* frames,
                           std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (frames == nullptr) {
    if (error) *error = "quic: quic_parse_frames_rtt was given a null frame list";
    return false;
  }
  frames->clear();
  std::size_t pos = 0;
  while (pos < len) {
    const std::size_t start = pos;
    const u8 type = data[pos];

    if (type == 0x00) {  // PADDING: coalesce, a payload can be thousands of them
      u64 pad = 0;
      while (pos < len && data[pos] == 0x00) {
        ++pos;
        ++pad;
      }
      QuicFrameInfo f;
      f.type = 0x00;
      f.type_name = "PADDING";
      f.offset = start;
      f.length = pos - start;
      f.note = "padding " + std::to_string(pad);
      frames->push_back(std::move(f));
      continue;
    }

    const char* name = quic_frame_name(type);
    if (name == nullptr) {
      if (error) {
        std::string hex;
        append_hex(&hex, type);
        *error = "quic: unknown frame type 0x" + hex + " in a 1-RTT payload";
      }
      return false;
    }

    QuicFrameInfo f;
    f.type = type;
    f.type_name = name;
    f.offset = start;
    ++pos;  // every non-PADDING frame consumes its type byte

    if (type >= 0x08 && type <= 0x0f) {  // STREAM
      u64 sid = 0, off = 0;
      if (!frame_varint(data, len, &pos, &sid, error)) return false;
      if (type & 0x04u) {
        if (!frame_varint(data, len, &pos, &off, error)) return false;
      }
      u64 slen = 0;
      bool has_len = (type & 0x02u) != 0;
      if (has_len) {
        if (!frame_varint(data, len, &pos, &slen, error)) return false;
        if (slen > len - pos) {
          if (error) *error = "quic: STREAM frame claims more bytes than the payload holds";
          return false;
        }
      } else {
        slen = len - pos;
      }
      f.stream.stream_id = sid;
      f.stream.offset = off;
      f.stream.length = slen;
      f.stream.fin = (type & 0x01u) != 0;
      f.stream.has_length = has_len;
      f.data.assign(data + pos, data + pos + std::size_t(slen));
      f.stream.data = f.data;
      pos += std::size_t(slen);
      f.note = "stream " + std::to_string(sid) + " offset " + std::to_string(off);
      if (f.stream.fin) f.note += " fin";
    } else if (type == 0x01) {  // PING
      f.note = "ping";
    } else if (type == 0x02 || type == 0x03) {  // ACK / ACK_ECN
      u64 largest = 0, delay = 0, range_count = 0, first = 0;
      if (!frame_varint(data, len, &pos, &largest, error)) return false;
      if (!frame_varint(data, len, &pos, &delay, error)) return false;
      if (!frame_varint(data, len, &pos, &range_count, error)) return false;
      if (!frame_varint(data, len, &pos, &first, error)) return false;
      for (u64 i = 0; i < range_count; ++i) {
        u64 gap = 0, rlen = 0;
        if (!frame_varint(data, len, &pos, &gap, error)) return false;
        if (!frame_varint(data, len, &pos, &rlen, error)) return false;
      }
      if (type == 0x03) {
        u64 ect0 = 0, ect1 = 0, ce = 0;
        if (!frame_varint(data, len, &pos, &ect0, error)) return false;
        if (!frame_varint(data, len, &pos, &ect1, error)) return false;
        if (!frame_varint(data, len, &pos, &ce, error)) return false;
      }
      f.note = "ack largest " + std::to_string(largest) + " " +
               std::to_string(range_count) + " ranges";
    } else if (type == 0x04) {  // RESET_STREAM
      u64 sid = 0, code = 0, final_size = 0;
      if (!frame_varint(data, len, &pos, &sid, error)) return false;
      if (!frame_varint(data, len, &pos, &code, error)) return false;
      if (!frame_varint(data, len, &pos, &final_size, error)) return false;
      f.note = "reset stream " + std::to_string(sid);
    } else if (type == 0x05) {  // STOP_SENDING
      u64 sid = 0, code = 0;
      if (!frame_varint(data, len, &pos, &sid, error)) return false;
      if (!frame_varint(data, len, &pos, &code, error)) return false;
      f.note = "stop sending " + std::to_string(sid);
    } else if (type == 0x06) {  // CRYPTO
      u64 off = 0, clen = 0;
      if (!frame_varint(data, len, &pos, &off, error)) return false;
      if (!frame_varint(data, len, &pos, &clen, error)) return false;
      if (clen > len - pos) {
        if (error) *error = "quic: CRYPTO frame claims more bytes than the payload holds";
        return false;
      }
      f.data.assign(data + pos, data + pos + std::size_t(clen));
      pos += std::size_t(clen);
      f.note = "crypto offset " + std::to_string(off);
    } else if (type == 0x07) {  // NEW_TOKEN
      u64 tlen = 0;
      if (!frame_varint(data, len, &pos, &tlen, error)) return false;
      if (tlen > len - pos) {
        if (error) *error = "quic: NEW_TOKEN frame claims more bytes than the payload holds";
        return false;
      }
      f.data.assign(data + pos, data + pos + std::size_t(tlen));
      pos += std::size_t(tlen);
      f.note = "new token " + std::to_string(tlen) + " bytes";
    } else if (type == 0x10 || type == 0x14) {  // MAX_DATA / DATA_BLOCKED
      u64 v = 0;
      if (!frame_varint(data, len, &pos, &v, error)) return false;
      f.note = std::to_string(v);
    } else if (type == 0x11 || type == 0x15) {  // MAX_STREAM_DATA / STREAM_DATA_BLOCKED
      u64 sid = 0, v = 0;
      if (!frame_varint(data, len, &pos, &sid, error)) return false;
      if (!frame_varint(data, len, &pos, &v, error)) return false;
      f.note = "stream " + std::to_string(sid);
    } else if (type == 0x12 || type == 0x13 || type == 0x16 || type == 0x17) {
      u64 v = 0;  // MAX_STREAMS / STREAMS_BLOCKED
      if (!frame_varint(data, len, &pos, &v, error)) return false;
      f.note = std::to_string(v);
    } else if (type == 0x18) {  // NEW_CONNECTION_ID
      u64 seq = 0, retire = 0, cid_len = 0;
      if (!frame_varint(data, len, &pos, &seq, error)) return false;
      if (!frame_varint(data, len, &pos, &retire, error)) return false;
      if (pos >= len) {
        if (error) *error = "quic: NEW_CONNECTION_ID frame ends before its length byte";
        return false;
      }
      cid_len = data[pos++];
      if (cid_len > 20) {
        if (error) *error = "quic: NEW_CONNECTION_ID length exceeds 20 bytes";
        return false;
      }
      if (cid_len + 16 > len - pos) {
        if (error) *error = "quic: NEW_CONNECTION_ID frame ends before its CID and token";
        return false;
      }
      f.data.assign(data + pos, data + pos + std::size_t(cid_len));
      pos += std::size_t(cid_len);
      pos += 16;  // stateless reset token
      f.note = "sequence " + std::to_string(seq) + " retire prior to " + std::to_string(retire);
    } else if (type == 0x19) {  // RETIRE_CONNECTION_ID
      u64 seq = 0;
      if (!frame_varint(data, len, &pos, &seq, error)) return false;
      f.note = "sequence " + std::to_string(seq);
    } else if (type == 0x1a || type == 0x1b) {  // PATH_CHALLENGE / PATH_RESPONSE
      if (8 > len - pos) {
        if (error) *error = "quic: PATH_CHALLENGE/PATH_RESPONSE frame needs 8 data bytes";
        return false;
      }
      f.data.assign(data + pos, data + pos + 8);
      pos += 8;
      f.note = to_hex(f.data);
    } else if (type == 0x1c || type == 0x1d) {  // CONNECTION_CLOSE
      u64 code = 0, frame_type = 0, reason_len = 0;
      if (!frame_varint(data, len, &pos, &code, error)) return false;
      if (type == 0x1c) {
        if (!frame_varint(data, len, &pos, &frame_type, error)) return false;
      }
      if (!frame_varint(data, len, &pos, &reason_len, error)) return false;
      if (reason_len > len - pos) {
        if (error) {
          *error = "quic: CONNECTION_CLOSE reason phrase runs past the end of the frame";
        }
        return false;
      }
      f.data.assign(data + pos, data + pos + std::size_t(reason_len));
      pos += std::size_t(reason_len);
      f.note = (type == 0x1c ? "transport error " : "application error ") +
               std::to_string(code) + ": " + std::string(f.data.begin(), f.data.end());
    } else if (type == 0x1e) {  // HANDSHAKE_DONE
      f.note = "handshake done";
    }

    f.length = pos - start;
    frames->push_back(std::move(f));
  }
  return true;
}

// ===========================================================================
// Public: HTTP/3 framing
// ===========================================================================

bool h3_parse_frames(const u8* data, std::size_t len, std::vector<H3Frame>* frames,
                     std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (frames == nullptr) {
    if (error) *error = "h3: h3_parse_frames was given a null frame list";
    return false;
  }
  frames->clear();
  std::size_t pos = 0;
  while (pos < len) {
    u64 type = 0, flen = 0;
    std::size_t used = 0;
    if (!quic_varint(data + pos, len - pos, &type, &used)) {
      if (error) *error = "h3: truncated frame type";
      return false;
    }
    pos += used;
    if (!quic_varint(data + pos, len - pos, &flen, &used)) {
      if (error) *error = "h3: truncated frame length";
      return false;
    }
    pos += used;
    if (flen > len - pos) {
      if (error) {
        *error = "h3: frame length " + std::to_string(flen) +
                 " runs past the end of the buffer";
      }
      return false;
    }
    H3Frame f;
    f.type = type;
    f.length = flen;
    const char* name = h3_frame_name(type);
    if (name != nullptr) {
      f.type_name = name;
    } else {
      f.type_name = "unknown";
      append_hex(&f.note, type);
      f.note = "unknown frame type 0x" + f.note;
    }
    f.payload.assign(data + pos, data + pos + std::size_t(flen));
    pos += std::size_t(flen);
    frames->push_back(std::move(f));
  }
  return true;
}

bool h3_parse_uni_stream(const Bytes& stream_bytes, H3UniStream* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "h3: h3_parse_uni_stream was given a null output";
    return false;
  }
  *out = H3UniStream();
  if (stream_bytes.empty()) {
    if (error) *error = "h3: unidirectional stream is empty, so it has no stream type";
    return false;
  }
  u64 type = 0;
  std::size_t used = 0;
  if (!quic_varint(stream_bytes.data(), stream_bytes.size(), &type, &used)) {
    if (error) *error = "h3: truncated stream type varint";
    return false;
  }
  out->type = type;
  out->body.assign(stream_bytes.begin() + std::ptrdiff_t(used), stream_bytes.end());
  switch (type) {
    case kH3StreamControl:
      out->type_name = "control";
      break;
    case kH3StreamPush:
      out->type_name = "push";
      break;
    case kH3StreamQpackEncoder:
      out->type_name = "qpack encoder";
      break;
    case kH3StreamQpackDecoder:
      out->type_name = "qpack decoder";
      break;
    default:
      out->type_name = "unknown";
      out->unknown_reason = "h3: unknown unidirectional stream type " + std::to_string(type);
      return true;  // RFC 9114 section 6.1: a peer may ignore an unknown stream
  }
  if (type == kH3StreamPush || type == kH3StreamQpackEncoder || type == kH3StreamQpackDecoder) {
    // These carry a grammar of their own (push ID + field section, or QPACK
    // instructions); the type is reported and the body is left to the caller.
    return true;
  }
  if (out->body.empty()) {
    if (error) *error = "h3: a control stream must send SETTINGS first, but the stream is empty";
    return false;
  }
  if (!h3_parse_frames(out->body.data(), out->body.size(), &out->frames, error)) return false;
  if (out->frames.empty() || out->frames[0].type != kH3FrameSettings) {
    if (error) *error = "h3: a control stream must send SETTINGS as its first frame (RFC 9114 6.2.1)";
    return false;
  }
  return true;
}

// ===========================================================================
// Public: QPACK field section, static table only
// ===========================================================================

namespace {

// One encoded field line (RFC 9204 section 4.5).  Returns false only for input
// that cannot be decoded at all; a dynamic-table reference is reported as a
// decode failure with an explanatory string, because that is a real limit and
// silently dropping the header would be worse.
bool decode_field_line(const u8* p, std::size_t len, std::size_t* pos,
                       std::vector<std::pair<std::string, std::string>>* out,
                       std::string* error) {
  if (*pos >= len) {
    *error = "qpack: truncated field line";
    return false;
  }
  const std::size_t line_at = *pos;  // for errors that must name where they happened
  const u8 b = p[*pos];

  if (b & 0x80u) {  // 1Txxxxxx  indexed field line
    // T distinguishes the static table from the dynamic one (RFC 9204 section
    // 4.5.2); only the static case can be resolved here.
    const bool is_static = (b & 0x40u) != 0;
    u64 index = 0;
    if (!h3_read_int(p, len, pos, 6, &index, error)) return false;
    if (!is_static) {
      *error = "qpack: indexed field line references the dynamic table, which this decoder does "
               "not track";
      return false;
    }
    const H3StaticEntry* e = static_by_index(index);
    if (e == nullptr) {
      *error = "qpack: indexed field line names static index " + std::to_string(index) +
               ", but the static table ends at 99";
      return false;
    }
    out->push_back({e->name, e->value});
    return true;
  }

  if (b & 0x40u) {  // 01NTxxxx  literal with name reference
    // N is the never-indexed bit and T again selects the static table; the name
    // index uses a 4-bit prefix (RFC 9204 section 4.5.4), and static index 0
    // (`:authority`) is perfectly legal here.
    const bool never_indexed = (b & 0x20u) != 0;
    const bool is_static = (b & 0x10u) != 0;
    (void)never_indexed;  // only affects insertion, which this decoder never does
    u64 index = 0;
    if (!h3_read_int(p, len, pos, 4, &index, error)) return false;
    std::string value;
    if (!h3_read_string(p, len, pos, &value, error)) return false;
    if (!is_static) {
      *error = "qpack: literal field line references dynamic table entry " + std::to_string(index) +
               ", which this decoder does not track";
      return false;
    }
    const H3StaticEntry* e = static_by_index(index);
    if (e == nullptr) {
      *error = "qpack: literal field line names static index " + std::to_string(index) +
               ", but the static table ends at 99";
      return false;
    }
    out->push_back({e->name, value});
    return true;
  }

  if (b & 0x20u) {  // 001NHHHH  literal with literal name
    std::string name, value;
    // The 3-bit prefix under the N and H bits carries the name length, with
    // 0x08 as its Huffman flag; the value is an ordinary 7-bit string (RFC 9204
    // section 4.5.6).  Using the 7-bit reader here would silently mis-split the
    // field section, because the two forms disagree on every name.
    if (!h3_read_string_prefix(p, len, pos, 3, 0x08u, &name, error)) return false;
    if (name.empty()) {
      *error = "qpack: literal field line has an empty field name";
      return false;
    }
    if (!h3_read_string(p, len, pos, &value, error)) return false;
    out->push_back({name, value});
    return true;
  }

  if (b & 0x10u) {  // 0001xxxx  indexed field line with post-base index
    *error = "qpack: field line at offset " + std::to_string(line_at) + " (byte 0x" +
             to_hex(&b, 1) + ") references the dynamic table by post-base index, which this "
             "decoder does not track";
    return false;
  }

  // 0000xxxx  literal field line with post-base name reference
  *error = "qpack: field line at offset " + std::to_string(line_at) + " (byte 0x" +
           to_hex(&b, 1) + ") names a post-base dynamic table entry, which this decoder does "
           "not track";
  return false;
}

}  // namespace

bool h3_decode_field_section(const u8* data, std::size_t len,
                             std::vector<std::pair<std::string, std::string>>* out,
                             std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "qpack: h3_decode_field_section was given a null output";
    return false;
  }
  out->clear();
  std::size_t pos = 0;
  if (len == 0) {
    if (error) *error = "qpack: empty field section";
    return false;
  }
  // Required Insert Count and Delta Base, RFC 9204 sections 4.5.1.1-4.5.1.2.
  u64 required_insert_count = 0;
  if (!h3_read_int(data, len, &pos, 8, &required_insert_count, error)) return false;
  if (required_insert_count != 0) {
    if (error) {
      *error = "qpack: Required Insert Count is " + std::to_string(required_insert_count) +
               ", so this field section uses the dynamic table, which we do not track";
    }
    return false;
  }
  bool sign = false;
  u64 delta_base = 0;
  if (pos >= len) {
    if (error) *error = "qpack: field section ends before its Delta Base";
    return false;
  }
  // The S bit is the high bit of the Delta Base first byte; the value uses the
  // low 7 bits (RFC 9204 section 4.5.1.2).
  sign = (data[pos] & 0x80u) != 0;
  if (!h3_read_int(data, len, &pos, 7, &delta_base, error)) return false;
  (void)sign;
  (void)delta_base;  // both are zero by construction when Required Insert Count is 0

  while (pos < len) {
    if (!decode_field_line(data, len, &pos, out, error)) return false;
  }
  if (out->empty()) {
    if (error) *error = "qpack: field section decoded to no fields";
    return false;
  }
  return true;
}

bool h3_decode_field_section(const Bytes& data,
                             std::vector<std::pair<std::string, std::string>>* out,
                             std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  return h3_decode_field_section(data.data(), data.size(), out, error);
}

// ===========================================================================
// Public: request extraction
// ===========================================================================

namespace {

bool fill_request(const std::vector<std::pair<std::string, std::string>>& fields, H3Request* out,
                  std::string* error) {
  for (const auto& kv : fields) {
    if (!kv.first.empty() && kv.first[0] == ':') {
      if (kv.first == kH3FieldMethod) {
        out->method = kv.second;
      } else if (kv.first == kH3FieldScheme) {
        out->scheme = kv.second;
      } else if (kv.first == kH3FieldAuthority) {
        out->authority = kv.second;
      } else if (kv.first == kH3FieldPath) {
        out->path = kv.second;
      } else {
        if (error) *error = "h3: unknown pseudo-header field \"" + kv.first + "\"";
        return false;
      }
    } else {
      out->headers.push_back(kv);
    }
  }
  out->has_pseudo = !out->method.empty() && !out->scheme.empty() && !out->authority.empty() &&
                    !out->path.empty();
  if (!out->has_pseudo) {
    if (error) {
      *error = "h3: request is missing one of :method, :scheme, :authority, :path "
               "(RFC 9114 section 4.3.2)";
    }
    return false;
  }
  return true;
}

}  // namespace

bool h3_request_from_stream(const Bytes& stream_bytes, bool client_initiated_bidi,
                            H3Request* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "h3: h3_request_from_stream was given a null output";
    return false;
  }
  *out = H3Request();
  if (!client_initiated_bidi) {
    if (error) {
      *error = "h3: server-initiated bidirectional streams carry no HTTP request";
    }
    return false;
  }
  if (stream_bytes.empty()) {
    if (error) *error = "h3: request stream is empty";
    return false;
  }
  u64 prefix = 0;
  std::size_t used = 0;
  if (!quic_varint(stream_bytes.data(), stream_bytes.size(), &prefix, &used)) {
    if (error) *error = "h3: truncated request-stream prefix varint";
    return false;
  }
  if (prefix != 0x00) {
    if (error) {
      *error = "h3: request stream must begin with the varint 0x00, not " + std::to_string(prefix);
    }
    return false;
  }
  std::vector<H3Frame> frames;
  if (!h3_parse_frames(stream_bytes.data() + used, stream_bytes.size() - used, &frames, error)) {
    return false;
  }
  const H3Frame* headers = nullptr;
  for (const H3Frame& f : frames) {
    if (f.type == kH3FrameHeaders) {
      headers = &f;
      break;
    }
    if (f.type == kH3FrameData) {
      if (error) *error = "h3: DATA frame arrives before the HEADERS frame (RFC 9114 section 4.1)";
      return false;
    }
  }
  if (headers == nullptr) {
    if (error) *error = "h3: request stream carries no HEADERS frame";
    return false;
  }
  std::vector<std::pair<std::string, std::string>> fields;
  if (!h3_decode_field_section(headers->payload, &fields, error)) return false;
  return fill_request(fields, out, error);
}

bool h3_request_from_stream(const Bytes& stream_bytes, H3Request* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  return h3_request_from_stream(stream_bytes, true, out, error);
}

bool h3_request_from_stream_frames(const std::vector<QuicFrameInfo>& frames, H3Request* out,
                                   std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    if (error) *error = "h3: h3_request_from_stream_frames was given a null output";
    return false;
  }
  *out = H3Request();
  Bytes joined;
  u64 expected_offset = 0;
  bool saw_stream = false;
  bool fin = false;
  u64 stream_id = 0;
  for (const QuicFrameInfo& f : frames) {
    if (f.type < 0x08 || f.type > 0x0f) continue;
    if (saw_stream && f.stream.stream_id != stream_id) {
      if (error) {
        *error = "h3: the frame list carries more than one STREAM id; pass a single stream";
      }
      return false;
    }
    if (!saw_stream) {
      stream_id = f.stream.stream_id;
      saw_stream = true;
    }
    if (f.stream.offset != expected_offset) {
      if (error) {
        *error = "h3: STREAM data has a gap at offset " + std::to_string(expected_offset) +
                 "; a request stream must be reassembled in order";
      }
      return false;
    }
    joined.insert(joined.end(), f.data.begin(), f.data.end());
    expected_offset += f.stream.length;
    fin = f.stream.fin;
  }
  if (!saw_stream) {
    if (error) *error = "h3: no STREAM frame in the frame list";
    return false;
  }
  if (!fin) {
    if (error) {
      *error = "h3: the request stream was not closed with FIN, so its HEADERS may be incomplete";
    }
    return false;
  }
  if (!h3_request_from_stream(joined, true, out, error)) return false;
  out->stream_id = stream_id;
  out->fin = true;
  return true;
}

// ===========================================================================
// Public: h3_selfcheck
//
// Every check below is a real vector or a real round trip, and the first
// failure is returned verbatim so a caller can see which invariant broke.  The
// RFC 9001 A.5 bytes are copied from the RFC text (they are also kept in
// _h3/rfc9001_a5.txt for review); the QPACK bytes are copied from RFC 9204
// appendix B.1.
// ===========================================================================

namespace {

// A tiny bit accumulator, used only to build Huffman-coded test strings.
struct BitWriter {
  Bytes out;
  u32 acc = 0;
  int bits = 0;
  void put(u32 code, int n) {
    for (int i = n - 1; i >= 0; --i) {
      acc = (acc << 1) | ((code >> i) & 1u);
      ++bits;
      if (bits == 8) {
        out.push_back(u8(acc));
        acc = 0;
        bits = 0;
      }
    }
  }
  void flush() {
    if (bits == 0) return;
    acc <<= (8 - bits);
    acc |= (1u << (8 - bits)) - 1u;  // pad with the EOS prefix, i.e. all ones
    out.push_back(u8(acc));
    acc = 0;
    bits = 0;
  }
};

bool h3_huffman_encode(const std::string& in, Bytes* out, std::string* error) {
  BitWriter w;
  for (unsigned char ch : in) {
    if (kH3Huff[ch].bits == 0) {
      *error = "h3: no huffman code for byte";
      return false;
    }
    w.put(kH3Huff[ch].code, kH3Huff[ch].bits);
  }
  w.flush();
  *out = w.out;
  return true;
}

// A minimal QPACK field-section builder covering exactly the three static-table
// representations this decoder accepts.  It needs no dynamic table, which is
// the point: it is what a peer that never inserts is allowed to send.
void qpack_put_int(Bytes* out, u64 value, int prefix_bits, u8 flags) {
  const u64 mask = (u64(1) << prefix_bits) - 1u;
  if (value < mask) {
    out->push_back(u8(flags | u8(value)));
    return;
  }
  out->push_back(u8(flags | u8(mask)));
  value -= mask;
  while (value >= 128) {
    out->push_back(u8(value & 0x7fu) | 0x80u);
    value >>= 7;
  }
  out->push_back(u8(value));
}

// The prefix width and the position of the Huffman flag differ between a value
// string (7 bits, flag 0x80) and the name of a literal-literal field line
// (3 bits, flag 0x08), so the caller supplies both.
void qpack_put_string_prefixed(Bytes* out, const std::string& s, int prefix_bits, u8 flags,
                               u8 huffman_flag) {
  Bytes huff;
  std::string ignored;
  if (!h3_huffman_encode(s, &huff, &ignored) || huff.size() >= s.size()) {
    qpack_put_int(out, s.size(), prefix_bits, flags);
    out->insert(out->end(), s.begin(), s.end());
    return;
  }
  qpack_put_int(out, huff.size(), prefix_bits, u8(flags | huffman_flag));
  out->insert(out->end(), huff.begin(), huff.end());
}

void qpack_put_string(Bytes* out, const std::string& s) {
  qpack_put_string_prefixed(out, s, 7, 0x00, 0x80u);
}

// The field-section prefix: Required Insert Count 0 and Delta Base 0 (RFC 9204
// sections 4.5.1.1 and 4.5.1.2).  A field section carries exactly one prefix no
// matter how many field lines follow it, so the line builders below never emit
// one -- concatenating five self-contained sections, as an earlier version of
// this self-check did, produces a second bogus prefix that decodes as a post-base
// field line.
void qpack_prefix(Bytes* out) {
  qpack_put_int(out, 0, 8, 0x00);  // Required Insert Count
  qpack_put_int(out, 0, 7, 0x00);  // Delta Base, S = 0
}

void qpack_line_indexed(Bytes* out, u64 static_index) {
  qpack_put_int(out, static_index, 6, 0xc0);  // 1Txxxxxx with T = 1 (static)
}

void qpack_line_literal_ref(Bytes* out, u64 static_index, const std::string& value) {
  qpack_put_int(out, static_index, 4, 0x50);  // 01NTxxxx with T = 1 (static)
  qpack_put_string(out, value);
}

void qpack_line_literal(Bytes* out, const std::string& name, const std::string& value) {
  // 001NHHHH: the name length is a 3-bit prefix with its own Huffman flag.
  qpack_put_string_prefixed(out, name, 3, 0x20, 0x08u);
  qpack_put_string(out, value);
}

Bytes h3_frame_bytes(u64 type, const Bytes& payload) {
  Bytes out;
  quic_varint_put(&out, type);
  quic_varint_put(&out, payload.size());
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

bool starts_with(const std::string& s, const char* prefix) {
  return s.rfind(prefix, 0) == 0;
}

// Seal a 1-RTT packet the way a sender would, so the receiver can be tested
// against a round trip rather than only against a fixed vector.  This exists
// for the self-check; it is not part of the library surface.
bool build_short_packet_for_test(const QuicKeyset& keys, std::size_t dcid_len, u64 pn,
                                 int pn_length, bool key_phase, const Bytes& payload,
                                 Bytes* out, std::string* error) {
  out->clear();
  const u8 first = u8(0x40) | u8(key_phase ? 0x04 : 0x00) | u8(pn_length - 1);
  out->push_back(first);
  out->insert(out->end(), dcid_len, 0xab);  // the DCID the receiver already knows
  const std::size_t pn_offset = out->size();
  for (int i = pn_length - 1; i >= 0; --i) out->push_back(u8(pn >> (8 * i)));

  Bytes header = *out;
  Bytes nonce = keys.iv;
  for (int i = 0; i < 8; ++i) nonce[nonce.size() - 1 - std::size_t(i)] ^= u8(pn >> (8 * i));

  Bytes ct, tag;
  if (keys.is_chacha20()) {
    AeadResult r = chacha20_poly1305_encrypt(keys.key, nonce, header, payload);
    if (!r.ok) {
      *error = "h3: chacha20 round-trip encryption failed";
      return false;
    }
    ct = r.ciphertext;
    tag = r.tag;
  } else {
    AeadResult r = aes_gcm_encrypt(keys.key, nonce, header, payload);
    if (!r.ok) {
      *error = "h3: aes-gcm round-trip encryption failed";
      return false;
    }
    ct = r.ciphertext;
    tag = r.tag;
  }
  out->insert(out->end(), ct.begin(), ct.end());
  out->insert(out->end(), tag.begin(), tag.end());

  // Apply header protection, including the self-consistent case where the
  // sample overlaps the packet number itself.
  const std::size_t sample_at = pn_offset + 4;
  if (sample_at + kQuicHpSampleLen > out->size()) {
    *error = "h3: test packet is too short for its own header protection sample";
    return false;
  }
  u8 mask[5];
  if (!hp_mask(keys, out->data() + sample_at, mask, error)) return false;
  (*out)[0] ^= (mask[0] & 0x1f);  // short header: five bits, same as the opener
  for (int i = 0; i < pn_length; ++i) (*out)[pn_offset + std::size_t(i)] ^= mask[1 + i];
  return true;
}

}  // namespace

bool h3_selfcheck(std::string* report) {
  std::string error_sink;  // so a caller may pass nullptr for the report
  if (report == nullptr) report = &error_sink;
  std::string err;
  // The report is one line per checked group: "ok   <group>" for every group that
  // finished and "FAIL <group>: <detail>" for the one that did not.  A group is
  // only listed as ok because a *later* group started, so a failure inside the
  // last group can never be reported as ok.
  std::vector<std::string> groups;
  const auto mark = [&](const char* name) { groups.push_back(name); };
  const auto fail = [&](const std::string& what) {
    if (report) {
      std::string text;
      for (std::size_t i = 0; i + 1 < groups.size(); ++i) text += "ok   " + groups[i] + "\n";
      text += "FAIL ";
      if (!groups.empty()) text += groups.back() + ": ";
      text += what + "\n";
      *report = text;
    }
    return false;
  };
  // `err` is read here, at throw time, not at the call site: an
  // `expect(call(..., &err), "x: " + err)` would build the message before the
  // call ran and report the *previous* check's error.  A message that ends with
  // ": " is asking for the current error to be appended; any other message is
  // self-contained, so a stale error from an earlier check stays out of it.
  const auto expect = [&](bool cond, const std::string& what) {
    if (cond) return;
    const bool wants_error = what.size() >= 2 && what.compare(what.size() - 2, 2, ": ") == 0;
    if (wants_error && !err.empty()) throw what + "[" + err + "]";
    throw std::string(what);
  };

  try {
    // -----------------------------------------------------------------
    // 1. RFC 9001 A.5: traffic secret -> key / iv / hp / ku
    mark("RFC 9001 A.5: a traffic secret derives quic key / quic iv / quic hp / quic ku");
    // -----------------------------------------------------------------
    const Bytes secret = from_hex(
        "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    QuicKeyset keys;
    expect(quic_keyset_from_secret(kH3TlsChacha20Poly1305Sha256, secret, &keys, &err),
           "A.5 keyset derivation failed: ");
    expect(to_hex(keys.key) ==
               "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8",
           "A.5 key mismatch: " + to_hex(keys.key));
    expect(to_hex(keys.iv) == "e0459b3474bdd0e44a41c144", "A.5 iv mismatch: " + to_hex(keys.iv));
    expect(to_hex(keys.hp) ==
               "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
           "A.5 hp mismatch: " + to_hex(keys.hp));

    Bytes next;
    expect(quic_next_secret(secret, &next, &err), "quic ku failed: ");
    expect(to_hex(next) ==
               "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9",
           "A.5 ku mismatch: " + to_hex(next));

    // The same secret must also derive the AES-128-GCM keyset of RFC 9001 A.1's
    // client_initial_secret, which exercises the other HP path.
    QuicKeyset aes_keys;
    expect(quic_keyset_from_secret(
               kH3TlsAes128GcmSha256,
               from_hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
               &aes_keys, &err),
           "A.1 keyset derivation failed: ");
    expect(to_hex(aes_keys.key) == "1f369613dd76d5467730efcbe3b1a22d",
           "A.1 key mismatch: " + to_hex(aes_keys.key));
    expect(to_hex(aes_keys.iv) == "fa044b2f42a3fd3b46fb255c", "A.1 iv mismatch");
    expect(to_hex(aes_keys.hp) == "9f50449e04a0e810283a1e9933adedd2", "A.1 hp mismatch");

    // The suite must not be guessed: an unknown one is refused, as is a secret
    // whose length disagrees with the suite.
    QuicKeyset bad;
    expect(!quic_keyset_from_secret(0x1304, secret, &bad, &err),
           "an unknown cipher suite was accepted");
    expect(quic_keyset_from_secret(kH3TlsAes256GcmSha384, secret, &bad, &err) == false,
           "a 32-byte secret was accepted for a SHA-384 suite");

    // -----------------------------------------------------------------
    // 2. RFC 9001 A.5: the 1-RTT packet itself
    mark("RFC 9001 A.5: the 1-RTT packet opens to pn 654360564 / header 4200bff4 / "
         "payload 01");
    //    packet = 4cfe4189655e5cd55c41f690805d7999c25a5bfb, pn = 654360564
    // -----------------------------------------------------------------
    // Verbatim from the RFC text (also kept at _h3/rfc9001_a5.txt): a first
    // transcription dropped the "75" in the tag and produced a 20-byte packet,
    // which the length check below now catches instead of an AEAD failure.
    const Bytes packet = from_hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    expect(packet.size() == 21, "RFC 9001 A.5 packet is " + std::to_string(packet.size()) +
                                    " bytes, not the 21 the RFC states");
    // The vector states the full packet number (654360564) but the packet only
    // carries its low 24 bits, so RFC 9000 section 17.1 can only recover that
    // number if the receiver's largest received number is inside the same 2^24
    // window: expected = largest_pn + 1 must have the bits of 0x2700BFF4, so
    // largest_pn = 654360563.  Passing 0 is not a valid reading of this vector;
    // it must decode 49140 and then fail to authenticate, which the check below
    // also pins down.
    constexpr u64 kA5LargestPn = 654360563u;
    constexpr u64 kA5Pn = 654360564u;
    QuicShortHeader hdr;
    const bool opened = quic_decrypt_short_full(keys, nullptr, 0, packet.data(), packet.size(),
                                                kA5LargestPn, &hdr, &err);
    expect(opened, "A.5 packet did not open");
    expect(hdr.packet_number == kA5Pn,
           "A.5 packet number mismatch: " + std::to_string(hdr.packet_number));
    expect(hdr.pn_length == 3, "A.5 packet number length mismatch");
    expect(hdr.first_byte_unprotected == 0x42,
           "A.5 unprotected first byte mismatch");
    expect(to_hex(hdr.header) == "4200bff4",
           "A.5 unprotected header mismatch: " + to_hex(hdr.header));
    expect(to_hex(hdr.payload) == "01", "A.5 payload mismatch: " + to_hex(hdr.payload));
    expect(hdr.key_phase == false, "A.5 key phase should be clear");
    expect(hdr.header_end == 4, "A.5 header length mismatch");

    // The same packet read against a wrong largest_pn must not silently produce
    // a different packet number and a payload: the window rule makes it decode
    // 49140, and the AEAD then has to reject it.
    {
      QuicShortHeader wrong_window;
      const bool bogus = quic_decrypt_short_full(keys, nullptr, 0, packet.data(), packet.size(), 0,
                                                 &wrong_window, &err);
      if (bogus) {
        expect(false, "the A.5 packet opened with largest_pn = 0, so the packet number window "
                      "was ignored");
      } else {
        expect(starts_with(err, "quic: packet failed to authenticate"),
               "wrong error for the A.5 packet with largest_pn = 0");
      }
    }

    // The convenience overload must agree.
    u64 pn_out = 0;
    Bytes payload_out;
    const bool convenient = quic_decrypt_short(keys, nullptr, 0, packet.data(), packet.size(),
                                               kA5LargestPn, &pn_out, &payload_out, &err);
    expect(convenient, "A.5 convenience overload failed: ");
    expect(pn_out == kA5Pn && to_hex(payload_out) == "01",
           "A.5 convenience overload disagrees with the full one");

    // A frame walker must see one PING.
    std::vector<QuicFrameInfo> frames;
    expect(quic_parse_frames_rtt(payload_out.data(), payload_out.size(), &frames, &err),
           "A.5 frame walk failed: ");
    expect(frames.size() == 1 && frames[0].type == 0x01, "A.5 payload is not a single PING");

    // -----------------------------------------------------------------
    // 3. Round trip: build a 1-RTT packet and open it again
    mark("round trip: a packet built here opens again for every packet-number length, "
         "both key phases, and must refuse a corrupted one");
    // -----------------------------------------------------------------
    for (int pn_length = 1; pn_length <= 4; ++pn_length) {
      const u64 pn = 0x1234u + u64(pn_length);
      const Bytes body = from_hex("0102030405060708");
      Bytes made;
      expect(build_short_packet_for_test(keys, 0, pn, pn_length, false, body, &made, &err),
             "round-trip build failed: ");
      QuicShortHeader rt;
      expect(quic_decrypt_short_full(keys, nullptr, 0, made.data(), made.size(), pn - 1, &rt,
                                     &err),
             "round-trip open failed: ");
      expect(rt.packet_number == pn, "round-trip packet number mismatch");
      expect(rt.payload == body, "round-trip payload mismatch");
      expect(rt.pn_length == pn_length, "round-trip pn length mismatch");
    }

    // A key phase flip is visible, so a caller can follow a key update.
    {
      Bytes made;
      // A 2-byte packet number plus a 16-byte tag does not leave room for the
      // 16-byte header protection sample, so a sender pads with a longer
      // payload here (RFC 9001 section 5.4.2 requires the sample to exist);
      // this is the same reason the RFC's own A.5 example uses a 3-byte number.
      const Bytes padded = from_hex("0102030405060708090a0b0c");
      expect(build_short_packet_for_test(keys, 0, 7, 2, true, padded, &made, &err),
             "key phase build failed: ");
      QuicShortHeader rt;
      expect(quic_decrypt_short_full(keys, nullptr, 0, made.data(), made.size(), 0, &rt, &err),
             "key phase open failed: ");
      expect(rt.key_phase, "key phase bit was not reported");
    }

    // A long header must be refused rather than misread.
    {
      Bytes long_header = packet;
      long_header[0] |= 0x80;
      QuicShortHeader rt;
      expect(!quic_decrypt_short_full(keys, nullptr, 0, long_header.data(), long_header.size(), 0,
                                      &rt, &err),
             "a long header was accepted as 1-RTT");
      expect(starts_with(err, "quic: packet has the long header bit set"),
             "wrong error for a long header: ");
    }

    // Corrupting the tag must fail authentication, not silently produce bytes.
    {
      Bytes broken = packet;
      broken[broken.size() - 1] ^= 0xff;
      QuicShortHeader rt;
      expect(!quic_decrypt_short_full(keys, nullptr, 0, broken.data(), broken.size(), 0, &rt, &err),
             "a corrupted packet authenticated");
      expect(starts_with(err, "quic: packet failed to authenticate"),
             "wrong error for a corrupted packet: ");
    }

    // -----------------------------------------------------------------
    // 4. QPACK: RFC 9204 appendix B.1 is a literal with a name reference
    mark("QPACK: RFC 9204 appendix B.1 decodes, the Huffman table round trips, and the "
         "static table is 0-based with 99 entries");
    //    and a Huffman-coded value.
    // -----------------------------------------------------------------
    {
      const Bytes section = from_hex("0000510b2f696e6465782e68746d6c");
      std::vector<std::pair<std::string, std::string>> fields;
      expect(h3_decode_field_section(section, &fields, &err), "B.1 decode failed: ");
      expect(fields.size() == 1 && fields[0].first == ":path" && fields[0].second == "/index.html",
             "B.1 decoded to " + (fields.empty() ? std::string("nothing")
                                                : fields[0].first + "=" + fields[0].second));
    }

    // An indexed field line must resolve through the static table.
    {
      const Bytes section = from_hex("0000d1");  // static index 17 = :method GET
      std::vector<std::pair<std::string, std::string>> fields;
      expect(h3_decode_field_section(section, &fields, &err), "indexed decode failed: ");
      expect(fields.size() == 1 && fields[0].first == ":method" && fields[0].second == "GET",
             "static index 17 did not decode to :method GET");
    }

    // The dynamic table must be refused with an exact reason, not guessed.
    {
      const Bytes section = from_hex("0300");  // Required Insert Count = 3
      std::vector<std::pair<std::string, std::string>> fields;
      expect(!h3_decode_field_section(section, &fields, &err),
             "a dynamic-table field section was decoded");
      expect(starts_with(err, "qpack: Required Insert Count is 3"),
             "wrong error for a dynamic-table field section: ");
    }

    // -----------------------------------------------------------------
    // 5. A hand-built HTTP/3 request stream, plus the frame walker
    mark("HTTP/3: a hand-built request stream yields :method/:scheme/:authority/:path, the "
         "frame walker names every frame, and the deliberate refusals all fire");
    // -----------------------------------------------------------------
    // The constructors below are only trustworthy if the encoder that feeds the
    // decoder agrees with it byte for byte; without this check a broken encoder
    // and a matching broken decoder would agree on nonsense forever.
    for (const char* sample : {"/hello?x=1", "example.com", "user-agent", "h3_probe/1.0", "?x=1",
                               "https", "</x>", ">", "a>b?c=d"}) {
      Bytes huff;
      std::string enc_err;
      expect(h3_huffman_encode(sample, &huff, &enc_err), "huffman encode failed: ");
      std::string back;
      expect(h3_huffman_decode(huff.data(), huff.size(), &back, &enc_err),
             std::string("huffman decode failed for \"") + sample + "\": ");
      expect(back == sample, std::string("huffman round trip of \"") + sample + "\" gave \"" + back +
                                 "\" via " + to_hex(huff));
    }

    // A Huffman code must be prefix-free.  Where a row is a prefix of another
    // row the decoder's first match wins, so one bad row corrupts every string
    // that contains the symbol -- which is exactly how the '>' row inherited
    // from src/http2.cpp failed the round trip above before it was corrected.
    {
      bool prefix_free = true;
      std::string clash;
      for (int i = 0; i < 256 && prefix_free; ++i) {
        for (int j = 0; j < 256; ++j) {
          if (i == j) continue;
          const int bi = kH3Huff[i].bits;
          const int bj = kH3Huff[j].bits;
          if (bj <= bi) continue;
          if ((kH3Huff[j].code >> (bj - bi)) == kH3Huff[i].code) {
            prefix_free = false;
            clash = "symbol " + std::to_string(i) + " is a prefix of symbol " + std::to_string(j);
            break;
          }
        }
      }
      expect(prefix_free, "the Huffman table is not prefix-free: " + clash);
      for (int i = 0; i < 257; ++i) {
        expect(kH3Huff[i].bits >= 1 && kH3Huff[i].bits <= 30,
               "huffman symbol " + std::to_string(i) + " has an impossible width");
      }
    }

    Bytes field_section;
    {
      // One prefix, then five field lines -- exactly what a client sends in one
      // HEADERS frame.
      qpack_prefix(&field_section);
      qpack_line_indexed(&field_section, 17);                     // :method GET
      qpack_line_literal_ref(&field_section, 23, "https");         // :scheme https
      qpack_line_literal(&field_section, ":authority", "example.com");
      qpack_line_literal_ref(&field_section, 1, "/hello?x=1");    // :path
      qpack_line_literal(&field_section, "user-agent", "h3_probe/1.0");
    }

    Bytes request_stream;
    quic_varint_put(&request_stream, 0x00);  // client-initiated bidirectional stream
    {
      const Bytes headers = h3_frame_bytes(kH3FrameHeaders, field_section);
      request_stream.insert(request_stream.end(), headers.begin(), headers.end());
      const Bytes data = h3_frame_bytes(kH3FrameData, Bytes{0x68, 0x69});
      request_stream.insert(request_stream.end(), data.begin(), data.end());
    }

    H3Request req;
    expect(h3_request_from_stream(request_stream, true, &req, &err),
           "hand-built request failed: ");
    expect(req.method == "GET" && req.scheme == "https" && req.authority == "example.com" &&
               req.path == "/hello?x=1",
           "hand-built request decoded as " + req.method + " " + req.scheme + "://" +
               req.authority + req.path);
    expect(req.has_pseudo, "hand-built request lost its pseudo-headers");
    expect(req.headers.size() == 1 && req.headers[0].first == "user-agent",
           "hand-built request headers are wrong");

    // The same bytes, reached through the frame list (offset 0 + FIN).
    {
      std::vector<QuicFrameInfo> stream_frames;
      QuicFrameInfo f;
      f.type = 0x0f;  // STREAM with the OFF, LEN and FIN bits (0x08|0x04|0x02|0x01)
      f.type_name = "STREAM";
      f.stream.stream_id = 4;
      f.stream.offset = 0;
      f.stream.length = request_stream.size();
      f.stream.fin = true;
      f.data = request_stream;
      stream_frames.push_back(f);
      H3Request via_frames;
      expect(h3_request_from_stream_frames(stream_frames, &via_frames, &err),
             "request from frames failed: ");
      expect(via_frames.path == "/hello?x=1" && via_frames.stream_id == 4,
             "request from frames decoded the wrong stream");
    }

    // A request stream the server could not have received: prefix 1 is a
    // server-initiated stream, and an unknown pseudo-header is illegal.
    {
      Bytes bad = request_stream;
      bad[0] = 0x01;
      H3Request r2;
      expect(!h3_request_from_stream(bad, true, &r2, &err), "prefix 1 was accepted");
      expect(starts_with(err, "h3: request stream must begin with the varint 0x00"),
             "wrong error for a bad stream prefix: ");
    }

    // DATA before HEADERS is a connection error (RFC 9114 section 4.1).
    {
      Bytes bad;
      quic_varint_put(&bad, 0x00);
      const Bytes data = h3_frame_bytes(kH3FrameData, Bytes{0x68});
      bad.insert(bad.end(), data.begin(), data.end());
      H3Request r2;
      expect(!h3_request_from_stream(bad, true, &r2, &err), "DATA before HEADERS was accepted");
      expect(starts_with(err, "h3: DATA frame arrives before the HEADERS frame"),
             "wrong error for DATA before HEADERS: ");
    }

    // A control stream: type 0 then SETTINGS, and SETTINGS must come first.
    {
      Bytes control;
      quic_varint_put(&control, kH3StreamControl);
      Bytes settings_body;
      quic_varint_put(&settings_body, 0x01);  // SETTINGS_QPACK_MAX_TABLE_CAPACITY
      quic_varint_put(&settings_body, 0);
      quic_varint_put(&settings_body, 0x06);  // SETTINGS_MAX_FIELD_SECTION_SIZE
      quic_varint_put(&settings_body, 65536);
      const Bytes settings = h3_frame_bytes(kH3FrameSettings, settings_body);
      control.insert(control.end(), settings.begin(), settings.end());
      H3UniStream uni;
      expect(h3_parse_uni_stream(control, &uni, &err), "control stream failed: ");
      expect(uni.type == kH3StreamControl && uni.type_name == "control",
             "control stream type mismatch");
      expect(uni.frames.size() == 1 && uni.frames[0].type == kH3FrameSettings,
             "control stream frames are wrong");
      expect(uni.frames[0].payload == settings_body, "SETTINGS payload mismatch");

      Bytes no_settings;
      quic_varint_put(&no_settings, kH3StreamControl);
      const Bytes goaway = h3_frame_bytes(kH3FrameGoaway, Bytes{0x00});
      no_settings.insert(no_settings.end(), goaway.begin(), goaway.end());
      H3UniStream uni2;
      expect(!h3_parse_uni_stream(no_settings, &uni2, &err),
             "a control stream without a leading SETTINGS was accepted");
      expect(starts_with(err, "h3: a control stream must send SETTINGS as its first frame"),
             "wrong error for a control stream without SETTINGS: ");
    }

    // The frame walker names every frame the brief lists, and refuses an
    // unknown QUIC frame type rather than skipping it.
    {
      std::vector<QuicFrameInfo> f;
      const Bytes ok = from_hex(
          "0000"                  // PADDING x2
          "01"                    // PING
          "02"                    // ACK
          "4112"                  // largest = 274 as a real two-byte varint (01|xx)
          "00"                    // ack delay
          "00"                    // range count
          "00"                    // first range
          "06"                    // CRYPTO
          "00" "01" "aa"          // offset 0, length 1, byte 0xaa
          "0f"                    // STREAM: 0x08 base | 0x04 OFF | 0x02 LEN | 0x01 FIN
          "04"                    // stream id 4
          "00"                    // offset 0
          "02"                    // length 2
          "6162");                // "ab"
      // The call is made first and the message built afterwards: `expect` appends
      // the current `err`, and a message built inside the call's own argument list
      // reads a stale `err` (argument evaluation order is unspecified).
      err.clear();
      const bool walked = quic_parse_frames_rtt(ok.data(), ok.size(), &f, &err);
      expect(walked, "frame walker failed: " + err);
      expect(f.size() == 5, "frame walker produced " + std::to_string(f.size()) + " frames");
      expect(f[0].type == 0x00 && f[0].note == "padding 2", "PADDING note mismatch: " + f[0].note);
      expect(f[1].type == 0x01, "PING missing");
      expect(f[2].type == 0x02, "ACK missing");
      // "4112" is a real two-byte varint, so this also pins the varint path: the
      // one-byte encoding of the same value would be "74" and would decode 274
      // only by accident of where the following bytes land.
      expect(f[2].note == "ack largest 274 0 ranges", "ACK note mismatch: " + f[2].note);
      expect(f[3].type == 0x06 && f[3].data.size() == 1 && f[3].data[0] == 0xaa,
             "CRYPTO frame mismatch");
      expect(f[4].type == 0x0f && f[4].stream.fin && f[4].stream.length == 2,
             "STREAM frame mismatch");

      const Bytes unknown = from_hex("3f");  // frame type 0x3f is unassigned
      expect(!quic_parse_frames_rtt(unknown.data(), unknown.size(), &f, &err),
             "an unknown frame type was accepted");
      expect(starts_with(err, "quic: unknown frame type 0x3f"),
             "wrong error for an unknown frame type: ");

      // The STREAM type bits are 0x08 base, 0x04 OFF, 0x02 LEN, 0x01 FIN, so a
      // frame with LEN and no OFF bit is 0x0a (0x0e already has the OFF bit) and
      // must not consume an offset.  Getting this bit map wrong is invisible
      // unless both forms are walked: 0x0b is LEN|FIN with no offset, and reading
      // it as OFF|LEN|FIN made the walker mis-read the payload while still
      // looking like it worked.
      std::vector<QuicFrameInfo> g;
      err.clear();
      const Bytes no_off = from_hex("0a" "04" "02" "6162");
      const bool walked_no_off = quic_parse_frames_rtt(no_off.data(), no_off.size(), &g, &err);
      expect(walked_no_off, "a STREAM frame without the OFF bit failed: " + err);
      expect(g.size() == 1 && g[0].stream.stream_id == 4 && g[0].stream.offset == 0 &&
                 g[0].stream.length == 2 && g[0].data.size() == 2,
             "a STREAM frame without the OFF bit decoded wrongly");
      // A STREAM length past the end of the payload must be refused rather than
      // read past the buffer.
      const Bytes too_long = from_hex("0a" "04" "09" "6162");
      expect(!quic_parse_frames_rtt(too_long.data(), too_long.size(), &g, &err),
             "a STREAM length past the end of the payload was accepted");
      expect(starts_with(err, "quic: STREAM frame claims more bytes than the payload holds"),
             "wrong error for an over-long STREAM length: ");
    }

    // A CONNECTION_CLOSE and a NEW_CONNECTION_ID must both walk cleanly.
    {
      std::vector<QuicFrameInfo> f;
      const Bytes ok = from_hex(
          "1c"            // CONNECTION_CLOSE (transport)
          "0a"            // error code 10
          "06"            // frame type 6
          "03" "627965"); // reason "bye"
      expect(quic_parse_frames_rtt(ok.data(), ok.size(), &f, &err),
             "CONNECTION_CLOSE failed: ");
      expect(f.size() == 1 && f[0].note == "transport error 10: bye",
             "CONNECTION_CLOSE note mismatch: " + f[0].note);
    }
  } catch (const std::string& what) {
    return fail(what);
  } catch (const std::exception& e) {
    return fail(e.what());
  }
  if (report) {
    std::string text;
    for (const std::string& g : groups) text += "ok   " + g + "\n";
    *report = text;
  }
  return true;
}

// ===========================================================================
// Public: the two tables the writer shares with this reader (see h3.hpp)
//
// Exposed rather than copied: `src/h3_write.cpp` encodes with exactly the rows
// this file decodes with, so an encoder/decoder disagreement about a static
// entry or a Huffman code is structurally impossible rather than merely tested
// for.
// ===========================================================================

bool h3_static_entry(std::size_t index, std::string* name, std::string* value) {
  if (name) name->clear();
  if (value) value->clear();
  const H3StaticEntry* e = static_by_index(index);
  if (e == nullptr) return false;
  if (name) *name = e->name;
  if (value) *value = e->value;
  return true;
}

bool h3_static_name_index(const std::string& name, std::size_t* index) {
  for (std::size_t i = 0; i < kH3StaticTableSize; ++i) {
    if (name == kH3Static[i].name) {
      if (index) *index = i;
      return true;
    }
  }
  return false;
}

bool h3_static_exact_index(const std::string& name, const std::string& value, std::size_t* index) {
  for (std::size_t i = 0; i < kH3StaticTableSize; ++i) {
    if (name == kH3Static[i].name && value == kH3Static[i].value) {
      if (index) *index = i;
      return true;
    }
  }
  return false;
}

const H3HuffmanCode& h3_huffman_code(std::size_t symbol) {
  static const H3HuffmanCode kOutOfRange{0, 0};
  if (symbol > 256) return kOutOfRange;
  return kH3Huff[symbol];
}

bool h3_huffman_decode_bytes(const u8* data, std::size_t len, std::string* out,
                             std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    *error = "hpack: h3_huffman_decode_bytes was given a null output";
    return false;
  }
  return h3_huffman_decode(data, len, out, error);
}

// ===========================================================================
// Public: response streams
//
// The same walk as `h3_request_from_stream`, with two differences that the RFC
// makes: the mandatory pseudo-header is `:status`, and the stream may carry
// DATA, which a request's first HEADERS-only prefix was never asked about.
// ===========================================================================

namespace {

bool fill_response_fields(const std::vector<std::pair<std::string, std::string>>& fields,
                          H3Response* out, bool trailers, std::string* error) {
  for (const auto& kv : fields) {
    if (kv.first.empty() || kv.first[0] != ':') {
      out->headers.push_back(kv);
      continue;
    }
    if (kv.first != ":status") {
      if (error) *error = "h3: unknown response pseudo-header field \"" + kv.first + "\"";
      return false;
    }
    if (trailers) {
      if (error) {
        *error = "h3: a trailer field section must not carry \":status\" "
                 "(RFC 9114 section 4.1)";
      }
      return false;
    }
    if (out->has_status) {
      if (error) *error = "h3: the response declares \":status\" twice";
      return false;
    }
    out->status = kv.second;
    out->has_status = true;
  }
  return true;
}

}  // namespace

bool h3_response_from_stream(const Bytes& stream_bytes, bool client_initiated_bidi,
                             H3Response* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (out == nullptr) {
    *error = "h3: h3_response_from_stream was given a null output";
    return false;
  }
  *out = H3Response();
  if (!client_initiated_bidi) {
    *error = "h3: server-initiated bidirectional streams carry no HTTP response";
    return false;
  }
  if (stream_bytes.empty()) {
    *error = "h3: response stream is empty";
    return false;
  }
  u64 prefix = 0;
  std::size_t used = 0;
  if (!quic_varint(stream_bytes.data(), stream_bytes.size(), &prefix, &used)) {
    *error = "h3: truncated response-stream prefix varint";
    return false;
  }
  if (prefix != 0x00) {
    *error = "h3: response stream must begin with the varint 0x00, not " + std::to_string(prefix);
    return false;
  }
  std::vector<H3Frame> frames;
  if (!h3_parse_frames(stream_bytes.data() + used, stream_bytes.size() - used, &frames, error)) {
    return false;
  }
  for (const H3Frame& f : frames) {
    if (f.type == kH3FrameHeaders) {
      std::vector<std::pair<std::string, std::string>> fields;
      if (!h3_decode_field_section(f.payload, &fields, error)) return false;
      const bool trailers = out->has_headers;
      if (!fill_response_fields(fields, out, trailers, error)) return false;
      if (trailers) out->has_trailers = true;
      out->has_headers = true;
    } else if (f.type == kH3FrameData) {
      if (!out->has_headers) {
        *error = "h3: DATA frame arrives before the HEADERS frame (RFC 9114 section 4.1)";
        return false;
      }
      if (!f.payload.empty()) {
        out->body.append(reinterpret_cast<const char*>(f.payload.data()), f.payload.size());
      }
    }
  }
  if (!out->has_headers) {
    *error = "h3: response stream carries no HEADERS frame";
    return false;
  }
  if (!out->has_status) {
    *error = "h3: response is missing the \":status\" pseudo-header (RFC 9114 section 4.3.1)";
    return false;
  }
  return true;
}

bool h3_response_from_stream(const Bytes& stream_bytes, H3Response* out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  return h3_response_from_stream(stream_bytes, true, out, error);
}

}  // namespace netcap
