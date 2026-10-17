// QPACK + HTTP/3 frame writers: the writing half of the HTTP/3 story.
//
// See `include/netcap/h3_write.hpp` for the contract.  Two design decisions are
// worth repeating here, because they are what keeps this file small:
//
//   * The static table and the Huffman code table are **not** transcribed into
//     this file.  They are read from the reader through `h3_static_*` and
//     `h3_huffman_code` (declared in `h3.hpp`), so there is exactly one row per
//     entry in the program.  The last hand-typed copy of this table shipped a
//     wrong `'>'` row and corrupted every `>` in HTTP/2 (see the note above
//     `kH3Huff` in `src/h3.cpp`); a second copy would be a second chance at
//     exactly that bug, and this time without a decoder to disagree with.
//
//   * Static-table-only means the encoder has no state: no dynamic table, no
//     encoder stream, no Required Insert Count.  That is a real limitation
//     (a field section here is larger than a stateful encoder's) and it is the
//     right trade for a passive writer that must never make the peer's decoder
//     depend on anything the observer sent.
//
// Everything the writer emits is decoded back, byte for byte, through the
// existing reader in `h3_write_selfcheck` -- including the published vectors
// from RFC 9204 appendix B.1 and RFC 7541 appendix C.4.
#include "netcap/h3_write.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/h3.hpp"
#include "netcap/quic.hpp"

namespace netcap {

namespace {

// ---------------------------------------------------------------------------
// QUIC varints (RFC 9000 section 16), which HTTP/3 framing uses for every frame
// type and every frame length (RFC 9114 section 7.2).
// ---------------------------------------------------------------------------

constexpr u64 kVarintMax = (1ull << 62) - 1ull;

int varint_length(u64 value) {
  if (value < (1ull << 6)) return 1;
  if (value < (1ull << 14)) return 2;
  if (value < (1ull << 30)) return 4;
  return 8;
}

bool put_varint(std::string* out, u64 value, std::string* error) {
  if (value > kVarintMax) {
    *error = "h3: " + std::to_string(value) + " does not fit in a QUIC varint (2^62-1 is the largest)";
    return false;
  }
  const int n = varint_length(value);
  const u8 tag = u8((n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3) << 6);
  if (n == 1) {
    out->push_back(char(u8(tag | u8(value))));
    return true;
  }
  out->push_back(char(u8(tag | u8((value >> (8 * (n - 1))) & 0x3full))));
  for (int shift = 8 * (n - 2); shift >= 0; shift -= 8) {
    out->push_back(char(u8((value >> shift) & 0xffull)));
  }
  return true;
}

// ---------------------------------------------------------------------------
// The prefixed integer every QPACK representation starts with
// (RFC 7541 section 5.1, reused verbatim by RFC 9204 section 4.1.1).
// ---------------------------------------------------------------------------

bool put_prefixed_int(std::string* out, u64 value, int prefix_bits, u8 flags,
                      std::string* error) {
  if (prefix_bits < 1 || prefix_bits > 8) {
    *error = "qpack: internal prefix width " + std::to_string(prefix_bits) + " is not in 1..8";
    return false;
  }
  const u64 limit = (1ull << prefix_bits) - 1ull;
  if (value < limit) {
    out->push_back(char(u8(flags | u8(value))));
    return true;
  }
  out->push_back(char(u8(flags | u8(limit))));
  value -= limit;
  while (value >= 128) {
    out->push_back(char(u8((value & 0x7full) | 0x80ull)));
    value >>= 7;
  }
  out->push_back(char(u8(value)));
  return true;
}

// ---------------------------------------------------------------------------
// Huffman (RFC 7541 appendix B, reused by RFC 9204 section 4.1.2)
//
// The codes are stored right-aligned in `bits` bits and are emitted MSB first,
// so the accumulator is shifted left by each code's width.  The final partial
// byte is padded with the most significant bits of the EOS symbol, i.e. ones
// (RFC 7541 section 5.2), which is also the only padding the reader accepts.
// ---------------------------------------------------------------------------

std::string huffman_encode(const std::string& in) {
  std::string out;
  u64 acc = 0;
  int bits = 0;
  for (std::size_t i = 0; i < in.size(); ++i) {
    const H3HuffmanCode& c = h3_huffman_code(u8(in[i]));
    if (c.bits == 0) return std::string();  // unreachable for 0..255; keeps the shift honest
    acc = (acc << c.bits) | u64(c.code);
    bits += c.bits;
    while (bits >= 8) {
      bits -= 8;
      out.push_back(char(u8((acc >> bits) & 0xffull)));
    }
    acc = (bits == 0) ? 0 : (acc & ((1ull << bits) - 1ull));
  }
  if (bits > 0) {
    const int pad = 8 - bits;
    out.push_back(char(u8(((acc << pad) | ((1ull << pad) - 1ull)) & 0xffull)));
  }
  return out;
}

// One string literal: a length with the given prefix width, the Huffman bit when
// the Huffman form is used, then the bytes.  `flags` is the fixed pattern above
// the length (e.g. 0x20 for the `001N` of a literal name) and `huffman_flag` is
// the bit at the bottom of the prefix that says "this string is Huffman-coded"
// (0x80 for the 7-bit prefix used by values, 0x08 for the 3-bit name prefix).
// They are separate parameters because the name prefix needs *both*: passing a
// single "flags" value silently dropped the 0x20 pattern and turned every
// literal-name field line into the `0001` post-base form the reader rejects.
bool put_string(std::string* out, const std::string& s, int prefix_bits, u8 flags, u8 huffman_flag,
                QpackHuffman policy, std::string* error) {
  const std::string huff = huffman_encode(s);
  bool use = false;
  switch (policy) {
    case QpackHuffman::kNever:
      use = false;
      break;
    case QpackHuffman::kAlways:
      use = true;
      break;
    case QpackHuffman::kWhenShorter:
    default:
      use = huff.size() < s.size();  // strictly shorter, never merely equal
      break;
  }
  if (s.empty()) use = false;  // an empty string has nothing to code, so H must be 0
  const std::string& body = use ? huff : s;
  const u8 first = use ? u8(flags | huffman_flag) : flags;
  if (!put_prefixed_int(out, u64(body.size()), prefix_bits, first, error)) {
    return false;
  }
  out->append(body);
  return true;
}

// ---------------------------------------------------------------------------
// Field line representations (RFC 9204 section 4.5)
// ---------------------------------------------------------------------------

// The exact error the brief asks for: an index past the static table is refused
// rather than emitted.  Every index this file produces comes from the table
// itself, so the guard is only reachable from a bug -- which is precisely why it
// is a hard failure and not a clamp.
bool static_index_ok(std::size_t index, std::string* error) {
  if (index < kH3StaticTableSize) return true;
  *error = "qpack: static table index " + std::to_string(index) +
           " is past the end of the QPACK static table (" + std::to_string(kH3StaticTableSize) +
           " entries, RFC 9204 appendix A)";
  return false;
}

// 1Txxxxxx, T=1: static table, 6-bit prefix (RFC 9204 section 4.5.2).
bool put_indexed(std::string* out, std::size_t static_index, std::string* error) {
  if (!static_index_ok(static_index, error)) return false;
  return put_prefixed_int(out, u64(static_index), 6, 0xc0, error);
}

// 01NTxxxx, N=0, T=1: static name reference, 4-bit prefix (section 4.5.4).
bool put_literal_name_ref(std::string* out, std::size_t static_index, const std::string& value,
                          QpackHuffman policy, std::string* error) {
  if (!static_index_ok(static_index, error)) return false;
  if (!put_prefixed_int(out, u64(static_index), 4, 0x50, error)) return false;
  if (!put_string(out, value, 7, 0x00, 0x80, policy, error)) return false;
  return true;
}

// 001NHHHH: literal name, literal value, 3-bit prefix on the name (section 4.5.6).
bool put_literal_literal(std::string* out, const std::string& name, const std::string& value,
                         QpackHuffman policy, std::string* error) {
  if (!put_string(out, name, 3, 0x20, 0x08, policy, error)) return false;
  return put_string(out, value, 7, 0x00, 0x80, policy, error);
}

bool encode_one_field(std::string* out, const H3Field& field, QpackHuffman policy,
                      std::string* error) {
  std::size_t index = 0;
  if (h3_static_exact_index(field.name, field.value, &index)) {
    return put_indexed(out, index, error);
  }
  if (h3_static_name_index(field.name, &index)) {
    return put_literal_name_ref(out, index, field.value, policy, error);
  }
  return put_literal_literal(out, field.name, field.value, policy, error);
}

// ---------------------------------------------------------------------------
// HTTP/3 frames (RFC 9114 section 7.2): type varint, length varint, payload.
// ---------------------------------------------------------------------------

bool append_frame(u64 type, const std::string& payload, std::string* out, std::string* error) {
  std::string sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &sink;
  if (out == nullptr) {
    *error = "h3: the frame writer was given a null output";
    return false;
  }
  std::string frame;
  if (!put_varint(&frame, type, error) || !put_varint(&frame, u64(payload.size()), error)) {
    out->clear();
    return false;
  }
  frame += payload;
  out->append(frame);
  return true;
}

}  // namespace

// ===========================================================================
// Public: QPACK field section
// ===========================================================================

bool qpack_encode_field_section(const std::vector<H3Field>& fields, QpackHuffman huffman,
                                std::string* out, std::string* error) {
  std::string sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &sink;
  if (out == nullptr) {
    *error = "qpack: qpack_encode_field_section was given a null output";
    return false;
  }
  out->clear();
  if (fields.empty()) {
    // The bytes would be legal, but this project's reader refuses an empty field
    // section ("qpack: field section decoded to no fields"), and the contract
    // here is that everything written can be read back.  A response always has
    // at least `:status`, so this is a caller bug, not a format limitation.
    *error = "qpack: a field section with no fields cannot be round-tripped (the reader refuses "
             "an empty field section)";
    return false;
  }
  std::string section;
  // Field section prefix: Required Insert Count = 0 (8-bit prefix) then the Sign
  // bit and Delta Base = 0 (7-bit prefix), i.e. the bytes `00 00` of RFC 9204
  // section 4.5.1 and appendix B.1.  A zero Required Insert Count is what tells
  // the peer that no dynamic table state is needed.
  if (!put_prefixed_int(&section, 0, 8, 0x00, error)) return false;
  if (!put_prefixed_int(&section, 0, 7, 0x00, error)) return false;
  for (const H3Field& field : fields) {
    if (!encode_one_field(&section, field, huffman, error)) {
      out->clear();
      return false;
    }
  }
  *out = section;
  return true;
}

bool qpack_encode_field_section(const std::vector<H3Field>& fields, std::string* out,
                                std::string* error) {
  return qpack_encode_field_section(fields, QpackHuffman::kWhenShorter, out, error);
}

// ===========================================================================
// Public: HTTP/3 frames
// ===========================================================================

bool h3_write_headers_frame(const std::string& field_section, std::string* out,
                            std::string* error) {
  return append_frame(kH3FrameHeaders, field_section, out, error);
}

bool h3_write_data_frame(const std::string& body, std::string* out, std::string* error) {
  return append_frame(kH3FrameData, body, out, error);
}

bool h3_encode_response(const std::vector<H3Field>& fields, const std::string& body,
                        std::string* out, std::string* error) {
  std::string sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &sink;
  if (out == nullptr) {
    *error = "h3: h3_encode_response was given a null output";
    return false;
  }
  out->clear();
  std::string field_section;
  if (!qpack_encode_field_section(fields, &field_section, error)) return false;
  std::string payload;
  if (!h3_write_headers_frame(field_section, &payload, error)) return false;
  // No DATA frame for an empty body: a zero-length DATA frame is legal but says
  // nothing, and omitting it keeps the re-encoded response the same shape as the
  // one a server would have sent.
  if (!body.empty() && !h3_write_data_frame(body, &payload, error)) {
    out->clear();
    return false;
  }
  *out = payload;
  return true;
}

bool h3_encode_response_stream(const std::vector<H3Field>& fields, const std::string& body,
                               std::string* out, std::string* error) {
  std::string sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &sink;
  if (out == nullptr) {
    *error = "h3: h3_encode_response_stream was given a null output";
    return false;
  }
  out->clear();
  std::string payload;
  if (!h3_encode_response(fields, body, &payload, error)) return false;
  std::string stream;
  // RFC 9114 section 6.1 / RFC 9000 section 2.1: a client-initiated
  // bidirectional stream begins with the stream-type varint 0x00.
  if (!put_varint(&stream, 0x00, error)) return false;
  stream += payload;
  *out = stream;
  return true;
}

// ===========================================================================
// Public: the encoders on their own
// ===========================================================================

std::string qpack_huffman_encode(const std::string& in) { return huffman_encode(in); }

bool qpack_huffman_encode(const u8* data, std::size_t len, std::string* out) {
  if (out == nullptr) return false;
  out->clear();
  if (data == nullptr && len != 0) return false;
  std::string in;
  if (len != 0) in.assign(reinterpret_cast<const char*>(data), len);
  *out = huffman_encode(in);
  return true;
}

// ===========================================================================
// Self-check
//
// Every vector below is hand-copied from an RFC and compared byte for byte; the
// round trips go through `h3_decode_field_section` / `h3_response_from_stream` /
// `h3_huffman_decode_bytes`, i.e. through `src/h3.cpp`'s tables and code, never
// through anything re-implemented here.
// ===========================================================================

bool h3_write_selfcheck(std::string* report) {
  std::string err;
  std::vector<std::string> groups;

  auto fail = [&](const std::string& what) {
    if (report) *report = "FAIL: " + what + "\n";
    return false;
  };
  auto expect = [&](bool ok, const std::string& what) {
    if (!ok) throw std::string(what);
  };
  auto mark = [&](const std::string& name) { groups.push_back(name); };
  auto hex_of = [](const std::string& s) {
    return s.empty() ? std::string("(empty)")
                     : to_hex(reinterpret_cast<const u8*>(s.data()), s.size());
  };
  // The reader takes `Bytes` (opaque octets), the writer works on `std::string`
  // (HTTP/3 field values are opaque bytes, not text), so the self-check converts
  // rather than pretending the two are interchangeable.
  auto to_bytes = [](const std::string& s) {
    Bytes b;
    b.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) b.push_back(u8(s[i]));
    return b;
  };
  // Decode one field section through the reader and compare, pair by pair.
  auto round_trip = [&](const std::vector<H3Field>& fields, QpackHuffman policy,
                        const std::string& what) {
    std::string section;
    expect(qpack_encode_field_section(fields, policy, &section, &err),
           what + ": encode failed: " + err);
    std::vector<std::pair<std::string, std::string>> decoded;
    expect(h3_decode_field_section(to_bytes(section), &decoded, &err),
           what + ": the reader refused what the writer produced: " + err);
    expect(decoded.size() == fields.size(),
           what + ": field count changed, " + std::to_string(fields.size()) + " -> " +
               std::to_string(decoded.size()));
    for (std::size_t i = 0; i < fields.size(); ++i) {
      expect(decoded[i].first == fields[i].name && decoded[i].second == fields[i].value,
             what + ": field " + std::to_string(i) + " changed, \"" + fields[i].name +
                 ": " + fields[i].value + "\" -> \"" + decoded[i].first + ": " +
                 decoded[i].second + "\"");
    }
    return section;
  };

  try {
    // -----------------------------------------------------------------------
    // RFC 9204 appendix B.1: a literal field line with a static name reference.
    // The published bytes are `0000 510b 2f696e6465782e68746d6c`: Required
    // Insert Count 0, Base 0, then static index 1 (`:path`) with the *raw*
    // value "/index.html".  Reproducing them needs the Huffman choice pinned to
    // "never" -- the default rule finds the Huffman form of that value strictly
    // shorter and would legitimately emit it instead, which is the one place
    // where "shortest legal encoding" and "the RFC's example" disagree.
    // -----------------------------------------------------------------------
    {
      const std::vector<H3Field> fields = {{":path", "/index.html"}};
      const std::string rfc = round_trip(fields, QpackHuffman::kNever, "RFC 9204 B.1");
      expect(hex_of(rfc) == "0000510b2f696e6465782e68746d6c",
             "RFC 9204 B.1 bytes differ: " + hex_of(rfc) +
                 " (expected 0000510b2f696e6465782e68746d6c)");
      const std::string shortest = round_trip(fields, QpackHuffman::kWhenShorter, "RFC 9204 B.1 default");
      expect(shortest.size() < rfc.size(),
             "the default policy should Huffman-code \"/index.html\" (13 -> 12 bytes)");
      const std::string always = round_trip(fields, QpackHuffman::kAlways, "RFC 9204 B.1 huffman");
      expect(always == shortest, "kAlways and kWhenShorter must agree for a shorter Huffman form");
      mark("RFC 9204 B.1 byte for byte: 0000510b2f696e6465782e68746d6c (kNever); default is " +
           hex_of(shortest) + " and decodes back identically");
    }

    // -----------------------------------------------------------------------
    // RFC 7541 appendix C.4: the HPACK Huffman vectors, which QPACK reuses
    // (RFC 9204 section 4.1.2).  These are the byte-exact encoder-side proof
    // that the shared table is right in the encode direction too, and each one
    // is decoded back by the reader's decoder.
    // -----------------------------------------------------------------------
    {
      struct Vec {
        const char* text;
        const char* hex;
      };
      const Vec vectors[] = {
          {"www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"},  // C.4.1
          {"no-cache", "a8eb10649cbf"},                     // C.4.2
          {"custom-key", "25a849e95ba97d7f"},               // C.4.3
          {"custom-value", "25a849e95bb8e8b4bf"},           // C.4.3
      };
      for (const Vec& v : vectors) {
        const std::string got = qpack_huffman_encode(v.text);
        expect(hex_of(got) == v.hex, std::string("RFC 7541 C.4 Huffman of \"") + v.text +
                                       "\" is " + hex_of(got) + ", expected " + v.hex);
        std::string back;
        expect(h3_huffman_decode_bytes(reinterpret_cast<const u8*>(got.data()), got.size(), &back,
                                      &err),
               std::string("the reader refused the Huffman code of \"") + v.text + "\": " + err);
        expect(back == v.text, std::string("Huffman round trip of \"") + v.text + "\" gave \"" +
                                   back + "\"");
      }
      // The row that was wrong in http2.cpp's copy: '>' is 0xffb over 12 bits.
      const H3HuffmanCode& gt = h3_huffman_code(u8('>'));
      expect(gt.code == 0xffb && gt.bits == 12,
             "the '>' code is not 0xffb/12: it is " + std::to_string(gt.code) + "/" +
                 std::to_string(gt.bits));
      const std::string gt_bytes = qpack_huffman_encode(">");
      expect(hex_of(gt_bytes) == "ffbf", "Huffman('>') is " + hex_of(gt_bytes) + ", expected ffbf");
      std::string gt_back;
      expect(h3_huffman_decode_bytes(reinterpret_cast<const u8*>(gt_bytes.data()), gt_bytes.size(),
                                     &gt_back, &err),
             "the reader refused Huffman('>'): " + err);
      expect(gt_back == ">", "Huffman('>') round trip gave \"" + gt_back + "\"");
      mark("RFC 7541 C.4 Huffman vectors (C.4.1/C.4.2/C.4.3): 4 strings byte for byte, each decoded "
           "back by the reader; '>' = 0xffb/12 -> ffbf");
    }

    // -----------------------------------------------------------------------
    // The table must also be a *prefix* code: no row's code may be a prefix of
    // another row's code, and the EOS row is the only 30-bit one that ends it.
    // The old wrong `'>'` row ({0xff, 8}) fails exactly this test, which is why
    // it corrupted every string containing '>' instead of failing loudly.
    // -----------------------------------------------------------------------
    {
      for (std::size_t a = 0; a < 257; ++a) {
        const H3HuffmanCode& x = h3_huffman_code(a);
        expect(x.bits != 0, "Huffman row " + std::to_string(a) + " is empty");
        for (std::size_t b = 0; b < 257; ++b) {
          if (a == b) continue;
          const H3HuffmanCode& y = h3_huffman_code(b);
          expect(y.bits != 0, "Huffman row " + std::to_string(b) + " is empty");
          if (y.bits <= x.bits) continue;
          // Codes are stored MSB-aligned inside their own bit length, so `x` is
          // a prefix of `y` when y's *high* x.bits bits are x -- comparing the
          // low bits would be a different (and wrong) test.
          expect((y.code >> (y.bits - x.bits)) != x.code,
                 "Huffman row " + std::to_string(a) + " is a prefix of row " + std::to_string(b));
        }
      }
      mark("Huffman table is a prefix code over all 257 rows (the check the wrong '>' row fails)");
    }

    // -----------------------------------------------------------------------
    // Static table accessors: the same 99 rows the reader uses, indexed the same
    // way, with the lowest-name rule the encoder relies on.
    // -----------------------------------------------------------------------
    {
      std::string name, value;
      expect(h3_static_entry(0, &name, &value) && name == ":authority" && value.empty(),
             "static entry 0 is not :authority with an empty value");
      expect(h3_static_entry(98, &name, &value) && name == "x-frame-options" &&
                 value == "sameorigin",
             "static entry 98 is not x-frame-options: sameorigin");
      expect(!h3_static_entry(kH3StaticTableSize, &name, &value),
             "static entry 99 must not exist");
      expect(name.empty() && value.empty(), "a failed static lookup must clear its outputs");
      std::size_t index = 0;
      expect(h3_static_exact_index(":method", "GET", &index) && index == 17,
             ":method GET is not static index 17");
      expect(h3_static_exact_index(":status", "200", &index) && index == 25,
             ":status 200 is not static index 25");
      expect(h3_static_name_index(":status", &index) && index == 24,
             "the lowest :status entry is not 24");
      expect(!h3_static_name_index("x-does-not-exist", &index), "a bogus name must not resolve");
      for (std::size_t i = 0; i < kH3StaticTableSize; ++i) {
        expect(h3_static_entry(i, &name, &value), "static entry " + std::to_string(i) + " missing");
        std::size_t by_name = 0;
        expect(h3_static_name_index(name, &by_name) && by_name <= i,
               "name lookup for entry " + std::to_string(i) + " did not find it (or found a later one)");
        std::size_t by_exact = 0;
        expect(h3_static_exact_index(name, value, &by_exact),
               "exact lookup for entry " + std::to_string(i) + " failed");
      }
      mark("static table shared with the reader: entry 0/98/99, :method GET = 17, :status 200 = 25, "
           "lowest-name rule, all 99 rows resolvable");
    }

    // -----------------------------------------------------------------------
    // Representation choice: each field takes the shortest static form, and the
    // bytes are what RFC 9204 section 4.5 says they are (including the
    // multi-byte static index and the 3-bit-prefix literal name).
    // -----------------------------------------------------------------------
    {
      struct Case {
        const char* name;
        const char* value;
        const char* hex;  // with the two prefix bytes, kNever (no Huffman)
      };
      const Case cases[] = {
          {":method", "GET", "0000d1"},                  // indexed, static 17
          {"content-length", "0", "0000c4"},             // indexed, static 4
          {"x-frame-options", "sameorigin", "0000ff23"},  // indexed, static 98 (2-byte index)
          {"content-length", "1234", "0000540431323334"}, // literal, name ref to static 4
          {"x-unknown", "v", "00002702782d756e6b6e6f776e0176"},  // literal name (3-bit prefix)
      };
      for (const Case& c : cases) {
        const std::vector<H3Field> fields = {{c.name, c.value}};
        const std::string got = round_trip(fields, QpackHuffman::kNever, c.name);
        expect(hex_of(got) == c.hex, std::string(c.name) + ": " + c.value + " encoded as " +
                                       hex_of(got) + ", expected " + c.hex);
      }
      // The same list with Huffman allowed: the reader must accept every form.
      for (const Case& c : cases) {
        round_trip({{c.name, c.value}}, QpackHuffman::kWhenShorter, std::string("huffman ") + c.name);
        round_trip({{c.name, c.value}}, QpackHuffman::kAlways, std::string("forced huffman ") + c.name);
      }
      mark("representation choice: indexed / name-reference / literal-name forms, 2-byte static "
           "index 98, 3-bit-prefix name length, all three policies round-trip");
    }

    // -----------------------------------------------------------------------
    // A whole field section, in order, including the cases that are awkward for
    // a rewriter: a response's `:status`, a `content-length` that must survive
    // as an ordinary field, an empty value, duplicate names, opaque non-UTF-8
    // bytes, and a value containing '>' (the byte http2.cpp's table corrupts).
    // -----------------------------------------------------------------------
    {
      std::vector<H3Field> fields = {
          {":status", "200"},
          {"content-type", "text/html; charset=utf-8"},
          {"content-length", "4096"},
          {"cache-control", "no-cache, no-store"},
          {"location", "https://www.example.com/a?b=1&c=>2"},
          {"x-frame-options", "sameorigin"},
          {"x-unknown-header", "some value with spaces"},
          {"x-empty", ""},
          {"x-binary", std::string("\x00\x01\x7f\xfe\xff", 5)},
          {"set-cookie", "a=b; Path=/; HttpOnly"},
          {"x-duplicate", "first"},
          {"x-duplicate", "second"},
      };
      round_trip(fields, QpackHuffman::kWhenShorter, "mixed response field section");
      round_trip(fields, QpackHuffman::kNever, "mixed response field section (no Huffman)");
      round_trip(fields, QpackHuffman::kAlways, "mixed response field section (forced Huffman)");
      mark("12-field section round-trips byte for byte in all three policies, in order, including "
           "content-length, an empty value, duplicates, 0x00/0xff bytes and '>'");
    }

    // -----------------------------------------------------------------------
    // Frame writers: RFC 9114 section 7.2 framing, the appending property, the
    // varint length rules, and the "out is cleared on failure" promise.
    // -----------------------------------------------------------------------
    {
      std::string out;
      err.clear();
      expect(h3_write_headers_frame(std::string("\x00\x00\xd1", 3), &out, &err),
             "HEADERS frame failed: " + err);
      expect(hex_of(out) == "01030000d1", "HEADERS frame bytes are " + hex_of(out));
      expect(h3_write_data_frame("hi", &out, &err), "DATA frame failed: " + err);
      expect(hex_of(out) == "01030000d100026869", "appending a DATA frame gave " + hex_of(out));

      const std::vector<H3Field> fields = {{":status", "200"}};
      std::string whole;
      expect(h3_encode_response(fields, "", &whole, &err), "empty-body response failed: " + err);
      // `:status 200` is static index 25, so the section is `0000d9`, the HEADERS
      // frame is `01 03 0000d9`, and an empty body adds no DATA frame at all.
      expect(hex_of(whole) == "01030000d9",
             "a body-less response should be exactly a HEADERS frame, got " + hex_of(whole));
      std::string stream;
      expect(h3_encode_response_stream(fields, "", &stream, &err), "stream response failed: " + err);
      expect(stream.size() == whole.size() + 1 && stream[0] == '\0',
             "the response stream must begin with the 0x00 stream-type varint");
      expect(stream.compare(1, std::string::npos, whole) == 0,
             "the response stream must be the type varint plus the payload");

      // Varints: the writer's encoding must be exactly what the project's own
      // reader accepts, for every length class.
      const u64 values[] = {0,        1,        63,        64,        16383,      16384,
                            1 << 20,  (1ull << 30) - 1, 1ull << 30, 1ull << 40, kVarintMax};
      for (u64 v : values) {
        std::string bytes;
        expect(put_varint(&bytes, v, &err), "put_varint(" + std::to_string(v) + ") failed: " + err);
        expect(bytes.size() == std::size_t(varint_length(v)),
               "varint(" + std::to_string(v) + ") has " + std::to_string(bytes.size()) +
                   " bytes, expected " + std::to_string(varint_length(v)));
        u64 back = 0;
        std::size_t used = 0;
        expect(quic_varint(reinterpret_cast<const u8*>(bytes.data()), bytes.size(), &back, &used),
               "quic_varint refused " + hex_of(bytes) + " for " + std::to_string(v));
        expect(back == v && used == bytes.size(),
               "varint round trip of " + std::to_string(v) + " gave " + std::to_string(back));
      }

      // A failure must leave *out empty, even when it was not empty before.
      std::string stale = "stale bytes";
      err.clear();
      expect(!h3_encode_response({}, "x", &stale, &err), "an empty field section must be refused");
      expect(stale.empty(), "a failed call must clear its output");
      std::string null_err;
      expect(!h3_write_data_frame("x", nullptr, &null_err), "a null output must be refused");
      expect(null_err.find("null output") != std::string::npos,
             "unexpected error for a null output: " + null_err);
      std::string index_err;
      std::string scratch;
      expect(!put_indexed(&scratch, kH3StaticTableSize, &index_err),
             "static index 99 must be refused");
      expect(index_err.find("past the end of the QPACK static table") != std::string::npos,
             "unexpected error for a static index past the table: " + index_err);
      expect(scratch.empty(), "a refused static index must not write anything");
      index_err.clear();
      expect(!put_literal_name_ref(&scratch, kH3StaticTableSize, "v", QpackHuffman::kNever,
                                  &index_err),
             "static index 99 as a name reference must be refused");
      mark("frames and varints: HEADERS/DATA framing byte-exact, appending, all four varint "
           "lengths accepted by quic_varint, a refused index writes nothing, failure clears out");
    }

    // -----------------------------------------------------------------------
    // The whole response, read back by the new response entry point of the
    // *existing* reader: status, header order, and body byte for byte.
    // -----------------------------------------------------------------------
    {
      const std::string body = "<html><body>hi</body></html>";
      std::vector<H3Field> fields = {
          {":status", "200"},
          {"content-type", "text/html; charset=utf-8"},
          {"content-length", std::to_string(body.size())},
          {"cache-control", "no-store"},
      };
      std::string stream;
      expect(h3_encode_response_stream(fields, body, &stream, &err),
             "response stream encode failed: " + err);
      H3Response got;
      expect(h3_response_from_stream(to_bytes(stream), &got, &err),
             "the reader refused the response stream: " + err);
      expect(got.status == "200", "status came back as \"" + got.status + "\"");
      expect(got.has_status && got.has_headers && !got.has_trailers, "response flags are wrong");
      expect(got.headers.size() == 3, "header count came back as " + std::to_string(got.headers.size()));
      expect(got.headers[0].first == "content-type" &&
                 got.headers[0].second == "text/html; charset=utf-8",
             "header 0 changed: " + got.headers[0].first + ": " + got.headers[0].second);
      expect(got.headers[1].first == "content-length" &&
                 got.headers[1].second == std::to_string(body.size()),
             "content-length did not survive as an ordinary field: " + got.headers[1].first + ": " +
                 got.headers[1].second);
      expect(got.headers[2].first == "cache-control" && got.headers[2].second == "no-store",
             "header 2 changed: " + got.headers[2].first + ": " + got.headers[2].second);
      expect(got.body == body, "the body came back as \"" + got.body + "\"");

      // Trailers: a second HEADERS frame after the DATA frame.
      std::string trailer_section;
      expect(qpack_encode_field_section({{"x-trailer", "1"}}, &trailer_section, &err),
             "trailer section failed: " + err);
      std::string with_trailers = stream;
      expect(h3_write_headers_frame(trailer_section, &with_trailers, &err),
             "trailer frame failed: " + err);
      H3Response trailed;
      expect(h3_response_from_stream(to_bytes(with_trailers), &trailed, &err),
             "the reader refused the trailed response: " + err);
      expect(trailed.has_trailers, "the second HEADERS frame was not reported as trailers");
      expect(trailed.body == body, "the trailed response lost its body");
      expect(trailed.headers.size() == 4 && trailed.headers[3].first == "x-trailer",
             "the trailer field is missing from the header list");

      // A trailer field section must not carry a pseudo-header.
      std::string status_section;
      expect(qpack_encode_field_section({{":status", "200"}}, &status_section, &err),
             "status section failed: " + err);
      std::string bad_trailer = stream;
      expect(h3_write_headers_frame(status_section, &bad_trailer, &err), "frame failed: " + err);
      H3Response scratch_out;
      err.clear();
      expect(!h3_response_from_stream(to_bytes(bad_trailer), &scratch_out, &err),
             "a trailer section carrying :status must be refused");
      expect(err.find("trailer field section") != std::string::npos,
             "unexpected error for a trailer with :status: " + err);

      // DATA before HEADERS, the same rule the request path enforces.
      std::string data_first;
      data_first.push_back('\0');
      expect(h3_write_data_frame("x", &data_first, &err), "DATA frame failed: " + err);
      err.clear();
      expect(!h3_response_from_stream(to_bytes(data_first), &scratch_out, &err),
             "DATA before HEADERS must be refused");
      expect(err == "h3: DATA frame arrives before the HEADERS frame (RFC 9114 section 4.1)",
             "unexpected error for DATA before HEADERS: " + err);

      // A response without :status is not a response.
      std::string no_status;
      std::string fs_only;
      expect(qpack_encode_field_section({{"content-type", "text/plain"}}, &fs_only, &err),
             "section failed: " + err);
      no_status.push_back('\0');
      expect(h3_write_headers_frame(fs_only, &no_status, &err), "frame failed: " + err);
      err.clear();
      expect(!h3_response_from_stream(to_bytes(no_status), &scratch_out, &err),
             "a response without :status must be refused");
      expect(err.find(":status") != std::string::npos,
             "unexpected error for a response without :status: " + err);

      // Server-initiated bidirectional streams carry no response.
      err.clear();
      expect(!h3_response_from_stream(to_bytes(stream), false, &scratch_out, &err),
             "a server-initiated stream must carry no response");
      mark("full response round trip through the existing reader: :status 200, 3 headers in order "
           "(content-length preserved), " + std::to_string(body.size()) +
           "-byte body, trailers, and the four refusal rules");
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

}  // namespace netcap
