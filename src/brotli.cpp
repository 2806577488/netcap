// Brotli (RFC 7932) decoder, written from the spec.
//
// Everything RFC 7932 defines is implemented here: simple and complex prefix
// codes (section 3), the four literal context modes and the context maps
// (section 7), block switching (section 6), the command loop with short
// distance codes and the last-distance ring buffer (sections 4, 5 and 10), and
// the static dictionary with its 121 transforms (section 8 and Appendix B).
// The dictionary bytes, the context lookup tables and the transform table live
// in the generated `src/brotli_dictionary.cpp`.
//
// The guiding rule is that a decode either produces exactly the bytes the
// encoder wrote or fails with a specific reason.  Every structural check the
// RFC states is enforced: code lengths must be complete, repeats and runs may
// not overrun their arrays, meta-block lengths may not be overrun, and a stream
// that stops in the middle of anything is refused.  Nothing here guesses.
#include "netcap/brotli.hpp"

#include "netcap/brotli_dictionary.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace netcap {
namespace {

constexpr std::size_t kMaxOutput = 32u * 1024u * 1024u;  // same as the inflate path

constexpr int kMaxCodeLength = 15;  // RFC 7932 section 3.2
constexpr unsigned kNumCodeLengthSymbols = 18;
constexpr unsigned kNumBlockCategories = 3;  // literals, insert-and-copy, distances
constexpr unsigned kNumBlockCountSymbols = 26;
constexpr std::uint32_t kAlphabetLiterals = 256;
constexpr std::uint32_t kAlphabetCommands = 704;
constexpr std::uint32_t kAlphabetBlockTypesMax = 256;
constexpr std::uint32_t kInitialBlockCount = 16777216u;  // section 10

// Section 3.5: the code length code lengths are stored in this order.
const unsigned kCodeLengthCodeOrder[kNumCodeLengthSymbols] = {
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15};

// Section 3.5: the fixed prefix code that carries the code length code lengths.
// The next four bits (LSB first) index these two tables.
const std::uint8_t kCodeLengthPrefixLength[16] = {
    2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4};
const std::uint8_t kCodeLengthPrefixValue[16] = {
    0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5};

// Section 4: the distance short codes as (ring buffer index, delta).
const std::uint8_t kDistanceShortCodeIndex[16] = {
    0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1};
const std::int8_t kDistanceShortCodeDelta[16] = {
    0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3};

// Section 5: insert and copy length codes as (base, extra bits).
const std::uint32_t kInsertBase[24] = {
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98,
    130, 194, 322, 578, 1090, 2114, 6210, 22594};
const std::uint8_t kInsertExtra[24] = {
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24};
const std::uint32_t kCopyBase[24] = {
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54,
    70, 102, 134, 198, 326, 582, 1094, 2118};
const std::uint8_t kCopyExtra[24] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24};
const std::uint8_t kInsertRangeLut[11] = {0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16};
const std::uint8_t kCopyRangeLut[11] = {0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16};

// Section 6: block count codes as (minimum count, extra bits).
const std::uint32_t kBlockCountBase[26] = {
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113,
    145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625};
const std::uint8_t kBlockCountExtra[26] = {
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
    5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24};

// Section 1.5.2: bits are packed into bytes least significant bit first, and
// multi-bit values are accumulated least significant bit first too.
class BitReader {
 public:
  BitReader(const u8* data, std::size_t len) : data_(data), len_(len) {}

  bool bad() const { return bad_; }
  std::size_t remaining() const { return (len_ - pos_) * 8 + count_; }
  // Number of bits consumed so far (always a multiple of 8 right after aligning).
  std::size_t bit_pos() const { return consumed(); }

  // The next `count` bits (count <= 32), zero padded past the end of the input.
  // `drop` reports the overrun, so a successful read never sees the padding.
  u32 peek(unsigned count) {
    if (count_ < count) fill();
    return static_cast<u32>(buffer_ & ((static_cast<u64>(1) << count) - 1));
  }

  void drop(unsigned count) {
    if (count_ < count) {
      fill();
      if (count_ < count) {
        bad_ = true;
        buffer_ = 0;
        count_ = 0;
        return;
      }
    }
    buffer_ >>= count;
    count_ -= count;
  }

  u32 bits(unsigned count) {
    const u32 value = peek(count);
    drop(count);
    return value;
  }

  void align_to_byte() {
    const unsigned used = static_cast<unsigned>(consumed() & 7u);
    if (used != 0) drop(8 - used);
  }

  // Reads the byte at the current (already aligned) position.
  bool byte(u8* out) {
    if (count_ < 8) fill();
    if (count_ < 8) {
      bad_ = true;
      return false;
    }
    *out = static_cast<u8>(buffer_ & 0xffu);
    buffer_ >>= 8;
    count_ -= 8;
    return true;
  }

 private:
  void fill() {
    while (count_ <= 56 && pos_ < len_) {
      buffer_ |= static_cast<u64>(data_[pos_++]) << count_;
      count_ += 8;
    }
  }
  std::size_t consumed() const { return len_ * 8 - remaining(); }

  const u8* data_;
  std::size_t len_;
  std::size_t pos_ = 0;
  u64 buffer_ = 0;
  unsigned count_ = 0;
  bool bad_ = false;
};

// RFC 7932 section 9.1.  WBITS is 10..24; values outside that are rejected.
bool read_window_bits(BitReader* br, int* window_bits, std::string* error) {
  if (br->bits(1) == 0) {
    *window_bits = 16;
    return true;
  }
  const u32 n = br->bits(3);
  if (n != 0) {
    *window_bits = 17 + static_cast<int>(n);
    return true;
  }
  const u32 m = br->bits(3);
  if (m == 1) {
    *error = "the stream asks for a large window, which this decoder does not offer";
    return false;
  }
  *window_bits = m != 0 ? 8 + static_cast<int>(m) : 17;
  return true;
}

// A canonical prefix code (RFC 7932 section 3.2).  Codes of equal length are
// assigned to symbols in ascending symbol order.
struct HuffmanCode {
  std::uint16_t counts[kMaxCodeLength + 1] = {};
  std::vector<std::int32_t> symbols;
  std::int32_t single = -1;  // >= 0 for a one-symbol code, which uses no bits
  int max_len = 0;

  int decode(BitReader* br) const {
    if (single >= 0) return single;
    int code = 0;
    int first = 0;
    int index = 0;
    for (int len = 1; len <= max_len; ++len) {
      code = (code << 1) | static_cast<int>(br->bits(1));
      const int count = counts[len];
      if (code - first < count) return symbols[static_cast<std::size_t>(index + code - first)];
      index += count;
      first = (first + count) << 1;
    }
    return -1;
  }
};

// Builds the canonical code from a table of code lengths.  `allow_single`
// permits the one-symbol form the RFC uses for the code length code; for every
// other alphabet a single non-zero length is an incomplete code and is refused.
bool build_huffman(const std::uint8_t* lengths, std::size_t n, bool allow_single,
                   HuffmanCode* out, std::string* error) {
  int counts[kMaxCodeLength + 1] = {0};
  std::size_t nonzero = 0;
  int last_nonzero = -1;
  for (std::size_t i = 0; i < n; ++i) {
    const unsigned len = lengths[i];
    if (len > static_cast<unsigned>(kMaxCodeLength)) {
      *error = "a prefix code asks for a code length above 15";
      return false;
    }
    if (len != 0) {
      ++counts[len];
      ++nonzero;
      last_nonzero = static_cast<int>(i);
    }
  }
  if (nonzero == 0) {
    *error = "a prefix code has no symbols";
    return false;
  }
  if (nonzero == 1) {
    if (!allow_single) {
      *error = "a prefix code has only one symbol with a non-zero code length";
      return false;
    }
    out->single = last_nonzero;
    for (int i = 0; i <= kMaxCodeLength; ++i) out->counts[i] = 0;
    out->symbols.clear();
    out->max_len = 0;
    return true;
  }
  int left = 1;
  for (int len = 1; len <= kMaxCodeLength; ++len) {
    left <<= 1;
    left -= counts[len];
    if (left < 0) {
      *error = "a prefix code is over-subscribed";
      return false;
    }
  }
  if (left != 0) {
    *error = "a prefix code is under-subscribed";
    return false;
  }
  out->single = -1;
  out->max_len = 0;
  for (int len = 1; len <= kMaxCodeLength; ++len) {
    out->counts[len] = static_cast<std::uint16_t>(counts[len]);
    if (counts[len] != 0) out->max_len = len;
  }
  out->counts[0] = 0;
  out->symbols.clear();
  out->symbols.reserve(nonzero);
  for (int len = 1; len <= kMaxCodeLength; ++len) {
    for (std::size_t i = 0; i < n; ++i) {
      if (lengths[i] == len) out->symbols.push_back(static_cast<std::int32_t>(i));
    }
  }
  return true;
}

// Section 7.1: the Context ID for the next literal.
u32 literal_context(std::uint32_t mode, u8 p1, u8 p2) {
  const u8* lut = brotli_context_lookup();
  switch (mode) {
    case 0:  // LSB6
      return p1 & 0x3fu;
    case 1:  // MSB6
      return p1 >> 2;
    case 2:  // UTF8
      return static_cast<u32>(lut[p1] | lut[256 + p2]);
    default:  // Signed
      return static_cast<u32>((lut[512 + p1] << 3) | lut[512 + p2]);
  }
}

// Section 8: Ferment, the transform that upper-cases a word, returns how many
// bytes it consumed.  Every index is checked against the word length.
int ferment(std::uint8_t* word, std::size_t word_len, std::size_t pos) {
  if (word[pos] < 192) {
    if (word[pos] >= 97 && word[pos] <= 122) word[pos] = static_cast<std::uint8_t>(word[pos] ^ 32);
    return 1;
  }
  if (word[pos] < 224) {
    if (pos + 1 < word_len) word[pos + 1] = static_cast<std::uint8_t>(word[pos + 1] ^ 32);
    return 2;
  }
  if (pos + 2 < word_len) word[pos + 2] = static_cast<std::uint8_t>(word[pos + 2] ^ 5);
  return 3;
}

// Section 8: prefix + T(word) + suffix.  A transformed word may be empty.
void apply_transform(const std::uint8_t* word, std::size_t word_len, std::size_t transform_id,
                     std::string* out) {
  const BrotliTransform& transform = brotli_transforms()[transform_id];
  out->append(transform.prefix, transform.prefix_len);
  std::uint8_t buffer[24];
  std::memcpy(buffer, word, word_len);
  const unsigned type = transform.type;
  if (type == 1) {  // FermentFirst
    if (word_len > 0) ferment(buffer, word_len, 0);
    out->append(reinterpret_cast<const char*>(buffer), word_len);
  } else if (type == 2) {  // FermentAll
    std::size_t i = 0;
    while (i < word_len) i += static_cast<std::size_t>(ferment(buffer, word_len, i));
    out->append(reinterpret_cast<const char*>(buffer), word_len);
  } else if (type >= 3 && type <= 11) {  // OmitFirst1..9
    const std::size_t omit = type - 2;
    if (word_len > omit) out->append(reinterpret_cast<const char*>(buffer + omit), word_len - omit);
  } else if (type >= 12) {  // OmitLast1..9
    const std::size_t omit = type - 11;
    if (word_len > omit) out->append(reinterpret_cast<const char*>(buffer), word_len - omit);
  } else {  // Identity
    out->append(reinterpret_cast<const char*>(buffer), word_len);
  }
  out->append(transform.suffix, transform.suffix_len);
}

// Section 6: one block category's switching state.
struct BlockState {
  std::uint32_t ntypes = 1;
  std::uint32_t type = 0;
  std::uint32_t prev_type = 1;
  std::uint32_t count = kInitialBlockCount;
  HuffmanCode type_code;
  HuffmanCode count_code;
};

// Everything a compressed meta-block header sets up.
struct MetaBlock {
  BlockState blocks[kNumBlockCategories];
  std::uint32_t npostfix = 0;
  std::uint32_t ndirect = 0;
  std::vector<std::uint8_t> context_modes;
  std::vector<std::uint8_t> cmap_l;
  std::vector<std::uint8_t> cmap_d;
  std::vector<HuffmanCode> literal_trees;
  std::vector<HuffmanCode> command_trees;
  std::vector<HuffmanCode> distance_trees;
};

class BrotliDecoder {
 public:
  BrotliDecoder(const u8* data, std::size_t len, std::string* out)
      : br_(data, len), out_(out) {}

  bool decode(std::string* error) {
    error_ = error;
    int window_bits = 0;
    if (!read_window_bits(&br_, &window_bits, error_)) return false;
    window_size_ = (1u << window_bits) - 16u;

    for (;;) {
      const std::uint32_t is_last = br_.bits(1);
      if (br_.bad()) return fail("the stream ends inside a meta-block header");
      if (is_last != 0) {
        if (br_.bits(1) != 0) break;  // ISLASTEMPTY: the stream is done
      }

      const std::uint32_t nibble_code = br_.bits(2);
      if (br_.bad()) return fail("the stream ends inside a meta-block header");
      if (nibble_code == 3) {
        // Section 9.2: the header form used for metadata and empty meta-blocks.
        if (!read_metadata_length_and_skip()) return false;
        if (is_last != 0) break;
        continue;
      }

      const unsigned nibbles = 4 + nibble_code;
      std::uint32_t mlen = 0;
      for (unsigned i = 0; i < nibbles; ++i) mlen |= br_.bits(4) << (4 * i);
      if (br_.bad()) return fail("the stream ends inside a meta-block length");
      if (nibbles > 4 && (mlen >> (4 * (nibbles - 1))) == 0) {
        return fail("a meta-block length is stored with a redundant leading nibble");
      }
      mlen += 1;

      // Section 9.2: ISUNCOMPRESSED is present only when ISLAST is not set, and
      // it is the last header field before the compressed header; there is no
      // separate ISMETADATA bit (metadata blocks use the MNIBBLES == 0 form).
      if (is_last == 0 && br_.bits(1) != 0) {  // ISUNCOMPRESSED
        if (!align_fill("an uncompressed meta-block")) return false;
        if (!copy_uncompressed(mlen)) return false;
        continue;
      }

      if (!decode_compressed_meta_block(mlen)) return false;
      if (is_last != 0) break;
    }

    if (br_.bad()) return fail("the stream ends before its last meta-block is complete");

    // Section 9.3: the last command of the last non-empty meta-block may end in the
    // middle of a byte, and then the unused bits of that last byte must be zeros --
    // nothing else may follow the stream.
    const std::size_t leftover = br_.remaining();
    if (leftover >= 8) return fail("the stream continues past its last meta-block");
    if (leftover != 0 && br_.peek(static_cast<unsigned>(leftover)) != 0) {
      return fail("the unused bits after the last meta-block are not zero");
    }
    return true;
  }

 private:
  bool fail(const std::string& why) {
    if (error_ != nullptr && error_->empty()) *error_ = why;
    return false;
  }

  // Section 9.2.  The length bytes follow the 2-bit count immediately, with no
  // byte alignment; only then are the fill bits dropped and the payload skipped.
  bool read_metadata_length_and_skip() {
    if (br_.bits(1) != 0) return fail("a metadata meta-block sets its reserved bit");
    const std::uint32_t length_bytes = br_.bits(2);
    if (br_.bad()) return fail("the stream ends inside a metadata meta-block header");
    std::size_t length = 0;
    if (length_bytes != 0) {
      for (std::uint32_t i = 0; i < length_bytes; ++i) {
        length |= static_cast<std::size_t>(br_.bits(8)) << (8 * i);
      }
      if (br_.bad()) return fail("the stream ends inside a metadata length");
      if (length_bytes > 1 && (length >> (8 * (length_bytes - 1))) == 0) {
        return fail("a metadata length is stored with a redundant leading byte");
      }
      length += 1;
    }
    // RFC 7932 section 9.2 (lines 1781 and 1786): MSKIPLEN is 0 when MSKIPBYTES is
    // zero, but the zero fill bits up to the next byte boundary are always there.
    if (!align_fill("a metadata meta-block")) return false;
    return skip_payload(length, "a metadata meta-block");
  }

  // Section 9.2.  Drops the bits up to the next byte boundary, which the format
  // requires to be zeros: the fill bits of a metadata meta-block (line 1786) and
  // the compressed bits ignored before uncompressed data (lines 1804-1809).
  bool align_fill(const char* what) {
    const unsigned used = static_cast<unsigned>(br_.bit_pos() & 7u);
    if (used != 0) {
      const unsigned fill = 8 - used;
      if (br_.peek(fill) != 0) {
        return fail(std::string("the fill bits before ") + what + " are not zero");
      }
      br_.drop(fill);
      if (br_.bad()) {
        return fail(std::string("the stream ends inside the fill bits before ") + what);
      }
    }
    return true;
  }

  bool copy_uncompressed(std::uint32_t mlen) {
    if (out_->size() + mlen > kMaxOutput) {
      return fail("the decoded body would be larger than " + std::to_string(kMaxOutput) + " bytes");
    }
    out_->reserve(out_->size() + mlen);
    for (std::uint32_t i = 0; i < mlen; ++i) {
      u8 b = 0;
      if (!br_.byte(&b)) return fail("the stream ends inside an uncompressed meta-block");
      out_->push_back(static_cast<char>(b));
    }
    return true;
  }

  bool skip_payload(std::size_t count, const char* what) {
    for (std::size_t i = 0; i < count; ++i) {
      u8 b = 0;
      if (!br_.byte(&b)) return fail(std::string("the stream ends inside ") + what);
    }
    return true;
  }

  // Section 9.2: the variable-length code used for NBLTYPES and NTREES.
  std::uint32_t decode_var_len_u8() {
    if (br_.bits(1) == 0) return 1;
    const std::uint32_t n = br_.bits(3);
    if (n == 0) return 2;
    return (1u << n) + 1u + br_.bits(n);
  }

  // Section 3.4 (simple) and section 3.5 (complex).
  bool read_prefix_code(std::uint32_t alphabet_size, const char* what, HuffmanCode* out) {
    const std::uint32_t hskip = br_.bits(2);
    if (br_.bad()) return fail(std::string("the stream ends at the start of ") + what);
    if (hskip == 1) return read_simple_prefix_code(alphabet_size, what, out);
    return read_complex_prefix_code(alphabet_size, hskip, what, out);
  }

  bool read_simple_prefix_code(std::uint32_t alphabet_size, const char* what, HuffmanCode* out) {
    const std::uint32_t nsym = br_.bits(2) + 1;
    std::uint32_t alphabet_bits = 0;
    while ((1u << alphabet_bits) < alphabet_size) ++alphabet_bits;
    std::uint32_t symbol[4] = {0, 0, 0, 0};
    for (std::uint32_t i = 0; i < nsym; ++i) {
      symbol[i] = br_.bits(alphabet_bits);
      if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
      if (symbol[i] >= alphabet_size) {
        return fail(std::string("a simple prefix code names a symbol outside the alphabet of ") + what);
      }
      for (std::uint32_t j = 0; j < i; ++j) {
        if (symbol[j] == symbol[i]) {
          return fail(std::string("a simple prefix code repeats a symbol in ") + what);
        }
      }
    }
    std::uint32_t tree_select = 0;
    if (nsym == 4) {
      tree_select = br_.bits(1);
      if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
    }
    if (nsym == 1) {
      out->single = static_cast<std::int32_t>(symbol[0]);
      for (int i = 0; i <= kMaxCodeLength; ++i) out->counts[i] = 0;
      out->symbols.clear();
      out->max_len = 0;
      return true;
    }
    static const std::uint8_t kLen2[2] = {1, 1};
    static const std::uint8_t kLen3[3] = {1, 2, 2};
    static const std::uint8_t kLen4Even[4] = {2, 2, 2, 2};
    static const std::uint8_t kLen4Skewed[4] = {1, 2, 3, 3};
    const std::uint8_t* lengths_for_symbol =
        nsym == 2 ? kLen2 : (nsym == 3 ? kLen3 : (tree_select != 0 ? kLen4Skewed : kLen4Even));
    std::vector<std::uint8_t> lengths(alphabet_size, 0);
    for (std::uint32_t i = 0; i < nsym; ++i) lengths[symbol[i]] = lengths_for_symbol[i];
    return build_huffman(lengths.data(), lengths.size(), false, out, error_);
  }

  bool read_complex_prefix_code(std::uint32_t alphabet_size, std::uint32_t hskip, const char* what,
                                HuffmanCode* out) {
    std::uint8_t clcl[kNumCodeLengthSymbols] = {};
    int space = 32;
    unsigned nonzero = 0;
    for (std::uint32_t i = hskip; i < kNumCodeLengthSymbols; ++i) {
      const std::uint32_t bits = br_.peek(4);
      clcl[kCodeLengthCodeOrder[i]] = kCodeLengthPrefixValue[bits];
      br_.drop(kCodeLengthPrefixLength[bits]);
      if (br_.bad()) return fail(std::string("the stream ends inside the code length code of ") + what);
      const unsigned value = kCodeLengthPrefixValue[bits];
      if (value != 0) {
        space -= 32 >> value;
        ++nonzero;
        if (space <= 0) break;
      }
    }
    if (nonzero == 0) return fail(std::string("the code length code of ") + what + " is empty");
    HuffmanCode cl_tree;
    if (!build_huffman(clcl, kNumCodeLengthSymbols, true, &cl_tree, error_)) {
      *error_ = std::string("the code length code of ") + what + ": " + *error_;
      return false;
    }

    std::vector<std::uint8_t> lengths(alphabet_size, 0);
    std::uint32_t symbol = 0;
    int prev_code_len = 8;   // section 3.5: the first repeat uses 8
    std::uint32_t repeat = 0;
    int repeat_len = -1;
    int remaining_space = 32768;
    while (symbol < alphabet_size && remaining_space > 0) {
      const int code_len = cl_tree.decode(&br_);
      if (br_.bad()) return fail(std::string("the stream ends inside the code lengths of ") + what);
      if (code_len < 0 || code_len > 17) {
        return fail(std::string("a code length symbol is out of range in ") + what);
      }
      if (code_len < 16) {
        lengths[symbol++] = static_cast<std::uint8_t>(code_len);
        if (code_len != 0) {
          prev_code_len = code_len;
          remaining_space -= 32768 >> code_len;
        }
        repeat = 0;
        repeat_len = -1;
        continue;
      }
      const int repeated_length = code_len == 16 ? prev_code_len : 0;
      const unsigned extra_bits = code_len == 16 ? 2 : 3;
      const std::uint32_t delta = 3 + br_.bits(extra_bits);
      if (br_.bad()) return fail(std::string("the stream ends inside the code length repeats of ") + what);
      std::uint32_t written = 0;
      std::uint32_t count = delta;
      if (repeat_len == repeated_length) {
        // Section 3.5: a repeat symbol that follows the same repeat symbol
        // rewrites the previous count instead of adding to it.
        count = (code_len == 16 ? 4u : 8u) * (repeat - 2u) + delta;
        written = repeat;
      }
      if (symbol + (count - written) > alphabet_size) {
        return fail(std::string("a code length repeat runs past the end of ") + what);
      }
      for (std::uint32_t i = written; i < count; ++i) {
        lengths[symbol++] = static_cast<std::uint8_t>(repeated_length);
      }
      if (repeated_length != 0) {
        remaining_space -= static_cast<int>(count - written) * (32768 >> repeated_length);
      }
      repeat = count;
      repeat_len = repeated_length;
    }
    if (remaining_space != 0) {
      return fail(std::string("the code lengths of ") + what + " do not add up to a complete code");
    }
    return build_huffman(lengths.data(), lengths.size(), false, out, error_);
  }

  // Section 7.3.
  bool read_context_map(std::uint32_t size, std::uint32_t ntrees, std::vector<std::uint8_t>* map,
                        const char* what) {
    std::uint32_t rlemax = 0;
    if (br_.bits(1) != 0) rlemax = 1 + br_.bits(4);
    if (br_.bad()) return fail(std::string("the stream ends inside the header of ") + what);
    HuffmanCode table;
    if (!read_prefix_code(ntrees + rlemax, what, &table)) return false;
    map->assign(size, 0);
    std::uint32_t i = 0;
    while (i < size) {
      const int symbol = table.decode(&br_);
      if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
      if (symbol < 0) return fail(std::string("a symbol is out of range in ") + what);
      if (symbol == 0) {
        ++i;
      } else if (static_cast<std::uint32_t>(symbol) <= rlemax) {
        const std::uint32_t run = (1u << symbol) + br_.bits(static_cast<unsigned>(symbol));
        if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
        if (i + run > size) {
          return fail(std::string("a zero run runs past the end of ") + what);
        }
        i += run;
      } else {
        (*map)[i++] = static_cast<std::uint8_t>(symbol - static_cast<int>(rlemax));
      }
    }
    if (br_.bits(1) != 0) {  // inverse move-to-front
      u8 mtf[256];
      for (unsigned j = 0; j < 256; ++j) mtf[j] = static_cast<u8>(j);
      for (std::uint32_t k = 0; k < size; ++k) {
        const u8 index = (*map)[k];
        const u8 value = mtf[index];
        (*map)[k] = value;
        for (u8 m = index; m != 0; --m) mtf[m] = mtf[m - 1u];
        mtf[0] = value;
      }
    }
    if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
    for (std::uint32_t k = 0; k < size; ++k) {
      if ((*map)[k] >= ntrees) {
        return fail(std::string("a context map names a prefix code that does not exist in ") + what);
      }
    }
    return true;
  }

  // Section 6: consumes one block of a category, switching when the count runs
  // out.  A category with a single block type never switches.
  bool take_block(BlockState* block, const char* what) {
    if (block->ntypes < 2) return true;
    if (block->count == 0) {
      const int symbol = block->type_code.decode(&br_);
      if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
      if (symbol < 0 || symbol > static_cast<int>(block->ntypes) + 1) {
        return fail(std::string("a block type symbol is out of range in ") + what);
      }
      std::uint32_t next = 0;
      if (symbol == 0) {
        next = block->prev_type;
      } else if (symbol == 1) {
        next = (block->type + 1u) % block->ntypes;
      } else {
        next = static_cast<std::uint32_t>(symbol) - 2u;
      }
      const int count_symbol = block->count_code.decode(&br_);
      if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
      if (count_symbol < 0 || count_symbol >= static_cast<int>(kNumBlockCountSymbols)) {
        return fail(std::string("a block count symbol is out of range in ") + what);
      }
      block->prev_type = block->type;
      block->type = next;
      block->count = kBlockCountBase[count_symbol] + br_.bits(kBlockCountExtra[count_symbol]);
      if (br_.bad()) return fail(std::string("the stream ends inside ") + what);
    }
    --block->count;
    return true;
  }

  // Section 9.2: the header of a compressed meta-block.
  bool read_meta_block_header(MetaBlock* mb) {
    for (unsigned category = 0; category < kNumBlockCategories; ++category) {
      BlockState& block = mb->blocks[category];
      block.ntypes = decode_var_len_u8();
      if (br_.bad()) return fail("the stream ends inside the number of block types");
      if (block.ntypes > kAlphabetBlockTypesMax) {
        return fail("the stream asks for more block types than the format allows");
      }
      block.type = 0;
      block.prev_type = 1;
      block.count = kInitialBlockCount;
      if (block.ntypes >= 2) {
        if (!read_prefix_code(block.ntypes + 2, "the block type code", &block.type_code)) {
          return false;
        }
        if (!read_prefix_code(kNumBlockCountSymbols, "the block count code", &block.count_code)) {
          return false;
        }
        const int symbol = block.count_code.decode(&br_);
        if (br_.bad()) return fail("the stream ends inside the first block count");
        if (symbol < 0 || symbol >= static_cast<int>(kNumBlockCountSymbols)) {
          return fail("the first block count symbol is out of range");
        }
        block.count = kBlockCountBase[symbol] + br_.bits(kBlockCountExtra[symbol]);
        if (br_.bad()) return fail("the stream ends inside the first block count");
      }
    }

    mb->npostfix = br_.bits(2);
    mb->ndirect = br_.bits(4) << mb->npostfix;
    if (br_.bad()) return fail("the stream ends inside the distance parameters");

    mb->context_modes.resize(mb->blocks[0].ntypes);
    for (std::uint32_t i = 0; i < mb->blocks[0].ntypes; ++i) {
      mb->context_modes[i] = static_cast<std::uint8_t>(br_.bits(2));
    }
    if (br_.bad()) return fail("the stream ends inside the literal context modes");

    const std::uint32_t ntrees_l = decode_var_len_u8();
    if (br_.bad()) return fail("the stream ends inside the number of literal prefix codes");
    mb->cmap_l.assign(64u * mb->blocks[0].ntypes, 0);
    if (ntrees_l >= 2 &&
        !read_context_map(64u * mb->blocks[0].ntypes, ntrees_l, &mb->cmap_l,
                          "the literal context map")) {
      return false;
    }
    const std::uint32_t ntrees_d = decode_var_len_u8();
    if (br_.bad()) return fail("the stream ends inside the number of distance prefix codes");
    mb->cmap_d.assign(4u * mb->blocks[2].ntypes, 0);
    if (ntrees_d >= 2 &&
        !read_context_map(4u * mb->blocks[2].ntypes, ntrees_d, &mb->cmap_d,
                          "the distance context map")) {
      return false;
    }

    mb->literal_trees.resize(ntrees_l);
    for (std::uint32_t i = 0; i < ntrees_l; ++i) {
      if (!read_prefix_code(kAlphabetLiterals, "a literal prefix code", &mb->literal_trees[i])) {
        return false;
      }
    }
    mb->command_trees.resize(mb->blocks[1].ntypes);
    for (std::uint32_t i = 0; i < mb->blocks[1].ntypes; ++i) {
      if (!read_prefix_code(kAlphabetCommands, "an insert-and-copy prefix code",
                            &mb->command_trees[i])) {
        return false;
      }
    }
    const std::uint32_t distance_alphabet = 16u + mb->ndirect + (48u << mb->npostfix);
    mb->distance_trees.resize(ntrees_d);
    for (std::uint32_t i = 0; i < ntrees_d; ++i) {
      if (!read_prefix_code(distance_alphabet, "a distance prefix code", &mb->distance_trees[i])) {
        return false;
      }
    }
    return true;
  }

  // Sections 4, 5 and 10: the command loop of a compressed meta-block.
  bool decode_compressed_meta_block(std::uint32_t mlen) {
    MetaBlock mb;
    if (!read_meta_block_header(&mb)) return false;
    if (out_->size() + mlen > kMaxOutput) {
      return fail("the decoded body would be larger than " + std::to_string(kMaxOutput) + " bytes");
    }
    out_->reserve(out_->size() + mlen);

    std::uint32_t produced = 0;
    while (produced < mlen) {
      if (!take_block(&mb.blocks[1], "the insert-and-copy block count")) return false;
      const int command = mb.command_trees[mb.blocks[1].type].decode(&br_);
      if (br_.bad()) return fail("the stream ends inside the command loop");
      if (command < 0) return fail("a command symbol is out of range");
      const std::uint32_t cell = static_cast<std::uint32_t>(command) >> 6;
      const std::uint32_t insert_code =
          kInsertRangeLut[cell] + ((static_cast<std::uint32_t>(command) >> 3) & 7u);
      const std::uint32_t copy_code =
          kCopyRangeLut[cell] + (static_cast<std::uint32_t>(command) & 7u);
      const std::uint32_t ilen = kInsertBase[insert_code] + br_.bits(kInsertExtra[insert_code]);
      const std::uint32_t clen = kCopyBase[copy_code] + br_.bits(kCopyExtra[copy_code]);
      if (br_.bad()) return fail("the stream ends inside a command");
      if (static_cast<std::uint64_t>(produced) + ilen > mlen) {
        return fail("a command inserts more literals than its meta-block holds");
      }

      for (std::uint32_t i = 0; i < ilen; ++i) {
        if (!take_block(&mb.blocks[0], "the literal block count")) return false;
        const std::uint32_t btype = mb.blocks[0].type;
        const std::size_t end = out_->size();
        const u8 p1 = end > 0 ? static_cast<u8>((*out_)[end - 1]) : 0;
        const u8 p2 = end > 1 ? static_cast<u8>((*out_)[end - 2]) : 0;
        const u32 context = literal_context(mb.context_modes[btype], p1, p2);
        const u8 tree = mb.cmap_l[64u * btype + context];
        const int literal = mb.literal_trees[tree].decode(&br_);
        if (br_.bad()) return fail("the stream ends inside a literal");
        if (literal < 0) return fail("a literal symbol is out of range");
        out_->push_back(static_cast<char>(literal));
      }
      produced += ilen;
      if (produced == mlen) break;  // the final command's copy length is ignored

      // Section 4: where the copy comes from.
      std::uint32_t dcode = 0;
      std::int64_t distance = 0;
      if (cell < 2) {
        distance = dist_rb_[0];  // implicit distance: the last one, no bits in the stream
      } else {
        if (!take_block(&mb.blocks[2], "the distance block count")) return false;
        const std::uint32_t dctx = clen > 4 ? 3u : clen - 2u;
        const u8 tree = mb.cmap_d[4u * mb.blocks[2].type + dctx];
        const int symbol = mb.distance_trees[tree].decode(&br_);
        if (br_.bad()) return fail("the stream ends inside a distance");
        if (symbol < 0) return fail("a distance symbol is out of range");
        dcode = static_cast<std::uint32_t>(symbol);
        if (dcode < 16) {
          distance = static_cast<std::int64_t>(dist_rb_[kDistanceShortCodeIndex[dcode]]) +
                     kDistanceShortCodeDelta[dcode];
          if (distance <= 0) {
            return fail("a distance short code refers to a distance that is not positive");
          }
        } else if (dcode < 16u + mb.ndirect) {
          distance = static_cast<std::int64_t>(dcode) - 15;
        } else {
          const std::uint32_t ndistbits = 1 + ((dcode - mb.ndirect - 16) >> (mb.npostfix + 1));
          const std::uint32_t hcode = (dcode - mb.ndirect - 16) >> mb.npostfix;
          const std::uint32_t lcode = (dcode - mb.ndirect - 16) & ((1u << mb.npostfix) - 1u);
          const std::uint32_t offset = ((2u + (hcode & 1u)) << ndistbits) - 4u;
          const std::uint32_t extra = br_.bits(ndistbits);
          if (br_.bad()) return fail("the stream ends inside a distance");
          distance = static_cast<std::int64_t>(((offset + extra) << mb.npostfix) + lcode +
                                               mb.ndirect + 1);
        }
      }

      const std::uint32_t pos = static_cast<std::uint32_t>(out_->size());
      const std::uint32_t max_distance = pos < window_size_ ? pos : window_size_;
      const bool is_dictionary = distance > static_cast<std::int64_t>(max_distance);
      if (dcode != 0 && !is_dictionary) {
        dist_rb_[3] = dist_rb_[2];
        dist_rb_[2] = dist_rb_[1];
        dist_rb_[1] = dist_rb_[0];
        dist_rb_[0] = static_cast<std::uint32_t>(distance);
      }

      if (!is_dictionary) {
        if (distance <= 0) return fail("a copy uses a distance that is not positive");
        if (static_cast<std::uint64_t>(produced) + clen > mlen) {
          return fail("a backward copy runs past the end of its meta-block");
        }
        const std::size_t back = static_cast<std::size_t>(distance);
        for (std::uint32_t i = 0; i < clen; ++i) {
          out_->push_back((*out_)[out_->size() - back]);  // overlapping copies repeat bytes
        }
        produced += clen;
      } else {
        if (clen < 4 || clen > 24) {
          return fail("a static dictionary reference uses a copy length outside 4..24");
        }
        const unsigned word_bits = brotli_dictionary_size_bits()[clen];
        const std::uint32_t word_id = static_cast<std::uint32_t>(distance) - max_distance - 1u;
        const std::uint32_t index = word_id & ((1u << word_bits) - 1u);
        const std::uint32_t transform_id = word_id >> word_bits;
        if (transform_id >= brotli_transform_count()) {
          return fail("a static dictionary reference names a transform that does not exist");
        }
        const std::size_t offset =
            brotli_dictionary_offsets()[clen] + static_cast<std::size_t>(index) * clen;
        const std::size_t before = out_->size();
        apply_transform(brotli_dictionary_data() + offset, clen, transform_id, out_);
        const std::size_t added = out_->size() - before;
        if (static_cast<std::uint64_t>(produced) + added > mlen) {
          return fail("a static dictionary word runs past the end of its meta-block");
        }
        produced += static_cast<std::uint32_t>(added);
      }
    }
    return true;
  }

  BitReader br_;
  std::string* out_;
  std::string* error_ = nullptr;
  std::uint32_t window_size_ = 0;
  // Section 4: the four most recent distances, initialised once per stream.
  std::uint32_t dist_rb_[4] = {4, 11, 15, 16};
};

}  // namespace

std::size_t brotli_max_output() { return kMaxOutput; }

bool brotli_decompress(const u8* data, std::size_t len, std::string* out, std::string* error) {
  std::string local_error;
  if (error == nullptr) error = &local_error;
  error->clear();
  if (out == nullptr) {
    *error = "no destination for the decoded body";
    return false;
  }
  out->clear();
  if (data == nullptr || len == 0) {
    *error = "an empty stream is not a body";
    return false;
  }

  BrotliDecoder decoder(data, len, out);
  return decoder.decode(error);
}

bool brotli_decompress(const std::string& in, std::string* out, std::string* error) {
  return brotli_decompress(reinterpret_cast<const u8*>(in.data()), in.size(), out, error);
}

namespace {

// A least-significant-bit-first bit writer, so `brotli_selfcheck` can spell out
// the streams it expects the decoder to accept or refuse.
class BitWriter {
 public:
  void put(std::uint32_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
      if (bit_ == 0) bytes_.push_back(0);
      if (((value >> i) & 1u) != 0) bytes_.back() |= static_cast<u8>(1u << bit_);
      bit_ = (bit_ + 1u) & 7u;
    }
  }
  void align() {
    while (bit_ != 0) put(0, 1);
  }
  // The index of the next bit inside the current byte, so the builders below can
  // spell out fill bits.
  unsigned bit() const { return bit_; }
  const std::vector<u8>& bytes() const { return bytes_; }

 private:
  std::vector<u8> bytes_;
  unsigned bit_ = 0;
};

// The window bits of a hand-built stream: a single zero bit, which is window 16.
void put_window_bits(BitWriter* w) { w->put(0, 1); }

// The shared head of the hand-built compressed meta-blocks below: a 6- or 8-byte
// meta-block, one block type and one prefix code in every category, no postfix
// and no direct distances, LSB6 literal contexts.  In a last meta-block
// ISLASTEMPTY follows ISLAST and the ISUNCOMPRESSED field is absent, because
// section 9.2 only has it when ISLAST is not set.  Only the caller knows whether
// this meta-block is the first one, so the window bits are written separately.
void put_compressed_head(BitWriter* w, std::uint32_t mlen, bool is_last = false) {
  w->put(is_last ? 1u : 0u, 1);  // ISLAST
  if (is_last) w->put(0, 1);     // ISLASTEMPTY = 0
  w->put(0, 2);                  // MNIBBLES = 4
  const std::uint32_t mlen_minus_one = mlen - 1;
  for (unsigned i = 0; i < 4; ++i) w->put((mlen_minus_one >> (4 * i)) & 0xfu, 4);
  if (!is_last) w->put(0, 1);  // ISUNCOMPRESSED = 0 (there is no separate ISMETADATA bit)
  w->put(0, 1);  // NBLTYPESL = 1
  w->put(0, 1);  // NBLTYPESI = 1
  w->put(0, 1);  // NBLTYPESD = 1
  w->put(0, 2);  // NPOSTFIX = 0
  w->put(0, 4);  // NDIRECT = 0
  w->put(0, 2);  // literal context mode 0 (LSB6)
  w->put(0, 1);  // NTREESL = 1 (the context map is then the identity)
  w->put(0, 1);  // NTREESD = 1
}

void put_simple_code(BitWriter* w, std::uint32_t alphabet_size, const std::uint32_t* symbols,
                     std::uint32_t nsym, std::uint32_t tree_select) {
  std::uint32_t alphabet_bits = 0;
  while ((1u << alphabet_bits) < alphabet_size) ++alphabet_bits;
  w->put(1, 2);  // simple prefix code
  w->put(nsym - 1, 2);
  for (std::uint32_t i = 0; i < nsym; ++i) w->put(symbols[i], alphabet_bits);
  if (nsym == 4) w->put(tree_select, 1);
}

void put_final_empty_meta_block(BitWriter* w) {
  w->put(1, 1);  // ISLAST
  w->put(1, 1);  // ISLASTEMPTY
}

// A stream that inserts one literal and then copies five bytes from distance 1,
// which is only expressible because the copy overlaps itself.
std::vector<u8> build_stream_lz77(std::uint32_t command_symbol) {
  BitWriter w;
  put_window_bits(&w);
  put_compressed_head(&w, 6);
  const std::uint32_t literal = 'A';
  put_simple_code(&w, kAlphabetLiterals, &literal, 1, 0);
  put_simple_code(&w, kAlphabetCommands, &command_symbol, 1, 0);
  const std::uint32_t distance_code = 16;  // a two-bit direct code: 1 + extra
  put_simple_code(&w, 64, &distance_code, 1, 0);
  // Command 139: insert code 1 (one literal), copy code 3 (five bytes), explicit
  // distance.  No insert, copy or distance extra bits are needed.
  w.put(0, 1);  // the single distance extra bit: distance 1
  put_final_empty_meta_block(&w);
  return w.bytes();
}

// The same shape, but with a literal prefix code that names the same symbol
// twice, which section 3.4 forbids.
std::vector<u8> build_stream_duplicate_literal() {
  BitWriter w;
  put_window_bits(&w);
  put_compressed_head(&w, 6);
  const std::uint32_t literals[2] = {'A', 'A'};
  put_simple_code(&w, kAlphabetLiterals, literals, 2, 0);
  const std::uint32_t command = 139;
  put_simple_code(&w, kAlphabetCommands, &command, 1, 0);
  const std::uint32_t distance_code = 16;
  put_simple_code(&w, 64, &distance_code, 1, 0);
  w.put(0, 1);
  put_final_empty_meta_block(&w);
  return w.bytes();
}

// A stream that reaches the static dictionary through a complex prefix code.
//   Command 148: insert code 2 (two literals), copy code 4 (six bytes).
//   The distance prefix code gives length 1 to codes 0 and 17.  Code 17 with
//   its single extra bit set is the distance 4; only two bytes have been decoded
//   so the maximum distance is 2, and 4 is past it: a dictionary reference with
//   word_id = 4 - 2 - 1 = 1, of length 6, transform 0 (identity).
//   Word 1 of length 6 is "domain" (dictionary offset 9216 + 1 * 6).
std::vector<u8> build_stream_dictionary() {
  BitWriter w;
  put_window_bits(&w);
  put_compressed_head(&w, 8);
  const std::uint32_t literals[2] = {'A', 'B'};
  put_simple_code(&w, kAlphabetLiterals, literals, 2, 0);
  const std::uint32_t command = 148;
  put_simple_code(&w, kAlphabetCommands, &command, 1, 0);

  // The complex form.  HSKIP is zero, so all 18 code length code lengths are
  // written, in the order of section 3.5.  Only the symbols 0 and 1 appear and
  // each gets length 1, which exactly fills the space, so the code is complete
  // after the fifth value and the decoder stops reading there.
  w.put(0, 2);  // HSKIP = 0
  w.put(7, 4);  // order[0] is symbol 1 -> length 1 (16 of 32 left)
  w.put(0, 2);  // order[1] is symbol 2 -> 0
  w.put(0, 2);  // order[2] is symbol 3 -> 0
  w.put(0, 2);  // order[3] is symbol 4 -> 0
  w.put(7, 4);  // order[4] is symbol 0 -> length 1 (space filled, stop)
  // The distance code lengths, one bit each: code 0 gets length 1, codes 1..16
  // get length 0, and code 17 gets length 1.  Those two ones fill the space
  // exactly, so the decoder stops after code 17.
  w.put(1, 1);                                    // distance code 0  -> 1
  for (unsigned i = 1; i < 17; ++i) w.put(0, 1);  // codes 1..16       -> 0
  w.put(1, 1);                                    // distance code 17 -> 1

  // The data.  Canonical codes assign code 0 to the first symbol of a code and
  // code 1 to the second, in both two-symbol codes above.
  w.put(0, 1);  // literal 'A'
  w.put(1, 1);  // literal 'B'
  w.put(1, 1);  // distance code 17
  w.put(1, 1);  // its single extra bit, which makes the distance 4
  put_final_empty_meta_block(&w);
  return w.bytes();
}

// One compressed meta-block that inserts 'A' and copies five bytes from distance
// 1: the body of build_stream_lz77 below, with the terminator and the window bits
// left to the caller.
void put_lz77_meta_block(BitWriter* w, std::uint32_t command_symbol, bool is_last = false) {
  put_compressed_head(w, 6, is_last);
  const std::uint32_t literal = 'A';
  put_simple_code(w, kAlphabetLiterals, &literal, 1, 0);
  put_simple_code(w, kAlphabetCommands, &command_symbol, 1, 0);
  const std::uint32_t distance_code = 16;  // a two-bit direct code: 1 + extra
  put_simple_code(w, 64, &distance_code, 1, 0);
  // Command 139: insert code 1 (one literal), copy code 3 (five bytes), explicit
  // distance.  No insert, copy or distance extra bits are needed.
  w->put(0, 1);  // the single distance extra bit: distance 1
}

// An empty metadata meta-block: MSKIPBYTES is 0, so there are no length bytes and
// MSKIPLEN is 0, but the zero fill bits up to the byte boundary are still part of
// the format (section 9.2).  Real encoders emit these; python's brotli.compress
// does not, which is why the hand-built streams have to cover them.
void put_empty_metadata_meta_block(BitWriter* w) {
  w->put(0, 1);  // ISLAST = 0
  w->put(3, 2);  // MNIBBLES = 0, the metadata form (bit pattern "11")
  w->put(0, 1);  // reserved, must be zero
  w->put(0, 2);  // MSKIPBYTES = 0
  w->align();    // the fill bits up to the byte boundary, all zero
}

// A metadata meta-block with a payload, which the decoder must skip and must not
// append to the output.
void put_metadata_meta_block(BitWriter* w, const char* payload, unsigned len) {
  w->put(0, 1);        // ISLAST = 0
  w->put(3, 2);        // MNIBBLES = 0, the metadata form
  w->put(0, 1);        // reserved, must be zero
  w->put(1, 2);        // MSKIPBYTES = 1
  w->put(len - 1, 8);  // MSKIPLEN - 1
  w->align();          // the fill bits up to the byte boundary
  for (unsigned i = 0; i < len; ++i) w->put(static_cast<std::uint8_t>(payload[i]), 8);
}

// A stream with an empty metadata meta-block between two compressed ones: the
// shape that real encoders produce.  Leaving its fill bits unread shifts every
// following meta-block header, so this stream pins that down.
std::vector<u8> build_stream_empty_metadata() {
  BitWriter w;
  put_window_bits(&w);
  put_lz77_meta_block(&w, 139);
  put_empty_metadata_meta_block(&w);
  put_lz77_meta_block(&w, 139);
  put_final_empty_meta_block(&w);
  return w.bytes();
}

// A non-empty metadata meta-block in front of a compressed one.
std::vector<u8> build_stream_metadata_payload() {
  BitWriter w;
  put_window_bits(&w);
  put_metadata_meta_block(&w, "MD", 2);
  put_lz77_meta_block(&w, 139);
  put_final_empty_meta_block(&w);
  return w.bytes();
}

// A single compressed meta-block that is itself the last one: ISLAST = 1 with
// ISLASTEMPTY = 0, so the stream ends right after its data and no terminating
// empty meta-block follows.
std::vector<u8> build_stream_last_compressed() {
  BitWriter w;
  put_window_bits(&w);
  put_lz77_meta_block(&w, 139, true);
  return w.bytes();
}

// The empty metadata stream with ones in the fill bits, which section 9.2
// forbids.
std::vector<u8> build_stream_bad_metadata_fill() {
  BitWriter w;
  put_lz77_meta_block(&w, 139);
  w.put(0, 1);  // ISLAST = 0
  w.put(3, 2);  // MNIBBLES = 0, the metadata form
  w.put(0, 1);  // reserved, must be zero
  w.put(0, 2);  // MSKIPBYTES = 0
  const unsigned used = w.bit() & 7u;
  if (used != 0) {
    const unsigned fill = 8u - used;
    w.put((1u << fill) - 1u, fill);  // the fill bits, wrongly set to one
  }
  put_lz77_meta_block(&w, 139);
  put_final_empty_meta_block(&w);
  return w.bytes();
}

}  // namespace

bool brotli_selfcheck(std::string* report) {
  std::string local;
  if (report == nullptr) report = &local;
  report->clear();
  int failures = 0;
  auto check = [&](bool ok, const std::string& what) {
    if (!ok) {
      ++failures;
      if (!report->empty()) *report += "; ";
      *report += what;
    }
  };

  // 1) The empty stream: window bits 16 (one 0 bit), then ISLAST=1 and
  //    ISLASTEMPTY=1 -> bits 0,1,1 = 0x06.
  {
    const u8 empty_stream[] = {0x06};
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(empty_stream, sizeof(empty_stream), &out, &why);
    check(ok && out.empty(), "the empty stream decodes to nothing (" + why + ")");
  }

  // 2) A stored meta-block holding "Hi".  All four MLEN nibbles come before the
  //    ISUNCOMPRESSED flag, so the flag lands in the middle of the third byte:
  //      byte 0: window 16 (0), ISLAST=0, MNIBBLES=0, nibble 0 = 1  -> 0x10
  //      byte 1: nibbles 1 and 2 = 0                                -> 0x00
  //      byte 2: nibble 3 = 0, ISUNCOMPRESSED=1 (bit 4), padding     -> 0x10
  //      byte 3/4: 'H' 'i'
  //      byte 5: final empty meta-block (ISLAST=1, ISLASTEMPTY=1)    -> 0x03
  {
    const u8 stream[] = {0x10, 0x00, 0x10, 'H', 'i', 0x03};
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream, sizeof(stream), &out, &why);
    check(ok && out == "Hi", "a stored meta-block yields its bytes (" + why + ", got " +
                                 std::to_string(out.size()) + " bytes)");
  }

  // 3) Broken streams must be refused rather than half-decoded: a stored block
  //    whose payload is missing, and a header that asks for a compressed block.
  {
    const u8 truncated[] = {0x10};
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(truncated, sizeof(truncated), &out, &why);
    check(!ok && !why.empty(), "a truncated stored meta-block is refused");

    const u8 compressed[] = {0x00};
    out.clear();
    why.clear();
    const bool ok2 = brotli_decompress(compressed, sizeof(compressed), &out, &why);
    check(!ok2 && !why.empty(), "a truncated compressed meta-block is refused");
  }

  // 4) A full command loop: insert one literal, then copy five bytes from
  //    distance 1 so that the copy overlaps the byte it is copying.
  {
    const std::vector<u8> stream = build_stream_lz77(139);
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(ok && out == "AAAAAA", "an overlapping backward copy produces the right bytes (" + why +
                                     ", got " + std::to_string(out.size()) + " bytes)");
  }

  // 5) A simple prefix code may not name the same symbol twice.
  {
    const std::vector<u8> stream = build_stream_duplicate_literal();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(!ok && !why.empty(), "a simple prefix code that repeats a symbol is refused");
  }

  // 6) A simple prefix code may not name a symbol outside its alphabet
  //    (the insert-and-copy alphabet holds 704 symbols).
  {
    const std::vector<u8> stream = build_stream_lz77(1000);
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(!ok && !why.empty(), "a simple prefix code outside its alphabet is refused");
  }

  // 7) The complex prefix code with an early stop, and the static dictionary.
  {
    const std::vector<u8> stream = build_stream_dictionary();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(ok && out == "ABdomain",
          "a static dictionary word decodes through a complex prefix code (" + why + ", got \"" +
              out + "\" from a " + std::to_string(stream.size()) + " byte stream)");
  }

  // 8) The same stream truncated in the middle is refused.
  {
    const std::vector<u8> stream = build_stream_dictionary();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size() / 2, &out, &why);
    check(!ok && !why.empty(), "a compressed meta-block that stops mid-header is refused");
  }

  // 9) An empty metadata meta-block between two compressed ones.  Real encoders
  //    emit these and python's brotli.compress never does; the fill bits that
  //    follow MSKIPBYTES are what a decoder is easy to leave unread.
  {
    const std::vector<u8> stream = build_stream_empty_metadata();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(ok && out == "AAAAAAAAAAAA",
          "an empty metadata meta-block between two compressed ones is skipped (" + why +
              ", got \"" + out + "\" from a " + std::to_string(stream.size()) + " byte stream)");
  }

  // 10) A metadata meta-block with a payload: the payload is skipped, never
  //     appended to the output.
  {
    const std::vector<u8> stream = build_stream_metadata_payload();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(ok && out == "AAAAAA",
          "a metadata meta-block payload is skipped (" + why + ", got \"" + out + "\")");
  }

  // 11) The last meta-block is a compressed one with ISLAST = 1 and ISLASTEMPTY =
  //     0, so the stream ends after its data with no terminating empty block.
  {
    const std::vector<u8> stream = build_stream_last_compressed();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(ok && out == "AAAAAA",
          "a last compressed meta-block terminates the stream (" + why + ", got \"" + out + "\")");
  }

  // 12) A one in the fill bits of a metadata meta-block is invalid.
  {
    const std::vector<u8> stream = build_stream_bad_metadata_fill();
    std::string out;
    std::string why;
    const bool ok = brotli_decompress(stream.data(), stream.size(), &out, &why);
    check(!ok && !why.empty(), "nonzero metadata fill bits are refused");
  }

  // 13) The stored encoder: what it writes must decode back byte for byte, its
  //     length must be the one brotli_stored_size predicts, and a body one byte
  //     bigger must not fit the same budget.
  {
    const std::string text = "Hello, stored world! 0123456789";
    std::string stream;
    std::string why;
    const bool built = brotli_compress_stored(reinterpret_cast<const u8*>(text.data()),
                                              text.size(), &stream, &why);
    check(built, "a stored stream is built (" + why + ")");
    check(stream.size() == brotli_stored_size(text.size()),
          "brotli_stored_size predicts the length (" + std::to_string(stream.size()) + " vs " +
              std::to_string(brotli_stored_size(text.size())) + ")");
    std::string back;
    const bool ok = brotli_decompress(stream, &back, &why);
    check(ok && back == text, "the stored stream decodes back to the same bytes (" + why + ")");
    check(brotli_stored_fits(text.size(), stream.size()), "a body fits its own stored stream");
    check(!brotli_stored_fits(text.size() + 1, stream.size()), "one byte more does not fit");

    std::string big(70000, 'a');
    for (std::size_t i = 0; i < big.size(); ++i) {
      big[i] = static_cast<char>('a' + static_cast<int>(i % 26));
    }
    std::string big_stream;
    back.clear();
    const bool big_ok =
        brotli_compress_stored(reinterpret_cast<const u8*>(big.data()), big.size(), &big_stream,
                               &why) &&
        brotli_decompress(big_stream, &back, &why) && back == big;
    check(big_ok, "a 70 KiB body crosses the 64 KiB block boundary (" + why + ")");
    check(big_stream.size() == brotli_stored_size(big.size()), "and its length is predicted too");
  }

  if (failures == 0) report->clear();
  return failures == 0;
}

// --- the stored encoder ---------------------------------------------------
//
// One stored meta-block, exactly as the decoder above reads it back (RFC 7932
// section 9.2):
//
//   ISLAST (1) = 0 | MNIBBLES (2) = 0 (four nibbles) | MLEN-1 (16) |
//   ISUNCOMPRESSED (1) = 1 | fill bits to the byte boundary | raw bytes
//
// ISUNCOMPRESSED exists only while ISLAST is clear, so a stored stream always
// ends with an empty ISLAST + ISLASTEMPTY meta-block -- the same two bits the
// decoder breaks on.
namespace {
constexpr std::size_t kStoredBlockMax = 65536;  // MLEN is sixteen bits wide
}  // namespace

std::size_t brotli_stored_size(std::size_t len) {
  std::size_t bits = 1;  // the window header: a single zero bit, window 16
  std::size_t left = len;
  while (left != 0) {
    const std::size_t chunk = left < kStoredBlockMax ? left : kStoredBlockMax;
    bits += 20;                      // ISLAST + MNIBBLES + MLEN + ISUNCOMPRESSED
    bits += (8u - (bits & 7u)) & 7u;  // the fill bits before the raw bytes
    bits += 8u * chunk;
    left -= chunk;
  }
  bits += 2;  // ISLAST + ISLASTEMPTY
  return (bits + 7u) / 8u;
}

bool brotli_stored_fits(std::size_t len, std::size_t budget) {
  return brotli_stored_size(len) <= budget;
}

bool brotli_compress_stored(const u8* data, std::size_t len, std::string* out,
                            std::string* error) {
  if (out == nullptr) return false;
  out->clear();
  if (len != 0 && data == nullptr) {
    if (error != nullptr) *error = "there is no input to store";
    return false;
  }
  if (len > brotli_max_output()) {
    if (error != nullptr) *error = "the body is larger than the 32 MiB ceiling";
    return false;
  }
  BitWriter w;
  put_window_bits(&w);
  std::size_t off = 0;
  while (off < len) {
    const std::size_t chunk = len - off < kStoredBlockMax ? len - off : kStoredBlockMax;
    w.put(0, 1);  // ISLAST = 0
    w.put(0, 2);  // MNIBBLES = 0: four nibbles
    const std::uint32_t mlen = static_cast<std::uint32_t>(chunk) - 1u;
    for (unsigned i = 0; i < 4; ++i) w.put((mlen >> (4u * i)) & 0xfu, 4);
    w.put(1, 1);  // ISUNCOMPRESSED
    w.align();    // section 9.2: the fill bits must be zeros
    for (std::size_t i = 0; i < chunk; ++i) w.put(data[off + i], 8);
    off += chunk;
  }
  w.put(1, 1);  // ISLAST
  w.put(1, 1);  // ISLASTEMPTY
  w.align();    // the unused bits of the last byte are zeros
  out->assign(reinterpret_cast<const char*>(w.bytes().data()), w.bytes().size());
  if (error != nullptr) error->clear();
  return true;
}

}  // namespace netcap
