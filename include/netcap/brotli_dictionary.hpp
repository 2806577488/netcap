// Data tables from RFC 7932 that the Brotli decoder needs at run time.
//
// The arrays themselves live in the generated translation unit
// `src/brotli_dictionary.cpp`, which `tools/embed_dictionary.py` writes from the
// canonical dictionary blob and the tables the RFC prints in its appendices.
// Keeping the 122784-byte dictionary in the binary is what lets the decoder stay
// self-contained.
#ifndef NETCAP_BROTLI_DICTIONARY_HPP
#define NETCAP_BROTLI_DICTIONARY_HPP

#include <cstddef>

#include "netcap/common.hpp"

namespace netcap {

// The static dictionary of RFC 7932 Appendix A: the words of length 4..24, laid
// out back to back in ascending length order (section 8).
const u8* brotli_dictionary_data();
std::size_t brotli_dictionary_size();  // 122784

// DOFFSET[L] is where the length-L words begin and NDBITS[L] is log2 of how many
// of them there are, so word `index` of length L lives at
// `DOFFSET[L] + index * L`.  Both arrays have 32 entries and are zero outside
// L = 4..24.
const std::size_t* brotli_dictionary_offsets();
const u8* brotli_dictionary_size_bits();

// One of the 121 transforms of Appendix B: the result is
// `prefix + T(word) + suffix`, where T is selected by `type`.
struct BrotliTransform {
  const char* prefix;
  unsigned prefix_len;
  // 0 identity, 1 ferment-first, 2 ferment-all, 3..11 omit the first 1..9 bytes,
  // 12..20 omit the last 1..9 bytes.
  unsigned type;
  const char* suffix;
  unsigned suffix_len;
};
const BrotliTransform* brotli_transforms();
std::size_t brotli_transform_count();  // 121

// Lut0, Lut1 and Lut2 of section 7.1 concatenated: 3 * 256 bytes, so
// `lookup[p1] | lookup[256 + p2]` is the UTF8 literal context and
// `lookup[512 + p]` the signed one.
const u8* brotli_context_lookup();

}  // namespace netcap

#endif  // NETCAP_BROTLI_DICTIONARY_HPP
