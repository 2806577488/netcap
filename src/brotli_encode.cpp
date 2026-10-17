// Brotli (RFC 7932) encoder -- written from the RFC.
//
// The decoder in `brotli.cpp` is the specification this file inverts, and it is
// the reason the bit-level details below are statements of fact rather than
// recollections: every layout here was read off the decoder branch that consumes
// it, then checked against the corresponding RFC section.
//
// Structure:
//   BitWriter / prefix codes   -- 1.5, 3.2, 3.4, 3.5
//   Huffman                    -- length-limited (package-merge), then canonical
//   MatchFinder                -- hash chains over the input
//   DictionaryIndex            -- 8 static dictionary + Appendix B transforms
//   MetaBlock                  -- 9.2 header, 4 distances, 5 commands, 7 contexts
//
// The encoder never guesses.  If any stage cannot produce something a decoder
// reads back as the same bytes, it returns false and leaves the caller's output
// empty.  A plausible-looking but wrong stream is the one failure mode this file
// exists to avoid: the caller rewrites responses in place, so a stream that
// decodes to different bytes is worse than no stream at all.
#include "netcap/brotli_encode.hpp"

#include <algorithm>
#include <array>
#include <cmath>

#include <cstdint>
#include <cstring>
#include <functional>
#include <queue>
#include <utility>
#include <vector>

#include "netcap/brotli.hpp"
#include "netcap/brotli_dictionary.hpp"

namespace netcap {
namespace {

using u64 = std::uint64_t;
using u32 = std::uint32_t;
using u16 = std::uint16_t;

// RFC 7932 section 5: insert-length and copy-length code tables, the exact tables
// the decoder indexes at `src/brotli.cpp:57-66`.  The encoder inverts them.
constexpr int kInsertBase[24] = {0,   1,   2,   3,   4,   5,   6,   8,    10,   14,   18,   26,
                                 34,  50,  66,  98,  130, 194, 322, 578,  1090, 2114, 6210, 22594};
constexpr int kInsertExtra[24] = {0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
                                  4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24};
constexpr int kCopyBase[24] = {2,   3,   4,   5,   6,   7,   8,   9,   10,  12,  14,  18,
                               22,  30,  38,  54,  70,  102, 134, 198, 326, 582, 1094, 2118};
constexpr int kCopyExtra[24] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2,
                                3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24};

// Section 5: `command >> 6` is the insert/copy range cell and the low six bits are
// the in-cell indices.
constexpr int kInsertRangeLut[11] = {0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16};
constexpr int kCopyRangeLut[11] = {0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16};

// Section 3.5: the code-length alphabet travels in this permuted order.
constexpr int kCodeLengthCodeOrder[18] = {1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15};
// Section 3.5: that alphabet's own code is fixed; these are its (length, value)
// pairs, held exactly as the decoder's kCodeLengthPrefix{Length,Value} tables do.
constexpr int kCodeLengthPrefixLength[16] = {2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4};
constexpr int kCodeLengthPrefixValue[16] = {0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5};

// Section 4: the 16 short distance codes, each an index into the ring buffer plus
// a delta.  A code whose result is <= 0 is invalid.
constexpr int kDistanceShortCodeIndex[16] = {0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1};
constexpr int kDistanceShortCodeDelta[16] = {0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3};

constexpr int kMaxHuffmanBits = 15;    // 3.2: lengths are 1..15
constexpr int kMaxCodeLenBits = 5;     // 3.5: code-length alphabet lengths are 2..5
constexpr int kLiteralAlphabet = 256;
constexpr int kCommandAlphabet = 704;  // 11 insert codes x 11 copy codes, then 128
constexpr int kDistanceAlphabet = 64;  // NPOSTFIX = 0, NDIRECT = 0
constexpr int kMaxLiteralTrees = 64;
constexpr int kMaxMlen = (1 << 24) - 1;
constexpr int kMaxDistanceTrees = 4;   // one per section 7.2 distance context

// ---------------------------------------------------------------------------
// Bit writer
// ---------------------------------------------------------------------------
// The decoder's BitReader fills with `buffer_ |= data[pos++] << count_`, so the
// stream is little-endian in bits: the first bit written is the least significant
// bit of the first byte.  Every bit below goes through this class so that fact
// lives in one place.
class BitWriter {
 public:
  void put(u32 value, int count) {
    if (count <= 0) return;
    buffer_ |= static_cast<u64>(value) << count_;
    count_ += count;
    while (count_ >= 8) {
      out_.push_back(static_cast<char>(buffer_ & 0xff));
      buffer_ >>= 8;
      count_ -= 8;
    }
  }

  void bit(int v) { put(static_cast<u32>(v & 1), 1); }

  void align() {
    if (count_ > 0) {
      out_.push_back(static_cast<char>(buffer_ & 0xff));
      buffer_ = 0;
      count_ = 0;
    }
  }

  std::size_t bit_size() const { return out_.size() * 8 + static_cast<std::size_t>(count_); }

  // Append `n` whole bytes WITHOUT aligning.  The caller has already filled to the byte
  // boundary its format requires, and a body that gets spliced into a wider stream (the
  // stored body, which follows the window header) must stay bit exact: an align() here
  // inserts zero bits the decoder does not expect and shifts every following byte.
  void append_bytes(const char* p, std::size_t n) {
    if (count_ == 0) {
      out_.append(p, n);
      return;
    }
    for (std::size_t i = 0; i < n; ++i) {
      put(static_cast<u32>(static_cast<u8>(p[i])), 8);
    }
  }

  // Continue this bit stream with `bit_count` bits taken from `bytes`, which must
  // itself be a little-endian bit stream (the first bit of the first byte is the
  // first bit written).  Meta-blocks are NOT byte aligned against each other, so a
  // meta-block emitted into its own writer has to be spliced in bit by bit; calling
  // `align()` and appending whole bytes would insert fill bits the decoder would
  // then read as the next meta-block's header.
  void append_bits(const std::string& bytes, std::size_t bit_count) {
    const std::size_t whole = bit_count / 8;
    for (std::size_t i = 0; i < whole; ++i) {
      put(static_cast<u32>(static_cast<u8>(bytes[i])), 8);
    }
    const unsigned rem = static_cast<unsigned>(bit_count % 8);
    if (rem != 0 && whole < bytes.size()) {
      put(static_cast<u32>(static_cast<u8>(bytes[whole])), static_cast<int>(rem));
    }
  }

  std::string take() {
    align();
    std::string out = std::move(out_);
    out_.clear();
    return out;
  }

 private:
  std::string out_;
  u64 buffer_ = 0;
  int count_ = 0;
};

// ---------------------------------------------------------------------------
// Prefix codes
// ---------------------------------------------------------------------------

// Section 3.2 canonical assignment: equal lengths get consecutive values in
// ascending symbol order and shorter lengths sort first.  HuffmanCode::decode
// builds its accumulator with `code = (code << 1) | bit`, i.e. it reads the
// canonical code most significant bit first, so writes must too.
void canonical_codes(const std::vector<u8>& lengths, std::vector<u16>* codes) {
  codes->assign(lengths.size(), 0);
  int max_len = 0;
  for (u8 l : lengths)
    if (l > max_len) max_len = l;
  if (max_len == 0) return;
  std::vector<int> count(static_cast<std::size_t>(max_len) + 1, 0);
  for (u8 l : lengths)
    if (l > 0) count[l]++;
  std::vector<int> next(static_cast<std::size_t>(max_len) + 2, 0);
  int code = 0;
  for (int len = 1; len <= max_len; ++len) {
    code = (code + count[len - 1]) << 1;
    next[len] = code;
  }
  for (std::size_t s = 0; s < lengths.size(); ++s) {
    const int len = lengths[s];
    if (len > 0) (*codes)[s] = static_cast<u16>(next[len]++);
  }
}

void write_code(BitWriter* w, u16 code, int len) {
  for (int i = len - 1; i >= 0; --i) w->bit((code >> i) & 1);
}

// How many literal trees the planner may create, by quality.  Low qualities stay at
// one tree so the context map never has to be sent at all.
constexpr int kTreeCaps[12] = {1, 1, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64};

// Section 9.2: MNIBBLES is at least 4, so the length needs at least four nibbles.
// Encoding `mnibbles - 4` in two bits is the RFC's own table, and only the shortest
// form that fits is legal because the decoder rejects an MLEN that does not fit.
void write_mlen_bits(BitWriter* w, std::size_t mlen) {
  // MNIBBLES must be the smallest count whose 4-bit groups hold MLEN-1: the decoder
  // rejects a leading zero nibble whenever MNIBBLES is above the minimum of four.
  const std::size_t v = mlen - 1;
  unsigned nibbles = 4;
  if (v > 0xffffu) {
    nibbles = 5;
    if (v > 0xfffffu) nibbles = 6;
  }
  w->put(nibbles - 4, 2);
  // MNIBBLES counts 4-bit groups, not bytes: the decoder reads `nibbles` groups of
  // four bits each, so the field is 16, 20 or 24 bits wide.
  for (unsigned i = 0; i < 4 * nibbles; ++i) {
    w->bit(static_cast<int>((v >> i) & 1));
  }
}

// Section 9.2's variable length byte: one bit for 1, otherwise a 3-bit exponent, a
// zero exponent meaning 2, and then the low `n` bits above `1 << n`.  Only ever used
// for small counts here, but the encoder must agree with the decoder exactly.
void write_var_len_u8(BitWriter* w, int value) {
  if (value == 1) {
    w->bit(0);
    return;
  }
  w->bit(1);
  if (value == 2) {
    w->put(0, 3);
    return;
  }
  int n = 1;
  while ((1 << (n + 1)) < value) ++n;
  w->put(static_cast<u32>(n), 3);
  w->put(static_cast<u32>(value - (1 << n) - 1), n);
}

// Section 3.2 caps code lengths at 15, and the decoder's `build_huffman` rejects an
// incomplete code, so what is needed here is not just "a short code" but one whose
// Kraft sum is exactly 2^limit.
//
// Recursive bisection (Shannon-Fano) with a hard count cap.  A subtree sitting at
// `depth` may hold at most 2^(limit - depth) symbols, so splitting at most half of
// that per side keeps every code within `limit`.  Every internal node has two
// non-empty children, so the result is a *full* binary tree and therefore a complete
// prefix code (Kraft sum exactly 1) with no repair arithmetic at all.  It is used
// only when the unbounded Huffman depths do not fit in `limit`, which keeps the
// optimal tree for every ordinary histogram.
bool bisect_lengths(const std::vector<u64>& w, int lo, int hi, int depth, int limit,
                    std::vector<int>* out) {
  if (hi - lo == 1) {
    (*out)[static_cast<std::size_t>(lo)] = depth;
    return true;
  }
  const int shift = limit - depth - 1;
  if (shift < 0) return false;
  const int cap = shift >= 30 ? (1 << 30) : (1 << shift);
  if (hi - lo > 2 * cap) return false;

  int lo_split = hi - cap;
  if (lo_split < lo + 1) lo_split = lo + 1;
  int hi_split = lo + cap;
  if (hi_split > hi - 1) hi_split = hi - 1;
  if (lo_split > hi_split) return false;

  u64 total = 0;
  for (int i = lo; i < hi; ++i) total += w[static_cast<std::size_t>(i)];
  const u64 half = total / 2;
  u64 acc = 0;
  u64 best = ~static_cast<u64>(0);
  int split = lo_split;
  for (int i = lo; i < hi; ++i) {
    acc += w[static_cast<std::size_t>(i)];
    const int s = i + 1;
    if (s < lo_split || s > hi_split) continue;
    const u64 diff = acc > half ? acc - half : half - acc;
    if (diff < best) {
      best = diff;
      split = s;
    }
  }
  return bisect_lengths(w, lo, split, depth + 1, limit, out) &&
         bisect_lengths(w, split, hi, depth + 1, limit, out);
}

// A previous package-merge implementation was wrong: each package node was built
// with `item = -1` while its leaves hung off a `next` chain, so the leaf-counting
// walk (`sub = item[nd]`) never entered a package at all and every package
// contributed zero leaves.  It rejected 135 - 135 == 0 coded symbols, which is why
// `write_meta_block_header` failed on `_br/real_bing.bin`.
//
// A zlib-style "clamp every over-long code, then repair the Kraft sum from the
// length histogram" replacement was tried next and was ALSO wrong: the repair loop
// moves one overflowed leaf per step and lowers the Kraft sum by exactly one unit,
// but the number of steps it runs (`overflow / 2`) is not the number of units that
// actually have to come off, so it overshot.  Measured on the code-length alphabet
// of `_br/real_bing.bin`: `length_limited_lengths(counts, 5)` returned false with a
// final Kraft sum of 33 - 32 == 1 unit too many (`space = -5` when the decoder
// counts down from 32).
//
// So the lengths are now taken straight from the unbounded Huffman tree, which is
// complete by construction, whenever its depth fits in `limit`.  That is the common
// case (the command tree of `_br/real_bing.bin` is Kraft-exact at depth 8 < 15).
// Only a histogram that genuinely needs clamping falls back to the capped
// bisection above.
bool length_limited_lengths(const std::vector<u32>& counts, int limit,
                            std::vector<u8>* lengths) {
  const int n = static_cast<int>(counts.size());
  lengths->assign(counts.size(), 0);
  if (limit < 1 || n <= 0) return false;

  std::vector<int> syms;
  syms.reserve(static_cast<std::size_t>(n));
  for (int s = 0; s < n; ++s) {
    if (counts[s] > 0) syms.push_back(s);
  }
  const int m = static_cast<int>(syms.size());
  if (m == 0) return false;
  if (m == 1) {
    (*lengths)[static_cast<std::size_t>(syms[0])] = 1;
    return true;
  }
  // A complete code of depth `limit` has at most 2^limit slots.
  if (limit >= 31 || m > (1 << limit)) return false;

  // 1) Unbounded Huffman, as an explicit tree so depths can be read back by walking
  //    to the root.  The `symbol` field is unused once the depths are known; the
  //    leaves are addressed by their index in `syms`.
  struct Node {
    u64 weight;
    int parent;
    int symbol;
  };
  std::vector<Node> nodes;
  nodes.reserve(static_cast<std::size_t>(2 * m));
  for (int i = 0; i < m; ++i) {
    nodes.push_back(Node{counts[static_cast<std::size_t>(syms[static_cast<std::size_t>(i)])], -1,
                         syms[static_cast<std::size_t>(i)]});
  }
  using Entry = std::pair<u64, int>;
  std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>> pq;
  for (int i = 0; i < m; ++i) pq.push(Entry{nodes[i].weight, i});
  while (pq.size() > 1) {
    const Entry a = pq.top();
    pq.pop();
    const Entry b = pq.top();
    pq.pop();
    const int idx = static_cast<int>(nodes.size());
    nodes.push_back(Node{a.first + b.first, -1, -1});
    nodes[static_cast<std::size_t>(a.second)].parent = idx;
    nodes[static_cast<std::size_t>(b.second)].parent = idx;
    pq.push(Entry{a.first + b.first, idx});
  }

  // 2) Unbounded Huffman depths, read back by walking each leaf to the root, and the
  //    symbol order the lengths will be handed out in (heaviest symbol first, so the
  //    shortest code goes to the most frequent symbol).
  std::vector<int> order(static_cast<std::size_t>(m));
  for (int i = 0; i < m; ++i) order[static_cast<std::size_t>(i)] = i;
  std::stable_sort(order.begin(), order.end(), [&](int a, int b) {
    const u32 ca = counts[static_cast<std::size_t>(syms[static_cast<std::size_t>(a)])];
    const u32 cb = counts[static_cast<std::size_t>(syms[static_cast<std::size_t>(b)])];
    if (ca != cb) return ca > cb;
    return syms[static_cast<std::size_t>(a)] < syms[static_cast<std::size_t>(b)];
  });

  std::vector<int> depth(static_cast<std::size_t>(m), 1);
  bool needs_clamp = false;
  for (int i = 0; i < m; ++i) {
    int d = 0;
    for (int c = i; nodes[static_cast<std::size_t>(c)].parent >= 0;
         c = nodes[static_cast<std::size_t>(c)].parent) {
      ++d;
    }
    if (d < 1) d = 1;
    depth[static_cast<std::size_t>(i)] = d;
    if (d > limit) needs_clamp = true;
  }

  std::vector<int> len_order(static_cast<std::size_t>(m), 1);
  if (!needs_clamp) {
    for (int j = 0; j < m; ++j) {
      len_order[static_cast<std::size_t>(j)] = depth[static_cast<std::size_t>(order[static_cast<std::size_t>(j)])];
    }
  } else {
    std::vector<u64> w(static_cast<std::size_t>(m), 0);
    for (int j = 0; j < m; ++j) {
      w[static_cast<std::size_t>(j)] = counts[static_cast<std::size_t>(syms[static_cast<std::size_t>(order[static_cast<std::size_t>(j)])])];
    }
    if (!bisect_lengths(w, 0, m, 0, limit, &len_order)) return false;
  }

  for (int j = 0; j < m; ++j) {
    const int l = len_order[static_cast<std::size_t>(j)];
    if (l < 1 || l > limit) return false;
    (*lengths)[static_cast<std::size_t>(syms[static_cast<std::size_t>(order[static_cast<std::size_t>(j)])])] =
        static_cast<u8>(l);
  }

  // 3) The decoder refuses an incomplete code, so re-derive the Kraft sum rather than
  //    trust the construction.
  u64 kraft = 0;
  for (int j = 0; j < m; ++j) kraft += static_cast<u64>(1) << (limit - len_order[static_cast<std::size_t>(j)]);
  return kraft == (static_cast<u64>(1) << limit);
}

// Section 3.5 needs the code-length alphabet's own code complete too, and its
// lengths are capped at 5 rather than 15.  Every symbol gets a non-zero length
// here (zero-count ones included), because the decoder reads all of them.
bool histogram_to_lengths(const std::vector<u32>& counts, int limit, std::vector<u8>* lengths) {
  std::vector<int> present;
  for (std::size_t s = 0; s < counts.size(); ++s)
    if (counts[s] > 0) present.push_back(static_cast<int>(s));
  if (present.empty()) return false;
  if (present.size() > (static_cast<std::size_t>(1) << limit)) return false;
  std::vector<u32> c(counts);
  for (std::size_t s = 0; s < c.size(); ++s)
    if (c[s] == 0) c[s] = 1;
  return length_limited_lengths(c, limit, lengths);
}

// Section 3.4: with at most four symbols the simple form is available.  It is the
// cheapest encoding and complete by construction, so small alphabets (distances,
// context maps, the code-length code) always route here.
bool write_simple_prefix_code(BitWriter* w, const std::vector<int>& present, int alphabet_bits) {
  const int nsym = static_cast<int>(present.size());
  if (nsym < 1 || nsym > 4) return false;
  // Sections 3.4/3.5: the prefix code is dispatched on TWO bits, and the value 1
  // selects the simple form (the complex form follows for HSKIP 0, 2 or 3).  Writing a
  // single bit here shifts every following field of the meta-block by one bit, which
  // the decoder then reads as part of the tree description.
  w->put(1, 2);
  w->put(static_cast<u32>(nsym - 1), 2);
  for (int s : present) w->put(static_cast<u32>(s), alphabet_bits);
  if (nsym == 4) {
    // The tree-select bit: 0 means four length-2 codes, 1 means lengths 1,2,3,3.
    // The caller orders `present` by descending count, so the skewed shape is the
    // one that matches the histogram.
    w->bit(1);
  }
  return true;
}

// Section 3.5: describe an arbitrary length vector in the complex form.  Returns
// false when no legal description exists, which must abort the meta-block rather
// than risk an incomplete code.
bool write_complex_prefix_code(BitWriter* w, const std::vector<u8>& lengths) {
  int last = -1;
  for (std::size_t i = 0; i < lengths.size(); ++i)
    if (lengths[i] > 0) last = static_cast<int>(i);
  if (last < 0) return false;

  // HSKIP stays 0.  HSKIP skips entries of the CODE LENGTH code, while `lengths` is
  // the alphabet's own length vector, so a leading-zero test on `lengths` says
  // nothing about which code length entries may be skipped -- and the emission loop
  // below walks the code length order from index 0, so a non-zero HSKIP would shift
  // the written entries against the ones the decoder reads.  Writing all 18 entries
  // is always legal and costs two bits.
  const int hskip = 0;
  w->put(0, 2);

  // The code-length alphabet's histogram, and the token stream that produced it.
  std::vector<u32> cl_counts(18, 0);
  std::vector<std::pair<int, int>> tokens;  // (symbol, extra-bit value)
  // Section 3.5: a repeat symbol that immediately follows a repeat of the SAME kind
  // rewrites the previous count instead of adding to it (`new = k * (prev - 2) + 3 + e`),
  // so chained repeats need exact arithmetic rather than a simple chunk loop.  This
  // tokenizer never chains: between two repeats of one kind it emits a single bare
  // length, which resets the decoder's repeat state and costs one extra symbol.
  int last_kind = 0;  // 0 = a bare length, otherwise 16 or 17 (the previous repeat)
  int i = hskip;
  while (i <= last) {
    const int len = lengths[i];
    int run = 1;
    while (i + run <= last && lengths[i + run] == len) ++run;
    if (len == 0) {
      int left = run;
      while (left > 0) {
        if (last_kind != 17 && left >= 3) {
          const int cnt = std::min(left, 10);  // 3.5: code 17 repeats zero 3..10 times
          tokens.push_back({17, cnt - 3});
          cl_counts[17]++;
          last_kind = 17;
          left -= cnt;
        } else {
          tokens.push_back({0, 0});
          cl_counts[0]++;
          last_kind = 0;
          --left;
        }
      }
    } else {
      tokens.push_back({len, 0});
      cl_counts[len]++;
      last_kind = 0;
      int left = run - 1;
      while (left > 0) {
        if (last_kind != 16 && left >= 3) {
          const int cnt = std::min(left, 6);  // 3.5: code 16 repeats 3..6 times
          tokens.push_back({16, cnt - 3});
          cl_counts[16]++;
          last_kind = 16;
          left -= cnt;
        } else {
          tokens.push_back({len, 0});
          cl_counts[len]++;
          last_kind = 0;
          --left;
        }
      }
    }
    i += run;
  }
  if (tokens.empty()) return false;

  std::vector<u8> cl_lengths(18, 0);
  if (!histogram_to_lengths(cl_counts, kMaxCodeLenBits, &cl_lengths)) return false;
  std::vector<u16> cl_codes(18, 0);
  canonical_codes(cl_lengths, &cl_codes);

  int cl_last = -1;
  int space = 32;  // 3.5: the decoder counts 2^(5 - length) down from 32
  for (int k = hskip; k < 18; ++k) {
    const int sym = kCodeLengthCodeOrder[k];
    if (cl_lengths[sym] > 0) {
      cl_last = k;
      space -= 32 >> cl_lengths[sym];
    }
  }
  if (space != 0) return false;  // the code-length code must be complete
  for (int k = hskip; k <= cl_last; ++k) {
    const int sym = kCodeLengthCodeOrder[k];
    // The decoder peeks four bits and uses that value as an index into
    // kCodeLengthPrefixValue; the writer must therefore emit the BITS OF THE INDEX
    // whose table value is this length, not the length itself.
    int idx = -1;
    for (int j = 0; j < 16; ++j) {
      if (kCodeLengthPrefixValue[j] == cl_lengths[sym]) {
        idx = j;
        break;
      }
    }
    if (idx < 0) return false;
    w->put(static_cast<u32>(idx), kCodeLengthPrefixLength[idx]);
  }

  for (const auto& t : tokens) {
    const int sym = t.first;
    if (cl_lengths[sym] == 0) return false;
    write_code(w, cl_codes[sym], cl_lengths[sym]);
    if (sym == 16) {
      w->put(static_cast<u32>(t.second), 2);
    } else if (sym == 17) {
      w->put(static_cast<u32>(t.second), 3);
    }
  }
  return true;
}

// A prefix code the caller can use to encode symbols.
struct PrefixCode {
  bool valid = false;
  // RFC 7932 section 3.4: a simple code with NSYM == 1 codes its single symbol in
  // ZERO bits.  The decoder records it as `single` and reads nothing, so `emit`
  // must treat that symbol as free instead of rejecting its zero length.
  bool single = false;
  int single_symbol = -1;
  std::vector<u8> lengths;
  std::vector<u16> codes;

  // Emitting a symbol whose code length is zero would write NO bits and silently
  // desynchronise the stream, so this reports it instead.  A zero length means the
  // histogram the tree was built from does not contain the symbol being emitted --
  // that was a real bug once (a dictionary distance counted as symbol 16 in the
  // histogram but emitted as its short code), so it must never pass unnoticed again.
  bool emit(BitWriter* w, int symbol) const {
    if (single) return symbol == single_symbol;
    if (symbol < 0 || symbol >= static_cast<int>(lengths.size())) return false;
    if (lengths[symbol] == 0) return false;
    write_code(w, codes[symbol], lengths[symbol]);
    return true;
  }
};

// Build the shortest legal description of `counts` and the code that matches it.
// Small alphabets take the simple form; everything else gets a complex code over
// package-merge lengths, which is complete by construction.
bool build_prefix_code(BitWriter* w, const std::vector<u32>& counts, int alphabet_bits,
                       PrefixCode* out) {
  std::vector<int> present;
  for (std::size_t s = 0; s < counts.size(); ++s)
    if (counts[s] > 0) present.push_back(static_cast<int>(s));
  if (present.empty()) {
    // Every meta-block names at least one tree per category, and a category can be
    // genuinely unused (an all-copy stream has no literals at all).  RFC 3.4's
    // one-symbol code costs no bits and the decoder's NSYM == 1 path accepts it, so
    // describe the unused tree over symbol 0; nothing is ever emitted through it.
    present.push_back(0);
  }
  const int nsym = static_cast<int>(present.size());
  std::stable_sort(present.begin(), present.end(),
                   [&](int a, int b) { return counts[a] > counts[b]; });

  out->lengths.assign(counts.size(), 0);
  out->codes.assign(counts.size(), 0);

  if (nsym <= 4) {
    if (!write_simple_prefix_code(w, present, alphabet_bits)) return false;
    switch (nsym) {
      case 1:
        // 3.4: a single symbol is coded in zero bits.  The symbol must be recorded
        // so `emit` accepts it: rejecting the zero length made every singleton
        // literal tree unwritable, which surfaced as the q11 error
        // "command stream failed self-verification" on _br/real_bing2.bin.
        out->single = true;
        out->single_symbol = present[0];
        out->lengths[present[0]] = 0;
        break;
      case 2:
        out->lengths[present[0]] = 1;
        out->lengths[present[1]] = 1;
        break;
      case 3:
        out->lengths[present[0]] = 1;
        out->lengths[present[1]] = 2;
        out->lengths[present[2]] = 2;
        break;
      default:
        out->lengths[present[0]] = 1;
        out->lengths[present[1]] = 2;
        out->lengths[present[2]] = 3;
        out->lengths[present[3]] = 3;
        break;
    }
    if (nsym > 1) canonical_codes(out->lengths, &out->codes);
    out->valid = true;
    return true;
  }

  std::vector<u8> lengths;
  if (!length_limited_lengths(counts, kMaxHuffmanBits, &lengths)) return false;
  if (!write_complex_prefix_code(w, lengths)) return false;
  out->valid = true;
  out->lengths = std::move(lengths);
  canonical_codes(out->lengths, &out->codes);
  return true;
}

// Section 7.3: the context map.  Zero runs go through the run-length symbols, the
// remaining values through the code.  NTREES must equal the number of distinct
// values and those values must be exactly 0..NTREES-1; the clustering that builds
// `v` guarantees both.
// Section 7.3: a zero run may be coded by a symbol `s` in 1..RLEMAX, and the decoder
// then reads `s` extra bits and computes the run length as (1 << s) + extra, so one
// symbol covers runs of exactly 2^s .. 2^(s+1)-1.  A run of one zero is NOT
// representable that way, so a split must never leave a remainder of exactly one.
// Greedy largest-first already yields a single chunk whenever the run fits one
// symbol's range; the `left - c == 1` correction handles the boundary case where the
// run is exactly one more than a symbol's maximum.
void split_zero_run(int run, std::vector<std::pair<int, int>>* out) {
  int left = run;
  while (left > 0) {
    int s = 1;
    while (s < 15 && (1 << (s + 1)) <= left) ++s;
    int c = std::min(left, (1 << (s + 1)) - 1);
    if (left - c == 1) --c;
    if (c < (1 << s)) c = 1 << s;  // cannot happen for left >= 2, kept as a guard
    out->push_back({s, c - (1 << s)});
    left -= c;
  }
}

bool write_context_map(BitWriter* w, const std::vector<u8>& v, int ntrees) {
  // RLEMAX must be at least the largest run symbol used, and at most 16.
  int max_symbol = 0;
  {
    std::vector<std::pair<int, int>> chunks;
    int i = 0;
    while (i < static_cast<int>(v.size())) {
      if (v[i] != 0) {
        ++i;
        continue;
      }
      int j = i;
      while (j < static_cast<int>(v.size()) && v[j] == 0) ++j;
      const int run = j - i;
      if (run >= 2) {
        chunks.clear();
        split_zero_run(run, &chunks);
        for (const auto& c : chunks) max_symbol = std::max(max_symbol, c.first);
      }
      i = j;
    }
  }
  if (max_symbol > 16) return false;
  const int rlemax = max_symbol;
  // The decoder reads the flag bit FIRST and then the four-bit value, which is
  // RLEMAX - 1.
  if (rlemax == 0) {
    w->bit(0);
  } else {
    w->bit(1);
    w->put(static_cast<u32>(rlemax - 1), 4);
  }

  std::vector<u32> counts(static_cast<std::size_t>(ntrees + rlemax), 0);
  std::vector<std::pair<int, int>> chunks;
  int i = 0;
  while (i < static_cast<int>(v.size())) {
    if (v[i] == 0) {
      int j = i;
      while (j < static_cast<int>(v.size()) && v[j] == 0) ++j;
      const int left = j - i;
      if (left >= 2) {
        chunks.clear();
        split_zero_run(left, &chunks);
        for (const auto& c : chunks) counts[static_cast<std::size_t>(c.first)]++;
      } else {
        counts[0] += static_cast<u32>(left);
      }
      i = j;
    } else {
      counts[static_cast<std::size_t>(rlemax) + v[i]]++;
      ++i;
    }
  }

  PrefixCode cmap;
  std::vector<u8> lengths;
  // A complex code is always used here: the alphabet mixes zero-run symbols with
  // values, and padding the alphabet to a multiple of the fixed 2..5-bit
  // code-length description is what keeps it complete.
  if (!histogram_to_lengths(counts, kMaxHuffmanBits, &lengths)) return false;
  if (!write_complex_prefix_code(w, lengths)) return false;
  cmap.valid = true;
  cmap.lengths = std::move(lengths);
  canonical_codes(cmap.lengths, &cmap.codes);

  i = 0;
  while (i < static_cast<int>(v.size())) {
    if (v[i] == 0) {
      int j = i;
      while (j < static_cast<int>(v.size()) && v[j] == 0) ++j;
      const int left = j - i;
      if (left >= 2) {
        chunks.clear();
        split_zero_run(left, &chunks);
        for (const auto& c : chunks) {
          cmap.emit(w, c.first);
          w->put(static_cast<u32>(c.second), c.first);
        }
      } else {
        for (int k = 0; k < left; ++k) cmap.emit(w, 0);
      }
      i = j;
    } else {
      cmap.emit(w, rlemax + v[i]);
      ++i;
    }
  }
  w->bit(0);  // IMTF = 0: values are written in place, not move-to-front coded
  return true;
}

// ---------------------------------------------------------------------------
// Section 8 static dictionary
// ---------------------------------------------------------------------------
// A dictionary reference is a copy whose distance exceeds every real distance --
// the decoder recovers it as `distance - (max_allowed_distance + 1)` -- so it can
// only encode a copy of length 4..24 that some Appendix B transform of some word
// produces exactly.
// Section 8: Ferment, the transform that upper-cases a word; returns how many bytes it
// consumed.  This must match the decoder's `ferment` byte for byte.
int ferment(u8* word, std::size_t word_len, std::size_t pos) {
  if (word[pos] < 192) {
    if (word[pos] >= 97 && word[pos] <= 122) word[pos] = static_cast<u8>(word[pos] ^ 32);
    return 1;
  }
  if (word[pos] < 224) {
    if (pos + 1 < word_len) word[pos + 1] = static_cast<u8>(word[pos + 1] ^ 32);
    return 2;
  }
  if (pos + 2 < word_len) word[pos + 2] = static_cast<u8>(word[pos + 2] ^ 5);
  return 3;
}

// Section 8: prefix + T(word) + suffix.  A transformed word may be empty.  Every
// transform type the RFC defines must be implemented here: the encoder has to know the
// exact length of a transform's output, because that length -- not the copy length -- is
// what advances the decoder's produced count.
std::string apply_transform(const BrotliTransform& t, const char* word, int len) {
  std::string out;
  out.reserve(static_cast<std::size_t>(t.prefix_len) + static_cast<std::size_t>(len) +
              static_cast<std::size_t>(t.suffix_len));
  if (t.prefix_len) out.append(t.prefix, t.prefix_len);
  const std::size_t word_len = static_cast<std::size_t>(len);
  u8 buffer[24];
  if (word_len > 0) std::memcpy(buffer, word, word_len);
  const unsigned type = t.type;
  if (type == 1) {  // FermentFirst
    if (word_len > 0) ferment(buffer, word_len, 0);
    out.append(reinterpret_cast<const char*>(buffer), word_len);
  } else if (type == 2) {  // FermentAll
    std::size_t i = 0;
    while (i < word_len) i += static_cast<std::size_t>(ferment(buffer, word_len, i));
    out.append(reinterpret_cast<const char*>(buffer), word_len);
  } else if (type >= 3 && type <= 11) {  // OmitFirst1..9
    const std::size_t omit = type - 2;
    if (word_len > omit) out.append(reinterpret_cast<const char*>(buffer + omit), word_len - omit);
  } else if (type >= 12) {  // OmitLast1..9
    const std::size_t omit = type - 11;
    if (word_len > omit) out.append(reinterpret_cast<const char*>(buffer), word_len - omit);
  } else {  // Identity
    out.append(reinterpret_cast<const char*>(buffer), word_len);
  }
  if (t.suffix_len) out.append(t.suffix, t.suffix_len);
  return out;
}

struct DictMatch {
  bool found = false;
  int out_len = 0;   // bytes the transform emits, which is how far `produced` moves
  int word_len = 0;  // the dictionary word length: this is the stream's COPY LENGTH
  int word_id = 0;
};

// Base dictionary words indexed by the hash of their own bytes.  `word_id` is
// `transform_id << NDBITS[len] | index`, which is exactly the value the decoder turns
// back into `(index, transform_id)`, so the encoder never has to send either.
class DictionaryIndex {
 public:
  DictionaryIndex() {
    dict_ = brotli_dictionary_data();
    const std::size_t* offsets = brotli_dictionary_offsets();
    const u8* nbits = brotli_dictionary_size_bits();
    ntransforms_ = brotli_transform_count();
    // Every base word is indexed by the hash of its own bytes.  The 121 transforms
    // are resolved lazily at match time: the decoder derives `word_id` from the copy
    // length alone, so whatever `word_id` we send reproduces exactly the transform
    // result we verified here.
    for (int len = 4; len <= 24; ++len) {
      const std::size_t off = offsets[len];
      const u32 count = 1u << nbits[len];
      for (u32 w = 0; w < count; ++w) {
        const char* word = reinterpret_cast<const char*>(dict_) + off + w * static_cast<u32>(len);
        Entry e;
        e.hash = hash8(word, static_cast<std::size_t>(len));
        e.len = static_cast<u8>(len);
        e.offset = static_cast<u32>(off + w * static_cast<u32>(len));
        e.index = w;
        e.len_bits = nbits[len];
        entries_.push_back(e);
      }
    }
    table_.assign(kTableSize, -1);
    for (int i = 0; i < static_cast<int>(entries_.size()); ++i) {
      const u32 slot = entries_[i].hash & kTableMask;
      entries_[i].next = table_[slot];
      table_[slot] = i;
    }
  }

  // The longest dictionary transform matching at `pos`.  The decoder reads the copy
  // length as the DICTIONARY WORD length (4..24) and derives both the word index and
  // the transform from `word_id`, then emits `apply_transform(word, clen, t)` -- whose
  // length may differ from `clen`, so a match carries both numbers.  Candidates come
  // from the hash of the base word's own bytes; each of the 121 transforms is then
  // materialised and compared, and the entry remembers the shift needed for `word_id`.
  DictMatch find(const char* data, std::size_t size, std::size_t pos) const {
    DictMatch best;
    if (size - pos < 4) return best;
    const std::size_t avail = size - pos;
    const u32 h = hash8(data + pos, avail);
    const BrotliTransform* transforms = brotli_transforms();
    for (int i = table_[h & kTableMask]; i >= 0; i = entries_[i].next) {
      const Entry& e = entries_[i];
      if (e.hash != h) continue;
      const char* word = reinterpret_cast<const char*>(dict_) + e.offset;
      for (unsigned t = 0; t < ntransforms_; ++t) {
        const std::string s = apply_transform(transforms[t], word, e.len);
        if (s.size() < 4) continue;
        if (s.size() > avail) continue;
        if (s.size() <= static_cast<std::size_t>(best.out_len)) continue;
        if (std::memcmp(s.data(), data + pos, s.size()) != 0) continue;
        best.found = true;
        best.out_len = static_cast<int>(s.size());
        best.word_len = e.len;
        best.word_id = static_cast<int>((static_cast<u32>(t) << e.len_bits) | e.index);
      }
    }
    return best;
  }

 private:
  struct Entry {
    u32 hash = 0;
    u32 offset = 0;   // byte offset of the base word inside the dictionary data
    u32 index = 0;    // word index inside its length class, for `word_id`
    u8 len = 0;       // base word length, 4..24
    u8 len_bits = 0;  // NDBITS[len], the shift that separates transform from index
    int next = -1;
  };
  static constexpr std::size_t kTableSize = 1u << 16;
  static constexpr std::size_t kTableMask = kTableSize - 1;

  static u32 hash8(const char* p, std::size_t n) {
    const std::size_t k = n < 8 ? n : 8;
    u64 h = 0xcbf29ce484222325ull;
    for (std::size_t i = 0; i < k; ++i) {
      h ^= static_cast<unsigned char>(p[i]);
      h *= 0x100000001b3ull;
    }
    return static_cast<u32>(h ^ (h >> 32));
  }

  std::vector<Entry> entries_;
  std::vector<int> table_;
  const u8* dict_ = nullptr;
  unsigned ntransforms_ = 0;
};

// ---------------------------------------------------------------------------
// Literal and distance contexts (section 7)
// ---------------------------------------------------------------------------

// The three lookup tables come straight from the dictionary header, so the
// encoder's contexts cannot drift from the decoder's.
int literal_context_id(int mode, const char* data, std::size_t pos) {
  const u8* lut = brotli_context_lookup();
  const unsigned p1 = pos >= 1 ? static_cast<unsigned char>(data[pos - 1]) : 0u;
  const unsigned p2 = pos >= 2 ? static_cast<unsigned char>(data[pos - 2]) : 0u;
  switch (mode) {
    case 0:  // LSB6
      return static_cast<int>(p1 & 0x3f);
    case 1:  // MSB6
      return static_cast<int>(p1 >> 2);
    case 2:  // UTF8
      return lut[p1] | lut[256 + p2];
    default:  // Signed
      return (lut[512 + p1] << 3) | lut[512 + p2];
  }
}

int distance_context_id(int copy_len) {
  if (copy_len > 4) return 3;
  return copy_len - 2;  // 2 -> 0, 3 -> 1, 4 -> 2
}

// ---------------------------------------------------------------------------
// Command model (section 5)
// ---------------------------------------------------------------------------
struct InsertCode {
  int len_code = 0;
  int len_extra = 0;
  int extra_bits = 0;
};

struct CopyCode {
  int len_code = 0;
  int len_extra = 0;
  int extra_bits = 0;
};

bool locate_insert(int len, InsertCode* out) {
  if (out == nullptr) return false;
  for (int code = 0; code < 24; ++code) {
    const int base = kInsertBase[code];
    const int extra = kInsertExtra[code];
    // Code 23 really does carry 24 extra bits, so the shift is done in 64 bits and no
    // extra-bit count is special-cased away.
    const long long max_extra = (1ll << extra) - 1;
    if (len >= base && static_cast<long long>(len - base) <= max_extra) {
      out->len_code = code;
      out->len_extra = len - base;
      out->extra_bits = extra;
      return true;
    }
  }
  return false;
}

bool locate_copy(int len, CopyCode* out) {
  if (out == nullptr) return false;
  for (int code = 0; code < 24; ++code) {
    const int base = kCopyBase[code];
    const int extra = kCopyExtra[code];
    const long long max_extra = (1ll << extra) - 1;
    if (len >= base && static_cast<long long>(len - base) <= max_extra) {
      out->len_code = code;
      out->len_extra = len - base;
      out->extra_bits = extra;
      return true;
    }
  }
  return false;
}

// Section 5: the command alphabet is eleven 64-symbol cells, and a cell only covers
// the insert/copy code pairs inside its own range.  The ranges are not aligned blocks
// of eight, so the cell has to be searched rather than computed by division.
//
// Cells 0 and 1 are the implicit-distance cells: the decoder takes the distance from
// the ring buffer without reading any bits.  Every command this encoder writes carries
// an explicit distance, so only cells 2..10 may be used, and those nine cells still
// cover every insert/copy code pair (each of the three insert groups crossed with each
// of the three copy groups), so no legal command is lost.
int command_symbol(int insert_code, int copy_code) {
  for (int cell = 2; cell < 11; ++cell) {
    const int in_cell = insert_code - kInsertRangeLut[cell];
    const int copy_in_cell = copy_code - kCopyRangeLut[cell];
    if (in_cell < 0 || in_cell > 7 || copy_in_cell < 0 || copy_in_cell > 7) continue;
    return cell * 64 + in_cell * 8 + copy_in_cell;
  }
  return -1;
}

// A distance is either one of the 16 short codes (relative to the ring buffer) or
// an explicit code >= 16 carrying extra bits.
struct DistanceCode {
  int dcode = -1;
  int extra = 0;
  int extra_bits = 0;
};

// The decoder at src/brotli.cpp:825-831 inverts an explicit distance code as
//   ndistbits = 1 + ((dcode - 16) >> 1)
//   hcode     = dcode - 16
//   lcode     = (dcode - 16) & ((1 << NPOSTFIX) - 1)
//   offset    = ((2 + (hcode & 1)) << ndistbits) - 4
//   distance  = ((offset + extra) << NPOSTFIX) + lcode + NDIRECT + 1
// With NPOSTFIX = 0 and NDIRECT = 0 the `lcode` term vanishes entirely, so a given
// distance does not determine the code: each of the 48 explicit codes covers one
// interval.  Search the codes instead of inverting the formula.
bool locate_distance(const int dist_rb[4], int distance, DistanceCode* out) {
  if (distance <= 0) return false;
  for (int code = 0; code < 16; ++code) {
    const int d = dist_rb[kDistanceShortCodeIndex[code]] + kDistanceShortCodeDelta[code];
    if (d == distance && d > 0) {
      out->dcode = code;
      out->extra = 0;
      out->extra_bits = 0;
      return true;
    }
  }
  for (int code = 0; code < 48; ++code) {
    const int ndistbits = 1 + (code >> 1);
    const int offset = ((2 + (code & 1)) << ndistbits) - 4;
    const long long extra = static_cast<long long>(distance) - 1 - offset;
    if (extra < 0) continue;
    if (extra >= (1ll << ndistbits)) continue;
    out->dcode = 16 + code;
    out->extra = static_cast<int>(extra);
    out->extra_bits = ndistbits;
    return true;
  }
  return false;
}

// The read side of a distance code, so the encoder can check its own output while
// it encodes instead of trusting the inverse above.
bool read_distance(const int dist_rb[4], int dcode, int extra, int* distance) {
  if (dcode < 16) {
    const int d = dist_rb[kDistanceShortCodeIndex[dcode]] + kDistanceShortCodeDelta[dcode];
    if (d <= 0) return false;
    *distance = d;
    return true;
  }
  const int code = dcode - 16;
  const int ndistbits = 1 + (code >> 1);
  // NPOSTFIX is always 0 here, so the decoder's `lcode` term is always zero and
  // `hcode` is the code itself: the offset bit comes from `code & 1`.
  const int offset = ((2 + (code & 1)) << ndistbits) - 4;
  const int d = offset + extra + 1;
  if (d <= 0) return false;
  *distance = d;
  return true;
}

// ---------------------------------------------------------------------------
// Match finder: hash chains over the input
// ---------------------------------------------------------------------------
constexpr int kHashBits = 17;
constexpr int kMaxChain = 128;
constexpr int kMinMatch = 4;
constexpr int kMaxMatch = 4096;
// The largest distance any explicit distance code can carry at NPOSTFIX = 0 and
// NDIRECT = 0: code 47 packs 24 extra bits on top of offset ((3 << 24) - 4).
constexpr long long kMaxDistance = 67108860LL;

// Match-search effort by quality.  Before this existed, `quality` changed nothing but
// the literal tree cap, so every quality from 5 to 8 produced a byte-identical stream
// and the parse itself never improved.  These are the knobs that actually move size.
struct SearchParams {
  int max_chain = 32;   // hash chain entries examined per position
  int nice_len = 64;    // stop searching once a match this long is found
  int max_match = 512;  // longest copy worth taking
  bool lazy = false;    // try position + 1 before committing to a match
  bool use_dictionary = true;
};

SearchParams search_params(int quality) {
  SearchParams p;
  if (quality <= 0) {
    // Quality 0 is the literal-only stage: the match finder and the dictionary are
    // both switched off, so the stream carries context-modelled literals and nothing
    // else.  This is the "Stage A" (no LZ77) number in the size table.
    p.max_chain = 0;
    p.nice_len = 0;
    p.max_match = 0;
    p.use_dictionary = false;
    p.lazy = false;
    return p;
  }
  p.use_dictionary = quality >= 2;
  p.lazy = quality >= 7;
  if (quality <= 1) {
    p.max_chain = 16;
    p.nice_len = 32;
    p.max_match = 128;
  } else if (quality <= 3) {
    p.max_chain = 32;
    p.nice_len = 64;
    p.max_match = 512;
  } else if (quality <= 5) {
    p.max_chain = 128;
    p.nice_len = 128;
    p.max_match = 4096;
  } else if (quality <= 8) {
    p.max_chain = 512;
    p.nice_len = 256;
    p.max_match = 8192;
  } else {
    p.max_chain = 4096;
    p.nice_len = 1024;
    p.max_match = 65536;
  }
  return p;
}

class MatchFinder {
 public:
  MatchFinder(const char* data, std::size_t size, const SearchParams& params)
      : data_(data), size_(size), params_(params) {
    head_.assign(static_cast<std::size_t>(1) << kHashBits, -1);
    prev_.assign(size + 1, -1);
    next4_.assign(size + 1, 0);
  }

  void insert(std::size_t pos) {
    if (pos + 4 > size_) return;
    if (next4_[pos]) return;
    next4_[pos] = 1;
    const u32 h = hash(pos);
    prev_[pos] = head_[h];
    head_[h] = static_cast<int>(pos);
  }

  // Longest backward match at `pos` among the most recent kMaxChain candidates.
  // Copies may overlap their source (the decoder reproduces them byte by byte from
  // an already-produced prefix), so the comparison runs past `pos`.
  int match(std::size_t pos, int* distance) const {
    *distance = 0;
    if (pos + kMinMatch > size_) return 0;
    int best_len = 0;
    int best_dist = 0;
    int cur = head_[hash(pos)];
    for (int steps = 0; cur >= 0 && steps < params_.max_chain; ++steps) {
      const std::size_t c = static_cast<std::size_t>(cur);
      if (c >= pos) break;
      if (!next4_[c]) break;
      const std::size_t dist = pos - c;
      if (dist > (static_cast<std::size_t>(1) << 22)) break;
      if (best_len == 0 || static_cast<std::size_t>(best_len) <= dist) {
        std::size_t len = 0;
        const std::size_t max_len = static_cast<std::size_t>(params_.max_match);
        while (len < max_len && pos + len < size_ && data_[c + len] == data_[pos + len]) ++len;
        if (static_cast<int>(len) > best_len) {
          best_len = static_cast<int>(len);
          best_dist = static_cast<int>(dist);
          if (best_len >= params_.nice_len) break;
        }
      }
      cur = prev_[c];
    }
    if (best_len < kMinMatch) return 0;
    // A short far-away match costs more bits than the literals it replaces, so skip
    // it rather than pay for a distance that will not repay itself.
    if (best_len == kMinMatch && best_dist > (1 << 14)) return 0;
    *distance = best_dist;
    return best_len;
  }

 private:
  u32 hash(std::size_t pos) const {
    u32 v;
    std::memcpy(&v, data_ + pos, 4);
    return (v * 0x9e3779b1u) >> (32 - kHashBits);
  }

  const char* data_;
  std::size_t size_;
  SearchParams params_;
  std::vector<int> head_;
  std::vector<int> prev_;
  std::vector<u8> next4_;
};

// ---------------------------------------------------------------------------
// Command list
// ---------------------------------------------------------------------------

// A command is some literals plus a copy.  The decoder stops the instant it has
// produced `mlen` bytes, so the copy of the *last* command is never applied and
// may be length 0 -- that is how a meta-block ends on literals.
struct Command {
  std::size_t pos = 0;  // output position of the first literal
  int nliterals = 0;
  int copy_len = 0;     // the stream's copy length: for a dictionary copy this is the
                        // WORD length, not the length of the transform's output
  int out_len = 0;      // bytes this command really produces (== copy_len except for a
                        // dictionary transform with a prefix or a suffix)
  int distance = 0;
  bool word = false;    // distance is a dictionary reference
  int word_id = 0;
  bool is_final = false;
};

struct CommandList {
  std::vector<Command> commands;
  std::size_t total_copy_bytes = 0;
};

// Insert runs are bounded by the length table (6210 + 2^14), and command
// generation never accumulates more than one literal before a match, so a single
// command per run is always enough; a run that somehow does not fit is an error
// rather than a silently wrong stream.
bool append_command(CommandList* list, std::size_t pos, int nliterals, int copy_len, int distance,
                    bool word, int word_id, bool is_final, int out_len = 0) {
  if (nliterals < 0 || copy_len < 0) return false;
  InsertCode ic;
  if (!locate_insert(nliterals, &ic)) return false;
  Command c;
  c.pos = pos;
  c.nliterals = nliterals;
  c.copy_len = copy_len;
  c.out_len = out_len > 0 ? out_len : copy_len;
  c.distance = distance;
  c.word = word;
  c.word_id = word_id;
  c.is_final = is_final;
  list->commands.push_back(c);
  if (c.out_len > 0) list->total_copy_bytes += static_cast<std::size_t>(c.out_len);
  return true;
}

// ---------------------------------------------------------------------------
// Planning: choose context model and tree counts
// ---------------------------------------------------------------------------
struct MetaBlockPlan {
  int context_mode = 0;
  int num_literal_trees = 1;
  int num_command_trees = 1;
  int num_distance_trees = 1;
  std::vector<u8> literal_context_map;   // one entry per literal byte
  std::vector<u8> distance_context_map;  // 4 entries, identity
  std::vector<std::vector<u32>> literal_hist;
  std::vector<u32> command_hist;
  std::vector<std::vector<u32>> distance_hist;
};

// Entropy of a histogram under its own optimal code, plus a rough price for the
// code description.  Used only to pick between models, never to decide validity.
double estimate_bits(const std::vector<u32>& counts) {
  u64 total = 0;
  for (u32 c : counts) total += c;
  if (total == 0) return 0.0;
  double bits = 0.0;
  int present = 0;
  for (u32 c : counts) {
    if (c == 0) continue;
    ++present;
    const double p = static_cast<double>(c) / static_cast<double>(total);
    bits += static_cast<double>(c) * (-std::log2(p));
  }
  if (present > 1) bits += 4.0 * present + 16.0;
  return bits;
}

struct LiteralPlanScore {
  double bits = 0;
  int mode = 0;
  int ntrees = 1;
  std::vector<u8> map;
  std::vector<std::vector<u32>> hist;
  bool ok = false;
};

// Try each context mode, clustering the 64 (or 256) raw contexts into at most
// `cap` trees by descending literal count.  Clustering by frequency rather than by
// context distance keeps this cheap and still captures the useful split, because
// the frequent contexts are the ones a Huffman tree can profitably specialize.
LiteralPlanScore plan_literals(const char* data, const CommandList& list, int cap) {
  LiteralPlanScore best;
  if (cap < 1) cap = 1;
  if (cap > kMaxLiteralTrees) cap = kMaxLiteralTrees;

  std::size_t total_literals = 0;
  for (const Command& c : list.commands) total_literals += static_cast<std::size_t>(c.nliterals);
  if (total_literals == 0) {
    best.ok = true;
    best.ntrees = 1;
    best.hist.assign(1, std::vector<u32>(kLiteralAlphabet, 0));
    return best;
  }

  for (int mode = 0; mode < 4; ++mode) {
    // RFC 7932 section 7.3, line 1416: "The size of the context map is 64 * NBLTYPESL
    // for literals".  That holds for every context mode -- the UTF8 lookup table's
    // second half only contributes 0..3 in the top bits (`lut[p1] | lut[256 + p2]` is
    // a multiple of 4 ORed with 0..3) and the Signed table only contributes 0..7, so
    // both modes also land in 0..63.  Using 256 here wrote a 256-entry context map
    // that the decoder truncated at 64, shifting every following header field.
    const int ctx_count = 64;
    std::vector<u32> ctx_totals(static_cast<std::size_t>(ctx_count), 0);
    for (const Command& c : list.commands) {
      for (int k = 0; k < c.nliterals; ++k) {
        ctx_totals[static_cast<std::size_t>(literal_context_id(mode, data, c.pos + k))]++;
      }
    }
    std::vector<int> order;
    order.reserve(ctx_totals.size());
    for (int i = 0; i < ctx_count; ++i)
      if (ctx_totals[i] > 0) order.push_back(i);
    std::stable_sort(order.begin(), order.end(),
                     [&](int a, int b) { return ctx_totals[a] > ctx_totals[b]; });

    for (int ntrees = 1; ntrees <= cap; ntrees *= 2) {
      std::vector<u8> ctx_to_tree(static_cast<std::size_t>(ctx_count), 0);
      const int n = std::min<int>(ntrees, static_cast<int>(order.size()));
      for (int i = 0; i < n; ++i) ctx_to_tree[order[i]] = static_cast<u8>(i);
      // Contexts outside the chosen trees fold into the last one; 0 is that tree when
      // there is only one, so the map stays within 0..n-1 and no literal is dropped.
      if (n > 1) {
        std::vector<bool> assigned(static_cast<std::size_t>(ctx_count), false);
        for (int i = 0; i < n; ++i) assigned[static_cast<std::size_t>(order[i])] = true;
        for (int i = 0; i < ctx_count; ++i)
          if (!assigned[static_cast<std::size_t>(i)]) ctx_to_tree[i] = static_cast<u8>(n - 1);
      }

      std::vector<std::vector<u32>> hist(static_cast<std::size_t>(n),
                                         std::vector<u32>(kLiteralAlphabet, 0));
      for (const Command& c : list.commands) {
        for (int k = 0; k < c.nliterals; ++k) {
          const int ctx = literal_context_id(mode, data, c.pos + k);
          // `data` is `const char*`, so the byte must be widened as unsigned or any
          // byte >= 0x80 indexes the alphabet at a negative offset.
          const u8 byte = static_cast<u8>(data[c.pos + k]);
          hist[static_cast<std::size_t>(ctx_to_tree[ctx])][byte]++;
        }
      }
      double bits = 0;
      for (const auto& h : hist) bits += estimate_bits(h);
      // The context map is only sent when there is more than one tree, and its real
      // cost grows with the number of distinct values, so charge per tree.
      if (n > 1) bits += 8.0 * static_cast<double>(ctx_count) + 64.0 * n;

      if (!best.ok || bits < best.bits) {
        best.ok = true;
        best.bits = bits;
        best.mode = mode;
        best.ntrees = n;
        best.map = ctx_to_tree;
        best.hist = std::move(hist);
      }
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// Emitting
// ---------------------------------------------------------------------------

// Section 9.2 header, in exactly the order the decoder reads it.
bool write_meta_block_header(BitWriter* w, const MetaBlockPlan& plan, std::size_t mlen,
                             bool is_last, bool is_last_empty, std::string* error) {
  w->bit(is_last ? 1 : 0);
  if (is_last) w->bit(is_last_empty ? 1 : 0);
  write_mlen_bits(w, mlen);
  if (!is_last) w->bit(0);  // ISUNCOMPRESSED
  write_var_len_u8(w, 1);   // NBLTYPESL
  write_var_len_u8(w, 1);   // NBLTYPESI
  write_var_len_u8(w, 1);   // NBLTYPESD
  w->put(0, 2);             // NPOSTFIX
  w->put(0, 4);             // NDIRECT
  w->put(static_cast<u32>(plan.context_mode), 2);
  write_var_len_u8(w, plan.num_literal_trees);
  if (plan.num_literal_trees >= 2) {
    if (!write_context_map(w, plan.literal_context_map, plan.num_literal_trees)) {
      if (error) *error = "brotli_encode: literal context map could not be encoded";
      return false;
    }
  }
  write_var_len_u8(w, plan.num_distance_trees);
  if (plan.num_distance_trees >= 2) {
    if (!write_context_map(w, plan.distance_context_map, plan.num_distance_trees)) {
      if (error) *error = "brotli_encode: distance context map could not be encoded";
      return false;
    }
  }

  for (std::size_t i = 0; i < plan.literal_hist.size(); ++i) {
    PrefixCode code;
    if (!build_prefix_code(w, plan.literal_hist[i], 8, &code)) {
      if (error) {
        std::size_t used = 0;
        for (u32 c : plan.literal_hist[i]) {
          if (c > 0) ++used;
        }
        *error = "brotli_encode: literal tree " + std::to_string(i) + " with " +
                 std::to_string(used) + " symbols could not be encoded";
      }
      return false;
    }
  }
  {
    PrefixCode code;
    if (!build_prefix_code(w, plan.command_hist, 10, &code)) {
      if (error) {
        std::size_t used = 0;
        for (u32 c : plan.command_hist) {
          if (c > 0) ++used;
        }
        *error = "brotli_encode: command tree with " + std::to_string(used) +
                 " symbols could not be encoded";
      }
      return false;
    }
  }
  for (std::size_t i = 0; i < plan.distance_hist.size(); ++i) {
    PrefixCode code;
    if (!build_prefix_code(w, plan.distance_hist[i], 6, &code)) {
      if (error) {
        std::size_t used = 0;
        for (u32 c : plan.distance_hist[i]) {
          if (c > 0) ++used;
        }
        *error = "brotli_encode: distance tree " + std::to_string(i) + " with " +
                 std::to_string(used) + " symbols could not be encoded";
      }
      return false;
    }
  }
  return true;
}

// Emit `mlen` bytes of literal data plus the commands that reference it.  The
// distance ring buffer is rebuilt here exactly as the decoder builds it, and every
// distance is verified by reading it back before it is written, so a mismatch
// aborts instead of producing a stream that decodes differently.
bool write_meta_block_data(BitWriter* w, const char* data, const CommandList& list,
                           const MetaBlockPlan& plan, std::size_t mlen, int window_bits) {
  // The decoder reads a distance past min(window_size, produced) as a dictionary
  // reference, so the encoder has to frame `word_id` relative to that same bound.
  const std::size_t window_size = static_cast<std::size_t>(1) << window_bits;
  std::vector<PrefixCode> lit_codes(plan.literal_hist.size());
  for (std::size_t i = 0; i < plan.literal_hist.size(); ++i) {
    BitWriter tmp;
    if (!build_prefix_code(&tmp, plan.literal_hist[i], 8, &lit_codes[i])) return false;
  }
  PrefixCode cmd_code;
  {
    BitWriter tmp;
    if (!build_prefix_code(&tmp, plan.command_hist, 10, &cmd_code)) return false;
  }
  std::vector<PrefixCode> dist_codes(plan.distance_hist.size());
  for (std::size_t i = 0; i < plan.distance_hist.size(); ++i) {
    BitWriter tmp;
    if (!build_prefix_code(&tmp, plan.distance_hist[i], 6, &dist_codes[i])) return false;
  }

  int dist_rb[4] = {4, 11, 15, 16};
  std::size_t produced = 0;
  for (const Command& c : list.commands) {
    if (produced >= mlen) break;
    // Section 5: the command symbol comes FIRST, then the insert extra bits, then the
    // copy extra bits, and only then the literals.  Emitting the literals first moves
    // every following field, which the decoder reads as a different command.
    const bool final_command = produced + static_cast<std::size_t>(c.nliterals) >= mlen;
    InsertCode ic;
    CopyCode cc;
    if (!locate_insert(c.nliterals, &ic)) return false;
    // When the insert run alone completes the meta-block the decoder breaks before it
    // reads the copy length, so any encodable copy length will do; length 2 is the
    // cheapest one.
    if (!locate_copy(final_command ? 2 : c.copy_len, &cc)) return false;
    const int sym = command_symbol(ic.len_code, cc.len_code);
    if (sym < 0) return false;
    if (!cmd_code.emit(w, sym)) return false;
    w->put(static_cast<u32>(ic.len_extra), ic.extra_bits);
    w->put(static_cast<u32>(cc.len_extra), cc.extra_bits);

    // The literals.
    for (int k = 0; k < c.nliterals; ++k) {
      const std::size_t p = c.pos + static_cast<std::size_t>(k);
      const int ctx = literal_context_id(plan.context_mode, data, p);
      int tree = 0;
      if (!plan.literal_context_map.empty()) {
        if (ctx < 0 || ctx >= static_cast<int>(plan.literal_context_map.size())) return false;
        tree = plan.literal_context_map[static_cast<std::size_t>(ctx)];
      }
      if (tree < 0 || tree >= static_cast<int>(lit_codes.size())) return false;
      if (!lit_codes[static_cast<std::size_t>(tree)].emit(w, static_cast<u8>(data[p]))) return false;
    }
    produced += static_cast<std::size_t>(c.nliterals);
    if (produced >= mlen) break;

    // Distance.
    if (c.word) {
      if (c.word_id < 0) return false;
      const std::size_t max_distance = produced < window_size ? produced : window_size;
      const long long distance =
          static_cast<long long>(max_distance) + 1 + static_cast<long long>(c.word_id);
      DistanceCode dc;
      int rb_copy[4] = {dist_rb[0], dist_rb[1], dist_rb[2], dist_rb[3]};
      if (distance > kMaxDistance) return false;  // past the largest distance a code can carry
      if (!locate_distance(rb_copy, static_cast<int>(distance), &dc)) return false;
      int check = 0;
      if (!read_distance(rb_copy, dc.dcode, dc.extra, &check)) return false;
      if (static_cast<long long>(check) != distance) return false;
      const int ctx = distance_context_id(c.copy_len);
      int tree = 0;
      if (plan.num_distance_trees >= 2) {
        if (ctx >= static_cast<int>(plan.distance_context_map.size())) return false;
        tree = plan.distance_context_map[static_cast<std::size_t>(ctx)];
      }
      if (tree < 0 || tree >= static_cast<int>(dist_codes.size())) return false;
      if (!dist_codes[static_cast<std::size_t>(tree)].emit(w, dc.dcode)) return false;
      w->put(static_cast<u32>(dc.extra), dc.extra_bits);
    } else {
      DistanceCode dc;
      if (!locate_distance(dist_rb, c.distance, &dc)) return false;
      int check = 0;
      if (!read_distance(dist_rb, dc.dcode, dc.extra, &check)) return false;
      if (check != c.distance) return false;
      const int ctx = distance_context_id(c.copy_len);
      int tree = 0;
      if (plan.num_distance_trees >= 2) {
        if (ctx >= static_cast<int>(plan.distance_context_map.size())) return false;
        tree = plan.distance_context_map[static_cast<std::size_t>(ctx)];
      }
      if (tree < 0 || tree >= static_cast<int>(dist_codes.size())) return false;
      if (!dist_codes[static_cast<std::size_t>(tree)].emit(w, dc.dcode)) return false;
      w->put(static_cast<u32>(dc.extra), dc.extra_bits);
      if (dc.dcode != 0) {
        dist_rb[3] = dist_rb[2];
        dist_rb[2] = dist_rb[1];
        dist_rb[1] = dist_rb[0];
        dist_rb[0] = c.distance;
      }
    }
    produced += static_cast<std::size_t>(c.out_len);
  }
  return produced == mlen;
}

// Build the plan, then write the header and the data from it.
bool compress_meta_block(const char* data, const CommandList& list, std::size_t mlen, int quality,
                         int window_bits, BitWriter* w, std::string* error) {
  const int cap = kTreeCaps[std::min(11, std::max(0, quality))];
  LiteralPlanScore lits = plan_literals(data, list, cap);
  if (!lits.ok) {
    if (error) *error = "brotli_encode: could not model literal contexts";
    return false;
  }

  MetaBlockPlan plan;
  plan.context_mode = lits.mode;
  plan.num_literal_trees = lits.ntrees;
  plan.literal_context_map = lits.map;
  plan.literal_hist = lits.hist;

  // Commands.
  std::vector<u32> cmd_hist(kCommandAlphabet, 0);
  for (const Command& c : list.commands) {
    InsertCode ic;
    CopyCode cc;
    const int copy_len = c.is_final ? 2 : c.copy_len;
    if (!locate_insert(c.nliterals, &ic)) {
      if (error) *error = "brotli_encode: insert length " + std::to_string(c.nliterals) +
                          " is not encodable";
      return false;
    }
    if (!locate_copy(copy_len, &cc)) {
      if (error) {
        *error = "brotli_encode: copy length " + std::to_string(copy_len) + " is not encodable";
      }
      return false;
    }
    const int sym = command_symbol(ic.len_code, cc.len_code);
    if (sym < 0) {
      if (error) {
        *error = "brotli_encode: command (" + std::to_string(ic.len_code) + "," +
                 std::to_string(cc.len_code) + ") is outside the command alphabet";
      }
      return false;
    }
    cmd_hist[static_cast<std::size_t>(sym)]++;
  }
  plan.command_hist = cmd_hist;
  plan.num_command_trees = 1;

  // Distances, using the same ring-buffer walk the writer will perform.  The events
  // are collected first because the tree count is chosen afterwards: RFC 7932 section
  // 7.3 fixes the distance context map at 4 entries, so up to four trees are legal
  // without any block splitting.
  plan.distance_hist.clear();
  plan.num_distance_trees = 1;
  plan.distance_context_map.assign(4, 0);
  {
    const std::size_t window_size = static_cast<std::size_t>(1) << window_bits;
    int dist_rb[4] = {4, 11, 15, 16};
    std::size_t produced = 0;
    std::vector<std::pair<int, int>> events;  // (distance context, distance code)
    for (const Command& c : list.commands) {
      produced += static_cast<std::size_t>(c.nliterals);
      if (produced >= mlen) break;  // the decoder reads no distance for this command
      DistanceCode dc;
      if (c.word) {
        const std::size_t max_distance = produced < window_size ? produced : window_size;
        const long long distance =
            static_cast<long long>(max_distance) + 1 + static_cast<long long>(c.word_id);
        if (!locate_distance(dist_rb, static_cast<int>(distance), &dc)) {
          if (error) {
            *error = "brotli_encode: dictionary distance " + std::to_string(distance) +
                     " is not encodable";
          }
          return false;
        }
        // A dictionary reference may legally use a SHORT distance code: the short codes
        // are only another spelling of a number, and the decoder classifies the result as
        // a dictionary reference purely because it exceeds min(window_size, produced).
        // The writer emits `dc.dcode` verbatim, so the histogram must count that same
        // symbol.  Rewriting it to 16 (an earlier, wrong idea) left the emitted symbol
        // with a zero-length code, so `emit` wrote no bits and the decoder read whatever
        // followed as the distance -- observed as `dist=14069` on `_br/v_html.bin`.
      } else {
        if (!locate_distance(dist_rb, c.distance, &dc)) {
          if (error) {
            *error = "brotli_encode: distance " + std::to_string(c.distance) +
                     " is not encodable";
          }
          return false;
        }
        if (dc.dcode != 0) {
          dist_rb[3] = dist_rb[2];
          dist_rb[2] = dist_rb[1];
          dist_rb[1] = dist_rb[0];
          dist_rb[0] = c.distance;
        }
      }
      events.push_back({distance_context_id(c.copy_len), dc.dcode});
      produced += static_cast<std::size_t>(c.out_len);
    }

    // Try every legal tree count and keep the cheapest, charging the context map its
    // real 4 entries plus a per-tree header allowance.
    double best_bits = 0;
    for (int n = 1; n <= kMaxDistanceTrees; ++n) {
      std::vector<std::vector<u32>> hist(static_cast<std::size_t>(n),
                                         std::vector<u32>(kDistanceAlphabet, 0));
      std::vector<u8> map(4, 0);
      for (int ctx = 0; ctx < 4; ++ctx) {
        map[static_cast<std::size_t>(ctx)] = static_cast<u8>(ctx * n / 4);
      }
      for (const auto& e : events) {
        hist[static_cast<std::size_t>(map[static_cast<std::size_t>(e.first)])]
            [static_cast<std::size_t>(e.second)]++;
      }
      double bits = 0;
      for (const auto& h : hist) bits += estimate_bits(h);
      if (n > 1) bits += 8.0 * 4.0 + 64.0 * static_cast<double>(n);
      if (n == 1 || bits < best_bits) {
        best_bits = bits;
        plan.distance_hist = std::move(hist);
        plan.num_distance_trees = n;
        plan.distance_context_map = std::move(map);
      }
    }
  }

  if (!write_meta_block_header(w, plan, mlen, false, false, error)) return false;
  if (!write_meta_block_data(w, data, list, plan, mlen, window_bits)) {
    if (error) *error = "brotli_encode: command stream failed self-verification";
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Command generation
// ---------------------------------------------------------------------------

// A dictionary copy must be longer than the best backward match to be preferred,
// and its distance has to exceed every distance already used.
bool generate_commands(const char* data, std::size_t len, int quality,
                       const DictionaryIndex& dict, CommandList* list, std::string* error) {
  const SearchParams params = search_params(quality);
  MatchFinder finder(data, len, params);
  std::size_t pos = 0;
  std::size_t last_literal = 0;
  while (pos < len) {
    int distance = 0;
    // Quality 0 disables the match finder entirely (see search_params), which makes
    // this a pure literal run.
    int best_len = params.max_match >= kMinMatch ? finder.match(pos, &distance) : 0;
    bool best_word = false;
    int best_word_id = 0;
    int best_word_len = 0;
    const DictMatch dm = params.use_dictionary ? dict.find(data, len, pos) : DictMatch();
    if (dm.found && dm.out_len > best_len) {
      best_len = dm.out_len;
      best_word = true;
      best_word_id = dm.word_id;
      best_word_len = dm.word_len;
      distance = 0;
    }
    if (best_len < kMinMatch) {
      finder.insert(pos);
      ++pos;
      continue;
    }
    // Lazy matching: a match starting one byte later that is strictly longer is worth
    // the single literal it costs to get there.  A full optimal parse would iterate
    // this; one step captures much of the gain for a fraction of the work.
    if (params.lazy && best_len < params.nice_len && pos + 1 < len) {
      int next_distance = 0;
      const int next_len = finder.match(pos + 1, &next_distance);
      if (next_len > best_len) {
        finder.insert(pos);
        ++pos;
        continue;
      }
    }
    // The hash chain stops at the end of the buffer
    // copy to the bytes that are actually left, then to the longest copy the length
    // alphabet can carry.  A dictionary match is already bounded by the remaining input
    // and its copy length is the WORD length, so it must not be clamped: shrinking it
    // would change which transform `word_id` names.
    int copy_len = best_len;
    if (!best_word) {
      if (best_len > static_cast<int>(len - pos)) best_len = static_cast<int>(len - pos);
      if (best_len > params.max_match) best_len = params.max_match;
      if (best_len < kMinMatch) {
        finder.insert(pos);
        ++pos;
        continue;
      }
      copy_len = best_len;
    } else {
      copy_len = best_word_len;
    }

    const int nliterals = static_cast<int>(pos - last_literal);
    // A match that runs to the end of the input is an ordinary command: the decoder
    // stops as soon as the produced count reaches the meta-block length, so the last
    // copy needs no special form.  Only the trailing literal run (appended after the
    // loop) is special, because the decoder reads neither a copy length nor a
    // distance for the command whose literals alone complete the block.
    if (!append_command(list, last_literal, nliterals, copy_len, best_word ? 0 : distance,
                        best_word, best_word_id, false, best_len)) {
      if (error) *error = "brotli_encode: insert run too long to encode";
      return false;
    }
    for (int k = 0; k < best_len; ++k) finder.insert(pos + static_cast<std::size_t>(k));
    pos += static_cast<std::size_t>(best_len);
    last_literal = pos;
  }
  if (last_literal < len) {
    const int nliterals = static_cast<int>(len - last_literal);
    if (!append_command(list, last_literal, nliterals, 0, 0, false, 0, true)) {
      if (error) *error = "brotli_encode: trailing literal run too long";
      return false;
    }
  }
  if (list->commands.empty()) {
    if (error) *error = "brotli_encode: no commands for a non-empty input";
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Whole-stream assembly
// ---------------------------------------------------------------------------

// The window size, section 9.1.  Bit 0 means the small window (16); otherwise a
// 3-bit code follows: 1..7 mean 18..24, and 0 needs one more 3-bit field where 0
// means 17 and 1 is invalid.
bool write_window_bits(BitWriter* w, int wbits, std::string* error) {
  if (wbits == 16) {
    w->bit(0);
    return true;
  }
  if (wbits >= 10 && wbits <= 15) {
    // 9.1: `1`, then three zero bits, then 8 + m with m in 2..7 gives windows
    // 10..15.  m == 1 is illegal and m == 0 means 17.  Leaving this form out made
    // every window below 16 unwritable even though the API documents 10..24.
    w->bit(1);
    w->put(0, 3);
    w->put(static_cast<u32>(wbits - 8), 3);
    return true;
  }
  if (wbits >= 18 && wbits <= 24) {
    w->bit(1);
    w->put(static_cast<u32>(wbits - 17), 3);
    return true;
  }
  if (wbits == 17) {
    w->bit(1);
    w->put(0, 3);
    w->put(0, 3);
    return true;
  }
  if (error) *error = "brotli_encode: window_bits must be 10..24";
  return false;
}

// An empty meta-block is 10 bits: ISLAST=1, ISLASTEMPTY=1, MNIBBLES=3 (the 11
// pattern).  Encoded at a bit offset this lands wherever the previous block ended.
void write_empty_last_block(BitWriter* w) {
  // 9.2: ISLASTEMPTY = 1 makes the meta-block empty AND last, and the rest of the
  // header is skipped -- the decoder reads these two bits and nothing else.  Writing
  // anything after them leaves non-zero bits the decoder then rejects with "the unused
  // bits after the last meta-block are not zero".
  w->bit(1);  // ISLAST
  w->bit(1);  // ISLASTEMPTY
}

// Encode `data` as one non-final compressed meta-block.  The body is returned as
// bytes plus its exact bit length, because meta-blocks are not byte aligned against
// each other and the caller has to splice it into the stream bit by bit.
bool encode_body(const char* data, std::size_t len, int quality, int window_bits,
                 std::string* body, std::size_t* body_bits, std::string* error) {
  DictionaryIndex dict;
  CommandList list;
  if (!generate_commands(data, len, quality, dict, &list, error)) return false;
  BitWriter w;
  if (!compress_meta_block(data, list, len, quality, window_bits, &w, error)) return false;
  *body_bits = w.bit_size();
  *body = w.take();
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Self-check
// ---------------------------------------------------------------------------

bool brotli_encode_selfcheck(std::string* report) {
  std::string log;
  int checks = 0;
  int failures = 0;

  const auto note = [&](const std::string& line) { log += line + "\n"; };
  const auto fail = [&](const std::string& line) {
    ++failures;
    note("FAIL: " + line);
  };

  // 1. The prefix code writer against the RFC's own worked example (section 3.2):
  //    lengths 3,3,3,3,3,2,4,4 over A..H must give A=010 B=011 C=100 D=101 E=110
  //    F=00 G=1110 H=1111.
  {
    ++checks;
    const std::vector<u8> lengths = {3, 3, 3, 3, 3, 2, 4, 4};
    std::vector<u16> codes;
    canonical_codes(lengths, &codes);
    const u16 expected[8] = {0x2, 0x3, 0x4, 0x5, 0x6, 0x0, 0xe, 0xf};
    bool ok = true;
    for (int i = 0; i < 8; ++i)
      if (codes[static_cast<std::size_t>(i)] != expected[i]) ok = false;
    if (!ok) {
      fail("canonical code assignment disagrees with RFC 7932 section 3.2");
    } else {
      note("canonical_codes: RFC 3.2 example reproduced");
    }
  }

  // 2. Round-trip a spread of inputs through the whole encoder and the decoder.
  std::vector<std::string> corpus;
  corpus.emplace_back();
  corpus.emplace_back("a");
  corpus.emplace_back("hello, brotli");
  std::string zeros(70000, '\0');
  corpus.push_back(zeros);
  std::string repeated;
  for (int i = 0; i < 4000; ++i) repeated += "the quick brown fox jumps over the lazy dog. ";
  corpus.push_back(repeated);
  std::string ramp;
  for (int i = 0; i < 5000; ++i) ramp.push_back(static_cast<char>((i * 7 + (i >> 3)) & 0xff));
  corpus.push_back(ramp);
  std::string randomish;
  {
    u64 state = 0x243f6a8885a308d3ull;
    while (randomish.size() < 40000) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      randomish.push_back(static_cast<char>(state >> 24));
    }
  }
  corpus.push_back(randomish);
  std::string html;
  for (int i = 0; i < 600; ++i) {
    html += "<div class=\"row\" id=\"r" + std::to_string(i) +
            "\"><a href=\"/item/" + std::to_string(i) + "\">Item " + std::to_string(i) +
            "</a></div>\n";
  }
  corpus.push_back(html);

  for (std::size_t ci = 0; ci < corpus.size(); ++ci) {
    const std::string& in = corpus[ci];
    for (int quality : {1, 5, 11}) {
      BrotliEncoderOptions options;
      options.quality = quality;
      std::string out;
      std::string error;
      if (!brotli_encode(in, &out, &error, options)) {
        fail("encode failed for vector " + std::to_string(ci) + " at quality " +
             std::to_string(quality) + ": " + error);
        continue;
      }
      if (out.size() > brotli_encode_bound(in.size())) {
        fail("brotli_encode_bound(" + std::to_string(in.size()) + ") = " +
             std::to_string(brotli_encode_bound(in.size())) + " is below the produced " +
             std::to_string(out.size()) + " bytes");
      }
      std::string decoded;
      std::string derror;
      if (!brotli_decompress(reinterpret_cast<const u8*>(out.data()), out.size(), &decoded,
                             &derror)) {
        fail("decode failed for vector " + std::to_string(ci) + " at quality " +
             std::to_string(quality) + ": " + derror);
        continue;
      }
      if (decoded != in) {
        fail("round-trip mismatch for vector " + std::to_string(ci) + " at quality " +
             std::to_string(quality) + " (" + std::to_string(in.size()) + " -> " +
             std::to_string(out.size()) + " -> " + std::to_string(decoded.size()) + ")");
        continue;
      }
      ++checks;
    }
  }
  note("round-trip: " + std::to_string(corpus.size()) + " vectors x 3 qualities");

  // 3. window_bits must be honoured, because the header selects the window the
  //    decoder is allowed to use.
  for (int wbits : {10, 16, 17, 18, 22, 24}) {
    ++checks;
    const std::string& in = repeated;
    BrotliEncoderOptions options;
    options.window_bits = wbits;
    options.quality = 5;
    std::string out;
    std::string error;
    if (!brotli_encode(in, &out, &error, options)) {
      fail("encode failed with window_bits " + std::to_string(wbits) + ": " + error);
      continue;
    }
    std::string decoded;
    std::string derror;
    if (!brotli_decompress(reinterpret_cast<const u8*>(out.data()), out.size(), &decoded,
                           &derror) ||
        decoded != in) {
      fail("round-trip failed with window_bits " + std::to_string(wbits) + ": " + derror);
    }
  }
  note("window_bits: 10, 16, 17, 18, 22, 24 all round-trip");

  // 4. `limit` is a hard ceiling and `target_size` is exact.
  {
    const std::string& in = repeated;
    BrotliEncoderOptions options;
    options.quality = 5;
    std::string out;
    std::string error;
    if (!brotli_encode(in, &out, &error, options)) {
      fail("baseline encode failed: " + error);
    } else {
      ++checks;
      BrotliEncoderOptions tight = options;
      tight.limit = out.size() - 1;
      std::string limited;
      std::string lerror;
      if (brotli_encode(in, &limited, &lerror, tight)) {
        fail("limit " + std::to_string(tight.limit) + " was not enforced");
      } else if (lerror.find(std::to_string(out.size())) == std::string::npos) {
        fail("limit error does not mention the size: " + lerror);
      }
      ++checks;
      BrotliEncoderOptions exact = options;
      exact.limit = out.size();
      std::string allowed;
      std::string aerror;
      if (!brotli_encode(in, &allowed, &aerror, exact)) {
        fail("limit equal to the size was rejected: " + aerror);
      }

      for (std::size_t extra : {std::size_t(0), std::size_t(5), std::size_t(6),
                                std::size_t(100)}) {
        ++checks;
        BrotliEncoderOptions target = options;
        target.target_size = out.size() + extra;
        std::string padded;
        std::string terror;
        if (!brotli_encode(in, &padded, &terror, target)) {
          fail("target " + std::to_string(target.target_size) + " failed: " + terror);
          continue;
        }
        if (padded.size() != target.target_size) {
          fail("target " + std::to_string(target.target_size) + " produced " +
               std::to_string(padded.size()) + " bytes");
          continue;
        }
        std::string decoded;
        std::string derror;
        if (!brotli_decompress(reinterpret_cast<const u8*>(padded.data()), padded.size(), &decoded,
                               &derror) ||
            decoded != in) {
          fail("padded stream at target " + std::to_string(target.target_size) +
               " did not round-trip: " + derror);
        }
      }
    }
  }
  note("limit and target_size behaviour checked");

  if (report) {
    *report = log;
    *report += failures == 0 ? "brotli_encode_selfcheck: OK (" + std::to_string(checks) +
                                   " checks)\n"
                             : "brotli_encode_selfcheck: " + std::to_string(failures) +
                                   " FAILURE(S)\n";
  }
  return failures == 0;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// A stored stream is `len` raw bytes plus a header per 64 KiB chunk, and it is
// always available, so it is the honest worst case.  `+ 2` covers the final empty
// meta-block and the byte the window header can occupy.
std::size_t brotli_encode_bound(std::size_t len) {
  const std::size_t chunks = (len + 65535) / 65536;
  return len + 4 * chunks + 2;
}

namespace {

// RFC 9.1: the window-size header costs 1 bit for 16, 4 bits for 18..24 and 7 for 17.
int window_header_bits(int wbits) {
  if (wbits == 16) return 1;                                 // `0`
  if (wbits >= 10 && wbits <= 15) return 7;                   // `1` + `000` + m
  if (wbits == 17) return 7;                                  // `1` + `000` + `000`
  return 4;                                                   // `1` + 3-bit n
}

// A metadata meta-block used purely as padding.  MSKIPBYTES == 0 means a zero-length
// payload (RFC 9.2), and the length field may not carry a redundant leading zero
// byte, which is why the MSKIPBYTES = 2 and 3 forms are not used here.
//
// The header starts at the CURRENT bit position: the decoder reads ISLAST, MNIBBLES,
// the reserved bit and MSKIPBYTES back to back with whatever preceded them.  An
// align() here emits fill bits that the decoder reads as this block's own header
// (observed as "the stream ends inside the code length code of a literal prefix
// code"), and the decoder's own reference writer put_empty_metadata_meta_block has
// no leading align either.  Only the fill bits AFTER MSKIPLEN-1 belong to the format.
void write_metadata_block(BitWriter* w, int mskipbytes, std::size_t payload_len) {
  if (mskipbytes < 0) mskipbytes = 0;
  if (mskipbytes > 4) mskipbytes = 4;
  if (mskipbytes == 0) payload_len = 0;
  // The length field holds MSKIPLEN - 1, so a zero-length payload cannot be written
  // with a length field at all: it would underflow and the decoder would then treat
  // the closing block as payload.  MSKIPBYTES == 0 is the only empty form.
  if (payload_len == 0) mskipbytes = 0;
  w->bit(0);     // ISLAST: padding is never the last meta-block
  w->put(3, 2);  // MNIBBLES == 3 selects the metadata form
  w->bit(0);     // reserved, section 9.2 requires zero
  w->put(static_cast<u32>(mskipbytes), 2);
  const std::size_t v = payload_len == 0 ? 0 : payload_len - 1;
  for (int i = 0; i < mskipbytes; ++i) {
    w->put(static_cast<u32>((v >> (8 * i)) & 0xff), 8);
  }
  w->align();
  for (std::size_t i = 0; i < payload_len; ++i) w->put(0, 8);
}

// The stored form as a BODY, without its closing block, so that metadata padding can
// follow it exactly as it follows the compressed body.  `brotli_compress_stored`
// writes a complete stream whose last meta-block is ISLAST, so nothing can be appended
// to it; for incompressible input the stored form is the smaller base, and this is what
// lets target_size reach the sizes above it.
//
// `window_bits` is needed because an uncompressed meta-block's payload begins at the
// next byte boundary OF THE STREAM, not of this body: the body is spliced after the
// window header, so a header that ends mid-byte here can already be byte aligned there.
// Aligning against the body's own origin instead inserted four stray zero bits, and the
// decoder then read the payload four bits early.
bool stored_body(const u8* data, std::size_t len, int window_bits, std::string* body,
                 std::size_t* bits, std::string* error) {
  const int head = window_header_bits(window_bits);
  if (len == 0) return false;
  BitWriter w;
  std::size_t pos = 0;
  while (pos < len) {
    const std::size_t chunk =
        std::min<std::size_t>(len - pos, static_cast<std::size_t>(1) << 16);
    w.bit(0);     // ISLAST: padding and the closing block follow this body
    w.put(0, 2);  // MNIBBLES == 4, a 16-bit MLEN
    w.put(static_cast<u32>(chunk - 1), 16);
    w.bit(1);     // ISUNCOMPRESSED
    // Fill to the byte boundary of the STREAM: `head` bits of window header precede
    // this body.  append_bytes is then safe because the writer is byte aligned.
    const std::size_t used = (static_cast<std::size_t>(head) + w.bit_size()) & 7u;
    if (used != 0) w.put(0, static_cast<int>(8 - used));
    w.append_bytes(reinterpret_cast<const char*>(data) + pos, chunk);
    pos += chunk;
  }
  *bits = w.bit_size();
  *body = w.take();
  if (error) error->clear();
  return true;
}

// Assemble `window header + body + padding + closing block` as ONE bit stream.  The
// body arrives as its own byte-aligned writer, so its bits are spliced in; aligning
// between the two would leave fill bits that the decoder reads as the next
// meta-block's header, because meta-blocks are not byte aligned against each other.
bool finish_stream(const std::string& body, std::size_t body_bits,
                   const std::vector<std::pair<int, std::size_t>>& padding, int window_bits,
                   std::string* out, std::string* error) {
  BitWriter w;
  if (!write_window_bits(&w, window_bits, error)) return false;
  w.append_bits(body, body_bits);
  for (const auto& p : padding) write_metadata_block(&w, p.first, p.second);
  write_empty_last_block(&w);
  *out = w.take();
  return true;
}

// Reach `target` bytes exactly, by measuring instead of predicting.  A metadata
// payload is byte granular and every payload byte adds exactly one byte to the stream,
// so one build plus the measured difference lands on the target; only the width of the
// length field has to be guessed.  0..2 leading empty blocks are tried as well, since a
// 6-bit header shifts the byte boundary and so reaches sizes one block cannot.
bool finish_exact(const std::string& body, std::size_t body_bits, int window_bits,
                  std::size_t target, std::string* out, std::string* error) {
  for (int empty = 0; empty <= 2; ++empty) {
    for (int k = 1; k <= 4; ++k) {
      // The length field holds MSKIPLEN - 1, and the decoder rejects a redundant
      // leading zero byte, so a k-byte field carries a payload of
      // 2^(8(k-1)) + 1 .. 2^(8k) bytes.
      const std::size_t lo =
          k == 1 ? 1 : (static_cast<std::size_t>(1) << (8 * (k - 1))) + 1;
      const std::size_t hi = k == 4 ? (static_cast<std::size_t>(1) << 32)
                                    : (static_cast<std::size_t>(1) << (8 * k));
      if (target < lo) continue;
      std::size_t payload = target < hi ? target : hi;
      for (int iter = 0; iter < 3; ++iter) {
        std::vector<std::pair<int, std::size_t>> plan(static_cast<std::size_t>(empty),
                                                      {0, 0});
        plan.push_back({k, payload});
        std::string result;
        if (!finish_stream(body, body_bits, plan, window_bits, &result, error)) return false;
        if (result.size() == target) {
          *out = std::move(result);
          return true;
        }
        const long long delta =
            static_cast<long long>(target) - static_cast<long long>(result.size());
        const long long next = static_cast<long long>(payload) + delta;
        if (next < static_cast<long long>(lo) || next > static_cast<long long>(hi)) break;
        payload = static_cast<std::size_t>(next);
      }
    }
    // The zero-length form is the only padding a single byte of output can need.
    std::vector<std::pair<int, std::size_t>> zeros(static_cast<std::size_t>(empty) + 1,
                                                   {0, 0});
    std::string result;
    if (!finish_stream(body, body_bits, zeros, window_bits, &result, error)) return false;
    if (result.size() == target) {
      *out = std::move(result);
      return true;
    }
  }
  return false;
}

}  // namespace

bool brotli_encode(const u8* data, std::size_t len, std::string* out, std::string* error,
                   const BrotliEncoderOptions& options) {
  if (out) out->clear();
  if (error) error->clear();

  const int quality = std::min(11, std::max(0, options.quality));
  if (len > 0 && data == nullptr) {
    if (error) *error = "brotli_encode: null input";
    return false;
  }
  if (options.window_bits < 10 || options.window_bits > 24) {
    if (error) *error = "brotli_encode: window_bits must be 10..24";
    return false;
  }
  if (len > kMaxMlen) {
    if (error) {
      *error = "brotli_encode: input of " + std::to_string(len) +
               " bytes exceeds one meta-block (16777215)";
    }
    return false;
  }

  const char* src = reinterpret_cast<const char*>(data);
  std::string body;
  std::size_t body_bits = 0;
  std::string encode_error;
  const bool compressed =
      len == 0 ||
      encode_body(src, len, quality, options.window_bits, &body, &body_bits, &encode_error);

  std::string natural;
  if (compressed) {
    const std::vector<std::pair<int, std::size_t>> none;
    if (!finish_stream(body, body_bits, none, options.window_bits, &natural, error)) return false;
  }

  std::string stored;
  if (options.allow_stored_fallback) {
    std::string stored_error;
    if (!brotli_compress_stored(data, len, &stored, &stored_error)) stored.clear();
  }

  // Without an exact length, emit the smaller of the two complete streams.  An empty
  // input has no stored form and needs none: the empty last meta-block is the stream.
  if (options.target_size == 0) {
    std::string result;
    if (compressed && (stored.empty() || natural.size() <= stored.size())) {
      result = std::move(natural);
    } else if (!stored.empty()) {
      result = std::move(stored);
    } else if (compressed) {
      result = std::move(natural);
    } else {
      if (error) {
        *error = encode_error.empty() ? std::string("brotli_encode: compression failed")
                                      : encode_error;
      }
      return false;
    }
    if (options.limit != 0 && result.size() > options.limit) {
      if (error) {
        *error = "brotli_encode: " + std::to_string(result.size()) + " bytes exceeds limit " +
                 std::to_string(options.limit);
      }
      return false;
    }
    *out = std::move(result);
    return true;
  }

  // `target_size`: reach the exact count.  Both the compressed body and the stored body
  // can be followed by a metadata padding block and the closing block, and the two bases
  // reach different ranges (for incompressible input the stored body is the smaller one),
  // so both are tried before giving up.  `finish_exact` measures, so it reports only
  // the sizes a given base genuinely cannot hit.
  const std::size_t target = options.target_size;
  if (compressed && target == natural.size()) {
    *out = std::move(natural);
    return true;
  }
  if (!stored.empty() && target == stored.size()) {
    *out = std::move(stored);
    return true;
  }
  {
    std::string stored_bytes;
    std::size_t stored_bits = 0;
    // Honour allow_stored_fallback here too: a caller that forbids the stored form must
    // not get one just because an exact target was requested.
    const bool have_stored = options.allow_stored_fallback &&
                             stored_body(data, len, options.window_bits, &stored_bytes,
                                         &stored_bits, nullptr);
    struct Base {
      const std::string* bytes;
      std::size_t bits;
    };
    Base bases[2];
    int base_count = 0;
    if (compressed) bases[base_count++] = Base{&body, body_bits};
    if (have_stored) bases[base_count++] = Base{&stored_bytes, stored_bits};
    for (int i = 0; i < base_count; ++i) {
      std::string result;
      if (finish_exact(*bases[i].bytes, bases[i].bits, options.window_bits, target, &result,
                       error)) {
        *out = std::move(result);
        return true;
      }
    }
  }
  if (error) {
    *error = "brotli_encode: cannot reach target " + std::to_string(target) +
             " exactly (the compressed stream is " +
             std::to_string(compressed ? natural.size() : 0) + " bytes and the stored form is " +
             (stored.empty() ? std::string("unavailable") : std::to_string(stored.size())) + ")";
  }
  return false;
}

bool brotli_encode(const std::string& in, std::string* out, std::string* error,
                   const BrotliEncoderOptions& options) {
  return brotli_encode(reinterpret_cast<const u8*>(in.data()), in.size(), out, error, options);
}

}  // namespace netcap

