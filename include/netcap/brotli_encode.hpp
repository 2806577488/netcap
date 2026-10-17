#pragma once
// Brotli (RFC 7932) encoder.
//
// The decoder in `brotli.hpp` says what a stream means; this is the inverse:
// it takes bytes and produces a stream our own decoder -- and libbrotli -- reads
// back byte for byte.  It is written from RFC 7932 like the decoder is, so the
// project still ships no third-party code.
//
// Two things make this more than a toy.  The first is that a `br` response can
// only be rewritten in place when the replacement body is the *same length*, so
// the encoder has to be able to hit an exact byte count (`target_size`) or prove
// it cannot (`limit`).  The second is that a wrong stream is worse than no
// stream, so every failure path returns false and leaves `*out` empty rather
// than emitting something a decoder might accept as different bytes.
#include <cstddef>
#include <string>

#include "netcap/common.hpp"

namespace netcap {

struct BrotliEncoderOptions {
  int quality = 5;                     // 0..11, the reference scale; 5 is the target
  int window_bits = 22;                // 10..24, must cover the whole input
  bool allow_stored_fallback = true;   // emit a stored stream when it is smaller
  std::size_t limit = 0;               // 0 = none; else fail instead of exceeding it
  std::size_t target_size = 0;         // 0 = none; else the exact byte count to produce
};

// Worst case for `len` bytes of input: a stored stream, whose length is known
// exactly, plus the one byte a longer window header can add.  Never smaller than
// what `brotli_encode` can return for that input.
std::size_t brotli_encode_bound(std::size_t len);

bool brotli_encode(const u8* data, std::size_t len, std::string* out, std::string* error,
                   const BrotliEncoderOptions& options = {});
bool brotli_encode(const std::string& in, std::string* out, std::string* error,
                   const BrotliEncoderOptions& options = {});

// Round-trips the encoder against the decoder over a fixed corpus (empty input,
// one byte, text, zeros, random bytes, a body across the window edge) and checks
// the invariants of `limit`, `target_size` and `brotli_encode_bound`.
bool brotli_encode_selfcheck(std::string* report);

}  // namespace netcap
