#pragma once
// Brotli (RFC 7932): the decoder, plus the "stored" writer.
//
// This header is the *reading* side: every response we touch over TCP goes back
// out as `identity` after the rewrite (the gzip path has worked that way from the
// start), so a real encoder has no caller on that path.  What we need here is
// "understand what the origin sent", and -- for the fixed-size slot described
// below -- the ability to say exactly how many bytes a stored stream would take.
//
// The *writing* side lives in `netcap/brotli_encode.hpp` (`src/brotli_encode.cpp`):
// it exists because an equal-length rewrite inside a QUIC packet has to put the
// body back where the original one was, and an origin that sent `br` will not
// accept a bigger body in the same number of bytes.  Deleting is easy, adding
// needs the encoder to have slack to spare.
//
// Written from the RFC rather than vendored -- this project ships no
// third-party code, and the reference decoder is not a dependency we want.
#include <cstddef>
#include <string>

#include "netcap/common.hpp"

namespace netcap {

// Same ceiling the inflate path uses: a body larger than this is refused
// instead of trusted (compressed bombs are cheap to make).
std::size_t brotli_max_output();

bool brotli_decompress(const u8* data, std::size_t len, std::string* out, std::string* error);
bool brotli_decompress(const std::string& in, std::string* out, std::string* error);

// Vectors taken from RFC 7932 plus the streaming rules (empty stream, stored
// meta-blocks, metadata skip).  Keeps the decoder honest without a network.
bool brotli_selfcheck(std::string* report);

// --- the one encoder we do need -------------------------------------------
//
// A "stored" stream: uncompressed meta-blocks only.  It compresses nothing, so
// it is not what an origin would send -- but its length is known before it is
// built, and that is exactly what a fixed-size slot needs.  The QUIC/HTTP-3
// notes in the README explain why: an equal-length rewrite can only put a body
// back where the original one was if the new body fits, and for a `br` response
// the only way to know that is to be able to produce one.
//
// `brotli_stored_size(n)` is the exact byte count of `brotli_compress_stored`
// for n bytes of input (one bit of window header, 20 bits per 64 KiB block,
// plus the final empty last meta-block).  `brotli_stored_fits(n, budget)` is
// the check the rewriter actually asks.
std::size_t brotli_stored_size(std::size_t len);
bool brotli_stored_fits(std::size_t len, std::size_t budget);
bool brotli_compress_stored(const u8* data, std::size_t len, std::string* out,
                            std::string* error);

}  // namespace netcap
