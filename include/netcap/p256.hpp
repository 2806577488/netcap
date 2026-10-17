// Self-contained NIST P-256 (secp256r1 / prime256v1) arithmetic: ECDSA with
// SHA-256 (RFC 6979 deterministic nonces) and ECDH.
//
// The interception proxy needs exactly one curve for both jobs: TLS 1.3's
// ecdsa_secp256r1_sha256 signature scheme and its secp256r1 key share. Keeping
// it to one curve means one implementation to trust instead of two.
//
// No external dependency: the big-integer arithmetic lives in p256.cpp.
#ifndef NETCAP_P256_HPP
#define NETCAP_P256_HPP

#include <cstddef>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"  // sha256 / hmac_sha256 (the RFC 6979 nonce)

namespace netcap {

// A point in affine coordinates. `x`/`y` are 32-byte big-endian field elements
// once they come out of this API; `infinity` is the point at infinity.
struct P256Point {
  bool infinity = true;
  Bytes x;
  Bytes y;
};

struct P256Key {
  Bytes d;  // private scalar, 32 bytes big-endian
  P256Point q;
};

// Best-effort OS randomness (BCryptGenRandom / getrandom / random_device).
bool random_bytes(u8* out, std::size_t len);

// Key handling. generate() draws `d` from the OS and derives `q = d*G`.
bool p256_generate(P256Key* out);
bool p256_from_private(const Bytes& d, P256Key* out);
bool p256_valid_public(const P256Point& p);

// SEC 1 encodings: 65 bytes (0x04 || X || Y) and 33 bytes (0x02/0x03 || X).
Bytes p256_serialize_uncompressed(const P256Point& p);
Bytes p256_serialize_compressed(const P256Point& p);
bool p256_parse_point(const u8* data, std::size_t len, P256Point* out);

// ECDH: the shared secret is the x coordinate of d*peer (32 bytes).
bool p256_ecdh(const P256Key& mine, const P256Point& peer, Bytes* shared_x);

// ECDSA over a 32-byte message digest. The nonce comes from RFC 6979, so signing
// the same digest twice gives the same signature (and never repeats a nonce).
// `public_hint` is the signer's own public point when the caller already has one
// (a P256Key carries it): the Windows CNG fast path needs X and Y to import the
// private key, so handing them in avoids re-deriving the point per signature.
// With a hint on Windows the signature comes from CNG, which draws its own nonce
// -- still a valid signature, just not reproducible from the digest alone.
bool p256_ecdsa_sign(const Bytes& d, const u8* hash32, Bytes* r, Bytes* s,
                     const P256Point* public_hint = nullptr);
bool p256_ecdsa_verify(const P256Point& q, const u8* hash32, const Bytes& r, const Bytes& s);

// Cross-checks the fast field/curve arithmetic (four 64-bit limbs, Montgomery
// reduction, windowed NAF) against the slow big-integer path on random inputs
// and returns false, filling `*report` with the first disagreement.  Used by
// `--selftest`: the fast path is the one that signs certificates, so it is
// checked against the implementation it replaced rather than against itself.
bool p256_selfcheck(std::string* report);

}  // namespace netcap

#endif  // NETCAP_P256_HPP
