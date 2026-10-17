// Self-contained NIST P-521 (secp521r1) arithmetic, for ECDHE only.
//
// P-256 signs the certificates, so this curve exists for exactly one job: a
// client that offers a secp521r1 key share and nothing this stack can otherwise
// use.  Refusing such a client costs a whole application; doing the key exchange
// costs two scalar multiplications.
//
// The field is 2^521 - 1, a Mersenne prime, so reduction is folding instead of
// division: nine 64-bit limbs, and every bit at or above 521 comes back down
// because 2^521 == 1 (mod p).  There is no ECDSA here -- signatures stay on
// P-256 -- so this file only has to be a correct point-multiplication machine.
//
// No external dependency: the arithmetic lives in p521.cpp.
#ifndef NETCAP_P521_HPP
#define NETCAP_P521_HPP

#include <cstddef>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"  // Bytes

namespace netcap {

// Affine coordinates; 66-byte big-endian values once they leave this API.
struct P521Point {
  bool infinity = true;
  Bytes x;
  Bytes y;
};

struct P521Key {
  Bytes d;  // private scalar, 66 bytes big-endian
  P521Point q;
};

// Key handling, mirroring the P-256 names.
bool p521_generate(P521Key* out);
bool p521_from_private(const Bytes& d, P521Key* out);
bool p521_valid_public(const P521Point& p);

// SEC 1 uncompressed encoding: 133 bytes (0x04 || X || Y).
Bytes p521_serialize_uncompressed(const P521Point& p);
bool p521_parse_point(const u8* data, std::size_t len, P521Point* out);

// ECDH: the shared secret is the x coordinate of d*peer (66 bytes), which is
// what RFC 8446 7.4.2 asks for on a NIST curve.
bool p521_ecdh(const P521Key& mine, const P521Point& peer, Bytes* shared_x);

// Known-answer test against vectors produced by an independent implementation
// (OpenSSL 3.2): scalar multiplication, the curve equation, ECDH in both
// directions, the encodings and the rejection of points that are not on the
// curve.  Used by `--selftest`, and the reason to trust this file at all.
bool p521_selfcheck(std::string* report);

}  // namespace netcap

#endif  // NETCAP_P521_HPP
