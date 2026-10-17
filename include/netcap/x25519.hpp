// X25519 (RFC 7748): the curve browsers actually put in their TLS 1.3 key
// share. P-256 is what signs our certificates; X25519 is what carries the key
// exchange, so the MITM needs both.
#pragma once

#include <cstddef>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"  // Bytes

namespace netcap {

struct X25519Key {
  Bytes priv;  // 32 bytes, already clamped
  Bytes pub;   // 32 bytes, the u coordinate
};

// Fresh key pair from the platform random source.
bool x25519_keypair(X25519Key* out);

// Scalar multiplication of the base point u = 9 with the scalar clamped the way
// RFC 7748 §5 prescribes. `scalar` must be 32 bytes.
bool x25519_public(const Bytes& scalar, Bytes* out_public);

// Raw scalar multiplication: `scalar` is used as given (no clamping) and
// `u_point` is the peer's 32 byte u coordinate. Fails for the low order points
// whose shared secret would be all zeroes.
bool x25519_scalar_mult(const Bytes& scalar, const Bytes& u_point, Bytes* out);

// The exchange itself: clamps `scalar`, multiplies the peer's public key and
// refuses an all-zero result (RFC 7748 §6.1).
bool x25519(const Bytes& scalar, const Bytes& peer_public, Bytes* shared);

// True when the 32 byte buffer is all zeroes, i.e. a shared secret that must be
// rejected before it is fed into HKDF.
bool x25519_is_zero(const Bytes& value);

std::string x25519_describe(const Bytes& pub);

}  // namespace netcap
