// RSA signature checking, for the HTTPS interception proxy.
//
// The proxy's TLS 1.3 client speaks to the real site, and most of the web still
// signs with an RSA key: a client that only offers `ecdsa_secp256r1_sha256` gets
// a `handshake_failure` from every RSA-only origin (CSDN, for one).  So the
// client has to be able to check two RSA things:
//
//   * RSASSA-PSS over SHA-256, the TLS 1.3 CertificateVerify signature;
//   * RSASSA-PKCS1-v1_5 over SHA-256, the usual certificate signature.
//
// The maths is delegated to Windows CNG (BCrypt), exactly like the P-256 fast
// path: a portable 2048-bit modexp would be a page of big-integer code for no
// benefit on the only platform that ships this tool.  When CNG is unavailable
// the functions return false and the caller reports "cannot check", never
// "valid".
#ifndef NETCAP_RSA_HPP
#define NETCAP_RSA_HPP

#include <cstddef>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"  // Bytes

namespace netcap {

/// True when RSA signature checking works on this machine.
bool rsa_available();

/// Verifies `signature` over a 32 byte SHA-256 digest.  `modulus` and
/// `exponent` are the big-endian integers as they appear in the certificate.
/// `pss` selects RSASSA-PSS (TLS 1.3 CertificateVerify) instead of PKCS#1 v1.5
/// (certificate signatures); `salt_len` is only used for PSS.
bool rsa_verify_sha256(const Bytes& modulus, const Bytes& exponent, const u8* digest32,
                       const Bytes& signature, bool pss, std::size_t salt_len = 32);

/// Encrypts `plain` with the RSA public key (modulus, exponent) using PKCS#1
/// v1.5 type-2 padding.  That is how TLS 1.0/1.1 with RSA key exchange carries
/// the 48 byte pre_master_secret to the server (RFC 5246 §7.4.7.1), and it is
/// the only RSA operation a client needs the *public* key for.  The modular
/// exponentiation is portable integer code instead of a CNG call: the public
/// exponent is 65537, so a handshake costs nineteen modular squarings, and the
/// legacy path then works on every platform netcap builds on.
bool rsa_encrypt_pkcs1(const Bytes& modulus, const Bytes& exponent, const Bytes& plain, Bytes* out,
                       std::string* why = nullptr);

/// Generates a key with CNG, signs with it and checks the signature with the
/// code above, so the blob layout and the padding flags are proven rather than
/// assumed.  Returns false with a reason when something does not add up.
bool rsa_selfcheck(std::string* report);

}  // namespace netcap

#endif  // NETCAP_RSA_HPP
