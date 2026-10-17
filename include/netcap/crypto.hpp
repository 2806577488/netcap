// Cryptographic primitives used by the TLS decryption path.
//
// Everything here is implemented from scratch on top of the standard library:
// the project deliberately has no third-party dependencies (no OpenSSL, no
// libsodium), so the hashes, the AEAD constructions and the key schedule are
// all local code with published test vectors in the self-test suite.
#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

// A byte string: keys, nonces, digests and bulk data all travel as Bytes.
using Bytes = std::vector<u8>;

// Hex helpers (tolerant of spaces, colons and dashes on input).
Bytes from_hex(const std::string& hex);
std::string to_hex(const u8* p, std::size_t n);
std::string to_hex(const Bytes& b);

// ------------------------------------------------------------------ hashes

Bytes sha256(const u8* data, std::size_t len);
Bytes sha384(const u8* data, std::size_t len);
Bytes sha512(const u8* data, std::size_t len);

inline Bytes sha256(const Bytes& b) { return sha256(b.data(), b.size()); }
inline Bytes sha384(const Bytes& b) { return sha384(b.data(), b.size()); }
inline Bytes sha512(const Bytes& b) { return sha512(b.data(), b.size()); }

// Legacy hashes, needed by the pre-1.2 handshake and the CBC suites:
// TLS 1.0/1.1 derive keys with P_MD5 XOR P_SHA1 and finish with MD5||SHA1,
// and the CBC cipher suites authenticate records with HMAC-SHA1.
Bytes sha1(const u8* data, std::size_t len);
Bytes md5(const u8* data, std::size_t len);

inline Bytes sha1(const Bytes& b) { return sha1(b.data(), b.size()); }
inline Bytes md5(const Bytes& b) { return md5(b.data(), b.size()); }

Bytes hmac_sha256(const Bytes& key, const u8* data, std::size_t len);
Bytes hmac_sha256(const Bytes& key, const Bytes& data);
Bytes hmac_sha384(const Bytes& key, const Bytes& data);

Bytes hmac_sha1(const Bytes& key, const u8* data, std::size_t len);
Bytes hmac_sha1(const Bytes& key, const Bytes& data);
Bytes hmac_md5(const Bytes& key, const u8* data, std::size_t len);
Bytes hmac_md5(const Bytes& key, const Bytes& data);

// ------------------------------------------------------------------ KDFs

// HKDF (RFC 5869). TLS 1.3 uses it with SHA-256 or SHA-384 depending on the
// negotiated cipher suite; `sha384` selects the latter.
Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm, bool sha384 = false);
Bytes hkdf_expand(const Bytes& prk, const Bytes& info, std::size_t out_len, bool sha384 = false);

// HKDF-Expand-Label from RFC 8446 §7.1:
//   struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
Bytes hkdf_expand_label(const Bytes& secret, const std::string& label, const Bytes& context,
                        std::size_t out_len, bool sha384 = false);

// TLS 1.2 PRF (RFC 5246 §5) for the pre-1.3 handshake.
Bytes tls12_prf(const Bytes& secret, const std::string& label, const Bytes& seed,
                std::size_t out_len, bool sha384 = false);

// ------------------------------------------------------------------ AES

class Aes {
 public:
  // Accepts 16, 24 or 32 byte keys; returns false for any other length.
  bool set_key(const u8* key, std::size_t key_len);
  bool set_key(const Bytes& key) { return set_key(key.data(), key.size()); }

  void encrypt_block(const u8 in[16], u8 out[16]) const;
  void decrypt_block(const u8 in[16], u8 out[16]) const;

  int rounds() const { return rounds_; }
  bool ready() const { return ready_; }
  static constexpr std::size_t kBlock = 16;

 private:
  std::array<u8, 240> rk_{};  // up to 15 round keys of 16 bytes
  int rounds_ = 0;
  bool ready_ = false;
};

// Counter mode with a 96-bit nonce and a 32-bit block counter.
void aes_ctr_xor(const Aes& aes, const u8 nonce[12], u32 counter, u8* data, std::size_t len);

// CBC. `len` must be a multiple of 16. Decryption performs no padding check:
// callers that carry TLS padding strip it themselves.
void aes_cbc_encrypt(const Aes& aes, const u8 iv[16], const u8* in, std::size_t len, u8* out);
void aes_cbc_decrypt(const Aes& aes, const u8 iv[16], const u8* in, std::size_t len, u8* out);

// ------------------------------------------------------------------ AEAD

struct AeadResult {
  Bytes ciphertext;
  Bytes tag;  // 16 bytes
  bool ok = false;
};

AeadResult aes_gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                           const Bytes& plaintext);
bool aes_gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                     const Bytes& ciphertext, const Bytes& tag, Bytes* plaintext);

AeadResult chacha20_poly1305_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                     const Bytes& plaintext);
bool chacha20_poly1305_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                               const Bytes& ciphertext, const Bytes& tag, Bytes* plaintext);

Bytes chacha20_xor(const Bytes& key, const Bytes& nonce, u32 counter, const Bytes& data);
Bytes poly1305(const Bytes& key32, const Bytes& msg);

// Streaming Poly1305.  The AEAD hashes "aad || pad || ciphertext || pad ||
// len(aad) || len(ct)"; doing that with one contiguous buffer means building a
// full copy of the ciphertext, which for a 16 KiB record cost more than the
// arithmetic.  With this class each piece is hashed where it already lives.
class Poly1305 {
 public:
  Poly1305();
  void init(const Bytes& key32);  // 32 bytes; any other size leaves the tag zeroed
  void update(const u8* data, std::size_t len);
  void update(const Bytes& data) { update(data.data(), data.size()); }
  Bytes finish();  // ends the message
  // Tests and benchmarks flip this to compare the four-block SSE2 path with the
  // scalar one; there is no reason for production code to touch it.
  void set_simd(bool enabled) { simd_ = enabled; }
  bool simd() const { return simd_; }

 private:
  void block(const u8* m, bool full);
  u32 r0_ = 0, r1_ = 0, r2_ = 0, r3_ = 0, r4_ = 0;
  u32 s1_ = 0, s2_ = 0, s3_ = 0, s4_ = 0;
  u32 h0_ = 0, h1_ = 0, h2_ = 0, h3_ = 0, h4_ = 0;
  u8 key_[32] = {0};
  u8 buf_[16] = {0};
  std::size_t have_ = 0;
  bool ready_ = false;
  bool simd_ = true;
};

// ------------------------------------------------------------------ key log

// One line of an SSLKEYLOGFILE (the format NSS, Firefox, Chrome and curl agree
// on): "<label> <client_random_hex> <secret_hex>".
struct KeyLogEntry {
  std::string label;
  Bytes client_random;  // 32 bytes
  Bytes secret;         // master secret (TLS 1.2) or traffic secret (TLS 1.3)
};

std::vector<KeyLogEntry> parse_keylog(const std::string& text);
bool load_keylog_file(const std::string& path, std::vector<KeyLogEntry>* out, std::string* error);

}  // namespace netcap
