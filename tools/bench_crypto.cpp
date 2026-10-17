// Micro-benchmark for netcap's own crypto primitives: the MITM handshake cost and
// the bulk TLS throughput both land in this code, so it is worth measuring alone.
//
// Build:  g++ -std=c++20 -O2 -Iinclude tools/bench_crypto.cpp src/p256.cpp src/x25519.cpp
//             src/crypto.cpp src/common.cpp -o tools/bench_crypto.exe -lbcrypt
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "netcap/crypto.hpp"
#include "netcap/p256.hpp"

using namespace netcap;

static double elapsed_ms(std::chrono::steady_clock::time_point start) {
  return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

template <typename F>
static void time_it(const char* label, int operations, F fn) {
  const auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < operations; ++i) fn(i);
  const double ms = elapsed_ms(start);
  std::printf("%-30s %10.3f ms/op   (%d ops in %.1f ms)\n", label, ms / operations, operations, ms);
}

int main() {
  P256Key key;
  if (!p256_generate(&key)) {
    std::printf("p256_generate failed\n");
    return 1;
  }
  P256Key other;
  p256_generate(&other);

  u8 hash[32];
  random_bytes(hash, sizeof(hash));
  Bytes r, s;
  if (!p256_ecdsa_sign(key.d, hash, &r, &s)) {
    std::printf("p256_ecdsa_sign failed\n");
    return 1;
  }
  const bool verified = p256_ecdsa_verify(key.q, hash, r, s);
  std::printf("sanity: signature verifies = %s\n", verified ? "yes" : "NO");

  time_it("p256_generate (keygen)", 5, [&](int) { P256Key k; p256_generate(&k); });
  time_it("p256_ecdh", 5, [&](int) { Bytes shared; p256_ecdh(key, other.q, &shared); });
  time_it("p256_ecdsa_sign", 5, [&](int) {
    Bytes rr, ss;
    p256_ecdsa_sign(key.d, hash, &rr, &ss);
  });
  time_it("p256_ecdsa_verify", 5, [&](int) { p256_ecdsa_verify(key.q, hash, r, s); });

  const Bytes key16(16, 0x2b);
  const Bytes nonce(12, 0x01);
  const Bytes aad(5, 0x17);
  const Bytes block(16384, 0x5a);
  time_it("aes_gcm_encrypt 16 KiB", 8, [&](int) { aes_gcm_encrypt(key16, nonce, aad, block); });
  const AeadResult sealed = aes_gcm_encrypt(key16, nonce, aad, block);
  time_it("aes_gcm_decrypt 16 KiB", 8, [&](int) {
    Bytes out;
    aes_gcm_decrypt(key16, nonce, aad, sealed.ciphertext, sealed.tag, &out);
  });

  const Bytes megabyte(1024 * 1024, 0x33);
  time_it("sha256 1 MiB", 4, [&](int) { sha256(megabyte.data(), megabyte.size()); });
  time_it("sha384 1 MiB", 4, [&](int) { sha384(megabyte.data(), megabyte.size()); });

  const Bytes chacha_key(32, 0x11);
  time_it("chacha20_poly1305 16 KiB", 40, [&](int) {
    chacha20_poly1305_encrypt(chacha_key, nonce, aad, block);
  });
  // The two halves of the AEAD, so it is clear which one is worth optimising.
  time_it("chacha20_xor 16 KiB", 40,
          [&](int) { chacha20_xor(chacha_key, nonce, 1, block); });
  time_it("poly1305 16 KiB", 40, [&](int) { poly1305(chacha_key, block); });
  return 0;
}
