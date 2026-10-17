// Deterministic cross-check between the portable P-256 path and the Windows
// CNG accelerator.  Keys and messages come from a counter (not from the RNG),
// so the two processes can be compared byte for byte:
//
//   _cng_case.exe sig 300 > a.txt                 (portable, NETCAP_NO_CNG=1)
//   _cng_case.exe sig 300 > c.txt                 (accelerated, NETCAP_CNG=1)
//   _cng_case.exe check 300 < c.txt               (does the other path accept?)
#include <cstdio>
#include <iostream>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/p256.hpp"

using namespace netcap;

static Bytes case_key(std::size_t i) {
  const std::string seed = "netcap-cng-case-" + std::to_string(i);
  return sha256(reinterpret_cast<const u8*>(seed.data()), seed.size());
}

static Bytes case_hash(std::size_t i) {
  const std::string seed = "netcap-cng-message-" + std::to_string(i);
  return sha256(reinterpret_cast<const u8*>(seed.data()), seed.size());
}

static P256Key case_public(std::size_t i) {
  P256Key key;
  if (!p256_from_private(case_key(i), &key)) key.d.clear();
  return key;
}

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "sig";
  const std::size_t count = argc > 2 ? static_cast<std::size_t>(std::stoull(argv[2])) : 100;
  if (mode == "sig") {
    for (std::size_t i = 0; i < count; ++i) {
      const P256Key key = case_public(i);
      if (key.d.empty()) {
        std::cout << "case " << i << " invalid-key\n";
        continue;
      }
      const Bytes hash = case_hash(i);
      Bytes r;
      Bytes s;
      if (!p256_ecdsa_sign(key.d, hash.data(), &r, &s, &key.q)) {
        std::cout << "case " << i << " sign-failed\n";
        continue;
      }
      const bool ok = p256_ecdsa_verify(key.q, hash.data(), r, s);
      Bytes shared;
      const std::string ecdh = p256_ecdh(key, key.q, &shared) ? to_hex(shared) : std::string("-");
      std::cout << "case " << i << " " << to_hex(r) << " " << to_hex(s) << " self=" << (ok ? 1 : 0)
                << " ecdh=" << ecdh << "\n";
    }
    return 0;
  }

  if (mode == "gen") {
    // Key generation itself: whatever produced the key (CNG when enabled) has
    // to agree with the portable scalar multiplication on the public point.
    for (std::size_t i = 0; i < count; ++i) {
      P256Key key;
      if (!p256_generate(&key)) {
        std::cout << "GEN-FAIL case " << i << " generate\n";
        continue;
      }
      P256Key portable;
      if (!p256_from_private(key.d, &portable)) {
        std::cout << "GEN-FAIL case " << i << " from_private\n";
        continue;
      }
      const bool same = portable.q.x == key.q.x && portable.q.y == key.q.y;
      Bytes r;
      Bytes s;
      const bool signed_ok =
          p256_ecdsa_sign(key.d, case_hash(i).data(), &r, &s, &key.q) &&
          p256_ecdsa_verify(key.q, case_hash(i).data(), r, s);
      Bytes shared;
      shared.assign(32, 0);
      const bool ecdh_ok = p256_ecdh(key, key.q, &shared);
      if (!same || !signed_ok || !ecdh_ok) {
        std::cout << "GEN-FAIL case " << i << " same=" << (same ? 1 : 0)
                  << " sign=" << (signed_ok ? 1 : 0) << " ecdh=" << (ecdh_ok ? 1 : 0)
                  << " d=" << to_hex(key.d) << " qx=" << to_hex(key.q.x) << " px=" << to_hex(portable.q.x)
                  << "\n";
      }
    }
    std::cout << "generated " << count << "\n";
    return 0;
  }

  if (mode == "self") {
    // p256_selfcheck() is what --selftest calls; run it many times so a rare
    // random case shows up, and print the report the selftest message hides.
    std::size_t failures = 0;
    for (std::size_t i = 0; i < count; ++i) {
      std::string why;
      if (!p256_selfcheck(&why)) {
        ++failures;
        if (failures <= 5) std::cout << "SELF-FAIL run " << i << ": " << why << "\n";
      }
    }
    std::cout << "selfcheck runs " << count << ", failures " << failures << "\n";
    return failures == 0 ? 0 : 1;
  }

  std::string tok;
  std::size_t seen = 0;
  std::size_t fails = 0;
  while (std::cin >> tok) {
    if (tok != "case") {
      std::string skip;
      std::getline(std::cin, skip);
      continue;
    }
    std::size_t i = 0;
    std::cin >> i;
    std::string rhex;
    std::string shex;
    std::cin >> rhex >> shex;
    std::string rest;
    std::getline(std::cin, rest);
    const P256Key key = case_public(i);
    if (key.d.empty() || rhex.size() != 64 || shex.size() != 64) continue;
    ++seen;
    if (!p256_ecdsa_verify(key.q, case_hash(i).data(), from_hex(rhex), from_hex(shex))) {
      ++fails;
      std::cout << "CHECK-FAIL case " << i << " r=" << rhex << " s=" << shex << "\n";
    }
  }
  std::cout << "checked " << seen << ", failures " << fails << "\n";
  return fails == 0 ? 0 : 1;
}
