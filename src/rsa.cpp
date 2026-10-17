// RSA signature checking through Windows CNG (BCrypt), see netcap/rsa.hpp.
//
// Why CNG and not our own big integers: RSA verification is one modexp with a
// 2048-bit modulus and the public exponent 65537, and every supported platform
// has a vetted implementation of exactly that.  Writing a second, slower one
// here would add a large attack surface to the component that decides whether a
// certificate is trustworthy.
#include "netcap/rsa.hpp"

#if defined(_WIN32)

#include <windows.h>

#include <bcrypt.h>

#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "netcap/crypto.hpp"

namespace netcap {
namespace {

// The padding structures are declared here instead of taken from bcrypt.h: the
// layout is what BCrypt reads (an algorithm name and, for PSS, a salt length),
// and spelling them out keeps this file independent of which Windows headers
// the MinGW build happens to have.
struct PssPadding {
  LPCWSTR alg;
  ULONG salt;
};
struct Pkcs1Padding {
  LPCWSTR alg;
};

std::mutex g_alg_mutex;
BCRYPT_ALG_HANDLE g_rsa_alg = nullptr;
bool g_rsa_tried = false;

/// Opens the RSA algorithm provider once.  Returns nullptr when CNG cannot give
/// us one, which is the signal for every caller to say "cannot check".
BCRYPT_ALG_HANDLE rsa_alg() {
  std::lock_guard<std::mutex> lock(g_alg_mutex);
  if (!g_rsa_tried) {
    g_rsa_tried = true;
    BCRYPT_ALG_HANDLE handle = nullptr;
    if (BCryptOpenAlgorithmProvider(&handle, BCRYPT_RSA_ALGORITHM, nullptr, 0) == 0) g_rsa_alg = handle;
  }
  return g_rsa_alg;
}

u32 le32(const u8* p) {
  return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
         (static_cast<u32>(p[3]) << 24);
}

// BCRYPT_RSAKEY_BLOB, as produced by BCryptExportKey(BCRYPT_RSAPUBLIC_BLOB):
//   { Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2 }
// followed by the exponent and then the modulus, both big-endian.
struct RsPublicKey {
  Bytes modulus;
  Bytes exponent;
};

bool split_public_blob(const std::vector<u8>& blob, RsPublicKey* out) {
  if (blob.size() < 24) return false;
  if (le32(blob.data()) != BCRYPT_RSAPUBLIC_MAGIC) return false;
  const u32 cb_exp = le32(blob.data() + 8);
  const u32 cb_mod = le32(blob.data() + 12);
  if (24 + static_cast<std::size_t>(cb_exp) + cb_mod > blob.size()) return false;
  out->exponent.assign(blob.begin() + 24, blob.begin() + 24 + cb_exp);
  out->modulus.assign(blob.begin() + 24 + cb_exp, blob.begin() + 24 + cb_exp + cb_mod);
  return !out->modulus.empty() && !out->exponent.empty();
}

// Strips the leading zero bytes a DER INTEGER carries when the top bit is set:
// BCrypt wants the bare big-endian integers and a length that matches.
Bytes strip_leading_zeros(const Bytes& in) {
  std::size_t first = 0;
  while (first + 1 < in.size() && in[first] == 0x00) ++first;
  return Bytes(in.begin() + static_cast<std::ptrdiff_t>(first), in.end());
}

bool verify_with_key(BCRYPT_KEY_HANDLE key, const u8* digest32, const Bytes& signature, bool pss,
                     std::size_t salt_len) {
  if (signature.empty()) return false;
  PssPadding pss_info{BCRYPT_SHA256_ALGORITHM, static_cast<ULONG>(salt_len)};
  Pkcs1Padding pkcs1_info{BCRYPT_SHA256_ALGORITHM};
  const NTSTATUS status =
      BCryptVerifySignature(key, pss ? static_cast<void*>(&pss_info) : static_cast<void*>(&pkcs1_info),
                            const_cast<PUCHAR>(digest32), 32, const_cast<PUCHAR>(signature.data()),
                            static_cast<ULONG>(signature.size()), pss ? BCRYPT_PAD_PSS : BCRYPT_PAD_PKCS1);
  return status == 0;
}

}  // namespace

bool rsa_available() { return rsa_alg() != nullptr; }

bool rsa_verify_sha256(const Bytes& modulus, const Bytes& exponent, const u8* digest32,
                       const Bytes& signature, bool pss, std::size_t salt_len) {
  BCRYPT_ALG_HANDLE alg = rsa_alg();
  if (alg == nullptr || digest32 == nullptr) return false;
  const Bytes mod = strip_leading_zeros(modulus);
  const Bytes exp = strip_leading_zeros(exponent);
  if (mod.size() < 64 || exp.empty()) return false;

  // The blob is { header, exponent, modulus }, all big-endian, and the bit
  // length has to describe the modulus we hand over.
  std::vector<u8> blob(24 + exp.size() + mod.size(), 0);
  const u32 bit_length = static_cast<u32>(mod.size() * 8);
  const u32 cb_exp = static_cast<u32>(exp.size());
  const u32 cb_mod = static_cast<u32>(mod.size());
  const u32 magic = BCRYPT_RSAPUBLIC_MAGIC;
  std::memcpy(blob.data(), &magic, 4);
  std::memcpy(blob.data() + 4, &bit_length, 4);
  std::memcpy(blob.data() + 8, &cb_exp, 4);
  std::memcpy(blob.data() + 12, &cb_mod, 4);
  std::memcpy(blob.data() + 24, exp.data(), exp.size());
  std::memcpy(blob.data() + 24 + exp.size(), mod.data(), mod.size());

  BCRYPT_KEY_HANDLE key = nullptr;
  if (BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key, blob.data(),
                          static_cast<ULONG>(blob.size()), 0) != 0) {
    return false;
  }
  const bool ok = verify_with_key(key, digest32, signature, pss, salt_len);
  BCryptDestroyKey(key);
  return ok;
}

bool rsa_selfcheck(std::string* report) {
  const auto fail = [&](const std::string& why) {
    if (report != nullptr) *report = why;
    return false;
  };
  BCRYPT_ALG_HANDLE alg = rsa_alg();
  if (alg == nullptr) return fail("CNG has no RSA provider here");

  BCRYPT_KEY_HANDLE key = nullptr;
  if (BCryptGenerateKeyPair(alg, &key, 2048, 0) != 0) return fail("could not generate an RSA key");
  struct KeyGuard {
    BCRYPT_KEY_HANDLE key;
    ~KeyGuard() {
      if (key != nullptr) BCryptDestroyKey(key);
    }
  } guard{key};
  if (BCryptFinalizeKeyPair(key, 0) != 0) return fail("could not finalize the RSA key");

  ULONG written = 0;
  if (BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &written, 0) != 0 || written == 0) {
    return fail("could not size the public key blob");
  }
  std::vector<u8> blob(written, 0);
  if (BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), written, &written, 0) != 0) {
    return fail("could not export the public key blob");
  }
  RsPublicKey parsed;
  if (!split_public_blob(blob, &parsed)) return fail("the exported blob did not parse");
  if (parsed.modulus.size() != 256) {
    return fail("the modulus is " + std::to_string(parsed.modulus.size()) + " bytes, expected 256");
  }

  const std::string message = "netcap rsa selfcheck";
  const Bytes digest = sha256(reinterpret_cast<const u8*>(message.data()), message.size());
  if (digest.size() != 32) return fail("sha256 gave " + std::to_string(digest.size()) + " bytes");

  // PSS, the TLS 1.3 CertificateVerify shape.
  PssPadding pss{BCRYPT_SHA256_ALGORITHM, 32};
  ULONG sig_len = 0;
  if (BCryptSignHash(key, &pss, const_cast<PUCHAR>(digest.data()), 32, nullptr, 0, &sig_len,
                     BCRYPT_PAD_PSS) != 0 ||
      sig_len == 0) {
    return fail("could not size a PSS signature");
  }
  Bytes signature(sig_len, 0);
  if (BCryptSignHash(key, &pss, const_cast<PUCHAR>(digest.data()), 32, signature.data(), sig_len, &sig_len,
                     BCRYPT_PAD_PSS) != 0) {
    return fail("could not sign with PSS");
  }
  signature.resize(sig_len);
  if (!rsa_verify_sha256(parsed.modulus, parsed.exponent, digest.data(), signature, true, 32)) {
    return fail("the PSS signature did not verify");
  }
  Bytes tampered = signature;
  tampered[tampered.size() / 2] ^= 0x40;
  if (rsa_verify_sha256(parsed.modulus, parsed.exponent, digest.data(), tampered, true, 32)) {
    return fail("a tampered PSS signature verified");
  }
  const std::string other = "netcap rsa selfcheck, other message";
  const Bytes other_digest = sha256(reinterpret_cast<const u8*>(other.data()), other.size());
  if (rsa_verify_sha256(parsed.modulus, parsed.exponent, other_digest.data(), signature, true, 32)) {
    return fail("a PSS signature verified against the wrong digest");
  }

  // PKCS#1 v1.5, the usual certificate signature shape.
  Pkcs1Padding pkcs1{BCRYPT_SHA256_ALGORITHM};
  sig_len = 0;
  if (BCryptSignHash(key, &pkcs1, const_cast<PUCHAR>(digest.data()), 32, nullptr, 0, &sig_len,
                     BCRYPT_PAD_PKCS1) != 0 ||
      sig_len == 0) {
    return fail("could not size a PKCS#1 signature");
  }
  Bytes pkcs1_sig(sig_len, 0);
  if (BCryptSignHash(key, &pkcs1, const_cast<PUCHAR>(digest.data()), 32, pkcs1_sig.data(), sig_len, &sig_len,
                     BCRYPT_PAD_PKCS1) != 0) {
    return fail("could not sign with PKCS#1");
  }
  pkcs1_sig.resize(sig_len);
  if (!rsa_verify_sha256(parsed.modulus, parsed.exponent, digest.data(), pkcs1_sig, false, 0)) {
    return fail("the PKCS#1 signature did not verify");
  }
  if (rsa_verify_sha256(parsed.modulus, parsed.exponent, other_digest.data(), pkcs1_sig, false, 0)) {
    return fail("a PKCS#1 signature verified against the wrong digest");
  }
  // A PSS signature must not pass as PKCS#1 and the other way round.
  if (rsa_verify_sha256(parsed.modulus, parsed.exponent, digest.data(), signature, false, 0)) {
    return fail("a PSS signature passed the PKCS#1 check");
  }

  // The pre-1.3 handshake encrypts with the public key instead of signing, so
  // the same selfcheck encrypts a pre_master_secret shaped message and asks CNG
  // to decrypt it back: that proves the padding and the big-endian conversion
  // instead of assuming them.
  Bytes secret(48, 0);
  secret[0] = 0x03;
  secret[1] = 0x03;
  for (std::size_t i = 2; i < secret.size(); ++i) secret[i] = static_cast<u8>(i * 7 + 1);
  Bytes cipher;
  if (!rsa_encrypt_pkcs1(parsed.modulus, parsed.exponent, secret, &cipher, nullptr)) {
    return fail("the RSA public key could not encrypt");
  }
  if (cipher.size() != parsed.modulus.size()) {
    return fail("the ciphertext is " + std::to_string(cipher.size()) + " bytes, expected " +
                std::to_string(parsed.modulus.size()));
  }
  Pkcs1Padding raw_pkcs1{nullptr};  // pszAlgId must be NULL for raw PKCS#1 decryption
  ULONG plain_len = 0;
  if (BCryptDecrypt(key, cipher.data(), static_cast<ULONG>(cipher.size()), &raw_pkcs1, nullptr, 0, nullptr, 0,
                    &plain_len, BCRYPT_PAD_PKCS1) != 0) {
    return fail("CNG refused to decrypt our PKCS#1 block");
  }
  Bytes recovered(plain_len, 0);
  ULONG got = 0;
  if (BCryptDecrypt(key, cipher.data(), static_cast<ULONG>(cipher.size()), &raw_pkcs1, nullptr, 0,
                    recovered.data(), plain_len, &got, BCRYPT_PAD_PKCS1) != 0) {
    return fail("CNG could not decrypt a sized PKCS#1 block");
  }
  recovered.resize(got);
  if (recovered != secret) return fail("the PKCS#1 round trip gave the wrong plaintext");
  cipher[cipher.size() - 1] ^= 0x01;
  plain_len = 0;
  if (BCryptDecrypt(key, cipher.data(), static_cast<ULONG>(cipher.size()), &raw_pkcs1, nullptr, 0, nullptr, 0,
                    &plain_len, BCRYPT_PAD_PKCS1) == 0) {
    return fail("a corrupted PKCS#1 block still decrypted");
  }

  if (report != nullptr) {
    *report =
        "CNG RSA: PSS and PKCS#1 sign/verify agree, tampering and wrong digests are refused, and a "
        "PKCS#1 encryption round trip recovers a 48 byte pre_master_secret";
  }
  return true;
}

}  // namespace netcap

#else  // not Windows

namespace netcap {

bool rsa_available() { return false; }

bool rsa_verify_sha256(const Bytes&, const Bytes&, const u8*, const Bytes&, bool, std::size_t) {
  return false;
}

bool rsa_selfcheck(std::string* report) {
  if (report != nullptr) *report = "RSA checking needs Windows CNG";
  return true;  // nothing to check on this platform
}

}  // namespace netcap

#endif

// ---------------------------------------------------------------- encryption
//
// The one RSA operation that uses the *public* key: PKCS#1 v1.5 encryption,
// which is what TLS 1.0/1.1 with RSA key exchange puts in ClientKeyExchange.
// It lives outside the platform guards above because it is plain integer code:
// a second, vetted modexp would only matter for signature *verification* (where
// a wrong answer means a wrong trust decision), while here the worst case is a
// handshake that fails.  With e = 65537 this is nineteen modular squarings.
#include <algorithm>
#include <string>
#include <vector>

#include "netcap/p256.hpp"  // random_bytes

namespace netcap {
namespace {

using Limbs = std::vector<u32>;  // little endian, trimmed

Limbs limbs_from_bytes(const Bytes& be) {
  Limbs out;
  out.reserve(be.size() / 4 + 1);
  for (std::size_t end = be.size(); end > 0;) {
    const std::size_t start = end >= 4 ? end - 4 : 0;
    u32 w = 0;
    for (std::size_t k = start; k < end; ++k) w = (w << 8) | static_cast<u32>(be[k]);
    out.push_back(w);
    end = start;
  }
  while (!out.empty() && out.back() == 0) out.pop_back();
  return out;
}

Bytes limbs_to_bytes(const Limbs& a, std::size_t len) {
  Bytes out(len, 0);
  for (std::size_t i = 0; i < a.size(); ++i) {
    for (int b = 0; b < 4; ++b) {
      const std::size_t pos = i * 4 + static_cast<std::size_t>(b);
      if (pos >= len) break;
      out[len - 1 - pos] = static_cast<u8>((a[i] >> (8 * b)) & 0xFFu);
    }
  }
  return out;
}

int limbs_cmp(const Limbs& a, const Limbs& b) {
  if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
  for (std::size_t i = a.size(); i > 0; --i) {
    if (a[i - 1] != b[i - 1]) return a[i - 1] < b[i - 1] ? -1 : 1;
  }
  return 0;
}

void limbs_sub(Limbs& a, const Limbs& b) {  // requires a >= b
  u64 borrow = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    const u64 sub = borrow + (i < b.size() ? static_cast<u64>(b[i]) : 0u);
    const u64 cur = a[i];
    a[i] = static_cast<u32>(cur - sub);
    borrow = cur < sub ? 1 : 0;
  }
  while (!a.empty() && a.back() == 0) a.pop_back();
}

Limbs limbs_mul(const Limbs& a, const Limbs& b) {
  Limbs r(a.size() + b.size(), 0);
  for (std::size_t i = 0; i < a.size(); ++i) {
    u64 carry = 0;
    for (std::size_t j = 0; j < b.size(); ++j) {
      const u64 cur = static_cast<u64>(a[i]) * b[j] + r[i + j] + carry;
      r[i + j] = static_cast<u32>(cur);
      carry = cur >> 32;
    }
    std::size_t k = i + b.size();
    while (carry != 0 && k < r.size()) {
      const u64 cur = static_cast<u64>(r[k]) + carry;
      r[k] = static_cast<u32>(cur);
      carry = cur >> 32;
      ++k;
    }
  }
  while (!r.empty() && r.back() == 0) r.pop_back();
  return r;
}

// a %= m.  Shift-and-subtract from the most significant bit: a couple of
// hundred microseconds for a 2048-bit modulus, once per handshake, which is
// not worth a Barrett or Montgomery reduction here.
void limbs_mod(Limbs& a, const Limbs& m) {
  if (m.empty() || a.empty()) {
    a.clear();
    return;
  }
  if (m.size() == 1 && m[0] == 1) {
    a.clear();
    return;
  }
  if (limbs_cmp(a, m) < 0) return;
  const std::size_t bits = a.size() * 32;
  Limbs rem;
  rem.reserve(m.size() + 1);
  for (std::size_t i = bits; i > 0; --i) {
    u32 carry = (a[(i - 1) / 32] >> ((i - 1) % 32)) & 1u;
    for (std::size_t k = 0; k < rem.size(); ++k) {
      const u32 next = rem[k] >> 31;
      rem[k] = static_cast<u32>((rem[k] << 1) | carry);
      carry = next;
    }
    if (carry != 0) rem.push_back(carry);
    if (limbs_cmp(rem, m) >= 0) limbs_sub(rem, m);
  }
  a = rem;
}

Limbs limbs_modpow(const Limbs& base, const Bytes& exponent, const Limbs& modulus) {
  Limbs result{1};
  if (modulus.empty()) return Limbs{};
  Limbs b = base;
  limbs_mod(b, modulus);
  const std::size_t bits = exponent.size() * 8;
  for (std::size_t i = 0; i < bits; ++i) {
    const std::size_t bit = bits - 1 - i;  // most significant bit first
    const bool set = ((exponent[bit / 8] >> (bit % 8)) & 1u) != 0;
    result = limbs_mul(result, result);
    limbs_mod(result, modulus);
    if (set) {
      result = limbs_mul(result, b);
      limbs_mod(result, modulus);
    }
  }
  return result;
}

}  // namespace

bool rsa_encrypt_pkcs1(const Bytes& modulus, const Bytes& exponent, const Bytes& plain, Bytes* out,
                       std::string* why) {
  auto fail = [&](const std::string& text) {
    if (why != nullptr) *why = text;
    return false;
  };
  if (out == nullptr) return fail("no output buffer");
  const std::size_t k = modulus.size();
  if (k < 64) return fail("the RSA modulus is only " + std::to_string(k) + " bytes");
  if (plain.size() + 11 > k) {
    return fail("a " + std::to_string(plain.size()) + " byte message does not fit in a " +
                std::to_string(k) + " byte modulus");
  }
  const Limbs m = limbs_from_bytes(modulus);
  const Limbs e = limbs_from_bytes(exponent);
  if (m.empty()) return fail("the RSA modulus is zero");
  if (e.empty() || (e[0] & 1u) == 0) return fail("the RSA public exponent must be odd");

  // PKCS#1 v1.5 type 2: 00 02 PS 00 M, with a random, all-non-zero PS.
  const std::size_t ps_len = k - 3 - plain.size();
  Bytes em(k, 0);
  em[0] = 0x00;
  em[1] = 0x02;
  bool filled = false;
  for (int attempt = 0; attempt < 64 && !filled; ++attempt) {
    if (!random_bytes(em.data() + 2, ps_len)) return fail("no randomness available for the padding");
    filled = true;
    for (std::size_t i = 0; i < ps_len; ++i) {
      if (em[2 + i] == 0) {
        filled = false;
        break;
      }
    }
  }
  if (!filled) return fail("could not build a padding string without a zero byte");
  em[2 + ps_len] = 0x00;
  std::copy(plain.begin(), plain.end(), em.begin() + static_cast<std::ptrdiff_t>(3 + ps_len));

  const Limbs message = limbs_from_bytes(em);
  if (limbs_cmp(message, m) >= 0) return fail("the padded message is not smaller than the modulus");
  *out = limbs_to_bytes(limbs_modpow(message, exponent, m), k);
  return true;
}

}  // namespace netcap
