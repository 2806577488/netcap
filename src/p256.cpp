// NIST P-256 (secp256r1) field and curve arithmetic, ECDSA (RFC 6979) and ECDH.
//
// The arithmetic is deliberately plain: a little-endian limb big integer with
// schoolbook multiply and bit-by-bit long division. That costs tens of
// milliseconds per scalar multiplication, which is fine here -- a MITM handshake
// does one ECDH and one signature, and certificates are minted once per host.
// Correctness and auditability matter more than speed for code that mints the
// keys this tool then presents to a browser.
#include "netcap/p256.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <random>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
// MinGW's bcrypt.h predates the raw secret KDF, so define the literal CNG uses.
#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"RAW_SECRET"
#endif
#elif defined(__linux__)
#include <sys/random.h>
#include <unistd.h>
#endif

namespace netcap {
namespace {

// ----------------------------------------------------------------- big integer
struct Nat {
  std::vector<u32> v;  // little-endian limbs, normalized: no high zero limbs
  bool zero() const { return v.empty(); }
};

void nat_norm(Nat& a) {
  while (!a.v.empty() && a.v.back() == 0) a.v.pop_back();
}

Nat nat_u32(u32 value) {
  Nat r;
  if (value != 0) r.v.push_back(value);
  return r;
}

Nat nat_from_be(const u8* p, std::size_t n) {
  Nat r;
  r.v.assign((n + 3) / 4, 0);
  for (std::size_t i = 0; i < n; ++i) {
    const std::size_t bitpos = (n - 1 - i) * 8;  // byte i sits this far from the right
    r.v[bitpos / 32] |= static_cast<u32>(p[i]) << (bitpos % 32);
  }
  nat_norm(r);
  return r;
}

Bytes nat_to_be(const Nat& a, std::size_t len) {
  Bytes out(len, 0);
  for (std::size_t i = 0; i < len; ++i) {
    const std::size_t bitpos = (len - 1 - i) * 8;
    const std::size_t limb = bitpos / 32;
    if (limb < a.v.size()) out[i] = static_cast<u8>((a.v[limb] >> (bitpos % 32)) & 0xff);
  }
  return out;
}

int nat_cmp(const Nat& a, const Nat& b) {
  if (a.v.size() != b.v.size()) return a.v.size() < b.v.size() ? -1 : 1;
  for (std::size_t i = a.v.size(); i-- > 0;) {
    if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
  }
  return 0;
}

Nat nat_add(const Nat& a, const Nat& b) {
  Nat r;
  const std::size_t n = std::max(a.v.size(), b.v.size());
  r.v.assign(n, 0);
  u64 carry = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const u64 cur = carry + (i < a.v.size() ? a.v[i] : 0u) + (i < b.v.size() ? b.v[i] : 0u);
    r.v[i] = static_cast<u32>(cur);
    carry = cur >> 32;
  }
  if (carry != 0) r.v.push_back(static_cast<u32>(carry));
  nat_norm(r);
  return r;
}

// Requires a >= b.
Nat nat_sub(const Nat& a, const Nat& b) {
  Nat r;
  r.v.assign(a.v.size(), 0);
  i64 borrow = 0;
  for (std::size_t i = 0; i < a.v.size(); ++i) {
    i64 cur = static_cast<i64>(a.v[i]) - (i < b.v.size() ? static_cast<i64>(b.v[i]) : 0) - borrow;
    if (cur < 0) {
      cur += (1LL << 32);
      borrow = 1;
    } else {
      borrow = 0;
    }
    r.v[i] = static_cast<u32>(cur);
  }
  nat_norm(r);
  return r;
}

Nat nat_mul(const Nat& a, const Nat& b) {
  Nat r;
  if (a.zero() || b.zero()) return r;
  r.v.assign(a.v.size() + b.v.size(), 0);
  for (std::size_t i = 0; i < a.v.size(); ++i) {
    u64 carry = 0;
    for (std::size_t j = 0; j < b.v.size(); ++j) {
      const u64 cur = static_cast<u64>(r.v[i + j]) +
                      static_cast<u64>(a.v[i]) * static_cast<u64>(b.v[j]) + carry;
      r.v[i + j] = static_cast<u32>(cur);
      carry = cur >> 32;
    }
    std::size_t k = i + b.v.size();
    while (carry != 0) {
      const u64 cur = static_cast<u64>(r.v[k]) + carry;
      r.v[k] = static_cast<u32>(cur);
      carry = cur >> 32;
      ++k;
    }
  }
  nat_norm(r);
  return r;
}

Nat nat_shl1(const Nat& a) {
  Nat r;
  r.v.assign(a.v.size(), 0);
  u32 carry = 0;
  for (std::size_t i = 0; i < a.v.size(); ++i) {
    const u32 next = a.v[i] >> 31;
    r.v[i] = (a.v[i] << 1) | carry;
    carry = next;
  }
  if (carry != 0) r.v.push_back(carry);
  nat_norm(r);
  return r;
}

std::size_t nat_bitlen(const Nat& a) {
  if (a.zero()) return 0;
  std::size_t bits = (a.v.size() - 1) * 32;
  u32 top = a.v.back();
  while (top != 0) {
    ++bits;
    top >>= 1;
  }
  return bits;
}

int nat_bit(const Nat& a, std::size_t i) {
  const std::size_t limb = i / 32;
  if (limb >= a.v.size()) return 0;
  return static_cast<int>((a.v[limb] >> (i % 32)) & 1u);
}

void nat_set_bit(Nat& a, std::size_t i) {
  const std::size_t limb = i / 32;
  if (limb >= a.v.size()) a.v.resize(limb + 1, 0);
  a.v[limb] |= (1u << (i % 32));
}

// Schoolbook binary long division: exact, and easy to check by hand.
void nat_divmod(const Nat& a, const Nat& m, Nat* q, Nat* r) {
  Nat quo;
  Nat rem;
  const std::size_t bits = nat_bitlen(a);
  if (bits != 0) quo.v.assign((bits + 31) / 32, 0);
  for (std::size_t i = bits; i-- > 0;) {
    rem = nat_shl1(rem);
    if (nat_bit(a, i)) {
      if (rem.v.empty()) rem.v.push_back(0);
      rem.v[0] |= 1u;
    }
    if (nat_cmp(rem, m) >= 0) {
      rem = nat_sub(rem, m);
      nat_set_bit(quo, i);
    }
  }
  nat_norm(rem);
  nat_norm(quo);
  if (q != nullptr) *q = quo;
  if (r != nullptr) *r = rem;
}

Nat nat_mod(const Nat& a, const Nat& m) {
  Nat rem;
  nat_divmod(a, m, nullptr, &rem);
  return rem;
}

Nat nat_div(const Nat& a, const Nat& m) {
  Nat quo;
  nat_divmod(a, m, &quo, nullptr);
  return quo;
}

Nat nat_pow(const Nat& base, const Nat& exp, const Nat& mod) {
  Nat result = nat_u32(1);
  Nat b = nat_mod(base, mod);
  const std::size_t bits = nat_bitlen(exp);
  for (std::size_t i = bits; i-- > 0;) {
    result = nat_mod(nat_mul(result, result), mod);
    if (nat_bit(exp, i)) result = nat_mod(nat_mul(result, b), mod);
  }
  return result;
}

// ------------------------------------------------------------------- constants
Nat nat_from_hex(const char* hex) {
  Nat r;
  const std::size_t len = std::strlen(hex);
  r.v.assign((len / 8) + 1, 0);
  for (std::size_t i = 0; i < len; ++i) {
    const char c = hex[len - 1 - i];
    u32 nibble = 0;
    if (c >= '0' && c <= '9') {
      nibble = static_cast<u32>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      nibble = static_cast<u32>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      nibble = static_cast<u32>(c - 'A' + 10);
    }
    r.v[i / 8] |= nibble << ((i % 8) * 4);
  }
  nat_norm(r);
  return r;
}

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1, a = -3, b = 0x5ac635d8...
const Nat& kP() {
  static const Nat p = nat_from_hex(
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  return p;
}
const Nat& kN() {
  static const Nat n = nat_from_hex(
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  return n;
}
const Nat& kB() {
  static const Nat b = nat_from_hex(
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
  return b;
}
const Nat& kGx() {
  static const Nat g = nat_from_hex(
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
  return g;
}
const Nat& kGy() {
  static const Nat g = nat_from_hex(
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  return g;
}

// ------------------------------------------------------------------ modular ops
Nat mod_add(const Nat& a, const Nat& b, const Nat& m) {
  Nat s = nat_add(a, b);
  if (nat_cmp(s, m) >= 0) s = nat_sub(s, m);
  return s;
}

Nat mod_sub(const Nat& a, const Nat& b, const Nat& m) {
  if (nat_cmp(a, b) >= 0) return nat_sub(a, b);
  return nat_sub(nat_add(a, m), b);
}

Nat mod_mul(const Nat& a, const Nat& b, const Nat& m) { return nat_mod(nat_mul(a, b), m); }

Nat mod_small(const Nat& a, u32 k, const Nat& m) { return mod_mul(a, nat_u32(k), m); }

Nat mod_inv(const Nat& a, const Nat& m) {
  return nat_pow(a, nat_sub(m, nat_u32(2)), m);  // Fermat: m is prime
}

// ----------------------------------------------------------------- Jacobian ops
struct Jac {
  Nat x, y, z;
  bool inf = true;
};

Jac jac_double(const Jac& p) {
  if (p.inf || p.y.zero()) return Jac{};
  const Nat& m = kP();
  const Nat delta = mod_mul(p.z, p.z, m);
  const Nat gamma = mod_mul(p.y, p.y, m);
  const Nat beta = mod_mul(p.x, gamma, m);
  const Nat alpha = mod_small(mod_mul(mod_sub(p.x, delta, m), mod_add(p.x, delta, m), m), 3, m);
  const Nat x3 = mod_sub(mod_mul(alpha, alpha, m), mod_small(beta, 8, m), m);
  const Nat y3 = mod_sub(mod_mul(alpha, mod_sub(mod_small(beta, 4, m), x3, m), m), mod_small(mod_mul(gamma, gamma, m), 8, m), m);
  const Nat yz = mod_add(p.y, p.z, m);
  const Nat z3 = mod_sub(mod_sub(mod_mul(yz, yz, m), gamma, m), delta, m);
  Jac r;
  r.inf = false;
  r.x = x3;
  r.y = y3;
  r.z = z3;
  return r;
}

Jac jac_add(const Jac& p, const Jac& q) {
  if (p.inf) return q;
  if (q.inf) return p;
  const Nat& m = kP();
  const Nat z1z1 = mod_mul(p.z, p.z, m);
  const Nat z2z2 = mod_mul(q.z, q.z, m);
  const Nat u1 = mod_mul(p.x, z2z2, m);
  const Nat u2 = mod_mul(q.x, z1z1, m);
  const Nat s1 = mod_mul(mod_mul(p.y, q.z, m), z2z2, m);
  const Nat s2 = mod_mul(mod_mul(q.y, p.z, m), z1z1, m);
  if (nat_cmp(u1, u2) == 0) {
    if (nat_cmp(s1, s2) == 0) return jac_double(p);
    return Jac{};  // P + (-P) = infinity
  }
  const Nat h = mod_sub(u2, u1, m);
  const Nat i = mod_small(h, 2, m);
  const Nat ii = mod_mul(i, i, m);
  const Nat j = mod_mul(h, ii, m);
  const Nat r = mod_sub(mod_add(s2, s2, m), mod_add(s1, s1, m), m);
  const Nat v = mod_mul(u1, ii, m);
  const Nat x3 = mod_sub(mod_sub(mod_mul(r, r, m), j, m), mod_add(v, v, m), m);
  const Nat y3 = mod_sub(mod_mul(r, mod_sub(v, x3, m), m), mod_mul(mod_add(s1, s1, m), j, m), m);
  const Nat zz = mod_add(p.z, q.z, m);
  const Nat z3 = mod_mul(mod_sub(mod_sub(mod_mul(zz, zz, m), z1z1, m), z2z2, m), h, m);
  Jac out;
  out.inf = false;
  out.x = x3;
  out.y = y3;
  out.z = z3;
  return out;
}

Jac jac_generator() {
  Jac g;
  g.inf = false;
  g.x = kGx();
  g.y = kGy();
  g.z = nat_u32(1);
  return g;
}

// Double-and-add over the scalar bits. Not constant time: this code mints
// certificates and performs one ECDH per intercepted host, it is not a signing
// service that has to resist timing attacks from local processes.
Jac jac_mul(const Nat& k, const Jac& p) {
  Jac r;
  const std::size_t bits = nat_bitlen(k);
  for (std::size_t i = bits; i-- > 0;) {
    r = jac_double(r);
    if (nat_bit(k, i)) r = jac_add(r, p);
  }
  return r;
}

bool jac_to_affine(const Jac& p, Nat* x, Nat* y) {
  if (p.inf) return false;
  const Nat& m = kP();
  const Nat zinv = mod_inv(p.z, m);
  const Nat zinv2 = mod_mul(zinv, zinv, m);
  *x = mod_mul(p.x, zinv2, m);
  *y = mod_mul(p.y, mod_mul(zinv2, zinv, m), m);
  return true;
}

bool on_curve(const Nat& x, const Nat& y) {
  const Nat& m = kP();
  const Nat lhs = mod_mul(y, y, m);
  const Nat x3 = mod_mul(mod_mul(x, x, m), x, m);
  const Nat rhs = mod_add(mod_add(x3, mod_sub(m, mod_small(x, 3, m), m), m), kB(), m);
  return nat_cmp(lhs, rhs) == 0;
}

Bytes be32(const Nat& a) { return nat_to_be(a, 32); }

Nat from_be32(const Bytes& b) { return nat_from_be(b.data(), b.size()); }

// ---------------------------------------------------------------- RFC 6979 DRBG
// Deterministic ECDSA nonces: no per-signature randomness, so a broken RNG can
// never repeat a nonce and leak the CA key.
class Rfc6979 {
 public:
  void seed(const Bytes& d, const u8* hash32, const Nat& n) {
    v_.assign(32, 0x01);
    k_.assign(32, 0x00);
    const Bytes h(hash32, hash32 + 32);
    const Bytes z = be32(nat_mod(nat_from_be(h.data(), h.size()), n));
    Bytes first(1, 0x00);
    Bytes second(1, 0x01);
    first.insert(first.end(), d.begin(), d.end());
    first.insert(first.end(), z.begin(), z.end());
    second.insert(second.end(), d.begin(), d.end());
    second.insert(second.end(), z.begin(), z.end());
    mix(first);
    mix(second);
  }

  // Yields the next candidate nonce; false once the DRBG gives up.
  bool next(const Nat& n, Nat* out) {
    for (int tries = 0; tries < 64; ++tries) {
      Bytes t;
      while (t.size() < 32) {
        v_ = hmac_sha256(k_, v_);
        t.insert(t.end(), v_.begin(), v_.end());
      }
      const Nat cand = nat_from_be(t.data(), 32);
      if (!cand.zero() && nat_cmp(cand, n) < 0) {
        *out = cand;
        return true;
      }
      Bytes retry = v_;
      retry.push_back(0x00);
      mix(retry);
    }
    return false;
  }

  void reseed_after_failure() {
    Bytes retry = v_;
    retry.push_back(0x00);
    mix(retry);
  }

 private:
  void mix(const Bytes& data) {
    Bytes in = v_;
    in.insert(in.end(), data.begin(), data.end());
    k_ = hmac_sha256(k_, in);
    v_ = hmac_sha256(k_, v_);
  }

  Bytes v_;
  Bytes k_;
};

bool random_scalar_in_range(const Nat& n, Nat* out) {
  for (int tries = 0; tries < 64; ++tries) {
    u8 buf[32];
    if (!random_bytes(buf, sizeof(buf))) return false;
    const Nat cand = nat_from_be(buf, sizeof(buf));
    if (cand.zero() || nat_cmp(cand, n) >= 0) continue;
    *out = cand;
    return true;
  }
  return false;
}

// ------------------------------------------------- fast Montgomery field (P-256)
// The arithmetic above is easy to audit but slow: every `mod_mul` ends in a
// bit-by-bit long division, so one scalar multiplication (~2000 field
// operations) costs ~137 ms -- and a MITM handshake performs two of them. The
// block below is the same curve on four 64-bit limbs with Montgomery reduction
// (CIOS) and a windowed-NAF scalar multiplication, which is the construction
// OpenSSL's nistz256, BoringSSL and ring use, minus their hand-written assembly.
//
// Every constant (R^2, the Montgomery word, m-2) is derived at run time from the
// same `Nat` constants the slow path uses, so there are no magic literals to
// mistype, and nothing here is secret-dependent: field operations and the
// conditional subtraction at the end of CIOS run in constant time, and the
// scalar multiplication is the same double-and-add shape as before (this code
// mints certificates for intercepted hosts, it is not a signing oracle exposed
// to a local attacker).
using u128 = unsigned __int128;

struct Fe {
  u64 v[4];  // little-endian limbs
};

struct Mont {
  u64 m[4];
  u64 inv;    // -m^-1 mod 2^64, the word CIOS needs
  u64 rr[4];  // R^2 mod m in plain form: multiplying by it enters Montgomery form
  Nat pm2;    // m - 2, the exponent of the Fermat inverse
};

void nat_to_limbs4(const Nat& a, u64* out) {
  const int limbs = static_cast<int>(a.v.size());
  for (int i = 0; i < 4; ++i) {
    const u64 lo = (2 * i < limbs) ? static_cast<u64>(a.v[2 * i]) : 0u;
    const u64 hi = (2 * i + 1 < limbs) ? static_cast<u64>(a.v[2 * i + 1]) : 0u;
    out[i] = lo | (hi << 32);
  }
}

Nat nat_shr1(const Nat& a) {
  Nat r;
  if (a.v.empty()) return r;
  r.v.assign(a.v.size(), 0);
  u32 carry = 0;
  for (std::size_t i = a.v.size(); i-- > 0;) {
    r.v[i] = (a.v[i] >> 1) | (carry << 31);
    carry = a.v[i] & 1u;
  }
  nat_norm(r);
  return r;
}

// Newton's iteration: each round doubles the number of correct low bits.
u64 mont_inv_word(u64 m0) {
  u64 x = 1;
  for (int i = 0; i < 6; ++i) x *= 2u - m0 * x;
  return ~x + 1u;  // -m^-1
}

Mont mont_build(const Nat& mod) {
  Mont M{};
  nat_to_limbs4(mod, M.m);
  M.inv = mont_inv_word(M.m[0]);
  Nat r;  // zero, then bit 256 -- nat_u32(1) would leave bit 0 set as well
  nat_set_bit(r, 256);                       // R = 2^256
  const Nat rmod = nat_mod(r, mod);          // R mod m
  nat_to_limbs4(nat_mod(nat_mul(rmod, rmod), mod), M.rr);  // R^2 mod m
  M.pm2 = nat_sub(mod, nat_u32(2));
  return M;
}

const Mont& mont_p() {
  static const Mont M = mont_build(kP());
  return M;
}

const Mont& mont_n() {
  static const Mont M = mont_build(kN());
  return M;
}

// True when the four limbs of `a` are >= the four limbs of `b`.
bool limbs_ge(const u64* a, const u64* b) {
  for (int i = 3; i >= 0; --i) {
    if (a[i] != b[i]) return a[i] > b[i];
  }
  return true;
}

void limbs_sub_in_place(u64* a, const u64* b) {
  u64 borrow = 0;
  for (int i = 0; i < 4; ++i) {
    const u64 bi = b[i];
    const u64 sub = bi + borrow;
    const bool wrap = sub < bi;
    const u64 ai = a[i];
    const u64 res = ai - sub;
    a[i] = res;
    borrow = (wrap || ai < sub) ? 1u : 0u;
  }
}

// 4x4 limbs -> 8 limbs.  Explicitly unrolled: GCC keeps the sixteen 64x64->128
// multiplies in registers this way, while the loop form spills them.
void limbs_mul4(const u64* a, const u64* b, u64* t) {
  const u64 a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
  const u64 b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3];
  u64 t0, t1, t2, t3;
  u128 c = static_cast<u128>(a0) * b0;
  t0 = static_cast<u64>(c);
  c = static_cast<u128>(a1) * b0 + static_cast<u64>(c >> 64);
  t1 = static_cast<u64>(c);
  c = static_cast<u128>(a2) * b0 + (c >> 64);
  t2 = static_cast<u64>(c);
  c = static_cast<u128>(a3) * b0 + (c >> 64);
  t3 = static_cast<u64>(c);
  t[4] = static_cast<u64>(c >> 64);

  c = static_cast<u128>(a0) * b1 + t1;
  t1 = static_cast<u64>(c);
  c = static_cast<u128>(a1) * b1 + t2 + (c >> 64);
  t2 = static_cast<u64>(c);
  c = static_cast<u128>(a2) * b1 + t3 + (c >> 64);
  t3 = static_cast<u64>(c);
  c = static_cast<u128>(a3) * b1 + t[4] + (c >> 64);
  t[4] = static_cast<u64>(c);
  t[5] = static_cast<u64>(c >> 64);

  c = static_cast<u128>(a0) * b2 + t2;
  t2 = static_cast<u64>(c);
  c = static_cast<u128>(a1) * b2 + t3 + (c >> 64);
  t3 = static_cast<u64>(c);
  c = static_cast<u128>(a2) * b2 + t[4] + (c >> 64);
  t[4] = static_cast<u64>(c);
  c = static_cast<u128>(a3) * b2 + t[5] + (c >> 64);
  t[5] = static_cast<u64>(c);
  t[6] = static_cast<u64>(c >> 64);

  c = static_cast<u128>(a0) * b3 + t3;
  t3 = static_cast<u64>(c);
  c = static_cast<u128>(a1) * b3 + t[4] + (c >> 64);
  t[4] = static_cast<u64>(c);
  c = static_cast<u128>(a2) * b3 + t[5] + (c >> 64);
  t[5] = static_cast<u64>(c);
  c = static_cast<u128>(a3) * b3 + t[6] + (c >> 64);
  t[6] = static_cast<u64>(c);
  t[7] = static_cast<u64>(c >> 64);

  t[0] = t0;
  t[1] = t1;
  t[2] = t2;
  t[3] = t3;
}

// Montgomery reduction of an 8-limb value, in place: four rounds of
// `t += q * m` that zero one low limb each, then one conditional subtraction.
// Separated from the multiply (SOS instead of CIOS) because the two halves then
// have independent carry chains and the out-of-order core overlaps them.
Fe mont_reduce8(u64* t, const Mont& M) {
  const u64 m0 = M.m[0], m1 = M.m[1], m2 = M.m[2], m3 = M.m[3];
  u64 extra = 0;
  for (int i = 0; i < 4; ++i) {
    const u64 q = t[i] * M.inv;
    u128 c = static_cast<u128>(q) * m0 + t[i];
    c = static_cast<u128>(q) * m1 + t[i + 1] + (c >> 64);
    t[i + 1] = static_cast<u64>(c);
    c = static_cast<u128>(q) * m2 + t[i + 2] + (c >> 64);
    t[i + 2] = static_cast<u64>(c);
    c = static_cast<u128>(q) * m3 + t[i + 3] + (c >> 64);
    t[i + 3] = static_cast<u64>(c);
    u128 s = static_cast<u128>(t[i + 4]) + static_cast<u64>(c >> 64);
    t[i + 4] = static_cast<u64>(s);
    u64 carry = static_cast<u64>(s >> 64);
    for (int k = i + 5; k < 8; ++k) {
      s = static_cast<u128>(t[k]) + carry;
      t[k] = static_cast<u64>(s);
      carry = static_cast<u64>(s >> 64);
    }
    extra += carry;
  }
  Fe r;
  r.v[0] = t[4];
  r.v[1] = t[5];
  r.v[2] = t[6];
  r.v[3] = t[7];
  if (extra != 0 || limbs_ge(r.v, M.m)) limbs_sub_in_place(r.v, M.m);
  return r;
}

// CIOS vs SOS: same 32 multiplies, but the multiply and the reduction are now
// separate passes.  Measured on this machine it is ~40% faster per multiply,
// which is most of what a scalar multiplication spends its time on.
Fe fe_mont_mul(const Fe& a, const Fe& b, const Mont& M) {
  u64 t[8];
  limbs_mul4(a.v, b.v, t);
  return mont_reduce8(t, M);
}

Fe fe_add(const Fe& a, const Fe& b, const Mont& M) {
  Fe r;
  u64 carry = 0;
  for (int i = 0; i < 4; ++i) {
    const u128 s = static_cast<u128>(a.v[i]) + b.v[i] + carry;
    r.v[i] = static_cast<u64>(s);
    carry = static_cast<u64>(s >> 64);
  }
  if (carry != 0 || limbs_ge(r.v, M.m)) limbs_sub_in_place(r.v, M.m);
  return r;
}

Fe fe_sub(const Fe& a, const Fe& b, const Mont& M) {
  Fe r;
  u64 borrow = 0;
  for (int i = 0; i < 4; ++i) {
    const u64 bi = b.v[i];
    const u64 sub = bi + borrow;
    const bool wrap = sub < bi;
    const u64 ai = a.v[i];
    const u64 res = ai - sub;
    r.v[i] = res;
    borrow = (wrap || ai < sub) ? 1u : 0u;
  }
  if (borrow != 0) {
    u64 carry = 0;
    for (int i = 0; i < 4; ++i) {
      const u128 s = static_cast<u128>(r.v[i]) + M.m[i] + carry;
      r.v[i] = static_cast<u64>(s);
      carry = static_cast<u64>(s >> 64);
    }
  }
  return r;
}

Fe fe_to_mont(const Fe& plain, const Mont& M) {
  const Fe rr{M.rr[0], M.rr[1], M.rr[2], M.rr[3]};
  return fe_mont_mul(plain, rr, M);
}

Fe fe_from_mont(const Fe& mont, const Mont& M) { return fe_mont_mul(mont, Fe{1, 0, 0, 0}, M); }

Fe fe_one(const Mont& M) { return fe_to_mont(Fe{1, 0, 0, 0}, M); }

// Small multiples by repeated addition: cheaper than entering and leaving the
// Montgomery domain, and there is nothing to get wrong.
Fe fe_times_small(const Fe& a, u32 k, const Mont& M) {
  Fe r = a;
  for (u32 i = 1; i < k; ++i) r = fe_add(r, a, M);
  return r;
}

bool fe_zero(const Fe& a) { return (a.v[0] | a.v[1] | a.v[2] | a.v[3]) == 0; }

bool fe_equal(const Fe& a, const Fe& b) {
  return ((a.v[0] ^ b.v[0]) | (a.v[1] ^ b.v[1]) | (a.v[2] ^ b.v[2]) | (a.v[3] ^ b.v[3])) == 0;
}

Fe fe_pow(const Fe& base, const Nat& exp, const Mont& M) {
  Fe result = fe_one(M);
  Fe b = base;
  for (std::size_t i = nat_bitlen(exp); i-- > 0;) {
    result = fe_mont_mul(result, result, M);
    if (nat_bit(exp, i)) result = fe_mont_mul(result, b, M);
  }
  return result;
}

// Binary extended Euclid (HAC 14.61) on four limbs.  Fermat's little theorem
// needs ~384 Montgomery multiplications per inversion; this needs ~512 shift,
// compare and subtract rounds instead.  The running coefficients stay in
// [0, p), so they need one extra limb for the (x + p) >> 1 step.
bool u256_is_zero(const u64* a) { return (a[0] | a[1] | a[2] | a[3]) == 0; }
bool u256_is_one(const u64* a) { return a[0] == 1 && (a[1] | a[2] | a[3]) == 0; }

bool u256_lt(const u64* a, const u64* b) {
  for (int i = 3; i >= 0; --i) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return false;
}

void u256_sub(u64* a, const u64* b) {  // a -= b, assumes a >= b
  u64 borrow = 0;
  for (int i = 0; i < 4; ++i) {
    const u64 ai = a[i];
    const u64 bi = b[i];
    a[i] = ai - bi - borrow;
    borrow = (ai < bi || (borrow != 0 && ai == bi)) ? 1u : 0u;
  }
}

void u256_shr1(u64* a) {
  for (int i = 0; i < 3; ++i) a[i] = (a[i] >> 1) | (a[i + 1] << 63);
  a[3] >>= 1;
}

bool u320_lt(const u64* a, const u64* b) {
  for (int i = 4; i >= 0; --i) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return false;
}

void u320_add(u64* a, const u64* b) {  // a += b, five limbs each
  unsigned __int128 carry = 0;
  for (int i = 0; i < 5; ++i) {
    const unsigned __int128 cur = static_cast<unsigned __int128>(a[i]) + b[i] + carry;
    a[i] = static_cast<u64>(cur);
    carry = cur >> 64;
  }
}

void u320_sub(u64* a, const u64* b) {  // a -= b, assumes a >= b
  u64 borrow = 0;
  for (int i = 0; i < 5; ++i) {
    const u64 ai = a[i];
    const u64 bi = b[i];
    a[i] = ai - bi - borrow;
    borrow = (ai < bi || (borrow != 0 && ai == bi)) ? 1u : 0u;
  }
}

void u320_shr1(u64* a) {
  for (int i = 0; i < 4; ++i) a[i] = (a[i] >> 1) | (a[i + 1] << 63);
  a[4] >>= 1;
}

bool u256_mod_inverse(const u64* a, const u64* p, u64* out) {
  u64 u[4];
  u64 v[4];
  std::memcpy(u, a, sizeof u);
  std::memcpy(v, p, sizeof v);
  u64 x1[5] = {1, 0, 0, 0, 0};
  u64 x2[5] = {0, 0, 0, 0, 0};
  const u64 p5[5] = {p[0], p[1], p[2], p[3], 0};
  while (!u256_is_one(u) && !u256_is_one(v)) {
    if (u256_is_zero(u) || u256_is_zero(v)) return false;  // not invertible
    while ((u[0] & 1u) == 0u) {
      u256_shr1(u);
      if ((x1[0] & 1u) != 0u) u320_add(x1, p5);
      u320_shr1(x1);
    }
    while ((v[0] & 1u) == 0u) {
      u256_shr1(v);
      if ((x2[0] & 1u) != 0u) u320_add(x2, p5);
      u320_shr1(x2);
    }
    if (!u256_lt(u, v)) {
      u256_sub(u, v);
      if (u320_lt(x1, x2)) u320_add(x1, p5);
      u320_sub(x1, x2);
    } else {
      u256_sub(v, u);
      if (u320_lt(x2, x1)) u320_add(x2, p5);
      u320_sub(x2, x1);
    }
  }
  const u64* r = u256_is_one(u) ? x1 : x2;
  std::memcpy(out, r, sizeof(u64) * 4);
  return true;
}

Fe fe_inv(const Fe& a, const Mont& M) {
  // Invert the plain integer the Montgomery value stands for, then step back
  // into the Montgomery domain: two multiplications instead of ~384.
  const Fe plain = fe_from_mont(a, M);
  u64 inv[4];
  if (!u256_mod_inverse(plain.v, M.m, inv)) return Fe{0, 0, 0, 0};
  Fe out;
  std::memcpy(out.v, inv, sizeof out.v);
  return fe_to_mont(out, M);
}

Fe fe_from_bytes(const u8* p, const Mont& M) {
  Fe plain{};
  for (int i = 0; i < 4; ++i) {
    u64 limb = 0;
    for (int j = 0; j < 8; ++j) limb = (limb << 8) | p[(3 - i) * 8 + j];
    plain.v[i] = limb;
  }
  return fe_to_mont(plain, M);
}

Bytes fe_to_bytes(const Fe& a, const Mont& M) {
  const Fe t = fe_from_mont(a, M);
  Bytes out(32, 0);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 8; ++j) out[(3 - i) * 8 + j] = static_cast<u8>(t.v[i] >> ((7 - j) * 8));
  }
  return out;
}

bool bytes_lt_p(const u8* p) { return nat_cmp(nat_from_be(p, 32), kP()) < 0; }

// Raw limbs as big-endian bytes, with no Montgomery conversion: only the
// self-check needs this, to look at R itself rather than at its plain form.
Bytes fe_raw_bytes(const Fe& a) {
  Bytes out(32, 0);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 8; ++j) out[(3 - i) * 8 + j] = static_cast<u8>(a.v[i] >> ((7 - j) * 8));
  }
  return out;
}

// ------------------------------------------------------- curve points (Jacobian)
struct JPoint {
  Fe x, y, z;
  bool inf = true;
};

constexpr int kWindow = 5;  // wNAF width: 256 doublings + ~51 additions

JPoint jp_double(const JPoint& p, const Mont& M) {
  if (p.inf || fe_zero(p.y)) return JPoint{};
  const Fe delta = fe_mont_mul(p.z, p.z, M);
  const Fe gamma = fe_mont_mul(p.y, p.y, M);
  const Fe beta = fe_mont_mul(p.x, gamma, M);
  const Fe alpha =
      fe_times_small(fe_mont_mul(fe_sub(p.x, delta, M), fe_add(p.x, delta, M), M), 3, M);
  const Fe x3 = fe_sub(fe_mont_mul(alpha, alpha, M), fe_times_small(beta, 8, M), M);
  const Fe y3 = fe_sub(fe_mont_mul(alpha, fe_sub(fe_times_small(beta, 4, M), x3, M), M),
                       fe_times_small(fe_mont_mul(gamma, gamma, M), 8, M), M);
  const Fe yz = fe_add(p.y, p.z, M);
  const Fe z3 = fe_sub(fe_sub(fe_mont_mul(yz, yz, M), gamma, M), delta, M);
  JPoint r;
  r.inf = false;
  r.x = x3;
  r.y = y3;
  r.z = z3;
  return r;
}

JPoint jp_add(const JPoint& p, const JPoint& q, const Mont& M) {
  if (p.inf) return q;
  if (q.inf) return p;
  const Fe z1z1 = fe_mont_mul(p.z, p.z, M);
  const Fe z2z2 = fe_mont_mul(q.z, q.z, M);
  const Fe u1 = fe_mont_mul(p.x, z2z2, M);
  const Fe u2 = fe_mont_mul(q.x, z1z1, M);
  const Fe s1 = fe_mont_mul(fe_mont_mul(p.y, q.z, M), z2z2, M);
  const Fe s2 = fe_mont_mul(fe_mont_mul(q.y, p.z, M), z1z1, M);
  if (fe_equal(u1, u2)) {
    if (fe_equal(s1, s2)) return jp_double(p, M);
    return JPoint{};  // P + (-P)
  }
  const Fe h = fe_sub(u2, u1, M);
  const Fe i = fe_times_small(h, 2, M);
  const Fe ii = fe_mont_mul(i, i, M);
  const Fe j = fe_mont_mul(h, ii, M);
  const Fe r = fe_sub(fe_times_small(s2, 2, M), fe_times_small(s1, 2, M), M);
  const Fe v = fe_mont_mul(u1, ii, M);
  const Fe x3 = fe_sub(fe_sub(fe_mont_mul(r, r, M), j, M), fe_times_small(v, 2, M), M);
  const Fe y3 = fe_sub(fe_mont_mul(r, fe_sub(v, x3, M), M),
                       fe_mont_mul(fe_times_small(s1, 2, M), j, M), M);
  const Fe zz = fe_add(p.z, q.z, M);
  const Fe z3 = fe_mont_mul(fe_sub(fe_sub(fe_mont_mul(zz, zz, M), z1z1, M), z2z2, M), h, M);
  JPoint out;
  out.inf = false;
  out.x = x3;
  out.y = y3;
  out.z = z3;
  return out;
}

// Mixed addition: the second operand is affine (Z = 1), which saves four field
// multiplications per addition.  The fixed-base comb below lives on this.
JPoint jp_add_mixed(const JPoint& p, const Fe& qx, const Fe& qy, const Mont& M) {
  if (p.inf) {
    JPoint out;
    out.inf = false;
    out.x = qx;
    out.y = qy;
    out.z = fe_one(M);
    return out;
  }
  const Fe z1z1 = fe_mont_mul(p.z, p.z, M);
  const Fe u2 = fe_mont_mul(qx, z1z1, M);
  const Fe s2 = fe_mont_mul(fe_mont_mul(qy, p.z, M), z1z1, M);
  if (fe_equal(p.x, u2)) {
    if (fe_equal(p.y, s2)) return jp_double(p, M);
    return JPoint{};  // P + (-P)
  }
  // madd-2007-bl
  const Fe h = fe_sub(u2, p.x, M);
  const Fe hh = fe_mont_mul(h, h, M);
  const Fe i = fe_times_small(hh, 4, M);
  const Fe j = fe_mont_mul(h, i, M);
  const Fe r = fe_times_small(fe_sub(s2, p.y, M), 2, M);
  const Fe v = fe_mont_mul(p.x, i, M);
  const Fe x3 = fe_sub(fe_sub(fe_mont_mul(r, r, M), j, M), fe_times_small(v, 2, M), M);
  const Fe y3 = fe_sub(fe_mont_mul(r, fe_sub(v, x3, M), M),
                       fe_times_small(fe_mont_mul(p.y, j, M), 2, M), M);
  const Fe zh = fe_add(p.z, h, M);
  const Fe z3 = fe_sub(fe_sub(fe_mont_mul(zh, zh, M), z1z1, M), hh, M);
  JPoint out;
  out.inf = false;
  out.x = x3;
  out.y = y3;
  out.z = z3;
  return out;
}

JPoint jp_negate(const JPoint& p, const Mont& M) {
  JPoint r = p;
  if (!r.inf) r.y = fe_sub(Fe{0, 0, 0, 0}, p.y, M);
  return r;
}

bool jp_to_affine(const JPoint& p, Fe* x, Fe* y, const Mont& M) {
  if (p.inf) return false;
  const Fe zinv = fe_inv(p.z, M);
  const Fe zinv2 = fe_mont_mul(zinv, zinv, M);
  *x = fe_mont_mul(p.x, zinv2, M);
  *y = fe_mont_mul(p.y, fe_mont_mul(zinv2, zinv, M), M);
  return true;
}

JPoint jp_from_bytes(const u8* x_be, const u8* y_be, const Mont& M) {
  JPoint p;
  p.inf = false;
  p.x = fe_from_bytes(x_be, M);
  p.y = fe_from_bytes(y_be, M);
  p.z = fe_one(M);
  return p;
}

JPoint jp_generator(const Mont& M) { return jp_from_bytes(be32(kGx()).data(), be32(kGy()).data(), M); }

bool on_curve_fast(const Fe& x, const Fe& y, const Mont& M) {
  const Fe b = fe_from_bytes(be32(kB()).data(), M);
  const Fe lhs = fe_mont_mul(y, y, M);
  const Fe x3 = fe_mont_mul(fe_mont_mul(x, x, M), x, M);
  const Fe rhs = fe_add(fe_add(x3, fe_sub(Fe{0, 0, 0, 0}, fe_times_small(x, 3, M), M), M), b, M);
  return fe_equal(lhs, rhs);
}

// width-w non-adjacent form: sparse signed digits, so a 256-bit scalar needs
// ~51 additions instead of ~128 with plain double-and-add.
void wnaf_digits(const Nat& k, int width, std::vector<int>* digits) {
  digits->clear();
  Nat n = k;
  const u32 mask = (1u << width) - 1u;
  const int half = 1 << (width - 1);
  const int full = 1 << width;
  while (!n.zero()) {
    if ((n.v[0] & 1u) == 0u) {
      digits->push_back(0);
    } else {
      int d = static_cast<int>(n.v[0] & mask);
      if (d >= half) d -= full;
      digits->push_back(d);
      n = (d > 0) ? nat_sub(n, nat_u32(static_cast<u32>(d)))
                  : nat_add(n, nat_u32(static_cast<u32>(-d)));
    }
    n = nat_shr1(n);
  }
}

std::vector<JPoint> wnaf_table(const JPoint& p, int width, const Mont& M) {
  const int size = 1 << (width - 2);
  std::vector<JPoint> table(static_cast<std::size_t>(size));
  table[0] = p;
  const JPoint p2 = jp_double(p, M);
  for (int i = 1; i < size; ++i) {
    table[static_cast<std::size_t>(i)] = jp_add(table[static_cast<std::size_t>(i - 1)], p2, M);
  }
  return table;
}

JPoint jp_mul_table(const Nat& k, const std::vector<JPoint>& table, int width, const Mont& M) {
  std::vector<int> digits;
  wnaf_digits(k, width, &digits);
  JPoint r;
  for (std::size_t i = digits.size(); i-- > 0;) {
    r = jp_double(r, M);
    const int d = digits[i];
    if (d > 0) {
      r = jp_add(r, table[static_cast<std::size_t>(d / 2)], M);
    } else if (d < 0) {
      r = jp_add(r, jp_negate(table[static_cast<std::size_t>(-d / 2)], M), M);
    }
  }
  return r;
}

JPoint jp_mul(const Nat& k, const JPoint& p, const Mont& M) {
  return jp_mul_table(k, wnaf_table(p, kWindow, M), kWindow, M);
}

// The generator's table never changes, so it is built once on first use.  The
// modulus is always the curve field, so the parameter is documentation only.
const std::vector<JPoint>& generator_table(const Mont& /*M*/) {
  static const std::vector<JPoint> table = wnaf_table(jp_generator(mont_p()), kWindow, mont_p());
  return table;
}

// ---- fixed-base comb -------------------------------------------------------
// G is the same point for every scalar, so all of its multiples can be computed
// once: 64 windows of four bits each, held in affine coordinates.  A scalar
// multiplication then costs at most 64 mixed additions and no doublings at all,
// which is what keeps key generation and signing off the doubling chain.
constexpr int kCombWindow = 4;
constexpr int kCombWindows = 64;              // 64 * 4 = 256 bits
constexpr int kCombWidth = 1 << kCombWindow;  // 16 multiples per window

struct CombEntry {
  Fe x;
  Fe y;
  bool inf = true;
};

int nat_bit_at(const Nat& k, std::size_t index) { return nat_bit(k, index) ? 1 : 0; }

// Montgomery's batch inversion: one fe_inv for the whole window.
void batch_to_affine(std::vector<JPoint>* points, std::vector<Fe>* prefix, const Mont& M) {
  const std::size_t n = points->size();
  prefix->assign(n, fe_one(M));
  Fe acc = fe_one(M);
  for (std::size_t i = 0; i < n; ++i) {
    (*prefix)[i] = acc;
    if (!(*points)[i].inf) acc = fe_mont_mul(acc, (*points)[i].z, M);
  }
  Fe inv = fe_inv(acc, M);
  for (std::size_t i = n; i-- > 0;) {
    if ((*points)[i].inf) continue;
    const Fe z = fe_mont_mul(inv, (*prefix)[i], M);
    inv = fe_mont_mul(inv, (*points)[i].z, M);
    const Fe z2 = fe_mont_mul(z, z, M);
    (*points)[i].x = fe_mont_mul((*points)[i].x, z2, M);
    (*points)[i].y = fe_mont_mul((*points)[i].y, fe_mont_mul(z2, z, M), M);
    (*points)[i].z = fe_one(M);
  }
}

// Affine form of a wNAF table.  Mixed addition (8M + 3S) is roughly half the
// cost of adding a full Jacobian point (16M), and a verify builds each table
// exactly once, so the single batch inversion that produces these pays for
// itself within the first few digits.
struct AffineEntry {
  Fe x;
  Fe y;
  bool inf = true;
};

std::vector<AffineEntry> affine_table(const std::vector<JPoint>& table, const Mont& M) {
  std::vector<JPoint> points = table;
  std::vector<Fe> prefix;
  batch_to_affine(&points, &prefix, M);
  std::vector<AffineEntry> out(points.size());
  for (std::size_t i = 0; i < points.size(); ++i) {
    out[i].x = points[i].x;
    out[i].y = points[i].y;
    out[i].inf = points[i].inf;
  }
  return out;
}

// G's table is the same for every verification, so it is converted once.
const std::vector<AffineEntry>& generator_affine_table(const Mont& M) {
  static const std::vector<AffineEntry> table = affine_table(generator_table(M), mont_p());
  return table;
}
const std::vector<CombEntry>& generator_comb(const Mont& /*M*/) {
  static const std::vector<CombEntry> comb = []() {
    const Mont& m = mont_p();
    std::vector<CombEntry> table(static_cast<std::size_t>(kCombWindows) * kCombWidth);
    std::vector<JPoint> window(kCombWidth);
    std::vector<Fe> prefix;
    JPoint base = jp_generator(m);
    for (int j = 0; j < kCombWindows; ++j) {
      window[0] = JPoint{};  // window[0] is never looked up: digit 0 adds nothing
      window[1] = base;
      for (int i = 2; i < kCombWidth; ++i) {
        window[static_cast<std::size_t>(i)] =
            jp_add(window[static_cast<std::size_t>(i - 1)], base, m);
      }
      batch_to_affine(&window, &prefix, m);
      for (int i = 0; i < kCombWidth; ++i) {
        CombEntry& entry = table[static_cast<std::size_t>(j) * kCombWidth + i];
        entry.inf = window[static_cast<std::size_t>(i)].inf;
        if (!entry.inf) {
          entry.x = window[static_cast<std::size_t>(i)].x;
          entry.y = window[static_cast<std::size_t>(i)].y;
        }
      }
      for (int i = 0; i < kCombWindow; ++i) base = jp_double(base, m);  // base *= 16
    }
    return table;
  }();
  return comb;
}

JPoint jp_mul_generator_comb(const Nat& k, const Mont& M) {
  const std::vector<CombEntry>& comb = generator_comb(M);
  JPoint acc;  // the point at infinity
  for (int j = 0; j < kCombWindows; ++j) {
    int digit = 0;
    for (int bit = 0; bit < kCombWindow; ++bit) {
      if (nat_bit_at(k, static_cast<std::size_t>(j * kCombWindow + bit)) != 0) {
        digit |= 1 << bit;
      }
    }
    if (digit == 0) continue;
    const CombEntry& entry =
        comb[static_cast<std::size_t>(j) * kCombWidth + static_cast<std::size_t>(digit)];
    if (entry.inf) continue;
    acc = jp_add_mixed(acc, entry.x, entry.y, M);
  }
  return acc;
}

JPoint jp_mul_generator(const Nat& k, const Mont& M) { return jp_mul_generator_comb(k, M); }

// u1*G + u2*Q with the doublings shared between the two scalars: this is the
// ECDSA verification shape, where the two independent multiplications used to
// run one after the other.
// Shamir's trick: u1*G + u2*Q with one doubling per bit for both scalars, and
// mixed (affine) additions for the digits of either scalar.  This is the ECDSA
// verification shape, where the two independent multiplications used to run one
// after the other and every addition carried a full Jacobian point.
JPoint jp_mul_two(const Nat& k1, const Nat& k2, const std::vector<AffineEntry>& t1,
                  const std::vector<AffineEntry>& t2, const Mont& M) {
  std::vector<int> d1;
  std::vector<int> d2;
  wnaf_digits(k1, kWindow, &d1);
  wnaf_digits(k2, kWindow, &d2);
  const std::size_t len = std::max(d1.size(), d2.size());
  JPoint r;
  for (std::size_t i = len; i-- > 0;) {
    r = jp_double(r, M);
    if (i < d1.size()) {
      const int d = d1[i];
      if (d != 0) {
        const AffineEntry& e = t1[static_cast<std::size_t>(d > 0 ? d : -d) / 2];
        if (!e.inf) {
          if (d > 0) {
            r = jp_add_mixed(r, e.x, e.y, M);
          } else {
            const JPoint flipped = jp_negate(JPoint{e.x, e.y, fe_one(M), false}, M);
            r = jp_add_mixed(r, flipped.x, flipped.y, M);
          }
        }
      }
    }
    if (i < d2.size()) {
      const int d = d2[i];
      if (d != 0) {
        const AffineEntry& e = t2[static_cast<std::size_t>(d > 0 ? d : -d) / 2];
        if (!e.inf) {
          if (d > 0) {
            r = jp_add_mixed(r, e.x, e.y, M);
          } else {
            const JPoint flipped = jp_negate(JPoint{e.x, e.y, fe_one(M), false}, M);
            r = jp_add_mixed(r, flipped.x, flipped.y, M);
          }
        }
      }
    }
  }
  return r;
}
// ------------------------------------------------------ slow path as an oracle
// The pre-Montgomery implementation, kept verbatim as the reference
// `p256_selfcheck()` compares against: a carry bug in the CIOS loop or a wrong
// Montgomery constant shows up as a disagreement here instead of as a
// certificate that does not validate.
bool slow_from_private(const Bytes& d, P256Point* out) {
  if (d.size() != 32) return false;
  const Nat n = kN();
  const Nat scalar = nat_from_be(d.data(), d.size());
  if (scalar.zero() || nat_cmp(scalar, n) >= 0) return false;
  const Jac q = jac_mul(scalar, jac_generator());
  Nat x;
  Nat y;
  if (!jac_to_affine(q, &x, &y)) return false;
  out->infinity = false;
  out->x = be32(x);
  out->y = be32(y);
  return true;
}

bool slow_ecdh(const Bytes& d, const P256Point& peer, Bytes* shared_x) {
  Jac p;
  p.inf = false;
  p.x = from_be32(peer.x);
  p.y = from_be32(peer.y);
  p.z = nat_u32(1);
  const Jac r = jac_mul(from_be32(d), p);
  Nat x;
  Nat y;
  if (!jac_to_affine(r, &x, &y)) return false;
  *shared_x = be32(x);
  return true;
}

bool slow_sign(const Bytes& d, const u8* hash32, Bytes* r_out, Bytes* s_out) {
  const Nat n = kN();
  const Nat priv = nat_from_be(d.data(), 32);
  if (priv.zero() || nat_cmp(priv, n) >= 0) return false;
  const Nat z = nat_mod(nat_from_be(hash32, 32), n);
  Rfc6979 drbg;
  drbg.seed(d, hash32, n);
  for (int attempt = 0; attempt < 64; ++attempt) {
    Nat k;
    if (!drbg.next(n, &k)) return false;
    const Jac rp = jac_mul(k, jac_generator());
    Nat x;
    Nat y;
    if (jac_to_affine(rp, &x, &y)) {
      const Nat r = nat_mod(x, n);
      if (!r.zero()) {
        const Nat s = mod_mul(mod_inv(k, n), mod_add(z, mod_mul(r, priv, n), n), n);
        if (!s.zero()) {
          *r_out = be32(r);
          *s_out = be32(s);
          return true;
        }
      }
    }
    drbg.reseed_after_failure();
  }
  return false;
}

bool slow_verify(const P256Point& q, const u8* hash32, const Bytes& r_in, const Bytes& s_in) {
  if (r_in.size() != 32 || s_in.size() != 32) return false;
  const Nat n = kN();
  const Nat r = from_be32(r_in);
  const Nat s = from_be32(s_in);
  if (r.zero() || s.zero() || nat_cmp(r, n) >= 0 || nat_cmp(s, n) >= 0) return false;
  if (!on_curve(from_be32(q.x), from_be32(q.y))) return false;
  const Nat z = nat_mod(nat_from_be(hash32, 32), n);
  const Nat w = mod_inv(s, n);
  const Nat u1 = mod_mul(z, w, n);
  const Nat u2 = mod_mul(r, w, n);
  Jac pub;
  pub.inf = false;
  pub.x = from_be32(q.x);
  pub.y = from_be32(q.y);
  pub.z = nat_u32(1);
  const Jac point = jac_add(jac_mul(u1, jac_generator()), jac_mul(u2, pub));
  Nat x;
  Nat y;
  if (!jac_to_affine(point, &x, &y)) return false;
  return nat_cmp(nat_mod(x, n), r) == 0;
}

bool slow_parse_point(const u8* data, std::size_t len, P256Point* out) {
  const Nat& m = kP();
  if (len == 65 && data[0] == 0x04) {
    const Nat x = nat_from_be(data + 1, 32);
    const Nat y = nat_from_be(data + 33, 32);
    if (nat_cmp(x, m) >= 0 || nat_cmp(y, m) >= 0) return false;
    if (!on_curve(x, y)) return false;
    out->infinity = false;
    out->x = be32(x);
    out->y = be32(y);
    return true;
  }
  if (len == 33 && (data[0] == 0x02 || data[0] == 0x03)) {
    const Nat x = nat_from_be(data + 1, 32);
    if (nat_cmp(x, m) >= 0) return false;
    const Nat x3 = mod_mul(mod_mul(x, x, m), x, m);
    const Nat rhs = mod_add(mod_add(x3, mod_sub(m, mod_small(x, 3, m), m), m), kB(), m);
    const Nat exp = nat_div(nat_add(m, nat_u32(1)), nat_u32(4));
    const Nat y = nat_pow(rhs, exp, m);
    if (nat_cmp(mod_mul(y, y, m), rhs) != 0) return false;
    const bool want_odd = data[0] == 0x03;
    const bool is_odd = !y.v.empty() && (y.v[0] & 1u) != 0;
    const Nat y_final = (is_odd == want_odd) ? y : mod_sub(m, y, m);
    out->infinity = false;
    out->x = be32(x);
    out->y = be32(y_final);
    return true;
  }
  return false;
}

}  // namespace

// ------------------------------------------------------------------ CNG fast path
// Windows ships a hand optimised P-256 inside CNG -- the code path Schannel
// itself uses.  Portable C needs ~0.3 ms per signature on this machine, CNG
// needs tens of microseconds, so the accelerator below is worth having.  It is
// only an accelerator: every function returns false when CNG is unavailable or
// refuses the key, and the portable code above remains the reference that
// p256_selfcheck() checks the accelerator against.
//
// It is on by default and NETCAP_NO_CNG=1 (or NETCAP_CNG=0) turns it off.  The
// win is concentrated in verification (0.262 ms -> 0.140 ms); signing and key
// generation are not faster here because CNG cannot export raw ECDH secrets
// (see cng_ecdh_available) and its key generation is itself a scalar multiply.
// Anything that looks like a mismatch between CNG and the portable path gets
// caught by p256_selfcheck, and every call site falls back on refusal.
#if defined(_WIN32)

bool env_truthy(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && value[0] != '\0' && value[0] != '0';
}

bool cng_allowed() {
  static const bool allowed = []() {
    if (env_truthy("NETCAP_NO_CNG")) return false;
    const char* flag = std::getenv("NETCAP_CNG");
    return flag == nullptr || flag[0] != '0';
  }();
  return allowed;
}

// The blobs CNG imports start with an eight byte header (magic + key size),
// followed by X || Y and, for a private key, d.
struct CngPair {
  BCRYPT_ALG_HANDLE alg = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  CngPair() = default;
  CngPair(const CngPair&) = delete;
  CngPair& operator=(const CngPair&) = delete;
  ~CngPair() { reset(); }
  void reset() {
    if (key != nullptr) {
      BCryptDestroyKey(key);
      key = nullptr;
    }
    if (alg != nullptr) {
      BCryptCloseAlgorithmProvider(alg, 0);
      alg = nullptr;
    }
  }
};

bool cng_import(LPCWSTR algorithm, ULONG magic, const P256Point& point, const Bytes* d,
                CngPair* out) {
  if (point.infinity || point.x.size() != 32 || point.y.size() != 32) return false;
  if (BCryptOpenAlgorithmProvider(&out->alg, algorithm, nullptr, 0) != 0) return false;
  std::vector<u8> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64 + (d != nullptr ? 32 : 0), 0);
  BCRYPT_ECCKEY_BLOB head{};
  head.dwMagic = magic;
  head.cbKey = 32;
  std::memcpy(blob.data(), &head, sizeof(head));
  std::memcpy(blob.data() + sizeof(head), point.x.data(), 32);
  std::memcpy(blob.data() + sizeof(head) + 32, point.y.data(), 32);
  if (d != nullptr) std::memcpy(blob.data() + sizeof(head) + 64, d->data(), 32);
  const NTSTATUS status =
      BCryptImportKeyPair(out->alg, nullptr, d != nullptr ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB,
                          &out->key, blob.data(), static_cast<ULONG>(blob.size()), 0);
  if (status != 0) {
    out->reset();
    return false;
  }
  return true;
}

bool cng_sign(const Bytes& d, const P256Point& own, const u8* hash32, Bytes* r_out, Bytes* s_out) {
  if (!cng_allowed()) return false;
  CngPair pair;
  if (!cng_import(BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, own, &d, &pair)) {
    return false;
  }
  u8 signature[64];
  ULONG written = 0;
  const NTSTATUS status = BCryptSignHash(pair.key, nullptr, const_cast<PUCHAR>(hash32), 32,
                                         signature, sizeof(signature), &written, 0);
  if (status != 0 || written != 64) return false;
  r_out->assign(signature, signature + 32);  // CNG returns r || s, big endian
  s_out->assign(signature + 32, signature + 64);
  return true;
}

// Returns false when CNG could not take part at all; otherwise `*verdict` is the
// answer, and an invalid signature is a verdict, not an error.
//
// Only the two statuses that mean "this signature is wrong" may become a
// verdict.  Everything else -- provider trouble, a malformed blob, an
// unexpected parameter complaint -- has to leave the accelerator, because
// answering "invalid" for a technical failure is exactly how a rare CNG hiccup
// turns into a mysterious cross-check failure against the big-integer path.
bool cng_verify(const P256Point& q, const u8* hash32, const Bytes& r, const Bytes& s,
                bool* verdict) {
  if (!cng_allowed() || r.size() != 32 || s.size() != 32) return false;
  CngPair pair;
  if (!cng_import(BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, q, nullptr, &pair)) {
    return false;
  }
  u8 signature[64];
  std::memcpy(signature, r.data(), 32);
  std::memcpy(signature + 32, s.data(), 32);
  const NTSTATUS status = BCryptVerifySignature(pair.key, nullptr, const_cast<PUCHAR>(hash32), 32,
                                                signature, sizeof(signature), 0);
  if (status == 0) {
    *verdict = true;
    return true;
  }
  constexpr NTSTATUS kInvalidSignature = static_cast<NTSTATUS>(0xC000A000L);  // STATUS_INVALID_SIGNATURE
  constexpr NTSTATUS kBadSignature = static_cast<NTSTATUS>(0x80090006L);      // NTE_BAD_SIGNATURE
  if (status == kInvalidSignature || status == kBadSignature) {
    *verdict = false;
    return true;
  }
  return false;
}

// BCRYPT_KDF_RAW_SECRET is the only way to pull the raw ECDH x coordinate out of
// CNG, and some Windows builds do not offer it for ECDH secrets at all:
// BCryptDeriveKey answers STATUS_NOT_SUPPORTED (0xC00000BB) even though the
// agreement itself succeeded.  An optional capability that is missing is not a
// failure, but re-importing two keys per call just to find out would be a waste,
// so probe once and remember.
bool cng_ecdh_available();

bool cng_ecdh(const Bytes& d, const P256Point& own, const P256Point& peer, Bytes* shared_x) {
  if (!cng_allowed() || !cng_ecdh_available()) return false;
  const bool trace = std::getenv("NETCAP_CNG_TRACE") != nullptr;
  CngPair mine;
  CngPair theirs;
  if (!cng_import(BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_PRIVATE_P256_MAGIC, own, &d, &mine)) {
    if (trace) std::fprintf(stderr, "netcap: cng_ecdh: private import failed\n");
    return false;
  }
  if (!cng_import(BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_PUBLIC_P256_MAGIC, peer, nullptr,
                  &theirs)) {
    if (trace) std::fprintf(stderr, "netcap: cng_ecdh: peer import failed\n");
    return false;
  }
  BCRYPT_SECRET_HANDLE secret = nullptr;
  const NTSTATUS agreed = BCryptSecretAgreement(mine.key, theirs.key, &secret, 0);
  if (agreed != 0) {
    if (trace) std::fprintf(stderr, "netcap: cng_ecdh: BCryptSecretAgreement 0x%08lx\n",
                            static_cast<unsigned long>(agreed));
    return false;
  }
  u8 raw[32];
  ULONG got = 0;
  const NTSTATUS status =
      BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, raw, sizeof(raw), &got, 0);
  BCryptDestroySecret(secret);
  if (status != 0 || got != 32) {
    if (trace) {
      std::fprintf(stderr, "netcap: cng_ecdh: BCryptDeriveKey 0x%08lx got %lu\n",
                   static_cast<unsigned long>(status), static_cast<unsigned long>(got));
    }
    return false;
  }
  // RAW_SECRET is the x coordinate in little-endian order -- the one place in
  // this file where that is true, so it is reversed here and nowhere else.
  shared_x->assign(raw, raw + 32);
  std::reverse(shared_x->begin(), shared_x->end());
  return true;
}

bool cng_ecdh_available() {
  static const bool available = []() {
    if (!cng_allowed()) return false;
    Bytes one(32, 0);
    one[31] = 1;
    P256Key generator;
    if (!p256_from_private(one, &generator)) return false;
    CngPair mine;
    CngPair theirs;
    if (!cng_import(BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_PRIVATE_P256_MAGIC, generator.q, &one,
                    &mine)) {
      return false;
    }
    if (!cng_import(BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_PUBLIC_P256_MAGIC, generator.q, nullptr,
                    &theirs)) {
      return false;
    }
    BCRYPT_SECRET_HANDLE secret = nullptr;
    if (BCryptSecretAgreement(mine.key, theirs.key, &secret, 0) != 0) return false;
    u8 raw[32];
    ULONG got = 0;
    const NTSTATUS status =
        BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, raw, sizeof(raw), &got, 0);
    BCryptDestroySecret(secret);
    const bool ok = status == 0 && got == 32;
    if (!ok && std::getenv("NETCAP_CNG_TRACE") != nullptr) {
      std::fprintf(stderr,
                   "netcap: CNG cannot export raw ECDH secrets here (BCryptDeriveKey 0x%08lx); "
                   "the portable path stays in charge\n",
                   static_cast<unsigned long>(status));
    }
    return ok;
  }();
  return available;
}

#else

bool cng_allowed() { return false; }
bool cng_sign(const Bytes&, const P256Point&, const u8*, Bytes*, Bytes*) { return false; }
bool cng_verify(const P256Point&, const u8*, const Bytes&, const Bytes&, bool*) { return false; }
bool cng_ecdh(const Bytes&, const P256Point&, const P256Point&, Bytes*) { return false; }
bool cng_ecdh_available() { return false; }

#endif

// ------------------------------------------------------------------- randomness
bool random_bytes(u8* out, std::size_t len) {
  if (len == 0) return true;
#if defined(_WIN32)
  return BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(__linux__)
  std::size_t done = 0;
  while (done < len) {
    const ssize_t got = getrandom(out + done, len - done, 0);
    if (got <= 0) break;
    done += static_cast<std::size_t>(got);
  }
  if (done == len) return true;
  std::FILE* f = std::fopen("/dev/urandom", "rb");
  if (f != nullptr) {
    const std::size_t rest = std::fread(out + done, 1, len - done, f);
    std::fclose(f);
    if (rest == len - done) return true;
  }
  return false;
#else
  std::random_device rd;
  for (std::size_t i = 0; i < len; ++i) out[i] = static_cast<u8>(rd() & 0xff);
  return true;
#endif
}

// ------------------------------------------------------------------------ keys
bool p256_from_private(const Bytes& d, P256Key* out) {
  if (out == nullptr || d.size() != 32) return false;
  const Nat n = kN();
  const Nat scalar = nat_from_be(d.data(), d.size());
  if (scalar.zero() || nat_cmp(scalar, n) >= 0) return false;
  const Mont& M = mont_p();
  const JPoint q = jp_mul_generator(scalar, M);
  Fe x;
  Fe y;
  if (!jp_to_affine(q, &x, &y, M)) return false;
  out->d = d;
  out->q.infinity = false;
  out->q.x = fe_to_bytes(x, M);
  out->q.y = fe_to_bytes(y, M);
  return true;
}

bool p256_generate(P256Key* out) {
  if (out == nullptr) return false;
  // Deliberately portable even when CNG is on: CNG key generation is a full
  // scalar multiply plus a private-key export (measured 0.315 ms against our
  // 0.049 ms), and a key is only generated once per certificate.  CNG is used
  // where it actually wins -- verification.
  Nat scalar;
  if (!random_scalar_in_range(kN(), &scalar)) return false;
  return p256_from_private(be32(scalar), out);
}

bool p256_valid_public(const P256Point& p) {
  if (p.infinity || p.x.size() != 32 || p.y.size() != 32) return false;
  if (!bytes_lt_p(p.x.data()) || !bytes_lt_p(p.y.data())) return false;
  const Mont& M = mont_p();
  return on_curve_fast(fe_from_bytes(p.x.data(), M), fe_from_bytes(p.y.data(), M), M);
}

Bytes p256_serialize_uncompressed(const P256Point& p) {
  Bytes out;
  if (p.infinity || p.x.size() != 32 || p.y.size() != 32) return out;
  out.reserve(65);
  out.push_back(0x04);
  out.insert(out.end(), p.x.begin(), p.x.end());
  out.insert(out.end(), p.y.begin(), p.y.end());
  return out;
}

Bytes p256_serialize_compressed(const P256Point& p) {
  Bytes out;
  if (p.infinity || p.x.size() != 32 || p.y.size() != 32) return out;
  out.reserve(33);
  out.push_back((p.y.back() & 1u) != 0 ? 0x03 : 0x02);
  out.insert(out.end(), p.x.begin(), p.x.end());
  return out;
}

bool p256_parse_point(const u8* data, std::size_t len, P256Point* out) {
  if (data == nullptr || out == nullptr) return false;
  const Mont& M = mont_p();
  if (len == 65 && data[0] == 0x04) {
    if (!bytes_lt_p(data + 1) || !bytes_lt_p(data + 33)) return false;
    const Fe x = fe_from_bytes(data + 1, M);
    const Fe y = fe_from_bytes(data + 33, M);
    if (!on_curve_fast(x, y, M)) return false;
    out->infinity = false;
    out->x.assign(data + 1, data + 33);
    out->y.assign(data + 33, data + 65);
    return true;
  }
  if (len == 33 && (data[0] == 0x02 || data[0] == 0x03)) {
    if (!bytes_lt_p(data + 1)) return false;
    const Fe x = fe_from_bytes(data + 1, M);
    // y^2 = x^3 - 3x + b; p == 3 (mod 4), so a square root is a^((p+1)/4).
    const Fe b = fe_from_bytes(be32(kB()).data(), M);
    const Fe x3 = fe_mont_mul(fe_mont_mul(x, x, M), x, M);
    const Fe rhs =
        fe_add(fe_add(x3, fe_sub(Fe{0, 0, 0, 0}, fe_times_small(x, 3, M), M), M), b, M);
    static const Nat exp = nat_div(nat_add(kP(), nat_u32(1)), nat_u32(4));
    const Fe y0 = fe_pow(rhs, exp, M);
    if (!fe_equal(fe_mont_mul(y0, y0, M), rhs)) return false;  // not on the curve
    const Bytes yb = fe_to_bytes(y0, M);
    const bool is_odd = (yb.back() & 1u) != 0;
    const bool want_odd = data[0] == 0x03;
    const Fe y = (is_odd == want_odd) ? y0 : fe_sub(Fe{0, 0, 0, 0}, y0, M);
    out->infinity = false;
    out->x.assign(data + 1, data + 33);
    out->y = fe_to_bytes(y, M);
    return true;
  }
  return false;
}

// ------------------------------------------------------------------------ ECDH
bool p256_ecdh(const P256Key& mine, const P256Point& peer, Bytes* shared_x) {
  if (shared_x == nullptr || !p256_valid_public(peer)) return false;
  if (mine.d.size() != 32) return false;
  if (cng_ecdh(mine.d, mine.q, peer, shared_x)) return true;
  const Nat n = kN();
  const Nat scalar = nat_from_be(mine.d.data(), 32);
  if (scalar.zero() || nat_cmp(scalar, n) >= 0) return false;
  const Mont& M = mont_p();
  const JPoint p = jp_from_bytes(peer.x.data(), peer.y.data(), M);
  const JPoint r = jp_mul(scalar, p, M);
  Fe x;
  Fe y;
  if (!jp_to_affine(r, &x, &y, M)) return false;
  *shared_x = fe_to_bytes(x, M);
  return true;
}

// ----------------------------------------------------------------------- ECDSA
bool p256_ecdsa_sign(const Bytes& d, const u8* hash32, Bytes* r_out, Bytes* s_out,
                     const P256Point* public_hint) {
  if (hash32 == nullptr || r_out == nullptr || s_out == nullptr || d.size() != 32) return false;
  if (public_hint != nullptr && cng_sign(d, *public_hint, hash32, r_out, s_out)) return true;
  const Nat n = kN();
  const Nat priv = nat_from_be(d.data(), 32);
  if (priv.zero() || nat_cmp(priv, n) >= 0) return false;
  const Mont& Mp = mont_p();
  const Mont& Mn = mont_n();
  const Nat z = nat_mod(nat_from_be(hash32, 32), n);
  Rfc6979 drbg;
  drbg.seed(d, hash32, n);
  for (int attempt = 0; attempt < 64; ++attempt) {
    Nat k;
    if (!drbg.next(n, &k)) return false;
    const JPoint rp = jp_mul_generator(k, Mp);
    Fe x;
    Fe y;
    if (jp_to_affine(rp, &x, &y, Mp)) {
      const Nat r_nat = nat_mod(nat_from_be(fe_to_bytes(x, Mp).data(), 32), n);
      if (!r_nat.zero()) {
        // s = k^-1 (z + r*d) mod n, in the Montgomery domain of n.
        const Fe km = fe_from_bytes(be32(k).data(), Mn);
        const Fe invk = fe_inv(km, Mn);
        const Fe rm = fe_from_bytes(be32(r_nat).data(), Mn);
        const Fe dm = fe_from_bytes(d.data(), Mn);
        const Fe zm = fe_from_bytes(be32(z).data(), Mn);
        const Fe s = fe_mont_mul(invk, fe_add(zm, fe_mont_mul(rm, dm, Mn), Mn), Mn);
        if (!fe_zero(s)) {
          *r_out = be32(r_nat);
          *s_out = fe_to_bytes(s, Mn);
          return true;
        }
      }
    }
    drbg.reseed_after_failure();  // RFC 6979 §3.2 step h.3
  }
  return false;
}

bool p256_ecdsa_verify(const P256Point& q, const u8* hash32, const Bytes& r_in, const Bytes& s_in) {
  if (hash32 == nullptr || !p256_valid_public(q)) return false;
  if (r_in.size() != 32 || s_in.size() != 32) return false;
  bool verdict = false;
  if (cng_verify(q, hash32, r_in, s_in, &verdict)) return verdict;
  const Nat n = kN();
  const Nat r = from_be32(r_in);
  const Nat s = from_be32(s_in);
  if (r.zero() || s.zero() || nat_cmp(r, n) >= 0 || nat_cmp(s, n) >= 0) return false;
  const Mont& Mp = mont_p();
  const Mont& Mn = mont_n();
  const Nat z = nat_mod(nat_from_be(hash32, 32), n);
  const Fe wm = fe_inv(fe_from_bytes(s_in.data(), Mn), Mn);
  const Fe zm = fe_from_bytes(be32(z).data(), Mn);
  const Fe rm = fe_from_bytes(r_in.data(), Mn);
  const Nat u1 = nat_from_be(fe_to_bytes(fe_mont_mul(zm, wm, Mn), Mn).data(), 32);
  const Nat u2 = nat_from_be(fe_to_bytes(fe_mont_mul(rm, wm, Mn), Mn).data(), 32);
  const JPoint pub = jp_from_bytes(q.x.data(), q.y.data(), Mp);
  const JPoint point = jp_mul_two(u1, u2, generator_affine_table(Mp),
                                  affine_table(wnaf_table(pub, kWindow, Mp), Mp), Mp);
  Fe x;
  Fe y;
  if (!jp_to_affine(point, &x, &y, Mp)) return false;
  return nat_cmp(nat_mod(nat_from_be(fe_to_bytes(x, Mp).data(), 32), n), r) == 0;
}

// ------------------------------------------------------------------ self-check
bool p256_selfcheck(std::string* report) {
  const Mont& M = mont_p();
  const Mont& N = mont_n();
  auto fail = [&](const std::string& what) {
    if (report != nullptr) *report = what;
    return false;
  };

  // Small deterministic cases first: if these fail the message says exactly
  // which conversion or product is wrong, before any random case is involved.
  {
    Nat r;  // zero (not nat_u32(1), which would set bit 0 too)
    nat_set_bit(r, 256);
    const Bytes r_expected = be32(nat_mod(r, kP()));
    const Bytes r_got = fe_raw_bytes(fe_to_mont(Fe{1, 0, 0, 0}, M));
    if (r_got != r_expected) {
      return fail("to_mont(1) is not R mod p: want " + to_hex(r_expected) + " got " + to_hex(r_got));
    }
    if (fe_to_bytes(fe_one(M), M) != be32(nat_u32(1))) {
      return fail("fe_one is not 1: " + to_hex(fe_to_bytes(fe_one(M), M)));
    }
    const u32 small[][2] = {{2, 3}, {12345, 6789}, {4294967295u, 4294967295u}, {1, 65537}};
    for (const auto& pair : small) {
      const Nat a = nat_u32(pair[0]);
      const Nat b = nat_u32(pair[1]);
      const Bytes want = be32(mod_mul(a, b, kP()));
      const Bytes ab = be32(a);
      const Bytes bb = be32(b);
      const Bytes got = fe_to_bytes(
          fe_mont_mul(fe_from_bytes(ab.data(), M), fe_from_bytes(bb.data(), M), M), M);
      if (got != want) {
        return fail("small product " + std::to_string(pair[0]) + " * " + std::to_string(pair[1]) +
                    " want " + to_hex(want) + " got " + to_hex(got));
      }
    }
  }

  // Field products mod p, including the Montgomery round trip.
  int field_cases = 0;
  for (int i = 0; i < 60; ++i) {
    u8 a[32];
    u8 b[32];
    if (!random_bytes(a, sizeof(a)) || !random_bytes(b, sizeof(b))) return fail("no randomness");
    const Nat an = nat_mod(nat_from_be(a, 32), kP());
    const Nat bn = nat_mod(nat_from_be(b, 32), kP());
    const Bytes ab = be32(an);
    const Bytes bb = be32(bn);
    const Bytes want = be32(mod_mul(an, bn, kP()));
    const Fe am = fe_from_bytes(ab.data(), M);
    const Fe bm = fe_from_bytes(bb.data(), M);
    if (fe_to_bytes(am, M) != ab) {
      return fail("Montgomery round trip broke on " + to_hex(ab) + " (got " +
                  to_hex(fe_to_bytes(am, M)) + ")");
    }
    const Bytes got = fe_to_bytes(fe_mont_mul(am, bm, M), M);
    if (got != want) {
      return fail("field product mismatch at case " + std::to_string(i) + ": " + to_hex(ab) + " * " +
                  to_hex(bb) + " want " + to_hex(want) + " got " + to_hex(got));
    }
    ++field_cases;
  }

  // The ECDSA scalar arithmetic uses the same code with n as the modulus.
  int scalar_cases = 0;
  for (int i = 0; i < 20; ++i) {
    u8 a[32];
    u8 b[32];
    if (!random_bytes(a, sizeof(a)) || !random_bytes(b, sizeof(b))) return fail("no randomness");
    const Nat an = nat_mod(nat_from_be(a, 32), kN());
    const Nat bn = nat_mod(nat_from_be(b, 32), kN());
    const Bytes ab = be32(an);
    const Bytes bb = be32(bn);
    const Bytes want = be32(mod_mul(an, bn, kN()));
    const Bytes got =
        fe_to_bytes(fe_mont_mul(fe_from_bytes(ab.data(), N), fe_from_bytes(bb.data(), N), N), N);
    if (got != want) {
      return fail("scalar product mismatch at case " + std::to_string(i) + ": " + to_hex(ab) +
                  " * " + to_hex(bb) + " want " + to_hex(want) + " got " + to_hex(got));
    }
    ++scalar_cases;
  }

  // Scalar multiplication, signing and verification against the slow path.
  int math_cases = 0;
  for (int i = 0; i < 2; ++i) {
    u8 seed[32];
    u8 hash[32];
    if (!random_bytes(seed, sizeof(seed)) || !random_bytes(hash, sizeof(hash))) {
      return fail("no randomness");
    }
    Nat k = nat_mod(nat_from_be(seed, 32), kN());
    if (k.zero()) k = nat_u32(1);
    const Bytes kb = be32(k);
    P256Key fast;
    P256Point slow;
    if (!p256_from_private(kb, &fast)) return fail("fast from_private failed");
    if (!slow_from_private(kb, &slow)) return fail("slow from_private failed");
    if (fast.q.x != slow.x || fast.q.y != slow.y) {
      return fail("public key mismatch at round " + std::to_string(i));
    }
    Bytes fast_shared;
    Bytes slow_shared;
    if (!p256_ecdh(fast, fast.q, &fast_shared)) return fail("fast ECDH failed");
    if (!slow_ecdh(kb, fast.q, &slow_shared)) return fail("slow ECDH failed");
    if (fast_shared != slow_shared) return fail("ECDH mismatch at round " + std::to_string(i));

    Bytes r;
    Bytes s;
    if (!p256_ecdsa_sign(kb, hash, &r, &s)) return fail("fast sign failed");
    if (!p256_ecdsa_verify(fast.q, hash, r, s)) return fail("fast verify rejected its own signature");
    if (!slow_verify(fast.q, hash, r, s)) return fail("slow verify rejected the fast signature");
    Bytes r2;
    Bytes s2;
    if (!slow_sign(kb, hash, &r2, &s2)) return fail("slow sign failed");
    if (!p256_ecdsa_verify(fast.q, hash, r2, s2)) {
      return fail("fast verify rejected the slow signature");
    }
    Bytes tampered = r;
    tampered[31] = static_cast<u8>(tampered[31] ^ 0x01);
    if (p256_ecdsa_verify(fast.q, hash, tampered, s)) return fail("fast verify accepted a tampered r");

    // Windows CNG is the path that actually signs certificates when it is
    // available, so it has to agree with the portable code in both directions:
    // a CNG signature must satisfy the slow verifier, a portable signature must
    // satisfy CNG, and both must derive the same ECDH secret.
    if (cng_allowed()) {
      Bytes cng_r;
      Bytes cng_s;
      if (!cng_sign(kb, fast.q, hash, &cng_r, &cng_s)) {
        return fail("CNG is enabled but refused to sign with a valid key");
      }
      if (!slow_verify(fast.q, hash, cng_r, cng_s)) {
        return fail("the big-integer path rejected a CNG signature");
      }
      if (!p256_ecdsa_verify(fast.q, hash, cng_r, cng_s)) {
        return fail("a CNG signature did not verify");
      }
      bool verdict = false;
      if (!cng_verify(fast.q, hash, r, s, &verdict) || !verdict) {
        return fail("CNG rejected a signature the portable path produced");
      }
      if (!cng_verify(fast.q, hash, tampered, s, &verdict)) {
        return fail("CNG verification is enabled but unavailable");
      }
      if (verdict) return fail("CNG accepted a tampered r");
      // The raw-secret KDF is not offered everywhere (see cng_ecdh_available):
      // when it is missing the portable path answers, and that is not a defect.
      if (cng_ecdh_available()) {
        Bytes cng_shared;
        if (!cng_ecdh(kb, fast.q, fast.q, &cng_shared)) {
          return fail("CNG ECDH is offered here but the call failed");
        }
        if (cng_shared != fast_shared) return fail("CNG ECDH disagreed with the portable path");
      }
    }
    ++math_cases;
  }

  // SEC 1 point parsing, both encodings, against the slow path.
  int parse_cases = 0;
  {
    P256Key key;
    if (!p256_generate(&key)) return fail("keygen failed");
    const Bytes raw = p256_serialize_uncompressed(key.q);
    const Bytes comp = p256_serialize_compressed(key.q);
    P256Point fa;
    P256Point sl;
    if (!p256_parse_point(raw.data(), raw.size(), &fa)) return fail("fast uncompressed parse failed");
    if (!slow_parse_point(raw.data(), raw.size(), &sl)) return fail("slow uncompressed parse failed");
    if (fa.x != sl.x || fa.y != sl.y) return fail("uncompressed parse mismatch");
    if (!p256_parse_point(comp.data(), comp.size(), &fa)) return fail("fast compressed parse failed");
    if (!slow_parse_point(comp.data(), comp.size(), &sl)) return fail("slow compressed parse failed");
    if (fa.x != sl.x || fa.y != sl.y) return fail("compressed parse mismatch");
    ++parse_cases;
  }

  if (report != nullptr) {
    *report = "field products " + std::to_string(field_cases) + ", scalar products " +
              std::to_string(scalar_cases) + ", key/sign/ECDH rounds " + std::to_string(math_cases) +
              ", point parses " + std::to_string(parse_cases) + " agree with the big-integer path" +
              (cng_allowed() ? (cng_ecdh_available()
                                    ? "; the CNG accelerator was cross-checked too"
                                    : "; the CNG accelerator was cross-checked, but this build "
                                      "cannot export raw ECDH secrets so ECDH stayed portable")
                             : "; portable only");
  }
  return true;
}

}  // namespace netcap
