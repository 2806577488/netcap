#include "netcap/x25519.hpp"

#include <cstring>

#include "netcap/crypto.hpp"
#include "netcap/p256.hpp"  // random_bytes

namespace netcap {
namespace {

// GCC/Clang give us a real 128 bit integer; the project builds with MinGW
// g++ on Windows, so this is always available where it is tested.
using u128 = unsigned __int128;

// Field elements modulo 2^255 - 19, four 64 bit limbs, little endian. Every
// operation returns a fully reduced value, which is slower than the usual
// lazy-reduction tricks but leaves far less room for a subtle mistake. The
// proxy runs a handful of these per connection, not per packet.
struct Fe {
  u64 v[4];
};

const u64 kP0 = 0xffffffffffffffedULL;  // p = 2^255 - 19
const u64 kP1 = 0xffffffffffffffffULL;
const u64 kP3 = 0x7fffffffffffffffULL;  // the top limb: p is 255 bits, not 256

Fe fe_zero() { return Fe{{0, 0, 0, 0}}; }
Fe fe_one() { return Fe{{1, 0, 0, 0}}; }

bool fe_ge_p(const Fe& a) {
  if (a.v[3] != kP3) return a.v[3] > kP3;
  if (a.v[2] != kP1) return a.v[2] > kP1;
  if (a.v[1] != kP1) return a.v[1] > kP1;
  return a.v[0] >= kP0;
}

Fe fe_sub_p(const Fe& a) {
  Fe r{};
  u64 borrow = 0;
  const u64 p[4] = {kP0, kP1, kP1, kP3};
  for (int i = 0; i < 4; ++i) {
    const u128 rhs = static_cast<u128>(p[i]) + borrow;
    r.v[i] = static_cast<u64>(static_cast<u128>(a.v[i]) - rhs);
    borrow = (static_cast<u128>(a.v[i]) < rhs) ? 1 : 0;
  }
  return r;
}

Fe fe_canonical(Fe a) {
  // The callers fold at most a handful of times over, so a bounded loop of
  // conditional subtractions is enough to land below p.
  for (int i = 0; i < 8 && fe_ge_p(a); ++i) a = fe_sub_p(a);
  return a;
}

// Fold any carry that escaped the top limb back into the low limb. The carry
// stands for 2^256, and 2^256 == 38 (mod p).
Fe fe_fold_carry(Fe r, u64 carry) {
  for (int guard = 0; guard < 4 && carry != 0; ++guard) {
    u128 acc = static_cast<u128>(r.v[0]) + 38 * carry;
    r.v[0] = static_cast<u64>(acc);
    carry = static_cast<u64>(acc >> 64);
    for (int i = 1; i < 4 && carry != 0; ++i) {
      const u128 s = static_cast<u128>(r.v[i]) + carry;
      r.v[i] = static_cast<u64>(s);
      carry = static_cast<u64>(s >> 64);
    }
  }
  return fe_canonical(r);
}

Fe fe_add(const Fe& a, const Fe& b) {
  Fe r{};
  u64 carry = 0;
  for (int i = 0; i < 4; ++i) {
    const u128 s = static_cast<u128>(a.v[i]) + b.v[i] + carry;
    r.v[i] = static_cast<u64>(s);
    carry = static_cast<u64>(s >> 64);
  }
  return fe_fold_carry(r, carry);
}

Fe fe_sub(const Fe& a, const Fe& b) {
  Fe r{};
  u64 borrow = 0;
  for (int i = 0; i < 4; ++i) {
    const u128 rhs = static_cast<u128>(b.v[i]) + borrow;
    r.v[i] = static_cast<u64>(static_cast<u128>(a.v[i]) - rhs);
    borrow = (static_cast<u128>(a.v[i]) < rhs) ? 1 : 0;
  }
  if (borrow != 0) {
    // The subtraction wrapped: the stored value is a-b+2^256, and 2^256 == 38,
    // so subtracting 38 recovers a-b. r is far larger than 38 here, because
    // both inputs are below p and therefore below 2^255.
    u64 borrow2 = 0;
    for (int i = 0; i < 4; ++i) {
      const u128 rhs = static_cast<u128>(i == 0 ? 38 : 0) + borrow2;
      r.v[i] = static_cast<u64>(static_cast<u128>(r.v[i]) - rhs);
      borrow2 = (static_cast<u128>(r.v[i]) < rhs) ? 1 : 0;
    }
  }
  return fe_canonical(r);
}

Fe fe_mul(const Fe& a, const Fe& b) {
  u64 t[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 4; ++i) {
    u64 carry = 0;
    for (int j = 0; j < 4; ++j) {
      const u128 cur = static_cast<u128>(a.v[i]) * b.v[j] + t[i + j] + carry;
      t[i + j] = static_cast<u64>(cur);
      carry = static_cast<u64>(cur >> 64);
    }
    t[i + 4] = carry;  // this limb has not been written yet
  }
  // Fold the upper half down: 2^256 == 38, so limb 4..7 shifts down by 4.
  u128 w[5];
  for (int i = 0; i < 4; ++i) w[i] = t[i];
  w[4] = 0;
  for (int i = 4; i < 8; ++i) w[i - 4] += static_cast<u128>(38) * t[i];
  for (int pass = 0; pass < 4; ++pass) {
    for (int i = 0; i < 4; ++i) {
      w[i + 1] += w[i] >> 64;
      w[i] &= static_cast<u128>(0xffffffffffffffffULL);
    }
    if (w[4] == 0) break;
    w[0] += static_cast<u128>(38) * w[4];
    w[4] = 0;
  }
  Fe r{};
  for (int i = 0; i < 4; ++i) r.v[i] = static_cast<u64>(w[i]);
  return fe_canonical(r);
}

Fe fe_sq(const Fe& a) { return fe_mul(a, a); }

Fe fe_mul_small(const Fe& a, u32 k) {
  Fe b{};
  b.v[0] = k;
  return fe_mul(a, b);
}

void fe_to_bytes(const Fe& a, u8 out[32]) {
  const Fe r = fe_canonical(a);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 8; ++j) out[i * 8 + j] = static_cast<u8>(r.v[i] >> (8 * j));
  }
}

Fe fe_from_bytes(const u8 in[32]) {
  Fe r{};
  for (int i = 0; i < 4; ++i) {
    u64 limb = 0;
    for (int j = 7; j >= 0; --j) limb = (limb << 8) | in[i * 8 + j];
    r.v[i] = limb;
  }
  return fe_canonical(r);
}

void fe_cswap(Fe& a, Fe& b, u64 swap) {
  const u64 mask = 0 - swap;  // 0 or all ones
  for (int i = 0; i < 4; ++i) {
    const u64 x = mask & (a.v[i] ^ b.v[i]);
    a.v[i] ^= x;
    b.v[i] ^= x;
  }
}

// a^(p-2) mod p by square and multiply: p-2 == 2^255 - 21.
Fe fe_invert(const Fe& a) {
  Fe result = fe_one();
  Fe base = a;
  // The exponent 2^255 - 21 in binary is 255 ones except for the low 5 bits
  // (0x...eb): bit0 = 1, bit1 = 1, bit2 = 0, bit3 = 1, bits 4..254 = 1.
  const u8 exp[32] = {0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
  for (int i = 254; i >= 0; --i) {
    result = fe_sq(result);
    if (((exp[i / 8] >> (i % 8)) & 1) != 0) result = fe_mul(result, base);
  }
  return result;
}

// RFC 7748 §5: clamp the scalar before use.
void clamp(u8 k[32]) {
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
}

// The Montgomery ladder, straight from RFC 7748 §5.
void ladder(const u8 scalar[32], const Fe& x1, Fe* x2_out, Fe* z2_out) {
  Fe x2 = fe_one();
  Fe z2 = fe_zero();
  Fe x3 = x1;
  Fe z3 = fe_one();
  u64 swap = 0;
  for (int t = 254; t >= 0; --t) {
    const u64 bit = static_cast<u64>((scalar[t / 8] >> (t % 8)) & 1);
    swap ^= bit;
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    swap = bit;

    const Fe a = fe_add(x2, z2);
    const Fe aa = fe_sq(a);
    const Fe b = fe_sub(x2, z2);
    const Fe bb = fe_sq(b);
    const Fe e = fe_sub(aa, bb);
    const Fe c = fe_add(x3, z3);
    const Fe d = fe_sub(x3, z3);
    const Fe da = fe_mul(d, a);
    const Fe cb = fe_mul(c, b);
    x3 = fe_sq(fe_add(da, cb));
    z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)));
    x2 = fe_mul(aa, bb);
    // a24 == 121665 for the twisted Edwards form used by X25519.
    z2 = fe_mul(e, fe_add(aa, fe_mul_small(e, 121665)));
  }
  fe_cswap(x2, x3, swap);
  fe_cswap(z2, z3, swap);
  *x2_out = x2;
  *z2_out = z2;
}

}  // namespace

bool x25519_is_zero(const Bytes& value) {
  u8 acc = 0;
  for (u8 byte : value) acc = static_cast<u8>(acc | byte);
  return value.empty() || acc == 0;
}

bool x25519_keypair(X25519Key* out) {
  if (out == nullptr) return false;
  out->priv.assign(32, 0);
  if (!random_bytes(out->priv.data(), 32)) return false;
  u8 k[32];
  std::memcpy(k, out->priv.data(), 32);
  clamp(k);
  std::memcpy(out->priv.data(), k, 32);
  Bytes pub;
  if (!x25519_public(out->priv, &pub)) return false;
  out->pub = pub;
  return true;
}

bool x25519_public(const Bytes& scalar, Bytes* out_public) {
  if (scalar.size() != 32 || out_public == nullptr) return false;
  u8 k[32];
  std::memcpy(k, scalar.data(), 32);
  clamp(k);
  u8 base[32] = {9};
  Fe x2{};
  Fe z2{};
  ladder(k, fe_from_bytes(base), &x2, &z2);
  const Fe x = fe_mul(x2, fe_invert(z2));
  out_public->assign(32, 0);
  fe_to_bytes(x, out_public->data());
  return true;
}

bool x25519_scalar_mult(const Bytes& scalar, const Bytes& u_point, Bytes* out) {
  if (scalar.size() != 32 || u_point.size() != 32 || out == nullptr) return false;
  Fe x2{};
  Fe z2{};
  ladder(reinterpret_cast<const u8*>(scalar.data()), fe_from_bytes(u_point.data()), &x2, &z2);
  const Fe x = fe_mul(x2, fe_invert(z2));
  out->assign(32, 0);
  fe_to_bytes(x, out->data());
  return true;
}

bool x25519(const Bytes& scalar, const Bytes& peer_public, Bytes* shared) {
  if (scalar.size() != 32 || peer_public.size() != 32 || shared == nullptr) return false;
  u8 k[32];
  std::memcpy(k, scalar.data(), 32);
  clamp(k);
  Bytes out;
  if (!x25519_scalar_mult(Bytes(k, k + 32), peer_public, &out)) return false;
  if (x25519_is_zero(out)) return false;  // low order point: RFC 7748 §6.1
  *shared = out;
  return true;
}

std::string x25519_describe(const Bytes& pub) {
  if (pub.size() != 32) return "(no x25519 key)";
  return to_hex(pub).substr(0, 16) + "...";
}

}  // namespace netcap
