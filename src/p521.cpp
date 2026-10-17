// NIST P-521 (secp521r1) field and curve arithmetic, ECDH only.
//
// Deliberately plain, like p256.cpp: schoolbook multiplication, a fold-based
// reduction (p = 2^521 - 1 is a Mersenne prime, so 2^521 == 1 and nothing above
// bit 520 ever needs a division), Jacobian coordinates with the textbook
// add/double formulas, and a Fermat inversion.  One scalar multiplication costs
// a few milliseconds; a handshake that falls back to this curve does two of them
// plus one inversion, which is the price of not breaking the client at all.
//
// Nothing here is secret-dependent: the field operations branch only on the
// final conditional subtraction, and the scalar multiplication is plain
// double-and-add.  This code produces ephemeral ECDHE keys for intercepted
// hosts; it is not a signing oracle exposed to a local attacker.

#include "netcap/p521.hpp"

#include <cstring>
#include <string>

#include "netcap/p256.hpp"  // random_bytes

namespace netcap {
namespace {

using u128 = unsigned __int128;

constexpr int kLimbs = 9;  // 9 * 64 = 576 bits >= 521

// --------------------------------------------------------------------- field
// Nine 64-bit limbs, little endian, always in [0, p).
struct Fe {
  u64 v[kLimbs];
};

void fe_zero(Fe* a) {
  for (int i = 0; i < kLimbs; ++i) a->v[i] = 0;
}

void fe_one(Fe* a) {
  fe_zero(a);
  a->v[0] = 1;
}

bool fe_is_zero(const Fe& a) {
  for (int i = 0; i < kLimbs; ++i) {
    if (a.v[i] != 0) return false;
  }
  return true;
}

// p itself: the only value below 2^521 that is still >= p.
bool fe_is_p(const Fe& a) {
  if (a.v[8] != 0x1ffULL) return false;
  for (int i = 0; i < 8; ++i) {
    if (a.v[i] != ~static_cast<u64>(0)) return false;
  }
  return true;
}

// Folds every bit at or above 521 back to the bottom (2^521 == 1 mod p) until
// the value is below 2^521, then turns p itself into zero.
void fe_normalize(Fe* a) {
  for (;;) {
    const u64 high = a->v[8] >> 9;
    if (high == 0) break;
    a->v[8] &= 0x1ffULL;
    u128 carry = high;
    for (int i = 0; i < kLimbs && carry != 0; ++i) {
      const u128 sum = static_cast<u128>(a->v[i]) + carry;
      a->v[i] = static_cast<u64>(sum);
      carry = sum >> 64;
    }
  }
  if (fe_is_p(*a)) fe_zero(a);
}

int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

// A 132 character (66 byte) big-endian hex constant.
Fe fe_from_hex(const char* hex) {
  const std::size_t n = std::strlen(hex);
  Fe r;
  fe_zero(&r);
  for (std::size_t i = 0; i < n; ++i) {
    const int nibble = hex_nibble(hex[n - 1 - i]);  // least significant first
    const std::size_t bit = 4 * i;
    r.v[bit / 64] |= static_cast<u64>(nibble) << (bit % 64);
  }
  return r;
}

Bytes hex_to_bytes(const char* hex) {
  const std::size_t n = std::strlen(hex);
  Bytes out(n / 2, 0);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<u8>((hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]));
  }
  return out;
}

Fe fe_from_be(const u8* be) {  // exactly 66 bytes
  Fe r;
  fe_zero(&r);
  for (int i = 0; i < 66; ++i) {
    const std::size_t bit = static_cast<std::size_t>(65 - i) * 8;
    r.v[bit / 64] |= static_cast<u64>(be[i]) << (bit % 64);
  }
  return r;
}

Bytes fe_to_be(const Fe& a) {  // exactly 66 bytes
  Bytes out(66, 0);
  for (int i = 0; i < 66; ++i) {
    const std::size_t bit = static_cast<std::size_t>(65 - i) * 8;
    out[i] = static_cast<u8>((a.v[bit / 64] >> (bit % 64)) & 0xff);
  }
  return out;
}

int fe_cmp(const Fe& a, const Fe& b) {
  for (int i = kLimbs; i-- > 0;) {
    if (a.v[i] != b.v[i]) return a.v[i] < b.v[i] ? -1 : 1;
  }
  return 0;
}

void add_raw(u64* r, const u64* a, const u64* b) {
  u128 carry = 0;
  for (int i = 0; i < kLimbs; ++i) {
    const u128 sum = static_cast<u128>(a[i]) + b[i] + carry;
    r[i] = static_cast<u64>(sum);
    carry = sum >> 64;
  }
}

// Requires a >= b.
void sub_raw(u64* r, const u64* a, const u64* b) {
  u64 borrow = 0;
  for (int i = 0; i < kLimbs; ++i) {
    const u128 ai = static_cast<u128>(a[i]);
    const u128 bi = static_cast<u128>(b[i]) + borrow;
    r[i] = static_cast<u64>(ai - bi);
    borrow = ai < bi ? 1 : 0;
  }
}

// ------------------------------------------------------------------ constants
// All of them come from `openssl ecparam -name secp521r1 -param_enc explicit`,
// so no long hex string here was typed by hand.
const char* const kBCurveHex =
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
    "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00";
const char* const kGxHex =
    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
    "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
const char* const kGyHex =
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
    "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";
const char* const kNOrderHex =
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";

const Fe& feP() {
  static const Fe value = [] {
    Fe f;
    for (int i = 0; i < kLimbs; ++i) f.v[i] = ~static_cast<u64>(0);
    f.v[8] = 0x1ffULL;  // 512 + 9 = 521 bits
    return f;
  }();
  return value;
}

const Fe& feB() {
  static const Fe value = fe_from_hex(kBCurveHex);
  return value;
}

const Fe& feGx() {
  static const Fe value = fe_from_hex(kGxHex);
  return value;
}

const Fe& feGy() {
  static const Fe value = fe_from_hex(kGyHex);
  return value;
}

const Fe& feN() {
  static const Fe value = fe_from_hex(kNOrderHex);
  return value;
}

// --------------------------------------------------------------- modular ops
Fe fe_add(const Fe& a, const Fe& b) {
  Fe r;
  add_raw(r.v, a.v, b.v);
  fe_normalize(&r);
  return r;
}

Fe fe_sub(const Fe& a, const Fe& b) {
  Fe r;
  if (fe_cmp(a, b) >= 0) {
    sub_raw(r.v, a.v, b.v);
  } else {
    u64 t[kLimbs];
    add_raw(t, a.v, feP().v);  // a + p, still nine limbs because a < 2^521
    sub_raw(r.v, t, b.v);
  }
  fe_normalize(&r);
  return r;
}

Fe fe_mul_small(const Fe& a, u32 k) {
  Fe r = a;
  for (u32 i = 1; i < k; ++i) r = fe_add(r, a);
  return r;
}

// t[limb] += value, carrying upwards.
void add_at(u64* t, int len, int limb, u64 value) {
  u128 carry = value;
  int k = limb;
  while (carry != 0 && k < len) {
    const u128 sum = static_cast<u128>(t[k]) + carry;
    t[k] = static_cast<u64>(sum);
    carry = sum >> 64;
    ++k;
  }
}

Fe fe_mul(const Fe& a, const Fe& b) {
  constexpr int kWide = 2 * kLimbs;
  u64 t[kWide];
  for (int i = 0; i < kWide; ++i) t[i] = 0;
  for (int i = 0; i < kLimbs; ++i) {
    u64 carry = 0;
    for (int j = 0; j < kLimbs; ++j) {
      const u128 cur = static_cast<u128>(a.v[i]) * b.v[j] + t[i + j] + carry;
      t[i + j] = static_cast<u64>(cur);
      carry = static_cast<u64>(cur >> 64);
    }
    add_at(t, kWide, i + kLimbs, carry);
  }
  // 2^521 == 1, so limb k >= 9 (bits 64k ...) belongs at bit 64k - 521, which is
  // exactly 55 + 64 * (k - 9).  Folding always moves value downwards, but the
  // carry of one fold can land on a limb that was just cleared, so repeat until
  // no limb at or above 9 is set (at most a couple of passes).
  bool moved = true;
  while (moved) {
    moved = false;
    for (int k = kWide - 1; k >= kLimbs; --k) {
      const u64 word = t[k];
      if (word == 0) continue;
      t[k] = 0;
      moved = true;
      const u128 shifted = static_cast<u128>(word) << 55;
      add_at(t, kWide, k - kLimbs, static_cast<u64>(shifted));
      add_at(t, kWide, k - kLimbs + 1, static_cast<u64>(shifted >> 64));
    }
  }
  Fe r;
  for (int i = 0; i < kLimbs; ++i) r.v[i] = t[i];
  fe_normalize(&r);
  return r;
}

Fe fe_sqr(const Fe& a) { return fe_mul(a, a); }

// a^(p-2) by Fermat, square and multiply over the exponent's bits.  p - 2 is
// 2^521 - 3: 521 bits, all ones except bit 1.
Fe fe_inv(const Fe& a) {
  Fe r;
  fe_one(&r);
  for (int i = 520; i >= 0; --i) {
    r = fe_sqr(r);
    if (i != 1) r = fe_mul(r, a);
  }
  return r;
}

bool fe_bit(const Fe& a, int i) { return ((a.v[i / 64] >> (i % 64)) & 1) != 0; }

// ------------------------------------------------------------------- points
struct Jac {
  Fe x;
  Fe y;
  Fe z;
  bool inf = true;
};

Jac jac_infinity() {
  Jac r;
  fe_zero(&r.x);
  fe_zero(&r.y);
  fe_zero(&r.z);
  r.inf = true;
  return r;
}

Jac jac_point(const Fe& x, const Fe& y) {
  Jac r;
  r.x = x;
  r.y = y;
  fe_one(&r.z);
  r.inf = false;
  return r;
}

// Textbook Jacobian doubling, general `a`; here a = -3, so the M term is
// 3 * (X^2 - Z^4).
Jac jac_double(const Jac& p) {
  if (p.inf) return p;
  if (fe_is_zero(p.y)) return jac_infinity();
  const Fe xx = fe_sqr(p.x);
  const Fe yy = fe_sqr(p.y);
  const Fe yyyy = fe_sqr(yy);
  const Fe zz = fe_sqr(p.z);
  const Fe s = fe_mul_small(fe_sub(fe_sub(fe_sqr(fe_add(p.x, yy)), xx), yyyy), 2);
  const Fe m = fe_mul_small(fe_sub(xx, fe_sqr(zz)), 3);
  const Fe x3 = fe_sub(fe_sqr(m), fe_mul_small(s, 2));
  const Fe y3 = fe_sub(fe_mul(m, fe_sub(s, x3)), fe_mul_small(yyyy, 8));
  const Fe z3 = fe_mul_small(fe_mul(p.y, p.z), 2);
  Jac r;
  r.x = x3;
  r.y = y3;
  r.z = z3;
  r.inf = false;
  return r;
}

// Jacobian addition (the usual H/R form).
Jac jac_add(const Jac& p, const Jac& q) {
  if (p.inf) return q;
  if (q.inf) return p;
  const Fe z1z1 = fe_sqr(p.z);
  const Fe z2z2 = fe_sqr(q.z);
  const Fe u1 = fe_mul(p.x, z2z2);
  const Fe u2 = fe_mul(q.x, z1z1);
  const Fe s1 = fe_mul(p.y, fe_mul(q.z, z2z2));
  const Fe s2 = fe_mul(q.y, fe_mul(p.z, z1z1));
  if (fe_cmp(u1, u2) == 0) {
    if (fe_cmp(s1, s2) == 0) return jac_double(p);
    return jac_infinity();
  }
  const Fe h = fe_sub(u2, u1);
  const Fe r = fe_sub(s2, s1);
  const Fe hh = fe_sqr(h);
  const Fe hhh = fe_mul(h, hh);
  const Fe u1hh = fe_mul(u1, hh);
  const Fe x3 = fe_sub(fe_sub(fe_sqr(r), hhh), fe_mul_small(u1hh, 2));
  const Fe y3 = fe_sub(fe_mul(r, fe_sub(u1hh, x3)), fe_mul(s1, hhh));
  const Fe z3 = fe_mul(fe_mul(p.z, q.z), h);
  Jac out;
  out.x = x3;
  out.y = y3;
  out.z = z3;
  out.inf = false;
  return out;
}

bool jac_to_affine(const Jac& p, Fe* x, Fe* y) {
  if (p.inf || fe_is_zero(p.z)) return false;
  const Fe zinv = fe_inv(p.z);
  const Fe zinv2 = fe_sqr(zinv);
  *x = fe_mul(p.x, zinv2);
  *y = fe_mul(p.y, fe_mul(zinv2, zinv));
  return true;
}

// MSB-first double-and-add over the 521 bits of the scalar.
Jac jac_mul(const Fe& k, const Jac& p) {
  Jac r = jac_infinity();
  for (int i = 520; i >= 0; --i) {
    r = jac_double(r);
    if (fe_bit(k, i)) r = jac_add(r, p);
  }
  return r;
}

bool on_curve(const Fe& x, const Fe& y) {
  // y^2 == x^3 - 3x + b
  const Fe lhs = fe_sqr(y);
  const Fe rhs = fe_add(fe_sub(fe_mul(fe_sqr(x), x), fe_mul_small(x, 3)), feB());
  return fe_cmp(lhs, rhs) == 0;
}

// ------------------------------------------------- known answer test vectors
// Generated with python-cryptography 49.0.0 (an independent implementation) from
// two fixed scalars derived from SHA-512, and cross-checked against
// `openssl pkeyutl -derive` before being written down here.
const char* const kDaHex =
    "019fe67760f68e36fbe6501eaf727995695a376441cf7fea61fdd73587d8c8ae"
    "6f4d63dee4dcd1e0bdd24ec5a9bb2c29ca80a978e348b4248580916f499fd9f10000";
const char* const kQaXHex =
    "002637efecd020fe563f0bbe4256b7103dca0731235d4b568cd06fa20cc71fb9"
    "affc062c2e614cb738431c5dc223942a5a2119b96b1b24ad19e0dd6d379745ec1338";
const char* const kQaYHex =
    "0041c485574b408ac650957921a44707919e5b920d468a54833f7cfd34fe27f4"
    "58b70bbd6b650bbc3043995c5abe388069f70887f130cc1c99853b84dfeb676fa52b";
const char* const kDbHex =
    "0194f56f0e1b1cc05d0a1032ce47f9c11911ef37d51ffbd7aed1ec2b108ec3ab"
    "32c7453fe96ff251dfaf62fc4e4914cd3939e283f98149c9e5508fd4c75cf0810000";
const char* const kQbXHex =
    "00ec3082b848d31869ad94b5c206cfdb07a346f8bad3babcf702dfecf7d588f5"
    "81ccc9435f5924bc2a5bf42fda0a57b60f643f81d460041dbf6da3b9db3278b5fd4c";
const char* const kQbYHex =
    "014bbefd043c4c11200cfffee3215d282ad2a209bae04c0bd7670e16b9a6e536"
    "5bf3447ff99c1165aabccc23be0832768c92b2a255e50e0215f44e039a34caf01917";
const char* const kSharedHex =
    "01379b97f5c0e600ce8a0fed48b778c394771a736d53404fac2c6525900655d5"
    "68c054fe8275489f595cb6cb0b46378d7a98c8247b5a9388c3c46fbb235778f76059";
const char* const kTwoGxHex =
    "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769"
    "be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
const char* const kTwoGyHex =
    "00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c4"
    "2dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02";

}  // namespace

// ----------------------------------------------------------------- public API
bool p521_valid_public(const P521Point& p) {
  if (p.infinity) return false;
  if (p.x.size() != 66 || p.y.size() != 66) return false;
  const Fe x = fe_from_be(p.x.data());
  const Fe y = fe_from_be(p.y.data());
  if (fe_cmp(x, feP()) >= 0 || fe_cmp(y, feP()) >= 0) return false;
  return on_curve(x, y);
}

Bytes p521_serialize_uncompressed(const P521Point& p) {
  Bytes out;
  if (p.infinity || p.x.size() != 66 || p.y.size() != 66) return out;
  out.reserve(133);
  out.push_back(4);
  out.insert(out.end(), p.x.begin(), p.x.end());
  out.insert(out.end(), p.y.begin(), p.y.end());
  return out;
}

bool p521_parse_point(const u8* data, std::size_t len, P521Point* out) {
  if (data == nullptr || out == nullptr) return false;
  if (len != 133 || data[0] != 4) return false;  // uncompressed only
  P521Point p;
  p.infinity = false;
  p.x.assign(data + 1, data + 67);
  p.y.assign(data + 67, data + 133);
  if (!p521_valid_public(p)) return false;
  *out = p;
  return true;
}

bool p521_from_private(const Bytes& d, P521Key* out) {
  if (out == nullptr || d.size() != 66) return false;
  const Fe k = fe_from_be(d.data());
  if (fe_is_zero(k) || fe_cmp(k, feN()) >= 0) return false;
  const Jac q = jac_mul(k, jac_point(feGx(), feGy()));
  Fe x;
  Fe y;
  if (!jac_to_affine(q, &x, &y)) return false;
  const P521Point point{false, fe_to_be(x), fe_to_be(y)};
  if (!p521_valid_public(point)) return false;
  out->d = d;
  out->q = point;
  return true;
}

bool p521_generate(P521Key* out) {
  for (int attempt = 0; attempt < 64; ++attempt) {
    u8 raw[66];
    if (!random_bytes(raw, sizeof(raw))) return false;
    raw[0] &= 0x01;  // keep exactly 521 bits
    const Bytes d(raw, raw + sizeof(raw));
    if (p521_from_private(d, out)) return true;
  }
  return false;
}

bool p521_ecdh(const P521Key& mine, const P521Point& peer, Bytes* shared_x) {
  if (shared_x == nullptr || mine.d.size() != 66) return false;
  if (!p521_valid_public(peer)) return false;
  const Fe k = fe_from_be(mine.d.data());
  const Jac s = jac_mul(k, jac_point(fe_from_be(peer.x.data()), fe_from_be(peer.y.data())));
  Fe x;
  Fe y;
  if (!jac_to_affine(s, &x, &y)) return false;  // the shared point is the identity
  *shared_x = fe_to_be(x);
  return true;
}

bool p521_selfcheck(std::string* report) {
  auto fail = [report](const std::string& why) {
    if (report != nullptr) *report = why;
    return false;
  };

  if (!on_curve(feGx(), feGy())) return fail("the generator is not on the curve");
  if (fe_cmp(feN(), feP()) >= 0) return fail("the group order is not below p");

  Bytes one(66, 0);
  one[65] = 1;
  P521Key k1;
  if (!p521_from_private(one, &k1)) return fail("d=1 does not derive a point");
  if (fe_cmp(fe_from_be(k1.q.x.data()), feGx()) != 0 ||
      fe_cmp(fe_from_be(k1.q.y.data()), feGy()) != 0) {
    return fail("d=1 did not give back the generator");
  }

  Bytes two(66, 0);
  two[65] = 2;
  P521Key k2;
  if (!p521_from_private(two, &k2)) return fail("d=2 does not derive a point");
  if (k2.q.x != hex_to_bytes(kTwoGxHex) || k2.q.y != hex_to_bytes(kTwoGyHex)) {
    return fail("2*G does not match the OpenSSL vector (doubling)");
  }

  P521Key a;
  P521Key b;
  if (!p521_from_private(hex_to_bytes(kDaHex), &a)) return fail("the vector scalar A is rejected");
  if (!p521_from_private(hex_to_bytes(kDbHex), &b)) return fail("the vector scalar B is rejected");
  if (a.q.x != hex_to_bytes(kQaXHex) || a.q.y != hex_to_bytes(kQaYHex)) {
    return fail("d_a*G does not match the OpenSSL vector");
  }
  if (b.q.x != hex_to_bytes(kQbXHex) || b.q.y != hex_to_bytes(kQbYHex)) {
    return fail("d_b*G does not match the OpenSSL vector");
  }

  const Bytes expected = hex_to_bytes(kSharedHex);
  Bytes ab;
  Bytes ba;
  if (!p521_ecdh(a, b.q, &ab)) return fail("a*Q_b failed");
  if (!p521_ecdh(b, a.q, &ba)) return fail("b*Q_a failed");
  if (ab != ba) return fail("the two ECDH directions disagree");
  if (ab != expected) return fail("ECDH does not match the shared secret OpenSSL computed");

  const Bytes encoded = p521_serialize_uncompressed(a.q);
  if (encoded.size() != 133 || encoded[0] != 4) return fail("the encoding is not 133 bytes");
  P521Point back;
  if (!p521_parse_point(encoded.data(), encoded.size(), &back) || back.x != a.q.x ||
      back.y != a.q.y) {
    return fail("the encoding does not round trip");
  }
  Bytes off_curve = encoded;
  off_curve[132] = static_cast<u8>(off_curve[132] ^ 0x01);
  P521Point junk;
  if (p521_parse_point(off_curve.data(), off_curve.size(), &junk)) {
    return fail("a point off the curve was accepted");
  }
  if (p521_parse_point(encoded.data(), encoded.size() - 1, &junk)) {
    return fail("a short encoding was accepted");
  }
  Bytes compressed = encoded;
  compressed[0] = 0x02;  // we do not do compressed points; say so instead of guessing
  if (p521_parse_point(compressed.data(), compressed.size(), &junk)) {
    return fail("a compressed encoding was accepted");
  }

  P521Key r1;
  P521Key r2;
  if (!p521_generate(&r1)) return fail("key generation failed");
  if (!p521_generate(&r2)) return fail("key generation failed");
  Bytes r12;
  Bytes r21;
  if (!p521_ecdh(r1, r2.q, &r12)) return fail("fresh ECDH failed");
  if (!p521_ecdh(r2, r1.q, &r21)) return fail("fresh ECDH failed");
  if (r12 != r21 || r12.size() != 66) return fail("two fresh keys do not agree");

  if (report != nullptr) {
    *report = "P-521: OpenSSL vectors, both ECDH directions, encodings, fresh keys";
  }
  return true;
}

}  // namespace netcap
