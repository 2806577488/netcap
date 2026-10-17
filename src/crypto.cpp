// Cryptographic primitives for the TLS decryption path.
//
// No third-party library is linked: SHA-256/384/512, HMAC, HKDF, the TLS 1.2
// PRF, AES (128/192/256) in ECB/CTR/CBC/GCM and ChaCha20-Poly1305 are all
// implemented here. The self-test suite pins them against the published test
// vectors (FIPS-197, FIPS-180, RFC 4231, RFC 5869, NIST GCM, RFC 8439).
#include "netcap/crypto.hpp"

#include <cstring>
#include <mutex>

namespace netcap {
namespace {

// ---------------------------------------------------------------- byte order

inline u32 ld32be(const u8* p) {
  return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}
inline u32 ld32le(const u8* p) {
  return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
inline void st32be(u8* p, u32 v) {
  p[0] = u8(v >> 24);
  p[1] = u8(v >> 16);
  p[2] = u8(v >> 8);
  p[3] = u8(v);
}
inline void st32le(u8* p, u32 v) {
  p[0] = u8(v);
  p[1] = u8(v >> 8);
  p[2] = u8(v >> 16);
  p[3] = u8(v >> 24);
}
inline void st64be(u8* p, u64 v) {
  for (int i = 0; i < 8; ++i) p[i] = u8(v >> (56 - 8 * i));
}
inline void st64le(u8* p, u64 v) {
  for (int i = 0; i < 8; ++i) p[i] = u8(v >> (8 * i));
}
inline u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
inline u32 rotr32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
inline u64 rotr64(u64 x, int n) { return (x >> n) | (x << (64 - n)); }
inline u64 rotl64(u64 x, int n) { return (x << n) | (x >> (64 - n)); }

}  // namespace

// ---------------------------------------------------------------- hex helpers

Bytes from_hex(const std::string& hex) {
  Bytes out;
  int hi = -1;
  for (char ch : hex) {
    int v;
    if (ch >= '0' && ch <= '9') {
      v = ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
      v = ch - 'a' + 10;
    } else if (ch >= 'A' && ch <= 'F') {
      v = ch - 'A' + 10;
    } else {
      continue;  // spaces, colons, dashes and newlines are all separators
    }
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(u8((hi << 4) | v));
      hi = -1;
    }
  }
  return out;
}

std::string to_hex(const u8* p, std::size_t n) {
  static const char* kDigits = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(kDigits[p[i] >> 4]);
    out.push_back(kDigits[p[i] & 0x0f]);
  }
  return out;
}

std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }

// ---------------------------------------------------------------- SHA-256

namespace {

const u32 kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

struct Sha256 {
  u32 h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  u64 bits = 0;
  u8 buf[64] = {0};
  std::size_t n = 0;

  void block(const u8* p) {
    u32 w[64];
    for (int i = 0; i < 16; ++i) w[i] = ld32be(p + 4 * i);
    for (int i = 16; i < 64; ++i) {
      u32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      u32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      u32 s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      u32 ch = (e & f) ^ (~e & g);
      u32 t1 = hh + s1 + ch + kSha256K[i] + w[i];
      u32 s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      u32 maj = (a & b) ^ (a & c) ^ (b & c);
      u32 t2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  void update(const u8* p, std::size_t len) {
    bits += u64(len) * 8;
    while (len > 0) {
      std::size_t take = 64 - n;
      if (take > len) take = len;
      std::memcpy(buf + n, p, take);
      n += take;
      p += take;
      len -= take;
      if (n == 64) {
        block(buf);
        n = 0;
      }
    }
  }

  void finish(u8 out[32]) {
    u64 total = bits;
    const u8 pad = 0x80;
    update(&pad, 1);
    const u8 zero = 0x00;
    while (n != 56) update(&zero, 1);
    u8 lenb[8];
    st64be(lenb, total);
    // update() folds these bytes into `bits` too, which is harmless here.
    update(lenb, 8);
    for (int i = 0; i < 8; ++i) st32be(out + 4 * i, h[i]);
  }
};

// ---------------------------------------------------------------- SHA-512/384

const u64 kSha512K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

struct Sha512 {
  u64 h[8];
  u64 bits = 0;
  u8 buf[128] = {0};
  std::size_t n = 0;

  void init(bool sha384_mode) {
    if (sha384_mode) {
      static const u64 iv[8] = {0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull,
                                0x152fecd8f70e5939ull, 0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
                                0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull};
      std::memcpy(h, iv, sizeof(h));
    } else {
      static const u64 iv[8] = {0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
                                0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
                                0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
      std::memcpy(h, iv, sizeof(h));
    }
  }

  void block(const u8* p) {
    u64 w[80];
    for (int i = 0; i < 16; ++i) {
      u64 v = 0;
      for (int k = 0; k < 8; ++k) v = (v << 8) | p[8 * i + k];
      w[i] = v;
    }
    for (int i = 16; i < 80; ++i) {
      u64 s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
      u64 s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u64 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; ++i) {
      u64 s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      u64 ch = (e & f) ^ (~e & g);
      u64 t1 = hh + s1 + ch + kSha512K[i] + w[i];
      u64 s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      u64 maj = (a & b) ^ (a & c) ^ (b & c);
      u64 t2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  void update(const u8* p, std::size_t len) {
    bits += u64(len) * 8;
    while (len > 0) {
      std::size_t take = 128 - n;
      if (take > len) take = len;
      std::memcpy(buf + n, p, take);
      n += take;
      p += take;
      len -= take;
      if (n == 128) {
        block(buf);
        n = 0;
      }
    }
  }

  void finish(u8* out, std::size_t out_len) {
    u64 total = bits;
    const u8 pad = 0x80;
    update(&pad, 1);
    const u8 zero = 0x00;
    while (n != 112) update(&zero, 1);
    u8 lenb[16];
    std::memset(lenb, 0, 8);
    st64be(lenb + 8, total);
    update(lenb, 16);
    u8 full[64];
    for (int i = 0; i < 8; ++i) st64be(full + 8 * i, h[i]);
    std::memcpy(out, full, out_len);
  }
};

Bytes hmac(const u8* key, std::size_t key_len, const u8* data, std::size_t len, bool sha384_mode) {
  const std::size_t block = sha384_mode ? 128 : 64;
  Bytes k(key, key + key_len);
  if (k.size() > block) {
    k = sha384_mode ? sha384(k.data(), k.size()) : sha256(k.data(), k.size());
  }
  k.resize(block, 0);
  Bytes ipad(block), opad(block);
  for (std::size_t i = 0; i < block; ++i) {
    ipad[i] = u8(k[i] ^ 0x36);
    opad[i] = u8(k[i] ^ 0x5c);
  }
  Bytes inner;
  if (sha384_mode) {
    Sha512 s;
    s.init(true);
    s.update(ipad.data(), ipad.size());
    s.update(data, len);
    inner.resize(48);
    s.finish(inner.data(), 48);
  } else {
    Sha256 s;
    s.update(ipad.data(), ipad.size());
    s.update(data, len);
    inner.resize(32);
    s.finish(inner.data());
  }
  Bytes out;
  if (sha384_mode) {
    Sha512 s;
    s.init(true);
    s.update(opad.data(), opad.size());
    s.update(inner.data(), inner.size());
    out.resize(48);
    s.finish(out.data(), 48);
  } else {
    Sha256 s;
    s.update(opad.data(), opad.size());
    s.update(inner.data(), inner.size());
    out.resize(32);
    s.finish(out.data());
  }
  return out;
}

}  // namespace

Bytes sha256(const u8* data, std::size_t len) {
  Sha256 s;
  s.update(data, len);
  Bytes out(32);
  s.finish(out.data());
  return out;
}

Bytes sha384(const u8* data, std::size_t len) {
  Sha512 s;
  s.init(true);
  s.update(data, len);
  Bytes out(48);
  s.finish(out.data(), 48);
  return out;
}

Bytes sha512(const u8* data, std::size_t len) {
  Sha512 s;
  s.init(false);
  s.update(data, len);
  Bytes out(64);
  s.finish(out.data(), 64);
  return out;
}

Bytes hmac_sha256(const Bytes& key, const u8* data, std::size_t len) {
  return hmac(key.data(), key.size(), data, len, false);
}
Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
  return hmac(key.data(), key.size(), data.data(), data.size(), false);
}
Bytes hmac_sha384(const Bytes& key, const Bytes& data) {
  return hmac(key.data(), key.size(), data.data(), data.size(), true);
}

// ---------------------------------------------------------------- SHA-1 / MD5

// The pre-1.2 handshake still needs the old digests: TLS 1.0/1.1 finish with
// MD5||SHA1, their PRF is P_MD5 XOR P_SHA1, and the CBC cipher suites (up to
// and including TLS 1.2) authenticate every record with HMAC-SHA1.  Nothing
// else in the project should reach for these.

namespace {

struct Sha1 {
  u32 h[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
  u64 bits = 0;
  u8 buf[64] = {0};
  std::size_t n = 0;

  void block(const u8* p) {
    u32 w[80];
    for (int i = 0; i < 16; ++i) w[i] = ld32be(p + 4 * i);
    for (int i = 16; i < 80; ++i) {
      w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
      u32 f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdcu;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6u;
      }
      u32 t = rotl32(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rotl32(b, 30);
      b = a;
      a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }

  void update(const u8* p, std::size_t len) {
    bits += u64(len) * 8;
    while (len > 0) {
      std::size_t take = 64 - n;
      if (take > len) take = len;
      std::memcpy(buf + n, p, take);
      n += take;
      p += take;
      len -= take;
      if (n == 64) {
        block(buf);
        n = 0;
      }
    }
  }

  void finish(u8 out[20]) {
    u64 total = bits;
    const u8 pad = 0x80;
    update(&pad, 1);
    const u8 zero = 0x00;
    while (n != 56) update(&zero, 1);
    u8 lenb[8];
    st64be(lenb, total);
    // update() folds these bytes into `bits` too, which is harmless here.
    update(lenb, 8);
    for (int i = 0; i < 5; ++i) st32be(out + 4 * i, h[i]);
  }
};

// MD5 is little-endian throughout: the message words, the length field and the
// digest itself (RFC 1321).
const u32 kMd5K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u,
    0xfd469501u, 0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u,
    0xa679438eu, 0x49b40821u, 0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du,
    0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u, 0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u,
    0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u, 0x289b7ec6u, 0xeaa127fau,
    0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u, 0xf4292244u,
    0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu,
    0xeb86d391u};

const u8 kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

struct Md5 {
  u32 h[4] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
  u64 bits = 0;
  u8 buf[64] = {0};
  std::size_t n = 0;

  void block(const u8* p) {
    u32 m[16];
    for (int i = 0; i < 16; ++i) m[i] = ld32le(p + 4 * i);
    u32 a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 64; ++i) {
      u32 f, g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = u32(i);
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = u32(5 * i + 1) & 15u;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = u32(3 * i + 5) & 15u;
      } else {
        f = c ^ (b | ~d);
        g = u32(7 * i) & 15u;
      }
      u32 tmp = d;
      d = c;
      c = b;
      b = b + rotl32(a + f + kMd5K[i] + m[g], kMd5S[i]);
      a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
  }

  void update(const u8* p, std::size_t len) {
    bits += u64(len) * 8;
    while (len > 0) {
      std::size_t take = 64 - n;
      if (take > len) take = len;
      std::memcpy(buf + n, p, take);
      n += take;
      p += take;
      len -= take;
      if (n == 64) {
        block(buf);
        n = 0;
      }
    }
  }

  void finish(u8 out[16]) {
    u64 total = bits;
    const u8 pad = 0x80;
    update(&pad, 1);
    const u8 zero = 0x00;
    while (n != 56) update(&zero, 1);
    u8 lenb[8];
    st64le(lenb, total);
    update(lenb, 8);
    for (int i = 0; i < 4; ++i) st32le(out + 4 * i, h[i]);
  }
};

// HMAC (RFC 2104) for the two legacy digests, following the same key
// normalisation and ipad/opad layout as hmac() above.
Bytes hmac_legacy(const u8* key, std::size_t key_len, const u8* data, std::size_t len,
                  bool md5_mode) {
  const std::size_t block_size = 64;
  Bytes k(key, key + key_len);
  if (k.size() > block_size) k = md5_mode ? md5(k.data(), k.size()) : sha1(k.data(), k.size());
  k.resize(block_size, 0);
  Bytes ipad(block_size), opad(block_size);
  for (std::size_t i = 0; i < block_size; ++i) {
    ipad[i] = u8(k[i] ^ 0x36);
    opad[i] = u8(k[i] ^ 0x5c);
  }
  Bytes inner;
  if (md5_mode) {
    Md5 s;
    s.update(ipad.data(), ipad.size());
    s.update(data, len);
    inner.resize(16);
    s.finish(inner.data());
  } else {
    Sha1 s;
    s.update(ipad.data(), ipad.size());
    s.update(data, len);
    inner.resize(20);
    s.finish(inner.data());
  }
  Bytes out;
  if (md5_mode) {
    Md5 s;
    s.update(opad.data(), opad.size());
    s.update(inner.data(), inner.size());
    out.resize(16);
    s.finish(out.data());
  } else {
    Sha1 s;
    s.update(opad.data(), opad.size());
    s.update(inner.data(), inner.size());
    out.resize(20);
    s.finish(out.data());
  }
  return out;
}

}  // namespace

Bytes sha1(const u8* data, std::size_t len) {
  Sha1 s;
  s.update(data, len);
  Bytes out(20);
  s.finish(out.data());
  return out;
}

Bytes md5(const u8* data, std::size_t len) {
  Md5 s;
  s.update(data, len);
  Bytes out(16);
  s.finish(out.data());
  return out;
}

Bytes hmac_sha1(const Bytes& key, const u8* data, std::size_t len) {
  return hmac_legacy(key.data(), key.size(), data, len, false);
}
Bytes hmac_sha1(const Bytes& key, const Bytes& data) {
  return hmac_legacy(key.data(), key.size(), data.data(), data.size(), false);
}
Bytes hmac_md5(const Bytes& key, const u8* data, std::size_t len) {
  return hmac_legacy(key.data(), key.size(), data, len, true);
}
Bytes hmac_md5(const Bytes& key, const Bytes& data) {
  return hmac_legacy(key.data(), key.size(), data.data(), data.size(), true);
}

// ---------------------------------------------------------------- KDFs

Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm, bool sha384_mode) {
  return sha384_mode ? hmac_sha384(salt, ikm) : hmac_sha256(salt, ikm);
}

Bytes hkdf_expand(const Bytes& prk, const Bytes& info, std::size_t out_len, bool sha384_mode) {
  Bytes out;
  Bytes t;
  u8 counter = 1;
  while (out.size() < out_len) {
    Bytes msg = t;
    msg.insert(msg.end(), info.begin(), info.end());
    msg.push_back(counter++);
    t = sha384_mode ? hmac_sha384(prk, msg) : hmac_sha256(prk, msg);
    out.insert(out.end(), t.begin(), t.end());
  }
  out.resize(out_len);
  return out;
}

Bytes hkdf_expand_label(const Bytes& secret, const std::string& label, const Bytes& context,
                        std::size_t out_len, bool sha384_mode) {
  std::string full = "tls13 " + label;
  Bytes info;
  info.push_back(u8(out_len >> 8));
  info.push_back(u8(out_len));
  info.push_back(u8(full.size()));
  info.insert(info.end(), full.begin(), full.end());
  info.push_back(u8(context.size()));
  info.insert(info.end(), context.begin(), context.end());
  return hkdf_expand(secret, info, out_len, sha384_mode);
}

Bytes tls12_prf(const Bytes& secret, const std::string& label, const Bytes& seed,
                std::size_t out_len, bool sha384_mode) {
  Bytes s = seed;
  Bytes ls(label.begin(), label.end());
  Bytes full = ls;
  full.insert(full.end(), s.begin(), s.end());
  Bytes out;
  // A(0) is the whole "label + seed", not just the seed: RFC 5246 §5 defines
  // PRF(secret, label, seed) = P_hash(secret, label + seed) and A(0) = seed, so the
  // label has to be inside A(1)'s HMAC too.  Leaving it out makes every TLS 1.2 key
  // wrong (the origin answers with a plaintext bad_record_mac).
  Bytes a = full;
  while (out.size() < out_len) {
    a = sha384_mode ? hmac_sha384(secret, a) : hmac_sha256(secret, a);
    Bytes msg = a;
    msg.insert(msg.end(), full.begin(), full.end());
    Bytes block = sha384_mode ? hmac_sha384(secret, msg) : hmac_sha256(secret, msg);
    out.insert(out.end(), block.begin(), block.end());
  }
  out.resize(out_len);
  return out;
}

// ---------------------------------------------------------------- AES

namespace {

u8 xtime(u8 x) { return u8((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }

// An 8-bit left rotation. rotl32() would be wrong here: its wrapped bits land
// above bit 7 and are lost when the result is truncated to a byte.
u8 rotl8(u8 x, int n) { return u8((x << n) | (x >> (8 - n))); }

u8 gmul(u8 a, u8 b) {
  u8 p = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) p ^= a;
    u8 hi = u8(a & 0x80);
    a = u8(a << 1);
    if (hi) a ^= 0x1b;
    b = u8(b >> 1);
  }
  return p;
}

// The S-box is derived rather than typed out: the multiplicative inverse in
// GF(2^8) followed by the affine transform. Fewer bytes, no transcription slips.
struct AesTables {
  u8 sbox[256];
  u8 inv[256];
  AesTables() {
    for (int i = 0; i < 256; ++i) {
      u8 x = u8(i);
      u8 y = 0;
      if (x) {
        y = 1;
        for (int k = 0; k < 254; ++k) y = gmul(y, x);  // x^254 == x^-1
      }
      u8 s = u8(y ^ rotl8(y, 1) ^ rotl8(y, 2) ^ rotl8(y, 3) ^ rotl8(y, 4));
      s ^= 0x63;
      sbox[i] = s;
    }
    for (int i = 0; i < 256; ++i) inv[sbox[i]] = u8(i);
  }
};

const AesTables& aes_tables() {
  static const AesTables t;
  return t;
}

const u8 kRcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

u32 sub_word(u32 w) {
  const AesTables& t = aes_tables();
  return (u32(t.sbox[(w >> 24) & 0xff]) << 24) | (u32(t.sbox[(w >> 16) & 0xff]) << 16) |
         (u32(t.sbox[(w >> 8) & 0xff]) << 8) | u32(t.sbox[w & 0xff]);
}

}  // namespace

bool Aes::set_key(const u8* key, std::size_t key_len) {
  if (!key || (key_len != 16 && key_len != 24 && key_len != 32)) return false;
  const int nk = int(key_len / 4);
  rounds_ = nk + 6;
  const int words = 4 * (rounds_ + 1);
  u8* rk = rk_.data();
  std::memcpy(rk, key, key_len);
  for (int i = nk; i < words; ++i) {
    u32 t = ld32be(rk + 4 * (i - 1));
    if (i % nk == 0) {
      t = sub_word(rotl32(t, 8)) ^ (u32(kRcon[i / nk]) << 24);
    } else if (nk > 6 && i % nk == 4) {
      t = sub_word(t);
    }
    st32be(rk + 4 * i, ld32be(rk + 4 * (i - nk)) ^ t);
  }
  ready_ = true;
  return true;
}

void Aes::encrypt_block(const u8 in[16], u8 out[16]) const {
  const AesTables& t = aes_tables();
  u8 s[16];
  std::memcpy(s, in, 16);
  const u8* rk = rk_.data();
  for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
  for (int round = 1; round <= rounds_; ++round) {
    // SubBytes
    for (int i = 0; i < 16; ++i) s[i] = t.sbox[s[i]];
    // ShiftRows: row r (r = i % 4) rotates left by r
    u8 tmp[16];
    for (int r = 0; r < 4; ++r) {
      for (int c = 0; c < 4; ++c) tmp[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    }
    std::memcpy(s, tmp, 16);
    // MixColumns (skipped in the final round)
    if (round != rounds_) {
      for (int c = 0; c < 4; ++c) {
        u8* p = s + 4 * c;
        u8 a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        u8 b0 = u8(xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3);
        u8 b1 = u8(a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3);
        u8 b2 = u8(a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3);
        u8 b3 = u8(xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3));
        p[0] = b0;
        p[1] = b1;
        p[2] = b2;
        p[3] = b3;
      }
    }
    for (int i = 0; i < 16; ++i) s[i] ^= rk[16 * round + i];
  }
  std::memcpy(out, s, 16);
}

void Aes::decrypt_block(const u8 in[16], u8 out[16]) const {
  const AesTables& t = aes_tables();
  u8 s[16];
  std::memcpy(s, in, 16);
  const u8* rk = rk_.data();
  for (int i = 0; i < 16; ++i) s[i] ^= rk[16 * rounds_ + i];
  for (int round = rounds_ - 1; round >= 0; --round) {
    // InvShiftRows: row r rotates right by r
    u8 tmp[16];
    for (int r = 0; r < 4; ++r) {
      for (int c = 0; c < 4; ++c) tmp[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
    }
    std::memcpy(s, tmp, 16);
    for (int i = 0; i < 16; ++i) s[i] = t.inv[s[i]];
    for (int i = 0; i < 16; ++i) s[i] ^= rk[16 * round + i];
    if (round != 0) {
      for (int c = 0; c < 4; ++c) {
        u8* p = s + 4 * c;
        u8 a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        u8 b0 = u8(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
        u8 b1 = u8(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
        u8 b2 = u8(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
        u8 b3 = u8(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
        p[0] = b0;
        p[1] = b1;
        p[2] = b2;
        p[3] = b3;
      }
    }
  }
  std::memcpy(out, s, 16);
}

void aes_ctr_xor(const Aes& aes, const u8 nonce[12], u32 counter, u8* data, std::size_t len) {
  u8 block[16];
  u8 ks[16];
  for (std::size_t off = 0; off < len; off += 16) {
    std::memcpy(block, nonce, 12);
    st32be(block + 12, counter + u32(off / 16));
    aes.encrypt_block(block, ks);
    std::size_t take = len - off < 16 ? len - off : 16;
    for (std::size_t i = 0; i < take; ++i) data[off + i] ^= ks[i];
  }
}

void aes_cbc_encrypt(const Aes& aes, const u8 iv[16], const u8* in, std::size_t len, u8* out) {
  u8 prev[16];
  std::memcpy(prev, iv, 16);
  for (std::size_t off = 0; off + 16 <= len; off += 16) {
    u8 x[16];
    for (int i = 0; i < 16; ++i) x[i] = u8(in[off + i] ^ prev[i]);
    aes.encrypt_block(x, out + off);
    std::memcpy(prev, out + off, 16);
  }
}

void aes_cbc_decrypt(const Aes& aes, const u8 iv[16], const u8* in, std::size_t len, u8* out) {
  u8 prev[16];
  std::memcpy(prev, iv, 16);
  u8 next[16];
  for (std::size_t off = 0; off + 16 <= len; off += 16) {
    std::memcpy(next, in + off, 16);
    u8 plain[16];
    aes.decrypt_block(in + off, plain);
    for (int i = 0; i < 16; ++i) out[off + i] = u8(plain[i] ^ prev[i]);
    std::memcpy(prev, next, 16);
  }
}

// ---------------------------------------------------------------- GCM

namespace {

// Carry-less multiplication in GF(2^128) with the GCM reduction polynomial.
void gf128_mul(const u8 x[16], const u8 h[16], u8 out[16]) {
  u8 z[16] = {0};
  u8 v[16];
  std::memcpy(v, h, 16);
  for (int i = 0; i < 128; ++i) {
    if (x[i / 8] & (0x80 >> (i % 8))) {
      for (int k = 0; k < 16; ++k) z[k] ^= v[k];
    }
    bool lsb = (v[15] & 1) != 0;
    for (int k = 15; k > 0; --k) v[k] = u8((v[k] >> 1) | (v[k - 1] << 7));
    v[0] = u8(v[0] >> 1);
    if (lsb) v[0] ^= 0xe1;
  }
  std::memcpy(out, z, 16);
}

void ghash(const u8 h[16], const u8* aad, std::size_t aad_len, const u8* ct, std::size_t ct_len,
           u8 out[16]) {
  u8 y[16] = {0};
  auto absorb = [&](const u8* p, std::size_t len) {
    for (std::size_t off = 0; off < len; off += 16) {
      u8 block[16] = {0};
      std::size_t take = len - off < 16 ? len - off : 16;
      std::memcpy(block, p + off, take);
      for (int i = 0; i < 16; ++i) y[i] ^= block[i];
      u8 next[16];
      gf128_mul(y, h, next);
      std::memcpy(y, next, 16);
    }
  };
  absorb(aad, aad_len);
  absorb(ct, ct_len);
  u8 lens[16];
  st64be(lens, u64(aad_len) * 8);
  st64be(lens + 8, u64(ct_len) * 8);
  for (int i = 0; i < 16; ++i) y[i] ^= lens[i];
  u8 next[16];
  gf128_mul(y, h, next);
  std::memcpy(out, next, 16);
}

// AES-GCM as used by TLS: 12 byte nonce, 16 byte tag, tag not truncated.
bool gcm_core(const Bytes& key, const Bytes& nonce, const Bytes& aad, const u8* input,
              std::size_t len, bool encrypt, u8* output, u8 tag[16]) {
  if (nonce.size() != 12) return false;
  Aes aes;
  if (!aes.set_key(key)) return false;
  u8 h[16] = {0};
  aes.encrypt_block(h, h);
  u8 j0[16];
  std::memcpy(j0, nonce.data(), 12);
  st32be(j0 + 12, 1);
  u8 ek[16];
  if (encrypt) {
    std::memcpy(output, input, len);
    aes_ctr_xor(aes, nonce.data(), 2, output, len);
  } else {
    std::memcpy(output, input, len);
    aes_ctr_xor(aes, nonce.data(), 2, output, len);
  }
  u8 s[16];
  ghash(h, aad.data(), aad.size(), encrypt ? output : input, len, s);
  aes.encrypt_block(j0, ek);
  for (int i = 0; i < 16; ++i) tag[i] = u8(s[i] ^ ek[i]);
  return true;
}

}  // namespace

AeadResult aes_gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                           const Bytes& plaintext) {
  AeadResult r;
  r.ciphertext.resize(plaintext.size());
  r.tag.resize(16);
  if (!gcm_core(key, nonce, aad, plaintext.data(), plaintext.size(), true, r.ciphertext.data(),
                r.tag.data())) {
    return r;
  }
  r.ok = true;
  return r;
}

bool aes_gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                     const Bytes& ciphertext, const Bytes& tag, Bytes* plaintext) {
  if (tag.size() != 16) return false;
  Bytes out(ciphertext.size());
  u8 want[16];
  if (!gcm_core(key, nonce, aad, ciphertext.data(), ciphertext.size(), false, out.data(), want)) {
    return false;
  }
  // Constant-time-ish comparison: same number of operations regardless of data.
  u8 diff = 0;
  for (int i = 0; i < 16; ++i) diff = u8(diff | (want[i] ^ tag[i]));
  if (diff != 0) return false;
  if (plaintext) *plaintext = std::move(out);
  return true;
}

// ---------------------------------------------------------------- ChaCha20

namespace {

void chacha_quarter(u32& a, u32& b, u32& c, u32& d) {
  a += b;
  d ^= a;
  d = rotl32(d, 16);
  c += d;
  b ^= c;
  b = rotl32(b, 12);
  a += b;
  d ^= a;
  d = rotl32(d, 8);
  c += d;
  b ^= c;
  b = rotl32(b, 7);
}

void chacha_block(const u32 in[16], u8 out[64]) {
  u32 x[16];
  std::memcpy(x, in, sizeof(x));
  for (int i = 0; i < 10; ++i) {
    chacha_quarter(x[0], x[4], x[8], x[12]);
    chacha_quarter(x[1], x[5], x[9], x[13]);
    chacha_quarter(x[2], x[6], x[10], x[14]);
    chacha_quarter(x[3], x[7], x[11], x[15]);
    chacha_quarter(x[0], x[5], x[10], x[15]);
    chacha_quarter(x[1], x[6], x[11], x[12]);
    chacha_quarter(x[2], x[7], x[8], x[13]);
    chacha_quarter(x[3], x[4], x[9], x[14]);
  }
  for (int i = 0; i < 16; ++i) st32le(out + 4 * i, x[i] + in[i]);
}

#if defined(__SSE2__) || defined(_M_X64)
#define NETCAP_CHACHA_SSE2 1
#include <emmintrin.h>

// Four blocks at a time: one XMM register per state word, its four lanes holding
// the same word of four consecutive blocks, so the quarter rounds need no
// cross-lane shuffles.  The registers are transposed on the way out because the
// keystream wants each block's sixteen words next to each other.
#define NETCAP_CHACHA_QR(a, b, c, d)                                                       \
  do {                                                                                     \
    (a) = _mm_add_epi32((a), (b));                                                         \
    (d) = _mm_xor_si128((d), (a));                                                         \
    (d) = _mm_or_si128(_mm_slli_epi32((d), 16), _mm_srli_epi32((d), 16));                  \
    (c) = _mm_add_epi32((c), (d));                                                         \
    (b) = _mm_xor_si128((b), (c));                                                         \
    (b) = _mm_or_si128(_mm_slli_epi32((b), 12), _mm_srli_epi32((b), 20));                  \
    (a) = _mm_add_epi32((a), (b));                                                         \
    (d) = _mm_xor_si128((d), (a));                                                         \
    (d) = _mm_or_si128(_mm_slli_epi32((d), 8), _mm_srli_epi32((d), 24));                   \
    (c) = _mm_add_epi32((c), (d));                                                         \
    (b) = _mm_xor_si128((b), (c));                                                         \
    (b) = _mm_or_si128(_mm_slli_epi32((b), 7), _mm_srli_epi32((b), 25));                   \
  } while (0)

void chacha_transpose(const __m128i w[4], __m128i out[4]) {
  const __m128i t0 = _mm_unpacklo_epi32(w[0], w[1]);
  const __m128i t1 = _mm_unpackhi_epi32(w[0], w[1]);
  const __m128i t2 = _mm_unpacklo_epi32(w[2], w[3]);
  const __m128i t3 = _mm_unpackhi_epi32(w[2], w[3]);
  out[0] = _mm_unpacklo_epi64(t0, t2);
  out[1] = _mm_unpackhi_epi64(t0, t2);
  out[2] = _mm_unpacklo_epi64(t1, t3);
  out[3] = _mm_unpackhi_epi64(t1, t3);
}

void chacha4_keystream(const u32 st[16], u32 counter, u8 out[256]) {
  __m128i x[16];
  for (int i = 0; i < 16; ++i) x[i] = _mm_set1_epi32(static_cast<int>(st[i]));
  x[12] = _mm_set_epi32(static_cast<int>(counter + 3), static_cast<int>(counter + 2),
                        static_cast<int>(counter + 1), static_cast<int>(counter));
  __m128i a[16];
  for (int i = 0; i < 16; ++i) a[i] = x[i];
  for (int round = 0; round < 10; ++round) {
    NETCAP_CHACHA_QR(a[0], a[4], a[8], a[12]);
    NETCAP_CHACHA_QR(a[1], a[5], a[9], a[13]);
    NETCAP_CHACHA_QR(a[2], a[6], a[10], a[14]);
    NETCAP_CHACHA_QR(a[3], a[7], a[11], a[15]);
    NETCAP_CHACHA_QR(a[0], a[5], a[10], a[15]);
    NETCAP_CHACHA_QR(a[1], a[6], a[11], a[12]);
    NETCAP_CHACHA_QR(a[2], a[7], a[8], a[13]);
    NETCAP_CHACHA_QR(a[3], a[4], a[9], a[14]);
  }
  for (int group = 0; group < 4; ++group) {
    __m128i sums[4];
    for (int i = 0; i < 4; ++i) {
      sums[i] = _mm_add_epi32(a[group * 4 + i], x[group * 4 + i]);
    }
    __m128i blocks[4];
    chacha_transpose(sums, blocks);
    for (int block = 0; block < 4; ++block) {
      _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 64 * block + 16 * group), blocks[block]);
    }
  }
}

#undef NETCAP_CHACHA_QR
#endif  // SSE2

void chacha_state(const Bytes& key, const Bytes& nonce, u32 counter, u32 st[16]) {
  static const u8 kSigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};
  for (int i = 0; i < 4; ++i) st[i] = ld32le(kSigma + 4 * i);
  for (int i = 0; i < 8; ++i) st[4 + i] = ld32le(key.data() + 4 * i);
  st[12] = counter;
  st[13] = ld32le(nonce.data());
  st[14] = ld32le(nonce.data() + 4);
  st[15] = ld32le(nonce.data() + 8);
}

}  // namespace

Bytes chacha20_xor(const Bytes& key, const Bytes& nonce, u32 counter, const Bytes& data) {
  Bytes out = data;
  if (key.size() != 32 || nonce.size() != 12) return out;
  u32 st[16];
  chacha_state(key, nonce, counter, st);
  u8 ks[64];
  std::size_t off = 0;
#if defined(NETCAP_CHACHA_SSE2)
  alignas(16) u8 stream[256];
  for (; off + 256 <= out.size(); off += 256) {
    chacha4_keystream(st, st[12], stream);
    st[12] += 4;
    for (std::size_t i = 0; i < 256; i += 16) {
      const __m128i data16 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(out.data() + off + i));
      const __m128i key16 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(stream + i));
      _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data() + off + i),
                       _mm_xor_si128(data16, key16));
    }
  }
#endif
  for (; off < out.size(); off += 64) {
    chacha_block(st, ks);
    st[12] += 1;
    std::size_t take = out.size() - off < 64 ? out.size() - off : 64;
    for (std::size_t i = 0; i < take; ++i) out[off + i] ^= ks[i];
  }
  return out;
}

#if defined(__SSE2__) || defined(_M_X64)
#define NETCAP_POLY_SSE2 1
#include <emmintrin.h>
#endif

namespace {

#ifdef NETCAP_POLY_SSE2

const u32 kPolyMask26 = 0x3ffffff;

// a * b mod 2^130-5 for two canonical 5x26-bit values.  Used to build the
// r^1..r^4 power table the four-block path needs.
void poly_mul_limbs(const u32 a[5], const u32 b[5], u32 out[5]) {
  const u64 s1 = 5ull * b[1], s2 = 5ull * b[2], s3 = 5ull * b[3], s4 = 5ull * b[4];
  u64 d0 = u64(a[0]) * b[0] + u64(a[1]) * s4 + u64(a[2]) * s3 + u64(a[3]) * s2 + u64(a[4]) * s1;
  u64 d1 = u64(a[0]) * b[1] + u64(a[1]) * b[0] + u64(a[2]) * s4 + u64(a[3]) * s3 + u64(a[4]) * s2;
  u64 d2 = u64(a[0]) * b[2] + u64(a[1]) * b[1] + u64(a[2]) * b[0] + u64(a[3]) * s4 + u64(a[4]) * s3;
  u64 d3 = u64(a[0]) * b[3] + u64(a[1]) * b[2] + u64(a[2]) * b[1] + u64(a[3]) * b[0] + u64(a[4]) * s4;
  u64 d4 = u64(a[0]) * b[4] + u64(a[1]) * b[3] + u64(a[2]) * b[2] + u64(a[3]) * b[1] + u64(a[4]) * b[0];

  u32 c = u32(d0 >> 26);
  out[0] = u32(d0) & kPolyMask26;
  d1 += c;
  c = u32(d1 >> 26);
  out[1] = u32(d1) & kPolyMask26;
  d2 += c;
  c = u32(d2 >> 26);
  out[2] = u32(d2) & kPolyMask26;
  d3 += c;
  c = u32(d3 >> 26);
  out[3] = u32(d3) & kPolyMask26;
  d4 += c;
  c = u32(d4 >> 26);
  out[4] = u32(d4) & kPolyMask26;
  u32 h0 = out[0] + c * 5;
  c = h0 >> 26;
  out[0] = h0 & kPolyMask26;
  out[1] += c;
}

// Multiply one 2-lane accumulator by the 2-lane power multiplier and reduce.
// Everything stays in 64-bit lanes, so no shuffles are needed in the loop.
inline void poly_lanes_mul(__m128i h[5], const __m128i R[5], const __m128i S[5],
                           const __m128i mask) {
  __m128i d0 = _mm_add_epi64(_mm_mul_epu32(h[0], R[0]), _mm_mul_epu32(h[1], S[4]));
  d0 = _mm_add_epi64(d0, _mm_mul_epu32(h[2], S[3]));
  d0 = _mm_add_epi64(d0, _mm_mul_epu32(h[3], S[2]));
  d0 = _mm_add_epi64(d0, _mm_mul_epu32(h[4], S[1]));

  __m128i d1 = _mm_add_epi64(_mm_mul_epu32(h[0], R[1]), _mm_mul_epu32(h[1], R[0]));
  d1 = _mm_add_epi64(d1, _mm_mul_epu32(h[2], S[4]));
  d1 = _mm_add_epi64(d1, _mm_mul_epu32(h[3], S[3]));
  d1 = _mm_add_epi64(d1, _mm_mul_epu32(h[4], S[2]));

  __m128i d2 = _mm_add_epi64(_mm_mul_epu32(h[0], R[2]), _mm_mul_epu32(h[1], R[1]));
  d2 = _mm_add_epi64(d2, _mm_mul_epu32(h[2], R[0]));
  d2 = _mm_add_epi64(d2, _mm_mul_epu32(h[3], S[4]));
  d2 = _mm_add_epi64(d2, _mm_mul_epu32(h[4], S[3]));

  __m128i d3 = _mm_add_epi64(_mm_mul_epu32(h[0], R[3]), _mm_mul_epu32(h[1], R[2]));
  d3 = _mm_add_epi64(d3, _mm_mul_epu32(h[2], R[1]));
  d3 = _mm_add_epi64(d3, _mm_mul_epu32(h[3], R[0]));
  d3 = _mm_add_epi64(d3, _mm_mul_epu32(h[4], S[4]));

  __m128i d4 = _mm_add_epi64(_mm_mul_epu32(h[0], R[4]), _mm_mul_epu32(h[1], R[3]));
  d4 = _mm_add_epi64(d4, _mm_mul_epu32(h[2], R[2]));
  d4 = _mm_add_epi64(d4, _mm_mul_epu32(h[3], R[1]));
  d4 = _mm_add_epi64(d4, _mm_mul_epu32(h[4], R[0]));

  __m128i c = _mm_srli_epi64(d0, 26);
  h[0] = _mm_and_si128(d0, mask);
  d1 = _mm_add_epi64(d1, c);
  c = _mm_srli_epi64(d1, 26);
  h[1] = _mm_and_si128(d1, mask);
  d2 = _mm_add_epi64(d2, c);
  c = _mm_srli_epi64(d2, 26);
  h[2] = _mm_and_si128(d2, mask);
  d3 = _mm_add_epi64(d3, c);
  c = _mm_srli_epi64(d3, 26);
  h[3] = _mm_and_si128(d3, mask);
  d4 = _mm_add_epi64(d4, c);
  c = _mm_srli_epi64(d4, 26);
  h[4] = _mm_and_si128(d4, mask);
  c = _mm_add_epi64(c, _mm_slli_epi64(c, 2));  // c * 5
  h[0] = _mm_add_epi64(h[0], c);
  c = _mm_srli_epi64(h[0], 26);
  h[0] = _mm_and_si128(h[0], mask);
  h[1] = _mm_add_epi64(h[1], c);
}

inline u64 poly_lane_hi(__m128i v) {
  return u64(_mm_cvtsi128_si64(_mm_unpackhi_epi64(v, v)));
}

inline u64 poly_lane_lo(__m128i v) { return u64(_mm_cvtsi128_si64(v)); }

#endif  // NETCAP_POLY_SSE2

// Four blocks of 16 bytes per pass.  The four blocks cannot share one
// multiplier - the recurrence is h' = ((h+m0)r + m1)r + ... - so a group is
// written as h' = (h+m0)r^4 + m1r^3 + m2r^2 + m3r^1: each lane carries its own
// power of r, and two 2-lane SSE2 streams cover the four lanes.  Returns the
// number of 64-byte groups consumed (0 when the machine has no SSE2, so the
// caller falls back to the scalar loop and still hashes every block).
std::size_t poly1305_blocks_sse2(const u32 r[5], u32 h[5], const u8* data, std::size_t groups) {
#ifdef NETCAP_POLY_SSE2
  if (groups == 0) return 0;
  u32 pw[4][5];  // pw[k] = r^(k+1)
  for (int i = 0; i < 5; ++i) pw[0][i] = r[i];
  poly_mul_limbs(pw[0], r, pw[1]);
  poly_mul_limbs(pw[1], r, pw[2]);
  poly_mul_limbs(pw[2], r, pw[3]);

  const __m128i mask = _mm_set1_epi64x(0x3ffffff);
  const __m128i zero = _mm_setzero_si128();
  __m128i ra[5], sa[5], rb[5], sb[5];
  for (int i = 0; i < 5; ++i) {
    // Stream a: lane 0 = block 0 with r^4, lane 1 = block 1 with r^3.
    // Stream b: lane 0 = block 2 with r^2, lane 1 = block 3 with r^1.
    ra[i] = _mm_set_epi64x(static_cast<long long>(pw[2][i]), static_cast<long long>(pw[3][i]));
    rb[i] = _mm_set_epi64x(static_cast<long long>(pw[0][i]), static_cast<long long>(pw[1][i]));
    sa[i] = _mm_set_epi64x(static_cast<long long>(5u * pw[2][i]), static_cast<long long>(5u * pw[3][i]));
    sb[i] = _mm_set_epi64x(static_cast<long long>(5u * pw[0][i]), static_cast<long long>(5u * pw[1][i]));
  }

  const __m128i hbit = _mm_set1_epi32(1 << 24);
  const __m128i m26 = _mm_set1_epi32(0x3ffffff);

  for (std::size_t g = 0; g < groups; ++g) {
    const u8* m = data + g * 64;
    const __m128i b0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m));
    const __m128i b1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m + 16));
    const __m128i b2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m + 32));
    const __m128i b3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m + 48));
    const __m128i t0 = _mm_unpacklo_epi32(b0, b1);
    const __m128i t1 = _mm_unpackhi_epi32(b0, b1);
    const __m128i t2 = _mm_unpacklo_epi32(b2, b3);
    const __m128i t3 = _mm_unpackhi_epi32(b2, b3);
    const __m128i w0 = _mm_unpacklo_epi64(t0, t2);
    const __m128i w1 = _mm_unpackhi_epi64(t0, t2);
    const __m128i w2 = _mm_unpacklo_epi64(t1, t3);
    const __m128i w3 = _mm_unpackhi_epi64(t1, t3);

    __m128i ml[5];
    ml[0] = _mm_and_si128(w0, m26);
    ml[1] = _mm_and_si128(_mm_or_si128(_mm_srli_epi32(w0, 26), _mm_slli_epi32(w1, 6)), m26);
    ml[2] = _mm_and_si128(_mm_or_si128(_mm_srli_epi32(w1, 20), _mm_slli_epi32(w2, 12)), m26);
    ml[3] = _mm_and_si128(_mm_or_si128(_mm_srli_epi32(w2, 14), _mm_slli_epi32(w3, 18)), m26);
    ml[4] = _mm_or_si128(_mm_srli_epi32(w3, 8), hbit);

    __m128i ha[5], hb[5];
    for (int i = 0; i < 5; ++i) {
      ha[i] = _mm_unpacklo_epi32(ml[i], zero);  // 64-bit lane 0 = block 0, lane 1 = block 1
      hb[i] = _mm_unpackhi_epi32(ml[i], zero);  // 64-bit lane 0 = block 2, lane 1 = block 3
    }
    // The running accumulator joins block 0's lane, whose multiplier is r^4.
    ha[0] = _mm_add_epi64(ha[0], _mm_set_epi64x(0, static_cast<long long>(h[0])));
    ha[1] = _mm_add_epi64(ha[1], _mm_set_epi64x(0, static_cast<long long>(h[1])));
    ha[2] = _mm_add_epi64(ha[2], _mm_set_epi64x(0, static_cast<long long>(h[2])));
    ha[3] = _mm_add_epi64(ha[3], _mm_set_epi64x(0, static_cast<long long>(h[3])));
    ha[4] = _mm_add_epi64(ha[4], _mm_set_epi64x(0, static_cast<long long>(h[4])));

    poly_lanes_mul(ha, ra, sa, mask);
    poly_lanes_mul(hb, rb, sb, mask);

    // Each lane holds a partial residue mod p; their sum is the new state.
    for (int i = 0; i < 5; ++i) {
      h[i] = poly_lane_lo(ha[i]) + poly_lane_hi(ha[i]) + poly_lane_lo(hb[i]) + poly_lane_hi(hb[i]);
    }
    // Renormalise: limb sums can reach a bit over 2^28 here.
    u64 c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;
  }
  return groups;
#else
  (void)r;
  (void)h;
  (void)data;
  return 0;
#endif
}

}  // namespace

Poly1305::Poly1305() {}

void Poly1305::init(const Bytes& key32) {
  r0_ = r1_ = r2_ = r3_ = r4_ = 0;
  s1_ = s2_ = s3_ = s4_ = 0;
  h0_ = h1_ = h2_ = h3_ = h4_ = 0;
  have_ = 0;
  std::memset(key_, 0, sizeof key_);
  ready_ = key32.size() == 32;
  if (!ready_) return;
  std::memcpy(key_, key32.data(), 32);
  const u8* key = key_;
  const u32 t0 = ld32le(key), t1 = ld32le(key + 4), t2 = ld32le(key + 8), t3 = ld32le(key + 12);
  r0_ = t0 & 0x3ffffff;
  r1_ = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  r2_ = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  r3_ = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  r4_ = (t3 >> 8) & 0x00fffff;
  s1_ = r1_ * 5;
  s2_ = r2_ * 5;
  s3_ = r3_ * 5;
  s4_ = r4_ * 5;
}

// One block straight out of the caller's buffer: no staging copy, which for a
// 16 KiB record used to cost more than the arithmetic itself.  "full" blocks
// carry the 2^128 bit; a short trailing block gets its own high bit set by
// finish() before it is handed over.
void Poly1305::block(const u8* m, bool full) {
  const u32 b0 = ld32le(m), b1 = ld32le(m + 4), b2 = ld32le(m + 8), b3 = ld32le(m + 12);
  h0_ += b0 & 0x3ffffff;
  h1_ += ((b0 >> 26) | (b1 << 6)) & 0x3ffffff;
  h2_ += ((b1 >> 20) | (b2 << 12)) & 0x3ffffff;
  h3_ += ((b2 >> 14) | (b3 << 18)) & 0x3ffffff;
  h4_ += (b3 >> 8) | (full ? (1u << 24) : 0u);

  u64 d0 = u64(h0_) * r0_ + u64(h1_) * s4_ + u64(h2_) * s3_ + u64(h3_) * s2_ + u64(h4_) * s1_;
  u64 d1 = u64(h0_) * r1_ + u64(h1_) * r0_ + u64(h2_) * s4_ + u64(h3_) * s3_ + u64(h4_) * s2_;
  u64 d2 = u64(h0_) * r2_ + u64(h1_) * r1_ + u64(h2_) * r0_ + u64(h3_) * s4_ + u64(h4_) * s3_;
  u64 d3 = u64(h0_) * r3_ + u64(h1_) * r2_ + u64(h2_) * r1_ + u64(h3_) * r0_ + u64(h4_) * s4_;
  u64 d4 = u64(h0_) * r4_ + u64(h1_) * r3_ + u64(h2_) * r2_ + u64(h3_) * r1_ + u64(h4_) * r0_;

  u32 c = u32(d0 >> 26);
  h0_ = u32(d0) & 0x3ffffff;
  d1 += c;
  c = u32(d1 >> 26);
  h1_ = u32(d1) & 0x3ffffff;
  d2 += c;
  c = u32(d2 >> 26);
  h2_ = u32(d2) & 0x3ffffff;
  d3 += c;
  c = u32(d3 >> 26);
  h3_ = u32(d3) & 0x3ffffff;
  d4 += c;
  c = u32(d4 >> 26);
  h4_ = u32(d4) & 0x3ffffff;
  h0_ += c * 5;
  c = h0_ >> 26;
  h0_ &= 0x3ffffff;
  h1_ += c;
}

void Poly1305::update(const u8* data, std::size_t len) {
  if (!ready_ || len == 0) return;
  if (have_ != 0) {
    const std::size_t need = 16 - have_;
    const std::size_t take = len < need ? len : need;
    std::memcpy(buf_ + have_, data, take);
    have_ += take;
    data += take;
    len -= take;
    if (have_ == 16) {
      block(buf_, true);
      have_ = 0;
    }
  }
    // Four 16-byte blocks per pass.  This is the whole reason the group trick
  // exists: a group of four blocks is one multiply chain instead of four, and
  // each lane carries its own power of r.  Whatever is left - the tail, or a
  // machine without SSE2, where the call returns 0 - falls through to the
  // scalar loop below.
  {
    u32 r[5] = {r0_, r1_, r2_, r3_, r4_};
    u32 h[5] = {h0_, h1_, h2_, h3_, h4_};
    const std::size_t groups = poly1305_blocks_sse2(r, h, data, len / 64);
    if (groups != 0) {
      h0_ = h[0];
      h1_ = h[1];
      h2_ = h[2];
      h3_ = h[3];
      h4_ = h[4];
      data += groups * 64;
      len -= groups * 64;
    }
  }while (len >= 16) {
    block(data, true);
    data += 16;
    len -= 16;
  }
  if (len != 0) {
    std::memcpy(buf_, data, len);
    have_ = len;
  }
}

Bytes Poly1305::finish() {
  Bytes tag16(16, 0);
  if (!ready_) return tag16;
  if (have_ != 0) {
    std::memset(buf_ + have_, 0, 16 - have_);
    buf_[have_] = 1;
    block(buf_, false);
    have_ = 0;
  }
  ready_ = false;  // the message ends here; a second finish() would be meaningless
  u32 h0 = h0_, h1 = h1_, h2 = h2_, h3 = h3_, h4 = h4_;

  u32 c = h1 >> 26;
  h1 &= 0x3ffffff;
  h2 += c;
  c = h2 >> 26;
  h2 &= 0x3ffffff;
  h3 += c;
  c = h3 >> 26;
  h3 &= 0x3ffffff;
  h4 += c;
  c = h4 >> 26;
  h4 &= 0x3ffffff;
  h0 += c * 5;
  c = h0 >> 26;
  h0 &= 0x3ffffff;
  h1 += c;

  u32 g0 = h0 + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;
  u32 g1 = h1 + c;
  c = g1 >> 26;
  g1 &= 0x3ffffff;
  u32 g2 = h2 + c;
  c = g2 >> 26;
  g2 &= 0x3ffffff;
  u32 g3 = h3 + c;
  c = g3 >> 26;
  g3 &= 0x3ffffff;
  u32 g4 = h4 + c - (1u << 26);

  u32 mask = (g4 >> 31) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  h0 = (h0 | (h1 << 26)) & 0xffffffff;
  h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
  h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

  u64 f = u64(h0) + u64(ld32le(key_ + 16));
  st32le(tag16.data(), u32(f));
  f = u64(h1) + u64(ld32le(key_ + 20)) + (f >> 32);
  st32le(tag16.data() + 4, u32(f));
  f = u64(h2) + u64(ld32le(key_ + 24)) + (f >> 32);
  st32le(tag16.data() + 8, u32(f));
  f = u64(h3) + u64(ld32le(key_ + 28)) + (f >> 32);
  st32le(tag16.data() + 12, u32(f));
  return tag16;
}

Bytes poly1305(const Bytes& key32, const Bytes& msg) {
  Poly1305 mac;
  mac.init(key32);
  mac.update(msg);
  return mac.finish();
}


namespace {
// Both AEAD halves hash a piece of data followed by zero padding to 16 bytes.
void poly_pad(Poly1305* mac, std::size_t len) {
  static const u8 zeros[16] = {0};
  const std::size_t pad = (16 - (len % 16)) % 16;
  if (pad != 0) mac->update(zeros, pad);
}
}  // namespace
AeadResult chacha20_poly1305_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                    const Bytes& plaintext) {
  AeadResult r;
  if (key.size() != 32 || nonce.size() != 12) return r;
  u32 st[16];
  chacha_state(key, nonce, 0, st);
  u8 block0[64];
  chacha_block(st, block0);
  Bytes otk(block0, block0 + 32);
  r.ciphertext = chacha20_xor(key, nonce, 1, plaintext);
  u8 lens[16];
  st64le(lens, u64(aad.size()));
  st64le(lens + 8, u64(r.ciphertext.size()));
  Poly1305 mac;
  mac.init(otk);
  mac.update(aad);
  poly_pad(&mac, aad.size());
  mac.update(r.ciphertext);
  poly_pad(&mac, r.ciphertext.size());
  mac.update(lens, 16);
  r.tag = mac.finish();
  r.ok = true;
  return r;
}

bool chacha20_poly1305_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                               const Bytes& ciphertext, const Bytes& tag, Bytes* plaintext) {
  if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16) return false;
  u32 st[16];
  chacha_state(key, nonce, 0, st);
  u8 block0[64];
  chacha_block(st, block0);
  Bytes otk(block0, block0 + 32);
  u8 lens[16];
  st64le(lens, u64(aad.size()));
  st64le(lens + 8, u64(ciphertext.size()));
  Poly1305 mac;
  mac.init(otk);
  mac.update(aad);
  poly_pad(&mac, aad.size());
  mac.update(ciphertext);
  poly_pad(&mac, ciphertext.size());
  mac.update(lens, 16);
  const Bytes want = mac.finish();
  u8 diff = 0;
  for (int i = 0; i < 16; ++i) diff = u8(diff | (want[i] ^ tag[i]));
  if (diff != 0) return false;
  if (plaintext) *plaintext = chacha20_xor(key, nonce, 1, ciphertext);
  return true;
}

// ---------------------------------------------------------------- key log

std::vector<KeyLogEntry> parse_keylog(const std::string& text) {
  std::vector<KeyLogEntry> out;
  std::size_t pos = 0;
  while (pos <= text.size()) {
    std::size_t nl = text.find('\n', pos);
    std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
    pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
    // Trim CR and surrounding blanks, skip comments and empty lines.
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
      line.pop_back();
    }
    std::size_t b = line.find_first_not_of(" \t");
    if (b == std::string::npos) continue;
    line = line.substr(b);
    if (line.empty() || line[0] == '#') continue;
    std::size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) continue;
    std::size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) continue;
    KeyLogEntry e;
    e.label = line.substr(0, sp1);
    e.client_random = from_hex(line.substr(sp1 + 1, sp2 - sp1 - 1));
    e.secret = from_hex(line.substr(sp2 + 1));
    if (e.client_random.size() != 32 || e.secret.empty()) continue;
    out.push_back(std::move(e));
  }
  return out;
}

bool load_keylog_file(const std::string& path, std::vector<KeyLogEntry>* out, std::string* error) {
  if (out) out->clear();
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    if (error) *error = "cannot open key log file '" + path + "'";
    return false;
  }
  std::string text;
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
  std::fclose(f);
  std::vector<KeyLogEntry> entries = parse_keylog(text);
  if (entries.empty()) {
    if (error) *error = "no usable key log lines in '" + path + "'";
    return false;
  }
  if (out) *out = std::move(entries);
  return true;
}

}  // namespace netcap
