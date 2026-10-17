// TLS 1.2 client: see include/netcap/tls12.hpp for what is covered and, just as
// importantly, what is not.
#include "netcap/tls12.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "netcap/p256.hpp"
#include "netcap/rsa.hpp"
#include "netcap/x25519.hpp"
#include "netcap/x509.hpp"

namespace netcap {
namespace {

constexpr u8 kHandshake = 22;
constexpr u8 kChangeCipherSpec = 20;
constexpr u8 kAlert = 21;
constexpr u8 kApplicationData = 23;

constexpr u16 kTls12Version = 0x0303;
constexpr u16 kTls10Version = 0x0301;

constexpr std::size_t kMaxPlaintext = 16384;  // RFC 5246 §6.2.1
constexpr std::size_t kMaxRecordBody = kMaxPlaintext + 2048;

// The suites this client offers, in preference order.  Field order matches
// Tls12Suite: {id, name, ecdsa, rsa, key_len, fixed_iv_len, chacha, cbc,
// rsa_key_exchange, mac_len, min_version}.
//
// The first block is what a modern TLS 1.2 origin wants; below it are the CBC
// suites, which are what TLS 1.0/1.1 origins actually offer.  `min_version`
// keeps the AEAD suites out of a 1.0/1.1 ClientHello (GCM and ChaCha20-Poly1305
// were defined for 1.2) and keeps the SHA-256 CBC suites out of 1.0/1.1 too.
// Suites with a SHA-384 PRF (…AES256-GCM-SHA384) are deliberately absent: the
// PRF hash would have to follow the suite, which buys nothing for the legacy
// origins this exists for.
const Tls12Suite kSuites[] = {
    {0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256", true, false, 16, 4, false},
    {0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", false, true, 16, 4, false},
    {0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305", true, false, 32, 12, true},
    {0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305", false, true, 32, 12, true},
    {0x009C, "RSA-AES128-GCM-SHA256", false, true, 16, 4, false, false, true},
    {0xC027, "ECDHE-RSA-AES128-CBC-SHA256", false, true, 16, 16, false, true, false, 32},
    {0xC028, "ECDHE-RSA-AES256-CBC-SHA256", false, true, 32, 16, false, true, false, 32},
    {0xC023, "ECDHE-ECDSA-AES128-CBC-SHA256", true, false, 16, 16, false, true, false, 32},
    {0xC024, "ECDHE-ECDSA-AES256-CBC-SHA256", true, false, 32, 16, false, true, false, 32},
    {0x003C, "RSA-AES128-CBC-SHA256", false, true, 16, 16, false, true, true, 32},
    {0x003D, "RSA-AES256-CBC-SHA256", false, true, 32, 16, false, true, true, 32},
    {0xC013, "ECDHE-RSA-AES128-CBC-SHA", false, true, 16, 16, false, true, false, 20, 0x0301},
    {0xC014, "ECDHE-RSA-AES256-CBC-SHA", false, true, 32, 16, false, true, false, 20, 0x0301},
    {0xC009, "ECDHE-ECDSA-AES128-CBC-SHA", true, false, 16, 16, false, true, false, 20, 0x0301},
    {0xC00A, "ECDHE-ECDSA-AES256-CBC-SHA", true, false, 32, 16, false, true, false, 20, 0x0301},
    {0x002F, "RSA-AES128-CBC-SHA", false, true, 16, 16, false, true, true, 20, 0x0301},
    {0x0035, "RSA-AES256-CBC-SHA", false, true, 32, 16, false, true, true, 20, 0x0301},
};

void put16(Bytes& out, u16 v) {
  out.push_back(static_cast<u8>(v >> 8));
  out.push_back(static_cast<u8>(v & 0xff));
}

void put24(Bytes& out, u32 v) {
  out.push_back(static_cast<u8>((v >> 16) & 0xff));
  out.push_back(static_cast<u8>((v >> 8) & 0xff));
  out.push_back(static_cast<u8>(v & 0xff));
}

u16 rd16(const Bytes& b, std::size_t off) {
  return static_cast<u16>((static_cast<u16>(b[off]) << 8) | b[off + 1]);
}

u32 rd24(const Bytes& b, std::size_t off) {
  return (static_cast<u32>(b[off]) << 16) | (static_cast<u32>(b[off + 1]) << 8) | b[off + 2];
}

Bytes u64_be(u64 v) {
  Bytes out(8, 0);
  for (int i = 7; i >= 0; --i) out[static_cast<std::size_t>(i)] = static_cast<u8>(v & 0xff), v >>= 8;
  return out;
}

Bytes ascii(const std::string& text) { return Bytes(text.begin(), text.end()); }

std::string hex_of(const Bytes& data, std::size_t limit = 0) {
  static const char* kDigits = "0123456789abcdef";
  std::string out;
  const std::size_t count = limit == 0 ? data.size() : std::min(limit, data.size());
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0f]);
  }
  return out;
}

bool trace_on() {
  static const bool on = std::getenv("NETCAP_TLS12_TRACE") != nullptr;
  return on;
}

Bytes record_header(u8 type, u16 version, std::size_t body) {
  Bytes out;
  out.push_back(type);
  put16(out, version);
  put16(out, static_cast<u16>(body));
  return out;
}

Bytes handshake_message(u8 type, const Bytes& body) {
  Bytes out;
  out.push_back(type);
  put24(out, static_cast<u32>(body.size()));
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::string alert_text(u8 description) {
  switch (description) {
    case 0: return "close_notify";
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 22: return "record_overflow";
    case 40: return "handshake_failure";
    case 42: return "bad_certificate";
    case 43: return "unsupported_certificate";
    case 45: return "certificate_expired";
    case 46: return "certificate_unknown";
    case 47: return "illegal_parameter";
    case 48: return "unknown_ca";
    case 49: return "access_denied";
    case 51: return "decrypt_error";
    case 70: return "protocol_version";
    case 71: return "insufficient_security";
    case 80: return "internal_error";
    case 90: return "user_canceled";
    case 100: return "no_renegotiation";
    case 109: return "missing_extension";
    case 110: return "unsupported_extension";
    default: return "alert " + std::to_string(description);
  }
}

std::string now_utc_key() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::snprintf(buf, sizeof buf, "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec);
  return std::string(buf);
}

// "240101000000Z" -> "20240101000000" (UTCTime); "20240101000000Z" with
// GeneralizedTime keeps all 14 digits.
std::string time_key(const std::string& text) {
  std::string digits;
  for (char ch : text) {
    if (ch >= '0' && ch <= '9') digits.push_back(ch);
    else break;
  }
  if (digits.size() == 12) return "20" + digits;
  if (digits.size() >= 14) return digits.substr(0, 14);
  return digits;
}

// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } — DER, minimally encoded.
bool parse_der_signature(const Bytes& der, Bytes* r, Bytes* s) {
  std::size_t off = 0;
  auto read_len = [&](std::size_t* len) -> bool {
    if (off >= der.size()) return false;
    u8 first = der[off++];
    if ((first & 0x80) == 0) {
      *len = first;
      return true;
    }
    std::size_t count = first & 0x7f;
    if (count == 0 || count > 3 || off + count > der.size()) return false;
    std::size_t value = 0;
    for (std::size_t i = 0; i < count; ++i) value = (value << 8) | der[off++];
    *len = value;
    return true;
  };
  if (der.empty() || der[off++] != 0x30) return false;
  std::size_t seq_len = 0;
  if (!read_len(&seq_len) || off + seq_len > der.size()) return false;
  auto read_int = [&](Bytes* out) -> bool {
    if (off >= der.size() || der[off++] != 0x02) return false;
    std::size_t len = 0;
    if (!read_len(&len) || off + len > der.size()) return false;
    Bytes raw(der.begin() + static_cast<std::ptrdiff_t>(off),
              der.begin() + static_cast<std::ptrdiff_t>(off + len));
    off += len;
    while (raw.size() > 1 && raw.front() == 0x00) raw.erase(raw.begin());
    *out = raw;
    return true;
  };
  if (!read_int(r) || !read_int(s)) return false;
  if (r->empty() || s->empty() || r->size() > 32 || s->size() > 32) return false;
  // left pad to 32 bytes so the verifier sees fixed width numbers
  auto pad = [](Bytes* v) {
    Bytes out(32 - v->size(), 0x00);
    out.insert(out.end(), v->begin(), v->end());
    *v = out;
  };
  pad(r);
  pad(s);
  return true;
}

Bytes client_hello_body(const std::string& host, const std::string& alpn, const Bytes& random,
                        int version = kTls12Version) {
  Bytes b;
  put16(b, static_cast<u16>(version));
  b.insert(b.end(), random.begin(), random.end());
  b.push_back(0x00);  // no session id: this client never resumes
  const std::vector<u16> suites = tls12_offered_suites(version);
  put16(b, static_cast<u16>(suites.size() * 2));
  for (u16 id : suites) put16(b, id);
  b.push_back(0x01);
  b.push_back(0x00);  // null compression only

  Bytes ext;
  auto extension = [&ext](u16 type, const Bytes& body) {
    put16(ext, type);
    put16(ext, static_cast<u16>(body.size()));
    ext.insert(ext.end(), body.begin(), body.end());
  };
  if (!host.empty()) {
    Bytes name = ascii(host);
    Bytes body;
    put16(body, static_cast<u16>(name.size() + 3));
    body.push_back(0x00);  // host_name
    put16(body, static_cast<u16>(name.size()));
    body.insert(body.end(), name.begin(), name.end());
    extension(0x0000, body);  // server_name (RFC 6066)
  }
  {
    Bytes body;
    put16(body, 4);
    put16(body, 0x001d);  // x25519
    put16(body, 0x0017);  // secp256r1
    extension(0x000a, body);  // supported_groups
  }
  {
    Bytes body;
    body.push_back(0x01);
    body.push_back(0x00);  // uncompressed
    extension(0x000b, body);  // ec_point_formats
  }
  // signature_algorithms is an RFC 5246 (1.2) extension: sending it in a 1.0/1.1
  // ClientHello makes some old servers answer with an unsupported_extension
  // alert, and those versions sign with the fixed SHA-1 scheme anyway.
  if (version >= kTls12Version) {
    Bytes body;
    put16(body, 8);
    put16(body, 0x0403);  // ecdsa_secp256r1_sha256 (RFC 8422)
    put16(body, 0x0804);  // rsa_pss_rsae_sha256
    put16(body, 0x0401);  // rsa_pkcs1_sha256
    put16(body, 0x0503);  // ecdsa_secp384r1_sha384 (only for completeness)
    extension(0x000d, body);  // signature_algorithms
  }
  if (!alpn.empty() && version >= kTls12Version) {
    Bytes list;
    list.push_back(static_cast<u8>(alpn.size()));
    list.insert(list.end(), alpn.begin(), alpn.end());
    Bytes body;
    put16(body, static_cast<u16>(list.size()));
    body.insert(body.end(), list.begin(), list.end());
    extension(0x0010, body);  // application_layer_protocol_negotiation (RFC 7301)
  }
  // RFC 7627 hooks the session hash into the master secret; for 1.0/1.1 that
  // hash would be MD5||SHA1, so this client keeps those versions on the plain
  // master secret instead (the extension is optional, servers accept its absence).
  if (version >= kTls12Version) extension(0x0017, Bytes());  // extended_master_secret (RFC 7627)
  {
    Bytes body;
    body.push_back(0x00);
    extension(0xff01, body);  // renegotiation_info, empty (RFC 5746)
  }
  put16(b, static_cast<u16>(ext.size()));
  b.insert(b.end(), ext.begin(), ext.end());
  return b;
}

struct ServerHello {
  Bytes random;
  Bytes session_id;
  u16 version = kTls12Version;
  u16 suite = 0;
  bool ems = false;
  std::string alpn;
};

bool parse_server_hello(const Bytes& body, ServerHello* out, std::string* error) {
  if (body.size() < 38) {
    *error = "the ServerHello is too short";
    return false;
  }
  const u16 version = rd16(body, 0);
  // We offer up to 1.2 and let the origin pick anything from 1.0 up: that is the
  // point of this client, whose callers pass the version they want to try first.
  if (version < 0x0301 || version > kTls12Version) {
    if (version == 0x0304) {
      *error = "the origin answered with TLS 1.3 even though we offered only 1.2 and below";
    } else {
      char buf[72];
      std::snprintf(buf, sizeof buf, "the origin chose TLS 0x%04x, which this client does not offer", version);
      *error = buf;
    }
    return false;
  }
  out->version = version;
  out->random.assign(body.begin() + 2, body.begin() + 34);
  const std::size_t sid_len = body[34];
  std::size_t off = 35 + sid_len;
  if (off + 3 > body.size()) {
    *error = "the ServerHello is truncated";
    return false;
  }
  out->session_id.assign(body.begin() + 35, body.begin() + 35 + sid_len);
  out->suite = rd16(body, off);
  off += 3;  // suite + compression
  if (off + 2 <= body.size()) {
    const std::size_t ext_total = rd16(body, off);
    off += 2;
    const std::size_t ext_end = std::min(body.size(), off + ext_total);
    while (off + 4 <= ext_end) {
      const u16 type = rd16(body, off);
      const std::size_t len = rd16(body, off + 2);
      off += 4;
      if (off + len > ext_end) break;
      if (type == 0x0017 && len == 0) out->ems = true;
      if (type == 0x0010 && len >= 3) {
        const std::size_t name_len = body[off + 2];
        if (3 + name_len <= len) {
          out->alpn.assign(body.begin() + static_cast<std::ptrdiff_t>(off + 3),
                           body.begin() + static_cast<std::ptrdiff_t>(off + 3 + name_len));
        }
      }
      off += len;
    }
  }
  return true;
}

struct CertChain {
  std::vector<X509Cert> certs;
};

bool parse_certificate(const Bytes& body, CertChain* out, std::string* error) {
  if (body.size() < 3) {
    *error = "the Certificate message is too short";
    return false;
  }
  const u32 total = rd24(body, 0);
  std::size_t off = 3;
  const std::size_t end = std::min(body.size(), 3 + static_cast<std::size_t>(total));
  while (off + 3 <= end) {
    const u32 len = rd24(body, off);
    off += 3;
    if (off + len > end) {
      *error = "a certificate in the chain is truncated";
      return false;
    }
    X509Cert cert;
    std::string why;
    if (!x509_parse(Bytes(body.begin() + static_cast<std::ptrdiff_t>(off),
                         body.begin() + static_cast<std::ptrdiff_t>(off + len)),
                    &cert, &why)) {
      *error = "the origin sent a certificate this parser cannot read: " + why;
      return false;
    }
    out->certs.push_back(cert);
    off += len;
  }
  if (out->certs.empty()) {
    *error = "the origin sent an empty certificate chain";
    return false;
  }
  return true;
}

struct ServerKeyExchange {
  int group = 0;
  Bytes params;       // exactly the bytes the signature covers
  Bytes public_key;   // the raw ECPoint contents
  u8 sig_hash = 0;
  u8 sig_alg = 0;
  Bytes signature;
};

bool parse_server_key_exchange(const Bytes& body, ServerKeyExchange* out, std::string* error) {
  if (body.size() < 5) {
    *error = "the ServerKeyExchange is too short";
    return false;
  }
  if (body[0] != 0x03) {
    *error = "the origin used an unnamed curve, which this client does not implement";
    return false;
  }
  out->group = rd16(body, 1);
  const std::size_t point_len = body[3];
  if (4 + point_len + 4 > body.size()) {
    *error = "the ServerKeyExchange is truncated";
    return false;
  }
  out->public_key.assign(body.begin() + 4, body.begin() + 4 + static_cast<std::ptrdiff_t>(point_len));
  out->params.assign(body.begin(), body.begin() + 4 + static_cast<std::ptrdiff_t>(point_len));
  std::size_t off = 4 + point_len;
  out->sig_hash = body[off];
  out->sig_alg = body[off + 1];
  const std::size_t sig_len = rd16(body, off + 2);
  off += 4;
  if (off + sig_len > body.size()) {
    *error = "the ServerKeyExchange signature is truncated";
    return false;
  }
  out->signature.assign(body.begin() + static_cast<std::ptrdiff_t>(off),
                        body.begin() + static_cast<std::ptrdiff_t>(off + sig_len));
  return true;
}

// RFC 5246 §7.4.3 / RFC 8422 §5.4: the signature covers client_random ||
// server_random || the ECDHE parameters.
bool verify_ske_signature(const X509Cert& leaf, const Bytes& client_random, const Bytes& server_random,
                          const ServerKeyExchange& ske, std::string* error) {
  Bytes signed_data = client_random;
  signed_data.insert(signed_data.end(), server_random.begin(), server_random.end());
  signed_data.insert(signed_data.end(), ske.params.begin(), ske.params.end());
  const Bytes digest = sha256(signed_data);

  const bool pss = ske.sig_hash == 0x08 && ske.sig_alg == 0x04;
  const bool rsa_pkcs1 = ske.sig_hash == 0x04 && ske.sig_alg == 0x01;
  const bool ecdsa = ske.sig_hash == 0x04 && ske.sig_alg == 0x03;

  if (ecdsa) {
    if (!leaf.has_rsa && !leaf.public_key.infinity) {
      Bytes r, s;
      if (!parse_der_signature(ske.signature, &r, &s)) {
        *error = "the origin's ECDSA signature is not a valid DER sequence";
        return false;
      }
      if (p256_ecdsa_verify(leaf.public_key, digest.data(), r, s)) return true;
      *error = "the origin's ECDSA signature over the key exchange does not verify";
      return false;
    }
    *error = "the origin signed the key exchange with ECDSA but its certificate has no P-256 key";
    return false;
  }
  if (pss || rsa_pkcs1) {
    if (!leaf.has_rsa) {
      *error = "the origin signed the key exchange with RSA but its certificate has no RSA key";
      return false;
    }
    if (rsa_verify_sha256(leaf.rsa_modulus, leaf.rsa_exponent, digest.data(), ske.signature, pss, 32)) {
      return true;
    }
    *error = pss ? "the origin's RSA-PSS signature over the key exchange does not verify"
                 : "the origin's RSA signature over the key exchange does not verify";
    return false;
  }
  char buf[64];
  std::snprintf(buf, sizeof buf, "unsupported signature algorithm 0x%02x%02x", ske.sig_hash, ske.sig_alg);
  *error = buf;
  return false;
}

}  // namespace

const Tls12Suite* tls12_suite(u16 id) {
  for (const Tls12Suite& s : kSuites) {
    if (s.id == id) return &s;
  }
  return nullptr;
}

std::vector<u16> tls12_offered_suites(int version) {
  std::vector<u16> out;
  for (const Tls12Suite& s : kSuites) {
    if (s.min_version <= version) out.push_back(s.id);
  }
  return out;
}

std::string tls12_suite_name(u16 id) {
  const Tls12Suite* s = tls12_suite(id);
  if (s != nullptr) return s->name;
  char buf[16];
  std::snprintf(buf, sizeof buf, "0x%04x", id);
  return buf;
}

// RFC 2246 §5: the pre-1.2 PRF is P_MD5(S1) XOR P_SHA1(S2) over label||seed,
// with the secret split in half (the halves overlap when the length is odd).
// RFC 4346 keeps it for TLS 1.1.  TLS 1.0/1.1 use it for the master secret, the
// key block *and* Finished, so both a 1.0 and a 1.1 origin need it.
Bytes tls_prf_legacy(const Bytes& secret, const std::string& label, const Bytes& seed,
                     std::size_t out_len) {
  const std::size_t half = (secret.size() + 1) / 2;
  const Bytes s1(secret.begin(), secret.begin() + static_cast<std::ptrdiff_t>(half));
  const Bytes s2(secret.end() - static_cast<std::ptrdiff_t>(half), secret.end());
  Bytes label_seed(label.begin(), label.end());
  label_seed.insert(label_seed.end(), seed.begin(), seed.end());

  auto p_hash = [&](const Bytes& sec, Bytes (*mac)(const Bytes&, const Bytes&)) {
    Bytes out;
    Bytes a = label_seed;  // A(0)
    while (out.size() < out_len) {
      a = mac(sec, a);  // A(i) = HMAC(secret, A(i-1))
      Bytes block = a;
      block.insert(block.end(), label_seed.begin(), label_seed.end());
      const Bytes chunk = mac(sec, block);
      out.insert(out.end(), chunk.begin(), chunk.end());
    }
    out.resize(out_len);
    return out;
  };
  const Bytes md5_part = p_hash(s1, static_cast<Bytes (*)(const Bytes&, const Bytes&)>(&hmac_md5));
  const Bytes sha_part = p_hash(s2, static_cast<Bytes (*)(const Bytes&, const Bytes&)>(&hmac_sha1));
  Bytes out(out_len, 0);
  for (std::size_t i = 0; i < out_len; ++i) out[i] = static_cast<u8>(md5_part[i] ^ sha_part[i]);
  return out;
}

// RFC 2246 §7.4.9 / RFC 4346 §7.4.9: verify_data =
// PRF(master_secret, finished_label, MD5(handshake_messages) ||
// SHA1(handshake_messages))[0..11].  Note the hash goes into the *seed*, and the
// handshake messages are hashed without the master secret.
Bytes tls12_finished_data_legacy(const Bytes& master_secret, bool from_server,
                                 const Bytes& handshake_messages) {
  Bytes seed = md5(handshake_messages);
  const Bytes tail = sha1(handshake_messages);
  seed.insert(seed.end(), tail.begin(), tail.end());
  return tls_prf_legacy(master_secret, from_server ? "server finished" : "client finished", seed, 12);
}

bool tls12_derive_keys(Tls12Secrets* secrets, const Bytes& pre_master, const Bytes& session_hash,
                       std::string* error) {
  const Tls12Suite* suite = tls12_suite(secrets->suite);
  if (suite == nullptr) {
    *error = "no cipher suite was chosen before the key schedule ran";
    return false;
  }
  if (secrets->client_random.size() != 32 || secrets->server_random.size() != 32) {
    *error = "the randoms are not 32 bytes";
    return false;
  }
  const bool legacy_prf = secrets->version < kTls12Version;  // TLS 1.0 / 1.1
  auto prf = [&](const Bytes& secret, const char* label, const Bytes& seed, std::size_t len) {
    return legacy_prf ? tls_prf_legacy(secret, label, seed, len) : tls12_prf(secret, label, seed, len);
  };
  if (secrets->extended_master_secret && !legacy_prf) {
    if (session_hash.size() != 32) {
      *error = "the extended master secret needs a 32 byte session hash";
      return false;
    }
    secrets->master_secret = prf(pre_master, "extended master secret", session_hash, 48);
  } else {
    if (secrets->extended_master_secret) secrets->extended_master_secret = false;  // EMS is 1.2+
    Bytes seed = secrets->client_random;
    seed.insert(seed.end(), secrets->server_random.begin(), secrets->server_random.end());
    secrets->master_secret = prf(pre_master, "master secret", seed, 48);
  }
  if (secrets->master_secret.size() != 48) {
    *error = "the PRF did not produce a 48 byte master secret";
    return false;
  }
  Bytes seed = secrets->server_random;
  seed.insert(seed.end(), secrets->client_random.begin(), secrets->client_random.end());
  // RFC 5246 §6.3: the key block carries both MAC secrets first for CBC suites
  // (which are MAC-then-encrypt), then the keys, then the IVs.
  const std::size_t mac_len = suite->cbc ? suite->mac_len : 0;
  const std::size_t need = mac_len * 2 + suite->key_len * 2 + suite->fixed_iv_len * 2;
  const Bytes block = prf(secrets->master_secret, "key expansion", seed, need);
  if (block.size() != need) {
    *error = "the PRF did not produce a full key block";
    return false;
  }
  std::size_t off = 0;
  auto take = [&](std::size_t n) {
    const Bytes part(block.begin() + static_cast<std::ptrdiff_t>(off),
                     block.begin() + static_cast<std::ptrdiff_t>(off + n));
    off += n;
    return part;
  };
  secrets->client_mac = take(mac_len);
  secrets->server_mac = take(mac_len);
  secrets->client_key = take(suite->key_len);
  secrets->server_key = take(suite->key_len);
  secrets->client_iv = take(suite->fixed_iv_len);
  secrets->server_iv = take(suite->fixed_iv_len);
  secrets->chacha = suite->chacha;
  secrets->cbc = suite->cbc;
  secrets->client_seq = 0;
  secrets->server_seq = 0;
  return true;
}

Bytes tls12_finished_data(const Bytes& master_secret, bool from_server, const Bytes& transcript_hash) {
  return tls12_prf(master_secret, from_server ? "server finished" : "client finished", transcript_hash, 12);
}

bool tls12_seal(Tls12Secrets* secrets, int dir, u8 content_type, const Bytes& plaintext, Bytes* record,
                std::string* error) {
  const Tls12Suite* suite = tls12_suite(secrets->suite);
  if (suite == nullptr) {
    *error = "no cipher suite is set";
    return false;
  }
  const Bytes& key = dir == 0 ? secrets->client_key : secrets->server_key;
  const Bytes& iv = dir == 0 ? secrets->client_iv : secrets->server_iv;
  const u64 seq = dir == 0 ? secrets->client_seq : secrets->server_seq;

  if (suite->cbc) {
    // MAC-then-encrypt (RFC 5246 §6.2.3.1): MAC over seq||type||version||len||fragment,
    // then padding, then CBC.  TLS 1.0 derives its IV from the key block and
    // chains it (the next record continues from the last ciphertext block);
    // 1.1 and 1.2 send a random explicit IV in front of the ciphertext.
    Bytes& iv_state = dir == 0 ? secrets->client_iv : secrets->server_iv;
    const Bytes& mac_key = dir == 0 ? secrets->client_mac : secrets->server_mac;
    const int version = secrets->version;
    Bytes mac_input = u64_be(seq);
    mac_input.push_back(content_type);
    put16(mac_input, static_cast<u16>(version));
    put16(mac_input, static_cast<u16>(plaintext.size()));
    mac_input.insert(mac_input.end(), plaintext.begin(), plaintext.end());
    const Bytes mac =
        suite->mac_len == 20 ? hmac_sha1(mac_key, mac_input) : hmac_sha256(mac_key, mac_input);
    if (mac.size() != suite->mac_len) {
      *error = "the CBC suite wanted a MAC this build cannot compute";
      return false;
    }
    Bytes body = plaintext;
    body.insert(body.end(), mac.begin(), mac.end());
    const std::size_t pad_len = 16 - ((body.size() + 1) % 16);  // 0..15, +1 byte for the length
    body.insert(body.end(), pad_len + 1, static_cast<u8>(pad_len));

    Bytes explicit_iv;
    Bytes iv(16, 0);
    if (version == 0x0301) {
      if (iv_state.size() != 16) {
        *error = "the CBC IV is not 16 bytes";
        return false;
      }
      iv = iv_state;
    } else {
      explicit_iv.assign(16, 0);
      if (!random_bytes(explicit_iv.data(), explicit_iv.size())) {
        *error = "no randomness available for the explicit IV";
        return false;
      }
      iv = explicit_iv;
    }
    Bytes ciphertext(body.size(), 0);
    Aes aes;
    if (!aes.set_key(key)) {
      *error = "the AES key length is not supported";
      return false;
    }
    aes_cbc_encrypt(aes, iv.data(), body.data(), body.size(), ciphertext.data());
    if (version == 0x0301) iv_state.assign(ciphertext.end() - 16, ciphertext.end());

    Bytes out_body = explicit_iv;
    out_body.insert(out_body.end(), ciphertext.begin(), ciphertext.end());
    *record = record_header(content_type, static_cast<u16>(version), out_body.size());
    record->insert(record->end(), out_body.begin(), out_body.end());
    if (dir == 0) {
      ++secrets->client_seq;
    } else {
      ++secrets->server_seq;
    }
    return true;
  }

  Bytes aad = u64_be(seq);
  aad.push_back(content_type);
  put16(aad, kTls12Version);
  put16(aad, static_cast<u16>(plaintext.size()));

  Bytes explicit_nonce;
  Bytes nonce = iv;
  if (suite->chacha) {
    const Bytes sn = u64_be(seq);
    if (nonce.size() < 8) {
      *error = "the ChaCha20 IV is too short";
      return false;
    }
    for (std::size_t i = 0; i < 8; ++i) nonce[nonce.size() - 8 + i] ^= sn[i];
  } else {
    explicit_nonce = u64_be(seq);
    nonce.insert(nonce.end(), explicit_nonce.begin(), explicit_nonce.end());
  }

  const AeadResult sealed =
      suite->chacha ? chacha20_poly1305_encrypt(key, nonce, aad, plaintext)
                    : aes_gcm_encrypt(key, nonce, aad, plaintext);
  if (sealed.ciphertext.size() != plaintext.size() || sealed.tag.size() != 16) {
    *error = "the AEAD refused to seal the record";
    return false;
  }
  Bytes body = explicit_nonce;
  body.insert(body.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
  body.insert(body.end(), sealed.tag.begin(), sealed.tag.end());
  *record = record_header(content_type, kTls12Version, body.size());
  record->insert(record->end(), body.begin(), body.end());
  if (dir == 0) {
    ++secrets->client_seq;
  } else {
    ++secrets->server_seq;
  }
  return true;
}

bool tls12_open(Tls12Secrets* secrets, int dir, const Bytes& record, u8* content_type, Bytes* plaintext,
                std::string* error) {
  const Tls12Suite* suite = tls12_suite(secrets->suite);
  if (suite == nullptr) {
    *error = "no cipher suite is set";
    return false;
  }
  if (record.size() < 5 + (suite->chacha ? 0 : 8) + 16) {
    *error = "the record is too short to hold a tag";
    return false;
  }
  const u8 type = record[0];
  const std::size_t body_len = rd16(record, 3);
  if (5 + body_len > record.size() || body_len < (suite->chacha ? 16u : 24u)) {
    *error = "the record length does not match its contents";
    return false;
  }
  if (suite->cbc) {
    const int version = secrets->version;
    const Bytes& key = dir == 0 ? secrets->client_key : secrets->server_key;
    const Bytes& mac_key = dir == 0 ? secrets->client_mac : secrets->server_mac;
    const u64 seq = dir == 0 ? secrets->client_seq : secrets->server_seq;
    const std::size_t explicit_len = version == 0x0301 ? 0 : 16;
    if (body_len < explicit_len + 16 || (body_len - explicit_len) % 16 != 0) {
      *error = "the CBC record is not a whole number of blocks";
      return false;
    }
    const Bytes ciphertext(record.begin() + 5 + static_cast<std::ptrdiff_t>(explicit_len),
                           record.begin() + 5 + static_cast<std::ptrdiff_t>(body_len));
    Bytes& iv_state = dir == 0 ? secrets->client_iv : secrets->server_iv;
    Bytes iv(16, 0);
    if (explicit_len == 0) {
      if (iv_state.size() != 16) {
        *error = "the CBC IV is not 16 bytes";
        return false;
      }
      iv = iv_state;
    } else {
      iv.assign(record.begin() + 5, record.begin() + 5 + static_cast<std::ptrdiff_t>(explicit_len));
    }
    Bytes plain(ciphertext.size(), 0);
    Aes aes;
    if (!aes.set_key(key)) {
      *error = "the AES key length is not supported";
      return false;
    }
    aes_cbc_decrypt(aes, iv.data(), ciphertext.data(), ciphertext.size(), plain.data());
    if (explicit_len == 0) iv_state.assign(ciphertext.end() - 16, ciphertext.end());

    const std::size_t padding = static_cast<std::size_t>(plain.back()) + 1;
    if (padding > plain.size() || plain.size() - padding < suite->mac_len) {
      *error = "the CBC padding is malformed";
      return false;
    }
    for (std::size_t i = plain.size() - padding; i < plain.size(); ++i) {
      if (plain[i] != plain.back()) {
        *error = "the CBC padding bytes disagree";
        return false;
      }
    }
    const std::size_t content_len = plain.size() - padding - suite->mac_len;
    const Bytes content(plain.begin(), plain.begin() + static_cast<std::ptrdiff_t>(content_len));
    const Bytes mac_seen(plain.begin() + static_cast<std::ptrdiff_t>(content_len),
                         plain.begin() + static_cast<std::ptrdiff_t>(content_len + suite->mac_len));
    Bytes mac_input = u64_be(seq);
    mac_input.push_back(type);
    put16(mac_input, static_cast<u16>(version));
    put16(mac_input, static_cast<u16>(content_len));
    mac_input.insert(mac_input.end(), content.begin(), content.end());
    const Bytes mac_want = suite->mac_len == 20 ? hmac_sha1(mac_key, mac_input)
                                                : hmac_sha256(mac_key, mac_input);
    if (mac_want.size() != mac_seen.size()) {
      *error = "the CBC suite wanted a MAC this build cannot compute";
      return false;
    }
    unsigned diff = 0;
    for (std::size_t i = 0; i < mac_want.size(); ++i) {
      diff |= static_cast<unsigned>(mac_want[i] ^ mac_seen[i]);
    }
    if (diff != 0) {
      *error = "the record MAC did not verify";
      return false;
    }
    if (dir == 0) {
      ++secrets->client_seq;
    } else {
      ++secrets->server_seq;
    }
    *content_type = type;
    *plaintext = content;
    return true;
  }

  const std::size_t prefix = suite->chacha ? 0 : 8;
  const std::size_t ct_len = body_len - prefix - 16;
  const Bytes explicit_nonce(record.begin() + 5, record.begin() + 5 + static_cast<std::ptrdiff_t>(prefix));
  const Bytes ciphertext(record.begin() + 5 + static_cast<std::ptrdiff_t>(prefix),
                         record.begin() + 5 + static_cast<std::ptrdiff_t>(prefix + ct_len));
  const Bytes tag(record.begin() + 5 + static_cast<std::ptrdiff_t>(prefix + ct_len),
                  record.begin() + 5 + static_cast<std::ptrdiff_t>(body_len));

  const Bytes& key = dir == 0 ? secrets->client_key : secrets->server_key;
  const Bytes& iv = dir == 0 ? secrets->client_iv : secrets->server_iv;
  const u64 seq = dir == 0 ? secrets->client_seq : secrets->server_seq;

  Bytes aad = u64_be(seq);
  aad.push_back(type);
  put16(aad, kTls12Version);
  put16(aad, static_cast<u16>(ct_len));

  Bytes nonce = iv;
  if (suite->chacha) {
    const Bytes sn = u64_be(seq);
    if (nonce.size() < 8) {
      *error = "the ChaCha20 IV is too short";
      return false;
    }
    for (std::size_t i = 0; i < 8; ++i) nonce[nonce.size() - 8 + i] ^= sn[i];
  } else {
    nonce.insert(nonce.end(), explicit_nonce.begin(), explicit_nonce.end());
  }

  Bytes out;
  const bool ok = suite->chacha ? chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag, &out)
                                : aes_gcm_decrypt(key, nonce, aad, ciphertext, tag, &out);
  if (!ok) {
    *error = "record authentication failed (the key or the record is wrong)";
    return false;
  }
  if (dir == 0) {
    ++secrets->client_seq;
  } else {
    ++secrets->server_seq;
  }
  *content_type = type;
  *plaintext = out;
  return true;
}

void Tls12Client::resume(const Tls12Secrets& secrets) {
  secrets_ = secrets;
  closed_ = false;
}

bool Tls12Client::connect(const Tls13Io& io, const std::string& host, const std::string& alpn,
                          bool allow_unverified, Tls12ClientInfo* info, std::string* error,
                          int version_hint) {
  secrets_ = Tls12Secrets();
  closed_ = false;
  if (info != nullptr) info->host = host;

  Bytes random(32, 0);
  if (!random_bytes(random.data(), random.size())) {
    *error = "no randomness available for the ClientHello";
    return false;
  }
  const Bytes hello_body = client_hello_body(host, alpn, random, version_hint);
  const Bytes hello = handshake_message(0x01, hello_body);
  Bytes transcript = hello;

  Bytes out;
  out.push_back(0x16);  // handshake
  put16(out, kTls10Version);
  put16(out, static_cast<u16>(hello.size()));
  out.insert(out.end(), hello.begin(), hello.end());
  if (!io.write(out.data(), out.size())) {
    *error = "the ClientHello could not be sent";
    return false;
  }
  if (info != nullptr) info->host = host;

  // ------------------------------------------------------------------ flight
  Bytes handshake_buffer;
  ServerHello server_hello;
  bool have_hello = false;
  bool done = false;
  CertChain chain;
  ServerKeyExchange ske;
  bool have_ske = false;

  while (!done) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) return false;
    if (record.size() < 5) {
      *error = "a record without a header arrived";
      return false;
    }
    const u8 type = record[0];
    const std::size_t body_len = rd16(record, 3);
    if (5 + body_len > record.size()) {
      *error = "a record's length field exceeds its contents";
      return false;
    }
    const Bytes body(record.begin() + 5, record.begin() + 5 + static_cast<std::ptrdiff_t>(body_len));
    if (type == kAlert) {
      if (body.size() >= 2) {
        *error = "the origin sent an alert: " + alert_text(body[1]);
      } else {
        *error = "the origin sent a malformed alert";
      }
      return false;
    }
    if (type != kHandshake) {
      if (type == kChangeCipherSpec) continue;
      *error = "the origin sent an unexpected record type during the handshake";
      return false;
    }
    handshake_buffer.insert(handshake_buffer.end(), body.begin(), body.end());
    while (true) {
      if (handshake_buffer.size() < 4) break;
      const u32 msg_len = rd24(handshake_buffer, 1);
      if (handshake_buffer.size() < 4 + msg_len) break;
      const u8 msg_type = handshake_buffer[0];
      const Bytes msg(handshake_buffer.begin(), handshake_buffer.begin() + 4 + static_cast<std::ptrdiff_t>(msg_len));
      const Bytes msg_body(handshake_buffer.begin() + 4, handshake_buffer.begin() + 4 + static_cast<std::ptrdiff_t>(msg_len));
      handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + 4 + static_cast<std::ptrdiff_t>(msg_len));
      transcript.insert(transcript.end(), msg.begin(), msg.end());

      if (msg_type == 0x02) {
        std::string why;
        if (!parse_server_hello(msg_body, &server_hello, &why)) {
          *error = why;
          return false;
        }
        const Tls12Suite* suite = tls12_suite(server_hello.suite);
        if (suite == nullptr) {
          *error = "the origin chose a cipher suite we did not offer (" + tls12_suite_name(server_hello.suite) + ")";
          return false;
        }
        if (suite->min_version > server_hello.version) {
          *error = "the origin chose " + tls12_suite_name(server_hello.suite) +
                   ", which is not valid in the version it chose";
          return false;
        }
        secrets_.suite = server_hello.suite;
        secrets_.version = server_hello.version;
        secrets_.client_random = random;
        secrets_.server_random = server_hello.random;
        secrets_.extended_master_secret = server_hello.ems;
        have_hello = true;
        if (info != nullptr) {
          info->cipher_suite = server_hello.suite;
          info->version = server_hello.version;
          info->alpn = server_hello.alpn;
          info->extended_master_secret = server_hello.ems;
        }
      } else if (msg_type == 0x0b) {
        std::string why;
        if (!parse_certificate(msg_body, &chain, &why)) {
          *error = why;
          return false;
        }
        if (info != nullptr) {
          info->certificate_seen = true;
          info->certificate_subject = chain.certs.front().subject_cn;
          info->certificate_issuer = chain.certs.front().issuer_cn;
        }
      } else if (msg_type == 0x0c) {
        std::string why;
        if (!parse_server_key_exchange(msg_body, &ske, &why)) {
          *error = why;
          return false;
        }
        have_ske = true;
      } else if (msg_type == 0x0d) {
        *error = "the origin asked for a client certificate, which this proxy does not have";
        return false;
      } else if (msg_type == 0x0e) {
        done = true;
        break;
      } else if (msg_type == 0x00 || msg_type == 0x04) {
        // HelloRequest / NewSessionTicket: nothing to do before the handshake ends.
      } else {
        char buf[64];
        std::snprintf(buf, sizeof buf, "the origin sent handshake message %u, which is not expected here", msg_type);
        *error = buf;
        return false;
      }
    }
  }

  const Tls12Suite* chosen = tls12_suite(secrets_.suite);
  const bool rsa_key_exchange = chosen != nullptr && chosen->rsa_key_exchange;
  if (!have_hello || chain.certs.empty() || (!have_ske && !rsa_key_exchange)) {
    *error = "the origin's flight is missing the ServerHello, the key exchange or the certificate";
    return false;
  }
  const X509Cert& leaf = chain.certs.front();
  if (rsa_key_exchange) {
    // Static RSA: no ServerKeyExchange, so nothing to verify a signature on.  The
    // premaster is encrypted to the certificate's key instead (below).
    if (info != nullptr) info->key_exchange = "rsa";
  } else {
    if (!verify_ske_signature(leaf, secrets_.client_random, secrets_.server_random, ske, error)) return false;
    if (info != nullptr) {
      info->server_key_exchange_verified = true;
      info->key_exchange = "ecdhe";
    }
  }

  // ---------------------------------------------------------- certificate checks
  const bool host_ok = x509_matches_host(leaf, host);
  const std::string now = now_utc_key();
  const std::string not_before = time_key(leaf.not_before);
  const std::string not_after = time_key(leaf.not_after);
  const bool dates_ok = !not_before.empty() && !not_after.empty() && not_before <= now && now <= not_after;
  if (info != nullptr) {
    info->certificate_host_matched = host_ok;
    info->certificate_dates_ok = dates_ok;
  }
  if (chain.certs.size() > 1) {
    if (info != nullptr) info->certificate_chain_checked = x509_verify_signature(leaf, chain.certs[1]);
  } else if (info != nullptr) {
    // No issuer was sent, so there is nothing to verify the leaf against.  We
    // can still vouch for the name and the dates; say so instead of leaving the
    // chain flag silently false with no explanation in the event.
    info->warning = "the certificate is self-signed or its issuer was not sent";
  }
  if (!allow_unverified) {
    if (!host_ok) {
      *error = "the origin's certificate does not cover " + host;
      return false;
    }
    if (!dates_ok) {
      *error = "the origin's certificate is outside its validity window";
      return false;
    }
    if (info != nullptr && chain.certs.size() > 1 && !info->certificate_chain_checked) {
      info->warning = "the certificate chain does not verify against its issuer";
    }
  }

  // ------------------------------------------------------------ key exchange
  Bytes client_public;
  Bytes shared;
  if (rsa_key_exchange) {
    // RFC 5246 §7.4.7.1 / RFC 2246 §7.4.7.1: 48 random bytes whose first two
    // bytes carry the version *we offered* (the downgrade canary), encrypted
    // under the leaf's RSA public key.  `shared` then holds the premaster.
    if (!leaf.has_rsa) {
      *error = "the origin chose RSA key exchange but its certificate carries no RSA key";
      return false;
    }
    shared.assign(48, 0);
    if (!random_bytes(shared.data() + 2, 46)) {
      *error = "no randomness available for the pre_master_secret";
      return false;
    }
    shared[0] = static_cast<u8>(version_hint >> 8);
    shared[1] = static_cast<u8>(version_hint & 0xff);
    Bytes encrypted;
    if (!rsa_encrypt_pkcs1(leaf.rsa_modulus, leaf.rsa_exponent, shared, &encrypted, error)) return false;
    client_public = encrypted;
    if (std::getenv("NETCAP_TLS12_TRACE") != nullptr) {
      // Public material only (the premaster is a per-connection secret, but it is
      // exactly what a trace needs to explain a decrypt_error from the origin).
      std::fprintf(stderr, "netcap: tls12 rsa kx modulus_bits=%zu exponent=%s ciphertext=%s\n",
                   leaf.rsa_modulus.size() * 8, hex_of(leaf.rsa_exponent).c_str(),
                   hex_of(encrypted).c_str());
      std::fflush(stderr);
    }
  } else if (ske.group == 0x001d) {
    X25519Key key;
    if (!x25519_keypair(&key)) {
      *error = "no X25519 key pair could be generated";
      return false;
    }
    if (!x25519(key.priv, ske.public_key, &shared)) {
      *error = "the origin's X25519 key share is not usable (low order point)";
      return false;
    }
    client_public = key.pub;
    if (std::getenv("NETCAP_TLS12_TRACE") != nullptr) {
      // Deliberately no private key here: this trace ships in release builds.
      std::fprintf(stderr, "netcap: tls12 x25519 pub=%s server_point=%s\n", hex_of(key.pub).c_str(),
                   hex_of(ske.public_key).c_str());
    }
  } else if (ske.group == 0x0017) {
    P256Key key;
    if (!p256_generate(&key)) {
      *error = "no P-256 key pair could be generated";
      return false;
    }
    P256Point peer;
    if (!p256_parse_point(ske.public_key.data(), ske.public_key.size(), &peer)) {
      *error = "the origin's P-256 point is not on the curve";
      return false;
    }
    if (!p256_ecdh(key, peer, &shared)) {
      *error = "the P-256 key exchange failed";
      return false;
    }
    client_public.push_back(0x04);
    client_public.insert(client_public.end(), key.q.x.begin(), key.q.x.end());
    client_public.insert(client_public.end(), key.q.y.begin(), key.q.y.end());
  } else {
    char buf[64];
    std::snprintf(buf, sizeof buf, "the origin chose group 0x%04x, which this client does not implement", ske.group);
    *error = buf;
    return false;
  }
  if (info != nullptr) info->group = ske.group;

  Bytes cke_body;
  if (rsa_key_exchange) {
    // ClientKeyExchange for static RSA is a 16 bit length prefix...
    put16(cke_body, static_cast<u16>(client_public.size()));
    cke_body.insert(cke_body.end(), client_public.begin(), client_public.end());
  } else {
    // ...and an 8 bit one for the ECDHE point.
    cke_body.push_back(static_cast<u8>(client_public.size()));
    cke_body.insert(cke_body.end(), client_public.begin(), client_public.end());
  }
  const Bytes cke = handshake_message(0x10, cke_body);
  transcript.insert(transcript.end(), cke.begin(), cke.end());

  if (!tls12_derive_keys(&secrets_, shared, sha256(transcript), error)) return false;
  if (trace_on()) {
    std::fprintf(stderr,
                 "netcap: tls12 suite=%s ems=%d group=0x%04x client_random=%s server_random=%s master=%s pms=%s\n",
                 tls12_suite_name(secrets_.suite).c_str(), secrets_.extended_master_secret ? 1 : 0,
                 ske.group, hex_of(secrets_.client_random).c_str(), hex_of(secrets_.server_random).c_str(),
                 hex_of(secrets_.master_secret).c_str(), hex_of(shared).c_str());
      std::fprintf(stderr, "netcap: tls12 keyblock client_key=%s server_key=%s client_iv=%s server_iv=%s\n",
                   hex_of(secrets_.client_key).c_str(), hex_of(secrets_.server_key).c_str(),
                   hex_of(secrets_.client_iv).c_str(), hex_of(secrets_.server_iv).c_str());
    std::fflush(stderr);
  }
  if (secrets_.chacha != (tls12_suite(secrets_.suite)->chacha)) {
    *error = "internal error: the suite and the key schedule disagree";
    return false;
  }

  // ------------------------------------------------------- our CCS + Finished
  Bytes ccs;
  ccs.push_back(0x01);
  Bytes ccs_record = record_header(kChangeCipherSpec, static_cast<u16>(secrets_.version), ccs.size());
  ccs_record.insert(ccs_record.end(), ccs.begin(), ccs.end());

  const bool legacy_finished = secrets_.version < kTls12Version;
  const Bytes client_verify =
      legacy_finished ? tls12_finished_data_legacy(secrets_.master_secret, false, transcript)
                      : tls12_finished_data(secrets_.master_secret, false, sha256(transcript));
  const Bytes client_finished = handshake_message(0x14, client_verify);
  Bytes finished_record;
  if (!tls12_seal(&secrets_, 0, kHandshake, client_finished, &finished_record, error)) return false;
  transcript.insert(transcript.end(), client_finished.begin(), client_finished.end());

  Bytes send = record_header(kHandshake, static_cast<u16>(secrets_.version), cke.size());
  send.insert(send.end(), cke.begin(), cke.end());
  send.insert(send.end(), ccs_record.begin(), ccs_record.end());
  send.insert(send.end(), finished_record.begin(), finished_record.end());
  if (!io.write(send.data(), send.size())) {
    *error = "the key exchange and Finished flight could not be sent";
    return false;
  }
  if (std::getenv("NETCAP_TLS12_TRACE") != nullptr) {
    std::fprintf(stderr, "netcap: tls12 flight=%s\n", hex_of(send).c_str());
  }

  // ------------------------------------------------------- their Finished
  const Bytes expected_server =
      legacy_finished ? tls12_finished_data_legacy(secrets_.master_secret, true, transcript)
                      : tls12_finished_data(secrets_.master_secret, true, sha256(transcript));
  bool saw_ccs = false;
  bool saw_finished = false;
  while (!saw_finished) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) return false;
    if (record.size() < 5) {
      *error = "a record without a header arrived";
      return false;
    }
    const u8 type = record[0];
    const std::size_t body_len = rd16(record, 3);
    if (5 + body_len > record.size()) {
      *error = "a record's length field exceeds its contents";
      return false;
    }
    if (type == kChangeCipherSpec) {
      saw_ccs = true;
      continue;
    }
    if (type == kAlert && body_len < 24) {
      // Before the handshake finishes an alert may still be in the clear, so it
      // is too short to hold an AEAD tag.  Report what the origin is unhappy
      // about instead of failing with a decryption error.
      if (body_len >= 2) {
        *error = "the origin sent a plaintext alert: " + alert_text(record[6]);
      } else {
        *error = "the origin sent a malformed plaintext alert";
      }
      return false;
    }
    u8 inner = 0;
    Bytes plain;
    if (!tls12_open(&secrets_, 1, record, &inner, &plain, error)) return false;
    if (inner == kAlert) {
      *error = plain.size() >= 2
                   ? "the origin sent an alert after our Finished: " + alert_text(plain[1])
                   : "the origin sent a malformed alert after our Finished";
      return false;
    }
    if (inner != kHandshake) {
      char buf[96];
      std::snprintf(buf, sizeof buf,
                    "the origin sent inner record type %u while we waited for its Finished", inner);
      *error = buf;
      return false;
    }
    if (plain.size() < 4) {
      *error = "the origin's Finished message is truncated";
      return false;
    }
    const u8 msg_type = plain[0];
    const u32 msg_len = rd24(plain, 1);
    if (4 + msg_len > plain.size()) {
      *error = "the origin's Finished message is truncated";
      return false;
    }
    if (msg_type == 0x14) {
      const Bytes verify(plain.begin() + 4, plain.begin() + 4 + static_cast<std::ptrdiff_t>(msg_len));
      if (verify != expected_server) {
        auto head = [](const Bytes& v) {
          char buf[64];
          std::snprintf(buf, sizeof buf, "%02x%02x%02x%02x", v.size() > 0 ? v[0] : 0,
                        v.size() > 1 ? v[1] : 0, v.size() > 2 ? v[2] : 0, v.size() > 3 ? v[3] : 0);
          return std::string(buf);
        };
        *error = "the origin's Finished did not match (got " + head(verify) + ", wanted " + head(expected_server) +
                 "; ems " + (secrets_.extended_master_secret ? "on" : "off") + ", suite " +
                 tls12_suite_name(secrets_.suite) + ")";
        return false;
      }
      transcript.insert(transcript.end(), plain.begin(),
                        plain.begin() + 4 + static_cast<std::ptrdiff_t>(msg_len));
      saw_finished = true;
    }
    // NewSessionTicket and friends: ignore.
  }
  (void)saw_ccs;

  if (info != nullptr) info->server_finished_ok = true;
  return true;
}

bool Tls12Client::read_app(const Tls13Io& io, Bytes* out, std::string* error) {
  out->clear();
  for (;;) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) return false;
    if (record.size() < 5) {
      *error = "a record without a header arrived";
      return false;
    }
    const u8 type = record[0];
    const std::size_t body_len = rd16(record, 3);
    if (5 + body_len > record.size()) {
      *error = "a record's length field exceeds its contents";
      return false;
    }
    if (type == kChangeCipherSpec) continue;
    u8 inner = 0;
    Bytes plain;
    if (!tls12_open(&secrets_, 1, record, &inner, &plain, error)) return false;
    if (inner == kAlert) {
      closed_ = true;
      if (plain.size() >= 2 && plain[1] == 0) {
        *error = "the origin closed the connection";
      } else {
        *error = plain.size() >= 2 ? "the origin sent an alert: " + alert_text(plain[1])
                                   : "the origin sent a malformed alert";
      }
      return false;
    }
    if (inner == kApplicationData) {
      *out = plain;
      return true;
    }
    // Handshake messages after the handshake (NewSessionTicket, HelloRequest): skip.
  }
}

bool Tls12Client::write_app(const Tls13Io& io, const Bytes& data, std::string* error) {
  std::size_t off = 0;
  while (off < data.size()) {
    const std::size_t take = std::min(kMaxPlaintext, data.size() - off);
    const Bytes chunk(data.begin() + static_cast<std::ptrdiff_t>(off),
                      data.begin() + static_cast<std::ptrdiff_t>(off + take));
    Bytes record;
    if (!tls12_seal(&secrets_, 0, kApplicationData, chunk, &record, error)) return false;
    if (!io.write(record.data(), record.size())) {
      *error = "the record could not be sent";
      return false;
    }
    off += take;
  }
  return true;
}

bool Tls12Client::send_close_notify(const Tls13Io& io, std::string* error) {
  Bytes alert;
  alert.push_back(0x01);  // warning
  alert.push_back(0x00);  // close_notify
  Bytes record;
  if (!tls12_seal(&secrets_, 0, kAlert, alert, &record, error)) return false;
  if (!io.write(record.data(), record.size())) {
    if (error != nullptr) *error = "close_notify could not be sent";
    return false;
  }
  closed_ = true;
  return true;
}

bool tls12_selfcheck(std::string* report) {
  std::string notes;
  auto fail = [&](const std::string& why) {
    if (report != nullptr) *report = why + notes;
    return false;
  };

  // ---------------------------------------------------------------- suite table
  const Tls12Suite* gcm = tls12_suite(0xC02B);
  const Tls12Suite* chacha = tls12_suite(0xCCA9);
  if (gcm == nullptr || chacha == nullptr) return fail("the suite table lost an entry");
  if (gcm->key_len != 16 || gcm->fixed_iv_len != 4 || gcm->chacha) return fail("the AES-GCM suite is misdescribed");
  if (!chacha->chacha || chacha->key_len != 32 || chacha->fixed_iv_len != 12) {
    return fail("the ChaCha20 suite is misdescribed");
  }
  const std::vector<u16> offered = tls12_offered_suites();
  if (offered.size() != 17) return fail("the client should offer 17 suites to a TLS 1.2 origin");
  const std::vector<u16> offered_legacy = tls12_offered_suites(0x0301);
  if (offered_legacy.size() != 6) return fail("a TLS 1.0 hello should offer the six SHA-1 CBC suites");
  for (u16 id : offered_legacy) {
    const Tls12Suite* s = tls12_suite(id);
    if (s == nullptr || !s->cbc || s->mac_len != 20) return fail("a 1.0 suite is not a CBC/SHA-1 suite");
  }
  const Tls12Suite* rsa_cbc = tls12_suite(0x002F);
  if (rsa_cbc == nullptr || !rsa_cbc->rsa_key_exchange || rsa_cbc->fixed_iv_len != 16) {
    return fail("the RSA key exchange CBC suite is misdescribed");
  }
  if (tls12_suite_name(0xC02F) != "ECDHE-RSA-AES128-GCM-SHA256") return fail("a suite name is wrong");
  if (tls12_suite_name(0x9999) != "0x9999") return fail("an unknown suite should print as its number");

  // ------------------------------------------------------------- key schedule
  Bytes pms(48, 0x5a);
  Bytes client_random(32, 0x11);
  Bytes server_random(32, 0x22);
  Tls12Secrets a;
  a.suite = 0xC02B;
  a.client_random = client_random;
  a.server_random = server_random;
  Tls12Secrets b = a;
  std::string why;
  if (!tls12_derive_keys(&a, pms, Bytes(), &why)) return fail("the key schedule refused a plain derivation: " + why);
  if (!tls12_derive_keys(&b, pms, Bytes(), &why)) return fail("the key schedule disagreed with itself: " + why);
  if (a.master_secret.size() != 48 || a.master_secret != b.master_secret) return fail("the master secret is not deterministic");
  if (a.client_key.size() != 16 || a.server_key.size() != 16) return fail("the key block did not split into 16 byte keys");
  if (a.client_iv.size() != 4 || a.server_iv.size() != 4) return fail("the GCM fixed IV should be 4 bytes");
  if (a.client_key == a.server_key) return fail("both directions got the same key");
  if (a.client_iv == a.server_iv) return fail("both directions got the same IV");

  Tls12Secrets ems = a;
  ems.extended_master_secret = true;
  if (!tls12_derive_keys(&ems, pms, sha256(client_random), &why)) return fail("EMS derivation failed: " + why);
  if (ems.master_secret == a.master_secret) return fail("EMS must change the master secret");
  Tls12Secrets ems_short = a;
  ems_short.extended_master_secret = true;
  if (tls12_derive_keys(&ems_short, pms, Bytes(), &why)) return fail("EMS accepted a missing session hash");

  Tls12Secrets cc = a;
  cc.suite = 0xCCA9;
  if (!tls12_derive_keys(&cc, pms, Bytes(), &why)) return fail("the ChaCha20 key schedule failed: " + why);
  if (cc.client_key.size() != 32 || cc.client_iv.size() != 12 || !cc.chacha) {
    return fail("the ChaCha20 key block is the wrong shape");
  }
  if (cc.master_secret != a.master_secret) return fail("the master secret must not depend on the suite");

  // ---------------------------------------------------------------- record layer
  for (const std::pair<u16, int>& tc :
       {std::pair<u16, int>{0xC02B, 0x0303}, std::pair<u16, int>{0xCCA9, 0x0303},
        std::pair<u16, int>{0xC027, 0x0303}, std::pair<u16, int>{0x002F, 0x0301}}) {
    const u16 suite_id = tc.first;
    const Tls12Suite* suite = tls12_suite(suite_id);
    Tls12Secrets tx;
    tx.suite = suite_id;
    tx.version = tc.second;
    tx.client_random = client_random;
    tx.server_random = server_random;
    if (!tls12_derive_keys(&tx, pms, Bytes(), &why)) return fail("record test setup failed: " + why);
    // The two directions use different keys, so give the "server" side the same
    // material to make a round trip possible.
    Tls12Secrets rx = tx;
    rx.server_key = tx.client_key;
    rx.server_iv = tx.client_iv;
    rx.server_mac = tx.client_mac;

    const Bytes message = ascii("hello tls 1.2 record");
    Bytes record;
    if (!tls12_seal(&tx, 0, kApplicationData, message, &record, &why)) return fail("sealing failed: " + why);
    if (suite->cbc) {
      const std::size_t explicit_len = tx.version == 0x0301 ? 0 : 16;
      const std::size_t body = record.size() - 5;
      if (body < explicit_len + 16 || (body - explicit_len) % 16 != 0) {
        return fail("the sealed CBC record is not a whole number of blocks");
      }
    } else if (record.size() != 5 + message.size() + 16 + (tx.chacha ? 0 : 8)) {
      return fail("the sealed record has the wrong length");
    }
    if (record[0] != kApplicationData || rd16(record, 1) != static_cast<u16>(tx.version)) {
      return fail("the sealed record has the wrong header");
    }
    u8 type = 0;
    Bytes plain;
    if (!tls12_open(&rx, 1, record, &type, &plain, &why)) return fail("opening our own record failed: " + why);
    if (plain != message || type != kApplicationData) return fail("the record round trip changed the payload");
    if (tx.client_seq != 1 || rx.server_seq != 1) return fail("the sequence numbers did not advance");

    // two records in a row must use different nonces
    Bytes second;
    if (!tls12_seal(&tx, 0, kApplicationData, message, &second, &why)) return fail("a second seal failed: " + why);
    if (second == record) return fail("two records were sealed with the same nonce");
    if (!tls12_open(&rx, 1, second, &type, &plain, &why)) return fail("the second record did not open: " + why);

    Bytes tampered = record;
    tampered[tampered.size() - 1] ^= 0x01;
    const u64 before = rx.server_seq;
    if (tls12_open(&rx, 1, tampered, &type, &plain, &why)) return fail("a tampered record was accepted");
    if (rx.server_seq != before) return fail("a failed record advanced the sequence number");

    Bytes short_record = record;
    short_record.resize(short_record.size() - 1);
    if (tls12_open(&rx, 1, short_record, &type, &plain, &why)) return fail("a truncated record was accepted");
  }

  // ----------------------------------------------------------------- finished
  const Bytes transcript = sha256(ascii("client hello | server hello"));
  const Bytes client_fin = tls12_finished_data(a.master_secret, false, transcript);
  const Bytes server_fin = tls12_finished_data(a.master_secret, true, transcript);
  if (client_fin.size() != 12) return fail("verify_data should be 12 bytes");
  if (client_fin == server_fin) return fail("both Finished labels produced the same verify_data");
  if (client_fin == tls12_finished_data(a.master_secret, false, sha256(ascii("other")))) {
    return fail("verify_data did not depend on the transcript");
  }
  if (client_fin == tls12_finished_data(b.master_secret, false, transcript) && a.master_secret != b.master_secret) {
    return fail("verify_data did not depend on the master secret");
  }

  // TLS 1.0/1.1 hash the handshake messages with MD5||SHA1 and feed that into the
  // legacy PRF; make sure the two Finished constructions stay distinct.
  {
    const Bytes messages = ascii("client hello | server hello");
    const Bytes legacy = tls12_finished_data_legacy(a.master_secret, false, messages);
    if (legacy.size() != 12) return fail("the 1.0/1.1 verify_data should be 12 bytes");
    if (legacy == tls12_finished_data(a.master_secret, false, sha256(messages))) {
      return fail("the 1.0/1.1 Finished should not equal the 1.2 one");
    }
  }

  // ------------------------------------------------------------------- alerts
  if (alert_text(70) != "protocol_version") return fail("alert 70 should read protocol_version");
  if (alert_text(40) != "handshake_failure") return fail("alert 40 should read handshake_failure");

  notes += "; offered suites: ";
  for (std::size_t i = 0; i < offered.size(); ++i) {
    if (i != 0) notes += ", ";
    notes += tls12_suite_name(offered[i]);
  }
  if (report != nullptr) *report = "TLS 1.2 key schedule, record layer and Finished agree" + notes;
  return true;
}

}  // namespace netcap
