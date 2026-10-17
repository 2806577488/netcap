// X.509 issuance and parsing for the interception proxy: DER encoding, a local
// CA, per-host leaf certificates, PKCS#8 keys, PEM I/O.
#include "netcap/x509.hpp"
#include "netcap/rsa.hpp"  // RSA signatures are checked by the platform verifier

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace netcap {
namespace {

// ---------------------------------------------------------------- DER writing
Bytes der_tlv(u8 tag, const Bytes& body) {
  Bytes out;
  out.push_back(tag);
  const std::size_t n = body.size();
  if (n < 0x80) {
    out.push_back(static_cast<u8>(n));
  } else {
    u8 tmp[8];
    int count = 0;
    std::size_t rest = n;
    while (rest != 0) {
      tmp[count++] = static_cast<u8>(rest & 0xff);
      rest >>= 8;
    }
    out.push_back(static_cast<u8>(0x80 | count));
    for (int i = count - 1; i >= 0; --i) out.push_back(tmp[i]);
  }
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

Bytes der_seq(const Bytes& body) { return der_tlv(0x30, body); }
Bytes der_set(const Bytes& body) { return der_tlv(0x31, body); }
Bytes der_octets(const Bytes& body) { return der_tlv(0x04, body); }
// Kept for completeness: a NULL and a printable string are part of ASN.1 even
// though the profiles we emit do not need them yet.
[[maybe_unused]] Bytes der_null() { return Bytes{0x05, 0x00}; }
Bytes der_bool(bool v) { return Bytes{0x01, 0x01, static_cast<u8>(v ? 0xff : 0x00)}; }

// INTEGER from an unsigned big-endian value, minimal encoding with a sign byte.
Bytes der_int_be(const Bytes& be) {
  std::size_t start = 0;
  while (start + 1 < be.size() && be[start] == 0) ++start;
  Bytes body;
  if (start >= be.size() || be[start] == 0) {
    body.push_back(0);
  } else {
    if ((be[start] & 0x80) != 0) body.push_back(0x00);  // keep the integer positive
    body.insert(body.end(), be.begin() + static_cast<std::ptrdiff_t>(start), be.end());
  }
  return der_tlv(0x02, body);
}

Bytes der_int_u64(u64 value) {
  Bytes be;
  do {
    be.insert(be.begin(), static_cast<u8>(value & 0xff));
    value >>= 8;
  } while (value != 0);
  return der_int_be(be);
}

Bytes der_bit_string(const Bytes& data) {
  Bytes body;
  body.push_back(0x00);  // no unused bits
  body.insert(body.end(), data.begin(), data.end());
  return der_tlv(0x03, body);
}

Bytes der_bit_string_bits(const Bytes& data, u8 unused) {
  Bytes body;
  body.push_back(unused);
  body.insert(body.end(), data.begin(), data.end());
  return der_tlv(0x03, body);
}

Bytes der_utf8(const std::string& text) { return der_tlv(0x0c, Bytes(text.begin(), text.end())); }
[[maybe_unused]] Bytes der_ia5(const std::string& text) { return der_tlv(0x16, Bytes(text.begin(), text.end())); }
Bytes der_ctx(int n, bool constructed, const Bytes& body) {
  return der_tlv(static_cast<u8>((constructed ? 0xa0 : 0x80) | n), body);
}

// OID from dotted notation.
Bytes der_oid(const std::string& dotted) {
  std::vector<u32> parts;
  u32 cur = 0;
  bool any = false;
  for (char c : dotted) {
    if (c == '.') {
      parts.push_back(cur);
      cur = 0;
      any = false;
    } else if (c >= '0' && c <= '9') {
      cur = cur * 10 + static_cast<u32>(c - '0');
      any = true;
    } else {
      return Bytes{};
    }
  }
  if (any) parts.push_back(cur);
  if (parts.size() < 2) return Bytes{};
  Bytes body;
  body.push_back(static_cast<u8>(parts[0] * 40 + parts[1]));
  for (std::size_t i = 2; i < parts.size(); ++i) {
    u32 value = parts[i];
    u8 tmp[5];
    int count = 0;
    do {
      tmp[count++] = static_cast<u8>(value & 0x7f);
      value >>= 7;
    } while (value != 0);
    for (int j = count - 1; j >= 0; --j) {
      body.push_back(static_cast<u8>(tmp[j] | (j == 0 ? 0x00 : 0x80)));
    }
  }
  return der_tlv(0x06, body);
}

// --------------------------------------------------------------- DER time text
struct Civil {
  int year = 1970;
  int month = 1;
  int day = 1;
  int hour = 0;
  int minute = 0;
  int second = 0;
};

Civil civil_from_epoch(i64 seconds) {
  i64 days = seconds / 86400;
  i64 rem = seconds % 86400;
  if (rem < 0) {
    rem += 86400;
    --days;
  }
  Civil c;
  c.hour = static_cast<int>(rem / 3600);
  c.minute = static_cast<int>((rem % 3600) / 60);
  c.second = static_cast<int>(rem % 60);
  // Howard Hinnant's civil_from_days.
  i64 z = days + 719468;
  const i64 era = (z >= 0 ? z : z - 146096) / 146097;
  const i64 doe = z - era * 146097;
  const i64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const i64 y = yoe + era * 400;
  const i64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const i64 mp = (5 * doy + 2) / 153;
  const i64 d = doy - (153 * mp + 2) / 5 + 1;
  const i64 m = mp < 10 ? mp + 3 : mp - 9;
  c.year = static_cast<int>(y + (m <= 2 ? 1 : 0));
  c.month = static_cast<int>(m);
  c.day = static_cast<int>(d);
  return c;
}

[[maybe_unused]] std::string two(int v) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%02d", v);
  return buf;
}

// UTCTime for 1950..2049, GeneralizedTime otherwise (RFC 5280 §4.1.2.5).
Bytes der_time(i64 unix_seconds) {
  const Civil c = civil_from_epoch(unix_seconds);
  char buf[32];
  if (c.year >= 1950 && c.year <= 2049) {
    std::snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ", c.year % 100, c.month, c.day, c.hour,
                  c.minute, c.second);
    return der_tlv(0x17, Bytes(buf, buf + std::strlen(buf)));
  }
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ", c.year, c.month, c.day, c.hour, c.minute,
                c.second);
  return der_tlv(0x18, Bytes(buf, buf + std::strlen(buf)));
}

// ------------------------------------------------------------------- DER input
struct Reader {
  const u8* p = nullptr;
  const u8* end = nullptr;

  Reader() = default;
  explicit Reader(const Bytes& b) : p(b.data()), end(b.data() + b.size()) {}
  Reader(const u8* begin, const u8* finish) : p(begin), end(finish) {}

  bool done() const { return p >= end; }
  std::size_t left() const { return static_cast<std::size_t>(end - p); }

  // Reads one TLV. `body` points inside the buffer; body_len excludes the header.
  bool tlv(u8* tag, const u8** body, std::size_t* body_len) {
    const u8* save = p;
    if (left() < 2) {
      p = save;
      return false;
    }
    const u8 t = *p++;
    u8 first = *p++;
    std::size_t len = 0;
    if (first < 0x80) {
      len = first;
    } else if (first == 0x80) {
      return false;  // indefinite length: not used by DER
    } else {
      const int count = first & 0x7f;
      if (count > 4 || left() < static_cast<std::size_t>(count)) return false;
      for (int i = 0; i < count; ++i) len = (len << 8) | *p++;
    }
    if (left() < len) {
      p = save;
      return false;
    }
    if (tag != nullptr) *tag = t;
    if (body != nullptr) *body = p;
    if (body_len != nullptr) *body_len = len;
    p += len;
    return true;
  }

  bool enter(u8 want, Reader* child) {
    u8 tag = 0;
    const u8* body = nullptr;
    std::size_t len = 0;
    if (!tlv(&tag, &body, &len)) return false;
    if (want != 0 && tag != want) return false;
    *child = Reader(body, body + len);
    return true;
  }
};

std::string strip_zero_bytes(const u8* p, std::size_t n) {
  return to_hex(p, n);
}

std::string oid_to_string(const u8* p, std::size_t n) {
  if (n == 0) return {};
  std::string out = std::to_string(p[0] / 40) + "." + std::to_string(p[0] % 40);
  std::size_t i = 1;
  while (i < n) {
    u32 value = 0;
    while (i < n) {
      const u8 b = p[i++];
      value = (value << 7) | (b & 0x7f);
      if ((b & 0x80) == 0) break;
    }
    out += "." + std::to_string(value);
  }
  return out;
}

std::string der_string_text(const u8* p, std::size_t n) {
  return std::string(reinterpret_cast<const char*>(p), n);
}

// Pulls the CN out of an RDNSequence.
std::string name_common_name(Reader r) {
  std::string cn;
  Reader rdn;
  while (!r.done()) {
    if (!r.enter(0x31, &rdn)) break;  // SET
    Reader atv;
    while (!rdn.done()) {
      if (!rdn.enter(0x30, &atv)) break;  // SEQUENCE { OID, value }
      u8 tag = 0;
      const u8* body = nullptr;
      std::size_t len = 0;
      if (!atv.tlv(&tag, &body, &len) || tag != 0x06) break;
      const std::string oid = oid_to_string(body, len);
      if (!atv.tlv(&tag, &body, &len)) break;
      if (oid == "2.5.4.3") cn = der_string_text(body, len);
    }
  }
  return cn;
}

Bytes name_der(const X509Subject& subject) {
  Bytes rdns;
  if (!subject.country.empty()) {
    Bytes atv = der_oid("2.5.4.6");
    const Bytes value = der_utf8(subject.country);
    atv.insert(atv.end(), value.begin(), value.end());
    const Bytes set = der_set(der_seq(atv));
    rdns.insert(rdns.end(), set.begin(), set.end());
  }
  if (!subject.organization.empty()) {
    Bytes atv = der_oid("2.5.4.10");
    const Bytes value = der_utf8(subject.organization);
    atv.insert(atv.end(), value.begin(), value.end());
    const Bytes set = der_set(der_seq(atv));
    rdns.insert(rdns.end(), set.begin(), set.end());
  }
  Bytes atv = der_oid("2.5.4.3");
  const Bytes value = der_utf8(subject.common_name);
  atv.insert(atv.end(), value.begin(), value.end());
  const Bytes set = der_set(der_seq(atv));
  rdns.insert(rdns.end(), set.begin(), set.end());
  return der_seq(rdns);
}

Bytes spki_der(const P256Point& point) {
  Bytes alg = der_oid("1.2.840.10045.2.1");
  const Bytes curve = der_oid("1.2.840.10045.3.1.7");
  alg.insert(alg.end(), curve.begin(), curve.end());
  Bytes body = der_seq(alg);
  const Bytes bits = der_bit_string(p256_serialize_uncompressed(point));
  body.insert(body.end(), bits.begin(), bits.end());
  return der_seq(body);
}

Bytes extension(const std::string& oid, bool critical, const Bytes& value) {
  Bytes body = der_oid(oid);
  if (critical) {
    const Bytes flag = der_bool(true);
    body.insert(body.end(), flag.begin(), flag.end());
  }
  const Bytes wrapped = der_octets(value);
  body.insert(body.end(), wrapped.begin(), wrapped.end());
  return der_seq(body);
}

std::string random_serial_hex() {
  u8 buf[16];
  if (!random_bytes(buf, sizeof(buf))) return "01";
  buf[0] &= 0x7f;  // keep it positive
  if (buf[0] == 0) buf[0] = 1;
  return to_hex(buf, sizeof(buf));
}

Bytes serial_der(const std::string& hex) {
  return der_int_be(from_hex(hex));
}

// A key identifier is SHA-256 over the public key, truncated to 20 bytes
// (RFC 7093 method 1). No SHA-1 dependency needed.
Bytes key_identifier(const P256Point& point) {
  const Bytes raw = p256_serialize_uncompressed(point);
  const Bytes digest = sha256(raw.data(), raw.size());
  return Bytes(digest.begin(), digest.begin() + 20);
}

Bytes signature_der(const Bytes& r, const Bytes& s) {
  Bytes body = der_int_be(r);
  const Bytes s_int = der_int_be(s);
  body.insert(body.end(), s_int.begin(), s_int.end());
  return der_seq(body);
}

const char* kSigAlg = "1.2.840.10045.4.3.2";  // ecdsa-with-SHA256

}  // namespace

// ------------------------------------------------------------------ PEM/base64
std::string pem_encode(const std::string& label, const Bytes& der) {
  static const char* kTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out = "-----BEGIN " + label + "-----\n";
  std::string line;
  for (std::size_t i = 0; i < der.size(); i += 3) {
    const u32 b0 = der[i];
    const u32 b1 = (i + 1 < der.size()) ? der[i + 1] : 0;
    const u32 b2 = (i + 2 < der.size()) ? der[i + 2] : 0;
    const u32 triple = (b0 << 16) | (b1 << 8) | b2;
    line.push_back(kTable[(triple >> 18) & 0x3f]);
    line.push_back(kTable[(triple >> 12) & 0x3f]);
    line.push_back(i + 1 < der.size() ? kTable[(triple >> 6) & 0x3f] : '=');
    line.push_back(i + 2 < der.size() ? kTable[triple & 0x3f] : '=');
    if (line.size() >= 64) {
      out += line;
      out += "\n";
      line.clear();
    }
  }
  if (!line.empty()) {
    out += line;
    out += "\n";
  }
  out += "-----END " + label + "-----\n";
  return out;
}

bool pem_decode(const std::string& text, const std::string& label, Bytes* der) {
  if (der == nullptr) return false;
  const std::string begin = "-----BEGIN " + label + "-----";
  const std::string end = "-----END " + label + "-----";
  const std::size_t b = text.find(begin);
  if (b == std::string::npos) return false;
  const std::size_t e = text.find(end, b);
  if (e == std::string::npos) return false;
  auto value_of = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  Bytes out;
  u32 acc = 0;
  int bits = 0;
  for (std::size_t i = b + begin.size(); i < e; ++i) {
    const char c = text[i];
    if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
    const int v = value_of(c);
    if (v < 0) return false;
    acc = (acc << 6) | static_cast<u32>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<u8>((acc >> bits) & 0xff));
    }
  }
  *der = out;
  return !out.empty();
}

// -------------------------------------------------------------------- keys/PEM
Bytes ec_private_key_pkcs8(const P256Key& key) {
  // ECPrivateKey (RFC 5915) then wrapped in PKCS#8 (RFC 5208).
  Bytes ec = der_int_u64(1);
  const Bytes priv = der_octets(key.d);
  ec.insert(ec.end(), priv.begin(), priv.end());
  const Bytes params = der_ctx(0, true, der_oid("1.2.840.10045.3.1.7"));
  ec.insert(ec.end(), params.begin(), params.end());
  const Bytes pub = der_ctx(1, true, der_bit_string(p256_serialize_uncompressed(key.q)));
  ec.insert(ec.end(), pub.begin(), pub.end());
  const Bytes ec_seq = der_seq(ec);

  Bytes alg = der_oid("1.2.840.10045.2.1");
  const Bytes curve = der_oid("1.2.840.10045.3.1.7");
  alg.insert(alg.end(), curve.begin(), curve.end());
  Bytes body = der_int_u64(0);
  const Bytes alg_seq = der_seq(alg);
  body.insert(body.end(), alg_seq.begin(), alg_seq.end());
  const Bytes wrapped = der_octets(ec_seq);
  body.insert(body.end(), wrapped.begin(), wrapped.end());
  return der_seq(body);
}

bool ec_private_key_parse(const Bytes& der, P256Key* out, std::string* error) {
  if (out == nullptr) return false;
  Reader top(der);
  Reader seq;
  if (!top.enter(0x30, &seq)) {
    if (error != nullptr) *error = "not a DER SEQUENCE";
    return false;
  }
  // PKCS#8 keeps the ECPrivateKey inside an OCTET STRING; RFC 5915 puts it at the
  // top level. Accept both.
  u8 tag = 0;
  const u8* body = nullptr;
  std::size_t len = 0;
  const u8* mark = seq.p;
  if (!seq.tlv(&tag, &body, &len)) {
    if (error != nullptr) *error = "empty key structure";
    return false;
  }
  if (tag == 0x02) {  // PKCS#8: version, AlgorithmIdentifier, OCTET STRING
    Reader alg;
    if (!seq.enter(0x30, &alg)) {
      if (error != nullptr) *error = "missing AlgorithmIdentifier";
      return false;
    }
    if (!seq.tlv(&tag, &body, &len) || tag != 0x04) {
      if (error != nullptr) *error = "missing private key OCTET STRING";
      return false;
    }
    Reader inner(body, body + len);
    Reader seq2;
    if (!inner.enter(0x30, &seq2)) {
      if (error != nullptr) *error = "bad ECPrivateKey";
      return false;
    }
    seq = seq2;
    if (!seq.tlv(&tag, &body, &len)) {
      if (error != nullptr) *error = "bad ECPrivateKey version";
      return false;
    }
    if (!seq.tlv(&tag, &body, &len)) {
      if (error != nullptr) *error = "missing private scalar";
      return false;
    }
  }
  (void)mark;
  if (tag != 0x04) {
    if (error != nullptr) *error = "private scalar is not an OCTET STRING";
    return false;
  }
  Bytes scalar(body, body + len);
  if (scalar.size() < 32) scalar.insert(scalar.begin(), 32 - scalar.size(), 0);
  if (scalar.size() > 32) scalar.erase(scalar.begin(), scalar.end() - 32);
  if (!p256_from_private(scalar, out)) {
    if (error != nullptr) *error = "the private scalar is not a valid P-256 key";
    return false;
  }
  return true;
}

// -------------------------------------------------------------------- issuance
bool ca_create(const X509Subject& subject, int days, CaBundle* out, std::string* error) {
  if (out == nullptr) return false;
  P256Key key;
  if (!p256_generate(&key)) {
    if (error != nullptr) *error = "could not generate a P-256 key (no randomness?)";
    return false;
  }
  const std::string serial = random_serial_hex();
  const i64 now = static_cast<i64>(std::time(nullptr));
  const Bytes validity = [&] {
    Bytes v = der_time(now - 86400);
    const Bytes after = der_time(now + static_cast<i64>(days) * 86400);
    v.insert(v.end(), after.begin(), after.end());
    return der_seq(v);
  }();

  Bytes ext = extension("2.5.29.19", true, der_seq(der_bool(true)));
  const Bytes usage = extension("2.5.29.15", true, der_bit_string_bits(Bytes{0x06}, 1));
  ext.insert(ext.end(), usage.begin(), usage.end());
  const Bytes ski = extension("2.5.29.14", false, der_octets(key_identifier(key.q)));
  ext.insert(ext.end(), ski.begin(), ski.end());
  const Bytes ext_seq = der_seq(ext);
  const Bytes extensions = der_ctx(3, true, ext_seq);

  Bytes tbs = der_ctx(0, true, der_int_u64(2));
  const Bytes serial_der_bytes = serial_der(serial);
  tbs.insert(tbs.end(), serial_der_bytes.begin(), serial_der_bytes.end());
  const Bytes alg = der_seq(der_oid(kSigAlg));
  tbs.insert(tbs.end(), alg.begin(), alg.end());
  const Bytes name = name_der(subject);
  tbs.insert(tbs.end(), name.begin(), name.end());
  tbs.insert(tbs.end(), validity.begin(), validity.end());
  tbs.insert(tbs.end(), name.begin(), name.end());
  const Bytes spki = spki_der(key.q);
  tbs.insert(tbs.end(), spki.begin(), spki.end());
  tbs.insert(tbs.end(), extensions.begin(), extensions.end());
  const Bytes tbs_seq = der_seq(tbs);

  const Bytes digest = sha256(tbs_seq.data(), tbs_seq.size());
  Bytes r;
  Bytes s;
  if (!p256_ecdsa_sign(key.d, digest.data(), &r, &s, &key.q)) {
    if (error != nullptr) *error = "signing the CA certificate failed";
    return false;
  }
  Bytes der = tbs_seq;
  der.insert(der.end(), alg.begin(), alg.end());
  const Bytes sig = der_bit_string(signature_der(r, s));
  der.insert(der.end(), sig.begin(), sig.end());
  const Bytes cert_der = der_seq(der);

  X509Cert cert;
  std::string parse_error;
  if (!x509_parse(cert_der, &cert, &parse_error)) {
    if (error != nullptr) *error = "the CA certificate did not parse back: " + parse_error;
    return false;
  }
  out->key = key;
  out->cert = cert;
  out->key_pem = pem_encode("PRIVATE KEY", ec_private_key_pkcs8(key));
  out->cert_pem = pem_encode("CERTIFICATE", cert_der);
  return true;
}

bool leaf_issue_with_key(const CaBundle& ca, const LeafRequest& req, const P256Key& key, X509Cert* out,
                         std::string* error) {
  if (out == nullptr || !ca.valid() || req.host.empty()) {
    if (error != nullptr) *error = "a CA and a host name are required";
    return false;
  }
  const std::string serial = random_serial_hex();
  const i64 now = static_cast<i64>(std::time(nullptr));
  Bytes validity = der_time(now - 86400);
  const Bytes after = der_time(now + static_cast<i64>(req.days) * 86400);
  validity.insert(validity.end(), after.begin(), after.end());
  const Bytes validity_seq = der_seq(validity);

  Bytes ext;
  // basicConstraints: not a CA (an empty SEQUENCE is the honest encoding).
  const Bytes basic = extension("2.5.29.19", true, der_seq(Bytes{}));
  ext.insert(ext.end(), basic.begin(), basic.end());
  const Bytes usage = extension("2.5.29.15", true, der_bit_string_bits(Bytes{0xa0}, 5));  // digitalSignature + keyEncipherment
  ext.insert(ext.end(), usage.begin(), usage.end());
  Bytes eku = der_oid("1.3.6.1.5.5.7.3.1");  // serverAuth
  const Bytes eku_seq = der_seq(eku);
  const Bytes eku_ext = extension("2.5.29.37", false, eku_seq);
  ext.insert(ext.end(), eku_ext.begin(), eku_ext.end());

  Bytes names;
  auto add_dns = [&](const std::string& host) {
    if (host.empty()) return;
    const Bytes gn = der_ctx(2, false, Bytes(host.begin(), host.end()));
    names.insert(names.end(), gn.begin(), gn.end());
  };
  add_dns(req.host);
  for (const std::string& extra : req.extra_dns) {
    if (extra != req.host) add_dns(extra);
  }
  for (const std::string& ip : req.ip_addresses) {
    int version = 0;
    u8 raw[16] = {0};
    if (!parse_ip(ip, &version, raw)) continue;
    if (version == 4) {
      const Bytes gn = der_ctx(7, false, Bytes(raw, raw + 4));
      names.insert(names.end(), gn.begin(), gn.end());
    } else {
      const Bytes gn = der_ctx(7, false, Bytes(raw, raw + 16));
      names.insert(names.end(), gn.begin(), gn.end());
    }
  }
  const Bytes san = extension("2.5.29.17", false, der_seq(names));
  ext.insert(ext.end(), san.begin(), san.end());

  const Bytes ski = extension("2.5.29.14", false, der_octets(key_identifier(key.q)));
  ext.insert(ext.end(), ski.begin(), ski.end());
  Bytes aki_body = der_ctx(0, false, key_identifier(ca.key.q));
  const Bytes aki = extension("2.5.29.35", false, der_seq(aki_body));
  ext.insert(ext.end(), aki.begin(), aki.end());

  const Bytes extensions = der_ctx(3, true, der_seq(ext));

  X509Subject subject;
  subject.common_name = req.host;
  subject.organization = ca.cert.subject_cn.empty() ? "netcap" : ca.cert.subject_cn;
  const Bytes subject_der = name_der(subject);
  // The issuer field has to repeat the CA's subject DN byte for byte, otherwise
  // chain building fails even though the signature is fine.
  const Bytes issuer_der = ca.cert.subject.empty()
                               ? name_der(X509Subject{ca.cert.subject_cn, subject.organization, subject.country})
                               : ca.cert.subject;

  Bytes tbs = der_ctx(0, true, der_int_u64(2));
  const Bytes serial_bytes = serial_der(serial);
  tbs.insert(tbs.end(), serial_bytes.begin(), serial_bytes.end());
  const Bytes alg = der_seq(der_oid(kSigAlg));
  tbs.insert(tbs.end(), alg.begin(), alg.end());
  tbs.insert(tbs.end(), issuer_der.begin(), issuer_der.end());
  tbs.insert(tbs.end(), validity_seq.begin(), validity_seq.end());
  tbs.insert(tbs.end(), subject_der.begin(), subject_der.end());
  const Bytes spki = spki_der(key.q);
  tbs.insert(tbs.end(), spki.begin(), spki.end());
  tbs.insert(tbs.end(), extensions.begin(), extensions.end());
  const Bytes tbs_seq = der_seq(tbs);

  const Bytes digest = sha256(tbs_seq.data(), tbs_seq.size());
  Bytes r;
  Bytes s;
  if (!p256_ecdsa_sign(ca.key.d, digest.data(), &r, &s, &ca.key.q)) {
    if (error != nullptr) *error = "signing the leaf certificate failed";
    return false;
  }
  Bytes der = tbs_seq;
  der.insert(der.end(), alg.begin(), alg.end());
  const Bytes sig = der_bit_string(signature_der(r, s));
  der.insert(der.end(), sig.begin(), sig.end());
  const Bytes cert_der = der_seq(der);

  std::string parse_error;
  if (!x509_parse(cert_der, out, &parse_error)) {
    if (error != nullptr) *error = "the leaf certificate did not parse back: " + parse_error;
    return false;
  }
  return true;
}

bool leaf_issue(const CaBundle& ca, const LeafRequest& req, P256Key* key, X509Cert* out, std::string* error) {
  if (key == nullptr) return false;
  if (!p256_generate(key)) {
    if (error != nullptr) *error = "could not generate a leaf key";
    return false;
  }
  return leaf_issue_with_key(ca, req, *key, out, error);
}

// ---------------------------------------------------------------------- parser
// The value of a DER INTEGER: strip the leading zero byte(s) DER uses to keep
// the value positive (a 2048-bit modulus is written as 257 bytes, one more than
// the number itself).  Everything else in DER is an encoding detail, but RSA
// math needs the bare big-endian number.
Bytes der_integer_value(const u8* body, std::size_t len) {
  std::size_t z = 0;
  while (z + 1 < len && body[z] == 0x00) ++z;
  return Bytes(body + z, body + len);
}

bool x509_parse(const Bytes& der, X509Cert* out, std::string* error) {
  if (out == nullptr || der.empty()) {
    if (error != nullptr) *error = "empty certificate";
    return false;
  }
  *out = X509Cert();
  out->der = der;
  out->sha256 = sha256(der.data(), der.size());

  Reader top(der);
  Reader cert;
  if (!top.enter(0x30, &cert)) {
    if (error != nullptr) *error = "certificate is not a SEQUENCE";
    return false;
  }
  // tbsCertificate: remember its exact bytes, they are what the signature covers.
  const u8* tbs_start = cert.p;
  u8 tag = 0;
  const u8* body = nullptr;
  std::size_t len = 0;
  if (!cert.tlv(&tag, &body, &len) || tag != 0x30) {
    if (error != nullptr) *error = "missing tbsCertificate";
    return false;
  }
  const u8* tbs_end = cert.p;
  Reader tbs(body, body + len);

  // version [0] EXPLICIT is optional.
  Reader opt;
  const u8* save = tbs.p;
  if (tbs.tlv(&tag, &body, &len) && tag == 0xa0) {
    // v3 marker: nothing else to read from it
  } else {
    tbs.p = save;
  }
  if (!tbs.tlv(&tag, &body, &len) || tag != 0x02) {
    if (error != nullptr) *error = "missing serialNumber";
    return false;
  }
  out->serial_hex = strip_zero_bytes(body, len);
  while (out->serial_hex.size() > 2 && out->serial_hex.rfind("00", 0) == 0) out->serial_hex.erase(0, 2);

  Reader sig_alg;
  if (!tbs.enter(0x30, &sig_alg)) {
    if (error != nullptr) *error = "missing signature algorithm";
    return false;
  }
  Reader issuer;
  {
    const u8* issuer_start = tbs.p;
    if (!tbs.enter(0x30, &issuer)) {
      if (error != nullptr) *error = "missing issuer";
      return false;
    }
    out->issuer.assign(issuer_start, tbs.p);
  }
  out->issuer_cn = name_common_name(issuer);

  Reader validity;
  if (!tbs.enter(0x30, &validity)) {
    if (error != nullptr) *error = "missing validity";
    return false;
  }
  for (int i = 0; i < 2; ++i) {
    if (!validity.tlv(&tag, &body, &len)) {
      if (error != nullptr) *error = "missing validity time";
      return false;
    }
    const std::string text = der_string_text(body, len);
    if (i == 0) {
      out->not_before = text;
    } else {
      out->not_after = text;
    }
  }

  Reader subject;
  {
    const u8* subject_start = tbs.p;
    if (!tbs.enter(0x30, &subject)) {
      if (error != nullptr) *error = "missing subject";
      return false;
    }
    out->subject.assign(subject_start, tbs.p);
  }
  out->subject_cn = name_common_name(subject);

  const u8* spki_start = tbs.p;
  Reader spki;
  if (!tbs.enter(0x30, &spki)) {
    if (error != nullptr) *error = "missing subjectPublicKeyInfo";
    return false;
  }
  out->spki.assign(spki_start, tbs.p);
  out->has_spki = true;

  // extensions [3] EXPLICIT SEQUENCE OF Extension
  while (!tbs.done()) {
    if (!tbs.tlv(&tag, &body, &len)) break;
    if (tag != 0xa3) continue;
    Reader list(body, body + len);
    Reader extensions;
    if (!list.enter(0x30, &extensions)) continue;
    Reader ext;
    while (extensions.enter(0x30, &ext)) {
      u8 etag = 0;
      const u8* ebody = nullptr;
      std::size_t elen = 0;
      if (!ext.tlv(&etag, &ebody, &elen) || etag != 0x06) break;
      const std::string oid = oid_to_string(ebody, elen);
      if (!ext.tlv(&etag, &ebody, &elen)) break;
      if (etag == 0x01) {  // critical flag
        if (!ext.tlv(&etag, &ebody, &elen)) break;
      }
      if (etag != 0x04) continue;
      Reader value(ebody, ebody + elen);
      if (oid == "2.5.29.19") {
        Reader bc;
        if (value.enter(0x30, &bc)) {
          const u8* save_bc = bc.p;
          if (bc.tlv(&etag, &ebody, &elen) && etag == 0x01) {
            out->is_ca = elen > 0 && ebody[0] != 0x00;
          } else {
            bc.p = save_bc;
            out->is_ca = false;
          }
        }
      } else if (oid == "2.5.29.17") {
        Reader san;
        if (value.enter(0x30, &san)) {
          Reader entry;
          while (san.tlv(&etag, &ebody, &elen)) {
            if (etag == 0x82) {
              out->dns_names.push_back(der_string_text(ebody, elen));
            } else if (etag == 0x87) {
              int version = 0;
              u8 raw[16] = {0};
              if (elen == 4) {
                std::memcpy(raw, ebody, 4);
                version = 4;
              } else if (elen == 16) {
                std::memcpy(raw, ebody, 16);
                version = 6;
              }
              if (version != 0) out->ip_names.push_back(format_ip(version, raw));
            }
          }
        }
      }
    }
  }

  // signature over the tbsCertificate
  Reader sig_alg2;
  const u8* sig_start = cert.p;
  if (!cert.enter(0x30, &sig_alg2)) {
    if (error != nullptr) *error = "missing outer signature algorithm";
    return false;
  }
  (void)sig_start;
  // The algorithm tells us how to read the bytes that follow: an ECDSA-Sig-Value
  // sequence, or a raw RSA signature.  Comparing the DER OID bytes avoids
  // depending on the dotted-name helper above.
  {
    u8 oid_tag = 0;
    const u8* oid_body = nullptr;
    std::size_t oid_len = 0;
    if (sig_alg2.tlv(&oid_tag, &oid_body, &oid_len) && oid_tag == 0x06) {
      static const u8 kEcSha256[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
      static const u8 kRsaPkcs1[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
      static const u8 kRsaPss[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a};
      if (oid_len == sizeof(kEcSha256) && std::memcmp(oid_body, kEcSha256, oid_len) == 0) {
        out->signature_algorithm = "ecdsa-with-SHA256";
      } else if (oid_len == sizeof(kRsaPkcs1) && std::memcmp(oid_body, kRsaPkcs1, oid_len) == 0) {
        out->signature_algorithm = "sha256WithRSAEncryption";
      } else if (oid_len == sizeof(kRsaPss) && std::memcmp(oid_body, kRsaPss, oid_len) == 0) {
        out->signature_algorithm = "rsassaPss";
      }
    }
  }
  if (!cert.tlv(&tag, &body, &len) || tag != 0x03) {
    if (error != nullptr) *error = "missing signature value";
    return false;
  }
  if (len < 1 || body[0] != 0x00) {
    if (error != nullptr) *error = "unexpected signature bit string";
    return false;
  }
  out->tbs.assign(tbs_start, tbs_end);
  const Bytes sig_der(body + 1, body + len);
  out->signature.assign(body + 1, body + len);
  const bool rsa_signed = out->signature_algorithm == "sha256WithRSAEncryption" ||
                          out->signature_algorithm == "rsassaPss";
  Reader sig_reader(sig_der);
  Reader sig_seq;
  if (!rsa_signed && sig_reader.enter(0x30, &sig_seq)) {
    u8 rtag = 0;
    const u8* rbody = nullptr;
    std::size_t rlen = 0;
    if (sig_seq.tlv(&rtag, &rbody, &rlen) && rtag == 0x02) {
      Bytes r(rbody, rbody + rlen);
      while (r.size() > 32 && r[0] == 0x00) r.erase(r.begin());
      out->signature_r = r;
    }
    if (sig_seq.tlv(&rtag, &rbody, &rlen) && rtag == 0x02) {
      Bytes s(rbody, rbody + rlen);
      while (s.size() > 32 && s[0] == 0x00) s.erase(s.begin());
      out->signature_s = s;
    }
  }
  // The public key, for callers that need to verify something with it.
  {
    Reader spki_reader(out->spki);
    Reader outer;
    if (spki_reader.enter(0x30, &outer)) {
      Reader algid;
      if (outer.enter(0x30, &algid)) {
        // rsaEncryption (1.2.840.113549.1.1.1) means the key is RSA: the BIT
        // STRING then holds `SEQUENCE { INTEGER modulus, INTEGER exponent }`.
        bool is_rsa = false;
        {
          u8 oid_tag = 0;
          const u8* oid_body = nullptr;
          std::size_t oid_len = 0;
          static const u8 kRsaEncryption[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
          if (algid.tlv(&oid_tag, &oid_body, &oid_len) && oid_tag == 0x06) {
            is_rsa = oid_len == sizeof(kRsaEncryption) &&
                     std::memcmp(oid_body, kRsaEncryption, oid_len) == 0;
          }
        }
        u8 btag = 0;
        const u8* bbody = nullptr;
        std::size_t blen = 0;
        if (outer.tlv(&btag, &bbody, &blen) && btag == 0x03 && blen > 1) {
          if (!is_rsa) {
            P256Point point;
            if (p256_parse_point(bbody + 1, blen - 1, &point)) out->public_key = point;
          } else {
            Reader key_reader(bbody + 1, bbody + blen);
            Reader key_seq;
            if (key_reader.enter(0x30, &key_seq)) {
              u8 ktag = 0;
              const u8* kbody = nullptr;
              std::size_t klen = 0;
              if (key_seq.tlv(&ktag, &kbody, &klen) && ktag == 0x02) {
                out->rsa_modulus = der_integer_value(kbody, klen);
              }
              if (key_seq.tlv(&ktag, &kbody, &klen) && ktag == 0x02) {
                out->rsa_exponent = der_integer_value(kbody, klen);
              }
              out->has_rsa = !out->rsa_modulus.empty() && !out->rsa_exponent.empty();
            }
          }
        }
      }
    }
  }
  return true;
}

bool x509_verify_signature(const X509Cert& cert, const X509Cert& issuer) {
  if (cert.tbs.empty()) return false;
  const Bytes digest = sha256(cert.tbs.data(), cert.tbs.size());
  // RSA-signed certificates (most of the web) are checked through the platform
  // verifier: the P-256 engine here has no RSA.
  if (cert.signature_algorithm == "sha256WithRSAEncryption" ||
      cert.signature_algorithm == "rsassaPss") {
    if (!issuer.has_rsa || cert.signature.empty()) return false;
    const bool pss = cert.signature_algorithm == "rsassaPss";
    return rsa_verify_sha256(issuer.rsa_modulus, issuer.rsa_exponent, digest.data(), cert.signature,
                             pss, 32);
  }
  if (cert.signature_r.size() != 32 || cert.signature_s.size() != 32) return false;
  if (!p256_valid_public(issuer.public_key)) return false;
  return p256_ecdsa_verify(issuer.public_key, digest.data(), cert.signature_r, cert.signature_s);
}

bool x509_matches_host(const X509Cert& cert, const std::string& host) {
  const std::string needle = to_lower(host);
  for (const std::string& name : cert.dns_names) {
    const std::string candidate = to_lower(name);
    if (candidate == needle) return true;
    if (candidate.size() > 2 && candidate[0] == '*' && candidate[1] == '.') {
      const std::string suffix = candidate.substr(1);  // ".example.com"
      if (needle.size() > suffix.size() &&
          needle.compare(needle.size() - suffix.size(), suffix.size(), suffix) == 0) {
        // A wildcard covers exactly one label.
        const std::string head = needle.substr(0, needle.size() - suffix.size());
        if (head.find('.') == std::string::npos) return true;
      }
    }
  }
  for (const std::string& ip : cert.ip_names) {
    if (to_lower(ip) == needle) return true;
  }
  return false;
}

std::string X509Cert::describe() const {
  std::string text = "subject=" + (subject_cn.empty() ? std::string("(none)") : subject_cn);
  text += " issuer=" + (issuer_cn.empty() ? std::string("(none)") : issuer_cn);
  text += " serial=" + serial_hex;
  text += std::string(" ca=") + (is_ca ? "yes" : "no");
  if (!dns_names.empty()) {
    text += " san=";
    for (std::size_t i = 0; i < dns_names.size(); ++i) {
      if (i != 0) text += ",";
      text += dns_names[i];
    }
  }
  text += " sha256=" + sha256_hex();
  return text;
}

// -------------------------------------------------------------------- CA files
bool ca_write_files(const CaBundle& ca, const std::string& cert_path, const std::string& key_path,
                    std::string* error) {
  auto write = [&](const std::string& path, const std::string& text) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (f == nullptr) return false;
    const std::size_t wrote = std::fwrite(text.data(), 1, text.size(), f);
    std::fclose(f);
    return wrote == text.size();
  };
  if (!write(cert_path, ca.cert_pem)) {
    if (error != nullptr) *error = "could not write " + cert_path;
    return false;
  }
  if (!key_path.empty() && !write(key_path, ca.key_pem)) {
    if (error != nullptr) *error = "could not write " + key_path;
    return false;
  }
  return true;
}

bool ca_read_files(const std::string& cert_path, const std::string& key_path, CaBundle* out,
                   std::string* error) {
  if (out == nullptr) return false;
  auto read = [](const std::string& path, std::string* text) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) return false;
    char buf[4096];
    text->clear();
    std::size_t got = 0;
    while ((got = std::fread(buf, 1, sizeof(buf), f)) > 0) text->append(buf, got);
    std::fclose(f);
    return true;
  };
  std::string cert_text;
  std::string key_text;
  if (!read(cert_path, &cert_text)) {
    if (error != nullptr) *error = "could not read " + cert_path;
    return false;
  }
  Bytes cert_der;
  if (!pem_decode(cert_text, "CERTIFICATE", &cert_der)) {
    if (error != nullptr) *error = cert_path + " does not contain a PEM certificate";
    return false;
  }
  X509Cert cert;
  std::string parse_error;
  if (!x509_parse(cert_der, &cert, &parse_error)) {
    if (error != nullptr) *error = "could not parse " + cert_path + ": " + parse_error;
    return false;
  }
  out->cert = cert;
  out->cert_pem = cert_text;
  if (key_path.empty()) return true;
  if (!read(key_path, &key_text)) {
    if (error != nullptr) *error = "could not read " + key_path;
    return false;
  }
  Bytes key_der;
  if (!pem_decode(key_text, "PRIVATE KEY", &key_der) && !pem_decode(key_text, "EC PRIVATE KEY", &key_der)) {
    if (error != nullptr) *error = key_path + " does not contain a PEM private key";
    return false;
  }
  if (!ec_private_key_parse(key_der, &out->key, error)) return false;
  out->key_pem = key_text;
  return true;
}

}  // namespace netcap
