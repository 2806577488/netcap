#include "netcap/tls13.hpp"
#include "netcap/rsa.hpp"  // rsa_verify_sha256 for RSA-only origins

#include <cctype>
#include <cstdlib>
#include <ctime>
#include <cstring>

#include "netcap/p521.hpp"  // the third ECDHE group, for clients that refuse the others
#include "netcap/tls.hpp"  // tls_cipher_suite_name / handshake names for logs

namespace netcap {
namespace {

// NETCAP_TLS_DEBUG=1 makes the record layer log what it reads and writes.  A
// hand-written TLS stack is otherwise impossible to debug from the outside.
bool tls_debug_enabled() {
  static const bool on = std::getenv("NETCAP_TLS_DEBUG") != nullptr;
  return on;
}

// Debug only: which read loop is running, so a proxy log can tell the client
// side of the connection from the upstream side.  Set at the top of each loop.
const char* g_read_role = "?";

constexpr std::size_t kMaxRecord = 16384 + 512;
constexpr u16 kLegacyVersion = 0x0303;
constexpr u16 kTls13Version = 0x0304;
constexpr u8 kHandshakeClientHello = 1;
constexpr u8 kHandshakeServerHello = 2;
constexpr u8 kHandshakeMessageHash = 254;  // RFC 8446 4.4.1, used with HRR
constexpr u8 kHandshakeEncryptedExtensions = 8;
constexpr u8 kHandshakeCertificate = 11;
constexpr u8 kHandshakeCertificateVerify = 15;
constexpr u8 kHandshakeFinished = 20;
constexpr u8 kHandshakeNewSessionTicket = 4;
constexpr u8 kAlertCloseNotify = 0;

const char* kServerContext = "TLS 1.3, server CertificateVerify";
const char* kClientContext = "TLS 1.3, client CertificateVerify";

// ------------------------------------------------------------------ helpers

void put16(Bytes& out, u16 v) {
  out.push_back(static_cast<u8>(v >> 8));
  out.push_back(static_cast<u8>(v & 0xff));
}

void put24(Bytes& out, u32 v) {
  out.push_back(static_cast<u8>((v >> 16) & 0xff));
  out.push_back(static_cast<u8>((v >> 8) & 0xff));
  out.push_back(static_cast<u8>(v & 0xff));
}

void append16(Bytes& out, const Bytes& body) {
  put16(out, static_cast<u16>(body.size()));
  out.insert(out.end(), body.begin(), body.end());
}

void append24(Bytes& out, const Bytes& body) {
  put24(out, static_cast<u32>(body.size()));
  out.insert(out.end(), body.begin(), body.end());
}

bool read16(const u8* p, std::size_t len, std::size_t* off, u16* out) {
  if (*off + 2 > len) return false;
  *out = static_cast<u16>((p[*off] << 8) | p[*off + 1]);
  *off += 2;
  return true;
}

bool read24(const u8* p, std::size_t len, std::size_t* off, u32* out) {
  if (*off + 3 > len) return false;
  *out = (static_cast<u32>(p[*off]) << 16) | (static_cast<u32>(p[*off + 1]) << 8) | p[*off + 2];
  *off += 3;
  return true;
}

bool read_bytes(const u8* p, std::size_t len, std::size_t* off, std::size_t n, Bytes* out) {
  if (*off + n > len) return false;
  if (out != nullptr) out->assign(p + *off, p + *off + n);
  *off += n;
  return true;
}

Bytes random_bytes_of(std::size_t n) {
  Bytes b(n, 0);
  random_bytes(b.data(), n);
  return b;
}

Bytes zero_hash() { return sha256(nullptr, 0); }

// The 5 byte record header, which is also the AEAD additional data.
Bytes record_header(std::size_t body_len) {
  Bytes h;
  h.push_back(TLS13_APPDATA);
  put16(h, kLegacyVersion);
  put16(h, static_cast<u16>(body_len));
  return h;
}

Bytes nonce_for(const Bytes& iv, u64 seq) {
  Bytes nonce = iv;
  for (int i = 0; i < 8; ++i) {
    nonce[nonce.size() - 1 - i] ^= static_cast<u8>((seq >> (8 * i)) & 0xff);
  }
  return nonce;
}

Bytes finished_key(const Bytes& traffic_secret) {
  return tls13_expand_label(traffic_secret, "finished", Bytes{}, 32);
}

// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
bool parse_ecdsa_signature(const Bytes& der, Bytes* r, Bytes* s) {
  std::size_t off = 0;
  if (der.size() < 8 || der[off++] != 0x30) return false;
  std::size_t seq_len = 0;
  if (der[off] < 0x80) {
    seq_len = der[off++];
  } else {
    const std::size_t n = der[off++] & 0x7f;
    if (n == 0 || n > 2 || off + n > der.size()) return false;
    for (std::size_t i = 0; i < n; ++i) seq_len = (seq_len << 8) | der[off++];
  }
  if (off + seq_len > der.size()) return false;
  auto read_int = [&](Bytes* out) -> bool {
    if (off >= der.size() || der[off++] != 0x02) return false;
    std::size_t n = 0;
    if (der[off] < 0x80) {
      n = der[off++];
    } else {
      const std::size_t k = der[off++] & 0x7f;
      if (k == 0 || k > 2 || off + k > der.size()) return false;
      for (std::size_t i = 0; i < k; ++i) n = (n << 8) | der[off++];
    }
    if (off + n > der.size()) return false;
    out->assign(der.begin() + static_cast<std::ptrdiff_t>(off),
                der.begin() + static_cast<std::ptrdiff_t>(off + n));
    off += n;
    // Strip the sign byte and left pad to 32 bytes.
    while (out->size() > 1 && out->front() == 0) out->erase(out->begin());
    if (out->size() > 32) return false;
    while (out->size() < 32) out->insert(out->begin(), 0);
    return true;
  };
  return read_int(r) && read_int(s);
}

// "YYMMDDHHMMSSZ" or "YYYYMMDDHHMMSSZ" -> "YYYYMMDDHHMMSS"
std::string date_key(const std::string& text) {
  std::string digits;
  for (char ch : text) {
    if (ch >= '0' && ch <= '9') digits.push_back(ch);
  }
  if (digits.size() == 12) return "20" + digits;  // UTCTime assumes 20xx
  return digits;
}

std::string now_key() {
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &now);
#else
  gmtime_r(&now, &tm);
#endif
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return std::string(buf);
}

// The signed content of a CertificateVerify message.
Bytes certificate_verify_input(bool from_server, const Bytes& transcript_hash) {
  Bytes input(64, 0x20);
  const char* context = from_server ? kServerContext : kClientContext;
  input.insert(input.end(), context, context + std::strlen(context));
  input.push_back(0x00);
  input.insert(input.end(), transcript_hash.begin(), transcript_hash.end());
  return input;
}

struct ClientHello {
  Bytes body;          // the whole handshake message body
  Bytes session_id;
  u16 cipher_suites[32] = {0};
  std::size_t cipher_count = 0;
  std::string sni;
  std::vector<std::string> alpn;
  bool tls13 = false;
  u16 key_share_group = 0;
  Bytes key_share;
  std::vector<u16> key_share_groups;   // every group a key share was sent for
  std::vector<u16> supported_groups;   // the supported_groups list, in order
  bool offers_x25519 = false;      // x25519 is listed in supported_groups (0x000a)
  bool offers_secp256r1 = false;   // secp256r1 is listed there as well
  bool offers_secp521r1 = false;   // and secp521r1, for clients that refuse both
  bool has_signature_algorithms = false;
  bool offers_ecdsa_p256 = false;
};

bool parse_client_hello(const Bytes& body, ClientHello* out, std::string* error) {
  const u8* p = body.data();
  const std::size_t len = body.size();
  std::size_t off = 0;
  u16 legacy = 0;
  if (!read16(p, len, &off, &legacy)) {
    if (error != nullptr) *error = "ClientHello is truncated";
    return false;
  }
  Bytes random;
  if (!read_bytes(p, len, &off, 32, &random)) {
    if (error != nullptr) *error = "ClientHello has no random";
    return false;
  }
  u8 sid_len = 0;
  if (off >= len) {
    if (error != nullptr) *error = "ClientHello has no session id length";
    return false;
  }
  sid_len = p[off++];
  if (!read_bytes(p, len, &off, sid_len, &out->session_id)) {
    if (error != nullptr) *error = "ClientHello session id is truncated";
    return false;
  }
  u16 suites_len = 0;
  if (!read16(p, len, &off, &suites_len) || (suites_len % 2) != 0 || off + suites_len > len) {
    if (error != nullptr) *error = "ClientHello cipher suite list is broken";
    return false;
  }
  for (std::size_t i = 0; i + 1 < suites_len && out->cipher_count < 32; i += 2) {
    out->cipher_suites[out->cipher_count++] = static_cast<u16>((p[off + i] << 8) | p[off + i + 1]);
  }
  off += suites_len;
  if (off >= len) {
    if (error != nullptr) *error = "ClientHello has no compression list";
    return false;
  }
  const u8 comp_len = p[off++];
  if (off + comp_len > len) {
    if (error != nullptr) *error = "ClientHello compression list is truncated";
    return false;
  }
  off += comp_len;
  u16 ext_total = 0;
  if (!read16(p, len, &off, &ext_total) || off + ext_total > len) {
    if (error != nullptr) *error = "ClientHello has no extensions";
    return false;
  }
  const std::size_t ext_end = off + ext_total;
  while (off + 4 <= ext_end) {
    u16 type = 0;
    u16 elen = 0;
    read16(p, ext_end, &off, &type);
    read16(p, ext_end, &off, &elen);
    if (off + elen > ext_end) break;
    const u8* e = p + off;
    switch (type) {
      case 0x0000: {  // server_name
        std::size_t eo = 0;
        u16 list_len = 0;
        if (read16(e, elen, &eo, &list_len) && eo + 1 <= elen) {
          const u8 name_type = e[eo++];
          u16 name_len = 0;
          if (name_type == 0 && read16(e, elen, &eo, &name_len) && eo + name_len <= elen) {
            out->sni.assign(reinterpret_cast<const char*>(e + eo), name_len);
            for (char& ch : out->sni) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
          }
        }
        break;
      }
      case 0x0010: {  // ALPN
        std::size_t eo = 0;
        u16 list_len = 0;
        if (read16(e, elen, &eo, &list_len)) {
          const std::size_t list_end = eo + list_len;
          while (eo < list_end && eo < elen) {
            const u8 n = e[eo++];
            if (eo + n > elen) break;
            out->alpn.emplace_back(reinterpret_cast<const char*>(e + eo), n);
            eo += n;
          }
        }
        break;
      }
      case 0x002b: {  // supported_versions
        if (elen >= 1) {
          const std::size_t n = e[0];
          for (std::size_t i = 0; i + 1 < n && i + 2 <= elen; i += 2) {
            if (static_cast<u16>((e[i + 1] << 8) | e[i + 2]) == kTls13Version) out->tls13 = true;
          }
        }
        break;
      }
      case 0x0033: {  // key_share
        // A modern client may send several entries and put the post-quantum
        // hybrid first (OpenSSL 3.5 and Chrome send X25519MLKEM768), so scan
        // the whole list and prefer the group this stack can actually use.
        struct KsEntry {
          u16 group;
          Bytes data;
        };
        std::vector<KsEntry> entries;
        std::size_t eo = 0;
        u16 list_len = 0;
        if (read16(e, elen, &eo, &list_len)) {
          const std::size_t list_end = eo + list_len;
          while (eo + 4 <= list_end && eo + 4 <= elen) {
            u16 group = 0;
            u16 klen = 0;
            read16(e, elen, &eo, &group);
            read16(e, elen, &eo, &klen);
            if (eo + klen > elen) break;
            KsEntry entry;
            entry.group = group;
            entry.data.assign(e + eo, e + eo + klen);
            entries.push_back(entry);
            eo += klen;
          }
        }
        for (const KsEntry& entry : entries) out->key_share_groups.push_back(entry.group);
        for (const KsEntry& entry : entries) {
          if (entry.group == TLS13_GROUP_X25519) {
            out->key_share_group = entry.group;
            out->key_share = entry.data;
            break;
          }
        }
        if (out->key_share.empty()) {
          // secp256r1 next: the P-256 code that signs the leaves also does ECDH,
          // and a client with no x25519 share usually sends one of these.
          for (const KsEntry& entry : entries) {
            if (entry.group == TLS13_GROUP_SECP256R1) {
              out->key_share_group = entry.group;
              out->key_share = entry.data;
              break;
            }
          }
        }
        if (out->key_share.empty()) {
          // secp521r1 last of the three this stack can do: rarer than the other
          // two, but a client that offers only this group used to be turned away
          // entirely, which costs the whole application it belongs to.
          for (const KsEntry& entry : entries) {
            if (entry.group == TLS13_GROUP_SECP521R1) {
              out->key_share_group = entry.group;
              out->key_share = entry.data;
              break;
            }
          }
        }
        if (out->key_share.empty() && !entries.empty()) {
          out->key_share_group = entries.front().group;
          out->key_share = entries.front().data;
        }
        break;
      }
      case 0x000a: {  // supported_groups
        std::size_t eo = 0;
        u16 list_len = 0;
        if (read16(e, elen, &eo, &list_len)) {
          const std::size_t list_end = eo + list_len;
          while (eo + 2 <= list_end && eo + 2 <= elen) {
            u16 group = 0;
            read16(e, elen, &eo, &group);
            out->supported_groups.push_back(group);
            if (group == TLS13_GROUP_X25519) out->offers_x25519 = true;
            if (group == TLS13_GROUP_SECP256R1) out->offers_secp256r1 = true;
            if (group == TLS13_GROUP_SECP521R1) out->offers_secp521r1 = true;
          }
        }
        break;
      }
      case 0x000d: {  // signature_algorithms
        out->has_signature_algorithms = true;
        std::size_t eo = 0;
        u16 list_len = 0;
        if (read16(e, elen, &eo, &list_len)) {
          for (std::size_t i = 0; i + 1 < list_len && eo + i + 1 < elen; i += 2) {
            if (static_cast<u16>((e[eo + i] << 8) | e[eo + i + 1]) == TLS13_SIG_ECDSA_P256_SHA256) {
              out->offers_ecdsa_p256 = true;
            }
          }
        }
        break;
      }
      default:
        break;
    }
    off += elen;
  }
  return true;
}

// Builds the handshake body of a ServerHello.
Bytes server_hello_body(const Bytes& server_random, const Bytes& session_id, u16 suite,
                        const Bytes& key_share_public, u16 group) {
  Bytes body;
  put16(body, kLegacyVersion);
  body.insert(body.end(), server_random.begin(), server_random.end());
  body.push_back(static_cast<u8>(session_id.size()));
  body.insert(body.end(), session_id.begin(), session_id.end());
  put16(body, suite);
  body.push_back(0);  // legacy_compression_method
  Bytes exts;
  put16(exts, 0x002b);  // supported_versions
  put16(exts, 2);
  put16(exts, kTls13Version);
  put16(exts, 0x0033);  // key_share
  {
    Bytes ks;
    put16(ks, group);
    append16(ks, key_share_public);
    append16(exts, ks);
  }
  append16(body, exts);
  return body;
}

// RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello whose random field is
// this constant, and whose key_share extension carries only the group the
// server wants to see in the second ClientHello.  4.1.4 adds one more rule the
// client does enforce: the cipher suite here must be the one the real ServerHello
// will name, or the client stops with "wrong cipher returned".
const u8 kHelloRetryRandom[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                  0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                  0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                  0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

Bytes hello_retry_body(const Bytes& session_id, u16 group, u16 suite) {
  Bytes body;
  put16(body, kLegacyVersion);
  body.insert(body.end(), kHelloRetryRandom, kHelloRetryRandom + 32);
  body.push_back(static_cast<u8>(session_id.size()));
  body.insert(body.end(), session_id.begin(), session_id.end());
  put16(body, suite);
  body.push_back(0);  // legacy_compression_method
  Bytes exts;
  put16(exts, 0x002b);  // supported_versions
  put16(exts, 2);
  put16(exts, kTls13Version);
  put16(exts, 0x0033);  // key_share: selected_group only
  put16(exts, 2);
  put16(exts, group);
  append16(body, exts);
  return body;
}

bool parse_server_hello(const Bytes& body, Bytes* server_random, Bytes* session_id, u16* suite,
                        u16* group, Bytes* key_share, bool* tls13, std::string* error) {
  const u8* p = body.data();
  const std::size_t len = body.size();
  std::size_t off = 0;
  u16 legacy = 0;
  if (!read16(p, len, &off, &legacy) || !read_bytes(p, len, &off, 32, server_random)) {
    if (error != nullptr) *error = "ServerHello is truncated";
    return false;
  }
  if (off >= len) {
    if (error != nullptr) *error = "ServerHello has no session id";
    return false;
  }
  const u8 sid_len = p[off++];
  if (!read_bytes(p, len, &off, sid_len, session_id)) {
    if (error != nullptr) *error = "ServerHello session id is truncated";
    return false;
  }
  if (!read16(p, len, &off, suite)) {
    if (error != nullptr) *error = "ServerHello has no cipher suite";
    return false;
  }
  if (off >= len) {
    if (error != nullptr) *error = "ServerHello has no compression byte";
    return false;
  }
  ++off;  // legacy_compression_method
  u16 ext_total = 0;
  *tls13 = false;
  if (!read16(p, len, &off, &ext_total)) {
    if (error != nullptr) *error = "ServerHello has no extensions";
    return false;
  }
  const std::size_t ext_end = off + ext_total;
  while (off + 4 <= ext_end) {
    u16 type = 0;
    u16 elen = 0;
    read16(p, ext_end, &off, &type);
    read16(p, ext_end, &off, &elen);
    if (off + elen > ext_end) break;
    const u8* e = p + off;
    if (type == 0x002b && elen >= 2) {
      *tls13 = (static_cast<u16>((e[0] << 8) | e[1]) == kTls13Version);
    } else if (type == 0x0033 && elen >= 4) {
      std::size_t eo = 0;
      read16(e, elen, &eo, group);
      u16 klen = 0;
      if (read16(e, elen, &eo, &klen) && eo + klen <= elen) {
        key_share->assign(e + eo, e + eo + klen);
      }
    }
    off += elen;
  }
  return true;
}

}  // namespace

// --------------------------------------------------------------- key schedule

Bytes tls13_expand_label(const Bytes& secret, const std::string& label, const Bytes& context,
                         std::size_t out_len) {
  return hkdf_expand_label(secret, label, context, out_len, false);
}

Bytes tls13_derive_secret(const Bytes& secret, const std::string& label, const Bytes& transcript) {
  return tls13_expand_label(secret, label, sha256(transcript), 32);
}

bool tls13_derive_handshake(const Bytes& shared, const Bytes& transcript_ch_sh, Tls13Secrets* out) {
  // The ECDHE input is the x coordinate of the shared point (RFC 8446 7.1), so
  // how long it is belongs to the group: 32 bytes for x25519 and secp256r1, 66
  // for secp521r1.  HKDF-Extract takes an IKM of any length, so only an empty
  // secret is actually an error here -- requiring exactly 32 bytes is what turned
  // every secp521r1 handshake into a "key schedule failed" and, before the blind
  // relay fallback existed, into a broken connection.
  if (out == nullptr || shared.empty()) return false;
  static const Bytes zeros(32, 0);
  const Bytes early = hkdf_extract(zeros, zeros);
  const Bytes derived = tls13_expand_label(early, "derived", zero_hash(), 32);
  const Bytes hs = hkdf_extract(derived, shared);
  out->early_secret = early;
  out->handshake_secret = hs;
  out->shared = shared;
  out->client_handshake.secret = tls13_derive_secret(hs, "c hs traffic", transcript_ch_sh);
  out->server_handshake.secret = tls13_derive_secret(hs, "s hs traffic", transcript_ch_sh);
  auto load = [&](Tls13Traffic* t) {
    // The key length follows the suite: AES-128-GCM uses 16 bytes,
    // ChaCha20-Poly1305 uses 32.
    const std::size_t key_len = out->suite == TLS13_CHACHA20_POLY1305 ? 32 : 16;
    t->key = tls13_expand_label(t->secret, "key", Bytes{}, key_len);
    t->iv = tls13_expand_label(t->secret, "iv", Bytes{}, 12);
    t->seq = 0;
    t->ready = true;
    t->suite = out->suite;
  };
  load(&out->client_handshake);
  load(&out->server_handshake);
  return true;
}

bool tls13_derive_application(Tls13Secrets* secrets, const Bytes& transcript_through_finished) {
  if (secrets == nullptr) return false;
  const Bytes derived = tls13_expand_label(secrets->handshake_secret, "derived", zero_hash(), 32);
  static const Bytes zeros(32, 0);
  const Bytes master = hkdf_extract(derived, zeros);
  secrets->master_secret = master;
  secrets->client_application.secret =
      tls13_derive_secret(master, "c ap traffic", transcript_through_finished);
  secrets->server_application.secret =
      tls13_derive_secret(master, "s ap traffic", transcript_through_finished);
  auto load = [&](Tls13Traffic* t) {
    const std::size_t key_len = secrets->suite == TLS13_CHACHA20_POLY1305 ? 32 : 16;
    t->key = tls13_expand_label(t->secret, "key", Bytes{}, key_len);
    t->iv = tls13_expand_label(t->secret, "iv", Bytes{}, 12);
    t->seq = 0;
    t->ready = true;
    t->suite = secrets->suite;
  };
  load(&secrets->client_application);
  load(&secrets->server_application);
  return true;
}

Bytes tls13_finished_data(const Bytes& traffic_secret, const Bytes& transcript) {
  return hmac_sha256(finished_key(traffic_secret), sha256(transcript));
}

bool tls13_seal(Tls13Traffic* traffic, u8 inner_type, const Bytes& content, Bytes* record) {
  if (traffic == nullptr || !traffic->ready || record == nullptr) return false;
  Bytes plain = content;
  plain.push_back(inner_type);
  Bytes header = record_header(plain.size() + 16);
  const Bytes nonce = nonce_for(traffic->iv, traffic->seq);
  const AeadResult sealed = traffic->suite == TLS13_CHACHA20_POLY1305
                                ? chacha20_poly1305_encrypt(traffic->key, nonce, header, plain)
                                : aes_gcm_encrypt(traffic->key, nonce, header, plain);
  if (!sealed.ok) return false;
  ++traffic->seq;  // the nonce must never repeat for the same key
  record->clear();
  record->insert(record->end(), header.begin(), header.end());
  record->insert(record->end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
  record->insert(record->end(), sealed.tag.begin(), sealed.tag.end());
  return true;
}

bool tls13_open(Tls13Traffic* traffic, const Bytes& record, u8* inner_type, Bytes* content,
                std::string* error) {
  if (traffic == nullptr || !traffic->ready) {
    if (error != nullptr) *error = "no keys for this direction yet";
    return false;
  }
  if (record.size() < 5 + 16) {
    if (error != nullptr) *error = "encrypted record is too short";
    return false;
  }
  const Bytes header(record.begin(), record.begin() + 5);
  const Bytes body(record.begin() + 5, record.end() - 16);
  const Bytes tag(record.end() - 16, record.end());
  const Bytes nonce = nonce_for(traffic->iv, traffic->seq);
  Bytes plain;
  const bool opened =
      traffic->suite == TLS13_CHACHA20_POLY1305
          ? chacha20_poly1305_decrypt(traffic->key, nonce, header, body, tag, &plain)
          : aes_gcm_decrypt(traffic->key, nonce, header, body, tag, &plain);
  if (!opened) {
    if (error != nullptr) *error = "record authentication failed";
    return false;
  }
  ++traffic->seq;
  // Strip the zero padding, then the last non-zero byte is the real type.
  std::size_t end = plain.size();
  while (end > 0 && plain[end - 1] == 0) --end;
  if (end == 0) {
    if (error != nullptr) *error = "encrypted record has no inner type";
    return false;
  }
  *inner_type = plain[end - 1];
  content->assign(plain.begin(), plain.begin() + static_cast<std::ptrdiff_t>(end - 1));
  return true;
}

// --------------------------------------------------------------- transcript

void Tls13Transcript::add(const Bytes& handshake_message) {
  data_.insert(data_.end(), handshake_message.begin(), handshake_message.end());
}

void Tls13Transcript::reset() { data_.clear(); }

Bytes Tls13Transcript::hash() const { return sha256(data_); }

Bytes tls13_handshake(u8 type, const Bytes& body) {
  Bytes msg;
  msg.push_back(type);
  put24(msg, static_cast<u32>(body.size()));
  msg.insert(msg.end(), body.begin(), body.end());
  return msg;
}

bool tls13_next_handshake(const Bytes& body, std::size_t* offset, u8* type, Bytes* message) {
  std::size_t off = *offset;
  if (off + 4 > body.size()) return false;
  const u8 t = body[off];
  const u32 len = (static_cast<u32>(body[off + 1]) << 16) | (static_cast<u32>(body[off + 2]) << 8) |
                  body[off + 3];
  if (off + 4 + len > body.size()) return false;
  *type = t;
  message->assign(body.begin() + static_cast<std::ptrdiff_t>(off),
                  body.begin() + static_cast<std::ptrdiff_t>(off + 4 + len));
  *offset = off + 4 + len;
  return true;
}

// -------------------------------------------------------------- record I/O

bool tls13_read_record(const Tls13Io& io, Bytes* record, std::string* error) {
  u8 header[5];
  std::size_t got = 0;
  if (!io.read(header, 5, &got) || got != 5) {
    if (error != nullptr) *error = "connection closed";
    return false;
  }
  const u16 len = static_cast<u16>((header[3] << 8) | header[4]);
  if (len > kMaxRecord) {
    if (error != nullptr) *error = "record length " + std::to_string(len) + " is implausible";
    return false;
  }
  record->assign(header, header + 5);
  if (len > 0) {
    Bytes body(len, 0);
    std::size_t n = 0;
    if (!io.read(body.data(), len, &n) || n != len) {
      if (error != nullptr) *error = "record body is truncated";
      return false;
    }
    record->insert(record->end(), body.begin(), body.end());
  }
  if (tls_debug_enabled()) {
    // A hand-rolled TLS stack is hard to debug from the outside: with
    // NETCAP_TLS_DEBUG=1 every record is logged with its index, content type,
    // legacy version and length. The role tag says which of the four read loops
    // (server accept, server app, client connect, client app) consumed it --
    // without it a proxy log mixes both sides of the connection together.
    static unsigned long long record_index = 0;
    std::fprintf(stderr, "[tls] %s <- #%llu type=%u version=%04x length=%u\n", g_read_role,
                 ++record_index, static_cast<unsigned>(header[0]),
                 static_cast<unsigned>((header[1] << 8) | header[2]), static_cast<unsigned>(len));
  }
  return true;
}

std::string tls13_cipher_name(u16 suite) {
  const std::string name = tls_cipher_suite_name(suite);
  return name.empty() ? "unknown" : name;
}

std::string tls13_group_name(u16 group) {
  switch (group) {
    case TLS13_GROUP_X25519:
      return "x25519";
    case 0x11ec:
      return "X25519MLKEM768";  // hybrid post-quantum group, sent first by OpenSSL 3.5 and Chrome
    case 0x0017:
      return "secp256r1";
    case 0x0018:
      return "secp384r1";
    case 0x0019:
      return "secp521r1";
    case 0x0100:
      return "ffdhe2048";
    default:
      break;
  }
  char buf[16];
  std::snprintf(buf, sizeof(buf), "0x%04x", group);
  return std::string(buf);
}

std::string tls13_alert_text(u8 description) {
  switch (description) {
    case 0:
      return "close_notify";
    case 10:
      return "unexpected_message";
    case 20:
      return "bad_record_mac";
    case 22:
      return "record_overflow";
    case 40:
      return "handshake_failure";
    case 42:
      return "bad_certificate";
    case 43:
      return "unsupported_certificate";
    case 47:
      return "illegal_parameter";
    case 48:
      return "unknown_ca";
    case 49:
      return "access_denied";
    case 50:
      return "decode_error";
    case 51:
      return "decrypt_error";
    case 70:
      return "protocol_version";
    case 80:
      return "internal_error";
    case 109:
      return "missing_extension";
    case 110:
      return "unsupported_extension";
    case 112:
      return "unrecognized_name";
    case 116:
      return "certificate_required";
    case 120:
      return "no_application_protocol";
    default:
      break;
  }
  return "alert " + std::to_string(description);
}

// ------------------------------------------------------------------ server

namespace {

// Names the groups a client offered, for the failure text: a user reading "the
// client's key share is secp521r1" deserves to see what else that client said it
// could do.
std::string group_list_text(const std::vector<u16>& groups) {
  std::string text;
  for (const u16 group : groups) {
    if (!text.empty()) text += ", ";
    text += tls13_group_name(group);
  }
  return text.empty() ? "(nothing)" : text;
}

// Can this stack finish a handshake with a key share for that group?
bool usable_share(u16 group, const Bytes& share) {
  if (group == TLS13_GROUP_X25519) return share.size() == 32;
  if (group == TLS13_GROUP_SECP256R1) {
    P256Point peer;
    return p256_parse_point(share.data(), share.size(), &peer);
  }
  if (group == TLS13_GROUP_SECP521R1) {
    P521Point peer;
    return p521_parse_point(share.data(), share.size(), &peer);
  }
  return false;
}

}  // namespace

bool Tls13Server::accept(const Tls13Io& io, const X509Cert& cert, const P256Key& key,
                         const std::string& sni_fallback, Tls13ServerInfo* info,
                         std::string* error) {
  g_read_role = "srv-accept";
  transcript_.reset();
  pending_.clear();
  pending_offset_ = 0;
  read_prefix_.clear();
  wrote_ = false;

  // Reads one ClientHello, which may be split over several plaintext records.
  auto read_client_hello = [&](ClientHello* out, Bytes* whole_msg, std::string* err) -> bool {
    Bytes plain;
    while (true) {
      Bytes record;
      if (!tls13_read_record(io, &record, err)) return false;
      const u8 type = record[0];
      if (type == TLS13_ALERT) {
        if (err != nullptr) *err = "the client sent an alert instead of a ClientHello";
        return false;
      }
      if (type != TLS13_HANDSHAKE) {
        // RFC 8446 5.3: a compatibility ChangeCipherSpec normally arrives right
        // after the ClientHello.  When this read is a second one -- the client's
        // answer to a HelloRetryRequest -- that record is already in flight, and
        // it neither says nor changes anything: read past it.
        if (type == 20) continue;
        if (err != nullptr) {
          *err = "expected a handshake record, got content type " +
                 std::to_string(static_cast<int>(type));
        }
        return false;
      }
      plain.insert(plain.end(), record.begin() + 5, record.end());
      // Keep the exact bytes while nothing has been answered yet: if this
      // ClientHello turns out to be one we cannot use, the caller can hand it to
      // the origin unchanged and relay the connection blind.
      if (!wrote_) read_prefix_.insert(read_prefix_.end(), record.begin(), record.end());
      if (plain.size() >= 4) {
        const u32 body_len = (static_cast<u32>(plain[1]) << 16) | (static_cast<u32>(plain[2]) << 8) |
                             plain[3];
        if (plain.size() >= 4 + body_len) break;
      }
    }
    std::size_t off = 0;
    u8 msg_type = 0;
    if (!tls13_next_handshake(plain, &off, &msg_type, whole_msg) || msg_type != kHandshakeClientHello) {
      if (err != nullptr) *err = "the first handshake message is not a ClientHello";
      return false;
    }
    const Bytes ch_body(whole_msg->begin() + 4, whole_msg->end());
    return parse_client_hello(ch_body, out, err);
  };

  ClientHello hello;
  Bytes ch_msg;
  if (!read_client_hello(&hello, &ch_msg, error)) return false;
  if (!hello.tls13) {
    if (error != nullptr) *error = "the client did not offer TLS 1.3";
    return false;
  }
  // Our own order: ChaCha20-Poly1305 first (no AES-NI in this build), then
  // AES-128-GCM.  Every current TLS 1.3 client offers at least one of them.
  u16 chosen_suite = 0;
  for (const u16 want : {TLS13_CHACHA20_POLY1305, TLS13_AES_128_GCM_SHA256}) {
    for (std::size_t i = 0; i < hello.cipher_count; ++i) {
      if (hello.cipher_suites[i] == want) chosen_suite = want;
    }
    if (chosen_suite != 0) break;
  }
  if (chosen_suite == 0) {
    if (error != nullptr) {
      *error = "the client offers neither TLS_CHACHA20_POLY1305 nor TLS_AES_128_GCM_SHA256";
    }
    return false;
  }
  secrets_.suite = chosen_suite;
  if (!hello.offers_ecdsa_p256) {
    if (error != nullptr) *error = "the client does not offer ecdsa_secp256r1_sha256";
    return false;
  }

  // The client's key share decides the group.  x25519 first (every current
  // client sends one), then secp256r1 -- the P-256 code that signs the leaf also
  // does ECDH, so the second curve is nearly free -- and finally secp521r1, which
  // has its own small implementation in p521.cpp for clients that offer nothing
  // else.  A share we cannot use, for a
  // group the client does list in supported_groups, gets a HelloRetryRequest:
  // that is also what keeps this proxy working with clients (OpenSSL 3.5,
  // Chrome) that put a post-quantum hybrid share first and no x25519 share at all.
  const u16 offered_group = hello.key_share_group;
  u16 group = usable_share(offered_group, hello.key_share) ? offered_group : 0;
  if (group == 0) {
    u16 ask = 0;
    if (hello.offers_x25519) {
      ask = TLS13_GROUP_X25519;
    } else if (hello.offers_secp256r1) {
      ask = TLS13_GROUP_SECP256R1;
    } else if (hello.offers_secp521r1) {
      ask = TLS13_GROUP_SECP521R1;
    }
    if (ask == 0) {
      if (error != nullptr) {
        *error = "the client sent a " + tls13_group_name(offered_group) +
                 " key share, and this proxy can do neither that nor anything else the client "
                 "offers (supported groups: " +
                 group_list_text(hello.supported_groups) + ")";
      }
      return false;
    }
    const Bytes hrr_msg =
        tls13_handshake(kHandshakeServerHello, hello_retry_body(hello.session_id, ask, chosen_suite));
    transcript_.reset();
    transcript_.add(tls13_handshake(kHandshakeMessageHash, sha256(ch_msg.data(), ch_msg.size())));
    transcript_.add(hrr_msg);
    {
      Bytes head{TLS13_HANDSHAKE, 0x03, 0x03};
      put16(head, static_cast<u16>(hrr_msg.size()));
      Bytes out = head;
      out.insert(out.end(), hrr_msg.begin(), hrr_msg.end());
      wrote_ = true;
      if (!io.write(out.data(), out.size())) {
        if (error != nullptr) *error = "could not send the HelloRetryRequest";
        return false;
      }
    }
    if (tls_debug_enabled()) {
      std::fprintf(stderr, "[tls] sent HelloRetryRequest for %s (the client offered %s)\n",
                   tls13_group_name(ask).c_str(), tls13_group_name(offered_group).c_str());
    }
    ClientHello retry_hello;
    Bytes retry_msg;
    if (!read_client_hello(&retry_hello, &retry_msg, error)) return false;
    if (retry_hello.key_share_group != ask || !usable_share(ask, retry_hello.key_share)) {
      if (error != nullptr) {
        *error = "the client ignored the HelloRetryRequest (key share " +
                 tls13_group_name(retry_hello.key_share_group) + ")";
      }
      return false;
    }
    hello = retry_hello;
    ch_msg = retry_msg;
    group = ask;
  }

  // Pick http/1.1 when it is on offer (it always is for a browser talking to
  // this proxy, because we advertise it upstream as well).
  std::string alpn;
  for (const std::string& candidate : hello.alpn) {
    if (candidate == "http/1.1") alpn = "http/1.1";
  }
  if (info != nullptr) {
    info->sni = hello.sni.empty() ? sni_fallback : hello.sni;
    info->alpn = alpn;
    info->cipher_suite = chosen_suite;
    info->group = group;
    info->offered_alpn = hello.alpn;
    info->offered_supported_versions = true;
  }
  if (tls_debug_enabled()) {
    std::fprintf(stderr, "[tls] ClientHello sni='%s' alpn=%zu suite(s)=%zu key_share=%s/%zu ecdsa=%d\n",
                 hello.sni.c_str(), hello.alpn.size(), static_cast<std::size_t>(hello.cipher_count),
                 tls13_group_name(hello.key_share_group).c_str(), hello.key_share.size(),
                 hello.offers_ecdsa_p256 ? 1 : 0);
    for (std::size_t i = 0; i < hello.cipher_count; ++i) {
      std::fprintf(stderr, "[tls]   offered suite %04x %s\n", static_cast<unsigned>(hello.cipher_suites[i]),
                   tls_cipher_suite_name(hello.cipher_suites[i]).c_str());
    }
  }

  Bytes shared;
  Bytes server_share;
  if (group == TLS13_GROUP_X25519) {
    X25519Key ours;
    if (!x25519_keypair(&ours)) {
      if (error != nullptr) *error = "could not generate an ephemeral x25519 key";
      return false;
    }
    if (!x25519(ours.priv, hello.key_share, &shared)) {
      if (error != nullptr) *error = "the client's key share is a low order point";
      return false;
    }
    server_share = ours.pub;
  } else if (group == TLS13_GROUP_SECP256R1) {
    P256Key ours;
    if (!p256_generate(&ours)) {
      if (error != nullptr) *error = "could not generate an ephemeral secp256r1 key";
      return false;
    }
    P256Point peer;
    if (!p256_parse_point(hello.key_share.data(), hello.key_share.size(), &peer)) {
      if (error != nullptr) *error = "the client's secp256r1 key share is not a point";
      return false;
    }
    // RFC 8446 7.4.2: for a NIST curve the ECDHE shared secret is the x
    // coordinate of the shared point, which is what p256_ecdh hands back.
    if (!p256_ecdh(ours, peer, &shared)) {
      if (error != nullptr) *error = "the client's secp256r1 key share is not usable";
      return false;
    }
    server_share = p256_serialize_uncompressed(ours.q);
  } else {
    // secp521r1: the same shape as the P-256 branch, one curve up.  RFC 8446
    // 7.4.2 wants the x coordinate of the shared point for a NIST curve, which is
    // what p521_ecdh hands back.  Reached only when the client offered this group
    // and nothing this server could use first.
    P521Key ours;
    if (!p521_generate(&ours)) {
      if (error != nullptr) *error = "could not generate an ephemeral secp521r1 key";
      return false;
    }
    P521Point peer;
    if (!p521_parse_point(hello.key_share.data(), hello.key_share.size(), &peer)) {
      if (error != nullptr) *error = "the client's secp521r1 key share is not a point";
      return false;
    }
    if (!p521_ecdh(ours, peer, &shared)) {
      if (error != nullptr) *error = "the client's secp521r1 key share is not usable";
      return false;
    }
    server_share = p521_serialize_uncompressed(ours.q);
    if (server_share.size() != 133) {
      if (error != nullptr) *error = "could not serialise the secp521r1 key share";
      return false;
    }
  }

  const Bytes server_random = random_bytes_of(32);
  const Bytes sh_body =
      server_hello_body(server_random, hello.session_id, chosen_suite, server_share, group);
  const Bytes sh_msg = tls13_handshake(kHandshakeServerHello, sh_body);
  transcript_.add(ch_msg);
  transcript_.add(sh_msg);
  if (!tls13_derive_handshake(shared, transcript_.bytes(), &secrets_)) {
    if (error != nullptr) *error = "the key schedule failed";
    return false;
  }
  secrets_.client_random = Bytes{};  // not needed on this side
  secrets_.server_random = server_random;

  // ServerHello in the clear, then a compatibility ChangeCipherSpec.
  Bytes flight;
  flight.insert(flight.end(), sh_msg.begin(), sh_msg.end());
  {
    Bytes head{TLS13_HANDSHAKE, 0x03, 0x03};
    put16(head, static_cast<u16>(flight.size()));
    Bytes out = head;
    out.insert(out.end(), flight.begin(), flight.end());
    wrote_ = true;
    if (!io.write(out.data(), out.size())) {
      if (error != nullptr) *error = "could not send the ServerHello";
      return false;
    }
  }
  if (tls_debug_enabled()) {
    std::fprintf(stderr, "[tls] -> ServerHello %s\n", to_hex(sh_msg).c_str());
  }
  // A compatibility CCS is optional; some middleboxes and one or two clients
  // dislike it, so it can be switched off for debugging.
  static const bool skip_ccs = std::getenv("NETCAP_TLS_NO_CCS") != nullptr;
  if (!skip_ccs) {
    const Bytes ccs{TLS13_CCS, 0x03, 0x03, 0x00, 0x01, 0x01};
    if (!io.write(ccs.data(), ccs.size())) {
      if (error != nullptr) *error = "could not send ChangeCipherSpec";
      return false;
    }
  }

  // The encrypted flight.
  Bytes inner;
  {
    // EncryptedExtensions: ALPN only when the client asked for it.
    Bytes ee_body;
    Bytes ee_exts;
    if (!hello.sni.empty()) {
      // RFC 6066 §3: a server that accepted the SNI name must acknowledge it
      // with an empty ServerNameList.  Schannel treats its absence as a
      // protocol error (SEC_E_ILLEGAL_MESSAGE), OpenSSL does not.
      Bytes ext;
      put16(ext, 0x0000);
      append16(ext, Bytes{});
      ee_exts.insert(ee_exts.end(), ext.begin(), ext.end());
    }
    if (!alpn.empty()) {
      // ProtocolNameList = u16 length + (u8 length + name).  The extension
      // data carries that list length as well: forgetting it makes OpenSSL
      // report "tls_parse_stoc_alpn:bad extension" and schannel abort the
      // handshake with SEC_E_ILLEGAL_MESSAGE.
      Bytes list;
      list.push_back(static_cast<u8>(alpn.size()));
      list.insert(list.end(), alpn.begin(), alpn.end());
      Bytes body_a;
      append16(body_a, list);
      Bytes ext;
      put16(ext, 0x0010);
      append16(ext, body_a);
      ee_exts.insert(ee_exts.end(), ext.begin(), ext.end());
    }
    append16(ee_body, ee_exts);
    const Bytes ee = tls13_handshake(kHandshakeEncryptedExtensions, ee_body);
    transcript_.add(ee);
    inner.insert(inner.end(), ee.begin(), ee.end());
  }
  {
    // Certificate: a single leaf, no per-certificate extensions.
    Bytes list_entry;
    append24(list_entry, cert.der);
    append16(list_entry, Bytes{});
    Bytes cert_body;
    cert_body.push_back(0);  // certificate_request_context
    append24(cert_body, list_entry);
    const Bytes msg = tls13_handshake(kHandshakeCertificate, cert_body);
    transcript_.add(msg);
    inner.insert(inner.end(), msg.begin(), msg.end());
  }
  {
    // CertificateVerify over the transcript so far.
    const Bytes input = certificate_verify_input(true, transcript_.hash());
    const Bytes digest = sha256(input);
    Bytes r;
    Bytes s;
    if (!p256_ecdsa_sign(key.d, digest.data(), &r, &s, &key.q)) {
      if (error != nullptr) *error = "could not sign the CertificateVerify";
      return false;
    }
    // DER encode the signature.
    auto der_int = [](const Bytes& v) {
      Bytes body = v;
      while (body.size() > 1 && body.front() == 0) body.erase(body.begin());
      if ((body[0] & 0x80) != 0) body.insert(body.begin(), 0x00);
      Bytes out;
      out.push_back(0x02);
      out.push_back(static_cast<u8>(body.size()));
      out.insert(out.end(), body.begin(), body.end());
      return out;
    };
    Bytes sig = der_int(r);
    const Bytes sig_s = der_int(s);
    sig.insert(sig.end(), sig_s.begin(), sig_s.end());
    Bytes sig_seq;
    sig_seq.push_back(0x30);
    if (sig.size() < 128) {
      sig_seq.push_back(static_cast<u8>(sig.size()));
    } else {
      sig_seq.push_back(0x81);
      sig_seq.push_back(static_cast<u8>(sig.size()));
    }
    sig_seq.insert(sig_seq.end(), sig.begin(), sig.end());

    Bytes body;
    put16(body, TLS13_SIG_ECDSA_P256_SHA256);
    append16(body, sig_seq);
    const Bytes msg = tls13_handshake(kHandshakeCertificateVerify, body);
    transcript_.add(msg);
    inner.insert(inner.end(), msg.begin(), msg.end());
  }
  {
    const Bytes verify = tls13_finished_data(secrets_.server_handshake.secret, transcript_.bytes());
    const Bytes msg = tls13_handshake(kHandshakeFinished, verify);
    transcript_.add(msg);
    inner.insert(inner.end(), msg.begin(), msg.end());
  }
  // Everything from here on uses the server application keys.
  if (!tls13_derive_application(&secrets_, transcript_.bytes())) {
    if (error != nullptr) *error = "the application key schedule failed";
    return false;
  }
  Bytes encrypted;
  if (!tls13_seal(&secrets_.server_handshake, TLS13_HANDSHAKE, inner, &encrypted)) {
    if (error != nullptr) *error = "could not encrypt the server flight";
    return false;
  }
  if (!io.write(encrypted.data(), encrypted.size())) {
    if (error != nullptr) *error = "could not send the server flight";
    return false;
  }

  // The client's Finished, protected with its handshake keys.
  while (true) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) return false;
    if (tls_debug_enabled()) {
      std::fprintf(stderr, "[tls] accept read type=%u len=%zu\n", unsigned(record[0]), record.size());
    }
    if (record[0] == TLS13_CCS) continue;
    if (record[0] == TLS13_ALERT) {
      if (error != nullptr) *error = "the client sent an alert during the handshake";
      return false;
    }
    u8 inner_type = 0;
    Bytes content;
    if (!tls13_open(&secrets_.client_handshake, record, &inner_type, &content, error)) {
      // Schannel sends its fatal alert with the *application* keys when it
      // rejects something in our flight, so try those before giving up: the
      // alert description is the only useful diagnostic there is.
      std::string first_error = error != nullptr ? *error : std::string();
      if (tls_debug_enabled()) {
        // Which key and which sequence number did the client actually use?
        struct Cand {
          const char* name;
          Tls13Traffic* traffic;
        };
        Cand cands[] = {{"client_hs", &secrets_.client_handshake},
                        {"client_ap", &secrets_.client_application},
                        {"server_hs", &secrets_.server_handshake},
                        {"server_ap", &secrets_.server_application}};
        std::fprintf(stderr, "[tls] undecryptable record (%zu bytes): %s\n", record.size(),
                     to_hex(record).c_str());
        std::fprintf(stderr, "[tls]   my counters: client_hs seq=%llu client_ap seq=%llu\n",
                     static_cast<unsigned long long>(secrets_.client_handshake.seq),
                     static_cast<unsigned long long>(secrets_.client_application.seq));
        for (const Cand& cand : cands) {
          for (u64 guess = 0; guess < 4; ++guess) {
            Tls13Traffic copy = *cand.traffic;
            copy.seq = guess;
            u8 probe_type = 0;
            Bytes probe;
            std::string probe_error;
            if (tls13_open(&copy, record, &probe_type, &probe, &probe_error)) {
              std::fprintf(stderr, "[tls]   decrypts with %s seq=%llu inner=%u plaintext=%s\n",
                           cand.name, static_cast<unsigned long long>(guess),
                           static_cast<unsigned>(probe_type), to_hex(probe).c_str());
            }
          }
        }
      }
      if (!tls13_open(&secrets_.client_application, record, &inner_type, &content, error)) {
        if (error != nullptr) {
          *error = "the client's record could not be decrypted with either the handshake or "
                   "the application keys (" + first_error + ")";
        }
        return false;
      }
    }
    if (inner_type == TLS13_CCS) continue;
    if (inner_type == TLS13_ALERT) {
      std::string what = "the client rejected the handshake";
      if (content.size() >= 2) {
        what += ": ";
        what += tls13_alert_text(content[1]);
        what += " (level " + std::to_string(static_cast<int>(content[0])) + ", description " +
                std::to_string(static_cast<int>(content[1])) + ")";
      }
      if (error != nullptr) *error = what;
      return false;
    }
    if (inner_type != TLS13_HANDSHAKE) {
      if (error != nullptr) *error = "expected the client Finished";
      return false;
    }
    std::size_t off2 = 0;
    u8 t2 = 0;
    Bytes msg;
    while (tls13_next_handshake(content, &off2, &t2, &msg)) {
      if (t2 == kHandshakeFinished) {
        const Bytes expected =
            tls13_finished_data(secrets_.client_handshake.secret, transcript_.bytes());
        const Bytes got(msg.begin() + 4, msg.end());
        if (got != expected) {
          if (error != nullptr) *error = "the client Finished did not verify";
          return false;
        }
        if (info != nullptr) {
          info->client_finished_ok = true;
          info->handshake_bytes = transcript_.size();
        }
      }
    }
    break;
  }
  return true;
}

bool Tls13Server::read_app(const Tls13Io& io, Bytes* out, std::string* error) {
  g_read_role = "srv-app";
  if (closed_) return false;
  out->clear();
  if (pending_offset_ < pending_.size()) {
    out->assign(pending_.begin() + static_cast<std::ptrdiff_t>(pending_offset_), pending_.end());
    pending_offset_ = pending_.size();
    return true;
  }
  while (out->empty()) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) {
      closed_ = true;
      return false;
    }
    if (record[0] == TLS13_CCS) continue;
    if (record[0] == TLS13_ALERT) {
      if (record.size() >= 7 && record[6] == kAlertCloseNotify) {
        closed_ = true;
        if (error != nullptr) *error = "the client closed the connection";
        return false;
      }
      if (error != nullptr) {
        *error = std::string("the client sent an alert");
        if (record.size() >= 7) {
          *error += " (level ";
          *error += std::to_string(record[5]);
          *error += ", ";
          *error += tls13_alert_text(record[6]);
          *error += ")";
        }
      }
      closed_ = true;
      return false;
    }
    u8 inner_type = 0;
    Bytes content;
    if (!tls13_open(&secrets_.client_application, record, &inner_type, &content, error)) {
      closed_ = true;
      return false;
    }
    if (tls_debug_enabled()) {
      std::fprintf(stderr, "[tls] opened inner=%u len=%zu head='%.60s'\n", unsigned(inner_type),
                   content.size(), content.empty() ? "" : reinterpret_cast<const char*>(content.data()));
    }
    if (inner_type == TLS13_ALERT) {
      closed_ = true;
      if (error != nullptr) {
        *error = "the client sent an alert";
        if (content.size() >= 2) {
          *error += " (level ";
          *error += std::to_string(content[0]);
          *error += ", ";
          *error += tls13_alert_text(content[1]);
          *error += ")";
        }
      }
      return false;
    }
    if (inner_type == TLS13_HANDSHAKE || inner_type == TLS13_CCS) continue;  // key update, tickets
    *out = content;
  }
  return true;
}

namespace {

// Application data has to be cut into records of at most 2^14 plaintext bytes:
// a longer record is refused by the reader ("packet length too long" in
// OpenSSL), and a big page is routinely far larger than that.
bool write_application_records(Tls13Traffic* traffic, const Tls13Io& io, const Bytes& data,
                               std::string* error) {
  const std::size_t kMaxPlaintext = 16384;
  if (data.empty()) {
    Bytes record;
    if (!tls13_seal(traffic, TLS13_APPDATA, data, &record)) {
      if (error != nullptr) *error = "could not encrypt application data";
      return false;
    }
    if (!io.write(record.data(), record.size())) {
      if (error != nullptr) *error = "could not send application data";
      return false;
    }
    return true;
  }
  for (std::size_t at = 0; at < data.size(); at += kMaxPlaintext) {
    const std::size_t take = data.size() - at < kMaxPlaintext ? data.size() - at : kMaxPlaintext;
    Bytes record;
    if (!tls13_seal(traffic, TLS13_APPDATA, Bytes(data.begin() + at, data.begin() + at + take),
                    &record)) {
      if (error != nullptr) *error = "could not encrypt application data";
      return false;
    }
    if (!io.write(record.data(), record.size())) {
      if (error != nullptr) *error = "could not send application data";
      return false;
    }
  }
  return true;
}

}  // namespace

bool Tls13Server::write_app(const Tls13Io& io, const Bytes& data, std::string* error) {
  return write_application_records(&secrets_.server_application, io, data, error);
}

bool Tls13Server::send_close_notify(const Tls13Io& io, std::string* error) {
  Bytes record;
  const Bytes alert{1, kAlertCloseNotify};  // warning level, close_notify
  if (!tls13_seal(&secrets_.server_application, TLS13_ALERT, alert, &record)) {
    if (error != nullptr) *error = "could not encrypt the alert";
    return false;
  }
  io.write(record.data(), record.size());
  (void)error;
  return true;
}

// ------------------------------------------------------------------ client

void Tls13Client::resume(const Tls13Secrets& secrets) {
  secrets_ = secrets;
  transcript_.reset();
  pending_.clear();
  closed_ = false;
}

bool Tls13Client::connect(const Tls13Io& io, const std::string& host, const std::string& alpn,
                          bool allow_unverified, Tls13ClientInfo* info, std::string* error) {
  g_read_role = "cli-connect";
  transcript_.reset();
  pending_.clear();
  if (info != nullptr) info->host = host;

  const Bytes client_random = random_bytes_of(32);
  const Bytes session_id = random_bytes_of(32);
  X25519Key ours;
  if (!x25519_keypair(&ours)) {
    if (error != nullptr) *error = "could not generate an ephemeral x25519 key";
    return false;
  }
  {
    Bytes body;
    put16(body, kLegacyVersion);
    body.insert(body.end(), client_random.begin(), client_random.end());
    body.push_back(static_cast<u8>(session_id.size()));
    body.insert(body.end(), session_id.begin(), session_id.end());
    Bytes suites;
    put16(suites, TLS13_CHACHA20_POLY1305);
    put16(suites, TLS13_AES_128_GCM_SHA256);
    append16(body, suites);
    body.push_back(1);
    body.push_back(0);  // null compression
    Bytes exts;
    {
      // server_name: ServerNameList = u16 length + (name_type, host_name<u16>)
      Bytes entry;
      entry.push_back(0);
      append16(entry, Bytes(host.begin(), host.end()));
      Bytes body_sni;
      append16(body_sni, entry);
      Bytes ext;
      put16(ext, 0x0000);
      append16(ext, body_sni);
      exts.insert(exts.end(), ext.begin(), ext.end());
    }
    {
      // supported_versions: a one byte length followed by the offered versions.
      Bytes versions;
      put16(versions, kTls13Version);
      Bytes body_v;
      body_v.push_back(static_cast<u8>(versions.size()));
      body_v.insert(body_v.end(), versions.begin(), versions.end());
      Bytes ext;
      put16(ext, 0x002b);
      append16(ext, body_v);
      exts.insert(exts.end(), ext.begin(), ext.end());
    }
    {
      Bytes groups;
      put16(groups, TLS13_GROUP_X25519);
      Bytes body_g;
      append16(body_g, groups);
      Bytes ext;
      put16(ext, 0x000a);
      append16(ext, body_g);
      exts.insert(exts.end(), ext.begin(), ext.end());
    }
    {
      Bytes entry;
      put16(entry, TLS13_GROUP_X25519);
      append16(entry, ours.pub);
      Bytes body_k;
      append16(body_k, entry);
      Bytes ext;
      put16(ext, 0x0033);
      append16(ext, body_k);
      exts.insert(exts.end(), ext.begin(), ext.end());
    }
    {
      Bytes algs;
      put16(algs, TLS13_SIG_ECDSA_P256_SHA256);
      // Most origins hold an RSA certificate, so the scheme has to be offered or
      // the handshake ends in handshake_failure before a single byte is fetched.
      put16(algs, TLS13_SIG_RSA_PSS_RSAE_SHA256);
      Bytes body_s;
      append16(body_s, algs);
      Bytes ext;
      put16(ext, 0x000d);
      append16(ext, body_s);
      exts.insert(exts.end(), ext.begin(), ext.end());
    }
    if (!alpn.empty()) {
      Bytes list;
      list.push_back(static_cast<u8>(alpn.size()));
      list.insert(list.end(), alpn.begin(), alpn.end());
      Bytes body_a;
      append16(body_a, list);
      Bytes ext;
      put16(ext, 0x0010);
      append16(ext, body_a);
      exts.insert(exts.end(), ext.begin(), ext.end());
    }
    append16(body, exts);
    const Bytes msg = tls13_handshake(kHandshakeClientHello, body);
    transcript_.add(msg);
    Bytes record{TLS13_HANDSHAKE, 0x03, 0x03};
    put16(record, static_cast<u16>(msg.size()));
    record.insert(record.end(), msg.begin(), msg.end());
    if (!io.write(record.data(), record.size())) {
      if (error != nullptr) *error = "could not send the ClientHello";
      return false;
    }
  }

  // ServerHello (plaintext, possibly after a CCS).
  Bytes sh_body;
  while (true) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) return false;
    if (record[0] == TLS13_CCS) continue;
    if (record[0] == TLS13_ALERT) {
      if (error != nullptr) *error = "the server refused the handshake (" +
                                     tls13_alert_text(record.size() >= 7 ? record[6] : 0) + ")";
      return false;
    }
    if (record[0] != TLS13_HANDSHAKE) {
      if (error != nullptr) *error = "expected a ServerHello";
      return false;
    }
    Bytes plain(record.begin() + 5, record.end());
    std::size_t off = 0;
    u8 type = 0;
    Bytes msg;
    if (!tls13_next_handshake(plain, &off, &type, &msg) || type != kHandshakeServerHello) {
      if (error != nullptr) *error = "the server did not start with a ServerHello";
      return false;
    }
    transcript_.add(msg);
    sh_body.assign(msg.begin() + 4, msg.end());
    break;
  }
  Bytes echoed_sid;
  Bytes server_random;
  u16 suite = 0;
  u16 group = 0;
  Bytes server_key_share;
  bool is13 = false;
  if (!parse_server_hello(sh_body, &server_random, &echoed_sid, &suite, &group, &server_key_share,
                          &is13, error)) {
    return false;
  }
  if (!is13) {
    if (error != nullptr) *error = "the server did not negotiate TLS 1.3";
    return false;
  }
  if (suite != TLS13_CHACHA20_POLY1305 && suite != TLS13_AES_128_GCM_SHA256) {
    if (error != nullptr) *error = "the server chose " + tls13_cipher_name(suite) +
                                   ", and this engine speaks TLS_CHACHA20_POLY1305 and "
                                   "TLS_AES_128_GCM_SHA256";
    return false;
  }
  secrets_.suite = suite;
  if (group != TLS13_GROUP_X25519 || server_key_share.size() != 32) {
    if (error != nullptr) *error = "the server's key share is " + tls13_group_name(group);
    return false;
  }
  if (echoed_sid != session_id) {
    if (error != nullptr) *error = "the server echoed a different session id";
    return false;
  }
  Bytes shared;
  if (!x25519(ours.priv, server_key_share, &shared)) {
    if (error != nullptr) *error = "the server's key share is a low order point";
    return false;
  }
  if (!tls13_derive_handshake(shared, transcript_.bytes(), &secrets_)) {
    if (error != nullptr) *error = "the key schedule failed";
    return false;
  }
  secrets_.client_random = client_random;
  secrets_.server_random = server_random;

  // The encrypted server flight. Handshake messages can straddle records, so
  // the stream keeps whatever is left over and only complete messages are
  // consumed from the front.
  Bytes handshake_stream;
  std::size_t stream_off = 0;
  bool got_finished = false;
  X509Cert server_cert;
  bool have_cert = false;
  bool cert_ok = false;
  std::string verify_warning;
  while (!got_finished) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) return false;
    if (record[0] == TLS13_CCS) continue;
    if (record[0] == TLS13_ALERT) {
      if (error != nullptr) *error = "the server sent an alert";
      return false;
    }
    u8 inner_type = 0;
    Bytes content;
    if (!tls13_open(&secrets_.server_handshake, record, &inner_type, &content, error)) return false;
    if (inner_type == TLS13_CCS) continue;
    if (inner_type == TLS13_ALERT) {
      if (error != nullptr) {
        *error = "the server sent " + tls13_alert_text(content.size() >= 2 ? content[1] : 0);
      }
      return false;
    }
    if (inner_type != TLS13_HANDSHAKE) {
      if (error != nullptr) *error = "unexpected content type during the handshake";
      return false;
    }
    handshake_stream.insert(handshake_stream.end(), content.begin(), content.end());

    std::size_t off = stream_off;
    u8 type = 0;
    Bytes msg;
    while (tls13_next_handshake(handshake_stream, &off, &type, &msg)) {
      if (type == kHandshakeEncryptedExtensions) {
        transcript_.add(msg);
        // The server echoes the ALPN it picked in EncryptedExtensions. Keep it
        // so a report can say what the proxy and the origin agreed on.
        const Bytes body(msg.begin() + 4, msg.end());
        if (info != nullptr && body.size() >= 2) {
          const std::size_t listed = rd16be(body.data());
          std::size_t o2 = 2;
          std::size_t end = o2 + listed;
          if (end > body.size()) end = body.size();
          while (o2 + 4 <= end) {
            const u16 ext_type = rd16be(body.data() + o2);
            const u16 ext_len = rd16be(body.data() + o2 + 2);
            o2 += 4;
            if (o2 + ext_len > end) break;
            if (ext_type == 0x0010 && ext_len >= 3) {
              const std::size_t name_len = body[o2 + 2];
              if (3 + name_len <= ext_len) {
                info->alpn.assign(reinterpret_cast<const char*>(body.data() + o2 + 3), name_len);
              }
            }
            o2 += ext_len;
          }
        }
      } else if (type == kHandshakeCertificate) {
        transcript_.add(msg);
        const Bytes body(msg.begin() + 4, msg.end());
        std::size_t o = 1;  // certificate_request_context
        if (!body.empty()) o = 1 + body[0];
        u32 list_len = 0;
        if (read24(body.data(), body.size(), &o, &list_len) && o + 3 <= body.size()) {
          u32 cert_len = 0;
          if (read24(body.data(), body.size(), &o, &cert_len) && o + cert_len <= body.size()) {
            const Bytes der(body.begin() + static_cast<std::ptrdiff_t>(o),
                            body.begin() + static_cast<std::ptrdiff_t>(o + cert_len));
            std::string cerr;
            if (x509_parse(der, &server_cert, &cerr)) {
              have_cert = true;
            } else {
              verify_warning = "the server certificate could not be parsed: " + cerr;
            }
          }
        }
      } else if (type == kHandshakeCertificateVerify) {
        transcript_.add(msg);
        const Bytes body(msg.begin() + 4, msg.end());
        std::size_t o = 0;
        u16 sig_scheme = 0;
        Bytes sig;
        if (read16(body.data(), body.size(), &o, &sig_scheme) && o + 2 <= body.size()) {
          u16 sig_len = 0;
          read16(body.data(), body.size(), &o, &sig_len);
          if (o + sig_len <= body.size()) sig.assign(body.begin() + static_cast<std::ptrdiff_t>(o),
                                                     body.begin() + static_cast<std::ptrdiff_t>(o + sig_len));
        }
        if (!have_cert) {
          verify_warning = "the server sent no usable certificate";
        } else if (sig_scheme != TLS13_SIG_ECDSA_P256_SHA256 &&
                   sig_scheme != TLS13_SIG_RSA_PSS_RSAE_SHA256) {
          verify_warning = "the certificate signature uses " + tls13_group_name(sig_scheme) +
                           ", which this client cannot check";
        } else {
          Bytes r;
          Bytes s;
          // The signature covers the transcript only through Certificate.
          Bytes through_cert;
          {
            // Rebuild: everything except the CertificateVerify we just added.
            const std::size_t cut = transcript_.bytes().size() - msg.size();
            through_cert.assign(transcript_.bytes().begin(),
                                transcript_.bytes().begin() + static_cast<std::ptrdiff_t>(cut));
          }
          const Bytes input = certificate_verify_input(true, sha256(through_cert));
          const Bytes digest = sha256(input);
          bool ok = false;
          bool malformed = false;
          if (sig_scheme == TLS13_SIG_RSA_PSS_RSAE_SHA256) {
            // RSA-PSS over SHA-256 with a 32 byte salt, checked by the platform
            // verifier (the P-256 engine here has no RSA).
            ok = server_cert.has_rsa && !sig.empty() &&
                 rsa_verify_sha256(server_cert.rsa_modulus, server_cert.rsa_exponent,
                                   digest.data(), sig, true, 32);
          } else if (!parse_ecdsa_signature(sig, &r, &s)) {
            malformed = true;
          } else {
            ok = server_cert.has_spki && p256_ecdsa_verify(server_cert.public_key, digest.data(), r, s);
          }
          if (malformed) {
            verify_warning = "the CertificateVerify signature is malformed";
          } else {
            cert_ok = ok;
            if (!ok) verify_warning = "the CertificateVerify signature did not verify";
          }
        }
        // Host name and validity are checked whether or not the signature was.
        if (have_cert) {
          const bool host_ok = x509_matches_host(server_cert, host);
          const std::string now = now_key();
          const bool dates_ok = date_key(server_cert.not_before) <= now &&
                               now <= date_key(server_cert.not_after);
          if (info != nullptr) {
            info->certificate_seen = true;
            info->certificate_signature_verified = cert_ok;
            info->certificate_host_matched = host_ok;
            info->certificate_dates_ok = dates_ok;
            info->certificate_subject = server_cert.subject_cn;
            info->certificate_issuer = server_cert.issuer_cn;
          }
          if (!host_ok) verify_warning = "the certificate does not cover " + host;
          else if (!dates_ok) verify_warning = "the certificate is outside its validity window";
        }
      } else if (type == kHandshakeFinished) {
        const Bytes got(msg.begin() + 4, msg.end());
        // The Finished covers the transcript without itself.
        const std::size_t cut = transcript_.bytes().size();
        const Bytes expected =
            tls13_finished_data(secrets_.server_handshake.secret, transcript_.bytes());
        if (got != expected) {
          if (error != nullptr) *error = "the server Finished did not verify";
          return false;
        }
        (void)cut;
        transcript_.add(msg);
        got_finished = true;
        if (info != nullptr) info->server_finished_ok = true;
      } else if (type == kHandshakeNewSessionTicket) {
        transcript_.add(msg);
      } else {
        transcript_.add(msg);
      }
    }
    // Drop what has been consumed so the next record continues where this one
    // stopped instead of replaying the whole stream.
    stream_off = off;
    if (stream_off > 0) {
      handshake_stream.erase(handshake_stream.begin(),
                             handshake_stream.begin() + static_cast<std::ptrdiff_t>(stream_off));
      stream_off = 0;
    }
  }
  if (!tls13_derive_application(&secrets_, transcript_.bytes())) {
    if (error != nullptr) *error = "the application key schedule failed";
    return false;
  }
  if (!verify_warning.empty() && !allow_unverified) {
    if (error != nullptr) *error = verify_warning;
    if (info != nullptr) info->warning = verify_warning;
    return false;
  }
  if (info != nullptr) {
    info->warning = verify_warning;
    info->cipher_suite = suite;
    info->group = group;
  }

  // Our own Finished, then switch to application keys.
  {
    const Bytes verify = tls13_finished_data(secrets_.client_handshake.secret, transcript_.bytes());
    const Bytes msg = tls13_handshake(kHandshakeFinished, verify);
    transcript_.add(msg);
    Bytes record;
    if (!tls13_seal(&secrets_.client_handshake, TLS13_HANDSHAKE, msg, &record)) {
      if (error != nullptr) *error = "could not encrypt the client Finished";
      return false;
    }
    if (!io.write(record.data(), record.size())) {
      if (error != nullptr) *error = "could not send the client Finished";
      return false;
    }
  }
  return true;
}

bool Tls13Client::read_app(const Tls13Io& io, Bytes* out, std::string* error) {
  g_read_role = "cli-app";
  if (closed_) return false;
  out->clear();
  if (!pending_.empty()) {
    *out = pending_;
    pending_.clear();
    return true;
  }
  while (out->empty()) {
    Bytes record;
    if (!tls13_read_record(io, &record, error)) {
      closed_ = true;
      return false;
    }
    if (record[0] == TLS13_CCS) continue;
    if (record[0] == TLS13_ALERT) {
      closed_ = true;
      if (error != nullptr) *error = "the server sent an alert";
      return false;
    }
    u8 inner_type = 0;
    Bytes content;
    if (!tls13_open(&secrets_.server_application, record, &inner_type, &content, error)) {
      closed_ = true;
      return false;
    }
    if (inner_type == TLS13_ALERT) {
      if (content.size() >= 2 && content[1] == kAlertCloseNotify) {
        closed_ = true;
        if (error != nullptr) *error = "the server closed the connection";
        return false;
      }
      closed_ = true;
      if (error != nullptr) *error = "the server sent " + tls13_alert_text(content.size() >= 2 ? content[1] : 0);
      return false;
    }
    if (inner_type == TLS13_HANDSHAKE || inner_type == TLS13_CCS) continue;
    *out = content;
  }
  return true;
}

bool Tls13Client::write_app(const Tls13Io& io, const Bytes& data, std::string* error) {
  return write_application_records(&secrets_.client_application, io, data, error);
}

bool Tls13Client::send_close_notify(const Tls13Io& io, std::string* error) {
  Bytes record;
  const Bytes alert{1, kAlertCloseNotify};
  if (!tls13_seal(&secrets_.client_application, TLS13_ALERT, alert, &record)) {
    if (error != nullptr) *error = "could not encrypt the alert";
    return false;
  }
  io.write(record.data(), record.size());
  return true;
}

}  // namespace netcap
