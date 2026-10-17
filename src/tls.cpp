// TLS record layer, handshake parsing and keylog-driven decryption.
#include "netcap/tls.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace netcap {
namespace {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

bool looks_like_record(u8 type, u16 version) {
  if (type < TLS_CCS || type > TLS_HEARTBEAT) return false;
  if ((version & 0xff00) != 0x0300) return false;
  const u16 minor = version & 0x00ff;
  return minor <= 4;
}

Bytes aad_with_seq(u64 seq, u8 type, u16 version, std::size_t length) {
  Bytes aad(13, 0);
  for (int i = 0; i < 8; ++i) aad[std::size_t(i)] = u8((seq >> (8 * (7 - i))) & 0xff);
  aad[8] = type;
  wr16be(aad.data() + 9, version);
  wr16be(aad.data() + 11, u16(length));
  return aad;
}

void xor_seq_into(Bytes* nonce, u64 seq) {
  if (nonce->size() < 8) return;
  const std::size_t off = nonce->size() - 8;
  for (int i = 0; i < 8; ++i) {
    (*nonce)[off + std::size_t(i)] ^= u8((seq >> (8 * (7 - i))) & 0xff);
  }
}

// Opens one AEAD record: the tag is the last 16 bytes of `ct`.
bool open_aead(const TlsCipherSuite& suite, const Bytes& key, const Bytes& nonce, const Bytes& aad,
               const u8* ct, std::size_t ct_len, Bytes* out) {
  if (ct_len < 16) return false;
  const Bytes ciphertext(ct, ct + (ct_len - 16));
  const Bytes tag(ct + (ct_len - 16), ct + ct_len);
  if (suite.mode == TlsCipherSuite::Mode::AesGcm) {
    return aes_gcm_decrypt(key, nonce, aad, ciphertext, tag, out);
  }
  if (suite.mode == TlsCipherSuite::Mode::Chacha20Poly1305) {
    return chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag, out);
  }
  return false;
}

bool constant_time_eq(const u8* a, const u8* b, std::size_t n) {
  u8 diff = 0;
  for (std::size_t i = 0; i < n; ++i) diff = u8(diff | (a[i] ^ b[i]));
  return diff == 0;
}

// Reads a vector of u16 values with a 2 byte length prefix.
std::vector<u16> read_u16_vector(const u8* p, std::size_t len) {
  std::vector<u16> out;
  for (std::size_t i = 0; i + 1 < len; i += 2) out.push_back(rd16be(p + i));
  return out;
}

const char* alert_level_name(u8 level) { return level == 1 ? "warning" : (level == 2 ? "fatal" : "?"); }

const char* alert_desc_name(u8 desc) {
  switch (desc) {
    case 0: return "close_notify";
    case 10: return "unexpected_message";
    case 20: return "bad_record_mac";
    case 21: return "decryption_failed";
    case 22: return "record_overflow";
    case 40: return "handshake_failure";
    case 42: return "bad_certificate";
    case 43: return "unsupported_certificate";
    case 46: return "certificate_unknown";
    case 47: return "illegal_parameter";
    case 48: return "unknown_ca";
    case 49: return "access_denied";
    case 50: return "decode_error";
    case 51: return "decrypt_error";
    case 70: return "protocol_version";
    case 71: return "insufficient_security";
    case 80: return "internal_error";
    case 86: return "inappropriate_fallback";
    case 90: return "user_canceled";
    case 100: return "no_renegotiation";
    case 109: return "missing_extension";
    case 110: return "unsupported_extension";
    case 112: return "unrecognized_name";
    case 113: return "bad_certificate_status_response";
    case 116: return "certificate_required";
    case 120: return "no_application_protocol";
    default: return "alert";
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

const char* tls_content_type_name(u8 type) {
  switch (type) {
    case TLS_CCS: return "ChangeCipherSpec";
    case TLS_ALERT: return "Alert";
    case TLS_HANDSHAKE: return "Handshake";
    case TLS_APPDATA: return "ApplicationData";
    case TLS_HEARTBEAT: return "Heartbeat";
    default: return "Unknown";
  }
}

const char* tls_handshake_type_name(u8 type) {
  switch (type) {
    case 0: return "hello_request";
    case 1: return "ClientHello";
    case 2: return "ServerHello";
    case 4: return "NewSessionTicket";
    case 5: return "EndOfEarlyData";
    case 8: return "EncryptedExtensions";
    case 11: return "Certificate";
    case 12: return "ServerKeyExchange";
    case 13: return "CertificateRequest";
    case 14: return "ServerHelloDone";
    case 15: return "CertificateVerify";
    case 16: return "ClientKeyExchange";
    case 20: return "Finished";
    case 24: return "KeyUpdate";
    case 254: return "message_hash";
    default: return "handshake";
  }
}

// ---------------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------------

namespace {
const TlsCipherSuite kSuites[] = {
    {0x1301, "TLS_AES_128_GCM_SHA256", TlsCipherSuite::Mode::AesGcm, 16, 0, 12, false, true},
    {0x1302, "TLS_AES_256_GCM_SHA384", TlsCipherSuite::Mode::AesGcm, 32, 0, 12, true, true},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256", TlsCipherSuite::Mode::Chacha20Poly1305, 32, 0, 12,
     false, true},
    {0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", TlsCipherSuite::Mode::AesGcm, 16, 0, 4, false,
     false},
    {0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", TlsCipherSuite::Mode::AesGcm, 32, 0, 4, true,
     false},
    {0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", TlsCipherSuite::Mode::AesGcm, 16, 0, 4, false,
     false},
    {0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TlsCipherSuite::Mode::AesGcm, 32, 0, 4, true,
     false},
    {0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256", TlsCipherSuite::Mode::AesGcm, 16, 0, 4, false, false},
    {0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384", TlsCipherSuite::Mode::AesGcm, 32, 0, 4, true, false},
    {0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
     TlsCipherSuite::Mode::Chacha20Poly1305, 32, 0, 12, false, false},
    {0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
     TlsCipherSuite::Mode::Chacha20Poly1305, 32, 0, 12, false, false},
    {0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", TlsCipherSuite::Mode::AesCbc, 16, 32, 16,
     false, false},
    {0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", TlsCipherSuite::Mode::AesCbc, 32, 48, 16,
     true, false},
    {0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", TlsCipherSuite::Mode::AesCbc, 16, 32, 16,
     false, false},
    {0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", TlsCipherSuite::Mode::AesCbc, 32, 48, 16, true,
     false},
};
}  // namespace

const TlsCipherSuite* tls_cipher_suite(u16 id) {
  for (const TlsCipherSuite& s : kSuites) {
    if (s.id == id) return &s;
  }
  return nullptr;
}

std::string tls_cipher_suite_name(u16 id) {
  if (const TlsCipherSuite* s = tls_cipher_suite(id)) return s->name;
  // Well known but unimplemented suites still deserve a name in the output.
  switch (id) {
    case 0x0000: return "TLS_NULL_WITH_NULL_NULL";
    case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0xc009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
    case 0xc00a: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
    case 0xc013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    case 0xc014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
    case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
    case 0x5600: return "TLS_FALLBACK_SCSV";
    default: break;
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%04x", unsigned(id));
  return buf;
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

std::size_t tls_parse_record_header(const u8* data, std::size_t len, TlsRecordHeader* out) {
  if (len < 5) return 0;
  // Only the first five bytes are read here, so the record signature has to be
  // validated: without this gate a plaintext HTTP request line or an SSH banner
  // would be accepted as a record header and the stream would be misclassified.
  if (!looks_like_record(data[0], rd16be(data + 1))) return 0;
  out->type = data[0];
  out->version = rd16be(data + 1);
  out->length = rd16be(data + 3);
  return 5;
}

// ---------------------------------------------------------------------------
// Handshake parsing
// ---------------------------------------------------------------------------

bool tls_parse_client_hello(const u8* b, std::size_t n, TlsClientHelloInfo* out, std::string* error) {
  auto fail = [&](const char* what) {
    if (error) *error = what;
    return false;
  };
  if (n < 2 + 32 + 1) return fail("ClientHello is too short");
  out->legacy_version = rd16be(b);
  out->random.assign(b + 2, b + 34);
  std::size_t p = 34;
  const std::size_t sid = b[p++];
  if (p + sid > n) return fail("ClientHello session id runs past the end");
  out->session_id.assign(b + p, b + p + sid);
  p += sid;
  if (p + 2 > n) return fail("ClientHello has no cipher suite list");
  const std::size_t cs = rd16be(b + p);
  p += 2;
  if (p + cs > n) return fail("ClientHello cipher suite list runs past the end");
  out->cipher_suites = read_u16_vector(b + p, cs);
  p += cs;
  if (p + 1 > n) return fail("ClientHello has no compression list");
  const std::size_t comp = b[p++];
  if (p + comp > n) return fail("ClientHello compression list runs past the end");
  p += comp;
  if (p == n) return true;  // no extensions at all
  if (p + 2 > n) return fail("ClientHello extensions length is truncated");
  std::size_t ext_len = rd16be(b + p);
  p += 2;
  if (p + ext_len > n) ext_len = n - p;  // be lenient, some stacks pad oddly
  const std::size_t ext_end = p + ext_len;

  while (p + 4 <= ext_end) {
    const u16 type = rd16be(b + p);
    const std::size_t elen = rd16be(b + p + 2);
    p += 4;
    if (p + elen > ext_end) break;
    const u8* e = b + p;
    switch (type) {
      case 0x0000: {  // server_name
        if (elen >= 2) {
          const std::size_t list_len = rd16be(e);
          std::size_t q = 2;
          const std::size_t stop = std::min(elen, 2 + list_len);
          while (q + 3 <= stop) {
            const u8 name_type = e[q];
            const std::size_t name_len = rd16be(e + q + 1);
            q += 3;
            if (q + name_len > stop) break;
            if (name_type == 0) {
              std::string name(reinterpret_cast<const char*>(e + q), name_len);
              out->sni = to_lower(name);
            }
            q += name_len;
          }
        }
        break;
      }
      case 0x0010: {  // ALPN
        if (elen >= 2) {
          const std::size_t list_len = rd16be(e);
          std::size_t q = 2;
          const std::size_t stop = std::min(elen, 2 + list_len);
          while (q + 1 <= stop) {
            const std::size_t l = e[q++];
            if (q + l > stop) break;
            out->alpn.emplace_back(reinterpret_cast<const char*>(e + q), l);
            q += l;
          }
        }
        break;
      }
      case 0x000a:  // supported_groups
        if (elen >= 2) out->supported_groups = read_u16_vector(e + 2, std::min(elen - 2, std::size_t(rd16be(e))));
        break;
      case 0x000d:  // signature_algorithms
        if (elen >= 2) {
          out->signature_algorithms =
              read_u16_vector(e + 2, std::min(elen - 2, std::size_t(rd16be(e))));
        }
        break;
      case 0x002b:  // supported_versions (client: 1 byte length then the list)
        if (elen >= 1) {
          out->has_supported_versions = true;
          const std::size_t l = std::min<std::size_t>(e[0], elen - 1);
          const std::vector<u16> versions = read_u16_vector(e + 1, l);
          if (!versions.empty()) out->supported_version = versions[0];
        }
        break;
      case 0x0033: {  // key_share
        out->has_key_share = true;
        if (elen >= 2) {
          const std::size_t list_len = rd16be(e);
          std::size_t q = 2;
          const std::size_t stop = std::min(elen, 2 + list_len);
          while (q + 4 <= stop) {
            const u16 group = rd16be(e + q);
            const std::size_t kl = rd16be(e + q + 2);
            out->key_share_groups.push_back(group);
            q += 4 + kl;
          }
        }
        break;
      }
      default:
        break;
    }
    p += elen;
  }
  return true;
}

bool tls_parse_server_hello(const u8* b, std::size_t n, TlsServerHelloInfo* out, std::string* error) {
  auto fail = [&](const char* what) {
    if (error) *error = what;
    return false;
  };
  if (n < 2 + 32 + 1 + 2 + 1) return fail("ServerHello is too short");
  out->legacy_version = rd16be(b);
  out->random.assign(b + 2, b + 34);
  std::size_t p = 34;
  const std::size_t sid = b[p++];
  if (p + sid + 3 > n) return fail("ServerHello session id runs past the end");
  out->session_id.assign(b + p, b + p + sid);
  p += sid;
  out->cipher_suite = rd16be(b + p);
  p += 2;
  p += 1;  // compression method
  if (p + 2 > n) {
    out->supported_version = out->legacy_version;
    return true;
  }
  std::size_t ext_len = rd16be(b + p);
  p += 2;
  if (p + ext_len > n) ext_len = n - p;
  const std::size_t ext_end = p + ext_len;
  while (p + 4 <= ext_end) {
    const u16 type = rd16be(b + p);
    const std::size_t elen = rd16be(b + p + 2);
    p += 4;
    if (p + elen > ext_end) break;
    const u8* e = b + p;
    if (type == 0x002b && elen >= 2) {  // supported_versions (server: length + version)
      out->supported_version = rd16be(e + elen - 2);
    } else if (type == 0x0033 && elen >= 4) {  // key_share
      out->has_key_share = true;
      out->key_share_group = rd16be(e);
    } else if (type == 0x0010 && elen >= 2) {  // ALPN
      const std::size_t list_len = rd16be(e);
      std::size_t q = 2;
      const std::size_t stop = std::min(elen, 2 + list_len);
      while (q + 1 <= stop) {
        const std::size_t l = e[q++];
        if (q + l > stop) break;
        out->alpn.emplace_back(reinterpret_cast<const char*>(e + q), l);
        q += l;
      }
    }
    p += elen;
  }
  if (out->supported_version == 0) out->supported_version = out->legacy_version;
  return true;
}

// ---------------------------------------------------------------------------
// Key log
// ---------------------------------------------------------------------------

bool KeyLogStore::load_file(const std::string& path, std::string* error) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    if (error) *error = "cannot open key log file '" + path + "'";
    return false;
  }
  std::string text;
  char chunk[4096];
  std::size_t n = 0;
  while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) text.append(chunk, n);
  std::fclose(f);
  const std::vector<KeyLogEntry> entries = parse_keylog(text);
  if (entries.empty()) {
    if (error) *error = "key log file '" + path + "' contains no usable lines";
    return false;
  }
  for (const KeyLogEntry& e : entries) add(e);
  return true;
}

void KeyLogStore::add(const KeyLogEntry& e) {
  if (e.label.empty() || e.client_random.empty() || e.secret.empty()) return;
  by_random_[to_hex(e.client_random)][e.label] = e.secret;
  ++entries_;
}

void KeyLogStore::clear() {
  by_random_.clear();
  entries_ = 0;
}

const Bytes* KeyLogStore::secret(const std::string& label, const u8* client_random) const {
  if (!client_random) return nullptr;
  const Bytes cr(client_random, client_random + 32);
  auto it = by_random_.find(to_hex(cr));
  if (it == by_random_.end()) return nullptr;
  auto sit = it->second.find(label);
  if (sit == it->second.end()) return nullptr;
  return &sit->second;
}

bool KeyLogStore::knows(const u8* client_random) const {
  if (!client_random) return false;
  const Bytes cr(client_random, client_random + 32);
  return by_random_.count(to_hex(cr)) > 0;
}

std::vector<std::string> KeyLogStore::labels_for(const u8* client_random) const {
  std::vector<std::string> out;
  if (!client_random) return out;
  const Bytes cr(client_random, client_random + 32);
  auto it = by_random_.find(to_hex(cr));
  if (it == by_random_.end()) return out;
  for (const auto& kv : it->second) out.push_back(kv.first);
  return out;
}

std::string KeyLogStore::describe() const {
  return std::to_string(entries_) + " secret(s) for " + std::to_string(by_random_.size()) +
         " client random(s)";
}

// ---------------------------------------------------------------------------
// TlsSession
// ---------------------------------------------------------------------------

TlsSession::TlsSession() = default;

void TlsSession::reset() {
  for (int d = 0; d < 2; ++d) {
    buf_[d].clear();
    buf_ts_[d] = 0;
    hs_buf_[d].clear();
    plaintext_[d].clear();
    app_plaintext_[d].clear();
    hs_keys_[d] = KeyState();
    app_keys_[d] = KeyState();
    active_epoch_[d] = 1;
    ccs_seen_[d] = false;
    tls12_mac_key_[d].clear();
    tls12_enc_key_[d].clear();
    tls12_iv_[d].clear();
    last_cbc_block_[d].clear();
    tls12_seq_[d] = 0;
  }
  records_.clear();
  client_hello_.reset();
  server_hello_.reset();
  stats_ = TlsConnectionStats();
  suite_ = nullptr;
  suite_id_ = 0;
  tls_ = false;
  tls13_ = false;
  master_secret_.clear();
}

void TlsSession::set_client_random(const Bytes& random) {
  if (!client_hello_) client_hello_.reset(new TlsClientHelloInfo());
  client_hello_->random = random;
  stats_.client_hello_seen = true;
}

void TlsSession::set_master_secret(const Bytes& master) {
  master_secret_ = master;
  derive_tls12_keys();
}

void TlsSession::set_traffic_secret(int dir, bool handshake, const Bytes& secret) {
  dir &= 1;
  if (!suite_) learn_cipher(suite_id_ ? suite_id_ : 0x1301);
  const int key_len = suite_ ? suite_->key_len : 16;
  const bool sha384 = suite_ ? suite_->sha384 : false;
  KeyState& ks = handshake ? hs_keys_[dir] : app_keys_[dir];
  ks.key = hkdf_expand_label(secret, "key", Bytes(), std::size_t(key_len), sha384);
  ks.iv = hkdf_expand_label(secret, "iv", Bytes(), 12, sha384);
  ks.ready = !ks.key.empty();
  if (ks.ready) stats_.keys_available = true;
}

void TlsSession::learn_cipher(u16 suite_id) {
  suite_id_ = suite_id;
  suite_ = tls_cipher_suite(suite_id);
  stats_.cipher_known = suite_ != nullptr;
  if (suite_ && suite_->tls13) tls13_ = true;
}

void TlsSession::derive_tls13_keys() {
  if (!client_hello_ || client_hello_->random.size() != 32) return;
  if (!server_hello_) return;
  learn_cipher(server_hello_->cipher_suite);
  if (server_hello_->supported_version >= 0x0304) tls13_ = true;
  if (!suite_ && suite_id_) suite_ = tls_cipher_suite(suite_id_);
  if (!tls13_) return;
  const int key_len = suite_ ? suite_->key_len : 16;
  const bool sha384 = suite_ ? suite_->sha384 : false;
  const u8* cr = client_hello_->random.data();

  struct Item {
    const char* label;
    int dir;
    bool handshake;
  };
  const Item items[] = {
      {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", 0, true},
      {"SERVER_HANDSHAKE_TRAFFIC_SECRET", 1, true},
      {"CLIENT_TRAFFIC_SECRET_0", 0, false},
      {"SERVER_TRAFFIC_SECRET_0", 1, false},
  };
  if (!keylog_) return;
  bool any = false;
  for (const Item& it : items) {
    const Bytes* s = keylog_->secret(it.label, cr);
    if (!s || s->size() < 16) continue;
    KeyState& ks = it.handshake ? hs_keys_[it.dir] : app_keys_[it.dir];
    if (ks.ready) {
      any = true;
      continue;
    }
    ks.key = hkdf_expand_label(*s, "key", Bytes(), std::size_t(key_len), sha384);
    ks.iv = hkdf_expand_label(*s, "iv", Bytes(), 12, sha384);
    ks.ready = ks.key.size() == std::size_t(key_len) && ks.iv.size() == 12;
    if (ks.ready) any = true;
  }
  if (any) stats_.keys_available = true;
  stats_.keylog_entries = keylog_->size();
}

void TlsSession::derive_tls12_keys() {
  if (!client_hello_ || client_hello_->random.size() != 32) return;
  if (!server_hello_ || server_hello_->random.size() != 32) return;
  learn_cipher(server_hello_->cipher_suite);
  if (!suite_ || suite_->tls13) return;
  Bytes master = master_secret_;
  if (master.empty() && keylog_) {
    const Bytes* ms = keylog_->secret("CLIENT_RANDOM", client_hello_->random.data());
    if (ms && ms->size() == 48) master = *ms;
  }
  if (master.size() != 48) return;
  stats_.keylog_entries = keylog_ ? keylog_->size() : 0;

  const std::size_t mac_len = std::size_t(suite_->mac_len);
  const std::size_t key_len = std::size_t(suite_->key_len);
  const std::size_t iv_len = std::size_t(suite_->fixed_iv_len);
  const std::size_t need = 2 * (mac_len + key_len + iv_len);
  Bytes seed = server_hello_->random;
  seed.insert(seed.end(), client_hello_->random.begin(), client_hello_->random.end());
  const Bytes kb = tls12_prf(master, "key expansion", seed, need, suite_->sha384);
  if (kb.size() < need) return;
  std::size_t o = 0;
  auto take = [&](std::size_t n) {
    Bytes r(kb.begin() + std::ptrdiff_t(o), kb.begin() + std::ptrdiff_t(o + n));
    o += n;
    return r;
  };
  tls12_mac_key_[0] = take(mac_len);
  tls12_mac_key_[1] = take(mac_len);
  tls12_enc_key_[0] = take(key_len);
  tls12_enc_key_[1] = take(key_len);
  tls12_iv_[0] = take(iv_len);
  tls12_iv_[1] = take(iv_len);
  stats_.keys_available = true;
}

void TlsSession::handle_handshake_bytes(int dir, const u8* data, std::size_t len, i64 ts_us,
                                        int epoch) {
  (void)epoch;
  if (len == 0) return;
  std::vector<u8>& b = hs_buf_[dir];
  b.insert(b.end(), data, data + len);
  while (b.size() >= 4) {
    const u8 type = b[0];
    const std::size_t mlen = std::size_t(rd24be(b.data() + 1));
    if (mlen > 1u << 20) {  // implausible: drop the buffer rather than grow forever
      b.clear();
      return;
    }
    if (b.size() < 4 + mlen) return;
    const u8* body = b.data() + 4;
    ++stats_.handshake_messages;
    if (type == 1 && dir == 0 && !client_hello_) {
      std::unique_ptr<TlsClientHelloInfo> ch(new TlsClientHelloInfo());
      if (tls_parse_client_hello(body, mlen, ch.get(), nullptr)) {
        client_hello_ = std::move(ch);
        stats_.client_hello_seen = true;
        derive_tls13_keys();
        derive_tls12_keys();
      }
    } else if (type == 2 && dir == 1 && !server_hello_) {
      std::unique_ptr<TlsServerHelloInfo> sh(new TlsServerHelloInfo());
      if (tls_parse_server_hello(body, mlen, sh.get(), nullptr)) {
        server_hello_ = std::move(sh);
        stats_.server_hello_seen = true;
        learn_cipher(server_hello_->cipher_suite);
        if (server_hello_->supported_version >= 0x0304) tls13_ = true;
        derive_tls13_keys();
        derive_tls12_keys();
      }
    }
    (void)ts_us;
    b.erase(b.begin(), b.begin() + std::ptrdiff_t(4 + mlen));
  }
}

void TlsSession::frame_records(int dir) {
  dir &= 1;
  std::vector<u8>& buf = buf_[dir];
  std::size_t pos = 0;
  while (buf.size() - pos >= 5) {
    const u8* p = buf.data() + pos;
    if (!looks_like_record(p[0], rd16be(p + 1))) {
      // Not a TLS record: stop framing this direction for good.
      buf.clear();
      return;
    }
    const std::size_t len = rd16be(p + 3);
    if (len > 16384 + 2048) {
      buf.clear();
      return;
    }
    if (buf.size() - pos - 5 < len) break;  // wait for the rest of the record
    TlsRecordHeader h;
    tls_parse_record_header(p, 5, &h);
    tls_ = true;
    handle_record(dir, h, p + 5, buf_ts_[dir]);
    pos += 5 + len;
  }
  if (pos > 0) buf.erase(buf.begin(), buf.begin() + std::ptrdiff_t(pos));
}

void TlsSession::feed(int dir, const u8* data, std::size_t len, i64 ts_us) {
  dir &= 1;
  if (len == 0) return;
  if (buf_[dir].empty()) buf_ts_[dir] = ts_us;
  buf_[dir].insert(buf_[dir].end(), data, data + len);
  frame_records(dir);
}

void TlsSession::handle_record(int dir, const TlsRecordHeader& h, const u8* payload, i64 ts_us) {
  TlsRecordInfo ri;
  ri.dir = dir;
  ri.type = h.type;
  ri.inner_type = h.type;
  ri.version = h.version;
  ri.length = h.length;
  ri.ts_us = ts_us;
  ++stats_.records;

  // Make sure keys are as fresh as the handshake information allows.
  if (!stats_.keys_available) {
    if (tls13_) {
      derive_tls13_keys();
    } else {
      derive_tls12_keys();
    }
  }

  Bytes inner;
  bool opened = false;

  if (tls13_ && (h.type == TLS_APPDATA || h.type == TLS_HANDSHAKE || h.type == TLS_ALERT)) {
    // TLS 1.3 hides the real content type inside the record. Try the epoch we
    // used last, then the other one: that tracks the handshake to application
    // key switch without having to follow every message.
    //
    // Past the ServerHello every handshake/application/alert record on a 1.3
    // connection is protected, so it counts as encrypted even when we cannot
    // open it: parsing the ciphertext as a cleartext handshake would only
    // invent messages that were never on the wire.
    ri.encrypted = true;
    ++stats_.encrypted_records;
    u8 hdr5[5];
    hdr5[0] = h.type;
    wr16be(hdr5 + 1, h.version);
    wr16be(hdr5 + 3, h.length);
    const Bytes aad(hdr5, hdr5 + 5);
    const int first = active_epoch_[dir] == 2 ? 2 : 1;
    const int order[2] = {first, first == 1 ? 2 : 1};
    bool tried_keys = false;
    for (int idx = 0; idx < 2 && !opened; ++idx) {
      const int epoch = order[idx];
      KeyState& ks = epoch == 1 ? hs_keys_[dir] : app_keys_[dir];
      if (!ks.ready || !suite_) continue;
      tried_keys = true;
      Bytes nonce = ks.iv;
      xor_seq_into(&nonce, ks.seq);
      Bytes cand;
      if (open_aead(*suite_, ks.key, nonce, aad, payload, h.length, &cand)) {
        // Inner plaintext is content || real_type || zeros.
        std::size_t end = cand.size();
        while (end > 0 && cand[end - 1] == 0) --end;
        if (end == 0) continue;  // all padding: not plausible
        ri.inner_type = cand[end - 1];
        inner.assign(cand.begin(), cand.begin() + std::ptrdiff_t(end - 1));
        opened = true;
        ri.epoch = epoch;
        active_epoch_[dir] = epoch;
        ++ks.seq;
        ri.decrypted = true;
        ri.plaintext_len = inner.size();
        ++stats_.decrypted_records;
      }
    }
    if (!opened) {
      // A record we cannot open is a real authentication failure only when a
      // key was actually available to try.
      ri.auth_failed = tried_keys;
      if (tried_keys) ++stats_.auth_failures;
      ++stats_.undecrypted_records;
      ri.note = tried_keys ? "could not decrypt" : "no keys (need --keylog)";
    }
  } else if (!tls13_ && ccs_seen_[dir] && h.type != TLS_CCS && suite_ && stats_.keys_available) {
    ri.encrypted = true;
    ++stats_.encrypted_records;
    const Bytes enc_key = tls12_enc_key_[dir];
    if (suite_->mode == TlsCipherSuite::Mode::AesCbc) {
      if (h.length >= 16 && h.length % 16 == 0 && enc_key.size() == std::size_t(suite_->key_len)) {
        Aes aes;
        if (aes.set_key(enc_key)) {
          Bytes iv = last_cbc_block_[dir].size() == 16 ? last_cbc_block_[dir] : tls12_iv_[dir];
          Bytes plain(h.length);
          aes_cbc_decrypt(aes, iv.data(), payload, h.length, plain.data());
          last_cbc_block_[dir].assign(payload + h.length - 16, payload + h.length);
          const std::size_t pad = plain[h.length - 1];
          if (pad + 1 <= h.length) {
            const std::size_t content_len = h.length - pad - 1;
            const std::size_t mac_len = std::size_t(suite_->mac_len);
            if (content_len >= mac_len) {
              const std::size_t body_len = content_len - mac_len;
              Bytes mac_in = aad_with_seq(tls12_seq_[dir], h.type, h.version, body_len);
              mac_in.insert(mac_in.end(), plain.begin(),
                            plain.begin() + std::ptrdiff_t(body_len));
              const Bytes want = suite_->sha384 ? hmac_sha384(tls12_mac_key_[dir], mac_in)
                                                : hmac_sha256(tls12_mac_key_[dir], mac_in);
              const bool mac_ok = want.size() == mac_len &&
                                  constant_time_eq(want.data(), plain.data() + body_len, mac_len);
              if (mac_ok) {
                inner.assign(plain.begin(), plain.begin() + std::ptrdiff_t(body_len));
                opened = true;
                ri.decrypted = true;
                ri.inner_type = inner.empty() ? h.type : inner[0];
                if (ri.inner_type < TLS_CCS || ri.inner_type > TLS_HEARTBEAT) ri.inner_type = h.type;
                ri.plaintext_len = inner.size();
                ++stats_.decrypted_records;
                ++tls12_seq_[dir];
              } else {
                ++stats_.auth_failures;
                ri.note = "bad record MAC";
              }
            }
          }
        }
      }
      if (!opened) {
        ri.auth_failed = true;
        if (ri.note.empty()) ri.note = "CBC record could not be opened";
      }
    } else {
      // AEAD (GCM or ChaCha20-Poly1305).
      Bytes nonce;
      const u8* ct = payload;
      std::size_t ct_len = h.length;
      std::size_t mac_body_len = h.length;
      if (suite_->mode == TlsCipherSuite::Mode::AesGcm) {
        if (ct_len < 8 + 16) {
          ri.auth_failed = true;
          ri.note = "short AEAD record";
          records_.push_back(ri);
          return;
        }
        nonce = tls12_iv_[dir];
        nonce.insert(nonce.end(), ct, ct + 8);  // explicit nonce
        ct += 8;
        ct_len -= 8;
        mac_body_len = ct_len - 16;
      } else {
        nonce = tls12_iv_[dir];
        xor_seq_into(&nonce, tls12_seq_[dir]);
        mac_body_len = ct_len - 16;
      }
      const Bytes aad = aad_with_seq(tls12_seq_[dir], h.type, h.version, mac_body_len);
      if (open_aead(*suite_, enc_key, nonce, aad, ct, ct_len, &inner)) {
        opened = true;
        ri.decrypted = true;
        ri.inner_type = inner.empty() ? h.type : inner[0];
        if (ri.inner_type < TLS_CCS || ri.inner_type > TLS_HEARTBEAT) ri.inner_type = h.type;
        ri.plaintext_len = inner.size();
        ++stats_.decrypted_records;
        ++tls12_seq_[dir];
      } else {
        ++stats_.auth_failures;
        ri.auth_failed = true;
        ri.note = "AEAD authentication failed";
      }
    }
    if (!opened) ++stats_.undecrypted_records;
  }

  // Plaintext records: handshake messages and alerts are readable as they are.
  if (!ri.encrypted) {
    if (h.type == TLS_HANDSHAKE) {
      handle_handshake_bytes(dir, payload, h.length, ts_us, 0);
      ri.plaintext_len = h.length;
    } else if (h.type == TLS_ALERT && h.length >= 2) {
      ++stats_.alerts;
      ri.note = std::string(alert_level_name(payload[0])) + " " + alert_desc_name(payload[1]);
    } else if (h.type == TLS_APPDATA) {
      ri.note = stats_.keys_available ? "not decrypted" : "no keys (need --keylog)";
      ++stats_.undecrypted_records;
    }
  } else if (opened) {
    stats_.plaintext_bytes += inner.size();
    if (ri.inner_type == TLS_HANDSHAKE) {
      handle_handshake_bytes(dir, inner.data(), inner.size(), ts_us, ri.epoch);
    } else if (ri.inner_type == TLS_APPDATA) {
      stats_.application_bytes += inner.size();
      plaintext_[dir].insert(plaintext_[dir].end(), inner.begin(), inner.end());
      app_plaintext_[dir].insert(app_plaintext_[dir].end(), inner.begin(), inner.end());
    } else if (ri.inner_type == TLS_ALERT && inner.size() >= 2) {
      ++stats_.alerts;
      ri.note = std::string(alert_level_name(inner[0])) + " " + alert_desc_name(inner[1]);
    }
  }

  // A ChangeCipherSpec record switches the following TLS 1.2 records to keys.
  if (h.type == TLS_CCS) {
    ccs_seen_[dir] = true;
    if (!tls13_) derive_tls12_keys();
    ri.note = "switch to encrypted records";
    if (h.length == 1) ri.inner_type = TLS_CCS;
  }

  stats_.keylog_entries = keylog_ ? keylog_->size() : 0;
  records_.push_back(ri);
}

std::string TlsSession::describe() const {
  std::string out;
  if (!is_tls()) return "not TLS";
  const TlsClientHelloInfo* ch = client_hello_.get();
  const TlsServerHelloInfo* sh = server_hello_.get();
  const u16 version = sh && sh->supported_version ? sh->supported_version
                                                  : (ch ? ch->supported_version : 0);
  if (version) out += tls_version_name(version);
  if (suite_id_) {
    out += out.empty() ? "" : " ";
    out += tls_cipher_suite_name(suite_id_);
  }
  if (ch && !ch->sni.empty()) {
    out += out.empty() ? "" : " ";
    out += "sni=" + ch->sni;
  }
  if (sh && !sh->alpn.empty()) {
    out += out.empty() ? "" : " ";
    out += "alpn=" + sh->alpn[0];
  }
  out += std::string(out.empty() ? "" : " ") + std::to_string(stats_.records) + " records, " +
         std::to_string(stats_.decrypted_records) + " decrypted";
  if (stats_.keys_available) {
    out += ", " + std::to_string(stats_.application_bytes) + " app bytes";
  } else {
    out += ", no keys";
  }
  return out;
}

}  // namespace netcap
