// TLS record layer, handshake parsing and keylog-driven decryption.
//
// The decryption path is the same one Wireshark uses: the browser (or any NSS
// style client) writes its session secrets to a file named by SSLKEYLOGFILE,
// and we use those secrets to open the records. No cryptanalysis is involved --
// the keys are handed to us -- but everything that turns a secret into a
// plaintext (HKDF-Expand-Label, the TLS 1.2 key block, AEAD and MAC checking) is
// implemented here on top of netcap/crypto.hpp.
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"

namespace netcap {

// Content types (the outer record type, and the inner type once TLS 1.3 hides
// the real one).
constexpr u8 TLS_CCS = 20;
constexpr u8 TLS_ALERT = 21;
constexpr u8 TLS_HANDSHAKE = 22;
constexpr u8 TLS_APPDATA = 23;
constexpr u8 TLS_HEARTBEAT = 24;

const char* tls_content_type_name(u8 type);
const char* tls_handshake_type_name(u8 type);

// ---------------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------------

struct TlsCipherSuite {
  enum class Mode { Unknown, AesGcm, Chacha20Poly1305, AesCbc };

  u16 id = 0;
  const char* name = "";
  Mode mode = Mode::Unknown;
  int key_len = 0;       // AEAD key or CBC key bytes
  int mac_len = 0;       // HMAC output for CBC suites, 0 for AEAD
  int fixed_iv_len = 0;  // implicit IV: CBC block size, or the GCM/ChaCha salt
  bool sha384 = false;   // PRF / HKDF hash
  bool tls13 = false;
};

// Returns nullptr for suites we do not implement (for example SHA-1 CBC ones).
const TlsCipherSuite* tls_cipher_suite(u16 id);
std::string tls_cipher_suite_name(u16 id);

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

struct TlsRecordHeader {
  u8 type = 0;
  u16 version = 0;
  u16 length = 0;
};

// Parses a 5 byte record header. Returns 5, or 0 when the bytes are not a TLS
// record signature (see looks_like_record) or when more bytes are needed.
std::size_t tls_parse_record_header(const u8* data, std::size_t len, TlsRecordHeader* out);

// ---------------------------------------------------------------------------
// Handshake messages
// ---------------------------------------------------------------------------

struct TlsClientHelloInfo {
  u16 legacy_version = 0;
  u16 supported_version = 0;
  Bytes random;  // 32 bytes, the "client random" the key log is indexed by
  Bytes session_id;
  std::vector<u16> cipher_suites;
  std::string sni;
  std::vector<std::string> alpn;
  std::vector<u16> supported_groups;
  std::vector<u16> signature_algorithms;
  std::vector<u16> key_share_groups;
  bool has_supported_versions = false;
  bool has_key_share = false;
};

struct TlsServerHelloInfo {
  u16 legacy_version = 0;
  u16 supported_version = 0;
  u16 cipher_suite = 0;
  Bytes random;
  Bytes session_id;
  u16 key_share_group = 0;
  bool has_key_share = false;
  std::vector<std::string> alpn;
};

bool tls_parse_client_hello(const u8* body, std::size_t len, TlsClientHelloInfo* out,
                            std::string* error);
bool tls_parse_server_hello(const u8* body, std::size_t len, TlsServerHelloInfo* out,
                            std::string* error);

// ---------------------------------------------------------------------------
// Key log
// ---------------------------------------------------------------------------

class KeyLogStore {
 public:
  bool load_file(const std::string& path, std::string* error);
  void add(const KeyLogEntry& e);
  void clear();

  std::size_t size() const { return entries_; }
  std::size_t client_randoms() const { return by_random_.size(); }
  const Bytes* secret(const std::string& label, const u8* client_random) const;
  bool knows(const u8* client_random) const;
  std::vector<std::string> labels_for(const u8* client_random) const;
  std::string describe() const;

 private:
  std::size_t entries_ = 0;
  std::map<std::string, std::map<std::string, Bytes>> by_random_;  // hex(random) -> label -> secret
};

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

struct TlsRecordInfo {
  int dir = 0;  // 0 = client to server, 1 = server to client
  u8 type = 0;      // outer content type
  u8 inner_type = 0;  // decrypted content type (TLS 1.3 hides it)
  u16 version = 0;
  std::size_t length = 0;         // record payload length on the wire
  std::size_t plaintext_len = 0;  // decrypted payload length
  int epoch = 0;                  // 0 plaintext, 1 handshake keys, 2 application keys
  bool encrypted = false;
  bool decrypted = false;
  bool auth_failed = false;
  i64 ts_us = 0;
  std::string note;
};

struct TlsConnectionStats {
  u64 records = 0;
  u64 encrypted_records = 0;
  u64 decrypted_records = 0;
  u64 auth_failures = 0;
  u64 undecrypted_records = 0;
  u64 alerts = 0;
  u64 handshake_messages = 0;
  u64 application_bytes = 0;
  u64 plaintext_bytes = 0;
  bool keys_available = false;
  bool client_hello_seen = false;
  bool server_hello_seen = false;
  bool cipher_known = false;
  std::size_t keylog_entries = 0;
};

// Reassembles and decrypts one TLS connection. Both directions are fed with the
// bytes recovered by the TCP stream reassembler; the object keeps the record
// framing state, learns the handshake parameters, derives keys from the key log
// and accumulates the decrypted plaintext of each direction.
class TlsSession {
 public:
  TlsSession();

  void set_keylog(std::shared_ptr<KeyLogStore> store) { keylog_ = std::move(store); }
  const std::shared_ptr<KeyLogStore>& keylog() const { return keylog_; }

  void feed(int dir, const u8* data, std::size_t len, i64 ts_us);
  void reset();

  bool is_tls() const { return client_hello_ != nullptr || server_hello_ != nullptr || tls_; }
  bool decrypted_anything() const { return stats_.decrypted_records > 0; }
  bool has_keys() const { return stats_.keys_available; }

  const std::vector<TlsRecordInfo>& records() const { return records_; }
  const std::vector<u8>& plaintext(int dir) const { return plaintext_[dir & 1]; }

  /// The decrypted application data of one direction.  Handshake records (the
  /// TLS 1.3 EncryptedExtensions, Finished, NewSessionTicket) are decrypted into
  /// the same session but left out here, so this is the byte stream an HTTP
  /// parser should be fed.
  const std::vector<u8>& application_plaintext(int dir) const { return app_plaintext_[dir & 1]; }
  const TlsClientHelloInfo* client_hello() const { return client_hello_.get(); }
  const TlsServerHelloInfo* server_hello() const { return server_hello_.get(); }
  const TlsConnectionStats& stats() const { return stats_; }
  std::string describe() const;

  // For callers that already hold the secrets (tests, and a future
  // --keylog-literal option).
  void set_master_secret(const Bytes& master);
  void set_traffic_secret(int dir, bool handshake, const Bytes& secret);
  void set_client_random(const Bytes& random);

 private:
  struct KeyState {
    Bytes key;
    Bytes iv;
    u64 seq = 0;
    bool ready = false;
  };

  void frame_records(int dir);
  void handle_record(int dir, const TlsRecordHeader& h, const u8* payload, i64 ts_us);
  void handle_handshake_bytes(int dir, const u8* data, std::size_t len, i64 ts_us, int epoch);
  void derive_tls13_keys();
  void derive_tls12_keys();
  void learn_cipher(u16 suite_id);

  std::shared_ptr<KeyLogStore> keylog_;
  std::vector<u8> buf_[2];
  i64 buf_ts_[2] = {0, 0};
  std::vector<u8> hs_buf_[2];  // handshake message reassembly per direction
  std::vector<TlsRecordInfo> records_;
  std::vector<u8> plaintext_[2];
  std::vector<u8> app_plaintext_[2];
  std::unique_ptr<TlsClientHelloInfo> client_hello_;
  std::unique_ptr<TlsServerHelloInfo> server_hello_;
  TlsConnectionStats stats_;

  const TlsCipherSuite* suite_ = nullptr;
  u16 suite_id_ = 0;
  bool tls_ = false;
  bool tls13_ = false;
  bool hs_keys_tried_ = false;

  KeyState hs_keys_[2];
  KeyState app_keys_[2];
  int active_epoch_[2] = {1, 1};
  bool ccs_seen_[2] = {false, false};

  Bytes master_secret_;
  Bytes tls12_mac_key_[2];
  Bytes tls12_enc_key_[2];
  Bytes tls12_iv_[2];
  Bytes last_cbc_block_[2];
  u64 tls12_seq_[2] = {0, 0};
};

}  // namespace netcap
