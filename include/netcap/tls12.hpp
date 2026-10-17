// TLS 1.0 / 1.1 / 1.2 (RFC 2246, 4346, 5246) as the *client* — the upstream leg
// of the interception proxy, for origins that cannot speak TLS 1.3.
//
// Why this exists: the MITM needs to terminate the origin's TLS itself. Our
// TLS 1.3 client alone left every older origin (eva2.csdn.net, cn.bing.com, ...)
// with a `protocol_version` alert, and those requests all turned into 502s.
// This client speaks the older handshakes so they can be decrypted (and
// therefore filtered by URL) instead of being blind-relayed.
//
// Spec coverage: RFC 5246 / 4346 / 2246 (handshake, PRF, record layer, the
// MD5+SHA1 PRF and the MD5||SHA1 Finished of 1.0/1.1), RFC 5289 / RFC 8422
// (ECDHE key exchange, signature algorithms), RFC 5288 (AES-GCM), RFC 7905
// (ChaCha20-Poly1305), RFC 3268 / RFC 5246 §6.2.3.2 (AES-CBC with HMAC-SHA1 or
// HMAC-SHA256, the 1.0 implicit IV and the 1.1+ explicit IV), RFC 5246 §7.4.7.1
// (RSA key exchange: the encrypted pre_master_secret), RFC 7627 (extended
// master secret), RFC 6066 (SNI), RFC 7301 (ALPN), RFC 5746
// (renegotiation_info), RFC 4492 (curves and point formats).
//
// Deliberately not offered: DHE / anon / PSK key exchange (finite-field and
// pre-shared-key math we do not need for the boxed-in case), compression,
// session resumption / tickets, renegotiation, and the RC4/3DES suites. An
// origin that insists on any of those is still reachable — the proxy falls back
// to a blind relay, which keeps the page working while saying so.
#pragma once

#include <cstddef>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/tls13.hpp"  // Tls13Io: the byte-level transport the caller owns

namespace netcap {

// One entry per cipher suite this client is willing to negotiate.
struct Tls12Suite {
  u16 id = 0;
  const char* name = "";
  bool ecdsa = false;       // the certificate signature must be ECDSA...
  bool rsa = false;         // ...or RSA (PSS / PKCS#1)
  std::size_t key_len = 16;  // AEAD/CBC key bytes
  std::size_t fixed_iv_len = 4;  // AES-GCM: 4 byte salt + 8 byte explicit nonce
  bool chacha = false;      // RFC 7905: 12 byte IV, nonce = IV xor seq, no explicit nonce
  // The additions below cover the older handshakes; they default to the AEAD
  // shapes above so the original four entries stay valid as written.
  bool cbc = false;             // AES-CBC + HMAC (MAC-then-encrypt): 16 byte IV
  bool rsa_key_exchange = false;  // static RSA: no ServerKeyExchange, encrypted premaster
  std::size_t mac_len = 0;      // HMAC length for CBC suites (20 for SHA1, 32 for SHA256)
  u16 min_version = 0x0303;     // the oldest protocol version this suite may be offered in
};

const Tls12Suite* tls12_suite(u16 id);
// The suites offered in a ClientHello for `version` (AEAD needs 1.2).
std::vector<u16> tls12_offered_suites(int version = 0x0303);
std::string tls12_suite_name(u16 id);

// Traffic keys for both directions plus the sequence numbers. Copied wholesale
// when a pooled connection is reused, so the numbers must live here.
struct Tls12Secrets {
  u16 suite = 0;
  int group = 0;
  int version = 0x0303;  // the negotiated protocol version
  Bytes client_random;
  Bytes server_random;
  Bytes master_secret;
  Bytes client_mac;  // CBC suites: the MAC keys come first in the key block
  Bytes server_mac;
  Bytes client_key;
  Bytes server_key;
  Bytes client_iv;  // 4 bytes for GCM, 12 for ChaCha20, 16 for CBC
  Bytes server_iv;
  u64 client_seq = 0;
  u64 server_seq = 0;
  bool chacha = false;
  bool cbc = false;
  bool extended_master_secret = false;
};

struct Tls12ClientInfo {
  std::string host;
  std::string alpn;
  u16 cipher_suite = 0;
  u16 version = 0;
  int group = 0;
  std::string key_exchange;  // "ecdhe" or "rsa"
  bool certificate_seen = false;
  bool certificate_host_matched = false;
  bool certificate_dates_ok = false;
  bool certificate_chain_checked = false;
  bool server_key_exchange_verified = false;
  bool server_finished_ok = false;
  bool extended_master_secret = false;
  std::string certificate_subject;
  std::string certificate_issuer;
  std::string warning;
};

// Record layer pieces, exposed so the self-test can exercise them without a
// server: `dir` 0 = we send, 1 = we receive.
bool tls12_seal(Tls12Secrets* secrets, int dir, u8 content_type, const Bytes& plaintext, Bytes* record,
                std::string* error);
bool tls12_open(Tls12Secrets* secrets, int dir, const Bytes& record, u8* content_type, Bytes* plaintext,
                std::string* error);

// The key schedule: RFC 5246 §8.1 (or RFC 7627 §4 when EMS was negotiated).
bool tls12_derive_keys(Tls12Secrets* secrets, const Bytes& pre_master, const Bytes& session_hash,
                       std::string* error);

// verify_data for one direction: PRF(master_secret, "… finished", hash)[0..11].
Bytes tls12_finished_data(const Bytes& master_secret, bool from_server, const Bytes& transcript_hash);

// The pre-1.2 PRF (RFC 2246 §5, kept by RFC 4346): P_MD5(S1) XOR P_SHA1(S2).
// TLS 1.0/1.1 origins use it for the master secret, the key block and Finished,
// so it is part of the same key schedule as tls12_derive_keys.
Bytes tls_prf_legacy(const Bytes& secret, const std::string& label, const Bytes& seed,
                     std::size_t out_len);
Bytes tls12_finished_data_legacy(const Bytes& master_secret, bool from_server,
                                 const Bytes& handshake_messages);

class Tls12Client {
 public:
  // Runs the full handshake. `allow_unverified` is what the proxy uses for its
  // reachability probe; a real interception passes false and a certificate that
  // does not match the host is then a hard failure.
  // `version_hint` is the version offered first: 0x0303 for 1.2, 0x0302 / 0x0301
  // when the caller wants 1.1 / 1.0 (the origin may still answer with anything
  // from 1.0 up to the hint, which is what makes one client cover all three).
  bool connect(const Tls13Io& io, const std::string& host, const std::string& alpn, bool allow_unverified,
               Tls12ClientInfo* info, std::string* error, int version_hint = 0x0303);
  bool read_app(const Tls13Io& io, Bytes* out, std::string* error);
  bool write_app(const Tls13Io& io, const Bytes& data, std::string* error);
  bool send_close_notify(const Tls13Io& io, std::string* error);
  bool closed() const { return closed_; }
  const Tls12Secrets& secrets() const { return secrets_; }
  void resume(const Tls12Secrets& secrets);

 private:
  Tls12Secrets secrets_;
  bool closed_ = false;
};

// Cross-checks the key schedule, the record layer and the finished computation.
bool tls12_selfcheck(std::string* report);

}  // namespace netcap
