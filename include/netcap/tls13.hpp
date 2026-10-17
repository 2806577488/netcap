// A small TLS 1.3 implementation (RFC 8446) with exactly the pieces the
// interception proxy needs:
//
//   * two cipher suites: ChaCha20-Poly1305 (0x1303, preferred because this build
//     has no AES-NI) and TLS_AES_128_GCM_SHA256 (0x1301), the mandatory one
//   * three groups:     x25519 (mandatory to implement), secp256r1 -- which costs
//     nothing extra because the same P-256 code signs the leaves -- and secp521r1,
//     which p521.cpp implements for clients (a Steam client, measured) that offer
//     that group and nothing else this server can use; a client whose key share
//     this server cannot use gets a HelloRetryRequest for one of them, as long as
//     its supported_groups lists it
//   * ALPN http/1.1 in both directions, so the proxy speaks HTTP/1.1 to the
//     browser and to the origin server
//   * ECDSA P-256 signatures for the certificates it issues; the upstream
//     certificate signature is verified when it is ECDSA P-256
//
// No resumption, no 0-RTT, no client certificates, no key update: a request that
// needs any of those is reported as unsupported instead of being half
// implemented.  A client that offers no group this server can do at all (a lone
// secp384r1 key share, say) is reported along with the groups it did list, and
// `read_prefix()` holds the raw ClientHello so the caller can still replay it to
// the origin and relay the connection blind.
#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/x509.hpp"
#include "netcap/x25519.hpp"

namespace netcap {

constexpr u8 TLS13_CCS = 20;
constexpr u8 TLS13_ALERT = 21;
constexpr u8 TLS13_HANDSHAKE = 22;
constexpr u8 TLS13_APPDATA = 23;

constexpr u16 TLS13_AES_128_GCM_SHA256 = 0x1301;
// Preferred whenever the client offers it: this build has no AES-NI, and its
// ChaCha20-Poly1305 runs roughly 25x faster than its table-free AES-GCM.
constexpr u16 TLS13_CHACHA20_POLY1305 = 0x1303;
constexpr u16 TLS13_GROUP_X25519 = 0x001d;
constexpr u16 TLS13_GROUP_SECP256R1 = 0x0017;
// P-521 is here for one measured client that offered this group and nothing the
// server could use.  The arithmetic lives in p521.cpp; certificate signatures
// stay on P-256.
constexpr u16 TLS13_GROUP_SECP521R1 = 0x0019;
constexpr u16 TLS13_SIG_ECDSA_P256_SHA256 = 0x0403;
// RSA-PSS with SHA-256: the scheme an RSA-only origin uses for its
// CertificateVerify.  Most of the web is in that category, so the client has to
// offer it and check it (`rsa_verify_sha256` does the checking through CNG).
constexpr u16 TLS13_SIG_RSA_PSS_RSAE_SHA256 = 0x0804;

// Transport hooks: whatever the caller reads and writes. `read` returns false
// on error or end of stream, and reports how many bytes it produced in
// `got`. Exactly one complete record is handed to the engines at a time.
struct Tls13Io {
  std::function<bool(u8*, std::size_t, std::size_t*)> read;
  std::function<bool(const u8*, std::size_t)> write;
};

// One direction of record protection.
struct Tls13Traffic {
  Bytes secret;  // the traffic secret this direction was derived from
  Bytes key;
  Bytes iv;
  u64 seq = 0;
  bool ready = false;
  u16 suite = TLS13_AES_128_GCM_SHA256;  // which AEAD protects this direction
};

// Everything a TLS 1.3 handshake establishes.
struct Tls13Secrets {
  Bytes early_secret;
  Bytes handshake_secret;
  Bytes master_secret;
  Tls13Traffic client_handshake;
  Tls13Traffic server_handshake;
  Tls13Traffic client_application;
  Tls13Traffic server_application;
  Bytes client_random;
  Bytes server_random;
  Bytes shared;  // the ECDHE shared secret
  // The negotiated AEAD: copied into every traffic direction by the key
  // schedule, so it has to be set before tls13_derive_handshake runs.
  u16 suite = TLS13_AES_128_GCM_SHA256;
};

// HKDF-Expand-Label with the TLS 1.3 prefix and an empty default context.
Bytes tls13_expand_label(const Bytes& secret, const std::string& label, const Bytes& context,
                         std::size_t out_len);
// Derive-Secret(secret, label, transcript).
Bytes tls13_derive_secret(const Bytes& secret, const std::string& label, const Bytes& transcript);

// The key schedule up to the application traffic secrets, given the ECDHE
// shared secret and the full ClientHello..ServerHello transcript.
bool tls13_derive_handshake(const Bytes& shared, const Bytes& transcript_ch_sh,
                            Tls13Secrets* out);
// Adds the application secrets once the server Finished is in the transcript.
bool tls13_derive_application(Tls13Secrets* secrets, const Bytes& transcript_through_server_finished);

// Finished verify_data for a direction.
Bytes tls13_finished_data(const Bytes& traffic_secret, const Bytes& transcript);

// Record protection. `inner_type` is the real content type carried inside the
// encrypted record (23 for application data, 22 for handshake). Sealing advances
// the traffic's sequence number, so the state must be writable.
bool tls13_seal(Tls13Traffic* traffic, u8 inner_type, const Bytes& content, Bytes* record);
bool tls13_open(Tls13Traffic* traffic, const Bytes& record, u8* inner_type, Bytes* content,
                std::string* error);

// Transcript hash helper: SHA-256 over a growing list of handshake messages.
class Tls13Transcript {
 public:
  void add(const Bytes& handshake_message);
  void reset();
  Bytes hash() const;
  std::size_t size() const { return data_.size(); }
  const Bytes& bytes() const { return data_; }

 private:
  Bytes data_;
};

// A handshake message: type byte plus a three byte length.
Bytes tls13_handshake(u8 type, const Bytes& body);

// Parses one handshake message out of `body` at `*offset`.
bool tls13_next_handshake(const Bytes& body, std::size_t* offset, u8* type, Bytes* message);

// ------------------------------------------------------------------ server

struct Tls13ServerInfo {
  std::string sni;             // what the client asked for
  std::string alpn;            // what we agreed on ("http/1.1")
  u16 cipher_suite = 0;
  u16 group = 0;
  bool client_finished_ok = false;
  std::size_t handshake_bytes = 0;
  std::vector<std::string> offered_alpn;
  bool offered_supported_versions = false;
};

// The side that faces the browser: presents a certificate for the host name it
// was given and then exposes the plaintext.
class Tls13Server {
 public:
  // `cert` and `key` must match; `sni_fallback` is used when the ClientHello
  // carries no server_name extension.
  bool accept(const Tls13Io& io, const X509Cert& cert, const P256Key& key,
              const std::string& sni_fallback, Tls13ServerInfo* info, std::string* error);

  // Application data. `read` returns false at end of stream (or on error, which
  // is then described in `error`).
  bool read_app(const Tls13Io& io, Bytes* out, std::string* error);
  bool write_app(const Tls13Io& io, const Bytes& data, std::string* error);
  bool send_close_notify(const Tls13Io& io, std::string* error);
  bool closed() const { return closed_; }
  const Tls13Secrets& secrets() const { return secrets_; }

  // Only meaningful after accept() has returned false: the raw records read from
  // the client (the ClientHello), exactly as they came off the wire, so a caller
  // can replay them to the origin and fall back to a blind relay.  Empty once
  // anything of ours has been written -- a half finished handshake cannot be
  // handed to a different TLS server.
  const Bytes& read_prefix() const { return read_prefix_; }
  bool wrote_anything() const { return wrote_; }

 private:
  Tls13Secrets secrets_;
  Tls13Transcript transcript_;
  bool closed_ = false;
  std::size_t pending_offset_ = 0;
  Bytes pending_;  // decrypted bytes not yet handed to the caller
  Bytes read_prefix_;  // raw records read from the client, for the blind fallback
  bool wrote_ = false;  // true as soon as a handshake byte went to the client
};

// ------------------------------------------------------------------ client

struct Tls13ClientInfo {
  std::string host;
  std::string alpn;
  u16 cipher_suite = 0;
  u16 group = 0;
  bool certificate_seen = false;
  bool certificate_signature_verified = false;
  bool certificate_host_matched = false;
  bool certificate_dates_ok = false;
  bool server_finished_ok = false;
  std::string certificate_subject;
  std::string certificate_issuer;
  std::string warning;  // set when the upstream could not be fully verified
};

// The side that faces the real server. Refuses to continue when the origin
// cannot be verified, unless `allow_unverified` is set.
class Tls13Client {
 public:
  // Continues a session whose traffic secrets -- and therefore the record
  // sequence numbers -- come from a pooled connection: no handshake is run, the
  // next record this object writes simply continues the old sequence.
  void resume(const Tls13Secrets& secrets);
  bool connect(const Tls13Io& io, const std::string& host, const std::string& alpn,
               bool allow_unverified, Tls13ClientInfo* info, std::string* error);
  bool read_app(const Tls13Io& io, Bytes* out, std::string* error);
  bool write_app(const Tls13Io& io, const Bytes& data, std::string* error);
  bool send_close_notify(const Tls13Io& io, std::string* error);
  bool closed() const { return closed_; }
  const Tls13Secrets& secrets() const { return secrets_; }

 private:
  Tls13Secrets secrets_;
  Tls13Transcript transcript_;
  bool closed_ = false;
  Bytes pending_;
};
// Reads exactly one TLS record from `io`: 5 byte header plus body. Rejects
// absurd lengths so a broken peer cannot make us allocate wildly.
bool tls13_read_record(const Tls13Io& io, Bytes* record, std::string* error);

// Human readable descriptions for logs and reports.
std::string tls13_cipher_name(u16 suite);
std::string tls13_group_name(u16 group);
std::string tls13_alert_text(u8 description);

}  // namespace netcap
