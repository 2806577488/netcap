// A small X.509 issuer: DER encoding, a local CA, and per-host leaf
// certificates for the HTTPS interception proxy.
//
// Scope is deliberately narrow: ECDSA P-256 with SHA-256, the extensions a
// browser actually checks (basicConstraints, keyUsage, extendedKeyUsage,
// subjectAltName), and a parser that reads back exactly the fields this tool
// needs. Anything else is out of scope -- this is not a general PKI toolkit.
#ifndef NETCAP_X509_HPP
#define NETCAP_X509_HPP

#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/p256.hpp"

namespace netcap {

// ------------------------------------------------------------------- PEM / DER
std::string pem_encode(const std::string& label, const Bytes& der);
bool pem_decode(const std::string& text, const std::string& label, Bytes* der);

// ---------------------------------------------------------------- certificates
struct X509Cert {
  Bytes der;    // the whole certificate, DER
  Bytes tbs;    // the tbsCertificate TLV: exactly what the signature covers
  Bytes subject;  // the subject Name, DER: a leaf's issuer must repeat it byte for byte
  Bytes issuer;   // the issuer Name, DER
  Bytes spki;   // SubjectPublicKeyInfo, DER
  Bytes signature_r;  // ECDSA r, 32 bytes
  Bytes signature_s;  // ECDSA s, 32 bytes
  Bytes signature;    // the raw signature over tbs (RSA); empty for ECDSA
  /// "ecdsa-with-SHA256", "sha256WithRSAEncryption", "rsassaPss", or empty when
  /// the OID is neither.
  std::string signature_algorithm;
  P256Point public_key;  // the subject key, when it is a P-256 point
  /// The subject key, when it is an RSA key (big-endian, as DER spells them).
  Bytes rsa_modulus;
  Bytes rsa_exponent;
  bool has_rsa = false;
  bool is_ca = false;
  bool has_spki = false;
  std::string subject_cn;
  std::string issuer_cn;
  std::string serial_hex;
  std::string not_before;  // raw DER time text, e.g. "240101000000Z"
  std::string not_after;
  std::vector<std::string> dns_names;
  std::vector<std::string> ip_names;
  Bytes sha256;  // fingerprint of the DER

  std::string sha256_hex() const { return to_hex(sha256); }
  std::string pem() const { return pem_encode("CERTIFICATE", der); }
  std::string describe() const;
};

// Parses the fields above. Returns false with a reason when the DER is broken.
bool x509_parse(const Bytes& der, X509Cert* out, std::string* error);

// The value of a DER INTEGER, without the leading 0x00 that DER adds when the
// top bit is set.  A 2048-bit RSA modulus is written with that byte, so the raw
// body is 257 bytes; feeding it to RSA math makes every ciphertext one byte too
// long and the origin answers `decrypt_error`.
Bytes der_integer_value(const u8* body, std::size_t len);

// Verifies `cert` against `issuer` (P-256/SHA-256 and RSA/SHA-256) and checks
// that the issuer's name matches and that the validity windows are consistent.
bool x509_verify_signature(const X509Cert& cert, const X509Cert& issuer);

// True when the certificate is valid for `host` (exact DNS name or wildcard).
bool x509_matches_host(const X509Cert& cert, const std::string& host);

// -------------------------------------------------------------------- issuance
struct X509Subject {
  std::string common_name;
  std::string organization = "netcap";
  std::string country = "XX";
};

struct CaBundle {
  P256Key key;
  X509Cert cert;
  std::string key_pem;
  std::string cert_pem;
  bool valid() const { return !key.d.empty() && !cert.der.empty(); }
};

// Creates a self-signed CA. `days` is the CA lifetime (10 years is fine: it is a
// local root the user can delete at any time).
bool ca_create(const X509Subject& subject, int days, CaBundle* out, std::string* error);

struct LeafRequest {
  std::string host;                       // the SNI or CONNECT target
  std::vector<std::string> extra_dns;     // additional dNSName SAN entries
  std::vector<std::string> ip_addresses;  // iPAddress SAN entries
  int days = 397;                         // browsers reject leaves over 398 days
};

// Issues a leaf certificate signed by `ca`. The key is generated unless one is
// supplied, so the proxy can reuse a cached key per host.
bool leaf_issue(const CaBundle& ca, const LeafRequest& req, P256Key* key, X509Cert* out, std::string* error);
bool leaf_issue_with_key(const CaBundle& ca, const LeafRequest& req, const P256Key& key, X509Cert* out,
                         std::string* error);

// ------------------------------------------------------------- key files (PEM)
Bytes ec_private_key_pkcs8(const P256Key& key);
bool ec_private_key_parse(const Bytes& der, P256Key* out, std::string* error);

bool ca_write_files(const CaBundle& ca, const std::string& cert_path, const std::string& key_path,
                    std::string* error);
bool ca_read_files(const std::string& cert_path, const std::string& key_path, CaBundle* out, std::string* error);

}  // namespace netcap

#endif  // NETCAP_X509_HPP
