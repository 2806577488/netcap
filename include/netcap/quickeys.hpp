// QUIC key logs, and the equal-length 1-RTT packet rewrite that is the whole
// point of this module.
//
// Why this file exists instead of a flag on `parse_keylog`:
// `crypto.hpp:158`'s `parse_keylog` is the *TLS* reader.  It insists that a
// line's second field be exactly 32 bytes of hex, because that field is the
// client random of a TLS connection.  QUIC key-log lines put the connection ID
// there instead, and a QUIC connection ID is 8 bytes in every browser build
// seen so far, so every QUIC line is dropped by that reader.  Nothing is wrong
// with `parse_keylog`; it is answering a different question.  This module
// answers the QUIC one.
//
// ---------------------------------------------------------------------------
// The key-log line, as Chromium writes it (net/ssl/ssl_key_logger_impl.cc)
// ---------------------------------------------------------------------------
//   <label> <connection_id_hex> <secret_hex>
// with no padding, one entry per line, the file appended to as connections are
// created.  The connection ID in a QUIC line is Chromium's
// `QuicConnectionId` for the connection whose secrets these are -- the id the
// *client* chose, i.e. the original destination connection ID the client put in
// its first Initial packet.  That is what `quic_keysets_from_keylog` looks up.
//
// Parsing rules, exactly as implemented:
//   * Labels accepted: `QUIC_CLIENT_TRAFFIC_SECRET_0`, `QUIC_SERVER_TRAFFIC_SECRET_0`,
//     and the two short spellings `CLIENT_TRAFFIC_SECRET_0` /
//     `SERVER_TRAFFIC_SECRET_0` (browsers differ; both are written by real
//     builds of the same code path), each with the trailing generation number.
//   * The generation is the digit run after a trailing '_' when one is present:
//     `_0` is the first key, `_1`, `_2`, ... are key updates (RFC 9001 section 6)
//     and are recorded in `generation`.  A label with no trailing digits has
//     generation 0.  A label that is otherwise unsupported is skipped -- this
//     reader never invents a secret from a label it does not recognise.
//   * `#` comment lines, blank lines, lines with fewer than three
//     whitespace-separated fields, lines whose second field is not 4..20 bytes
//     of hex, and lines with an empty or non-hex secret are ignored, silently
//     and individually: one bad line must not cost the caller the other entries.
//   * A half-written final line (the browser was in the middle of a write when
//     we read) is just a line with too few fields or an odd hex digit, so the
//     same rule drops it.  `refresh()` therefore re-reads at any moment without
//     risking a parse failure.  It also treats a repeat read of the same
//     (label, id, secret) triple as a no-op rather than a second entry.
//
// ---------------------------------------------------------------------------
// The rewrite contract
// ---------------------------------------------------------------------------
// `quic_reseal_same_pn` is the reason this module exists: it takes a packet off
// the wire, opens it, and puts a *different* plaintext of the *same length*
// back under the same packet number.  The result is byte-for-byte the same
// length as the input, so nothing downstream moves -- no packet number shifts,
// no ACK range is stolen, no flow-control limit is touched, no congestion
// controller sees a new packet.  The caller is responsible for the plaintext
// being a legal replacement (same frames, same sizes); this module enforces the
// length and the cryptography, not the semantics.
#ifndef NETCAP_QUICKEYS_HPP
#define NETCAP_QUICKEYS_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/h3.hpp"

namespace netcap {

// ---------------------------------------------------------------------------
// One key-log entry
// ---------------------------------------------------------------------------

struct QuicKeyEntry {
  std::string label;        // exactly as written, e.g. "QUIC_CLIENT_TRAFFIC_SECRET_0"
  std::string conn_id_hex;  // lowercase hex as written (accept 4..20 bytes)
  Bytes secret;             // the traffic secret (usually 32 bytes)
  bool from_client = false; // label says client, or label starts with CLIENT_
  int generation = 0;       // trailing _0/_1/... when the label ends with one
  std::string source;       // the file it came from
};

// A set of key-log files, merged.  Entries are kept in file order and are never
// discarded by `refresh`; the caller decides which entry to use.
class QuicKeyLog {
 public:
  // Read the whole file now, replacing whatever this object held for that path.
  // A path that cannot be read is an error (with `errno`-free, exact text).
  bool load_file(const std::string& path, std::string* error);
  // Re-read and MERGE: the writer appends while we read, so nothing already
  // known may be dropped, and a repeated read of the same triple is idempotent.
  bool refresh(const std::string& path, std::string* error);

  std::size_t size() const { return entries_.size(); }
  std::size_t files() const { return files_.size(); }

  // Entries whose connection id equals `conn_id`, hex compared
  // case-insensitively.  `conn_id_hex` additionally tolerates the separators
  // `from_hex` tolerates (spaces, colons, dashes).
  std::vector<QuicKeyEntry> find(const Bytes& conn_id) const;
  std::vector<QuicKeyEntry> find_hex(const std::string& conn_id_hex) const;

  std::vector<std::string> labels() const;  // distinct labels seen, sorted
  std::string describe() const;             // one honest line: file count, entry count, labels

  const std::vector<QuicKeyEntry>& entries() const { return entries_; }
  const std::vector<std::string>& file_list() const { return files_; }

 private:
  std::vector<QuicKeyEntry> entries_;
  std::vector<std::string> files_;
};

// ---------------------------------------------------------------------------
// Key-log entries -> 1-RTT keysets
// ---------------------------------------------------------------------------

// Derive the 1-RTT keysets of a connection from its ORIGINAL destination
// connection ID (see the header comment for why that is the right key).
//
// A 32-byte secret is ambiguous between AES-128-GCM and ChaCha20-Poly1305 -- the
// secret length cannot tell them apart and the key log does not record the
// suite -- so all three suites are tried in a fixed order and the first one that
// yields a usable keyset wins; `*suite_out` reports which.  A 48-byte secret is
// only valid for AES-256-GCM/SHA-384, and `quic_keyset_from_secret` refuses it
// for the other two rather than truncating it.
//
// The client and server keysets are filled independently: a log that carries
// only one direction still produces the one keyset it can, and the other is left
// `ready == false`.  Returns false, with a reason naming what was missing, when
// no entry at all matches the id or no matching secret derives under any suite.
bool quic_keysets_from_keylog(const QuicKeyLog& log, const Bytes& original_dcid, u16* suite_out,
                              QuicKeyset* client_keys, QuicKeyset* server_keys,
                              std::string* error);

// ---------------------------------------------------------------------------
// Sealing (RFC 9001 sections 5.3 and 5.4)
// ---------------------------------------------------------------------------

// Seal one short-header 1-RTT packet: build the header, AEAD the plaintext, then
// apply header protection to the first byte and the packet number.
//
// `hdr.pn_offset` is the packet number offset, i.e. `1 + dcid_len`; the
// connection ID bytes are taken from `hdr.header` (a header shorter than
// `pn_offset` bytes is refused, so a caller that has decrypted a packet
// elsewhere must supply the header).  `hdr.first_byte_unprotected` is used for
// the key phase (`0x04`) and spin (`0x20`) bits; its low two bits are ignored
// and rewritten from `hdr.pn_length`.  When `hdr.pn_length` is not 1..4 the
// shortest length that carries `packet_number` is used.
bool quic_seal_short(const QuicKeyset& keys, const QuicShortHeader& hdr, const Bytes& payload,
                     u64 packet_number, Bytes* packet_out, std::string* error);

// THE POINT OF THIS MODULE: an equal-length rewrite.  Decrypt `packet`, replace
// its plaintext with `new_payload` (which MUST have exactly the same length as
// the plaintext it replaces), re-seal under the same packet number, and return
// the new packet.  `*packet_out` is always exactly `packet.size()` bytes.
//
// `largest_pn` is the largest packet number already seen on this connection, the
// same value RFC 9000 appendix A.3 uses to recover a truncated packet number.
// It cannot be omitted honestly: a short header carries only the low 1..4 bytes
// of the packet number, and RFC 9001 section 5.3 builds the nonce from the FULL
// number.  The default 0 is only correct for a connection whose packets are
// still inside the first window (packet numbers below 2^(8 * field width)).
// Callers tracking a live connection must pass the real value, or the rewrite
// will fail to authenticate.
//
// Errors, each explicit: `new_payload` of a different length; a packet that is
// not a 1-RTT short-header packet (long header bit set, or too short); and a
// packet that does not authenticate under `keys` (wrong secret, key phase,
// wrong largest_pn, or a corrupted capture).  The connection ID length is not
// carried in a short header either, so it is recovered from the packet itself by
// trying the lengths that leave a header protection sample in range and keeping
// the one that authenticates; the recovered length is what the re-sealed packet
// uses.
bool quic_reseal_same_pn(const QuicKeyset& keys, const Bytes& packet, const Bytes& new_payload,
                         Bytes* packet_out, std::string* error, u64 largest_pn = 0);

// Decrypt one 1-RTT short-header packet with the connection ID length supplied by
// the caller, filling `hdr` (header with the packet number in the clear, plaintext
// in `hdr.payload`) and `*payload_out`.
//
// This is the opener `quic_reseal_same_pn` uses, exposed so that a caller can see
// exactly what a rewrite started from.  It was originally written because `h3`'s
// `quic_decrypt_short_full` unprotected the first byte with a four-bit mask
// (`mask[0] & 0x0f`) where RFC 9001 section 5.4.1 and Figure 6 specify five bits
// for a short header (`mask[0] & 0x1f`), and could not open the appendix A.5
// vector at all.  `h3` has since been fixed and `src/selftest.cpp` checks both
// openers against that vector, so the two now agree; this entry point stays
// because it also reports the packet it opened.
bool quic_open_short(const QuicKeyset& keys, const Bytes& packet, std::size_t dcid_len,
                     u64 largest_pn, QuicShortHeader* hdr, Bytes* payload_out,
                     std::string* error);

// ---------------------------------------------------------------------------
// Self-check
// ---------------------------------------------------------------------------

// One line per group in `*report`, ending in "FAIL <group>: <detail>" when a
// group does not finish; the return value is exactly "no failure line".  Covers
// the parser (comments, malformed lines, a TLS line being skipped), `refresh()`
// picking up an appended line, and the RFC 9001 A.5 round trip.
bool quickeys_selfcheck(std::string* report);

}  // namespace netcap

#endif  // NETCAP_QUICKEYS_HPP
