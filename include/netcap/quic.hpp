// QUIC Initial packet parsing (RFC 9000 + RFC 9001), enough to read the TLS
// ClientHello out of the handshake and therefore the SNI / ALPN.
//
// This module is deliberately standalone: it depends only on netcap/common.hpp,
// netcap/crypto.hpp and the project's existing TLS handshake parser
// (netcap/tls.hpp, function tls_parse_client_hello).  It owns no sockets, no
// global state and no threads; a caller feeds it one decrypted-or-encrypted UDP
// payload at a time and owns whatever reassembly state it wants to keep.
//
// Scope: QUIC version 1 (RFC 9000/9001) and version 2 (RFC 9369) Initial
// packets, protected with AES-128-GCM and AES-128-ECB header protection -- which
// is what the Initial packet number space always uses in both versions.  Short
// header packets, Retry, 0-RTT and ChaCha20 header protection are *not*
// implemented; those inputs produce an explicit error string, never a silently
// wrong answer.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"

namespace netcap {

// ------------------------------------------------------------------ constants

// QUIC version numbers, on the wire.
constexpr u32 kQuicV1 = 0x00000001;
constexpr u32 kQuicV2 = 0x6b3343cf;

// A long header packet type (the two bits above the fixed bit differ per
// version, so the raw value is version dependent; only Initial is decoded here).
constexpr u8 kQuicTypeInitial = 0;
constexpr u8 kQuicTypeZeroRtt = 1;
constexpr u8 kQuicTypeHandshake = 2;
constexpr u8 kQuicTypeRetry = 3;

// Before decrypting anything, an Initial packet is at least this many bytes:
// 1 flags + 4 version + 1 dcid_len + 1 scid_len + 1 length + 1 pn + 16 tag.
constexpr std::size_t kQuicMinInitialSize = 26;

// The 16-byte sample for header protection is read at pn_offset + 4, so the
// smallest legal Initial carries 20 bytes past the connection IDs.
constexpr std::size_t kQuicHpSampleLen = 16;
constexpr std::size_t kQuicHpSampleOffsetFromPn = 4;

// A CRYPTO stream larger than this is refused rather than grown without bound:
// a real ClientHello is a few hundred to a few thousand bytes (see the notes in
// src/quic.cpp); anything past 64 KiB is a malformed or hostile peer.
constexpr std::size_t kQuicMaxCryptoStream = 64 * 1024;

// ------------------------------------------------------------------ varints

// RFC 9000 section 16.  `out` receives the value, `used` the encoded length
// (1, 2, 4 or 8).  Returns false when the buffer is too short or the encoding
// uses one of the reserved 2-bit prefixes.
bool quic_varint(const u8* data, std::size_t len, u64* out, std::size_t* used);
bool quic_varint(const Bytes& b, std::size_t off, u64* out, std::size_t* used);

// Appends `v` to `out` using the shortest of the four legal encodings.
void quic_varint_put(Bytes* out, u64 v);

// ------------------------------------------------------------------ keys

// Which side of the handshake the Initial keys protect.
enum class QuicInitialSide { Client, Server };

// The four secrets an Initial packet needs, for one direction.  Every field is
// empty and `error` explains why when the derivation failed.
struct QuicInitialKeys {
  bool ready = false;
  std::string error;
  u32 version = 0;
  QuicInitialSide side = QuicInitialSide::Client;
  Bytes secret;  // client_initial_secret / server_initial_secret (32 bytes)
  Bytes key;     // AEAD key (16 bytes)
  Bytes iv;      // AEAD nonce base (12 bytes)
  Bytes hp;      // header protection key (16 bytes)

  // Convenience: the AES-128 key schedule for `hp`, ready for encrypt_block().
  bool set_hp_cipher(Aes* out) const;
};

// derive_initial_keys(DCID, version, side, out).  `dcid` is the Destination
// Connection ID from the client's *first* Initial packet (RFC 9001 section 5.2).
// On failure `out->ready` is false and `out->error` names the reason.
bool derive_initial_keys(const u8* dcid, std::size_t dcid_len, u32 version,
                         QuicInitialSide side, QuicInitialKeys* out);

// ------------------------------------------------------------------ packets

// Everything an Initial packet header gives us, before the payload is touched.
struct QuicInitialHeader {
  bool ok = false;
  std::string error;
  u32 version = 0;
  bool is_v2 = false;
  u8 first_byte = 0;   // protected first byte as it arrived on the wire
  u8 first_byte_unprotected = 0;
  u8 packet_type = 0;  // the long header type bits, version decoded
  Bytes dcid;
  Bytes scid;
  Bytes token;
  u64 length = 0;               // the Header Length field (pn + ciphertext + tag)
  std::size_t pn_offset = 0;    // offset of the (still protected) packet number
  int pn_length = 0;            // 1..4, decoded from the first byte
  std::size_t header_end = 0;   // one past the last packet-number byte, == AAD length
  std::size_t payload_offset = 0;  // start of the AEAD ciphertext
  // The unprotected header through the packet number, i.e. exactly the AEAD
  // associated data.  header_prefix.size() == header_end.  The packet number
  // bytes have already been unmasked, because RFC 9001 section 5.4.1 says the
  // header protection mask is removed before the header is authenticated.
  Bytes header_prefix;
  std::size_t payload_length = 0;  // ciphertext bytes actually present
  u64 packet_number = 0;        // after unmasking and packet-number decoding
  u64 largest_acked = 0;        // caller's previous largest packet number, for decoding
  bool trunced = false;         // wire packet was shorter than the Length field
};

// Walks a long header Initial packet: varint fields, header protection removal,
// packet-number decoding.  Does not decrypt.  `largest_acked` is the RFC 9001
// packet-number-decoding input (0 in a test, the previous largest PN in a flow).
bool quic_parse_initial_header(const u8* data, std::size_t len, u64 largest_acked,
                               const QuicInitialKeys& keys, QuicInitialHeader* out);

// Header + AEAD decryption of the payload.  `out_payload` receives the plaintext
// (1162 bytes for the RFC 9001 Appendix A.2 vector).  Returns false and fills
// `error` when the tag does not verify or the packet is malformed.
bool quic_decrypt_initial(const u8* data, std::size_t len, u64 largest_acked,
                          const QuicInitialKeys& keys, QuicInitialHeader* header,
                          Bytes* out_payload, std::string* error);

// ------------------------------------------------------------------ frames

// One parsed frame, with just enough detail to report it.
struct QuicFrame {
  u8 type = 0;
  std::string type_name;
  u64 offset = 0;       // CRYPTO / STREAM offset, or the value field
  u64 length = 0;       // payload length on the wire
  Bytes data;           // CRYPTO payload, when `type == 0x06`
  std::string note;     // e.g. "padding 917", "ack 0 ranges"
};

// Parses a decrypted frame stream, typing and measuring each frame.  PADDING
// frames are coalesced into one entry.  Anything unknown or truncated stops the
// walk with an explicit error.
bool quic_parse_frames(const u8* data, std::size_t len, std::vector<QuicFrame>* frames,
                       std::string* error);

// ------------------------------------------------------------------ CRYPTO reassembly

// Reassembles CRYPTO frames spread over several Initial packets into the
// contiguous handshake byte stream.  The caller owns one of these per direction
// (per connection) and feeds it every decrypted payload in packet-number order.
struct QuicCryptoStream {
  Bytes bytes;         // the reassembled stream
  u64 highest = 0;     // highest offset + length seen (the buffered prefix length)
  bool complete = false;
  std::string error;

  void reset();
  // Absorbs the CRYPTO frames of one decrypted payload.  Returns false, with
  // `error` set, when a frame leaves a hole (a packet was lost or reordered --
  // the bytes in between are unknown, so the stream is refused rather than
  // silently shifted), when a retransmission disagrees with the bytes already
  // held, or when the stream would exceed kQuicMaxCryptoStream.  Feed payloads
  // in packet-number order; out-of-order delivery is an error, not a wait.
  bool absorb(const u8* frames, std::size_t len);
  bool absorb(const std::vector<QuicFrame>& frames);
};

// ------------------------------------------------------------------ ClientHello

// The fields the filter stage needs out of a QUIC ClientHello.
struct QuicClientHello {
  std::string host;     // server_name SNI, lowercased
  std::string alpn;     // first (preferred) ALPN protocol; all of them go in `alpns`
  std::vector<std::string> alpns;
  std::string version;  // negotiated TLS version from supported_versions, e.g. "TLS 1.3"
  u16 legacy_version = 0;
  Bytes random;
  std::vector<u16> cipher_suites;
};

// Parses the TLS handshake stream that came out of the CRYPTO frames.  Skips
// non-ClientHello handshake messages (a HelloRetryRequest-then-ClientHello
// stream, or a server-direction stream) and returns the ClientHello found.
bool quic_parse_client_hello(const u8* data, std::size_t len, QuicClientHello* out,
                             std::string* error);

// ------------------------------------------------------------------ one-shot API

// Parses one UDP payload as a client Initial packet.  Returns true when the
// packet was a decryptable Initial that carried (at least the start of) a
// ClientHello; `sni` / `alpn` are then filled in.  `error` receives a precise
// reason on every false return.
//
// This is the whole path in one call, so a CRYPTO stream split across several
// Initial packets cannot be reassembled here -- use quic_decrypt_initial +
// QuicCryptoStream + quic_parse_client_hello for that.  `sni` and `alpn` may be
// null if the caller only wants the verdict.
bool quic_parse_initial(const u8* data, std::size_t len, std::string* sni, std::string* alpn,
                        std::string* error);

// ------------------------------------------------------------------ builder

// Builds a protected client Initial packet around `frames` (a CRYPTO frame and
// any padding the caller appends).  Exists so the parser can be round-tripped
// against packets this module produced itself; it is also what
// quic_selfcheck() uses.  Returns false with `error` set on a bad input.
bool quic_build_initial(const u8* dcid, std::size_t dcid_len, u32 version, u64 packet_number,
                        std::size_t pn_length, const u8* frames, std::size_t frames_len,
                        Bytes* out_packet, std::string* error);

// Builds the bytes of a TLS 1.3 ClientHello handshake message carrying
// server_name = `sni`, ALPN = `alpn` and supported_versions = TLS 1.3.
// The result is a bare handshake message (type 0x01), which is what a CRYPTO
// frame carries.
bool quic_build_client_hello(const std::string& sni, const std::string& alpn, u16 sni_type,
                             Bytes* out_message, std::string* error);

// ------------------------------------------------------------------ self test

// Runs the RFC 9001 Appendix A.2 vector and the build/parse round trip.
// Returns false only when an assertion failed; `report` always receives the
// human-readable transcript.
bool quic_selfcheck(std::string* report);

}  // namespace netcap
