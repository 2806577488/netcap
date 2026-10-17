// HTTP/3 over QUIC 1-RTT:  the second half of the QUIC story.
//
// `quic.hpp` stops at the Initial packet.  That is enough to read the
// ClientHello -- and therefore the SNI -- but nothing else, because the
// ClientHello is the only thing a passive observer can decrypt without a secret.
// This header picks the story up where the browser's TLS key log gives us a
// secret: it derives the 1-RTT (short header) keys, removes header protection,
// opens the AEAD, walks the QUIC frames, and decodes the HTTP/3 field section
// down to `:method`, `:authority` and `:path`.
//
// The contract is the same one `quic.hpp` uses: every function either succeeds,
// or leaves an exact lower-case sentence in `*error` naming the rule that was
// violated.  Nothing is guessed and no partial result is ever reported as a
// success -- a caller that gets `false` can safely ignore every out-parameter.
//
// Deliberate non-support, each with its own error string rather than a guess:
//   * the QPACK *dynamic* table (see `h3_decode_field_section`),
//   * 0-RTT and Retry packets (those are `quic.cpp`'s gap, kept as its own),
//   * ChaCha20 header protection *is* supported; so is AES-ECB.
#ifndef NETCAP_H3_HPP
#define NETCAP_H3_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/quic.hpp"

namespace netcap {

// TLS 1.3 cipher suites as they appear on the wire.  `tls.hpp` does not name
// them and `quic.cpp` declares only the one it needs, locally; QUIC needs all
// three, because a 1-RTT keyset is derived from whichever suite the handshake
// negotiated.  See RFC 8446 section B.4.
constexpr u16 kH3TlsAes128GcmSha256 = 0x1301;
constexpr u16 kH3TlsAes256GcmSha384 = 0x1302;
constexpr u16 kH3TlsChacha20Poly1305Sha256 = 0x1303;

// ---------------------------------------------------------------------------
// 1-RTT packet protection (RFC 9001 section 5.1)
// ---------------------------------------------------------------------------

// What a packet protection secret expands into.  A QUIC `QuicInitialKeys` is a
// different thing (it is 0-RTT-free and pinned to AES-128-GCM by the version
// salt), so this is a separate type rather than a reuse of that one.
struct QuicKeyset {
  bool ready = false;
  std::string error;

  // RFC 8446 section B.4 suite id.  The secret length alone cannot say which
  // AEAD to use, so the suite must be supplied; `quic_keyset_from_secret`
  // refuses any value it does not know instead of picking one.
  u16 suite = 0;
  Bytes secret;  // the traffic secret the keys were expanded from ("quic ku")
  Bytes key;     // AEAD key:   16 bytes (AES-128-GCM) or 32 (AES-256-GCM, ChaCha20)
  Bytes iv;      // packet IV:  12 bytes
  Bytes hp;      // header protection key: 16 bytes (AES) or 32 (ChaCha20)

  bool is_chacha20() const { return suite == kH3TlsChacha20Poly1305Sha256; }
  bool is_aes256() const { return suite == kH3TlsAes256GcmSha384; }
  std::size_t key_len() const { return key.size(); }
};

// HKDF-Expand-Label(secret, "quic key"|"quic iv"|"quic hp", "", len) with
// SHA-256, per RFC 9001 section 5.1.  `suite` must be one of the three
// constants above; `*out->ready` is false and `*error` is set otherwise.
bool quic_keyset_from_secret(u16 suite, const Bytes& traffic_secret, QuicKeyset* out,
                             std::string* error);

// RFC 9001 section 6: the next generation of a traffic secret, via the
// "quic ku" label.  The caller follows a key phase flip by expanding this into
// a fresh keyset and retrying the packet that failed to open.
bool quic_next_secret(const Bytes& traffic_secret, Bytes* out, std::string* error);

// ---------------------------------------------------------------------------
// Short header (1-RTT) packets
// ---------------------------------------------------------------------------

struct QuicShortHeader {
  bool ok = false;
  std::string error;

  u8 first_byte = 0;             // as received, i.e. still protected
  u8 first_byte_unprotected = 0; // after header protection is removed
  bool key_phase = false;        // RFC 9000 section 17.3.1 bit 0x04
  bool spin = false;             // bit 0x20
  std::size_t pn_offset = 0;     // first packet number byte
  int pn_length = 0;             // 1..4
  u64 packet_number = 0;         // fully reconstructed
  std::size_t header_end = 0;    // first byte of the AEAD ciphertext
  Bytes header;                  // AAD: the header with the PN in the clear
  Bytes payload;                 // the opened plaintext
  std::size_t ciphertext_length = 0;
  std::size_t tag_length = 0;
};

// Open one 1-RTT packet.  `packet` is the whole datagram (or the whole
// coalesced packet), starting at the long/short header; `dcid` is the
// connection ID the receiver would have used, which a short header does not
// carry.  `largest_pn` is the largest packet number already seen on this
// connection, or 0 for the first packet (RFC 9000 section 17.1).
bool quic_decrypt_short(const QuicKeyset& keys, const u8* dcid, std::size_t dcid_len,
                        const u8* packet, std::size_t len, u64 largest_pn, u64* pn,
                        Bytes* payload, std::string* error);

// The same operation, but reporting everything needed to follow a key update
// (the key phase bit) and to byte-compare against a vector (the header, the PN).
bool quic_decrypt_short_full(const QuicKeyset& keys, const u8* dcid, std::size_t dcid_len,
                             const u8* packet, std::size_t len, u64 largest_pn,
                             QuicShortHeader* out, std::string* error);

// ---------------------------------------------------------------------------
// QUIC frames in a 1-RTT payload (RFC 9000 section 19)
//
// `quic.hpp`'s `quic_parse_frames` covers the Initial-only subset.  A 1-RTT
// payload additionally carries STREAM, NEW_CONNECTION_ID, NEW_TOKEN,
// MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS, DATA_BLOCKED and friends, so it gets
// its own walker with a richer frame structure.
// ---------------------------------------------------------------------------

struct QuicStreamFrame {
  u64 stream_id = 0;
  u64 offset = 0;
  u64 length = 0;
  bool fin = false;
  bool has_length = true;
  Bytes data;
};

struct QuicFrameInfo {
  u8 type = 0;
  std::string type_name;
  u64 offset = 0;  // byte offset of the frame inside the payload
  u64 length = 0;  // total bytes the frame occupied, including its type
  Bytes data;      // CRYPTO/STREAM payload, when the frame carries one
  std::string note;
  QuicStreamFrame stream;  // valid when type is 0x08..0x0f
};

bool quic_parse_frames_rtt(const u8* data, std::size_t len, std::vector<QuicFrameInfo>* frames,
                           std::string* error);

// ---------------------------------------------------------------------------
// HTTP/3 framing (RFC 9114)
// ---------------------------------------------------------------------------

constexpr u64 kH3FrameData = 0x00;
constexpr u64 kH3FrameHeaders = 0x01;
constexpr u64 kH3FrameCancelPush = 0x03;
constexpr u64 kH3FrameSettings = 0x04;
constexpr u64 kH3FramePushPromise = 0x05;
constexpr u64 kH3FrameGoaway = 0x07;
constexpr u64 kH3FrameMaxPushId = 0x0d;

constexpr u64 kH3StreamControl = 0x00;
constexpr u64 kH3StreamPush = 0x01;
constexpr u64 kH3StreamQpackEncoder = 0x02;
constexpr u64 kH3StreamQpackDecoder = 0x03;

struct H3Frame {
  u64 type = 0;
  std::string type_name;
  u64 length = 0;
  Bytes payload;
  std::string note;
};

// One unidirectional stream, with its leading stream type consumed.
struct H3UniStream {
  u64 type = 0;             // one of the kH3Stream* constants
  std::string type_name;    // "control", "push", "qpack encoder", "qpack decoder"
  std::string unknown_reason;  // set when `type` is not one of the above
  Bytes body;               // everything after the type varint
  std::vector<H3Frame> frames;
};

// Parse a whole unidirectional stream: a stream-type varint followed by that
// stream's own framing.  A control stream's SETTINGS must be its first frame
// (RFC 9114 section 6.2.1); a push/QPACK-encoder/QPACK-decoder stream has its
// own grammar and is reported from the type alone.
bool h3_parse_uni_stream(const Bytes& stream_bytes, H3UniStream* out, std::string* error);

// Walk HTTP/3 frames out of a byte range.  Used for request streams and for the
// body of a control stream.
bool h3_parse_frames(const u8* data, std::size_t len, std::vector<H3Frame>* frames,
                     std::string* error);

// ---------------------------------------------------------------------------
// QPACK field sections (RFC 9204), static table only
// ---------------------------------------------------------------------------

// RFC 9114 section 4.1: only these two pseudo-header fields are legal in a
// request, and both must be present.
constexpr const char* kH3FieldMethod = ":method";
constexpr const char* kH3FieldScheme = ":scheme";
constexpr const char* kH3FieldAuthority = ":authority";
constexpr const char* kH3FieldPath = ":path";

// Decode one field section.  `Required Insert Count != 0` -- and any encoder
// instruction that would populate the dynamic table -- is refused with an exact
// error, because this decoder never tracks the dynamic table; everything a
// static-table-only encoder emits decodes normally.
bool h3_decode_field_section(const u8* data, std::size_t len,
                             std::vector<std::pair<std::string, std::string>>* out,
                             std::string* error);
bool h3_decode_field_section(const Bytes& data,
                             std::vector<std::pair<std::string, std::string>>* out,
                             std::string* error);

// RFC 9204 appendix A defines exactly 99 static entries, indexed from zero
// (entry 0 is `:authority`, unlike HPACK whose index 0 is invalid).
constexpr std::size_t kH3StaticTableSize = 99;

// The static table and the Huffman code table are exposed so the *writer* can
// use the very same objects the reader uses.  A second transcription would be a
// second chance to mistype a row, and a mistyped Huffman row is invisible until
// one particular byte breaks -- that is exactly how `'>'` came to be wrong in
// `src/http2.cpp` (see the note above `kH3Huff` in `src/h3.cpp`).
//
// `h3_static_entry` returns false (and clears both strings) for an index >= 99.
// `h3_static_name_index` finds the **lowest** static entry with that name, which
// is what a name reference is allowed to point at (name references use the name
// only).  `h3_static_exact_index` finds a full name *and* value match.
bool h3_static_entry(std::size_t index, std::string* name, std::string* value);
bool h3_static_name_index(const std::string& name, std::size_t* index);
bool h3_static_exact_index(const std::string& name, const std::string& value, std::size_t* index);

// One row of RFC 7541 appendix B (the HTTP/2 table, reused verbatim by QPACK).
struct H3HuffmanCode {
  u32 code;
  u8 bits;
};

// Symbols 0..255 are the bytes; symbol 256 is EOS.  Out-of-range symbols return
// the all-zero row instead of reading past the table.
const H3HuffmanCode& h3_huffman_code(std::size_t symbol);

// The reader's Huffman decoder, exposed under a distinct name so a test can
// round-trip the writer's bytes through *this* decoder (and therefore through
// *this* table) rather than through a second copy of either.
bool h3_huffman_decode_bytes(const u8* data, std::size_t len, std::string* out,
                             std::string* error);

// ---------------------------------------------------------------------------
// The entry point the parent session wants: STREAM bytes -> request line
// ---------------------------------------------------------------------------

struct H3Request {
  std::string method;
  std::string authority;
  std::string path;
  std::string scheme;
  std::vector<std::pair<std::string, std::string>> headers;  // non-pseudo only
  bool has_pseudo = false;  // true once all four pseudo-headers were seen
  u64 stream_id = 0;
  bool fin = false;
};

// The two-argument form the brief asks for: a client-initiated bidirectional
// stream, i.e. the prefix is the request-stream varint 0x00.
bool h3_request_from_stream(const Bytes& stream_bytes, bool client_initiated_bidi,
                            H3Request* out, std::string* error);

// Convenience: same thing for a request stream's *bytes after* the stream-type
// varint, when the caller has already established that.
bool h3_request_from_stream(const Bytes& stream_bytes, H3Request* out, std::string* error);

// Pull the request out of a fully assembled STREAM frame: the frame must start
// at offset 0 and be flagged FIN, otherwise the prefix cannot be trusted.
bool h3_request_from_stream_frames(const std::vector<QuicFrameInfo>& frames, H3Request* out,
                                   std::string* error);

// ---------------------------------------------------------------------------
// The same walk, one entry point up: STREAM bytes -> response
//
// A response field section is decoded by the same static-table-only decoder;
// what changes is the pseudo-header it must carry (`:status`) and the fact that
// a response stream also carries DATA.  Re-encoding a response therefore has a
// complete round trip: `h3_encode_response` (in `h3_write.hpp`) writes the
// bytes, this reads them back.
// ---------------------------------------------------------------------------

struct H3Response {
  std::string status;                                        // ":status"
  std::vector<std::pair<std::string, std::string>> headers;  // non-pseudo only
  std::string body;  // DATA frame payloads, concatenated in arrival order
  bool has_status = false;
  bool has_headers = false;   // a HEADERS frame was seen, even an empty one
  bool has_trailers = false;  // a second HEADERS frame (RFC 9114 section 4.1)
  u64 stream_id = 0;
  bool fin = false;
};

// `client_initiated_bidi` is the same test the request path makes: a response
// stream is a client-initiated bidirectional stream, so its prefix is 0x00.
bool h3_response_from_stream(const Bytes& stream_bytes, bool client_initiated_bidi,
                             H3Response* out, std::string* error);

// Convenience: a client-initiated bidirectional stream.
bool h3_response_from_stream(const Bytes& stream_bytes, H3Response* out, std::string* error);

bool h3_selfcheck(std::string* report);

}  // namespace netcap

#endif  // NETCAP_H3_HPP
