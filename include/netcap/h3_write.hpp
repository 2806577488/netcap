// HTTP/3 + QPACK, the writing half.
//
// `h3.hpp` reads: it opens a 1-RTT packet, walks the HTTP/3 frames and decodes a
// field section back to `:method` / `:path`.  This header goes the other way, so
// a response that was modified in flight (advertising CSS injected, elements
// dropped, text replaced) can be re-emitted as HEADERS + DATA frames that fit
// back into the same QUIC stream -- and, because only the payload length
// changes, into the same packet number space.
//
// The encoder is deliberately incapable of the two things that would make a
// passive writer dangerous:
//
//   * it never inserts into, or references, the QPACK **dynamic** table, so it
//     requires no encoder state on the peer and no encoder stream at all;
//   * it never emits anything the reader in `src/h3.cpp` cannot decode, which
//     makes "encode then decode gives the same bytes back" a checkable contract
//     rather than a hope (see `h3_write_selfcheck`).
//
// Everything is literal-only with static-table *name* references (RFC 9204
// section 4.5.4/4.5.6); a name or value the static table does not hold is simply
// written out as a literal, because refusing to encode a header is never the
// right answer for a proxy that must pass the response on.
//
// The tables come from `h3.hpp` (`h3_static_*`, `h3_huffman_code`), so the
// encoder cannot disagree with the decoder about a row.
//
// Error convention, the same one every other header in this project uses: a
// function that returns false has put one lower-case sentence naming the rule
// that was violated into `*error` and has left `*out` empty.  A caller may pass
// `error == nullptr` when it only cares about the boolean.
#ifndef NETCAP_H3_WRITE_HPP
#define NETCAP_H3_WRITE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/h3.hpp"  // reuse its field/frame types where they exist

namespace netcap {

// A field section line.  Values are opaque bytes (HTTP/3 does not require UTF-8).
struct H3Field {
  std::string name;
  std::string value;
};

// ---------------------------------------------------------------------------
// Required API
// ---------------------------------------------------------------------------

// QPACK field-section encoding.  Literal-only with static-table *name*
// references: never emit a dynamic-table reference, and never require the peer
// to have encoder state.  `STATIC_TABLE_SIZE`-aware: fail with a precise error
// instead of emitting an index past the static table.
//
// The output is a complete encoded field section: the field section prefix
// (Required Insert Count = 0, Delta Base = 0, i.e. the two bytes `00 00`) followed
// by one representation per field, in the order given.
//
// Each field is encoded as the shortest static-table form that fits:
//   1. exact (name, value) match  -> Indexed Field Line (RFC 9204 section 4.5.2)
//   2. name-only match            -> Literal Field Line with Name Reference
//                                    (section 4.5.4), lowest matching index
//   3. neither                    -> Literal Field Line with Literal Name
//                                    (section 4.5.6)
// A value is Huffman-coded only when the Huffman form is **strictly** shorter
// (RFC 7541 section 5.2), and the H bit is set to match, in every representation
// that carries a string.
bool qpack_encode_field_section(const std::vector<H3Field>& fields, std::string* out,
                                std::string* error);

// HTTP/3 frames (RFC 9114 section 7.2).  Each writer appends one frame to *out:
// the frame type as a QUIC varint, the payload length as a QUIC varint, then the
// payload.  Appending (rather than replacing) is what lets a caller build
// HEADERS + DATA + ... in one buffer; on failure `*out` is cleared, so a caller
// never mistakes a partially written frame for a complete one.
bool h3_write_headers_frame(const std::string& field_section, std::string* out, std::string* error);
bool h3_write_data_frame(const std::string& body, std::string* out, std::string* error);

// HEADERS + (optional) DATA, i.e. a whole response payload.  The DATA frame is
// omitted when `body` is empty (an empty DATA frame is legal but pointless).
// Note that this is the payload *after* the stream-type varint; use
// `h3_encode_response_stream` when the caller has nothing else to write.
bool h3_encode_response(const std::vector<H3Field>& fields, const std::string& body,
                        std::string* out, std::string* error);

// The QPACK/Huffman encoders in isolation, for tests.
std::string qpack_huffman_encode(const std::string& in);      // RFC 7541 Appendix B codes
bool qpack_huffman_encode(const u8* data, std::size_t len, std::string* out);

bool h3_write_selfcheck(std::string* report);                  // true = all checks passed

// ---------------------------------------------------------------------------
// Additions to the required API (the four signatures above are unchanged)
//
// Two things the brief's API cannot express, both needed by the checks it asks
// for.  Neither changes the meaning of anything above.
// ---------------------------------------------------------------------------

// Which Huffman policy the field-section encoder uses.  `kWhenShorter` is the
// required behaviour and the default of the three-argument overload.
//   * `kNever`  -- reproduce RFC 9204 appendix B.1 byte for byte: that example
//                  illustrates the literal field line with a *raw* value
//                  (`510b2f696e6465782e68746d6c`), and the value's Huffman form
//                  is shorter, so the default encoder legitimately emits the
//                  Huffman form instead.  Byte-exact agreement with a published
//                  vector is worth one extra knob.
//   * `kAlways` -- exercise the H bit on strings whose Huffman form is longer,
//                  which the "strictly shorter" rule would otherwise never
//                  produce.  The reader must still decode them.
enum class QpackHuffman {
  kWhenShorter = 0,
  kNever = 1,
  kAlways = 2,
};

bool qpack_encode_field_section(const std::vector<H3Field>& fields, QpackHuffman huffman,
                                std::string* out, std::string* error);

// HEADERS + (optional) DATA with the client-initiated bidirectional stream-type
// varint (0x00) in front: the complete byte sequence of a response stream, so
// `h3_response_from_stream` can read back exactly what was written.
bool h3_encode_response_stream(const std::vector<H3Field>& fields, const std::string& body,
                               std::string* out, std::string* error);

}  // namespace netcap

#endif  // NETCAP_H3_WRITE_HPP
