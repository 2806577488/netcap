// Rewriting inside QUIC without terminating it.
//
// Deleting is easy: a datagram that is not forwarded is a request that never
// happened (that is what `src/tunpipe.cpp` already does for a blocked name).
// *Changing* something is the hard half, because a QUIC packet is protected in
// two ways at once:
//
//   * the AEAD tag covers the unprotected header as associated data, and the
//     header protection mask is sampled from the ciphertext, so a new payload
//     means re-sealing -- and therefore re-applying header protection;
//   * the packet number lives in that header, and the nonce is derived from it,
//     so we may only re-seal *the same* packet number.  A packet that grew
//     would also have to move the packet number and consume flow-control
//     credit the server never granted.
//
// The way out is the same one HTTP/1.1 gives us: shrink the payload, then pad
// it back to exactly the original length with PADDING frames (RFC 9000
// section 19.1).  The result is a packet the server accepts as the one the
// client sent, with a different request inside it.  Note what this buys: no
// retransmission, no stream offset moves, no extra bytes on the wire, and the
// server's flow-control accounting never notices.
//
// The asymmetry is real and worth stating: we can delete and we can rewrite
// something into *less* space, but we can never make a datagram longer.  When a
// rewrite does not fit, the honest answer is to leave the packet alone.
#ifndef NETCAP_QUIC_REWRITE_HPP
#define NETCAP_QUIC_REWRITE_HPP

#include "netcap/common.hpp"
#include "netcap/h3.hpp"
#include "netcap/quickeys.hpp"
#include "netcap/rules.hpp"

namespace netcap {

// What a successful rewrite did, for the event log.
struct QuicRewriteResult {
  bool rewritten = false;  // `out` holds a replacement packet when true
  std::string url;         // what the client asked for
  std::string new_path;    // what we put in its place
  std::string rule;        // the rule that asked for the change (raw text)
  std::string note;        // one honest line, safe to print
};

// Edit one HTTP/3 request inside one 1-RTT datagram.
//
// `keys` is the client's 1-RTT key set, `dcid_len` the connection ID length the
// opener needs for a short header, `largest_pn` the largest packet number seen
// so far on this connection (for packet-number reconstruction).
//
// Returns false only on a real error (with `*error` filled in).  Returns true
// with `result->rewritten == false` when there was nothing to change -- no
// request we could parse, no rule that wanted a change, or a change that does
// not fit in the original length.  When it returns true with
// `result->rewritten == true`, `out` is the replacement datagram, it is exactly
// `len` bytes, and it has already been opened and re-parsed successfully.
bool quic_rewrite_request(const QuicKeyset& keys, std::size_t dcid_len, const u8* packet,
                          std::size_t len, u64 largest_pn, const RuleSet& rules, Bytes* out,
                          QuicRewriteResult* result, std::string* error);

// Drop one query parameter from a path, keeping the rest in order.  Exposed
// because the QUIC path and the HTTP/1.1 path must agree byte for byte on what
// `$removeparam` means.
std::string quic_strip_query_parameter(const std::string& path, const std::string& name);

// Round trips a synthesised 1-RTT request through the rewrite: sealing, opening,
// editing, padding, re-sealing, re-opening, and the two refusals (no rule, does
// not fit).  Kept next to the code it proves, like the other self-checks.
bool quic_rewrite_selfcheck(std::string* report);

}  // namespace netcap

#endif  // NETCAP_QUIC_REWRITE_HPP
