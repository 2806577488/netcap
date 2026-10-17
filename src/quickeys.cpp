// QUIC key logs and the equal-length 1-RTT rewrite.  See
// include/netcap/quickeys.hpp for the format, the parsing rules and the
// contract; this file is the implementation.
//
// Everything here is deliberately built on the *public* API of h3.hpp
// (`quic_keyset_from_secret`, the `QuicKeyset` fields, the AEAD helpers from
// crypto.hpp) rather than on h3.cpp's file-local helpers, which have internal
// linkage and cannot be linked to.  Two consequences worth naming:
//   * the ChaCha20 header protection keystream is rebuilt here, and
//   * the connection ID length, which a short header does not carry, is
//     recovered by authentication rather than by assumption.
#include "netcap/quickeys.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "netcap/crypto.hpp"
#include "netcap/h3.hpp"

namespace netcap {
namespace {

constexpr std::size_t kTagLen = 16;    // AEAD tag, both suites (RFC 9001 section 5.3)
constexpr std::size_t kHpSample = 16;  // header protection sample (RFC 9001 section 5.4.2)

// RFC 9000 section 17.2 caps a connection ID at 20 bytes; the lower bound is the
// key-log format's, not the protocol's (a 1-byte id is legal on the wire but
// would make every hex string in the file collide).
constexpr std::size_t kMinConnId = 4;
constexpr std::size_t kMaxConnId = 20;

// RFC 9000 section 17.2: a short header packet is at least 1 + dcid + pn + tag.
constexpr std::size_t kShortHeaderMin = 5;

// The payload of a datagram-sized packet cannot approach this; the limit exists
// so that the arithmetic below cannot wrap and so a caller cannot ask for a
// packet no network could carry.
constexpr std::size_t kMaxPayload = 65535;

struct HeaderSample {
  std::size_t offset = 0;
  u8 bytes[kHpSample] = {0};
};

std::string dec(unsigned long long v) { return std::to_string(v); }

std::string hex_of(const u8* p, std::size_t n) { return to_hex(p, n); }

bool is_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Even length, hex digits only, and at most `max_len` characters.  No separators:
// this is the check the *file* format needs, so "8 bytes of hex" means exactly 16
// hex characters with nothing between them.
bool valid_hex_field(const std::string& s, std::size_t max_len) {
  if (s.empty() || s.size() > max_len || (s.size() % 2) != 0) return false;
  for (char c : s) {
    if (!is_hex_char(c)) return false;
  }
  return true;
}

void split_ws(const std::string& line, std::vector<std::string>* out) {
  out->clear();
  std::size_t i = 0;
  while (i < line.size()) {
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) ++i;
    const std::size_t start = i;
    while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') ++i;
    if (i > start) out->push_back(line.substr(start, i - start));
  }
}

// "QUIC_CLIENT_TRAFFIC_SECRET_0" -> base "QUIC_CLIENT_TRAFFIC_SECRET", gen 0.
// The digits must be a generation suffix (short, no overflow); a label whose
// trailing run is not that is simply not this label.
bool split_generation(const std::string& label, std::string* base, int* generation) {
  std::size_t cut = label.size();
  while (cut > 0 && label[cut - 1] >= '0' && label[cut - 1] <= '9') --cut;
  if (cut == label.size()) {
    if (label.empty() || label[label.size() - 1] != '_') {
      *base = label;
      *generation = 0;
      return true;
    }
    return false;  // a trailing '_' with no digits is not a known label
  }
  if (cut == 0 || label[cut - 1] != '_') return false;
  const std::string digits = label.substr(cut);
  if (digits.size() > 9) return false;
  unsigned long long value = 0;
  for (char c : digits) value = value * 10 + static_cast<unsigned long long>(c - '0');
  if (value > 2000000000ull) return false;
  *base = label.substr(0, cut - 1);
  *generation = static_cast<int>(value);
  return true;
}

// Returns false when the label is not one this module understands.  The caller
// skips such a line: an unrecognised label is never mined for a secret.
bool parse_quic_label(const std::string& label, bool* from_client, std::string* canonical,
                      int* generation) {
  std::string base;
  int gen = 0;
  if (!split_generation(label, &base, &gen)) return false;
  const char* canonical_base = nullptr;
  if (base == "QUIC_CLIENT_TRAFFIC_SECRET" || base == "CLIENT_TRAFFIC_SECRET") {
    canonical_base = "QUIC_CLIENT_TRAFFIC_SECRET";
    *from_client = true;
  } else if (base == "QUIC_SERVER_TRAFFIC_SECRET" || base == "SERVER_TRAFFIC_SECRET") {
    canonical_base = "QUIC_SERVER_TRAFFIC_SECRET";
    *from_client = false;
  } else {
    return false;
  }
  *canonical = std::string(canonical_base) + "_" + std::to_string(gen);
  *generation = gen;
  return true;
}

void drop_from(std::vector<std::string>* files, const std::string& path) {
  for (std::size_t i = 0; i < files->size();) {
    if ((*files)[i] == path) {
      files->erase(files->begin() + static_cast<std::ptrdiff_t>(i));
    } else {
      ++i;
    }
  }
}

// The header protection mask: the ChaCha20-keystream / AES-ECB transform of the
// sample.  RFC 9001 sections 5.4.3 and 5.4.4.
bool hp_mask_from_sample(const QuicKeyset& keys, const u8* sample, u8 out[5], std::string* error) {
  if (!keys.ready) {
    if (error) *error = "quickeys: keyset is not ready -- derive it first with quic_keyset_from_secret";
    return false;
  }
  if (keys.is_chacha20()) {
    // The first four sample bytes are the block counter in little-endian order
    // and the remaining twelve are the nonce -- not the other way round.
    const u32 counter = u32(sample[0]) | (u32(sample[1]) << 8) | (u32(sample[2]) << 16) |
                        (u32(sample[3]) << 24);
    const Bytes nonce(sample + 4, sample + 16);
    const Bytes zeros(16, 0);
    const Bytes ks = chacha20_xor(keys.hp, nonce, counter, zeros);
    if (ks.size() < 5) {
      if (error) *error = "quickeys: chacha20 header protection produced a short keystream";
      return false;
    }
    std::memcpy(out, ks.data(), 5);
    return true;
  }
  Aes aes;
  if (!aes.set_key(keys.hp)) {
    if (error) *error = "quickeys: header protection key is not a valid AES key length";
    return false;
  }
  u8 block[16];
  aes.encrypt_block(sample, block);  // ECB: the sample block, encrypted once
  std::memcpy(out, block, 5);
  return true;
}

// Locate the header protection sample inside a completed packet (header already
// written, packet number still in the clear) and return the 5-byte mask.
bool hp_mask_at(const QuicKeyset& keys, const Bytes& packet, std::size_t pn_offset, u8 out[5],
                std::string* error) {
  const std::size_t at = pn_offset + 4;
  if (packet.size() < at + kHpSample) {
    if (error) {
      *error = "quickeys: a packet with its packet number at offset " + dec(pn_offset) +
               " needs at least " + dec(at + kHpSample) +
               " bytes before header protection can be applied";
    }
    return false;
  }
  return hp_mask_from_sample(keys, packet.data() + at, out, error);
}

// One packet-number byte count: the shortest that carries `pn`, or 4.
int pn_length_for(u64 pn) {
  if (pn <= 0xffu) return 1;
  if (pn <= 0xffffu) return 2;
  if (pn <= 0xffffffu) return 3;
  return 4;
}

// The shared QUIC packet-number recovery (RFC 9000 appendix A.3, the same
// algorithm `src/h3.cpp` uses; it is file-local there, so it is repeated here --
// two callers must never disagree about which packet number a truncated field
// means, and this module only reads it, never re-encodes it).
u64 decode_packet_number(u64 largest_pn, u64 truncated, int pn_length) {
  const u64 expected = largest_pn + 1;
  const u64 win = 1ull << (pn_length * 8);
  const u64 half = win / 2;
  u64 candidate = (expected & ~(win - 1)) | truncated;
  if (candidate + half <= expected && candidate + win < (1ull << 62)) {
    candidate += win;
  } else if (candidate > expected + half && candidate >= win) {
    candidate -= win;
  }
  return candidate;
}

// Nonce = iv XOR the packet number written into the last 8 bytes big-endian
// (RFC 9001 section 5.3).  Both the seal and the local open use this so they
// cannot drift apart.
Bytes make_nonce(const Bytes& iv, u64 packet_number) {
  Bytes nonce = iv;
  for (int i = 0; i < 8 && static_cast<std::size_t>(i) < nonce.size(); ++i) {
    nonce[nonce.size() - 1 - static_cast<std::size_t>(i)] ^=
        static_cast<u8>(packet_number >> (8 * i));
  }
  return nonce;
}

// A local 1-RTT opener.  It deliberately does NOT call
// `quic_decrypt_short_full`: that path unprotects the short-header first byte
// with a four-bit mask (`first ^= mask[0] & 0x0f`, `src/h3.cpp:799`) where
// RFC 9001 figure 6 requires five (`0x1f`), so it disagrees with this module
// about bit 4 of the first byte even though both recover the same packet number
// and payload.  The self-check has to measure THIS module's output, so it opens
// packets with the rule this module seals with.  The AEAD tag is still the
// authority: a wrong mask bit changes the AAD and the tag then fails.
// `pn_out`, when given, receives the full packet number the AEAD actually
// authenticated with.  A rewrite must re-seal with exactly that number: the
// truncated field on the wire only pins the low bytes, so a caller that guesses
// the number instead (say, the smallest one that reproduces the field) builds a
// different nonce and produces a packet no peer can read.
bool open_short_packet(const QuicKeyset& keys, const Bytes& packet, std::size_t dcid_len,
                       u64 largest_pn, QuicShortHeader* out, Bytes* payload, std::string* error,
                       u64* pn_out = nullptr) {
  if (!keys.ready) {
    if (error) *error = "quickeys: keyset is not ready -- derive it first with quic_keyset_from_secret";
    return false;
  }
  if (packet.size() < kShortHeaderMin + kTagLen) {
    if (error) {
      *error = "quickeys: a " + dec(packet.size()) +
               "-byte packet cannot be a 1-RTT packet with a 16-byte AEAD tag";
    }
    return false;
  }
  if ((packet[0] & 0x80u) != 0) {
    if (error) *error = "quickeys: this is a long header packet, not a 1-RTT short header packet";
    return false;
  }
  const std::size_t pn_offset = 1 + dcid_len;
  if (pn_offset + 4 + kHpSample > packet.size()) {
    if (error) {
      *error = "quickeys: a " + dec(packet.size()) +
               "-byte packet is too short to hold a header protection sample " + dec(4) +
               " bytes after the packet number offset";
    }
    return false;
  }
  u8 mask[5] = {0, 0, 0, 0, 0};
  if (!hp_mask_at(keys, packet, pn_offset, mask, error)) return false;

  QuicShortHeader h;
  const u8 first = static_cast<u8>(packet[0] ^ (mask[0] & 0x1fu));
  h.first_byte = packet[0];
  h.first_byte_unprotected = first;
  h.pn_offset = pn_offset;
  h.pn_length = static_cast<int>(first & 0x03u) + 1;
  h.key_phase = (first & 0x04u) != 0;
  h.spin = (first & 0x20u) != 0;
  // `h.header` is the HEADER, not the whole packet: the first byte with its
  // protection removed, the connection ID, and the packet number bytes in the
  // clear.  It has to be exactly `header_end` bytes long, because that is both
  // what a caller re-seals from and what the AEAD authenticates as its
  // associated data -- handing back the ciphertext and tag as "header" would
  // make every re-seal of a packet opened here fail to authenticate.
  h.header.assign(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(pn_offset));
  h.header[0] = first;
  u64 truncated = 0;
  for (int i = 0; i < h.pn_length; ++i) {
    const u8 clear = static_cast<u8>(packet[pn_offset + static_cast<std::size_t>(i)] ^
                                     mask[1 + static_cast<std::size_t>(i)]);
    h.header.push_back(clear);
    truncated = (truncated << 8) | clear;
  }
  h.packet_number = decode_packet_number(largest_pn, truncated, h.pn_length);
  h.header_end = h.header.size();
  if (packet.size() < h.header_end + kTagLen) {
    if (error) *error = "quickeys: the packet is shorter than its header plus the 16-byte AEAD tag";
    return false;
  }
  h.ciphertext_length = packet.size() - h.header_end - kTagLen;
  h.tag_length = kTagLen;

  const Bytes aad(h.header.begin(), h.header.end());
  const Bytes nonce = make_nonce(keys.iv, h.packet_number);
  const Bytes ciphertext(packet.begin() + static_cast<std::ptrdiff_t>(h.header_end),
                         packet.begin() + static_cast<std::ptrdiff_t>(h.header_end + h.ciphertext_length));
  const Bytes tag(packet.begin() + static_cast<std::ptrdiff_t>(h.header_end + h.ciphertext_length),
                  packet.end());
  Bytes plain;
  const bool opened = keys.is_chacha20()
                          ? chacha20_poly1305_decrypt(keys.key, nonce, aad, ciphertext, tag, &plain)
                          : aes_gcm_decrypt(keys.key, nonce, aad, ciphertext, tag, &plain);
  if (!opened) {
    if (error) {
      *error = "quickeys: the packet did not authenticate under this keyset, so it cannot be "
               "rewritten (wrong secret, a key update this caller has not followed, a corrupted "
               "capture, or a connection id length no short header can carry)";
    }
    return false;
  }
  h.payload = plain;
  h.ok = true;
  if (out) *out = h;
  if (payload) *payload = plain;
  if (pn_out) *pn_out = h.packet_number;
  return true;
}

// The shared sealing core.  `hdr` supplies the header bytes (its first
// `pn_offset` bytes), the key phase and the spin bit; everything protected is
// recomputed here.
// `pn_length` is the width of the packet-number field on the wire; 0 means "the
// shortest width that carries `packet_number`".  A rewrite passes the width it
// read from the original packet, because a full packet number larger than its
// own truncated field is normal: RFC 9000 section 17.1 sends only the low 1..4
// bytes, and a rewriter must reproduce exactly those bytes, not the full value.
bool seal_into(const QuicKeyset& keys, const QuicShortHeader& hdr, const Bytes& payload,
               u64 packet_number, Bytes* out, std::string* error, int pn_length = 0) {
  if (!keys.ready) {
    if (error) *error = "quickeys: keyset is not ready -- derive it first with quic_keyset_from_secret";
    return false;
  }
  if (out == nullptr) {
    if (error) *error = "quickeys: quic_seal_short was given a null output";
    return false;
  }
  if (payload.size() > kMaxPayload) {
    if (error) {
      *error = "quickeys: a 1-RTT payload of " + dec(payload.size()) +
               " bytes is beyond anything a datagram can carry";
    }
    return false;
  }
  if (pn_length < 1 || pn_length > 4) pn_length = pn_length_for(packet_number);
  if (hdr.header.size() < hdr.pn_offset || hdr.pn_offset == 0) {
    if (error) {
      *error = "quickeys: the header is " + dec(hdr.header.size()) +
               " bytes, which does not cover a packet number at offset " + dec(hdr.pn_offset);
    }
    return false;
  }

  // The unprotected header: connection id, then the first byte with the key
  // phase and spin bits in place and the packet-number length bits set.
  Bytes header(hdr.header.begin(),
               hdr.header.begin() + static_cast<std::ptrdiff_t>(hdr.pn_offset));
  u8 first = static_cast<u8>(hdr.first_byte_unprotected);
  first = static_cast<u8>(first & 0xfc);  // the low two bits are the PN length
  first = static_cast<u8>(first | (pn_length - 1));
  first = static_cast<u8>(first & 0xbf);  // a short header never has 0x40 clear; fix it set
  first = static_cast<u8>(first | 0x40);
  if (hdr.key_phase) {
    first = static_cast<u8>(first | 0x04);
  } else {
    first = static_cast<u8>(first & ~0x04);
  }
  if (hdr.spin) {
    first = static_cast<u8>(first | 0x20);
  } else {
    first = static_cast<u8>(first & ~0x20);
  }
  header[0] = first;
  for (int i = pn_length - 1; i >= 0; --i) {
    header.push_back(static_cast<u8>(packet_number >> (8 * i)));
  }

  // Nonce = iv XOR the packet number in the last 8 bytes, big-endian.
  Bytes nonce = keys.iv;
  if (nonce.size() != 12) {
    if (error) *error = "quickeys: the packet IV is " + dec(nonce.size()) + " bytes, not 12";
    return false;
  }
  for (int i = 0; i < 8; ++i) {
    nonce[11 - static_cast<std::size_t>(i)] ^= static_cast<u8>(packet_number >> (8 * i));
  }

  const AeadResult sealed = keys.is_chacha20()
                                ? chacha20_poly1305_encrypt(keys.key, nonce, header, payload)
                                : aes_gcm_encrypt(keys.key, nonce, header, payload);
  if (!sealed.ok || sealed.tag.size() != kTagLen) {
    if (error) {
      *error = "quickeys: the AEAD refused to seal a " + dec(payload.size()) +
               "-byte payload (key length " + dec(keys.key.size()) + " bytes)";
    }
    return false;
  }

  // Assemble with the packet number still in the clear, so the header protection
  // sample is read from where it will be in the finished packet.
  Bytes packet = header;
  packet.insert(packet.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
  packet.insert(packet.end(), sealed.tag.begin(), sealed.tag.end());

  u8 mask[5] = {0, 0, 0, 0, 0};
  if (!hp_mask_at(keys, packet, hdr.pn_offset, mask, error)) return false;
  packet[0] = static_cast<u8>(packet[0] ^ (mask[0] & 0x1f));  // short header: 5 low bits
  for (int i = 0; i < pn_length; ++i) {
    const std::size_t at = hdr.pn_offset + static_cast<std::size_t>(i);
    packet[at] = static_cast<u8>(packet[at] ^ mask[1 + i]);
  }
  *out = std::move(packet);
  return true;
}

// One decryption attempt at a fixed connection ID length.  The plaintext length
// is reported so that `quic_reseal_same_pn` can compare it before it commits, and
// the recovered packet number so that it re-seals with the number the AEAD
// actually used.
bool try_open(const QuicKeyset& keys, const Bytes& packet, std::size_t dcid_len, u64 largest_pn,
              QuicShortHeader* out, std::string* error, u64* pn_out) {
  Bytes payload;
  return open_short_packet(keys, packet, dcid_len, largest_pn, out, &payload, error, pn_out);
}

// Open a 1-RTT short header packet with THIS module's header-protection rules.
//
// The self-check cannot use `quic_decrypt_short_full` to verify what this module
// seals, and that is not a preference.  RFC 9001 Figure 6 protects five bits of a
// short header's first byte:
//
//     else:  packet[0] ^= mask[0] & 0x1f
//
// while `src/h3.cpp:799` uses `mask[0] & 0x0f`, four bits.  The repo's own
// decoders therefore read the A.5 packet's wire byte 0x4c as 0x42 even though the
// RFC states the header protection mask is `aefefe7d03` (0x4c ^ 0xae == 0xe2):
// the four-bit mask hides the discrepancy because 0xae and 0x0e share their low
// nibble.  Sealing with the correct five bits and then reading the result back
// with the four-bit rule would fail on exactly the bit the A.5 vector exists to
// pin down, so this helper repeats the RFC's rule rather than borrowing the
// repo's.  `src/h3.cpp` is outside the files this module was allowed to touch.

}  // namespace

// ===========================================================================
// QuicKeyLog: the file format
// ===========================================================================

bool QuicKeyLog::load_file(const std::string& path, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error) *error = "quickeys: cannot open key log \"" + path + "\" for reading";
    return false;
  }
  std::vector<QuicKeyEntry> fresh;
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    // Individually skipped, never fatal: a log being appended to has a partial
    // last line more often than not.
    const std::size_t hash = line.find('#');
    if (hash == 0) continue;
    if (line.empty()) continue;
    std::vector<std::string> fields;
    split_ws(line, &fields);
    if (fields.size() != 3) continue;
    std::string canonical;
    int generation = 0;
    bool from_client = false;
    if (!parse_quic_label(fields[0], &from_client, &canonical, &generation)) continue;
    if (!valid_hex_field(fields[1], 2 * kMaxConnId)) continue;
    if (fields[1].size() < 2 * kMinConnId) continue;
    if (!valid_hex_field(fields[2], 2 * 64)) continue;  // a traffic secret is at most 48 bytes
    QuicKeyEntry entry;
    entry.label = canonical;
    entry.conn_id_hex = to_lower(fields[1]);
    entry.secret = from_hex(fields[1 + 1]);
    entry.from_client = from_client;
    entry.generation = generation;
    entry.source = path;
    fresh.push_back(std::move(entry));
  }
  if (in.bad()) {
    if (error) *error = "quickeys: reading key log \"" + path + "\" failed part way through";
    return false;
  }
  // A re-load of a path replaces what that path contributed and nothing else.
  drop_from(&files_, path);
  for (std::size_t i = 0; i < entries_.size();) {
    if (entries_[i].source == path) {
      entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
    } else {
      ++i;
    }
  }
  files_.push_back(path);
  for (QuicKeyEntry& e : fresh) entries_.push_back(std::move(e));
  return true;
}

bool QuicKeyLog::refresh(const std::string& path, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error) *error = "quickeys: cannot open key log \"" + path + "\" for reading";
    return false;
  }
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> fields;
    split_ws(line, &fields);
    // A half-written final line has too few fields or an odd hex digit; both
    // fall out here, so a read that races the writer still succeeds.
    if (fields.size() != 3) continue;
    std::string canonical;
    int generation = 0;
    bool from_client = false;
    if (!parse_quic_label(fields[0], &from_client, &canonical, &generation)) continue;
    if (!valid_hex_field(fields[1], 2 * kMaxConnId)) continue;
    if (fields[1].size() < 2 * kMinConnId) continue;
    if (!valid_hex_field(fields[2], 2 * 64)) continue;
    const std::string id_hex = to_lower(fields[1]);
    const Bytes secret = from_hex(fields[2]);
    bool known = false;
    for (const QuicKeyEntry& e : entries_) {
      if (e.label == canonical && e.conn_id_hex == id_hex && e.secret == secret) {
        known = true;
        break;
      }
    }
    if (known) continue;
    QuicKeyEntry entry;
    entry.label = canonical;
    entry.conn_id_hex = id_hex;
    entry.secret = secret;
    entry.from_client = from_client;
    entry.generation = generation;
    entry.source = path;
    entries_.push_back(std::move(entry));
  }
  if (in.bad()) {
    if (error) *error = "quickeys: reading key log \"" + path + "\" failed part way through";
    return false;
  }
  bool listed = false;
  for (const std::string& f : files_) {
    if (f == path) listed = true;
  }
  if (!listed) files_.push_back(path);
  return true;
}

std::vector<QuicKeyEntry> QuicKeyLog::find(const Bytes& conn_id) const {
  return find_hex(to_hex(conn_id.data(), conn_id.size()));
}

std::vector<QuicKeyEntry> QuicKeyLog::find_hex(const std::string& conn_id_hex) const {
  const Bytes raw = from_hex(conn_id_hex);  // tolerates spaces, colons and dashes
  const std::string wanted = raw.empty() ? std::string() : to_hex(raw);
  std::vector<QuicKeyEntry> hits;
  if (wanted.size() % 2 != 0) return hits;  // not a hex string at all, so it matches nothing
  for (const QuicKeyEntry& e : entries_) {
    if (e.conn_id_hex == wanted) hits.push_back(e);
  }
  return hits;
}

std::vector<std::string> QuicKeyLog::labels() const {
  std::vector<std::string> out;
  for (const QuicKeyEntry& e : entries_) {
    bool seen = false;
    for (const std::string& s : out) {
      if (s == e.label) seen = true;
    }
    if (!seen) out.push_back(e.label);
  }
  for (std::size_t i = 1; i < out.size(); ++i) {  // insertion sort: a handful of labels
    std::string key = out[i];
    std::size_t j = i;
    while (j > 0 && out[j - 1] > key) {
      out[j] = out[j - 1];
      --j;
    }
    out[j] = key;
  }
  return out;
}

std::string QuicKeyLog::describe() const {
  std::string out = "quickeys: " + dec(files_.size()) + (files_.size() == 1 ? " file, " : " files, ") +
                    dec(entries_.size()) + (entries_.size() == 1 ? " entry" : " entries");
  const std::vector<std::string> names = labels();
  out += names.empty() ? ", no labels" : ", labels";
  for (const std::string& n : names) out += " " + n;
  return out;
}

// ===========================================================================
// Key-log entries -> 1-RTT keysets
// ===========================================================================

bool quic_keysets_from_keylog(const QuicKeyLog& log, const Bytes& original_dcid, u16* suite_out,
                              QuicKeyset* client_keys, QuicKeyset* server_keys,
                              std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  QuicKeyset client_local;
  QuicKeyset server_local;
  if (client_keys == nullptr) client_keys = &client_local;
  if (server_keys == nullptr) server_keys = &server_local;
  *client_keys = QuicKeyset();
  *server_keys = QuicKeyset();

  const std::vector<QuicKeyEntry> hits = log.find(original_dcid);
  if (hits.empty()) {
    *error = "quickeys: the key log has no QUIC entry for connection id " +
             to_hex(original_dcid.data(), original_dcid.size()) + " (" + dec(log.size()) +
             " entries in " + dec(log.files()) + " file(s))";
    return false;
  }

  // A 32-byte secret is ambiguous (AES-128-GCM and ChaCha20-Poly1305 both use
  // one), so the suite is chosen by trying, in a fixed order, and reporting the
  // one that worked.  A 48-byte secret only ever derives under SHA-384, and
  // `quic_keyset_from_secret` refuses it for the others instead of truncating.
  const u16 suites[3] = {kH3TlsAes128GcmSha256, kH3TlsChacha20Poly1305Sha256,
                         kH3TlsAes256GcmSha384};
  const QuicKeyEntry* client = nullptr;
  const QuicKeyEntry* server = nullptr;
  u16 chosen = 0;
  for (u16 suite : suites) {
    const QuicKeyEntry* c = nullptr;
    const QuicKeyEntry* s = nullptr;
    for (const QuicKeyEntry& e : hits) {
      QuicKeyset probe;
      std::string ignored;
      if (!quic_keyset_from_secret(suite, e.secret, &probe, &ignored)) continue;
      if (!probe.ready) continue;
      if (e.from_client && c == nullptr) c = &e;
      if (!e.from_client && s == nullptr) s = &e;
    }
    if (c == nullptr && s == nullptr) continue;
    client = c;
    server = s;
    chosen = suite;
    break;
  }
  if (chosen == 0) {
    *error = "quickeys: " + dec(hits.size()) + " entry(ies) match connection id " +
             to_hex(original_dcid.data(), original_dcid.size()) +
             ", but none carries a secret any known TLS 1.3 suite can expand";
    return false;
  }

  std::string ignored;
  if (client != nullptr) {
    if (!quic_keyset_from_secret(chosen, client->secret, client_keys, &ignored)) {
      *error = "quickeys: the client secret of connection id " +
               to_hex(original_dcid.data(), original_dcid.size()) +
               " would not expand: " + ignored;
      return false;
    }
  }
  if (server != nullptr) {
    if (!quic_keyset_from_secret(chosen, server->secret, server_keys, &ignored)) {
      *error = "quickeys: the server secret of connection id " +
               to_hex(original_dcid.data(), original_dcid.size()) +
               " would not expand: " + ignored;
      return false;
    }
  }
  if (suite_out != nullptr) *suite_out = chosen;
  return true;
}

// ===========================================================================
// Sealing
// ===========================================================================

bool quic_seal_short(const QuicKeyset& keys, const QuicShortHeader& hdr, const Bytes& payload,
                     u64 packet_number, Bytes* packet_out, std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (packet_out == nullptr) {
    *error = "quickeys: quic_seal_short was given a null output";
    return false;
  }
  packet_out->clear();
  // A fresh seal is not a rewrite: the caller supplies the number, so it must fit
  // the declared width.  Refusing is the honest answer -- silently truncating
  // would hand back a packet with a different packet number than the caller
  // asked for.
  const int pn_length = (hdr.pn_length >= 1 && hdr.pn_length <= 4) ? hdr.pn_length : 0;
  if (pn_length != 0 && pn_length < 4 && (packet_number >> (8 * pn_length)) != 0) {
    *error = "quickeys: packet number " + dec(packet_number) + " does not fit in " +
             dec(pn_length) + " bytes";
    return false;
  }
  return seal_into(keys, hdr, payload, packet_number, packet_out, error, pn_length);
}

bool quic_open_short(const QuicKeyset& keys, const Bytes& packet, std::size_t dcid_len,
                     u64 largest_pn, QuicShortHeader* hdr, Bytes* payload_out,
                     std::string* error) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (hdr == nullptr || payload_out == nullptr) {
    *error = "quickeys: quic_open_short needs both a header and a payload output";
    return false;
  }
  QuicShortHeader h;
  Bytes payload;
  if (!open_short_packet(keys, packet, dcid_len, largest_pn, &h, &payload, error, nullptr)) {
    return false;
  }
  *hdr = std::move(h);
  *payload_out = std::move(payload);
  return true;
}

bool quic_reseal_same_pn(const QuicKeyset& keys, const Bytes& packet, const Bytes& new_payload,
                         Bytes* packet_out, std::string* error, u64 largest_pn) {
  std::string error_sink;  // callers may pass nullptr when they ignore the message
  if (error == nullptr) error = &error_sink;
  if (packet_out == nullptr) {
    *error = "quickeys: quic_reseal_same_pn was given a null output";
    return false;
  }
  packet_out->clear();
  if (!keys.ready) {
    *error = "quickeys: keyset is not ready -- derive it first with quic_keyset_from_secret";
    return false;
  }
  if (packet.size() < kShortHeaderMin) {
    *error = "quickeys: a " + dec(packet.size()) +
             "-byte packet is too short to be a 1-RTT packet";
    return false;
  }
  if ((packet[0] & 0x80u) != 0) {
    *error = "quickeys: the packet has the long header bit set, so it is not a 1-RTT short-header "
             "packet (RFC 9000 section 17.2)";
    return false;
  }

  // The connection ID length is not in a short header.  Try the lengths that
  // leave a 16-byte sample inside the packet and keep the one that
  // authenticates: the AEAD is the only oracle that can tell us, and using it is
  // the honest way to recover what the packet does not say.  The recovered
  // length is not kept as a variable -- `hdr.pn_offset` is `1 + dcid_len` and
  // carries it, and the re-seal below reads it from there.  The caller's
  // `largest_pn` is what makes the truncated packet number recoverable; without
  // it the nonce would be built from the wrong full number and the AEAD would
  // refuse, which is the honest outcome rather than a silently wrong packet.
  bool opened = false;
  QuicShortHeader hdr;
  u64 recovered_pn = 0;
  std::string last_error;
  for (std::size_t candidate = 0; candidate <= kMaxConnId; ++candidate) {
    // Only lengths that leave a whole 16-byte header protection sample inside the
    // packet can be the real connection ID length, so the search stops there
    // instead of guessing a length the packet cannot carry.
    if (candidate + 1 + 4 + kHpSample > packet.size()) break;
    QuicShortHeader attempt;
    std::string attempt_error;
    u64 attempt_pn = 0;
    if (try_open(keys, packet, candidate, largest_pn, &attempt, &attempt_error, &attempt_pn)) {
      opened = true;
      hdr = attempt;
      recovered_pn = attempt_pn;
      break;
    }
    last_error = attempt_error;
  }
  if (!opened) {
    *error = "quickeys: the packet did not authenticate under this keyset, so it cannot be "
             "rewritten (wrong secret, a key update this caller has not followed, a corrupted "
             "capture, or a connection id length no short header can carry)";
    if (!last_error.empty()) *error += "; the last attempt said: " + last_error;
    return false;
  }

  // The equal-length rule, checked against the plaintext that was actually in
  // the packet rather than against a caller's claim about it.
  if (new_payload.size() != hdr.payload.size()) {
    *error = "quickeys: a same-length rewrite needs " + dec(hdr.payload.size()) +
             " payload bytes, not " + dec(new_payload.size()) +
             "; anything else moves the packet number or the ACK space";
    return false;
  }

  // Same header bits, same packet number, same packet-number length.
  QuicShortHeader out_header;
  out_header.pn_offset = hdr.pn_offset;
  out_header.pn_length = hdr.pn_length;
  out_header.key_phase = hdr.key_phase;
  out_header.spin = hdr.spin;
  out_header.first_byte_unprotected = hdr.first_byte_unprotected;
  out_header.header = hdr.header;
  // `recovered_pn` rather than the number the caller never supplied: the packet
  // number is not in a short header in full, so the only honest value to re-seal
  // with is the one the original packet's AEAD authenticated.
  if (!seal_into(keys, out_header, new_payload, recovered_pn, packet_out, error,
                 hdr.pn_length)) {
    packet_out->clear();
    return false;
  }
  if (packet_out->size() != packet.size()) {
    *error = "quickeys: the rewrite changed the packet length from " + dec(packet.size()) +
             " to " + dec(packet_out->size()) + " bytes, which must never happen";
    packet_out->clear();
    return false;
  }
  return true;
}

// ===========================================================================
// Self-check
// ===========================================================================

namespace {

// One line per group, in the same shape `h3_selfcheck` uses: the report ends on
// "FAIL <group>: <detail>" and the return value is "no failure line".
bool report_ok(const std::string& report) { return report.find("FAIL ") == std::string::npos; }

void line_ok(std::string* report, const std::string& group) {
  *report += "ok   " + group + "\n";
}

void line_fail(std::string* report, const std::string& group, const std::string& detail) {
  *report += "FAIL " + group + ": " + detail + "\n";
}

bool write_text(const std::string& path, const std::string& text, std::string* error) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    *error = "cannot create \"" + path + "\"";
    return false;
  }
  out << text;
  if (!out) {
    *error = "writing \"" + path + "\" failed";
    return false;
  }
  return true;
}

bool append_text(const std::string& path, const std::string& text, std::string* error) {
  std::ofstream out(path, std::ios::binary | std::ios::app);
  if (!out) {
    *error = "cannot append to \"" + path + "\"";
    return false;
  }
  out << text;
  if (!out) {
    *error = "appending to \"" + path + "\" failed";
    return false;
  }
  return true;
}

}  // namespace

bool quickeys_selfcheck(std::string* report) {
  std::string local;
  if (report == nullptr) report = &local;
  report->clear();

  // Scratch files from an earlier run must not leak into this one: check 1 writes
  // Each check owns its own log file.  They used to share one fixed path, which
  // meant a file left behind by an earlier run -- or by the other check -- was
  // read as this run's input and every count drifted.
  for (const char* name : {"parse_once.log", "merge_append.log"}) {
    std::error_code removed;
    std::filesystem::remove(std::string("_qk/") + name, removed);
  }

  const std::string a5_hex = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";
  const std::string a5_secret = "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b";
  const std::string client_id = "8394c8f03e515708";
  const std::string client_secret =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

  // -----------------------------------------------------------------
  // 1. The parser: a synthetic key log with one good line, a comment, a
  //    malformed line and a TLS line that must be skipped.
  // -----------------------------------------------------------------
  {
    const std::string group = "key log: one QUIC line parses; comment, malformed and TLS lines are skipped";
    std::string err;
    const std::string dir = "_qk";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const std::string path = dir + "/parse_once.log";
    std::string text = "# a comment, ignored\n";
    text += "\n";
    text += "QUIC_CLIENT_TRAFFIC_SECRET_0 " + client_id + " " + client_secret + "\n";
    text += "QUIC_CLIENT_TRAFFIC_SECRET_0 8394c8f03e51570\n";              // no secret
    text += "QUIC_CLIENT_TRAFFIC_SECRET_0 8394c8f03e515708 zznothexzz\n";   // not hex
    text += "QUIC_CLIENT_TRAFFIC_SECRET_0 83 zz00\n";                       // id too short
    text += "SERVER_HANDSHAKE_TRAFFIC_SECRET " + client_id + " " + client_secret + "\n";
    // The short spellings some browsers write, plus a generation suffix.  Both
    // lines carry the FIRST line's connection id on purpose, so check 1 also
    // proves find_hex() returns every match instead of the first one.  They reuse
    // `client_secret` rather than spelling a second 64-character literal: one
    // miscounted digit in a hand-written literal silently turns the line into a
    // 65-character non-secret and the parser then drops it.
    text += "CLIENT_TRAFFIC_SECRET_0 " + client_id + " " + client_secret + "\n";
    text += "QUIC_SERVER_TRAFFIC_SECRET_2 " + client_id + " " + client_secret + "\n";
    if (!write_text(path, text, &err)) {
      line_fail(report, group, err);
    } else {
      QuicKeyLog log;
      std::size_t bad = 0;
      if (!log.load_file(path, &err)) {
        line_fail(report, group, err);
        bad = 1;
      }
      if (bad == 0 && log.files() != 1) {
        line_fail(report, group, "files() is " + dec(log.files()) + ", not 1");
      } else if (bad == 0 && log.size() != 3) {
        // Three lines carry a usable traffic secret: the QUIC client line, the
        // short client spelling, and the generation-2 server line.  The other six
        // are skipped on purpose (handshake label, no secret, bad hex, short id,
        // 32-byte field where a connection id belongs).
        line_fail(report, group, "size() is " + dec(log.size()) + ", not the 3 good lines");
      } else if (bad == 0) {
        const std::vector<QuicKeyEntry> hits = log.find_hex(client_id);
        const std::vector<QuicKeyEntry> upper = log.find_hex(to_lower(client_id));
        const std::vector<QuicKeyEntry> by_bytes = log.find(from_hex(client_id));
        const std::vector<QuicKeyEntry> absent = log.find_hex("0011223344556677");
        const std::vector<std::string> names = log.labels();
        // All three accepted lines carry the same connection id, so find_hex has
        // to return all three -- the two generation-0 client entries (one spelled
        // QUIC_CLIENT_..., one spelled CLIENT_...) and the generation-2 server
        // entry.  A parser that returned only the first match would leave us one
        // key-update secret short at a key update.
        const bool gen_ok = hits.size() == 3 && hits[0].generation == 0 &&
                            hits[1].generation == 0 && hits[2].generation == 2 &&
                            hits[0].from_client && hits[1].from_client &&
                            !hits[2].from_client;
        if (hits.size() != 3) {
          line_fail(report, group,
                    "connection id " + client_id + " matched " + dec(hits.size()) +
                        " entries, not 3 -- the TLS line or the short-spelling line was lost");
        } else if (!gen_ok) {
          line_fail(report, group, "the generation numbers or directions were read wrong");
        } else if (upper.size() != hits.size() || by_bytes.size() != hits.size()) {
          line_fail(report, group, "find_hex / find disagree about the same connection id");
        } else if (!absent.empty()) {
          line_fail(report, group, "an unknown connection id matched something");
        } else if (names.size() != 2 ||
                   names[0] != "QUIC_CLIENT_TRAFFIC_SECRET_0" ||
                   names[1] != "QUIC_SERVER_TRAFFIC_SECRET_2") {
          line_fail(report, group, "labels() did not return the two distinct labels, sorted");
        } else {
          bool id_lower = true;
          bool secret_ok = false;
          for (const QuicKeyEntry& e : log.entries()) {
            if (e.conn_id_hex != client_id) id_lower = false;
            if (e.secret == from_hex(client_secret)) secret_ok = true;
          }
          if (!id_lower) {
            line_fail(report, group, "a connection id was not stored as lowercase hex");
          } else if (!secret_ok) {
            line_fail(report, group, "the secret bytes do not match the hex in the file");
          } else {
            line_ok(report, group);
          }
        }
      }
    }

    // -----------------------------------------------------------------
    // 2. refresh(): a line appended after the first load must join the set
    //    without dropping anything, and a repeat read must not double it.
    // -----------------------------------------------------------------
    const std::string group2 = "refresh: an appended line is picked up and old entries survive";
    const std::string merge_path = dir + "/merge_append.log";
    const std::string first_line = "QUIC_CLIENT_TRAFFIC_SECRET_0 " + client_id + " " + client_secret + "\n";
    if (!write_text(merge_path, first_line, &err)) {
      line_fail(report, group2, err);
    } else {
      QuicKeyLog log;
      if (!log.load_file(merge_path, &err)) {
        line_fail(report, group2, err);
      } else {
        // The log is one line when it is first read; the browser appends the
        // second line while we are looking at it, and only `refresh()` may see
        // it.  Loading after the append would hide whether refresh() merges.
        const std::size_t before = log.size();
        const std::string appended = "QUIC_SERVER_TRAFFIC_SECRET_0 0011223344556677 " +
                                     std::string("ab") + std::string(62, 'c') + "\n";
        if (before != 1) {
          line_fail(report, group2, "the first load saw " + dec(before) + " entries, not 1");
        } else if (!append_text(merge_path, appended, &err)) {
          line_fail(report, group2, err);
        } else if (!log.refresh(merge_path, &err)) {
          line_fail(report, group2, err);
        } else if (log.size() != before + 1) {
          line_fail(report, group2,
                    "size() went from " + dec(before) + " to " + dec(log.size()) +
                        " after appending one line");
        } else if (log.find_hex("0011223344556677").size() != 1) {
          line_fail(report, group2, "the appended line did not become findable");
        } else if (!log.refresh(merge_path, &err) || log.size() != before + 1) {
          line_fail(report, group2, "re-refreshing the same file changed the entry count");
        } else if (log.files() != 1) {
          line_fail(report, group2, "files() is " + dec(log.files()) + " after a merge");
        } else {
          // A half-written final line must be dropped, not fatal.
          if (!append_text(merge_path, "QUIC_CLIENT_TRAFFIC_SECRET_0 8394c8f03e51", &err)) {
            line_fail(report, group2, err);
          } else if (!log.refresh(merge_path, &err) || log.size() != before + 1) {
            line_fail(report, group2, "a half-written final line was not ignored");
          } else {
            line_ok(report, group2);
          }
        }
      }
    }
  }

  // -----------------------------------------------------------------
  // 3. The A.5 round trip: decrypt the RFC packet, re-seal the identical
  //    payload under the identical packet number, demand identical bytes.
  // -----------------------------------------------------------------
  {
    const std::string group = "RFC 9001 A.5: decrypt, re-seal the same payload, bytes identical";
    std::string err;
    const Bytes packet = from_hex(a5_hex);
    QuicKeyset keys;
    if (!quic_keyset_from_secret(kH3TlsChacha20Poly1305Sha256, from_hex(a5_secret), &keys, &err)) {
      line_fail(report, group, err);
    } else if (packet.size() != 21) {
      line_fail(report, group, "the embedded A.5 packet is " + dec(packet.size()) + " bytes, not 21");
    } else {
      // The vector states pn 654360564 but carries only its low 24 bits, so the
      // receiver's window has to be inside the same 2^24 block.
      constexpr u64 kA5LargestPn = 654360563u;
      QuicShortHeader hdr;
      Bytes opened;
      if (!open_short_packet(keys, packet, 0, kA5LargestPn, &hdr, &opened, &err)) {
        line_fail(report, group, "the A.5 packet did not open: " + err);
      } else if (to_hex(opened) != "01" || hdr.packet_number != 654360564u) {
        line_fail(report, group,
                  "the A.5 packet opened to pn " + dec(hdr.packet_number) + " / payload " +
                      hex_of(opened.data(), opened.size()) + ", not pn 654360564 / 01");
      } else {
        Bytes again;
        if (!quic_reseal_same_pn(keys, packet, opened, &again, &err, kA5LargestPn)) {
          line_fail(report, group, "re-sealing the original payload failed: " + err);
        } else if (again != packet) {
          line_fail(report, group,
                    "the re-sealed packet is " + dec(again.size()) + " bytes (" +
                        hex_of(again.data(), again.size()) + "), not byte-identical to " + a5_hex);
        } else {
          line_ok(report, group);
        }
      }

      // A modified payload of the same length must survive a round trip.
      const std::string group3 = "equal-length rewrite: a changed payload re-seals and re-opens";
      Bytes changed = opened;
      changed[0] = static_cast<u8>(changed[0] ^ 0x01);  // PING (0x01) -> 0x00, still one frame
      Bytes swapped;
      if (!quic_reseal_same_pn(keys, packet, changed, &swapped, &err, kA5LargestPn)) {
        line_fail(report, group3, "the equal-length rewrite was refused: " + err);
      } else if (swapped.size() != packet.size()) {
        line_fail(report, group3, "the rewrite changed the packet length");
      } else if (swapped == packet) {
        line_fail(report, group3, "the rewrite returned the input unchanged");
      } else {
        QuicShortHeader re;
        Bytes re_payload;
        if (!open_short_packet(keys, swapped, 0, kA5LargestPn, &re, &re_payload, &err)) {
          line_fail(report, group3, "the rewritten packet did not open: " + err);
        } else if (re_payload != changed || re.packet_number != hdr.packet_number ||
                   re.pn_length != hdr.pn_length || re.key_phase != hdr.key_phase) {
          line_fail(report, group3, "the rewritten packet opened to different contents");
        } else {
          line_ok(report, group3);
        }
      }

      // The refusals: length, corruption, wrong secret, long header.
      const std::string group4 = "refusals: wrong length, corrupted packet, wrong secret, long header";
      Bytes too_long = opened;
      too_long.push_back(0x00);
      Bytes out;
      std::string e1;
      const bool refused_len =
          !quic_reseal_same_pn(keys, packet, too_long, &out, &e1, kA5LargestPn);
      Bytes corrupted = packet;
      corrupted[corrupted.size() - 1] = static_cast<u8>(corrupted[corrupted.size() - 1] ^ 0x80);
      std::string e2;
      const bool refused_corrupt =
          !quic_reseal_same_pn(keys, corrupted, opened, &out, &e2, kA5LargestPn);
      QuicKeyset wrong;
      std::string e3;
      const bool wrong_ready = quic_keyset_from_secret(
          kH3TlsChacha20Poly1305Sha256,
          from_hex("0000000000000000000000000000000000000000000000000000000000000042"), &wrong, &e3);
      const bool refused_secret =
          !wrong_ready || !quic_reseal_same_pn(wrong, packet, opened, &out, &e3, kA5LargestPn);
      Bytes long_header = packet;
      long_header[0] = static_cast<u8>(long_header[0] | 0x80);
      std::string e4;
      const bool refused_long =
          !quic_reseal_same_pn(keys, long_header, opened, &out, &e4, kA5LargestPn);
      if (!refused_len || !refused_corrupt || !refused_secret || !refused_long) {
        line_fail(report, group4,
                  "a rewrite that should have been refused was not (length " +
                      std::string(refused_len ? "ok" : "accepted") + ", corrupt " +
                      std::string(refused_corrupt ? "ok" : "accepted") + ", wrong secret " +
                      std::string(refused_secret ? "ok" : "accepted") + ", long header " +
                      std::string(refused_long ? "ok" : "accepted") + ")");
      } else if (e1.find("same-length rewrite") == std::string::npos ||
                 e2.find("did not authenticate") == std::string::npos ||
                 e4.find("long header bit") == std::string::npos) {
        line_fail(report, group4, "a refusal carried the wrong reason: " + e1 + " | " + e2 + " | " + e4);
      } else {
        line_ok(report, group4);
      }

      // A freshly sealed packet of every packet-number length, both key phases.
      const std::string group5 = "seal: every packet-number length and both key phases round trip";
      bool all_ok = true;
      std::string detail;
      for (int pn_length = 1; pn_length <= 4 && all_ok; ++pn_length) {
        for (int phase = 0; phase <= 1 && all_ok; ++phase) {
          // Every packet-number length, both key phases, and a value that
          // genuinely needs the width being tested: it fills the whole field, so
          // the re-encoded field length must come back the same.  The top bit of
          // the top byte is set (a value below 2^(8*n-8) would fit in fewer
          // bytes and `quic_seal_short` would refuse it for `pn_length` 1).
          const u64 pn = (static_cast<u64>(0xc0) << (8 * (pn_length - 1))) |
                         static_cast<u64>(phase);
          Bytes body = from_hex("0102030405060708090a0b0c");
          body[0] = static_cast<u8>(body[0] + pn_length);  // a distinct plaintext per case
          QuicShortHeader made;
          made.pn_offset = 8;
          made.pn_length = pn_length;
          made.key_phase = phase != 0;
          made.spin = phase != 0;
          made.first_byte_unprotected = 0x40;
          made.header = Bytes(8, 0xab);
          Bytes sealed;
          std::string serr;
          if (!quic_seal_short(keys, made, body, pn, &sealed, &serr)) {
            all_ok = false;
            detail = "sealing pn_length " + dec(pn_length) + " failed: " + serr;
            break;
          }
          // pn_offset bytes of header, then the packet number field, the sealed
          // payload, and the tag: `pn_offset` already counts the first byte.
          if (sealed.size() != made.pn_offset + static_cast<std::size_t>(pn_length) +
                                   body.size() + kTagLen) {
            all_ok = false;
            detail = "a sealed packet is " + dec(sealed.size()) + " bytes, not " +
                     dec(made.pn_offset + static_cast<std::size_t>(pn_length) + body.size() +
                         kTagLen) +
                     " (pn_length " + dec(pn_length) + ", phase " + dec(phase) + ")";
            break;
          }
          QuicShortHeader rt;
          Bytes rt_payload;
          // The connection ID length is `pn_offset - 1`, because `pn_offset`
          // counts the first byte as well: `made.header` is 8 bytes here, so the
          // id it stands for is 7 bytes and the packet number sits at offset 8.
          // Passing 8 instead would move the number to offset 9 and read the
          // header protection sample one byte past where the seal read it, so
          // the mask would differ and the packet could never authenticate.
          const std::size_t reopen_dcid = made.pn_offset - 1;
          if (!open_short_packet(keys, sealed, reopen_dcid, pn - 1, &rt, &rt_payload, &serr)) {
            all_ok = false;
            detail = "re-opening pn_length " + dec(pn_length) + " phase " + dec(phase) +
                     " (pn " + dec(pn) + ", sealed " + to_hex(sealed) + ") failed: " + serr;
            break;
          }          if (rt_payload != body || rt.packet_number != pn || rt.pn_length != pn_length ||
              rt.key_phase != (phase != 0) || rt.spin != (phase != 0)) {
            all_ok = false;
            detail = "the round trip lost a header bit or a payload byte";
          }
        }
      }
      if (all_ok) {
        line_ok(report, group5);
      } else {
        line_fail(report, group5, detail);
      }
    }
  }

  return report_ok(*report);
}

}  // namespace netcap
