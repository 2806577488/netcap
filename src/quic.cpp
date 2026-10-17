// QUIC Initial packet parsing: RFC 9000 packet layout, RFC 9001 Initial packet
// protection, RFC 9369 version 2, plus ClientHello extraction.
//
// Everything in here is file-local apart from the declarations in
// include/netcap/quic.hpp.  The only external pieces used are netcap/crypto.hpp
// (SHA-256, HMAC-SHA-256, HKDF, AES, AES-GCM) and netcap/tls.hpp's
// tls_parse_client_hello(), which already implements the TLS extension walk --
// duplicating it here would just give the two copies a chance to disagree.
//
// Deliberate scope limits, each of which produces an explicit error string:
//   * short header packets, Retry, 0-RTT and version negotiation packets;
//   * ChaCha20 header protection (only reachable when a peer picks a ChaCha20
//     cipher suite, which never happens for an Initial packet);
//   * QUIC versions other than 1 and 2;
//   * frames whose type we cannot walk without risking a wrong offset (we stop
//     and report rather than guess).
#include "netcap/quic.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

#include "netcap/tls.hpp"

namespace netcap {
namespace {

// ------------------------------------------------------------------ constants

// RFC 9001 section 5.2: initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
constexpr u8 kSaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
// RFC 9369 section 3.1: initial_salt = 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
constexpr u8 kSaltV2[20] = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                            0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

constexpr u16 kTlsHkdfSha256 = 0x0001;
constexpr u16 kTlsAes128Gcm = 0x1301;

// ------------------------------------------------------------------ small helpers

bool version_known(u32 v) { return v == kQuicV1 || v == kQuicV2; }

const char* version_name(u32 v) {
  switch (v) {
    case kQuicV1: return "QUICv1";
    case kQuicV2: return "QUICv2";
    case 0: return "version negotiation";
    default: return "unknown";
  }
}

// The long header type bits sit in different places in v1 and v2 (RFC 9369
// section 3.2 moved them so that the v1 Retry type becomes a reserved value).
// Both layouts still put the packet type in the top two bits of the first byte.
u8 decode_packet_type(u8 first_byte, bool v2) {
  const u8 raw = u8((first_byte >> 4) & 0x03);
  if (!v2) return raw;
  // RFC 9369 section 3.2 renumbered the v2 long header types, so the same two
  // bits mean something different: 0 Retry, 1 Initial, 2 0-RTT, 3 Handshake.
  switch (raw) {
    case 0: return kQuicTypeRetry;
    case 1: return kQuicTypeInitial;
    case 2: return kQuicTypeZeroRtt;
    default: return kQuicTypeHandshake;
  }
}

const char* packet_type_name(u8 t) {
  switch (t) {
    case kQuicTypeInitial: return "Initial";
    case kQuicTypeZeroRtt: return "0-RTT";
    case kQuicTypeHandshake: return "Handshake";
    case kQuicTypeRetry: return "Retry";
    default: return "?";
  }
}

// RFC 9001 section 5.2: the Initial packet number space always uses AES-128-GCM
// for AEAD and AES-128-ECB for header protection, in both QUIC versions.
constexpr std::size_t kKeyLen = 16;
constexpr std::size_t kIvLen = 12;

// Nonce construction, RFC 9001 section 5.3: the packet number is left-padded to
// the IV length and XORed in.
Bytes initial_nonce(const Bytes& iv, u64 packet_number) {
  Bytes nonce = iv;
  for (std::size_t i = 0; i < 8; ++i) {
    nonce[nonce.size() - 1 - i] ^= u8(packet_number >> (8 * i));
  }
  return nonce;
}

// RFC 9000 section 17.1: the first byte's low two bits are pn_length - 1, and
// the second-lowest bit must be set on every protected long header packet.
int header_pn_length(u8 first_byte) { return int(first_byte & 0x03) + 1; }
bool header_reserved_bit_set(u8 first_byte) { return (first_byte & 0x04) != 0; }

// RFC 9000 section A.2 packet number decoding.  `largest_acked` is the largest
// packet number the receiver has already processed (0 in a test).
bool decode_packet_number(u64 largest_acked, u64 truncated, int pn_length, u64* out,
                          std::string* error) {
  const u64 expected = largest_acked + 1;
  const u64 window = u64(1) << (pn_length * 8);
  const u64 half = window / 2;
  const u64 mask = window - 1;
  if (truncated > mask) {
    if (error) *error = "packet number does not fit its encoded length";
    return false;
  }
  if (expected > half) {
    const u64 candidate = (expected & ~mask) | truncated;
    if (candidate <= expected - half && candidate < (u64(1) << 62) - window) {
      *out = candidate + window;
      return true;
    }
  }
  *out = (expected & ~mask) | truncated;
  return true;
}

// RFC 9001 section 5.4.1: mask = AES-ECB(hp_key, sample), applied to the low
// four bits of the first byte and to every packet-number byte.
bool header_mask(const QuicInitialKeys& keys, const u8* sample, u8 mask[5], std::string* error) {
  Aes hp;
  if (!hp.set_key(keys.hp)) {
    if (error) *error = "header protection key is not a legal AES key length";
    return false;
  }
  u8 block[16];
  hp.encrypt_block(sample, block);
  std::memcpy(mask, block, 5);
  return true;
}

}  // namespace

// ------------------------------------------------------------------ varints

bool quic_varint(const u8* data, std::size_t len, u64* out, std::size_t* used) {
  if (len == 0) return false;
  const std::size_t size = std::size_t(1) << (data[0] >> 6);  // 1, 2, 4 or 8
  if (len < size) return false;
  u64 v = u64(data[0] & 0x3f);
  for (std::size_t i = 1; i < size; ++i) v = (v << 8) | u64(data[i]);
  if (out) *out = v;
  if (used) *used = size;
  return true;
}

bool quic_varint(const Bytes& b, std::size_t off, u64* out, std::size_t* used) {
  if (off > b.size()) return false;
  return quic_varint(b.data() + off, b.size() - off, out, used);
}

void quic_varint_put(Bytes* out, u64 v) {
  if (out == nullptr) return;
  if (v < 64) {
    out->push_back(u8(v));
  } else if (v < 16384) {
    out->push_back(u8(0x40 | (v >> 8)));
    out->push_back(u8(v));
  } else if (v < 1073741824ULL) {
    out->push_back(u8(0x80 | (v >> 24)));
    out->push_back(u8(v >> 16));
    out->push_back(u8(v >> 8));
    out->push_back(u8(v));
  } else {
    out->push_back(u8(0xc0 | (v >> 56)));
    for (int s = 48; s >= 0; s -= 8) out->push_back(u8(v >> s));
  }
}

// ------------------------------------------------------------------ keys

bool QuicInitialKeys::set_hp_cipher(Aes* out) const {
  if (out == nullptr || !ready) return false;
  return out->set_key(hp);
}

bool derive_initial_keys(const u8* dcid, std::size_t dcid_len, u32 version,
                         QuicInitialSide side, QuicInitialKeys* out) {
  auto fail = [&](const std::string& why) {
    if (out) {
      out->ready = false;
      out->error = why;
      out->secret.clear();
      out->key.clear();
      out->iv.clear();
      out->hp.clear();
    }
    return false;
  };
  if (out == nullptr) return false;
  if (!version_known(version)) {
    char buf[96];
    std::snprintf(buf, sizeof(buf),
                  "QUIC version 0x%08x is not Initial-derivable (only 0x00000001 v1 and "
                  "0x6b3343cf v2 are implemented)",
                  unsigned(version));
    return fail(buf);
  }
  if (dcid == nullptr || dcid_len == 0) return fail("empty Destination Connection ID");

  const u8* salt = (version == kQuicV2) ? kSaltV2 : kSaltV1;
  const Bytes initial_secret = hkdf_extract(Bytes(salt, salt + 20), Bytes(dcid, dcid + dcid_len));

  const bool v2 = (version == kQuicV2);
  const std::string in_label = (side == QuicInitialSide::Client) ? "client in" : "server in";
  const std::string key_label = v2 ? "quicv2 key" : "quic key";
  const std::string iv_label = v2 ? "quicv2 iv" : "quic iv";
  const std::string hp_label = v2 ? "quicv2 hp" : "quic hp";

  out->version = version;
  out->side = side;
  out->secret = hkdf_expand_label(initial_secret, in_label, Bytes{}, 32);
  out->key = hkdf_expand_label(out->secret, key_label, Bytes{}, kKeyLen);
  out->iv = hkdf_expand_label(out->secret, iv_label, Bytes{}, kIvLen);
  out->hp = hkdf_expand_label(out->secret, hp_label, Bytes{}, kKeyLen);
  out->error.clear();
  out->ready = true;
  return true;
}

// ------------------------------------------------------------------ header

bool quic_parse_initial_header(const u8* data, std::size_t len, u64 largest_acked,
                               const QuicInitialKeys& keys, QuicInitialHeader* out) {
  auto fail = [&](const std::string& why) {
    if (out) {
      out->ok = false;
      out->error = why;
    }
    return false;
  };
  if (out == nullptr) return false;
  *out = QuicInitialHeader{};
  if (data == nullptr) return fail("no packet data");
  if (len < kQuicMinInitialSize) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "packet is %zu bytes, an Initial packet is at least %zu",
                  len, kQuicMinInitialSize);
    return fail(buf);
  }
  if ((data[0] & 0x80) == 0) return fail("not a long header packet (short header / no fixed bit)");
  if ((data[0] & 0x40) == 0) return fail("fixed bit is clear: not a QUIC packet");

  out->first_byte = data[0];
  out->version = rd32be(data + 1);
  out->is_v2 = (out->version == kQuicV2);
  if (!version_known(out->version)) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "QUIC version 0x%08x is not supported (%s); only 0x00000001 (v1) and "
                  "0x6b3343cf (v2) are implemented",
                  unsigned(out->version), version_name(out->version));
    return fail(buf);
  }
  out->packet_type = decode_packet_type(data[0], out->is_v2);
  if (out->packet_type != kQuicTypeInitial) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "long header type is %s, not Initial",
                  packet_type_name(out->packet_type));
    return fail(buf);
  }

  std::size_t p = 5;
  const std::size_t dcid_len = data[p++];
  if (dcid_len > 20) return fail("Destination Connection ID longer than 20 bytes");
  if (p + dcid_len > len) return fail("Destination Connection ID runs past the end of the packet");
  out->dcid.assign(data + p, data + p + dcid_len);
  p += dcid_len;

  if (p + 1 > len) return fail("truncated before the Source Connection ID length");
  const std::size_t scid_len = data[p++];
  if (scid_len > 20) return fail("Source Connection ID longer than 20 bytes");
  if (p + scid_len > len) return fail("Source Connection ID runs past the end of the packet");
  out->scid.assign(data + p, data + p + scid_len);
  p += scid_len;

  // RFC 9000 section 17.2.2: the Initial long header always carries a Token
  // Length field, and it is zero when no token is present.  This is NOT gated
  // on a first-byte bit (that rule came from the old drafts), so a real Initial
  // has two zero bytes in a row here -- SCID Length 0 and Token Length 0.
  // Skipping this field shifts the Length varint by one byte and every
  // subsequent offset with it.
  {
    u64 token_len = 0;
    std::size_t used = 0;
    if (!quic_varint(data + p, len - p, &token_len, &used)) return fail("truncated token length");
    p += used;
    if (token_len > len - p) return fail("token runs past the end of the packet");
    out->token.assign(data + p, data + p + std::size_t(token_len));
    p += std::size_t(token_len);
  }

  u64 payload_len = 0;
  std::size_t used = 0;
  if (!quic_varint(data + p, len - p, &payload_len, &used)) return fail("truncated Length field");
  p += used;
  out->length = payload_len;
  if (payload_len < 1 + 16) return fail("Length field is smaller than a 1-byte number plus a tag");

  out->pn_offset = p;
  out->largest_acked = largest_acked;

  // The header protection sample lives at pn_offset + 4 regardless of how many
  // bytes the packet number itself uses (RFC 9001 section 5.4.2).
  const std::size_t sample_off = out->pn_offset + kQuicHpSampleOffsetFromPn;
  if (sample_off + kQuicHpSampleLen > len) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "packet is too short for the header protection sample (need %zu bytes at "
                  "offset %zu, have %zu)",
                  kQuicHpSampleLen, sample_off, len);
    return fail(buf);
  }
  if (!keys.ready) return fail("Initial keys are not available: " + keys.error);

  u8 mask[5] = {0, 0, 0, 0, 0};
  std::string err;
  if (!header_mask(keys, data + sample_off, mask, &err)) return fail(err);

  const u8 plain_first = u8(data[0] ^ (mask[0] & 0x0f));
  out->first_byte_unprotected = plain_first;
  if (header_reserved_bit_set(plain_first)) {
    return fail("reserved bit is set after header protection removal (wrong keys or corruption)");
  }
  out->pn_length = header_pn_length(plain_first);

  std::size_t pn_bytes = out->pn_offset + std::size_t(out->pn_length);
  if (pn_bytes > len) return fail("packet number runs past the end of the packet");

  // The Length field counts the packet number, the ciphertext and the tag, so
  // the packet must contain that much after the packet number.
  const std::size_t need = out->pn_offset + std::size_t(payload_len);
  if (need > len) {
    out->trunced = true;
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "packet is truncated: header Length says %llu bytes from offset %zu but only "
                  "%zu are present",
                  static_cast<unsigned long long>(payload_len), out->pn_offset, len);
    return fail(buf);
  }

  // RFC 9001 section 5.4.1: the packet number bytes recovered from the mask are
  // the real header bytes, so put them back before anything is authenticated.
  // The AEAD associated data is the *unprotected* header through the packet
  // number; using the protected bytes here is what makes the tag check fail.
  out->header_prefix.assign(data, data + out->pn_offset);
  out->header_prefix[0] = plain_first;  // unmasked flags byte
  u64 truncated = 0;
  for (int i = 0; i < out->pn_length; ++i) {
    const u8 pn_byte = u8(data[out->pn_offset + std::size_t(i)] ^ mask[1 + i]);
    out->header_prefix.push_back(pn_byte);
    truncated = (truncated << 8) | u64(pn_byte);
  }
  if (!decode_packet_number(largest_acked, truncated, out->pn_length, &out->packet_number, &err)) {
    return fail(err);
  }

  out->header_end = pn_bytes;
  out->payload_offset = pn_bytes;
  // A coalesced datagram can hold more than this packet; the Length field is
  // authoritative, so the ciphertext is exactly what it says.
  out->payload_length = std::size_t(payload_len) - std::size_t(out->pn_length);
  out->ok = true;
  out->error.clear();
  return true;
}

// ------------------------------------------------------------------ decrypt

bool quic_decrypt_initial(const u8* data, std::size_t len, u64 largest_acked,
                          const QuicInitialKeys& keys, QuicInitialHeader* header,
                          Bytes* out_payload, std::string* error) {
  auto fail = [&](const std::string& why) {
    if (error) *error = why;
    return false;
  };
  QuicInitialHeader local;
  QuicInitialHeader* h = (header != nullptr) ? header : &local;
  if (!quic_parse_initial_header(data, len, largest_acked, keys, h)) {
    return fail(h->error.empty() ? std::string("Initial header parse failed") : h->error);
  }
  if (out_payload == nullptr) return true;

  if (h->payload_length < 16) return fail("ciphertext is shorter than the AEAD tag");
  const std::size_t ct_len = h->payload_length - 16;
  const Bytes nonce = initial_nonce(keys.iv, h->packet_number);
  // The AAD is the unprotected header through the packet number, which is
  // header_prefix (the same length as header_end, with the PN bytes unmasked).
  const Bytes aad = h->header_prefix.size() == h->header_end
                        ? h->header_prefix
                        : Bytes(data, data + h->header_end);
  const Bytes ciphertext(data + h->payload_offset, data + h->payload_offset + ct_len);
  const Bytes tag(data + h->payload_offset + ct_len, data + h->payload_offset + ct_len + 16);

  Bytes plaintext;
  if (!aes_gcm_decrypt(keys.key, nonce, aad, ciphertext, tag, &plaintext)) {
    char buf[192];
    std::snprintf(buf, sizeof(buf),
                  "AEAD tag verification failed for packet number %llu (pn_length %d, %zu "
                  "ciphertext bytes, %zu AAD bytes): wrong keys, not an Initial packet, or "
                  "corruption",
                  static_cast<unsigned long long>(h->packet_number), h->pn_length, ct_len,
                  h->header_end);
    return fail(buf);
  }
  *out_payload = std::move(plaintext);
  return true;
}

// ------------------------------------------------------------------ frames

namespace {

bool parse_ack_frame(const u8* d, std::size_t len, std::size_t* p, std::string* note,
                     std::string* error) {
  auto need = [&](std::size_t n) { return *p + n <= len; };
  if (!need(2)) {
    *error = "ACK frame is truncated";
    return false;
  }
  u64 largest = 0, delay = 0, ranges = 0, first = 0;
  std::size_t used = 0;
  if (!quic_varint(d + *p, len - *p, &largest, &used)) {
    *error = "ACK frame has a truncated Largest Acknowledged";
    return false;
  }
  *p += used;
  if (!quic_varint(d + *p, len - *p, &delay, &used)) {
    *error = "ACK frame has a truncated ACK Delay";
    return false;
  }
  *p += used;
  if (!quic_varint(d + *p, len - *p, &ranges, &used)) {
    *error = "ACK frame has a truncated ACK Range Count";
    return false;
  }
  *p += used;
  if (!quic_varint(d + *p, len - *p, &first, &used)) {
    *error = "ACK frame has a truncated First ACK Range";
    return false;
  }
  *p += used;
  for (u64 i = 0; i < ranges; ++i) {
    u64 gap = 0, rlen = 0;
    if (!quic_varint(d + *p, len - *p, &gap, &used)) {
      *error = "ACK frame has a truncated Gap";
      return false;
    }
    *p += used;
    if (!quic_varint(d + *p, len - *p, &rlen, &used)) {
      *error = "ACK frame has a truncated ACK Range Length";
      return false;
    }
    *p += used;
  }
  if (note != nullptr) {
    char buf[80];
    std::snprintf(buf, sizeof(buf), "largest %llu, delay %llu, %llu extra ranges",
                  static_cast<unsigned long long>(largest), static_cast<unsigned long long>(delay),
                  static_cast<unsigned long long>(ranges));
    *note = buf;
  }
  return true;
}

}  // namespace

bool quic_parse_frames(const u8* data, std::size_t len, std::vector<QuicFrame>* frames,
                       std::string* error) {
  auto fail = [&](const std::string& why) {
    if (error) *error = why;
    return false;
  };
  if (frames == nullptr) return fail("no output vector");
  frames->clear();
  std::size_t p = 0;
  std::size_t padding_run = 0;

  auto flush_padding = [&]() {
    if (padding_run == 0) return;
    QuicFrame f;
    f.type = 0x00;
    f.type_name = "PADDING";
    f.length = padding_run;
    f.note = "padding " + std::to_string(padding_run);
    frames->push_back(std::move(f));
    padding_run = 0;
  };

  while (p < len) {
    if (data[p] == 0x00) {  // PADDING
      ++padding_run;
      ++p;
      continue;
    }
    flush_padding();

    QuicFrame f;
    f.type = data[p];
    std::size_t used = 0;
    switch (data[p]) {
      case 0x01: {  // PING
        f.type_name = "PING";
        ++p;
        break;
      }
      case 0x02:    // ACK
      case 0x03: {  // ACK with ECN counts
        f.type_name = (data[p] == 0x02) ? "ACK" : "ACK_ECN";
        ++p;
        if (!parse_ack_frame(data, len, &p, &f.note, error)) return false;
        if (f.type == 0x03) {  // ECT0, ECT1, CE counts
          for (int i = 0; i < 3; ++i) {
            u64 ignored = 0;
            if (!quic_varint(data + p, len - p, &ignored, &used)) {
              return fail("ACK_ECN frame has a truncated ECN count");
            }
            p += used;
          }
        }
        break;
      }
      case 0x04: {  // RESET_STREAM
        f.type_name = "RESET_STREAM";
        ++p;
        for (int i = 0; i < 3; ++i) {
          u64 v = 0;
          if (!quic_varint(data + p, len - p, &v, &used)) {
            return fail("RESET_STREAM frame is truncated");
          }
          p += used;
        }
        break;
      }
      case 0x05: {  // STOP_SENDING
        f.type_name = "STOP_SENDING";
        ++p;
        for (int i = 0; i < 2; ++i) {
          u64 v = 0;
          if (!quic_varint(data + p, len - p, &v, &used)) {
            return fail("STOP_SENDING frame is truncated");
          }
          p += used;
        }
        break;
      }
      case 0x06: {  // CRYPTO
        f.type_name = "CRYPTO";
        ++p;
        if (!quic_varint(data + p, len - p, &f.offset, &used)) {
          return fail("CRYPTO frame has a truncated offset");
        }
        p += used;
        if (!quic_varint(data + p, len - p, &f.length, &used)) {
          return fail("CRYPTO frame has a truncated length");
        }
        p += used;
        if (f.length > len - p) {
          char buf[128];
          std::snprintf(buf, sizeof(buf),
                        "CRYPTO frame claims %llu bytes but only %zu remain in the payload",
                        static_cast<unsigned long long>(f.length), len - p);
          return fail(buf);
        }
        f.data.assign(data + p, data + p + std::size_t(f.length));
        p += std::size_t(f.length);
        break;
      }
      case 0x07: {  // NEW_TOKEN
        f.type_name = "NEW_TOKEN";
        ++p;
        if (!quic_varint(data + p, len - p, &f.length, &used)) {
          return fail("NEW_TOKEN frame has a truncated length");
        }
        p += used;
        if (f.length > len - p) return fail("NEW_TOKEN frame runs past the end of the payload");
        p += std::size_t(f.length);
        break;
      }
      case 0x08: case 0x09: case 0x0a: case 0x0b:
      case 0x0c: case 0x0d: case 0x0e: case 0x0f: {  // STREAM
        f.type_name = "STREAM";
        const bool has_off = (data[p] & 0x04) != 0;
        const bool has_len = (data[p] & 0x02) != 0;
        const bool has_fin = (data[p] & 0x01) != 0;
        f.note = (has_fin ? "FIN " : "");
        ++p;
        u64 sid = 0;
        if (!quic_varint(data + p, len - p, &sid, &used)) {
          return fail("STREAM frame has a truncated stream ID");
        }
        p += used;
        f.offset = sid;
        if (has_off) {
          if (!quic_varint(data + p, len - p, &f.offset, &used)) {
            return fail("STREAM frame has a truncated offset");
          }
          p += used;
        }
        if (has_len) {
          if (!quic_varint(data + p, len - p, &f.length, &used)) {
            return fail("STREAM frame has a truncated length");
          }
          p += used;
        } else {
          f.length = len - p;
        }
        if (f.length > len - p) return fail("STREAM frame runs past the end of the payload");
        p += std::size_t(f.length);
        break;
      }
      case 0x10:  // MAX_DATA
      case 0x11:  // MAX_STREAM_DATA
      case 0x12:  // MAX_STREAMS (bidirectional)
      case 0x13:  // MAX_STREAMS (unidirectional)
      case 0x14:  // DATA_BLOCKED
      case 0x15:  // STREAM_DATA_BLOCKED
      case 0x16:  // STREAMS_BLOCKED (bidirectional)
      case 0x17:  // STREAMS_BLOCKED (unidirectional)
      case 0x1a:  // PATH_CHALLENGE
      case 0x1b: {  // PATH_RESPONSE
        switch (data[p]) {
          case 0x10: f.type_name = "MAX_DATA"; break;
          case 0x11: f.type_name = "MAX_STREAM_DATA"; break;
          case 0x12: f.type_name = "MAX_STREAMS_BIDI"; break;
          case 0x13: f.type_name = "MAX_STREAMS_UNI"; break;
          case 0x14: f.type_name = "DATA_BLOCKED"; break;
          case 0x15: f.type_name = "STREAM_DATA_BLOCKED"; break;
          case 0x16: f.type_name = "STREAMS_BLOCKED_BIDI"; break;
          case 0x17: f.type_name = "STREAMS_BLOCKED_UNI"; break;
          case 0x1a: f.type_name = "PATH_CHALLENGE"; break;
          default: f.type_name = "PATH_RESPONSE"; break;
        }
        ++p;
        if (f.type == 0x1a || f.type == 0x1b) {
          if (len - p < 8) return fail("PATH_CHALLENGE/PATH_RESPONSE is truncated");
          p += 8;  // opaque 8 bytes
        } else {
          u64 v = 0;
          if (!quic_varint(data + p, len - p, &v, &used)) {
            std::string why = f.type_name + " frame is truncated";
            return fail(why);
          }
          p += used;
          if (f.type == 0x11 || f.type == 0x15) {  // these carry a stream ID first
            if (!quic_varint(data + p, len - p, &v, &used)) {
              std::string why = f.type_name + " frame has a truncated stream ID";
              return fail(why);
            }
            p += used;
          }
        }
        break;
      }
      case 0x18: {  // NEW_CONNECTION_ID
        f.type_name = "NEW_CONNECTION_ID";
        ++p;
        for (int i = 0; i < 2; ++i) {  // sequence number, retire prior to
          u64 v = 0;
          if (!quic_varint(data + p, len - p, &v, &used)) {
            return fail("NEW_CONNECTION_ID frame is truncated");
          }
          p += used;
        }
        if (len - p < 1) return fail("NEW_CONNECTION_ID frame is truncated");
        const std::size_t cid_len = data[p++];
        if (cid_len > 20 || cid_len + 16 > len - p) {
          return fail("NEW_CONNECTION_ID frame has an out-of-range connection ID");
        }
        p += cid_len + 16;  // connection ID + stateless reset token
        break;
      }
      case 0x19: {  // RETIRE_CONNECTION_ID
        f.type_name = "RETIRE_CONNECTION_ID";
        ++p;
        u64 v = 0;
        if (!quic_varint(data + p, len - p, &v, &used)) {
          return fail("RETIRE_CONNECTION_ID frame is truncated");
        }
        p += used;
        break;
      }
      case 0x1c: {  // CONNECTION_CLOSE
        f.type_name = "CONNECTION_CLOSE";
        ++p;
        u64 code = 0, frame_type = 0, reason_len = 0;
        const bool transport = (data[p - 1] == 0x1c);
        if (!quic_varint(data + p, len - p, &code, &used)) {
          return fail("CONNECTION_CLOSE frame is truncated");
        }
        p += used;
        if (transport) {
          if (!quic_varint(data + p, len - p, &frame_type, &used)) {
            return fail("CONNECTION_CLOSE frame has a truncated frame type");
          }
          p += used;
        }
        if (!quic_varint(data + p, len - p, &reason_len, &used)) {
          return fail("CONNECTION_CLOSE frame has a truncated reason length");
        }
        p += used;
        if (reason_len > len - p) return fail("CONNECTION_CLOSE reason runs past the payload");
        f.offset = code;
        f.length = reason_len;
        p += std::size_t(reason_len);
        break;
      }
      case 0x1d:  // HANDSHAKE_DONE
        f.type_name = "HANDSHAKE_DONE";
        ++p;
        break;
      default:
        if (data[p] >= 0x20 && data[p] <= 0x3f) {
          // RFC 9000 section 19.11: experimental / extension frames; no length
          // is defined, so walking any further would guess at the offset.
          f.type_name = "EXTENSION";
          f.type = data[p];
          std::string why;
          {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "unknown frame type 0x%02x at decrypted offset %zu: this parser does "
                          "not know how to walk it, so the remaining frames are not reported",
                          unsigned(data[p]), p);
            why = buf;
          }
          frames->push_back(std::move(f));
          return fail(why);
        }
        {
          char buf[128];
          std::snprintf(buf, sizeof(buf), "unknown frame type 0x%02x at decrypted offset %zu",
                        unsigned(data[p]), p);
          return fail(buf);
        }
    }
    frames->push_back(std::move(f));
  }
  flush_padding();
  if (error) error->clear();
  return true;
}

// ------------------------------------------------------------------ CRYPTO stream

void QuicCryptoStream::reset() {
  bytes.clear();
  highest = 0;
  complete = false;
  error.clear();
}

bool QuicCryptoStream::absorb(const u8* frames, std::size_t len) {
  std::vector<QuicFrame> parsed;
  std::string err;
  if (!quic_parse_frames(frames, len, &parsed, &err)) {
    error = err;
    return false;
  }
  return absorb(parsed);
}

bool QuicCryptoStream::absorb(const std::vector<QuicFrame>& frames) {
  for (const QuicFrame& f : frames) {
    if (f.type != 0x06) continue;
    const std::size_t off = std::size_t(f.offset);
    const std::size_t n = f.data.size();
    if (n == 0) continue;
    if (off + n > kQuicMaxCryptoStream) {
      char buf[160];
      std::snprintf(buf, sizeof(buf),
                    "CRYPTO frame reaches offset %zu, past the %zu byte reassembly limit",
                    off + n, kQuicMaxCryptoStream);
      error = buf;
      return false;
    }
    if (off > highest) {
      // A hole in the stream.  We cannot pretend the bytes in between arrived,
      // so the frame is refused rather than silently shifting the ClientHello.
      char buf[160];
      std::snprintf(buf, sizeof(buf),
                    "CRYPTO frame starts at offset %zu but the stream is only contiguous to "
                    "%llu: a packet was lost or reordered",
                    off, static_cast<unsigned long long>(highest));
      error = buf;
      return false;
    }
    if (bytes.size() < off + n) bytes.resize(off + n, 0);
    if (off < highest) {
      // Retransmission: the overlapping bytes have to agree with what we hold.
      const std::size_t overlap = std::min<std::size_t>(n, std::size_t(highest) - off);
      if (!std::equal(f.data.begin(), f.data.begin() + overlap, bytes.begin() + off)) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "CRYPTO retransmission at offset %zu disagrees with the bytes already "
                      "reassembled",
                      off);
        error = buf;
        return false;
      }
    }
    for (std::size_t i = 0; i < n; ++i) bytes[off + i] = f.data[i];
    if (off + n > highest) highest = off + n;
  }
  error.clear();
  return true;
}

// ------------------------------------------------------------------ ClientHello

bool quic_parse_client_hello(const u8* data, std::size_t len, QuicClientHello* out,
                             std::string* error) {
  auto fail = [&](const std::string& why) {
    if (error) *error = why;
    return false;
  };
  if (out == nullptr) return fail("no output structure");
  *out = QuicClientHello{};
  std::size_t p = 0;
  while (p + 4 <= len) {
    const u8 msg_type = data[p];
    const std::size_t body_len = rd24be(data + p + 1);
    const std::size_t body_off = p + 4;
    if (body_len > len - body_off) {
      char buf[128];
      std::snprintf(buf, sizeof(buf),
                    "handshake message type %u claims %zu bytes but only %zu remain",
                    unsigned(msg_type), body_len, len - body_off);
      return fail(buf);
    }
    if (msg_type == 1) {  // ClientHello
      TlsClientHelloInfo info;
      std::string err;
      if (!tls_parse_client_hello(data + body_off, body_len, &info, &err)) {
        return fail("ClientHello did not parse: " + err);
      }
      out->host = info.sni;
      out->alpns = info.alpn;
      if (!info.alpn.empty()) out->alpn = info.alpn.front();
      out->legacy_version = info.legacy_version;
      out->random = info.random;
      out->cipher_suites = info.cipher_suites;
      const u16 v = info.has_supported_versions ? info.supported_version : info.legacy_version;
      out->version = tls_version_name(v);
      if (error) error->clear();
      return true;
    }
    p = body_off + body_len;  // skip: server-direction streams and post-HRR resends
  }
  return fail("no ClientHello handshake message in the CRYPTO stream");
}

// ------------------------------------------------------------------ one-shot API

bool quic_parse_initial(const u8* data, std::size_t len, std::string* sni, std::string* alpn,
                        std::string* error) {
  if (sni) sni->clear();
  if (alpn) alpn->clear();
  auto fail = [&](const std::string& why) {
    if (error) *error = why;
    return false;
  };
  if (len < kQuicMinInitialSize) return fail("packet is too short to be a QUIC Initial packet");
  if ((data[0] & 0x80) == 0) return fail("not a long header packet");
  const u32 version = rd32be(data + 1);
  if (!version_known(version)) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "QUIC version 0x%08x is not supported (only v1 0x00000001 and v2 0x6b3343cf)",
                  unsigned(version));
    return fail(buf);
  }
  if (version == kQuicV2 && decode_packet_type(data[0], true) != kQuicTypeInitial) {
    return fail("long header packet is not an Initial packet");
  }
  if (version == kQuicV1 && decode_packet_type(data[0], false) != kQuicTypeInitial) {
    return fail("long header packet is not an Initial packet");
  }
  const std::size_t dcid_len = data[5];
  if (dcid_len == 0 || dcid_len > 20 || 6 + dcid_len > len) {
    return fail("Destination Connection ID is missing or runs past the packet");
  }
  const Bytes dcid(data + 6, data + 6 + dcid_len);

  QuicInitialKeys keys;
  if (!derive_initial_keys(dcid.data(), dcid.size(), version, QuicInitialSide::Client, &keys)) {
    return fail("Initial key derivation failed: " + keys.error);
  }
  QuicInitialHeader header;
  Bytes payload;
  std::string err;
  if (!quic_decrypt_initial(data, len, 0, keys, &header, &payload, &err)) return fail(err);
  if (payload.empty()) return fail("Initial packet decrypted to an empty payload");

  std::vector<QuicFrame> frames;
  if (!quic_parse_frames(payload.data(), payload.size(), &frames, &err)) {
    return fail("frame parsing failed: " + err);
  }
  Bytes crypto;
  for (const QuicFrame& f : frames) {
    if (f.type != 0x06) continue;
    if (f.offset != 0) continue;  // see the note in the header: no reassembly here
    crypto.insert(crypto.end(), f.data.begin(), f.data.end());
  }
  if (crypto.empty()) return fail("the Initial packet carried no CRYPTO frame at offset 0");

  QuicClientHello hello;
  if (!quic_parse_client_hello(crypto.data(), crypto.size(), &hello, &err)) {
    return fail(err);
  }
  if (sni) *sni = hello.host;
  if (alpn) *alpn = hello.alpn;
  if (error) error->clear();
  return true;
}

// ------------------------------------------------------------------ builder

bool quic_build_initial(const u8* dcid, std::size_t dcid_len, u32 version, u64 packet_number,
                        std::size_t pn_length, const u8* frames, std::size_t frames_len,
                        Bytes* out_packet, std::string* error) {
  auto fail = [&](const std::string& why) {
    if (error) *error = why;
    return false;
  };
  if (out_packet == nullptr) return fail("no output buffer");
  if (!version_known(version)) return fail("builder only supports QUIC v1 and v2");
  if (dcid == nullptr || dcid_len == 0) return fail("builder needs a Destination Connection ID");
  if (pn_length < 1 || pn_length > 4) return fail("packet number length must be 1..4");

  // RFC 9000 section 17.1 / A.2: the truncated form must fit in
  // 8*pn_length - 2 bits, otherwise the encoding cannot represent it.
  const unsigned bits = unsigned(pn_length * 8 - 2);
  if (bits < 64 && packet_number >= (u64(1) << bits)) {
    return fail("packet number does not fit the requested encoding length");
  }

  QuicInitialKeys keys;
  if (!derive_initial_keys(dcid, dcid_len, version, QuicInitialSide::Client, &keys)) {
    return fail(keys.error);
  }

  // Header: flags, version, DCID, SCID (empty), Length, packet number.
  Bytes header;
  const bool v2 = (version == kQuicV2);
  u8 flags = 0xc0;  // long header + fixed bit (the type bits are zero for Initial)
  if (v2) flags = 0xd0;  // v2 Initial has the type bits at 0b01 in the high nibble
  flags = u8(flags | (u8(pn_length) - 1));
  header.push_back(flags);
  header.push_back(u8(version >> 24));
  header.push_back(u8(version >> 16));
  header.push_back(u8(version >> 8));
  header.push_back(u8(version));
  header.push_back(u8(dcid_len));
  header.insert(header.end(), dcid, dcid + dcid_len);
  header.push_back(0);  // Source Connection ID length
  header.push_back(0);  // Token Length: always present in an Initial header
  const u64 length_field = u64(pn_length) + u64(frames_len) + 16;
  quic_varint_put(&header, length_field);
  const std::size_t pn_offset = header.size();
  for (std::size_t i = 0; i < pn_length; ++i) {
    header.push_back(u8(packet_number >> (8 * (pn_length - 1 - i))));
  }

  const Bytes nonce = initial_nonce(keys.iv, packet_number);
  const Bytes aad = header;
  const AeadResult sealed =
      aes_gcm_encrypt(keys.key, nonce, aad, Bytes(frames, frames + frames_len));
  if (!sealed.ok) return fail("AES-GCM encryption failed");

  Bytes packet = header;
  packet.insert(packet.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
  packet.insert(packet.end(), sealed.tag.begin(), sealed.tag.end());

  const std::size_t sample_off = pn_offset + kQuicHpSampleOffsetFromPn;
  if (sample_off + kQuicHpSampleLen > packet.size()) {
    return fail("built packet is too short to sample for header protection");
  }
  u8 mask[5];
  std::string err;
  if (!header_mask(keys, packet.data() + sample_off, mask, &err)) return fail(err);
  packet[0] = u8(packet[0] ^ (mask[0] & 0x0f));
  for (std::size_t i = 0; i < pn_length; ++i) packet[pn_offset + i] ^= mask[1 + i];

  *out_packet = std::move(packet);
  if (error) error->clear();
  return true;
}

bool quic_build_client_hello(const std::string& sni, const std::string& alpn, u16 sni_type,
                             Bytes* out_message, std::string* error) {
  auto fail = [&](const char* why) {
    if (error) *error = why;
    return false;
  };
  if (out_message == nullptr) return fail("no output buffer");
  if (sni.size() > 0xffff) return fail("SNI is too long for a one-entry name list");

  Bytes exts;
  {  // server_name (0x0000)
    Bytes list;
    // TLS name_type is a single byte; a 2-byte encoding here would make the
    // parser read a zero-length name and report an empty SNI.
    list.push_back(u8(sni_type));
    list.push_back(u8(sni.size() >> 8));
    list.push_back(u8(sni.size()));
    list.insert(list.end(), sni.begin(), sni.end());
    const u16 list_len = u16(list.size());
    exts.push_back(0x00);
    exts.push_back(0x00);
    const u16 ext_len = u16(2 + list_len);
    exts.push_back(u8(ext_len >> 8));
    exts.push_back(u8(ext_len));
    exts.push_back(u8(list_len >> 8));
    exts.push_back(u8(list_len));
    exts.insert(exts.end(), list.begin(), list.end());
  }
  if (!alpn.empty()) {  // ALPN (0x0010)
    if (alpn.size() > 255) return fail("ALPN protocol name is longer than 255 bytes");
    Bytes list;
    list.push_back(u8(alpn.size()));
    list.insert(list.end(), alpn.begin(), alpn.end());
    const u16 list_len = u16(list.size());
    exts.push_back(0x00);
    exts.push_back(0x10);
    const u16 ext_len = u16(2 + list_len);
    exts.push_back(u8(ext_len >> 8));
    exts.push_back(u8(ext_len));
    exts.push_back(u8(list_len >> 8));
    exts.push_back(u8(list_len));
    exts.insert(exts.end(), list.begin(), list.end());
  }
  {  // supported_versions (0x002b) = TLS 1.3
    exts.push_back(0x00);
    exts.push_back(0x2b);
    exts.push_back(0x00);
    exts.push_back(0x03);
    exts.push_back(0x02);  // extension length
    exts.push_back(0x02);  // one version follows
    exts.push_back(0x03);
    exts.push_back(0x04);
  }

  Bytes body;
  body.push_back(0x03);  // legacy_version = TLS 1.2
  body.push_back(0x03);
  for (u8 i = 0; i < 32; ++i) body.push_back(u8(0xa0 + i));  // deterministic "random"
  body.push_back(32);                                        // legacy_session_id
  for (u8 i = 0; i < 32; ++i) body.push_back(u8(i));
  body.push_back(0x00);  // cipher_suites
  body.push_back(0x02);
  body.push_back(u8(kTlsAes128Gcm >> 8));
  body.push_back(u8(kTlsAes128Gcm));
  body.push_back(0x01);  // legacy_compression_methods
  body.push_back(0x00);
  const u16 ext_total = u16(exts.size());
  body.push_back(u8(ext_total >> 8));
  body.push_back(u8(ext_total));
  body.insert(body.end(), exts.begin(), exts.end());

  Bytes msg;
  msg.push_back(0x01);  // ClientHello
  msg.push_back(u8(body.size() >> 16));
  msg.push_back(u8(body.size() >> 8));
  msg.push_back(u8(body.size()));
  msg.insert(msg.end(), body.begin(), body.end());

  *out_message = std::move(msg);
  if (error) error->clear();
  return true;
}

// ------------------------------------------------------------------ self check

namespace {

// The full protected client Initial packet from RFC 9001 Appendix A.2.
const char* kRfc9001A2ClientInitial =
    // RFC 9001 A.2 byte layout, verified against the RFC's own hex dump:
    //   0     flags, on the wire 0xc0; unmasked it is 0xc3, so the packet
    //         number is 4 bytes (long header, Initial)
    //   1..4  version 0x00000001
    //   5     DCID length 8
    //   6..13 DCID 8394c8f03e515708
    //   14    SCID length 0
    //   15    Token Length 0 (always present in an Initial header)
    //   16..17 Length, the 2-byte varint 449e = 1182
    //   18..21 packet number, protected as 7b9aec34 -> 00000002
    //   22..  1162 ciphertext bytes + 16-byte tag (1178 bytes, so 1200 total)
    // The two zero bytes at 14 and 15 are the SCID length and the Token Length;
    // reading only one of them puts the Length varint one byte early.
    "c000000001088394c8f03e5157"
    "080000449e7b9aec34d1b1c98dd7689fb8ec11"
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
    "e221af44860018ab0856972e194cd934";

struct Check {
  bool ok = true;
  std::string text;
  void line(const std::string& s) { text += s; text += "\n"; }
  void expect(bool cond, const std::string& what) {
    text += cond ? "  PASS  " : "  FAIL  ";
    text += what;
    text += "\n";
    if (!cond) ok = false;
  }
};

std::string hex_short(const Bytes& b, std::size_t n) {
  return to_hex(b.data(), std::min(n, b.size()));
}

}  // namespace

bool quic_selfcheck(std::string* report) {
  Check c;
  c.line("QUIC Initial packet self-test (RFC 9001 Appendix A.2 vector)");

  const Bytes packet = from_hex(kRfc9001A2ClientInitial);
  c.line("vector: " + std::to_string(packet.size()) + " protected bytes, DCID 8394c8f03e515708");

  // 1. key schedule, against A.1's published values.
  QuicInitialKeys client;
  c.expect(derive_initial_keys(packet.data() + 6, 8, kQuicV1, QuicInitialSide::Client, &client),
           "client Initial keys derive");
  c.expect(to_hex(client.secret) ==
               "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
           "client_initial_secret matches RFC 9001 A.1");
  c.expect(to_hex(client.key) == "1f369613dd76d5467730efcbe3b1a22d",
           "client key matches RFC 9001 A.1");
  c.expect(to_hex(client.iv) == "fa044b2f42a3fd3b46fb255c", "client iv matches RFC 9001 A.1");
  c.expect(to_hex(client.hp) == "9f50449e04a0e810283a1e9933adedd2",
           "client hp matches RFC 9001 A.1");
  QuicInitialKeys server;
  derive_initial_keys(packet.data() + 6, 8, kQuicV1, QuicInitialSide::Server, &server);
  c.expect(to_hex(server.secret) ==
               "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
           "server_initial_secret matches RFC 9001 A.1");

  // 2. header protection + packet number + AEAD.
  QuicInitialHeader header;
  Bytes payload;
  std::string err;
  const bool decrypted = quic_decrypt_initial(packet.data(), packet.size(), 0, client, &header,
                                              &payload, &err);
  c.expect(decrypted, std::string("the Initial packet decrypts (AEAD tag verifies)") +
                          (decrypted ? "" : ": " + err));
  if (decrypted) {
    c.line("  version              " + std::to_string(header.version));
    c.line("  dcid                 " + to_hex(header.dcid));
    c.line("  scid                 " + to_hex(header.scid));
    c.line("  first byte           0x" + to_hex(&header.first_byte, 1) + " -> 0x" +
           to_hex(&header.first_byte_unprotected, 1));
    c.line("  pn_length            " + std::to_string(header.pn_length));
    c.line("  packet number        " + std::to_string(header.packet_number));
    c.line("  aad length           " + std::to_string(header.header_end));
    c.line("  decrypted            " + std::to_string(payload.size()) + " bytes");
    c.expect(header.header_end == 22, "AAD is the 22-byte unprotected header (offsets 0..21)");
    c.expect(header.packet_number == 2, "packet number decodes to 2");
    c.expect(header.header_end - std::size_t(header.pn_length) == 18,
             "the packet number starts at offset 18 (4-byte Length varint)");
    c.expect(header.first_byte_unprotected == 0xc3, "unprotected first byte is 0xc3");
    c.expect(header.pn_length == 4, "packet number length is 4");
    c.expect(payload.size() == 1162, "decrypted payload is 1162 bytes");
    const Bytes want_start = from_hex("060040f1010000ed0303");
    c.expect(payload.size() >= want_start.size() &&
                 std::equal(want_start.begin(), want_start.end(), payload.begin()),
             "decrypted CRYPTO frame starts 06 00 40 f1 01 00 00 ed 03 03 (actual " +
                 hex_short(payload, 10) + ")");
  }

  // 3. frames + CRYPTO reassembly + ClientHello.
  if (decrypted) {
    std::vector<QuicFrame> frames;
    const bool framed = quic_parse_frames(payload.data(), payload.size(), &frames, &err);
    c.expect(framed, std::string("every frame in the payload is walked") +
                         (framed ? "" : ": " + err));
    if (framed) {
      std::string summary;
      for (const QuicFrame& f : frames) {
        if (!summary.empty()) summary += ", ";
        summary += f.type_name;
        if (f.length != 0) summary += "(" + std::to_string(f.length) + ")";
      }
      c.line("  frames               " + summary);
      c.expect(!frames.empty() && frames.front().type == 0x06, "the first frame is CRYPTO");
      if (!frames.empty() && frames.front().type == 0x06) {
        c.expect(frames.front().offset == 0 && frames.front().length == 241,
                 "CRYPTO frame is offset 0, 241 bytes");
      }
    }

    QuicCryptoStream stream;
    c.expect(stream.absorb(frames), "the CRYPTO frames reassemble");
    c.expect(stream.bytes.size() == 241, "the reassembled CRYPTO stream is 241 bytes");
    c.expect(stream.bytes.size() >= 10 && stream.bytes[0] == 0x01 && stream.bytes[1] == 0x00 &&
                 stream.bytes[2] == 0x00 && stream.bytes[3] == 0xed,
             "the stream is one ClientHello handshake of body length 237");
    QuicClientHello hello;
    const bool parsed = quic_parse_client_hello(stream.bytes.data(), stream.bytes.size(), &hello,
                                               &err);
    c.expect(parsed, std::string("the ClientHello parses") + (parsed ? "" : ": " + err));
    if (parsed) {
      c.line("  sni                  '" + hello.host + "'");
      c.line("  alpn                 '" + hello.alpn + "'");
      c.line("  version              '" + hello.version + "'");
      c.line("  cipher suites        " + std::to_string(hello.cipher_suites.size()));
      c.expect(hello.host == "example.com", "SNI is example.com");
      // RFC 9001 A.2 spells the protocol list literally "alpn"; it is not "h3".
      c.expect(hello.alpn == "alpn", "ALPN is the RFC sample's 'alpn'");
      c.expect(hello.version == "TLS 1.3", "supported_versions says TLS 1.3");
    }
  }

  // 4. build/parse round trip with the same values through a whole new packet.
  {
    Bytes ch;
    std::string build_err;
    const bool built = quic_build_client_hello("example.com", "h3", 0, &ch, &build_err);
    c.expect(built, std::string("a synthetic ClientHello builds") +
                        (built ? "" : ": " + build_err));
    if (built) {
      Bytes frames;
      frames.push_back(0x06);
      quic_varint_put(&frames, 0);
      quic_varint_put(&frames, ch.size());
      frames.insert(frames.end(), ch.begin(), ch.end());
      while (frames.size() < 300) frames.push_back(0x00);

      const u8 dcid[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
      Bytes roundtrip;
      const bool made = quic_build_initial(dcid, sizeof(dcid), kQuicV1, 7, 2, frames.data(),
                                           frames.size(), &roundtrip, &build_err);
      c.expect(made, std::string("a synthetic Initial packet builds") +
                         (made ? "" : ": " + build_err));
      if (made) {
        std::string sni, alpn, perr;
        const bool reparsed =
            quic_parse_initial(roundtrip.data(), roundtrip.size(), &sni, &alpn, &perr);
        c.expect(reparsed, std::string("the synthetic Initial parses back") +
                               (reparsed ? "" : ": " + perr));
        c.expect(reparsed && sni == "example.com", "round trip SNI == example.com");
        c.expect(reparsed && alpn == "h3", "round trip ALPN == h3");
      }
      // v2 uses a different salt and different labels; the same builder/parser
      // pair must work with both.
      Bytes v2packet;
      const bool made2 = quic_build_initial(dcid, sizeof(dcid), kQuicV2, 3, 4, frames.data(),
                                            frames.size(), &v2packet, &build_err);
      if (made2) {
        std::string sni, alpn, perr;
        const bool ok2 = quic_parse_initial(v2packet.data(), v2packet.size(), &sni, &alpn, &perr);
        c.expect(ok2 && sni == "example.com" && alpn == "h3",
                 std::string("QUIC v2 round trip (RFC 9369 salt/labels)") +
                     (ok2 ? "" : ": " + perr));
      } else {
        c.expect(false, "QUIC v2 packet builds: " + build_err);
      }
    }
  }

  // 5. error paths must be explicit, never silently wrong.
  {
    std::string sni, alpn, err2;
    // Note: the parse call must be made in its own statement, so the error
    // string concatenated into the label is read after the call, not before it
    // (function-argument evaluation order is unspecified in C++).
    Bytes truncated(packet.begin(), packet.begin() + 40);
    const bool t_ok = quic_parse_initial(truncated.data(), truncated.size(), &sni, &alpn, &err2);
    c.expect(!t_ok, "a truncated packet is refused: " + err2);
    Bytes corrupt = packet;
    corrupt[100] ^= 0x01;
    const bool c_ok = quic_parse_initial(corrupt.data(), corrupt.size(), &sni, &alpn, &err2);
    c.expect(!c_ok, "a flipped ciphertext byte fails the AEAD tag: " + err2);
    Bytes v3 = packet;
    v3[4] = 0x00;  // pretend the version is something else
    const bool v_ok = quic_parse_initial(v3.data(), v3.size(), &sni, &alpn, &err2);
    c.expect(!v_ok, "an unknown QUIC version is refused: " + err2);
    // A ClientHello whose server_name entry uses name_type 1 (not host_name)
    // must not be mistaken for an SNI.
    Bytes odd;
    std::string berr;
    if (quic_build_client_hello("example.com", "h3", 1, &odd, &berr)) {
      Bytes frames;
      frames.push_back(0x06);
      quic_varint_put(&frames, 0);
      quic_varint_put(&frames, odd.size());
      frames.insert(frames.end(), odd.begin(), odd.end());
      const u8 dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
      Bytes pkt;
      if (quic_build_initial(dcid, 8, kQuicV1, 1, 1, frames.data(), frames.size(), &pkt, &berr)) {
        std::string s2, a2;
        const bool ok3 = quic_parse_initial(pkt.data(), pkt.size(), &s2, &a2, &err2);
        c.expect(ok3 && s2.empty(), "server_name with name_type 1 yields no SNI (got '" + s2 + "')");
      }
    }
  }

  if (report != nullptr) *report = c.text;
  return c.ok;
}

}  // namespace netcap
