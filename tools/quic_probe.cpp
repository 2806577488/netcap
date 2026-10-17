// quic_probe - standalone driver for netcap's QUIC Initial packet parser.
//
//   quic_probe --hex <hex>          decode one protected Initial packet
//   quic_probe --file <path>        decode a file of raw packet bytes, or the
//                                   first whitespace-separated hex token in it
//   quic_probe --rfc9001            the RFC 9001 Appendix A.2 vector, built in
//   quic_probe --selfcheck          the full self test (also prints a report)
//
// It prints version / dcid / packet number / decrypted size / frames / sni /
// alpn, or the precise error the parser returned.  Never links selftest.cpp.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "netcap/quic.hpp"

using namespace netcap;

namespace {

std::string slurp(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::string();
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// A file is either raw packet bytes or a text hex dump; decide by looking for
// bytes that cannot be hex.
bool looks_like_hex_text(const std::string& s) {
  std::size_t digits = 0;
  for (char ch : s) {
    if (ch == ' ' || ch == '\r' || ch == '\n' || ch == '\t' || ch == ':' || ch == '-') continue;
    const bool hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    if (!hex) return false;
    ++digits;
  }
  return digits > 0;
}

void print_packet(const Bytes& packet, u64 largest_acked) {
  if (packet.size() > 5 && packet[5] != 0 && packet.size() > std::size_t(6 + packet[5])) {
    std::printf("dcid_raw          %s\n", to_hex(packet.data() + 6, packet[5]).c_str());
  }
  if (std::getenv("QUIC_PROBE_DEBUG") != nullptr) {
    std::printf("first 24 bytes    %s\n", packet.size() >= 24 ? to_hex(packet.data(), 24).c_str() : to_hex(packet).c_str());
  }
  std::printf("input             %zu bytes\n", packet.size());

  // Step 1: header + header protection + packet number.
  QuicInitialKeys keys;
  QuicInitialHeader header;
  std::string err;

  const bool header_done = [&]() {
    if (packet.size() < kQuicMinInitialSize) return false;
    if ((packet[0] & 0x80) == 0 || (packet[0] & 0x40) == 0) return false;
    const u32 version = rd32be(packet.data() + 1);
    const std::size_t dcid_len = packet[5];
    if (dcid_len == 0 || dcid_len > 20 || 6 + dcid_len > packet.size()) return false;
    if (!derive_initial_keys(packet.data() + 6, dcid_len, version, QuicInitialSide::Client, &keys)) {
      err = keys.error;
      return false;
    }
    if (!quic_parse_initial_header(packet.data(), packet.size(), largest_acked, keys, &header)) {
      err = header.error;
      return false;
    }
    return true;
  }();

  if (!header_done) {
    std::printf("error             %s\n", err.empty() ? "not a QUIC Initial packet" : err.c_str());
    return;
  }
  std::printf("version           %s (0x%08x)\n",
              header.version == kQuicV1 ? "QUICv1"
                                        : (header.version == kQuicV2 ? "QUICv2" : "unknown"),
              unsigned(header.version));
  std::printf("dcid              %s\n", to_hex(header.dcid).c_str());
  std::printf("scid              %s\n", to_hex(header.scid).c_str());
  if (!header.token.empty()) std::printf("token             %zu bytes\n", header.token.size());
  std::printf("first byte        0x%02x -> 0x%02x\n", unsigned(header.first_byte),
              unsigned(header.first_byte_unprotected));
  std::printf("pn_length         %d\n", header.pn_length);
  std::printf("packet number     %llu\n", static_cast<unsigned long long>(header.packet_number));
  std::printf("length field      %llu\n", static_cast<unsigned long long>(header.length));
  std::printf("aad               %zu bytes (header_end)\n", header.header_end);

  // Step 2: AEAD.
  Bytes payload;
  std::string derr;
  if (!quic_decrypt_initial(packet.data(), packet.size(), largest_acked, keys, &header, &payload,
                            &derr)) {
    std::printf("error             %s\n", derr.c_str());
    return;
  }
  std::printf("decrypted         %zu bytes\n", payload.size());

  // Step 3: frames.
  std::vector<QuicFrame> frames;
  std::string ferr;
  if (!quic_parse_frames(payload.data(), payload.size(), &frames, &ferr)) {
    std::printf("frames_error      %s\n", ferr.c_str());
  }
  std::printf("frames            %zu\n", frames.size());
  for (const QuicFrame& f : frames) {
    std::printf("  [0x%02x] %-20s len=%-6llu off=%-8llu %s\n", unsigned(f.type),
                f.type_name.c_str(), static_cast<unsigned long long>(f.length),
                static_cast<unsigned long long>(f.offset), f.note.c_str());
    if (f.type == 0x06 && f.data.size() <= 64) {
      std::printf("         data %s\n", to_hex(f.data).c_str());
    } else if (f.type == 0x06) {
      std::printf("         data %s ... (%zu bytes)\n", to_hex(f.data.data(), 32).c_str(),
                  f.data.size());
    }
  }

  // Step 4: reassembly + ClientHello.
  QuicCryptoStream stream;
  std::string serr;
  if (!stream.absorb(frames)) {
    std::printf("crypto_error      %s\n", stream.error.c_str());
    return;
  }
  std::printf("crypto stream     %zu bytes\n", stream.bytes.size());
  if (stream.bytes.empty()) {
    std::printf("sni               (none)\n");
    std::printf("alpn              (none)\n");
    return;
  }
  QuicClientHello hello;
  std::string herr;
  if (!quic_parse_client_hello(stream.bytes.data(), stream.bytes.size(), &hello, &herr)) {
    std::printf("error             %s\n", herr.c_str());
    return;
  }
  std::printf("tls version       %s\n", hello.version.c_str());
  std::printf("cipher suites     %zu\n", hello.cipher_suites.size());
  std::printf("sni               %s\n", hello.host.empty() ? "(none)" : hello.host.c_str());
  std::printf("alpn              %s\n", hello.alpn.empty() ? "(none)" : hello.alpn.c_str());
  if (hello.alpns.size() > 1) {
    std::string all;
    for (const std::string& a : hello.alpns) {
      if (!all.empty()) all += ",";
      all += a;
    }
    std::printf("alpn (all)        %s\n", all.c_str());
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string mode, arg;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--hex" || a == "--file") {
      mode = a;
      if (i + 1 < argc) arg = argv[++i];
    } else if (a == "--rfc9001") {
      mode = a;
    } else if (a == "--selfcheck") {
      mode = a;
    } else if (a == "--help" || a == "-h") {
      std::printf("usage: quic_probe --hex <hex> | --file <path> | --rfc9001 | --selfcheck\n");
      return 0;
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", a.c_str());
      return 2;
    }
  }
  if (mode.empty()) {
    std::fprintf(stderr, "usage: quic_probe --hex <hex> | --file <path> | --rfc9001 | --selfcheck\n");
    return 2;
  }

  if (mode == "--selfcheck") {
    std::string report;
    const bool ok = quic_selfcheck(&report);
    std::fputs(report.c_str(), stdout);
    std::printf("selfcheck         %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
  }

  Bytes packet;
  if (mode == "--hex") {
    packet = from_hex(arg);
  } else if (mode == "--file") {
    const std::string raw = slurp(arg);
    if (raw.empty()) {
      std::fprintf(stderr, "cannot read %s (or it is empty)\n", arg.c_str());
      return 2;
    }
    if (looks_like_hex_text(raw)) {
      packet = from_hex(raw);
    } else {
      packet.assign(reinterpret_cast<const u8*>(raw.data()),
                    reinterpret_cast<const u8*>(raw.data()) + raw.size());
    }
  } else {  // --rfc9001
    const std::string raw = slurp("_br\\quic_a2_client_initial.hex");
    if (raw.empty()) {
      std::fprintf(stderr,
                   "--rfc9001 needs _br\\quic_a2_client_initial.hex (the A.2 vector extracted\n"
                   "from rfc9001.txt); use --selfcheck, which carries the same vector inline.\n");
      return 2;
    }
    packet = from_hex(raw);
  }

  if (packet.empty()) {
    std::fprintf(stderr, "no packet bytes\n");
    return 2;
  }
  print_packet(packet, 0);
  return 0;
}
