// h3_probe -- a standalone self-check and packet opener for the HTTP/3-over-QUIC
// decoder in `src/h3.cpp`.  It is deliberately outside CMake: the probe is a
// debugging tool, and the library itself is built by whoever owns the build
// (the parent session owns CMakeLists.txt).
//
// Build (MinGW g++ 13.2.0, from the repository root) -- this is the exact
// command this probe was built and run with, and it is one line on purpose so
// that a copy-paste cannot lose a continuation:
//
// g++ -std=c++20 -O2 -Wall -Wextra -Iinclude tools/h3_probe.cpp src/h3.cpp src/quic.cpp src/crypto.cpp src/common.cpp src/tls.cpp -o tools/h3_probe.exe -lws2_32 -lbcrypt
//
// `tls.cpp` is needed because `quic.cpp` calls `tls_parse_client_hello` for its
// ClientHello walk; `http2.cpp` is NOT needed, because the HPACK Huffman table
// is copied into `src/h3.cpp` on purpose (see the comment at the top of that
// file).  If a future change drops the ClientHello walk, the link line can lose
// `src/tls.cpp` again.
//
// Usage:
//   h3_probe.exe --selfcheck                 run every embedded check
//   h3_probe.exe --keyset <suite> <secret>   derive and print a 1-RTT keyset
//   h3_probe.exe --packet <dcid_hex> <largest_pn> <packet_hex>
//                                            decrypt one 1-RTT packet and walk it
//   h3_probe.exe --stream <stream_hex>       decode a hand-built request stream
//   h3_probe.exe --dump <file>               run the above over a hex dump file
//
// `--dump` accepts the format `tools/h3_probe.exe` writes and the one
// `xxd -p`/`certutil -encodehex` produce: whitespace, blank lines and `#`
// comments are ignored, and a line may be prefixed with `dcid=`, `pn=` or
// `secret=`.  Every command exits non-zero when a check fails, so the probe can
// be used from a script.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "netcap/h3.hpp"

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
  std::cout << (ok ? "  ok   " : "  FAIL ") << what << "\n";
  if (!ok) ++failures;
}

bool parse_suite(const std::string& text, netcap::u16* out) {
  if (text == "aes128" || text == "0x1301" || text == "1301") {
    *out = netcap::kH3TlsAes128GcmSha256;
    return true;
  }
  if (text == "aes256" || text == "0x1302" || text == "1302") {
    *out = netcap::kH3TlsAes256GcmSha384;
    return true;
  }
  if (text == "chacha20" || text == "0x1303" || text == "1303") {
    *out = netcap::kH3TlsChacha20Poly1305Sha256;
    return true;
  }
  return false;
}

std::string read_all(const std::string& path, bool* ok) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    *ok = false;
    return std::string();
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  *ok = true;
  return ss.str();
}

// One named blob out of a dump file: blank lines and `#` comments are ignored,
// and a `key=value` prefix is kept so the caller can pick out the DCID, the
// largest packet number and the secret alongside the packet bytes.
struct DumpEntry {
  std::string key;
  std::string hex;   // hex digits only, for dcid/secret/packet/stream
  std::string text;  // the value as written, for suite (a name) and pn (decimal)
};

std::vector<DumpEntry> parse_dump(const std::string& text) {
  std::vector<DumpEntry> out;
  std::istringstream in(text);
  std::string line;
  while (std::getline(in, line)) {
    const std::size_t hash = line.find('#');
    if (hash != std::string::npos) line = line.substr(0, hash);
    std::size_t b = line.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) continue;
    line = line.substr(b);
    DumpEntry e;
    const std::size_t eq = line.find('=');
    if (eq != std::string::npos) {
      e.key = line.substr(0, eq);
      line = line.substr(eq + 1);
    }
    // The value is kept verbatim as well as hex-filtered: `suite=chacha20` and
    // `pn=654360563` are not hex, and hex-filtering them silently turned the
    // first into "caca20" and dropped the 9 from the second.
    std::string raw = line;
    while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\r')) {
      raw.pop_back();
    }
    e.text = raw;
    std::string hex;
    for (char ch : raw) {
      if (std::isxdigit(static_cast<unsigned char>(ch))) hex.push_back(ch);
    }
    e.hex = hex;
    if (!e.text.empty()) out.push_back(e);
  }
  return out;
}

void walk_frames(const netcap::Bytes& payload, bool show_streams) {
  std::vector<netcap::QuicFrameInfo> frames;
  std::string err;
  if (!netcap::quic_parse_frames_rtt(payload.data(), payload.size(), &frames, &err)) {
    std::cout << "  frames: " << err << "\n";
    return;
  }
  for (const auto& f : frames) {
    std::cout << "  frame " << f.type_name << " (" << f.length << " bytes)";
    if (!f.note.empty()) std::cout << " -- " << f.note;
    std::cout << "\n";
    if (show_streams && f.type >= 0x08 && f.type <= 0x0f) {
      netcap::H3Request req;
      std::string serr;
      std::vector<netcap::QuicFrameInfo> one{f};
      if (netcap::h3_request_from_stream_frames(one, &req, &serr)) {
        std::cout << "    " << req.method << " " << req.scheme << "://" << req.authority
                  << req.path << "\n";
      } else {
        std::cout << "    (not a complete request: " << serr << ")\n";
      }
    }
  }
}

int run_selfcheck() {
  std::cout << "h3 self-check\n";
  // The RFC 9001 A.5 packet, verbatim; the length assertion is the cheap guard
  // that caught a one-byte transcription slip during development.
  netcap::Bytes a5 = netcap::from_hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
  check(a5.size() == 21, "the RFC 9001 A.5 packet constant is 21 bytes, as the RFC states");
  std::string report;
  const bool ok = netcap::h3_selfcheck(&report);
  // `report` already carries one line per checked group: "ok   <group>" for each
  // group that finished, or a final "FAIL <group>: <detail>" naming the group
  // that did not.  Printing it as-is is what keeps this one line per check.
  if (!report.empty()) std::cout << report;
  if (ok) {
    check(true, "every embedded vector, round trip and refusal check passed");
  } else {
    ++failures;
  }
  std::cout << (failures == 0 ? "self-check: all checks passed\n" : "self-check: FAILURES\n");
  return failures == 0 ? 0 : 1;
}

int run_keyset(const std::string& suite_text, const std::string& secret_hex) {
  netcap::u16 suite = 0;
  if (!parse_suite(suite_text, &suite)) {
    std::cout << "unknown suite \"" << suite_text << "\"; use aes128, aes256 or chacha20\n";
    return 2;
  }
  const netcap::Bytes secret = netcap::from_hex(secret_hex);
  netcap::QuicKeyset keys;
  std::string err;
  if (!netcap::quic_keyset_from_secret(suite, secret, &keys, &err)) {
    std::cout << "keyset failed: " << err << "\n";
    return 1;
  }
  std::cout << "secret " << netcap::to_hex(keys.secret) << "\n";
  std::cout << "key    " << netcap::to_hex(keys.key) << "\n";
  std::cout << "iv     " << netcap::to_hex(keys.iv) << "\n";
  std::cout << "hp     " << netcap::to_hex(keys.hp) << "\n";
  netcap::Bytes next;
  if (netcap::quic_next_secret(secret, &next, &err)) {
    std::cout << "ku     " << netcap::to_hex(next) << "\n";
  } else {
    std::cout << "ku     (" << err << ")\n";
  }
  return 0;
}

int run_packet(const std::string& dcid_hex, const std::string& largest_pn_text,
               const std::string& packet_hex, const std::string& suite_text,
               const std::string& secret_hex) {
  netcap::u16 suite = netcap::kH3TlsChacha20Poly1305Sha256;
  if (!suite_text.empty() && !parse_suite(suite_text, &suite)) {
    std::cout << "unknown suite \"" << suite_text << "\"\n";
    return 2;
  }
  netcap::QuicKeyset keys;
  std::string err;
  if (secret_hex.empty()) {
    std::cout << "a --packet run needs --secret <hex>\n";
    return 2;
  }
  if (!netcap::quic_keyset_from_secret(suite, netcap::from_hex(secret_hex), &keys, &err)) {
    std::cout << "keyset failed: " << err << "\n";
    return 1;
  }
  // `-` or `none` means "this packet really has an empty Destination Connection
  // ID", which a shell makes awkward to pass as a bare empty argument.
  const netcap::Bytes dcid =
      (dcid_hex == "-" || dcid_hex == "none") ? netcap::Bytes() : netcap::from_hex(dcid_hex);
  const netcap::Bytes packet = netcap::from_hex(packet_hex);
  const netcap::u64 largest =
      largest_pn_text.empty() ? 0 : std::strtoull(largest_pn_text.c_str(), nullptr, 0);

  netcap::QuicShortHeader hdr;
  if (!netcap::quic_decrypt_short_full(keys, dcid.data(), dcid.size(), packet.data(),
                                       packet.size(), largest, &hdr, &err)) {
    std::cout << "decrypt failed: " << err << "\n";
    return 1;
  }
  std::cout << "packet number " << hdr.packet_number << " (" << hdr.pn_length << " bytes)\n";
  std::cout << "key phase     " << (hdr.key_phase ? "1 (updated)" : "0") << "\n";
  std::cout << "header        " << netcap::to_hex(hdr.header) << "\n";
  std::cout << "payload       " << netcap::to_hex(hdr.payload) << "\n";
  walk_frames(hdr.payload, true);
  return 0;
}

int run_stream(const std::string& stream_hex, bool uni) {
  const netcap::Bytes stream = netcap::from_hex(stream_hex);
  std::string err;
  if (uni) {
    netcap::H3UniStream s;
    if (!netcap::h3_parse_uni_stream(stream, &s, &err)) {
      std::cout << "unidirectional stream failed: " << err << "\n";
      return 1;
    }
    std::cout << "stream type " << s.type << " (" << s.type_name << ")\n";
    for (const auto& f : s.frames) {
      std::cout << "  frame " << f.type_name << " (" << f.length << " bytes)\n";
    }
    return 0;
  }
  netcap::H3Request req;
  if (!netcap::h3_request_from_stream(stream, true, &req, &err)) {
    std::cout << "request failed: " << err << "\n";
    return 1;
  }
  std::cout << req.method << " " << req.scheme << "://" << req.authority << req.path << "\n";
  for (const auto& kv : req.headers) std::cout << "  " << kv.first << ": " << kv.second << "\n";
  return 0;
}

int run_dump(const std::string& path) {
  bool ok = false;
  const std::string text = read_all(path, &ok);
  if (!ok) {
    std::cout << "cannot read " << path << "\n";
    return 2;
  }
  const std::vector<DumpEntry> entries = parse_dump(text);
  if (entries.empty()) {
    std::cout << "no hex blobs in " << path << "\n";
    return 2;
  }
  std::string dcid_hex, secret_hex, suite_text, pn_text, packet_hex, stream_hex;
  for (const auto& e : entries) {
    if (e.key == "dcid") dcid_hex = e.hex;
    else if (e.key == "secret") secret_hex = e.hex;
    else if (e.key == "suite") suite_text = e.text;
    else if (e.key == "pn") pn_text = e.text;
    else if (e.key == "packet") packet_hex = e.hex;
    else if (e.key == "stream") stream_hex = e.hex;
    else if (packet_hex.empty()) packet_hex = e.hex;
  }
  std::cout << path << ": " << entries.size() << " blob(s)\n";
  // A dump file may carry both a packet and a request stream; decode whichever
  // are present rather than stopping at the first one, so one file can be the
  // whole worked example.  The two runs are separated by a banner because their
  // outputs would otherwise read as one confusing block.
  if (packet_hex.empty() && stream_hex.empty()) {
    std::cout << "no packet or stream blob found\n";
    return 2;
  }
  int rc = 0;
  if (!packet_hex.empty()) {
    if (secret_hex.empty()) {
      std::cout << "packet " << packet_hex << "\n(no secret= line, so it cannot be opened)\n";
      return 2;
    }
    std::cout << "== packet ==\n";
    rc |= run_packet(dcid_hex, pn_text, packet_hex, suite_text, secret_hex);
  }
  if (!stream_hex.empty()) {
    std::cout << "== request stream ==\n";
    rc |= run_stream(stream_hex, false);
  }
  return rc;
}

void usage() {
  std::cout <<
      "h3_probe -- HTTP/3 over QUIC 1-RTT decoder probe\n"
      "\n"
      "  --selfcheck                run the embedded RFC 9001 A.5 / RFC 9204\n"
      "                             appendix B vectors and the round trips\n"
      "  --keyset <suite> <secret>  derive the 1-RTT keyset (suite: aes128,\n"
      "                             aes256, chacha20) and print key/iv/hp/ku\n"
      "  --secret <hex>             traffic secret for --packet\n"
      "  --suite <name>             cipher suite for --packet (default chacha20)\n"
      "  --packet <dcid_hex> <largest_pn> <packet_hex>\n"
      "                             open one short-header packet and walk frames\n"
      "  --stream <stream_hex>      decode a request stream\n"
      "  --uni <stream_hex>         decode a unidirectional stream\n"
      "  --dump <file>              read dcid=/pn=/secret=/packet=/stream= blobs\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> args(argv + 1, argv + argc);
  if (args.empty()) {
    usage();
    return 2;
  }
  const std::string cmd = args[0];
  if (cmd == "--selfcheck") return run_selfcheck();
  if (cmd == "--keyset" && args.size() >= 3) return run_keyset(args[1], args[2]);
  if (cmd == "--stream" && args.size() >= 2) return run_stream(args[1], false);
  if (cmd == "--uni" && args.size() >= 2) return run_stream(args[1], true);
  if (cmd == "--dump" && args.size() >= 2) return run_dump(args[1]);
  if (cmd == "--packet" && args.size() >= 4) {
    std::string suite_text, secret_hex;
    for (std::size_t i = 4; i + 1 < args.size(); ++i) {
      if (args[i] == "--suite") suite_text = args[i + 1];
      if (args[i] == "--secret") secret_hex = args[i + 1];
    }
    return run_packet(args[1], args[2], args[3], suite_text, secret_hex);
  }
  usage();
  return 2;
}
