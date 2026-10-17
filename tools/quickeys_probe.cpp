// quickeys_probe: command-line front end for the QUIC key-log reader and the
// equal-length 1-RTT rewrite.
//
// Build (from the repository root; the project has no third-party dependencies).
// The backslash continuations are written without a trailing space, and this
// paragraph is the only place the command appears, because "-Wcomment" warns on
// a backslash at the end of a comment line:
//
//   g++ -std=c++20 -O2 -Wall -Wextra -Iinclude tools/quickeys_probe.cpp src/quickeys.cpp src/h3.cpp src/quic.cpp src/crypto.cpp src/common.cpp src/tls.cpp -o tools/quickeys_probe.exe -lws2_32 -lbcrypt
//
// Modes:
//   --selfcheck              the embedded checks (parser, refresh, RFC 9001 A.5
//                            round trip, refusals); exit 0 when all pass
//   --parse <file>           dump every key-log entry that parsed
//   --keys <file> <dcid>     derive the 1-RTT keysets for one connection id
//   --rfc                    the A.5 round trip, printing the input packet, the
//                            re-sealed packet and the byte comparison
//   --demo                   a same-length rewrite of the A.5 packet with a
//                            changed payload, before/after hex
//
// Scratch files live in `_qk/` next to the working directory.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "netcap/quickeys.hpp"

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
  std::cout << (ok ? "ok   " : "FAIL ") << what << "\n";
  if (!ok) ++failures;
}

const char* kA5Packet = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";
const char* kA5Secret = "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b";

// RFC 9001 A.5: the vector gives pn 654360564 but the packet carries only its
// low 24 bits, so the receiver's window must sit inside the same 2^24 block.
constexpr netcap::u64 kA5LargestPn = 654360563u;

void usage() {
  std::cout << "quickeys_probe -- QUIC key logs and the equal-length 1-RTT rewrite\n"
               "  --selfcheck              run the embedded checks\n"
               "  --parse <file>           dump the entries of a QUIC key log\n"
               "  --keys <file> <dcid>     derive the 1-RTT keysets of one connection\n"
               "  --rfc                    RFC 9001 A.5 decrypt -> re-seal round trip\n"
               "  --demo                   same-length rewrite, before/after hex\n";
}

int run_selfcheck() {
  std::cout << "quickeys self-check\n";
  std::string report;
  const bool ok = netcap::quickeys_selfcheck(&report);
  // `report` carries one line per group: "ok   <group>", or the final
  // "FAIL <group>: <detail>" that names what did not finish.
  if (!report.empty()) std::cout << report;
  if (ok) {
    check(true, "every embedded vector, round trip and refusal check passed");
  } else {
    ++failures;
  }
  std::cout << (failures == 0 ? "self-check: all checks passed\n" : "self-check: FAILURES\n");
  return failures == 0 ? 0 : 1;
}

int run_parse(const std::string& path) {
  netcap::QuicKeyLog log;
  std::string err;
  if (!log.load_file(path, &err)) {
    std::cout << "load failed: " << err << "\n";
    return 1;
  }
  std::cout << log.describe() << "\n";
  for (const netcap::QuicKeyEntry& e : log.entries()) {
    std::cout << (e.from_client ? "client" : "server") << " gen " << e.generation << "  id "
              << e.conn_id_hex << "  " << e.label << "  secret "
              << netcap::to_hex(e.secret) << "  (" << e.secret.size() << " bytes, from " << e.source
              << ")\n";
  }
  return 0;
}

int run_keys(const std::string& path, const std::string& dcid_hex) {
  netcap::QuicKeyLog log;
  std::string err;
  if (!log.load_file(path, &err)) {
    std::cout << "load failed: " << err << "\n";
    return 1;
  }
  const netcap::Bytes dcid = netcap::from_hex(dcid_hex);
  netcap::u16 suite = 0;
  netcap::QuicKeyset client;
  netcap::QuicKeyset server;
  if (!netcap::quic_keysets_from_keylog(log, dcid, &suite, &client, &server, &err)) {
    std::cout << "no keysets: " << err << "\n";
    return 1;
  }
  std::cout << "suite 0x" << std::hex << suite << std::dec << "\n";
  if (client.ready) {
    std::cout << "client key " << netcap::to_hex(client.key) << "\n"
              << "client iv  " << netcap::to_hex(client.iv) << "\n"
              << "client hp  " << netcap::to_hex(client.hp) << "\n";
  } else {
    std::cout << "client keyset: no client secret in the log\n";
  }
  if (server.ready) {
    std::cout << "server key " << netcap::to_hex(server.key) << "\n"
              << "server iv  " << netcap::to_hex(server.iv) << "\n"
              << "server hp  " << netcap::to_hex(server.hp) << "\n";
  } else {
    std::cout << "server keyset: no server secret in the log\n";
  }
  return 0;
}

// Open the A.5 packet with the A.5 keyset and hand back both.
bool a5_context(netcap::QuicKeyset* keys, netcap::QuicShortHeader* hdr, netcap::Bytes* packet,
                std::string* error) {
  *packet = netcap::from_hex(kA5Packet);
  if (!netcap::quic_keyset_from_secret(netcap::kH3TlsChacha20Poly1305Sha256,
                                       netcap::from_hex(kA5Secret), keys, error)) {
    return false;
  }
  // Use THIS module's opener, not `h3`'s: the two disagree about the first byte
  // (four mask bits versus the five RFC 9001 Figure 6 specifies), so the `h3`
  // opener reports the A.5 packet's first byte as 0x41 rather than 0x42.
  netcap::Bytes payload;
  return netcap::quic_open_short(*keys, *packet, 0, kA5LargestPn, hdr, &payload, error);
}

int run_rfc() {
  netcap::QuicKeyset keys;
  netcap::QuicShortHeader hdr;
  netcap::Bytes packet;
  std::string err;
  if (!a5_context(&keys, &hdr, &packet, &err)) {
    std::cout << "A.5 open failed: " << err << "\n";
    return 1;
  }
  std::cout << "input        " << netcap::to_hex(packet) << " (" << packet.size() << " bytes)\n";
  std::cout << "pn           " << hdr.packet_number << " (pn_length " << hdr.pn_length << ")\n";
  std::cout << "header       " << netcap::to_hex(hdr.header) << "\n";
  std::cout << "payload      " << netcap::to_hex(hdr.payload) << "\n";
  netcap::Bytes again;
  // `kA5LargestPn` must be passed: A.5's packet number is 654360564 but only its
  // low three bytes are on the wire, so with largest_pn 0 the truncated field
  // decodes to 49140, the nonce is built from the wrong full number, and the
  // packet honestly fails to authenticate.
  if (!netcap::quic_reseal_same_pn(keys, packet, hdr.payload, &again, &err, kA5LargestPn)) {
    std::cout << "re-seal failed: " << err << "\n";
    return 1;
  }
  std::cout << "re-sealed    " << netcap::to_hex(again) << " (" << again.size() << " bytes)\n";
  const bool identical = (again == packet);
  check(identical, "the re-sealed packet is byte-identical to the RFC's");
  return identical ? 0 : 1;
}

int run_demo() {
  netcap::QuicKeyset keys;
  netcap::QuicShortHeader hdr;
  netcap::Bytes packet;
  std::string err;
  if (!a5_context(&keys, &hdr, &packet, &err)) {
    std::cout << "A.5 open failed: " << err << "\n";
    return 1;
  }
  netcap::Bytes changed = hdr.payload;
  changed[0] = static_cast<netcap::u8>(changed[0] ^ 0x01);  // PING 0x01 -> 0x00, still one byte
  netcap::Bytes swapped;
  if (!netcap::quic_reseal_same_pn(keys, packet, changed, &swapped, &err, kA5LargestPn)) {
    std::cout << "rewrite failed: " << err << "\n";
    return 1;
  }
  std::cout << "before  " << netcap::to_hex(packet) << "  payload " << netcap::to_hex(hdr.payload)
            << "\n";
  std::cout << "after   " << netcap::to_hex(swapped) << "  payload " << netcap::to_hex(changed)
            << "\n";
  check(swapped.size() == packet.size(), "the rewrite is exactly as long as the input");
  check(swapped != packet, "the ciphertext actually changed");
  netcap::QuicShortHeader re;
  netcap::Bytes re_payload;
  const bool opened =
      netcap::quic_open_short(keys, swapped, 0, kA5LargestPn, &re, &re_payload, &err);
  check(opened && re_payload == changed, "the rewritten packet decrypts to the new payload");
  check(opened && re.packet_number == hdr.packet_number,
        "the rewritten packet kept its packet number");

  // The refusal that protects the invariant.
  netcap::Bytes longer = changed;
  longer.push_back(0x00);
  netcap::Bytes refused_out;
  std::string refused_err;
  const bool refused =
      !netcap::quic_reseal_same_pn(keys, packet, longer, &refused_out, &refused_err, kA5LargestPn);
  check(refused, std::string("a longer payload is refused: ") + refused_err);
  return failures == 0 ? 0 : 1;
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
  if (cmd == "--parse" && args.size() >= 2) return run_parse(args[1]);
  if (cmd == "--keys" && args.size() >= 3) return run_keys(args[1], args[2]);
  if (cmd == "--rfc") return run_rfc();
  if (cmd == "--demo") return run_demo();
  usage();
  return 2;
}
