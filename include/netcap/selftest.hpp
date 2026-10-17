// Self-test suite and synthetic traffic generator.
#pragma once

#include <string>

namespace netcap {

/// Runs every built-in check (low-level readers, address parsing, the
/// dissector, IPv4 fragment reassembly, application-layer extraction, the
/// filter engine and the pcap reader/writer).
///
/// Returns the number of failed checks (0 = everything passed).  When `report`
/// is non-null it receives a readable log; `verbose` adds one line per passing
/// check.
int run_selftest(bool verbose, std::string* report);

/// Writes a small, hand-built pcap file exercising ARP, IPv4, IPv6, VLAN, TCP,
/// UDP, ICMP, DNS, HTTP, TLS ClientHello, SSH, QUIC and IPv4 fragmentation.
/// `packets_written` receives the record count.
int write_sample_pcap(const std::string& path, int* packets_written, std::string* error);

/// The key log written beside a generated sample capture: "sample.pcap" becomes
/// "sample.keys".  It holds the TLS 1.3 secrets of the HTTPS session in the
/// capture, so the generated traffic can be decrypted offline.
std::string sample_keylog_path(const std::string& capture_path);

}  // namespace netcap
