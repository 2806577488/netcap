// WFP (Windows Filtering Platform) blocking filters, installed from user mode.
//
// This is the "make it stick" layer of the blocker: hosts files and a DNS sink
// only stop name lookups, and SetTcpEntry only kills connections that already
// exist.  A WFP filter at the ALE_AUTH_CONNECT layer stops the connection from
// ever being established, for every program on the machine, without a kernel
// driver and without loading anything into other processes.
//
// Two things to know before using it:
//   * installing a filter needs Administrator rights (the BFE rejects the call
//     with "Access is denied" otherwise) - this is enforced by Windows, not by
//     us, and the error is reported verbatim;
//   * a filter that is installed while this process lives disappears with it,
//     because the engine is opened in a *dynamic* session.  Nothing is left
//     behind after a crash, which is the safe default for a tool that can cut
//     the machine off the network.
#ifndef NETCAP_WFP_HPP
#define NETCAP_WFP_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

// Which way the filter looks at a connection.
enum class WfpDirection : u8 { Outbound = 0, Inbound = 1 };

const char* wfp_direction_name(WfpDirection);

// One filter to install.  Every field is optional except that at least one of
// remote_ip / remote_port / protocol / app_path must be set - a filter that
// matches everything would block the whole machine.
struct WfpSpec {
  std::string name;          // display name shown by WFP diagnostics
  int family = 4;            // 4 or 6
  u8 protocol = 0;           // 6 TCP, 17 UDP, 0 = any protocol
  std::string remote_ip;     // empty = any address
  u16 remote_port = 0;       // 0 = any port
  std::string app_path;      // image path, empty = any process
  WfpDirection direction = WfpDirection::Outbound;

  bool empty() const;        // matches everything -> refused
  bool specific() const;     // has at least one condition
  std::string describe() const;
};

// "1.2.3.4", "1.2.3.4:443", "1.2.3.4:443/udp", "[::1]:443", "port=443",
// "tcp", "app=C:\games\thing.exe", and space-separated combinations of those.
// Returns false and fills *error on anything that cannot be understood.
bool wfp_parse_spec(const std::string& text, WfpSpec* out, std::string* error);

// Help text for --wfp-help and the usage screen.
std::string wfp_help();

struct WfpFilterRecord {
  u64 id = 0;                // filter id handed back by the BFE
  WfpSpec spec;
};

// Bookkeeping + policy; the actual BFE calls live in the platform layer.
class WfpEngine {
 public:
  WfpEngine();
  ~WfpEngine();
  WfpEngine(const WfpEngine&) = delete;
  WfpEngine& operator=(const WfpEngine&) = delete;

  // Opens the BFE session.  False + *error when not elevated.
  bool open(std::string* error);
  void close();
  bool opened() const;

  bool add_block(const WfpSpec& spec, u64* id, std::string* error);
  bool remove(u64 id, std::string* error);
  bool remove_all(std::string* error);

  std::size_t filters() const { return installed_.size(); }
  const std::vector<WfpFilterRecord>& installed() const { return installed_; }
  u64 added_total() const { return added_; }
  u64 removed_total() const { return removed_; }
  u64 failed_total() const { return failed_; }
  const std::string& error() const { return error_; }

  std::string describe() const;
  std::string report() const;

  // True when this build can talk to the BFE at all; *note explains the
  // platform and the privilege requirement.
  static bool available(std::string* note);

 private:
  void* engine_ = nullptr;  // platform handle, kept opaque on purpose
  std::vector<WfpFilterRecord> installed_;
  std::string error_;
  u64 added_ = 0;
  u64 removed_ = 0;
  u64 failed_ = 0;
};

// ---------------------------------------------------------------------------
// Platform layer.  Implemented in src/wfp_win.cpp (Windows) and by a stub in
// src/wfp.cpp everywhere else.
// ---------------------------------------------------------------------------
bool wfp_platform_available(std::string* note);
std::string wfp_platform_note();
// True when this process already holds the rights the BFE wants for adding a
// filter (Windows: the token is elevated).  Used to warn before --wfp-apply
// fails, not to gate anything.
bool wfp_platform_elevated();
bool wfp_platform_open(void** engine, std::string* error);
bool wfp_platform_add_block(void* engine, const WfpSpec& spec, u64* id, std::string* error);
bool wfp_platform_remove(void* engine, u64 id, std::string* error);
void wfp_platform_close(void* engine);

}  // namespace netcap

#endif  // NETCAP_WFP_HPP
