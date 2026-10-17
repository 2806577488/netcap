// Process attribution: which program owns a captured packet?
//
// A packet carries no process identifier, so the only honest way to answer the
// question on Windows is to ask the OS who owns the local endpoint.  The IP
// Helper API exposes the endpoint tables together with the owning PID
// (GetExtendedTcpTable / GetExtendedUdpTable with the OWNER_PID table class);
// the PID is then resolved to an image name and path once and cached.
//
// Everything here is deliberately testable without a network capture: the
// endpoint table is a plain container that can be filled from the OS *or* by
// hand, and ProcessTable::add_endpoint / add_process exist exactly for that.
#ifndef NETCAP_PROC_HPP
#define NETCAP_PROC_HPP

#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/dissect.hpp"

namespace netcap {

// One running process, as far as attribution needs to know about it.
struct ProcessInfo {
  u32 pid = 0;
  std::string name;   // image base name, e.g. "chrome.exe" (may be empty)
  std::string path;   // full image path when it could be read
  std::string key;    // lowercased name, used by `proc <substring>` matching

  bool named() const { return !name.empty(); }
  // "chrome.exe (1234)" or "pid 1234" when the name could not be read.
  std::string label() const;
};

// Answer to "who owns this packet?".
struct ProcOwnership {
  bool known = false;
  ProcessInfo proc;
  int dir = -1;              // 0 = outbound (local endpoint is the source), 1 = inbound
  bool from_cache = false;   // resolved from the per-flow memory, not the table
  const char* why = "attribution not attempted";

  void reset(const char* reason) {
    known = false;
    proc = ProcessInfo();
    dir = -1;
    from_cache = false;
    why = reason;
  }
};

// Is attribution implemented on this build, and what does it need?
bool proc_attribution_available(std::string* note);
// One-line description of the platform mechanism (`netstat -ano` equivalent).
std::string proc_platform_note();

// --- platform layer (proc_win.cpp / proc_stub.cpp) --------------------------
// One row of the OS endpoint table.
struct ProcEndpoint {
  int family = 4;          // 4 or 6
  u8 addr[16] = {0};       // local address, network order; IPv4 lives in [0,4)
  u16 port = 0;            // local port, host order
  u8 proto = 0;            // 6 = TCP, 17 = UDP
  u32 pid = 0;
  // TCP rows also carry the peer and the connection state.  The peer is what
  // makes proxy correlation possible: a browser -> 127.0.0.1:7890 row and the
  // proxy's own 192.168.x.x:port -> real.server:443 row are two halves of one
  // user request.  UDP rows and listeners leave these at zero.
  u8 raddr[16] = {0};      // remote address, network order
  u16 rport = 0;           // remote port, host order
  u8 state = 0;            // TCP state (MIB_TCP_STATE_*); 0 = unknown/UDP
};

// Reads the OS endpoint table.  Returns false and fills *error when the platform
// cannot answer; ProcessTable::refresh() then keeps its previous contents.
bool proc_collect_endpoints(std::vector<ProcEndpoint>* out, std::string* error);
// PID -> image name for every running process, without opening a single handle.
// This is the fallback for processes that refuse OpenProcess (protected ones,
// other sessions, other integrity levels); it carries no image path.
bool proc_collect_process_names(std::map<u32, std::string>* out);
// PID -> image name and path.  Returns false when the process cannot be opened
// (protected processes are the normal case, not an error worth failing over).
bool proc_resolve_process(u32 pid, ProcessInfo* out);

// Turns a process name into something usable as a file name: keeps
// [A-Za-z0-9._-], replaces every other byte with '_', and never returns empty.
std::string proc_sanitize_name(const std::string& name);

// The OS endpoint table plus the processes behind it.
class ProcessTable {
 public:
  // Re-reads the endpoint tables and resolves any new PIDs.  Returns false and
  // fills *error when the OS refused (the usual reason is a restricted token or
  // an unsupported platform); the previous contents are then left untouched.
  bool refresh(std::string* error = nullptr);

  std::size_t endpoints() const { return endpoints_.size(); }
  std::size_t processes() const { return procs_.size(); }
  i64 refreshed_us() const { return refreshed_us_; }
  u64 refreshes() const { return refreshes_; }

  /// Every row of the last successful read, in the order the OS handed them out.
  /// The proxy correlator needs the peers and states that `owner()` throws away.
  const std::vector<ProcEndpoint>& raw_endpoints() const { return raw_; }

  // Owner of a local endpoint.  `family` is 4 or 6 and `addr` points at 4 or 16
  // bytes in network order.  Returns nullptr when nothing in the table matches.
  const ProcessInfo* owner(int family, const u8* addr, u16 port, u8 proto) const;
  // Same, but for a PacketInfo: tries the source side first (outbound traffic),
  // then the destination side (inbound).  *dir reports which one matched.
  const ProcessInfo* owner_of(const PacketInfo& pi, int* dir) const;

  const ProcessInfo* by_pid(u32 pid) const;
  // Exact, case-insensitive lookup by image name ("chrome.exe").
  const ProcessInfo* by_name(const std::string& name) const;
  // Every process that owns at least one endpoint, sorted by name then pid.
  std::vector<const ProcessInfo*> owners() const;

  std::string describe() const;

  // --- test seams -----------------------------------------------------------
  void clear();
  void add_process(const ProcessInfo& p);
  void add_endpoint(int family, const u8* addr, u16 port, u8 proto, u32 pid);
  void set_refreshed_us(i64 us) { refreshed_us_ = us; }

 private:
  std::map<std::string, u32> endpoints_;   // packed endpoint -> pid
  std::vector<ProcEndpoint> raw_;          // same rows, peers and states intact
  std::map<u32, ProcessInfo> procs_;       // pid -> process
  i64 refreshed_us_ = 0;
  u64 refreshes_ = 0;
};

struct ProcAttrConfig {
  bool enabled = true;
  i64 table_ttl_us = 1000000;   // re-read the OS table at most this often
  i64 retry_us = 200000;        // ... and not again sooner than this after a miss
  i64 cache_ttl_us = 5000000;   // remember a flow's owner for this long
  bool cache = true;            // learn the owner of a flow once and keep it
};

// Per-packet attribution with a per-flow memory.
//
// Why the memory matters: a capture can miss the SYN (both directions are not
// guaranteed to be seen) or the endpoint can disappear between table reads.
// Once a flow is attributed, later packets of the same flow keep that owner
// until cache_ttl_us passes without a packet.
class ProcAttributor {
 public:
  ProcAttributor();

  void set_config(const ProcAttrConfig& c) { cfg_ = c; }
  const ProcAttrConfig& config() const { return cfg_; }
  void set_enabled(bool on) { cfg_.enabled = on; }
  bool enabled() const { return cfg_.enabled; }

  // The table is owned by the attributor unless one is injected.
  ProcessTable& table() { return table_; }
  const ProcessTable& table() const { return table_; }
  void set_table(ProcessTable* t) { external_ = t; }
  ProcessTable& active_table() { return external_ ? *external_ : table_; }
  const ProcessTable& active_table() const { return external_ ? *external_ : table_; }

  // Attributes one packet.  The returned reference is valid until the next call.
  //
  // Every time comparison inside uses netcap's own monotonic clock, never the
  // packet timestamp: a pcap replay carries timestamps from an arbitrary epoch,
  // and a cache whose expiry is decided by capture time would either never
  // expire or expire instantly.  `ts_us` is accepted for symmetry with the rest
  // of the pipeline and is not used for control flow.
  const ProcOwnership& attribute(const PacketInfo& pi, i64 ts_us);
  const ProcOwnership& last() const { return last_; }

  void clear_cache() { cache_.clear(); }
  std::size_t cache_size() const { return cache_.size(); }
  void gc(i64 now_us);

  u64 lookups() const { return lookups_; }
  u64 hits() const { return hits_; }
  u64 misses() const { return misses_; }
  u64 cache_hits() const { return cache_hits_; }
  u64 refreshes() const { return refreshes_; }
  u64 unnameable() const { return unnameable_; }

  std::string describe() const;

  /// Called right after a successful table refresh, with that same snapshot.
  /// The proxy correlator needs the peers and states the owner lookup discards,
  /// and it must see exactly the snapshot the attribution just used.
  void set_refresh_hook(std::function<void(const ProcessTable&)> hook) {
    refresh_hook_ = std::move(hook);
  }

 private:
  struct Entry {
    ProcessInfo proc;
    int dir = -1;
    i64 ts_us = 0;
  };
  static std::string flow_key(const PacketInfo& pi);

  ProcAttrConfig cfg_;
  ProcessTable table_;
  ProcessTable* external_ = nullptr;
  std::map<std::string, Entry> cache_;   // directional 5-tuple -> owner
  ProcOwnership last_;
  std::string why_storage_;              // backing store for last_.why when dynamic
  i64 last_miss_us_ = 0;
  std::function<void(const ProcessTable&)> refresh_hook_;
  u64 lookups_ = 0, hits_ = 0, misses_ = 0, cache_hits_ = 0, refreshes_ = 0;
  u64 unnameable_ = 0;
};

// Per-process counters for the summary: packets, bytes, flows, transactions.
struct ProcCounters {
  u32 pid = 0;
  std::string name;
  u64 packets = 0;
  u64 bytes = 0;
  u64 flows = 0;
  u64 transactions = 0;
  u64 decrypted_streams = 0;

  std::string label() const;
};

class ProcTotals {
 public:
  void add_packet(const ProcessInfo& p, u64 bytes);
  void add_flow(const ProcessInfo& p);
  void add_transaction(const ProcessInfo& p);
  void add_decrypted_stream(const ProcessInfo& p);

  bool empty() const { return by_pid_.empty(); }
  std::size_t size() const { return by_pid_.size(); }
  void clear() { by_pid_.clear(); }
  // Sorted by bytes (descending), then pid, so the report is deterministic.
  std::vector<ProcCounters> sorted() const;
  u64 total_packets() const;
  u64 total_bytes() const;

 private:
  ProcCounters& slot(const ProcessInfo& p);
  std::map<u32, ProcCounters> by_pid_;
};

}  // namespace netcap

#endif  // NETCAP_PROC_HPP
