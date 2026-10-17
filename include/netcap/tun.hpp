// Layer-3 tunnel endpoint built on the Wintun driver.
//
// Why: the system proxy only covers programs that honour it, and WFP can only
// drop traffic.  A TUN adapter is the smallest mechanism that gives netcap every
// IP packet of this machine without a kernel driver of our own: Wintun is a
// signed, widely deployed driver (it ships with WireGuard and several VPN
// clients), and wintun.dll is loaded at runtime, so the build stays dependency
// free and the tool keeps working on machines that do not have it.
//
// This file is deliberately split in two halves:
//   * the portable half (snapshots, formatting, availability reporting) is
//     testable anywhere and never touches the machine;
//   * the Windows half creates the adapter, assigns the address and rewrites the
//     default route -- all of which need administrator rights and are only ever
//     done by an explicit command line flag.
#ifndef NETCAP_TUN_HPP
#define NETCAP_TUN_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

// ---------------------------------------------------------------------------
// portable helpers
// ---------------------------------------------------------------------------

// One `0.0.0.0/0` style entry of the routing table.
struct TunRoute {
  std::string destination;  // "0.0.0.0"
  int prefix_len = 0;
  std::string next_hop;  // "192.168.0.1"
  std::uint64_t luid = 0;  // interface NET_LUID
  std::uint32_t ifindex = 0;
  std::uint32_t metric = 0;
};

// Portable, diffable text form of a route set.  An empty set is still a valid
// document (the header line alone), which is what a snapshot taken on a machine
// without a default route looks like.
std::string tun_routes_text(const std::vector<TunRoute>& routes);
bool tun_routes_parse(const std::string& text, std::vector<TunRoute>* routes, std::string* error);

// One interface's IPv4 interface metric (the part of a route's *effective*
// metric that belongs to the adapter, not to the route).
struct TunInterfaceMetric {
  std::uint64_t luid = 0;
  std::uint32_t ifindex = 0;
  std::uint32_t metric = 0;
};

// Everything a takeover has to remember to be undoable, exactly:
//  * `routes`   - the default routes as they were (informational; they are
//                 never deleted, so restore only repairs what went missing),
//  * `ifmetrics`- the interface metrics a takeover lowered, so they can be put
//                 back byte for byte,
//  * `taken`    - the default routes the takeover added: restore deletes these
//                 and nothing else.
//
// A takeover is purely additive: it never removes somebody else's route.  The
// tunnel wins by having the *lowest effective metric* (route metric + interface
// metric), which is why a takeover lowers the Wintun interface metric to 0
// instead of deleting the physical default route.  Getting that wrong is what
// blackholed this machine once, so `tun_takeover_is_safe` is consulted first.
struct TunTakeoverPlan {
  std::vector<TunRoute> routes;
  std::vector<TunInterfaceMetric> ifmetrics;
  std::vector<TunRoute> taken;
};

std::string tun_plan_text(const TunTakeoverPlan& plan);
bool tun_plan_parse(const std::string& text, TunTakeoverPlan* plan, std::string* error);

// Effective metric of a route: both parts count.
std::uint32_t tun_effective_metric(std::uint32_t route_metric, std::uint32_t interface_metric);

// Which adapter a forwarded UDP datagram has to leave through once the tunnel
// owns the default route: the one with the lowest effective metric among the
// default routes that are not `own_ifindex`.  0 means "none", and the caller
// must then drop UDP instead of letting it loop back into the tunnel.
std::uint32_t tun_pick_physical_ifindex(const std::vector<TunRoute>& routes,
                                        const std::vector<TunInterfaceMetric>& ifmetrics,
                                        std::uint32_t own_ifindex);

// Read-only: the IPv4 interface metric of every adapter that owns one of the
// given default routes.  Adapters whose metric cannot be read are left out (the
// safety check treats those as 0).  False when the platform cannot answer at all
// (non-Windows), in which case `ifmetrics` is empty.
bool tun_interface_metrics(const std::vector<TunRoute>& routes,
                           std::vector<TunInterfaceMetric>* ifmetrics);

// Pure decision helper (no syscalls on any platform): may a takeover on `own_luid`
// with the lowest possible effective metric (0) be expected to win?  Returns false
// and fills `why` when another default route already has an effective metric of 0
// (a tie could leave the machine pointing at a dead route) or when the table looks
// inconsistent.  Unit-tested; the real takeover is only a syscall shell around it.
bool tun_takeover_is_safe(const std::vector<TunRoute>& routes,
                          const std::vector<TunInterfaceMetric>& ifmetrics,
                          std::uint64_t own_luid, std::string* why);

// 24 -> "255.255.255.0".  Empty string for anything outside 0..32.
std::string tun_mask_from_prefix(int prefix_len);

// Where the loader looks for wintun.dll, in order.
std::vector<std::string> tun_dll_search_paths();
std::string tun_default_name();  // "netcap"
std::string tun_help();          // printed by --tun-help

// Point the loader at one specific wintun.dll (--tun-dll) instead of searching.
// Must be called before the first tun_available()/TunDevice::open(); a path that
// cannot be used shows up verbatim in the diagnostics tun_available() reports.
void tun_prefer_dll(const std::string& path);

// Can the driver be used right now?  `detail` always receives a printable line
// (which DLL was loaded, which driver version it reports, or why it is unusable).
bool tun_available(std::string* detail);

// The default routes of this machine as they are right now, in `tun_routes_text`
// form.  Read-only: no rights needed, nothing is changed.
bool tun_default_routes(std::string* snapshot, std::string* error);

// Snapshot files: a takeover writes one before it touches anything, so an
// interrupted run can be undone with --tun-restore <file>.  Plain UTF-8, meant to
// be readable and editable by hand.
bool tun_read_file(const std::string& path, std::string* text, std::string* error);
bool tun_write_file(const std::string& path, const std::string& text, std::string* error);

// ---------------------------------------------------------------------------
// the device itself
// ---------------------------------------------------------------------------

struct TunDeviceInfo {
  std::string name;         // adapter alias, e.g. "netcap"
  std::string description;  // tunnel type shown by the OS, e.g. "netcap"
  std::string address;      // assigned IPv4 address, empty when not configured
  int prefix_len = 24;
  std::uint32_t mtu = 1500;
  std::uint64_t luid = 0;  // interface NET_LUID
  std::uint32_t ifindex = 0;
  bool created = false;   // true when open() had to create the adapter
  bool open = false;
  std::string describe() const;
};

class TunDevice {
 public:
  TunDevice();
  ~TunDevice();
  TunDevice(const TunDevice&) = delete;
  TunDevice& operator=(const TunDevice&) = delete;

  // name: adapter alias ("" means tun_default_name()).  address: IPv4 address to
  // assign ("" skips the address, which only makes sense for diagnostics).
  // Creating the adapter needs administrator rights the first time; opening an
  // existing one does not.
  bool open(const std::string& name, const std::string& address, int prefix_len, std::uint32_t mtu,
            TunDeviceInfo* info, std::string* error);
  void close();
  bool is_open() const;
  const TunDeviceInfo& info() const;

  // Reads one IP packet (a whole IPv4/IPv6 datagram, no framing).  Returns the
  // packet length, 0 on timeout, -1 on error or when the device is closed.
  int read_packet(std::uint8_t* buffer, std::size_t capacity, int timeout_ms, std::string* error);
  bool write_packet(const std::uint8_t* packet, std::size_t length, std::string* error);

  std::string describe() const;

 private:
  struct Impl;
  Impl* impl_;
};

// Sends every default route through `device` (metric 0) and returns what was
// there before, so a crash is recoverable.  Nothing is changed unless the
// snapshot could be produced first, and the caller is expected to have an
// upstream to chain to: a TUN without one blackholes the machine.
bool tun_takeover_default_routes(const TunDevice& device, std::string* snapshot,
                                 std::string* error);

// Puts the routes recorded in `snapshot` back and removes the ones we added.
bool tun_restore_default_routes(const std::string& snapshot, std::string* error);

}  // namespace netcap

#endif  // NETCAP_TUN_HPP
