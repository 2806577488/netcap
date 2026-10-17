// Capture backends.
//
// Three sources feed the same downstream pipeline:
//   * live raw sockets   (Windows: SOCK_RAW + SIO_RCVALL, DLT_RAW)
//                        (Linux:   AF_PACKET + PACKET_RX_RING, DLT_EN10MB)
//   * pcap savefiles     (DLT_* from the file header)
//   * synthetic frames   (self-test / sample generator)
//
// A backend yields PacketView objects that stay valid only until the next call
// to next().  That is what lets the Linux ring path hand out pointers straight
// into the mmap'ed kernel buffer with no copy at all.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "netcap/packet.hpp"

namespace netcap {

/// One capture-capable interface as reported by the OS.
struct DeviceInfo {
  std::string name;         ///< short name ("eth0", "Ethernet 2") or index string
  std::string description;  ///< human readable description
  std::string address;      ///< first usable unicast address
  std::string mac;          ///< formatted MAC, if the link layer has one
  std::uint32_t ifindex = 0;
  int family = 0;           ///< 4, 6, or 0 when unknown
  bool loopback = false;
  bool up = false;
  bool is_default = false;  ///< marked by the platform as the preferred route
  /// Virtual adapter: TAP/TUN/Wintun, WireGuard, OpenVPN, a proxy's tunnel.
  /// Traffic on one of these is not the physical link's traffic, which is
  /// exactly why it is worth capturing separately (see --with-tunnel).
  bool tunnel = false;
};

struct CaptureStats {
  std::uint64_t packets = 0;      ///< packets handed to the caller
  std::uint64_t bytes = 0;        ///< bytes handed to the caller (captured length)
  std::uint64_t huge = 0;         ///< live: records larger than the receive buffer
  std::uint64_t dropped = 0;      ///< live: ring/data lost according to the kernel
  bool kernel_stats = false;      ///< live: dropped/huge came from the kernel
};

struct CaptureConfig {
  std::string device;        ///< name or decimal index; empty = first usable
  /// Additional live interfaces, opened at the same time as `device`.  On
  /// Windows every interface needs its own raw socket, and one process can hold
  /// as many as it likes, so "capture the physical NIC *and* the proxy's TAP
  /// adapter" is just two entries here.
  std::vector<std::string> extra_devices;
  /// Append every interface that is up and looks like a tunnel (TAP/TUN/Wintun,
  /// WireGuard, OpenVPN, a proxy client).  Packets on those interfaces still
  /// carry the original five-tuple, so --with-tunnel is what makes the process
  /// behind a TUN-mode proxy visible.
  bool with_tunnel = false;
  int snaplen = 262144;      ///< bytes to capture per packet
  bool promisc = true;       ///< live only, best effort
  int timeout_ms = 1000;     ///< how long next() may block when idle
  bool nanosecond = false;   ///< timestamps (and written files) in nanoseconds
  std::uint32_t buffer_bytes = 4u * 1024u * 1024u;  ///< requested kernel buffer
};

/// True when a device name/description looks like a virtual tunnel adapter.
bool device_looks_like_tunnel(const std::string& name, const std::string& description);

/// Finds one interface by decimal index, exact name, address, or name/description
/// substring (case-insensitive).  An empty `want` prefers the default route, then
/// any interface that is up and not loopback.  Returns nullptr and fills `error`
/// when nothing matches; the returned pointer aliases `devs`.
const DeviceInfo* find_device(const std::vector<DeviceInfo>& devs, const std::string& want,
                              std::string* error);

/// Resolves `cfg.device` (the literal name "all" means every up, non-loopback
/// interface), `cfg.extra_devices` and `cfg.with_tunnel` into the ordered list of
/// interfaces to open.  Duplicates are removed by interface index.  The first
/// entry is the required one - if its socket cannot be created the capture fails;
/// the rest are best effort so that a missing TAP adapter cannot sink the run.
bool select_devices(const std::vector<DeviceInfo>& devs, const CaptureConfig& cfg,
                    std::vector<DeviceInfo>* out, std::string* error);

/// Abstract packet source.  next() returns false both for "nothing available
/// right now" (live, timeout) and for end-of-stream (file); use the accessors
/// to tell those apart.
class CaptureBackend {
 public:
  virtual ~CaptureBackend() = default;

  virtual bool open(const CaptureConfig& cfg, std::string* error) = 0;
  virtual bool next(PacketView& view) = 0;
  virtual void close() = 0;

  /// One of the DLT_* constants: the link layer of the frames handed out.
  virtual int linktype() const = 0;
  virtual CaptureStats stats() const = 0;
  virtual bool eof() const = 0;
  /// Non-empty when the last next() failed for a reason other than a timeout.
  virtual const std::string& error() const = 0;
  /// Human readable description of the opened source ("raw socket on ...").
  virtual std::string describe() const = 0;
};

/// Live capture backend for the current platform, or nullptr when the platform
/// has no implementation (the error explains why).
std::unique_ptr<CaptureBackend> make_live_backend(std::string* error);

/// pcap savefile backend.  "path" may be "-" for stdin.
std::unique_ptr<CaptureBackend> make_file_backend();

/// Enumerate capture-capable interfaces.  Returns false and fills `error` when
/// enumeration itself failed (the list may still be partial).
bool list_devices(std::vector<DeviceInfo>& out, std::string* error);

/// True when live capture can work on this platform at all (it may still fail
/// at open() time, e.g. for missing privileges).
bool live_capture_supported(std::string* note);

/// Human readable explanation of what live capture needs on this platform.
std::string live_capture_requirement();

}  // namespace netcap
