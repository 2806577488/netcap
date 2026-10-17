// Portable part of the capture layer: the pcap savefile backend.
#include <cstdlib>
#include <cstring>
#include <utility>

#include "netcap/capture.hpp"
#include "netcap/common.hpp"
#include "netcap/pcap.hpp"

namespace netcap {

namespace {

class FileBackend final : public CaptureBackend {
 public:
  bool open(const CaptureConfig& cfg, std::string* error) override {
    path_ = cfg.device.empty() ? "-" : cfg.device;
    std::string err;
    if (!reader_.open(path_, &err)) {
      error_ = err;
      if (error) *error = err;
      return false;
    }
    linktype_ = reader_.linktype();
    eof_ = false;
    return true;
  }

  bool next(PacketView& view) override {
    if (eof_) return false;
    if (!reader_.next(buf_)) {
      eof_ = true;
      if (reader_.failed()) error_ = reader_.error();
      return false;
    }
    ++stats_.packets;
    stats_.bytes += buf_.data.size();
    view = buf_.view();
    return true;
  }

  void close() override { reader_.close(); }

  int linktype() const override { return linktype_; }
  CaptureStats stats() const override { return stats_; }
  bool eof() const override { return eof_; }
  const std::string& error() const override { return error_; }

  std::string describe() const override {
    std::string d = "pcap file '" + path_ + "'";
    d += ", linktype ";
    d += linktype_name(linktype_);
    if (reader_.nanosecond()) d += ", nanosecond timestamps";
    if (reader_.big_endian()) d += ", big-endian";
    return d;
  }

 private:
  PcapReader reader_;
  Packet buf_;
  CaptureStats stats_;
  std::string path_ = "-";
  std::string error_;
  int linktype_ = DLT_EN10MB;
  bool eof_ = true;
};

}  // namespace

std::unique_ptr<CaptureBackend> make_file_backend() {
  return std::unique_ptr<CaptureBackend>(new FileBackend());
}

// --- device selection (portable, so the self-test can exercise it) -----------

bool device_looks_like_tunnel(const std::string& name, const std::string& description) {
  // Substrings that mark a virtual/tunnel adapter on Windows and Linux.  "tap"
  // and "tun" catch cfw-tap (Clash for Windows) and wintun; the rest catch the
  // usual VPN/proxy clients that create their own adapter.
  static const char* kMarks[] = {"tun",     "tap",      "wintun",   "cfw",     "clash",
                                 "wireguard", "wg",     "openvpn",  "tailscale", "zerotier",
                                 "softether", "sing-box", "singbox", "hysteria", "nekoray",
                                 "v2ray",   "xray",     "tunnel",   "vpn"};
  const std::string n = to_lower(name);
  const std::string d = to_lower(description);
  for (const char* m : kMarks) {
    if (n.find(m) != std::string::npos) return true;
    if (d.find(m) != std::string::npos) return true;
  }
  return false;
}

const DeviceInfo* find_device(const std::vector<DeviceInfo>& devs, const std::string& want,
                              std::string* error) {
  if (devs.empty()) {
    if (error) *error = "no capture-capable interfaces were found";
    return nullptr;
  }
  if (!want.empty()) {
    for (const DeviceInfo& d : devs) {
      if (iequals(d.name, want)) return &d;
    }
    for (const DeviceInfo& d : devs) {
      if (iequals(d.description, want)) return &d;
    }
    for (const DeviceInfo& d : devs) {
      if (d.address == want) return &d;
    }
    if (want.find_first_not_of("0123456789") == std::string::npos) {
      const std::uint32_t idx = std::uint32_t(std::strtoul(want.c_str(), nullptr, 10));
      for (const DeviceInfo& d : devs) {
        if (d.ifindex == idx) return &d;
      }
    }
    // Last resort: a case-insensitive substring of the name or description, so
    // "-i cfw" or "-i wlan" work without typing the whole friendly name.
    const std::string lowered = to_lower(want);
    for (const DeviceInfo& d : devs) {
      if (to_lower(d.name).find(lowered) != std::string::npos) return &d;
    }
    for (const DeviceInfo& d : devs) {
      if (to_lower(d.description).find(lowered) != std::string::npos) return &d;
    }
    if (error) *error = "no interface matches '" + want + "' (use --devices to list them)";
    return nullptr;
  }
  const DeviceInfo* fallback = nullptr;
  for (const DeviceInfo& d : devs) {
    if (d.loopback || !d.up || d.family != 4) continue;
    if (d.is_default) return &d;
    if (!fallback) fallback = &d;
  }
  if (fallback) return fallback;
  for (const DeviceInfo& d : devs) {
    if (d.up && d.family == 4) return &d;
  }
  if (error) {
    *error =
        "no usable IPv4 interface found; live capture binds a raw IPv4 socket, so an "
        "interface with an IPv4 address is required (use --devices to list them)";
  }
  return nullptr;
}

bool select_devices(const std::vector<DeviceInfo>& devs, const CaptureConfig& cfg,
                    std::vector<DeviceInfo>* out, std::string* error) {
  out->clear();
  auto add = [out](const DeviceInfo& d) {
    for (const DeviceInfo& e : *out) {
      if (e.ifindex == d.ifindex && e.name == d.name) return;
    }
    out->push_back(d);
  };

  if (iequals(cfg.device, "all")) {
    for (const DeviceInfo& d : devs) {
      if (d.up && !d.loopback && d.family == 4) add(d);
    }
    if (out->empty()) {
      if (error) *error = "no interface is up with an IPv4 address ('-i all')";
      return false;
    }
  } else {
    std::string derr;
    const DeviceInfo* first = find_device(devs, cfg.device, &derr);
    if (!first) {
      if (error) *error = derr;
      return false;
    }
    if (first->family != 4) {
      if (error) {
        *error = "interface '" + first->name +
                 "' has no IPv4 address; live capture binds an IPv4 raw socket";
      }
      return false;
    }
    add(*first);
  }

  // Explicitly named extra interfaces are an instruction, not a wish: a typo
  // must not silently leave the user capturing only half of the traffic.
  for (const std::string& want : cfg.extra_devices) {
    std::string derr;
    const DeviceInfo* d = find_device(devs, want, &derr);
    if (!d) {
      if (error) *error = derr;
      return false;
    }
    if (d->family != 4) {
      if (error) {
        *error = "interface '" + d->name +
                 "' has no IPv4 address; live capture binds an IPv4 raw socket";
      }
      return false;
    }
    add(*d);
  }

  // --with-tunnel is best effort by design: a tunnel adapter may be down, may
  // have no address yet, or may not exist at all, and none of that should stop
  // a capture that was asked for the physical interface as well.
  if (cfg.with_tunnel) {
    for (const DeviceInfo& d : devs) {
      if (!d.up || d.loopback || d.family != 4) continue;
      if (d.tunnel) add(d);
    }
  }
  return true;
}

}  // namespace netcap
