// POSIX live capture backend.
//
// Linux: AF_PACKET/SOCK_RAW bound to one interface, with a TPACKET_V2 RX ring
// mapped into user space (PACKET_RX_RING + mmap).  The ring uses one frame per
// block (tp_block_size == tp_frame_size, tp_frame_nr == tp_block_nr) which is
// the layout libpcap uses in its "single frame per block" mode; the frame
// header sits at the start of each block and the packet data follows it.  A
// frame is owned by user space while TP_STATUS_USER is set and is handed back
// to the kernel by storing TP_STATUS_KERNEL.  No packet data is ever copied.
//
// If the ring cannot be set up the backend falls back to recvfrom() on the same
// socket, which still works but copies every frame.
//
// Other POSIX systems (macOS/BSD) would use /dev/bpf; that is not implemented
// here and the stub below says so instead of failing obscurely.

#if defined(__linux__)

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "netcap/capture.hpp"
#include "netcap/common.hpp"

namespace netcap {

namespace {

std::string errno_string() { return std::string(std::strerror(errno)); }

class LinuxPacketBackend final : public CaptureBackend {
 public:
  ~LinuxPacketBackend() override { close(); }

  bool open(const CaptureConfig& cfg, std::string* error) override {
    close();

    std::vector<DeviceInfo> devs;
    std::string derr;
    list_devices(devs, &derr);
    const DeviceInfo* dev = pick_device(devs, cfg.device, &derr);
    if (!dev) {
      error_ = derr;
      if (error) *error = derr;
      return false;
    }
    device_ = *dev;

    fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0) {
      error_ = "socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) failed: " + errno_string();
      if (errno == EPERM || errno == EACCES) error_ += "\n" + live_capture_requirement();
      if (error) *error = error_;
      return false;
    }

    const int rcvbuf = int(std::min<std::uint32_t>(cfg.buffer_bytes, 256u * 1024u * 1024u));
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = int(device_.ifindex);
    if (bind(fd_, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
      error_ = "bind to '" + device_.name + "' failed: " + errno_string();
      if (error) *error = error_;
      close();
      return false;
    }

    if (cfg.promisc) {
      packet_mreq mreq{};
      mreq.mr_ifindex = int(device_.ifindex);
      mreq.mr_type = PACKET_MR_PROMISC;
      if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        // Not fatal: we still see unicast-to-us, broadcast and multicast.
        promisc_failed_ = errno_string();
      }
    }

    snaplen_ = cfg.snaplen > 0 ? std::size_t(cfg.snaplen) : 262144;
    timeout_ms_ = cfg.timeout_ms;
    stats_ = CaptureStats();
    error_.clear();

    if (!setup_ring()) setup_fallback();
    return true;
  }

  bool next(PacketView& view) override {
    if (fd_ < 0) return false;
    if (ring_) return next_ring(view);
    return next_recvfrom(view);
  }

  void close() override {
    if (ring_) {
      munmap(ring_, ring_bytes_);
      ring_ = nullptr;
      ring_bytes_ = 0;
      frame_index_ = 0;
    }
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

  int linktype() const override { return DLT_EN10MB; }

  CaptureStats stats() const override {
    CaptureStats s = stats_;
    if (fd_ >= 0) {
      // Reading PACKET_STATISTICS also resets the kernel counters, so fold the
      // delta into our running total instead of reporting it verbatim.
      tpacket_stats kst{};
      socklen_t len = sizeof(kst);
      if (getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &kst, &len) == 0) {
        pending_drops_ += kst.tp_drops;
        s.dropped = pending_drops_;
        s.huge = pending_huge_;
        s.kernel_stats = true;
      }
    }
    return s;
  }

  bool eof() const override { return false; }
  const std::string& error() const override { return error_; }

  std::string describe() const override {
    std::string d = "AF_PACKET socket on '";
    d += device_.name;
    d += "'";
    if (ring_) {
      d += ", TPACKET_V2 RX ring ";
      d += std::to_string(block_nr_) + "x" + std::to_string(block_size_) + "B (zero-copy)";
    } else {
      d += ", recvfrom fallback (no ring)";
    }
    if (!promisc_failed_.empty()) d += ", promiscuous mode refused: " + promisc_failed_;
    return d;
  }

 private:
  static const DeviceInfo* pick_device(const std::vector<DeviceInfo>& devs,
                                       const std::string& want, std::string* error) {
    if (devs.empty()) {
      if (error) *error = "no capture-capable interfaces were found";
      return nullptr;
    }
    if (!want.empty()) {
      for (const DeviceInfo& d : devs) {
        if (d.name == want || d.address == want) return &d;
      }
      if (want.find_first_not_of("0123456789") == std::string::npos) {
        const unsigned idx = unsigned(std::strtoul(want.c_str(), nullptr, 10));
        for (const DeviceInfo& d : devs) {
          if (d.ifindex == idx) return &d;
        }
      }
      if (error) *error = "no interface matches '" + want + "' (use --devices to list them)";
      return nullptr;
    }
    for (const DeviceInfo& d : devs) {
      if (!d.loopback && d.up && d.is_default) return &d;
    }
    for (const DeviceInfo& d : devs) {
      if (!d.loopback && d.up) return &d;
    }
    for (const DeviceInfo& d : devs) {
      if (d.up) return &d;
    }
    if (error) *error = "no interface is up";
    return nullptr;
  }

  bool setup_ring() {
    int version = TPACKET_V2;
    if (setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) return false;

    // One frame per block: the frame header is at the block start and the data
    // directly follows it, so a block pointer is also a frame pointer.
    block_size_ = 1u << 16;
    block_nr_ = 64;
    tpacket_req req{};
    req.tp_block_size = block_size_;
    req.tp_block_nr = block_nr_;
    req.tp_frame_size = block_size_;
    req.tp_frame_nr = block_nr_;
    if (setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
      block_size_ = 0;
      block_nr_ = 0;
      return false;
    }

    ring_bytes_ = std::size_t(block_size_) * block_nr_;
    void* p = mmap(nullptr, ring_bytes_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (p == MAP_FAILED) {
      ring_bytes_ = 0;
      return false;
    }
    ring_ = static_cast<u8*>(p);
    frame_index_ = 0;
    return true;
  }

  void setup_fallback() {
    ring_ = nullptr;
    block_size_ = 0;
    block_nr_ = 0;
    ring_bytes_ = 0;
    recv_buf_.assign(snaplen_ + 64, 0);
  }

  bool wait_readable() {
    pollfd pfd{};
    pfd.fd = fd_;
    pfd.events = POLLIN;
    const int r = ::poll(&pfd, 1, timeout_ms_);
    if (r <= 0) return false;  // timeout or error: caller treats as "no packet"
    return (pfd.revents & POLLIN) != 0;
  }

  bool next_ring(PacketView& view) {
    if (!wait_readable()) return false;

    // Drain one frame that is currently owned by user space.
    const std::size_t total_blocks = block_nr_;
    for (std::size_t tries = 0; tries < total_blocks; ++tries) {
      u8* block = ring_ + (frame_index_ % total_blocks) * block_size_;
      auto* hdr = reinterpret_cast<tpacket2_hdr*>(block);
      if (!(hdr->tp_status & TP_STATUS_USER)) {
        frame_index_ = (frame_index_ + 1) % total_blocks;
        continue;
      }

      if (hdr->tp_status & TP_STATUS_COPY) {
        // The frame was too big for the slot; the full length is readable with
        // recvfrom() on this socket.
        recv_buf_.assign(std::max<std::size_t>(snaplen_ + 64, hdr->tp_len + 64), 0);
        const ssize_t n = ::recv(fd_, recv_buf_.data(), recv_buf_.size(), MSG_TRUNC);
        hdr->tp_status = TP_STATUS_KERNEL;
        __sync_synchronize();
        frame_index_ = (frame_index_ + 1) % total_blocks;
        if (n <= 0) continue;
        return make_view(recv_buf_.data(), std::size_t(std::min<ssize_t>(n, ssize_t(snaplen_))),
                         std::size_t(n), i64(hdr->tp_sec) * 1000000 + i64(hdr->tp_nsec) / 1000,
                         view);
      }

      const u8* data = block + (hdr->tp_mac ? hdr->tp_mac : TPACKET2_HDRLEN);
      const std::size_t caplen = std::min<std::size_t>(hdr->tp_snaplen, snaplen_);
      const std::size_t wirelen = hdr->tp_len;
      const i64 ts_us = i64(hdr->tp_sec) * 1000000 + i64(hdr->tp_nsec) / 1000;

      // Hand the slot back before returning: the view stays valid because the
      // kernel will not overwrite the block until it is refilled, and the next
      // call starts scanning at the following block.
      hdr->tp_status = TP_STATUS_KERNEL;
      __sync_synchronize();
      frame_index_ = (frame_index_ + 1) % total_blocks;

      return make_view(data, caplen, wirelen, ts_us, view);
    }
    return false;
  }

  bool next_recvfrom(PacketView& view) {
    if (!wait_readable()) return false;
    const ssize_t n = ::recv(fd_, recv_buf_.data(), recv_buf_.size(), MSG_TRUNC);
    if (n <= 0) return false;
    return make_view(recv_buf_.data(), std::size_t(std::min<ssize_t>(n, ssize_t(snaplen_))),
                     std::size_t(n), now_unix_us(), view);
  }

  bool make_view(const u8* data, std::size_t caplen, std::size_t wirelen, i64 ts_us,
                 PacketView& view) {
    view.data = data;
    view.len = caplen;
    view.origlen = wirelen;
    view.ts_us = ts_us;
    view.linktype = DLT_EN10MB;
    view.ifindex = device_.ifindex;
    view.truncated = caplen < wirelen;
    ++stats_.packets;
    stats_.bytes += caplen;
    return true;
  }

  int fd_ = -1;
  u8* ring_ = nullptr;
  std::size_t ring_bytes_ = 0;
  std::size_t block_size_ = 0;
  std::size_t block_nr_ = 0;
  std::size_t frame_index_ = 0;
  std::vector<u8> recv_buf_;
  DeviceInfo device_;
  CaptureStats stats_;
  std::string error_;
  std::string promisc_failed_;
  std::size_t snaplen_ = 262144;
  int timeout_ms_ = 1000;
  std::uint64_t pending_drops_ = 0;
  std::uint64_t pending_huge_ = 0;
};

}  // namespace

bool list_devices(std::vector<DeviceInfo>& out, std::string* error) {
  out.clear();
  ifaddrs* head = nullptr;
  if (getifaddrs(&head) != 0) {
    if (error) *error = "getifaddrs failed: " + errno_string();
    return false;
  }
  // Track which interfaces we already emitted so each one appears once with its
  // best address.
  for (ifaddrs* ifa = head; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name || !ifa->ifa_addr) continue;
    const int fam = ifa->ifa_addr->sa_family;
    if (fam != AF_PACKET && fam != AF_INET && fam != AF_INET6) continue;

    DeviceInfo* di = nullptr;
    for (DeviceInfo& d : out) {
      if (d.name == ifa->ifa_name) {
        di = &d;
        break;
      }
    }
    if (!di) {
      DeviceInfo fresh;
      fresh.name = ifa->ifa_name;
      fresh.ifindex = if_nametoindex(ifa->ifa_name);
      fresh.up = (ifa->ifa_flags & IFF_UP) != 0;
      fresh.loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
      fresh.is_default = false;
      out.push_back(std::move(fresh));
      di = &out.back();
    }

    char text[INET6_ADDRSTRLEN] = {0};
    if (fam == AF_PACKET) {
      auto* sll = reinterpret_cast<sockaddr_ll*>(ifa->ifa_addr);
      if (sll->sll_halen == 6) di->mac = format_mac(sll->sll_addr);
    } else if (fam == AF_INET) {
      const void* src = &reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr;
      if (inet_ntop(AF_INET, src, text, sizeof(text))) {
        // Keep one address per family; IPv4 wins for the raw-socket default.
        if (di->address.empty() || di->family != 4) {
          di->address = text;
          di->family = 4;
        }
      }
    } else {
      const void* src = &reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
      if (di->address.empty() && inet_ntop(AF_INET6, src, text, sizeof(text))) {
        di->address = text;
        di->family = 6;
      }
    }
  }
  freeifaddrs(head);

  // Best-effort default route detection: the interface holding the default
  // route is the one whose index the kernel reports for an external address.
  std::string port;
  std::string best;
  {
    std::FILE* f = std::fopen("/proc/net/route", "r");
    if (f) {
      char line[512];
      std::fgets(line, sizeof(line), f);  // header
      while (std::fgets(line, sizeof(line), f)) {
        char iface[64] = {0};
        unsigned long dest = 0, mask = 0;
        if (std::sscanf(line, "%63s %lx %*s %*s %*s %*s %*s %lx", iface, &dest, &mask) == 3) {
          if (dest == 0 && mask == 0) {
            best = iface;
            break;
          }
        }
      }
      std::fclose(f);
    }
  }
  if (!best.empty()) {
    for (DeviceInfo& d : out) {
      if (d.name == best) d.is_default = true;
    }
  }
  for (DeviceInfo& d : out) {
    if (d.description.empty()) d.description = d.name;
  }
  return true;
}

std::unique_ptr<CaptureBackend> make_live_backend(std::string* error) {
  (void)error;
  return std::unique_ptr<CaptureBackend>(new LinuxPacketBackend());
}

bool live_capture_supported(std::string* note) {
  if (note) *note = "AF_PACKET SOCK_RAW with a TPACKET_V2 RX ring";
  return true;
}

std::string live_capture_requirement() {
  return
      "Live capture on Linux needs CAP_NET_RAW (run as root, or grant the binary the "
      "capability:  setcap cap_net_raw,cap_net_admin=eip ./netcap ).";
}

}  // namespace netcap

#else  // not Linux

#include "netcap/capture.hpp"

namespace netcap {

std::unique_ptr<CaptureBackend> make_live_backend(std::string* error) {
  if (error) {
    *error =
        "live capture is not implemented for this platform; only Linux (AF_PACKET RX "
        "ring) and Windows (raw socket + SIO_RCVALL) have backends.  Use --read to "
        "analyse a pcap file instead.";
  }
  return nullptr;
}

bool list_devices(std::vector<DeviceInfo>& out, std::string* error) {
  out.clear();
  if (error) *error = "interface enumeration is not implemented for this platform";
  return false;
}

bool live_capture_supported(std::string* note) {
  if (note) *note = "not supported on this platform";
  return false;
}

std::string live_capture_requirement() {
  return "Live capture is only implemented on Linux and Windows.";
}

}  // namespace netcap

#endif
