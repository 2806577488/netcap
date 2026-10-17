// Windows live capture backend.
//
// Method: a raw IPv4 socket bound to one local interface address, switched
// into "receive all" mode with WSAIoctl(SIO_RCVALL).  The kernel then hands up
// every IPv4 datagram seen on that interface, starting at the IP header, which
// is why this backend reports DLT_RAW.  SIO_RCVALL is a privileged operation:
// without elevation WSAIoctl fails with WSAEACCES and we say so plainly.
#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>
#include <mstcpip.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "netcap/capture.hpp"
#include "netcap/common.hpp"

namespace netcap {

namespace {

// Link type / operational status constants, spelled out so the file builds
// against any MinGW SDK vintage.
constexpr unsigned long kIfTypeSoftwareLoopback = 24;
constexpr unsigned long kIfOperStatusUp = 1;

class WsaGuard {
 public:
  WsaGuard() {
    WSADATA d;
    ok_ = WSAStartup(MAKEWORD(2, 2), &d) == 0;
  }
  ~WsaGuard() {
    if (ok_) WSACleanup();
  }
  bool ok() const { return ok_; }

 private:
  bool ok_ = false;
};

WsaGuard& wsa() {
  static WsaGuard g;
  return g;
}

std::string wide_to_utf8(const wchar_t* w) {
  if (!w) return std::string();
  const int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  if (need <= 1) return std::string();
  std::string out(std::size_t(need - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], need, nullptr, nullptr);
  return out;
}

std::string socket_error(int code) {
  char buf[512] = {0};
  const DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 nullptr, DWORD(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                 buf, sizeof(buf) - 1, nullptr);
  std::string msg = (n > 0) ? std::string(buf, n) : std::string();
  if (!msg.empty()) {
    // FormatMessageA answers in the ANSI code page. Everything else this tool
    // prints is UTF-8, so translate it rather than emitting mixed encodings.
    const int wlen = MultiByteToWideChar(CP_ACP, 0, msg.c_str(), int(msg.size()), nullptr, 0);
    if (wlen > 0) {
      std::wstring wide(std::size_t(wlen), L'\0');
      MultiByteToWideChar(CP_ACP, 0, msg.c_str(), int(msg.size()), wide.data(), wlen);
      msg = wide_to_utf8(wide.c_str());
    }
  }
  while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' ')) {
    msg.pop_back();
  }
  if (msg.empty()) msg = "socket error";
  return msg + " (WSA error " + std::to_string(code) + ")";
}

bool collect_adapters(std::vector<DeviceInfo>& out, std::string* error) {
  const ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
  ULONG size = 16 * 1024;
  std::vector<u8> buf;
  ULONG rc = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 6; ++attempt) {
    buf.assign(size, 0);
    rc = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                              reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    if (rc != ERROR_BUFFER_OVERFLOW) break;
  }
  if (rc != NO_ERROR) {
    if (error) *error = "GetAdaptersAddresses failed (code " + std::to_string(rc) + ")";
    return false;
  }

  DWORD best_index = 0;
  IN_ADDR probe{};
  probe.s_addr = htonl(0x08080808u);  // 8.8.8.8; only used to ask for the default route
  const bool have_best = GetBestInterface(probe.s_addr, &best_index) == NO_ERROR;

  out.clear();
  for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a;
       a = a->Next) {
    DeviceInfo di;
    di.name = wide_to_utf8(a->FriendlyName);
    di.description = wide_to_utf8(a->Description);
    di.ifindex = a->IfIndex;
    di.loopback = (a->IfType == kIfTypeSoftwareLoopback);
    di.up = (a->OperStatus == kIfOperStatusUp);
    di.is_default = have_best && a->IfIndex == best_index;
    if (a->PhysicalAddressLength == 6) di.mac = format_mac(a->PhysicalAddress);
    di.tunnel = device_looks_like_tunnel(di.name, di.description);

    for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u; u = u->Next) {
      if (!u->Address.lpSockaddr) continue;
      const int fam = u->Address.lpSockaddr->sa_family;
      if (fam != AF_INET && fam != AF_INET6) continue;
      char text[INET6_ADDRSTRLEN] = {0};
      const void* src = nullptr;
      if (fam == AF_INET) {
        src = &reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr)->sin_addr;
      } else {
        src = &reinterpret_cast<sockaddr_in6*>(u->Address.lpSockaddr)->sin6_addr;
      }
      if (!inet_ntop(fam, src, text, sizeof(text))) continue;
      if (fam == AF_INET) {
        di.address = text;
        di.family = 4;
        break;  // prefer IPv4: it is the family the raw socket uses
      }
      if (di.address.empty()) {
        di.address = text;
        di.family = 6;
      }
    }
    out.push_back(std::move(di));
  }
  return true;
}

class WinRawBackend final : public CaptureBackend {
 public:
  ~WinRawBackend() override { close(); }

  bool open(const CaptureConfig& cfg, std::string* error) override {
    close();
    if (!wsa().ok()) {
      error_ = "WSAStartup failed";
      if (error) *error = error_;
      return false;
    }
    std::vector<DeviceInfo> devs;
    std::string derr;
    if (!collect_adapters(devs, &derr)) {
      error_ = derr;
      if (error) *error = derr;
      return false;
    }
    std::vector<DeviceInfo> chosen;
    if (!select_devices(devs, cfg, &chosen, &derr)) {
      error_ = derr;
      if (error) *error = derr;
      return false;
    }

    snaplen_ = cfg.snaplen > 0 ? std::size_t(cfg.snaplen) : 65536;
    timeout_ms_ = cfg.timeout_ms;
    stats_ = CaptureStats();
    error_.clear();
    warnings_.clear();

    for (std::size_t i = 0; i < chosen.size(); ++i) {
      std::string serr;
      if (open_one(chosen[i], cfg, &serr)) continue;
      // The first interface is the one the user actually asked for: if it cannot
      // be opened the capture fails.  Interfaces appended by --with-tunnel (a TAP
      // adapter that is down, say) are best effort and only become a warning.
      if (i == 0) {
        error_ = serr;
        if (error) *error = error_;
        close();
        return false;
      }
      warnings_.push_back(serr);
    }
    if (slots_.empty()) {
      error_ = "no interface could be opened for live capture";
      if (error) *error = error_;
      return false;
    }
    device_ = slots_.front().dev;
    return true;
  }

  bool next(PacketView& view) override {
    if (slots_.empty()) return false;
    fd_set rd;
    FD_ZERO(&rd);
    SOCKET maxfd = 0;
    for (const Slot& s : slots_) {
      FD_SET(s.sock, &rd);
      if (s.sock > maxfd) maxfd = s.sock;
    }
    timeval tv;
    tv.tv_sec = timeout_ms_ / 1000;
    tv.tv_usec = (timeout_ms_ % 1000) * 1000;
    const int ready = ::select(int(maxfd + 1), &rd, nullptr, nullptr, &tv);
    if (ready == 0) return false;  // idle, not an error
    if (ready == SOCKET_ERROR) {
      error_ = "select failed: " + socket_error(WSAGetLastError());
      return false;
    }
    for (Slot& s : slots_) {
      if (!FD_ISSET(s.sock, &rd)) continue;
      const int n = ::recv(s.sock, reinterpret_cast<char*>(s.buf.data()), int(s.buf.size()), 0);
      if (n == SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e == WSAEMSGSIZE) {
          ++stats_.huge;
          return false;
        }
        error_ = "recv failed on '" + s.dev.name + "': " + socket_error(e);
        return false;
      }
      if (n <= 0) return false;
      if (n < 20) return false;  // not even an IPv4 header; skip silently
      view.data = s.buf.data();
      view.len = std::min<std::size_t>(std::size_t(n), snaplen_);
      view.origlen = std::size_t(n);
      view.ts_us = now_unix_us();
      view.linktype = DLT_RAW;
      view.ifindex = s.dev.ifindex;
      view.truncated = view.len < view.origlen;
      ++stats_.packets;
      stats_.bytes += view.len;
      return true;
    }
    return false;
  }

  void close() override {
    for (Slot& s : slots_) {
      if (s.sock == INVALID_SOCKET) continue;
      DWORD off = RCVALL_OFF;
      DWORD returned = 0;
      WSAIoctl(s.sock, SIO_RCVALL, &off, sizeof(off), nullptr, 0, &returned, nullptr, nullptr);
      closesocket(s.sock);
      s.sock = INVALID_SOCKET;
    }
    slots_.clear();
  }

  int linktype() const override { return DLT_RAW; }
  CaptureStats stats() const override { return stats_; }
  bool eof() const override { return false; }
  const std::string& error() const override { return error_; }

  std::string describe() const override {
    std::string d = slots_.size() > 1 ? "raw IPv4 sockets (SIO_RCVALL) on "
                                      : "raw IPv4 socket (SIO_RCVALL) on ";
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (i) d += ", ";
      d += "'" + slots_[i].dev.name;
      if (!slots_[i].dev.address.empty()) d += " " + slots_[i].dev.address;
      if (slots_[i].dev.tunnel) d += " [tunnel]";
      d += "'";
    }
    for (const std::string& w : warnings_) d += "\n  skipped: " + w;
    return d;
  }

 private:
  struct Slot {
    SOCKET sock = INVALID_SOCKET;
    DeviceInfo dev;
    std::vector<u8> buf;
  };

  /// One raw socket per interface: bound to that interface's IPv4 address and
  /// switched into "receive all" mode, so the kernel hands up every IPv4 packet
  /// seen on it (including the inner packets of a TUN/TAP adapter).
  bool open_one(const DeviceInfo& dev, const CaptureConfig& cfg, std::string* error) {
    IN_ADDR local{};
    if (inet_pton(AF_INET, dev.address.c_str(), &local) != 1) {
      *error = "interface '" + dev.name + "' has no usable IPv4 address";
      return false;
    }
    Slot slot;
    slot.dev = dev;
    slot.sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (slot.sock == INVALID_SOCKET) {
      const int e = WSAGetLastError();
      *error = "raw socket creation failed on '" + dev.name + "': " + socket_error(e);
      if (e == WSAEACCES) *error += "\n" + live_capture_requirement();
      return false;
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr = local;
    if (bind(slot.sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == SOCKET_ERROR) {
      const int e = WSAGetLastError();
      *error = "bind to " + dev.address + " failed: " + socket_error(e);
      closesocket(slot.sock);
      return false;
    }
    const int rcvbuf = int(std::min<std::uint32_t>(cfg.buffer_bytes, 64u * 1024u * 1024u));
    setsockopt(slot.sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf),
               sizeof(rcvbuf));
    DWORD mode = RCVALL_ON;
    DWORD returned = 0;
    if (WSAIoctl(slot.sock, SIO_RCVALL, &mode, sizeof(mode), nullptr, 0, &returned, nullptr,
                 nullptr) == SOCKET_ERROR) {
      const int e = WSAGetLastError();
      if (e == WSAEACCES) {
        *error = "SIO_RCVALL was refused on '" + dev.name + "': access denied.\n" +
                 live_capture_requirement();
      } else if (e == WSAEINVAL) {
        *error = "SIO_RCVALL is not supported on '" + dev.name + "'.";
      } else {
        *error = "SIO_RCVALL failed on '" + dev.name + "': " + socket_error(e);
      }
      closesocket(slot.sock);
      return false;
    }
    slot.buf.assign(65536 + 64, 0);
    slots_.push_back(std::move(slot));
    return true;
  }

  std::vector<Slot> slots_;
  DeviceInfo device_;
  std::vector<std::string> warnings_;
  CaptureStats stats_;
  std::string error_;
  std::size_t snaplen_ = 65536;
  int timeout_ms_ = 1000;
};

}  // namespace

std::unique_ptr<CaptureBackend> make_live_backend(std::string* error) {
  if (!wsa().ok()) {
    if (error) *error = "WSAStartup failed";
    return nullptr;
  }
  return std::unique_ptr<CaptureBackend>(new WinRawBackend());
}

bool list_devices(std::vector<DeviceInfo>& out, std::string* error) {
  if (!wsa().ok()) {
    if (error) *error = "WSAStartup failed";
    return false;
  }
  return collect_adapters(out, error);
}

bool live_capture_supported(std::string* note) {
  if (note) *note = "raw IPv4 socket with SIO_RCVALL";
  return true;
}

std::string live_capture_requirement() {
  return
      "Live capture on Windows needs Administrator privileges: SIO_RCVALL puts the raw "
      "socket into promiscuous receive-all mode, which the OS only grants to elevated "
      "processes.  Re-run the tool from an elevated prompt, or analyse a saved capture "
      "with --read instead.";
}

}  // namespace netcap

#endif  // _WIN32
