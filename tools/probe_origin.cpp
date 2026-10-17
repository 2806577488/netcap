// probe_origin -- measure how long it takes to reach every address a host
// resolves to.
//
//   g++ -std=c++20 -O2 -Iinclude tools/probe_origin.cpp src/origin.cpp \
//       src/common.cpp -o tools/probe_origin.exe -lws2_32
//   tools/probe_origin.exe example.com 443 [attempts]
//
// This is the evidence behind "pick the fastest address, not the first one":
// the same name usually resolves to several addresses, and on a machine behind
// a slow international link the spread between them is far larger than the cost
// of one extra TCP handshake.  The tool measures with the same non-blocking
// connect + select the proxy uses, so the numbers are comparable with
// NETCAP_ORIGIN_TRACE output.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/origin.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static const socket_t kBad = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static const socket_t kBad = -1;
#endif

namespace {

void ensure_sockets() {
#if defined(_WIN32)
  static const bool started = []() {
    WSADATA data;
    return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  (void)started;
#endif
}

bool set_nonblocking(socket_t s, bool on) {
#if defined(_WIN32)
  u_long mode = on ? 1 : 0;
  return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  const int flags = ::fcntl(s, F_GETFL, 0);
  if (flags < 0) return false;
  return ::fcntl(s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
#endif
}

void set_nodelay(socket_t s) {
  const int one = 1;
#if defined(_WIN32)
  ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
#else
  ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif
}

// One attempt: returns the connect time in microseconds, or -1 when the address
// did not answer inside the timeout.
netcap::i64 connect_once(const netcap::OriginAddress& address, int timeout_ms, std::string* why) {
  unsigned char storage[128];
  std::size_t length = 0;
  if (!netcap::origin_sockaddr(address, storage, &length)) {
    if (why != nullptr) *why = "unsupported family";
    return -1;
  }
  const socket_t s = ::socket(address.family, SOCK_STREAM, IPPROTO_TCP);
  if (s == kBad) {
    if (why != nullptr) *why = "socket() failed";
    return -1;
  }
  set_nodelay(s);
  if (!set_nonblocking(s, true)) {
    if (why != nullptr) *why = "cannot go non-blocking";
#if defined(_WIN32)
    ::closesocket(s);
#else
    ::close(s);
#endif
    return -1;
  }
  const netcap::i64 started = netcap::now_monotonic_us();
  const int rc = ::connect(s, reinterpret_cast<const sockaddr*>(storage), static_cast<int>(length));
  bool connected = rc == 0;
  if (!connected) {
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(s, &wr);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int ready = ::select(static_cast<int>(s) + 1, nullptr, &wr, nullptr, &tv);
    if (ready > 0) {
      int error = 0;
#if defined(_WIN32)
      int elen = sizeof(error);
      ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &elen);
#else
      socklen_t elen = sizeof(error);
      ::getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &elen);
#endif
      connected = error == 0;
    }
  }
  const netcap::i64 elapsed = netcap::now_monotonic_us() - started;
#if defined(_WIN32)
  ::closesocket(s);
#else
  ::close(s);
#endif
  if (!connected) {
    if (why != nullptr) *why = "no answer";
    return -1;
  }
  if (why != nullptr) why->clear();
  return elapsed;
}

}  // namespace

int main(int argc, char** argv) {
  ensure_sockets();
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: probe_origin <host> [port] [attempts]\n"
                 "       measures a TCP connect to every address the host resolves to\n");
    return 2;
  }
  const std::string host = argv[1];
  const std::uint16_t port =
      argc > 2 ? static_cast<std::uint16_t>(std::atoi(argv[2])) : static_cast<std::uint16_t>(443);
  const int attempts = argc > 3 ? std::max(1, std::atoi(argv[3])) : 1;

  std::vector<netcap::OriginAddress> addresses;
  std::string error;
  if (!netcap::origin_resolve(host, port, &addresses, &error)) {
    std::fprintf(stderr, "probe_origin: %s: %s\n", host.c_str(),
                 error.empty() ? "cannot resolve" : error.c_str());
    return 3;
  }
  if (addresses.empty()) {
    std::fprintf(stderr, "probe_origin: %s has no addresses\n", host.c_str());
    return 3;
  }

  struct Row {
    std::string text;
    int family = 0;
    std::size_t resolver_index = 0;
    netcap::i64 best_us = -1;
    int answered = 0;
  };
  std::vector<Row> rows;
  rows.reserve(addresses.size());
  for (std::size_t i = 0; i < addresses.size(); ++i) {
    Row row;
    row.text = addresses[i].text;
    row.family = addresses[i].family;
    row.resolver_index = i;
    for (int attempt = 0; attempt < attempts; ++attempt) {
      std::string why;
      const netcap::i64 us = connect_once(addresses[i], 3000, &why);
      if (us < 0) continue;
      ++row.answered;
      if (row.best_us < 0 || us < row.best_us) row.best_us = us;
    }
    rows.push_back(row);
  }

  std::vector<Row> sorted = rows;
  std::stable_sort(sorted.begin(), sorted.end(), [](const Row& a, const Row& b) {
    if (a.best_us < 0) return false;
    if (b.best_us < 0) return true;
    return a.best_us < b.best_us;
  });

  std::printf("%s:%u resolves to %zu address(es), %d attempt(s) each, connect timeout 3 s\n", host.c_str(),
              static_cast<unsigned>(port), rows.size(), attempts);
  std::printf("  %-4s %-42s %-6s %10s %8s\n", "rank", "address", "family", "connect", "resolver");
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    const Row& row = sorted[i];
    char time_text[32];
    if (row.best_us < 0) {
      std::snprintf(time_text, sizeof(time_text), "no answer");
    } else if (row.best_us < 1000) {
      std::snprintf(time_text, sizeof(time_text), "%.3f ms", static_cast<double>(row.best_us) / 1000.0);
    } else {
      std::snprintf(time_text, sizeof(time_text), "%.2f ms", static_cast<double>(row.best_us) / 1000.0);
    }
    std::printf("  %-4zu %-42s %-6s %10s %8zu%s\n", i + 1, row.text.c_str(),
                netcap::origin_family_name(row.family).c_str(), time_text, row.resolver_index + 1,
                row.resolver_index == 0 ? "  <- resolver's first choice" : "");
  }

  const Row& first = rows[0];
  const Row& fastest = sorted[0];
  std::printf("\n");
  if (fastest.best_us < 0) {
    std::printf("nothing answered\n");
    return 4;
  }
  std::printf("first address   : %s %s\n", first.text.c_str(),
              first.best_us < 0 ? "(no answer)" : "(measured)");
  std::printf("fastest address : %s %.2f ms\n", fastest.text.c_str(),
              static_cast<double>(fastest.best_us) / 1000.0);
  if (first.best_us >= 0) {
    const double gain = static_cast<double>(first.best_us - fastest.best_us) / 1000.0;
    std::printf("first vs fastest: %.2f ms %s\n", gain < 0 ? -gain : gain,
                gain > 0 ? "saved per new connection" : "already the fastest");
  }
  return 0;
}
