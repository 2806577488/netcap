// A tiny TLS 1.2 client probe: point it at any TLS 1.2 server (openssl s_server
// is the usual victim) and it prints whether our own handshake completed and
// what the first response record looked like.  Built for debugging the
// interception proxy's upstream leg:
//
//   openssl s_server -accept 8890 -tls1_2 -cert c.crt -key c.key -keylogfile k.log -www -quiet
//   g++ -std=c++20 -O2 -Iinclude tools/tls12_probe.cpp src/tls12.cpp src/tls13.cpp \
//       src/p256.cpp src/x25519.cpp src/x509.cpp src/rsa.cpp src/crypto.cpp src/common.cpp \
//       -o tools/tls12_probe.exe -lws2_32 -lbcrypt
//   NETCAP_TLS12_TRACE=1 tools/tls12_probe.exe 127.0.0.1 8890
//   tools/tls12_probe.exe 127.0.0.1 8890 1.1      # offer TLS 1.1 first (1.0 also accepted)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "netcap/common.hpp"
#include "netcap/tls12.hpp"
#include "netcap/tls13.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using probe_socket = SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using probe_socket = int;
#endif

using namespace netcap;

int main(int argc, char** argv) {
  const std::string host = argc > 1 ? argv[1] : "127.0.0.1";
  const unsigned port = argc > 2 ? static_cast<unsigned>(std::atoi(argv[2])) : 8890u;
  // Third argument: which version to offer first ("1.0", "1.1", "1.2" or a hex
  // number).  The origin may still answer with anything from 1.0 up to it.
  int version_hint = 0x0303;
  if (argc > 3) {
    const std::string v = argv[3];
    if (v == "1.0" || v == "10") version_hint = 0x0301;
    else if (v == "1.1" || v == "11") version_hint = 0x0302;
    else if (v == "1.2" || v == "12") version_hint = 0x0303;
    else version_hint = static_cast<int>(std::strtol(v.c_str(), nullptr, 16));
  }
#if defined(_WIN32)
  WSADATA wsa;
  ::WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  const std::string port_text = std::to_string(port);
  if (::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &res) != 0 || res == nullptr) {
    std::printf("resolve failed\n");
    return 2;
  }
  const probe_socket sock = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (::connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
    std::printf("connect to %s:%u failed\n", host.c_str(), port);
    return 3;
  }
  ::freeaddrinfo(res);
  int timeout_ms = 8000;
  ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof timeout_ms);
  ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof timeout_ms);

  Tls13Io io;
  io.read = [sock](u8* buf, std::size_t len, std::size_t* got) -> bool {
    std::size_t have = 0;
    while (have < len) {
#if defined(_WIN32)
      const int n = ::recv(sock, reinterpret_cast<char*>(buf + have), static_cast<int>(len - have), 0);
#else
      const long n = ::recv(sock, reinterpret_cast<char*>(buf + have), len - have, 0);
#endif
      if (n <= 0) return false;
      have += static_cast<std::size_t>(n);
    }
    if (got != nullptr) *got = have;
    return true;
  };
  io.write = [sock](const u8* data, std::size_t len) -> bool {
    std::size_t sent = 0;
    while (sent < len) {
#if defined(_WIN32)
      const int n = ::send(sock, reinterpret_cast<const char*>(data + sent), static_cast<int>(len - sent), 0);
#else
      const long n = ::send(sock, reinterpret_cast<const char*>(data + sent), len - sent, 0);
#endif
      if (n <= 0) return false;
      sent += static_cast<std::size_t>(n);
    }
    return true;
  };

  Tls12Client client;
  Tls12ClientInfo info;
  std::string why;
  if (!client.connect(io, host, "http/1.1", true, &info, &why, version_hint)) {
    std::printf("handshake failed: %s\n", why.c_str());
    return 1;
  }
  std::printf("handshake ok: suite=%s version=0x%04x kx=%s alpn='%s' ems=%d group=0x%04x chain_checked=%d\n",
              tls12_suite_name(info.cipher_suite).c_str(), info.version, info.key_exchange.c_str(),
              info.alpn.c_str(), info.extended_master_secret ? 1 : 0, info.group,
              info.certificate_chain_checked ? 1 : 0);

  const std::string request =
      "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: tls12probe\r\nConnection: close\r\n\r\n";
  const Bytes outgoing(request.begin(), request.end());
  if (!client.write_app(io, outgoing, &why)) {
    std::printf("write failed: %s\n", why.c_str());
    return 1;
  }
  for (int round = 0; round < 4; ++round) {
    Bytes app;
    if (!client.read_app(io, &app, &why)) {
      std::printf("read %d failed: %s\n", round, why.c_str());
      break;
    }
    const std::string text(app.begin(), app.end());
    std::printf("read %d: %zu byte(s): %.140s\n", round, app.size(), text.c_str());
    if (text.find("\r\n\r\n") != std::string::npos) break;
  }
  client.send_close_notify(io, nullptr);
  return 0;
}
