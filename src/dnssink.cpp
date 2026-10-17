#include "netcap/dnssink.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fstream>
#endif

namespace netcap {

namespace {

#ifdef _WIN32
using native_socket = SOCKET;
using socket_len = int;
const native_socket kNoSocket = INVALID_SOCKET;
#else
using native_socket = int;
using socket_len = socklen_t;
const int kNoSocket = -1;
#endif

// One WSAStartup for the whole process; the capture layer does the same.
bool ensure_sockets() {
#ifdef _WIN32
  static bool ready = false;
  if (ready) return true;
  WSADATA data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
  ready = true;
#endif
  return true;
}

void close_socket(native_socket s) {
  if (s == kNoSocket) return;
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

int last_socket_error() {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

std::string socket_error_text(int code) {
  return "socket error " + std::to_string(code);
}

// "1.2.3.4:53" or "[::1]:53" for a sockaddr_storage.
std::string endpoint_text(const sockaddr_storage& ss) {
  char host[64] = {0};
  u16 port = 0;
  if (ss.ss_family == AF_INET) {
    const sockaddr_in* in = reinterpret_cast<const sockaddr_in*>(&ss);
    if (inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host)) == nullptr) return "?";
    port = ntohs(in->sin_port);
  } else if (ss.ss_family == AF_INET6) {
    const sockaddr_in6* in6 = reinterpret_cast<const sockaddr_in6*>(&ss);
    if (inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host)) == nullptr) return "?";
    port = ntohs(in6->sin6_port);
  } else {
    return "?";
  }
  std::ostringstream os;
  os << host << ":" << port;
  return os.str();
}

bool resolve_datagram(const std::string& host, u16 port, sockaddr_storage* out, socket_len* out_len,
                      std::string* error) {
  addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  addrinfo* res = nullptr;
  const std::string service = std::to_string(port);
  const int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
  if (rc != 0 || res == nullptr) {
    if (error != nullptr) *error = "cannot use '" + host + "' as a DNS address";
    return false;
  }
  std::memcpy(out, res->ai_addr, res->ai_addrlen);
  *out_len = static_cast<socket_len>(res->ai_addrlen);
  freeaddrinfo(res);
  return true;
}

bool split_endpoint(const std::string& text, std::string* host, u16* port) {
  if (text.empty()) return false;
  if (text[0] == '[') {  // [::1]:53
    const std::size_t close = text.find(']');
    if (close == std::string::npos) return false;
    *host = text.substr(1, close - 1);
    *port = 53;
    if (close + 2 <= text.size() && text[close + 1] == ':') {
      *port = static_cast<u16>(std::strtoul(text.substr(close + 2).c_str(), nullptr, 10));
    }
    return !host->empty() && *port != 0;
  }
  const std::size_t colon = text.rfind(':');
  if (colon == std::string::npos || text.find(':') != colon) {  // bare IPv6 or bare host
    *host = text;
    *port = 53;
  } else {
    *host = text.substr(0, colon);
    *port = static_cast<u16>(std::strtoul(text.substr(colon + 1).c_str(), nullptr, 10));
  }
  return !host->empty() && *port != 0;
}

std::string lower_name(const std::string& s) { return to_lower(s); }

}  // namespace

bool dns_parse_question(const u8* data, std::size_t len, std::string* name, u16* qtype,
                        u16* qclass, std::size_t* after) {
  if (data == nullptr || len < 12) return false;
  const u16 qdcount = static_cast<u16>(rd16be(data + 4));
  if (qdcount != 1) return false;  // one question per query is all we serve
  std::size_t pos = 12;
  std::string out;
  u32 jumps = 0;
  bool jumped = false;
  std::size_t next = pos;
  while (pos < len) {
    const u8 label = data[pos];
    if ((label & 0xc0) == 0xc0) {
      if (pos + 1 >= len) return false;
      const std::size_t target = (static_cast<std::size_t>(label & 0x3f) << 8) | data[pos + 1];
      if (!jumped) {
        next = pos + 2;
        jumped = true;
      }
      if (++jumps > 8 || target >= len) return false;
      pos = target;
      continue;
    }
    if (label == 0) {
      ++pos;
      if (!jumped) next = pos;
      break;
    }
    if ((label & 0xc0) != 0) return false;  // reserved label kind
    if (pos + 1 + label > len) return false;
    if (!out.empty()) out.push_back('.');
    for (u8 k = 0; k < label; ++k) {
      out.push_back(static_cast<char>(std::tolower(data[pos + 1 + k])));
    }
    pos += 1u + label;
    if (out.size() > 255) return false;
  }
  if (pos + 4 > len) return false;
  if (name != nullptr) *name = out;
  if (qtype != nullptr) *qtype = static_cast<u16>(rd16be(data + pos));
  if (qclass != nullptr) *qclass = static_cast<u16>(rd16be(data + pos + 2));
  if (after != nullptr) *after = pos + 4;
  return true;
}

std::size_t dns_build_sink_answer(const u8* query, std::size_t len, const std::string& sink_ipv4,
                                 const std::string& sink_ipv6, u32 ttl, std::vector<u8>* out) {
  if (out == nullptr) return 0;
  out->clear();
  u16 qtype = 0;
  u16 qclass = 0;
  std::size_t after = 0;
  if (!dns_parse_question(query, len, nullptr, &qtype, &qclass, &after)) return 0;

  u8 address[16];
  int version = 0;
  std::size_t rdlen = 0;
  const u16 answer_type = qtype;
  if (qtype == 1) {
    if (!parse_ip(sink_ipv4, &version, address) || version != 4) return 0;
    rdlen = 4;
  } else if (qtype == 28) {
    if (!parse_ip(sink_ipv6, &version, address) || version != 6) return 0;
    rdlen = 16;
  }

  // Header: same id, QR=1, same opcode, AA=1, RD copied, RA=1, rcode 0.
  out->insert(out->end(), query, query + 12);
  (*out)[2] = static_cast<u8>(0x80 | (query[2] & 0x79) | 0x04);
  (*out)[3] = 0x80;
  (*out)[4] = 0;
  (*out)[5] = 1;  // one question
  const u16 ancount = rdlen != 0 ? 1 : 0;
  (*out)[6] = static_cast<u8>(ancount >> 8);
  (*out)[7] = static_cast<u8>(ancount & 0xff);
  (*out)[8] = 0;
  (*out)[9] = 0;
  (*out)[10] = 0;
  (*out)[11] = 0;
  // Question, verbatim.
  out->insert(out->end(), query + 12, query + after);
  if (ancount == 0) return out->size();
  // Answer: a compression pointer back to the question name.
  const u8 rr[] = {0xc0, 0x0c, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0};
  out->insert(out->end(), rr, rr + sizeof(rr));
  const std::size_t rr_start = out->size() - sizeof(rr);
  (*out)[rr_start + 2] = static_cast<u8>(answer_type >> 8);
  (*out)[rr_start + 3] = static_cast<u8>(answer_type & 0xff);
  (*out)[rr_start + 4] = 0;
  (*out)[rr_start + 5] = 1;  // class IN
  (*out)[rr_start + 6] = static_cast<u8>((ttl >> 24) & 0xff);
  (*out)[rr_start + 7] = static_cast<u8>((ttl >> 16) & 0xff);
  (*out)[rr_start + 8] = static_cast<u8>((ttl >> 8) & 0xff);
  (*out)[rr_start + 9] = static_cast<u8>(ttl & 0xff);
  (*out)[rr_start + 10] = static_cast<u8>(rdlen >> 8);
  (*out)[rr_start + 11] = static_cast<u8>(rdlen & 0xff);
  out->insert(out->end(), address, address + rdlen);
  return out->size();
}

std::string system_dns_upstream() {
#ifdef _WIN32
  ULONG size = 0;
  if (GetNetworkParams(nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) return "";
  std::vector<u8> buffer(size);
  FIXED_INFO* info = reinterpret_cast<FIXED_INFO*>(buffer.data());
  if (GetNetworkParams(info, &size) != ERROR_SUCCESS) return "";
  const IP_ADDR_STRING* server = &info->DnsServerList;
  while (server != nullptr) {
    const std::string text = server->IpAddress.String;
    if (!text.empty() && text != "0.0.0.0") return text + ":53";
    server = server->Next;
  }
  return "";
#else
  std::ifstream in("/etc/resolv.conf");
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream is(line);
    std::string key;
    std::string value;
    is >> key >> value;
    if (key == "nameserver" && !value.empty()) return value + ":53";
  }
  return "";
#endif
}

struct DnsSink::Impl {
  DnsSinkConfig cfg;
  const RuleSet* rules = nullptr;
  native_socket fd = kNoSocket;
  sockaddr_storage upstream_addr;
  socket_len upstream_len = 0;
  std::string bound;
  std::string upstream_text;
  std::string error;
  std::vector<DnsQueryEvent> events;
  DnsSinkStats stats;
  bool running = false;
  i64 started_us = 0;
};

DnsSink::DnsSink() : impl_(new Impl()) {}
DnsSink::~DnsSink() {
  stop();
  delete impl_;
}

bool DnsSink::start(const DnsSinkConfig& config, const RuleSet* rules, std::string* error) {
  stop();
  impl_->cfg = config;
  impl_->rules = rules;
  impl_->events.clear();
  impl_->stats = DnsSinkStats();
  impl_->error.clear();
  if (!ensure_sockets()) {
    if (error != nullptr) *error = "winsock could not be started";
    return false;
  }

  const std::string upstream = config.upstream.empty() ? system_dns_upstream() : config.upstream;
  if (upstream.empty()) {
    if (error != nullptr) {
      *error = "no upstream DNS server is known; pass --dns-upstream <ip[:port]>";
    }
    return false;
  }
  std::string up_host;
  u16 up_port = 53;
  if (!split_endpoint(upstream, &up_host, &up_port)) {
    if (error != nullptr) *error = "cannot parse the upstream resolver '" + upstream + "'";
    return false;
  }
  std::string resolve_error;
  if (!resolve_datagram(up_host, up_port, &impl_->upstream_addr, &impl_->upstream_len,
                        &resolve_error)) {
    if (error != nullptr) *error = resolve_error + " (" + upstream + ")";
    return false;
  }
  impl_->upstream_text = up_host + ":" + std::to_string(up_port);

  sockaddr_storage bind_addr;
  socket_len bind_len = 0;
  std::string bind_error;
  if (!resolve_datagram(config.bind_address, config.port, &bind_addr, &bind_len, &bind_error)) {
    if (error != nullptr) *error = bind_error;
    return false;
  }
  const native_socket fd = socket(bind_addr.ss_family, SOCK_DGRAM, 0);
  if (fd == kNoSocket) {
    if (error != nullptr) *error = socket_error_text(last_socket_error());
    return false;
  }
  if (bind(fd, reinterpret_cast<const sockaddr*>(&bind_addr), bind_len) != 0) {
    const int code = last_socket_error();
    close_socket(fd);
    std::ostringstream os;
    os << "cannot listen on " << config.bind_address << ":" << config.port << " ("
       << socket_error_text(code) << ")";
    if (config.port < 1024) os << "; ports below 1024 need Administrator rights";
    if (config.port == 5353) os << "; Windows' own mDNS resolver owns 5353, try 5399 instead";
    if (error != nullptr) *error = os.str();
    return false;
  }
  sockaddr_storage bound;
  socket_len bound_out = sizeof(bound);
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_out) == 0) {
    impl_->bound = endpoint_text(bound);
  } else {
    impl_->bound = config.bind_address + ":" + std::to_string(config.port);
  }
  impl_->fd = fd;
  impl_->running = true;
  impl_->started_us = now_monotonic_us();
  return true;
}

void DnsSink::stop() {
  if (impl_ == nullptr) return;
  impl_->running = false;
  if (impl_->fd != kNoSocket) {
    close_socket(impl_->fd);
    impl_->fd = kNoSocket;
  }
}

bool DnsSink::running() const { return impl_ != nullptr && impl_->running; }
u16 DnsSink::port() const {
  const std::size_t colon = impl_->bound.rfind(':');
  if (colon == std::string::npos) return 0;
  return static_cast<u16>(std::strtoul(impl_->bound.substr(colon + 1).c_str(), nullptr, 10));
}
const std::string& DnsSink::bound_endpoint() const { return impl_->bound; }
const std::string& DnsSink::upstream() const { return impl_->upstream_text; }
const std::string& DnsSink::error() const { return impl_->error; }
std::vector<DnsQueryEvent> DnsSink::events() const { return impl_->events; }
DnsSinkStats DnsSink::stats() const { return impl_->stats; }

bool DnsSink::serve_once(int timeout_ms) {
  if (impl_ == nullptr || impl_->fd == kNoSocket) return false;
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(impl_->fd, &read_set);
  timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  const int ready = select(static_cast<int>(impl_->fd + 1), &read_set, nullptr, nullptr, &tv);
  if (ready <= 0) return false;

  u8 buffer[4096];
  sockaddr_storage client;
  socket_len client_len = sizeof(client);
  const int got = recvfrom(impl_->fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                           reinterpret_cast<sockaddr*>(&client), &client_len);
  if (got <= 0) return false;
  const std::size_t len = static_cast<std::size_t>(got);

  DnsQueryEvent event;
  event.ts_us = now_monotonic_us();
  event.client = endpoint_text(client);
  ++impl_->stats.queries;

  std::string name;
  u16 qtype = 0;
  u16 qclass = 0;
  std::size_t after = 0;
  if (!dns_parse_question(buffer, len, &name, &qtype, &qclass, &after)) {
    event.action = "malformed";
    event.detail = "not a single question DNS query";
    ++impl_->stats.malformed;
    impl_->events.push_back(event);
    return true;
  }
  event.name = name;
  event.qtype = qtype;
  event.qclass = qclass;

  std::vector<u8> reply;
  const Rule* rule = impl_->rules != nullptr ? impl_->rules->host_rule(name) : nullptr;
  const bool blocked = impl_->rules != nullptr && impl_->rules->host_blocked(name);
  if (blocked) {
    const std::size_t written = dns_build_sink_answer(buffer, len, impl_->cfg.sink_ipv4,
                                                      impl_->cfg.sink_ipv6, impl_->cfg.ttl, &reply);
    if (written == 0) {
      event.action = "error";
      event.detail = "the query could not be answered";
      ++impl_->stats.errors;
      impl_->events.push_back(event);
      return true;
    }
    event.blocked = true;
    event.action = "sink";
    event.detail = qtype == 1 ? impl_->cfg.sink_ipv4
                              : (qtype == 28 ? impl_->cfg.sink_ipv6 : std::string("no answer"));
    if (rule != nullptr) event.detail += "  [" + rule->raw + "]";
    ++impl_->stats.blocked;
  } else {
    // Pass the query through untouched and relay whatever comes back: this
    // server must not change how the rest of the internet resolves.
    const native_socket up = socket(impl_->upstream_addr.ss_family, SOCK_DGRAM, 0);
    if (up == kNoSocket) {
      event.action = "error";
      event.detail = socket_error_text(last_socket_error());
      ++impl_->stats.errors;
      impl_->events.push_back(event);
      return true;
    }
    const int sent = sendto(up, reinterpret_cast<const char*>(buffer), len, 0,
                            reinterpret_cast<const sockaddr*>(&impl_->upstream_addr),
                            impl_->upstream_len);
    if (sent <= 0) {
      event.action = "error";
      event.detail = "the upstream resolver could not be reached";
      ++impl_->stats.errors;
      close_socket(up);
      impl_->events.push_back(event);
      return true;
    }
    fd_set up_set;
    FD_ZERO(&up_set);
    FD_SET(up, &up_set);
    timeval up_tv;
    up_tv.tv_sec = impl_->cfg.timeout_ms / 1000;
    up_tv.tv_usec = (impl_->cfg.timeout_ms % 1000) * 1000;
    const int up_ready = select(static_cast<int>(up + 1), &up_set, nullptr, nullptr, &up_tv);
    if (up_ready <= 0) {
      event.action = "error";
      event.detail = "the upstream resolver did not answer in time";
      ++impl_->stats.errors;
      close_socket(up);
      impl_->events.push_back(event);
      return true;
    }
    u8 answer[4096];
    const int answered = recv(up, reinterpret_cast<char*>(answer), sizeof(answer), 0);
    close_socket(up);
    if (answered <= 0) {
      event.action = "error";
      event.detail = "no answer arrived from the upstream resolver";
      ++impl_->stats.errors;
      impl_->events.push_back(event);
      return true;
    }
    reply.assign(answer, answer + answered);
    event.action = "forward";
    event.detail = impl_->upstream_text;
    ++impl_->stats.forwarded;
  }

  sendto(impl_->fd, reinterpret_cast<const char*>(reply.data()), reply.size(), 0,
         reinterpret_cast<const sockaddr*>(&client), client_len);
  ++impl_->stats.answers_sent;
  impl_->events.push_back(event);
  if (impl_->cfg.max_queries != 0 && impl_->stats.queries >= impl_->cfg.max_queries) {
    impl_->running = false;
  }
  return true;
}

void DnsSink::run() {
  while (impl_ != nullptr && impl_->running) {
    serve_once(impl_->cfg.timeout_ms);
  }
}

std::string DnsSink::report() const {
  std::ostringstream os;
  os << "dns sink            : " << impl_->bound << "  (upstream " << impl_->upstream_text << ")\n";
  os << "dns queries         : " << impl_->stats.queries << " (" << impl_->stats.blocked
     << " blocked, " << impl_->stats.forwarded << " forwarded, " << impl_->stats.errors
     << " error(s), " << impl_->stats.malformed << " malformed)\n";
  std::map<std::string, unsigned> blocked_names;
  for (const DnsQueryEvent& e : impl_->events) {
    if (e.blocked) ++blocked_names[e.name];
  }
  if (!blocked_names.empty()) {
    std::vector<std::pair<unsigned, std::string>> top;
    for (const auto& kv : blocked_names) top.push_back({kv.second, kv.first});
    std::sort(top.begin(), top.end(), [](const std::pair<unsigned, std::string>& a,
                                         const std::pair<unsigned, std::string>& b) {
      if (a.first != b.first) return a.first > b.first;
      return a.second < b.second;
    });
    os << "most blocked names  :";
    for (std::size_t i = 0; i < top.size() && i < 5; ++i) {
      os << " " << top[i].second << " (" << top[i].first << ")";
    }
    os << "\n";
  }
  return os.str();
}

std::string DnsSink::describe() const {
  std::ostringstream os;
  os << "dns sink hole on " << impl_->bound << ", upstream " << impl_->upstream_text << ", "
     << (impl_->rules != nullptr ? impl_->rules->size() : 0) << " rule(s)";
  return os.str();
}

}  // namespace netcap
