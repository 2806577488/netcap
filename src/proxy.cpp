#include "netcap/proxy.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace netcap {
namespace {

constexpr u8 kProtoTcp = 6;
constexpr u8 kStateListen = 2;

/** Proxy client image names (lower case, without the .exe suffix). */
const char* kProxyNames[] = {
    "clash", "clash-win64", "clash-verge", "verge-mihomo", "mihomo", "flclash", "clashn",
    "v2ray", "v2raya", "xray", "xray-core", "wingsv", "winsw", "qv2ray", "qv2ray-core",
    "sing-box", "singbox", "sing-box-core", "hysteria", "hysteria2", "tuic", "naive",
    "trojan", "trojan-go", "shadowsocks", "shadowsocksr", "sslocal", "ssr", "ss-local",
    "nekoray", "nekobox", "netch", "tun2socks", "proxifier", "proxycap", "socks",
    "privoxy", "polipo", "tor", "obfs4proxy", "shadowsocks-libev", "mellow", "brooks",
};

/** Ports local proxies listen on.  Kept deliberately short: a wrong entry here
 *  would turn an ordinary server into a "proxy". */
const u16 kProxyPorts[] = {
    1080, 1081, 1086, 1087, 1088, 1089, 2080, 2081, 2082, 2083, 2086, 2087, 2088,
    7890, 7891, 7892, 7893, 7894, 7897, 7898, 7899, 8118, 8123, 9000, 9050, 9150,
    10808, 10809, 10810, 10811, 20170, 20171, 20172, 20808,
};

std::string lower(const std::string& s) { return to_lower(s); }

std::string strip_exe(std::string s) {
  if (s.size() > 4 && iequals(s.substr(s.size() - 4), ".exe")) s.resize(s.size() - 4);
  return s;
}

std::size_t addr_len(int family) { return family == 6 ? 16 : 4; }

std::string key_of(int family, const u8* addr, u16 port, u8 proto) {
  std::string k;
  k.reserve(2 + 16 + 2 + 1);
  k.push_back(char(proto));
  k.push_back(char(family));
  k.append(reinterpret_cast<const char*>(addr), addr_len(family));
  k.push_back(char((port >> 8) & 0xffu));
  k.push_back(char(port & 0xffu));
  return k;
}

std::string peer_key(int family, const u8* addr, u16 port) { return key_of(family, addr, port, 0); }

bool addr_is_zero(int family, const u8* addr) {
  const std::size_t n = addr_len(family);
  for (std::size_t i = 0; i < n; ++i) {
    if (addr[i] != 0) return false;
  }
  return true;
}

bool addr_equal(int family, const u8* a, const u8* b) {
  return std::memcmp(a, b, addr_len(family)) == 0;
}

bool addr_is_loopback(int family, const u8* addr) {
  if (family == 6) {
    for (int i = 0; i < 15; ++i) {
      if (addr[i] != 0) return false;
    }
    return addr[15] == 1;
  }
  return addr[0] == 127;
}

/** A proxy listens on loopback or on a wildcard address; anything else is a
 *  server, not a proxy. */
bool addr_is_localish(int family, const u8* addr) {
  return addr_is_zero(family, addr) || addr_is_loopback(family, addr);
}

std::string endpoint_text(int family, const u8* addr, u16 port) {
  return format_ip(family, addr) + ":" + std::to_string(unsigned(port));
}

std::string proc_label(const std::string& name, u32 pid) {
  if (name.empty()) return "pid " + std::to_string(pid);
  return name + " (" + std::to_string(pid) + ")";
}

}  // namespace

bool name_looks_like_proxy(const std::string& image_name) {
  const std::string n = strip_exe(lower(image_name));
  if (n.empty()) return false;
  for (const char* p : kProxyNames) {
    if (n == p || n.find(p) != std::string::npos) return true;
  }
  return false;
}

bool port_looks_like_proxy(u16 port) {
  for (u16 p : kProxyPorts) {
    if (p == port) return true;
  }
  return false;
}

const char* proxy_confidence_name(ProxyConfidence c) {
  switch (c) {
    case ProxyConfidence::Order: return "order";
    case ProxyConfidence::Host: return "host";
    case ProxyConfidence::None: break;
  }
  return "none";
}

const char* proxy_confidence_text(ProxyConfidence c) {
  switch (c) {
    case ProxyConfidence::Order:
      return "guessed from the order the two ends appeared in: treat it as a hint, not as proof";
    case ProxyConfidence::Host:
      return "the same host name was seen on the application's request and on the proxy's connection";
    case ProxyConfidence::None: break;
  }
  return "not correlated";
}

std::string ProxyTable::why(const std::string& key) {
  auto it = outbound_hosts_.find(key);
  if (it != outbound_hosts_.end() && !it->second.empty()) return it->second;
  return std::string();
}

void ProxyTable::clear() {
  endpoints_.clear();
  clients_.clear();
  outbounds_.clear();
  proxy_names_.clear();
  links_.clear();
  outbound_hosts_.clear();
  client_hosts_.clear();
  seen_.clear();
  clock_ = 0;
  rebuilds_ = 0;
}

bool ProxyTable::is_proxy_pid(u32 pid) const { return proxy_names_.find(pid) != proxy_names_.end(); }

const std::string* ProxyTable::proxy_name(u32 pid) const {
  auto it = proxy_names_.find(pid);
  return it == proxy_names_.end() ? nullptr : &it->second;
}

const ProxyLink* ProxyTable::link(int family, const u8* raddr, u16 rport) const {
  auto it = links_.find(peer_key(family, raddr, rport));
  return it == links_.end() ? nullptr : &it->second;
}

void ProxyTable::note_outbound_host(int family, const u8* raddr, u16 rport, const std::string& host) {
  if (host.empty()) return;
  outbound_hosts_[peer_key(family, raddr, rport)] = lower(host);
}

void ProxyTable::note_client_host(int family, const u8* addr, u16 port, const std::string& host) {
  if (host.empty()) return;
  client_hosts_[peer_key(family, addr, port)] = lower(host);
}

void ProxyTable::rebuild(const std::vector<ProcEndpoint>& rows, const ProcessTable& procs, i64 now_us) {
  (void)now_us;   // ordering uses sighting order, never a timestamp
  ++rebuilds_;
  endpoints_.clear();
  clients_.clear();
  outbounds_.clear();
  proxy_names_.clear();
  if (!enabled_) {
    links_.clear();
    return;
  }

  // 1. Find the proxy processes: either by image name or by a listening socket
  //    on a well known proxy port bound to a local address.
  std::vector<bool> is_proxy(rows.size(), false);
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const ProcEndpoint& r = rows[i];
    const ProcessInfo* pi = procs.by_pid(r.pid);
    const std::string name = pi ? pi->name : std::string();
    bool proxy = name_looks_like_proxy(name);
    const bool listener = r.proto == kProtoTcp && (r.state == kStateListen || r.rport == 0);
    if (!proxy && listener && port_looks_like_proxy(r.port) && addr_is_localish(r.family, r.addr)) {
      proxy = true;
    }
    is_proxy[i] = proxy;
    if (!proxy) continue;
    proxy_names_[r.pid] = name;
    if (listener && r.proto == kProtoTcp) {
      ProxyEndpoint e;
      e.pid = r.pid;
      e.name = name;
      e.family = r.family;
      std::memcpy(e.addr, r.addr, addr_len(r.family));
      e.port = r.port;
      endpoints_.push_back(e);
    }
  }

  // A proxy process that is running but has no listening row we could see (they
  // appear and disappear) still counts: its connections are outbound halves.
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const ProcEndpoint& r = rows[i];
    if (r.proto != kProtoTcp || r.rport == 0) continue;
    if (is_proxy[i]) {
      if (addr_is_loopback(r.family, r.raddr) || addr_is_zero(r.family, r.raddr)) continue;
      ProxyOutbound o;
      o.pid = r.pid;
      o.name = proxy_names_[r.pid];
      o.family = r.family;
      std::memcpy(o.raddr, r.raddr, addr_len(r.family));
      o.rport = r.rport;
      o.lport = r.port;
      o.order = 0;
      outbounds_.push_back(o);
      continue;
    }
    // Application -> proxy: the peer must be one of the proxy endpoints.
    for (const ProxyEndpoint& e : endpoints_) {
      if (e.family != r.family || e.port != r.rport) continue;
      const bool wildcard = addr_is_zero(e.family, e.addr);
      if (!wildcard && !addr_equal(e.family, e.addr, r.raddr)) continue;
      if (!addr_is_loopback(r.family, r.raddr) && !wildcard) continue;
      ProxyClient c;
      c.pid = r.pid;
      const ProcessInfo* pi = procs.by_pid(r.pid);
      c.name = pi ? pi->name : std::string();
      c.family = r.family;
      std::memcpy(c.addr, r.addr, addr_len(r.family));
      c.port = r.port;
      std::memcpy(c.paddr, r.raddr, addr_len(r.family));
      c.pport = r.rport;
      c.order = 0;
      clients_.push_back(c);
      break;
    }
  }

  // 2. First sighting order, remembered across rebuilds so that a connection
  //    keeps its position while it lives.
  const auto order_of = [&](int family, const u8* addr, u16 port, u32 pid) {
    const std::string k = key_of(family, addr, port, kProtoTcp) + std::to_string(pid);
    auto it = seen_.find(k);
    if (it != seen_.end()) return it->second;
    const u64 v = ++clock_;
    seen_[k] = v;
    return v;
  };
  for (ProxyClient& c : clients_) c.order = order_of(c.family, c.addr, c.port, c.pid);
  for (ProxyOutbound& o : outbounds_) o.order = order_of(o.family, o.raddr, o.rport, o.pid);
  std::sort(clients_.begin(), clients_.end(), [](const ProxyClient& a, const ProxyClient& b) {
    return a.order < b.order;
  });
  std::sort(outbounds_.begin(), outbounds_.end(), [](const ProxyOutbound& a, const ProxyOutbound& b) {
    return a.order < b.order;
  });

  // 3. Pick up host names we have learned about either half in the meantime.
  for (ProxyClient& c : clients_) {
    auto it = client_hosts_.find(peer_key(c.family, c.addr, c.port));
    if (it != client_hosts_.end()) c.host = it->second;
  }
  for (ProxyOutbound& o : outbounds_) {
    auto it = outbound_hosts_.find(peer_key(o.family, o.raddr, o.rport));
    if (it != outbound_hosts_.end()) o.host = it->second;
  }

  // 4. Pair: host-exact matches first, then first-sighting order.
  links_.clear();
  std::vector<bool> taken(outbounds_.size(), false);
  std::vector<bool> client_taken(clients_.size(), false);
  const auto make_link = [&](const ProxyClient& c, const ProxyOutbound& o, ProxyConfidence conf,
                             const std::string& basis) {
    ProxyLink l;
    l.origin_pid = c.pid;
    l.origin_name = c.name;
    l.proxy_pid = o.pid;
    l.proxy_name = o.name;
    l.family = o.family;
    std::memcpy(l.raddr, o.raddr, addr_len(l.family));
    l.rport = o.rport;
    l.confidence = conf;
    l.basis = basis;
    links_[peer_key(l.family, l.raddr, l.rport)] = l;
  };
  for (std::size_t ci = 0; ci < clients_.size(); ++ci) {
    const ProxyClient& c = clients_[ci];
    if (c.host.empty()) continue;
    for (std::size_t i = 0; i < outbounds_.size(); ++i) {
      if (taken[i] || outbounds_[i].host.empty()) continue;
      if (lower(outbounds_[i].host) != lower(c.host)) continue;
      make_link(c, outbounds_[i], ProxyConfidence::Host,
                std::string("both halves asked for '") + lower(c.host) + "'");
      taken[i] = true;
      client_taken[ci] = true;
      outbounds_[i].paired = true;
      break;
    }
  }
  std::size_t next = 0;
  for (std::size_t ci = 0; ci < clients_.size(); ++ci) {
    if (client_taken[ci]) continue;
    while (next < outbounds_.size() && taken[next]) ++next;
    if (next >= outbounds_.size()) break;
    make_link(clients_[ci], outbounds_[next], ProxyConfidence::Order,
              "the proxy opened this connection around the time the application asked it to");
    taken[next] = true;
    outbounds_[next].paired = true;
    ++next;
  }
}

std::string ProxyTable::describe() const {
  if (!enabled_) return "proxy correlation is off";
  if (proxy_names_.empty()) return "no local proxy process was found in the endpoint table";
  std::ostringstream out;
  out << proxy_names_.size() << " proxy process(es), " << clients_.size() << " client socket(s), "
      << links_.size() << " of " << outbounds_.size() << " outbound connection(s) matched";
  return out.str();
}

std::string ProxyTable::report() const {
  std::ostringstream out;
  if (!enabled_) {
    out << "proxy correlation   : off\n";
    return out.str();
  }
  out << "proxy correlation   : " << describe() << "\n";
  for (const auto& kv : proxy_names_) {
    bool listening = false;
    std::string where;
    for (const ProxyEndpoint& e : endpoints_) {
      if (e.pid != kv.first) continue;
      listening = true;
      where = endpoint_text(e.family, e.addr, e.port);
    }
    out << "  proxy process     : " << proc_label(kv.second, kv.first);
    if (listening) out << "  listening on " << where;
    else out << "  (no listening socket seen)";
    out << "\n";
  }
  std::size_t shown = 0;
  for (const ProxyOutbound& o : outbounds_) {
    const ProxyLink* l = link(o.family, o.raddr, o.rport);
    out << "  " << (l ? "matched          " : "unmatched        ") << " : ";
    out << endpoint_text(o.family, o.raddr, o.rport);
    if (l) {
      out << "  <- " << proc_label(l->origin_name, l->origin_pid) << "  (" << proxy_confidence_name(l->confidence)
          << ")\n";
    } else {
      out << "  <- ?\n";
    }
    if (++shown >= 12 && outbounds_.size() > 12) {
      out << "  ... and " << (outbounds_.size() - shown) << " more outbound connection(s)\n";
      break;
    }
  }
  if (outbounds_.empty()) out << "  (no outbound connection of a proxy process was seen)\n";
  return out.str();
}

}  // namespace netcap
