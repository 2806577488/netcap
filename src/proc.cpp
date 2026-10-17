// Process attribution, portable part: the endpoint table container, the
// per-flow memory and the per-process counters.  The platform layer
// (proc_win.cpp) only has to answer two questions: "list the local endpoints
// with their owning PIDs" and "what is the image name of this PID?".
#include "netcap/proc.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace netcap {

namespace {

constexpr u8 kProtoTcp = 6;
constexpr u8 kProtoUdp = 17;

// Endpoint key: proto, address family, address, port.  A std::string keeps the
// map node small and avoids padding surprises, exactly like the fragment key in
// the dissector.
std::string endpoint_key(int family, const u8* addr, u16 port, u8 proto) {
  std::string k;
  k.reserve(20);
  k.push_back(char(proto));
  k.push_back(char(family));
  k.append(reinterpret_cast<const char*>(addr), family == 6 ? 16 : 4);
  k.push_back(char((port >> 8) & 0xff));
  k.push_back(char(port & 0xff));
  return k;
}

std::string lower_copy(const std::string& s) {
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return char(std::tolower(c)); });
  return out;
}

}  // namespace

std::string ProcessInfo::label() const {
  if (name.empty()) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "pid %lu", static_cast<unsigned long>(pid));
    return buf;
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), " (%lu)", static_cast<unsigned long>(pid));
  return name + buf;
}

std::string proc_sanitize_name(const std::string& name) {
  std::string out;
  out.reserve(name.size() + 8);
  for (unsigned char c : name) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-';
    out.push_back(ok ? char(c) : '_');
  }
  while (!out.empty() && (out.front() == '.' || out.front() == '_')) out.erase(out.begin());
  if (out.empty()) out = "unknown";
  if (out.size() > 64) out.resize(64);
  return out;
}

// --- endpoint table --------------------------------------------------------

bool ProcessTable::refresh(std::string* error) {
  std::vector<ProcEndpoint> rows;
  if (!proc_collect_endpoints(&rows, error)) return false;

  // Every process name the OS is willing to hand over without opening handles:
  // the fallback for PIDs that refuse OpenProcess and the source of retries for
  // PIDs whose first lookup happened before the process had an image.
  std::map<u32, std::string> names;
  proc_collect_process_names(&names);

  endpoints_.clear();
  raw_.clear();
  raw_.reserve(rows.size());
  for (const ProcEndpoint& r : rows) {
    const std::size_t alen = r.family == 6 ? 16 : 4;
    u8 addr[16] = {0};
    std::memcpy(addr, r.addr, alen);
    endpoints_[endpoint_key(r.family, addr, r.port, r.proto)] = r.pid;
    raw_.push_back(r);   // peers and states intact: the proxy correlator needs them
    auto it = procs_.find(r.pid);
    // Retry while the name is still unknown: an empty cached name would
    // otherwise stick for the whole run and the report would only ever say
    // "pid N", even though the process is perfectly nameable one second later.
    if (it == procs_.end() || it->second.name.empty()) {
      ProcessInfo p;
      p.pid = r.pid;
      proc_resolve_process(r.pid, &p);   // may fail: the PID is kept anyway
      if (p.name.empty()) {
        const auto n = names.find(r.pid);
        if (n != names.end()) p.name = n->second;
      }
      p.pid = r.pid;
      if (p.key.empty() && !p.name.empty()) p.key = lower_copy(p.name);
      auto prev = procs_.find(r.pid);
      // Keep a path we already know: the snapshot fallback only has the name.
      if (prev != procs_.end() && p.path.empty()) p.path = prev->second.path;
      procs_[r.pid] = p;
    }
  }
  refreshed_us_ = now_monotonic_us();
  ++refreshes_;
  return true;
}

const ProcessInfo* ProcessTable::owner(int family, const u8* addr, u16 port, u8 proto) const {
  if (family != 4 && family != 6) return nullptr;
  auto it = endpoints_.find(endpoint_key(family, addr, port, proto));
  if (it == endpoints_.end()) {
    // A wildcard bind (0.0.0.0 / ::) owns the port even when the packet went to
    // a specific local address, and connection rows can lag behind the packets.
    u8 any[16] = {0};
    it = endpoints_.find(endpoint_key(family, any, port, proto));
    if (it == endpoints_.end()) return nullptr;
  }
  return by_pid(it->second);
}

const ProcessInfo* ProcessTable::owner_of(const PacketInfo& pi, int* dir) const {
  if (dir) *dir = -1;
  if (!pi.has_ports) return nullptr;
  const int family = pi.ip_version;
  if (family != 4 && family != 6) return nullptr;
  const u8 proto = (pi.l4 == L4::Udp) ? kProtoUdp : kProtoTcp;
  if (const ProcessInfo* p = owner(family, pi.src_ip, pi.src_port, proto)) {
    if (dir) *dir = 0;
    return p;
  }
  if (const ProcessInfo* p = owner(family, pi.dst_ip, pi.dst_port, proto)) {
    if (dir) *dir = 1;
    return p;
  }
  return nullptr;
}

const ProcessInfo* ProcessTable::by_pid(u32 pid) const {
  auto it = procs_.find(pid);
  return it == procs_.end() ? nullptr : &it->second;
}

const ProcessInfo* ProcessTable::by_name(const std::string& name) const {
  const std::string want = lower_copy(name);
  for (const auto& kv : procs_) {
    if (kv.second.key == want) return &kv.second;
  }
  return nullptr;
}

std::vector<const ProcessInfo*> ProcessTable::owners() const {
  std::vector<u32> pids;
  pids.reserve(endpoints_.size());
  for (const auto& kv : endpoints_) {
    if (std::find(pids.begin(), pids.end(), kv.second) == pids.end()) pids.push_back(kv.second);
  }
  std::vector<const ProcessInfo*> out;
  out.reserve(pids.size());
  for (u32 pid : pids) {
    if (const ProcessInfo* p = by_pid(pid)) out.push_back(p);
  }
  std::sort(out.begin(), out.end(), [](const ProcessInfo* a, const ProcessInfo* b) {
    if (a->key != b->key) return a->key < b->key;
    return a->pid < b->pid;
  });
  return out;
}

std::string ProcessTable::describe() const {
  char buf[192];
  std::snprintf(buf, sizeof(buf), "endpoint table: %zu endpoints, %zu processes, refreshed %.1fs ago",
                endpoints_.size(), procs_.size(),
                refreshed_us_ ? double(now_monotonic_us() - refreshed_us_) / 1e6 : 0.0);
  return buf;
}

void ProcessTable::clear() {
  endpoints_.clear();
  procs_.clear();
  refreshed_us_ = 0;
}

void ProcessTable::add_process(const ProcessInfo& p) {
  ProcessInfo copy = p;
  if (copy.key.empty() && !copy.name.empty()) copy.key = lower_copy(copy.name);
  procs_[copy.pid] = copy;
}

void ProcessTable::add_endpoint(int family, const u8* addr, u16 port, u8 proto, u32 pid) {
  endpoints_[endpoint_key(family, addr, port, proto)] = pid;
  if (procs_.find(pid) == procs_.end()) {
    ProcessInfo p;
    p.pid = pid;
    procs_[pid] = p;
  }
}

// --- attribution -----------------------------------------------------------

ProcAttributor::ProcAttributor() = default;

std::string ProcAttributor::flow_key(const PacketInfo& pi) {
  std::string k;
  k.reserve(44);
  k.push_back(char(pi.l4 == L4::Udp ? kProtoUdp : kProtoTcp));
  k.push_back(char(pi.ip_version));
  const std::size_t alen = pi.ip_version == 6 ? 16 : 4;
  k.append(reinterpret_cast<const char*>(pi.src_ip), alen);
  k.push_back(char((pi.src_port >> 8) & 0xff));
  k.push_back(char(pi.src_port & 0xff));
  k.append(reinterpret_cast<const char*>(pi.dst_ip), alen);
  k.push_back(char((pi.dst_port >> 8) & 0xff));
  k.push_back(char(pi.dst_port & 0xff));
  return k;
}

const ProcOwnership& ProcAttributor::attribute(const PacketInfo& pi, i64 ts_us) {
  (void)ts_us;   // capture timestamps may come from any epoch: see proc.hpp
  const i64 now = now_monotonic_us();
  ++lookups_;

  if (!cfg_.enabled) {
    last_.reset("process attribution is disabled");
    ++misses_;
    return last_;
  }
  if (!pi.has_ports || (pi.ip_version != 4 && pi.ip_version != 6)) {
    last_.reset("packet carries no IP transport ports");
    ++misses_;
    return last_;
  }

  const std::string key = flow_key(pi);
  if (cfg_.cache) {
    auto it = cache_.find(key);
    if (it != cache_.end() && now - it->second.ts_us <= cfg_.cache_ttl_us) {
      it->second.ts_us = now;
      last_.known = true;
      last_.proc = it->second.proc;
      last_.dir = it->second.dir;
      last_.from_cache = true;
      last_.why = "remembered from an earlier packet of this flow";
      ++hits_;
      ++cache_hits_;
      return last_;
    }
  }

  ProcessTable& t = active_table();
  // An injected table belongs to the caller (tests, and a live run that already
  // refreshed it): never refresh it behind their back.
  const bool injected = external_ != nullptr;
  const bool never = t.refreshed_us() == 0;
  const bool stale = never || (now - t.refreshed_us() > cfg_.table_ttl_us);
  if (!injected && stale && (never || now - last_miss_us_ >= cfg_.retry_us)) {
    std::string err;
    last_miss_us_ = now;
    ++refreshes_;
    if (!t.refresh(&err)) {
      why_storage_ = err.empty() ? std::string("could not read the OS endpoint table") : err;
      last_.reset(why_storage_.c_str());
      ++misses_;
      return last_;
    }
    // The proxy correlator rebuilds from the very snapshot this lookup uses.
    if (refresh_hook_) refresh_hook_(t);
  }

  int dir = -1;
  const ProcessInfo* p = t.owner_of(pi, &dir);
  if (!p) {
    last_.reset("no local endpoint in the OS table owns this packet");
    ++misses_;
    return last_;
  }
  last_.known = true;
  last_.proc = *p;
  last_.dir = dir;
  last_.from_cache = false;
  last_.why = dir == 0 ? "local source endpoint belongs to this process"
                       : "local destination endpoint belongs to this process";
  ++hits_;
  if (!p->named()) ++unnameable_;
  if (cfg_.cache) {
    Entry e;
    e.proc = *p;
    e.dir = dir;
    e.ts_us = now;
    cache_[key] = e;
  }
  return last_;
}

void ProcAttributor::gc(i64 now_us) {
  for (auto it = cache_.begin(); it != cache_.end();) {
    if (now_us - it->second.ts_us > cfg_.cache_ttl_us)
      it = cache_.erase(it);
    else
      ++it;
  }
}

std::string ProcAttributor::describe() const {
  char buf[256];
  std::snprintf(buf, sizeof(buf),
                "process attribution: %llu lookup(s), %llu hit(s) (%llu from flow memory), "
                "%llu miss(es), %llu table read(s), %zu flow(s) remembered",
                static_cast<unsigned long long>(lookups_), static_cast<unsigned long long>(hits_),
                static_cast<unsigned long long>(cache_hits_),
                static_cast<unsigned long long>(misses_),
                static_cast<unsigned long long>(refreshes_), cache_.size());
  return buf;
}

// --- per-process counters --------------------------------------------------

std::string ProcCounters::label() const {
  if (name.empty()) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "pid %lu", static_cast<unsigned long>(pid));
    return buf;
  }
  return name;
}

ProcCounters& ProcTotals::slot(const ProcessInfo& p) {
  ProcCounters& c = by_pid_[p.pid];
  if (c.pid == 0) c.pid = p.pid;
  if (c.name.empty() && !p.name.empty()) c.name = p.name;
  return c;
}

void ProcTotals::add_packet(const ProcessInfo& p, u64 bytes) {
  ProcCounters& c = slot(p);
  ++c.packets;
  c.bytes += bytes;
}

void ProcTotals::add_flow(const ProcessInfo& p) { ++slot(p).flows; }
void ProcTotals::add_transaction(const ProcessInfo& p) { ++slot(p).transactions; }
void ProcTotals::add_decrypted_stream(const ProcessInfo& p) { ++slot(p).decrypted_streams; }

std::vector<ProcCounters> ProcTotals::sorted() const {
  std::vector<ProcCounters> out;
  out.reserve(by_pid_.size());
  for (const auto& kv : by_pid_) out.push_back(kv.second);
  std::sort(out.begin(), out.end(), [](const ProcCounters& a, const ProcCounters& b) {
    if (a.bytes != b.bytes) return a.bytes > b.bytes;
    return a.pid < b.pid;
  });
  return out;
}

u64 ProcTotals::total_packets() const {
  u64 n = 0;
  for (const auto& kv : by_pid_) n += kv.second.packets;
  return n;
}

u64 ProcTotals::total_bytes() const {
  u64 n = 0;
  for (const auto& kv : by_pid_) n += kv.second.bytes;
  return n;
}

}  // namespace netcap
