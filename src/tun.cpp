#include "netcap/tun.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#endif

namespace netcap {

// ---------------------------------------------------------------------------
// portable half
// ---------------------------------------------------------------------------

std::string tun_mask_from_prefix(int prefix_len) {
  if (prefix_len < 0 || prefix_len > 32) return std::string();
  std::uint32_t mask = prefix_len == 0 ? 0u : (0xffffffffu << (32 - prefix_len));
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (mask >> 24) & 0xffu, (mask >> 16) & 0xffu,
                (mask >> 8) & 0xffu, mask & 0xffu);
  return std::string(buf);
}

std::string tun_routes_text(const std::vector<TunRoute>& routes) {
  std::ostringstream out;
  out << "netcap-tun-routes 1\n";
  for (const TunRoute& r : routes) {
    out << "route " << r.destination << "/" << r.prefix_len << " via " << r.next_hop
        << " luid=0x" << std::hex << r.luid << std::dec << " ifindex=" << r.ifindex
        << " metric=" << r.metric << "\n";
  }
  return out.str();
}

namespace {

bool parse_route_line(const std::string& line, TunRoute* route, std::string* error) {
  // route 0.0.0.0/0 via 192.168.0.1 luid=0x16 ifindex=22 metric=0
  std::istringstream in(line);
  std::string kw;
  std::string prefix;
  std::string via_kw;
  std::string next_hop;
  if (!(in >> kw >> prefix >> via_kw >> next_hop) || kw != "route" || via_kw != "via") {
    if (error) *error = "malformed route line: " + line;
    return false;
  }
  const std::size_t slash = prefix.find('/');
  if (slash == std::string::npos) {
    if (error) *error = "route without a prefix length: " + line;
    return false;
  }
  route->destination = prefix.substr(0, slash);
  route->next_hop = next_hop;
  const std::string len_text = prefix.substr(slash + 1);
  if (len_text.empty() || len_text.size() > 2) {
    if (error) *error = "route with a bad prefix length: " + line;
    return false;
  }
  route->prefix_len = std::atoi(len_text.c_str());
  if (route->prefix_len < 0 || route->prefix_len > 32) {
    if (error) *error = "route prefix length out of range: " + line;
    return false;
  }
  std::string token;
  while (in >> token) {
    const std::size_t eq = token.find('=');
    if (eq == std::string::npos) {
      if (error) *error = "route attribute without a value: " + token;
      return false;
    }
    const std::string key = token.substr(0, eq);
    const std::string value = token.substr(eq + 1);
    if (key == "luid") {
      route->luid = std::strtoull(value.c_str(), nullptr, 0);
    } else if (key == "ifindex") {
      route->ifindex = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
    } else if (key == "metric") {
      route->metric = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
    } else {
      if (error) *error = "unknown route attribute: " + key;
      return false;
    }
  }
  return true;
}

}  // namespace

bool tun_routes_parse(const std::string& text, std::vector<TunRoute>* routes, std::string* error) {
  if (routes == nullptr) {
    if (error) *error = "no destination for the parsed routes";
    return false;
  }
  routes->clear();
  std::istringstream in(text);
  std::string line;
  bool header_seen = false;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    if (!header_seen) {
      if (line != "netcap-tun-routes 1") {
        if (error) *error = "not a netcap route snapshot: " + line;
        return false;
      }
      header_seen = true;
      continue;
    }
    if (line.rfind("route ", 0) != 0) {
      if (error) *error = "unexpected line in a route snapshot: " + line;
      return false;
    }
    TunRoute route;
    if (!parse_route_line(line, &route, error)) return false;
    routes->push_back(route);
  }
  if (!header_seen) {
    if (error) *error = "empty route snapshot";
    return false;
  }
  return true;
}

std::uint32_t tun_effective_metric(std::uint32_t route_metric,
                                   std::uint32_t interface_metric) {
  return route_metric + interface_metric;
}

std::uint32_t tun_pick_physical_ifindex(const std::vector<TunRoute>& routes,
                                        const std::vector<TunInterfaceMetric>& ifmetrics,
                                        std::uint32_t own_ifindex) {
  std::uint32_t best = 0;
  std::uint32_t best_metric = 0;
  for (const TunRoute& r : routes) {
    if (r.ifindex == 0 || r.ifindex == own_ifindex) continue;
    std::uint32_t ifmetric = 0;
    for (const TunInterfaceMetric& m : ifmetrics) {
      if (m.luid == r.luid && m.ifindex == r.ifindex) {
        ifmetric = m.metric;
        break;
      }
    }
    const std::uint32_t effective = tun_effective_metric(r.metric, ifmetric);
    if (best == 0 || effective < best_metric) {
      best = r.ifindex;
      best_metric = effective;
    }
  }
  return best;
}

std::string tun_plan_text(const TunTakeoverPlan& plan) {
  std::ostringstream out;
  out << "netcap-tun-plan 2\n";
  for (const TunRoute& r : plan.routes) {
    out << "route " << r.destination << "/" << r.prefix_len << " via " << r.next_hop << " luid=0x"
        << std::hex << r.luid << std::dec << " ifindex=" << r.ifindex << " metric=" << r.metric
        << "\n";
  }
  for (const TunInterfaceMetric& m : plan.ifmetrics) {
    out << "ifmetric luid=0x" << std::hex << m.luid << std::dec << " ifindex=" << m.ifindex
        << " metric=" << m.metric << "\n";
  }
  for (const TunRoute& r : plan.taken) {
    out << "taken " << r.destination << "/" << r.prefix_len << " via " << r.next_hop << " luid=0x"
        << std::hex << r.luid << std::dec << " ifindex=" << r.ifindex << " metric=" << r.metric
        << "\n";
  }
  return out.str();
}

bool tun_plan_parse(const std::string& text, TunTakeoverPlan* plan, std::string* error) {
  if (plan == nullptr) {
    if (error) *error = "no destination for the parsed takeover plan";
    return false;
  }
  plan->routes.clear();
  plan->ifmetrics.clear();
  plan->taken.clear();
  std::istringstream in(text);
  std::string line;
  bool header_seen = false;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    if (!header_seen) {
      // v2 is what this build writes; v1 (a plain route list) still parses so an
      // old snapshot file can be restored: it simply has nothing to delete.
      if (line == "netcap-tun-plan 2" || line == "netcap-tun-routes 1") {
        header_seen = true;
        continue;
      }
      if (error) *error = "not a netcap takeover plan: " + line;
      return false;
    }
    if (line.rfind("route ", 0) == 0) {
      TunRoute route;
      if (!parse_route_line(line, &route, error)) return false;
      plan->routes.push_back(route);
    } else if (line.rfind("taken ", 0) == 0) {
      TunRoute route;
      if (!parse_route_line("route " + line.substr(6), &route, error)) return false;
      plan->taken.push_back(route);
    } else if (line.rfind("ifmetric ", 0) == 0) {
      TunInterfaceMetric entry;
      std::istringstream fields(line.substr(9));
      std::string token;
      bool have_luid = false;
      bool have_index = false;
      bool have_metric = false;
      while (fields >> token) {
        const std::size_t eq = token.find('=');
        if (eq == std::string::npos) {
          if (error) *error = "interface metric without a value: " + token;
          return false;
        }
        const std::string key = token.substr(0, eq);
        const std::string value = token.substr(eq + 1);
        if (key == "luid") {
          entry.luid = std::strtoull(value.c_str(), nullptr, 0);
          have_luid = true;
        } else if (key == "ifindex") {
          entry.ifindex = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
          have_index = true;
        } else if (key == "metric") {
          entry.metric = static_cast<std::uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
          have_metric = true;
        } else {
          if (error) *error = "unknown interface metric attribute: " + key;
          return false;
        }
      }
      if (!have_luid || !have_index || !have_metric) {
        if (error) *error = "incomplete interface metric line: " + line;
        return false;
      }
      plan->ifmetrics.push_back(entry);
    } else {
      if (error) *error = "unexpected line in a takeover plan: " + line;
      return false;
    }
  }
  if (!header_seen) {
    if (error) *error = "empty takeover plan";
    return false;
  }
  return true;
}

bool tun_takeover_is_safe(const std::vector<TunRoute>& routes,
                          const std::vector<TunInterfaceMetric>& ifmetrics,
                          std::uint64_t own_luid, std::string* why) {
  for (const TunRoute& route : routes) {
    if (route.luid == own_luid) continue;  // our own leftover route
    std::uint32_t interface_metric = 0;
    bool known = false;
    for (const TunInterfaceMetric& m : ifmetrics) {
      if (m.ifindex == route.ifindex && m.luid == route.luid) {
        interface_metric = m.metric;
        known = true;
        break;
      }
    }
    // An unknown adapter metric counts as 0: that is the value that would tie
    // with us, so an unknown adapter is treated as a possible loser for us.
    const std::uint32_t effective = tun_effective_metric(route.metric, interface_metric);
    if (effective == 0) {
      if (why != nullptr) {
        *why = "the default route via " + route.next_hop + " (interface " +
               std::to_string(route.ifindex) + ") already has an effective metric of 0" +
               (known ? "" : " (its interface metric could not be read, so it may be 0)") +
               "; a tunnel route would tie with it and the machine could keep using the dead "
               "one, so netcap refuses to take over";
      }
      return false;
    }
  }
  return true;
}

bool tun_read_file(const std::string& path, std::string* text, std::string* error) {
  if (path.empty()) {
    if (error) *error = "no snapshot file given";
    return false;
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error) *error = "could not open " + path;
    return false;
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  if (text != nullptr) *text = buffer.str();
  return true;
}

bool tun_write_file(const std::string& path, const std::string& text, std::string* error) {
  if (path.empty()) {
    if (error) *error = "no snapshot file given";
    return false;
  }
  // Write a temporary file first and rename it into place: a snapshot that is
  // half written is worse than no snapshot at all.
  const std::string temp = path + ".tmp";
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      if (error) *error = "could not write " + temp;
      return false;
    }
    out << text;
    if (!out) {
      if (error) *error = "could not write " + temp;
      return false;
    }
  }
  if (std::remove(path.c_str()) != 0) {
    // Not an error: the file usually does not exist yet.
  }
  if (std::rename(temp.c_str(), path.c_str()) != 0) {
    if (error) *error = "could not rename " + temp + " to " + path;
    std::remove(temp.c_str());
    return false;
  }
  return true;
}

namespace {
// Set by --tun-dll.  Deliberately a single global: the loader caches the first
// usable DLL for the whole process, so the choice has to be in place before it
// runs.
std::string& preferred_dll_path() {
  static std::string path;
  return path;
}
}  // namespace

void tun_prefer_dll(const std::string& path) { preferred_dll_path() = path; }

std::vector<std::string> tun_dll_search_paths() {
  std::vector<std::string> paths;
#ifdef _WIN32
  char exe[MAX_PATH] = {0};
  const DWORD n = GetModuleFileNameA(nullptr, exe, MAX_PATH);
  if (n > 0 && n < MAX_PATH) {
    std::string dir(exe, n);
    const std::size_t slash = dir.find_last_of("\\/");
    if (slash != std::string::npos) dir = dir.substr(0, slash + 1);
    // Next to the executable first: a self-contained folder wins over whatever
    // else happens to be installed on the machine.  The exe lives in build/ (or
    // in ui/build/windows/x64/runner/Release/), so walk a few levels up too:
    // that is where a checkout keeps third_party/wintun/wintun.dll.
    paths.push_back(dir + "wintun.dll");
    paths.push_back(dir + "third_party\\wintun\\wintun.dll");
    std::string up = dir;
    for (int level = 0; level < 3; ++level) {
      up += "..\\";
      paths.push_back(up + "wintun.dll");
      paths.push_back(up + "third_party\\wintun\\wintun.dll");
    }
  }
  char cwd[MAX_PATH] = {0};
  if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) {
    paths.push_back(std::string(cwd) + "\\wintun.dll");
    paths.push_back(std::string(cwd) + "\\third_party\\wintun\\wintun.dll");
  }
  // Bundled with other VPN-ish tools, then the system directory.  These are the
  // places a driver copy tends to already exist, which keeps netcap dependency
  // free without shipping the DLL.
  paths.push_back("C:\\Program Files (x86)\\WattAccelerator\\wintun.dll");
  paths.push_back("C:\\Program Files\\WattAccelerator\\wintun.dll");
  paths.push_back("C:\\Program Files\\WireGuard\\wintun.dll");
  paths.push_back("C:\\Windows\\System32\\wintun.dll");
#else
  paths.push_back("wintun.dll");
#endif
  return paths;
}

std::string tun_default_name() { return "netcap"; }

std::string tun_help() {
  std::string text;
  text +=
      "TUN mode (--tun) takes every IP packet of this machine through a Wintun\n"
      "adapter that netcap owns, so a program does not have to be told about a\n"
      "proxy to be filtered.\n"
      "\n"
      "  --tun                  create/open the adapter and report it (no routing)\n"
      "  --tun-name <name>      adapter alias (default: netcap)\n"
      "  --tun-address <a/n>    address assigned to the adapter (default 10.7.0.1/24)\n"
      "  --tun-mtu <n>          MTU for the adapter (default 1500)\n"
      "  --tun-takeover         send the default route through the adapter; purely\n"
      "                         additive (it lowers the adapter's interface metric and\n"
      "                         adds one route, never removes somebody else's) and it is\n"
      "                         refused unless an upstream answers and no other default\n"
      "                         route already sits at effective metric 0.  A takeover\n"
      "                         that carries no packet within 2 s rolls itself back\n"
      "  --tun-seconds <n>      stop the takeover after n seconds (0 = until Ctrl+C)\n"
      "  --tun-restore <file>   undo a takeover: delete only the route it added and put\n"
      "                         the interface metric back, other routes are left alone\n"
      "  --tun-check            report availability, driver version and routes\n"
      "  --tun-help             this text\n"
      "\n"
      "wintun.dll is loaded at run time (never linked).  Without it --tun reports\n"
      "what is missing and nothing else changes.  Creating the adapter for the\n"
      "first time needs administrator rights; opening it afterwards does not.\n";
  return text;
}

// ---------------------------------------------------------------------------
// Windows half
// ---------------------------------------------------------------------------

#ifdef _WIN32

namespace {

using WintunAdapterHandle = void*;
using WintunSessionHandle = void*;

struct WintunApi {
  HMODULE dll = nullptr;
  std::string path;
  std::string note;
  DWORD driver_version = 0;
  bool usable = false;
  WintunAdapterHandle(WINAPI* create_adapter)(const WCHAR*, const WCHAR*, const GUID*) = nullptr;
  WintunAdapterHandle(WINAPI* open_adapter)(const WCHAR*) = nullptr;
  void(WINAPI* close_adapter)(WintunAdapterHandle) = nullptr;
  void(WINAPI* get_adapter_luid)(WintunAdapterHandle, NET_LUID*) = nullptr;
  DWORD(WINAPI* running_driver_version)() = nullptr;
  WintunSessionHandle(WINAPI* start_session)(WintunAdapterHandle, DWORD) = nullptr;
  void(WINAPI* end_session)(WintunSessionHandle) = nullptr;
  HANDLE(WINAPI* read_wait_event)(WintunSessionHandle) = nullptr;
  BYTE*(WINAPI* receive_packet)(WintunSessionHandle, DWORD*) = nullptr;
  void(WINAPI* release_receive_packet)(WintunSessionHandle, const BYTE*) = nullptr;
  BYTE*(WINAPI* allocate_send_packet)(WintunSessionHandle, DWORD) = nullptr;
  void(WINAPI* send_packet)(WintunSessionHandle, const BYTE*) = nullptr;
};

std::string format_driver_version(DWORD version) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u (0x%08lx)", (unsigned)((version >> 16) & 0xffffu),
                (unsigned)((version >> 8) & 0xffu), (unsigned)(version & 0xffu),
                (unsigned long)version);
  return std::string(buf);
}

// Forward declaration: the loader reports load failures with the OS text, which
// is what makes "wrong architecture" visible instead of "not found".
std::string win_error_text(DWORD code);

// Loaded once per process; the note explains the failure so --tun/--tun-check
// can print it verbatim.
WintunApi& wintun_api() {
  static WintunApi api;
  static bool tried = false;
  if (tried) return api;
  tried = true;
  std::vector<std::string> candidates;
  const std::string preferred = preferred_dll_path();
  if (!preferred.empty()) candidates.push_back(preferred);
  for (const std::string& candidate : tun_dll_search_paths()) {
    if (std::find(candidates.begin(), candidates.end(), candidate) == candidates.end()) {
      candidates.push_back(candidate);
    }
  }
  std::string failures;
  std::string preferred_failure;
  for (const std::string& candidate : candidates) {
    HMODULE dll = LoadLibraryA(candidate.c_str());
    if (dll == nullptr) {
      const DWORD load_error = GetLastError();
      if (!failures.empty()) failures += "; ";
      failures += candidate + " -> " + win_error_text(load_error);
      if (load_error == ERROR_BAD_EXE_FORMAT) {
        failures += " (wrong architecture: this build is 64-bit, that DLL is not)";
      }
      if (!preferred.empty() && candidate == preferred) preferred_failure = failures;
      continue;
    }
    api.dll = dll;
    api.path = candidate;
    // GetProcAddress returns a generic FARPROC; casting it to each real
    // signature is the documented way to bind a DLL at run time.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
    api.create_adapter = (WintunAdapterHandle(WINAPI*)(const WCHAR*, const WCHAR*, const GUID*))
        GetProcAddress(dll, "WintunCreateAdapter");
    api.open_adapter =
        (WintunAdapterHandle(WINAPI*)(const WCHAR*))GetProcAddress(dll, "WintunOpenAdapter");
    api.close_adapter =
        (void(WINAPI*)(WintunAdapterHandle))GetProcAddress(dll, "WintunCloseAdapter");
    api.get_adapter_luid =
        (void(WINAPI*)(WintunAdapterHandle, NET_LUID*))GetProcAddress(dll, "WintunGetAdapterLUID");
    api.running_driver_version =
        (DWORD(WINAPI*)())GetProcAddress(dll, "WintunGetRunningDriverVersion");
    api.start_session = (WintunSessionHandle(WINAPI*)(WintunAdapterHandle, DWORD))
        GetProcAddress(dll, "WintunStartSession");
    api.end_session =
        (void(WINAPI*)(WintunSessionHandle))GetProcAddress(dll, "WintunEndSession");
    api.read_wait_event =
        (HANDLE(WINAPI*)(WintunSessionHandle))GetProcAddress(dll, "WintunGetReadWaitEvent");
    api.receive_packet = (BYTE * (WINAPI*)(WintunSessionHandle, DWORD*))
        GetProcAddress(dll, "WintunReceivePacket");
    api.release_receive_packet = (void(WINAPI*)(WintunSessionHandle, const BYTE*))
        GetProcAddress(dll, "WintunReleaseReceivePacket");
    api.allocate_send_packet = (BYTE * (WINAPI*)(WintunSessionHandle, DWORD))
        GetProcAddress(dll, "WintunAllocateSendPacket");
    api.send_packet =
        (void(WINAPI*)(WintunSessionHandle, const BYTE*))GetProcAddress(dll, "WintunSendPacket");
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
    const bool complete = api.create_adapter != nullptr && api.open_adapter != nullptr &&
                          api.close_adapter != nullptr && api.get_adapter_luid != nullptr &&
                          api.start_session != nullptr && api.end_session != nullptr &&
                          api.read_wait_event != nullptr && api.receive_packet != nullptr &&
                          api.release_receive_packet != nullptr && api.allocate_send_packet != nullptr &&
                          api.send_packet != nullptr;
    if (!complete) {
      if (!failures.empty()) failures += "; ";
      failures += candidate + " -> missing entry points (need wintun 0.14 or newer)";
      api.note = "loaded " + candidate + " but it is missing entry points (wintun 0.14 or newer)";
      api.dll = nullptr;
      api.path.clear();
      FreeLibrary(dll);
      continue;
    }
    if (api.running_driver_version != nullptr) {
      api.driver_version = api.running_driver_version();
    }
    api.usable = true;
    api.note = "using " + candidate;
    if (!preferred_failure.empty()) {
      // --tun-dll pointed at something unusable; say so instead of silently
      // loading a different DLL.
      api.note += " (--tun-dll was rejected: " + preferred_failure + ")";
    }
    if (api.driver_version != 0) {
      api.note += ", driver " + format_driver_version(api.driver_version);
    }
    return api;
  }
  if (api.note.empty()) {
    api.note = "no usable wintun.dll";
    if (failures.empty()) {
      api.note += ": no candidate path was even tried";
    } else {
      api.note += " (tried: " + failures + ")";
    }
  }
  return api;
}

std::string wide_to_utf8(const std::wstring& wide) {
  if (wide.empty()) return std::string();
  const int need = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0,
                                       nullptr, nullptr);
  if (need <= 0) return std::string();
  std::string out(static_cast<std::size_t>(need), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &out[0], need, nullptr, nullptr);
  return out;
}

std::wstring utf8_to_wide(const std::string& text) {
  if (text.empty()) return std::wstring();
  const int need = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), nullptr, 0);
  if (need <= 0) return std::wstring();
  std::wstring out(static_cast<std::size_t>(need), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], need);
  return out;
}

std::string win_error_text(DWORD code) {
  LPWSTR buffer = nullptr;
  const DWORD len = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buffer, 0, nullptr);
  std::string text;
  if (len != 0 && buffer != nullptr) {
    std::wstring wide(buffer, len);
    while (!wide.empty() && (wide.back() == L'\r' || wide.back() == L'\n' || wide.back() == L' ')) {
      wide.pop_back();
    }
    text = wide_to_utf8(wide);
  }
  if (buffer != nullptr) LocalFree(buffer);
  if (text.empty()) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "Win32 error %lu", (unsigned long)code);
    text = buf;
  }
  return text;
}

bool parse_address(const std::string& text, int* prefix_len, std::string* address, std::string* error) {
  const std::size_t slash = text.find('/');
  *address = slash == std::string::npos ? text : text.substr(0, slash);
  *prefix_len = 24;
  if (slash != std::string::npos) {
    const std::string len_text = text.substr(slash + 1);
    if (len_text.empty() || len_text.size() > 2) {
      if (error) *error = "address prefix must be 0..32: " + text;
      return false;
    }
    *prefix_len = std::atoi(len_text.c_str());
    if (*prefix_len < 0 || *prefix_len > 32) {
      if (error) *error = "address prefix must be 0..32: " + text;
      return false;
    }
  }
  IN_ADDR parsed;
  if (InetPtonA(AF_INET, address->c_str(), &parsed) != 1) {
    if (error) *error = "not an IPv4 address: " + *address;
    return false;
  }
  return true;
}

bool luid_to_index(std::uint64_t luid_value, std::uint32_t* ifindex, std::string* error) {
  NET_LUID luid;
  luid.Value = luid_value;
  NET_IFINDEX index = 0;
  const DWORD rc = ConvertInterfaceLuidToIndex(&luid, &index);
  if (rc != NO_ERROR) {
    if (error) *error = "ConvertInterfaceLuidToIndex failed: " + win_error_text(rc);
    return false;
  }
  *ifindex = static_cast<std::uint32_t>(index);
  return true;
}

// Reads every IPv4 default route (0.0.0.0/0) of this machine.
bool read_default_routes(std::vector<TunRoute>* routes, std::string* error) {
  routes->clear();
  MIB_IPFORWARD_TABLE2* table = nullptr;
  const DWORD rc = GetIpForwardTable2(AF_INET, &table);
  if (rc != NO_ERROR) {
    if (error) *error = "GetIpForwardTable2 failed: " + win_error_text(rc);
    return false;
  }
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const MIB_IPFORWARD_ROW2& row = table->Table[i];
    if (row.DestinationPrefix.PrefixLength != 0) continue;
    TunRoute route;
    char dest[INET_ADDRSTRLEN] = {0};
    char hop[INET_ADDRSTRLEN] = {0};
    InetNtopA(AF_INET, &row.DestinationPrefix.Prefix.Ipv4.sin_addr, dest, sizeof(dest));
    InetNtopA(AF_INET, &row.NextHop.Ipv4.sin_addr, hop, sizeof(hop));
    route.destination = dest;
    route.next_hop = hop;
    route.prefix_len = 0;
    route.luid = row.InterfaceLuid.Value;
    route.ifindex = row.InterfaceIndex;
    route.metric = row.Metric;
    routes->push_back(route);
  }
  FreeMibTable(table);
  return true;
}

bool delete_default_route(const TunRoute& route, std::string* error) {
  MIB_IPFORWARD_ROW2 row;
  InitializeIpForwardEntry(&row);
  row.InterfaceLuid.Value = route.luid;
  row.InterfaceIndex = route.ifindex;
  row.DestinationPrefix.Prefix.si_family = AF_INET;
  row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
  row.DestinationPrefix.PrefixLength = 0;
  row.NextHop.si_family = AF_INET;
  row.NextHop.Ipv4.sin_family = AF_INET;
  InetPtonA(AF_INET, route.next_hop.c_str(), &row.NextHop.Ipv4.sin_addr);
  row.Metric = route.metric;
  const DWORD rc = DeleteIpForwardEntry2(&row);
  if (rc != NO_ERROR && rc != ERROR_NOT_FOUND) {
    if (error) {
      *error = "DeleteIpForwardEntry2 " + route.next_hop + " (ifindex " +
               std::to_string(route.ifindex) + ") failed: " + win_error_text(rc);
    }
    return false;
  }
  return true;
}

bool add_default_route(std::uint64_t luid, std::uint32_t ifindex, std::uint32_t metric,
                       std::string* error) {
  MIB_IPFORWARD_ROW2 row;
  InitializeIpForwardEntry(&row);
  row.InterfaceLuid.Value = luid;
  row.InterfaceIndex = ifindex;
  row.DestinationPrefix.Prefix.si_family = AF_INET;
  row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
  row.DestinationPrefix.PrefixLength = 0;
  row.NextHop.si_family = AF_INET;
  row.NextHop.Ipv4.sin_family = AF_INET;
  row.NextHop.Ipv4.sin_addr.s_addr = 0;  // on-link: a TUN has no next hop
  row.Metric = metric;
  row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
  row.ValidLifetime = 0xffffffff;
  row.PreferredLifetime = 0xffffffff;
  row.Immortal = TRUE;
  const DWORD rc = CreateIpForwardEntry2(&row);
  if (rc != NO_ERROR) {
    if (error) *error = "CreateIpForwardEntry2 failed: " + win_error_text(rc);
    return false;
  }
  return true;
}

// The IPv4 interface metric of one adapter.  Together with the route metric it
// decides which default route wins, which is exactly what a takeover has to
// beat - by lowering this number, not by deleting somebody else's route.
bool read_interface_metric(std::uint64_t luid_value, std::uint32_t ifindex,
                           std::uint32_t* metric, std::string* error) {
  MIB_IPINTERFACE_ROW row;
  InitializeIpInterfaceEntry(&row);
  NET_LUID luid;
  luid.Value = luid_value;
  row.InterfaceLuid = luid;
  row.InterfaceIndex = ifindex;
  row.Family = AF_INET;
  const DWORD rc = GetIpInterfaceEntry(&row);
  if (rc != NO_ERROR) {
    if (error) {
      *error = "GetIpInterfaceEntry (interface " + std::to_string(ifindex) +
               ") failed: " + win_error_text(rc);
    }
    return false;
  }
  *metric = row.Metric;
  return true;
}

// Sets the IPv4 interface metric.  Automatic metrics are switched off on the
// way, otherwise the stack would recompute the value and the tunnel route could
// silently lose again.
bool set_interface_metric(std::uint64_t luid_value, std::uint32_t ifindex,
                          std::uint32_t metric, std::string* error) {
  MIB_IPINTERFACE_ROW row;
  InitializeIpInterfaceEntry(&row);
  NET_LUID luid;
  luid.Value = luid_value;
  row.InterfaceLuid = luid;
  row.InterfaceIndex = ifindex;
  row.Family = AF_INET;
  DWORD rc = GetIpInterfaceEntry(&row);
  if (rc == ERROR_NOT_FOUND || rc == ERROR_FILE_NOT_FOUND) {
    return true;  // the adapter is gone (restore after a reboot): nothing to do
  }
  if (rc != NO_ERROR) {
    if (error) {
      *error = "GetIpInterfaceEntry (interface " + std::to_string(ifindex) +
               ") failed: " + win_error_text(rc);
    }
    return false;
  }
  if (row.Metric == metric && row.UseAutomaticMetric == FALSE) return true;
  row.UseAutomaticMetric = FALSE;
  row.Metric = metric;
  row.SitePrefixLength = 0;
  rc = SetIpInterfaceEntry(&row);
  if (rc != NO_ERROR) {
    if (error) {
      *error = "SetIpInterfaceEntry (interface " + std::to_string(ifindex) + " -> metric " +
               std::to_string(metric) + ") failed: " + win_error_text(rc);
    }
    return false;
  }
  return true;
}

}  // namespace

bool tun_available(std::string* detail) {
  WintunApi& api = wintun_api();
  if (detail != nullptr) *detail = api.note;
  return api.usable;
}

bool tun_default_routes(std::string* snapshot, std::string* error) {
  std::vector<TunRoute> routes;
  if (!read_default_routes(&routes, error)) return false;
  if (snapshot != nullptr) *snapshot = tun_routes_text(routes);
  return true;
}

bool tun_interface_metrics(const std::vector<TunRoute>& routes,
                           std::vector<TunInterfaceMetric>* ifmetrics) {
  if (ifmetrics == nullptr) return false;
  ifmetrics->clear();
  for (const TunRoute& route : routes) {
    std::uint32_t metric = 0;
    if (!read_interface_metric(route.luid, route.ifindex, &metric, nullptr)) continue;
    TunInterfaceMetric entry;
    entry.luid = route.luid;
    entry.ifindex = route.ifindex;
    entry.metric = metric;
    ifmetrics->push_back(entry);
  }
  return true;
}

struct TunDevice::Impl {
  WintunApi* api = nullptr;
  WintunAdapterHandle adapter = nullptr;
  WintunSessionHandle session = nullptr;
  HANDLE read_event = nullptr;
  TunDeviceInfo info;
  bool created = false;
};

TunDevice::TunDevice() : impl_(new Impl()) {}

TunDevice::~TunDevice() { close(); }

bool TunDevice::is_open() const { return impl_ != nullptr && impl_->session != nullptr; }

const TunDeviceInfo& TunDevice::info() const { return impl_->info; }

std::string TunDeviceInfo::describe() const {
  std::ostringstream out;
  out << name << " (";
  if (address.empty()) {
    out << "no address";
  } else {
    out << address << "/" << prefix_len;
  }
  out << ", mtu " << mtu << ", ifindex " << ifindex << ", luid 0x" << std::hex << luid << std::dec;
  out << (created ? ", created by netcap" : ", already existed");
  out << ")";
  return out.str();
}

std::string TunDevice::describe() const {
  if (!is_open()) return "tun: closed";
  return "tun: " + impl_->info.describe();
}

bool TunDevice::open(const std::string& name, const std::string& address, int prefix_len,
                     std::uint32_t mtu, TunDeviceInfo* info, std::string* error) {
  close();
  WintunApi& api = wintun_api();
  impl_->api = &api;
  if (!api.usable) {
    if (error) *error = api.note;
    return false;
  }
  const std::string alias = name.empty() ? tun_default_name() : name;
  const std::wstring wide_alias = utf8_to_wide(alias);
  const std::wstring wide_type = utf8_to_wide("netcap");

  // WintunCreateAdapter is the call that makes a *persistent* adapter; it fails
  // with ERROR_ALREADY_EXISTS when the adapter is already there (then OpenAdapter
  // hands us the existing one).  WintunOpenAdapter must not be tried first: for an
  // adapter that does not exist yet it creates a volatile one that disappears again
  // as soon as the last handle is closed - which is exactly the "the adapter was up
  // a moment ago, where did it go" trap.
  WintunAdapterHandle adapter = api.create_adapter(wide_alias.c_str(), wide_type.c_str(), nullptr);
  DWORD create_error = GetLastError();
  bool created = adapter != nullptr;
  if (adapter == nullptr && create_error == ERROR_ALREADY_EXISTS) {
    adapter = api.open_adapter(wide_alias.c_str());
    create_error = adapter != nullptr ? ERROR_SUCCESS : GetLastError();
  }
  if (adapter == nullptr) {
    if (error) {
      *error = "could not open or create the Wintun adapter '" + alias + "': " +
               win_error_text(create_error) +
               " (creating an adapter needs administrator rights the first time)";
    }
    return false;
  }
  if (created) {
    // A freshly created adapter needs a moment before the IP Helper API can see
    // its interface; retry the LUID lookup instead of failing outright.
    NET_LUID probe;
    for (int attempt = 0; attempt < 20; ++attempt) {
      std::memset(&probe, 0, sizeof(probe));
      if (ConvertInterfaceAliasToLuid(wide_alias.c_str(), &probe) == NO_ERROR) break;
      Sleep(50);
    }
  }

  NET_LUID luid;
  std::memset(&luid, 0, sizeof(luid));
  api.get_adapter_luid(adapter, &luid);
  if (luid.Value == 0) {
    if (ConvertInterfaceAliasToLuid(wide_alias.c_str(), &luid) != NO_ERROR) {
      if (error) *error = "the adapter '" + alias + "' has no interface LUID yet";
      api.close_adapter(adapter);
      return false;
    }
  }

  impl_->adapter = adapter;
  impl_->created = created;
  impl_->info.name = alias;
  impl_->info.description = "netcap";
  impl_->info.luid = luid.Value;
  std::uint32_t ifindex = 0;
  std::string index_error;
  if (luid_to_index(luid.Value, &ifindex, &index_error)) {
    impl_->info.ifindex = ifindex;
  }

  if (!address.empty()) {
    int parsed_prefix = prefix_len;
    std::string parsed_address;
    std::string parse_error;
    const std::string spec = address.find('/') == std::string::npos
                                 ? address + "/" + std::to_string(prefix_len)
                                 : address;
    if (!parse_address(spec, &parsed_prefix, &parsed_address, &parse_error)) {
      if (error) *error = parse_error;
      close();
      return false;
    }
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    if (impl_->info.ifindex != 0) row.InterfaceIndex = impl_->info.ifindex;
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    InetPtonA(AF_INET, parsed_address.c_str(), &row.Address.Ipv4.sin_addr);
    row.OnLinkPrefixLength = static_cast<UINT8>(parsed_prefix);
    row.DadState = IpDadStatePreferred;
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;
    DWORD rc = CreateUnicastIpAddressEntry(&row);
    if (rc == ERROR_OBJECT_ALREADY_EXISTS) rc = NO_ERROR;
    if (rc != NO_ERROR) {
      if (error) {
        *error = "could not assign " + parsed_address + "/" + std::to_string(parsed_prefix) +
                 " to '" + alias + "': " + win_error_text(rc);
      }
      close();
      return false;
    }
    impl_->info.address = parsed_address;
    impl_->info.prefix_len = parsed_prefix;
  } else {
    impl_->info.prefix_len = prefix_len;
  }

  // Bring the interface up and set the MTU, otherwise packets are dropped on
  // the floor even though the adapter exists.
  MIB_IPINTERFACE_ROW ifrow;
  InitializeIpInterfaceEntry(&ifrow);
  ifrow.InterfaceLuid = luid;
  ifrow.Family = AF_INET;
  DWORD rc = GetIpInterfaceEntry(&ifrow);
  if (rc == NO_ERROR) {
    if (mtu != 0) ifrow.NlMtu = mtu;
    ifrow.SitePrefixLength = 0;
    rc = SetIpInterfaceEntry(&ifrow);
    if (rc != NO_ERROR) {
      if (error) *error = "could not configure '" + alias + "': " + win_error_text(rc);
      close();
      return false;
    }
    impl_->info.mtu = ifrow.NlMtu;
  } else if (mtu != 0) {
    impl_->info.mtu = mtu;
  }

  impl_->session = api.start_session(adapter, 0x400000);  // 4 MiB ring, as WireGuard uses
  if (impl_->session == nullptr) {
    const DWORD session_error = GetLastError();
    if (error) {
      *error = "WintunStartSession failed on '" + alias + "': " + win_error_text(session_error);
    }
    close();
    return false;
  }
  impl_->read_event = api.read_wait_event(impl_->session);
  impl_->info.open = true;
  if (info != nullptr) *info = impl_->info;
  return true;
}

void TunDevice::close() {
  if (impl_ == nullptr) return;
  if (impl_->api != nullptr && impl_->session != nullptr) {
    impl_->api->end_session(impl_->session);
  }
  impl_->session = nullptr;
  impl_->read_event = nullptr;
  if (impl_->api != nullptr && impl_->adapter != nullptr) {
    impl_->api->close_adapter(impl_->adapter);
  }
  impl_->adapter = nullptr;
  impl_->info.open = false;
}

int TunDevice::read_packet(std::uint8_t* buffer, std::size_t capacity, int timeout_ms,
                           std::string* error) {
  if (!is_open()) {
    if (error) *error = "the tunnel is not open";
    return -1;
  }
  WintunApi& api = *impl_->api;
  const DWORD deadline = GetTickCount();
  for (;;) {
    DWORD size = 0;
    BYTE* packet = api.receive_packet(impl_->session, &size);
    if (packet != nullptr) {
      int result = static_cast<int>(size);
      if (size > capacity) {
        result = -1;
        if (error) {
          *error = "packet of " + std::to_string(size) + " bytes does not fit in " +
                   std::to_string(capacity);
        }
      } else {
        std::memcpy(buffer, packet, size);
      }
      api.release_receive_packet(impl_->session, packet);
      return result;
    }
    const DWORD rc = GetLastError();
    if (rc != ERROR_NO_MORE_ITEMS) {
      if (error) *error = "WintunReceivePacket failed: " + win_error_text(rc);
      return -1;
    }
    if (timeout_ms == 0) return 0;
    DWORD wait = INFINITE;
    if (timeout_ms > 0) {
      const DWORD spent = GetTickCount() - deadline;
      if (spent >= static_cast<DWORD>(timeout_ms)) return 0;
      wait = static_cast<DWORD>(timeout_ms) - spent;
    }
    if (impl_->read_event != nullptr) {
      const DWORD signalled = WaitForSingleObject(impl_->read_event, wait);
      if (signalled == WAIT_TIMEOUT) return 0;
    } else if (wait != INFINITE) {
      Sleep(wait);
      return 0;
    }
  }
}

bool TunDevice::write_packet(const std::uint8_t* packet, std::size_t length, std::string* error) {
  if (!is_open()) {
    if (error) *error = "the tunnel is not open";
    return false;
  }
  if (length == 0 || length > 0xffff) {
    if (error) *error = "refusing to send a packet of " + std::to_string(length) + " bytes";
    return false;
  }
  WintunApi& api = *impl_->api;
  BYTE* slot = api.allocate_send_packet(impl_->session, static_cast<DWORD>(length));
  if (slot == nullptr) {
    const DWORD rc = GetLastError();
    if (error) *error = "WintunAllocateSendPacket failed: " + win_error_text(rc);
    return false;
  }
  std::memcpy(slot, packet, length);
  api.send_packet(impl_->session, slot);
  return true;
}

bool tun_takeover_default_routes(const TunDevice& device, std::string* snapshot, std::string* error) {
  if (!device.is_open()) {
    if (error) *error = "the tunnel is not open";
    return false;
  }
  // Snapshot first: if this fails the routing table is left exactly as it was,
  // which is the only way a crash can stay recoverable.
  std::vector<TunRoute> before;
  if (!read_default_routes(&before, error)) return false;
  const TunDeviceInfo& info = device.info();

  // Effective metric = route metric + interface metric, so the interface metric
  // of every adapter with a default route belongs in the plan.
  std::vector<TunInterfaceMetric> ifmetrics;
  for (const TunRoute& route : before) {
    std::uint32_t metric = 0;
    std::string why;
    if (read_interface_metric(route.luid, route.ifindex, &metric, &why)) {
      TunInterfaceMetric entry;
      entry.luid = route.luid;
      entry.ifindex = route.ifindex;
      entry.metric = metric;
      ifmetrics.push_back(entry);
    }
    // Unreadable adapters are left out on purpose: tun_takeover_is_safe() then
    // treats their metric as 0 and refuses, instead of guessing.
  }

  std::string refusal;
  if (!tun_takeover_is_safe(before, ifmetrics, info.luid, &refusal)) {
    if (error) *error = refusal;
    return false;
  }

  std::uint32_t own_metric = 0;
  if (!read_interface_metric(info.luid, info.ifindex, &own_metric, error)) return false;

  TunTakeoverPlan plan;
  plan.routes = before;
  plan.ifmetrics = ifmetrics;
  TunInterfaceMetric own;
  own.luid = info.luid;
  own.ifindex = info.ifindex;
  own.metric = own_metric;
  plan.ifmetrics.push_back(own);

  // Additive takeover: the tunnel wins by having the lowest effective metric
  // (0 + 0), not by removing the physical default route.  Deleting that route
  // is what cut this machine off the network once, so nothing of somebody
  // else's is touched here at all.
  if (!set_interface_metric(info.luid, info.ifindex, 0, error)) return false;
  if (!add_default_route(info.luid, info.ifindex, 0, error)) {
    std::string ignored;
    set_interface_metric(info.luid, info.ifindex, own_metric, &ignored);  // roll back
    return false;
  }

  TunRoute ours;
  ours.destination = "0.0.0.0";
  ours.prefix_len = 0;
  ours.next_hop = "0.0.0.0";
  ours.luid = info.luid;
  ours.ifindex = info.ifindex;
  ours.metric = 0;
  plan.taken.push_back(ours);
  if (snapshot != nullptr) *snapshot = tun_plan_text(plan);
  return true;
}

bool tun_restore_default_routes(const std::string& snapshot, std::string* error) {
  if (snapshot.empty()) return true;  // nothing was taken over
  TunTakeoverPlan plan;
  if (!tun_plan_parse(snapshot, &plan, error)) return false;

  // 1. Delete the routes this takeover added - and only those.
  for (const TunRoute& ours : plan.taken) {
    std::string why;
    if (!delete_default_route(ours, &why)) {
      if (error) *error = "could not remove the tunnel default route: " + why;
      return false;
    }
  }

  // 2. Put the interface metrics back to the values from before.
  for (const TunInterfaceMetric& m : plan.ifmetrics) {
    std::string why;
    if (!set_interface_metric(m.luid, m.ifindex, m.metric, &why)) {
      if (error) *error = "could not restore an interface metric: " + why;
      return false;
    }
  }

  // 3. Repair, do not rebuild: a default route from the snapshot that is missing
  //    (because something else removed it) is added back.  Routes that are not
  //    in the plan are left alone - this function never deletes foreign routes.
  std::vector<TunRoute> now;
  if (!read_default_routes(&now, error)) return false;
  for (const TunRoute& want : plan.routes) {
    bool present = false;
    for (const TunRoute& have : now) {
      if (have.luid == want.luid && have.ifindex == want.ifindex &&
          have.next_hop == want.next_hop && have.metric == want.metric) {
        present = true;
        break;
      }
    }
    if (present) continue;
    std::string why;
    if (!add_default_route(want.luid, want.ifindex, want.metric, &why)) {
      if (error) *error = "could not put the default route via " + want.next_hop + " back: " + why;
      return false;
    }
  }
  return true;
}

#else  // !_WIN32

namespace {
struct TunDevice::Impl {};
}  // namespace

bool tun_available(std::string* detail) {
  if (detail != nullptr) {
    *detail = "TUN mode is implemented for Windows (Wintun) only; on this platform --tun does "
              "nothing";
  }
  return false;
}

bool tun_default_routes(std::string* snapshot, std::string* error) {
  if (snapshot != nullptr) *snapshot = tun_routes_text({});
  if (error) *error = "reading the routing table is only implemented on Windows";
  return false;
}

bool tun_interface_metrics(const std::vector<TunRoute>&,
                           std::vector<TunInterfaceMetric>* ifmetrics) {
  if (ifmetrics != nullptr) ifmetrics->clear();
  return false;  // interface metrics can only be read on Windows
}

TunDevice::TunDevice() : impl_(new Impl()) {}
TunDevice::~TunDevice() { close(); }
bool TunDevice::is_open() const { return false; }
const TunDeviceInfo& TunDevice::info() const { return impl_->info; }
std::string TunDeviceInfo::describe() const { return name + " (unsupported platform)"; }
std::string TunDevice::describe() const { return "tun: unsupported platform"; }
bool TunDevice::open(const std::string&, const std::string&, int, std::uint32_t, TunDeviceInfo*,
                     std::string* error) {
  if (error) *error = "TUN mode is implemented for Windows (Wintun) only";
  return false;
}
void TunDevice::close() {}
int TunDevice::read_packet(std::uint8_t*, std::size_t, int, std::string* error) {
  if (error) *error = "TUN mode is implemented for Windows (Wintun) only";
  return -1;
}
bool TunDevice::write_packet(const std::uint8_t*, std::size_t, std::string* error) {
  if (error) *error = "TUN mode is implemented for Windows (Wintun) only";
  return false;
}
bool tun_takeover_default_routes(const TunDevice&, std::string*, std::string* error) {
  if (error) *error = "TUN mode is implemented for Windows (Wintun) only";
  return false;
}
bool tun_restore_default_routes(const std::string&, std::string* error) {
  if (error) *error = "TUN mode is implemented for Windows (Wintun) only";
  return false;
}

#endif  // _WIN32

}  // namespace netcap
