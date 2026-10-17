// System proxy takeover: portable snapshot format + the Windows registry half.
//
// See include/netcap/sysproxy.hpp for the safety rules this file implements.

#include "netcap/sysproxy.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#ifdef _WIN32
// winsock2.h has to be included before windows.h: windows.h pulls in the old
// winsock.h otherwise, and the two cannot be mixed in one translation unit.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace netcap {
namespace {

const char* kSnapshotHeader = "netcap-system-proxy 1";

std::string trim_copy(const std::string& s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
  return s.substr(b, e - b);
}

std::string escape_value(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char c : value) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

bool unescape_value(const std::string& text, std::string* out, std::string* error) {
  out->clear();
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] != '\\') {
      out->push_back(text[i]);
      continue;
    }
    if (i + 1 >= text.size()) {
      if (error) *error = "the snapshot ends with a lone backslash";
      return false;
    }
    const char c = text[++i];
    switch (c) {
      case '\\': out->push_back('\\'); break;
      case 'n': out->push_back('\n'); break;
      case 'r': out->push_back('\r'); break;
      case 't': out->push_back('\t'); break;
      default:
        if (error) *error = std::string("unknown escape '\\") + c + "' in the snapshot";
        return false;
    }
  }
  return true;
}

void append_field(std::string* out, const char* key, bool present, const std::string& value) {
  if (!present) {
    *out += "!";
    *out += key;
    *out += "\n";
    return;
  }
  *out += key;
  *out += "=";
  *out += escape_value(value);
  *out += "\n";
}

// Resolves path + ".tmp" -> path, replacing an existing file (Windows rename()
// refuses to overwrite, so the target is removed first).
bool write_text_file(const std::string& path, const std::string& text, std::string* error) {
  const std::string temp = path + ".tmp";
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) {
      if (error) *error = "cannot write '" + temp + "'";
      return false;
    }
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    out.flush();
    if (!out) {
      if (error) *error = "cannot write '" + temp + "'";
      return false;
    }
  }
  std::remove(path.c_str());
  if (std::rename(temp.c_str(), path.c_str()) != 0) {
    if (error) *error = "cannot move '" + temp + "' into place";
    std::remove(temp.c_str());
    return false;
  }
  return true;
}

bool read_text_file(const std::string& path, std::string* out, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error) *error = "cannot read '" + path + "'";
    return false;
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  *out = buffer.str();
  return true;
}

}  // namespace

std::string SystemProxyState::describe() const {
  std::ostringstream out;
  if (!enabled()) {
    out << "off";
  } else if (server.empty()) {
    out << "on (no server value)";
  } else {
    out << "on -> " << server;
  }
  if (override_present && !override_list.empty()) out << ", bypass " << override_list;
  if (auto_config_present && !auto_config_url.empty()) {
    out << ", auto-config " << auto_config_url;
  }
  return out.str();
}

// ---------------------------------------------------------------- portable

std::string system_proxy_snapshot_text(const SystemProxyState& state) {
  std::string out;
  out += kSnapshotHeader;
  out += "\n";
  append_field(&out, "proxy_enable", state.enable_present,
               state.enable_present ? std::to_string(state.enable) : std::string());
  append_field(&out, "proxy_server", state.server_present, state.server);
  append_field(&out, "proxy_override", state.override_present, state.override_list);
  append_field(&out, "auto_config_url", state.auto_config_present, state.auto_config_url);
  return out;
}

bool system_proxy_snapshot_parse(const std::string& text, SystemProxyState* out, std::string* error) {
  if (out == nullptr) {
    if (error) *error = "no destination for the snapshot";
    return false;
  }
  *out = SystemProxyState();
  std::istringstream in(text);
  std::string line;
  bool first = true;
  std::size_t number = 0;
  while (std::getline(in, line)) {
    ++number;
    line = trim_copy(line);
    if (line.empty()) continue;
    if (first) {
      first = false;
      if (line != kSnapshotHeader) {
        if (error) *error = "this is not a netcap system proxy snapshot (line 1 is '" + line + "')";
        return false;
      }
      continue;
    }
    bool present = true;
    std::string body = line;
    if (body[0] == '!') {
      present = false;
      body = body.substr(1);
    }
    std::string key = body;
    std::string value;
    if (present) {
      const std::size_t eq = body.find('=');
      if (eq == std::string::npos) {
        if (error) *error = "line " + std::to_string(number) + ": '" + line + "' has no '='";
        return false;
      }
      key = body.substr(0, eq);
      if (!unescape_value(body.substr(eq + 1), &value, error)) {
        if (error) *error = "line " + std::to_string(number) + ": " + *error;
        return false;
      }
    }
    if (key == "proxy_enable") {
      out->enable_present = present;
      if (!present) continue;
      char* end = nullptr;
      const unsigned long v = std::strtoul(value.c_str(), &end, 10);
      if (end == nullptr || *end != '\0' || value.empty()) {
        if (error) *error = "line " + std::to_string(number) + ": proxy_enable is not a number";
        return false;
      }
      out->enable = static_cast<u32>(v);
    } else if (key == "proxy_server") {
      out->server_present = present;
      out->server = value;
    } else if (key == "proxy_override") {
      out->override_present = present;
      out->override_list = value;
    } else if (key == "auto_config_url") {
      out->auto_config_present = present;
      out->auto_config_url = value;
    } else {
      if (error) *error = "line " + std::to_string(number) + ": unknown key '" + key + "'";
      return false;
    }
  }
  if (first) {
    if (error) *error = "the snapshot is empty";
    return false;
  }
  return true;
}

bool system_proxy_snapshot_write(const SystemProxyState& state, const std::string& path,
                                 std::string* error) {
  if (path.empty()) {
    if (error) *error = "no snapshot path was given";
    return false;
  }
  return write_text_file(path, system_proxy_snapshot_text(state), error);
}

bool system_proxy_snapshot_load(const std::string& path, SystemProxyState* out, std::string* error) {
  std::string text;
  if (!read_text_file(path, &text, error)) return false;
  return system_proxy_snapshot_parse(text, out, error);
}

bool system_proxy_snapshot_exists(const std::string& path) {
  if (path.empty()) return false;
  std::ifstream in(path, std::ios::binary);
  return in.good();
}

bool system_proxy_snapshot_remove(const std::string& path) {
  if (path.empty()) return false;
  return std::remove(path.c_str()) == 0;
}

bool system_proxy_endpoint_ok(const std::string& server, u16* port, std::string* normalized,
                              std::string* error) {
  const std::string text = trim_copy(server);
  if (text.empty()) {
    if (error) *error = "the proxy endpoint is empty";
    return false;
  }
  std::string host = text;
  std::string port_text;
  if (text[0] == '[') {  // [2001:db8::1]:8080
    const std::size_t close = text.find(']');
    if (close == std::string::npos) {
      if (error) *error = "'" + text + "' has no closing ']'";
      return false;
    }
    host = text.substr(1, close - 1);
    const std::string rest = text.substr(close + 1);
    if (!rest.empty()) {
      if (rest[0] != ':') {
        if (error) *error = "'" + text + "' has trailing text after the address";
        return false;
      }
      port_text = rest.substr(1);
    }
  } else {
    const std::size_t colon = text.find(':');
    if (colon != std::string::npos) {
      if (text.find(':', colon + 1) != std::string::npos) {
        if (error) {
          *error = "'" + text + "' looks like a bare IPv6 address; wrap it in [ ] to add a port";
        }
        return false;
      }
      host = text.substr(0, colon);
      port_text = text.substr(colon + 1);
    }
  }
  if (host.empty()) {
    if (error) *error = "'" + text + "' has no host part";
    return false;
  }
  u16 parsed_port = 0;
  if (!port_text.empty()) {
    char* end = nullptr;
    const unsigned long v = std::strtoul(port_text.c_str(), &end, 10);
    if (end == nullptr || *end != '\0' || v == 0 || v > 65535) {
      if (error) *error = "'" + port_text + "' is not a port number";
      return false;
    }
    parsed_port = static_cast<u16>(v);
  }
  if (port != nullptr) *port = parsed_port;
  if (normalized != nullptr) {
    *normalized = parsed_port == 0 ? host : host + ":" + std::to_string(parsed_port);
  }
  return true;
}

std::string system_proxy_bypass_auto(const std::string& base, bool machine_has_ipv6) {
  if (machine_has_ipv6) return base;
  const std::string kNcsiV6 = "ipv6.msftncsi.com";
  std::string out = base.empty() ? std::string("<local>") : base;
  if (out.find(kNcsiV6) == std::string::npos) {
    if (!out.empty() && out.back() != ';') out += ';';
    out += kNcsiV6;
  }
  return out;
}

// ---------------------------------------------------------------- platform

#ifdef _WIN32
namespace {

const wchar_t* kSettingsKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

std::string win_error_text(const char* what, LONG code) {
  std::ostringstream out;
  out << what << " failed (Win32 error " << static_cast<long>(code) << ")";
  return out.str();
}

std::wstring to_wide(const std::string& text) {
  if (text.empty()) return std::wstring();
  const int need = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                       nullptr, 0);
  std::wstring out(static_cast<std::size_t>(need < 0 ? 0 : need), L'\0');
  if (need > 0) {
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), need);
  }
  return out;
}

std::string to_utf8(const std::wstring& text) {
  if (text.empty()) return std::string();
  const int need = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                       nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(need < 0 ? 0 : need), '\0');
  if (need > 0) {
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), need,
                        nullptr, nullptr);
  }
  return out;
}

bool reg_read(HKEY key, const wchar_t* name, bool* present, DWORD* type, std::vector<u8>* data,
              std::string* error) {
  *present = false;
  DWORD size = 0;
  DWORD kind = 0;
  LONG rc = RegQueryValueExW(key, name, nullptr, &kind, nullptr, &size);
  if (rc == ERROR_FILE_NOT_FOUND) return true;
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegQueryValueEx", rc);
    return false;
  }
  std::vector<u8> buffer(size + sizeof(wchar_t), 0);
  rc = RegQueryValueExW(key, name, nullptr, &kind, buffer.data(), &size);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegQueryValueEx", rc);
    return false;
  }
  buffer.resize(size);
  *present = true;
  *type = kind;
  *data = buffer;
  return true;
}

bool reg_open_read(HKEY* key, std::string* error) {
  const LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, kSettingsKey, 0, KEY_READ, key);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegOpenKeyEx(Internet Settings)", rc);
    return false;
  }
  return true;
}

bool reg_open_write(HKEY* key, std::string* error) {
  const LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, kSettingsKey, 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_READ | KEY_SET_VALUE, nullptr, key,
                                  nullptr);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegCreateKeyEx(Internet Settings)", rc);
    return false;
  }
  return true;
}

void notify_wininet() {
  // WinINET caches the settings; without these two the change is only visible
  // to processes that start later.
  InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
  InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}

bool read_state(HKEY key, SystemProxyState* out, std::string* error) {
  bool present = false;
  DWORD type = 0;
  std::vector<u8> data;
  if (!reg_read(key, L"ProxyEnable", &present, &type, &data, error)) return false;
  out->enable_present = present;
  if (present && type == REG_DWORD && data.size() >= 4) {
    out->enable = static_cast<u32>(data[0]) | (static_cast<u32>(data[1]) << 8) |
                  (static_cast<u32>(data[2]) << 16) | (static_cast<u32>(data[3]) << 24);
  } else if (present) {
    out->enable = 1;  // present but not a DWORD: treat it as "on"
  }
  const wchar_t* names[3] = {L"ProxyServer", L"ProxyOverride", L"AutoConfigURL"};
  for (int i = 0; i < 3; ++i) {
    if (!reg_read(key, names[i], &present, &type, &data, error)) return false;
    std::string value;
    if (present && data.size() >= sizeof(wchar_t)) {
      const std::wstring wide(reinterpret_cast<const wchar_t*>(data.data()),
                              data.size() / sizeof(wchar_t));
      value = to_utf8(wide);
      while (!value.empty() && value.back() == '\0') value.pop_back();
    }
    if (i == 0) {
      out->server_present = present;
      out->server = value;
    } else if (i == 1) {
      out->override_present = present;
      out->override_list = value;
    } else {
      out->auto_config_present = present;
      out->auto_config_url = value;
    }
  }
  return true;
}

bool write_string(HKEY key, const wchar_t* name, const std::string& value, std::string* error) {
  const std::wstring wide = to_wide(value);
  const DWORD bytes = static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t));
  const LONG rc = RegSetValueExW(key, name, 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(wide.c_str()), bytes);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegSetValueEx", rc);
    return false;
  }
  return true;
}

bool write_dword(HKEY key, const wchar_t* name, DWORD value, std::string* error) {
  const LONG rc = RegSetValueExW(key, name, 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&value), sizeof(value));
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegSetValueEx", rc);
    return false;
  }
  return true;
}

bool delete_value(HKEY key, const wchar_t* name, std::string* error) {
  const LONG rc = RegDeleteValueW(key, name);
  if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
    if (error) *error = win_error_text("RegDeleteValue", rc);
    return false;
  }
  return true;
}

}  // namespace

bool system_proxy_available(std::string* note) {
  HKEY key = nullptr;
  std::string error;
  if (!reg_open_read(&key, &error)) {
    if (note) *note = error;
    return false;
  }
  RegCloseKey(key);
  if (note) {
    *note = "HKCU Internet Settings (the WinINET system proxy used by Edge, Chrome and "
            "anything else that reads the system settings)";
  }
  return true;
}

std::string system_proxy_note() {
  return "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings + "
         "InternetSetOption(INTERNET_OPTION_SETTINGS_CHANGED)";
}

bool system_proxy_read(SystemProxyState* out, std::string* error) {
  if (out == nullptr) {
    if (error) *error = "no destination for the system proxy settings";
    return false;
  }
  HKEY key = nullptr;
  if (!reg_open_read(&key, error)) return false;
  const bool ok = read_state(key, out, error);
  RegCloseKey(key);
  return ok;
}

bool system_proxy_apply(const SystemProxyState& want, std::string* error) {
  HKEY key = nullptr;
  if (!reg_open_write(&key, error)) return false;
  bool ok = true;
  if (want.enable_present) {
    ok = write_dword(key, L"ProxyEnable", want.enable != 0 ? 1u : 0u, error);
  } else {
    ok = delete_value(key, L"ProxyEnable", error);
  }
  if (ok) {
    if (want.server_present) {
      ok = write_string(key, L"ProxyServer", want.server, error);
    } else {
      ok = delete_value(key, L"ProxyServer", error);
    }
  }
  if (ok) {
    if (want.override_present) {
      ok = write_string(key, L"ProxyOverride", want.override_list, error);
    } else {
      ok = delete_value(key, L"ProxyOverride", error);
    }
  }
  if (ok) {
    // An auto-config (PAC) script wins over a manual proxy, so it is always
    // removed while we hold the setting - and put back by a restore.
    if (want.auto_config_present) {
      ok = write_string(key, L"AutoConfigURL", want.auto_config_url, error);
    } else {
      ok = delete_value(key, L"AutoConfigURL", error);
    }
  }
  RegCloseKey(key);
  if (!ok) return false;
  notify_wininet();
  return true;
}

bool system_proxy_enable(const std::string& server, const std::string& bypass,
                         const std::string& state_path, SystemProxyState* saved,
                         std::string* error) {
  SystemProxyState live;
  if (!system_proxy_read(&live, error)) return false;
  SystemProxyState previous = live;
  if (system_proxy_snapshot_exists(state_path)) {
    // A previous run was killed before it could restore.  Its snapshot holds
    // the real original values, so keep that file instead of overwriting it
    // with the settings we are about to replace.
    if (!system_proxy_snapshot_load(state_path, &previous, error)) {
      if (error) *error = "there is already a snapshot at '" + state_path + "': " + *error;
      return false;
    }
  } else if (!system_proxy_snapshot_write(live, state_path, error)) {
    // Nothing has been changed yet: a failed snapshot leaves the machine alone.
    return false;
  }
  SystemProxyState want;
  want.enable_present = true;
  want.enable = 1;
  want.server_present = true;
  want.server = server;
  want.override_present = true;
  want.override_list = bypass.empty() ? "<local>" : bypass;
  want.auto_config_present = false;
  if (!system_proxy_apply(want, error)) return false;
  if (saved != nullptr) *saved = previous;
  return true;
}

bool system_proxy_restore(const std::string& state_path, SystemProxyState* restored,
                          bool* had_snapshot, std::string* error) {
  if (had_snapshot != nullptr) *had_snapshot = false;
  if (!system_proxy_snapshot_exists(state_path)) return true;
  SystemProxyState previous;
  if (!system_proxy_snapshot_load(state_path, &previous, error)) return false;
  if (!system_proxy_apply(previous, error)) return false;
  if (restored != nullptr) *restored = previous;
  if (had_snapshot != nullptr) *had_snapshot = true;
  system_proxy_snapshot_remove(state_path);
  return true;
}

bool system_proxy_active(const std::string& server) {
  SystemProxyState live;
  std::string error;
  if (!system_proxy_read(&live, &error)) return false;
  if (!live.enabled()) return false;
  if (live.server.empty()) return false;
  const std::string needle = to_lower(trim_copy(server));
  const std::string haystack = to_lower(live.server);
  if (haystack == needle) return true;
  std::size_t at = 0;
  while (at <= haystack.size()) {
    const std::size_t semi = haystack.find(';', at);
    const std::string token = haystack.substr(at, semi == std::string::npos ? std::string::npos
                                                                           : semi - at);
    const std::size_t eq = token.find('=');
    const std::string value = trim_copy(eq == std::string::npos ? token : token.substr(eq + 1));
    if (!value.empty() && value == needle) return true;
    if (semi == std::string::npos) break;
    at = semi + 1;
  }
  return false;
}

#else  // !_WIN32

bool system_proxy_available(std::string* note) {
  if (note) {
    *note = "the system proxy is only implemented on Windows (HKCU Internet Settings)";
  }
  return false;
}

std::string system_proxy_note() { return "not available on this platform"; }

bool system_proxy_read(SystemProxyState* out, std::string* error) {
  if (out != nullptr) *out = SystemProxyState();
  if (error) {
    *error = "the system proxy is only implemented on Windows (HKCU Internet Settings)";
  }
  return false;
}

bool system_proxy_apply(const SystemProxyState& want, std::string* error) {
  (void)want;
  if (error) {
    *error = "the system proxy is only implemented on Windows (HKCU Internet Settings)";
  }
  return false;
}

bool system_proxy_enable(const std::string& server, const std::string& bypass,
                         const std::string& state_path, SystemProxyState* saved,
                         std::string* error) {
  (void)server;
  (void)bypass;
  (void)state_path;
  (void)saved;
  if (error) {
    *error = "the system proxy is only implemented on Windows (HKCU Internet Settings)";
  }
  return false;
}

bool system_proxy_restore(const std::string& state_path, SystemProxyState* restored,
                          bool* had_snapshot, std::string* error) {
  (void)state_path;
  (void)restored;
  if (had_snapshot != nullptr) *had_snapshot = false;
  if (error) {
    *error = "the system proxy is only implemented on Windows (HKCU Internet Settings)";
  }
  return false;
}

bool system_proxy_active(const std::string& server) {
  (void)server;
  return false;
}

#endif  // _WIN32

std::string system_proxy_help() {
  return
      "System proxy takeover (filter without configuring anything):\n"
      "  --system-proxy on      point this user's system proxy at the --serve endpoint\n"
      "                         while netcap runs, and put the previous settings back\n"
      "                         on exit; HKCU only, no Administrator rights\n"
      "  --system-proxy off     switch the system proxy off (the snapshot stays, so a\n"
      "                         later 'restore' still puts the original back)\n"
      "  --system-proxy restore put the snapshot back and delete it; run this after a\n"
      "                         crash, or whenever the proxy looks stuck\n"
      "  --system-proxy status  print the live settings and whether a snapshot exists\n"
      "  --system-proxy-bypass <list>\n"
      "                         ProxyOverride written while taken over (default <local>)\n"
      "  --system-proxy-state <file>\n"
      "                         where the previous settings are saved (default\n"
      "                         netcap_sysproxy.state in the working directory)\n"
      "  --system-proxy-help    this text\n"
      "\n"
      "  Edge, Chrome and everything else that reads the system settings follow this\n"
      "  without being told.  Programs with their own proxy setting - Firefox with a\n"
      "  manual configuration, most games, anything that only uses WinHTTP - do not.\n"
      "  Example:  netcap --rules easylist.txt --serve 8080 --system-proxy on\n";
}

std::string system_proxy_report() {  std::ostringstream out;
  out << "platform            : " << system_proxy_note() << "\n";
  std::string note;
  const bool available = system_proxy_available(&note);
  out << "available           : " << (available ? "yes" : "no") << "\n";
  if (!note.empty()) out << "note                : " << note << "\n";
  SystemProxyState live;
  std::string error;
  if (system_proxy_read(&live, &error)) {
    out << "ProxyEnable         : " << (live.enable_present ? (live.enabled() ? "1" : "0")
                                                           : "(absent)") << "\n";
    out << "ProxyServer         : "
        << (live.server_present ? (live.server.empty() ? "(empty)" : live.server) : "(absent)")
        << "\n";
    out << "ProxyOverride       : "
        << (live.override_present
                ? (live.override_list.empty() ? "(empty)" : live.override_list)
                : "(absent)")
        << "\n";
    out << "AutoConfigURL       : "
        << (live.auto_config_present
                ? (live.auto_config_url.empty() ? "(empty)" : live.auto_config_url)
                : "(absent)")
        << "\n";
    out << "current             : " << live.describe() << "\n";
  } else {
    out << "current             : unreadable (" << error << ")\n";
  }
  return out.str();
}

// ---------------------------------------------------------------- chaining
//
// Taking the system proxy over is only safe when the traffic that used to go
// through somebody else's proxy can still do so: netcap becomes the new first
// hop and chains to the old one.  These helpers find that old one and check
// that it is really there - the mistake that cut this machine off the network
// was taking over with *nothing* behind us.

bool system_proxy_upstream_from_server(const std::string& server, std::string* upstream,
                                       std::string* error) {
  if (upstream != nullptr) upstream->clear();
  std::vector<std::string> entries;
  std::size_t start = 0;
  for (;;) {
    const std::size_t semi = server.find(';', start);
    const std::string piece =
        trim_copy(server.substr(start, semi == std::string::npos ? std::string::npos : semi - start));
    if (!piece.empty()) entries.push_back(piece);
    if (semi == std::string::npos) break;
    start = semi + 1;
  }
  bool saw_socks = false;
  for (const std::string& entry : entries) {
    const std::size_t eq = entry.find('=');
    const std::string scheme = eq == std::string::npos ? std::string() : trim_copy(entry.substr(0, eq));
    const std::string value = eq == std::string::npos ? entry : trim_copy(entry.substr(eq + 1));
    if (!scheme.empty() && scheme != "http" && scheme != "https") {
      if (scheme == "socks" || scheme == "socks4" || scheme == "socks5") saw_socks = true;
      continue;
    }
    u16 port = 0;
    std::string normalized;
    std::string why;
    if (!system_proxy_endpoint_ok(value, &port, &normalized, &why)) continue;
    if (port == 0) continue;
    if (upstream != nullptr) *upstream = normalized;
    return true;
  }
  if (error != nullptr) {
    *error = saw_socks ? "the configured proxy is SOCKS-only, which netcap cannot chain through"
                       : "no usable HTTP proxy in '" + server + "'";
  }
  return false;
}

std::vector<std::string> system_proxy_candidate_upstreams(const SystemProxyState& state) {
  std::vector<std::string> out;
  if (state.server_present && !state.server.empty()) {
    std::string from_state;
    std::string why;
    if (system_proxy_upstream_from_server(state.server, &from_state, &why)) out.push_back(from_state);
  }
  // The ports local proxies listen on in practice: Clash (7890/7891/7897),
  // v2rayN (10809/10808), a SOCKS/HTTP mix (1080), Fiddler (8888).
  static const char* const kWellKnown[] = {"127.0.0.1:7890", "127.0.0.1:7897", "127.0.0.1:7891",
                                           "127.0.0.1:10809", "127.0.0.1:1080", "127.0.0.1:10808",
                                           "127.0.0.1:8888"};
  for (const char* candidate : kWellKnown) {
    if (std::find(out.begin(), out.end(), std::string(candidate)) == out.end()) {
      out.push_back(candidate);
    }
  }
  return out;
}

#if defined(_WIN32)
using probe_socket_t = SOCKET;
const probe_socket_t kProbeBadSocket = INVALID_SOCKET;
void probe_close(probe_socket_t s) { ::closesocket(s); }
bool probe_set_nonblocking(probe_socket_t s) {
  u_long mode = 1;
  return ::ioctlsocket(s, FIONBIO, &mode) == 0;
}
#else
using probe_socket_t = int;
const probe_socket_t kProbeBadSocket = -1;
void probe_close(probe_socket_t s) { ::close(s); }
bool probe_set_nonblocking(probe_socket_t s) {
  const int flags = ::fcntl(s, F_GETFL, 0);
  return flags >= 0 && ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
}
#endif

bool system_proxy_probe(const std::string& endpoint, int timeout_ms, std::string* error) {
  if (error != nullptr) error->clear();
  u16 port = 0;
  std::string normalized;
  std::string why;
  if (!system_proxy_endpoint_ok(endpoint, &port, &normalized, &why)) {
    if (error != nullptr) *error = why;
    return false;
  }
  if (port == 0) {
    if (error != nullptr) *error = "'" + endpoint + "' has no port";
    return false;
  }
  std::string host = normalized;
  const std::size_t colon = host.rfind(':');
  if (colon == std::string::npos) {
    if (error != nullptr) *error = "'" + endpoint + "' has no port";
    return false;
  }
  host = host.substr(0, colon);
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
    host = host.substr(1, host.size() - 2);
  }
  if (host.empty()) {
    if (error != nullptr) *error = "'" + endpoint + "' has no host";
    return false;
  }
#if defined(_WIN32)
  // WSAStartup is reference counted, so a probe from a process that already
  // captured packets is harmless.
  WSADATA wsa;
  const bool wsa_ok = ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
  if (!wsa_ok) {
    if (error != nullptr) *error = "Winsock is not available";
    return false;
  }
#endif
  addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* list = nullptr;
  const std::string service = std::to_string(port);
  if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &list) != 0 || list == nullptr) {
    if (error != nullptr) *error = "cannot resolve " + host;
#if defined(_WIN32)
    ::WSACleanup();
#endif
    return false;
  }
  bool ok = false;
  for (addrinfo* it = list; it != nullptr && !ok; it = it->ai_next) {
    const probe_socket_t s = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
    if (s == kProbeBadSocket) continue;
    if (probe_set_nonblocking(s)) {
      const int rc = ::connect(s, it->ai_addr, static_cast<int>(it->ai_addrlen));
      if (rc == 0) {
        ok = true;
      } else {
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(s, &writable);
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (::select(0, nullptr, &writable, nullptr, &tv) > 0) {
          int so_error = 0;
#if defined(_WIN32)
          int len = static_cast<int>(sizeof(so_error));
#else
          socklen_t len = sizeof(so_error);
#endif
          if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) == 0) {
            ok = so_error == 0;
          }
        }
      }
    }
    probe_close(s);
  }
  ::freeaddrinfo(list);
#if defined(_WIN32)
  ::WSACleanup();
#endif
  if (!ok && error != nullptr && error->empty()) {
    *error = "nothing answered on " + normalized + " within " + std::to_string(timeout_ms) + " ms";
  }
  return ok;
}

}  // namespace netcap
