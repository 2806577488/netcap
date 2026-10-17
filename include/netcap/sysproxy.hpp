// System proxy takeover ("zero configuration" mode).
//
// Everything else in netcap is a listener: the operator has to point a browser
// at it.  AdGuard and friends do not need that because they install a kernel
// driver that redirects traffic.  We cannot ship a driver, so the honest
// middle ground is to publish our own endpoint as the *current user's* system
// proxy while we run, and to put the previous settings back afterwards.
//
// The rules that make this safe:
//   * only HKEY_CURRENT_USER is touched - never machine-wide policy, and no
//     Administrator rights are needed;
//   * the previous settings are written to a snapshot file *before* the
//     registry is modified, so a failed write leaves the machine untouched;
//   * the snapshot file is only created when it does not exist yet: if a
//     previous run was killed, the original values survive and are the ones
//     that get restored;
//   * restoring deletes the snapshot, so "restore" is idempotent and a second
//     call reports that there is nothing left to do.

#ifndef NETCAP_SYSPROXY_HPP
#define NETCAP_SYSPROXY_HPP

#include <string>

#include "netcap/common.hpp"

namespace netcap {

// The four Internet Settings values that decide how WinINET (and therefore
// Edge, Chrome and anything else that uses the system proxy) reaches the
// network.  `present` distinguishes "the value is absent" from "the value is
// an empty string" - restoring an empty string where nothing existed before
// would leave a stray value behind.
struct SystemProxyState {
  bool enable_present = false;
  u32 enable = 0;
  bool server_present = false;
  std::string server;
  bool override_present = false;
  std::string override_list;
  bool auto_config_present = false;
  std::string auto_config_url;

  bool enabled() const { return enable_present && enable != 0; }
  std::string describe() const;
};

// ---------------------------------------------------------------- portable
//
// Line based snapshot text, so the format can be diffed, copied and unit
// tested without touching a registry:
//
//     netcap-system-proxy 1
//     proxy_enable=1
//     proxy_server=http=127.0.0.1:8080;https=127.0.0.1:8080
//     !proxy_override
//     auto_config_url=
//
// A line starting with '!' means "this value was absent".  Values are escaped
// (\n, \r, \t, \\) so a single line stays a single line.
std::string system_proxy_snapshot_text(const SystemProxyState& state);
bool system_proxy_snapshot_parse(const std::string& text, SystemProxyState* out, std::string* error);

bool system_proxy_snapshot_write(const SystemProxyState& state, const std::string& path,
                                 std::string* error);
bool system_proxy_snapshot_load(const std::string& path, SystemProxyState* out, std::string* error);
bool system_proxy_snapshot_exists(const std::string& path);
bool system_proxy_snapshot_remove(const std::string& path);

// Accepts "host:port", "[::1]:port" and a bare "host".  When no port is given
// `*port` is set to 0.  `*normalized` gets a cleaned up copy of the input.
bool system_proxy_endpoint_ok(const std::string& server, u16* port, std::string* normalized,
                              std::string* error);

// Picks a usable "host:port" out of a ProxyServer value.  WinINET accepts a
// per-scheme list ("http=127.0.0.1:7890;https=127.0.0.1:7890"), so the first
// HTTP-capable entry wins and the scheme prefix is dropped.  This is how a
// takeover keeps chaining through whatever proxy was already in place; a
// SOCKS-only value is reported as an error because netcap can only chain HTTP.
bool system_proxy_upstream_from_server(const std::string& server, std::string* upstream,
                                       std::string* error);

// Candidate chaining targets, best first: the configured proxy (when there is
// one), then the ports local proxies usually listen on.  The caller is expected
// to probe them with system_proxy_probe() and refuse to take the system proxy
// over when none answers - a takeover without a working upstream is exactly
// what cuts a machine off the network.
std::vector<std::string> system_proxy_candidate_upstreams(const SystemProxyState& state);

// True when something accepts a TCP connection on that endpoint within
// `timeout_ms`.  Never sends a byte: this is a liveness probe, not a request.
bool system_proxy_probe(const std::string& endpoint, int timeout_ms, std::string* error);

// The bypass list a takeover should actually publish.  When the machine has a
// usable global IPv6 address the operator's list is passed through untouched.
// When it does not, the Windows IPv6 connectivity probe (`ipv6.msftncsi.com`,
// AAAA records only) is appended and sent direct: it can never answer here, and
// letting the proxy fail it turns "this machine has no IPv6" into a 502 from us
// that reads as "the proxy broke the network".  An empty list becomes the
// `<local>` a takeover would have used anyway.  Pure, so it is unit tested.
std::string system_proxy_bypass_auto(const std::string& base, bool machine_has_ipv6);

// ---------------------------------------------------------------- platform
bool system_proxy_available(std::string* note);
std::string system_proxy_note();

// Reads the live settings.  Read-only: used for status output and as the
// snapshot source.
bool system_proxy_read(SystemProxyState* out, std::string* error);

// Writes the given settings and tells WinINET to re-read them.
bool system_proxy_apply(const SystemProxyState& want, std::string* error);

// Takes the system proxy over.  Returns the settings that were in place (the
// ones `system_proxy_restore` will put back).
bool system_proxy_enable(const std::string& server, const std::string& bypass,
                         const std::string& state_path, SystemProxyState* saved, std::string* error);

// Puts the snapshot back and deletes it.  `*had_snapshot` reports whether
// there was anything to restore.
bool system_proxy_restore(const std::string& state_path, SystemProxyState* restored,
                          bool* had_snapshot, std::string* error);

// True when the registry currently points at `server` with ProxyEnable set.
bool system_proxy_active(const std::string& server);

// Convenience: the printout the CLI shows for `--system-proxy status`.
std::string system_proxy_report();

// The `--system-proxy-help` text.
std::string system_proxy_help();

}  // namespace netcap

#endif  // NETCAP_SYSPROXY_HPP
