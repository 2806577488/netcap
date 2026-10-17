// netcap - command line front end.
//
//   netcap --devices
//   netcap -i "Ethernet" -f "tcp and dst port 443"
//   netcap --selftest
//   netcap --generate-sample sample.pcap
//   netcap -r sample.pcap -f "tls and hostname example.com" -v
#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>   // _O_BINARY
#include <io.h>      // _setmode, _fileno
#include <windows.h>
#endif

#include "netcap/analyze.hpp"
#include "netcap/app.hpp"
#include "netcap/capture.hpp"
#include "netcap/common.hpp"
#include "netcap/dissect.hpp"
#include "netcap/filter.hpp"
#include "netcap/packet.hpp"
#include "netcap/pcap.hpp"
#include "netcap/selftest.hpp"

#include "netcap/block.hpp"
#include "netcap/proc.hpp"
#include "netcap/proxy.hpp"
#include "netcap/rules.hpp"
#include "netcap/blocker.hpp"
#include "netcap/origin.hpp"
#include "netcap/hosts.hpp"
#include "netcap/dnssink.hpp"
#include "netcap/wfp.hpp"
#include "netcap/sysproxy.hpp"
#include "netcap/sysenv.hpp"
#include "netcap/tun.hpp"
#include "netcap/tunpipe.hpp"
#include "netcap/quickeys.hpp"
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>
#include "netcap/split.hpp"
#include "netcap/x509.hpp"

namespace netcap {

namespace {

// The bridge between the browser's key log and the tunnel's QUIC inspection.
// Only this file knows where the log is (`--quic-keys`, or the path netcap itself
// put into SSLKEYLOGFILE), so `tunpipe` sees nothing but the interface below.
class QuicKeyLogProvider : public QuicKeysProvider {
 public:
  explicit QuicKeyLogProvider(std::string path) : path_(std::move(path)) {}

  bool keys_for(const Bytes& original_dcid, u16* suite, QuicKeyset* client, QuicKeyset* server,
                std::string* why) override {
    if (path_.empty()) {
      if (why != nullptr) *why = "no key log is configured";
      return false;
    }
    // The browser appends while we run, so re-read now and then: a connection that
    // is not in the log yet may be there a moment later.
    const i64 now = now_monotonic_us();
    if (now - last_read_us_ > kRefreshUs) {
      last_read_us_ = now;
      std::string error;
      if (!log_.refresh(path_, &error)) {
        if (why != nullptr) *why = error;
        return false;
      }
    }
    if (log_.find(original_dcid).empty()) {
      if (why != nullptr) *why = "this connection id is not in the key log";
      return false;
    }
    u16 picked = 0;
    if (!quic_keysets_from_keylog(log_, original_dcid, &picked, client, server, why)) return false;
    if (suite != nullptr) *suite = picked;
    return true;
  }

 private:
  static constexpr i64 kRefreshUs = 2 * 1000 * 1000;
  std::string path_;
  QuicKeyLog log_;
  i64 last_read_us_ = 0;
};

const char* kVersion = "netcap 1.0";

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

struct Options {
  bool list_devices = false;
  bool list_processes = false;  // --list-processes: running programs, as JSONL
  bool show_help = false;
  bool show_version = false;
  bool selftest = false;
  bool filter_help = false;
  bool numeric = false;
  bool hex_payload = false;
  bool hex_frame = false;
  bool ascii_payload = false;
  bool verbose = false;
  bool quiet = false;
  bool no_promisc = false;
  bool nanosecond = false;
  bool show_stats = false;
  bool json = false;
  bool show_streams = false;
  bool show_http = false;
  bool follow = false;
  bool no_reassembly = false;
  bool attrib = false;      // attribute packets to processes even for file input
  bool no_attrib = false;   // never read the OS endpoint table
  bool no_proxy = false;    // never correlate a local proxy with its clients
  std::string split_by;     // "", "proc", "app" or "origin": one output file per key
  std::string block_filter; // when set, matching traffic is intercepted
  std::string block_mode = "cut";  // dry-run | cut | kill | both
  long block_max = 32;      // 0 = no cap
  bool block_mode_set = false;  // --block-mode was given (it defaults to "cut")
  std::string keylog;
  std::string rules_path;        // --rules: an Adblock / hosts filter list
  std::vector<std::string> rules_extra;  // --rules-extra: more lists on top (repeatable);
                                         // the interface keeps the user's own rules here
  bool rules_check = false;      // --rules-check: parse the list, report and exit
  std::string check_rule;        // --check-rule <line>: validate one rule line and exit
  bool check_rule_set = false;
  std::string hosts_path;        // --hosts [file]: the hosts file to block names in
  bool hosts_set = false;
  bool hosts_apply = false;      // --hosts-apply: actually write it (default is a dry run)
  bool rules_help = false;       // --rules-help: print the supported syntax
  std::string serve;             // --serve [addr:]port: run the interception proxy
  bool serve_set = false;
  std::string stub_body;         // --stub: body served for a blocked document
  bool third_party_cookies = false;  // --third-party-cookies: strip third-party Cookie
  bool show_blocks = false;      // --show-blocks: also list decisions that were not needed
  std::string log_file;          // --log-file: append every decision to this file as JSON Lines
  bool picker = false;           // --picker: inject the element picker into every document
  std::string picker_rules;      // --picker-rules: the list a pick appends its rule to
  std::string picker_flag;       // --picker-flag: picking is on while this file exists
  bool no_procedural = false;    // --no-procedural: do not run the page's cosmetic engine
  bool log_file_set = false;
  // Internal: where a browser is told to write its TLS/QUIC session secrets.
  // Only a TUN takeover needs it (a proxy never sees UDP), and it is not a
  // feature the user manages -- see the QUIC section of the README.
  std::string quic_keys;
  bool mitm = false;             // --mitm: decrypt CONNECT tunnels with a local CA
  bool mitm_insecure = false;    // --mitm-insecure: forward to origins we cannot verify
  std::string mitm_skip;         // --mitm-skip: applications that keep a plain tunnel
  std::string mitm_only;         // --mitm-only: the only applications to decrypt
  bool mitm_strict = false;      // --mitm-strict: never tunnel because the client refused our CA
  std::string origin_policy = "best";  // --origin-policy first|best (multi-address hosts)
  int origin_race = 2;           // --origin-race: addresses started before one answers
  int origin_ttl = 300;          // --origin-ttl: seconds before a host is re-measured
  std::string ca_prefix = "netcap-ca";  // --ca: base path of the certificate + key
  bool ca_init = false;          // --ca-init: create the CA files and exit
  bool ca_show = false;          // --ca-show: print the CA fingerprint and where it lives
  std::vector<std::string> wfp_specs;  // --wfp <spec>: WFP block filters to install
  bool wfp_apply = false;              // --wfp-apply: really install them
  bool wfp_wait = false;               // --wfp-wait: hold them until Ctrl+C
  bool wfp_help = false;               // --wfp-help
  // --system-proxy on|off|restore|status: publish the --serve endpoint as this
  // user's system proxy (and put the previous settings back afterwards).
  int system_proxy = 0;
  std::string system_proxy_bypass;  // --system-proxy-bypass <list>
  std::string system_proxy_state;   // --system-proxy-state <file>
  bool system_proxy_help = false;   // --system-proxy-help
  // Upstream HTTP proxy every connection is chained through ("host:port").
  // Required for a safe system-proxy takeover on a machine that already
  // reaches the network through a local proxy.
  std::string upstream;             // --upstream <host:port>
  bool system_proxy_force = false;  // --system-proxy-force
  // TUN mode (--tun): a Wintun adapter owned by this process, so no program has
  // to be told about a proxy.  The --tun-* options describe that adapter;
  // --tun-takeover points the default route at it.
  bool tun_set = false;       // --tun
  std::string tun_name;       // --tun-name <name>
  std::string tun_address;    // --tun-address <addr/prefix>
  unsigned int tun_mtu = 0;   // --tun-mtu <n> (0 means 1500)
  int tun_hold = 0;           // --tun-hold <seconds> (diagnostic: keep the adapter open)
  bool tun_takeover = false;  // --tun-takeover
  int tun_seconds = 0;        // --tun-seconds <n>, 0 = until Ctrl+C
  bool tun_check = false;     // --tun-check
  bool tun_help = false;      // --tun-help
  std::string tun_restore;    // --tun-restore <file>
  std::string tun_dll;        // --tun-dll <path>
  std::string dns_bind;          // --dns [addr:]port: run the DNS sink hole here
  bool dns_set = false;
  std::string dns_upstream;      // --dns-upstream <ip[:port]>
  std::string device;
  std::vector<std::string> extra_devices;  // -i given more than once
  bool with_tunnel = false;                // append up tunnel adapters (TAP/TUN)
  std::string read_path;
  std::string write_path;
  std::string filter;
  std::string generate_sample;
  long count = 0;
  int snaplen = 262144;
  int timeout_ms = 1000;
};

// Extra help for the multi-interface / tunnel switches.  Written as a raw string
// literal so the text itself needs no escaping.
void print_tunnel_usage(std::FILE* out) {
  std::fprintf(out, R"(
Multi-interface and tunnel capture:
  -i may be repeated.  The first interface is required; the rest are opened
  alongside it.  '-i all' opens every interface that is up with an IPv4 address.
  --with-tunnel also opens every up TAP/TUN/VPN adapter.  That is how a TUN-mode
  proxy reveals the programs behind it: packets inside the tunnel still carry the
  original five-tuple, so attribution lands on the real client, not on the proxy.
  Example:  netcap -i all --with-tunnel --attrib -f "proc chrome"
)");
}

// Help for the rule list and the interception proxy, written as a raw string
// literal so the text itself needs no escaping.
void print_rules_usage(std::FILE* out) {
  std::fprintf(out, R"(
Rule lists and the interception proxy:
  --rules <file>        load an Adblock/uBlock list or a hosts file
  --rules-extra <file>  load another list on top of --rules (repeatable); the interface keeps
                        the user's own rules in a small file and passes it here
  --picker              inject the element picker into every document: click an element on the page
                        and it is hidden from then on (the rule is appended to --picker-rules)
  --picker-rules <file> the list a pick appends its rule to
  --picker-flag <file>  picking is on while this file exists; the interface creates and deletes it,
                        which lets picking be switched without restarting the proxy
  --no-procedural       do not ship the cosmetic engine: `#?#`, `:has()`, `:upward()` and
                        `{ remove: true; }` rules are then read and counted but never applied
  --rules-check         parse --rules, report what was understood and what was skipped, then exit
  --check-rule <line>   validate one rule line: exits 0 for a comment, a network rule or an
                        element hiding rule, and 1 with the reason for anything rejected
  --rules-help          print the rule syntax this program understands
  --serve [addr:]port   run the local interception proxy (default 127.0.0.1:8080)
  --mitm                decrypt HTTPS through the proxy with a local CA, so rules see the
                        full URL; needs a CA first (see --ca-init)
  --mitm-insecure       with --mitm, also forward to origins whose certificate cannot be
                        verified (off by default: an unverifiable origin is refused)
  --mitm-skip <list>    with --mitm, keep a plain tunnel for these applications, so their
                        HTTPS is never decrypted (comma or pipe separated, matched
                        case-insensitively against the image name or path, e.g.
                        --mitm-skip "bank.exe,pinapp")
  --mitm-only <list>    decrypt HTTPS only for these applications (also loads the CA when
                        --mitm is off), e.g. --mitm-only msedge.exe
  --mitm-strict         do not fall back to a plain tunnel when a client refuses our
                        certificate: such connections keep failing.  By default an
                        application that will not verify the netcap CA for a host name
                        (its own trust store, certificate pinning) is remembered and that
                        pair is tunnelled without decryption, so the application keeps
                        working; the event table says when that happened
  --ca <prefix>         base name of the CA files (default: netcap-ca -> netcap-ca.crt/.key)
  --ca-init             create the CA used by --mitm, print its fingerprint and exit
  --ca-show             print the CA fingerprint, subject and paths, then exit
  --stub <html>         body served for a blocked document
  --origin-policy <m>   first|best: with 'best' (default) the addresses of a multi-address
                        origin are raced once, the fastest is remembered and dialled
                        afterwards; 'first' keeps the resolver order and never measures
  --origin-race <n>     addresses started before one of them answers (default 2, max 16)
  --origin-ttl <sec>    re-measure a host after this many seconds (default 300, 0 = never)
  --third-party-cookies strip the Cookie header from requests whose site differs
                        from the page that asked (Referer/Origin)
  --show-blocks         print every decision, not only the ones that changed something
  --log-file <path>     append every decision to <path> as JSON Lines (one object per
                        decision, the same schema as --jsonl; rotates to <path>.1 at 8 MiB).
                        The file is flushed per decision, so it survives a crash
  --hosts [file]        map the blocked names in a hosts file (default: the system one)
  --hosts-apply         really write it; without this option --hosts only prints the plan
  --dns [addr:]port     answer blocked names with 0.0.0.0 locally (default 127.0.0.1:5353)
  --dns-upstream <ip>   resolver used for everything else (default: the system resolver)
  --system-proxy <mode> on|off|restore|status|check: with 'on', point this user's system
                        proxy at the --serve endpoint while netcap runs (Edge and Chrome
                        then need no configuration at all) and put the previous settings
                        back on exit; 'restore' undoes it after a crash; 'check' prints
                        what a takeover would do and changes nothing.  HKCU only, and no
                        Administrator rights.  See --system-proxy-help.
  --system-proxy-bypass <list>  value written to the system proxy bypass list when taken
                        over (default: <local>)
  --system-proxy-state <file>  where the previous settings are kept while taken over
                        (default: netcap_sysproxy.state in the working directory)
  --upstream <host:port> chain every upstream connection through an HTTP proxy instead of
                        dialling out directly (e.g. the local Clash/other client port).
                        With --system-proxy on this is the difference between "keeps
                        working" and "cuts this machine off the network", so a takeover
                        is refused when nothing answers behind us
  --system-proxy-force  take the system proxy over even when nothing answers behind us
                        (everything then goes through netcap directly)
  --tun                 open a Wintun adapter this process owns (TUN mode): every IP
                        packet of this machine, without a proxy setting anywhere.
                        wintun.dll is loaded at run time and is never linked in;
                        creating the adapter needs administrator rights the first time
  --tun-name <name>     adapter name (default: netcap)
  --tun-address <a/n>   address assigned to the adapter (default: 10.7.0.1/24)
  --tun-mtu <n>         MTU of the adapter (default: 1500)
  --tun-takeover        point the default route at the adapter and carry every packet
                        through --rules (and --upstream, when it resolves): plain HTTP by
                        full URL, HTTPS by the SNI in the ClientHello.  Needs an upstream:
                        once the tunnel owns the default route a direct socket would loop
                        straight back into it and cut this machine off the network
  --tun-seconds <n>     stop the takeover after n seconds (0 = until Ctrl+C).  The routes
                        go back on every exit path either way
  --tun-restore <file>  put the default routes back from a snapshot file
  --tun-check           report wintun.dll, the driver version and the current routes
  --tun-help            the long TUN explanation
  --tun-dll <path>      use this wintun.dll instead of searching for one (it has to
                        be a 64-bit DLL; the loader reports why a candidate was
                        rejected, including "wrong architecture")
  --tun-hold <secs>     diagnostic: open the adapter, keep the session open for this
                        many seconds and report how many packets came out of it (a
                        Wintun interface is only visible while a session is open)
  Point the browser's HTTP proxy (or the system proxy) at the --serve endpoint: plain
  HTTP is filtered by full URL, HTTPS by host name.  Full URL filtering for HTTPS needs
  the man-in-the-middle mode (--mitm) and a CA that the browser trusts: create it with
  --ca-init and install netcap-ca.crt yourself.  netcap never touches the trust store.
  Example:  netcap --rules easylist.txt --serve 8080
  Example:  netcap --rules easylist.txt --serve 8080 --mitm
)");
}

void print_usage(std::FILE* out) {  std::fprintf(out,
               "%s - low-level network traffic capture and dissection\n"
               "\n"
               "Usage:\n"
               "  netcap [options] [filter expression]\n"
               "\n"
               "Sources:\n"
               "  -i, --interface <name|index>  capture live from an interface\n"
               "  -r, --read <file>             read packets from a pcap file ('-' = stdin)\n"
               "  -d, --devices                 list capture-capable interfaces and exit\n"
               "  -g, --generate-sample <file>  write a synthetic demo capture and exit\n"
               "\n"
               "Output:\n"
               "  -w, --write <file>            also write matching packets to a pcap file\n"
               "                                with --split-by this is a directory instead\n"
               "      --split-by <mode>         one pcap per proc / app / origin (the real\n"
               "                                program behind a local proxy)\n"
               "                                (needs -w <directory>; index.json lists them)\n"
               "      --block <filter>          intercept matching traffic (nothing happens\n"
               "                                without this option; see --block-mode)\n"
               "      --block-mode <m>          dry-run (default) | cut | kill | both\n"
               "      --block-max <n>           stop after n actions (default 32, 0 = no cap)\n"
               "                                ('-' = stdout; then the packet log goes to stderr)\n"
               "  -v, --verbose                 full field-by-field dump per packet\n"
               "  -x, --hex                     hex+ASCII dump of the transport payload\n"
               "  -X, --hex-all                 hex+ASCII dump of the whole frame\n"
               "  -A, --ascii                   printable-only ASCII dump of the payload\n"
               "  -n, --numeric                 numeric ports (no service names)\n"
               "  -q, --quiet                   no per-packet output, only the summary\n"
               "      --attrib                  attribute packets to processes (default on live captures)\n"
               "      --no-attrib               never read the OS endpoint table\n"
               "      --list-processes          print the running programs as JSONL and exit\n"
               "      --no-proxy                do not look behind a local proxy (Clash, v2ray, ...)\n"
               "      --stats                   per-application packet counters\n"
               "      --nanosecond              nanosecond timestamps in the written file\n"
               "      --jsonl                   JSON Lines on stdout (one object per packet)\n"
               "                                for graphical front ends; -d and\n"
               "                                -g honour it too\n"
               "\n"
               "Analysis:\n"
               "      --keylog <file>           SSLKEYLOGFILE secrets to decrypt TLS\n"
               "      --streams                 TCP stream report (reassembly)\n"
               "      --http                    HTTP/1.1 and HTTP/2 transactions\n"
               "      --follow                  print each transaction as it completes\n"
               "      --no-reassembly           do not reassemble TCP streams\n"
               "\n"
               "Capture:\n"
               "  -f, --filter <expr>           userspace filter (see --filter-help)\n"
               "  -c, --count <n>               stop after n matching packets\n"
               "  -s, --snaplen <n>             bytes captured per packet (default 262144)\n"
               "  -t, --timeout <ms>            blocking read timeout for live capture\n"
               "  -p, --no-promisc              do not request promiscuous mode\n"
               "\n"
               "Misc:\n"
               "      --filter-help             print the filter grammar and examples\n"
               "      --selftest                run the built-in verification suite\n"
               "  -h, --help                    this message\n"
               "      --version                 version information\n",
               kVersion);
}

bool parse_args(int argc, char** argv, Options& o, std::string* error) {
  auto need_value = [&](int& i, const char* flag) -> const char* {
    if (i + 1 >= argc) {
      *error = std::string(flag) + " requires a value";
      return nullptr;
    }
    return argv[++i];
  };

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "-h" || a == "--help") {
      o.show_help = true;
    } else if (a == "--version") {
      o.show_version = true;
    } else if (a == "-d" || a == "--devices" || a == "--list-devices") {
      o.list_devices = true;
    } else if (a == "--list-processes") {
      o.list_processes = true;
    } else if (a == "--selftest" || a == "--self-test") {
      o.selftest = true;
    } else if (a == "--filter-help") {
      o.filter_help = true;
    } else if (a == "-v" || a == "--verbose") {
      o.verbose = true;
    } else if (a == "-q" || a == "--quiet") {
      o.quiet = true;
    } else if (a == "-x" || a == "--hex") {
      o.hex_payload = true;
    } else if (a == "-X" || a == "--hex-all") {
      o.hex_frame = true;
    } else if (a == "-A" || a == "--ascii") {
      o.ascii_payload = true;
    } else if (a == "-n" || a == "--numeric") {
      o.numeric = true;
    } else if (a == "-p" || a == "--no-promisc") {
      o.no_promisc = true;
    } else if (a == "--nanosecond") {
      o.nanosecond = true;
    } else if (a == "--stats") {
      o.show_stats = true;
    } else if (a == "--json" || a == "--jsonl" || a == "--json-lines") {
      o.json = true;
    } else if (a == "--streams") {
      o.show_streams = true;
    } else if (a == "--http") {
      o.show_http = true;
    } else if (a == "--follow") {
      o.follow = true;
    } else if (a == "--no-reassembly") {
      o.no_reassembly = true;
    } else if (a == "--keylog") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.keylog = v;
    } else if (a == "--rules" || a == "--filter-list") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.rules_path = v;
    } else if (a == "--rules-extra") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.rules_extra.emplace_back(v);
    } else if (a == "--picker") {
      o.picker = true;
    } else if (a == "--no-procedural") {
      o.no_procedural = true;
    } else if (a == "--picker-rules") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.picker_rules = v;
    } else if (a == "--picker-flag") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.picker_flag = v;
    } else if (a == "--check-rule") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.check_rule = v;
      o.check_rule_set = true;
    } else if (a == "--rules-check") {
      o.rules_check = true;
    } else if (a == "--rules-help") {
      o.rules_help = true;
    } else if (a == "--stub") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.stub_body = v;
    } else if (a == "--mitm") {
      o.mitm = true;
    } else if (a == "--mitm-insecure") {
      o.mitm = true;
      o.mitm_insecure = true;
    } else if (a == "--mitm-skip" || a == "--mitm-except") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "netcap: %s needs a process name list\n", a.c_str());
        return 2;
      }
      o.mitm_skip = argv[++i];
    } else if (a == "--mitm-only") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "netcap: --mitm-only needs a process name list\n");
        return 2;
      }
      o.mitm_only = argv[++i];
    } else if (a == "--mitm-strict") {
      o.mitm = true;
      o.mitm_strict = true;
    } else if (a == "--origin-policy") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.origin_policy = v;
    } else if (a == "--origin-race") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.origin_race = static_cast<int>(std::strtol(v, nullptr, 10));
      if (o.origin_race < 1 || o.origin_race > 16) {
        std::fprintf(stderr, "netcap: --origin-race must be between 1 and 16\n");
        return 2;
      }
    } else if (a == "--origin-ttl") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.origin_ttl = static_cast<int>(std::strtol(v, nullptr, 10));
      if (o.origin_ttl < 0 || o.origin_ttl > 86400) {
        std::fprintf(stderr, "netcap: --origin-ttl must be between 0 and 86400 seconds\n");
        return 2;
      }
    } else if (a == "--ca") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.ca_prefix = v;
    } else if (a == "--ca-init") {
      o.ca_init = true;
    } else if (a == "--ca-show") {
      o.ca_show = true;
    } else if (a == "--dns") {
      // Optional endpoint, like --serve: --dns, --dns 5353 or --dns 127.0.0.1:53
      o.dns_set = true;
      o.dns_bind = "127.0.0.1:5353";
      if (i + 1 < argc) {
        const std::string next = argv[i + 1];
        bool looks_like_endpoint = !next.empty();
        for (char ch : next) {
          if (!(ch == ':' || ch == '.' || (ch >= '0' && ch <= '9'))) looks_like_endpoint = false;
        }
        if (looks_like_endpoint) {
          o.dns_bind = next;
          ++i;
        }
      }
    } else if (a == "--dns-upstream") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.dns_upstream = v;
    } else if (a == "--wfp") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.wfp_specs.push_back(v);
    } else if (a == "--wfp-apply") {
      o.wfp_apply = true;
    } else if (a == "--wfp-wait") {
      // Waiting only makes sense for filters that were really installed.
      o.wfp_apply = true;
      o.wfp_wait = true;
    } else if (a == "--wfp-help") {
      o.wfp_help = true;
    } else if (a == "--system-proxy") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      const std::string mode = to_lower(v);
      if (mode == "on") {
        o.system_proxy = 1;
      } else if (mode == "off") {
        o.system_proxy = 2;
      } else if (mode == "restore") {
        o.system_proxy = 3;
      } else if (mode == "status") {
        o.system_proxy = 4;
      } else if (mode == "check") {
        // Decides and prints what a takeover would chain through, without
        // touching the registry.
        o.system_proxy = 5;
      } else {
        std::fprintf(stderr,
                     "netcap: --system-proxy wants on, off, restore, status or check (got '%s')\n",
                     v);
        return 2;
      }
    } else if (a == "--system-proxy-bypass") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.system_proxy_bypass = v;
    } else if (a == "--system-proxy-state") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.system_proxy_state = v;
    } else if (a == "--upstream") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.upstream = v;
    } else if (a == "--system-proxy-force") {
      o.system_proxy_force = true;
    } else if (a == "--system-proxy-help") {
      o.system_proxy_help = true;
    } else if (a == "--tun") {
      o.tun_set = true;
    } else if (a == "--tun-name") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.tun_name = v;
    } else if (a == "--tun-address") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.tun_address = v;
    } else if (a == "--tun-mtu") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      char* end = nullptr;
      const unsigned long parsed = std::strtoul(v, &end, 10);
      if (end == v || *end != '\0' || parsed < 576 || parsed > 65535) {
        std::fprintf(stderr, "netcap: --tun-mtu wants a number between 576 and 65535 (got '%s')\n",
                     v);
        return false;
      }
      o.tun_mtu = static_cast<unsigned int>(parsed);
    } else if (a == "--tun-hold") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      char* end = nullptr;
      const long parsed = std::strtol(v, &end, 10);
      if (end == v || *end != '\0' || parsed < 0 || parsed > 3600) {
        std::fprintf(stderr, "netcap: --tun-hold wants a number of seconds between 0 and 3600\n");
        return false;
      }
      o.tun_hold = static_cast<int>(parsed);
    } else if (a == "--tun-takeover") {
      o.tun_takeover = true;
    } else if (a == "--tun-seconds") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      char* end = nullptr;
      const long parsed = std::strtol(v, &end, 10);
      if (end == v || *end != '\0' || parsed < 0 || parsed > 3600) {
        std::fprintf(stderr, "netcap: --tun-seconds wants a number of seconds between 0 and 3600\n");
        return false;
      }
      o.tun_seconds = static_cast<int>(parsed);
    } else if (a == "--tun-check") {
      o.tun_check = true;
    } else if (a == "--tun-help") {
      o.tun_help = true;
    } else if (a == "--tun-restore") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.tun_restore = v;
    } else if (a == "--tun-dll") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.tun_dll = v;
    } else if (a == "--hosts") {
      // The path is optional: --hosts uses the system hosts file, --hosts <file>
      // works on a copy, which is the only sane way to try it from a test.
      o.hosts_set = true;
      o.hosts_path = platform_hosts_path();
      if (i + 1 < argc) {
        const std::string next = argv[i + 1];
        if (!next.empty() && next[0] != '-') {
          o.hosts_path = next;
          ++i;
        }
      }
    } else if (a == "--hosts-apply") {
      o.hosts_set = true;
      o.hosts_apply = true;
      if (o.hosts_path.empty()) o.hosts_path = platform_hosts_path();
    } else if (a == "--show-blocks") {
      o.show_blocks = true;
    } else if (a == "--quic-keys" && i + 1 < argc) {
      o.quic_keys = argv[++i];
    } else if (a == "--log-file" && i + 1 < argc) {
      o.log_file = argv[++i];
      o.log_file_set = true;
    } else if (a == "--third-party-cookies" || a == "--block-third-party-cookies") {
      o.third_party_cookies = true;
    } else if (a == "--serve" || a == "--proxy") {
      // The endpoint is optional: --serve, --serve 8080 or --serve 127.0.0.1:8080
      o.serve_set = true;
      o.serve = "127.0.0.1:8080";
      if (i + 1 < argc) {
        const std::string next = argv[i + 1];
        bool looks_like_endpoint = !next.empty();
        for (char ch : next) {
          if (!(ch == ':' || ch == '.' || (ch >= '0' && ch <= '9'))) looks_like_endpoint = false;
        }
        if (looks_like_endpoint) {
          o.serve = next;
          ++i;
        }
      }
    } else if (a == "-i" || a == "--interface") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      // Repeatable: the first -i is the required interface, the rest are opened
      // alongside it (a physical NIC plus a proxy's TAP adapter, for instance).
      if (o.device.empty()) {
        o.device = v;
      } else {
        o.extra_devices.push_back(v);
      }
    } else if (a == "--with-tunnel" || a == "--tunnel") {
      o.with_tunnel = true;
    } else if (a == "-r" || a == "--read") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.read_path = v;
    } else if (a == "-w" || a == "--write") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.write_path = v;
    } else if (a == "-f" || a == "--filter") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.filter = v;
    } else if (a == "-g" || a == "--generate-sample") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.generate_sample = v;
    } else if (a == "-c" || a == "--count") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.count = std::strtol(v, nullptr, 10);
      if (o.count <= 0) {
        *error = "--count must be a positive integer";
        return false;
      }
    } else if (a == "-s" || a == "--snaplen") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.snaplen = int(std::strtol(v, nullptr, 10));
      if (o.snaplen <= 0) {
        *error = "--snaplen must be a positive integer";
        return false;
      }
    } else if (a == "-t" || a == "--timeout") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.timeout_ms = int(std::strtol(v, nullptr, 10));
      if (o.timeout_ms < 0) {
        *error = "--timeout must not be negative";
        return false;
      }
    } else if (a == "--attrib" || a == "--processes") {
      o.attrib = true;
    } else if (a == "--no-proxy") {
      o.no_proxy = true;
    } else if (a == "--no-attrib") {
      o.no_attrib = true;
    } else if (a == "--split-by") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      SplitMode mode = SplitMode::Off;
      if (!split_mode_from_string(v, &mode) || mode == SplitMode::Off) {
        *error = std::string("unknown --split-by mode '") + v + "' (use proc, app or origin)";
        return false;
      }
      o.split_by = split_mode_name(mode);
    } else if (a == "--block") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.block_filter = v;
    } else if (a == "--block-mode") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      BlockMode m = BlockMode::DryRun;
      if (!block_mode_from_string(v, &m)) {
        *error = std::string("unknown --block-mode '") + v + "' (use dry-run, cut, kill or both)";
        return false;
      }
      o.block_mode = block_mode_name(m);
      o.block_mode_set = true;
    } else if (a == "--block-max") {
      const char* v = need_value(i, a.c_str());
      if (!v) return false;
      o.block_max = std::strtol(v, nullptr, 10);
      if (o.block_max < 0) {
        *error = "--block-max must not be negative";
        return false;
      }
    } else if (!a.empty() && a[0] == '-' && a.size() > 1 && !std::isdigit(u8(a[1]))) {
      *error = "unknown option '" + a + "'";
      return false;
    } else {
      if (o.filter.empty()) {
        o.filter = a;
      } else {
        o.filter += " " + a;
      }
    }
  }
  return true;
}

std::string port_text(u16 port, u8 proto, bool numeric) {
  if (numeric) return std::to_string(port);
  const char* name = service_name(port, proto);
  if (name && *name) return std::to_string(port) + "(" + name + ")";
  return std::to_string(port);
}

std::string tls_version_text(u16 v) {
  const char* n = tls_version_name(v);
  if (n && *n) return n;
  char buf[16];
  std::snprintf(buf, sizeof(buf), "0x%04x", v);
  return buf;
}

std::string app_summary(const PacketInfo& pi, const AppInfo& app, bool numeric) {
  (void)pi;
  (void)numeric;
  switch (app.kind) {
    case AppKind::Http: {
      const HttpInfo& h = app.http;
      std::string s = "HTTP ";
      if (h.http2_preface) return "HTTP/2 preface";
      if (h.is_request) {
        s += h.method;
        s += " ";
        s += h.uri;
        if (h.host[0]) {
          s += " Host=";
          s += h.host;
        }
      } else if (h.is_response) {
        s += std::to_string(h.status);
        s += " ";
        s += h.reason;
        if (h.server[0]) {
          s += " Server=";
          s += h.server;
        }
        if (h.has_content_length) s += " Content-Length=" + std::to_string(h.content_length);
      } else {
        s += "(partial header)";
      }
      if (h.chunked) s += " chunked";
      if (h.connection_close) s += " close";
      return s;
    }
    case AppKind::Tls: {
      const TlsInfo& t = app.tls;
      std::string s = "TLS ";
      if (t.is_client_hello) {
        s += "ClientHello";
        if (t.client_version) s += " ver=" + tls_version_text(t.client_version);
        if (t.sni[0]) {
          s += " SNI=";
          s += t.sni;
        }
        if (t.alpn[0]) {
          s += " ALPN=";
          s += t.alpn;
        }
      } else if (t.is_record) {
        switch (t.record_type) {
          case 20: s += "ChangeCipherSpec"; break;
          case 21: s += "Alert"; break;
          case 22: s += "Handshake"; break;
          case 23: s += "ApplicationData"; break;
          case 24: s += "Heartbeat"; break;
          default: s += "record type " + std::to_string(t.record_type); break;
        }
        s += " ver=" + tls_version_text(t.record_version);
      } else {
        s += "port-based guess (no complete record in this segment)";
      }
      return s;
    }
    case AppKind::Dns:
    case AppKind::Mdns: {
      const DnsInfo& d = app.dns;
      std::string s = (app.kind == AppKind::Mdns) ? "mDNS " : "DNS ";
      if (!d.valid) {
        s += "(short message)";
        return s;
      }
      s += d.is_response ? "response " : "query ";
      const char* tn = dns_type_name(d.qtype);
      s += (tn && *tn) ? tn : std::to_string(d.qtype);
      s += " ";
      s += d.qname[0] ? d.qname : "<?>";
      if (d.is_response) {
        s += " rcode=";
        s += std::to_string(int(d.rcode));
        s += " answers=" + std::to_string(d.ancount);
      }
      if (d.truncated) s += " [truncated]";
      return s;
    }
    case AppKind::Quic: {
      std::string s = "QUIC";
      if (pi.payload_len) {
        const u8 first = pi.payload ? pi.payload[0] : 0;
        const u8 type = u8((first & 0x30) >> 4);
        s += (first & 0x40) ? " short header" : " long header";
        if (!(first & 0x40)) {
          switch (type) {
            case 0: s += " Initial"; break;
            case 1: s += " 0-RTT"; break;
            case 2: s += " Handshake"; break;
            case 3: s += " Retry"; break;
            default: break;
          }
        }
      }
      return s;
    }
    case AppKind::Ssh: {
      std::string s = "SSH banner";
      if (pi.payload && pi.payload_len > 4) {
        std::size_t n = 0;
        while (n < pi.payload_len && n < 64 && pi.payload[n] != '\r' && pi.payload[n] != '\n') ++n;
        s += " \"";
        s.append(reinterpret_cast<const char*>(pi.payload), n);
        s += "\"";
      }
      return s;
    }
    case AppKind::Dhcp:
      return std::string("DHCP ") + (pi.src_port == 68 ? "client -> server" : "server -> client");
    default:
      break;
  }
  if (app.note && *app.note) return std::string("? ") + app.note;
  return std::string();
}

std::string transport_name(const PacketInfo& pi) {
  return l4_name(pi.l4);
}

std::string endpoint_text(const PacketInfo& pi, bool src, bool numeric) {
  const std::string addr = format_ip(pi.ip_version, src ? pi.src_ip : pi.dst_ip);
  if (!pi.has_ports) return addr;
  const u16 port = src ? pi.src_port : pi.dst_port;
  return addr + ":" + port_text(port, l4_number(pi.l4), numeric);
}

std::string ascii_dump(const u8* data, std::size_t len, std::size_t max_bytes) {
  const std::size_t n = (max_bytes && len > max_bytes) ? max_bytes : len;
  std::string out;
  out.reserve(n + 2);
  out += '|';
  for (std::size_t i = 0; i < n; ++i) {
    const u8 c = data[i];
    out += (c >= 0x20 && c < 0x7f) ? char(c) : '.';
  }
  out += '|';
  return out;
}

void print_verbose(std::FILE* out, const PacketView& v, const PacketInfo& pi, const AppInfo& app,
                   const Options& o) {
  std::fprintf(out, "    link      %s", linktype_name(v.linktype));
  if (pi.has_eth) {
    std::fprintf(out, "  %s -> %s  ethertype=0x%04x", format_mac(pi.src_mac).c_str(),
                 format_mac(pi.dst_mac).c_str(), pi.ethertype);
  }
  std::fprintf(out, "\n");
  if (pi.has_vlan) {
    std::fprintf(out, "    vlan      id=%u priority=%u inner=0x%04x\n", unsigned(pi.vlan_id),
                 unsigned(pi.vlan_priority), unsigned(pi.inner_ethertype));
  }
  if (pi.ip_version) {
    std::fprintf(out, "    network   IPv%d  %s -> %s  proto=%s ttl=%u tos=0x%02x len=%u id=0x%04x",
                 pi.ip_version, pi.src_addr().c_str(), pi.dst_addr().c_str(),
                 ip_proto_name(pi.l3_proto), unsigned(pi.l3_hoplimit), unsigned(pi.l3_tos),
                 unsigned(pi.l3_len), unsigned(pi.l3_id));
    if (pi.l3_df) std::fprintf(out, " DF");
    if (pi.l3_mf) std::fprintf(out, " MF");
    if (pi.l3_frag_off) std::fprintf(out, " frag@%u", unsigned(pi.l3_frag_off) * 8u);
    if (pi.reassembled) std::fprintf(out, " [reassembled]");
    std::fprintf(out, "\n");
  }
  if (pi.is_arp) {
    std::fprintf(out, "    arp       op=%u  %s (%s) -> %s (%s)\n", unsigned(pi.arp_op),
                 format_ipv4(pi.arp_spa).c_str(), format_mac(pi.arp_sha).c_str(),
                 format_ipv4(pi.arp_tpa).c_str(), format_mac(pi.arp_tha).c_str());
  }
  if (pi.is_tcp()) {
    const TcpInfo& t = pi.tcp;
    std::fprintf(out,
                 "    transport TCP   %u -> %u  flags=%s seq=%u ack=%u win=%u hdr=%u%s%s%s%s\n",
                 unsigned(pi.src_port), unsigned(pi.dst_port), tcp_flags_str(t.flags).c_str(),
                 t.seq, t.ack, unsigned(t.window), unsigned(t.header_len),
                 t.has_mss ? (" mss=" + std::to_string(t.mss)).c_str() : "",
                 t.has_window_scale ? (" ws=" + std::to_string(unsigned(t.window_scale))).c_str()
                                    : "",
                 t.sack_permitted ? " sack" : "",
                 t.has_timestamp ? (" ts=" + std::to_string(t.ts_val)).c_str() : "");
  } else if (pi.is_udp()) {
    std::fprintf(out, "    transport UDP   %u -> %u  length=%u\n", unsigned(pi.src_port),
                 unsigned(pi.dst_port), unsigned(pi.l3_len));
  } else if (pi.l4 == L4::Icmp || pi.l4 == L4::Icmpv6) {
    const char* tn = (pi.l4 == L4::Icmp) ? icmp_type_name(pi.icmp.type)
                                         : icmpv6_type_name(pi.icmp.type);
    std::fprintf(out, "    transport %s  type=%u(%s) code=%u\n", l4_name(pi.l4),
                 unsigned(pi.icmp.type), tn ? tn : "?", unsigned(pi.icmp.code));
  }
  std::fprintf(out, "    payload   %zu byte(s) after offset %zu\n", pi.payload_len, pi.l4_offset);
  if (app.kind != AppKind::Unknown) {
    std::fprintf(out, "    app       %s  %s\n", app_kind_name(app.kind),
                 app_summary(pi, app, o.numeric).c_str());
    if (app.http.is_request || app.http.is_response) {
      const HttpInfo& h = app.http;
      std::fprintf(out, "    http      headers=%d body_offset=%zu content_length=%s\n",
                   h.header_count, h.body_offset,
                   h.has_content_length ? std::to_string(h.content_length).c_str() : "?");
    }
    if (app.tls.is_record) {
      std::fprintf(out, "    tls       record type=%u version=%s length=%u\n",
                   unsigned(app.tls.record_type), tls_version_text(app.tls.record_version).c_str(),
                   unsigned(app.tls.record_length));
    }
  }
  if (pi.malformed) {
    std::fprintf(out, "    malformed %s\n", pi.malformed_reason ? pi.malformed_reason : "?");
  }
}

std::string origin_label(const ProxyLink& l) {
  if (l.origin_name.empty()) return "pid " + std::to_string(l.origin_pid);
  return l.origin_name + " (" + std::to_string(l.origin_pid) + ")";
}

void print_packet(std::FILE* out, const PacketView& v, const PacketInfo& pi, const AppInfo& app,
                  const ProcOwnership& own, const ProxyLink* origin, const Options& o) {
  std::string layer = "ETH";
  if (pi.is_arp) {
    layer = "ARP";
  } else if (pi.ip_version) {
    layer = pi.ip_version == 4 ? "IPv4" : "IPv6";
  }

  std::fprintf(out, "%s  %-4s %-7s ", format_time_us(v.ts_us).c_str(), layer.c_str(),
               transport_name(pi).c_str());

  if (pi.is_arp) {
    std::fprintf(out, "who-has %s tell %s", format_ipv4(pi.arp_tpa).c_str(),
                 format_ipv4(pi.arp_spa).c_str());
  } else if (pi.has_ports) {
    std::fprintf(out, "%-28s > %-28s", endpoint_text(pi, true, o.numeric).c_str(),
                 endpoint_text(pi, false, o.numeric).c_str());
  } else {
    std::fprintf(out, "%-28s > %-28s", pi.src_addr().c_str(), pi.dst_addr().c_str());
  }

  if (pi.is_tcp()) {
    std::fprintf(out, " %-8s", tcp_flags_str(pi.tcp.flags).c_str());
  } else if (pi.l4 == L4::Icmp || pi.l4 == L4::Icmpv6) {
    std::fprintf(out, " %-8s", (pi.l4 == L4::Icmp ? icmp_type_name(pi.icmp.type)
                                                  : icmpv6_type_name(pi.icmp.type)));
  } else {
    std::fprintf(out, " %-8s", "-");
  }

  std::fprintf(out, " %5zuB", pi.frame_len);
  if (v.truncated) std::fprintf(out, " (of %zu)", v.origlen);

  const std::string summary = app_summary(pi, app, o.numeric);
  if (!summary.empty()) std::fprintf(out, "  %s", summary.c_str());
  if (own.known) std::fprintf(out, "  proc=%s", own.proc.label().c_str());
  // The proxy already owns the socket; the interesting name is the program that
  // asked for the traffic.  The confidence tag is always printed: an order-based
  // match is a guess and must never read like a fact.
  if (origin) {
    std::fprintf(out, "  origin=%s [%s]", origin_label(*origin).c_str(),
                 proxy_confidence_name(origin->confidence));
  }
  std::fprintf(out, "\n");

  if (o.verbose) print_verbose(out, v, pi, app, o);

  if (o.hex_frame) {
    std::fprintf(out, "%s", hexdump(v.data, v.len, 0, "    ").c_str());
  } else if (o.hex_payload && pi.payload && pi.payload_len) {
    std::fprintf(out, "%s", hexdump(pi.payload, pi.payload_len, 0, "    ").c_str());
  }
  if (o.ascii_payload && pi.payload && pi.payload_len) {
    std::fprintf(out, "    %s\n", ascii_dump(pi.payload, pi.payload_len, 0).c_str());
  }
}

struct AppCounter {
  AppKind kind = AppKind::Unknown;
  u64 packets = 0;
  u64 bytes = 0;
};

void bump(std::vector<AppCounter>& counters, AppKind k, std::size_t bytes) {
  for (AppCounter& c : counters) {
    if (c.kind == k) {
      ++c.packets;
      c.bytes += bytes;
      return;
    }
  }
  AppCounter c;
  c.kind = k;
  c.packets = 1;
  c.bytes = bytes;
  counters.push_back(c);
}

// ---------------------------------------------------------------------------
// --jsonl: one JSON object per line, for the Flutter front end.
//
// The stream is: one "hello" object when the source is open, one "packet"
// object per matching packet (flushed immediately, so a live capture shows up
// in the UI as it happens) and a closing "summary" object.
//
// Bytes above 0x7f are passed through only when they form a valid UTF-8
// sequence; anything else is escaped as \u00XX.  A hostname, DNS label or HTTP
// header carrying binary junk therefore cannot make the stream invalid JSON.
// ---------------------------------------------------------------------------

const char* kHexDigits = "0123456789abcdef";

const char* or_empty(const char* s) { return s ? s : ""; }

void json_escape_into(std::string& out, const char* s, std::size_t len) {
  for (std::size_t i = 0; i < len; ++i) {
    const u8 c = u8(s[i]);
    if (c == '"') { out += "\\\""; continue; }
    if (c == '\\') { out += "\\\\"; continue; }
    if (c == '\n') { out += "\\n"; continue; }
    if (c == '\r') { out += "\\r"; continue; }
    if (c == '\t') { out += "\\t"; continue; }
    if (c >= 0x20 && c < 0x7f) { out += char(c); continue; }
    if (c >= 0x80) {
      std::size_t need = 0;
      if ((c & 0xe0) == 0xc0) need = 1;
      else if ((c & 0xf0) == 0xe0) need = 2;
      else if ((c & 0xf8) == 0xf0) need = 3;
      bool valid = need > 0 && i + need < len;
      for (std::size_t k = 1; valid && k <= need; ++k) {
        if ((u8(s[i + k]) & 0xc0) != 0x80) valid = false;
      }
      if (valid) {
        out.append(s + i, need + 1);
        i += need;
        continue;
      }
    }
    out += "\\u00";
    out += kHexDigits[(c >> 4) & 0x0f];
    out += kHexDigits[c & 0x0f];
  }
}

std::string json_str(const char* s, std::size_t max_len = 0) {
  std::string out = "\"";
  if (s) {
    std::size_t len = 0;
    while (s[len] != '\0' && (max_len == 0 || len < max_len)) ++len;
    json_escape_into(out, s, len);
  }
  out += '"';
  return out;
}

std::string json_str(const std::string& s, std::size_t max_len = 0) {
  return json_str(s.c_str(), max_len);
}

std::string hex_bytes(const u8* p, std::size_t len) {
  std::string out;
  out.reserve(len * 2);
  for (std::size_t i = 0; i < len; ++i) {
    out += kHexDigits[(p[i] >> 4) & 0x0f];
    out += kHexDigits[p[i] & 0x0f];
  }
  return out;
}

std::string hex16(u16 v) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "0x%04x", unsigned(v));
  return buf;
}

const char* ethertype_label(u16 t) {
  switch (t) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x8035: return "RARP";
    case 0x86dd: return "IPv6";
    case 0x8100: return "802.1Q VLAN";
    case 0x88a8: return "802.1ad QinQ";
    case 0x8847: return "MPLS unicast";
    default: return "unknown";
  }
}

std::string port_label(u16 port, u8 proto) {
  if (proto != 6 && proto != 17) return std::to_string(port);
  const char* n = service_name(port, proto);
  if (n && *n) return std::to_string(port) + " (" + n + ")";
  return std::to_string(port);
}

std::string proto_column(const PacketInfo& pi) {
  if (pi.is_arp) return "ARP";
  if (pi.ip_version == 0) return pi.has_eth ? "ETH" : "RAW";
  return or_empty(l4_name(pi.l4));
}

/// Small builder for a flat JSON object; keys keep their insertion order.
struct JsonObj {
  std::string s;
  explicit JsonObj(const char* type) {
    s = "{\"type\":";
    s += json_str(type);
  }
  void key(const char* k) {
    s += ',';
    s += json_str(k);
    s += ':';
  }
  void str(const char* k, const char* v) { key(k); s += json_str(v); }
  void str(const char* k, const std::string& v) { key(k); s += json_str(v); }
  void num(const char* k, long long v) { key(k); s += std::to_string(v); }
  void unum(const char* k, unsigned long long v) { key(k); s += std::to_string(v); }
  void boolean(const char* k, bool v) { key(k); s += v ? "true" : "false"; }
  void raw(const char* k, const std::string& json) { key(k); s += json; }
  void finish() { s += "}\n"; }
};

std::string json_packet_line(u64 n, const PacketView& v, const PacketInfo& pi,
                             const AppInfo& app, const ProcOwnership& own, const ProxyLink* origin,
                             const Options& o) {
  JsonObj j("packet");
  j.unum("n", n);
  j.num("ts_us", (long long)v.ts_us);
  j.str("time", format_time_us(v.ts_us));
  j.unum("len", v.len);
  j.unum("origlen", v.origlen);
  j.num("linktype", v.linktype);
  j.boolean("truncated", v.truncated);
  j.boolean("malformed", pi.malformed);
  j.str("reason", or_empty(pi.malformed_reason));
  j.num("ip_version", pi.ip_version);
  // ARP carries no IP header; report its protocol addresses so the packet list
  // still has something meaningful to show in the endpoints column.
  if (pi.ip_version != 0) {
    j.str("src", pi.src_addr());
    j.str("dst", pi.dst_addr());
  } else if (pi.is_arp) {
    j.str("src", format_ipv4(pi.arp_spa));
    j.str("dst", format_ipv4(pi.arp_tpa));
  } else {
    j.str("src", "");
    j.str("dst", "");
  }
  j.str("proto", proto_column(pi));
  j.unum("sport", pi.has_ports ? pi.src_port : 0);
  j.unum("dport", pi.has_ports ? pi.dst_port : 0);
  j.str("sport_name", pi.has_ports ? or_empty(service_name(pi.src_port, pi.l3_proto)) : "");
  j.str("dport_name", pi.has_ports ? or_empty(service_name(pi.dst_port, pi.l3_proto)) : "");
  if (pi.is_tcp()) j.str("flags", tcp_flags_str(pi.tcp.flags));
  else j.str("flags", "");
  j.str("app", app_kind_tag(app.kind));
  j.str("app_name", app_kind_name(app.kind));
  j.str("app_summary", app_summary(pi, app, o.numeric));
  j.str("hostname", or_empty(app_hostname(app)));
  if (app.kind == AppKind::Http) {
    j.str("http_method", app.http.method);
    j.str("http_uri", app.http.uri);
    j.num("http_status", app.http.status);
  }
  if (app.kind == AppKind::Tls) j.str("tls_sni", app.tls.sni);
  if (app.kind == AppKind::Dns || app.kind == AppKind::Mdns) j.str("dns_qname", app.dns.qname);
  if (own.known) {
    j.str("proc", own.proc.name);
    j.str("proc_path", own.proc.path);
    j.unum("proc_pid", own.proc.pid);
    j.str("proc_dir", own.dir == 0 ? "out" : "in");
  }
  if (origin) {
    j.str("origin", origin->origin_name);
    j.unum("origin_pid", origin->origin_pid);
    j.str("proxy", origin->proxy_name);
    j.unum("proxy_pid", origin->proxy_pid);
    j.str("proxy_confidence", proxy_confidence_name(origin->confidence));
    j.str("proxy_basis", origin->basis);
  }
  j.unum("payload_len", pi.payload_len);
  if (pi.payload && pi.payload_len > 0) {
    const std::size_t head = pi.payload_len < 64 ? pi.payload_len : 64;
    j.str("payload_head", hex_bytes(pi.payload, head));
    if (o.hex_payload) j.str("payload_hex", hex_bytes(pi.payload, pi.payload_len));
  }
  if (o.hex_frame && v.data && v.len > 0) j.str("frame_hex", hex_bytes(v.data, v.len));

  // Ordered key/value rows: the UI renders these as a dissection tree without
  // knowing anything about the individual protocols.
  std::string tree;
  auto add = [&tree](const char* k, const std::string& val) {
    if (!tree.empty()) tree += ',';
    tree += json_str(k);
    tree += ':';
    tree += json_str(val);
  };
  add("frame.time", format_time_us(v.ts_us));
  add("frame.length", std::to_string(v.len) + " bytes captured" +
                          (v.truncated ? ", " + std::to_string(v.origlen) + " on the wire"
                                       : ""));
  add("frame.linktype",
      std::string(or_empty(linktype_name(v.linktype))) + " (" + std::to_string(v.linktype) + ")");
  if (pi.has_eth) {
    add("eth.dst", format_mac(pi.dst_mac));
    add("eth.src", format_mac(pi.src_mac));
    add("eth.ethertype", hex16(pi.ethertype) + " (" + ethertype_label(pi.ethertype) + ")");
  }
  if (pi.has_vlan) {
    add("vlan.id", std::to_string(pi.vlan_id));
    add("vlan.priority", std::to_string(pi.vlan_priority));
    add("vlan.inner_ethertype", hex16(pi.inner_ethertype));
  }
  if (pi.ip_version != 0) {
    add("ip.version", std::to_string(pi.ip_version));
    add("ip.src", pi.src_addr());
    add("ip.dst", pi.dst_addr());
    add("ip.proto",
        std::string(or_empty(ip_proto_name(pi.l3_proto))) + " (" + std::to_string(pi.l3_proto) +
            ")");
    add(pi.ip_version == 4 ? "ip.ttl" : "ip.hop_limit", std::to_string(pi.l3_hoplimit));
    add(pi.ip_version == 4 ? "ip.tos" : "ip.traffic_class", hex16(pi.l3_tos));
    add("ip.len", std::to_string(pi.l3_len));
    if (pi.ip_version == 4) {
      add("ip.id", hex16(pi.l3_id));
      std::string f;
      if (pi.l3_df) f = "DF";
      if (pi.l3_mf) f = f.empty() ? "MF" : f + ", MF";
      add("ip.flags", f.empty() ? "none" : f);
      add("ip.frag_offset", std::to_string(unsigned(pi.l3_frag_off) * 8) + " bytes");
    } else {
      add("ipv6.next_header", std::to_string(pi.ipv6_next_header));
    }
    if (pi.is_fragment) add("ip.fragment", "yes");
    if (pi.reassembled) add("ip.reassembled", "yes (rebuilt from fragments)");
  }
  if (pi.is_arp) {
    std::string op = std::to_string(pi.arp_op);
    if (pi.arp_op == 1) op += " (request)";
    else if (pi.arp_op == 2) op += " (reply)";
    add("arp.op", op);
    add("arp.sender", format_ipv4(pi.arp_spa) + "  " + format_mac(pi.arp_sha));
    add("arp.target", format_ipv4(pi.arp_tpa) + "  " + format_mac(pi.arp_tha));
  }
  if (pi.is_tcp()) {
    add("tcp.src_port", port_label(pi.src_port, 6));
    add("tcp.dst_port", port_label(pi.dst_port, 6));
    add("tcp.flags", tcp_flags_str(pi.tcp.flags));
    add("tcp.seq", std::to_string(pi.tcp.seq));
    add("tcp.ack", std::to_string(pi.tcp.ack));
    add("tcp.window", std::to_string(pi.tcp.window));
    add("tcp.header_len", std::to_string(pi.tcp.header_len) + " bytes");
    if (pi.tcp.has_mss) add("tcp.mss", std::to_string(pi.tcp.mss));
    if (pi.tcp.has_window_scale) add("tcp.window_scale", std::to_string(pi.tcp.window_scale));
    if (pi.tcp.sack_permitted) add("tcp.sack_permitted", "yes");
    if (pi.tcp.has_timestamp) {
      add("tcp.timestamp", std::to_string(pi.tcp.ts_val) + " / " + std::to_string(pi.tcp.ts_ecr));
    }
  } else if (pi.l4 == L4::Udp) {
    add("udp.src_port", port_label(pi.src_port, 17));
    add("udp.dst_port", port_label(pi.dst_port, 17));
    add("udp.length", std::to_string(pi.payload_len + 8) + " bytes");
  } else if (pi.l4 == L4::Icmp || pi.l4 == L4::Icmpv6) {
    const bool v6 = pi.l4 == L4::Icmpv6;
    const char* tn = v6 ? icmpv6_type_name(pi.icmp.type) : icmp_type_name(pi.icmp.type);
    add(v6 ? "icmpv6.type" : "icmp.type",
        std::to_string(pi.icmp.type) + " (" + or_empty(tn) + ")");
    add(v6 ? "icmpv6.code" : "icmp.code", std::to_string(pi.icmp.code));
  }
  if (app.kind != AppKind::Unknown) {
    add("app.kind", app_kind_name(app.kind));
    add("app.summary", app_summary(pi, app, o.numeric));
    if (app.note && *app.note) add("app.note", app.note);
    const char* hn = app_hostname(app);
    if (hn && *hn) add("app.hostname", hn);
  }
  if (own.known) {
    add("proc.name", own.proc.name);
    add("proc.pid", std::to_string(own.proc.pid));
    // The application behind a local proxy: the process that really asked for
    // this traffic, plus how sure we are about the pairing.
    if (origin) {
      add("origin.name", origin->origin_name);
      add("origin.pid", std::to_string(origin->origin_pid));
      add("origin.proxy", origin->proxy_name);
      add("origin.confidence", proxy_confidence_name(origin->confidence));
      add("origin.basis", origin->basis);
    }
    add("proc.direction", own.dir == 0 ? "outbound (local source)" : "inbound (local destination)");
    if (!own.proc.path.empty()) add("proc.path", own.proc.path);
    if (own.from_cache) add("proc.source", "remembered from an earlier packet of this flow");
  }
  if (app.kind == AppKind::Http) {
    const HttpInfo& h = app.http;
    if (h.http2_preface) add("http.line", "PRI * HTTP/2.0 (connection preface)");
    else if (h.is_request) add("http.request", std::string(h.method) + " " + h.uri);
    else if (h.is_response) add("http.status", std::to_string(h.status) + " " + h.reason);
    add("http.version", std::to_string(h.version_major) + "." + std::to_string(h.version_minor));
    if (h.host[0]) add("http.host", h.host);
    if (h.user_agent[0]) add("http.user_agent", h.user_agent);
    if (h.server[0]) add("http.server", h.server);
    if (h.content_type[0]) add("http.content_type", h.content_type);
    if (h.upgrade[0]) add("http.upgrade", h.upgrade);
    if (h.accept_encoding[0]) add("http.accept_encoding", h.accept_encoding);
    add("http.headers", std::to_string(h.header_count));
    if (h.has_content_length) {
      add("http.content_length", std::to_string((unsigned long long)h.content_length));
    }
    if (h.chunked) add("http.transfer_encoding", "chunked");
    if (h.connection_close) add("http.connection", "close");
    add("http.body_offset", std::to_string(h.body_offset));
  } else if (app.kind == AppKind::Tls) {
    const TlsInfo& t = app.tls;
    if (t.is_record) {
      add("tls.record_type", std::to_string(t.record_type));
      add("tls.record_version", tls_version_text(t.record_version));
      add("tls.record_length", std::to_string(t.record_length) + " bytes");
    }
    if (t.is_client_hello) {
      add("tls.client_version", tls_version_text(t.client_version));
      if (t.sni[0]) add("tls.sni", t.sni);
      if (t.alpn[0]) add("tls.alpn", t.alpn);
      add("tls.cipher_suites", std::to_string(t.cipher_count));
      if (t.has_supported_versions) {
        add("tls.supported_version", tls_version_text(t.supported_version));
      }
    }
  } else if (app.kind == AppKind::Dns || app.kind == AppKind::Mdns) {
    const DnsInfo& d = app.dns;
    if (d.valid) {
      add("dns.message", d.is_response ? "response" : "query");
      if (d.qname[0]) add("dns.qname", d.qname);
      add("dns.qtype",
          std::string(or_empty(dns_type_name(d.qtype))) + " (" + std::to_string(d.qtype) + ")");
      add("dns.qclass", std::to_string(d.qclass));
      add("dns.questions", std::to_string(d.qdcount));
      add("dns.answers", std::to_string(d.ancount));
      if (d.truncated) add("dns.truncated", "yes");
      add("dns.rcode", std::to_string(d.rcode));
    }
  }
  add("payload.length", std::to_string(pi.payload_len) + " bytes");
  j.raw("tree", "{" + tree + "}");
  j.finish();
  return j.s;
}

// ---- reassembled streams and decrypted HTTP (--streams / --http / --follow) ----

std::string json_stream_report(const StreamReport& s) {
  JsonObj j("stream");
  j.num("index", (long long)s.index);
  j.str("client", s.client());
  j.str("server", s.server());
  j.str("protocol", s.protocol());
  j.str("app", app_kind_tag(s.kind));
  j.str("sni", s.sni);
  j.str("alpn", s.alpn);
  j.boolean("tls", s.tls);
  j.boolean("decrypted", s.decrypted);
  j.boolean("http", s.http);
  j.boolean("http2", s.http2);
  j.boolean("websocket", s.websocket);
  j.boolean("keys_available", s.keys_available);
  j.boolean("truncated", s.truncated);
  j.num("tls_version_id", (long long)s.tls_version);
  j.str("tls_version", or_empty(tls_version_name(s.tls_version)));
  j.num("cipher_id", (long long)s.cipher_suite);
  j.str("cipher", tls_cipher_suite_name(s.cipher_suite));
  j.unum("packets", s.packets);
  j.unum("client_bytes", s.client_bytes);
  j.unum("server_bytes", s.server_bytes);
  j.unum("plaintext_bytes", s.plaintext_bytes);
  j.unum("records", s.tls_stats.records);
  j.unum("retransmits", s.retransmits);
  j.unum("out_of_order", s.out_of_order);
  j.unum("overlaps", s.overlaps);
  j.unum("gaps", s.gaps);
  j.unum("transactions", (unsigned long long)s.transactions);
  j.num("first_us", (long long)s.first_us);
  j.num("last_us", (long long)s.last_us);
  j.str("note", s.note);
  j.finish();
  return j.s;
}

std::string json_http_record(const HttpRecord& r) {
  JsonObj j("http");
  j.num("stream", (long long)r.stream_index);
  j.boolean("http2", r.http2);
  j.boolean("decrypted", r.decrypted);
  if (r.http2) j.num("stream_id", (long long)r.stream_id);
  j.str("client", r.client());
  j.str("server", r.server());
  j.str("transport", r.transport());
  j.str("host", r.host);
  j.str("method", r.method);
  j.str("target", r.target);
  j.str("url", r.url());
  j.str("version", r.version_text());
  j.num("status", r.status);
  j.str("status_line", r.status_line());
  j.str("content_type", r.content_type);
  j.unum("request_bytes", r.request_body_bytes);
  j.unum("response_bytes", r.response_body_bytes);
  j.boolean("request_complete", r.request_complete);
  j.boolean("response_complete", r.response_complete);
  j.boolean("websocket", r.websocket);
  j.boolean("truncated", r.truncated);
  j.num("start_us", (long long)r.start_us);
  j.num("end_us", (long long)r.end_us);
  j.num("duration_ms", (long long)((r.end_us - r.start_us) / 1000));
  j.str("note", r.note);
  j.str("summary", r.summary());
  j.finish();
  return j.s;
}

void print_stream_line(std::FILE* out, const StreamReport& s) {
  std::string detail;
  if (s.tls) {
    if (s.tls_version != 0) detail = std::string("tls=") + or_empty(tls_version_name(s.tls_version));
    if (s.cipher_suite != 0) {
      const std::string cs = tls_cipher_suite_name(s.cipher_suite);
      if (!cs.empty()) detail += (detail.empty() ? "" : " ") + cs;
    }
    if (!s.alpn.empty()) detail += (detail.empty() ? "" : " ") + std::string("alpn=") + s.alpn;
  }
  if (!s.sni.empty()) detail += (detail.empty() ? "" : " ") + std::string("sni=") + s.sni;
  if (!s.note.empty()) detail += (detail.empty() ? "" : " ") + s.note;
  const std::string ends = s.client() + " -> " + s.server();
  const std::string shown = ends.size() > 43 ? ends.substr(0, 40) + "..." : ends;
  std::fprintf(out, " #%-3d %-43s %-10s %5llu pkts %9llu B  %s\n", s.index, shown.c_str(),
               s.protocol().c_str(), (unsigned long long)s.packets,
               (unsigned long long)s.plaintext_bytes, detail.c_str());
}

// ------------------------------------------------- interception proxy output

void print_intercept_line(std::FILE* out, const InterceptEvent& e) {
  std::fprintf(out, "%-8s %-7s %s", intercept_action_name(e.action), e.method.c_str(), e.url.c_str());
  if (e.decrypted) std::fputs("  [decrypted]", out);
  if (!e.mitm.empty() && e.mitm != "on") std::fprintf(out, "  [mitm %s]", e.mitm.c_str());
  if (!e.client_proc.empty()) std::fprintf(out, "  [%s]", e.client_proc.c_str());
  if (!e.origin_ip.empty()) {
    if (e.origin_rtt_us >= 0) {
      std::fprintf(out, "  [origin %s %.2f ms]", e.origin_ip.c_str(),
                   static_cast<double>(e.origin_rtt_us) / 1000.0);
    } else {
      std::fprintf(out, "  [origin %s]", e.origin_ip.c_str());
    }
  }
  if (!e.rule.empty()) std::fprintf(out, "  [%s]", e.rule.c_str());
  if (!e.detail.empty()) std::fprintf(out, "  (%s)", e.detail.c_str());
  std::fprintf(out, "  -> %d\n", e.status);
  std::fflush(out);  // a running proxy reports one decision at a time
}

std::string json_intercept_line(const InterceptEvent& e) {
  JsonObj j("intercept");
  j.str("action", intercept_action_name(e.action));
  j.str("method", e.method);
  j.str("url", e.url);
  j.str("host", e.host);
  j.str("client", e.client);
  j.str("rule", e.rule);
  j.str("detail", e.detail);
  j.boolean("decrypted", e.decrypted);
  j.str("client_proc", e.client_proc);
  j.str("mitm", e.mitm);
  j.str("origin_ip", e.origin_ip);
  j.num("origin_rtt_us", (long long)e.origin_rtt_us);
  j.num("status", e.status);
  j.num("ts_us", (long long)e.ts_us);
  j.unum("request_bytes", e.request_bytes);
  j.unum("response_bytes", e.response_bytes);
  j.finish();
  return j.s;
}

void print_dns_line(std::FILE* out, const DnsQueryEvent& e) {
  std::fprintf(out, "%-8s %-40s %-5s %s\n", e.blocked ? "sink" : e.action.c_str(), e.name.c_str(),
               dns_type_name(e.qtype), e.detail.c_str());
  std::fflush(out);
}

std::string json_dns_line(const DnsQueryEvent& e) {
  JsonObj j("dns");
  j.str("action", e.action);
  j.str("name", e.name);
  j.num("qtype", e.qtype);
  j.str("qtype_name", dns_type_name(e.qtype));
  j.boolean("blocked", e.blocked);
  j.str("client", e.client);
  j.str("detail", e.detail);
  j.num("rcode", e.rcode);
  j.num("ts_us", (long long)e.ts_us);
  j.finish();
  return j.s;
}

std::string json_dns_summary(const DnsSink& sink) {
  const DnsSinkStats s = sink.stats();
  JsonObj j("dns_summary");
  j.str("endpoint", sink.bound_endpoint());
  j.str("upstream", sink.upstream());
  j.unum("queries", s.queries);
  j.unum("blocked", s.blocked);
  j.unum("forwarded", s.forwarded);
  j.unum("errors", s.errors);
  j.unum("malformed", s.malformed);
  j.unum("answers_sent", s.answers_sent);
  j.finish();
  return j.s;
}

std::string json_intercept_summary(const InterceptProxy& proxy) {
  const BlockerStats s = proxy.stats();
  JsonObj j("intercept_summary");
  j.str("endpoint", proxy.bound_endpoint());
  j.unum("requests", s.requests);
  j.unum("blocked", s.blocked);
  j.unum("modified", s.modified);
  j.unum("redirected", s.redirected);
  j.unum("passed", s.passed);
  j.unum("tunnels", s.tunnels);
  j.unum("decrypted", s.decrypted);
  j.unum("mitm_failures", s.mitm_failures);
  j.unum("mitm_skipped", s.mitm_skipped);
  j.unum("mitm_client_refusals", s.mitm_client_refusals);
  j.unum("origin_resolves", s.origin_resolves);
  j.unum("origin_races", s.origin_races);
  j.unum("origin_measured", s.origin_measured);
  j.unum("origin_failovers", s.origin_failovers);
  j.unum("errors", s.errors);
  j.unum("cancelled", s.cancelled);
  j.unum("bytes_in", s.bytes_in);
  j.unum("bytes_out", s.bytes_out);
  j.finish();
  return j.s;
}

void print_streams(std::FILE* out, const std::vector<StreamReport>& streams) {
  std::fprintf(out, "--- tcp streams (%zu) ---\n", streams.size());
  if (streams.empty()) {
    std::fprintf(out, "(no TCP stream was reassembled)\n");
    return;
  }
  for (const StreamReport& s : streams) print_stream_line(out, s);
}

void print_http_line(std::FILE* out, const HttpRecord& r) {
  std::string url = r.url();
  if (url.size() > 56) url = url.substr(0, 53) + "...";
  std::fprintf(out, " #%-3d %-6s %-56s %-16s %8llu B %s\n", r.stream_index, r.method.c_str(),
               url.c_str(), r.status_line().c_str(), (unsigned long long)r.response_body_bytes,
               r.decrypted ? "[decrypted]" : (r.http2 ? "[h2]" : ""));
  std::fflush(out);  // --follow reports a live capture one transaction at a time
}

void print_http_records(std::FILE* out, const std::vector<HttpRecord>& recs) {
  std::fprintf(out, "--- http transactions (%zu) ---\n", recs.size());
  if (recs.empty()) {
    std::fprintf(out, "(no HTTP request/response pair was found)\n");
    return;
  }
  for (const HttpRecord& r : recs) print_http_line(out, r);
}

void emit_json_line(std::FILE* out, const std::string& line) {
  std::fwrite(line.data(), 1, line.size(), out);
  std::fflush(out);  // a live capture must reach the UI packet by packet
}

// --log-file: the durable record of what this proxy decided.
//
// Three deliberate choices.  It keeps *every* decision, not just the ones that
// changed something, because "why was this let through" is as much a question as
// "why was this blocked", and the panel's --show-blocks switch should not decide
// what history is kept.  It flushes after every line: a log still sitting in a
// buffer when the proxy dies is exactly the log you needed.  And it rotates once
// (to <path>.1) so a machine that proxies for a week does not fill the disk.
class DecisionLog {
 public:
  static constexpr long kRotateAt = 8L * 1024L * 1024L;

  bool open(const std::string& path, std::string* why) {
    path_ = path;
    rotate_if_needed();
    file_ = std::fopen(path_.c_str(), "ab");
    if (file_ == nullptr) {
      if (why != nullptr) *why = "cannot write " + path_;
      return false;
    }
    return true;
  }

  bool is_open() const { return file_ != nullptr; }

  void write(const std::string& line) {
    if (file_ == nullptr) return;
    std::fwrite(line.data(), 1, line.size(), file_);
    if (line.empty() || line.back() != '\n') std::fputc('\n', file_);
    std::fflush(file_);
    written_ += static_cast<long>(line.size()) + 1;
    if (written_ >= kRotateAt) {
      std::fclose(file_);
      file_ = nullptr;
      rotate_if_needed();
      file_ = std::fopen(path_.c_str(), "ab");
      written_ = 0;
    }
  }

  void close() {
    if (file_ != nullptr) {
      std::fclose(file_);
      file_ = nullptr;
    }
  }

  ~DecisionLog() { close(); }

  DecisionLog() = default;
  DecisionLog(const DecisionLog&) = delete;
  DecisionLog& operator=(const DecisionLog&) = delete;

 private:
  void rotate_if_needed() {
    std::FILE* probe = std::fopen(path_.c_str(), "rb");
    if (probe == nullptr) return;
    std::fseek(probe, 0, SEEK_END);
    const long size = std::ftell(probe);
    std::fclose(probe);
    if (size < kRotateAt) return;
    const std::string rolled = path_ + ".1";
    std::remove(rolled.c_str());
    std::rename(path_.c_str(), rolled.c_str());
  }

  std::string path_;
  std::FILE* file_ = nullptr;
  long written_ = 0;
};

// The first line of a decision log: what produced it and under which settings.
// A log that cannot say which rule file was in charge is hard to trust later.
std::string json_session_line(const std::string& log_path, const std::string& serve,
                              const std::string& rules, const std::string& upstream) {
  std::string out = "{\"type\":\"session\",\"tool\":\"netcap 1.0\",\"log_format\":1,\"log\":\"";
  json_escape_into(out, log_path.c_str(), log_path.size());
  out += "\",\"serve\":\"";
  json_escape_into(out, serve.c_str(), serve.size());
  out += "\",\"rules\":\"";
  json_escape_into(out, rules.c_str(), rules.size());
  out += "\",\"upstream\":\"";
  json_escape_into(out, upstream.c_str(), upstream.size());
  out += "\"}";
  return out;
}

// ---------------------------------------------------------------------------
// Crash safety net.
//
// What this program changes outside its own process -- the system proxy, the
// default routes -- is system-wide.  The RAII guards put those back on every
// normal exit path, but destructors do not run when an exception escapes a
// thread and std::terminate is called.  A machine left pointing at a proxy that
// no longer exists, or at a tunnel that is gone, is simply "the network broke"
// for whoever is using the computer, so the terminate handler undoes whatever is
// still owed before dying.
struct PanicUndo {
  std::string sysproxy_state;  // empty: the system proxy was not touched
  std::string routes;          // empty: the default routes were not touched
  std::string sysenv_state;    // empty: no per-user environment variable was set
  std::string quic_key_file;   // empty: no key log left behind to purge
};

PanicUndo& panic_undo() {
  static PanicUndo state;
  return state;
}

void netcap_terminate_handler() {
  PanicUndo& undo = panic_undo();
  std::fprintf(stderr, "netcap: dying from an uncaught error; putting the system back\n");
  if (!undo.routes.empty()) {
    std::string error;
    if (netcap::tun_restore_default_routes(undo.routes, &error)) {
      std::fprintf(stderr, "netcap: crash: default routes restored\n");
      undo.routes.clear();
    } else {
      std::fprintf(stderr,
                   "netcap: crash: could not restore the default routes: %s\n"
                   "netcap: run netcap-restore.cmd on the desktop\n",
                   error.c_str());
    }
  }
  if (!undo.sysproxy_state.empty()) {
    std::string error;
    netcap::SystemProxyState back;
    bool had = false;
    if (netcap::system_proxy_restore(undo.sysproxy_state, &back, &had, &error)) {
      std::fprintf(stderr, "netcap: crash: system proxy restored (%s)\n", back.describe().c_str());
      undo.sysproxy_state.clear();
    } else {
      std::fprintf(stderr,
                   "netcap: crash: could not restore the system proxy: %s\n"
                   "netcap: run 'netcap --system-proxy restore'\n",
                   error.c_str());
    }
  }
  if (!undo.sysenv_state.empty()) {
    std::string error;
    netcap::SysEnvState back;
    if (netcap::sysenv_restore(undo.sysenv_state, &back, &error)) {
      std::fprintf(stderr, "netcap: crash: the per-user environment is back to normal\n");
      undo.sysenv_state.clear();
    } else {
      std::fprintf(stderr,
                   "netcap: crash: could not undo the environment change: %s\n"
                   "netcap: run netcap-restore.cmd on the desktop\n",
                   error.c_str());
    }
  }
  if (!undo.quic_key_file.empty()) {
    std::string error;
    if (netcap::sysenv_purge_file(undo.quic_key_file, &error)) {
      undo.quic_key_file.clear();
    } else {
      std::fprintf(stderr, "netcap: crash: a session key file is still on disk: %s (%s)\n",
                   undo.quic_key_file.c_str(), error.c_str());
    }
  }
  std::fflush(stderr);
  std::_Exit(4);
}

// Registered once, before anything system-wide is touched.
void install_terminate_guard() {
  static const bool once = []() {
    std::set_terminate(netcap_terminate_handler);
    return true;
  }();
  (void)once;
}

}  // namespace

// Decides where upstream connections are reached, and whether a system proxy
// takeover is safe.  Returns false when the decision cannot even be made (a
// malformed --upstream), leaving *error set; *refusal is set when a takeover
// would leave this machine without a way out (nothing answers behind us).
// `--system-proxy check` runs exactly this and prints it instead of applying it.
static bool resolve_upstream(const Options& o, std::string* upstream, std::string* refusal,
                             std::string* error) {
  *upstream = o.upstream;
  if (!upstream->empty()) {
    u16 port = 0;
    std::string normalized;
    if (!system_proxy_endpoint_ok(*upstream, &port, &normalized, error) || port == 0) return false;
    *upstream = normalized;
    std::string why;
    if (!system_proxy_probe(*upstream, 1500, &why)) {
      std::fprintf(stderr, "netcap: --upstream %s is not answering (%s)\n", upstream->c_str(),
                   why.c_str());
      if ((o.system_proxy == 1 && !o.system_proxy_force) || o.system_proxy == 5) {
        *refusal = "--upstream " + *upstream +
                   " is not answering, so a takeover would leave the machine without a way out";
      }
    }
    return true;
  }
  // Mode 5 (`--system-proxy check`) previews exactly what a mode 1 would pick,
  // so the search for a live upstream behind us runs in both cases.
  const bool preview = o.system_proxy == 5;
  if ((o.system_proxy != 1 && !preview) || (!preview && o.system_proxy_force)) return true;
  // Nothing was named: chain through whatever already carries this machine's
  // traffic.  When nothing answers, the registry is left alone.
  SystemProxyState live;
  std::string live_error;
  std::string tried;
  if (!system_proxy_read(&live, &live_error)) {
    *refusal = "cannot read the current system proxy settings (" + live_error + ")";
    return true;
  }
  for (const std::string& candidate : system_proxy_candidate_upstreams(live)) {
    std::string probe_error;
    if (system_proxy_probe(candidate, 400, &probe_error)) {
      *upstream = candidate;
      return true;
    }
    tried += candidate + " ";
  }
  *refusal = "nothing answered behind us (tried " + tried +
             "), so the machine would lose its network; it currently points at '" + live.server + "'";
  return true;
}

int run(int argc, char** argv) {
#ifdef _WIN32
  // Adapter names and socket error strings are emitted as UTF-8, so ask the
  // console to decode them that way instead of as the local ANSI code page.
  SetConsoleOutputCP(CP_UTF8);
#endif
  // Before anything that touches the system: a crash must not leave the machine
  // pointed at a proxy or a tunnel that is already gone.
  install_terminate_guard();
  Options o;
  std::string error;
  if (!parse_args(argc, argv, o, &error)) {
    std::fprintf(stderr, "netcap: %s\n", error.c_str());
    std::fprintf(stderr, "Try 'netcap --help'.\n");
    return 2;
  }

  if (o.show_version) {
    std::printf("%s\n", kVersion);
    return 0;
  }
  if (o.show_help) {
    print_usage(stdout);
    print_tunnel_usage(stdout);
    print_rules_usage(stdout);
    std::fputs(wfp_help().c_str(), stdout);
    return 0;
  }
  if (o.rules_help) {
    std::printf("%s\n", rule_syntax_help().c_str());
    return 0;
  }
  if (o.wfp_help) {
    std::printf("%s\n", wfp_help().c_str());
    return 0;
  }
  if (o.filter_help) {
    std::printf("%s\n", filter_syntax_help().c_str());
    return 0;
  }

  if (o.json && o.write_path == "-") {
    std::fprintf(stderr, "netcap: --jsonl and '-w -' both want stdout; write the pcap elsewhere\n");
    return 2;
  }

  SplitMode split_mode = SplitMode::Off;
  if (!o.split_by.empty()) split_mode_from_string(o.split_by, &split_mode);
  if (split_mode != SplitMode::Off) {
    if (o.write_path.empty()) {
      std::fprintf(stderr, "netcap: --split-by needs -w <directory>\n");
      return 2;
    }
    if (o.write_path == "-") {
      std::fprintf(stderr, "netcap: --split-by cannot write to stdout; give it a directory\n");
      return 2;
    }
  }

  if (!o.block_filter.empty()) {
    BlockMode bm = BlockMode::DryRun;
    if (!block_mode_from_string(o.block_mode, &bm)) {
      std::fprintf(stderr, "netcap: unknown --block-mode '%s' (use dry-run, cut, kill or both)\n",
                   o.block_mode.c_str());
      return 2;
    }
    std::string berr;
    const Filter bf = Filter::parse(o.block_filter, &berr);
    if (bf.parse_failed()) {
      std::fprintf(stderr, "netcap: --block: %s\n", berr.c_str());
      return 2;
    }
  } else if (o.block_mode_set) {
    std::fprintf(stderr, "netcap: --block-mode needs --block <filter>\n");
    return 2;
  }

  if (o.selftest) {
    std::string report;
    const int failures = run_selftest(o.verbose, &report);
    std::fputs(report.c_str(), stdout);
    return failures == 0 ? 0 : 1;
  }

  if (!o.generate_sample.empty()) {
    int n = 0;
    if (write_sample_pcap(o.generate_sample, &n, &error) != 0) {
      std::fprintf(stderr, "netcap: %s\n", error.c_str());
      return 3;
    }
    if (o.json) {
      JsonObj j("sample");
      j.str("path", o.generate_sample);
      j.num("packets", (long long)n);
      j.finish();
      emit_json_line(stdout, j.s);
      return 0;
    }
    std::printf("wrote %d synthetic packets to %s\n", n, o.generate_sample.c_str());
    std::printf("try:  netcap -r %s -v -c 5\n", o.generate_sample.c_str());
    return 0;
  }

  if (o.list_processes) {
    // Always JSONL: the GUI's program picker reads exactly this, and a person at
    // a prompt can pipe it through anything.  The enumeration does not open a
    // single process handle, so it also works for protected processes.
    std::map<u32, std::string> names;
    if (!proc_collect_process_names(&names)) {
      std::fprintf(stderr, "netcap: --list-processes: cannot enumerate processes here\n");
      return 3;
    }
    std::vector<std::pair<std::string, u32>> rows;
    rows.reserve(names.size());
    for (const auto& kv : names) rows.emplace_back(kv.second, kv.first);
    std::sort(rows.begin(), rows.end());
    for (const auto& row : rows) {
      JsonObj j("process");
      j.str("name", row.first);
      j.unum("pid", row.second);
      j.finish();
      emit_json_line(stdout, j.s);
    }
    JsonObj j("processes");
    j.unum("count", rows.size());
    j.finish();
    emit_json_line(stdout, j.s);
    return 0;
  }

  if (o.list_devices) {
    std::vector<DeviceInfo> devs;
    std::string err;
    const bool ok = list_devices(devs, &err);
    if (!ok && devs.empty()) {
      std::fprintf(stderr, "netcap: %s\n", err.c_str());
      return 3;
    }
    if (o.json) {
      for (const DeviceInfo& d : devs) {
        JsonObj j("device");
        j.num("index", (long long)d.ifindex);
        j.str("name", d.name);
        j.str("description", d.description);
        j.str("address", d.address);
        j.str("mac", d.mac);
        j.num("family", d.family);
        j.boolean("up", d.up);
        j.boolean("loopback", d.loopback);
        j.boolean("default", d.is_default);
        j.boolean("tunnel", d.tunnel);
        j.finish();
        emit_json_line(stdout, j.s);
      }
      std::string note;
      const bool available = live_capture_supported(&note);
      JsonObj j("devices");
      j.unum("count", devs.size());
      j.boolean("mechanism_available", available);
      j.str("mechanism", note);
      j.str("requirement", live_capture_requirement());
      j.finish();
      emit_json_line(stdout, j.s);
      return ok ? 0 : 3;
    }
    std::printf("%-4s %-24s %-22s %-18s %s\n", "idx", "name", "address", "mac", "state");
    for (const DeviceInfo& d : devs) {
      std::string state;
      state += d.up ? "up" : "down";
      if (d.loopback) state += ",loopback";
      if (d.is_default) state += ",default";
      if (d.tunnel) state += ",tunnel";
      std::printf("%-4u %-24s %-22s %-18s %s\n", d.ifindex,
                  d.name.size() > 24 ? d.name.substr(0, 24).c_str() : d.name.c_str(),
                  d.address.empty() ? "-" : d.address.c_str(),
                  d.mac.empty() ? "-" : d.mac.c_str(), state.c_str());
    }
    std::string note;
    live_capture_supported(&note);
    std::printf("\nlive capture mechanism: %s\n", note.c_str());
    std::printf("%s\n", live_capture_requirement().c_str());
    return ok ? 0 : 3;
  }

  // ---- filter ----
  Filter filter = Filter::parse(o.filter, &error);
  if (filter.parse_failed()) {
    std::fprintf(stderr, "netcap: filter error: %s\n", error.c_str());
    std::fprintf(stderr, "Try 'netcap --filter-help'.\n");
    return 2;
  }

  // ---- stream analysis: reassembly, TLS decryption, HTTP ----
  Analyzer analyzer;
  analyzer.set_reassembly(!o.no_reassembly);
  std::shared_ptr<KeyLogStore> keylog;
  if (!o.keylog.empty()) {
    keylog = std::make_shared<KeyLogStore>();
    if (!keylog->load_file(o.keylog, &error)) {
      std::fprintf(stderr, "netcap: %s\n", error.c_str());
      return 3;
    }
    analyzer.set_keylog(keylog);
  }

  // ---- source ----
  // ---- rule list and the interception proxy ------------------------------
  RuleSet rule_list;
  if (!o.rules_path.empty()) {
    std::string rerr;
    if (!rule_list.load_file(o.rules_path, &rerr)) {
      std::fprintf(stderr, "netcap: %s\n", rerr.c_str());
      return 2;
    }
    if (!o.quiet) {
      std::fprintf(stderr, "netcap: %s\n", rule_list.describe().c_str());
      const std::string skipped = rule_list.skipped_report(3);
      if (!skipped.empty()) std::fputs(skipped.c_str(), stderr);
    }
  }
  for (const std::string& extra : o.rules_extra) {
    std::string rerr;
    if (!rule_list.load_file(extra, &rerr)) {
      std::fprintf(stderr, "netcap: --rules-extra: %s\n", rerr.c_str());
      return 2;
    }
    if (!o.quiet) std::fprintf(stderr, "netcap: extra rules: %s\n", rule_list.describe().c_str());
  }
  if (o.check_rule_set) {
    RuleSet probe;
    std::string reason;
    const bool network = probe.add_line(o.check_rule, &reason);
    if (!reason.empty()) {
      std::printf("rejected: %s\n", reason.c_str());
      return 1;
    }
    if (network) {
      const std::vector<Rule>& accepted = probe.rules();
      std::printf("ok network rule: %s\n",
                  accepted.empty() ? o.check_rule.c_str() : accepted.back().raw.c_str());
      return 0;
    }
    const std::size_t cosmetic = probe.cosmetics().size() + probe.cosmetic_exceptions().size();
    if (cosmetic > 0) {
      std::printf("ok element hiding rule: %s\n", o.check_rule.c_str());
      return 0;
    }
    std::printf("ok comment: nothing is blocked by this line\n");
    return 0;
  }
  if (o.rules_check) {
    if (o.rules_path.empty()) {
      std::fprintf(stderr, "netcap: --rules-check needs --rules <file>\n");
      return 2;
    }
    std::printf("%s\n", rule_list.describe().c_str());
    std::fputs(rule_list.skipped_report().c_str(), stdout);
    return 0;
  }
  if (!o.wfp_specs.empty()) {
    std::vector<WfpSpec> specs;
    for (const std::string& text : o.wfp_specs) {
      WfpSpec spec;
      std::string spec_error;
      if (!wfp_parse_spec(text, &spec, &spec_error)) {
        std::fprintf(stderr, "netcap: --wfp: %s\n", spec_error.c_str());
        return 2;
      }
      specs.push_back(spec);
    }
    std::printf("wfp filters         : %zu\n", specs.size());
    for (const WfpSpec& spec : specs) std::printf("  %s\n", spec.describe().c_str());
    std::string wfp_note;
    WfpEngine::available(&wfp_note);
    std::printf("wfp platform        : %s\n", wfp_note.c_str());
    std::printf("elevation           : %s\n",
                wfp_platform_elevated() ? "Administrator"
                                        : "standard user (--wfp-apply will fail with access denied; "
                                          "run netcap from an Administrator terminal)");
    if (!o.wfp_apply) {
      std::printf("dry run             : nothing was installed (add --wfp-apply)\n");
      return 0;
    }
    WfpEngine engine;
    std::string engine_error;
    if (!engine.open(&engine_error)) {
      std::fprintf(stderr, "netcap: %s\n", engine_error.c_str());
      return 4;
    }
    for (const WfpSpec& spec : specs) {
      u64 filter_id = 0;
      std::string add_error;
      if (!engine.add_block(spec, &filter_id, &add_error)) {
        std::fprintf(stderr, "netcap: %s\n", add_error.c_str());
        return 4;
      }
      std::printf("installed           : id %llu  %s\n", static_cast<unsigned long long>(filter_id),
                  spec.describe().c_str());
    }
    std::fputs(engine.report().c_str(), stdout);
    if (o.wfp_wait) {
      std::printf("holding             : %zu filter(s); press Ctrl+C to remove them\n", engine.filters());
      std::fflush(stdout);
      while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(100));
      std::printf("interrupted         : Ctrl+C, removing the filters\n");
    }
    engine.close();
    std::printf("removed             : %llu filter(s)\n",
                static_cast<unsigned long long>(engine.removed_total()));
    if (engine.failed_total() > 0) {
      std::fprintf(stderr, "netcap: %llu wfp operation(s) failed\n",
                   static_cast<unsigned long long>(engine.failed_total()));
      return 4;
    }
    return 0;
  }

  if (o.hosts_set) {
    if (o.rules_path.empty()) {
      std::fprintf(stderr, "netcap: --hosts needs --rules <file> to know which names to block\n");
      return 2;
    }
    const std::string hp = o.hosts_path.empty() ? platform_hosts_path() : o.hosts_path;
    std::string current;
    {
      std::ifstream in(hp, std::ios::binary);
      std::ostringstream buf;
      buf << in.rdbuf();
      current = buf.str();
    }
    const std::vector<std::string> wanted = rule_list.blocked_hosts();
    const HostsPlan plan = plan_hosts(current, wanted);
    std::printf("hosts file          : %s\n", hp.c_str());
    std::printf("names to block      : %zu\n", wanted.size());
    std::printf("plan                : %s\n", plan.describe().c_str());
    for (std::size_t i = 0; i < plan.added.size() && i < 10; ++i) {
      std::printf("  + 0.0.0.0 %s\n", plan.added[i].c_str());
    }
    if (plan.added.size() > 10) std::printf("  + ... and %zu more\n", plan.added.size() - 10);
    for (std::size_t i = 0; i < plan.removed.size() && i < 10; ++i) {
      std::printf("  - %s\n", plan.removed[i].c_str());
    }
    if (plan.added.empty() && plan.removed.empty()) {
      std::printf("nothing to do       : the file already matches the rule list\n");
    }
    if (!o.hosts_apply) {
      std::printf("dry run             : nothing was written (add --hosts-apply to change the file)\n");
      return 0;
    }
    std::string herr;
    if (!write_hosts_file(hp, plan.text, &herr, true)) {
      std::fprintf(stderr, "netcap: %s\n", herr.c_str());
      if (hp == platform_hosts_path()) {
        std::fprintf(stderr, "netcap: writing the system hosts file needs Administrator rights\n");
      }
      return 4;
    }
    std::printf("written             : %zu name(s) blocked, previous file kept as %s.bak\n",
                wanted.size(), hp.c_str());
    return 0;
  }
  if (o.dns_set) {
    if (o.rules_path.empty()) {
      std::fprintf(stderr, "netcap: --dns needs --rules <file> to know which names to block\n");
      return 2;
    }
    DnsSinkConfig dcfg;
    dcfg.bind_address = "127.0.0.1";
    dcfg.port = 5353;
    {
      const std::string bind = o.dns_bind.empty() ? std::string("127.0.0.1:5353") : o.dns_bind;
      const std::size_t colon = bind.rfind(':');
      if (colon == std::string::npos) {
        dcfg.port = static_cast<u16>(std::strtoul(bind.c_str(), nullptr, 10));
      } else {
        dcfg.bind_address = bind.substr(0, colon);
        dcfg.port = static_cast<u16>(std::strtoul(bind.substr(colon + 1).c_str(), nullptr, 10));
        if (dcfg.bind_address == "0.0.0.0") dcfg.bind_address = "127.0.0.1";
      }
      if (dcfg.port == 0) dcfg.port = 5353;
    }
    if (!o.dns_upstream.empty()) dcfg.upstream = o.dns_upstream;
    DnsSink sink;
    std::string dns_error;
    if (!sink.start(dcfg, &rule_list, &dns_error)) {
      std::fprintf(stderr, "netcap: %s\n", dns_error.c_str());
      return 3;
    }
    if (!o.quiet) {
      std::fprintf(stderr, "netcap: %s\n", sink.describe().c_str());
      std::fprintf(stderr,
                   "netcap: point the system resolver at %s (or try: nslookup ads.example.com %s)\n",
                   sink.bound_endpoint().c_str(), dcfg.bind_address.c_str());
      std::fprintf(stderr, "netcap: Ctrl+C stops it\n");
    }
    std::thread dns_worker([&sink]() { sink.run(); });
    std::size_t shown = 0;
    while (!g_stop) {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
      const std::vector<DnsQueryEvent> live = sink.events();
      for (; shown < live.size(); ++shown) {
        const DnsQueryEvent& e = live[shown];
        const bool interesting = e.blocked || e.action != "forward";
        if (!interesting && !o.show_blocks) continue;
        if (o.json) {
          emit_json_line(stdout, json_dns_line(e));
        } else {
          print_dns_line(stdout, e);
        }
      }
    }
    sink.stop();
    dns_worker.join();
    if (o.json) emit_json_line(stdout, json_dns_summary(sink));
    if (!o.quiet) std::fputs(sink.report().c_str(), o.json ? stderr : stdout);
    return (sink.stats().errors > 0) ? 4 : 0;
  }
  // ---- the local CA used by --mitm -----------------------------------------
  const std::string ca_cert = o.ca_prefix + ".crt";
  const std::string ca_key = o.ca_prefix + ".key";
  if (o.ca_init || o.ca_show) {
    CaBundle ca;
    std::string ca_err;
    const bool exists = std::ifstream(ca_cert.c_str()).good();
    if (o.ca_show || exists) {
      if (!ca_read_files(ca_cert, ca_key, &ca, &ca_err)) {
        std::fprintf(stderr, "netcap: %s\n", ca_err.c_str());
        return 3;
      }
      std::printf("ca certificate : %s\n", ca_cert.c_str());
      std::printf("ca private key : %s\n", ca_key.c_str());
      std::printf("subject        : %s\n", ca.cert.subject_cn.c_str());
      std::printf("serial         : %s\n", ca.cert.serial_hex.c_str());
      std::printf("sha-256        : %s\n", ca.cert.sha256_hex().c_str());
      std::printf("valid          : %s .. %s\n", ca.cert.not_before.c_str(), ca.cert.not_after.c_str());
      if (o.ca_show) return 0;
      std::printf("note           : left untouched; delete both files to start over\n");
      return 0;
    }
    X509Subject subject;
    subject.common_name = "netcap local CA";
    subject.organization = "netcap";
    subject.country = "CN";
    if (!ca_create(subject, 3650, &ca, &ca_err)) {
      std::fprintf(stderr, "netcap: could not create the CA: %s\n", ca_err.c_str());
      return 3;
    }
    if (!ca_write_files(ca, ca_cert, ca_key, &ca_err)) {
      std::fprintf(stderr, "netcap: could not write the CA: %s\n", ca_err.c_str());
      return 3;
    }
    std::printf("ca certificate : %s\n", ca_cert.c_str());
    std::printf("ca private key : %s\n", ca_key.c_str());
    std::printf("subject        : %s\n", ca.cert.subject_cn.c_str());
    std::printf("serial         : %s\n", ca.cert.serial_hex.c_str());
    std::printf("sha-256        : %s\n", ca.cert.sha256_hex().c_str());
    std::printf("valid          : %s .. %s\n", ca.cert.not_before.c_str(), ca.cert.not_after.c_str());
    std::printf(
        "\nnetcap will NOT install this for you. To let --mitm decrypt HTTPS, import\n"
        "  %s\n"
        "into the trust store you want to use (browser and/or Windows 'Trusted Root\n"
        "Certification Authorities'), then remove it again when you are done. The CA\n"
        "private key stays on this machine and can sign any name: keep it private.\n",
        ca_cert.c_str());
    return 0;
  }

  // ------------------------------------------------------------- system proxy
  //
  // 'on' is handled further down, next to --serve: the takeover only makes
  // sense once the listener is really bound.  Everything else is a one-shot
  // command that prints what it did and exits.
  const std::string sysproxy_state =
      o.system_proxy_state.empty() ? std::string("netcap_sysproxy.state") : o.system_proxy_state;
  if (o.system_proxy_help) {
    std::fputs(system_proxy_help().c_str(), stdout);
    return 0;
  }
  if (o.system_proxy == 4) {
    std::string note;
    const bool available = system_proxy_available(&note);
    const bool snapshot = system_proxy_snapshot_exists(sysproxy_state);
    SystemProxyState live;
    std::string read_error;
    const bool readable = system_proxy_read(&live, &read_error);
    if (o.json) {
      std::string line = "{\"event\":\"system_proxy\",\"mode\":\"status\",\"available\":";
      line += available ? "true" : "false";
      line += ",\"readable\":";
      line += readable ? "true" : "false";
      line += ",\"state_file\":" + json_str(sysproxy_state);
      line += ",\"snapshot\":";
      line += snapshot ? "true" : "false";
      if (readable) {
        line += ",\"enable\":" + std::to_string(live.enabled() ? 1 : 0);
        line += ",\"server\":" + json_str(live.server);
        line += ",\"override\":" + json_str(live.override_list);
        line += ",\"auto_config\":" + json_str(live.auto_config_url);
      }
      if (!note.empty()) line += ",\"note\":" + json_str(note);
      line += "}";
      emit_json_line(stdout, line);
      return 0;
    }
    std::fputs(system_proxy_report().c_str(), stdout);
    std::printf("snapshot            : %s%s\n", sysproxy_state.c_str(),
                snapshot ? " (present: --system-proxy restore will put it back)"
                         : " (absent: nothing is taken over)");
    return 0;
  }
  if (o.system_proxy == 2) {
    SystemProxyState live;
    std::string error;
    if (!system_proxy_read(&live, &error)) {
      std::fprintf(stderr, "netcap: --system-proxy off: %s\n", error.c_str());
      return 4;
    }
    if (!live.enabled()) {
      std::printf("system proxy        : already off\n");
      return 0;
    }
    live.enable = 0;
    live.enable_present = true;
    if (!system_proxy_apply(live, &error)) {
      std::fprintf(stderr, "netcap: --system-proxy off: %s\n", error.c_str());
      return 4;
    }
    std::printf("system proxy        : switched off (the original settings stay in %s)\n",
                sysproxy_state.c_str());
    return 0;
  }
  if (o.system_proxy == 3) {
    SystemProxyState restored;
    bool had = false;
    std::string error;
    if (!system_proxy_restore(sysproxy_state, &restored, &had, &error)) {
      std::fprintf(stderr, "netcap: --system-proxy restore: %s\n", error.c_str());
      return 4;
    }
    if (!had) {
      std::printf("system proxy        : nothing to restore ('%s' does not exist)\n",
                  sysproxy_state.c_str());
    } else {
      std::printf("system proxy        : restored %s\n", restored.describe().c_str());
      std::printf("snapshot            : %s (removed)\n", sysproxy_state.c_str());
    }
    return 0;
  }
  if (o.system_proxy == 1 && !o.serve_set) {
    std::fprintf(stderr,
                 "netcap: --system-proxy on needs --serve: there is no endpoint to point the "
                 "system proxy at\n");
    return 2;
  }

  // Where upstream connections go, and whether a system proxy takeover would
  // leave this machine without a way out, is decided before anything starts: the
  // blocker reads it once at start().  `--system-proxy check` exists to print
  // exactly this decision without touching the registry.
  std::string upstream_proxy;
  std::string refusal;
  {
    std::string upstream_error;
    if (!resolve_upstream(o, &upstream_proxy, &refusal, &upstream_error)) {
      std::fprintf(stderr, "netcap: --upstream: %s\n", upstream_error.c_str());
      return 2;
    }
  }
  if (o.system_proxy == 5) {
    if (!refusal.empty()) {
      std::printf("netcap: a takeover would be refused: %s\n", refusal.c_str());
      std::printf("netcap: pass --upstream host:port (for example the local proxy port) to chain\n");
    } else if (!upstream_proxy.empty()) {
      std::printf("netcap: a system proxy takeover would chain through %s\n",
                  upstream_proxy.c_str());
    } else {
      std::printf(
          "netcap: a system proxy takeover would not chain anywhere: traffic would leave this\n"
          "        machine directly (that only works for what this machine can reach on its own)\n");
    }
    return 0;
  }
  if (!refusal.empty()) {
    std::fprintf(stderr,
                 "netcap: refusing to take the system proxy over: %s\n"
                 "        Pass --upstream host:port (the local proxy port, e.g. 127.0.0.1:7890)\n"
                 "        or --system-proxy-force to take over anyway (everything then goes\n"
                 "        through netcap directly).\n",
                 refusal.c_str());
    return 4;
  }

  // ---- TUN mode ------------------------------------------------------------
  if (o.tun_help) {
    std::fputs(tun_help().c_str(), stdout);
    return 0;
  }
  if (o.tun_check || o.tun_set || !o.tun_restore.empty()) {
    if (!o.tun_dll.empty()) tun_prefer_dll(o.tun_dll);
    if (!o.tun_restore.empty()) {
      std::string text;
      std::string file_error;
      if (!tun_read_file(o.tun_restore, &text, &file_error)) {
        std::fprintf(stderr, "netcap: --tun-restore: %s\n", file_error.c_str());
        return 2;
      }
      std::string restore_error;
      if (!tun_restore_default_routes(text, &restore_error)) {
        std::fprintf(stderr, "netcap: --tun-restore: %s\n", restore_error.c_str());
        return 4;
      }
      std::printf("netcap: default routes restored from %s\n", o.tun_restore.c_str());
      return 0;
    }
    std::string detail;
    const bool tun_ready = tun_available(&detail);
    std::printf("netcap: tun %s: %s\n", tun_ready ? "available" : "unavailable", detail.c_str());
    std::string routes_error;
    std::string routes_snapshot;
    if (tun_default_routes(&routes_snapshot, &routes_error)) {
      std::vector<TunRoute> routes;
      std::string parse_error;
      if (tun_routes_parse(routes_snapshot, &routes, &parse_error)) {
        std::vector<TunInterfaceMetric> ifmetrics;
        const bool metrics_ok = tun_interface_metrics(routes, &ifmetrics);
        std::printf("netcap: %zu default route(s) right now:\n", routes.size());
        for (const TunRoute& r : routes) {
          const TunInterfaceMetric* own_metric = nullptr;
          for (const TunInterfaceMetric& m : ifmetrics) {
            if (m.luid == r.luid && m.ifindex == r.ifindex) {
              own_metric = &m;
              break;
            }
          }
          std::printf("        %s/%d via %s ifindex %u luid 0x%llx metric %u", r.destination.c_str(),
                      r.prefix_len, r.next_hop.c_str(), (unsigned)r.ifindex,
                      (unsigned long long)r.luid, (unsigned)r.metric);
          if (own_metric != nullptr) {
            std::printf(" (interface %u -> effective %u)", (unsigned)own_metric->metric,
                        (unsigned)tun_effective_metric(r.metric, own_metric->metric));
          } else {
            std::printf(" (interface metric unknown -> effective %u)",
                        (unsigned)tun_effective_metric(r.metric, 0));
          }
          std::printf("\n");
        }
        if (!metrics_ok) {
          std::printf("netcap: interface metrics cannot be read on this platform\n");
        }
        // Read-only verdict, and the same rule the takeover itself enforces: a
        // tunnel route wins only if effective metric 0 is still free.  luid 0
        // means "no route of ours is in the table yet".
        std::string takeover_why;
        if (tun_takeover_is_safe(routes, ifmetrics, 0, &takeover_why)) {
          std::printf("netcap: a tunnel default route (effective metric 0) would win, so a "
                      "takeover is allowed\n");
        } else {
          std::printf("netcap: a takeover would be refused: %s\n", takeover_why.c_str());
        }
        // Where forwarded UDP (QUIC, DNS-over-UDP, games) would have to leave
        // once the tunnel owns the route.  Read-only: nothing is pinned here.
        {
          const std::uint32_t physical = tun_pick_physical_ifindex(routes, ifmetrics, 0);
          if (physical != 0) {
            std::printf("netcap: udp, if a takeover forwards it, would leave through interface "
                        "%u\n",
                        (unsigned)physical);
          } else {
            std::printf("netcap: udp would be dropped after a takeover: no physical default "
                        "route to aim it at\n");
          }
        }
      } else {
        std::printf("netcap: default routes: %s\n", parse_error.c_str());
      }
    } else {
      std::printf("netcap: default routes: %s\n", routes_error.c_str());
    }
    {
      // The same decision `--system-proxy check` prints: a takeover without a
      // working way out is what cuts a machine off the network.
      Options preview = o;
      preview.system_proxy = 5;
      std::string preview_upstream;
      std::string preview_refusal;
      std::string preview_error;
      if (!resolve_upstream(preview, &preview_upstream, &preview_refusal, &preview_error)) {
        std::printf("netcap: upstream: %s\n", preview_error.c_str());
      } else if (!preview_refusal.empty()) {
        std::printf("netcap: a takeover would be refused: %s\n", preview_refusal.c_str());
      } else if (!preview_upstream.empty()) {
        std::printf("netcap: a takeover would chain through %s\n", preview_upstream.c_str());
      } else {
        std::printf("netcap: a takeover would not chain anywhere\n");
      }
    }
    if (!o.tun_set) return 0;
    if (!tun_ready) {
      std::fprintf(stderr, "netcap: --tun: %s\n", detail.c_str());
      return 4;
    }
    TunDevice device;
    TunDeviceInfo tun_info;
    std::string open_error;
    // --tun-address accepts "addr/prefix"; the prefix defaults to /24 and the MTU
    // to 1500 (a Wintun adapter otherwise keeps the 65535 the driver reports).
    std::string tun_address = o.tun_address.empty() ? std::string("10.7.0.1/24") : o.tun_address;
    int tun_prefix = 24;
    const std::size_t tun_slash = tun_address.find('/');
    if (tun_slash != std::string::npos) {
      const int parsed_prefix = std::atoi(tun_address.c_str() + tun_slash + 1);
      if (parsed_prefix >= 0 && parsed_prefix <= 32) tun_prefix = parsed_prefix;
      tun_address = tun_address.substr(0, tun_slash);
    }
    const unsigned int tun_mtu = o.tun_mtu == 0 ? 1500u : o.tun_mtu;
    if (!device.open(o.tun_name, tun_address, tun_prefix, tun_mtu, &tun_info, &open_error)) {
      std::fprintf(stderr, "netcap: --tun: %s\n", open_error.c_str());
      return 4;
    }
    std::printf("netcap: %s\n", device.describe().c_str());
    std::printf("netcap: %s\n", detail.c_str());
    if (!o.tun_takeover) {
      std::printf(
          "netcap: the adapter is up, but nothing is routed through it yet; add --tun-takeover "
          "once\n        the packet engine is in (see --tun-help)\n");
      if (o.tun_hold > 0) {
        // Diagnostic mode: a Wintun adapter only has a visible network interface
        // while somebody holds a session open, so this is the only way to look at
        // it (and at the packets that arrive) from another shell.
        std::printf("netcap: holding the adapter open for %d s; read the tunnel from another shell\n",
                    o.tun_hold);
        std::vector<std::uint8_t> tun_buffer(65536);
        unsigned long long tun_packets = 0;
        unsigned long long tun_bytes = 0;
        int tun_dumped = 0;
        std::string tun_read_error;
        for (int second = 0; second < o.tun_hold; ++second) {
          const int got = device.read_packet(tun_buffer.data(), tun_buffer.size(), 1000, &tun_read_error);
          if (got > 0) {
            ++tun_packets;
            tun_bytes += static_cast<unsigned long long>(got);
            if (tun_dumped < 3) {
              // Show what actually came out of the ring: the first bytes say which
              // EtherType this interface is being fed.
              ++tun_dumped;
              std::string hex;
              char pair[4];
              for (int i = 0; i < got && i < 48; ++i) {
                std::snprintf(pair, sizeof(pair), "%02x", tun_buffer[static_cast<std::size_t>(i)]);
                hex += pair;
              }
              std::printf("netcap: packet %d, %d bytes: %s\n", tun_dumped, got, hex.c_str());
            }
          } else if (got < 0 && !tun_read_error.empty()) {
            std::fprintf(stderr, "netcap: --tun-hold: %s\n", tun_read_error.c_str());
            tun_read_error.clear();
          }
        }
        std::printf("netcap: the tunnel carried %llu packet(s), %llu bytes, in %d s\n", tun_packets,
                    tun_bytes, o.tun_hold);
      }
      device.close();
      return 0;
    }
    // --- the takeover: the packet engine carries what the route sends us ----
    // Safety first.  Once the default route points at this tunnel, every socket
    // netcap opens to reach an origin matches that route as well and comes back
    // into the tunnel, so a chainless takeover would loop and cut the machine
    // off the network (that is exactly what the system-proxy round did once).
    // A chain on 127.0.0.1 is immune, because loopback never enters the tunnel.
    if (upstream_proxy.empty()) {
      std::fprintf(stderr,
                   "netcap: --tun-takeover: refusing to take the default route without an "
                   "upstream to chain to.\n"
                   "        Once the tunnel owns that route netcap's own upstream sockets match "
                   "it too and come\n"
                   "        back into the tunnel, so the machine would be cut off.  Pass "
                   "--upstream <host:port>\n"
                   "        (a proxy on 127.0.0.1 is safe: loopback never enters the tunnel), or "
                   "keep using\n"
                   "        '--tun-hold' to watch the tunnel without changing the routes.\n");
      device.close();
      return 4;
    }

    RuleSet tun_rules;
    const RuleSet* tun_rules_ptr = nullptr;
    if (!o.rules_path.empty()) {
      std::string rule_error;
      if (!tun_rules.load_file(o.rules_path, &rule_error)) {
        std::fprintf(stderr, "netcap: --rules: %s\n", rule_error.c_str());
        device.close();
        return 2;
      }
      tun_rules_ptr = &tun_rules;
      std::printf("netcap: %s\n", tun_rules.describe().c_str());
    } else {
      std::printf(
          "netcap: no --rules given: every connection is forwarded and nothing is blocked\n");
    }

    // Decide where the browser's secrets will go *before* the pipe is built: the
    // pipe has to know whether QUIC can be inspected at all.  A key log that is
    // already configured belongs to the user, so it is left alone and QUIC is not
    // inspected (the file there may not even be Chromium's format).
    {
      const char* existing = std::getenv("SSLKEYLOGFILE");
      if (existing != nullptr && existing[0] != '\0') {
        o.quic_keys.clear();  // someone already pointed this machine at a key log
      } else if (o.quic_keys.empty()) {
        const std::string base = netcap::sysenv_default_state_path();
        const std::size_t slash = base.find_last_of("\\/");
        o.quic_keys =
            (slash == std::string::npos ? base : base.substr(0, slash + 1)) + "quickkeys.log";
      }
    }
    QuicKeyLogProvider quic_provider(o.quic_keys);

    RelayConfig relay_config;
    relay_config.version = 4;
    relay_config.mtu = tun_mtu;
    relay_config.rules = tun_rules_ptr;
    relay_config.answer_icmp_echo = true;
    // Whether UDP can be forwarded at all is decided just before the pipe is
    // built, once we know which physical adapter the default route came from.
    relay_config.forward_udp = false;
    // QUIC 1-RTT inspection: with a key log the pipe can open a short-header
    // packet and apply the URL rules to the HTTP/3 request inside it.  Without one
    // QUIC is forwarded untouched, exactly as before.
    relay_config.quic_keys = o.quic_keys.empty() ? nullptr : &quic_provider;
    {
      unsigned int parts[4] = {0, 0, 0, 0};
      if (std::sscanf(tun_address.c_str(), "%u.%u.%u.%u", &parts[0], &parts[1], &parts[2],
                      &parts[3]) == 4) {
        for (int i = 0; i < 4; ++i) {
          relay_config.local[static_cast<std::size_t>(i)] =
              static_cast<std::uint8_t>(parts[i] & 0xffu);
        }
      }
    }
    {
      const std::size_t colon = upstream_proxy.rfind(':');
      if (colon != std::string::npos && colon + 1 < upstream_proxy.size()) {
        relay_config.chain_host = upstream_proxy.substr(0, colon);
        relay_config.chain_port = static_cast<std::uint16_t>(
            std::strtoul(upstream_proxy.c_str() + colon + 1, nullptr, 10));
      }
      if (relay_config.chain_host.empty() || relay_config.chain_port == 0) {
        std::fprintf(stderr, "netcap: --tun-takeover: the upstream '%s' is not host:port\n",
                     upstream_proxy.c_str());
        device.close();
        return 2;
      }
    }
    // QUIC - and every other UDP flow - only works while the tunnel is up if the
    // datagram leaves through the adapter that used to own the default route.
    // Work out which adapter that is *before* the route moves: the lowest
    // effective metric among the default routes that are not ours.
    {
      std::string udp_routes_text;
      std::string udp_routes_error;
      std::vector<TunRoute> udp_routes;
      std::vector<TunInterfaceMetric> udp_ifmetrics;
      if (tun_default_routes(&udp_routes_text, &udp_routes_error) &&
          tun_routes_parse(udp_routes_text, &udp_routes, &udp_routes_error) &&
          tun_interface_metrics(udp_routes, &udp_ifmetrics)) {
        const std::uint32_t own = device.info().ifindex;
        relay_config.physical_ifindex = tun_pick_physical_ifindex(udp_routes, udp_ifmetrics, own);
        relay_config.tunnel_ifindex = own;
      }
      relay_config.forward_udp = relay_config.physical_ifindex != 0 &&
                                 relay_config.physical_ifindex != relay_config.tunnel_ifindex;
      if (relay_config.forward_udp) {
        std::printf("netcap: udp will leave through interface %u (the adapter the default route "
                    "came from)\n",
                    static_cast<unsigned>(relay_config.physical_ifindex));
      } else {
        std::printf("netcap: udp is dropped: no physical default route to pin it to\n");
      }
      std::fflush(stdout);
    }
    TunPipe relay(relay_config);
    // Refuse to point the default route at a chain that is not answering: a TUN
    // with a dead upstream blackholes the machine, and this check is cheap.
    if (!tunpipe_chain_reachable(relay_config.chain_host, relay_config.chain_port, 1500)) {
      std::fprintf(stderr,
                   "netcap: --tun-takeover: the chain at %s:%u is not answering, so taking the "
                   "default\n        route would cut this machine off.  Start it (or pass a "
                   "different --upstream) and\n        try again.\n",
                   relay_config.chain_host.c_str(),
                   static_cast<unsigned>(relay_config.chain_port));
      device.close();
      return 4;
    }
    std::printf("netcap: chain %s:%u answers\n", relay_config.chain_host.c_str(),
                static_cast<unsigned>(relay_config.chain_port));

    const std::string snapshot_file = "netcap_tun_routes.txt";
    std::string route_snapshot;
    std::string route_error;
    {
      // What is about to change, in plain words, before anything is touched.
      // The takeover is purely additive (it lowers the tunnel's interface metric
      // and adds one default route), so this list is printed for the record, not
      // as a list of deletions.
      std::string before_text;
      std::string before_error;
      if (tun_default_routes(&before_text, &before_error)) {
        std::printf("netcap: default routes before the takeover:\n%s", before_text.c_str());
      }
      std::printf("netcap: the takeover ADDS 0.0.0.0/0 on-link on the tunnel and lowers that "
                  "interface metric to 0\n"
                  "netcap: no other route is removed; the old routes stay in the table\n");
      std::fflush(stdout);
    }
    if (!tun_takeover_default_routes(device, &route_snapshot, &route_error)) {
      std::fprintf(stderr, "netcap: --tun-takeover: %s\n", route_error.c_str());
      device.close();
      return 4;
    }
    {
      std::string write_error;
      if (!tun_write_file(snapshot_file, route_snapshot, &write_error)) {
        std::fprintf(stderr, "netcap: could not save the route snapshot: %s\n",
                     write_error.c_str());
      }
    }
    std::printf("netcap: the default route now points at the tunnel, and traffic is chained "
                "through %s:%u\n",
                relay_config.chain_host.c_str(),
                static_cast<unsigned>(relay_config.chain_port));
    std::printf("netcap: Ctrl+C puts the routes back; 'netcap --tun-restore %s' does it by hand\n",
                snapshot_file.c_str());
    std::fflush(stdout);
    bool watchdog_tripped = false;
    {
      // Nothing below may leave the machine without a default route: the guard
      // restores the snapshot on every exit path, including the error ones.
      struct RouteRestore {
        const std::string* snapshot;
        std::string file;
        ~RouteRestore() {
          if (snapshot == nullptr || snapshot->empty()) return;
          std::string restore_error;
          if (tun_restore_default_routes(*snapshot, &restore_error)) {
            std::printf("netcap: default routes restored\n");
            panic_undo().routes.clear();  // nothing owed to the terminate handler
          } else {
            std::fprintf(stderr,
                         "netcap: could not put the default routes back: %s\n"
                         "netcap: run 'netcap --tun-restore %s' as administrator\n",
                         restore_error.c_str(), file.c_str());
          }
          std::fflush(stderr);
        }
      } route_guard{&route_snapshot, snapshot_file};
      // Crash safety net: the guard's destructor does not run during
      // std::terminate, so hand the same snapshot to the terminate handler.
      panic_undo().routes = route_snapshot;

      // The invisible half of reading QUIC.  A Chromium-family browser only
      // writes its TLS/QUIC session secrets when SSLKEYLOGFILE was already in
      // the environment of the process that started it, so the per-user block
      // gets the value here -- before anything new is launched -- and every exit
      // path (this guard, and the terminate handler through panic_undo) puts the
      // old value back and wipes the file.  Nothing about it is printed unless
      // NETCAP_QUIC_TRACE is set: the secrets are how netcap reads QUIC, not
      // something the user is asked to manage.
      struct QuicKeyEnv {
        std::string state_file;
        std::string key_file;
        bool active = false;
        ~QuicKeyEnv() {
          if (!active) return;
          std::string why;
          netcap::SysEnvState back;
          if (netcap::sysenv_restore(state_file, &back, &why)) {
            panic_undo().sysenv_state.clear();
          } else {
            std::fprintf(stderr, "netcap: could not put SSLKEYLOGFILE back: %s\n", why.c_str());
          }
          std::string purge_error;
          if (netcap::sysenv_purge_file(key_file, &purge_error)) {
            panic_undo().quic_key_file.clear();
          } else {
            std::fprintf(stderr, "netcap: the session key file is still there: %s\n",
                         purge_error.c_str());
          }
          std::fflush(stderr);
        }
      } quic_env;
      {
        // The path itself was decided before the pipe was built (the pipe needs to
        // know whether it can inspect QUIC at all); publishing it here is what the
        // browsers started afterwards will read.
        if (!o.quic_keys.empty()) {
          quic_env.key_file = o.quic_keys;
          quic_env.state_file = netcap::sysenv_default_state_path();
          netcap::SysEnvState st;
          std::string why;
          if (netcap::sysenv_set("SSLKEYLOGFILE", quic_env.key_file, quic_env.state_file, &st,
                                 &why)) {
            quic_env.active = true;
            panic_undo().sysenv_state = quic_env.state_file;
            panic_undo().quic_key_file = quic_env.key_file;
          } else if (std::getenv("NETCAP_QUIC_TRACE") != nullptr) {
            std::fprintf(stderr, "netcap: cannot point SSLKEYLOGFILE at %s: %s\n",
                         quic_env.key_file.c_str(), why.c_str());
          }
        }
      }

      std::vector<std::uint8_t> tun_packet(65536);
      std::vector<Packet> outgoing;
      const i64 started_us = now_monotonic_us();
      const i64 stop_at_us =
          o.tun_seconds > 0 ? started_us + static_cast<i64>(o.tun_seconds) * 1000000 : 0;
      i64 last_report = started_us;
      std::string read_error;
      // Watchdog: a takeover that nothing uses is a broken machine.  If the
      // tunnel sees no packet at all within two seconds, roll back and say so.
      std::size_t tun_packets = 0;
      std::size_t tun_bytes = 0;
      while (!g_stop && (stop_at_us == 0 || now_monotonic_us() < stop_at_us)) {
        const i64 now = now_monotonic_us();
        const int got = device.read_packet(tun_packet.data(), tun_packet.size(), 10, &read_error);
        if (got > 0) {
          ++tun_packets;
          tun_bytes += static_cast<std::size_t>(got);
          relay.on_packet(tun_packet.data(), static_cast<std::size_t>(got), now, &outgoing);
        } else if (got < 0 && !read_error.empty()) {
          std::fprintf(stderr, "netcap: --tun-takeover: %s\n", read_error.c_str());
          read_error.clear();
          break;
        }
        relay.poll(got > 0 ? 0 : 5, now, &outgoing);
        relay.tick(now, &outgoing);
        std::string write_error;
        for (const Packet& packet : outgoing) {
          if (!device.write_packet(packet.data.data(), packet.data.size(), &write_error)) {
            std::fprintf(stderr, "netcap: --tun-takeover: %s\n", write_error.c_str());
            break;
          }
        }
        outgoing.clear();
        if (tun_packets == 0 && now - started_us > 2000000) {
          std::fprintf(stderr,
                       "netcap: --tun-takeover: not a single packet reached the tunnel in two "
                       "seconds, so this machine is not using it;\n"
                       "netcap: rolling the routing table back instead of leaving the network "
                       "half-broken\n");
          watchdog_tripped = true;
          break;
        }
        if (now - last_report >= 5000000) {
          last_report = now;
          std::printf("netcap: tunnel %zu packet(s), %zu byte(s); %s\n", tun_packets, tun_bytes,
                      relay.describe().c_str());
          std::fflush(stdout);
        }
      }
      relay.stop();
      if (!watchdog_tripped) {
        std::printf("netcap: the tunnel carried %zu packet(s), %zu byte(s)\n", tun_packets, tun_bytes);
      }
      if (stop_at_us != 0 && !watchdog_tripped) {
        std::printf("netcap: --tun-seconds reached the limit, stopping the takeover\n");
      }
    }
    device.close();
    if (watchdog_tripped) {
      std::fprintf(stderr, "netcap: --tun-takeover: the takeover was rolled back\n");
      return 4;
    }
    return 0;
  }

  if (o.serve_set) {
    if (o.rules_path.empty() && o.rules_extra.empty()) {
      std::fprintf(stderr, "netcap: --serve needs --rules <file>; there is nothing to block with\n");
      return 2;
    }

    BlockerConfig bc;
    bc.upstream_proxy = upstream_proxy;
    bc.stub_body = o.stub_body;
    bc.block_third_party_cookies = o.third_party_cookies;
    // The picker needs somewhere to write rules; without it a pick would be
    // hidden for this session only, which is worse than not offering it.
    bc.picker = (o.picker || !o.picker_flag.empty()) && !o.picker_rules.empty();
    bc.picker_rules = o.picker_rules;
    bc.picker_flag = o.picker_flag;
    bc.procedural_cosmetics = !o.no_procedural;
    bc.mitm = o.mitm;
    bc.mitm_insecure = o.mitm_insecure;
    bc.mitm_skip = split_name_list(o.mitm_skip);
    bc.mitm_only = split_name_list(o.mitm_only);
    bc.mitm_strict = o.mitm_strict;
    if (!origin_policy_parse(o.origin_policy, &bc.origin_policy)) {
      std::fprintf(stderr, "netcap: --origin-policy must be first or best (got '%s')\n",
                   o.origin_policy.c_str());
      return 2;
    }
    bc.origin_race = o.origin_race;
    bc.origin_ttl_s = o.origin_ttl;
    bc.ca_cert_path = ca_cert;
    bc.ca_key_path = ca_key;
    const std::string endpoint = o.serve.empty() ? std::string("127.0.0.1:8080") : o.serve;
    const std::size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos) {
      bc.bind_address = "127.0.0.1";
      bc.port = static_cast<std::uint16_t>(std::strtoul(endpoint.c_str(), nullptr, 10));
    } else {
      bc.bind_address = endpoint.substr(0, colon);
      bc.port = static_cast<std::uint16_t>(std::strtoul(endpoint.substr(colon + 1).c_str(), nullptr, 10));
    }
    if (bc.port == 0) bc.port = 8080;

    InterceptProxy proxy;
    // Every accepted connection gets attributed to the process that opened it:
    // the same OS endpoint table --attrib uses, refreshed at most once a second
    // because the resolver runs on proxy worker threads (hence the mutex).
    {
      auto table = std::make_shared<ProcessTable>();
      auto table_mu = std::make_shared<std::mutex>();
      auto last_refresh = std::make_shared<i64>(0);
      auto last_forced = std::make_shared<i64>(0);
      proxy.set_client_resolver([table, table_mu, last_refresh, last_forced](const std::string& address,
                                                               std::uint16_t port) {
        std::lock_guard<std::mutex> lock(*table_mu);
        const i64 now = now_monotonic_us();
        if (*last_refresh == 0 || now - *last_refresh > 1000000) {
          std::string ignored;
          table->refresh(&ignored);
          *last_refresh = now;
        }
        int version = 0;
        u8 parsed[16] = {0};
        if (!parse_ip(address, &version, parsed)) return std::string();
        PacketInfo pi;
        pi.ip_version = version;
        pi.l4 = L4::Tcp;
        pi.has_ports = true;
        pi.src_port = port;
        std::memcpy(pi.src_ip, parsed, version == 4 ? 4 : 16);
        int dir = 0;
        const ProcessInfo* owner = table->owner_of(pi, &dir);
        if (owner != nullptr) return owner->name;
        // A connection opened within the last second is not in that snapshot yet,
        // so one miss is not an answer: read the table again (rate limited, since
        // this runs on every accepted connection) before telling the UI that a
        // request belongs to nobody.
        const i64 now2 = now_monotonic_us();
        if (now2 - *last_forced > 150000) {
          std::string ignored;
          table->refresh(&ignored);
          *last_refresh = now2;
          *last_forced = now2;
          owner = table->owner_of(pi, &dir);
          if (owner != nullptr) return owner->name;
        }
        return std::string();
      });
    }
    std::string perr;
    if (!proxy.start(bc, &rule_list, &perr)) {
      std::fprintf(stderr, "netcap: %s\n", perr.c_str());
      return 3;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    if (!o.quiet) {
      std::fprintf(stderr, "netcap: %s\n", proxy.describe().c_str());
      std::fprintf(stderr,
                   "netcap: point the browser or the system HTTP proxy at http://%s; Ctrl+C stops\n",
                   proxy.bound_endpoint().c_str());
      if (!upstream_proxy.empty()) {
        std::fprintf(stderr, "netcap: chaining every upstream connection through %s\n",
                     upstream_proxy.c_str());
      }
    }
    // Hand the system proxy over only once the listener is really bound: a
    // failed start must never leave the machine pointing at a dead port.
    SystemProxyState sysproxy_previous;
    bool sysproxy_taken = false;
    if (o.system_proxy == 1) {
      std::string enable_error;
      // One name is deliberately kept out of our hands: the Windows IPv6
      // connectivity probe.  Its only record is AAAA, so on a machine without a
      // usable global IPv6 address it can never answer, and handing it to the
      // proxy turns "this machine has no IPv6" into a 502 from us that reads as
      // "netcap broke the internet".  Sent direct it fails the way it should.
      // The list is built by system_proxy_bypass_auto() (unit tested) so this
      // stays a decision rather than a string assembled by hand.
      const bool have_ipv6 = machine_has_ipv6();
      const std::string bypass = system_proxy_bypass_auto(o.system_proxy_bypass, have_ipv6);
      if (!have_ipv6 && !o.quiet) {
        std::fprintf(stderr,
                     "netcap: no usable IPv6 address on this machine; ipv6.msftncsi.com stays "
                     "direct (an IPv6-only name cannot be reached from here)\n");
      }
      if (!system_proxy_enable(proxy.bound_endpoint(), bypass, sysproxy_state,
                               &sysproxy_previous, &enable_error)) {
        std::fprintf(stderr, "netcap: --system-proxy on: %s\n", enable_error.c_str());
        proxy.stop();
        return 4;
      }
      sysproxy_taken = true;
      // Crash safety net: should this process die from an uncaught error, the
      // terminate handler puts the previous settings back before exiting.
      panic_undo().sysproxy_state = sysproxy_state;
      if (!o.quiet) {
        std::fprintf(stderr,
                     "netcap: system proxy now %s (was %s), previous settings in %s; Ctrl+C puts "
                     "them back\n",
                     proxy.bound_endpoint().c_str(), sysproxy_previous.describe().c_str(),
                     sysproxy_state.c_str());
        if (!upstream_proxy.empty()) {
          std::fprintf(stderr, "netcap: chaining through %s so the previous path keeps working\n",
                       upstream_proxy.c_str());
        }
      }
    }
    // --log-file: the durable record.  It keeps every decision (the panel's
    // --show-blocks switch decides what is *printed*, not what is remembered),
    // and it is flushed per line, so a crash cannot take the last decisions.
    DecisionLog decisions;
    if (o.log_file_set) {
      std::string log_why;
      if (decisions.open(o.log_file, &log_why)) {
        decisions.write(json_session_line(o.log_file, proxy.bound_endpoint(), o.rules_path,
                                          upstream_proxy));
        if (!o.quiet) {
          std::fprintf(stderr, "netcap: decisions are appended to %s\n", o.log_file.c_str());
        }
      } else if (!o.quiet) {
        std::fprintf(stderr, "netcap: cannot write the decision log: %s\n", log_why.c_str());
      }
    }
    std::thread worker([&proxy]() { proxy.run(); });
    std::size_t printed = 0;
    while (!g_stop) {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
      // The interface switches picking on and off by creating or deleting a
      // flag file: the proxy cannot be restarted mid-session, so watch the file.
      if (!o.picker_flag.empty()) {
        std::ifstream flag(o.picker_flag.c_str());
        const bool picking = flag.good();
        if (proxy.picker() != picking) proxy.set_picker(picking);
      }
      const std::vector<InterceptEvent> events = proxy.events();
      for (; printed < events.size(); ++printed) {
        const InterceptEvent& e = events[printed];
        const bool changed = e.action != InterceptAction::Pass && e.action != InterceptAction::Tunnel;
        if (decisions.is_open()) {
          // The cosmetic rule list can be tens of kilobytes (every generic
          // hiding rule that applied); the log only needs enough of it to see
          // which rule spoke, and the full text is in the rule files.
          InterceptEvent logged = e;
          if (logged.rule.size() > 300) logged.rule = logged.rule.substr(0, 300) + " ...";
          decisions.write(json_intercept_line(logged));
        }
        if (o.json) {
          if (changed || o.show_blocks) emit_json_line(stdout, json_intercept_line(e));
        } else if (changed || o.show_blocks) {
          print_intercept_line(stdout, e);
        }
      }
      // Keep the stream usable when stdout is a pipe or a file: a block-buffered
      // stream would hide every decision until the process exits, which is
      // useless for a proxy meant to be watched while it runs.
      std::fflush(stdout);
    }
    proxy.stop();
    worker.join();
    if (sysproxy_taken) {
      panic_undo().sysproxy_state.clear();  // the restore below is enough now
      SystemProxyState back;
      bool had = false;
      std::string restore_error;
      if (system_proxy_restore(sysproxy_state, &back, &had, &restore_error)) {
        if (!o.quiet) {
          std::fprintf(stderr, "netcap: system proxy restored (%s)\n", back.describe().c_str());
        }
      } else {
        std::fprintf(stderr,
                     "netcap: could not put the system proxy back: %s (run 'netcap --system-proxy "
                     "restore')\n",
                     restore_error.c_str());
      }
    }
    if (o.json) emit_json_line(stdout, json_intercept_summary(proxy));
    if (decisions.is_open()) decisions.write(json_intercept_summary(proxy));
    if (!o.quiet) std::fputs(proxy.report().c_str(), o.json ? stderr : stdout);
    return 0;
  }

  const bool from_file = !o.read_path.empty();
  CaptureConfig cfg;
  cfg.snaplen = o.snaplen;
  cfg.timeout_ms = o.timeout_ms;
  cfg.promisc = !o.no_promisc;
  cfg.nanosecond = o.nanosecond;
  cfg.device = from_file ? o.read_path : o.device;
  if (!from_file) {
    cfg.extra_devices = o.extra_devices;
    cfg.with_tunnel = o.with_tunnel;
  }

#ifdef _WIN32
  // Binary streams, switched before the first byte is touched: MSVC/MinGW stdio
  // defaults to text mode, which would translate 0x0a in packet data to CRLF on
  // the way out and collapse CRLF on the way in.  Doing it after the pcap header
  // has been read is too late - stdio has already buffered translated bytes.
  if (o.write_path == "-") _setmode(_fileno(stdout), _O_BINARY);
  if (from_file && o.read_path == "-") _setmode(_fileno(stdin), _O_BINARY);
#endif

  std::unique_ptr<CaptureBackend> cap;
  if (from_file) {
    cap = make_file_backend();
  } else {
    cap = make_live_backend(&error);
    if (!cap) {
      std::fprintf(stderr, "netcap: %s\n", error.c_str());
      return 3;
    }
  }
  if (!cap->open(cfg, &error)) {
    std::fprintf(stderr, "netcap: %s\n", error.c_str());
    return 3;
  }

  std::FILE* log = stdout;
  if (o.write_path == "-") log = stderr;  // keep stdout a clean pcap stream
  if (o.json) log = stderr;               // ... and a clean JSON Lines stream

  std::fprintf(log, "netcap: %s\n", cap->describe().c_str());
  if (!o.filter.empty()) std::fprintf(log, "netcap: filter  %s\n", o.filter.c_str());
  else std::fprintf(log, "netcap: filter  (none - every packet matches)\n");
  if (o.json) {
    JsonObj j("hello");
    j.str("tool", kVersion);
    j.boolean("live", !from_file);
    j.str("source", from_file ? o.read_path : o.device);
    j.str("described", cap->describe());
    j.num("linktype", (long long)cap->linktype());
    j.str("linktype_name", or_empty(linktype_name(cap->linktype())));
    j.str("filter", o.filter);
    j.num("snaplen", (long long)o.snaplen);
    j.boolean("nanosecond", o.nanosecond);
    j.boolean("reassembly", analyzer.reassembly());
    j.str("keylog", o.keylog);
    j.boolean("keylog_loaded", keylog != nullptr);
    j.unum("keylog_entries", keylog ? keylog->size() : 0);
    j.finish();
    emit_json_line(stdout, j.s);
  } else if (log != stdout) {
    std::fprintf(stderr, "netcap: pcap output on stdout; the packet log is on stderr\n");
    std::fflush(stdout);
  }

  PcapWriter writer;
  SplitWriter splitter;
  if (split_mode != SplitMode::Off) {
    splitter.set_mode(split_mode);
    if (!splitter.open(o.write_path, cap->linktype(), u32(o.snaplen), o.nanosecond, 64, &error)) {
      std::fprintf(stderr, "netcap: %s\n", error.c_str());
      return 3;
    }
  } else if (!o.write_path.empty()) {
    if (!writer.open(o.write_path, cap->linktype(), u32(o.snaplen), o.nanosecond, &error)) {
      std::fprintf(stderr, "netcap: %s\n", error.c_str());
      return 3;
    }
  }

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  Dissector dissector;
  u64 seen = 0, matched = 0, bytes = 0, written = 0, malformed = 0;
  std::vector<AppCounter> counters;
  i64 last_gc = now_monotonic_us();

  // Process attribution.  On a live capture the endpoint table describes the
  // sockets that are sending this traffic, so it is on by default; a recording
  // replayed from a file usually has no matching sockets left, so it stays off
  // unless --attrib asks for it explicitly.
  ProcAttributor attributor;
  ProcTotals proc_totals;
  const bool want_attrib =
      !o.no_attrib &&
      (o.attrib || o.read_path.empty() || split_mode == SplitMode::Proc ||
       split_mode == SplitMode::Origin);
  attributor.set_enabled(want_attrib);

  // Local proxy correlation: rebuild from the same endpoint snapshot the
  // attribution uses, so the two views can never disagree.
  ProxyTable proxy_table;
  const bool want_proxy = want_attrib && !o.no_proxy;
  proxy_table.set_enabled(want_proxy);
  if (want_proxy) {
    attributor.set_refresh_hook([&proxy_table](const ProcessTable& t) {
      proxy_table.rebuild(t.raw_endpoints(), t, now_monotonic_us());
    });
  }

  // Interception.  The block filter is deliberately independent of -f: -f says
  // what is displayed, --block says what is acted on.  Nothing happens without
  // an explicit --block, and the guards live in BlockConfig.
  Filter block_filter;
  Blocker blocker;
  bool block_on = false;
  if (!o.block_filter.empty()) {
    std::string berr;
    block_filter = Filter::parse(o.block_filter, &berr);
    if (block_filter.parse_failed()) {
      std::fprintf(stderr, "netcap: --block: %s\n", berr.c_str());
      return 2;
    }
    BlockConfig bc;
    block_mode_from_string(o.block_mode, &bc.mode);
    bc.max_actions = u32(o.block_max);
    bc.guard_name = "netcap.exe";   // never kill the capture tool, whoever started it
#ifdef _WIN32
    bc.guard_pid = u32(GetCurrentProcessId());
#endif
    blocker.set_config(bc);
    block_on = true;
  }
  const auto report_block = [&](const BlockDecision& d) {
    // done = the platform call succeeded, dry = nothing was touched, skip = a
    // guard refused, fail = the platform call itself failed (it carries error).
    const char* state =
        d.performed ? "done" : (d.skipped ? "skip" : (d.error.empty() ? "dry" : "fail"));
    const std::string why = d.error.empty() ? d.reason : d.error;
    if (o.json) {
      // A live capture never reaches the summary, so every decision is its own
      // event; a file run still gets the complete `block` object at the end.
      JsonObj j("block");
      j.str("state", std::string(state));
      j.str("mode", d.mode);
      j.str("target", d.target);
      j.str("process", d.process);
      j.num("pid", (long long)d.pid);
      j.str("reason", d.reason);
      j.str("error", d.error);
      j.num("ts_us", (long long)d.ts_us);
      j.finish();
      emit_json_line(stdout, j.s);
    }
    std::string who = d.target;
    if (!d.process.empty()) who += "  " + d.process;
    std::fprintf(log, "block  %-4s %-7s %-48s %s\n", state, d.mode.c_str(), who.c_str(),
                 why.c_str());
    std::fflush(log);
  };

  for (;;) {
    if (g_stop) break;
    PacketView v;
    if (!cap->next(v)) {
      if (!cap->error().empty()) {
        std::fprintf(stderr, "netcap: capture error: %s\n", cap->error().c_str());
        break;
      }
      if (cap->eof()) break;
      const i64 now = now_monotonic_us();
      if (now - last_gc > 1000000) {
        dissector.gc(now);
        last_gc = now;
      }
      continue;
    }

    ++seen;
    PacketInfo pi;
    const bool ok = dissector.dissect(v, pi);
    if (pi.malformed) ++malformed;

    AppInfo app{};
    if (ok) classify_app(pi, app);

    // Every dissected packet goes to the reassembler, whatever the filter says:
    // a filter that dropped half a stream would leave holes in the byte stream.
    // The filter still decides which packets are logged.
    if (ok) analyzer.feed(pi, v.ts_us);

    ProcOwnership own;
    if (want_attrib) own = attributor.attribute(pi, v.ts_us);

    // Behind a local proxy the socket belongs to the proxy process, so the
    // interesting answer is the application that asked for the traffic.  The
    // link is only accepted when the packet's owner really is the proxy end of
    // that pair; anything else would invent a relationship.
    const ProxyLink* origin = nullptr;
    if (want_proxy && own.known && pi.has_ports && pi.ip_version) {
      const ProxyLink* l = proxy_table.link(pi.ip_version, pi.dst_ip, pi.dst_port);
      if (!l) l = proxy_table.link(pi.ip_version, pi.src_ip, pi.src_port);
      if (l && l->proxy_pid == own.proc.pid) origin = l;
      // Host names we can read in the clear make the pairing exact instead of a
      // guess: the application's request (or the proxy's own handshake) names
      // the host it wants.
      if (const char* host = app_hostname(app)) {
        if (host[0] != '\0') {
          const u8* peer = own.dir == 0 ? pi.dst_ip : pi.src_ip;
          const u16 peer_port = own.dir == 0 ? pi.dst_port : pi.src_port;
          if (proxy_table.is_proxy_pid(own.proc.pid)) {
            proxy_table.note_outbound_host(pi.ip_version, peer, peer_port, host);
          } else {
            proxy_table.note_client_host(pi.ip_version, pi.src_ip, pi.src_port, host);
          }
        }
      }
    }

    if (block_on &&
        block_filter.match(pi, &app, own.known ? &own.proc : nullptr, origin)) {
      const ProcessInfo* bp = own.known ? &own.proc : nullptr;
      report_block(blocker.act(pi, bp, own.known ? own.dir : -1, now_monotonic_us()));
    }

    if (!filter.match(pi, &app, own.known ? &own.proc : nullptr, origin)) continue;

    ++matched;
    bytes += v.len;
    bump(counters, ok ? app.kind : AppKind::Unknown, v.len);
    if (own.known) proc_totals.add_packet(own.proc, v.len);

    if (o.json) emit_json_line(stdout, json_packet_line(matched, v, pi, app, own, origin, o));
    else if (!o.quiet) print_packet(log, v, pi, app, own, origin, o);

    if (o.follow) {
      for (const HttpRecord& r : analyzer.take_completed()) {
        if (o.json) emit_json_line(stdout, json_http_record(r));
        else print_http_line(log, r);
      }
    }
    if (splitter.is_open()) {
      // One file per process, per application, or per *real* application behind
      // a local proxy.  A packet that cannot be keyed still gets recorded, under
      // "unattributed" / "other".
      std::string key;
      switch (split_mode) {
        case SplitMode::Proc:
          key = split_key_proc(own.known ? &own.proc : nullptr);
          break;
        case SplitMode::Origin:
          key = split_key_origin(origin, own.known ? &own.proc : nullptr);
          break;
        case SplitMode::App:
        case SplitMode::Off:
          key = split_key_app(ok ? app.kind : AppKind::Unknown);
          break;
      }
      std::string werr;
      if (!splitter.write(key, v, &werr)) {
        std::fprintf(stderr, "netcap: %s\n", werr.c_str());
        break;
      }
      ++written;
      if (written % 4096 == 0) splitter.flush();
    } else if (writer.is_open()) {
      std::string werr;
      if (!writer.write(v, &werr)) {
        std::fprintf(stderr, "netcap: %s\n", werr.c_str());
        break;
      }
      ++written;
      if (written % 4096 == 0) writer.flush();
    }

    if (o.count > 0 && matched >= u64(o.count)) break;
    if (g_stop) break;
  }

  writer.close();
  if (splitter.is_open()) {
    std::string serr;
    splitter.flush();
    if (!splitter.close(&serr)) std::fprintf(stderr, "netcap: %s\n", serr.c_str());
  }
  dissector.gc(now_monotonic_us());
  analyzer.finish();
  if (o.follow) {
    // A file capture ends with transactions still open; report what completed.
    for (const HttpRecord& r : analyzer.take_completed()) {
      if (o.json) emit_json_line(stdout, json_http_record(r));
      else print_http_line(log, r);
    }
  }

  const CaptureStats st = cap->stats();
  std::fprintf(log, "\n--- summary ---\n");
  std::fprintf(log, "packets seen        : %llu\n", (unsigned long long)seen);
  std::fprintf(log, "packets matching    : %llu\n", (unsigned long long)matched);
  std::fprintf(log, "bytes matching      : %llu\n", (unsigned long long)bytes);
  std::fprintf(log, "malformed frames    : %llu\n", (unsigned long long)malformed);
  std::fprintf(log, "source packets      : %llu (backend total)\n", (unsigned long long)st.packets);
  if (st.kernel_stats) {
    std::fprintf(log, "kernel drops        : %llu\n", (unsigned long long)st.dropped);
  }
  std::fprintf(log, "ipv4 reassembly     : %llu datagram(s) seen, %llu reassembled, %llu dropped, %zu pending\n",
               (unsigned long long)dissector.fragments_seen(),
               (unsigned long long)dissector.fragments_completed(),
               (unsigned long long)dissector.fragments_dropped(),
               dissector.pending_fragments());
  if (writer.is_open() || written) {
    std::fprintf(log, "records written     : %llu to %s\n", (unsigned long long)written,
                 o.write_path.c_str());
  }

  const AnalyzeStats as = analyzer.stats();
  if (as.streams > 0 || as.tls_streams > 0 || as.transactions > 0) {
    std::fprintf(log,
                 "tcp streams         : %llu (%llu TLS, %llu decrypted, %llu HTTP/1.1, %llu HTTP/2)\n",
                 (unsigned long long)as.streams, (unsigned long long)as.tls_streams,
                 (unsigned long long)as.decrypted_streams, (unsigned long long)as.http1_streams,
                 (unsigned long long)as.http2_streams);
    std::fprintf(log, "http transactions   : %llu (%llu decrypted, %llu HTTP/2)\n",
                 (unsigned long long)as.transactions,
                 (unsigned long long)as.decrypted_transactions,
                 (unsigned long long)as.http2_transactions);
    if (as.keys_loaded) {
      std::fprintf(log, "key log             : %zu secret(s) from %s\n", as.keylog_entries,
                   o.keylog.c_str());
    } else if (as.tls_streams > 0) {
      std::fprintf(log, "key log             : none - pass --keylog <file> to decrypt TLS\n");
    }
  }
  if (o.show_streams) {
    std::fprintf(log, "\n");
    print_streams(log, analyzer.streams());
  }
  if (o.show_http && !o.follow) {
    std::fprintf(log, "\n");
    print_http_records(log, analyzer.http());
  }

  if (!counters.empty()) {
    std::fprintf(log, "--- applications ---\n");
    for (std::size_t i = 0; i < counters.size(); ++i) {
      for (std::size_t j = i + 1; j < counters.size(); ++j) {
        if (counters[j].packets > counters[i].packets) std::swap(counters[i], counters[j]);
      }
    }
    for (const AppCounter& c : counters) {
      if (c.kind == AppKind::Unknown) continue;
      std::fprintf(log, "%-8s %8llu packets %10llu bytes\n", app_kind_name(c.kind),
                   (unsigned long long)c.packets, (unsigned long long)c.bytes);
    }
    for (const AppCounter& c : counters) {
      if (c.kind != AppKind::Unknown) continue;
      std::fprintf(log, "%-8s %8llu packets %10llu bytes\n", "other", (unsigned long long)c.packets,
                   (unsigned long long)c.bytes);
    }
  }

  if (!proc_totals.empty()) {
    const std::vector<ProcCounters> ranked = proc_totals.sorted();
    std::fprintf(log, "--- processes (%zu) ---\n", ranked.size());
    for (const ProcCounters& pc : ranked) {
      std::fprintf(log, "%-28s %8llu packets %10llu bytes\n", pc.label().c_str(),
                   (unsigned long long)pc.packets, (unsigned long long)pc.bytes);
    }
  }

  if (want_proxy) {
    // The proxy story gets its own block: which local proxy was found, which
    // applications asked it for traffic, and which pairs are only guesses.
    std::fprintf(log, "--- proxy correlation ---\n");
    const std::string rep = proxy_table.report();
    std::fputs(rep.c_str(), log);
  }

  if (splitter.key_count() > 0) {
    std::vector<SplitEntry> ranked = splitter.entries();
    for (std::size_t i = 0; i < ranked.size(); ++i) {
      for (std::size_t j = i + 1; j < ranked.size(); ++j) {
        if (ranked[j].bytes > ranked[i].bytes) std::swap(ranked[i], ranked[j]);
      }
    }
    std::fprintf(log, "--- split files (%zu) ---\n", ranked.size());
    for (const SplitEntry& e : ranked) {
      std::fprintf(log, "%-40s %8llu packets %10llu bytes\n", e.file.c_str(),
                   (unsigned long long)e.packets, (unsigned long long)e.bytes);
    }
    const char sep =
#ifdef _WIN32
        '\\';
#else
        '/';
#endif
    std::fprintf(log, "manifest            : %s%cindex.json\n", splitter.directory().c_str(),
                 sep);
  }

  if (block_on) {
    std::fprintf(log,
                 "--- interception (%llu matched, %llu attempted, %llu done, %llu failed, "
                 "%llu skipped) ---\n",
                 (unsigned long long)blocker.matched(), (unsigned long long)blocker.attempts(),
                 (unsigned long long)blocker.successes(), (unsigned long long)blocker.failures(),
                 (unsigned long long)blocker.skipped());
    std::fprintf(log, "block policy        : %s\n", blocker.describe().c_str());
    if (!blocker.last_error().empty())
      std::fprintf(log, "block last error    : %s\n", blocker.last_error().c_str());
  }

  if (o.json) {
    JsonObj j("summary");
    j.unum("seen", seen);
    j.unum("matched", matched);
    j.unum("bytes", bytes);
    j.unum("malformed", malformed);
    j.unum("source_packets", st.packets);
    j.boolean("kernel_stats", st.kernel_stats);
    j.unum("kernel_drops", st.dropped);
    j.unum("frag_seen", dissector.fragments_seen());
    j.unum("frag_completed", dissector.fragments_completed());
    j.unum("frag_dropped", dissector.fragments_dropped());
    j.unum("frag_pending", (unsigned long long)dissector.pending_fragments());
    j.unum("streams", as.streams);
    j.boolean("reassembly", analyzer.reassembly());
    j.unum("tls_streams", as.tls_streams);
    j.unum("decrypted_streams", as.decrypted_streams);
    j.unum("http1_streams", as.http1_streams);
    j.unum("http2_streams", as.http2_streams);
    j.unum("http_transactions", as.transactions);
    j.unum("http_decrypted_transactions", as.decrypted_transactions);
    j.unum("http2_transactions", as.http2_transactions);
    j.unum("reassembled_bytes", as.reassembled_bytes);
    j.boolean("keys_loaded", as.keys_loaded);
    j.unum("keylog_entries", as.keylog_entries);
    j.unum("written", written);
    j.str("write_path", o.write_path);
    j.str("split_by", o.split_by);
    {
      std::string files = "[";
      const std::vector<SplitEntry>& se = splitter.entries();
      for (std::size_t i = 0; i < se.size(); ++i) {
        if (i) files += ',';
        files += "{\"key\":";
        files += json_str(se[i].key);
        files += ",\"file\":";
        files += json_str(se[i].file);
        files += ",\"packets\":";
        files += std::to_string((unsigned long long)se[i].packets);
        files += ",\"bytes\":";
        files += std::to_string((unsigned long long)se[i].bytes);
        files += '}';
      }
      files += ']';
      j.raw("split_files", files);
    }
    j.boolean("interrupted", g_stop != 0);
    {
      std::string bl = "{\"enabled\":";
      bl += block_on ? "true" : "false";
      bl += ",\"mode\":";
      bl += json_str(blocker.config().mode == BlockMode::DryRun ? "dry-run"
                                                                : block_mode_name(blocker.config().mode));
      bl += ",\"matched\":";
      bl += std::to_string((unsigned long long)blocker.matched());
      bl += ",\"attempted\":";
      bl += std::to_string((unsigned long long)blocker.attempts());
      bl += ",\"performed\":";
      bl += std::to_string((unsigned long long)blocker.successes());
      bl += ",\"failed\":";
      bl += std::to_string((unsigned long long)blocker.failures());
      bl += ",\"skipped\":";
      bl += std::to_string((unsigned long long)blocker.skipped());
      bl += ",\"last_error\":";
      bl += json_str(blocker.last_error());
      bl += ",\"actions\":[";
      const std::vector<BlockDecision>& ds = blocker.decisions();
      for (std::size_t i = 0; i < ds.size(); ++i) {
        if (i) bl += ',';
        bl += "{\"target\":";
        bl += json_str(ds[i].target);
        bl += ",\"process\":";
        bl += json_str(ds[i].process);
        bl += ",\"pid\":";
        bl += std::to_string((unsigned long long)ds[i].pid);
        bl += ",\"mode\":";
        bl += json_str(ds[i].mode);
        bl += ",\"performed\":";
        bl += ds[i].performed ? "true" : "false";
        bl += ",\"skipped\":";
        bl += ds[i].skipped ? "true" : "false";
        bl += ",\"reason\":";
        bl += json_str(ds[i].reason);
        bl += ",\"error\":";
        bl += json_str(ds[i].error);
        bl += '}';
      }
      bl += "]}";
      j.raw("block", bl);
    }
    std::string apps = "[";
    for (std::size_t i = 0; i < counters.size(); ++i) {
      if (i) apps += ',';
      apps += "{\"kind\":";
      apps += json_str(app_kind_tag(counters[i].kind));
      apps += ",\"name\":";
      apps += json_str(app_kind_name(counters[i].kind));
      apps += ",\"packets\":";
      apps += std::to_string((unsigned long long)counters[i].packets);
      apps += ",\"bytes\":";
      apps += std::to_string((unsigned long long)counters[i].bytes);
      apps += '}';
    }
    apps += ']';
    j.raw("apps", apps);
    j.boolean("attribution", want_attrib);
    {
      const std::vector<ProcCounters> ranked = proc_totals.sorted();
      std::string procs = "[";
      for (std::size_t i = 0; i < ranked.size(); ++i) {
        if (i) procs += ',';
        procs += "{\"pid\":";
        procs += std::to_string((unsigned long long)ranked[i].pid);
        procs += ",\"name\":";
        procs += json_str(ranked[i].name);
        procs += ",\"label\":";
        procs += json_str(ranked[i].label());
        procs += ",\"packets\":";
        procs += std::to_string((unsigned long long)ranked[i].packets);
        procs += ",\"bytes\":";
        procs += std::to_string((unsigned long long)ranked[i].bytes);
        procs += ",\"flows\":";
        procs += std::to_string((unsigned long long)ranked[i].flows);
        procs += ",\"transactions\":";
        procs += std::to_string((unsigned long long)ranked[i].transactions);
        procs += '}';
      }
      procs += ']';
      j.raw("procs", procs);
    }
    // Proxy correlation: the applications behind a local proxy.  The confidence
    // of every link travels with it, so a consumer can tell a guess from a fact.
    {
      std::string pj = "{\"enabled\":";
      pj += want_proxy ? "true" : "false";
      pj += ",\"processes\":";
      pj += std::to_string((unsigned long long)proxy_table.proxy_processes());
      pj += ",\"client_sockets\":";
      pj += std::to_string((unsigned long long)proxy_table.clients().size());
      pj += ",\"outbound_connections\":";
      pj += std::to_string((unsigned long long)proxy_table.outbounds().size());
      pj += ",\"matched\":";
      pj += std::to_string((unsigned long long)proxy_table.paired());
      pj += ",\"proxies\":[";
      const std::vector<ProxyEndpoint>& eps = proxy_table.endpoints();
      for (std::size_t i = 0; i < eps.size(); ++i) {
        if (i) pj += ',';
        pj += "{\"pid\":";
        pj += std::to_string((unsigned long long)eps[i].pid);
        pj += ",\"name\":";
        pj += json_str(eps[i].name);
        pj += ",\"endpoint\":";
        pj += json_str(format_ip(eps[i].family, eps[i].addr) + ":" + std::to_string(eps[i].port));
        pj += '}';
      }
      pj += "],\"links\":[";
      bool first = true;
      for (const ProxyOutbound& ob : proxy_table.outbounds()) {
        const ProxyLink* l = proxy_table.link(ob.family, ob.raddr, ob.rport);
        if (!l) continue;
        if (!first) pj += ',';
        first = false;
        pj += "{\"proxy\":";
        pj += json_str(l->proxy_name);
        pj += ",\"proxy_pid\":";
        pj += std::to_string((unsigned long long)l->proxy_pid);
        pj += ",\"origin\":";
        pj += json_str(l->origin_name);
        pj += ",\"origin_pid\":";
        pj += std::to_string((unsigned long long)l->origin_pid);
        pj += ",\"peer\":";
        pj += json_str(format_ip(l->family, l->raddr) + ":" + std::to_string(l->rport));
        pj += ",\"confidence\":";
        pj += json_str(proxy_confidence_name(l->confidence));
        pj += ",\"basis\":";
        pj += json_str(l->basis);
        pj += '}';
      }
      pj += "]}";
      j.raw("proxy", pj);
    }
    j.finish();
    emit_json_line(stdout, j.s);
    if (o.show_streams) {
      for (const StreamReport& s : analyzer.streams()) emit_json_line(stdout, json_stream_report(s));
    }
    if (o.show_http && !o.follow) {
      for (const HttpRecord& r : analyzer.http()) emit_json_line(stdout, json_http_record(r));
    }
  }

  if (g_stop) std::fprintf(log, "\ninterrupted\n");
  // A failed interception is not the same as a quiet run: say so in the status.
  if (block_on && blocker.failures() > 0) return 4;
  return 0;
}

}  // namespace netcap

int main(int argc, char** argv) { return netcap::run(argc, argv); }
