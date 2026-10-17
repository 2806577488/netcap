// netcap - local interception proxy.
//
// This is the module that actually changes what the browser sees.  It is a
// plain HTTP/HTTPS proxy bound to a loopback address: point a browser (or the
// operating system) at it and every request passes through the rule engine
// before it reaches the network.
//
//   * plain HTTP   - the full URL is visible, so `||ads.example.com^`,
//                    `/banner/*`, `$removeparam=` and `$redirect=` all work.
//   * HTTPS        - only the host name is visible (CONNECT).  A matching rule
//                    is answered locally, everything else is tunnelled through
//                    untouched.  Full URL filtering for HTTPS needs the
//                    man-in-the-middle mode and a locally trusted CA.
//
// Deliberate design choices:
//   * No third-party code and no threads inside the rule path: the RuleSet is
//     read-only once the blocker starts, so any number of worker threads can
//     consult it without locking.
//   * `serve_once()` handles at most one pending connection on the calling
//     thread.  That is what the self-test uses, so the whole proxy can be
//     exercised without timing games.  `run()` is the threaded version used by
//     the CLI.
//   * Every decision is recorded as an InterceptEvent, so "why did this page
//     break" is always answerable.

#pragma once

#include <cstddef>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/origin.hpp"

namespace netcap {

class RuleSet;
struct RuleDecision;

enum class InterceptAction : std::uint8_t {
  Pass = 0,   // forwarded untouched
  Block,      // answered locally, nothing sent upstream
  Modify,     // forwarded with a rewritten request
  Redirect,   // answered with a redirect to a stub resource
  Tunnel,     // CONNECT: bytes piped through, contents not inspected
  Error,      // malformed request or upstream failure
  // The client hung up before we could hand it the response.  Browsers do this
  // all the time: a redirect chain supersedes the request that started it, a
  // tab is closed, a prefetch is dropped.  It is a fact about the client, not a
  // failure of the proxy, so it gets its own name instead of landing in `Error`
  // (which is what made a perfectly healthy log read as if everything broke).
  Cancelled,
};

const char* intercept_action_name(InterceptAction action);

struct BlockerConfig {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 8080;        // 0 lets the OS pick one (tests rely on it)
  std::size_t max_clients = 64;     // threads in flight in run()
  int io_timeout_ms = 15000;
  int connect_timeout_ms = 8000;
  std::size_t max_head_bytes = 65536;
  std::string stub_body;            // body served for blocked documents
  std::size_t log_limit = 4096;     // events kept in memory
  bool verbose = false;
  // Strip the Cookie header from requests whose site differs from the page that
  // asked (from Referer, then Origin).  This is "block third-party cookies"; it
  // never looks inside the cookie string, it only decides whether to send one.
  bool block_third_party_cookies = false;
  // Element picker ("point at an element and block it").  While it is on, every
  // text/html document gets one extra script: it highlights whatever the mouse
  // is over and, on click, hands the selector to this proxy (a request to
  // `/__netcap/pick`, answered locally and never forwarded).  A picked selector
  // is hidden in later responses for that host straight away, and appended to
  // `picker_rules` as a real element-hiding rule so the decision outlives the
  // process.  The interface flips it while the proxy runs by creating or
  // removing `picker_flag` (the serve loop polls that file).
  bool picker = false;
  std::string picker_rules;  // list file picked rules are appended to
  std::string picker_flag;   // file whose existence means "picker on"
  // Procedural cosmetics: `#?#` rules and any selector using `:has()`,
  // `:upward()`, `:contains()` or a `{ remove: true; }` block.  No stylesheet can
  // express those, so a page that has one gets a small engine (`/__netcap/
  // cosmetic.js`, served by this proxy) plus the compiled selectors.  Turning it
  // off means those rules are read, counted, and never applied — `--no-procedural`
  // is for the case where running any script in the page is the part that is not
  // wanted.
  bool procedural_cosmetics = true;
  // Man-in-the-middle mode: CONNECT requests are terminated with a certificate
  // signed on the fly by the local CA in `ca_cert_path` / `ca_key_path`, so the
  // rule engine sees full HTTPS URLs instead of just the host name.  The CA must
  // be trusted by the client (installing it is the user's decision, see the
  // README) and `mitm_insecure` decides what happens when the origin itself
  // cannot be verified: false aborts the request with an explanation, true
  // forwards it anyway and records a warning.
  bool mitm = false;
  bool mitm_insecure = false;
  std::string ca_cert_path = "netcap-ca.crt";
  std::string ca_key_path = "netcap-ca.key";
  // Per-application HTTPS decryption policy.  `mitm_skip` names processes that
  // must keep a plain tunnel even while `mitm` is on (banking apps, certificate
  // pinning, ...); `mitm_only` names processes to decrypt even while `mitm` is
  // off.  Matching is a case-insensitive substring of the image name or path,
  // the same rule the `proc` filter keyword uses.  See MitmPolicy below.
  std::vector<std::string> mitm_skip;
  std::vector<std::string> mitm_only;
  // What to do when the *client* refuses our leaf.  A browser trusts the CA the
  // user installed; a runtime that carries its own trust store (Node.js, Go,
  // Rust, anything that pins certificates) drops the connection the moment it
  // has seen the certificate, and while netcap holds the system proxy, retrying
  // only breaks that application again.  Default (false): an application that
  // refuses our certificate for a host name is remembered, and that pair is
  // tunnelled without decryption from then on - the connection keeps working,
  // host-name rules still apply, and only the inside of its requests is no
  // longer inspected.  true: never tunnel for that reason, such connections
  // keep failing instead.
  bool mitm_strict = false;
  // Chain every upstream connection through an HTTP proxy ("host:port") instead
  // of dialling origins directly.  This is what makes a system-proxy takeover
  // safe on a machine whose traffic already goes through a local proxy (Clash,
  // v2ray, ...): without it the takeover would *remove* that proxy from the
  // path and cut the machine off the network.  Empty means "go direct".
  std::string upstream_proxy;
  // Multi-address origins.  A host name usually resolves to several addresses
  // and the resolver's order has nothing to do with which one is close to this
  // machine, so `Best` measures them once (a short connect race), remembers the
  // round trip time of each and then dials the fastest one directly.  `First`
  // keeps the resolver's order and never measures.
  OriginPolicy origin_policy = OriginPolicy::Best;
  int origin_race = 2;          // addresses started before the first one answers
  int origin_stagger_ms = 250;  // delay between two starts inside one race
  int origin_ttl_s = 300;       // re-measure a host after this long
};

// Decides, per connection, whether HTTPS is terminated (decrypted) or tunnelled
// untouched.  The default follows the global switch: with `--mitm` every
// application is decrypted except the ones in `skip`.  With `--mitm` off only
// the applications named in `only` are decrypted, which is how a single app can
// be enabled without turning the feature on for the whole machine.
struct MitmPolicy {
  bool global_on = false;
  std::vector<std::string> skip;
  std::vector<std::string> only;

  // `proc_name` may be empty when the client cannot be attributed to a process;
  // an empty name can never match `skip` or `only`, so the global switch decides.
  bool wants(const std::string& proc_name) const;
  // "decrypt"/"tunnel" plus the reason, for logs and the UI.
  std::string reason(const std::string& proc_name) const;
  std::string describe() const;
  bool empty() const { return !global_on && skip.empty() && only.empty(); }
};

// Splits "chrome.exe,firefox|msedge" into its parts (comma or pipe separated,
// trimmed, empty parts dropped).  The CLI and the UI both produce this shape.
std::vector<std::string> split_name_list(const std::string& text);

// True when `name` contains any of `patterns` (case-insensitive substring).
bool name_matches_any(const std::vector<std::string>& patterns, const std::string& name);

struct InterceptEvent {
  i64 ts_us = 0;
  InterceptAction action = InterceptAction::Pass;
  std::string method;   // GET, POST, CONNECT, ...
  std::string url;      // what the rule engine was asked about
  std::string host;     // host[:port] the request was aimed at
  std::string client;   // peer address
  std::string rule;     // text of the rule that decided it, when there was one
  std::string detail;   // "removeparam=utm_source", "upstream connect failed", ...
  int status = 0;       // status sent to the client
  u64 request_bytes = 0;
  u64 response_bytes = 0;
  bool decrypted = false;  // the request came out of a man-in-the-middle TLS session
  std::string client_proc; // image name of the application behind the connection
  std::string mitm;        // "on" (terminated), "skip" (policy said no), "off"
  std::string origin_ip;   // address the upstream connection was really made to
  i64 origin_rtt_us = -1;  // measured connect time for it, -1 when unknown
};

struct BlockerStats {
  u64 connections = 0;
  u64 requests = 0;
  u64 blocked = 0;
  u64 modified = 0;
  u64 redirected = 0;
  u64 passed = 0;
  u64 tunnels = 0;
  u64 errors = 0;
  u64 cancelled = 0;  // the client went away before we sent the response
  u64 bytes_in = 0;     // client -> blocker
  u64 bytes_out = 0;    // blocker -> client
  u64 decrypted = 0;    // CONNECT requests terminated with our own certificate
  u64 mitm_failures = 0;  // handshake or origin verification failures in that mode
  u64 mitm_skipped = 0;   // CONNECT requests left as plain tunnels by the per-app policy
  // Browsers open speculative connections (preconnect) and close the ones they
  // never use before sending a ClientHello.  That is normal client behaviour,
  // so it is counted here and deliberately not reported as an error.
  u64 mitm_preconnect = 0;
  // (application, host name) pairs taken out of decryption because the client
  // refused our certificate (see `mitm_strict`).
  u64 mitm_client_refusals = 0;
  u64 origin_resolves = 0;  // host names resolved while choosing an upstream
  u64 origin_races = 0;     // connect races run because nothing had been measured
  u64 origin_measured = 0;  // addresses that answered inside those races
  u64 origin_failovers = 0; // times the remembered fastest address did not answer
};

class InterceptProxy {
 public:
  InterceptProxy();
  ~InterceptProxy();
  InterceptProxy(const InterceptProxy&) = delete;
  InterceptProxy& operator=(const InterceptProxy&) = delete;

  // The RuleSet must outlive the blocker; nullptr means "block nothing", which
  // is useful when the caller only wants the pass-through statistics.
  bool start(const BlockerConfig& cfg, const RuleSet* rules, std::string* error);
  // Optional hook used by the per-application HTTPS policy: maps the peer of an
  // accepted connection ("127.0.0.1", 53211) to the image name of the process
  // that owns it.  Returning an empty string means "unknown", which makes the
  // global switch alone decide.  Install it before start().
  void set_client_resolver(
      std::function<std::string(const std::string& address, std::uint16_t port)> resolver);
  void stop();
  bool running() const;
  // Element picker, switchable while the proxy runs.  `set_picker` returns the
  // previous state.  `picked_elements` lists what has been picked so far as
  // "host##selector" (for the interface and the tests; the rule file on disk is
  // the durable record).
  bool set_picker(bool on);
  bool picker() const;
  // Self-test hook: pins what the upstream TLS probe would report for host:port.
  // The client-facing handshake only runs when the origin is believed to speak
  // TLS, and a self-test cannot make a real origin present a certificate our own
  // probe would accept, so it states the verdict instead of dialling anything.
  // `ability` of -1 clears the pin and any cached verdict.
  void set_origin_tls_ability(const std::string& host, std::uint16_t port, int ability);
  std::vector<std::string> picked_elements() const;
  std::uint16_t port() const;
  std::string bound_endpoint() const;
  const std::string& error() const;

  // Handles at most one pending connection.  Returns true when a connection
  // was accepted and fully served on this thread.
  bool serve_once(int timeout_ms);

  // Accepts until stop() is called.  Blocks the calling thread; each accepted
  // connection is served on its own worker thread.
  void run();

  std::vector<InterceptEvent> events() const;
  BlockerStats stats() const;
  std::string url_for_event(std::size_t index) const;
  std::string report() const;
  std::string describe() const;

 private:
  struct Impl;
  Impl* impl_;
};

// Exposed for the self-test and for callers that want the same parsing the
// proxy uses: splits a request target into the pieces the rule engine needs.
struct RequestTarget {
  std::string url;     // absolute URL handed to the rule engine
  std::string host;    // host name without the port
  std::uint16_t port = 0;
  std::string path;    // path + query, as sent upstream
  bool secure = false;
};

// `target` is the request target as it appeared on the request line; `host`
// is the value of the Host: header (may be empty).
RequestTarget parse_request_target(const std::string& method, const std::string& target,
                                   const std::string& host);

// Removes the query parameters named in `spec` ("a|b", or "*" for the built-in
// tracker list) from a path+query string.  Returns true when something changed.
bool strip_query_parameters(std::string* path, const std::string& spec);

// The parameter names `$removeparam` with no value strips.
const char* const* tracker_parameter_names(std::size_t* count);

// Removes every header line whose name equals `lower_name` (lower case) from a
// raw request head, keeping the request line, the other headers, the blank line
// and any body.  Returns how many lines were removed (0 = head left untouched).
std::size_t strip_header(std::string* head, const std::string& lower_name);

// The page a request belongs to: the host from Referer (preferred) or Origin,
// lower case, without userinfo, port or path.  Empty when neither is usable,
// which is the usual case for a top-level navigation.
std::string request_document_host(const std::string& head);

}  // namespace netcap
