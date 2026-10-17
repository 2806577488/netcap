// Ad blocking rules: Adblock Plus / uBlock style filter lists plus hosts files.
//
// netcap started as a capture and analysis tool.  Its job now is to *change* the
// traffic, so this is the decision layer: which request is an advertisement,
// which one is allowed by an exception, and which one must be rewritten rather
// than blocked.
//
// The syntax understood here is the subset that matters for a network blocker:
//
//   ||ads.example.com^          block anything served from that domain
//   ||example.com/ads/*         wildcards inside a domain-anchored pattern
//   |http://example.com/banner  anchored at the very start of the URL
//   /ads/track.js|              anchored at the very end of the URL
//   -advertisement-             plain substring, anywhere in the URL
//   @@||example.com^$document   an exception (allow) rule
//   ||example.com^$third-party,script,image
//   ||example.com^$~script      every type except a script ($~ = "not")
//   ||example.com^$domain=news.example|~mail.example
//   ||example.com^$removeparam=utm_source      rewrite instead of block
//   ||example.com^$redirect=noop.js            redirect instead of block
//   ||example.com^$csp=script-src 'none'       add or replace a response header
//   ||example.com^$removeheader=refresh        drop a response header
//   ||example.com^$removecookie=tracker        drop one Set-Cookie
//   ||ads.example.com^$replace=/banner/ad/gi   edit the response body (regex)
//   ||example.com^$css=body{display:none}      inject a <style> before </head>
//   ||example.com^$script=console.log(1)       inject a <script> before </head>
//   0.0.0.0 ads.example.com     hosts file syntax: block that host
//   ! comment                   and [Adblock Plus 2.0] headers are skipped
//
// A rule whose only options are response-side ones does not block the request:
// it lets it through and edits the answer.  That matches how AdGuard treats
// `$replace`/`$csp`, and it means one line can never both block and rewrite.
//
// Anything this engine does not understand is counted and skipped, never
// silently treated as a block rule: a filter list must not be able to take the
// network down because of one unrecognised line.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "netcap/cosmetic.hpp"
#include "netcap/rewrite.hpp"

namespace netcap {

/// What kind of resource the browser is asking for.  The names match the
/// `$type` options of Adblock Plus.
enum class ResourceType : std::uint8_t {
  Other = 0,
  Document,
  Subdocument,
  Script,
  Image,
  Stylesheet,
  XmlHttpRequest,
  Font,
  Media,
  WebSocket,
  Ping,
  Object,
};

const char* resource_type_name(ResourceType type);
/// `$script`, `$image`, ... (case-insensitive, several aliases each).
bool resource_type_from_string(const std::string& text, ResourceType* out);
/// Best-effort guess from a URL path plus the response content type, which is
/// all a proxy knows for sure.
ResourceType resource_type_from_path(const std::string& path,
                                     const std::string& content_type = std::string());

/// What the engine wants done with one request.
enum class RuleAction : std::uint8_t { None = 0, Block, Allow, Modify, Redirect };
const char* rule_action_name(RuleAction action);

/// One parsed filter list line.
struct Rule {
  /// Original text, for logs and for the user interface.
  std::string raw;
  /// Pattern without `@@`, without the `$options` tail.
  std::string pattern;
  bool allow = false;          ///< `@@` exception
  bool important = false;      ///< `$important`: beats an exception
  bool match_case = false;     ///< `$match-case`
  bool domain_anchor = false;  ///< `||` in front
  bool start_anchor = false;   ///< `|` in front
  bool end_anchor = false;     ///< `|` at the end
  bool plain_substring = false;///< no `*`, no `^`, no anchors: use a fast find
  /// `$badfilter`: this line does not block anything by itself, it switches off
  /// the rules that look exactly like it (same pattern, same options, minus this
  /// one).  uBlock's fix lists are built entirely out of these.
  bool badfilter = false;
  /// Set by apply_badfilters() when some `$badfilter` line named this rule.
  bool disabled = false;
  /// Type options; empty means "any type".
  std::vector<ResourceType> types;
  /// `$~script`, `$~image`, ...: types this rule must not be used for.
  std::vector<ResourceType> exclude_types;
  bool third_party = false;    ///< `$third-party` was given
  bool first_party = false;    ///< `$first-party` was given
  std::vector<std::string> include_domains;  ///< `$domain=a|b`
  std::vector<std::string> exclude_domains;  ///< `$domain=~c`
  std::string removeparam;     ///< `$removeparam=utm_source` -> Modify
  std::string redirect;        ///< `$redirect=noop.js`     -> Redirect
  /// Response-side rewriting (`$csp`, `$header`, `$removeheader`, `$removecookie`,
  /// `$replace`, `$css`, `$script`).  A rule that carries only these never blocks
  /// the request: it lets it through and edits what comes back.
  std::vector<std::string> set_headers;      ///< "Name: value" pairs to add or replace
  std::vector<std::string> remove_headers;   ///< header names to drop
  std::vector<std::string> remove_cookies;   ///< Set-Cookie names to drop, "*" = all
  std::vector<RewriteReplace> replaces;      ///< `$replace=/pattern/replacement/`
  std::vector<std::string> inject_css;       ///< `$css=...`: <style> before </head>
  std::vector<std::string> inject_script;    ///< `$script=...`: <script> before </head>
  /// Longest literal run inside the pattern, lower case.  Every match must
  /// contain it, so it lets the engine skip the rule without running the
  /// wildcard matcher.  See the literal index in RuleSet.
  std::string literal;
  /// First four bytes of `literal` packed little-endian; 0 means "not indexed",
  /// which is the case for very short literals and for patterns that are only
  /// wildcards.
  std::uint32_t literal_key = 0;
  std::uint32_t line = 0;
  std::size_t index = 0;

  RuleAction action() const;
  /// True when this rule carries a condition the URL alone cannot answer.
  bool needs_context() const;
  /// True when the rule edits the response at all.
  bool has_response_modifiers() const;
  /// True when editing the response is the *only* thing the rule does, which
  /// means it must not be read as a block rule (matching AdGuard's semantics).
  bool is_response_only() const;
};

/// Why a rule was ignored; kept so the user can see what a list asked for.
struct SkippedRule {
  std::uint32_t line = 0;
  std::string text;
  std::string reason;
};

/// Statistics for one loaded list, and for the whole rule set.
struct RuleStats {
  std::size_t lines = 0;
  std::size_t block_rules = 0;
  std::size_t allow_rules = 0;
  std::size_t response_rules = 0; ///< rules that only rewrite the response
  std::size_t element_hide = 0;
  std::size_t comments = 0;
  std::size_t skipped = 0;
  std::size_t badfilter_rules = 0; ///< `$badfilter` lines that switched rules off
  std::size_t host_rules = 0;   ///< indexed by host name
  std::size_t generic_rules = 0;///< scanned linearly
};

/// One element-hiding rule: `##selector`, with `#@#selector` as the exception
/// form.  Cosmetics are not network rules — nothing is blocked, the element is
/// simply hidden — so they live outside `rules_` and are turned into a single
/// CSS injection for the page that carries them (`RuleSet::cosmetic_css`).
///
/// A rule whose selector needs the page's own DOM (`:has()`, `:upward()`, …) or
/// which carries declarations a stylesheet cannot apply (`{ remove: true; }`)
/// goes to `RuleSet::procedural_programs` instead, and is run by the engine
/// script the page loads.
struct CosmeticRule {
  std::string selector;                      ///< ".simple-ad-slot__fixed"
  std::vector<std::string> include_domains;  ///< empty means every site
  std::vector<std::string> exclude_domains;  ///< "~news.example.com"
  std::uint32_t line = 0;
  /// `#$#selector { … }`: apply these declarations instead of hiding.  The
  /// declarations are already normalised into one line; empty means "hide".
  std::string style;
  /// `{ remove: true; }`: take the element out of the page, not just hide it.
  bool remove = false;
};

/// One request, as the proxy sees it.
struct RuleRequest {
  std::string url;
  std::string host;      ///< lower-case host, no port
  std::string scheme;    ///< lower-case: http, https, ws, wss
  std::string path;      ///< path without the query string
  std::string query;     ///< without '?'
  std::string document;  ///< host of the page that asked, empty when unknown
  ResourceType type = ResourceType::Other;

  bool third_party() const;
  /// True when `host` is `document` or a subdomain of it.
  static bool same_site(const std::string& host, const std::string& document);
};

/// Builds a RuleRequest out of an absolute URL.
RuleRequest rule_request_from_url(const std::string& url,
                                  const std::string& document_host = std::string(),
                                  ResourceType type = ResourceType::Other);

/// The decision for one request.
struct RuleDecision {
  RuleAction action = RuleAction::None;
  const Rule* rule = nullptr;
  std::string value;  ///< the redirect target or the parameter to remove
  /// True when an exception suppressed a block: useful in logs.
  bool allowed_by_exception = false;
  std::string explain() const;
};

/// A parsed filter list (or several of them merged).
class RuleSet {
 public:
  RuleSet();

  /// Adds one line.  Returns false when the line was skipped.
  bool add_line(const std::string& line, std::string* reason = nullptr);
  /// Loads a file; `!` comments and blank lines are fine.  Missing file is an
  /// error, a malformed line inside it is not.
  bool load_file(const std::string& path, std::string* error = nullptr);
  /// Loads from memory (used by tests and by the user interface).
  bool load_text(const std::string& text, std::string* error = nullptr);
  void clear();

  /// The decision for one request: the most specific matching rule wins, with
  /// `$important` block rules overriding exceptions.
  RuleDecision decide(const RuleRequest& request) const;

  /// Turns the literal index on or off.  It is on by default; turning it off
  /// makes every generic rule run the wildcard matcher, which is exactly what
  /// the self-test compares against and what `tools/bench_rules.exe` measures a
  /// real list with.
  void set_literal_index(bool enabled) { literal_index_enabled_ = enabled; }
  bool literal_index_enabled() const { return literal_index_enabled_; }

  /// Collects every matching response-side rule into one rewrite plan.  Returns
  /// true when at least one rule applies, in which case `out` must not be
  /// empty.  Rules that only block or only allow are ignored here.
  bool collect_response_rewrite(const RuleRequest& request, ResponseRewrite* out) const;

  /// The CSS that hides everything the cosmetic rules select for a page served
  /// from `document_host`, or an empty string when none of them apply.  `#@#`
  /// exceptions are already subtracted.  The result goes straight into
  /// `ResponseRewrite::inject_css`, which puts it in a <style> in the page — that
  /// is what makes an ad slot disappear instead of merely failing to load.
  /// `source`, when given, receives one line per applied selector
  /// ("blog.csdn.net##.simple-ad-slot"), so the log can name the cosmetic rules
  /// that hid something just like it names the `$css`/`$replace` rules.
  /// `include_generic` (default) also applies the rules that carry no domain
  /// list; pass false for a reply that cannot render a page (an API call, an
  /// image), where that list can only add noise.
  std::string cosmetic_css(const std::string& document_host,
                           std::string* source = nullptr,
                           bool include_generic = true) const;
  const std::vector<CosmeticRule>& cosmetics() const { return cosmetics_; }
  const std::vector<CosmeticRule>& cosmetic_exceptions() const { return cosmetic_exceptions_; }

  /// The compiled programs the page's own engine has to run, because no
  /// stylesheet can express them: `#?#`, `#$?#` and any selector with `:has()`,
  /// `:upward()`, `:contains()`, `:matches-css()` …  Compiled once here, so the
  /// engine in the page is a tiny evaluator and every syntax error is caught by
  /// the selftest rather than in someone's browser.
  ///
  /// `source`, when given, receives the selectors that matched — the log names
  /// them the way it names the CSS ones.  `include_generic` mirrors
  /// `cosmetic_css`: a reply that cannot render a page skips the domain-less
  /// rules.
  std::vector<CosmeticProgram> procedural_programs(const std::string& document_host,
                                                   std::string* source = nullptr,
                                                   bool include_generic = true) const;
  /// The `#?#`/`#$#`/`#$?#` rules, for `--help` and the selftest.
  const std::vector<CosmeticRule>& procedural() const { return procedural_; }
  const std::vector<CosmeticRule>& procedural_exceptions() const {
    return procedural_exceptions_;
  }

  /// True when the host is on a hosts-file block list.
  bool host_blocked(const std::string& host) const;
  /// Every host name a hosts-style rule blocks, sorted, for hosts file writing.
  std::vector<std::string> blocked_hosts() const;
  /// The rule that blocked a host, when there is one.
  const Rule* host_rule(const std::string& host) const;

  std::size_t size() const { return rules_.size(); }
  const std::vector<Rule>& rules() const { return rules_; }
  const std::vector<SkippedRule>& skipped() const { return skipped_; }
  const RuleStats& stats() const { return stats_; }
  const std::string& source() const { return source_; }
  void set_source(const std::string& source) { source_ = source; }

  /// "1204 rules (930 block, 274 allow), 12 skipped"
  std::string describe() const;
  /// Up to `limit` lines describing what was skipped, for the user interface.
  std::string skipped_report(std::size_t limit = 8) const;

 private:
  void index_rule(Rule& rule);
  /// Every generic rule whose required literal can still be in `lower_url`, in
  /// ascending rule order.  This is what keeps a 100k-line list usable: without
  /// it every request would run the wildcard matcher over every generic rule.
  void collect_candidates(const std::string& lower_url, std::vector<std::size_t>* out) const;
  static std::string required_literal(const Rule& rule);
  static bool rule_matches(const Rule& rule, const RuleRequest& request,
                           const std::string& lower_url);
  static bool pattern_matches(const Rule& rule, const std::string& url);
  static bool type_matches(const Rule& rule, ResourceType type);
  static bool option_domains_allow(const Rule& rule, const std::string& document);

  std::vector<Rule> rules_;
  std::vector<SkippedRule> skipped_;
  std::map<std::string, std::vector<std::size_t>> host_index_;
  std::vector<std::size_t> generic_index_;
  /// Literal index: a four byte window of the URL -> the rules that need it.
  std::unordered_map<std::uint32_t, std::vector<std::size_t>> literal_index_;
  /// Generic rules the index cannot answer for (wildcard-only patterns, very
  /// short literals): they are always tested.
  std::vector<std::size_t> generic_unkeyed_;
  std::set<std::string> blocked_hosts_;
  std::map<std::string, std::size_t> host_rule_index_;
  /// `##selector` rules and their `#@#` exceptions, in list order.
  std::vector<CosmeticRule> cosmetics_;
  std::vector<CosmeticRule> cosmetic_exceptions_;
  /// `#?#`/`#$#`/`#$?#` (and `##` selectors that need the DOM): they are not CSS
  /// at all, they are programs for the engine in the page.
  std::vector<CosmeticRule> procedural_;
  std::vector<CosmeticRule> procedural_exceptions_;
  /// Raw text of every `$badfilter` line, resolved once after a list is loaded.
  std::vector<std::string> badfilter_lines_;
  /// `$badfilter` lines: they block nothing themselves, they switch off the rules
  /// that look exactly like them (same pattern, same options).  uBlock's fix
  /// lists ship thousands of these.
  void apply_badfilters();

  bool literal_index_enabled_ = true;
  RuleStats stats_;
  std::string source_;
};

/// The subset of the Adblock Plus syntax this engine understands, for --help.
std::string rule_syntax_help();

}  // namespace netcap
