#include "netcap/rules.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "netcap/common.hpp"
#include "netcap/regex.hpp"

namespace netcap {

namespace {

constexpr std::size_t kMaxLineLength = 8192;

std::string trim(const std::string& in) {
  std::size_t b = 0;
  std::size_t e = in.size();
  while (b < e && std::isspace(static_cast<unsigned char>(in[b]))) ++b;
  while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1]))) --e;
  return in.substr(b, e - b);
}

std::vector<std::string> split(const std::string& in, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (const char c : in) {
    if (c == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur += c;
    }
  }
  out.push_back(cur);
  return out;
}

bool starts_with(const std::string& s, const char* prefix) {
  const std::size_t n = std::strlen(prefix);
  return s.size() >= n && s.compare(0, n, prefix) == 0;
}

bool ends_with(const std::string& s, const char* suffix) {
  const std::size_t n = std::strlen(suffix);
  return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

/// `^` in Adblock: a separator is anything that is not a letter, a digit, `_`,
/// `-`, `.` or `%`.  The end of the URL counts as a separator.
bool sep_at(const std::string& url, std::size_t i) {
  if (i >= url.size()) return true;
  const char c = url[i];
  return !(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' ||
           c == '.' || c == '%');
}

bool is_ip_literal_host(const std::string& host) {
  int version = 0;
  u8 addr[16];
  return parse_ip(host, &version, addr);
}

/// A bare token is only a hosts-file entry when it really looks like a host
/// name: "||ads.example.com^" also contains a dot, but it is an Adblock rule.
bool looks_like_hostname(const std::string& text) {
  if (text.empty() || text.find('.') == std::string::npos) return false;
  if (text.back() == '.') return false;
  for (const char c : text) {
    const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_';
    if (!ok) return false;
  }
  return true;
}

/// "a.b.co.uk" -> "b.co.uk", "co.uk", "uk"
std::vector<std::string> parent_domains(const std::string& host) {
  std::vector<std::string> out;
  out.push_back(host);
  std::size_t pos = host.find('.');
  while (pos != std::string::npos) {
    const std::string rest = host.substr(pos + 1);
    if (rest.find('.') == std::string::npos && rest.size() <= 3) break;  // bare TLD
    out.push_back(rest);
    pos = host.find('.', pos + 1);
  }
  return out;
}

/// Two labels, or three for the common country-code second-level domains
/// ("example.co.uk"), which is close enough to a registrable domain for
/// third-party decisions.
/// The document host can carry a port ("127.0.0.1:8899") while element hiding
/// rules are written against the bare name; without this, every domain-scoped
/// `##` rule silently stops matching for sites reached on an explicit port.
std::string without_port(const std::string& host) {
  const std::size_t colon = host.rfind(':');
  if (colon == std::string::npos) return host;
  const std::size_t close = host.rfind(']');
  if (close != std::string::npos && close > colon) return host;  // "[::1]" has no port
  for (std::size_t i = colon + 1; i < host.size(); ++i) {
    if (host[i] < '0' || host[i] > '9') return host;
  }
  return colon == 0 ? host : host.substr(0, colon);
}

// True when a cosmetic rule's domain list lets it run on `host`.  An empty
// include list means "every site"; a "~domain" entry always wins.
bool cosmetic_applies(const CosmeticRule& rule, const std::string& host) {
  const std::string bare = without_port(host);
  for (const std::string& domain : rule.exclude_domains) {
    if (bare == domain || ends_with(bare, ("." + domain).c_str())) return false;
  }
  if (rule.include_domains.empty()) return true;
  for (const std::string& domain : rule.include_domains) {
    if (bare == domain || ends_with(bare, ("." + domain).c_str())) return true;
  }
  return false;
}

std::string registrable_domain(const std::string& host) {
  static const char* kTwoLevel[] = {"co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp",
                                    "com.cn", "net.cn", "org.cn", "com.au", "com.br",
                                    "co.kr", "com.tw", "co.in", "com.hk", "com.sg"};
  const std::vector<std::string> parts = split(host, '.');
  if (parts.size() <= 2) return host;
  std::string last_two = parts[parts.size() - 2] + "." + parts[parts.size() - 1];
  for (const char* t : kTwoLevel) {
    if (last_two == t) {
      return parts[parts.size() - 3] + "." + last_two;
    }
  }
  return last_two;
}

}  // namespace

// ---------------------------------------------------------------- resource type

const char* resource_type_name(ResourceType type) {
  switch (type) {
    case ResourceType::Document: return "document";
    case ResourceType::Subdocument: return "subdocument";
    case ResourceType::Script: return "script";
    case ResourceType::Image: return "image";
    case ResourceType::Stylesheet: return "stylesheet";
    case ResourceType::XmlHttpRequest: return "xmlhttprequest";
    case ResourceType::Font: return "font";
    case ResourceType::Media: return "media";
    case ResourceType::WebSocket: return "websocket";
    case ResourceType::Ping: return "ping";
    case ResourceType::Object: return "object";
    case ResourceType::Other: break;
  }
  return "other";
}

bool resource_type_from_string(const std::string& text, ResourceType* out) {
  const std::string t = to_lower(text);
  struct Entry { const char* name; ResourceType type; };
  static const Entry kEntries[] = {
      {"document", ResourceType::Document},        {"doc", ResourceType::Document},
      {"subdocument", ResourceType::Subdocument},  {"frame", ResourceType::Subdocument},
      {"script", ResourceType::Script},            {"image", ResourceType::Image},
      {"stylesheet", ResourceType::Stylesheet},    {"css", ResourceType::Stylesheet},
      {"xmlhttprequest", ResourceType::XmlHttpRequest},
      {"xhr", ResourceType::XmlHttpRequest},
      {"font", ResourceType::Font},                {"media", ResourceType::Media},
      {"websocket", ResourceType::WebSocket},      {"ping", ResourceType::Ping},
      {"beacon", ResourceType::Ping},              {"object", ResourceType::Object},
      {"other", ResourceType::Other},
  };
  for (const Entry& e : kEntries) {
    if (t == e.name) {
      *out = e.type;
      return true;
    }
  }
  return false;
}

ResourceType resource_type_from_path(const std::string& path, const std::string& content_type) {
  const std::string p = to_lower(path);
  const std::string ct = to_lower(content_type);
  const std::size_t dot = p.find_last_of('.');
  const std::string ext =
      dot == std::string::npos ? std::string() : p.substr(dot + 1, p.find('?', dot) - dot - 1);
  if (ext == "js" || ext == "mjs") return ResourceType::Script;
  if (ext == "css") return ResourceType::Stylesheet;
  if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "gif" || ext == "webp" ||
      ext == "svg" || ext == "ico" || ext == "bmp" || ext == "avif") {
    return ResourceType::Image;
  }
  if (ext == "woff" || ext == "woff2" || ext == "ttf" || ext == "otf" || ext == "eot") {
    return ResourceType::Font;
  }
  if (ext == "mp4" || ext == "webm" || ext == "mp3" || ext == "ogg" || ext == "m4a" ||
      ext == "ts" || ext == "m3u8") {
    return ResourceType::Media;
  }
  if (ext == "html" || ext == "htm" || ext == "php" || ext == "asp" || ext == "aspx") {
    return ResourceType::Document;
  }
  if (!ct.empty()) {
    if (ct.find("javascript") != std::string::npos) return ResourceType::Script;
    if (ct.find("text/css") != std::string::npos) return ResourceType::Stylesheet;
    if (ct.find("image/") != std::string::npos) return ResourceType::Image;
    if (ct.find("font/") != std::string::npos) return ResourceType::Font;
    if (ct.find("video/") != std::string::npos || ct.find("audio/") != std::string::npos) {
      return ResourceType::Media;
    }
    if (ct.find("text/html") != std::string::npos) return ResourceType::Document;
    if (ct.find("json") != std::string::npos) return ResourceType::XmlHttpRequest;
  }
  return ResourceType::Other;
}

// ---------------------------------------------------------------- actions

const char* rule_action_name(RuleAction action) {
  switch (action) {
    case RuleAction::Block: return "block";
    case RuleAction::Allow: return "allow";
    case RuleAction::Modify: return "modify";
    case RuleAction::Redirect: return "redirect";
    case RuleAction::None: break;
  }
  return "none";
}

RuleAction Rule::action() const {
  if (allow) return RuleAction::Allow;
  if (!redirect.empty()) return RuleAction::Redirect;
  if (!removeparam.empty()) return RuleAction::Modify;
  // A rule that only edits the response lets the request through: saying
  // "block" here would take the whole page down instead of cleaning it up.
  if (is_response_only()) return RuleAction::None;
  return RuleAction::Block;
}

bool Rule::has_response_modifiers() const {
  return !set_headers.empty() || !remove_headers.empty() || !remove_cookies.empty() ||
         !replaces.empty() || !inject_css.empty() || !inject_script.empty();
}

bool Rule::is_response_only() const {
  return has_response_modifiers() && !allow && redirect.empty() && removeparam.empty();
}

bool Rule::needs_context() const {
  return third_party || first_party || !include_domains.empty() || !exclude_domains.empty() ||
         !types.empty();
}

// ---------------------------------------------------------------- request

bool RuleRequest::same_site(const std::string& host, const std::string& document) {
  if (host.empty() || document.empty()) return false;
  return registrable_domain(host) == registrable_domain(document);
}

bool RuleRequest::third_party() const {
  if (document.empty()) return false;
  return !same_site(host, document);
}

RuleRequest rule_request_from_url(const std::string& url, const std::string& document_host,
                                 ResourceType type) {
  RuleRequest r;
  r.url = url;
  r.document = to_lower(document_host);
  r.type = type;
  const std::size_t scheme_end = url.find("://");
  if (scheme_end != std::string::npos) {
    r.scheme = to_lower(url.substr(0, scheme_end));
  }
  const std::size_t host_start = scheme_end == std::string::npos ? 0 : scheme_end + 3;
  std::size_t host_end = url.find('/', host_start);
  if (host_end == std::string::npos) host_end = url.size();
  std::string authority = url.substr(host_start, host_end - host_start);
  const std::size_t at = authority.find('@');
  if (at != std::string::npos) authority = authority.substr(at + 1);
  const std::size_t colon = authority.rfind(':');
  if (colon != std::string::npos && authority.find(']') == std::string::npos) {
    authority = authority.substr(0, colon);
  }
  r.host = to_lower(authority);
  std::string rest = url.substr(host_end);
  const std::size_t q = rest.find('?');
  if (q == std::string::npos) {
    r.path = rest;
  } else {
    r.path = rest.substr(0, q);
    r.query = rest.substr(q + 1);
  }
  if (r.path.empty()) r.path = "/";
  return r;
}

std::string RuleDecision::explain() const {
  if (action == RuleAction::None) return "no rule matched";
  std::string out = rule_action_name(action);
  if (rule) {
    out += " by '";
    out += rule->raw;
    out += '\'';
  }
  if (!value.empty()) {
    out += " (";
    out += value;
    out += ')';
  }
  if (allowed_by_exception) out += " [exception]";
  return out;
}

// ---------------------------------------------------------------- parsing

namespace {

/// Option names this engine knows.  A `$` tail that starts with one of them is
/// meant to be an option list, so a parse failure is a broken rule rather than
/// part of the URL pattern (patterns with a `$` in them are common, but they do
/// not start with `$replace=`, `$css=` and friends).
bool known_option_key(const std::string& key) {
  static const char* const kKeys[] = {
      "third-party", "3p", "first-party", "1p", "match-case", "important", "all",
      "popup", "elemhide", "generichide", "genericblock", "specifichide", "domain",
      "from", "removeparam", "queryprune", "redirect", "redirect-rule", "header",
      "csp", "removeheader", "remove-header", "removecookie", "remove-cookies",
      "replace", "css", "script", "urltransform", "permissions", "badfilter"};
  for (const char* candidate : kKeys) {
    if (key == candidate) return true;
  }
  ResourceType type = ResourceType::Other;
  return resource_type_from_string(key, &type);
}

/// Options are everything after a `$` that parses cleanly.  A `$` inside a URL
/// pattern is common enough that a failed parse must leave it alone.
///
/// Splitting on commas is not enough on its own: `$css` and `$script` carry CSS
/// and JavaScript, `$replace` carries a pattern, and a header value may be a
/// comma separated list — all of those are full of commas.  The keys whose value
/// runs to the end of the option list swallow the rest, which is why they have
/// to be written last (that is also how they are written in the wild).
/// `$removeheader`/`$removecookie` are deliberately *not* in that set: a header
/// name list is written with `|`, so `$removeheader=x-drop,removecookie` has to
/// keep working as two options.
std::vector<std::string> split_options(const std::string& text) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t comma = text.find(',', start);
    const std::string seg =
        comma == std::string::npos ? text.substr(start) : text.substr(start, comma - start);
    const std::size_t eq = seg.find('=');
    if (eq != std::string::npos) {
      const std::string key = to_lower(trim(seg.substr(0, eq)));
      if (key == "css" || key == "script" || key == "replace" || key == "csp" ||
          key == "header") {
        out.push_back(text.substr(start));
        return out;
      }
    }
    out.push_back(seg);
    if (comma == std::string::npos) return out;
    start = comma + 1;
  }
  return out;
}

/// `$replace=/pattern/replacement/` with an optional trailing flag list.
/// The pattern may contain `\/` to mean a literal slash.
bool parse_replace_value(const std::string& value, RewriteReplace* out, std::string* reason) {
  if (value.size() < 3 || value[0] != '/') {
    *reason = "malformed $replace value (want /pattern/replacement/)";
    return false;
  }
  std::size_t sep = std::string::npos;
  for (std::size_t i = 1; i < value.size(); ++i) {
    if (value[i] == '\\') {
      ++i;  // skip the escaped character
      continue;
    }
    if (value[i] == '/') {
      sep = i;
      break;
    }
  }
  if (sep == std::string::npos || sep == 1) {
    *reason = "malformed $replace value (want /pattern/replacement/)";
    return false;
  }
  const std::size_t end = value.rfind('/');
  if (end <= sep) {
    *reason = "malformed $replace value (want /pattern/replacement/)";
    return false;
  }
  out->pattern = value.substr(1, sep - 1);
  out->replacement = value.substr(sep + 1, end - sep - 1);
  out->raw = value;
  for (std::size_t i = end + 1; i < value.size(); ++i) {
    const char c = value[i];
    if (c == 'i') {
      out->case_insensitive = true;
    } else if (c == 'g') {
      // Global is the only mode this engine has; accept it and move on.
    } else {
      *reason = std::string("unknown $replace flag '") + c + "'";
      return false;
    }
  }
  // The pattern has to compile now: a bad one would otherwise be discovered
  // while a page is being served.
  std::string error;
  const std::string pattern = out->case_insensitive ? "(?i)" + out->pattern : out->pattern;
  Regex compiled;
  if (!Regex::compile(pattern, &compiled, &error)) {
    *reason = "bad $replace pattern: " + error;
    return false;
  }
  return true;
}

bool parse_options(const std::string& text, Rule* rule, std::string* reason) {
  const std::vector<std::string> parts = split_options(text);
  for (const std::string& raw_part : parts) {
    const std::string trimmed = trim(raw_part);
    const std::string part = to_lower(trimmed);
    if (part.empty()) {
      *reason = "empty $option";
      return false;
    }
    const std::size_t eq = part.find('=');
    const std::string key = eq == std::string::npos ? part : part.substr(0, eq);
    // A leading `~` on the option name means "not this one": `$~script` is every
    // type except a script.  Real lists lean on it (EasyList + EasyPrivacy use it
    // on 683 lines), so it must not be skipped as an unknown option.
    const bool negate = !key.empty() && key[0] == '~';
    const std::string name = negate ? key.substr(1) : key;
    const std::string value = eq == std::string::npos ? std::string() : part.substr(eq + 1);
    // CSS, JavaScript and regular expressions are case sensitive, so those
    // options keep the value exactly as the list wrote it.
    const std::size_t raw_eq = trimmed.find('=');
    const std::string raw_value =
        raw_eq == std::string::npos ? std::string() : trimmed.substr(raw_eq + 1);
    const bool negated = !value.empty() && value[0] == '~';
    const std::string bare = negated ? value.substr(1) : value;

    if (name == "third-party" || name == "3p") {
      // `$~third-party` is the same condition as `$first-party`.
      if (negate) {
        rule->first_party = true;
      } else {
        rule->third_party = true;
      }
    } else if (name == "first-party" || name == "1p") {
      if (negate) {
        rule->third_party = true;
      } else {
        rule->first_party = true;
      }
    } else if (!negate && name == "match-case") {
      rule->match_case = true;
    } else if (!negate && name == "important") {
      rule->important = true;
    } else if (name == "all" || name == "network") {
      // Matches every resource type: no type restriction.  AdGuard writes
      // `$network` on IP-shaped rules to say "this is a network-level rule".
    } else if (name == "popup" || name == "elemhide" || name == "generichide" ||
               name == "genericblock" || name == "specifichide") {
      // Cosmetic or window-level options: a network blocker has nothing to do.
    } else if (name == "domain" || name == "from") {
      for (const std::string& entry : split(value, '|')) {
        const std::string name = to_lower(trim(entry));
        if (name.empty()) continue;
        if (name[0] == '~') {
          rule->exclude_domains.push_back(name.substr(1));
        } else {
          rule->include_domains.push_back(name);
        }
      }
    } else if (name == "removeparam" || key == "queryprune") {
      if (value.empty()) {
        // $removeparam with no value strips every tracking parameter.
        rule->removeparam = "*";
      } else {
        rule->removeparam = value;
      }
    } else if (name == "redirect" || key == "redirect-rule") {
      rule->redirect = value.empty() ? "noop" : value;
    } else if (name == "header") {
      if (raw_value.find(':') == std::string::npos) {
        *reason = "malformed $header value (want Name: value)";
        return false;
      }
      rule->set_headers.push_back(trim(raw_value));
    } else if (name == "csp") {
      // A bare `$csp` is the classic "stop the page from loading anything it
      // did not ship itself" rule.
      rule->set_headers.push_back("Content-Security-Policy: " +
                                  (raw_value.empty() ? std::string("default-src 'self'")
                                                     : trim(raw_value)));
    } else if (name == "removeheader" || key == "remove-header") {
      if (value.empty()) {
        *reason = "$removeheader needs a header name";
        return false;
      }
      for (const std::string& entry : split(value, '|')) {
        const std::string name = trim(entry);
        if (!name.empty()) rule->remove_headers.push_back(name);
      }
      if (rule->remove_headers.empty()) {
        *reason = "$removeheader needs a header name";
        return false;
      }
    } else if (name == "removecookie" || key == "remove-cookies") {
      if (value.empty()) {
        // Without a name every Set-Cookie is dropped.
        rule->remove_cookies.push_back("*");
      } else {
        for (const std::string& entry : split(value, '|')) {
          const std::string name = trim(entry);
          if (!name.empty()) rule->remove_cookies.push_back(name);
        }
      }
    } else if (name == "replace") {
      RewriteReplace rep;
      if (!parse_replace_value(raw_value, &rep, reason)) return false;
      rule->replaces.push_back(rep);
    } else if ((name == "css" || name == "script") && eq != std::string::npos && raw_value.empty()) {
      *reason = "empty $" + name + " value (write the markup, or drop the '=' for the type)";
      return false;
    } else if ((name == "css" || name == "script") && !raw_value.empty()) {
      // `$css=...` / `$script=...` inject markup.  Without a value they are the
      // resource-type options ($css = stylesheet, $script = script), which is
      // why the empty case falls through to the type table below.
      if (key == "css") {
        rule->inject_css.push_back(raw_value);
      } else {
        rule->inject_script.push_back(raw_value);
      }
    } else if (name == "urltransform" || name == "permissions") {
      // Still beyond our scope: skip rather than mis-handle.
      *reason = "unsupported $" + name + " option";
      return false;
    } else if (name == "rewrite") {
      // ABP's `$rewrite=abp-resource:blank-mp3` swaps in a local placeholder;
      // that is the same job as `$redirect`, and answering with our noop
      // response is the honest version of it.
      rule->redirect = "noop";
    } else if (name == "badfilter") {
      // Not an error any more: the line is loaded, then switched off together
      // with everything that looks exactly like it (see apply_badfilters()).
      rule->badfilter = true;
    } else {
      ResourceType type = ResourceType::Other;
      if (resource_type_from_string(name, &type)) {
        if (negate) {
          rule->exclude_types.push_back(type);
        } else {
          rule->types.push_back(type);
        }
      } else {
        *reason = "unknown $" + key + " option";
        return false;
      }
    }
    (void)bare;
  }
  return true;
}

}  // namespace

// ---------------------------------------------------------------- set

// The constructor lives here (not in the header) so that the header stays free
// of the standard library details and the test file can build an empty set.
RuleSet::RuleSet() = default;

bool RuleSet::add_line(const std::string& line, std::string* reason) {
  ++stats_.lines;
  const std::string text = trim(line);
  if (text.empty()) {
    ++stats_.comments;
    return false;
  }
  if (text[0] == '!') {
    ++stats_.comments;
    return false;
  }
  if (text[0] == '[') {
    ++stats_.comments;  // "[Adblock Plus 2.0]" and friends
    return false;
  }
  if (text.size() > kMaxLineLength) {
    skipped_.push_back({static_cast<std::uint32_t>(stats_.lines), text.substr(0, 80),
                        "line too long"});
    ++stats_.skipped;
    if (reason) *reason = "line too long";
    return false;
  }

  // Element hiding is a cosmetic rule, not a network rule: `##selector` hides an
  // element in the page, `#@#` is the "do not hide it" exception.  Three more
  // families cannot be a stylesheet at all, and they are compiled here and run by
  // the page's own engine instead (netcap/cosmetic.hpp):
  //
  //   #?#   procedural: `:has()`, `:upward()`, `:contains()` … — the proxy has no
  //         DOM to evaluate them against and a browser would ignore them
  //   #$#   `selector { declarations }`: apply those declarations
  //   #$?#  both at once
  //
  // A plain `##` selector that *contains* one of those operators is routed the
  // same way, because that is where the lists actually put them.  `#%#` scriptlet
  // injection is a different feature altogether: still not run, but now skipped
  // by name rather than read as a broken network rule.
  {
    const std::size_t at = text.find('#');
    if (at != std::string::npos) {
      const std::string tail = text.substr(at);
      struct CosmeticMarker {
        const char* text;
        bool exception;
        bool procedural;
      };
      static const CosmeticMarker kMarkers[] = {
          {"#@$?#", true, true}, {"#$?#", false, true}, {"#@?#", true, true},
          {"#@$#", true, true},  {"#@#", true, false},  {"#?#", false, true},
          {"#$#", false, true},  {"##", false, false},
      };
      const CosmeticMarker* marker = nullptr;
      for (const CosmeticMarker& candidate : kMarkers) {
        if (tail.rfind(candidate.text, 0) == 0) {
          marker = &candidate;
          break;
        }
      }
      if (marker == nullptr && tail.rfind("#%#", 0) == 0) {
        skipped_.push_back({static_cast<std::uint32_t>(stats_.lines), text.substr(0, 80),
                            "scriptlet injection rules are not run"});
        ++stats_.skipped;
        if (reason) *reason = "scriptlet injection rules are not run";
        return false;
      }
      if (marker != nullptr) {
        std::string selector = trim(tail.substr(std::strlen(marker->text)));
        std::string style;
        bool remove = false;
        // `#$#selector { declarations }`: the block is the point of the rule.
        const std::size_t brace = selector.find('{');
        if (brace != std::string::npos) {
          const std::size_t close = selector.rfind('}');
          if (close == std::string::npos || close < brace) {
            skipped_.push_back({static_cast<std::uint32_t>(stats_.lines), text.substr(0, 80),
                                "a cosmetic rule with an unterminated declaration block"});
            ++stats_.skipped;
            if (reason) *reason = "a cosmetic rule with an unterminated declaration block";
            return false;
          }
          const std::string declarations = trim(selector.substr(brace + 1, close - brace - 1));
          selector = trim(selector.substr(0, brace));
          // `{ remove: true; }` is AdGuard saying "take the element out", not a
          // CSS declaration: no browser knows that property.
          std::string kept;
          for (const std::string& declaration : split(declarations, ';')) {
            const std::string entry = trim(declaration);
            if (entry.empty()) continue;
            const std::size_t colon = entry.find(':');
            if (colon == std::string::npos) continue;
            const std::string name = to_lower(trim(entry.substr(0, colon)));
            const std::string value = to_lower(trim(entry.substr(colon + 1)));
            if (name == "remove" && (value == "true" || value == "yes")) {
              remove = true;
              continue;
            }
            if (!kept.empty()) kept += " ";
            kept += entry + ";";
          }
          style = kept;
        }
        if (selector.empty()) {
          skipped_.push_back({static_cast<std::uint32_t>(stats_.lines), text.substr(0, 80),
                              "cosmetic rule without a selector"});
          ++stats_.skipped;
          if (reason) *reason = "cosmetic rule without a selector";
          return false;
        }
        // Compiling says two things at once: whether the selector uses an
        // operator only the page can run, and whether it uses one this engine
        // does not implement.  The procedural families are refused loudly in the
        // second case; a plain `##` selector is left to the browser, which is how
        // an exotic pseudo-class has always been handled.
        CosmeticProgram program;
        std::string why;
        const bool compiles = cosmetic_compile(selector, &program, &why);
        if (!compiles && marker->procedural) {
          skipped_.push_back({static_cast<std::uint32_t>(stats_.lines), text.substr(0, 80), why});
          ++stats_.skipped;
          if (reason) *reason = why;
          return false;
        }
        const bool engine = compiles && (remove || !program.ops.empty());
        CosmeticRule rule;
        rule.selector = selector;
        rule.style = style;
        rule.remove = remove;
        rule.line = static_cast<std::uint32_t>(stats_.lines);
        for (const std::string& entry : split(text.substr(0, at), ',')) {
          const std::string domain = to_lower(trim(entry));
          if (domain.empty()) continue;
          if (domain[0] == '~') {
            if (domain.size() > 1) rule.exclude_domains.push_back(domain.substr(1));
          } else {
            rule.include_domains.push_back(domain);
          }
        }
        if (engine) {
          (marker->exception ? procedural_exceptions_ : procedural_).push_back(rule);
        } else if (marker->exception) {
          cosmetic_exceptions_.push_back(rule);
        } else {
          cosmetics_.push_back(rule);
        }
        ++stats_.element_hide;
        return false;  // parsed, but it is not a network rule
      }
    }
  }

  // Hosts file syntax: "0.0.0.0 ads.example.com" (several hosts per line are
  // allowed, and so is the single-column form).
  {
    const std::vector<std::string> fields = split(text, ' ');
    std::vector<std::string> words;
    for (const std::string& f : fields) {
      const std::string w = trim(f);
      if (!w.empty()) words.push_back(w);
    }
    if (!words.empty()) {
      const bool first_is_sink = words[0] == "0.0.0.0" || words[0] == "127.0.0.1" ||
                                 words[0] == "::" || words[0] == "::1";
      if (first_is_sink && words.size() >= 2) {
        bool named = false;
        for (std::size_t i = 1; i < words.size(); ++i) {
          const std::string host = to_lower(words[i]);
          if (host.empty() || host == "localhost" || host[0] == '#') continue;
          if (is_ip_literal_host(host)) continue;
          if (!looks_like_hostname(host)) continue;
          Rule rule;
          rule.raw = text;
          rule.pattern = host;
          rule.domain_anchor = true;
          rule.line = static_cast<std::uint32_t>(stats_.lines);
          rule.index = rules_.size();
          rules_.push_back(rule);
          index_rule(rules_.back());
          ++stats_.block_rules;
          named = true;
        }
        if (named) return true;
      } else if (words.size() == 1 && looks_like_hostname(to_lower(words[0]))) {
        // Single-column hosts list ("ads.example.com").
        const std::string host = to_lower(words[0]);
        Rule rule;
        rule.raw = text;
        rule.pattern = host;
        rule.domain_anchor = true;
        rule.line = static_cast<std::uint32_t>(stats_.lines);
        rule.index = rules_.size();
        rules_.push_back(rule);
        index_rule(rules_.back());
        ++stats_.block_rules;
        return true;
      }
    }
  }

  Rule rule;
  rule.raw = text;
  rule.line = static_cast<std::uint32_t>(stats_.lines);
  std::string body = text;
  if (starts_with(body, "@@")) {
    rule.allow = true;
    body = body.substr(2);
  }

  // A pattern wrapped in slashes is a regular expression: not supported, and
  // pretending otherwise would block the wrong things.
  if (body.size() > 2 && body[0] == '/' && body[body.size() - 1] == '/' &&
      body.find('$') == std::string::npos) {
    skipped_.push_back({rule.line, text, "regular expression patterns are not supported"});
    ++stats_.skipped;
    if (reason) *reason = "regular expression patterns are not supported";
    return false;
  }

  // Find the option separator: the last `$` that parses cleanly.
  std::size_t dollar = std::string::npos;
  for (std::size_t i = body.size(); i-- > 0;) {
    if (body[i] != '$') continue;
    const std::string tail = body.substr(i + 1);
    std::string why;
    Rule probe;
    if (parse_options(tail, &probe, &why)) {
      dollar = i;
      rule.types = probe.types;
      rule.exclude_types = probe.exclude_types;
      // `$badfilter` has to survive this copy: without it the line is loaded as a
      // normal block rule and the rule it was meant to cancel keeps working.
      rule.badfilter = probe.badfilter;
      rule.third_party = probe.third_party;
      rule.first_party = probe.first_party;
      rule.match_case = probe.match_case;
      rule.important = probe.important;
      rule.include_domains = probe.include_domains;
      rule.exclude_domains = probe.exclude_domains;
      rule.removeparam = probe.removeparam;
      rule.redirect = probe.redirect;
      rule.set_headers = probe.set_headers;
      rule.remove_headers = probe.remove_headers;
      rule.remove_cookies = probe.remove_cookies;
      rule.replaces = probe.replaces;
      rule.inject_css = probe.inject_css;
      rule.inject_script = probe.inject_script;
      break;
    }
    // A `$` that is not an option list is part of the URL pattern (query
    // strings contain them).  A tail that looks like one but does not parse is
    // a broken rule: skip it instead of blocking something unrelated.
    const std::size_t key_end = tail.find_first_of("=,");
    const std::string tail_key = to_lower(trim(tail.substr(0, key_end)));
    const bool looks_like_options =
        known_option_key(tail_key) ||
        (!tail.empty() && tail.find('/') == std::string::npos &&
         tail.find('?') == std::string::npos && tail.find(' ') == std::string::npos);
    if (looks_like_options) {
      skipped_.push_back({rule.line, text, why});
      ++stats_.skipped;
      if (reason) *reason = why;
      return false;
    }
  }
  if (dollar != std::string::npos) body = body.substr(0, dollar);

  if (starts_with(body, "||")) {
    rule.domain_anchor = true;
    body = body.substr(2);
  } else if (starts_with(body, "|")) {
    rule.start_anchor = true;
    body = body.substr(1);
  }
  if (ends_with(body, "|")) {
    rule.end_anchor = true;
    body.pop_back();
  }
  if (body.empty()) {
    // ABP and AdGuard both allow a rule that is nothing but options
    // (`$image,third-party,domain=a.com|b.com`): the pattern is "every URL" and
    // the type/domain options do the work.  Without options the line really is
    // empty and gets skipped.
    const bool constrained = !rule.types.empty() || !rule.exclude_types.empty() ||
                             !rule.include_domains.empty() ||
                             !rule.exclude_domains.empty();
    if (!constrained) {
      skipped_.push_back({rule.line, text, "empty pattern"});
      ++stats_.skipped;
      if (reason) *reason = "empty pattern";
      return false;
    }
  }
  rule.pattern = rule.match_case ? body : to_lower(body);
  rule.plain_substring = body.find('*') == std::string::npos && body.find('^') == std::string::npos;
  if (rule.badfilter) {
    // A `$badfilter` line blocks nothing by itself: remember it and let
    // apply_badfilters() switch off the rules that look exactly like it.
    badfilter_lines_.push_back(text);
    ++stats_.badfilter_rules;
    return true;
  }
  rule.index = rules_.size();
  rules_.push_back(rule);
  index_rule(rules_.back());
  if (rule.allow) {
    ++stats_.allow_rules;
  } else if (rule.is_response_only()) {
    // Not a block rule: it edits the answer instead of stopping the request.
    ++stats_.response_rules;
  } else {
    ++stats_.block_rules;
  }
  return true;
}

namespace {

/// Four bytes of a string as one little-endian word: the key of the literal
/// index.  Both the rule literal and the URL go through this, which is why the
/// index answer is always a superset of the rules that can match.
std::uint32_t key4_of(const std::string& text, std::size_t at = 0) {
  return static_cast<std::uint32_t>(static_cast<unsigned char>(text[at])) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(text[at + 1])) << 8) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(text[at + 2])) << 16) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(text[at + 3])) << 24);
}

/// Canonical form of a filter line: the pattern plus its options, sorted, with
/// `$badfilter` dropped.  Two lines with the same signature ask for the same
/// thing, which is exactly what a `$badfilter` line names.
std::string filter_signature(const std::string& raw) {
  const std::string text = to_lower(trim(raw));
  const std::size_t dollar = text.rfind('$');
  if (dollar == std::string::npos) return text + "$";
  std::vector<std::string> keep;
  for (const std::string& part : split_options(text.substr(dollar + 1))) {
    const std::string one = trim(part);
    if (one == "badfilter") continue;
    keep.push_back(one);
  }
  std::sort(keep.begin(), keep.end());
  std::string out = text.substr(0, dollar) + "$";
  for (std::size_t i = 0; i < keep.size(); ++i) {
    if (i) out += ',';
    out += keep[i];
  }
  return out;
}

}  // namespace

void RuleSet::index_rule(Rule& rule) {
  // A pure host pattern ("ads.example.com^", "ads.example.com") can be indexed
  // by host name: the trailing `^` is a separator, not part of the name.
  std::string host_key = rule.pattern;
  if (!host_key.empty() && host_key.back() == '^') host_key.pop_back();
  const bool host_shaped = rule.domain_anchor && host_key.find('/') == std::string::npos &&
                           host_key.find('*') == std::string::npos &&
                           host_key.find('^') == std::string::npos && !host_key.empty();
  if (host_shaped) {
    host_index_[host_key].push_back(rule.index);
    ++stats_.host_rules;
    // Only a rule that really blocks the request may reach the hosts file and
    // the DNS sink: `$removeparam` rewrites, `$redirect` answers locally and a
    // response rule edits the answer.  None of those may sink the whole name.
    if (rule.action() == RuleAction::Block) {
      blocked_hosts_.insert(host_key);
      if (host_rule_index_.find(host_key) == host_rule_index_.end()) {
        host_rule_index_[host_key] = rule.index;
      }
    }
    return;
  }
  generic_index_.push_back(rule.index);
  ++stats_.generic_rules;
  // A generic rule is only reachable when its required literal is in the URL,
  // so index it by the first four bytes of that literal.  Patterns that are all
  // wildcards (or have a literal shorter than the key) cannot be indexed and are
  // tested on every request instead.
  rule.literal = required_literal(rule);
  if (rule.literal.size() >= 4) {
    rule.literal_key = key4_of(rule.literal);
    literal_index_[rule.literal_key].push_back(rule.index);
  } else {
    rule.literal_key = 0;
    generic_unkeyed_.push_back(rule.index);
  }
}

bool RuleSet::load_text(const std::string& text, std::string* error) {
  std::istringstream in(text);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::string reason;
    add_line(line, &reason);
  }
  // `$badfilter` names rules that may live in an earlier list, so this runs once
  // per loaded list, over everything loaded so far.
  apply_badfilters();
  if (error) error->clear();
  return true;
}

bool RuleSet::load_file(const std::string& path, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error) *error = "cannot open rule list '" + path + "'";
    return false;
  }
  std::ostringstream buf;
  buf << in.rdbuf();
  // Several lists can be stacked (--rules + --rules-extra): keep every path so the
  // summary line says where the loaded rules came from.
  if (source_.empty()) {
    source_ = path;
  } else if (source_.find(path) == std::string::npos) {
    source_ += ", " + path;
  }
  return load_text(buf.str(), error);
}

void RuleSet::apply_badfilters() {
  if (badfilter_lines_.empty()) return;
  std::vector<std::string> off;
  off.reserve(badfilter_lines_.size());
  for (const std::string& line : badfilter_lines_) off.push_back(filter_signature(line));
  std::sort(off.begin(), off.end());
  for (Rule& rule : rules_) {
    if (rule.disabled) continue;
    if (std::binary_search(off.begin(), off.end(), filter_signature(rule.raw))) {
      rule.disabled = true;
    }
  }
}

void RuleSet::clear() {
  rules_.clear();
  skipped_.clear();
  badfilter_lines_.clear();
  host_index_.clear();
  generic_index_.clear();
  literal_index_.clear();
  generic_unkeyed_.clear();
  blocked_hosts_.clear();
  host_rule_index_.clear();
  stats_ = RuleStats();
  source_.clear();
}

// ---------------------------------------------------------------- matching

namespace {

bool match_here(const std::string& pat, std::size_t pi, const std::string& url, std::size_t ui,
                bool end_anchor) {
  while (pi < pat.size()) {
    const char c = pat[pi];
    if (c == '*') {
      while (pi < pat.size() && pat[pi] == '*') ++pi;
      if (pi == pat.size()) return true;  // trailing * matches anything, even nothing
      for (std::size_t k = ui; k <= url.size(); ++k) {
        if (match_here(pat, pi, url, k, end_anchor)) return true;
      }
      return false;
    }
    if (c == '^') {
      if (!sep_at(url, ui)) return false;
      ++pi;
      if (ui < url.size()) ++ui;  // at the end of the URL a separator eats nothing
      continue;
    }
    if (ui >= url.size() || url[ui] != c) return false;
    ++pi;
    ++ui;
  }
  return !end_anchor || ui == url.size();
}

/// Leading literal of a pattern, used to skip hopeless start positions.
std::string leading_literal(const std::string& pat) {
  std::size_t n = 0;
  while (n < pat.size() && pat[n] != '*' && pat[n] != '^') ++n;
  return pat.substr(0, n);
}

}  // namespace

bool RuleSet::pattern_matches(const Rule& rule, const std::string& url) {
  const std::string& pat = rule.pattern;
  // An empty pattern is "every URL": add_line() only lets those through when a
  // type or domain option constrains them, so this is not a match-everything.
  if (pat.empty()) return true;
  if (rule.plain_substring) {
    if (rule.start_anchor) return url.compare(0, pat.size(), pat) == 0;
    if (rule.end_anchor) {
      return url.size() >= pat.size() && url.compare(url.size() - pat.size(), pat.size(), pat) == 0;
    }
    return url.find(pat) != std::string::npos;
  }
  if (rule.start_anchor) {
    return match_here(pat, 0, url, 0, rule.end_anchor);
  }
  const std::string lead = leading_literal(pat);
  if (rule.domain_anchor && !lead.empty()) {
    // `||` means "at a host label boundary": the match may start at the
    // beginning of the URL or right after '.', '/', ':' or '?'.
    std::size_t pos = url.find(lead);
    while (pos != std::string::npos) {
      const bool boundary = pos == 0 || url[pos - 1] == '.' || url[pos - 1] == '/' ||
                            url[pos - 1] == ':' || url[pos - 1] == '?';
      if (boundary && match_here(pat, 0, url, pos, rule.end_anchor)) return true;
      pos = url.find(lead, pos + 1);
    }
    return false;
  }
  if (!lead.empty()) {
    std::size_t pos = url.find(lead);
    while (pos != std::string::npos) {
      if (match_here(pat, 0, url, pos, rule.end_anchor)) return true;
      pos = url.find(lead, pos + 1);
    }
    return false;
  }
  for (std::size_t i = 0; i <= url.size(); ++i) {
    if (match_here(pat, 0, url, i, rule.end_anchor)) return true;
  }
  return false;
}

bool RuleSet::type_matches(const Rule& rule, ResourceType type) {
  // `$~script`-style options say what the rule must *not* be used for.
  for (const ResourceType t : rule.exclude_types) {
    if (t == type) return false;
    if (t == ResourceType::Document && type == ResourceType::Subdocument) return false;
  }
  if (rule.types.empty()) return true;
  for (const ResourceType t : rule.types) {
    if (t == type) return true;
    // `$document` in a list usually means "the page itself or a frame".
    if (t == ResourceType::Document && type == ResourceType::Subdocument) return true;
  }
  return false;
}

bool RuleSet::option_domains_allow(const Rule& rule, const std::string& document) {
  for (const std::string& ex : rule.exclude_domains) {
    if (document == ex || ends_with(document, ("." + ex).c_str())) return false;
  }
  if (rule.include_domains.empty()) return true;
  if (document.empty()) return false;  // the option cannot be satisfied
  for (const std::string& inc : rule.include_domains) {
    if (document == inc || ends_with(document, ("." + inc).c_str())) return true;
  }
  return false;
}

bool RuleSet::rule_matches(const Rule& rule, const RuleRequest& request,
                          const std::string& lower_url) {
  // The caller lower-cases the URL once per request; doing it here would copy it
  // for every rule, which on a real list is thousands of copies per request.
  const std::string& url = rule.match_case ? request.url : lower_url;
  // A `$badfilter` line switched this rule off; `$badfilter` lines themselves are
  // never active either.
  if (rule.disabled || rule.badfilter) return false;
  if (!type_matches(rule, request.type)) return false;
  if (rule.third_party && !request.third_party()) return false;
  if (rule.first_party && request.third_party()) return false;
  if (!option_domains_allow(rule, request.document)) return false;
  return pattern_matches(rule, url);
}

std::string RuleSet::required_literal(const Rule& rule) {
  if (rule.plain_substring) return to_lower(rule.pattern);
  // Longest run of ordinary characters.  Wildcards and separators can be
  // skipped by the pattern, but every literal run has to be in the URL for the
  // pattern to match at all, so the longest one is a safe requirement.
  std::string best;
  std::string current;
  for (const char c : rule.pattern) {
    if (c == '*' || c == '^') {
      if (current.size() > best.size()) best = current;
      current.clear();
      continue;
    }
    current.push_back(c);
  }
  if (current.size() > best.size()) best = current;
  return to_lower(best);
}

void RuleSet::collect_candidates(const std::string& lower_url,
                                 std::vector<std::size_t>* out) const {
  out->clear();
  if (!literal_index_enabled_) {
    // The honest, slow answer: every generic rule, in list order.  The self-test
    // compares the two so the index can never quietly drop a match.
    *out = generic_index_;
    return;
  }
  if (!literal_index_.empty() && lower_url.size() >= 4) {
    for (std::size_t at = 0; at + 4 <= lower_url.size(); ++at) {
      const auto it = literal_index_.find(key4_of(lower_url, at));
      if (it == literal_index_.end()) continue;
      out->insert(out->end(), it->second.begin(), it->second.end());
    }
  }
  out->insert(out->end(), generic_unkeyed_.begin(), generic_unkeyed_.end());
  std::sort(out->begin(), out->end());
  out->erase(std::unique(out->begin(), out->end()), out->end());
}

RuleDecision RuleSet::decide(const RuleRequest& request) const {
  RuleDecision out;
  const Rule* first_allow = nullptr;
  const Rule* first_block = nullptr;
  const Rule* first_important = nullptr;
  const std::string lower_url = to_lower(request.url);
  std::vector<std::size_t> candidates;
  collect_candidates(lower_url, &candidates);

  // Every rule is inspected: an exception further down the list still wins over
  // a block rule further up, so stopping at the first match would be wrong.
  // Host-anchored rules are looked at first because naming the exact host is
  // more specific than a substring of the URL.
  if (!request.host.empty()) {
    for (const std::string& candidate : parent_domains(request.host)) {
      const auto it = host_index_.find(candidate);
      if (it == host_index_.end()) continue;
      for (const std::size_t idx : it->second) {
        const Rule& rule = rules_[idx];
        if (rule.is_response_only()) continue;  // handled by collect_response_rewrite
        if (!rule_matches(rule, request, lower_url)) continue;
        if (rule.important && !rule.allow) {
          if (!first_important) first_important = &rule;
        } else if (rule.allow) {
          if (!first_allow) first_allow = &rule;
        } else if (!first_block) {
          first_block = &rule;
        }
      }
    }
  }
  for (const std::size_t idx : candidates) {
    const Rule& rule = rules_[idx];
    if (rule.is_response_only()) continue;
    if (!rule_matches(rule, request, lower_url)) continue;
    if (rule.important && !rule.allow) {
      if (!first_important) first_important = &rule;
    } else if (rule.allow) {
      if (!first_allow) first_allow = &rule;
    } else if (!first_block) {
      first_block = &rule;
    }
  }

  // $important beats an exception, which beats an ordinary block rule.
  const Rule* chosen = first_important ? first_important : (first_allow ? first_allow : first_block);
  if (!chosen) return out;
  out.action = chosen->action();
  out.rule = chosen;
  out.value = !chosen->removeparam.empty() ? chosen->removeparam : chosen->redirect;
  out.allowed_by_exception = chosen->allow;
  return out;
}

bool RuleSet::collect_response_rewrite(const RuleRequest& request, ResponseRewrite* out) const {
  if (out == nullptr) return false;
  bool any = false;
  const std::string lower_url = to_lower(request.url);
  const auto consider = [&](const Rule& rule) {
    if (rule.allow || !rule.has_response_modifiers()) return;
    if (!rule_matches(rule, request, lower_url)) return;
    for (const std::string& header : rule.set_headers) out->set_headers.push_back(header);
    for (const std::string& name : rule.remove_headers) out->remove_headers.push_back(name);
    for (const std::string& name : rule.remove_cookies) out->remove_cookies.push_back(name);
    for (const RewriteReplace& rep : rule.replaces) out->replaces.push_back(rep);
    for (const std::string& css : rule.inject_css) out->inject_css.push_back(css);
    for (const std::string& script : rule.inject_script) out->inject_script.push_back(script);
    // Name the rule in the plan: every rewrite is triggered by a rule, so the
    // log has to be able to say which one.
    if (out->source_count == 0) out->source = rule.raw;
    ++out->source_count;
    any = true;
  };
  // Same order as decide(): exact host names first, then the generic patterns,
  // and only the ones whose literal can still be in the URL.
  std::vector<std::size_t> candidates;
  collect_candidates(lower_url, &candidates);
  if (!request.host.empty()) {
    for (const std::string& candidate : parent_domains(request.host)) {
      const auto it = host_index_.find(candidate);
      if (it == host_index_.end()) continue;
      for (const std::size_t idx : it->second) consider(rules_[idx]);
    }
  }
  for (const std::size_t idx : candidates) consider(rules_[idx]);
  return any;
}

std::string RuleSet::cosmetic_css(const std::string& document_host, std::string* source,
                                 bool include_generic) const {
  if (cosmetics_.empty()) return std::string();
  const std::string host = to_lower(document_host);
  std::string css;
  // Which rules get named in `source`.  A site's own rules come first: EasyList's
  // generic half matches every document, so naming the first six rules that
  // happened to match made a page cleaned up by `onlinedown.net##…` read as if
  // `###AC_ad` had done it.  Site rules are named, everything unnamed is counted.
  std::vector<std::string> site_names;
  std::vector<std::string> generic_names;
  std::size_t applied = 0;
  constexpr std::size_t kShownSelectors = 6;    // the rest are only counted
  for (const CosmeticRule& rule : cosmetics_) {
    // A rule with no domain list applies everywhere.  Injecting that whole list
    // into replies that cannot render a page (JSON, images, scripts) changes
    // nothing a user could see, so the caller turns them off for those.
    if (!include_generic && rule.include_domains.empty()) continue;
    if (!cosmetic_applies(rule, host)) continue;
    // A selector that needs the page engine — `:has()`, `:upward()`, … — cannot
    // be expressed as CSS here: the two EasyList Bing rules
    // (`bing.com##.b_algo:has(.b_lineclamp2):not(:has([data-rslinkclamp-iid]))`)
    // are exactly that shape, and evaluating them against the DOM is what
    // `RuleSet::procedural_programs` does instead.  Everything a plain
    // class/id selector hides still works, so those stay here.
    if (cosmetic_selector_is_procedural(rule.selector)) continue;
    bool excepted = false;
    for (const CosmeticRule& ex : cosmetic_exceptions_) {
      if (ex.selector == rule.selector && cosmetic_applies(ex, host)) {
        excepted = true;
        break;
      }
    }
    if (excepted) continue;
    if (!css.empty()) css += "\n";
    // `!important` so a page rule cannot out-specify the hiding.  A `#$#` rule
    // brought its own declarations along; those replace the hiding.
    css += rule.selector + "{" +
           (rule.style.empty() ? "display:none !important" : rule.style) + "}";
    if (source != nullptr) {
      // Spell it the way it would be written in a list, so the log entry can be
      // pasted back into the rules file.
      const bool everywhere = rule.include_domains.empty();
      std::vector<std::string>& names = everywhere ? generic_names : site_names;
      if (names.size() < kShownSelectors) {
        names.push_back(everywhere ? ("##" + rule.selector) : (host + "##" + rule.selector));
      }
      ++applied;
    }
  }
  if (source != nullptr && applied > 0) {
    const std::vector<std::string>& names = site_names.empty() ? generic_names : site_names;
    for (const std::string& name : names) {
      if (!source->empty()) *source += ", ";
      *source += name;
    }
    const std::size_t unnamed = applied - names.size();
    if (unnamed > 0) *source += "  (+" + std::to_string(unnamed) + " more)";
  }
  return css;
}

std::vector<CosmeticProgram> RuleSet::procedural_programs(const std::string& document_host,
                                                          std::string* source,
                                                          bool include_generic) const {
  std::vector<CosmeticProgram> out;
  if (procedural_.empty()) return out;
  const std::string host = to_lower(document_host);
  // Named the same way `cosmetic_css` names its selectors: the site's own rules
  // come first, then the domain-less ones, and the rest is only counted.
  std::vector<std::string> site_names;
  std::vector<std::string> generic_names;
  std::size_t applied = 0;
  constexpr std::size_t kShownSelectors = 6;
  for (const CosmeticRule& rule : procedural_) {
    if (!include_generic && rule.include_domains.empty()) continue;
    if (!cosmetic_applies(rule, host)) continue;
    bool excepted = false;
    for (const CosmeticRule& ex : procedural_exceptions_) {
      if (ex.selector == rule.selector && cosmetic_applies(ex, host)) {
        excepted = true;
        break;
      }
    }
    if (excepted) continue;
    // It compiled once when the line was read; a failure here would mean the
    // stored selector changed, so there is nothing to report to the user.
    CosmeticProgram program;
    if (!cosmetic_compile(rule.selector, &program, nullptr)) continue;
    program.remove = rule.remove;
    program.style = rule.style;
    if (source != nullptr) {
      const bool everywhere = rule.include_domains.empty();
      std::vector<std::string>& names = everywhere ? generic_names : site_names;
      if (names.size() < kShownSelectors) {
        names.push_back(everywhere ? ("##" + rule.selector) : (host + "##" + rule.selector));
      }
      ++applied;
    }
    out.push_back(std::move(program));
  }
  if (source != nullptr && applied > 0) {
    const std::vector<std::string>& names = site_names.empty() ? generic_names : site_names;
    for (const std::string& name : names) {
      if (!source->empty()) *source += ", ";
      *source += name;
    }
    const std::size_t unnamed = applied - names.size();
    if (unnamed > 0) *source += "  (+" + std::to_string(unnamed) + " more)";
  }
  return out;
}

bool RuleSet::host_blocked(const std::string& host) const {
  if (host.empty()) return false;
  for (const std::string& candidate : parent_domains(to_lower(host))) {
    if (blocked_hosts_.find(candidate) != blocked_hosts_.end()) return true;
  }
  return false;
}

std::vector<std::string> RuleSet::blocked_hosts() const {
  // blocked_hosts_ is a std::set, so the result is already sorted and unique.
  return std::vector<std::string>(blocked_hosts_.begin(), blocked_hosts_.end());
}

const Rule* RuleSet::host_rule(const std::string& host) const {
  if (host.empty()) return nullptr;
  for (const std::string& candidate : parent_domains(to_lower(host))) {
    const auto it = host_rule_index_.find(candidate);
    if (it != host_rule_index_.end()) return &rules_[it->second];
  }
  return nullptr;
}

std::string RuleSet::describe() const {
  std::string out = std::to_string(rules_.size()) + " rule(s): " +
                    std::to_string(stats_.block_rules) + " block, " +
                    std::to_string(stats_.allow_rules) + " allow";
  if (stats_.response_rules) out += ", " + std::to_string(stats_.response_rules) + " response";
  if (stats_.host_rules) out += ", " + std::to_string(stats_.host_rules) + " by host name";
  if (stats_.generic_rules) out += ", " + std::to_string(stats_.generic_rules) + " generic";
  if (stats_.element_hide) out += ", " + std::to_string(stats_.element_hide) + " cosmetic";
  if (stats_.badfilter_rules) {
    out += ", " + std::to_string(stats_.badfilter_rules) + " badfilter";
  }
  if (stats_.skipped) out += ", " + std::to_string(stats_.skipped) + " skipped";
  if (!source_.empty()) out += "  [" + source_ + "]";
  return out;
}

std::string RuleSet::skipped_report(std::size_t limit) const {
  std::string out;
  const std::size_t n = skipped_.size() < limit ? skipped_.size() : limit;
  for (std::size_t i = 0; i < n; ++i) {
    out += "  line " + std::to_string(skipped_[i].line) + ": " + skipped_[i].reason + "  (" +
           skipped_[i].text + ")\n";
  }
  if (skipped_.size() > n) {
    out += "  ... and " + std::to_string(skipped_.size() - n) + " more\n";
  }
  return out;
}

std::string rule_syntax_help() {
  return "Filter list syntax (Adblock Plus / uBlock compatible subset)\n"
         "  ||domain^            block a whole domain and its subdomains\n"
         "  ||domain/path/*      wildcards inside a domain-anchored pattern\n"
         "  |http://...          anchored at the start of the URL\n"
         "  /ads/track.js|       anchored at the end of the URL\n"
         "  -advertisement-      plain substring anywhere in the URL\n"
         "  ^                    separator (anything but a letter, digit, _ - . %)\n"
         "  @@||domain^          exception: never block this\n"
         "  $third-party,$script,$image,$stylesheet,$xmlhttprequest,$font,\n"
         "  $media,$subdocument,$document,$websocket,$ping,$object,$other\n"
         "  $domain=a.com|~b.com   only on those sites / never on those sites\n"
         "  $important           beats an exception\n"
         "  $removeparam=utm_*   rewrite the query string instead of blocking\n"
         "  $redirect=noop.js    answer with a local stub instead of the network\n"
         "  $csp=script-src 'none'   set a Content-Security-Policy response header\n"
         "                       (a bare $csp uses default-src 'self')\n"
         "  $header=x-thing: yes     set any other response header\n"
         "  $removeheader=refresh    drop a response header\n"
         "  $removecookie=tracker    drop one Set-Cookie ('*' drops them all)\n"
         "  $replace=/ads/ad/gi      edit the response body with a regular expression\n"
         "  $css=body{display:none}  inject a <style> before </head>\n"
         "  $script=console.log(1)   inject a <script> before </head>\n"
         "  ! comment            [Adblock Plus 2.0] header lines are skipped\n"
         "  hosts files          \"0.0.0.0 ads.example.com\" or one host per line\n"
         "Notes\n"
         "  $css, $script, $replace, $csp and $header take free text, so they swallow\n"
         "  the rest of the line: write them last, and put one per rule.\n"
         "  Response options only rewrite; a rule with just those never blocks.\n"
         "  not supported        lookaround/backreference regexps, /.../ URL patterns,\n"
         "                       brotli/zstd bodies, ranged or streamed responses\n";
}

}  // namespace netcap
