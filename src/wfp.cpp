// WFP blocking filters: portable half (spec parsing, bookkeeping, reporting)
// plus the non-Windows stub.  The BFE calls themselves live in wfp_win.cpp.
#include "netcap/wfp.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace netcap {

namespace {

const char* proto_word(u8 p) {
  switch (p) {
    case 6: return "tcp";
    case 17: return "udp";
    case 1: return "icmp";
    case 58: return "icmpv6";
    case 0: return "any";
    default: return nullptr;
  }
}

bool parse_port(const std::string& text, u16* out) {
  if (text.empty() || text.size() > 5) return false;
  for (char c : text) {
    if (c < '0' || c > '9') return false;
  }
  const long v = std::strtol(text.c_str(), nullptr, 10);
  if (v <= 0 || v > 65535) return false;
  *out = u16(v);
  return true;
}

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

// True when this token starts a new piece of the spec (a protocol word, a
// direction word or a key=value pair) rather than a fragment of an image path.
// It is what lets "app=C:\games\x.exe tcp out" keep its trailing words while
// "app=C:\Program Files\x.exe" keeps its spaces.
bool starts_spec_piece(const std::string& t) {
  const std::string lower = to_lower(t);
  if (lower == "tcp" || lower == "udp" || lower == "icmp" || lower == "any" || lower == "all" ||
      lower == "in" || lower == "inbound" || lower == "out" || lower == "outbound") {
    return true;
  }
  const std::size_t eq = lower.find('=');
  if (eq == std::string::npos) return false;
  const std::string key = lower.substr(0, eq);
  return key == "port" || key == "ip" || key == "addr" || key == "host" || key == "name" ||
         key == "app" || key == "path" || key == "exe";
}

// "C:\dir\app.exe" or "\\server\share\app.exe": an absolute Windows path can be
// told apart from an address, which is why it is allowed without the app= key.
bool looks_like_image_path(const std::string& t) {
  if (t.size() >= 3 && t[1] == ':' && (t[2] == '\\' || t[2] == '/')) {
    const char c = t[0];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return true;
  }
  return t.size() >= 2 && t[0] == '\\' && t[1] == '\\';
}

// "host", "host:port", "[v6]:port", with an optional "/tcp|udp|any" tail.
bool parse_host_token(const std::string& token, WfpSpec* spec, std::string* error) {
  std::string body = token;
  std::string proto;
  const std::size_t slash = body.find('/');
  if (slash != std::string::npos) {
    proto = to_lower(body.substr(slash + 1));
    body = body.substr(0, slash);
  }
  std::string host = body;
  std::string port_text;
  if (!body.empty() && body[0] == '[') {
    const std::size_t close = body.find(']');
    if (close == std::string::npos) {
      if (error) *error = "unterminated '[' in '" + token + "'";
      return false;
    }
    host = body.substr(1, close - 1);
    if (close + 1 < body.size()) {
      if (body[close + 1] != ':') {
        if (error) *error = "expected ':port' after ']' in '" + token + "'";
        return false;
      }
      port_text = body.substr(close + 2);
    }
  } else {
    const std::size_t first = body.find(':');
    const std::size_t last = body.rfind(':');
    if (first != std::string::npos && first == last) {  // exactly one colon: host:port
      host = body.substr(0, first);
      port_text = body.substr(first + 1);
    } else if (first == std::string::npos) {
      host = body;  // plain address
    } else {
      host = body;  // several colons: a bare IPv6 literal, no port
    }
  }
  int version = 0;
  u8 raw[16];
  if (!parse_ip(host, &version, raw)) {
    if (error) {
      *error = "'" + host +
               "' is not an IP address (use app=<path> or port=<n> for other matches; a path "
               "with spaces has to reach netcap as one quoted argument)";
    }
    return false;
  }
  spec->family = version;
  spec->remote_ip = format_ip(version, raw);
  if (!port_text.empty()) {
    u16 port = 0;
    if (!parse_port(port_text, &port)) {
      if (error) *error = "bad port '" + port_text + "' in '" + token + "'";
      return false;
    }
    spec->remote_port = port;
  }
  if (!proto.empty()) {
    if (proto == "tcp") spec->protocol = 6;
    else if (proto == "udp") spec->protocol = 17;
    else if (proto == "any" || proto == "ip") spec->protocol = 0;
    else {
      if (error) *error = "unknown protocol '" + proto + "' (use tcp, udp or any)";
      return false;
    }
  }
  return true;
}

bool parse_key_token(const std::string& token, std::size_t eq, WfpSpec* spec, std::string* error) {
  const std::string key = to_lower(token.substr(0, eq));
  const std::string value = token.substr(eq + 1);
  if (key == "app" || key == "path" || key == "exe") {
    if (value.empty()) {
      if (error) *error = "'" + key + "=' needs an image path";
      return false;
    }
    spec->app_path = value;  // kept verbatim: paths are case sensitive
    return true;
  }  if (key == "port") {
    // "port=53/udp" is a common way to write it; the tail is a protocol.
    std::string number = value;
    std::string proto_tail;
    const std::size_t slash = value.find('/');
    if (slash != std::string::npos) {
      number = value.substr(0, slash);
      proto_tail = to_lower(value.substr(slash + 1));
    }
    u16 port = 0;
    if (!parse_port(number, &port)) {
      if (error) *error = "'" + number + "' is not a port number (1-65535)";
      return false;
    }
    spec->remote_port = port;
    if (!proto_tail.empty()) {
      if (proto_tail == "tcp") spec->protocol = 6;
      else if (proto_tail == "udp") spec->protocol = 17;
      else if (proto_tail == "any" || proto_tail == "ip") spec->protocol = 0;
      else {
        if (error) *error = "unknown protocol '" + proto_tail + "' in port= (use tcp, udp or any)";
        return false;
      }
    }
    return true;
  }
  if (key == "ip" || key == "addr" || key == "host") {
    int version = 0;
    u8 raw[16];
    if (!parse_ip(value, &version, raw)) {
      if (error) *error = "'" + value + "' is not an IP address";
      return false;
    }
    spec->family = version;
    spec->remote_ip = format_ip(version, raw);
    return true;
  }
  if (key == "name") {
    spec->name = value;
    return true;
  }
  if (error) *error = "unknown --wfp key '" + key + "' (try app=, ip=, port=, name=)";
  return false;
}

}  // namespace

const char* wfp_direction_name(WfpDirection d) {
  return d == WfpDirection::Inbound ? "inbound" : "outbound";
}

bool WfpSpec::empty() const {
  return remote_ip.empty() && remote_port == 0 && protocol == 0 && app_path.empty();
}

bool WfpSpec::specific() const { return !empty(); }

std::string WfpSpec::describe() const {
  std::string s = "block ";
  const char* word = proto_word(protocol);
  if (word) {
    s += word;
  } else {
    s += "proto ";
    s += std::to_string(int(protocol));
  }
  s += ' ';
  s += wfp_direction_name(direction);
  s += " to ";
  if (remote_ip.empty()) {
    s += family == 6 ? "any IPv6 address" : "any address";
  } else {
    s += remote_ip;
  }
  if (remote_port != 0) {
    s += ':';
    s += std::to_string(remote_port);
  }
  if (!app_path.empty()) {
    s += " from ";
    s += app_path;
  }
  return s;
}

bool wfp_parse_spec(const std::string& text, WfpSpec* out, std::string* error) {
  if (out == nullptr) {
    if (error) *error = "no spec to fill in";
    return false;
  }
  *out = WfpSpec();
  std::size_t i = 0;
  while (i < text.size()) {
    while (i < text.size() && is_space(text[i])) ++i;
    if (i >= text.size()) break;
    std::size_t end = i;
    while (end < text.size() && !is_space(text[end])) ++end;
    const std::string token = text.substr(i, end - i);
    i = end;
    if (token.empty()) continue;

    const std::size_t eq = token.find('=');
    if (eq != std::string::npos && eq > 0) {
      const std::string key = to_lower(token.substr(0, eq));
      if (key == "app" || key == "path" || key == "exe") {
        // Image paths contain spaces, and a quoted spec still reaches us as one
        // string, so "app=<path>" also takes what follows it verbatim - unless
        // that next token is clearly another piece of the spec.
        std::string rest = token.substr(eq + 1);
        std::size_t tail = i;
        while (tail < text.size() && is_space(text[tail])) ++tail;
        bool swallowed = false;
        if (tail < text.size()) {
          std::size_t tail_end = tail;
          while (tail_end < text.size() && !is_space(text[tail_end])) ++tail_end;
          const std::string next = text.substr(tail, tail_end - tail);
          if (!starts_spec_piece(next)) {
            if (!rest.empty()) rest += ' ';
            rest += text.substr(tail);
            swallowed = true;
          }
        }
        if (rest.empty()) {
          if (error) *error = "'" + key + "=' needs an image path";
          return false;
        }
        out->app_path = rest;
        if (swallowed) i = text.size();
        continue;
      }
      if (!parse_key_token(token, eq, out, error)) return false;
      continue;
    }
    const std::string lower = to_lower(token);
    if (lower == "tcp") {
      out->protocol = 6;
      continue;
    }
    if (lower == "udp") {
      out->protocol = 17;
      continue;
    }
    if (lower == "icmp") {
      out->protocol = 1;
      continue;
    }
    if (lower == "any" || lower == "all") {
      out->protocol = 0;
      continue;
    }
    if (lower == "in" || lower == "inbound") {
      out->direction = WfpDirection::Inbound;
      continue;
    }
    if (lower == "out" || lower == "outbound") {
      out->direction = WfpDirection::Outbound;
      continue;
    }
    // A Windows image path is easy to paste without the app= key: accept a bare
    // absolute path (X:\... or \\server\share) and keep it verbatim.  A fragment
    // such as "Files\Google\chrome.exe" is not accepted, because that is what a
    // shell hands over when a quoted spec was split on its spaces: the honest
    // answer there is an error that says so.
    if (looks_like_image_path(token)) {
      // Same rule as app=: the path may contain spaces, so it takes the rest
      // unless the next token is clearly another piece of the spec.
      std::string rest = token;
      std::size_t tail = i;
      while (tail < text.size() && is_space(text[tail])) ++tail;
      bool swallowed = false;
      if (tail < text.size()) {
        std::size_t tail_end = tail;
        while (tail_end < text.size() && !is_space(text[tail_end])) ++tail_end;
        const std::string next = text.substr(tail, tail_end - tail);
        if (!starts_spec_piece(next)) {
          rest += ' ';
          rest += text.substr(tail);
          swallowed = true;
        }
      }
      out->app_path = rest;
      if (swallowed) i = text.size();
      continue;
    }
    if (!parse_host_token(token, out, error)) return false;
  }
  if (!out->specific()) {
    if (error) {
      *error =
          "'" + text +
          "' matches every packet; give at least an address, a port, a protocol or an app path";
    }
    return false;
  }
  if (out->name.empty()) out->name = out->describe();
  return true;
}

std::string wfp_help() {
  return
      "  --wfp <spec>              block matching traffic with a Windows Filtering\n"
      "                            Platform filter (repeatable)\n"
      "  --wfp-apply               really install the filters (without this they are\n"
      "                            only listed)\n"
      "  --wfp-wait                keep the process alive until Ctrl+C, then remove\n"
      "                            the filters again\n"
      "  --wfp-help                this text\n"
      "\n"
      "  A spec is space-separated pieces:\n"
      "    1.2.3.4           every protocol to that address\n"
      "    1.2.3.4:443       that address and port\n"
      "    [::1]:443         the same for IPv6\n"
      "    1.2.3.4:53/udp    address, port and protocol on one token\n"
      "    port=443          any address on that port (port=53/udp also works)\n"
      "    tcp               protocol only\n"
      "    app=C:\\games\\x.exe   only that image\n"
      "    C:\\games\\x.exe       the same, without the app= key\n"
      "    in | out          inbound (default is outbound)\n"
      "  An image path (app=... or a bare X:\\... ) takes the rest of the spec and\n"
      "  keeps spaces, so put it last and quote the whole spec in the shell.\n"
      "\n"
      "  Examples:\n"
      "    netcap --wfp 203.0.113.5:443 --wfp-apply --wfp-wait\n"
      "    netcap --wfp \"udp port=53 app=C:\\tools\\dnsprobe.exe\" --wfp-apply\n"
      "\n"
      "  Installing a filter needs Administrator rights, and the filters live only\n"
      "  as long as this process: they are removed when it exits (dynamic session).\n";
}

// ---------------------------------------------------------------------------
// Engine bookkeeping (platform independent)
// ---------------------------------------------------------------------------

WfpEngine::WfpEngine() = default;

WfpEngine::~WfpEngine() { close(); }

bool WfpEngine::open(std::string* error) {
  if (engine_ != nullptr) {
    if (error) *error = "the WFP engine is already open";
    return true;
  }
  void* handle = nullptr;
  std::string err;
  if (!wfp_platform_open(&handle, &err)) {
    error_ = err;
    ++failed_;
    if (error) *error = err;
    return false;
  }
  engine_ = handle;
  error_.clear();
  installed_.clear();
  return true;
}

void WfpEngine::close() {
  if (engine_ == nullptr) return;
  for (std::size_t i = installed_.size(); i > 0; --i) {
    std::string err;
    if (wfp_platform_remove(engine_, installed_[i - 1].id, &err)) {
      ++removed_;
    } else {
      ++failed_;
      error_ = err;
    }
  }
  installed_.clear();
  wfp_platform_close(engine_);
  engine_ = nullptr;
}

bool WfpEngine::opened() const { return engine_ != nullptr; }

bool WfpEngine::add_block(const WfpSpec& spec, u64* id, std::string* error) {
  if (engine_ == nullptr) {
    error_ = "the WFP engine is not open";
    ++failed_;
    if (error) *error = error_;
    return false;
  }
  if (!spec.specific()) {
    error_ = "refusing to install a filter that matches every packet";
    ++failed_;
    if (error) *error = error_;
    return false;
  }
  u64 filter_id = 0;
  std::string err;
  if (!wfp_platform_add_block(engine_, spec, &filter_id, &err)) {
    error_ = err;
    ++failed_;
    if (error) *error = err;
    return false;
  }
  WfpFilterRecord rec;
  rec.id = filter_id;
  rec.spec = spec;
  installed_.push_back(rec);
  ++added_;
  if (id) *id = filter_id;
  return true;
}

bool WfpEngine::remove(u64 id, std::string* error) {
  if (engine_ == nullptr) {
    error_ = "the WFP engine is not open";
    ++failed_;
    if (error) *error = error_;
    return false;
  }
  for (std::size_t i = 0; i < installed_.size(); ++i) {
    if (installed_[i].id != id) continue;
    std::string err;
    if (!wfp_platform_remove(engine_, id, &err)) {
      error_ = err;
      ++failed_;
      if (error) *error = err;
      return false;
    }
    installed_.erase(installed_.begin() + std::ptrdiff_t(i));
    ++removed_;
    return true;
  }
  if (error) *error = "no filter with id " + std::to_string(id) + " was installed by this process";
  return false;
}

bool WfpEngine::remove_all(std::string* error) {
  bool all = true;
  std::string first_error;
  while (!installed_.empty()) {
    std::string err;
    if (!remove(installed_.back().id, &err)) {
      all = false;
      if (first_error.empty()) first_error = err;
      installed_.pop_back();  // do not spin forever on a filter that will not go
    }
  }
  if (!all && error) *error = first_error;
  return all;
}

std::string WfpEngine::describe() const {
  if (engine_ == nullptr) {
    return "closed: " + (error_.empty() ? std::string("not opened") : error_);
  }
  return "open, " + std::to_string(installed_.size()) + " filter(s) installed";
}

std::string WfpEngine::report() const {
  std::string s;
  char buf[256];
  std::snprintf(buf, sizeof(buf), "wfp engine          : %s\n", describe().c_str());
  s += buf;
  for (const WfpFilterRecord& rec : installed_) {
    std::snprintf(buf, sizeof(buf), "wfp filter          : id %llu  %s\n",
                  static_cast<unsigned long long>(rec.id), rec.spec.describe().c_str());
    s += buf;
  }
  std::snprintf(buf, sizeof(buf), "wfp totals          : %llu added, %llu removed, %llu failed\n",
                static_cast<unsigned long long>(added_), static_cast<unsigned long long>(removed_),
                static_cast<unsigned long long>(failed_));
  s += buf;
  return s;
}

bool WfpEngine::available(std::string* note) { return wfp_platform_available(note); }

#ifndef _WIN32

// The Windows Filtering Platform only exists on Windows.  Everything above is
// still exercised on other platforms (spec parsing, refusal to open), which is
// the point of keeping the split where it is.
bool wfp_platform_available(std::string* note) {
  if (note) *note = "the Windows Filtering Platform only exists on Windows";
  return false;
}

bool wfp_platform_elevated() { return false; }

std::string wfp_platform_note() { return "not available on this platform"; }

bool wfp_platform_open(void** engine, std::string* error) {
  if (engine) *engine = nullptr;
  if (error) *error = "the Windows Filtering Platform only exists on Windows";
  return false;
}

bool wfp_platform_add_block(void* engine, const WfpSpec& spec, u64* id, std::string* error) {
  (void)engine;
  (void)spec;
  if (id) *id = 0;
  if (error) *error = "the Windows Filtering Platform only exists on Windows";
  return false;
}

bool wfp_platform_remove(void* engine, u64 id, std::string* error) {
  (void)engine;
  (void)id;
  if (error) *error = "the Windows Filtering Platform only exists on Windows";
  return false;
}

void wfp_platform_close(void* engine) { (void)engine; }

#endif  // !_WIN32

}  // namespace netcap
