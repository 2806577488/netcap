// Procedural cosmetic filters — see include/netcap/cosmetic.hpp for the design.
//
// This file is strings in, strings out: the selector compiler, the JSON the page
// reads, and the engine that runs in the page.  Nothing here touches a socket,
// which is what lets the self-test check every operator without a browser.
#include "netcap/cosmetic.hpp"

#include <cctype>
#include <cstdlib>

namespace netcap {

const char* const kCosmeticScriptPath = "/__netcap/cosmetic.js";

namespace {

constexpr std::size_t kMaxSelectorLength = 512;

std::string trim_copy(const std::string& text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && std::isspace(static_cast<unsigned char>(text[begin]))) ++begin;
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) --end;
  return text.substr(begin, end - begin);
}

std::string lower_copy(const std::string& text) {
  std::string out = text;
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string unquote(const std::string& text) {
  const std::string t = trim_copy(text);
  if (t.size() >= 2 && (t.front() == '"' || t.front() == '\'') && t.back() == t.front()) {
    return t.substr(1, t.size() - 2);
  }
  return t;
}

bool is_name_char(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-';
}

bool all_digits(const std::string& text) {
  if (text.empty()) return false;
  for (char c : text) {
    if (std::isdigit(static_cast<unsigned char>(c)) == 0) return false;
  }
  return true;
}

// Reads the argument of a function call whose '(' sits at `open`.  Handles
// nesting and quotes so `:has(> a[href=")"])` is read whole.  On success `inner`
// is the text between the parentheses and `after` is the index just past ')'.
bool read_call(const std::string& text, std::size_t open, std::string* inner,
               std::size_t* after) {
  if (open >= text.size() || text[open] != '(') return false;
  int depth = 0;
  char quote = 0;
  for (std::size_t i = open; i < text.size(); ++i) {
    const char c = text[i];
    if (quote != 0) {
      if (c == '\\') {
        ++i;
      } else if (c == quote) {
        quote = 0;
      }
      continue;
    }
    if (c == '"' || c == '\'') {
      quote = c;
      continue;
    }
    if (c == '(') {
      ++depth;
      continue;
    }
    if (c == ')') {
      if (--depth == 0) {
        *inner = text.substr(open + 1, i - open - 1);
        *after = i + 1;
        return true;
      }
    }
  }
  return false;
}

// Splits "a, b" at top level, so `:matches-css(content, "a, b")` stays in two.
std::vector<std::string> split_args(const std::string& inner) {
  std::vector<std::string> out;
  int depth = 0;
  char quote = 0;
  std::string current;
  for (std::size_t i = 0; i < inner.size(); ++i) {
    const char c = inner[i];
    if (quote != 0) {
      current += c;
      if (c == '\\' && i + 1 < inner.size()) {
        current += inner[++i];
      } else if (c == quote) {
        quote = 0;
      }
      continue;
    }
    if (c == '"' || c == '\'') {
      quote = c;
      current += c;
      continue;
    }
    if (c == '(' || c == '[') ++depth;
    if (c == ')' || c == ']') --depth;
    if (c == ',' && depth == 0) {
      out.push_back(trim_copy(current));
      current.clear();
      continue;
    }
    current += c;
  }
  if (!trim_copy(current).empty() || !out.empty()) out.push_back(trim_copy(current));
  return out;
}

// Pseudo-classes that are plain CSS: they stay in the base selector, where the
// browser evaluates them.  Anything else in `:name(…)` form is either one of our
// operators or something this engine does not implement — and the difference
// matters, because silently leaving an unknown operator in the base selector
// makes `querySelectorAll` throw and the rule vanish without a word.
bool is_plain_css_pseudo(const std::string& name) {
  static const char* kNames[] = {"not",  "is",   "where",     "nth-child",  "nth-last-child",
                                 "nth-of-type", "nth-last-of-type", "lang", "dir", "host",
                                 "host-context", "slotted", "matches"};
  for (const char* candidate : kNames) {
    if (name == candidate) return true;
  }
  return false;
}

// `> .ad` is relative to the element the op runs on; `:scope` is how a browser
// spells that in `querySelectorAll`.
std::string relative_selector(const std::string& arg) {
  const std::string t = trim_copy(arg);
  if (t.empty()) return t;
  const char first = t[0];
  if (first == '>' || first == '+' || first == '~') return ":scope " + t;
  return t;
}

// The heart of the compiler: walks `text`, moves every operator out of it and
// leaves the plain CSS part in `base`.
bool compile_ops(const std::string& text, std::string* base, std::vector<CosmeticOp>* ops,
                 std::string* why) {
  for (std::size_t i = 0; i < text.size();) {
    const char c = text[i];
    if (c == '"' || c == '\'') {
      const char quote = c;
      std::size_t j = i + 1;
      while (j < text.size() && text[j] != quote) {
        if (text[j] == '\\' && j + 1 < text.size()) ++j;
        ++j;
      }
      if (j >= text.size()) {
        *why = "unterminated quote";
        return false;
      }
      *base += text.substr(i, j - i + 1);
      i = j + 1;
      continue;
    }
    if (c == '[') {
      // Attribute selectors can hold quotes, ')' and even ']' inside a value.
      std::size_t j = i + 1;
      char quote = 0;
      for (; j < text.size(); ++j) {
        const char d = text[j];
        if (quote != 0) {
          if (d == '\\') {
            ++j;
          } else if (d == quote) {
            quote = 0;
          }
          continue;
        }
        if (d == '"' || d == '\'') {
          quote = d;
          continue;
        }
        if (d == ']') break;
      }
      if (j >= text.size()) {
        *why = "unbalanced '[' in the selector";
        return false;
      }
      *base += text.substr(i, j - i + 1);
      i = j + 1;
      continue;
    }
    if (c == '{' || c == '}' || c == '<') {
      *why = "the selector contains a character that does not belong in one";
      return false;
    }
    if (c != ':') {
      *base += c;
      ++i;
      continue;
    }
    std::size_t j = i + 1;
    std::string name;
    while (j < text.size() && is_name_char(text[j])) {
      name += text[j];
      ++j;
    }
    const std::string lname = lower_copy(name);
    if (j >= text.size() || text[j] != '(') {
      // A bare pseudo-class (`:hover`) or a pseudo-element (`::before`).
      *base += text.substr(i, j - i);
      i = j;
      continue;
    }
    std::string inner;
    std::size_t after = 0;
    if (!read_call(text, j, &inner, &after)) {
      *why = "unbalanced '(' after :" + name;
      return false;
    }
    if (lname == "has") {
      const std::string arg = relative_selector(inner);
      if (arg.empty()) {
        *why = ":has() needs a selector";
        return false;
      }
      CosmeticOp op;
      op.kind = CosmeticOp::Kind::Has;
      op.arg = arg;
      ops->push_back(op);
      i = after;
      continue;
    }
    if (lname == "not") {
      std::string nested_base;
      std::vector<CosmeticOp> nested;
      if (!compile_ops(inner, &nested_base, &nested, why)) return false;
      if (nested.empty()) {
        // `:not(.ad)` is plain CSS: leave it where the browser can use it.
        *base += text.substr(i, after - i);
        i = after;
        continue;
      }
      CosmeticOp op;
      op.kind = CosmeticOp::Kind::Not;
      op.arg = trim_copy(nested_base);
      op.nested = nested;
      ops->push_back(op);
      i = after;
      continue;
    }
    if (lname == "upward" || lname == "nth-ancestor") {
      const std::string arg = trim_copy(inner);
      if (arg.empty()) {
        *why = ":" + name + "() needs a number or a selector";
        return false;
      }
      CosmeticOp op;
      op.kind = CosmeticOp::Kind::Upward;
      op.arg = arg;
      if (all_digits(arg)) op.number = std::strtol(arg.c_str(), nullptr, 10);
      ops->push_back(op);
      i = after;
      continue;
    }
    if (lname == "contains" || lname == "has-text") {
      CosmeticOp op;
      op.kind = CosmeticOp::Kind::Contains;
      op.arg = unquote(inner);
      if (op.arg.empty()) {
        *why = ":contains() needs some text";
        return false;
      }
      ops->push_back(op);
      i = after;
      continue;
    }
    if (lname == "min-text-length") {
      const std::string arg = trim_copy(inner);
      if (!all_digits(arg)) {
        *why = ":min-text-length() needs a number";
        return false;
      }
      CosmeticOp op;
      op.kind = CosmeticOp::Kind::MinTextLength;
      op.arg = arg;
      op.number = std::strtol(arg.c_str(), nullptr, 10);
      ops->push_back(op);
      i = after;
      continue;
    }
    if (lname == "matches-css" || lname == "matches-attr") {
      const std::vector<std::string> args = split_args(inner);
      if (args.empty() || args[0].empty()) {
        *why = ":" + name + "() needs a name";
        return false;
      }
      CosmeticOp op;
      op.kind = lname == "matches-css" ? CosmeticOp::Kind::MatchesCss
                                       : CosmeticOp::Kind::MatchesAttr;
      op.arg = unquote(args[0]);
      if (args.size() > 1) op.value = unquote(args[1]);
      ops->push_back(op);
      i = after;
      continue;
    }
    if (lname == "xpath") {
      CosmeticOp op;
      op.kind = CosmeticOp::Kind::XPath;
      op.arg = trim_copy(inner);
      if (op.arg.empty()) {
        *why = ":xpath() needs an expression";
        return false;
      }
      ops->push_back(op);
      i = after;
      continue;
    }
    if (is_plain_css_pseudo(lname)) {
      *base += text.substr(i, after - i);
      i = after;
      continue;
    }
    *why = "unsupported procedural operator :" + name + "(…)";
    return false;
  }
  return true;
}

void append_json_string(std::string* out, const std::string& text) {
  *out += '"';
  for (unsigned char c : text) {
    switch (c) {
      case '"': *out += "\\\""; break;
      case '\\': *out += "\\\\"; break;
      case '\n': *out += "\\n"; break;
      case '\r': *out += "\\r"; break;
      case '\t': *out += "\\t"; break;
      // The program rides inside a <script> in the page: <, > and & are escaped
      // so that no selector a list can carry ends the script element early, and
      // the two line separators are escaped because they are not legal in a
      // JavaScript string literal in older engines.
      case '<': *out += "\\u003c"; break;
      case '>': *out += "\\u003e"; break;
      case '&': *out += "\\u0026"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          *out += buf;
        } else {
          *out += static_cast<char>(c);
        }
        break;
    }
  }
  *out += '"';
}

void append_json_op(std::string* out, const CosmeticOp& op) {
  *out += '[';
  append_json_string(out, op.name());
  if (op.kind == CosmeticOp::Kind::Not) {
    // ["not", "nested base", [ …nested ops… ]]
    *out += ',';
    append_json_string(out, op.arg);
    *out += ",[";
    for (std::size_t i = 0; i < op.nested.size(); ++i) {
      if (i != 0) *out += ',';
      append_json_op(out, op.nested[i]);
    }
    *out += ']';
  } else {
    *out += ',';
    append_json_string(out, op.kind == CosmeticOp::Kind::MinTextLength ? std::to_string(op.number)
                                                                      : op.arg);
    if (op.kind == CosmeticOp::Kind::MatchesCss || op.kind == CosmeticOp::Kind::MatchesAttr) {
      if (!op.value.empty()) {
        *out += ',';
        append_json_string(out, op.value);
      }
    }
  }
  *out += ']';
}

}  // namespace

const char* CosmeticOp::name() const {
  switch (kind) {
    case Kind::Has: return "has";
    case Kind::Not: return "not";
    case Kind::Upward: return "upward";
    case Kind::Contains: return "contains";
    case Kind::MatchesCss: return "mcss";
    case Kind::MatchesAttr: return "mattr";
    case Kind::MinTextLength: return "mtlen";
    case Kind::XPath: return "xpath";
  }
  return "?";
}

bool cosmetic_compile(const std::string& selector, CosmeticProgram* out, std::string* why) {
  std::string reason;
  if (out == nullptr) {
    if (why != nullptr) *why = "no output";
    return false;
  }
  const std::string text = trim_copy(selector);
  if (text.empty()) {
    if (why != nullptr) *why = "the selector is empty";
    return false;
  }
  if (text.size() > kMaxSelectorLength) {
    if (why != nullptr) *why = "the selector is longer than " + std::to_string(kMaxSelectorLength) +
                               " characters";
    return false;
  }
  std::string base;
  std::vector<CosmeticOp> ops;
  if (!compile_ops(text, &base, &ops, &reason)) {
    if (why != nullptr) *why = reason;
    return false;
  }
  out->base = trim_copy(base);
  if (out->base.empty()) out->base = "*";
  // `:upward()` with nothing to walk would collect ancestors of every element.
  out->ops = ops;
  out->raw = text;
  return true;
}

bool cosmetic_selector_is_procedural(const std::string& selector) {
  CosmeticProgram program;
  if (!cosmetic_compile(selector, &program, nullptr)) return false;
  return !program.ops.empty();
}

std::string cosmetic_operators_in(const std::string& selector) {
  CosmeticProgram program;
  if (!cosmetic_compile(selector, &program, nullptr)) return std::string();
  std::string out;
  for (const CosmeticOp& op : program.ops) {
    if (!out.empty()) out += ", ";
    out += op.name();
  }
  return out;
}

std::string cosmetic_program_json(const std::vector<CosmeticProgram>& programs) {
  if (programs.empty()) return std::string();
  std::string out = "[";
  for (std::size_t i = 0; i < programs.size(); ++i) {
    const CosmeticProgram& program = programs[i];
    if (i != 0) out += ',';
    out += "{\"b\":";
    append_json_string(&out, program.base);
    out += ",\"ops\":[";
    for (std::size_t k = 0; k < program.ops.size(); ++k) {
      if (k != 0) out += ',';
      append_json_op(&out, program.ops[k]);
    }
    out += "],\"a\":";
    append_json_string(&out, program.remove ? "remove" : (program.style.empty() ? "hide" : "style"));
    if (!program.style.empty()) {
      out += ",\"s\":";
      append_json_string(&out, program.style);
    }
    out += ",\"r\":";
    append_json_string(&out, program.raw);
    out += '}';
  }
  out += ']';
  return out;
}

std::string cosmetic_engine_script() {
  // Plain ES5: it runs in whatever engine the page runs in.  Everything inside is
  // wrapped so that one bad program (a selector the browser refuses) cannot stop
  // the others, and the console gets exactly one line when something was hidden.
  static const char* const kScript = R"JS(// netcap procedural cosmetic filter engine
(function () {
  if (window.__ncCosRun) return;
  window.__ncCosRun = 1;
  var PROGS = window.__ncCos || [];

  function textOf(el) {
    var t = el.textContent || '';
    var inner = el.innerText;
    if (inner && inner.length > t.length) t = inner;
    return t;
  }
  function listOf(nodes) {
    var out = [], i;
    for (i = 0; i < nodes.length; ++i) out.push(nodes[i]);
    return out;
  }
  function query(root, sel) {
    try { return listOf(root.querySelectorAll(sel || '*')); } catch (e) { return []; }
  }
  function matches(el, sel) {
    try { return el.matches ? el.matches(sel) : false; } catch (e) { return false; }
  }
  function asRegex(s) {
    if (s && s.length > 1 && s.charAt(0) === '/' && s.charAt(s.length - 1) === '/') {
      try { return new RegExp(s.substring(1, s.length - 1)); } catch (e) { return null; }
    }
    return null;
  }
  function keep(set, fn) {
    var out = [], i;
    for (i = 0; i < set.length; ++i) { if (fn(set[i])) out.push(set[i]); }
    return out;
  }
  function uniq(set) {
    var out = [], i;
    for (i = 0; i < set.length; ++i) { if (out.indexOf(set[i]) < 0) out.push(set[i]); }
    return out;
  }
  function applyOps(set, ops) {
    var i, k, re, out;
    for (i = 0; i < ops.length; ++i) {
      var op = ops[i] || [];
      var kind = op[0], a = op[1], v = op[2];
      if (kind === 'has') {
        set = keep(set, function (el) { return query(el, a).length > 0; });
      } else if (kind === 'not') {
        set = keep(set, function (el) {
          if (a && !matches(el, a)) return true;
          return applyOps([el], op[2] || []).length === 0;
        });
      } else if (kind === 'upward') {
        out = [];
        for (k = 0; k < set.length; ++k) {
          var el = set[k];
          if (/^[0-9]+$/.test(a)) {
            var up = parseInt(a, 10);
            for (var n = 0; n < up && el; ++n) el = el.parentElement || el.parentNode;
          } else {
            el = el.closest ? el.closest(a) : null;
          }
          if (el && el.nodeType === 1) out.push(el);
        }
        set = uniq(out);
      } else if (kind === 'contains') {
        set = keep(set, function (el) { return textOf(el).indexOf(a) >= 0; });
      } else if (kind === 'mtlen') {
        var min = parseInt(a, 10) || 0;
        set = keep(set, function (el) { return textOf(el).length >= min; });
      } else if (kind === 'mcss') {
        set = keep(set, function (el) {
          var st = null;
          try { st = window.getComputedStyle ? window.getComputedStyle(el) : null; } catch (e) { st = null; }
          if (!st) return false;
          var got = st.getPropertyValue(op[1]) || '';
          if (!v) return got !== '';
          re = asRegex(v);
          if (re) return re.test(got);
          return got.replace(/^\s+|\s+$/g, '') === v;
        });
      } else if (kind === 'mattr') {
        set = keep(set, function (el) {
          var got = el.getAttribute ? el.getAttribute(op[1]) : null;
          if (got === null || got === undefined) return false;
          if (!v) return got !== '';
          re = asRegex(v);
          if (re) return re.test(got);
          return got === v;
        });
      } else if (kind === 'xpath') {
        out = [];
        try {
          var res = document.evaluate(a, document, null, 7, null);
          for (k = 0; k < res.snapshotLength; ++k) {
            if (res.snapshotItem(k).nodeType === 1) out.push(res.snapshotItem(k));
          }
        } catch (e) { out = []; }
        set = uniq(out);
      }
    }
    return set;
  }
  function applyStyle(el, decls) {
    var parts = decls.split(';'), i;
    for (i = 0; i < parts.length; ++i) {
      var at = parts[i].indexOf(':');
      if (at <= 0) continue;
      var name = parts[i].substring(0, at).replace(/^\s+|\s+$/g, '');
      var value = parts[i].substring(at + 1).replace(/^\s+|\s+$/g, '');
      var important = '';
      if (/!\s*important$/i.test(value)) {
        important = 'important';
        value = value.replace(/!\s*important$/i, '').replace(/\s+$/, '');
      }
      try { el.style.setProperty(name, value, important); } catch (e) { /* not a property */ }
    }
  }
  function run() {
    var acted = 0, names = [], i, k;
    for (i = 0; i < PROGS.length; ++i) {
      var p = PROGS[i] || {};
      var found;
      try {
        found = applyOps(query(document, p.b), p.ops || []);
      } catch (e) { continue; }
      var count = 0;
      for (k = 0; k < found.length; ++k) {
        var el = found[k];
        if (!el || el.nodeType !== 1) continue;
        try {
          if (p.a === 'remove') {
            if (el.parentNode) el.parentNode.removeChild(el);
          } else if (p.a === 'style') {
            applyStyle(el, p.s || '');
          } else {
            el.style.setProperty('display', 'none', 'important');
          }
          ++count;
        } catch (e) { /* the page fought back: skip this element */ }
      }
      if (count > 0) {
        acted += count;
        if (names.length < 3) names.push((p.r || p.b) + ' [' + count + ']');
      }
    }
    if (acted > 0 && window.console && console.log) {
      console.log('[netcap cosmetic] ' + acted + ' element(s) handled: ' + names.join(', '));
    }
    return acted;
  }
  function arm() {
    if (!window.MutationObserver || !document.documentElement) return;
    var pending = 0;
    try {
      new MutationObserver(function () {
        if (pending) return;
        pending = setTimeout(function () { pending = 0; run(); }, 150);
      }).observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) { /* nothing to observe */ }
  }
  window.__ncCosRun = run;
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { run(); arm(); });
  } else {
    run();
    arm();
  }
})();
)JS";
  return std::string(kScript);
}

std::string cosmetic_bootstrap_script(const std::string& programs_json) {
  if (programs_json.empty()) return std::string();
  std::string js = "window.__ncCos=" + programs_json + ";";
  js += "(function(){var d=document;if(d.__ncCosLoad)return;d.__ncCosLoad=1;";
  js += "var s=d.createElement('script');s.src='";
  js += kCosmeticScriptPath;
  js += "';s.async=false;(d.head||d.documentElement).appendChild(s);})();";
  return js;
}

bool cosmetic_is_script_path(const std::string& path_and_query) {
  std::string path = path_and_query;
  const std::size_t at = path.find_first_of("?#");
  if (at != std::string::npos) path = path.substr(0, at);
  return path == kCosmeticScriptPath;
}

}  // namespace netcap
