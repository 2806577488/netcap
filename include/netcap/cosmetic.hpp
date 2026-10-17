// Procedural cosmetic filters: the element-hiding rules a stylesheet cannot
// express.
//
// A plain `##selector` becomes one line of CSS (see `RuleSet::cosmetic_css`).
// Some selectors are not CSS at all — a list writes them in the procedural
// families `#?#` (procedural), `#$#` (declarations) and `#$?#` (both), and
// sometimes in `##` directly, because the operators below are its own extension
// to the syntax:
//
//   :has(> .bili-video-card)     the container is an ad because of a child
//   :upward(2)                   remove the card, not the link inside it
//   :contains(广告)              patched through an attribute or a script
//   :matches-css(display, block) the element only exists once a script ran
//   :matches-attr(data-target-url)
//   :min-text-length(20)
//   :xpath(…)                    the list fell back to raw XPath
//
// The proxy has no DOM, so the work is split the way the picker splits it:
//
//   * C++ compiles each selector once, here, into a tiny program —
//     `{"b":"base selector","ops":[["has",".ad"],["upward","2"]],"a":"remove"}`.
//     Parsing, validation and the "which operator is this" decision are all
//     strings in / strings out, so the self-test can check every operator
//     without a browser;
//   * the page runs the program.  `cosmetic_engine_script()` is a few kilobytes
//     of plain ES5 served from `kCosmeticScriptPath`, and
//     `cosmetic_bootstrap_script()` is the one-line inline script that carries
//     the programs for that host and pulls the engine in.  Both are answered by
//     the proxy itself and never forwarded upstream, and the inline part is
//     JSON-escaped so a hostile list cannot break out of the <script>.
//
// Everything in the header is pure.  Nothing here touches a socket.
#pragma once

#include <string>
#include <vector>

namespace netcap {

/// Served locally as application/javascript; the bootstrap pulls it in only on
/// the pages that actually carry procedural rules.
extern const char* const kCosmeticScriptPath;  // "/__netcap/cosmetic.js"

/// One operator written after the base selector, in the order it appears.
struct CosmeticOp {
  enum class Kind {
    Has,            ///< `:has(selector)`   keep elements with a matching descendant
    Not,            ///< `:not(ops…)`       keep elements the nested operators reject
    Upward,         ///< `:upward(2)`       act on the nth ancestor instead
    Contains,       ///< `:contains(text)`  keep elements whose text contains it
    MatchesCss,     ///< `:matches-css(prop[, value])`
    MatchesAttr,    ///< `:matches-attr(name[, value])`
    MinTextLength,  ///< `:min-text-length(n)`
    XPath,          ///< `:xpath(expr)`     replace the match set outright
  };
  Kind kind = Kind::Has;
  std::string arg;    ///< the selector, the text, the property or attribute name
  std::string value;  ///< the second argument, when the operator takes one
  long number = 0;    ///< `:upward(2)`, `:min-text-length(20)`
  /// `:not()` may carry operators of its own: `:not(:has(.x))`.
  std::vector<CosmeticOp> nested;

  /// "has" / "not" / "upward" / … — the name the JavaScript engine knows.
  const char* name() const;
};

/// One compiled selector plus what to do with what it matched.
struct CosmeticProgram {
  std::string base;             ///< ".container > .bili-feed-card" (never empty)
  std::vector<CosmeticOp> ops;  ///< applied left to right to the base match
  bool remove = false;          ///< `{ remove: true; }`: take the element out
  std::string style;            ///< `#$#…{ … }` declarations; empty means hide
  std::string raw;              ///< the selector as the list wrote it, for the log
};

/// Compiles one selector.  Returns false when it uses something this engine does
/// not implement (`:matches-media(…)`, `:watch-attr(…)`, unbalanced brackets),
/// with `why` naming it — the caller then skips the rule *and says so*, which is
/// the difference between "this rule did nothing" and "this rule was ignored".
/// `out->base` is "*" when the selector is nothing but operators.
bool cosmetic_compile(const std::string& selector, CosmeticProgram* out,
                      std::string* why = nullptr);

/// True when `selector` uses at least one operator above.  `RuleSet` uses this
/// to keep such a selector out of the CSS injection (it would simply never match
/// there) and to route it to the page engine instead.
bool cosmetic_selector_is_procedural(const std::string& selector);

/// The names of the operators `selector` uses ("has, upward"), for a log line.
std::string cosmetic_operators_in(const std::string& selector);

/// `[{"b":"…","ops":[["has",".ad"]],"a":"remove","s":"…"}, …]`, which is what the
/// injected inline script assigns to `window.__ncCos`.  `<`, `>` and `&` are
/// escaped as \u003c/…, so no selector can end the <script> early.
std::string cosmetic_program_json(const std::vector<CosmeticProgram>& programs);

/// The interpreter.  Plain ES5 (it runs in whatever the page runs in), no
/// dependencies, one console line when it actually removed or hid something.
std::string cosmetic_engine_script();

/// The inline script for one document: the programs, then a loader for the
/// engine.  Empty when `programs_json` is empty, in which case nothing is
/// injected at all — most pages carry no procedural rule.
std::string cosmetic_bootstrap_script(const std::string& programs_json);

/// True for the engine's own route.
bool cosmetic_is_script_path(const std::string& path_and_query);

}  // namespace netcap
