// Element picker: "point at an element on the page and block it".
//
// The pieces, and why they are split this way:
//
//   * The proxy cannot see the DOM — only bytes on the wire.  So the picking
//     happens *inside the page*: when picker mode is on, every text/html
//     response gets one extra script (picker_script()) that highlights whatever
//     the mouse is over and, on click, asks the proxy to remember it.
//   * The page talks to the proxy over the same origin it is already using
//     (`/__netcap/pick?...`), so there is no CORS negotiation and no mixed
//     content to worry about: from the browser's point of view it is a plain
//     request to the site it is visiting, and the proxy answers it locally
//     instead of forwarding it.
//   * The proxy both (a) hides the picked selector in later responses for that
//     host right away — the user must see the element disappear without
//     restarting anything — and (b) appends a real rule line to a list file so
//     the decision survives the next restart.
//
// Everything in this header is pure (strings in, strings out) so the selector
// validation, the query parsing and the rule text can be unit tested without a
// browser and without a socket.
#pragma once

#include <string>
#include <vector>

namespace netcap {

/// Path the injected script calls.  Kept short and unlikely to collide with a
/// real page: netcap answers it itself and never forwards it upstream.
extern const char* const kPickerPath;  // "/__netcap/pick"

/// Asked by the always-present bootstrap script: "is picking on right now?".
/// Answered locally and immediately ({"picker":true|false}), which is what makes
/// the interface button work on pages that are already open.
extern const char* const kPickerCtlPath;  // "/__netcap/ctl"

/// Served locally as application/javascript — the bootstrap pulls this in the
/// moment picking turns on, so the real script is not in every response.
extern const char* const kPickerScriptPath;  // "/__netcap/picker.js"

/// The script injected into text/html responses while picker mode is on.
/// Plain ES5, no dependencies, and it removes itself on Escape.
std::string picker_script();

/// The tiny script that is in *every* text/html response while the proxy runs.
/// It polls kPickerCtlPath and loads/unloads picker_script() accordingly.
std::string picker_bootstrap_script();

/// True for the two control routes above (they work even while picking is off,
/// because that is how it gets turned on).
bool picker_is_ctl_path(const std::string& path_and_query);
bool picker_is_script_path(const std::string& path_and_query);

/// Parses "/__netcap/pick?h=example.com&s=%23ad&u=https%3A%2F%2F..."
/// (`path_and_query` is the request target as it arrived).  Returns false when
/// this is not a pick request at all, or when the selector/host are unusable.
bool picker_parse_pick(const std::string& path_and_query, std::string* host,
                       std::string* selector, std::string* url);

/// True for request targets that belong to the picker.
bool picker_is_pick_path(const std::string& path_and_query);

/// Validates a CSS selector that came out of a page.  Rejects anything that
/// could break out of the injected rule (braces, semicolons, newlines, angle
/// brackets) and anything absurdly long.
bool picker_selector_ok(const std::string& selector, std::string* why = nullptr);

/// Builds the element-hiding rule line for `host` + `selector` ("example.com##.ad").
/// Returns an empty string when either part is unusable.
std::string picker_rule_line(const std::string& host, const std::string& selector);

/// Appends `rule` to `path`, preceded by a comment naming where it was picked.
/// Creates the file (and its directory) when needed.  Returns false and fills
/// `error` when the file cannot be written.
bool picker_append_rule(const std::string& path, const std::string& rule,
                        const std::string& picked_url, std::string* error);

/// True when `document_host` is `rule_host` or a subdomain of it — the picker
/// hides on the site it was picked on, subdomains included.
bool picker_host_matches(const std::string& rule_host, const std::string& document_host);

}  // namespace netcap
