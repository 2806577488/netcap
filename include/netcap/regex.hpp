// A small regular expression engine, written for one job: the `$replace=/re/repl/`
// option of the filter lists, which needs to find a pattern inside an HTTP body
// and replace every occurrence.
//
// Why not std::regex: it is unusably slow, it throws on bad input, and its
// backtracking implementation turns a hostile pattern into a denial of service.
// This engine compiles the pattern into a small program and runs it as a
// Thompson/Pike virtual machine: the match time is linear in the input, the
// memory is bounded, and a step budget stops even the patterns that would blow up
// a backtracking matcher.  A filter list is untrusted input, so that matters.
//
// Supported: literals, `.`, `\d \D \w \W \s \S`, `\b \B`, escapes `\n \r \t \0
// \xHH`, character classes `[a-z]` `[^a-z]`, anchors `^` `$`, quantifiers
// `* + ? {n} {n,} {n,m}` with their lazy forms, groups `(...)` and `(?:...)`,
// alternation `|`, and the inline flag `(?i)` for case-insensitive matching.
//
// Not supported (rejected at compile time with a readable message): lookaround,
// back references inside the pattern, recursion, and named groups.
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace netcap {

class Regex {
 public:
  Regex();
  ~Regex();
  Regex(const Regex&);
  Regex& operator=(const Regex&);
  Regex(Regex&&) noexcept;
  Regex& operator=(Regex&&) noexcept;

  /// Compiles `pattern`.  On failure `error` explains what was not understood
  /// and the returned object is invalid.
  static bool compile(const std::string& pattern, Regex* out, std::string* error);
  static Regex compiled(const std::string& pattern, std::string* error = nullptr);

  bool valid() const;
  const std::string& pattern() const;
  /// True when the match is case insensitive (`(?i)`).
  bool case_insensitive() const;
  /// Instructions in the compiled program; useful in the self test.
  std::size_t program_size() const;

  /// Leftmost match at or after `from`.  `begin`/`end` are byte offsets.
  bool search(const std::string& text, std::size_t from, std::size_t* begin, std::size_t* end) const;
  bool search(const char* data, std::size_t len, std::size_t from, std::size_t* begin,
              std::size_t* end) const;
  bool matches(const std::string& text) const;

  /// Replaces every match.  `replacement` understands `$0`..`$9` and `\0`..`\9`
  /// (group references; `$0` is the whole match) and `$$` for a literal `$`.
  /// `count` receives how many replacements were made.
  std::string replace_all(const std::string& text, const std::string& replacement,
                          std::size_t* count = nullptr) const;

  /// Capture slots of the last successful search: `[0]`/`[1]` are the whole
  /// match, `[2]`/`[3]` the first group, and a slot pair of -1 means the group
  /// did not take part.  `replace_all` uses it for `$1`, `$2`, ...
  const std::vector<int>& last_captures() const;

  /// How many virtual machine steps the last search used, and the budget.  A
  /// search that runs out of budget simply stops early: the engine never hangs.
  std::size_t last_steps() const;
  static std::size_t step_budget();

 private:
  struct Impl;
  std::shared_ptr<Impl> impl_;
};

}  // namespace netcap
