// The regular expression engine behind `$replace=/re/repl/`.  See regex.hpp for
// the design notes: a Pike virtual machine, so the match time is linear and a
// hostile pattern from a filter list cannot hang the proxy.
#include "netcap/regex.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace netcap {
namespace {

enum class Op : std::uint8_t {
  Char,
  Any,
  Class,
  Jmp,
  Split,
  Save,
  Bol,
  Eol,
  WordB,
  NWordB,
  Match,
};

struct Inst {
  Op op = Op::Match;
  int x = -1;
  int y = -1;
  unsigned char ch = 0;
  int cls = -1;
  int slot = 0;
};

struct CharClass {
  bool bits[256] = {};
  void add(unsigned char c) { bits[c] = true; }
  bool has(unsigned char c) const { return bits[c]; }
};

bool is_word(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

unsigned char lower(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c - 'A' + 'a') : c;
}

const std::size_t kMaxProgram = 8192;

// ---------------------------------------------------------------- the parser

enum class NT { Empty, Char, Any, Class, Bol, Eol, WordB, NWordB, Concat, Alt, Repeat, Group };

struct Node {
  NT type = NT::Empty;
  unsigned char ch = 0;
  int cls = -1;
  std::vector<std::unique_ptr<Node>> kids;
  int min = 0;
  int max = -1;  // < 0 means unbounded
  bool lazy = false;
  int slot = -1;  // capture slot of a group, -1 for (?:...)
};

std::unique_ptr<Node> make_node(NT type) {
  auto n = std::make_unique<Node>();
  n->type = type;
  return n;
}

struct Parser {
  const std::string& text;
  std::size_t pos = 0;
  int groups = 0;
  bool icase = false;
  std::vector<CharClass> pool;
  std::string error;

  explicit Parser(const std::string& t) : text(t) {}

  bool at_end() const { return pos >= text.size(); }
  char peek() const { return pos < text.size() ? text[pos] : '\0'; }
  char peek_at(std::size_t ahead) const { return pos + ahead < text.size() ? text[pos + ahead] : '\0'; }

  bool fail(const std::string& what) {
    if (error.empty()) error = what + " (at offset " + std::to_string(pos) + " of '" + text + "')";
    return false;
  }

  int add_class(const CharClass& c) {
    pool.push_back(c);
    return static_cast<int>(pool.size()) - 1;
  }

  std::unique_ptr<Node> parse_alternation() {
    std::vector<std::unique_ptr<Node>> branches;
    branches.push_back(parse_concat());
    while (!at_end() && peek() == '|') {
      ++pos;
      branches.push_back(parse_concat());
    }
    if (branches.size() == 1) return std::move(branches[0]);
    auto alt = make_node(NT::Alt);
    for (auto& b : branches) alt->kids.push_back(std::move(b));
    return alt;
  }

  std::unique_ptr<Node> parse_concat() {
    auto concat = make_node(NT::Concat);
    while (!at_end() && peek() != '|' && peek() != ')') {
      auto piece = parse_repeat();
      if (!piece) return nullptr;
      concat->kids.push_back(std::move(piece));
    }
    if (concat->kids.empty()) return make_node(NT::Empty);
    if (concat->kids.size() == 1) return std::move(concat->kids[0]);
    return concat;
  }

  bool parse_braces(int* min, int* max) {
    const std::size_t save = pos;
    ++pos;  // '{'
    std::string a;
    while (!at_end() && std::isdigit(static_cast<unsigned char>(peek()))) a.push_back(text[pos++]);
    std::string b;
    bool comma = false;
    if (!at_end() && peek() == ',') {
      comma = true;
      ++pos;
      while (!at_end() && std::isdigit(static_cast<unsigned char>(peek()))) b.push_back(text[pos++]);
    }
    if (at_end() || peek() != '}' || (a.empty() && b.empty())) {
      pos = save;  // not a quantifier: the '{' is a literal character
      return false;
    }
    ++pos;  // '}'
    *min = a.empty() ? 0 : std::atoi(a.c_str());
    if (!comma) {
      *max = *min;
    } else {
      *max = b.empty() ? -1 : std::atoi(b.c_str());
    }
    if (*max >= 0 && *max < *min) {
      fail("a {n,m} quantifier needs n <= m");
      return false;
    }
    return true;
  }

  std::unique_ptr<Node> parse_repeat() {
    auto atom = parse_atom();
    if (!atom) return nullptr;
    for (;;) {
      if (at_end()) return atom;
      const char c = peek();
      int min = 0;
      int max = 0;
      if (c == '*') {
        min = 0;
        max = -1;
        ++pos;
      } else if (c == '+') {
        min = 1;
        max = -1;
        ++pos;
      } else if (c == '?') {
        min = 0;
        max = 1;
        ++pos;
      } else if (c == '{') {
        if (!parse_braces(&min, &max)) {
          // A malformed quantifier such as {3,1} is an error; a lone '{' is a
          // literal character and parse_braces says so without setting `error`.
          if (!error.empty()) return nullptr;
          return atom;
        }
      } else {
        return atom;
      }
      const bool lazy = !at_end() && peek() == '?';
      if (lazy) ++pos;
      auto rep = make_node(NT::Repeat);
      rep->min = min;
      rep->max = max;
      rep->lazy = lazy;
      rep->kids.push_back(std::move(atom));
      atom = std::move(rep);
    }
  }

  bool parse_escape(CharClass* into) {
    if (at_end()) return fail("a trailing backslash has nothing to escape");
    const char c = text[pos++];
    switch (c) {
      case 'd':
        for (int i = '0'; i <= '9'; ++i) into->add(static_cast<unsigned char>(i));
        return true;
      case 'w':
        for (int i = 'a'; i <= 'z'; ++i) into->add(static_cast<unsigned char>(i));
        for (int i = 'A'; i <= 'Z'; ++i) into->add(static_cast<unsigned char>(i));
        for (int i = '0'; i <= '9'; ++i) into->add(static_cast<unsigned char>(i));
        into->add('_');
        return true;
      case 's':
        into->add(' ');
        into->add('\t');
        into->add('\n');
        into->add('\r');
        into->add('\f');
        into->add('\v');
        return true;
      case 'n': into->add('\n'); return true;
      case 'r': into->add('\r'); return true;
      case 't': into->add('\t'); return true;
      case 'f': into->add('\f'); return true;
      case 'v': into->add('\v'); return true;
      case '0': into->add('\0'); return true;
      case 'x': {
        if (pos + 1 >= text.size()) return fail("\\x needs two hex digits");
        const auto hex = [](char h) -> int {
          if (h >= '0' && h <= '9') return h - '0';
          if (h >= 'a' && h <= 'f') return h - 'a' + 10;
          if (h >= 'A' && h <= 'F') return h - 'A' + 10;
          return -1;
        };
        const int hi = hex(text[pos]);
        const int lo = hex(text[pos + 1]);
        if (hi < 0 || lo < 0) return fail("\\x needs two hex digits");
        pos += 2;
        into->add(static_cast<unsigned char>(hi * 16 + lo));
        return true;
      }
      default:
        into->add(static_cast<unsigned char>(c));
        if (icase) {
          if (c >= 'a' && c <= 'z') into->add(static_cast<unsigned char>(c - 'a' + 'A'));
          if (c >= 'A' && c <= 'Z') into->add(static_cast<unsigned char>(c - 'A' + 'a'));
        }
        return true;
    }
  }

  std::unique_ptr<Node> parse_class() {
    CharClass cls;
    bool negate = false;
    if (!at_end() && peek() == '^') {
      negate = true;
      ++pos;
    }
    bool first = true;
    for (;;) {
      if (at_end()) {
        fail("a character class is not closed");
        return nullptr;
      }
      if (peek() == ']' && !first) {
        ++pos;
        break;
      }
      first = false;
      CharClass one;
      // Parse one class atom, whether literal or escaped, and remember the
      // single character it stands for so that `\x41-\x43` and `a-\x7a` both
      // work.  Set-valued escapes such as \d are not a range endpoint.
      bool single = false;
      unsigned char lo = 0;
      if (peek() == '\\') {
        ++pos;
        if (!parse_escape(&one)) return nullptr;
        for (int i = 0; i < 256; ++i) {
          if (one.has(static_cast<unsigned char>(i))) {
            if (single) {
              single = false;
              break;
            }
            single = true;
            lo = static_cast<unsigned char>(i);
          }
        }
      } else {
        const char c = text[pos++];
        one.add(static_cast<unsigned char>(c));
        single = true;
        lo = static_cast<unsigned char>(c);
        if (icase) {
          if (c >= 'a' && c <= 'z') one.add(static_cast<unsigned char>(c - 'a' + 'A'));
          if (c >= 'A' && c <= 'Z') one.add(static_cast<unsigned char>(c - 'A' + 'a'));
        }
      }
      if (single && !at_end() && peek() == '-' && pos + 1 < text.size() && text[pos + 1] != ']') {
        ++pos;  // '-'
        CharClass two;
        bool single_hi = false;
        unsigned char hi = 0;
        if (peek() == '\\') {
          ++pos;
          if (!parse_escape(&two)) return nullptr;
          for (int i = 0; i < 256; ++i) {
            if (two.has(static_cast<unsigned char>(i))) {
              if (single_hi) {
                single_hi = false;
                break;
              }
              single_hi = true;
              hi = static_cast<unsigned char>(i);
            }
          }
        } else {
          hi = static_cast<unsigned char>(text[pos++]);
          single_hi = true;
        }
        if (single_hi) {
          if (hi < lo) {
            fail("a character range is reversed");
            return nullptr;
          }
          one = CharClass();
          for (int i = lo; i <= hi; ++i) {
            one.add(static_cast<unsigned char>(i));
            const char c = static_cast<char>(i);
            if (icase) {
              if (c >= 'a' && c <= 'z') one.add(static_cast<unsigned char>(c - 'a' + 'A'));
              if (c >= 'A' && c <= 'Z') one.add(static_cast<unsigned char>(c - 'A' + 'a'));
            }
          }
        } else {
          // A set on the right of '-': the '-' is a literal member, not a range.
          one.add('-');
          for (int i = 0; i < 256; ++i) {
            if (two.has(static_cast<unsigned char>(i))) one.add(static_cast<unsigned char>(i));
          }
        }
      }
      for (int i = 0; i < 256; ++i) {
        if (one.has(static_cast<unsigned char>(i))) cls.add(static_cast<unsigned char>(i));
      }
    }
    if (negate) {
      for (int i = 0; i < 256; ++i) cls.bits[i] = !cls.bits[i];
    }
    auto n = make_node(NT::Class);
    n->cls = add_class(cls);
    return n;
  }

  std::unique_ptr<Node> parse_atom() {
    if (at_end()) return make_node(NT::Empty);
    const char c = peek();
    switch (c) {
      case '(': {
        ++pos;
        int slot = -1;
        if (peek() == '?') {
          if (peek_at(1) == ':') {
            pos += 2;
          } else {
            fail("only the group forms (...) and (?:...) are supported");
            return nullptr;
          }
        } else {
          slot = 2 * (++groups);
        }
        auto inner = parse_alternation();
        if (!inner) return nullptr;
        if (at_end() || peek() != ')') {
          fail("a group is not closed");
          return nullptr;
        }
        ++pos;
        if (slot < 0) return inner;
        auto g = make_node(NT::Group);
        g->slot = slot;
        g->kids.push_back(std::move(inner));
        return g;
      }
      case ')':
        fail("unbalanced ')'");
        return nullptr;
      case '[': {
        ++pos;
        return parse_class();
      }
      case '.': {
        ++pos;
        return make_node(NT::Any);
      }
      case '^': {
        ++pos;
        return make_node(NT::Bol);
      }
      case '$': {
        ++pos;
        return make_node(NT::Eol);
      }
      case '*':
      case '+':
      case '?':
        fail("a quantifier has nothing to repeat");
        return nullptr;
      case '\\': {
        ++pos;
        if (at_end()) {
          fail("a trailing backslash has nothing to escape");
          return nullptr;
        }
        const char e = peek();
        if (e == 'b' || e == 'B') {
          ++pos;
          return make_node(e == 'b' ? NT::WordB : NT::NWordB);
        }
        if (e >= '1' && e <= '9') {
          fail("back references inside the pattern are not supported");
          return nullptr;
        }
        CharClass one;
        if (!parse_escape(&one)) return nullptr;
        auto n = make_node(NT::Class);
        n->cls = add_class(one);
        return n;
      }
      default: {
        ++pos;
        auto n = make_node(NT::Char);
        n->ch = icase ? lower(static_cast<unsigned char>(c)) : static_cast<unsigned char>(c);
        return n;
      }
    }
  }
};

// ------------------------------------------------------------- the compiler

struct Compiler {
  std::vector<Inst>* prog;
  std::string error;

  int emit(Inst inst) {
    prog->push_back(inst);
    return static_cast<int>(prog->size()) - 1;
  }

  bool compile(const Node* n) {
    if (n == nullptr) return true;
    switch (n->type) {
      case NT::Empty:
        return true;
      case NT::Char: {
        Inst i;
        i.op = Op::Char;
        i.ch = n->ch;
        emit(i);
        return true;
      }
      case NT::Any: {
        Inst i;
        i.op = Op::Any;
        emit(i);
        return true;
      }
      case NT::Class: {
        Inst i;
        i.op = Op::Class;
        i.cls = n->cls;
        emit(i);
        return true;
      }
      case NT::Bol:
      case NT::Eol:
      case NT::WordB:
      case NT::NWordB: {
        Inst i;
        i.op = n->type == NT::Bol     ? Op::Bol
               : n->type == NT::Eol   ? Op::Eol
               : n->type == NT::WordB ? Op::WordB
                                      : Op::NWordB;
        emit(i);
        return true;
      }
      case NT::Concat:
        for (const auto& k : n->kids) {
          if (!compile(k.get())) return false;
        }
        return true;
      case NT::Alt:
        return compile_alt(n->kids, 0);
      case NT::Group: {
        Inst a;
        a.op = Op::Save;
        a.slot = n->slot;
        emit(a);
        if (!compile(n->kids[0].get())) return false;
        Inst b;
        b.op = Op::Save;
        b.slot = n->slot + 1;
        emit(b);
        return true;
      }
      case NT::Repeat:
        return compile_repeat(n);
    }
    return true;
  }

  bool compile_alt(const std::vector<std::unique_ptr<Node>>& kids, std::size_t index) {
    if (index + 1 == kids.size()) return compile(kids[index].get());
    Inst sp;
    sp.op = Op::Split;
    const int at = emit(sp);
    (*prog)[static_cast<std::size_t>(at)].x = static_cast<int>(prog->size());
    if (!compile(kids[index].get())) return false;
    Inst jmp;
    jmp.op = Op::Jmp;
    const int j = emit(jmp);
    (*prog)[static_cast<std::size_t>(at)].y = static_cast<int>(prog->size());
    if (!compile_alt(kids, index + 1)) return false;
    (*prog)[static_cast<std::size_t>(j)].x = static_cast<int>(prog->size());
    return true;
  }

  bool compile_repeat(const Node* n) {
    const int min = n->min;
    const int max = n->max;
    const bool lazy = n->lazy;
    const Node* body = n->kids[0].get();
    for (int i = 0; i < min; ++i) {
      if (!compile(body)) return false;
    }
    if (max < 0) {
      Inst sp;
      sp.op = Op::Split;
      const int at = emit(sp);
      const int body_start = static_cast<int>(prog->size());
      if (!compile(body)) return false;
      Inst back;
      back.op = Op::Jmp;
      back.x = at;
      emit(back);
      const int after = static_cast<int>(prog->size());
      (*prog)[static_cast<std::size_t>(at)].x = lazy ? after : body_start;
      (*prog)[static_cast<std::size_t>(at)].y = lazy ? body_start : after;
      return true;
    }
    for (int i = min; i < max; ++i) {
      Inst sp;
      sp.op = Op::Split;
      const int at = emit(sp);
      const int body_start = static_cast<int>(prog->size());
      if (!compile(body)) return false;
      const int after = static_cast<int>(prog->size());
      (*prog)[static_cast<std::size_t>(at)].x = lazy ? after : body_start;
      (*prog)[static_cast<std::size_t>(at)].y = lazy ? body_start : after;
    }
    return true;
  }
};

}  // namespace

struct Regex::Impl {
  bool ok = false;
  bool icase = false;
  std::string pattern;
  std::vector<Inst> prog;
  std::vector<CharClass> classes;
  std::size_t slots = 2;  // slots[0..1] are the whole match
  mutable std::size_t steps = 0;
  mutable bool overflow = false;
  mutable std::vector<int> captures;  // from the last successful search

  struct Thread {
    int pc = 0;
    int start = 0;  // where the attempt that produced this thread began
    std::vector<int> caps;
  };

  bool consumes(const Inst& in, unsigned char c) const {
    switch (in.op) {
      case Op::Char: return icase ? lower(c) == in.ch : c == in.ch;
      case Op::Any: return c != '\n';
      case Op::Class: return classes[static_cast<std::size_t>(in.cls)].has(c);
      default: return false;
    }
  }

  // Adds `pc` (and everything reachable from it without consuming input) to
  // `list`, recording `sp` in the capture slots as it goes.
  void add_thread(std::vector<Thread>& list, std::vector<int>& seen, int gen, int pc, int start,
                  const std::vector<int>& caps, std::size_t sp, std::size_t len,
                  const char* data) {
    if (pc < 0 || pc >= static_cast<int>(prog.size()) || overflow) return;
    if (++steps > step_budget()) {
      overflow = true;
      return;
    }
    if (seen[static_cast<std::size_t>(pc)] == gen) return;
    seen[static_cast<std::size_t>(pc)] = gen;
    const Inst& in = prog[static_cast<std::size_t>(pc)];
    switch (in.op) {
      case Op::Jmp:
        add_thread(list, seen, gen, in.x, start, caps, sp, len, data);
        return;
      case Op::Split:
        add_thread(list, seen, gen, in.x, start, caps, sp, len, data);
        add_thread(list, seen, gen, in.y, start, caps, sp, len, data);
        return;
      case Op::Save: {
        std::vector<int> next = caps;
        next[static_cast<std::size_t>(in.slot)] = static_cast<int>(sp);
        add_thread(list, seen, gen, pc + 1, start, next, sp, len, data);
        return;
      }
      case Op::Bol: {
        if (sp == 0 || data[sp - 1] == '\n') {
          add_thread(list, seen, gen, pc + 1, start, caps, sp, len, data);
        }
        return;
      }
      case Op::Eol: {
        if (sp >= len || data[sp] == '\n') {
          add_thread(list, seen, gen, pc + 1, start, caps, sp, len, data);
        }
        return;
      }
      case Op::WordB:
      case Op::NWordB: {
        const bool before = sp > 0 && is_word(static_cast<unsigned char>(data[sp - 1]));
        const bool after = sp < len && is_word(static_cast<unsigned char>(data[sp]));
        if ((before != after) == (in.op == Op::WordB)) {
          add_thread(list, seen, gen, pc + 1, start, caps, sp, len, data);
        }
        return;
      }
      default: {
        Thread t;
        t.pc = pc;
        t.start = start;
        t.caps = caps;
        list.push_back(std::move(t));
        return;
      }
    }
  }

  bool search(const char* data, std::size_t len, std::size_t from, std::size_t* begin,
              std::size_t* end) {
    steps = 0;
    overflow = false;
    captures.clear();
    if (!ok) return false;
    // Capture bookkeeping is only paid for when the pattern has groups.
    const bool track = slots > 2;
    struct Raw {
      int pc = 0;
      int start = 0;
      std::vector<int> caps;
    };
    std::vector<Thread> clist;
    std::vector<Raw> raw;
    std::vector<Raw> raw_next;
    std::vector<int> seen(prog.size(), -1);
    int gen = 0;
    const std::vector<int> fresh(track ? slots : 0, -1);
    int best_start = -1;
    int best_end = -1;
    std::vector<int> best_caps;
    for (std::size_t sp = from; sp <= len; ++sp) {
      // One generation per position: the threads carried over from `sp - 1` are
      // closed over the epsilon transitions at this position, and so is the
      // fresh attempt that starts here.  Carried threads are added first, which
      // is what makes the match leftmost.
      ++gen;
      clist.clear();
      for (const Raw& r : raw) {
        if (best_start >= 0 && r.start > best_start) continue;  // too late to win
        add_thread(clist, seen, gen, r.pc, r.start, r.caps, sp, len, data);
      }
      if (best_start < 0) {
        add_thread(clist, seen, gen, 0, static_cast<int>(sp), fresh, sp, len, data);
      }
      raw.clear();
      for (std::size_t i = 0; i < clist.size(); ++i) {
        const Thread& t = clist[i];
        const Inst& in = prog[static_cast<std::size_t>(t.pc)];
        if (in.op == Op::Match) {
          // Priority order decides, exactly like a backtracking engine: the
          // first thread that reaches Match in this list is the answer, and
          // every thread after it is lower priority and must not run.  The
          // threads before it are higher priority and may still extend the
          // match, so they keep consuming (that is what makes a greedy
          // quantifier greedy and a lazy one lazy).
          best_start = t.start;
          best_end = static_cast<int>(sp);
          best_caps = t.caps;
          break;
        }
        if (sp < len && consumes(in, static_cast<unsigned char>(data[sp]))) {
          Raw r;
          r.pc = t.pc + 1;
          r.start = t.start;
          r.caps = t.caps;
          raw_next.push_back(std::move(r));
        }
      }
      if (overflow) return false;
      raw.swap(raw_next);
      raw_next.clear();
      if (raw.empty() && (best_start >= 0 || sp == len)) break;
    }
    if (best_start < 0) return false;
    *begin = static_cast<std::size_t>(best_start);
    *end = static_cast<std::size_t>(best_end);
    captures = best_caps;
    if (captures.size() >= 2) {
      captures[0] = best_start;
      captures[1] = best_end;
    } else {
      captures.assign({best_start, best_end});
    }
    return true;
  }
};

Regex::Regex() : impl_(std::make_shared<Impl>()) {}
Regex::~Regex() = default;
Regex::Regex(const Regex&) = default;
Regex& Regex::operator=(const Regex&) = default;
Regex::Regex(Regex&&) noexcept = default;
Regex& Regex::operator=(Regex&&) noexcept = default;

std::size_t Regex::step_budget() { return 2000000; }

bool Regex::compile(const std::string& pattern, Regex* out, std::string* error) {
  if (out == nullptr) return false;
  Regex result;
  result.impl_->pattern = pattern;
  Parser parser(pattern);
  if (pattern.size() >= 4 && pattern.compare(0, 4, "(?i)") == 0) {
    parser.icase = true;
    parser.pos = 4;
  } else if (pattern.find("(?i)") != std::string::npos) {
    if (error != nullptr) *error = "inline flags are only supported at the start of the pattern";
    *out = Regex();
    return false;
  }
  auto tree = parser.parse_alternation();
  if (!tree || !parser.at_end()) {
    if (error != nullptr) {
      *error = parser.error.empty() ? std::string("the pattern could not be parsed") : parser.error;
    }
    *out = Regex();
    return false;
  }
  Compiler compiler;
  compiler.prog = &result.impl_->prog;
  if (!compiler.compile(tree.get())) {
    if (error != nullptr) *error = "the pattern is too large";
    *out = Regex();
    return false;
  }
  Inst match;
  match.op = Op::Match;
  compiler.emit(match);
  if (result.impl_->prog.size() > kMaxProgram) {
    if (error != nullptr) *error = "the pattern compiles to more than 8192 instructions";
    *out = Regex();
    return false;
  }
  result.impl_->classes = parser.pool;
  result.impl_->icase = parser.icase;
  result.impl_->slots = 2 * (static_cast<std::size_t>(parser.groups) + 1);
  result.impl_->ok = true;
  *out = result;
  return true;
}

Regex Regex::compiled(const std::string& pattern, std::string* error) {
  Regex r;
  std::string why;
  if (!compile(pattern, &r, &why)) {
    if (error != nullptr) *error = why;
    return Regex();
  }
  return r;
}

bool Regex::valid() const { return impl_ && impl_->ok; }
const std::string& Regex::pattern() const { return impl_->pattern; }
bool Regex::case_insensitive() const { return impl_->icase; }
std::size_t Regex::program_size() const { return impl_->prog.size(); }
std::size_t Regex::last_steps() const { return impl_->steps; }

bool Regex::search(const char* data, std::size_t len, std::size_t from, std::size_t* begin,
                   std::size_t* end) const {
  if (!valid() || begin == nullptr || end == nullptr) return false;
  if (from > len) return false;
  return impl_->search(data, len, from, begin, end);
}

bool Regex::search(const std::string& text, std::size_t from, std::size_t* begin,
                   std::size_t* end) const {
  return search(text.data(), text.size(), from, begin, end);
}

bool Regex::matches(const std::string& text) const {
  std::size_t b = 0;
  std::size_t e = 0;
  return search(text, 0, &b, &e);
}

const std::vector<int>& Regex::last_captures() const { return impl_->captures; }

std::string Regex::replace_all(const std::string& text, const std::string& replacement,
                               std::size_t* count) const {
  if (count != nullptr) *count = 0;
  if (!valid()) return text;
  std::string out;
  out.reserve(text.size());
  std::size_t pos = 0;
  std::size_t made = 0;
  const std::size_t cap = 100000;
  bool last_nonempty = false;
  while (pos <= text.size()) {
    std::size_t b = 0;
    std::size_t e = 0;
    if (!search(text, pos, &b, &e)) break;
    const bool empty_match = (e == b);
    if (empty_match && last_nonempty && b == pos) {
      // Python 3.7+ and JavaScript both treat an empty match that sits right
      // after a non-empty one as no match at all; without this rule
      // replace_all("x*", "-", "axb") would produce "-a--b-".
      if (pos < text.size()) out.push_back(text[pos]);
      ++pos;
      last_nonempty = false;
      continue;
    }
    if (b > pos) out.append(text, pos, b - pos);
    const std::vector<int>& caps = impl_->captures;
    for (std::size_t i = 0; i < replacement.size(); ++i) {
      const char c = replacement[i];
      if ((c == '$' || c == '\\') && i + 1 < replacement.size()) {
        const char d = replacement[i + 1];
        if (d == '$' || d == '\\') {
          out.push_back(d);
          ++i;
          continue;
        }
        if (d >= '0' && d <= '9') {
          const std::size_t slot = static_cast<std::size_t>(d - '0');
          if (slot == 0) {
            out.append(text, b, e - b);
          } else if (2 * slot + 1 < caps.size()) {
            const int gs = caps[2 * slot];
            const int ge = caps[2 * slot + 1];
            if (gs >= 0 && ge >= gs) out.append(text, static_cast<std::size_t>(gs),
                                                static_cast<std::size_t>(ge - gs));
          }
          ++i;
          continue;
        }
      }
      out.push_back(c);
    }
    ++made;
    last_nonempty = !empty_match;
    if (e > b) {
      pos = e;
    } else {
      if (pos < text.size()) out.push_back(text[pos]);
      ++pos;  // an empty match: advance one byte so the loop cannot spin
    }
    if (made >= cap) break;
  }
  if (pos < text.size()) out.append(text, pos, std::string::npos);
  if (count != nullptr) *count = made;
  return out;
}

}  // namespace netcap
