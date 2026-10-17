#include "netcap/filter.hpp"

#include <cstdlib>
#include <cstring>
#include <vector>

#include "netcap/proxy.hpp"

namespace netcap {

namespace {

enum ProtoBit : u32 {
  P_IP4 = 1u << 0,
  P_IP6 = 1u << 1,
  P_TCP = 1u << 2,
  P_UDP = 1u << 3,
  P_ICMP = 1u << 4,
  P_ICMP6 = 1u << 5,
  P_ARP = 1u << 6,
  P_HTTP = 1u << 7,
  P_TLS = 1u << 8,
  P_DNS = 1u << 9,
  P_QUIC = 1u << 10,
  P_SSH = 1u << 11,
  P_DHCP = 1u << 12,
  P_MDNS = 1u << 13,
  P_FRAG = 1u << 14,
  P_VLAN = 1u << 15,
  P_IP = 1u << 16,
  P_PROC = 1u << 17,
  P_PROXIED = 1u << 18,
};

enum class Op { Lt, Le, Gt, Ge, Eq, Ne };

bool compare_num(Op op, u64 a, u64 b) {
  switch (op) {
    case Op::Lt: return a < b;
    case Op::Le: return a <= b;
    case Op::Gt: return a > b;
    case Op::Ge: return a >= b;
    case Op::Eq: return a == b;
    case Op::Ne: return a != b;
  }
  return false;
}

bool parse_u64(const std::string& s, u64* out) {
  if (s.empty()) return false;
  u64 v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + u64(c - '0');
    if (v > 0xffffffffull) return false;
  }
  *out = v;
  return true;
}

/// Case-insensitive byte substring search over a non-terminated payload.
bool payload_contains(const u8* hay, std::size_t hlen, const std::string& needle) {
  if (!hay || needle.empty() || hlen < needle.size()) return false;
  const std::size_t n = needle.size();
  const std::size_t last = hlen - n;
  for (std::size_t i = 0; i <= last; ++i) {
    std::size_t j = 0;
    while (j < n) {
      char c = char(hay[i + j]);
      if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
      if (c != needle[j]) break;
      ++j;
    }
    if (j == n) return true;
  }
  return false;
}

AppKind port_hint(const PacketInfo& pi) {
  if (!pi.has_ports) return AppKind::Unknown;
  if (pi.l4 == L4::Udp) {
    if (pi.src_port == 53 || pi.dst_port == 53) return AppKind::Dns;
    if (pi.src_port == 5353 || pi.dst_port == 5353) return AppKind::Mdns;
    if (pi.src_port == 67 || pi.dst_port == 67 || pi.src_port == 68 || pi.dst_port == 68) {
      return AppKind::Dhcp;
    }
    return AppKind::Unknown;
  }
  if (pi.l4 != L4::Tcp) return AppKind::Unknown;
  const u16 ports[2] = {pi.dst_port, pi.src_port};
  for (u16 p : ports) {
    switch (p) {
      case 443: case 8443: case 993: case 995: case 465: case 990: return AppKind::Tls;
      case 80: case 8080: case 8000: case 8008: case 3128: case 8888: return AppKind::Http;
      case 22: return AppKind::Ssh;
      case 53: return AppKind::Dns;
      default: break;
    }
  }
  return AppKind::Unknown;
}

bool match_proto(const PacketInfo& pi, const AppInfo* app, const ProcessInfo* proc,
                 const ProxyLink* origin, u32 bit) {
  switch (bit) {
    case P_IP4: return pi.ip_version == 4;
    case P_IP6: return pi.ip_version == 6;
    case P_IP: return pi.ip_version == 4 || pi.ip_version == 6;
    case P_TCP: return pi.l4 == L4::Tcp;
    case P_UDP: return pi.l4 == L4::Udp;
    case P_ICMP: return pi.l4 == L4::Icmp;
    case P_ICMP6: return pi.l4 == L4::Icmpv6;
    case P_ARP: return pi.is_arp;
    case P_VLAN: return pi.has_vlan;
    case P_FRAG: return pi.is_fragment;
    default: break;
  }
  const AppKind k = (app && app->kind != AppKind::Unknown) ? app->kind : port_hint(pi);
  switch (bit) {
    case P_HTTP: return k == AppKind::Http;
    case P_TLS: return k == AppKind::Tls;
    case P_DNS: return k == AppKind::Dns;
    case P_QUIC: return k == AppKind::Quic;
    case P_SSH: return k == AppKind::Ssh;
    case P_DHCP: return k == AppKind::Dhcp;
    case P_MDNS: return k == AppKind::Mdns;
    // "proc" on its own asks whether the packet was attributed to a process at
    // all (the PID may be known while the image name is not).
    case P_PROC: return proc != nullptr && proc->pid != 0;
    // "proxied" asks whether this packet went through a local proxy *and* the
    // program behind it could be correlated.
    case P_PROXIED: return origin != nullptr && origin->origin_pid != 0;
    default: return false;
  }
}

struct ProtoKeyword {
  const char* name;
  u32 bit;
};

const ProtoKeyword kProtoKeywords[] = {
    {"ip", P_IP},       {"ip4", P_IP4},   {"ipv4", P_IP4}, {"ip6", P_IP6},   {"ipv6", P_IP6},
    {"tcp", P_TCP},     {"udp", P_UDP},   {"icmp", P_ICMP}, {"icmp6", P_ICMP6},
    {"icmpv6", P_ICMP6}, {"arp", P_ARP},  {"fragment", P_FRAG}, {"frag", P_FRAG},
    {"http", P_HTTP},   {"tls", P_TLS},   {"https", P_TLS}, {"ssl", P_TLS},
    {"dns", P_DNS},     {"quic", P_QUIC}, {"ssh", P_SSH},   {"dhcp", P_DHCP},
    {"mdns", P_MDNS},   {"vlan", P_VLAN},
};

bool lookup_proto(const std::string& tok, u32* bit) {
  for (const ProtoKeyword& k : kProtoKeywords) {
    if (tok == k.name) {
      *bit = k.bit;
      return true;
    }
  }
  return false;
}

bool split_flags(const std::string& s, std::vector<std::string>& out) {
  std::string cur;
  for (char c : s) {
    if (c == ',' || c == '-') {
      if (!cur.empty()) out.push_back(cur);
      cur.clear();
    } else {
      cur += c;
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return !out.empty();
}

bool flag_name_to_bit(const std::string& n, u8* bit) {
  if (n == "fin" || n == "f") { *bit = TCP_FIN; return true; }
  if (n == "syn" || n == "s") { *bit = TCP_SYN; return true; }
  if (n == "rst" || n == "r") { *bit = TCP_RST; return true; }
  if (n == "psh" || n == "push" || n == "p") { *bit = TCP_PSH; return true; }
  if (n == "ack" || n == "a") { *bit = TCP_ACK; return true; }
  if (n == "urg" || n == "u") { *bit = TCP_URG; return true; }
  if (n == "ece" || n == "e") { *bit = TCP_ECE; return true; }
  if (n == "cwr" || n == "c") { *bit = TCP_CWR; return true; }
  return false;
}

bool parse_tcp_flags(const std::string& in, u8* flags, u8* mask) {
  const std::string s = to_lower(in);
  if (s.empty()) return false;
  const std::size_t slash = s.find('/');
  if (slash != std::string::npos) {
    const std::string f = s.substr(0, slash);
    const std::string m = s.substr(slash + 1);
    char* end = nullptr;
    const unsigned long fv = std::strtoul(f.c_str(), &end, 0);
    if (end == f.c_str() || *end != '\0') return false;
    end = nullptr;
    const unsigned long mv = std::strtoul(m.c_str(), &end, 0);
    if (end == m.c_str() || *end != '\0') return false;
    *flags = u8(fv & 0xff);
    *mask = u8(mv & 0xff);
    return true;
  }
  std::vector<std::string> parts;
  if (!split_flags(s, parts)) return false;
  u8 f = 0;
  for (const std::string& p : parts) {
    u8 bit = 0;
    if (!flag_name_to_bit(p, &bit)) return false;
    f |= bit;
  }
  *flags = f;
  *mask = f;
  return true;
}

bool parse_op(const std::string& t, Op* op) {
  if (t == "<") { *op = Op::Lt; return true; }
  if (t == "<=") { *op = Op::Le; return true; }
  if (t == ">") { *op = Op::Gt; return true; }
  if (t == ">=") { *op = Op::Ge; return true; }
  if (t == "=" || t == "==") { *op = Op::Eq; return true; }
  if (t == "!=") { *op = Op::Ne; return true; }
  return false;
}

void tokenize(const std::string& s, std::vector<std::string>& out, std::string* err) {
  std::size_t i = 0;
  while (i < s.size()) {
    const char c = s[i];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      ++i;
      continue;
    }
    if (c == '(' || c == ')') {
      out.push_back(std::string(1, c));
      ++i;
      continue;
    }
    if (c == '"' || c == '\'') {
      ++i;
      std::string t;
      while (i < s.size() && s[i] != c) {
        t += s[i];
        ++i;
      }
      if (i >= s.size()) {
        if (err) *err = "unterminated quoted string";
        return;
      }
      ++i;
      out.push_back(t);
      continue;
    }
    std::string t;
    while (i < s.size()) {
      const char d = s[i];
      if (d == ' ' || d == '\t' || d == '\r' || d == '\n' || d == '(' || d == ')') break;
      t += d;
      ++i;
    }
    out.push_back(t);
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Predicate tree
// ---------------------------------------------------------------------------

struct Filter::Node {
  enum class K {
    True,
    False,
    And,
    Or,
    Not,
    Proto,
    Host,
    Port,
    PortRange,
    Net,
    Vlan,
    Name,
    Url,
    Payload,
    Flags,
    Num,
    Fragment,
    Proc,
    Via,
    Origin,
  };

  K k = K::True;
  std::vector<std::shared_ptr<Node>> kids;
  u32 proto = 0;
  int dir = 0;  // 0 = any, 1 = src, 2 = dst
  int version = 0;
  u8 addr[16] = {0};
  int bits = 0;
  u16 port = 0;
  u16 port2 = 0;
  u8 flags = 0;
  u8 mask = 0;
  Op op = Op::Eq;
  u64 num = 0;
  u32 proc_pid = 0;    // K::Proc with exact_pid: match this PID
  bool exact_pid = false;
  std::string text;  // "len" / "ttl" for K::Num, substr for Name/Url/Payload/Proc
};

namespace {

using NodePtr = std::shared_ptr<Filter::Node>;

NodePtr make_node(Filter::Node::K k) {
  auto n = std::make_shared<Filter::Node>();
  n->k = k;
  return n;
}

class Parser {
 public:
  Parser(const std::vector<std::string>& toks, std::string* err) : toks_(toks), err_(err) {}

  NodePtr parse() {
    if (toks_.empty()) return make_node(Filter::Node::K::True);
    NodePtr n = parse_or();
    if (!n) return nullptr;
    if (pos_ != toks_.size()) {
      fail("unexpected trailing token '" + toks_[pos_] + "'");
      return nullptr;
    }
    return n;
  }

 private:
  const std::vector<std::string>& toks_;
  std::string* err_;
  std::size_t pos_ = 0;

  bool at_end() const { return pos_ >= toks_.size(); }
  const std::string& peek() const { return toks_[pos_]; }
  bool is_paren() const { return !at_end() && (peek() == "(" || peek() == ")"); }

  void fail(const std::string& msg) {
    if (err_ && err_->empty()) *err_ = msg;
  }

  bool is_and_boundary(const std::string& t) const {
    return t == "or" || t == "||" || t == ")" || t == "and" || t == "&&";
  }

  NodePtr parse_or() {
    NodePtr left = parse_and();
    if (!left) return nullptr;
    std::vector<NodePtr> kids;
    kids.push_back(left);
    while (!at_end() && (peek() == "or" || peek() == "||")) {
      ++pos_;
      NodePtr rhs = parse_and();
      if (!rhs) return nullptr;
      kids.push_back(rhs);
    }
    if (kids.size() == 1) return kids[0];
    NodePtr n = make_node(Filter::Node::K::Or);
    n->kids = std::move(kids);
    return n;
  }

  NodePtr parse_and() {
    NodePtr left = parse_unary();
    if (!left) return nullptr;
    std::vector<NodePtr> kids;
    kids.push_back(left);
    for (;;) {
      if (at_end()) break;
      const std::string t = peek();
      if (t == "or" || t == "||" || t == ")") break;
      if (t == "and" || t == "&&") ++pos_;
      else if (is_and_boundary(t)) break;
      // Implicit "and" (tcpdump style juxtaposition).
      NodePtr rhs = parse_unary();
      if (!rhs) return nullptr;
      kids.push_back(rhs);
    }
    if (kids.size() == 1) return kids[0];
    NodePtr n = make_node(Filter::Node::K::And);
    n->kids = std::move(kids);
    return n;
  }

  NodePtr parse_unary() {
    if (at_end()) {
      fail("unexpected end of filter expression");
      return nullptr;
    }
    if (peek() == "not" || peek() == "!") {
      ++pos_;
      NodePtr inner = parse_unary();
      if (!inner) return nullptr;
      NodePtr n = make_node(Filter::Node::K::Not);
      n->kids.push_back(inner);
      return n;
    }
    if (peek() == "(") {
      ++pos_;
      NodePtr inner = parse_or();
      if (!inner) return nullptr;
      if (at_end() || peek() != ")") {
        fail("missing ')'");
        return nullptr;
      }
      ++pos_;
      return inner;
    }
    if (peek() == ")") {
      fail("unexpected ')'");
      return nullptr;
    }
    return parse_primitive();
  }

  NodePtr parse_primitive() {
    const std::string tok = to_lower(peek());
    ++pos_;

    int dir = 0;
    std::string kw = tok;
    if (kw == "src" || kw == "dst") {
      dir = (kw == "src") ? 1 : 2;
      if (at_end() || is_paren()) {
        fail("'" + tok + "' must be followed by a primitive");
        return nullptr;
      }
      kw = to_lower(peek());
      ++pos_;
    }

    if (kw == "host" || kw == "hostname" || kw == "url" || kw == "payload") {
      if (at_end() || is_paren()) {
        fail("'" + kw + "' needs a value");
        return nullptr;
      }
      const std::string val = peek();
      ++pos_;
      if (kw == "host") {
        int ver = 0;
        u8 a[16] = {0};
        if (!parse_ip(val, &ver, a)) {
          fail("'host " + val + "' is not an IP literal (did you mean 'hostname " + val + "'?)");
          return nullptr;
        }
        NodePtr n = make_node(Filter::Node::K::Host);
        n->dir = dir;
        n->version = ver;
        std::memcpy(n->addr, a, 16);
        return n;
      }
      if (kw == "hostname") {
        NodePtr n = make_node(Filter::Node::K::Name);
        n->dir = dir;
        n->text = to_lower(val);
        return n;
      }
      if (kw == "url") {
        NodePtr n = make_node(Filter::Node::K::Url);
        n->text = to_lower(val);
        return n;
      }
      NodePtr n = make_node(Filter::Node::K::Payload);
      n->text = to_lower(val);
      return n;
    }

    if (kw == "port" || kw == "portrange") {
      if (at_end() || is_paren()) {
        fail("'" + kw + "' needs a value");
        return nullptr;
      }
      const std::string val = peek();
      ++pos_;
      if (kw == "port") {
        u64 v = 0;
        if (!parse_u64(val, &v) || v > 65535) {
          fail("bad port '" + val + "'");
          return nullptr;
        }
        NodePtr n = make_node(Filter::Node::K::Port);
        n->dir = dir;
        n->port = u16(v);
        return n;
      }
      const std::size_t dash = val.find('-');
      if (dash == std::string::npos) {
        fail("portrange needs the form A-B, got '" + val + "'");
        return nullptr;
      }
      u64 a = 0, b = 0;
      if (!parse_u64(val.substr(0, dash), &a) || !parse_u64(val.substr(dash + 1), &b) || a > 65535 ||
          b > 65535 || a > b) {
        fail("bad portrange '" + val + "'");
        return nullptr;
      }
      NodePtr n = make_node(Filter::Node::K::PortRange);
      n->dir = dir;
      n->port = u16(a);
      n->port2 = u16(b);
      return n;
    }

    if (kw == "net") {
      if (at_end() || is_paren()) {
        fail("'net' needs a CIDR value");
        return nullptr;
      }
      const std::string val = peek();
      ++pos_;
      int ver = 0, bits = 0;
      u8 a[16] = {0};
      if (!parse_cidr(val, &ver, a, &bits)) {
        fail("bad network '" + val + "'");
        return nullptr;
      }
      NodePtr n = make_node(Filter::Node::K::Net);
      n->version = ver;
      n->bits = bits;
      std::memcpy(n->addr, a, 16);
      return n;
    }

    if (kw == "proc" || kw == "process") {
      // Bare "proc" is the protocol test; "proc chrome" matches a substring of
      // the image name or path.
      if (at_end() || is_paren() || is_and_boundary(peek())) {
        NodePtr n = make_node(Filter::Node::K::Proto);
        n->proto = P_PROC;
        return n;
      }
      const std::string val = peek();
      ++pos_;
      if (val.empty()) {
        fail("'proc' needs a name or a substring");
        return nullptr;
      }
      NodePtr n = make_node(Filter::Node::K::Proc);
      n->text = to_lower(val);
      return n;
    }

    if (kw == "pid") {
      if (at_end() || is_paren()) {
        fail("'pid' needs a number");
        return nullptr;
      }
      const std::string val = peek();
      u64 v = 0;
      if (!parse_u64(val, &v)) {
        fail("bad pid '" + val + "'");
        return nullptr;
      }
      ++pos_;
      NodePtr n = make_node(Filter::Node::K::Proc);
      n->exact_pid = true;
      n->proc_pid = u32(v);
      return n;
    }

    if (kw == "proxied" || kw == "through-proxy") {
      // This packet went through a local proxy and the program behind it is known.
      NodePtr n = make_node(Filter::Node::K::Proto);
      n->proto = P_PROXIED;
      return n;
    }

    if (kw == "via" || kw == "origin") {
      const bool want_origin = (kw == "origin");
      if (at_end() || is_paren()) {
        fail(std::string("'") + kw + "' needs a process name or pid");
        return nullptr;
      }
      const std::string val = peek();
      if (val.empty()) {
        fail(std::string("'") + kw + "' needs a process name or pid");
        return nullptr;
      }
      ++pos_;
      NodePtr n = make_node(want_origin ? Filter::Node::K::Origin : Filter::Node::K::Via);
      u64 pid = 0;
      if (parse_u64(val, &pid)) {
        n->exact_pid = true;
        n->proc_pid = u32(pid);
      } else {
        n->text = to_lower(val);
      }
      return n;
    }

    if (kw == "vlan") {
      // Bare "vlan" is the proto test; "vlan 100" matches the tag.
      if (at_end() || is_paren() || is_and_boundary(peek())) {
        NodePtr n = make_node(Filter::Node::K::Proto);
        n->proto = P_VLAN;
        return n;
      }
      const std::string val = peek();
      u64 v = 0;
      if (!parse_u64(val, &v) || v > 4095) {
        fail("bad vlan id '" + val + "'");
        return nullptr;
      }
      ++pos_;
      NodePtr n = make_node(Filter::Node::K::Vlan);
      n->port = u16(v);
      return n;
    }

    if (kw == "tcpflags" || kw == "tcp-flags") {
      if (at_end() || is_paren()) {
        fail("'tcpflags' needs a flag set, e.g. syn or syn-ack or 0x12/0xff");
        return nullptr;
      }
      const std::string val = peek();
      ++pos_;
      u8 f = 0, m = 0;
      if (!parse_tcp_flags(val, &f, &m)) {
        fail("bad tcpflags '" + val + "'");
        return nullptr;
      }
      NodePtr n = make_node(Filter::Node::K::Flags);
      n->flags = f;
      n->mask = m;
      return n;
    }

    if (kw == "len" || kw == "ttl") {
      if (at_end() || is_paren()) {
        fail("'" + kw + "' needs an operator and a number");
        return nullptr;
      }
      const std::string op_tok = peek();
      ++pos_;
      Op op{};
      if (!parse_op(op_tok, &op)) {
        fail("bad operator '" + op_tok + "' after '" + kw + "'");
        return nullptr;
      }
      if (at_end() || is_paren()) {
        fail("'" + kw + "' needs a number");
        return nullptr;
      }
      u64 v = 0;
      if (!parse_u64(peek(), &v)) {
        fail("bad number '" + peek() + "'");
        return nullptr;
      }
      ++pos_;
      NodePtr n = make_node(Filter::Node::K::Num);
      n->text = kw;
      n->op = op;
      n->num = v;
      return n;
    }

    u32 bit = 0;
    if (lookup_proto(kw, &bit)) {
      if (dir != 0) {
        fail("'" + tok + "' cannot take a src/dst qualifier");
        return nullptr;
      }
      NodePtr n = make_node(Filter::Node::K::Proto);
      n->proto = bit;
      return n;
    }

    fail("unknown filter primitive '" + tok + "'");
    return nullptr;
  }
};

bool eval(const Filter::Node& n, const PacketInfo& pi, const AppInfo* app,
          const ProcessInfo* proc, const ProxyLink* origin) {
  switch (n.k) {
    case Filter::Node::K::True:
      return true;
    case Filter::Node::K::False:
      return false;
    case Filter::Node::K::And:
      for (const auto& kid : n.kids) {
        if (!eval(*kid, pi, app, proc, origin)) return false;
      }
      return true;
    case Filter::Node::K::Or:
      for (const auto& kid : n.kids) {
        if (eval(*kid, pi, app, proc, origin)) return true;
      }
      return false;
    case Filter::Node::K::Not:
      return !eval(*n.kids[0], pi, app, proc, origin);

    case Filter::Node::K::Proto:
      return match_proto(pi, app, proc, origin, n.proto);

    case Filter::Node::K::Proc: {
      if (!proc) return false;
      if (n.exact_pid) return proc->pid == n.proc_pid;
      const std::string& key = proc->key.empty() ? proc->name : proc->key;
      std::string lower_key = to_lower(key);
      if (lower_key.find(n.text) != std::string::npos) return true;
      // The full image path is searched as well, so a filter can pin an exact
      // installation ("proc \\program files\\google\\chrome").
      const std::string lower_path = to_lower(proc->path);
      return lower_path.find(n.text) != std::string::npos;
    }

    // "via clash" / "via 16664": which proxy carried this packet.
    case Filter::Node::K::Via: {
      if (!origin || origin->proxy_pid == 0) return false;
      if (n.exact_pid) return origin->proxy_pid == n.proc_pid;
      if (to_lower(origin->proxy_name).find(n.text) != std::string::npos) return true;
      return std::to_string(origin->proxy_pid) == n.text;
    }

    // "origin chrome" / "origin 4321": the program that really asked for it.
    case Filter::Node::K::Origin: {
      if (!origin || origin->origin_pid == 0) return false;
      if (n.exact_pid) return origin->origin_pid == n.proc_pid;
      if (to_lower(origin->origin_name).find(n.text) != std::string::npos) return true;
      return std::to_string(origin->origin_pid) == n.text;
    }

    case Filter::Node::K::Fragment:
      return pi.is_fragment;

    case Filter::Node::K::Host: {
      if (pi.ip_version != n.version) return false;
      const bool s = std::memcmp(pi.src_ip, n.addr, n.version == 4 ? 4 : 16) == 0;
      const bool d = std::memcmp(pi.dst_ip, n.addr, n.version == 4 ? 4 : 16) == 0;
      if (n.dir == 1) return s;
      if (n.dir == 2) return d;
      return s || d;
    }

    case Filter::Node::K::Net: {
      if (pi.ip_version != n.version) return false;
      const bool s = cidr_match(n.version, pi.src_ip, n.addr, n.bits);
      const bool d = cidr_match(n.version, pi.dst_ip, n.addr, n.bits);
      if (n.dir == 1) return s;
      if (n.dir == 2) return d;
      return s || d;
    }

    case Filter::Node::K::Port: {
      if (!pi.has_ports) return false;
      if (n.dir == 1) return pi.src_port == n.port;
      if (n.dir == 2) return pi.dst_port == n.port;
      return pi.src_port == n.port || pi.dst_port == n.port;
    }

    case Filter::Node::K::PortRange: {
      if (!pi.has_ports) return false;
      const bool s = pi.src_port >= n.port && pi.src_port <= n.port2;
      const bool d = pi.dst_port >= n.port && pi.dst_port <= n.port2;
      if (n.dir == 1) return s;
      if (n.dir == 2) return d;
      return s || d;
    }

    case Filter::Node::K::Vlan:
      return pi.has_vlan && pi.vlan_id == n.port;

    case Filter::Node::K::Name: {
      if (!app) return false;
      const char* hn = app_hostname(*app);
      if (!hn || !*hn) return false;
      return icontains_lower(hn, n.text.c_str());
    }

    case Filter::Node::K::Url: {
      if (!app) return false;
      if (!app->http.uri[0]) return false;
      return icontains_lower(app->http.uri, n.text.c_str());
    }

    case Filter::Node::K::Payload: {
      if (!pi.payload || pi.payload_len == 0) return false;
      return payload_contains(pi.payload, pi.payload_len, n.text);
    }

    case Filter::Node::K::Flags: {
      if (!pi.is_tcp()) return false;
      return (pi.tcp.flags & n.mask) == n.flags;
    }

    case Filter::Node::K::Num: {
      const u64 v = (n.text == "ttl") ? u64(pi.l3_hoplimit) : u64(pi.frame_len);
      return compare_num(n.op, v, n.num);
    }
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

Filter::Filter() : root_(make_node(Node::K::True)) {}

Filter::~Filter() = default;
Filter::Filter(const Filter&) = default;
Filter& Filter::operator=(const Filter&) = default;
Filter::Filter(Filter&&) noexcept = default;
Filter& Filter::operator=(Filter&&) noexcept = default;

Filter Filter::parse(const std::string& text, std::string* error) {
  Filter f;
  f.text_ = text;
  std::vector<std::string> toks;
  std::string terr;
  tokenize(text, toks, &terr);
  if (!terr.empty()) {
    if (error) *error = terr;
    f.root_ = make_node(Node::K::False);
    f.failed_ = true;
    return f;
  }
  if (toks.empty()) {
    f.root_ = make_node(Node::K::True);
    return f;
  }
  std::string perr;
  Parser p(toks, &perr);
  NodePtr root = p.parse();
  if (!root) {
    if (error) *error = perr.empty() ? "invalid filter expression" : perr;
    f.root_ = make_node(Node::K::False);
    f.failed_ = true;
    return f;
  }
  f.root_ = root;
  return f;
}

bool Filter::match(const PacketInfo& pi, const AppInfo* app, const ProcessInfo* proc,
                   const ProxyLink* origin) const {
  if (!root_) return true;
  return eval(*root_, pi, app, proc, origin);
}

bool Filter::match_all() const {
  return root_ && (root_->k == Node::K::True || text_.empty());
}

std::string filter_syntax_help() {
  return
      "Filter grammar (whitespace separated, '(' ')' group, precedence: not > and > or)\n"
      "  protocols : ip ip4 ip6 tcp udp icmp icmp6 arp vlan fragment\n"
      "              http https|tls dns mdns quic ssh dhcp\n"
      "  addresses : [src|dst] host <ip>            e.g. host 10.0.0.5\n"
      "              net <cidr>                    e.g. net 192.168.0.0/16\n"
      "  ports     : [src|dst] port <n>             e.g. dst port 443\n"
      "              portrange <a>-<b>             e.g. portrange 1-1024\n"
      "  tags      : vlan <id>\n"
      "  tcp       : tcpflags <set>                 syn | syn-ack | fin,psh | 0x12/0xff\n"
      "  sizes     : len <op> <n>                   captured frame length\n"
      "              ttl <op> <n>                   IP TTL / hop limit\n"
      "  payload   : hostname <substr>              HTTP Host or TLS SNI substring\n"
      "              url <substr>                   HTTP request-target substring\n"
      "              payload <substr>               raw payload substring (case-insensitive)\n"
      "  processes : proc                           only packets attributed to a process\n"
      "              proc <substr>                  image name or path substring, e.g. proc chrome\n"
      "              pid <n>                        exact process id\n"
      "  proxies   : proxied                        packet went through a local proxy\n"
      "              via <substr|pid>               the proxy that carried it\n"
      "              origin <substr|pid>            the program that really asked for it\n"
      "  ops       : < <= > >= = !=   (for len/ttl)\n"
      "  examples  : \"tcp and dst port 443 and not net 10.0.0.0/8\"\n"
      "              \"tls and hostname example.com\"\n"
      "              \"http and url /login\"\n"
      "              \"proc chrome and dst port 443\"\n"
      "              \"origin chrome and proxied\"\n"
      "              \"udp port 53 or (tcp port 80 and tcpflags syn)\"";
}

}  // namespace netcap
