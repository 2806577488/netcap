#include "netcap/analyze.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <utility>

#include "netcap/common.hpp"
#include "netcap/http.hpp"

namespace netcap {
namespace {

Endpoint endpoint_of(const u8 addr[16], u16 port, int version) {
  Endpoint e;
  std::memcpy(e.addr, addr, 16);
  e.port = port;
  e.ip_version = u8(version);
  return e;
}

Endpoint src_endpoint(const PacketInfo& pi) {
  return endpoint_of(pi.src_ip, pi.src_port, pi.ip_version);
}

// The HTTP/2 client preface, matched on a partial buffer: "PRI * HTTP/2" can
// only be an HTTP/2 preface, never an HTTP/1.x request.
bool looks_like_h2_preface(const u8* d, std::size_t n) {
  static const char kPre[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  const std::size_t pre_len = sizeof(kPre) - 1;
  const std::size_t m = std::min(n, pre_len);
  if (m < 4) return false;
  return std::memcmp(d, kPre, m) == 0;
}

bool has_h2_alpn(const TlsServerHelloInfo& sh) {
  for (const std::string& a : sh.alpn) {
    if (a == "h2") return true;
  }
  return false;
}

bool has_h2_alpn(const TlsClientHelloInfo& ch) {
  for (const std::string& a : ch.alpn) {
    if (a == "h2") return true;
  }
  return false;
}

}  // namespace

// ----------------------------------------------------------------- http record

std::string HttpRecord::version_text() const {
  if (http2) return "HTTP/2";
  char b[16];
  std::snprintf(b, sizeof(b), "HTTP/%d.%d", version_major, version_minor);
  return b;
}

std::string HttpRecord::transport() const {
  if (http2 && decrypted) return "HTTPS/2 (decrypted)";
  if (http2) return "HTTP/2";
  if (decrypted) return "HTTPS/1.1 (decrypted)";
  return version_text();
}

std::string HttpRecord::url() const {
  const bool secure = decrypted || server_endpoint.port == 443 || server_endpoint.port == 8443;
  std::string u = secure ? "https://" : "http://";
  if (!host.empty()) u += host;
  else u += server_endpoint.to_string();
  if (target.empty()) u += "/";
  else if (target[0] != '/') u += "/" + target;
  else u += target;
  return u;
}

std::string HttpRecord::status_line() const {
  if (status == 0) return {};
  std::string s = "HTTP";
  if (http2) s = "HTTP/2";
  else {
    char b[16];
    std::snprintf(b, sizeof(b), "/%d.%d", version_major, version_minor);
    s += b;
  }
  s += " " + std::to_string(status);
  if (!status_text.empty()) s += " " + status_text;
  return s;
}

std::string HttpRecord::summary() const {
  std::string s;
  if (!method.empty()) s += method + " " + url();
  else if (!host.empty()) s += url();
  if (status) {
    s += " -> " + std::to_string(status);
    if (!status_text.empty()) s += " " + status_text;
  }
  if (response_body_bytes) s += " [" + std::to_string(response_body_bytes) + "B]";
  if (decrypted) s += " (decrypted)";
  if (truncated) s += " (truncated)";
  return s;
}

// ------------------------------------------------------------------- stream

std::string StreamReport::protocol() const {
  if (tls) {
    if (http2) return "HTTPS/2";
    if (http) return "HTTPS/1.1";
    return "TLS";
  }
  if (http2) return "HTTP/2";
  if (http) return "HTTP/1.1";
  return "TCP";
}

std::string StreamReport::describe() const {
  std::string s = "#" + std::to_string(index) + " " + client() + " <-> " + server() + " " + protocol();
  if (!sni.empty()) s += " sni=" + sni;
  if (!alpn.empty()) s += " alpn=" + alpn;
  if (cipher_suite) s += " " + tls_cipher_suite_name(cipher_suite);
  if (tls_version) s += " " + std::string(tls_version_name(tls_version));
  s += " " + std::to_string(packets) + "pkt " + std::to_string(client_bytes + server_bytes) + "B";
  if (decrypted) s += " decrypted=" + std::to_string(plaintext_bytes) + "B";
  else if (tls) s += " (encrypted)";
  if (transactions) s += " " + std::to_string(transactions) + "tx";
  if (retransmits || out_of_order || gaps) {
    s += " [";
    if (retransmits) s += std::to_string(retransmits) + " retrans";
    if (out_of_order) s += (retransmits ? ", " : "") + std::to_string(out_of_order) + " ooo";
    if (gaps) s += (retransmits || out_of_order ? ", " : "") + std::to_string(gaps) + " gap";
    s += "]";
  }
  if (!note.empty()) s += " - " + note;
  return s;
}

// ------------------------------------------------------------------- impl

struct Analyzer::Impl {
  enum class Kind { Unknown, Tls, Http1, Http2, Other };
  enum class L7 { Undecided, Http1, Http2, Other };

  struct Conn {
    int index = 0;
    FlowKey key;
    Endpoint client, server;

    bool decided = false;
    Kind kind = Kind::Unknown;
    L7 l7 = L7::Undecided;

    std::shared_ptr<TlsSession> tls;
    std::unique_ptr<HttpAnalyzer> http;
    std::unique_ptr<H2Connection> h2;

    std::vector<u8> pending[2];   // undecided record-layer bytes
    i64 pending_ts[2] = {0, 0};
    std::vector<u8> l7_pending[2];  // undecided plaintext
    i64 l7_ts[2] = {0, 0};
    std::size_t consumed[2] = {0, 0};        // record-layer bytes taken from the halves
    std::size_t plain_consumed[2] = {0, 0};  // plaintext bytes fed onwards

    u64 packets = 0;
    u64 client_bytes = 0;
    u64 server_bytes = 0;
    u64 retransmits = 0;
    u64 out_of_order = 0;
    u64 overlaps = 0;
    u64 gaps = 0;
    bool truncated = false;
    i64 first_us = 0;
    i64 last_us = 0;
    std::string note;
  };

  FlowConfig cfg;
  std::unique_ptr<FlowTable> flows;
  std::map<FlowKey, Conn> conns;
  std::shared_ptr<KeyLogStore> keylog;
  std::size_t max_http_message = 16u << 20;
  int next_index = 1;
  bool reassembly = true;

  mutable std::vector<StreamReport> stream_cache;
  mutable std::vector<HttpRecord> http_cache;
  mutable AnalyzeStats stats;
  mutable bool dirty = true;
  std::set<std::string> reported;

  FlowTable& table() {
    if (!flows) flows.reset(new FlowTable(cfg));
    return *flows;
  }

  Conn& conn_for(TcpStream& st) {
    auto it = conns.find(st.key);
    if (it != conns.end()) return it->second;
    Conn c;
    c.index = next_index++;
    c.key = st.key;
    c.client = st.client();
    c.server = st.server();
    c.first_us = st.first_us;
    auto res = conns.emplace(st.key, std::move(c));
    return res.first->second;
  }

  void start(Conn& c, Kind k);
  void dispatch(Conn& c, int dir, const u8* data, std::size_t len, i64 ts_us);
  void try_decide(Conn& c);
  void handle_payload(Conn& c, int dir, const u8* data, std::size_t len, i64 ts_us);
  void feed_l7(Conn& c, int dir, const u8* data, std::size_t len, i64 ts_us);
  void drain_plaintext(Conn& c, int dir, i64 ts_us);

  void rebuild() const;
};

void Analyzer::Impl::start(Conn& c, Kind k) {
  c.kind = k;
  c.decided = true;
  switch (k) {
    case Kind::Tls:
      c.tls = std::make_shared<TlsSession>();
      if (keylog) c.tls->set_keylog(keylog);
      break;
    case Kind::Http1:
      c.http.reset(new HttpAnalyzer());
      c.http->set_max_message_bytes(max_http_message);
      c.l7 = L7::Http1;
      break;
    case Kind::Http2:
      c.h2.reset(new H2Connection());
      c.l7 = L7::Http2;
      break;
    default:
      c.note = "unrecognised application protocol";
      break;
  }
  for (int d = 0; d < 2; ++d) {
    if (c.pending[d].empty()) continue;
    std::vector<u8> bytes;
    bytes.swap(c.pending[d]);
    dispatch(c, d, bytes.data(), bytes.size(), c.pending_ts[d]);
  }
}

void Analyzer::Impl::try_decide(Conn& c) {
  TlsRecordHeader h;
  for (int d = 0; d < 2; ++d) {
    const std::vector<u8>& b = c.pending[d];
    if (b.size() < 5) continue;
    if (tls_parse_record_header(b.data(), b.size(), &h) != 0) {
      start(c, Kind::Tls);
      return;
    }
    if (HttpParser::is_http2_preface(b.data(), b.size()) || looks_like_h2_preface(b.data(), b.size())) {
      start(c, Kind::Http2);
      return;
    }
    if (HttpParser::looks_like_http(b.data(), b.size())) {
      start(c, Kind::Http1);
      return;
    }
  }
  // None of the signatures matched. Wait for a little more before falling back
  // to a port-based guess, so a small first segment is not misclassified.
  if (c.pending[0].size() + c.pending[1].size() < 16) return;
  const u16 sp = c.server.port;
  if (sp == 443 || sp == 8443 || sp == 993 || sp == 995 || sp == 465 || sp == 990) {
    start(c, Kind::Tls);
    return;
  }
  if (sp == 80 || sp == 8080 || sp == 8000 || sp == 8008 || sp == 3128 || sp == 8888) {
    start(c, Kind::Http1);
    return;
  }
  start(c, Kind::Other);
}

void Analyzer::Impl::feed_l7(Conn& c, int dir, const u8* data, std::size_t len, i64 ts_us) {
  if (c.l7 == L7::Undecided) {
    bool h2_hint = false;
    if (c.tls) {
      if (const TlsServerHelloInfo* sh = c.tls->server_hello()) h2_hint = has_h2_alpn(*sh);
      if (!h2_hint) {
        if (const TlsClientHelloInfo* ch = c.tls->client_hello()) h2_hint = has_h2_alpn(*ch);
      }
    }
    if (h2_hint || HttpParser::is_http2_preface(data, len) || looks_like_h2_preface(data, len)) {
      c.l7 = L7::Http2;
      c.h2.reset(new H2Connection());
      c.h2->set_max_body(1u << 20);
    } else if (HttpParser::looks_like_http(data, len)) {
      c.l7 = L7::Http1;
      c.http.reset(new HttpAnalyzer());
      c.http->set_max_message_bytes(max_http_message);
    } else if (len >= 8) {
      c.l7 = L7::Other;
    } else {
      c.l7_pending[dir].insert(c.l7_pending[dir].end(), data, data + len);
      c.l7_ts[dir] = ts_us;
      return;
    }
    // Flush whatever was buffered while the plaintext was still unknown.
    for (int d = 0; d < 2; ++d) {
      if (c.l7_pending[d].empty()) continue;
      std::vector<u8> bytes;
      bytes.swap(c.l7_pending[d]);
      if (c.h2) c.h2->feed(d, bytes.data(), bytes.size(), c.l7_ts[d]);
      else if (c.http) {
        if (d == 0) c.http->feed_client_to_server(bytes.data(), bytes.size(), c.l7_ts[d]);
        else c.http->feed_server_to_client(bytes.data(), bytes.size(), c.l7_ts[d]);
      }
    }
  }
  c.l7_pending[dir].clear();
  if (c.h2) {
    c.h2->feed(dir, data, len, ts_us);
  } else if (c.http) {
    if (dir == 0) c.http->feed_client_to_server(data, len, ts_us);
    else c.http->feed_server_to_client(data, len, ts_us);
  }
}

void Analyzer::Impl::dispatch(Conn& c, int dir, const u8* data, std::size_t len, i64 ts_us) {
  switch (c.kind) {
    case Kind::Tls:
      if (c.tls) {
        c.tls->feed(dir, data, len, ts_us);
        drain_plaintext(c, dir, ts_us);
      }
      break;
    case Kind::Http1:
      if (c.http) {
        if (dir == 0) c.http->feed_client_to_server(data, len, ts_us);
        else c.http->feed_server_to_client(data, len, ts_us);
      }
      break;
    case Kind::Http2:
      if (c.h2) c.h2->feed(dir, data, len, ts_us);
      break;
    default:
      break;
  }
}

void Analyzer::Impl::drain_plaintext(Conn& c, int dir, i64 ts_us) {
  if (!c.tls) return;
  // Application data only: handshake records decrypt into the same session, and
  // their bodies must not be spliced into the HTTP byte stream.
  const std::vector<u8>& pt = c.tls->application_plaintext(dir);
  if (pt.size() <= c.plain_consumed[dir]) return;
  const std::size_t from = c.plain_consumed[dir];
  const std::size_t n = pt.size() - from;
  c.plain_consumed[dir] = pt.size();
  feed_l7(c, dir, pt.data() + from, n, ts_us);
}

void Analyzer::Impl::handle_payload(Conn& c, int dir, const u8* data, std::size_t len, i64 ts_us) {
  if (!c.decided) {
    c.pending[dir].insert(c.pending[dir].end(), data, data + len);
    c.pending_ts[dir] = ts_us;
    try_decide(c);
    return;
  }
  dispatch(c, dir, data, len, ts_us);
}

void Analyzer::Impl::rebuild() const {
  stream_cache.clear();
  http_cache.clear();
  AnalyzeStats& s = stats;
  s.live_streams = conns.size();
  s.tls_streams = 0;
  s.decrypted_streams = 0;
  s.http1_streams = 0;
  s.http2_streams = 0;
  s.transactions = 0;
  s.decrypted_transactions = 0;
  s.http2_transactions = 0;
  s.completed_transactions = 0;
  s.streams_truncated = 0;

  for (const auto& kv : conns) {
    const Conn& c = kv.second;
    StreamReport r;
    r.index = c.index;
    r.key = c.key;
    r.client_endpoint = c.client;
    r.server_endpoint = c.server;
    r.packets = c.packets;
    r.client_bytes = c.client_bytes;
    r.server_bytes = c.server_bytes;
    r.retransmits = c.retransmits;
    r.out_of_order = c.out_of_order;
    r.overlaps = c.overlaps;
    r.gaps = c.gaps;
    r.truncated = c.truncated;
    r.first_us = c.first_us;
    r.last_us = c.last_us;
    r.note = c.note;
    if (r.truncated) ++s.streams_truncated;

    if (c.tls) {
      r.tls = c.tls->is_tls();
      r.decrypted = c.tls->decrypted_anything();
      r.keys_available = c.tls->has_keys();
      r.tls_stats = c.tls->stats();
      r.plaintext_bytes = u64(c.tls->plaintext(0).size() + c.tls->plaintext(1).size());
      if (const TlsClientHelloInfo* ch = c.tls->client_hello()) {
        r.sni = ch->sni;
        if (!ch->alpn.empty()) r.alpn = ch->alpn[0];
      }
      if (const TlsServerHelloInfo* sh = c.tls->server_hello()) {
        r.cipher_suite = sh->cipher_suite;
        r.tls_version = sh->supported_version;
        if (!sh->alpn.empty()) r.alpn = sh->alpn[0];
      }
      if (r.tls) {
        ++s.tls_streams;
        if (r.decrypted) ++s.decrypted_streams;
      }
      if (!r.decrypted && r.tls && !r.keys_available) {
        r.note = r.note.empty() ? "encrypted (no keys: use --keylog)" : r.note;
      } else if (!r.decrypted && r.tls) {
        r.note = r.note.empty() ? "encrypted (keys did not decrypt this session)" : r.note;
      }
    }

    std::size_t ntx = 0;
    const bool decrypted = c.tls ? c.tls->decrypted_anything() : false;
    if (c.h2) {
      r.http2 = true;
      r.rejected = c.h2->rejected();
      r.h2_stats = c.h2->stats();
      ++s.http2_streams;
      for (const H2Message& m : c.h2->messages()) {
        HttpRecord rec;
        rec.stream_index = r.index;
        rec.http2 = true;
        rec.decrypted = decrypted;
        rec.stream_id = m.stream_id;
        rec.client_endpoint = c.client;
        rec.server_endpoint = c.server;
        rec.host = !m.authority.empty() ? m.authority : r.sni;
        rec.method = m.method;
        rec.target = m.path;
        rec.status = m.status.empty() ? 0 : std::atoi(m.status.c_str());
        rec.version_major = 2;
        rec.version_minor = 0;
        rec.content_type = m.content_type;
        rec.request_body_bytes = m.request_body_bytes;
        rec.response_body_bytes = m.response_body_bytes;
        rec.request_complete = m.request_complete;
        rec.response_complete = m.response_complete;
        rec.truncated = m.truncated;
        rec.start_us = m.first_us;
        rec.end_us = m.last_us;
        rec.note = m.note;
        http_cache.push_back(std::move(rec));
        ++s.transactions;
        ++s.http2_transactions;
        if (m.response_complete) ++s.completed_transactions;
        if (decrypted) ++s.decrypted_transactions;
        ++ntx;
      }
    } else if (c.http) {
      r.http = c.http->saw_http();
      r.websocket = c.http->websocket();
      if (r.http || !c.http->transactions().empty()) ++s.http1_streams;
      for (const HttpTransaction& tx : c.http->transactions()) {
        HttpRecord rec;
        rec.stream_index = r.index;
        rec.decrypted = decrypted;
        rec.client_endpoint = c.client;
        rec.server_endpoint = c.server;
        if (tx.has_request) {
          rec.method = tx.request.method;
          rec.target = tx.request.target;
          rec.host = tx.request.host();
          rec.version_major = tx.request.version_major;
          rec.version_minor = tx.request.version_minor;
          rec.request_body_bytes = tx.request.body.size();
          rec.request_complete = true;
          rec.websocket = tx.request.upgrade_websocket;
        }
        if (rec.host.empty()) rec.host = r.sni;
        if (tx.has_response) {
          rec.status = tx.response.status;
          rec.status_text = tx.response.reason;
          rec.content_type = tx.response.content_type();
          rec.response_body_bytes = tx.response.body.size();
          rec.response_complete = true;
          rec.truncated = tx.response.truncated;
        }
        rec.start_us = tx.start_us;
        rec.end_us = tx.end_us;
        if (decrypted) rec.note = "decrypted";
        http_cache.push_back(std::move(rec));
        ++s.transactions;
        if (tx.has_response) ++s.completed_transactions;
        if (decrypted) ++s.decrypted_transactions;
        ++ntx;
      }
    }
    r.transactions = ntx;
    if (r.http2) r.kind = AppKind::Http;
    else if (r.http) r.kind = AppKind::Http;
    else if (r.tls) r.kind = AppKind::Tls;
    else r.kind = AppKind::Unknown;
    stream_cache.push_back(std::move(r));
  }

  std::stable_sort(http_cache.begin(), http_cache.end(),
                   [](const HttpRecord& a, const HttpRecord& b) {
                     if (a.start_us != b.start_us) return a.start_us < b.start_us;
                     if (a.stream_index != b.stream_index) return a.stream_index < b.stream_index;
                     return a.stream_id < b.stream_id;
                   });
  dirty = false;
}

// ------------------------------------------------------------------- analyzer

Analyzer::Analyzer() : impl_(new Impl()) {}
Analyzer::~Analyzer() = default;

void Analyzer::set_keylog(std::shared_ptr<KeyLogStore> store) {
  impl_->keylog = std::move(store);
  impl_->stats.keys_loaded = impl_->keylog && impl_->keylog->size() > 0;
  impl_->stats.keylog_entries = impl_->keylog ? impl_->keylog->size() : 0;
  impl_->stats.keylog_description = impl_->keylog ? impl_->keylog->describe() : std::string();
  for (auto& kv : impl_->conns) {
    if (kv.second.tls) kv.second.tls->set_keylog(impl_->keylog);
  }
}

const std::shared_ptr<KeyLogStore>& Analyzer::keylog() const { return impl_->keylog; }

void Analyzer::set_reassembly(bool on) { impl_->reassembly = on; }

bool Analyzer::reassembly() const { return impl_->reassembly; }

void Analyzer::set_max_streams(std::size_t n) {
  impl_->cfg.max_streams = n;
  if (impl_->flows && impl_->stats.streams == 0) impl_->flows.reset();
}

void Analyzer::set_flow_limits(std::size_t max_stream_bytes, std::size_t max_pending_bytes) {
  impl_->cfg.max_stream_bytes = max_stream_bytes;
  impl_->cfg.max_pending_bytes = max_pending_bytes;
  if (impl_->flows && impl_->stats.streams == 0) impl_->flows.reset();
}

void Analyzer::set_max_http_message_bytes(std::size_t n) { impl_->max_http_message = n; }

void Analyzer::feed(const PacketInfo& pi, i64 ts_us) {
  Impl& im = *impl_;
  ++im.stats.packets;
  if (pi.malformed) {
    ++im.stats.malformed;
    return;
  }
  if (pi.l4 == L4::Tcp) {
    ++im.stats.tcp;
  } else if (pi.l4 == L4::Udp) {
    ++im.stats.udp;
    return;
  } else {
    ++im.stats.other;
    return;
  }
  if (!pi.has_ports) {
    ++im.stats.no_ports;
    return;
  }
  if (!im.reassembly) return;

  FlowUpdate u = im.table().add(pi, ts_us);
  if (!u.stream) return;
  TcpStream& st = *u.stream;
  Impl::Conn& c = im.conn_for(st);
  if (u.new_stream) ++im.stats.streams;
  if (u.retransmission) {
    ++im.stats.retransmits;
    ++c.retransmits;
  }
  if (u.out_of_order) {
    ++im.stats.out_of_order;
    ++c.out_of_order;
  }
  if (u.overlap) {
    ++im.stats.overlaps;
    ++c.overlaps;
  }
  if (u.gap) {
    ++im.stats.gaps;
    ++c.gaps;
  }
  if (u.delivered) im.stats.reassembled_bytes += u.delivered;

  c.packets = st.packets;
  c.first_us = st.first_us;
  c.last_us = st.last_us;
  const HalfStream& hc = st.client_to_server();
  const HalfStream& hs = st.server_to_client();
  c.client_bytes = hc.data().size();
  c.server_bytes = hs.data().size();
  if (hc.stats().truncated || hs.stats().truncated) c.truncated = true;

  const Endpoint src = src_endpoint(pi);
  const int dir = (src == st.client()) ? 0 : 1;
  const HalfStream& half = (dir == 0) ? hc : hs;
  if (half.data().size() > c.consumed[dir]) {
    const std::size_t from = c.consumed[dir];
    const std::size_t to = half.data().size();
    c.consumed[dir] = to;
    im.handle_payload(c, dir, half.data().data() + from, to - from, ts_us);
  }
  im.dirty = true;
}

void Analyzer::finish() { impl_->dirty = true; }

const std::vector<StreamReport>& Analyzer::streams() const {
  if (impl_->dirty) impl_->rebuild();
  return impl_->stream_cache;
}

const std::vector<HttpRecord>& Analyzer::http() const {
  if (impl_->dirty) impl_->rebuild();
  return impl_->http_cache;
}

const AnalyzeStats& Analyzer::stats() const {
  if (impl_->dirty) impl_->rebuild();
  return impl_->stats;
}

std::vector<HttpRecord> Analyzer::take_completed() {
  Impl& im = *impl_;
  if (im.dirty) im.rebuild();
  std::vector<HttpRecord> out;
  for (const HttpRecord& r : im.http_cache) {
    if (!r.response_complete) continue;
    std::string key = std::to_string(r.stream_index) + "|" + std::to_string(r.stream_id) + "|" +
                      r.method + "|" + r.target + "|" + std::to_string(r.start_us);
    if (!im.reported.insert(key).second) continue;
    out.push_back(r);
  }
  return out;
}

void Analyzer::clear() {
  std::shared_ptr<KeyLogStore> keylog = impl_->keylog;
  const FlowConfig cfg = impl_->cfg;
  const std::size_t mhm = impl_->max_http_message;
  const bool ra = impl_->reassembly;
  impl_.reset(new Impl());
  impl_->cfg = cfg;
  impl_->max_http_message = mhm;
  impl_->reassembly = ra;
  set_keylog(std::move(keylog));
}

std::string Analyzer::describe() const {
  if (impl_->dirty) impl_->rebuild();
  const AnalyzeStats& s = impl_->stats;
  std::string t = std::to_string(s.streams) + " TCP stream(s): " + std::to_string(s.tls_streams) +
                  " TLS (" + std::to_string(s.decrypted_streams) + " decrypted), " +
                  std::to_string(s.http1_streams) + " HTTP/1.x, " + std::to_string(s.http2_streams) +
                  " HTTP/2; " + std::to_string(s.transactions) + " transaction(s)";
  if (s.keylog_entries) t += ", keylog: " + std::to_string(s.keylog_entries) + " secret(s)";
  return t;
}

}  // namespace netcap
