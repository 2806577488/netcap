// The analysis pipeline: TCP reassembly -> TLS decryption -> HTTP analysis.
//
// The pieces live in their own modules (flow.hpp, tls.hpp, http.hpp, http2.hpp);
// this is the glue that turns a sequence of dissected packets into streams and
// HTTP transactions a caller can print, filter or export.
//
// What it does per TCP connection:
//   * reassembles both directions (flow.hpp), tolerating reordering, retransmits
//     and gaps, with bounded memory;
//   * decides what the connection is carrying (TLS records, cleartext HTTP/1.x,
//     the HTTP/2 preface, or neither) from the first bytes that arrive;
//   * for TLS, parses the handshake for SNI/cipher/version and, when a key log is
//     available, decrypts the records (tls.hpp) and feeds the recovered
//     plaintext to the HTTP layers - so HTTPS is analysed as HTTP;
//   * for HTTP/1.x pairs requests with responses; for HTTP/2 decodes frames and
//     HPACK and pairs each stream.
//
// Nothing here allocates per packet beyond what the sub-modules already do, and
// every buffer is bounded.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "netcap/app.hpp"
#include "netcap/common.hpp"
#include "netcap/dissect.hpp"
#include "netcap/flow.hpp"
#include "netcap/http2.hpp"
#include "netcap/packet.hpp"
#include "netcap/tls.hpp"

namespace netcap {

// One request/response exchange, from HTTP/1.x or from one HTTP/2 stream, over
// cleartext or over decrypted TLS.
struct HttpRecord {
  int stream_index = 0;  // matches StreamReport::index
  bool http2 = false;
  bool decrypted = false;  // the bytes came out of a decrypted TLS session
  u32 stream_id = 0;       // HTTP/2 stream id, 0 for HTTP/1.x
  Endpoint client_endpoint;
  Endpoint server_endpoint;

  std::string host;  // Host header, :authority, or the TLS SNI
  std::string method;
  std::string target;
  int status = 0;
  std::string status_text;
  int version_major = 1;
  int version_minor = 1;
  std::string content_type;

  u64 request_body_bytes = 0;
  u64 response_body_bytes = 0;
  bool request_complete = false;
  bool response_complete = false;
  bool truncated = false;
  bool websocket = false;
  i64 start_us = 0;
  i64 end_us = 0;
  std::string note;

  std::string client() const { return client_endpoint.to_string(); }
  std::string server() const { return server_endpoint.to_string(); }
  std::string transport() const;
  std::string version_text() const;
  std::string url() const;
  std::string status_line() const;
  std::string summary() const;
};

// Everything learned about one TCP connection.
struct StreamReport {
  int index = 0;
  FlowKey key;
  Endpoint client_endpoint;
  Endpoint server_endpoint;

  bool tls = false;
  bool decrypted = false;
  bool http = false;
  bool http2 = false;
  bool websocket = false;
  bool keys_available = false;
  bool rejected = false;  // the bytes looked like HTTP/2 but were not

  std::string sni;
  std::string alpn;
  u16 tls_version = 0;
  u16 cipher_suite = 0;
  AppKind kind = AppKind::Unknown;

  u64 packets = 0;
  u64 client_bytes = 0;  // reassembled payload bytes
  u64 server_bytes = 0;
  u64 plaintext_bytes = 0;  // decrypted application bytes
  u64 retransmits = 0;
  u64 out_of_order = 0;
  u64 overlaps = 0;
  u64 gaps = 0;
  bool truncated = false;

  TlsConnectionStats tls_stats;
  H2Stats h2_stats;
  std::size_t transactions = 0;

  i64 first_us = 0;
  i64 last_us = 0;
  std::string note;

  std::string client() const { return client_endpoint.to_string(); }
  std::string server() const { return server_endpoint.to_string(); }
  std::string protocol() const;  // "TLS", "HTTP/1.1", "HTTP/2", "TCP", ...
  std::string describe() const;
};

struct AnalyzeStats {
  u64 packets = 0;
  u64 malformed = 0;
  u64 tcp = 0;
  u64 udp = 0;
  u64 other = 0;
  u64 no_ports = 0;

  u64 streams = 0;
  u64 tls_streams = 0;
  u64 decrypted_streams = 0;
  u64 http1_streams = 0;
  u64 http2_streams = 0;
  u64 live_streams = 0;

  u64 transactions = 0;
  u64 decrypted_transactions = 0;
  u64 http2_transactions = 0;
  u64 completed_transactions = 0;

  u64 reassembled_bytes = 0;
  u64 retransmits = 0;
  u64 out_of_order = 0;
  u64 overlaps = 0;
  u64 gaps = 0;
  u64 streams_truncated = 0;

  bool reassembly = true;
  bool keys_loaded = false;
  std::size_t keylog_entries = 0;
  std::string keylog_description;
};

class Analyzer {
 public:
  Analyzer();
  ~Analyzer();
  Analyzer(const Analyzer&) = delete;
  Analyzer& operator=(const Analyzer&) = delete;

  // The key log is shared: several analyzers (or connections) can use one store.
  void set_keylog(std::shared_ptr<KeyLogStore> store);
  const std::shared_ptr<KeyLogStore>& keylog() const;

  void set_reassembly(bool on);
  bool reassembly() const;

  void set_max_streams(std::size_t n);
  void set_flow_limits(std::size_t max_stream_bytes, std::size_t max_pending_bytes);
  void set_max_http_message_bytes(std::size_t n);

  // Feed one dissected packet, in capture order.
  void feed(const PacketInfo& pi, i64 ts_us);
  // Mark the end of the capture (no more packets will arrive).
  void finish();

  const std::vector<StreamReport>& streams() const;
  const std::vector<HttpRecord>& http() const;
  const AnalyzeStats& stats() const;

  // Records whose response finished since the last call, for streaming output.
  std::vector<HttpRecord> take_completed();

  void clear();
  std::string describe() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace netcap
