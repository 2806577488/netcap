// TCP stream reassembly.
//
// Packets are fed in capture order and each direction of a connection is
// rebuilt into an ordered byte stream. The engine tolerates the things real
// captures contain: out-of-order delivery, retransmissions, overlaps,
// 32-bit sequence wraparound, gaps, and streams that never see a handshake.
//
// Memory is bounded on purpose: a half stream keeps at most
// FlowConfig::max_stream_bytes of delivered data and FlowConfig::max_pending_bytes
// of out-of-order data, and drops what does not fit instead of growing without
// limit. Anything dropped for capacity is reported so callers can mark the
// stream as truncated.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/dissect.hpp"

namespace netcap {

// ------------------------------------------------------------------ endpoints

struct Endpoint {
  u8 addr[16] = {0};   // IPv4 lives in the first four bytes
  u16 port = 0;
  u8 ip_version = 0;   // 4 or 6
  bool operator==(const Endpoint& o) const;
  bool operator<(const Endpoint& o) const;
  std::string to_string() const;  // "10.0.0.5:51000"
};

// Canonical connection key: the two endpoints sorted, so both directions map to
// the same object no matter which side spoke first.
struct FlowKey {
  Endpoint lo;
  Endpoint hi;
  u8 proto = 6;        // IPPROTO_TCP
  u32 ifindex = 0;
  bool operator<(const FlowKey& o) const;
  bool operator==(const FlowKey& o) const;
  std::string to_string() const;  // "10.0.0.5:51000 <-> 93.184.216.34:443"
};

FlowKey flow_key_of(const PacketInfo& pi, u32 ifindex = 0);

// ------------------------------------------------------------------ one direction

// How a half stream ended up where it is. Kept as counters rather than flags so
// the UI can show "3 retransmissions, 1 gap".
struct HalfStats {
  u64 segments = 0;        // segments added
  u64 bytes = 0;           // payload bytes seen (including duplicates)
  u64 delivered = 0;       // bytes handed to the ordered stream
  u64 retransmits = 0;     // segments that were entirely old
  u64 overlaps = 0;        // segments that partly covered old data
  u64 out_of_order = 0;    // segments that arrived after a gap opened
  u64 gaps = 0;            // gaps observed (a jump forward in sequence space)
  u64 duplicate_bytes = 0;
  u64 dropped_pending = 0;  // out-of-order bytes discarded for capacity
  bool saw_syn = false;
  bool saw_fin = false;
  bool saw_rst = false;
  bool truncated = false;  // delivered data was capped
  u32 isn = 0;             // initial sequence number (data starts at isn+1 after SYN)
  bool isn_known = false;
  i64 first_us = 0;        // first segment
  i64 last_us = 0;
  i64 first_data_us = 0;   // first delivered byte
};

class HalfStream {
 public:
  HalfStream() = default;

  void set_limits(std::size_t max_stream_bytes, std::size_t max_pending_bytes) {
    max_stream_ = max_stream_bytes;
    max_pending_ = max_pending_bytes;
  }

  // Feed one TCP segment payload. `seq` is the segment's sequence number,
  // `payload`/`len` its data. SYN/FIN occupy one sequence number each.
  // Returns the number of newly delivered (contiguous, previously unseen) bytes.
  std::size_t add(u32 seq, const u8* payload, std::size_t len, bool syn, bool fin, i64 ts_us);

  // Everything delivered so far, in order (possibly containing holes only if
  // truncated/dropped bytes were counted; otherwise a faithful byte stream).
  const std::vector<u8>& data() const { return data_; }
  const HalfStats& stats() const { return st_; }
  // True once the FIN has been reached (or the connection was reset), meaning
  // no further bytes can arrive in this direction.
  bool complete() const { return st_.saw_rst || (fin_seen_ && next_abs_ >= fin_abs_); }
  // Absolute sequence number of the next byte the consumer expects.
  u64 next_seq() const { return next_abs_; }
  bool has_gap() const { return gap_open_; }

 private:
  u64 to_abs(u32 seq) const;
  std::size_t append(const u8* p, std::size_t n, i64 ts_us);
  std::size_t drain(i64 ts_us);
  void trim_pending();

  std::vector<u8> data_;
  std::map<u64, std::vector<u8>> pending_;  // absolute seq -> bytes
  std::size_t pending_bytes_ = 0;
  std::size_t max_stream_ = 4u << 20;
  std::size_t max_pending_ = 1u << 20;

  bool have_base_ = false;
  u64 base_abs_ = 0;   // absolute value of base_seq_
  u32 base_seq_ = 0;
  u64 next_abs_ = 0;   // next byte the consumer wants
  bool gap_open_ = false;
  bool fin_seen_ = false;
  u64 fin_abs_ = 0;
  HalfStats st_;
};

// ------------------------------------------------------------------ connection

enum class ConnState : u8 { SynSent, Established, Closing, Closed, Reset };

const char* conn_state_name(ConnState s);

struct TcpStream {
  int index = 0;               // 1-based, in order of appearance
  FlowKey key;
  bool initiator_is_lo = true; // which endpoint opened the connection
  bool handshake_seen = false;
  bool server_seen = false;    // a segment in the responder -> initiator direction
  ConnState state = ConnState::Established;
  HalfStream lo_to_hi;         // initiator -> responder
  HalfStream hi_to_lo;         // responder -> initiator
  u64 packets = 0;
  u64 payload_bytes = 0;
  i64 first_us = 0;
  i64 last_us = 0;

  // Convenience for the common client/server reading of a flow.
  const Endpoint& client() const { return initiator_is_lo ? key.lo : key.hi; }
  const Endpoint& server() const { return initiator_is_lo ? key.hi : key.lo; }
  const HalfStream& client_to_server() const { return initiator_is_lo ? lo_to_hi : hi_to_lo; }
  const HalfStream& server_to_client() const { return initiator_is_lo ? hi_to_lo : lo_to_hi; }
  HalfStream& client_to_server() { return initiator_is_lo ? lo_to_hi : hi_to_lo; }
  HalfStream& server_to_client() { return initiator_is_lo ? hi_to_lo : lo_to_hi; }
  // The half stream a packet with this source belongs to.
  HalfStream& half_for_src(const Endpoint& src) {
    return src == key.lo ? lo_to_hi : hi_to_lo;
  }
  const HalfStream& half_for_src(const Endpoint& src) const {
    return src == key.lo ? lo_to_hi : hi_to_lo;
  }
  double duration_us() const { return double(last_us - first_us); }
  bool closed() const { return state == ConnState::Closed || state == ConnState::Reset; }
};

// What one packet did to the table.
struct FlowUpdate {
  TcpStream* stream = nullptr;
  bool new_stream = false;
  std::size_t delivered = 0;
  bool syn = false;
  bool ack = false;
  bool fin = false;
  bool rst = false;
  bool out_of_order = false;
  bool retransmission = false;
  bool overlap = false;
  bool gap = false;
};

struct FlowConfig {
  std::size_t max_stream_bytes = 4u << 20;   // per direction, delivered data
  std::size_t max_pending_bytes = 1u << 20;  // per direction, out-of-order data
  std::size_t max_streams = 4096;
  i64 idle_timeout_us = 300000000;  // 5 minutes
  // Keep streams that ended cleanly in the table (so a pcap can be summarised).
  bool keep_closed = true;
};

struct FlowTableStats {
  u64 packets = 0;        // TCP packets fed in
  u64 bytes = 0;          // payload bytes fed in
  u64 streams = 0;        // streams created
  u64 retransmits = 0;
  u64 overlaps = 0;
  u64 out_of_order = 0;
  u64 gaps = 0;
  u64 evicted = 0;        // dropped because of max_streams / idle timeout
  u64 non_tcp = 0;
};

class FlowTable {
 public:
  explicit FlowTable(const FlowConfig& cfg = FlowConfig());
  ~FlowTable();

  FlowTable(const FlowTable&) = delete;
  FlowTable& operator=(const FlowTable&) = delete;

  // Feed a dissected packet, in capture order. Non-TCP packets are counted and
  // ignored. The returned pointer stays valid until the next add()/gc().
  FlowUpdate add(const PacketInfo& pi, i64 ts_us);

  const std::vector<std::unique_ptr<TcpStream>>& streams() const { return streams_; }
  std::size_t size() const { return streams_.size(); }
  TcpStream* find(const FlowKey& key);
  const FlowConfig& config() const { return cfg_; }
  const FlowTableStats& stats() const { return stats_; }
  void clear();
  // Drop idle streams (and, if over the cap, the oldest closed ones).
  std::size_t gc(i64 now_us);

 private:
  void evict_if_needed();

  FlowConfig cfg_;
  std::map<FlowKey, TcpStream*> index_;
  std::vector<std::unique_ptr<TcpStream>> streams_;
  FlowTableStats stats_;
  int next_index_ = 1;
};

}  // namespace netcap
