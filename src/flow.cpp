// TCP stream reassembly.
#include "netcap/flow.hpp"

#include <algorithm>
#include <cstring>

namespace netcap {

// ------------------------------------------------------------------ endpoints

bool Endpoint::operator==(const Endpoint& o) const {
  return ip_version == o.ip_version && port == o.port &&
         std::memcmp(addr, o.addr, sizeof(addr)) == 0;
}

bool Endpoint::operator<(const Endpoint& o) const {
  if (ip_version != o.ip_version) return ip_version < o.ip_version;
  const int c = std::memcmp(addr, o.addr, sizeof(addr));
  if (c != 0) return c < 0;
  return port < o.port;
}

std::string Endpoint::to_string() const {
  std::string s = format_ip(ip_version, addr);
  s += ':';
  s += std::to_string(port);
  return s;
}

bool FlowKey::operator<(const FlowKey& o) const {
  if (lo < o.lo) return true;
  if (o.lo < lo) return false;
  if (hi < o.hi) return true;
  if (o.hi < hi) return false;
  if (proto != o.proto) return proto < o.proto;
  return ifindex < o.ifindex;
}

bool FlowKey::operator==(const FlowKey& o) const {
  return lo == o.lo && hi == o.hi && proto == o.proto && ifindex == o.ifindex;
}

std::string FlowKey::to_string() const {
  return lo.to_string() + " <-> " + hi.to_string();
}

namespace {

Endpoint endpoint_of(const PacketInfo& pi, bool source) {
  Endpoint e;
  e.ip_version = u8(pi.ip_version);
  std::memcpy(e.addr, source ? pi.src_ip : pi.dst_ip, 16);
  e.port = source ? pi.src_port : pi.dst_port;
  return e;
}

}  // namespace

FlowKey flow_key_of(const PacketInfo& pi, u32 ifindex) {
  FlowKey k;
  Endpoint a = endpoint_of(pi, true);
  Endpoint b = endpoint_of(pi, false);
  if (b < a) std::swap(a, b);
  k.lo = a;
  k.hi = b;
  k.proto = 6;
  k.ifindex = ifindex;
  return k;
}

// ------------------------------------------------------------------ half stream

const char* conn_state_name(ConnState s) {
  switch (s) {
    case ConnState::SynSent: return "SYN_SENT";
    case ConnState::Established: return "ESTABLISHED";
    case ConnState::Closing: return "CLOSING";
    case ConnState::Closed: return "CLOSED";
    case ConnState::Reset: return "RESET";
  }
  return "UNKNOWN";
}

u64 HalfStream::to_abs(u32 seq) const {
  // Unsigned modular difference: correct across the 32-bit wraparound as long
  // as the two points are within 2^31 of each other, which everything in a
  // single direction of a TCP connection is.
  return base_abs_ + u64(u32(seq - base_seq_));
}

std::size_t HalfStream::append(const u8* p, std::size_t n, i64 ts_us) {
  if (n == 0) return 0;
  if (data_.empty()) st_.first_data_us = ts_us;
  const std::size_t room = max_stream_ > data_.size() ? max_stream_ - data_.size() : 0;
  const std::size_t take = n < room ? n : room;
  data_.insert(data_.end(), p, p + take);
  if (take < n) st_.truncated = true;
  st_.delivered += take;
  return take;
}

void HalfStream::trim_pending() {
  // Capacity rule: keep the segments closest to the hole we are waiting for and
  // drop the far future ones (they are the least likely to be needed).
  while (pending_bytes_ > max_pending_ && pending_.size() > 1) {
    auto it = std::prev(pending_.end());
    st_.dropped_pending += it->second.size();
    pending_bytes_ -= it->second.size();
    pending_.erase(it);
  }
}

std::size_t HalfStream::drain(i64 ts_us) {
  std::size_t delivered = 0;
  while (!pending_.empty()) {
    auto it = pending_.begin();
    const u64 start = it->first;
    const u64 end = start + it->second.size();
    if (end <= next_abs_) {  // entirely old
      pending_bytes_ -= it->second.size();
      pending_.erase(it);
      continue;
    }
    if (start > next_abs_) break;  // the hole is still there
    const std::size_t off = std::size_t(next_abs_ - start);
    delivered += append(it->second.data() + off, it->second.size() - off, ts_us);
    next_abs_ = end;
    pending_bytes_ -= it->second.size();
    pending_.erase(it);
    gap_open_ = false;  // the out-of-order data just closed the hole
  }
  return delivered;
}

std::size_t HalfStream::add(u32 seq, const u8* payload, std::size_t len, bool syn, bool fin,
                            i64 ts_us) {
  if (st_.segments == 0) st_.first_us = ts_us;
  st_.last_us = ts_us;
  st_.segments++;
  st_.bytes += len;
  if (syn) st_.saw_syn = true;
  if (fin) st_.saw_fin = true;

  if (!have_base_) {
    have_base_ = true;
    base_seq_ = seq;
    base_abs_ = 0;
    next_abs_ = syn ? 1 : 0;  // the SYN consumes one sequence number
    st_.isn = seq;
    st_.isn_known = true;
  }

  const u32 data_seq = u32(seq + (syn ? 1u : 0u));
  const u64 a0 = to_abs(data_seq);
  const u64 end0 = a0 + len;
  if (fin) {
    fin_seen_ = true;
    fin_abs_ = end0;
  }
  if (len == 0) return 0;

  if (end0 <= next_abs_) {  // completely retransmitted
    st_.retransmits++;
    st_.duplicate_bytes += len;
    return 0;
  }

  u64 a = a0;
  const u8* p = payload;
  std::size_t n = len;
  if (a < next_abs_) {  // partly old (overlapping retransmission)
    const std::size_t skip = std::size_t(next_abs_ - a);
    st_.overlaps++;
    st_.duplicate_bytes += skip;
    p += skip;
    n -= skip;
    a = next_abs_;
  }

  if (a > next_abs_) {  // a hole opened: hold it until the missing bytes arrive
    st_.out_of_order++;
    if (!gap_open_) {
      st_.gaps++;
      gap_open_ = true;
    }
    auto it = pending_.find(a);
    if (it == pending_.end()) {
      pending_.emplace(a, std::vector<u8>(p, p + n));
      pending_bytes_ += n;
    } else if (it->second.size() < n) {
      pending_bytes_ -= it->second.size();
      it->second.assign(p, p + n);
      pending_bytes_ += n;
    }
    trim_pending();
    return 0;
  }

  std::size_t delivered = append(p, n, ts_us);
  next_abs_ = end0;
  delivered += drain(ts_us);
  return delivered;
}

// ------------------------------------------------------------------ table

FlowTable::FlowTable(const FlowConfig& cfg) : cfg_(cfg) {}
FlowTable::~FlowTable() = default;

FlowUpdate FlowTable::add(const PacketInfo& pi, i64 ts_us) {
  FlowUpdate up;
  if (!pi.is_tcp()) {
    stats_.non_tcp++;
    return up;
  }
  stats_.packets++;
  stats_.bytes += pi.payload_len;

  const FlowKey key = flow_key_of(pi);
  TcpStream* st = nullptr;
  auto it = index_.find(key);
  if (it == index_.end()) {
    evict_if_needed();
    auto owned = std::make_unique<TcpStream>();
    st = owned.get();
    st->index = next_index_++;
    st->key = key;
    st->first_us = ts_us;
    st->last_us = ts_us;
    st->lo_to_hi.set_limits(cfg_.max_stream_bytes, cfg_.max_pending_bytes);
    st->hi_to_lo.set_limits(cfg_.max_stream_bytes, cfg_.max_pending_bytes);
    // Without a handshake the first speaker is taken as the initiator.
    st->initiator_is_lo = (endpoint_of(pi, true) == key.lo);
    streams_.push_back(std::move(owned));
    index_.emplace(key, st);
    stats_.streams++;
    up.new_stream = true;
  } else {
    st = it->second;
  }
  up.stream = st;

  const bool syn = (pi.tcp.flags & TCP_SYN) != 0;
  const bool ack = (pi.tcp.flags & TCP_ACK) != 0;
  const bool fin = (pi.tcp.flags & TCP_FIN) != 0;
  const bool rst = (pi.tcp.flags & TCP_RST) != 0;
  up.syn = syn;
  up.ack = ack;
  up.fin = fin;
  up.rst = rst;

  const Endpoint src = endpoint_of(pi, true);
  const Endpoint dst = endpoint_of(pi, false);

  // A SYN without ACK identifies the connection initiator; a SYN+ACK confirms
  // that the other side is the responder.
  if (syn && !ack) {
    st->initiator_is_lo = (src == st->key.lo);
    st->handshake_seen = true;
    if (st->state == ConnState::Established) st->state = ConnState::SynSent;
  } else if (syn && ack) {
    st->handshake_seen = true;
    st->initiator_is_lo = (dst == st->key.lo);
    st->state = ConnState::Established;
  } else if (ack && st->state == ConnState::SynSent) {
    st->state = ConnState::Established;
  }
  if (src == st->client()) {
    // nothing: the initiator is the client by definition
  } else {
    st->server_seen = true;
  }

  HalfStream& half = st->half_for_src(src);
  const HalfStats before = half.stats();
  const std::size_t delivered = half.add(pi.tcp.seq, pi.payload, pi.payload_len, syn, fin, ts_us);
  const HalfStats& after = half.stats();

  up.delivered = delivered;
  up.retransmission = after.retransmits > before.retransmits;
  up.overlap = after.overlaps > before.overlaps;
  up.out_of_order = after.out_of_order > before.out_of_order;
  up.gap = after.gaps > before.gaps;
  stats_.retransmits = up.retransmission ? stats_.retransmits + 1 : stats_.retransmits;
  stats_.overlaps = up.overlap ? stats_.overlaps + 1 : stats_.overlaps;
  stats_.out_of_order = up.out_of_order ? stats_.out_of_order + 1 : stats_.out_of_order;
  stats_.gaps = up.gap ? stats_.gaps + 1 : stats_.gaps;

  st->packets++;
  st->payload_bytes += pi.payload_len;
  st->last_us = ts_us;

  if (rst) {
    st->state = ConnState::Reset;
  } else if (st->lo_to_hi.complete() && st->hi_to_lo.complete()) {
    st->state = ConnState::Closed;
  } else if (fin) {
    st->state = ConnState::Closing;
  }
  return up;
}

void FlowTable::evict_if_needed() {
  if (streams_.size() < cfg_.max_streams) return;
  // Prefer to drop a connection that already ended, then the oldest one.
  std::size_t victim = streams_.size();
  for (std::size_t i = 0; i < streams_.size(); ++i) {
    if (streams_[i]->closed()) {
      victim = i;
      break;
    }
  }
  if (victim == streams_.size()) victim = 0;
  index_.erase(streams_[victim]->key);
  streams_.erase(streams_.begin() + std::ptrdiff_t(victim));
  stats_.evicted++;
}

TcpStream* FlowTable::find(const FlowKey& key) {
  auto it = index_.find(key);
  return it == index_.end() ? nullptr : it->second;
}

void FlowTable::clear() {
  streams_.clear();
  index_.clear();
  next_index_ = 1;
}

std::size_t FlowTable::gc(i64 now_us) {
  // Only call this with a timestamp from the same clock as the packets: during
  // a live capture that is the wall clock, for a pcap it is the file's own
  // timeline.
  std::size_t removed = 0;
  for (std::size_t i = 0; i < streams_.size();) {
    TcpStream* st = streams_[i].get();
    const bool expired = now_us - st->last_us > cfg_.idle_timeout_us;
    if (expired && !(cfg_.keep_closed && st->closed())) {
      index_.erase(st->key);
      streams_.erase(streams_.begin() + std::ptrdiff_t(i));
      stats_.evicted++;
      ++removed;
      continue;
    }
    ++i;
  }
  return removed;
}

}  // namespace netcap
