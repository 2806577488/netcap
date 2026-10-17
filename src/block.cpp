#include "netcap/block.hpp"

#include <cstdio>

#include "netcap/common.hpp"
#include "netcap/proc.hpp"

namespace netcap {

const char* block_mode_name(BlockMode mode) {
  switch (mode) {
    case BlockMode::DryRun: return "dry-run";
    case BlockMode::CutTcp: return "cut";
    case BlockMode::KillProcess: return "kill";
    case BlockMode::Both: return "cut+kill";
  }
  return "dry-run";
}

bool block_mode_from_string(const std::string& text, BlockMode* out) {
  const std::string t = to_lower(text);
  if (t == "dry" || t == "dry-run" || t == "dryrun" || t == "none" || t == "off") {
    *out = BlockMode::DryRun;
    return true;
  }
  if (t == "cut" || t == "drop" || t == "reset" || t == "rst") {
    *out = BlockMode::CutTcp;
    return true;
  }
  if (t == "kill" || t == "terminate" || t == "process") {
    *out = BlockMode::KillProcess;
    return true;
  }
  if (t == "both" || t == "all" || t == "cut+kill") {
    *out = BlockMode::Both;
    return true;
  }
  return false;
}

std::string block_mode_help() {
  return
      "interception modes for --block:\n"
      "  dry-run  report what would be cut, change nothing (default)\n"
      "  cut      delete the TCP connection (Windows: SetTcpEntry, IPv4 only)\n"
      "  kill     terminate the process that owns the connection\n"
      "  both     cut, then kill\n"
      "notes:\n"
      "  * nothing happens without an explicit --block <filter>\n"
      "  * --block-max caps the number of actions (default 32)\n"
      "  * a process can never be killed by a 'cut' mode, and never netcap itself\n"
      "  * cutting a connection needs Administrator (SetTcpEntry)\n"
      "  * blocking by image path would need a WFP filter (see README)";
}

// ---------------------------------------------------------------------------
// Guards and actions
// ---------------------------------------------------------------------------

bool Blocker::observable(const PacketInfo& pi) {
  return pi.l4 == L4::Tcp && pi.has_ports && pi.ip_version != 0;
}

std::string Blocker::connection_text(const PacketInfo& pi) const {
  std::string s = to_lower(l4_name(pi.l4));
  s += ' ';
  s += pi.src_addr();
  s += ':';
  s += std::to_string(pi.src_port);
  s += " -> ";
  s += pi.dst_addr();
  s += ':';
  s += std::to_string(pi.dst_port);
  return s;
}

bool Blocker::on_cooldown(const std::string& key, i64 now_us) {
  const auto it = cooldown_.find(key);
  if (it != cooldown_.end() && cfg_.cooldown_us > 0 && now_us - it->second < cfg_.cooldown_us)
    return true;
  cooldown_[key] = now_us;
  return false;
}

void Blocker::reset() {
  cooldown_.clear();
  decisions_.clear();
  matched_ = attempts_ = successes_ = failures_ = skipped_ = 0;
  last_error_.clear();
}

BlockDecision Blocker::act(const PacketInfo& pi, const ProcessInfo* proc, int dir, i64 now_us) {
  BlockDecision d;
  d.ts_us = now_us;
  d.mode = block_mode_name(cfg_.mode);
  d.target = connection_text(pi);
  if (proc && proc->pid) {
    d.pid = proc->pid;
    d.process = proc->label();
  }
  d.matched = true;
  ++matched_;

  auto refuse = [&](const std::string& why) {
    d.skipped = true;
    d.reason = why;
    ++skipped_;
    decisions_.push_back(d);
    return d;
  };

  // A dry run previews what the real run would do, so the "only TCP can be cut"
  // refusal comes first in every mode: a UDP flow would not be touched either.
  if (!observable(pi))
    return refuse("not a TCP connection with ports (only TCP connections can be cut)");

  if (cfg_.mode == BlockMode::DryRun) {
    d.action = true;
    d.reason = "dry run: nothing was touched";
    decisions_.push_back(d);
    return d;
  }

  if (cfg_.max_actions > 0 && attempts_ >= cfg_.max_actions)
    return refuse("action limit reached (--block-max " + std::to_string(cfg_.max_actions) + ")");

  const bool want_cut = cfg_.mode == BlockMode::CutTcp || cfg_.mode == BlockMode::Both;
  const bool want_kill = cfg_.mode == BlockMode::KillProcess || cfg_.mode == BlockMode::Both;

  if (want_kill && (!proc || !proc->pid)) return refuse("cannot kill: no process is known for this packet");
  if (want_kill && proc && cfg_.guard_pid && proc->pid == cfg_.guard_pid)
    return refuse("refusing to kill the capture process itself (pid " + std::to_string(proc->pid) + ")");
  if (want_kill && proc && !cfg_.guard_name.empty() && iequals(proc->name, cfg_.guard_name))
    return refuse("refusing to kill a guarded image ('" + proc->name + "')");
  if (want_kill && proc && (proc->pid == 0 || proc->pid == 4))
    return refuse("refusing to kill a system process (pid " + std::to_string(proc->pid) + ")");
  if (!cfg_.include_loopback) {
    if (pi.ip_version == 4 && ((rd32be(pi.src_ip) >> 24) == 127 || (rd32be(pi.dst_ip) >> 24) == 127))
      return refuse("loopback is excluded");
  }

  // One connection, one action set: a burst of retransmits must not turn into a
  // burst of SetTcpEntry calls.
  const std::string key = connection_text(pi);
  if (on_cooldown(key, now_us))
    return refuse("already acted on this connection within " +
                  std::to_string(cfg_.cooldown_us / 1000) + " ms");

  ++attempts_;
  std::string err;
  bool ok = true;
  if (actor_) {
    // Injected by the self-test: one call covers whichever action the mode asks
    // for, so the decision logic can be checked without touching the machine.
    ok = actor_(pi, dir, want_kill ? proc : nullptr, &err);
    if (!ok) last_error_ = err;
  } else {
    if (want_cut) {
      ok = block_cut_tcp(pi, dir, &err);
      if (!ok) last_error_ = err;
    }
    if (ok && want_kill) {
      ok = block_kill_process(proc->pid, &err);
      if (!ok) last_error_ = err;
    }
  }

  d.action = true;
  d.performed = ok;
  d.error = err;
  if (ok) {
    ++successes_;
    d.reason = "connection cut";
    if (want_kill) d.reason += " and process terminated";
  } else {
    ++failures_;
  }
  decisions_.push_back(d);
  return d;
}

std::string Blocker::describe() const {
  std::string s = "block mode ";
  s += block_mode_name(cfg_.mode);
  s += ", max ";
  s += std::to_string(cfg_.max_actions);
  s += " action(s), cooldown ";
  s += std::to_string(cfg_.cooldown_us / 1000);
  s += " ms";
  if (cfg_.guard_pid) s += ", guarding pid " + std::to_string(cfg_.guard_pid);
  return s;
}

}  // namespace netcap
