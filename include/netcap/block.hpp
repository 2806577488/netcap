// Interception: deciding which capture should be cut short, and saying clearly
// what was done about it.
//
// This layer is deliberately conservative.  Everything it may touch is visible
// in BlockConfig, every decision is recorded as a BlockDecision (including the
// ones it refused to take), and nothing happens at all until the user opts in
// with an explicit filter.  The portable half holds the policy; the platform
// half (block_win.cpp) does the one destructive call that Windows offers to a
// user-mode process: SetTcpEntry with MIB_TCP_STATE_DELETE_TCB.
#ifndef NETCAP_BLOCK_HPP
#define NETCAP_BLOCK_HPP

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/dissect.hpp"

namespace netcap {

/// Forward declaration; the process layer owns the definition.
struct ProcessInfo;

/// What netcap is allowed to do to a matching connection.
enum class BlockMode : u8 {
  DryRun = 0,      ///< report the decision, touch nothing (the safe default)
  CutTcp = 1,      ///< delete the TCP connection (SetTcpEntry / RST both ways)
  KillProcess = 2, ///< terminate the process that owns the connection
  Both = 3,
};

const char* block_mode_name(BlockMode mode);
bool block_mode_from_string(const std::string& text, BlockMode* out);
std::string block_mode_help();

struct BlockConfig {
  BlockMode mode = BlockMode::DryRun;
  u32 max_actions = 32;           ///< hard stop: never more than this per run
  bool include_loopback = true;   ///< loopback connections are cut too
  u32 guard_pid = 0;              ///< never touch this pid (netcap itself)
  std::string guard_name;         ///< never kill a process with this name
  i64 cooldown_us = 500000;       ///< same connection at most once per interval
};

struct BlockDecision {
  bool matched = false;    ///< the block filter matched this packet
  bool action = false;     ///< an action was intended for it
  bool performed = false;  ///< and the platform call succeeded
  bool skipped = false;    ///< deliberately left alone
  std::string mode;        ///< "dry-run" / "cut" / "kill" / "cut+kill"
  std::string target;      ///< "tcp 10.0.0.5:51000 -> 93.184.216.34:443"
  std::string process;     ///< "chrome.exe (1234)" or empty
  std::string reason;      ///< why it was skipped, or what was done
  std::string error;       ///< platform error text when the action failed
  u32 pid = 0;
  i64 ts_us = 0;
};

/// Is there a platform implementation of the cut action on this machine?
bool block_platform_available(std::string* note);
std::string block_platform_note();

/// Delete the TCP connection this packet belongs to.  Only IPv4 is possible:
/// SetTcpEntry has no IPv6 counterpart, so an IPv6 flow reports that instead of
/// pretending to have cut something.  `outbound` says whether the local side is
/// the packet's source; -1 means "unknown, try both".
bool block_cut_tcp(const PacketInfo& pi, int outbound, std::string* error);

/// Terminate the process that owns the packet.
bool block_kill_process(u32 pid, std::string* error);

/// Injected action, used by the self-test so that no real connection is cut and
/// no real process is killed while the decision logic is checked.
using BlockActor = std::function<bool(const PacketInfo&, int, const ProcessInfo*, std::string*)>;

class Blocker {
 public:
  void set_config(const BlockConfig& cfg) { cfg_ = cfg; }
  const BlockConfig& config() const { return cfg_; }
  void set_actor(BlockActor actor) { actor_ = std::move(actor); }
  void reset();

  /// Applies the guards, then the configured action.  Never throws; every
  /// refusal comes back as a decision with a reason (and a log line in main).
  BlockDecision act(const PacketInfo& pi, const ProcessInfo* proc, int dir, i64 now_us);

  const std::vector<BlockDecision>& decisions() const { return decisions_; }
  u64 matched() const { return matched_; }
  u64 attempts() const { return attempts_; }
  u64 successes() const { return successes_; }
  u64 failures() const { return failures_; }
  u64 skipped() const { return skipped_; }
  const std::string& last_error() const { return last_error_; }
  std::string describe() const;

  /// True when the packet is worth acting on at all: TCP with ports.
  static bool observable(const PacketInfo& pi);

 private:
  bool on_cooldown(const std::string& key, i64 now_us);
  std::string connection_text(const PacketInfo& pi) const;

  BlockConfig cfg_;
  BlockActor actor_;
  std::map<std::string, i64> cooldown_;
  std::vector<BlockDecision> decisions_;
  u64 matched_ = 0, attempts_ = 0, successes_ = 0, failures_ = 0, skipped_ = 0;
  std::string last_error_;
};

}  // namespace netcap

#endif  // NETCAP_BLOCK_HPP
