// One output capture per process, or per application.
//
// A live capture on a normal desktop mixes traffic from dozens of programs, and
// a single pcap of all of it is hard to read.  This writer keeps one file per
// key, opens files lazily, holds at most `max_open` of them at once (the least
// recently used one is closed and reopened in append mode when its key shows up
// again, so no packets are lost), and drops a JSON manifest next to the files
// so the directory explains itself.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "netcap/pcap.hpp"
#include "netcap/proc.hpp"

namespace netcap {

struct ProxyLink;

/// Off, one file per process, one file per application, or one file per *real*
/// application behind a local proxy (Origin).
enum class SplitMode : std::uint8_t { Off = 0, Proc, App, Origin };

/// "off" / "proc" / "app" / "origin"
const char* split_mode_name(SplitMode mode);
/// Accepts proc|process|app|application|origin|real (case-insensitive).  False on
/// anything else.
bool split_mode_from_string(const std::string& text, SplitMode* out);

/// Key for one packet.  Empty means "this packet has nothing to key on", which
/// the caller records in the unattributed/unknown file instead of dropping.
std::string split_key_proc(const ProcessInfo* proc);
std::string split_key_app(AppKind kind);
/// Key for SplitMode::Origin: the program that asked for the traffic, not the
/// proxy that carried it.  `fallback` is used for traffic that did not go
/// through a proxy, so a mixed capture still lands in sensible files.
std::string split_key_origin(const ProxyLink* link, const ProcessInfo* fallback);

struct SplitEntry {
  std::string key;                ///< e.g. "proc-chrome.exe-1234" or "app-tls"
  std::string file;               ///< file name inside the directory
  std::uint64_t packets = 0;
  std::uint64_t bytes = 0;
};

class SplitWriter {
 public:
  SplitWriter() = default;
  ~SplitWriter();
  SplitWriter(const SplitWriter&) = delete;
  SplitWriter& operator=(const SplitWriter&) = delete;

  bool open(const std::string& directory, int linktype, std::uint32_t snaplen = 262144,
            bool nanosecond = false, std::size_t max_open = 64, std::string* error = nullptr);
  /// Recorded in index.json so the directory says how it was split.
  void set_mode(SplitMode mode) { mode_ = mode; }
  SplitMode mode() const { return mode_; }
  bool write(const std::string& key, const PacketView& pkt, std::string* error = nullptr);
  void flush();
  /// Closes every file and writes index.json.
  bool close(std::string* error = nullptr);

  /// False once close() ran, even though directory() still answers afterwards so
  /// the caller can print where index.json went.
  bool is_open() const { return open_; }
  const std::string& directory() const { return dir_; }
  const std::vector<SplitEntry>& entries() const { return entries_; }
  std::uint64_t packets() const { return packets_; }
  std::uint64_t bytes() const { return bytes_; }
  std::size_t key_count() const { return entries_.size(); }
  std::size_t open_files() const { return slots_.size(); }
  std::uint64_t reopen_events() const { return reopens_; }
  const std::string& last_error() const { return error_; }

 private:
  struct Slot {
    std::unique_ptr<PcapWriter> writer;
    std::size_t index = 0;
    std::uint64_t used = 0;  ///< LRU stamp
  };

  Slot* slot_for(const std::string& key, std::string* error);
  std::string path_for(const std::string& key) const;
  bool write_manifest(std::string* error);

  std::string dir_;
  bool open_ = false;
  SplitMode mode_ = SplitMode::Off;
  int linktype_ = DLT_EN10MB;
  std::uint32_t snaplen_ = 262144;
  bool nano_ = false;
  std::size_t max_open_ = 64;
  std::uint64_t clock_ = 0;
  std::uint64_t reopens_ = 0;
  std::uint64_t packets_ = 0;
  std::uint64_t bytes_ = 0;
  std::vector<SplitEntry> entries_;
  std::map<std::string, std::size_t> index_;
  std::map<std::string, Slot> slots_;
  std::string error_;
};

}  // namespace netcap
