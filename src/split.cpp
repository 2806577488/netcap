#include "netcap/split.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <system_error>

#include "netcap/common.hpp"
#include "netcap/proxy.hpp"

namespace netcap {

namespace {

constexpr std::size_t kDefaultMaxOpen = 64;

std::string json_escape(const std::string& in) {
  std::string out;
  out.reserve(in.size() + 8);
  for (const char ch : in) {
    const unsigned char u = static_cast<unsigned char>(ch);
    switch (ch) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (u < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", u);
          out += buf;
        } else {
          out += ch;
        }
    }
  }
  return out;
}

}  // namespace

const char* split_mode_name(SplitMode mode) {
  switch (mode) {
    case SplitMode::Proc: return "proc";
    case SplitMode::App: return "app";
    case SplitMode::Origin: return "origin";
    case SplitMode::Off: break;
  }
  return "off";
}

bool split_mode_from_string(const std::string& text, SplitMode* out) {
  const std::string t = to_lower(text);
  if (t == "proc" || t == "process" || t == "processes" || t == "pid") {
    *out = SplitMode::Proc;
    return true;
  }
  if (t == "app" || t == "apps" || t == "application" || t == "protocol") {
    *out = SplitMode::App;
    return true;
  }
  // "origin" is the program behind a local proxy: what the user actually asked
  // to see when the honest answer to "which process sent this?" is "clash".
  if (t == "origin" || t == "real" || t == "real-app" || t == "reals" ||
      t == "upstream" || t == "behind-proxy") {
    *out = SplitMode::Origin;
    return true;
  }
  if (t == "off" || t == "none") {
    *out = SplitMode::Off;
    return true;
  }
  return false;
}

std::string split_key_proc(const ProcessInfo* proc) {
  if (!proc) return "proc-unattributed";
  if (proc->name.empty()) {
    // A PID we could not name still deserves its own file.
    if (proc->pid != 0) return "proc-pid-" + std::to_string(proc->pid);
    return "proc-unattributed";
  }
  std::string key = "proc-";
  key += proc_sanitize_name(proc->name);
  key += '-';
  key += std::to_string(proc->pid);
  return key;
}

std::string split_key_app(AppKind kind) {
  const char* tag = app_kind_tag(kind);
  // AppKind::Unknown has no tag; it still deserves a readable file name.
  return std::string("app-") + ((tag && *tag) ? tag : "other");
}

std::string split_key_origin(const ProxyLink* link, const ProcessInfo* fallback) {
  // Only a link with a PID identifies the program behind the proxy.
  if (link && link->origin_pid != 0) {
    std::string key = "origin-";
    key += link->origin_name.empty() ? std::string("pid")
                                     : proc_sanitize_name(link->origin_name);
    key += '-';
    key += std::to_string(link->origin_pid);
    return key;
  }
  // Traffic that did not go through a proxy keeps its own process, so a mixed
  // capture is still split by program.
  if (fallback && (!fallback->name.empty() || fallback->pid != 0)) {
    const std::string inner = split_key_proc(fallback);
    return "origin-direct-" + inner.substr(inner.find('-') + 1);
  }
  return "origin-unattributed";
}

SplitWriter::~SplitWriter() {
  std::string ignored;
  close(&ignored);
}

bool SplitWriter::open(const std::string& directory, int linktype, std::uint32_t snaplen,
                       bool nanosecond, std::size_t max_open, std::string* error) {
  std::string ignored;
  close(&ignored);  // a second run must not inherit the first run's state

  if (directory.empty()) {
    if (error) *error = "no output directory for --split-by";
    return false;
  }
  std::error_code ec;
  std::filesystem::create_directories(std::filesystem::path(directory), ec);
  if (ec) {
    if (error) *error = "cannot create directory '" + directory + "': " + ec.message();
    return false;
  }
  dir_ = directory;
  open_ = true;
  linktype_ = linktype;
  snaplen_ = snaplen ? snaplen : 262144;
  nano_ = nanosecond;
  max_open_ = max_open ? max_open : kDefaultMaxOpen;
  // Fresh run: the previous run's index, counters and error belong to its report.
  entries_.clear();
  index_.clear();
  slots_.clear();
  clock_ = 0;
  reopens_ = 0;
  packets_ = 0;
  bytes_ = 0;
  error_.clear();
  return true;
}

std::string SplitWriter::path_for(const std::string& key) const {
  const std::filesystem::path p = std::filesystem::path(dir_) / (key + ".pcap");
  return p.string();
}

SplitWriter::Slot* SplitWriter::slot_for(const std::string& key, std::string* error) {
  auto it = slots_.find(key);
  if (it != slots_.end()) {
    it->second.used = ++clock_;
    return &it->second;
  }

  // At the limit: close the least recently used file.  Its packets are already
  // on disk, and re-entering the key below reopens it in append mode.
  if (slots_.size() >= max_open_) {
    auto victim = slots_.begin();
    for (auto scan = slots_.begin(); scan != slots_.end(); ++scan) {
      if (scan->second.used < victim->second.used) victim = scan;
    }
    victim->second.writer->flush();
    victim->second.writer->close();
    slots_.erase(victim);
    ++reopens_;
  }

  auto idx = index_.find(key);
  if (idx == index_.end()) {
    SplitEntry e;
    e.key = key;
    e.file = key + ".pcap";
    entries_.push_back(e);
    index_[key] = entries_.size() - 1;
    idx = index_.find(key);
  }

  Slot slot;
  slot.index = idx->second;
  slot.used = ++clock_;
  slot.writer.reset(new PcapWriter());
  const std::string path = path_for(key);
  // First use in this run truncates (a stale file from an earlier run must not
  // be mixed in); a reopen after LRU eviction appends to what we already wrote.
  const bool have_data = entries_[slot.index].packets > 0;
  const bool ok = have_data
                      ? slot.writer->open_append(path, linktype_, snaplen_, nano_, error)
                      : slot.writer->open(path, linktype_, snaplen_, nano_, error);
  if (!ok) {
    slot.writer.reset();
    return nullptr;
  }
  auto inserted = slots_.emplace(key, std::move(slot));
  return &inserted.first->second;
}

bool SplitWriter::write(const std::string& key, const PacketView& pkt, std::string* error) {
  if (!is_open()) {
    if (error) *error = "split writer is not open";
    return false;
  }
  Slot* slot = slot_for(key, error);
  if (!slot) return false;
  if (!slot->writer->write(pkt, error)) return false;

  SplitEntry& e = entries_[slot->index];
  ++e.packets;
  e.bytes += pkt.len;
  ++packets_;
  bytes_ += pkt.len;
  return true;
}

void SplitWriter::flush() {
  for (auto& kv : slots_) kv.second.writer->flush();
}

bool SplitWriter::close(std::string* error) {
  bool ok = true;
  for (auto& kv : slots_) {
    kv.second.writer->flush();
    kv.second.writer->close();
  }
  slots_.clear();
  if (!dir_.empty() && !entries_.empty() && !write_manifest(error)) ok = false;
  // Entries and the directory stay behind for the report; only the "open" flag
  // is cleared, so is_open() tells the truth and a later open() starts fresh.
  open_ = false;
  return ok;
}

bool SplitWriter::write_manifest(std::string* error) {
  const std::filesystem::path path = std::filesystem::path(dir_) / "index.json";
  std::FILE* f = std::fopen(path.string().c_str(), "wb");
  if (!f) {
    if (error) *error = "cannot write '" + path.string() + "'";
    return false;
  }
  std::string out = "{\"split\":\"" + std::string(split_mode_name(mode_)) + "\"";
  // The mode is filled in by the caller's report; here the manifest only has to
  // be self-describing about what actually landed on disk.
  out += ",\"files\":[";
  for (std::size_t i = 0; i < entries_.size(); ++i) {
    if (i) out += ',';
    out += "{\"key\":\"" + json_escape(entries_[i].key) + "\",\"file\":\"" +
           json_escape(entries_[i].file) + "\",\"packets\":" +
           std::to_string((unsigned long long)entries_[i].packets) + ",\"bytes\":" +
           std::to_string((unsigned long long)entries_[i].bytes) + "}";
  }
  out += "],\"packets\":" + std::to_string((unsigned long long)packets_);
  out += ",\"bytes\":" + std::to_string((unsigned long long)bytes_) + "}\n";

  const bool ok = std::fwrite(out.data(), 1, out.size(), f) == out.size();
  if (std::fclose(f) != 0 || !ok) {
    if (error) *error = "cannot write '" + path.string() + "'";
    return false;
  }
  return true;
}

}  // namespace netcap
