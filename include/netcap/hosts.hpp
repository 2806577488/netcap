// hosts file handling for the system wide part of the ad blocker.
//
// Writing the hosts file is the bluntest but most reliable way to block a name
// for every program on the machine, so it is treated carefully here:
//   * parse_hosts() never drops a line without saying so;
//   * plan_hosts() keeps everything the user already had, rewrites only the
//     block this program owns (between two markers), and never duplicates an
//     entry that is already there;
//   * a plan is a pure value: building it changes nothing on disk;
//   * write_hosts_file() writes a temporary file first, keeps one .bak copy and
//     then replaces the target, so an interrupted run cannot leave a half
//     written hosts file behind.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "netcap/common.hpp"

namespace netcap {

// One "address name" pair.  A hosts line may carry several names; each one
// becomes its own entry with the same address and line number.
struct HostsEntry {
  std::string address;
  std::string name;      // lower case, trailing dot removed
  std::string comment;   // text after '#', trimmed
  std::size_t line = 0;  // 1-based line number in the source text
};

struct HostsFile {
  std::vector<HostsEntry> entries;
  std::vector<std::string> comments;  // pure comment lines, in order
  std::size_t blank_lines = 0;

  bool has_name(const std::string& name) const;
  const HostsEntry* find(const std::string& name) const;
  std::size_t size() const { return entries.size(); }
  std::string describe() const;
};

// Parses hosts text.  When a line cannot be understood, `*error` receives the
// first complaint (augmented with its line number) and the line is skipped;
// everything else is still parsed.
bool parse_hosts(const std::string& text, HostsFile* out, std::string* error);

extern const char* const kHostsMarkerBegin;
extern const char* const kHostsMarkerEnd;

// The complete file this program would write.
struct HostsPlan {
  std::vector<std::string> added;    // names the plan starts blocking
  std::vector<std::string> removed;  // names the plan stops blocking
  std::vector<std::string> present;  // blocked names that were already mapped
  std::size_t kept_entries = 0;      // entries left untouched
  std::string text;                  // full new file contents

  bool changed() const { return !added.empty() || !removed.empty(); }
  std::string describe() const;
};

// Builds the new file: user content is preserved verbatim, and one marked block
// (kHostsMarkerBegin .. kHostsMarkerEnd) holds `blocked` mapped to
// `sink_address`.  A name that is already mapped to the sink address outside
// the block is reported in `present` instead of being written twice.
HostsPlan plan_hosts(const std::string& current_text, const std::vector<std::string>& blocked,
                     const std::string& sink_address = "0.0.0.0");

// Writes atomically, keeping one .bak copy of the previous file.  The directory
// must already exist; the file itself may not.
bool write_hosts_file(const std::string& path, const std::string& text, std::string* error,
                      bool make_backup = true);

// Where Windows keeps its hosts file (empty on other platforms).
std::string platform_hosts_path();

}  // namespace netcap
