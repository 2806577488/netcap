// Platform layer for process attribution on systems without an endpoint table
// API: the container, the per-flow memory and the counters still work (they are
// in proc.cpp), but nothing can be filled from the OS, so netcap says so instead
// of silently reporting every packet as unattributed.
#include "netcap/proc.hpp"

namespace netcap {

bool proc_collect_endpoints(std::vector<ProcEndpoint>* out, std::string* error) {
  out->clear();
  if (error) *error = "process attribution is only implemented on Windows (IP Helper endpoint tables)";
  return false;
}

bool proc_collect_process_names(std::map<u32, std::string>* out) {
  out->clear();
  return false;
}

bool proc_resolve_process(u32 pid, ProcessInfo* out) {
  out->pid = pid;
  return false;
}

bool proc_attribution_available(std::string* note) {
  if (note) *note = "not available on this platform: only Windows exposes endpoint owners";
  return false;
}

std::string proc_platform_note() { return "not available on this platform"; }

}  // namespace netcap
