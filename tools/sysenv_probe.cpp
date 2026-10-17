// netcap - low-level network traffic capture toolkit
//
// sysenv_probe - drive the sysenv module (HKCU\Environment + WM_SETTINGCHANGE)
// without a browser, without administrator rights, and without ever touching the
// real SSLKEYLOGFILE variable.
//
// Build (zero warnings with g++ 13.2):
//   g++ -std=c++20 -O2 -Wall -Wextra -Iinclude tools/sysenv_probe.cpp src/sysenv.cpp src/sysenv_win.cpp src/common.cpp -o tools/sysenv_probe.exe
//
// Modes:
//   --selfcheck
//       Run the reversible self-check on the scratch variable NETCAP_SYSENV_PROBE
//       and the scratch files under _se\.  Every check prints one line; the exit
//       code is 0 only when all of them passed and the machine was left exactly as
//       it was found.
//   --set <name> <value> [state-file]
//       sysenv_set().  The state file defaults to sysenv_default_state_path().
//       Writing the real SSLKEYLOGFILE is refused unless --allow-sslkeylogfile is
//       passed: that variable changes what a browser writes to disk.
//   --restore [state-file]
//       sysenv_restore().  Never refused - undoing a change is always allowed.
//   --read <name>
//       sysenv_current(): the user-level registry value, not the process block.
//   --purge <file>
//       sysenv_purge_file(): zero a key log, then delete it.
//
// Exit codes: 0 success, 1 the operation failed, 2 the command line was wrong.
#include "netcap/sysenv.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

namespace {

// The only variable the self-check is allowed to touch.  A browser that is
// already running would not see a change to SSLKEYLOGFILE anyway, and clobbering
// it while netcap itself is not managing it would be a side effect the user did
// not ask for.
const char* const kScratchVariable = "NETCAP_SYSENV_PROBE";
const char* const kForbiddenVariable = "SSLKEYLOGFILE";
const char* const kScratchDir = "_se";

std::string lower(std::string text) {
  for (char& c : text) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return text;
}

bool iequals(const std::string& a, const std::string& b) { return lower(a) == lower(b); }

bool file_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(std::filesystem::path(path), ec);
}

std::string read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return std::string();
  std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  return data;
}

bool write_file(const std::string& path, const std::string& text) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) return false;
  file.write(text.data(), static_cast<std::streamsize>(text.size()));
  return file.good();
}

bool remove_file(const std::string& path) {
  std::error_code ec;
  std::filesystem::remove(std::filesystem::path(path), ec);
  return !file_exists(path);
}

// A snapshot is one line per field; folding the newlines keeps the self-check
// output at one line per entry.
std::string one_line(const std::string& text) {
  std::string out;
  for (char c : text) {
    if (c == '\n') {
      out += " | ";
    } else if (c != '\r') {
      out.push_back(c);
    }
  }
  while (!out.empty() && out.back() == ' ') out.pop_back();
  return out;
}

std::string show(bool exists, const std::string& value) {
  if (!exists) return "not present";
  return "'" + value + "'";
}

struct Report {
  int total = 0;
  int index = 0;
  int failed = 0;

  void check(bool ok, const std::string& label, const std::string& detail) {
    ++index;
    std::cout << "[" << index << "/" << total << "] " << std::left << std::setw(52) << label
              << " : " << (ok ? "ok  " : "FAIL");
    if (!detail.empty()) std::cout << "  " << detail;
    std::cout << "\n";
    if (!ok) ++failed;
  }

  void info(const std::string& label, const std::string& detail) {
    std::cout << "         " << std::left << std::setw(52) << label << " : " << detail << "\n";
  }
};

// Reads a snapshot with the module's own reader, so the checks look at exactly
// what sysenv_restore will see rather than at a second-hand interpretation.
bool read_snapshot(const std::string& path, netcap::SysEnvState* state, bool* expandable,
                   bool* found, std::string* error) {
  return netcap::sysenv_state_read(path, state, expandable, found, error);
}

int run_selfcheck() {
  const std::string variable = kScratchVariable;
  const std::string dir = kScratchDir;
  const std::string state_a = dir + "\\probe-env-a.state";
  const std::string state_b = dir + "\\probe-env-b.state";
  const std::string state_c = dir + "\\probe-env-c.state";
  const std::string key_file = dir + "\\probe-keys.log";

  std::error_code ec;
  const bool dir_existed = std::filesystem::is_directory(std::filesystem::path(dir), ec);
  std::filesystem::create_directories(std::filesystem::path(dir), ec);
  if (!std::filesystem::is_directory(std::filesystem::path(dir), ec)) {
    std::cerr << "error: cannot use the scratch directory '" << dir << "': " << ec.message()
              << "\n";
    return 1;
  }
  // A previous run may have died between the snapshot write and the restore; its
  // leftovers would make this run's snapshot look like another variable's.
  for (const std::string& stale : {state_a, state_b, state_c, state_a + ".tmp", state_b + ".tmp",
                                   state_c + ".tmp", key_file}) {
    remove_file(stale);
  }

  Report report;
  report.total = 19;  // fixed so every line reads "[n/19]" even after a failure
  std::string error;

  // ---- 1: what the machine looks like now -------------------------------
  bool exists_before = false;
  std::string value_before;
  if (!netcap::sysenv_current(variable, &value_before, &exists_before, &error)) {
    report.check(false, "1 baseline sysenv_current", error);
    return 1;
  }
  report.check(true, "1 baseline sysenv_current",
               "HKCU\\Environment\\" + variable + " is " + show(exists_before, value_before));

  // ---- 2: set, and record the original ----------------------------------
  netcap::SysEnvState set1;
  const bool set1_ok = netcap::sysenv_set(variable, "probe-value-1", state_a, &set1, &error);
  report.check(set1_ok, "2a sysenv_set probe-value-1", set1_ok ? set1.note : error);
  if (!set1_ok) {
    std::cout << "         (stopping: the first set failed, so there is nothing to undo)\n";
    return 1;
  }

  bool now_exists = false;
  std::string now_value;
  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  report.check(now_exists && now_value == "probe-value-1", "2b registry holds probe-value-1",
               "observed " + show(now_exists, now_value));

  const std::string text_a = read_file(state_a);
  report.check(file_exists(state_a) && text_a.find("probe-value-1") != std::string::npos,
               "2c snapshot exists and mentions the value", state_a);
  report.check(!file_exists(state_a + ".tmp"), "2d no .tmp file was left behind",
               file_exists(state_a + ".tmp") ? state_a + ".tmp" : "none");

  netcap::SysEnvState rec_a;
  bool expand_a = false;
  bool found_a = false;
  read_snapshot(state_a, &rec_a, &expand_a, &found_a, &error);
  report.info("snapshot after the first set", one_line(text_a));

  // ---- 3: a second set must keep the ORIGINAL previous value -------------
  netcap::SysEnvState set2;
  const bool set2_ok = netcap::sysenv_set(variable, "probe-value-2", state_a, &set2, &error);
  report.check(set2_ok, "3a second sysenv_set probe-value-2", set2_ok ? set2.note : error);
  if (!set2_ok) {
    std::cout << "         (undoing the first set)\n";
    netcap::sysenv_restore(state_a, nullptr, &error);
    return 1;
  }

  netcap::SysEnvState rec_a2;
  bool expand_a2 = false;
  bool found_a2 = false;
  read_snapshot(state_a, &rec_a2, &expand_a2, &found_a2, &error);
  const bool original_kept = found_a2 && rec_a2.had_previous == exists_before &&
                             rec_a2.previous == value_before && rec_a2.value == "probe-value-2";
  report.check(original_kept, "3b snapshot still remembers the ORIGINAL previous value",
               "had_previous=" + std::string(rec_a2.had_previous ? "1" : "0") + " previous=" +
                   (rec_a2.had_previous ? "'" + rec_a2.previous + "'" : std::string("(none)")) +
                   " value='" + rec_a2.value + "'");

  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  report.check(now_exists && now_value == "probe-value-2", "3c registry holds probe-value-2",
               "observed " + show(now_exists, now_value));

  // ---- 4: restore puts the original back --------------------------------
  netcap::SysEnvState restored;
  const bool restore_ok = netcap::sysenv_restore(state_a, &restored, &error);
  report.check(restore_ok, "4a sysenv_restore", restore_ok ? restored.note : error);

  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  const bool back_to_baseline = now_exists == exists_before &&
                                (!exists_before || now_value == value_before);
  report.check(back_to_baseline,
               exists_before ? "4b original value is back" : "4b variable was deleted",
               "observed " + show(now_exists, now_value) +
                   (exists_before ? " (expected " + show(exists_before, value_before) + ")"
                                  : " (it did not exist before netcap set it)"));
  report.check(!file_exists(state_a) && !file_exists(state_a + ".tmp"), "4c snapshot was removed",
               file_exists(state_a) || file_exists(state_a + ".tmp") ? "still present" : "gone");

  // ---- 5: restoring twice is harmless -----------------------------------
  std::string second_error;
  const bool restore_again = netcap::sysenv_restore(state_a, &restored, &second_error);
  report.check(!restore_again && !second_error.empty(), "5a second sysenv_restore refuses",
               restore_again ? "it reported success" : second_error);
  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  report.check(now_exists == exists_before && (!exists_before || now_value == value_before),
               "5b the refusal changed nothing", "observed " + show(now_exists, now_value));

  // ---- 6: purge a key file ---------------------------------------------
  const std::string secret = "netcap-probe-key-material-0123456789\n";
  const bool seeded = write_file(key_file, secret) && read_file(key_file) == secret;
  std::string purge_error;
  const bool purged = seeded && netcap::sysenv_purge_file(key_file, &purge_error);
  report.check(seeded && purged && !file_exists(key_file), "6a sysenv_purge_file removes the file",
               seeded ? (purged ? (file_exists(key_file) ? "the file is still there" : "gone")
                                : purge_error)
                      : "cannot create " + key_file);
  std::string missing_error;
  const bool purge_missing = netcap::sysenv_purge_file(key_file, &missing_error);
  report.check(purge_missing, "6b purging an absent file succeeds", missing_error);

  // ---- 7: a real previous value round trip ------------------------------
  // Scenario 1 above only proves the original-value rule for whatever the machine
  // happened to have.  Here the value that must survive is one this run created,
  // so the had_previous=1 path is always exercised: B remembers the baseline, C -
  // written while "probe-value-1" is in force - must remember "probe-value-1".
  netcap::SysEnvState setb;
  netcap::SysEnvState setc;
  const bool b_ok = netcap::sysenv_set(variable, "probe-value-1", state_b, &setb, &error);
  const bool c_ok = b_ok && netcap::sysenv_set(variable, "probe-value-2", state_c, &setc, &error);
  netcap::SysEnvState rec_c;
  bool expand_c = false;
  bool found_c = false;
  if (c_ok) read_snapshot(state_c, &rec_c, &expand_c, &found_c, &error);
  report.check(c_ok && found_c && rec_c.had_previous && rec_c.previous == "probe-value-1",
               "7a a fresh snapshot remembers a REAL previous value",
               c_ok ? "had_previous=" + std::string(rec_c.had_previous ? "1" : "0") +
                          " previous=" + show(rec_c.had_previous, rec_c.previous)
                    : (b_ok ? error : "the first set of this scenario failed"));

  bool step_ok = true;
  std::string step_detail;
  if (c_ok) {
    step_ok = netcap::sysenv_restore(state_c, &restored, &error);
    step_detail = step_ok ? restored.note : error;
  } else {
    step_ok = false;
    step_detail = "skipped: the snapshot was not written";
  }
  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  report.check(step_ok && now_exists && now_value == "probe-value-1",
               "7b restoring it puts probe-value-1 back", "observed " + show(now_exists, now_value));

  bool b_ok2 = false;
  std::string b_detail = "skipped: the baseline snapshot was not written";
  if (b_ok) {
    b_ok2 = netcap::sysenv_restore(state_b, &restored, &error);
    b_detail = b_ok2 ? restored.note : error;
  }
  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  report.check(b_ok && b_ok2 && now_exists == exists_before &&
                   (!exists_before || now_value == value_before),
               "7c the baseline is back", b_detail + "; observed " + show(now_exists, now_value));

  // ---- 8: the machine is exactly as it was ------------------------------
  netcap::sysenv_current(variable, &now_value, &now_exists, &error);
  report.check(now_exists == exists_before && (!exists_before || now_value == value_before),
               "8 final state matches the baseline", "observed " + show(now_exists, now_value));
  report.info("observed registry value",
              "HKCU\\Environment\\" + variable + " = " +
                  (now_exists ? "'" + now_value + "'" : std::string("not present")));

  // Leftovers only exist when a check failed above, but undo whatever is left so
  // a failed run does not leave the machine changed.
  for (const std::string& path : {state_c + ".tmp", state_b + ".tmp", state_a + ".tmp"}) {
    remove_file(path);
  }
  for (const std::string& path : {state_c, state_b, state_a}) {
    if (!file_exists(path)) continue;
    std::string undo_error;
    const bool undone = netcap::sysenv_restore(path, nullptr, &undo_error);
    std::cout << "         recovery: sysenv_restore " << path << " : "
              << (undone ? "ok" : undo_error) << "\n";
  }
  remove_file(key_file);
  if (!dir_existed) {
    std::filesystem::remove(std::filesystem::path(dir), ec);  // only when it is empty
  }

  std::cout << (report.failed == 0 ? "self-check: all checks passed\n"
                                   : "self-check: " + std::to_string(report.failed) +
                                         " check(s) FAILED\n");
  return report.failed == 0 ? 0 : 1;
}

int usage() {
  std::cerr << "usage: sysenv_probe --selfcheck\n"
            << "       sysenv_probe --set <name> <value> [state-file] [--allow-sslkeylogfile]\n"
            << "       sysenv_probe --restore [state-file]\n"
            << "       sysenv_probe --read <name>\n"
            << "       sysenv_probe --purge <file>\n";
  return 2;
}

// --set takes a name, a value and an optional state file, plus flags.  Parsing
// them apart matters: "--set NAME VALUE --allow-sslkeylogfile" must not read the
// flag as a file name.
struct SetRequest {
  bool valid = false;
  std::string error;
  bool allow_sslkeylogfile = false;
  std::string name;
  std::string value;
  std::string state_file;
};

SetRequest parse_set_request(int argc, char** argv) {
  SetRequest request;
  std::vector<std::string> positional;
  for (int i = 2; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--allow-sslkeylogfile") {
      request.allow_sslkeylogfile = true;
    } else if (arg.size() > 2 && arg.compare(0, 2, "--") == 0) {
      request.error = "unknown option '" + arg + "'";
      return request;
    } else {
      positional.push_back(arg);
    }
  }
  if (positional.size() < 2 || positional.size() > 3) {
    request.error = "--set needs a name, a value and optionally a state file";
    return request;
  }
  request.name = positional[0];
  request.value = positional[1];
  request.state_file = positional.size() == 3 ? positional[2] : netcap::sysenv_default_state_path();
  request.valid = true;
  return request;
}

int mode_set(int argc, char** argv) {
  const SetRequest request = parse_set_request(argc, argv);
  if (!request.valid) {
    std::cerr << "error: " << request.error << "\n";
    return usage();
  }
  const std::string name = request.name;
  const std::string value = request.value;
  const std::string state_file = request.state_file;
  if (iequals(name, kForbiddenVariable) && !request.allow_sslkeylogfile) {
    std::cerr << "error: refusing to write the real " << kForbiddenVariable
              << " variable from this probe; use netcap's own path, or pass "
                 "--allow-sslkeylogfile if you really mean it\n";
    return 2;
  }

  netcap::SysEnvState state;
  std::string error;
  const bool ok = netcap::sysenv_set(name, value, state_file, &state, &error);
  std::cout << std::left << std::setw(12) << "name" << ": " << name << "\n";
  std::cout << std::left << std::setw(12) << "value" << ": " << value << "\n";
  std::cout << std::left << std::setw(12) << "snapshot" << ": " << state_file << "\n";
  std::cout << std::left << std::setw(12) << "previous"
            << ": "
            << (state.had_previous ? "'" + state.previous + "' (remembered; a restore puts it back)"
                                   : std::string("(none; a restore deletes the value)"))
            << "\n";
  std::cout << std::left << std::setw(12) << "result" << ": " << (ok ? "ok" : "failed") << "\n";
  if (!ok) {
    std::cout << std::left << std::setw(12) << "error" << ": " << error << "\n";
    return 1;
  }
  if (!state.note.empty()) std::cout << std::left << std::setw(12) << "note" << ": " << state.note << "\n";
  return 0;
}

int mode_restore(int argc, char** argv) {
  if (argc != 2 && argc != 3) return usage();
  const std::string state_file = argc == 3 ? argv[2] : netcap::sysenv_default_state_path();
  netcap::SysEnvState state;
  std::string error;
  const bool ok = netcap::sysenv_restore(state_file, &state, &error);
  std::cout << std::left << std::setw(12) << "snapshot" << ": " << state_file << "\n";
  std::cout << std::left << std::setw(12) << "name" << ": " << state.name << "\n";
  std::cout << std::left << std::setw(12) << "restored" << ": "
            << (state.had_previous ? show(true, state.previous) : std::string("deleted")) << "\n";
  std::cout << std::left << std::setw(12) << "result" << ": " << (ok ? "ok" : "failed") << "\n";
  if (!ok) {
    std::cout << std::left << std::setw(12) << "error" << ": " << error << "\n";
    return 1;
  }
  if (!state.note.empty()) std::cout << std::left << std::setw(12) << "note" << ": " << state.note << "\n";
  return 0;
}

int mode_read(int argc, char** argv) {
  if (argc != 3) return usage();
  const std::string name = argv[2];
  std::string value;
  bool exists = false;
  std::string error;
  const bool ok = netcap::sysenv_current(name, &value, &exists, &error);
  std::cout << std::left << std::setw(12) << "name" << ": " << name << "\n";
  if (!ok) {
    std::cout << std::left << std::setw(12) << "result" << ": failed\n";
    std::cout << std::left << std::setw(12) << "error" << ": " << error << "\n";
    return 1;
  }
  std::cout << std::left << std::setw(12) << "exists" << ": " << (exists ? "yes" : "no") << "\n";
  std::cout << std::left << std::setw(12) << "value" << ": " << value << "\n";
  return 0;
}

int mode_purge(int argc, char** argv) {
  if (argc != 3) return usage();
  const std::string path = argv[2];
  std::string error;
  const bool ok = netcap::sysenv_purge_file(path, &error);
  std::cout << std::left << std::setw(12) << "file" << ": " << path << "\n";
  std::cout << std::left << std::setw(12) << "result" << ": " << (ok ? "ok" : "failed") << "\n";
  if (!ok) {
    std::cout << std::left << std::setw(12) << "error" << ": " << error << "\n";
    return 1;
  }
  std::cout << std::left << std::setw(12) << "note" << ": the file is no longer on disk\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  // The self-check is about the module, not about argument handling, so it runs
  // before any of the mode wrappers.
  if (std::string(argv[1]) == "--selfcheck") return run_selfcheck();
  if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") return usage();

  // A whole-program guard: nothing here may quietly write a variable netcap does
  // not manage, least of all the browser's key log switch.
  const std::string mode = argv[1];
  if (mode == "--set") return mode_set(argc, argv);
  if (mode == "--restore") return mode_restore(argc, argv);
  if (mode == "--read") return mode_read(argc, argv);
  if (mode == "--purge") return mode_purge(argc, argv);
  return usage();
}
