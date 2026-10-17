// netcap - low-level network traffic capture toolkit
// sysenv.hpp: set, remember and undo a per-user environment variable without
// administrator rights.
//
// Why this exists: a Chromium-family browser only writes its TLS/QUIC session
// keys to disk when SSLKEYLOGFILE is already in the environment of the process
// that starts it, and "already" means before the browser exists at all.  netcap
// therefore writes the value into HKCU\Environment - the per-user block every new
// process inherits - broadcasts WM_SETTINGCHANGE so Explorer and the shell
// launchers hand the new block to the programs they start, and keeps the old
// value in a small snapshot file.  That snapshot is what makes the change
// undoable after a crash or a reboot: netcap must never leave a user's
// environment permanently rewritten.
//
// Everything here is best effort by nature.  A browser that is already running
// keeps the environment it was started with, and no broadcast can change that.
//
// All strings are UTF-8, including paths; they are converted to UTF-16 only where
// the Windows API demands it.
#pragma once

#include <string>

namespace netcap {

/// Outcome of a set/restore call, with enough context to report it in a UI.
struct SysEnvState {
  bool active = false;        // true when a value is currently set by us
  std::string name;           // the variable name
  std::string value;          // the value we set
  std::string previous;       // what was there before (empty when none)
  bool had_previous = false;  // false => restore must delete the value
  std::string state_file;     // where the previous value was remembered
  std::string note;           // human-readable status, e.g. "set for new programs"
};

/// Sets HKCU\Environment\<name> to `value` and broadcasts WM_SETTINGCHANGE so a
/// program started afterwards inherits it.  The previous state is written to
/// `state_file` *before* the registry changes, so a process killed at any point
/// can still be undone by sysenv_restore.  No administrator rights are needed.
///
/// Calling it again for the same variable reuses the snapshot: the remembered
/// "previous" value stays the ORIGINAL one, never a value netcap set itself.
/// `out` may be null.  Returns false with a reason, and without touching the
/// registry, when the snapshot cannot be written.
bool sysenv_set(const std::string& name, const std::string& value, const std::string& state_file,
                SysEnvState* out, std::string* error);

/// Puts the variable back exactly as it was: re-writes the remembered value, or
/// deletes the value when there was none.  The snapshot is removed on success, so
/// calling this twice returns false the second time ("nothing to restore") and
/// changes nothing - restoring is idempotent by contract, never destructive.
bool sysenv_restore(const std::string& state_file, SysEnvState* out, std::string* error);

/// Reads the current per-user value from HKCU\Environment.  Deliberately does not
/// consult this process's environment: the registry is what a program started
/// later will inherit.  A missing value is not an error (exists=false).
bool sysenv_current(const std::string& name, std::string* value, bool* exists, std::string* error);

/// %APPDATA%\netcap-ui\quickkeys-env.json, falling back to the temp directory
/// (%TEMP%\netcap-ui\...).  The name is fixed by the UI contract; the content is
/// the tiny key=value snapshot below, not JSON.
std::string sysenv_default_state_path();

/// Deletes a file, overwriting it with zeros first (best effort) - used for the
/// key log once a session is over.  A missing file already counts as purged;
/// returns false with a reason only when the file is still there afterwards.
bool sysenv_purge_file(const std::string& path, std::string* error);

// ---------------------------------------------------------------------------
// Internal: the half of the module that is shared between the portable and the
// platform translation unit (src/sysenv.cpp and src/sysenv_win.cpp).  Nothing
// outside those two files should call these.
// ---------------------------------------------------------------------------

/// Serialised snapshot: a "netcap-sysenv 1" header and key=value lines.
std::string sysenv_state_text(const SysEnvState& state, bool previous_expandable);

/// Parses a snapshot.  `previous_expandable` reports whether the remembered value
/// was REG_EXPAND_SZ and therefore has to be written back as such (may be null).
bool sysenv_state_parse(const std::string& text, SysEnvState* out, bool* previous_expandable,
                        std::string* error);

/// Writes the snapshot atomically: creates the parent directory, writes a temp
/// file, flushes it and renames it into place.
bool sysenv_state_write(const std::string& path, const SysEnvState& state, bool previous_expandable,
                        std::string* error);

/// Reads the snapshot.  `*found` is false when no snapshot exists at all, which
/// is not an error - the caller then reports "nothing to restore".  A snapshot
/// that exists but cannot be parsed is an error: refusing to guess is what keeps
/// a damaged file from being half-applied.  A leftover "<path>.tmp" is used when
/// the file itself is gone, i.e. the writer died between flush and rename.
bool sysenv_state_read(const std::string& path, SysEnvState* out, bool* previous_expandable,
                       bool* found, std::string* error);

/// Removes the snapshot and a leftover "<path>.tmp".  Returns false with a reason
/// when either file is still there.
bool sysenv_state_remove(const std::string& path, std::string* error);

}  // namespace netcap
