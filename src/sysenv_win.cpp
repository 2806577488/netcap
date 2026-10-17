// Windows half of the sysenv module.  HKCU\Environment is the per-user variable
// block that every newly created process inherits, and WM_SETTINGCHANGE is how
// Explorer and the shell launchers are told to re-read it so the programs they
// start pick the change up.  Nothing here needs administrator rights: HKCU is the
// current user's own hive.
//
// sysenv_set writes the snapshot before it touches the registry, which is what
// lets sysenv_restore undo the change even after this process was killed.
#include "netcap/sysenv.hpp"

#include <sstream>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace netcap {
namespace {

// Environment variables live under this key; the value name *is* the variable
// name and its type is normally REG_SZ.  REG_EXPAND_SZ (a path containing
// %USERPROFILE%) is also possible and is preserved across a restore.
const wchar_t* const kEnvironmentKey = L"Environment";

// The value is already set when the broadcast runs, so a hung Explorer must not
// hold netcap for longer than this; a timeout only costs the note.
const DWORD kBroadcastTimeoutMs = 5000;

std::wstring to_wide(const std::string& utf8) {
  if (utf8.empty()) return std::wstring();
  const int need = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()),
                                       nullptr, 0);
  std::wstring out(static_cast<std::size_t>(need < 0 ? 0 : need), L'\0');
  if (need > 0) {
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), out.data(), need);
  }
  return out;
}

std::string to_utf8(const std::wstring& wide) {
  if (wide.empty()) return std::string();
  const int need = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                                       nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(need < 0 ? 0 : need), '\0');
  if (need > 0) {
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), need,
                        nullptr, nullptr);
  }
  return out;
}

// "RegSetValueEx(HKCU\Environment\SSLKEYLOGFILE) failed (Win32 error 5: Access is
// denied.)" - the code alone would leave a user guessing.
std::string win_error_text(const std::string& what, LONG code) {
  std::ostringstream out;
  out << what << " failed (Win32 error " << static_cast<long>(code);
  wchar_t* message = nullptr;
  const DWORD length =
      FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                         FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr, static_cast<DWORD>(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     reinterpret_cast<wchar_t*>(&message), 0, nullptr);
  if (length > 0 && message) {
    std::string text = to_utf8(std::wstring(message, length));
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' ||
                             text.back() == '.')) {
      text.pop_back();
    }
    if (!text.empty()) out << ": " << text;
  }
  if (message) LocalFree(message);
  out << ")";
  return out.str();
}

// The keys are closed by the destructor, which is the only way to be sure that
// every early return below - and there are many - cannot leak a handle.
struct RegKey {
  HKEY handle = nullptr;
  RegKey() = default;
  RegKey(const RegKey&) = delete;
  RegKey& operator=(const RegKey&) = delete;
  ~RegKey() {
    if (handle) RegCloseKey(handle);
  }
};

bool reg_open_environment(RegKey* key, REGSAM access, bool create, std::string* error) {
  HKEY handle = nullptr;
  LONG rc = ERROR_SUCCESS;
  if (create) {
    rc = RegCreateKeyExW(HKEY_CURRENT_USER, kEnvironmentKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                         access, nullptr, &handle, nullptr);
  } else {
    rc = RegOpenKeyExW(HKEY_CURRENT_USER, kEnvironmentKey, 0, access, &handle);
  }
  if (rc != ERROR_SUCCESS) {
    if (error) {
      *error = win_error_text(create ? "RegCreateKeyEx(HKCU\\Environment)"
                                     : "RegOpenKeyEx(HKCU\\Environment)",
                              rc);
    }
    return false;
  }
  key->handle = handle;
  return true;
}

// Reads the value as text.  `*present` is false when the value does not exist,
// which every caller treats as ordinary rather than as an error.
bool reg_read_string(HKEY key, const std::string& name, bool* present, std::string* value,
                     bool* expandable, std::string* error) {
  *present = false;
  value->clear();
  if (expandable) *expandable = false;

  const std::wstring wide_name = to_wide(name);
  DWORD type = 0;
  DWORD size = 0;
  LONG rc = RegQueryValueExW(key, wide_name.c_str(), nullptr, &type, nullptr, &size);
  if (rc == ERROR_FILE_NOT_FOUND) return true;
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegQueryValueEx(HKCU\\Environment\\" + name + ")", rc);
    return false;
  }
  if (type != REG_SZ && type != REG_EXPAND_SZ) {
    std::ostringstream out;
    out << "the value '" << name << "' in HKCU\\Environment has registry type "
        << static_cast<unsigned long>(type)
        << ", not a string; netcap cannot represent it and will not guess";
    if (error) *error = out.str();
    return false;
  }

  std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
  DWORD got = size;
  rc = RegQueryValueExW(key, wide_name.c_str(), nullptr, nullptr,
                        reinterpret_cast<BYTE*>(buffer.data()), &got);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegQueryValueEx(HKCU\\Environment\\" + name + ")", rc);
    return false;
  }
  std::size_t chars = got / sizeof(wchar_t);
  // An environment value cannot contain a NUL, so a trailing terminator is the
  // string's end, not data.
  while (chars > 0 && buffer[chars - 1] == L'\0') --chars;
  *value = to_utf8(std::wstring(buffer.data(), chars));
  *present = true;
  if (expandable) *expandable = type == REG_EXPAND_SZ;
  return true;
}

bool reg_write_string(HKEY key, const std::string& name, const std::string& value, bool expandable,
                      std::string* error) {
  const std::wstring wide_name = to_wide(name);
  const std::wstring wide_value = to_wide(value);
  const DWORD bytes = static_cast<DWORD>((wide_value.size() + 1) * sizeof(wchar_t));
  const LONG rc = RegSetValueExW(key, wide_name.c_str(), 0, expandable ? REG_EXPAND_SZ : REG_SZ,
                                 reinterpret_cast<const BYTE*>(wide_value.c_str()), bytes);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("RegSetValueEx(HKCU\\Environment\\" + name + ")", rc);
    return false;
  }
  return true;
}

bool reg_delete_value(HKEY key, const std::string& name, std::string* error) {
  const std::wstring wide_name = to_wide(name);
  const LONG rc = RegDeleteValueW(key, wide_name.c_str());
  // Already gone is the end state restore wants, so it is not a failure.
  if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
    if (error) *error = win_error_text("RegDeleteValue(HKCU\\Environment\\" + name + ")", rc);
    return false;
  }
  return true;
}

// Tells the shell to re-read the environment.  Failing is not an error: the value
// is in the registry either way, only programs started by an already-running
// Explorer would keep seeing the old block.  `why` says what went wrong.
bool broadcast_environment_change(std::string* why) {
  why->clear();
  SetLastError(ERROR_SUCCESS);
  DWORD_PTR result = 0;
  const LRESULT answered =
      SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                          reinterpret_cast<LPARAM>(L"Environment"), SMTO_ABORTIFHUNG,
                          kBroadcastTimeoutMs, &result);
  if (answered != 0) return true;
  const DWORD rc = GetLastError();
  if (rc == ERROR_TIMEOUT) {
    std::ostringstream out;
    out << "timed out after " << static_cast<long>(kBroadcastTimeoutMs) << " ms";
    *why = out.str();
  } else if (rc == ERROR_SUCCESS) {
    *why = "reached no window (no shell is listening)";
  } else {
    *why = win_error_text("SendMessageTimeout(WM_SETTINGCHANGE)", static_cast<LONG>(rc));
  }
  return false;
}

std::string broadcast_note(bool delivered, const std::string& why) {
  if (delivered) return " (WM_SETTINGCHANGE delivered)";
  return " (WM_SETTINGCHANGE " + why +
         "; the registry is correct, but a program started by an already-running Explorer may "
         "still see the old environment)";
}

}  // namespace

bool sysenv_set(const std::string& name, const std::string& value, const std::string& state_file,
                SysEnvState* out, std::string* error) {
  SysEnvState local;
  SysEnvState* state = out ? out : &local;
  *state = SysEnvState();
  std::string ignored;
  if (!error) error = &ignored;

  if (name.empty()) {
    *error = "the environment variable name is empty";
    return false;
  }
  if (name.find('=') != std::string::npos || name.find('\\') != std::string::npos) {
    *error = "the variable name '" + name +
             "' contains '=' or '\\', which a Windows environment variable name cannot hold";
    return false;
  }
  if (value.find('\0') != std::string::npos) {
    *error = "the value for '" + name + "' contains a NUL byte, which an environment variable "
             "cannot hold";
    return false;
  }
  if (state_file.empty()) {
    *error = "no snapshot path was given, so a crash could not be undone";
    return false;
  }

  // An existing snapshot wins over the current registry value: a second set must
  // remember the value that was there before netcap did anything, never the value
  // netcap wrote itself.
  SysEnvState record;
  bool previous_expandable = false;
  bool found = false;
  if (!sysenv_state_read(state_file, &record, &previous_expandable, &found, error)) return false;
  if (found) {
    if (record.name != name) {
      *error = "the snapshot '" + state_file + "' remembers '" + record.name + "', not '" + name +
               "'; refusing to overwrite it";
      return false;
    }
  } else {
    {
      RegKey key;
      if (!reg_open_environment(&key, KEY_QUERY_VALUE, false, error)) return false;
      bool present = false;
      std::string current;
      bool expandable = false;
      if (!reg_read_string(key.handle, name, &present, &current, &expandable, error)) return false;
      record.previous = current;
      record.had_previous = present;
      previous_expandable = expandable;
    }
  }
  record.active = true;
  record.name = name;
  record.value = value;
  record.state_file = state_file;

  // Snapshot first.  Dying before the registry write then leaves the machine
  // untouched, and dying after it leaves the record already on disk.
  if (!sysenv_state_write(state_file, record, previous_expandable, error)) return false;

  {
    RegKey key;
    if (!reg_open_environment(&key, KEY_QUERY_VALUE | KEY_SET_VALUE, true, error)) {
      // The registry is unchanged, so a snapshot this call created is noise.
      // One that was already there still describes the registry correctly.
      if (!found) {
        std::string purge_error;
        sysenv_state_remove(state_file, &purge_error);
      }
      return false;
    }
    if (!reg_write_string(key.handle, name, value, false, error)) {
      if (!found) {
        std::string purge_error;
        sysenv_state_remove(state_file, &purge_error);
      }
      return false;
    }
  }

  std::string why;
  const bool delivered = broadcast_environment_change(&why);
  record.note = "set for programs started after the broadcast" + broadcast_note(delivered, why);
  *state = record;
  return true;
}

bool sysenv_restore(const std::string& state_file, SysEnvState* out, std::string* error) {
  SysEnvState local;
  SysEnvState* state = out ? out : &local;
  *state = SysEnvState();
  std::string ignored;
  if (!error) error = &ignored;

  if (state_file.empty()) {
    *error = "no snapshot path was given";
    return false;
  }

  SysEnvState record;
  bool previous_expandable = false;
  bool found = false;
  if (!sysenv_state_read(state_file, &record, &previous_expandable, &found, error)) return false;
  if (!found) {
    *error = "no netcap environment snapshot at '" + state_file +
             "': nothing is set by netcap, or it was already restored";
    return false;
  }
  if (record.name.empty()) {
    *error = "the snapshot '" + state_file + "' does not name an environment variable";
    return false;
  }

  {
    RegKey key;
    if (!reg_open_environment(&key, KEY_QUERY_VALUE | KEY_SET_VALUE, true, error)) return false;
    if (record.had_previous) {
      if (!reg_write_string(key.handle, record.name, record.previous, previous_expandable, error)) {
        return false;
      }
    } else if (!reg_delete_value(key.handle, record.name, error)) {
      return false;
    }
  }

  std::string remove_error;
  if (!sysenv_state_remove(state_file, &remove_error)) {
    // The environment is right, only the record is left over: say exactly that,
    // because a caller that reports "restore failed" here would be wrong about
    // the machine's state.
    state->active = false;
    state->name = record.name;
    state->value = record.value;
    state->previous = record.previous;
    state->had_previous = record.had_previous;
    state->state_file = state_file;
    state->note = "the environment was put back, but the snapshot file is still there";
    *error = "the environment was restored, but the snapshot could not be deleted: " + remove_error;
    return false;
  }

  std::string why;
  const bool delivered = broadcast_environment_change(&why);
  record.active = false;
  record.state_file = state_file;
  record.note = record.had_previous
                    ? "restored the value that was there before netcap set it"
                    : "deleted: the variable did not exist before netcap set it";
  record.note += broadcast_note(delivered, why);
  *state = record;
  return true;
}

bool sysenv_current(const std::string& name, std::string* value, bool* exists, std::string* error) {
  std::string local_value;
  bool local_exists = false;
  std::string ignored;
  if (!value) value = &local_value;
  if (!exists) exists = &local_exists;
  if (!error) error = &ignored;
  value->clear();
  *exists = false;

  if (name.empty()) {
    *error = "the environment variable name is empty";
    return false;
  }

  HKEY handle = nullptr;
  const LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, kEnvironmentKey, 0, KEY_QUERY_VALUE, &handle);
  if (rc == ERROR_FILE_NOT_FOUND) return true;  // no per-user environment block at all
  if (rc != ERROR_SUCCESS) {
    *error = win_error_text("RegOpenKeyEx(HKCU\\Environment)", rc);
    return false;
  }
  RegKey key;
  key.handle = handle;

  bool present = false;
  bool expandable = false;
  if (!reg_read_string(key.handle, name, &present, value, &expandable, error)) return false;
  *exists = present;
  return true;
}

}  // namespace netcap
