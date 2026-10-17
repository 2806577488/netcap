// Portable half of the sysenv module: the snapshot on disk that makes a set
// undoable after a crash, where that snapshot lives by default, and the
// zero-then-delete purge.  The platform half (src/sysenv_win.cpp or
// src/sysenv_stub.cpp) owns the actual environment change.
#include "netcap/sysenv.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <wchar.h>
#include <windows.h>
#endif

namespace netcap {
namespace {

// Version tag of the snapshot format.  Bumping it is the only way an existing
// file becomes unreadable, which is intentional: a snapshot we cannot parse is
// refused rather than half-applied.
const char* const kSnapshotHeader = "netcap-sysenv 1";

// The Windows narrow file APIs interpret their argument in the ANSI code page,
// so a path that arrived as UTF-8 (a user name with non-ASCII characters, e.g.
// C:\Users\<...>\AppData\Roaming) would be mangled there.  Every path in this
// module is UTF-8, so on Windows the wide entry points are used and everywhere
// else plain fopen is enough.
#ifdef _WIN32
const wchar_t* const kModeRead = L"rb";
const wchar_t* const kModeWrite = L"wb";
const wchar_t* const kModeUpdate = L"r+b";

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

std::string win_environment(const wchar_t* name) {
  const DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
  if (need == 0) return std::string();
  std::wstring buffer(static_cast<std::size_t>(need), L'\0');
  const DWORD got = GetEnvironmentVariableW(name, buffer.data(), need);
  if (got == 0 || got >= need) return std::string();
  buffer.resize(static_cast<std::size_t>(got));
  return to_utf8(buffer);
}

std::FILE* open_file(const std::string& path, const wchar_t* mode) {
  return _wfopen(to_wide(path).c_str(), mode);
}

std::filesystem::path native_path(const std::string& utf8) {
  return std::filesystem::path(to_wide(utf8));
}

int remove_native(const std::string& path) { return _wremove(to_wide(path).c_str()); }
int rename_native(const std::string& from, const std::string& to) {
  return _wrename(to_wide(from).c_str(), to_wide(to).c_str());
}
#else
const char* const kModeRead = "rb";
const char* const kModeWrite = "wb";
const char* const kModeUpdate = "r+b";

std::string get_environment(const char* name) {
  const char* value = std::getenv(name);
  return value ? std::string(value) : std::string();
}

std::FILE* open_file(const std::string& path, const char* mode) {
  return std::fopen(path.c_str(), mode);
}

std::filesystem::path native_path(const std::string& path) {
  return std::filesystem::path(path);
}

int remove_native(const std::string& path) { return std::remove(path.c_str()); }
int rename_native(const std::string& from, const std::string& to) {
  return std::rename(from.c_str(), to.c_str());
}
#endif

std::string system_error_text(int code) {
  return code ? std::string(std::strerror(code)) : std::string("no system error reported");
}

bool file_exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::exists(native_path(path), ec);
}

bool is_directory(const std::string& path) {
  std::error_code ec;
  return std::filesystem::is_directory(native_path(path), ec);
}

// Escaping keeps a value that contains a newline or a backslash (a Windows path
// is full of backslashes) on its own line and readable in the snapshot.
std::string escape_value(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (char c : value) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

bool unescape_value(const std::string& text, std::string* out, std::string* error) {
  out->clear();
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] != '\\') {
      out->push_back(text[i]);
      continue;
    }
    if (i + 1 >= text.size()) {
      if (error) *error = "the snapshot ends with a lone backslash";
      return false;
    }
    const char c = text[++i];
    switch (c) {
      case '\\': out->push_back('\\'); break;
      case 'n': out->push_back('\n'); break;
      case 'r': out->push_back('\r'); break;
      case 't': out->push_back('\t'); break;
      default:
        if (error) *error = std::string("unknown escape '\\") + c + "' in the snapshot";
        return false;
    }
  }
  return true;
}

bool write_text_file(const std::string& path, const std::string& text, std::string* error) {
  const std::string temp = path + ".tmp";
  std::FILE* file = open_file(temp, kModeWrite);
  if (!file) {
    if (error) *error = "cannot open '" + temp + "' for writing: " + system_error_text(errno);
    return false;
  }
  const std::size_t written = std::fwrite(text.data(), 1, text.size(), file);
  const bool flushed = std::fflush(file) == 0;
  const int flush_error = errno;
  const bool closed = std::fclose(file) == 0;
  if (written != text.size() || !flushed || !closed) {
    if (error) *error = "cannot write '" + temp + "': " + system_error_text(flush_error);
    remove_native(temp);
    return false;
  }
  // Windows rename() refuses to replace an existing file, so the target goes
  // first.  The new content has been complete on disk since the flush above,
  // which is what makes a crash in this tiny window survivable: sysenv_state_read
  // falls back to the ".tmp" file.
  remove_native(path);
  errno = 0;
  if (rename_native(temp, path) != 0) {
    if (error) *error = "cannot move '" + temp + "' to '" + path + "': " + system_error_text(errno);
    remove_native(temp);
    return false;
  }
  return true;
}

bool read_text_file(const std::string& path, std::string* out, std::string* error) {
  std::FILE* file = open_file(path, kModeRead);
  if (!file) {
    if (error) *error = "cannot open '" + path + "' for reading: " + system_error_text(errno);
    return false;
  }
  std::string data;
  char buffer[4096];
  std::size_t got = 0;
  while ((got = std::fread(buffer, 1, sizeof buffer, file)) > 0) data.append(buffer, got);
  const bool failed = std::ferror(file) != 0;
  const int read_error = errno;
  std::fclose(file);
  if (failed) {
    if (error) *error = "cannot read '" + path + "': " + system_error_text(read_error);
    return false;
  }
  *out = std::move(data);
  return true;
}

}  // namespace

std::string sysenv_state_text(const SysEnvState& state, bool previous_expandable) {
  std::string out = kSnapshotHeader;
  out += "\nname=";
  out += escape_value(state.name);
  out += "\nvalue=";
  out += escape_value(state.value);
  out += "\nhad_previous=";
  out += state.had_previous ? "1" : "0";
  out += "\nprevious=";
  out += escape_value(state.previous);
  // The whole reason this field exists: a value like %USERPROFILE%\keys.log is
  // REG_EXPAND_SZ and has to go back as REG_EXPAND_SZ, or the browser would see
  // the literal percent signs after a restore.
  out += "\nprevious_type=";
  out += previous_expandable ? "expand" : "sz";
  out += "\n";
  return out;
}

bool sysenv_state_parse(const std::string& text, SysEnvState* out, bool* previous_expandable,
                        std::string* error) {
  *out = SysEnvState();
  if (previous_expandable) *previous_expandable = false;
  bool have_name = false;
  bool have_previous_flag = false;
  bool first_line = true;
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string::npos) end = text.size();
    std::string line = text.substr(start, end - start);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    start = end + 1;

    if (first_line) {
      first_line = false;
      if (line != kSnapshotHeader) {
        if (error) {
          *error = std::string("the snapshot does not start with '") + kSnapshotHeader + "'";
        }
        return false;
      }
      continue;
    }
    if (line.empty()) continue;

    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) {
      if (error) *error = "the snapshot line '" + line + "' has no '='";
      return false;
    }
    const std::string key = line.substr(0, equals);
    const std::string raw = line.substr(equals + 1);

    if (key == "had_previous") {
      if (raw != "0" && raw != "1") {
        if (error) *error = "the snapshot's had_previous field is '" + raw + "', expected 0 or 1";
        return false;
      }
      out->had_previous = raw == "1";
      have_previous_flag = true;
    } else if (key == "previous_type") {
      if (raw != "sz" && raw != "expand") {
        if (error) *error = "the snapshot's previous_type field is '" + raw + "', expected sz or expand";
        return false;
      }
      if (previous_expandable) *previous_expandable = raw == "expand";
    } else if (key == "name" || key == "value" || key == "previous") {
      std::string value;
      if (!unescape_value(raw, &value, error)) return false;
      if (key == "name") {
        out->name = value;
        have_name = true;
      } else if (key == "value") {
        out->value = value;
      } else {
        out->previous = value;
      }
    }
    // Unknown keys are ignored on purpose: a snapshot written by a newer netcap
    // must still be restorable by an older one.
  }
  if (!have_name) {
    if (error) *error = "the snapshot does not name an environment variable";
    return false;
  }
  if (!have_previous_flag) {
    // Guessing here would mean guessing between "delete the value" and "put the
    // old value back", and one of those guesses destroys user state.
    if (error) *error = "the snapshot has no had_previous line, so restoring it would be a guess";
    return false;
  }
  return true;
}

bool sysenv_state_write(const std::string& path, const SysEnvState& state, bool previous_expandable,
                        std::string* error) {
  if (path.empty()) {
    if (error) *error = "the snapshot path is empty";
    return false;
  }
  const std::filesystem::path parent = native_path(path).parent_path();
  if (!parent.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (!std::filesystem::is_directory(parent, ec)) {
      if (error) *error = "cannot create the directory for '" + path + "': " + ec.message();
      return false;
    }
  }
  return write_text_file(path, sysenv_state_text(state, previous_expandable), error);
}

bool sysenv_state_read(const std::string& path, SysEnvState* out, bool* previous_expandable,
                       bool* found, std::string* error) {
  *out = SysEnvState();
  if (previous_expandable) *previous_expandable = false;
  *found = false;

  std::string source = path;
  std::string text;
  if (!file_exists(path)) {
    // A leftover ".tmp" means the writer died between flush and rename.  Its
    // content is complete by construction and is the only remaining record of
    // what the registry looked like, so it is used instead of losing the change.
    const std::string temp = path + ".tmp";
    if (!file_exists(temp)) return true;  // nothing was ever recorded
    source = temp;
  }
  if (!read_text_file(source, &text, error)) return false;
  if (!sysenv_state_parse(text, out, previous_expandable, error)) {
    if (error) {
      const std::string reason = *error;
      *error = "the snapshot '" + source + "' is not usable: " + reason;
    }
    return false;
  }
  out->state_file = source;
  *found = true;
  return true;
}

bool sysenv_state_remove(const std::string& path, std::string* error) {
  const std::string temp = path + ".tmp";
  std::string stuck;
  for (const std::string& candidate : {path, temp}) {
    if (!file_exists(candidate)) continue;
    errno = 0;
    if (remove_native(candidate) != 0 && file_exists(candidate)) {
      if (stuck.empty()) stuck = candidate + ": " + system_error_text(errno);
    }
  }
  if (!stuck.empty()) {
    if (error) *error = "cannot delete '" + stuck + "'";
    return false;
  }
  return true;
}

std::string sysenv_default_state_path() {
  std::string base;
#ifdef _WIN32
  base = win_environment(L"APPDATA");
  if (base.empty()) base = win_environment(L"TEMP");
  if (base.empty()) base = win_environment(L"TMP");
  if (base.empty()) {
    wchar_t fallback[MAX_PATH + 1] = {};
    const DWORD got = GetTempPathW(MAX_PATH, fallback);
    if (got > 0 && got <= MAX_PATH) base = to_utf8(std::wstring(fallback, got));
  }
  const char separator = '\\';
#else
  base = get_environment("APPDATA");
  if (base.empty()) base = get_environment("TMPDIR");
  if (base.empty()) base = get_environment("TEMP");
  if (base.empty()) base = get_environment("TMP");
  const char separator = '/';
#endif
  while (!base.empty() && (base.back() == '\\' || base.back() == '/')) base.pop_back();
  if (base.empty()) base = ".";  // never observed; a relative path still works
  std::string out = base;
  out += separator;
  out += "netcap-ui";
  out += separator;
  out += "quickkeys-env.json";
  return out;
}

bool sysenv_purge_file(const std::string& path, std::string* error) {
  if (path.empty()) {
    if (error) *error = "the file to purge has an empty path";
    return false;
  }
  if (!file_exists(path)) return true;  // already gone: purging it again is a no-op
  if (is_directory(path)) {
    if (error) *error = "'" + path + "' is a directory, not a file";
    return false;
  }

  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(native_path(path), ec);
  if (!ec && size > 0) {
    // Overwrite in place, in chunks.  The goal is that no plaintext key log is
    // left in this file's clusters; this is best effort, not a secure erase, so
    // failure to zero is not fatal - the delete below is what has to work.
    if (std::FILE* file = open_file(path, kModeUpdate)) {
      std::vector<char> zeros(64 * 1024, 0);
      std::uintmax_t left = size;
      bool wrote_all = true;
      while (left > 0) {
        const std::size_t chunk =
            static_cast<std::size_t>(std::min<std::uintmax_t>(left, zeros.size()));
        if (std::fwrite(zeros.data(), 1, chunk, file) != chunk) {
          wrote_all = false;
          break;
        }
        left -= chunk;
      }
      if (wrote_all) std::fflush(file);
      std::fclose(file);
    }
  }

  errno = 0;
  if (remove_native(path) != 0 && file_exists(path)) {
    // The requirement is about the file still being there, so the removal result
    // is checked against reality rather than trusted.
    if (error) *error = "cannot delete '" + path + "': " + system_error_text(errno);
    return false;
  }
  return true;
}

}  // namespace netcap
