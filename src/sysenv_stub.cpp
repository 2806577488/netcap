// Platform half of the sysenv module on systems without HKCU\Environment.  The
// per-user variable block is a Windows registry key and WM_SETTINGCHANGE is a
// Windows message, so there is nothing honest to implement here: every call says
// exactly what is missing instead of pretending the environment changed.  The
// portable half (the snapshot file, the default location, the purge) still works,
// because those are plain files.
#include "netcap/sysenv.hpp"

namespace netcap {

bool sysenv_set(const std::string& name, const std::string& value, const std::string& state_file,
                SysEnvState* out, std::string* error) {
  if (out) {
    *out = SysEnvState();
    out->name = name;
    out->value = value;
    out->state_file = state_file;
    out->note = "not available on this platform";
  }
  if (error) {
    *error = "cannot set '" + name +
             "': a user-level environment variable is only implemented on Windows "
             "(HKCU\\Environment + WM_SETTINGCHANGE)";
  }
  return false;
}

bool sysenv_restore(const std::string& state_file, SysEnvState* out, std::string* error) {
  if (out) {
    *out = SysEnvState();
    out->state_file = state_file;
    out->note = "not available on this platform";
  }
  if (error) {
    *error = "cannot restore '" + state_file +
             "': a user-level environment variable is only implemented on Windows";
  }
  return false;
}

bool sysenv_current(const std::string& name, std::string* value, bool* exists, std::string* error) {
  if (value) value->clear();
  if (exists) *exists = false;
  if (error) {
    *error = "cannot read '" + name +
             "': the user-level environment is only implemented on Windows";
  }
  return false;
}

}  // namespace netcap
