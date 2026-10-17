// WFP blocking filters: the Windows half.  Everything here is a thin wrapper
// around the Base Filtering Engine (BFE) calls; the policy, the spec parsing and
// the bookkeeping live in wfp.cpp.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <fwptypes.h>
#include <fwpmu.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/wfp.hpp"

namespace netcap {

namespace {

// The MinGW headers ship fwpmtypes.h/fwpmu.h (structs and function prototypes)
// but not the layer/condition GUID *values*: on MSVC those are DEFINE_GUIDs in
// um/fwpmu.h and are exported by fwpuclnt.lib.  The values below are copied
// verbatim from the Windows SDK header (10.0.22621.0, um/fwpmu.h) with the SDK
// name kept beside each one, so they can be checked against the SDK at a glance.
const GUID kLayerAleAuthConnectV4 = {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
const GUID kLayerAleAuthConnectV6 = {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
const GUID kLayerAleAuthRecvAcceptV4 = {0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}};
const GUID kLayerAleAuthRecvAcceptV6 = {0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}};
const GUID kCondRemoteAddress = {0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};
const GUID kCondRemotePort = {0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};
const GUID kCondIpProtocol = {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
const GUID kCondAleAppId = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
const GUID kSubLayerUniversal = {0xeebecc03, 0xced4, 0x4380, {0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74}};

// RPC_C_AUTHN_WINNT: the BFE only accepts this one.
constexpr UINT32 kAuthnWinnt = 10;
// FWPM_SESSION_FLAG_DYNAMIC (also missing from the MinGW headers): every filter
// added through this handle is deleted when the handle closes, so a crash cannot
// leave the machine blocked.
constexpr UINT32 kSessionFlagDynamic = 0x00000001;

std::string wide_to_utf8(const wchar_t* text) {
  if (text == nullptr) return std::string();
  const int need = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
  if (need <= 1) return std::string();
  std::string out(std::size_t(need - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), need, nullptr, nullptr);
  return out;
}

std::wstring utf8_to_wide(const std::string& text) {
  if (text.empty()) return std::wstring();
  const int need = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), int(text.size()), nullptr, 0);
  if (need <= 0) return std::wstring();
  std::wstring out(std::size_t(need), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.c_str(), int(text.size()), out.data(), need);
  return out;
}

// Same shape as the helpers in proc_win.cpp / block_win.cpp: message -> UTF-8,
// and a plain "(Win32 error N)" when the system has no text for the code.
std::string win_error_text(const char* what, DWORD code) {
  std::string out = std::string(what) + " failed";
  wchar_t* wide = nullptr;
  const DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS,
                                 nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                 reinterpret_cast<wchar_t*>(&wide), 0, nullptr);
  if (n != 0 && wide != nullptr) {
    std::string text = wide_to_utf8(wide);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ' || text.back() == '.')) {
      text.pop_back();
    }
    if (!text.empty() && text.find('%') == std::string::npos) {
      out += ": ";
      out += text;
    }
  }
  if (wide != nullptr) LocalFree(wide);
  out += " (Win32 error " + std::to_string(unsigned(code)) + ")";
  return out;
}

const GUID& layer_for(const WfpSpec& spec) {
  const bool v6 = spec.family == 6;
  const bool outbound = spec.direction == WfpDirection::Outbound;
  if (v6) return outbound ? kLayerAleAuthConnectV6 : kLayerAleAuthRecvAcceptV6;
  return outbound ? kLayerAleAuthConnectV4 : kLayerAleAuthRecvAcceptV4;
}

}  // namespace

bool wfp_platform_available(std::string* note) {
  if (note) {
    *note =
        "Windows Filtering Platform via fwpuclnt.dll (the BFE service); installing a filter needs "
        "Administrator rights";
  }
  return true;
}

std::string wfp_platform_note() {
  return "Windows Filtering Platform ALE layers (fwpuclnt.dll, Administrator required)";
}

// FwpmEngineOpen0 itself is allowed for a standard user, but adding a filter is
// not: the BFE answers ERROR_ACCESS_DENIED.  Telling the two apart up front saves
// a confusing failure, so read the token's elevation flag.
bool wfp_platform_elevated() {
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) return false;
  TOKEN_ELEVATION elevation;
  std::memset(&elevation, 0, sizeof(elevation));
  DWORD size = sizeof(elevation);
  const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
  CloseHandle(token);
  return ok != 0 && elevation.TokenIsElevated != 0;
}

bool wfp_platform_open(void** engine, std::string* error) {
  if (engine == nullptr) return false;
  *engine = nullptr;

  FWPM_SESSION0 session;
  std::memset(&session, 0, sizeof(session));
  session.flags = kSessionFlagDynamic;
  session.txnWaitTimeoutInMSec = 0;

  HANDLE handle = nullptr;
  const DWORD rc = FwpmEngineOpen0(nullptr, kAuthnWinnt, nullptr, &session, &handle);
  if (rc != ERROR_SUCCESS) {
    // Older builds may refuse a dynamic session; a plain one works but then the
    // filters outlive us, which close() and --wfp-apply bookkeeping must handle.
    HANDLE plain = nullptr;
    const DWORD rc2 = FwpmEngineOpen0(nullptr, kAuthnWinnt, nullptr, nullptr, &plain);
    if (rc2 != ERROR_SUCCESS) {
      std::string msg = win_error_text("FwpmEngineOpen0", rc2);
      msg += "; installing a WFP filter needs Administrator rights";
      if (error) *error = msg;
      return false;
    }
    handle = plain;
  }
  *engine = reinterpret_cast<void*>(handle);
  return true;
}

bool wfp_platform_add_block(void* engine, const WfpSpec& spec, u64* id, std::string* error) {
  if (id) *id = 0;
  if (engine == nullptr) {
    if (error) *error = "the WFP engine is not open";
    return false;
  }
  HANDLE handle = reinterpret_cast<HANDLE>(engine);
  const bool v6 = spec.family == 6;

  std::vector<FWPM_FILTER_CONDITION0> condition_list;
  UINT32 address_v4 = 0;
  FWP_BYTE_ARRAY16 address_v6;
  std::memset(&address_v6, 0, sizeof(address_v6));
  FWP_BYTE_BLOB* app_id = nullptr;

  if (!spec.remote_ip.empty()) {
    int version = 0;
    u8 raw[16];
    if (!parse_ip(spec.remote_ip, &version, raw)) {
      if (error) *error = "bad --wfp address '" + spec.remote_ip + "'";
      return false;
    }
    FWPM_FILTER_CONDITION0 cond;
    std::memset(&cond, 0, sizeof(cond));
    cond.fieldKey = kCondRemoteAddress;
    cond.matchType = FWP_MATCH_EQUAL;
    if (version == 4) {
      if (v6) {
        if (error) *error = "an IPv6 filter cannot carry the IPv4 address " + spec.remote_ip;
        return false;
      }
      // WFP wants the IPv4 address in host byte order in an FWP_UINT32.
      address_v4 = ntohl(rd32be(raw));
      cond.conditionValue.type = FWP_UINT32;
      cond.conditionValue.uint32 = address_v4;
    } else {
      if (!v6) {
        if (error) *error = "an IPv4 filter cannot carry the IPv6 address " + spec.remote_ip;
        return false;
      }
      std::memcpy(address_v6.byteArray16, raw, 16);
      cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
      cond.conditionValue.byteArray16 = &address_v6;
    }
    condition_list.push_back(cond);
  }

  if (spec.remote_port != 0) {
    FWPM_FILTER_CONDITION0 cond;
    std::memset(&cond, 0, sizeof(cond));
    cond.fieldKey = kCondRemotePort;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_UINT16;
    cond.conditionValue.uint16 = spec.remote_port;  // ports are host order too
    condition_list.push_back(cond);
  }

  if (spec.protocol != 0) {
    FWPM_FILTER_CONDITION0 cond;
    std::memset(&cond, 0, sizeof(cond));
    cond.fieldKey = kCondIpProtocol;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_UINT8;
    cond.conditionValue.uint8 = spec.protocol;
    condition_list.push_back(cond);
  }

  if (!spec.app_path.empty()) {
    const std::wstring path = utf8_to_wide(spec.app_path);
    const DWORD rc = FwpmGetAppIdFromFileName0(path.c_str(), &app_id);
    if (rc != ERROR_SUCCESS || app_id == nullptr) {
      if (error) *error = win_error_text("FwpmGetAppIdFromFileName0", rc);
      return false;
    }
    FWPM_FILTER_CONDITION0 cond;
    std::memset(&cond, 0, sizeof(cond));
    cond.fieldKey = kCondAleAppId;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = app_id;
    condition_list.push_back(cond);
  }

  const std::wstring name = utf8_to_wide(spec.name.empty() ? spec.describe() : spec.name);
  const std::wstring description = utf8_to_wide("netcap: " + spec.describe());

  FWPM_FILTER0 filter;
  std::memset(&filter, 0, sizeof(filter));
  filter.displayData.name = const_cast<wchar_t*>(name.c_str());
  filter.displayData.description = const_cast<wchar_t*>(description.c_str());
  filter.layerKey = layer_for(spec);
  filter.subLayerKey = kSubLayerUniversal;
  filter.numFilterConditions = UINT32(condition_list.size());
  filter.filterCondition = condition_list.empty() ? nullptr : condition_list.data();
  filter.action.type = FWP_ACTION_BLOCK;
  // Terminating filters (BLOCK/PERMIT) must not carry a hand-made weight: the
  // BFE assigns one and rejects anything else with FWP_E_INVALID_WEIGHT.  Only
  // callout/continue filters may set a weight themselves.
  filter.weight.type = FWP_EMPTY;
  filter.flags = 0;  // session scoped: it goes away with this handle
  // providerKey stays null on purpose: naming a provider that is not registered
  // makes FwpmFilterAdd0 fail with FWP_E_PROVIDER_NOT_FOUND.

  UINT64 filter_id = 0;
  const DWORD rc = FwpmFilterAdd0(handle, &filter, nullptr, &filter_id);

  if (app_id != nullptr) FwpmFreeMemory0(reinterpret_cast<void**>(&app_id));

  if (rc != ERROR_SUCCESS) {
    std::string msg = win_error_text("FwpmFilterAdd0", rc);
    if (rc == DWORD(FWP_E_ALREADY_EXISTS)) msg += "; a filter with this key is already installed";
    if (rc == ERROR_ACCESS_DENIED) msg += "; installing a WFP filter needs Administrator rights";
    if (error) *error = msg;
    return false;
  }
  if (id) *id = u64(filter_id);
  return true;
}

bool wfp_platform_remove(void* engine, u64 id, std::string* error) {
  if (engine == nullptr) {
    if (error) *error = "the WFP engine is not open";
    return false;
  }
  const DWORD rc = FwpmFilterDeleteById0(reinterpret_cast<HANDLE>(engine), id);
  if (rc != ERROR_SUCCESS) {
    if (error) *error = win_error_text("FwpmFilterDeleteById0", rc);
    return false;
  }
  return true;
}

void wfp_platform_close(void* engine) {
  if (engine == nullptr) return;
  FwpmEngineClose0(reinterpret_cast<HANDLE>(engine));
}

}  // namespace netcap

#endif  // _WIN32
