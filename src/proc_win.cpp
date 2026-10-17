// Windows platform layer for process attribution.
//
// Two questions are answered here:
//   1. which local endpoints exist, and which PID owns each of them
//      (GetExtendedTcpTable / GetExtendedUdpTable, OWNER_PID table classes)
//   2. what is the image name/path behind a PID
//      (OpenProcess + QueryFullProcessImageNameW)
//
// The endpoint tables come back as a header count followed by fixed-size rows.
// Those row layouts are frozen by the OS ABI, so this file walks the buffer by
// offset with the unaligned-safe readers from common.hpp instead of casting it
// to a packed struct -- the same rule the packet dissector follows.
#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/proc.hpp"

// Table classes, spelled out as casts so any SDK header version builds: the
// enumerators exist in iphlpapi.h, but naming them directly would break on a
// header set that guards them behind a newer _WIN32_WINNT.
namespace {
const TCP_TABLE_CLASS kTcpOwnerPidAll = static_cast<TCP_TABLE_CLASS>(5);
const UDP_TABLE_CLASS kUdpOwnerPid = static_cast<UDP_TABLE_CLASS>(1);
}  // namespace

namespace netcap {

namespace {

constexpr u8 kProtoTcp = 6;
constexpr u8 kProtoUdp = 17;

std::string system_error_text(const char* what, unsigned long code) {
  // Wide API + explicit UTF-8 conversion: netcap's own output is UTF-8, and
  // FormatMessageA would return the ANSI code page instead.
  wchar_t* wmsg = nullptr;
  const DWORD n = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<wchar_t*>(&wmsg), 0,
      nullptr);
  std::string text;
  if (n && wmsg) {
    const int need = WideCharToMultiByte(CP_UTF8, 0, wmsg, int(n), nullptr, 0, nullptr, nullptr);
    if (need > 0) {
      text.resize(std::size_t(need));
      WideCharToMultiByte(CP_UTF8, 0, wmsg, int(n), &text[0], need, nullptr, nullptr);
    }
    LocalFree(wmsg);
  }
  while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
    text.pop_back();
  if (text.find('%') != std::string::npos) text.clear();  // unsubstituted template
  std::string out = what;
  out += " failed";
  if (!text.empty()) {
    out += ": ";
    out += text;
  } else {
    char buf[64];
    std::snprintf(buf, sizeof(buf), " (Win32 error %lu)", code);
    out += buf;
  }
  return out;
}

std::string wide_to_utf8(const wchar_t* w) {
  if (!w) return std::string();
  const int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  if (need <= 1) return std::string();
  std::string out(std::size_t(need - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w, -1, &out[0], need, nullptr, nullptr);
  return out;
}

std::string base_name(const std::string& path) {
  const std::size_t pos = path.find_last_of("\\/");
  return pos == std::string::npos ? path : path.substr(pos + 1);
}

// Ports sit in the low 16 bits, in network order.
u16 host_port_from_table(u32 raw) { return ntohs(u16(unsigned(raw) & 0xffffu)); }

// `ipver` is the IP version (4 or 6), not the address-family constant: AF_INET
// is 2, so using it as a version silently selects the wrong row layout.
bool collect_tcp(int ipver, std::vector<ProcEndpoint>* out, std::string* error) {
  const ULONG af = ipver == 6 ? ULONG(AF_INET6) : ULONG(AF_INET);
  DWORD size = 0;
  DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, af, kTcpOwnerPidAll, 0);
  if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
    if (error) *error = system_error_text("GetExtendedTcpTable", rc);
    return false;
  }
  std::vector<u8> buf(size ? size : 4, 0);
  rc = GetExtendedTcpTable(buf.data(), &size, FALSE, af, kTcpOwnerPidAll, 0);
  if (rc != NO_ERROR) {
    if (error) *error = system_error_text("GetExtendedTcpTable", rc);
    return false;
  }
  if (buf.size() < 4) return true;
  const u32 count = rd32le(buf.data());
  const std::size_t row_size = ipver == 4 ? 24 : 56;
  std::size_t off = 4;
  for (u32 i = 0; i < count; ++i) {
    if (off + row_size > buf.size()) break;   // truncated table: keep what we have
    const u8* row = buf.data() + off;
    ProcEndpoint r;
    r.family = ipver;
    r.proto = kProtoTcp;
    if (ipver == 4) {
      std::memcpy(r.addr, row + 4, 4);
      r.port = host_port_from_table(rd32le(row + 8));
      std::memcpy(r.raddr, row + 12, 4);
      r.rport = host_port_from_table(rd32le(row + 16));
      r.pid = rd32le(row + 20);
      r.state = static_cast<u8>(rd32le(row + 0) & 0xffu);
    } else {
      std::memcpy(r.addr, row, 16);
      r.port = host_port_from_table(rd32le(row + 20));
      std::memcpy(r.raddr, row + 24, 16);
      r.rport = host_port_from_table(rd32le(row + 44));
      r.state = static_cast<u8>(rd32le(row + 48) & 0xffu);
      r.pid = rd32le(row + 52);
    }
    out->push_back(r);
    off += row_size;
  }
  return true;
}

bool collect_udp(int ipver, std::vector<ProcEndpoint>* out, std::string* error) {
  const ULONG af = ipver == 6 ? ULONG(AF_INET6) : ULONG(AF_INET);
  DWORD size = 0;
  DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, af, kUdpOwnerPid, 0);
  if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
    if (error) *error = system_error_text("GetExtendedUdpTable", rc);
    return false;
  }
  std::vector<u8> buf(size ? size : 4, 0);
  rc = GetExtendedUdpTable(buf.data(), &size, FALSE, af, kUdpOwnerPid, 0);
  if (rc != NO_ERROR) {
    if (error) *error = system_error_text("GetExtendedUdpTable", rc);
    return false;
  }
  if (buf.size() < 4) return true;
  const u32 count = rd32le(buf.data());
  const std::size_t row_size = ipver == 4 ? 12 : 28;
  std::size_t off = 4;
  for (u32 i = 0; i < count; ++i) {
    if (off + row_size > buf.size()) break;
    const u8* row = buf.data() + off;
    ProcEndpoint r;
    r.family = ipver;
    r.proto = kProtoUdp;
    if (ipver == 4) {
      std::memcpy(r.addr, row, 4);
      r.port = host_port_from_table(rd32le(row + 4));
      r.pid = rd32le(row + 8);
    } else {
      std::memcpy(r.addr, row, 16);
      r.port = host_port_from_table(rd32le(row + 20));
      r.pid = rd32le(row + 24);
    }
    out->push_back(r);
    off += row_size;
  }
  return true;
}

// A protected or already-exited process cannot be opened.  That is a normal
// outcome, not a failure: the PID stays in the table and the report says
// "pid N" instead of inventing a name.
bool resolve_process(u32 pid, ProcessInfo* out) {
  out->pid = pid;
  if (pid == 0) {
    out->name = "System Idle Process";
    out->key = "system idle process";
    return true;
  }
  if (pid == 4) {
    out->name = "System";
    out->key = "system";
    return true;
  }
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!h) return false;
  wchar_t buf[4096];
  DWORD n = DWORD(sizeof(buf) / sizeof(buf[0]));
  if (QueryFullProcessImageNameW(h, 0, buf, &n)) {
    out->path = wide_to_utf8(buf);
    out->name = base_name(out->path);
    out->key = out->name;
    for (char& c : out->key) c = char(std::tolower(static_cast<unsigned char>(c)));
  }
  CloseHandle(h);
  return !out->name.empty();
}

}  // namespace

bool proc_collect_endpoints(std::vector<ProcEndpoint>* out, std::string* error) {
  out->clear();
  if (!collect_tcp(4, out, error)) return false;
  if (!collect_tcp(6, out, error)) return false;
  if (!collect_udp(4, out, error)) return false;
  if (!collect_udp(6, out, error)) return false;
  return true;
}

bool proc_resolve_process(u32 pid, ProcessInfo* out) { return resolve_process(pid, out); }

// One Toolhelp snapshot names every running process, including the ones that
// refuse OpenProcess.  A PID that has already exited is simply absent, which is
// how the caller learns that no name will ever be available for it.
bool proc_collect_process_names(std::map<u32, std::string>* out) {
  out->clear();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W e;
  std::memset(&e, 0, sizeof(e));
  e.dwSize = sizeof(e);
  if (Process32FirstW(snap, &e)) {
    do {
      (*out)[u32(e.th32ProcessID)] = wide_to_utf8(e.szExeFile);
    } while (Process32NextW(snap, &e));
  }
  CloseHandle(snap);
  return true;
}

bool proc_attribution_available(std::string* note) {
  if (note)
    *note =
        "GetExtendedTcpTable/GetExtendedUdpTable with the OWNER_PID table class "
        "(needs no elevation, but only a live capture has sockets to attribute)";
  return true;
}

std::string proc_platform_note() {
  return "Windows IP Helper endpoint tables (the same source as netstat -ano)";
}

}  // namespace netcap

#endif  // _WIN32
