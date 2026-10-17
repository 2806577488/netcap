// Platform half of interception: the two destructive calls netcap can make.
//
//  * cut   SetTcpEntry(MIB_TCPROW{dwState = MIB_TCP_STATE_DELETE_TCB}) -- asks
//          the TCP stack to tear the connection down.  IPv4 only: there is no
//          IPv6 equivalent, so an IPv6 flow is reported, not silently ignored.
//          Needs Administrator; without it the call fails with access denied,
//          which is reported verbatim rather than swallowed.
//  * kill  OpenProcess(PROCESS_TERMINATE) + TerminateProcess.
//
// Blocking *by image path* (the "never let this program talk to the network"
// case) cannot be done with these APIs: it needs a Windows Filtering Platform
// filter, which is a separate, larger piece of work -- block_platform_note()
// says so instead of pretending otherwise.
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

#include <cstdio>
#include <cstring>
#include <string>

#include "netcap/block.hpp"
#include "netcap/common.hpp"

// Spelled out so headers that predate the value still compile.
#ifndef MIB_TCP_STATE_DELETE_TCB
#define MIB_TCP_STATE_DELETE_TCB 12
#endif

namespace netcap {

namespace {

std::string win_error_text(const char* what, unsigned long code) {
  // FormatMessageA would hand back text in the console's ANSI code page; netcap
  // prints UTF-8, so ask the wide API and convert.
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
  // A "message not found" template still carries %1/%2 placeholders; the numeric
  // code below is more useful than a half-substituted sentence.
  if (text.find('%') != std::string::npos) text.clear();
  std::string out = what;
  out += " failed";
  if (!text.empty()) {
    out += ": ";
    out += text;
  }
  char buf[48];
  std::snprintf(buf, sizeof(buf), " (Win32 error %lu)", code);
  out += buf;
  return out;
}

// MIB_TCPROW carries addresses in network byte order and the port in the low
// 16 bits, also network order -- exactly what the endpoint table returns.
bool cut_one(u32 local_addr, u16 local_port, u32 remote_addr, u16 remote_port,
             std::string* error) {
  MIB_TCPROW row;
  std::memset(&row, 0, sizeof(row));
  row.dwState = MIB_TCP_STATE_DELETE_TCB;
  row.dwLocalAddr = local_addr;
  row.dwLocalPort = u32(htons(local_port));
  row.dwRemoteAddr = remote_addr;
  row.dwRemotePort = u32(htons(remote_port));
  const DWORD rc = SetTcpEntry(&row);
  if (rc == NO_ERROR) return true;
  if (error) *error = win_error_text("SetTcpEntry", rc);
  return false;
}

}  // namespace

bool block_platform_available(std::string* note) {
  if (note)
    *note =
        "Windows SetTcpEntry (MIB_TCP_STATE_DELETE_TCB) for cutting a TCP connection and "
        "TerminateProcess for killing its owner; both need Administrator";
  return true;
}

std::string block_platform_note() {
  return "Windows SetTcpEntry / TerminateProcess (Administrator required; IPv4 only for cuts)";
}

bool block_cut_tcp(const PacketInfo& pi, int outbound, std::string* error) {
  if (pi.ip_version != 4) {
    if (error)
      *error = "SetTcpEntry only understands IPv4; an IPv6 connection cannot be cut this way";
    return false;
  }
  const u32 s = rd32be(pi.src_ip);
  const u32 d = rd32be(pi.dst_ip);
  std::string first;
  if (outbound != 0) {  // unknown or outbound: local side is the source
    if (cut_one(s, pi.src_port, d, pi.dst_port, &first)) return true;
  }
  if (outbound != 1) {  // unknown or inbound: local side is the destination
    std::string second;
    if (cut_one(d, pi.dst_port, s, pi.src_port, &second)) return true;
    if (first.empty()) first = second;
  }
  if (error) *error = first.empty() ? "SetTcpEntry was not attempted" : first;
  return false;
}

bool block_kill_process(u32 pid, std::string* error) {
  if (pid == 0 || pid == 4) {
    if (error) *error = "refusing to terminate a system process";
    return false;
  }
  HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (!h) {
    if (error) *error = win_error_text("OpenProcess(PROCESS_TERMINATE)", GetLastError());
    return false;
  }
  const BOOL ok = TerminateProcess(h, 1);
  const DWORD code = ok ? 0 : GetLastError();
  CloseHandle(h);
  if (!ok) {
    if (error) *error = win_error_text("TerminateProcess", code);
    return false;
  }
  return true;
}

}  // namespace netcap

#else

#include "netcap/block.hpp"

namespace netcap {

bool block_platform_available(std::string* note) {
  if (note) *note = "interception is only implemented on Windows in this build";
  return false;
}

std::string block_platform_note() { return "not available on this platform"; }

bool block_cut_tcp(const PacketInfo&, int, std::string* error) {
  if (error) *error = "cutting a TCP connection is only implemented on Windows (SetTcpEntry)";
  return false;
}

bool block_kill_process(u32, std::string* error) {
  if (error) *error = "terminating a process is only implemented on Windows";
  return false;
}

}  // namespace netcap

#endif  // _WIN32
