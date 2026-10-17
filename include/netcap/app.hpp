// netcap - app.hpp
// Application-layer extraction: HTTP/1.x, TLS ClientHello (SNI/ALPN), DNS.
//
// These parsers are deliberately defensive: they work on a single captured
// segment, never trust a length field without bounds-checking it, and simply
// fail (returning false) rather than attempting to "fix up" a truncated frame.
// That means a flow that spans several segments may only be partially decoded,
// which is the honest behaviour for a stateless segment-level sniffer.
#pragma once

#include "netcap/dissect.hpp"

namespace netcap {

struct HttpInfo {
  bool is_request = false;
  bool is_response = false;
  bool http2_preface = false;
  char method[16]{};
  char uri[512]{};
  int status = 0;
  char reason[64]{};
  int version_major = 1;
  int version_minor = 1;
  char host[256]{};
  char user_agent[256]{};
  char content_type[128]{};
  char server[128]{};
  char upgrade[64]{};
  char accept_encoding[64]{};
  bool has_content_length = false;
  u64 content_length = 0;
  bool chunked = false;
  bool connection_close = false;
  int header_count = 0;
  std::size_t body_offset = 0;  ///< payload offset where the body starts
};

struct TlsInfo {
  bool is_record = false;
  u8 record_type = 0;      // 20 CCS, 21 alert, 22 handshake, 23 app data
  u16 record_version = 0;
  u16 record_length = 0;
  bool is_client_hello = false;
  u16 client_version = 0;
  char sni[256]{};
  char alpn[128]{};        // comma-separated protocols
  u16 cipher_count = 0;
  u8 compression_count = 0;
  bool has_extensions = false;
  bool has_supported_versions = false;
  u16 supported_version = 0;
};

struct DnsInfo {
  bool valid = false;
  bool is_response = false;
  u8 opcode = 0;
  u8 rcode = 0;
  bool truncated = false;
  u16 qdcount = 0;
  u16 ancount = 0;
  char qname[256]{};
  u16 qtype = 0;
  u16 qclass = 0;
};

/// Everything the app layer could say about one payload.
struct AppInfo {
  AppKind kind = AppKind::Unknown;
  bool detected = false;
  HttpInfo http{};
  TlsInfo tls{};
  DnsInfo dns{};
  const char* note = nullptr;
};

/// Classifies and parses the payload. Never throws; unknown payloads simply
/// leave `detected == false`.
AppKind classify_app(const PacketInfo& pi, AppInfo& out);

bool parse_http(const u8* p, std::size_t len, HttpInfo& out);
bool parse_tls(const u8* p, std::size_t len, TlsInfo& out);
bool parse_dns(const u8* p, std::size_t len, DnsInfo& out);

/// The name a user would filter on: HTTP Host, else TLS SNI, else DNS qname.
/// Returns "" when none was extracted. Pointer is owned by `a`.
const char* app_hostname(const AppInfo& a);

/// Payload bytes the app layer considers "content" (HTTP body offset etc.).
std::size_t http_body_offset(const HttpInfo& h);

}  // namespace netcap
