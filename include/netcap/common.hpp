// netcap - low-level network traffic capture toolkit
// common.hpp: primitive types, unaligned endian readers, address/format helpers.
//
// Everything here is dependency-free (no libpcap, no external libraries) so the
// toolchain only needs a C++17 compiler and the platform sockets API.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace netcap {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i64 = std::int64_t;

// ---------------------------------------------------------------------------
// Unaligned-safe integer readers/writers (network = big endian).
// Deliberately byte-wise: packet buffers are frequently unaligned and casting
// to a struct pointer would be undefined behaviour on strict-alignment targets.
// ---------------------------------------------------------------------------
inline u16 rd16be(const u8* p) noexcept { return u16((u16(p[0]) << 8) | u16(p[1])); }
inline u16 rd16le(const u8* p) noexcept { return u16((u16(p[1]) << 8) | u16(p[0])); }
inline u32 rd24be(const u8* p) noexcept { return (u32(p[0]) << 16) | (u32(p[1]) << 8) | u32(p[2]); }
inline u32 rd32be(const u8* p) noexcept {
  return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}
inline u32 rd32le(const u8* p) noexcept {
  return (u32(p[3]) << 24) | (u32(p[2]) << 16) | (u32(p[1]) << 8) | u32(p[0]);
}

inline void wr16be(u8* p, u16 v) noexcept { p[0] = u8(v >> 8); p[1] = u8(v); }
inline void wr16le(u8* p, u16 v) noexcept { p[1] = u8(v >> 8); p[0] = u8(v); }
inline void wr24be(u8* p, u32 v) noexcept { p[0] = u8(v >> 16); p[1] = u8(v >> 8); p[2] = u8(v); }
inline void wr32be(u8* p, u32 v) noexcept {
  p[0] = u8(v >> 24); p[1] = u8(v >> 16); p[2] = u8(v >> 8); p[3] = u8(v);
}
inline void wr32le(u8* p, u32 v) noexcept {
  p[3] = u8(v >> 24); p[2] = u8(v >> 16); p[1] = u8(v >> 8); p[0] = u8(v);
}

inline void wr64be(u8* p, u64 v) noexcept { wr32be(p, u32(v >> 32)); wr32be(p + 4, u32(v)); }
inline u64 rd64be(const u8* p) noexcept { return (u64(rd32be(p)) << 32) | u64(rd32be(p + 4)); }

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Microseconds since the Unix epoch (wall clock).
i64 now_unix_us() noexcept;

/// Monotonic microseconds, used for timeouts and rate accounting.
i64 now_monotonic_us() noexcept;

/// "HH:MM:SS.uuuuuu" in UTC.
std::string format_time_us(i64 ts_us);
/// "YYYY-MM-DD HH:MM:SS" in UTC.
std::string format_datetime_us(i64 ts_us);

// ---------------------------------------------------------------------------
// Address formatting / parsing
// ---------------------------------------------------------------------------

std::string format_mac(const u8* mac6);
std::string format_ipv4(u32 addr_be);
/// RFC 5952 canonical text form (longest zero run compressed to "::", lowercase).
std::string format_ipv6(const u8* addr16);
/// `version` is 4 or 6; returns "?" when version is neither.
std::string format_ip(int version, const u8* addr);

/// Parses dotted quad into a big-endian u32 (o1<<24 | o2<<16 | o3<<8 | o4).
bool parse_ipv4(const std::string& s, u32* out_be);
/// Parses IPv6 text, including "::" compression, a trailing embedded IPv4 and
/// a "%zone" suffix (the zone is ignored). Writes 16 bytes in network order.
bool parse_ipv6(const std::string& s, u8 out16[16]);
/// Accepts either family into a 16-byte network-order buffer; v4 lands in [0,4).
bool parse_ip(const std::string& s, int* version, u8 out16[16]);
/// "a.b.c.d/n" or "x::y/n". `bits` defaults to the family width when omitted.
bool parse_cidr(const std::string& s, int* version, u8 out16[16], int* bits);

/// True when `addr` (16-byte form for the given version) falls inside prefix/bits.
bool cidr_match(int version, const u8* addr, const u8* prefix, int bits);

// ---------------------------------------------------------------------------
// Small string helpers
// ---------------------------------------------------------------------------

std::string to_lower(std::string s);
bool iequals(const std::string& a, const std::string& b);
/// Case-insensitive substring search; `needle` must be lowercase.
bool icontains_lower(const char* hay, const char* lower_needle);
bool icontains(const std::string& hay, const std::string& needle);

/// tcpdump-style hex+ASCII dump. `max_bytes == 0` means "everything".
std::string hexdump(const u8* data, std::size_t len, std::size_t max_bytes, const std::string& indent);

/// IANA service name for a port, or "" when unknown.
const char* service_name(u16 port, u8 ip_proto);
/// "S", ".", "S.", "P.", "F.", ... (tcpdump ordering: FSRPAUEC).
std::string tcp_flags_str(u8 flags);
const char* ip_proto_name(u8 proto);
const char* icmp_type_name(u8 type);
const char* icmpv6_type_name(u8 type);
const char* dns_type_name(u16 t);
const char* tls_version_name(u16 v);

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// RFC 1071 Internet checksum over big-endian 16-bit words. `init` may carry a
/// pseudo-header partial sum (already folded); returns the value to store.
u16 internet_checksum(const u8* data, std::size_t len, u32 init = 0);
/// One's-complement fold of a partial sum.
u16 checksum_fold(u32 sum) noexcept;

}  // namespace netcap
