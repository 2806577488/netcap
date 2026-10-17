// Self-contained libpcap *file format* reader/writer.
//
// This implements the pcap savefile format directly (classic 24-byte global
// header + 16-byte per-record header) so that the tool has no dependency on
// libpcap for offline analysis, and so that captures can be handed to
// Wireshark/tcpdump afterwards.  Both byte orders and both timestamp
// resolutions (microsecond and nanosecond) are understood on read; files are
// written little-endian.
//
// pcapng is intentionally NOT implemented: the reader detects its magic and
// tells the user how to convert.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

#include "netcap/packet.hpp"

namespace netcap {

/// Classic pcap global header (24 bytes on disk).
struct PcapFileHeader {
  std::uint32_t magic = 0xa1b2c3d4u;  ///< 0xa1b2c3d4 usec, 0xa1b23c4d nsec
  std::uint16_t version_major = 2;
  std::uint16_t version_minor = 4;
  std::int32_t thiszone = 0;
  std::uint32_t sigfigs = 0;
  std::uint32_t snaplen = 262144;
  std::uint32_t network = DLT_EN10MB;
};

/// Writes pcap savefiles.  Use "-" as the path to write to stdout.
class PcapWriter {
 public:
  PcapWriter() = default;
  ~PcapWriter();
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;

  /// nanosecond selects the 0xa1b23c4d magic.
  bool open(const std::string& path, int linktype, std::uint32_t snaplen = 262144,
            bool nanosecond = false, std::string* error = nullptr);
  /// Continues an existing file instead of truncating it: the global header is
  /// only written when the file is missing or empty, and the record counter
  /// restarts (it counts this session, not the file's lifetime).
  bool open_append(const std::string& path, int linktype, std::uint32_t snaplen = 262144,
                   bool nanosecond = false, std::string* error = nullptr);
  bool write(const PacketView& pkt, std::string* error = nullptr);
  bool write(const Packet& pkt, std::string* error = nullptr);
  void flush();
  void close();

  bool is_open() const { return file_ != nullptr; }
  int linktype() const { return linktype_; }
  std::uint64_t packets_written() const { return packets_; }
  std::uint64_t bytes_written() const { return bytes_; }

 private:
  std::FILE* file_ = nullptr;
  bool owns_ = true;
  bool nano_ = false;
  int linktype_ = DLT_EN10MB;
  std::uint32_t snaplen_ = 262144;
  std::uint64_t packets_ = 0;
  std::uint64_t bytes_ = 0;
};

/// Reads pcap savefiles.  Use "-" as the path to read from stdin.
class PcapReader {
 public:
  PcapReader() = default;
  ~PcapReader();
  PcapReader(const PcapReader&) = delete;
  PcapReader& operator=(const PcapReader&) = delete;

  bool open(const std::string& path, std::string* error = nullptr);
  /// Reads the next record into `out`.  Returns false at EOF and on error;
  /// distinguish the two with eof()/error().
  bool next(Packet& out);
  void close();

  bool eof() const { return eof_; }
  bool failed() const { return !error_.empty(); }
  const std::string& error() const { return error_; }
  int linktype() const { return linktype_; }
  std::uint32_t snaplen() const { return snaplen_; }
  bool nanosecond() const { return nano_; }
  bool big_endian() const { return big_endian_; }
  std::uint16_t version_major() const { return version_major_; }
  std::uint16_t version_minor() const { return version_minor_; }
  std::uint64_t packets_read() const { return packets_; }

 private:
  std::FILE* file_ = nullptr;
  bool owns_ = true;
  bool big_endian_ = false;
  bool nano_ = false;
  bool eof_ = false;
  int linktype_ = DLT_EN10MB;
  std::uint32_t snaplen_ = 0;
  std::uint16_t version_major_ = 0;
  std::uint16_t version_minor_ = 0;
  std::uint64_t packets_ = 0;
  std::string error_;
};

}  // namespace netcap
