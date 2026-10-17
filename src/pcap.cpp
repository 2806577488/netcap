#include "netcap/pcap.hpp"

#include <cerrno>
#include <cstring>

#include "netcap/common.hpp"

namespace netcap {

namespace {

constexpr std::uint32_t kMagicUsec = 0xa1b2c3d4u;
constexpr std::uint32_t kMagicNsec = 0xa1b23c4du;
constexpr std::uint32_t kMagicPcapng = 0x0a0d0d0au;

/// Refuse absurd record lengths before allocating (guards corrupt files).
constexpr std::uint32_t kMaxRecord = 64u * 1024u * 1024u;

std::string errno_string() {
  return std::string(std::strerror(errno));
}

std::FILE* open_stream(const std::string& path, bool writing, bool* owns, std::string* error) {
  if (path == "-") {
    *owns = false;
    return writing ? stdout : stdin;
  }
  *owns = true;
  std::FILE* f = std::fopen(path.c_str(), writing ? "wb" : "rb");
  if (!f && error) *error = "cannot open '" + path + "': " + errno_string();
  return f;
}

}  // namespace

// ---------------------------------------------------------------------------
// PcapWriter
// ---------------------------------------------------------------------------

PcapWriter::~PcapWriter() { close(); }

bool PcapWriter::open(const std::string& path, int linktype, std::uint32_t snaplen, bool nanosecond,
                      std::string* error) {
  close();
  bool owns = true;
  std::FILE* f = open_stream(path, true, &owns, error);
  if (!f) return false;
  file_ = f;
  owns_ = owns;
  nano_ = nanosecond;
  linktype_ = linktype;
  snaplen_ = snaplen ? snaplen : 262144;
  packets_ = 0;
  bytes_ = 0;

  u8 h[24];
  wr32le(h + 0, nano_ ? kMagicNsec : kMagicUsec);
  wr16le(h + 4, 2);
  wr16le(h + 6, 4);
  wr32le(h + 8, 0);   // thiszone
  wr32le(h + 12, 0);  // sigfigs
  wr32le(h + 16, snaplen_);
  wr32le(h + 20, std::uint32_t(linktype_));
  if (std::fwrite(h, 1, sizeof(h), file_) != sizeof(h)) {
    if (error) *error = "cannot write pcap header to '" + path + "': " + errno_string();
    close();
    return false;
  }
  return true;
}

bool PcapWriter::open_append(const std::string& path, int linktype, std::uint32_t snaplen,
                             bool nanosecond, std::string* error) {
  close();
  if (path.empty() || path == "-") {
    if (error) *error = "cannot append to '" + path + "'";
    return false;
  }
  bool have_data = false;
  if (std::FILE* probe = std::fopen(path.c_str(), "rb")) {
    if (std::fseek(probe, 0, SEEK_END) == 0) have_data = std::ftell(probe) > 0;
    std::fclose(probe);
  }
  if (!have_data) return open(path, linktype, snaplen, nanosecond, error);

  std::FILE* f = std::fopen(path.c_str(), "ab");
  if (!f) {
    if (error) *error = "cannot open '" + path + "': " + errno_string();
    return false;
  }
  file_ = f;
  owns_ = true;
  nano_ = nanosecond;
  linktype_ = linktype;
  snaplen_ = snaplen ? snaplen : 262144;
  packets_ = 0;
  bytes_ = 0;
  return true;
}

bool PcapWriter::write(const PacketView& pkt, std::string* error) {
  if (!file_) {
    if (error) *error = "pcap writer is not open";
    return false;
  }
  std::size_t incl = pkt.len;
  const bool truncated = incl > snaplen_;
  if (truncated) incl = snaplen_;

  const std::uint64_t sec = std::uint64_t(pkt.ts_us / 1000000);
  const std::uint64_t rem = std::uint64_t(pkt.ts_us % 1000000);
  const std::uint64_t frac = nano_ ? rem * 1000u : rem;

  u8 rh[16];
  wr32le(rh + 0, std::uint32_t(sec));
  wr32le(rh + 4, std::uint32_t(frac));
  wr32le(rh + 8, std::uint32_t(incl));
  wr32le(rh + 12, std::uint32_t(pkt.origlen ? pkt.origlen : pkt.len));

  if (std::fwrite(rh, 1, sizeof(rh), file_) != sizeof(rh) ||
      (incl && std::fwrite(pkt.data, 1, incl, file_) != incl)) {
    if (error) *error = "short write to pcap file: " + errno_string();
    return false;
  }
  ++packets_;
  bytes_ += sizeof(rh) + incl;
  return true;
}

bool PcapWriter::write(const Packet& pkt, std::string* error) { return write(pkt.view(), error); }

void PcapWriter::flush() {
  if (file_) std::fflush(file_);
}

void PcapWriter::close() {
  if (!file_) return;
  std::fflush(file_);
  if (owns_) std::fclose(file_);
  file_ = nullptr;
}

// ---------------------------------------------------------------------------
// PcapReader
// ---------------------------------------------------------------------------

PcapReader::~PcapReader() { close(); }

bool PcapReader::open(const std::string& path, std::string* error) {
  close();
  error_.clear();
  eof_ = false;
  bool owns = true;
  std::FILE* f = open_stream(path, false, &owns, error);
  if (!f) return false;
  file_ = f;
  owns_ = owns;

  u8 h[24];
  const std::size_t got = std::fread(h, 1, sizeof(h), file_);
  if (got != sizeof(h)) {
    if (error) {
      if (got == 0) *error = "'" + path + "' is empty";
      else *error = "'" + path + "' is too short to hold a pcap header";
    }
    close();
    return false;
  }

  const std::uint32_t le = rd32le(h);
  const std::uint32_t be = rd32be(h);
  if (le == kMagicUsec) {
    big_endian_ = false;
    nano_ = false;
  } else if (le == kMagicNsec) {
    big_endian_ = false;
    nano_ = true;
  } else if (be == kMagicUsec) {
    big_endian_ = true;
    nano_ = false;
  } else if (be == kMagicNsec) {
    big_endian_ = true;
    nano_ = true;
  } else if (le == kMagicPcapng || be == kMagicPcapng) {
    if (error) {
      *error =
          "'" + path +
          "' is a pcapng file; this reader implements the classic pcap format only.\n"
          "Convert it first:  editcap -F pcap in.pcapng out.pcap";
    }
    close();
    return false;
  } else {
    if (error) *error = "'" + path + "' is not a pcap file (bad magic)";
    close();
    return false;
  }

  version_major_ = big_endian_ ? rd16be(h + 4) : rd16le(h + 4);
  version_minor_ = big_endian_ ? rd16be(h + 6) : rd16le(h + 6);
  snaplen_ = big_endian_ ? rd32be(h + 16) : rd32le(h + 16);
  linktype_ = int(big_endian_ ? rd32be(h + 20) : rd32le(h + 20));
  packets_ = 0;
  return true;
}

bool PcapReader::next(Packet& out) {
  if (!file_ || eof_) return false;
  u8 rh[16];
  const std::size_t got = std::fread(rh, 1, sizeof(rh), file_);
  if (got == 0) {
    eof_ = true;
    return false;
  }
  if (got != sizeof(rh)) {
    error_ = "truncated pcap record header";
    eof_ = true;
    return false;
  }
  const std::uint32_t ts_sec = big_endian_ ? rd32be(rh + 0) : rd32le(rh + 0);
  const std::uint32_t ts_frac = big_endian_ ? rd32be(rh + 4) : rd32le(rh + 4);
  const std::uint32_t incl = big_endian_ ? rd32be(rh + 8) : rd32le(rh + 8);
  const std::uint32_t orig = big_endian_ ? rd32be(rh + 12) : rd32le(rh + 12);

  if (incl > kMaxRecord) {
    error_ = "implausible pcap record length (" + std::to_string(incl) + " bytes)";
    eof_ = true;
    return false;
  }

  out.data.resize(incl);
  if (incl && std::fread(out.data.data(), 1, incl, file_) != incl) {
    error_ = "truncated pcap packet data";
    eof_ = true;
    return false;
  }
  out.origlen = orig ? std::size_t(orig) : std::size_t(incl);
  out.ts_us = i64(ts_sec) * 1000000 + (nano_ ? i64(ts_frac) / 1000 : i64(ts_frac));
  out.linktype = linktype_;
  out.ifindex = 0;
  ++packets_;
  return true;
}

void PcapReader::close() {
  if (!file_) return;
  if (owns_) std::fclose(file_);
  file_ = nullptr;
}

}  // namespace netcap
