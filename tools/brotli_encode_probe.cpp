// Exercises the Brotli encoder: round-trips it against our own decoder, cross-checks
// the streams with python-brotli, and reports sizes so the encoder can be compared
// with the reference implementation.
//
// Usage:
//   brotli_encode_probe --roundtrip <file> [quality]
//   brotli_encode_probe --encode <in> <out.br> [quality]
//   brotli_encode_probe --roundtrip <f> [q] --limit <n>
//   brotli_encode_probe --roundtrip <f> [q] --target <n>
//   brotli_encode_probe --selfcheck
//   brotli_encode_probe --corpus <file> [file...]
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "netcap/brotli.hpp"
#include "netcap/brotli_encode.hpp"

namespace {

using netcap::u32;
using netcap::u64;

bool read_file(const std::string& path, std::string* out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  out->assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return true;
}

bool write_file(const std::string& path, const std::string& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) return false;
  out.write(data.data(), static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(out);
}

bool make_dirs(const std::string& relative) {
  std::string cmd = "cmd /c mkdir \"" + relative + "\" >nul 2>nul";
  return std::system(cmd.c_str()) == 0;
}

// ---------------------------------------------------------------------------
// SHA-256, so the probe can print the digest of what it wrote and read back
// ---------------------------------------------------------------------------
class Sha256 {
 public:
  Sha256() { reset(); }

  void reset() {
    h_[0] = 0x6a09e667u;
    h_[1] = 0xbb67ae85u;
    h_[2] = 0x3c6ef372u;
    h_[3] = 0xa54ff53au;
    h_[4] = 0x510e527fu;
    h_[5] = 0x9b05688cu;
    h_[6] = 0x1f83d9abu;
    h_[7] = 0x5be0cd19u;
    len_ = 0;
    fill_ = 0;
  }

  void update(const void* data, std::size_t n) {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    len_ += n;
    while (n > 0) {
      const std::size_t take = std::min<std::size_t>(n, 64 - fill_);
      std::memcpy(buf_ + fill_, p, take);
      fill_ += take;
      p += take;
      n -= take;
      if (fill_ == 64) {
        block(buf_);
        fill_ = 0;
      }
    }
  }

  std::string hex() {
    const u64 bits = len_ * 8;
    // Padding goes in through `raw`, which never touches `len_`, so the length field
    // stays the message length instead of the padded length.
    const unsigned char pad = 0x80;
    raw(&pad, 1);
    const unsigned char zero = 0;
    while (fill_ != 56) raw(&zero, 1);
    unsigned char tail[8];
    for (int i = 0; i < 8; ++i) tail[i] = static_cast<unsigned char>((bits >> (8 * (7 - i))) & 0xff);
    raw(tail, 8);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 8; ++i) {
      for (int b = 3; b >= 0; --b) {
        const unsigned char byte = static_cast<unsigned char>((h_[i] >> (8 * b)) & 0xff);
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0xf]);
      }
    }
    return out;
  }

 private:
  static u32 rotr(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

  void raw(const unsigned char* p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
      buf_[fill_++] = p[i];
      if (fill_ == 64) {
        block(buf_);
        fill_ = 0;
      }
    }
  }

  void block(const unsigned char* p) {
    static const u32 k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
        0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
        0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
        0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
        0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
        0xc67178f2u};
    u32 w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = (static_cast<u32>(p[4 * i]) << 24) | (static_cast<u32>(p[4 * i + 1]) << 16) |
             (static_cast<u32>(p[4 * i + 2]) << 8) | static_cast<u32>(p[4 * i + 3]);
    }
    for (int i = 16; i < 64; ++i) {
      const u32 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const u32 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    u32 e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
    for (int i = 0; i < 64; ++i) {
      const u32 s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const u32 ch = (e & f) ^ (~e & g);
      const u32 t1 = hh + s1 + ch + k[i] + w[i];
      const u32 s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const u32 maj = (a & b) ^ (a & c) ^ (b & c);
      const u32 t2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
    h_[5] += f;
    h_[6] += g;
    h_[7] += hh;
  }

  u32 h_[8];
  u64 len_ = 0;
  std::size_t fill_ = 0;
  unsigned char buf_[64] = {};
};

std::string sha256_hex(const std::string& data) {
  Sha256 s;
  s.update(data.data(), data.size());
  return s.hex();
}

// ---------------------------------------------------------------------------
// python-brotli, used only as an external oracle
// ---------------------------------------------------------------------------

// Returns the decompressed bytes python-brotli produced, or an empty string with
// `error` set.  An empty input decompresses to an empty string, so callers must look
// at `ok` rather than at the size.
bool python_decompress(const std::string& br_path, const std::string& out_path) {
  const std::string cmd =
      "python -c \"import brotli,sys; d=brotli.decompress(open(sys.argv[1],'rb').read()); "
      "open(sys.argv[2],'wb').write(d)\" \"" +
      br_path + "\" \"" + out_path + "\"";
  return std::system(cmd.c_str()) == 0;
}

// `python -c "import brotli,sys; sys.stdout.write(str(len(brotli.compress(...))))"`,
// returning -1 when python or the module is unavailable.
long python_compress_size(const std::string& in_path, int quality) {
  const std::string tmp = "_br/enc_probe_pycheck.br";
  const std::string cmd =
      "python -c \"import brotli,sys; d=open(sys.argv[1],'rb').read(); "
      "open(sys.argv[2],'wb').write(brotli.compress(d, quality=int(sys.argv[3]))); "
      "sys.stdout.write(str(len(open(sys.argv[2],'rb').read())))\" \"" +
      in_path + "\" \"" + tmp + "\" " + std::to_string(quality) + " > _br/enc_probe_pysize.txt 2>nul";
  if (std::system(cmd.c_str()) != 0) return -1;
  std::string text;
  if (!read_file("_br/enc_probe_pysize.txt", &text)) return -1;
  if (text.empty()) return -1;
  return std::strtol(text.c_str(), nullptr, 10);
}

void print_hex_diff(const std::string& a, const std::string& b, std::size_t limit = 24) {
  const std::size_t n = std::min(a.size(), b.size());
  std::size_t shown = 0;
  for (std::size_t i = 0; i < n && shown < limit; ++i) {
    if (a[i] != b[i]) {
      std::printf("    first difference at byte %zu: got 0x%02x, want 0x%02x\n", i,
                  static_cast<unsigned char>(a[i]), static_cast<unsigned char>(b[i]));
      ++shown;
      break;
    }
  }
  if (shown == 0 && a.size() != b.size())
    std::printf("    sizes differ: got %zu, want %zu\n", a.size(), b.size());
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

struct RoundTripResult {
  bool ok = false;
  std::string out;
  std::string error;
  std::size_t limit = 0;
  std::size_t target = 0;
};

RoundTripResult encode_and_check(const std::string& in, const netcap::BrotliEncoderOptions& opts,
                                 bool expect_failure) {
  RoundTripResult r;
  r.limit = opts.limit;
  r.target = opts.target_size;
  std::string out;
  std::string error;
  const bool encoded = netcap::brotli_encode(in, &out, &error, opts);
  if (expect_failure) {
    if (encoded) {
      r.error = "expected the encoder to refuse, but it returned " + std::to_string(out.size()) +
                " bytes";
      return r;
    }
    r.ok = true;
    r.error = error;
    return r;
  }
  if (!encoded) {
    r.error = "brotli_encode failed: " + error;
    return r;
  }
  std::string decoded;
  std::string derror;
  if (!netcap::brotli_decompress(reinterpret_cast<const netcap::u8*>(out.data()), out.size(),
                                 &decoded, &derror)) {
    r.error = "brotli_decompress failed: " + derror;
    std::printf("  stream rejected by our decoder (%zu bytes)\n", out.size());
    return r;
  }
  if (decoded != in) {
    r.error = "round-trip mismatch";
    std::printf("  round-trip mismatch: input %zu, decoded %zu\n", in.size(), decoded.size());
    print_hex_diff(decoded, in);
    return r;
  }
  r.ok = true;
  r.out = std::move(out);
  return r;
}

int cmd_roundtrip(const std::string& path, int quality, std::size_t limit, std::size_t target) {
  std::string in;
  if (!read_file(path, &in)) {
    std::fprintf(stderr, "cannot read %s\n", path.c_str());
    return 2;
  }
  netcap::BrotliEncoderOptions opts;
  opts.quality = quality;
  opts.limit = limit;
  opts.target_size = target;

  std::printf("input      : %s\n", path.c_str());
  std::printf("input size : %zu bytes\n", in.size());
  std::printf("quality    : %d\n", quality);
  if (limit != 0) std::printf("limit      : %zu\n", limit);
  if (target != 0) std::printf("target     : %zu\n", target);

  RoundTripResult r = encode_and_check(in, opts, false);
  if (!r.ok) {
    std::printf("RESULT     : FAIL (%s)\n", r.error.c_str());
    return 1;
  }

  std::printf("output size: %zu bytes (%.2f%% of input)\n", r.out.size(),
              100.0 * static_cast<double>(r.out.size()) / static_cast<double>(in.size() ? in.size() : 1));
  std::printf("in  sha256 : %s\n", sha256_hex(in).c_str());
  std::printf("out sha256 : %s\n", sha256_hex(r.out).c_str());
  if (target != 0 && r.out.size() != target) {
    std::printf("RESULT     : FAIL (target %zu but produced %zu)\n", target, r.out.size());
    return 1;
  }

  // Cross-check with the external oracle: it must decode our stream to the same bytes.
  make_dirs("_br");
  const std::string br = "_br/enc_probe_rt.br";
  const std::string back = "_br/enc_probe_rt.dec";
  if (!write_file(br, r.out)) {
    std::printf("RESULT     : FAIL (cannot write %s)\n", br.c_str());
    return 1;
  }
  if (!python_decompress(br, back)) {
    std::printf("python     : SKIPPED (python-brotli unavailable or rejected the stream)\n");
    std::printf("RESULT     : PASS (our decoder only)\n");
    return 0;
  }
  std::string py;
  if (!read_file(back, &py)) {
    std::printf("python     : FAIL (python wrote nothing)\n");
    return 1;
  }
  if (py != in) {
    std::printf("python     : FAIL (decoded %zu bytes, expected %zu)\n", py.size(), in.size());
    print_hex_diff(py, in);
    return 1;
  }
  std::printf("python     : OK (python-brotli decoded %zu bytes)\n", py.size());
  std::printf("RESULT     : PASS\n");
  return 0;
}

int cmd_encode(const std::string& in_path, const std::string& out_path, int quality,
               std::size_t limit, std::size_t target) {
  std::string in;
  if (!read_file(in_path, &in)) {
    std::fprintf(stderr, "cannot read %s\n", in_path.c_str());
    return 2;
  }
  netcap::BrotliEncoderOptions opts;
  opts.quality = quality;
  opts.limit = limit;
  opts.target_size = target;
  std::string out;
  std::string error;
  if (!netcap::brotli_encode(in, &out, &error, opts)) {
    std::fprintf(stderr, "brotli_encode failed: %s\n", error.c_str());
    return 1;
  }
  if (!write_file(out_path, out)) {
    std::fprintf(stderr, "cannot write %s\n", out_path.c_str());
    return 2;
  }
  std::printf("%s: %zu -> %zu bytes (quality %d)\n", out_path.c_str(), in.size(), out.size(),
              quality);
  return 0;
}

int cmd_selfcheck() {
  std::string report;
  const bool ok = netcap::brotli_encode_selfcheck(&report);
  std::fputs(report.c_str(), stdout);
  return ok ? 0 : 1;
}

int cmd_corpus(const std::vector<std::string>& files) {
  make_dirs("_br");
  const std::string out = "_br/enc_probe_corpus.br";
  std::printf("%-34s %10s %10s %10s %8s %s\n", "file", "input", "ours(q5)", "python(q5)", "ratio",
              "verdict");
  int failures = 0;
  for (const std::string& path : files) {
    std::string in;
    if (!read_file(path, &in)) {
      std::printf("%-34s %10s %10s %10s %8s %s\n", path.c_str(), "-", "-", "-", "-", "UNREADABLE");
      ++failures;
      continue;
    }
    netcap::BrotliEncoderOptions opts;
    opts.quality = 5;
    RoundTripResult r = encode_and_check(in, opts, false);
    if (!r.ok) {
      std::printf("%-34s %10zu %10s %10s %8s %s\n", path.c_str(), in.size(), "-", "-", "-",
                  ("FAIL: " + r.error).c_str());
      ++failures;
      continue;
    }
    const long py = python_compress_size(path, 5);
    bool oracle_ok = true;
    if (py >= 0) {
      if (!write_file(out, r.out)) {
        oracle_ok = false;
      } else if (!python_decompress(out, "_br/enc_probe_corpus.dec")) {
        oracle_ok = false;
      } else {
        std::string back;
        oracle_ok = read_file("_br/enc_probe_corpus.dec", &back) && back == in;
      }
    }
    const double ratio =
        in.empty() ? 1.0 : static_cast<double>(r.out.size()) / static_cast<double>(in.size());
    char ours[32];
    char pysize[32];
    char ratiobuf[32];
    std::snprintf(ours, sizeof(ours), "%zu", r.out.size());
    if (py < 0)
      std::snprintf(pysize, sizeof(pysize), "n/a");
    else
      std::snprintf(pysize, sizeof(pysize), "%ld", py);
    std::snprintf(ratiobuf, sizeof(ratiobuf), "%.3f", ratio);
    std::printf("%-34s %10zu %10s %10s %8s %s\n", path.c_str(), in.size(), ours, pysize, ratiobuf,
                oracle_ok ? "ok" : "python-reject");
    if (!oracle_ok) ++failures;
  }
  std::printf("\n%d file(s), %d failure(s)\n", static_cast<int>(files.size()), failures);
  return failures == 0 ? 0 : 1;
}

void usage() {
  std::fprintf(stderr,
               "usage:\n"
               "  brotli_encode_probe --roundtrip <file> [quality]\n"
               "  brotli_encode_probe --encode <in> <out.br> [quality]\n"
               "  brotli_encode_probe --selfcheck\n"
               "  brotli_encode_probe --corpus <file> [file...]\n"
               "options (place after a command):\n"
               "  --limit <n>    fail instead of producing more than n bytes\n"
               "  --target <n>   produce exactly n bytes\n");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string command = argv[1];
  std::vector<std::string> positionals;
  int quality = 5;
  std::size_t limit = 0;
  std::size_t target = 0;
  bool have_quality = false;

  for (int i = 2; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--limit") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "--limit needs a value\n");
        return 2;
      }
      limit = std::strtoull(argv[++i], nullptr, 10);
    } else if (arg == "--target") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "--target needs a value\n");
        return 2;
      }
      target = std::strtoull(argv[++i], nullptr, 10);
    } else {
      // A bare number after the input file is the quality.
      const bool numeric =
          !arg.empty() && arg.find_first_not_of("0123456789") == std::string::npos;
      if (numeric && !positionals.empty() && !have_quality && command != "--corpus") {
        quality = std::atoi(arg.c_str());
        have_quality = true;
      } else if (numeric && positionals.empty() && command == "--roundtrip") {
        quality = std::atoi(arg.c_str());
        have_quality = true;
      } else {
        positionals.push_back(arg);
      }
    }
  }

  if (command == "--selfcheck") {
    if (!positionals.empty()) {
      usage();
      return 2;
    }
    return cmd_selfcheck();
  }
  if (command == "--corpus") {
    if (positionals.empty()) {
      usage();
      return 2;
    }
    return cmd_corpus(positionals);
  }
  if (command == "--roundtrip") {
    if (positionals.size() != 1) {
      usage();
      return 2;
    }
    return cmd_roundtrip(positionals[0], quality, limit, target);
  }
  if (command == "--encode") {
    if (positionals.size() != 2) {
      usage();
      return 2;
    }
    return cmd_encode(positionals[0], positionals[1], quality, limit, target);
  }
  usage();
  return 2;
}
