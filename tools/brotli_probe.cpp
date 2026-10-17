// Cross-checks the Brotli decoder against vectors produced by libbrotli
// (python -c "import brotli" or the brotli CLI).
//
// Usage:  brotli_probe <file.br> [file.expected]
// With the second argument it also compares the decoded bytes with that file.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include "netcap/brotli.hpp"

namespace {

bool read_file(const std::string& path, std::string* out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  out->assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: brotli_probe <file.br> [file.expected]\n"
                 "       brotli_probe --store <file.in> <file.br>\n");
    return 2;
  }

  // The stored encoder, so libbrotli (python -c "import brotli") can be asked
  // whether it accepts what we write.
  if (std::string(argv[1]) == "--store") {
    if (argc < 4) {
      std::fprintf(stderr, "usage: brotli_probe --store <file.in> <file.br>\n");
      return 2;
    }
    std::string raw;
    if (!read_file(argv[2], &raw)) {
      std::fprintf(stderr, "cannot read %s\n", argv[2]);
      return 2;
    }
    std::string packed;
    std::string why;
    const bool built = netcap::brotli_compress_stored(
        reinterpret_cast<const netcap::u8*>(raw.data()), raw.size(), &packed, &why);
    std::printf("stored   : %s, %zu bytes in -> %zu bytes out (predicted %zu)\n",
                built ? "ok" : "FAILED", raw.size(), packed.size(),
                netcap::brotli_stored_size(raw.size()));
    if (!built) {
      std::printf("reason   : %s\n", why.c_str());
      return 1;
    }
    std::ofstream out(argv[3], std::ios::binary);
    out.write(packed.data(), static_cast<std::streamsize>(packed.size()));
    out.close();
    return packed.size() == netcap::brotli_stored_size(raw.size()) ? 0 : 1;
  }

  std::string packed;
  if (!read_file(argv[1], &packed)) {
    std::fprintf(stderr, "cannot read %s\n", argv[1]);
    return 2;
  }

  std::string out;
  std::string why;
  const bool ok = netcap::brotli_decompress(packed, &out, &why);
  std::printf("stream   : %s (%zu bytes)\n", argv[1], packed.size());
  std::printf("decoded  : %s, %zu bytes\n", ok ? "ok" : "FAILED", out.size());
  if (!why.empty()) std::printf("reason   : %s\n", why.c_str());

  if (argc >= 3) {
    std::string expected;
    if (!read_file(argv[2], &expected)) {
      std::fprintf(stderr, "cannot read %s\n", argv[2]);
      return 2;
    }
    const bool same = ok && out == expected;
    std::printf("expected : %zu bytes, %s\n", expected.size(), same ? "identical" : "DIFFERENT");
    if (!same) return 1;
  }

  std::string report;
  const bool self = netcap::brotli_selfcheck(&report);
  std::printf("selfcheck: %s%s\n", self ? "ok" : "FAILED", self ? "" : (" -> " + report).c_str());
  return (ok && self) ? 0 : 1;
}
