// Isolated check of netcap's TLS 1.2 PRF and HMAC against the Python oracle in _prf.py.
#include <cstdio>
#include <string>

#include "netcap/crypto.hpp"

namespace {

std::string hex_in(const char* hex) {
  std::string out;
  for (const char* p = hex; p[0] != '\0' && p[1] != '\0'; p += 2) {
    auto nib = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return 0;
    };
    out.push_back(static_cast<char>((nib(p[0]) << 4) | nib(p[1])));
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  // RFC 4231 test case 1: this pins the HMAC layer on its own.
  {
    const netcap::Bytes key(20, static_cast<netcap::u8>(0x0b));
    const std::string data = "Hi There";
    const netcap::Bytes mac = netcap::hmac_sha256(key, reinterpret_cast<const netcap::u8*>(data.data()), data.size());
    std::printf("hmac  %s\n", netcap::to_hex(mac).c_str());
  }
  const char* pms_hex = argc > 3 ? argv[1] : "edbde4a18dc2d9aba2a4394bfa6b6ed053abb90f70f216bf2c817ed58b5a4a5d";
  const char* cr_hex = argc > 3 ? argv[2] : "1acbcbf07eada2acf18b6608ed26b9bd341ed2c9a6b5dcd6288242471115d490";
  const char* sr_hex = argc > 3 ? argv[3] : "d7dceebce0026d808af772f3cfdb14d77a4c70d5cb18ced376ef8b9df78d9e5e";
  const std::string pms = hex_in(pms_hex);
  const std::string cr = hex_in(cr_hex);
  const std::string sr = hex_in(sr_hex);
  const netcap::Bytes premaster(pms.begin(), pms.end());
  netcap::Bytes master_seed(cr.begin(), cr.end());
  master_seed.insert(master_seed.end(), sr.begin(), sr.end());
  std::printf("inputs %zu %zu %zu\n", premaster.size(), cr.size(), sr.size());
  {
    netcap::Bytes s(cr.begin(), cr.end());
    s.insert(s.end(), sr.begin(), sr.end());
    const netcap::Bytes a1 = netcap::hmac_sha256(premaster, s);
    netcap::Bytes msg = a1;
    const std::string label = "master secret";
    msg.insert(msg.end(), label.begin(), label.end());
    msg.insert(msg.end(), s.begin(), s.end());
    const netcap::Bytes block1 = netcap::hmac_sha256(premaster, msg);
    std::printf("cpp A1       %s\n", netcap::to_hex(a1).c_str());
    std::printf("cpp block1   %s\n", netcap::to_hex(block1).c_str());
  }
  const netcap::Bytes master = netcap::tls12_prf(premaster, "master secret", master_seed, 48);
  netcap::Bytes expand_seed(sr.begin(), sr.end());
  expand_seed.insert(expand_seed.end(), cr.begin(), cr.end());
  const netcap::Bytes block = netcap::tls12_prf(master, "key expansion", expand_seed, 40);
  std::printf("cpp master   %s\n", netcap::to_hex(master).c_str());
  netcap::Bytes ck(block.begin(), block.begin() + 16), sk(block.begin() + 16, block.begin() + 32);
  netcap::Bytes ci(block.begin() + 32, block.begin() + 36), si(block.begin() + 36, block.begin() + 40);
  std::printf("cpp client_k %s\n", netcap::to_hex(ck).c_str());
  std::printf("cpp server_k %s\n", netcap::to_hex(sk).c_str());
  std::printf("cpp client_i %s\n", netcap::to_hex(ci).c_str());
  std::printf("cpp server_i %s\n", netcap::to_hex(si).c_str());
  return 0;
}
