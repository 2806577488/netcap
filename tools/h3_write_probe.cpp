// h3_write_probe - write side of HTTP/3 + QPACK (RFC 9114 / RFC 9204).
//
//   tools/h3_write_probe.exe --selfcheck
//   tools/h3_write_probe.exe --fields ":method:GET,:path:/a b,x-test:v"
//   tools/h3_write_probe.exe --fields "..." --huffman=never
//   tools/h3_write_probe.exe --response 404 pages/404.html
//   tools/h3_write_probe.exe --huffman "www.example.com"
//
// Everything the writer emits is decoded back through the *reader* in
// src/h3.cpp (h3_decode_field_section / h3_response_from_stream), never through
// a second decoder living in this tool.
//
// build:
//   g++ -std=c++20 -O2 -Wall -Wextra -Iinclude tools/h3_write_probe.cpp src/h3_write.cpp src/h3.cpp src/quic.cpp src/tls.cpp src/http2.cpp src/common.cpp src/crypto.cpp -o tools/h3_write_probe.exe -static -static-libgcc -static-libstdc++ -lws2_32 -lbcrypt
//
// `src/quic.cpp` and `src/tls.cpp` are in the line because `h3.cpp` calls
// `quic_varint`/`quic_varint_put` and `quic.cpp` calls `tls_parse_client_hello`;
// the task's build line stopped at `http2.cpp` and cannot link without them.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/crypto.hpp"
#include "netcap/h3.hpp"
#include "netcap/h3_write.hpp"

using namespace netcap;

namespace {

int g_failures = 0;

void check(bool ok, const std::string& what) {
  std::cout << (ok ? "  ok   " : "  FAIL ") << what << "\n";
  if (!ok) ++g_failures;
}

std::string hex(const std::string& s) {
  if (s.empty()) return "(empty)";
  return to_hex(reinterpret_cast<const u8*>(s.data()), s.size());
}

// Field values are opaque bytes, so print them the way a packet dump would.
std::string quote(const std::string& s) {
  std::string out = "\"";
  for (std::size_t i = 0; i < s.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(char(c));
    } else if (c >= 0x20 && c < 0x7f) {
      out.push_back(char(c));
    } else {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\x%02x", c);
      out += buf;
    }
  }
  out.push_back('"');
  return out;
}

Bytes to_bytes(const std::string& s) {
  Bytes b;
  b.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) b.push_back(u8(s[i]));
  return b;
}

void usage() {
  std::cout <<
      "usage: h3_write_probe --selfcheck\n"
      "       h3_write_probe --fields <name:value,...> [--huffman=auto|never|always]\n"
      "       h3_write_probe --response <status> <body-file> [--huffman=...]\n"
      "       h3_write_probe --huffman <text>\n";
}

// "name:value,..." - a leading ':' means a pseudo-header, whose name itself
// starts with ':', so the separator is the *second* colon in that case.
bool parse_fields(const std::string& spec, std::vector<H3Field>* out, std::string* error) {
  std::size_t pos = 0;
  while (pos <= spec.size()) {
    std::size_t comma = spec.find(',', pos);
    if (comma == std::string::npos) comma = spec.size();
    const std::string piece = spec.substr(pos, comma - pos);
    if (!piece.empty()) {
      const std::size_t sep = piece[0] == ':' ? piece.find(':', 1) : piece.find(':');
      if (sep == std::string::npos || sep == 0) {
        *error = "field '" + piece + "' is not name:value";
        return false;
      }
      H3Field f;
      f.name = piece.substr(0, sep);
      f.value = piece.substr(sep + 1);
      out->push_back(f);
    }
    if (comma == spec.size()) break;
    pos = comma + 1;
  }
  if (out->empty()) {
    *error = "no fields given (expected name:value,...)";
    return false;
  }
  return true;
}

bool parse_policy(const std::string& arg, QpackHuffman* out) {
  const std::string v = arg.substr(arg.find('=') + 1);
  if (v == "auto" || v == "when-shorter" || v == "whenshorter") {
    *out = QpackHuffman::kWhenShorter;
    return true;
  }
  if (v == "never" || v == "raw") {
    *out = QpackHuffman::kNever;
    return true;
  }
  if (v == "always") {
    *out = QpackHuffman::kAlways;
    return true;
  }
  return false;
}

bool read_file(const std::string& path, std::string* out, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    *error = "cannot open '" + path + "'";
    return false;
  }
  out->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  return true;
}

// Decode a field section through the shipping reader and compare, byte for byte.
bool round_trip_fields(const std::string& section, const std::vector<H3Field>& want) {
  std::vector<std::pair<std::string, std::string>> decoded;
  std::string error;
  if (!h3_decode_field_section(to_bytes(section), &decoded, &error)) {
    check(false, "reader refused our field section: " + error);
    return false;
  }
  bool same = decoded.size() == want.size();
  if (same) {
    for (std::size_t i = 0; i < want.size(); ++i) {
      if (decoded[i].first != want[i].name || decoded[i].second != want[i].value) same = false;
    }
  }
  check(same, "round trip through h3_decode_field_section");
  for (std::size_t i = 0; i < decoded.size(); ++i) {
    std::cout << "       [" << i << "] " << quote(decoded[i].first) << ": "
              << quote(decoded[i].second) << "\n";
  }
  return same;
}

int cmd_selfcheck() {
  std::string report;
  const bool ok = h3_write_selfcheck(&report);
  std::cout << report;
  if (!report.empty() && report.back() != '\n') std::cout << "\n";
  check(ok, "h3_write_selfcheck");
  // The pre-existing reader self-check must still pass: this task extends
  // src/h3.cpp, so a regression there is a regression in the writer's contract.
  std::string reader_report;
  const bool reader_ok = h3_selfcheck(&reader_report);
  check(reader_ok, "h3_selfcheck (reader must be untouched by the extension)");
  if (!reader_ok) std::cout << reader_report;
  return g_failures == 0 ? 0 : 1;
}

int cmd_fields(const std::vector<std::string>& names, QpackHuffman policy) {
  std::vector<H3Field> fields;
  std::string error;
  if (!parse_fields(names.front(), &fields, &error)) {
    std::cout << "h3_write_probe: " << error << "\n";
    return 2;
  }
  std::string section;
  if (!qpack_encode_field_section(fields, policy, &section, &error)) {
    check(false, "qpack_encode_field_section: " + error);
    return 1;
  }
  std::cout << "  field section (" << section.size() << " bytes): " << hex(section) << "\n";
  round_trip_fields(section, fields);

  // Show what the other Huffman policies would have produced, so the
  // "only when strictly shorter" rule is visible on screen.
  const QpackHuffman others[2] = {QpackHuffman::kNever, QpackHuffman::kAlways};
  const char* labels[2] = {"never", "always"};
  for (int i = 0; i < 2; ++i) {
    if (others[i] == policy) continue;
    std::string alt;
    std::string alt_error;
    if (qpack_encode_field_section(fields, others[i], &alt, &alt_error)) {
      std::cout << "  --huffman=" << labels[i] << " would be " << alt.size() << " bytes: "
                << hex(alt) << "\n";
    }
  }
  return g_failures == 0 ? 0 : 1;
}

int cmd_response(const std::vector<std::string>& names, QpackHuffman policy) {
  if (names.size() < 2) {
    usage();
    return 2;
  }
  const std::string status = names[0];
  std::string body;
  std::string error;
  if (!read_file(names[1], &body, &error)) {
    std::cout << "h3_write_probe: " << error << "\n";
    return 2;
  }
  std::vector<H3Field> fields;
  fields.push_back(H3Field{":status", status});
  fields.push_back(H3Field{"content-type", "text/html; charset=utf-8"});
  {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%zu", body.size());
    // content-length stays an ordinary field: it must survive as a field, not
    // be recomputed or dropped by the writer.
    fields.push_back(H3Field{"content-length", buf});
  }
  fields.push_back(H3Field{"x-netcap-modified", "1"});

  // Build the payload out of the two frame writers, honouring --huffman, and
  // then check that the composite helper agrees with them.
  std::string section;
  if (!qpack_encode_field_section(fields, policy, &section, &error)) {
    check(false, "qpack_encode_field_section: " + error);
    return 1;
  }
  std::string payload;
  if (!h3_write_headers_frame(section, &payload, &error)) {
    check(false, "h3_write_headers_frame: " + error);
    return 1;
  }
  if (!body.empty() && !h3_write_data_frame(body, &payload, &error)) {
    check(false, "h3_write_data_frame: " + error);
    return 1;
  }
  std::cout << "  HEADERS+DATA (" << payload.size() << " bytes): " << hex(payload) << "\n";

  std::string composite;
  if (!h3_encode_response(fields, body, &composite, &error)) {
    check(false, "h3_encode_response: " + error);
    return 1;
  }
  if (policy == QpackHuffman::kWhenShorter) {
    check(composite == payload,
          "h3_encode_response == HEADERS+DATA written by hand, byte for byte");
  } else {
    std::cout << "  (--huffman != auto: h3_encode_response always uses the auto policy, so the"
                 " composite comparison is skipped)\n";
  }

  std::vector<H3Frame> frames;
  if (!h3_parse_frames(reinterpret_cast<const u8*>(payload.data()), payload.size(), &frames,
                       &error)) {
    check(false, "h3_parse_frames refused our frames: " + error);
    return 1;
  }
  for (std::size_t i = 0; i < frames.size(); ++i) {
    std::cout << "       frame " << i << ": " << frames[i].type_name << " length="
              << frames[i].length << "\n";
  }

  std::string stream;
  if (!h3_encode_response_stream(fields, body, &stream, &error)) {
    check(false, "h3_encode_response_stream: " + error);
    return 1;
  }
  H3Response got;
  if (!h3_response_from_stream(to_bytes(stream), &got, &error)) {
    check(false, "reader refused our response: " + error);
    return 1;
  }
  check(got.status == status, "round trip: :status " + got.status);
  check(got.body == body, "round trip: body is byte-identical (" +
                              std::to_string(got.body.size()) + " bytes)");
  check(!got.has_trailers, "round trip: no trailers unless we wrote one");
  bool fields_ok = got.headers.size() == fields.size() - 1;
  for (std::size_t i = 1; fields_ok && i < fields.size(); ++i) {
    if (got.headers[i - 1].first != fields[i].name ||
        got.headers[i - 1].second != fields[i].value) {
      fields_ok = false;
    }
  }
  check(fields_ok, "round trip: the " + std::to_string(got.headers.size()) +
                       " ordinary fields survived in order");
  for (std::size_t i = 0; i < got.headers.size(); ++i) {
    std::cout << "       [" << i << "] " << quote(got.headers[i].first) << ": "
              << quote(got.headers[i].second) << "\n";
  }
  return g_failures == 0 ? 0 : 1;
}

int cmd_huffman(const std::string& text) {
  const std::string enc = qpack_huffman_encode(text);
  std::cout << "  huffman (" << text.size() << " bytes -> " << enc.size() << "): " << hex(enc)
            << "\n";
  std::string back;
  std::string error;
  if (!h3_huffman_decode_bytes(reinterpret_cast<const u8*>(enc.data()), enc.size(), &back,
                               &error)) {
    check(false, "reader refused our huffman string: " + error);
    return 1;
  }
  check(back == text, "round trip through h3_huffman_decode_bytes: " + quote(back));
  std::string out;
  check(qpack_huffman_encode(reinterpret_cast<const u8*>(text.data()), text.size(), &out) &&
            out == enc,
        "the (data,len) overload agrees with the std::string one");
  return g_failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<std::string> args(argv + 1, argv + argc);
  if (args.empty()) {
    usage();
    return 2;
  }
  const std::string cmd = args[0];

  std::vector<std::string> rest;
  QpackHuffman policy = QpackHuffman::kWhenShorter;
  bool policy_given = false;
  for (std::size_t i = 1; i < args.size(); ++i) {
    if (args[i].rfind("--huffman=", 0) == 0) {
      if (!parse_policy(args[i], &policy)) {
        std::cout << "h3_write_probe: bad policy '" << args[i]
                  << "' (expected auto|never|always)\n";
        return 2;
      }
      policy_given = true;
    } else {
      rest.push_back(args[i]);
    }
  }
  (void)policy_given;

  if (cmd == "--selfcheck") return cmd_selfcheck();
  if (cmd == "--fields") {
    if (rest.empty()) {
      usage();
      return 2;
    }
    return cmd_fields(rest, policy);
  }
  if (cmd == "--response") return cmd_response(rest, policy);
  if (cmd == "--huffman") {
    if (rest.empty()) {
      usage();
      return 2;
    }
    return cmd_huffman(rest[0]);
  }
  usage();
  return 2;
}
