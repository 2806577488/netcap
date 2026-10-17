#include "netcap/quic_rewrite.hpp"

#include "netcap/h3_write.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace netcap {

namespace {

// RFC 9000 section 16: two-bit length prefix in the first byte.
void put_varint(std::string& out, u64 value) {
  if (value < 64) {
    out.push_back(static_cast<char>(value));
  } else if (value < 16384) {
    out.push_back(static_cast<char>(0x40 | (value >> 8)));
    out.push_back(static_cast<char>(value & 0xff));
  } else if (value < 1073741824ULL) {
    out.push_back(static_cast<char>(0x80 | (value >> 24)));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
  } else {
    out.push_back(static_cast<char>(0xc0 | (value >> 56)));
    for (int shift = 48; shift >= 0; shift -= 8) {
      out.push_back(static_cast<char>((value >> shift) & 0xff));
    }
  }
}

// One STREAM frame (RFC 9000 section 19.8).  We never invent a stream: the id
// and the offset come from the frame we are replacing.
std::string build_stream_frame(const QuicStreamFrame& original, bool has_offset,
                               const std::string& data) {
  std::string out;
  u8 type = 0x08;
  if (has_offset) type |= 0x04;
  type |= 0x02;  // an explicit length: a frame whose end depends on the datagram
                 // end would break the moment we pad behind it
  if (original.fin) type |= 0x01;
  out.push_back(static_cast<char>(type));
  put_varint(out, original.stream_id);
  if (has_offset) put_varint(out, original.offset);
  put_varint(out, static_cast<u64>(data.size()));
  out.append(data);
  return out;
}

bool is_client_bidi(u64 stream_id) { return (stream_id & 0x03) == 0; }

}  // namespace

std::string quic_strip_query_parameter(const std::string& path, const std::string& name) {
  if (name.empty()) return path;
  const std::size_t mark = path.find('?');
  if (mark == std::string::npos) return path;
  const std::string head = path.substr(0, mark);
  const std::string query = path.substr(mark + 1);
  std::string kept;
  std::size_t pos = 0;
  while (pos <= query.size()) {
    std::size_t amp = query.find('&', pos);
    if (amp == std::string::npos) amp = query.size();
    const std::string pair = query.substr(pos, amp - pos);
    const std::size_t eq = pair.find('=');
    const std::string key = eq == std::string::npos ? pair : pair.substr(0, eq);
    if (!pair.empty() && key != name) {
      if (!kept.empty()) kept.push_back('&');
      kept.append(pair);
    }
    if (amp == query.size()) break;
    pos = amp + 1;
  }
  return kept.empty() ? head : head + "?" + kept;
}

bool quic_rewrite_request(const QuicKeyset& keys, std::size_t dcid_len, const u8* packet,
                          std::size_t len, u64 largest_pn, const RuleSet& rules, Bytes* out,
                          QuicRewriteResult* result, std::string* error) {
  if (out == nullptr || result == nullptr) {
    if (error) *error = "quic_rewrite_request needs an output packet and a result";
    return false;
  }
  *result = QuicRewriteResult();
  out->clear();

  QuicShortHeader header;
  if (!quic_decrypt_short_full(keys, packet, dcid_len, packet, len, largest_pn, &header, error)) {
    return false;
  }
  std::vector<QuicFrameInfo> frames;
  if (!quic_parse_frames_rtt(header.payload.data(), header.payload.size(), &frames, error)) {
    return false;
  }

  // Find the request: the first client-initiated bidirectional STREAM frame
  // that starts at offset zero and carries a complete field section.
  std::size_t target = frames.size();
  H3Request request;
  for (std::size_t i = 0; i < frames.size(); ++i) {
    const QuicFrameInfo& frame = frames[i];
    if (frame.type < 0x08 || frame.type > 0x0f) continue;
    if (!is_client_bidi(frame.stream.stream_id)) continue;
    if (frame.stream.offset != 0) continue;  // a continuation has no field section
    H3Request candidate;
    std::string why;
    if (!h3_request_from_stream(frame.stream.data, true, &candidate, &why)) continue;
    target = i;
    request = candidate;
    break;
  }
  if (target == frames.size()) {
    result->note = "no complete HTTP/3 request in this datagram";
    return true;
  }

  const std::string url = (request.scheme.empty() ? std::string("https") : request.scheme) +
                          "://" + request.authority + request.path;
  result->url = url;

  const RuleDecision decision = rules.decide(rule_request_from_url(url, "", ResourceType::Document));
  if (decision.action != RuleAction::Modify || decision.value.empty()) {
    result->note = "nothing in the rule set rewrites this request";
    return true;
  }
  result->rule = decision.rule != nullptr ? decision.rule->raw : std::string();

  const std::string new_path = quic_strip_query_parameter(request.path, decision.value);
  if (new_path == request.path) {
    result->note = "the parameter " + decision.value + " is not in this URL";
    return true;
  }
  result->new_path = new_path;

  std::vector<H3Field> fields;
  fields.push_back(H3Field{kH3FieldMethod, request.method.empty() ? "GET" : request.method});
  fields.push_back(H3Field{kH3FieldScheme, request.scheme.empty() ? "https" : request.scheme});
  fields.push_back(H3Field{kH3FieldAuthority, request.authority});
  fields.push_back(H3Field{kH3FieldPath, new_path});
  for (const std::pair<std::string, std::string>& header : request.headers) {
    fields.push_back(H3Field{header.first, header.second});
  }

  std::string section;
  std::string why;
  // Literal, never Huffman: the length has to be predictable, and the padding
  // below absorbs the few bytes we give away.
  if (!qpack_encode_field_section(fields, QpackHuffman::kNever, &section, &why)) {
    if (error) *error = "cannot re-encode the request field section: " + why;
    return false;
  }
  std::string stream_bytes;
  // The first byte of a client-initiated bidirectional stream is the
  // request-stream type varint (0x00).  Writing the HEADERS frame alone would
  // produce a stream the reader cannot recognise as a request at all.
  stream_bytes.push_back('\0');
  if (!h3_write_headers_frame(section, &stream_bytes, &why)) {
    if (error) *error = "cannot write a HEADERS frame onto the request stream: " + why;
    return false;
  }

  const QuicFrameInfo& victim = frames[target];
  const bool had_offset = (victim.type & 0x04) != 0;
  const std::string replacement =
      build_stream_frame(victim.stream, had_offset, stream_bytes);
  if (replacement.size() > victim.length) {
    result->note = "the rewrite needs " + std::to_string(replacement.size()) +
                   " bytes but the original frame is " + std::to_string(victim.length) +
                   "; a datagram may not grow";
    result->rewritten = false;
    result->new_path.clear();
    return true;
  }

  std::string payload;
  payload.reserve(header.payload.size());
  for (std::size_t i = 0; i < frames.size(); ++i) {
    if (i == target) {
      payload.append(replacement);
      continue;
    }
    const QuicFrameInfo& frame = frames[i];
    const std::size_t begin = static_cast<std::size_t>(frame.offset);
    const std::size_t end = begin + static_cast<std::size_t>(frame.length);
    if (end > header.payload.size()) {
      if (error) *error = "a frame claims to end past the payload";
      return false;
    }
    payload.append(reinterpret_cast<const char*>(header.payload.data()) + begin,
                   static_cast<std::size_t>(frame.length));
  }
  // RFC 9000 section 19.1: a PADDING frame is a single zero byte, and a
  // recipient must ignore it, which is exactly what a same-length rewrite needs.
  if (payload.size() > header.payload.size()) {
    result->note = "the rebuilt payload is longer than the original by " +
                   std::to_string(payload.size() - header.payload.size()) + " bytes";
    result->rewritten = false;
    result->new_path.clear();
    return true;
  }
  const std::size_t padding = header.payload.size() - payload.size();
  payload.append(padding, '\0');

  const Bytes original(packet, packet + len);
  if (!quic_reseal_same_pn(keys, original, Bytes(payload.begin(), payload.end()), out, error,
                           largest_pn)) {
    return false;
  }
  if (out->size() != len) {
    if (error) *error = "the re-sealed datagram is " + std::to_string(out->size()) +
                        " bytes, not " + std::to_string(len);
    return false;
  }

  // Never hand out a packet we cannot open again: this is the check that makes
  // the whole path safe to enable.
  QuicShortHeader check;
  std::string verify_why;
  if (!quic_decrypt_short_full(keys, out->data(), dcid_len, out->data(), out->size(), largest_pn,
                               &check, &verify_why)) {
    if (error) *error = "the rewritten datagram does not open again: " + verify_why;
    return false;
  }
  std::vector<QuicFrameInfo> check_frames;
  if (!quic_parse_frames_rtt(check.payload.data(), check.payload.size(), &check_frames,
                             &verify_why)) {
    if (error) *error = "the rewritten payload does not parse: " + verify_why;
    return false;
  }
  H3Request seen;
  bool found = false;
  for (const QuicFrameInfo& frame : check_frames) {
    if (frame.type < 0x08 || frame.type > 0x0f) continue;
    if (frame.stream.offset != 0) continue;
    if (h3_request_from_stream(frame.stream.data, true, &seen, &verify_why)) {
      found = true;
      break;
    }
  }
  if (!found || seen.path != new_path) {
    if (error) {
      std::string dump;
      for (const QuicFrameInfo& frame : check_frames) {
        dump += " " + std::to_string(static_cast<int>(frame.type)) + "@" +
                std::to_string(frame.offset) + "+" + std::to_string(frame.length);
      }
      std::string hex;
      for (std::size_t i = 0; i < check.payload.size() && i < 48; ++i) {
        char buf[4] = {0, 0, 0, 0};
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(check.payload[i]));
        hex += buf;
      }
      *error = "the rewritten request does not read back as " + new_path + " (it reads back as '" +
               seen.path + "', found=" + (found ? "yes" : "no") + ", frame bytes " +
               std::to_string(replacement.size()) + ", frames:" + dump + ", payload:" + hex + ")";
    }
    return false;
  }

  result->rewritten = true;
  result->note = "same-length rewrite: " + request.path + " -> " + new_path + " (" +
                 std::to_string(padding) + " padding byte(s), packet number untouched)";
  return true;
}

bool quic_rewrite_selfcheck(std::string* report) {
  int checks = 0;
  int failures = 0;
  std::string log;
  auto ok = [&](bool condition, const std::string& what) {
    ++checks;
    if (!condition) {
      ++failures;
      log += "  FAIL " + what + "\n";
    } else {
      log += "  ok   " + what + "\n";
    }
  };

  ok(quic_strip_query_parameter("/p?a=1&b=2", "a") == "/p?b=2", "$removeparam drops one of two");
  ok(quic_strip_query_parameter("/p?a=1", "a") == "/p", "dropping the last parameter drops the ?");
  ok(quic_strip_query_parameter("/p?a=1", "z") == "/p?a=1", "an absent parameter changes nothing");
  ok(quic_strip_query_parameter("/p", "a") == "/p", "a path without a query is left alone");
  ok(quic_strip_query_parameter("/p?a=1&a=2&b=3", "a") == "/p?b=3", "every copy goes");

  const u8 secret_bytes[32] = {0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
                               0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
                               0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
                               0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b};
  QuicKeyset keys;
  std::string why;
  ok(quic_keyset_from_secret(kH3TlsChacha20Poly1305Sha256, Bytes(secret_bytes, secret_bytes + 32),
                             &keys, &why),
     "the A.5 secret expands into a key set" + (why.empty() ? std::string() : (": " + why)));

  // A request stream: the field section, then the HEADERS frame, then the
  // request-stream prefix the HTTP/3 layer puts in front of it.
  std::vector<H3Field> fields;
  fields.push_back(H3Field{kH3FieldMethod, "GET"});
  fields.push_back(H3Field{kH3FieldScheme, "https"});
  fields.push_back(H3Field{kH3FieldAuthority, "ads.example.com"});
  fields.push_back(H3Field{kH3FieldPath, "/p?spm=track&keep=1"});
  std::string section;
  why.clear();
  ok(qpack_encode_field_section(fields, QpackHuffman::kNever, &section, &why),
     "the request field section encodes" + (why.empty() ? std::string() : (": " + why)));
  std::string stream;
  stream.push_back('\0');  // request-stream type: client-initiated bidirectional
  why.clear();
  ok(h3_write_headers_frame(section, &stream, &why),
     "the HEADERS frame goes onto the stream" + (why.empty() ? std::string() : (": " + why)));

  QuicStreamFrame original;
  original.stream_id = 0;
  original.offset = 0;
  original.fin = true;
  const std::string frame_bytes = build_stream_frame(original, false, stream);
  std::string payload = frame_bytes;
  payload.append(6, '\0');  // room to grow the request: PADDING frames

  QuicShortHeader made;
  made.pn_offset = 8;
  made.pn_length = 2;
  made.first_byte_unprotected = 0x40;
  made.header = Bytes(8, 0xab);
  Bytes sealed;
  why.clear();
  const u64 pn = 0x1234;
  ok(quic_seal_short(keys, made, Bytes(payload.begin(), payload.end()), pn, &sealed, &why),
     "a synthetic 1-RTT packet with a request inside it seals" +
         (why.empty() ? std::string() : (": " + why)));

  RuleSet rules;
  why.clear();
  rules.add_line("||ads.example.com^$removeparam=spm", &why);
  ok(why.empty(), "the $removeparam rule loads" + (why.empty() ? std::string() : (": " + why)));

  Bytes rewritten;
  QuicRewriteResult result;
  why.clear();
  // `pn_offset` counts the first byte, so the connection ID `made.header`
  // stands for is one byte shorter than the header: sealing put the packet
  // number at offset 8, and opening has to agree or the header-protection
  // sample moves (see the long comment in `src/quickeys.cpp`).
  const std::size_t dcid_len = made.pn_offset - 1;
  if (!quic_rewrite_request(keys, dcid_len, sealed.data(), sealed.size(), pn - 1, rules,
                            &rewritten, &result, &why)) {
    ok(false, "the rewrite runs: " + why);
  } else {
    ok(result.rewritten, "a matching $removeparam rule rewrites the request: " + result.note);
    ok(rewritten.size() == sealed.size(), "the datagram keeps its length");
    QuicShortHeader opened;
    std::string open_why;
    if (quic_decrypt_short_full(keys, rewritten.data(), dcid_len, rewritten.data(),
                                rewritten.size(), pn - 1, &opened, &open_why)) {
      ok(opened.packet_number == pn, "the packet number is the one the client used");
      std::vector<QuicFrameInfo> frames;
      std::string frame_why;
      if (quic_parse_frames_rtt(opened.payload.data(), opened.payload.size(), &frames, &frame_why)) {
        bool parsed = false;
        H3Request seen;
        for (const QuicFrameInfo& frame : frames) {
          if (frame.type < 0x08 || frame.type > 0x0f || frame.stream.offset != 0) continue;
          if (h3_request_from_stream(frame.stream.data, true, &seen, &frame_why)) {
            parsed = true;
            break;
          }
        }
        ok(parsed, "the rewritten payload still holds a request");
        ok(seen.path == "/p?keep=1", "the tracking parameter is gone and the rest is intact");
        ok(seen.authority == "ads.example.com" && seen.method == "GET",
           "the other pseudo-headers survive the round trip");
      } else {
        ok(false, "the rewritten payload parses: " + frame_why);
      }
    } else {
      ok(false, "the rewritten datagram opens: " + open_why);
    }
  }

  // Nothing to do: no rule matches, so the packet is handed back untouched.
  RuleSet empty_rules;
  Bytes untouched;
  QuicRewriteResult idle;
  why.clear();
  const bool idle_ok =
      quic_rewrite_request(keys, dcid_len, sealed.data(), sealed.size(), pn - 1, empty_rules,
                           &untouched, &idle, &why);
  ok(idle_ok && !idle.rewritten && untouched.empty(),
     "a request no rule rewrites is left alone" + (why.empty() ? std::string() : (": " + why)));

  // Zero slack: a shrinking rewrite needs no padding at all, so even a
  // datagram with not one byte of room must go through.
  Bytes tight;
  why.clear();
  if (!quic_seal_short(keys, made, Bytes(frame_bytes.begin(), frame_bytes.end()), pn, &tight,
                       &why)) {
    ok(false, "the tight packet seals: " + why);
  } else {
    Bytes fitted;
    QuicRewriteResult tight_result;
    why.clear();
    const bool ran = quic_rewrite_request(keys, dcid_len, tight.data(), tight.size(), pn - 1, rules,
                                          &fitted, &tight_result, &why);
    ok(ran && tight_result.rewritten && fitted.size() == tight.size(),
       "a shrinking rewrite fits even with no padding to give back" +
           (why.empty() ? std::string() : (": " + why)));
  }

  // A rewrite that does not fit must be refused, not truncated.  Huffman-coded
  // field sections are what browsers actually send, and the parameter we take
  // out here is tiny while the authority is long -- so the literal re-encode we
  // produce is genuinely bigger than the bytes it replaces.
  const std::string long_host = "a-very-long-advertising-host.example.com";
  std::vector<H3Field> wide;
  wide.push_back(H3Field{kH3FieldMethod, "GET"});
  wide.push_back(H3Field{kH3FieldScheme, "https"});
  wide.push_back(H3Field{kH3FieldAuthority, long_host});
  wide.push_back(H3Field{kH3FieldPath, "/p?a=1"});
  std::string huff_section;
  why.clear();
  if (!qpack_encode_field_section(wide, QpackHuffman::kAlways, &huff_section, &why)) {
    ok(false, "the Huffman field section encodes: " + why);
  } else {
    std::string huff_stream;
    huff_stream.push_back('\0');
    why.clear();
    if (!h3_write_headers_frame(huff_section, &huff_stream, &why)) {
      ok(false, "the Huffman HEADERS frame writes: " + why);
    } else {
      const std::string huff_frame = build_stream_frame(original, false, huff_stream);
      RuleSet wide_rules;
      std::string wide_why;
      wide_rules.add_line("||" + long_host + "^$removeparam=a", &wide_why);
      Bytes huff;
      why.clear();
      if (!quic_seal_short(keys, made, Bytes(huff_frame.begin(), huff_frame.end()), pn, &huff,
                           &why)) {
        ok(false, "the Huffman packet seals: " + why);
      } else {
        Bytes refused;
        QuicRewriteResult huff_result;
        why.clear();
        const bool ran = quic_rewrite_request(keys, dcid_len, huff.data(), huff.size(), pn - 1,
                                              wide_rules, &refused, &huff_result, &why);
        ok(ran && !huff_result.rewritten && refused.empty(),
           "a rewrite that does not fit is refused instead of truncated [" + huff_result.note + "]" +
               (why.empty() ? std::string() : (": " + why)));
      }
    }
  }

  if (report != nullptr) {
    *report = "quic rewrite: " + std::to_string(checks - failures) + "/" + std::to_string(checks) +
              " ok\n" + log;
  }
  return failures == 0;
}

}  // namespace netcap
