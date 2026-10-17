#include "netcap/httpframe.hpp"

#include <algorithm>

namespace netcap {
namespace {

constexpr std::size_t kMaxHead = 64 * 1024;
constexpr std::size_t kMaxLine = 8 * 1024;
// A body larger than this is refused rather than framed: a proxy that buffers
// or counts gigabytes from an untrusted origin is a denial of service waiting
// to happen, and no real response needs it.
constexpr std::size_t kMaxBody = static_cast<std::size_t>(1) << 32;

void ascii_lower(std::string* text) {
  for (char& ch : *text) {
    if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
  }
}

std::string trim(const std::string& text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) ++begin;
  while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) --end;
  return text.substr(begin, end - begin);
}

}  // namespace

HttpResponseFramer::HttpResponseFramer(std::string method) : method_(std::move(method)) {}

void HttpResponseFramer::fail(const std::string& why, std::string* error) {
  state_ = State::Failed;
  reusable_ = false;
  if (error != nullptr && error->empty()) *error = why;
}

bool HttpResponseFramer::feed(const char* data, std::size_t len, std::size_t* consumed,
                              std::string* error) {
  std::size_t at = 0;
  while (at < len) {
    if (state_ == State::Done || state_ == State::Failed) break;
    switch (state_) {
      case State::Head: {
        head_.push_back(data[at++]);
        if (head_.size() >= 4 && head_.compare(head_.size() - 4, 4, "\r\n\r\n") == 0) {
          if (!parse_head(error)) {
            if (consumed != nullptr) *consumed = at;
            return false;
          }
        } else if (head_.size() > kMaxHead) {
          fail("the response head is larger than " + std::to_string(kMaxHead) + " bytes", error);
        }
        break;
      }
      case State::Fixed: {
        const std::size_t take = std::min(remaining_, len - at);
        remaining_ -= take;
        body_bytes_ += take;
        at += take;
        if (remaining_ == 0) {
          state_ = State::Done;
          reusable_ = true;
        }
        break;
      }
      case State::ChunkSize: {
        const char ch = data[at++];
        if (ch == '\n' && !line_.empty() && line_.back() == '\r') {
          line_.pop_back();
          if (!take_chunk_size(error)) {
            if (consumed != nullptr) *consumed = at;
            return false;
          }
        } else {
          line_.push_back(ch);
          if (line_.size() > kMaxLine) fail("a chunk size line never ended", error);
        }
        break;
      }
      case State::ChunkData: {
        const std::size_t take = std::min(remaining_, len - at);
        remaining_ -= take;
        body_bytes_ += take;
        at += take;
        if (remaining_ == 0) {
          state_ = State::ChunkCrlf;
          crlf_seen_ = false;
        }
        break;
      }
      case State::ChunkCrlf: {
        const char ch = data[at++];
        if (!crlf_seen_) {
          if (ch != '\r') {
            fail("a chunk did not end with CRLF", error);
          } else {
            crlf_seen_ = true;
          }
        } else if (ch != '\n') {
          fail("a chunk did not end with CRLF", error);
        } else {
          crlf_seen_ = false;
          state_ = State::ChunkSize;
        }
        break;
      }
      case State::Trailer: {
        const char ch = data[at++];
        if (ch == '\n' && !line_.empty() && line_.back() == '\r') {
          line_.pop_back();
          const bool empty = line_.empty();
          line_.clear();
          if (empty) {
            state_ = State::Done;
            reusable_ = true;
          }
        } else {
          line_.push_back(ch);
          if (line_.size() > kMaxLine) fail("a chunked trailer line never ended", error);
        }
        break;
      }
      case State::UntilClose: {
        body_bytes_ += len - at;
        at = len;
        break;
      }
      case State::Done:
      case State::Failed:
        break;
    }
  }
  if (consumed != nullptr) *consumed = at;
  return state_ != State::Failed;
}

bool HttpResponseFramer::parse_head(std::string* error) {
  const std::size_t blank = head_.find("\r\n\r\n");
  if (blank == std::string::npos) {
    fail("the response head was not terminated", error);
    return false;
  }
  const std::string block = head_.substr(0, blank);
  std::size_t at = block.find("\r\n");
  const std::string status_line = at == std::string::npos ? block : block.substr(0, at);
  // "HTTP/1.1 200 OK"
  const std::size_t space = status_line.find(' ');
  if (space == std::string::npos || status_line.compare(0, 5, "HTTP/") != 0) {
    fail("the response does not start with a status line", error);
    return false;
  }
  const std::size_t code_at = status_line.find_first_not_of(' ', space);
  if (code_at == std::string::npos) {
    fail("the status line has no status code", error);
    return false;
  }
  int code = 0;
  std::size_t digits = 0;
  for (std::size_t i = code_at; i < status_line.size() && digits < 3; ++i, ++digits) {
    const char ch = status_line[i];
    if (ch < '0' || ch > '9') break;
    code = code * 10 + (ch - '0');
  }
  if (digits != 3) {
    fail("the status line has no three digit status code", error);
    return false;
  }
  status_ = code;

  std::string transfer_encoding;
  bool has_length = false;
  std::size_t content_length = 0;
  while (at != std::string::npos) {
    const std::size_t next = block.find("\r\n", at + 2);
    const std::string line = block.substr(at + 2, next == std::string::npos ? std::string::npos
                                                                           : next - (at + 2));
    const std::size_t colon = line.find(':');
    if (colon != std::string::npos) {
      std::string name = line.substr(0, colon);
      ascii_lower(&name);
      const std::string value = trim(line.substr(colon + 1));
      if (name == "transfer-encoding") {
        transfer_encoding = value;
        ascii_lower(&transfer_encoding);
      } else if (name == "content-length") {
        const std::string number = trim(value);
        std::size_t parsed = 0;
        bool ok = !number.empty();
        for (char ch : number) {
          if (ch < '0' || ch > '9' || parsed > kMaxBody) {
            ok = false;
            break;
          }
          parsed = parsed * 10 + static_cast<std::size_t>(ch - '0');
        }
        if (ok) {
          has_length = true;
          content_length = parsed;
        }
      }
    }
    at = next;
  }

  if (method_ == "HEAD" || (status_ >= 100 && status_ < 200) || status_ == 204 || status_ == 304) {
    state_ = State::Done;
    reusable_ = true;
    return true;
  }
  if (transfer_encoding.find("chunked") != std::string::npos) {
    state_ = State::ChunkSize;
    line_.clear();
    return true;
  }
  if (has_length) {
    if (content_length == 0) {
      state_ = State::Done;
      reusable_ = true;
    } else {
      remaining_ = content_length;
      state_ = State::Fixed;
    }
    return true;
  }
  // No framing at all: the body ends when the origin closes the connection, so
  // this response can be relayed but the connection cannot be reused.
  state_ = State::UntilClose;
  return true;
}

bool HttpResponseFramer::take_chunk_size(std::string* error) {
  std::string digits = line_;
  line_.clear();
  const std::size_t semi = digits.find(';');  // chunk extensions are ignored
  if (semi != std::string::npos) digits = digits.substr(0, semi);
  digits = trim(digits);
  if (digits.empty()) {
    fail("a chunk size line was empty", error);
    return false;
  }
  std::size_t size = 0;
  for (char ch : digits) {
    int digit = -1;
    if (ch >= '0' && ch <= '9') {
      digit = ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
      digit = ch - 'a' + 10;
    } else if (ch >= 'A' && ch <= 'F') {
      digit = ch - 'A' + 10;
    }
    if (digit < 0 || size > kMaxBody) {
      fail("a chunk size could not be read", error);
      return false;
    }
    size = size * 16 + static_cast<std::size_t>(digit);
  }
  if (size == 0) {
    state_ = State::Trailer;
    return true;
  }
  remaining_ = size;
  state_ = State::ChunkData;
  return true;
}

std::string HttpResponseFramer::describe() const {
  static const char* names[] = {"head",     "body",   "chunk size", "chunk data",
                                "chunk CRLF", "trailer", "until close", "done", "failed"};
  const std::size_t index = static_cast<std::size_t>(state_);
  const char* name = index < (sizeof(names) / sizeof(names[0])) ? names[index] : "?";
  std::string text = "http response ";
  text += name;
  if (status_ > 0) text += " status " + std::to_string(status_);
  text += ", " + std::to_string(body_bytes_) + " body byte(s)";
  if (state_ == State::Done) text += reusable_ ? ", reusable" : ", not reusable";
  return text;
}

}  // namespace netcap
