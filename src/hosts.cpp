#include "netcap/hosts.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

namespace netcap {

const char* const kHostsMarkerBegin = "# netcap blocklist";
const char* const kHostsMarkerEnd = "# netcap blocklist end";

namespace {

std::string trim(const std::string& s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
  return s.substr(b, e - b);
}

std::vector<std::string> split_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string cur;
  for (const char c : text) {
    if (c == '\n') {
      if (!cur.empty() && cur[cur.size() - 1] == '\r') cur.erase(cur.size() - 1);
      lines.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) {
    if (cur[cur.size() - 1] == '\r') cur.erase(cur.size() - 1);
    lines.push_back(cur);
  }
  return lines;
}

std::string clean_name(const std::string& raw) {
  std::string name = to_lower(trim(raw));
  while (!name.empty() && name[name.size() - 1] == '.') name.erase(name.size() - 1);
  return name;
}

// Addresses that mean "black hole this name".
bool is_sink_address(const std::string& a) {
  return a == "0.0.0.0" || a == "127.0.0.1" || a == "::" || a == "::1";
}

std::set<std::string> blocked_set(const std::vector<std::string>& blocked) {
  std::set<std::string> out;
  for (const std::string& n : blocked) {
    const std::string name = clean_name(n);
    if (!name.empty()) out.insert(name);
  }
  return out;
}

}  // namespace

bool HostsFile::has_name(const std::string& name) const { return find(name) != nullptr; }

const HostsEntry* HostsFile::find(const std::string& name) const {
  const std::string want = clean_name(name);
  for (const HostsEntry& e : entries) {
    if (e.name == want) return &e;
  }
  return nullptr;
}

std::string HostsFile::describe() const {
  std::ostringstream os;
  os << entries.size() << " entr" << (entries.size() == 1 ? "y" : "ies") << ", " << comments.size()
     << " comment(s), " << blank_lines << " blank line(s)";
  return os.str();
}

bool parse_hosts(const std::string& text, HostsFile* out, std::string* error) {
  if (out == nullptr) return false;
  out->entries.clear();
  out->comments.clear();
  out->blank_lines = 0;
  bool ok = true;
  const std::vector<std::string> lines = split_lines(text);
  for (std::size_t i = 0; i < lines.size(); ++i) {
    const std::string t = trim(lines[i]);
    if (t.empty()) {
      ++out->blank_lines;
      continue;
    }
    if (t[0] == '#') {
      out->comments.push_back(trim(t.substr(1)));
      continue;
    }
    // Split the line into words; the first word is the address, the rest are
    // names, and the first word that starts with '#' starts a comment.
    std::vector<std::string> words;
    std::string comment;
    std::istringstream is(t);
    std::string w;
    while (is >> w) {
      if (!w.empty() && w[0] == '#') {
        std::string rest;
        std::getline(is, rest);
        comment = trim(w.substr(1) + rest);
        break;
      }
      words.push_back(w);
    }
    if (words.size() < 2) {
      if (ok && error != nullptr) {
        *error = "hosts line " + std::to_string(i + 1) + ": expected 'address name [name...]'";
        ok = false;
      }
      continue;
    }
    // The first word must be an address: without that check a stray sentence
    // would silently become five bogus entries.
    int version = 0;
    u8 parsed[16];
    if (!parse_ip(words[0], &version, parsed)) {
      if (ok && error != nullptr) {
        *error = "hosts line " + std::to_string(i + 1) + ": '" + words[0] + "' is not an IP address";
        ok = false;
      }
      continue;
    }
    for (std::size_t k = 1; k < words.size(); ++k) {
      HostsEntry e;
      e.address = words[0];
      e.name = clean_name(words[k]);
      e.comment = comment;
      e.line = i + 1;
      if (e.name.empty()) continue;
      out->entries.push_back(e);
    }
  }
  return ok;
}

std::string HostsPlan::describe() const {
  std::ostringstream os;
  os << "+" << added.size() << " added, -" << removed.size() << " removed, " << present.size()
     << " already blocked, " << kept_entries << " existing entr" << (kept_entries == 1 ? "y" : "ies")
     << " kept";
  return os.str();
}

HostsPlan plan_hosts(const std::string& current_text, const std::vector<std::string>& blocked,
                     const std::string& sink_address) {
  const std::set<std::string> want = blocked_set(blocked);
  const std::vector<std::string> lines = split_lines(current_text);

  std::size_t begin = lines.size();
  std::size_t end = lines.size();
  for (std::size_t i = 0; i < lines.size(); ++i) {
    const std::string t = trim(lines[i]);
    if (t == kHostsMarkerBegin && begin == lines.size()) {
      begin = i;
    } else if (t == kHostsMarkerEnd && begin != lines.size() && end == lines.size()) {
      end = i;
    }
  }
  const bool have_block = begin != lines.size() && end != lines.size() && end > begin;

  std::set<std::string> old_block;
  if (have_block) {
    for (std::size_t i = begin + 1; i < end; ++i) {
      HostsFile tmp;
      std::string ignored;
      parse_hosts(lines[i], &tmp, &ignored);
      for (const HostsEntry& e : tmp.entries) old_block.insert(e.name);
    }
  }

  HostsPlan plan;
  std::vector<std::string> kept;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (have_block && i >= begin && i <= end) continue;
    kept.push_back(lines[i]);
    HostsFile tmp;
    std::string ignored;
    parse_hosts(lines[i], &tmp, &ignored);
    for (const HostsEntry& e : tmp.entries) {
      ++plan.kept_entries;
      if (is_sink_address(e.address) && want.count(e.name) != 0) plan.present.push_back(e.name);
    }
  }

  std::vector<std::string> needed;
  for (const std::string& name : want) {
    const bool already = std::find(plan.present.begin(), plan.present.end(), name) != plan.present.end();
    if (!already) needed.push_back(name);
  }
  for (const std::string& name : needed) {
    if (old_block.count(name) == 0) plan.added.push_back(name);
  }
  for (const std::string& name : old_block) {
    if (want.count(name) == 0) plan.removed.push_back(name);
  }

  std::ostringstream os;
  bool first = true;
  for (const std::string& line : kept) {
    if (!first) os << "\n";
    first = false;
    os << line;
  }
  if (!first) os << "\n";
  os << kHostsMarkerBegin << "\n";
  for (const std::string& name : needed) os << sink_address << " " << name << "\n";
  os << kHostsMarkerEnd << "\n";
  plan.text = os.str();
  return plan;
}

bool write_hosts_file(const std::string& path, const std::string& text, std::string* error,
                      bool make_backup) {
  if (path.empty()) {
    if (error != nullptr) *error = "no hosts file path was given";
    return false;
  }
  // Keep one copy of what was there before, so a bad blocklist can always be
  // undone by hand.
  if (make_backup) {
    std::ifstream in(path, std::ios::binary);
    if (in) {
      std::ostringstream buf;
      buf << in.rdbuf();
      in.close();
      std::ofstream bak(path + ".bak", std::ios::binary | std::ios::trunc);
      if (bak) {
        bak << buf.str();
        bak.close();
      }
    }
  }

  const std::string tmp = path + ".netcap.tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) {
      if (error != nullptr) *error = "cannot create '" + tmp + "'";
      return false;
    }
    out << text;
    out.flush();
    if (!out) {
      if (error != nullptr) *error = "cannot write '" + tmp + "'";
      return false;
    }
  }
  // rename() refuses to replace an existing file on Windows, so the target is
  // removed first.  The .bak copy above is what makes that window safe.
  std::remove(path.c_str());
  if (std::rename(tmp.c_str(), path.c_str()) != 0) {
    if (error != nullptr) *error = "cannot move '" + tmp + "' onto '" + path + "'";
    std::remove(tmp.c_str());
    return false;
  }
  return true;
}

std::string platform_hosts_path() {
#ifdef _WIN32
  const char* root = std::getenv("SystemRoot");
  const std::string base = (root != nullptr && root[0] != '\0') ? std::string(root) : std::string("C:\\Windows");
  return base + "\\System32\\drivers\\etc\\hosts";
#else
  return "/etc/hosts";
#endif
}

}  // namespace netcap
