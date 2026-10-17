// bench_rules -- how fast is the filter engine on a real block list?
//
//   g++ -std=c++20 -O2 -Iinclude tools/bench_rules.cpp src/rules.cpp src/regex.cpp
//       src/common.cpp -o tools/bench_rules.exe
//   tools/bench_rules.exe _lists\easylist.txt _lists\easyprivacy.txt
//
// Real lists are big: EasyList is ~80k lines and EasyPrivacy ~57k, together about
// 3.6 MB.  A browser-side blocker is asked "block or not?" for every request a
// page makes, so what matters is (a) how long the list takes to load and (b) how
// long one decision costs when almost every rule is a miss.  This tool answers
// both with the same code the proxy runs.
#include <cstdio>
#include <string>
#include <vector>

#include "netcap/common.hpp"
#include "netcap/rules.hpp"

namespace {

// A page makes requests for several kinds of resources; the engine's answer can
// depend on the type (`$image`, `$script`, ...), so the corpus covers them.
const netcap::ResourceType kTypes[] = {
    netcap::ResourceType::Document, netcap::ResourceType::Script,
    netcap::ResourceType::Image,    netcap::ResourceType::Stylesheet,
    netcap::ResourceType::XmlHttpRequest, netcap::ResourceType::Font,
    netcap::ResourceType::Media,    netcap::ResourceType::Subdocument,
};

const char* kSeedUrls[] = {
    "https://www.google-analytics.com/analytics.js",
    "https://www.googletagmanager.com/gtm.js?id=GTM-123456",
    "https://static.doubleclick.net/instream/ad_status.js",
    "https://securepubads.g.doubleclick.net/tag/js/gpt.js",
    "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js",
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
    "https://fonts.gstatic.com/s/inter/v13/UcCO3Fwr.woff2",
    "https://upload.wikimedia.org/wikipedia/commons/thumb/a/a9/x.png",
    "https://api.github.com/repos/torvalds/linux",
    "https://www.bing.com/search?q=netcap",
    "https://example.com/assets/app.js?ver=1.2.3",
    "https://news.example.org/article/2026/why-ads-are-slow",
    "https://tracking.example.net/pixel.gif?uid=42&utm_source=mail",
    "https://ads.example.com/banner/728x90.jpg",
    "https://cdn.example.com/static/main.css",
    "http://static.chartbeat.com/js/chartbeat.js",
    "https://connect.facebook.net/en_US/fbevents.js",
    "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js",
    "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
    "https://cdn.shopify.com/s/files/1/0001/logo.png",
};

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: bench_rules <list> [list ...]\n"
                 "       several files are loaded into one rule set, the way --rules works\n");
    return 2;
  }

  netcap::RuleSet rules;
  const netcap::i64 load_started = netcap::now_monotonic_us();
  for (int i = 1; i < argc; ++i) {
    std::string error;
    if (!rules.load_file(argv[i], &error)) {
      std::fprintf(stderr, "bench_rules: %s: %s\n", argv[i], error.c_str());
      return 3;
    }
  }
  const netcap::i64 load_us = netcap::now_monotonic_us() - load_started;

  const netcap::RuleStats& stats = rules.stats();
  std::printf("loaded %zu rule(s) from %d file(s) in %.0f ms\n", rules.size(), argc - 1,
              static_cast<double>(load_us) / 1000.0);
  std::printf("  lines %llu, block %llu, allow %llu, host %llu, generic %llu, "
              "element-hide %llu, comments %llu, skipped %llu\n",
              static_cast<unsigned long long>(stats.lines),
              static_cast<unsigned long long>(stats.block_rules),
              static_cast<unsigned long long>(stats.allow_rules),
              static_cast<unsigned long long>(stats.host_rules),
              static_cast<unsigned long long>(stats.generic_rules),
              static_cast<unsigned long long>(stats.element_hide),
              static_cast<unsigned long long>(stats.comments),
              static_cast<unsigned long long>(stats.skipped));
  const std::string skipped = rules.skipped_report(3);
  if (!skipped.empty()) std::fputs(skipped.c_str(), stdout);

  // The corpus: the seed requests a normal page makes, plus a lot of ordinary
  // same-site assets, which is what the engine spends most of its time on.
  std::vector<std::string> urls;
  for (const char* url : kSeedUrls) urls.push_back(url);
  for (int i = 0; i < 20000; ++i) {
    const int host_index = i % 37;
    std::string url = "https://cdn" + std::to_string(host_index) + ".example" +
                      std::to_string(i % 5) + ".com/assets/";
    url += (i % 3 == 0) ? "script" : (i % 3 == 1 ? "image" : "style");
    url += std::to_string(i) + (i % 3 == 1 ? ".jpg" : ".js") + "?ver=" + std::to_string(i);
    urls.push_back(std::move(url));
  }

  struct Tally {
    std::size_t blocked = 0;
    std::size_t allowed = 0;
    std::size_t modified = 0;
    std::size_t redirected = 0;
    std::size_t matched = 0;
    netcap::i64 us = 0;
  };

  const auto run_pass = [&](const std::vector<std::string>& corpus) {
    Tally tally;
    const netcap::i64 started = netcap::now_monotonic_us();
    for (std::size_t i = 0; i < corpus.size(); ++i) {
      const netcap::ResourceType type = kTypes[i % (sizeof(kTypes) / sizeof(kTypes[0]))];
      const netcap::RuleRequest request =
          netcap::rule_request_from_url(corpus[i], "news.example.org", type);
      const netcap::RuleDecision decision = rules.decide(request);
      switch (decision.action) {
        case netcap::RuleAction::Block: ++tally.blocked; break;
        case netcap::RuleAction::Allow: ++tally.allowed; break;
        case netcap::RuleAction::Modify: ++tally.modified; break;
        case netcap::RuleAction::Redirect: ++tally.redirected; break;
        case netcap::RuleAction::None: break;
      }
      if (decision.rule != nullptr) ++tally.matched;
    }
    tally.us = netcap::now_monotonic_us() - started;
    return tally;
  };

  // The corpus above is almost all misses, which is the common case.  The other
  // half of the story is the requests a list actually cares about, so the second
  // corpus is built out of the loaded list's own hosts: every one of them hits.
  const std::vector<std::string> listed_hosts = rules.blocked_hosts();
  std::vector<std::string> hit_urls;
  if (!listed_hosts.empty()) {
    const std::size_t stride = listed_hosts.size() > 2000 ? listed_hosts.size() / 2000 : 1;
    for (std::size_t i = 0; i < listed_hosts.size() && hit_urls.size() < 4000; i += stride) {
      hit_urls.push_back("https://" + listed_hosts[i] + "/assets/app.js?ver=7");
      hit_urls.push_back("https://" + listed_hosts[i] + "/pixel.gif");
    }
  }

  const auto report = [](const char* what, const std::vector<std::string>& corpus, const Tally& t) {
    const double per = corpus.empty()
                           ? 0.0
                           : static_cast<double>(t.us) / static_cast<double>(corpus.size());
    std::printf("\n%s: %zu decision(s) in %.1f ms\n", what, corpus.size(),
                static_cast<double>(t.us) / 1000.0);
    std::printf("  %.2f us per decision (%.0f decisions/s, single thread)\n", per,
                per > 0 ? 1000000.0 / per : 0.0);
    std::printf("  block %zu, allow %zu, modify %zu, redirect %zu, pass-through %zu\n", t.blocked,
                t.allowed, t.modified, t.redirected,
                corpus.size() - t.blocked - t.allowed - t.modified - t.redirected);
    std::printf("  %zu of %zu requests had a rule on them (%.1f%%) -- a 100-request page costs "
                "%.2f ms of rule time\n",
                t.matched, corpus.size(),
                corpus.empty()
                    ? 0.0
                    : 100.0 * static_cast<double>(t.matched) / static_cast<double>(corpus.size()),
                per * 100.0 / 1000.0);
  };

  rules.set_literal_index(true);
  const Tally indexed = run_pass(urls);
  report("ordinary traffic", urls, indexed);

  // The same corpus with the literal index switched off: that is the engine as it
  // was before the index existed, and the honest yardstick for it.
  rules.set_literal_index(false);
  const Tally linear = run_pass(urls);
  const auto per_decision = [](const Tally& t, std::size_t n) {
    return n ? static_cast<double>(t.us) / static_cast<double>(n) : 0.0;
  };
  const auto ratio = [&](const Tally& fast, const Tally& slow, std::size_t n) {
    const double a = per_decision(fast, n);
    const double b = per_decision(slow, n);
    return b / (a > 0 ? a : 1.0);
  };
  const bool same = linear.blocked == indexed.blocked && linear.allowed == indexed.allowed &&
                    linear.modified == indexed.modified && linear.redirected == indexed.redirected &&
                    linear.matched == indexed.matched;
  std::printf("\nwithout the literal index: %.2f us per decision (%.1fx slower, same answers: %s)\n",
              per_decision(linear, urls.size()), ratio(indexed, linear, urls.size()),
              same ? "yes" : "NO");

  if (!hit_urls.empty()) {
    rules.set_literal_index(true);
    const Tally hit_indexed = run_pass(hit_urls);
    rules.set_literal_index(false);
    const Tally hit_linear = run_pass(hit_urls);
    report("requests that hit the list", hit_urls, hit_indexed);
    std::printf("\nwithout the literal index: %.2f us per decision (%.1fx slower)\n",
                per_decision(hit_linear, hit_urls.size()),
                ratio(hit_indexed, hit_linear, hit_urls.size()));
  }
  return 0;
}
