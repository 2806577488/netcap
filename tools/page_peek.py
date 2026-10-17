"""Print what a served page actually is: title, a body excerpt and a few markers.

usage: python tools/page_peek.py <page.html> [marker ...]
"""
import re
import sys

sys.path.insert(0, "tools")
from css_inject_probe import strip_http  # noqa: E402


def main() -> int:
    path = sys.argv[1]
    markers = sys.argv[2:] or [
        "captcha", "unusual traffic", "sb_form", "b_results", "b_algo",
        "noscript", "location.href", "window.location", "<title",
    ]
    text = strip_http(open(path, "rb").read()).decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    print("title      :", (m.group(1).strip()[:120] if m else "(none)"))
    body = text
    i = text.lower().find("<body")
    if i >= 0:
        body = text[i:]
        print("body start :", repr(body[:220]))
    print("body bytes :", len(body), " text bytes:", len(text))
    for k in markers:
        print(f"  {k!r:24} {text.count(k)}")
    # Selectors in the injected CSS that mention one of the given words: these are
    # the rules that would hide this page's own markup.
    wanted = [w for w in ("b_algo", "b_results", "b_content", "b_respl") if w in text]
    if wanted:
        styles = re.findall(r"<style[^>]*>(.*?)</style>", text, re.S)
        css = "\n".join(styles)
        print("injected selectors mentioning", wanted, ":")
        shown = 0
        for line in css.split("\n"):
            sel = line.split("{")[0].strip()
            if not sel or sel.startswith("/*"):
                continue
            if any(w in sel for w in wanted):
                print("   ", sel[:160])
                shown += 1
                if shown >= 25:
                    print("    ... and more")
                    break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
