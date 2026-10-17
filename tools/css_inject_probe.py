"""Inspect a page we served through netcap: what did we inject, and would it hide
the page's own content?

usage: python tools/css_inject_probe.py <page.html> [marker ...]

It prints the response size, whether the document is complete, how many style
blocks we injected, and for every marker (a CSS selector fragment or class name)
how often it appears in the page body versus inside the injected CSS.  A marker
that appears in the injected CSS but not in the body is harmless; one that
appears in both is a rule that will hide real content in a browser.
"""
import re
import sys


def strip_http(raw: bytes) -> bytes:
    """Drop a leading HTTP response head and undo chunked framing, so the probe
    can also read a response captured with `openssl s_client`."""
    if not raw.startswith(b"HTTP/"):
        return raw
    head, _, rest = raw.partition(b"\r\n\r\n")
    headers = head.decode("latin-1").lower()
    if "transfer-encoding: chunked" not in headers:
        return rest
    out = bytearray()
    while True:
        line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return bytes(out) + line + rest
        if size == 0:
            return bytes(out)
        out += rest[:size]
        rest = rest[size + 2:]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    markers = sys.argv[2:] or [".b_algo", ".b_results", ".b_content", "#b_content"]
    raw = open(path, "rb").read()
    raw = strip_http(raw)
    text = raw.decode("utf-8", "replace")
    styles = re.findall(r"<style[^>]*>(.*?)</style>", text, re.S)
    injected = max(styles, key=len) if styles else ""
    body = text
    for s in styles:
        body = body.replace(s, "")
    print(f"file            : {path}")
    print(f"bytes           : {len(raw)}")
    print(f"complete html   : {'<html' in text} .. {text.rstrip()[-24:]!r}")
    print(f"style blocks    : {len(styles)}  injected css bytes: {len(injected)}")
    print(f"injected rules  : {injected.count('display:none !important}')}")
    for m in markers:
        print(f"marker {m!r:24} body={body.count(m):5d}  injected-css={injected.count(m):5d}")
    # a couple of the host scoped rules, if any
    host = re.findall(r"[a-z0-9.\-]+\.[a-z]{2,}##[^,\n]+", injected)
    print(f"host scoped     : {len(host)}")
    for h in host[:8]:
        print("   ", h[:120])
    i = text.find("<style")
    if i >= 0:
        print("injection site  :", repr(text[max(0, i - 140):i + 24]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
