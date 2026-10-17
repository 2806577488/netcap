"""End to end check of the compression gate in apply_response_rewrite().

A `br` body that no rule can edit (an `application/javascript` asset while the
only rule in scope is a cosmetic one) must reach the client byte for byte, still
compressed.  A `br` `text/html` body with the same rule in scope must be inflated,
edited and sent as identity.  Run it against a live proxy:

    python tools/br_encoding_gate_check.py <proxy_port> [origin_port]
"""

import http.server
import socket
import socketserver
import sys
import threading

import brotli

ASSET_JS = b"var a = 1;\nfunction f(x) { return x + a; }\n" * 40
PAGE_HTML = b"<html><head><title>gate</title></head><body><div class=\"ad-box\">ad</div>ok</body></html>"

ASSET_BR = brotli.compress(ASSET_JS, quality=5)
PAGE_BR = brotli.compress(PAGE_HTML, quality=5)


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - the name is fixed by the base class
        if self.path.startswith("/asset.js"):
            body, ctype = ASSET_BR, "application/javascript"
        elif self.path.startswith("/page.html"):
            body, ctype = PAGE_BR, "text/html; charset=utf-8"
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Encoding", "br")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the output clean
        pass


def fetch(port, path):
    """One proxied plain HTTP request; returns (status_line, headers, body)."""
    with socket.create_connection(("127.0.0.1", port), timeout=20) as s:
        request = (
            "GET http://127.0.0.1:%d%s HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: br\r\n"
            "Sec-Fetch-Dest: %s\r\n"
            "Connection: close\r\n\r\n"
            % (ORIGIN_PORT, path, ORIGIN_PORT,
               "document" if path.endswith(".html") else "script")
        )
        s.sendall(request.encode("ascii"))
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return lines[0], headers, body


def main():
    global ORIGIN_PORT
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    proxy_port = int(sys.argv[1])
    ORIGIN_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8899

    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", ORIGIN_PORT), Origin)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    failures = []

    status, headers, body = fetch(proxy_port, "/asset.js")
    print("asset.js :", status)
    print("  content-encoding :", headers.get("content-encoding", "(none)"))
    print("  content-length   :", headers.get("content-length"), "origin", len(ASSET_BR))
    print("  body bytes       :", len(body), "same as origin:", body == ASSET_BR)
    if "br" not in headers.get("content-encoding", ""):
        failures.append("the javascript asset lost its Content-Encoding: br")
    if body != ASSET_BR:
        failures.append("the javascript asset came back re-encoded (%d bytes vs %d)"
                        % (len(body), len(ASSET_BR)))

    status, headers, body = fetch(proxy_port, "/page.html")
    text = body.decode("utf-8", "replace")
    print("page.html:", status)
    print("  content-encoding :", headers.get("content-encoding", "(none)"))
    print("  content-length   :", headers.get("content-length"), "body", len(body))
    injected = text.count("display:none !important}")
    print("  injected rules   :", injected)
    if "br" in headers.get("content-encoding", ""):
        failures.append("the html page was not inflated")
    if injected == 0:
        failures.append("the html page did not get any hiding rule")
    if len(body) <= len(PAGE_BR):
        failures.append("the html page is not bigger than its compressed form")

    httpd.shutdown()
    if failures:
        for line in failures:
            print("FAIL:", line)
        return 1
    print("OK: the gate keeps uneditable compressed bodies alone and still edits pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
