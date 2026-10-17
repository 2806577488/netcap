#!/usr/bin/env python3
"""Checks that a response we cannot rewrite still has a head that matches its body.

Starts a tiny origin server that answers with `Transfer-Encoding: chunked` and a
Brotli body (`Content-Encoding: br`) -- i.e. something netcap plans to rewrite
(there are element-hiding rules for it) but cannot, because Brotli decoding is
still missing.  The response is then fetched *through* netcap with a raw socket
so the bytes on the wire can be inspected: the head must not claim chunked
framing in front of an unframed body.

Usage: python tools/chunked_br_check.py <proxy_port> [origin_port]
"""
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import brotli

PAGE = ("<!doctype html><html><head><title>chunked brotli</title></head><body>"
        + "<div class='ad-box'>buy</div>" * 200
        + "</body></html>").encode()


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 so that chunked framing is the origin's real choice: with HTTP/1.0
    # a response without Content-Length is legitimately delimited by the close,
    # and the check below would be testing nothing.
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - the name is fixed by BaseHTTPRequestHandler
        packed = brotli.compress(PAGE, quality=5)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Encoding", "br")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        # chunked framing, 4 KiB chunks
        for i in range(0, len(packed), 4096):
            part = packed[i:i + 4096]
            self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    def log_message(self, *args):
        pass


def raw_get(port: int, target: str, host: str) -> bytes:
    request = (f"GET {target} HTTP/1.1\r\nHost: {host}\r\n"
               "Sec-Fetch-Dest: document\r\n"
               "Accept: text/html\r\nAccept-Encoding: br\r\n"
               "Connection: close\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    proxy_port = int(sys.argv[1])
    origin_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8898

    server = ThreadingHTTPServer(("127.0.0.1", origin_port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    problems = []
    try:
        raw = raw_get(proxy_port, f"http://127.0.0.1:{origin_port}/page", f"127.0.0.1:{origin_port}")
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = [l.decode("latin1") for l in head.split(b"\r\n") if l]
        print("status :", lines[0] if lines else "(no status line)")
        for want in ("content-encoding", "content-length", "transfer-encoding"):
            for line in lines:
                if line.lower().startswith(want):
                    print("header :", line)
        print("body   :", len(body), "bytes, first", body[:12].hex())

        if any(l.lower().startswith("transfer-encoding") and "chunked" in l.lower() for l in lines):
            problems.append("the head still advertises chunked framing")
        lengths = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("content-length")]
        if not lengths:
            problems.append("there is no Content-Length")
        elif int(lengths[0]) != len(body):
            problems.append(f"Content-Length says {lengths[0]} but the body is {len(body)} bytes")
        try:
            decoded = brotli.decompress(body)
            print("brotli : decodes to", len(decoded), "bytes")
        except Exception as exc:  # noqa: BLE001 - any failure is a failure here
            problems.append(f"the body is not a brotli stream: {exc}")
    finally:
        server.shutdown()
        server.server_close()

    if problems:
        print("FAILED:")
        for p in problems:
            print("  -", p)
        return 1
    print("OK: the framing header and the body agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
