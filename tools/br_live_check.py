#!/usr/bin/env python3
"""Live check of what our proxy does with a `Content-Encoding: br` page.

Connects to the proxy, opens a CONNECT tunnel to the host, speaks TLS to it (we
present the netcap CA, so verification is off), asks for the path with
`Accept-Encoding: br`, and then inspects the bytes that actually came back:

* is the body framed the way the head claims (no leftover `Transfer-Encoding:
  chunked` in front of an unframed body, and `Content-Length` matching)?
* does the body still decode as Brotli, and to what size?
* did our element-hiding CSS get injected into the decoded HTML?

Usage: python tools/br_live_check.py <proxy_port> [host] [path] [--ca _mitmca.crt]
"""
import socket
import ssl
import sys

import brotli

REQUEST = (
    "GET {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0\r\n"
    "Accept: text/html,application/xhtml+xml\r\n"
    "Accept-Encoding: br\r\n"
    "Sec-Fetch-Dest: document\r\n"
    "Sec-Fetch-Mode: navigate\r\n"
    "Connection: close\r\n\r\n"
)


def fetch(proxy_port: int, host: str, path: str, ca: str | None):
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=30)
    raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        part = raw.recv(4096)
        if not part:
            raise RuntimeError("the proxy closed the tunnel before answering CONNECT")
        head += part
    status = head.split(b"\r\n", 1)[0].decode("latin1")
    if "200" not in status:
        raise RuntimeError(f"CONNECT was refused: {status}")

    if ca:
        context = ssl.create_default_context(cafile=ca)
        context.check_hostname = True
    else:
        context = ssl._create_unverified_context()  # noqa: SLF001 - a test tool
    tls = context.wrap_socket(raw, server_hostname=host)
    tls.sendall(REQUEST.format(path=path, host=host).encode())
    data = b""
    while True:
        part = tls.recv(65536)
        if not part:
            break
        data += part
    tls.close()
    return status, data


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    proxy_port = int(sys.argv[1])
    host = sys.argv[2] if len(sys.argv) > 2 else "www.bing.com"
    path = sys.argv[3] if len(sys.argv) > 3 else "/search?q=test"
    ca = sys.argv[4] if len(sys.argv) > 4 else None

    tunnel, data = fetch(proxy_port, host, path, ca)
    head, _, body = data.partition(b"\r\n\r\n")
    lines = [l.decode("latin1") for l in head.split(b"\r\n") if l]
    print("CONNECT :", tunnel)
    print("status  :", lines[0] if lines else "(none)")
    framing = {}
    for line in lines:
        name, _, value = line.partition(":")
        if name.strip().lower() in ("content-length", "content-encoding", "transfer-encoding"):
            framing[name.strip().lower()] = value.strip()
    print("headers :", framing or "(none of content-length/encoding/transfer-encoding)")

    problems = []
    if framing.get("transfer-encoding", "").lower() == "chunked":
        problems.append("the head still says chunked while the body is what it is")
    if "content-length" in framing and int(framing["content-length"]) != len(body):
        problems.append(f"Content-Length {framing['content-length']} != body {len(body)}")

    encoding = framing.get("content-encoding", "identity")
    print("body    :", len(body), "bytes, first", body[:8].hex())
    if encoding == "br":
        try:
            decoded = brotli.decompress(body)
            print("decoded :", len(decoded), "bytes of", encoding)
            if b"display:none !important" in decoded:
                hits = decoded.count(b"display:none !important")
                print("injected:", hits, "element-hiding rule(s) inside a <style> block")
            else:
                print("injected: no hiding CSS (the page was forwarded unchanged)")
        except Exception as exc:  # noqa: BLE001 - any failure is a failure here
            problems.append(f"the body does not decode as brotli: {exc}")
    else:
        print("decoded : not brotli (encoding is", encoding, ")")

    if problems:
        print("FAILED:")
        for p in problems:
            print("  -", p)
        return 1
    print("OK: the framing header and the body agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
