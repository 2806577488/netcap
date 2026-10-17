#!/usr/bin/env python3
"""Adversarial client for the netcap intercept proxy.

The proxy is meant to be the thing every program on the machine talks to, so a
malformed request must never take it down: one dead proxy port looks exactly
like "the network broke".  This script throws a set of hostile requests at it
and then checks that it is still answering.

Usage:  python tools/proxy_fuzz.py [host:port] [--rounds N]
"""

import socket
import sys
import time

HOST = "127.0.0.1"
PORT = 8117


def talk(payload: bytes, wait: float = 1.0, label: str = "") -> bytes:
    """Send one raw request and read whatever comes back (possibly nothing)."""
    try:
        sock = socket.create_connection((HOST, PORT), timeout=4.0)
    except OSError as exc:
        print(f"  {label}: cannot even connect: {exc}")
        return b""
    with sock:
        sock.settimeout(wait)
        try:
            sock.sendall(payload)
        except OSError as exc:
            print(f"  {label}: send failed: {exc}")
            return b""
        chunks = []
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                part = sock.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not part:
                break
            chunks.append(part)
            if sum(len(c) for c in chunks) > 4096:
                break
        return b"".join(chunks)


def alive() -> bool:
    """A plain, well formed request must still be answered."""
    reply = talk(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
                 wait=6.0, label="liveness")
    return reply.startswith(b"HTTP/")


def main() -> int:
    global HOST, PORT
    rounds = 6
    args = sys.argv[1:]
    while args:
        arg = args.pop(0)
        if arg == "--rounds" and args:
            rounds = int(args.pop(0))
        elif ":" in arg:
            HOST, port_text = arg.split(":", 1)
            PORT = int(port_text)
    print(f"fuzzing the proxy at {HOST}:{PORT} ({rounds} round(s))")

    big = str(1 << 40).encode()
    cases: list[tuple[str, bytes]] = [
        # A declared body length is not a promise; it must be refused, not read.
        ("huge content-length", b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                               b"Content-Length: " + big + b"\r\n\r\n"),
        ("negative content-length", b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                                   b"Content-Length: -1\r\n\r\nx"),
        ("no digit content-length", b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                                   b"Content-Length: nope\r\n\r\n"),
        ("chunked body, never terminated", b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                                           b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"),
        ("chunk size that is not hex", b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                                       b"Transfer-Encoding: chunked\r\n\r\nzz\r\n"),
        ("one 100 KiB header", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Big: " +
                              b"a" * (100 * 1024) + b"\r\n\r\n"),
        ("HTTP/2 preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        ("bare CRLF soup", b"\r\n\r\n\r\n"),
        ("CONNECT without a port", b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("CONNECT with a huge port", b"CONNECT example.com:99999999999 HTTP/1.1\r\n\r\n"),
        ("method that is not a token", b"\x00\x01\x02\x03 http://example.com/ HTTP/1.1\r\n\r\n"),
        ("absolute URL with no host", b"GET http:/// HTTP/1.1\r\n\r\n"),
        ("TLS record where HTTP belongs", b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"),
        ("doubled content-length", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                                  b"Content-Length: 1\r\nContent-Length: 2\r\n\r\n"),
    ]

    failures = 0
    for round_index in range(rounds):
        for label, payload in cases:
            reply = talk(payload)
            first = reply.split(b"\r\n", 1)[0].decode("latin-1") if reply else "(no reply)"
            print(f"  round {round_index + 1} {label}: {first}")
        if not alive():
            failures += 1
            print(f"  round {round_index + 1}: THE PROXY STOPPED ANSWERING")
            break

    print(f"done: {failures} round(s) lost the proxy")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
