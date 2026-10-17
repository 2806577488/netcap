"""Interoperability check for the netcap HTTPS interception proxy.

Run the proxy first, then point this script at it::

    netcap.exe --jsonl --rules sample.rules --serve 127.0.0.1:18099 --mitm --ca _mitmca
    python tools/mitm_check.py 18099 _mitmca.crt

Why this script exists: the proxy is verified with a TLS stack that is not the
Windows one. Python's ``ssl`` module is OpenSSL, and OpenSSL 3.5 sends the
post-quantum hybrid key share ``X25519MLKEM768`` first -- exactly like Chrome
124 and later. That exercises the HelloRetryRequest path in the proxy, which a
plain x25519 client never touches. curl and Edge on this machine use schannel,
which cannot do TLS 1.3 inside a CONNECT tunnel at all, so they are useless as
an acceptance client.
"""

import http.client
import ssl
import sys

BLOCKED_HOST = "ads.example.com"  # matches "||ads.example.com^" in sample.rules


def fetch(port, ctx, host, path):
    """Fetch https://host/path through the proxy. Returns (status, body, cert)."""
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=20)
    conn.set_tunnel(host, 443)
    try:
        conn.request("GET", path, headers={"Host": host, "Connection": "close"})
        sock = conn.sock  # live right after request(): that is where the handshake ran
        peer = (sock.getpeercert() or {}) if sock is not None else {}
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, body, peer
    finally:
        conn.close()


def describe(peer):
    subject = dict(item[0] for item in peer.get("subject", ()))
    issuer = dict(item[0] for item in peer.get("issuer", ()))
    return "leaf cn=%s issuer=%s san=%s" % (
        subject.get("commonName"),
        issuer.get("commonName"),
        peer.get("subjectAltName"),
    )


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port = int(sys.argv[1])
    ctx = ssl.create_default_context(cafile=sys.argv[2])
    failures = []

    status, body, peer = fetch(port, ctx, "example.com", "/")
    print("example.com/        -> %s  bytes=%d" % (status, len(body)))
    print("    " + describe(peer))
    print("    body head: %r" % body[:60])
    if status != 200:
        failures.append("example.com returned %s, expected 200" % status)
    if b"Example Domain" not in body:
        failures.append("example.com body does not look like the real page")
    if "netcap local CA" not in describe(peer):
        failures.append("the leaf certificate was not issued by the local CA")

    # A blocked host is refused at the CONNECT stage, so the tunnel never opens.
    try:
        status, body, _ = fetch(port, ctx, BLOCKED_HOST, "/banner.gif")
        print("%s -> %s (the proxy answered instead of refusing)" % (BLOCKED_HOST, status))
        if status != 403:
            failures.append("%s returned %s, expected 403" % (BLOCKED_HOST, status))
    except OSError as exc:
        print("%s -> refused the tunnel: %s" % (BLOCKED_HOST, exc))
        if "403" not in str(exc):
            failures.append("%s was not refused with 403: %s" % (BLOCKED_HOST, exc))

    print("RESULT: %s" % ("PASS" if not failures else "FAIL"))
    for line in failures:
        print("  - " + line)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
