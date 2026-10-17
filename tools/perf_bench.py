"""Latency / throughput probe for the netcap interception proxy.

Usage: python tools/perf_bench.py <rules_proxy> <empty_proxy> <rewrite_proxy>

Measures against the origin from tools/perf_origin.py (127.0.0.1:9101):
  * direct, keep-alive and new-connection-per-request baselines
  * the proxy with 5201 rules, with no rules, and with response rewriting
Everything is sequential so the numbers stay comparable.
"""
import http.client
import statistics
import sys
import time

ORIGIN = ("127.0.0.1", 9101)
TINY_REQUESTS = 200
PAGE_REQUESTS = 40


def _pct(values, q):
    return values[min(len(values) - 1, int(len(values) * q))]


def report(name, ms):
    ms = sorted(ms)
    print(
        "%-28s n=%-4d median=%7.2f ms  p95=%7.2f ms  min=%7.2f  max=%7.2f"
        % (name, len(ms), statistics.median(ms), _pct(ms, 0.95), ms[0], ms[-1])
    )


def tiny_direct_keepalive(n):
    conn = http.client.HTTPConnection(*ORIGIN, timeout=15)
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        conn.request("GET", "/tiny")
        conn.getresponse().read()
        samples.append((time.perf_counter() - start) * 1000.0)
    conn.close()
    return samples


def tiny_direct_newconn(n):
    samples = []
    for _ in range(n):
        conn = http.client.HTTPConnection(*ORIGIN, timeout=15)
        start = time.perf_counter()
        conn.request("GET", "/tiny")
        conn.getresponse().read()
        samples.append((time.perf_counter() - start) * 1000.0)
        conn.close()
    return samples


def tiny_proxy(port, n):
    samples = []
    for _ in range(n):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        start = time.perf_counter()
        conn.request("GET", "http://127.0.0.1:9101/tiny")
        conn.getresponse().read()
        samples.append((time.perf_counter() - start) * 1000.0)
        conn.close()
    return samples


def page_proxy(port, n):
    """64 KiB HTML through the proxy: catches the response-rewrite path."""
    samples = []
    sizes = set()
    for _ in range(n):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        start = time.perf_counter()
        conn.request("GET", "http://127.0.0.1:9101/page")
        body = conn.getresponse().read()
        samples.append((time.perf_counter() - start) * 1000.0)
        sizes.add(len(body))
        conn.close()
    return samples, sorted(sizes)


def probe_keepalive(port):
    """Does the proxy reuse one client connection?  Three requests, one socket."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    ms = []
    try:
        for _ in range(3):
            start = time.perf_counter()
            conn.request("GET", "http://127.0.0.1:9101/tiny")
            conn.getresponse().read()
            ms.append((time.perf_counter() - start) * 1000.0)
        reused = True
    except Exception as exc:  # noqa: BLE001 - the point is to report the failure
        reused = False
        print("   keep-alive probe stopped after %d request(s): %s" % (len(ms), exc))
    finally:
        conn.close()
    if ms:
        print("   one client socket, %d request(s): %s | reused=%s"
              % (len(ms), ", ".join("%.2f ms" % m for m in ms), reused))
    return reused


def bulk(port):
    start = time.perf_counter()
    if port is None:
        conn = http.client.HTTPConnection(*ORIGIN, timeout=120)
        conn.request("GET", "/big")
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        conn.request("GET", "http://127.0.0.1:9101/big")
    body = conn.getresponse().read()
    elapsed = time.perf_counter() - start
    conn.close()
    return len(body), elapsed


def main():
    rules_port = int(sys.argv[1])
    empty_port = int(sys.argv[2])
    rewrite_port = int(sys.argv[3]) if len(sys.argv) > 3 else rules_port

    print("-- 1 byte request, 200 in a row --")
    report("direct (keep-alive)", tiny_direct_keepalive(TINY_REQUESTS))
    report("direct (new conn)", tiny_direct_newconn(TINY_REQUESTS))
    report("proxy %d (5201 rules)" % rules_port, tiny_proxy(rules_port, TINY_REQUESTS))
    report("proxy %d (no rules)" % empty_port, tiny_proxy(empty_port, TINY_REQUESTS))

    print("-- client connection reuse --")
    print("   proxy %d:" % rules_port)
    probe_keepalive(rules_port)

    print("-- 64 KiB HTML page --")
    for label, port in (("proxy %d (5201 rules)" % rules_port, rules_port),
                        ("proxy %d (rewrite)" % rewrite_port, rewrite_port)):
        samples, sizes = page_proxy(port, PAGE_REQUESTS)
        report(label, samples)
        print("   body sizes seen: %s" % sizes)

    print("-- 8 MiB download --")
    for label, port in (("direct", None), ("proxy %d" % rules_port, rules_port)):
        size, elapsed = bulk(port)
        print(
            "%-28s %7.2f MiB in %6.3f s = %7.2f MiB/s  (%.0f Mbit/s)"
            % (label, size / 1048576.0, elapsed, size / 1048576.0 / elapsed,
               size * 8 / 1e6 / elapsed)
        )


if __name__ == "__main__":
    main()
