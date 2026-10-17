"""Break down the HTTPS MITM path: CONNECT, both TLS handshakes, and bulk transfer.

Starts the loopback origins and the netcap MITM proxy itself, then runs the same
download directly and through the proxy so the two can be compared phase by phase.

Usage: python tools/perf_mitm.py
"""
import os
import socket
import ssl
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NETCAP = os.path.join(ROOT, "build", "netcap.exe")
TLS_PORT = 9543
PROXY_PORT = 8093
CA = os.path.join(ROOT, "_mitmca")
ORIGIN = os.path.join(ROOT, "tools", "perf_origin.py")

children = []


def start(args):
    proc = subprocess.Popen(
        args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    children.append(proc)
    return proc


def wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), 0.25)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def read_head(sock, limit=8192):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data


def client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def open_direct():
    raw = socket.create_connection(("127.0.0.1", TLS_PORT), 10)
    start = time.perf_counter()
    tls = client_context().wrap_socket(raw, server_hostname="localhost")
    return tls, (time.perf_counter() - start) * 1000.0, 0.0, b""


def open_via_proxy():
    raw = socket.create_connection(("127.0.0.1", PROXY_PORT), 10)
    start = time.perf_counter()
    raw.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n"
                 % (TLS_PORT, TLS_PORT)).encode())
    head = read_head(raw)
    connect_ms = (time.perf_counter() - start) * 1000.0
    start = time.perf_counter()
    tls = client_context().wrap_socket(raw, server_hostname="localhost")
    return tls, connect_ms, (time.perf_counter() - start) * 1000.0, head


def download(sock, path, chunk=65536):
    start = time.perf_counter()
    sock.sendall(("GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" % path).encode())
    first = None
    total = 0
    reads = 0
    while True:
        data = sock.recv(chunk)
        if not data:
            break
        if first is None:
            first = time.perf_counter()
        total += len(data)
        reads += 1
    end = time.perf_counter()
    return total, (first - start) * 1000.0, (end - start) * 1000.0, reads


def case(name, opener, repeats=5):
    handshakes = []
    connects = []
    samples = []
    for _ in range(repeats):
        try:
            sock, connect_ms, handshake_ms, _head = opener()
        except Exception as exc:  # noqa: BLE001 - report and stop
            print("   %s failed to connect: %s" % (name, exc))
            return None
        connects.append(connect_ms)
        handshakes.append(handshake_ms)
        sock.close()
    for path in ("/tiny", "/big"):
        try:
            sock, _c, _h, _head = opener()
        except Exception as exc:  # noqa: BLE001
            print("   %s could not open a connection for %s: %s" % (name, path, exc))
            continue
        try:
            samples.append((path,) + download(sock, path))
        except Exception as exc:  # noqa: BLE001
            print("   %s %s failed: %s" % (name, path, exc))
        finally:
            sock.close()
    return connects, handshakes, samples


def show(name, result):
    if not result:
        return
    connects, handshakes, samples = result
    print("-- %s --" % name)
    print("   setup: connect/CONNECT median %6.1f ms | TLS handshake median %7.1f ms (n=%d)"
          % (statistics.median(connects), statistics.median(handshakes), len(handshakes)))
    for path, total, first_ms, wall_ms, reads in samples:
        mib = total / 1048576.0
        rate = mib / (wall_ms / 1000.0) if wall_ms else 0.0
        print("   %-5s %9d bytes | first byte %8.1f ms | total %8.1f ms | %7.2f MiB/s | %d recv() calls"
              % (path, total, first_ms, wall_ms, rate, reads))


def main():
    if "--client-only" in sys.argv:
        # The proxy and the origins are already running (used with NETCAP_MITM_TRACE=1).
        show("through the running proxy", case("proxy", open_via_proxy, repeats=1))
        return 0
    start([sys.executable, ORIGIN, str(TLS_PORT), os.path.join(ROOT, "_mitmca.crt"),
           os.path.join(ROOT, "_mitmca.key")])
    if not wait_port(TLS_PORT):
        print("https origin did not start")
        return 1
    start([NETCAP, "--serve", "127.0.0.1:%d" % PROXY_PORT, "--rules", os.path.join(ROOT, "sample.rules"),
           "--ca", CA, "--mitm", "--mitm-insecure"])
    if not wait_port(PROXY_PORT):
        print("mitm proxy did not start")
        return 1
    time.sleep(0.5)
    try:
        show("direct TLS to the origin", case("direct", open_direct))
        show("through netcap --serve --mitm", case("proxy", open_via_proxy))
    finally:
        for proc in children:
            proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
