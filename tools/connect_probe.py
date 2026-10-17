"""Two client shapes against the interception proxy, to see which one makes the
proxy record an error:

  1. connect and drop   -- what a browser does when it opens a speculative
                           connection and then abandons it (no TLS at all);
  2. connect and fetch  -- a full CONNECT + TLS + GET (what openssl does).

usage: python tools/connect_probe.py <proxy_port> <host> [--insecure]
Prints the proxy's answer to each step and how many bytes came back.
"""
import socket
import ssl
import sys


def connect(port: int, host: str, port_remote: int = 443) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    req = (
        f"CONNECT {host}:{port_remote} HTTP/1.1\r\n"
        f"Host: {host}:{port_remote}\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
    )
    s.sendall(req.encode())
    head = b""
    while b"\r\n\r\n" not in head and len(head) < 8192:
        chunk = s.recv(1024)
        if not chunk:
            break
        head += chunk
    print("  proxy says:", head.split(b"\r\n")[0].decode("latin1", "replace"))
    return s


def fetch(port: int, host: str, path: str = "/", insecure: bool = False) -> tuple:
    """CONNECT + TLS + GET, returning (status line, headers text, body bytes)."""
    s = connect(port, host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED
    if not insecure:
        ctx.load_verify_locations(r"D:\Demo\FilterTheWeb\_mitmca.crt")
    tls = ctx.wrap_socket(s, server_hostname=host)
    tls.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
        "Accept-Language: zh-CN,zh;q=0.9\r\n"
        "Connection: close\r\n\r\n".encode()
    )
    data = b""
    while True:
        chunk = tls.recv(65536)
        if not chunk:
            break
        data += chunk
    tls.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode("latin1", "replace"), head.decode("latin1", "replace"), body


def follow(port: int, host: str, insecure: bool) -> int:
    """What a browser does with a redirect: hop 1, read Location, hop 2."""
    print(f"hop 1: {host}")
    status, head, body = fetch(port, host, "/", insecure)
    print("  ", status, "bytes:", len(body))
    location = ""
    for line in head.split("\r\n"):
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
    print("   location:", location)
    if not location:
        return 0
    target = location.split("//", 1)[-1]
    next_host = target.split("/", 1)[0]
    next_path = "/" + target.split("/", 1)[1] if "/" in target else "/"
    print(f"hop 2: {next_host}{next_path}")
    status, head, body = fetch(port, next_host, next_path, insecure)
    print("  ", status, "bytes:", len(body))
    if body[:15].lower().startswith(b"<!doctype html>") or b"<html" in body[:2048].lower():
        print("   got html:", len(body), "bytes")
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port, host = int(sys.argv[1]), sys.argv[2]
    insecure = "--insecure" in sys.argv
    if "--follow" in sys.argv:
        return follow(port, host, insecure)

    print("1) connect and drop (no TLS, close right away)")
    s = connect(port, host)
    s.close()

    print("2) connect, TLS, GET / (like openssl)")
    s = connect(port, host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED
    if not insecure:
        ctx.load_verify_locations(r"D:\Demo\FilterTheWeb\_mitmca.crt")
    try:
        tls = ctx.wrap_socket(s, server_hostname=host)
        print("  tls:", tls.version(), tls.cipher()[0])
        tls.sendall(
            b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            b"Accept: */*\r\nConnection: close\r\n\r\n"
        )
        data = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            data += chunk
        print("  status:", data.split(b"\r\n")[0].decode("latin1", "replace"))
        print("  bytes:", len(data))
        tls.close()
    except Exception as exc:  # noqa: BLE001 - the point is to report it
        print("  tls failed:", exc)
        s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
