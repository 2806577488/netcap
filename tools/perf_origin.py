"""Tiny HTTP/1.1 origin used by tools/perf_plain.ps1 for netcap throughput runs.

Endpoints:
  /tiny   -> 1 byte          (latency probe)
  /page   -> 64 KiB of HTML  (rewrite / rule matching probe)
  /big    -> 8 MiB           (bulk throughput probe)

Usage:
  python tools/perf_origin.py [port]                  # plain HTTP
  python tools/perf_origin.py [port] <cert> <key>     # HTTPS (TLS 1.3 online)
"""
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TINY = b"x"
PAGE = b"<p>hello tracker</p>\n" * 4096
BIG = (b"0123456789abcdef" * 64) * 8192


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path.endswith("/big"):
            self._send(BIG, "application/octet-stream")
        elif path.endswith("/page"):
            self._send(PAGE, "text/html; charset=utf-8")
        else:
            self._send(TINY, "text/plain")

    def log_message(self, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9101
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    if len(sys.argv) > 3:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(sys.argv[2], sys.argv[3])
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print("https origin listening on 127.0.0.1:%d" % port, flush=True)
    else:
        print("origin listening on 127.0.0.1:%d" % port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
