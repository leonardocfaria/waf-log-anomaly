"""A tiny local "shop" web app that writes an nginx-style combined access log.

Behind-a-proxy semantics, trusted from loopback only (like nginx real_ip): X-Forwarded-For sets the logged
client IP, X-Sim-Time (epoch seconds) sets the logged time, X-Label is written to a separate labels file
(same line order) and never to the log. Not vulnerable to anything: it only returns status codes.

python -m waf.app --port 8000 --log data/access.log --labels data/labels.csv
"""
import argparse
import ipaddress
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

_PAGES = re.compile(r"^/($|products/\d+$|search$|blog/[\w-]+$|cart$|static/[\w.-]+$|category/\d+$|login$|item$|download$|about$)")


def trusted(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def route(method: str, path: str, query: str) -> int:
    """Status code the shop returns. /item errors on a non-numeric id like a naive SQL backend would."""
    if not _PAGES.match(path):
        return 404
    if path == "/login" and method == "POST":
        return 401
    if path == "/item":
        m = re.fullmatch(r"id=(\d+)", query)
        return 200 if m else 500
    if path == "/download" and ".." in query:
        return 403
    return 200


def _q(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        if 0 < n <= 65536:
            self.rfile.read(n)
        url = urlsplit(self.path)
        status = route(self.command, url.path, url.query)
        body = b"ok" if status == 200 else b"error"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        ip, ts, label = self.client_address[0], time.time(), "unknown"
        if self.server.trust_headers or self.server.loopback_check(ip):
            ip = self.headers.get("X-Forwarded-For", ip).split(",")[0].strip() or ip
            ts = self.headers.get("X-Sim-Time", ts)
            label = self.headers.get("X-Label", label)
        try:
            t = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime(float(ts)))
        except (ValueError, OverflowError, OSError):  # junk / nan / out-of-range X-Sim-Time
            t = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        line = (f'{ip} - - [{t}] "{self.command} {_q(self.path)} {self.request_version}" {status} {len(body)} '
                f'"{_q(self.headers.get("Referer", "-"))}" "{_q(self.headers.get("User-Agent", "-"))}"\n')
        with self.server.lock:
            self.server.log.write(line)
            self.server.log.flush()
            if self.server.labels:
                self.server.labels.write(label + "\n")
                self.server.labels.flush()

    do_GET = do_POST = do_HEAD = _handle


class _Server(HTTPServer):
    def server_close(self):
        super().server_close()
        self.log.close()
        if self.labels:
            self.labels.close()


def make_server(host: str, port: int, log_path: str, labels_path: str | None = None,
                trust_headers: bool = False) -> HTTPServer:
    """trust_headers: honour the X-* headers from any client (only for the compose demo network)."""
    srv = _Server((host, port), Handler)
    srv.trust_headers, srv.loopback_check = trust_headers, trusted
    srv.lock = threading.Lock()
    srv.log = open(log_path, "a", encoding="utf-8")
    srv.labels = open(labels_path, "a", encoding="utf-8") if labels_path else None
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log", default="data/access.log")
    ap.add_argument("--labels", default=None)
    ap.add_argument("--trust-headers", action="store_true", help="honour X-* headers from non-loopback clients")
    a = ap.parse_args()
    print(f"dummy app on http://{a.host}:{a.port}, logging to {a.log}")
    make_server(a.host, a.port, a.log, a.labels, a.trust_headers).serve_forever()
