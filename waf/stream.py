"""Streaming mode: tail an access log, score each line, keep per-client aggregates, serve a dashboard.

python -m waf.stream --train data/benign.log --log data/access.log --port 8090
"""
import argparse
import html
import json
import os
import queue
import sys
import threading
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from waf.detect import Detector

MAX_LINE = 1_000_000


def follow(path: str, stop: threading.Event, poll: float = 0.2, from_start: bool = False):
    """Yield complete lines appended to path until stop is set. Survives truncation and rotation (reopens)."""
    f, buf, ino = None, "", None
    while not stop.is_set():
        if f is None:
            try:
                f = open(path, encoding="utf-8", errors="replace", newline="\n")
            except FileNotFoundError:
                from_start = True  # the file did not exist yet, so all of it will be new
                stop.wait(poll)
                continue
            ino = os.fstat(f.fileno()).st_ino
            if not from_start:
                f.seek(0, os.SEEK_END)
            from_start = True  # any later reopen is a new file: read it whole
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith("\n"):
                yield buf.rstrip("\r\n")
                buf = ""
            elif len(buf) > MAX_LINE:
                buf = ""  # a runaway line without newline: drop it rather than grow forever
            continue
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        # shortcut: truncation is detected by size shrinking; a rewrite longer than our offset looks like an append.
        if st is None or st.st_ino != ino or st.st_size < f.tell():
            f.close()
            f, buf = None, ""
            continue
        stop.wait(poll)
    if f:
        f.close()


class State:
    """Per-client aggregates and recent alerts, shared between the tail thread and the dashboard."""

    def __init__(self, keep: int = 200):
        self.clients, self.alerts, self.lock = {}, deque(maxlen=keep), threading.Lock()
        self.processed = self.skipped = 0

    def update(self, r: dict | None) -> None:
        with self.lock:
            if r is None:
                self.skipped += 1
                return
            self.processed += 1
            # shortcut: one entry per client IP forever; add LRU eviction for long-running, internet-facing use.
            c = self.clients.setdefault(r["ip"], {"ip": r["ip"], "requests": 0, "alerts": 0, "max_score": 0.0,
                                                  "rules": Counter(), "worst": None})
            c["requests"] += 1
            c["rules"].update(r["rules"])
            alert = r["verdict"] != "benign"
            if alert:
                c["alerts"] += 1
                self.alerts.append(_brief(r))
            if c["worst"] is None or (alert, r["score"]) > (c["worst"]["verdict"] != "benign", c["worst"]["score"]):
                c["worst"] = _brief(r)
            c["max_score"] = max(c["max_score"], r["score"])

    def top_clients(self, k: int = 20) -> list:
        with self.lock:
            rows = sorted(self.clients.values(), key=lambda c: (c["alerts"], c["max_score"]), reverse=True)[:k]
            return [{**c, "rules": dict(c["rules"])} for c in rows]

    def recent_alerts(self) -> list:
        with self.lock:
            return list(self.alerts)


def _brief(r: dict) -> dict:
    return {"ts": r["ts"], "ip": r["ip"], "request": f'{r["method"]} {r["path"]}{"?" + r["query"] if r["query"] else ""}'[:300],
            "status": r["status"], "verdict": r["verdict"], "score": r["score"], "rules": r["rules"],
            "novel": r["novel"], "top_features": r["top_features"]}


def _feats(fs) -> str:
    return ", ".join(f"{n} (z={z:+.1f})" for n, z in fs)


def _page(state: State) -> bytes:
    e = lambda v: html.escape(str(v))  # noqa: E731
    clients = "".join(
        f"<tr><td>{e(c['ip'])}</td><td>{c['requests']}</td><td>{c['alerts']}</td><td>{c['max_score']:.3f}</td>"
        f"<td>{e(c['worst']['verdict'])}</td><td class=req>{e(c['worst']['request'])}</td>"
        f"<td>{e(_feats(c['worst']['top_features']))}</td></tr>" for c in state.top_clients())
    alerts = "".join(
        f"<tr><td>{e(a['ip'])}</td><td>{e(a['verdict'])}</td><td>{a['score']:.3f}</td><td>{a['status']}</td>"
        f"<td class=req>{e(a['request'])}</td><td>{e(', '.join(a['rules'] + a['novel']))}</td>"
        f"<td>{e(_feats(a['top_features']))}</td></tr>" for a in reversed(state.recent_alerts()))
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WAF log anomaly</title><style>
body{{font:14px system-ui,sans-serif;margin:16px;background:#fff;color:#111}} table{{border-collapse:collapse;width:100%;margin-bottom:24px}}
td,th{{border-bottom:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}} .req{{font-family:monospace;word-break:break-all}}
</style></head><body><h1>WAF log anomaly</h1>
<p>{state.processed} requests scored, {state.skipped} unparsable lines skipped. Auto-refresh 5 s.
z = standard deviations from benign training traffic.</p>
<h2>Top anomalous clients</h2><table><tr><th>client</th><th>requests</th><th>alerts</th><th>max score</th>
<th>worst verdict</th><th>worst request</th><th>top features</th></tr>{clients}</table>
<h2>Recent alerts</h2><table><tr><th>client</th><th>verdict</th><th>score</th><th>status</th><th>request</th>
<th>rules / novel</th><th>top features</th></tr>{alerts}</table></body></html>""".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path in ("/", "/dashboard"):
            body, ctype, code = _page(self.server.state), "text/html; charset=utf-8", 200
        elif self.path == "/api/clients":
            s = self.server.state
            body = json.dumps({"processed": s.processed, "skipped": s.skipped, "clients": s.top_clients(),
                               "alerts": s.recent_alerts()}).encode()
            ctype, code = "application/json", 200
        else:
            body, ctype, code = b"not found", "text/plain", 404
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_server(host: str, port: int, state: State) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.state = state
    return srv


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train", required=True, help="log of benign traffic to fit the anomaly model on")
    ap.add_argument("--log", required=True, help="access log to tail")
    ap.add_argument("--from-start", action="store_true", help="score the existing content too, not only new lines")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    a = ap.parse_args()
    det, state, stop = Detector.train_on_log(a.train), State(), threading.Event()
    srv = make_server(a.host, a.port, state)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"dashboard on http://{a.host}:{a.port}/ ; tailing {a.log}", file=sys.stderr)
    q = queue.Queue(maxsize=100_000)
    threading.Thread(target=lambda: [q.put(x) for x in follow(a.log, stop, from_start=a.from_start)], daemon=True).start()
    try:
        while True:
            batch = [q.get()]
            while len(batch) < 1000 and not q.empty():  # score whatever has queued up in one model call
                batch.append(q.get_nowait())
            for r in det.process_batch(batch):
                state.update(r)
                if r and r["verdict"] != "benign":
                    print(json.dumps(_brief(r)), flush=True)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
