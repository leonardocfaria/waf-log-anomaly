"""Labelled synthetic traffic: benign browsing sessions plus attack sessions, sent ONLY to a local app.

python -m waf.traffic --url http://127.0.0.1:8000 --sessions 300 --attacks-per-class 15 --seed 2
"""
import argparse
import random
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "dummy-app"}  # dummy-app = the compose service we start
ATTACK_CLASSES = ["sqli", "xss", "path_traversal", "scanner", "bruteforce", "obfuscated"]

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
]
WORDS = ["shoes", "red", "jacket", "size 42", "o'reilly books", "rock & roll", "gift card", "union station",
         "café", "kids", "summer sale", "100% cotton", "running", "waterproof", "best price"]
SCANNER_UAS = ["sqlmap/1.8.4#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
               "Mozilla/5.0 zgrab/0.x", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"]
PROBES = ["/wp-admin/", "/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/", "/admin.php", "/config.php",
          "/server-status", "/xmlrpc.php", "/backup.zip", "/admin/", "/api/v1/users", "/.DS_Store", "/cgi-bin/test.cgi",
          "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/actuator/health", "/old/", "/test.php", "/db.sql"]
PAYLOADS = {
    "sqli": ["1' OR '1'='1", "1' OR 1=1--", "1 UNION SELECT username,password FROM users--", "1; DROP TABLE users",
             "1 AND SLEEP(5)", "1' AND (SELECT 1 FROM information_schema.tables)--", "-1' UNION SELECT null,version()#"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>", "<svg/onload=alert(1)>",
            "\"><script>fetch('//x')</script>", "javascript:alert(1)", "<iframe src=javascript:alert(1)>"],
    "path_traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
                       "%252e%252e%252f%252e%252e%252fetc%252fshadow", "..\\..\\..\\boot.ini"],
    # Payloads built to slip past the signature rules (comment-split SQL, HTML entities, overlong UTF-8).
    "obfuscated": ["1/**/oR/**/2>1", "1%09||%09true", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                   "%u003Cscript%u003Ealert(1)%u003C/script%u003E", "..%c0%af..%c0%afetc%c0%afpasswd",
                   "1)/**/oR/**/(sElEcT/**/1)=(1"],
}


def check_target(url: str) -> None:
    """Refuse anything that is not this machine (or the compose dummy-app we start)."""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or u.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to send traffic to {url!r}: only {sorted(ALLOWED_HOSTS)} are allowed")


def _ip(rng):
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _q(s):
    return quote(s, safe="")


def _benign(rng, t):
    ip, ua = _ip(rng), rng.choice(BROWSERS)
    for _ in range(rng.randint(3, 15)):
        page = rng.choice([
            "/", f"/products/{rng.randint(1, 500)}", f"/search?q={_q(rng.choice(WORDS))}",
            f"/category/{rng.randint(1, 30)}?sort={rng.choice(['price', 'new', 'rating'])}&page={rng.randint(1, 5)}",
            f"/blog/{rng.choice(['spring-trends', 'how-to-choose-shoes', 'care-guide'])}", "/cart", "/about",
            f"/static/app.{rng.randint(1000, 9999)}.js", f"/item?id={rng.randint(1, 900)}",
            f"/download?file={rng.choice(['catalogue.pdf', 'size-chart.pdf'])}", "/login",
            f"/products/{rng.choice(['old-model', 'discontinued'])}",  # occasional dead link -> 404
        ])
        yield t, ip, "GET", page, ua, "benign"
        t += rng.uniform(2, 40)
    if rng.random() < 0.2:
        yield t, ip, "POST", "/login", ua, "benign"  # a mistyped password


def _attack(rng, t, cls):
    ip, ua = _ip(rng), rng.choice(BROWSERS + ["python-requests/2.32.3", "curl/8.5.0"])
    if cls == "scanner":
        ua = rng.choice(SCANNER_UAS + BROWSERS)  # some scanners spoof a browser UA; their probe paths still show
        for p in rng.sample(PROBES, rng.randint(8, len(PROBES))):
            yield t, ip, "GET", p, ua, cls
            t += rng.uniform(0.1, 1.0)
    elif cls == "bruteforce":
        for _ in range(rng.randint(30, 80)):
            yield t, ip, "POST", "/login", ua, cls
            t += rng.uniform(0.3, 2.0)
    else:
        for _ in range(rng.randint(3, 10)):
            p = _q(rng.choice(PAYLOADS[cls])) if rng.random() < 0.5 else quote(rng.choice(PAYLOADS[cls]), safe="%/=&|")
            page = {"sqli": f"/item?id={p}", "xss": f"/search?q={p}", "path_traversal": f"/download?file={p}"}.get(
                cls, rng.choice([f"/item?id={p}", f"/search?q={p}", f"/download?file={p}"]))
            yield t, ip, "GET", page, ua, cls
            t += rng.uniform(1, 6)


def run(base_url: str, n_sessions: int, seed: int, attack_sessions_per_class: int = 0,
        start: float = 1_793_836_800.0, duration: float = 3600.0) -> int:
    """Send interleaved benign + attack sessions in simulated-time order. Returns the number of requests."""
    check_target(base_url)
    rng = random.Random(seed)
    events = []
    for _ in range(n_sessions):
        events += _benign(rng, start + rng.uniform(0, duration))
    for cls in ATTACK_CLASSES:
        for _ in range(attack_sessions_per_class):
            events += _attack(rng, start + rng.uniform(0, duration), cls)
    events.sort(key=lambda e: e[0])
    base = base_url.rstrip("/")
    for t, ip, method, path, ua, label in events:
        req = urllib.request.Request(base + path, method=method, data=b"user=admin&password=guess" if method == "POST" else None,
                                     headers={"User-Agent": ua, "X-Forwarded-For": ip, "X-Sim-Time": f"{t:.3f}", "X-Label": label})
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except urllib.error.HTTPError as e:
            e.read()
    return len(events)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--sessions", type=int, default=300)
    ap.add_argument("--attacks-per-class", type=int, default=15)
    ap.add_argument("--seed", type=int, default=2)
    ap.add_argument("--start", type=float, default=None, help="simulated start time (epoch); default now")
    ap.add_argument("--local-log", help="ignore --url: start the dummy app in-process on 127.0.0.1 and write its "
                                        "log here (labels go to <log>.labels)")
    a = ap.parse_args()
    t0, srv = time.time(), None
    if a.local_log:
        from waf import app  # noqa: PLC0415  (only needed in this mode)
        srv = app.make_server("127.0.0.1", 0, a.local_log, a.local_log + ".labels")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        a.url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        n = run(a.url, a.sessions, a.seed, a.attacks_per_class, start=a.start or time.time())
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
    print(f"sent {n} requests to {a.url} in {time.time() - t0:.1f}s")
