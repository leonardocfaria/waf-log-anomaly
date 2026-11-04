"""Per-request and per-client sliding-window features."""
import math
import re
from collections import Counter, deque

SPECIAL = set("'\"<>;()%{}$|\\`*!")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")

REQUEST_FEATURES = ["url_len", "entropy", "special_ratio", "pct_encoded", "path_depth", "n_params",
                    "digit_ratio", "ua_len", "is_4xx", "is_5xx"]
WINDOW_FEATURES = ["rate_per_min", "ratio_4xx", "ratio_5xx", "distinct_path_ratio", "post_ratio"]
FEATURES = REQUEST_FEATURES + WINDOW_FEATURES


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def request_features(r: dict) -> list[float]:
    url = r["path"] + ("?" + r["query"] if r["query"] else "")
    n = len(url) or 1
    return [len(url), _entropy(url), sum(c in SPECIAL for c in url) / n, len(_PCT.findall(url)),
            len([p for p in r["path"].split("/") if p]), len([p for p in r["query"].split("&") if p]),
            sum(c.isdigit() for c in url) / n, len(r["ua"]),
            float(400 <= r["status"] < 500), float(r["status"] >= 500)]


class Windows:
    """Sliding window of each client's recent requests (by log timestamp, so replayed logs work too)."""

    def __init__(self, seconds: float = 60):
        self.seconds, self.clients, self._n = seconds, {}, 0

    def update(self, r: dict) -> list[float]:
        q = self.clients.setdefault(r["ip"], deque())
        q.append((r["ts"], r["status"], r["path"], r["method"]))
        while q[0][0] <= r["ts"] - self.seconds:
            q.popleft()
        self._n += 1
        if self._n % 10_000 == 0:  # forget idle clients so a long stream does not grow without bound
            self.clients = {ip: d for ip, d in self.clients.items() if d[-1][0] > r["ts"] - self.seconds or ip == r["ip"]}
        k = len(q)
        return [k * 60 / self.seconds, sum(400 <= s < 500 for _, s, _, _ in q) / k, sum(s >= 500 for _, s, _, _ in q) / k,
                len({p for _, _, p, _ in q}) / k, sum(m == "POST" for _, _, _, m in q) / k]


def vector(r: dict, windows: Windows) -> list[float]:
    return request_features(r) + windows.update(r)
