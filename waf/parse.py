"""Parse nginx/Apache "combined" access-log lines."""
import re
from datetime import datetime

_LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+) (?P<protocol>[^"\s]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"')


def parse(line: str) -> dict | None:
    """Return the request as a dict, or None if the line is not a well-formed combined-log request."""
    m = _LINE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None
    path, _, query = m["target"].partition("?")
    return {"ip": m["ip"], "ts": ts, "method": m["method"], "path": path, "query": query,
            "protocol": m["protocol"], "status": int(m["status"]),
            "size": 0 if m["size"] == "-" else int(m["size"]), "referer": m["referer"], "ua": m["ua"]}
