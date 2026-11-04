import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from waf import stream


def _collect(path, stop, out, **kw):
    for line in stream.follow(path, stop, poll=0.02, **kw):
        out.append(line)


class FollowTest(unittest.TestCase):
    def test_appended_lines_partial_writes_and_truncation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "a.log")
            p.write_text("old line\n")
            stop, out = threading.Event(), []
            t = threading.Thread(target=_collect, args=(str(p), stop, out), daemon=True)
            t.start()
            time.sleep(0.1)
            with p.open("a") as f:
                f.write("one\ntw")
                f.flush()
                time.sleep(0.1)
                f.write("o\n")
            time.sleep(0.1)
            p.write_text("after truncate\n")  # truncation, like copytruncate rotation
            time.sleep(0.2)
            stop.set()
            t.join(2)
            self.assertEqual(out, ["one", "two", "after truncate"])

    def test_from_start_and_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "late.log")
            stop, out = threading.Event(), []
            t = threading.Thread(target=_collect, args=(str(p), stop, out), kwargs={"from_start": True}, daemon=True)
            t.start()
            time.sleep(0.1)
            p.write_text("first\n")
            time.sleep(0.2)
            stop.set()
            t.join(2)
            self.assertEqual(out, ["first"])


class StateAndDashboardTest(unittest.TestCase):
    def setUp(self):
        self.state = stream.State()
        base = {"ts": 0, "method": "GET", "query": "", "status": 200, "rules": [], "novel": [], "ua": "x"}
        self.state.update(None)
        self.state.update({**base, "ip": "10.0.0.1", "path": "/ok", "score": 0.4, "verdict": "benign",
                           "top_features": [("url_len", 0.1)]})
        self.state.update({**base, "ip": "10.6.6.6", "path": "/<script>alert(1)</script>", "score": 0.7,
                           "verdict": "attack:xss", "rules": ["xss"], "top_features": [("special_ratio", 9.5)]})

    def test_aggregates(self):
        self.assertEqual(self.state.skipped, 1)
        top = self.state.top_clients()
        self.assertEqual(top[0]["ip"], "10.6.6.6")
        self.assertEqual(top[0]["alerts"], 1)
        self.assertEqual(len(self.state.recent_alerts()), 1)

    def test_dashboard_and_api(self):
        srv = stream.make_server("127.0.0.1", 0, self.state)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        try:
            page = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("10.6.6.6", page)
            self.assertNotIn("<script>alert(1)", page)
            self.assertIn("special_ratio", page)
            api = json.loads(urllib.request.urlopen(base + "/api/clients").read())
            self.assertEqual(api["clients"][0]["ip"], "10.6.6.6")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
