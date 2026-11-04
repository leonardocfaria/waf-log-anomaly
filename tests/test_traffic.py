import tempfile
import threading
import unittest
from pathlib import Path

from waf import app, traffic
from waf.parse import parse


class TargetTest(unittest.TestCase):
    def test_rejects_non_local(self):
        for url in ["http://example.com", "http://10.0.0.5:8000", "https://8.8.8.8/", "http://127.0.0.1.example.com/",
                    "http://localhost.evil.test", "ftp://127.0.0.1"]:
            with self.assertRaises(ValueError, msg=url):
                traffic.check_target(url)

    def test_accepts_local(self):
        for url in ["http://127.0.0.1:8000", "http://localhost:1", "http://[::1]:8000", "http://dummy-app:8000"]:
            traffic.check_target(url)


class AppTest(unittest.TestCase):
    def test_trust_only_loopback(self):
        self.assertTrue(app.trusted("127.0.0.1"))
        self.assertTrue(app.trusted("::1"))
        self.assertFalse(app.trusted("192.168.1.10"))

    def test_routes(self):
        self.assertEqual(app.route("GET", "/", ""), 200)
        self.assertEqual(app.route("GET", "/products/12", ""), 200)
        self.assertEqual(app.route("GET", "/nope", ""), 404)
        self.assertEqual(app.route("GET", "/item", "id=1%27"), 500)
        self.assertEqual(app.route("POST", "/login", ""), 401)


class EndToEndTest(unittest.TestCase):
    def test_small_run_writes_matching_log_and_labels(self):
        with tempfile.TemporaryDirectory() as d:
            log, labels = Path(d, "access.log"), Path(d, "labels.csv")
            srv = app.make_server("127.0.0.1", 0, str(log), str(labels))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                n = traffic.run(f"http://127.0.0.1:{srv.server_address[1]}", n_sessions=4, seed=3,
                                attack_sessions_per_class=1)
            finally:
                srv.shutdown()
                srv.server_close()
            lines = log.read_text().splitlines()
            labs = labels.read_text().splitlines()
            self.assertEqual(len(lines), n)
            self.assertEqual(len(labs), n)
            self.assertTrue(all(parse(x) for x in lines))
            self.assertEqual(set(labs), {"benign", *traffic.ATTACK_CLASSES})
            ips = {parse(x)["ip"] for x in lines}
            self.assertGreater(len(ips), 4, "sessions should get distinct client IPs")
            self.assertNotIn("127.0.0.1", ips)


if __name__ == "__main__":
    unittest.main()
