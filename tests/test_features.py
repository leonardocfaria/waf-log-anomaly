import unittest

from waf import features as F


def req(path="/", query="", ip="10.0.0.1", ts=0.0, status=200, method="GET", ua="Mozilla/5.0"):
    return {"ip": ip, "ts": ts, "method": method, "path": path, "query": query, "status": status, "ua": ua}


class RequestFeaturesTest(unittest.TestCase):
    def get(self, r, name):
        return F.request_features(r)[F.REQUEST_FEATURES.index(name)]

    def test_entropy(self):
        self.assertEqual(self.get(req("/aaaa"), "entropy"), self.get(req("/bbbb"), "entropy"))
        self.assertGreater(self.get(req("/a8$kQ"), "entropy"), self.get(req("/aaaa"), "entropy"))

    def test_special_ratio_and_depth(self):
        self.assertGreater(self.get(req("/s", "q=<script>"), "special_ratio"), 0.1)
        self.assertEqual(self.get(req("/a/b/c"), "path_depth"), 3)
        self.assertEqual(self.get(req("/"), "path_depth"), 0)

    def test_params_and_pct(self):
        self.assertEqual(self.get(req("/s", "a=1&b=2&c=3"), "n_params"), 3)
        self.assertEqual(self.get(req("/s", "a=%27%20OR"), "pct_encoded"), 2)

    def test_vector_length(self):
        self.assertEqual(len(F.vector(req(), F.Windows())), len(F.FEATURES))


class WindowsTest(unittest.TestCase):
    def test_rate_and_isolation(self):
        w = F.Windows(seconds=60)
        for i in range(10):
            out = w.update(req(ts=i, status=404 if i % 2 else 200))
        names = F.WINDOW_FEATURES
        self.assertEqual(out[names.index("rate_per_min")], 10)
        self.assertAlmostEqual(out[names.index("ratio_4xx")], 0.5)
        other = w.update(req(ip="10.0.0.2", ts=10))
        self.assertEqual(other[names.index("rate_per_min")], 1)

    def test_expiry(self):
        w = F.Windows(seconds=60)
        for i in range(5):
            w.update(req(ts=i))
        out = w.update(req(ts=100))
        self.assertEqual(out[F.WINDOW_FEATURES.index("rate_per_min")], 1)

    def test_distinct_paths(self):
        w = F.Windows()
        for i in range(4):
            out = w.update(req(path=f"/p{i}", ts=i))
        self.assertEqual(out[F.WINDOW_FEATURES.index("distinct_path_ratio")], 1.0)


if __name__ == "__main__":
    unittest.main()
