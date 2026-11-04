import random
import tempfile
import unittest
from pathlib import Path

import numpy as np

from waf.detect import Detector
from waf.features import FEATURES
from waf.model import Model


def line(ip="10.0.0.1", t="05/Nov/2026:01:02:03", target="/products/1", status=200, ua="Mozilla/5.0 (X11)"):
    return f'{ip} - - [{t} +0000] "GET {target} HTTP/1.1" {status} 100 "-" "{ua}"'


class ModelTest(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(0)
        self.X = rng.normal(10, 1, size=(500, len(FEATURES)))
        self.m = Model.fit(self.X)

    def test_threshold_and_scores(self):
        normal = self.m.score(self.X[:50])
        self.assertLess((normal > self.m.threshold).mean(), 0.1)
        odd = self.X[0].copy()
        odd[:6] = 20  # attacks move several request features at once
        self.assertGreater(self.m.score(odd[None, :])[0], self.m.threshold)

    def test_explain_names_pushed_feature(self):
        odd = self.X[0].copy()
        odd[FEATURES.index("special_ratio")] = 30
        self.assertEqual(self.m.explain(odd)[0][0], "special_ratio")

    def test_novel_value_in_constant_feature(self):
        X = self.X.copy()
        X[:, FEATURES.index("pct_encoded")] = 0
        m = Model.fit(X)
        x = X[0].copy()
        self.assertEqual(m.novel(x), [])
        x[FEATURES.index("pct_encoded")] = 3
        self.assertEqual(m.novel(x), ["pct_encoded"])

    def test_constant_feature_no_division_error(self):
        X = self.X.copy()
        X[:, 0] = 5
        m = Model.fit(X)
        self.assertTrue(np.isfinite(m.score(X[:3])).all())


class DetectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        random.seed(0)
        pages = ["/", "/products/{n}", "/search?q=shoes+size+{n}", "/blog/post-{n}", "/cart", "/static/app.js?v={n}",
                 "/category/{n}?sort=price&page=2"]
        uas = ["Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "curl/8.4.0"]
        lines = [line(ip=f"10.0.0.{i % 20}", t=f"05/Nov/2026:01:{(i // 20) % 60:02d}:{i % 60:02d}",
                      target=random.choice(pages).format(n=random.randint(1, 999)), ua=random.choice(uas),
                      status=random.choice([200] * 9 + [404])) for i in range(600)]
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("\n".join(lines + ["garbage line"]) + "\n")
        cls.det = Detector.train_on_log(f.name)
        Path(f.name).unlink()

    def test_rule_hit(self):
        r = self.det.process(line(ip="10.9.9.9", target="/item?id=1%27%20OR%20%271%27=%271"))
        self.assertEqual(r["verdict"], "attack:sqli")
        self.assertEqual(r["rules"], ["sqli"])

    def test_benign(self):
        self.assertEqual(self.det.process(line(ip="10.0.0.3", target="/products/7"))["verdict"], "benign")

    def test_anomaly_without_rule(self):
        r = self.det.process(line(ip="10.7.7.7", target="/x?" + "q=%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d%4e" * 5))
        self.assertEqual(r["verdict"], "anomaly")
        self.assertIn("pct_encoded", r["novel"])
        self.assertEqual(r["top_features"][0][0], "pct_encoded")

    def test_bad_line(self):
        self.assertIsNone(self.det.process("nope"))


if __name__ == "__main__":
    unittest.main()
