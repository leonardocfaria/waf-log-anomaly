import unittest

from waf.rules import match


def req(path="/", query="", ua="Mozilla/5.0 (Windows NT 10.0)"):
    return {"path": path, "query": query, "ua": ua}


class RulesTest(unittest.TestCase):
    def test_sqli(self):
        self.assertIn("sqli", match(req("/item", "id=1'%20OR%20'1'='1")))
        self.assertIn("sqli", match(req("/item", "id=1+UNION+SELECT+username,password+FROM+users--")))
        self.assertIn("sqli", match(req("/item", "id=1;DROP TABLE users")))
        self.assertIn("sqli", match(req("/item", "id=1%20AND%20SLEEP(5)")))

    def test_xss(self):
        self.assertIn("xss", match(req("/search", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")))
        self.assertIn("xss", match(req("/search", "q=<img src=x onerror=alert(1)>")))
        self.assertIn("xss", match(req("/search", "q=javascript:alert(document.cookie)")))

    def test_traversal(self):
        self.assertIn("path_traversal", match(req("/download", "file=../../../etc/passwd")))
        self.assertIn("path_traversal", match(req("/static/%2e%2e%2f%2e%2e%2fetc/shadow")))
        self.assertIn("path_traversal", match(req("/download", "file=%252e%252e%252fetc%252fpasswd")))
        self.assertIn("path_traversal", match(req("/download", "file=%25252e%25252e%25252fetc%25252fpasswd")))

    def test_scanner(self):
        self.assertIn("scanner", match(req(ua="sqlmap/1.7.2#stable (https://sqlmap.org)")))
        self.assertIn("scanner", match(req(ua="Mozilla/5.00 (Nikto/2.5.0)")))
        self.assertIn("scanner", match(req("/wp-admin/install.php")))
        self.assertIn("scanner", match(req("/.env")))
        self.assertIn("scanner", match(req("/.git/config")))

    def test_benign(self):
        for r in [req("/search", "q=union+station+opening+hours"), req("/products/42", "sort=price&dir=asc"),
                  req("/blog/select-the-right-shoes"), req("/search", "q=rock+%26+roll"), req("/"),
                  req("/static/app.3f9a.js"), req("/search", "q=o%27reilly+books"),
                  req("/search", "q=select+the+best+shoes+from+our+range")]:
            self.assertEqual(match(r), [], r)

    def test_undecodable(self):
        self.assertEqual(match(req("/x", "q=%ff%fe%zz")), [])


if __name__ == "__main__":
    unittest.main()


class RulesHardeningTest(unittest.TestCase):
    def test_no_quadratic_backtracking(self):
        import time
        for q in ["'or1" * 16000, "%27or1" * 11000, "1-" * 30000, "<" * 60000, "../" * 20000]:
            t = time.perf_counter()
            match(req("/x", q, ua="a" * 60000))
            self.assertLess(time.perf_counter() - t, 1.0, q[:10])

    def test_benign_lookalikes_from_review(self):
        for r in [req("/search", "q=size+10+-+12+--+sale"), req("/api/v1/*"), req("/search", "q=product+5+%23+3"),
                  req("/search", "q=onload%3Dtrue")]:
            self.assertEqual(match(r), [], r)

    def test_numeric_comment_sqli_still_caught(self):
        self.assertIn("sqli", match(req("/item", "id=1'--")))
        self.assertIn("sqli", match(req("/item", "id=1 OR 1=1--")))
