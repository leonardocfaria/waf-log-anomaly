import unittest

from waf.parse import parse

LINE = ('203.0.113.7 - - [05/Nov/2026:01:02:03 +0100] "GET /products/42?ref=home&x=1 HTTP/1.1" 200 5120 '
        '"https://shop.local/" "Mozilla/5.0 (X11; Linux x86_64)"')


class ParseTest(unittest.TestCase):
    def test_combined_line(self):
        r = parse(LINE)
        self.assertEqual(r["ip"], "203.0.113.7")
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/products/42")
        self.assertEqual(r["query"], "ref=home&x=1")
        self.assertEqual((r["status"], r["size"]), (200, 5120))
        self.assertEqual(r["ua"], "Mozilla/5.0 (X11; Linux x86_64)")
        self.assertEqual(r["ts"], 1793836923.0)  # 2026-11-05T00:02:03Z

    def test_dash_size_no_query(self):
        r = parse('10.0.0.1 - - [05/Nov/2026:01:02:03 +0000] "POST /login HTTP/1.1" 401 - "-" "curl/8.0"')
        self.assertEqual((r["size"], r["query"], r["path"]), (0, "", "/login"))

    def test_ipv6(self):
        r = parse('2001:db8::1 - bob [05/Nov/2026:01:02:03 +0000] "GET / HTTP/2.0" 304 0 "-" "-"')
        self.assertEqual(r["ip"], "2001:db8::1")

    def test_escaped_quote_in_ua(self):
        r = parse('10.0.0.1 - - [05/Nov/2026:01:02:03 +0000] "GET /a HTTP/1.1" 200 1 "-" "x\\"y"')
        self.assertEqual(r["ua"], 'x\\"y')

    def test_garbage(self):
        for bad in ["", "hello", '10.0.0.1 - - [05/Nov/2026:01:02:03 +0000] "-" 400 0 "-" "-"',
                    '10.0.0.1 - - [99/Nov/2026:01:02:03 +0000] "GET / HTTP/1.1" 200 1 "-" "-"']:
            self.assertIsNone(parse(bad), bad)


if __name__ == "__main__":
    unittest.main()
