"""Signature rules for common web attacks, matched on the URL-decoded request."""
import re
from urllib.parse import unquote_plus

_URL_RULES = {
    "sqli": r"('|\")\s*(or|and)\s*('|\"|\d)\s*\S*\s*=|\bunion\b.{0,20}\bselect\b|;\s*(drop|delete|insert|update|shutdown)\b"
            r"|\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|('|\d)\s*(--|#|/\*)|\binformation_schema\b",
    "xss": r"<\s*(script|iframe|svg|img|body|object|embed)\b|\bon(error|load|mouseover|focus|click)\s*=|javascript\s*:|\balert\s*\(|document\.(cookie|location)",
    "path_traversal": r"(\.\.[/\\])|([/\\]\.\.$)|/etc/(passwd|shadow|hosts)|\b(boot|win)\.ini\b|c:\\\\windows",
}
_SCANNER_UA = r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|ffuf|acunetix|nessus|openvas|w3af|whatweb|zmeu"
_SCANNER_PATH = (r"^/(wp-admin|wp-login\.php|phpmyadmin|pma|\.env|\.git|\.svn|\.ds_store|server-status|cgi-bin|actuator|"
                 r"config\.php|xmlrpc\.php|admin\.php|vendor/phpunit|boaform|hnap1)\b")
_COMPILED = {k: re.compile(v, re.I | re.S) for k, v in _URL_RULES.items()}
_UA = re.compile(_SCANNER_UA, re.I)
_PATH = re.compile(_SCANNER_PATH, re.I)


def _decoded(s: str) -> str:
    """All decoding layers joined, so multi-encoded payloads (%25252e -> %252e -> %2e -> .) still match."""
    layers = [s]
    for _ in range(4):
        nxt = unquote_plus(layers[-1])
        if nxt == layers[-1]:
            break
        layers.append(nxt)
    return "\n".join(layers)


def match(r: dict) -> list[str]:
    url = _decoded(r["path"] + ("?" + r["query"] if r["query"] else ""))
    hits = [name for name, rx in _COMPILED.items() if rx.search(url)]
    if _UA.search(r["ua"]) or _PATH.search(r["path"]):
        hits.append("scanner")
    return hits
