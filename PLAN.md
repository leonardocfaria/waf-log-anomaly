# waf-log-anomaly Implementation Plan

> **For agentic workers:** executed natively (superpowers:executing-plans) in the overnight session. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Detect web attacks in nginx/Apache combined access logs with signature rules + an Isolation Forest trained on benign traffic, evaluated per attack class on labelled synthetic traffic generated against a local dummy app, with a streaming tail mode and a small dashboard.

**Architecture:** `waf/` package.
- `parse.py`: combined-log line to dict.
- `features.py`: per-request features plus a per-client sliding window (60 s).
- `rules.py`: SQLi, XSS, path traversal and scanner signatures.
- `model.py`: Isolation Forest on standardised features, a threshold at the 99th percentile of benign training scores, and z-score feature explanations.
- `detect.py`: the `Detector` combines rules and the model per line.
- `app.py`: dummy local web app that writes a combined log plus ground-truth labels.
- `traffic.py`: generator for benign and attack sessions, sent only to 127.0.0.1/localhost.
- `evaluate.py`: writes `reports/`.
- `stream.py`: tails a log and serves the dashboard.

**Tech Stack:** Python 3.11+, numpy + scikit-learn (IsolationForest), stdlib for everything else, `unittest`.

**Spec:** `SPEC.md` (this folder). Design decisions in `.overnight/DECISIONS.md`.

## Global Constraints
- The traffic generator refuses any host other than `127.0.0.1`, `localhost` or `::1`, or a compose service name it starts itself (`dummy-app`). No external scanning.
- CPU only, seeds fixed, runtime documented. One command for tests: `python -m unittest -v`.
- No model files committed. The model is trained at start-up from a benign log in seconds, so nothing is unpickled.

## Design decisions (answers to brainstorming questions, from SPEC)
- **Client identity.** All synthetic traffic comes from 127.0.0.1. The dummy app therefore logs `X-Forwarded-For` as the client IP, the way nginx `real_ip` does behind a proxy, and the generator gives each simulated session an address from 10.0.0.0/8.
- **Time.** Sending thousands of requests in seconds would make every client look like a flood. The generator sends `X-Sim-Time` (epoch seconds), and the app uses it as the log timestamp. That header and `X-Label` are honoured only from loopback. `X-Label` goes to a separate `labels.csv` (same line order), never into the log, so features cannot see it.
- **Attack classes:** `sqli`, `xss`, `path_traversal`, `scanner` (scanner UA + probe paths), `bruteforce` (POST /login bursts, no signature: only the anomaly model can see it), `obfuscated` (double-encoded / case-mangled payloads that slip past the rules).
- **Verdict per request.** A rule hit gives `attack:<class>`. Otherwise an anomaly score above the threshold gives `anomaly`, and anything else is `benign`.
- **Eval.** Train benign (seed 1) and test mix (seed 2).
  - Per class: n, recall for rules, the model and the combined detector.
  - Overall: binary precision / recall / F1 and false-positive rate on benign traffic.
  - Rules also report per-class precision.

## Review Focus
1. Malformed / truncated / non-UTF-8 log lines → skipped and counted, never crash the stream. (test_parse, test_stream)
2. Log rotation / truncation while tailing → tail reopens from start, no crash. (test_stream)
3. Requests with no query, `-` size, IPv6 clients → parsed. (test_parse)
4. Percent-encoded payloads → rules decode (once, plus a second time for double encoding) before matching. (test_rules)
5. Untrusted strings (paths, UAs) on the dashboard → HTML-escaped. (test_stream)

---

### Task 1: Parser
**Files:** `waf/parse.py`, `tests/test_parse.py`
**Produces:** `parse(line: str) -> dict | None` with keys `ip, ts (float epoch), method, path, query, protocol, status (int), size (int), referer, ua`.
- [ ] Tests: a sample nginx combined line; `-` size → 0; IPv6 client; garbage → None; request line `"-"` (nginx 400) → None.
- [ ] Implement with one regex + `datetime.strptime("%d/%b/%Y:%H:%M:%S %z")`. Commit.

### Task 2: Features
**Files:** `waf/features.py`, `tests/test_features.py`
**Produces:** `FEATURES: list[str]`; `request_features(req) -> list[float]`; `class Windows(seconds=60)` with `.update(req) -> list[float]` (per-client: rate per minute, 4xx ratio, 5xx ratio, distinct-path ratio, POST ratio, over the client's last 60 s including this request); `vector(req, windows) -> list[float]`.
- Request features: length of path+query, Shannon entropy of path+query, special-char ratio (`'"<>;()%{}$|\` and backtick), count of `%xx`, path depth, number of params, digit ratio, UA length, status class 4xx / 5xx flags.
- [ ] Tests: entropy of "aaaa" == 0, special ratio of `<script>` > 0.3, depth of `/a/b/c` == 3; windows: 10 requests from one IP in 10 s → rate 10, a different IP is unaffected, old entries expire after 60 s. Commit.

### Task 3: Rules
**Files:** `waf/rules.py`, `tests/test_rules.py`
**Produces:** `match(req) -> list[str]` of classes among `sqli, xss, path_traversal, scanner`.
- [ ] Tests: `?id=1' OR '1'='1` → sqli; `UNION SELECT` → sqli; `<script>alert(1)</script>` url-encoded → xss; `../../etc/passwd` and `%2e%2e%2f` → path_traversal; UA `sqlmap/1.7` / `Nikto` → scanner; `/wp-admin/` probe → scanner; benign `/search?q=union+station` → []. Commit.

### Task 4: Model + Detector
**Files:** `waf/model.py`, `waf/detect.py`, `tests/test_detect.py`
**Produces:** `Model.fit(X) -> Model` (StandardScaler stats in numpy, `IsolationForest(n_estimators=200, random_state=42)`, threshold = 99th pct of training scores); `Model.score(X) -> np.ndarray` (higher = more anomalous); `Model.explain(x, k=3) -> list[(feature, z)]`. `Detector(model).process(line) -> dict | None` = parsed req + `score, verdict, rules, top_features`; `Detector.train_on_log(path) -> Detector`.
- [ ] Tests: fit on synthetic normal points, an extreme point scores above threshold, normal below; explain returns the feature that was pushed; Detector on a rule line → `attack:sqli`. Commit.

### Task 5: Dummy app + traffic generator + eval
**Files:** `waf/app.py`, `waf/traffic.py`, `evaluate.py`, `tests/test_traffic.py`, `reports/eval.{md,json}`
**Produces:** `app.make_server(host, port, log_path, labels_path)`; `traffic.run(base_url, n_sessions, seed, attacks: bool)`; `traffic.check_target(url)` raises `ValueError` for non-local hosts.
- [ ] Tests: check_target rejects `http://example.com`, `http://10.0.0.5`, accepts `http://127.0.0.1:8000`; end-to-end small run writes N log lines and N labels with matching counts; app ignores `X-Label` from non-loopback (unit-level).
- [ ] `evaluate.py`: start app on port 0, generate train (benign) and test (mixed), train, score, write per-class table. Commit with reports.

### Task 6: Streaming + dashboard
**Files:** `waf/stream.py`, `tests/test_stream.py`
**Produces:** `follow(path, stop: threading.Event, poll=0.2)` generator of lines (handles truncation); `State` (per-client aggregates: requests, alerts, max score, last rule hits, top features of worst request; recent alerts ring); `make_server(host, port, state)` with `/` dashboard and `/api/clients`. CLI: `python -m waf.stream --train benign.log --log access.log --port 8090`.
- [ ] Tests: follow yields appended lines and survives truncation; dashboard escapes `<script>`; bad lines counted in `state.skipped`. Commit.

### Task 7: Packaging
**Files:** `README.md`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/waf-log-anomaly.yml`
- [ ] Compose: `dummy-app` (writes log to a shared volume), `traffic` (generates against `dummy-app` only), `detector` (tails, dashboard on 127.0.0.1:8090).
- [ ] CI with paths filter; README (setup, usage, architecture, results, limitations). Commit, push.
