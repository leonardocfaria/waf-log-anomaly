# waf-log-anomaly

## Goal
Build "waf-log-anomaly": a web-attack detector over HTTP access logs. Parse nginx/Apache combined logs, extract per-request and per-client-window features (URL entropy, special-character ratios, path depth, status mix, rate), and score them with (1) signature rules for SQLi/XSS/path traversal/scanner user-agents and (2) an unsupervised anomaly model (Isolation Forest) trained on benign traffic. Generate labelled synthetic traffic locally (benign browsing plus attacks replayed ONLY against a local intentionally-vulnerable container or a local dummy app you start), evaluate precision/recall per attack class, and show results in a small web dashboard (top anomalous clients, explanation of top features). Streaming mode tails a log file. Include docker-compose for the demo.

## Definition of done
- [ ] Log parser and feature extraction with unit tests
- [ ] Rules + Isolation Forest scoring; eval report per attack class committed under reports/
- [ ] Synthetic traffic generator targets only localhost / containers it starts
- [ ] Dashboard and streaming mode work
- [ ] Tests pass with one command; CI workflow runs them
- [ ] README with setup, usage, architecture and limitations
- [ ] Self code review done
- [ ] Draft PR open

