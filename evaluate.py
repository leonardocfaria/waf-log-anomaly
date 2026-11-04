"""End-to-end eval: generate labelled traffic against a local dummy app, train on benign, score, report.

python evaluate.py   (about 5 s on a laptop CPU; writes reports/eval.md and reports/eval.json)
"""
import json
import tempfile
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

from waf import app, traffic
from waf.detect import Detector

ROOT = Path(__file__).resolve().parent
TRAIN = dict(n_sessions=400, seed=1)
TEST = dict(n_sessions=400, seed=2, attack_sessions_per_class=15)


def generate(d: Path, name: str, **kw) -> tuple[Path, Path]:
    log, labels = d / f"{name}.log", d / f"{name}.labels"
    srv = app.make_server("127.0.0.1", 0, str(log), str(labels))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        traffic.run(f"http://127.0.0.1:{srv.server_address[1]}", **kw)
    finally:
        srv.shutdown()
        srv.server_close()
    return log, labels


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


def main():
    t0 = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        train_log, _ = generate(d, "train", **TRAIN)
        test_log, test_labels = generate(d, "test", **TEST)
        det = Detector.train_on_log(str(train_log))
        results = det.process_batch(test_log.read_text().splitlines())
        rows = [(label, r) for label, r in zip(test_labels.read_text().splitlines(), results) if r]
    secs = time.time() - t0

    detectors = {  # name -> did this request get flagged?
        "rules": lambda r: bool(r["rules"]),
        "iforest": lambda r: r["score"] > det.model.threshold,
        "iforest+novelty": lambda r: r["score"] > det.model.threshold or bool(r["novel"]),
        "combined (rules + iforest+novelty)": lambda r: r["verdict"] != "benign",
    }
    classes = ["benign"] + traffic.ATTACK_CLASSES
    n = Counter(label for label, _ in rows)
    per_class = {c: {"n": n[c], **{k: round(sum(f(r) for lab, r in rows if lab == c) / n[c], 4) for k, f in detectors.items()}}
                 for c in classes}
    overall = {}
    for k, f in detectors.items():
        tp = sum(f(r) for lab, r in rows if lab != "benign")
        fp = sum(f(r) for lab, r in rows if lab == "benign")
        overall[k] = {**prf(tp, fp, sum(lab != "benign" for lab, _ in rows) - tp), "fpr": round(fp / n["benign"], 4)}
    # Per-class precision of the signature rules (a rule names a class, so precision is defined per class).
    rule_prec = {}
    for c in ["sqli", "xss", "path_traversal", "scanner"]:
        fired = [lab for lab, r in rows if c in r["rules"]]
        rule_prec[c] = {"fired": len(fired), "precision": round(sum(lab == c for lab in fired) / len(fired), 4) if fired else None,
                        "labels_when_fired": dict(Counter(fired))}
    # Which features explain the anomaly-only detections?
    top = defaultdict(Counter)
    for lab, r in rows:
        if r["verdict"] == "anomaly":
            top[lab][r["top_features"][0][0]] += 1

    report = {"train": TRAIN, "test": TEST, "n_test_requests": len(rows), "threshold": round(det.model.threshold, 4),
              "runtime_seconds": round(secs, 1), "per_class_detection_rate": per_class, "overall": overall,
              "rule_precision": rule_prec, "top_feature_of_anomaly_only_detections": {k: dict(v) for k, v in top.items()}}
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / "eval.json").write_text(json.dumps(report, indent=2) + "\n")

    keys = list(detectors)
    L = ["# Evaluation\n",
         f"Synthetic traffic against the local dummy app. Train: {TRAIN['n_sessions']} benign sessions (seed {TRAIN['seed']}). "
         f"Test: {TEST['n_sessions']} benign sessions + {TEST['attack_sessions_per_class']} sessions per attack class "
         f"(seed {TEST['seed']}), {len(rows)} requests. Isolation Forest threshold = 99th percentile of benign training "
         f"scores ({report['threshold']}). Runtime {secs:.0f} s on CPU.\n",
         "## Detection rate per class (recall; for `benign` it is the false-positive rate)\n",
         "| class | requests | " + " | ".join(keys) + " |", "|---|---|" + "---|" * len(keys)]
    for c in classes:
        L.append(f"| {c} | {per_class[c]['n']} | " + " | ".join(f"{per_class[c][k]:.3f}" for k in keys) + " |")
    L += ["\n## Overall (attack vs benign, per request)\n", "| detector | precision | recall | F1 | FPR |", "|---|---|---|---|---|"]
    for k in keys:
        o = overall[k]
        L.append(f"| {k} | {o['precision']:.3f} | {o['recall']:.3f} | {o['f1']:.3f} | {o['fpr']:.3f} |")
    L += ["\n## Signature-rule precision per class\n", "| rule class | fired | precision | true labels when fired |", "|---|---|---|---|"]
    for c, v in rule_prec.items():
        L.append(f"| {c} | {v['fired']} | {v['precision']} | {v['labels_when_fired']} |")
    L += ["\n## Top explaining feature of anomaly-only detections\n"]
    L += [f"- {lab}: {dict(cnt.most_common(4))}" for lab, cnt in sorted(top.items())]
    (out / "eval.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
