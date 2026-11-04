"""Per-line detector: signature rules first, then the anomaly model."""
from waf import features, rules
from waf.model import Model
from waf.parse import parse


class Detector:
    def __init__(self, model: Model, window_seconds: float = 60):
        self.model, self.windows = model, features.Windows(window_seconds)

    @classmethod
    def train_on_log(cls, path: str) -> "Detector":
        """Fit the model on a log of benign traffic."""
        w, X = features.Windows(), []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                r = parse(line)
                if r:
                    X.append(features.vector(r, w))
        if len(X) < 50:
            raise ValueError(f"need at least 50 parsable benign lines in {path}, got {len(X)}")
        return cls(Model.fit(X))

    def process(self, line: str) -> dict | None:
        return self.process_batch([line])[0]

    def process_batch(self, lines: list[str]) -> list[dict | None]:
        """Score lines in order (None for unparsable ones). One model call per batch: ~300x faster than per line."""
        reqs = [parse(line) for line in lines]
        xs = [features.vector(r, self.windows) for r in reqs if r]  # windows must see lines in order
        scores = iter(self.model.score(xs)) if xs else iter(())
        out, xi = [], iter(xs)
        for r in reqs:
            if r is None:
                out.append(None)
                continue
            x, score = next(xi), float(next(scores))
            hits, novel = rules.match(r), self.model.novel(x)
            if hits:
                verdict = f"attack:{hits[0]}"
            else:
                verdict = "anomaly" if score > self.model.threshold or novel else "benign"
            out.append({**r, "score": round(score, 4), "verdict": verdict, "rules": hits, "novel": novel,
                        "top_features": self.model.explain(x)})
        return out
