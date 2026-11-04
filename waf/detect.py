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
        r = parse(line)
        if r is None:
            return None
        x = features.vector(r, self.windows)
        score = float(self.model.score([x])[0])
        hits, novel = rules.match(r), self.model.novel(x)
        if hits:
            verdict = f"attack:{hits[0]}"
        else:
            verdict = "anomaly" if score > self.model.threshold or novel else "benign"
        return {**r, "score": round(score, 4), "verdict": verdict, "rules": hits, "novel": novel,
                "top_features": self.model.explain(x)}
