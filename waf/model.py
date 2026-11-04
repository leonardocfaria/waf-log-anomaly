"""Isolation Forest over standardised features, with z-score explanations."""
import numpy as np
from sklearn.ensemble import IsolationForest

from waf.features import FEATURES

SEED = 42
THRESHOLD_PCT = 99  # flag scores above the 99th percentile of benign training traffic (about 1% FPR)


class Model:
    def __init__(self, mean, std, constant, forest, threshold):
        self.mean, self.std, self.constant, self.forest, self.threshold = mean, std, constant, forest, threshold

    @classmethod
    def fit(cls, X) -> "Model":
        X = np.asarray(X, dtype=float)
        mean, std = X.mean(0), X.std(0)
        constant = std == 0
        std[constant] = 1.0
        forest = IsolationForest(n_estimators=200, random_state=SEED).fit((X - mean) / std)
        m = cls(mean, std, constant, forest, 0.0)
        m.threshold = float(np.percentile(m.score(X), THRESHOLD_PCT))
        return m

    def score(self, X) -> np.ndarray:
        """Isolation Forest anomaly score, higher = more anomalous."""
        return -self.forest.score_samples((np.asarray(X, dtype=float) - self.mean) / self.std)

    def novel(self, x) -> list[str]:
        """Features that never varied in benign training but differ here.

        An Isolation Forest cannot split on a constant feature, so it is blind to these (e.g. %-encoding
        when benign traffic never had any); report them separately.
        """
        diff = self.constant & (np.asarray(x, dtype=float) != self.mean)
        return [FEATURES[i] for i in np.flatnonzero(diff)]

    def explain(self, x, k: int = 3) -> list[tuple[str, float]]:
        """The k features furthest from benign traffic, as (name, z-score)."""
        z = (np.asarray(x, dtype=float) - self.mean) / self.std
        return [(FEATURES[i], round(float(z[i]), 2)) for i in np.argsort(-np.abs(z))[:k]]
