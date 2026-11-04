# Evaluation

Synthetic traffic against the local dummy app. Train: 400 benign sessions (seed 1). Test: 400 benign sessions + 15 sessions per attack class (seed 2), 5181 requests. Isolation Forest threshold = 99th percentile of benign training scores (0.6282). Runtime 5 s on CPU.

## Detection rate per class (recall; for `benign` it is the false-positive rate)

| class | requests | rules | iforest | iforest+novelty | combined (rules + iforest+novelty) |
|---|---|---|---|---|---|
| benign | 3752 | 0.000 | 0.012 | 0.012 | 0.012 |
| sqli | 106 | 1.000 | 1.000 | 1.000 | 1.000 |
| xss | 109 | 1.000 | 1.000 | 1.000 | 1.000 |
| path_traversal | 76 | 1.000 | 0.987 | 0.987 | 1.000 |
| scanner | 193 | 0.819 | 0.249 | 0.249 | 0.850 |
| bruteforce | 858 | 0.000 | 1.000 | 1.000 | 1.000 |
| obfuscated | 87 | 0.310 | 0.897 | 0.966 | 0.966 |

## Overall (attack vs benign, per request)

| detector | precision | recall | F1 | FPR |
|---|---|---|---|---|
| rules | 1.000 | 0.333 | 0.500 | 0.000 |
| iforest | 0.967 | 0.891 | 0.928 | 0.012 |
| iforest+novelty | 0.967 | 0.896 | 0.930 | 0.012 |
| combined (rules + iforest+novelty) | 0.970 | 0.978 | 0.974 | 0.012 |

## Signature-rule precision per class

| rule class | fired | precision | true labels when fired |
|---|---|---|---|
| sqli | 117 | 0.906 | {'sqli': 106, 'obfuscated': 11} |
| xss | 125 | 0.872 | {'xss': 109, 'obfuscated': 16} |
| path_traversal | 76 | 1.0 | {'path_traversal': 76} |
| scanner | 158 | 1.0 | {'scanner': 158} |

## Top explaining feature of anomaly-only detections

- benign: {'pct_encoded': 23, 'post_ratio': 10, 'special_ratio': 7, 'ratio_4xx': 3}
- bruteforce: {'rate_per_min': 498, 'post_ratio': 360}
- obfuscated: {'pct_encoded': 42, 'special_ratio': 15}
- scanner: {'rate_per_min': 5, 'ratio_4xx': 1}
