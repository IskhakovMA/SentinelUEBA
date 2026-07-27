# Model Evaluation

Stage 3 separates synthetic labeled evaluation from real unlabeled evaluation.

Synthetic evaluation reports:

- train, calibration, and test counts;
- precision, recall, F1, false positive rate, ROC-AUC, and PR-AUC when labels contain both classes;
- scenario recall for the five canonical demo windows;
- confusion counts;
- score percentiles;
- inference duration and windows per second.

The recommendation rule is deterministic: prefer higher scenario recall, then lower false positive rate, then higher PR-AUC, then faster inference. A false positive rate of `0.0` is treated as a real best value, not as a missing metric. Compare recommendations are emitted only for compatible synthetic candidates from the same dataset kind, profile, dataset id, split id, feature schema, and feature order. Real compare reports are descriptive only and do not recommend a model.

Real evaluation reports:

- label status `unlabeled`;
- flagged window rate;
- score percentiles;
- timing;
- explicit limitations.

Real evaluation does not fabricate accuracy, precision, recall, F1, ROC-AUC, PR-AUC, or attack labels.

Drift reports compare the model training snapshot to another registered snapshot with the same dataset kind and profile. Reports include standardized mean shift, quantiles, and PSI-style feature shift. Very small datasets return `insufficient_data`.
