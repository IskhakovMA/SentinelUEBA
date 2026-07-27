# 0013 Detection Fusion

Stage 4 uses deterministic `hybrid-fusion-v1`.

The primary matched signal contributes its full strength. Secondary matched signals add a
bounded corroboration bonus. This keeps the score explainable, avoids hidden trained
weights, and prevents weak single signals from becoming critical by accident.
