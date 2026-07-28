# 0014 Direct Feature Window Detection Only

Stage 4 may score persisted feature windows directly for detection.

This exception does not apply to training, calibration, evaluation, promotion, rollback,
or drift. Those workflows still require verified registered Parquet snapshots and SQLite
registry checks.
