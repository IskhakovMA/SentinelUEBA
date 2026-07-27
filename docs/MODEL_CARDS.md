# Model Cards

Every registered model bundle includes `model_card.md`. The card is generated locally and stored with the immutable bundle.

The card records:

- model id, family, and version;
- intended local offline scoring use;
- out-of-scope uses such as alerts, automated response, SIEM export, or proof of compromise;
- source dataset id and dataset kind;
- profile key, feature schema, split id, and threshold method;
- threshold value and held-out metrics;
- synthetic/real limitations;
- privacy statement excluding raw usernames, hostnames, paths, network addresses, payloads, and identity secrets;
- known telemetry gaps;
- artifact hashes;
- application version and source commit.

Model cards are documentation and audit artifacts. They are not a security certification, and they do not make anomaly scores proof of malicious activity.
