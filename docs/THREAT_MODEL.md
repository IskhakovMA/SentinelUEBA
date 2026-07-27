# Threat Model

Stage 0 detects statistical anomalies in synthetic behavior windows. It does not classify malware, attribute attacks, inspect packet payloads, read file contents, record keystrokes, inspect clipboard data, or collect browser history.

The main risks are false positives, misunderstood explanations, and accidental inclusion of private artifacts. The implementation mitigates them with synthetic-only data, honest explanations, `.gitignore`, and documentation.

