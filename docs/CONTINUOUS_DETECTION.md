# Continuous Detection

Stage 4 provides a controlled local detection worker lease in SQLite. It is not a Windows
Service, MSI, autostart task, daemon supervisor, or production alerting system.

Commands:

```bash
uv run sentinelueba detection worker status
uv run sentinelueba detection worker start --dataset synthetic --interval-seconds 60
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256 --single-cycle
uv run sentinelueba detection worker stop --confirm
```

The worker lease stores an opaque owner id, namespace key, heartbeat, expiry, stop
request, status, config, policy hash, and sanitized errors. Public status exposes only
an allowlisted view and does not return owner ids, thread ids, host names, local paths,
or config JSON. API start uses a process-level worker manager keyed by database path and
worker key; API stop signals the current process event and waits for the thread to exit.
`worker start` is a foreground alias, and `run-foreground` runs until Ctrl+C or stop
request unless `--single-cycle` is passed for tests and CI. Foreground cycles call the
same SQL anti-join idempotent run-once engine used by the CLI and API. Watermarks are
keyed by dataset kind, profile, policy hash, and model identity so changed policy or
champion identity causes fresh evaluations instead of silently skipping changed inputs.
