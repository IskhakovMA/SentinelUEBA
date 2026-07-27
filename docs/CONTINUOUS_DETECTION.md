# Continuous Detection

Stage 4 provides a controlled local detection worker lease in SQLite. It is not a Windows
Service, MSI, autostart task, daemon supervisor, or production alerting system.

Commands:

```bash
uv run sentinelueba detection worker status
uv run sentinelueba detection worker start --dataset synthetic --interval-seconds 60
uv run sentinelueba detection worker run-foreground --dataset synthetic --max-windows 256
uv run sentinelueba detection worker stop
```

The worker lease stores owner, heartbeat, stop request, status, config, and sanitized
errors. Foreground cycles call the same idempotent run-once engine used by the CLI and API.
Watermarks are keyed by dataset kind, profile, policy hash, and model identity so changed
policy or champion identity causes fresh evaluations instead of silently skipping changed
inputs.
