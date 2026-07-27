# Windows Collection

Stage 1 adds opt-in Windows telemetry collection. It is not a Windows Service and it does not start automatically.

| Collector | Data | Privilege | Notes |
| --- | --- | --- | --- |
| `windows.process.psutil` | started/stopped process metadata | user | polling can miss very short-lived processes |
| `windows.network.psutil` | opened/closed TCP/UDP connection metadata | user | no packet capture and no payload inspection |
| `windows.system_metrics.psutil` | CPU, RAM, disk, network byte deltas, uptime | user | first network sample initializes counters |
| `windows.auth.security_event_log` | 4624, 4625, 4634, 4647 parser and cursor | admin optional | reports unavailable or permission_required without changing audit policy |

Collected process summaries intentionally exclude command line. General UI summaries do not show raw username, hostname, or full executable paths by default.

## Cumulative vs Continuous

SentinelUEBA tracks cumulative collected duration across sessions separately from the longest continuous session. Reaching 24 cumulative hours is not the same as strict continuous 24-hour validation.

## Manual Windows Check

```powershell
uv sync --all-extras --dev
uv run sentinelueba init
uv run sentinelueba capabilities
uv run sentinelueba collect --duration 300 --interval 5
uv run sentinelueba collector-status
uv run sentinelueba collection-sessions
uv run sentinelueba training-eligibility --dataset real
```

Security Event Log access may require elevated rights. The collector must report `permission_required`; it must not modify Windows audit policy.

## Delete Local Telemetry

```powershell
uv run sentinelueba clean
Remove-Item -Recurse -Force data, artifacts, logs, reports -ErrorAction SilentlyContinue
```
