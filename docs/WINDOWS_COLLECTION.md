# Windows Collection

Stage 1 adds opt-in Windows telemetry collection. It is not a Windows Service and it does not start automatically.

| Collector | Data | Privilege | Notes |
| --- | --- | --- | --- |
| `windows.process.psutil` | started/stopped process metadata | user | polling can miss very short-lived processes |
| `windows.network.psutil` | opened/closed TCP/UDP connection metadata | user | no packet capture and no payload inspection |
| `windows.system_metrics.psutil` | CPU, RAM, disk, network byte deltas, uptime | user | first network sample initializes counters |
| `windows.auth.security_event_log` | 4624, 4625, 4634, 4647 parser and cursor | admin optional | reports unavailable or permission_required without changing audit policy |

Collected process summaries intentionally exclude command line. General UI summaries do not show raw username, hostname, or full executable paths by default.

Canonical Stage 2 payload actions match the real collectors:

- Process: `started`, `stopped`, `snapshot`.
- Network: `opened`, `closed`, `snapshot`.
- Authentication: `login`, `logout`, `authentication`.
- System metrics: `boot_time` is a finite non-negative epoch-seconds float when present.

## Event Log Cursor

The authentication collector uses the modern Windows Event Log API through pywin32: `EvtQuery`, `EvtNext`, `EvtRender`, and `EvtClose`. On first start it initializes the cursor to the newest existing `EventRecordID`. Polling then queries records with `EventRecordID` greater than the cursor, so the first new event after start is eligible and already processed records are skipped after restart. Event Log handles are closed on success and error paths.

The same parser handles live Event XML and artificial fixtures. Filtering keeps interactive logon types `2`, `7`, `10`, and `11`, excludes `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, and machine accounts ending in `$`. If a supported event does not include `LogonType`, the payload omits it instead of inventing `0`.

## Cumulative vs Continuous

SentinelUEBA tracks cumulative collected duration across sessions separately from the longest continuous session. Reaching 24 cumulative hours is not the same as strict continuous 24-hour validation.

Collection sessions store `last_heartbeat_at` and periodically persisted counters/errors. After a crash or power-off, recovery stops the stale session at the last heartbeat, so time while the computer or app was not running is not counted as collected duration. A session with no available collectors is rejected and does not count.

Process and network collectors use polling. Polling can miss very short-lived processes/connections. Process identity includes PID and process create time, so PID reuse is represented as the old process stopping and a new process starting.

## Demo Scenario Validation

Synthetic demo scenarios are validated after inference by matching the anomaly windows against a separate manifest. The manifest is not passed into model training, feature engineering, or anomaly scoring.

Stage 3 keeps the same boundary: scenario windows are used only for held-out synthetic
evaluation and recommendation after scoring. They are never training features or
calibration inputs.

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

## Stage 2 Usable Coverage

Stage 2 changes the real training gate from raw session duration to usable real coverage:
at least 24 cumulative hours of good 15-minute real feature windows in one user+host
profile. Process and system metrics are core sources, network is recommended, and
authentication is optional. Missing authentication rights do not make the whole dataset
unusable.

Coverage comes from per-poll collector observations. A successful zero-event poll counts
as coverage because it proves the collector ran and observed no changes. Gaps in
observations reduce coverage, and session `started_at` to `stopped_at` is not counted as
usable coverage by itself.

Collectors report an explicit poll result to the manager. `successful=true` means the
source was actually polled; it is not inferred from the absence of a thrown exception.
Process and network collectors may return successful zero-event polls when there are no
changes. Whole-source failures such as `AccessDenied`, `OSError`, permission loss, or
Event Log query/render failures produce failed observations with `successful_poll=0`.
Returned event counts and saved event counts are stored separately.

## Delete Local Telemetry

```powershell
uv run sentinelueba clean
Remove-Item -Recurse -Force data, artifacts, logs, reports -ErrorAction SilentlyContinue
```
