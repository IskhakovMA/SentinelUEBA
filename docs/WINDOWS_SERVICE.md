# Windows Service

Stage 5 includes an optional Windows Service entrypoint. It is not installed automatically.

Service id: `SentinelUEBA`

Display name: `SentinelUEBA Local Host`

Install:

```powershell
SentinelUEBA.exe service install --confirm
```

Uninstall:

```powershell
SentinelUEBA.exe service uninstall --confirm
```

Start and stop:

```powershell
SentinelUEBA.exe service start
SentinelUEBA.exe service stop --confirm
```

The service is Windows-only, manual-start, loopback-only, and uses `%PROGRAMDATA%\SentinelUEBA`.
It does not change Windows Firewall rules and does not delete user data on uninstall.

User-session telemetry collection is disabled in service mode by default. `POST /collection/start`
returns HTTP 409 with a safe explanation because desktop user collectors belong to an interactive
session. Service mode still allows API, frontend, data quality, feature materialization, ML
operations, detection worker, finding lifecycle, and suppressions when explicitly requested.
