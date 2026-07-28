# Windows Service

Stage 5 includes an optional Windows Service entrypoint. It is not installed automatically.

Service id: `SentinelUEBA`

Display name: `SentinelUEBA Local Host`

Account: `NT AUTHORITY\LocalService`

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
It does not change Windows Firewall rules, does not create an autostart entry, and does not delete
user data on uninstall. Install writes a quoted `SentinelUEBAService.exe` service path and configures
three bounded restart attempts rather than an infinite restart policy.

The frozen service entry uses the pywin32 SCM dispatcher for normal service execution. Explicit
management/debug commands use the pywin32 command-line handler or the safe debug smoke path.

User-session telemetry collection is disabled in service mode by default. `POST /collection/start`
returns HTTP 409 with a safe explanation because desktop user collectors belong to an interactive
session. Service mode still allows API, frontend, data quality, feature materialization, ML
operations, detection worker, finding lifecycle, and suppressions when explicitly requested.
