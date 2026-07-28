# 0018 Explicit Worker Lease

The Stage 4 worker is a local SQLite lease.

It records owner, heartbeat, stop request, status, config, and sanitized errors. It does
not install a Windows Service, autostart entry, daemon, MSI, or production supervisor.
