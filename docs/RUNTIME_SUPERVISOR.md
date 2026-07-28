# Runtime Supervisor

Stage 5 introduces a single local host supervisor shared by desktop and service mode.

```mermaid
flowchart TD
  A["Launcher / CLI / Windows Service"] --> B["Runtime Supervisor"]
  B --> C["Loopback FastAPI + embedded React"]
  B --> D["SQLite / snapshots / models"]
  B --> E["Collector Manager"]
  B --> F["Detection Worker Manager"]
  B --> G["graceful shutdown and local logs"]
```

The supervisor resolves runtime paths, acquires a single-instance lock, verifies the installation
manifest in packaged mode, initializes SQLite, checks frontend assets, selects a loopback port,
starts Uvicorn in-process, writes safe status metadata, and cleans transient control files during
shutdown.

Readiness means the process, SQLite, runtime root, and packaged frontend are available. It does not
mean collectors are running, a champion model exists, or 24 hours of collection are complete.
