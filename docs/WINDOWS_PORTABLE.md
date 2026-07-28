# Windows Portable

Stage 5 adds an unsigned Technical Preview Windows x64 portable bundle:

- `SentinelUEBA.exe` for console CLI commands;
- `SentinelUEBALauncher.exe` for desktop startup without a console window;
- `SentinelUEBAService.exe` for the optional Windows Service entrypoint;
- embedded React production assets served by the local FastAPI backend;
- `release-manifest.json` with SHA-256 hashes for shipped files;
- `dependency-inventory.json` with deterministic package names, versions, and license metadata when available.

The package is PyInstaller one-folder, not one-file. It does not require installed Python or
Node.js at runtime. Runtime data is written outside the installation directory.

Desktop runtime root:

`%LOCALAPPDATA%\SentinelUEBA\`

Service runtime root:

`%PROGRAMDATA%\SentinelUEBA\`

Each root contains `config`, `data`, `models`, `logs`, `runtime`, and `backups`.
The package directory can be read-only.

The desktop launcher is single-instance. A second launch reads the first host status, opens the
existing loopback URL when configured, and exits without rewriting or deleting the owning host's
`status.json` or `control.token`.

Start desktop mode with `SentinelUEBALauncher.exe` or:

```powershell
SentinelUEBA.exe host run --open-browser
```

Stop desktop mode:

```powershell
SentinelUEBA.exe host stop --confirm
```

Verify installation integrity:

```powershell
SentinelUEBA.exe verify-installation
```

Unsigned PR builds are expected to report `unsigned_verified`. That status means file consistency,
manifest consistency, dependency inventory integrity, and runtime-path safety passed. It does not
prove publisher authenticity. A package with `signed=true` reports `verified` only after the expected
EXE/DLL/PYD files pass Authenticode verification.
