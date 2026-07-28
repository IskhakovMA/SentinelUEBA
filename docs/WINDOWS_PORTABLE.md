# Windows Portable

Stage 5 adds an unsigned Technical Preview Windows x64 portable bundle:

- `SentinelUEBA.exe` for console CLI commands;
- `SentinelUEBALauncher.exe` for desktop startup without a console window;
- `SentinelUEBAService.exe` for the optional Windows Service entrypoint;
- embedded React production assets served by the local FastAPI backend;
- `release-manifest.json` with SHA-256 hashes for shipped files.

The package is PyInstaller one-folder, not one-file. It does not require installed Python or
Node.js at runtime. Runtime data is written outside the installation directory.

Desktop runtime root:

`%LOCALAPPDATA%\SentinelUEBA\`

Service runtime root:

`%PROGRAMDATA%\SentinelUEBA\`

Each root contains `config`, `data`, `models`, `logs`, `runtime`, and `backups`.
The package directory can be read-only.

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

Unsigned PR builds are expected to report `unsigned_verified`.
