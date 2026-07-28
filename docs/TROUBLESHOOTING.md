# Troubleshooting

Use safe diagnostics:

```powershell
SentinelUEBA.exe host doctor
SentinelUEBA.exe verify-installation
```

Common states:

- `unsigned_verified`: expected for PR Technical Preview builds. It verifies internal consistency,
  not publisher authenticity.
- `tampered`: a shipped file changed or an extra executable/library was found.
- `incomplete`: `release-manifest.json` or a shipped file is missing.
- `degraded`: the host is available but a non-critical readiness check failed.
- `failed`: startup blocked to avoid unsafe runtime state.

Data is not removed automatically when uninstalling or deleting the portable directory.
Remove `%LOCALAPPDATA%\SentinelUEBA` or `%PROGRAMDATA%\SentinelUEBA` manually only when local data is
no longer needed.

Import older data explicitly:

```powershell
SentinelUEBA.exe runtime import-data --source C:\Path\To\Old\Data --confirm
```

The import command previews first unless `--confirm` is supplied, creates a local backup, skips
secrets and transient runtime locks, and does not migrate the source database in place.

If `host doctor` reports `migration_required`, start the host or run the planned packaged migration
path after making sure the generated backup can be retained. Doctor itself does not mutate the
database.
