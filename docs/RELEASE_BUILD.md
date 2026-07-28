# Release Build

Build an unsigned Technical Preview portable package on Windows:

```powershell
.\scripts\package-windows.ps1
```

The script:

1. builds the React/Vite frontend;
2. writes `frontend-assets.json`;
3. runs PyInstaller one-folder;
4. optionally signs binaries when SignTool configuration exists;
5. writes canonical `release-manifest.json`;
6. creates `SentinelUEBA-0.5.0-windows-x64-portable.zip`;
7. writes `SentinelUEBA-0.5.0-windows-x64-portable.zip.sha256`.

Optional signing inputs:

- `SENTINELUEBA_SIGN_CERT_THUMBPRINT`;
- or `SENTINELUEBA_SIGN_PFX_PATH` plus secret `SENTINELUEBA_SIGN_PFX_PASSWORD`;
- optional RFC 3161 timestamp URL in `SENTINELUEBA_SIGN_TIMESTAMP_URL`.

Unsigned PR builds remain valid and are marked `signed=false`.
Production signing certificates are out of scope for Stage 5.
