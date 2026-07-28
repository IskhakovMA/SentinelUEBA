# Installation Integrity

Portable packages include `release-manifest.json`. The manifest records:

- schema version;
- application version;
- build commit and UTC timestamp;
- Windows x64 target;
- signed or unsigned status;
- relative shipped files;
- file sizes;
- SHA-256 hashes;
- frontend manifest hash;
- dependency inventory hash;
- canonical manifest payload hash.

`sentinelueba verify-installation` returns one of:

- `verified`;
- `unsigned_verified`;
- `tampered`;
- `incomplete`;
- `unsupported_manifest`.

Packaged host startup blocks tampered or incomplete installations. Read-only `doctor` and
`verify-installation` remain available. Errors are safe and do not expose home, workspace, or
installation paths.
