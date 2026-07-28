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
- expected executable names;
- packaged mode, target platform, and architecture;
- canonical manifest payload hash.

Manifest file records must use normalized relative POSIX paths. Absolute paths, Windows drive/UNC
paths, backslashes, `..`, duplicates, symlink/reparse escapes, and extra EXE/DLL/PYD files fail
verification.

`dependency-inventory.json` is part of the package and is verified by SHA-256. It records normalized
distribution names, versions, and license metadata when available in deterministic order.

`sentinelueba verify-installation` returns one of:

- `verified`;
- `unsigned_verified`;
- `tampered`;
- `incomplete`;
- `unsupported_manifest`.

`unsigned_verified` means the package is internally consistent but does not prove publisher
authenticity. `signed=true` in the manifest is not trusted by itself; signed packages are considered
`verified` only when the expected EXE/DLL/PYD files pass Authenticode verification through the
Windows trust adapter.

Packaged host startup blocks tampered or incomplete installations. Read-only `doctor` and
`verify-installation` remain available. Errors are safe and do not expose home, workspace, or
installation paths.
