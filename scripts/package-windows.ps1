param(
  [string]$PackageDir = "dist\SentinelUEBA",
  [string]$Version = "0.5.0",
  [string]$GitCommit = $env:GITHUB_SHA,
  [string]$BuildTimestampUtc = $env:SENTINELUEBA_BUILD_TIMESTAMP_UTC
)

$ErrorActionPreference = "Stop"

if (-not $GitCommit) {
  $GitCommit = "development"
}
if (-not $BuildTimestampUtc) {
  $BuildTimestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

& "$PSScriptRoot\build-windows.ps1" -GitCommit $GitCommit -BuildTimestampUtc $BuildTimestampUtc
& "$PSScriptRoot\sign-windows.ps1" -PackageDir $PackageDir

$signed = [bool]($env:SENTINELUEBA_SIGN_CERT_THUMBPRINT -or $env:SENTINELUEBA_SIGN_PFX_PATH)
$env:SENTINELUEBA_SIGNED = if ($signed) { "1" } else { "0" }
$signedLiteral = if ($signed) { "True" } else { "False" }

uv run python -c "from pathlib import Path; from sentinelueba.runtime.installation import create_release_manifest, dependency_inventory_hash, sha256_file, canonical_json; package=Path('$PackageDir'); frontend=package/'frontend'/'frontend-assets.json'; manifest=create_release_manifest(package, version='$Version', git_commit='$GitCommit', build_timestamp_utc='$BuildTimestampUtc', signed=$signedLiteral, frontend_manifest_sha256=sha256_file(frontend) if frontend.exists() else None, dependency_inventory_sha256=dependency_inventory_hash()); (package/'release-manifest.json').write_bytes(canonical_json(manifest))"

$zip = "dist\SentinelUEBA-$Version-windows-x64-portable.zip"
Remove-Item -Force -ErrorAction SilentlyContinue $zip, "$zip.sha256"
Compress-Archive -Path $PackageDir -DestinationPath $zip
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
"$hash  $(Split-Path -Leaf $zip)" | Set-Content -Encoding ascii "$zip.sha256"
Write-Host "ZIP=$zip"
Write-Host "SHA256=$hash"
