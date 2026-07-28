param(
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

$env:SENTINELUEBA_BUILD_COMMIT = $GitCommit
$env:SENTINELUEBA_BUILD_TIMESTAMP_UTC = $BuildTimestampUtc
$env:SENTINELUEBA_PACKAGED = "1"

pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
uv run python -c "from pathlib import Path; from sentinelueba.runtime.installation import write_frontend_asset_manifest; write_frontend_asset_manifest(Path('frontend/dist'))"

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build, dist\SentinelUEBA
uv run pyinstaller --noconfirm packaging/windows/SentinelUEBA.spec

$packageDir = "dist\SentinelUEBA"
if (-not (Test-Path $packageDir)) {
  throw "PyInstaller package directory was not created: $packageDir"
}

$frontendTarget = Join-Path $packageDir "frontend"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $frontendTarget
Copy-Item -Recurse -Force "frontend\dist" $frontendTarget

foreach ($file in @("LICENSE", "README.md", "README.ru.md", "THIRD_PARTY_NOTICES.txt")) {
  Copy-Item -Force $file (Join-Path $packageDir $file)
}
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $packageDir "docs")
Copy-Item -Recurse -Force "docs" (Join-Path $packageDir "docs")

$internal = Join-Path $packageDir "_internal"
foreach ($duplicate in @("frontend", "docs", "LICENSE", "README.md", "README.ru.md", "THIRD_PARTY_NOTICES.txt")) {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $internal $duplicate)
}
