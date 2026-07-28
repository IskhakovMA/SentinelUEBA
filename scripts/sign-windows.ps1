param(
  [string]$PackageDir = "dist\SentinelUEBA",
  [string]$CertificateThumbprint = $env:SENTINELUEBA_SIGN_CERT_THUMBPRINT,
  [string]$PfxPath = $env:SENTINELUEBA_SIGN_PFX_PATH,
  [string]$TimestampUrl = $env:SENTINELUEBA_SIGN_TIMESTAMP_URL
)

$ErrorActionPreference = "Stop"

if (-not $CertificateThumbprint -and -not $PfxPath) {
  Write-Host "Signing not configured; leaving unsigned Technical Preview build."
  exit 0
}

$signTool = Get-Command signtool.exe -ErrorAction Stop
$files = Get-ChildItem -Path $PackageDir -Recurse -File |
  Where-Object { $_.Extension -in ".exe", ".dll", ".pyd" }

foreach ($file in $files) {
  $args = @("sign", "/fd", "SHA256")
  if ($CertificateThumbprint) {
    $args += @("/sha1", $CertificateThumbprint)
  } else {
    if (-not $env:SENTINELUEBA_SIGN_PFX_PASSWORD) {
      throw "PFX signing requires SENTINELUEBA_SIGN_PFX_PASSWORD."
    }
    $args += @("/f", $PfxPath, "/p", $env:SENTINELUEBA_SIGN_PFX_PASSWORD)
  }
  if ($TimestampUrl) {
    $args += @("/tr", $TimestampUrl, "/td", "SHA256")
  }
  $args += @($file.FullName)
  & $signTool.Source @args
  if ($LASTEXITCODE -ne 0) {
    throw "SignTool failed for $($file.Name)."
  }
  & $signTool.Source verify /pa $file.FullName
  if ($LASTEXITCODE -ne 0) {
    throw "SignTool verify failed for $($file.Name)."
  }
}
