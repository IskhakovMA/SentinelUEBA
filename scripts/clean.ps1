$ErrorActionPreference = "Stop"
if (Test-Path .\.venv\Scripts\sentinelueba.exe) {
  .\.venv\Scripts\sentinelueba clean
}
Remove-Item -Recurse -Force data, artifacts, logs, reports -ErrorAction SilentlyContinue

