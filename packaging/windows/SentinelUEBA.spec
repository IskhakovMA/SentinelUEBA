# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path.cwd()
FRONTEND_DIST = ROOT / "frontend" / "dist"

datas = [
    (str(ROOT / "LICENSE"), "."),
    (str(ROOT / "README.md"), "."),
    (str(ROOT / "README.ru.md"), "."),
    (str(ROOT / "THIRD_PARTY_NOTICES.txt"), "."),
    (str(ROOT / "docs"), "docs"),
]
if FRONTEND_DIST.exists():
    datas.append((str(FRONTEND_DIST), "frontend"))

datas += collect_data_files("skops")
datas += collect_data_files("pyarrow")

hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("sentinelueba")
    + collect_submodules("skops")
    + ["win32timezone", "win32serviceutil", "win32service", "win32event", "servicemanager"]
)

common_kwargs = {
    "pathex": [str(ROOT / "backend" / "src")],
    "binaries": [],
    "datas": datas,
    "hiddenimports": hiddenimports,
    "hookspath": [],
    "hooksconfig": {},
    "runtime_hooks": [],
    "excludes": ["pytest", "node_modules"],
    "noarchive": False,
    "optimize": 0,
}

cli_analysis = Analysis([str(ROOT / "packaging" / "windows" / "cli_entry.py")], **common_kwargs)
cli_pyz = PYZ(cli_analysis.pure)
cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    [],
    exclude_binaries=True,
    name="SentinelUEBA",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

launcher_analysis = Analysis(
    [str(ROOT / "packaging" / "windows" / "launcher_entry.py")],
    **common_kwargs,
)
launcher_pyz = PYZ(launcher_analysis.pure)
launcher_exe = EXE(
    launcher_pyz,
    launcher_analysis.scripts,
    [],
    exclude_binaries=True,
    name="SentinelUEBALauncher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)

service_analysis = Analysis(
    [str(ROOT / "packaging" / "windows" / "service_entry.py")],
    **common_kwargs,
)
service_pyz = PYZ(service_analysis.pure)
service_exe = EXE(
    service_pyz,
    service_analysis.scripts,
    [],
    exclude_binaries=True,
    name="SentinelUEBAService",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)

coll = COLLECT(
    cli_exe,
    launcher_exe,
    service_exe,
    cli_analysis.binaries
    + launcher_analysis.binaries
    + service_analysis.binaries,
    cli_analysis.datas
    + launcher_analysis.datas
    + service_analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SentinelUEBA",
)
