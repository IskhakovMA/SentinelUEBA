from __future__ import annotations

import ctypes
import os
import sys
from contextlib import suppress


def _message_box(message: str) -> None:
    with suppress(Exception):
        ctypes.windll.user32.MessageBoxW(None, message, "SentinelUEBA", 0x10)


def _ensure_safe_stdio() -> None:
    if sys.stdin is None:
        sys.stdin = open(os.devnull, encoding="utf-8")  # noqa: SIM115 - process lifetime stream.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115


def main() -> int:
    _ensure_safe_stdio()
    try:
        from sentinelueba.runtime.supervisor import run_host

        run_host(open_browser=True, windowed=True)
        return 0
    except Exception as exc:
        _message_box(f"SentinelUEBA could not start safely: {exc.__class__.__name__}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
