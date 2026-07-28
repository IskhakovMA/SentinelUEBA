from __future__ import annotations

import ctypes
import sys
from contextlib import suppress

from sentinelueba.runtime.supervisor import run_host


def _message_box(message: str) -> None:
    with suppress(Exception):
        ctypes.windll.user32.MessageBoxW(None, message, "SentinelUEBA", 0x10)


def main() -> int:
    try:
        run_host(open_browser=True)
        return 0
    except Exception as exc:
        _message_box(f"SentinelUEBA could not start safely: {exc.__class__.__name__}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
