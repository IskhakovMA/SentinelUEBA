from __future__ import annotations

import sys

from sentinelueba.runtime.service import (
    dispatch_service,
    handle_service_command_line,
    run_service_debug_smoke,
)


def main() -> int:
    if "--debug-smoke" in sys.argv:
        print(run_service_debug_smoke())
        return 0
    management_args = {"install", "remove", "uninstall", "start", "stop", "restart", "debug"}
    if any(arg.lower() in management_args for arg in sys.argv[1:]):
        handle_service_command_line()
        return 0
    dispatch_service()
    return 0


if __name__ == "__main__":
    sys.exit(main())
