from __future__ import annotations

import sys

from sentinelueba.runtime.service import run_service_debug_smoke
from sentinelueba.runtime.supervisor import run_host


def main() -> int:
    if "--debug-smoke" in sys.argv:
        print(run_service_debug_smoke())
        return 0
    run_host(service=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
