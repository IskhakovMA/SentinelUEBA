from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5


class SafeFormatter(logging.Formatter):
    def __init__(self, secrets: list[str] | None = None) -> None:
        super().__init__()
        self._secrets = [item for item in (secrets or []) if item]

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp_utc": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "component": getattr(record, "component", record.name),
            "event": getattr(record, "event", "runtime_log"),
            "message": self._redact(record.getMessage()),
        }
        if record.exc_info:
            payload["error_class"] = (
                record.exc_info[0].__name__ if record.exc_info[0] is not None else "Exception"
            )
        return json.dumps(payload, sort_keys=True)

    def _redact(self, value: str) -> str:
        redacted = value
        for secret in self._secrets:
            redacted = redacted.replace(secret, "<redacted>")
        return redacted


def configure_runtime_logging(
    logs_dir: Path,
    *,
    level: str = "INFO",
    secrets: list[str] | None = None,
) -> None:
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("sentinelueba")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers = []
    handler = RotatingFileHandler(
        logs_dir / "sentinelueba.log",
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(SafeFormatter(secrets=secrets))
    logger.addHandler(handler)
    logger.propagate = False


def log_event(component: str, event: str, message: str, *, level: int = logging.INFO) -> None:
    logging.getLogger("sentinelueba").log(
        level,
        message,
        extra={"component": component, "event": event},
    )
