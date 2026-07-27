from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelueba.domain.events import AnomalyRecord, EventType, TelemetryEvent

DB_SCHEMA_VERSION = 1


class SQLiteStorage:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    synthetic INTEGER NOT NULL,
                    schema_version TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    threshold_value REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    top_features_json TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    UNIQUE(user_id, host_id, window_start, model_version)
                )
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES (?, ?)",
                (DB_SCHEMA_VERSION, datetime.now(UTC).isoformat()),
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_time ON telemetry_events(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_type ON telemetry_events(event_type)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON telemetry_events(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON telemetry_events(host_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_time ON anomalies(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_risk ON anomalies(risk_level)")

    def insert_events(self, events: list[TelemetryEvent]) -> int:
        with self.connect() as conn:
            before = conn.total_changes
            conn.executemany(
                """
                INSERT OR IGNORE INTO telemetry_events (
                    event_id, timestamp, event_type, user_id, host_id, source,
                    payload_json, synthetic, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.event_type.value,
                        event.user_id,
                        event.host_id,
                        event.source,
                        json.dumps(event.payload, sort_keys=True),
                        int(event.synthetic),
                        event.schema_version,
                    )
                    for event in events
                ],
            )
            return int(conn.total_changes - before)

    def list_events(self) -> list[TelemetryEvent]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM telemetry_events ORDER BY timestamp ASC, event_id ASC"
            ).fetchall()
        return [
            TelemetryEvent(
                event_id=row["event_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                event_type=EventType(row["event_type"]),
                user_id=row["user_id"],
                host_id=row["host_id"],
                source=row["source"],
                payload=json.loads(row["payload_json"]),
                synthetic=bool(row["synthetic"]),
                schema_version=row["schema_version"],
            )
            for row in rows
        ]

    def replace_anomalies(self, anomalies: list[AnomalyRecord]) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM anomalies")
            conn.executemany(
                """
                INSERT OR IGNORE INTO anomalies (
                    timestamp, user_id, host_id, anomaly_score, threshold_value, risk_level,
                    top_features_json, explanation, model_version, window_start, window_end
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        anomaly.timestamp.isoformat(),
                        anomaly.user_id,
                        anomaly.host_id,
                        anomaly.anomaly_score,
                        anomaly.threshold,
                        anomaly.risk_level.value,
                        json.dumps(anomaly.top_features),
                        anomaly.explanation,
                        anomaly.model_version,
                        anomaly.window_start.isoformat(),
                        anomaly.window_end.isoformat(),
                    )
                    for anomaly in anomalies
                ],
            )

    def list_anomalies(self) -> list[AnomalyRecord]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM anomalies ORDER BY anomaly_score DESC").fetchall()
        return [
            AnomalyRecord(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                user_id=row["user_id"],
                host_id=row["host_id"],
                anomaly_score=row["anomaly_score"],
                threshold=row["threshold_value"],
                risk_level=row["risk_level"],
                top_features=json.loads(row["top_features_json"]),
                explanation=row["explanation"],
                model_version=row["model_version"],
                window_start=datetime.fromisoformat(row["window_start"]),
                window_end=datetime.fromisoformat(row["window_end"]),
            )
            for row in rows
        ]

    def clear_demo_data(self) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM anomalies")
            conn.execute("DELETE FROM telemetry_events WHERE synthetic = 1")

    def status(self) -> dict[str, Any]:
        with self.connect() as conn:
            event_count = conn.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0]
            anomaly_count = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            schema = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        return {
            "database_path": str(self.database_path),
            "schema_version": schema,
            "event_count": event_count,
            "anomaly_count": anomaly_count,
        }
