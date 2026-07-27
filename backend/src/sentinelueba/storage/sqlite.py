from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelueba.domain.events import AnomalyRecord, EventType, TelemetryEvent

DB_SCHEMA_VERSION = 2


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
            current_version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            version = int(current_version or 0)
            if version < 1:
                self._apply_v1(conn)
                version = 1
            if version < 2:
                self._apply_v2(conn)

    def _record_migration(self, conn: sqlite3.Connection, version: int) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES (?, ?)",
            (version, datetime.now(UTC).isoformat()),
        )

    def _apply_v1(self, conn: sqlite3.Connection) -> None:
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON telemetry_events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON telemetry_events(event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON telemetry_events(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON telemetry_events(host_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_time ON anomalies(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_risk ON anomalies(risk_level)")
        self._record_migration(conn, 1)

    def _apply_v2(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(anomalies)").fetchall()
        }
        if "feature_contributions_json" not in columns:
            conn.execute(
                "ALTER TABLE anomalies ADD COLUMN feature_contributions_json "
                "TEXT NOT NULL DEFAULT '[]'"
            )
        if "range_kind" not in columns:
            conn.execute(
                "ALTER TABLE anomalies ADD COLUMN range_kind "
                "TEXT NOT NULL DEFAULT 'evaluation'"
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS collection_sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                stopped_at TEXT,
                status TEXT NOT NULL,
                collection_mode TEXT NOT NULL,
                enabled_collectors_json TEXT NOT NULL,
                counters_json TEXT NOT NULL,
                errors_json TEXT NOT NULL,
                application_version TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS collector_state (
                collector_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                cursor_json TEXT NOT NULL,
                last_error TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_started ON collection_sessions(started_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_status ON collection_sessions(status)"
        )
        self._record_migration(conn, 2)

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

    def list_events(
        self,
        *,
        synthetic: bool | None = None,
        event_type: EventType | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[TelemetryEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if synthetic is not None:
            clauses.append("synthetic = ?")
            params.append(int(synthetic))
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type.value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_sql = ""
        if limit is not None:
            limit_sql = " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM telemetry_events {where} "
                f"ORDER BY timestamp ASC, event_id ASC{limit_sql}",
                params,
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
                    top_features_json, feature_contributions_json, explanation, model_version,
                    window_start, window_end, range_kind
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        json.dumps(anomaly.feature_contributions),
                        anomaly.explanation,
                        anomaly.model_version,
                        anomaly.window_start.isoformat(),
                        anomaly.window_end.isoformat(),
                        anomaly.range_kind,
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
                feature_contributions=json.loads(row["feature_contributions_json"]),
                explanation=row["explanation"],
                model_version=row["model_version"],
                window_start=datetime.fromisoformat(row["window_start"]),
                window_end=datetime.fromisoformat(row["window_end"]),
                range_kind=row["range_kind"],
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
            real_event_count = conn.execute(
                "SELECT COUNT(*) FROM telemetry_events WHERE synthetic = 0"
            ).fetchone()[0]
            anomaly_count = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            schema = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        return {
            "database_path": str(self.database_path),
            "schema_version": schema,
            "event_count": event_count,
            "real_event_count": real_event_count,
            "anomaly_count": anomaly_count,
        }

    def upsert_collector_state(
        self,
        collector_id: str,
        status: str,
        cursor: dict[str, object],
        last_error: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO collector_state (
                    collector_id, status, cursor_json, last_error, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(collector_id) DO UPDATE SET
                    status = excluded.status,
                    cursor_json = excluded.cursor_json,
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at
                """,
                (
                    collector_id,
                    status,
                    json.dumps(cursor, sort_keys=True),
                    last_error,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def get_collector_cursor(self, collector_id: str) -> dict[str, object]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT cursor_json FROM collector_state WHERE collector_id = ?",
                (collector_id,),
            ).fetchone()
        if row is None:
            return {}
        payload = json.loads(row["cursor_json"])
        return payload if isinstance(payload, dict) else {}

    def start_session(
        self,
        session_id: str,
        collection_mode: str,
        enabled_collectors: list[str],
        application_version: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO collection_sessions (
                    session_id, started_at, stopped_at, status, collection_mode,
                    enabled_collectors_json, counters_json, errors_json, application_version
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    datetime.now(UTC).isoformat(),
                    "running",
                    collection_mode,
                    json.dumps(enabled_collectors),
                    json.dumps({}),
                    json.dumps([]),
                    application_version,
                ),
            )

    def finish_session(
        self,
        session_id: str,
        status: str,
        counters: dict[str, int],
        errors: list[str],
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE collection_sessions
                SET stopped_at = ?, status = ?, counters_json = ?, errors_json = ?
                WHERE session_id = ?
                """,
                (
                    datetime.now(UTC).isoformat(),
                    status,
                    json.dumps(counters, sort_keys=True),
                    json.dumps(errors),
                    session_id,
                ),
            )

    def list_sessions(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM collection_sessions ORDER BY started_at DESC"
            ).fetchall()
        return [self._session_row(row) for row in rows]

    def get_running_session(self) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM collection_sessions WHERE status = 'running' "
                "ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return self._session_row(row) if row is not None else None

    def mark_stale_running_sessions(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE collection_sessions
                SET stopped_at = ?, status = 'interrupted'
                WHERE status = 'running'
                """,
                (datetime.now(UTC).isoformat(),),
            )

    def event_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, synthetic, COUNT(*) AS count
                FROM telemetry_events
                GROUP BY event_type, synthetic
                """
            ).fetchall()
        summary: dict[str, Any] = {"synthetic": {}, "real": {}}
        for row in rows:
            bucket = "synthetic" if bool(row["synthetic"]) else "real"
            summary[bucket][row["event_type"]] = row["count"]
        return summary

    def collection_progress(self) -> dict[str, Any]:
        sessions = list(reversed(self.list_sessions()))
        now = datetime.now(UTC)
        durations: list[float] = []
        gaps: list[dict[str, str | float]] = []
        previous_stop: datetime | None = None
        current_duration = 0.0
        for session in sessions:
            start = datetime.fromisoformat(str(session["started_at"]))
            stopped_raw = session.get("stopped_at")
            stop = (
                datetime.fromisoformat(str(stopped_raw))
                if stopped_raw
                else now
            )
            duration = max(0.0, (stop - start).total_seconds())
            durations.append(duration)
            if session["status"] == "running":
                current_duration = duration
            if previous_stop is not None and start > previous_stop:
                gaps.append(
                    {
                        "from": previous_stop.isoformat(),
                        "to": start.isoformat(),
                        "seconds": (start - previous_stop).total_seconds(),
                    }
                )
            previous_stop = stop
        cumulative = sum(durations)
        longest = max(durations, default=0.0)
        target = 24 * 60 * 60
        return {
            "cumulative_collected_seconds": cumulative,
            "longest_continuous_session_seconds": longest,
            "current_session_seconds": current_duration,
            "gaps": gaps,
            "progress_to_24h": min(1.0, cumulative / target),
            "strict_continuous_24h_validated": longest >= target,
        }

    def _session_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "session_id": row["session_id"],
            "started_at": row["started_at"],
            "stopped_at": row["stopped_at"],
            "status": row["status"],
            "collection_mode": row["collection_mode"],
            "enabled_collectors": json.loads(row["enabled_collectors_json"]),
            "counters": json.loads(row["counters_json"]),
            "errors": json.loads(row["errors_json"]),
            "application_version": row["application_version"],
        }
