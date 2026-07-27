from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelueba.domain.events import AnomalyRecord, EventType, TelemetryEvent
from sentinelueba.validation import (
    EVENT_SCHEMA_VERSION,
    ValidationFailure,
    payload_hash,
    validate_event,
)

DB_SCHEMA_VERSION = 5


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
                version = 2
            if version < 3:
                self._apply_v3(conn)
                version = 3
            if version < 4:
                self._apply_v4(conn)
                version = 4
            if version < 5:
                self._apply_v5(conn)
            if version >= DB_SCHEMA_VERSION:
                self._apply_v3(conn)
                self._apply_v4(conn)
                self._apply_v5(conn)

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

    def _apply_v3(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(collection_sessions)").fetchall()
        }
        if "last_heartbeat_at" not in columns:
            conn.execute("ALTER TABLE collection_sessions ADD COLUMN last_heartbeat_at TEXT")
        if "last_successful_collection_at" not in columns:
            conn.execute(
                "ALTER TABLE collection_sessions ADD COLUMN "
                "last_successful_collection_at TEXT"
            )
        self._record_migration(conn, 3)

    def _apply_v4(self, conn: sqlite3.Connection) -> None:
        event_columns = self._columns(conn, "telemetry_events")
        metadata_columns = {
            "ingested_at": "TEXT",
            "collection_session_id": "TEXT",
            "collector_id": "TEXT",
            "collector_version": "TEXT",
            "validation_status": "TEXT",
            "payload_hash": "TEXT",
            "event_schema_version": "TEXT",
        }
        for column, column_type in metadata_columns.items():
            if column not in event_columns:
                conn.execute(f"ALTER TABLE telemetry_events ADD COLUMN {column} {column_type}")
        now = datetime.now(UTC).isoformat()
        rows = conn.execute(
            """
            SELECT event_id, payload_json, source, schema_version
            FROM telemetry_events
            """
        ).fetchall()
        for row in rows:
            try:
                parsed_payload = json.loads(row["payload_json"])
                parsed_hash = payload_hash(
                    parsed_payload if isinstance(parsed_payload, dict) else {}
                )
            except (TypeError, ValueError):
                parsed_hash = ""
            conn.execute(
                """
                UPDATE telemetry_events
                SET ingested_at = COALESCE(ingested_at, ?),
                    collector_id = COALESCE(collector_id, source),
                    collector_version = COALESCE(collector_version, 'unknown'),
                    validation_status = COALESCE(validation_status, 'accepted'),
                    payload_hash = COALESCE(payload_hash, ?),
                    event_schema_version = COALESCE(event_schema_version, schema_version)
                WHERE event_id = ?
                """,
                (now, parsed_hash, row["event_id"]),
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantined_events (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                collector_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_schema_version TEXT NOT NULL,
                error_class TEXT NOT NULL,
                reason TEXT NOT NULL,
                safe_event_json TEXT NOT NULL,
                payload_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_windows (
                window_id TEXT PRIMARY KEY,
                dataset_kind TEXT NOT NULL,
                user_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                feature_schema_version TEXT NOT NULL,
                window_size_minutes INTEGER NOT NULL,
                features_json TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                event_counts_json TEXT NOT NULL,
                collector_coverage_json TEXT NOT NULL,
                quality_status TEXT NOT NULL,
                quality_reasons_json TEXT NOT NULL,
                gap_duration_seconds REAL NOT NULL,
                finalized INTEGER NOT NULL,
                source_event_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(dataset_kind, user_id, host_id, window_start, feature_schema_version)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_materialization_state (
                dataset_kind TEXT PRIMARY KEY,
                watermark TEXT,
                last_materialized_at TEXT NOT NULL,
                late_event_interval_minutes INTEGER NOT NULL,
                window_size_minutes INTEGER NOT NULL,
                baseline_state_json TEXT NOT NULL,
                last_rebuild_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS data_quality_runs (
                run_id TEXT PRIMARY KEY,
                dataset_kind TEXT NOT NULL,
                created_at TEXT NOT NULL,
                summary_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dataset_snapshots (
                dataset_id TEXT PRIMARY KEY,
                dataset_kind TEXT NOT NULL,
                created_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                parquet_sha256 TEXT NOT NULL,
                feature_schema_version TEXT NOT NULL,
                profile_json TEXT NOT NULL,
                start_at TEXT NOT NULL,
                end_at TEXT NOT NULL,
                window_count INTEGER NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_ingested_at "
            "ON telemetry_events(ingested_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_dataset_time "
            "ON telemetry_events(synthetic, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_received "
            "ON quarantined_events(received_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_windows_kind_time "
            "ON feature_windows(dataset_kind, window_start)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_windows_quality "
            "ON feature_windows(dataset_kind, quality_status)"
        )
        self._record_migration(conn, 4)

    def _columns(self, conn: sqlite3.Connection, table: str) -> set[str]:
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _apply_v5(self, conn: sqlite3.Connection) -> None:
        state_columns = self._columns(conn, "feature_materialization_state")
        state_metadata_columns = {
            "last_ingested_at": "TEXT",
            "last_event_id": "TEXT",
            "event_time_watermark": "TEXT",
            "last_observation_at": "TEXT",
            "last_successful_run_at": "TEXT",
            "late_events_within_policy": "INTEGER NOT NULL DEFAULT 0",
            "late_events_outside_policy": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, column_type in state_metadata_columns.items():
            if column not in state_columns:
                conn.execute(
                    f"ALTER TABLE feature_materialization_state ADD COLUMN {column} {column_type}"
                )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS collector_observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                collector_id TEXT NOT NULL,
                user_id TEXT,
                host_id TEXT,
                observed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                successful_poll INTEGER NOT NULL,
                error_class TEXT,
                configured_interval_seconds REAL NOT NULL,
                returned_events INTEGER NOT NULL,
                saved_events INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS late_event_records (
                late_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_kind TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                policy_boundary TEXT NOT NULL,
                within_policy INTEGER NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(dataset_kind, event_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS duplicate_event_records (
                duplicate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                first_seen_at TEXT,
                duplicate_seen_at TEXT NOT NULL,
                collector_id TEXT,
                source TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_observations_kind_time "
            "ON collector_observations(observed_at, collector_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_observations_session "
            "ON collector_observations(session_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_late_events_kind_time "
            "ON late_event_records(dataset_kind, event_timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_duplicate_events_kind "
            "ON duplicate_event_records(dataset_kind, duplicate_seen_at)"
        )
        self._record_migration(conn, 5)

    def insert_events(self, events: list[TelemetryEvent]) -> int:
        inserted, _ = self.insert_events_detailed(events)
        return inserted

    def insert_events_detailed(
        self,
        events: list[TelemetryEvent],
    ) -> tuple[int, dict[str, int]]:
        return self._insert_events_with_metadata(events)

    def _insert_events_with_metadata(
        self,
        events: list[TelemetryEvent],
        *,
        collection_session_id: str | None = None,
        collector_id: str | None = None,
        collector_version: str | None = None,
    ) -> tuple[int, dict[str, int]]:
        with self.connect() as conn:
            inserted = 0
            by_type: dict[str, int] = {}
            for event in events:
                validation = validate_event(event)
                if isinstance(validation, ValidationFailure):
                    self._insert_quarantine_row(
                        conn,
                        event,
                        validation.reason,
                        validation.error_class,
                        validation.safe_event,
                        validation.payload_hash,
                        collector_id or event.source,
                    )
                    continue
                event = validation.event
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO telemetry_events (
                        event_id, timestamp, event_type, user_id, host_id, source,
                        payload_json, synthetic, schema_version, ingested_at,
                        collection_session_id, collector_id, collector_version,
                        validation_status, payload_hash, event_schema_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
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
                        datetime.now(UTC).isoformat(),
                        collection_session_id,
                        collector_id or event.source,
                        collector_version or "unknown",
                        "accepted",
                        validation.payload_hash,
                        validation.event_schema_version,
                    ),
                )
                if cursor.rowcount == 1:
                    inserted += 1
                    by_type[event.event_type.value] = by_type.get(event.event_type.value, 0) + 1
                else:
                    self._insert_duplicate_row(conn, event, collector_id or event.source)
            return inserted, by_type

    def insert_events_and_update_collector_state(
        self,
        events: list[TelemetryEvent],
        collector_id: str,
        status: str,
        cursor: dict[str, object],
        last_error: str | None = None,
        collection_session_id: str | None = None,
        collector_version: str | None = None,
    ) -> tuple[int, dict[str, int]]:
        with self.connect() as conn:
            inserted = 0
            by_type: dict[str, int] = {}
            for event in events:
                validation = validate_event(event)
                if isinstance(validation, ValidationFailure):
                    self._insert_quarantine_row(
                        conn,
                        event,
                        validation.reason,
                        validation.error_class,
                        validation.safe_event,
                        validation.payload_hash,
                        collector_id,
                    )
                    continue
                event = validation.event
                row = conn.execute(
                    """
                    INSERT OR IGNORE INTO telemetry_events (
                        event_id, timestamp, event_type, user_id, host_id, source,
                        payload_json, synthetic, schema_version, ingested_at,
                        collection_session_id, collector_id, collector_version,
                        validation_status, payload_hash, event_schema_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
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
                        datetime.now(UTC).isoformat(),
                        collection_session_id,
                        collector_id,
                        collector_version or getattr(event, "version", "unknown"),
                        "accepted",
                        validation.payload_hash,
                        validation.event_schema_version,
                    ),
                )
                if row.rowcount == 1:
                    inserted += 1
                    by_type[event.event_type.value] = by_type.get(event.event_type.value, 0) + 1
                else:
                    self._insert_duplicate_row(conn, event, collector_id)
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
            return inserted, by_type

    def _insert_duplicate_row(
        self,
        conn: sqlite3.Connection,
        event: TelemetryEvent,
        collector_id: str,
    ) -> None:
        existing = conn.execute(
            "SELECT ingested_at FROM telemetry_events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        conn.execute(
            """
            INSERT INTO duplicate_event_records (
                event_id, dataset_kind, first_seen_at, duplicate_seen_at,
                collector_id, source
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                "synthetic" if event.synthetic else "real",
                existing["ingested_at"] if existing is not None else None,
                datetime.now(UTC).isoformat(),
                collector_id,
                event.source,
            ),
        )

    def _insert_quarantine_row(
        self,
        conn: sqlite3.Connection,
        event: TelemetryEvent,
        reason: str,
        error_class: str,
        safe_event: dict[str, Any],
        event_payload_hash: str,
        collector_id: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO quarantined_events (
                received_at, collector_id, source, event_type, event_schema_version,
                error_class, reason, safe_event_json, payload_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(UTC).isoformat(),
                collector_id,
                event.source,
                event.event_type.value,
                EVENT_SCHEMA_VERSION,
                error_class,
                reason[:1000],
                json.dumps(safe_event, sort_keys=True),
                event_payload_hash,
            ),
        )

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

    def list_event_rows(
        self,
        *,
        synthetic: bool | None = None,
        since: datetime | None = None,
        ingested_after: str | None = None,
        after_event_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if synthetic is not None:
            clauses.append("synthetic = ?")
            params.append(int(synthetic))
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start.isoformat())
        if end is not None:
            clauses.append("timestamp < ?")
            params.append(end.isoformat())
        if ingested_after is not None:
            if after_event_id is None:
                clauses.append("ingested_at > ?")
                params.append(ingested_after)
            else:
                clauses.append("(ingested_at > ? OR (ingested_at = ? AND event_id > ?))")
                params.extend([ingested_after, ingested_after, after_event_id])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM telemetry_events {where} "
                "ORDER BY timestamp ASC, event_id ASC",
                params,
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            output.append(
                {
                    "event": TelemetryEvent(
                        event_id=row["event_id"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        event_type=EventType(row["event_type"]),
                        user_id=row["user_id"],
                        host_id=row["host_id"],
                        source=row["source"],
                        payload=json.loads(row["payload_json"]),
                        synthetic=bool(row["synthetic"]),
                        schema_version=row["schema_version"],
                    ),
                    "ingested_at": row["ingested_at"],
                    "collection_session_id": row["collection_session_id"],
                    "collector_id": row["collector_id"],
                    "collector_version": row["collector_version"],
                    "validation_status": row["validation_status"],
                    "payload_hash": row["payload_hash"],
                    "event_schema_version": row["event_schema_version"],
                }
            )
        return output

    def record_collector_observation(
        self,
        *,
        session_id: str | None,
        collector_id: str,
        user_id: str | None,
        host_id: str | None,
        observed_at: datetime,
        status: str,
        successful_poll: bool,
        error_class: str | None,
        configured_interval_seconds: float,
        returned_events: int,
        saved_events: int,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO collector_observations (
                    session_id, collector_id, user_id, host_id, observed_at, status,
                    successful_poll, error_class, configured_interval_seconds,
                    returned_events, saved_events
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    collector_id,
                    user_id,
                    host_id,
                    observed_at.astimezone(UTC).isoformat(),
                    status,
                    int(successful_poll),
                    error_class,
                    configured_interval_seconds,
                    returned_events,
                    saved_events,
                ),
            )

    def list_collector_observations(
        self,
        *,
        since: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if since is not None:
            clauses.append("observed_at > ?")
            params.append(since)
        if start is not None:
            clauses.append("observed_at >= ?")
            params.append(start.isoformat())
        if end is not None:
            clauses.append("observed_at < ?")
            params.append(end.isoformat())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM collector_observations {where} "
                "ORDER BY observed_at ASC, observation_id ASC",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_feature_windows(self, windows: list[dict[str, Any]]) -> int:
        with self.connect() as conn:
            count = 0
            for window in windows:
                now = datetime.now(UTC).isoformat()
                existing = conn.execute(
                    "SELECT created_at FROM feature_windows WHERE window_id = ?",
                    (window["window_id"],),
                ).fetchone()
                created_at = existing["created_at"] if existing is not None else now
                conn.execute(
                    """
                    INSERT INTO feature_windows (
                        window_id, dataset_kind, user_id, host_id, window_start, window_end,
                        feature_schema_version, window_size_minutes, features_json,
                        event_count, event_counts_json, collector_coverage_json,
                        quality_status, quality_reasons_json, gap_duration_seconds,
                        finalized, source_event_hash, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(window_id) DO UPDATE SET
                        features_json = excluded.features_json,
                        event_count = excluded.event_count,
                        event_counts_json = excluded.event_counts_json,
                        collector_coverage_json = excluded.collector_coverage_json,
                        quality_status = excluded.quality_status,
                        quality_reasons_json = excluded.quality_reasons_json,
                        gap_duration_seconds = excluded.gap_duration_seconds,
                        finalized = excluded.finalized,
                        source_event_hash = excluded.source_event_hash,
                        updated_at = excluded.updated_at
                    """,
                    (
                        window["window_id"],
                        window["dataset_kind"],
                        window["user_id"],
                        window["host_id"],
                        window["window_start"],
                        window["window_end"],
                        window["feature_schema_version"],
                        window["window_size_minutes"],
                        json.dumps(window["features"], sort_keys=True),
                        window["event_count"],
                        json.dumps(window["event_counts"], sort_keys=True),
                        json.dumps(window["collector_coverage"], sort_keys=True),
                        window["quality_status"],
                        json.dumps(window["quality_reasons"], sort_keys=True),
                        window["gap_duration_seconds"],
                        int(window["finalized"]),
                        window["source_event_hash"],
                        created_at,
                        now,
                    ),
                )
                count += 1
            return count

    def delete_feature_windows(
        self,
        dataset_kind: str,
        *,
        from_start: datetime | None = None,
        before_start: datetime | None = None,
    ) -> int:
        clauses = ["dataset_kind = ?"]
        params: list[object] = [dataset_kind]
        if from_start is not None:
            clauses.append("window_start >= ?")
            params.append(from_start.isoformat())
        if before_start is not None:
            clauses.append("window_start < ?")
            params.append(before_start.isoformat())
        with self.connect() as conn:
            row = conn.execute(
                f"DELETE FROM feature_windows WHERE {' AND '.join(clauses)}",
                params,
            )
            return int(row.rowcount)

    def record_late_event(
        self,
        *,
        dataset_kind: str,
        event_id: str,
        event_timestamp: datetime,
        ingested_at: str,
        policy_boundary: datetime,
        within_policy: bool,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO late_event_records (
                    dataset_kind, event_id, event_timestamp, ingested_at,
                    policy_boundary, within_policy, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dataset_kind,
                    event_id,
                    event_timestamp.isoformat(),
                    ingested_at,
                    policy_boundary.isoformat(),
                    int(within_policy),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def late_event_summary(self) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT within_policy, COUNT(*) AS count
                FROM late_event_records
                GROUP BY within_policy
                """
            ).fetchall()
        return {
            "within_policy": sum(row["count"] for row in rows if int(row["within_policy"]) == 1),
            "outside_policy": sum(row["count"] for row in rows if int(row["within_policy"]) == 0),
        }

    def duplicate_event_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM duplicate_event_records").fetchone()[0]
            rows = conn.execute(
                """
                SELECT dataset_kind, COUNT(*) AS count
                FROM duplicate_event_records
                GROUP BY dataset_kind
                """
            ).fetchall()
        return {
            "count": total,
            "by_dataset_kind": {row["dataset_kind"]: row["count"] for row in rows},
        }

    def list_feature_windows(
        self,
        *,
        dataset_kind: str | None = None,
        quality_status: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if dataset_kind is not None:
            clauses.append("dataset_kind = ?")
            params.append(dataset_kind)
        if quality_status:
            placeholders = ", ".join("?" for _ in quality_status)
            clauses.append(f"quality_status IN ({placeholders})")
            params.extend(sorted(quality_status))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM feature_windows {where} ORDER BY window_start ASC, window_id ASC",
                params,
            ).fetchall()
        return [self._feature_window_row(row) for row in rows]

    def feature_window_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT dataset_kind, quality_status, COUNT(*) AS count
                FROM feature_windows
                GROUP BY dataset_kind, quality_status
                """
            ).fetchall()
        summary: dict[str, Any] = {"synthetic": {}, "real": {}}
        for row in rows:
            summary.setdefault(row["dataset_kind"], {})[row["quality_status"]] = row["count"]
        return summary

    def get_materialization_state(self, dataset_kind: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM feature_materialization_state WHERE dataset_kind = ?",
                (dataset_kind,),
            ).fetchone()
        if row is None:
            return None
        return {
            "dataset_kind": row["dataset_kind"],
            "watermark": row["watermark"],
            "event_time_watermark": row["event_time_watermark"],
            "last_ingested_at": row["last_ingested_at"],
            "last_event_id": row["last_event_id"],
            "last_observation_at": row["last_observation_at"],
            "last_materialized_at": row["last_materialized_at"],
            "last_successful_run_at": row["last_successful_run_at"],
            "late_event_interval_minutes": row["late_event_interval_minutes"],
            "window_size_minutes": row["window_size_minutes"],
            "baseline_state": json.loads(row["baseline_state_json"]),
            "last_rebuild_at": row["last_rebuild_at"],
            "late_events_within_policy": row["late_events_within_policy"],
            "late_events_outside_policy": row["late_events_outside_policy"],
        }

    def upsert_materialization_state(
        self,
        dataset_kind: str,
        *,
        watermark: datetime | None,
        late_event_interval_minutes: int,
        window_size_minutes: int,
        baseline_state: dict[str, Any],
        event_time_watermark: datetime | None = None,
        last_ingested_at: str | None = None,
        last_event_id: str | None = None,
        last_observation_at: str | None = None,
        late_events_within_policy: int = 0,
        late_events_outside_policy: int = 0,
        rebuilt: bool = False,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO feature_materialization_state (
                    dataset_kind, watermark, last_materialized_at,
                    late_event_interval_minutes, window_size_minutes,
                    baseline_state_json, last_rebuild_at, last_ingested_at,
                    last_event_id, event_time_watermark, last_observation_at,
                    last_successful_run_at, late_events_within_policy,
                    late_events_outside_policy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dataset_kind) DO UPDATE SET
                    watermark = excluded.watermark,
                    last_materialized_at = excluded.last_materialized_at,
                    late_event_interval_minutes = excluded.late_event_interval_minutes,
                    window_size_minutes = excluded.window_size_minutes,
                    baseline_state_json = excluded.baseline_state_json,
                    last_rebuild_at = COALESCE(excluded.last_rebuild_at, last_rebuild_at),
                    last_ingested_at = excluded.last_ingested_at,
                    last_event_id = excluded.last_event_id,
                    event_time_watermark = excluded.event_time_watermark,
                    last_observation_at = excluded.last_observation_at,
                    last_successful_run_at = excluded.last_successful_run_at,
                    late_events_within_policy = excluded.late_events_within_policy,
                    late_events_outside_policy = excluded.late_events_outside_policy
                """,
                (
                    dataset_kind,
                    watermark.isoformat() if watermark else None,
                    now,
                    late_event_interval_minutes,
                    window_size_minutes,
                    json.dumps(baseline_state, sort_keys=True),
                    now if rebuilt else None,
                    last_ingested_at,
                    last_event_id,
                    event_time_watermark.isoformat() if event_time_watermark else None,
                    last_observation_at,
                    now,
                    late_events_within_policy,
                    late_events_outside_policy,
                ),
            )

    def get_dataset_snapshot(self, dataset_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM dataset_snapshots WHERE dataset_id = ?",
                (dataset_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "dataset_id": row["dataset_id"],
            "dataset_kind": row["dataset_kind"],
            "created_at": row["created_at"],
            "manifest": json.loads(row["manifest_json"]),
            "manifest_sha256": row["manifest_sha256"],
            "parquet_sha256": row["parquet_sha256"],
            "feature_schema_version": row["feature_schema_version"],
            "profile": json.loads(row["profile_json"]),
            "start": row["start_at"],
            "end": row["end_at"],
            "window_count": row["window_count"],
            "status": row["status"],
        }

    def register_dataset_snapshot(self, manifest: dict[str, Any], manifest_sha256: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO dataset_snapshots (
                    dataset_id, dataset_kind, created_at, manifest_json, manifest_sha256,
                    parquet_sha256, feature_schema_version, profile_json, start_at, end_at,
                    window_count, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest["dataset_id"],
                    manifest["dataset_kind"],
                    manifest["created_at"],
                    json.dumps(manifest, sort_keys=True),
                    manifest_sha256,
                    manifest["parquet_sha256"],
                    manifest["feature_schema_version"],
                    json.dumps(manifest["profile"], sort_keys=True),
                    manifest["start"],
                    manifest["end"],
                    manifest["window_count"],
                    "created",
                ),
            )

    def list_dataset_snapshots(self, dataset_kind: str | None = None) -> list[dict[str, Any]]:
        params: list[object] = []
        where = ""
        if dataset_kind is not None:
            where = "WHERE dataset_kind = ?"
            params.append(dataset_kind)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM dataset_snapshots {where} ORDER BY created_at DESC",
                params,
            ).fetchall()
        return [
            {
                "dataset_id": row["dataset_id"],
                "dataset_kind": row["dataset_kind"],
                "created_at": row["created_at"],
                "manifest": json.loads(row["manifest_json"]),
                "manifest_sha256": row["manifest_sha256"],
                "parquet_sha256": row["parquet_sha256"],
                "feature_schema_version": row["feature_schema_version"],
                "profile": json.loads(row["profile_json"]),
                "start": row["start_at"],
                "end": row["end_at"],
                "window_count": row["window_count"],
                "status": row["status"],
            }
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
            conn.execute("DELETE FROM feature_windows WHERE dataset_kind = 'synthetic'")

    def quarantine_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM quarantined_events").fetchone()[0]
            rows = conn.execute(
                """
                SELECT event_type, error_class, COUNT(*) AS count
                FROM quarantined_events
                GROUP BY event_type, error_class
                ORDER BY count DESC
                """
            ).fetchall()
        return {
            "count": total,
            "by_reason": [
                {
                    "event_type": row["event_type"],
                    "error_class": row["error_class"],
                    "count": row["count"],
                }
                for row in rows
            ],
        }

    def record_data_quality_run(
        self,
        run_id: str,
        dataset_kind: str,
        summary: dict[str, Any],
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO data_quality_runs (
                    run_id, dataset_kind, created_at, summary_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    run_id,
                    dataset_kind,
                    datetime.now(UTC).isoformat(),
                    json.dumps(summary, sort_keys=True),
                ),
            )

    def retention_preview(self, cutoff: datetime) -> dict[str, Any]:
        with self.connect() as conn:
            real = conn.execute(
                """
                SELECT COUNT(*) AS count, MIN(timestamp) AS oldest, MAX(timestamp) AS newest
                FROM telemetry_events
                WHERE synthetic = 0 AND timestamp < ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()
            quarantine = conn.execute(
                """
                SELECT COUNT(*) AS count, MIN(received_at) AS oldest, MAX(received_at) AS newest
                FROM quarantined_events
                WHERE received_at < ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()
        return {
            "cutoff": cutoff.isoformat(),
            "raw_real_events": dict(real),
            "quarantined_events": dict(quarantine),
            "snapshots_affected": 0,
            "models_affected": 0,
        }

    def retention_apply(self, cutoff: datetime) -> dict[str, Any]:
        with self.connect() as conn:
            real = conn.execute(
                "DELETE FROM telemetry_events WHERE synthetic = 0 AND timestamp < ?",
                (cutoff.isoformat(),),
            ).rowcount
            quarantine = conn.execute(
                "DELETE FROM quarantined_events WHERE received_at < ?",
                (cutoff.isoformat(),),
            ).rowcount
        return {
            "cutoff": cutoff.isoformat(),
            "deleted_raw_real_events": int(real),
            "deleted_quarantined_events": int(quarantine),
            "snapshots_deleted": 0,
            "models_deleted": 0,
        }

    def status(self) -> dict[str, Any]:
        with self.connect() as conn:
            event_count = conn.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0]
            real_event_count = conn.execute(
                "SELECT COUNT(*) FROM telemetry_events WHERE synthetic = 0"
            ).fetchone()[0]
            anomaly_count = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            quarantine_count = conn.execute("SELECT COUNT(*) FROM quarantined_events").fetchone()[0]
            feature_window_count = conn.execute(
                "SELECT COUNT(*) FROM feature_windows"
            ).fetchone()[0]
            dataset_snapshot_count = conn.execute(
                "SELECT COUNT(*) FROM dataset_snapshots"
            ).fetchone()[0]
            schema = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        return {
            "database_path": str(self.database_path),
            "schema_version": schema,
            "event_count": event_count,
            "real_event_count": real_event_count,
            "anomaly_count": anomaly_count,
            "quarantine_count": quarantine_count,
            "feature_window_count": feature_window_count,
            "dataset_snapshot_count": dataset_snapshot_count,
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
                    , last_heartbeat_at, last_successful_collection_at
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, NULL)
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

    def update_session_heartbeat(
        self,
        session_id: str,
        counters: dict[str, int],
        errors: list[str],
        successful: bool,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE collection_sessions
                SET last_heartbeat_at = ?,
                    last_successful_collection_at =
                        CASE WHEN ? THEN ? ELSE last_successful_collection_at END,
                    counters_json = ?,
                    errors_json = ?
                WHERE session_id = ? AND status = 'running'
                """,
                (
                    now,
                    int(successful),
                    now,
                    json.dumps(counters, sort_keys=True),
                    json.dumps(errors),
                    session_id,
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
                SET stopped_at = ?,
                    last_heartbeat_at = COALESCE(last_heartbeat_at, ?),
                    status = ?,
                    counters_json = ?,
                    errors_json = ?
                WHERE session_id = ?
                """,
                (
                    now := datetime.now(UTC).isoformat(),
                    now,
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
                SET stopped_at = COALESCE(last_heartbeat_at, started_at),
                    status = 'interrupted'
                WHERE status = 'running'
                """
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
                else datetime.fromisoformat(
                    str(session.get("last_heartbeat_at") or now.isoformat())
                )
            )
            if session["status"] == "running":
                stop = now
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
            "last_heartbeat_at": row["last_heartbeat_at"],
            "last_successful_collection_at": row["last_successful_collection_at"],
        }

    def _feature_window_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "window_id": row["window_id"],
            "dataset_kind": row["dataset_kind"],
            "user_id": row["user_id"],
            "host_id": row["host_id"],
            "window_start": row["window_start"],
            "window_end": row["window_end"],
            "feature_schema_version": row["feature_schema_version"],
            "window_size_minutes": row["window_size_minutes"],
            "features": json.loads(row["features_json"]),
            "event_count": row["event_count"],
            "event_counts": json.loads(row["event_counts_json"]),
            "collector_coverage": json.loads(row["collector_coverage_json"]),
            "quality_status": row["quality_status"],
            "quality_reasons": json.loads(row["quality_reasons_json"]),
            "gap_duration_seconds": row["gap_duration_seconds"],
            "finalized": bool(row["finalized"]),
            "source_event_hash": row["source_event_hash"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
