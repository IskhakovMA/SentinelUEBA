from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelueba.domain.events import AnomalyRecord, EventType, TelemetryEvent
from sentinelueba.features.windows import FEATURE_NAMES
from sentinelueba.validation import (
    EVENT_SCHEMA_VERSION,
    ValidationFailure,
    payload_hash,
    validate_event,
)

DB_SCHEMA_VERSION = 10


class SchemaIntegrityError(RuntimeError):
    pass


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
            if version > DB_SCHEMA_VERSION:
                raise SchemaIntegrityError(
                    f"database schema version {version} is newer than supported {DB_SCHEMA_VERSION}"
                )
            if version == DB_SCHEMA_VERSION:
                self._assert_schema_integrity(conn)
                return
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
                version = 5
            if version < 6:
                self._apply_v6(conn)
                version = 6
            if version < 7:
                self._apply_v7(conn)
                version = 7
            if version < 8:
                self._apply_v8(conn)
                version = 8
            if version < 9:
                self._apply_v9(conn)
                version = 9
            if version < 10:
                self._apply_v10(conn)
            self._assert_schema_integrity(conn)

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

    def _assert_schema_integrity(self, conn: sqlite3.Connection) -> None:
        required_tables = {
            "schema_version",
            "telemetry_events",
            "anomalies",
            "collection_sessions",
            "collector_state",
            "quarantined_events",
            "feature_windows",
            "feature_materialization_state",
            "data_quality_runs",
            "dataset_snapshots",
            "collector_observations",
            "late_event_records",
            "duplicate_event_records",
            "training_runs",
            "model_versions",
            "model_evaluations",
            "model_promotions",
            "scoring_runs",
            "scored_windows",
            "detection_policies",
            "detection_runs",
            "detection_evaluations",
            "findings",
            "finding_occurrences",
            "finding_state_history",
            "detection_suppressions",
            "detection_watermarks",
            "detection_worker_leases",
            "detection_policy_activations",
        }
        existing_tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        missing = sorted(required_tables - existing_tables)
        if missing:
            raise SchemaIntegrityError(
                "database schema integrity check failed; missing table(s): "
                + ", ".join(missing)
            )
        required_columns = {
            "telemetry_events": {
                "event_id",
                "timestamp",
                "event_type",
                "user_id",
                "host_id",
                "payload_json",
                "ingested_at",
                "payload_hash",
                "event_schema_version",
            },
            "feature_materialization_state": {
                "dataset_kind",
                "last_ingested_at",
                "last_event_id",
                "event_time_watermark",
                "last_observation_at",
                "last_observation_id",
                "last_successful_run_at",
            },
            "feature_windows": {"profile_key", "feature_input_hash"},
            "collector_observations": {
                "collector_id",
                "observed_at",
                "status",
                "successful_poll",
                "configured_interval_seconds",
                "returned_events",
                "saved_events",
            },
            "training_runs": {"training_run_id", "dataset_id", "split_id", "status"},
            "model_versions": {
                "model_id",
                "training_run_id",
                "family",
                "lifecycle_status",
                "manifest_sha256",
            },
            "scoring_runs": {"scoring_run_id", "model_id", "dataset_id", "status"},
            "scored_windows": {"scoring_run_id", "window_id", "anomaly_score"},
            "detection_policies": {"policy_id", "policy_version", "policy_hash", "active"},
            "detection_runs": {
                "detection_run_id",
                "policy_hash",
                "status",
                "mode",
                "run_mode",
                "policy_mode",
                "examined_windows",
                "evaluated_windows",
                "blocked_reason",
            },
            "detection_evaluations": {
                "evaluation_id",
                "window_id",
                "feature_input_hash",
                "policy_hash",
                "model_id",
                "decision_json",
                "suppression_id",
            },
            "findings": {
                "finding_id",
                "fingerprint",
                "status",
                "risk_level",
                "related_previous_finding_id",
            },
            "finding_occurrences": {"occurrence_id", "finding_id", "evaluation_id", "window_id"},
            "finding_state_history": {"history_id", "finding_id", "from_status", "to_status"},
            "detection_suppressions": {"suppression_id", "scope", "active"},
            "detection_watermarks": {"watermark_key", "last_window_start", "last_window_id"},
            "detection_worker_leases": {
                "worker_id",
                "worker_key",
                "owner_id",
                "dataset_kind",
                "policy_hash",
                "status",
                "heartbeat_at",
                "expires_at",
            },
            "detection_policy_activations": {
                "activation_id",
                "previous_policy_hash",
                "new_policy_hash",
                "reason",
                "created_at",
            },
        }
        for table, columns in required_columns.items():
            missing_columns = sorted(columns - self._columns(conn, table))
            if missing_columns:
                raise SchemaIntegrityError(
                    "database schema integrity check failed; "
                    f"{table} missing column(s): {', '.join(missing_columns)}"
                )

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

    def _apply_v6(self, conn: sqlite3.Connection) -> None:
        state_columns = self._columns(conn, "feature_materialization_state")
        if "last_observation_id" not in state_columns:
            conn.execute(
                "ALTER TABLE feature_materialization_state "
                "ADD COLUMN last_observation_id INTEGER"
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_observations_watermark "
            "ON collector_observations(observed_at, observation_id)"
        )
        self._record_migration(conn, 6)

    def _apply_v7(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS training_runs (
                training_run_id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL,
                dataset_manifest_sha256 TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                profile_key TEXT NOT NULL,
                split_id TEXT NOT NULL,
                split_manifest_sha256 TEXT NOT NULL,
                effective_config_json TEXT NOT NULL,
                config_sha256 TEXT NOT NULL,
                seed INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                application_version TEXT NOT NULL,
                source_commit TEXT,
                error_class TEXT,
                safe_error_message TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_versions (
                model_id TEXT PRIMARY KEY,
                training_run_id TEXT NOT NULL,
                family TEXT NOT NULL,
                model_version TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                dataset_manifest_sha256 TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                profile_key TEXT NOT NULL,
                feature_schema_version TEXT NOT NULL,
                split_id TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                model_artifact_sha256 TEXT NOT NULL,
                lifecycle_status TEXT NOT NULL,
                threshold REAL NOT NULL,
                created_at TEXT NOT NULL,
                verified_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                model_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                split_id TEXT NOT NULL,
                label_status TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_promotions (
                promotion_id TEXT PRIMARY KEY,
                profile_key TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                previous_model_id TEXT,
                new_model_id TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scoring_runs (
                scoring_run_id TEXT PRIMARY KEY,
                model_id TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                dataset_manifest_sha256 TEXT NOT NULL,
                split_range_json TEXT NOT NULL,
                status TEXT NOT NULL,
                threshold REAL NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                window_count INTEGER NOT NULL,
                anomaly_count INTEGER NOT NULL,
                safe_error TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scored_windows (
                scoring_run_id TEXT NOT NULL,
                window_id TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                threshold REAL NOT NULL,
                is_anomaly INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                explanation_kind TEXT NOT NULL,
                explanation_json TEXT NOT NULL,
                PRIMARY KEY(scoring_run_id, window_id)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_model_versions_profile "
            "ON model_versions(dataset_kind, profile_key, lifecycle_status)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_one_champion_per_profile "
            "ON model_versions(dataset_kind, profile_key) "
            "WHERE lifecycle_status = 'champion'"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scored_windows_run_score "
            "ON scored_windows(scoring_run_id, anomaly_score)"
        )
        self._record_migration(conn, 7)

    def _apply_v8(self, conn: sqlite3.Connection) -> None:
        columns = self._columns(conn, "model_promotions")
        if "new_model_id" in columns:
            conn.execute("ALTER TABLE model_promotions RENAME TO model_promotions_v7")
            conn.execute(
                """
                CREATE TABLE model_promotions (
                    promotion_id TEXT PRIMARY KEY,
                    profile_key TEXT NOT NULL,
                    dataset_kind TEXT NOT NULL,
                    previous_model_id TEXT,
                    new_model_id TEXT,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO model_promotions (
                    promotion_id, profile_key, dataset_kind, previous_model_id,
                    new_model_id, action, reason, created_at
                )
                SELECT promotion_id, profile_key, dataset_kind, previous_model_id,
                       NULLIF(new_model_id, ''), action, reason, created_at
                FROM model_promotions_v7
                """
            )
            conn.execute("DROP TABLE model_promotions_v7")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_model_promotions_profile "
            "ON model_promotions(dataset_kind, profile_key, created_at)"
        )
        self._record_migration(conn, 8)

    def _apply_v9(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_policies (
                policy_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                source_commit TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_policy_identity
            ON detection_policies(policy_id, policy_version)
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_detection_policy
            ON detection_policies(active)
            WHERE active = 1
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_runs (
                detection_run_id TEXT PRIMARY KEY,
                dataset_kind TEXT NOT NULL,
                profile_key TEXT,
                policy_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                mode TEXT NOT NULL,
                model_id TEXT,
                model_version TEXT,
                model_hash TEXT,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                window_count INTEGER NOT NULL,
                evaluated_count INTEGER NOT NULL,
                skipped_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                no_op_count INTEGER NOT NULL,
                dry_run INTEGER NOT NULL,
                safe_error TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                detection_run_id TEXT NOT NULL,
                window_id TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                profile_key TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                feature_schema_version TEXT NOT NULL,
                feature_input_hash TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                model_id TEXT,
                model_version TEXT,
                model_hash TEXT,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                detection_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                matched_signal_ids_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                finding_id TEXT,
                created_at TEXT NOT NULL,
                skipped_reason TEXT,
                UNIQUE(window_id, feature_input_hash, policy_hash, model_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                dataset_kind TEXT NOT NULL,
                profile_key TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                model_id TEXT,
                model_version TEXT,
                model_hash TEXT,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                detection_score REAL NOT NULL,
                primary_signal_id TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_occurrences (
                occurrence_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                evaluation_id TEXT NOT NULL,
                window_id TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                detection_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                signals_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(finding_id, evaluation_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_state_history (
                history_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_suppressions (
                suppression_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                dataset_kind TEXT,
                profile_key TEXT,
                finding_fingerprint TEXT,
                signal_id TEXT,
                reason TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_watermarks (
                watermark_key TEXT PRIMARY KEY,
                dataset_kind TEXT NOT NULL,
                profile_key TEXT,
                policy_hash TEXT NOT NULL,
                model_id TEXT,
                last_window_start TEXT,
                last_window_id TEXT,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_worker_leases (
                worker_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                status TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                stop_requested INTEGER NOT NULL,
                config_json TEXT NOT NULL,
                safe_error TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_detection_runs_started "
            "ON detection_runs(started_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_detection_evaluations_window "
            "ON detection_evaluations(dataset_kind, profile_key, window_start, window_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_status "
            "ON findings(status, last_seen_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint "
            "ON findings(fingerprint, status, last_seen_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_suppressions_scope "
            "ON detection_suppressions(scope, active, expires_at)"
        )
        self._record_migration(conn, 9)

    def _apply_v10(self, conn: sqlite3.Connection) -> None:
        feature_columns = self._columns(conn, "feature_windows")
        if "profile_key" not in feature_columns:
            conn.execute("ALTER TABLE feature_windows ADD COLUMN profile_key TEXT")
        if "feature_input_hash" not in feature_columns:
            conn.execute("ALTER TABLE feature_windows ADD COLUMN feature_input_hash TEXT")
        rows = conn.execute("SELECT * FROM feature_windows").fetchall()
        for row in rows:
            payload = self._feature_window_row(row)
            conn.execute(
                """
                UPDATE feature_windows
                SET profile_key = ?, feature_input_hash = ?
                WHERE window_id = ?
                """,
                (
                    self._feature_profile_key(payload),
                    self._feature_input_hash(payload),
                    payload["window_id"],
                ),
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_windows_detection_pending "
            "ON feature_windows(dataset_kind, profile_key, window_start, window_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_windows_feature_hash "
            "ON feature_windows(window_id, feature_input_hash)"
        )
        run_columns = self._columns(conn, "detection_runs")
        run_additions = {
            "run_mode": "TEXT NOT NULL DEFAULT 'manual'",
            "policy_mode": "TEXT NOT NULL DEFAULT 'hybrid'",
            "range_start": "TEXT",
            "range_end": "TEXT",
            "examined_windows": "INTEGER NOT NULL DEFAULT 0",
            "evaluated_windows": "INTEGER NOT NULL DEFAULT 0",
            "skipped_windows": "INTEGER NOT NULL DEFAULT 0",
            "no_op_windows": "INTEGER NOT NULL DEFAULT 0",
            "finding_occurrences": "INTEGER NOT NULL DEFAULT 0",
            "new_findings": "INTEGER NOT NULL DEFAULT 0",
            "updated_findings": "INTEGER NOT NULL DEFAULT 0",
            "blocked_reason": "TEXT",
            "error_class": "TEXT",
            "safe_error_message": "TEXT",
            "parent_run_id": "TEXT",
        }
        for column, column_type in run_additions.items():
            if column not in run_columns:
                conn.execute(f"ALTER TABLE detection_runs ADD COLUMN {column} {column_type}")
        conn.execute("UPDATE detection_runs SET policy_mode = COALESCE(policy_mode, mode)")
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_running_detection_namespace
            ON detection_runs(dataset_kind, profile_key, policy_hash, model_id)
            WHERE status = 'running'
            """
        )
        eval_columns = self._columns(conn, "detection_evaluations")
        eval_additions = {
            "suppression_id": "TEXT",
            "suppression_reason": "TEXT",
            "suppression_expires_at": "TEXT",
        }
        for column, column_type in eval_additions.items():
            if column not in eval_columns:
                conn.execute(
                    f"ALTER TABLE detection_evaluations ADD COLUMN {column} {column_type}"
                )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_detection_eval_identity
            ON detection_evaluations(window_id, feature_input_hash, policy_hash, model_id)
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_occurrence_evaluation
            ON finding_occurrences(evaluation_id)
            """
        )
        finding_columns = self._columns(conn, "findings")
        if "related_previous_finding_id" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN related_previous_finding_id TEXT")
        worker_columns = self._columns(conn, "detection_worker_leases")
        worker_additions = {
            "worker_key": "TEXT",
            "dataset_kind": "TEXT",
            "profile_key": "TEXT",
            "policy_hash": "TEXT",
            "acquired_at": "TEXT",
            "expires_at": "TEXT",
        }
        for column, column_type in worker_additions.items():
            if column not in worker_columns:
                conn.execute(
                    f"ALTER TABLE detection_worker_leases ADD COLUMN {column} {column_type}"
                )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_key
            ON detection_worker_leases(worker_key)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_policy_activations (
                activation_id TEXT PRIMARY KEY,
                previous_policy_hash TEXT,
                new_policy_hash TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_policy_activations_created
            ON detection_policy_activations(created_at)
            """
        )
        self._record_migration(conn, 10)

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
        after_observation_id: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if since is not None:
            if after_observation_id is None:
                clauses.append("observed_at > ?")
                params.append(since)
            else:
                clauses.append("(observed_at > ? OR (observed_at = ? AND observation_id > ?))")
                params.extend([since, since, after_observation_id])
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

    def list_collector_observations_overlapping(
        self,
        *,
        start: datetime,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        clauses = [
            "julianday(observed_at) < "
            "COALESCE(julianday(?), julianday('9999-12-31T23:59:59+00:00'))",
            "julianday(observed_at) + (configured_interval_seconds / 86400.0) > julianday(?)",
        ]
        params: list[object] = [end.isoformat() if end is not None else None, start.isoformat()]
        where = " AND ".join(clauses)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM collector_observations WHERE {where} "
                "ORDER BY observed_at ASC, observation_id ASC",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def feature_novelty_baseline(
        self,
        *,
        synthetic: bool,
        before: datetime,
    ) -> dict[tuple[str, str], dict[str, set[str]]]:
        baseline: dict[tuple[str, str], dict[str, set[str]]] = {}
        with self.connect() as conn:
            process_rows = conn.execute(
                """
                SELECT DISTINCT user_id, host_id,
                    json_extract(payload_json, '$.process_name') AS process_name
                FROM telemetry_events
                WHERE synthetic = ?
                    AND timestamp < ?
                    AND event_type = ?
                    AND process_name IS NOT NULL
                    AND process_name != ''
                """,
                (int(synthetic), before.isoformat(), EventType.PROCESS.value),
            ).fetchall()
            network_rows = conn.execute(
                """
                SELECT DISTINCT user_id, host_id,
                    json_extract(payload_json, '$.remote_address') AS remote_address,
                    json_extract(payload_json, '$.remote_port') AS remote_port
                FROM telemetry_events
                WHERE synthetic = ?
                    AND timestamp < ?
                    AND event_type = ?
                    AND remote_address IS NOT NULL
                    AND remote_port IS NOT NULL
                """,
                (int(synthetic), before.isoformat(), EventType.NETWORK.value),
            ).fetchall()
        for row in process_rows:
            current = baseline.setdefault(
                (str(row["user_id"]), str(row["host_id"])),
                {"processes": set(), "remotes": set()},
            )
            current["processes"].add(str(row["process_name"]))
        for row in network_rows:
            current = baseline.setdefault(
                (str(row["user_id"]), str(row["host_id"])),
                {"processes": set(), "remotes": set()},
            )
            current["remotes"].add(f"{row['remote_address']}:{row['remote_port']}")
        return baseline

    def upsert_feature_windows(self, windows: list[dict[str, Any]]) -> int:
        with self.connect() as conn:
            return self._upsert_feature_windows_conn(conn, windows)

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
            return self._delete_feature_windows_conn(conn, clauses, params)

    def replace_feature_windows_and_materialization_state(
        self,
        dataset_kind: str,
        *,
        windows: list[dict[str, Any]],
        state: dict[str, Any],
        from_start: datetime | None = None,
        before_start: datetime | None = None,
    ) -> tuple[int, int]:
        clauses = ["dataset_kind = ?"]
        params: list[object] = [dataset_kind]
        if from_start is not None:
            clauses.append("window_start >= ?")
            params.append(from_start.isoformat())
        if before_start is not None:
            clauses.append("window_start < ?")
            params.append(before_start.isoformat())
        with self.connect() as conn:
            deleted = self._delete_feature_windows_conn(conn, clauses, params)
            upserted = self._upsert_feature_windows_conn(conn, windows)
            self._upsert_materialization_state_conn(conn, **state)
            return deleted, upserted

    def _upsert_feature_windows_conn(
        self,
        conn: sqlite3.Connection,
        windows: list[dict[str, Any]],
    ) -> int:
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
                    finalized, source_event_hash, profile_key, feature_input_hash,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    profile_key = excluded.profile_key,
                    feature_input_hash = excluded.feature_input_hash,
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
                    self._feature_profile_key(window),
                    self._feature_input_hash(window),
                    created_at,
                    now,
                ),
            )
            count += 1
        return count

    def _delete_feature_windows_conn(
        self,
        conn: sqlite3.Connection,
        clauses: list[str],
        params: list[object],
    ) -> int:
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
        start: datetime | None = None,
        end: datetime | None = None,
        after_window_start: str | None = None,
        after_window_id: str | None = None,
        limit: int | None = None,
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
        if start is not None:
            clauses.append("window_start >= ?")
            params.append(start.isoformat())
        if end is not None:
            clauses.append("window_start < ?")
            params.append(end.isoformat())
        if after_window_start is not None:
            if after_window_id is None:
                clauses.append("window_start > ?")
                params.append(after_window_start)
            else:
                clauses.append("(window_start > ? OR (window_start = ? AND window_id > ?))")
                params.extend([after_window_start, after_window_start, after_window_id])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit_sql = ""
        if limit is not None:
            limit_sql = " LIMIT ?"
            params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM feature_windows {where} "
                f"ORDER BY window_start ASC, window_id ASC{limit_sql}",
                params,
            ).fetchall()
        return [self._feature_window_row(row) for row in rows]

    def list_detection_profiles(
        self,
        *,
        dataset_kind: str,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[str]:
        clauses = ["dataset_kind = ?"]
        params: list[object] = [dataset_kind]
        if start is not None:
            clauses.append("window_start >= ?")
            params.append(start.isoformat())
        if end is not None:
            clauses.append("window_start < ?")
            params.append(end.isoformat())
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT DISTINCT profile_key
                FROM feature_windows
                WHERE {' AND '.join(clauses)}
                ORDER BY profile_key ASC
                """,
                params,
            ).fetchall()
        return [str(row["profile_key"]) for row in rows if row["profile_key"]]

    def list_pending_detection_windows(
        self,
        *,
        dataset_kind: str,
        profile_key: str,
        policy_hash: str,
        model_identity: str,
        start: datetime | None = None,
        end: datetime | None = None,
        window_ids: list[str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses = [
            "w.dataset_kind = ?",
            "w.profile_key = ?",
            """
            NOT EXISTS (
                SELECT 1
                FROM detection_evaluations e
                WHERE e.window_id = w.window_id
                    AND e.feature_input_hash = w.feature_input_hash
                    AND e.policy_hash = ?
                    AND e.model_id = ?
            )
            """,
        ]
        params: list[object] = [dataset_kind, profile_key, policy_hash, model_identity]
        if start is not None:
            clauses.append("w.window_start >= ?")
            params.append(start.isoformat())
        if end is not None:
            clauses.append("w.window_start < ?")
            params.append(end.isoformat())
        if window_ids is not None:
            if not window_ids:
                return []
            placeholders = ", ".join("?" for _ in window_ids)
            clauses.append(f"w.window_id IN ({placeholders})")
            params.extend(window_ids)
        limit_sql = ""
        if limit is not None:
            limit_sql = " LIMIT ?"
            params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT w.*
                FROM feature_windows w
                WHERE {' AND '.join(clauses)}
                ORDER BY w.window_start ASC, w.window_id ASC
                {limit_sql}
                """,
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
            "last_observation_id": row["last_observation_id"],
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
        last_observation_id: int | None = None,
        late_events_within_policy: int = 0,
        late_events_outside_policy: int = 0,
        rebuilt: bool = False,
    ) -> None:
        with self.connect() as conn:
            self._upsert_materialization_state_conn(
                conn,
                dataset_kind=dataset_kind,
                watermark=watermark,
                late_event_interval_minutes=late_event_interval_minutes,
                window_size_minutes=window_size_minutes,
                baseline_state=baseline_state,
                event_time_watermark=event_time_watermark,
                last_ingested_at=last_ingested_at,
                last_event_id=last_event_id,
                last_observation_at=last_observation_at,
                last_observation_id=last_observation_id,
                late_events_within_policy=late_events_within_policy,
                late_events_outside_policy=late_events_outside_policy,
                rebuilt=rebuilt,
            )

    def _upsert_materialization_state_conn(
        self,
        conn: sqlite3.Connection,
        *,
        dataset_kind: str,
        watermark: datetime | None,
        late_event_interval_minutes: int,
        window_size_minutes: int,
        baseline_state: dict[str, Any],
        event_time_watermark: datetime | None = None,
        last_ingested_at: str | None = None,
        last_event_id: str | None = None,
        last_observation_at: str | None = None,
        last_observation_id: int | None = None,
        late_events_within_policy: int = 0,
        late_events_outside_policy: int = 0,
        rebuilt: bool = False,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        conn.execute(
            """
            INSERT INTO feature_materialization_state (
                dataset_kind, watermark, last_materialized_at,
                late_event_interval_minutes, window_size_minutes,
                baseline_state_json, last_rebuild_at, last_ingested_at,
                last_event_id, event_time_watermark, last_observation_at, last_observation_id,
                last_successful_run_at, late_events_within_policy,
                late_events_outside_policy
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                last_observation_id = excluded.last_observation_id,
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
                last_observation_id,
                now,
                late_events_within_policy,
                late_events_outside_policy,
            )
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

    def create_training_run(self, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO training_runs (
                    training_run_id, dataset_id, dataset_manifest_sha256, dataset_kind,
                    profile_key, split_id, split_manifest_sha256, effective_config_json,
                    config_sha256, seed, status, started_at, completed_at,
                    application_version, source_commit, error_class, safe_error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["training_run_id"],
                    payload["dataset_id"],
                    payload["dataset_manifest_sha256"],
                    payload["dataset_kind"],
                    payload["profile_key"],
                    payload["split_id"],
                    payload["split_manifest_sha256"],
                    payload["effective_config_json"],
                    payload["config_sha256"],
                    payload["seed"],
                    payload["status"],
                    payload["started_at"],
                    payload.get("completed_at"),
                    payload["application_version"],
                    payload.get("source_commit"),
                    payload.get("error_class"),
                    payload.get("safe_error_message"),
                ),
            )

    def create_training_run_if_no_running(self, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            running = conn.execute(
                """
                SELECT training_run_id FROM training_runs
                WHERE dataset_kind = ? AND profile_key = ? AND status = 'running'
                LIMIT 1
                """,
                (payload["dataset_kind"], payload["profile_key"]),
            ).fetchone()
            if running is not None:
                raise ValueError(
                    "training is already running for this dataset kind and profile"
                )
            conn.execute(
                """
                INSERT INTO training_runs (
                    training_run_id, dataset_id, dataset_manifest_sha256, dataset_kind,
                    profile_key, split_id, split_manifest_sha256, effective_config_json,
                    config_sha256, seed, status, started_at, completed_at,
                    application_version, source_commit, error_class, safe_error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["training_run_id"],
                    payload["dataset_id"],
                    payload["dataset_manifest_sha256"],
                    payload["dataset_kind"],
                    payload["profile_key"],
                    payload["split_id"],
                    payload["split_manifest_sha256"],
                    payload["effective_config_json"],
                    payload["config_sha256"],
                    payload["seed"],
                    payload["status"],
                    payload["started_at"],
                    payload.get("completed_at"),
                    payload["application_version"],
                    payload.get("source_commit"),
                    payload.get("error_class"),
                    payload.get("safe_error_message"),
                ),
            )

    def complete_training_run(
        self,
        training_run_id: str,
        *,
        status: str,
        completed_at: str,
        error_class: str | None = None,
        safe_error_message: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE training_runs
                SET status = ?, completed_at = ?, error_class = ?, safe_error_message = ?
                WHERE training_run_id = ?
                """,
                (status, completed_at, error_class, safe_error_message, training_run_id),
            )

    def update_training_run_split(
        self,
        training_run_id: str,
        *,
        split_id: str,
        split_manifest_sha256: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE training_runs
                SET split_id = ?, split_manifest_sha256 = ?
                WHERE training_run_id = ?
                """,
                (split_id, split_manifest_sha256, training_run_id),
            )

    def register_model_version(self, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO model_versions (
                    model_id, training_run_id, family, model_version, dataset_id,
                    dataset_manifest_sha256, dataset_kind, profile_key,
                    feature_schema_version, split_id, artifact_path, manifest_sha256,
                    model_artifact_sha256, lifecycle_status, threshold, created_at,
                    verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["model_id"],
                    payload["training_run_id"],
                    payload["family"],
                    payload["model_version"],
                    payload["dataset_id"],
                    payload["dataset_manifest_sha256"],
                    payload["dataset_kind"],
                    payload["profile_key"],
                    payload["feature_schema_version"],
                    payload["split_id"],
                    payload["artifact_path"],
                    payload["manifest_sha256"],
                    payload["model_artifact_sha256"],
                    payload["lifecycle_status"],
                    payload["threshold"],
                    payload["created_at"],
                    payload.get("verified_at"),
                ),
            )

    def update_model_lifecycle(
        self,
        model_id: str,
        status: str,
        *,
        verified_at: str | None = None,
    ) -> None:
        clauses = ["lifecycle_status = ?"]
        params: list[object] = [status]
        if verified_at is not None:
            clauses.append("verified_at = ?")
            params.append(verified_at)
        params.append(model_id)
        with self.connect() as conn:
            conn.execute(
                f"UPDATE model_versions SET {', '.join(clauses)} WHERE model_id = ?",
                params,
            )

    def mark_model_verified(self, model_id: str, verified_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE model_versions SET verified_at = ? WHERE model_id = ?",
                (verified_at, model_id),
            )

    def delete_models_for_training_run(self, training_run_id: str) -> None:
        with self.connect() as conn:
            model_ids = [
                row["model_id"]
                for row in conn.execute(
                    "SELECT model_id FROM model_versions WHERE training_run_id = ?",
                    (training_run_id,),
                ).fetchall()
            ]
            if model_ids:
                placeholders = ", ".join("?" for _ in model_ids)
                conn.execute(
                    f"DELETE FROM model_evaluations WHERE model_id IN ({placeholders})",
                    model_ids,
                )
                conn.execute(
                    f"DELETE FROM model_versions WHERE model_id IN ({placeholders})",
                    model_ids,
                )

    def finalize_training_run_success(
        self,
        training_run_id: str,
        *,
        model_ids: list[str],
        completed_at: str,
        verified_at: str,
    ) -> None:
        if not model_ids:
            raise ValueError("training run finalization requires at least one model")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            run = conn.execute(
                "SELECT * FROM training_runs WHERE training_run_id = ?",
                (training_run_id,),
            ).fetchone()
            if run is None:
                raise ValueError("training run is missing")
            if run["status"] != "running":
                raise ValueError("training run is not running")
            placeholders = ", ".join("?" for _ in model_ids)
            rows = conn.execute(
                f"""
                SELECT * FROM model_versions
                WHERE training_run_id = ? AND model_id IN ({placeholders})
                """,
                [training_run_id, *model_ids],
            ).fetchall()
            if len(rows) != len(set(model_ids)):
                raise ValueError("not all candidate model rows exist")
            for row in rows:
                if row["verified_at"] is not None:
                    raise ValueError("candidate model is already finalized")
                if row["dataset_id"] != run["dataset_id"]:
                    raise ValueError("candidate dataset id does not match training run")
                if row["dataset_manifest_sha256"] != run["dataset_manifest_sha256"]:
                    raise ValueError("candidate dataset hash does not match training run")
                if row["dataset_kind"] != run["dataset_kind"]:
                    raise ValueError("candidate dataset kind does not match training run")
                if row["profile_key"] != run["profile_key"]:
                    raise ValueError("candidate profile does not match training run")
                if row["split_id"] != run["split_id"]:
                    raise ValueError("candidate split does not match training run")
            conn.execute(
                """
                UPDATE training_runs
                SET status = 'success', completed_at = ?, error_class = NULL,
                    safe_error_message = NULL
                WHERE training_run_id = ? AND status = 'running'
                """,
                (completed_at, training_run_id),
            )
            conn.execute(
                f"""
                UPDATE model_versions
                SET verified_at = ?
                WHERE training_run_id = ? AND model_id IN ({placeholders})
                """,
                [verified_at, training_run_id, *model_ids],
            )

    def record_model_evaluation(self, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO model_evaluations (
                    evaluation_id, model_id, dataset_id, split_id, label_status,
                    metrics_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["evaluation_id"],
                    payload["model_id"],
                    payload["dataset_id"],
                    payload["split_id"],
                    payload["label_status"],
                    json.dumps(payload["metrics"], sort_keys=True),
                    payload["created_at"],
                ),
            )

    def promote_model(
        self,
        *,
        promotion_id: str,
        model_id: str,
        action: str,
        reason: str,
        created_at: str,
    ) -> dict[str, Any]:
        with self.connect() as conn:
            model = conn.execute(
                "SELECT * FROM model_versions WHERE model_id = ?",
                (model_id,),
            ).fetchone()
            if model is None:
                raise ValueError("model is not registered")
            previous = conn.execute(
                """
                SELECT model_id FROM model_versions
                WHERE dataset_kind = ? AND profile_key = ? AND lifecycle_status = 'champion'
                """,
                (model["dataset_kind"], model["profile_key"]),
            ).fetchone()
            previous_model_id = previous["model_id"] if previous is not None else None
            if previous_model_id == model_id:
                return {
                    "previous_model_id": previous_model_id,
                    "new_model_id": model_id,
                    "action": "noop",
                }
            if previous_model_id and previous_model_id != model_id:
                conn.execute(
                    "UPDATE model_versions SET lifecycle_status = 'retired' WHERE model_id = ?",
                    (previous_model_id,),
                )
            conn.execute(
                "UPDATE model_versions SET lifecycle_status = 'champion' WHERE model_id = ?",
                (model_id,),
            )
            conn.execute(
                """
                INSERT INTO model_promotions (
                    promotion_id, profile_key, dataset_kind, previous_model_id,
                    new_model_id, action, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    promotion_id,
                    model["profile_key"],
                    model["dataset_kind"],
                    previous_model_id,
                    model_id,
                    action,
                    reason,
                    created_at,
                ),
            )
        return {"previous_model_id": previous_model_id, "new_model_id": model_id, "action": action}

    def retire_model(
        self,
        *,
        promotion_id: str,
        model_id: str,
        reason: str,
        created_at: str,
    ) -> dict[str, Any]:
        with self.connect() as conn:
            model = conn.execute(
                "SELECT * FROM model_versions WHERE model_id = ?",
                (model_id,),
            ).fetchone()
            if model is None:
                raise ValueError("model is not registered")
            conn.execute(
                "UPDATE model_versions SET lifecycle_status = 'retired' WHERE model_id = ?",
                (model_id,),
            )
            conn.execute(
                """
                INSERT INTO model_promotions (
                    promotion_id, profile_key, dataset_kind, previous_model_id,
                    new_model_id, action, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    promotion_id,
                    model["profile_key"],
                    model["dataset_kind"],
                    model_id,
                    None,
                    "retire",
                    reason,
                    created_at,
                ),
            )
        return {"retired_model_id": model_id, "action": "retire"}

    def list_model_promotions(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM model_promotions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_model_version(self, model_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM model_versions WHERE model_id = ?",
                (model_id,),
            ).fetchone()
        return self._model_version_row(row) if row is not None else None

    def list_model_versions(
        self,
        *,
        dataset_kind: str | None = None,
        lifecycle_status: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if dataset_kind is not None:
            clauses.append("dataset_kind = ?")
            params.append(dataset_kind)
        if lifecycle_status is not None:
            clauses.append("lifecycle_status = ?")
            params.append(lifecycle_status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM model_versions {where} ORDER BY created_at DESC",
                params,
            ).fetchall()
        return [self._model_version_row(row) for row in rows]

    def champion_model(
        self,
        dataset_kind: str,
        profile_key: str | None = None,
    ) -> dict[str, Any] | None:
        clauses = ["dataset_kind = ?", "lifecycle_status = 'champion'"]
        params: list[object] = [dataset_kind]
        if profile_key is not None:
            clauses.append("profile_key = ?")
            params.append(profile_key)
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT * FROM model_versions WHERE {' AND '.join(clauses)} "
                "ORDER BY created_at DESC LIMIT 1",
                params,
            ).fetchone()
        return self._model_version_row(row) if row is not None else None

    def list_training_runs(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM training_runs ORDER BY started_at DESC").fetchall()
        return [dict(row) for row in rows]

    def get_training_run(self, training_run_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM training_runs WHERE training_run_id = ?",
                (training_run_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def latest_model_evaluation(self, model_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM model_evaluations
                WHERE model_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (model_id,),
            ).fetchone()
        if row is None:
            return None
        payload = dict(row)
        payload["metrics"] = json.loads(payload.pop("metrics_json"))
        return payload

    def create_scoring_run(self, payload: dict[str, Any], rows: list[dict[str, Any]]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scoring_runs (
                    scoring_run_id, model_id, dataset_id, dataset_manifest_sha256,
                    split_range_json, status, threshold, started_at, completed_at,
                    window_count, anomaly_count, safe_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["scoring_run_id"],
                    payload["model_id"],
                    payload["dataset_id"],
                    payload["dataset_manifest_sha256"],
                    json.dumps(payload["split_range"], sort_keys=True),
                    payload["status"],
                    payload["threshold"],
                    payload["started_at"],
                    payload.get("completed_at"),
                    payload["window_count"],
                    payload["anomaly_count"],
                    payload.get("safe_error"),
                ),
            )
            conn.executemany(
                """
                INSERT INTO scored_windows (
                    scoring_run_id, window_id, window_start, window_end, anomaly_score,
                    threshold, is_anomaly, risk_level, explanation_kind, explanation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        payload["scoring_run_id"],
                        row["window_id"],
                        row["window_start"],
                        row["window_end"],
                        row["anomaly_score"],
                        row["threshold"],
                        int(row["is_anomaly"]),
                        row["risk_level"],
                        row["explanation_kind"],
                        json.dumps(row["explanation"], sort_keys=True),
                    )
                    for row in rows
                ],
            )

    def create_scoring_run_start(self, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scoring_runs (
                    scoring_run_id, model_id, dataset_id, dataset_manifest_sha256,
                    split_range_json, status, threshold, started_at, completed_at,
                    window_count, anomaly_count, safe_error
                ) VALUES (?, ?, ?, ?, ?, 'running', ?, ?, NULL, 0, 0, NULL)
                """,
                (
                    payload["scoring_run_id"],
                    payload["model_id"],
                    payload["dataset_id"],
                    payload["dataset_manifest_sha256"],
                    json.dumps(payload["split_range"], sort_keys=True),
                    payload.get("threshold", 0.0),
                    payload["started_at"],
                ),
            )

    def complete_scoring_run_success(
        self,
        scoring_run_id: str,
        *,
        threshold: float,
        completed_at: str,
        rows: list[dict[str, Any]],
    ) -> None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            anomaly_count = sum(1 for row in rows if bool(row["is_anomaly"]))
            conn.executemany(
                """
                INSERT INTO scored_windows (
                    scoring_run_id, window_id, window_start, window_end, anomaly_score,
                    threshold, is_anomaly, risk_level, explanation_kind, explanation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scoring_run_id,
                        row["window_id"],
                        row["window_start"],
                        row["window_end"],
                        row["anomaly_score"],
                        row["threshold"],
                        int(row["is_anomaly"]),
                        row["risk_level"],
                        row["explanation_kind"],
                        json.dumps(row["explanation"], sort_keys=True),
                    )
                    for row in rows
                ],
            )
            conn.execute(
                """
                UPDATE scoring_runs
                SET status = 'success', threshold = ?, completed_at = ?,
                    window_count = ?, anomaly_count = ?, safe_error = NULL
                WHERE scoring_run_id = ?
                """,
                (threshold, completed_at, len(rows), anomaly_count, scoring_run_id),
            )

    def complete_scoring_run_failed(
        self,
        scoring_run_id: str,
        *,
        completed_at: str,
        safe_error: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM scored_windows WHERE scoring_run_id = ?", (scoring_run_id,))
            conn.execute(
                """
                UPDATE scoring_runs
                SET status = 'failed', completed_at = ?, window_count = 0,
                    anomaly_count = 0, safe_error = ?
                WHERE scoring_run_id = ?
                """,
                (completed_at, safe_error, scoring_run_id),
            )

    def list_scoring_runs(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM scoring_runs ORDER BY started_at DESC").fetchall()
        return [self._scoring_run_row(row) for row in rows]

    def get_scoring_run(self, scoring_run_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            run = conn.execute(
                "SELECT * FROM scoring_runs WHERE scoring_run_id = ?",
                (scoring_run_id,),
            ).fetchone()
            if run is None:
                return None
            rows = conn.execute(
                """
                SELECT * FROM scored_windows
                WHERE scoring_run_id = ?
                ORDER BY anomaly_score DESC, window_start ASC
                """,
                (scoring_run_id,),
            ).fetchall()
        payload = self._scoring_run_row(run)
        payload["windows"] = [self._scored_window_row(row) for row in rows]
        return payload

    def persist_detection_evaluation_atomic(
        self,
        *,
        evaluation: dict[str, Any],
        decision_json: str,
        matched_signal_ids_json: str,
        signals_json: str,
        finding: dict[str, Any] | None,
        occurrence: dict[str, Any] | None,
        correlation_from: str | None,
        correlation_to: str | None,
    ) -> dict[str, Any]:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO detection_evaluations (
                    evaluation_id, detection_run_id, window_id, dataset_kind, profile_key,
                    window_start, window_end, feature_schema_version, feature_input_hash,
                    policy_id, policy_version, policy_hash, model_id, model_version,
                    model_hash, mode, status, detection_score, risk_level,
                    matched_signal_ids_json, decision_json, finding_id, created_at,
                    skipped_reason, suppression_id, suppression_reason, suppression_expires_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    NULL, ?, ?, ?, ?, ?
                )
                """,
                (
                    evaluation["evaluation_id"],
                    evaluation["detection_run_id"],
                    evaluation["window_id"],
                    evaluation["dataset_kind"],
                    evaluation["profile_key"],
                    evaluation["window_start"],
                    evaluation["window_end"],
                    evaluation["feature_schema_version"],
                    evaluation["feature_input_hash"],
                    evaluation["policy_id"],
                    evaluation["policy_version"],
                    evaluation["policy_hash"],
                    evaluation["model_id"],
                    evaluation.get("model_version"),
                    evaluation.get("model_hash"),
                    evaluation["mode"],
                    evaluation["status"],
                    evaluation["detection_score"],
                    evaluation["risk_level"],
                    matched_signal_ids_json,
                    decision_json,
                    evaluation["created_at"],
                    evaluation.get("skipped_reason"),
                    evaluation.get("suppression_id"),
                    evaluation.get("suppression_reason"),
                    evaluation.get("suppression_expires_at"),
                ),
            )
            if cursor.rowcount == 0:
                return {
                    "inserted": False,
                    "finding_id": None,
                    "new_finding": False,
                    "updated_finding": False,
                    "occurrence_inserted": False,
                }
            finding_id = None
            new_finding = False
            updated_finding = False
            occurrence_inserted = False
            related_previous = None
            if finding is not None and occurrence is not None:
                row = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE fingerprint = ?
                        AND status IN ('open', 'acknowledged', 'investigating', 'suppressed')
                        AND first_seen_at <= ?
                        AND last_seen_at >= ?
                    ORDER BY last_seen_at DESC
                    LIMIT 1
                    """,
                    (finding["fingerprint"], correlation_to, correlation_from),
                ).fetchone()
                if row is None:
                    previous = conn.execute(
                        """
                        SELECT finding_id FROM findings
                        WHERE fingerprint = ?
                            AND status IN ('resolved', 'false_positive')
                        ORDER BY last_seen_at DESC
                        LIMIT 1
                        """,
                        (finding["fingerprint"],),
                    ).fetchone()
                    related_previous = previous["finding_id"] if previous is not None else None
                    finding_id = finding["finding_id"]
                    conn.execute(
                        """
                        INSERT INTO findings (
                            finding_id, fingerprint, dataset_kind, profile_key, policy_id,
                            policy_version, policy_hash, model_id, model_version, model_hash,
                            status, risk_level, detection_score, primary_signal_id, title,
                            summary, first_seen_at, last_seen_at, occurrence_count, created_at,
                            updated_at, related_previous_finding_id
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?,
                            0, ?, ?, ?
                        )
                        """,
                        (
                            finding_id,
                            finding["fingerprint"],
                            finding["dataset_kind"],
                            finding["profile_key"],
                            finding["policy_id"],
                            finding["policy_version"],
                            finding["policy_hash"],
                            finding.get("model_id"),
                            finding.get("model_version"),
                            finding.get("model_hash"),
                            finding["risk_level"],
                            finding["detection_score"],
                            finding["primary_signal_id"],
                            finding["title"],
                            finding["summary"],
                            finding["first_seen_at"],
                            finding["last_seen_at"],
                            finding["created_at"],
                            finding["updated_at"],
                            related_previous,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO finding_state_history (
                            history_id, finding_id, from_status, to_status, reason, created_at
                        ) VALUES (?, ?, NULL, 'open', ?, ?)
                        """,
                        (
                            finding["history_id"],
                            finding_id,
                            "created by detection engine",
                            finding["created_at"],
                        ),
                    )
                    new_finding = True
                else:
                    finding_id = str(row["finding_id"])
                    conn.execute(
                        """
                        UPDATE findings
                        SET last_seen_at = CASE WHEN last_seen_at < ? THEN ? ELSE last_seen_at END,
                            first_seen_at = CASE
                                WHEN first_seen_at > ? THEN ? ELSE first_seen_at
                            END,
                            risk_level = CASE WHEN detection_score < ? THEN ? ELSE risk_level END,
                            detection_score = MAX(detection_score, ?),
                            updated_at = ?
                        WHERE finding_id = ?
                        """,
                        (
                            finding["last_seen_at"],
                            finding["last_seen_at"],
                            finding["first_seen_at"],
                            finding["first_seen_at"],
                            finding["detection_score"],
                            finding["risk_level"],
                            finding["detection_score"],
                            finding["updated_at"],
                            finding_id,
                        ),
                    )
                    updated_finding = True
                conn.execute(
                    "UPDATE detection_evaluations SET finding_id = ? WHERE evaluation_id = ?",
                    (finding_id, evaluation["evaluation_id"]),
                )
                occ_cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO finding_occurrences (
                        occurrence_id, finding_id, evaluation_id, window_id, window_start,
                        window_end, detection_score, risk_level, signals_json, evidence_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        occurrence["occurrence_id"],
                        finding_id,
                        evaluation["evaluation_id"],
                        occurrence["window_id"],
                        occurrence["window_start"],
                        occurrence["window_end"],
                        occurrence["detection_score"],
                        occurrence["risk_level"],
                        matched_signal_ids_json,
                        signals_json,
                        occurrence["created_at"],
                    ),
                )
                occurrence_inserted = occ_cursor.rowcount == 1
                if occurrence_inserted:
                    conn.execute(
                        """
                        UPDATE findings
                        SET occurrence_count = occurrence_count + 1
                        WHERE finding_id = ?
                        """,
                        (finding_id,),
                    )
            conn.execute(
                """
                UPDATE detection_runs
                SET examined_windows = examined_windows + 1,
                    evaluated_windows = evaluated_windows + ?,
                    skipped_windows = skipped_windows + ?,
                    finding_occurrences = finding_occurrences + ?,
                    new_findings = new_findings + ?,
                    updated_findings = updated_findings + ?,
                    window_count = window_count + 1,
                    evaluated_count = evaluated_count + ?,
                    skipped_count = skipped_count + ?,
                    finding_count = finding_count + ?
                WHERE detection_run_id = ?
                """,
                (
                    1 if evaluation["status"] in {"finding", "no_finding", "suppressed"} else 0,
                    1 if evaluation["status"] == "skipped" else 0,
                    1 if occurrence_inserted else 0,
                    1 if new_finding else 0,
                    1 if updated_finding else 0,
                    1 if evaluation["status"] in {"finding", "no_finding", "suppressed"} else 0,
                    1 if evaluation["status"] == "skipped" else 0,
                    1 if evaluation["status"] == "finding" else 0,
                    evaluation["detection_run_id"],
                ),
            )
            return {
                "inserted": True,
                "finding_id": finding_id,
                "new_finding": new_finding,
                "updated_finding": updated_finding,
                "occurrence_inserted": occurrence_inserted,
                "related_previous_finding_id": related_previous,
            }

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
            model_count = conn.execute("SELECT COUNT(*) FROM model_versions").fetchone()[0]
            scoring_run_count = conn.execute("SELECT COUNT(*) FROM scoring_runs").fetchone()[0]
            detection_run_count = conn.execute(
                "SELECT COUNT(*) FROM detection_runs"
            ).fetchone()[0]
            finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
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
            "model_count": model_count,
            "scoring_run_count": scoring_run_count,
            "detection_run_count": detection_run_count,
            "finding_count": finding_count,
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
        payload = {
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
        columns = set(row.keys())
        payload["profile_key"] = (
            row["profile_key"]
            if "profile_key" in columns and row["profile_key"]
            else self._feature_profile_key(payload)
        )
        payload["feature_input_hash"] = (
            row["feature_input_hash"]
            if "feature_input_hash" in columns and row["feature_input_hash"]
            else self._feature_input_hash(payload)
        )
        return payload

    def _feature_profile_key(self, window: dict[str, Any]) -> str:
        payload = json.dumps(
            {"user_id": str(window["user_id"]), "host_id": str(window["host_id"])},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _feature_input_hash(self, window: dict[str, Any]) -> str:
        features = window["features"]
        payload = {
            "window_id": window["window_id"],
            "dataset_kind": window["dataset_kind"],
            "profile_key": self._feature_profile_key(window),
            "window_start": window["window_start"],
            "window_end": window["window_end"],
            "feature_schema_version": window["feature_schema_version"],
            "feature_names": FEATURE_NAMES,
            "feature_values": [float(features[name]) for name in FEATURE_NAMES],
            "quality": window["quality_status"],
            "source_event_hash": window["source_event_hash"],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def _model_version_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "model_id": row["model_id"],
            "training_run_id": row["training_run_id"],
            "family": row["family"],
            "model_version": row["model_version"],
            "dataset_id": row["dataset_id"],
            "dataset_manifest_sha256": row["dataset_manifest_sha256"],
            "dataset_kind": row["dataset_kind"],
            "profile_key": row["profile_key"],
            "feature_schema_version": row["feature_schema_version"],
            "split_id": row["split_id"],
            "artifact_path": row["artifact_path"],
            "manifest_sha256": row["manifest_sha256"],
            "model_artifact_sha256": row["model_artifact_sha256"],
            "lifecycle_status": row["lifecycle_status"],
            "threshold": row["threshold"],
            "created_at": row["created_at"],
            "verified_at": row["verified_at"],
        }

    def _scoring_run_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "scoring_run_id": row["scoring_run_id"],
            "model_id": row["model_id"],
            "dataset_id": row["dataset_id"],
            "dataset_manifest_sha256": row["dataset_manifest_sha256"],
            "split_range": json.loads(row["split_range_json"]),
            "status": row["status"],
            "threshold": row["threshold"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "window_count": row["window_count"],
            "anomaly_count": row["anomaly_count"],
            "safe_error": row["safe_error"],
        }

    def _scored_window_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "scoring_run_id": row["scoring_run_id"],
            "window_id": row["window_id"],
            "window_start": row["window_start"],
            "window_end": row["window_end"],
            "anomaly_score": row["anomaly_score"],
            "threshold": row["threshold"],
            "is_anomaly": bool(row["is_anomaly"]),
            "risk_level": row["risk_level"],
            "explanation_kind": row["explanation_kind"],
            "explanation": json.loads(row["explanation_json"]),
        }
