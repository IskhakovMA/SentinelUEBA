from __future__ import annotations

import hashlib
import json
import math
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from sentinelueba.detection.contracts import (
    DetectionDecision,
    DetectionEvidence,
    DetectionInput,
    DetectionPolicy,
    DetectionRule,
    DetectionRunResult,
    DetectionSignal,
    ModelSignal,
)
from sentinelueba.detection.fusion import fuse_signals
from sentinelueba.detection.policies import (
    MODEL_STRENGTH_VERSION,
    default_policy,
    load_policy,
    policy_storage_payload,
    safe_source_commit,
    sanitize_reason,
    sha_json,
)
from sentinelueba.detection.rules import evaluate_rules
from sentinelueba.features.windows import FEATURE_NAMES
from sentinelueba.ml.stage3_service import (
    ModelBundleVerificationError,
    Stage3MLService,
    profile_key,
)
from sentinelueba.storage.sqlite import SQLiteStorage

OPEN_FINDING_STATUSES = {"open", "acknowledged", "investigating", "suppressed"}
END_FINDING_STATUSES = {"resolved", "false_positive"}
MODEL_ID_SENTINEL = "__rules_only__"


class DetectionEngineError(ValueError):
    pass


class DetectionService:
    def __init__(self, storage: SQLiteStorage, data_dir: Path, model_dir: Path) -> None:
        self.storage = storage
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.ml = Stage3MLService(storage, data_dir, model_dir)

    def status(self) -> dict[str, Any]:
        self.storage.initialize()
        policy = self.ensure_default_policy()
        with self.storage.connect() as conn:
            run = conn.execute(
                "SELECT * FROM detection_runs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
            findings = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM findings
                GROUP BY status
                """
            ).fetchall()
            evaluations = conn.execute("SELECT COUNT(*) FROM detection_evaluations").fetchone()[0]
            watermarks = conn.execute(
                "SELECT * FROM detection_watermarks ORDER BY updated_at DESC"
            ).fetchall()
            worker = conn.execute(
                "SELECT * FROM detection_worker_leases ORDER BY heartbeat_at DESC LIMIT 1"
            ).fetchone()
        return {
            "schema_version": self.storage.status()["schema_version"],
            "active_policy": policy.model_dump(mode="json"),
            "rules": self.rules_list(),
            "latest_run": dict(run) if run is not None else None,
            "finding_counts": {row["status"]: row["count"] for row in findings},
            "evaluation_count": evaluations,
            "watermarks": [dict(row) for row in watermarks],
            "worker": dict(worker) if worker is not None else None,
        }

    def ensure_default_policy(self) -> DetectionPolicy:
        policy = default_policy(source_commit=safe_source_commit())
        with self.storage.connect() as conn:
            row = conn.execute(
                "SELECT * FROM detection_policies WHERE policy_hash = ?",
                (policy.policy_hash,),
            ).fetchone()
            if row is None:
                payload = policy_storage_payload(policy)
                conn.execute(
                    """
                    INSERT OR IGNORE INTO detection_policies (
                        policy_id, policy_version, policy_hash, mode, policy_json,
                        active, created_at, source_commit
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload["policy_id"],
                        payload["policy_version"],
                        payload["policy_hash"],
                        payload["mode"],
                        payload["policy_json"],
                        payload["active"],
                        payload["created_at"],
                        payload["source_commit"],
                    ),
                )
                conn.execute(
                    "UPDATE detection_policies SET active = 0 WHERE policy_hash != ?",
                    (policy.policy_hash,),
                )
                conn.execute(
                    "UPDATE detection_policies SET active = 1 WHERE policy_hash = ?",
                    (policy.policy_hash,),
                )
                return policy
            active = conn.execute(
                "SELECT * FROM detection_policies WHERE active = 1 ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return load_policy(dict(active or row))

    def policies_list(self) -> list[dict[str, Any]]:
        self.ensure_default_policy()
        with self.storage.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM detection_policies ORDER BY active DESC, created_at DESC"
            ).fetchall()
        return [self._policy_row(row) for row in rows]

    def policy_show(self, policy_id: str, policy_version: str | None = None) -> dict[str, Any]:
        self.ensure_default_policy()
        clauses = ["policy_id = ?"]
        params: list[object] = [policy_id]
        if policy_version is not None:
            clauses.append("policy_version = ?")
            params.append(policy_version)
        with self.storage.connect() as conn:
            row = conn.execute(
                f"SELECT * FROM detection_policies WHERE {' AND '.join(clauses)} "
                "ORDER BY created_at DESC LIMIT 1",
                params,
            ).fetchone()
        if row is None:
            raise DetectionEngineError("detection policy not found")
        return self._policy_row(row)

    def activate_policy(self, policy_id: str, policy_version: str | None = None) -> dict[str, Any]:
        policy = self.policy_show(policy_id, policy_version)
        with self.storage.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE detection_policies SET active = 0")
            conn.execute(
                "UPDATE detection_policies SET active = 1 WHERE policy_hash = ?",
                (policy["policy_hash"],),
            )
        policy["active"] = True
        return policy

    def rules_list(self) -> list[dict[str, Any]]:
        policy = default_policy()
        return [rule.model_dump(mode="json") for rule in policy.rules]

    def run_once(
        self,
        *,
        dataset_kind: str = "synthetic",
        profile: str | None = None,
        policy_id: str | None = None,
        policy_version: str | None = None,
        model_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        batch_size: int = 256,
        max_windows: int | None = None,
        rules_only: bool = False,
        dry_run: bool = False,
        advance_watermark: bool = True,
    ) -> dict[str, Any]:
        del batch_size
        self.storage.initialize()
        policy = (
            self._policy_from_public(self.policy_show(policy_id, policy_version))
            if policy_id is not None
            else self.ensure_default_policy()
        )
        if rules_only:
            policy = policy.model_copy(update={"mode": "rules_only", "model_required": False})
        windows = self._candidate_windows(
            dataset_kind=dataset_kind,
            profile=profile,
            start=start,
            end=end,
            max_windows=max_windows,
        )
        run_id = f"detect-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        model_record = self._resolve_model(policy, dataset_kind, profile, model_id)
        model_context = self._load_model_context(model_record) if model_record else None
        now = datetime.now(UTC).isoformat()
        if not dry_run:
            self._insert_run_start(run_id, policy, dataset_kind, profile, model_record, now)
        evaluated = skipped = findings = noop = 0
        safe_error: str | None = None
        try:
            for window in windows:
                detection_input = self._window_input(window)
                if profile is not None and detection_input.profile_key != profile:
                    continue
                model_identity = (
                    str(model_record["model_id"]) if model_record else MODEL_ID_SENTINEL
                )
                if not dry_run and self._evaluation_exists(
                    detection_input.window_id,
                    detection_input.feature_input_hash,
                    policy.policy_hash,
                    model_identity,
                ):
                    noop += 1
                    continue
                if detection_input.quality not in set(policy.quality_gate):
                    skipped += 1
                    decision = self._skipped_decision(detection_input, policy, model_record)
                    if not dry_run:
                        self._persist_evaluation(
                            run_id,
                            detection_input,
                            policy,
                            model_record,
                            decision,
                            [],
                            status="skipped",
                            skipped_reason=decision.skipped_reason,
                        )
                    continue
                signals: list[DetectionSignal] = []
                if policy.mode in {"hybrid", "rules_only"}:
                    signals.extend(evaluate_rules(detection_input, policy.rules))
                if policy.mode in {"hybrid", "model_only"} and model_context is not None:
                    signals.append(self._model_signal(detection_input, model_record, model_context))
                if policy.mode == "model_only" and model_context is None:
                    skipped += 1
                    decision = self._skipped_decision(
                        detection_input,
                        policy,
                        model_record,
                        reason="verified champion model is required for model_only detection",
                    )
                    if not dry_run:
                        self._persist_evaluation(
                            run_id,
                            detection_input,
                            policy,
                            model_record,
                            decision,
                            [],
                            status="skipped",
                            skipped_reason=decision.skipped_reason,
                        )
                    continue
                suppressed = self._is_suppressed(detection_input, signals)
                decision = fuse_signals(
                    detection_input,
                    policy,
                    signals,
                    model_id=str(model_record["model_id"]) if model_record else None,
                    model_version=str(model_record["model_version"]) if model_record else None,
                    model_hash=str(model_record["model_artifact_sha256"]) if model_record else None,
                    suppressed=suppressed,
                )
                if decision.finding and self._fingerprint_suppressed(detection_input, decision):
                    suppressed = True
                    decision = decision.model_copy(update={"suppressed": True, "finding": False})
                status = "suppressed" if suppressed and decision.matched_signal_ids else (
                    "finding" if decision.finding else "no_finding"
                )
                evaluated += 1
                if decision.finding:
                    findings += 1
                if not dry_run:
                    self._persist_evaluation(
                        run_id,
                        detection_input,
                        policy,
                        model_record,
                        decision,
                        signals,
                        status=status,
                    )
            if not dry_run:
                self._complete_run(
                    run_id,
                    status="success",
                    completed_at=datetime.now(UTC).isoformat(),
                    evaluated=evaluated,
                    skipped=skipped,
                    findings=findings,
                    noop=noop,
                    safe_error=None,
                )
                if advance_watermark and windows:
                    last = windows[-1]
                    self._advance_watermark(policy, dataset_kind, profile, model_record, last)
        except Exception as exc:
            safe_error = self._safe_error(exc)
            if not dry_run:
                self._complete_run(
                    run_id,
                    status="failed",
                    completed_at=datetime.now(UTC).isoformat(),
                    evaluated=evaluated,
                    skipped=skipped,
                    findings=findings,
                    noop=noop,
                    safe_error=safe_error,
                )
            raise
        result = DetectionRunResult(
            detection_run_id=run_id,
            status="dry_run" if dry_run else "success",
            dataset_kind=cast(Literal["synthetic", "real"], dataset_kind),
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            mode=policy.mode,
            model_id=str(model_record["model_id"]) if model_record else None,
            window_count=len(windows),
            evaluated_count=evaluated,
            skipped_count=skipped,
            finding_count=findings,
            no_op_count=noop,
            dry_run=dry_run,
            safe_error=safe_error,
        )
        return result.model_dump(mode="json")

    def backfill(
        self,
        *,
        dataset_kind: str = "synthetic",
        policy_id: str | None = None,
        model_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        registered_dataset_id: str | None = None,
        confirm: bool = False,
        advance_watermark: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise DetectionEngineError("detection backfill requires confirm=true")
        if registered_dataset_id is not None:
            snapshot = self.storage.get_dataset_snapshot(registered_dataset_id)
            if snapshot is None:
                raise DetectionEngineError("registered dataset snapshot not found")
            dataset_kind = str(snapshot["dataset_kind"])
            start = datetime.fromisoformat(str(snapshot["start"]))
            end = datetime.fromisoformat(str(snapshot["end"]))
        if start is None or end is None:
            raise DetectionEngineError("backfill requires an explicit range or dataset id")
        return self.run_once(
            dataset_kind=dataset_kind,
            policy_id=policy_id,
            model_id=model_id,
            start=start,
            end=end,
            max_windows=None,
            advance_watermark=advance_watermark,
        )

    def runs_list(self) -> list[dict[str, Any]]:
        with self.storage.connect() as conn:
            rows = conn.execute("SELECT * FROM detection_runs ORDER BY started_at DESC").fetchall()
        return [dict(row) for row in rows]

    def run_show(self, detection_run_id: str) -> dict[str, Any] | None:
        with self.storage.connect() as conn:
            run = conn.execute(
                "SELECT * FROM detection_runs WHERE detection_run_id = ?",
                (detection_run_id,),
            ).fetchone()
            if run is None:
                return None
            evaluations = conn.execute(
                """
                SELECT * FROM detection_evaluations
                WHERE detection_run_id = ?
                ORDER BY detection_score DESC, window_start ASC
                """,
                (detection_run_id,),
            ).fetchall()
        payload = dict(run)
        payload["evaluations"] = [self._evaluation_row(row) for row in evaluations]
        return payload

    def findings_list(
        self,
        *,
        status: str | None = None,
        dataset_kind: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[object] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if dataset_kind is not None:
            clauses.append("dataset_kind = ?")
            params.append(dataset_kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.storage.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings {where} ORDER BY last_seen_at DESC",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def finding_show(self, finding_id: str) -> dict[str, Any] | None:
        with self.storage.connect() as conn:
            finding = conn.execute(
                "SELECT * FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if finding is None:
                return None
            occurrences = conn.execute(
                """
                SELECT * FROM finding_occurrences
                WHERE finding_id = ?
                ORDER BY window_start ASC
                """,
                (finding_id,),
            ).fetchall()
            history = conn.execute(
                """
                SELECT * FROM finding_state_history
                WHERE finding_id = ?
                ORDER BY created_at ASC
                """,
                (finding_id,),
            ).fetchall()
        payload = dict(finding)
        payload["occurrences"] = [self._occurrence_row(row) for row in occurrences]
        payload["history"] = [dict(row) for row in history]
        return payload

    def transition_finding(
        self,
        finding_id: str,
        *,
        to_status: str,
        reason: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        allowed = {
            "open": {"acknowledged", "investigating", "suppressed", "resolved", "false_positive"},
            "acknowledged": {"investigating", "suppressed", "resolved", "false_positive"},
            "investigating": {"acknowledged", "suppressed", "resolved", "false_positive"},
            "suppressed": {"open", "resolved", "false_positive"},
            "resolved": set(),
            "false_positive": set(),
        }
        with self.storage.connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if row is None:
                raise DetectionEngineError("finding not found")
            current = str(row["status"])
            if to_status in END_FINDING_STATUSES and not confirm:
                raise DetectionEngineError("destructive finding transition requires confirm=true")
            if to_status not in allowed[current]:
                raise DetectionEngineError(f"invalid finding transition {current} -> {to_status}")
            now = datetime.now(UTC).isoformat()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?",
                (to_status, now, finding_id),
            )
            conn.execute(
                """
                INSERT INTO finding_state_history (
                    history_id, finding_id, from_status, to_status, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"hist-{uuid4().hex}",
                    finding_id,
                    current,
                    to_status,
                    sanitize_reason(reason),
                    now,
                ),
            )
        return self.finding_show(finding_id) or {}

    def suppressions_list(self) -> list[dict[str, Any]]:
        with self.storage.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM detection_suppressions ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def create_suppression(
        self,
        *,
        scope: str,
        reason: str,
        ttl_minutes: int,
        dataset_kind: str | None = None,
        profile_key_value: str | None = None,
        finding_fingerprint: str | None = None,
        signal_id: str | None = None,
    ) -> dict[str, Any]:
        if scope not in {
            "finding_fingerprint",
            "signal_for_profile",
            "signal_for_dataset_kind",
        }:
            raise DetectionEngineError("unsupported suppression scope")
        if ttl_minutes <= 0 or ttl_minutes > 525_600:
            raise DetectionEngineError("ttl_minutes must be between 1 and 525600")
        expires = datetime.now(UTC) + timedelta(minutes=ttl_minutes)
        payload = {
            "suppression_id": f"supp-{uuid4().hex}",
            "scope": scope,
            "dataset_kind": dataset_kind,
            "profile_key": profile_key_value,
            "finding_fingerprint": finding_fingerprint,
            "signal_id": signal_id,
            "reason": sanitize_reason(reason),
            "expires_at": expires.isoformat(),
            "active": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "revoked_at": None,
        }
        with self.storage.connect() as conn:
            conn.execute(
                """
                INSERT INTO detection_suppressions (
                    suppression_id, scope, dataset_kind, profile_key, finding_fingerprint,
                    signal_id, reason, expires_at, active, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(payload.values()),
            )
        return payload

    def revoke_suppression(self, suppression_id: str) -> dict[str, Any]:
        with self.storage.connect() as conn:
            row = conn.execute(
                "SELECT * FROM detection_suppressions WHERE suppression_id = ?",
                (suppression_id,),
            ).fetchone()
            if row is None:
                raise DetectionEngineError("suppression not found")
            conn.execute(
                """
                UPDATE detection_suppressions
                SET active = 0, revoked_at = ?
                WHERE suppression_id = ?
                """,
                (datetime.now(UTC).isoformat(), suppression_id),
            )
        return {"suppression_id": suppression_id, "revoked": True}

    def worker_status(self) -> dict[str, Any]:
        with self.storage.connect() as conn:
            row = conn.execute(
                "SELECT * FROM detection_worker_leases ORDER BY heartbeat_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row is not None else {"status": "stopped"}

    def worker_start(
        self,
        *,
        dataset_kind: str = "synthetic",
        interval_seconds: int = 60,
    ) -> dict[str, Any]:
        worker_id = "local-detection-worker"
        now = datetime.now(UTC).isoformat()
        with self.storage.connect() as conn:
            conn.execute(
                """
                INSERT INTO detection_worker_leases (
                    worker_id, owner_id, status, heartbeat_at, stop_requested,
                    config_json, safe_error
                ) VALUES (?, ?, 'running', ?, 0, ?, NULL)
                ON CONFLICT(worker_id) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    status = 'running',
                    heartbeat_at = excluded.heartbeat_at,
                    stop_requested = 0,
                    config_json = excluded.config_json,
                    safe_error = NULL
                """,
                (
                    worker_id,
                    socket.gethostname(),
                    now,
                    json.dumps(
                        {"dataset_kind": dataset_kind, "interval_seconds": interval_seconds}
                    ),
                ),
            )
        return self.worker_status()

    def worker_stop(self) -> dict[str, Any]:
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_worker_leases
                SET status = 'stopped', stop_requested = 1, heartbeat_at = ?
                WHERE worker_id = 'local-detection-worker'
                """,
                (datetime.now(UTC).isoformat(),),
            )
        return self.worker_status()

    def worker_run_foreground(
        self,
        *,
        dataset_kind: str = "synthetic",
        max_windows: int | None = 256,
    ) -> dict[str, Any]:
        self.worker_start(dataset_kind=dataset_kind)
        result = self.run_once(dataset_kind=dataset_kind, max_windows=max_windows)
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_worker_leases
                SET heartbeat_at = ?, status = 'idle'
                WHERE worker_id = 'local-detection-worker'
                """,
                (datetime.now(UTC).isoformat(),),
            )
        return {"worker": self.worker_status(), "run": result}

    def _candidate_windows(
        self,
        *,
        dataset_kind: str,
        profile: str | None,
        start: datetime | None,
        end: datetime | None,
        max_windows: int | None,
    ) -> list[dict[str, Any]]:
        windows = self.storage.list_feature_windows(
            dataset_kind=dataset_kind,
            start=start,
            end=end,
            limit=None,
        )
        filtered = [
            window
            for window in windows
            if profile is None
            or self._profile_key_for_window(window) == profile
        ]
        return filtered[:max_windows] if max_windows is not None else filtered

    def _resolve_model(
        self,
        policy: DetectionPolicy,
        dataset_kind: str,
        profile: str | None,
        model_id: str | None,
    ) -> dict[str, Any] | None:
        if policy.mode == "rules_only":
            return None
        if model_id is not None:
            model = self.storage.get_model_version(model_id)
            if model is None:
                raise DetectionEngineError("verified model is not registered")
            self.ml.verifier.verify(model_id)
            return model
        model = self.storage.champion_model(dataset_kind, profile)
        if model is not None:
            self.ml.verifier.verify(str(model["model_id"]))
            return model
        if policy.mode == "model_only" or policy.model_required:
            raise DetectionEngineError("verified champion model is required by detection policy")
        if not policy.allow_rules_without_model:
            raise DetectionEngineError("detection policy does not allow rules-only fallback")
        return None

    def _load_model_context(self, model_record: dict[str, Any] | None) -> dict[str, Any] | None:
        if model_record is None:
            return None
        manifest, preprocessor, artifact = self.ml.verifier.load(str(model_record["model_id"]))
        return {"manifest": manifest, "preprocessor": preprocessor, "artifact": artifact}

    def _window_input(self, window: dict[str, Any]) -> DetectionInput:
        values = tuple(float(window["features"][name]) for name in FEATURE_NAMES)
        payload = {
            "window_id": window["window_id"],
            "dataset_kind": window["dataset_kind"],
            "profile_key": self._profile_key_for_window(window),
            "window_start": window["window_start"],
            "window_end": window["window_end"],
            "feature_schema_version": window["feature_schema_version"],
            "feature_names": FEATURE_NAMES,
            "feature_values": list(values),
            "quality": window["quality_status"],
            "source_event_hash": window["source_event_hash"],
        }
        return DetectionInput(
            window_id=str(window["window_id"]),
            dataset_kind=cast(Literal["synthetic", "real"], str(window["dataset_kind"])),
            profile_key=self._profile_key_for_window(window),
            window_start=datetime.fromisoformat(str(window["window_start"])),
            window_end=datetime.fromisoformat(str(window["window_end"])),
            feature_schema_version=str(window["feature_schema_version"]),
            feature_values=values,
            quality=cast(
                Literal["good", "degraded", "insufficient"],
                str(window["quality_status"]),
            ),
            feature_input_hash=sha_json(payload),
        )

    def _model_signal(
        self,
        detection_input: DetectionInput,
        model_record: dict[str, Any] | None,
        model_context: dict[str, Any] | None,
    ) -> ModelSignal:
        if model_record is None or model_context is None:
            raise DetectionEngineError("model context is unavailable")
        preprocessor = model_context["preprocessor"]
        artifact = model_context["artifact"]
        scaled = preprocessor.transform([list(detection_input.feature_values)])
        batch = artifact.score(scaled)
        score = float(batch.scores[0])
        threshold = float(model_record["threshold"])
        if not math.isfinite(score) or not math.isfinite(threshold):
            raise DetectionEngineError("model score or threshold contains NaN or Infinity")
        matched = score > threshold
        strength = model_strength(score, threshold) if matched else 0
        explanations = batch.explanations[0] if batch.explanations else []
        feature_names = tuple(
            str(item.get("feature_name"))
            for item in explanations[:5]
            if isinstance(item, dict) and item.get("feature_name") in FEATURE_NAMES
        ) or tuple(FEATURE_NAMES[:3])
        evidence = tuple(
            DetectionEvidence(
                feature_name=name,
                observed_value=float(
                    detection_input.feature_values[detection_input.feature_names.index(name)]
                ),
                threshold_value=threshold,
                direction="context",
                summary="Model explanation feature contribution.",
            )
            for name in feature_names[:3]
        )
        return ModelSignal(
            signal_id=f"model-{str(model_record['family'])}-{str(model_record['model_version'])}",
            signal_version=MODEL_STRENGTH_VERSION,
            strength=strength,
            matched=matched,
            summary=(
                "Verified Stage 3 champion score exceeded calibration threshold."
                if matched
                else "Verified Stage 3 champion score did not exceed calibration threshold."
            ),
            evidence=evidence,
            contributing_feature_names=feature_names,
            config_hash=sha_json(
                {
                    "formula": MODEL_STRENGTH_VERSION,
                    "model_id": model_record["model_id"],
                    "threshold": threshold,
                }
            ),
            model_id=str(model_record["model_id"]),
            model_version=str(model_record["model_version"]),
            model_hash=str(model_record["model_artifact_sha256"]),
            anomaly_score=score,
            threshold=threshold,
        )

    def _skipped_decision(
        self,
        detection_input: DetectionInput,
        policy: DetectionPolicy,
        model_record: dict[str, Any] | None,
        *,
        reason: str | None = None,
    ) -> DetectionDecision:
        return DetectionDecision(
            detection_score=0,
            risk_level="none",
            matched_signal_ids=(),
            primary_signal_id=None,
            corroboration_count=0,
            explanation="Stage 4 skipped this feature window without creating a security finding.",
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            model_id=str(model_record["model_id"]) if model_record else None,
            model_version=str(model_record["model_version"]) if model_record else None,
            model_hash=str(model_record["model_artifact_sha256"]) if model_record else None,
            feature_input_hash=detection_input.feature_input_hash,
            finding=False,
            skipped_reason=(
                reason or f"quality={detection_input.quality} is outside policy quality gate"
            ),
        )

    def _insert_run_start(
        self,
        run_id: str,
        policy: DetectionPolicy,
        dataset_kind: str,
        profile: str | None,
        model_record: dict[str, Any] | None,
        started_at: str,
    ) -> None:
        with self.storage.connect() as conn:
            conn.execute(
                """
                INSERT INTO detection_runs (
                    detection_run_id, dataset_kind, profile_key, policy_id, policy_version,
                    policy_hash, mode, model_id, model_version, model_hash, status,
                    started_at, completed_at, window_count, evaluated_count, skipped_count,
                    finding_count, no_op_count, dry_run, safe_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, NULL, 0, 0, 0, 0, 0, 0, NULL)
                """,
                (
                    run_id,
                    dataset_kind,
                    profile,
                    policy.policy_id,
                    policy.policy_version,
                    policy.policy_hash,
                    policy.mode,
                    model_record["model_id"] if model_record else None,
                    model_record["model_version"] if model_record else None,
                    model_record["model_artifact_sha256"] if model_record else None,
                    started_at,
                ),
            )

    def _complete_run(
        self,
        run_id: str,
        *,
        status: str,
        completed_at: str,
        evaluated: int,
        skipped: int,
        findings: int,
        noop: int,
        safe_error: str | None,
    ) -> None:
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_runs
                SET status = ?, completed_at = ?, window_count = ?,
                    evaluated_count = ?, skipped_count = ?, finding_count = ?,
                    no_op_count = ?, safe_error = ?
                WHERE detection_run_id = ?
                """,
                (
                    status,
                    completed_at,
                    evaluated + skipped + noop,
                    evaluated,
                    skipped,
                    findings,
                    noop,
                    safe_error,
                    run_id,
                ),
            )

    def _persist_evaluation(
        self,
        run_id: str,
        detection_input: DetectionInput,
        policy: DetectionPolicy,
        model_record: dict[str, Any] | None,
        decision: DetectionDecision,
        signals: list[DetectionSignal],
        *,
        status: str,
        skipped_reason: str | None = None,
    ) -> None:
        evaluation_id = f"eval-{uuid4().hex}"
        finding_id = None
        now = datetime.now(UTC).isoformat()
        if decision.finding:
            finding_id = self._upsert_finding(
                detection_input,
                policy,
                model_record,
                decision,
                signals,
                evaluation_id,
                now,
            )
        with self.storage.connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO detection_evaluations (
                    evaluation_id, detection_run_id, window_id, dataset_kind, profile_key,
                    window_start, window_end, feature_schema_version, feature_input_hash,
                    policy_id, policy_version, policy_hash, model_id, model_version,
                    model_hash, mode, status, detection_score, risk_level,
                    matched_signal_ids_json, decision_json, finding_id, created_at,
                    skipped_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evaluation_id,
                    run_id,
                    detection_input.window_id,
                    detection_input.dataset_kind,
                    detection_input.profile_key,
                    detection_input.window_start.isoformat(),
                    detection_input.window_end.isoformat(),
                    detection_input.feature_schema_version,
                    detection_input.feature_input_hash,
                    policy.policy_id,
                    policy.policy_version,
                    policy.policy_hash,
                    model_record["model_id"] if model_record else MODEL_ID_SENTINEL,
                    model_record["model_version"] if model_record else None,
                    model_record["model_artifact_sha256"] if model_record else None,
                    policy.mode,
                    status,
                    decision.detection_score,
                    decision.risk_level,
                    json.dumps(decision.matched_signal_ids, sort_keys=True),
                    json.dumps(
                        {
                            "decision": decision.model_dump(mode="json"),
                            "signals": [signal.model_dump(mode="json") for signal in signals],
                        },
                        sort_keys=True,
                    ),
                    finding_id,
                    now,
                    skipped_reason,
                ),
            )

    def _upsert_finding(
        self,
        detection_input: DetectionInput,
        policy: DetectionPolicy,
        model_record: dict[str, Any] | None,
        decision: DetectionDecision,
        signals: list[DetectionSignal],
        evaluation_id: str,
        now: str,
    ) -> str:
        fingerprint = self._fingerprint(detection_input, decision)
        occurrence_id = f"occ-{uuid4().hex}"
        title = f"{decision.risk_level} Stage 4 finding"
        summary = decision.explanation[:500]
        with self.storage.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            reuse_after = (detection_input.window_start - timedelta(minutes=60)).isoformat()
            row = conn.execute(
                """
                SELECT * FROM findings
                WHERE fingerprint = ?
                    AND status IN ('open', 'acknowledged', 'investigating', 'suppressed')
                    AND last_seen_at >= ?
                ORDER BY last_seen_at DESC
                LIMIT 1
                """,
                (fingerprint, reuse_after),
            ).fetchone()
            if row is None:
                finding_id = f"find-{uuid4().hex}"
                conn.execute(
                    """
                    INSERT INTO findings (
                        finding_id, fingerprint, dataset_kind, profile_key, policy_id,
                        policy_version, policy_hash, model_id, model_version, model_hash,
                        status, risk_level, detection_score, primary_signal_id, title,
                        summary, first_seen_at, last_seen_at, occurrence_count, created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        finding_id,
                        fingerprint,
                        detection_input.dataset_kind,
                        detection_input.profile_key,
                        policy.policy_id,
                        policy.policy_version,
                        policy.policy_hash,
                        model_record["model_id"] if model_record else None,
                        model_record["model_version"] if model_record else None,
                        model_record["model_artifact_sha256"] if model_record else None,
                        decision.risk_level,
                        decision.detection_score,
                        decision.primary_signal_id or "none",
                        title,
                        summary,
                        detection_input.window_start.isoformat(),
                        detection_input.window_start.isoformat(),
                        now,
                        now,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO finding_state_history (
                        history_id, finding_id, from_status, to_status, reason, created_at
                    ) VALUES (?, ?, NULL, 'open', ?, ?)
                    """,
                    (
                        f"hist-{uuid4().hex}",
                        finding_id,
                        "created by detection engine",
                        now,
                    ),
                )
            else:
                finding_id = str(row["finding_id"])
                conn.execute(
                    """
                    UPDATE findings
                    SET last_seen_at = ?, occurrence_count = occurrence_count + 1,
                        risk_level = CASE WHEN detection_score < ? THEN ? ELSE risk_level END,
                        detection_score = MAX(detection_score, ?),
                        updated_at = ?
                    WHERE finding_id = ?
                    """,
                    (
                        detection_input.window_start.isoformat(),
                        decision.detection_score,
                        decision.risk_level,
                        decision.detection_score,
                        now,
                        finding_id,
                    ),
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO finding_occurrences (
                    occurrence_id, finding_id, evaluation_id, window_id, window_start,
                    window_end, detection_score, risk_level, signals_json, evidence_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    occurrence_id,
                    finding_id,
                    evaluation_id,
                    detection_input.window_id,
                    detection_input.window_start.isoformat(),
                    detection_input.window_end.isoformat(),
                    decision.detection_score,
                    decision.risk_level,
                    json.dumps(decision.matched_signal_ids, sort_keys=True),
                    json.dumps(
                        [signal.model_dump(mode="json") for signal in signals],
                        sort_keys=True,
                    ),
                    now,
                ),
            )
        return finding_id

    def _evaluation_exists(
        self,
        window_id: str,
        feature_input_hash: str,
        policy_hash: str,
        model_id: str,
    ) -> bool:
        with self.storage.connect() as conn:
            row = conn.execute(
                """
                SELECT evaluation_id FROM detection_evaluations
                WHERE window_id = ?
                    AND feature_input_hash = ?
                    AND policy_hash = ?
                    AND model_id = ?
                LIMIT 1
                """,
                (window_id, feature_input_hash, policy_hash, model_id),
            ).fetchone()
        return row is not None

    def _is_suppressed(
        self,
        detection_input: DetectionInput,
        signals: list[DetectionSignal],
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        signal_ids = {signal.signal_id for signal in signals if signal.matched}
        with self.storage.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM detection_suppressions
                WHERE active = 1 AND expires_at > ?
                """,
                (now,),
            ).fetchall()
        for row in rows:
            scope = str(row["scope"])
            if (
                scope == "signal_for_profile"
                and row["profile_key"] == detection_input.profile_key
                and row["signal_id"] in signal_ids
            ):
                return True
            if (
                scope == "signal_for_dataset_kind"
                and row["dataset_kind"] == detection_input.dataset_kind
                and row["signal_id"] in signal_ids
            ):
                return True
        return False

    def _fingerprint_suppressed(
        self,
        detection_input: DetectionInput,
        decision: DetectionDecision,
    ) -> bool:
        fingerprint = self._fingerprint(detection_input, decision)
        now = datetime.now(UTC).isoformat()
        with self.storage.connect() as conn:
            row = conn.execute(
                """
                SELECT suppression_id FROM detection_suppressions
                WHERE active = 1
                    AND expires_at > ?
                    AND scope = 'finding_fingerprint'
                    AND finding_fingerprint = ?
                LIMIT 1
                """,
                (now, fingerprint),
            ).fetchone()
        return row is not None

    def _advance_watermark(
        self,
        policy: DetectionPolicy,
        dataset_kind: str,
        profile: str | None,
        model_record: dict[str, Any] | None,
        window: dict[str, Any],
    ) -> None:
        model_id = str(model_record["model_id"]) if model_record else MODEL_ID_SENTINEL
        key = "|".join([dataset_kind, profile or "*", policy.policy_hash, model_id])
        with self.storage.connect() as conn:
            conn.execute(
                """
                INSERT INTO detection_watermarks (
                    watermark_key, dataset_kind, profile_key, policy_hash, model_id,
                    last_window_start, last_window_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(watermark_key) DO UPDATE SET
                    last_window_start = excluded.last_window_start,
                    last_window_id = excluded.last_window_id,
                    updated_at = excluded.updated_at
                """,
                (
                    key,
                    dataset_kind,
                    profile,
                    policy.policy_hash,
                    model_id,
                    window["window_start"],
                    window["window_id"],
                    datetime.now(UTC).isoformat(),
                ),
            )

    def _fingerprint(self, detection_input: DetectionInput, decision: DetectionDecision) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "strategy": "finding-fingerprint-v1",
                    "dataset_kind": detection_input.dataset_kind,
                    "profile_key": detection_input.profile_key,
                    "primary_signal_id": decision.primary_signal_id,
                    "matched_signal_ids": sorted(decision.matched_signal_ids),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]

    def _profile_key_for_window(self, window: dict[str, Any]) -> str:
        return profile_key({"user_id": str(window["user_id"]), "host_id": str(window["host_id"])})

    def _policy_row(self, row: Any) -> dict[str, Any]:
        payload = dict(row)
        payload["policy"] = json.loads(payload.pop("policy_json"))
        payload["active"] = bool(payload["active"])
        return payload

    def _policy_from_public(self, payload: dict[str, Any]) -> DetectionPolicy:
        policy = dict(payload["policy"])
        policy["created_at"] = datetime.fromisoformat(str(policy["created_at"]))
        policy["rules"] = tuple(DetectionRule(**item) for item in policy["rules"])
        policy["quality_gate"] = tuple(policy["quality_gate"])
        return DetectionPolicy(**policy)

    def _evaluation_row(self, row: Any) -> dict[str, Any]:
        payload = dict(row)
        payload["matched_signal_ids"] = json.loads(payload.pop("matched_signal_ids_json"))
        payload["decision"] = json.loads(payload.pop("decision_json"))
        return payload

    def _occurrence_row(self, row: Any) -> dict[str, Any]:
        payload = dict(row)
        payload["signals"] = json.loads(payload.pop("signals_json"))
        payload["evidence"] = json.loads(payload.pop("evidence_json"))
        return payload

    def _safe_error(self, exc: Exception) -> str:
        if isinstance(exc, ModelBundleVerificationError):
            prefix = "model verification failed"
        else:
            prefix = exc.__class__.__name__
        message = str(exc).replace(str(Path.home()), "~")
        return sanitize_reason(f"{prefix}: {message}", limit=500)


def model_strength(score: float, threshold: float) -> int:
    if not math.isfinite(score) or not math.isfinite(threshold):
        raise DetectionEngineError("model score or threshold contains NaN or Infinity")
    margin = score - threshold
    if margin <= 0:
        return 0
    if threshold > 0:
        ratio = margin / max(abs(threshold), 1e-9)
    else:
        ratio = margin / max(abs(score), 1e-9)
    return max(1, min(100, int(round(50 + min(1.0, ratio) * 50))))
