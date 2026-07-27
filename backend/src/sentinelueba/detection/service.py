from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from sentinelueba.datasets import DatasetSnapshotService
from sentinelueba.detection.contracts import (
    DetectionDecision,
    DetectionEvidence,
    DetectionInput,
    DetectionPolicy,
    DetectionRunResult,
    DetectionSignal,
    ModelSignal,
    RiskThresholdConfig,
    SuppressionRequest,
)
from sentinelueba.detection.fusion import fuse_signals
from sentinelueba.detection.policies import (
    KNOWN_SIGNAL_IDS,
    MODEL_STRENGTH_VERSION,
    built_in_policies,
    default_policy,
    load_policy,
    parse_rule,
    policy_storage_payload,
    rules_only_policy,
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
        policies = built_in_policies(source_commit=safe_source_commit())
        default = policies[0]
        with self.storage.connect() as conn:
            for policy in policies:
                row = conn.execute(
                    "SELECT * FROM detection_policies WHERE policy_hash = ?",
                    (policy.policy_hash,),
                ).fetchone()
                if row is not None:
                    load_policy(dict(row))
                    continue
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
                        0,
                        payload["created_at"],
                        payload["source_commit"],
                    ),
                )
            active_count = conn.execute(
                "SELECT COUNT(*) FROM detection_policies WHERE active = 1"
            ).fetchone()[0]
            if int(active_count) == 0:
                conn.execute(
                    "UPDATE detection_policies SET active = 1 WHERE policy_hash = ?",
                    (default.policy_hash,),
                )
            active = conn.execute(
                "SELECT * FROM detection_policies WHERE active = 1 ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return load_policy(dict(active))

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

    def activate_policy(
        self,
        policy_id: str,
        policy_version: str | None = None,
        *,
        confirm: bool = False,
        reason: str = "manual policy activation",
    ) -> dict[str, Any]:
        if not confirm:
            raise DetectionEngineError("policy activation requires confirm=true")
        policy = self.policy_show(policy_id, policy_version)
        with self.storage.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute(
                "SELECT policy_hash FROM detection_policies WHERE active = 1 LIMIT 1"
            ).fetchone()
            conn.execute("UPDATE detection_policies SET active = 0")
            conn.execute(
                "UPDATE detection_policies SET active = 1 WHERE policy_hash = ?",
                (policy["policy_hash"],),
            )
            conn.execute(
                """
                INSERT INTO detection_policy_activations (
                    activation_id, previous_policy_hash, new_policy_hash, reason, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    f"policy-act-{uuid4().hex}",
                    previous["policy_hash"] if previous is not None else None,
                    policy["policy_hash"],
                    sanitize_reason(reason),
                    datetime.now(UTC).isoformat(),
                ),
            )
        policy["active"] = True
        return policy

    def rules_list(self) -> list[dict[str, Any]]:
        policy = default_policy(source_commit=safe_source_commit())
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
        run_mode: str = "manual",
        parent_run_id: str | None = None,
    ) -> dict[str, Any]:
        self.storage.initialize()
        base_policy = (
            self._policy_from_public(self.policy_show(policy_id, policy_version))
            if policy_id is not None
            else self.ensure_default_policy()
        )
        if rules_only:
            base_policy = self._registered_policy(
                rules_only_policy(source_commit=safe_source_commit())
            )
        if profile is None and model_id is None:
            profiles = self.storage.list_detection_profiles(
                dataset_kind=dataset_kind,
                start=start,
                end=end,
            )
            children = [
                self._run_profile_once(
                    dataset_kind=dataset_kind,
                    profile=profile_key_value,
                    base_policy=base_policy,
                    explicit_model_id=None,
                    start=start,
                    end=end,
                    batch_size=batch_size,
                    max_windows=max_windows,
                    dry_run=dry_run,
                    advance_watermark=advance_watermark,
                    run_mode=run_mode,
                    parent_run_id=parent_run_id,
                )
                for profile_key_value in profiles
            ]
            return self._aggregate_results(dataset_kind, base_policy, children, dry_run)
        if profile is None and model_id is not None:
            model = self.storage.get_model_version(model_id)
            if model is None:
                raise DetectionEngineError("verified model is not registered")
            profile = str(model["profile_key"])
        if profile is None:
            raise DetectionEngineError("profile is required for exact detection run")
        return self._run_profile_once(
            dataset_kind=dataset_kind,
            profile=profile,
            base_policy=base_policy,
            explicit_model_id=model_id,
            start=start,
            end=end,
            batch_size=batch_size,
            max_windows=max_windows,
            dry_run=dry_run,
            advance_watermark=advance_watermark,
            run_mode=run_mode,
            parent_run_id=parent_run_id,
        )

    def _run_profile_once(
        self,
        *,
        dataset_kind: str,
        profile: str,
        base_policy: DetectionPolicy,
        explicit_model_id: str | None,
        start: datetime | None,
        end: datetime | None,
        batch_size: int,
        max_windows: int | None,
        dry_run: bool,
        advance_watermark: bool,
        run_mode: str,
        parent_run_id: str | None,
    ) -> dict[str, Any]:
        run_id = f"detect-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"
        hint = self._model_hint(base_policy, dataset_kind, profile, explicit_model_id)
        policy = hint["policy"]
        model_record = hint["model"]
        now = datetime.now(UTC).isoformat()
        if not dry_run:
            self._insert_run_start(
                run_id,
                policy,
                dataset_kind,
                profile,
                model_record,
                now,
                run_mode=run_mode,
                range_start=start,
                range_end=end,
                parent_run_id=parent_run_id,
            )
        model_context = None
        safe_error: str | None = None
        error_class: str | None = None
        try:
            model_record = self._resolve_model(policy, dataset_kind, profile, explicit_model_id)
            if not dry_run and model_record is not None:
                self._update_run_model(run_id, model_record)
            model_context = self._load_model_context(model_record) if model_record else None
        except Exception as exc:
            safe_error = self._safe_error(exc)
            error_class = exc.__class__.__name__
            if not dry_run:
                self._block_run(run_id, reason=safe_error, error_class=error_class)
            return self._run_result(run_id, policy, dataset_kind, model_record, dry_run)
        model_identity = str(model_record["model_id"]) if model_record else MODEL_ID_SENTINEL
        processed = 0
        had_error = False
        while max_windows is None or processed < max_windows:
            limit = max(1, batch_size)
            if max_windows is not None:
                limit = min(limit, max_windows - processed)
            if limit <= 0:
                break
            windows = self.storage.list_pending_detection_windows(
                dataset_kind=dataset_kind,
                profile_key=profile,
                policy_hash=policy.policy_hash,
                model_identity=model_identity,
                start=start,
                end=end,
                limit=limit,
            )
            if not windows:
                break
            last_window: dict[str, Any] | None = None
            for window in windows:
                processed += 1
                last_window = window
                if dry_run:
                    continue
                try:
                    self._evaluate_window_atomic(
                        run_id=run_id,
                        window=window,
                        policy=policy,
                        model_record=model_record,
                        model_context=model_context,
                    )
                except Exception as exc:
                    had_error = True
                    safe_error = self._safe_error(exc)
                    error_class = exc.__class__.__name__
                    self._record_run_error(run_id, safe_error=safe_error, error_class=error_class)
                    continue
            if advance_watermark and not dry_run and last_window is not None:
                self._advance_watermark(policy, dataset_kind, profile, model_record, last_window)
            if len(windows) < limit:
                break
        if not dry_run:
            self._finish_run(
                run_id,
                status="partial" if had_error else "success",
                safe_error=safe_error,
                error_class=error_class,
            )
        return self._run_result(run_id, policy, dataset_kind, model_record, dry_run)

    def _registered_policy(self, policy: DetectionPolicy) -> DetectionPolicy:
        self.ensure_default_policy()
        with self.storage.connect() as conn:
            row = conn.execute(
                "SELECT * FROM detection_policies WHERE policy_hash = ?",
                (policy.policy_hash,),
            ).fetchone()
        if row is None:
            raise DetectionEngineError("effective detection policy is not registered")
        return load_policy(dict(row))

    def _model_hint(
        self,
        policy: DetectionPolicy,
        dataset_kind: str,
        profile: str,
        explicit_model_id: str | None,
    ) -> dict[str, Any]:
        if policy.mode == "rules_only":
            return {"policy": policy, "model": None}
        if explicit_model_id is not None:
            return {"policy": policy, "model": self.storage.get_model_version(explicit_model_id)}
        model = self.storage.champion_model(dataset_kind, profile)
        if model is None and policy.mode == "hybrid" and policy.allow_rules_without_model:
            return {
                "policy": self._registered_policy(
                    rules_only_policy(source_commit=safe_source_commit())
                ),
                "model": None,
            }
        return {"policy": policy, "model": model}

    def _aggregate_results(
        self,
        dataset_kind: str,
        policy: DetectionPolicy,
        children: list[dict[str, Any]],
        dry_run: bool,
    ) -> dict[str, Any]:
        status = "success"
        if any(child["status"] == "failed" for child in children):
            status = "failed"
        elif any(child["status"] in {"partial", "blocked"} for child in children):
            status = "partial"
        result = DetectionRunResult(
            detection_run_id=None,
            child_run_ids=tuple(
                str(child["detection_run_id"])
                for child in children
                if child.get("detection_run_id") is not None
            ),
            status=cast(Literal["success", "partial", "failed", "blocked", "dry_run"], status),
            dataset_kind=cast(Literal["synthetic", "real"], dataset_kind),
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            mode=policy.mode,
            model_id=None,
            window_count=sum(int(child["window_count"]) for child in children),
            examined_count=sum(int(child.get("examined_count", 0)) for child in children),
            evaluated_count=sum(int(child["evaluated_count"]) for child in children),
            skipped_count=sum(int(child["skipped_count"]) for child in children),
            finding_count=sum(int(child["finding_count"]) for child in children),
            new_findings=sum(int(child.get("new_findings", 0)) for child in children),
            updated_findings=sum(int(child.get("updated_findings", 0)) for child in children),
            finding_occurrences=sum(
                int(child.get("finding_occurrences", 0)) for child in children
            ),
            no_op_count=sum(int(child["no_op_count"]) for child in children),
            dry_run=dry_run,
        )
        return result.model_dump(mode="json")

    def _evaluate_window_atomic(
        self,
        *,
        run_id: str,
        window: dict[str, Any],
        policy: DetectionPolicy,
        model_record: dict[str, Any] | None,
        model_context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        detection_input = self._window_input(window)
        signals: list[DetectionSignal] = []
        if detection_input.quality not in set(policy.quality_gate):
            decision = self._skipped_decision(detection_input, policy, model_record)
            status = "skipped"
        else:
            if policy.mode in {"hybrid", "rules_only"}:
                signals.extend(evaluate_rules(detection_input, policy.rules))
            if policy.mode in {"hybrid", "model_only"} and model_context is not None:
                signals.append(self._model_signal(detection_input, model_record, model_context))
            signal_suppression = self._suppression_for(detection_input, signals)
            decision = fuse_signals(
                detection_input,
                policy,
                signals,
                model_id=str(model_record["model_id"]) if model_record else None,
                model_version=str(model_record["model_version"]) if model_record else None,
                model_hash=str(model_record["model_artifact_sha256"]) if model_record else None,
                suppressed=signal_suppression is not None,
            )
            fingerprint_suppression = (
                self._suppression_for(
                    detection_input,
                    signals,
                    decision=decision,
                    model_record=model_record,
                )
                if decision.finding
                else None
            )
            suppression = signal_suppression or fingerprint_suppression
            if suppression is not None:
                decision = decision.model_copy(
                    update={
                        "suppressed": True,
                        "finding": False,
                        "suppression": {
                            "suppression_id": suppression["suppression_id"],
                            "reason": suppression["reason"],
                            "expires_at": suppression["expires_at"],
                        },
                    }
                )
            status = "suppressed" if suppression is not None and decision.matched_signal_ids else (
                "finding" if decision.finding else "no_finding"
            )
        now = datetime.now(UTC).isoformat()
        model_identity = str(model_record["model_id"]) if model_record else MODEL_ID_SENTINEL
        decision_payload = {
            "decision": decision.model_dump(mode="json"),
            "signals": [signal.model_dump(mode="json") for signal in signals],
        }
        finding = None
        occurrence = None
        if decision.finding:
            fingerprint = self._fingerprint(detection_input, decision, model_record)
            finding = {
                "finding_id": f"find-{uuid4().hex}",
                "history_id": f"hist-{uuid4().hex}",
                "fingerprint": fingerprint,
                "dataset_kind": detection_input.dataset_kind,
                "profile_key": detection_input.profile_key,
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_hash": policy.policy_hash,
                "model_id": model_record["model_id"] if model_record else None,
                "model_version": model_record["model_version"] if model_record else None,
                "model_hash": model_record["model_artifact_sha256"] if model_record else None,
                "risk_level": decision.risk_level,
                "detection_score": decision.detection_score,
                "primary_signal_id": decision.primary_signal_id or "none",
                "title": f"{decision.risk_level} Stage 4 finding",
                "summary": decision.explanation[:500],
                "first_seen_at": detection_input.window_start.isoformat(),
                "last_seen_at": detection_input.window_start.isoformat(),
                "created_at": now,
                "updated_at": now,
            }
            occurrence = {
                "occurrence_id": f"occ-{uuid4().hex}",
                "window_id": detection_input.window_id,
                "window_start": detection_input.window_start.isoformat(),
                "window_end": detection_input.window_end.isoformat(),
                "detection_score": decision.detection_score,
                "risk_level": decision.risk_level,
                "created_at": now,
            }
        suppression = decision.suppression or {}
        return self.storage.persist_detection_evaluation_atomic(
            evaluation={
                "evaluation_id": f"eval-{uuid4().hex}",
                "detection_run_id": run_id,
                "window_id": detection_input.window_id,
                "dataset_kind": detection_input.dataset_kind,
                "profile_key": detection_input.profile_key,
                "window_start": detection_input.window_start.isoformat(),
                "window_end": detection_input.window_end.isoformat(),
                "feature_schema_version": detection_input.feature_schema_version,
                "feature_input_hash": detection_input.feature_input_hash,
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_hash": policy.policy_hash,
                "model_id": model_identity,
                "model_version": model_record["model_version"] if model_record else None,
                "model_hash": model_record["model_artifact_sha256"] if model_record else None,
                "mode": policy.mode,
                "status": status,
                "detection_score": decision.detection_score,
                "risk_level": decision.risk_level,
                "created_at": now,
                "skipped_reason": decision.skipped_reason,
                "suppression_id": suppression.get("suppression_id"),
                "suppression_reason": suppression.get("reason"),
                "suppression_expires_at": suppression.get("expires_at"),
            },
            decision_json=json.dumps(decision_payload, sort_keys=True),
            matched_signal_ids_json=json.dumps(decision.matched_signal_ids, sort_keys=True),
            signals_json=json.dumps(
                [signal.model_dump(mode="json") for signal in signals],
                sort_keys=True,
            ),
            finding=finding,
            occurrence=occurrence,
            correlation_from=(detection_input.window_start - timedelta(minutes=60)).isoformat(),
            correlation_to=(detection_input.window_start + timedelta(minutes=60)).isoformat(),
        )

    def backfill(
        self,
        *,
        dataset_kind: str = "synthetic",
        policy_id: str | None = None,
        policy_version: str | None = None,
        model_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        registered_dataset_id: str | None = None,
        confirm: bool = False,
        advance_watermark: bool = False,
        confirm_advance_watermark: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise DetectionEngineError("detection backfill requires confirm=true")
        if advance_watermark and not confirm_advance_watermark:
            raise DetectionEngineError(
                "backfill watermark advancement requires confirm_advance_watermark=true"
            )
        if policy_id is None:
            raise DetectionEngineError("backfill requires an explicit registered policy id")
        if registered_dataset_id is not None:
            snapshot = self.storage.get_dataset_snapshot(registered_dataset_id)
            if snapshot is None:
                raise DetectionEngineError("registered dataset snapshot not found")
            self._verify_registered_snapshot(registered_dataset_id)
            dataset_kind = str(snapshot["dataset_kind"])
            start = datetime.fromisoformat(str(snapshot["start"]))
            end = datetime.fromisoformat(str(snapshot["end"]))
        if start is None or end is None:
            raise DetectionEngineError("backfill requires an explicit range or dataset id")
        return self.run_once(
            dataset_kind=dataset_kind,
            policy_id=policy_id,
            policy_version=policy_version,
            model_id=model_id,
            start=start,
            end=end,
            max_windows=None,
            advance_watermark=advance_watermark,
            run_mode="backfill",
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
        now = datetime.now(UTC).isoformat()
        with self.storage.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM detection_suppressions ORDER BY created_at DESC"
            ).fetchall()
        payload = []
        for row in rows:
            item = dict(row)
            item["effective_active"] = bool(item["active"]) and str(item["expires_at"]) > now
            payload.append(item)
        return payload

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
        try:
            contract = SuppressionRequest(
                scope=cast(
                    Literal[
                        "finding_fingerprint",
                        "signal_for_profile",
                        "signal_for_dataset_kind",
                    ],
                    scope,
                ),
                reason=reason,
                ttl_minutes=ttl_minutes,
                dataset_kind=cast(Literal["synthetic", "real"] | None, dataset_kind),
                profile_key=profile_key_value,
                finding_fingerprint=finding_fingerprint,
                signal_id=signal_id,
            )
        except ValueError as exc:
            raise DetectionEngineError(str(exc)) from exc
        if ttl_minutes <= 0 or ttl_minutes > 525_600:
            raise DetectionEngineError("ttl_minutes must be between 1 and 525600")
        if contract.signal_id is not None and contract.signal_id not in KNOWN_SIGNAL_IDS:
            raise DetectionEngineError("suppression signal_id is not a known Stage 4 signal")
        expires = datetime.now(UTC) + timedelta(minutes=ttl_minutes)
        payload = {
            "suppression_id": f"supp-{uuid4().hex}",
            "scope": contract.scope,
            "dataset_kind": contract.dataset_kind,
            "profile_key": contract.profile_key,
            "finding_fingerprint": contract.finding_fingerprint,
            "signal_id": contract.signal_id,
            "reason": sanitize_reason(contract.reason),
            "expires_at": expires.isoformat(),
            "active": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "revoked_at": None,
        }
        with self.storage.connect() as conn:
            duplicate = conn.execute(
                """
                SELECT suppression_id
                FROM detection_suppressions
                WHERE active = 1
                    AND expires_at > ?
                    AND scope = ?
                    AND COALESCE(dataset_kind, '') = COALESCE(?, '')
                    AND COALESCE(profile_key, '') = COALESCE(?, '')
                    AND COALESCE(finding_fingerprint, '') = COALESCE(?, '')
                    AND COALESCE(signal_id, '') = COALESCE(?, '')
                LIMIT 1
                """,
                (
                    datetime.now(UTC).isoformat(),
                    payload["scope"],
                    payload["dataset_kind"],
                    payload["profile_key"],
                    payload["finding_fingerprint"],
                    payload["signal_id"],
                ),
            ).fetchone()
            if duplicate is not None:
                raise DetectionEngineError("equivalent active suppression already exists")
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

    def revoke_suppression(self, suppression_id: str, *, confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            raise DetectionEngineError("suppression revoke requires confirm=true")
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
        if row is None:
            return {"status": "stopped"}
        payload = dict(row)
        payload["lease_expired"] = (
            payload.get("expires_at") is not None
            and str(payload["expires_at"]) <= datetime.now(UTC).isoformat()
        )
        return payload

    def worker_start(
        self,
        *,
        dataset_kind: str = "synthetic",
        interval_seconds: int = 60,
        profile: str | None = None,
        lease_seconds: int = 120,
    ) -> dict[str, Any]:
        if interval_seconds < 5:
            raise DetectionEngineError("worker interval_seconds must be at least 5")
        worker_key = self._worker_key(dataset_kind, profile)
        owner_id = f"owner-{uuid4().hex}"
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        expires_at = (now_dt + timedelta(seconds=max(lease_seconds, interval_seconds))).isoformat()
        policy = self.ensure_default_policy()
        with self.storage.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                SELECT * FROM detection_worker_leases
                WHERE worker_key = ?
                ORDER BY heartbeat_at DESC
                LIMIT 1
                """,
                (worker_key,),
            ).fetchone()
            if (
                existing is not None
                and str(existing["status"]) in {"running", "idle"}
                and int(existing["stop_requested"]) == 0
                and (existing["expires_at"] is None or str(existing["expires_at"]) > now)
            ):
                raise DetectionEngineError("active detection worker lease already exists")
            worker_id = (
                str(existing["worker_id"])
                if existing is not None
                else f"worker-{uuid4().hex[:12]}"
            )
            conn.execute(
                """
                INSERT INTO detection_worker_leases (
                    worker_id, owner_id, status, heartbeat_at, stop_requested,
                    config_json, safe_error, worker_key, dataset_kind, profile_key,
                    policy_hash, acquired_at, expires_at
                ) VALUES (?, ?, 'running', ?, 0, ?, NULL, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    status = 'running',
                    heartbeat_at = excluded.heartbeat_at,
                    stop_requested = 0,
                    config_json = excluded.config_json,
                    safe_error = NULL,
                    worker_key = excluded.worker_key,
                    dataset_kind = excluded.dataset_kind,
                    profile_key = excluded.profile_key,
                    policy_hash = excluded.policy_hash,
                    acquired_at = excluded.acquired_at,
                    expires_at = excluded.expires_at
                """,
                (
                    worker_id,
                    owner_id,
                    now,
                    json.dumps(
                        {
                            "dataset_kind": dataset_kind,
                            "profile": profile,
                            "interval_seconds": interval_seconds,
                        },
                        sort_keys=True,
                    ),
                    worker_key,
                    dataset_kind,
                    profile,
                    policy.policy_hash,
                    now,
                    expires_at,
                ),
            )
        return self.worker_status()

    def worker_stop(self, *, confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            raise DetectionEngineError("worker stop requires confirm=true")
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_worker_leases
                SET status = 'stopping', stop_requested = 1, heartbeat_at = ?,
                    expires_at = ?
                WHERE status IN ('running', 'idle')
                """,
                (datetime.now(UTC).isoformat(), datetime.now(UTC).isoformat()),
            )
        return self.worker_status()

    def worker_run_foreground(
        self,
        *,
        dataset_kind: str = "synthetic",
        max_windows: int | None = 256,
        interval_seconds: int = 60,
        max_cycles: int = 1,
    ) -> dict[str, Any]:
        lease = self.worker_start(
            dataset_kind=dataset_kind,
            interval_seconds=interval_seconds,
            lease_seconds=max(interval_seconds * 2, 30),
        )
        worker_id = str(lease["worker_id"])
        runs = []
        result: dict[str, Any] = {}
        cycles = 0
        safe_error: str | None = None
        while cycles < max_cycles:
            cycles += 1
            result = self.run_once(
                dataset_kind=dataset_kind,
                max_windows=max_windows,
                run_mode="worker",
            )
            runs.append(result)
            now_dt = datetime.now(UTC)
            with self.storage.connect() as conn:
                conn.execute(
                    """
                    UPDATE detection_worker_leases
                    SET heartbeat_at = ?, status = 'idle', expires_at = ?
                    WHERE worker_id = ?
                    """,
                    (
                        now_dt.isoformat(),
                        (now_dt + timedelta(seconds=max(interval_seconds * 2, 30))).isoformat(),
                        worker_id,
                    ),
                )
                stop = conn.execute(
                    "SELECT stop_requested FROM detection_worker_leases WHERE worker_id = ?",
                    (worker_id,),
                ).fetchone()
            if stop is not None and int(stop["stop_requested"]):
                break
            if max_cycles <= 1:
                break
            time.sleep(interval_seconds)
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_worker_leases
                SET heartbeat_at = ?, status = ?, safe_error = ?
                WHERE worker_id = ?
                """,
                (
                    datetime.now(UTC).isoformat(),
                    "failed" if safe_error is not None else "idle",
                    safe_error,
                    worker_id,
                ),
            )
        return {"worker": self.worker_status(), "run": result, "runs": runs}

    def _worker_key(self, dataset_kind: str, profile: str | None) -> str:
        return "|".join(["stage4", dataset_kind, profile or "*"])

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
            self._validate_model_for_profile(model, dataset_kind, profile)
            return model
        model = self.storage.champion_model(dataset_kind, profile)
        if model is not None:
            self.ml.verifier.verify(str(model["model_id"]))
            self._validate_model_for_profile(model, dataset_kind, profile)
            return model
        if policy.mode == "model_only" or policy.model_required:
            raise DetectionEngineError("verified champion model is required by detection policy")
        if not policy.allow_rules_without_model:
            raise DetectionEngineError("detection policy does not allow rules-only fallback")
        return None

    def _validate_model_for_profile(
        self,
        model: dict[str, Any],
        dataset_kind: str,
        profile: str | None,
    ) -> None:
        if str(model["dataset_kind"]) != dataset_kind:
            raise DetectionEngineError("model dataset kind does not match detection run")
        if profile is not None and str(model["profile_key"]) != profile:
            raise DetectionEngineError("model profile does not match detection run")
        if str(model["feature_schema_version"]) == "":
            raise DetectionEngineError("model feature schema is missing")
        manifest, preprocessor, artifact = self.ml.verifier.load(str(model["model_id"]))
        del manifest
        if list(preprocessor.feature_names) != FEATURE_NAMES:
            raise DetectionEngineError("model feature names/order do not match detection contract")
        if int(artifact.input_dimension) != len(FEATURE_NAMES):
            raise DetectionEngineError("model input dimension does not match detection contract")
        if not math.isfinite(float(model["threshold"])):
            raise DetectionEngineError("model score threshold is not finite")

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
            profile_key=str(window.get("profile_key") or self._profile_key_for_window(window)),
            window_start=datetime.fromisoformat(str(window["window_start"])),
            window_end=datetime.fromisoformat(str(window["window_end"])),
            feature_schema_version=str(window["feature_schema_version"]),
            feature_values=values,
            quality=cast(
                Literal["good", "degraded", "insufficient"],
                str(window["quality_status"]),
            ),
            feature_input_hash=str(window.get("feature_input_hash") or sha_json(payload)),
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
                threshold_value=None,
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
        *,
        run_mode: str,
        range_start: datetime | None,
        range_end: datetime | None,
        parent_run_id: str | None,
    ) -> None:
        model_identity = str(model_record["model_id"]) if model_record else MODEL_ID_SENTINEL
        with self.storage.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO detection_runs (
                        detection_run_id, dataset_kind, profile_key, policy_id,
                        policy_version, policy_hash, mode, policy_mode, run_mode,
                        model_id, model_version, model_hash, status, started_at,
                        completed_at, window_count, evaluated_count, skipped_count,
                        finding_count, no_op_count, dry_run, safe_error, range_start,
                        range_end, examined_windows, evaluated_windows, skipped_windows,
                        no_op_windows, finding_occurrences, new_findings, updated_findings,
                        blocked_reason, error_class, safe_error_message, parent_run_id
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, NULL,
                        0, 0, 0, 0, 0, 0, NULL, ?, ?, 0, 0, 0, 0, 0, 0, 0,
                        NULL, NULL, NULL, ?
                    )
                    """,
                    (
                        run_id,
                        dataset_kind,
                        profile,
                        policy.policy_id,
                        policy.policy_version,
                        policy.policy_hash,
                        policy.mode,
                        policy.mode,
                        run_mode,
                        model_identity,
                        model_record["model_version"] if model_record else None,
                        model_record["model_artifact_sha256"] if model_record else None,
                        started_at,
                        range_start.isoformat() if range_start is not None else None,
                        range_end.isoformat() if range_end is not None else None,
                        parent_run_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DetectionEngineError(
                    "detection run namespace already has an active running lease"
                ) from exc

    def _update_run_model(self, run_id: str, model_record: dict[str, Any]) -> None:
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_runs
                SET model_id = ?, model_version = ?, model_hash = ?
                WHERE detection_run_id = ?
                """,
                (
                    str(model_record["model_id"]),
                    str(model_record["model_version"]),
                    str(model_record["model_artifact_sha256"]),
                    run_id,
                ),
            )

    def _block_run(self, run_id: str, *, reason: str, error_class: str) -> None:
        completed_at = datetime.now(UTC).isoformat()
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_runs
                SET status = 'blocked', completed_at = ?, blocked_reason = ?,
                    error_class = ?, safe_error_message = ?, safe_error = ?
                WHERE detection_run_id = ?
                """,
                (completed_at, reason, error_class, reason, reason, run_id),
            )

    def _record_run_error(
        self,
        run_id: str,
        *,
        safe_error: str,
        error_class: str,
    ) -> None:
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_runs
                SET error_class = ?, safe_error_message = ?, safe_error = ?
                WHERE detection_run_id = ?
                """,
                (error_class, safe_error, safe_error, run_id),
            )

    def _finish_run(
        self,
        run_id: str,
        *,
        status: Literal["success", "partial", "failed"],
        safe_error: str | None,
        error_class: str | None,
    ) -> None:
        completed_at = datetime.now(UTC).isoformat()
        with self.storage.connect() as conn:
            conn.execute(
                """
                UPDATE detection_runs
                SET status = ?, completed_at = ?, error_class = ?,
                    safe_error_message = ?, safe_error = ?
                WHERE detection_run_id = ?
                """,
                (status, completed_at, error_class, safe_error, safe_error, run_id),
            )

    def _run_result(
        self,
        run_id: str,
        policy: DetectionPolicy,
        dataset_kind: str,
        model_record: dict[str, Any] | None,
        dry_run: bool,
    ) -> dict[str, Any]:
        if dry_run:
            result = DetectionRunResult(
                detection_run_id=None,
                status="dry_run",
                dataset_kind=cast(Literal["synthetic", "real"], dataset_kind),
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_hash=policy.policy_hash,
                mode=policy.mode,
                model_id=str(model_record["model_id"]) if model_record else None,
                window_count=0,
                examined_count=0,
                evaluated_count=0,
                skipped_count=0,
                finding_count=0,
                no_op_count=0,
                dry_run=True,
            )
            return result.model_dump(mode="json")
        with self.storage.connect() as conn:
            row = conn.execute(
                "SELECT * FROM detection_runs WHERE detection_run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise DetectionEngineError("detection run audit row was not created")
        result = DetectionRunResult(
            detection_run_id=run_id,
            status=cast(
                Literal["success", "partial", "failed", "blocked", "dry_run"],
                str(row["status"]),
            ),
            dataset_kind=cast(Literal["synthetic", "real"], str(row["dataset_kind"])),
            policy_id=str(row["policy_id"]),
            policy_version=str(row["policy_version"]),
            policy_hash=str(row["policy_hash"]),
            mode=cast(Literal["hybrid", "rules_only", "model_only"], str(row["mode"])),
            model_id=(
                None
                if row["model_id"] in {None, MODEL_ID_SENTINEL}
                else str(row["model_id"])
            ),
            window_count=int(row["window_count"]),
            examined_count=int(row["examined_windows"]),
            evaluated_count=int(row["evaluated_windows"]),
            skipped_count=int(row["skipped_windows"]),
            finding_count=int(row["finding_count"]),
            new_findings=int(row["new_findings"]),
            updated_findings=int(row["updated_findings"]),
            finding_occurrences=int(row["finding_occurrences"]),
            no_op_count=int(row["no_op_windows"]),
            dry_run=bool(row["dry_run"]),
            blocked_reason=row["blocked_reason"],
            safe_error=row["safe_error_message"] or row["safe_error"],
        )
        return result.model_dump(mode="json")

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
        return self._suppression_for(detection_input, signals) is not None

    def _suppression_for(
        self,
        detection_input: DetectionInput,
        signals: list[DetectionSignal],
        *,
        decision: DetectionDecision | None = None,
        model_record: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
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
                return dict(row)
            if (
                scope == "signal_for_dataset_kind"
                and row["dataset_kind"] == detection_input.dataset_kind
                and row["signal_id"] in signal_ids
            ):
                return dict(row)
            if (
                scope == "finding_fingerprint"
                and decision is not None
                and row["finding_fingerprint"]
                == self._fingerprint(detection_input, decision, model_record)
            ):
                return dict(row)
        return None

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

    def _fingerprint(
        self,
        detection_input: DetectionInput,
        decision: DetectionDecision,
        model_record: dict[str, Any] | None = None,
    ) -> str:
        model_namespace = (
            f"{model_record['family']}:{model_record['model_version']}"
            if model_record is not None
            else MODEL_ID_SENTINEL
        )
        return hashlib.sha256(
            json.dumps(
                {
                    "strategy": "finding-fingerprint-v2",
                    "dataset_kind": detection_input.dataset_kind,
                    "profile_key": detection_input.profile_key,
                    "primary_signal": decision.primary_signal_id,
                    "matched_rule_ids": sorted(
                        signal_id
                        for signal_id in decision.matched_signal_ids
                        if not signal_id.startswith("model-")
                    ),
                    "policy_id": decision.policy_id,
                    "policy_version": decision.policy_version,
                    "policy_hash": decision.policy_hash,
                    "model_namespace": model_namespace,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]

    def _profile_key_for_window(self, window: dict[str, Any]) -> str:
        return profile_key({"user_id": str(window["user_id"]), "host_id": str(window["host_id"])})

    def _verify_registered_snapshot(self, dataset_id: str) -> None:
        verification = DatasetSnapshotService(self.storage, self.data_dir).verify(dataset_id)
        if not verification.get("verified"):
            raise DetectionEngineError("registered dataset snapshot failed verification")

    def _policy_row(self, row: Any) -> dict[str, Any]:
        verified = load_policy(dict(row))
        payload = dict(row)
        payload["policy"] = verified.model_dump(mode="json")
        payload.pop("policy_json")
        payload["active"] = bool(payload["active"])
        return payload

    def _policy_from_public(self, payload: dict[str, Any]) -> DetectionPolicy:
        policy = dict(payload["policy"])
        policy["created_at"] = datetime.fromisoformat(str(policy["created_at"]))
        policy["rules"] = tuple(parse_rule(item) for item in policy["rules"])
        policy["quality_gate"] = tuple(policy["quality_gate"])
        policy["risk_thresholds"] = RiskThresholdConfig(**policy["risk_thresholds"])
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
