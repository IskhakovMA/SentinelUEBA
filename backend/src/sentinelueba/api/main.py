from __future__ import annotations

from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

import anyio
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

from sentinelueba import __version__
from sentinelueba.api.schemas import (
    AnomalyListResponse,
    ApiResponse,
    CollectionStartRequest,
    ConfirmRequest,
    DatasetKindRequest,
    DetectionBackfillRequest,
    DetectionPolicyActivateRequest,
    DetectionRunRequest,
    DetectionWorkerRunRequest,
    DetectionWorkerStartRequest,
    DetectionWorkerStopRequest,
    FindingTransitionRequest,
    MLCompareRequest,
    MLConfirmRequest,
    MLDriftRequest,
    MLEvaluateRequest,
    MLScoreRequest,
    MLTrainRequest,
    RetentionApplyRequest,
    SeedRequest,
    SuppressionCreateRequest,
    TrainingEligibilityRequest,
)
from sentinelueba.config import get_settings
from sentinelueba.detection.worker_manager import (
    DetectionWorkerAlreadyRunningError,
    get_detection_worker_manager,
)
from sentinelueba.runtime.build_info import get_build_info
from sentinelueba.runtime.control import CONTROL_HEADER
from sentinelueba.runtime.installation import verify_installation
from sentinelueba.runtime.paths import resolve_runtime_paths
from sentinelueba.runtime.state import get_runtime_context
from sentinelueba.services.pipeline import DemoPipeline


def parse_api_datetime(value: str | None) -> Any:
    if value is None:
        return None
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))

app = FastAPI(title="SentinelUEBA API", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
TOKEN_EXEMPT_PATHS = {"/runtime/bootstrap"}


@app.middleware("http")
async def runtime_security(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if request.scope["path"].startswith("/api/"):
        request.scope["path"] = request.scope["path"][4:]
    context = get_runtime_context()
    if context.mode in {"desktop", "service"}:
        host = request.headers.get("host", "")
        allowed_hosts = {"localhost", "127.0.0.1"}
        if context.port is not None:
            allowed_hosts.update({f"localhost:{context.port}", f"127.0.0.1:{context.port}"})
        if host not in allowed_hosts:
            return JSONResponse({"detail": "host header is not allowed"}, status_code=400)
        origin = request.headers.get("origin")
        if origin and origin not in {
            f"http://localhost:{context.port}",
            f"http://127.0.0.1:{context.port}",
        }:
            return JSONResponse({"detail": "origin is not allowed"}, status_code=403)
    path = str(request.scope["path"])
    if (
        request.method in MUTATING_METHODS
        and context.require_token
        and path not in TOKEN_EXEMPT_PATHS
        and request.headers.get(CONTROL_HEADER) != context.control_token
    ):
        return JSONResponse({"detail": "control token is required"}, status_code=403)
    return await call_next(request)


def pipeline() -> DemoPipeline:
    return DemoPipeline(get_settings())


@app.on_event("shutdown")
def shutdown_workers() -> None:
    settings = get_settings()
    get_detection_worker_manager().shutdown_process(
        database_path=settings.database_path,
        data_dir=settings.data_dir,
        model_dir=settings.model_dir,
    )


async def run_blocking(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


@app.get("/health", response_model=ApiResponse)
async def health() -> ApiResponse:
    return ApiResponse(data={"ok": True})


@app.get("/health/live", response_model=ApiResponse)
async def health_live() -> ApiResponse:
    return ApiResponse(data={"ok": True})


@app.get("/health/ready", response_model=ApiResponse)
async def health_ready() -> ApiResponse:
    context = get_runtime_context()
    ready = (
        context.state in {"ready", "degraded"}
        and (context.mode == "development" or context.frontend_ready)
        and (context.mode == "development" or context.database_ready)
        and (context.mode == "development" or context.data_root_writable)
    )
    return ApiResponse(
        data={
            "ready": ready,
            "state": context.state,
            "mode": context.mode,
            "frontend_ready": context.frontend_ready or context.mode == "development",
            "database_ready": context.database_ready or context.mode == "development",
            "data_root_writable": context.data_root_writable or context.mode == "development",
        }
    )


@app.get("/runtime/status", response_model=ApiResponse)
async def runtime_status() -> ApiResponse:
    context = get_runtime_context()
    return ApiResponse(
        data={
            "state": context.state,
            "mode": context.mode,
            "port": context.port,
            "version": __version__,
        }
    )


@app.get("/runtime/build", response_model=ApiResponse)
async def runtime_build() -> ApiResponse:
    return ApiResponse(data=get_build_info().safe_dict())


@app.get("/runtime/bootstrap", response_model=ApiResponse)
async def runtime_bootstrap() -> ApiResponse:
    context = get_runtime_context()
    return ApiResponse(
        data={
            "version": __version__,
            "mode": context.mode,
            "service_mode": context.mode == "service",
            "control_token": context.control_token,
        }
    )


@app.post("/runtime/shutdown", response_model=ApiResponse)
async def runtime_shutdown(request: ConfirmRequest) -> ApiResponse:
    context = get_runtime_context()
    if context.mode == "service" or context.shutdown_disabled:
        raise HTTPException(status_code=409, detail="runtime shutdown is disabled in service mode")
    if not request.confirm:
        raise HTTPException(status_code=400, detail="runtime shutdown requires confirm=true")
    from sentinelueba.runtime.supervisor import request_shutdown

    request_shutdown()
    return ApiResponse(data={"state": "stopping"})


@app.get("/runtime/verify-installation", response_model=ApiResponse)
async def runtime_verify_installation() -> ApiResponse:
    return ApiResponse(data=verify_installation(resolve_runtime_paths().package_dir).safe_dict())


@app.get("/status", response_model=ApiResponse)
async def status() -> ApiResponse:
    return ApiResponse(data=_safe_public_payload(pipeline().status()))


@app.post("/demo/generate", response_model=ApiResponse)
async def generate_demo(request: SeedRequest) -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().generate_demo_data, request.seed))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/model/train", response_model=ApiResponse)
async def train_model(request: SeedRequest) -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().train, request.seed))
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/model/train/{dataset_kind}", response_model=ApiResponse)
async def train_model_for_dataset(dataset_kind: str, request: SeedRequest) -> ApiResponse:
    if dataset_kind not in {"synthetic", "real"}:
        raise HTTPException(status_code=400, detail="dataset_kind must be synthetic or real")
    try:
        return ApiResponse(data=await run_blocking(pipeline().train, request.seed, dataset_kind))
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/model", response_model=ApiResponse)
async def get_model() -> ApiResponse:
    model = pipeline().status().get("model", {})
    if not isinstance(model, dict):
        model = {}
    return ApiResponse(data=model)


@app.get("/ml/status", response_model=ApiResponse)
async def ml_status() -> ApiResponse:
    return ApiResponse(data=pipeline().ml_status())


@app.post("/ml/train", response_model=ApiResponse)
async def ml_train(request: MLTrainRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_train,
                dataset_kind=request.dataset_kind,
                dataset_id=request.dataset_id,
                families=request.families,
                seed=request.seed,
                target_fpr=request.target_fpr,
                autoencoder_config=(
                    request.autoencoder.model_dump() if request.autoencoder else None
                ),
                isolation_forest_config=(
                    request.isolation_forest.model_dump() if request.isolation_forest else None
                ),
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/ml/training-runs", response_model=ApiResponse)
async def ml_training_runs() -> ApiResponse:
    return ApiResponse(data={"training_runs": pipeline().ml_training_runs()})


@app.get("/ml/training-runs/{training_run_id}", response_model=ApiResponse)
async def ml_training_run(training_run_id: str) -> ApiResponse:
    run = pipeline().ml_training_run(training_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="training run not found")
    return ApiResponse(data=run)


@app.get("/ml/models", response_model=ApiResponse)
async def ml_models() -> ApiResponse:
    return ApiResponse(data={"models": pipeline().ml_models()})


@app.get("/ml/models/{model_id}", response_model=ApiResponse)
async def ml_model(model_id: str) -> ApiResponse:
    try:
        return ApiResponse(data=pipeline().ml_model(model_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/ml/models/{model_id}/verify", response_model=ApiResponse)
async def ml_verify_model(model_id: str) -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().ml_verify_model, model_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/ml/models/{model_id}/recommend", response_model=ApiResponse)
async def ml_recommend_model(model_id: str, request: MLConfirmRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_recommend_model,
                model_id,
                confirm=request.confirm,
                reason=request.reason,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/ml/models/{model_id}/promote", response_model=ApiResponse)
async def ml_promote_model(model_id: str, request: MLConfirmRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_promote_model,
                model_id,
                confirm=request.confirm,
                reason=request.reason,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/ml/models/{model_id}/retire", response_model=ApiResponse)
async def ml_retire_model(model_id: str, request: MLConfirmRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_retire_model,
                model_id,
                confirm=request.confirm,
                reason=request.reason,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/ml/models/{model_id}/rollback", response_model=ApiResponse)
async def ml_rollback_model(model_id: str, request: MLConfirmRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_rollback_model,
                model_id,
                confirm=request.confirm,
                reason=request.reason,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/ml/models/compare", response_model=ApiResponse)
async def ml_compare(request: MLCompareRequest) -> ApiResponse:
    return ApiResponse(data=pipeline().ml_compare_models(request.model_ids))


@app.post("/ml/evaluate", response_model=ApiResponse)
async def ml_evaluate(request: MLEvaluateRequest) -> ApiResponse:
    return ApiResponse(data=pipeline().ml_evaluate_model(request.model_id))


@app.post("/ml/score", response_model=ApiResponse)
async def ml_score(request: MLScoreRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_score,
                dataset_id=request.dataset_id,
                model_id=request.model_id,
                dataset_kind=request.dataset_kind,
                batch_size=request.batch_size,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/ml/scoring-runs", response_model=ApiResponse)
async def ml_scoring_runs() -> ApiResponse:
    return ApiResponse(data={"scoring_runs": pipeline().ml_scoring_runs()})


@app.get("/ml/scoring-runs/{scoring_run_id}", response_model=ApiResponse)
async def ml_scoring_run(scoring_run_id: str) -> ApiResponse:
    run = pipeline().ml_scoring_run(scoring_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="scoring run not found")
    return ApiResponse(data=run)


@app.post("/ml/drift", response_model=ApiResponse)
async def ml_drift(request: MLDriftRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().ml_drift,
                model_id=request.model_id,
                dataset_id=request.dataset_id,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/detection/status", response_model=ApiResponse)
async def detection_status() -> ApiResponse:
    return ApiResponse(data=pipeline().detection_status())


@app.get("/detection/policies", response_model=ApiResponse)
async def detection_policies() -> ApiResponse:
    return ApiResponse(data={"policies": pipeline().detection_policies()})


@app.get("/detection/policies/{policy_id}", response_model=ApiResponse)
async def detection_policy(policy_id: str, policy_version: str | None = None) -> ApiResponse:
    try:
        return ApiResponse(data=pipeline().detection_policy(policy_id, policy_version))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/detection/policies/{policy_id}/activate", response_model=ApiResponse)
async def detection_policy_activate(
    policy_id: str,
    request: DetectionPolicyActivateRequest,
) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_activate_policy,
                policy_id,
                request.policy_version,
                confirm=request.confirm,
                reason=request.reason,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/detection/rules", response_model=ApiResponse)
async def detection_rules() -> ApiResponse:
    return ApiResponse(data={"rules": pipeline().detection_rules()})


@app.post("/detection/run-once", response_model=ApiResponse)
async def detection_run_once(request: DetectionRunRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_run_once,
                dataset_kind=request.dataset_kind,
                profile=request.profile,
                policy_id=request.policy_id,
                policy_version=request.policy_version,
                model_id=request.model_id,
                start=parse_api_datetime(request.start),
                end=parse_api_datetime(request.end),
                batch_size=request.batch_size,
                max_windows=request.max_windows,
                rules_only=request.rules_only,
                dry_run=request.dry_run,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/detection/backfill", response_model=ApiResponse)
async def detection_backfill(request: DetectionBackfillRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_backfill,
                dataset_kind=request.dataset_kind,
                policy_id=request.policy_id,
                policy_version=request.policy_version,
                model_id=request.model_id,
                start=parse_api_datetime(request.start),
                end=parse_api_datetime(request.end),
                registered_dataset_id=request.dataset_id,
                confirm=request.confirm,
                advance_watermark=request.advance_watermark,
                confirm_advance_watermark=request.confirm_advance_watermark,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/detection/runs", response_model=ApiResponse)
async def detection_runs() -> ApiResponse:
    return ApiResponse(data={"detection_runs": pipeline().detection_runs()})


@app.get("/detection/runs/{detection_run_id}", response_model=ApiResponse)
async def detection_run(detection_run_id: str) -> ApiResponse:
    run = pipeline().detection_run(detection_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="detection run not found")
    return ApiResponse(data=run)


@app.get("/detection/findings", response_model=ApiResponse)
async def detection_findings(
    status: str | None = None,
    dataset_kind: str | None = None,
) -> ApiResponse:
    return ApiResponse(
        data={"findings": pipeline().detection_findings(status=status, dataset_kind=dataset_kind)}
    )


@app.get("/detection/findings/{finding_id}", response_model=ApiResponse)
async def detection_finding(finding_id: str) -> ApiResponse:
    finding = pipeline().detection_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return ApiResponse(data=finding)


async def transition_finding_api(
    finding_id: str,
    to_status: str,
    request: FindingTransitionRequest,
) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_transition_finding,
                finding_id,
                to_status=to_status,
                reason=request.reason,
                confirm=request.confirm,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/detection/findings/{finding_id}/acknowledge", response_model=ApiResponse)
async def detection_finding_acknowledge(
    finding_id: str,
    request: FindingTransitionRequest,
) -> ApiResponse:
    return await transition_finding_api(finding_id, "acknowledged", request)


@app.post("/detection/findings/{finding_id}/investigate", response_model=ApiResponse)
async def detection_finding_investigate(
    finding_id: str,
    request: FindingTransitionRequest,
) -> ApiResponse:
    return await transition_finding_api(finding_id, "investigating", request)


@app.post("/detection/findings/{finding_id}/resolve", response_model=ApiResponse)
async def detection_finding_resolve(
    finding_id: str,
    request: FindingTransitionRequest,
) -> ApiResponse:
    return await transition_finding_api(finding_id, "resolved", request)


@app.post("/detection/findings/{finding_id}/false-positive", response_model=ApiResponse)
async def detection_finding_false_positive(
    finding_id: str,
    request: FindingTransitionRequest,
) -> ApiResponse:
    return await transition_finding_api(finding_id, "false_positive", request)


@app.get("/detection/suppressions", response_model=ApiResponse)
async def detection_suppressions() -> ApiResponse:
    return ApiResponse(data={"suppressions": pipeline().detection_suppressions()})


@app.post("/detection/suppressions", response_model=ApiResponse)
async def detection_suppression_create(request: SuppressionCreateRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_create_suppression,
                scope=request.scope,
                reason=request.reason,
                ttl_minutes=request.ttl_minutes,
                dataset_kind=request.dataset_kind,
                profile_key=request.profile_key,
                finding_fingerprint=request.finding_fingerprint,
                signal_id=request.signal_id,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/detection/suppressions/{suppression_id}/revoke", response_model=ApiResponse)
async def detection_suppression_revoke(
    suppression_id: str,
    request: ConfirmRequest | None = None,
) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_revoke_suppression,
                suppression_id,
                confirm=request.confirm if request is not None else False,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/detection/worker/status", response_model=ApiResponse)
async def detection_worker_status(dataset_kind: str = "synthetic") -> ApiResponse:
    if dataset_kind not in {"synthetic", "real"}:
        raise HTTPException(status_code=400, detail="dataset_kind must be synthetic or real")
    return ApiResponse(data=pipeline().detection_worker_status(dataset_kind=dataset_kind))


@app.post("/detection/worker/start", response_model=ApiResponse)
async def detection_worker_start(request: DetectionWorkerStartRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_worker_start,
                dataset_kind=request.dataset_kind,
                interval_seconds=request.interval_seconds,
                max_windows=request.max_windows,
            )
        )
    except DetectionWorkerAlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        detail = str(exc)
        status_code = 409 if "active detection worker lease" in detail else 400
        raise HTTPException(status_code=status_code, detail=detail) from exc


@app.post("/detection/worker/stop", response_model=ApiResponse)
async def detection_worker_stop(request: DetectionWorkerStopRequest | None = None) -> ApiResponse:
    request = request or DetectionWorkerStopRequest()
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_worker_stop,
                dataset_kind=request.dataset_kind,
                confirm=request.confirm,
            )
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        detail = str(exc)
        status_code = 400 if "confirm=true" in detail else 409
        raise HTTPException(status_code=status_code, detail=detail) from exc


@app.post("/detection/worker/run-foreground", response_model=ApiResponse)
async def detection_worker_run_foreground(request: DetectionWorkerRunRequest) -> ApiResponse:
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().detection_worker_run_foreground,
                dataset_kind=request.dataset_kind,
                max_windows=request.max_windows,
                interval_seconds=request.interval_seconds,
                single_cycle=request.single_cycle,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/detect", response_model=ApiResponse)
async def detect() -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().detect))
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/collectors/capabilities", response_model=ApiResponse)
async def collector_capabilities() -> ApiResponse:
    return ApiResponse(data={"collectors": pipeline().collector_capabilities()})


@app.get("/collectors/status", response_model=ApiResponse)
async def collector_status() -> ApiResponse:
    return ApiResponse(data=pipeline().collection_status())


@app.post("/collection/start", response_model=ApiResponse)
async def start_collection(request: CollectionStartRequest) -> ApiResponse:
    if get_runtime_context().mode == "service":
        raise HTTPException(
            status_code=409,
            detail="user-session telemetry collection is disabled in service mode",
        )
    try:
        return ApiResponse(
            data=await run_blocking(
                pipeline().start_collection,
                request.duration_seconds,
                request.interval_seconds,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/collection/stop", response_model=ApiResponse)
async def stop_collection() -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().stop_collection))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/collection/sessions", response_model=ApiResponse)
async def collection_sessions() -> ApiResponse:
    return ApiResponse(data={"sessions": pipeline().collection_sessions()})


@app.get("/collection/progress", response_model=ApiResponse)
async def collection_progress() -> ApiResponse:
    return ApiResponse(data=pipeline().collection_progress())


@app.get("/events/summary", response_model=ApiResponse)
async def event_summary() -> ApiResponse:
    return ApiResponse(data=pipeline().event_summary())


@app.post("/training/eligibility", response_model=ApiResponse)
async def training_eligibility(request: TrainingEligibilityRequest) -> ApiResponse:
    return ApiResponse(data=pipeline().training_eligibility(request.dataset_kind))


@app.get("/data-quality", response_model=ApiResponse)
async def data_quality() -> ApiResponse:
    return ApiResponse(data=await run_blocking(pipeline().data_quality))


@app.post("/features/materialize", response_model=ApiResponse)
async def materialize_features(request: DatasetKindRequest) -> ApiResponse:
    return ApiResponse(
        data=await run_blocking(pipeline().materialize_features, request.dataset_kind)
    )


@app.post("/features/rebuild", response_model=ApiResponse)
async def rebuild_features(request: DatasetKindRequest) -> ApiResponse:
    return ApiResponse(data=await run_blocking(pipeline().rebuild_features, request.dataset_kind))


@app.get("/features/status", response_model=ApiResponse)
async def features_status() -> ApiResponse:
    return ApiResponse(data=pipeline().features_status())


@app.get("/features/windows", response_model=ApiResponse)
async def feature_window_summary() -> ApiResponse:
    return ApiResponse(data={"windows": pipeline().features_status().get("windows", {})})


@app.post("/datasets", response_model=ApiResponse)
async def create_dataset(request: DatasetKindRequest) -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().create_dataset, request.dataset_kind))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/datasets", response_model=ApiResponse)
async def list_datasets(dataset_kind: str | None = None) -> ApiResponse:
    if dataset_kind is not None and dataset_kind not in {"synthetic", "real"}:
        raise HTTPException(status_code=400, detail="dataset_kind must be synthetic or real")
    return ApiResponse(data=pipeline().list_datasets(dataset_kind))


@app.get("/datasets/{dataset_id}", response_model=ApiResponse)
async def show_dataset(dataset_id: str) -> ApiResponse:
    try:
        return ApiResponse(data=pipeline().show_dataset(dataset_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/datasets/{dataset_id}/verify", response_model=ApiResponse)
async def verify_dataset(dataset_id: str) -> ApiResponse:
    try:
        return ApiResponse(data=await run_blocking(pipeline().verify_dataset, dataset_id))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/readiness/{dataset_kind}", response_model=ApiResponse)
async def readiness(dataset_kind: str) -> ApiResponse:
    if dataset_kind not in {"synthetic", "real"}:
        raise HTTPException(status_code=400, detail="dataset_kind must be synthetic or real")
    return ApiResponse(data=pipeline().training_eligibility(dataset_kind))


@app.get("/quarantine/summary", response_model=ApiResponse)
async def quarantine_summary() -> ApiResponse:
    return ApiResponse(data=pipeline().quarantine_summary())


@app.get("/retention/preview", response_model=ApiResponse)
async def retention_preview() -> ApiResponse:
    return ApiResponse(data=pipeline().retention_preview())


@app.post("/retention/apply", response_model=ApiResponse)
async def retention_apply(request: RetentionApplyRequest) -> ApiResponse:
    if not request.confirm:
        raise HTTPException(status_code=400, detail="retention apply requires confirm=true")
    return ApiResponse(data=await run_blocking(pipeline().retention_apply))


@app.get("/anomalies", response_model=AnomalyListResponse)
async def list_anomalies() -> AnomalyListResponse:
    return AnomalyListResponse(anomalies=pipeline().anomalies())


@app.get("/anomalies/{index}", response_model=ApiResponse)
async def anomaly_details(index: int) -> ApiResponse:
    anomalies = pipeline().anomalies()
    if index < 0 or index >= len(anomalies):
        raise HTTPException(status_code=404, detail="anomaly not found")
    return ApiResponse(data=anomalies[index])


@app.get("/summary", response_model=ApiResponse)
async def summary() -> ApiResponse:
    return ApiResponse(data=pipeline().summary())


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str) -> Response:
    if full_path.startswith("api/"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    from sentinelueba.runtime.supervisor import frontend_dir

    root = frontend_dir(resolve_runtime_paths())
    target = (root / full_path).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return JSONResponse({"detail": "not found"}, status_code=404)
    if target.is_file():
        return FileResponse(target)
    index = root / "index.html"
    if index.is_file():
        return FileResponse(index)
    return JSONResponse({"detail": "frontend assets are unavailable"}, status_code=503)


def _safe_public_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("<runtime-managed>" if key.endswith("_path") else _safe_public_payload(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe_public_payload(item) for item in value]
    return value
