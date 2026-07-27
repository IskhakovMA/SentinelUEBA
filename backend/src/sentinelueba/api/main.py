from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

import anyio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from sentinelueba.api.schemas import (
    AnomalyListResponse,
    ApiResponse,
    CollectionStartRequest,
    DatasetKindRequest,
    MLCompareRequest,
    MLConfirmRequest,
    MLDriftRequest,
    MLEvaluateRequest,
    MLScoreRequest,
    MLTrainRequest,
    RetentionApplyRequest,
    SeedRequest,
    TrainingEligibilityRequest,
)
from sentinelueba.config import get_settings
from sentinelueba.services.pipeline import DemoPipeline

app = FastAPI(title="SentinelUEBA API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def pipeline() -> DemoPipeline:
    return DemoPipeline(get_settings())


async def run_blocking(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


@app.get("/health", response_model=ApiResponse)
async def health() -> ApiResponse:
    return ApiResponse(data={"ok": True})


@app.get("/status", response_model=ApiResponse)
async def status() -> ApiResponse:
    return ApiResponse(data=pipeline().status())


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
