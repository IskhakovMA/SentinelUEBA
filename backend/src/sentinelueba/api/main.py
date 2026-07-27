from __future__ import annotations

from typing import Any

import anyio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from sentinelueba.api.schemas import (
    AnomalyListResponse,
    ApiResponse,
    CollectionStartRequest,
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


async def run_blocking(fn: Any, *args: Any) -> Any:
    return await anyio.to_thread.run_sync(fn, *args)


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
    return ApiResponse(data=await run_blocking(pipeline().stop_collection))


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
