"""HTTP API：批次提交、指标查询、单指标获取、状态查看。"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from app.exceptions import BatchRejected
from app.service import AggregatorService
from app.store import IndicatorStore

router = APIRouter()
_service: AggregatorService | None = None


def get_service() -> AggregatorService:
    global _service
    if _service is None:
        _service = AggregatorService(IndicatorStore())
    return _service


@router.post("/api/v1/batches")
async def submit_batch(request: Request) -> JSONResponse:
    # 不用 Pydantic 模型：原始 JSON 缺字段/类型错误时要由服务层给出可区分原因。
    try:
        payload = await request.json()
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "malformed_batch", "reason": "malformed_batch",
                     "detail": f"请求体不是合法 JSON: {exc}"},
        )
    service = get_service()
    try:
        result = service.submit_batch(payload)
    except BatchRejected as exc:
        # empty_batch / malformed_batch 可区分；不产生任何写入。
        status = 404 if exc.reason == "duplicate_batch" else 400
        return JSONResponse(
            status_code=status,
            content={"error": exc.reason, "reason": exc.reason, "detail": exc.detail},
        )
    return JSONResponse(status_code=200 if result.replayed else 201, content=result.to_dict())


@router.get("/api/v1/indicators")
async def list_indicators(
    ioc_type: str | None = None,
    source: str | None = None,
    include_inactive: bool = False,
) -> dict:
    service = get_service()
    items = service.query(
        ioc_type=ioc_type, source=source, include_inactive=include_inactive
    )
    return {"count": len(items), "indicators": items}


@router.get("/api/v1/indicators/{indicator:path}")
async def get_indicator(indicator: str) -> JSONResponse:
    service = get_service()
    item = service.get(indicator)
    if item is None:
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "detail": f"指标不存在: {indicator}"},
        )
    return JSONResponse(content=item)


@router.get("/api/v1/stats")
async def stats() -> dict:
    return get_service().store.stats()


def create_app(service: AggregatorService | None = None) -> FastAPI:
    global _service
    application = FastAPI(title="threat-ioc-aggregator", version="0.1.0")
    _service = service or AggregatorService(IndicatorStore())
    application.include_router(router)
    return application
