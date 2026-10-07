"""FastAPI HTTP 接口：批次提交、指标查询、来源追溯。

进程内持有一个 ThreatIocService 单例；启动时从 data/feeds 加载本地情报，
模拟多个来源的推送。
"""

from __future__ import annotations

from pathlib import Path
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from app.ingestion import BatchRejected
from app.logging_utils import get_logger
from app.models import BatchRejectReason
from app.service import ThreatIocService
from app.store import RejudgeFailed
from app.weights import WeightConfigError

logger = get_logger(__name__)

_DEFAULT_FEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"


class BatchSubmitRequest(BaseModel):
    """批次提交请求体。

    entries 刻意接受任意 JSON：条目级非法（非对象、缺字段等）必须进入
    服务层逐条判定，返回可区分的条目级拒绝原因，而不是被 schema 一刀切。
    """

    batch_id: str | None = Field(default=None, description="批次幂等键")
    source_hint: str | None = Field(default=None, description="来源兜底标识")
    entries: Any = Field(default=None, description="条目列表，元素为任意 JSON")


class WeightUpdateRequest(BaseModel):
    """权重配置更新请求体。"""

    weights: Any = Field(default=None, description="{来源: 权重} 映射")
    note: str = Field(default="", description="变更说明（进入审计历史）")
    rejudge: bool = Field(default=True, description="是否立即对存量指标重判")


def _ioc_to_dict(ioc) -> dict[str, Any]:
    return {
        "indicator": ioc.indicator,
        "ioc_type": ioc.ioc_type.value,
        "verdict": ioc.verdict.value,
        "confidence": ioc.confidence,
        "status": ioc.status.value,
        "sources": sorted(ioc.sources),
        "source_detail": {
            s: {
                "confidence": o.confidence,
                "verdict": o.verdict.value,
                "first_seen": o.first_seen,
                "last_seen": o.last_seen,
                "expires_at": o.expires_at,
                "revoked": o.revoked,
                "tags": sorted(o.tags),
            }
            for s, o in ioc.sources.items()
        },
        "tags": sorted(ioc.tags),
        "first_seen": ioc.first_seen,
        "last_seen": ioc.last_seen,
        "expires_at": ioc.expires_at,
        "revoked": ioc.revoked,
        "updated_at": ioc.updated_at,
        "weight_version": ioc.weight_version,
        "history": [
            {"at": h.at, "batch_id": h.batch_id, "source": h.source,
             "action": h.action, "detail": h.detail}
            for h in ioc.history
        ],
    }


def _result_to_dict(result) -> dict[str, Any]:
    return {
        "batch_id": result.batch_id,
        "accepted": result.accepted,
        "updated": result.updated,
        "rejected": result.rejected,
        "degraded": result.degraded,
        "replayed": result.replayed,
        "indicators": list(result.indicators),
        "rejected_entries": [
            {"index": r.index, "reason": r.reason.value,
             "detail": r.detail, "raw": r.raw}
            for r in result.rejected_entries
        ],
        "degraded_entries": [
            {"index": dg.index, "indicator": dg.indicator,
             "source": dg.source,
             "reasons": [r.value for r in dg.reasons],
             "detail": dg.detail}
            for dg in result.degraded_entries
        ],
    }


def create_app(feeds_dir: str | Path | None = None) -> FastAPI:
    """构造 FastAPI 应用并预加载本地情报。"""

    service = ThreatIocService()
    feed_reports: list = []

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        target = Path(feeds_dir) if feeds_dir else _DEFAULT_FEEDS_DIR
        if target.exists():
            feed_reports.extend(service.load_local_feeds(str(target)))
            logger.info("启动加载本地情报完成：%d 份文件", len(feed_reports))
        yield

    app = FastAPI(
        title="威胁情报 IOC 本地汇聚与判定服务",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.service = service
    app.state.feed_reports = feed_reports

    @app.get("/")
    def read_root() -> dict[str, str]:
        return {"service": "threat-ioc-aggregator", "status": "running"}

    @app.post("/api/v1/batches")
    def submit_batch(req: BatchSubmitRequest) -> dict[str, Any]:
        """提交一个情报批次（并发安全、幂等、原子写入）。"""

        try:
            result = app.state.service.submit_batch(
                req.batch_id, req.entries, source_hint=req.source_hint
            )
        except BatchRejected as exc:
            # 422 语义：请求批次结构非法，未写入任何数据
            raise HTTPException(
                status_code=422,
                detail={
                    "code": exc.reason.value,
                    "reason": exc.reason.name,
                    "message": exc.detail,
                },
            ) from exc
        return _result_to_dict(result)

    @app.get("/api/v1/iocs")
    def list_iocs(
        ioc_type: str | None = Query(default=None, description="按类型过滤"),
    ) -> dict[str, Any]:
        """列出当前可见指标；过期/撤回不会出现。"""

        from app.models import IocType

        type_filter = None
        if ioc_type is not None:
            try:
                type_filter = IocType(ioc_type)
            except ValueError as exc:
                raise HTTPException(
                    status_code=422,
                    detail={"code": "unsupported_ioc_type",
                            "message": f"未知 ioc_type: {ioc_type}"},
                ) from exc
        items = app.state.service.list_active(ioc_type=type_filter)
        return {"count": len(items), "items": [_ioc_to_dict(i) for i in items]}

    @app.get("/api/v1/iocs/{indicator:path}/explain")
    def explain_ioc(indicator: str) -> dict[str, Any]:
        """返回指标置信度与判定结论的人类可读依据（含来源权重贡献）。"""

        explanation = app.state.service.explain(indicator)
        if explanation is None:
            raise HTTPException(status_code=404, detail="indicator not found")
        return {
            "indicator": explanation.indicator,
            "status": explanation.status,
            "visible": explanation.visible,
            "verdict": explanation.verdict,
            "confidence": explanation.confidence,
            "confidence_basis": explanation.confidence_basis,
            "verdict_basis": explanation.verdict_basis,
            "sources": list(explanation.sources),
            "weight_version": explanation.weight_version,
            "contributions": list(explanation.contributions),
        }

    @app.get("/api/v1/weights")
    def get_weights() -> dict[str, Any]:
        """查看当前生效的来源权重配置。"""

        return app.state.service.current_weights()

    @app.get("/api/v1/weights/history")
    def get_weight_history() -> dict[str, Any]:
        """查看权重变更历史（什么时候被改成了什么）。"""

        return {"history": app.state.service.weight_history()}

    @app.put("/api/v1/weights")
    def put_weights(req: WeightUpdateRequest) -> dict[str, Any]:
        """发布新一版权重配置，默认立即对全量存量指标原子重判。"""

        try:
            return app.state.service.set_weights(
                req.weights, note=req.note, rejudge=req.rejudge
            )
        except WeightConfigError as exc:
            # 422：配置本身非法，校验阶段拒绝，权重与存量均无变更
            raise HTTPException(
                status_code=422,
                detail={"code": exc.reason, "message": exc.detail},
            ) from exc
        except RejudgeFailed as exc:
            # 500：配置合法但配套重判在提交前失败；事务已整体回滚，
            # 权重未发布、存量未改动，调用方可用同一份权重安全重试
            logger.exception("权重发布的配套重判失败，事务整体回滚")
            raise HTTPException(
                status_code=500,
                detail={
                    "code": "weight_publish_rejudge_failed",
                    "weight_version": exc.version,
                    "message": exc.detail,
                    "hint": "权重配置与存量指标均未变更，可使用同一份权重重试",
                },
            ) from exc

    @app.post("/api/v1/rejudge")
    def rejudge() -> dict[str, Any]:
        """按当前权重配置对全量存量指标重判（幂等，可安全重试）。"""

        try:
            return app.state.service.rejudge_all()
        except RejudgeFailed as exc:
            logger.exception("手动批量重判失败，存储零变更")
            raise HTTPException(
                status_code=500,
                detail={
                    "code": "rejudge_failed",
                    "weight_version": exc.version,
                    "message": exc.detail,
                },
            ) from exc


    @app.get("/api/v1/iocs/{indicator:path}")
    def get_ioc(indicator: str) -> dict[str, Any]:
        """查询单个指标（含过期/撤回完整记录与历史，来源可追溯）。"""

        ioc = app.state.service.query(indicator)
        if ioc is None:
            raise HTTPException(status_code=404, detail="indicator not found")
        return _ioc_to_dict(ioc)

    @app.get("/api/v1/feeds/report")
    def feed_report() -> dict[str, Any]:
        """查看启动时本地情报文件的加载/入库汇总。"""

        return {
            "reports": [
                {
                    "feed_path": r.feed_path,
                    "source": r.source,
                    "batch_id": r.batch_id,
                    "error": r.error,
                    "result": None if r.result is None
                    else _result_to_dict(r.result),
                }
                for r in app.state.feed_reports
            ]
        }

    return app
