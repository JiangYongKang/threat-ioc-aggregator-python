"""汇聚服务：批次校验、归一化与原子入库的编排层。"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime

from app.exceptions import BatchRejected
from app.models import (
    BatchRejectReason,
    BatchResult,
    DegradedEntry,
    RejectedEntry,
)
from app.normalizer import normalize_entry
from app.store import IndicatorStore

logger = logging.getLogger("ioc_aggregator")


class AggregatorService:
    def __init__(self, store: IndicatorStore | None = None) -> None:
        self.store = store or IndicatorStore()

    @staticmethod
    def _derive_batch_id(entries: list) -> str:
        """未显式提供 batch_id 时，按内容生成确定性 id（相同批次重放天然幂等）。"""
        canonical = json.dumps(entries, sort_keys=True, ensure_ascii=False, default=str)
        return "auto-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def submit_batch(self, payload: object) -> BatchResult:
        """提交一个情报批次（幂等）。

        payload 形如:
            {"batch_id": "...", "source": "可作为条目默认来源", "entries": [ {...}, ... ]}
        非法批次抛 BatchRejected（reason 可区分），归一化在入库前完成，
        因此非法批次不会污染已入库数据。
        """
        # ---- 批次级校验（任一不满足 -> 整批拒绝，零写入）----
        if not isinstance(payload, dict):
            raise BatchRejected(
                BatchRejectReason.MALFORMED_BATCH.value,
                f"批次负载必须是对象，实际为 {type(payload).__name__}",
            )

        batch_id = payload.get("batch_id")
        if batch_id is not None and not isinstance(batch_id, str):
            raise BatchRejected(
                BatchRejectReason.MALFORMED_BATCH.value, "batch_id 必须是字符串"
            )

        # 重放优先：只要 batch_id 已登记（即便重放请求缺 entries/为空），
        # 也原样返回首次结果，保证重复请求下结论一致。
        if isinstance(batch_id, str) and batch_id.strip():
            cached = self.store.get_batch_result(batch_id)
            if cached is not None:
                return cached

        entries = payload.get("entries")
        if entries is None:
            raise BatchRejected(
                BatchRejectReason.MALFORMED_BATCH.value, "缺少 entries 字段"
            )
        if not isinstance(entries, list):
            raise BatchRejected(
                BatchRejectReason.MALFORMED_BATCH.value,
                f"entries 必须是数组，实际为 {type(entries).__name__}",
            )
        if len(entries) == 0:
            raise BatchRejected(BatchRejectReason.EMPTY_BATCH.value, "entries 为空")

        if not batch_id or not batch_id.strip():
            batch_id = self._derive_batch_id(entries)
            # 内容派生 id 同样支持重放。
            cached = self.store.get_batch_result(batch_id)
            if cached is not None:
                return cached

        default_source = payload.get("source")
        if not isinstance(default_source, str) or not default_source.strip():
            default_source = "unknown"

        logger.info(
            "收到批次 batch_id=%s 条目数=%d 输入=%s",
            batch_id,
            len(entries),
            json.dumps(payload, ensure_ascii=False, default=str),
        )

        # ---- 逐条归一（先全部归一，再一次性原子应用）----
        observations = []
        rejected: list[RejectedEntry] = []
        degraded: list[DegradedEntry] = []
        for idx, raw in enumerate(entries):
            try:
                obs = normalize_entry(raw, default_source=default_source)
            except Exception as exc:  # EntryRejected 及其携带的可区分 reason
                reason = getattr(exc, "reason", "entry_error")
                detail = getattr(exc, "detail", str(exc))
                rejected.append(
                    RejectedEntry(index=idx, reason=reason, detail=detail, raw=raw if isinstance(raw, dict) else None)
                )
                logger.warning("条目被拒绝 index=%d reason=%s detail=%s raw=%s",
                               idx, reason, detail, raw)
                continue
            observations.append(obs)
            if obs.degrade_reasons:
                degraded.append(
                    DegradedEntry(
                        index=idx,
                        indicator=obs.indicator,
                        reasons=sorted(obs.degrade_reasons),
                        source=obs.source,
                    )
                )
                logger.info(
                    "条目降级入库 index=%d indicator=%s 判定依据=%s",
                    idx, obs.indicator, sorted(obs.degrade_reasons),
                )

        # 全部条目都无法归一 -> 视为整批失败，不写入任何内容。
        if not observations and rejected:
            reasons = sorted({r.reason for r in rejected})
            raise BatchRejected(
                BatchRejectReason.MALFORMED_BATCH.value,
                f"全部 {len(rejected)} 条均归一失败: {reasons}",
            )

        result = self.store.apply_batch(batch_id, observations, rejected, degraded)
        logger.info(
            "批次处理完成 batch_id=%s replayed=%s new=%d merged=%d rejected=%d degraded=%d",
            result.batch_id, result.replayed, result.accepted_new,
            result.merged, len(result.rejected), len(result.degraded),
        )
        return result

    def query(self, *, now: datetime | None = None, **kwargs) -> list[dict]:
        return [a.to_dict(now=now) for a in self.store.query(now=now, **kwargs)]

    def get(self, indicator: str, now: datetime | None = None) -> dict | None:
        agg = self.store.get(indicator)
        return agg.to_dict(now=now) if agg else None


__all__ = ["AggregatorService", "BatchRejected", "normalize_entry"]
