"""线程安全的指标汇聚存储：去重、生命周期与批次幂等。"""

from __future__ import annotations

import threading
from copy import deepcopy
from datetime import datetime

from app.models import AggregatedIndicator, BatchResult, SourceObservation


class IndicatorStore:
    """内存存储；所有公开方法在同一把锁下完成，保证原子性与幂等。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # indicator 身份键 (ioc_type:归一化值) -> 汇聚指标
        self._indicators: dict[str, AggregatedIndicator] = {}
        # batch_id -> 首次提交的结果（重放时原样返回，保证幂等）
        self._batches: dict[str, BatchResult] = {}

    def apply_batch(
        self,
        batch_id: str,
        observations: list[SourceObservation],
        rejected: list,
        degraded: list,
    ) -> BatchResult:
        """原子应用一个（已校验/归一化的）批次。

        同一 batch_id 的重复/并发/重放请求：只返回首次结果，不重复写入。
        返回结果中的 accepted_new / merged 反映首次应用时的实际变化。
        """
        with self._lock:
            existing = self._batches.get(batch_id)
            if existing is not None:
                return BatchResult(
                    batch_id=existing.batch_id,
                    replayed=True,
                    accepted_new=existing.accepted_new,
                    merged=existing.merged,
                    rejected=deepcopy(existing.rejected),
                    degraded=deepcopy(existing.degraded),
                )

            now = datetime.now()
            accepted_new = 0   # 新建的指标数（此前不存在该 indicator）
            merged = 0         # 并入已有指标的观测数（含跨来源与同源更新）
            for obs in observations:
                agg = self._indicators.get(obs.indicator)
                if agg is None:
                    agg = AggregatedIndicator(
                        indicator=obs.indicator,
                        ioc_type=obs.ioc_type,
                        value=obs.value,
                        created_at=now,
                        updated_at=now,
                    )
                    self._indicators[obs.indicator] = agg
                    agg.apply(obs)
                    accepted_new += 1
                else:
                    agg.apply(obs)
                    merged += 1
                agg.updated_at = now

            result = BatchResult(
                batch_id=batch_id,
                replayed=False,
                accepted_new=accepted_new,
                merged=merged,
                rejected=list(rejected),
                degraded=list(degraded),
            )
            # 最后一步才登记批次：与上面的写入处于同一临界区，对外整体可见。
            self._batches[batch_id] = result
            stored = self._batches[batch_id]
            return BatchResult(
                batch_id=stored.batch_id,
                replayed=False,
                accepted_new=stored.accepted_new,
                merged=stored.merged,
                rejected=deepcopy(stored.rejected),
                degraded=deepcopy(stored.degraded),
            )

    def get(self, indicator: str) -> AggregatedIndicator | None:
        with self._lock:
            return self._indicators.get(indicator)

    def query(
        self,
        *,
        ioc_type: str | None = None,
        source: str | None = None,
        now: datetime | None = None,
        include_inactive: bool = False,
    ) -> list[AggregatedIndicator]:
        """查询指标；默认只返回 active（未过期、未撤回）的指标。

        - source：按来源名过滤（指标的任一来源观测匹配即命中）。
        - ioc_type：按指标类型精确过滤。
        - include_inactive=True 时同时返回 expired/revoked（结果带 status 字段以便区分）。
        """
        now = now or datetime.now()
        with self._lock:
            out: list[AggregatedIndicator] = []
            for agg in self._indicators.values():
                if ioc_type is not None and agg.ioc_type.value != ioc_type:
                    continue
                if source is not None and source not in agg.source_names:
                    continue
                if not include_inactive and agg.status(now).value != "active":
                    continue
                out.append(agg)
            out.sort(key=lambda a: a.last_seen, reverse=True)
            return out

    def has_batch(self, batch_id: str) -> bool:
        with self._lock:
            return batch_id in self._batches

    def get_batch_result(self, batch_id: str) -> BatchResult | None:
        """只读获取已登记批次的结果快照（不产生任何写入），用于重放预检。"""
        with self._lock:
            existing = self._batches.get(batch_id)
            if existing is None:
                return None
            return BatchResult(
                batch_id=existing.batch_id,
                replayed=True,
                accepted_new=existing.accepted_new,
                merged=existing.merged,
                rejected=deepcopy(existing.rejected),
                degraded=deepcopy(existing.degraded),
            )

    def stats(self, now: datetime | None = None) -> dict:
        now = now or datetime.now()
        with self._lock:
            counts = {"active": 0, "expired": 0, "revoked": 0}
            for agg in self._indicators.values():
                counts[agg.status(now).value] += 1
            return {
                "indicators_total": len(self._indicators),
                "batches_total": len(self._batches),
                **counts,
            }

    def reset(self) -> None:
        with self._lock:
            self._indicators.clear()
            self._batches.clear()
