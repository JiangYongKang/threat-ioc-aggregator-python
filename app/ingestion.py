"""批次入库服务：原子写入、幂等重放、并发安全。

保证：
- 批次结构非法（非列表/空/缺批次号/超限）整体拒绝，抛 BatchRejected，
  存储零变更、不污染已入库数据；
- 条目级非法只拒绝该条并给出可区分原因，其余条目正常（可能降级）入库；
- 同一 batch_id 重放：内容一致则原样返回首次结果（replayed=True），
  入库数量/指标状态完全不变；内容不一致则以 DUPLICATE_BATCH_ID 拒绝；
- 全局锁串行化"判定+写入"，并发提交等价于顺序提交。
"""

from __future__ import annotations

import hashlib
import json
import threading

from app.logging_utils import get_logger
from app.models import (
    BatchRejectReason,
    BatchResult,
    DegradedEntry,
    RejectedEntry,
)
from app.normalizer import normalize_entry

logger = get_logger(__name__)


class BatchRejected(Exception):
    """整个批次被原子拒绝（没有任何条目写入）。"""

    def __init__(self, reason: BatchRejectReason, detail: str) -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail


class IngestionService:
    """批次入库服务。"""

    def __init__(self, store: object, max_entries_per_batch: int = 10_000) -> None:
        self.store = store
        self.max_entries_per_batch = max_entries_per_batch
        # 串行化所有批次的"判定 + 写入"临界区
        self._global_lock = threading.RLock()

    # ------------------------------------------------- 批次指纹

    @staticmethod
    def _fingerprint(entries: object) -> str:
        """对批次条目内容计算稳定指纹，用于重放冲突检测。"""

        blob = json.dumps(
            entries, ensure_ascii=False, sort_keys=True, default=str
        ).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    # ------------------------------------------------- 主入口

    def submit_batch(
        self,
        batch_id: str | None,
        entries: object,
        *,
        source_hint: str | None = None,
    ) -> BatchResult:
        """提交一个批次：结构校验 -> 逐条归一 -> 临界区原子写入。"""

        # 1) 批次级结构校验（任何写入之前）
        if not isinstance(batch_id, str) or not batch_id.strip():
            raise BatchRejected(
                BatchRejectReason.MISSING_BATCH_ID,
                "批次必须携带非空字符串 batch_id 作为幂等键",
            )
        batch_id = batch_id.strip()

        if not isinstance(entries, list):
            raise BatchRejected(
                BatchRejectReason.NOT_A_LIST,
                f"批次内容必须是条目列表，实际类型 {type(entries).__name__}",
            )
        if len(entries) == 0:
            raise BatchRejected(
                BatchRejectReason.EMPTY_BATCH, "空批次不允许提交"
            )
        if len(entries) > self.max_entries_per_batch:
            raise BatchRejected(
                BatchRejectReason.ENTRY_LIMIT_EXCEEDED,
                f"批次条目数 {len(entries)} 超过上限 "
                f"{self.max_entries_per_batch}",
            )

        logger.info(
            "[批次输入] batch_id=%s source_hint=%s 条目数=%d 原始内容=%s",
            batch_id, source_hint, len(entries),
            json.dumps(entries, ensure_ascii=False, default=str)[:2000],
        )

        # 2) 锁外逐条归一（纯计算，不触碰存储）
        normalized: list[tuple[int, object]] = []
        rejected: list[RejectedEntry] = []
        degraded: list[DegradedEntry] = []

        for index, raw in enumerate(entries):
            entry, reason, detail = normalize_entry(
                raw, index, source_hint=source_hint
            )
            if reason is not None:
                rejected.append(RejectedEntry(
                    index=index, raw=raw, reason=reason, detail=detail,
                ))
                logger.info("[条目判定] #%d 拒绝 reason=%s detail=%s raw=%s",
                            index, reason.value, detail, raw)
                continue
            if entry.degrade_reasons:
                degraded.append(DegradedEntry(
                    index=index,
                    indicator=entry.indicator,
                    source=entry.source,
                    reasons=tuple(entry.degrade_reasons),
                    detail=entry.degrade_detail,
                ))
                logger.info("[条目判定] #%d 降级 indicator=%s reasons=%s detail=%s",
                            index, entry.indicator,
                            [r.value for r in entry.degrade_reasons],
                            entry.degrade_detail)
            normalized.append((index, entry))

        fingerprint = self._fingerprint(entries)

        # 3) 临界区：幂等判定 + 原子写入
        with self._global_lock:
            existing_fp = self.store.get_batch_fingerprint(batch_id)
            if existing_fp is not None:
                if existing_fp != fingerprint:
                    logger.warning(
                        "[批次冲突] batch_id=%s 曾用于不同内容: %s != %s",
                        batch_id, existing_fp, fingerprint,
                    )
                    raise BatchRejected(
                        BatchRejectReason.DUPLICATE_BATCH_ID,
                        f"batch_id={batch_id} 已提交过不同内容的批次，"
                        "拒绝重放以防覆盖",
                    )
                result = self.store.get_batch_result(batch_id)
                replayed = BatchResult(
                    batch_id=result.batch_id,
                    accepted=result.accepted,
                    updated=result.updated,
                    rejected=result.rejected,
                    degraded=result.degraded,
                    replayed=True,
                    rejected_entries=result.rejected_entries,
                    degraded_entries=result.degraded_entries,
                    indicators=result.indicators,
                )
                logger.info(
                    "[幂等重放] batch_id=%s 原样返回 accepted=%d updated=%d "
                    "rejected=%d degraded=%d",
                    batch_id, replayed.accepted, replayed.updated,
                    replayed.rejected, replayed.degraded,
                )
                return replayed

            accepted = 0
            updated = 0
            touched: list[str] = []
            for index, entry in normalized:
                action = self.store.upsert(entry, batch_id=batch_id)
                if action == "create":
                    accepted += 1
                else:
                    updated += 1
                touched.append(entry.indicator)
                logger.info(
                    "[写入] batch_id=%s #%d indicator=%s source=%s action=%s",
                    batch_id, index, entry.indicator, entry.source, action,
                )

            result = BatchResult(
                batch_id=batch_id,
                accepted=accepted,
                updated=updated,
                rejected=len(rejected),
                degraded=len(degraded),
                replayed=False,
                rejected_entries=tuple(rejected),
                degraded_entries=tuple(degraded),
                indicators=tuple(sorted(set(touched))),
            )
            # 写入完成后再登记批次，保证"批次结果可见"与"数据落库"同时发生
            self.store.save_batch_result(batch_id, fingerprint, result)
            logger.info(
                "[批次完成] batch_id=%s accepted=%d updated=%d rejected=%d "
                "degraded=%d indicators=%s",
                batch_id, accepted, updated, len(rejected), len(degraded),
                result.indicators,
            )
            return result
