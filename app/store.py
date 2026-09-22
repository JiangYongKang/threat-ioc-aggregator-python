"""线程安全的内存 IOC 聚合存储。

去重键：归一化后的指标值（小写/去空白）。同一指标全库只保留一份，
多来源观测挂在 Ioc.sources 下，全部变更写入 history 以保证可追溯。

并发：单把可重入锁串行化所有写入批次；查询在锁外做快照拷贝。
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

from app.lifecycle import (
    aggregate_confidence,
    aggregate_verdict,
    derive_expiry,
    derive_status,
    is_observation_live,
    now_iso,
    parse_ts,
)
from app.logging_utils import get_logger
from app.models import (
    AuditEvent,
    BatchResult,
    Ioc,
    IocStatus,
    IocType,
    SourceObservation,
)

logger = get_logger(__name__)


class IocStore:
    """线程安全的 IOC 聚合存储。"""

    def __init__(self) -> None:
        self._iocs: dict[str, Ioc] = {}
        # batch_id -> (批次指纹, 首次处理结果)，用于幂等重放与冲突检测
        self._batches: dict[str, tuple[str, BatchResult]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------- 写入

    def upsert(self, entry: object, *, batch_id: str, now: str | None = None) -> str:
        """聚合写入一条归一化情报。

        返回动作：create（新指标）/ update_source（首次见到该来源）/
        refresh（该来源重复投递，刷新可见时间）。
        调用方必须已持有批次处理上下文（本方法自带存储锁）。
        """

        now = now or now_iso()
        with self._lock:
            existing = self._iocs.get(entry.indicator)

            obs = SourceObservation(
                source=entry.source,
                confidence=entry.confidence,
                verdict=entry.verdict,
                tags=entry.tags,
                first_seen=entry.first_seen,
                last_seen=entry.last_seen,
                expires_at=entry.expires_at,
                revoked=entry.revoked,
            )

            if existing is None:
                ioc = Ioc(
                    indicator=entry.indicator,
                    ioc_type=entry.ioc_type,
                    verdict=entry.verdict,
                    confidence=entry.confidence,
                    status=IocStatus.ACTIVE,
                    sources={entry.source: obs},
                    tags=set_tags(entry.tags),
                    first_seen=entry.first_seen,
                    last_seen=entry.last_seen,
                    expires_at=entry.expires_at,
                    revoked=entry.revoked,
                    updated_at=now,
                    history=[AuditEvent(
                        at=now, batch_id=batch_id, source=entry.source,
                        action="create",
                        detail=(f"首次入库：来源={entry.source} "
                                f"verdict={entry.verdict.value} "
                                f"confidence={entry.confidence}"),
                    )],
                )
                self._iocs[entry.indicator] = ioc
                action = "create"
            else:
                action = self._merge(existing, obs, entry, batch_id, now)

            self._recompute(entry.indicator, now)
            return action

    def _merge(self, ioc: Ioc, obs: SourceObservation, entry: object,
               batch_id: str, now: str) -> str:
        """把一个来源观测合并进既有指标。"""

        prior = ioc.sources.get(entry.source)
        if prior is None:
            action = "update_source"
            detail = f"新增来源 {entry.source}（既有来源 {len(ioc.sources)} 个）"
        else:
            action = "refresh"
            detail = (
                f"来源 {entry.source} 重复投递："
                f"verdict {prior.verdict.value}->{entry.verdict.value}, "
                f"confidence {prior.confidence}->{entry.confidence}, "
                f"last_seen {prior.last_seen}->{entry.last_seen}, "
                f"revoked={entry.revoked}"
            )

        ioc.sources[entry.source] = obs
        ioc.tags = frozenset(ioc.tags) | entry.tags
        if parse_ts(entry.first_seen) < parse_ts(ioc.first_seen):
            ioc.first_seen = entry.first_seen
        if parse_ts(entry.last_seen) > parse_ts(ioc.last_seen):
            ioc.last_seen = entry.last_seen
        ioc.updated_at = now
        ioc.history.append(AuditEvent(
            at=now, batch_id=batch_id, source=entry.source,
            action=action, detail=detail,
        ))
        return action

    def _recompute(self, indicator: str, now: str) -> None:
        """写入路径：按当前时刻重算并持久化聚合字段与生命周期状态。"""

        ioc = self._iocs[indicator]
        old_status = self._apply_recompute(ioc, now)
        if old_status is not ioc.status:
            ioc.history.append(AuditEvent(
                at=now, batch_id="-", source="-",
                action=f"transition:{old_status.value}->{ioc.status.value}",
                detail=(f"生命周期状态在 {now} 由 {old_status.value} "
                        f"迁移为 {ioc.status.value}（过期={ioc.expires_at}, "
                        f"全部撤回={ioc.revoked}）"),
            ))
            logger.info("指标 %s 状态迁移: %s -> %s @ %s",
                        indicator, old_status.value, ioc.status.value, now)

    def _apply_recompute(self, target: Ioc, now: str) -> IocStatus:
        """按给定时刻把聚合字段物化到 target（可为副本），返回旧状态。

        过期与否取决于判定时刻，因此读取与写入都需要重新物化。
        """

        old_status = target.status
        target.confidence = aggregate_confidence(target.sources, now)
        target.verdict = aggregate_verdict(target.sources, now)
        target.expires_at = derive_expiry(target.sources)
        target.revoked = bool(target.sources) and all(
            o.revoked for o in target.sources.values()
        )
        target.status = derive_status(
            revoked=target.revoked, expires_at=target.expires_at, now=now
        )
        live = {s: o for s, o in target.sources.items()
                if is_observation_live(o, now)}
        if live:
            latest = max(o.last_seen for o in live.values())
            if parse_ts(latest) > parse_ts(target.last_seen):
                target.last_seen = latest
        return old_status

    def _materialized(self, ioc: Ioc, now: str) -> Ioc:
        """读取路径：在快照副本上按 now 物化，不触碰存储对象。"""

        clone = _clone_ioc(ioc)
        old_status = self._apply_recompute(clone, now)
        if old_status is not clone.status:
            clone.history.append(AuditEvent(
                at=now, batch_id="-", source="-",
                action=f"transition:{old_status.value}->{clone.status.value}",
                detail=f"按查询时刻 {now} 临时物化：{old_status.value} -> "
                       f"{clone.status.value}（过期={clone.expires_at}, "
                       f"全部撤回={clone.revoked}）",
            ))
        return clone

    # ------------------------------------------------------- 查询

    def get(self, indicator: str, *, now: str | None = None) -> Ioc | None:
        """按指标值取整份记录（含过期/撤回，用于追溯）。

        状态按查询时刻 now 物化在返回副本上，不改动存储内部数据。
        """

        now = now or now_iso()
        with self._lock:
            ioc = self._iocs.get(indicator)
            return self._materialized(ioc, now) if ioc else None

    def query_active(self, *, ioc_type: IocType | None = None,
                     now: str | None = None) -> list[Ioc]:
        """只返回当前可见（ACTIVE）的指标；过期/撤回一律不出现。"""

        now = now or now_iso()
        with self._lock:
            out = []
            for ioc in self._iocs.values():
                view = self._materialized(ioc, now)
                if view.status is not IocStatus.ACTIVE:
                    continue
                if ioc_type is not None and view.ioc_type is not ioc_type:
                    continue
                out.append(view)
            return sorted(out, key=lambda x: x.indicator)

    def all_iocs(self) -> list[Ioc]:
        """返回全部指标的快照（含非 ACTIVE，供审计/测试）。"""

        now = now or now_iso()
        with self._lock:
            return [self._materialized(ioc, now) for ioc in self._iocs.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._iocs)

    # --------------------------------------------------- 批次幂等表

    def get_batch_result(self, batch_id: str) -> BatchResult | None:
        with self._lock:
            pair = self._batches.get(batch_id)
            return pair[1] if pair else None

    def get_batch_fingerprint(self, batch_id: str) -> str | None:
        with self._lock:
            pair = self._batches.get(batch_id)
            return pair[0] if pair else None

    def save_batch_result(self, batch_id: str, fingerprint: str,
                          result: BatchResult) -> None:
        with self._lock:
            self._batches[batch_id] = (fingerprint, result)

    # ------------------------------------------------------- 锁

    def lock(self) -> threading.RLock:
        """暴露底层锁，供批次做"校验+写入"临界区。"""

        return self._lock


def set_tags(tags: Iterable[str]) -> frozenset[str]:
    return frozenset(tags)


def _clone_ioc(ioc: Ioc) -> Ioc:
    """浅结构深拷贝一份快照，避免调用方修改存储内部对象。"""

    return Ioc(
        indicator=ioc.indicator,
        ioc_type=ioc.ioc_type,
        verdict=ioc.verdict,
        confidence=ioc.confidence,
        status=ioc.status,
        sources=dict(ioc.sources),
        tags=frozenset(ioc.tags),
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        expires_at=ioc.expires_at,
        revoked=ioc.revoked,
        updated_at=ioc.updated_at,
        history=list(ioc.history),
    )
