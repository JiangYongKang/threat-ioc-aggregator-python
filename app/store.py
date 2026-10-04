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
from app.weights import WeightRevision, WeightStore

logger = get_logger(__name__)


class IocStore:
    """线程安全的 IOC 聚合存储。"""

    def __init__(self, weight_store: WeightStore | None = None) -> None:
        self._iocs: dict[str, Ioc] = {}
        # batch_id -> (批次指纹, 首次处理结果)，用于幂等重放与冲突检测
        self._batches: dict[str, tuple[str, BatchResult]] = {}
        self._weights = weight_store or WeightStore()
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
        """写入路径：按当前时刻与当前权重版本重算并持久化聚合字段。"""

        ioc = self._iocs[indicator]
        revision = self._weights.current()
        old_status = self._apply_recompute(ioc, now, revision.weights)
        ioc.weights_version = revision.version
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

    def _apply_recompute(self, target: Ioc, now: str,
                         weights: dict[str, float] | None = None) -> IocStatus:
        """按给定时刻与权重把聚合字段物化到 target（可为副本），返回旧状态。

        过期与否取决于判定时刻，因此读取与写入都需要重新物化。
        """

        old_status = target.status
        target.confidence = aggregate_confidence(target.sources, now, weights)
        target.verdict = aggregate_verdict(target.sources, now, weights)
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
        """读取路径：在快照副本上按 now 与当前权重物化，不触碰存储对象。"""

        clone = _clone_ioc(ioc)
        revision = self._weights.current()
        old_status = self._apply_recompute(clone, now, revision.weights)
        clone.weights_version = revision.version
        if old_status is not clone.status:
            clone.history.append(AuditEvent(
                at=now, batch_id="-", source="-",
                action=f"transition:{old_status.value}->{clone.status.value}",
                detail=f"按查询时刻 {now} 临时物化：{old_status.value} -> "
                       f"{clone.status.value}（过期={clone.expires_at}, "
                       f"全部撤回={clone.revoked}）",
            ))
        return clone

    # ------------------------------------------------- 全量重新判定

    @property
    def weight_store(self) -> WeightStore:
        return self._weights

    def recompute_all(self, revision: WeightRevision,
                      now: str | None = None) -> dict[str, int]:
        """用新版权重对全量存量指标重新判定，并生效该权重版本。

        原子性：先在副本上预计算全部指标，全部成功才一次性写回并提交
        权重版本；中途任何异常都不会改动存量数据，权重版本也不变，
        用同一配置重试得到同一结果（幂等）。
        并发：调用方须持有入库全局锁（与批次写入互斥），本方法再持
        存储锁，保证重算期间没有批次写入插入，杜绝新旧权重混用。
        过期/撤回指标只重算聚合字段，生命周期规则不变，不会复活。
        """

        now = now or now_iso()
        with self._lock:
            # 1) 预计算：在副本上物化，任何异常都尚未触碰存储
            staged: dict[str, Ioc] = {}
            for indicator, ioc in self._iocs.items():
                clone = _clone_ioc(ioc)
                self._apply_recompute(clone, now, revision.weights)
                clone.weights_version = revision.version
                staged[indicator] = clone

            # 2) 全部成功后一次性写回并追加审计
            changed = 0
            for indicator, clone in staged.items():
                ioc = self._iocs[indicator]
                delta = (
                    f"verdict {ioc.verdict.value}->{clone.verdict.value}, "
                    f"confidence {ioc.confidence}->{clone.confidence}, "
                    f"status {ioc.status.value}->{clone.status.value}"
                )
                if (ioc.verdict is not clone.verdict
                        or ioc.confidence != clone.confidence
                        or ioc.status is not clone.status):
                    changed += 1
                ioc.verdict = clone.verdict
                ioc.confidence = clone.confidence
                ioc.status = clone.status
                ioc.expires_at = clone.expires_at
                ioc.revoked = clone.revoked
                ioc.last_seen = clone.last_seen
                ioc.weights_version = revision.version
                ioc.updated_at = now
                ioc.history.append(AuditEvent(
                    at=now, batch_id="-", source="-",
                    action="reweight",
                    detail=(f"按权重版本 v{revision.version} 重新判定：{delta}"),
                ))

            # 3) 数据全部落位后才提交权重版本（整体生效/整体不生效）
            self._weights.commit(revision)
            summary = {"total": len(staged), "changed": changed,
                       "version": revision.version}
            logger.info("[全量重算完成] version=%d total=%d changed=%d",
                        revision.version, len(staged), changed)
            return summary

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

    def all_iocs(self, *, now: str | None = None) -> list[Ioc]:
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
        weights_version=ioc.weights_version,
        history=list(ioc.history),
    )
