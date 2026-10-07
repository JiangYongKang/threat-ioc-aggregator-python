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
from app.weights import (
    WeightConfig,
    WeightRegistry,
    validate_weights,
)

logger = get_logger(__name__)


class RejudgeFailed(RuntimeError):
    """批量重新判定在提交前失败（重算阶段异常）。

    抛出时权重配置与存量指标均未发生任何变更，调用方可安全重试。
    原始异常挂在 __cause__ 上，不会被静默吞掉。
    """

    def __init__(self, version: int, detail: str) -> None:
        super().__init__(
            f"按权重版本 v{version} 的批量重判在提交前失败，全部变更已回滚："
            f"{detail}"
        )
        self.version = version
        self.detail = detail


class IocStore:
    """线程安全的 IOC 聚合存储。"""

    def __init__(self, weights: WeightRegistry | None = None) -> None:
        self._iocs: dict[str, Ioc] = {}
        # batch_id -> (批次指纹, 首次处理结果)，用于幂等重放与冲突检测
        self._batches: dict[str, tuple[str, BatchResult]] = {}
        self._weights = weights or WeightRegistry()
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

    def _apply_recompute(self, target: Ioc, now: str,
                         weights: object | None = None) -> IocStatus:
        """按给定时刻把聚合字段物化到 target（可为副本），返回旧状态。

        过期与否取决于判定时刻，因此读取与写入都需要重新物化。
        weights 为 None 时使用注册表当前生效的权重配置。
        """

        config = weights if weights is not None else self._weights.current()
        old_status = target.status
        target.confidence = aggregate_confidence(target.sources, now, config)
        target.verdict = aggregate_verdict(target.sources, now, config)
        target.weight_version = getattr(config, "version", 0)
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
        """读取路径：在快照副本上按 now 物化，不触碰存储对象。

        聚合按指标记录的 weight_version 对应配置物化：查询看到的是
        "最近一次判定"的结论，权重变更只有经过重判/新写入才会体现，
        保证判定依据与 weight_version 始终对得上。
        """

        config = (self._weights.get_version(ioc.weight_version)
                  or self._weights.current())
        clone = _clone_ioc(ioc)
        old_status = self._apply_recompute(clone, now, weights=config)
        if old_status is not clone.status:
            clone.history.append(AuditEvent(
                at=now, batch_id="-", source="-",
                action=f"transition:{old_status.value}->{clone.status.value}",
                detail=f"按查询时刻 {now} 临时物化：{old_status.value} -> "
                       f"{clone.status.value}（过期={clone.expires_at}, "
                       f"全部撤回={clone.revoked}）",
            ))
        return clone

    # --------------------------------------------------- 批量重新判定

    def _plan_rejudge(self, config: WeightConfig, now: str,
                      ) -> list[tuple[str, Ioc]]:
        """在副本上为所有需要重判的指标出计划（纯计算，不触碰存储）。

        任一指标的重算抛错都会中断，已算出的副本全部丢弃，存储零变更。
        过期/撤回指标同样只重算聚合字段：生命周期规则不变，不会因此复活。
        返回 (指标键, 完整新快照) 列表。
        """

        plans: list[tuple[str, Ioc]] = []
        for indicator, ioc in self._iocs.items():
            if ioc.weight_version == config.version:
                continue  # 已按目标版本判定过：重试/重复触发时跳过，不重复记账
            clone = _clone_ioc(ioc)
            old_status = self._apply_recompute(clone, now, weights=config)
            clone.updated_at = now
            clone.history.append(AuditEvent(
                at=now, batch_id="-", source="-",
                action="rejudge",
                detail=(f"按权重版本 v{config.version} 重新判定："
                        f"verdict={clone.verdict.value} "
                        f"confidence={clone.confidence} "
                        f"status={clone.status.value}"),
            ))
            if old_status is not clone.status:
                clone.history.append(AuditEvent(
                    at=now, batch_id="-", source="-",
                    action=f"transition:{old_status.value}->{clone.status.value}",
                    detail=(f"重判触发生命周期迁移：{old_status.value} -> "
                            f"{clone.status.value}"),
                ))
            plans.append((indicator, clone))
        return plans

    def _commit_plan(self, plans: list[tuple[str, Ioc]]) -> None:
        """把整份重判计划一次性提交到存储。

        计划里的每项都是完整快照；这里先构造好替换后的新字典，再用
        **单次属性赋值**整体替换 self._iocs——提交点只有一次引用写入，
        其他线程（以及任何读取路径）看到的要么是整份旧表、要么是整份
        新表，绝不存在同一时刻一部分指标新、一部分指标旧的混用状态。
        """

        if not plans:
            return
        new_iocs = dict(self._iocs)
        for indicator, clone in plans:
            new_iocs[indicator] = clone
        self._iocs = new_iocs

    def rejudge_all(self, config: object, *, now: str | None = None,
                    fail_hook: object | None = None) -> dict[str, int]:
        """用指定权重配置对全量存量指标做一次原子批量重新判定。

        保证：
        - 与写入共用同一把锁：重算期间并发投递的批次整体排在重算之前
          或之后，不会出现新旧权重混用的中间态；
        - 两阶段提交：先在副本上完成全部计算，任一环节抛错则存储零变更，
          失败以 RejudgeFailed 反馈给调用方（不静默吞错），重试安全；
        - 已按该版本权重判定过的指标跳过（重试不产生重复审计记录）；
        - 过期/撤回指标只重算聚合字段，生命周期规则不变，不会在查询中
          重新冒出来。
        """

        now = now or now_iso()
        version = getattr(config, "version", 0)
        with self._lock:
            try:
                plans = self._plan_rejudge(config, now)
                if fail_hook is not None:
                    fail_hook()  # 测试注入点：模拟重算全部完成后、提交前失败
            except Exception as exc:
                if isinstance(exc, RejudgeFailed):
                    raise
                logger.exception(
                    "[批量重判] 权重版本=v%d 重算阶段失败，存储零变更 @ %s",
                    version, now,
                )
                raise RejudgeFailed(version, str(exc)) from exc

            self._commit_plan(plans)
            changed = len(plans)
            logger.info(
                "[批量重判] 权重版本=v%d 重算指标=%d 跳过=%d 总量=%d @ %s",
                version, changed, len(self._iocs) - changed,
                len(self._iocs), now,
            )
            return {"rejudged": changed, "total": len(self._iocs),
                    "weight_version": version}

    def publish_weights_and_rejudge(self, weights: object, *, note: str = "",
                                    now: str | None = None,
                                    fail_hook: object | None = None
                                    ) -> tuple[WeightConfig, dict[str, int]]:
        """原子地"发布新一版权重 + 对全量存量指标重判"。

        单事务语义（全程持有存储锁，与批次写入互斥）：
        - 配置非法（WeightConfigError）：在任何变更前抛出，权重与存量都不变；
        - 重算阶段失败：权重版本尚未发布、存量尚未改动，两边都保持原样，
          抛 RejudgeFailed，调用方拿同一份权重重试不会多出版本、
          不重复记账，最终结果与一次成功完全一致；
        - 只有重算全部成功，才在同一临界区内先提交权重配置（版本号+历史
          只记这一次）、再整表原子替换；其他线程观察不到半新半旧状态。
        """

        # 非法配置在校验阶段直接拒绝（无副作用）；合法配置的候选版本号
        # 必须在存储锁内读取当前版本后构造，避免两个并发事务拿到同一版本号
        validate_weights(weights)
        now = now or now_iso()
        with self._lock:
            candidate = self._weights.stage_weights(
                weights, note=note, now=now
            )
            try:
                plans = self._plan_rejudge(candidate, now)
                if fail_hook is not None:
                    fail_hook()  # 测试注入点：模拟重算全部完成后、提交前失败
            except Exception as exc:
                if isinstance(exc, RejudgeFailed):
                    raise
                logger.exception(
                    "[权重发布] v%d 配套重判在提交前失败，配置与存量均不变更 @ %s",
                    candidate.version, now,
                )
                raise RejudgeFailed(candidate.version, str(exc)) from exc

            # 提交点：版本发布与存量重判在同一临界区内连续完成
            self._weights.commit_weights(candidate)
            self._commit_plan(plans)
            changed = len(plans)
            logger.info(
                "[权重发布] version=v%d 已发布并完成原子重判：重算=%d 跳过=%d "
                "总量=%d @ %s",
                candidate.version, changed, len(self._iocs) - changed,
                len(self._iocs), now,
            )
            summary = {"rejudged": changed, "total": len(self._iocs),
                       "weight_version": candidate.version}
            return candidate, summary

    def commit_weights_only(self, weights: object, *, note: str = "",
                            now: str | None = None) -> WeightConfig:
        """只发布权重配置、不触发存量重判（查询仍按各指标当前版本口径）。

        与批次写入共用存储锁，保证配置发布点与批次写入点线性一致。
        """

        validate_weights(weights)
        now = now or now_iso()
        with self._lock:
            candidate = self._weights.stage_weights(
                weights, note=note, now=now
            )
            self._weights.commit_weights(candidate)
            return candidate

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
        weight_version=ioc.weight_version,
        history=list(ioc.history),
    )
