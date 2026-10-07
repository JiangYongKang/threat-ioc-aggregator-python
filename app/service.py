"""对外应用服务门面：聚合存储 + 批次入库 + 本地情报加载。

供 HTTP API、CLI 与测试复用，避免接口层直接操作底层组件。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.feeds import LoadedFeed, load_all_feeds
from app.ingestion import BatchRejected, IngestionService
from app.lifecycle import (
    explain_confidence,
    explain_contributions,
    explain_verdict,
    now_iso,
)
from app.logging_utils import get_logger
from app.models import BatchResult, IocStatus, IocType
from app.store import IocStore, RejudgeFailed
from app.weights import WeightRegistry

__all__ = ["Explanation", "FeedIngestionReport", "RejudgeFailed",
           "ThreatIocService"]

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class FeedIngestionReport:
    """本地情报目录一轮加载的汇总报告。"""

    feed_path: str
    source: str
    batch_id: str
    result: BatchResult | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Explanation:
    """指标判定的可解释视图。"""

    indicator: str
    status: str
    verdict: str
    confidence: float
    confidence_basis: str
    verdict_basis: str
    sources: tuple[str, ...]
    visible: bool
    weight_version: int
    contributions: tuple[dict, ...]


class ThreatIocService:
    """聚合存储 + 入库服务的门面。"""

    def __init__(self, feeds_dir: str | None = None,
                 max_entries_per_batch: int = 10_000) -> None:
        self.feeds_dir = feeds_dir
        self.weights = WeightRegistry()
        self.store = IocStore(self.weights)
        self.ingestion = IngestionService(
            self.store, max_entries_per_batch=max_entries_per_batch
        )

    # ------------------------------------------------- 批次提交

    def submit_batch(
        self,
        batch_id: str | None,
        entries: object,
        *,
        source_hint: str | None = None,
    ) -> BatchResult:
        """提交批次（委托给入库服务，异常原样向上抛）。"""

        return self.ingestion.submit_batch(
            batch_id, entries, source_hint=source_hint
        )

    # ------------------------------------------------- 本地情报

    @staticmethod
    def _default_batch_id(feed: LoadedFeed) -> str:
        """为没有显式 batch_id 的情报文件生成确定性批次号。

        同一文件重复加载 => 相同 batch_id + 相同内容 => 幂等重放。
        """

        digest = hashlib.sha256(
            json.dumps(feed.entries, ensure_ascii=False, sort_keys=True,
                       default=str).encode("utf-8")
        ).hexdigest()[:12]
        return f"file:{feed.source}:{digest}"

    def load_local_feeds(
        self, feeds_dir: str | None = None
    ) -> list[FeedIngestionReport]:
        """加载目录下所有来源文件并逐批入库。

        文件级解析错误以 error 记录、不入库；批次级拒绝（理论上不会发生，
        因为重放被幂等接受）同样记录到报告中。
        """

        target = feeds_dir or self.feeds_dir
        if not target:
            raise ValueError("未配置 feeds_dir，无法加载本地情报")

        loaded, errors = load_all_feeds(target)
        reports: list[FeedIngestionReport] = []

        for err in errors:
            reports.append(FeedIngestionReport(
                feed_path=str(err.path),
                source=err.path.stem,
                batch_id="",
                result=None,
                error=err.detail,
            ))

        for feed in loaded:
            batch_id = feed.batch_id or self._default_batch_id(feed)
            try:
                result = self.submit_batch(
                    batch_id, feed.entries, source_hint=feed.source
                )
                reports.append(FeedIngestionReport(
                    feed_path=str(feed.path),
                    source=feed.source,
                    batch_id=batch_id,
                    result=result,
                ))
            except BatchRejected as exc:
                reports.append(FeedIngestionReport(
                    feed_path=str(feed.path),
                    source=feed.source,
                    batch_id=batch_id,
                    result=None,
                    error=f"{exc.reason.value}: {exc.detail}",
                ))
        return reports

    # ------------------------------------------------- 权重与重判

    def set_weights(self, weights: object, *, note: str = "",
                    rejudge: bool = True,
                    fail_hook: object | None = None) -> dict:
        """发布新一版权重配置；默认与全量存量重判**原子**完成。

        原子语义（rejudge=True，默认）：
        - 配置校验失败抛 WeightConfigError，不产生任何变更；
        - 重算阶段失败抛 WeightPublishError：权重版本未发布、存量未改动，
          两边保持对齐，拿同一份权重再次调用不会多出版本/历史，最终状态
          与一次成功完全一致；
        - 成功时权重发布与存量重判在同一存储锁临界区内一次性对外可见，
          期间并发投递的批次整体排在其前或其后，不存在新旧权重混用。

        rejudge=False 时只发布配置（仍与批次写入互斥），查询结论保持按
        各指标当前 weight_version 的口径，直到下一次重判或新写入。

        fail_hook 仅供测试注入：在重算完成、提交前调用，用于稳定复现失败。
        """

        if rejudge:
            config, summary = self.store.publish_weights_and_rejudge(
                weights, note=note, fail_hook=fail_hook
            )
        else:
            config = self.store.commit_weights_only(weights, note=note)
            summary = {"rejudged": 0, "total": self.store.count(),
                       "weight_version": config.version}
        return {
            "version": config.version,
            "weights": dict(config.weights),
            "updated_at": config.updated_at,
            "note": config.note,
            "rejudge": summary,
        }

    def rejudge_all(self) -> dict:
        """按当前生效的权重配置对全量存量指标重判（幂等）。"""

        return self.store.rejudge_all(self.weights.current())

    def current_weights(self) -> dict:
        """返回当前生效的权重配置。"""

        config = self.weights.current()
        return {
            "version": config.version,
            "weights": dict(config.weights),
            "updated_at": config.updated_at,
            "note": config.note,
            "default_weight": 1.0,
        }

    def weight_history(self) -> list[dict]:
        """返回全部权重变更记录（什么时候被改成了什么）。"""

        return [
            {"version": c.version, "at": c.at,
             "weights": dict(c.weights), "note": c.note}
            for c in self.weights.history()
        ]

    # ------------------------------------------------- 查询

    def query(self, indicator: str, *, now: str | None = None):
        """返回指标记录快照（含过期/撤回，用于追溯），不存在返回 None。"""

        return self.store.get(indicator, now=now)

    def explain(self, indicator: str, *, now: str | None = None):
        """返回指标结论的可解释视图（含置信度、判定依据与来源权重贡献）。"""

        now = now or now_iso()
        ioc = self.store.get(indicator, now=now)
        if ioc is None:
            return None
        # 解释视图与指标记录的 weight_version 对齐：看到的是哪版权重算的，
        # 依据就按哪版权重解释
        config = (self.weights.get_version(ioc.weight_version)
                  or self.weights.current())
        confidence, conf_basis = explain_confidence(ioc.sources, now, config)
        verdict, verdict_basis = explain_verdict(ioc.sources, now, config)
        contributions = explain_contributions(ioc.sources, now, config)
        return Explanation(
            indicator=ioc.indicator,
            status=ioc.status.value,
            verdict=verdict.value,
            confidence=confidence,
            confidence_basis=conf_basis,
            verdict_basis=verdict_basis,
            sources=tuple(sorted(ioc.sources)),
            visible=ioc.status is IocStatus.ACTIVE,
            weight_version=ioc.weight_version,
            contributions=tuple(contributions),
        )

    def list_active(self, *, ioc_type: IocType | None = None,
                    now: str | None = None) -> list[object]:
        """只列当前可见指标；过期/撤回不出现。"""

        return self.store.query_active(ioc_type=ioc_type, now=now)
