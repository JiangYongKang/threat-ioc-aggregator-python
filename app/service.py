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
from app.store import IocStore
from app.weights import WeightPublishError, WeightRegistry

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
        """原子发布新一版权重并（默认）对全量存量指标重判。

        一致性语义：
        - **配置与存量一起生效或一起不变**：候选构造（含校验）与全量
          副本重算都在共享锁内、任何提交之前完成；重算中途出错则权重
          版本不发布、存量零变更、批次幂等表不动，调用方会收到
          WeightPublishError（原始异常挂在 __cause__ 上），不会静默吞掉；
        - **同一份权重失败重试不重复记账**：候选权重与当前版本内容相同
          时复用原版本号（reused=True），历史不新增条目，最终状态与
          "一次调权就成功"完全一致；
        - **与并发投递不混用**：临界期内进入的批次整体在临界区之前
          （会被本次重判覆盖到新版本）或之后（直接按新权重写入），
          不会出现一部分指标新权重、一部分旧权重。

        rejudge=False 时只发布配置，存量结论与 weight_version 保持原样，
        直到手动 rejudge_all() 或新批次写入（发布/解耦两种模式都支持
        同内容幂等）。
        """

        if not rejudge:
            # 与主路径一样把候选构造放进锁内，避免并发发布时拿到陈旧版本号
            with self.store.lock():
                config, reused = self.weights.candidate(weights, note=note)
                self.weights.commit(config)
            return self._weight_publish_result(config, {"rejudged": 0,
                                                        "total": self.store.count(),
                                                        "weight_version": config.version},
                                               reused=reused)

        # 校验在锁外先做一次：非法配置快速失败，且不占用临界区
        # （candidate 是纯函数式校验，锁内会再确定性地构造一次）。
        self.weights.candidate(weights, note=note)
        config, reused = None, False
        try:
            with self.store.lock():
                # 锁内构造候选：拿到相对当前版本的正确版本号，并与全量
                # 重算、发布、提交处于同一不可分割的临界区。
                config, reused = self.weights.candidate(weights, note=note)
                plans = self.store.plan_rejudge(config)
                if fail_hook is not None:
                    fail_hook()  # 测试注入点：重算完成、提交发布之前
                self.weights.commit(config)
                summary = self.store.commit_rejudge(config, plans)
        except WeightPublishError:
            raise
        except Exception as exc:
            # 走到这里说明没有发生任何提交：权重未发布、存量零变更。
            logger.exception(
                "[权重发布] 候选版本 v%s 的全量重判失败，权重与存量均回滚",
                config.version,
            )
            raise WeightPublishError(config.version, str(exc)) from exc

        return self._weight_publish_result(config, summary, reused=reused)

    @staticmethod
    def _weight_publish_result(config, summary: dict, *, reused: bool) -> dict:
        return {
            "version": config.version,
            "weights": dict(config.weights),
            "updated_at": config.updated_at,
            "note": config.note,
            "reused": reused,
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
