"""对外应用服务门面：聚合存储 + 批次入库 + 本地情报加载。

供 HTTP API、CLI 与测试复用，避免接口层直接操作底层组件。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.feeds import LoadedFeed, load_all_feeds
from app.ingestion import BatchRejected, IngestionService
from app.lifecycle import explain_confidence, explain_verdict, now_iso
from app.logging_utils import get_logger
from app.models import BatchResult, IocStatus, IocType
from app.store import IocStore

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


class ThreatIocService:
    """聚合存储 + 入库服务的门面。"""

    def __init__(self, feeds_dir: str | None = None,
                 max_entries_per_batch: int = 10_000) -> None:
        self.feeds_dir = feeds_dir
        self.store = IocStore()
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

    # ------------------------------------------------- 查询

    def query(self, indicator: str, *, now: str | None = None):
        """返回指标记录快照（含过期/撤回，用于追溯），不存在返回 None。"""

        return self.store.get(indicator, now=now)

    def explain(self, indicator: str, *, now: str | None = None):
        """返回指标结论的可解释视图（含置信度与判定依据）。"""

        now = now or now_iso()
        ioc = self.store.get(indicator, now=now)
        if ioc is None:
            return None
        confidence, conf_basis = explain_confidence(ioc.sources, now)
        verdict, verdict_basis = explain_verdict(ioc.sources, now)
        return Explanation(
            indicator=ioc.indicator,
            status=ioc.status.value,
            verdict=verdict.value,
            confidence=confidence,
            confidence_basis=conf_basis,
            verdict_basis=verdict_basis,
            sources=tuple(sorted(ioc.sources)),
            visible=ioc.status is IocStatus.ACTIVE,
        )

    def list_active(self, *, ioc_type: IocType | None = None,
                    now: str | None = None) -> list[object]:
        """只列当前可见指标；过期/撤回不出现。"""

        return self.store.query_active(ioc_type=ioc_type, now=now)
