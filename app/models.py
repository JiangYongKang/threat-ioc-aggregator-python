"""统一情报模型与归一化/批次结果类型定义。"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum


class IOCTypes(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def score(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]


class LifecycleStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RejectReason(str, Enum):
    """条目被拒绝（未入库）的可区分原因。"""

    MISSING_VALUE = "missing_value"
    MISSING_TYPE = "missing_type"
    UNKNOWN_TYPE = "unknown_type"
    INVALID_VALUE = "invalid_value"
    INVALID_CONFIDENCE = "invalid_confidence"
    INVALID_TIMESTAMP = "invalid_timestamp"
    REVOKED_WITHOUT_VALUE = "revoked_without_value"


class DegradeReason(str, Enum):
    """条目可入库但字段残缺、发生降级的可区分原因。"""

    MISSING_CONFIDENCE = "missing_confidence"
    MISSING_TAGS = "missing_tags"
    MISSING_TIMESTAMP = "missing_timestamp"
    MISSING_VALID_UNTIL = "missing_valid_until"
    UNKNOWN_EXTRA_FIELDS = "unknown_extra_fields"


class BatchRejectReason(str, Enum):
    EMPTY_BATCH = "empty_batch"
    MALFORMED_BATCH = "malformed_batch"
    DUPLICATE_BATCH = "duplicate_batch"


@dataclass(frozen=True)
class SourceObservation:
    """归一化后的单条来源观测。"""

    indicator: str
    ioc_type: IOCTypes
    value: str
    source: str
    confidence: Confidence
    first_seen: datetime
    last_seen: datetime
    valid_until: datetime | None
    revoked: bool
    tags: frozenset[str] = frozenset()
    degrade_reasons: frozenset[str] = frozenset()
    ingested_at: datetime = field(default_factory=datetime.now)


@dataclass
class AggregatedIndicator:
    """同一指标跨来源汇聚后的唯一记录。

    指标身份 = (ioc_type, 归一化后的 value)，对应字符串键 indicator。
    每个来源至多保留一条最新观测；状态由全部来源观测派生：
      - revoked：所有来源观测均撤回；
      - expired：当前时间晚于任一来源给出的最晚 valid_until；
      - 否则 active。
    """

    indicator: str
    ioc_type: IOCTypes
    value: str
    sources: list[SourceObservation] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def _active_observations(self) -> list[SourceObservation]:
        return [o for o in self.sources if not o.revoked]

    def apply(self, obs: SourceObservation) -> bool:
        """并入一条来源观测。返回 True 表示该来源此前已有观测（更新），False 表示新来源。"""
        for idx, existing in enumerate(self.sources):
            if existing.source == obs.source:
                # 同一来源先后投递：保留最早 first_seen 与最晚 last_seen，其余以新观测为准。
                merged = replace(
                    obs,
                    first_seen=min(existing.first_seen, obs.first_seen),
                    last_seen=max(existing.last_seen, obs.last_seen),
                    tags=existing.tags | obs.tags,
                    degrade_reasons=existing.degrade_reasons | obs.degrade_reasons,
                )
                self.sources[idx] = merged
                return True
        self.sources.append(obs)
        return False

    @property
    def source_names(self) -> list[str]:
        seen: list[str] = []
        for obs in self.sources:
            if obs.source not in seen:
                seen.append(obs.source)
        return seen

    @property
    def max_confidence(self) -> Confidence:
        # 汇聚置信度 = 各来源置信度的最大值；撤回观测不参与，全部撤回时退化为全部观测最大值。
        candidates = self._active_observations() or self.sources
        return max((o.confidence for o in candidates), key=lambda c: c.score)

    @property
    def confidence_sources(self) -> list[str]:
        """给出提供当前汇聚置信度的来源，便于解释。"""
        top = self.max_confidence
        return [o.source for o in self.sources if o.confidence == top]

    @property
    def last_seen(self) -> datetime:
        # 最近可见时间 = 未撤回观测中的最晚 last_seen；全部撤回时取撤回事件时间。
        candidates = self._active_observations() or self.sources
        return max(o.last_seen for o in candidates)

    @property
    def first_seen(self) -> datetime:
        return min(o.first_seen for o in self.sources)

    @property
    def is_revoked(self) -> bool:
        # 只有所有来源都撤回时才整体撤回；任一来源仍在报告则保持有效。
        return bool(self.sources) and all(o.revoked for o in self.sources)

    @property
    def valid_until(self) -> datetime | None:
        # 汇聚有效期 = 未撤回来源给出的最晚 valid_until；均未提供则为 None（不自动过期）。
        deadlines = [
            o.valid_until for o in self._active_observations() if o.valid_until is not None
        ]
        return max(deadlines) if deadlines else None

    @property
    def tags(self) -> frozenset[str]:
        result: frozenset[str] = frozenset()
        for obs in self.sources:
            result |= obs.tags
        return result

    def status(self, now: datetime) -> LifecycleStatus:
        if self.is_revoked:
            return LifecycleStatus.REVOKED
        deadline = self.valid_until
        if deadline is not None and now > deadline:
            return LifecycleStatus.EXPIRED
        return LifecycleStatus.ACTIVE

    def to_dict(self, now: datetime | None = None) -> dict:
        now = now or datetime.now()
        status = self.status(now)
        return {
            "indicator": self.indicator,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "status": status.value,
            "confidence": self.max_confidence.value,
            "confidence_sources": self.confidence_sources,
            "sources": self.source_names,
            "source_observations": [
                {
                    "source": o.source,
                    "confidence": o.confidence.value,
                    "first_seen": o.first_seen.isoformat(),
                    "last_seen": o.last_seen.isoformat(),
                    "valid_until": o.valid_until.isoformat() if o.valid_until else None,
                    "revoked": o.revoked,
                    "tags": sorted(o.tags),
                    "degrade_reasons": sorted(o.degrade_reasons),
                }
                for o in self.sources
            ],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "tags": sorted(self.tags),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "explanation": (
                f"confidence={self.max_confidence.value} 来自来源 "
                f"{','.join(self.confidence_sources)}；来源数={len(self.source_names)}；"
                f"最近可见={self.last_seen.isoformat()}；状态={status.value}"
            ),
        }


@dataclass
class RejectedEntry:
    index: int
    reason: str
    detail: str | None
    raw: dict | None


@dataclass
class DegradedEntry:
    index: int
    indicator: str
    reasons: list[str]
    source: str


@dataclass
class BatchResult:
    batch_id: str
    replayed: bool
    accepted_new: int
    merged: int
    rejected: list[RejectedEntry]
    degraded: list[DegradedEntry]

    @property
    def accepted_total(self) -> int:
        return self.accepted_new + self.merged

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "replayed": self.replayed,
            "accepted_new": self.accepted_new,
            "merged": self.merged,
            "accepted_total": self.accepted_total,
            "rejected": [
                {"index": r.index, "reason": r.reason, "detail": r.detail, "raw": r.raw}
                for r in self.rejected
            ],
            "degraded": [
                {
                    "index": d.index,
                    "indicator": d.indicator,
                    "reasons": d.reasons,
                    "source": d.source,
                }
                for d in self.degraded
            ],
        }
