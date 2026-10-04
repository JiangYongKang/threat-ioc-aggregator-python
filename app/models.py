"""威胁情报 IOC 汇聚服务的统一领域模型。

本模块只包含类型定义与纯数据结构，不包含业务逻辑。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IocType(str, Enum):
    """归一化后的指标类型。"""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    """最终判定结论。"""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    BENIGN = "benign"


class IocStatus(str, Enum):
    """指标生命周期状态。"""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RejectReason(str, Enum):
    """单条情报被拒绝（不入库）的可区分原因。"""

    MISSING_INDICATOR = "missing_indicator"          # 缺少指标值
    EMPTY_INDICATOR = "empty_indicator"              # 指标值为空串/纯空白
    MISSING_SOURCE = "missing_source"                # 缺少来源标识
    UNSUPPORTED_IOC_TYPE = "unsupported_ioc_type"    # 指标类型不支持
    MALFORMED_JSON = "malformed_json"                # 单条不是合法对象
    NON_OBJECT_ENTRY = "non_object_entry"            # 条目不是 dict
    INVALID_CONFIDENCE = "invalid_confidence"        # 置信度字段类型/范围非法
    INVALID_TIMESTAMP = "invalid_timestamp"          # 时间戳无法解析
    CONFLICTING_TYPE = "conflicting_type"            # 同值指标类型互相矛盾


class DegradeReason(str, Enum):
    """条目被降级（仍入库，但标注缺失）的可区分原因。"""

    MISSING_CONFIDENCE = "missing_confidence"        # 无置信度，按来源默认值
    MISSING_IOC_TYPE = "missing_ioc_type"            # 无类型，按值推断
    INFERRED_IOC_TYPE = "inferred_ioc_type"          # 类型非法，按值推断
    MISSING_TAGS = "missing_tags"                    # 无标签
    MISSING_VALIDITY_DAYS = "missing_validity_days"  # 无有效期，按默认值
    LOW_CONFIDENCE_CLAMPED = "low_confidence_clamped"  # 置信度越界被裁剪
    NON_STRING_TAGS = "non_string_tags"              # 标签存在非字符串项被过滤


class BatchRejectReason(str, Enum):
    """整个批次被拒绝（原子失败，不写入任何数据）的原因。"""

    NOT_A_LIST = "not_a_list"                # 批次不是列表
    EMPTY_BATCH = "empty_batch"              # 空批次
    MISSING_BATCH_ID = "missing_batch_id"    # 缺少批次幂等键
    DUPLICATE_BATCH_ID = "duplicate_batch_id"  # 批次号在不同内容上重放
    INVALID_BATCH_META = "invalid_batch_meta"  # 批次元信息非法
    ENTRY_LIMIT_EXCEEDED = "entry_limit_exceeded"  # 批次条目超限


@dataclass(frozen=True, slots=True)
class SourceObservation:
    """某个来源对某指标的一次观测（来源可追溯的最小单元）。"""

    source: str
    confidence: float
    verdict: Verdict
    tags: frozenset[str]
    first_seen: str
    last_seen: str
    expires_at: str | None
    revoked: bool


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """指标上的一次可追溯变更。"""

    at: str
    batch_id: str
    source: str
    action: str          # create / update_source / refresh / revoke
    detail: str


@dataclass(slots=True)
class Ioc:
    """归一化后全局唯一的 IOC 聚合记录。"""

    indicator: str
    ioc_type: IocType
    verdict: Verdict
    confidence: float
    status: IocStatus
    sources: dict[str, SourceObservation] = field(default_factory=dict)
    tags: frozenset[str] = frozenset()
    first_seen: str = ""
    last_seen: str = ""
    expires_at: str | None = None
    revoked: bool = False
    updated_at: str = ""
    weight_version: int = 0  # 最近一次聚合判定所用的权重配置版本
    history: list[AuditEvent] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RejectedEntry:
    """被拒绝条目的记录（含在批次结果中，不进入存储）。"""

    index: int
    raw: object
    reason: RejectReason
    detail: str


@dataclass(frozen=True, slots=True)
class DegradedEntry:
    """降级条目的记录（已入库，但带有可解释的降级说明）。"""

    index: int
    indicator: str
    source: str
    reasons: tuple[DegradeReason, ...]
    detail: str


@dataclass(frozen=True, slots=True)
class BatchResult:
    """一个批次提交的完整结果（幂等重放时原样返回）。"""

    batch_id: str
    accepted: int
    updated: int
    rejected: int
    degraded: int
    replayed: bool
    rejected_entries: tuple[RejectedEntry, ...]
    degraded_entries: tuple[DegradedEntry, ...]
    indicators: tuple[str, ...]
