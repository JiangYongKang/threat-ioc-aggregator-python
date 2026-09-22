"""多来源情报归一化：字段不一致不静默丢弃，区分拒绝与降级。

归一化产出三种结果：
- 成功且完整：NormalizedEntry，degrade_reasons 为空；
- 降级入库：NormalizedEntry，degrade_reasons 非空（条目仍可用）；
- 拒绝：返回 (None, RejectReason, 详情)，条目不入库。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from app.lifecycle import default_expiry, now_iso, parse_ts, parse_ts_iso
from app.logging_utils import get_logger
from app.models import (
    DegradeReason,
    IocType,
    RejectReason,
    Verdict,
)

logger = get_logger(__name__)


# --------------------------------------------------------------- 中间模型

@dataclass(slots=True)
class NormalizedEntry:
    """归一化后的单条情报（聚合前的中间产物）。"""

    indicator: str = ""
    ioc_type: IocType = IocType.UNKNOWN
    source: str = ""
    confidence: float = 0.0
    verdict: Verdict = Verdict.UNKNOWN
    tags: frozenset[str] = frozenset()
    first_seen: str = ""
    last_seen: str = ""
    expires_at: str | None = None
    revoked: bool = False
    degrade_reasons: list[DegradeReason] = field(default_factory=list)
    degrade_detail: str = ""


# --------------------------------------------------------------- 来源画像

# 各来源的通用字段别名：原始字段名 -> 标准字段名
_COMMON_ALIASES: dict[str, str] = {
    # 指标值
    "indicator": "indicator", "ioc": "indicator", "value": "indicator",
    "observable": "indicator", "artifact": "indicator",
    # 类型
    "type": "ioc_type", "ioc_type": "ioc_type", "itype": "ioc_type",
    "kind": "ioc_type", "indicator_type": "ioc_type",
    # 来源
    "source": "source", "feed": "source", "origin": "source",
    "source_name": "source", "provider": "source",
    # 置信度
    "confidence": "confidence", "score": "confidence",
    "conf": "confidence", "certainty": "confidence",
    # 判定
    "verdict": "verdict", "classification": "verdict",
    "threat_type": "verdict", "status_label": "verdict", "label": "verdict",
    # 标签
    "tags": "tags", "labels": "tags", "families": "tags",
    # 时间
    "first_seen": "first_seen", "seen_first": "first_seen",
    "published_at": "first_seen", "created_at": "first_seen",
    "last_seen": "last_seen", "seen_last": "last_seen",
    "updated_at": "last_seen", "timestamp": "last_seen", "ts": "last_seen",
    # 有效期
    "expires_at": "expires_at", "expire_at": "expires_at",
    "expiration": "expires_at", "valid_until": "expires_at",
    "validity_days": "validity_days", "ttl_days": "validity_days",
    # 撤回
    "revoked": "revoked", "withdrawn": "revoked", "deleted": "revoked",
}


@dataclass(frozen=True, slots=True)
class SourceProfile:
    """来源画像：字段别名、默认置信度与默认有效期（天）。"""

    name: str
    field_aliases: dict[str, str] = field(default_factory=dict)
    default_confidence: float = 0.5
    default_validity_days: int = 30

    def resolve(self, raw: dict) -> dict[str, object]:
        """按来源别名 + 通用别名把原始 dict 映射到标准字段。"""

        resolved: dict[str, object] = {}
        for key, value in raw.items():
            if not isinstance(key, str):
                continue
            std = self.field_aliases.get(key, _COMMON_ALIASES.get(key.lower()))
            if std is not None and std not in resolved:
                resolved[std] = value
        return resolved


# 预置来源画像（本地情报文件可通过文件名匹配）
SOURCE_PROFILES: dict[str, SourceProfile] = {
    "alpha": SourceProfile("alpha", default_confidence=0.6, default_validity_days=30),
    "beta": SourceProfile(
        "beta",
        field_aliases={"dst_ip": "indicator", "threat_level": "verdict",
                       "weight": "confidence", "malware_family": "tags"},
        default_confidence=0.5,
        default_validity_days=14,
    ),
    "gamma": SourceProfile(
        "gamma",
        field_aliases={"observable_value": "indicator", "category": "ioc_type",
                       "trust": "confidence", "until": "expires_at"},
        default_confidence=0.7,
        default_validity_days=60,
    ),
}
DEFAULT_PROFILE = SourceProfile("unknown", default_confidence=0.5,
                                default_validity_days=30)


# --------------------------------------------------------------- 值推断

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")

_TYPE_TOKENS: dict[str, IocType] = {
    "ip": IocType.IP, "ipv4": IocType.IP, "ipv6": IocType.IP, "addr": IocType.IP,
    "domain": IocType.DOMAIN, "dns": IocType.DOMAIN, "hostname": IocType.DOMAIN,
    "url": IocType.URL, "uri": IocType.URL, "link": IocType.URL,
    "hash": IocType.HASH, "md5": IocType.HASH, "sha1": IocType.HASH,
    "sha256": IocType.HASH, "filehash": IocType.HASH,
    "email": IocType.EMAIL, "mail": IocType.EMAIL, "email_address": IocType.EMAIL,
}
_VERDICT_TOKENS: dict[str, Verdict] = {
    "malicious": Verdict.MALICIOUS, "malware": Verdict.MALICIOUS,
    "c2": Verdict.MALICIOUS, "c&c": Verdict.MALICIOUS,
    "phishing": Verdict.MALICIOUS, "bad": Verdict.MALICIOUS, "threat": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS, "suspect": Verdict.SUSPICIOUS,
    "grayware": Verdict.SUSPICIOUS, "greyware": Verdict.SUSPICIOUS,
    "unknown": Verdict.UNKNOWN, "unrated": Verdict.UNKNOWN, "": Verdict.UNKNOWN,
    "benign": Verdict.BENIGN, "clean": Verdict.BENIGN, "safe": Verdict.BENIGN,
    "whitelist": Verdict.BENIGN, "whitelisted": Verdict.BENIGN,
}


def infer_ioc_type(value: str) -> IocType:
    """按指标值形态推断类型。"""

    if _IP_RE.match(value):
        try:
            ipaddress.ip_address(value)
            return IocType.IP
        except ValueError:
            pass
    if _URL_RE.match(value):
        return IocType.URL
    if _EMAIL_RE.match(value):
        return IocType.EMAIL
    if _HASH_RE.match(value):
        return IocType.HASH
    if _DOMAIN_RE.match(value):
        return IocType.DOMAIN
    return IocType.UNKNOWN


def canonicalize_indicator(value: str, ioc_type: IocType) -> str:
    """对指标值做轻量规范化（小写、去空白），保证同一指标可去重。"""

    text = value.strip()
    if ioc_type in (IocType.DOMAIN, IocType.EMAIL, IocType.URL, IocType.HASH):
        text = text.lower()
    if ioc_type is IocType.URL:
        text = text.rstrip("/")
    return text


# --------------------------------------------------------------- 归一化主流程

def normalize_entry(
    raw: object,
    index: int,
    source_hint: str | None = None,
    *,
    profile: SourceProfile | None = None,
) -> tuple[NormalizedEntry | None, RejectReason | None, str]:
    """把一条原始情报归一到统一模型。

    返回 (归一化条目或 None, 拒绝原因或 None, 说明)。
    归一化成功（含降级）时拒绝原因为 None。
    """

    if not isinstance(raw, dict):
        return None, RejectReason.NON_OBJECT_ENTRY, (
            f"条目 #{index} 不是 JSON 对象，实际类型 {type(raw).__name__}"
        )

    prof = profile or SOURCE_PROFILES.get(str(source_hint or ""), DEFAULT_PROFILE)
    fields = prof.resolve(raw)
    degrades: list[DegradeReason] = []
    details: list[str] = []

    # ---- 指标值（缺失/空白 => 拒绝） ----
    indicator_raw = fields.get("indicator")
    if "indicator" not in fields:
        return None, RejectReason.MISSING_INDICATOR, (
            f"条目 #{index} 缺少指标值字段（indicator/value/ioc 等）")
    if not isinstance(indicator_raw, str):
        return None, RejectReason.MISSING_INDICATOR, (
            f"条目 #{index} 指标值不是字符串，实际类型 "
            f"{type(indicator_raw).__name__}")
    if not indicator_raw.strip():
        return None, RejectReason.EMPTY_INDICATOR, f"条目 #{index} 指标值为空白"

    # ---- 来源（缺失 => 拒绝；提示来源可兜底并记降级） ----
    source = fields.get("source")
    if source is None:
        if source_hint:
            source = source_hint
            details.append("条目缺少来源字段，使用批次/文件来源兜底")
        else:
            return None, RejectReason.MISSING_SOURCE, (
                f"条目 #{index} 缺少来源标识（source/feed 等）")
    if not isinstance(source, str) or not source.strip():
        return None, RejectReason.MISSING_SOURCE, (
            f"条目 #{index} 来源标识为空或非字符串")
    source = source.strip()

    # ---- 类型（缺失/非法 => 按值推断，降级） ----
    type_token = fields.get("ioc_type")
    ioc_type: IocType
    if type_token is None:
        ioc_type = infer_ioc_type(indicator_raw.strip())
        degrades.append(DegradeReason.MISSING_IOC_TYPE)
        details.append(f"缺少类型字段，按值推断为 {ioc_type.value}")
    elif not isinstance(type_token, str) or type_token.strip().lower() not in _TYPE_TOKENS:
        ioc_type = infer_ioc_type(indicator_raw.strip())
        degrades.append(DegradeReason.INFERRED_IOC_TYPE)
        details.append(f"类型值 {type_token!r} 无法识别，按值推断为 {ioc_type.value}")
    else:
        ioc_type = _TYPE_TOKENS[type_token.strip().lower()]
        if ioc_type is IocType.UNKNOWN:
            return None, RejectReason.UNSUPPORTED_IOC_TYPE, (
                f"条目 #{index} 指标类型不支持: {type_token!r}")

    indicator = canonicalize_indicator(indicator_raw, ioc_type)
    inferred_now = infer_ioc_type(indicator)
    if inferred_now is not IocType.UNKNOWN and inferred_now is not ioc_type:
        return None, RejectReason.CONFLICTING_TYPE, (
            f"条目 #{index} 声明类型 {ioc_type.value} 与指标值形态 "
            f"{inferred_now.value} 矛盾: {indicator!r}")
    if ioc_type is IocType.UNKNOWN:
        return None, RejectReason.UNSUPPORTED_IOC_TYPE, (
            f"条目 #{index} 指标值无法归类到受支持类型: {indicator!r}")

    # ---- 置信度（键缺失 => 默认值降级；显式 null/非法类型 => 拒绝） ----
    confidence = prof.default_confidence
    if "confidence" not in fields:
        degrades.append(DegradeReason.MISSING_CONFIDENCE)
        details.append(f"缺少置信度，使用来源默认值 {prof.default_confidence}")
    else:
        conf_raw = fields["confidence"]
        if conf_raw is None or isinstance(conf_raw, bool) or not isinstance(
            conf_raw, (int, float)
        ):
            return None, RejectReason.INVALID_CONFIDENCE, (
                f"条目 #{index} 置信度不是数值: {conf_raw!r}")
        conf_val = float(conf_raw)
        if conf_val < 0.0 or conf_val > 1.0:
            clamped = min(1.0, max(0.0, conf_val))
            confidence = clamped
            degrades.append(DegradeReason.LOW_CONFIDENCE_CLAMPED)
            details.append(f"置信度 {conf_val} 越界，裁剪为 {clamped}")
        else:
            confidence = conf_val

    # ---- 判定（缺失/非法 => unknown，不阻断入库） ----
    verdict_raw = fields.get("verdict")
    if verdict_raw is None or (isinstance(verdict_raw, str)
                               and verdict_raw.strip().lower() in ("", "unknown", "unrated")):
        verdict = Verdict.UNKNOWN
    elif not isinstance(verdict_raw, str) or verdict_raw.strip().lower() not in _VERDICT_TOKENS:
        verdict = Verdict.UNKNOWN
        details.append(f"判定值 {verdict_raw!r} 无法识别，按 unknown 处理")
    else:
        verdict = _VERDICT_TOKENS[verdict_raw.strip().lower()]

    # ---- 标签（缺失 => 降级；含非字符串 => 过滤并降级） ----
    tags_raw = fields.get("tags")
    tags: frozenset[str]
    if tags_raw is None:
        tags = frozenset()
        degrades.append(DegradeReason.MISSING_TAGS)
        details.append("缺少标签字段")
    elif isinstance(tags_raw, str):
        tags = frozenset({tags_raw.strip()}) if tags_raw.strip() else frozenset()
    elif isinstance(tags_raw, (list, tuple, set, frozenset)):
        str_tags = {t.strip() for t in tags_raw if isinstance(t, str) and t.strip()}
        if len(str_tags) != len([t for t in tags_raw if isinstance(t, str) and t.strip()]):
            degrades.append(DegradeReason.NON_STRING_TAGS)
            details.append("标签中存在非字符串项，已过滤")
        tags = frozenset(str_tags)
    else:
        tags = frozenset()
        degrades.append(DegradeReason.NON_STRING_TAGS)
        details.append(f"标签字段类型异常 {type(tags_raw).__name__}，按空标签处理")

    # ---- 时间 ----
    try:
        if "first_seen" in fields:
            first_seen = parse_ts_iso(fields["first_seen"])
        else:
            first_seen = now_iso()
            details.append("缺少 first_seen，使用当前时间")
        if "last_seen" in fields:
            last_seen = parse_ts_iso(fields["last_seen"])
        else:
            last_seen = first_seen
    except ValueError as exc:
        return None, RejectReason.INVALID_TIMESTAMP, f"条目 #{index} {exc}"
    if parse_ts(last_seen) < parse_ts(first_seen):
        last_seen = first_seen

    # ---- 有效期 ----
    expires_at: str | None
    if fields.get("expires_at") is not None:
        try:
            expires_at = parse_ts_iso(fields["expires_at"])
        except ValueError as exc:
            return None, RejectReason.INVALID_TIMESTAMP, f"条目 #{index} {exc}"
    elif fields.get("validity_days") is not None:
        vd = fields["validity_days"]
        if isinstance(vd, bool) or not isinstance(vd, (int, float)) or vd <= 0:
            return None, RejectReason.INVALID_TIMESTAMP, (
                f"条目 #{index} validity_days 非法: {vd!r}")
        expires_at = default_expiry(first_seen, int(vd))
    else:
        expires_at = default_expiry(first_seen, prof.default_validity_days)
        degrades.append(DegradeReason.MISSING_VALIDITY_DAYS)
        details.append(
            f"缺少有效期，使用来源默认 {prof.default_validity_days} 天")

    # ---- 撤回标记 ----
    revoked_raw = fields.get("revoked", False)
    revoked = bool(revoked_raw) if isinstance(revoked_raw, (bool, int, str)) else False
    if isinstance(revoked_raw, str):
        revoked = revoked_raw.strip().lower() in ("1", "true", "yes", "revoked")

    entry = NormalizedEntry(
        indicator=indicator,
        ioc_type=ioc_type,
        source=source,
        confidence=round(confidence, 3),
        verdict=verdict,
        tags=tags,
        first_seen=first_seen,
        last_seen=last_seen,
        expires_at=expires_at,
        revoked=revoked,
        degrade_reasons=degrades,
        degrade_detail="；".join(details),
    )
    return entry, None, ""
