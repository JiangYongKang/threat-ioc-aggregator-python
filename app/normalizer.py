"""来源条目归一化：字段不一致/残缺时给出可区分的拒绝或降级原因。"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from app.exceptions import EntryRejected
from app.models import DegradeReason, RejectReason, SourceObservation

# 各来源可能使用的字段别名 -> 统一字段
_FIELD_ALIASES: dict[str, str] = {
    "type": "ioc_type",
    "ioc_type": "ioc_type",
    "indicator_type": "ioc_type",
    "kind": "ioc_type",
    "value": "value",
    "indicator": "value",
    "ioc": "value",
    "data": "value",
    "source": "source",
    "feed": "source",
    "provider": "source",
    "confidence": "confidence",
    "score": "confidence",
    "severity": "confidence",
    "first_seen": "first_seen", "first_seen_ts": "first_seen",
    "last_seen": "last_seen", "last_seen_ts": "last_seen",
    "seen": "last_seen", "observed_at": "last_seen",
    "valid_until": "valid_until",
    "expires_at": "valid_until",
    "expiry": "valid_until",
    "expiration": "valid_until",
    "tags": "tags",
    "labels": "tags",
    "threat_types": "tags",
    "revoked": "revoked",
    "deleted": "revoked",
    "status": "status",
}

_TYPE_ALIASES: dict[str, str] = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ipaddr": "ip", "ip-address": "ip",
    "domain": "domain", "dom": "domain", "hostname": "domain", "host": "domain",
    "url": "url", "uri": "url",
    "md5": "hash_md5", "hash_md5": "hash_md5",
    "sha1": "hash_sha1", "hash_sha1": "hash_sha1",
    "sha256": "hash_sha256", "hash_sha256": "hash_sha256",
    "hash": "hash_sha256",
    "email": "email", "email_addr": "email", "mail": "email",
}

_KNOWN_FIELDS = frozenset(_FIELD_ALIASES.values())

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


def _resolve(raw: dict) -> dict:
    """按别名把来源字段归一到统一字段，后出现的标准名覆盖别名。"""
    resolved: dict = {}
    for key, value in raw.items():
        canonical = _FIELD_ALIASES.get(key.lower()) if isinstance(key, str) else None
        if canonical is None:
            continue
        resolved.setdefault(canonical, value)
    return resolved


def parse_ts(value: object) -> datetime | None:
    """解析时间字段；无法解析返回 None（调用方区分“缺失”与“非法”）。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return _as_naive(value)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value))
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return _as_naive(datetime.fromisoformat(text))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(text, fmt)
                except ValueError:
                    continue
    return None


def _as_naive(dt: datetime) -> datetime:
    """统一使用 naive 本地时间比较，避免 aware/naive 混用报错。"""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def canonicalize(ioc_type: str, value: str) -> str:
    """按类型做值归一化；值与类型不匹配时抛 EntryRejected(INVALID_VALUE)。"""
    v = value.strip()
    if ioc_type == "ip":
        candidate = v
        # 兼容来源给出的前导零写法（如 001.002.003.004）：先去前导零再校验。
        if re.match(r"^\d{1,4}(\.\d{1,4}){3}$", candidate):
            candidate = ".".join(str(int(p)) for p in candidate.split("."))
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise EntryRejected(
                RejectReason.INVALID_VALUE.value, f"不是合法 IP: {value!r}"
            ) from exc
    if ioc_type == "domain":
        low = v.lower().rstrip(".")
        if not _DOMAIN_RE.match(low):
            raise EntryRejected(
                RejectReason.INVALID_VALUE.value, f"不是合法域名: {value!r}"
            )
        return low
    if ioc_type == "url":
        if not re.match(r"^https?://[^\s]+$", v, flags=re.IGNORECASE):
            raise EntryRejected(
                RejectReason.INVALID_VALUE.value, f"不是合法 http(s) URL: {value!r}"
            )
        return v
    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        low = v.lower()
        pattern = {
            "hash_md5": _MD5_RE,
            "hash_sha1": _SHA1_RE,
            "hash_sha256": _SHA256_RE,
        }[ioc_type]
        if not pattern.match(low):
            raise EntryRejected(
                RejectReason.INVALID_VALUE.value,
                f"不是合法的 {ioc_type}: {value!r}",
            )
        return low
    if ioc_type == "email":
        low = v.lower()
        if not _EMAIL_RE.match(low):
            raise EntryRejected(
                RejectReason.INVALID_VALUE.value, f"不是合法邮箱: {value!r}"
            )
        return low
    raise EntryRejected(RejectReason.UNKNOWN_TYPE.value, ioc_type)


def validate_ioc_value(ioc_type: str, value: str) -> bool:
    """按类型对指标值做基本格式校验。"""
    try:
        canonicalize(ioc_type, value)
        return True
    except EntryRejected:
        return False


def _parse_confidence(value: object) -> tuple[object, bool]:
    """返回 (Confidence 或 None, 是否非法)。缺失/无法识别时降级为 low。"""
    if value is None:
        return None, False
    from app.models import Confidence

    if isinstance(value, str):
        text = value.strip().lower()
        word_level = {
            "low": Confidence.LOW,
            "info": Confidence.LOW,
            "medium": Confidence.MEDIUM,
            "med": Confidence.MEDIUM,
            "moderate": Confidence.MEDIUM,
            "high": Confidence.HIGH,
            "critical": Confidence.HIGH,
        }
        if text in word_level:
            return word_level[text], False
        try:
            value = float(text)
        except ValueError:
            return None, True
    if isinstance(value, bool):
        return None, True
    if isinstance(value, (int, float)):
        if value < 0 or value > 100:
            return None, True
        if value <= 1:  # 0..1 比例制
            score = int(round(value * 100))
        else:
            score = int(round(value))
        level = 1 if score < 34 else 2 if score < 67 else 3
        return [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH][level - 1], False
    return None, True


def _is_revoked(raw_status: object, revoked_flag: object) -> tuple[bool, bool]:
    """返回 (revoked, revoked_explicit)。"""
    explicit = False
    revoked = False
    if isinstance(raw_status, str):
        status_text = raw_status.strip().lower()
        if status_text in ("revoked", "withdrawn", "deleted", "false_positive", "inactive"):
            revoked = True
            explicit = True
        elif status_text in ("active", "malicious", "sighting"):
            revoked = False
            explicit = True
    if isinstance(revoked_flag, bool):
        revoked = revoked_flag
        explicit = True
    elif isinstance(revoked_flag, str) and revoked_flag.strip():
        revoked = revoked_flag.strip().lower() in ("true", "1", "yes", "revoked")
        explicit = True
    return revoked, explicit


def normalize_entry(raw: dict, *, default_source: str = "unknown") -> SourceObservation:
    """把一个来源原始条目归一为 SourceObservation。

    - 无法归一（关键字段缺失/非法）时抛 EntryRejected，reason 可区分。
    - 可入库但字段残缺时，在 degrade_reasons 中记录降级原因。
    """
    if not isinstance(raw, dict):
        raise EntryRejected(RejectReason.INVALID_VALUE.value, f"条目不是对象: {type(raw).__name__}")

    # 未识别字段 -> 降级信息（不丢弃语义：原始条目仍保留在批次结果中）。
    unknown_fields = sorted(
        k for k in raw
        if not (isinstance(k, str) and (k.lower() in _FIELD_ALIASES))
    )

    resolved = _resolve(raw)

    # --- 类型 ---
    raw_type = resolved.get("ioc_type")
    if raw_type is None or (isinstance(raw_type, str) and not raw_type.strip()):
        raise EntryRejected(RejectReason.MISSING_TYPE.value, "缺少 ioc_type/type 字段")
    if not isinstance(raw_type, str):
        raise EntryRejected(RejectReason.INVALID_VALUE.value, f"ioc_type 不是字符串: {raw_type!r}")
    type_key = raw_type.strip().lower()
    if type_key not in _TYPE_ALIASES:
        raise EntryRejected(RejectReason.UNKNOWN_TYPE.value, f"未知指标类型: {raw_type!r}")

    # --- 值 ---
    raw_value = resolved.get("value")
    if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
        raise EntryRejected(RejectReason.MISSING_VALUE.value, "缺少 value/indicator 字段")
    if not isinstance(raw_value, str):
        raise EntryRejected(RejectReason.INVALID_VALUE.value, f"指标值不是字符串: {raw_value!r}")

    revoked, _revoked_explicit = _is_revoked(resolved.get("status"), resolved.get("revoked"))

    from app.models import IOCTypes

    ioc_type = IOCTypes(_TYPE_ALIASES[type_key])
    canonical = canonicalize(ioc_type.value, raw_value)
    indicator = f"{ioc_type.value}:{canonical}"

    # --- 来源 ---
    source = resolved.get("source")
    source = source.strip() if isinstance(source, str) and source.strip() else default_source

    # --- 置信度（可缺失：降级为 low） ---
    degrade: set[str] = set()
    confidence, bad_conf = _parse_confidence(resolved.get("confidence"))
    if bad_conf:
        raise EntryRejected(
            RejectReason.INVALID_CONFIDENCE.value,
            f"非法置信度: {resolved.get('confidence')!r}",
        )
    if confidence is None:
        from app.models import Confidence

        confidence = Confidence.LOW
        degrade.add(DegradeReason.MISSING_CONFIDENCE.value)

    # --- 时间 ---
    now = datetime.now()
    first_seen = parse_ts(resolved.get("first_seen"))
    last_seen = parse_ts(resolved.get("last_seen"))
    if resolved.get("first_seen") is not None and first_seen is None:
        raise EntryRejected(
            RejectReason.INVALID_TIMESTAMP.value, f"非法 first_seen: {resolved.get('first_seen')!r}"
        )
    if resolved.get("last_seen") is not None and last_seen is None:
        raise EntryRejected(
            RejectReason.INVALID_TIMESTAMP.value, f"非法 last_seen: {resolved.get('last_seen')!r}"
        )
    if last_seen is None and first_seen is not None:
        last_seen = first_seen
    if first_seen is None and last_seen is not None:
        first_seen = last_seen
    if first_seen is None and last_seen is None:
        first_seen = last_seen = now
        degrade.add(DegradeReason.MISSING_TIMESTAMP.value)
    if first_seen > last_seen:
        first_seen, last_seen = last_seen, first_seen

    # --- 有效期 ---
    raw_until = resolved.get("valid_until")
    valid_until = parse_ts(raw_until)
    if raw_until is not None and valid_until is None:
        raise EntryRejected(
            RejectReason.INVALID_TIMESTAMP.value, f"非法 valid_until: {raw_until!r}"
        )
    if valid_until is None and not revoked:
        # 未给出有效期：不强制过期，但记录降级，便于解释“为何一直有效”。
        degrade.add(DegradeReason.MISSING_VALID_UNTIL.value)

    # --- 标签 ---
    raw_tags = resolved.get("tags")
    tags: frozenset[str]
    if raw_tags is None:
        tags = frozenset()
        degrade.add(DegradeReason.MISSING_TAGS.value)
    elif isinstance(raw_tags, str):
        tags = frozenset(t.strip() for t in re.split(r"[,;|]", raw_tags) if t.strip())
    elif isinstance(raw_tags, (list, tuple, set)):
        tags = frozenset(str(t).strip() for t in raw_tags if str(t).strip())
    else:
        raise EntryRejected(RejectReason.INVALID_VALUE.value, f"tags 字段类型非法: {type(raw_tags).__name__}")

    if unknown_fields:
        degrade.add(DegradeReason.UNKNOWN_EXTRA_FIELDS.value + ":" + ",".join(unknown_fields))

    return SourceObservation(
        indicator=indicator,
        ioc_type=ioc_type,
        value=canonical,
        source=source,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        valid_until=valid_until,
        revoked=revoked,
        tags=tags,
        degrade_reasons=frozenset(degrade),
    )


__all__ = ["normalize_entry", "validate_ioc_value", "canonicalize", "parse_ts",
           "RejectReason", "DegradeReason"]
