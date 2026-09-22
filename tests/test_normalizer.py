"""归一化测试：字段别名、值归一化、可区分的拒绝/降级原因。"""

from __future__ import annotations

import logging

import pytest

from app.exceptions import EntryRejected
from app.models import Confidence, DegradeReason, IOCTypes, RejectReason
from app.normalizer import canonicalize, normalize_entry, parse_ts

logger = logging.getLogger("ioc_aggregator.test")


def test_alias_fields_and_canonicalization() -> None:
    raw = {
        "kind": "ipv4",
        "data": " 8.8.8.8 ",
        "severity": 90,
        "observed_at": "2026-09-10T00:00:00Z",
        "expires_at": "2026-10-10",
        "threat_types": ["c2", " c2 ", "phishing"],
    }
    logger.info("输入条目=%s 判定：别名归一 + 值裁剪 + 标签去重", raw)
    obs = normalize_entry(raw, default_source="src")
    assert obs.indicator == "ip:8.8.8.8"
    assert obs.ioc_type is IOCTypes.IP
    assert obs.source == "src"
    assert obs.confidence is Confidence.HIGH
    assert obs.tags == frozenset({"c2", "phishing"})
    assert obs.valid_until is not None


def test_domain_canonicalized_lowercase_without_root_dot() -> None:
    obs = normalize_entry({"type": "domain", "value": "WWW.Example.COM.", "source": "s"})
    assert obs.indicator == "domain:www.example.com"


@pytest.mark.parametrize(
    "raw,reason",
    [
        ({"source": "s"}, RejectReason.MISSING_TYPE.value),
        ({"type": "ip"}, RejectReason.MISSING_VALUE.value),
        ({"type": "weird", "value": "x"}, RejectReason.UNKNOWN_TYPE.value),
        ({"type": "ip", "value": "999.1.1.1"}, RejectReason.INVALID_VALUE.value),
        ({"type": "sha256", "value": "xyz"}, RejectReason.INVALID_VALUE.value),
        ({"type": "md5", "value": "A" * 32, "confidence": "nope"},
         RejectReason.INVALID_CONFIDENCE.value),
        ({"type": "ip", "value": "1.1.1.1", "first_seen": "bad-ts"},
         RejectReason.INVALID_TIMESTAMP.value),
        ({"type": "ip", "value": "1.1.1.1", "valid_until": "bad-ts"},
         RejectReason.INVALID_TIMESTAMP.value),
    ],
)
def test_rejected_reasons_are_distinguishable(raw: dict, reason: str) -> None:
    logger.info("输入条目=%s 判定依据：必须以 reason=%s 拒绝", raw, reason)
    with pytest.raises(EntryRejected) as exc:
        normalize_entry(raw)
    assert exc.value.reason == reason


def test_missing_optional_fields_degrade_instead_of_drop() -> None:
    raw = {"type": "domain", "value": "a.example", "source": "s", "x_unknown": 1}
    logger.info("输入条目=%s 判定依据：缺 confidence/tags/时间/有效期 -> 降级入库", raw)
    obs = normalize_entry(raw)
    assert obs.confidence is Confidence.LOW
    reasons = obs.degrade_reasons
    assert DegradeReason.MISSING_CONFIDENCE.value in reasons
    assert DegradeReason.MISSING_TAGS.value in reasons
    assert DegradeReason.MISSING_TIMESTAMP.value in reasons
    assert DegradeReason.MISSING_VALID_UNTIL.value in reasons
    assert any(r.startswith(DegradeReason.UNKNOWN_EXTRA_FIELDS.value) for r in reasons)


def test_revoked_entry_does_not_require_valid_until() -> None:
    raw = {"type": "ip", "value": "10.0.0.1", "source": "s",
           "status": "withdrawn", "last_seen": "2026-09-01"}
    logger.info("输入条目=%s 判定依据：撤回条目不要求有效期", raw)
    obs = normalize_entry(raw)
    assert obs.revoked is True
    assert DegradeReason.MISSING_VALID_UNTIL.value not in obs.degrade_reasons


def test_confidence_levels() -> None:
    assert normalize_entry({"type": "ip", "value": "1.1.1.1", "confidence": 10}).confidence is Confidence.LOW
    assert normalize_entry({"type": "ip", "value": "1.1.1.2", "confidence": 50}).confidence is Confidence.MEDIUM
    assert normalize_entry({"type": "ip", "value": "1.1.1.3", "confidence": 0.95}).confidence is Confidence.HIGH
    assert normalize_entry({"type": "ip", "value": "1.1.1.4", "confidence": "medium"}).confidence is Confidence.MEDIUM


def test_parse_ts_formats_and_canonicalize() -> None:
    assert parse_ts("2026-09-01") is not None
    assert parse_ts(1756684800) is not None
    assert parse_ts("not-a-time") is None
    assert canonicalize("hash_md5", "A" * 32) == "a" * 32
