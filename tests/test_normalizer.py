"""归一化测试：字段差异、残缺条目的拒绝/降级必须可区分。"""

from __future__ import annotations

import pytest

from app.models import DegradeReason, IocType, RejectReason, Verdict
from app.normalizer import normalize_entry


def _show(title, raw, entry, reason, detail):
    print(f"\n[输入批次] {title}: {raw}")
    if reason:
        print(f"[判定依据] 拒绝 {reason.value}: {detail}")
    else:
        print(f"[判定依据] 归一成功 indicator={entry.indicator} "
              f"type={entry.ioc_type.value} source={entry.source} "
              f"confidence={entry.confidence} verdict={entry.verdict.value} "
              f"降级={[d.value for d in entry.degrade_reasons]}")


def test_full_entry_with_source_specific_aliases():
    raw = {"dst_ip": "8.8.8.8", "threat_level": "c2", "weight": 0.9,
           "malware_family": "Emotet",
           "published_at": "2026-09-20T00:00:00Z", "ttl_days": 10}
    entry, reason, _ = normalize_entry(raw, 0, source_hint="beta")
    _show("beta 来源别名", raw, entry, reason, "")
    assert reason is None
    assert entry.indicator == "8.8.8.8"
    assert entry.ioc_type is IocType.IP
    assert entry.verdict is Verdict.MALICIOUS
    assert entry.confidence == 0.9
    assert entry.source == "beta"
    assert entry.tags == frozenset({"Emotet"})


def test_missing_indicator_rejected():
    raw = {"source": "alpha", "confidence": 0.5}
    entry, reason, detail = normalize_entry(raw, 1)
    _show("缺指标值", raw, entry, reason, detail)
    assert reason is RejectReason.MISSING_INDICATOR
    assert entry is None


def test_blank_indicator_rejected():
    raw = {"indicator": "   ", "source": "alpha"}
    entry, reason, detail = normalize_entry(raw, 2)
    _show("空白指标值", raw, entry, reason, detail)
    assert reason is RejectReason.EMPTY_INDICATOR


def test_missing_source_rejected_without_hint():
    raw = {"indicator": "1.1.1.1", "type": "ip"}
    entry, reason, detail = normalize_entry(raw, 3)
    _show("缺来源且无兜底", raw, entry, reason, detail)
    assert reason is RejectReason.MISSING_SOURCE


def test_missing_type_and_confidence_degrades():
    raw = {"value": "bad.example.com", "source": "alpha"}
    entry, reason, detail = normalize_entry(raw, 4)
    _show("缺类型缺置信度", raw, entry, reason, detail)
    assert reason is None
    assert entry.ioc_type is IocType.DOMAIN
    assert DegradeReason.MISSING_IOC_TYPE in entry.degrade_reasons
    assert DegradeReason.MISSING_CONFIDENCE in entry.degrade_reasons
    assert DegradeReason.MISSING_VALIDITY_DAYS in entry.degrade_reasons


def test_conflicting_type_rejected():
    raw = {"value": "8.8.8.8", "type": "domain", "source": "a"}
    entry, reason, detail = normalize_entry(raw, 5)
    _show("类型与值形态矛盾", raw, entry, reason, detail)
    assert reason is RejectReason.CONFLICTING_TYPE


def test_unrecognized_type_inferred_with_degrade():
    raw = {"value": "9.9.9.9", "type": "weird-thing", "source": "a"}
    entry, reason, detail = normalize_entry(raw, 6)
    _show("类型非法按值推断", raw, entry, reason, detail)
    assert reason is None
    assert entry.ioc_type is IocType.IP
    assert DegradeReason.INFERRED_IOC_TYPE in entry.degrade_reasons


@pytest.mark.parametrize("value", ["1.2", "not-a-number", True, None, ["1"]])
def test_invalid_confidence_rejected(value):
    raw = {"value": "1.1.1.1", "type": "ip", "source": "a",
           "confidence": value}
    entry, reason, detail = normalize_entry(raw, 7)
    _show(f"非法置信度 {value!r}", raw, entry, reason, detail)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # 数值越界走裁剪降级分支（本参数组中无数值越界项，数值都是非法类型）
        pytest.fail("参数组不应包含越界数值")
    assert reason is RejectReason.INVALID_CONFIDENCE


def test_out_of_range_confidence_clamped():
    raw = {"value": "1.1.1.1", "type": "ip", "source": "a",
           "confidence": 1.5}
    entry, reason, detail = normalize_entry(raw, 8)
    _show("置信度越界裁剪", raw, entry, reason, detail)
    assert reason is None
    assert entry.confidence == 1.0
    assert DegradeReason.LOW_CONFIDENCE_CLAMPED in entry.degrade_reasons


def test_non_object_entry_rejected():
    entry, reason, detail = normalize_entry("junk-string", 9)
    _show("非对象条目", "junk-string", entry, reason, detail)
    assert reason is RejectReason.NON_OBJECT_ENTRY


def test_indicator_canonicalization_for_dedup():
    raw_upper = {"value": "Bad.Example.COM", "type": "domain",
                 "source": "a"}
    raw_space = {"value": "  bad.example.com  ", "type": "domain",
                 "source": "b"}
    e1, _, _ = normalize_entry(raw_upper, 10)
    e2, _, _ = normalize_entry(raw_space, 11)
    print(f"\n[输入批次] {raw_upper['value']!r} 与 {raw_space['value']!r}")
    print(f"[判定依据] 规范化后均为 {e1.indicator!r} / {e2.indicator!r}")
    assert e1.indicator == e2.indicator == "bad.example.com"


def test_invalid_timestamp_rejected():
    raw = {"value": "1.1.1.1", "type": "ip", "source": "a",
           "first_seen": "not-a-time"}
    entry, reason, detail = normalize_entry(raw, 12)
    _show("非法时间戳", raw, entry, reason, detail)
    assert reason is RejectReason.INVALID_TIMESTAMP


def test_hash_inference_and_lowercasing():
    raw = {"value": "A" * 64, "source": "a"}
    entry, reason, detail = normalize_entry(raw, 13)
    _show("SHA256 缺类型", raw, entry, reason, detail)
    assert reason is None
    assert entry.ioc_type is IocType.HASH
    assert entry.indicator == "a" * 64
