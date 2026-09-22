"""去重、汇聚、生命周期测试：同指标多来源/先后投递只保留一份且可追溯。"""

from __future__ import annotations

import logging
from datetime import datetime

from app.models import LifecycleStatus
from app.service import AggregatorService

logger = logging.getLogger("ioc_aggregator.test")


def _entry(value: str = "1.2.3.4", **over) -> dict:
    base = {
        "type": "ip",
        "value": value,
        "source": "s1",
        "confidence": "low",
        "first_seen": "2026-09-01T00:00:00",
        "last_seen": "2026-09-05T00:00:00",
        "valid_until": "2026-09-20T00:00:00",
        "tags": ["t1"],
    }
    base.update(over)
    return base


def test_same_indicator_multiple_sources_deduped_and_traceable(service: AggregatorService) -> None:
    batch1 = {"batch_id": "b1", "entries": [_entry(source="s1", confidence=30)]}
    batch2 = {"batch_id": "b2", "entries": [_entry(source="s2", confidence=90,
                                                   last_seen="2026-09-10T00:00:00",
                                                   tags=["t2"])]}
    logger.info("输入批次1=%s", batch1)
    logger.info("输入批次2=%s 判定依据：同一 (ip,1.2.3.4) 跨来源只保留一份", batch2)
    r1 = service.submit_batch(batch1)
    r2 = service.submit_batch(batch2)
    assert r1.accepted_new == 1 and r2.accepted_new == 0 and r2.merged == 1

    items = service.query(now=datetime(2026, 9, 15))
    assert len(items) == 1
    item = items[0]
    assert item["sources"] == ["s1", "s2"]
    assert item["confidence"] == "high"
    assert item["confidence_sources"] == ["s2"]
    assert item["last_seen"] == "2026-09-10T00:00:00"
    assert set(item["tags"]) == {"t1", "t2"}
    # 每条来源观测都可追溯
    assert {o["source"] for o in item["source_observations"]} == {"s1", "s2"}


def test_value_canonicalization_dedup_across_spellings(service: AggregatorService) -> None:
    batches = [
        {"batch_id": "b1", "entries": [{"type": "ipv4", "value": "1.2.3.4", "source": "s1"}]},
        {"batch_id": "b2", "entries": [{"kind": "ip", "data": "001.002.003.004", "feed": "s2"}]},
    ]
    logger.info("输入批次=%s 判定依据：IP 规范化后应去重", batches)
    r1 = service.submit_batch(batches[0])
    r2 = service.submit_batch(batches[1])
    assert r1.accepted_new == 1
    assert r2.merged == 1
    assert service.store.stats()["indicators_total"] == 1


def test_same_source_repeated_delivery_keeps_one_observation(service: AggregatorService) -> None:
    r1 = service.submit_batch({"batch_id": "b1", "entries": [
        _entry(source="s1", first_seen="2026-09-01", last_seen="2026-09-05")]})
    r2 = service.submit_batch({"batch_id": "b2", "entries": [
        _entry(source="s1", first_seen="2026-09-03", last_seen="2026-09-09")]})
    logger.info("重复投递结果 r1=%s r2=%s 判定依据：同源只更新一条观测", r1.to_dict(), r2.to_dict())
    item = service.get("ip:1.2.3.4", now=datetime(2026, 9, 10))
    assert len(item["source_observations"]) == 1
    # first_seen 取最早，last_seen 取最晚，可解释
    assert item["first_seen"].startswith("2026-09-01")
    assert item["last_seen"].startswith("2026-09-09")


def test_expiry_boundary_is_strictly_after_deadline(service: AggregatorService) -> None:
    service.submit_batch({"batch_id": "b1", "entries": [_entry(valid_until="2026-09-20T12:00:00")]})
    ind = "ip:1.2.3.4"
    at_deadline = datetime(2026, 9, 20, 12, 0, 0)
    just_after = datetime(2026, 9, 20, 12, 0, 1)

    logger.info("过期边界 now==valid_until -> active；now>valid_until -> expired")
    assert service.get(ind, now=at_deadline)["status"] == LifecycleStatus.ACTIVE.value
    assert service.get(ind, now=just_after)["status"] == LifecycleStatus.EXPIRED.value
    # 默认查询在边界内可见，边界后不可见
    assert service.query(now=at_deadline) and not service.query(now=just_after)
    # include_inactive 仍可追溯
    assert service.query(now=just_after, include_inactive=True)[0]["status"] == "expired"


def test_revocation_disappears_from_default_query_but_traceable(service: AggregatorService) -> None:
    service.submit_batch({"batch_id": "b1", "entries": [
        _entry(source="s1", valid_until="2026-12-31"),
        _entry(value="5.6.7.8", source="s1", valid_until="2026-12-31")]})
    revoke = {"batch_id": "b2", "entries": [
        {"type": "ip", "value": "1.2.3.4", "source": "s1", "status": "revoked",
         "last_seen": "2026-09-21T00:00:00"},
        {"type": "ip", "value": "5.6.7.8", "source": "s2", "status": "revoked",
         "last_seen": "2026-09-21T00:00:00"},
    ]}
    logger.info("撤回批次=%s 判定依据：全来源撤回才 revoked；单来源撤回仍 active", revoke)
    service.submit_batch(revoke)
    now = datetime(2026, 9, 22)
    visible = service.query(now=now)
    assert [i["indicator"] for i in visible] == ["ip:5.6.7.8"]
    revoked_item = service.get("ip:1.2.3.4", now=now)
    assert revoked_item["status"] == "revoked"
    # 单来源撤回 5.6.7.8 仍 active，但保留撤回观测可追溯
    item = service.get("ip:5.6.7.8", now=now)
    assert item["status"] == "active"
    assert {o["source"]: o["revoked"] for o in item["source_observations"]} == {
        "s1": False, "s2": True
    }
