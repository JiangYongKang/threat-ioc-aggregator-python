"""基于 data/sources 本地情报文件的端到端测试：结论稳定、可追溯、可重放。"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from app.feed_loader import ingest_feed_dir
from app.service import AggregatorService
from app.store import IndicatorStore

FEED_DIR = Path(__file__).resolve().parent.parent / "data" / "sources"
NOW = datetime(2026, 9, 23, 12, 0, 0)


def test_feed_scenario_conclusions(caplog) -> None:
    service = AggregatorService(IndicatorStore())
    with caplog.at_level(logging.INFO, logger="ioc_aggregator"):
        first_results = ingest_feed_dir(service, FEED_DIR)
        # 再触发一次重放：必须全部 replayed，且结论稳定
        replay_results = ingest_feed_dir(service, FEED_DIR)

    log_text = caplog.text
    # 首次入库日志必须含输入批次与判定依据
    assert "收到批次 batch_id=batch-b-001" in log_text
    assert "判定依据" in log_text
    assert all(r.replayed for r in replay_results)

    active = {i["indicator"]: i for i in service.query(now=NOW)}
    # 1) 三来源汇聚为一份，置信度取最高，来源可追溯
    shared = active["ip:185.220.101.42"]
    assert shared["sources"] == ["vendor_a", "vendor_b", "vendor_c"]
    assert shared["confidence"] == "high"
    assert set(shared["confidence_sources"]) <= {"vendor_b", "vendor_c"}

    # 2) 已过期的 sha256/url 不在默认结果中
    assert "hash_sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" not in active
    assert "url:http://bad.example.test/path" not in active

    # 3) 全来源撤回的域名不在默认结果中，但在 include_inactive 中可追溯为 revoked
    assert "domain:evil.example.com" not in active
    revoked = service.get("domain:evil.example.com", now=NOW)
    assert revoked["status"] == "revoked"

    # 4) 非法 IP 与缺值条目被拒绝，原因可区分；好条目仍入库
    batch_b = next(r for r in first_results if r.batch_id == "batch-b-001")
    assert {r.reason for r in batch_b.rejected} == {"invalid_value", "missing_value"}
    assert {d.indicator for d in batch_b.degraded} == {
        "ip:185.220.101.42",
        "domain:www.malware-drop.test",
        "url:http://bad.example.test/path",
    }

    # 5) 空批次文件被整批拒绝且未登记
    assert not service.store.has_batch("batch-bad-001")


def test_replay_is_stable() -> None:
    service = AggregatorService(IndicatorStore())
    ingest_feed_dir(service, FEED_DIR)
    before = service.store.stats(NOW)
    results = ingest_feed_dir(service, FEED_DIR)
    after = service.store.stats(NOW)
    # 重放前后指标与批次数量完全一致
    assert before == after
    assert all(r.replayed for r in results)
    # 结论稳定：再查一次，序列化结果一致
    first = service.query(now=NOW)
    second = service.query(now=NOW)
    assert first == second
