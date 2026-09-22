"""并发投递与重放的幂等性、非法批次的可区分失败与零污染测试。"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import pytest

from app.exceptions import BatchRejected
from app.models import BatchRejectReason
from app.service import AggregatorService

logger = logging.getLogger("ioc_aggregator.test")


def _batch(bid: str, n: int = 5) -> dict:
    return {
        "batch_id": bid,
        "source": "src",
        "entries": [
            {
                "type": "ip",
                "value": f"10.0.0.{i}",
                "confidence": 50,
                "last_seen": "2026-09-20T00:00:00",
                "valid_until": "2026-12-31T00:00:00",
                "tags": ["x"],
            }
            for i in range(n)
        ],
    }


def test_replay_same_batch_is_idempotent(service: AggregatorService) -> None:
    payload = _batch("dup-1")
    logger.info("输入批次=%s 判定依据：相同 batch_id 重放必须返回首次结果且无重复写入", payload)
    r1 = service.submit_batch(payload)
    r2 = service.submit_batch(payload)
    r3 = service.submit_batch(payload)
    assert r1.replayed is False
    assert (r2.replayed, r3.replayed) == (True, True)
    for r in (r1, r2, r3):
        assert (r.accepted_new, r.merged, r.accepted_total) == (5, 0, 5)
    assert service.store.stats()["indicators_total"] == 5
    assert service.store.stats()["batches_total"] == 1


def test_concurrent_same_batch_submitted_once(service: AggregatorService) -> None:
    payload = _batch("conc-1", n=8)
    logger.info("并发输入：20 个线程同时提交同一批次 %s", payload["batch_id"])
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: service.submit_batch(payload), range(20)))

    first = [r for r in results if not r.replayed]
    replays = [r for r in results if r.replayed]
    assert len(first) == 1, "恰好一个请求真正应用批次"
    assert len(replays) == 19
    assert all(r.accepted_total == 8 for r in results)
    stats = service.store.stats()
    assert stats["indicators_total"] == 8
    assert stats["batches_total"] == 1


def test_concurrent_distinct_batches_no_loss(service: AggregatorService) -> None:
    def payload_for(bid: str) -> dict:
        return {
            "batch_id": bid,
            "entries": [
                {"type": "ip", "value": f"172.16.{bid[-2:]}.{i}", "source": f"s{bid[-2:]}",
                 "confidence": "medium", "valid_until": "2026-12-31",
                 "last_seen": "2026-09-01"}
                for i in range(3)
            ],
        }

    bids = [f"b{idx:02d}" for idx in range(12)]
    logger.info("并发输入：%d 个不同批次，判定依据：无丢失、无重复", len(bids))
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda b: service.submit_batch(payload_for(b)), bids))

    assert sum(r.accepted_new for r in results) == 36
    assert service.store.stats()["indicators_total"] == 36
    assert len(service.query(now=datetime(2026, 10, 1))) == 36


def test_concurrent_overlapping_batches_merge_consistently(service: AggregatorService) -> None:
    # 多个批次包含部分相同指标：最终每个指标仍只有一份，且来源齐全。
    def payload_for(source: str) -> dict:
        return {
            "batch_id": f"batch-{source}",
            "entries": [
                {"type": "ip", "value": "192.168.0.1", "source": source,
                 "confidence": "low", "valid_until": "2026-12-31",
                 "last_seen": "2026-09-01"},
                {"type": "ip", "value": f"192.168.0.{10 + ord(source) - 96}",
                 "source": source, "confidence": "low", "valid_until": "2026-12-31",
                 "last_seen": "2026-09-01"},
            ],
        }

    sources = ["a", "b", "c", "d", "e"]
    logger.info("并发输入：%d 个批次共享指标 192.168.0.1", len(sources))
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda s: service.submit_batch(payload_for(s)), sources))

    stats = service.store.stats()
    assert stats["indicators_total"] == 6  # 1 个共享 + 5 个独立
    item = service.get("ip:192.168.0.1", now=datetime(2026, 10, 1))
    assert sorted(item["sources"]) == ["a", "b", "c", "d", "e"]
    assert len(item["source_observations"]) == 5
    assert sum(r.accepted_new for r in results) == 6
    assert sum(r.merged for r in results) == 4


@pytest.mark.parametrize(
    "payload,reason",
    [
        ("not-a-dict", BatchRejectReason.MALFORMED_BATCH.value),
        ({"batch_id": "x"}, BatchRejectReason.MALFORMED_BATCH.value),
        ({"entries": "nope"}, BatchRejectReason.MALFORMED_BATCH.value),
        ({"entries": []}, BatchRejectReason.EMPTY_BATCH.value),
        ({"batch_id": 9, "entries": [{"type": "ip", "value": "1.1.1.1"}]},
         BatchRejectReason.MALFORMED_BATCH.value),
        ({"entries": [{"type": "ip"}, {"type": "ip"}]},
         BatchRejectReason.MALFORMED_BATCH.value),
    ],
)
def test_invalid_batches_rejected_distinguishably_and_not_persisted(
    service: AggregatorService, payload: object, reason: str
) -> None:
    logger.info("非法输入批次=%s 判定依据：必须以 reason=%s 整批拒绝", payload, reason)
    with pytest.raises(BatchRejected) as exc:
        service.submit_batch(payload)
    assert exc.value.reason == reason
    # 零污染：没有批次登记、没有指标写入
    assert service.store.stats()["indicators_total"] == 0
    assert service.store.stats()["batches_total"] == 0


def test_partial_bad_entries_do_not_poison_good_ones(service: AggregatorService) -> None:
    payload = {
        "batch_id": "mixed",
        "entries": [
            {"type": "ip", "value": "10.1.1.1", "source": "s", "valid_until": "2026-12-31",
             "last_seen": "2026-09-01"},
            {"type": "ip", "value": "bad", "source": "s"},
        ],
    }
    logger.info("混合批次=%s 判定依据：好条目入库，坏条目带原因返回，互不污染", payload)
    result = service.submit_batch(payload)
    assert result.accepted_new == 1
    assert len(result.rejected) == 1
    assert result.rejected[0].reason == "invalid_value"
    assert service.store.stats()["indicators_total"] == 1


def test_replay_even_with_empty_or_missing_entries(service: AggregatorService) -> None:
    # 重复请求可能退化为空/缺字段负载：只要 batch_id 相同，结论必须与首次一致。
    payload = _batch("dup-empty", n=2)
    first = service.submit_batch(payload)
    for replayed_payload in (
        {"batch_id": "dup-empty", "entries": []},
        {"batch_id": "dup-empty"},
    ):
        logger.info("退化重放输入=%s 判定依据：返回首次结果且无新写入", replayed_payload)
        r = service.submit_batch(replayed_payload)
        assert r.replayed is True
        assert r.accepted_total == first.accepted_total == 2
    assert service.store.stats()["indicators_total"] == 2
    assert service.store.stats()["batches_total"] == 1


def test_auto_batch_id_makes_identical_payload_idempotent(service: AggregatorService) -> None:
    payload = {"entries": [{"type": "domain", "value": "a.example", "source": "s"}]}
    logger.info("无 batch_id 的相同内容提交两次：按内容派生 id，必须幂等")
    r1 = service.submit_batch(payload)
    r2 = service.submit_batch(payload)
    assert r1.batch_id == r2.batch_id and r2.replayed is True
    assert service.store.stats()["indicators_total"] == 1
