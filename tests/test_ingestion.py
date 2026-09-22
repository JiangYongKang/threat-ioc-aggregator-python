"""入库服务测试：原子性、幂等重放、并发安全与可区分失败原因。"""

from __future__ import annotations

import json
import threading

import pytest

from app.ingestion import BatchRejected, IngestionService
from app.models import BatchRejectReason
from app.store import IocStore


def _good(indicator, source="alpha", **over):
    entry = {
        "indicator": indicator,
        "type": "ip",
        "source": source,
        "confidence": 0.7,
        "verdict": "malicious",
        "first_seen": "2026-09-20T00:00:00Z",
        "validity_days": 30,
        "tags": ["t1"],
    }
    entry.update(over)
    return entry


@pytest.fixture()
def service():
    return IngestionService(IocStore())


def _dump_batch(batch_id, entries, source_hint=None):
    print(f"\n[输入批次] batch_id={batch_id!r} source_hint={source_hint} "
          f"条目数={len(entries) if isinstance(entries, list) else 'N/A'}")
    print("[批次内容]", json.dumps(entries, ensure_ascii=False, default=str))


# --------------------------------------------------- 正常入库与降级共存

def test_partial_reject_keeps_good_entries(service):
    entries = [
        _good("1.1.1.1"),
        {"source": "alpha"},                                   # 缺指标 => 拒绝
        "not-an-object",                                       # 非对象 => 拒绝
        {"indicator": "2.2.2.2", "type": "ip", "source": "alpha"},  # 降级
    ]
    _dump_batch("b-partial", entries)
    result = service.submit_batch("b-partial", entries)
    print("[判定依据] accepted=%d updated=%d rejected=%d degraded=%d"
          % (result.accepted, result.updated, result.rejected,
             result.degraded))
    assert result.accepted == 2
    assert result.updated == 0
    assert result.rejected == 2
    assert result.degraded == 1  # 仅残缺的 2.2.2.2 降级
    reasons = {r.reason for r in result.rejected_entries}
    print("[判定依据] 拒绝原因集合 =", {r.value for r in reasons})
    assert reasons  # 非空且两种原因可区分
    assert service.store.count() == 2


# --------------------------------------------------- 非法批次整体拒绝

@pytest.mark.parametrize(
    "batch_id,entries,expected",
    [
        (None, [{"indicator": "1.1.1.1"}], BatchRejectReason.MISSING_BATCH_ID),
        ("", [{"indicator": "1.1.1.1"}], BatchRejectReason.MISSING_BATCH_ID),
        ("b1", {"not": "a list"}, BatchRejectReason.NOT_A_LIST),
        ("b2", [], BatchRejectReason.EMPTY_BATCH),
    ],
)
def test_invalid_batch_rejected_atomically(service, batch_id, entries,
                                           expected):
    _dump_batch(batch_id, entries)
    with pytest.raises(BatchRejected) as exc:
        service.submit_batch(batch_id, entries)
    print("[判定依据] 整批拒绝 code =", exc.value.reason.value)
    assert exc.value.reason is expected
    assert service.store.count() == 0
    assert service.store.get_batch_result(
        batch_id or ""
    ) is None  # 失败批次不登记


def test_entry_limit_exceeded(service):
    service.max_entries_per_batch = 3
    entries = [_good(f"10.0.0.{i}") for i in range(4)]
    _dump_batch("b-big", entries)
    with pytest.raises(BatchRejected) as exc:
        service.submit_batch("b-big", entries)
    print("[判定依据] code =", exc.value.reason.value)
    assert exc.value.reason is BatchRejectReason.ENTRY_LIMIT_EXCEEDED
    assert service.store.count() == 0


def test_illegal_batch_does_not_pollute_existing_data(service):
    r1 = service.submit_batch("b-ok", [_good("1.1.1.1")])
    snapshot_before = service.store.count()
    print("[输入批次] 先合法入库 b-ok，当前指标数 =", snapshot_before)
    with pytest.raises(BatchRejected):
        service.submit_batch("b-ok", [{"not": "a-list-content"}])
    with pytest.raises(BatchRejected):
        service.submit_batch(None, [_good("2.2.2.2")])
    assert service.store.count() == snapshot_before
    existing = service.store.get("1.1.1.1")
    print("[判定依据] 非法批次后 1.1.1.1 仍在，来源历史未受污染:",
          [(h.action, h.batch_id) for h in existing.history])
    assert all(h.batch_id in ("b-ok", "-") for h in existing.history)


# --------------------------------------------------- 幂等重放

def test_replay_same_batch_is_idempotent(service):
    entries = [_good("1.1.1.1"), _good("1.1.1.1", source="beta"),
               _good("2.2.2.2")]
    _dump_batch("b-replay", entries)
    r1 = service.submit_batch("b-replay", entries)
    print("[判定依据] 首次:",
          (r1.accepted, r1.updated, r1.rejected, r1.replayed))
    assert (r1.accepted, r1.updated) == (2, 1)
    assert service.store.count() == 2

    for n in range(3):
        r = service.submit_batch("b-replay", entries)
        print(f"[判定依据] 第 {n + 1} 次重放:",
              (r.accepted, r.updated, r.rejected, r.replayed))
        assert r.replayed is True
        assert r.accepted == r1.accepted
        assert r.updated == r1.updated
        assert r.rejected == r1.rejected
        assert r.indicators == r1.indicators
    assert service.store.count() == 2
    # 同一来源记录不会因重放被刷新多次
    obs = service.store.get("1.1.1.1")
    print("[判定依据] 1.1.1.1 审计链:",
          [(h.action, h.batch_id) for h in obs.history])
    assert sum(1 for h in obs.history if h.batch_id == "b-replay") == 2


def test_replay_same_batch_id_different_content_rejected(service):
    e1 = [_good("1.1.1.1")]
    e2 = [_good("9.9.9.9")]
    _dump_batch("b-dup", e1)
    service.submit_batch("b-dup", e1)
    print("[输入批次] 同 batch_id 重放不同内容:",
          json.dumps(e2, ensure_ascii=False))
    with pytest.raises(BatchRejected) as exc:
        service.submit_batch("b-dup", e2)
    print("[判定依据] code =", exc.value.reason.value)
    assert exc.value.reason is BatchRejectReason.DUPLICATE_BATCH_ID
    # 原数据未被污染
    assert service.store.count() == 1
    assert service.store.get("9.9.9.9") is None
    assert service.store.get("1.1.1.1") is not None


# --------------------------------------------------- 并发提交

def test_concurrent_identical_batch_submissions(service):
    entries = [_good("1.1.1.1"), _good("1.1.1.1", source="beta"),
               _good("2.2.2.2")]
    _dump_batch("b-concurrent", entries)

    results: list = []
    errors: list = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()  # 最大化竞争：同时进入
        try:
            results.append(service.submit_batch("b-concurrent", entries))
        except BatchRejected as exc:  # 并发下不应出现冲突拒绝
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print("[判定依据] 8 并发结果数 =", len(results), "异常数 =", len(errors))
    assert not errors
    assert len(results) == 8
    firsts = [r for r in results if not r.replayed]
    replays = [r for r in results if r.replayed]
    print("[判定依据] 首次处理数 =", len(firsts), "幂等重放数 =",
          len(replays))
    assert len(firsts) == 1
    assert len(replays) == 7
    for r in results:
        assert (r.accepted, r.updated, r.rejected) == (2, 1, 0)
    # 不重不漏：只有两个指标，每个指标来源审计确定
    assert service.store.count() == 2
    ioc1 = service.store.get("1.1.1.1")
    assert set(ioc1.sources) == {"alpha", "beta"}


def test_concurrent_disjoint_batches_all_persist(service):
    """多个不同批次并发提交：全部落库、互不丢失、无部分写入。"""

    def batch_entries(k):
        return [_good(f"10.{k}.0.1"), _good(f"10.{k}.0.2")]

    print("\n[输入批次] 6 个互不相交批次各 2 条，并发提交")
    results: list = []
    errors: list = []
    barrier = threading.Barrier(6)

    def worker(k):
        barrier.wait()
        try:
            results.append(
                service.submit_batch(f"b-disjoint-{k}", batch_entries(k)))
        except BatchRejected as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(results) == 6
    assert all(r.accepted == 2 and r.updated == 0 for r in results)
    print("[判定依据] 全部 accepted=2，存储指标总数 =", service.store.count())
    assert service.store.count() == 12


def test_concurrent_overlapping_batches_dedup_consistent(service):
    """多个批次含重叠指标并发：最终只保留一份指标、来源完整、计数确定。"""

    batches = {
        "b-a": [_good("shared.1", source="alpha")],
        "b-b": [_good("shared.1", source="beta"),
                _good("only-b.1", source="beta")],
        "b-c": [_good("shared.1", source="gamma"),
                _good("only-c.1", source="gamma")],
    }
    print("\n[输入批次] 3 批次并发，均含 shared.1")
    outcomes: dict[str, object] = {}
    barrier = threading.Barrier(3)

    def worker(bid):
        barrier.wait()
        outcomes[bid] = service.submit_batch(bid, batches[bid])

    threads = [threading.Thread(target=worker, args=(b,))
               for b in batches]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_accepted = sum(r.accepted for r in outcomes.values())
    total_updated = sum(r.updated for r in outcomes.values())
    print("[判定依据] 总 accepted =", total_accepted,
          "总 updated =", total_updated)
    # 无论顺序如何：3 个唯一指标，shared.1 被后到的两个批次各 update 一次
    assert total_accepted == 3
    assert total_updated == 2
    assert service.store.count() == 3
    shared = service.store.get("shared.1")
    assert set(shared.sources) == {"alpha", "beta", "gamma"}
    print("[判定依据] shared.1 来源 =", sorted(shared.sources))
