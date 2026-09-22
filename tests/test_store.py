"""存储层测试：去重、多源聚合、来源追溯、生命周期物化。"""

from __future__ import annotations

from app.models import IocStatus, IocType, Verdict
from app.normalizer import NormalizedEntry
from app.store import IocStore


def _entry(indicator, source, *, confidence=0.7, verdict=Verdict.MALICIOUS,
           ioc_type=IocType.IP, revoked=False,
           expires_at="2026-09-30T00:00:00Z",
           first_seen="2026-09-20T00:00:00Z",
           last_seen="2026-09-20T00:00:00Z",
           tags=None):
    return NormalizedEntry(
        indicator=indicator, ioc_type=ioc_type, source=source,
        confidence=confidence, verdict=verdict,
        tags=frozenset(tags or set()), first_seen=first_seen,
        last_seen=last_seen, expires_at=expires_at, revoked=revoked,
    )


def test_same_indicator_multiple_sources_keeps_one_record():
    store = IocStore()
    batches = [
        ("b1", _entry("10.0.0.1", "alpha", confidence=0.7, tags=["c2"])),
        ("b2", _entry("10.0.0.1", "beta", confidence=0.6,
                      verdict=Verdict.SUSPICIOUS,
                      last_seen="2026-09-21T00:00:00Z", tags=["sliver"])),
        ("b3", _entry("10.0.0.1", "gamma", confidence=0.8,
                      last_seen="2026-09-22T00:00:00Z")),
    ]
    for batch_id, entry in batches:
        print(f"[输入批次] {batch_id} source={entry.source} "
              f"indicator={entry.indicator}")
        store.upsert(entry, batch_id=batch_id)

    assert store.count() == 1
    ioc = store.get("10.0.0.1", now="2026-09-23T00:00:00Z")
    print("[判定依据] 指标唯一，来源集合 =", sorted(ioc.sources))
    assert set(ioc.sources) == {"alpha", "beta", "gamma"}
    assert ioc.last_seen == "2026-09-22T00:00:00Z"
    assert {"c2", "sliver"} <= ioc.tags
    # 审计链完整可追溯
    actions = [(h.action, h.source, h.batch_id) for h in ioc.history]
    print("[判定依据] 审计链 =", actions)
    assert ("create", "alpha", "b1") in actions
    assert ("update_source", "beta", "b2") in actions
    assert ("update_source", "gamma", "b3") in actions


def test_repeated_delivery_from_same_source_refreshes():
    store = IocStore()
    store.upsert(_entry("10.0.0.2", "alpha", confidence=0.7), batch_id="b1")
    print("[输入批次] b1 首次投递 10.0.0.2/alpha")
    action = store.upsert(
        _entry("10.0.0.2", "alpha", confidence=0.9,
               last_seen="2026-09-22T00:00:00Z"),
        batch_id="b2",
    )
    print("[输入批次] b2 同源重复投递，动作 =", action)
    assert action == "refresh"
    assert store.count() == 1
    ioc = store.get("10.0.0.2", now="2026-09-23T00:00:00Z")
    assert ioc.sources["alpha"].confidence == 0.9
    assert any(h.action == "refresh" for h in ioc.history)


def test_expired_indicator_hidden_but_traceable():
    store = IocStore()
    store.upsert(
        _entry("10.0.0.3", "alpha", expires_at="2026-09-23T00:00:00Z"),
        batch_id="b1",
    )
    print("[输入批次] 10.0.0.3 expires_at=2026-09-23T00:00:00Z")
    before = store.query_active(now="2026-09-22T23:59:59Z")
    after = store.query_active(now="2026-09-23T00:00:00Z")
    print(f"[判定依据] 边界前可见数={len(before)}，边界时刻可见数={len(after)}")
    assert len(before) == 1 and len(after) == 0
    # 记录仍可取回用于追溯
    trace = store.get("10.0.0.3", now="2026-09-23T00:00:00Z")
    assert trace.status is IocStatus.EXPIRED
    assert "alpha" in trace.sources


def test_all_sources_revoke_hides_indicator():
    store = IocStore()
    store.upsert(_entry("10.0.0.4", "alpha"), batch_id="b1")
    store.upsert(_entry("10.0.0.4", "beta"), batch_id="b2")
    store.upsert(_entry("10.0.0.4", "alpha", revoked=True), batch_id="b3")
    print("[输入批次] alpha 撤回，beta 仍有效")
    ioc = store.get("10.0.0.4", now="2026-09-23T00:00:00Z")
    print("[判定依据] 状态 =", ioc.status.value,
          "剩余有效来源 =",
          [s for s, o in ioc.sources.items() if not o.revoked])
    assert ioc.status is IocStatus.ACTIVE  # 还有 beta 有效
    assert len(store.query_active(now="2026-09-23T00:00:00Z")) == 1

    store.upsert(_entry("10.0.0.4", "beta", revoked=True), batch_id="b4")
    ioc = store.get("10.0.0.4", now="2026-09-23T00:00:00Z")
    print("[输入批次] beta 也撤回")
    print("[判定依据] 状态 =", ioc.status.value)
    assert ioc.status is IocStatus.REVOKED
    assert store.query_active(now="2026-09-23T00:00:00Z") == []


def test_reads_do_not_mutate_storage():
    store = IocStore()
    write_now = "2026-09-21T00:00:00Z"  # 显式写入时刻，保证写入时仍 ACTIVE
    store.upsert(
        _entry("10.0.0.5", "alpha", expires_at="2026-09-22T00:00:00Z"),
        batch_id="b1", now=write_now,
    )
    store.get("10.0.0.5", now="2026-09-25T00:00:00Z")
    store.query_active(now="2026-09-25T00:00:00Z")
    internal = store._iocs["10.0.0.5"]
    print("[判定依据] 只读查询后内部 status 仍为", internal.status.value,
          "history 长度 =", len(internal.history))
    assert internal.status is IocStatus.ACTIVE
    # 只有 create 一条写入审计，只读物化不落盘
    assert len(internal.history) == 1


def test_one_source_open_ended_keeps_indicator_alive():
    store = IocStore()
    store.upsert(
        _entry("10.0.0.6", "alpha", expires_at="2026-09-22T00:00:00Z"),
        batch_id="b1",
    )
    store.upsert(
        _entry("10.0.0.6", "beta", expires_at=None,
               last_seen="2026-09-21T00:00:00Z"),
        batch_id="b2",
    )
    print("[输入批次] alpha 短期 + beta 开放有效期")
    ioc = store.get("10.0.0.6", now="2027-01-01T00:00:00Z")
    print("[判定依据] 聚合 expires_at =", ioc.expires_at, "状态 =",
          ioc.status.value)
    assert ioc.expires_at is None
    assert ioc.status is IocStatus.ACTIVE
