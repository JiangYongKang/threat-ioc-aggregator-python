"""来源权重与动态重新判定测试：

- 权重生效与默认兼容（未配置来源 == 旧口径）；
- 批量重新判定与"新权重重新入库"结果一致；
- 重算与并发投递交叉：不丢数据、不重复计数、无新旧权重混用；
- 重算失败重试幂等：失败零变更，重试安全；
- 拒绝/降级原因不被本轮改动吞掉；
- 过期/撤回指标在重算后不复活；
- 权重变更历史可追溯。
"""

from __future__ import annotations

import json
import threading

import pytest

from app.lifecycle import explain_confidence, explain_verdict
from app.service import ThreatIocService
from app.weights import WeightConfigError

NOW = "2026-10-04T00:00:00Z"


def _entry(indicator, source, confidence, verdict, **over):
    entry = {
        "indicator": indicator,
        "type": "ip",
        "source": source,
        "confidence": confidence,
        "verdict": verdict,
        "first_seen": "2026-09-20T00:00:00Z",
        "validity_days": 30,
        "tags": ["t"],
    }
    entry.update(over)
    return entry


def _submit(svc, batch_id, entries):
    print(f"\n[输入批次] batch_id={batch_id} 条目数={len(entries)}")
    print("[批次内容]", json.dumps(entries, ensure_ascii=False, default=str))
    result = svc.submit_batch(batch_id, entries)
    print("[判定依据] accepted=%d updated=%d rejected=%d degraded=%d"
          % (result.accepted, result.updated, result.rejected,
             result.degraded))
    return result


def _snapshot(svc, now=NOW):
    """全库关键结论快照：{indicator: (verdict, confidence, status, version)}"""

    return {
        i.indicator: (i.verdict.value, i.confidence, i.status.value,
                      i.weights_version)
        for i in svc.store.all_iocs()
    }


# --------------------------------------------------- 权重生效与默认兼容

def test_default_weights_match_legacy_aggregation():
    """未配置任何权重时，结论与旧版（无权重）聚合完全一致。"""

    svc = ThreatIocService()
    _submit(svc, "w-def", [
        _entry("10.0.0.1", "alpha", 0.8, "malicious"),
        _entry("10.0.0.1", "beta", 0.6, "malicious"),
    ])
    ioc = svc.query("10.0.0.1", now=NOW)
    legacy_conf, legacy_conf_basis = explain_confidence(ioc.sources, NOW)
    legacy_verdict, _ = explain_verdict(ioc.sources, NOW)
    print("[判定依据] 默认权重置信度 =", ioc.confidence,
          "旧口径 =", legacy_conf, "|", legacy_conf_basis)
    assert ioc.confidence == legacy_conf
    assert ioc.verdict is legacy_verdict
    assert ioc.weights_version == 0
    ex = svc.explain("10.0.0.1", now=NOW)
    print("[判定依据] 各来源贡献 =",
          [(c.source, c.weight, c.effective_confidence)
           for c in ex.contributions])
    assert all(c.weight == 1.0 for c in ex.contributions)


def test_weight_changes_verdict_and_confidence():
    """权重差异体现到最终结论：高权重来源压制对立的低权重来源。"""

    svc = ThreatIocService()
    _submit(svc, "w-conf", [
        _entry("10.0.0.2", "alpha", 0.7, "malicious"),
        _entry("10.0.0.2", "beta", 0.8, "benign"),
    ])
    before = svc.explain("10.0.0.2", now=NOW)
    print("[判定依据-默认]", before.verdict, "|", before.verdict_basis)
    assert before.verdict == "suspicious"  # 0.7 vs 0.8 冲突降级

    result = svc.update_weights({"alpha": 2.0}, note="alpha 更可信")
    print("[权重变更]", result)
    assert result.changed and result.version == 1
    assert result.recomputed == 1

    after = svc.explain("10.0.0.2", now=NOW)
    print("[判定依据-加权]", after.verdict, "|", after.verdict_basis)
    print("[判定依据-置信度]", after.confidence, "|", after.confidence_basis)
    # alpha 有效置信度 min(0.999, 0.7*2)=0.999 明显高于 beta 的 0.8
    assert after.verdict == "malicious"
    assert after.weights_version == 1
    contrib = {c.source: c for c in after.contributions}
    assert contrib["alpha"].weight == 2.0
    assert contrib["alpha"].effective_confidence == 0.999
    assert contrib["beta"].weight == 1.0  # 未配置来源默认 1.0
    assert contrib["beta"].effective_confidence == 0.8
    ioc = svc.query("10.0.0.2", now=NOW)
    assert ioc.weights_version == 1


def test_unconfigured_source_keeps_default_weight():
    """只配置部分来源时，其余来源结论口径不变。"""

    svc = ThreatIocService()
    _submit(svc, "w-part", [
        _entry("10.0.0.3", "alpha", 0.9, "malicious"),
        _entry("10.0.0.3", "gamma", 0.7, "malicious"),
    ])
    svc.update_weights({"alpha": 0.5}, note="调低 alpha")
    ex = svc.explain("10.0.0.3", now=NOW)
    contrib = {c.source: c for c in ex.contributions}
    print("[判定依据] 贡献 =",
          {s: (c.weight, c.effective_confidence)
           for s, c in contrib.items()})
    assert contrib["alpha"].effective_confidence == 0.45   # 0.9 * 0.5
    assert contrib["gamma"].weight == 1.0
    assert contrib["gamma"].effective_confidence == 0.7    # 未配置不受影响
    # 聚合：最高有效置信度 0.7（gamma）+ 佐证 0.05
    assert ex.confidence == 0.75


# --------------------------------------- 批量重新判定 vs 重新入库一致性

def test_recompute_matches_reingest_with_new_weights():
    """重算结果 == 用新权重把同样情报重新入库一遍的结果。"""

    entries_a = [
        _entry("10.1.0.1", "alpha", 0.7, "malicious"),
        _entry("10.1.0.1", "beta", 0.8, "benign"),
        _entry("10.1.0.2", "gamma", 0.6, "suspicious"),
    ]
    entries_b = [
        _entry("10.1.0.2", "alpha", 0.9, "malicious"),
        _entry("10.1.0.3", "beta", 0.4, "benign"),
    ]
    weights = {"alpha": 1.5, "beta": 0.5}

    # 路径 A：先入库存量，再调权重触发全量重算
    svc_a = ThreatIocService()
    _submit(svc_a, "ra-1", entries_a)
    _submit(svc_a, "ra-2", entries_b)
    svc_a.update_weights(weights, note="一致性验证")
    snap_a = _snapshot(svc_a)

    # 路径 B：先配权重，再把同样的情报重新入库
    svc_b = ThreatIocService()
    svc_b.update_weights(weights, note="一致性验证")
    _submit(svc_b, "ra-1", entries_a)
    _submit(svc_b, "ra-2", entries_b)
    snap_b = _snapshot(svc_b)

    print("[判定依据] 重算路径 =", snap_a)
    print("[判定依据] 重新入库路径 =", snap_b)
    assert snap_a == snap_b
    assert all(v[3] == 1 for v in snap_a.values())


# --------------------------------------- 重算与并发投递交叉

def test_recompute_concurrent_with_ingestion():
    """重算期间并发投递新批次：不丢、不重、最终态与顺序执行一致。"""

    def build_batches():
        return {
            f"cc-{i}": [_entry(f"10.2.0.{i}", "alpha", 0.7, "malicious"),
                        _entry(f"10.2.0.{i}", "beta", 0.6, "suspicious")]
            for i in range(8)
        }

    batches = build_batches()
    weights = {"alpha": 1.2, "beta": 0.4}

    # 顺序参照：全部入库后再调权重
    ref = ThreatIocService()
    for bid, entries in batches.items():
        ref.submit_batch(bid, entries)
    ref.update_weights(weights, note="参照")
    expected = _snapshot(ref)

    # 并发：一个线程调权重（触发重算），其余线程并发投递
    svc = ThreatIocService()
    svc.submit_batch("cc-0", batches["cc-0"])  # 先制造存量
    barrier = threading.Barrier(len(batches))  # 7 个投递线程 + 1 个重算线程
    errors: list[Exception] = []

    def submit(bid):
        try:
            barrier.wait(timeout=10)
            svc.submit_batch(bid, batches[bid])
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def reweight():
        try:
            barrier.wait(timeout=10)
            svc.update_weights(weights, note="并发重算")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = ([threading.Thread(target=submit, args=(bid,))
                for bid in batches if bid != "cc-0"]
               + [threading.Thread(target=reweight)])
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"并发执行出现异常: {errors}"
    actual = _snapshot(svc)
    print("[判定依据] 顺序参照 =", expected)
    print("[判定依据] 并发结果 =", actual)
    assert actual == expected            # 不丢数据、无中间态残留
    assert svc.store.count() == len(batches)  # 不重复计数
    assert all(v[3] == 1 for v in actual.values())  # 全部按新权重落位


# --------------------------------------- 失败重试幂等

def test_invalid_weight_config_rejected_without_side_effect():
    """非法权重配置整体拒绝，存量与版本零变更。"""

    svc = ThreatIocService()
    _submit(svc, "w-bad", [_entry("10.3.0.1", "alpha", 0.7, "malicious")])
    before = _snapshot(svc)
    for bad in ({"alpha": 0}, {"alpha": -1}, {"alpha": True},
                {"alpha": "high"}, {"": 1.0}, ["not-a-dict"]):
        with pytest.raises(WeightConfigError):
            svc.update_weights(bad)
        print("[判定依据] 非法配置被拒绝:", bad)
    assert _snapshot(svc) == before
    assert svc.get_weights()["version"] == 0


def test_failed_recompute_is_atomic_and_retry_idempotent(monkeypatch):
    """重算中途失败：存量不改坏、版本不升；重试幂等生效。"""

    svc = ThreatIocService()
    _submit(svc, "w-fail", [
        _entry("10.4.0.1", "alpha", 0.7, "malicious"),
        _entry("10.4.0.2", "beta", 0.6, "suspicious"),
    ])
    before = _snapshot(svc)

    from app.store import IocStore
    original = IocStore._apply_recompute

    def boom(self, target, now, weights=None):
        if weights:  # 只在加权重算时失败
            raise RuntimeError("模拟重算中途失败")
        return original(self, target, now, weights)

    monkeypatch.setattr(IocStore, "_apply_recompute", boom)
    with pytest.raises(RuntimeError):
        svc.update_weights({"alpha": 2.0}, note="会失败的变更")
    print("[判定依据] 重算失败后快照 =", _snapshot(svc))
    assert _snapshot(svc) == before                 # 存量未改坏
    assert svc.get_weights()["version"] == 0        # 版本未生效

    monkeypatch.setattr(IocStore, "_apply_recompute", original)
    ok = svc.update_weights({"alpha": 2.0}, note="重试")
    print("[判定依据] 重试结果 =", ok)
    assert ok.changed and ok.version == 1
    assert all(v[3] == 1 for v in _snapshot(svc).values())

    again = svc.update_weights({"alpha": 2.0}, note="重复提交")
    print("[判定依据] 同内容重复提交 =", again)
    assert not again.changed and again.version == 1  # 幂等：不升版本
    assert len(svc.get_weights()["history"]) == 2    # v0 + v1


# --------------------------------------- 拒绝/降级不被吞掉

def test_reject_and_degrade_reasons_survive_weight_changes():
    """类型矛盾拒绝、字段残缺降级的口径在权重改动后保持不变。"""

    svc = ThreatIocService()
    entries = [
        _good := _entry("10.5.0.1", "alpha", 0.7, "malicious"),
        {"indicator": "8.8.8.8", "type": "domain", "source": "alpha",
         "confidence": 0.5, "verdict": "malicious"},          # 类型矛盾 => 拒绝
        {"indicator": "10.5.0.2", "type": "ip", "source": "alpha",
         "verdict": "malicious", "first_seen": "2026-09-20T00:00:00Z",
         "validity_days": 30},                                  # 缺置信度 => 降级
    ]
    result = _submit(svc, "w-rj", entries)
    assert result.rejected == 1 and result.degraded == 1
    assert result.rejected_entries[0].reason.value == "conflicting_type"
    degrade_reasons = [r.value for r in
                       result.degraded_entries[0].reasons]
    print("[判定依据] 拒绝 =", result.rejected_entries[0].detail,
          "| 降级 =", degrade_reasons)
    assert "missing_confidence" in degrade_reasons

    svc.update_weights({"alpha": 1.5}, note="权重变更后复查")
    replay = svc.submit_batch("w-rj", entries)  # 幂等重放
    print("[判定依据] 重放 rejected=%d degraded=%d replayed=%s"
          % (replay.rejected, replay.degraded, replay.replayed))
    assert replay.replayed
    assert replay.rejected == 1 and replay.degraded == 1
    assert replay.rejected_entries[0].reason.value == "conflicting_type"
    # 被拒绝的指标从未入库，重算后也不会冒出来
    assert svc.query("8.8.8.8", now=NOW) is None
    assert svc.query("10.5.0.2", now=NOW) is not None


# --------------------------------------- 过期/撤回不复活

def test_expired_and_revoked_stay_hidden_after_recompute():
    """过期/撤回指标在重算与查询中仍然不出现。"""

    svc = ThreatIocService()
    _submit(svc, "w-life", [
        _entry("10.6.0.1", "alpha", 0.9, "malicious",
               first_seen="2026-09-01T00:00:00Z", validity_days=1),  # 已过期
        _entry("10.6.0.2", "alpha", 0.9, "malicious", revoked=True),  # 已撤回
        _entry("10.6.0.3", "alpha", 0.9, "malicious"),                # 正常
    ])
    svc.update_weights({"alpha": 0.5}, note="调低权重")
    active = {i.indicator for i in svc.list_active(now=NOW)}
    print("[判定依据] 重算后可见指标 =", active)
    assert active == {"10.6.0.3"}
    expired = svc.query("10.6.0.1", now=NOW)
    revoked = svc.query("10.6.0.2", now=NOW)
    assert expired.status.value == "expired"
    assert revoked.status.value == "revoked"
    # 非活跃指标也按新权重落位（可追溯），但不复活
    assert expired.weights_version == 1
    assert revoked.weights_version == 1


# --------------------------------------- 权重历史可追溯

def test_weight_history_and_audit_trail():
    """权重什么时候被改成什么可查；指标判定依据标注权重版本。"""

    svc = ThreatIocService()
    _submit(svc, "w-hist", [_entry("10.7.0.1", "alpha", 0.7, "malicious")])
    svc.update_weights({"alpha": 1.5}, note="第一次调整")
    svc.update_weights({"alpha": 0.8, "beta": 1.2}, note="第二次调整")

    info = svc.get_weights()
    print("[判定依据] 权重历史 =", json.dumps(info, ensure_ascii=False))
    assert info["version"] == 2
    assert [h["version"] for h in info["history"]] == [0, 1, 2]
    assert info["history"][1]["weights"] == {"alpha": 1.5}
    assert info["history"][1]["note"] == "第一次调整"
    assert info["history"][1]["at"]            # 有生效时间
    assert info["history"][2]["note"] == "第二次调整"

    ioc = svc.query("10.7.0.1", now=NOW)
    assert ioc.weights_version == 2
    reweight_events = [h for h in ioc.history if h.action == "reweight"]
    print("[判定依据] 重算审计 =",
          [(e.action, e.detail) for e in reweight_events])
    assert len(reweight_events) == 2           # 每次重算都有审计
    assert "v1" in reweight_events[0].detail
    assert "v2" in reweight_events[1].detail


# --------------------------------------- HTTP 接口层

def test_weights_api_endpoints(tmp_path):
    """PUT/GET /api/v1/weights 与 explain 的权重可解释字段。"""

    from fastapi.testclient import TestClient

    from app.api import create_app

    client = TestClient(create_app(feeds_dir=str(tmp_path)))
    resp = client.post("/api/v1/batches", json={
        "batch_id": "api-w1",
        "entries": [_entry("10.8.0.1", "alpha", 0.7, "malicious"),
                    _entry("10.8.0.1", "beta", 0.8, "benign")],
    })
    assert resp.status_code == 200

    # 非法配置 => 422，可区分错误码
    resp = client.put("/api/v1/weights", json={"weights": {"alpha": -1}})
    print("[判定依据] 非法权重响应 =", resp.status_code, resp.json())
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_weight_config"

    # 合法变更 => 触发全量重算
    resp = client.put("/api/v1/weights",
                      json={"weights": {"alpha": 2.0}, "note": "api 调整"})
    body = resp.json()
    print("[判定依据] 权重变更响应 =", body)
    assert resp.status_code == 200
    assert body["changed"] and body["version"] == 1
    assert body["recomputed"] == 1

    # 当前权重与历史可查
    resp = client.get("/api/v1/weights")
    info = resp.json()
    print("[判定依据] 权重查询 =", info)
    assert info["version"] == 1
    assert info["weights"] == {"alpha": 2.0}
    assert len(info["history"]) == 2

    # explain 暴露权重版本与各来源贡献
    resp = client.get("/api/v1/iocs/10.8.0.1/explain")
    ex = resp.json()
    print("[判定依据] explain =", ex["verdict"], ex["weights_version"],
          ex["contributions"])
    assert ex["verdict"] == "malicious"
    assert ex["weights_version"] == 1
    contrib = {c["source"]: c for c in ex["contributions"]}
    assert contrib["alpha"]["weight"] == 2.0
    assert contrib["beta"]["weight"] == 1.0

    # 指标详情带权重版本
    resp = client.get("/api/v1/iocs/10.8.0.1")
    assert resp.json()["weights_version"] == 1
