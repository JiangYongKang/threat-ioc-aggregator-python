"""来源可信度权重与批量重新判定测试。

覆盖：
- 权重生效与默认兼容（未配置来源按 1.0，与旧口径一致）；
- 权重配置校验与版本化审计；
- 批量重判与"用新权重重新入库"的一致性；
- 重判与并发投递交叉（不丢数据、不重复计数、无新旧权重混用）；
- 重判失败的原子性与重试幂等；
- 过期/撤回指标在重判后仍然不可见；
- 批次混入类型矛盾/字段残缺条目时拒绝与降级原因仍可区分。
"""

from __future__ import annotations

import threading

import pytest

from app.lifecycle import explain_confidence, explain_verdict
from app.models import IocStatus, RejectReason, Verdict
from app.service import ThreatIocService
from app.store import IocStore
from app.weights import WeightConfigError, WeightRegistry

NOW = "2026-09-23T00:00:00Z"


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


# --------------------------------------------------- 权重生效与默认兼容

def test_default_weight_matches_legacy_behavior(make_obs):
    """未配置任何权重时，聚合结果与引入权重机制前完全一致。"""

    sources = {
        "alpha": make_obs("alpha", 0.7, "malicious"),
        "beta": make_obs("beta", 0.6, "suspicious"),
    }
    print("\n[场景] 默认权重兼容：alpha=0.7/malicious beta=0.6/suspicious")
    legacy_conf, legacy_basis = explain_confidence(sources, NOW)
    legacy_verdict, _ = explain_verdict(sources, NOW)

    registry = WeightRegistry()  # 空配置：全部来源默认 1.0
    conf, basis = explain_confidence(sources, NOW, registry.current())
    verdict, _ = explain_verdict(sources, NOW, registry.current())
    print("[判定依据] 旧口径:", legacy_basis)
    print("[判定依据] 新口径:", basis)
    assert conf == legacy_conf == 0.75
    assert verdict is legacy_verdict is Verdict.MALICIOUS


def test_weight_changes_confidence_ranking(make_obs):
    """高置信度来源被调低权重后，基础置信度让位于低权重比更高的来源。"""

    sources = {
        "alpha": make_obs("alpha", 0.9, "malicious"),
        "beta": make_obs("beta", 0.5, "malicious"),
    }
    registry = WeightRegistry()
    config = registry.set_weights({"alpha": 0.5}, note="alpha 噪声大，降权")
    print("\n[场景] alpha=0.9×0.5=0.45 < beta=0.5×1.0=0.5")
    conf, basis = explain_confidence(sources, NOW, config)
    print("[判定依据]", basis)
    # 基础 0.5（beta）+ 佐证 0.5*0.05=0.025 => 0.525
    assert conf == 0.525
    legacy, _ = explain_confidence(sources, NOW)
    assert legacy == 0.95  # 旧口径：0.9 + 0.05
    assert conf != legacy


def test_weight_flips_conflict_verdict(make_obs):
    """恶意来源被降权后，与良性来源的有效置信度拉近，结论降级为可疑。"""

    sources = {
        "alpha": make_obs("alpha", 0.9, "malicious"),
        "beta": make_obs("beta", 0.5, "benign"),
    }
    legacy_verdict, legacy_basis = explain_verdict(sources, NOW)
    print("\n[场景] 无权重：alpha=0.9/malicious vs beta=0.5/benign")
    print("[判定依据]", legacy_basis)
    assert legacy_verdict is Verdict.MALICIOUS

    registry = WeightRegistry()
    config = registry.set_weights({"alpha": 0.5}, note="alpha 降权")
    verdict, basis = explain_verdict(sources, NOW, config)
    print("[场景] alpha 权重 0.5：有效 0.45 vs 0.5，差 -0.05 <= 0.10")
    print("[判定依据]", basis)
    assert verdict is Verdict.SUSPICIOUS


def test_unconfigured_source_falls_back_to_default(make_obs):
    """只配置部分来源时，其余来源按默认 1.0 参与聚合。"""

    sources = {
        "alpha": make_obs("alpha", 0.6, "malicious"),
        "beta": make_obs("beta", 0.6, "malicious"),
    }
    registry = WeightRegistry()
    config = registry.set_weights({"alpha": 2.0}, note="只配 alpha")
    print("\n[场景] alpha=0.6×2.0=1.2，beta 未配置按 1.0 => 0.6")
    conf, basis = explain_confidence(sources, NOW, config)
    print("[判定依据]", basis)
    # 基础 min(0.999, 1.2) 方向取 1.2，加成 0.05*1.0，最终封顶 0.999
    assert conf == 0.999
    assert config.weight_of("beta") == 1.0


# --------------------------------------------------- 配置校验与版本审计

@pytest.mark.parametrize(
    "weights,reason",
    [
        (["not-a-dict"], "invalid_weight_config"),
        ({"": 1.0}, "invalid_weight_config"),
        ({"alpha": "high"}, "invalid_weight_value"),
        ({"alpha": True}, "invalid_weight_value"),
        ({"alpha": 0}, "invalid_weight_value"),
        ({"alpha": -0.5}, "invalid_weight_value"),
        ({"alpha": 1000.0}, "invalid_weight_value"),
        ({"alpha": float("nan")}, "invalid_weight_value"),
    ],
)
def test_invalid_weight_config_rejected(weights, reason):
    registry = WeightRegistry()
    print(f"\n[场景] 非法权重配置: {weights!r}")
    with pytest.raises(WeightConfigError) as exc:
        registry.set_weights(weights)
    print("[判定依据] 拒绝原因 =", exc.value.reason, "|", exc.value.detail)
    assert exc.value.reason == reason
    # 校验失败不产生任何变更
    assert registry.current().version == 0
    assert len(registry.history()) == 1


def test_weight_versions_and_history():
    registry = WeightRegistry()
    v1 = registry.set_weights({"alpha": 2.0}, note="第一次调权")
    v2 = registry.set_weights({"alpha": 0.5, "beta": 1.5}, note="第二次调权")
    print("\n[场景] 连续两次调权")
    history = registry.history()
    for h in history:
        print(f"[审计] v{h.version} @ {h.at} weights={h.weights} note={h.note}")
    assert (v1.version, v2.version) == (1, 2)
    assert registry.current().weights == {"alpha": 0.5, "beta": 1.5}
    assert [h.version for h in history] == [0, 1, 2]
    assert history[1].weights == {"alpha": 2.0}
    assert history[2].note == "第二次调权"


# --------------------------------------------------- 重判与重新入库一致

def _ingest_sample(service):
    """两个来源对同一指标给出冲突结论的样例数据。"""

    service.submit_batch("w-b1", [
        _good("198.51.100.10", "alpha", confidence=0.9, verdict="malicious"),
        _good("198.51.100.11", "alpha", confidence=0.8, verdict="malicious"),
    ])
    service.submit_batch("w-b2", [
        _good("198.51.100.10", "beta", confidence=0.5, verdict="benign"),
        _good("198.51.100.11", "beta", confidence=0.6, verdict="suspicious"),
    ])


def _snapshot(service):
    return {
        ioc.indicator: (ioc.verdict, ioc.confidence, ioc.status,
                        ioc.weight_version)
        for ioc in service.store.all_iocs()
    }


def test_rejudge_matches_fresh_ingest_with_same_weights():
    """先入库再调权重判 == 先配权重再入库同样的情报。"""

    weights = {"alpha": 0.5, "beta": 1.5}
    print("\n[场景] A：默认权重入库后调权重判；B：先配权重再入库")

    service_a = ThreatIocService()
    _ingest_sample(service_a)
    before = _snapshot(service_a)
    print("[判定依据] A 调权前:", before)
    service_a.set_weights(weights, note="A 调权")

    service_b = ThreatIocService()
    service_b.set_weights(weights, note="B 先配权重")
    _ingest_sample(service_b)

    snap_a, snap_b = _snapshot(service_a), _snapshot(service_b)
    print("[判定依据] A 重判后:", snap_a)
    print("[判定依据] B 入库后:", snap_b)
    assert snap_a == snap_b
    # 结论确实体现了权重差异（与默认口径不同）
    assert snap_a["198.51.100.10"][0] is Verdict.SUSPICIOUS
    assert before["198.51.100.10"][0] is Verdict.MALICIOUS
    # 两个服务的权重版本序列一致（都经历过 v1）
    assert all(v[3] == 1 for v in snap_a.values())


# --------------------------------------------------- 重判与并发投递交叉

def test_rejudge_concurrent_with_ingestion():
    """重判期间并发投递新批次：不丢数据、不重复计数、最终权重版本统一。"""

    service = ThreatIocService()
    _ingest_sample(service)
    print("\n[场景] 1 个线程调权重判，4 个线程并发投递新批次")

    def do_rejudge():
        service.set_weights({"alpha": 0.5}, note="并发调权")

    def do_ingest(n):
        service.submit_batch(f"conc-{n}", [
            _good(f"203.0.113.{n}", "gamma", confidence=0.6,
                  verdict="suspicious"),
        ])

    threads = [threading.Thread(target=do_rejudge)]
    threads += [threading.Thread(target=do_ingest, args=(n,))
                for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 参照：同样的操作顺序执行，最终状态必须一致
    reference = ThreatIocService()
    _ingest_sample(reference)
    for n in range(4):
        reference.submit_batch(f"conc-{n}", [
            _good(f"203.0.113.{n}", "gamma", confidence=0.6,
                  verdict="suspicious"),
        ])
    reference.set_weights({"alpha": 0.5}, note="参照调权")

    snap, ref = _snapshot(service), _snapshot(reference)
    print("[判定依据] 并发终态:", snap)
    print("[判定依据] 参照终态:", ref)
    assert service.store.count() == 6  # 2 存量 + 4 新增，无丢失无重复
    assert snap == ref
    assert all(v[3] == 1 for v in snap.values())  # 全部按 v1 权重判定


# --------------------------------------------------- 失败原子性与重试幂等

def test_rejudge_failure_is_atomic_and_retryable():
    """重判中途失败：存储零变更；重试成功且结果与一次成功相同；再重试无效果。"""

    from app.ingestion import IngestionService

    registry = WeightRegistry()
    store = IocStore(registry)
    ingestion = IngestionService(store)
    ingestion.submit_batch("f-b1", [
        _good("192.0.2.10", "alpha", confidence=0.9, verdict="malicious"),
        _good("192.0.2.11", "beta", confidence=0.6, verdict="suspicious"),
    ])
    config = registry.set_weights({"alpha": 0.5}, note="会失败的调权")

    def _state():
        return {
            ind: (ioc.verdict, ioc.confidence, ioc.weight_version,
                  len(ioc.history))
            for ind, ioc in store._iocs.items()
        }

    before = _state()
    print("\n[场景] 重判中途注入失败，前态:", before)

    def _boom():
        raise RuntimeError("模拟重算中途失败")

    with pytest.raises(RuntimeError):
        store.rejudge_all(config, fail_hook=_boom)
    after_fail = _state()
    print("[判定依据] 失败后状态:", after_fail)
    assert after_fail == before  # 零变更：要么整体生效要么整体不生效

    summary = store.rejudge_all(config)
    after_retry = _state()
    print("[判定依据] 重试成功:", summary, after_retry)
    assert summary["rejudged"] == 2
    assert all(v[2] == config.version for v in after_retry.values())

    # 与"一次成功"的参照结果一致
    from app.ingestion import IngestionService as _Ingestion

    ref_registry = WeightRegistry()
    ref_store = IocStore(ref_registry)
    ref_ingestion = _Ingestion(ref_store)
    ref_ingestion.submit_batch("f-b1", [
        _good("192.0.2.10", "alpha", confidence=0.9, verdict="malicious"),
        _good("192.0.2.11", "beta", confidence=0.6, verdict="suspicious"),
    ])
    ref_config = ref_registry.set_weights({"alpha": 0.5})
    ref_store.rejudge_all(ref_config)
    for ind, ioc in store._iocs.items():
        ref = ref_store._iocs[ind]
        assert (ioc.verdict, ioc.confidence) == (ref.verdict, ref.confidence)

    # 再次重试：已按该版本判定过，幂等无效果
    history_len = {ind: len(ioc.history) for ind, ioc in store._iocs.items()}
    summary2 = store.rejudge_all(config)
    print("[判定依据] 二次重试:", summary2)
    assert summary2["rejudged"] == 0
    assert {ind: len(ioc.history) for ind, ioc in store._iocs.items()} == history_len


# --------------------------------------------------- 过期/撤回不重判复活

def test_expired_and_revoked_stay_hidden_after_rejudge():
    service = ThreatIocService()
    service.submit_batch("lc-b1", [
        _good("192.0.2.20", "alpha", confidence=0.9,
              expires_at="2026-09-22T00:00:00Z"),  # 已过期
        _good("192.0.2.21", "alpha", confidence=0.9, revoked=True),  # 已撤回
        _good("192.0.2.22", "alpha", confidence=0.9),  # 正常
    ])
    print("\n[场景] 过期 + 撤回 + 正常各一，调权重判")
    summary = service.set_weights({"alpha": 2.0}, note="调权")
    print("[判定依据] 重判汇总:", summary["rejudge"])

    active = service.list_active(now=NOW)
    visible = {i.indicator for i in active}
    print("[判定依据] 重判后可见指标:", visible)
    assert visible == {"192.0.2.22"}
    expired = service.query("192.0.2.20", now=NOW)
    revoked = service.query("192.0.2.21", now=NOW)
    assert expired.status is IocStatus.EXPIRED
    assert revoked.status is IocStatus.REVOKED
    # 权重版本已推进，但状态没有复活
    assert expired.weight_version == 1
    assert revoked.weight_version == 1


# --------------------------------------------------- 权重审计与解释视图

def test_weight_audit_trail_on_indicator():
    service = ThreatIocService()
    service.submit_batch("a-b1", [
        _good("198.51.100.20", "alpha", confidence=0.9, verdict="malicious"),
        _good("198.51.100.20", "beta", confidence=0.5, verdict="benign"),
    ])
    print("\n[场景] 入库后调权，检查指标审计链与解释视图")
    service.set_weights({"alpha": 0.5}, note="alpha 降权")

    ioc = service.query("198.51.100.20", now=NOW)
    rejudge_events = [h for h in ioc.history if h.action == "rejudge"]
    for h in rejudge_events:
        print("[审计]", h.at, h.action, h.detail)
    assert ioc.weight_version == 1
    assert rejudge_events and "v1" in rejudge_events[-1].detail

    history = service.weight_history()
    print("[审计] 权重变更历史:", history)
    assert [h["version"] for h in history] == [0, 1]
    assert history[1]["weights"] == {"alpha": 0.5}
    assert history[1]["note"] == "alpha 降权"

    explanation = service.explain("198.51.100.20", now=NOW)
    print("[判定依据] 置信度:", explanation.confidence_basis)
    print("[判定依据] 结论:", explanation.verdict_basis)
    print("[判定依据] 来源贡献:", explanation.contributions)
    assert explanation.weight_version == 1
    contrib = {c["source"]: c for c in explanation.contributions}
    assert contrib["alpha"]["weight"] == 0.5
    assert contrib["beta"]["weight"] == 1.0  # 未配置默认 1.0
    assert contrib["alpha"]["effective_confidence"] == 0.45
    assert contrib["beta"]["effective_confidence"] == 0.5
    assert explanation.verdict == "suspicious"


# --------------------------------------------------- 畸形条目仍可区分

def test_malformed_entries_still_distinguished_with_weights():
    """权重机制不影响条目级拒绝/降级的可区分性。"""

    service = ThreatIocService()
    service.set_weights({"alpha": 2.0}, note="先配权重")
    entries = [
        _good("203.0.113.50", "alpha"),                          # 正常
        {"indicator": "203.0.113.51", "type": "hash",
         "source": "alpha", "confidence": 0.7},                  # 类型矛盾 => 拒绝
        {"source": "alpha", "confidence": 0.7},                  # 缺指标 => 拒绝
        {"indicator": "203.0.113.52", "type": "ip",
         "source": "alpha"},                                     # 缺字段 => 降级
    ]
    print("\n[场景] 权重已配置，批次混入类型矛盾/缺指标/缺字段条目")
    result = service.submit_batch("m-b1", entries)
    reasons = {r.reason for r in result.rejected_entries}
    degrades = {tuple(r.value for r in d.reasons)
                for d in result.degraded_entries}
    print("[判定依据] accepted=%d rejected=%d degraded=%d"
          % (result.accepted, result.rejected, result.degraded))
    print("[判定依据] 拒绝原因:", {r.value for r in reasons})
    print("[判定依据] 降级原因:", degrades)
    assert result.accepted == 2 and result.rejected == 2
    assert RejectReason.CONFLICTING_TYPE in reasons
    assert RejectReason.MISSING_INDICATOR in reasons
    assert result.degraded == 1
    assert service.store.count() == 2
    # 正常入库的条目已按新权重判定
    ioc = service.query("203.0.113.50", now=NOW)
    assert ioc.weight_version == 1


# --------------------------------------------------- HTTP 接口行为

def test_weights_http_endpoints(tmp_path):
    from fastapi.testclient import TestClient

    from app.api import create_app

    client = TestClient(create_app(feeds_dir=str(tmp_path)))
    print("\n[场景] HTTP：提交批次 -> 查权重 -> 调权 -> 查解释/历史")

    client.post("/api/v1/batches", json={
        "batch_id": "http-w1",
        "entries": [_good("198.51.100.30", "alpha", confidence=0.9),
                    _good("198.51.100.30", "beta", confidence=0.5,
                          verdict="benign")],
    })

    resp = client.get("/api/v1/weights")
    print("[判定依据] 初始权重:", resp.json())
    assert resp.status_code == 200
    assert resp.json()["version"] == 0
    assert resp.json()["default_weight"] == 1.0

    resp = client.put("/api/v1/weights", json={
        "weights": {"alpha": 0.5}, "note": "HTTP 调权",
    })
    print("[判定依据] 调权响应:", resp.json())
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert body["rejudge"]["rejudged"] == 1

    explain = client.get("/api/v1/iocs/198.51.100.30/explain").json()
    print("[判定依据] 解释视图:", explain["verdict"],
          explain["contributions"])
    assert explain["weight_version"] == 1
    assert explain["verdict"] == "suspicious"
    assert {c["source"]: c["weight"] for c in explain["contributions"]} == {
        "alpha": 0.5, "beta": 1.0,
    }

    detail = client.get("/api/v1/iocs/198.51.100.30").json()
    assert detail["weight_version"] == 1
    assert any(h["action"] == "rejudge" for h in detail["history"])

    history = client.get("/api/v1/weights/history").json()["history"]
    assert [h["version"] for h in history] == [0, 1]
    assert history[1]["note"] == "HTTP 调权"

    # 非法配置：422 且不产生变更
    resp = client.put("/api/v1/weights", json={"weights": {"alpha": -1}})
    print("[判定依据] 非法权重 HTTP", resp.status_code, resp.json())
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_weight_value"
    assert client.get("/api/v1/weights").json()["version"] == 1

    # 手动触发重判：幂等
    resp = client.post("/api/v1/rejudge")
    assert resp.status_code == 200
    assert resp.json()["rejudged"] == 0


# --------------------------------------------------- 配置发布与重判解耦

def test_config_without_rejudge_does_not_change_query_results():
    """只发布配置（rejudge=False）时查询仍按旧版本口径；手动重判后整体生效。"""

    service = ThreatIocService()
    service.submit_batch("d-b1", [
        _good("198.51.100.40", "alpha", confidence=0.9, verdict="malicious"),
        _good("198.51.100.40", "beta", confidence=0.5, verdict="benign"),
    ])
    print("\n[场景] 入库后只发配置不重判，再手动重判")

    service.set_weights({"alpha": 0.5}, note="只发配置", rejudge=False)
    view = service.explain("198.51.100.40", now=NOW)
    print("[判定依据] 重判前:", view.verdict, "weight_version=",
          view.weight_version)
    assert view.weight_version == 0          # 仍按 v0（默认权重）解释
    assert view.verdict == "malicious"       # 结论未变
    ioc = service.query("198.51.100.40", now=NOW)
    assert ioc.weight_version == 0

    summary = service.rejudge_all()
    print("[判定依据] 手动重判:", summary)
    assert summary["rejudged"] == 1
    view = service.explain("198.51.100.40", now=NOW)
    print("[判定依据] 重判后:", view.verdict, "weight_version=",
          view.weight_version)
    assert view.weight_version == 1
    assert view.verdict == "suspicious"      # 新权重整体生效
