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
from app.store import IocStore, RejudgeFailed
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


# ------------------------------------ 调权+重判事务：失败/重试/并发交叉

def _full_snapshot(service):
    """记录结论/置信度/版本/状态/审计链长度，用于失败前后逐字段比对。"""

    snap = {}
    for ind, ioc in service.store._iocs.items():
        snap[ind] = (
            ioc.verdict, ioc.confidence, ioc.status, ioc.weight_version,
            ioc.expires_at, ioc.revoked, ioc.updated_at,
            tuple((h.action, h.detail) for h in ioc.history),
            tuple(sorted(ioc.sources)),
        )
    return snap


def test_set_weights_failure_leaves_config_and_data_both_unchanged():
    """调权触发的重判中途失败：权重配置与存量结论要么一起生效、要么都不变。

    复现"新一版权重已对外生效、存量还按旧权重"的撕裂缺陷：修复后失败时
    权重版本必须停在 v0，存量结论/版本标记也必须原样不动。
    """

    service = ThreatIocService()
    _ingest_sample(service)
    print("\n[场景] 调权重判在提交前注入失败，检查配置与存量是否同时回滚")

    before_data = _full_snapshot(service)
    before_weights = (
        service.weights.current().version,
        [h["version"] for h in service.weight_history()],
    )
    print("[判定依据] 失败前 存量:", {k: v[:4] for k, v in before_data.items()})
    print("[判定依据] 失败前 权重:", before_weights)

    def _boom():
        raise RuntimeError("模拟重算全部完成后提交前失败")

    with pytest.raises(Exception) as exc:
        service.set_weights({"alpha": 0.5}, note="撕裂复现", fail_hook=_boom)
    print("[判定依据] 调用方收到异常:", type(exc.value).__name__, "|",
          str(exc.value)[:60], "| cause:",
          type(exc.value.__cause__).__name__)

    after_data = _full_snapshot(service)
    after_weights = (
        service.weights.current().version,
        [h["version"] for h in service.weight_history()],
    )
    print("[判定依据] 失败后 存量:", {k: v[:4] for k, v in after_data.items()})
    print("[判定依据] 失败后 权重:", after_weights)
    assert after_data == before_data          # 存量结论/版本/审计/来源零变更
    assert after_weights == before_weights    # 权重版本与历史也零变更
    assert after_weights[0] == 0
    # 错误被明确反馈，而不是静默吞掉
    from app.store import RejudgeFailed
    assert isinstance(exc.value, RejudgeFailed)
    assert isinstance(exc.value.__cause__, RuntimeError)


def test_retry_same_weights_after_failure_records_single_version():
    """失败后用同一份权重重试：版本/历史只推进一格，终态等同一次成功。"""

    service = ThreatIocService()
    _ingest_sample(service)
    print("\n[场景] 失败后用同一份权重再次调权")

    def _fail_first():
        raise RuntimeError("第一次失败")

    with pytest.raises(RejudgeFailed):
        service.set_weights({"alpha": 0.5}, note="第一次（失败）",
                            fail_hook=_fail_first)

    # 参照：从头开始、一次调权成功
    reference = ThreatIocService()
    _ingest_sample(reference)
    reference.set_weights({"alpha": 0.5}, note="一次成功")

    result = service.set_weights({"alpha": 0.5}, note="重试（成功）")
    print("[判定依据] 重试响应:", result["version"], result["rejudge"])

    versions = [h["version"] for h in service.weight_history()]
    print("[判定依据] 权重版本序列:", versions)
    assert versions == [0, 1]                 # 失败不占版本号，重试不重复记账
    assert service.weights.current().version == 1

    got = _snapshot(service)
    want = _snapshot(reference)
    print("[判定依据] 重试终态:", got)
    print("[判定依据] 参照终态:", want)
    assert got == want                        # 与一次成功完全一致
    assert all(v[3] == 1 for v in got.values())  # 存量与新数据版本标记统一


def test_failure_preserves_conclusions_provenance_and_hidden_lifecycle():
    """失败不能改坏已有数据：结论/版本/来源追溯原样，过期与撤回不复活。"""

    service = ThreatIocService()
    service.submit_batch("p-b1", [
        _good("192.0.2.30", "alpha", confidence=0.9, verdict="malicious"),
        _good("192.0.2.30", "beta", confidence=0.5, verdict="benign"),
        _good("192.0.2.31", "alpha", confidence=0.9,
              expires_at="2026-09-22T00:00:00Z"),   # 已过期
        _good("192.0.2.32", "alpha", confidence=0.9, revoked=True),  # 已撤回
    ])
    print("\n[场景] 含多来源/过期/撤回指标，调权重判失败")
    before = _full_snapshot(service)
    before_visible = {i.indicator for i in service.list_active(now=NOW)}
    print("[判定依据] 失败前可见:", before_visible)

    def _fail_provenance():
        raise ValueError("重算失败")

    with pytest.raises(RejudgeFailed):
        service.set_weights({"alpha": 2.0}, note="应整体回滚",
                            fail_hook=_fail_provenance)

    after = _full_snapshot(service)
    after_visible = {i.indicator for i in service.list_active(now=NOW)}
    print("[判定依据] 失败后可见:", after_visible)
    assert after == before                    # 结论/版本标记/来源追溯全保持
    assert after_visible == before_visible    # 过期/撤回没有重新冒出来
    assert "192.0.2.31" not in after_visible
    assert "192.0.2.32" not in after_visible


def test_failed_reweight_concurrent_with_ingestion_never_mixes_versions():
    """失败调权的窗口内并发投递批次：不丢数据，且不出现新旧权重混用。

    用 Barrier 让一个批次严格在"重算完成但尚未提交（随后失败）"的窗口里
    尝试写入；由于调权+重判与批次共用同一把锁，该批次必然整体排在失败
    事务之后（按旧权重 v0 入库），随后重试成功把全量统一推进到 v1。
    """

    service = ThreatIocService()
    _ingest_sample(service)
    print("\n[场景] 失败调权窗口内并发投递 4 个批次，随后重试成功")

    entered = threading.Barrier(2)

    def _hook():
        # 此时重算已完成、提交尚未发生；释放批次线程后立即让事务失败，
        # 于是被释放的批次只能在事务回滚释放锁之后按旧权重 v0 写入
        entered.wait()
        raise RuntimeError("提交前失败，触发整体回滚")

    failure_seen: list[BaseException] = []

    def do_failed_reweight():
        try:
            service.set_weights({"alpha": 0.5}, note="并发失败",
                                fail_hook=_hook)
        except RejudgeFailed as exc:
            # 预期失败，由主线程随后重试；记录下来供断言不静默吞错
            failure_seen.append(exc)

    def do_ingest(n):
        entered.wait() if n == 0 else None
        service.submit_batch(f"xc-{n}", [
            _good(f"203.0.113.{100 + n}", "gamma", confidence=0.6,
                  verdict="suspicious"),
        ])

    threads = [threading.Thread(target=do_failed_reweight)]
    threads += [threading.Thread(target=do_ingest, args=(n,))
                for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 失败事务后：配置仍 v0；窗口期批次要么还没写、要么整体按 v0 写入
    assert len(failure_seen) == 1               # 失败被明确反馈，未静默
    assert service.weights.current().version == 0
    mid_versions = {ioc.indicator: ioc.weight_version
                    for ioc in service.store.all_iocs()}
    print("[判定依据] 失败窗口期后版本分布:", set(mid_versions.values()))
    assert set(mid_versions.values()) <= {0}  # 绝不能出现 v0/v1 混用

    # 重试成功：全量统一 v1，无丢失（2 存量 + 4 新）
    result = service.set_weights({"alpha": 0.5}, note="并发重试成功")
    final = _snapshot(service)
    version_dist = {v[3] for v in final.values()}
    print(f"[判定依据] 重试后总量={service.store.count()} 版本分布={version_dist}")
    assert service.store.count() == 6
    assert all(v[3] == 1 for v in final.values())
    assert result["rejudge"]["rejudged"] == 6

    # 终态等价于"4 批次先按序入库、再一次调权成功"
    reference = ThreatIocService()
    _ingest_sample(reference)
    for n in range(4):
        reference.submit_batch(f"xc-{n}", [
            _good(f"203.0.113.{100 + n}", "gamma", confidence=0.6,
                  verdict="suspicious"),
        ])
    reference.set_weights({"alpha": 0.5}, note="参照一次成功")
    assert final == _snapshot(reference)


def test_failed_reweight_surfaces_structured_http_error():
    """HTTP 层：重判失败返回结构化 500，且权重/存量未变更，可安全重试。"""

    from fastapi.testclient import TestClient

    import app.store as store_mod
    from app.api import create_app

    service = ThreatIocService()
    _ingest_sample(service)

    def _boom(self, *a, **k):
        raise RuntimeError("HTTP 路径模拟重判失败")

    # monkeypatch 计划阶段，确保走真实 HTTP 错误映射
    orig = store_mod.IocStore._plan_rejudge
    store_mod.IocStore._plan_rejudge = _boom
    try:
        client = TestClient(create_app(feeds_dir="/nonexistent"))
        client.app.state.service = service
        resp = client.put("/api/v1/weights",
                          json={"weights": {"alpha": 0.5}, "note": "http 失败"})
    finally:
        store_mod.IocStore._plan_rejudge = orig

    print("\n[场景] HTTP 调权，重判阶段失败")
    print("[判定依据] HTTP:", resp.status_code, resp.json())
    assert resp.status_code == 500
    body = resp.json()["detail"]
    assert body["code"] == "weight_publish_rejudge_failed"
    assert body["weight_version"] == 1
    assert service.weights.current().version == 0

    # 恢复后用同一份权重重试：200 且只记一版
    resp2 = client.put("/api/v1/weights",
                       json={"weights": {"alpha": 0.5}, "note": "http 重试"})
    print("[判定依据] HTTP 重试:", resp2.status_code, resp2.json()["version"])
    assert resp2.status_code == 200
    assert resp2.json()["version"] == 1


def test_manual_rejudge_failure_surfaces_structured_http_error():
    """HTTP 层：手动 POST /rejudge 失败也返回结构化 500，且不静默吞错。"""

    from fastapi.testclient import TestClient

    import app.store as store_mod
    from app.api import create_app

    service = ThreatIocService()
    _ingest_sample(service)
    service.set_weights({"alpha": 0.5}, note="先发配置", rejudge=False)

    def _boom(self, *a, **k):
        raise ValueError("手动重判重算失败")

    orig = store_mod.IocStore._plan_rejudge
    store_mod.IocStore._plan_rejudge = _boom
    try:
        client = TestClient(create_app(feeds_dir="/nonexistent"))
        client.app.state.service = service
        resp = client.post("/api/v1/rejudge")
    finally:
        store_mod.IocStore._plan_rejudge = orig

    print("\n[场景] HTTP 手动重判失败")
    print("[判定依据] HTTP:", resp.status_code, resp.json())
    assert resp.status_code == 500
    assert resp.json()["detail"]["code"] == "rejudge_failed"
    # 存量仍停在 v0（配置 v1 已发布但尚未重判，查询口径不变）
    assert all(i.weight_version == 0 for i in service.store.all_iocs())


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
