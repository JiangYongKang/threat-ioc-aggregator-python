"""服务门面 + 本地情报文件端到端测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.service import ThreatIocService

FEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"
BOUNDARY = "2026-09-23T00:00:00Z"


@pytest.fixture()
def loaded_service():
    svc = ThreatIocService()
    reports = svc.load_local_feeds(str(FEEDS_DIR))
    return svc, reports


def test_feed_reports_distinguish_file_error(loaded_service):
    _, reports = loaded_service
    print("\n[输入批次] 加载目录 data/feeds，报告数 =", len(reports))
    errored = [r for r in reports if r.error]
    for r in errored:
        print(f"[判定依据] 文件错误 {r.feed_path}: {r.error}")
    assert len(errored) == 1
    assert "broken.json" in errored[0].feed_path
    assert "JSON 解析失败" in errored[0].error


def test_multi_source_indicator_single_consistent_record(loaded_service):
    svc, _ = loaded_service
    ioc = svc.query("203.0.113.10", now=BOUNDARY)
    print("\n[输入批次] 203.0.113.10 出现在 alpha/beta/gamma 三来源")
    print("[判定依据] sources =", sorted(ioc.sources),
          "verdict =", ioc.verdict.value, "confidence =", ioc.confidence)
    assert set(ioc.sources) == {"alpha", "beta", "gamma"}
    assert ioc.verdict.value == "malicious"
    assert 0.0 <= ioc.confidence <= 1.0

    active = svc.list_active(now=BOUNDARY)
    matches = [i for i in active if i.indicator == "203.0.113.10"]
    print("[判定依据] ACTIVE 列表中该指标出现次数 =", len(matches))
    assert len(matches) == 1  # 去重：只保留一份


def test_conclusion_stable_across_reloads(loaded_service):
    svc, reports1 = loaded_service
    before = sorted(
        (i.indicator, i.verdict.value, round(i.confidence, 6),
         tuple(sorted(i.sources)))
        for i in svc.list_active(now=BOUNDARY)
    )
    print("\n[输入批次] 对同一目录再次执行 load_local_feeds（模拟重放）")
    reports2 = svc.load_local_feeds(str(FEEDS_DIR))
    after = sorted(
        (i.indicator, i.verdict.value, round(i.confidence, 6),
         tuple(sorted(i.sources)))
        for i in svc.list_active(now=BOUNDARY)
    )
    replayed = [r for r in reports2 if r.result and r.result.replayed]
    print("[判定依据] 重放批次数 =", len(replayed), "/", len(reports2))
    assert len(replayed) == 4  # 4 个合法文件全部幂等
    assert before == after
    print("[判定依据] 重载前后可见指标结论完全一致，条数 =", len(after))


def test_expired_and_revoked_hidden_at_boundary(loaded_service):
    svc, _ = loaded_service
    print(f"\n[输入批次] 边界时刻 {BOUNDARY} 查询可见集")
    active_indicators = {i.indicator for i in svc.list_active(now=BOUNDARY)}
    print("[判定依据] 可见指标 =", sorted(active_indicators))
    # expires_at == 2026-09-23T00:00:00Z 恰好过期
    assert "expired-boundary.test" not in active_indicators
    # 唯一来源撤回
    assert "44.55.66.77" not in active_indicators
    # 但记录仍可追溯
    revoked_ioc = svc.query("44.55.66.77", now=BOUNDARY)
    print("[判定依据] 44.55.66.77 可追溯状态 =", revoked_ioc.status.value)
    assert revoked_ioc.status.value == "revoked"


def test_just_before_expiry_still_visible(loaded_service):
    svc, _ = loaded_service
    active = {i.indicator for i in svc.list_active(now="2026-09-22T23:59:59Z")}
    print("\n[输入批次] 2026-09-22T23:59:59Z（过期前一秒）")
    print("[判定依据] expired-boundary.test 可见 =",
          "expired-boundary.test" in active)
    assert "expired-boundary.test" in active


def test_explain_contains_human_basis(loaded_service):
    svc, _ = loaded_service
    ex = svc.explain("203.0.113.10", now=BOUNDARY)
    print("\n[输入批次] explain 203.0.113.10")
    print("[判定依据-置信度]", ex.confidence_basis)
    print("[判定依据-结论]", ex.verdict_basis)
    assert "基础置信度" in ex.confidence_basis
    assert "来源" in ex.verdict_basis
    assert ex.visible is True


def test_partial_source_revocation_keeps_indicator(loaded_service):
    """alpha 撤回 203.0.113.10，但 beta/gamma 仍有效 => 指标仍可见。"""

    svc, _ = loaded_service
    ioc = svc.query("203.0.113.10", now=BOUNDARY)
    live_sources = {s for s, o in ioc.sources.items() if not o.revoked}
    print("\n[输入批次] alpha 撤回，beta/gamma 未撤回")
    print("[判定依据] 仍有效来源 =", sorted(live_sources),
          "指标状态 =", ioc.status.value)
    assert live_sources == {"beta", "gamma"}
    assert ioc.status.value == "active"
