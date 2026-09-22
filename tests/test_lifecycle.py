"""生命周期、置信度与判定聚合规则测试。"""

from __future__ import annotations

from app.lifecycle import (
    aggregate_confidence,
    aggregate_verdict,
    default_expiry,
    derive_status,
    explain_confidence,
    explain_verdict,
    is_visible,
    parse_ts_iso,
)
from app.models import IocStatus, Verdict

NOW = "2026-09-23T00:00:00Z"


def test_confidence_single_source(make_obs):
    sources = {"alpha": make_obs("alpha", 0.8, "malicious")}
    print("\n[输入批次] 单来源:", {"alpha": "0.8/malicious"})
    value, basis = explain_confidence(sources, NOW)
    print("[判定依据]", basis)
    assert value == 0.8
    assert aggregate_confidence(sources, NOW) == 0.8


def test_confidence_corroboration_bonus_caps(make_obs):
    sources = {
        "alpha": make_obs("alpha", 0.7, "malicious"),
        "beta": make_obs("beta", 0.6, "suspicious"),
        "gamma": make_obs("gamma", 0.5, "malicious"),
        "delta": make_obs("delta", 0.4, "suspicious"),
        "epsilon": make_obs("epsilon", 0.3, "malicious"),
    }
    print("\n[输入批次] 五来源佐证，置信度 0.7/0.6/0.5/0.4/0.3")
    value, basis = explain_confidence(sources, NOW)
    print("[判定依据]", basis)
    # 0.7 基础 + 佐证加成上限 0.15
    assert value == 0.85


def test_confidence_all_expired_is_zero(make_obs):
    sources = {
        "alpha": make_obs("alpha", 0.9, "malicious",
                          expires_at="2026-09-22T00:00:00Z"),
    }
    print("\n[输入批次] 唯一来源已于 2026-09-22 过期，判定时刻", NOW)
    value, basis = explain_confidence(sources, NOW)
    print("[判定依据]", basis)
    assert value == 0.0


def test_verdict_conflict_downgrades_to_suspicious(make_obs):
    sources = {
        "alpha": make_obs("alpha", 0.7, "malicious"),
        "beta": make_obs("beta", 0.7, "benign"),
    }
    print("\n[输入批次] 来源冲突 alpha=0.7/malicious beta=0.7/benign")
    verdict, basis = explain_verdict(sources, NOW)
    print("[判定依据]", basis)
    assert verdict is Verdict.SUSPICIOUS


def test_verdict_clear_malicious_wins(make_obs):
    sources = {
        "alpha": make_obs("alpha", 0.9, "malicious"),
        "beta": make_obs("beta", 0.2, "benign"),
    }
    print("\n[输入批次] alpha=0.9/malicious beta=0.2/benign")
    verdict, basis = explain_verdict(sources, NOW)
    print("[判定依据]", basis)
    assert verdict is Verdict.MALICIOUS


def test_verdict_severity_order(make_obs):
    sources = {
        "a": make_obs("a", 0.5, "suspicious"),
        "b": make_obs("b", 0.5, "benign"),
    }
    print("\n[输入批次] suspicious + benign 同置信度")
    print("[判定依据]", explain_verdict(sources, NOW)[1])
    assert aggregate_verdict(sources, NOW) is Verdict.SUSPICIOUS


def test_expiry_boundary_is_exclusive(make_obs):
    """过期边界：expires_at 时刻本身即视为过期（左闭右开）。"""

    obs_expiry = "2026-09-23T00:00:00Z"
    print(f"\n[输入批次] expires_at={obs_expiry}，边界两侧查询")
    assert is_visible(revoked=False, expires_at=obs_expiry,
                      now="2026-09-22T23:59:59Z")
    assert not is_visible(revoked=False, expires_at=obs_expiry,
                          now="2026-09-23T00:00:00Z")
    assert not is_visible(revoked=False, expires_at=obs_expiry,
                          now="2026-09-24T00:00:00Z")
    assert derive_status(revoked=False, expires_at=obs_expiry,
                         now="2026-09-23T00:00:00Z") is IocStatus.EXPIRED
    print("[判定依据] now < expires_at => ACTIVE；now >= expires_at => EXPIRED")


def test_revoked_takes_precedence(make_obs):
    print("\n[输入批次] revoked=True 且未到 expires_at")
    status = derive_status(
        revoked=True, expires_at="2027-01-01T00:00:00Z", now=NOW
    )
    print("[判定依据] 撤回优先于过期判断 =>", status.value)
    assert status is IocStatus.REVOKED
    assert not is_visible(
        revoked=True, expires_at="2027-01-01T00:00:00Z", now=NOW
    )


def test_open_ended_expiry_never_expires():
    print("\n[输入批次] expires_at=None（开放有效期）")
    print("[判定依据] 无过期时间 => 始终 ACTIVE（除非撤回）")
    assert is_visible(revoked=False, expires_at=None, now="2099-01-01T00:00:00Z")


def test_default_expiry_and_timestamp_normalize():
    assert default_expiry("2026-09-23T10:00:00Z", 7) == "2026-09-30T10:00:00Z"
    assert parse_ts_iso("2026/09/23 10:00:00".replace("/", "-")) == (
        "2026-09-23T10:00:00Z")
    assert parse_ts_iso(0) == "1970-01-01T00:00:00Z"
