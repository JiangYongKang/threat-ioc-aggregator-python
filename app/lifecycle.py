"""置信度聚合、判定聚合与生命周期规则（纯函数，无 I/O）。

所有结论均可解释：聚合函数同时返回人类可读的判定依据字符串。
时间统一使用 UTC，ISO-8601 字符串（以 Z 结尾）在系统内流转。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP

from app.models import IocStatus, SourceContribution, SourceObservation, Verdict

# 判定严重度排序：用于多数来源聚合时的兜底比较
_SEVERITY = {
    Verdict.MALICIOUS: 3,
    Verdict.SUSPICIOUS: 2,
    Verdict.UNKNOWN: 1,
    Verdict.BENIGN: 0,
}

# 每多一个独立来源佐证带来的置信度加成上限与步长
_CORROBORATION_STEP = Decimal("0.05")
_CORROBORATION_CAP = Decimal("0.15")
# 良性与恶性结论冲突时，置信度差小于该阈值则降级为可疑
_CONFLICT_MARGIN = Decimal("0.10")


# ---------------------------------------------------------------- 时间工具

def now_utc() -> datetime:
    """当前 UTC 时间（aware）。"""

    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    """把 datetime 格式化为系统内统一的 ISO-8601 UTC 字符串。"""

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    """当前时间的 ISO 字符串。"""

    return to_iso(now_utc())


def parse_ts(value: object) -> datetime:
    """把多种时间表达解析为 aware UTC datetime，无法解析时抛 ValueError。

    支持：ISO-8601（含 Z 结尾）、int/float（Unix 秒）。
    """

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"无法解析时间戳: {value!r}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"无法解析时间戳: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_ts_iso(value: object) -> str:
    """解析时间并归一为系统 ISO 字符串。"""

    return to_iso(parse_ts(value))


def default_expiry(first_seen_iso: str, validity_days: int) -> str:
    """按首次可见时间与有效期天数计算过期时间。"""

    return to_iso(parse_ts(first_seen_iso) + timedelta(days=validity_days))


# ------------------------------------------------------------- 观测过滤

def is_observation_live(obs: SourceObservation, now: str) -> bool:
    """单个来源观测在给定时刻是否仍有效（未撤回且未过期）。"""

    if obs.revoked:
        return False
    if obs.expires_at is not None and parse_ts(now) >= parse_ts(obs.expires_at):
        return False
    return True


def live_observations(
    sources: dict[str, SourceObservation], now: str
) -> dict[str, SourceObservation]:
    """返回当前仍有效的来源观测子集。"""

    return {s: o for s, o in sources.items() if is_observation_live(o, now)}


# ------------------------------------------------------------- 权重工具

def _weight_of(weights: dict[str, float] | None, source: str) -> float:
    """取来源权重；weights 为 None 或来源未配置时均为 1.0（旧口径）。"""

    if weights is None:
        return 1.0
    return float(weights.get(source, 1.0))


def effective_confidence(
    obs: SourceObservation, weights: dict[str, float] | None, source: str
) -> float:
    """来源观测的加权有效置信度：raw * weight，裁剪到 [0, 0.999]。

    权重为 1.0（未配置）时有效置信度与原始置信度完全一致。
    """

    w = _weight_of(weights, source)
    return min(0.999, max(0.0, obs.confidence * w))


def explain_contributions(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: dict[str, float] | None = None,
) -> list[SourceContribution]:
    """逐来源列出对最终结论的贡献：权重、原始/有效置信度、是否仍有效。"""

    now = now or now_iso()
    out: list[SourceContribution] = []
    for source in sorted(sources):
        obs = sources[source]
        out.append(SourceContribution(
            source=source,
            weight=_weight_of(weights, source),
            raw_confidence=obs.confidence,
            effective_confidence=round(
                effective_confidence(obs, weights, source), 3),
            verdict=obs.verdict.value,
            live=is_observation_live(obs, now),
        ))
    return out


# ------------------------------------------------------------- 置信度聚合

def explain_confidence(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: dict[str, float] | None = None,
) -> tuple[float, str]:
    """聚合置信度并返回 (置信度, 判定依据)。

    规则（可解释）：
    1. 仅统计当前仍有效、且给出了明确结论（verdict != unknown）的来源；
    2. 每个来源先按权重折算有效置信度（raw * weight，裁剪到 [0, 0.999]），
       未配置权重的来源权重为 1.0，折算后与原始值一致；
    3. 基础置信度取这些来源中的最高有效置信度；
    4. 每增加一个独立佐证来源 +0.05，佐证加成上限 0.15；
    5. 结果四舍五入保留三位小数。
    """

    now = now or now_iso()
    live = live_observations(sources, now)
    asserting = {
        s: o for s, o in live.items() if o.verdict is not Verdict.UNKNOWN
    }
    if not asserting:
        return 0.0, "无任何有效来源给出明确结论，置信度记为 0"

    eff = {s: effective_confidence(o, weights, s) for s, o in asserting.items()}
    # max 在并列时取先出现者，与旧版（未加权）行为保持一致
    top_source = max(eff, key=lambda s: eff[s])
    base = Decimal(str(round(eff[top_source], 6)))
    extra_count = len(asserting) - 1
    bonus = min(_CORROBORATION_CAP, _CORROBORATION_STEP * extra_count)
    value = (base + bonus).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
    value = min(Decimal("0.999"), value)
    if weights is None:
        detail = (
            f"基础置信度 {base} 取最高来源 {top_source}；"
            f"另有 {extra_count} 个独立佐证来源，加成 {bonus}；"
            f"聚合置信度 {value}"
        )
    else:
        parts = "；".join(
            f"{s} 权重 {_weight_of(weights, s)} "
            f"有效置信度 {round(eff[s], 3)}（原始 {asserting[s].confidence}）"
            for s in sorted(eff)
        )
        detail = (
            f"加权折算：{parts}；"
            f"基础置信度 {base} 取最高来源 {top_source}；"
            f"另有 {extra_count} 个独立佐证来源，加成 {bonus}；"
            f"聚合置信度 {value}"
        )
    return float(value), detail


def aggregate_confidence(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: dict[str, float] | None = None,
) -> float:
    """根据各来源观测聚合可解释的置信度。"""

    return explain_confidence(sources, now, weights)[0]


# --------------------------------------------------------------- 判定聚合

def explain_verdict(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: dict[str, float] | None = None,
) -> tuple[Verdict, str]:
    """聚合最终判定并返回 (判定, 判定依据)。

    规则（可解释）：
    - 仅采纳当前有效来源的结论；无有效来源时为 unknown；
    - 恶意与良性结论并存时比较双方的加权有效置信度
      （raw * weight，未配置权重为 1.0），差距 <= 0.10 时
      因来源冲突降级为 suspicious；
    - 否则取严重度最高的结论（malicious > suspicious > benign）。
    """

    now = now or now_iso()
    live = live_observations(sources, now)
    assertions = [(s, o) for s, o in live.items() if o.verdict is not Verdict.UNKNOWN]
    if not assertions:
        return Verdict.UNKNOWN, "无有效来源结论，判定为 unknown"

    eff = {s: effective_confidence(o, weights, s) for s, o in assertions}
    malicious = [(s, o) for s, o in assertions if o.verdict is Verdict.MALICIOUS]
    benign = [(s, o) for s, o in assertions if o.verdict is Verdict.BENIGN]

    if malicious and benign:
        top_mal = max(malicious, key=lambda kv: eff[kv[0]])
        top_ben = max(benign, key=lambda kv: eff[kv[0]])
        diff = Decimal(str(round(eff[top_mal[0]], 6))) - Decimal(
            str(round(eff[top_ben[0]], 6)))
        if diff <= _CONFLICT_MARGIN:
            return Verdict.SUSPICIOUS, (
                f"来源结论冲突：{top_mal[0]} 报恶意"
                f"(有效置信度 {round(eff[top_mal[0]], 3)})，"
                f"{top_ben[0]} 报良性(有效置信度 {round(eff[top_ben[0]], 3)})，"
                f"差距 {diff} <= {_CONFLICT_MARGIN}，降级为 suspicious"
            )
        return Verdict.MALICIOUS, (
            f"恶意来源 {top_mal[0]} 有效置信度 {round(eff[top_mal[0]], 3)} "
            f"明显高于良性来源 {top_ben[0]} 的 {round(eff[top_ben[0]], 3)}"
            f"（差 {diff}），判定为 malicious"
        )

    winner = max(assertions, key=lambda kv: _SEVERITY[kv[1].verdict])
    names = ",".join(sorted(s for s, o in assertions if o.verdict is winner[1].verdict))
    return winner[1].verdict, f"来源 {names} 的最高严重度结论为 {winner[1].verdict.value}"


def aggregate_verdict(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: dict[str, float] | None = None,
) -> Verdict:
    """根据各来源判定聚合最终结论。"""

    return explain_verdict(sources, now, weights)[0]


# ------------------------------------------------------------- 生命周期

def derive_expiry(sources: dict[str, SourceObservation]) -> str | None:
    """聚合过期时间：任一未撤回来源开放有效期则整体开放，否则取最晚者。

    已撤回的来源不再参与有效期计算。
    """

    candidates = [o.expires_at for o in sources.values() if not o.revoked]
    if not candidates:
        return None
    if any(e is None for e in candidates):
        return None
    return max(candidates, key=lambda e: parse_ts(e))


def derive_status(
    *,
    revoked: bool,
    expires_at: str | None,
    now: str | None = None,
) -> IocStatus:
    """依据撤回标记与过期时间推导生命周期状态。"""

    now = now or now_iso()
    if revoked:
        return IocStatus.REVOKED
    if expires_at is not None and parse_ts(now) >= parse_ts(expires_at):
        return IocStatus.EXPIRED
    return IocStatus.ACTIVE


def is_visible(
    *,
    revoked: bool,
    expires_at: str | None,
    now: str | None = None,
) -> bool:
    """指标在给定时刻是否可出现在查询结果中（仅 ACTIVE 可见）。"""

    return derive_status(
        revoked=revoked, expires_at=expires_at, now=now
    ) is IocStatus.ACTIVE
