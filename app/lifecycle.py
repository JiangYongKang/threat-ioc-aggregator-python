"""置信度聚合、判定聚合与生命周期规则（纯函数，无 I/O）。

所有结论均可解释：聚合函数同时返回人类可读的判定依据字符串。
时间统一使用 UTC，ISO-8601 字符串（以 Z 结尾）在系统内流转。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP

from app.models import IocStatus, SourceObservation, Verdict

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


# ------------------------------------------------------------- 权重适配

def _weight_fn(weights: object):
    """把可选的权重配置（带 weight_of 方法）归一为取权函数。

    weights 为 None 时所有来源按 1.0 处理，与引入权重机制前完全一致。
    """

    if weights is None:
        return lambda _source: 1.0
    return weights.weight_of


# ------------------------------------------------------------- 置信度聚合

def explain_confidence(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: object | None = None,
) -> tuple[float, str]:
    """聚合置信度并返回 (置信度, 判定依据)。

    规则（可解释）：
    1. 仅统计当前仍有效、且给出了明确结论（verdict != unknown）的来源；
    2. 每个来源的有效置信度 = 来源权重 × 原始置信度，
       基础置信度取有效置信度最高的来源；
    3. 佐证加成 = 0.05 × 其余佐证来源的权重之和，上限 0.15；
    4. 结果四舍五入保留三位小数；
    5. 所有来源权重为默认 1.0 时，与未引入权重机制的口径完全一致。
    """

    now = now or now_iso()
    weight_of = _weight_fn(weights)
    live = live_observations(sources, now)
    asserting = {
        s: o for s, o in live.items() if o.verdict is not Verdict.UNKNOWN
    }
    if not asserting:
        return 0.0, "无任何有效来源给出明确结论，置信度记为 0"

    def effective(item: tuple[str, SourceObservation]) -> Decimal:
        return Decimal(str(weight_of(item[0]))) * Decimal(str(item[1].confidence))

    top_source, top_obs = max(asserting.items(), key=effective)
    top_weight = Decimal(str(weight_of(top_source)))
    base = Decimal(str(top_obs.confidence)) * top_weight
    extra_weight = sum(
        Decimal(str(weight_of(s))) for s in asserting if s != top_source
    )
    bonus = min(_CORROBORATION_CAP, _CORROBORATION_STEP * extra_weight)
    value = (base + bonus).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
    value = min(Decimal("0.999"), value)
    detail = (
        f"基础置信度 {base} = 来源 {top_source} 原始 {top_obs.confidence} "
        f"× 权重 {top_weight}（有效置信度最高）；"
        f"其余佐证来源权重合计 {extra_weight}，加成 {bonus}；"
        f"聚合置信度 {value}"
    )
    return float(value), detail


def aggregate_confidence(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: object | None = None,
) -> float:
    """根据各来源观测聚合可解释的置信度。"""

    return explain_confidence(sources, now, weights)[0]


# --------------------------------------------------------------- 判定聚合

def explain_verdict(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: object | None = None,
) -> tuple[Verdict, str]:
    """聚合最终判定并返回 (判定, 判定依据)。

    规则（可解释）：
    - 仅采纳当前有效来源的结论；无有效来源时为 unknown；
    - 恶意与良性结论并存时，比较双方有效置信度（权重 × 原始置信度）
      的最高值，差 <= 0.10 则因来源冲突降级为 suspicious；
    - 否则取严重度最高的结论（malicious > suspicious > benign）；
    - 所有来源权重为默认 1.0 时，与未引入权重机制的口径完全一致。
    """

    now = now or now_iso()
    weight_of = _weight_fn(weights)
    live = live_observations(sources, now)
    assertions = [(s, o) for s, o in live.items() if o.verdict is not Verdict.UNKNOWN]
    if not assertions:
        return Verdict.UNKNOWN, "无有效来源结论，判定为 unknown"

    def effective(item: tuple[str, SourceObservation]) -> Decimal:
        return Decimal(str(weight_of(item[0]))) * Decimal(str(item[1].confidence))

    malicious = [(s, o) for s, o in assertions if o.verdict is Verdict.MALICIOUS]
    benign = [(s, o) for s, o in assertions if o.verdict is Verdict.BENIGN]

    if malicious and benign:
        top_mal = max(malicious, key=effective)
        top_ben = max(benign, key=effective)
        eff_mal = effective(top_mal)
        eff_ben = effective(top_ben)
        diff = eff_mal - eff_ben
        if diff <= _CONFLICT_MARGIN:
            return Verdict.SUSPICIOUS, (
                f"来源结论冲突：{top_mal[0]} 报恶意(有效置信度 {eff_mal} = "
                f"{top_mal[1].confidence} × 权重 {weight_of(top_mal[0])})，"
                f"{top_ben[0]} 报良性(有效置信度 {eff_ben} = "
                f"{top_ben[1].confidence} × 权重 {weight_of(top_ben[0])})，"
                f"差距 {diff} <= {_CONFLICT_MARGIN}，降级为 suspicious"
            )
        return Verdict.MALICIOUS, (
            f"恶意来源 {top_mal[0]} 有效置信度 {eff_mal} 明显高于"
            f"良性来源 {top_ben[0]} 的 {eff_ben}（差 {diff}），"
            f"判定为 malicious"
        )

    winner = max(assertions, key=lambda kv: _SEVERITY[kv[1].verdict])
    names = ",".join(sorted(s for s, o in assertions if o.verdict is winner[1].verdict))
    return winner[1].verdict, f"来源 {names} 的最高严重度结论为 {winner[1].verdict.value}"


def aggregate_verdict(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: object | None = None,
) -> Verdict:
    """根据各来源判定聚合最终结论。"""

    return explain_verdict(sources, now, weights)[0]


def explain_contributions(
    sources: dict[str, SourceObservation],
    now: str | None = None,
    weights: object | None = None,
) -> list[dict[str, object]]:
    """逐来源列出对最终结论的贡献（权重、有效置信度、是否计入聚合）。"""

    now = now or now_iso()
    weight_of = _weight_fn(weights)
    rows: list[dict[str, object]] = []
    for source in sorted(sources):
        obs = sources[source]
        live = is_observation_live(obs, now)
        asserting = live and obs.verdict is not Verdict.UNKNOWN
        weight = weight_of(source)
        effective = round(weight * obs.confidence, 3) if asserting else 0.0
        rows.append({
            "source": source,
            "weight": weight,
            "confidence": obs.confidence,
            "verdict": obs.verdict.value,
            "live": live,
            "counted": asserting,
            "effective_confidence": effective,
        })
    return rows


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
