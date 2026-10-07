"""来源可信度权重：版本化配置、校验与变更历史（纯数据 + 线程安全注册表）。

设计要点：
- 权重配置按版本递增，每次变更生成一个不可变 WeightConfig 快照；
- 未配置的来源一律按 DEFAULT_WEIGHT（1.0）处理，与引入权重前的口径一致；
- 注册表保存全部变更历史，支撑"什么时候被改成什么"的追溯；
- 聚合只依赖 (来源观测, 权重快照, 判定时刻)，因此"用新权重重新判定"
  与"用新权重把同样情报重新入库"天然等价。
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field

from app.lifecycle import now_iso
from app.logging_utils import get_logger

logger = get_logger(__name__)

# 未配置来源的默认权重：保持与引入权重机制前的结论口径一致
DEFAULT_WEIGHT = 1.0
# 权重合法范围（开区间下限，闭区间上限）
MAX_WEIGHT = 100.0


class WeightConfigError(ValueError):
    """权重配置非法（校验失败，不产生任何变更）。"""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


class WeightTransactionError(RuntimeError):
    """权重发布事务的内部状态不合法（如候选版本与当前版本不连续）。

    属于防御性错误：正常事务编排不会触发；触发即说明锁/并发编排有缺陷，
    此时注册表未发生任何变更。
    """


@dataclass(frozen=True, slots=True)
class WeightConfig:
    """一版不可变的来源权重配置。"""

    version: int
    weights: dict[str, float]
    updated_at: str
    note: str = ""

    def weight_of(self, source: str) -> float:
        """取来源权重；未配置的来源返回默认权重。"""

        return self.weights.get(source, DEFAULT_WEIGHT)


@dataclass(frozen=True, slots=True)
class WeightChange:
    """一次权重变更的审计记录。"""

    version: int
    at: str
    weights: dict[str, float]
    note: str


def validate_weights(weights: object) -> dict[str, float]:
    """校验并归一化权重表；非法时抛 WeightConfigError，不产生副作用。"""

    if not isinstance(weights, dict):
        raise WeightConfigError(
            "invalid_weight_config",
            f"权重配置必须是 {{来源: 权重}} 的对象，实际类型 {type(weights).__name__}",
        )
    cleaned: dict[str, float] = {}
    for source, raw in weights.items():
        if not isinstance(source, str) or not source.strip():
            raise WeightConfigError(
                "invalid_weight_config", f"来源标识非法: {source!r}"
            )
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise WeightConfigError(
                "invalid_weight_value",
                f"来源 {source} 的权重不是数值: {raw!r}",
            )
        value = float(raw)
        if not math.isfinite(value) or value <= 0.0 or value > MAX_WEIGHT:
            raise WeightConfigError(
                "invalid_weight_value",
                f"来源 {source} 的权重 {value} 超出合法范围 (0, {MAX_WEIGHT}]",
            )
        cleaned[source.strip()] = value
    return cleaned


class WeightRegistry:
    """线程安全的权重配置注册表：当前版本 + 全部变更历史。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._current = WeightConfig(
            version=0, weights={}, updated_at=now_iso(),
            note="初始默认配置：所有来源权重 1.0",
        )
        self._configs: dict[int, WeightConfig] = {0: self._current}
        self._history: list[WeightChange] = [
            WeightChange(version=0, at=self._current.updated_at,
                         weights={}, note=self._current.note)
        ]

    def current(self) -> WeightConfig:
        """返回当前生效的权重配置快照。"""

        with self._lock:
            return self._current

    def get_version(self, version: int) -> WeightConfig | None:
        """按版本号取历史配置快照；不存在返回 None。"""

        with self._lock:
            return self._configs.get(version)

    def stage_weights(self, weights: object, *, note: str = "",
                      now: str | None = None) -> WeightConfig:
        """校验并构造下一版候选配置快照，但**不发布**（无任何副作用）。

        用于"发布配置 + 存量重判"事务：调用方先 stage 拿到候选版本，
        在副本上完成重算后再调用 commit_weights 一次性发布；
        stage 之后若中途失败，注册表状态完全不变，可安全重试。
        """

        cleaned = validate_weights(weights)
        with self._lock:
            return WeightConfig(
                version=self._current.version + 1,
                weights=cleaned,
                updated_at=now or now_iso(),
                note=note,
            )

    def commit_weights(self, config: WeightConfig) -> None:
        """把 stage 出来的候选配置正式发布为当前版本并写入历史。

        只接受"紧邻当前版本的下一版"，防止并发/重试下跳号或重复记账。
        """

        with self._lock:
            expected = self._current.version + 1
            if config.version != expected:
                raise WeightTransactionError(
                    f"候选权重版本 v{config.version} 不是当前版本 "
                    f"v{self._current.version} 的下一版（应为 v{expected}），"
                    "拒绝发布以防跳号或重复记账"
                )
            self._current = config
            self._configs[config.version] = config
            self._history.append(WeightChange(
                version=config.version, at=config.updated_at,
                weights=dict(config.weights), note=config.note,
            ))
            logger.info("[权重变更] version=%d weights=%s note=%s",
                        config.version, dict(config.weights), config.note)

    def set_weights(self, weights: object, *, note: str = "",
                    now: str | None = None) -> WeightConfig:
        """校验并发布新一版权重配置，返回新配置快照。

        等价于 stage_weights + commit_weights 的独立快捷方式；
        需要与存量重判组成原子事务时，请改用两阶段方法。
        """

        config = self.stage_weights(weights, note=note, now=now)
        self.commit_weights(config)
        return config

    def history(self) -> list[WeightChange]:
        """返回全部权重变更记录（含初始默认版本）。"""

        with self._lock:
            return list(self._history)
