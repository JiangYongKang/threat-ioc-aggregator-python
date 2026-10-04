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

    def set_weights(self, weights: object, *, note: str = "",
                    now: str | None = None) -> WeightConfig:
        """校验并发布新一版权重配置，返回新配置快照。"""

        cleaned = validate_weights(weights)
        with self._lock:
            config = WeightConfig(
                version=self._current.version + 1,
                weights=cleaned,
                updated_at=now or now_iso(),
                note=note,
            )
            self._current = config
            self._configs[config.version] = config
            self._history.append(WeightChange(
                version=config.version, at=config.updated_at,
                weights=dict(cleaned), note=note,
            ))
            logger.info("[权重变更] version=%d weights=%s note=%s",
                        config.version, cleaned, note)
            return config

    def history(self) -> list[WeightChange]:
        """返回全部权重变更记录（含初始默认版本）。"""

        with self._lock:
            return list(self._history)
