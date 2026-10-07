"""来源可信度权重：版本化配置、校验与变更历史（纯数据 + 线程安全注册表）。

设计要点：
- 权重配置按版本递增，每次变更生成一个不可变 WeightConfig 快照；
- 未配置的来源一律按 DEFAULT_WEIGHT（1.0）处理，与引入权重前的口径一致；
- 注册表保存全部变更历史，支撑"什么时候被改成什么"的追溯；
- 聚合只依赖 (来源观测, 权重快照, 判定时刻)，因此"用新权重重新判定"
  与"用新权重把同样情报重新入库"天然等价。

发布原子性（与存储层配合）：
- candidate() 只做校验与"下一版快照"的构造，不产生任何变更；
- commit() 才真正发布；提交内容与当前版本一致时原样复用，不新增版本
  也不追加历史——因此"同一份权重失败后重试"不会重复记账；
- 注册表可绑定存储层的同一把锁（bind_lock），使"发布配置 + 全量重判"
  对其他线程呈现为一个不可分割的临界区。
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


class WeightPublishError(RuntimeError):
    """权重发布 + 存量重判的原子流程在重判阶段失败。

    与 WeightConfigError 区分：配置本身合法，失败发生在对存量指标做
    重新判定的过程中。原子保证意味着权重版本与存量数据均未变更，
    调用方可用同一份权重原样重试。
    """

    def __init__(self, candidate_version: int, detail: str) -> None:
        super().__init__(
            f"weight_publish_failed: 权重 v{candidate_version} 的发布与重判"
            f"整体回滚（{detail}），可用同一份权重重试"
        )
        self.candidate_version = candidate_version
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
    """线程安全的权重配置注册表：当前版本 + 全部变更历史。

    lock 可由外部（存储层）注入同一把可重入锁，使权重发布与批量重判
    能被同一个临界区包裹；不传则自建一把锁。
    """

    def __init__(self, lock: threading.RLock | None = None) -> None:
        self._lock = lock or threading.RLock()
        self._current = WeightConfig(
            version=0, weights={}, updated_at=now_iso(),
            note="初始默认配置：所有来源权重 1.0",
        )
        self._configs: dict[int, WeightConfig] = {0: self._current}
        self._history: list[WeightChange] = [
            WeightChange(version=0, at=self._current.updated_at,
                         weights={}, note=self._current.note)
        ]

    def lock(self) -> threading.RLock:
        """暴露底层锁；与 IocStore 共享时与存储锁是同一把。"""

        return self._lock

    def bind_lock(self, lock: threading.RLock) -> None:
        """改用外部传入的锁（由 IocStore 在装配时绑定为同一把）。

        只允许在任何并发使用之前绑定一次；注册表已经发布过非默认版本时
        拒绝重绑，避免运行期悄悄换锁。
        """

        with self._lock:
            if self._current.version != 0 or len(self._history) != 1:
                raise RuntimeError("权重注册表已产生变更，不能再绑定外部锁")
        self._lock = lock

    def current(self) -> WeightConfig:
        """返回当前生效的权重配置快照。"""

        with self._lock:
            return self._current

    def get_version(self, version: int) -> WeightConfig | None:
        """按版本号取历史配置快照；不存在返回 None。"""

        with self._lock:
            return self._configs.get(version)

    def candidate(self, weights: object, *, note: str = "",
                  now: str | None = None) -> tuple[WeightConfig, bool]:
        """校验并构造"下一版权重"快照，但**不发布、不记账**。

        返回 (config, reused)：
        - 校验失败抛 WeightConfigError，不产生任何副作用；
        - cleaned 与当前版本权重完全相同时，reused=True 且原样返回当前
          配置（版本/历史都不动）——失败重试同一份权重走这条路；
        - 否则构造 current.version + 1 的候选快照，reused=False。

        可在已持锁（含存储层共享锁）的情况下安全调用。
        """

        cleaned = validate_weights(weights)
        with self._lock:
            if self._current.weights == cleaned:
                return self._current, True
            config = WeightConfig(
                version=self._current.version + 1,
                weights=cleaned,
                updated_at=now or now_iso(),
                note=note,
            )
            return config, False

    def commit(self, config: WeightConfig) -> WeightConfig:
        """发布一个由 candidate() 构造的候选快照。

        注意"复用"按候选对象身份判定，而不是版本号：未提交的候选不占
        版本号，两个不同候选可能同为 current+1，仅凭版本号会让陈旧候选
        误覆盖新版本。
        """

        with self._lock:
            if config is self._current:
                return self._current
            if config.version != self._current.version + 1:
                raise WeightPublishConflict(
                    current_version=self._current.version,
                    candidate_version=config.version,
                )
            self._current = config
            self._configs[config.version] = config
            self._history.append(WeightChange(
                version=config.version, at=config.updated_at,
                weights=dict(config.weights), note=config.note,
            ))
            logger.info("[权重变更] version=%d weights=%s note=%s",
                        config.version, config.weights, config.note)
            return config

    def set_weights(self, weights: object, *, note: str = "",
                    now: str | None = None) -> WeightConfig:
        """校验并发布新一版权重配置，返回新配置快照。

        与当前版本内容相同时不产生新版本（幂等）。需要"发布 + 全量重判"
        整体原子时不要直接调用本方法，应使用 candidate()/commit() 与
        存储重判组成两阶段提交流程（见 ThreatIocService.set_weights）。
        """

        config, _reused = self.candidate(weights, note=note, now=now)
        return self.commit(config)

    def history(self) -> list[WeightChange]:
        """返回全部权重变更记录（含初始默认版本）。"""

        with self._lock:
            return list(self._history)


class WeightPublishConflict(RuntimeError):
    """候选权重版本与注册表当前版本不连续（不应在同一临界区内发生）。"""

    def __init__(self, *, current_version: int, candidate_version: int) -> None:
        super().__init__(
            f"权重候选版本 v{candidate_version} 与当前版本 v{current_version} "
            "不连续，发布已拒绝"
        )
        self.current_version = current_version
        self.candidate_version = candidate_version
