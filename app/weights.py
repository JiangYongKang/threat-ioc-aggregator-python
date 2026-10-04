"""来源可信度权重配置：版本化管理 + 校验。

- 每个来源可配置一个正数权重；未配置的来源使用 DEFAULT_WEIGHT(1.0)，
  此时加权聚合退化为现有"一视同仁"口径，结论与旧版本完全一致；
- 权重配置按版本号递增管理，每次变更记录一条 WeightRevision（生效时间、
  完整权重表、备注），可追溯"什么时候被改成了什么"；
- 新版本只在全量重算成功后由 store 提交：重算失败 => 配置不变，
  用同样内容重试只会得到同一个结果（幂等）。
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass

from app.lifecycle import now_iso
from app.logging_utils import get_logger

logger = get_logger(__name__)

# 未配置来源的默认权重：1.0 时加权聚合退化为现有口径
DEFAULT_WEIGHT = 1.0

# 权重上限，防止极端配置把置信度放大到失去意义
MAX_WEIGHT = 100.0


class WeightConfigError(ValueError):
    """权重配置非法（非正数、非数值、来源名空白等），整体拒绝。"""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True, slots=True)
class WeightRevision:
    """一版权重配置：版本号、生效时间、内容与备注。"""

    version: int
    at: str
    weights: dict[str, float]
    note: str = ""


class WeightStore:
    """线程安全的权重配置存储：当前版本 + 全部历史。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._revisions: list[WeightRevision] = [
            WeightRevision(version=0, at="", weights={},
                           note="初始默认配置（所有来源权重 1.0）")
        ]

    # ------------------------------------------------------- 查询

    def current(self) -> WeightRevision:
        """当前生效的权重版本。"""

        with self._lock:
            return self._revisions[-1]

    def weight_for(self, source: str) -> float:
        """某来源的权重；未配置返回 DEFAULT_WEIGHT。"""

        return self.weights_view().get(source, DEFAULT_WEIGHT)

    def weights_view(self) -> dict[str, float]:
        """当前权重表的拷贝（供聚合函数使用，调用方修改不影响配置）。"""

        with self._lock:
            return dict(self._revisions[-1].weights)

    def history(self) -> list[WeightRevision]:
        """全部历史版本（含初始版本），按版本号升序。"""

        with self._lock:
            return list(self._revisions)

    # ------------------------------------------------------- 变更

    def validate(self, weights: object) -> dict[str, float]:
        """校验并归一化权重表；非法时抛 WeightConfigError，不产生任何变更。

        规则：必须是 dict；来源名非空白字符串；权重为 (0, MAX_WEIGHT]
        区间内的有限数值；bool 拒绝。归一化：来源名去空白，权重转 float。
        """

        if not isinstance(weights, dict):
            raise WeightConfigError(
                f"权重配置必须是 {{来源: 权重}} 的对象，"
                f"实际类型 {type(weights).__name__}"
            )
        normalized: dict[str, float] = {}
        for key, value in weights.items():
            if not isinstance(key, str) or not key.strip():
                raise WeightConfigError(f"来源名必须是非空白字符串: {key!r}")
            name = key.strip()
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise WeightConfigError(
                    f"来源 {name} 的权重不是数值: {value!r}")
            w = float(value)
            if not math.isfinite(w) or w <= 0.0:
                raise WeightConfigError(
                    f"来源 {name} 的权重必须是正数: {value!r}")
            if w > MAX_WEIGHT:
                raise WeightConfigError(
                    f"来源 {name} 的权重 {w} 超过上限 {MAX_WEIGHT}")
            normalized[name] = w
        return normalized

    def next_revision(self, weights: dict[str, float],
                      note: str = "") -> WeightRevision:
        """基于已校验的权重表构造下一版本（不提交）。"""

        with self._lock:
            return WeightRevision(
                version=self._revisions[-1].version + 1,
                at=now_iso(),
                weights=dict(weights),
                note=note,
            )

    def commit(self, revision: WeightRevision) -> None:
        """提交新版本（仅在全量重算成功后调用，保证整体生效/整体不生效）。"""

        with self._lock:
            if revision.version != self._revisions[-1].version + 1:
                raise WeightConfigError(
                    f"版本号不连续：期望 {self._revisions[-1].version + 1}，"
                    f"实际 {revision.version}"
                )
            self._revisions.append(revision)
            logger.info("[权重版本生效] version=%d weights=%s note=%s",
                        revision.version, revision.weights, revision.note)
