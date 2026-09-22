"""统一日志工具（骨架：空实现占位）。"""

from __future__ import annotations

import logging


def get_logger(name: str) -> logging.Logger:
    """返回模块 logger。骨架阶段直接返回标准库 logger。"""
    return logging.getLogger(name)
