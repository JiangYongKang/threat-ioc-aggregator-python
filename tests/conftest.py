"""pytest 公共夹具与日志配置（单测需打印输入批次与判定依据）。"""

from __future__ import annotations

import logging

import pytest

from app.service import AggregatorService
from app.store import IndicatorStore


@pytest.fixture(autouse=True)
def _enable_ioc_logging(caplog) -> None:
    """让 ioc_aggregator 及其子 logger 的 INFO 日志在单测中可被捕获并打印。"""
    caplog.set_level(logging.INFO, logger="ioc_aggregator")
    logging.getLogger("ioc_aggregator").setLevel(logging.INFO)


@pytest.fixture()
def service() -> AggregatorService:
    return AggregatorService(store=IndicatorStore())
