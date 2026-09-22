"""骨架冒烟测试：保证应用可导入、可构造。"""

from __future__ import annotations

from app.api import create_app
from app.models import Confidence, IOCTypes
from app.service import AggregatorService


def test_models_enum() -> None:
    assert IOCTypes.IP.value == "ip"
    assert Confidence.HIGH.score > Confidence.LOW.score


def test_app_construct() -> None:
    app = create_app(AggregatorService())
    assert app.title == "threat-ioc-aggregator"
