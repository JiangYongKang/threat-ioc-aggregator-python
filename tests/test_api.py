"""HTTP API 测试：提交、重放状态码、可区分错误、查询过滤。"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.service import AggregatorService
from app.store import IndicatorStore

logger = logging.getLogger("ioc_aggregator.test")


@pytest.fixture()
def client() -> TestClient:
    service = AggregatorService(IndicatorStore())
    return TestClient(create_app(service))


def _valid_batch() -> dict:
    return {
        "batch_id": "api-1",
        "entries": [
            {"type": "ip", "value": "203.0.113.7", "source": "net", "confidence": 80,
             "valid_until": "2026-12-31T00:00:00", "last_seen": "2026-09-20T00:00:00",
             "tags": ["c2"]},
        ],
    }


def test_submit_then_get_and_list(client: TestClient) -> None:
    logger.info("输入批次=%s", _valid_batch())
    r = client.post("/api/v1/batches", json=_valid_batch())
    assert r.status_code == 201
    body = r.json()
    assert body["accepted_new"] == 1

    r2 = client.post("/api/v1/batches", json=_valid_batch())
    assert r2.status_code == 200 and r2.json()["replayed"] is True

    listed = client.get("/api/v1/indicators").json()
    assert listed["count"] == 1
    one = client.get("/api/v1/indicators/ip:203.0.113.7")
    assert one.status_code == 200
    assert one.json()["sources"] == ["net"]


def test_empty_batch_400_with_distinct_reason(client: TestClient) -> None:
    logger.info("输入批次=空 entries 判定依据：HTTP 400 reason=empty_batch")
    r = client.post("/api/v1/batches", json={"batch_id": "x", "entries": []})
    assert r.status_code == 400
    assert r.json()["reason"] == "empty_batch"


def test_malformed_json_and_shape(client: TestClient) -> None:
    r = client.post("/api/v1/batches", content=b"{not json",
                    headers={"content-type": "application/json"})
    assert r.status_code == 400 and r.json()["reason"] == "malformed_batch"

    r = client.post("/api/v1/batches", json={"entries": [{"type": "ip"}]})
    # 全部条目归一失败 -> 整批 malformed_batch，且无写入
    assert r.status_code == 400 and r.json()["reason"] == "malformed_batch"
    assert client.get("/api/v1/stats").json()["indicators_total"] == 0


def test_query_filters_and_inactive(client: TestClient) -> None:
    client.post("/api/v1/batches", json={
        "batch_id": "q1",
        "entries": [
            {"type": "ip", "value": "198.51.100.1", "source": "s1",
             "valid_until": "2026-12-31", "last_seen": "2026-09-01"},
            {"type": "ip", "value": "198.51.100.2", "source": "s2",
             "valid_until": "2026-01-01", "last_seen": "2026-01-01"},
        ],
    })
    logger.info("查询过滤：ioc_type/source/include_inactive")
    assert client.get("/api/v1/indicators", params={"source": "s1"}).json()["count"] == 1
    assert client.get("/api/v1/indicators", params={"ioc_type": "domain"}).json()["count"] == 0
    all_items = client.get("/api/v1/indicators", params={"include_inactive": "true"}).json()
    assert all_items["count"] == 2
    statuses = {i["indicator"]: i["status"] for i in all_items["indicators"]}
    assert statuses["ip:198.51.100.2"] == "expired"
    # 默认查询不含过期指标
    assert client.get("/api/v1/indicators").json()["count"] == 1


def test_indicator_not_found(client: TestClient) -> None:
    assert client.get("/api/v1/indicators/ip:9.9.9.9").status_code == 404
