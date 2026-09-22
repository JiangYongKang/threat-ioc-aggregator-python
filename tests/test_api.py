"""HTTP API 测试：批次提交、幂等、非法批次错误码、查询过滤。"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.api import create_app


@pytest.fixture()
def client(tmp_path):
    # API 测试使用空情报目录，避免与文件样本耦合
    return TestClient(create_app(feeds_dir=str(tmp_path)))


def _post(client, body):
    print("\n[输入批次] POST /api/v1/batches body=",
          json.dumps(body, ensure_ascii=False)[:500])
    resp = client.post("/api/v1/batches", json=body)
    print("[判定依据] HTTP", resp.status_code, resp.text[:500])
    return resp


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "threat-ioc-aggregator"


def test_submit_batch_ok(client):
    resp = _post(client, {
        "batch_id": "api-1",
        "entries": [
            {"indicator": "203.0.113.77", "type": "ip", "source": "alpha",
             "confidence": 0.9, "verdict": "malicious",
             "first_seen": "2026-09-20T00:00:00Z", "validity_days": 30,
             "tags": ["c2"]},
        ],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] == 1 and data["rejected"] == 0

    listing = client.get("/api/v1/iocs").json()
    assert listing["count"] >= 1
    assert any(i["indicator"] == "203.0.113.77" for i in listing["items"])


def test_replay_returns_replayed_flag(client):
    body = {
        "batch_id": "api-replay",
        "entries": [{"indicator": "8.8.4.4", "type": "ip", "source": "alpha",
                     "confidence": 0.5, "first_seen":
                     "2026-09-20T00:00:00Z"}],
    }
    r1 = _post(client, body).json()
    r2 = _post(client, body).json()
    assert r1["replayed"] is False
    assert r2["replayed"] is True
    assert r2["accepted"] == r1["accepted"]
    assert client.get("/api/v1/iocs").json()["count"] == 1


def test_missing_batch_id_is_422_distinct_code(client):
    resp = _post(client, {"entries": [{"indicator": "1.1.1.1"}]})
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "missing_batch_id"


def test_non_list_batch_is_422_distinct_code(client):
    resp = _post(client, {
        "batch_id": "api-bad",
        "entries": {"oops": "not-a-list"},
    })
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "not_a_list"
    assert client.get("/api/v1/iocs").json()["count"] == 0


def test_empty_batch_is_422(client):
    resp = _post(client, {"batch_id": "api-empty", "entries": []})
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "empty_batch"


def test_rejected_entries_are_itemized(client):
    resp = _post(client, {
        "batch_id": "api-mixed",
        "entries": [
            {"indicator": "5.5.5.5", "type": "ip", "source": "alpha",
             "confidence": 0.6, "first_seen": "2026-09-20T00:00:00Z"},
            {"indicator": "   ", "source": "alpha"},
            "junk",
        ],
    })
    data = resp.json()
    assert data["accepted"] == 1
    codes = {e["reason"] for e in data["rejected_entries"]}
    print("[判定依据] 条目级拒绝原因 =", codes)
    assert codes == {"empty_indicator", "non_object_entry"}


def test_get_indicator_trace_and_explain(client):
    _post(client, {
        "batch_id": "api-trace",
        "entries": [{"indicator": "6.6.6.6", "type": "ip", "source": "alpha",
                     "confidence": 0.8, "verdict": "malicious",
                     "first_seen": "2026-09-20T00:00:00Z",
                     "validity_days": 30}],
    })
    detail = client.get("/api/v1/iocs/6.6.6.6").json()
    assert detail["sources"] == ["alpha"]
    assert any(h["action"] == "create" for h in detail["history"])

    ex = client.get("/api/v1/iocs/6.6.6.6/explain").json()
    print("[判定依据] explain:", ex["confidence_basis"], "|",
          ex["verdict_basis"])
    assert ex["verdict"] == "malicious"
    assert "confidence_basis" in ex

    assert client.get("/api/v1/iocs/no-such-thing").status_code == 404


def test_iocs_type_filter_rejects_unknown_type(client):
    resp = client.get("/api/v1/iocs?ioc_type=nope")
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "unsupported_ioc_type"
