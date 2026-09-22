"""pytest 公共夹具与日志配置。"""

from __future__ import annotations

import logging
import sys

import pytest

# 打开 INFO 日志，单测日志中可见输入批次与判定依据
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    force=True,
)


@pytest.fixture()
def make_obs():
    """构造 SourceObservation 的工厂夹具。"""

    from app.models import SourceObservation, Verdict

    def _make(source, confidence, verdict, *, first_seen="2026-09-20T00:00:00Z",
              last_seen="2026-09-20T00:00:00Z",
              expires_at="2026-09-30T00:00:00Z", revoked=False,
              tags=None):
        return SourceObservation(
            source=source,
            confidence=confidence,
            verdict=Verdict(verdict) if isinstance(verdict, str) else verdict,
            tags=frozenset(tags or set()),
            first_seen=first_seen,
            last_seen=last_seen,
            expires_at=expires_at,
            revoked=revoked,
        )

    return _make
