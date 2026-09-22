"""本地情报文件加载：用 data/sources 下的文件模拟多来源推送。"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from app.exceptions import BatchRejected, IOCServiceError
from app.models import BatchResult
from app.service import AggregatorService

logger = logging.getLogger("ioc_aggregator.feed")


@dataclass(frozen=True)
class RawFeed:
    source: str
    path: Path
    payload: dict


def load_feed_file(path: Path) -> RawFeed:
    """读取单个来源文件：JSON 顶层为 {"source": ..., "batch_id": ..., "entries": [...]}。

    文件不是合法 JSON / 结构错误时抛出 IOCServiceError，由调用方决定处理方式。
    """
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IOCServiceError(f"情报文件不存在: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IOCServiceError(f"情报文件不是合法 JSON ({path}): {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise IOCServiceError(f"情报文件结构错误 ({path})：需要对象且包含 entries 数组")
    source = payload.get("source") or path.stem
    return RawFeed(source=source, path=path, payload=payload)


def load_feed_dir(feed_dir: Path) -> list[RawFeed]:
    feed_dir = Path(feed_dir)
    if not feed_dir.is_dir():
        raise IOCServiceError(f"情报目录不存在: {feed_dir}")
    feeds = [load_feed_file(p) for p in sorted(feed_dir.glob("*.json"))]
    logger.info("从 %s 加载了 %d 个来源文件", feed_dir, len(feeds))
    return feeds


def ingest_feed_dir(
    service: AggregatorService,
    feed_dir: Path,
    *,
    skip_invalid: bool = True,
) -> list[BatchResult]:
    """加载并逐个提交目录下的全部来源文件。

    skip_invalid=True 时，单个非法文件/批次被跳过并记录日志，不影响其他来源；
    否则抛出异常。重复执行（重放）结果幂等。
    """
    results: list[BatchResult] = []
    for feed in load_feed_dir(feed_dir):
        payload = dict(feed.payload)
        payload.setdefault("source", feed.source)
        try:
            results.append(service.submit_batch(payload))
        except BatchRejected as exc:
            logger.error("来源文件 %s 整批被拒绝: reason=%s detail=%s",
                         feed.path.name, exc.reason, exc.detail)
            if not skip_invalid:
                raise
    return results


__all__ = ["RawFeed", "load_feed_file", "load_feed_dir", "ingest_feed_dir"]
