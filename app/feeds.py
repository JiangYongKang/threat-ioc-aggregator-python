"""本地情报文件加载，模拟多个来源的推送。

约定的情报文件格式（JSON，UTF-8），支持两种形态：
1. 裸列表：[{...}, {...}]，来源由文件名（去掉扩展名）推断；
2. 信封对象：
   {
     "source": "alpha",
     "batch_id": "alpha-2026-09-20",   # 可选，缺省用文件内容指纹
     "entries": [ {...}, {...} ]
   }

无法解析的文件不会让整个加载过程崩溃，而是返回明确的加载错误，
由上层决定如何记录（同样不静默丢弃）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.logging_utils import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class LoadedFeed:
    """成功加载的一个情报文件。"""

    path: Path
    source: str
    batch_id: str | None
    entries: list[object]


@dataclass(frozen=True, slots=True)
class FeedLoadError:
    """单个情报文件的加载失败信息。"""

    path: Path
    detail: str


def discover_feed_files(feeds_dir: str | Path) -> list[Path]:
    """发现目录下全部 .json 情报文件（按文件名排序，保证加载顺序确定）。"""

    base = Path(feeds_dir)
    if not base.exists():
        return []
    return sorted(p for p in base.glob("*.json") if p.is_file())


def load_feed_file(
    path: str | Path,
) -> tuple[LoadedFeed | None, FeedLoadError | None]:
    """加载单个情报文件。

    返回 (LoadedFeed, None) 或 (None, FeedLoadError)，二者互斥。
    """

    p = Path(path)
    source_hint = p.stem
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        return None, FeedLoadError(p, f"文件读取失败: {exc}")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, FeedLoadError(
            p, f"JSON 解析失败（行 {exc.lineno} 列 {exc.colno}）: {exc.msg}"
        )

    if isinstance(payload, list):
        return LoadedFeed(
            path=p, source=source_hint, batch_id=None, entries=payload
        ), None

    if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
        source = payload.get("source") or source_hint
        if not isinstance(source, str) or not source.strip():
            return None, FeedLoadError(p, "信封 source 字段为空或非字符串")
        batch_id = payload.get("batch_id")
        if batch_id is not None and not isinstance(batch_id, str):
            return None, FeedLoadError(p, "信封 batch_id 必须为字符串")
        return LoadedFeed(
            path=p,
            source=source.strip(),
            batch_id=batch_id.strip() if isinstance(batch_id, str) else None,
            entries=payload["entries"],
        ), None

    return None, FeedLoadError(
        p,
        "情报文件必须是条目列表，或含 entries 列表的信封对象，"
        f"实际顶层类型 {type(payload).__name__}",
    )


def load_all_feeds(
    feeds_dir: str | Path,
) -> tuple[list[LoadedFeed], list[FeedLoadError]]:
    """发现并加载目录下所有情报文件，分别返回成功与失败清单。"""

    loaded: list[LoadedFeed] = []
    errors: list[FeedLoadError] = []
    for path in discover_feed_files(feeds_dir):
        feed, err = load_feed_file(path)
        if err is not None:
            logger.warning("[情报文件加载失败] %s: %s", err.path, err.detail)
            errors.append(err)
        else:
            logger.info("[情报文件已加载] %s source=%s 条目=%d",
                        feed.path, feed.source, len(feed.entries))
            loaded.append(feed)
    return loaded, errors
