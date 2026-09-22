"""本地端到端验证：加载 data/sources 全部情报并打印汇聚结果与判定依据。

用法:
    uv run python scripts/load_feeds.py
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.feed_loader import ingest_feed_dir, load_feed_dir  # noqa: E402
from app.service import AggregatorService  # noqa: E402
from app.store import IndicatorStore  # noqa: E402

FEED_DIR = ROOT / "data" / "sources"


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    service = AggregatorService(IndicatorStore())

    print("=== 1. 加载来源文件 ===")
    for feed in load_feed_dir(FEED_DIR):
        print(f"  - {feed.path.name} (source={feed.source})")

    print("\n=== 2. 第一遍提交（并发模拟见 tests）===")
    results = ingest_feed_dir(service, FEED_DIR)
    for r in results:
        print(f"  batch={r.batch_id} new={r.accepted_new} merged={r.merged} "
              f"rejected={len(r.rejected)} degraded={len(r.degraded)} replayed={r.replayed}")

    print("\n=== 3. 第二遍重放（必须幂等）===")
    results2 = ingest_feed_dir(service, FEED_DIR)
    for r in results2:
        print(f"  batch={r.batch_id} replayed={r.replayed} accepted_total={r.accepted_total}")

    now = datetime.now()
    print(f"\n=== 4. 当前有效指标 (now={now.isoformat()}) ===")
    for item in service.query(now=now):
        print(f"  [{item['ioc_type']}] {item['indicator']} "
              f"confidence={item['confidence']} sources={item['sources']}")
        print(f"      判定依据: {item['explanation']}")

    print("\n=== 5. 含过期/撤回的全部指标 ===")
    for item in service.query(now=now, include_inactive=True):
        print(f"  [{item['status']:7}] {item['indicator']} "
              f"confidence={item['confidence']} sources={item['sources']}")

    print("\n=== 6. 被拒绝/降级明细（以来源 B 的批次结果为例）===")
    for r in results:
        if r.rejected or r.degraded:
            print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2, default=str))

    print("\n=== 7. 存储统计 ===")
    print(json.dumps(service.store.stats(now), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
