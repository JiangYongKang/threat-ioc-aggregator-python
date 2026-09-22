# 威胁情报 IOC 本地汇聚与判定服务

用本地情报文件模拟多个来源的情报推送，将字段风格各异的 IOC（失陷指标）
归一到统一模型，完成 **去重、生命周期管理、并发幂等入库**，并保证同一指标
在多来源、重复投递、过期/撤回场景下结论 **一致且可追溯**。

## 1. 能力概览

| 需求 | 实现 |
| --- | --- |
| 多来源入库与归一 | `app/normalizer.py`：字段别名映射、值规范化、置信度/时间多格式解析 |
| 残缺条目不静默丢弃 | 区分 **拒绝(rejected)** 与 **降级(degraded)**，原因码可区分并随批次返回 |
| 去重与来源可追溯 | 指标身份 `(ioc_type, 归一化value)`；每来源保留一条观测，结论带解释 |
| 生命周期 | `active / expired / revoked`；过期与撤回指标默认不出现在查询结果 |
| 并发与重放幂等 | 存储单锁 + 批次登记表；同 `batch_id` 只生效一次，结果一致 |
| 非法批次零污染 | 批次级校验 + 先全部归一后原子写入；失败原因可区分 |
| 本地多来源模拟 | `data/sources/*.json` + `scripts/load_feeds.py` |
| HTTP 接口 | FastAPI：提交批次 / 查询 / 单指标 / 统计 |

## 2. 快速开始

```bash
uv sync                                  # 安装依赖
uv run python scripts/load_feeds.py      # 端到端本地验证（加载情报+打印判定依据）
uv run pytest -s                         # 运行全部单测（日志打印输入批次与判定依据）
uv run uvicorn main:app --reload         # 启动 HTTP 服务
```

启动后：

```bash
curl -s -X POST localhost:8000/api/v1/batches \
  -H 'content-type: application/json' \
  -d '{"batch_id":"demo-1","entries":[
        {"type":"ipv4","indicator":"185.220.101.42","confidence":90,
         "valid_until":"2026-12-31","last_seen":"2026-09-20","tags":["c2"]}]}'

curl -s 'localhost:8000/api/v1/indicators'                       # 仅 active
curl -s 'localhost:8000/api/v1/indicators?include_inactive=true' # 含过期/撤回
curl -s 'localhost:8000/api/v1/indicators/ip:185.220.101.42'     # 单指标（含来源观测与解释）
curl -s 'localhost:8000/api/v1/stats'
```

## 3. 目录结构

```
app/
  models.py       统一模型：IOCTypes/Confidence/LifecycleStatus、SourceObservation、
                  AggregatedIndicator（汇聚与生命周期派生）、BatchResult
  normalizer.py   来源条目归一化：字段别名、值规范化、拒绝/降级原因
  store.py        线程安全内存存储：原子应用批次、去重合并、批次幂等、查询过滤
  service.py      批次校验→逐条归一→原子入库的编排，含输入/判定日志
  feed_loader.py  读取 data/sources 本地情报文件，模拟多来源推送
  api.py          FastAPI 路由
data/sources/     多来源模拟数据（含正常、重复、残缺、非法、过期、撤回场景）
scripts/load_feeds.py  端到端验证脚本
tests/            40 个单测（归一化、去重/生命周期、并发幂等、API、端到端）
docs/MODEL.md     情报模型、去重与生命周期规则的详细说明
```

## 4. 批次请求与响应

请求：

```json
{
  "batch_id": "可选；缺省时按条目内容生成确定性 id（相同内容重放天然幂等）",
  "source": "可选；条目不自带来源时作为默认来源",
  "entries": [ { "type": "ip", "value": "1.2.3.4", "...": "..." } ]
}
```

成功响应（`201` 首次 / `200` 重放）：

```json
{
  "batch_id": "b1", "replayed": false,
  "accepted_new": 1, "merged": 0, "accepted_total": 1,
  "rejected": [ { "index": 3, "reason": "invalid_value", "detail": "...", "raw": {} } ],
  "degraded": [ { "index": 0, "indicator": "ip:1.2.3.4", "reasons": ["..."], "source": "s1" } ]
}
```

失败（整批拒绝，HTTP 400，不产生任何写入）：

```json
{ "error": "empty_batch", "reason": "empty_batch", "detail": "entries 为空" }
```

`reason` 取值：`empty_batch`（空批次）、`malformed_batch`（结构非法 / JSON 非法 /
全部条目归一失败）；条目级拒绝原因见 `docs/MODEL.md`。

## 5. 本地验证方法

- **脚本**：`uv run python scripts/load_feeds.py`
  依次演示：加载来源 → 提交 → **重放幂等** → 当前有效指标（带判定依据）
  → 含过期/撤回全量 → 拒绝/降级明细 → 存储统计。
- **单测**：`uv run pytest -s`
  覆盖重复投递、20/50 线程并发提交、过期边界（`now == valid_until` 仍 active，
  晚 1 秒 expired）、全来源/单来源撤回、非法批次可区分失败与零污染。
  测试与服务均通过 `logging` 打印 **输入批次** 与 **判定依据**。

## 6. 关键设计结论（可解释性）

- 同一指标只保留一份 `AggregatedIndicator`，但保留每个来源的一条
  `SourceObservation`，来源、各自置信度/时间/有效期/撤回状态全程可追溯。
- 汇聚置信度 = 各来源置信度最大值，响应中的 `confidence_sources` 指明由哪些来源提供。
- 最近可见时间 = 未撤回来源的最晚 `last_seen`；`first_seen` 取最早。
- 有效期 = 未撤回来源给出的最晚 `valid_until`；均未提供则不自动过期（并降级标注）。
- 状态优先级：**revoked > expired > active**；只有所有来源都撤回才整体撤回。
