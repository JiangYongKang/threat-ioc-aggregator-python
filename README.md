# 威胁情报 IOC 本地汇聚与判定服务

一个**本地运行**的威胁情报 IOC（Indicator of Compromise）汇聚与判定服务。
用 `data/feeds/` 下的本地 JSON 情报文件模拟多个来源（alpha / beta / gamma）
的推送，演示同一指标在：

- **多来源字段不一致、条目残缺**；
- **多来源重复 / 先后投递**；
- **过期与撤回**；
- **并发提交与批次重放**

等场景下，结论仍然**一致、可追溯、幂等**。

## 快速开始

```bash
# 1. 安装依赖（需要 Python >= 3.14，使用 uv）
uv sync --group dev

# 2. 运行全部测试（61 个，含并发/过期边界/重放）
uv run pytest

# 3. 启动 HTTP 服务（启动时自动加载 data/feeds/*.json）
uv run uvicorn main:app --reload
# 打开 http://127.0.0.1:8000/docs 查看交互式接口文档
```

## 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/batches` | 提交情报批次（并发安全、幂等、原子写入） |
| GET  | `/api/v1/iocs` | 列出当前**可见**指标（过期/撤回不出现），支持 `?ioc_type=ip` |
| GET  | `/api/v1/iocs/{indicator}` | 查询指标完整聚合记录与审计历史（含过期/撤回，用于追溯） |
| GET  | `/api/v1/iocs/{indicator}/explain` | 返回置信度与判定结论的**人类可读依据** |
| GET  | `/api/v1/feeds/report` | 启动时本地情报文件的加载/入库汇总（含文件级错误） |

### 提交批次示例

```bash
curl -X POST http://127.0.0.1:8000/api/v1/batches \
  -H 'content-type: application/json' \
  -d '{
    "batch_id": "demo-001",
    "source_hint": "alpha",
    "entries": [
      {"indicator": "203.0.113.10", "type": "ip", "source": "alpha",
       "confidence": 0.9, "verdict": "malicious",
       "first_seen": "2026-09-20T00:00:00Z", "validity_days": 30,
       "tags": ["c2"]}
    ]
  }'
```

响应字段含义：

- `accepted`：本批次**新建**指标数；`updated`：命中既有指标（新增来源或刷新）数；
- `rejected` / `rejected_entries`：被**拒绝**条目及可区分原因（不入库）；
- `degraded` / `degraded_entries`：**降级**但仍入库的条目及原因；
- `replayed`：是否为同一批次的幂等重放（原样返回首次结果）。

## 失败原因速查（均可区分，且非法批次零污染）

批次级（HTTP 422，整个批次不写入）：
`missing_batch_id`、`not_a_list`、`empty_batch`、
`duplicate_batch_id`（同一批次号提交了不同内容）、`entry_limit_exceeded`。

条目级拒绝（只拒绝该条，其余正常入库）：
`missing_indicator`、`empty_indicator`、`missing_source`、
`unsupported_ioc_type`、`non_object_entry`、`invalid_confidence`、
`invalid_timestamp`、`conflicting_type`。

条目级降级（入库但标注）：
`missing_confidence`、`missing_ioc_type`、`inferred_ioc_type`、
`missing_tags`、`missing_validity_days`、`low_confidence_clamped`、
`non_string_tags`。

## 本地验证方法

```bash
# 全量测试，并观察 -s 打印的"输入批次"与"判定依据"日志
uv run pytest -s

# 只看某类场景
uv run pytest tests/test_ingestion.py       # 原子性 / 幂等 / 并发
uv run pytest tests/test_lifecycle.py       # 过期边界 / 撤回 / 置信度
uv run pytest tests/test_service_feeds.py   # 多来源文件端到端
uv run pytest tests/test_api.py             # HTTP 行为与错误码
```

目录结构与详细规则见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
