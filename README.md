# 威胁情报 IOC 本地汇聚与判定服务

一个**本地运行**的威胁情报 IOC（Indicator of Compromise）汇聚与判定服务。
用 `data/feeds/` 下的本地 JSON 情报文件模拟多个来源（alpha / beta / gamma）
的推送，演示同一指标在：

- **多来源字段不一致、条目残缺**；
- **多来源重复 / 先后投递**；
- **过期与撤回**；
- **并发提交与批次重放**

等场景下，结论仍然**一致、可追溯、幂等**。在此之上，服务还支持
**按来源配置可信度权重**（版本化、可审计），并能在权重调整后对全量
存量指标做一次**原子批量重新判定**。

## 快速开始

```bash
# 1. 安装依赖（需要 Python >= 3.14，使用 uv）
uv sync --group dev

# 2. 运行全部测试（81 个，含并发/过期边界/重放/权重重判）
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
| GET  | `/api/v1/iocs/{indicator}/explain` | 返回置信度与判定结论的**人类可读依据**（含逐来源权重贡献） |
| GET  | `/api/v1/feeds/report` | 启动时本地情报文件的加载/入库汇总（含文件级错误） |
| GET  | `/api/v1/weights` | 查看当前生效的来源权重配置（版本号 + 权重表） |
| PUT  | `/api/v1/weights` | 发布新一版权重配置，默认立即对存量指标**原子重判** |
| GET  | `/api/v1/weights/history` | 权重变更历史（什么时候、被改成了什么、备注） |
| POST | `/api/v1/rejudge` | 按当前权重配置手动触发全量重判（幂等，可安全重试） |

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

## 来源可信度权重与重新判定

### 权重模型

- 每个来源可配置权重 `w ∈ (0, 100]`；**未配置的来源按默认权重 1.0**，
  此时所有结论与未启用权重机制时完全一致（向后兼容）。
- 聚合时来源的**有效置信度 = 权重 × 原始置信度**：
  - 最终置信度 = 有效置信度最高者为基础，其余佐证来源按
    `0.05 × 权重` 加成（上限 +0.15）；
  - 恶意/良性结论冲突时，比较双方最高**有效置信度**，差 ≤ 0.10
    降级为 suspicious。
- 权重配置**版本化**：每次 `PUT /api/v1/weights` 生成单调递增的版本号；
  每个指标记录 `weight_version`（最近一次判定所用的权重版本），
  变更历史可通过 `GET /api/v1/weights/history` 追溯。
- 查询 `GET /api/v1/iocs/{indicator}/explain` 的 `contributions` 字段
  逐来源列出权重、原始/有效置信度、是否计入聚合。

```bash
# 调权并立即对存量指标重判
curl -X PUT http://127.0.0.1:8000/api/v1/weights \
  -H 'content-type: application/json' \
  -d '{"weights": {"alpha": 0.5, "gamma": 1.5}, "note": "alpha 噪声大，降权"}'
```

非法配置（非数值、非正、超过 100、来源名非法）返回 422
（`invalid_weight_config` / `invalid_weight_value`），且**不产生任何变更**。

### 重新判定的触发时机与一致性规则

- **触发**：`PUT /api/v1/weights` 默认立即重判（可传 `"rejudge": false`
  只发布配置——此时查询结论不变，直到下一次重判或新写入）；
  `POST /api/v1/rejudge` 可随时手动按当前权重重判。
- **等价性**：重判结果与"用新权重把同样情报重新入库一遍"逐指标一致
  （聚合是纯函数，来源观测在重判中不被修改）。
- **并发**：重判与批次写入共用同一把锁，重判期间并发投递的批次不丢、
  不重复计数，也不会出现新旧权重混用的中间态。
- **原子与幂等**：重算先在副本上完成再一次性提交，中途失败存储零变更；
  失败重试或重复触发不产生额外效果（已按目标版本判定的指标会跳过）。
- **生命周期**：过期/撤回指标在重判后仍然不会出现在可见查询中。

### 兼容范围

- 不配权重 = 全部来源 1.0 = 旧口径，原有 61 个用例全部不回归；
- 权重只影响置信度/判定的聚合，不影响入库校验、幂等重放、生命周期、
  拒绝/降级原因的可区分性；
- 权重配置保存在进程内（与 IOC 存储一致），重启后恢复默认版本 v0。

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
uv run pytest tests/test_weights.py         # 权重生效 / 重判一致性 / 失败重试
uv run pytest tests/test_service_feeds.py   # 多来源文件端到端
uv run pytest tests/test_api.py             # HTTP 行为与错误码
```

权重机制的端到端手动验证：

```bash
uv run uvicorn main:app &
# 1. 看默认口径下某共享指标的结论
curl -s http://127.0.0.1:8000/api/v1/iocs/203.0.113.10/explain | jq
# 2. 调低某来源权重（自动触发全量重判）
curl -s -X PUT http://127.0.0.1:8000/api/v1/weights \
  -H 'content-type: application/json' \
  -d '{"weights": {"alpha": 0.5}, "note": "alpha 降权"}' | jq
# 3. 再看结论与逐来源贡献的变化，以及指标审计链里的 rejudge 记录
curl -s http://127.0.0.1:8000/api/v1/iocs/203.0.113.10/explain | jq
curl -s http://127.0.0.1:8000/api/v1/weights/history | jq
```

目录结构与详细规则见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
