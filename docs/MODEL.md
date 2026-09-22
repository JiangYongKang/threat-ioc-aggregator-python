# 情报模型、去重与生命周期规则

## 1. 统一模型

### 1.1 支持的指标类型 `IOCTypes`

| 枚举 | 取值 | 值规范化（canonicalize） |
| --- | --- | --- |
| `ip` | ip / ipv4 / ipv6 | `ipaddress` 校验；兼容来源前导零写法（`001.002.003.004` → `1.2.3.4`） |
| `domain` | domain / hostname / host | 转小写、去尾部根点；域名语法校验 |
| `url` | url / uri | 仅接受 `http(s)://` |
| `hash_md5/sha1/sha256` | md5/sha1/sha256/hash | 转小写并按长度校验；裸 `hash` 映射为 sha256 |
| `email` | email / mail | 转小写、基本格式校验 |

### 1.2 置信度 `Confidence`

三档：`low(1) < medium(2) < high(3)`。来源中的多种表达都能解析：

- 档位词：low/info→low；medium/med/moderate→medium；high/critical→high
- 数值 0–100：`<34→low`，`<67→medium`，其余 `high`
- 比例 0–1（含）：先乘 100 再按上档划分（如 `0.95→high`）
- 缺失 → 降级为 `low` 并记录 `missing_confidence`；**无法识别 → 拒绝**（`invalid_confidence`）

### 1.3 SourceObs（归一化后的单条来源观测）

`indicator, ioc_type, value, source, confidence, first_seen, last_seen,
valid_until, revoked, tags, degrade_reasons, ingested_at`

时间支持 ISO-8601（含结尾 `Z`）、Unix 时间戳、`YYYY-MM-DD HH:MM:SS`、`YYYY-MM-DD`；
统一转 naive UTC 比较，避免 aware/naive 混用。

### 1.4 AggregatedIndicator（同一指标唯一汇聚记录）

身份键：`indicator = f"{ioc_type}:{canonical_value}"`。内部保留
`list[SourceObservation]`（**每个来源至多一条**），并派生：

| 派生项 | 规则 |
| --- | --- |
| `sources` | 各来源观测的来源名（按首次出现顺序） |
| `max_confidence` | 未撤回来源置信度的最大值；全部撤回时取全部观测最大值 |
| `confidence_sources` | 提供当前汇聚置信度的来源（解释“置信度从哪来”） |
| `first_seen` / `last_seen` | 最早 first_seen / 未撤回来源最晚 last_seen |
| `valid_until` | 未撤回来源给出的最晚 valid_until；全缺则为 `None` |
| `tags` | 各来源标签并集 |
| `is_revoked` | **所有**来源观测均撤回才为真 |
| `to_dict().explanation` | 一行自然语言判定依据（置信度/来源数/最近可见/状态） |

同一来源先后投递：保留**最早 first_seen 与最晚 last_seen**，标签与降级原因取并集，
其余字段以最新观测为准。

## 2. 归一化：拒绝 vs 降级（残缺条目不静默丢弃）

### 2.1 拒绝原因 `RejectReason`（条目不入库，随批次返回）

| reason | 触发条件 |
| --- | --- |
| `missing_type` | 无 `ioc_type/type/kind/indicator_type` 或为空 |
| `missing_value` | 无 `value/indicator/ioc/data` 或为空 |
| `unknown_type` | 类型不在别名表中 |
| `invalid_value` | 值不是字符串，或与类型不匹配（非法 IP/域名/URL/哈希/邮箱），或条目不是对象 |
| `invalid_confidence` | 置信度存在但无法解析（如 `"banana"`、>100） |
| `invalid_timestamp` | `first_seen/last_seen/valid_until` 存在但无法解析 |

### 2.2 降级原因 `DegradeReason`（条目入库，但标注残缺原因）

| reason | 触发条件 |
| --- | --- |
| `missing_confidence` | 无置信度 → 默认 low |
| `missing_tags` | 无标签 |
| `missing_timestamp` | first_seen 与 last_seen 均缺 → 以入库时刻兜底 |
| `missing_valid_until` | 非撤回条目未给有效期 → 不自动过期，但明确标注 |
| `unknown_extra_fields:<names>` | 出现未识别字段（不丢弃原始条目，字段名随原因返回） |

时间字段只给一个时另一个自动补齐（first_seen↔last_seen）；
若 first_seen 晚于 last_seen 则交换。

> 批次中部分条目被拒绝时，好条目正常入库，拒绝明细随响应返回；
> **全部**条目均归一失败时，整批以 `malformed_batch` 拒绝且零写入。

## 3. 去重与生命周期规则

### 3.1 去重 / 合并

- 指标身份只取决于 **(类型, 规范化后的值)**，与来源、字段命名、大小写/前导零无关。
- 新观测命中已有指标：合并进该指标，批次计数记 `merged`；否则新建，记 `accepted_new`。
- 每个来源在同一指标上至多一条观测（同源更新而非新增）。

### 3.2 状态判定 `status(now)`

优先级 **revoked > expired > active**：

1. `revoked`：所有来源观测 `revoked=true`（`status` 为
   revoked/withdrawn/deleted/false_positive/inactive，或 `revoked/deleted` 为真）。
2. `expired`：未整体撤回，且 `now > valid_until`（最晚有效期）。
3. 否则 `active`。

**过期边界**：`now == valid_until` 仍为 active；严格 `now > valid_until` 才 expired。
单来源撤回不会让指标消失（其余来源仍报告即保持 active，撤回观测保留可追溯）。
`valid_until` 全缺的指标不会仅因时间流逝而消失。

### 3.3 查询行为

- `GET /indicators` 默认只返回 `active`；过期/撤回指标不出现在默认结果。
- `?include_inactive=true` 返回全量并带 `status`，保证“消失”的指标仍可追溯。
- 支持 `?ioc_type=`、`?source=` 过滤；结果按 `last_seen` 倒序。

## 4. 并发与幂等

- `IndicatorStore` 所有公开方法在同一把 `RLock` 下执行；
  “检查 batch_id → 合并观测 → 登记批次结果”在**同一临界区**完成。
- 批次结果在首次应用时快照；同 `batch_id` 的并发/重放请求只返回首次结果
  （`replayed=true`，计数与首次完全一致），不重复合并、不改状态。
- 未提供 `batch_id` 时，按条目内容 SHA-256 派生确定性 id，相同内容重复提交天然幂等。
- 批次级非法（非对象、缺 entries、entries 非数组、空批次、batch_id 非字符串）
  在任何归一化/写入之前抛 `BatchRejected`，因此 **不会污染已入库数据**。

## 5. 本地情报文件（多来源模拟）

`data/sources/`：

| 文件 | 场景 |
| --- | --- |
| `source_a.json` | 标准字段：3 个指标（其中 1 个 sha256 已过期） |
| `source_b.json` | 字段别名/残缺：共享 IP 汇聚、缺字段降级、非法 IP/缺值被拒、已过期 URL、未识别字段 |
| `source_c_updates.json` | 第三方更高置信度、撤回域名、新增 md5 |
| `source_d_revoke.json` | 与 C 一起把 `evil.example.com` 全来源撤回（从默认查询消失） |
| `source_a_replay.json` | 复用 `batch-a-001` 的重放请求（内容不同也只返回首次结果） |
| `source_bad.json` | 空批次，整批拒绝 |

## 6. 验证

```bash
uv run python scripts/load_feeds.py   # 场景演示，含判定依据
uv run pytest -s                      # 40 个单测，日志含输入批次与判定依据
```
