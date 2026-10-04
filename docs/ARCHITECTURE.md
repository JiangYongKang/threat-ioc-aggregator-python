# 设计说明：统一模型、去重、生命周期、并发与幂等

## 1. 目录结构

```
app/
├── models.py       # 枚举与数据结构（统一模型、批次结果、审计事件、来源贡献）
├── normalizer.py   # 多来源字段归一化、指标值规范化、类型推断、拒绝/降级判定
├── lifecycle.py    # 时刻解析、加权置信度/结论聚合、状态推导（纯函数，无 I/O）
├── weights.py      # 来源可信度权重：校验、版本化配置存储、变更历史
├── store.py        # 线程安全内存存储：去重合并、按查询时刻物化、全量原子重算
├── ingestion.py    # 批次校验、逐条归一、幂等重放、全局锁串行化写入与重算
├── feeds.py        # 本地 JSON 情报文件发现与加载（模拟来源推送）
├── service.py      # 门面：组装存储+入库+权重管理，提供可解释查询
├── api.py          # FastAPI：HTTP 接口与启动加载
└── logging_utils.py
data/feeds/         # 本地情报样本：alpha/beta/gamma、撤回批次、故意损坏文件
tests/              # 72 个测试，日志用 -s 打印"输入批次/判定依据"
main.py             # uvicorn main:app 入口
```

数据流向：

```
data/feeds/*.json ─┐
                   ├─► IngestionService.submit_batch ─► Normalizer(逐条)
POST /api/v1/... ──┘            │  结构非法→BatchRejected（零写入）
                                ▼
            IocStore.upsert（去重合并 + 审计历史 + 重算）
                                ▼
   GET /api/v1/iocs(.explain) ── 按查询时刻物化 ACTIVE/EXPIRED/REVOKED
```

## 2. 统一情报模型

### 2.1 归一化指标 `Ioc`（全库每个指标只保留一份）

| 字段 | 含义 |
| --- | --- |
| `indicator` | **去重键**。原始值规范化：去首尾空白；domain/email/url/hash 转小写；url 去结尾 `/` |
| `ioc_type` | `ip / domain / url / hash / email`，无法归类直接拒绝 |
| `verdict` | 聚合判定：`malicious / suspicious / unknown / benign` |
| `confidence` | 聚合置信度，`[0,1]`，保留三位小数 |
| `status` | 生命周期：`active / expired / revoked` |
| `sources` | `{来源名: SourceObservation}`，**多来源可追溯的核心** |
| `tags / first_seen / last_seen / expires_at / revoked` | 跨来源聚合属性 |
| `history` | `AuditEvent` 列表：create / update_source / refresh / 状态迁移 |

### 2.2 来源观测 `SourceObservation`

每个来源对某指标的一次观测独立保存：来源、来源置信度、来源判定、标签、
`first_seen / last_seen`、来源自身的 `expires_at` 与 `revoked`。
即使指标聚合为一条，任何结论都能下钻到"哪个来源、什么时间、给了什么值"。

### 2.3 多来源字段不一致如何归一

`normalizer.py` 内置：

- 通用别名字典（`ioc/value/observable→indicator`、`score/weight/trust→
  confidence`、`threat_level/classification→verdict` 等）；
- 来源画像 `SourceProfile`（alpha/beta/gamma 各自的别名、默认置信度、
  默认有效期天数）；
- 值形态推断：IPv4、URL、Email、MD5/SHA1/SHA256、域名的正则 +
  `ipaddress` 校验。

### 2.4 残缺条目的处理原则：**绝不静默丢弃，拒绝 vs 降级可区分**

- **拒绝（Reject）**：关键事实缺失或自相矛盾，条目不入库，批次结果里
  逐条给出原因，例如缺指标值、空白指标、缺来源、声明类型与值形态矛盾
  （`8.8.8.8` 标成 `domain`）、置信度不是数值、时间戳无法解析。
- **降级（Degrade）**：可选/可推断字段缺失，仍入库并打上原因标签，
  例如缺类型→按值推断、缺置信度→来源默认值、缺有效期→来源默认天数、
  置信度越界→裁剪到 `[0,1]`、标签里混了非字符串→过滤。

## 3. 去重与来源追溯规则

去重键是规范化后的 `indicator`。`IocStore.upsert` 对每个归一化条目：

1. 指标不存在 → `create`；
2. 指标已存在、该来源首次出现 → `update_source`（来源集合扩大，标签取并集，
   `first_seen` 取最早、`last_seen` 取最晚）；
3. 指标与来源都已存在 → `refresh`（更新该来源观测，审计里记录
   verdict/confidence/last_seen/revoked 的前后变化）。

无论多少来源、投递多少次，全局只有一份 `Ioc`；`history` 保留每一次动作的
批次号、来源与明细，形成完整追溯链。

## 4. 置信度与判定聚合（可解释）

聚合只采纳**当前时刻仍有效**（未撤回、未过期）的来源观测：

- **来源权重**：每个来源先按配置的权重折算**有效置信度**
  `effective = clamp(raw × weight, 0, 0.999)`。未配置的来源权重为 `1.0`，
  折算后与原始值一致——**默认配置下所有结论与旧口径逐位相同**。
- **置信度** = 给出明确结论来源中的最高有效置信度，每多一个独立佐证来源
  `+0.05`，佐证加成上限 `+0.15`，四舍五入三位小数。
  例：三来源 0.81 / 0.6 / 0.8 报恶意 → `0.81 + 0.05 = 0.86`。
- **判定严重度**：`malicious > suspicious > benign`；
  当恶意与良性来源的最高**有效置信度**相差不超过 `0.10` 时，因来源冲突
  **降级为 suspicious**（避免单一高置信误报碾压对立证据）。
- `GET .../explain` 同时返回人类可读的 `confidence_basis` 与
  `verdict_basis`，说明结论由哪个来源、以什么数值推出；
  `contributions` 逐来源列出 `weight / raw_confidence /
  effective_confidence / verdict / live`，`weights_version` 标明该结论
  是按哪一版权重算出的。

## 4.1 来源权重模型（`weights.py`）

- 配置形态：整表 `{来源名: 正数权重}`，权重上限 100；非正数、非数值、
  空白来源名等非法配置整体拒绝（HTTP 422 `invalid_weight_config`），
  存储与版本零变更。
- **版本化**：每次生效的变更生成递增版本号（v0 为初始默认配置），
  `WeightRevision` 记录生效时间与完整权重表；
  `GET /api/v1/weights` 返回当前版本与全部历史——
  "权重什么时候、被改成了什么"可查。
- **指标级追溯**：每个 `Ioc` 记录 `weights_version`（最近一次按哪一版
  权重算出），重算时写入 `reweight` 审计事件（含新旧结论对比）。

## 4.2 权重变更与全量重新判定（`PUT /api/v1/weights`）

触发时机：仅在权重表内容真正变化时触发全量重算；与当前版本内容相同的
提交直接幂等返回（不升版本、不重算）。

一致性与并发规则：

- **重算 == 重新入库**：聚合是 `(sources, weights, now)` 的纯函数，
  入库路径与重算路径共用同一套 `aggregate_*`，因此"调权后重算"与
  "用新权重把同样情报重新入库一遍"结论逐位一致
  （`test_recompute_matches_reingest_with_new_weights`）。
- **原子性**：重算先在副本上预计算全部指标，全部成功才一次性写回并
  提交权重版本；中途任何异常 => 存量数据与权重版本都不变，
  用同一配置重试得到同一结果
  （`test_failed_recompute_is_atomic_and_retry_idempotent`）。
- **并发**：重算与批次写入共用同一把全局锁，重算期间到达的批次在锁外
  等待——不丢数据、不重复计数，也不会出现"部分指标按旧权重、部分按
  新权重"的中间态（`test_recompute_concurrent_with_ingestion`）。
- **生命周期不变**：重算只重算聚合字段，过期/撤回指标不会复活，
  仍不会出现在 `GET /iocs` 中
  （`test_expired_and_revoked_stay_hidden_after_recompute`）。

兼容范围：权重只影响置信度/判定的聚合口径；归一化、拒绝/降级判定、
批次幂等、生命周期规则完全不变。未配置权重（全默认 1.0）时，所有结论
与引入权重前的旧版本一致。

## 5. 生命周期规则

- 来源观测级：`revoked=true` 立即失效；观测有自己的 `expires_at`；
  显式提供 `validity_days/ttl_days` 时按 `first_seen + N 天` 计算；
  都没有时使用来源画像的默认有效期。
- 指标级 `expires_at`：**任一未撤回来源开放有效期（null）则整体开放**，
  否则取所有未撤回来源中最晚的过期时间。
- 指标级 `revoked`：**所有**来源都撤回才为真。
  部分来源撤回时指标仍然可见，只是该来源不再参与聚合。
- **过期边界（左闭右开）**：`now < expires_at` 为 ACTIVE；
  `now >= expires_at` 立即转为 EXPIRED。
- EXPIRED / REVOKED 的指标**不会出现在 `GET /iocs` 结果中**，
  但仍可通过 `GET /iocs/{indicator}` 取完整份记录用于追溯。

> 过期是"时间相关"状态，因此状态在**每次读取/写入时按给定时刻物化**。
> 读取只在返回的快照副本上物化并附一条临时迁移说明，不改动存储对象；
> 写入时的状态迁移才持久化进 `history`（见 `test_reads_do_not_mutate_storage`）。

## 6. 批次原子性、并发与幂等

### 6.1 两级校验

- **批次级**（结构问题）：缺 `batch_id`、内容不是列表、空批次、超过
  条目上限 → 抛 `BatchRejected`，发生在任何写入之前，存储零变更，
  失败批次也不会登记。
- **条目级**（内容问题）：在锁外逐条归一，非法条目只进
  `rejected_entries`，其余条目进入临界区统一写入。

### 6.2 原子写入与并发

`IngestionService` 持有一把进程内 `RLock`，"幂等判定 + 全部 upsert +
批次结果登记" 在同一临界区内完成。因此：

- 同一批次被 N 个线程并发提交，结果严格等价于"恰好一次执行 + N-1 次重放"；
- 多个不同批次（含重叠指标）并发提交，不会出现重复、丢失或部分写入，
  最终指标数与来源集合确定（见 `tests/test_ingestion.py` 中三个并发用例，
  使用 `threading.Barrier` 最大化竞争）。

### 6.3 幂等重放

- 批次指纹 = 对条目内容做 `SHA-256`（排序键、确定性序列化）；
- 相同 `batch_id` + 相同指纹：**不重复写入**，原样返回首次的
  `accepted/updated/rejected/...`，并置 `replayed=true`；
- 相同 `batch_id` + **不同指纹**：以 `duplicate_batch_id` 拒绝，
  防止用同一幂等键覆盖不同内容；
- 本地文件没有显式批次号时，按
  `file:{source}:{内容指纹}` 生成确定性批次号，所以重复加载同一文件
  天然是一次幂等重放（见 `test_conclusion_stable_across_reloads`）。

## 7. 本地情报样本说明（`data/feeds/`）

| 文件 | 覆盖场景 |
| --- | --- |
| `alpha.json` | 标准字段；重复共享指标；空白指标、非法置信度（拒绝）；缺字段条目（降级） |
| `beta.json` | 异构别名（`dst_ip/weight/threat_level/ttl_days`）；非对象条目（拒绝）；良性对立结论 |
| `gamma.json` | 裸列表 + 文件名为来源；过期边界指标；SHA256 推断；同来源重复投递（refresh） |
| `revocations.json` | alpha 撤回共享指标（部分撤回，仍可见）与唯一来源指标（完全撤回，隐藏） |
| `broken.json` | 故意损坏的 JSON：验证文件级错误被区分记录，不影响其他来源加载 |

## 8. 验证与扩展

- 运行：`uv run pytest -s`（72 个用例，日志打印每个用例的输入批次与
  判定依据；INFO 日志在并发用例中可见线程交织但结果确定）。
- 权重相关用例集中在 `tests/test_weights.py`：默认兼容、权重改变结论、
  重算与重新入库一致、重算与并发投递交叉、失败重试幂等、
  拒绝/降级口径不回归、过期/撤回不复活、权重历史可追溯。
- 扩展一个新来源：在 `SOURCE_PROFILES` 增加一个 `SourceProfile`
  （字段别名 + 默认值），在 `data/feeds/` 放一个同名 JSON 即可，无需改动
  聚合与生命周期逻辑；如需差异化可信度，再 `PUT /api/v1/weights` 配权重。
- 当前存储为进程内内存实现；`IocStore` 的写入都收敛在锁与 `upsert` 之后，
  后续替换为 SQLite/Redis 时只需保持同样的"临界区 + 批次表"语义。
