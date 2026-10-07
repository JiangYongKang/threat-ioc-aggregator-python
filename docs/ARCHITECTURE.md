# 设计说明：统一模型、去重、生命周期、并发与幂等

## 1. 目录结构

```
app/
├── models.py       # 枚举与数据结构（统一模型、批次结果、审计事件）
├── normalizer.py   # 多来源字段归一化、指标值规范化、类型推断、拒绝/降级判定
├── lifecycle.py    # 时刻解析、加权置信度/结论聚合、状态推导（纯函数，无 I/O）
├── weights.py      # 来源可信度权重：版本化配置、校验、同内容去重、两阶段发布
├── store.py        # 线程安全内存存储：去重合并、按查询时刻物化、plan/commit 原子重判
├── ingestion.py    # 批次校验、逐条归一、幂等重放、全局锁串行化写入
├── feeds.py        # 本地 JSON 情报文件发现与加载（模拟来源推送）
├── service.py      # 门面：组装存储+入库+权重+文件加载，提供可解释查询与原子调权
├── api.py          # FastAPI：HTTP 接口与启动加载
└── logging_utils.py
data/feeds/         # 本地情报样本：alpha/beta/gamma、撤回批次、故意损坏文件
tests/              # 94 个测试，日志用 -s 打印"输入批次/判定依据"
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

## 4. 置信度与判定聚合（可解释、可按来源加权）

聚合只采纳**当前时刻仍有效**（未撤回、未过期）的来源观测。
每个来源配有可信度权重 `w(s)`（见第 4.1 节），其**有效置信度** =
`w(s) × 原始置信度`：

- **置信度** = 有效置信度最高的来源作为基础，每多一个独立佐证来源
  加成 `0.05 × 该来源权重`，佐证加成上限 `+0.15`，四舍五入三位小数，
  封顶 `0.999`。
- **判定严重度**：`malicious > suspicious > benign`；
  当恶意与良性来源的最高**有效置信度**相差不超过 `0.10` 时，因来源冲突
  **降级为 suspicious**（避免单一高置信误报碾压对立证据）。
- `GET .../explain` 返回人类可读的 `confidence_basis` / `verdict_basis`，
  以及逐来源的 `contributions`（权重、原始/有效置信度、是否计入聚合），
  能看清每个来源对最终结论各出了多少力。

### 4.1 来源可信度权重模型（`weights.py`）

- 权重配置是**版本化**的不可变快照 `WeightConfig(version, weights, ...)`
  （`PUT /api/v1/weights` 发布新版本，版本号单调递增）；
- **未配置的来源一律按默认权重 `1.0`**，此时全部规则退化为引入权重
  机制前的口径（`tests/test_weights.py::test_default_weight_matches_legacy_behavior`
  逐条验证等价性）；
- 合法范围 `(0, 100]`，非数值 / 非正 / 超界 / 非法来源名都会被
  `WeightConfigError` 拒绝（HTTP 422），**校验失败不产生任何变更**；
- 每次变更写入 `WeightRegistry` 历史，`GET /api/v1/weights/history`
  可查到"什么时候、被改成了什么、备注是什么"；
- 每个 `Ioc` 记录 `weight_version`：最近一次聚合判定用的是哪一版权重，
  重判时也会在 `history` 里追加 `rejudge` 审计事件。
- **同内容去重（重试不重复记账）**：发布的权重与当前版本内容完全相同时，
  复用原配置快照（响应里 `reused=true`），**不新增版本号、不追加历史**。
  因此"调权在重判阶段失败 → 拿同一份权重重试"与一次调成功的最终状态、
  版本序列、指标审计链完全一致
  （`test_service_retry_same_weights_equivalent_to_single_success`）。

### 4.2 权重发布与存量重判的原子提交

`PUT /api/v1/weights`（默认 `rejudge=true`）走一条**两阶段原子提交**
流水线；`ThreatIocService.set_weights` 让 `IocStore` 与 `WeightRegistry`
共用**同一把可重入锁**（`IocStore` 装配时 `bind_lock` 绑定），批次写入
也抢这把锁：

```
┌─ 临界区（权重注册表 / 存储 / 批次写入共用同一把锁）────────────────────┐
│ 1. registry.candidate(weights)   校验 + 构造候选快照（不发布、不记账）  │
│ 2. store.plan_rejudge(candidate) 全量指标在副本上重算（不碰存储对象）   │
│    （fail_hook：测试在"算完未提交"处注入失败）                         │
│ 3. registry.commit(candidate)    发布权重版本                          │
│ 4. store.commit_rejudge(plans)   一次性写回结论/版本并追加审计         │
└───────────────────────────────────────────────────────────────────────┘
```

一致性与失败语义：

- **要么一起生效、要么都不变**：第 1、2 步是纯计算，任何异常都发生在
  任何提交之前——权重版本不发布，存量结论 / `weight_version` /
  来源追溯审计 / 批次幂等表全部保持原样
  （`test_service_publish_failure_leaves_everything_untouched`）。
  重判阶段的异常由服务层包装为 `WeightPublishError`（原始异常挂在
  `__cause__`）并打 ERROR 日志，HTTP 映射为 **500**
  `weight_publish_failed`（响应体带 `retryable=true` 与
  `candidate_version`），**不静默吞掉**，调用方可拿同一份权重原样重试
  （`test_publish_failure_http_maps_to_500_and_is_retryable`）；
- **失败窗口不混用**：临界区内并发投递的批次只能整体排在临界区之前
  （会被第 2 步重算覆盖到新版本）或之后（upsert 直接读到新权重、按
  新版本写入）。失败时权重未发布，窗口内新批次一律按旧权重入库，
  重试成功后全部指标统一到新版本——不存在"一部分新权重、一部分旧权重"
  （`test_failure_window_new_batch_uses_old_weights_then_retry_unifies`、
  `test_publish_concurrent_with_ingestion_is_linearizable`）；
- **失败不损坏已有数据**：过期 / 撤回指标的结论、版本标记与可见性在
  失败前后逐字段一致；重试成功后仍不会在 `GET /iocs` 中复活
  （`test_failed_publish_does_not_revive_expired_or_revoked`）；
- **并发同内容去重**：多线程并发发布完全相同的权重只记一版
  （`test_concurrent_same_weight_publishes_dedup_to_one_version`）。

> 第 3、4 步都是锁内纯内存赋值，正常流程不抛错；注册表与存储共享锁也让
> 并发读者不可能观察到"已发布未重判"的中间态。将来替换为真实数据库时，
> 应把这四步放进同一个数据库事务。

### 4.3 批量重新判定（`plan_rejudge` + `commit_rejudge` / `rejudge_all`）

权重调整后对全量存量指标做一次重判（`PUT /api/v1/weights` 默认立即触发，
也可 `POST /api/v1/rejudge` 手动触发；后者本质是在同一临界区内顺序调用
`plan_rejudge` + `commit_rejudge`）。一致性规则：

- **与重新入库等价**：聚合是 `(来源观测, 权重快照, 判定时刻)` 的纯函数，
  来源观测在重判中不被修改，因此重判结果与"用新权重把同样情报重新
  入库一遍"逐指标一致（`test_rejudge_matches_fresh_ingest_with_same_weights`）；
- **并发安全**：重判与批次写入共用同一把存储锁，并发投递的批次整体
  排在重判之前或之后——之前的会被重判覆盖到新版本，之后的直接按新
  权重写入，不存在新旧权重混用的中间态，也不丢数据、不重复计数
  （`test_rejudge_concurrent_with_ingestion`）；
- **原子性**：`plan_rejudge`（快照副本计算）+ `commit_rejudge`
  （一次性写回）两阶段；中途任何失败存储零变更
  （`test_rejudge_failure_is_atomic_and_retryable` 用 `fail_hook`
  在提交前注入失败验证）；
- **幂等重试**：已按目标版本判定过的指标直接跳过，失败重试或重复触发
  不产生额外效果、不重复追加审计记录；
- **生命周期不变**：重判只重算聚合字段，过期/撤回指标状态规则不变，
  不会在 `GET /iocs` 中重新出现
  （`test_expired_and_revoked_stay_hidden_after_rejudge`）。
- **查询口径与版本对齐**：读取物化按指标记录的 `weight_version`
  对应的权重配置计算，因此"只发布配置不重判"时查询结论不变；
  只有重判或新写入才会把指标推进到新版本，判定依据与版本号始终
  对得上（`test_config_without_rejudge_does_not_change_query_results`）。

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

- 运行：`uv run pytest -s`（94 个用例，日志打印每个用例的输入批次与
  判定依据；INFO 日志在并发用例中可见线程交织但结果确定）。
- 权重与重判行为集中在 `tests/test_weights.py`：默认兼容、权重生效、
  重判与重新入库一致、**发布原子性（失败整体回滚）、同内容失败重试不
  重复记账、失败窗口与并发投递线性化、并发同内容去重、失败不复活过期/
  撤回、HTTP 500 错误反馈**、生命周期不回归、畸形条目可区分。
- 扩展一个新来源：在 `SOURCE_PROFILES` 增加一个 `SourceProfile`
  （字段别名 + 默认值），在 `data/feeds/` 放一个同名 JSON 即可，无需改动
  聚合与生命周期逻辑。
- 当前存储为进程内内存实现；`IocStore` 的写入都收敛在锁与 `upsert` 之后，
  后续替换为 SQLite/Redis 时只需保持同样的"临界区 + 批次表"语义。
