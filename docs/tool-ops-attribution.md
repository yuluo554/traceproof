# tool-ops-attribution · 工具调用运行取证

> 器官 slug `tool-ops-attribution`，版本 `0.2.0`（迁自 target-map ④ 行；版本沿用源仓
> `src/opslens/__init__.py` 的 `__version__ = "0.2.0"`，不随本产品升版）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这组 agent 工具调用跑了多少次、失败率多少、token / 耗时开销多大、失败该归到哪一类、
哪个 server 该删 / 该查」的主张，逐条对到**同一份已解析事件流**的确定性重算：

| check | asserted 闭集 | 判据 |
|---|---|---|
| `metric` | 数字 / `null` / 布尔 | 两级聚合行的一个指标；`level=server|tool`，tool 级带 `tool`；`field` 见 §3.1 |
| `totals` | 数字 / `null` | 全量汇总字段（`calls_total` / `calls_ok` / `calls_error` / `calls_unknown` / `failure_rate` / 分子分母 / `retry_count` / token / duration 样本 / `servers`） |
| `params` | 整数 | 规则包参数：`rate_precision` / `retry_window_seconds` |
| `category` | 整数 | `by_category` 某一类的调用数 |
| `server_category` | 整数 | 某 `(source, server)` 的某个失败类别计数 |
| `event_category` | 类别 / `other` / `not_attributed` | 单条事件的重算类别；非 `error` 事件一律 `not_attributed` |
| `effective` | 布尔 | 某失败模式规则是否生效；可附 `reasons` 逐条比对未生效原因 |
| `suggestion` | 建议标签闭集 | 某 server 某轴的建议；可附 `evidence` 逐字段比对（`value` / 分子分母 / 样本 / 阈值 / …） |
| `insufficient` | 布尔 | 某 server 某轴是否存在「数据不足」条目；可附 `reason_contains` / `observed_sample` / `required_sample` |
| `event` | 任意 JSON 值 | 单条事件的规范化字段（`status` / `tokens` / `duration_ms` / `notes` / …） |
| `stream` | 字符串 / 整数 / 布尔 | 事件流载荷级事实：`schema` / `count` / `sorted` |
| `timestamp` | 整数 / `null` | ISO 时间戳 → 自 1970-01-01T00:00:00Z 起的整数秒 |
| `count` | 整数 | `of=events/server_level/tool_level/effective_rules/ineffective_rules/matched_pattern/suggestion/insufficient` |

**器官不做的事**：不读文件 / 环境变量 / 时钟，不联网，不调用模型，不发现日志，不解析 JSONL，
不产出 Markdown / HTML / JSON 报告，不自带 CLI / 配置 / 排版。事件流、规则包与主张都由输入提供；
证据只经 `makeRecord()` 入账（内核在入账时脱敏）。

## 2. 输入（subject）

```json
{
  "events": {
    "schema": "opslens.events/1",
    "count": 202,
    "events": [
      {
        "source": "claude_code",
        "source_version": "2.1.233",
        "session_id": "sess-claude-high",
        "seq": 2,
        "timestamp": "2026-10-16T00:00:01.100Z",
        "server": "fake-high-fail",
        "tool": "tool_exec",
        "call_id": "call_sess-claude-high_000",
        "status": "ok",
        "error_text": "",
        "tokens": {"input": 53386, "output": 1045, "cache_read": 11280, "cache_creation": 85},
        "duration_ms": null,
        "turn_tokens_attributed": true,
        "notes": []
      }
    ]
  },
  "rules": {
    "params": {"retry": {"window_seconds": 120}, "rate_precision": 6},
    "thresholds": {"min_samples": {}, "remove_candidate": {}, "investigate": {}, "cost_heavy": {}},
    "failure_patterns": {"categories": [], "rules": []}
  },
  "claims": [
    {"claim_id": "c1", "check": "metric", "level": "server", "source": "claude_code",
     "server": "fake-high-fail", "field": "failure_rate", "asserted": 0.6,
     "node": {"session_id": "s-ops-1", "turn": 1, "tool_call_id": "call-ops-1"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `events` | 是 | `opslens.events/1` 载荷对象，或裸事件数组（视为同一 IR） |
| `rules` | 否 | 覆盖随包规则包的三件套；缺任一份 / 结构非法 → `RulePackError`（退出码 2） |
| `claims[]` | 是 | `claim_id` 唯一；`check` 闭集；`node` 可选（痕迹节点） |

### 2.1 事件 IR（`opslens.events/1`）

| 字段 | 规则 |
|---|---|
| `source` | `claude_code` / `codex`；其它值 → 契约错误 |
| `status` | `ok` / `error` / `unknown`；**缺省 = `unknown`**（绝不等于成功） |
| `tokens` | `null` 或四字段对象；缺键补 0；`null` **不等于 0**（该条不提供 token 归因） |
| `duration_ms` | `null`（不可得）或有限数字；**不可得不得写成 0** |
| `turn_tokens_attributed` | 布尔，缺省 `false` |
| `notes` | 字符串数组，缺省 `[]` |
| `seq` | 非负整数；与 `source + session_id` 组成确定性排序键 |
| 其它 | `source_version` / `timestamp` / `call_id` / `error_text` 缺省空串；未知字段 → 契约错误 |

载荷对象只认 `schema` / `count` / `events` / `home` / `sources` / `schema_versions` / `coverage_note`；
`schema` 必须是 `opslens.events/1`，`count` 若给出必须与 `events` 条数一致。

## 3. 规则

### 3.1 聚合（与源仓 `aggregate.py` 同口径）

1. 两级维度：server 级 `GROUP BY source, server`；tool 级 `GROUP BY source, server, tool`；
   两级都单列 `calls_unknown`，排序按 `(source, server[, tool])` 字典序。
2. 对账等式：`calls_ok + calls_error + calls_unknown == calls_total`；破坏即内部错误。
3. 失败率 = `calls_error / (calls_ok + calls_error)`；**分母不含 `unknown`**；分母为 0 →
   `null` + `insufficient_data=true`。精度来自 `params.rate_precision`。
4. token 四项（`input` / `output` / `cache_read` / `cache_creation`）分列求和；
   `token_samples` / `token_missing` 单列；`turn_token_avg = token_sum / token_samples`；
   无样本时四项与均值一律 `null`（**缺失 ≠ 0**）。
5. 耗时：`duration_sum / duration_samples`；无样本 → `null` + `duration_available=false`；
   两侧口径不同源，不混算。
6. 重试：同 `(source, server, tool)` 按 `(timestamp 秒, seq)` 排序，前一条为 `error` 且
   当前调用与它的时间差 ≤ `params.retry.window_seconds` 时记一次；时间戳不可解析的调用
   不参与判定（源仓 SQL `LAG` 同语义）。
7. 时间戳：纯整数换算（闰年规则完整、小数秒截断、时区偏移参与、缺时区按 UTC）；
   **不 import 时钟**。

`metric.field` 闭集：`calls_total` / `calls_ok` / `calls_error` / `calls_unknown` /
`failure_rate` / `failure_rate_numerator` / `failure_rate_denominator` / `insufficient_data` /
`retry_count` / `tokens_input` / `tokens_output` / `tokens_cache_read` / `tokens_cache_creation` /
`token_samples` / `token_missing` / `turn_token_avg` / `duration_avg_ms` / `duration_samples` /
`duration_missing` / `duration_available`。

### 3.2 失败归因（与源仓 `attribute.py` 同口径）

1. 五分类来自 `failure_patterns.categories`；未声明 `other` 时，`other` 仍进分布但不进
   输出的 `categories` 列表（与源仓 `setdefault` 一致）。
2. **只在 `status=error` 的事件上匹配**，匹配面只有 `error_text`；成功记录的正常输出
   可能命中宽模式（源仓本机实测），`unknown` 是「未声明成败」而不是失败，两者都不参与。
3. 规则门控（源仓 K10）：`status === "verified"` **且** `verified_samples` 非空才进计算路径；
   其余规则不生效，命中它们的失败落 `other`，未生效原因逐条列出（`ineffective_rules`）。
4. 按规则包顺序取第一条命中的规则 / 模式；`matched_patterns` 逐条登记
   `(rule_id, pattern, calls)`，可审计。
5. `by_server` 只包含有失败调用的 server；`calls_error` 等于该行类别计数之和。

### 3.3 删换建议（迁移自源仓 `report/suggestions.py` 的判定部分）

| 轴 | 触发 | 证据 |
|---|---|---|
| `failure_rate` | 样本 ≥ `min_samples.calls_total_gte` 且失败率 ≥ `remove_candidate.failure_rate_gte` → `remove_candidate`；在 `[investigate.failure_rate_gte, investigate.failure_rate_lt)` → `investigate`；否则 `none` | `value` / 分子 / 分母 / 样本量 / 实际用到的阈值 / 口径说明 |
| `turn_token_avg` | 样本 ≥ `min_samples.token_samples_gte` 且均值 ≥ `cost_heavy.turn_token_avg_gte` → `cost_heavy`；否则 `none` | 均值 / token 四项之和 / 样本量 / `token_missing` / 阈值 / 口径说明 |

- 样本不足 → 该轴降级「数据不足」：不产出建议，只产出 `insufficient` 条目
  （`observed_sample` / `required_sample` / 原因 / 阈值）。
- **证据完整性硬门**：每条建议缺任一项证据 → `assertEvidenceComplete()` 当场抛错，
  该条不输出（内部错误，不是静默跳过）。
- 排序：建议按 `remove → investigate → cost`，组内按 `(source, server)`；
  数据不足按 `(axis, source, server)`。
- 阈值只来自规则包；器官代码不写第二份阈值，报告排版（Markdown / HTML / JSON）不迁。

### 3.4 随包规则包（源仓 `data/rules/` 只读导出）

| 数据 | 内容 |
|---|---|
| `params.json` | 重试窗口 120s / 比率精度 6 / error_text 截断上限 240（截断由输入侧执行） |
| `thresholds.json` | 建议触发阈值（remove 0.5、investigate 0.2–0.5、cost 20000、样本 20） |
| `failure-patterns.json` | 5 类 + 4 条规则（3 条 verified / 1 条 pending） |

## 4. 输出示例

随包样例 = 旧仓 `scan --home data/synthetic` 的 202 条调用事件 + 46 条主张
（聚合 / 归因 / 门控 / 建议 / 时间戳 / IR 六面）。

```console
$ traceproof check tool-ops-attribution --input samples/tool-ops-attribution.json \
                                       --basis samples/tool-ops-attribution-traces.json
traceproof :: tool-ops-attribution 0.2.0 :: tool-ops-attribution.json
[claim] c-01-stream-count — 主张「stream.count = 202」被同一份输入上的重算支持：事件流 count = 202，与主张一致 :: s-ops-1#1#call-ops-1
[claim] c-22-metric-high-rate — 主张「server claude_code/fake-high-fail.failure_rate = 0.6」被同一份输入上的重算支持：server 级 claude_code/fake-high-fail 的 failure_rate = 0.6，与主张一致 :: s-ops-1#3#call-ops-3
[claim] c-28-suggestion-high-remove — 主张「failure_rate@claude_code/fake-high-fail = "remove_candidate"」被同一份输入上的重算支持：claude_code/fake-high-fail 的 failure_rate 建议 = remove_candidate，与主张一致 :: s-ops-1#4#call-ops-4
…
合计 46 条，阻断 0 条（claim=46 refuted=0 inconclusive=0）
# 退出码 0
```

`--json` 输出与内核一致：无时间戳、无绝对路径、字段顺序固定；同输入两次运行**逐字节一致**。
账本行 `evidence` 含 `check` / `asserted` / `computed` / `comparison`，以及该 check 的实测细节
（`level` / `field` / `row_found` / `actual` / `suggestion` / `entry` / `count` 等）。

## 5. §7.3 四项无损判据

### 5.1 判据 1：X = 150（D1 + D18 机械选，源仓实跑）

D1 排除词（`cli|gui|packaging|audit|desensit|guard|bench|infra|export|version|license|generat|docs?_|health|release|selftest|smoke`）
+ D18 追加词（`parse|report|input|output|web|panel`）按**文件名**机械匹配；未改 D1 / D18，未删源仓文件。

命令（来源仓只读；`PYTHONDONTWRITEBYTECODE=1` 防写旧仓 `__pycache__`）：

```console
$ cd <源仓>
$ PYTHONDONTWRITEBYTECODE=1 .venv/Scripts/python.exe -m pytest \
    tests/test_aggregate.py tests/test_attribute.py tests/test_discipline.py \
    tests/test_encoding.py tests/test_exit_codes.py tests/test_install_contract.py \
    tests/test_privacy.py tests/test_readme_gate.py tests/test_rules_gate.py \
    tests/test_schema.py tests/test_serialize.py tests/test_synthetic_data.py
150 passed in 14.76s
```

| 源仓测试文件 | 实跑 passed | 域 | 器官处置 |
|---|---:|---|---|
| `test_aggregate.py` | 29 | 两级聚合 / 三态 / token / 耗时 / 重试 / 时间戳 | **部分迁**：聚合判定 25 条已迁（`aggregate.ts`）；AST 口径唯一性守门 4 条不迁（TS 器官内只有一处比率计算，由代码结构保证） |
| `test_attribute.py` | 18 | 五分类 / K10 双门 / 匹配面 / 真值对账 | **已迁**：`attribute.ts` + `rules.ts` |
| `test_discipline.py` | 4 | 零第三方 / 零出网 / 无时钟无随机 | **不迁**：Python 源码级 AST 门；本器官运行期只处理已解析 JSON，不 import 网络 / random / time，由产品构建与评审复核 |
| `test_encoding.py` | 12 | 控制台 UTF-8 守卫 | **不迁**：CLI / stdio 层，属产品级；器官不打印 |
| `test_exit_codes.py` | 5 | 旧退出码 0/1/2/4 表 | **不迁**：新产品退出码固定 0/1/2/3（`docs/traceproof.md` §5） |
| `test_install_contract.py` | 1 | wheel 不带规则包 → exit 4 | **不迁**：安装面契约；由本产品判据 4（`npm pack` 后 `data/` 进包）接管 |
| `test_privacy.py` | 6 | 真实 server 名 / `env` 禁读 / 脱敏审计器 | **不迁**：输入侧解析与仓库审计属产品级；本产品由 CI 的 desensitize 门接管，器官不读 `env` / 文件 |
| `test_readme_gate.py` | 7 | README ↔ CLI 反射一致 | **不迁**：产品级文档门 |
| `test_rules_gate.py` | 13 | 规则包装载 / 双门独立可证伪 / 合成覆盖不冒充样例 | **已迁**：`rules.ts`（含无效正则显式拒绝） |
| `test_schema.py` | 11 | IR 三态 / 排序 / 序列化 | **已迁**：`event.ts` |
| `test_serialize.py` | 9 | 原子写盘 / LF / 确定性 | **不迁**：文件写盘属唯一入口 / 内核输出，器官不写盘 |
| `test_synthetic_data.py` | 35 | 冻结合成数据 / 真值 / 清单覆盖 | **不迁**：生成器与真值库是产品级 fixture；其冻结产物作为 `test/fixtures/tool-ops-attribution/events.json` 只读输入，器官测试逐值对账 |
| **合计** | **150** | — | 已迁 4 文件 / 部分迁 1 文件 / 不迁 7 文件（按判定逻辑计） |

**D1/D18 剔除（不计入 X，共 136 条）**——逐文件处置：

| 源仓测试文件 | 实跑 passed | 排除词 | 处置 |
|---|---:|---|---|
| `test_cli.py` | 15 | D1 `cli` | 产品级 CLI 参数 / 摘要输出；本产品入口已固定 `check` / `list` |
| `test_bench.py` | 40 | D1 `bench` | 真值基准脚手架（合成数据 + 探活）；器官只核对输入事实，不跑基准 |
| `test_parsers.py` | 52 | D18 `parse` | 日志发现 / JSONL 解析 / 配置读取留在旧仓（MCP 壳），不迁；器官接收已解析事件流 |
| `test_report.py` | 29 | D18 `report` | 报告排版（Markdown / HTML / 外链守卫）不迁；建议判定已迁 |

> `conftest.py` 无测试函数，不计入 X。

### 5.2 判据 2：旧示例 rc 相同

源仓 README 的「按失败调用做规则匹配分类」示例：

| 侧 | 命令 | 实测 | rc |
|---|---|---|---:|
| 旧 | `opslens scan --home data/synthetic --out <tmp>/events.json`（README 示例 1，显式传演示目录） | 2 个文件 / 202 次调用（ok=122 error=75 unknown=5） | **0** |
| 旧 | `opslens attribute --events <tmp>/events.json --out <tmp>/attr.json`（README 示例 3，原参数） | 75 次失败（命中 71 / 落 other 4）；timeout 24 / permission_denied 25 / invalid_args 22 / content_refusal 0 / other 4 | **0** |
| 新 | `traceproof check tool-ops-attribution --input samples/tool-ops-attribution.json --basis samples/tool-ops-attribution-traces.json` | 46 条 claim / 阻断 0 | **0** |
| 新 | 同上 `--json` | `summary.total=46`、`summary.blocking=0` | **0** |

**同为「完成且无阻断」**，无 rc 差。旧插件 / MCP 壳形态不是 CLI，未照抄其调用方式。
另以旧仓判定层产物做逐字段对账：`aggregate` 的 server / tool 两级 **7 + 12 行**全部指标、
`attribute` 的类别分布 / `by_server` / `matched_patterns` / 未生效规则，以及报告层的
**6 条建议 + 2 条「数据不足」**，新器官重算与旧产物**逐项相等**（仅对象键序不同）。

### 5.3 判据 3：口径乙（用例 + 函数）

| 项 | 旧层 | 新器官 | 结论 |
|---|---:|---:|---|
| 实跑用例数 | 150（12 文件） | **230**（`node --test test/tool-ops-attribution.test.js`） | 过（230 ≥ 150） |
| `test(` 函数数（按条计） | **150**（12 文件 AST `ast.FunctionDef/AsyncFunctionDef` 且名以 `test_` 开头） | **230**（顶层 `test(` 调用数） | 过（230 ≥ 150） |
| 测试文件数（只记录） | 12 | 1 | 记录 |

### 5.4 判据 4：`npm pack` 后 `data/` 进包

在 `%TEMP%` 的**副本**里构建（`npm run build`）后 `npm pack`（依赖目录用 junction 指回本地
`node_modules`，构建输入仍是副本里的源码）：

| 项 | 实测 |
|---|---|
| 包文件 | `dsh-prompt-polisher-0.2.0.tgz`，**246 条目 / 371234 B**（unpacked 1.5 MB） |
| 器官 data | `package/lib/traceproof/verbs/tool-ops-attribution/data/` **3 文件**：`failure-patterns.json` 4970 B / `params.json` 628 B / `thresholds.json` 960 B |
| 数据等价 | 与 `src/.../data/` 逐文件 `JSON.parse` 后深比较**相等**（tsc 重新序列化后语义不变） |
| 解包后 `list` | 含 `tool-ops-attribution 0.2.0`（9 器官） |
| 解包后 `check` | 样例 rc **0**，46 条 claim / 阻断 0 |

`:data` 以 `import … from './data/*.json' with { type: 'json' }` 引入，tsc 才会把它发到
`lib/.../data/`；器官运行期不读文件。

## 6. 口径差（如实登记）

1. **Python 源 → TypeScript 重写**；只迁判定层：IR 规范化 / 两级聚合 / 失败归因 /
   规则门控 / 删换建议。源仓的日志发现、JSONL 解析、MCP 配置读取、CLI、报告排版
   （Markdown / HTML / 外链守卫）、wheel 安装面、真值基准与探活**不迁**。
2. **输入从文件变成 subject**：事件流是已解析的 `opslens.events/1` 载荷（或裸数组）；
   器官不读文件 / 环境变量 / 时钟，不联网。
3. **`error_text` 的截断与路径脱敏在输入侧完成**：源仓 `scan` 按 `params.error_text.max_chars`
   截断并替换本机路径；器官只对收到的文本做正则匹配，不二次截断、不读 `env`。
4. **退出码语义按本产品契约收敛**：旧仓 `0/1/2/4`（1 = 检出问题，4 = 数据不可用）→
   新仓 `0/1/2/3`（1 = 有 `refuted`，2 = 输入不合法，3 = 契约违约）。
   旧 `report` 在出现 `remove_candidate` 时 rc 1；新器官的**建议本身不是阻断**，只有主张被
   推翻且挂了痕迹节点才 `refuted` → rc 1。
5. **阈值 / 规则结构非法改为显式 `RulePackError`（退出码 2）**：源仓对缺失阈值键抛
   `ValueError` / 对非法正则抛 `re.error`（未捕获）；器官在装载时统一校验并一次列出全部违规。
6. **建议证据完整性由 `assertEvidenceComplete()` 常驻执行**：缺任一项即抛内部错误；
   源仓同语义，但新器官允许主张用 `evidence` 只比对**本条建议实际用到的**子集字段。
7. **比率/均值为半偶舍入**：`roundTo` 复刻 Python `round()` 的 ties-to-even（6 位）；合成样例
   全部数值逐项相等，仅在极端二进制浮点边界可能有末位差。
8. **`coverage_note` 文案去掉旧仓 `plan/03 §2.1` 章节引用**，语义（分母不含 unknown /
   token 分列 / 耗时不可得）逐条保留。
9. **两级聚合不复刻 SQLite**：分组 / 排序 / 重试用确定性数组实现；对 `NULL` 时间戳按
   SQLite 「NULL 最小」的顺序处理，合成样例与旧仓产物逐项一致。
10. **判据 2 的新样例覆盖面大于旧示例**：旧示例只演示 `attribute`；新样例同时核对聚合、
    归因、门控、建议与时间戳，共 46 条主张（旧 `attribute` 产物 75 条失败的全部类别计数
    均在其中）。
11. **接线副作用**：`test/pipeline-run.test.js` / `test/pattern-evidence.test.js` /
    `test/rework-evidence.test.js` / `test/hazard-triage.test.js` 的精确 8 项器官清单断言
    改为**精确 9 项**（测试名同步）；`test/anonymity-collapse.test.js` 的
    `list --json` 计数 8→9（测试名同步），未退回 `contains`。
12. **D16 仓外编辑**：本批改动在运维计划会话（`01-运维-2611`）里 `cd` 进产品仓 / 来源仓完成
    （宿主门 `MIMOSA_GIT_GATE_MODE=warn`，graded 模式不追溯扫描）；来源仓只读、未改未删未提交；
    未跑 `security_scan`；未碰可见性 / DB / 删仓。

## 7. 数据溯源与审计

来源仓 HEAD `5831c1d`；`data/rules/` 三件套只读导出为器官 `data/`（字节级同源）：

| 源文件 | sha256 | 器官文件 |
|---|---|---|
| `data/rules/params.json` | `737c4bbe390a1685fd5e7e03430e3d0ef6e438a313b2c967f2e6909b836dac9c` | `params.json` |
| `data/rules/thresholds.json` | `f80c4216a5bf19cfd940f37fe99ad92f5e1094e4e9b93d77cf243d4a0e2875de` | `thresholds.json` |
| `data/rules/failure_patterns.json` | `2a3c0c7566d3983d0139c52a1e079defe90469da60065dfd3bf9525d7d10e225` | `failure-patterns.json` |

`test/fixtures/tool-ops-attribution/events.json`（sha256
`67d0c084b6b5ce18bc5e4ea0606ab768e1d3cf113e75c30b08192a377068a8a8`）是旧仓
`scan --home data/synthetic` 的只读产物；合成日志只含 `fake-*` server 名与
`<redacted-path>`，不含真实会话、个人信息或凭据。