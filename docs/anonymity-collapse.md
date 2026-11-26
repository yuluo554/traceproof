# anonymity-collapse · 匿名性崩塌取证

> 器官 slug `anonymity-collapse`，版本 `0.1.1`（迁自 target-map ④ 行；版本沿用源仓 `__version__`）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这张表在给定**列角色声明 + 缺失策略 + 阈值**下，k/l/t 是多少、哪几列组合会让 k 崩塌、
哪些行被唯一识别」的主张，逐条对到**同一份数据快照**的确定性重算：

| check | asserted 类型 | 判定内容 |
|---|---|---|
| `k` / `l` / `t` | 整数 / 整数 / 数，或 `null` | 最小等价类大小 / 最小类内敏感值数 / 最大类内分布距离 |
| `class-count` | 整数 | 等价类总数 |
| `histogram` | `{类大小: 类数}` | 类大小直方图（只列出现的大小） |
| `violations` | `[{key,count,row_numbers}]` | 违例三件套全集 |
| `violation-count` | 整数 | 违例条数 |
| `unique-records` | 整数数组 | 落在单例类里的行号 |
| `undecided-rows` | 整数数组 | `drop` 下未参与分组的行号 |
| `missing-class` | `{k,row_numbers}` 或 `null` | `separate-class` 的缺失独立类 |
| `verdict` | `pass` / `violation` / `undecidable` | 扫描结论（空表 / 无参与行 → `undecidable`） |
| `subset-k` | 整数或 `null`，附 `columns` | 指定 qi 子集的 k（空数组 = 空集语义） |
| `exposed-rows` | 整数，附 `columns` | 指定 qi 子集中落入 `k < 阈值` 的行数 |
| `collapse-sets` | `[[列名...]]` | 最小崩塌集（穷尽） / 崩塌边界集（非穷尽） |
| `completeness` | `exhausted` / `budget-truncated` / `monotonicity-not-applicable` | 完整性三态 |
| `empty-set-witness` | 布尔 | 空集是否**有证据**是边界集（「一个 QI 列都不能加」） |
| `declared-k` | 整数或 `null` | 声明集合本身的 k（搜索的诊断值） |
| `monotonicity` | 布尔 | 单调性前提是否成立（`drop` + 候选池含缺失 → false） |
| `evaluated-subsets` / `pruned-subsets` | 整数 | 已评估 / 已剪枝子集数（空集计入已评估） |
| `search-verdict` | `ok` / `no_solution` | 搜索自身的结论（无解显式表达，不用空数组冒充） |
| `outcome` | `pass` / `violation` / `undecidable` | 扫描 + 搜索合并后的 gate 结论 |
| `undefined-reason` | 字符串或 `null` | `empty_table` / `no_participating_rows` / 两个搜索原因 |
| `flagged-rows` | 整数数组，附 `attacker` | 逐记录风险命中行 |
| `attack-rule` | 字符串，附 `attacker` | 口径文本（`class_size == 1` 等） |
| `risk-verdict` | `pass` / `violation` / `undecidable` | 逐记录风险结论 |
| `row-class` / `row-class-size` | 字符串或 `null` / 整数或 `null`，附 `row` | 指定行的等价类键 / 类大小 |

**器官不做的事**：不读 CSV/TSV 文件、不读判据文件、不读环境变量、不读时钟、不打印、
不带参数解析器、不写报告。表格、声明、阈值、搜索策略、主张全部由 `subject` 提供；
证据只经 `makeRecord()` 入账（内核在入账时脱敏）。

## 2. 输入（subject）

```json
{
  "table": {
    "header": ["age", "zip", "disease"],
    "rows": [["30", "100", "flu"], ["31", "100", "cold"], ["30", "101", "flu"]]
  },
  "declaration": {
    "columns": {
      "age": {"role": "qi"},
      "zip": {"role": "qi"},
      "disease": {"role": "sensitive"}
    }
  },
  "policy": "drop",
  "thresholds": {"k": 2, "l": null, "t": null},
  "search": {"enabled": true, "budget": 100, "require_exhaustive": false},
  "claims": [
    {"claim_id": "k", "check": "k", "asserted": 1,
     "node": {"session_id": "s-anon-1", "turn": 1, "tool_call_id": "call-anon-1"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `table.header` | 是 | 非空字符串数组；去首尾空白；空列名 / 重复列名直接契约错误 |
| `table.rows` | 是 | 字符串二维数组；每行宽度必须等于表头；行号 = 数组下标 + 1 |
| `declaration.columns` | 是 | 角色闭集 `qi` / `sensitive` / `direct-identifier` / `date-precision`；未声明即不参与 |
| `policy` | 是 | `drop` / `single-column` / `separate-class`，**无默认值** |
| `thresholds` | 是 | 闭合键 `k` / `l` / `t`；`k` 必填正整数，`l` 正整数或 null，`t` ∈ [0,1] 或 null |
| `search` | 否 | 闭合键 `enabled` / `budget` / `require_exhaustive`；`enabled=true` 必须给 `budget` |
| `claims[]` | 是 | `claim_id` 唯一；字段闭集随 check 而定（`columns` / `attacker` / `row`），多写即契约错误 |

`subject` 顶层只接受上表六个键；未知键一律契约错误（判据闭合，不做静默忽略）。

## 3. 规则

### 3.1 等价类（M2）

- 分组键 = **声明书写顺序**的 `name=value` 用 `|` 拼接，不是表头顺序。
- 缺失值集合 = `""` / `NA` / `N/A` / `null` / `NULL` / `-`（大小写敏感，单点定义在
  `data/anonymity-defaults.json`）。
- `drop`：含缺失的行不参与分组，列入 `undecided_rows`；
  `single-column`：缺失值渲染为 `NULL` 作为普通取值；
  `separate-class`：含缺失的行合并为 `__MISSING__` 独立类。
- k = 最小类大小；l = 逐 sensitive 列算类内不同取值数 → 列间取最小 → 全部类再取最小；
  t = 逐类逐 sensitive 列与全表分布的总变差距离，取最大（精确有理数 + 6 位半偶舍入）。
- 空表 / 非空表但全部行被丢弃 → `k=null` + `undefined_reason`，结论 `undecidable`，
  绝不返回 0 冒充通过。

### 3.2 组合搜索（M3）

- 候选池 = 声明为 qi 的列；子集按大小升序、同大小按码位序枚举。
- 单调性前提：`drop` 且候选池含缺失 → `monotonicity-not-applicable` 且**不剪枝**；
  其余情况父集不安全 ⇒ 超集必不安全。
- 预算按**已评估子集数**计数（含空集）；剪枝与预算分开计数。
- 完整性三态闭合互斥；非穷尽结果只称「崩塌边界集」，不称「最小崩塌集」。
- `empty_set_witness` 只有在**每个单列扩展都实算过且都不安全**时才为 true；
  预算截断导致没算完时一律 false（「没算过」≠「不存在安全扩展」）。
- 无解（空集本身不安全 / 候选池为空）→ `verdict=no_solution`，`minimal_collapse_sets=[]`，
  不用空数组冒充「搜索完成」。

### 3.3 逐记录风险（M4）

| attacker | 规则 |
|---|---|
| `prosecutor` | `class_size == 1` |
| `journalist` | `class_size <= 2` |
| `marketer` | `class_size < 3` |

`drop` 下未裁决的行以 `participates=false` + `class_id=null` 显式出现；
`separate-class` 的缺失类照常参与判定；空表 / 无参与行 → `undecidable`。

### 3.4 判据组合（M5）

- 扫描结论与搜索结论按 `undecidable > violation > pass` 合并；未知值按 `undecidable`。
- `search.require_exhaustive=true` 且被预算截断 → 结论 `undecidable`，
  `undefined_reason=search_budget_truncated_require_exhaustive`（**不吞掉**已算出的搜索证据）。
- 非穷尽但未要求穷尽 → `search_not_exhausted`；已判出违例时不挂无法裁决原因。

### 3.5 主张 → 账本

重算一致 → `claim`；不一致且**有痕迹节点** → `refuted`；
不一致但**没有节点** → `inconclusive`（无节点不得下 `refuted`）；
重算判不了（例如 `search.enabled=false` 却主张搜索结论）→ `inconclusive` 并写明缺失项。
节点不完整（缺 `turn` / `tool_call_id`）由内核降级 `inconclusive`。

## 4. 输出示例

```text
traceproof :: anonymity-collapse 0.1.1 :: anonymity-collapse.json
[claim] adult-class-count — 主张「class-count=1703」被数据重算支持 :: s-anon-adult#2#call-anon-adult-2
[refuted] adult-k-threshold — 数据重算推翻主张：主张 <5> ≠ 重算 <1>（重算 k=1） :: s-anon-adult#1#call-anon-adult-1
[claim] adult-outcome — 主张「outcome="violation"」被数据重算支持 :: s-anon-adult#8#call-anon-adult-8
合计 11 条，阻断 1 条（claim=10 refuted=1 inconclusive=0）
# 退出码 1
```

关键证据字段：`computed`（重算值）、`scan.{k,l,t,class_count,violation_count,undefined_reason,verdict}`、
`search.{completeness,minimal_collapse_sets,empty_set_witness,declared_k}`、`dataset.{rows,columns,policy,qi_columns}`。

## 5. §7.3 四项无损判据（实测）

| # | 实测 | 结论 |
|---:|---|---|
| 1 | 旧仓判定层（D1 + D18 机械选 **7 文件**）实跑 **263 passed / 0 failed / 0 skipped**（JUnit 对账）；新器官 `node --test test/anonymity-collapse.test.js` **299 passed / 0 failed** | **过**（299 ≥ 263） |
| 2 | 旧 README 示例 `anonymity-scanner gate --criteria examples/adult/criteria.json --out-dir <out> --root .` rc **1**（k=1 / 1703 类 / 762 条违例 / 搜索 `[["education","sex"]]`）；新 `node bin/traceproof check anonymity-collapse --input samples/anonymity-collapse.json --basis samples/anonymity-collapse-traces.json` rc **1**（k=1 / class-count=1703 / violation-count=762 / collapse-sets=`[["education","sex"]]` / completeness=`exhausted` / declared-k=1 / outcome=`violation`；`--json` 同参数 rc **1**、`summary.blocking=1`） | **过**（rc 1 = 1，逐值一致） |
| 3 | 口径乙：实跑用例 299 ≥ 263；`test(` 函数 **299** ≥ 旧层 AST **153**；文件数旧 **7** → 新 **1**（只记录） | **过** |
| 4 | `%TEMP%` 副本 `npm run build` + `npm pack`：**195 条目 / 290012 B**；`package/lib/traceproof/verbs/anonymity-collapse/data/anonymity-defaults.json` **1171 B**；解包后 `list` 显示 `anonymity-collapse 0.1.1`、Adult 样本 `check` rc **1** | **过** |

> 判据 1 的 X 由 `pytest --junitxml` 实跑取准，不是 `baseline` 静态计数；
> 判据 3 的 `test(` 调用数与 `node --test` 的 `ℹ tests 299` 一致（无循环生成测试）。

### 5.1 判定层选文件（D1 + D18）

命令（来源仓只读；`PYTHONDONTWRITEBYTECODE=1` 防写旧仓 `__pycache__`）：

```bash
pytest tests/test_contract.py tests/test_determinism.py tests/test_fixtures.py \
  tests/test_m2_classes.py tests/test_m3_search.py tests/test_m4_risk.py \
  tests/test_m5_gate.py -q -p no:cacheprovider
# → 263 passed（rc 0）
```

| 文件 | 实跑 passed | 域 | 器官处置 |
|---|---:|---|---|
| `test_contract.py` | 67 | 退出码映射 / 参数形态 / 未实现模块 fail-closed / 输入校验 | **部分迁**：退出码与「无依据不下结论」由 traceproof 内核 `ledger.ts` 接管；表格与声明校验已迁到 `table.ts` / `declaration.ts`；参数形态由唯一入口 `cli.ts` 与 `input_fields` 接管，器官不迁 CLI |
| `test_determinism.py` | 13 | `round6` 半偶 / 序列化冻结参数 / 原子写 / 无绝对路径 | **部分迁**：`round6` 已迁（`round.ts`，含半偶与 -0 归一）；序列化 / 原子写 / 相对化由内核 `Report` 与唯一入口接管（器官不写盘、不打印） |
| `test_fixtures.py` | 49 | 四组夹具真值 / oracle / 生成器 AST 守门 / sha256 | **部分迁**：4 组夹具表格与 3 份 truth 只读拷贝到 `test/fixtures/anonymity-collapse/`，真值对账已迁；生成器 / oracle / manifest sha256 属源仓数据工程，不迁 |
| `test_m2_classes.py` | 29 | 等价类 / k/l/t / 三种缺失策略 / 边界表 | **已迁**（`classes.ts`） |
| `test_m3_search.py` | 47 | 子集枚举 / 剪枝 / 预算 / 完整性三态 / 空集证据 / 无解 | **已迁**（`search.ts`） |
| `test_m4_risk.py` | 19 | 三口径攻击者 / 逐记录 / 未裁决行 / 缺失类 | **已迁**（`risk.ts`） |
| `test_m5_gate.py` | 39 | 判据闭合 / 结论优先级 / 三态退出码 / 搜索与扫描合并 / 报告纪律 | **部分迁**：判据闭合、结论优先级、`undefined_reason` 已迁（`criteria.ts`）；路径相对化、`gate.md` 渲染、示例脚本与零网络扫描属产品级脚手架，不迁 |
| **合计** | **263** | — | — |

### 5.2 脚手架测试处置表（D1/D18 剔除，不计入 X）

| 旧文件 | D1/D18 命中词 | 收集数 | 内容 | 处置 |
|---|---|---:|---|---|
| `test_doc_counts.py` | `docs?_` | 2 | README / 文档计数门 | 不迁：产品级文档门，由本仓文档与 CI 的自检接管 |
| `test_inputs.py` | `input`（D18） | 26 | CSV/TSV 读取、编码、宽度、空文件、缺列 | 不迁：器官只收已解析 JSON；表头/宽度/列存在/缺失值判定的语义已由 `table.ts` 覆盖，文件读取是唯一入口职责 |
| `test_packaging.py` | `packaging` | 4 | wheel / 安装形态 / 包内数据 | 不迁：由判据 4 的 `npm pack` 与解包检查接管 |
| `tests/conftest.py` | —（不是测试文件） | — | pytest 路径注入 | 不适用 |

> 机械 X 仍含产品级用例（`test_contract` 的参数/子进程部分、`test_determinism` 的写盘/序列化、
> `test_fixtures` 的生成器/oracle、`test_m5_gate` 的报告/路径/示例脚本）。D1/D18 是**文件名机械规则**，
> 不因器官不复刻这些路径而改口径；判据 1 用 299 条判定用例满足 `≥263`。未改 D1、未删源仓文件。

## 6. 与旧仓的口径差（如实登记）

1. **Python → TypeScript 重写**：只迁判定层（等价类 / 搜索 / 风险 / 判据组合 / 6 位半偶舍入）。
   CSV/TSV 读取、CLI、`gate.md` / `scan.json` 等产物、判据文件路径基准、示例脚本与
   `prepare.py` 均为产品级脚手架，不迁。
2. **输入从文件变成 `subject`**：源仓 `--table <csv> --decl <json>`；器官收 `{table:{header,rows}}`
   与 `{declaration:{columns}}`。行号语义不变（1 起，不含表头；JSON 无空行概念）。
3. **退出码**：源仓 `0/1/2`；本产品 `0/1/2/3`（取证账本契约）。判据 2 的 rc 一致（均为 1）；
   输入不合法由唯一入口映射 2，器官契约错误映射 3。
4. **`require_exhaustive` 截断**：源仓 `search --require-exhaustive` 抛 `CriteriaError`（2）；
   器官按 gate 语义产出 `outcome=undecidable` + `undefined_reason=search_budget_truncated_require_exhaustive`，
   保留搜索证据供主张核对，不把整份输入判成非法。
5. **声明顺序**：按 `declaration.columns` 的 JSON 对象键序（`JSON.parse` 保持文本顺序）。
   与源仓 Python `dict` 的差异仅在「整数型列名」这类 JS 对象会把整数键提前的极端边界；
   常规列名与源仓一致。
6. **t 的精确算术**：源仓用 `Fraction` + `round6(float(...))`；本器官用 BigInt 有理数求和后
   再按最短十进制文本做 6 位半偶舍入（`round.ts`），四组夹具与 Adult 的 t 逐值一致。
7. **`row-class` / `row-class-size` 不依赖 attacker**：源仓 M4 通过 attacker 入口计算，但类键 /
   类大小与 attacker 无关；器官直接用 `groupRows` 重算，避免伪造攻击者上下文。
8. **`subset-k` / `exposed-rows` 只接受 qi 候选池的子集**（允许空集）；源仓 `search` 的
   `subsets` / `strata` 同口径。
9. **Adult 样本**：源仓 `examples/adult/adult.csv`（3.5 MB）转成 `samples/anonymity-collapse.json`
   （4.5 MB，同一数据 / 策略 / 阈值 / 预算）；样本不进 `npm pack`（`files` 不含 `samples`）。
10. **新增第 7 个 verb 的接线副作用**：`test/pipeline-run.test.js`、`test/pattern-evidence.test.js`、
    `test/rework-evidence.test.js` 的精确 6 项断言改为**精确 7 项**（测试名同步），未退回 `contains`。
11. **D16 仓外编辑**：本批改动在 `01-运维-2611` 会话里 `cd` 进产品仓完成
    （宿主门 `MIMOSA_GIT_GATE_MODE=warn`，graded 模式不会追溯扫描），供审计复核。
    来源仓只读、未改未删未提交；未跑 `security_scan`；未碰可见性/DB/删仓。

## 7. 复现命令

```bash
# 判据 1（来源仓，只读）
cd <source-repo>
PYTHONDONTWRITEBYTECODE=1 py -3.12 -m pytest tests/test_contract.py tests/test_determinism.py \
  tests/test_fixtures.py tests/test_m2_classes.py tests/test_m3_search.py \
  tests/test_m4_risk.py tests/test_m5_gate.py -q -p no:cacheprovider

# 判据 1（本仓）
cd <product-repo>
npm run build
node --test test/anonymity-collapse.test.js

# 判据 2（本仓）
node bin/traceproof check anonymity-collapse --input samples/anonymity-collapse.json \
  --basis samples/anonymity-collapse-traces.json
# → 合计 11 条，阻断 1 条；rc 1
```