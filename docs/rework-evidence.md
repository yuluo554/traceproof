# rework-evidence · 会话返工取证

> 器官 slug `rework-evidence`，版本 `0.2.0`（迁自 target-map ④ 行；版本沿用源仓的 `0.2.0`）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这次会话里哪些文件被反复改回、Read:Edit 比是多少、新写符号是否与项目已有工具重复」
的主张，对到**同一份会话记录**上：

| check | asserted 闭集 | 判定 |
|---|---|---|
| `rework` | `rework` / `not_rework` / `insufficient_data` / `absent` | 单个文件的返工三态；可带 `expected_edits` 与 `expected_versions` 逐数对账 |
| `duplicate-candidate` | `present` / `absent` | 新写符号 × 已有符号的粗匹配候选（**披露制：粗匹配 ≠ 确认重复**） |
| `read-edit-ratio` | `defined` / `undefined` | Read:Edit 比；可带 `expected_ratio` |
| `parse-note` | `present` / `absent` | 某个解析注记码是否出现；可带 `count` |

**器官不做的事**：不读会话日志文件、不读 `file-history/` 目录、不读环境变量、不读时钟、
不打印、不带参数解析器。会话记录、版本链、项目文件内容全部由 `subject` 提供；
证据只经 `makeRecord()` 入账（内核在入账时脱敏）。

## 2. 输入（subject）

```json
{
  "session": {
    "harness": "claude",
    "source_file": "sessions/<session-id>/session.jsonl",
    "records": [ {"type": "assistant", "message": {"role": "assistant", "content": []}} ]
  },
  "version_chains": {
    "89b13e3cd80c18a9": {"versions": [1, 2, 3]}
  },
  "project_files": {
    "/demo/alpha/src/common.py": "def make_compute_helper(v):\n    return v\n"
  },
  "claims": [
    {"claim_id": "c1", "check": "rework", "asserted": "rework",
     "file": "/demo/alpha/src/alpha_a.py", "expected_edits": 3, "expected_versions": 3,
     "node": {"session_id": "<session-id>", "turn": 3, "tool_call_id": "call-1"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `session.harness` | 否 | `claude` / `codex`；缺省时按记录形态判别（`message` → claude，`payload` → codex），未知形态显式报错 |
| `session.records` | 是 | 已解析的 jsonl 行（**seq = 数组下标 + 1**），不得为空 |
| `session.source_file` | 否 | 证据锚点标签；缺省时用 `session_id`，再缺省用 `<session>` |
| `version_chains` | 否 | `{backup_stem: {"versions": [N...]}}`，只接受实数版本（不反推） |
| `project_files` | 否 | `{路径: 内容}`；`duplicate-candidate` 主张需要它，缺省判 `inconclusive` |
| `claims[]` | 是 | `claim_id` 唯一；各 check 的必填字段见 §1 |

`claims[]` 允许字段：`claim_id` / `check` / `asserted` / `file` / `new_symbol` /
`existing_symbol` / `code` / `expected_edits` / `expected_versions` / `expected_ratio` /
`count` / `node`。**字段只在其对应的 check 上生效**，放到别的 check 上直接契约错误
（不做静默忽略）。

## 3. 规则

### 3.1 会话记录 → 统一 IR

- **Claude**：`assistant` 消息里的 `tool_use` → 事件（`Read`→read、`Edit`/`NotebookEdit`→edit、
  `Write`→write、`MultiEdit`→edit 并计 `multiedit_downgraded` 注记、`Bash`→exec、其余→other）；
  `usage` → token 事件；`file-history-snapshot` 行只做形态校验与
  `file_path → backup_stem` 关联（快照 entry 固定 4 字段，未核对字段计入注记）。
- **Codex**：`session_meta` → 元数据；`function_call` 的 `exec` → exec，其余 → other；
  `custom_tool_call` + `apply_patch` 从 V4A 文本的 `*** Update File:` / `*** Add File:`
  取目标路径，每个路径一条 write 事件（缺 input 仍计一条未知路径 write + 注记）；
  `event_msg` → token 事件；未核对的 `payload.type` → 注记（不猜测）。
- 坏行/未核对字段/空 `tool_use` 一律计 `ParseNote`，**显式可见，不静默**。

### 3.2 返工判定（三态）

1. 同一文件的版本链长度 ≥ `rework_min_versions`，或写事件（edit/write）数 ≥ `rework_min_edits`
   → `rework`；
2. 两条都不成立且**版本链缺失**（文件只有 Edit、且没有 Write 新建）→ `insufficient_data`
   （`version_count = null`，**不由 Edit 次数反推链**）；
3. 两条都不成立且链存在 / 纯 Write 新建（首写不备份，无链属正常）→ `not_rework`。

版本数只来自 `version_chains` 的实读链长度；快照行只提供 `file_path → backup_stem` 关联。
跨度为写事件时间戳的 `max - min`（少于 2 个时间戳 → `null`）。证据锚点 =
`<source_file>:<seq>` 与 `<stem>@v<版本数>`。

### 3.3 指标 / 符号 / 粗匹配

- **Read:Edit 比**：分子 = `read` 事件，分母 = `edit` / `write` / `multiedit`；分母为 0
  → `undefined`（不填 0 不填 inf）。
- **符号提取**：首期仅 Python（`def` / `async def` / `class`），非支持语言显式返回 null；
  语言按 Write 目标文件扩展名判定（`.py` → python），不支持 → 披露后跳过。
- **归一化 5 步**：小写 → `-` 变 `_` → 去首尾 `_` → 按 `_` 切分后**迭代**剔除首 token
  前缀词表与尾 token 后缀词表 → 拼接。
- **匹配两级**：归一化精确相等 → `normalized_exact`；否则按 Python
  `difflib.SequenceMatcher.ratio()`（2M/T）≥ `dup_match_threshold` → `high_similarity`。
  该算法在 TS 本地重实现（含 autojunk），同阈值下命中与源仓一致。
- 候选输出必带披露文本（`粗匹配 ≠ 确认重复…需人工复核`），且候选不是判决。

### 3.4 主张 → 账本

重算结果与 `asserted` 一致 → `claim`；不一致且**有痕迹节点** → `refuted`；
不一致但**没有节点** → `inconclusive`（无节点不得下 `refuted`）；
重算判不了（会话格式错误、缺 `project_files`、Codex 符号候选未启用）→ `inconclusive`
并写明缺失项。节点不完整（缺 `turn` / `tool_call_id`）由内核降级 `inconclusive`。

## 4. 输出示例

```text
traceproof :: rework-evidence 0.2.0 :: rework-evidence.json
[claim] no-bad-lines — 主张「parse-note=absent」被会话痕迹支持 :: <session-id>#3#call-rework-3
[claim] read-edit-ratio — 主张「read-edit-ratio=defined」被会话痕迹支持 :: <session-id>#2#call-rework-2
[claim] rework-alpha-a — 主张「rework=rework」被会话痕迹支持 :: <session-id>#1#call-rework-1
合计 3 条，阻断 0 条（claim=3 refuted=0 inconclusive=0）
# 退出码 0
```

`rework` 证据里的关键字段：`finding.verdict` / `version_count` / `edit_count` /
`first_edit_seq` / `last_edit_seq` / `span_seconds` / `reasons` / `anchors`。

## 5. §7.3 四项无损判据（实测）

| # | 实测 | 结论 |
|---:|---|---|
| 1 | 旧仓判定层（D1 + D18 机械选 **10 文件**）实跑 **102 passed / 0 failed**（rc 0）；新器官 `node --test test/rework-evidence.test.js` **142 passed / 0 failed** | **过**（142 ≥ 102） |
| 2 | 旧 README 示例 `arl scan --claude-home <tmp-claude> --codex-home <tmp-codex>` 对合成 rework-01 会话 rc **0**（`rework /demo/alpha/src/alpha_a.py：版本 3 / 编辑 3 / 跨度 1200s / 理由 versions>=N,edits>=M`）；新 `traceproof check rework-evidence --input samples/rework-evidence.json --basis samples/rework-evidence-traces.json` rc **0**（3 条 claim 全支持，`version_count=3 / edit_count=3 / span_seconds=1200`；`--json` 同参数 rc **0**、`summary.claim=3`） | **过**（rc 0 = 0，逐值一致） |
| 3 | 口径乙：实跑用例 142 ≥ 102；`test(` 函数 **142** ≥ 旧层 AST **69**；文件数旧 **10** → 新 **1**（只记录） | **过** |
| 4 | `%TEMP%` 副本 `npm run build` + `npm pack`：**174 条目 / 263757 B**；`package/lib/traceproof/verbs/rework-evidence/data/rework-defaults.json` **660 B**；解包后 `list` 显示 `rework-evidence 0.2.0`、`check` rc **0** | **过** |

> 判据 1 的 X 由 `pytest` 实跑取准（JUnit 对账），不是 `baseline` 静态计数；
> 判据 3 的 `test(` 调用数与 `node --test` 的 `ℹ tests 142` 一致（无循环生成测试）。

### 5.1 判定层选文件（D1 + D18）

命令（来源仓只读；`PYTHONDONTWRITEBYTECODE=1` 防写旧仓 `__pycache__`）：

```bash
pytest tests/test_config.py tests/test_discovery.py tests/test_engine.py \
  tests/test_exitcodes.py tests/test_install_contract.py tests/test_ir.py \
  tests/test_m2_parsing.py tests/test_m3_engine.py tests/test_stdio.py \
  tests/test_synthetic_data.py -q -p no:cacheprovider
# → 102 passed in 13.91s（rc 0）
```

| 文件 | passed | 域 | 器官处置 |
|---|---:|---|---|
| `test_config.py` | 3 | 阈值/口径单点 | 已迁（`data/rework-defaults.json` + `defaults.ts`） |
| `test_discovery.py` | 7 | 路径发现（参数/环境变量/默认位置） | 不迁（器官不读环境/文件系统；产品级宿主职责） |
| `test_engine.py` | 12 | 引擎算法单测 | 已迁（`rework.ts` + `metrics.ts`） |
| `test_exitcodes.py` | 2 | 退出码契约 | 不迁（traceproof 内核 `ledger.ts` 统一 0/1/2/3） |
| `test_install_contract.py` | 1 | 非 editable 安装态 `bench` 契约 | 不迁（源仓打包/基准脚手架；本仓由判据 4 与 `npm pack` 接管） |
| `test_ir.py` | 6 | IR 确定性/形状 | 已迁（`parse.ts`；证据锚点与事件字段） |
| `test_m2_parsing.py` | 36 | 双源解析 + 容错（文件名含 `parsing`，未命中 D18 的 `parse`） | 已迁（`parse.ts`；输入侧读 jsonl 文件的部分不迁） |
| `test_m3_engine.py` | 19 | truth 驱动引擎回归 | 已迁（12 个冻结样例逐例对账 + 反例） |
| `test_stdio.py` | 8 | Windows 编码护栏 | 不迁（产品级输出层；器官不打印） |
| `test_synthetic_data.py` | 8 | 合成冻结数据守门 | 不迁（源仓 fixture 生成器/sha256 守门；本仓 fixture 只读拷贝 + 对账用例） |
| **合计** | **102** | — | — |

### 5.2 脚手架测试处置表（D1/D18 剔除，不计入 X）

| 旧文件 | D1/D18 命中词 | 内容 | 处置 |
|---|---|---|---|
| `test_cli.py` | `cli` | 进程内 argv / 子进程 `python -m` / 裸 `arl` 通路 | 由本仓唯一入口门 `test/entry-surface.test.js`、`test/traceproof-contract.test.js` 接管；器官不带 CLI |
| `test_m4_bench.py` | `bench` | 合成基准 truth 对账 / 退出码三语义 | 产品级基准留在源仓；本仓由 fixture 对账用例与判据 4 接管，不迁 runner |
| `test_m5_report.py` | `report` | Markdown / HTML 报告成稿 | 不迁：器官不得自带输出排版（`SKELETON-SPEC` §2）；人读/JSON 由内核 `ledger.ts` 输出 |
| `test_parsers.py` | `parse` | jsonl 容错读取 + 双源解析器 | 输入侧解析不迁（器官收已解析 JSON）；格式容错语义由 `parse-note` 主张覆盖 |
| `test_report.py` | `report` | 报告层披露/确定性/空节 | 不迁：同上，报告层是产品级脚手架 |
| `test_selftest.py` | `selftest` | 内置自检 | 不迁：由 `node --test` 全量与 CI 接管；器官无自检命令 |
| `tests/conftest.py` | —（不是测试文件） | pytest 路径注入 | 不适用 |

> 机械 X 仍含 5 个产品级文件的实跑用例（`discovery` 7 / `exitcodes` 2 /
> `install_contract` 1 / `stdio` 8 / `synthetic_data` 8，共 **26** 条）。D1/D18 是
> **文件名机械规则**，不因器官不复刻这些路径而改口径；判据 1 用 142 条判定用例满足
> `≥102`。未改 D1、未删源仓文件。

## 6. 与旧仓的口径差（如实登记）

1. **Python → TypeScript 重写**：只迁判定层（IR / 双源解析 / 返工三态 / Read:Edit 比 /
   符号提取 / 归一化 / 粗匹配）。源仓的 CLI、发现层、`file-history` 目录实读、
   Markdown/HTML 报告、bench runner、selftest 均为产品级脚手架，不迁。
2. **版本链是输入事实**：源仓 `read_version_chains()` 实读目录；器官不读文件，
   `version_chains` 由 `subject` 提供。快照行仍在记录里解析（`file_path → stem` 关联），
   版本数仍只按链长度计（不反推）。
3. **已有符号来自 `project_files`**：源仓按 `source_root` + 后缀回退读磁盘；器官用同序
   **后缀回退**在 `project_files` 里定位（多键命中取字典序最小），读不到 → 显式注记。
4. **Codex 符号候选不启用**：`apply_patch` 载荷没有独立 `file_path + content` 双字段形态，
   与源仓 R5 一致；`duplicate-candidate` 在 codex 源上判 `inconclusive`，不编造。
5. **消息内联中文**：源仓消息/披露文本来自代码常量与 locale 无关；器官不读 locale /
   不读配置，错误码与判定结论不变。
6. **difflib 本地重实现**：`SequenceMatcher.ratio()`（含 matching blocks 与 autojunk）
   按 Python 算法复刻；极端非 ASCII 符号名的 ratio 若逐位不同，只影响 `high_similarity`
   的边界，阈值与两级匹配语义不变。
7. **阈值与词表在 `data/rework-defaults.json`**：随包导入，不接受 subject 覆盖
   （源仓也是 config 单点；本器官不提供隐式覆盖通路）。
8. **会话源标签**：源仓 `source = "claude_code"`；本器官用 `claude` / `codex`
   （与 traceproof 的 harness 词汇一致）。`source_file` 由输入提供，缺省用 `session_id`。
9. **账本模型是 traceproof 取证账本**，不是源仓 `ReworkFinding` / `SessionMetrics`：
   `insufficient_data` 是**重算结果值**（可被主张 `asserted`），不是账本 verdict；
   `refuted` 必须有痕迹节点，否则降级 `inconclusive`。
10. **D1 机械 X ≠ 器官职责**：见 §5.2；26 条产品级用例照记 X，器官不复刻。
11. **新增第 6 个 verb 的接线副作用**：`test/pipeline-run.test.js` 与
    `test/pattern-evidence.test.js` 的精确 5 项断言改为**精确 6 项**（测试名同步），
    未退回 `contains`。
12. **D16 仓外编辑**：本批改动在 `01-运维-2611` 会话里 `cd` 进产品仓完成
    （宿主门 `MIMOSA_GIT_GATE_MODE=warn`，graded 模式不会追溯扫描），供审计复核。
    来源仓只读、未改未删未提交；未跑 `security_scan`；未碰可见性/DB/删仓。

## 7. 复现命令

```bash
# 判据 1（来源仓，只读）
cd <source-repo>
PYTHONDONTWRITEBYTECODE=1 py -3.12 -m pytest tests/test_config.py tests/test_discovery.py \
  tests/test_engine.py tests/test_exitcodes.py tests/test_install_contract.py tests/test_ir.py \
  tests/test_m2_parsing.py tests/test_m3_engine.py tests/test_stdio.py tests/test_synthetic_data.py \
  -q -p no:cacheprovider

# 判据 1（本仓）
cd <product-repo>
npm run build
node --test test/rework-evidence.test.js

# 判据 2
node bin/traceproof check rework-evidence --input samples/rework-evidence.json \
  --basis samples/rework-evidence-traces.json

# 判据 4（%TEMP% 副本）
npm run build && npm pack
tar -xzf dsh-prompt-polisher-0.2.0.tgz -C <unpack-dir>
ls <unpack-dir>/package/lib/traceproof/verbs/rework-evidence/data/
```