# session-replay · 会话回归取证

> 器官 slug `session-replay`，版本 `0.1.1`（迁自 target-map ④ 行；版本沿用旧仓的 `v0.1.1`）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这次会话里到底哪一段是 bug 修复、修前修后是什么」的主张，对到**同一份会话痕迹**上：

| check | 判定 |
|---|---|
| `episode` | 是否切出 bug-fix episode（用户报 bug → 失败信号 → 改文件 → 同一测试命令转通过）；可指定 `index` 与 `status` |
| `reconstruction` | 某路径的修复 diff 还原状态：`ok` / `partial` / `unresolved` / `no_before_image` / `absent` |
| `failure-signal` | 会话里是否出现失败证据（**数值退出码优先**；文本标记命中不算失败） |

**器官不做的事**：不跑 pytest（没有 RED/GREEN 双验证）、不生成落盘测试文件、不读日志文件、
不读时钟。会话记录由输入给出；「是否修好了」只能取证到「同一测试命令是否转为通过」。

## 2. 输入（subject）

```json
{
  "session": {
    "harness": "claude",
    "records": [
      {"type": "user", "sessionId": "s-demo", "timestamp": "…",
       "message": {"role": "user", "content": "bug: divide() raises on empty denominator"}},
      {"type": "assistant", "sessionId": "s-demo", "timestamp": "…",
       "message": {"content": [{"type": "tool_use", "id": "c1", "name": "Edit",
                                "input": {"file_path": "/demo/alpha/src/calc.py",
                                          "old_string": "    return a / b",
                                          "new_string": "    return a / b if b else 0"}}]}},
      {"type": "user", "sessionId": "s-demo", "timestamp": "…",
       "message": {"content": [{"type": "tool_result", "tool_use_id": "c1",
                                "content": [{"type": "text", "text": "ok"}]}]},
       "toolUseResult": {"filePath": "/demo/alpha/src/calc.py",
                         "originalFile": "def divide(a, b):\n    return a / b\n",
                         "structuredPatch": []}}
    ]
  },
  "repo": {"files": {"/demo/alpha/src/calc.py": "<基线内容>"}},
  "claims": [
    {"claim_id": "c1", "check": "episode", "asserted": "present",
     "status": "verified_by_run",
     "node": {"session_id": "s-s2r-1", "turn": 2, "tool_call_id": "call-s2r-2"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `session.harness` | 否 | `claude` / `codex`；缺省时按记录形态判别（`message` → claude，`payload` → codex），未知形态显式报错 |
| `session.records` | 是 | 已解析的 jsonl 行（**seq = 行号**，1-based） |
| `repo.files` | 是 | 路径 → 基线内容（还原 before 的兜底来源） |
| `claims[]` | 是 | `claim_id` 唯一；`reconstruction` 必须带 `path`；只有 `episode` 可带 `status` |

`claims[]` 允许字段：`claim_id` / `check` / `asserted` / `path` / `index` / `status` / `node`。

## 3. 规则（与旧仓 `episode.py` / `reconstruct.py` 对齐）

### 3.1 episode 切分

1. **起点**：`user_msg` 命中 bug 语义词（词表在 `data/session-replay-defaults.json`；ASCII 词按词边界，
   `debug` 不会命中 `bug`）。
2. **失败信号**：数值退出码优先（`exit_code != 0`）；无退出码时看 `is_error`，再看文本信号
   （`FAILED` / `AssertionError` / `Traceback` / `Exit code`）。
3. **修复动作**：失败之后出现写类工具（Claude `Edit`/`Write`/`MultiEdit`/`NotebookEdit`；
   Codex `apply_patch` / `file_change`）。
4. **终点**：**同一测试命令**（按 `call_id` 配对）转为通过 → `verified_by_run`；
   否则 `ended_without_pass`。
5. **丢弃**（逐条给 reason）：`no_failure_evidence` → `no_fix_action` → `docs_only` →
   `below_threshold`（权重与阈值 5 来自数据文件）。
6. 同一会话多个 bug → 各自成 episode，`episode_id = <session>#<首次修复 seq>`。

### 3.2 修复 diff 还原（三级降级）

| 证据 | status | confidence |
|---|---|---|
| Claude `structuredPatch`（有 hunk），上下文与 before 一致 | `ok` | `high` |
| Claude `old_string` 在 before 里**恰好出现一次** | `ok` | `high` |
| Codex `FileChange.unified_diff` 应用成功 | `ok` | `medium` |
| Codex `apply_patch` patch 应用成功 | `ok` | `medium` |
| 上下文对不上（基线漂移） | `partial` | `low` |
| `old_string` 多处命中且未 `replace_all` | `unresolved` | `none` |
| Write 新文件、没有 before 镜像 | `no_before_image` | `none` |

**before 只从日志（`originalFile`）或 `repo.files` 取**；两者都没有就**不猜**。
`partial` / `unresolved` 的 `before`/`after` 一律为 `null`（不把"差不多"当成"还原了"）。

## 4. 输出示例

```console
$ traceproof check session-replay --input samples/session-replay.json \
                                  --basis samples/session-replay-traces.json
traceproof :: session-replay 0.1.1 :: session-replay.json
[claim] episode-verified — 主张「episode=present」被会话痕迹支持 :: s-s2r-1#2#call-s2r-2
[claim] failure-signal — 主张「failure-signal=present」被会话痕迹支持 :: s-s2r-1#2#call-s2r-2
[claim] fix-reconstructed — 主张「reconstruction=ok」被会话痕迹支持 :: s-s2r-1#2#call-s2r-2
合计 3 条，阻断 0 条（claim=3 refuted=0 inconclusive=0）
# 退出码 0
```

证据（已脱敏；**不放原始用户文本与文件内容**，只放词表内的 bug 语义词、计数与摘要）：

```json
{
  "check": "reconstruction", "path": "/demo/alpha/src/calc.py",
  "computed": "ok", "comparison": "match",
  "reconstruction": {"path": "/demo/alpha/src/calc.py", "status": "ok",
                     "confidence": "high", "source": "claude_structured_patch",
                     "hunks": 1, "before_chars": 33, "after_chars": 45, "note": ""},
  "event_count": 7,
  "kind_counts": {"user_msg": 1, "tool_call": 3, "tool_result": 3},
  "episodes": [{"episode_id": "sess-demo-0009#5", "status": "verified_by_run", ...}]
}
```

## 5. 与旧仓的口径差异（逐条登记）

| # | 差异 | 原因 / 影响 |
|---|---|---|
| 1 | **不跑 pytest**：没有 RED/GREEN 双验证，也不生成落盘的测试文件 | 器官不能起子进程/写文件；`verified_by_run` 只由会话自身的测试命令结果判定。旧仓 5 个基准字段（`expect_red_green` / `expect_generated`）因此**不在本器官的判定面** |
| 2 | 生成器（`generate.py`，1102 行）未迁 | 它输出 pytest 代码并写盘；本仓器官只取证不产出工件。候选断言的字段（symbols / sections / reasons）不在账本里 |
| 3 | 数值口径从 `config/scoring.toml` 改为 `data/session-replay-defaults.json` | 本仓约定器官静态数据只放 `data/*.json`；词表/权重/文档后缀仍是单一来源 |
| 4 | 格式版本指纹表未做 | 旧仓对 Claude/Codex 的**版本键集**做白名单；本器官按容器键（`message` / `payload`）判别，未知形态显式报错。指纹表用于"新版本先核对字段"，属发布期纪律 |
| 5 | `bench` / `verify` / `manifest` 未迁 | 它们是"跑基准 / 跑临时副本验证 / 落 manifest"的编排层；traceproof 的账本是唯一输出，编排留给主流程 |

## 6. §7.3 四项无损判据（实测）

> 迁自 target-map ④ 行（旧仓 v0.1.1）。

**判据 1：旧仓判定层实跑 188 / 新仓实跑 209 / 过（209 ≥ 188）。**

> 计数口径（§3.0）：`node --test test/session-replay.test.js` → `ℹ tests 209`。
> 文件里**顶层** `test(` 字面量 59 条，其余 150 条由 9 个基准样本的 truth 字段矩阵、
> 还原记录逐项对账表与规则三态表生成。静态 grep 会低估，不能拿字面量当用例数。

| # | 判据 | 旧仓实测 | 本仓实测 | 结论 |
|---|---|---|---|---|
| 1 | 旧仓**判定层**实跑用例数（§3.0） | 判定层 **12 文件** → `pytest <文件…> -q` → **188 passed**，rc 0（静态 155；全量 355 passed 含脚手架） | 本器官测试 **209 passed**（`node --test test/session-replay.test.js`） | **过**（209 ≥ 188） |
| 2 | README 示例命令 rc 相同 | 旧仓 `bench` → **rc 0**（样本 10，检出率 10/10，误报 0） | `traceproof check session-replay --input samples/session-replay.json --basis samples/session-replay-traces.json` → **rc 0**（claim 3 / blocking 0） | **过**（同一批基准样本，同为「全通过」） |
| 3 | 测试文件数 / 函数数 | 判定层 **12** 文件 / **155** `def test_`（实跑 188） | **口径乙（2026-11-25 用户裁决）**：文件数按域计 → **1 文件**（容器数 ≠ 覆盖数）；函数数按条计 → `test(` 字面量 **78**（顶层 59 + 循环内调用）；用例 **209** | ⚠️ **waiver**：函数数 78 < 155（缺口 77）。用户 2026-11-25 批准；理由：用例数 209 ≥ 188（且 ≥ 155）已过，缺口由 9 个基准样本 truth 矩阵 / 还原记录对账表生成；残余风险：函数级断言粒度变粗。归档 `records/criterion-verdicts-20261125.md` |
| 4 | `data/` 进包 | 旧仓 `pip wheel`：**26 文件**；随包数值口径在 `resources/scoring.toml`（**4337 B**，1 条 resources） | `npm pack` → **129 文件 / 185581 B**；`lib/traceproof/verbs/session-replay/data/session-replay-defaults.json` **1045 B** | **过（命名替换）**：旧仓的 `resources/` 对应本仓的 `lib/.../data/`；两边都是"随包的唯一数值口径" |

### 6.1 脚手架测试处置表（§3.0 要求，逐文件）

判定层口径剔除的 11 个文件（合计 148 个静态用例）：

| 旧仓测试文件 | 静态用例 | 处置 |
|---|---:|---|
| `tests/test_bench.py` | 26 | **舍弃（不复刻评分器）**：旧仓 `bench` 是检出率/误报评分门；本仓用 9 个样本的 truth **逐字段对账**（事件/种类/工具/episode/还原 before-after）覆盖同一批语料，不产出评分 |
| `tests/test_check_release.py` | 5 | **舍弃**：发布门；打包面由 `npm pack`（判据 4）与 CI 覆盖，其余发布纪律不在器官 |
| `tests/test_cli_contract.py` | 16 | **由唯一入口契约接管**：`bin/traceproof` 的退出码契约 + 本器官 CLI 用例；旧 argparse 面不适用 |
| `tests/test_generate.py` | 30 | **舍弃（未迁）**：pytest 骨架生成器不在器官范围（器官不产出工件）；生成层的 `symbols/sections/reasons` 字段因此不在账本 |
| `tests/test_generate_cli.py` | 15 | **舍弃**：生成器 CLI；生成层未迁 + 唯一入口不暴露该子命令 |
| `tests/test_reconstruct_cli.py` | 12 | **部分接管**：还原的判定面（status/confidence/before/after/来源/hunk）由本器官测试覆盖；CLI 编排由唯一入口接管 |
| `tests/test_run_cli.py` | 9 | **舍弃**：旧仓 `run` 的端到端编排（生成 + 验证 + 落盘）；器官不跑 pytest、不写文件 |
| `tests/test_scan_cli.py` | 14 | **舍弃**：旧仓 `scan` 的日志发现 CLI；读文件层未迁（记录由输入给出） |
| `tests/test_smoke_coverage.py` | 4 | **舍弃**：冒烟覆盖门；产品级门，不在器官判定面 |
| `tests/test_stdio_guard.py` | 5 | **由内核出口接管**：器官不打印；stdout/stderr 只由 `bin/traceproof` 统一产出，其契约由内核测试与 CLI 用例覆盖 |
| `tests/test_verify_cli.py` | 12 | **舍弃（未迁）**：RED/GREEN 验证 CLI；器官不起子进程、不建临时副本，`verified_by_run` 只来自会话内测试命令结果 |

**判据 1 的旧仓实跑**：
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src py -3.12 -m pytest <判定层 12 文件…> -q -o addopts="" -p no:cacheprovider`
→ `188 passed in 18.63s`（静态 155）。全量跑为 `355 passed`。

**判据 4 的 TS 替换**：`pip wheel` 的 `package-data` 换成 `npm pack` 的 `files: ["lib"]` +
`resolveJsonModule` 复制 `src/**/data/*.json`；判据是"该器官的静态数据在发布件里非空"。

## 7. 不做的事

- 不读会话日志文件、不扫目录、不起 pytest、不写测试文件、不联网。
- 不把 `ended_without_pass` 说成"没修好"（只是**没有转为通过的证据**）。
- 不在证据里放原始用户文本、绝对路径或文件内容。