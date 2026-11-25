# agent-conflict · 多 agent 并行冲突取证

> 器官 slug `agent-conflict`，版本 `0.0.4`（迁自 target-map ④ 行；版本沿用旧仓的 `v0.0.4`）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

多个 agent 并行改同一个仓库时，冲突往往在合并那一刻才暴露。本器官把「这几个 agent 会/不会撞车」
的主张，对到**同一份判据**上并按三级粒度给证据：

| 粒度 | 判据 |
|---|---|
| `file` | 同一 `path` 被两个**不同工作区**的会话改过 |
| `block` | 痕迹里的 `git merge-tree` 对该工作区对报冲突，且冲突路径含本 `path` |
| `symbol` | 两侧改动落在同一 Python 符号，或落在相邻符号（行间距 ≤ `adjacent_tolerance`） |

主张（`claims[]`）：

| check | asserted 闭集 | 含义 |
|---|---|---|
| `conflict` | `none` / `conflict` | 该路径上是否有一组跨工作区同改 |
| `block` | `none` / `conflict` / `undecidable` | 无副作用试合并是否在该路径上冲突 |
| `symbol-relation` | `same` / `adjacent` / `different` / `cross_file` / `unavailable` / `undecidable` | 两个会话在同一路径上的符号关系 |

**器官不跑 git 子进程**：区块级判定只消费痕迹里已经发生过的 `merge-tree` 结果。
没有这份证据 → `inconclusive` 并写明缺 `merge-tree(a, b)`；**不把「没查」读成「不冲突」**。

## 2. 输入（subject）

```json
{
  "repo": {"files": {"src/alpha.py": "<基线内容>"}},
  "sessions": [
    {"id": "sess-radar-0003", "workspace": "ws-1", "derived_from": null,
     "writes": [{"path": "src/alpha.py", "kind": "edit", "ranges": [[2, 2]]}]},
    {"id": "sess-radar-0004", "workspace": "ws-2", "derived_from": null,
     "writes": [{"path": "src/alpha.py", "kind": "edit", "ranges": [[9, 9]]}]}
  ],
  "merge_trees": [{"a": "ws-1", "b": "ws-2", "status": "ok", "paths": []}],
  "claims": [
    {"claim_id": "same-file-symbol", "check": "conflict", "path": "src/alpha.py",
     "asserted": "conflict", "node": {"session_id": "s-radar-1", "turn": 4, "tool_call_id": "call-radar-4"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `repo.files` | 是 | 路径 → 基线内容（符号级要用；缺内容 → `approximate`，只给文件级） |
| `sessions[]` | 是 | `id` / `workspace` / `derived_from`（同一 parent 派生的 subagent **整对不产出**）/ `writes[]` |
| `writes[].ranges` | 是 | 1-based 闭区间列表（`[start, end]`，`end >= start >= 1`） |
| `merge_trees[]` | 否 | `{a, b, status: conflict\|ok\|error, paths[]}`；缺省 → 区块级不可判定 |
| `claims[]` | 是 | `claim_id` 唯一；`workspace_a/b`（block 可用）、`session_a/b`（symbol-relation 必填） |

## 3. 规则（与旧仓 `detect.py` 对齐）

1. **只对跨工作区**：同一工作区的两个会话不算「多 agent 并行」。
2. **subagent 去重**：`derived_from` 非空且两侧相同 → 整对不产出（"自己和自己"不是冲突）。
3. **粒度集合精确匹配**：一条记录 `levels` 可同时含 `file` / `block` / `symbol`；
   `level` 只用于排序与严重度展示，不用于匹配。
4. **符号级用限定名**：嵌套 `Outer.Inner.gamma`；两侧触及符号有交集 → `same`；
   否则各自最内层符号 + 行间距 ≤ 容差 → `adjacent`；否则不升格。
5. **降级纪律**：`merge-tree` 缺失 / `status=error` → `degraded` 且只给文件级；
   非 Python 或缺基线 → `approximate` 且**不出现**符号结论（不报空集合冒充"无符号命中"）。
6. **严重度取自数据文件**：`same_symbol=50` / `same_file_diff_symbol=30` /
   `adjacent_lines=20` / `file_only=10`（`data/agent-conflict-defaults.json`，旧仓 `config/radar.toml` 的单一来源）。
7. **确定性**：会话、路径、区间全部排序后再产记录；同一输入两次运行输出一致。

## 4. 输出示例

```console
$ traceproof check agent-conflict --input samples/agent-conflict.json \
                                  --basis samples/agent-conflict-traces.json
traceproof :: agent-conflict 0.0.4 :: agent-conflict.json
[claim] no-block-conflict — 主张「block=none」被冲突判据支持 :: s-radar-1#4#call-radar-4
[claim] same-file-symbol — 主张「conflict=conflict」被冲突判据支持 :: s-radar-1#4#call-radar-4
[claim] same-symbol — 主张「symbol-relation=same」被冲突判据支持 :: s-radar-1#4#call-radar-4
合计 3 条，阻断 0 条（claim=3 refuted=0 inconclusive=0）
# 退出码 0
```

账本行里的证据（已脱敏）：

```json
{
  "check": "conflict", "path": "src/alpha.py", "computed": "conflict",
  "conflicts": [{
    "levels": ["file", "symbol"], "level": "symbol",
    "workspace_a": "ws-1", "workspace_b": "ws-2",
    "symbols": ["f"], "line_ranges": [[2, 2], [9, 9]],
    "severity": 50, "severity_key": "same_symbol",
    "degraded": false, "approximate": false
  }],
  "comparison": "match"
}
```

缺 `merge-tree` 时 `block` 主张落 `inconclusive`，退出码 0：

```text
[inconclusive] no-block-conflict — 痕迹不足以判定：痕迹里没有 ws-1 × ws-2 的 merge-tree 结果：区块级不能判；缺失项：merge-tree(ws-1, ws-2)
```

## 5. 与旧仓的口径差异（逐条登记）

| # | 差异 | 原因 / 影响 |
|---|---|---|
| 1 | **符号区间用缩进扫描**，不调 Python `ast` | 器官不能起子进程/读文件；基准矩阵的 7 个场景逐字段一致（`levels` / 符号名 / 关系）。复杂语法（多行字符串里的 `def` 字样）可能比 `ast` 粗——已在「未解问题」登记 |
| 2 | **区块级不跑 `git merge-tree`**，只消费痕迹里的结果 | 器官只做取证，不执行写对象库的命令；缺证据 → `inconclusive`，不猜 |
| 3 | `discover` / `intent` / `report` / `bench` / 通知**未迁** | 它们分别是"发现会话""解析写入意图""渲染报告""跑基准"；traceproof 的时间线由输入给出，渲染只在唯一入口。本器官只保留 **detect** 的判定面 |
| 4 | 配置从 TOML 改为 `data/agent-conflict-defaults.json` | 本仓约定器官静态数据只放 `data/*.json`；数值仍是单一来源（4 个严重度 + 容差 + 最小重叠行数） |
| 5 | 产物形态改为账本行 | 旧仓 `conflicts.json` 的字段（levels/severity/sessions…）保留在 `evidence` 里；不再自带 CLI 参数 |

## 6. §7.3 四项无损判据（实测）

> 迁自 target-map ④ 行（旧仓 v0.0.4）。

**判据 1：旧仓判定层实跑 264 / 新仓实跑 428 / 过（428 ≥ 264）。**

> 计数口径（§3.0）：`node --test test/agent-conflict.test.js` → `ℹ tests 428`。
> 文件里**顶层** `test(` 字面量 92 条，其余 336 条由 7 个基准场景的 truth 字段矩阵、
> 符号/区间判据表、检测输入表、规则三态表、主张 × 判据矩阵（§11）、
> **场景 × asserted 闭集全交叉（§16，77 条）**、输入校验边界表（§14）与检测/归一化边界（§17–§18）生成。
> 静态 grep 会低估，不能拿字面量当用例数。

| # | 判据 | 旧仓实测 | 本仓实测 | 结论 |
|---|---|---|---|---|
| 1 | 旧仓**判定层**实跑用例数（§3.0） | 判定层 **12 文件** → `pytest <文件…> -q` → **264 passed / 1 skipped**，rc 0（静态 228；全量 398 passed / 1 skipped 含脚手架） | 本器官测试 **428 passed**（`node --test test/agent-conflict.test.js`） | **过**（428 ≥ 264） |
| 2 | README 示例命令 rc 相同 | 旧仓 `bench` → **rc 0**（15 场景 / 174 检查全过） | `traceproof check agent-conflict --input samples/agent-conflict.json --basis samples/agent-conflict-traces.json` → **rc 0**（claim 3 / blocking 0） | **过**（同一个基准场景，同为「全通过」） |
| 3 | 测试文件数 / 函数数 | 判定层 **12** 文件 / **228** `def test_`（实跑 264） | **1** 文件 / **428** 用例 | 用例数**过**（428 ≥ 264，也 ≥ 228）；文件数**不可对齐**（布局规定单文件）→ 未解问题 |
| 4 | `data/` 进包 | 旧仓 `pip wheel`：**25 文件、无 `data/` 目录** | `npm pack` → **129 文件 / 185581 B**；`lib/traceproof/verbs/agent-conflict/data/agent-conflict-defaults.json` **504 B** | 旧仓**没有** `data/` 可对账（判据不适用）；本仓新增的单一数值来源**已进发布件** |

### 6.1 脚手架测试处置表（§3.0 要求，逐文件）

判定层口径剔除的 8 个文件（合计 127 个静态用例）：

| 旧仓测试文件 | 静态用例 | 处置 |
|---|---:|---|
| `tests/test_bench.py` | 26 | **舍弃（不复刻评分器）**：旧仓 `bench` 是发布前评分门（逐场景 期望/实际/判定 + 覆盖度门槛），不是 verb 判定面。本仓用 7 个场景的 truth **逐字段对账**覆盖同一批几何，但不产出评分与 `last_run.json` |
| `tests/test_bench_matrix.py` | 19 | **舍弃**：守基准矩阵清单/覆盖度完整性；矩阵与评分器都未迁，本仓只保留 truth 作为测试夹具 |
| `tests/test_bench_rng.py` | 8 | **舍弃**：守基准生成器（`bench/gen.py`）的随机源；生成器未迁 |
| `tests/test_cli_contract.py` | 25 | **由唯一入口契约接管**：`bin/traceproof` 的 `test/traceproof-contract.test.js` 锁退出码 0/1/2/3 + `test/agent-conflict.test.js` 的 3 条 CLI 用例；旧 argparse 面不适用 |
| `tests/test_encoding_guard.py` | 9 | **舍弃**：仓库编码守门（换行/编码归一）；本仓由脱敏审计与 CI 承担，属产品级门 |
| `tests/test_release_gate.py` | 19 | **舍弃**：发布终态门（tag / 资产 / sha256）；本仓发布由 CI 与 `npm pack`（判据 4）覆盖打包面，其余发布纪律不在器官 |
| `tests/test_scan_cli.py` | 12 | **舍弃**：旧仓 `scan` 的目录/会话发现 CLI；扫描层未迁（时间线由输入给出），器官无扫描入口 |
| `tests/test_stage_guard.py` | 9 | **舍弃**：阶段表/里程碑守门；器官没有"阶段"概念，属产品级流程门 |

**判据 1 的旧仓实跑**：
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src py -3.12 -m pytest <判定层 12 文件…> -q -o addopts="" -p no:cacheprovider`
→ `264 passed, 1 skipped in 96.60s`（静态 228）。全量跑为 `398 passed, 1 skipped`。

**判据 4 的说明**：旧仓把数值放在仓库级 `config/radar.toml`（**不进 wheel**，运行时从源码树读）。
本仓按 SKELETON-SPEC 把器官静态数据放进 `data/*.json` 并随包发布——这是**增强**，不是无损对齐；
「旧包里的 data 必须仍在」在旧仓为空集，因此不存在丢失。

### 6.2 已实测的归一化边界（待与旧仓核对，未改代码）

| 现象 | 当前行为 | 影响 |
|---|---|---|
| `writes[].path` 带首尾空白 | **不 trim**（`sessions[].id/workspace` 与 `claim.path` 都 trim） | 空白写入路径与主张路径就匹配不上 → `conflict=none`，静默漏报 |
| `merge_trees[].a/b` 带首尾空白 | **不 trim** | 与已 trim 的 `sessions[].workspace` 对不上 → `block` 落 `undecidable` |
| `derived_from` 为纯空白 | trim 成 `''`（不是 `null`），两侧同为 `''` 时**仍按「同一 parent」整对抑制** | 缺失的 parent id 被当成共享 parent，可能吞掉真实冲突 |

测试侧只锁了有效归一（session id / workspace / claim 路径与 `derived_from` 的正常 trim），
上述三条按「未解问题」上报，未写成断言、也未改器官代码。

## 7. 不做的事

- 不读会话日志文件、不扫工作区、不跑 git（时间线与试合并结果由输入提供）。
- 不渲染 Markdown、不打印、不落盘。
- 不把 `degraded` / `approximate` 当成「无冲突」；`undetermined` 与 `conflicts` 分开。