# pipeline-run · 流水线运行取证

> 器官 slug `pipeline-run`，版本 `0.2.2`（迁自 target-map ④ 行；版本沿用源仓 `package.json` 的 `0.2.2`）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这份流水线定义能不能编译、这次运行到底怎么结算」的主张，对到**同一份定义 / 运行记录**上：

| check | asserted 闭集 | 判据 |
|---|---|---|
| `definition` | `valid` / `invalid` | 定义形状校验（字段闭集 / id 语法 / prompts / options…）；可附 `error_paths` 断言具体违规位置 |
| `compile` | `compiles` / `rejected` | 形状 -> IR 语义（依赖 / 模板 / skip 引用 / outputSchema 子集 / M2 gates）-> 冻结格式脚本；可附 `error_code` / `order` / `total_agent_calls` |
| `preflight` | `ok` / `missing-agent-options` / `missing-output-schema` | 运行前能力预检：按 IR 的 `needsAgentOptions` / `needsOutputSchema` 对照声明的 provider 能力 |
| `run` | `completed` / `failed` / `cancelled` / `interrupted` / `running` | 折叠 `pipeline-run/*` 事件后的运行状态 |
| `node` | `pending` / `running` / `completed` / `failed` / `cancelled` / `interrupted` / `absent` | 节点状态（最后一条 seq 的成员说了算）；可附 `attempts` |
| `form` | `roundtrip` / `lossy` | 定义 -> 编辑器表单 -> 定义的双向无损 + 重新校验 |

**器官不做的事**：不跑 workflow 引擎、不起子进程、不读 `.dsh/pipelines/`、不读技能注册表、
不读时钟、不渲染运行卡。定义与运行记录都由输入给出；技能节点必须由 `pipeline.skills`
提供**已渲染**的技能块，缺失即 `inconclusive`（不猜内容）。

## 2. 输入（subject）

```json
{
  "pipeline": {
    "definition": {
      "name": "three-node-two-models",
      "description": "…",
      "nodes": [
        {"id": "outline", "label": "Outline", "prompts": ["…{{input}}…"],
         "model": {"provider": "deepseek", "model": "deepseek-chat"}}
      ]
    },
    "skills": {"draft": ["<已渲染的技能块>"]},
    "capabilities": {"agentOptions": true, "outputSchema": true},
    "provider": "spawn",
    "run": {
      "interrupted": false,
      "events": [
        {"type": "pipeline-run/run-start",
         "data": {"runId": "run-1", "name": "…",
                  "nodes": [{"id": "outline", "label": "Outline", "provider": "deepseek", "model": "deepseek-chat"}],
                  "startedAt": 1000}},
        {"type": "pipeline-run/agent-start", "data": {"runId": "run-1", "seq": 1, "label": "Outline",
                                                     "phase": "Outline", "childId": "child-1", "startedAt": 1100}},
        {"type": "pipeline-run/agent-end", "data": {"runId": "run-1", "seq": 1, "outcome": "completed",
                                                    "durationMs": 1200, "usage": {"inputTokens": 120, "outputTokens": 60}}},
        {"type": "pipeline-run/run-end", "data": {"runId": "run-1", "stopReason": "completed", "durationMs": 4000}}
      ]
    }
  },
  "claims": [
    {"claim_id": "compile-three-nodes", "check": "compile", "asserted": "compiles",
     "order": ["outline", "review", "write"], "total_agent_calls": 3,
     "node": {"session_id": "s-pipe-1", "turn": 2, "tool_call_id": "call-pipe-2"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `pipeline` | 是 | 同一份工件；以下块按主张按需提供 |
| `pipeline.definition` | `definition` / `compile` / `preflight` / `form` 主张必需 | 旧仓 `PipelineDef` 原样（JSON） |
| `pipeline.skills` | 技能节点必需 | `nodeId -> [已渲染技能块]`；条数必须等于该节点 `skills[]` 的长度 |
| `pipeline.capabilities` | `preflight` 主张必需 | `{agentOptions: bool, outputSchema: bool}` |
| `pipeline.provider` | 否 | 预检错误里点名的 provider，默认 `spawn` |
| `pipeline.run` | `run` / `node` 主张必需 | `{events: [...], interrupted?: bool}`；`events[0]` 必须是 `pipeline-run/run-start` |
| `claims[]` | 是 | `claim_id` 唯一；`check` 闭集；`node` 可选（痕迹节点） |

`claims[]` 允许字段（按 check）：全局 `claim_id` / `check` / `asserted` / `node`；
`definition` 加 `error_paths`；`compile` 加 `error_code` / `order` / `total_agent_calls`；
`node` 加 `node_id`（必填）/ `attempts`。其余字段一律契约错误。

## 3. 规则（与旧仓判定层对齐）

### 3.1 定义形状（`schema.ts`）

1. 字段闭集：顶层 `name / description / nodes / options`，节点 `id / label / prompts / model /
   skills / tools / dependsOn / outputSchema / failurePolicy / retry`；未知字段拒绝。
2. `name` / 节点 `id` 用源仓 id 语法 `^[A-Za-z0-9][A-Za-z0-9_-]*$`；`input` / `prev` 形状合法
   （保留字是 IR 语义层拒绝）。
3. 一次收集全部违规，不 fail-fast；path 语法与旧仓一致（`nodes[2].prompts[0]`）。

### 3.2 IR 语义（`ir.ts`）

1. 重复 id / 保留 id / 未知依赖 / 自依赖 / 依赖环 / 未知模板变量 / 自引用 / skip 输出引用
   → 各自的冻结错误码。
2. 显式 `dependsOn` 覆盖隐式串接；模板引用 `{{var}}` 也产生依赖边；Kahn + 定义序 tie-break。
3. `{{prev}}` 只能出现在第二条及之后的 prompt；首条出现即拒绝。
4. `outputSchema` 必须在引擎受控子集内（对象根；`type/oneOf/properties/required/
   additionalProperties/items/enum/const` + 注解）；`format` 等关键字拒绝，不静默忽略。
5. M2 gates 原样保留：`tools`、`model.reasoningEffort`、`options.maxAgentsPerNode`
   → `IR_UNSUPPORTED_FEATURE`。

### 3.3 编译（`compiler.ts`，冻结格式）

1. 两行头（版本 / 节点与 agent 调用上界 / 每节点策略）→ `const out = {}` → 拓扑序节点 → `return { nodes: out };`。
2. `agent()` 选项字段序冻结：`label` / `provider` / `model` / `schema`；多条 prompt 的 label 带 ` #k`。
3. 失败策略编译进脚本：abort / skip / retry 三种形状；模板插值 JSON 安全
   （静态段 JSON 转义；outputSchema 节点引用包 `JSON.stringify`）。
4. 无 `eval` / `Function`；脚本是普通字符串。

### 3.4 表单（`form-model.ts`）

1. 定义 <-> 扁平表单往返逐字段一致；`model: {}` / `options: {}` 归一化为缺省；
   `dependsOn` 缺省与显式 `[]` 区分保留；gated 字段原样往返。
2. 规范字节 = `JSON.stringify(def, null, 2) + "\n"`（与旧仓 `saveDef` 一致）。

### 3.5 运行事件折叠（`run-events.ts`）

1. `run-start` 建立计划节点；`agent-start` 追加成员（按 `seq`），`agent-end` 回填 outcome / 耗时 / usage。
2. 节点状态：运行中优先；中断后未完成成员记 interrupted；否则按**最后一条 seq**（重试恢复 = completed，
   最后失败 = failed）。
3. 未知事件类型忽略（与旧仓 `foldUpdate` 一致）；`run-start` 不是第一条 → 契约错误。
4. 无 `run-end` 且 `interrupted=false` → running；`interrupted=true` → interrupted。
5. 成本：按声明路由（`provider|model`，null model = 会话默认）分组，失败尝试计入，
   token 桶在全部成员缺省时保持缺省。

### 3.6 能力预检（`preflight`）

按 IR 的 `needsAgentOptions` / `needsOutputSchema` 与 `pipeline.capabilities` 对照；
agentOptions 缺失优先（与旧仓 `assertCaps` 的检查顺序一致）。定义不可编译 / 技能块缺失 → `inconclusive`。

## 4. 输出示例

```console
$ node bin/traceproof check pipeline-run --input samples/pipeline-run.json \
                                         --basis samples/pipeline-run-traces.json
traceproof :: pipeline-run 0.2.2 :: pipeline-run.json
[claim] compile-three-nodes — 主张「compile=compiles」被编译判据支持；编译通过：3 个节点 / 3 次 agent 调用上界 / 脚本 882bfd326941… :: s-pipe-1#2#call-pipe-2
[claim] definition-valid — 主张「definition=valid」被定义形状判据支持；定义通过形状校验 :: 无节点
[claim] form-roundtrip — 主张「form=roundtrip」被表单往返判据支持；定义经 form -> def 往返后逐字段一致，且重新通过形状校验 :: 无节点
[claim] preflight-ok — 主张「preflight=ok」被能力预检支持；能力预检通过（provider "spawn"） :: 无节点
[claim] run-completed — 主张「run=completed」被运行记录支持；运行记录结算为 completed（stopReason=completed） :: s-pipe-1#2#call-pipe-2
[claim] write-completed — 主张「node=completed」被运行记录（节点级）支持；节点 "write" 结算为 completed（attempts=1） :: s-pipe-1#2#call-pipe-2
合计 6 条，阻断 0 条（claim=6 refuted=0 inconclusive=0）
# 退出码 0
```

`--json` 的账本行（节选，evidence 已脱敏）：

```json
{
  "claim_id": "compile-three-nodes",
  "verdict": "claim",
  "basis_ref": {"session_id": "s-pipe-1", "turn": 2, "tool_call_id": "call-pipe-2", "quote": "…"},
  "evidence": {
    "check": "compile", "asserted": "compiles", "computed": "compiles",
    "comparison": "match", "order": ["outline", "review", "write"],
    "total_agent_calls": 3, "script_sha256": "…", "script_lines": 32, "script_chars": 1254
  }
}
```

主张不符且**没有挂痕迹节点**时按内核契约降级 `inconclusive`（不能下 `refuted`）：

```text
[inconclusive] run-completed — 判据与主张不符（重算 failed ≠ 主张 completed），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive；运行状态不符：…
```

## 5. 与旧仓的口径差异（逐条登记）

| # | 差异 | 原因 / 影响 |
|---|---|---|
| 1 | **JS 源码（旧仓以 TS 编写、构建到 JS）→ 本仓 TS 重写**，只迁判定层 | 插件半（`entry` / `web` / `store` / `runner` / `run-recorder` / `client`）是宿主接线与 GUI，器官不得自带 CLI / 文件 IO / 时钟。运行事件折叠是纯函数，完整迁入 |
| 2 | 消息从 `locale/en.json` + `locale/zh.json` 改为**内联中文** | 器官不得读文件 / 自带配置；**错误码与 path 语法不变**，测试按 code 断言。旧仓的 en 文案不迁 |
| 3 | JSON Schema 子集校验**本地重实现**（不依赖 `@deepseek-ai/dsh-tools`） | 器官不新增运行时依赖；对象根 + 受控关键字 + `format` 拒绝的语义已由 `ir-output-schema-subset` 固件覆盖。极端注解值的 violation 文案可能与 dsh-tools 逐字不同，**结论（接受/拒绝）一致** |
| 4 | **技能块由输入提供**（`pipeline.skills`），不读 `ctx.skills` | 器官不读注册表；缺块 / 条数不符 → `inconclusive`，不伪造技能内容。旧仓 `renderSkillContent` 的渲染在宿主侧完成 |
| 5 | **记录器未迁**：器官消费已记录的事件 | `run-recorder` 需要宿主时钟与 `session.append`；器官不读时钟。折叠/投影（`run-events`）全量迁入 |
| 6 | **存储未迁**：定义从输入读取 | `store` 是 `.dsh/pipelines/*.json` 的 fs seam；器官不读文件。唯一入口负责读入 |
| 7 | **Web / 表单 UI 未迁**：只保留表单模型的纯往返 | `form` 主张验证定义 <-> 表单无损；设置页/运行卡属 GUI |
| 8 | **`pipeline` 字段的形状是器官自己的输入契约** | 旧仓的 `PipelineDef` 原样嵌在 `pipeline.definition`；运行记录嵌在 `pipeline.run.events`。claim 词汇（`definition/compile/preflight/run/node/form`）是本产品的取证面，不是旧仓 API |
| 9 | 旧仓 README 的 `/pipeline run` 是会话内命令，**没有进程退出码** | 判据 2 的可执行示例取源仓 `node scripts/bench.js`（B1–B4 全绿，rc 0）；新侧同语义样例 rc 0。不照抄 `cordis.patch.yml` |

## 6. §7.3 四项无损判据（实测）

> 迁自 target-map ④ 行（旧仓 `0.2.2`）。旧仓判定层 14 文件实跑 **86 passed**。

| # | 判据 | 旧仓实测 | 本仓实测 | 结论 |
|---|---|---|---|---|
| 1 | 旧仓**判定层**实跑用例数（D1 + D18） | 判定层 **14 文件** → `node --test <…>` → **86 passed / 0 failed**，rc 0（全部用例均为顶层 `test()`，无循环子测试） | 本器官测试 **148 passed**（`node --test test/pipeline-run.test.js`） | **过**（148 ≥ 86） |
| 2 | README 示例命令 rc 相同 | 旧仓 README 无 CLI 示例（`/pipeline run` 是会话内命令，无进程 rc）；以源仓可执行示例 `node scripts/bench.js` → **rc 0**（`ALL GREEN`：B1 7/7 快照、B2 22/22 矩阵、B3 4/4、B4 6/6） | `traceproof check pipeline-run --input samples/pipeline-run.json --basis samples/pipeline-run-traces.json` → **rc 0**（claim 6 / blocking 0） | **过**（同为「全通过」；样例覆盖定义/编译/表单/预检/运行/节点六条主张） |
| 3 | 用例数 / 函数数（口径乙） | **14** 文件 / **86** `test(` 调用 | **口径乙**：文件数按域计 → **1 文件**（容器数 ≠ 覆盖数）；函数数按条计 → **148** `test(` 调用；用例 **148** | **过**（用例 148 ≥ 86；函数 148 ≥ 86） |
| 4 | `data/` 进包（`npm pack`） | 旧仓 `files` 只含 `lib/cordis.patch.yml/locale/data`；运行时无「器官 data」概念（locale 走文件读） | `%TEMP%` 副本（`E:\zcode_data\temp\tmp.qUkF8LS5h4`）构建后 `npm pack` → **148 条目 / 218189 B**；`package/lib/traceproof/verbs/pipeline-run/data/pipeline-run-defaults.json` **1585 B**；解包后 `list` 显示 `pipeline-run 0.2.2`、`check` rc 0 | **过**（器官静态数据随包发布；解包可运行） |

> 计数口径：新侧 `grep -c '^test(' test/pipeline-run.test.js` = **148**（只数顶层调用，不把文档注释里的
> 字样算进函数数）。`node --test` 的 `ℹ tests 148` 与函数数一致（本文件没有循环子测试）。

### 6.1 脚手架测试处置表（D1 + D18 逐文件）

**D1/D18 剔除的 4 个文件（23 个静态用例，不计入 X）：**

| 旧仓测试文件 | 用例 | 处置 |
|---|---:|---|
| `test/bench.test.js` | 4 | **D1 `bench` 剔出**。评分器 B1–B4 不迁；但 B1 的 7 份冻结快照与 B2 的 15 份失败固件作为本器官**只读测试夹具**迁入（`test/fixtures/pipeline-run/`），7/7 逐字节与 22/22 判定矩阵在本器官测试里重放 |
| `test/desensitize.test.js` | 1 | **D1 `desensit` 剔出**。旧仓发布前脱敏审计（工作树 + 全历史，`scripts/release-audit.mjs`）；本产品由入口的脱敏前置（`core/redact.ts`）与产品级审计承担，器官不迁 |
| `test/self-report.test.js` | 4 | **D18 `report` 剔出**。README 自述测试数门（旧仓统计自身 `test(` 声明）；属产品发布纪律，不属器官判定面 |
| `test/web.test.js` | 14 | **D18 `web` 剔出**。`/api/dsh-pipeline/*` 路由 + 设置区/运行入口；器官不得自带 CLI / 输出排版 / 文件 IO |

**D1/D18 保留、但器官**不复刻**的 10 个文件（仍如实计入 X，不删不改）：**

| 旧仓测试文件 | 用例 | 处置 |
|---|---:|---|
| `test/schema.test.js` | 8 | **已迁**：`schema.ts` + `definition` 主张 |
| `test/ir.test.js` | 14 | **已迁**：`ir.ts` + `compile` 主张；错误码矩阵与模板边界逐条锁 |
| `test/form-model.test.js` | 9 | **已迁**：`form-model.ts` + `form` 主张 |
| `test/run-events.test.js` | 8 | **已迁**：`run-events.ts` + `run` / `node` 主张 |
| `test/runner.test.js` | 7 | **部分迁**：`assertCaps` 纯判定 → `preflight` 主张；引擎生命周期 / AbortSignal / 错误包装属宿主接线，不迁（本仓产品级 runner 门） |
| `test/run-recorder.test.js` | 6 | **不迁**：宿主时钟 + `session.append`；折叠逻辑已由 `run-events` 覆盖 |
| `test/store.test.js` | 6 | **不迁**：`.dsh/pipelines` 文件 IO；器官不得读文件 |
| `test/real-engine.test.js` | 4 | **不迁**：真实 PTC 引擎 / 沙箱 / 子进程；器官不跑引擎 |
| `test/session-integration.test.js` | 1 | **不迁**：真实 `@deepseek-ai/dsh-session` 持久日志重建；宿主接线 |
| `test/entry.test.js` | 11 | **不迁**：`/pipeline` 命令 + `pipeline` 工具 + web 子插件注册；唯一入口只有 `list` / `check` |
| `test/hello.test.js` | 5 | **不迁**：M0 smoke tool / 插件契约；产品级 |
| `test/compat.test.js` | 5 | **不迁**：`engines.dsh` / peer 兼容门；产品打包身份与 CI |
| `test/eol.test.js` | 1 | **不迁**：旧仓 fixture 的 LF 守卫；本器官快照副本按 LF 保存（测试按字节比较） |
| `test/client-bundle.test.js` | 1 | **不迁**：GUI bundle smoke（`window.__ModuleLoader__`）；本仓 `test/client-bundle.test.js` 承担 |

> 保留文件合计 **86** 个 `test(` 调用，与实跑 passed 一致（本仓旧层没有循环子测试）。
> 「已迁」指判定逻辑可在器官里找到；「部分迁 / 不迁」的文件仍计入 X，**没有为了达标而改 D1**。

### 6.2 测试夹具来源

`test/fixtures/pipeline-run/` 是旧仓 `data/{pipelines,snapshots,invalid}` 的**只读拷贝**：

- `pipelines/`：7 份有效定义（JSON）；
- `snapshots/`：7 份冻结编译快照，以 `.js.txt` 保存（`node --test` 会把 `test/` 下的 `.js`
  当测试文件执行；扩展名改动只影响存放，测试读取时逐字节比较）；
- `invalid/`：15 份失败固件 + `index.json`（文件 → 期望错误码）。

## 7. 不做的事

- 不跑 workflow 引擎、不跑 `agent()`、不跑 bench 评分器。
- 不读 `.dsh/pipelines/`、不读技能注册表 / locale 文件 / 环境变量。
- 不读时钟：运行耗时 / token 都是输入里已经记录的事实。
- 不渲染运行卡 / Markdown / 报告；输出只由唯一入口排版。
- 不把「技能块缺失」「定义不可编译」读成「编译失败」——前者是 `inconclusive`，后者才是 `rejected`。