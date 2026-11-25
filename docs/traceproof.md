# traceproof · 内核契约（Stage 1）

> 本页是 `src/traceproof/` 的唯一说明处。契约字段、退出码、目录形状与
> `clauseproof` / `byteproof` / `speccalc` 共用一份 `SKELETON-SPEC`；本页只写
> **traceproof 自己的那一列**（取证账本 + 痕迹节点 + 脱敏前置）。

## 1. 这个产品回答什么

给定一组「主张」（claim）和一份会话痕迹，逐条判断它到底有没有被痕迹支持：
`claim`（有支撑）/ `refuted`（被痕迹推翻）/ `inconclusive`（痕迹不足以判定）。

它不做的事：不带自己的 CLI、不读时钟、不联网、不修改输入工件。

## 2. 唯一入口

```text
traceproof list                          # 列出器官（slug / 版本 / 摘要）
traceproof check <slug> --input <file>   # 跑一个器官
traceproof check <slug> --input -        # stdin
traceproof --version
```

可执行入口只有 `bin/traceproof` 一个（`package.json` 的 `bin` 只登记它）。
器官（verb）签名固定：

```ts
evaluate(subject: Record<string, unknown>, basis: Basis): Iterable<LedgerRecord>
```

## 3. 取证账本（本产品的 record 类型）

| 字段 | 含义 |
|---|---|
| `id` | 稳定键：`<claim_id>@<session>#<turn>#<tool_call>`（无节点为 `@-`） |
| `verdict` | `claim` / `refuted` / `inconclusive` |
| `message` | 人读结论；降级时必须写明缺失项 |
| `basis_ref` | `{session_id, turn, tool_call_id, quote}`；无节点为 `null` |
| `evidence` | 机器可读证据（**入账时已脱敏**） |

`refuted` 是唯一阻断级。

## 4. 四条内核约束（违反即退出码 3）

1. **无痕迹节点不下 `refuted`**：`basis_ref` 为空即 `ContractError`。
2. **节点不完整就降级**：缺 `turn` 或 `tool_call_id` -> 降级 `inconclusive`，
   `message` 追加「痕迹节点不完整：缺 …」；痕迹包自身缺版本 -> 直接契约违约。
3. **脱敏前置**：`evidence` 在 `makeRecord` 内部就被深拷贝 + 按键名脱敏，
   器官没有「先入库再打码」的通路（`MASK = "***"`）。
4. **输出确定性**：`--json` 无时间戳、无绝对路径、字段顺序固定；同输入两次运行字节一致。

## 5. 退出码

| 码 | 含义 | 本产品的触发点 |
|---|---|---|
| 0 | 无阻断性结论 | 全部 `claim` / `inconclusive` |
| 1 | 存在阻断性结论 | 至少一条 `refuted` |
| 2 | 输入不合法 | 输入文件缺失/非法 JSON/缺 `input_fields` 声明键 |
| 3 | 契约违约 | 无节点下 `refuted`、痕迹包版本缺失、节点缺失（`NodeMissing`）、器官不存在 |

## 6. 加一个器官

```text
src/traceproof/verbs/<slug>/index.ts   # register({slug, version, summary,
                                       #           input_fields, evaluate})
src/traceproof/verbs/index.ts          # 把目录名加进 BUILTIN_MODULES（显式清单）
test/<slug>.test.js                    # 该器官的无损测试
docs/<slug>.md                         # 输入 / 规则 / 输出示例
```

**显式清单而不是目录扫描**：扫描式加载会把「器官忘了登记」变成静默空跑。

## 7. 与 SKELETON-SPEC 的两处命名差异（有意为之）

| 差异 | 原因 |
|---|---|
| 依据模块叫 `core/trace-index.ts`（其余三产品叫 `basis`） | 本产品的依据是**痕迹索引**而非条文库；导出符号仍是 `Basis` / `NodeMissing` / `ref()`，契约面一致 |
| 账本类型叫 `LedgerRecord` | TypeScript 里 `Record` 是内置工具类型，直接占用会污染类型面 |

## 8. 示例（Stage 1，器官尚未迁入）

```console
$ traceproof list
（未注册任何器官）

$ traceproof check no-such --input samples/anything.json
VerbMissing: 未注册的器官：no-such          # 退出码 3
```

器官迁入后，本页与 README 的「器官表」按 `_workspace/target-map-20261125.tsv`
的 ④traceproof 行逐个补齐（每个器官一页 `docs/<slug>.md`）。

## 9. 防回退

`test/traceproof-contract.test.js` 的 25 条用例锁住 §4 的四条约束与 §5 的四个退出码；
其中「脱敏前置」这条是**结构性**验证：证据里的敏感键在 `makeRecord` 返回时就已是 `MASK`，
并且序列化后的账本里搜不到原始值。