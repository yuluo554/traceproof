# pattern-evidence · 界面可疑模式取证

> 器官 slug `pattern-evidence`，版本 `0.2.0`（迁自 target-map ④ 行；版本沿用源仓 `package.json`
> 的 `0.2.0`，不随本产品升版）。规则包版本 `0.1.0`（源仓规则包原样）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这一页在给定规则包下会产出哪些可疑模式、哪些候选被证据门禁丢掉」的主张，逐条对到
**同一份归一化页面模型**的确定性重算：

| check | asserted 闭集 | 判据 |
|---|---|---|
| `rule` | `reported` / `absent` / `suppressed` / `missing-evidence` | 某 `rule_id` 在某个 `locator` 上是产出 finding、完全没命中、被中和项抑制，还是证据不足被丢弃；可附 `snippet` / `snippet_truncated` / `evidence`（证据 kind 列表）/ `finding_id` / `missing_evidence` |
| `count` | 十进制数字 | `of=findings` 或 `of=rejected` 的条数；`rejected` 可附 `reason` 过滤（`missing_evidence` / `suppressed` / `duplicate_locator`） |
| `order` | `exact` / `prefix` | 账本顺序（severity 降序 → DOM 序）的 `rule_ids`；可附 `finding_ids`（`F-01…`） |
| `ruleset` | `valid` / `invalid` | 规则包校验；`invalid` 时可附 `error_terms` 要求逐项出现在校验错误里 |
| `site` | `enabled` / `disabled` | 站点黑白名单闸门；可附 `url` / `settings` / `reason`（期望的闸门原因） |
| `coverage` | `complete` / `truncated` | 扫描完整性；可附 `node_count` |

**器官不做的事**：不碰 DOM、不启动浏览器、不读文件 / 环境变量 / 时钟、不联网、不导出 Markdown /
JSON 证据包、不渲染侧边栏。页面模型由输入提供；证据只经 `makeRecord()` 入账（内核在入账时脱敏）。

## 2. 输入（subject）

```json
{
  "page": {
    "url": "https://example.invalid/checkout",
    "scanned_at": "2026-10-18T00:00:00.000Z",
    "elapsed_ms": 12,
    "truncated": false,
    "nodes": [
      {"seq": 1, "kind": "control", "tag": "input", "text": "", "label": "自动续订会员",
       "attrs": {"type": "checkbox", "checked": "true"},
       "style": {}, "box": {"widthPx": 16, "heightPx": 16},
       "nearText": "结算页", "path": "html:nth(0)>body:nth(0)>input:nth(0)"}
    ]
  },
  "ruleset": {"manifest": {…}, "rules": [ … ]},
  "settings": {"site_policy": {"mode": "blocklist", "hosts": []}, "disabled_rule_ids": []},
  "claims": [
    {"claim_id": "c1", "check": "rule", "asserted": "reported",
     "rule_id": "dp-prechecked-optin", "locator": "html:nth(0)>body:nth(0)>input:nth(0)",
     "snippet": "自动续订会员", "evidence": ["checked-state", "label-text"], "finding_id": "F-01",
     "node": {"session_id": "s-ui-1", "turn": 1, "tool_call_id": "call-ui-1"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `page.url` | 是 | 扫描页 URL；`site` 主张可自带 `url` 覆盖 |
| `page.scanned_at` | 是 | 输入事实（器官不读时钟） |
| `page.elapsed_ms` | 是 | 输入事实，非负有限数 |
| `page.truncated` | 否 | 缺省 `false`；`coverage` 主张据此判定 |
| `page.nodes` | 是 | 归一化 PageModel 节点数组（可为空页） |
| `ruleset` | 否 | `{manifest, rules}`；缺省 = 随器官打包的 12 条规则 |
| `settings` | 否 | 站点策略 + 禁用规则；按源仓 `normalizeSettings` 归一化 |
| `claims[]` | 是 | `claim_id` 唯一；`check` 闭集；`node` 可选（痕迹节点） |

节点字段：`seq`（非负整数）/ `kind`（`text` / `element` / `control`）/ `tag` / `text` / `label` /
`attrs`（值只接受字符串 / 数字 / 布尔）/ `style`（`color` / `backgroundColor` / `display` /
`opacity` / `fontSizePx`）/ `box`（`widthPx` / `heightPx`）/ `contrast` / `nearText` / `path`（非空）。
未知顶层键、未知 style/box 键一律契约错误——输入是**已归一化**的 PageModel，不是任意 DOM dump。

`claims[]` 允许字段（按 check）：全局 `claim_id` / `check` / `asserted` / `node`；
`rule` 加 `rule_id` / `locator`（均必填）/ `snippet` / `snippet_truncated` / `evidence` /
`missing_evidence` / `finding_id`；`count` 加 `of`（必填）/ `reason`；`order` 加 `rule_ids`（必填）/
`finding_ids`；`ruleset` 加 `error_terms`；`site` 加 `url` / `settings` / `reason`；
`coverage` 加 `node_count`。其余字段一律契约错误。

## 3. 规则

### 3.1 随包规则（12 条）

分组顺序与严重度分级来自规则包 manifest（`categories` / `severity_levels`），器官不写死。

| 规则 id | 名称 | 分组 | 严重度 | 需要的证据 |
|---|---|---|---|---|
| `dp-prechecked-optin` | 预勾选（默认勾选） | 误导 | 高 | 勾选状态 + 标签文本 |
| `dp-hidden-close` | 隐形关闭（关闭控件不可见或极小） | 障碍 | 高 | 尺寸 + 前景/背景色 + 标签文本 |
| `dp-countdown-pressure` | 倒计时施压 | 紧迫 | 中 | 文本 |
| `dp-fake-scarcity` | 稀缺表述且无可核对来源 | 紧迫 | 中 | 文本 + 周边文本 |
| `dp-confirmshaming` | 确认羞辱（把拒绝写成贬损选项） | 误导 | 中 | 文本 + 标签文本 |
| `dp-anchored-discount` | 锚定折扣（划线价无可核对来源） | 价格 | 中 | 文本 + 周边文本 |
| `dp-default-addon` | 默认加购（附加项默认选中） | 误导 | 中 | 勾选状态 + 标签文本 |
| `dp-exit-retention` | 退出挽留文案 | 障碍 | 中 | 文本 + 周边文本 |
| `dp-subscription-trap` | 订阅取消渠道受限（仅电话/客服） | 障碍 | 高 | 文本 + 周边文本 |
| `dp-hidden-fee` | 费用后置（结账阶段才出现费用） | 价格 | 高 | 文本 + 周边文本 |
| `dp-forced-signup` | 强迫注册（须注册/登录才能继续） | 障碍 | 中 | 文本 + 标签文本 |
| `dp-dark-close` | 低对比关闭控件 | 误导 | 中 | 对比度 + 前景/背景色 + 标签文本 |

### 3.2 判定语义（与源仓逐条对齐）

1. **证据门禁**：`evidence_required` 取不到（`undefined`）→ **丢弃候选并记 rejected**，不降级、不产出；
   空串是「取到了空值」，是合法证据。
2. **同一节点多规则命中** → 按 `manifest.match_priority` 归属（先到先得，一个节点只出一条 finding）。
3. **中和项**（`neutralizers`）命中 → 记 `suppressed`；`nearby_absent_any` 命中 → 也记 `suppressed`
   （「没命中」与「被中和」是两种事实）。
4. **重复 locator**：同一 `(rule_id, locator)` 只出一条 finding；被丢弃的第二条候选记
   `duplicate_locator`。该原因**只能经 `count` 的 `rejected(reason=duplicate_locator)` 观察**——
   因为它必然与同 `rule+locator` 的 finding 同时存在，不单列为 `rule.asserted`（避免两条互斥主张都成立）。
5. **snippet** 是宿主文本的**原样子串**；超 `manifest.thresholds.snippet_max_len`（160）截断并记
   `snippet_truncated: true`。
6. **排序与编号**：severity 降序 → DOM 文档序；编号 `F-01…` 与排序后顺序一致（宽度 = max(2, 位数)）。
7. **站点闸门**：黑名单 = 命中的站点不扫描；白名单 = 不在名单的站点不扫描；URL 不可解析 → 显式
   `url_unparsable`（不静默放行）。
8. **规则包校验**：缺字段 / 枚举越界 / 未知 detect 键 / 未知 style 键 / `rule_files` 数量不符 /
   `match_priority` 漏项或重复 / `ruleset_hash` 仍为占位值 → 拒绝加载并列出全部错误。

## 4. 输出示例

```console
$ traceproof check pattern-evidence --input samples/pattern-evidence.json \
                                    --basis samples/pattern-evidence-traces.json
traceproof :: pattern-evidence 0.2.0 :: pattern-evidence.json
[claim] c-count-findings — 主张「findings = 6」被同一份输入上的重算支持：重算 findings = 6，与主张一致 :: s-ui-1#3#call-ui-3
[claim] c-coverage-complete — 主张「coverage = complete」被同一份输入上的重算支持：扫描结果 complete（node_count=6） :: s-ui-1#7#call-ui-7
[claim] c-rule-prechecked — 主张「dp-prechecked-optin@html:nth(0)>body:nth(0)>input:nth(0) = reported」被同一份输入上的重算支持：产出 F-01（dp-prechecked-optin，severity=high） :: s-ui-1#1#call-ui-1
…
合计 7 条，阻断 0 条（claim=7 refuted=0 inconclusive=0）
# 退出码 0
```

`--json` 输出与内核一致：无时间戳、无绝对路径、字段顺序固定；同输入两次运行**逐字节一致**。
账本行的 `evidence` 含 `check` / `asserted` / `computed` / `comparison`，以及该 check 的实测细节
（`finding_id` / `snippet` / `evidence_kinds` / `reject_reason` / `missing_evidence` /
`actual_rule_ids` / `errors` / `gate_reason` / `node_count` 等）。

## 5. §7.3 四项无损判据

### 5.1 判据 1：X = 182（D1 + D18 机械选，源仓实跑）

命令（来源仓只读；`node --test` 显式文件清单，按 D1 + D18 的文件名规则机械选取）：

```console
$ node --test tests/build.test.mjs tests/ci-workflow.test.mjs \
  tests/collector-parity.test.mjs tests/engine-gate.test.mjs tests/engine-order.test.mjs \
  tests/fixtures-frozen.test.mjs tests/injection-chain.test.mjs tests/manifest-permissions.test.mjs \
  tests/overlay-dom-diff.test.mjs tests/rules-schema.test.mjs tests/site-settings.test.mjs \
  tests/snippet-verbatim.test.mjs tests/source-hygiene.test.mjs tests/sprint-layout.test.mjs \
  tests/store-assets.test.mjs tests/test-manifest.test.mjs tests/threshold-token.test.mjs \
  tests/truth-shape.test.mjs tests/zero-network.test.mjs
ℹ tests 182
ℹ pass 182
ℹ fail 0
```

**X = 182**。D1 排除词（`cli|gui|packaging|audit|desensit|guard|bench|infra|export|version|license|generat|docs?_|health|release|selftest|smoke`）
+ D18 追加词（`parse|report|input|output|web|panel`）按**文件名**机械匹配；未改 D1 / D18，未删源仓文件。
该器官在 `baseline-20261125.csv` 里也被静态记 0（9 个非 Python / 嵌套测试器官之一），X 只能实跑求。

| 源仓测试文件 | 实跑 passed | 域 | 器官处置 |
|---|---:|---|---|
| `build.test.mjs` | 11 | 打包/构建 | 产品级：由仓库构建与判据 4 接管，不迁 |
| `ci-workflow.test.mjs` | 5 | CI 脚手架 | 产品级：由仓库 CI 接管，不迁 |
| `collector-parity.test.mjs` | 4 | 采集层 DOM 语义 | **部分迁**：`labelFrom` / `limitNearText` / 归一化口径在 `page-model.ts` 复刻；DOM 采集不迁 |
| `engine-gate.test.mjs` | 7 | 证据门禁 | **已迁**：`engine.ts` + `page-model.ts` |
| `engine-order.test.mjs` | 7 | 排序/编号 | **已迁**：`ordering.ts` + `engine.ts` |
| `fixtures-frozen.test.mjs` | 10 | 40 页 fixture 冻结 | 产品级：本器官不读夹具，不迁 |
| `injection-chain.test.mjs` | 13 | 扩展注入链路 | 产品级：service worker / chrome 接线，不迁 |
| `manifest-permissions.test.mjs` | 6 | MV3 权限面 | 产品级：打包/安全门，不迁 |
| `overlay-dom-diff.test.mjs` | 23 | 页内覆盖层 DOM | 不迁：器官不碰 DOM |
| `rules-schema.test.mjs` | 15 | 规则包 schema | **已迁**：`rules.ts` + `data/ruleset.json` |
| `site-settings.test.mjs` | 11 | 站点闸门/规则开关 | **纯函数部分已迁**：`site-policy.ts`；UI 明示 / storage / 注入不迁 |
| `snippet-verbatim.test.mjs` | 4 | snippet 原样子串 | **已迁**：`page-model.ts` |
| `source-hygiene.test.mjs` | 8 | 源码纪律 | 产品级：不迁 |
| `sprint-layout.test.mjs` | 10 | 项目布局方法论 | 产品级：不迁 |
| `store-assets.test.mjs` | 14 | 商店素材 | 产品级：不迁 |
| `test-manifest.test.mjs` | 3 | 扩展清单 | 产品级：不迁 |
| `threshold-token.test.mjs` | 6 | 阈值单一真相源 | **判定侧已迁**：阈值只从 `manifest.thresholds` 读；源码 token 扫描属产品级，不迁 |
| `truth-shape.test.mjs` | 18 | fixture 真值形态 | 产品级基准数据：不迁 |
| `zero-network.test.mjs` | 7 | 零网络形态 | 产品级安全门：器官本身无网络 API，不迁 |
| **合计** | **182** | — | 已迁/部分迁：engine-gate、engine-order、rules-schema、snippet、site-policy、collector 口径 |

**D1/D18 剔除（不计入 X，共 82 条）**——逐项处置：

| 源仓测试文件 | 实跑 passed | 排除词 | 处置 |
|---|---:|---|---|
| `copy-guard.test.mjs` | 6 | D1 `guard` | 产品级文案门；器官不手写文案，不迁 |
| `export.test.mjs` | 8 | D1 `export` | 产品级导出（Markdown/JSON 证据包）；器官不带输出排版，不迁 |
| `export-fields.test.mjs` | 8 | D1 `export` | 同上（导出字段契约）；器官输出由内核 `Report` 决定 |
| `release-gate.test.mjs` | 11 | D1 `release` | 发布终态门；不迁 |
| `rules-bench.test.mjs` | 17 | D1 `bench` | 40 页合成基准；产品级，不迁（判据 2 用其底层命令的 rc 对账） |
| `sidepanel-restore.test.mjs` | 24 | D18 `panel` | 侧边栏恢复/假 chrome；产品级，不迁 |
| `version-pointer.test.mjs` | 8 | D1 `version` | 版本指针门；不迁 |

### 5.2 判据 2：旧示例 rc 相同

源仓是浏览器扩展，**没有 CLI**；README「开发与自检」里对应判定层的一条真示例是
`npm run bench`（规则基准 B1–B7）。用它的底层命令复跑：

| 侧 | 命令 | 实测 | rc |
|---|---|---|---:|
| 旧 | `node tools/bench-rules.mjs` | B1 12/12 达标；B2–B7 全 PASS；结论「全达标」 | **0** |
| 新 | `traceproof check pattern-evidence --input samples/pattern-evidence.json --basis samples/pattern-evidence-traces.json` | 7 条 claim / 阻断 0（claim=7 refuted=0 inconclusive=0） | **0** |

旧插件形态（浏览器扩展）不是 CLI，未照抄 `cordis.patch.yml` 的调用方式；新侧按本产品
唯一入口 `bin/traceproof` 的 `check` 子命令复跑。**同为「全通过」**，无 rc 差。

### 5.3 判据 3：口径乙（用例 + 函数）

| 项 | 旧层 | 新器官 | 结论 |
|---|---:|---:|---|
| 实跑用例数 | 182（19 文件） | **249**（`node --test test/pattern-evidence.test.js`） | 过（249 ≥ 182） |
| `test(` 函数数（按条计） | **160**（19 文件顶层调用数） | **249** | 过（249 ≥ 160） |
| 测试文件数（只记录） | 19 | 1 | 记录 |

旧层 160 / 实跑 182 的差额来自 `rules-schema` / `sprint-layout` / `truth-shape` 里的生成式用例
（`test(` 调用数按条计，不拿子测试/生成用例冒充函数数）。

### 5.4 判据 4：`npm pack` 后 `data/` 进包

在 `%TEMP%` 的**副本**里构建（`pnpm run build`）后 `npm pack`：

| 项 | 实测 |
|---|---|
| 包文件 | `dsh-prompt-polisher-0.2.0.tgz`，**163 条目 / 246725 B** |
| 器官 data | `package/lib/traceproof/verbs/pattern-evidence/data/ruleset.json`，**19604 B**（非空） |
| 数据等价 | 源 `data/ruleset.json` 16228 B；tsc 以 4 空格重新序列化后语义逐键一致（`JSON.parse` 后深比较相等） |
| 解包后 `list` | 含 `pattern-evidence 0.2.0`（5 器官） |
| 解包后 `check` | 样例 rc **0**，7 条 claim / 阻断 0 |

`:data` 以 `import rulesetData from './data/ruleset.json' with { type: 'json' }` 引入，tsc 才会把它
发到 `lib/.../data/`；器官运行期不读文件。

## 6. 口径差（如实登记）

1. **Node/mjs 源 → TypeScript 重写**；只迁判定层（page-model / rules / engine / ordering /
   site-policy）。浏览器宿主半（collector / overlay / service worker / sidepanel / background）
   不迁——器官不得碰 DOM / chrome API / 时钟 / 文件。
2. **40 页合成 fixture、逐页真值、规则基准 B1–B7、商店素材、发布门不迁**：它们是产品级基准资产与
   发布工程，不是「不得自带 CLI」的器官能承载的判定逻辑。判据 1 的 X 仍按 D1/D18 机械记 182；
   器官用 249 条判定用例满足 ≥182，未因此改 D1 或删源仓文件。
3. **claim 模型是 traceproof 账本，不是旧仓证据包**：旧仓输出 `findings / rejected` 证据包；
   本器官把同一份重算结果映射成 6 类 claim，`refuted` 要求痕迹节点，证据在入账时脱敏。
4. **`duplicate_locator` 只经 `count` 观察**：重复 locator 的 rejected 与同 rule+locator 的 finding
   同时存在；若把 `duplicate-locator` 也列成 `rule.asserted`，同一事实会允许两条互斥主张都成立。
   因此 `rule` 闭集只到 `reported / absent / suppressed / missing-evidence`，去重条数用
   `count(of=rejected, reason=duplicate_locator)` 核对。
5. **`detect.min_font_size_px` 保留源仓语义**：源仓要求 `fontSizePx >= min_font_size_px` 才命中
   （低于阈值反而不命中）；本器官逐行照搬，未「修正」成直觉方向。首期 12 条规则没有使用该键。
6. **输入比源仓采集层更严格**：节点 / style / box 的未知键一律契约错误；源仓采集层直接产出闭合
   形状，本器官不接收任意 DOM dump。`page.truncated` 缺省 false；`settings` 仍按源仓宽松归一化。
7. **规则包可由输入覆盖**：缺省用随包 12 条规则；`ruleset` 主张可校验任意候选包（含故意变异的包），
   但 `rule` / `count` / `order` 主张遇到无效规则包 → `RulePackError`（唯一入口映射退出码 2），
   不拿坏包静默扫出空结果。
8. **消息内联中文**：源仓文案在 `copy.js` 单点；器官不得自带文案配置，账本 message 由本器官直写。
9. **判据 2 的样例替换**：源仓 README 的示例是扩展构建/测试命令，无进程退出码；以判定层基准命令
   `node tools/bench-rules.mjs`（rc 0）对账，新侧用 `traceproof check` 样例（rc 0）。
10. **D16 仓外编辑**：本批改动在运维计划会话里 `cd` 进产品仓 / 来源仓完成（宿主门
    `MIMOSA_GIT_GATE_MODE=warn`，graded 模式不追溯扫描）；来源仓只读、未改未删未提交；
    未跑 `security_scan`；未碰可见性 / DB / 删仓。

## 7. 数据溯源与审计

- 规则包数据 = 源仓 `rules/manifest.json` + `rules/dp-*.json` 的**只读导出**；源 manifest
  sha256 `d778f424e0c623263999a333eca8199f2f223b95c35d37e5ad87067088d78300`；
  `ruleset_hash` 原样保留 `b81d12e8…`，未在器官里重算/改写。
- 导出脚本与逐文件处置留档在运维计划目录（本批记录 #52 与 `scripts/` 下的导出脚本）。
- 测试数据全部为自建页面模型 / 保留域名 `example.invalid`，不含真实站点与个人信息。