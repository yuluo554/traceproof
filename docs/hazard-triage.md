# hazard-triage · 施工安全风险研判取证

> 器官 slug `hazard-triage`，版本 `0.1.1`（迁自 target-map ④ 行；版本沿用源仓
> `pyproject.toml` 的 `0.1.1`，不随本产品升版）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这组施工日志会抽出哪些隐患、关联哪些规范条款、定成哪一级风险、给出哪些整改建议」
的主张，逐条对到**同一份输入**的确定性重算：

| check | asserted 闭集 | 判据 |
|---|---|---|
| `record` | `exact` | 第 N 条记录的规范化时间戳与文本；可附 `timestamp` / `text` |
| `hazard` | `reported` / `absent` | 第 N 条记录是否抽出某隐患类型；可附 `quote` / `category` / `site_object` / `extractor` |
| `count` | 十进制数字 | `of=records / hazards / type / level / suggestions / fallback`；`type` 带 `hazard_type_id`，`level` 带 `risk_level` |
| `level` | `低风险` / `一般风险` / `较大风险` / `重大风险` | 条目卡等级；可附 `rule_id` / `override_id` / `threshold_id` / `upgraded`（`major` / `severity` / `none`）/ `human_confirm` |
| `clause` | `linked` / `unlinked` | 条款清单；`clause_refs` 逐条比对，`require_quotes` 要求原文摘录非空 |
| `anchor` | `exact` | 报告条款锚点 `kg.html#<URL编码节点id>`；`require_node` 默认要求图谱有该条款节点 |
| `suggestion` | `sourced` / `fallback` | 整改建议来源清单与必含文本；`sources` / `contains` |
| `graph` | 十进制数字 | `of=node-count / edge-count / nodes-of-type / edges-of-relation / neighbors` |
| `node` | `present` / `absent` | 图谱节点存在性与类型；`relations` 是必须出现的关系名集合 |
| `schema` | 十进制数字 | `of=hazard-types / measures / regulations / thresholds / overrides / threshold-rules / base-rules / patterns` |
| `consistency` | `consistent` / `inconsistent` | `kind=base-rules / pattern-coverage / measure-refs / clause-refs / kg-nodes / rule-fallback` |
| `vision` | `mapped` / `dropped` | 第 N 条视觉检出是否映射受控词表；可附 `hazard_type_id` / `bbox` / `confidence` |
| `merge` | `merged` / `unmerged` | 文本卡与视觉卡是否融合；可附 `merged_from` / `confidence` / `evidence_images` |
| `fallback` | `candidates` / `none` | 空条款卡片的向量兜底候选；`clauses` 比对候选清单，`min_score` 可覆盖阈值 |
| `keyframes` | 数字或 `exact` | 视频关键帧选择；`frames` 给出精确清单时 asserted 必须是 `exact` |
| `paired` | `present` / `absent` | 施工日志版 vs 巡查版差异（`missing` / `extra` / `value` @ 时间戳） |
| `metric` | 十进制数字 | `of=micro-f1 / micro-precision / micro-recall / micro-fp / level-accuracy / detection-rate / false-positive-rate / field-f1`；`tolerance` 可给容差 |
| `candidate` | `valid` / `invalid` | LLM 候选校验（摘录必须是原文子串、词表命中、类别受控）——复刻源仓 `validate_llm_item` |

**器官不做的事**：不读文件 / 环境变量 / 时钟，不联网，不调 LLM / YOLO / opencv / pyvis，
不导出 JSON / Markdown / docx / Web 面板。日志文本、知识库、视觉检出、视频帧数、
配对记录与真值都由输入提供；证据只经 `makeRecord()` 入账（内核在入账时脱敏）。

## 2. 输入（subject）

```json
{
  "text": "[2026-09-21 08:30] 3#楼3层楼层临边未设置防护栏杆\n[2026/09/22 08:53] ...",
  "records": [{"index": 1, "timestamp": "2026-09-21 08:30", "text": "..."}],
  "knowledge": {"hazard_types": [], "measures": [], "thresholds": [], "rules": {}, "regulations": [], "cases": []},
  "vision": {
    "images": [{"name": "shwd_3.jpg", "detections": [{"class_name": "head", "bbox": [120, 80, 240, 360], "confidence": 0.7}]}],
    "time_window_minutes": 60
  },
  "video": {"total_frames": 100, "max_frames": 8},
  "paired": {
    "log": [{"index": 1, "timestamp": "2026-09-21 15:47", "text": "..."}],
    "patrol": [{"index": 1, "timestamp": "2026-09-21 16:33", "text": "..."}]
  },
  "gold": {"records": [{"index": 1, "hazard_type_id": "HT-GCZY-001", "expected_level": "较大风险"}]},
  "claims": [{"claim_id": "c1", "check": "level", "asserted": "较大风险", "record_index": 1,
              "hazard_type_id": "HT-GCZY-001", "node": {"session_id": "s-site-1", "turn": 1, "tool_call_id": "call-site-1"}}]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `text` | 条件 | 原始施工日志文本；与 `records` 二选一 |
| `records` | 条件 | 已解析记录（`index` 从 1 起 / `timestamp` / `text`）；与 `text` 二选一 |
| `knowledge` | 否 | 覆盖随包知识库的任意一份；形状不合法 → 退出码 2 |
| `vision` | 否 | 已归一化的视觉检出；器官不读图片、不跑模型 |
| `video` | 否 | 视频总帧数（选帧纯函数输入）；器官不打开视频 |
| `paired` | 否 | 施工日志版 / 巡查版记录（文本或已解析记录） |
| `gold` | 否 | 基准真值；`metric` 主张需要 |
| `claims[]` | 是 | `claim_id` 唯一；`check` 闭集；`node` 可选（痕迹节点） |

`text` / `records` 只在「需要条目卡」的主张上要求；`graph` / `node` / `anchor` / `schema` /
`consistency` / `keyframes` 可以只凭知识库或输入事实核对。`vision` / `video` / `paired` / `gold`
缺失时，对应 check 直接契约错误，不静默返回空结果。

## 3. 规则

### 3.1 判定链（与源仓 `pipeline/runner.py` 同序）

1. **解析**：时间戳容错四种日期分隔符 + 三种时间形态；多行记录按邻近合并；注释 / 表头跳过。
2. **抽取**：受控词表 `patterns` 正则逐类型命中；同一类型每条记录只出一次卡；
   部位取 `site_objects` 的最长匹配。文本卡 `confidence=0.95`、`extractor=rules`。
3. **融合**（可选）：视觉检出 `head` / `no_helmet` / `person_without_helmet` → 未佩戴安全帽（HT-GCZY-007）；
   同 `site_object` + 同 `hazard_type_id` 且时间窗内（默认 60 分钟，含边界）合并；
   `merged_from` 回填双方、置信度取高、视觉证据进 `evidence.vision`。
4. **条款关联**：条款号来自词表 `clause_refs`，原文摘录来自条文库；查不到不硬造。
5. **四级判定**（从重原则，命中即停）：
   - 规则库 `major_patterns` 命中 → 重大风险；
   - 规则库 `overrides`（建质规〔2022〕2号重大隐患情形）命中 → 取最高档，只升不降；
   - 严重词（坠亡 / 伤亡 / …）在基础上调一档，封顶重大；
   - 阈值数值判定：卡片 `attrs` 携带实测值且超限 → 取 `level_on_violation`；
   - 否则取受控词表 `base_level`。
   `rule_id` 可溯源：override → `OV-*`，阈值 → `RT-*`，否则 → `RL-<类型后缀>`。
6. **整改建议**：措施库模板 + 条款编号，建议必带出处；无措施时回退到「受控词表」提示。
7. **图谱**：187 节点 / 238 边；风险分级 / 属于 / 整改用 / 应依据 / 作业类型 / 发生于 / 涉及。
8. **兜底**：条款为空的卡片可用字符二元组 TF-IDF 检索条文库；候选逐条标「非判定依据」，
   不改 `risk_level` / `clause_refs` / `suggestions`。
9. **指标**：按 `(记录序号, hazard_type_id)` 对齐做微平均 P/R/F1、分级准确率、字段级 F1、
   端到端检出率 / 误报率。
10. **配对差异**：按规范化时间戳对齐两版记录，检出漏项 / 多报 / 数值多重集不一致。

### 3.2 随包知识库（源仓只读导出）

| 数据 | 条目 | 说明 |
|---|---:|---|
| `hazard-types.json` | 31 | 8 大类 / 31 类隐患；patterns / 部位 / 措施 / 条款锚点 |
| `measures.json` | 29 | 整改措施模板 |
| `thresholds.json` | 7 | 阈值表（`op` / `value` / `range` / `level_on_violation`） |
| `rules.json` | 31 base / 15 override / 7 threshold rules | 规则库 v1.1.0 |
| `regulations.json` | 54 | 条文库（标准 / 条款 / 原文 / 关键词） |
| `cases.json` | 10 | 教学案例（图谱 Case 节点） |

**阈值与规则数据缺失时**：`major_patterns` / `severity_words` 回退模块常量（与源仓一致），
`consistency(rule-fallback)` 会如实判 `inconsistent`。

## 4. 输出示例

随包样例 = 源仓 `demo_gczy` 的 67 条记录 + 2 条合成记录（第 68 条未佩戴安全帽、
第 69 条塔吊限位失效），共 **69 条记录 / 56 条隐患 / 57 条主张**。

```console
$ traceproof check hazard-triage --input samples/hazard-triage.json \
                                 --basis samples/hazard-triage-traces.json
traceproof :: hazard-triage 0.1.1 :: hazard-triage.json
[claim] c-01-record — 主张「record 1 = exact」被同一份输入上的重算支持：记录 1 的规范化时间戳与文本逐字一致 :: s-site-1#1#call-site-1
[claim] c-02-hazard — 主张「1/HT-GCZY-001 = reported」被同一份输入上的重算支持：记录 1 抽出 HT-GCZY-001（临边防护缺失，部位 楼层临边） :: s-site-1#2#call-site-2
[claim] c-14-level — 主张「69/HT-QZ-002 level = 重大风险」被同一份输入上的重算支持：记录 69 / HT-QZ-002 判定 重大风险（rule_id=OV-2022-008-5） :: s-site-1#14#call-site-14
[claim] c-46-keyframes — 主张「keyframes(100) = exact」被同一份输入上的重算支持：关键帧选择成立（total=100 max=8 → [0, 12, 25, 37, 50, 62, 75, 87]） :: s-site-1#46#call-site-46
…
合计 57 条，阻断 0 条（claim=57 refuted=0 inconclusive=0）
# 退出码 0
```

`--json` 输出与内核一致：无时间戳、无绝对路径、字段顺序固定；同输入两次运行**逐字节一致**。
账本行 `evidence` 含 `check` / `asserted` / `computed` / `comparison`，以及该 check 的实测细节
（`record` / `clause_refs` / `node_id` / `frames` / `candidates` / `metrics` 等）。

## 5. §7.3 四项无损判据

### 5.1 判据 1：X = 128（D1 + D18 机械选，源仓实跑）

D1 排除词（`cli|gui|packaging|audit|desensit|guard|bench|infra|export|version|license|generat|docs?_|health|release|selftest|smoke`）
+ D18 追加词（`parse|report|input|output|web|panel`）按**文件名**机械匹配；未改 D1 / D18，未删源仓文件。

命令（来源仓只读；`PYTHONDONTWRITEBYTECODE=1` 防写旧仓 `__pycache__`）：

```console
$ cd <源仓>
$ PYTHONDONTWRITEBYTECODE=1 py -3.12 -m pytest \
    tests/test_datagen.py tests/test_extras_contract.py tests/test_kg.py \
    tests/test_m2.py tests/test_m3.py tests/test_m4.py tests/test_m5.py \
    tests/test_m6.py tests/test_pipeline.py tests/test_risk_level.py tests/test_rules.py \
    -q -p no:cacheprovider
128 passed, 2 warnings in 7.43s
```

> 首次实跑（未装 `pyvis`）为 `1 failed, 125 passed, 2 skipped`；唯一失败是 `test_m3` 的
> `build-kg` 三件套断言缺 `kg.html`（源仓 README 注明该测试前提是装齐 `.[llm,doc,kg,web]`）。
> 按源仓声明的 optional 依赖装上 `pyvis 0.3.2` 后重跑得到 `128 passed`，X 取 **128**。
> JUnit 对账 `tests=128 failures=0 errors=0 skipped=0`。

| 源仓测试文件 | 实跑 passed | 域 | 器官处置 |
|---|---:|---|---|
| `test_datagen.py` | 7 | 语料生成 / 变体覆盖 / 真值 schema | **不迁**：生成器与冻结语料属产品级 fixture；解析口径由 `parse` 覆盖 |
| `test_extras_contract.py` | 7 | optional extras 静态契约 | **不迁**：Python 打包契约；本产品无 Python extras |
| `test_kg.py` | 8 | 种子图节点预算 / 关系语义 / 实例挂图 | **已迁**：`graph.ts`（187/238、四类关系、条文 text、attach_instance） |
| `test_m2.py` | 16 | 规则库 / override / 阈值 / docx / LLM / 端到端指标 | **部分迁**：规则库 + override + 阈值 + 兜底 + 指标已迁；docx 解析与 LLM 传输不迁 |
| `test_m3.py` | 9 | pyvis HTML / 降级 / 条款锚点 / build-kg CLI | **部分迁**：`anchor` + 图谱节点已迁；pyvis / HTML / CLI 产物不迁 |
| `test_m4.py` | 23 | 视觉三路降级 / 受控映射 / 图文融合 / runner / demo | **部分迁**：映射 / 融合 / 低置信人工确认已迁；图片 IO / YOLO / demo 不迁 |
| `test_m5.py` | 22 | docx 导出 / 路径脱敏 / Web / 脱敏审查 | **不迁**：报告排版、Web 面板、上传路径清洗属产品级（器官不带输出排版 / 文件 IO） |
| `test_m6.py` | 13 | 向量检索 / 视频选帧 / CLI 旗标 / 技术 docx | **部分迁**：TF-IDF 兜底 + 选帧纯函数已迁；opencv / CLI / docx 不迁 |
| `test_pipeline.py` | 8 | 端到端研判 / 评测 / 报告导出 | **部分迁**：研判链（解析→抽取→关联→分级→建议）已迁；文件 IO / 报告写盘不迁 |
| `test_risk_level.py` | 6 | 四级判定 / 封顶 / 人工确认 | **已迁**：`judge.ts` |
| `test_rules.py` | 9 | 规则抽取 / LLM 校验 / 视觉缺图降级 | **部分迁**：RuleEngine 4 条 + `candidate` 校验 1 条已迁；LLM 调用与视觉 IO 不迁 |
| **合计** | **128** | — | 已迁 2 文件 / 部分迁 6 文件 / 不迁 3 文件（按判定逻辑计） |

**D1/D18 剔除（不计入 X，共 29 条）**——逐文件处置：

| 源仓测试文件 | 实跑 passed | 排除词 | 处置 |
|---|---:|---|---|
| `test_license_metadata.py` | 7 | D1 `license` | 产品级元数据 / SPDX 门；本产品不迁 |
| `test_packaging_assets.py` | 7 | D1 `packaging` | 产品级 wheel 资产门；由本产品判据 4（`npm pack`）接管 |
| `test_parsers.py` | 15 | D18 `parse` | 输入侧解析（文件读取 / docx / 编码错误）不迁；纯文本清洗与记录解析已在 `parse.ts` 复刻并由 `record` 主张覆盖 |

### 5.2 判据 2：旧示例 rc 相同

源仓 README 的快速开始示例（`demo` 两场景端到端研判）：

| 侧 | 命令 | 实测 | rc |
|---|---|---|---:|
| 旧 | `py -X utf8 -m siteguard.cli demo`（在 `git archive` 导出的临时副本里实跑，产物写副本内，源仓只读） | 两场景各 54 条隐患；两份 JSON + 两份 Markdown 报告 | **0** |
| 新 | `traceproof check hazard-triage --input samples/hazard-triage.json --basis samples/hazard-triage-traces.json` | 57 条 claim / 阻断 0（claim=57 refuted=0 inconclusive=0） | **0** |
| 新 | 同上 `--json` | `summary.total=57`、`summary.blocking=0` | **0** |

**同为「全通过」**，无 rc 差。旧插件形态（`cordis.patch.yml`）不是 CLI，未照抄其调用方式。
另以源仓判定层事实做逐条对账：`demo_gczy` + `demo_lsyd` 两场景 **108 张条目卡**的
`category / site_object / quote / risk_level / rule_id / override_id / threshold_id /
upgraded / human_confirm / clause_refs（含原文）/ suggestions（含出处）` 与源仓实跑**逐字段一致**；
`run_eval()` 的微平均 F1=1.0、FP=0、分级准确率=1.0、字段级 F1=1.0、
配对差异 gczy/lsyd 各 4/4 检出，新器官重算同值。

### 5.3 判据 3：口径乙（用例 + 函数）

| 项 | 旧层 | 新器官 | 结论 |
|---|---:|---:|---|
| 实跑用例数 | 128（11 文件） | **274**（`node --test test/hazard-triage.test.js`） | 过（274 ≥ 128） |
| `test(` 函数数（按条计） | **128**（11 文件 AST `ast.FunctionDef/AsyncFunctionDef` 且名以 `test_` 开头） | **274**（顶层 `test(` 调用数） | 过（274 ≥ 128） |
| 测试文件数（只记录） | 11 | 1 | 记录 |

### 5.4 判据 4：`npm pack` 后 `data/` 进包

在 `%TEMP%` 的**副本**里构建（`npm run build`）后 `npm pack`：

| 项 | 实测 |
|---|---|
| 包文件 | `dsh-prompt-polisher-0.2.0.tgz`，**229 条目 / 343651 B**（unpacked 1355513 B） |
| 器官 data | `package/lib/traceproof/verbs/hazard-triage/data/` **6 文件**：`hazard-types.json` 18930 B / `measures.json` 5675 B / `thresholds.json` 2697 B / `rules.json` 11265 B / `regulations.json` 37386 B / `cases.json` 8454 B |
| 数据等价 | 与 `src/.../data/` 逐文件 `JSON.parse` 后深比较**相等**（tsc 重新序列化后语义不变） |
| 解包后 `list` | 含 `hazard-triage 0.1.1`（8 器官） |
| 解包后 `check` | 样例 rc **0**，57 条 claim / 阻断 0 |

`:data` 以 `import … from './data/*.json' with { type: 'json' }` 引入，tsc 才会把它发到
`lib/.../data/`；器官运行期不读文件。

## 6. 口径差（如实登记）

1. **Python 源 → TypeScript 重写**；只迁判定层：parse / extract / clause-link / judge / suggest /
   kg / anchors / vision mapping+merge / vector / keyframes / paired / metrics。
   源仓 CLI、Web 面板（FastAPI）、报告导出（JSON/Markdown/docx）、pyvis 可视化、YOLO 推理、
   opencv 抽帧、docx 解析、文件发现与写盘**不迁**。
2. **输入从文件变成 subject**：日志文本 / 已解析记录、知识库、视觉检出、视频帧数、
   配对记录、真值都由输入提供。器官不读文件 / 环境变量 / 时钟。
3. **LLM 不调用**：只复刻 `validate_llm_item` 的纯校验（`candidate` 主张：摘录必须是原文子串、
   词表命中、类别受控）；transport / retry / JSON 截断修复不迁。
4. **视觉与视频不读二进制**：`vision.images[].detections` 是输入事实；`head` / `no_helmet` /
   `person_without_helmet` → 未佩戴安全帽，未登记类别丢弃并记 warning（与源仓一致）。
   视频只复刻 `select_keyframes` 纯函数，帧数据不由器官解码。
5. **消息内联中文**：源仓报告文案分散在 `report/export.py` / `serverapp.py`；器官不得自带输出排版，
   账本 message 由本器官直写，结论字段不变。
6. **`not_in` 阈值缺 `range` 时跳过**：源仓会因 `range=None` 抛 `TypeError`；本器官显式跳过该阈值。
   随包阈值表 7 条均带 `range` 或 `value`，行为无差异。
7. **图谱 `stats()` 的键按字典序输出**：源仓按插入顺序；键值对逐项相等（187/238、
   8 类 / 7 关系），仅序列化顺序不同。
8. **无视觉输入时 `mergeCards` 返回新数组**：源仓原样返回入参列表（身份相同）；器官内部 API
   改为副本，判定结果逐项不变。
9. **`round4` 用 `Math.round`**：源仓 Python `round()` 为半偶舍入；源数据实测分数
   （如 0.5662 / 0.1054 / 0.0924）逐值一致，仅在恰好落在 `.00005` 边界时可能有末位差。
10. **样例替换**：判据 2 的旧示例是 `demo` 两场景；新样例取 `demo_gczy` 的 67 条记录 +
    2 条合成记录（未佩戴安全帽 / 塔吊限位失效），真值同步扩 2 条；视觉检出为合成输入
    （仅用于演示 mapping/merge，不声称真实检测）。
11. **接线副作用**：`test/pipeline-run.test.js` / `test/pattern-evidence.test.js` /
    `test/rework-evidence.test.js` 的精确 7 项断言改为**精确 8 项**，`test/anonymity-collapse.test.js`
    的 `list --json` 计数 7→8（测试名同步），未退回 `contains`。
12. **D16 仓外编辑**：本批改动在运维计划会话里 `cd` 进产品仓 / 来源仓完成（宿主门
    `MIMOSA_GIT_GATE_MODE=warn`，graded 模式不追溯扫描）；来源仓只读、未改未删未提交；
    未跑 `security_scan`；未碰可见性 / DB / 删仓。

## 7. 数据溯源与审计

来源仓 HEAD `beead77`；`data/knowledge/` 只读导出为器官 `data/`：

| 源文件 | sha256 | 器官文件 |
|---|---|---|
| `data/knowledge/seed/hazard_types.json` | `1134a46bd8b6202c37418197912b5c580eac7fb4a167bab6229199ee5793c368` | `hazard-types.json` |
| `data/knowledge/seed/measures.json` | `2c555b1c5f1ee576f7c9ac8ace027620c47b8c954771554b470e905cde0308f3` | `measures.json` |
| `data/knowledge/thresholds/seed_thresholds.json` | `56a101e06d1ebbd02a0ee2654330520aab5a0d1c1e176db78914ddfae1dbbd1a` | `thresholds.json` |
| `data/knowledge/rules/rules_v1.json` | `1a2e46d6f23f2a3286e81e65b51d566b2cd816f861c6dcf12dcf50cf52204af0` | `rules.json` |
| `data/knowledge/regulations/seed_regulations.jsonl` | `be63653bd3dd4d3c32617eaa89a91b72e261c0d94ec69e78714c60eeec1b8216` | `regulations.json`（JSONL → 数组） |
| `data/knowledge/cases/cases.jsonl` | `31aa37770f4b17af4c0c483b5657a95390ae732ed3ccaeb831552a307b34dfd7` | `cases.json`（JSONL → 数组） |

- 条文为源仓研究性摘录概括，原样保留「以官方文本为准」语义；器官未新增 / 改写条款号。
- 测试样例与真值来自源仓程序生成语料（seed=42），另加 2 条明确标注的合成记录；
  不含真实项目、个人信息或真实检测结果。