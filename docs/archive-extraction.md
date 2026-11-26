# archive-extraction · 归档提取取证

> 器官 slug `archive-extraction`，版本 `1.0.1`（迁自 target-map ④ 行；版本沿用源仓
> `src/extract_oracle/__init__.py` 的 `__version__ = "1.0.1"`，不随本产品升版）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

把「这份归档在目标平台上会写出什么名字、谁覆盖谁、谁被拒绝」的主张，逐条对到**同一份
已解析结构事实**的确定性重算，再挂到痕迹节点（`session_id + turn + tool_call_id`）。

| check | asserted 闭集 | 判据 |
|---|---|---|
| `finding` | 布尔 | 某条 `rule`（可带 `entry_index` / `platform`）是否存在 |
| `finding_count` | 整数 | 某条（或全部）规则的 finding 数 |
| `finding_field` | 任意 JSON | 某条 finding 的字段路径（如 `evidence.lfhNameHex`） |
| `collision` | 布尔 | 某 `(code, platform, entry_a, entry_b)` 是否相撞 |
| `collision_count` | 整数 | 某条（或全部）折叠规则的 collision 数 |
| `collision_field` | 任意 JSON | 某条 collision 的字段路径（如 `survivor` / `verdict`） |
| `accessibility` | 四级闭集 | 单条目单平台的可访问性；可附 `reasons` / `evidence` 逐项比对 |
| `encoding` | 任意 JSON | 编码推断字段：`bit11` / `upath` / `confidence` / `preferred` / `candidates` / `effective_name` / `predicted_*` / `raw_name_hex` / `extra_ids` |
| `container` | `kind` 或整数 | 容器识别结果或 `mimetype` 条目下标 |
| `archive` | 整数 / 布尔 / 数组 | 结构事实级字段：条目数 / EOCD 声明数 / CD 实际数 / zip64 / CD 区间 |
| `display` | 字符串 / `null` | 条目 LFH / CD 名的展示形（`backslashreplace`） |
| `platforms` | 整数 / 字符串 | 平台表身份：条目数 / sha256 / 指纹 / source / 副表强度 |
| `clean` | 布尔 | 无 finding、无 collision、无可访问性异常 |
| `summary` | 整数 | findings / collisions / accessibility_issues / low_confidence / container_findings |

**器官不做的事**：不读文件 / 环境变量 / 时钟，不联网，不解析 ZIP 字节，不产出报告排版，
不自带 CLI / 配置。归档结构事实、目标平台与主张都由输入提供；证据只经 `makeRecord()` 入账
（内核在入账时脱敏）。

## 2. 输入（subject）

```json
{
  "archive": {
    "probe": {
      "archive_size": 200, "eocd_offset": 178, "declared_entries": 2,
      "declared_cd_size": 92, "declared_cd_offset": 100, "comment_length": 0
    },
    "entries": [
      {
        "index": 0,
        "lfh_offset": 0, "lfh_end": 49, "cd_offset": 97,
        "lfh_name_hex": "526561646d652e747874",
        "cd_name_hex": "526561646d652e747874",
        "lfh_flags": 0, "cd_flags": 0,
        "lfh_crc": 0, "cd_crc": 0,
        "lfh_csize": 10, "cd_csize": 10,
        "lfh_usize": 10, "cd_usize": 10,
        "lfh_extra": [], "cd_extra": [{"id": 28789, "data_hex": "01..."}],
        "method": 0, "data_offset": 40
      }
    ],
    "cd_actual_entries": 2,
    "cd_span": [100, 192],
    "zip64": false,
    "data_b64": "UEsDB..."
  },
  "targets": ["windows", "macos", "linux"],
  "claims": [
    {
      "claim_id": "c-casefold",
      "check": "collision",
      "code": "collision.CASEFOLD",
      "platform": "windows",
      "entry_a": 0, "entry_b": 1,
      "asserted": true,
      "node": {"session_id": "s-archive-1", "turn": 1, "tool_call_id": "call-archive-1"}
    }
  ]
}
```

字段口径：

- `archive.entries[]` 与源仓 `EntryView` 一一对应；名字与 extra 的精确字节一律十六进制，
  判定内部还原为字节。`cd_actual_entries` 若给，必须等于 `entries.length`。
- `data_b64` 只在 `container.*` 需要读 `mimetype` 内容时使用；缺省视为空字节。
- `targets` 非空、去重，取值只能是 `windows` / `macos` / `linux`；主张里的 `platform`
  必须在本次 `targets` 内。
- 结构事实非法 → `ArchivePayloadError`（唯一入口退出码 2）；主张字段非法 → `ContractError`
  （退出码 3）。

## 3. 判定规则（20 条）

### 3.1 `structure.*` 六条（零解码，字节层）

| ruleId | 判定 | precedent |
|---|---|---|
| `structure.NAME_DIVERGES` | `lfh_name != cd_name`（字节比较） | `libarchive_reads_lfh` |
| `structure.CRC_DIVERGES` | `lfh_crc != cd_crc`；bit 3 置位且 LFH 字段为 0 时豁免 | `libarchive_reads_lfh` |
| `structure.SIZE_DIVERGES` | 压缩/未压缩大小任一不等；bit 3 豁免同上 | `libarchive_reads_lfh` |
| `structure.FLAG_DIVERGES` | `lfh_flags != cd_flags`（全 16 位，列出差异位） | `unzip_reads_cd` |
| `structure.LFH_OVERLAP` | 两个 LFH 的 `[start, end)` 相交；相邻不算 | `structural_self_evidence` |
| `structure.CD_COUNT_MISMATCH` | EOCD 声明条目数 ≠ 实际解析条目数 | `structural_self_evidence` |

不引「规范要求 LFH 与 CD 一致」——源仓逐字检索 APPNOTE 6.3.10 无此句。

### 3.2 `collision.*` 四条（跨平台折叠）

评估顺序固定 FILEDIR → CASEFOLD → NFC → TRIM；同一对名字可命中多条，全部输出。

| ruleId | windows | macos | linux | 证据强度 |
|---|---|---|---|---|
| `collision.FILEDIR` | 报 | 报 | 报 | `measured` |
| `collision.CASEFOLD` | 真实 `$UpCase` 表 | 不报 | 不报 | `table_simulated` |
| `collision.NFC` | 不报 | 报（NFD 比较） | 不报 | `medium` |
| `collision.TRIM` | 报 | 不报 | 不报 | `measured` |

写序 = CD 顺序；`survivor` = 后写者（FILEDIR 例外：先写者存活，后写者根本没落盘）；
`verdict` ∈ `overwritten` / `renamed` / `skipped`。纯裁剪差异归 TRIM，不重复记 CASEFOLD。

### 3.3 `accessibility` 四级

| 级别 | 判据 |
|---|---|
| `BLOCKED` | 空名 / 空组件 / `.` / `..` / 含 NUL / Windows 非法字符（`<>\|?*` 与控制字符）/ 单组件 > 255 个 UTF-16 码元 |
| `WRITTEN_UNREADABLE` | Windows 保留设备名出现在最后一个点之前（`CON` / `PRN` / `AUX` / `NUL` / `CLOCK$` / `COM0–9` / `LPT0–9`） |
| `WRITTEN_TRUNCATED` | Windows 尾随空格/点被裁剪；`:` 按 ADS 语义截断 |
| `OK` | 其余（不是级别，只是「无上述三情形」的标记） |

判定顺序：BLOCKED 类 → 保留名 → 裁剪；`reasons[]` / `evidence[]` 收集全部命中项。
保留名按**裁剪后**组件匹配，键取最后一个点之前的整体；`AUX.tar.gz` 不是保留名。

### 3.4 `encoding.*` 推断

- 候选顺序固定 `UTF-8 / CP437 / GBK / CP932 / CP949 / CP1251`；无法完整解码的候选**不出现**。
- `high`：bit 11 置位，或 `0x7075` 存在且 CRC 通过；`medium`：胜出候选完整解码且全部落在
  常用字区（ASCII 可打印或 Unicode `L*` / `M*` / `N*`）；`low`：其余（含 CRC 失配）。
- `0x7075` 的 `NameCRC32` 按**条目原名字节**校验；失配 → 覆盖失效、降级 `low`、
  输出 `encoding.UPATH_CRC_MISMATCH`。
- 四提取器落盘名：`python-zipfile` 读 `0x7075` → bit 11 → CP437；`info-zip-unzip` 走
  CP850 解码 + OEM→ANSI best-fit；`7zip` / `libarchive` 走声明 ANSI 码页（不做字符集探测）。
  不可解码时给 `null` + `reason`，不编造替代名。

### 3.5 `container.*` 五条

识别：`mimetype` 存在且（`META-INF/container.xml` 存在或内容为 EPUB / ODF media type）；
识别不出 → 不做容器检查。

| ruleId | 判定 |
|---|---|
| `container.MIMETYPE_NOT_FIRST` | `mimetype` 不是 CD 首条目 |
| `container.MIMETYPE_COMPRESSED` | method ≠ 0 或有加密位 |
| `container.MIMETYPE_EXTRA` | `mimetype` 带 extra field |
| `container.MIMETYPE_PADDING` | 内容前后有空白/padding（ODF 上下文 `inferred=true`） |
| `container.UTF8_REQUIRED` | EPUB 上下文里非纯 ASCII 名字且 bit 11 未置位 |

### 3.6 `budget.*` 两条

| ruleId | 判定 |
|---|---|
| `budget.PATH_OVER_260` | Windows：整路径 UTF-16 码元 + 终止 NUL > 260（**预算告警**，`kind=portability_budget`）；Linux：> 4096 字节 |
| `budget.COMPONENT_OVER_255` | Windows：单组件 > 255 个 UTF-16 码元；Linux：单组件 > 255 字节 |

`PATH_OVER_260` 不是「本机必然截断」——本机开启长路径支持时超 260 的路径可直接创建；
同一份样本的 `accessibility` 仍判 `OK`，两者不打架。

## 4. 输出示例

```console
$ traceproof check archive-extraction --input samples/archive-extraction.json \
                                      --basis samples/archive-extraction-traces.json
traceproof :: archive-extraction 1.0.1 :: archive-extraction.json
[claim] c-casefold — 主张「collision code=collision.CASEFOLD platform=windows entries=0,1 = true」与重算一致 :: s-archive-1#1#call-archive-1
[refuted] c-clean — 主张「clean = true」被重算推翻：实算 false :: s-archive-1#1#call-archive-1
…
合计 10 条，阻断 1 条（claim=9 refuted=1 inconclusive=0）        # 退出码 1
```

`--json` 顶层固定为 `{product, verb, verb_version, subject, summary, records}`；同输入两次运行
字节一致。

## 5. 与旧仓的口径差（如实登记）

1. **Python → TS 重写**；只迁判定层。字节层（EOCD / CD / LFH 解析）、CLI（`inspect` /
   `capabilities` / `platforms`）、报告排版（JSON 文本 / 文本面）、fixture 生成、工具矩阵、
   PyInstaller 与安装面**不迁**。
2. **输入从归档文件变成已解析结构事实**：`subject.archive` 携带 `ZipProbe` / `EntryView` /
   归档字节（base64）。器官不调用 `zipfile`，不读文件。
3. **退出码按本产品契约收敛**：旧仓 `0/1/2/3/4` → 新仓 `0/1/2/3`；旧 `rc 1 = 有 finding /
   collision / 不可访问条目`，新仓对应「一条 `clean=true` 主张被 `refuted`」。
   `--module` 作用域不存在：新器官始终评估五个已落地模块（与旧仓不带 `--module` 的完整 check 同口径）；
   判据 2 的旧示例用了 `--module fold`，样本归档在其余模块无产出，rc 相同。
4. **GBK / CP932 / CP949 走宿主 `TextDecoder`**（WHATWG 标签），不随包携带三张双字节表；
   CP437 / CP850 / CP1251 与 OEM→ANSI 替换表随包导入。GBK 额外做**Python gbk 字节语法预检**
   （拒绝单字节 `0x80` 与 GB18030 四字节序列，堵住 WHATWG 的两处宽化），全部 22 个 fixture
   的候选列表 / 预测名与旧仓逐值一致。
5. **deflate 的 `mimetype` 内容**用 `node:zlib` 的 `inflateRawSync`（`maxOutputLength=4097`）；
   超限时旧仓返回截断流、新器官返回「取不到」（不报 padding）——已按「不猜」登记。
6. **`$UpCase` 表用紧凑形式随包**：`data/ntfs-upcase.json` 只存 973 个非恒等映射，
   装载时重建 65536 × uint16 整表并核对 `sha256`；对不上直接 `ContractError`（退出码 3）。
7. **`display_name` 的展示形**复刻 `backslashreplace`（非法字节 → `\xNN`）；精确字节仍在
   `*_hex` 字段。
8. **排序是全序**：`Finding` 按 `(cdOffset, ruleId, entryIndex, evidence)`；
   `Collision` 按 `(min(cdOffsets), code, platform, writeOrder)`。
9. **接线副作用**：6 个既有测试文件的精确 8/9 项器官清单断言改为**精确 10 项**（测试名同步）；
   `list --json` 计数 9 → 10（`anonymity-collapse` / `tool-ops-attribution`）。
10. **D16 仓外编辑**：改动在 `01-运维-2611` 会话里 `cd` 进产品仓完成（宿主门
    `MIMOSA_GIT_GATE_MODE=warn`，graded 不会追溯扫描），供审计复核。来源仓只读，未改未删未提交。

## 6. 脚手架测试处置表（D1 + D18）

判定层 = 19 个文件名不匹配 `cli|gui|packaging|audit|desensit|guard|bench|infra|export|version|license|generat|docs?_|health|release|selftest|smoke|parse|report|input|output|web|panel`
的测试文件；实跑 **429 passed**，AST 函数 **278**。

| 源仓测试文件 | 函数 | 实跑 passed | 器官处置 |
|---|---:|---:|---|
| `test_accessibility` | 34 | 60 | **部分迁**：`judge_name` 四级 / 保留名 / 裁剪 / 顺序 / 计数已迁；报告 summary 与 CLI 面不迁 |
| `test_artifact_e2e` | 10 | 10 | 不迁（制品 / CLI / 确定性 / 安装面；由本产品 CLI 与判据 4 接管） |
| `test_budget` | 16 | 16 | **已迁**：两条规则 / 双平台口径 / 证据 / 排序；CLI 面不迁 |
| `test_container` | 17 | 20 | **已迁**：识别 / 五条规则 / ODF inferred / UTF8 边界 |
| `test_encoding` | 22 | 37 | **部分迁**：候选 / 置信度 / `0x7075` / 四提取器已迁；CLI 报告块不迁 |
| `test_encoding_skeleton` | 11 | 11 | **已迁**：`describe` / `parse_upath` / extra 切分 |
| `test_fixtures` | 8 | 8 | 不迁（fixture 生成器与 truth 文件；结构事实由输入提供） |
| `test_fold` | 40 | 50 | **已迁**：平台表校验 / 四条折叠 / 写序 / 排序；CLI 与报告面不迁 |
| `test_freeze_entry` | 3 | 3 | 不迁（PyInstaller 冻结入口） |
| `test_layout_gate` | 17 | 17 | 不迁（仓库布局门） |
| `test_m1_data` | 24 | 35 | 不迁（数据台账 / 工具矩阵 / truth 文件） |
| `test_m2_ci_assertions` | 7 | 13 | 不迁（CI 断言） |
| `test_publish_ready` | 17 | 17 | 不迁（发布就绪门） |
| `test_py39_compat` | 7 | 53 | 不迁（Python 语法兼容，参数化放大） |
| `test_readme_commands` | 7 | 23 | 不迁（README ↔ CLI 反射） |
| `test_rule_boundaries` | 6 | 24 | 不迁（Python AST 分层门；TS 器官无对应 import 图） |
| `test_structure_diff` | 18 | 18 | **已迁**：六条规则 / 豁免 / 重叠 / 计数 / 先例 |
| `test_tool_behaviour` | 8 | 8 | 不迁（真实 unzip / 7z 二进制行为对照） |
| `test_zip_reader` | 6 | 6 | 不迁（EOCD 字节解析；器官接收已解析事实） |

D1/D18 剔除（不计入 X，共 **65** 条 collected）：`test_ci_smoke_scripts` 16（`smoke`）、
`test_cli_contract` 23（`cli`）、`test_license_metadata` 8（`license`）、
`test_report_determinism` 18（`report`）。对应产品级门：CI / 唯一入口 CLI / 许可证元数据 /
确定性报告，均不在器官范围。

## 7. §7.3 四项无损判据（2026-11-26 实测）

| # | 实测 | 结论 |
|---:|---|---|
| 1 | 旧仓 D1+D18 机械选 19 文件 `pytest` 实跑 **429 passed / 0 failed**（38.14s，JUnit 对账）；新器官 `node --test test/archive-extraction.test.js` **475 passed / 0 failed** | **过**（475 ≥ 429） |
| 2 | 旧仓 README 示例 `extract-oracle check data/fixtures/case.zip --target windows --module fold` rc **1**（`collision.CASEFOLD`，survivor `README.TXT`）/ 新仓 `node bin/traceproof check archive-extraction --input samples/archive-extraction.json --basis samples/archive-extraction-traces.json --json` rc **1**（10 条主张：claim 9 / refuted 1；`clean=true` 被推翻） | **过**（rc 1 = 1；作用域差异见 §5.3） |
| 3 | 口径乙：用例 475 ≥ 429；`test(` 调用 **369** ≥ 旧层 AST **278**；文件数旧 19 → 新 1（只记录） | **过** |
| 4 | `%TEMP%` 副本 `npm run build` + `npm pack`：**269 条目 / 414513 B**；`package/lib/traceproof/verbs/archive-extraction/data/` **3 文件**（codecs 6258B / ntfs-upcase 11735B / platforms 289B，tsc 重序列化后 `JSON.parse` 深比较与源数据相等）；解包 `list` 含 `archive-extraction 1.0.1`（10 器官）、样本 `check` rc **1** | **过** |

`npm pack` 前的全量本地测试：`npm run build` rc 0；`node --test` **3062 passed / 0 failed**。

## 8. 随包数据清单

| 文件 | 字节 | sha256 | 来源 |
|---|---:|---|---|
| `data/ntfs-upcase.json` | 9780 | `61d52485581a5ed0e0a6ff8a5146871ef08614698298a884e5c2408533dfdf12` | 源仓 `data/platforms/ntfs-upcase.bin`（131072 B，`sha256 41c26b…0742`）的 973 个非恒等映射；装载时重建整表并核对 |
| `data/codecs.json` | 4159 | `01462867febcf646f2759911e5bb580d52d3f97a421e48dcb6c0109182e657c4` | 源仓 Python `cp437` / `cp850` / `cp1251` 码表与 33 条 OEM 替换表逐项导出 |
| `data/platforms.json` | 258 | `b21bdcdc3ca62e7b8ae547f5f43913185150f21261e614617e32c745129447b1` | 源仓 `meta.json` 的 macOS / Linux 副表（`evidence_strength` / `source`） |

全部数据以 `import … with { type: 'json' }` 引用；`tsc` 会发到 `lib/.../data/`，
`npm pack` 后随包分发。器官运行期不读文件、不读环境变量、不看时钟。

## 9. 本会话偏差

**D16 仓外编辑**：本次改动在 `01-运维-2611` 会话里 `cd` 进产品仓完成（宿主门
`MIMOSA_GIT_GATE_MODE=warn`，graded 模式不会追溯扫描），供审计复核。
来源仓只读、未改未删未提交；未跑 `security_scan`；未碰可见性 / DB / 删仓。