# email-evidence · 离线邮件认证取证（SPF / DKIM / DMARC + 三方对账）

> 器官 slug `email-evidence`，版本 `1.0.0`（迁自 target-map ④ 行；版本沿用旧仓的 `v1.0.0`）。
> 本页是该器官的唯一说明处：输入 / 规则 / 输出示例 / 与旧仓的口径差异 / §7.3 四项无损判据。

## 1. 做什么

给定**一份 DNS 快照**和**一封报文的原始字节**，器官在同一份证据上确定性地重算
SPF（RFC 7208）/ DKIM（RFC 6376 + RFC 8301）/ DMARC（RFC 9989），再与报文里的
`Authentication-Results`（RFC 8601）对账；然后逐条回答 agent 的「主张」：

| verdict | 含义 |
|---|---|
| `claim` | 主张与重算一致 |
| `refuted` | 主张被重算**推翻**（必须有痕迹节点） |
| `inconclusive` | 重算判不了（数据缺口 / undecidable），或主张**没有挂痕迹节点** |

器官**不打印、不读文件、不读环境变量、不读时钟、不带参数解析器**。
DNS 与报文都由 subject 提供；文件读取是唯一入口 `bin/traceproof` 的职责。
证据只经内核 `makeRecord()` 入账（**脱敏前置**在核心里）；报文原文与邮箱地址**不进证据**。

## 2. 输入（subject）

```json
{
  "snapshot": {
    "schema_version": 1,
    "fetched_at": "2026-10-19T18:35:00Z",
    "resolver": "synthetic",
    "psl_version": "2026-10-20_08-40-56_UTC",
    "psl_date": "2026-10-20",
    "queries": [
      {"qname": "_dmarc.example.com", "qtype": "TXT", "rcode": "NOERROR",
       "answer": ["v=DMARC1; p=reject"], "ttl": 300}
    ]
  },
  "query": {
    "mail_from": "alice@example.com",
    "client_ip": "192.0.2.10",
    "helo": "mail.example.com",
    "trusted_authserv_ids": ["mx.example.com"]
  },
  "message_b64": "<原始报文 base64>",
  "claims": [
    {"claim_id": "spf-pass", "check": "spf", "asserted": "pass",
     "node": {"session_id": "s-mail-1", "turn": 1, "tool_call_id": "call-spf-1"}}
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `snapshot` | 是 | `schema_version` 必须为 `1`；`fetched_at` / `resolver` / `psl_version` / `psl_date` 非空；`queries` 是**有序列表**（同名多次查询可见） |
| `query` | 是 | `mail_from`（空发件人写 `""`）、`client_ip`、`helo`、`trusted_authserv_ids` |
| `message_b64` | 否 | 原始报文（base64，字节级保真）；也可给 `message`（UTF-8 文本）。DKIM / DMARC / 对账需要它 |
| `claims` | 是 | 非空数组；`claim_id` 唯一 |

`claims[]` 字段：

| 字段 | 说明 |
|---|---|
| `claim_id` | 账本稳定键的一部分（重复即契约违约） |
| `check` | `spf` / `dkim` / `dmarc` / `reconcile` |
| `asserted` | **闭集**：spf `none/neutral/pass/fail/softfail/temperror/permerror/undecidable`；dkim `none/pass/fail/permerror/undecidable`；dmarc `none/pass/fail/undecidable`；reconcile `none/consistent/contradiction/undecidable` |
| `asserted_disposition` | 仅 dmarc：`none/quarantine/reject/null`；给了就**同时**比对处置 |
| `signature_index` | 仅 dkim：比第几条签名（默认 0；越界 → inconclusive） |
| `node` | 痕迹节点 `{session_id, turn, tool_call_id}`；缺省 → 无节点 |

## 3. 规则

1. **只从快照取值**：`found=false` 一律是**数据缺口**（→ `inconclusive` 并列出缺的
   `qname/qtype`），绝不读成「没有记录」。
2. **先校验、后求值**（RFC 7208 §4.6）：任何位置的语法错都是 `permerror`，即使前面的
   机制已经匹配。
3. **include 树完整展开**：树的构建用独立 shadow 预算，不参与判定（`tree` 只进证据摘要，
   证据里给节点数，不给整棵树）。
4. **`refuted` 必须带节点**：主张与重算不符但没有 `node` → 判 `inconclusive` 并写明
   「不能下 refuted」；节点在 basis 里不存在 → `NodeMissing` 冒到 CLI（退出码 3）。
5. **节点不完整**（缺 `turn` 或 `tool_call_id`）→ 由内核降级 `inconclusive`，
   `message` 追加「痕迹节点不完整：缺 …」。
6. **多签名不短路**：DKIM 逐条独立；`dkim` 主张用 `signature_index` 指定要比哪条。
7. **对账 fail-closed**：`trusted_authserv_ids` 为空 ≠ 全部可信；不可解析的
   `Authentication-Results` 与不可比的 method 都判 `undecidable`；每条 `contradiction`
   给 ≥2 条可能解释与各自要查什么，解释里不出现定性词。

### 引擎覆盖

| 模块 | RFC | 覆盖要点 |
|---|---|---|
| SPF | 7208 §4–§7 | 全机制（`all/include/a/mx/ptr/ip4/ip6/exists`）、限定符、CIDR 与 dual-cidr、宏（含 `%{p}` 灰区）、`redirect` / `exp`、term/MX/PTR/void/depth 预算、include 树 |
| DKIM | 6376 §3.4/§3.5/§3.7/§6.1 + 8301 | simple/relaxed 头与正文规范化、`bh`/`b`、`l=`、`h=` 选择（同名取最靠下）、多签名、密钥状态 `ok/revoked/missing/weak/invalid`、`rsa-sha1` → permerror、`ed25519-sha256` → undecidable、`t=`/`x=` 不参与判定 |
| DMARC | 9989 §4.10/§5.3 | DNS Tree Walk（含 ≥8 标签跳步）、`psd=` 改变 Organizational Domain、Author → Organizational → PSD 发现、`p/sp/np` 选择、`t=y` 降级、`pct/rf/ri` 删除告警、relaxed/strict 双算 |
| 对账 | 8601 | `authserv-id`（含版本）/ method / result / `header.d`、可信列表、三分类、≥2 条解释 |

## 4. 输出示例

```console
$ traceproof check email-evidence --input samples/email-evidence-dmarc-b41.json \
                                  --basis samples/email-evidence-traces.json
traceproof :: email-evidence 1.0.0 :: email-evidence-dmarc-b41.json
[claim] dkim-pass — 主张「dkim=pass」被同一份快照上的重算支持 :: s-mail-1#2#call-dkim-2
[claim] dmarc-pass — 主张「dmarc=pass」被同一份快照上的重算支持 :: s-mail-1#3#call-dmarc-3
[claim] reconcile-consistent — 主张「reconcile=consistent」被同一份快照上的重算支持 :: s-mail-1#4#call-ar-4
[claim] spf-pass — 主张「spf=pass」被同一份快照上的重算支持 :: s-mail-1#1#call-spf-1
合计 4 条，阻断 0 条（claim=4 refuted=0 inconclusive=0）
# 退出码 0
```

`--json` 的账本行（每行含 `basis_ref` 与已脱敏 `evidence`）：

```json
{
  "id": "dmarc-pass@s-mail-1#3#call-dmarc-3",
  "claim_id": "dmarc-pass",
  "verdict": "claim",
  "message": "主张「dmarc=pass」被同一份快照上的重算支持",
  "basis_ref": {"session_id": "s-mail-1", "turn": 3, "tool_call_id": "call-dmarc-3", "quote": "…"},
  "evidence": {
    "claimed": "pass", "check": "dmarc",
    "author_domain": "example.com", "organizational_domain": "example.com",
    "disposition": null, "disposition_status": "not_applicable",
    "evidence_ref": ["RFC9989#4.10", "RFC9989#4.10.1", "RFC9989#4.10.2", "RFC9989#4.4", "RFC9989#5.3.5"],
    "comparison": "match"
  }
}
```

`refuted` 时 `verdict` 为 `refuted` 且退出码 1；无节点时同一条会落 `inconclusive`
（退出码 0）并在 `message` 里写明「不能下 refuted」。数据缺口时 `message` 列出缺失项：

```text
[inconclusive] dkim-pass — 痕迹不足以判定：重算判不了（undecidable）：…；缺失项：sel20261021._domainkey.example.com/TXT
```

## 5. 与旧仓的口径差异（逐条登记）

| # | 差异 | 原因 / 影响 |
|---|---|---|
| 1 | **void 超限判 `undecidable`**（RFC 原文是 SHOULD，不是 permerror） | 与旧仓一致；RFC 7208 上游套件里**唯一**一条不匹配（`Processing limits/void-over-limit`），测试里显式登记 |
| 2 | PTR 超 10 条**只取前 10 条**（不判 permerror） | 与旧仓一致（§4.6.4 的 MUST 是「忽略超出部分」） |
| 3 | `%{p}` 缺 PTR 且由含该宏的机制决定结果 → `undecidable` | 与旧仓一致（灰区 4），不默认判 `fail` |
| 4 | `%{t}` 在判定路径不可展开（无时钟） | 与旧仓一致；`exp=` 文本里的 `%{t}` 被忽略并告警 |
| 5 | `l=` 大于规范化正文长度、`a=rsa-sha1` → `permerror` | 与旧仓一致（RFC 8301 §3.1；dkimpy 会把前者静默取全量） |
| 6 | **RSA 验签改用 `node:crypto`**，不迁旧仓 `crypto/der.py` + `crypto/rsa.py` 的手写 DER/PKCS#1 | 平台标准库就是本仓的「零第三方依赖」实现；判据是**结果一致**：11 个 DKIM fixture（含 512 位弱密钥、revoked、多签名、`l=` 两种边界）逐键相同 |
| 7 | PSL 冻结件从 `.dat` 转成 **JSON**（`data/psl-rules.json` + `data/psl-meta.json`） | 本仓约定「器官静态数据只放 `data/*.json`」；规则语义不变（10396 条），仍**只作对照**，判定用 tree walk（RFC 9989 §4.10.2） |
| 8 | **Received 链跳数 / 单调性 / 时钟回退未迁** | 旧仓把它作为对账的人读提示，不参与三分类判定；本器官的三分类与解释完整保留。补回属增强项，见「未解问题」 |
| 9 | `--strict-evidence` 的**禁词门**未做成开关 | 器官不做输出排版；解释文本按不含定性词编写，并由测试逐词断言（`攻击/伪造/被黑/…`） |
| 10 | 一个测试文件承载全部用例 | 本仓器官测试布局固定为 `test/<slug>.test.js`（`docs/traceproof.md` §6）；旧仓是 18 个文件。**文件数不可对齐**，函数/用例数已对齐，见 §6 判据 3 |

## 6. §7.3 四项无损判据（实测）

> 迁自 target-map ④ 行（旧仓 v1.0.0）。
> 命令与原始输出见主对话交付报告；本节只记实测值。

**判据 1：旧仓判定层实跑 466 / 新仓实跑 504 / 过（504 ≥ 466）。**

> 计数口径（§3.0）：`node --test test/email-evidence.test.js` → `ℹ tests 504`。
> 顶层 `test(` 字面量 **486** 条，其余 18 条由数据表生成；486 里含显式展开的
> RFC 7208 上游套件 203 条与 DKIM/DMARC fixture 逐键 101 条（断言逻辑集中在
> `assertRfcCase` / `assertDkimKey` / `assertDmarcKey`，不重复写断言）。
> 静态 grep 仍会低估生成用例，验收以 `node --test` 为准。

| # | 判据 | 旧仓实测 | 本仓实测 | 结论 |
|---|---|---|---|---|
| 1 | 旧仓**判定层**实跑用例数（§3.0） | 判定层 **14 文件** → `pytest <文件…> -q` → **466 passed**，rc 0（静态 392；全量 477 passed 含非判定层） | 本器官测试 **504 passed**（`node --test test/email-evidence.test.js`） | **过**（504 ≥ 466） |
| 2 | README 示例命令 rc 相同 | 旧仓 `audit --snapshot fixtures/dmarc/b41/snap.json --eml … --query …` → **rc 0**（pass 3 / fail 0 / undecidable 0） | `traceproof check email-evidence --input samples/email-evidence-dmarc-b41.json --basis samples/email-evidence-traces.json` → **rc 0**（claim 4 / blocking 0） | **过**（同一份 b41 数据、同为「全通过」） |
| 3 | 测试文件数 / 函数数 | 判定层 **14** 文件 / **392** `def test_`（实跑 466，参数化展开） | **口径乙（2026-11-25 用户裁决）**：文件数按域计 → **1 文件**（容器数 ≠ 覆盖数）；函数数按条计 → `test(` 字面量 **489**（顶层 486 + 数据表生成）；用例 **504** | **过**（489 ≥ 392；用例 504 ≥ 466） |
| 4 | `data/` 进包 | 旧仓 `pip wheel`：**30 文件**，`data/` **2 条**（`psl.meta.json` 484 B、`public_suffix_list.dat` 338010 B） | `npm pack` → `dsh-prompt-polisher-0.2.0.tgz`（185581 B，129 文件），`lib/traceproof/verbs/email-evidence/data/` **2 条**：`psl-meta.json` 717 B、`psl-rules.json` 266542 B（`tsc` 复制 JSON 时按 4 空格重排，源文件 183354 B） | **过**（2 条 data 均非空，与旧包 2 条对应） |

### 6.1 脚手架测试处置表（§3.0 要求，逐文件）

判定层口径剔除的 2 个文件（合计 11 个静态用例）：

| 旧仓测试文件 | 静态用例 | 处置 |
|---|---:|---|
| `tests/test_license_metadata.py` | 7 | **舍弃**：该文件守的是 Python 打包元数据（PEP 639 / `license-files` / `pyproject` 字段）。本仓是 npm 包：许可证由 `package.json` 的 `license: MIT` 与根 `LICENSE` 表达，发布件由 `npm pack`（判据 4）与 CI 检查覆盖；`pyproject` 语义在 TS 产品里不适用，无法"接管"到同一判据 |
| `tests/test_version_consistency.py` | 4 | **未接管（记为未解问题）**：它守"版本单一真源"（旧仓 `__init__.py` ↔ `pyproject`）。本仓目前是 `src/traceproof/index.ts` 的 `VERSION` 与 `package.json` 两处，器官版本在 `register({version})` 又是第三处；本次未新增版本门（避免自造口径），已在交付报告「未解问题」登记 |

**判据 1 的旧仓实跑**：
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. py -3.12 -m pytest <判定层 14 文件…> -q -o addopts="" -p no:cacheprovider`
→ `466 passed in 6.36s`（判定层 14 文件；静态 392）。
全量跑（含 2 个脚手架文件）本机为 `477 passed`；主对话记录为 `475 passed / 3 skipped`，两者都不改变 X=466。

**判据 4 的 TS 替换理由**：TS 产品用 `npm pack` / `pnpm pack` 取代 `pip wheel`——
两者都是「按包清单把文件装进发布件」。`package.json` 的 `files` 只登记 `lib`
（构建产物），`tsc` 在 `resolveJsonModule` 下把 `src/**/data/*.json` 复制到 `lib/**/data/`，
所以「发布件里该器官的 `data/` 非空」与 Python 的 `package-data` 是同一件事。

**判据 2 的旧仓实跑**：旧仓 `audit --snapshot fixtures/dmarc/b41/snap.json --eml fixtures/dmarc/b41/message.eml --query fixtures/dmarc/b41/query.json --json -`
→ rc 0；`summary.counts = {pass: 3, fail: 0, undecidable: 0}`。

## 7. 静态数据与许可

| 文件 | 内容 | 许可 |
|---|---|---|
| `data/psl-rules.json` | Public Suffix List（2026-10-20 版，10396 条；ICANN 6949 / PRIVATE 3447） | **MPL 2.0**（上游头部声明随 `psl-meta.json` 带入） |
| `data/psl-meta.json` | 版本 / 日期 / 来源 URL / 上游 .dat 的 sha256 / 许可说明 | 同上 |
| `test/fixtures/email-evidence/rfc7208-suite.json` | openspf.org RFC 7208 测试集（2014.04，203 用例，**测试期专用**，不进发布件） | BSD 式许可（全文在 JSON `_license_text`，副本见同目录 `rfc7208-tests.LICENSE`） |
| `test/fixtures/email-evidence/upstream/` | 旧仓 11 个 DKIM + 6 个 DMARC fixture 的只读拷贝（测试期专用） | 见各 `README.md` |

## 8. 不做的事

- 不联网、不抓 DNS（快照由输入给出；旧仓的 `snapshot fetch` 不在本产品里）。
- 不渲染 Markdown、不写文件、不打印；输出排版属唯一入口。
- 不把 `undecidable` 折叠成 `fail`；不猜「哪一行被改」。
- 不做 `whatif` / `diff` 子命令（反事实差分不在本器官的判定面内）。