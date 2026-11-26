/**
 * pattern-evidence · 界面可疑模式取证
 *
 * 一个 traceproof 器官：把「这一页在给定规则包下会产出哪些可疑模式、哪些候选被证据门禁丢掉」
 * 的主张，逐条对到**同一份归一化页面模型**的确定性重算，再挂到痕迹节点
 * （`session_id + turn + tool_call_id`）。
 *
 * 迁移来源：旧仓 `src/lib/` 的判定层（page-model / rules / engine / ordering / site-policy），
 * target-map ④ 行。浏览器扩展宿主（collector / overlay / service worker / sidepanel）、
 * 40 页合成 fixture、商店素材与发布门**不迁**：本器官只接收已归一化的节点，不碰 DOM、不读文件、
 * 不读时钟、不联网。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "page": {
 *     "url": "https://example.invalid/checkout",
 *     "scanned_at": "2026-10-18T00:00:00.000Z",
 *     "elapsed_ms": 12,
 *     "truncated": false,
 *     "nodes": [
 *       {"seq": 1, "kind": "control", "tag": "input", "text": "", "label": "自动续订会员",
 *        "attrs": {"type": "checkbox", "checked": "true"}, "style": {}, "box": {"widthPx": 16, "heightPx": 16},
 *        "nearText": "结算页", "path": "html:nth(0)>body:nth(0)>input:nth(0)"}
 *     ]
 *   },
 *   "ruleset": {"manifest": {…}, "rules": [ … ]},   // 可选；缺省 = 随器官打包的 12 条规则
 *   "settings": {"site_policy": {"mode": "blocklist", "hosts": []}, "disabled_rule_ids": []}, // 可选
 *   "claims": [
 *     {"claim_id": "c1", "check": "rule", "asserted": "reported",
 *      "rule_id": "dp-prechecked-optin", "locator": "html:nth(0)>body:nth(0)>input:nth(0)",
 *      "snippet": "自动续订会员",
 *      "node": {"session_id": "s-ui-1", "turn": 1, "tool_call_id": "call-ui-1"}}
 *   ]
 * }
 * ```
 *
 * check 闭集（`asserted` 闭集）：
 *  - `rule`：`reported` / `absent` / `suppressed` / `missing-evidence`；
 *    可附 `snippet` / `snippet_truncated` / `evidence`（证据 kind 列表）/ `finding_id` /
 *    `missing_evidence`（仅 missing-evidence）。同一 rule+locator 的重复候选（duplicate_locator）
 *    只经 `count` 的 `rejected(reason=duplicate_locator)` 观察，不单列为主张值。
 *  - `count`：`of=findings|rejected`，`asserted` 是十进制数字；`rejected` 可附 `reason` 过滤。
 *  - `order`：`exact` / `prefix`，`rule_ids`（必填）与 `finding_ids`（可选）。
 *  - `ruleset`：`valid` / `invalid`；`invalid` 时可附 `error_terms` 要求逐项出现在校验错误里。
 *  - `site`：`enabled` / `disabled`；可附 `url` / `settings` / `reason`（期望的闸门原因）。
 *  - `coverage`：`complete` / `truncated`；可附 `node_count`。
 *
 * 判定：与重算一致 → `claim`；不一致且**有痕迹节点** → `refuted`；不一致且无节点 → `inconclusive`
 * 并写明原因。重算本身不可用（规则包校验不过）→ `RulePackError` 冒到唯一入口（退出码 2）。
 */

import rulesetData from './data/ruleset.json' with { type: 'json' }
import type { Basis } from '../../core/trace-index.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'
import { buildScanResult, REJECT_REASONS } from './engine.js'
import type { ScanResult } from './engine.js'
import { parsePageNodes } from './page-model.js'
import type { PageNode } from './page-model.js'
import { loadRulePack, validateRulePack } from './rules.js'
import type { LoadedPack } from './rules.js'
import { DEFAULT_SETTINGS, hostOf, isSiteEnabled, normalizeSettings } from './site-policy.js'
import type { Settings } from './site-policy.js'
import {
  isPlainObject,
  jsonEqual,
  readFiniteNumber,
  readInteger,
  readString,
  readStringArray,
  sortedUnique,
} from './util.js'

/** 版本沿用源仓 `package.json` 的 0.2.0（不随本产品升版）。 */
export const VERSION = '0.2.0'

export const CHECKS = ['rule', 'count', 'order', 'ruleset', 'site', 'coverage'] as const
export type CheckName = (typeof CHECKS)[number]

export const ASSERTED_VALUES: Readonly<Record<Exclude<CheckName, 'count'>, readonly string[]>> = {
  rule: ['reported', 'absent', 'suppressed', 'missing-evidence'],
  order: ['exact', 'prefix'],
  ruleset: ['valid', 'invalid'],
  site: ['enabled', 'disabled'],
  coverage: ['complete', 'truncated'],
}

const GLOBAL_FIELDS = ['claim_id', 'check', 'asserted', 'node'] as const

const CHECK_FIELDS: Readonly<Record<CheckName, readonly string[]>> = {
  rule: ['rule_id', 'locator', 'snippet', 'snippet_truncated', 'evidence', 'missing_evidence', 'finding_id'],
  count: ['of', 'reason'],
  order: ['rule_ids', 'finding_ids'],
  ruleset: ['error_terms'],
  site: ['url', 'settings', 'reason'],
  coverage: ['node_count'],
}

const SUBJECT_FIELDS = new Set(['page', 'ruleset', 'settings', 'claims'])

export const DEFAULT_RULESET = {
  manifest: rulesetData.manifest,
  rules: rulesetData.rules,
} as { readonly manifest: unknown; readonly rules: unknown }

interface PageInput {
  readonly url: string
  readonly scannedAt: string
  readonly elapsedMs: number
  readonly truncated: boolean
  readonly nodes: readonly PageNode[]
}

interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: string
  readonly node: unknown
  readonly ruleId: string | null
  readonly locator: string | null
  readonly snippet: string | null
  readonly snippetTruncated: boolean | null
  readonly evidenceKinds: readonly string[] | null
  readonly missingEvidence: readonly string[] | null
  readonly findingId: string | null
  readonly of: 'findings' | 'rejected' | null
  readonly countReason: string | null
  readonly countValue: number | null
  readonly ruleIds: readonly string[] | null
  readonly findingIds: readonly string[] | null
  readonly errorTerms: readonly string[] | null
  readonly siteUrl: string | null
  readonly siteSettings: Settings | null
  readonly siteReason: string | null
  readonly nodeCount: number | null
}

interface Computed {
  readonly result: string
  readonly matched: boolean
  readonly reason: string
  readonly evidence: Readonly<Record<string, unknown>>
}

// ---------------------------------------------------------------------------
// 输入解析（只认 JSON 面；坏输入 = 契约违约，冒到唯一入口）
// ---------------------------------------------------------------------------

function readPage(raw: unknown): PageInput {
  if (!isPlainObject(raw)) throw new ContractError('page 必须是对象')
  for (const key of Object.keys(raw)) {
    if (!['url', 'scanned_at', 'elapsed_ms', 'truncated', 'nodes'].includes(key)) {
      throw new ContractError(`page 含未知字段：${key}`)
    }
  }
  const url = readString(raw.url, 'page.url')
  const scannedAt = readString(raw.scanned_at, 'page.scanned_at')
  const elapsedMs = readFiniteNumber(raw.elapsed_ms, 'page.elapsed_ms')
  if (raw.truncated !== undefined && typeof raw.truncated !== 'boolean') {
    throw new ContractError('page.truncated 必须是布尔值')
  }
  const nodes = parsePageNodes(raw.nodes, 'page.nodes')
  return { url, scannedAt, elapsedMs, truncated: raw.truncated === true, nodes }
}

interface PackCandidate {
  readonly manifest: unknown
  readonly rules: unknown
}

function readPackCandidate(raw: unknown): PackCandidate {
  if (raw === undefined) return { manifest: DEFAULT_RULESET.manifest, rules: DEFAULT_RULESET.rules }
  if (!isPlainObject(raw)) throw new ContractError('ruleset 必须是对象（{manifest, rules}）')
  for (const key of Object.keys(raw)) {
    if (key !== 'manifest' && key !== 'rules') throw new ContractError(`ruleset 含未知字段：${key}`)
  }
  if (raw.manifest === undefined || raw.rules === undefined) {
    throw new ContractError('ruleset 需要 manifest 与 rules 两个字段')
  }
  if (!Array.isArray(raw.rules)) throw new ContractError('ruleset.rules 必须是数组')
  return { manifest: raw.manifest, rules: raw.rules }
}

function optionalString(raw: Record<string, unknown>, name: string, where: string): string | null {
  if (raw[name] === undefined) return null
  if (typeof raw[name] !== 'string') throw new ContractError(`${where}.${name} 必须是字符串`)
  return raw[name] as string
}

function optionalBoolean(raw: Record<string, unknown>, name: string, where: string): boolean | null {
  if (raw[name] === undefined) return null
  if (typeof raw[name] !== 'boolean') throw new ContractError(`${where}.${name} 必须是布尔值`)
  return raw[name] as boolean
}

function optionalStringArray(raw: Record<string, unknown>, name: string, where: string): string[] | null {
  if (raw[name] === undefined) return null
  return readStringArray(raw[name], `${where}.${name}`)
}

function readClaim(raw: unknown, position: number): Claim {
  const where = `claims[${position}]`
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const check = raw.check
  if (typeof check !== 'string' || !(CHECKS as readonly string[]).includes(check)) {
    throw new ContractError(`${where} 的 check 非法：<${String(check)}>（允许 ${CHECKS.join(' / ')}）`)
  }
  const checkName = check as CheckName
  const allowed = new Set<string>([...GLOBAL_FIELDS, ...CHECK_FIELDS[checkName]])
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new ContractError(`${where} 的字段 ${key} 不适用于 check=${checkName}`)
    }
  }

  const claimId = readString(raw.claim_id, `${where}.claim_id`)
  if (typeof raw.asserted !== 'string' || raw.asserted.trim().length === 0) {
    throw new ContractError(`${where} 缺 asserted`)
  }
  const assertedText = raw.asserted.trim()
  let asserted: string
  let countValue: number | null = null
  if (checkName === 'count') {
    if (!/^\d+$/.test(assertedText)) {
      throw new ContractError(`${where} 的 asserted 必须是十进制数字（收到 <${assertedText}>）`)
    }
    countValue = Number(assertedText)
    if (!Number.isSafeInteger(countValue)) throw new ContractError(`${where} 的 asserted 超出安全整数范围`)
    asserted = assertedText
  } else {
    asserted = assertedText.toLowerCase()
    const allowedValues = ASSERTED_VALUES[checkName]
    if (!allowedValues.includes(asserted)) {
      throw new ContractError(`${where} 的 asserted 非法：<${asserted}>（${checkName} 允许 ${allowedValues.join(' / ')}）`)
    }
  }

  const ruleId = optionalString(raw, 'rule_id', where)
  const locator = optionalString(raw, 'locator', where)
  const snippet = optionalString(raw, 'snippet', where)
  const snippetTruncated = optionalBoolean(raw, 'snippet_truncated', where)
  const evidenceKinds = optionalStringArray(raw, 'evidence', where)
  const missingEvidence = optionalStringArray(raw, 'missing_evidence', where)
  const findingId = optionalString(raw, 'finding_id', where)
  const ruleIds = optionalStringArray(raw, 'rule_ids', where)
  const findingIds = optionalStringArray(raw, 'finding_ids', where)
  const errorTerms = optionalStringArray(raw, 'error_terms', where)
  const siteUrl = optionalString(raw, 'url', where)
  const siteReason = optionalString(raw, 'reason', where)

  let of: 'findings' | 'rejected' | null = null
  let countReason: string | null = null
  if (checkName === 'count') {
    if (raw.of !== 'findings' && raw.of !== 'rejected') {
      throw new ContractError(`${where} 的 of 必须是 findings 或 rejected`)
    }
    of = raw.of
    if (raw.reason !== undefined) {
      if (typeof raw.reason !== 'string' || !(REJECT_REASONS as readonly string[]).includes(raw.reason)) {
        throw new ContractError(`${where} 的 reason 非法（允许 ${REJECT_REASONS.join(' / ')}）`)
      }
      if (of !== 'rejected') throw new ContractError(`${where}：reason 只适用于 of=rejected`)
      countReason = raw.reason
    }
  }

  let siteSettings: Settings | null = null
  if (raw.settings !== undefined) siteSettings = normalizeSettings(raw.settings)

  let nodeCount: number | null = null
  if (raw.node_count !== undefined) nodeCount = readInteger(raw.node_count, `${where}.node_count`)

  if (checkName === 'rule') {
    if (ruleId === null) throw new ContractError(`${where}：rule 主张必须带 rule_id`)
    if (locator === null) throw new ContractError(`${where}：rule 主张必须带 locator`)
    const detailProvided =
      snippet !== null || snippetTruncated !== null || evidenceKinds !== null || findingId !== null
    if (detailProvided && asserted !== 'reported') {
      throw new ContractError(`${where}：snippet / evidence / finding_id 只在 asserted=reported 时有意义`)
    }
    if (missingEvidence !== null && asserted !== 'missing-evidence') {
      throw new ContractError(`${where}：missing_evidence 只在 asserted=missing-evidence 时有意义`)
    }
  }
  if (checkName === 'order') {
    if (ruleIds === null) throw new ContractError(`${where}：order 主张必须带 rule_ids`)
  }
  if (checkName === 'ruleset') {
    if (errorTerms !== null && asserted !== 'invalid') {
      throw new ContractError(`${where}：error_terms 只在 asserted=invalid 时有意义`)
    }
  }

  return {
    claimId,
    check: checkName,
    asserted,
    node: raw.node,
    ruleId,
    locator,
    snippet,
    snippetTruncated,
    evidenceKinds,
    missingEvidence,
    findingId,
    of,
    countReason,
    countValue,
    ruleIds,
    findingIds,
    errorTerms,
    siteUrl,
    siteSettings,
    siteReason,
    nodeCount,
  }
}

function resolveNode(basis: Basis, raw: unknown, claimId: string): TraceNode | null {
  if (raw === undefined || raw === null) return null
  if (!isPlainObject(raw)) throw new ContractError(`${claimId}：node 必须是对象`)
  const sessionId = raw.session_id
  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    throw new ContractError(`${claimId}：node.session_id 必须是非空字符串`)
  }
  const turnRaw = raw.turn
  let turn: number | null = null
  if (turnRaw !== undefined && turnRaw !== null) {
    const numeric = Number(turnRaw)
    if (!Number.isInteger(numeric)) throw new ContractError(`${claimId}：node.turn 必须是整数`)
    turn = numeric
  }
  const toolCallId = raw.tool_call_id
  if (typeof toolCallId !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  // 唯一取节点入口：取不到就让 NodeMissing 冒到 CLI（内核映射退出码 3）。
  return basis.ref(sessionId.trim(), turn, toolCallId)
}

// ---------------------------------------------------------------------------
// 逐 check 重算
// ---------------------------------------------------------------------------

function computeRule(scan: ScanResult, claim: Claim): Computed {
  const ruleId = claim.ruleId as string
  const locator = claim.locator as string
  const finding = scan.findings.find(
    (candidate) => candidate.rule_id === ruleId && candidate.locator === locator,
  )
  if (finding !== undefined) {
    const evidenceKinds = finding.evidence.map((item) => item.kind)
    const problems: string[] = []
    if (claim.snippet !== null && claim.snippet !== finding.snippet) {
      problems.push(`snippet 不符（账本「${finding.snippet}」≠ 主张「${claim.snippet}」）`)
    }
    if (claim.snippetTruncated !== null && claim.snippetTruncated !== finding.snippet_truncated) {
      problems.push(`snippet_truncated 不符（${String(finding.snippet_truncated)} ≠ ${String(claim.snippetTruncated)}）`)
    }
    if (claim.evidenceKinds !== null && !jsonEqual(sortedUnique(claim.evidenceKinds), sortedUnique(evidenceKinds))) {
      problems.push(`证据 kind 不符（[${sortedUnique(evidenceKinds).join(', ')}] ≠ [${sortedUnique(claim.evidenceKinds).join(', ')}]）`)
    }
    if (claim.findingId !== null && claim.findingId !== finding.finding_id) {
      problems.push(`finding_id 不符（${finding.finding_id} ≠ ${claim.findingId}）`)
    }
    const detail = `产出 ${finding.finding_id}（${ruleId}，severity=${finding.severity}）`
    if (problems.length > 0) {
      return {
        result: 'reported',
        matched: false,
        reason: `已产出 finding，但明细不符：${problems.join('；')}`,
        evidence: {
          rule_id: ruleId,
          locator,
          finding_id: finding.finding_id,
          snippet: finding.snippet,
          snippet_truncated: finding.snippet_truncated,
          evidence_kinds: evidenceKinds,
          severity: finding.severity,
          category: finding.category,
          dom_order: finding.dom_order,
        },
      }
    }
    return {
      result: 'reported',
      matched: claim.asserted === 'reported',
      reason:
        claim.asserted === 'reported'
          ? detail
          : `实际产出 finding（${finding.finding_id}），主张却是 ${claim.asserted}`,
      evidence: {
        rule_id: ruleId,
        locator,
        finding_id: finding.finding_id,
        snippet: finding.snippet,
        snippet_truncated: finding.snippet_truncated,
        evidence_kinds: evidenceKinds,
        severity: finding.severity,
        category: finding.category,
        dom_order: finding.dom_order,
      },
    }
  }

  const rejection = scan.rejected.find(
    (candidate) => candidate.rule_id === ruleId && candidate.locator === locator,
  )
  if (rejection !== undefined) {
    const mapped = rejection.reason === 'missing_evidence' ? 'missing-evidence' : rejection.reason
    const problems: string[] = []
    if (claim.missingEvidence !== null) {
      if (!jsonEqual(sortedUnique(claim.missingEvidence), sortedUnique(rejection.missing_evidence))) {
        problems.push(
          `missing_evidence 不符（[${sortedUnique(rejection.missing_evidence).join(', ')}] ≠ [${sortedUnique(claim.missingEvidence).join(', ')}]）`,
        )
      }
    }
    if (problems.length > 0) {
      return {
        result: mapped,
        matched: false,
        reason: `候选被拒绝（${rejection.reason}），但明细不符：${problems.join('；')}`,
        evidence: {
          rule_id: ruleId,
          locator,
          reject_reason: rejection.reason,
          missing_evidence: rejection.missing_evidence,
        },
      }
    }
    return {
      result: mapped,
      matched: claim.asserted === mapped,
      reason:
        claim.asserted === mapped
          ? `候选被拒绝：${rejection.reason}（${rejection.missing_evidence.join('、') || '无缺失项'}）`
          : `实际拒绝原因 ${rejection.reason}，主张却是 ${claim.asserted}`,
      evidence: {
        rule_id: ruleId,
        locator,
        reject_reason: rejection.reason,
        missing_evidence: rejection.missing_evidence,
      },
    }
  }

  return {
    result: 'absent',
    matched: claim.asserted === 'absent',
    reason:
      claim.asserted === 'absent'
        ? '该 rule_id 在此 locator 上既无 finding 也无 rejected 记录'
        : '该 rule_id 在此 locator 上既无 finding 也无 rejected 记录（不成立的主张）',
    evidence: { rule_id: ruleId, locator },
  }
}

function computeCount(scan: ScanResult, claim: Claim): Computed {
  const of = claim.of as 'findings' | 'rejected'
  const filtered =
    of === 'findings'
      ? scan.findings.length
      : scan.rejected.filter((item) => claim.countReason === null || item.reason === claim.countReason).length
  const matched = claim.countValue === filtered
  const scope = claim.countReason === null ? of : `${of}（reason=${claim.countReason}）`
  return {
    result: String(filtered),
    matched,
    reason: matched
      ? `重算 ${scope} = ${filtered}，与主张一致`
      : `重算 ${scope} = ${filtered} ≠ 主张 ${String(claim.countValue)}`,
    evidence: {
      of,
      ...(claim.countReason !== null ? { reason: claim.countReason } : {}),
      count: filtered,
    },
  }
}

function computeOrder(scan: ScanResult, claim: Claim): Computed {
  const actualRuleIds = scan.findings.map((finding) => finding.rule_id)
  const actualFindingIds = scan.findings.map((finding) => finding.finding_id)
  const claimedRuleIds = claim.ruleIds as readonly string[]
  const claimedFindingIds = claim.findingIds
  const problems: string[] = []
  if (claim.asserted === 'exact') {
    if (!jsonEqual(actualRuleIds, claimedRuleIds)) problems.push('rule_ids 与账本顺序不完全一致')
    if (claimedFindingIds !== null && !jsonEqual(actualFindingIds, claimedFindingIds)) {
      problems.push('finding_ids 与账本编号不完全一致')
    }
  } else {
    const prefix = (actual: readonly string[], claimed: readonly string[]): boolean =>
      claimed.length <= actual.length && claimed.every((value, index) => actual[index] === value)
    if (!prefix(actualRuleIds, claimedRuleIds)) problems.push('rule_ids 不是账本顺序的前缀')
    if (claimedFindingIds !== null && !prefix(actualFindingIds, claimedFindingIds)) {
      problems.push('finding_ids 不是账本编号的前缀')
    }
  }
  return {
    result: actualRuleIds.join(','),
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `账本顺序 ${claim.asserted} 成立（${actualRuleIds.join(' → ')}）`
        : `账本顺序不符：${problems.join('；')}（实际 ${actualRuleIds.join(' → ')}）`,
    evidence: {
      actual_rule_ids: actualRuleIds,
      actual_finding_ids: actualFindingIds,
      claimed_rule_ids: [...claimedRuleIds],
      ...(claimedFindingIds !== null ? { claimed_finding_ids: [...claimedFindingIds] } : {}),
    },
  }
}

function computeRuleset(candidate: PackCandidate, claim: Claim): Computed {
  const errors = validateRulePack(candidate.manifest, candidate.rules)
  const result = errors.length === 0 ? 'valid' : 'invalid'
  let matched = claim.asserted === result
  let reason =
    result === 'valid'
      ? '规则包校验通过'
      : `规则包校验失败 ${errors.length} 项：${errors[0] ?? ''}`
  if (matched && claim.asserted === 'invalid' && claim.errorTerms !== null) {
    const text = errors.join('\n')
    const missingTerms = claim.errorTerms.filter((term) => !text.includes(term))
    if (missingTerms.length > 0) {
      matched = false
      reason = `规则包确实无效，但缺少主张点名的错误项：${missingTerms.join('、')}`
    }
  }
  return {
    result,
    matched,
    reason,
    evidence: { errors, error_count: errors.length },
  }
}

function computeSite(page: PageInput, settings: Settings, claim: Claim): Computed {
  const url = claim.siteUrl ?? page.url
  const effective = claim.siteSettings ?? settings
  const gate = isSiteEnabled(url, effective)
  const result = gate.enabled ? 'enabled' : 'disabled'
  let matched = claim.asserted === result
  let reason = `站点闸门 ${result}（reason=${gate.reason}）`
  if (matched && claim.siteReason !== null && claim.siteReason !== gate.reason) {
    matched = false
    reason = `闸门结论一致，但原因不符（账本 ${gate.reason} ≠ 主张 ${claim.siteReason}）`
  }
  return {
    result,
    matched,
    reason,
    evidence: {
      host: hostOf(url),
      gate_reason: gate.reason,
      site_policy_mode: effective.site_policy.mode,
    },
  }
}

function computeCoverage(page: PageInput, claim: Claim): Computed {
  const result = page.truncated ? 'truncated' : 'complete'
  let matched = claim.asserted === result
  let reason = `扫描结果 ${result}（node_count=${page.nodes.length}）`
  if (matched && claim.nodeCount !== null && claim.nodeCount !== page.nodes.length) {
    matched = false
    reason = `扫描完整性一致，但 node_count 不符（账本 ${page.nodes.length} ≠ 主张 ${claim.nodeCount}）`
  }
  return {
    result,
    matched,
    reason,
    evidence: { truncated: page.truncated, node_count: page.nodes.length },
  }
}

// ---------------------------------------------------------------------------
// 账本行
// ---------------------------------------------------------------------------

function claimLabel(claim: Claim): string {
  switch (claim.check) {
    case 'rule':
      return `${claim.ruleId}@${claim.locator} = ${claim.asserted}`
    case 'count':
      return `${claim.of}${claim.countReason === null ? '' : `(${claim.countReason})`} = ${claim.asserted}`
    case 'order':
      return `order ${claim.asserted} = [${(claim.ruleIds ?? []).join(', ')}]`
    case 'ruleset':
      return `ruleset = ${claim.asserted}`
    case 'site':
      return `site = ${claim.asserted}`
    case 'coverage':
      return `coverage = ${claim.asserted}`
  }
}

function buildRecord(claim: Claim, computed: Computed, node: TraceNode | null): LedgerRecord {
  const verdict: Verdict = computed.matched ? CLAIM : node === null ? INCONCLUSIVE : REFUTED
  const message = computed.matched
    ? `主张「${claimLabel(claim)}」被同一份输入上的重算支持：${computed.reason}`
    : node === null
      ? `重算与主张不符（${computed.reason}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`
      : `重算推翻主张：${computed.reason}`
  return makeRecord({
    claim_id: claim.claimId,
    verdict,
    message,
    node,
    evidence: {
      check: claim.check,
      asserted: claim.asserted,
      computed: computed.result,
      comparison: computed.matched ? 'match' : 'mismatch',
      ...computed.evidence,
    },
  })
}

// ---------------------------------------------------------------------------
// 器官主体
// ---------------------------------------------------------------------------

export function evaluatePatternEvidence(
  subject: Record<string, unknown>,
  basis: Basis,
): LedgerRecord[] {
  for (const key of Object.keys(subject)) {
    if (!SUBJECT_FIELDS.has(key)) throw new ContractError(`输入含未知字段：${key}`)
  }
  const page = readPage(subject.page)
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }

  const settings = normalizeSettings(subject.settings)
  const candidate = readPackCandidate(subject.ruleset)

  const needsScan = claims.some(
    (claim) => claim.check === 'rule' || claim.check === 'count' || claim.check === 'order',
  )
  let scan: ScanResult | null = null
  if (needsScan) {
    const pack: LoadedPack = loadRulePack(candidate.manifest, candidate.rules)
    scan = buildScanResult({
      url: page.url,
      scannedAt: page.scannedAt,
      nodes: page.nodes,
      pack,
      elapsedMs: page.elapsedMs,
      truncated: page.truncated,
      disabledRuleIds: settings.disabled_rule_ids,
    })
  }

  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    let computed: Computed
    switch (claim.check) {
      case 'rule':
        computed = computeRule(scan as ScanResult, claim)
        break
      case 'count':
        computed = computeCount(scan as ScanResult, claim)
        break
      case 'order':
        computed = computeOrder(scan as ScanResult, claim)
        break
      case 'ruleset':
        computed = computeRuleset(candidate, claim)
        break
      case 'site':
        computed = computeSite(page, settings, claim)
        break
      case 'coverage':
        computed = computeCoverage(page, claim)
        break
    }
    const scanEvidence =
      claim.check === 'rule' || claim.check === 'count' || claim.check === 'order'
        ? {
            ruleset_version: (scan as ScanResult).ruleset_version,
            ruleset_hash: (scan as ScanResult).ruleset_hash,
            disabled_rule_ids: [...(scan as ScanResult).disabled_rule_ids],
          }
        : {}
    records.push(
      buildRecord(
        claim,
        { ...computed, evidence: { ...computed.evidence, ...scanEvidence } },
        node,
      ),
    )
  }
  return records
}

export const patternEvidenceVerb: Verb = register({
  slug: 'pattern-evidence',
  version: VERSION,
  summary: '界面可疑模式取证：按规则包逐节点核对证据门禁与归属，逐条核对主张',
  input_fields: ['page', 'claims'],
  evaluate: evaluatePatternEvidence,
})

export { DEFAULT_SETTINGS }
export default patternEvidenceVerb