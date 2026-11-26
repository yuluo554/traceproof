/**
 * anonymity-collapse · 匿名性崩塌取证
 *
 * 一个 traceproof 器官：把「这张表在给定列角色声明 / 缺失策略 / 阈值下，k/l/t 是多少、
 * 哪几列组合会让 k 崩塌、哪些行被唯一识别」的主张，逐条对到**同一份数据快照**的
 * 确定性重算，再挂到痕迹节点（`session_id + turn + tool_call_id`）。
 *
 * 迁移来源：target-map ④ 行（旧仓判定层 M2/M3/M4/M5）。旧仓的 CSV/TSV 读取、CLI、
 * Markdown 报告、判据文件路径解析与示例脚本**不迁**：器官只接收已解析对象，
 * 不读文件、不读环境变量、不读时钟、不打印、不带参数解析器。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "table": {"header": ["age", "zip", "disease"],
 *             "rows": [["30", "100", "flu"], ["31", "100", "cold"]]},
 *   "declaration": {"columns": {"age": {"role": "qi"}, "zip": {"role": "qi"},
 *                               "disease": {"role": "sensitive"}}},
 *   "policy": "drop",
 *   "thresholds": {"k": 2, "l": null, "t": null},
 *   "search": {"enabled": true, "budget": 100, "require_exhaustive": false},
 *   "claims": [
 *     {"claim_id": "c1", "check": "k", "asserted": 1,
 *      "node": {"session_id": "s-anon-1", "turn": 1, "tool_call_id": "call-anon-1"}}
 *   ]
 * }
 * ```
 *
 * `check` 闭集见 `claims.CHECKS`；`asserted` 类型随 check 而定。搜索相关主张要求
 * `search.enabled=true`；否则重算判不了 → `inconclusive` 并写明缺失项。
 *
 * 判定：重算一致 → `claim`；不一致且**有痕迹节点** → `refuted`；不一致且无节点
 * → `inconclusive`；重算判不了 → `inconclusive`。节点不完整（缺 turn / tool_call_id）
 * 由内核降级 `inconclusive`。
 */

import type { Basis } from '../../core/trace-index.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'

import { CHECKS, computeClaim, readClaim } from './claims.js'
import type { Claim, ComputeContext, Computed } from './claims.js'
import { summarize } from './classes.js'
import type { Summary } from './classes.js'
import { evaluateGate, parseCriteriaInput } from './criteria.js'
import type { CriteriaInput, GateEvaluation } from './criteria.js'
import { risk } from './risk.js'
import type { RiskResult } from './risk.js'
import { search } from './search.js'
import type { SearchResult } from './search.js'
import { isPlainObject, jsonEqual } from './util.js'

/** 版本沿用源仓 `__version__` 的 0.1.1（不随本产品升版）。 */
export const VERSION = '0.1.1'

export { CHECKS }

function renderValue(value: unknown): string {
  if (value === undefined) return 'undefined'
  try {
    return JSON.stringify(value) as string
  } catch {
    return String(value)
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
  if (typeof raw.tool_call_id !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  return basis.ref(sessionId.trim(), turn, raw.tool_call_id)
}

function compare(claim: Claim, computed: Computed): {
  verdict: Verdict
  comparison: 'match' | 'mismatch' | 'undecidable'
  detail: string
} {
  if (computed.undecidable) {
    return {
      verdict: INCONCLUSIVE,
      comparison: 'undecidable',
      detail: `重算判不了：${computed.reason}`,
    }
  }
  const matched = jsonEqual(claim.asserted, computed.value)
  if (matched) {
    return {
      verdict: CLAIM,
      comparison: 'match',
      detail: `主张「${claim.check}=${renderValue(claim.asserted)}」被数据重算支持（${computed.reason}）`,
    }
  }
  return {
    verdict: REFUTED,
    comparison: 'mismatch',
    detail: `主张 <${renderValue(claim.asserted)}> ≠ 重算 <${renderValue(computed.value)}>（${computed.reason}）`,
  }
}

function buildSummary(stats: Summary, searchResult: SearchResult | null): Record<string, unknown> {
  return {
    scan: {
      k: stats.k_l_t.k,
      l: stats.k_l_t.l,
      t: stats.k_l_t.t,
      class_count: stats.k_l_t.class_count,
      violation_count: stats.violations.length,
      unique_records: stats.unique_records.length,
      undefined_reason: stats.undefined_reason,
      verdict: stats.verdict,
    },
    search:
      searchResult === null
        ? null
        : {
            verdict: searchResult.verdict,
            completeness: searchResult.completeness,
            minimal_collapse_sets: searchResult.minimal_collapse_sets,
            empty_set_witness: searchResult.empty_set_witness,
            declared_k: searchResult.declared_k,
            evaluated_subsets: searchResult.evaluated_subsets,
            pruned_subsets: searchResult.pruned_subsets,
            monotonicity_applicable: searchResult.monotonicity_applicable,
          },
  }
}

function baseEvidence(criteria: CriteriaInput, stats: Summary, searchResult: SearchResult | null): Record<string, unknown> {
  return {
    dataset: {
      rows: criteria.table.rowCount,
      columns: [...criteria.table.header],
      policy: criteria.policy,
      qi_columns: criteria.declaration.qiColumns(),
      sensitive_columns: criteria.declaration.sensitiveColumns(),
      thresholds: { ...criteria.thresholds },
      search_enabled: criteria.search.enabled,
    },
    ...buildSummary(stats, searchResult),
    disclosure:
      '崩塌边界集是同一份数据 + 同一声明 + 同一缺失策略下的可复算结果，不是该表的绝对隐私水平。',
  }
}

export function evaluate(subject: Record<string, unknown>, basis: Basis): LedgerRecord[] {
  const criteria = parseCriteriaInput(subject)
  const qi = criteria.declaration.qiColumns()
  const sensitive = criteria.declaration.sensitiveColumns()

  const stats = summarize(
    criteria.table,
    qi,
    sensitive,
    criteria.policy,
    criteria.thresholds.k,
    criteria.thresholds.l,
    criteria.thresholds.t,
  )

  let searchResult: SearchResult | null = null
  if (criteria.search.enabled) {
    searchResult = search(
      criteria.table,
      qi,
      sensitive,
      criteria.policy,
      criteria.thresholds.k,
      criteria.search.budget,
      false,
    )
  }
  const gate: GateEvaluation = evaluateGate(criteria, stats, searchResult)

  const claims: Claim[] = criteria.claims.map((raw, position) =>
    readClaim(raw, position, qi, criteria.table.rowCount),
  )
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }

  const riskResults = new Map<string, RiskResult>()
  const context: ComputeContext = { criteria, scan: stats, gate, searchResult, riskResults }
  const records: LedgerRecord[] = []

  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    const computed = computeClaim(claim, context)
    const outcome = compare(claim, computed)

    const verdict: Verdict =
      outcome.verdict === REFUTED && node === null ? INCONCLUSIVE : outcome.verdict

    const parts: string[] = []
    if (outcome.comparison === 'match') {
      parts.push(`主张「${claim.check}=${renderValue(claim.asserted)}」被数据重算支持`)
    } else if (outcome.comparison === 'mismatch') {
      parts.push(
        node === null
          ? `数据重算与主张不符（${outcome.detail}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`
          : `数据重算推翻主张：${outcome.detail}`,
      )
    } else {
      parts.push(`数据重算判不了：${computed.reason}`)
    }
    if (computed.missing.length > 0) parts.push(`缺失项：${computed.missing.join('、')}`)

    const evidence: Record<string, unknown> = {
      check: claim.check,
      claimed: claim.asserted,
      computed: computed.value,
      comparison: outcome.comparison,
      ...(claim.columns === null ? {} : { columns: [...claim.columns] }),
      ...(claim.attacker === null ? {} : { attacker: claim.attacker }),
      ...(claim.row === null ? {} : { row: claim.row }),
      ...baseEvidence(criteria, stats, searchResult),
    }

    records.push(
      makeRecord({
        claim_id: claim.claimId,
        verdict,
        message: parts.join('；'),
        node,
        evidence,
      }),
    )
  }
  return records
}

export const anonymityCollapseVerb: Verb = register({
  slug: 'anonymity-collapse',
  version: VERSION,
  summary: '匿名性崩塌取证：等价类 k/l/t、崩塌边界集搜索与逐记录风险，逐条核对主张',
  input_fields: ['table', 'declaration', 'policy', 'thresholds', 'claims'],
  evaluate,
})

export default anonymityCollapseVerb