/**
 * 判据面（源仓 `m5_gate` 的闭合校验与结论组合）。
 *
 * 判据是政策输入：未知键 / 非法阈值 / 矛盾的 search 块一律 `ContractError`
 * （唯一入口映射退出码 3）。本模块不读文件：判据由 `subject` 提供。
 */

import { ContractError } from '../../core/ledger.js'
import { requirePolicy } from './classes.js'
import type { Summary } from './classes.js'
import { readClaim } from './claims.js'
import { parseDeclaration } from './declaration.js'
import type { Declaration } from './declaration.js'
import type { SearchResult } from './search.js'
import { outcomeFor } from './search.js'
import { parseTable } from './table.js'
import type { Table } from './table.js'
import {
  hasOwn,
  isBoolean,
  isPlainObject,
  readFiniteNumber,
  readInteger,
} from './util.js'

export const TOP_LEVEL_KEYS = new Set([
  'table',
  'declaration',
  'policy',
  'thresholds',
  'search',
  'claims',
])
export const THRESHOLD_KEYS = new Set(['k', 'l', 't'])
export const SEARCH_KEYS = new Set(['enabled', 'budget', 'require_exhaustive'])

export const REASON_REQUIRE_EXHAUSTIVE = 'search_budget_truncated_require_exhaustive'
export const REASON_SEARCH_NOT_EXHAUSTED = 'search_not_exhausted'

export interface Thresholds {
  readonly k: number
  readonly l: number | null
  readonly t: number | null
}

export interface SearchPolicy {
  readonly enabled: boolean
  readonly budget: number | null
  readonly require_exhaustive: boolean
}

export interface CriteriaInput {
  readonly table: Table
  readonly declaration: Declaration
  readonly policy: string
  readonly thresholds: Thresholds
  readonly search: SearchPolicy
  readonly claims: readonly unknown[]
}

export type Outcome = 'pass' | 'violation' | 'undecidable'

const OUTCOME_RANK: Readonly<Record<Outcome, number>> = {
  pass: 0,
  violation: 1,
  undecidable: 2,
}

function positiveInt(label: string, value: unknown): number {
  const number = readInteger(value, label, 1)
  return number
}

function readThresholds(raw: unknown): Thresholds {
  if (!isPlainObject(raw)) throw new ContractError('thresholds 必须是对象')
  for (const key of Object.keys(raw)) {
    if (!THRESHOLD_KEYS.has(key)) throw new ContractError(`thresholds 有未知键：${key}`)
  }
  if (!hasOwn(raw, 'k')) throw new ContractError('thresholds.k 必填（k 门限是闸门的必要条件）')
  const k = positiveInt('thresholds.k', raw.k)

  let l: number | null = null
  if (raw.l !== undefined && raw.l !== null) l = positiveInt('thresholds.l', raw.l)

  let t: number | null = null
  if (raw.t !== undefined && raw.t !== null) {
    if (typeof raw.t !== 'number' || !Number.isFinite(raw.t)) {
      throw new ContractError('thresholds.t 必须是 [0, 1] 内的数或 null')
    }
    const value = readFiniteNumber(raw.t, 'thresholds.t')
    if (value < 0 || value > 1) throw new ContractError('thresholds.t 必须落在 [0, 1]')
    t = value
  }
  return { k, l, t }
}

function readSearchPolicy(raw: unknown): SearchPolicy {
  if (raw === undefined || raw === null) {
    return { enabled: false, budget: null, require_exhaustive: false }
  }
  if (!isPlainObject(raw)) throw new ContractError('search 必须是对象')
  for (const key of Object.keys(raw)) {
    if (!SEARCH_KEYS.has(key)) throw new ContractError(`search 有未知键：${key}`)
  }
  let enabled = false
  if (raw.enabled !== undefined) {
    if (!isBoolean(raw.enabled)) throw new ContractError('search.enabled 必须是布尔值')
    enabled = raw.enabled
  }
  let budget: number | null = null
  if (raw.budget !== undefined && raw.budget !== null) {
    budget = positiveInt('search.budget', raw.budget)
  }
  let requireExhaustive = false
  if (raw.require_exhaustive !== undefined) {
    if (!isBoolean(raw.require_exhaustive)) {
      throw new ContractError('search.require_exhaustive 必须是布尔值')
    }
    requireExhaustive = raw.require_exhaustive
  }
  if (enabled && budget === null) {
    throw new ContractError('search.enabled=true 时必须给 search.budget（没有预算的搜索不可复算）')
  }
  if (!enabled && requireExhaustive) {
    throw new ContractError(
      'search.require_exhaustive=true 但 search.enabled=false（二者不能互相矛盾）',
    )
  }
  return { enabled, budget, require_exhaustive: requireExhaustive }
}

export function parseCriteriaInput(subject: Record<string, unknown>): CriteriaInput {
  for (const key of Object.keys(subject)) {
    if (!TOP_LEVEL_KEYS.has(key)) throw new ContractError(`subject 含未知顶层键：${key}`)
  }
  for (const key of ['table', 'declaration', 'policy', 'thresholds']) {
    if (!hasOwn(subject, key)) throw new ContractError(`subject 缺必填项：${key}`)
  }
  const table = parseTable(subject.table)
  const declaration = parseDeclaration(subject.declaration, table.header)
  const policy = requirePolicy(subject.policy)
  const thresholds = readThresholds(subject.thresholds)
  const search = readSearchPolicy(subject.search)

  if (declaration.qiColumns().length === 0) {
    throw new ContractError('未声明任何 qi 列，无法分组')
  }
  if ((thresholds.l !== null || thresholds.t !== null) && declaration.sensitiveColumns().length === 0) {
    throw new ContractError('判据声明了 l/t 门限但没有 sensitive 列（l/t 只在 sensitive 列上定义）')
  }
  const claims = subject.claims
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const qi = declaration.qiColumns()
  const seen = new Set<string>()
  for (const [position, raw] of claims.entries()) {
    const claim = readClaim(raw, position, qi, table.rowCount)
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }
  return { table, declaration, policy, thresholds, search, claims }
}

export function combineOutcomes(...outcomes: readonly string[]): Outcome {
  let result: Outcome = 'pass'
  for (const outcome of outcomes) {
    if (!(outcome in OUTCOME_RANK)) return 'undecidable'
    const value = outcome as Outcome
    if (OUTCOME_RANK[value] > OUTCOME_RANK[result]) result = value
  }
  return result
}

export interface GateEvaluation {
  readonly outcome: Outcome
  readonly undefined_reason: string | null
  readonly search_outcome: Outcome | null
}

export function evaluateGate(criteria: CriteriaInput, scan: Summary, searchResult: SearchResult | null): GateEvaluation {
  const searchOutcome = searchResult === null ? null : outcomeFor(searchResult)
  const outcomes: string[] = [scan.verdict]
  if (searchOutcome !== null) outcomes.push(searchOutcome)
  if (
    searchResult !== null &&
    searchResult.completeness === 'budget-truncated' &&
    criteria.search.require_exhaustive
  ) {
    outcomes.push('undecidable')
  }
  const outcome = combineOutcomes(...outcomes)

  let undefinedReason: string | null = null
  if (scan.undefined_reason !== null) {
    undefinedReason = scan.undefined_reason
  } else if (searchResult === null) {
    undefinedReason = null
  } else if (
    searchResult.completeness === 'budget-truncated' &&
    criteria.search.require_exhaustive
  ) {
    undefinedReason = REASON_REQUIRE_EXHAUSTIVE
  } else if (outcome === 'undecidable' && searchResult.completeness !== 'exhausted') {
    undefinedReason = REASON_SEARCH_NOT_EXHAUSTED
  }
  return { outcome, undefined_reason: undefinedReason, search_outcome: searchOutcome }
}