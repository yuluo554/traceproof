/**
 * 主张的解析与重算（anonymity-collapse 的 check 闭集）。
 *
 * 每条主张 = 一个可复算的数值 / 结构断言；重算在同一声明、同一缺失策略、
 * 同一阈值下进行。重算判不了（例如 search 未启用而主张搜索结论）→ 调用方记
 * `inconclusive` 并写明缺失项。
 */

import { ContractError } from '../../core/ledger.js'
import { groupRows, kOf } from './classes.js'
import type { Summary } from './classes.js'
import type { CriteriaInput, GateEvaluation } from './criteria.js'
import { ATTACKERS, risk, ruleText } from './risk.js'
import type { RiskResult } from './risk.js'
import type { SearchResult } from './search.js'
import {
  isPlainObject,
  readBoolean,
  readInteger,
  readIntegerArray,
  readRawString,
  readString,
  jsonEqual,
} from './util.js'

export const CHECKS = [
  'k',
  'l',
  't',
  'class-count',
  'histogram',
  'violations',
  'violation-count',
  'unique-records',
  'undecided-rows',
  'missing-class',
  'verdict',
  'subset-k',
  'exposed-rows',
  'collapse-sets',
  'completeness',
  'empty-set-witness',
  'declared-k',
  'monotonicity',
  'evaluated-subsets',
  'pruned-subsets',
  'search-verdict',
  'outcome',
  'undefined-reason',
  'flagged-rows',
  'attack-rule',
  'risk-verdict',
  'row-class',
  'row-class-size',
] as const

export type CheckName = (typeof CHECKS)[number]

const CHECK_FIELDS: Readonly<Record<CheckName, readonly string[]>> = {
  k: [],
  l: [],
  t: [],
  'class-count': [],
  histogram: [],
  violations: [],
  'violation-count': [],
  'unique-records': [],
  'undecided-rows': [],
  'missing-class': [],
  verdict: [],
  'subset-k': ['columns'],
  'exposed-rows': ['columns'],
  'collapse-sets': [],
  completeness: [],
  'empty-set-witness': [],
  'declared-k': [],
  monotonicity: [],
  'evaluated-subsets': [],
  'pruned-subsets': [],
  'search-verdict': [],
  outcome: [],
  'undefined-reason': [],
  'flagged-rows': ['attacker'],
  'attack-rule': ['attacker'],
  'risk-verdict': ['attacker'],
  'row-class': ['row'],
  'row-class-size': ['row'],
}

const VERDICTS = ['pass', 'violation', 'undecidable'] as const
const COMPLETENESS_VALUES = ['exhausted', 'budget-truncated', 'monotonicity-not-applicable'] as const
const SEARCH_VERDICTS = ['ok', 'no_solution'] as const

export interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: unknown
  readonly columns: readonly string[] | null
  readonly attacker: string | null
  readonly row: number | null
  readonly node: unknown
}

export interface Computed {
  readonly value: unknown
  readonly reason: string
  readonly undecidable: boolean
  readonly missing: readonly string[]
}

/** 解析一条主张；字段闭集与类型错误一律契约违约。 */
export function readClaim(raw: unknown, position: number, qiColumns: readonly string[], rowCount: number): Claim {
  const where = `claims[${position}]`
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const check = raw.check
  if (typeof check !== 'string' || !(CHECKS as readonly string[]).includes(check)) {
    throw new ContractError(`${where} 的 check 非法：<${String(check)}>（允许 ${CHECKS.join(' / ')}）`)
  }
  const checkName = check as CheckName
  const allowed = new Set<string>(['claim_id', 'check', 'asserted', 'node', ...CHECK_FIELDS[checkName]])
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new ContractError(`${where} 的字段 ${key} 不适用于 check=${checkName}`)
    }
  }
  const claimId = readString(raw.claim_id, `${where}.claim_id`)
  if (!Object.prototype.hasOwnProperty.call(raw, 'asserted')) {
    throw new ContractError(`${where} 缺 asserted`)
  }

  let columns: string[] | null = null
  if (CHECK_FIELDS[checkName].includes('columns')) {
    if (!Array.isArray(raw.columns)) throw new ContractError(`${where}.columns 必须是字符串数组`)
    columns = raw.columns.map((item, index) => readString(item, `${where}.columns[${index}]`))
    const unique = new Set(columns)
    if (unique.size !== columns.length) throw new ContractError(`${where}.columns 有重复列`)
    for (const name of columns) {
      if (!qiColumns.includes(name)) {
        throw new ContractError(`${where}.columns 的列不在 qi 候选池：${name}`)
      }
    }
  }

  let attacker: string | null = null
  if (CHECK_FIELDS[checkName].includes('attacker')) {
    if (typeof raw.attacker !== 'string' || !ATTACKERS.includes(raw.attacker)) {
      throw new ContractError(`${where}.attacker 非法：<${String(raw.attacker)}>`)
    }
    attacker = raw.attacker
  }

  let row: number | null = null
  if (CHECK_FIELDS[checkName].includes('row')) {
    row = readInteger(raw.row, `${where}.row`, 1)
    if (row > rowCount) throw new ContractError(`${where}.row 超出数据行范围（1..${rowCount}）`)
  }

  const asserted = parseAsserted(checkName, raw.asserted, where)
  return Object.freeze({ claimId, check: checkName, asserted, columns, attacker, row, node: raw.node })
}

function nullableInteger(value: unknown, where: string, minimum = 0): number | null {
  if (value === null) return null
  return readInteger(value, where, minimum)
}

function parseAsserted(check: CheckName, raw: unknown, where: string): unknown {
  switch (check) {
    case 'k':
    case 'l':
      return nullableInteger(raw, `${where}.asserted`)
    case 't':
      if (raw === null) return null
      if (typeof raw !== 'number' || !Number.isFinite(raw) || raw < 0 || raw > 1) {
        throw new ContractError(`${where}.asserted 必须是 [0, 1] 内的数或 null`)
      }
      return raw
    case 'class-count':
    case 'violation-count':
    case 'evaluated-subsets':
    case 'pruned-subsets':
    case 'exposed-rows':
    case 'subset-k':
      return check === 'subset-k'
        ? nullableInteger(raw, `${where}.asserted`)
        : readInteger(raw, `${where}.asserted`, 0)
    case 'declared-k':
      return nullableInteger(raw, `${where}.asserted`)
    case 'histogram': {
      if (!isPlainObject(raw)) throw new ContractError(`${where}.asserted 必须是对象`)
      const out: Record<string, number> = {}
      for (const [size, count] of Object.entries(raw)) {
        if (!/^\d+$/.test(size)) throw new ContractError(`${where}.asserted 的键必须是类大小：${size}`)
        out[size] = readInteger(count, `${where}.asserted[${size}]`, 0)
      }
      return out
    }
    case 'violations': {
      if (!Array.isArray(raw)) throw new ContractError(`${where}.asserted 必须是数组`)
      return raw.map((item, index) => {
        const bucket = `${where}.asserted[${index}]`
        if (!isPlainObject(item)) throw new ContractError(`${bucket} 必须是对象`)
        const allowed = new Set(['key', 'count', 'row_numbers'])
        for (const key of Object.keys(item)) {
          if (!allowed.has(key)) throw new ContractError(`${bucket} 含未知键：${key}`)
        }
        return {
          key: readString(item.key, `${bucket}.key`, true),
          count: readInteger(item.count, `${bucket}.count`, 0),
          row_numbers: readIntegerArray(item.row_numbers, `${bucket}.row_numbers`, 1),
        }
      })
    }
    case 'unique-records':
    case 'undecided-rows':
    case 'flagged-rows':
      return readIntegerArray(raw, `${where}.asserted`, 1)
    case 'missing-class': {
      if (raw === null) return null
      if (!isPlainObject(raw)) throw new ContractError(`${where}.asserted 必须是对象或 null`)
      const allowed = new Set(['k', 'row_numbers'])
      for (const key of Object.keys(raw)) {
        if (!allowed.has(key)) throw new ContractError(`${where}.asserted 含未知键：${key}`)
      }
      return {
        k: readInteger(raw.k, `${where}.asserted.k`, 0),
        row_numbers: readIntegerArray(raw.row_numbers, `${where}.asserted.row_numbers`, 1),
      }
    }
    case 'collapse-sets': {
      if (!Array.isArray(raw)) throw new ContractError(`${where}.asserted 必须是数组`)
      return raw.map((combo, index) => {
        if (!Array.isArray(combo)) throw new ContractError(`${where}.asserted[${index}] 必须是数组`)
        const columns = combo.map((item, position) =>
          readString(item, `${where}.asserted[${index}][${position}]`),
        )
        if (new Set(columns).size !== columns.length) {
          throw new ContractError(`${where}.asserted[${index}] 有重复列`)
        }
        return columns
      })
    }
    case 'verdict':
    case 'outcome': {
      if (typeof raw !== 'string' || !(VERDICTS as readonly string[]).includes(raw)) {
        throw new ContractError(`${where}.asserted 必须是 ${VERDICTS.join(' / ')} 之一`)
      }
      return raw
    }
    case 'completeness': {
      if (typeof raw !== 'string' || !(COMPLETENESS_VALUES as readonly string[]).includes(raw)) {
        throw new ContractError(`${where}.asserted 必须是 ${COMPLETENESS_VALUES.join(' / ')} 之一`)
      }
      return raw
    }
    case 'search-verdict': {
      if (typeof raw !== 'string' || !(SEARCH_VERDICTS as readonly string[]).includes(raw)) {
        throw new ContractError(`${where}.asserted 必须是 ok / no_solution 之一`)
      }
      return raw
    }
    case 'empty-set-witness':
    case 'monotonicity':
      return readBoolean(raw, `${where}.asserted`)
    case 'undefined-reason':
      if (raw === null) return null
      return readString(raw, `${where}.asserted`, true)
    case 'attack-rule':
      return readString(raw, `${where}.asserted`)
    case 'risk-verdict':
      if (typeof raw !== 'string' || !(VERDICTS as readonly string[]).includes(raw)) {
        throw new ContractError(`${where}.asserted 必须是 ${VERDICTS.join(' / ')} 之一`)
      }
      return raw
    case 'row-class':
      if (raw === null) return null
      return readRawString(raw, `${where}.asserted`)
    case 'row-class-size':
      return nullableInteger(raw, `${where}.asserted`, 1)
    default: {
      const exhaustive: never = check
      throw new ContractError(`未知 check：${String(exhaustive)}`)
    }
  }
}

export interface ComputeContext {
  readonly criteria: CriteriaInput
  readonly scan: Summary
  readonly gate: GateEvaluation
  readonly searchResult: SearchResult | null
  readonly riskResults: Map<string, RiskResult>
}

function requireSearch(
  context: ComputeContext,
  label: string,
): { result: SearchResult } | { undecidable: Computed } {
  if (context.searchResult === null) {
    return {
      undecidable: {
        value: null,
        reason: `search 未启用，无法重算${label}`,
        undecidable: true,
        missing: ['search'],
      },
    }
  }
  return { result: context.searchResult }
}

function riskFor(context: ComputeContext, attacker: string): RiskResult {
  const cached = context.riskResults.get(attacker)
  if (cached !== undefined) return cached
  const result = risk(
    context.criteria.table,
    context.criteria.declaration.qiColumns(),
    context.criteria.policy,
    attacker,
  )
  context.riskResults.set(attacker, result)
  return result
}

function valueComputed(value: unknown, reason: string): Computed {
  return { value, reason, undecidable: false, missing: [] }
}

export function computeClaim(claim: Claim, context: ComputeContext): Computed {
  const metrics = context.scan.k_l_t
  switch (claim.check) {
    case 'k':
      return valueComputed(metrics.k, `重算 k=${String(metrics.k)}`)
    case 'l':
      return valueComputed(metrics.l, `重算 l=${String(metrics.l)}`)
    case 't':
      return valueComputed(metrics.t, `重算 t=${String(metrics.t)}`)
    case 'class-count':
      return valueComputed(metrics.class_count, `重算等价类数=${metrics.class_count}`)
    case 'histogram':
      return valueComputed(metrics.class_size_histogram, '重算类大小直方图')
    case 'violations':
      return valueComputed(context.scan.violations, `重算违例 ${context.scan.violations.length} 条`)
    case 'violation-count':
      return valueComputed(context.scan.violations.length, `重算违例 ${context.scan.violations.length} 条`)
    case 'unique-records':
      return valueComputed(context.scan.unique_records, `重算唯一记录 ${context.scan.unique_records.length} 行`)
    case 'undecided-rows':
      return valueComputed(metrics.undecided_rows, `重算未裁决行 ${metrics.undecided_rows.length} 行`)
    case 'missing-class':
      return valueComputed(metrics.missing_class, metrics.missing_class === null ? '无缺失独立类' : '重算缺失独立类')
    case 'verdict':
      return valueComputed(context.scan.verdict, `重算扫描结论=${context.scan.verdict}`)
    case 'subset-k': {
      const columns = claim.columns as readonly string[]
      const k = kOf(groupRows(context.criteria.table, columns, context.criteria.policy).classes)
      return valueComputed(k, `重算子集 [${columns.join(', ')}] 的 k=${String(k)}`)
    }
    case 'exposed-rows': {
      const columns = claim.columns as readonly string[]
      const grouped = groupRows(context.criteria.table, columns, context.criteria.policy)
      const threshold = context.criteria.thresholds.k
      let exposed = 0
      for (const numbers of grouped.classes.values()) {
        if (numbers.length < threshold) exposed += numbers.length
      }
      return valueComputed(exposed, `重算子集 [${columns.join(', ')}] 的暴露行数=${exposed}`)
    }
    case 'collapse-sets': {
      const state = requireSearch(context, '崩塌边界集')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(
        state.result.minimal_collapse_sets,
        `重算崩塌边界集 ${state.result.minimal_collapse_sets.length} 组（完整性 ${state.result.completeness}）`,
      )
    }
    case 'completeness': {
      const state = requireSearch(context, '完整性')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(state.result.completeness, `重算完整性=${state.result.completeness}`)
    }
    case 'empty-set-witness': {
      const state = requireSearch(context, '空集边界证据')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(
        state.result.empty_set_witness,
        `重算 empty_set_witness=${String(state.result.empty_set_witness)}`,
      )
    }
    case 'declared-k': {
      const state = requireSearch(context, '声明集合 k')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(state.result.declared_k, `重算声明集合 k=${String(state.result.declared_k)}`)
    }
    case 'monotonicity': {
      const state = requireSearch(context, '单调性')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(
        state.result.monotonicity_applicable,
        `重算单调性适用=${String(state.result.monotonicity_applicable)}`,
      )
    }
    case 'evaluated-subsets': {
      const state = requireSearch(context, '已评估子集数')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(state.result.evaluated_subsets, `重算已评估子集=${state.result.evaluated_subsets}`)
    }
    case 'pruned-subsets': {
      const state = requireSearch(context, '剪枝子集数')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(state.result.pruned_subsets, `重算剪枝子集=${state.result.pruned_subsets}`)
    }
    case 'search-verdict': {
      const state = requireSearch(context, '搜索结论')
      if ('undecidable' in state) return state.undecidable
      return valueComputed(state.result.verdict, `重算搜索结论=${state.result.verdict}`)
    }
    case 'outcome':
      return valueComputed(context.gate.outcome, `重算 gate 结论=${context.gate.outcome}`)
    case 'undefined-reason':
      return valueComputed(
        context.gate.undefined_reason,
        context.gate.undefined_reason === null
          ? '重算无法裁决原因=null'
          : `重算无法裁决原因=${context.gate.undefined_reason}`,
      )
    case 'flagged-rows': {
      const result = riskFor(context, claim.attacker as string)
      return valueComputed(result.flagged_rows, `重算 ${result.rule} 命中 ${result.flagged_rows.length} 行`)
    }
    case 'attack-rule': {
      const attacker = claim.attacker as string
      return valueComputed(ruleText(attacker), `重算 ${attacker} 规则=${ruleText(attacker)}`)
    }
    case 'risk-verdict': {
      const result = riskFor(context, claim.attacker as string)
      return valueComputed(result.verdict, `重算风险结论=${result.verdict}`)
    }
    case 'row-class': {
      const row = claim.row as number
      const grouped = groupRows(
        context.criteria.table,
        context.criteria.declaration.qiColumns(),
        context.criteria.policy,
      )
      let found: string | null = null
      for (const [key, numbers] of grouped.classes.entries()) {
        if (numbers.includes(row)) {
          found = key
          break
        }
      }
      return valueComputed(found, found === null ? `行 ${row} 未参与分组` : `行 ${row} 的等价类键=${found}`)
    }
    case 'row-class-size': {
      const row = claim.row as number
      const grouped = groupRows(
        context.criteria.table,
        context.criteria.declaration.qiColumns(),
        context.criteria.policy,
      )
      let found: number | null = null
      for (const numbers of grouped.classes.values()) {
        if (numbers.includes(row)) {
          found = numbers.length
          break
        }
      }
      return valueComputed(found, found === null ? `行 ${row} 未参与分组` : `行 ${row} 的类大小=${found}`)
    }
    default: {
      const exhaustive: never = claim.check
      throw new ContractError(`未知 check：${String(exhaustive)}`)
    }
  }
}

export function assertedMatches(claim: Claim, computed: Computed): boolean {
  return jsonEqual(claim.asserted, computed.value)
}