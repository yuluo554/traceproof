/**
 * hazard-triage · 受控词表与知识库装载。
 *
 * 数据是源仓 `data/knowledge/` 的**只读导出**（hazard_types / measures /
 * thresholds / rules_v1 / regulations / cases）。JSON 以 `import … with { type: 'json' }`
 * 引入，tsc 才会把它发到 `lib/.../data/`；器官运行期不读文件。
 *
 * `subject.knowledge` 可覆盖其中任意一份（测试与扩展用）；形状不合法抛
 * `KnowledgePackError`（唯一入口映射退出码 2），不静默扫出空结果。
 */

import hazardTypesData from './data/hazard-types.json' with { type: 'json' }
import measuresData from './data/measures.json' with { type: 'json' }
import thresholdsData from './data/thresholds.json' with { type: 'json' }
import rulesData from './data/rules.json' with { type: 'json' }
import regulationsData from './data/regulations.json' with { type: 'json' }
import casesData from './data/cases.json' with { type: 'json' }

import { ContractError } from '../../core/ledger.js'
import { isPlainObject, readString, readStringArray } from './util.js'

/** 知识库包不合法：输入级错误（退出码 2），不是契约违约。 */
export class KnowledgePackError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'KnowledgePackError'
  }
}

export interface ClauseRef {
  readonly standard: string
  readonly clause: string
}

export interface HazardType {
  readonly id: string
  readonly name: string
  readonly category: string
  readonly work_type: string
  readonly site_objects: readonly string[]
  readonly patterns: readonly string[]
  readonly base_level: string
  readonly measure_ids: readonly string[]
  readonly clause_refs: readonly ClauseRef[]
  readonly note?: string
}

export interface Measure {
  readonly id: string
  readonly text: string
}

export interface Threshold {
  readonly id: string
  readonly param: string
  readonly unit?: string
  readonly op: string
  readonly value?: number
  readonly range?: readonly [number, number]
  readonly level_on_violation: string
  readonly clause_ref?: ClauseRef
  readonly note?: string
}

export interface Override {
  readonly override_id: string
  readonly name?: string
  readonly match: { readonly any_of: readonly string[] }
  readonly std_id?: string
  readonly clause?: string
  readonly level: string
}

export interface ThresholdRule {
  readonly rule_id: string
  readonly threshold_id: string
  readonly hazard_type_ids: readonly string[]
  readonly level_on_violation: string
  readonly note?: string
}

export interface BaseRule {
  readonly rule_id: string
  readonly hazard_type_id: string
  readonly base_level: string
}

export interface RulePack {
  readonly meta?: Record<string, unknown>
  readonly major_patterns: readonly string[]
  readonly severity_words: readonly string[]
  readonly overrides: readonly Override[]
  readonly threshold_rules: readonly ThresholdRule[]
  readonly base_rules: readonly BaseRule[]
}

export interface Regulation {
  readonly std_id: string
  readonly std_name: string
  readonly clause: string
  readonly text: string
  readonly blocks: readonly string[]
  readonly keywords: readonly string[]
  readonly note?: string
}

export interface CaseRecord {
  readonly case_id: string
  readonly title: string
  readonly hazard_type_ids: readonly string[]
  readonly risk_level: string
}

export interface Knowledge {
  readonly categories: readonly string[]
  readonly riskLevels: readonly string[]
  readonly hazardTypes: readonly HazardType[]
  readonly hazardTypeById: ReadonlyMap<string, HazardType>
  readonly measures: readonly Measure[]
  readonly measureById: ReadonlyMap<string, Measure>
  readonly thresholds: readonly Threshold[]
  readonly thresholdById: ReadonlyMap<string, Threshold>
  readonly rules: RulePack
  readonly regulations: readonly Regulation[]
  readonly regulationByKey: ReadonlyMap<string, Regulation>
  readonly cases: readonly CaseRecord[]
}

interface KnowledgeOverride {
  hazard_types?: unknown
  measures?: unknown
  thresholds?: unknown
  rules?: unknown
  regulations?: unknown
  cases?: unknown
}

const OVERRIDE_KEYS = new Set([
  'hazard_types',
  'measures',
  'thresholds',
  'rules',
  'regulations',
  'cases',
])

function packError(message: string): never {
  throw new KnowledgePackError(message)
}

function readRecordArray(value: unknown, where: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) packError(`${where} 必须是数组`)
  return value.map((item, index) => {
    if (!isPlainObject(item)) packError(`${where}[${index}] 必须是对象`)
    return item
  })
}

function optionalStrings(raw: Record<string, unknown>, name: string, where: string): string[] {
  if (raw[name] === undefined) return []
  if (!Array.isArray(raw[name])) packError(`${where}.${name} 必须是字符串数组`)
  return raw[name].map((item, index) => {
    if (typeof item !== 'string') packError(`${where}.${name}[${index}] 必须是字符串`)
    return item
  })
}

function readClauseRefs(value: unknown, where: string): ClauseRef[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) packError(`${where} 必须是数组`)
  return value.map((item, index) => {
    if (!isPlainObject(item)) packError(`${where}[${index}] 必须是对象`)
    const standard = item.standard
    const clause = item.clause
    if (typeof standard !== 'string' || !standard.trim()) packError(`${where}[${index}].standard 必须是非空字符串`)
    if (typeof clause !== 'string' || !clause.trim()) packError(`${where}[${index}].clause 必须是非空字符串`)
    return { standard, clause }
  })
}

function readHazardTypes(value: unknown): HazardType[] {
  return readRecordArray(value, 'knowledge.hazard_types').map((raw, index) => {
    const where = `knowledge.hazard_types[${index}]`
    const id = readString(raw.id, `${where}.id`).trim()
    const name = readString(raw.name, `${where}.name`).trim()
    const category = readString(raw.category, `${where}.category`).trim()
    if (!id || !name || !category) packError(`${where} 的 id / name / category 不能为空`)
    const patterns = optionalStrings(raw, 'patterns', where)
    for (const pattern of patterns) {
      try {
        new RegExp(pattern)
      } catch (error) {
        packError(`${where}.patterns 含非法正则: ${pattern}（${(error as Error).message}）`)
      }
    }
    return {
      id,
      name,
      category,
      work_type: typeof raw.work_type === 'string' ? raw.work_type : '普通作业',
      site_objects: optionalStrings(raw, 'site_objects', where),
      patterns,
      base_level: typeof raw.base_level === 'string' && raw.base_level ? raw.base_level : '一般风险',
      measure_ids: optionalStrings(raw, 'measure_ids', where),
      clause_refs: readClauseRefs(raw.clause_refs, `${where}.clause_refs`),
      ...(typeof raw.note === 'string' ? { note: raw.note } : {}),
    }
  })
}

function readMeasures(value: unknown): Measure[] {
  return readRecordArray(value, 'knowledge.measures').map((raw, index) => {
    const where = `knowledge.measures[${index}]`
    const id = readString(raw.id, `${where}.id`).trim()
    const text = readString(raw.text, `${where}.text`).trim()
    if (!id || !text) packError(`${where} 的 id / text 不能为空`)
    return { id, text }
  })
}

function readThresholds(value: unknown): Threshold[] {
  return readRecordArray(value, 'knowledge.thresholds').map((raw, index) => {
    const where = `knowledge.thresholds[${index}]`
    const id = readString(raw.id, `${where}.id`).trim()
    const param = readString(raw.param, `${where}.param`).trim()
    const op = readString(raw.op, `${where}.op`).trim()
    if (!id || !param || !op) packError(`${where} 的 id / param / op 不能为空`)
    let thresholdValue: number | undefined
    if (raw.value !== undefined) {
      if (typeof raw.value !== 'number' || !Number.isFinite(raw.value)) {
        packError(`${where}.value 必须是有限数`)
      }
      thresholdValue = raw.value
    }
    let range: readonly [number, number] | undefined
    if (raw.range !== undefined) {
      if (!Array.isArray(raw.range) || raw.range.length !== 2) packError(`${where}.range 必须是两个数的数组`)
      const [low, high] = raw.range
      if (typeof low !== 'number' || typeof high !== 'number' || !Number.isFinite(low) || !Number.isFinite(high)) {
        packError(`${where}.range 必须是两个有限数`)
      }
      range = [low, high]
    }
    if (thresholdValue === undefined && range === undefined) {
      packError(`${where} 需要 value 或 range`)
    }
    return {
      id,
      param,
      ...(typeof raw.unit === 'string' ? { unit: raw.unit } : {}),
      op,
      ...(thresholdValue !== undefined ? { value: thresholdValue } : {}),
      ...(range !== undefined ? { range } : {}),
      level_on_violation:
        typeof raw.level_on_violation === 'string' && raw.level_on_violation
          ? raw.level_on_violation
          : '较大风险',
      ...(isPlainObject(raw.clause_ref)
        ? { clause_ref: { standard: String(raw.clause_ref.standard ?? ''), clause: String(raw.clause_ref.clause ?? '') } }
        : {}),
      ...(typeof raw.note === 'string' ? { note: raw.note } : {}),
    }
  })
}

function readRules(value: unknown): RulePack {
  if (!isPlainObject(value)) packError('knowledge.rules 必须是对象')
  const majorPatterns = optionalStrings(value, 'major_patterns', 'knowledge.rules')
  const severityWords = optionalStrings(value, 'severity_words', 'knowledge.rules')
  for (const pattern of majorPatterns) {
    try {
      new RegExp(pattern)
    } catch (error) {
      packError(`knowledge.rules.major_patterns 含非法正则: ${pattern}（${(error as Error).message}）`)
    }
  }
  const overrides = readRecordArray(value.overrides ?? [], 'knowledge.rules.overrides').map((raw, index) => {
    const where = `knowledge.rules.overrides[${index}]`
    const overrideId = readString(raw.override_id, `${where}.override_id`).trim()
    if (!overrideId) packError(`${where}.override_id 不能为空`)
    if (!isPlainObject(raw.match)) packError(`${where}.match 必须是对象`)
    const anyOf = optionalStrings(raw.match, 'any_of', `${where}.match`)
    for (const pattern of anyOf) {
      try {
        new RegExp(pattern)
      } catch (error) {
        packError(`${where}.match.any_of 含非法正则: ${pattern}（${(error as Error).message}）`)
      }
    }
    return {
      override_id: overrideId,
      ...(typeof raw.name === 'string' ? { name: raw.name } : {}),
      match: { any_of: anyOf },
      ...(typeof raw.std_id === 'string' ? { std_id: raw.std_id } : {}),
      ...(typeof raw.clause === 'string' ? { clause: raw.clause } : {}),
      level: typeof raw.level === 'string' && raw.level ? raw.level : '重大风险',
    }
  })
  const thresholdRules = readRecordArray(value.threshold_rules ?? [], 'knowledge.rules.threshold_rules').map(
    (raw, index) => {
      const where = `knowledge.rules.threshold_rules[${index}]`
      const ruleId = readString(raw.rule_id, `${where}.rule_id`).trim()
      const thresholdId = readString(raw.threshold_id, `${where}.threshold_id`).trim()
      if (!ruleId || !thresholdId) packError(`${where} 的 rule_id / threshold_id 不能为空`)
      return {
        rule_id: ruleId,
        threshold_id: thresholdId,
        hazard_type_ids: optionalStrings(raw, 'hazard_type_ids', where),
        level_on_violation:
          typeof raw.level_on_violation === 'string' && raw.level_on_violation
            ? raw.level_on_violation
            : '较大风险',
        ...(typeof raw.note === 'string' ? { note: raw.note } : {}),
      }
    },
  )
  const baseRules = readRecordArray(value.base_rules ?? [], 'knowledge.rules.base_rules').map((raw, index) => {
    const where = `knowledge.rules.base_rules[${index}]`
    const ruleId = readString(raw.rule_id, `${where}.rule_id`).trim()
    const hazardTypeId = readString(raw.hazard_type_id, `${where}.hazard_type_id`).trim()
    const baseLevel = readString(raw.base_level, `${where}.base_level`).trim()
    if (!ruleId || !hazardTypeId || !baseLevel) packError(`${where} 的字段不能为空`)
    return { rule_id: ruleId, hazard_type_id: hazardTypeId, base_level: baseLevel }
  })
  return {
    ...(isPlainObject(value.meta) ? { meta: value.meta } : {}),
    major_patterns: majorPatterns,
    severity_words: severityWords,
    overrides,
    threshold_rules: thresholdRules,
    base_rules: baseRules,
  }
}

function readRegulations(value: unknown): Regulation[] {
  return readRecordArray(value, 'knowledge.regulations').map((raw, index) => {
    const where = `knowledge.regulations[${index}]`
    const stdId = readString(raw.std_id, `${where}.std_id`).trim()
    const stdName = readString(raw.std_name, `${where}.std_name`).trim()
    const clause = readString(raw.clause, `${where}.clause`).trim()
    const text = readString(raw.text, `${where}.text`)
    if (!stdId || !stdName || !clause) packError(`${where} 的 std_id / std_name / clause 不能为空`)
    return {
      std_id: stdId,
      std_name: stdName,
      clause,
      text,
      blocks: optionalStrings(raw, 'blocks', where),
      keywords: optionalStrings(raw, 'keywords', where),
      ...(typeof raw.note === 'string' ? { note: raw.note } : {}),
    }
  })
}

function readCases(value: unknown): CaseRecord[] {
  return readRecordArray(value, 'knowledge.cases').map((raw, index) => {
    const where = `knowledge.cases[${index}]`
    const caseId = readString(raw.case_id, `${where}.case_id`).trim()
    const title = readString(raw.title, `${where}.title`).trim()
    if (!caseId || !title) packError(`${where} 的 case_id / title 不能为空`)
    return {
      case_id: caseId,
      title,
      hazard_type_ids: optionalStrings(raw, 'hazard_type_ids', where),
      risk_level: typeof raw.risk_level === 'string' ? raw.risk_level : '',
    }
  })
}

function indexBy<T>(items: readonly T[], key: (item: T) => string): Map<string, T> {
  const map = new Map<string, T>()
  for (const item of items) {
    const id = key(item)
    if (map.has(id)) packError(`知识库存在重复键：${id}`)
    map.set(id, item)
  }
  return map
}

export function buildKnowledge(override?: unknown): Knowledge {
  const base: Record<string, unknown> = {
    hazard_types: hazardTypesData.hazard_types,
    measures: measuresData.measures,
    thresholds: thresholdsData.thresholds,
    rules: rulesData,
    regulations: regulationsData,
    cases: casesData,
  }
  let merged: Record<string, unknown> = base
  if (override !== undefined) {
    if (!isPlainObject(override)) throw new ContractError('knowledge 必须是对象')
    for (const key of Object.keys(override)) {
      if (!OVERRIDE_KEYS.has(key)) throw new ContractError(`knowledge 含未知字段：${key}`)
    }
    const patch = override as KnowledgeOverride
    merged = {
      hazard_types: patch.hazard_types ?? base.hazard_types,
      measures: patch.measures ?? base.measures,
      thresholds: patch.thresholds ?? base.thresholds,
      rules: patch.rules ?? base.rules,
      regulations: patch.regulations ?? base.regulations,
      cases: patch.cases ?? base.cases,
    }
  }

  let hazardTypes: HazardType[]
  let measures: Measure[]
  let thresholds: Threshold[]
  let rules: RulePack
  let regulations: Regulation[]
  let cases: CaseRecord[]
  try {
    hazardTypes = readHazardTypes(merged.hazard_types)
    measures = readMeasures(merged.measures)
    thresholds = readThresholds(merged.thresholds)
    rules = readRules(merged.rules)
    regulations = readRegulations(merged.regulations)
    cases = readCases(merged.cases)
  } catch (error) {
    if (error instanceof ContractError) throw new KnowledgePackError(error.message)
    throw error
  }

  const declaredCategories = Array.isArray(hazardTypesData.categories) ? hazardTypesData.categories : []
  const categories = [...declaredCategories]
  for (const hazard of hazardTypes) {
    if (!categories.includes(hazard.category)) categories.push(hazard.category)
  }
  const declaredLevels = Array.isArray(hazardTypesData.risk_levels) ? hazardTypesData.risk_levels : []
  const riskLevels = declaredLevels.length > 0 ? [...declaredLevels] : ['低风险', '一般风险', '较大风险', '重大风险']

  return Object.freeze({
    categories,
    riskLevels,
    hazardTypes,
    hazardTypeById: indexBy(hazardTypes, (hazard) => hazard.id),
    measures,
    measureById: indexBy(measures, (measure) => measure.id),
    thresholds,
    thresholdById: indexBy(thresholds, (threshold) => threshold.id),
    rules,
    regulations,
    regulationByKey: indexBy(regulations, (regulation) => `${regulation.std_id}\u0000${regulation.clause}`),
    cases,
  })
}

/** 随器官打包的默认知识库（源仓 v0.3.0 / rules 1.1.0 / thresholds 0.2.0）。 */
export const DEFAULT_KNOWLEDGE: Knowledge = buildKnowledge()

export function regulationKey(standard: string, clause: string): string {
  return `${standard}\u0000${clause}`
}

export { readStringArray }