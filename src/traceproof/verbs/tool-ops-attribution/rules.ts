/**
 * tool-ops-attribution · 规则包装载与门控（迁移自源仓 `config.py`）。
 *
 * 源仓从 `data/rules/` 读三件套（thresholds / params / failure_patterns）；
 * 器官把三份数据随模块导入（`import … with { type: 'json' }`），运行期不读文件。
 *
 * 门控（源仓 K10）：失败模式规则**同时**满足 `status === "verified"` 与
 * `verified_samples` 非空才进计算路径；其余规则落 `other`，并在产出里逐条列出原因。
 * 规则包结构非法 → `RulePackError`（唯一入口映射退出码 2），不静默扫出空结果。
 */

import paramsData from './data/params.json' with { type: 'json' }
import thresholdsData from './data/thresholds.json' with { type: 'json' }
import patternsData from './data/failure-patterns.json' with { type: 'json' }

import { isPlainObject } from './util.js'

export const STATUS_VERIFIED = 'verified'

export class RulePackError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RulePackError'
  }
}

export interface RetryParams {
  readonly window_seconds: number
  readonly [key: string]: unknown
}

export interface OrganParams {
  readonly retry: RetryParams
  readonly rate_precision: number
  readonly error_text?: { readonly max_chars?: number; readonly [key: string]: unknown }
  readonly [key: string]: unknown
}

export interface Thresholds {
  readonly min_samples: {
    readonly calls_total_gte: number
    readonly token_samples_gte: number
    readonly [key: string]: unknown
  }
  readonly remove_candidate: {
    readonly failure_rate_gte: number
    readonly [key: string]: unknown
  }
  readonly investigate: {
    readonly failure_rate_gte: number
    readonly failure_rate_lt: number
    readonly [key: string]: unknown
  }
  readonly cost_heavy: {
    readonly turn_token_avg_gte: number
    readonly [key: string]: unknown
  }
  readonly [key: string]: unknown
}

export interface CompiledPattern {
  readonly pattern: string
  readonly regex: RegExp
}

export interface RuleSpec {
  readonly id: string
  readonly category?: string
  readonly status: string
  readonly patterns: readonly CompiledPattern[]
  readonly verified_samples: readonly unknown[]
  readonly [key: string]: unknown
}

export interface IneffectiveRule {
  readonly id: string
  readonly reasons: readonly string[]
}

export interface RulePack {
  readonly params: OrganParams
  readonly thresholds: Thresholds
  readonly categories: readonly string[]
  readonly rules: readonly RuleSpec[]
  readonly effective: readonly RuleSpec[]
  readonly ineffective: readonly IneffectiveRule[]
}

/** 默认规则包（随器官打包；测试与演示可直接使用）。 */
export const DEFAULT_RULES = {
  params: paramsData as unknown as OrganParams,
  thresholds: thresholdsData as unknown as Thresholds,
  failure_patterns: patternsData as unknown as Record<string, unknown>,
} as const

function numberAt(
  raw: Record<string, unknown>,
  section: string,
  key: string,
  errors: string[],
  integer = false,
): number {
  const block = raw[section]
  if (!isPlainObject(block)) {
    errors.push(`${section} 必须是对象`)
    return 0
  }
  const value = block[key]
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    errors.push(`${section}.${key} 缺失或非数值`)
    return 0
  }
  if (integer && !Number.isInteger(value)) {
    errors.push(`${section}.${key} 必须是整数`)
    return 0
  }
  return value
}

function validateParams(raw: unknown, errors: string[]): OrganParams {
  if (!isPlainObject(raw)) {
    errors.push('params 必须是对象')
    return DEFAULT_RULES.params
  }
  if (!isPlainObject(raw.retry)) {
    errors.push('params.retry 必须是对象')
  }
  if (!isPlainObject(raw.error_text)) {
    if (raw.error_text !== undefined) errors.push('params.error_text 必须是对象')
  } else if (
    raw.error_text.max_chars !== undefined &&
    (typeof raw.error_text.max_chars !== 'number' || !Number.isInteger(raw.error_text.max_chars))
  ) {
    errors.push('params.error_text.max_chars 必须是整数')
  }
  numberAt(raw, 'retry', 'window_seconds', errors, true)
  // rate_precision 在顶层而非分段：单独校验。
  if (typeof raw.rate_precision !== 'number' || !Number.isInteger(raw.rate_precision)) {
    errors.push('params.rate_precision 缺失或非整数')
  }
  return raw as unknown as OrganParams
}

function validateThresholds(raw: unknown, errors: string[]): Thresholds {
  if (!isPlainObject(raw)) {
    errors.push('thresholds 必须是对象')
    return DEFAULT_RULES.thresholds
  }
  numberAt(raw, 'min_samples', 'calls_total_gte', errors)
  numberAt(raw, 'min_samples', 'token_samples_gte', errors)
  numberAt(raw, 'remove_candidate', 'failure_rate_gte', errors)
  numberAt(raw, 'investigate', 'failure_rate_gte', errors)
  numberAt(raw, 'investigate', 'failure_rate_lt', errors)
  numberAt(raw, 'cost_heavy', 'turn_token_avg_gte', errors)
  return raw as unknown as Thresholds
}

function validatePatterns(
  raw: unknown,
  errors: string[],
): { categories: string[]; rules: RuleSpec[]; effective: RuleSpec[]; ineffective: IneffectiveRule[] } {
  const empty = { categories: [], rules: [], effective: [], ineffective: [] }
  if (!isPlainObject(raw)) {
    errors.push('failure_patterns 必须是对象')
    return empty
  }
  let categories: string[] = []
  if (raw.categories !== undefined) {
    if (!Array.isArray(raw.categories)) {
      errors.push('failure_patterns.categories 必须是字符串数组')
    } else {
      categories = raw.categories.map((item, index) => {
        if (typeof item !== 'string' || item.trim().length === 0) {
          errors.push(`failure_patterns.categories[${index}] 必须是非空字符串`)
          return ''
        }
        return item
      })
    }
  }
  let specs: unknown[] = []
  if (raw.rules !== undefined) {
    if (!Array.isArray(raw.rules)) {
      errors.push('failure_patterns.rules 必须是数组')
    } else {
      specs = raw.rules
    }
  }
  const rules: RuleSpec[] = []
  const effective: RuleSpec[] = []
  const ineffective: IneffectiveRule[] = []
  specs.forEach((item, index) => {
    const where = `failure_patterns.rules[${index}]`
    if (!isPlainObject(item)) {
      errors.push(`${where} 必须是对象`)
      return
    }
    if (typeof item.id !== 'string' || item.id.trim().length === 0) {
      errors.push(`${where}.id 必须是非空字符串`)
      return
    }
    if (typeof item.status !== 'string' || item.status.trim().length === 0) {
      errors.push(`${where}.status 必须是非空字符串`)
    }
    if (item.category !== undefined && (typeof item.category !== 'string' || item.category.length === 0)) {
      errors.push(`${where}.category 必须是非空字符串`)
    }
    if (item.verified_samples !== undefined && !Array.isArray(item.verified_samples)) {
      errors.push(`${where}.verified_samples 必须是数组`)
    }
    const patterns: CompiledPattern[] = []
    if (item.patterns !== undefined) {
      if (!Array.isArray(item.patterns)) {
        errors.push(`${where}.patterns 必须是字符串数组`)
      } else {
        item.patterns.forEach((pattern: unknown, patternIndex: number) => {
          if (typeof pattern !== 'string' || pattern.length === 0) {
            errors.push(`${where}.patterns[${patternIndex}] 必须是非空字符串`)
            return
          }
          try {
            patterns.push({ pattern, regex: new RegExp(pattern) })
          } catch (error) {
            errors.push(`${where}.patterns[${patternIndex}] 不是合法正则：${(error as Error).message}`)
          }
        })
      }
    }
    const samples = Array.isArray(item.verified_samples) ? item.verified_samples : []
    const status = typeof item.status === 'string' ? item.status : ''
    const rule: RuleSpec = {
      ...(item as unknown as Record<string, unknown>),
      id: item.id as string,
      ...(typeof item.category === 'string' && item.category.length > 0
        ? { category: item.category }
        : {}),
      status,
      patterns,
      verified_samples: samples,
    }
    rules.push(rule)
    const reasons: string[] = []
    if (status !== STATUS_VERIFIED) reasons.push(`status=${status}`)
    if (samples.length === 0) reasons.push('verified_samples 为空')
    if (reasons.length > 0) {
      ineffective.push({ id: rule.id, reasons })
    } else {
      effective.push(rule)
    }
  })
  return { categories, rules, effective, ineffective }
}

/** 装载规则包；`raw === undefined` 用随包默认值。结构非法抛 `RulePackError`。 */
export function loadRulePack(raw: unknown): RulePack {
  if (raw === undefined) {
    return loadRulePack({
      params: DEFAULT_RULES.params,
      thresholds: DEFAULT_RULES.thresholds,
      failure_patterns: DEFAULT_RULES.failure_patterns,
    })
  }
  if (!isPlainObject(raw)) throw new RulePackError('rules 必须是对象（params / thresholds / failure_patterns）')
  for (const key of Object.keys(raw)) {
    if (!['params', 'thresholds', 'failure_patterns'].includes(key)) {
      throw new RulePackError(`rules 含未知字段：${key}`)
    }
  }
  if (raw.params === undefined || raw.thresholds === undefined || raw.failure_patterns === undefined) {
    throw new RulePackError('rules 需要 params / thresholds / failure_patterns 三件套')
  }
  const errors: string[] = []
  const params = validateParams(raw.params, errors)
  const thresholds = validateThresholds(raw.thresholds, errors)
  const patterns = validatePatterns(raw.failure_patterns, errors)
  if (errors.length > 0) {
    throw new RulePackError(`规则包校验失败（${errors.length} 项）：\n- ${errors.join('\n- ')}`)
  }
  return {
    params,
    thresholds,
    categories: patterns.categories,
    rules: patterns.rules,
    effective: patterns.effective,
    ineffective: patterns.ineffective,
  }
}

export function aggregateParamsOf(pack: RulePack): { window_seconds: number; rate_precision: number } {
  return {
    window_seconds: pack.params.retry.window_seconds,
    rate_precision: pack.params.rate_precision,
  }
}