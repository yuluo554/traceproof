/**
 * tool-ops-attribution · 失败模式归因（迁移自源仓 `attribute.py`）。
 *
 * 规则匹配，不是 AI 评分。纪律（与源仓一致）：
 *  - 只在 `status === "error"` 的事件上匹配；成功与 unknown **不参与**归因；
 *  - 匹配面只有 `error_text`（宽模式不得命中成功记录的正常输出）；
 *  - 按规则包顺序取第一条命中的规则 / 模式；
 *  - 未生效规则（`status !== verified` 或 `verified_samples` 为空）不参与匹配，
 *    其覆盖的失败落 `other`，原因逐条列出；
 *  - 每类计数 + 未命中计数单列；`matched_patterns` 可审计。
 */

import { compareText } from './util.js'
import type { NormalizedEvent } from './event.js'
import type { RulePack, RuleSpec } from './rules.js'

export const ATTRIBUTE_SCHEMA = 'opslens.attribute/1'
export const CATEGORY_OTHER = 'other'
export const NOT_ATTRIBUTED = 'not_attributed'

const UNMATCHED_NOTE =
  '落 other 的失败 = 未命中任何生效规则（含被门控拦下的规则所覆盖的类别），未生效原因见 ineffective_rules'

const COVERAGE_NOTE =
  '归因只在失败记录（status=error）的 error_text 上匹配；status=unknown 的记录不参与归因' +
  '（未声明成败 ≠ 失败）；未生效规则（status≠verified 或 verified_samples 为空）不参与匹配，' +
  '其覆盖的类别落 other。'

export interface MatchedPattern {
  readonly rule_id: string
  readonly pattern: string
  readonly calls: number
}

export interface CategoryCount {
  readonly category: string
  readonly calls: number
}

export interface ServerCategoryRow {
  readonly source: string
  readonly server: string
  readonly calls_error: number
  readonly categories: Readonly<Record<string, number>>
}

export interface AttributePayload {
  readonly [key: string]: unknown
  readonly schema: string
  readonly categories: readonly string[]
  readonly effective_rule_ids: readonly string[]
  readonly ineffective_rules: readonly { readonly id: string; readonly reasons: readonly string[] }[]
  readonly totals: {
    readonly calls_error: number
    readonly matched: number
    readonly other: number
    readonly unmatched_note: string
  }
  readonly by_category: readonly CategoryCount[]
  readonly by_server: readonly ServerCategoryRow[]
  readonly matched_patterns: readonly MatchedPattern[]
  readonly coverage_note: string
}

export interface Classification {
  readonly category: string
  readonly rule_id: string | null
  readonly pattern: string | null
  readonly attributed: boolean
}

function matchRule(errorText: string, rule: RuleSpec): string | null {
  for (const compiled of rule.patterns) {
    if (compiled.regex.test(errorText)) return compiled.pattern
  }
  return null
}

/** 单条事件的归因结果；非 error 事件记 `not_attributed`（不猜、不归因）。 */
export function classifyEvent(event: NormalizedEvent, pack: RulePack): Classification {
  if (event.status !== 'error') {
    return { category: NOT_ATTRIBUTED, rule_id: null, pattern: null, attributed: false }
  }
  for (const rule of pack.effective) {
    const pattern = matchRule(event.error_text, rule)
    if (pattern !== null) {
      const category =
        rule.category !== undefined && rule.category.length > 0 ? rule.category : CATEGORY_OTHER
      return { category, rule_id: rule.id, pattern, attributed: true }
    }
  }
  return { category: CATEGORY_OTHER, rule_id: null, pattern: null, attributed: true }
}

function blankDistribution(categories: readonly string[]): Record<string, number> {
  const distribution: Record<string, number> = {}
  for (const category of categories) distribution[category] = 0
  return distribution
}

/** 事件流 + 规则包 → 归因载荷（`opslens.attribute/1`）。 */
export function attributeEvents(
  events: readonly NormalizedEvent[],
  pack: RulePack,
): AttributePayload {
  const categories = [...pack.categories]
  const distributionCategories = [...categories]
  if (!distributionCategories.includes(CATEGORY_OTHER)) distributionCategories.push(CATEGORY_OTHER)

  const byCategory = blankDistribution(distributionCategories)
  const byServer = new Map<string, { source: string; server: string; calls_error: number; categories: Record<string, number> }>()
  const patternHits = new Map<string, number>()
  let errorCalls = 0

  for (const event of events) {
    if (event.status !== 'error') continue
    errorCalls += 1
    let category = CATEGORY_OTHER
    let matchedRule: string | null = null
    let matchedPattern: string | null = null
    for (const rule of pack.effective) {
      const pattern = matchRule(event.error_text, rule)
      if (pattern !== null) {
        category = rule.category !== undefined && rule.category.length > 0 ? rule.category : CATEGORY_OTHER
        matchedRule = rule.id
        matchedPattern = pattern
        const key = `${matchedRule}\u0000${pattern}`
        patternHits.set(key, (patternHits.get(key) ?? 0) + 1)
        break
      }
    }
    byCategory[category] = (byCategory[category] ?? 0) + 1

    const serverKey = `${event.source}\u0000${event.server}`
    let bucket = byServer.get(serverKey)
    if (bucket === undefined) {
      bucket = {
        source: event.source,
        server: event.server,
        calls_error: 0,
        categories: blankDistribution(categories),
      }
      byServer.set(serverKey, bucket)
    }
    bucket.calls_error += 1
    bucket.categories[category] = (bucket.categories[category] ?? 0) + 1
    // matchedRule / matchedPattern 只用于计数，不单独输出（与源仓一致）。
    void matchedRule
    void matchedPattern
  }

  const other = byCategory[CATEGORY_OTHER] ?? 0
  const matched = errorCalls - other
  const serverRows = [...byServer.values()].sort(
    (left, right) => compareText(left.source, right.source) || compareText(left.server, right.server),
  )
  const matchedPatterns: MatchedPattern[] = [...patternHits.entries()]
    .map(([key, calls]) => {
      const [ruleId, pattern] = key.split('\u0000')
      return { rule_id: ruleId as string, pattern: pattern as string, calls }
    })
    .sort((left, right) => compareText(left.rule_id, right.rule_id) || compareText(left.pattern, right.pattern))

  return {
    schema: ATTRIBUTE_SCHEMA,
    categories,
    effective_rule_ids: pack.effective.map((rule) => rule.id),
    ineffective_rules: pack.ineffective.map((item) => ({ id: item.id, reasons: [...item.reasons] })),
    totals: {
      calls_error: errorCalls,
      matched,
      other,
      unmatched_note: UNMATCHED_NOTE,
    },
    by_category: categories.map((category) => ({ category, calls: byCategory[category] ?? 0 })),
    by_server: serverRows,
    matched_patterns: matchedPatterns,
    coverage_note: COVERAGE_NOTE,
  }
}

/** 某个 (rule_id, pattern) 的命中次数（对账 / 主张用）。 */
export function matchedPatternCount(
  payload: AttributePayload,
  ruleId: string,
  pattern: string,
): number {
  const item = payload.matched_patterns.find(
    (candidate) => candidate.rule_id === ruleId && candidate.pattern === pattern,
  )
  return item === undefined ? 0 : item.calls
}