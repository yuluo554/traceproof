/**
 * tool-ops-attribution · 删换建议（迁移自源仓 `report/suggestions.py` 的判定部分）。
 *
 * 纪律（与源仓一致）：
 *  - 阈值全部来自规则包 `thresholds`，代码不写第二份；
 *  - 只消费**已算好的**聚合行，不重算比率；
 *  - 每条建议缺任一证据项 → 该条不输出（内部错误，`assertEvidenceComplete` 当场抛错）；
 *  - 样本不足一律降级「数据不足」，不因小样本给出「建议移除」。
 *
 * 报告排版（Markdown / HTML / JSON 渲染）不迁：器官只产出结构化判定。
 */

import { compareText } from './util.js'
import type { AggregateRow } from './aggregate.js'
import type { Thresholds } from './rules.js'

export const SUGGESTION_REMOVE = 'remove_candidate'
export const SUGGESTION_INVESTIGATE = 'investigate'
export const SUGGESTION_COST_HEAVY = 'cost_heavy'
export const SUGGESTION_LOW_SIGNAL = 'low_signal'
export const SUGGESTION_NONE = 'none'

export const AXIS_FAILURE_RATE = 'failure_rate'
export const AXIS_TURN_TOKEN = 'turn_token_avg'

/** 输出顺序（确定性）：按类型分组，组内按 (source, server)。 */
export const TYPE_ORDER = [SUGGESTION_REMOVE, SUGGESTION_INVESTIGATE, SUGGESTION_COST_HEAVY] as const

const FAILURE_BASIS =
  '口径：失败率 = calls_error / (calls_ok + calls_error)，分母不含 unknown（缺失态不进分母）；' +
  '阈值取自 thresholds.json，改该文件即为调参，不需改代码。'
const COST_BASIS =
  '口径：turn_token_avg = 轮次 token 四项之和 / token_samples（按调用轮次归属，四项分列不合并）；' +
  'Codex 侧 token 为会话级、不摊到单次调用，故其 token_samples 为 0、本轴不出建议。'
const SAMPLE_BASIS =
  '口径：样本量低于门槛一律降级为"数据不足"，不出建议——绝不因小样本给出"建议移除"。'

export interface SuggestionEntry {
  readonly [key: string]: unknown
  readonly type: string
  readonly axis: string
  readonly metric: string
  readonly source: string
  readonly server: string
  readonly value: number
  readonly numerator: number
  readonly denominator: number
  readonly sample_size: number
  readonly sample_requirement: Readonly<Record<string, number>>
  readonly threshold: Readonly<Record<string, number>>
  readonly basis: string
  readonly missing?: number
}

export interface InsufficientEntry {
  readonly [key: string]: unknown
  readonly axis: string
  readonly metric: string
  readonly source: string
  readonly server: string
  readonly reason: string
  readonly observed_sample: number
  readonly required_sample: number
  readonly threshold: Readonly<Record<string, number>>
  readonly basis: string
}

export interface ServerEvaluation {
  readonly failure_suggestion: string
  readonly cost_suggestion: string | null
  readonly suggestions: readonly SuggestionEntry[]
  readonly insufficient: readonly InsufficientEntry[]
}

const REQUIRED_EVIDENCE = [
  'type',
  'axis',
  'metric',
  'source',
  'server',
  'value',
  'numerator',
  'denominator',
  'sample_size',
  'sample_requirement',
  'threshold',
  'basis',
] as const

/** 证据完整性硬门：缺任一项 → 该条不输出（内部错误，直接抛错）。 */
export function assertEvidenceComplete(entry: Record<string, unknown>): Record<string, unknown> {
  const missing = REQUIRED_EVIDENCE.filter((key) => entry[key] === undefined || entry[key] === null)
  if (missing.length > 0) {
    throw new Error(
      `建议 ${String(entry.type)}/${String(entry.server)} 缺证据项 ${missing.join(', ')}——按纪律该条不输出（内部错误）`,
    )
  }
  return entry
}

function thresholdOf(
  block: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): Record<string, number> {
  const picked: Record<string, number> = {}
  for (const key of keys) picked[key] = block[key] as number
  return picked
}

function failureAxis(
  row: AggregateRow,
  thresholds: Thresholds,
): { label: string; entry: SuggestionEntry | null; insufficient: InsufficientEntry | null } {
  const minCalls = thresholds.min_samples.calls_total_gte
  const remove = thresholds.remove_candidate
  const investigate = thresholds.investigate
  const callsTotal = row.calls_total
  const rate = row.failure_rate

  if (callsTotal < minCalls) {
    return {
      label: SUGGESTION_LOW_SIGNAL,
      entry: null,
      insufficient: {
        axis: AXIS_FAILURE_RATE,
        metric: 'calls_total',
        source: row.source,
        server: row.server,
        reason: '样本不足，降级为"数据不足"，不出建议',
        observed_sample: callsTotal,
        required_sample: minCalls,
        threshold: { calls_total_gte: minCalls },
        basis: SAMPLE_BASIS,
      },
    }
  }
  if (rate === null) {
    return {
      label: SUGGESTION_LOW_SIGNAL,
      entry: null,
      insufficient: {
        axis: AXIS_FAILURE_RATE,
        metric: 'failure_rate',
        source: row.source,
        server: row.server,
        reason: '失败率分母为 0（无 ok/error 样本），降级为"数据不足"',
        observed_sample: callsTotal,
        required_sample: minCalls,
        threshold: { calls_total_gte: minCalls },
        basis: SAMPLE_BASIS,
      },
    }
  }

  const common = {
    axis: AXIS_FAILURE_RATE,
    metric: 'failure_rate',
    source: row.source,
    server: row.server,
    value: rate,
    numerator: row.failure_rate_numerator,
    denominator: row.failure_rate_denominator,
    sample_size: callsTotal,
    sample_requirement: { calls_total_gte: minCalls },
    basis: FAILURE_BASIS,
  } as const
  if (rate >= remove.failure_rate_gte) {
    return {
      label: SUGGESTION_REMOVE,
      entry: assertEvidenceComplete({
        ...common,
        type: SUGGESTION_REMOVE,
        threshold: thresholdOf(remove as unknown as Record<string, unknown>, ['failure_rate_gte']),
      }) as unknown as SuggestionEntry,
      insufficient: null,
    }
  }
  if (rate >= investigate.failure_rate_gte && rate < investigate.failure_rate_lt) {
    return {
      label: SUGGESTION_INVESTIGATE,
      entry: assertEvidenceComplete({
        ...common,
        type: SUGGESTION_INVESTIGATE,
        threshold: thresholdOf(investigate as unknown as Record<string, unknown>, [
          'failure_rate_gte',
          'failure_rate_lt',
        ]),
      }) as unknown as SuggestionEntry,
      insufficient: null,
    }
  }
  return { label: SUGGESTION_NONE, entry: null, insufficient: null }
}

function costAxis(
  row: AggregateRow,
  thresholds: Thresholds,
): { label: string | null; entry: SuggestionEntry | null; insufficient: InsufficientEntry | null } {
  const minTokens = thresholds.min_samples.token_samples_gte
  const cost = thresholds.cost_heavy
  const samples = row.token_samples
  const average = row.turn_token_avg

  if (samples < minTokens) {
    return {
      label: null,
      entry: null,
      insufficient: {
        axis: AXIS_TURN_TOKEN,
        metric: 'token_samples',
        source: row.source,
        server: row.server,
        reason: 'token 参与样本不足，开销轴降级为"数据不足"，不出建议',
        observed_sample: samples,
        required_sample: minTokens,
        threshold: { token_samples_gte: minTokens },
        basis: SAMPLE_BASIS,
      },
    }
  }
  if (average === null) return { label: null, entry: null, insufficient: null }
  if (average >= cost.turn_token_avg_gte) {
    const tokenSum =
      (row.tokens_input as number) +
      (row.tokens_output as number) +
      (row.tokens_cache_read as number) +
      (row.tokens_cache_creation as number)
    return {
      label: SUGGESTION_COST_HEAVY,
      entry: assertEvidenceComplete({
        type: SUGGESTION_COST_HEAVY,
        axis: AXIS_TURN_TOKEN,
        metric: 'turn_token_avg',
        source: row.source,
        server: row.server,
        value: average,
        numerator: tokenSum,
        denominator: samples,
        sample_size: samples,
        missing: row.token_missing,
        sample_requirement: { token_samples_gte: minTokens },
        threshold: thresholdOf(cost as unknown as Record<string, unknown>, ['turn_token_avg_gte']),
        basis: COST_BASIS,
      }) as unknown as SuggestionEntry,
      insufficient: null,
    }
  }
  return { label: null, entry: null, insufficient: null }
}

/** 单个 server 聚合行 → 两条轴的标签、建议与「数据不足」条目。 */
export function evaluateServer(row: AggregateRow, thresholds: Thresholds): ServerEvaluation {
  const failure = failureAxis(row, thresholds)
  const cost = costAxis(row, thresholds)
  const suggestions = [failure.entry, cost.entry].filter(
    (entry): entry is SuggestionEntry => entry !== null,
  )
  const insufficient = [failure.insufficient, cost.insufficient].filter(
    (entry): entry is InsufficientEntry => entry !== null,
  )
  return {
    failure_suggestion: failure.label,
    cost_suggestion: cost.label,
    suggestions,
    insufficient,
  }
}

/** 确定性排序：先按类型顺序，再按 (source, server)。 */
export function sortSuggestions(entries: readonly SuggestionEntry[]): SuggestionEntry[] {
  return [...entries].sort((left, right) => {
    const leftOrder = TYPE_ORDER.indexOf(left.type as (typeof TYPE_ORDER)[number])
    const rightOrder = TYPE_ORDER.indexOf(right.type as (typeof TYPE_ORDER)[number])
    const leftRank = leftOrder < 0 ? TYPE_ORDER.length : leftOrder
    const rightRank = rightOrder < 0 ? TYPE_ORDER.length : rightOrder
    return (
      leftRank - rightRank ||
      compareText(left.source, right.source) ||
      compareText(left.server, right.server)
    )
  })
}

/** 确定性排序：按 (axis, source, server)。 */
export function sortInsufficient(entries: readonly InsufficientEntry[]): InsufficientEntry[] {
  return [...entries].sort(
    (left, right) =>
      compareText(left.axis, right.axis) ||
      compareText(left.source, right.source) ||
      compareText(left.server, right.server),
  )
}