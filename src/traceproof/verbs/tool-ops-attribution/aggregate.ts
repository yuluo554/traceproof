/**
 * tool-ops-attribution · 两级聚合（迁移自源仓 `aggregate.py`）。
 *
 * 口径（与源仓 `plan/03 §2.1` 对应，数值语义逐项保留）：
 *  - 三态 `ok / error / unknown` 相加 == 总数（对账等式，破坏即内部错误）；
 *  - `failure_rate = error / (ok + error)`，分母**不含 unknown**；分母 0 → `null` +
 *    `insufficient_data=true`；
 *  - token 四项分列（input / output / cache_read / cache_creation），
 *    `token_samples` / `token_missing` 单列，均值名带 `turn_` 前缀；
 *  - 耗时只按有样本源计算；无样本 → `null` + `duration_available=false`；
 *  - 重试：同 `(source, server, tool)` 在时间窗内失败后再次调用记一次；窗口值来自规则包；
 *  - 两级维度都输出 unknown 计数；排序按 `(source, server[, tool])` 字典序。
 *
 * 器官不读文件 / 时钟：时间戳只做字符串 → 整数秒的纯换算。
 */

import { compareText, roundTo } from './util.js'
import type { NormalizedEvent } from './event.js'

export const AGGREGATE_SCHEMA = 'opslens.aggregate/1'

export interface AggregateParams {
  readonly window_seconds: number
  readonly rate_precision: number
}

export interface AggregateRow {
  readonly [key: string]: unknown
  readonly level: 'server' | 'tool'
  readonly source: string
  readonly server: string
  readonly tool?: string
  readonly calls_total: number
  readonly calls_ok: number
  readonly calls_error: number
  readonly calls_unknown: number
  readonly failure_rate: number | null
  readonly failure_rate_numerator: number
  readonly failure_rate_denominator: number
  readonly insufficient_data: boolean
  readonly retry_count: number
  readonly tokens_input: number | null
  readonly tokens_output: number | null
  readonly tokens_cache_read: number | null
  readonly tokens_cache_creation: number | null
  readonly token_samples: number
  readonly token_missing: number
  readonly turn_token_avg: number | null
  readonly duration_avg_ms: number | null
  readonly duration_samples: number
  readonly duration_missing: number
  readonly duration_available: boolean
}

export interface AggregateTotals {
  readonly calls_total: number
  readonly calls_ok: number
  readonly calls_error: number
  readonly calls_unknown: number
  readonly failure_rate: number | null
  readonly failure_rate_numerator: number
  readonly failure_rate_denominator: number
  readonly retry_count: number
  readonly token_samples: number
  readonly token_missing: number
  readonly duration_samples: number
  readonly servers: number
}

export interface AggregatePayload {
  readonly [key: string]: unknown
  readonly schema: string
  readonly rate_precision: number
  readonly retry_window_seconds: number
  readonly server_level: readonly AggregateRow[]
  readonly tool_level: readonly AggregateRow[]
  readonly totals: AggregateTotals
  readonly coverage_note: string
}

export interface RawMetricRow {
  readonly source: string
  readonly server: string
  readonly tool: string
  readonly calls_total: number
  readonly calls_ok: number
  readonly calls_error: number
  readonly calls_unknown: number
  readonly tokens_input: number
  readonly tokens_output: number
  readonly tokens_cache_read: number
  readonly tokens_cache_creation: number
  readonly token_samples: number
  readonly token_missing: number
  readonly duration_sum: number
  readonly duration_samples: number
  readonly duration_missing: number
}

const COVERAGE_NOTE =
  '聚合口径：失败率分母不含 unknown；token 四项分列且按调用轮次归属' +
  '（Codex 侧不按工具归因，token_samples=0 表示该维度不可得而非零开销）；' +
  'Claude 侧按工具耗时不可得（duration_available=false）。'

const TIMESTAMP_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$/

function daysFromCivil(year: number, month: number, day: number): number {
  const adjusted = year - (month <= 2 ? 1 : 0)
  const era = Math.floor((adjusted >= 0 ? adjusted : adjusted - 399) / 400)
  const yearOfEra = adjusted - era * 400
  const dayOfYear = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear
  return era * 146097 + dayOfEra - 719468
}

/**
 * ISO 时间戳 → 自 1970-01-01T00:00:00Z 起的整数秒（不可解析 → `null`）。
 *
 * 与源仓一致：纯整数运算，不 import 时钟；小数秒截断；时区偏移参与换算；
 * 缺时区按 UTC 处理。闰年规则完整。
 */
export function timestampToSeconds(value: unknown): number | null {
  if (typeof value !== 'string') return null
  const match = value.trim().match(TIMESTAMP_RE)
  if (match === null) return null
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const days = daysFromCivil(year, month, day)
  let total = days * 86400 + hour * 3600 + minute * 60 + second
  const zone = match[8]
  if (zone !== undefined && zone !== 'Z') {
    const sign = zone[0] === '+' ? 1 : -1
    const digits = zone.slice(1).replace(':', '')
    total -= sign * (Number(digits.slice(0, 2)) * 3600 + Number(digits.slice(2, 4)) * 60)
  }
  return total
}

function ratio(numerator: number, denominator: number, precision: number): number | null {
  if (denominator === 0) return null
  return roundTo(numerator / denominator, precision)
}

/** 单行 SQL 聚合结果 → 指标行；对账等式破坏即抛错（内部错误，绝不静默出数）。 */
export function finishRow(
  row: RawMetricRow,
  precision: number,
  retryCount: number,
  level: 'server' | 'tool',
): AggregateRow {
  const { calls_total, calls_ok, calls_error, calls_unknown } = row
  if (calls_ok + calls_error + calls_unknown !== calls_total) {
    throw new Error(
      `对账等式被打破：${calls_ok} + ${calls_error} + ${calls_unknown} != ${calls_total}`,
    )
  }
  const denominator = calls_ok + calls_error
  const tokenValues =
    row.token_samples > 0
      ? [
          row.tokens_input,
          row.tokens_output,
          row.tokens_cache_read,
          row.tokens_cache_creation,
        ]
      : [null, null, null, null]
  const tokenSum =
    row.token_samples > 0
      ? row.tokens_input + row.tokens_output + row.tokens_cache_read + row.tokens_cache_creation
      : null
  return {
    level,
    source: row.source,
    server: row.server,
    ...(level === 'tool' ? { tool: row.tool } : {}),
    calls_total,
    calls_ok,
    calls_error,
    calls_unknown,
    failure_rate: ratio(calls_error, denominator, precision),
    failure_rate_numerator: calls_error,
    failure_rate_denominator: denominator,
    insufficient_data: denominator === 0,
    retry_count: retryCount,
    tokens_input: tokenValues[0] as number | null,
    tokens_output: tokenValues[1] as number | null,
    tokens_cache_read: tokenValues[2] as number | null,
    tokens_cache_creation: tokenValues[3] as number | null,
    token_samples: row.token_samples,
    token_missing: row.token_missing,
    turn_token_avg: tokenSum === null ? null : ratio(tokenSum, row.token_samples, precision),
    duration_avg_ms: ratio(row.duration_sum, row.duration_samples, precision),
    duration_samples: row.duration_samples,
    duration_missing: row.duration_missing,
    duration_available: row.duration_samples > 0,
  }
}

interface Group {
  readonly source: string
  readonly server: string
  readonly tool?: string
  readonly events: NormalizedEvent[]
}

function groupKey(source: string, server: string, tool?: string): string {
  return tool === undefined ? `${source}\u0000${server}` : `${source}\u0000${server}\u0000${tool}`
}

function collect(events: readonly NormalizedEvent[]): {
  serverGroups: Map<string, Group>
  toolGroups: Map<string, Group>
} {
  const serverGroups = new Map<string, Group>()
  const toolGroups = new Map<string, Group>()
  for (const event of events) {
    const serverKey = groupKey(event.source, event.server)
    const serverGroup = serverGroups.get(serverKey)
    if (serverGroup === undefined) {
      serverGroups.set(serverKey, { source: event.source, server: event.server, events: [event] })
    } else {
      serverGroup.events.push(event)
    }
    const toolKey = groupKey(event.source, event.server, event.tool)
    const toolGroup = toolGroups.get(toolKey)
    if (toolGroup === undefined) {
      toolGroups.set(toolKey, {
        source: event.source,
        server: event.server,
        tool: event.tool,
        events: [event],
      })
    } else {
      toolGroup.events.push(event)
    }
  }
  return { serverGroups, toolGroups }
}

function retryByTool(
  toolGroups: Map<string, Group>,
  windowSeconds: number,
): Map<string, number> {
  const counts = new Map<string, number>()
  for (const [key, group] of toolGroups) {
    const ordered = [...group.events].sort((left, right) => {
      const leftSeconds = timestampToSeconds(left.timestamp)
      const rightSeconds = timestampToSeconds(right.timestamp)
      const leftKey = leftSeconds === null ? -Infinity : leftSeconds
      const rightKey = rightSeconds === null ? -Infinity : rightSeconds
      return leftKey - rightKey || left.seq - right.seq
    })
    let retries = 0
    for (let index = 1; index < ordered.length; index += 1) {
      const previous = ordered[index - 1] as NormalizedEvent
      const current = ordered[index] as NormalizedEvent
      const previousSeconds = timestampToSeconds(previous.timestamp)
      const currentSeconds = timestampToSeconds(current.timestamp)
      if (
        previous.status === 'error' &&
        previousSeconds !== null &&
        currentSeconds !== null &&
        currentSeconds - previousSeconds <= windowSeconds
      ) {
        retries += 1
      }
    }
    counts.set(key, retries)
  }
  return counts
}

function buildRawRow(group: Group): RawMetricRow {
  let callsOk = 0
  let callsError = 0
  let callsUnknown = 0
  let tokensInput = 0
  let tokensOutput = 0
  let tokensCacheRead = 0
  let tokensCacheCreation = 0
  let tokenSamples = 0
  let durationSum = 0
  let durationSamples = 0
  for (const event of group.events) {
    if (event.status === 'ok') callsOk += 1
    else if (event.status === 'error') callsError += 1
    else callsUnknown += 1
    if (event.tokens !== null) {
      tokenSamples += 1
      tokensInput += event.tokens.input
      tokensOutput += event.tokens.output
      tokensCacheRead += event.tokens.cache_read
      tokensCacheCreation += event.tokens.cache_creation
    }
    if (event.duration_ms !== null) {
      durationSamples += 1
      durationSum += event.duration_ms
    }
  }
  const total = group.events.length
  return {
    source: group.source,
    server: group.server,
    tool: group.tool ?? '',
    calls_total: total,
    calls_ok: callsOk,
    calls_error: callsError,
    calls_unknown: callsUnknown,
    tokens_input: tokensInput,
    tokens_output: tokensOutput,
    tokens_cache_read: tokensCacheRead,
    tokens_cache_creation: tokensCacheCreation,
    token_samples: tokenSamples,
    token_missing: total - tokenSamples,
    duration_sum: durationSum,
    duration_samples: durationSamples,
    duration_missing: total - durationSamples,
  }
}

function compareRowKeys(left: Group, right: Group): number {
  return (
    compareText(left.source, right.source) ||
    compareText(left.server, right.server) ||
    compareText(left.tool ?? '', right.tool ?? '')
  )
}

/** 事件流 → 两级聚合载荷（`opslens.aggregate/1`）。 */
export function aggregateEvents(
  events: readonly NormalizedEvent[],
  params: AggregateParams,
): AggregatePayload {
  const windowSeconds = params.window_seconds
  const precision = params.rate_precision
  const { serverGroups, toolGroups } = collect(events)
  const retriesByTool = retryByTool(toolGroups, windowSeconds)

  const retriesByServer = new Map<string, number>()
  for (const [key, count] of retriesByTool) {
    const [source, server] = key.split('\u0000')
    const serverKey = groupKey(source as string, server as string)
    retriesByServer.set(serverKey, (retriesByServer.get(serverKey) ?? 0) + count)
  }

  const serverLevel = [...serverGroups.entries()]
    .sort(([, left], [, right]) => compareRowKeys(left, right))
    .map(([key, group]) =>
      finishRow(buildRawRow(group), precision, retriesByServer.get(key) ?? 0, 'server'),
    )
  const toolLevel = [...toolGroups.entries()]
    .sort(([, left], [, right]) => compareRowKeys(left, right))
    .map(([key, group]) =>
      finishRow(buildRawRow(group), precision, retriesByTool.get(key) ?? 0, 'tool'),
    )

  return {
    schema: AGGREGATE_SCHEMA,
    rate_precision: precision,
    retry_window_seconds: windowSeconds,
    server_level: serverLevel,
    tool_level: toolLevel,
    totals: totalsOf(serverLevel, precision),
    coverage_note: COVERAGE_NOTE,
  }
}

/** 全量汇总（与 server 级同口径，防「汇总另算一份」）。 */
export function totalsOf(serverLevel: readonly AggregateRow[], precision: number): AggregateTotals {
  let callsTotal = 0
  let callsOk = 0
  let callsError = 0
  let callsUnknown = 0
  let retryCount = 0
  let tokenSamples = 0
  let tokenMissing = 0
  let durationSamples = 0
  for (const row of serverLevel) {
    callsTotal += row.calls_total
    callsOk += row.calls_ok
    callsError += row.calls_error
    callsUnknown += row.calls_unknown
    retryCount += row.retry_count
    tokenSamples += row.token_samples
    tokenMissing += row.token_missing
    durationSamples += row.duration_samples
  }
  const denominator = callsOk + callsError
  return {
    calls_total: callsTotal,
    calls_ok: callsOk,
    calls_error: callsError,
    calls_unknown: callsUnknown,
    failure_rate: ratio(callsError, denominator, precision),
    failure_rate_numerator: callsError,
    failure_rate_denominator: denominator,
    retry_count: retryCount,
    token_samples: tokenSamples,
    token_missing: tokenMissing,
    duration_samples: durationSamples,
    servers: serverLevel.length,
  }
}