/**
 * tool-ops-attribution · 工具调用运行取证
 *
 * 一个 traceproof 器官：把「这组 agent 工具调用到底跑了多少次、失败率多少、token / 耗时
 * 开销多大、失败该归到哪一类、哪个 server 该删 / 该查」的主张，逐条对到**同一份
 * 已解析事件流**的确定性重算，再挂到痕迹节点（`session_id + turn + tool_call_id`）。
 *
 * 迁移来源：旧仓的判定层（`schema` / `config` / `aggregate` / `attribute` /
 * `report/suggestions`）；日志发现、JSONL 解析、CLI、报告排版、HTML/Markdown 渲染、
 * 安装面与基准脚手架**不迁**（D1/D18：cli / parse / report / packaging / bench /
 * guard / selftest 等属产品级）。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "events": {
 *     "schema": "opslens.events/1",
 *     "count": 202,
 *     "events": [
 *       {"source":"claude_code","session_id":"sess-1","seq":2,"timestamp":"2026-10-16T00:00:01.100Z",
 *        "server":"fake-high-fail","tool":"tool_exec","status":"ok",
 *        "tokens":{"input":53386,"output":1045,"cache_read":11280,"cache_creation":85},
 *        "duration_ms":null,"turn_tokens_attributed":true}
 *     ]
 *   },
 *   "rules": {"params": {…}, "thresholds": {…}, "failure_patterns": {…}},   // 可选；缺省 = 随器官打包
 *   "claims": [
 *     {"claim_id":"c1","check":"metric","level":"server","source":"claude_code",
 *      "server":"fake-high-fail","field":"failure_rate","asserted":0.6,
 *      "node":{"session_id":"s-ops-1","turn":1,"tool_call_id":"call-ops-1"}}
 *   ]
 * }
 * ```
 *
 * check 闭集：
 *  - `metric`：两级聚合行的一个指标字段；`level=server|tool`，tool 级带 `tool`；
 *  - `totals`：全量汇总字段；
 *  - `params`：规则包参数（`rate_precision` / `retry_window_seconds`）；
 *  - `category`：`by_category` 某一类计数；
 *  - `server_category`：某 server 的失败类别计数；
 *  - `event_category`：单条事件的重算类别（非 error 事件为 `not_attributed`）；
 *  - `effective`：某失败模式规则是否生效（可附 `reasons` 逐条比对未生效原因）；
 *  - `suggestion`：某 server 某轴的建议标签（`remove_candidate` / `investigate` /
 *    `low_signal` / `cost_heavy` / `none`），可附 `evidence` 逐字段比对；
 *  - `insufficient`：某 server 某轴是否存在「数据不足」条目（可附原因 / 样本量）；
 *  - `event`：单条事件的规范化字段（status / tokens / duration_ms / …）；
 *  - `stream`：事件流载荷级事实（`schema` / `count` / `sorted`）；
 *  - `timestamp`：ISO 时间戳 → 整数秒的纯换算（不可解析 → null）；
 *  - `count`：全局计数（事件 / 两级行数 / 生效规则 / 未生效规则 / 匹配模式 / 建议 / 数据不足）。
 *
 * 判定：与重算一致 → `claim`；不一致且**有痕迹节点** → `refuted`；不一致且无节点 →
 * `inconclusive` 并写明原因。规则包结构非法 → `RulePackError` 冒到唯一入口（退出码 2）。
 */

import type { Basis } from '../../core/trace-index.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'
import { aggregateEvents, timestampToSeconds } from './aggregate.js'
import type { AggregatePayload, AggregateRow } from './aggregate.js'
import {
  attributeEvents,
  classifyEvent,
  matchedPatternCount,
  NOT_ATTRIBUTED,
  CATEGORY_OTHER,
} from './attribute.js'
import type { AttributePayload } from './attribute.js'
import { EVENT_FIELDS, readEventStream } from './event.js'
import type { EventStream, NormalizedEvent } from './event.js'
import { aggregateParamsOf, loadRulePack } from './rules.js'
import type { RulePack } from './rules.js'
import { AXIS_FAILURE_RATE, AXIS_TURN_TOKEN, evaluateServer } from './suggest.js'
import type { InsufficientEntry, ServerEvaluation, SuggestionEntry } from './suggest.js'
import {
  isPlainObject,
  jsonEqual,
  readExactString,
  readInteger,
  readString,
  readStringArray,
} from './util.js'

/** 版本沿用源仓 `__version__`（0.2.0，不随本产品升版）。 */
export const VERSION = '0.2.0'

export const CHECKS = [
  'metric',
  'totals',
  'params',
  'category',
  'server_category',
  'event_category',
  'effective',
  'suggestion',
  'insufficient',
  'event',
  'stream',
  'timestamp',
  'count',
] as const
export type CheckName = (typeof CHECKS)[number]

const METRIC_FIELDS: Readonly<Record<string, 'integer' | 'number-or-null' | 'boolean'>> = {
  calls_total: 'integer',
  calls_ok: 'integer',
  calls_error: 'integer',
  calls_unknown: 'integer',
  failure_rate: 'number-or-null',
  failure_rate_numerator: 'integer',
  failure_rate_denominator: 'integer',
  insufficient_data: 'boolean',
  retry_count: 'integer',
  tokens_input: 'number-or-null',
  tokens_output: 'number-or-null',
  tokens_cache_read: 'number-or-null',
  tokens_cache_creation: 'number-or-null',
  token_samples: 'integer',
  token_missing: 'integer',
  turn_token_avg: 'number-or-null',
  duration_avg_ms: 'number-or-null',
  duration_samples: 'integer',
  duration_missing: 'integer',
  duration_available: 'boolean',
}

const TOTALS_FIELDS: Readonly<Record<string, 'integer' | 'number-or-null'>> = {
  calls_total: 'integer',
  calls_ok: 'integer',
  calls_error: 'integer',
  calls_unknown: 'integer',
  failure_rate: 'number-or-null',
  failure_rate_numerator: 'integer',
  failure_rate_denominator: 'integer',
  retry_count: 'integer',
  token_samples: 'integer',
  token_missing: 'integer',
  duration_samples: 'integer',
  servers: 'integer',
}

const PARAMS_FIELDS = ['rate_precision', 'retry_window_seconds'] as const
const STREAM_FIELDS = ['schema', 'count', 'sorted'] as const
const AXES = [AXIS_FAILURE_RATE, AXIS_TURN_TOKEN] as const
const LABELS: Readonly<Record<string, readonly string[]>> = {
  [AXIS_FAILURE_RATE]: ['remove_candidate', 'investigate', 'low_signal', 'none'],
  [AXIS_TURN_TOKEN]: ['cost_heavy', 'none'],
}
const COUNT_OFS = [
  'events',
  'server_level',
  'tool_level',
  'effective_rules',
  'ineffective_rules',
  'matched_pattern',
  'suggestion',
  'insufficient',
] as const

const GLOBAL_FIELDS = ['claim_id', 'check', 'asserted', 'node'] as const

const CHECK_FIELDS: Readonly<Record<CheckName, readonly string[]>> = {
  metric: ['level', 'source', 'server', 'tool', 'field'],
  totals: ['field'],
  params: ['field'],
  category: ['category'],
  server_category: ['source', 'server', 'category'],
  event_category: ['source', 'session_id', 'seq'],
  effective: ['rule_id', 'reasons'],
  suggestion: ['axis', 'source', 'server', 'evidence'],
  insufficient: ['axis', 'source', 'server', 'reason_contains', 'observed_sample', 'required_sample'],
  event: ['source', 'session_id', 'seq', 'field'],
  stream: ['field'],
  timestamp: ['timestamp'],
  count: ['of', 'rule_id', 'pattern', 'type', 'axis'],
}

const SUBJECT_FIELDS = new Set(['events', 'rules', 'claims'])

interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: unknown
  readonly node: unknown
  readonly level: 'server' | 'tool' | null
  readonly source: string | null
  readonly server: string | null
  readonly tool: string | null
  readonly field: string | null
  readonly category: string | null
  readonly sessionId: string | null
  readonly seq: number | null
  readonly ruleId: string | null
  readonly pattern: string | null
  readonly reasons: readonly string[] | null
  readonly axis: string | null
  readonly evidence: Readonly<Record<string, unknown>> | null
  readonly reasonContains: string | null
  readonly observedSample: number | null
  readonly requiredSample: number | null
  readonly timestamp: string | null
  readonly of: string | null
  readonly type: string | null
}

function optionalString(raw: Record<string, unknown>, name: string, where: string): string | null {
  if (raw[name] === undefined) return null
  return readString(raw[name], `${where}.${name}`)
}

function optionalExactString(
  raw: Record<string, unknown>,
  name: string,
  where: string,
): string | null {
  if (raw[name] === undefined) return null
  return readExactString(raw[name], `${where}.${name}`)
}

function optionalInteger(raw: Record<string, unknown>, name: string, where: string): number | null {
  if (raw[name] === undefined) return null
  return readInteger(raw[name], `${where}.${name}`)
}

function optionalStringArray(
  raw: Record<string, unknown>,
  name: string,
  where: string,
): string[] | null {
  if (raw[name] === undefined) return null
  return readStringArray(raw[name], `${where}.${name}`, true)
}

function assertNumberOrNull(value: unknown, where: string): void {
  if (value === null) return
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ContractError(`${where} 必须是有限数字或 null`)
  }
}

function assertIntegerValue(value: unknown, where: string): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new ContractError(`${where} 必须是整数`)
  }
}

function assertBooleanValue(value: unknown, where: string): void {
  if (typeof value !== 'boolean') throw new ContractError(`${where} 必须是布尔值`)
}

function readClaim(raw: unknown, position: number, pack: RulePack): Claim {
  const where = `claims[${position}]`
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const check = raw.check
  if (typeof check !== 'string' || !(CHECKS as readonly string[]).includes(check)) {
    throw new ContractError(`${where} 的 check 非法：<${String(check)}>（允许 ${CHECKS.join(' / ')}）`)
  }
  const checkName = check as CheckName
  const allowed = new Set<string>([...GLOBAL_FIELDS, ...CHECK_FIELDS[checkName]])
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) throw new ContractError(`${where} 的字段 ${key} 不适用于 check=${checkName}`)
  }
  if (raw.asserted === undefined) throw new ContractError(`${where} 缺 asserted`)
  const claimId = readString(raw.claim_id, `${where}.claim_id`)

  const levelRaw = optionalString(raw, 'level', where)
  let level: 'server' | 'tool' | null = null
  if (levelRaw !== null) {
    if (levelRaw !== 'server' && levelRaw !== 'tool') {
      throw new ContractError(`${where}.level 必须是 server 或 tool`)
    }
    level = levelRaw
  }
  const source = optionalString(raw, 'source', where)
  const server = optionalString(raw, 'server', where)
  const tool = optionalString(raw, 'tool', where)
  const field = optionalString(raw, 'field', where)
  const category = optionalString(raw, 'category', where)
  const sessionId = optionalString(raw, 'session_id', where)
  const seq = optionalInteger(raw, 'seq', where)
  const ruleId = optionalString(raw, 'rule_id', where)
  const pattern = optionalExactString(raw, 'pattern', where)
  const axis = optionalString(raw, 'axis', where)
  const type = optionalString(raw, 'type', where)
  const of = optionalString(raw, 'of', where)
  const timestamp = optionalString(raw, 'timestamp', where)
  const reasonContains = optionalString(raw, 'reason_contains', where)
  const observedSample = optionalInteger(raw, 'observed_sample', where)
  const requiredSample = optionalInteger(raw, 'required_sample', where)
  const reasons = optionalStringArray(raw, 'reasons', where)

  let evidence: Readonly<Record<string, unknown>> | null = null
  if (raw.evidence !== undefined) {
    if (!isPlainObject(raw.evidence)) throw new ContractError(`${where}.evidence 必须是对象`)
    evidence = raw.evidence
  }

  const ensure = (value: unknown, name: string): void => {
    if (value === null) throw new ContractError(`${where}：check=${checkName} 必须带 ${name}`)
  }

  if (checkName === 'metric') {
    ensure(level, 'level')
    ensure(source, 'source')
    ensure(server, 'server')
    ensure(field, 'field')
    if (level === 'tool') ensure(tool, 'tool')
    if (level === 'server' && tool !== null) {
      throw new ContractError(`${where}：level=server 时不得带 tool`)
    }
    const kind = METRIC_FIELDS[field as string]
    if (kind === undefined) {
      throw new ContractError(
        `${where}.field 非法：<${String(field)}>（允许 ${Object.keys(METRIC_FIELDS).join(' / ')}）`,
      )
    }
    if (kind === 'integer') assertIntegerValue(raw.asserted, `${where}.asserted`)
    else if (kind === 'number-or-null') assertNumberOrNull(raw.asserted, `${where}.asserted`)
    else assertBooleanValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'totals') {
    ensure(field, 'field')
    const kind = TOTALS_FIELDS[field as string]
    if (kind === undefined) {
      throw new ContractError(
        `${where}.field 非法：<${String(field)}>（允许 ${Object.keys(TOTALS_FIELDS).join(' / ')}）`,
      )
    }
    if (kind === 'integer') assertIntegerValue(raw.asserted, `${where}.asserted`)
    else assertNumberOrNull(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'params') {
    ensure(field, 'field')
    if (!(PARAMS_FIELDS as readonly string[]).includes(field as string)) {
      throw new ContractError(`${where}.field 非法：<${String(field)}>（允许 ${PARAMS_FIELDS.join(' / ')}）`)
    }
    assertIntegerValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'category') {
    ensure(category, 'category')
    assertIntegerValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'server_category') {
    ensure(source, 'source')
    ensure(server, 'server')
    ensure(category, 'category')
    assertIntegerValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'event_category') {
    ensure(source, 'source')
    ensure(sessionId, 'session_id')
    ensure(seq, 'seq')
    if (typeof raw.asserted !== 'string' || raw.asserted.trim().length === 0) {
      throw new ContractError(`${where}.asserted 必须是非空类别字符串`)
    }
    const allowedCategories = new Set<string>([...pack.categories, CATEGORY_OTHER, NOT_ATTRIBUTED])
    if (!allowedCategories.has(raw.asserted.trim())) {
      throw new ContractError(
        `${where}.asserted 非法：<${raw.asserted}>（允许 ${[...allowedCategories].join(' / ')}）`,
      )
    }
  } else if (checkName === 'effective') {
    ensure(ruleId, 'rule_id')
    assertBooleanValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'suggestion') {
    ensure(axis, 'axis')
    ensure(source, 'source')
    ensure(server, 'server')
    if (!(AXES as readonly string[]).includes(axis as string)) {
      throw new ContractError(`${where}.axis 非法：<${String(axis)}>（允许 ${AXES.join(' / ')}）`)
    }
    if (
      typeof raw.asserted !== 'string' ||
      !(LABELS[axis as string] as readonly string[]).includes(raw.asserted)
    ) {
      throw new ContractError(
        `${where}.asserted 非法：<${String(raw.asserted)}>（axis=${axis} 允许 ${(LABELS[axis as string] as readonly string[]).join(' / ')}）`,
      )
    }
  } else if (checkName === 'insufficient') {
    ensure(axis, 'axis')
    ensure(source, 'source')
    ensure(server, 'server')
    if (!(AXES as readonly string[]).includes(axis as string)) {
      throw new ContractError(`${where}.axis 非法：<${String(axis)}>（允许 ${AXES.join(' / ')}）`)
    }
    assertBooleanValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'event') {
    ensure(source, 'source')
    ensure(sessionId, 'session_id')
    ensure(seq, 'seq')
    ensure(field, 'field')
    if (!(EVENT_FIELDS as readonly string[]).includes(field as string)) {
      throw new ContractError(`${where}.field 非法：<${String(field)}>（允许 ${EVENT_FIELDS.join(' / ')}）`)
    }
  } else if (checkName === 'stream') {
    ensure(field, 'field')
    if (!(STREAM_FIELDS as readonly string[]).includes(field as string)) {
      throw new ContractError(`${where}.field 非法：<${String(field)}>（允许 ${STREAM_FIELDS.join(' / ')}）`)
    }
    if (field === 'schema' && typeof raw.asserted !== 'string') {
      throw new ContractError(`${where}.asserted 必须是字符串`)
    }
    if (field === 'count') assertIntegerValue(raw.asserted, `${where}.asserted`)
    if (field === 'sorted') assertBooleanValue(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'timestamp') {
    ensure(timestamp, 'timestamp')
    assertNumberOrNull(raw.asserted, `${where}.asserted`)
  } else if (checkName === 'count') {
    ensure(of, 'of')
    if (!(COUNT_OFS as readonly string[]).includes(of as string)) {
      throw new ContractError(`${where}.of 非法：<${String(of)}>（允许 ${COUNT_OFS.join(' / ')}）`)
    }
    assertIntegerValue(raw.asserted, `${where}.asserted`)
    if (of === 'matched_pattern') {
      ensure(ruleId, 'rule_id')
      ensure(pattern, 'pattern')
    }
    if (of === 'suggestion') ensure(type, 'type')
    if (type !== null && !Object.values(LABELS).some((labels) => labels.includes(type as string))) {
      throw new ContractError(`${where}.type 非法：<${String(type)}>`)
    }
    if (of !== 'matched_pattern' && (ruleId !== null || pattern !== null)) {
      throw new ContractError(`${where}：rule_id / pattern 只适用于 of=matched_pattern`)
    }
    if (of !== 'suggestion' && type !== null) {
      throw new ContractError(`${where}：type 只适用于 of=suggestion`)
    }
    if (of !== 'insufficient' && axis !== null) {
      throw new ContractError(`${where}：axis 只适用于 of=insufficient`)
    }
    if (of === 'insufficient' && axis !== null && !(AXES as readonly string[]).includes(axis)) {
      throw new ContractError(`${where}.axis 非法：<${axis}>（允许 ${AXES.join(' / ')}）`)
    }
  }

  return {
    claimId,
    check: checkName,
    asserted: raw.asserted,
    node: raw.node,
    level,
    source,
    server,
    tool,
    field,
    category,
    sessionId,
    seq,
    ruleId,
    pattern,
    reasons,
    axis,
    evidence,
    reasonContains,
    observedSample,
    requiredSample,
    timestamp,
    of,
    type,
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
  return basis.ref(sessionId.trim(), turn, toolCallId)
}

interface Computed {
  readonly found: boolean
  readonly actual: unknown
  readonly matched: boolean
  readonly reason: string
  readonly evidence: Readonly<Record<string, unknown>>
}

function findServerRow(
  payload: AggregatePayload,
  source: string,
  server: string,
): AggregateRow | undefined {
  return payload.server_level.find((row) => row.source === source && row.server === server)
}

function findToolRow(
  payload: AggregatePayload,
  source: string,
  server: string,
  tool: string,
): AggregateRow | undefined {
  return payload.tool_level.find(
    (row) => row.source === source && row.server === server && row.tool === tool,
  )
}

function findEvent(
  stream: EventStream,
  source: string,
  sessionId: string,
  seq: number,
): NormalizedEvent | undefined {
  return stream.events.find(
    (event) => event.source === source && event.session_id === sessionId && event.seq === seq,
  )
}

function computeMetric(payload: AggregatePayload, claim: Claim): Computed {
  const level = claim.level as 'server' | 'tool'
  const row =
    level === 'server'
      ? findServerRow(payload, claim.source as string, claim.server as string)
      : findToolRow(payload, claim.source as string, claim.server as string, claim.tool as string)
  const field = claim.field as string
  if (row === undefined) {
    return {
      found: false,
      actual: null,
      matched: false,
      reason: `未找到 ${level} 级聚合行（${claim.source}/${claim.server}${level === 'tool' ? `/${claim.tool}` : ''}）`,
      evidence: {
        level,
        source: claim.source,
        server: claim.server,
        ...(level === 'tool' ? { tool: claim.tool } : {}),
        field,
        row_found: false,
        rate_precision: payload.rate_precision,
        retry_window_seconds: payload.retry_window_seconds,
      },
    }
  }
  const actual = row[field]
  const matched = jsonEqual(actual, claim.asserted)
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `${level} 级 ${claim.source}/${claim.server}${level === 'tool' ? `/${claim.tool}` : ''} 的 ${field} = ${String(actual)}，与主张一致`
      : `${level} 级 ${claim.source}/${claim.server}${level === 'tool' ? `/${claim.tool}` : ''} 的 ${field} = ${String(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: {
      level,
      source: claim.source,
      server: claim.server,
      ...(level === 'tool' ? { tool: claim.tool } : {}),
      field,
      actual,
      row_found: true,
      rate_precision: payload.rate_precision,
      retry_window_seconds: payload.retry_window_seconds,
    },
  }
}

function computeTotals(payload: AggregatePayload, claim: Claim): Computed {
  const field = claim.field as string
  const actual = (payload.totals as unknown as Record<string, unknown>)[field]
  const matched = jsonEqual(actual, claim.asserted)
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `totals.${field} = ${String(actual)}，与主张一致`
      : `totals.${field} = ${String(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: {
      field,
      actual,
      rate_precision: payload.rate_precision,
      retry_window_seconds: payload.retry_window_seconds,
    },
  }
}

function computeParams(claim: Claim, pack: RulePack): Computed {
  const field = claim.field as string
  const actual =
    field === 'rate_precision'
      ? pack.params.rate_precision
      : field === 'retry_window_seconds'
        ? pack.params.retry.window_seconds
        : null
  const matched = jsonEqual(actual, claim.asserted)
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `params.${field} = ${String(actual)}，与主张一致`
      : `params.${field} = ${String(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: { field, actual },
  }
}

function computeCategory(payload: AttributePayload, claim: Claim): Computed {
  const category = claim.category as string
  const declared = payload.categories.includes(category)
  const item = payload.by_category.find((candidate) => candidate.category === category)
  const found = declared && item !== undefined
  const actual = found ? item.calls : null
  const matched = found && jsonEqual(actual, claim.asserted)
  return {
    found,
    actual,
    matched,
    reason: matched
      ? `by_category.${category} = ${String(actual)}，与主张一致`
      : found
        ? `by_category.${category} = ${String(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`
        : `分类 ${category} 不在声明类别表里（${payload.categories.join(' / ')}）`,
    evidence: { category, calls: actual, categories: payload.categories },
  }
}

function computeServerCategory(payload: AttributePayload, claim: Claim): Computed {
  const row = payload.by_server.find(
    (candidate) => candidate.source === claim.source && candidate.server === claim.server,
  )
  const category = claim.category as string
  const found = row !== undefined && category in row.categories
  const actual = found ? (row as NonNullable<typeof row>).categories[category] : null
  const matched = found && jsonEqual(actual, claim.asserted)
  return {
    found,
    actual,
    matched,
    reason: matched
      ? `${claim.source}/${claim.server} 的 ${category} = ${String(actual)}，与主张一致`
      : found
        ? `${claim.source}/${claim.server} 的 ${category} = ${String(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`
        : `未找到 ${claim.source}/${claim.server} 的失败类别行（或该类无记录）`,
    evidence: {
      source: claim.source,
      server: claim.server,
      category,
      calls: actual,
      row_found: row !== undefined,
      calls_error: row?.calls_error,
    },
  }
}

function computeEventCategory(stream: EventStream, pack: RulePack, claim: Claim): Computed {
  const event = findEvent(
    stream,
    claim.source as string,
    claim.sessionId as string,
    claim.seq as number,
  )
  if (event === undefined) {
    return {
      found: false,
      actual: null,
      matched: false,
      reason: `未找到事件 ${claim.source}/${claim.sessionId}#${String(claim.seq)}`,
      evidence: {
        source: claim.source,
        session_id: claim.sessionId,
        seq: claim.seq,
        event_found: false,
      },
    }
  }
  const classification = classifyEvent(event, pack)
  const matched = jsonEqual(classification.category, claim.asserted)
  return {
    found: true,
    actual: classification.category,
    matched,
    reason: matched
      ? `事件 ${claim.source}/${claim.sessionId}#${String(claim.seq)} 的重算类别 = ${classification.category}，与主张一致`
      : `事件 ${claim.source}/${claim.sessionId}#${String(claim.seq)} 的重算类别 = ${classification.category} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: {
      source: claim.source,
      session_id: claim.sessionId,
      seq: claim.seq,
      status: event.status,
      rule_id: classification.rule_id,
      pattern: classification.pattern,
      event_found: true,
    },
  }
}

function computeEffective(pack: RulePack, claim: Claim): Computed {
  const rule = pack.rules.find((candidate) => candidate.id === claim.ruleId)
  if (rule === undefined) {
    return {
      found: false,
      actual: null,
      matched: false,
      reason: `规则包里没有规则 ${claim.ruleId}`,
      evidence: { rule_id: claim.ruleId, rule_found: false },
    }
  }
  const effective = pack.effective.some((candidate) => candidate.id === claim.ruleId)
  const reasons = pack.ineffective.find((candidate) => candidate.id === claim.ruleId)?.reasons ?? []
  const problems: string[] = []
  if (claim.reasons !== null && !jsonEqual([...reasons], [...claim.reasons])) {
    problems.push(`未生效原因不符（账本 [${reasons.join('、')}] ≠ 主张 [${claim.reasons.join('、')}]）`)
  }
  const matched = effective === claim.asserted && problems.length === 0
  return {
    found: true,
    actual: effective,
    matched,
    reason: matched
      ? `规则 ${claim.ruleId} 生效=${String(effective)}，与主张一致`
      : problems.length > 0
        ? `规则 ${claim.ruleId} 生效=${String(effective)}，但${problems.join('；')}`
        : `规则 ${claim.ruleId} 生效=${String(effective)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: { rule_id: claim.ruleId, effective, reasons },
  }
}

function suggestionForAxis(evaluation: ServerEvaluation, axis: string): string {
  return axis === AXIS_FAILURE_RATE
    ? evaluation.failure_suggestion
    : (evaluation.cost_suggestion ?? 'none')
}

function evaluateForClaim(
  agg: AggregatePayload,
  pack: RulePack,
  source: string,
  server: string,
): ServerEvaluation | null {
  const row = findServerRow(agg, source, server)
  if (row === undefined) return null
  return evaluateServer(row, pack.thresholds)
}

function computeSuggestion(agg: AggregatePayload, pack: RulePack, claim: Claim): Computed {
  const axis = claim.axis as string
  const evaluation = evaluateForClaim(agg, pack, claim.source as string, claim.server as string)
  if (evaluation === null) {
    return {
      found: false,
      actual: null,
      matched: false,
      reason: `未找到 server 聚合行 ${claim.source}/${claim.server}`,
      evidence: { axis, source: claim.source, server: claim.server, row_found: false },
    }
  }
  const actual = suggestionForAxis(evaluation, axis)
  const problems: string[] = []
  let entry: SuggestionEntry | undefined
  if (claim.evidence !== null) {
    entry = evaluation.suggestions.find((candidate) => candidate.type === actual)
    for (const [key, expected] of Object.entries(claim.evidence)) {
      if (entry === undefined) {
        problems.push(`实际没有 ${actual} 建议，无法核对 evidence.${key}`)
        continue
      }
      const value = (entry as unknown as Record<string, unknown>)[key]
      if (!jsonEqual(value, expected)) {
        problems.push(
          `evidence.${key} 不符（账本 ${JSON.stringify(value)} ≠ 主张 ${JSON.stringify(expected)}）`,
        )
      }
    }
  }
  const matched = jsonEqual(actual, claim.asserted) && problems.length === 0
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `${claim.source}/${claim.server} 的 ${axis} 建议 = ${actual}，与主张一致`
      : problems.length > 0
        ? `${claim.source}/${claim.server} 的 ${axis} 建议 = ${actual}，但${problems.join('；')}`
        : `${claim.source}/${claim.server} 的 ${axis} 建议 = ${actual} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: {
      axis,
      source: claim.source,
      server: claim.server,
      actual,
      suggestion: entry,
      failure_suggestion: evaluation.failure_suggestion,
      cost_suggestion: evaluation.cost_suggestion,
    },
  }
}

function computeInsufficient(agg: AggregatePayload, pack: RulePack, claim: Claim): Computed {
  const axis = claim.axis as string
  const evaluation = evaluateForClaim(agg, pack, claim.source as string, claim.server as string)
  if (evaluation === null) {
    return {
      found: false,
      actual: null,
      matched: false,
      reason: `未找到 server 聚合行 ${claim.source}/${claim.server}`,
      evidence: { axis, source: claim.source, server: claim.server, row_found: false },
    }
  }
  const entry = evaluation.insufficient.find((candidate) => candidate.axis === axis)
  const actual = entry !== undefined
  const problems: string[] = []
  if (entry !== undefined) {
    if (claim.reasonContains !== null && !entry.reason.includes(claim.reasonContains)) {
      problems.push(`原因不含「${claim.reasonContains}」（实际：${entry.reason}）`)
    }
    if (claim.observedSample !== null && entry.observed_sample !== claim.observedSample) {
      problems.push(`observed_sample=${entry.observed_sample} ≠ 主张 ${String(claim.observedSample)}`)
    }
    if (claim.requiredSample !== null && entry.required_sample !== claim.requiredSample) {
      problems.push(`required_sample=${entry.required_sample} ≠ 主张 ${String(claim.requiredSample)}`)
    }
  }
  const matched = actual === claim.asserted && problems.length === 0
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `${claim.source}/${claim.server} 的 ${axis} 数据不足条目 = ${String(actual)}，与主张一致`
      : problems.length > 0
        ? `${claim.source}/${claim.server} 的 ${axis} 数据不足条目 = ${String(actual)}，但${problems.join('；')}`
        : `${claim.source}/${claim.server} 的 ${axis} 数据不足条目 = ${String(actual)} ≠ 主张 ${String(claim.asserted)}`,
    evidence: { axis, source: claim.source, server: claim.server, actual, entry },
  }
}

function eventField(event: NormalizedEvent, field: string): unknown {
  return (event as unknown as Record<string, unknown>)[field]
}

function computeEvent(stream: EventStream, claim: Claim): Computed {
  const event = findEvent(
    stream,
    claim.source as string,
    claim.sessionId as string,
    claim.seq as number,
  )
  const field = claim.field as string
  if (event === undefined) {
    return {
      found: false,
      actual: null,
      matched: false,
      reason: `未找到事件 ${claim.source}/${claim.sessionId}#${String(claim.seq)}`,
      evidence: {
        source: claim.source,
        session_id: claim.sessionId,
        seq: claim.seq,
        field,
        event_found: false,
      },
    }
  }
  const actual = eventField(event, field)
  const matched = jsonEqual(actual, claim.asserted)
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `事件 ${claim.source}/${claim.sessionId}#${String(claim.seq)} 的 ${field} 与主张一致`
      : `事件 ${claim.source}/${claim.sessionId}#${String(claim.seq)} 的 ${field} = ${JSON.stringify(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: {
      source: claim.source,
      session_id: claim.sessionId,
      seq: claim.seq,
      field,
      actual,
      event_found: true,
    },
  }
}

function computeStream(stream: EventStream, claim: Claim): Computed {
  const field = claim.field as string
  const actual = field === 'schema' ? stream.schema : field === 'count' ? stream.count : stream.sorted
  const matched = jsonEqual(actual, claim.asserted)
  return {
    found: true,
    actual,
    matched,
    reason: matched
      ? `事件流 ${field} = ${String(actual)}，与主张一致`
      : `事件流 ${field} = ${String(actual)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: { field, actual },
  }
}

function computeTimestamp(claim: Claim): Computed {
  const seconds = timestampToSeconds(claim.timestamp as string)
  const matched = jsonEqual(seconds, claim.asserted)
  return {
    found: true,
    actual: seconds,
    matched,
    reason: matched
      ? `timestamp(${claim.timestamp}) → ${String(seconds)}，与主张一致`
      : `timestamp(${claim.timestamp}) → ${String(seconds)} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: { timestamp: claim.timestamp, seconds },
  }
}

function countFor(
  of: string,
  claim: Claim,
  stream: EventStream,
  pack: RulePack,
  agg: AggregatePayload | null,
  attr: AttributePayload | null,
): number {
  switch (of) {
    case 'events':
      return stream.events.length
    case 'server_level':
      return (agg as AggregatePayload).server_level.length
    case 'tool_level':
      return (agg as AggregatePayload).tool_level.length
    case 'effective_rules':
      return pack.effective.length
    case 'ineffective_rules':
      return pack.ineffective.length
    case 'matched_pattern':
      return matchedPatternCount(
        attr as AttributePayload,
        claim.ruleId as string,
        claim.pattern as string,
      )
    case 'suggestion': {
      let total = 0
      for (const row of (agg as AggregatePayload).server_level) {
        const evaluation = evaluateServer(row, pack.thresholds)
        total += evaluation.suggestions.filter((entry) => entry.type === claim.type).length
      }
      return total
    }
    case 'insufficient': {
      let total = 0
      for (const row of (agg as AggregatePayload).server_level) {
        const evaluation = evaluateServer(row, pack.thresholds)
        total += evaluation.insufficient.filter(
          (entry) => claim.axis === null || entry.axis === claim.axis,
        ).length
      }
      return total
    }
    default:
      throw new ContractError(`未知计数对象：${of}`)
  }
}

function computeCount(
  claim: Claim,
  stream: EventStream,
  pack: RulePack,
  agg: AggregatePayload | null,
  attr: AttributePayload | null,
): Computed {
  const of = claim.of as string
  const count = countFor(of, claim, stream, pack, agg, attr)
  const filters: Record<string, unknown> = {}
  if (claim.ruleId !== null) filters.rule_id = claim.ruleId
  if (claim.pattern !== null) filters.pattern = claim.pattern
  if (claim.type !== null) filters.type = claim.type
  if (claim.axis !== null) filters.axis = claim.axis
  const filterText = Object.keys(filters).length > 0 ? `, ${JSON.stringify(filters)}` : ''
  const matched = jsonEqual(count, claim.asserted)
  return {
    found: true,
    actual: count,
    matched,
    reason: matched
      ? `count(${of}${filterText}) = ${count}，与主张一致`
      : `count(${of}${filterText}) = ${count} ≠ 主张 ${JSON.stringify(claim.asserted)}`,
    evidence: { of, ...filters, count },
  }
}

function claimLabel(claim: Claim): string {
  switch (claim.check) {
    case 'metric':
      return `${claim.level} ${claim.source}/${claim.server}${claim.level === 'tool' ? `/${claim.tool}` : ''}.${claim.field} = ${JSON.stringify(claim.asserted)}`
    case 'totals':
      return `totals.${claim.field} = ${JSON.stringify(claim.asserted)}`
    case 'params':
      return `params.${claim.field} = ${JSON.stringify(claim.asserted)}`
    case 'category':
      return `by_category.${claim.category} = ${JSON.stringify(claim.asserted)}`
    case 'server_category':
      return `${claim.source}/${claim.server}.${claim.category} = ${JSON.stringify(claim.asserted)}`
    case 'event_category':
      return `${claim.source}/${claim.sessionId}#${String(claim.seq)} category = ${JSON.stringify(claim.asserted)}`
    case 'effective':
      return `rule ${claim.ruleId} effective = ${JSON.stringify(claim.asserted)}`
    case 'suggestion':
      return `${claim.axis}@${claim.source}/${claim.server} = ${JSON.stringify(claim.asserted)}`
    case 'insufficient':
      return `${claim.axis}@${claim.source}/${claim.server} insufficient = ${JSON.stringify(claim.asserted)}`
    case 'event':
      return `${claim.source}/${claim.sessionId}#${String(claim.seq)}.${claim.field}`
    case 'stream':
      return `stream.${claim.field} = ${JSON.stringify(claim.asserted)}`
    case 'timestamp':
      return `timestamp(${claim.timestamp}) = ${JSON.stringify(claim.asserted)}`
    case 'count':
      return `count(${claim.of}) = ${JSON.stringify(claim.asserted)}`
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
      computed: computed.actual,
      comparison: computed.matched ? 'match' : 'mismatch',
      ...computed.evidence,
    },
  })
}

/** 器官主体：事件流 + 规则包 + 主张 → 取证账本行。 */
export function evaluateToolOpsAttribution(
  subject: Record<string, unknown>,
  basis: Basis,
): LedgerRecord[] {
  for (const key of Object.keys(subject)) {
    if (!SUBJECT_FIELDS.has(key)) throw new ContractError(`输入含未知字段：${key}`)
  }
  if (subject.events === undefined) throw new ContractError('输入缺少 events')
  const stream = readEventStream(subject.events, 'events')
  const pack = loadRulePack(subject.rules)
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const claims = rawClaims.map((item, position) => readClaim(item, position, pack))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }

  const needsAgg = claims.some(
    (claim) =>
      claim.check === 'metric' ||
      claim.check === 'totals' ||
      claim.check === 'suggestion' ||
      claim.check === 'insufficient' ||
      (claim.check === 'count' &&
        ['server_level', 'tool_level', 'suggestion', 'insufficient'].includes(claim.of as string)),
  )
  const needsAttr = claims.some(
    (claim) =>
      claim.check === 'category' ||
      claim.check === 'server_category' ||
      claim.check === 'event_category' ||
      (claim.check === 'count' && claim.of === 'matched_pattern'),
  )
  const agg = needsAgg ? aggregateEvents(stream.events, aggregateParamsOf(pack)) : null
  const attr = needsAttr ? attributeEvents(stream.events, pack) : null

  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    let computed: Computed
    switch (claim.check) {
      case 'metric':
        computed = computeMetric(agg as AggregatePayload, claim)
        break
      case 'totals':
        computed = computeTotals(agg as AggregatePayload, claim)
        break
      case 'params':
        computed = computeParams(claim, pack)
        break
      case 'category':
        computed = computeCategory(attr as AttributePayload, claim)
        break
      case 'server_category':
        computed = computeServerCategory(attr as AttributePayload, claim)
        break
      case 'event_category':
        computed = computeEventCategory(stream, pack, claim)
        break
      case 'effective':
        computed = computeEffective(pack, claim)
        break
      case 'suggestion':
        computed = computeSuggestion(agg as AggregatePayload, pack, claim)
        break
      case 'insufficient':
        computed = computeInsufficient(agg as AggregatePayload, pack, claim)
        break
      case 'event':
        computed = computeEvent(stream, claim)
        break
      case 'stream':
        computed = computeStream(stream, claim)
        break
      case 'timestamp':
        computed = computeTimestamp(claim)
        break
      case 'count':
        computed = computeCount(claim, stream, pack, agg, attr)
        break
    }
    records.push(buildRecord(claim, computed, node))
  }
  return records
}

export const toolOpsAttributionVerb: Verb = register({
  slug: 'tool-ops-attribution',
  version: VERSION,
  summary: '工具调用运行取证：两级聚合失败率 / token / 耗时，规则归因失败模式并核对删换建议',
  input_fields: ['events', 'claims'],
  evaluate: evaluateToolOpsAttribution,
})

export type { InsufficientEntry, SuggestionEntry }