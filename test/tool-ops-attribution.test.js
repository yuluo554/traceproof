/**
 * tool-ops-attribution 器官的无损测试。
 *
 * 数据面：旧仓 `data/rules/{params,thresholds,failure_patterns}.json` 只读导出为
 * `src/traceproof/verbs/tool-ops-attribution/data/*.json`；`test/fixtures/tool-ops-attribution/events.json`
 * 是旧仓 `scan --home data/synthetic` 的事件流载荷只读拷贝（202 条调用 / 7 server / 12 tool）。
 *
 * 判定层对齐：
 *  - event：IR 规范化 / 三态 / tokens 缺失 ≠ 0 / duration 不可得 / 排序键；
 *  - aggregate：两级聚合 / 对账等式 / unknown 不进失败率分母 / token 四项分列 /
 *    耗时口径 / 重试窗口 / 时间戳纯整数换算；
 *  - attribute：五分类 / 规则门控 / 只在 error 记录上匹配 / 匹配模式可审计；
 *  - suggestion：阈值触发 / 证据完整性 / 样本不足降级 / 确定性排序；
 *  - 器官契约：13 类主张、verdict 映射、痕迹节点、CLI 退出码、打包数据。
 *
 * 判据 1 的 X = 旧仓判定层（D1+D18 机械选 12 文件）`pytest` 实跑 **150 passed**；
 * 本文件顶层 `test(` 调用数与实跑用例数均 ≥ 150。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { main } from '../lib/traceproof/cli.js'
import {
  CLAIM,
  ContractError,
  EXIT_BLOCKED,
  EXIT_CONTRACT,
  EXIT_INPUT,
  EXIT_OK,
  INCONCLUSIVE,
  REFUTED,
  Report,
} from '../lib/traceproof/core/ledger.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  aggregateEvents,
  finishRow,
  timestampToSeconds,
  totalsOf,
  AGGREGATE_SCHEMA,
} from '../lib/traceproof/verbs/tool-ops-attribution/aggregate.js'
import {
  attributeEvents,
  classifyEvent,
  matchedPatternCount,
  CATEGORY_OTHER,
  NOT_ATTRIBUTED,
} from '../lib/traceproof/verbs/tool-ops-attribution/attribute.js'
import {
  compareEvents,
  EVENT_SCHEMA,
  isSorted,
  normalizeEvent,
  readEventStream,
} from '../lib/traceproof/verbs/tool-ops-attribution/event.js'
import {
  aggregateParamsOf,
  DEFAULT_RULES,
  loadRulePack,
  RulePackError,
  STATUS_VERIFIED,
} from '../lib/traceproof/verbs/tool-ops-attribution/rules.js'
import {
  assertEvidenceComplete,
  AXIS_FAILURE_RATE,
  AXIS_TURN_TOKEN,
  evaluateServer,
  sortInsufficient,
  sortSuggestions,
  SUGGESTION_COST_HEAVY,
  SUGGESTION_INVESTIGATE,
  SUGGESTION_LOW_SIGNAL,
  SUGGESTION_NONE,
  SUGGESTION_REMOVE,
} from '../lib/traceproof/verbs/tool-ops-attribution/suggest.js'
import {
  evaluateToolOpsAttribution,
  toolOpsAttributionVerb,
  VERSION,
} from '../lib/traceproof/verbs/tool-ops-attribution/index.js'

await loadBuiltin()

const ROOT = fileURLToPath(new URL('./fixtures/tool-ops-attribution/', import.meta.url))
const EVENTS_PAYLOAD = JSON.parse(readFileSync(join(ROOT, 'events.json'), 'utf8'))
const SAMPLE_PATH = fileURLToPath(new URL('../samples/tool-ops-attribution.json', import.meta.url))
const TRACES_PATH = fileURLToPath(new URL('../samples/tool-ops-attribution-traces.json', import.meta.url))

const STREAM = readEventStream(EVENTS_PAYLOAD, 'events')
const PACK = loadRulePack(undefined)
const AGG = aggregateEvents(STREAM.events, aggregateParamsOf(PACK))
const ATTR = attributeEvents(STREAM.events, PACK)

const clone = (value) => JSON.parse(JSON.stringify(value))

function deepMerge(base, patch) {
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch)) return patch
  const result = { ...base }
  for (const [key, value] of Object.entries(patch)) {
    result[key] =
      value !== null && typeof value === 'object' && !Array.isArray(value) && base[key] !== null && typeof base[key] === 'object'
        ? deepMerge(base[key], value)
        : value
  }
  return result
}

function customPack({ params, thresholds, failure_patterns } = {}) {
  return {
    params: params === undefined ? clone(DEFAULT_RULES.params) : deepMerge(clone(DEFAULT_RULES.params), params),
    thresholds:
      thresholds === undefined
        ? clone(DEFAULT_RULES.thresholds)
        : deepMerge(clone(DEFAULT_RULES.thresholds), thresholds),
    failure_patterns:
      failure_patterns === undefined ? clone(DEFAULT_RULES.failure_patterns) : failure_patterns,
  }
}

let claimSeq = 0
function claim(overrides = {}) {
  claimSeq += 1
  return { claim_id: `t-${claimSeq}`, ...overrides }
}

function basisOf(nodes = []) {
  return Basis.fromObject({ version: '2026.11.25', nodes })
}

function evalClaim(overrides, subject = {}) {
  const one = claim(overrides)
  const nodes = one.node === undefined || one.node === null ? [] : [one.node]
  return [
    ...evaluateToolOpsAttribution(
      { events: EVENTS_PAYLOAD, ...subject, claims: [one] },
      basisOf(nodes),
    ),
  ][0]
}

function recordFor(overrides, subject = {}, nodes = []) {
  const one = claim(overrides)
  return [
    ...evaluateToolOpsAttribution({ events: EVENTS_PAYLOAD, ...subject, claims: [one] }, basisOf(nodes)),
  ][0]
}

function serverRow(server, source = 'claude_code') {
  return AGG.server_level.find((row) => row.source === source && row.server === server)
}

function toolRow(server, tool, source = 'claude_code') {
  return AGG.tool_level.find(
    (row) => row.source === source && row.server === server && row.tool === tool,
  )
}

function categoryOf(server, category, source = 'claude_code') {
  const row = ATTR.by_server.find((item) => item.source === source && item.server === server)
  assert.ok(row, `缺少 by_server 行 ${source}/${server}`)
  return row.categories[category]
}

function eventOf(source, sessionId, seq) {
  return STREAM.events.find(
    (event) => event.source === source && event.session_id === sessionId && event.seq === seq,
  )
}

function eventBase(overrides = {}) {
  return {
    source: 'claude_code',
    session_id: 's-1',
    seq: 1,
    timestamp: '2026-10-16T00:00:00Z',
    server: 'fake-server',
    tool: 'tool_a',
    ...overrides,
  }
}

function claudeEvent(seq, status, errorText, options = {}) {
  return {
    source: 'claude_code',
    source_version: '2.1.233',
    session_id: options.sessionId ?? 's-1',
    seq,
    timestamp: options.timestamp ?? `2026-10-16T00:00:0${seq % 10}Z`,
    server: options.server ?? 'fake-server',
    tool: options.tool ?? 'tool_a',
    status,
    error_text: errorText,
    ...(options.tokens !== undefined ? { tokens: options.tokens } : {}),
    ...(options.duration !== undefined ? { duration_ms: options.duration } : {}),
  }
}

function evaluateEvents(events, claims, nodes = []) {
  return [
    ...evaluateToolOpsAttribution(
      { events: { schema: EVENT_SCHEMA, events }, claims },
      basisOf(nodes),
    ),
  ]
}

function rawRow(overrides = {}) {
  return {
    source: 'claude_code',
    server: 'fake-server',
    tool: 'tool_a',
    calls_total: 3,
    calls_ok: 1,
    calls_error: 1,
    calls_unknown: 1,
    tokens_input: 100,
    tokens_output: 20,
    tokens_cache_read: 5,
    tokens_cache_creation: 3,
    token_samples: 2,
    token_missing: 1,
    duration_sum: 200,
    duration_samples: 2,
    duration_missing: 1,
    ...overrides,
  }
}

async function capture(fn) {
  const out = []
  const err = []
  const originalLog = console.log
  const originalWrite = process.stderr.write
  console.log = (...args) => {
    out.push(args.map(String).join(' '))
  }
  process.stderr.write = (chunk) => {
    err.push(String(chunk))
    return true
  }
  try {
    const code = await fn()
    return { code, out: out.join('\n'), err: err.join('') }
  } finally {
    console.log = originalLog
    process.stderr.write = originalWrite
  }
}

function tempDir() {
  return mkdtempSync(join(tmpdir(), 'traceproof-tool-ops-'))
}

function writeJSON(dir, name, value) {
  const path = join(dir, name)
  writeFileSync(path, JSON.stringify(value))
  return path
}

// ===========================================================================
// 1. 器官声明 / 默认规则包
// ===========================================================================

test('verb: slug is tool-ops-attribution', () => {
  assert.equal(toolOpsAttributionVerb.slug, 'tool-ops-attribution')
  assert.equal(get('tool-ops-attribution').slug, 'tool-ops-attribution')
})

test('verb: version follows the old repository (0.2.0)', () => {
  assert.equal(VERSION, '0.2.0')
  assert.equal(toolOpsAttributionVerb.version, '0.2.0')
})

test('verb: summary names aggregation and attribution', () => {
  assert.match(toolOpsAttributionVerb.summary, /工具调用/)
  assert.match(toolOpsAttributionVerb.summary, /归因/)
})

test('verb: input_fields are events and claims', () => {
  assert.deepEqual([...toolOpsAttributionVerb.input_fields], ['events', 'claims'])
})

test('verbs: BUILTIN_MODULES contains 9 verbs in dictionary order', () => {
  assert.deepEqual([...BUILTIN_MODULES], [
    'agent-conflict',
    'anonymity-collapse',
    'email-evidence',
    'hazard-triage',
    'pattern-evidence',
    'pipeline-run',
    'rework-evidence',
    'session-replay',
    'tool-ops-attribution',
  ])
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
})

test('defaults: params carry retry window 120 and precision 6', () => {
  assert.equal(DEFAULT_RULES.params.retry.window_seconds, 120)
  assert.equal(DEFAULT_RULES.params.rate_precision, 6)
})

test('defaults: thresholds carry remove / investigate / cost / min sample values', () => {
  assert.equal(DEFAULT_RULES.thresholds.remove_candidate.failure_rate_gte, 0.5)
  assert.equal(DEFAULT_RULES.thresholds.investigate.failure_rate_gte, 0.2)
  assert.equal(DEFAULT_RULES.thresholds.investigate.failure_rate_lt, 0.5)
  assert.equal(DEFAULT_RULES.thresholds.cost_heavy.turn_token_avg_gte, 20000)
  assert.equal(DEFAULT_RULES.thresholds.min_samples.calls_total_gte, 20)
  assert.equal(DEFAULT_RULES.thresholds.min_samples.token_samples_gte, 20)
})

test('defaults: failure patterns declare five categories and four rules', () => {
  assert.deepEqual(DEFAULT_RULES.failure_patterns.categories, [
    'timeout',
    'permission_denied',
    'invalid_args',
    'content_refusal',
    'other',
  ])
  assert.equal(DEFAULT_RULES.failure_patterns.rules.length, 4)
  assert.deepEqual(
    DEFAULT_RULES.failure_patterns.rules.map((rule) => rule.id),
    ['F-TIMEOUT-1', 'F-PERM-1', 'F-ARGS-1', 'F-REFUSE-1'],
  )
})

// ===========================================================================
// 2. 事件 IR 规范化
// ===========================================================================

test('event: missing status defaults to unknown, never ok', () => {
  const event = normalizeEvent(eventBase(), 'e')
  assert.equal(event.status, 'unknown')
})

test('event: ok / error / unknown statuses are accepted', () => {
  for (const status of ['ok', 'error', 'unknown']) {
    assert.equal(normalizeEvent(eventBase({ status }), 'e').status, status)
  }
})

test('event: unknown source is rejected', () => {
  assert.throws(() => normalizeEvent(eventBase({ source: 'cursor' }), 'e'), ContractError)
})

test('event: bad status is rejected', () => {
  assert.throws(() => normalizeEvent(eventBase({ status: 'success' }), 'e'), ContractError)
})

test('event: seq is required and must be a non-negative integer', () => {
  assert.throws(() => normalizeEvent({ ...eventBase(), seq: undefined }, 'e'), ContractError)
  assert.throws(() => normalizeEvent(eventBase({ seq: '2' }), 'e'), ContractError)
  assert.throws(() => normalizeEvent(eventBase({ seq: -1 }), 'e'), ContractError)
  assert.throws(() => normalizeEvent(eventBase({ seq: 1.5 }), 'e'), ContractError)
})

test('event: session_id / server / tool are required non-empty strings', () => {
  assert.throws(() => normalizeEvent({ ...eventBase(), session_id: undefined }, 'e'), ContractError)
  assert.throws(() => normalizeEvent(eventBase({ session_id: '  ' }), 'e'), ContractError)
  assert.throws(() => normalizeEvent({ ...eventBase(), server: undefined }, 'e'), ContractError)
  assert.throws(() => normalizeEvent({ ...eventBase(), tool: undefined }, 'e'), ContractError)
})

test('event: unknown event field is rejected', () => {
  assert.throws(() => normalizeEvent(eventBase({ surprise: 1 }), 'e'), ContractError)
})

test('event: tokens null is not zero', () => {
  const event = normalizeEvent(eventBase(), 'e')
  assert.equal(event.tokens, null)
})

test('event: tokens are kept as four separate fields', () => {
  const event = normalizeEvent(
    eventBase({ tokens: { input: 100, output: 20, cache_read: 5, cache_creation: 3 } }),
    'e',
  )
  assert.deepEqual(event.tokens, { input: 100, output: 20, cache_read: 5, cache_creation: 3 })
})

test('event: missing token keys default to zero', () => {
  const event = normalizeEvent(eventBase({ tokens: { input: 7 } }), 'e')
  assert.deepEqual(event.tokens, { input: 7, output: 0, cache_read: 0, cache_creation: 0 })
})

test('event: unknown token key is rejected', () => {
  assert.throws(
    () => normalizeEvent(eventBase({ tokens: { input: 1, total: 2 } }), 'e'),
    ContractError,
  )
})

test('event: negative token value is rejected', () => {
  assert.throws(
    () => normalizeEvent(eventBase({ tokens: { input: -1 } }), 'e'),
    ContractError,
  )
})

test('event: duration null means unavailable, not zero', () => {
  assert.equal(normalizeEvent(eventBase(), 'e').duration_ms, null)
})

test('event: numeric duration is kept', () => {
  assert.equal(normalizeEvent(eventBase({ duration_ms: 0 }), 'e').duration_ms, 0)
  assert.equal(normalizeEvent(eventBase({ duration_ms: 500 }), 'e').duration_ms, 500)
})

test('event: duration string is rejected', () => {
  assert.throws(() => normalizeEvent(eventBase({ duration_ms: '500' }), 'e'), ContractError)
})

test('event: turn_tokens_attributed defaults to false', () => {
  assert.equal(normalizeEvent(eventBase(), 'e').turn_tokens_attributed, false)
})

test('event: turn_tokens_attributed accepts boolean', () => {
  assert.equal(normalizeEvent(eventBase({ turn_tokens_attributed: true }), 'e').turn_tokens_attributed, true)
})

test('event: turn_tokens_attributed rejects non-boolean', () => {
  assert.throws(
    () => normalizeEvent(eventBase({ turn_tokens_attributed: 1 }), 'e'),
    ContractError,
  )
})

test('event: notes default to an empty array', () => {
  assert.deepEqual(normalizeEvent(eventBase(), 'e').notes, [])
})

test('event: notes keep string entries', () => {
  assert.deepEqual(normalizeEvent(eventBase({ notes: ['stderr_nonempty'] }), 'e').notes, [
    'stderr_nonempty',
  ])
})

test('event: notes reject non-array', () => {
  assert.throws(() => normalizeEvent(eventBase({ notes: 'x' }), 'e'), ContractError)
})

test('event: optional string fields default to empty', () => {
  const event = normalizeEvent(eventBase(), 'e')
  assert.equal(event.source_version, '')
  assert.equal(event.call_id, '')
  assert.equal(event.timestamp, '2026-10-16T00:00:00Z')
  assert.equal(event.error_text, '')
})

test('event: error_text keeps trailing spaces (match surface is exact)', () => {
  const event = normalizeEvent(eventBase({ error_text: 'usage: ' }), 'e')
  assert.equal(event.error_text, 'usage: ')
})

test('stream: payload schema must be opslens.events/1', () => {
  assert.throws(
    () => readEventStream({ schema: 'opslens.events/2', events: [] }, 's'),
    ContractError,
  )
  assert.throws(() => readEventStream({ events: [] }, 's'), ContractError)
})

test('stream: payload count must equal events length', () => {
  assert.throws(
    () => readEventStream({ schema: EVENT_SCHEMA, count: 2, events: [eventBase()] }, 's'),
    ContractError,
  )
})

test('stream: payload count may be omitted', () => {
  const stream = readEventStream({ schema: EVENT_SCHEMA, events: [eventBase()] }, 's')
  assert.equal(stream.count, 1)
})

test('stream: bare event array is accepted as the same IR', () => {
  const stream = readEventStream([eventBase()], 's')
  assert.equal(stream.schema, EVENT_SCHEMA)
  assert.equal(stream.count, 1)
})

test('stream: sorted is true for source/session/seq order', () => {
  const stream = readEventStream(
    [
      claudeEvent(1, 'ok', ''),
      claudeEvent(2, 'ok', ''),
      { ...claudeEvent(1, 'ok', ''), source: 'codex' },
    ],
    's',
  )
  assert.equal(stream.sorted, true)
})

test('stream: sorted is false when seq goes backwards', () => {
  const stream = readEventStream([claudeEvent(2, 'ok', ''), claudeEvent(1, 'ok', '')], 's')
  assert.equal(stream.sorted, false)
  assert.equal(isSorted([...stream.events].reverse()), true)
})

test('stream: compareEvents orders by source then session then seq', () => {
  const a = normalizeEvent(eventBase({ source: 'claude_code', session_id: 's-1', seq: 9 }), 'a')
  const b = normalizeEvent(eventBase({ source: 'claude_code', session_id: 's-1', seq: 10 }), 'b')
  const c = normalizeEvent(eventBase({ source: 'codex', session_id: 's-1', seq: 1 }), 'c')
  assert.ok(compareEvents(a, b) < 0)
  assert.ok(compareEvents(b, c) < 0)
})

test('stream: payload size is 202 events', () => {
  assert.equal(STREAM.count, 202)
  assert.equal(STREAM.events.length, 202)
  assert.equal(STREAM.schema, EVENT_SCHEMA)
})

test('stream: fixture is already in sorted order', () => {
  assert.equal(STREAM.sorted, true)
})

// ===========================================================================
// 3. 时间戳纯整数换算
// ===========================================================================

test('timestamp: Z suffix converts to seconds', () => {
  assert.equal(timestampToSeconds('2026-10-16T00:00:00Z'), 1792108800)
})

test('timestamp: fractional seconds are truncated', () => {
  assert.equal(timestampToSeconds('2026-10-16T00:00:01.999Z'), 1792108801)
})

test('timestamp: +01:00 offset is subtracted', () => {
  assert.equal(timestampToSeconds('2026-10-16T01:00:00+01:00'), 1792108800)
})

test('timestamp: -01:00 offset is added', () => {
  assert.equal(timestampToSeconds('2026-10-16T00:00:00-01:00'), 1792112400)
})

test('timestamp: missing timezone is treated as UTC', () => {
  assert.equal(timestampToSeconds('2026-10-16T00:00:00'), 1792108800)
})

test('timestamp: compact offset form is accepted', () => {
  assert.equal(timestampToSeconds('2026-10-16T01:00:00+0100'), 1792108800)
})

test('timestamp: unparseable inputs return null', () => {
  assert.equal(timestampToSeconds(''), null)
  assert.equal(timestampToSeconds('T0'), null)
  assert.equal(timestampToSeconds(null), null)
  assert.equal(timestampToSeconds(123), null)
})

test('timestamp: leap-year day difference is 86400 seconds', () => {
  const feb29 = timestampToSeconds('2024-02-29T00:00:00Z')
  const mar1 = timestampToSeconds('2024-03-01T00:00:00Z')
  assert.ok(feb29 !== null)
  assert.ok(mar1 !== null)
  assert.equal(mar1 - feb29, 86400)
})

// ===========================================================================
// 4. 聚合：两级行 / 指标 / 对账等式
// ===========================================================================

test('aggregate: seven server rows and twelve tool rows', () => {
  assert.equal(AGG.server_level.length, 7)
  assert.equal(AGG.tool_level.length, 12)
  assert.equal(AGG.totals.servers, 7)
})

test('aggregate: every server row keeps three-state accounting identity', () => {
  for (const row of AGG.server_level) {
    assert.equal(row.calls_ok + row.calls_error + row.calls_unknown, row.calls_total)
  }
})

test('aggregate: every tool row keeps three-state accounting identity', () => {
  for (const row of AGG.tool_level) {
    assert.equal(row.calls_ok + row.calls_error + row.calls_unknown, row.calls_total)
  }
})

test('aggregate: totals keep three-state accounting identity', () => {
  const totals = AGG.totals
  assert.equal(totals.calls_ok + totals.calls_error + totals.calls_unknown, totals.calls_total)
  assert.equal(
    totals.calls_total,
    AGG.server_level.reduce((sum, row) => sum + row.calls_total, 0),
  )
})

test('aggregate: identity guard rejects a broken row', () => {
  assert.throws(() => finishRow(rawRow({ calls_total: 9 }), 6, 0, 'server'), /对账等式被打破/)
})

test('aggregate: identity guard accepts a consistent row', () => {
  const row = finishRow(rawRow(), 6, 0, 'server')
  assert.equal(row.calls_total, 3)
})

test('aggregate: fake-high-fail call counts', () => {
  const row = serverRow('fake-high-fail')
  assert.ok(row)
  assert.equal(row.calls_total, 40)
  assert.equal(row.calls_ok, 16)
  assert.equal(row.calls_error, 24)
  assert.equal(row.calls_unknown, 0)
})

test('aggregate: fake-high-fail failure rate is 0.6', () => {
  const row = serverRow('fake-high-fail')
  assert.ok(row)
  assert.equal(row.failure_rate, 0.6)
  assert.equal(row.failure_rate_numerator, 24)
  assert.equal(row.failure_rate_denominator, 40)
  assert.equal(row.insufficient_data, false)
})

test('aggregate: fake-high-fail token columns are four separate sums', () => {
  const row = serverRow('fake-high-fail')
  assert.ok(row)
  assert.equal(row.tokens_input, 1998938)
  assert.equal(row.tokens_output, 53820)
  assert.equal(row.tokens_cache_read, 653953)
  assert.equal(row.tokens_cache_creation, 25409)
  assert.equal(row.token_samples, 40)
  assert.equal(row.token_missing, 0)
  assert.equal(row.turn_token_avg, 68303)
})

test('aggregate: claude duration is unavailable, not zero', () => {
  const row = serverRow('fake-high-fail')
  assert.ok(row)
  assert.equal(row.duration_avg_ms, null)
  assert.equal(row.duration_samples, 0)
  assert.equal(row.duration_missing, 40)
  assert.equal(row.duration_available, false)
})

test('aggregate: fake-low-fail failure rate is 0.041667', () => {
  const row = serverRow('fake-low-fail')
  assert.ok(row)
  assert.equal(row.calls_total, 24)
  assert.equal(row.calls_error, 1)
  assert.equal(row.failure_rate, 0.041667)
  assert.equal(row.turn_token_avg, 3546.291667)
})

test('aggregate: unknown is reported and excluded from the denominator', () => {
  const row = serverRow('fake-mid-fail')
  assert.ok(row)
  assert.equal(row.calls_total, 40)
  assert.equal(row.calls_ok, 26)
  assert.equal(row.calls_error, 10)
  assert.equal(row.calls_unknown, 4)
  assert.equal(row.failure_rate_denominator, 36)
  assert.equal(row.failure_rate, 0.277778)
})

test('aggregate: fake-near-miss rate is 0.475', () => {
  const row = serverRow('fake-near-miss')
  assert.ok(row)
  assert.equal(row.failure_rate, 0.475)
})

test('aggregate: fake-threshold-exact rate is exactly 0.5', () => {
  const row = serverRow('fake-threshold-exact')
  assert.ok(row)
  assert.equal(row.failure_rate, 0.5)
  assert.equal(row.failure_rate_denominator, 20)
})

test('aggregate: fake-retry retry_count is 8', () => {
  const row = serverRow('fake-retry')
  assert.ok(row)
  assert.equal(row.retry_count, 8)
})

test('aggregate: codex totals are 8 calls / 1 unknown', () => {
  const row = serverRow('<codex>', 'codex')
  assert.ok(row)
  assert.equal(row.calls_total, 8)
  assert.equal(row.calls_ok, 4)
  assert.equal(row.calls_error, 3)
  assert.equal(row.calls_unknown, 1)
})

test('aggregate: codex failure rate uses denominator excluding unknown', () => {
  const row = serverRow('<codex>', 'codex')
  assert.ok(row)
  assert.equal(row.failure_rate_numerator, 3)
  assert.equal(row.failure_rate_denominator, 7)
  assert.equal(row.failure_rate, 0.428571)
})

test('aggregate: codex tokens are not attributed to calls', () => {
  const row = serverRow('<codex>', 'codex')
  assert.ok(row)
  assert.equal(row.token_samples, 0)
  assert.equal(row.token_missing, 8)
  assert.equal(row.tokens_input, null)
  assert.equal(row.tokens_output, null)
  assert.equal(row.tokens_cache_read, null)
  assert.equal(row.tokens_cache_creation, null)
  assert.equal(row.turn_token_avg, null)
})

test('aggregate: codex duration is available from wall time', () => {
  const row = serverRow('<codex>', 'codex')
  assert.ok(row)
  assert.equal(row.duration_available, true)
  assert.equal(row.duration_samples, 7)
  assert.equal(row.duration_missing, 1)
  assert.equal(row.duration_avg_ms, 3757.142857)
})

test('aggregate: codex retry_count is 3', () => {
  const row = serverRow('<codex>', 'codex')
  assert.ok(row)
  assert.equal(row.retry_count, 3)
})

test('aggregate: zero denominator yields null failure rate and insufficient_data', () => {
  const events = [
    claudeEvent(1, 'unknown', '', { server: 'fake-only-unknown' }),
    claudeEvent(2, 'unknown', '', { server: 'fake-only-unknown' }),
    claudeEvent(3, 'unknown', '', { server: 'fake-only-unknown' }),
  ]
  const payload = aggregateEvents(
    events.map((event, index) => normalizeEvent(event, `e${index}`)),
    aggregateParamsOf(PACK),
  )
  const row = payload.server_level.find((item) => item.server === 'fake-only-unknown')
  assert.ok(row)
  assert.equal(row.calls_total, 3)
  assert.equal(row.calls_unknown, 3)
  assert.equal(row.failure_rate, null)
  assert.equal(row.failure_rate_denominator, 0)
  assert.equal(row.insufficient_data, true)
})

test('aggregate: unknown counts appear at both levels', () => {
  assert.ok(AGG.server_level.some((row) => row.calls_unknown > 0))
  assert.ok(AGG.tool_level.some((row) => row.calls_unknown > 0))
})

test('aggregate: token_samples + token_missing equals calls_total', () => {
  for (const row of AGG.server_level) {
    assert.equal(row.token_samples + row.token_missing, row.calls_total)
  }
})

test('aggregate: no merged tokens_total column exists', () => {
  for (const row of AGG.server_level) {
    assert.equal(Object.hasOwn(row, 'tokens_total'), false)
  }
})

test('aggregate: duration_samples + duration_missing equals calls_total', () => {
  for (const row of AGG.server_level) {
    assert.equal(row.duration_samples + row.duration_missing, row.calls_total)
  }
})

test('aggregate: totals are 202 calls / 122 ok / 75 error / 5 unknown', () => {
  assert.equal(AGG.totals.calls_total, 202)
  assert.equal(AGG.totals.calls_ok, 122)
  assert.equal(AGG.totals.calls_error, 75)
  assert.equal(AGG.totals.calls_unknown, 5)
})

test('aggregate: totals failure rate is 0.380711', () => {
  assert.equal(AGG.totals.failure_rate_numerator, 75)
  assert.equal(AGG.totals.failure_rate_denominator, 197)
  assert.equal(AGG.totals.failure_rate, 0.380711)
})

test('aggregate: totals retry is 11 and token samples are 194', () => {
  assert.equal(AGG.totals.retry_count, 11)
  assert.equal(AGG.totals.token_samples, 194)
  assert.equal(AGG.totals.token_missing, 8)
  assert.equal(AGG.totals.duration_samples, 7)
})

test('aggregate: totals are computed from server rows, not a second formula', () => {
  const restart = totalsOf(AGG.server_level, AGG.rate_precision)
  assert.deepEqual(restart, AGG.totals)
})

test('aggregate: tool rows are finer than server rows', () => {
  assert.ok(AGG.tool_level.length >= AGG.server_level.length)
  for (const row of AGG.tool_level) {
    assert.equal(row.level, 'tool')
    assert.ok(row.tool)
  }
  for (const row of AGG.server_level) {
    assert.equal(row.level, 'server')
    assert.equal(Object.hasOwn(row, 'tool'), false)
  }
})

test('aggregate: high-fail tool_fetch rate is 0.65', () => {
  const row = toolRow('fake-high-fail', 'tool_fetch')
  assert.ok(row)
  assert.equal(row.calls_total, 20)
  assert.equal(row.calls_error, 13)
  assert.equal(row.failure_rate, 0.65)
})

test('aggregate: high-fail tool_exec rate is 0.55', () => {
  const row = toolRow('fake-high-fail', 'tool_exec')
  assert.ok(row)
  assert.equal(row.failure_rate, 0.55)
  assert.equal(row.turn_token_avg, 68579.75)
})

test('aggregate: mid-fail tool_index and tool_query rates', () => {
  assert.equal(toolRow('fake-mid-fail', 'tool_index')?.failure_rate, 0.235294)
  assert.equal(toolRow('fake-mid-fail', 'tool_query')?.failure_rate, 0.315789)
})

test('aggregate: codex view_image has zero denominator', () => {
  const row = toolRow('fake-mid-fail', 'tool_index', 'claude_code')
  assert.ok(row)
  const view = toolRow('<codex>', 'view_image', 'codex')
  assert.ok(view)
  assert.equal(view.calls_total, 1)
  assert.equal(view.calls_unknown, 1)
  assert.equal(view.failure_rate, null)
  assert.equal(view.insufficient_data, true)
})

test('aggregate: precision comes from params and changes rounding', () => {
  const params = { window_seconds: 120, rate_precision: 2 }
  const payload = aggregateEvents(STREAM.events, params)
  assert.equal(payload.rate_precision, 2)
  assert.equal(payload.server_level.find((row) => row.server === 'fake-mid-fail')?.failure_rate, 0.28)
})

test('aggregate: retry window is a real parameter (0 reduces retries)', () => {
  const baseline = aggregateEvents(STREAM.events, { window_seconds: 120, rate_precision: 6 })
  const narrow = aggregateEvents(STREAM.events, { window_seconds: 0, rate_precision: 6 })
  assert.equal(baseline.totals.retry_count, 11)
  assert.ok(narrow.totals.retry_count < baseline.totals.retry_count)
})

test('aggregate: payload schema is opslens.aggregate/1', () => {
  assert.equal(AGG.schema, AGGREGATE_SCHEMA)
  assert.equal(AGG.rate_precision, 6)
  assert.equal(AGG.retry_window_seconds, 120)
})

test('aggregate: reversed event order produces the same payload', () => {
  const reversed = aggregateEvents([...STREAM.events].reverse(), aggregateParamsOf(PACK))
  assert.deepEqual(reversed, AGG)
})

test('aggregate: retry uses time window and ignores unparseable timestamps', () => {
  const events = [
    normalizeEvent(claudeEvent(1, 'error', 'boom', { timestamp: '2026-10-16T00:00:00Z' }), 'a'),
    normalizeEvent(claudeEvent(2, 'error', 'boom', { timestamp: 'not-a-time' }), 'b'),
    normalizeEvent(claudeEvent(3, 'ok', '', { timestamp: '2026-10-16T00:00:30Z' }), 'c'),
    normalizeEvent(claudeEvent(4, 'error', 'boom', { timestamp: '2026-10-16T00:01:00Z' }), 'd'),
  ]
  const payload = aggregateEvents(events, { window_seconds: 120, rate_precision: 6 })
  // seq=3 是 error 之后窗口内的再次调用 → 记 1 次重试；seq=2 的时间戳不可解析，不参与判定。
  assert.equal(payload.server_level[0]?.retry_count, 1)
})

// ===========================================================================
// 5. 归因：五分类 / 门控 / 匹配面
// ===========================================================================

test('attribute: categories are the five declared classes', () => {
  assert.deepEqual(ATTR.categories, [
    'timeout',
    'permission_denied',
    'invalid_args',
    'content_refusal',
    'other',
  ])
})

test('attribute: effective rules are the three verified rules', () => {
  assert.deepEqual(ATTR.effective_rule_ids, ['F-TIMEOUT-1', 'F-PERM-1', 'F-ARGS-1'])
})

test('attribute: ineffective rules list F-REFUSE-1 with both reasons', () => {
  assert.deepEqual(ATTR.ineffective_rules, [
    { id: 'F-REFUSE-1', reasons: ['status=pending', 'verified_samples 为空'] },
  ])
})

test('attribute: by_category lists every declared category in order', () => {
  assert.deepEqual(
    ATTR.by_category.map((item) => item.category),
    ['timeout', 'permission_denied', 'invalid_args', 'content_refusal', 'other'],
  )
})

test('attribute: category counts are 24 / 25 / 22 / 0 / 4', () => {
  const counts = Object.fromEntries(ATTR.by_category.map((item) => [item.category, item.calls]))
  assert.deepEqual(counts, {
    timeout: 24,
    permission_denied: 25,
    invalid_args: 22,
    content_refusal: 0,
    other: 4,
  })
})

test('attribute: category counts sum to participating error calls', () => {
  const sum = ATTR.by_category.reduce((total, item) => total + item.calls, 0)
  assert.equal(sum, ATTR.totals.calls_error)
  assert.equal(ATTR.totals.calls_error, 75)
})

test('attribute: matched = error calls minus other', () => {
  assert.equal(ATTR.totals.matched, 71)
  assert.equal(ATTR.totals.other, 4)
})

test('attribute: fake-high-fail splits timeout and invalid_args', () => {
  assert.equal(categoryOf('fake-high-fail', 'timeout'), 12)
  assert.equal(categoryOf('fake-high-fail', 'invalid_args'), 12)
  assert.equal(categoryOf('fake-high-fail', 'permission_denied'), 0)
})

test('attribute: fake-mid-fail splits timeout / permission / other', () => {
  assert.equal(categoryOf('fake-mid-fail', 'timeout'), 3)
  assert.equal(categoryOf('fake-mid-fail', 'permission_denied'), 6)
  assert.equal(categoryOf('fake-mid-fail', 'other'), 1)
})

test('attribute: fake-near-miss is permission_denied only', () => {
  assert.equal(categoryOf('fake-near-miss', 'permission_denied'), 19)
})

test('attribute: fake-retry is timeout only', () => {
  assert.equal(categoryOf('fake-retry', 'timeout'), 8)
})

test('attribute: fake-threshold-exact is invalid_args only', () => {
  assert.equal(categoryOf('fake-threshold-exact', 'invalid_args'), 10)
})

test('attribute: fake-low-fail content refusal falls to other', () => {
  assert.equal(categoryOf('fake-low-fail', 'content_refusal'), 0)
  assert.equal(categoryOf('fake-low-fail', 'other'), 1)
})

test('attribute: codex splits timeout and other', () => {
  assert.equal(categoryOf('<codex>', 'timeout', 'codex'), 1)
  assert.equal(categoryOf('<codex>', 'other', 'codex'), 2)
})

test('attribute: by_server calls_error equals category sum', () => {
  for (const row of ATTR.by_server) {
    const sum = Object.values(row.categories).reduce((total, value) => total + value, 0)
    assert.equal(sum, row.calls_error)
  }
})

test('attribute: by_server is sorted by (source, server)', () => {
  const keys = ATTR.by_server.map((row) => `${row.source}/${row.server}`)
  assert.deepEqual(keys, [...keys].sort())
})

test('attribute: per-event timeout classification', () => {
  const event = eventOf('claude_code', 'sess-claude-high', 10)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'timeout')
})

test('attribute: per-event permission classification', () => {
  const event = eventOf('claude_code', 'sess-claude-mid', 99)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'permission_denied')
})

test('attribute: Access is denied also maps to permission_denied', () => {
  const event = eventOf('claude_code', 'sess-claude-mid', 109)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'permission_denied')
})

test('attribute: unexpected argument maps to invalid_args', () => {
  const event = eventOf('claude_code', 'sess-claude-high', 6)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'invalid_args')
})

test('attribute: SyntaxError maps to invalid_args', () => {
  const event = eventOf('claude_code', 'sess-claude-high', 8)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'invalid_args')
})

test('attribute: AttributeError maps to invalid_args', () => {
  const event = eventOf('claude_code', 'sess-claude-high', 4)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'invalid_args')
})

test('attribute: unverified content refusal maps to other', () => {
  const event = eventOf('claude_code', 'sess-claude-low', 168)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'other')
  assert.equal(classifyEvent(event, PACK).rule_id, null)
})

test('attribute: codex Exit code 124 maps to timeout', () => {
  const event = eventOf('codex', 'sess-codex-alpha', 12)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, 'timeout')
})

test('attribute: ok event is not attributed', () => {
  const event = eventOf('claude_code', 'sess-claude-high', 2)
  assert.ok(event)
  assert.equal(classifyEvent(event, PACK).category, NOT_ATTRIBUTED)
})

test('attribute: unknown event is not attributed even with error text', () => {
  const event = normalizeEvent(
    claudeEvent(1, 'unknown', 'PermissionError: [Errno 13] Permission denied'),
    'e',
  )
  assert.equal(classifyEvent(event, PACK).category, NOT_ATTRIBUTED)
})

test('attribute: ok event carrying a wide-pattern text is not matched', () => {
  const event = normalizeEvent(
    claudeEvent(1, 'ok', "error: unexpected argument '-n' found"),
    'e',
  )
  assert.equal(classifyEvent(event, PACK).category, NOT_ATTRIBUTED)
})

test('attribute: matched patterns are auditable with counts', () => {
  for (const item of ATTR.matched_patterns) {
    assert.ok(item.rule_id)
    assert.ok(item.pattern)
    assert.ok(item.calls >= 1)
  }
})

test('attribute: timeout signature counts', () => {
  assert.equal(matchedPatternCount(ATTR, 'F-TIMEOUT-1', 'Command timed out after'), 15)
  assert.equal(matchedPatternCount(ATTR, 'F-TIMEOUT-1', 'ETIMEDOUT'), 8)
  assert.equal(matchedPatternCount(ATTR, 'F-TIMEOUT-1', 'Exit code: 124'), 1)
})

test('attribute: permission signature counts', () => {
  assert.equal(matchedPatternCount(ATTR, 'F-PERM-1', 'PermissionError'), 12)
  assert.equal(matchedPatternCount(ATTR, 'F-PERM-1', 'Access is denied'), 13)
})

test('attribute: args signature counts', () => {
  assert.equal(matchedPatternCount(ATTR, 'F-ARGS-1', 'AttributeError'), 8)
  assert.equal(matchedPatternCount(ATTR, 'F-ARGS-1', 'SyntaxError'), 8)
  assert.equal(matchedPatternCount(ATTR, 'F-ARGS-1', 'unexpected argument'), 6)
})

test('attribute: matched_patterns are sorted by rule then pattern', () => {
  const keys = ATTR.matched_patterns.map((item) => `${item.rule_id}\u0000${item.pattern}`)
  assert.deepEqual(keys, [...keys].sort())
})

test('attribute: reversed event order produces the same payload', () => {
  const reversed = attributeEvents([...STREAM.events].reverse(), PACK)
  assert.deepEqual(reversed, ATTR)
})

test('attribute: status gate alone blocks a pending rule with samples', () => {
  const pack = loadRulePack(
    customPack({
      failure_patterns: {
        categories: ['timeout', 'other'],
        rules: [
          {
            id: 'P-PENDING-WITH-SAMPLES',
            category: 'timeout',
            status: 'pending',
            patterns: ['boom'],
            verified_samples: ['有样例但状态仍是待核对'],
          },
        ],
      },
    }),
  )
  assert.deepEqual(pack.effective, [])
  assert.deepEqual(pack.ineffective, [
    { id: 'P-PENDING-WITH-SAMPLES', reasons: ['status=pending'] },
  ])
})

test('attribute: samples gate alone blocks a verified rule without samples', () => {
  const pack = loadRulePack(
    customPack({
      failure_patterns: {
        categories: ['timeout', 'other'],
        rules: [
          {
            id: 'P-VERIFIED-NO-SAMPLES',
            category: 'timeout',
            status: 'verified',
            patterns: ['boom'],
            verified_samples: [],
          },
        ],
      },
    }),
  )
  assert.deepEqual(pack.effective, [])
  assert.deepEqual(pack.ineffective, [
    { id: 'P-VERIFIED-NO-SAMPLES', reasons: ['verified_samples 为空'] },
  ])
})

test('attribute: both gates satisfied makes the rule effective', () => {
  const pack = loadRulePack(
    customPack({
      failure_patterns: {
        categories: ['timeout', 'other'],
        rules: [
          {
            id: 'P-OK',
            category: 'timeout',
            status: 'verified',
            patterns: ['boom'],
            verified_samples: ['真实样例'],
          },
        ],
      },
    }),
  )
  assert.deepEqual(pack.effective.map((rule) => rule.id), ['P-OK'])
  const payload = attributeEvents([normalizeEvent(claudeEvent(1, 'error', 'boom'), 'e')], pack)
  assert.equal(payload.effective_rule_ids[0], 'P-OK')
  assert.equal(payload.by_category[0]?.calls, 1)
})

test('attribute: synthetic coverage alone does not satisfy the samples gate', () => {
  const pack = loadRulePack(
    customPack({
      failure_patterns: {
        categories: ['content_refusal', 'other'],
        rules: [
          {
            id: 'P-SYNTHETIC-ONLY',
            category: 'content_refusal',
            status: 'verified',
            patterns: ['boom'],
            verified_samples: [],
            synthetic_coverage: { claude_servers: ['fake-low-fail'] },
          },
        ],
      },
    }),
  )
  assert.deepEqual(pack.effective, [])
  assert.equal(pack.ineffective[0]?.reasons[0], 'verified_samples 为空')
})

test('attribute: default effective rules all carry verified samples', () => {
  const byId = new Map(PACK.rules.map((rule) => [rule.id, rule]))
  for (const id of ATTR.effective_rule_ids) {
    const rule = byId.get(id)
    assert.ok(rule)
    assert.equal(rule.status, STATUS_VERIFIED)
    assert.ok(rule.verified_samples.length > 0)
  }
})

test('attribute: payload schema is opslens.attribute/1', () => {
  assert.equal(ATTR.schema, 'opslens.attribute/1')
  assert.ok(ATTR.coverage_note.includes('status=error'))
})

// ===========================================================================
// 6. 删换建议：阈值 / 证据 / 数据不足
// ===========================================================================

test('suggestion: fake-high-fail failure axis is remove_candidate', () => {
  const evaluation = evaluateServer(serverRow('fake-high-fail'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_REMOVE)
})

test('suggestion: fake-threshold-exact hits remove at the exact boundary', () => {
  const evaluation = evaluateServer(serverRow('fake-threshold-exact'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_REMOVE)
})

test('suggestion: fake-near-miss stays investigate', () => {
  const evaluation = evaluateServer(serverRow('fake-near-miss'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_INVESTIGATE)
})

test('suggestion: fake-mid-fail is investigate', () => {
  const evaluation = evaluateServer(serverRow('fake-mid-fail'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_INVESTIGATE)
})

test('suggestion: fake-retry is investigate', () => {
  const evaluation = evaluateServer(serverRow('fake-retry'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_INVESTIGATE)
})

test('suggestion: fake-low-fail produces no failure suggestion', () => {
  const evaluation = evaluateServer(serverRow('fake-low-fail'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_NONE)
})

test('suggestion: codex failure axis is low_signal due to sample size', () => {
  const evaluation = evaluateServer(serverRow('<codex>', 'codex'), PACK.thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_LOW_SIGNAL)
})

test('suggestion: fake-high-fail cost axis is cost_heavy', () => {
  const evaluation = evaluateServer(serverRow('fake-high-fail'), PACK.thresholds)
  assert.equal(evaluation.cost_suggestion, SUGGESTION_COST_HEAVY)
})

test('suggestion: fake-mid-fail cost axis stays below the cost threshold', () => {
  const evaluation = evaluateServer(serverRow('fake-mid-fail'), PACK.thresholds)
  assert.equal(evaluation.cost_suggestion, null)
  assert.equal(evaluation.suggestions.some((entry) => entry.type === SUGGESTION_COST_HEAVY), false)
})

test('suggestion: codex cost axis is not suggested and records insufficient samples', () => {
  const evaluation = evaluateServer(serverRow('<codex>', 'codex'), PACK.thresholds)
  assert.equal(evaluation.cost_suggestion, null)
  assert.equal(evaluation.insufficient.length, 2)
})

test('suggestion: remove entry carries complete evidence', () => {
  const evaluation = evaluateServer(serverRow('fake-high-fail'), PACK.thresholds)
  const entry = evaluation.suggestions.find((item) => item.type === SUGGESTION_REMOVE)
  assert.ok(entry)
  assert.equal(entry.axis, AXIS_FAILURE_RATE)
  assert.equal(entry.metric, 'failure_rate')
  assert.equal(entry.value, 0.6)
  assert.equal(entry.numerator, 24)
  assert.equal(entry.denominator, 40)
  assert.equal(entry.sample_size, 40)
  assert.deepEqual(entry.threshold, { failure_rate_gte: 0.5 })
  assert.ok(entry.basis.includes('分母不含 unknown'))
})

test('suggestion: investigate entry carries both thresholds', () => {
  const evaluation = evaluateServer(serverRow('fake-mid-fail'), PACK.thresholds)
  const entry = evaluation.suggestions.find((item) => item.type === SUGGESTION_INVESTIGATE)
  assert.ok(entry)
  assert.equal(entry.value, 0.277778)
  assert.equal(entry.denominator, 36)
  assert.equal(entry.sample_size, 40)
  assert.deepEqual(entry.threshold, { failure_rate_gte: 0.2, failure_rate_lt: 0.5 })
})

test('suggestion: cost entry carries token sum / sample / missing', () => {
  const evaluation = evaluateServer(serverRow('fake-high-fail'), PACK.thresholds)
  const entry = evaluation.suggestions.find((item) => item.type === SUGGESTION_COST_HEAVY)
  assert.ok(entry)
  assert.equal(entry.axis, AXIS_TURN_TOKEN)
  assert.equal(entry.metric, 'turn_token_avg')
  assert.equal(entry.value, 68303)
  assert.equal(entry.numerator, 2732120)
  assert.equal(entry.denominator, 40)
  assert.equal(entry.sample_size, 40)
  assert.equal(entry.missing, 0)
  assert.deepEqual(entry.threshold, { turn_token_avg_gte: 20000 })
})

test('suggestion: insufficient failure entry has observed / required sample', () => {
  const evaluation = evaluateServer(serverRow('<codex>', 'codex'), PACK.thresholds)
  const entry = evaluation.insufficient.find((item) => item.axis === AXIS_FAILURE_RATE)
  assert.ok(entry)
  assert.equal(entry.metric, 'calls_total')
  assert.equal(entry.observed_sample, 8)
  assert.equal(entry.required_sample, 20)
  assert.match(entry.reason, /样本不足/)
})

test('suggestion: insufficient cost entry has observed / required sample', () => {
  const evaluation = evaluateServer(serverRow('<codex>', 'codex'), PACK.thresholds)
  const entry = evaluation.insufficient.find((item) => item.axis === AXIS_TURN_TOKEN)
  assert.ok(entry)
  assert.equal(entry.metric, 'token_samples')
  assert.equal(entry.observed_sample, 0)
  assert.equal(entry.required_sample, 20)
  assert.match(entry.reason, /token 参与样本不足/)
})

test('suggestion: sufficient server has no insufficient entries', () => {
  const evaluation = evaluateServer(serverRow('fake-high-fail'), PACK.thresholds)
  assert.deepEqual(evaluation.insufficient, [])
})

test('suggestion: evidence completeness gate rejects a missing field', () => {
  assert.throws(
    () =>
      assertEvidenceComplete({
        type: SUGGESTION_REMOVE,
        axis: AXIS_FAILURE_RATE,
        metric: 'failure_rate',
        source: 'claude_code',
        server: 'fake-high-fail',
        value: 0.6,
        numerator: 24,
        denominator: 40,
        sample_requirement: { calls_total_gte: 20 },
        threshold: { failure_rate_gte: 0.5 },
        basis: 'x',
      }),
    /缺证据项 sample_size/,
  )
})

test('suggestion: evidence completeness gate accepts a complete entry', () => {
  const entry = {
    type: SUGGESTION_REMOVE,
    axis: AXIS_FAILURE_RATE,
    metric: 'failure_rate',
    source: 'claude_code',
    server: 'fake-high-fail',
    value: 0.6,
    numerator: 24,
    denominator: 40,
    sample_size: 40,
    sample_requirement: { calls_total_gte: 20 },
    threshold: { failure_rate_gte: 0.5 },
    basis: 'x',
  }
  assert.equal(assertEvidenceComplete(entry), entry)
})

test('suggestion: raising remove threshold demotes high-fail to none', () => {
  const thresholds = deepMerge(clone(DEFAULT_RULES.thresholds), {
    remove_candidate: { failure_rate_gte: 0.7 },
  })
  const evaluation = evaluateServer(serverRow('fake-high-fail'), thresholds)
  assert.equal(evaluation.failure_suggestion, SUGGESTION_NONE)
})

test('suggestion: lowering remove threshold promotes near-miss', () => {
  const thresholds = deepMerge(clone(DEFAULT_RULES.thresholds), {
    remove_candidate: { failure_rate_gte: 0.4 },
  })
  assert.equal(
    evaluateServer(serverRow('fake-near-miss'), thresholds).failure_suggestion,
    SUGGESTION_REMOVE,
  )
})

test('suggestion: raising minimum sample demotes high-fail to low_signal', () => {
  const thresholds = deepMerge(clone(DEFAULT_RULES.thresholds), {
    min_samples: { calls_total_gte: 100 },
  })
  assert.equal(
    evaluateServer(serverRow('fake-high-fail'), thresholds).failure_suggestion,
    SUGGESTION_LOW_SIGNAL,
  )
})

test('suggestion: raising token sample minimum records cost insufficiency', () => {
  const thresholds = deepMerge(clone(DEFAULT_RULES.thresholds), {
    min_samples: { token_samples_gte: 100 },
  })
  const evaluation = evaluateServer(serverRow('fake-high-fail'), thresholds)
  assert.equal(evaluation.cost_suggestion, null)
  assert.equal(evaluation.insufficient.some((item) => item.axis === AXIS_TURN_TOKEN), true)
})

test('suggestion: lowering cost threshold promotes mid-fail', () => {
  const thresholds = deepMerge(clone(DEFAULT_RULES.thresholds), {
    cost_heavy: { turn_token_avg_gte: 10000 },
  })
  assert.equal(
    evaluateServer(serverRow('fake-mid-fail'), thresholds).cost_suggestion,
    SUGGESTION_COST_HEAVY,
  )
})

test('suggestion: sort order is remove -> investigate -> cost', () => {
  const entries = []
  for (const row of AGG.server_level) {
    entries.push(...evaluateServer(row, PACK.thresholds).suggestions)
  }
  assert.deepEqual(
    sortSuggestions(entries).map((entry) => `${entry.type}/${entry.server}`),
    [
      'remove_candidate/fake-high-fail',
      'remove_candidate/fake-threshold-exact',
      'investigate/fake-mid-fail',
      'investigate/fake-near-miss',
      'investigate/fake-retry',
      'cost_heavy/fake-high-fail',
    ],
  )
})

test('suggestion: insufficient entries sort by axis then source/server', () => {
  const entries = []
  for (const row of AGG.server_level) {
    entries.push(...evaluateServer(row, PACK.thresholds).insufficient)
  }
  assert.deepEqual(
    sortInsufficient(entries).map((entry) => `${entry.axis}/${entry.server}`),
    ['failure_rate/<codex>', 'turn_token_avg/<codex>'],
  )
})

test('suggestion: six suggestions in total (2 remove / 3 investigate / 1 cost)', () => {
  const entries = []
  for (const row of AGG.server_level) {
    entries.push(...evaluateServer(row, PACK.thresholds).suggestions)
  }
  assert.equal(entries.length, 6)
  assert.equal(entries.filter((entry) => entry.type === SUGGESTION_REMOVE).length, 2)
  assert.equal(entries.filter((entry) => entry.type === SUGGESTION_INVESTIGATE).length, 3)
  assert.equal(entries.filter((entry) => entry.type === SUGGESTION_COST_HEAVY).length, 1)
})

test('suggestion: exactly two insufficient entries for codex', () => {
  const entries = []
  for (const row of AGG.server_level) {
    entries.push(...evaluateServer(row, PACK.thresholds).insufficient)
  }
  assert.equal(entries.length, 2)
  assert.equal(entries.every((entry) => entry.server === '<codex>'), true)
})

// ===========================================================================
// 7. 规则包校验
// ===========================================================================

test('rules: default pack loads with 3 effective / 1 ineffective', () => {
  assert.equal(PACK.rules.length, 4)
  assert.equal(PACK.effective.length, 3)
  assert.equal(PACK.ineffective.length, 1)
})

test('rules: missing third pack is rejected', () => {
  assert.throws(
    () => loadRulePack({ params: clone(DEFAULT_RULES.params), thresholds: clone(DEFAULT_RULES.thresholds) }),
    RulePackError,
  )
})

test('rules: unknown top-level key is rejected', () => {
  assert.throws(() => loadRulePack({ ...customPack(), extra: 1 }), RulePackError)
})

test('rules: params without retry window is rejected', () => {
  const pack = customPack()
  delete pack.params.retry.window_seconds
  assert.throws(() => loadRulePack(pack), /retry.window_seconds/)
})

test('rules: params without rate_precision is rejected', () => {
  const pack = customPack()
  delete pack.params.rate_precision
  assert.throws(() => loadRulePack(pack), /rate_precision/)
})

test('rules: thresholds without remove_candidate rate is rejected', () => {
  const pack = customPack()
  delete pack.thresholds.remove_candidate.failure_rate_gte
  assert.throws(() => loadRulePack(pack), /remove_candidate.failure_rate_gte/)
})

test('rules: thresholds without investigate bounds is rejected', () => {
  const pack = customPack()
  delete pack.thresholds.investigate.failure_rate_lt
  assert.throws(() => loadRulePack(pack), /investigate.failure_rate_lt/)
})

test('rules: categories must be an array', () => {
  const pack = customPack({ failure_patterns: { categories: 'timeout', rules: [] } })
  assert.throws(() => loadRulePack(pack), /categories 必须是字符串数组/)
})

test('rules: rules must be an array', () => {
  const pack = customPack({ failure_patterns: { categories: [], rules: {} } })
  assert.throws(() => loadRulePack(pack), /rules 必须是数组/)
})

test('rules: rule without id is rejected', () => {
  const pack = customPack({
    failure_patterns: { categories: [], rules: [{ status: 'verified', patterns: [] }] },
  })
  assert.throws(() => loadRulePack(pack), /\.id 必须是非空字符串/)
})

test('rules: invalid regular expression is rejected', () => {
  const pack = customPack({
    failure_patterns: {
      categories: [],
      rules: [
        { id: 'R-1', status: 'verified', patterns: ['['], verified_samples: ['x'] },
      ],
    },
  })
  assert.throws(() => loadRulePack(pack), /不是合法正则/)
})

test('rules: rule without status is rejected', () => {
  const pack = customPack({
    failure_patterns: {
      categories: [],
      rules: [{ id: 'R-1', patterns: [], verified_samples: ['x'] }],
    },
  })
  assert.throws(() => loadRulePack(pack), /\.status 必须是非空字符串/)
})

test('rules: verified_samples must be an array', () => {
  const pack = customPack({
    failure_patterns: {
      categories: [],
      rules: [{ id: 'R-1', status: 'verified', patterns: [], verified_samples: 'x' }],
    },
  })
  assert.throws(() => loadRulePack(pack), /verified_samples 必须是数组/)
})

test('rules: valid custom pack loads without touching defaults', () => {
  const pack = loadRulePack(
    customPack({
      failure_patterns: {
        categories: ['timeout', 'other'],
        rules: [
          { id: 'R-1', category: 'timeout', status: 'verified', patterns: ['boom'], verified_samples: ['x'] },
        ],
      },
    }),
  )
  assert.equal(pack.rules.length, 1)
  assert.deepEqual(pack.categories, ['timeout', 'other'])
})

// ===========================================================================
// 8. 器官主张：13 类 check / verdict 映射
// ===========================================================================

test('claim metric: matching server row is a claim', () => {
  const record = evalClaim({
    check: 'metric',
    level: 'server',
    source: 'claude_code',
    server: 'fake-high-fail',
    field: 'failure_rate',
    asserted: 0.6,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim metric: tool-level row is a claim', () => {
  const record = evalClaim({
    check: 'metric',
    level: 'tool',
    source: 'claude_code',
    server: 'fake-high-fail',
    tool: 'tool_fetch',
    field: 'failure_rate',
    asserted: 0.65,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim metric: null rate is claimable', () => {
  const record = evalClaim({
    check: 'metric',
    level: 'tool',
    source: 'codex',
    server: '<codex>',
    tool: 'view_image',
    field: 'failure_rate',
    asserted: null,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim metric: mismatch without node is inconclusive', () => {
  const record = evalClaim({
    check: 'metric',
    level: 'server',
    source: 'claude_code',
    server: 'fake-high-fail',
    field: 'failure_rate',
    asserted: 0.5,
  })
  assert.equal(record.verdict, INCONCLUSIVE)
})

test('claim metric: mismatch with node is refuted', () => {
  const record = evalClaim({
    check: 'metric',
    level: 'server',
    source: 'claude_code',
    server: 'fake-high-fail',
    field: 'failure_rate',
    asserted: 0.5,
    node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
  })
  assert.equal(record.verdict, REFUTED)
})

test('claim metric: missing row with node is refuted', () => {
  const record = evalClaim({
    check: 'metric',
    level: 'server',
    source: 'claude_code',
    server: 'fake-nope',
    field: 'calls_total',
    asserted: 0,
    node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
  })
  assert.equal(record.verdict, REFUTED)
  assert.match(record.message, /未找到/)
})

test('claim totals: matching total is a claim', () => {
  const record = evalClaim({ check: 'totals', field: 'calls_error', asserted: 75 })
  assert.equal(record.verdict, CLAIM)
})

test('claim params: retry window is a claim', () => {
  const record = evalClaim({ check: 'params', field: 'retry_window_seconds', asserted: 120 })
  assert.equal(record.verdict, CLAIM)
})

test('claim category: matching category count is a claim', () => {
  const record = evalClaim({ check: 'category', category: 'timeout', asserted: 24 })
  assert.equal(record.verdict, CLAIM)
})

test('claim category: undeclared category is inconclusive', () => {
  const record = evalClaim({ check: 'category', category: 'not_declared', asserted: 0 })
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /不在声明类别表/)
})

test('claim server_category: matching count is a claim', () => {
  const record = evalClaim({
    check: 'server_category',
    source: 'claude_code',
    server: 'fake-high-fail',
    category: 'timeout',
    asserted: 12,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim event_category: error event is claimable', () => {
  const record = evalClaim({
    check: 'event_category',
    source: 'claude_code',
    session_id: 'sess-claude-high',
    seq: 10,
    asserted: 'timeout',
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim event_category: ok event is not_attributed', () => {
  const record = evalClaim({
    check: 'event_category',
    source: 'claude_code',
    session_id: 'sess-claude-high',
    seq: 2,
    asserted: 'not_attributed',
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim effective: pending rule is ineffective with reasons', () => {
  const record = evalClaim({
    check: 'effective',
    rule_id: 'F-REFUSE-1',
    asserted: false,
    reasons: ['status=pending', 'verified_samples 为空'],
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim effective: reason mismatch with node is refuted', () => {
  const record = evalClaim({
    check: 'effective',
    rule_id: 'F-REFUSE-1',
    asserted: false,
    reasons: ['status=pending'],
    node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
  })
  assert.equal(record.verdict, REFUTED)
  assert.match(record.message, /未生效原因不符/)
})

test('claim effective: unknown rule is inconclusive without node', () => {
  const record = evalClaim({ check: 'effective', rule_id: 'F-NOPE', asserted: false })
  assert.equal(record.verdict, INCONCLUSIVE)
})

test('claim suggestion: remove_candidate is a claim', () => {
  const record = evalClaim({
    check: 'suggestion',
    axis: 'failure_rate',
    source: 'claude_code',
    server: 'fake-high-fail',
    asserted: 'remove_candidate',
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim suggestion: evidence fields are checked', () => {
  const record = evalClaim({
    check: 'suggestion',
    axis: 'failure_rate',
    source: 'claude_code',
    server: 'fake-high-fail',
    asserted: 'remove_candidate',
    evidence: { value: 0.6, numerator: 24, denominator: 40, sample_size: 40 },
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim suggestion: wrong evidence with node is refuted', () => {
  const record = evalClaim({
    check: 'suggestion',
    axis: 'failure_rate',
    source: 'claude_code',
    server: 'fake-high-fail',
    asserted: 'remove_candidate',
    evidence: { denominator: 41 },
    node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
  })
  assert.equal(record.verdict, REFUTED)
  assert.match(record.message, /evidence.denominator 不符/)
})

test('claim suggestion: codex low_signal is a claim', () => {
  const record = evalClaim({
    check: 'suggestion',
    axis: 'failure_rate',
    source: 'codex',
    server: '<codex>',
    asserted: 'low_signal',
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim insufficient: codex sample shortfall is a claim', () => {
  const record = evalClaim({
    check: 'insufficient',
    axis: 'failure_rate',
    source: 'codex',
    server: '<codex>',
    asserted: true,
    observed_sample: 8,
    required_sample: 20,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim insufficient: false when the entry exists is refuted with node', () => {
  const record = evalClaim({
    check: 'insufficient',
    axis: 'failure_rate',
    source: 'codex',
    server: '<codex>',
    asserted: false,
    node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
  })
  assert.equal(record.verdict, REFUTED)
})

test('claim event: normalized tokens can be claimed', () => {
  const record = evalClaim({
    check: 'event',
    source: 'claude_code',
    session_id: 'sess-claude-high',
    seq: 2,
    field: 'tokens',
    asserted: { input: 53386, output: 1045, cache_read: 11280, cache_creation: 85 },
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim event: wrong status with node is refuted', () => {
  const record = evalClaim({
    check: 'event',
    source: 'claude_code',
    session_id: 'sess-claude-high',
    seq: 10,
    field: 'status',
    asserted: 'ok',
    node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
  })
  assert.equal(record.verdict, REFUTED)
})

test('claim stream: schema is a claim', () => {
  const record = evalClaim({ check: 'stream', field: 'schema', asserted: EVENT_SCHEMA })
  assert.equal(record.verdict, CLAIM)
})

test('claim stream: sorted is a claim', () => {
  const record = evalClaim({ check: 'stream', field: 'sorted', asserted: true })
  assert.equal(record.verdict, CLAIM)
})

test('claim timestamp: offset conversion is a claim', () => {
  const record = evalClaim({
    check: 'timestamp',
    timestamp: '2026-10-16T01:00:00+01:00',
    asserted: 1792108800,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim timestamp: unparseable value is null and claimable', () => {
  const record = evalClaim({ check: 'timestamp', timestamp: 'T0', asserted: null })
  assert.equal(record.verdict, CLAIM)
})

test('claim count: events count is a claim', () => {
  const record = evalClaim({ check: 'count', of: 'events', asserted: 202 })
  assert.equal(record.verdict, CLAIM)
})

test('claim count: matched pattern count is a claim', () => {
  const record = evalClaim({
    check: 'count',
    of: 'matched_pattern',
    rule_id: 'F-TIMEOUT-1',
    pattern: 'Command timed out after',
    asserted: 15,
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim count: suggestion type count is a claim', () => {
  const record = evalClaim({ check: 'count', of: 'suggestion', type: 'remove_candidate', asserted: 2 })
  assert.equal(record.verdict, CLAIM)
})

test('claim count: insufficient count is a claim', () => {
  const record = evalClaim({ check: 'count', of: 'insufficient', asserted: 2 })
  assert.equal(record.verdict, CLAIM)
})

test('claim count: tool_level count is a claim', () => {
  const record = evalClaim({ check: 'count', of: 'tool_level', asserted: 12 })
  assert.equal(record.verdict, CLAIM)
})

test('claim count: effective rule count is a claim', () => {
  const record = evalClaim({ check: 'count', of: 'effective_rules', asserted: 3 })
  assert.equal(record.verdict, CLAIM)
})

test('contract: unknown claim field is rejected', () => {
  assert.throws(
    () =>
      evaluateToolOpsAttribution(
        { events: EVENTS_PAYLOAD, claims: [claim({ check: 'count', of: 'events', asserted: 1, surprise: 1 })] },
        Basis.empty('1'),
      ),
    ContractError,
  )
})

test('contract: unknown check is rejected', () => {
  assert.throws(
    () =>
      evaluateToolOpsAttribution(
        { events: EVENTS_PAYLOAD, claims: [claim({ check: 'nope', asserted: 1 })] },
        Basis.empty('1'),
      ),
    ContractError,
  )
})

test('contract: duplicate claim_id is rejected', () => {
  assert.throws(
    () =>
      evaluateToolOpsAttribution(
        {
          events: EVENTS_PAYLOAD,
          claims: [
            { claim_id: 'dup', check: 'count', of: 'events', asserted: 202 },
            { claim_id: 'dup', check: 'count', of: 'events', asserted: 202 },
          ],
        },
        Basis.empty('1'),
      ),
    ContractError,
  )
})

test('contract: empty claims are rejected', () => {
  assert.throws(
    () => evaluateToolOpsAttribution({ events: EVENTS_PAYLOAD, claims: [] }, Basis.empty('1')),
    ContractError,
  )
})

test('contract: bad metric field is rejected', () => {
  assert.throws(
    () => evalClaim({ check: 'metric', level: 'server', source: 'codex', server: '<codex>', field: 'nope', asserted: 0 }),
    ContractError,
  )
})

test('contract: bad asserted type is rejected', () => {
  assert.throws(
    () => evalClaim({ check: 'totals', field: 'calls_total', asserted: '202' }),
    ContractError,
  )
})

test('contract: bad suggestion label is rejected', () => {
  assert.throws(
    () => evalClaim({ check: 'suggestion', axis: 'failure_rate', source: 'codex', server: '<codex>', asserted: 'cost_heavy' }),
    ContractError,
  )
})

test('contract: level=server rejects tool', () => {
  assert.throws(
    () =>
      evalClaim({
        check: 'metric',
        level: 'server',
        source: 'codex',
        server: '<codex>',
        tool: 'exec',
        field: 'calls_total',
        asserted: 0,
      }),
    ContractError,
  )
})

test('contract: claim node missing from basis throws NodeMissing', () => {
  assert.throws(
    () =>
      evaluateToolOpsAttribution(
        {
          events: EVENTS_PAYLOAD,
          claims: [
            {
              claim_id: 'missing-node',
              check: 'metric',
              level: 'server',
              source: 'claude_code',
              server: 'fake-high-fail',
              field: 'failure_rate',
              asserted: 0.6,
              node: { session_id: 's-ops-1', turn: 9, tool_call_id: 'call-ops-9' },
            },
          ],
        },
        Basis.empty('1'),
      ),
    NodeMissing,
  )
})

test('contract: incomplete node downgrades a matching claim to inconclusive', () => {
  const node = { session_id: 's-ops-1', turn: null, tool_call_id: 'call-ops-1' }
  const record = recordFor(
    {
      check: 'metric',
      level: 'server',
      source: 'claude_code',
      server: 'fake-high-fail',
      field: 'failure_rate',
      asserted: 0.6,
      node,
    },
    {},
    [node],
  )
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /痕迹节点不完整/)
})

test('contract: records are sorted deterministically by claim_id', () => {
  const records = evaluateEvents(STREAM.events, [
    { claim_id: 'b', check: 'count', of: 'events', asserted: 202 },
    { claim_id: 'a', check: 'count', of: 'events', asserted: 202 },
  ])
  const report = new Report({
    product: 'traceproof',
    verb: 'tool-ops-attribution',
    verb_version: VERSION,
    subject: 'test',
    records,
  })
  assert.deepEqual(report.records.map((record) => record.claim_id), ['a', 'b'])
})

test('contract: claim evidence is not accepted on non-suggestion checks', () => {
  assert.throws(
    () =>
      evalClaim({
        check: 'event',
        source: 'claude_code',
        session_id: 'sess-claude-high',
        seq: 2,
        field: 'status',
        asserted: 'ok',
        evidence: { token: 'x' },
      }),
    ContractError,
  )
})

// ===========================================================================
// 9. CLI / 样例 / 打包数据
// ===========================================================================

test('cli: list shows tool-ops-attribution at 0.2.0', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /tool-ops-attribution\s+0\.2\.0/)
})

test('cli: list --json returns nine verbs including the new one', async () => {
  const { code, out } = await capture(() => main(['list', '--json']))
  assert.equal(code, EXIT_OK)
  const verbs = JSON.parse(out)
  assert.equal(verbs.length, 9)
  assert.ok(verbs.some((verb) => verb.slug === 'tool-ops-attribution' && verb.version === '0.2.0'))
})

test('cli: sample subject exits 0 with 46 claims', async () => {
  const { code, out } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', SAMPLE_PATH, '--basis', TRACES_PATH]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /合计 46 条，阻断 0 条（claim=46 refuted=0 inconclusive=0）/)
})

test('cli: sample --json reports total 46 / blocking 0', async () => {
  const { code, out } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', SAMPLE_PATH, '--basis', TRACES_PATH, '--json']),
  )
  assert.equal(code, EXIT_OK)
  const report = JSON.parse(out)
  assert.equal(report.summary.total, 46)
  assert.equal(report.summary.blocking, 0)
  assert.equal(report.verb, 'tool-ops-attribution')
  assert.equal(report.verb_version, '0.2.0')
})

test('cli: sample output is byte-identical across two runs', async () => {
  const first = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', SAMPLE_PATH, '--basis', TRACES_PATH, '--json']),
  )
  const second = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', SAMPLE_PATH, '--basis', TRACES_PATH, '--json']),
  )
  assert.equal(first.code, EXIT_OK)
  assert.equal(second.code, EXIT_OK)
  assert.equal(first.out, second.out)
})

test('cli: a refuted claim exits 1', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    events: EVENTS_PAYLOAD,
    claims: [
      {
        claim_id: 'refuted',
        check: 'metric',
        level: 'server',
        source: 'claude_code',
        server: 'fake-high-fail',
        field: 'failure_rate',
        asserted: 0.1,
        node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' },
      },
    ],
  })
  const basis = writeJSON(dir, 'basis.json', {
    version: '1',
    nodes: [{ session_id: 's-ops-1', turn: 1, tool_call_id: 'call-ops-1' }],
  })
  const { code, out } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', input, '--basis', basis]),
  )
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /\[refuted\] refuted/)
})

test('cli: an inconclusive claim exits 0', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    events: EVENTS_PAYLOAD,
    claims: [
      {
        claim_id: 'inconclusive',
        check: 'metric',
        level: 'server',
        source: 'claude_code',
        server: 'fake-high-fail',
        field: 'failure_rate',
        asserted: 0.1,
      },
    ],
  })
  const basis = writeJSON(dir, 'basis.json', { version: '1', nodes: [] })
  const { code, out } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', input, '--basis', basis]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /\[inconclusive\]/)
})

test('cli: a missing trace node exits 3', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    events: EVENTS_PAYLOAD,
    claims: [
      {
        claim_id: 'missing-node',
        check: 'count',
        of: 'events',
        asserted: 202,
        node: { session_id: 's-ops-1', turn: 1, tool_call_id: 'call-missing' },
      },
    ],
  })
  const basis = writeJSON(dir, 'basis.json', { version: '1', nodes: [] })
  const { code, err } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', input, '--basis', basis]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: bad rules pack exits 2', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    events: EVENTS_PAYLOAD,
    rules: { params: DEFAULT_RULES.params },
    claims: [{ claim_id: 'c', check: 'count', of: 'events', asserted: 202 }],
  })
  const basis = writeJSON(dir, 'basis.json', { version: '1', nodes: [] })
  const { code, err } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', input, '--basis', basis]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /rules 需要 params/)
})

test('cli: invalid JSON input exits 2', async () => {
  const dir = tempDir()
  const input = join(dir, 'bad.json')
  writeFileSync(input, '{not json')
  const { code, err } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', input, '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /输入不合法/)
})

test('cli: missing required subject field exits 2', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', { claims: [{ claim_id: 'c', check: 'count', of: 'events', asserted: 1 }] })
  const { code } = await capture(() =>
    main(['check', 'tool-ops-attribution', '--input', input, '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_INPUT)
})

test('sample: subject carries 202 events and 46 claims', () => {
  const sample = JSON.parse(readFileSync(SAMPLE_PATH, 'utf8'))
  assert.equal(sample.events.events.length, 202)
  assert.equal(sample.claims.length, 46)
  assert.deepEqual(
    sample.claims.map((item) => item.claim_id),
    [...sample.claims.map((item) => item.claim_id)].sort(),
  )
})

test('sample: traces version and nodes are complete', () => {
  const traces = JSON.parse(readFileSync(TRACES_PATH, 'utf8'))
  assert.equal(traces.version, '2026.11.25')
  assert.equal(traces.nodes.length, 4)
  for (const node of traces.nodes) {
    assert.ok(node.session_id)
    assert.ok(Number.isInteger(node.turn))
    assert.ok(node.tool_call_id)
  }
})

test('sample: every claim in the sample evaluates to claim', () => {
  const sample = JSON.parse(readFileSync(SAMPLE_PATH, 'utf8'))
  const traces = JSON.parse(readFileSync(TRACES_PATH, 'utf8'))
  const records = [
    ...evaluateToolOpsAttribution(
      { events: sample.events, claims: sample.claims },
      Basis.fromObject(traces),
    ),
  ]
  assert.equal(records.length, 46)
  assert.equal(records.every((record) => record.verdict === CLAIM), true)
})

test('package: organ data files are imported (path and sizes)', () => {
  const dataDir = fileURLToPath(new URL('../src/traceproof/verbs/tool-ops-attribution/data/', import.meta.url))
  const names = ['params.json', 'thresholds.json', 'failure-patterns.json']
  for (const name of names) {
    const text = readFileSync(join(dataDir, name), 'utf8')
    assert.ok(text.length > 100, `${name} 数据文件过小`)
  }
})

test('package: default rule ids are the four source rules', () => {
  assert.deepEqual(
    PACK.rules.map((rule) => rule.id),
    ['F-TIMEOUT-1', 'F-PERM-1', 'F-ARGS-1', 'F-REFUSE-1'],
  )
})

test('package: coverage notes state the denominator / source caveats', () => {
  assert.ok(AGG.coverage_note.includes('失败率分母不含 unknown'))
  assert.ok(AGG.coverage_note.includes('duration_available=false'))
  assert.ok(ATTR.coverage_note.includes('status=error'))
  assert.ok(ATTR.coverage_note.includes('status=unknown'))
})