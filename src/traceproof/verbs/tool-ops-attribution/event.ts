/**
 * tool-ops-attribution · 统一事件流（IR）读取与规范化。
 *
 * 迁移来源：源仓 `schema.py` + `pipeline.events_from_payload`。判定层只接收**已解析**的
 * 事件流；日志发现 / JSONL 解析 / 文件读取留在输入侧（D18：`parse` 不迁）。
 *
 * 三态纪律沿用源仓：`status` 缺省 = `unknown`（**绝不等于成功**）；`tokens=null` 表示
 * 该源/该条不提供 token 归因（**不等于 0**）；`duration_ms=null` 表示不可得。
 *
 * 事件流载荷 schema 固定 `opslens.events/1`；器官不读文件、不读时钟。
 */

import { ContractError } from '../../core/ledger.js'
import { compareText, isPlainObject, readExactString, readFiniteNumber, readInteger } from './util.js'

export const EVENT_SCHEMA = 'opslens.events/1'

export const EVENT_SOURCES = ['claude_code', 'codex'] as const
export type EventSource = (typeof EVENT_SOURCES)[number]

export const EVENT_STATUSES = ['ok', 'error', 'unknown'] as const
export type EventStatus = (typeof EVENT_STATUSES)[number]

export interface EventTokens {
  readonly input: number
  readonly output: number
  readonly cache_read: number
  readonly cache_creation: number
}

export interface NormalizedEvent {
  readonly source: EventSource
  readonly source_version: string
  readonly session_id: string
  readonly seq: number
  readonly timestamp: string
  readonly server: string
  readonly tool: string
  readonly call_id: string
  readonly status: EventStatus
  readonly error_text: string
  readonly tokens: EventTokens | null
  readonly duration_ms: number | null
  readonly turn_tokens_attributed: boolean
  readonly notes: readonly string[]
}

export const EVENT_FIELDS = [
  'source',
  'source_version',
  'session_id',
  'seq',
  'timestamp',
  'server',
  'tool',
  'call_id',
  'status',
  'error_text',
  'tokens',
  'duration_ms',
  'turn_tokens_attributed',
  'notes',
] as const

const TOKEN_FIELDS = ['input', 'output', 'cache_read', 'cache_creation'] as const

const STREAM_FIELDS = [
  'schema',
  'count',
  'events',
  'home',
  'sources',
  'schema_versions',
  'coverage_note',
] as const

function readTokens(raw: unknown, where: string): EventTokens | null {
  if (raw === undefined || raw === null) return null
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象或 null`)
  for (const key of Object.keys(raw)) {
    if (!(TOKEN_FIELDS as readonly string[]).includes(key)) {
      throw new ContractError(`${where} 含未知字段：${key}`)
    }
  }
  const value = (name: (typeof TOKEN_FIELDS)[number]): number =>
    raw[name] === undefined ? 0 : readFiniteNumber(raw[name], `${where}.${name}`)
  return {
    input: value('input'),
    output: value('output'),
    cache_read: value('cache_read'),
    cache_creation: value('cache_creation'),
  }
}

function readNotes(raw: unknown, where: string): string[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) throw new ContractError(`${where} 必须是字符串数组`)
  return raw.map((item, index) => readExactString(item, `${where}[${index}]`, true))
}

function readDuration(raw: unknown, where: string): number | null {
  if (raw === undefined || raw === null) return null
  return readFiniteNumber(raw, where)
}

function readStatus(raw: unknown, where: string): EventStatus {
  if (raw === undefined) return 'unknown'
  if (typeof raw !== 'string' || !(EVENT_STATUSES as readonly string[]).includes(raw)) {
    throw new ContractError(`${where} 非法：<${String(raw)}>（允许 ${EVENT_STATUSES.join(' / ')}）`)
  }
  return raw as EventStatus
}

function readSource(raw: unknown, where: string): EventSource {
  if (typeof raw !== 'string' || !(EVENT_SOURCES as readonly string[]).includes(raw)) {
    throw new ContractError(`${where} 非法：<${String(raw)}>（允许 ${EVENT_SOURCES.join(' / ')}）`)
  }
  return raw as EventSource
}

/** 单条事件：只认 `opslens.events/1` 的字段面；未知字段 / 坏枚举 → 契约错误。 */
export function normalizeEvent(raw: unknown, where: string): NormalizedEvent {
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!(EVENT_FIELDS as readonly string[]).includes(key)) {
      throw new ContractError(`${where} 含未知字段：${key}`)
    }
  }
  if (raw.turn_tokens_attributed !== undefined && typeof raw.turn_tokens_attributed !== 'boolean') {
    throw new ContractError(`${where}.turn_tokens_attributed 必须是布尔值`)
  }
  return {
    source: readSource(raw.source, `${where}.source`),
    source_version:
      raw.source_version === undefined ? '' : readExactString(raw.source_version, `${where}.source_version`, true),
    session_id: readExactString(raw.session_id, `${where}.session_id`),
    seq: readInteger(raw.seq, `${where}.seq`),
    timestamp: raw.timestamp === undefined ? '' : readExactString(raw.timestamp, `${where}.timestamp`, true),
    server: readExactString(raw.server, `${where}.server`),
    tool: readExactString(raw.tool, `${where}.tool`),
    call_id: raw.call_id === undefined ? '' : readExactString(raw.call_id, `${where}.call_id`, true),
    status: readStatus(raw.status, `${where}.status`),
    error_text: raw.error_text === undefined ? '' : readExactString(raw.error_text, `${where}.error_text`, true),
    tokens: readTokens(raw.tokens, `${where}.tokens`),
    duration_ms: readDuration(raw.duration_ms, `${where}.duration_ms`),
    turn_tokens_attributed: raw.turn_tokens_attributed === true,
    notes: readNotes(raw.notes, `${where}.notes`),
  }
}

export function compareEvents(left: NormalizedEvent, right: NormalizedEvent): number {
  return (
    compareText(left.source, right.source) ||
    compareText(left.session_id, right.session_id) ||
    left.seq - right.seq
  )
}

export function isSorted(events: readonly NormalizedEvent[]): boolean {
  for (let index = 1; index < events.length; index += 1) {
    if (compareEvents(events[index - 1] as NormalizedEvent, events[index] as NormalizedEvent) > 0) {
      return false
    }
  }
  return true
}

export interface EventStream {
  readonly events: readonly NormalizedEvent[]
  readonly schema: string
  readonly count: number
  readonly sorted: boolean
}

/** 事件流：接受 `opslens.events/1` 载荷对象，或裸事件数组（视为同一 IR）。 */
export function readEventStream(raw: unknown, where: string): EventStream {
  if (Array.isArray(raw)) {
    const events = raw.map((item, index) => normalizeEvent(item, `${where}[${index}]`))
    return { events, schema: EVENT_SCHEMA, count: events.length, sorted: isSorted(events) }
  }
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是事件数组或 opslens.events/1 载荷对象`)
  for (const key of Object.keys(raw)) {
    if (!(STREAM_FIELDS as readonly string[]).includes(key)) {
      throw new ContractError(`${where} 含未知字段：${key}`)
    }
  }
  if (raw.schema !== EVENT_SCHEMA) {
    throw new ContractError(`${where}.schema 必须是 ${EVENT_SCHEMA}（收到 <${String(raw.schema)}>）`)
  }
  if (!Array.isArray(raw.events)) throw new ContractError(`${where}.events 必须是数组`)
  const events = raw.events.map((item, index) => normalizeEvent(item, `${where}.events[${index}]`))
  if (raw.count !== undefined) {
    const declared = readInteger(raw.count, `${where}.count`)
    if (declared !== events.length) {
      throw new ContractError(`${where}.count=${declared} 与 events 条数 ${events.length} 不一致`)
    }
  }
  return { events, schema: EVENT_SCHEMA, count: events.length, sorted: isSorted(events) }
}