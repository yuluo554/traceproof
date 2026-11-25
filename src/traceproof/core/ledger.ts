/**
 * 取证账本：traceproof 的唯一输出模型（契约见 SKELETON-SPEC §3–§6）。
 *
 * 一条账本行 = 一个主张 + 一个痕迹节点。
 *
 * 三条约束是结构性的，不是文档约定：
 *  1. 无痕迹节点不下 `refuted`（构造即 `ContractError`，进程退出码 3）；
 *  2. 痕迹节点不完整（缺 turn / tool_call_id）-> 降级 `inconclusive` 并写明缺失项；
 *  3. **脱敏前置**：`evidence` 在入账时就地脱敏，不存在「先入库再打码」的通路。
 */

import { redactDeep } from './redact.js'

export const CLAIM = 'claim'
export const REFUTED = 'refuted'
export const INCONCLUSIVE = 'inconclusive'

export type Verdict = 'claim' | 'refuted' | 'inconclusive'
export const VERDICTS: readonly Verdict[] = [CLAIM, REFUTED, INCONCLUSIVE]
/** 会阻断的结论；`claim` / `inconclusive` 只记录、不阻断。 */
export const BLOCKING_VERDICTS: readonly Verdict[] = [REFUTED]

export const EXIT_OK = 0
export const EXIT_BLOCKED = 1
export const EXIT_INPUT = 2
export const EXIT_CONTRACT = 3

/** 契约违约：无节点下 refuted、节点字段为空、结论取值非法。 */
export class ContractError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ContractError'
  }
}

export interface TraceNodeInit {
  session_id: string
  turn?: number | null
  tool_call_id?: string
  quote?: string
}

/** 痕迹节点：`session_id + turn + tool_call_id`（SKELETON-SPEC §3）。 */
export interface TraceNode {
  readonly session_id: string
  readonly turn: number | null
  readonly tool_call_id: string
  readonly quote: string
  /** 三个定位字段是否齐备（缺一不得支撑 refuted）。 */
  readonly complete: boolean
}

export function makeNode(init: TraceNodeInit): TraceNode {
  const sessionId = (init.session_id ?? '').trim()
  if (!sessionId) throw new ContractError('痕迹节点字段为空：session_id')
  const turn = init.turn === undefined ? null : init.turn
  const toolCallId = (init.tool_call_id ?? '').trim()
  const complete = turn !== null && Number.isInteger(turn) && toolCallId.length > 0
  return Object.freeze({
    session_id: sessionId,
    turn,
    tool_call_id: toolCallId,
    quote: init.quote ?? '',
    complete,
  })
}

export function nodeToJSON(node: TraceNode): Record<string, unknown> {
  return {
    session_id: node.session_id,
    turn: node.turn,
    tool_call_id: node.tool_call_id,
    quote: node.quote,
  }
}

export interface RecordInit {
  claim_id: string
  verdict: Verdict
  message: string
  node?: TraceNode | null
  evidence?: Record<string, unknown>
}

export interface LedgerRecord {
  readonly claim_id: string
  readonly verdict: Verdict
  readonly message: string
  readonly node: TraceNode | null
  readonly evidence: Record<string, unknown>
  readonly id: string
}

/**
 * 造一条账本行。这里是三条内核约束唯一的落点 —— 绕过它就绕过了契约。
 */
export function makeRecord(init: RecordInit): LedgerRecord {
  const claimId = (init.claim_id ?? '').trim()
  if (!claimId) throw new ContractError('claim_id 为空')
  if (!VERDICTS.includes(init.verdict)) {
    throw new ContractError(`非法结论：${String(init.verdict)}（允许 ${VERDICTS.join(' / ')}）`)
  }

  const node = init.node ?? null
  if (node === null && BLOCKING_VERDICTS.includes(init.verdict)) {
    throw new ContractError(`无痕迹节点不得下 refuted（claim=${claimId}）`)
  }

  // §4.4 脱敏前置：证据在入账那一刻就脱敏（深拷贝，调用方的对象不被改）
  const evidence = redactDeep(init.evidence ?? {}) as Record<string, unknown>

  let verdict = init.verdict
  let message = init.message
  if (node !== null && !node.complete) {
    const missing: string[] = []
    if (node.turn === null) missing.push('turn')
    if (!node.tool_call_id) missing.push('tool_call_id')
    verdict = INCONCLUSIVE
    message = `${message}（痕迹节点不完整：缺 ${missing.join(' / ')}，按契约降级为 inconclusive）`
  }

  return Object.freeze({
    claim_id: claimId,
    verdict,
    message,
    node,
    evidence,
    id: recordId(claimId, node),
  })
}

function recordId(claimId: string, node: TraceNode | null): string {
  if (node === null) return `${claimId}@-`
  return `${claimId}@${node.session_id}#${node.turn ?? '-'}#${node.tool_call_id || '-'}`
}

export function recordToJSON(record: LedgerRecord): Record<string, unknown> {
  return {
    id: record.id,
    claim_id: record.claim_id,
    verdict: record.verdict,
    message: record.message,
    basis_ref: record.node === null ? null : nodeToJSON(record.node),
    evidence: record.evidence,
  }
}

export function recordLine(record: LedgerRecord): string {
  const where =
    record.node === null
      ? '无节点'
      : `${record.node.session_id}#${record.node.turn ?? '-'}#${record.node.tool_call_id || '-'}`
  return `[${record.verdict}] ${record.claim_id} — ${record.message} :: ${where}`
}

export interface ReportInit {
  product: string
  verb: string
  verb_version: string
  subject: string
  records?: readonly LedgerRecord[]
}

export class Report {
  readonly product: string
  readonly verb: string
  readonly verbVersion: string
  readonly subject: string
  readonly records: readonly LedgerRecord[]

  constructor(init: ReportInit) {
    for (const [name, value] of [
      ['product', init.product],
      ['verb', init.verb],
      ['verb_version', init.verb_version],
      ['subject', init.subject],
    ] as const) {
      if (!value || !String(value).trim()) throw new ContractError(`账本头字段为空：${name}`)
    }
    const records = [...(init.records ?? [])]
    const seen = new Set<string>()
    const dup = new Set<string>()
    for (const record of records) {
      if (seen.has(record.id)) dup.add(record.id)
      seen.add(record.id)
    }
    if (dup.size > 0) {
      throw new ContractError(`账本 id 冲突（同一主张命中同一节点两次）：${[...dup].sort().join(', ')}`)
    }
    // 确定性排序：同一输入无论器官按什么顺序产出，账本顺序一致
    records.sort((a, b) =>
      a.claim_id === b.claim_id
        ? a.verdict.localeCompare(b.verdict)
        : a.claim_id.localeCompare(b.claim_id),
    )
    this.product = init.product
    this.verb = init.verb
    this.verbVersion = init.verb_version
    this.subject = init.subject
    this.records = Object.freeze(records)
  }

  blocking(): LedgerRecord[] {
    return this.records.filter((r) => BLOCKING_VERDICTS.includes(r.verdict))
  }

  summary(): Record<string, unknown> {
    const verdicts: Record<string, number> = {}
    for (const verdict of VERDICTS) verdicts[verdict] = 0
    for (const record of this.records) verdicts[record.verdict] += 1
    return { blocking: this.blocking().length, total: this.records.length, verdicts }
  }

  exitCode(): number {
    return this.blocking().length > 0 ? EXIT_BLOCKED : EXIT_OK
  }

  toJSON(): Record<string, unknown> {
    return {
      product: this.product,
      verb: this.verb,
      verb_version: this.verbVersion,
      subject: this.subject,
      summary: this.summary(),
      records: this.records.map(recordToJSON),
    }
  }

  lines(): string[] {
    const out = [`${this.product} :: ${this.verb} ${this.verbVersion} :: ${this.subject}`]
    for (const record of this.records) out.push(recordLine(record))
    const s = this.summary() as { total: number; blocking: number; verdicts: Record<string, number> }
    out.push(
      `合计 ${s.total} 条，阻断 ${s.blocking} 条（claim=${s.verdicts[CLAIM]} refuted=${s.verdicts[REFUTED]} inconclusive=${s.verdicts[INCONCLUSIVE]}）`,
    )
    return out
  }
}