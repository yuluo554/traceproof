/**
 * email-evidence · 离线邮件认证取证（SPF / DKIM / DMARC + 三方对账）
 *
 * 一个 traceproof 器官：把「agent 说这封邮件怎样」的主张，逐条对到**同一份 DNS 快照**
 * 上的确定性重算，再挂到痕迹节点（`session_id + turn + tool_call_id`）。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "snapshot": { "schema_version": 1, "psl_version": "...", "queries": [...] },
 *   "query":    { "mail_from": "...", "client_ip": "...", "helo": "..." },
 *   "message_b64": "...",            // 原始报文（base64）；也可用 "message"（UTF-8 文本）
 *   "claims": [
 *     {"claim_id":"c1","check":"spf","asserted":"pass",
 *      "node":{"session_id":"s-1","turn":3,"tool_call_id":"call-7"}}
 *   ]
 * }
 * ```
 *
 * 判定：`computed.result == asserted` → `claim`；不等且**有痕迹节点** → `refuted`；
 * 重算判不了（数据缺口 / undecidable）或**没有节点** → `inconclusive` 并写明缺失项。
 *
 * 器官纪律：不打印、不读文件、不读环境变量、不读时钟、不带参数解析器；
 * 证据只经 `makeRecord()` 入账（内核在入账时脱敏）。报文原文**不进证据**，
 * 避免邮箱地址绕过键名脱敏。
 */

import type { Basis } from '../../core/trace-index.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'

import { Snapshot, SnapshotProblem } from './snapshot.js'
import { spfEvaluate } from './spf.js'
import type { SpfQuery, SpfResult } from './spf.js'
import { parseMessage, verifyMessage } from './dkim.js'
import type { DkimResult, Message } from './dkim.js'
import { dmarcEvaluate } from './dmarc.js'
import type { DmarcResult } from './dmarc.js'
import { reconcileEvaluate } from './reconcile.js'
import type { ReconcileResult } from './reconcile.js'

const CHECKS = ['spf', 'dkim', 'dmarc', 'reconcile'] as const
type CheckName = (typeof CHECKS)[number]

const ALLOWED_CLAIM_FIELDS = new Set([
  'claim_id',
  'check',
  'asserted',
  'asserted_disposition',
  'signature_index',
  'node',
])

/**
 * 每种 check 允许的主张值。
 *
 * 收紧到闭集有两个作用：一是把"主张"限定在引擎真能产出的结论上（拼错不会静默变成
 * `refuted`）；二是保证 `asserted`（会进 evidence）不可能是任意自由文本——证据里的
 * 字符串全部来自闭集或 DNS/报文结构，不存在"用户塞一个密钥进账本"的通路。
 */
const ASSERTED_VALUES: Record<CheckName, readonly string[]> = {
  spf: ['none', 'neutral', 'pass', 'fail', 'softfail', 'temperror', 'permerror', 'undecidable'],
  dkim: ['none', 'pass', 'fail', 'permerror', 'undecidable'],
  dmarc: ['none', 'pass', 'fail', 'undecidable'],
  reconcile: ['none', 'consistent', 'contradiction', 'undecidable'],
}
const ASSERTED_DISPOSITIONS = ['none', 'quarantine', 'reject', 'null']

interface Claim {
  claimId: string
  check: CheckName
  asserted: string
  assertedDisposition: string | null
  signatureIndex: number
  node: unknown
}

interface Computed {
  /** 确定性结论；`input_error` 表示输入不可用（不是引擎结论）。 */
  result: string
  reason: string
  evidence: Record<string, unknown>
  refs: string[]
  /** 判不了：必须降级 `inconclusive` 并写明缺失项。 */
  inconclusive: boolean
  /** 缺失项（人读）。 */
  missing: string[]
}

interface Inputs {
  readonly snapshot: Snapshot | null
  readonly snapshotError: string | null
  readonly query: SpfQuery | null
  readonly queryError: string | null
  readonly message: Message | null
  readonly messageError: string | null
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function readClaim(raw: unknown, position: number): Claim {
  if (!isPlainObject(raw)) throw new ContractError(`claims[${position}] 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_CLAIM_FIELDS.has(key)) {
      throw new ContractError(`claims[${position}] 未知字段：${key}（允许：${[...ALLOWED_CLAIM_FIELDS].join('、')}）`)
    }
  }
  const claimId = raw.claim_id
  if (typeof claimId !== 'string' || !claimId.trim()) {
    throw new ContractError(`claims[${position}] 缺 claim_id`)
  }
  const check = raw.check
  if (typeof check !== 'string' || !(CHECKS as readonly string[]).includes(check)) {
    throw new ContractError(`claims[${position}] 的 check 非法：<${String(check)}>（允许 ${CHECKS.join(' / ')}）`)
  }
  const asserted = raw.asserted
  if (typeof asserted !== 'string' || !asserted.trim()) {
    throw new ContractError(`claims[${position}] 缺 asserted`)
  }
  const assertedDispositionRaw = raw.asserted_disposition
  if (assertedDispositionRaw !== undefined && typeof assertedDispositionRaw !== 'string') {
    throw new ContractError(`claims[${position}] 的 asserted_disposition 必须是字符串`)
  }
  const signatureIndexRaw = raw.signature_index
  if (
    signatureIndexRaw !== undefined &&
    (typeof signatureIndexRaw !== 'number' || !Number.isInteger(signatureIndexRaw) || signatureIndexRaw < 0)
  ) {
    throw new ContractError(`claims[${position}] 的 signature_index 必须是非负整数`)
  }
  return {
    claimId: claimId.trim(),
    check: check as CheckName,
    asserted: asserted.trim().toLowerCase(),
    assertedDisposition:
      assertedDispositionRaw === undefined ? null : assertedDispositionRaw.trim().toLowerCase(),
    signatureIndex: typeof signatureIndexRaw === 'number' ? signatureIndexRaw : 0,
    node: raw.node,
  }
}

function validateAsserted(claim: Claim, position: number): void {
  const allowed = ASSERTED_VALUES[claim.check]
  if (!allowed.includes(claim.asserted)) {
    throw new ContractError(
      `claims[${position}] 的 asserted 非法：<${claim.asserted}>（${claim.check} 允许 ${allowed.join(' / ')}）`,
    )
  }
  if (claim.assertedDisposition !== null && !ASSERTED_DISPOSITIONS.includes(claim.assertedDisposition)) {
    throw new ContractError(
      `claims[${position}] 的 asserted_disposition 非法：<${claim.assertedDisposition}>（允许 ${ASSERTED_DISPOSITIONS.join(' / ')}）`,
    )
  }
  if (claim.assertedDisposition !== null && claim.check !== 'dmarc') {
    throw new ContractError(`claims[${position}]：只有 dmarc 主张可以带 asserted_disposition`)
  }
}

function resolveNode(basis: Basis, raw: unknown, claimId: string): TraceNode | null {
  if (raw === undefined || raw === null) return null
  if (!isPlainObject(raw)) throw new ContractError(`${claimId}：node 必须是对象`)
  const sessionId = raw.session_id
  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    throw new ContractError(`${claimId}：node.session_id 必须是非空字符串`)
  }
  const rawTurn = raw.turn
  let turn: number | null = null
  if (rawTurn !== undefined && rawTurn !== null) {
    const numeric = Number(rawTurn)
    if (!Number.isInteger(numeric)) throw new ContractError(`${claimId}：node.turn 必须是整数`)
    turn = numeric
  }
  const toolCallId = raw.tool_call_id
  if (typeof toolCallId !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  // 唯一取节点入口：取不到就让 NodeMissing 冒到 CLI（内核映射退出码 3）。
  return basis.ref(sessionId.trim(), turn, toolCallId)
}

function parseSnapshot(raw: unknown): { snapshot: Snapshot | null; error: string | null } {
  try {
    return { snapshot: Snapshot.fromObject(raw), error: null }
  } catch (error) {
    if (error instanceof SnapshotProblem) return { snapshot: null, error: error.message }
    throw error
  }
}

function parseQuery(raw: unknown): { query: SpfQuery | null; error: string | null } {
  if (!isPlainObject(raw)) return { query: null, error: 'query 必须是对象' }
  const mailFrom = raw.mail_from
  if (typeof mailFrom !== 'string') return { query: null, error: 'query.mail_from 必须是字符串（空发件人写 ""）' }
  if (mailFrom && !mailFrom.includes('@')) return { query: null, error: 'query.mail_from 必须形如 local@domain' }
  const clientIp = raw.client_ip
  if (typeof clientIp !== 'string' || !clientIp.trim()) {
    return { query: null, error: 'query.client_ip 必须是非空字符串' }
  }
  const helo = raw.helo
  if (helo !== undefined && helo !== null && typeof helo !== 'string') {
    return { query: null, error: 'query.helo 必须是字符串或 null' }
  }
  const trustedRaw = raw.trusted_authserv_ids ?? []
  if (!Array.isArray(trustedRaw) || trustedRaw.some((item) => typeof item !== 'string')) {
    return { query: null, error: 'query.trusted_authserv_ids 必须是字符串列表' }
  }
  return {
    query: {
      mail_from: mailFrom,
      client_ip: clientIp.trim(),
      helo: typeof helo === 'string' ? helo : null,
      trusted_authserv_ids: (trustedRaw as string[]).map((item) => item.trim()),
    },
    error: null,
  }
}

function parseRawMessage(subject: Record<string, unknown>): { message: Message | null; error: string | null } {
  const b64 = subject.message_b64
  if (typeof b64 === 'string') {
    const compact = b64.replace(/\s+/g, '')
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 !== 0) {
      return { message: null, error: 'message_b64 不是合法 base64' }
    }
    try {
      return { message: parseMessage(Buffer.from(compact, 'base64')), error: null }
    } catch (error) {
      return { message: null, error: `报文解析失败：${(error as Error).message}` }
    }
  }
  const text = subject.message
  if (typeof text === 'string') {
    try {
      return { message: parseMessage(Buffer.from(text, 'utf8')), error: null }
    } catch (error) {
      return { message: null, error: `报文解析失败：${(error as Error).message}` }
    }
  }
  return { message: null, error: '没有提供报文（message / message_b64），该判定需要原始报文' }
}

function memoizeValue<T>(fn: () => T): () => T {
  let cached: { value: T } | null = null
  return () => {
    if (cached === null) cached = { value: fn() }
    return cached.value
  }
}

/** 器官主体：逐条 claim 重算 + 对照 + 挂痕迹节点。 */
function evaluate(subject: Record<string, unknown>, basis: Basis): LedgerRecord[] {
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  claims.forEach((claim, position) => {
    validateAsserted(claim, position)
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  })

  const snapshot = parseSnapshot(subject.snapshot)
  const query = parseQuery(subject.query)
  const message = parseRawMessage(subject)
  const inputs: Inputs = {
    snapshot: snapshot.snapshot,
    snapshotError: snapshot.error,
    query: query.query,
    queryError: query.error,
    message: message.message,
    messageError: message.error,
  }

  const runSpf = memoizeValue((): SpfResult | null => {
    if (inputs.snapshot === null || inputs.query === null) return null
    return spfEvaluate(inputs.snapshot, inputs.query)
  })

  const runDkim = memoizeValue((): DkimResult | null => {
    if (inputs.snapshot === null || inputs.message === null) return null
    return verifyMessage(inputs.message, inputs.snapshot)
  })

  const runDmarc = memoizeValue((): DmarcResult | null => {
    if (inputs.snapshot === null || inputs.message === null || inputs.query === null) return null
    return dmarcEvaluate(inputs.snapshot, inputs.message, inputs.query, runSpf(), runDkim())
  })

  const runReconcile = memoizeValue((): ReconcileResult | null => {
    if (inputs.message === null) return null
    return reconcileEvaluate(
      inputs.message,
      runSpf(),
      runDkim(),
      runDmarc(),
      inputs.query?.trusted_authserv_ids ?? [],
    )
  })

  const spfComputed = memoizeValue((): Computed => {
    if (inputs.snapshot === null) return inputProblem(`快照不合法：${inputs.snapshotError}`)
    if (inputs.query === null) return inputProblem(`query 不合法：${inputs.queryError}`)
    const result = runSpf() as SpfResult
    return {
      result: result.result,
      reason: result.reason,
      refs: result.evidence_ref,
      inconclusive: result.result === 'undecidable',
      missing:
        result.data_gap === null ? ['数据不足（见重算理由）'] : [`${result.data_gap[0]}/${result.data_gap[1]}`],
      evidence: {
        domain: result.domain,
        record: result.record,
        mechanism: result.mechanism,
        result: result.result,
        reason: result.reason,
        evidence_ref: result.evidence_ref,
        budget: {
          terms: result.budget.terms.used,
          mx: result.budget.mx.used,
          ptr: result.budget.ptr.used,
          void: result.budget.void.used,
          depth: result.budget.depth.used,
        },
        limit_hits: result.limit_hits,
        warnings: result.warnings,
        gray_areas: result.gray_areas,
        data_gap: result.data_gap,
        include_tree_nodes: countTreeNodes(result.tree),
      },
    }
  })

  const dkimComputed = new Map<number, Computed>()
  const computeDkim = (claim: Claim): Computed => {
    const cached = dkimComputed.get(claim.signatureIndex)
    if (cached !== undefined) return cached
    let value: Computed
    if (inputs.snapshot === null) {
      value = inputProblem(`快照不合法：${inputs.snapshotError}`)
    } else if (inputs.message === null) {
      value = inputProblem(`报文不可用：${inputs.messageError}`)
    } else {
      const result = runDkim() as DkimResult
      const summary = result.signatures.map((signature) => ({
        index: signature.index,
        selector: signature.selector,
        d: signature.domain,
        a: signature.algorithm,
        c: signature.canonicalization,
        result: signature.result,
        bh_matches: signature.bh_matches,
        key_status: signature.key_status,
        key_bits: signature.key_bits,
        failure_at: signature.failure_at,
      }))
      const baseEvidence = {
        signatures: summary,
        message_has_signatures: result.message_has_signatures,
        warnings: result.warnings,
      }
      if (result.signatures.length === 0) {
        value = {
          result: 'none',
          reason: '报文里没有 DKIM-Signature 头字段，本项判 none（不是 fail）',
          evidence: baseEvidence,
          refs: ['RFC6376#6.1'],
          inconclusive: false,
          missing: [],
        }
      } else if (claim.signatureIndex >= result.signatures.length) {
        value = {
          ...inputProblem(
            `signature_index=${claim.signatureIndex} 超出签名条数 ${result.signatures.length}`,
          ),
          evidence: baseEvidence,
          refs: ['RFC6376#6.1'],
        }
      } else {
        const signature = result.signatures[claim.signatureIndex]
        value = {
          result: signature.result,
          reason: signature.reason,
          evidence: {
            ...baseEvidence,
            signature_index: claim.signatureIndex,
            signatures_total: result.signatures.length,
            reason: signature.reason,
            evidence_ref: signature.evidence_ref,
            data_gap: signature.data_gap,
          },
          refs: signature.evidence_ref,
          inconclusive: signature.result === 'undecidable' || signature.data_gap !== null,
          missing:
            signature.data_gap === null
              ? ['数据不足（见重算理由）']
              : [`${signature.data_gap[0]}/${signature.data_gap[1]}`],
        }
      }
    }
    dkimComputed.set(claim.signatureIndex, value)
    return value
  }

  const dmarcComputed = memoizeValue((): Computed => {
    if (inputs.snapshot === null) return inputProblem(`快照不合法：${inputs.snapshotError}`)
    if (inputs.query === null) return inputProblem(`query 不合法：${inputs.queryError}`)
    if (inputs.message === null) return inputProblem(`报文不可用：${inputs.messageError}`)
    const result = runDmarc() as DmarcResult
    const dispositionUndecidable = result.disposition_status === 'undecidable'
    return {
      result: result.result,
      reason: result.reason,
      refs: result.evidence_ref,
      inconclusive: result.result === 'undecidable' || dispositionUndecidable,
      missing:
        result.data_gaps.length > 0
          ? result.data_gaps.map(([qname, qtype]) => `${qname}/${qtype}`)
          : dispositionUndecidable
            ? ['Author Domain 存在性查询（sp= / np= 的选择依赖它）']
            : ['数据不足（见重算理由）'],
      evidence: {
        author_domain: result.author_domain,
        organizational_domain: result.organizational_domain,
        policy_domain: result.policy_domain,
        policy_source: result.policy_source,
        policy_tag: result.policy_tag,
        policy_value: result.policy_value,
        disposition: result.disposition,
        disposition_status: result.disposition_status,
        test_mode: result.test_mode,
        spf_align: result.spf_align,
        dkim_align: result.dkim_align,
        alignments: result.alignments.map((alignment) => ({
          identifier: alignment.identifier,
          source: alignment.source,
          organizational_domain: alignment.organizational_domain,
          relaxed: alignment.relaxed,
          strict: alignment.strict,
        })),
        walk:
          result.walk === null
            ? []
            : result.walk.hops.map((hop) => ({ qname: hop.qname, status: hop.status })),
        psl_version: result.psl_version,
        psl_date: result.psl_date,
        psl_organizational_domain: result.psl_organizational_domain,
        reason: result.reason,
        evidence_ref: result.evidence_ref,
        warnings: result.warnings,
        data_gaps: result.data_gaps,
      },
    }
  })

  const reconcileComputed = memoizeValue((): Computed => {
    if (inputs.message === null) return inputProblem(`报文不可用：${inputs.messageError}`)
    const result = runReconcile() as ReconcileResult
    return {
      result: result.class,
      reason: reconcileReason(result),
      refs: result.evidence_ref,
      inconclusive: result.class === 'undecidable',
      missing:
        result.class === 'undecidable'
          ? ['可信 authserv-id / 可解析的 Authentication-Results / 可比的重算结论']
          : [],
      evidence: {
        class: result.class,
        entries: result.entries,
        authserv_ids: result.authserv_ids,
        trusted_authserv_ids: result.trusted_authserv_ids,
        notes: result.notes,
        evidence_ref: result.evidence_ref,
      },
    }
  })

  const compute = (claim: Claim): Computed => {
    if (claim.check === 'spf') return spfComputed()
    if (claim.check === 'dkim') return computeDkim(claim)
    if (claim.check === 'dmarc') return dmarcComputed()
    return reconcileComputed()
  }

  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    const computed = compute(claim)
    const compared = compare(claim, computed)
    records.push(
      makeRecord({
        claim_id: claim.claimId,
        verdict: decidedVerdict(compared, node),
        message: buildMessage(claim, computed, compared, node),
        node,
        evidence: {
          claimed: claim.asserted,
          claimed_disposition: claim.assertedDisposition,
          check: claim.check,
          ...computed.evidence,
          comparison: compared.kind,
          comparison_detail: compared.detail,
        },
      }),
    )
  }
  return records
}

function inputProblem(reason: string): Computed {
  return { result: 'input_error', reason, evidence: {}, refs: [], inconclusive: true, missing: [reason] }
}

interface Comparison {
  kind: 'match' | 'mismatch' | 'undecidable' | 'input_error'
  detail: string
}

function compare(claim: Claim, computed: Computed): Comparison {
  if (computed.result === 'input_error') {
    return { kind: 'input_error', detail: computed.reason }
  }
  if (computed.inconclusive) {
    return { kind: 'undecidable', detail: `重算判不了（${computed.result}）：${computed.reason}` }
  }
  if (claim.asserted !== computed.result) {
    return { kind: 'mismatch', detail: `主张 <${claim.asserted}> ≠ 重算 <${computed.result}>（${computed.reason}）` }
  }
  if (claim.assertedDisposition !== null && claim.check === 'dmarc') {
    const actual = computed.evidence.disposition === null ? 'null' : String(computed.evidence.disposition)
    if (claim.assertedDisposition !== actual) {
      return { kind: 'mismatch', detail: `主张处置 <${claim.assertedDisposition}> ≠ 重算处置 <${actual}>` }
    }
  }
  return { kind: 'match', detail: `主张与重算一致：${computed.result}` }
}

function decidedVerdict(compared: Comparison, node: TraceNode | null): Verdict {
  if (compared.kind === 'match') return CLAIM
  if (compared.kind === 'mismatch' && node !== null) return REFUTED
  return INCONCLUSIVE
}

function buildMessage(claim: Claim, computed: Computed, compared: Comparison, node: TraceNode | null): string {
  const parts: string[] = []
  if (compared.kind === 'match') {
    parts.push(`主张「${claim.check}=${claim.asserted}」被同一份快照上的重算支持`)
  } else if (compared.kind === 'mismatch') {
    if (node === null) {
      parts.push(`重算与主张不符（${compared.detail}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`)
    } else {
      parts.push(`重算推翻主张：${compared.detail}`)
    }
  } else if (compared.kind === 'undecidable') {
    parts.push(`痕迹不足以判定：${compared.detail}`)
  } else {
    parts.push(`输入不合法，未做判定：${compared.detail}`)
  }
  if (computed.inconclusive && computed.missing.length > 0) {
    parts.push(`缺失项：${computed.missing.join('、')}`)
  }
  if (claim.assertedDisposition !== null) parts.push(`主张处置：${claim.assertedDisposition}`)
  return parts.join('；')
}

function reconcileReason(result: ReconcileResult): string {
  if (result.class === 'consistent') {
    return `${result.entries.length} 条声称与方法重算一致（RFC 8601）`
  }
  if (result.class === 'contradiction') {
    const contradictions = result.entries.filter((entry) => entry.class === 'contradiction')
    return (
      `${contradictions.length} 条声称与重算不一致；每条给 ${contradictions[0]?.explanations.length ?? 0} 条可能解释` +
      `（${result.notes.join('；')}）`
    )
  }
  if (result.class === 'undecidable') {
    return `对账无法判定：${result.notes.join('；') || '头不可解析 / 无可比结论'}`
  }
  return '报文里没有 Authentication-Results 头，本次没有可对账的声称值（none）'
}

function countTreeNodes(node: { children: readonly { children: readonly unknown[] }[] } | null): number {
  if (node === null) return 0
  let total = 1
  for (const child of node.children) {
    total += countTreeNodes(child as { children: readonly { children: readonly unknown[] }[] })
  }
  return total
}

export const emailEvidenceVerb: Verb = register({
  slug: 'email-evidence',
  version: '1.0.0',
  summary: '邮件认证取证：同一份 DNS 快照上重算 SPF/DKIM/DMARC，并逐条核对主张',
  input_fields: ['snapshot', 'query', 'claims'],
  evaluate,
})

export default emailEvidenceVerb