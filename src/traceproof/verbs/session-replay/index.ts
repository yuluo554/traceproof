/**
 * session-replay · 会话 → 回归取证
 *
 * 一个 traceproof 器官：把「这次会话里到底哪一段是 bug 修复、修前修后是什么」的主张，
 * 对到**同一份会话痕迹**上。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "session": {"harness": "claude", "records": [ <jsonl 行解析后的对象> ]},
 *   "repo":    {"files": {"/demo/alpha/src/calc.py": "<基线内容>"}},
 *   "claims": [
 *     {"claim_id":"c1","check":"episode","asserted":"present",
 *      "node":{"session_id":"s-1","turn":1,"tool_call_id":"call-1"}}
 *   ]
 * }
 * ```
 *
 * 主张（`claims[]`）：

 * | check | asserted 闭集 | 说明 |
 * |---|---|---|
 * | `episode` | `present` / `absent` | 是否切出 bug-fix episode；可带 `index` 与 `status` |
 * | `reconstruction` | `ok` / `partial` / `unresolved` / `no_before_image` / `absent` | 某路径的修复 diff 还原状态 |
 * | `failure-signal` | `present` / `absent` | 会话里是否出现失败证据 |
 *
 * **不做的事**：不跑 pytest（没有 RED/GREEN 验证）、不生成落盘测试文件、不读日志文件。
 * 会话记录由输入提供；失败判定只取数值退出码（文本标记不算）。
 *
 * 器官纪律：不打印、不读文件、不读环境变量、不读时钟、不带参数解析器；
 * 证据里**不放原始用户文本与文件内容**（只放词表内的 bug 语义词、计数与摘要）。
 */

import type { Basis } from '../../core/trace-index.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'

import { FormatProblem, normalizeSession } from './readers.js'
import type { Event, Source } from './readers.js'
import { failureEvidence, reconstructAll, splitEpisodes } from './episode.js'
import type { Episode, Reconstruction, SplitResult } from './episode.js'

const CHECKS = ['episode', 'reconstruction', 'failure-signal'] as const
type CheckName = (typeof CHECKS)[number]

const ASSERTED_VALUES: Record<CheckName, readonly string[]> = {
  episode: ['present', 'absent'],
  reconstruction: ['ok', 'partial', 'unresolved', 'no_before_image', 'absent'],
  'failure-signal': ['present', 'absent'],
}
const EPISODE_STATUSES = ['verified_by_run', 'ended_without_pass']
const ALLOWED_CLAIM_FIELDS = new Set(['claim_id', 'check', 'asserted', 'path', 'index', 'status', 'node'])

interface Claim {
  claimId: string
  check: CheckName
  asserted: string
  path: string | null
  index: number
  status: string | null
  node: unknown
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function readClaim(raw: unknown, position: number): Claim {
  if (!isPlainObject(raw)) throw new ContractError(`claims[${position}] 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_CLAIM_FIELDS.has(key)) throw new ContractError(`claims[${position}] 未知字段：${key}`)
  }
  if (typeof raw.claim_id !== 'string' || !raw.claim_id.trim()) throw new ContractError(`claims[${position}] 缺 claim_id`)
  if (typeof raw.check !== 'string' || !(CHECKS as readonly string[]).includes(raw.check)) {
    throw new ContractError(`claims[${position}] 的 check 非法：<${String(raw.check)}>`)
  }
  const check = raw.check as CheckName
  if (typeof raw.asserted !== 'string' || !raw.asserted.trim()) throw new ContractError(`claims[${position}] 缺 asserted`)
  const asserted = raw.asserted.trim().toLowerCase()
  if (!ASSERTED_VALUES[check].includes(asserted)) {
    throw new ContractError(
      `claims[${position}] 的 asserted 非法：<${asserted}>（${check} 允许 ${ASSERTED_VALUES[check].join(' / ')}）`,
    )
  }
  const path = raw.path === undefined || raw.path === null ? null : raw.path
  if (path !== null && (typeof path !== 'string' || !path.trim())) {
    throw new ContractError(`claims[${position}] 的 path 必须是非空字符串`)
  }
  if (check === 'reconstruction' && path === null) {
    throw new ContractError(`claims[${position}]：reconstruction 需要 path`)
  }
  const indexRaw = raw.index
  if (indexRaw !== undefined && (typeof indexRaw !== 'number' || !Number.isInteger(indexRaw) || indexRaw < 0)) {
    throw new ContractError(`claims[${position}] 的 index 必须是非负整数`)
  }
  const statusRaw = raw.status
  if (statusRaw !== undefined && (typeof statusRaw !== 'string' || !EPISODE_STATUSES.includes(statusRaw))) {
    throw new ContractError(`claims[${position}] 的 status 必须是 ${EPISODE_STATUSES.join(' / ')}`)
  }
  if (statusRaw !== undefined && check !== 'episode') {
    throw new ContractError(`claims[${position}]：只有 episode 主张可以带 status`)
  }
  return {
    claimId: raw.claim_id.trim(),
    check,
    asserted,
    path: path === null ? null : (path as string),
    index: typeof indexRaw === 'number' ? indexRaw : 0,
    status: statusRaw === undefined ? null : (statusRaw as string),
    node: raw.node,
  }
}

function resolveNode(basis: Basis, raw: unknown, claimId: string): TraceNode | null {
  if (raw === undefined || raw === null) return null
  if (!isPlainObject(raw)) throw new ContractError(`${claimId}：node 必须是对象`)
  const sessionId = raw.session_id
  if (typeof sessionId !== 'string' || !sessionId.trim()) throw new ContractError(`${claimId}：node.session_id 必须是非空字符串`)
  const turnRaw = raw.turn
  let turn: number | null = null
  if (turnRaw !== undefined && turnRaw !== null) {
    const numeric = Number(turnRaw)
    if (!Number.isInteger(numeric)) throw new ContractError(`${claimId}：node.turn 必须是整数`)
    turn = numeric
  }
  if (typeof raw.tool_call_id !== 'string') throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  return basis.ref(sessionId.trim(), turn, raw.tool_call_id)
}

function readRecords(session: unknown): { harness: Source | null; records: Array<Record<string, unknown>>; error: string | null } {
  if (!isPlainObject(session)) return { harness: null, records: [], error: 'session 必须是对象' }
  const harnessRaw = session.harness
  let harness: Source | null = null
  if (harnessRaw !== undefined && harnessRaw !== null) {
    if (harnessRaw !== 'claude' && harnessRaw !== 'codex') {
      return { harness: null, records: [], error: `session.harness 必须是 claude / codex（收到 <${String(harnessRaw)}>）` }
    }
    harness = harnessRaw
  }
  const recordsRaw = session.records
  if (!Array.isArray(recordsRaw) || recordsRaw.length === 0) {
    return { harness, records: [], error: 'session.records 必须是非空数组' }
  }
  for (const [index, record] of recordsRaw.entries()) {
    if (!isPlainObject(record)) return { harness, records: [], error: `session.records[${index}] 必须是对象` }
  }
  return { harness, records: recordsRaw as Array<Record<string, unknown>>, error: null }
}

function readRepoFiles(raw: unknown): { files: Record<string, string>; error: string | null } {
  if (raw === undefined) return { files: {}, error: null }
  if (!isPlainObject(raw)) return { files: {}, error: 'repo 必须是对象' }
  const filesRaw = raw.files ?? {}
  if (!isPlainObject(filesRaw)) return { files: {}, error: 'repo.files 必须是对象' }
  const files: Record<string, string> = {}
  for (const [path, content] of Object.entries(filesRaw)) {
    if (typeof content !== 'string') return { files: {}, error: `repo.files[${path}] 必须是字符串` }
    files[path] = content
  }
  return { files, error: null }
}

interface Computed {
  result: string
  reason: string
  evidence: Record<string, unknown>
  inconclusive: boolean
  missing: string[]
}

function inputProblem(reason: string): Computed {
  return { result: 'input_error', reason, evidence: {}, inconclusive: true, missing: [reason] }
}

function kindCounts(events: readonly Event[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const event of events) counts[event.kind] = (counts[event.kind] ?? 0) + 1
  return counts
}

function toolsUsed(events: readonly Event[]): string[] {
  return [
    ...new Set(
      events
        .filter((event) => event.kind === 'tool_call')
        .map((event) => event.tool)
        .filter((tool) => tool !== 'unknown'),
    ),
  ].sort()
}

function summarizeEpisode(episode: Episode): Record<string, unknown> {
  return {
    episode_id: episode.episode_id,
    session_id: episode.session_id,
    source: episode.source,
    start_seq: episode.start_seq,
    end_seq: episode.end_seq,
    bug_term: episode.bug_term,
    status: episode.status,
    files: episode.files,
    score: episode.score,
    score_breakdown: episode.score_breakdown,
    failure_evidence: episode.failure_evidence,
    edits: episode.edits,
    test_commands: episode.test_commands,
  }
}

function summarizeReconstruction(item: Reconstruction): Record<string, unknown> {
  return {
    path: item.path,
    status: item.status,
    confidence: item.confidence,
    source: item.source,
    hunks: item.hunks,
    before_chars: item.before === null ? 0 : item.before.length,
    after_chars: item.after === null ? 0 : item.after.length,
    note: item.note,
  }
}

function evaluate(subject: Record<string, unknown>, basis: Basis): LedgerRecord[] {
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) throw new ContractError('claims 必须是非空数组')
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }
  const session = readRecords(subject.session)
  const repo = readRepoFiles(subject.repo)

  let events: Event[] | null = null
  let split: SplitResult | null = null
  let reconstructions: Reconstruction[] = []
  let formatError: string | null = null
  if (session.error !== null) formatError = session.error
  else {
    try {
      events = normalizeSession(session.harness, session.records)
      split = splitEpisodes(events)
      reconstructions = reconstructAll(events, repo.files)
    } catch (error) {
      if (error instanceof FormatProblem) formatError = error.message
      else throw error
    }
  }

  const baseEvidence = (): Record<string, unknown> => ({
    event_count: events?.length ?? 0,
    kind_counts: events === null ? {} : kindCounts(events),
    tools_used: events === null ? [] : toolsUsed(events),
    episodes: split === null ? [] : split.episodes.map(summarizeEpisode),
    filtered: split === null ? [] : split.filtered,
    reconstructions: reconstructions.map(summarizeReconstruction),
  })

  const compute = (claim: Claim): Computed => {
    if (formatError !== null) return inputProblem(`会话不可归一：${formatError}`)
    if (split === null || events === null) return inputProblem('会话不可归一')

    if (claim.check === 'failure-signal') {
      const failures = events.filter((event) => failureEvidence(event) !== null)
      return {
        result: failures.length > 0 ? 'present' : 'absent',
        reason: failures.length > 0 ? `出现 ${failures.length} 条失败证据` : '没有任何失败证据（数值退出码与文本信号都没有命中）',
        inconclusive: false,
        missing: [],
        evidence: { ...baseEvidence(), failure_count: failures.length },
      }
    }

    if (claim.check === 'episode') {
      const found = split.episodes.length > 0
      const result = found ? 'present' : 'absent'
      if (claim.asserted === 'absent') {
        return {
          result,
          reason: found ? `切出 ${split.episodes.length} 个 episode` : '没有可保留的 episode',
          inconclusive: false,
          missing: [],
          evidence: baseEvidence(),
        }
      }
      if (!found) {
        return {
          result: 'absent',
          reason: `没有可保留的 episode（丢弃原因：${split.filtered.map((item) => item.reason).join('、') || '无'}）`,
          inconclusive: false,
          missing: [],
          evidence: baseEvidence(),
        }
      }
      if (claim.index >= split.episodes.length) {
        return {
          result: 'input_error',
          reason: `index=${claim.index} 超出 episode 条数 ${split.episodes.length}`,
          inconclusive: true,
          missing: [`episode[${claim.index}]`],
          evidence: baseEvidence(),
        }
      }
      const episode = split.episodes[claim.index]
      return {
        result: 'present',
        reason: `episode ${episode.episode_id} 状态 ${episode.status}`,
        inconclusive: false,
        missing: [],
        evidence: {
          ...baseEvidence(),
          episode_index: claim.index,
          episode_status: episode.status,
          episode_id: episode.episode_id,
          comptime_note: 'episode 状态由同一测试命令是否转为通过决定',
        },
      }
    }

    const path = claim.path as string
    const matches = reconstructions.filter((item) => item.path === path)
    if (matches.length === 0) {
      return {
        result: 'absent',
        reason: `${path} 没有修复还原记录（会话里没有该路径的写事件）`,
        inconclusive: false,
        missing: [],
        evidence: baseEvidence(),
      }
    }
    const item = matches[matches.length - 1]
    return {
      result: item.status,
      reason: `还原状态 ${item.status}（${item.source}，置信度 ${item.confidence}，${item.hunks} 个 hunk）${item.note ? `：${item.note}` : ''}`,
      inconclusive: false,
      missing: [],
      evidence: { ...baseEvidence(), path, reconstruction: summarizeReconstruction(item) },
    }
  }

  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    const computed = compute(claim)
    let comparison: 'match' | 'mismatch' | 'undecidable' | 'input_error'
    let detail = ''
    if (computed.result === 'input_error') {
      comparison = 'input_error'
      detail = computed.reason
    } else if (computed.inconclusive) {
      comparison = 'undecidable'
      detail = `重算判不了：${computed.reason}`
    } else if (claim.asserted !== computed.result) {
      comparison = 'mismatch'
      detail = `主张 <${claim.asserted}> ≠ 重算 <${computed.result}>（${computed.reason}）`
    } else if (claim.status !== null && computed.evidence.episode_status !== undefined && claim.status !== computed.evidence.episode_status) {
      comparison = 'mismatch'
      detail = `主张状态 <${claim.status}> ≠ 重算状态 <${String(computed.evidence.episode_status)}>`
    } else {
      comparison = 'match'
      detail = `主张与重算一致：${computed.result}${claim.status === null ? '' : ` / ${claim.status}`}`
    }

    const verdict: Verdict =
      comparison === 'match' ? CLAIM : comparison === 'mismatch' && node !== null ? REFUTED : INCONCLUSIVE
    const parts: string[] = []
    if (comparison === 'match') parts.push(`主张「${claim.check}=${claim.asserted}」被会话痕迹支持`)
    else if (comparison === 'mismatch') {
      parts.push(
        node === null
          ? `痕迹与主张不符（${detail}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`
          : `痕迹推翻主张：${detail}`,
      )
    } else if (comparison === 'undecidable') parts.push(`痕迹不足以判定：${detail}`)
    else parts.push(`输入不合法，未做判定：${detail}`)
    if (computed.inconclusive && computed.missing.length > 0) parts.push(`缺失项：${computed.missing.join('、')}`)
    records.push(
      makeRecord({
        claim_id: claim.claimId,
        verdict,
        message: parts.join('；'),
        node,
        evidence: {
          check: claim.check,
          claimed: claim.asserted,
          claimed_status: claim.status,
          path: claim.path,
          computed: computed.result,
          comparison,
          ...computed.evidence,
        },
      }),
    )
  }
  return records
}

export const sessionReplayVerb: Verb = register({
  slug: 'session-replay',
  version: '0.1.1',
  summary: '会话回归取证：切 bug-fix episode、还原修复 diff，并逐条核对主张',
  input_fields: ['session', 'repo', 'claims'],
  evaluate,
})

export default sessionReplayVerb