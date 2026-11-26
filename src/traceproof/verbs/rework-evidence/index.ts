/**
 * rework-evidence · 会话返工取证
 *
 * 一个 traceproof 器官：把「这次会话里哪些文件被反复改回、Read:Edit 比是多少、
 * 新写符号是否与项目已有工具重复」的主张，对到**同一份会话记录**上。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "session": {"harness": "claude", "source_file": "sessions/<id>/session.jsonl",
 *               "records": [ <jsonl 行解析后的对象> ]},
 *   "version_chains": {"89b13e3…": {"versions": [1, 2, 3]}},
 *   "project_files": {"/demo/alpha/src/util.py": "<基线内容>"},
 *   "claims": [
 *     {"claim_id":"c1","check":"rework","asserted":"rework",
 *      "file":"/demo/alpha/src/alpha_a.py","expected_edits":3,"expected_versions":3,
 *      "node":{"session_id":"s-1","turn":3,"tool_call_id":"call-1"}}
 *   ]
 * }
 * ```
 *
 * | check | asserted 闭集 | 说明 |
 * |---|---|---|
 * | `rework` | `rework` / `not_rework` / `insufficient_data` / `absent` | 文件的返工判定；可带 `expected_edits` / `expected_versions` |
 * | `duplicate-candidate` | `present` / `absent` | 新写符号与已有符号的粗匹配候选（披露制，非克隆判决） |
 * | `read-edit-ratio` | `defined` / `undefined` | Read:Edit 比；可带 `expected_ratio` |
 * | `parse-note` | `present` / `absent` | 某个解析注记码是否出现；可带 `count` |
 *
 * 判定：重算结果 == `asserted` → `claim`；不等且**有痕迹节点** → `refuted`；
 * 重算判不了（源格式错误 / 缺 project_files / Codex 符号候选不启用）或**没有节点**
 * → `inconclusive` 并写明缺失项。
 *
 * 器官纪律：不打印、不读文件、不读环境变量、不读时钟、不带参数解析器；
 * 证据只经 `makeRecord()` 入账（内核在入账时脱敏）。证据不放源码正文，
 * 只放路径、符号名、计数与理由。
 */

import type { Basis } from '../../core/trace-index.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'

import { DUP_DISCLOSURE } from './defaults.js'
import {
  detectHarness,
  parseClaudeSession,
  parseCodexSession,
  readSnapshotFileMap,
} from './parse.js'
import type { SessionIR, SnapshotMapping, Source } from './parse.js'
import { analyzeRework } from './rework.js'
import type { ReworkFinding } from './rework.js'
import {
  computeSessionMetrics,
  existingSymbolsFromReads,
  writePayloadsFromRecords,
} from './metrics.js'
import type { DupCandidate, SessionMetrics, Symbol } from './metrics.js'

export const VERSION = '0.2.0'

export const CHECKS = ['rework', 'duplicate-candidate', 'read-edit-ratio', 'parse-note'] as const
export type CheckName = (typeof CHECKS)[number]

export const ASSERTED_VALUES: Readonly<Record<CheckName, readonly string[]>> = Object.freeze({
  rework: ['rework', 'not_rework', 'insufficient_data', 'absent'],
  'duplicate-candidate': ['present', 'absent'],
  'read-edit-ratio': ['defined', 'undefined'],
  'parse-note': ['present', 'absent'],
})

const ALLOWED_CLAIM_FIELDS = new Set([
  'claim_id',
  'check',
  'asserted',
  'file',
  'new_symbol',
  'existing_symbol',
  'code',
  'expected_edits',
  'expected_versions',
  'expected_ratio',
  'count',
  'node',
])

interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: string
  readonly file: string | null
  readonly newSymbol: string | null
  readonly existingSymbol: string | null
  readonly code: string | null
  readonly expectedEdits: number | null
  readonly expectedEditsPresent: boolean
  readonly expectedVersions: number | null
  readonly expectedVersionsPresent: boolean
  readonly expectedRatio: number | null
  readonly expectedRatioPresent: boolean
  readonly count: number | null
  readonly countPresent: boolean
  readonly node: unknown
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function hasOwn(source: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(source, key)
}

function requireString(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !raw.trim()) throw new ContractError(`${label} 必须是非空字符串`)
  return raw.trim()
}

function nonNegativeInteger(raw: unknown, label: string): number {
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 0) {
    throw new ContractError(`${label} 必须是非负整数`)
  }
  return raw
}

function readClaim(raw: unknown, position: number): Claim {
  if (!isPlainObject(raw)) throw new ContractError(`claims[${position}] 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_CLAIM_FIELDS.has(key)) throw new ContractError(`claims[${position}] 未知字段：${key}`)
  }
  const claimId = requireString(raw.claim_id, `claims[${position}] 的 claim_id`)
  if (typeof raw.check !== 'string' || !(CHECKS as readonly string[]).includes(raw.check)) {
    throw new ContractError(`claims[${position}] 的 check 非法：<${String(raw.check)}>`)
  }
  const check = raw.check as CheckName
  if (typeof raw.asserted !== 'string' || !raw.asserted.trim()) {
    throw new ContractError(`claims[${position}] 缺 asserted`)
  }
  const asserted = raw.asserted.trim().toLowerCase()
  if (!ASSERTED_VALUES[check].includes(asserted)) {
    throw new ContractError(
      `claims[${position}] 的 asserted 非法：<${asserted}>（${check} 允许 ${ASSERTED_VALUES[check].join(' / ')}）`,
    )
  }

  const file = hasOwn(raw, 'file') ? requireString(raw.file, `claims[${position}] 的 file`) : null
  const newSymbol = hasOwn(raw, 'new_symbol')
    ? requireString(raw.new_symbol, `claims[${position}] 的 new_symbol`)
    : null
  const existingSymbol = hasOwn(raw, 'existing_symbol')
    ? requireString(raw.existing_symbol, `claims[${position}] 的 existing_symbol`)
    : null
  const code = hasOwn(raw, 'code') ? requireString(raw.code, `claims[${position}] 的 code`) : null

  if (check === 'rework' && file === null) throw new ContractError(`claims[${position}]：rework 需要 file`)
  if (check === 'duplicate-candidate') {
    if (newSymbol === null || existingSymbol === null) {
      throw new ContractError(`claims[${position}]：duplicate-candidate 需要 new_symbol 与 existing_symbol`)
    }
  }
  if (check === 'parse-note' && code === null) throw new ContractError(`claims[${position}]：parse-note 需要 code`)
  const perCheckFields: Record<CheckName, readonly string[]> = {
    rework: ['file', 'expected_edits', 'expected_versions'],
    'duplicate-candidate': ['new_symbol', 'existing_symbol'],
    'read-edit-ratio': ['expected_ratio'],
    'parse-note': ['code', 'count'],
  }
  for (const key of Object.keys(raw)) {
    if (key === 'claim_id' || key === 'check' || key === 'asserted' || key === 'node') continue
    if (!perCheckFields[check].includes(key)) {
      throw new ContractError(`claims[${position}]：${check} 不接受字段 ${key}`)
    }
  }

  const expectedEdits = hasOwn(raw, 'expected_edits')
    ? nonNegativeInteger(raw.expected_edits, `claims[${position}] 的 expected_edits`)
    : null
  let expectedVersions: number | null = null
  if (hasOwn(raw, 'expected_versions')) {
    if (raw.expected_versions !== null) {
      expectedVersions = nonNegativeInteger(
        raw.expected_versions,
        `claims[${position}] 的 expected_versions`,
      )
    }
  }
  let expectedRatio: number | null = null
  if (hasOwn(raw, 'expected_ratio')) {
    if (typeof raw.expected_ratio !== 'number' || !Number.isFinite(raw.expected_ratio) || raw.expected_ratio < 0) {
      throw new ContractError(`claims[${position}] 的 expected_ratio 必须是非负有限数`)
    }
    expectedRatio = raw.expected_ratio
  }
  const count = hasOwn(raw, 'count')
    ? nonNegativeInteger(raw.count, `claims[${position}] 的 count`)
    : null

  return Object.freeze({
    claimId,
    check,
    asserted,
    file,
    newSymbol,
    existingSymbol,
    code,
    expectedEdits,
    expectedEditsPresent: hasOwn(raw, 'expected_edits'),
    expectedVersions,
    expectedVersionsPresent: hasOwn(raw, 'expected_versions'),
    expectedRatio,
    expectedRatioPresent: hasOwn(raw, 'expected_ratio'),
    count,
    countPresent: hasOwn(raw, 'count'),
    node: raw.node,
  })
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
  if (typeof raw.tool_call_id !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  return basis.ref(sessionId.trim(), turn, raw.tool_call_id)
}

// ── 输入读取（纯函数；格式问题按 claim 记 input_error，不静默补值） ──────

interface NormalizedChains {
  readonly chains: ReadonlyMap<string, readonly number[]>
}

function readVersionChains(raw: unknown): NormalizedChains {
  if (raw === undefined || raw === null) return { chains: new Map() }
  if (!isPlainObject(raw)) throw new ContractError('version_chains 必须是对象')
  const chains = new Map<string, readonly number[]>()
  for (const [stem, value] of Object.entries(raw)) {
    if (!stem.trim()) throw new ContractError('version_chains 的键必须是非空字符串')
    if (!isPlainObject(value)) throw new ContractError(`version_chains[${stem}] 必须是对象`)
    const versionsRaw = value.versions
    if (!Array.isArray(versionsRaw)) {
      throw new ContractError(`version_chains[${stem}].versions 必须是数组`)
    }
    const versions = versionsRaw.map((item, index) =>
      nonNegativeInteger(item, `version_chains[${stem}].versions[${index}]`),
    )
    chains.set(stem, Object.freeze([...new Set(versions)].sort((a, b) => a - b)))
  }
  return { chains }
}

function readProjectFiles(raw: unknown): Record<string, string> | null {
  if (raw === undefined || raw === null) return null
  if (!isPlainObject(raw)) throw new ContractError('project_files 必须是对象')
  const files: Record<string, string> = {}
  for (const [path, content] of Object.entries(raw)) {
    if (!path.trim()) throw new ContractError('project_files 的键必须是非空路径')
    if (typeof content !== 'string') throw new ContractError(`project_files[${path}] 必须是字符串`)
    files[path] = content
  }
  return files
}

interface SessionInput {
  readonly harness: Source
  readonly records: readonly Record<string, unknown>[]
  readonly sourceFile: string
}

function readSession(raw: unknown): { input: SessionInput; error: null } | { input: null; error: string } {
  if (!isPlainObject(raw)) return { input: null, error: 'session 必须是对象' }
  const recordsRaw = raw.records
  if (!Array.isArray(recordsRaw) || recordsRaw.length === 0) {
    return { input: null, error: 'session.records 必须是非空数组' }
  }
  const records: Record<string, unknown>[] = []
  for (const [index, record] of recordsRaw.entries()) {
    if (!isPlainObject(record)) return { input: null, error: `session.records[${index}] 必须是对象` }
    records.push(record)
  }
  let harness: Source | null = null
  if (hasOwn(raw, 'harness') && raw.harness !== null && raw.harness !== undefined) {
    if (raw.harness !== 'claude' && raw.harness !== 'codex') {
      return { input: null, error: `session.harness 必须是 claude / codex（收到 <${String(raw.harness)}>）` }
    }
    harness = raw.harness
  } else {
    harness = detectHarness(records)
    if (harness === null) return { input: null, error: '无法判别会话形态（记录里既无 message 也无 payload）' }
  }
  let sourceFile = ''
  if (hasOwn(raw, 'source_file') && raw.source_file !== null && raw.source_file !== undefined) {
    if (typeof raw.source_file !== 'string' || !raw.source_file.trim()) {
      return { input: null, error: 'session.source_file 必须是非空字符串' }
    }
    sourceFile = raw.source_file.trim()
  }
  return { input: { harness, records, sourceFile }, error: null }
}

// ── 重算 ──────────────────────────────────────────────────────────────────

interface Computed {
  readonly result: string
  readonly reason: string
  readonly evidence: Record<string, unknown>
  readonly undecidable: boolean
  readonly missing: readonly string[]
}

function inputProblem(reason: string): Computed {
  return { result: 'input_error', reason, evidence: {}, undecidable: true, missing: [reason] }
}

function summarizeFinding(finding: ReworkFinding): Record<string, unknown> {
  return {
    file_path: finding.file_path,
    verdict: finding.verdict,
    version_count: finding.version_count,
    edit_count: finding.edit_count,
    first_edit_seq: finding.first_edit_seq,
    last_edit_seq: finding.last_edit_seq,
    span_seconds: finding.span_seconds,
    reasons: [...finding.reasons],
    anchors: [...finding.evidence],
  }
}

function summarizeCandidate(candidate: DupCandidate): Record<string, unknown> {
  return {
    new_symbol: candidate.new_symbol,
    existing_symbol: candidate.existing_symbol,
    match_reason: candidate.match_reason,
    similarity: candidate.similarity,
  }
}

function summarizeMetrics(metrics: SessionMetrics): Record<string, unknown> {
  return {
    session_id: metrics.session_id,
    reads: metrics.reads,
    writes: metrics.writes,
    writes_by_kind: metrics.writes_by_kind.map(([kind, count]) => ({ kind, count })),
    read_edit_ratio: metrics.read_edit_ratio,
  }
}

export function evaluate(subject: Record<string, unknown>, basis: Basis): LedgerRecord[] {
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) throw new ContractError('claims 必须是非空数组')
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }

  const sessionState = readSession(subject.session)
  const { chains } = readVersionChains(subject.version_chains)
  const projectFiles = readProjectFiles(subject.project_files)

  let ir: SessionIR | null = null
  let snapshotMap: Record<string, SnapshotMapping> = {}
  let findings: ReworkFinding[] = []
  let metrics: SessionMetrics | null = null
  let dupCandidates: DupCandidate[] | null = null
  let formatError: string | null = sessionState.error
  const reportNotes: string[] = []

  if (sessionState.input !== null) {
    const { harness, records, sourceFile } = sessionState.input
    ir =
      harness === 'claude'
        ? parseClaudeSession(records, sourceFile)
        : parseCodexSession(records, sourceFile)
    const sessionLabel = sourceFile || ir.meta.session_id || '<session>'
    ir = Object.freeze({
      ...ir,
      meta: Object.freeze({ ...ir.meta, source_file: sessionLabel }),
    })
    const sessionId = ir.meta.session_id
    snapshotMap = readSnapshotFileMap(records)
    findings = analyzeRework(ir, chains, snapshotMap)
    const readTargets = ir.tool_events
      .filter((event) => event.kind === 'read' && event.file_path !== null)
      .map((event) => event.file_path as string)
    const evidenceLabel = `${sessionLabel}:${ir.meta.session_id}`

    let writePayloads: Array<readonly [string, string]> = []
    let existingSymbols: Symbol[] = []
    if (harness === 'claude') {
      for (const payload of writePayloadsFromRecords(records)) {
        if (payload.language === null) {
          reportNotes.push(
            `会话 ${sessionId}：Write 载荷 ${payload.path || '<unknown>'} 非首期支持语言（python），符号提取显式跳过（不猜测）`,
          )
          continue
        }
        writePayloads.push([payload.language, payload.content] as const)
      }
      if (projectFiles !== null) {
        existingSymbols = existingSymbolsFromReads(readTargets, projectFiles, (target) => {
          reportNotes.push(
            `会话 ${sessionId}：Read 目标 ${target} 不在 project_files 中，已有符号提取跳过（显式披露）`,
          )
        })
      }
    } else if (ir.tool_events.some((event) => event.kind === 'edit' || event.kind === 'write')) {
      reportNotes.push(
        `会话 ${sessionId}（codex 源）：符号候选未启用（apply_patch 载荷无独立 file_path+content 双字段形态，不编造）`,
      )
    }

    metrics = computeSessionMetrics(
      sessionId,
      ir.tool_events,
      writePayloads,
      existingSymbols,
      evidenceLabel,
      evidenceLabel,
    )
    if (harness === 'claude' && projectFiles !== null) {
      dupCandidates = [...metrics.dup_candidates]
    }
  }

  const baseEvidence = (): Record<string, unknown> => ({
    session:
      ir === null
        ? null
        : {
            source: ir.meta.source,
            session_id: ir.meta.session_id,
            source_file: ir.meta.source_file,
            tool_events: ir.tool_events.length,
            token_events: ir.token_events.length,
            notes: ir.notes.length,
          },
    findings: findings.map(summarizeFinding),
    metrics: metrics === null ? null : summarizeMetrics(metrics),
    dup_candidates: dupCandidates === null ? null : dupCandidates.map(summarizeCandidate),
    report_notes: [...reportNotes],
  })

  const compute = (claim: Claim): Computed => {
    if (formatError !== null) return inputProblem(`会话不可归一：${formatError}`)

    if (claim.check === 'rework') {
      const file = claim.file as string
      const finding = findings.find((item) => item.file_path === file)
      if (finding === undefined) {
        return {
          result: 'absent',
          reason: `该文件在会话里没有写事件（edit/write）：${file}`,
          evidence: { file },
          undecidable: false,
          missing: [],
        }
      }
      const span = finding.span_seconds === null ? '时间戳缺失' : `${finding.span_seconds}s`
      return {
        result: finding.verdict,
        reason: `判定 ${finding.verdict}（版本 ${finding.version_count === null ? '缺失' : finding.version_count} / 编辑 ${finding.edit_count} / 跨度 ${span} / 理由 ${finding.reasons.join(',') || '无'}）`,
        evidence: { file, finding: summarizeFinding(finding) },
        undecidable: false,
        missing: [],
      }
    }

    if (claim.check === 'duplicate-candidate') {
      if (ir === null) return inputProblem('会话不可归一')
      if (ir.meta.source === 'codex') {
        return inputProblem('codex 源符号候选未启用（apply_patch 载荷无独立 file_path+content 双字段形态，不编造）')
      }
      if (projectFiles === null) {
        return inputProblem('缺少 project_files，无法提取已有符号（不猜测）')
      }
      const candidates = dupCandidates ?? []
      const found = candidates.find(
        (candidate) =>
          candidate.new_symbol === claim.newSymbol && candidate.existing_symbol === claim.existingSymbol,
      )
      return {
        result: found === undefined ? 'absent' : 'present',
        reason:
          found === undefined
            ? `新写符号 ${claim.newSymbol} 与已有符号 ${claim.existingSymbol} 没有粗匹配候选`
            : `粗匹配候选命中：${found.match_reason}${found.similarity === null ? '' : `（ratio ${found.similarity.toFixed(6)}）`}`,
        evidence: {
          new_symbol: claim.newSymbol,
          existing_symbol: claim.existingSymbol,
          candidate_count: candidates.length,
          matched: found === undefined ? null : summarizeCandidate(found),
          disclosure: DUP_DISCLOSURE,
        },
        undecidable: false,
        missing: [],
      }
    }

    if (claim.check === 'read-edit-ratio') {
      if (metrics === null) return inputProblem('会话不可归一')
      const ratio = metrics.read_edit_ratio
      return {
        result: ratio === null ? 'undefined' : 'defined',
        reason:
          ratio === null
            ? `写事件为 0，Read:Edit 比未定义（不填 0 不填 inf；reads=${metrics.reads}）`
            : `Read:Edit = ${metrics.reads}/${metrics.writes} = ${ratio}`,
        evidence: {
          reads: metrics.reads,
          writes: metrics.writes,
          read_edit_ratio: ratio,
          writes_by_kind: metrics.writes_by_kind.map(([kind, count]) => ({ kind, count })),
        },
        undecidable: false,
        missing: [],
      }
    }

    // parse-note
    if (ir === null) return inputProblem('会话不可归一')
    const code = claim.code as string
    const matching = ir.notes.filter((note) => note.code === code)
    const total = matching.reduce((sum, note) => sum + note.count, 0)
    return {
      result: total > 0 ? 'present' : 'absent',
      reason: total > 0 ? `解析注记 ${code} 出现 ${total} 次` : `解析注记 ${code} 没有出现`,
      evidence: {
        code,
        note_count: total,
        notes: ir.notes.map((note) => ({ code: note.code, count: note.count })),
      },
      undecidable: false,
      missing: [],
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
    } else if (computed.undecidable) {
      comparison = 'undecidable'
      detail = `重算判不了：${computed.reason}`
    } else if (claim.asserted !== computed.result) {
      comparison = 'mismatch'
      detail = `主张 <${claim.asserted}> ≠ 重算 <${computed.result}>（${computed.reason}）`
    } else if (
      claim.check === 'rework' &&
      (() => {
        const finding = computed.evidence.finding as Record<string, unknown> | undefined
        if (!claim.expectedEditsPresent && !claim.expectedVersionsPresent) return false
        if (finding === undefined) return true
        if (claim.expectedEditsPresent && claim.expectedEdits !== finding.edit_count) return true
        return claim.expectedVersionsPresent && claim.expectedVersions !== finding.version_count
      })()
    ) {
      comparison = 'mismatch'
      detail = `主张的编辑/版本计数与重算不符（期望 edits=${String(claim.expectedEdits)} / versions=${String(claim.expectedVersions)}；重算 ${JSON.stringify(computed.evidence.finding)}）`
    } else if (
      claim.check === 'read-edit-ratio' &&
      claim.expectedRatioPresent &&
      (typeof computed.evidence.read_edit_ratio !== 'number' ||
        Math.abs(computed.evidence.read_edit_ratio - (claim.expectedRatio as number)) > 1e-12)
    ) {
      comparison = 'mismatch'
      detail = `主张的 ratio ${String(claim.expectedRatio)} ≠ 重算 ${String(computed.evidence.read_edit_ratio)}`
    } else if (
      claim.check === 'parse-note' &&
      claim.countPresent &&
      claim.count !== computed.evidence.note_count
    ) {
      comparison = 'mismatch'
      detail = `主张的注记次数 ${String(claim.count)} ≠ 重算 ${String(computed.evidence.note_count)}`
    } else {
      comparison = 'match'
      detail = `主张与重算一致：${computed.result}`
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
    if (computed.missing.length > 0) parts.push(`缺失项：${computed.missing.join('、')}`)

    records.push(
      makeRecord({
        claim_id: claim.claimId,
        verdict,
        message: parts.join('；'),
        node,
        evidence: {
          check: claim.check,
          claimed: claim.asserted,
          ...(claim.file === null ? {} : { file: claim.file }),
          ...(claim.newSymbol === null ? {} : { new_symbol: claim.newSymbol }),
          ...(claim.existingSymbol === null ? {} : { existing_symbol: claim.existingSymbol }),
          ...(claim.code === null ? {} : { code: claim.code }),
          ...(claim.expectedEditsPresent ? { expected_edits: claim.expectedEdits } : {}),
          ...(claim.expectedVersionsPresent ? { expected_versions: claim.expectedVersions } : {}),
          ...(claim.expectedRatioPresent ? { expected_ratio: claim.expectedRatio } : {}),
          ...(claim.countPresent ? { expected_count: claim.count } : {}),
          computed: computed.result,
          comparison,
          ...computed.evidence,
          ...baseEvidence(),
        },
      }),
    )
  }
  return records
}

export const reworkEvidenceVerb: Verb = register({
  slug: 'rework-evidence',
  version: VERSION,
  summary: '会话返工取证：版本链/编辑计数、Read:Edit 比与重复造轮子候选，并逐条核对主张',
  input_fields: ['session', 'claims'],
  evaluate,
})

export default reworkEvidenceVerb