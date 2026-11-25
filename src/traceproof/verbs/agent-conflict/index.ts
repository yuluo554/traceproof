/**
 * agent-conflict · 多 agent 并行开发的冲突取证
 *
 * 一个 traceproof 器官：把「这几个 agent 会不会撞车」的主张，对到**同一份判据**上——
 * 谁在哪个工作区改了哪个文件的哪些行，加上痕迹里已经跑过的 `git merge-tree` 结果。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "repo":     {"files": {"src/alpha.py": "<基线内容>"}},
 *   "sessions": [{"id":"sess-a","workspace":"ws-1","derived_from":null,
 *                 "writes":[{"path":"src/alpha.py","kind":"edit","ranges":[[2,2]]}]}],
 *   "merge_trees": [{"a":"ws-1","b":"ws-2","status":"conflict","paths":["src/alpha.py"]}],
 *   "claims": [{"claim_id":"c1","check":"conflict","path":"src/alpha.py","asserted":"conflict",
 *               "node":{"session_id":"s-1","turn":1,"tool_call_id":"call-1"}}]
 * }
 * ```
 *
 * 三级判据（移植自 `detect.py`）：
 * 1. **文件级**：同一 `path` 被两个**不同工作区**的会话改过；同一 parent 派生的 subagent
 *    （`derived_from` 相同且非空）**整对不产出**；
 * 2. **区块级**：痕迹里的 `merge-tree` 对该工作区对报 `conflict` 且冲突路径含本 path；
 *    **没有这份证据就判 `undecidable`，不猜**；
 * 3. **符号级**：Python 符号区间（`def`/`async def`/`class`）→ 同一符号命中 / 相邻符号命中
 *    （间距 ≤ `adjacent_tolerance`）；非 Python 或取不到基线 → 只给文件级并标 `approximate`。
 *
 * 器官纪律：不打印、不读文件、不读环境变量、不读时钟、不带参数解析器；
 * 不跑 git 子进程（试合并结果由痕迹提供），证据只经 `makeRecord()` 入账。
 */

import type { Basis } from '../../core/trace-index.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'

import defaults from './data/agent-conflict-defaults.json' with { type: 'json' }
import { innermostPair, pairSymbolHit, rangeGap, symbolSpans } from './symbols.js'
import type { Span, SymbolSpan } from './symbols.js'

const LEVEL_FILE = 'file'
const LEVEL_BLOCK = 'block'
const LEVEL_SYMBOL = 'symbol'
const LEVEL_ORDER = ['file', 'block', 'symbol'] as const
const LEVEL_RANK = new Map<string, number>(LEVEL_ORDER.map((level, index) => [level, index]))

const CHECKS = ['conflict', 'block', 'symbol-relation'] as const
type CheckName = (typeof CHECKS)[number]

const ASSERTED_VALUES: Record<CheckName, readonly string[]> = {
  conflict: ['none', 'conflict'],
  block: ['none', 'conflict', 'undecidable'],
  'symbol-relation': ['same', 'adjacent', 'different', 'cross_file', 'unavailable', 'undecidable'],
}

const ALLOWED_CLAIM_FIELDS = new Set([
  'claim_id',
  'check',
  'path',
  'asserted',
  'workspace_a',
  'workspace_b',
  'session_a',
  'session_b',
  'node',
])

export interface Write {
  readonly path: string
  readonly kind: string
  readonly ranges: readonly Span[]
}

export interface Session {
  readonly id: string
  readonly workspace: string
  readonly derived_from: string | null
  readonly writes: readonly Write[]
}

export interface MergeTree {
  readonly a: string
  readonly b: string
  readonly status: 'conflict' | 'ok' | 'error'
  readonly paths: readonly string[]
}

export interface Conflict {
  readonly levels: string[]
  readonly level: string
  readonly workspace_a: string
  readonly workspace_b: string
  readonly path: string
  readonly symbols: string[]
  readonly line_ranges: Span[]
  readonly severity: number
  readonly severity_key: string
  readonly degraded: boolean
  readonly degrade_reasons: string[]
  readonly approximate: boolean
  readonly sessions: string[]
  readonly session_ids: string[]
  readonly sessions_a: string[]
  readonly sessions_b: string[]
}

interface Settings {
  readonly adjacent_tolerance: number
  readonly min_overlap_lines: number
  readonly severity: Record<string, number>
}

const SETTINGS: Settings = {
  adjacent_tolerance: defaults.symbol.adjacent_tolerance,
  min_overlap_lines: defaults.symbol.min_overlap_lines,
  severity: defaults.severity,
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function readSpan(value: unknown, where: string): Span {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new ContractError(`${where}：ranges 的每一项必须是 [start, end]`)
  }
  const [start, end] = value
  if (
    typeof start !== 'number' ||
    typeof end !== 'number' ||
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 1 ||
    end < start
  ) {
    throw new ContractError(`${where}：ranges 必须是 1-based 闭区间`)
  }
  return [start, end]
}

function readSessions(raw: unknown): Session[] {
  if (!Array.isArray(raw)) throw new ContractError('sessions 必须是数组')
  return raw.map((item, position) => {
    const where = `sessions[${position}]`
    if (!isPlainObject(item)) throw new ContractError(`${where} 必须是对象`)
    if (typeof item.id !== 'string' || !item.id.trim()) throw new ContractError(`${where} 缺 id`)
    if (typeof item.workspace !== 'string' || !item.workspace.trim()) {
      throw new ContractError(`${where} 缺 workspace`)
    }
    const derived = item.derived_from
    if (derived !== undefined && derived !== null && typeof derived !== 'string') {
      throw new ContractError(`${where}：derived_from 必须是字符串或 null`)
    }
    const writesRaw = item.writes ?? []
    if (!Array.isArray(writesRaw)) throw new ContractError(`${where}：writes 必须是数组`)
    const writes: Write[] = writesRaw.map((write, index) => {
      const spot = `${where}.writes[${index}]`
      if (!isPlainObject(write)) throw new ContractError(`${spot} 必须是对象`)
      if (typeof write.path !== 'string' || !write.path.trim()) throw new ContractError(`${spot} 缺 path`)
      if (typeof write.kind !== 'string' || !write.kind.trim()) throw new ContractError(`${spot} 缺 kind`)
      const rangesRaw = write.ranges ?? []
      if (!Array.isArray(rangesRaw)) throw new ContractError(`${spot}：ranges 必须是数组`)
      return {
        path: write.path,
        kind: write.kind,
        ranges: rangesRaw.map((range) => readSpan(range, spot)),
      }
    })
    return {
      id: item.id.trim(),
      workspace: item.workspace.trim(),
      derived_from: typeof derived === 'string' ? derived.trim() : null,
      writes,
    }
  })
}

function readMergeTrees(raw: unknown): MergeTree[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) throw new ContractError('merge_trees 必须是数组')
  return raw.map((item, position) => {
    const where = `merge_trees[${position}]`
    if (!isPlainObject(item)) throw new ContractError(`${where} 必须是对象`)
    for (const field of ['a', 'b'] as const) {
      if (typeof item[field] !== 'string' || !item[field].trim()) {
        throw new ContractError(`${where} 缺 ${field}`)
      }
    }
    const status = item.status
    if (status !== 'conflict' && status !== 'ok' && status !== 'error') {
      throw new ContractError(`${where}：status 必须是 conflict / ok / error`)
    }
    const paths = item.paths ?? []
    if (!Array.isArray(paths) || paths.some((path) => typeof path !== 'string')) {
      throw new ContractError(`${where}：paths 必须是字符串数组`)
    }
    return { a: item.a as string, b: item.b as string, status, paths: paths as string[] }
  })
}

function readRepo(raw: unknown): Record<string, string> {
  if (!isPlainObject(raw)) throw new ContractError('repo 必须是对象')
  const files = raw.files ?? {}
  if (!isPlainObject(files)) throw new ContractError('repo.files 必须是对象')
  const out: Record<string, string> = {}
  for (const [path, content] of Object.entries(files)) {
    if (typeof content !== 'string') throw new ContractError(`repo.files[${path}] 必须是字符串`)
    out[path] = content
  }
  return out
}

interface Claim {
  claimId: string
  check: CheckName
  path: string
  asserted: string
  workspaceA: string | null
  workspaceB: string | null
  sessionA: string | null
  sessionB: string | null
  node: unknown
}

function readClaim(raw: unknown, position: number): Claim {
  if (!isPlainObject(raw)) throw new ContractError(`claims[${position}] 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_CLAIM_FIELDS.has(key)) {
      throw new ContractError(`claims[${position}] 未知字段：${key}`)
    }
  }
  if (typeof raw.claim_id !== 'string' || !raw.claim_id.trim()) {
    throw new ContractError(`claims[${position}] 缺 claim_id`)
  }
  if (typeof raw.check !== 'string' || !(CHECKS as readonly string[]).includes(raw.check)) {
    throw new ContractError(`claims[${position}] 的 check 非法：<${String(raw.check)}>`)
  }
  if (typeof raw.path !== 'string' || !raw.path.trim()) {
    throw new ContractError(`claims[${position}] 缺 path`)
  }
  if (typeof raw.asserted !== 'string' || !raw.asserted.trim()) {
    throw new ContractError(`claims[${position}] 缺 asserted`)
  }
  const check = raw.check as CheckName
  const asserted = raw.asserted.trim().toLowerCase()
  if (!ASSERTED_VALUES[check].includes(asserted)) {
    throw new ContractError(
      `claims[${position}] 的 asserted 非法：<${asserted}>（${check} 允许 ${ASSERTED_VALUES[check].join(' / ')}）`,
    )
  }
  const optional = (name: string): string | null => {
    const value = raw[name]
    if (value === undefined || value === null) return null
    if (typeof value !== 'string' || !value.trim()) {
      throw new ContractError(`claims[${position}] 的 ${name} 必须是非空字符串`)
    }
    return value.trim()
  }
  return {
    claimId: raw.claim_id.trim(),
    check,
    path: raw.path.trim(),
    asserted,
    workspaceA: optional('workspace_a'),
    workspaceB: optional('workspace_b'),
    sessionA: optional('session_a'),
    sessionB: optional('session_b'),
    node: raw.node,
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
  if (typeof raw.tool_call_id !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  return basis.ref(sessionId.trim(), turn, raw.tool_call_id)
}

function severityKey(
  symbolKind: 'same' | 'adjacent' | '',
  symbolsResolved: boolean,
): string {
  if (symbolKind === 'same') return 'same_symbol'
  if (symbolKind === 'adjacent') return 'adjacent_lines'
  return symbolsResolved ? 'same_file_diff_symbol' : 'file_only'
}

/** 冲突检测主体（导出给测试逐条对账）。 */
export function detectConflicts(
  repoFiles: Record<string, string>,
  sessions: readonly Session[],
  mergeTrees: readonly MergeTree[],
  settings: Settings = SETTINGS,
): Conflict[] {
  const ordered = [...sessions].sort((a, b) => (a.workspace === b.workspace ? a.id.localeCompare(b.id) : a.workspace.localeCompare(b.workspace)))
  const byWorkspace = new Map<string, Session[]>()
  for (const session of ordered) {
    const bucket = byWorkspace.get(session.workspace)
    if (bucket === undefined) byWorkspace.set(session.workspace, [session])
    else bucket.push(session)
  }
  const workspaces = [...byWorkspace.keys()].sort()
  const conflicts: Conflict[] = []

  for (let i = 0; i < workspaces.length; i += 1) {
    for (let j = i + 1; j < workspaces.length; j += 1) {
      const workspaceA = workspaces[i]
      const workspaceB = workspaces[j]
      const merge = findMerge(mergeTrees, workspaceA, workspaceB)
      for (const sessionA of byWorkspace.get(workspaceA) as Session[]) {
        for (const sessionB of byWorkspace.get(workspaceB) as Session[]) {
          if (
            sessionA.derived_from !== null &&
            sessionA.derived_from === sessionB.derived_from
          ) {
            continue
          }
          const paths = [...new Set(sessionA.writes.map((write) => write.path))].sort()
          for (const path of paths) {
            const writesA = sessionA.writes.filter((write) => write.path === path)
            const writesB = sessionB.writes.filter((write) => write.path === path)
            if (writesA.length === 0 || writesB.length === 0) continue
            const rangesA = writesA.flatMap((write) => write.ranges)
            const rangesB = writesB.flatMap((write) => write.ranges)
            if (rangesA.length === 0 || rangesB.length === 0) continue

            let symbolKind: 'same' | 'adjacent' | '' = ''
            let symbols: string[] = []
            let symbolsResolved = false
            const content = repoFiles[path]
            const python = path.endsWith('.py')
            const spans: SymbolSpan[] = python && typeof content === 'string' ? symbolSpans(content) : []
            const approximate = !python || content === undefined || spans.length === 0
            if (spans.length > 0) {
              for (const left of rangesA) {
                for (const right of rangesB) {
                  const hit = pairSymbolHit(spans, left, right, settings.adjacent_tolerance)
                  if (hit.kind === 'same') {
                    symbolKind = 'same'
                    symbols = hit.symbols
                  } else if (hit.kind === 'adjacent' && symbolKind !== 'same') {
                    symbolKind = 'adjacent'
                    symbols = hit.symbols
                  }
                  const [innerLeft, innerRight] = innermostPair(spans, left, right)
                  if (innerLeft !== null && innerRight !== null && innerLeft !== innerRight) {
                    symbolsResolved = true
                  }
                }
              }
            }

            const levels: string[] = [LEVEL_FILE]
            const degradeReasons: string[] = []
            if (merge !== undefined && merge.status === 'conflict' && merge.paths.includes(path)) {
              levels.push(LEVEL_BLOCK)
            }
            if (merge === undefined) degradeReasons.push('痕迹里没有这对工作区的 merge-tree 结果（区块级不可判定）')
            else if (merge.status === 'error') degradeReasons.push('痕迹里的 merge-tree 是环境错误（区块级不可判定）')
            if (symbolKind !== '') levels.push(LEVEL_SYMBOL)

            const severity = settings.severity[severityKey(symbolKind, symbolsResolved)] ?? 0
            conflicts.push({
              levels: [...levels].sort((a, b) => (LEVEL_RANK.get(a) ?? 0) - (LEVEL_RANK.get(b) ?? 0)),
              level: levels.reduce((best, level) => ((LEVEL_RANK.get(level) ?? 0) > (LEVEL_RANK.get(best) ?? 0) ? level : best), LEVEL_FILE),
              workspace_a: workspaceA,
              workspace_b: workspaceB,
              path,
              symbols,
              line_ranges: [rangesA[0], rangesB[0]],
              severity,
              severity_key: severityKey(symbolKind, symbolsResolved),
              degraded: merge === undefined || merge.status === 'error',
              degrade_reasons: degradeReasons,
              approximate,
              sessions: [sessionA.id, sessionB.id],
              session_ids: [sessionA.id, sessionB.id],
              sessions_a: [sessionA.id],
              sessions_b: [sessionB.id],
            })
          }
        }
      }
    }
  }

  conflicts.sort((a, b) =>
    a.path === b.path
      ? (LEVEL_RANK.get(b.level) ?? 0) - (LEVEL_RANK.get(a.level) ?? 0) || b.severity - a.severity
      : a.path.localeCompare(b.path),
  )
  return conflicts
}

function findMerge(
  mergeTrees: readonly MergeTree[],
  workspaceA: string,
  workspaceB: string,
): MergeTree | undefined {
  return mergeTrees.find(
    (entry) =>
      (entry.a === workspaceA && entry.b === workspaceB) ||
      (entry.a === workspaceB && entry.b === workspaceA),
  )
}

function findWrites(session: Session, path: string): Write[] {
  return session.writes.filter((write) => write.path === path)
}

function symbolRelation(
  repoFiles: Record<string, string>,
  sessionA: Session,
  sessionB: Session,
  path: string,
): { relation: string; symbols: string[]; missing: string[] } {
  const writesA = findWrites(sessionA, path)
  const writesB = findWrites(sessionB, path)
  if (writesA.length === 0 || writesB.length === 0) {
    return {
      relation: 'cross_file',
      symbols: [],
      missing: [`${path} 不是两侧共同改过的文件（${writesA.length} / ${writesB.length} 侧有写记录）`],
    }
  }
  const content = repoFiles[path]
  if (!path.endsWith('.py') || content === undefined) {
    return {
      relation: 'unavailable',
      symbols: [],
      missing: [path.endsWith('.py') ? `repo.files 里没有 ${path}（取不到符号基线）` : `${path} 不是 Python 文件（无符号能力）`],
    }
  }
  const spans = symbolSpans(content)
  const rangesA = writesA.flatMap((write) => write.ranges)
  const rangesB = writesB.flatMap((write) => write.ranges)
  let best: 'same' | 'adjacent' | '' = ''
  let symbols: string[] = []
  let different = false
  for (const left of rangesA) {
    for (const right of rangesB) {
      const hit = pairSymbolHit(spans, left, right, SETTINGS.adjacent_tolerance)
      if (hit.kind === 'same') {
        best = 'same'
        symbols = hit.symbols
      } else if (hit.kind === 'adjacent' && best !== 'same') {
        best = 'adjacent'
        symbols = hit.symbols
      }
      const [innerLeft, innerRight] = innermostPair(spans, left, right)
      if (innerLeft !== null && innerRight !== null && innerLeft !== innerRight) different = true
    }
  }
  if (best === 'same') return { relation: 'same', symbols, missing: [] }
  if (best === 'adjacent') return { relation: 'adjacent', symbols, missing: [] }
  if (different) return { relation: 'different', symbols: [], missing: [] }
  return { relation: 'unavailable', symbols: [], missing: ['两侧区间至少有一侧落不到任何符号里'] }
}

interface Computed {
  result: string
  reason: string
  evidence: Record<string, unknown>
  inconclusive: boolean
  missing: string[]
}

function evaluate(subject: Record<string, unknown>, basis: Basis): LedgerRecord[] {
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }
  const repoFiles = readRepo(subject.repo)
  const sessions = readSessions(subject.sessions)
  const mergeTrees = readMergeTrees(subject.merge_trees)
  const conflicts = detectConflicts(repoFiles, sessions, mergeTrees)
  const sessionsById = new Map(sessions.map((session) => [session.id, session]))

  const compute = (claim: Claim): Computed => {
    if (claim.check === 'conflict') {
      const matched = conflicts.filter(
        (conflict) =>
          conflict.path === claim.path &&
          (claim.workspaceA === null || conflict.workspace_a === claim.workspaceA || conflict.workspace_b === claim.workspaceA) &&
          (claim.workspaceB === null || conflict.workspace_a === claim.workspaceB || conflict.workspace_b === claim.workspaceB),
      )
      return {
        result: matched.length > 0 ? 'conflict' : 'none',
        reason:
          matched.length > 0
            ? `${claim.path} 上有 ${matched.length} 组跨工作区同改（最高粒度 ${matched.map((item) => item.level).join('、')}）`
            : `${claim.path} 上没有跨工作区的同改记录`,
        inconclusive: false,
        missing: [],
        evidence: {
          path: claim.path,
          conflicts: matched.map(summarizeConflict),
          total_conflicts: conflicts.length,
        },
      }
    }

    if (claim.check === 'block') {
      let pair: [string, string] | null = null
      if (claim.workspaceA !== null && claim.workspaceB !== null) {
        pair = [claim.workspaceA, claim.workspaceB]
      } else {
        const writers = sessions.filter((session) => findWrites(session, claim.path).length > 0)
        const workspaces = [...new Set(writers.map((session) => session.workspace))].sort()
        if (workspaces.length === 1) {
          return {
            result: 'undecidable',
            reason: `${claim.path} 只有一个工作区有写记录（${workspaces[0]}）：没有跨工作区的区块级问题`,
            inconclusive: true,
            missing: ['第二个工作区的写记录'],
            evidence: { path: claim.path },
          }
        }
        if (workspaces.length === 2) pair = [workspaces[0], workspaces[1]]
      }
      if (pair === null) {
        return {
          result: 'undecidable',
          reason: `区块级需要明确的工作区对（${claim.path} 的写记录分布在多于两个工作区）`,
          inconclusive: true,
          missing: ['workspace_a / workspace_b'],
          evidence: { path: claim.path },
        }
      }
      const merge = findMerge(mergeTrees, pair[0], pair[1])
      if (merge === undefined) {
        return {
          result: 'undecidable',
          reason: `痕迹里没有 ${pair[0]} × ${pair[1]} 的 merge-tree 结果：区块级不能判`,
          inconclusive: true,
          missing: [`merge-tree(${pair[0]}, ${pair[1]})`],
          evidence: { path: claim.path, pair },
        }
      }
      if (merge.status === 'error') {
        return {
          result: 'undecidable',
          reason: `痕迹里的 merge-tree 是环境错误（§降级纪律）：只保留文件级`,
          inconclusive: true,
          missing: [`可用的 merge-tree(${pair[0]}, ${pair[1]})`],
          evidence: { path: claim.path, pair, merge_status: merge.status },
        }
      }
      const conflicted = merge.status === 'conflict' && merge.paths.includes(claim.path)
      return {
        result: conflicted ? 'conflict' : 'none',
        reason: conflicted
          ? `${claim.path} 在 ${pair[0]} × ${pair[1]} 的无副作用试合并里冲突`
          : `${claim.path} 在 ${pair[0]} × ${pair[1]} 的无副作用试合并里不冲突`,
        inconclusive: false,
        missing: [],
        evidence: { path: claim.path, pair, merge_status: merge.status, merge_paths: merge.paths },
      }
    }

    if (claim.sessionA === null || claim.sessionB === null) {
      return {
        result: 'undecidable',
        reason: 'symbol-relation 需要 session_a / session_b',
        inconclusive: true,
        missing: ['session_a / session_b'],
        evidence: { path: claim.path },
      }
    }
    const sessionA = sessionsById.get(claim.sessionA)
    const sessionB = sessionsById.get(claim.sessionB)
    if (sessionA === undefined || sessionB === undefined) {
      const missing = [
        sessionA === undefined ? `session ${claim.sessionA}` : null,
        sessionB === undefined ? `session ${claim.sessionB}` : null,
      ].filter(Boolean) as string[]
      return {
        result: 'undecidable',
        reason: `sessions 里没有 ${missing.join('、')}`,
        inconclusive: true,
        missing,
        evidence: { path: claim.path },
      }
    }
    if (sessionA.workspace === sessionB.workspace) {
      return {
        result: 'cross_file',
        reason: '两侧在同一工作区：本器官只对跨工作区做符号级判定',
        inconclusive: false,
        missing: [],
        evidence: { path: claim.path, sessions: [sessionA.id, sessionB.id] },
      }
    }
    const relation = symbolRelation(repoFiles, sessionA, sessionB, claim.path)
    const inconclusive = relation.relation === 'unavailable' && relation.missing.length > 0 && !repoFiles[claim.path]
    return {
      result: relation.relation,
      reason:
        relation.relation === 'same'
          ? `${claim.path} 两侧改动落在同一符号 ${relation.symbols.join('、')}`
          : relation.relation === 'adjacent'
            ? `${claim.path} 两侧改动落在相邻符号 ${relation.symbols.join('、')}`
            : relation.relation === 'different'
              ? `${claim.path} 两侧改动落在不同符号`
              : relation.relation === 'cross_file'
                ? `${claim.path} 不是两侧共同改过的文件（关系按跨文件处理）`
                : `${claim.path} 的符号关系取不到：${relation.missing.join('；')}`,
      inconclusive,
      missing: relation.missing,
      evidence: {
        path: claim.path,
        sessions: [sessionA.id, sessionB.id],
        relation: relation.relation,
        symbols: relation.symbols,
        ranges: [
          findWrites(sessionA, claim.path).flatMap((write) => write.ranges),
          findWrites(sessionB, claim.path).flatMap((write) => write.ranges),
        ],
        adjacent_tolerance: SETTINGS.adjacent_tolerance,
      },
    }
  }

  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    const computed = compute(claim)
    const comparison =
      computed.inconclusive
        ? 'undecidable'
        : claim.asserted === computed.result
          ? 'match'
          : 'mismatch'
    const verdict: Verdict =
      comparison === 'match'
        ? CLAIM
        : comparison === 'mismatch' && node !== null
          ? REFUTED
          : INCONCLUSIVE
    const parts: string[] = []
    if (comparison === 'match') parts.push(`主张「${claim.check}=${claim.asserted}」被冲突判据支持`)
    else if (comparison === 'mismatch') {
      parts.push(
        node === null
          ? `判据与主张不符（重算 ${computed.result} ≠ 主张 ${claim.asserted}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`
          : `判据推翻主张：重算 ${computed.result} ≠ 主张 ${claim.asserted}（${computed.reason}）`,
      )
    } else parts.push(`痕迹不足以判定：${computed.reason}`)
    if (computed.inconclusive && computed.missing.length > 0) parts.push(`缺失项：${computed.missing.join('、')}`)
    records.push(
      makeRecord({
        claim_id: claim.claimId,
        verdict,
        message: parts.join('；'),
        node,
        evidence: {
          check: claim.check,
          path: claim.path,
          claimed: claim.asserted,
          computed: computed.result,
          comparison,
          ...computed.evidence,
        },
      }),
    )
  }
  return records
}

function summarizeConflict(conflict: Conflict): Record<string, unknown> {
  return {
    levels: conflict.levels,
    level: conflict.level,
    workspace_a: conflict.workspace_a,
    workspace_b: conflict.workspace_b,
    path: conflict.path,
    symbols: conflict.symbols,
    line_ranges: conflict.line_ranges,
    severity: conflict.severity,
    severity_key: conflict.severity_key,
    degraded: conflict.degraded,
    approximate: conflict.approximate,
    sessions: conflict.sessions,
    session_ids: conflict.session_ids,
    sessions_a: conflict.sessions_a,
    sessions_b: conflict.sessions_b,
  }
}

export const agentConflictVerb: Verb = register({
  slug: 'agent-conflict',
  version: '0.0.4',
  summary: '多 agent 并行冲突取证：文件 / 区块 / 符号三级判据，逐条核对主张',
  input_fields: ['repo', 'sessions', 'claims'],
  evaluate,
})

export { rangeGap, LEVEL_ORDER }
export default agentConflictVerb