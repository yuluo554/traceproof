/**
 * bug-fix episode 切分 + 修复 diff 还原。
 *
 * 移植自旧仓 `episode.py`（M2）与 `reconstruct.py`（M3）的核心判据：
 *
 * - **起点**：`user_msg` 命中 bug 语义词；
 * - **失败信号**：`tool_result` 的**数值退出码优先**，其次 `is_error`，最后文本信号；
 * - **修复动作**：失败信号之后出现文件写类工具；
 * - **终点**：同一测试命令转为通过 → `verified_by_run`；否则 `ended_without_pass`；
 * - 丢弃候选逐条给 reason（`no_failure_evidence` / `no_fix_action` / `docs_only` / `below_threshold`）。
 *
 * 还原层（旧仓三级降级）：
 * 1. Claude `structuredPatch`（有 hunk）/ `originalFile` + `old_string` → high；
 * 2. Codex `apply_patch` / `FileChange.unified_diff` → medium；
 * 3. 基线漂移 / 上下文对不上 → `partial` + low；`old_string` 多处命中 → `unresolved`；
 *    新建文件没有 before → `no_before_image`。
 */

import defaults from './data/session-replay-defaults.json' with { type: 'json' }
import { UNKNOWN, isWriteTool } from './readers.js'
import type { Event } from './readers.js'

export interface Episode {
  episode_id: string
  session_id: string
  source: string
  start_seq: number
  end_seq: number
  user_report: string
  bug_term: string
  failure_evidence: Array<{ reason: string; seq: number }>
  edits: Array<{ tool: string; path: string; seq: number }>
  test_commands: Array<{ command: string; seq: number }>
  files: string[]
  score: number
  score_breakdown: Record<string, number>
  status: string
}

export interface Filtered {
  reason: string
  session_id: string
  source: string
  start_seq: number
  end_seq: number
  bug_term: string
  score: number
}

export interface SplitResult {
  episodes: Episode[]
  filtered: Filtered[]
}

export interface Reconstruction {
  path: string
  status: 'ok' | 'partial' | 'unresolved' | 'no_before_image'
  confidence: 'high' | 'medium' | 'low' | 'none'
  source: string
  before: string | null
  after: string | null
  hunks: number
  note: string
}

interface Settings {
  weights: Record<string, number>
  minScore: number
  idFormat: string
  docSuffixes: string[]
  bugTerms: string[]
  failureSignals: string[]
  testMarkers: string[]
  passMarkers: string[]
}

const SETTINGS: Settings = {
  weights: defaults.scoring.weights,
  minScore: defaults.scoring.min_score,
  idFormat: defaults.episode.id_format,
  docSuffixes: defaults.episode.doc_suffixes,
  bugTerms: defaults.vocabulary.bug_terms,
  failureSignals: defaults.vocabulary.failure_signals,
  testMarkers: defaults.vocabulary.test_command_markers,
  passMarkers: defaults.vocabulary.test_pass_markers,
}

const ASCII_ONLY = /^[\x20-\x7e]+$/

export function matchesBugTerm(text: string, terms: readonly string[]): string | null {
  if (!text) return null
  const lowered = text.toLowerCase()
  for (const term of terms) {
    if (ASCII_ONLY.test(term)) {
      const escaped = term.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const matched = new RegExp(`(?<![0-9a-z_])${escaped}(?![0-9a-z_])`).test(lowered)
      if (matched) return term
    } else if (lowered.includes(term.toLowerCase())) {
      return term
    }
  }
  return null
}

export function failureEvidence(event: Event, signals: readonly string[] = SETTINGS.failureSignals): string | null {
  if (event.kind !== 'tool_result') return null
  const code = event.payload.exit_code
  if (typeof code === 'number' && Number.isInteger(code)) {
    return code !== 0 ? 'exit_code' : null
  }
  if (event.payload.is_error === true) return 'is_error'
  const text = event.payload.text
  if (typeof text === 'string' && text) {
    for (const signal of signals) {
      if (text.includes(signal)) return `text_signal:${signal}`
    }
  }
  return null
}

function normalizeCommand(command: string): string {
  return command.split(/\s+/).filter(Boolean).join(' ')
}

export function testCommandOf(event: Event, markers: readonly string[] = SETTINGS.testMarkers): string | null {
  if (event.kind !== 'tool_call') return null
  const command = event.payload.command
  if (typeof command !== 'string' || !command) return null
  const lowered = command.toLowerCase()
  for (const marker of markers) {
    if (lowered.includes(marker.toLowerCase())) return normalizeCommand(command)
  }
  return null
}

function passEvidence(event: Event, signals: readonly string[], passMarkers: readonly string[]): boolean {
  if (event.kind !== 'tool_result') return false
  const code = event.payload.exit_code
  if (typeof code === 'number' && Number.isInteger(code)) return code === 0
  const text = event.payload.text
  if (typeof text !== 'string' || !text) return false
  if (signals.some((signal) => text.includes(signal))) return false
  return passMarkers.some((marker) => text.includes(marker))
}

function isDocPath(path: string, suffixes: readonly string[]): boolean {
  const lowered = (path || '').toLowerCase()
  return suffixes.some((suffix) => lowered.endsWith(suffix.toLowerCase()))
}

function hasBeforeImage(event: Event): boolean {
  const payload = event.payload
  const result = payload.result
  if (result !== null && typeof result === 'object') {
    const meta = result as Record<string, unknown>
    if (typeof meta.original_file === 'string' && meta.original_file) return true
    if (meta.has_patch_hunks === true) return true
    if (meta.files !== null && typeof meta.files === 'object' && Object.keys(meta.files as Record<string, unknown>).length > 0) return true
  }
  if (typeof payload.old_string === 'string' && payload.old_string) return true
  if (typeof payload.content === 'string' && payload.content) return true
  if (payload.has_input === true && Array.isArray(payload.files) && payload.files.length > 0) return true
  return false
}

interface Candidate {
  session_id: string
  source: string
  start_seq: number
  user_report: string
  bug_term: string
  failure_evidence: Array<{ reason: string; seq: number }>
  edits: Array<{ tool: string; path: string; seq: number }>
  edited_files: string[]
  test_commands: Array<{ command: string; seq: number }>
  failing_commands: string[]
  call_index: Map<string, string>
  before_image: boolean
  end_seq: number
  status: string
}

function emptyCandidate(event: Event, report: string, bugTerm: string): Candidate {
  return {
    session_id: event.session_id,
    source: event.source,
    start_seq: event.seq,
    user_report: report,
    bug_term: bugTerm,
    failure_evidence: [],
    edits: [],
    edited_files: [],
    test_commands: [],
    failing_commands: [],
    call_index: new Map(),
    before_image: false,
    end_seq: event.seq,
    status: 'ended_without_pass',
  }
}

function breakdown(candidate: Candidate): Record<string, number> {
  const parts: Record<string, number> = {}
  if (candidate.failure_evidence.length > 0) parts.failure_signal = SETTINGS.weights.failure_signal
  if (candidate.before_image) parts.reconstruction = SETTINGS.weights.reconstruction
  if (candidate.test_commands.length > 0) parts.test_command = SETTINGS.weights.test_command
  if (candidate.edited_files.length > 0 && candidate.edited_files.some((path) => !isDocPath(path, SETTINGS.docSuffixes))) {
    parts.code_change = SETTINGS.weights.code_change
  }
  return parts
}

function scoreOf(candidate: Candidate): number {
  return Object.values(breakdown(candidate)).reduce((sum, value) => sum + value, 0)
}

function dropReason(candidate: Candidate): string | null {
  if (candidate.failure_evidence.length === 0) return 'no_failure_evidence'
  if (candidate.edits.length === 0) return 'no_fix_action'
  if (candidate.edited_files.length > 0 && candidate.edited_files.every((path) => isDocPath(path, SETTINGS.docSuffixes))) {
    return 'docs_only'
  }
  if (scoreOf(candidate) < SETTINGS.minScore) return 'below_threshold'
  return null
}

function recordEdit(candidate: Candidate, event: Event): void {
  candidate.edits.push({ tool: event.tool, path: event.path, seq: event.seq })
  if (event.path !== UNKNOWN && !candidate.edited_files.includes(event.path)) candidate.edited_files.push(event.path)
  if (hasBeforeImage(event)) candidate.before_image = true
  candidate.end_seq = event.seq
}

function pairedCommand(event: Event, candidate: Candidate): string | null {
  for (const key of ['call_id', 'tool_use_id'] as const) {
    const value = event.payload[key]
    if (typeof value === 'string' && value !== UNKNOWN) {
      const found = candidate.call_index.get(value)
      if (found !== undefined) return found
    }
  }
  return null
}

export function splitEpisodes(events: readonly Event[]): SplitResult {
  const ordered = [...events].sort((a, b) =>
    a.source === b.source
      ? a.session_id === b.session_id
        ? a.seq - b.seq
        : a.session_id.localeCompare(b.session_id)
      : a.source.localeCompare(b.source),
  )
  const result: SplitResult = { episodes: [], filtered: [] }
  let current: Candidate | null = null
  const lastSeq = new Map<string, number>()

  const close = (candidate: Candidate, endSeq: number): void => {
    candidate.end_seq = Math.max(endSeq, candidate.start_seq)
    const reason = dropReason(candidate)
    if (reason !== null) {
      result.filtered.push({
        reason,
        session_id: candidate.session_id,
        source: candidate.source,
        start_seq: candidate.start_seq,
        end_seq: candidate.end_seq,
        bug_term: candidate.bug_term,
        score: scoreOf(candidate),
      })
      return
    }
    const firstFix = candidate.edits[0].seq
    result.episodes.push({
      episode_id: SETTINGS.idFormat.replace('{session_id}', candidate.session_id).replace('{first_fix_seq}', String(firstFix)),
      session_id: candidate.session_id,
      source: candidate.source,
      start_seq: candidate.start_seq,
      end_seq: candidate.end_seq,
      user_report: candidate.user_report,
      bug_term: candidate.bug_term,
      failure_evidence: [...candidate.failure_evidence],
      edits: [...candidate.edits],
      test_commands: [...candidate.test_commands],
      files: [...candidate.edited_files],
      score: scoreOf(candidate),
      score_breakdown: breakdown(candidate),
      status: candidate.status,
    })
  }

  for (const event of ordered) {
    const sessionKey = `${event.source}\u0000${event.session_id}`
    lastSeq.set(sessionKey, event.seq)

    if (event.kind === 'user_msg') {
      const text = typeof event.payload.text === 'string' ? event.payload.text : ''
      const term = matchesBugTerm(text, SETTINGS.bugTerms)
      if (term !== null) {
        if (current !== null) close(current, event.seq - 1)
        current = emptyCandidate(event, text, term)
      }
      continue
    }
    if (current === null) continue

    if (event.kind === 'tool_call') {
      const command = testCommandOf(event)
      if (command !== null) {
        current.test_commands.push({ command, seq: event.seq })
        const callId = event.payload.call_id ?? event.payload.tool_use_id
        if (typeof callId === 'string' && callId !== UNKNOWN) current.call_index.set(callId, command)
      }
      if (isWriteTool(event.tool)) recordEdit(current, event)
      continue
    }

    if (event.kind === 'tool_result') {
      const reason = failureEvidence(event)
      if (reason !== null) {
        current.failure_evidence.push({ reason, seq: event.seq })
        current.end_seq = event.seq
        const paired = pairedCommand(event, current)
        if (paired !== null && !current.failing_commands.includes(paired)) current.failing_commands.push(paired)
        continue
      }
      if (isWriteTool(event.tool)) {
        recordEdit(current, event)
        continue
      }
      const paired = pairedCommand(event, current)
      if (paired !== null && passEvidence(event, SETTINGS.failureSignals, SETTINGS.passMarkers)) {
        current.end_seq = event.seq
        const verified = current.failing_commands.length > 0 ? current.failing_commands.includes(paired) : current.edits.length > 0
        if (current.edits.length > 0 && verified) {
          current.status = 'verified_by_run'
          close(current, event.seq)
          current = null
        }
      }
    }
  }
  if (current !== null) close(current, lastSeq.get(`${current.source}\u0000${current.session_id}`) ?? current.start_seq)

  result.episodes.sort((a, b) =>
    a.source === b.source
      ? a.session_id === b.session_id
        ? a.start_seq - b.start_seq
        : a.session_id.localeCompare(b.session_id)
      : a.source.localeCompare(b.source),
  )
  result.filtered.sort((a, b) =>
    a.source === b.source
      ? a.session_id === b.session_id
        ? a.start_seq - b.start_seq
        : a.session_id.localeCompare(b.session_id)
      : a.source.localeCompare(b.source),
  )
  return result
}

// ── 还原层 ──────────────────────────────────────────────────────────────

interface Hunk {
  readonly oldStart: number
  readonly lines: readonly string[]
}

function linesOf(text: string): string[] {
  return text.split('\n')
}

function applyHunks(base: string, hunks: readonly Hunk[]): string | null {
  const baseLines = linesOf(base)
  const output: string[] = []
  let cursor = 0
  for (const hunk of hunks) {
    const start = hunk.oldStart - 1
    if (start < cursor || start > baseLines.length) return null
    output.push(...baseLines.slice(cursor, start))
    cursor = start
    for (const raw of hunk.lines) {
      const prefix = raw.slice(0, 1)
      const content = raw.slice(1)
      if (prefix === ' ') {
        if (baseLines[cursor] !== content) return null
        output.push(content)
        cursor += 1
      } else if (prefix === '-') {
        if (baseLines[cursor] !== content) return null
        cursor += 1
      } else if (prefix === '+') {
        output.push(content)
      } else {
        return null
      }
    }
  }
  output.push(...baseLines.slice(cursor))
  return output.join('\n')
}

function parseUnified(diffText: string): Hunk[] | null {
  const hunks: Hunk[] = []
  let current: { oldStart: number; lines: string[] } | null = null
  for (const line of diffText.split('\n')) {
    const header = line.match(/^@@\s+-(\d+)(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@/)
    if (header) {
      if (current !== null) hunks.push(current)
      current = { oldStart: Number(header[1]), lines: [] }
      continue
    }
    if (current === null) continue
    if (line === '' || line.startsWith('\\')) continue
    if (line[0] !== ' ' && line[0] !== '+' && line[0] !== '-') return null
    current.lines.push(line)
  }
  if (current !== null) hunks.push(current)
  return hunks.length > 0 ? hunks : null
}

function applyPatchText(base: string, patchText: string): { after: string | null; hunks: number } {
  const baseLines = linesOf(base)
  const hunks: Array<{ oldLines: string[]; newLines: string[] }> = []
  let body: { oldLines: string[]; newLines: string[] } | null = null
  for (const line of patchText.split('\n')) {
    const trimmed = line.trim()
    if (trimmed.startsWith('*** Begin Patch') || trimmed.startsWith('*** End Patch') || trimmed.startsWith('*** Update File') || trimmed.startsWith('*** Add File') || trimmed.startsWith('*** Delete File')) {
      if (body !== null && (body.oldLines.length > 0 || body.newLines.length > 0)) hunks.push(body)
      body = null
      continue
    }
    if (trimmed.startsWith('@@')) {
      if (body !== null && (body.oldLines.length > 0 || body.newLines.length > 0)) hunks.push(body)
      body = { oldLines: [], newLines: [] }
      continue
    }
    if (body === null) continue
    if (line === '') continue
    const prefix = line[0]
    const content = line.slice(1)
    if (prefix === ' ') {
      body.oldLines.push(content)
      body.newLines.push(content)
    } else if (prefix === '-') {
      body.oldLines.push(content)
    } else if (prefix === '+') {
      body.newLines.push(content)
    }
  }
  if (body !== null && (body.oldLines.length > 0 || body.newLines.length > 0)) hunks.push(body)
  if (hunks.length === 0) return { after: null, hunks: 0 }

  let output = [...baseLines]
  for (const hunk of hunks) {
    if (hunk.oldLines.length === 0) {
      output = [...hunk.newLines, ...output]
      continue
    }
    let found = -1
    for (let index = 0; index <= output.length - hunk.oldLines.length; index += 1) {
      let matched = true
      for (let offset = 0; offset < hunk.oldLines.length; offset += 1) {
        if (output[index + offset] !== hunk.oldLines[offset]) {
          matched = false
          break
        }
      }
      if (matched) {
        found = index
        break
      }
    }
    if (found < 0) return { after: null, hunks: hunks.length }
    output = [...output.slice(0, found), ...hunk.newLines, ...output.slice(found + hunk.oldLines.length)]
  }
  return { after: output.join('\n'), hunks: hunks.length }
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0
  let count = 0
  let index = 0
  for (;;) {
    const found = haystack.indexOf(needle, index)
    if (found < 0) break
    count += 1
    index = found + needle.length
  }
  return count
}

interface Evidence {
  path: string
  seq: number
  tool: string
  payload: Record<string, unknown>
  result: Record<string, unknown>
}

function collectEvidence(events: readonly Event[]): Evidence[] {
  const list: Evidence[] = []
  for (const event of events) {
    if (event.kind === 'tool_call' && isWriteTool(event.tool)) {
      const result = event.payload.result !== null && typeof event.payload.result === 'object' ? (event.payload.result as Record<string, unknown>) : {}
      list.push({ path: event.path, seq: event.seq, tool: event.tool, payload: event.payload, result })
    } else if (event.kind === 'tool_result' && event.tool === 'file_change') {
      const files = event.payload.files
      if (files !== null && typeof files === 'object') {
        for (const [path, detail] of Object.entries(files as Record<string, unknown>)) {
          const record = detail !== null && typeof detail === 'object' ? (detail as Record<string, unknown>) : {}
          list.push({ path, seq: event.seq, tool: 'file_change', payload: {}, result: { files: { [path]: record } } })
        }
      }
    }
  }
  return list
}

export function reconstructAll(events: readonly Event[], repoFiles: Record<string, string>): Reconstruction[] {
  const results: Reconstruction[] = []
  for (const evidence of collectEvidence(events)) {
    const path = evidence.path
    if (path === UNKNOWN) continue
    const result = evidence.result
    const originalFile = typeof result.original_file === 'string' ? result.original_file : null
    const base = originalFile ?? repoFiles[path] ?? null
    const patch = Array.isArray(result.structured_patch) ? (result.structured_patch as Array<Record<string, unknown>>) : []
    const oldString = typeof evidence.payload.old_string === 'string' ? evidence.payload.old_string : null
    const newString = typeof evidence.payload.new_string === 'string' ? evidence.payload.new_string : null
    const content = typeof evidence.payload.content === 'string' ? evidence.payload.content : null
    const patchText = typeof evidence.payload.input === 'string' ? evidence.payload.input : null
    const unified = result.files !== null && typeof result.files === 'object'
      ? ((result.files as Record<string, Record<string, unknown>>)[path]?.unified_diff as string | undefined) ?? null
      : null

    if (patch.length > 0) {
      const hunks: Hunk[] = patch.map((hunk) => ({
        oldStart: Number(hunk.oldStart ?? 1),
        lines: Array.isArray(hunk.lines) ? (hunk.lines as string[]) : [],
      }))
      if (base === null) {
        results.push({ path, status: 'unresolved', confidence: 'none', source: 'claude_structured_patch', before: null, after: null, hunks: hunks.length, note: '没有 before 镜像（原文件不在日志也不在 repo.files）' })
        continue
      }
      const after = applyHunks(base, hunks)
      if (after === null) {
        results.push({ path, status: 'partial', confidence: 'low', source: 'claude_structured_patch', before: null, after: null, hunks: hunks.length, note: 'structuredPatch 的上下文与 before 镜像不符（基线漂移）' })
      } else {
        results.push({ path, status: 'ok', confidence: 'high', source: 'claude_structured_patch', before: base, after, hunks: hunks.length, note: '' })
      }
      continue
    }

    if (oldString !== null && newString !== null) {
      if (base === null) {
        results.push({ path, status: 'unresolved', confidence: 'none', source: 'claude_old_string', before: null, after: null, hunks: 0, note: '没有 before 镜像' })
        continue
      }
      const occurrences = countOccurrences(base, oldString)
      if (occurrences === 0) {
        results.push({ path, status: 'partial', confidence: 'low', source: 'claude_old_string', before: null, after: null, hunks: 0, note: 'old_string 在 before 镜像里找不到（基线漂移）' })
      } else if (occurrences > 1 && evidence.payload.replace_all !== true) {
        results.push({ path, status: 'unresolved', confidence: 'none', source: 'claude_old_string', before: null, after: null, hunks: 0, note: `old_string 在 before 镜像里出现 ${occurrences} 次（定位不唯一）` })
      } else {
        const after = evidence.payload.replace_all === true ? base.split(oldString).join(newString) : base.replace(oldString, newString)
        results.push({ path, status: 'ok', confidence: 'high', source: 'claude_old_string', before: base, after, hunks: 1, note: '' })
      }
      continue
    }

    if (content !== null) {
      if (base === null) {
        results.push({ path, status: 'no_before_image', confidence: 'none', source: 'claude_write_content', before: null, after: content, hunks: 0, note: 'Write 只给了新内容，没有 before 镜像' })
      } else {
        results.push({ path, status: 'ok', confidence: 'high', source: 'claude_write_content', before: base, after: content, hunks: 1, note: '' })
      }
      continue
    }

    if (unified !== null) {
      if (base === null) {
        results.push({ path, status: 'unresolved', confidence: 'none', source: 'codex_unified_diff', before: null, after: null, hunks: 0, note: '没有 before 镜像' })
        continue
      }
      const hunks = parseUnified(unified)
      if (hunks === null) {
        results.push({ path, status: 'partial', confidence: 'low', source: 'codex_unified_diff', before: null, after: null, hunks: 0, note: 'unified_diff 无法解析' })
        continue
      }
      const after = applyHunks(base, hunks)
      if (after === null) {
        results.push({ path, status: 'partial', confidence: 'low', source: 'codex_unified_diff', before: null, after: null, hunks: hunks.length, note: 'unified_diff 的上下文与 before 镜像不符（基线漂移）' })
      } else {
        results.push({ path, status: 'ok', confidence: 'medium', source: 'codex_unified_diff', before: base, after, hunks: hunks.length, note: '' })
      }
      continue
    }

    if (patchText !== null && patchText.includes('*** Begin Patch')) {
      if (base === null) {
        results.push({ path, status: 'unresolved', confidence: 'none', source: 'codex_patch_text', before: null, after: null, hunks: 0, note: '没有 before 镜像' })
        continue
      }
      const applied = applyPatchText(base, patchText)
      if (applied.after === null) {
        results.push({ path, status: 'partial', confidence: 'low', source: 'codex_patch_text', before: null, after: null, hunks: applied.hunks, note: 'patch 的上下文与 before 镜像不符（基线漂移）' })
      } else {
        results.push({ path, status: 'ok', confidence: 'medium', source: 'codex_patch_text', before: base, after: applied.after, hunks: applied.hunks, note: '' })
      }
      continue
    }

    results.push({ path, status: 'unresolved', confidence: 'none', source: 'none', before: null, after: null, hunks: 0, note: '写事件没有可用的 diff 证据' })
  }
  return results
}