/**
 * 指标层（迁自源仓 `engine/metrics.py` + `engine/symbols.py`）。
 *
 * - Read:Edit 比：分子 = `read` 事件，分母 = 写事件（edit / write / multiedit）；
 *   分母为 0 → 比值「未定义」（`null`），不填 0 不填 inf。
 * - 符号提取：首期仅 Python（`def` / `async def` / `class`）；非支持语言显式返回 null。
 * - 粗匹配：5 步归一化 → 精确相等 `normalized_exact`，否则 `difflib` ratio ≥ 阈值
 *   → `high_similarity`。候选输出必须伴随披露文本（`DUP_DISCLOSURE`），非克隆判决。
 *
 * `difflib.SequenceMatcher.ratio()` 在 TypeScript 里按 Python 算法本地重实现
 * （matching blocks + 2M/T），保证同一阈值下的命中与源仓一致。
 */

import {
  DUP_MATCH_THRESHOLD,
  DUP_DISCLOSURE,
  READ_EVENT_KINDS,
  SUPPORTED_SYMBOL_LANGUAGES,
  SYMBOL_LANGUAGE_BY_SUFFIX,
  SYMBOL_PREFIX_TOKENS,
  SYMBOL_SUFFIX_TOKENS,
  WRITE_EVENT_KINDS,
} from './defaults.js'
import type { ToolUseEvent } from './parse.js'

export interface Symbol {
  readonly name: string
  readonly kind: 'function' | 'class'
  readonly line_in_payload: number
}

export interface DupCandidate {
  readonly new_symbol: string
  readonly existing_symbol: string
  readonly match_reason: 'normalized_exact' | 'high_similarity'
  readonly similarity: number | null
  readonly new_evidence: string
  readonly existing_evidence: string
}

export interface SessionMetrics {
  readonly session_id: string
  readonly reads: number
  readonly writes: number
  readonly writes_by_kind: readonly (readonly [string, number])[]
  readonly read_edit_ratio: number | null
  readonly dup_candidates: readonly DupCandidate[]
}

export interface WritePayload {
  readonly path: string
  readonly content: string
  readonly language: string | null
}

export { DUP_DISCLOSURE }

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

// ── Python difflib.SequenceMatcher 的确定性复刻（无 junk，含 autojunk） ────

function buildB2J(b: readonly string[]): Map<string, number[]> {
  const b2j = new Map<string, number[]>()
  b.forEach((element, index) => {
    const bucket = b2j.get(element)
    if (bucket === undefined) b2j.set(element, [index])
    else bucket.push(index)
  })
  const n = b.length
  if (n >= 200) {
    const popularLimit = Math.floor(n / 100) + 1
    for (const [element, indices] of [...b2j.entries()]) {
      if (indices.length > popularLimit) b2j.delete(element)
    }
  }
  return b2j
}

function findLongestMatch(
  a: readonly string[],
  b: readonly string[],
  b2j: ReadonlyMap<string, readonly number[]>,
  alo: number,
  ahi: number,
  blo: number,
  bhi: number,
): [number, number, number] {
  let besti = alo
  let bestj = blo
  let bestsize = 0
  let previous = new Map<number, number>()
  for (let i = alo; i < ahi; i += 1) {
    const current = new Map<number, number>()
    const indices = b2j.get(a[i]) ?? []
    for (const j of indices) {
      if (j < blo) continue
      if (j >= bhi) break
      const size = (previous.get(j - 1) ?? 0) + 1
      current.set(j, size)
      if (size > bestsize) {
        besti = i - size + 1
        bestj = j - size + 1
        bestsize = size
      }
    }
    previous = current
  }
  while (besti > alo && bestj > blo && a[besti - 1] === b[bestj - 1]) {
    besti -= 1
    bestj -= 1
    bestsize += 1
  }
  const aTail = besti + bestsize
  const bTail = bestj + bestsize
  while (aTail < ahi && bTail < bhi && a[aTail] === b[bTail]) bestsize += 1
  return [besti, bestj, bestsize]
}

function matchingBlocks(a: readonly string[], b: readonly string[]): Array<[number, number, number]> {
  const b2j = buildB2J(b)
  const queue: Array<[number, number, number, number]> = [[0, a.length, 0, b.length]]
  const blocks: Array<[number, number, number]> = []
  while (queue.length > 0) {
    const [alo, ahi, blo, bhi] = queue.pop() as [number, number, number, number]
    const [i, j, size] = findLongestMatch(a, b, b2j, alo, ahi, blo, bhi)
    if (size > 0) {
      blocks.push([i, j, size])
      if (alo < i && blo < j) queue.push([alo, i, blo, j])
      if (i + size < ahi && j + size < bhi) queue.push([i + size, ahi, j + size, bhi])
    }
  }
  blocks.sort(([ai, aj, ak], [bi, bj, bk]) => ai - bi || aj - bj || ak - bk)
  const merged: Array<[number, number, number]> = []
  let i1 = 0
  let j1 = 0
  let k1 = 0
  for (const [i2, j2, k2] of blocks) {
    if (i1 + k1 === i2 && j1 + k1 === j2) {
      k1 += k2
    } else {
      if (k1 > 0) merged.push([i1, j1, k1])
      i1 = i2
      j1 = j2
      k1 = k2
    }
  }
  if (k1 > 0) merged.push([i1, j1, k1])
  merged.push([a.length, b.length, 0])
  return merged
}

/** `difflib.SequenceMatcher(None, a, b).ratio()`：2M/T；T=0 → 1.0。 */
export function sequenceRatio(left: string, right: string): number {
  const a = Array.from(left)
  const b = Array.from(right)
  const total = a.length + b.length
  if (total === 0) return 1.0
  const matches = matchingBlocks(a, b).reduce((sum, [, , size]) => sum + size, 0)
  return (2.0 * matches) / total
}

// ── 符号提取 ──────────────────────────────────────────────────────────────

const DEF_PATTERN = /^[ \t]*(?:async[ \t]+)?def[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(/
const CLASS_PATTERN = /^[ \t]*class[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*[:({]/

export function isSupportedLanguage(language: string): boolean {
  return SUPPORTED_SYMBOL_LANGUAGES.has(language)
}

/** 提取源码文本中的 `def` / `class` 定义名；语言未支持 → null（显式拒绝，不猜测）。 */
export function extractDefinedSymbols(text: string, language = 'python'): Symbol[] | null {
  if (!isSupportedLanguage(language)) return null
  const symbols: Symbol[] = []
  const lines = text.split(/\r\n|\r|\n/)
  lines.forEach((line, index) => {
    const def = line.match(DEF_PATTERN)
    if (def !== null) {
      symbols.push(Object.freeze({ name: def[1], kind: 'function', line_in_payload: index + 1 }))
      return
    }
    const cls = line.match(CLASS_PATTERN)
    if (cls !== null) {
      symbols.push(Object.freeze({ name: cls[1], kind: 'class', line_in_payload: index + 1 }))
    }
  })
  return symbols
}

export function symbolsFromWritePayloads(
  payloads: readonly (readonly [string, string])[],
): Symbol[] {
  const symbols: Symbol[] = []
  for (const [language, text] of payloads) {
    const extracted = extractDefinedSymbols(text, language)
    if (extracted === null) continue
    symbols.push(...extracted)
  }
  return symbols
}

// ── 归一化 / 匹配 ─────────────────────────────────────────────────────────

/** 源仓冻结的 5 步归一化：小写 / `-`→`_` / 去首尾 `_` / 首尾词表剔除（可迭代）/ 拼接。 */
export function normalizeSymbolName(name: string): string {
  const lowered = name.toLowerCase().replace(/-/g, '_')
  const stripped = lowered.replace(/^_+|_+$/g, '')
  const tokens = stripped.split('_').filter((token) => token.length > 0)
  let changed = true
  while (changed && tokens.length > 0) {
    changed = false
    while (tokens.length > 0 && SYMBOL_PREFIX_TOKENS.has(tokens[0])) {
      tokens.shift()
      changed = true
    }
    while (tokens.length > 0 && SYMBOL_SUFFIX_TOKENS.has(tokens[tokens.length - 1])) {
      tokens.pop()
      changed = true
    }
  }
  return tokens.join('')
}

/** 两级匹配：归一化精确相等 → `normalized_exact`；否则原始名 ratio ≥ 阈值。 */
export function matchSymbols(
  newSymbol: string,
  existingSymbol: string,
): [DupCandidate['match_reason'], number | null] | null {
  if (normalizeSymbolName(newSymbol) === normalizeSymbolName(existingSymbol)) {
    return ['normalized_exact', null]
  }
  const ratio = sequenceRatio(newSymbol, existingSymbol)
  if (ratio >= DUP_MATCH_THRESHOLD) return ['high_similarity', ratio]
  return null
}

/** 新写符号 × 已有符号 → 粗匹配候选（确定性：按三元组排序去重）。 */
export function findDupCandidates(
  newSymbols: readonly Symbol[],
  existingSymbols: readonly Symbol[],
  newEvidence = '',
  existingEvidence = '',
): DupCandidate[] {
  const candidates = new Map<string, DupCandidate>()
  for (const fresh of newSymbols) {
    for (const existing of existingSymbols) {
      if (fresh.name === existing.name) continue
      const matched = matchSymbols(fresh.name, existing.name)
      if (matched === null) continue
      const [reason, similarity] = matched
      const candidate: DupCandidate = Object.freeze({
        new_symbol: fresh.name,
        existing_symbol: existing.name,
        match_reason: reason,
        similarity,
        new_evidence: newEvidence,
        existing_evidence: existingEvidence,
      })
      candidates.set(`${fresh.name}\u0000${existing.name}\u0000${reason}`, candidate)
    }
  }
  return [...candidates.values()].sort(
    (a, b) =>
      a.new_symbol.localeCompare(b.new_symbol) ||
      a.existing_symbol.localeCompare(b.existing_symbol) ||
      a.match_reason.localeCompare(b.match_reason),
  )
}

// ── 会话指标 ──────────────────────────────────────────────────────────────

export function countReadWrite(events: readonly ToolUseEvent[]): [number, number] {
  let reads = 0
  let writes = 0
  for (const event of events) {
    if (READ_EVENT_KINDS.has(event.kind)) reads += 1
    else if (WRITE_EVENT_KINDS.has(event.kind)) writes += 1
  }
  return [reads, writes]
}

/** Read:Edit 比；分母为 0 → null（未定义）。 */
export function computeReadEditRatio(reads: number, writes: number): number | null {
  if (writes <= 0) return null
  return reads / writes
}

export function computeSessionMetrics(
  sessionId: string,
  events: readonly ToolUseEvent[],
  writePayloads: readonly (readonly [string, string])[] = [],
  existingSymbols: readonly Symbol[] = [],
  newEvidence = '',
  existingEvidence = '',
): SessionMetrics {
  const [reads, writes] = countReadWrite(events)
  const writesByKind: Array<readonly [string, number]> = []
  for (const kind of [...WRITE_EVENT_KINDS].sort()) {
    const count = events.filter((event) => event.kind === kind).length
    if (count > 0) writesByKind.push(Object.freeze([kind, count] as const))
  }
  const newSymbols = symbolsFromWritePayloads(writePayloads)
  const candidates =
    newSymbols.length > 0 && existingSymbols.length > 0
      ? findDupCandidates(newSymbols, existingSymbols, newEvidence, existingEvidence)
      : []
  return Object.freeze({
    session_id: sessionId,
    reads,
    writes,
    writes_by_kind: Object.freeze(writesByKind),
    read_edit_ratio: computeReadEditRatio(reads, writes),
    dup_candidates: Object.freeze(candidates),
  })
}

// ── 输入侧的载荷 / 工程文件（器官不读盘：数据全部来自 subject） ─────────

function suffixOf(path: string): string {
  const base = path.split(/[\\/]/).pop() ?? ''
  const index = base.lastIndexOf('.')
  if (index <= 0 || index === base.length - 1) return ''
  return base.slice(index).toLowerCase()
}

/** 从 Claude 记录里取 Write 载荷（源仓 `_iter_write_payloads` 的纯函数版）。 */
export function writePayloadsFromRecords(
  records: readonly Record<string, unknown>[],
): WritePayload[] {
  const payloads: WritePayload[] = []
  for (const record of records) {
    if (record.type !== 'assistant') continue
    const message = record.message
    if (!isPlainObject(message)) continue
    const content = message.content
    if (!Array.isArray(content)) continue
    for (const block of content) {
      if (!isPlainObject(block) || block.type !== 'tool_use' || block.name !== 'Write') continue
      const input = block.input
      if (!isPlainObject(input)) continue
      const text = input.content
      if (typeof text !== 'string') continue
      const path = typeof input.file_path === 'string' ? input.file_path : ''
      payloads.push(
        Object.freeze({
          path,
          content: text,
          language: SYMBOL_LANGUAGE_BY_SUFFIX[suffixOf(path)] ?? null,
        }),
      )
    }
  }
  return payloads
}

function normalizeSlashes(value: string): string {
  return value.replace(/\\/g, '/')
}

/**
 * 读目标 → `project_files` 里的文件（源仓 `_resolve_existing` 的后缀回退：
 * 先整路径，再从最长后缀逐级回退；多个键命中时取字典序最小，保证确定性）。
 */
export function resolveProjectFile(
  target: string,
  projectFiles: Readonly<Record<string, string>>,
): { path: string; content: string } | null {
  if (Object.prototype.hasOwnProperty.call(projectFiles, target)) {
    return { path: target, content: projectFiles[target] }
  }
  const parts = normalizeSlashes(target)
    .split('/')
    .filter((part) => part.length > 0 && part !== '.' && part !== '..')
  const keys = Object.keys(projectFiles)
    .filter((key) => normalizeSlashes(key))
    .sort()
  for (let start = 0; start < parts.length; start += 1) {
    const suffix = parts.slice(start).join('/')
    const found = keys.find((key) => {
      const normalized = normalizeSlashes(key)
      return normalized === suffix || normalized.endsWith(`/${suffix}`)
    })
    if (found !== undefined) return { path: found, content: projectFiles[found] }
  }
  return null
}

/** Read 过且能在 `project_files` 里定位的 .py 文件 → 已有符号清单。 */
export function existingSymbolsFromReads(
  readTargets: readonly string[],
  projectFiles: Readonly<Record<string, string>>,
  onMissing: (target: string) => void,
): Symbol[] {
  const collected: Symbol[] = []
  const seen = new Set<string>()
  for (const target of [...new Set(readTargets)].sort()) {
    const resolved = resolveProjectFile(target, projectFiles)
    if (resolved === null) {
      onMissing(target)
      continue
    }
    if (seen.has(resolved.path)) continue
    seen.add(resolved.path)
    const extracted = extractDefinedSymbols(resolved.content, 'python')
    if (extracted !== null) collected.push(...extracted)
  }
  return collected
}