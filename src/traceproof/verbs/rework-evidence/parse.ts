/**
 * 会话记录 → 统一 IR（迁自源仓 `parsers/claude_code.py` / `parsers/codex.py` + `ir.py`）。
 *
 * 输入是**已解析的 jsonl 行对象**（`session.records`，seq = 数组下标 + 1），
 * 器官不读文件：源仓里「按行读 jsonl + file-history 目录实读」的 I/O 部分不迁，
 * 版本链改由输入 `version_chains` 提供（见 `rework.ts`）。
 *
 * 字段纪律沿用源仓 K7：未核对字段不进计算路径，跳过并计 `ParseNote`（显式可见，不静默）。
 */

export type Source = 'claude' | 'codex'

export const KINDS = ['read', 'edit', 'write', 'multiedit', 'exec', 'other'] as const
export type Kind = (typeof KINDS)[number]

export const IR_VERSION = 1

export interface SessionMeta {
  readonly source: Source
  readonly session_id: string
  readonly cwd: string | null
  readonly started_at: string | null
  readonly source_file: string
  readonly agent_version: string | null
}

export interface ToolUseEvent {
  readonly seq: number
  readonly kind: Kind
  readonly tool_name: string
  readonly timestamp: string | null
  readonly file_path: string | null
}

export interface TokenUsageEvent {
  readonly seq: number
  readonly timestamp: string | null
  readonly input_tokens: number | null
  readonly output_tokens: number | null
  readonly cache_creation_input_tokens: number | null
  readonly cache_read_input_tokens: number | null
  readonly total_tokens: number | null
}

export interface ParseNote {
  readonly code: string
  readonly message: string
  readonly count: number
}

export interface SessionIR {
  readonly meta: SessionMeta
  readonly tool_events: readonly ToolUseEvent[]
  readonly token_events: readonly TokenUsageEvent[]
  readonly notes: readonly ParseNote[]
  readonly ir_version: number
}

export interface SnapshotMapping {
  readonly backup_stem: string
  readonly max_version: number
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function intOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) ? value : null
}

class NoteBook {
  private readonly notes: ParseNote[] = []
  private readonly index = new Map<string, number>()

  bump(code: string, message: string): void {
    const key = `${code}\u0000${message}`
    const position = this.index.get(key)
    if (position === undefined) {
      this.index.set(key, this.notes.length)
      this.notes.push(Object.freeze({ code, message, count: 1 }))
      return
    }
    const previous = this.notes[position]
    this.notes[position] = Object.freeze({ code, message: previous.message, count: previous.count + 1 })
  }

  finish(): ParseNote[] {
    return this.notes.map((note) => Object.freeze({ ...note }))
  }
}

/** 源仓 `%r` 的最小复刻：只用于「未核对 payload.type」注记的稳定文本。 */
function pyRepr(value: unknown): string {
  if (value === null || value === undefined) return 'None'
  if (typeof value === 'string') return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
  if (typeof value === 'boolean') return value ? 'True' : 'False'
  if (typeof value === 'number') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

// ── Claude Code ───────────────────────────────────────────────────────────

const SNAPSHOT_ENTRY_FIELDS = new Set(['backupFileName', 'version', 'backupTime', 'realParentDir'])

/** 工具名 → kind（源仓 R3/R4 核对口径；MultiEdit 与 Edit 同为编辑语义）。 */
const CLAUDE_TOOL_KINDS: Readonly<Record<string, Kind>> = Object.freeze({
  Read: 'read',
  Edit: 'edit',
  NotebookEdit: 'edit',
  Write: 'write',
  MultiEdit: 'edit',
  Bash: 'exec',
})

function replaceMeta(meta: SessionMeta, changes: Partial<SessionMeta>): SessionMeta {
  return Object.freeze({ ...meta, ...changes })
}

function absorbClaudeMeta(meta: SessionMeta, record: Record<string, unknown>): SessionMeta {
  let next = meta
  if (typeof record.sessionId === 'string' && next.session_id === 'unknown') {
    next = replaceMeta(next, { session_id: record.sessionId })
  }
  if (typeof record.cwd === 'string' && next.cwd === null) {
    next = replaceMeta(next, { cwd: record.cwd })
  }
  const type = record.type
  if (
    typeof record.timestamp === 'string' &&
    next.started_at === null &&
    (type === undefined || type === null || type === 'session_meta' || type === 'session_meta_like')
  ) {
    next = replaceMeta(next, { started_at: record.timestamp })
  }
  if (typeof record.version === 'string' && next.agent_version === null) {
    next = replaceMeta(next, { agent_version: record.version })
  }
  return next
}

function checkSnapshot(record: Record<string, unknown>, notes: NoteBook): void {
  const snapshot = record.snapshot
  if (!isPlainObject(snapshot)) return
  const tracked = snapshot.trackedFileBackups
  if (!isPlainObject(tracked)) return
  for (const entry of Object.values(tracked)) {
    if (entry === null) {
      notes.bump('snapshot_entry_null', '快照 entry 为 null（R6 容错）')
      continue
    }
    if (!isPlainObject(entry)) {
      notes.bump('snapshot_entry_shape', '快照 entry 形态异常（非 dict）')
      continue
    }
    const unknown = Object.keys(entry)
      .filter((key) => !SNAPSHOT_ENTRY_FIELDS.has(key))
      .sort()
    if (unknown.length > 0) {
      notes.bump(
        'snapshot_entry_extra_field',
        `快照 entry 含未核对字段 ${unknown.join(',')}（K7：跳过不启用）`,
      )
    }
  }
}

function claudeUsage(seq: number, timestamp: string | null, usage: Record<string, unknown>): TokenUsageEvent {
  const input = intOrNull(usage.input_tokens)
  const output = intOrNull(usage.output_tokens)
  const total = input !== null && output !== null ? input + output : null
  return Object.freeze({
    seq,
    timestamp,
    input_tokens: input,
    output_tokens: output,
    cache_creation_input_tokens: intOrNull(usage.cache_creation_input_tokens),
    cache_read_input_tokens: intOrNull(usage.cache_read_input_tokens),
    total_tokens: total,
  })
}

function classifyClaudeToolUse(
  block: Record<string, unknown>,
  seq: number,
  timestamp: string | null,
): ToolUseEvent | null {
  const name = block.name
  const input = block.input
  if (typeof name !== 'string' || !isPlainObject(input)) return null
  const filePath = input.file_path
  return Object.freeze({
    seq,
    kind: CLAUDE_TOOL_KINDS[name] ?? 'other',
    tool_name: name,
    timestamp,
    file_path: typeof filePath === 'string' ? filePath : null,
  })
}

/** 解析单个 Claude Code 会话的已解析行 → IR。 */
export function parseClaudeSession(
  records: readonly Record<string, unknown>[],
  sourceFile: string,
): SessionIR {
  let meta: SessionMeta = Object.freeze({
    source: 'claude',
    session_id: 'unknown',
    cwd: null,
    started_at: null,
    source_file: sourceFile,
    agent_version: null,
  })
  const toolEvents: ToolUseEvent[] = []
  const tokenEvents: TokenUsageEvent[] = []
  const notes = new NoteBook()

  records.forEach((record, position) => {
    const seq = position + 1
    if (record.type === 'file-history-snapshot') {
      checkSnapshot(record, notes)
      return
    }
    const message = record.message
    if (!isPlainObject(message)) {
      meta = absorbClaudeMeta(meta, record)
      return
    }
    if (message.role !== 'assistant') return

    const timestamp = typeof record.timestamp === 'string' ? record.timestamp : null
    const usage = message.usage
    if (isPlainObject(usage)) tokenEvents.push(claudeUsage(seq, timestamp, usage))

    const content = message.content
    if (!Array.isArray(content)) return
    for (const block of content) {
      if (!isPlainObject(block) || block.type !== 'tool_use') continue
      const event = classifyClaudeToolUse(block, seq, timestamp)
      if (event === null) {
        notes.bump('unverified_field_skipped', `第 ${seq} 行：tool_use 缺 name/input，未核对不启用（K7）`)
        continue
      }
      if (event.tool_name === 'MultiEdit') {
        notes.bump(
          'multiedit_downgraded',
          `第 ${seq} 行：MultiEdit 本机未核对（D-M1-4），按 edit 序列降级计数`,
        )
      }
      toolEvents.push(event)
    }
  })

  return Object.freeze({
    meta,
    tool_events: Object.freeze(toolEvents),
    token_events: Object.freeze(tokenEvents),
    notes: Object.freeze(notes.finish()),
    ir_version: IR_VERSION,
  })
}

/** 实读快照行（源仓 R6）→ `{file_path: {backup_stem, max_version}}`；只取已核对字段。 */
export function readSnapshotFileMap(
  records: readonly Record<string, unknown>[],
): Record<string, SnapshotMapping> {
  const versionPattern = /@v(\d+)(?:\.[^@\\/]*)?$/
  const latest: Record<string, SnapshotMapping> = {}
  for (const record of records) {
    if (record.type !== 'file-history-snapshot') continue
    const snapshot = record.snapshot
    if (!isPlainObject(snapshot)) continue
    const tracked = snapshot.trackedFileBackups
    if (!isPlainObject(tracked)) continue
    for (const [filePath, entry] of Object.entries(tracked)) {
      if (!isPlainObject(entry)) continue
      const backupName = entry.backupFileName
      if (typeof backupName !== 'string') continue
      const match = backupName.match(versionPattern)
      if (match === null) continue
      const stem = backupName.slice(0, match.index)
      const version = Number(match[1])
      const current = latest[filePath]
      if (current === undefined || version > current.max_version) {
        latest[filePath] = Object.freeze({ backup_stem: stem, max_version: version })
      }
    }
  }
  return latest
}

// ── Codex ─────────────────────────────────────────────────────────────────

const V4A_FILE_PATTERN = /^\*\*\* (Update|Add) File: (.+?)\s*$/

/** 从 V4A 补丁文本提取 Update/Add File 目标路径；input 非字符串 → null。 */
export function extractPatchPaths(input: unknown): string[] | null {
  if (typeof input !== 'string') return null
  const paths: string[] = []
  for (const line of input.split(/\r?\n/)) {
    const match = line.match(V4A_FILE_PATTERN)
    if (match !== null) paths.push(match[2].trim())
  }
  return paths
}

function codexUsage(seq: number, timestamp: string | null, usage: Record<string, unknown>): TokenUsageEvent {
  const input = intOrNull(usage.input_tokens)
  const output = intOrNull(usage.output_tokens)
  const declaredTotal = intOrNull(usage.total_token_counts)
  const total =
    declaredTotal !== null && declaredTotal !== 0
      ? declaredTotal
      : input !== null && output !== null
        ? input + output
        : null
  return Object.freeze({
    seq,
    timestamp,
    input_tokens: input,
    output_tokens: output,
    cache_creation_input_tokens: null,
    cache_read_input_tokens: intOrNull(usage.input_tokens_cached),
    total_tokens: total,
  })
}

/** 解析单个 Codex 会话的已解析行 → IR。 */
export function parseCodexSession(
  records: readonly Record<string, unknown>[],
  sourceFile: string,
): SessionIR {
  let meta: SessionMeta = Object.freeze({
    source: 'codex',
    session_id: 'unknown',
    cwd: null,
    started_at: null,
    source_file: sourceFile,
    agent_version: null,
  })
  const toolEvents: ToolUseEvent[] = []
  const tokenEvents: TokenUsageEvent[] = []
  const notes = new NoteBook()

  records.forEach((record, position) => {
    const seq = position + 1
    const payload = record.payload
    if (!isPlainObject(payload)) return
    const timestamp = typeof record.timestamp === 'string' ? record.timestamp : null
    const lineType = record.type
    const payloadType = payload.type

    if (lineType === 'session_meta') {
      const sid = payload.session_id || payload.id
      if (typeof sid === 'string' && sid.trim()) meta = replaceMeta(meta, { session_id: sid })
      if (typeof payload.cwd === 'string') meta = replaceMeta(meta, { cwd: payload.cwd })
      if (typeof payload.cli_version === 'string') {
        meta = replaceMeta(meta, { agent_version: payload.cli_version })
      }
      if (meta.started_at === null && typeof payload.timestamp === 'string') {
        meta = replaceMeta(meta, { started_at: payload.timestamp })
      }
      return
    }

    if (payloadType === 'function_call') {
      const name = payload.name
      if (name === 'exec') {
        toolEvents.push(
          Object.freeze({ seq, kind: 'exec', tool_name: 'exec', timestamp, file_path: null }),
        )
      } else {
        toolEvents.push(
          Object.freeze({
            seq,
            kind: 'other',
            tool_name: typeof name === 'string' ? name : 'unknown',
            timestamp,
            file_path: null,
          }),
        )
      }
      return
    }

    if (payloadType === 'custom_tool_call' && payload.name === 'apply_patch') {
      let paths = extractPatchPaths(payload.input)
      if (paths === null) {
        notes.bump(
          'apply_patch_input_missing',
          `第 ${seq} 行：apply_patch 缺 V4A 文本 input，跳过路径提取（K7）`,
        )
        paths = []
      }
      for (const filePath of paths) {
        toolEvents.push(
          Object.freeze({ seq, kind: 'write', tool_name: 'apply_patch', timestamp, file_path: filePath }),
        )
      }
      if (paths.length === 0) {
        // 无可提取路径仍计一次写事件（编辑计数主证据 R5；路径 unknown）
        toolEvents.push(
          Object.freeze({ seq, kind: 'write', tool_name: 'apply_patch', timestamp, file_path: null }),
        )
      }
      return
    }

    if (payloadType === 'event_msg') {
      const tokenPayload = payload.payload
      if (isPlainObject(tokenPayload)) tokenEvents.push(codexUsage(seq, timestamp, tokenPayload))
      return
    }

    notes.bump(
      'unverified_payload_type_skipped',
      `第 ${seq} 行：payload.type=${pyRepr(payloadType)} 未核对不启用（K7）`,
    )
  })

  return Object.freeze({
    meta,
    tool_events: Object.freeze(toolEvents),
    token_events: Object.freeze(tokenEvents),
    notes: Object.freeze(notes.finish()),
    ir_version: IR_VERSION,
  })
}

/**
 * 会话形态判别：显式 `harness` 优先；缺省时按记录形态判别（`message` → claude，
 * `payload` → codex）。未知形态返回 null（上游显式报错，不猜测）。
 */
export function detectHarness(records: readonly Record<string, unknown>[]): Source | null {
  for (const record of records) {
    if (isPlainObject(record.message)) return 'claude'
    if (isPlainObject(record.payload)) return 'codex'
  }
  return null
}