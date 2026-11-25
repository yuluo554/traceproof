/**
 * 会话日志 → 统一事件流（claude / codex 两种形态）。
 *
 * 移植自旧仓 `readers/claude.py` + `readers/codex.py` 的归一规则：
 *
 * - **seq = 源文件行号（1-based）**，不是过滤后的下标；
 * - 只认实测过的容器：Claude 的 `type: user|assistant` + `message.content`，
 *   Codex 的 `record.type == session_meta` 与 `payload.type`；
 * - Codex 的失败判定**只取数值**（`Exit code: N` / `Process exited with code N`），
 *   文本标记命中不算失败；
 * - `apply_patch` 的路径只在 patch 指令行里（`*** Update File:`）；
 * - 不认识的形态显式报 `FormatProblem`（不静默产出空事件流）。
 */

export const UNKNOWN = 'unknown'

export type Source = 'claude' | 'codex'
export type EventKind = 'user_msg' | 'assistant_msg' | 'tool_call' | 'tool_result' | 'meta'

export interface Event {
  readonly source: Source
  readonly session_id: string
  readonly seq: number
  readonly kind: EventKind
  readonly ts: string
  readonly tool: string
  readonly path: string
  readonly payload: Record<string, unknown>
}

export class FormatProblem extends Error {
  readonly missing: string[]
  constructor(message: string, missing: string[] = []) {
    super(message)
    this.name = 'FormatProblem'
    this.missing = missing
  }
}

const CLAUDE_WRITE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit'])
const CODEX_WRITE_TOOLS = new Set(['apply_patch', 'file_change'])
const PROCESS_EXITED = /Process exited with code\s*(-?\d+)/
const EXIT_CODE_LINE = /^Exit code:\s*(-?\d+)\s*$/m

export function isWriteTool(tool: string): boolean {
  return CLAUDE_WRITE_TOOLS.has(tool) || CODEX_WRITE_TOOLS.has(tool)
}

export function detectHarness(records: readonly Record<string, unknown>[]): Source {
  if (records.length === 0) throw new FormatProblem('没有可判别的 JSON 记录', ['message', 'payload'])
  const claude = records.some((record) => 'message' in record)
  const codex = records.some((record) => 'payload' in record)
  if (claude && codex) throw new FormatProblem('窗口内同时命中 claude 与 codex 形态')
  if (claude) return 'claude'
  if (codex) return 'codex'
  throw new FormatProblem('无法判别日志来源：没有已知 harness 的判别键', ['message', 'payload'])
}

function asText(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === 'string') return item
        if (item !== null && typeof item === 'object' && typeof (item as Record<string, unknown>).text === 'string') {
          return String((item as Record<string, unknown>).text)
        }
        return ''
      })
      .join('\n')
  }
  return ''
}

function clip(text: string, limit: number): { text: string; truncated: boolean } {
  if (text.length <= limit) return { text, truncated: false }
  return { text: text.slice(0, limit), truncated: true }
}

function parsePatchTargets(patchText: string): { files: string[]; actions: Record<string, string> } {
  const actionMap: Record<string, string> = {
    'Add File': 'add',
    'Update File': 'update',
    'Delete File': 'delete',
    'Move to': 'move_to',
  }
  const files: string[] = []
  const actions: Record<string, string> = {}
  const directive = /^\*\*\* (Add File|Update File|Delete File|Move to):\s*(.+?)\s*$/gm
  for (const match of patchText.matchAll(directive)) {
    const target = match[2].trim().replace(/^["']|["']$/g, '')
    if (!target) continue
    if (!(target in actions)) files.push(target)
    actions[target] = actionMap[match[1]] ?? 'unknown'
  }
  return { files, actions }
}

export function parseExitCode(text: string): { exit_code: number | null; source: string } {
  const exited = text.match(PROCESS_EXITED)
  if (exited) return { exit_code: Number(exited[1]), source: 'process_exited' }
  const line = text.match(EXIT_CODE_LINE)
  if (line) return { exit_code: Number(line[1]), source: 'exit_code_line' }
  return { exit_code: null, source: UNKNOWN }
}

function claudeEvents(records: readonly Record<string, unknown>[], maxChars: number): Event[] {
  const events: Event[] = []
  const pending = new Map<string, Event>()
  const callNames = new Map<string, string>()
  let sessionId = UNKNOWN

  records.forEach((record, index) => {
    const seq = index + 1
    const type = record.type
    if (type !== 'user' && type !== 'assistant') return
    const message = record.message
    if (message === null || typeof message !== 'object') return
    const messageObject = message as Record<string, unknown>
    const sid = record.sessionId ?? record.session_id
    if (typeof sid === 'string' && sid) sessionId = sid
    const ts = typeof record.timestamp === 'string' ? record.timestamp : UNKNOWN
    const eventSession = sessionId === UNKNOWN ? `line-${seq}` : sessionId
    const content = messageObject.content

    if (typeof content === 'string') {
      const clipped = clip(content, maxChars)
      if (!clipped.text.trim()) return
      events.push({
        source: 'claude',
        session_id: eventSession,
        seq,
        kind: type === 'user' ? 'user_msg' : 'assistant_msg',
        ts,
        tool: UNKNOWN,
        path: UNKNOWN,
        payload: { text: clipped.text, truncated: clipped.truncated },
      })
      return
    }
    if (!Array.isArray(content)) return

    const resultMeta =
      record.toolUseResult !== null && typeof record.toolUseResult === 'object'
        ? (record.toolUseResult as Record<string, unknown>)
        : {}
    for (const block of content) {
      if (block === null || typeof block !== 'object') continue
      const item = block as Record<string, unknown>
      if (item.type === 'tool_use') {
        const input = item.input !== null && typeof item.input === 'object' ? (item.input as Record<string, unknown>) : {}
        const name = typeof item.name === 'string' ? item.name : UNKNOWN
        const id = typeof item.id === 'string' ? item.id : UNKNOWN
        const payload: Record<string, unknown> = {
          tool_use_id: id,
          input_keys: Object.keys(input).sort(),
          command: typeof input.command === 'string' ? input.command : '',
        }
        for (const key of ['old_string', 'new_string', 'content'] as const) {
          if (typeof input[key] === 'string') {
            payload[key] = input[key]
            payload[`has_${key}`] = true
          }
        }
        if (typeof input.replace_all === 'boolean') payload.replace_all = input.replace_all
        const path =
          typeof input.file_path === 'string'
            ? input.file_path
            : typeof input.notebook_path === 'string'
              ? input.notebook_path
              : UNKNOWN
        if (id !== UNKNOWN) callNames.set(id, name)
        const event: Event = { source: 'claude', session_id: eventSession, seq, kind: 'tool_call', ts, tool: name, path, payload }
        events.push(event)
        if (id !== UNKNOWN) pending.set(id, event)
      } else if (item.type === 'text') {
        const text = clip(asText([item]), maxChars)
        if (!text.text.trim()) continue
        events.push({
          source: 'claude',
          session_id: eventSession,
          seq,
          kind: type === 'user' ? 'user_msg' : 'assistant_msg',
          ts,
          tool: UNKNOWN,
          path: UNKNOWN,
          payload: { text: text.text, truncated: text.truncated },
        })
      } else if (item.type === 'tool_result') {
        const id = typeof item.tool_use_id === 'string' ? item.tool_use_id : UNKNOWN
        const text = clip(asText(item.content), maxChars)
        const payload: Record<string, unknown> = {
          tool_use_id: id,
          is_error: item.is_error === true,
          text: text.text,
          truncated: text.truncated,
        }
        events.push({
          source: 'claude',
          session_id: eventSession,
          seq,
          kind: 'tool_result',
          ts,
          tool: callNames.get(id) ?? UNKNOWN,
          path: typeof resultMeta.filePath === 'string' ? resultMeta.filePath : UNKNOWN,
          payload,
        })
        const call = pending.get(id)
        if (call !== undefined) {
          call.payload.result = {
            original_file: typeof resultMeta.originalFile === 'string' ? resultMeta.originalFile : null,
            structured_patch: Array.isArray(resultMeta.structuredPatch) ? resultMeta.structuredPatch : [],
            has_patch_hunks: Array.isArray(resultMeta.structuredPatch) && resultMeta.structuredPatch.length > 0,
          }
        }
      }
    }
  })
  return events
}

function codexEvents(records: readonly Record<string, unknown>[], maxChars: number): Event[] {
  const events: Event[] = []
  const pending = new Map<string, Event>()
  const callNames = new Map<string, string>()
  let sessionId = UNKNOWN

  records.forEach((record, index) => {
    const seq = index + 1
    const payload = record.payload
    if (payload === null || typeof payload !== 'object') return
    const item = payload as Record<string, unknown>
    const ts = typeof record.timestamp === 'string' ? record.timestamp : UNKNOWN
    const sid = item.session_id ?? item.id
    if (record.type === 'session_meta' && typeof sid === 'string' && sid) sessionId = sid
    const eventSession = sessionId === UNKNOWN ? `line-${seq}` : sessionId

    if (record.type === 'session_meta') {
      events.push({
        source: 'codex',
        session_id: eventSession,
        seq,
        kind: 'meta',
        ts,
        tool: UNKNOWN,
        path: UNKNOWN,
        payload: { kind: 'session_meta' },
      })
      return
    }

    const payloadType = item.type
    if (payloadType === 'message') {
      const role = typeof item.role === 'string' ? item.role : UNKNOWN
      const text = clip(asText(item.content), maxChars)
      const kind: EventKind = role === 'user' ? 'user_msg' : role === 'assistant' ? 'assistant_msg' : 'meta'
      events.push({ source: 'codex', session_id: eventSession, seq, kind, ts, tool: UNKNOWN, path: UNKNOWN, payload: { role, text: text.text, truncated: text.truncated } })
      return
    }
    if (payloadType === 'function_call') {
      const name = typeof item.name === 'string' ? item.name : UNKNOWN
      let args: Record<string, unknown> = {}
      if (item.arguments !== null && typeof item.arguments === 'object') args = item.arguments as Record<string, unknown>
      else if (typeof item.arguments === 'string') {
        try {
          const parsed = JSON.parse(item.arguments)
          if (parsed !== null && typeof parsed === 'object') args = parsed as Record<string, unknown>
        } catch {
          args = {}
        }
      }
      const command = typeof args.command === 'string' ? args.command : typeof args.cmd === 'string' ? args.cmd : ''
      const callId = typeof item.call_id === 'string' ? item.call_id : UNKNOWN
      if (callId !== UNKNOWN) callNames.set(callId, name)
      const event: Event = {
        source: 'codex',
        session_id: eventSession,
        seq,
        kind: 'tool_call',
        ts,
        tool: name,
        path: UNKNOWN,
        payload: { call_id: callId, command: clip(command, maxChars).text, has_command: Boolean(command) },
      }
      events.push(event)
      if (callId !== UNKNOWN) pending.set(callId, event)
      return
    }
    if (payloadType === 'custom_tool_call') {
      const name = typeof item.name === 'string' ? item.name : UNKNOWN
      const raw = typeof item.input === 'string' ? item.input : ''
      const callId = typeof item.call_id === 'string' ? item.call_id : UNKNOWN
      const targets = raw.includes('*** Begin Patch') ? parsePatchTargets(raw) : { files: [], actions: {} }
      if (callId !== UNKNOWN) callNames.set(callId, name)
      const event: Event = {
        source: 'codex',
        session_id: eventSession,
        seq,
        kind: 'tool_call',
        ts,
        tool: name,
        path: targets.files[0] ?? UNKNOWN,
        payload: { call_id: callId, input: raw, has_input: Boolean(raw), files: targets.files, file_actions: targets.actions },
      }
      events.push(event)
      if (callId !== UNKNOWN) pending.set(callId, event)
      return
    }
    if (payloadType === 'function_call_output' || payloadType === 'custom_tool_call_output') {
      const output =
        typeof item.output === 'string'
          ? item.output
          : item.output === undefined || item.output === null
            ? ''
            : JSON.stringify(item.output)
      const clipped = clip(output, maxChars)
      const callId = typeof item.call_id === 'string' ? item.call_id : UNKNOWN
      const parsed = parseExitCode(output)
      const event: Event = {
        source: 'codex',
        session_id: eventSession,
        seq,
        kind: 'tool_result',
        ts,
        tool: callNames.get(callId) ?? UNKNOWN,
        path: UNKNOWN,
        payload: { call_id: callId, text: clipped.text, truncated: clipped.truncated, exit_code: parsed.exit_code, exit_code_source: parsed.source },
      }
      events.push(event)
      const call = pending.get(callId)
      if (call !== undefined) call.payload.result_text = output
      return
    }
    if (payloadType === 'item_completed') {
      const completed = item.item
      if (completed === null || typeof completed !== 'object') return
      const entry = completed as Record<string, unknown>
      if (entry.type !== 'FileChange') return
      const changes = entry.changes
      const files: Record<string, { unified_diff?: string; content?: string }> = {}
      if (changes !== null && typeof changes === 'object') {
        for (const [path, change] of Object.entries(changes as Record<string, unknown>)) {
          if (change === null || typeof change !== 'object') continue
          const detail = change as Record<string, unknown>
          const recordOut: { unified_diff?: string; content?: string } = {}
          if (typeof detail.unified_diff === 'string') recordOut.unified_diff = detail.unified_diff
          if (typeof detail.content === 'string') recordOut.content = detail.content
          files[path] = recordOut
        }
      }
      const first = Object.keys(files).sort()[0] ?? UNKNOWN
      const event: Event = {
        source: 'codex',
        session_id: eventSession,
        seq,
        kind: 'tool_result',
        ts,
        tool: 'file_change',
        path: first,
        payload: { files, files_count: Object.keys(files).length },
      }
      events.push(event)
      // 把结构化变更贴到最近一条 apply_patch 调用上（供还原层取 unified_diff）
      const writeCalls = [...pending.values()].filter((candidate) => candidate.tool === 'apply_patch')
      const last = writeCalls[writeCalls.length - 1]
      if (last !== undefined) last.payload.result = { files }
      return
    }
  })
  return events
}

export function normalizeSession(
  harness: Source | null,
  records: readonly Record<string, unknown>[],
  maxChars = 4000,
): Event[] {
  const source = harness ?? detectHarness(records)
  return source === 'claude' ? claudeEvents(records, maxChars) : codexEvents(records, maxChars)
}