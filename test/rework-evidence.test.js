/**
 * rework-evidence 器官的无损测试。
 *
 * 数据面：源仓 `data/synthetic/samples/` 的 12 个冻结样例（只读拷贝到
 * `test/fixtures/rework-evidence/samples/`，不做任何改写）。判定层对齐：
 *  - IR：Claude / Codex 双源解析、token 用量、ParseNote（坏行/未核对字段/快照容错）；
 *  - rework：版本链计数 + 编辑计数三态判定（rework / not_rework / insufficient_data）；
 *  - metrics：Read:Edit 比、符号提取、5 步归一化、difflib ratio、粗匹配候选；
 *  - 器官契约：4 类 claim、verdict 映射、痕迹节点、确定性、CLI 退出码。
 *
 * 判据 1 的 X = 源仓判定层（D1+D18 机械选 10 个文件）`pytest` 实跑 102 passed；
 * 本文件 `test(` 调用数与实跑用例数均 ≥ 102（旧层 AST 函数 69 同样覆盖）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { main } from '../lib/traceproof/cli.js'
import {
  CLAIM,
  ContractError,
  EXIT_BLOCKED,
  EXIT_CONTRACT,
  EXIT_INPUT,
  EXIT_OK,
  INCONCLUSIVE,
  REFUTED,
} from '../lib/traceproof/core/ledger.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  DEFAULTS,
  DUP_DISCLOSURE,
  DUP_MATCH_THRESHOLD,
  READ_EVENT_KINDS,
  REWORK_MIN_EDITS,
  REWORK_MIN_VERSIONS,
  SUPPORTED_SYMBOL_LANGUAGES,
  SYMBOL_LANGUAGE_BY_SUFFIX,
  SYMBOL_PREFIX_TOKENS,
  SYMBOL_SUFFIX_TOKENS,
  WRITE_EVENT_KINDS,
} from '../lib/traceproof/verbs/rework-evidence/defaults.js'
import {
  IR_VERSION,
  KINDS,
  detectHarness,
  extractPatchPaths,
  parseClaudeSession,
  parseCodexSession,
  readSnapshotFileMap,
} from '../lib/traceproof/verbs/rework-evidence/parse.js'
import {
  REASON_CHAIN_MISSING,
  REASON_EDITS,
  REASON_NO_HIT,
  REASON_VERSIONS,
  VERDICT_INSUFFICIENT,
  VERDICT_NOT_REWORK,
  VERDICT_REWORK,
  analyzeRework,
} from '../lib/traceproof/verbs/rework-evidence/rework.js'
import {
  computeReadEditRatio,
  computeSessionMetrics,
  countReadWrite,
  existingSymbolsFromReads,
  extractDefinedSymbols,
  findDupCandidates,
  isSupportedLanguage,
  matchSymbols,
  normalizeSymbolName,
  resolveProjectFile,
  sequenceRatio,
  symbolsFromWritePayloads,
  writePayloadsFromRecords,
} from '../lib/traceproof/verbs/rework-evidence/metrics.js'
import {
  ASSERTED_VALUES,
  CHECKS,
  VERSION,
  evaluate,
  reworkEvidenceVerb,
} from '../lib/traceproof/verbs/rework-evidence/index.js'

await loadBuiltin()

const FIXTURES = fileURLToPath(new URL('./fixtures/rework-evidence/samples/', import.meta.url))
const PRODUCT_ROOT = fileURLToPath(new URL('..', import.meta.url))
const AT = String.fromCharCode(64)
const NODE = { session_id: 's-rework-1', turn: 2, tool_call_id: 'call-rework-2' }

function basisOf(nodes = [NODE]) {
  return Basis.fromObject({ version: '2026.11.25', nodes })
}

function runOrgan(subject, basis = basisOf()) {
  return [...evaluate(subject, basis)]
}

function readJSON(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function readRecords(path) {
  return readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line))
}

function versionChainsOf(dir, sessionId) {
  const chains = {}
  const history = join(dir, 'file-history', sessionId)
  if (!existsSync(history)) return chains
  for (const name of readdirSync(history)) {
    const match = name.match(/@v(\d+)(?:\.[^@\\/]*)?$/)
    if (match === null) continue
    const stem = name.slice(0, match.index)
    if (chains[stem] === undefined) chains[stem] = { versions: [] }
    chains[stem].versions.push(Number(match[1]))
  }
  return chains
}

function projectFilesOf(dir) {
  const files = {}
  const project = join(dir, 'project')
  if (!existsSync(project)) return files
  for (const name of readdirSync(project)) {
    files[`/demo/alpha/src/${name}`] = readFileSync(join(project, name), 'utf8')
  }
  return files
}

function caseData(caseId) {
  const dir = join(FIXTURES, caseId)
  const truth = readJSON(join(dir, 'truth.json'))
  return {
    dir,
    truth,
    records: readRecords(join(dir, 'session.jsonl')),
    version_chains: versionChainsOf(dir, truth.session_id),
    project_files: projectFilesOf(dir),
  }
}

function caseSubject(caseId, claims, options = {}) {
  const data = caseData(caseId)
  const subject = {
    session: {
      harness: data.truth.source === 'codex' ? 'codex' : 'claude',
      source_file: `sessions/${data.truth.session_id}/session.jsonl`,
      records: data.records,
    },
    version_chains: data.version_chains,
    claims,
  }
  if (options.withProject !== false) subject.project_files = data.project_files
  return { subject, data }
}

function truthClaims(caseId, data) {
  const claims = []
  for (const item of data.truth.expected_rework) {
    const observed = data.truth.also_expect?.[item.file] ?? {}
    claims.push({
      claim_id: `rework:${item.file}`,
      check: 'rework',
      asserted: 'rework',
      file: item.file,
      expected_edits: item.edit_count,
      ...('version_chain_observed' in observed ? { expected_versions: observed.version_chain_observed } : {}),
      node: NODE,
    })
  }
  for (const item of data.truth.expected_normal) {
    claims.push({
      claim_id: `normal:${item.file}`,
      check: 'rework',
      asserted: 'not_rework',
      file: item.file,
      expected_edits: item.edit_count,
      node: NODE,
    })
  }
  if (data.truth.case_type === 'missing_chain') {
    claims.push({
      claim_id: 'missing-chain',
      check: 'rework',
      asserted: 'insufficient_data',
      file: '/demo/beta/src/alpha_b.py',
      node: NODE,
    })
  }
  for (const [index, candidate] of data.truth.expected_dup_candidates.entries()) {
    claims.push({
      claim_id: `dup:${index}`,
      check: 'duplicate-candidate',
      asserted: 'present',
      new_symbol: candidate.new_symbol,
      existing_symbol: candidate.existing_symbol,
      node: NODE,
    })
  }
  if (claims.length === 0) {
    const ir = parseClaudeSession(data.records, 's.jsonl')
    const write = ir.tool_events.find((event) => event.kind === 'write' || event.kind === 'edit')
    assert.ok(write, `${caseId} 应有写事件`)
    claims.push({
      claim_id: 'case-write',
      check: 'rework',
      asserted: 'not_rework',
      file: write.file_path,
      node: NODE,
    })
  }
  return claims
}

function assertCaseTruth(caseId) {
  const data = caseData(caseId)
  const { subject } = caseSubject(caseId, truthClaims(caseId, data))
  const records = runOrgan(subject)
  const failed = records.filter((record) => record.verdict !== CLAIM)
  assert.deepEqual(
    failed.map((record) => ({ id: record.id, verdict: record.verdict, message: record.message })),
    [],
  )
  return records
}

function toolEvent(seq, kind, filePath = null, timestamp = null, toolName = kind) {
  return { seq, kind, tool_name: toolName, timestamp, file_path: filePath }
}

// ===========================================================================
// 1. 口径数据（源仓 config.py 单点）
// ===========================================================================

test('defaults: thresholds keep source values (versions=3 / edits=3 / dup=0.9)', () => {
  assert.equal(REWORK_MIN_VERSIONS, 3)
  assert.equal(REWORK_MIN_EDITS, 3)
  assert.equal(DUP_MATCH_THRESHOLD, 0.9)
  assert.equal(DEFAULTS.thresholds.rework_min_versions, 3)
  assert.equal(DEFAULTS.thresholds.rework_min_edits, 3)
  assert.equal(DEFAULTS.thresholds.dup_match_threshold, 0.9)
})

test('defaults: read/write kind sets are non-empty and disjoint', () => {
  assert.deepEqual([...READ_EVENT_KINDS], ['read'])
  assert.deepEqual([...WRITE_EVENT_KINDS], ['edit', 'multiedit', 'write'])
  assert.equal([...READ_EVENT_KINDS].some((kind) => WRITE_EVENT_KINDS.has(kind)), false)
})

test('defaults: symbol token sets and language map keep source vocabulary', () => {
  assert.deepEqual([...SYMBOL_PREFIX_TOKENS].sort(), ['build', 'create', 'do', 'fetch', 'get', 'handle', 'make', 'set', 'try'])
  assert.deepEqual([...SYMBOL_SUFFIX_TOKENS].sort(), ['fn', 'func', 'helper', 'impl', 'util', 'utils', 'wrapper'])
  assert.deepEqual([...SUPPORTED_SYMBOL_LANGUAGES], ['python'])
  assert.equal(SYMBOL_LANGUAGE_BY_SUFFIX['.py'], 'python')
})

test('defaults: disclosure text is present and non-verdict wording', () => {
  assert.ok(DUP_DISCLOSURE.length > 0)
  assert.match(DUP_DISCLOSURE, /粗匹配/)
  assert.match(DUP_DISCLOSURE, /人工复核/)
})

test('defaults: nested defaults are frozen (callers cannot mutate thresholds)', () => {
  assert.equal(Object.isFrozen(DEFAULTS), true)
  assert.equal(Object.isFrozen(DEFAULTS.thresholds), true)
  assert.equal(Object.isFrozen(DEFAULTS.symbol_language_by_suffix), true)
})

// ===========================================================================
// 2. Claude 解析 → IR
// ===========================================================================

test('parse: kind registry is locked to source IR v1', () => {
  assert.deepEqual([...KINDS], ['read', 'edit', 'write', 'multiedit', 'exec', 'other'])
  assert.equal(IR_VERSION, 1)
})

test('parse claude: session meta absorbed from meta-like line', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'session_meta_like',
        sessionId: 's-meta',
        timestamp: '2026-01-01T00:00:00.000Z',
        cwd: '/demo/alpha',
        version: 'agent-1.0',
      },
    ],
    'sessions/s.jsonl',
  )
  assert.equal(ir.meta.source, 'claude')
  assert.equal(ir.meta.session_id, 's-meta')
  assert.equal(ir.meta.cwd, '/demo/alpha')
  assert.equal(ir.meta.started_at, '2026-01-01T00:00:00.000Z')
  assert.equal(ir.meta.agent_version, 'agent-1.0')
  assert.equal(ir.meta.source_file, 'sessions/s.jsonl')
  assert.equal(ir.ir_version, 1)
})

test('parse claude: tool names map to kinds including MultiEdit downgrade', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'assistant',
        message: {
          role: 'assistant',
          content: [
            { type: 'tool_use', name: 'Read', input: { file_path: '/a.py' } },
            { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
            { type: 'tool_use', name: 'Write', input: { file_path: '/a.py' } },
            { type: 'tool_use', name: 'MultiEdit', input: { file_path: '/a.py' } },
            { type: 'tool_use', name: 'Bash', input: { command: 'ls' } },
            { type: 'tool_use', name: 'TaskCreate', input: {} },
          ],
        },
      },
    ],
    's.jsonl',
  )
  assert.deepEqual(
    ir.tool_events.map((event) => event.kind),
    ['read', 'edit', 'write', 'edit', 'exec', 'other'],
  )
  assert.ok(ir.notes.some((note) => note.code === 'multiedit_downgraded'))
})

test('parse claude: non-string file_path becomes null (not guessed)', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'assistant',
        message: {
          role: 'assistant',
          content: [{ type: 'tool_use', name: 'Edit', input: { file_path: 42 } }],
        },
      },
    ],
    's.jsonl',
  )
  assert.equal(ir.tool_events.length, 1)
  assert.equal(ir.tool_events[0].file_path, null)
})

test('parse claude: tool_use without name/input is skipped with a note', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'assistant',
        message: {
          role: 'assistant',
          content: [
            { type: 'tool_use', input: { file_path: '/a.py' } },
            { type: 'tool_use', name: 'Edit', input: 'not-an-object' },
          ],
        },
      },
    ],
    's.jsonl',
  )
  assert.equal(ir.tool_events.length, 0)
  const note = ir.notes.find((item) => item.code === 'unverified_field_skipped')
  assert.equal(note.count, 2)
  assert.match(note.message, /第 1 行/)
})

test('parse claude: user tool_result blocks are not tool events', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'user',
        message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'c1', content: 'ok' }] },
      },
    ],
    's.jsonl',
  )
  assert.deepEqual(ir.tool_events, [])
})

test('parse claude: non-message line absorbs meta but yields no events', () => {
  const ir = parseClaudeSession(
    [{ type: 'summary', sessionId: 's-sum', timestamp: '2026-01-01T00:00:00Z', cwd: '/demo' }],
    's.jsonl',
  )
  assert.equal(ir.meta.session_id, 's-sum')
  assert.equal(ir.meta.cwd, '/demo')
  assert.deepEqual(ir.tool_events, [])
})

test('parse claude: usage yields token event with summed total', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'assistant',
        timestamp: '2026-01-01T00:00:01Z',
        message: {
          role: 'assistant',
          content: [],
          usage: {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: 2,
            cache_read_input_tokens: 3,
          },
        },
      },
    ],
    's.jsonl',
  )
  assert.equal(ir.token_events.length, 1)
  assert.deepEqual(
    { ...ir.token_events[0] },
    {
      seq: 1,
      timestamp: '2026-01-01T00:00:01Z',
      input_tokens: 10,
      output_tokens: 5,
      cache_creation_input_tokens: 2,
      cache_read_input_tokens: 3,
      total_tokens: 15,
    },
  )
})

test('parse claude: missing output tokens leaves total null', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'assistant',
        message: { role: 'assistant', content: [], usage: { input_tokens: 10 } },
      },
    ],
    's.jsonl',
  )
  assert.equal(ir.token_events[0].total_tokens, null)
  assert.equal(ir.token_events[0].output_tokens, null)
})

test('parse claude: non-object usage yields no token event', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'assistant',
        message: { role: 'assistant', content: [], usage: 'n/a' },
      },
    ],
    's.jsonl',
  )
  assert.deepEqual(ir.token_events, [])
})

test('parse claude: non-array content is ignored safely', () => {
  const ir = parseClaudeSession(
    [{ type: 'assistant', message: { role: 'assistant', content: 'plain text' } }],
    's.jsonl',
  )
  assert.deepEqual(ir.tool_events, [])
})

test('parse claude: snapshot null entry and shape problems become notes', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'file-history-snapshot',
        snapshot: {
          trackedFileBackups: {
            '/a.py': null,
            '/b.py': 'not-an-object',
            '/c.py': { backupFileName: 'h@v1', version: 1, backupTime: 't', realParentDir: '/' },
          },
        },
      },
    ],
    's.jsonl',
  )
  const codes = Object.fromEntries(ir.notes.map((note) => [note.code, note.count]))
  assert.equal(codes.snapshot_entry_null, 1)
  assert.equal(codes.snapshot_entry_shape, 1)
  assert.equal(codes.snapshot_entry_extra_field, undefined)
})

test('parse claude: unknown snapshot entry fields are noted in sorted order', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'file-history-snapshot',
        snapshot: {
          trackedFileBackups: {
            '/a.py': {
              backupFileName: 'h@v2',
              version: 2,
              backupTime: 't',
              realParentDir: '/',
              zeta: 1,
              alpha: 2,
            },
          },
        },
      },
    ],
    's.jsonl',
  )
  const note = ir.notes.find((item) => item.code === 'snapshot_entry_extra_field')
  assert.ok(note)
  assert.match(note.message, /alpha,zeta/)
})

test('parse claude: snapshot map keeps max version and strips extension form', () => {
  const records = [
    {
      type: 'file-history-snapshot',
      snapshot: {
        trackedFileBackups: { '/a.py': { backupFileName: `stem${AT}v1.py`, version: 1 } },
      },
    },
    {
      type: 'file-history-snapshot',
      snapshot: {
        trackedFileBackups: { '/a.py': { backupFileName: 'stem@v4', version: 4 } },
      },
    },
    {
      type: 'file-history-snapshot',
      snapshot: {
        trackedFileBackups: { '/a.py': { backupFileName: 'stem@v2', version: 2 } },
      },
    },
  ]
  const map = readSnapshotFileMap(records)
  assert.equal(map['/a.py'].backup_stem, 'stem')
  assert.equal(map['/a.py'].max_version, 4)
})

test('parse claude: snapshot backupFileName without @vN is unusable (skipped)', () => {
  const map = readSnapshotFileMap([
    {
      type: 'file-history-snapshot',
      snapshot: { trackedFileBackups: { '/a.py': { backupFileName: 'plain', version: 9 } } },
    },
  ])
  assert.deepEqual(map, {})
})

test('parse claude: repeated snapshot null entries aggregate count', () => {
  const ir = parseClaudeSession(
    [
      {
        type: 'file-history-snapshot',
        snapshot: { trackedFileBackups: { '/a.py': null, '/b.py': null } },
      },
    ],
    's.jsonl',
  )
  assert.equal(ir.notes.find((note) => note.code === 'snapshot_entry_null').count, 2)
})

// ===========================================================================
// 3. Codex 解析 → IR
// ===========================================================================

test('parse codex: session_meta fills id/cwd/version/started', () => {
  const ir = parseCodexSession(
    [
      {
        type: 'session_meta',
        payload: {
          session_id: 's-codex',
          id: 'ignored-id',
          cwd: '/demo/beta',
          cli_version: '0.1.0',
          timestamp: '2026-01-01T00:00:00Z',
        },
      },
    ],
    'codex.jsonl',
  )
  assert.equal(ir.meta.source, 'codex')
  assert.equal(ir.meta.session_id, 's-codex')
  assert.equal(ir.meta.cwd, '/demo/beta')
  assert.equal(ir.meta.agent_version, '0.1.0')
  assert.equal(ir.meta.started_at, '2026-01-01T00:00:00Z')
})

test('parse codex: empty session_id falls back to payload.id', () => {
  const ir = parseCodexSession(
    [{ type: 'session_meta', payload: { session_id: '', id: 'fallback-id' } }],
    'c.jsonl',
  )
  assert.equal(ir.meta.session_id, 'fallback-id')
})

test('parse codex: function_call exec becomes exec event', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'function_call', name: 'exec' } }],
    'c.jsonl',
  )
  assert.equal(ir.tool_events.length, 1)
  assert.equal(ir.tool_events[0].kind, 'exec')
})

test('parse codex: other function_call becomes other with tool name', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'function_call', name: 'browser' } }],
    'c.jsonl',
  )
  assert.equal(ir.tool_events[0].kind, 'other')
  assert.equal(ir.tool_events[0].tool_name, 'browser')
})

test('parse codex: non-string function name becomes unknown', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'function_call', name: 7 } }],
    'c.jsonl',
  )
  assert.equal(ir.tool_events[0].tool_name, 'unknown')
})

test('parse codex: apply_patch extracts V4A Update/Add paths in order', () => {
  const input = [
    '*** Begin Patch',
    '*** Update File: /demo/a.py',
    '@@',
    '-x',
    '+y',
    '*** Add File: /demo/b.py',
    '+new',
    '*** End Patch',
  ].join('\n')
  assert.deepEqual(extractPatchPaths(input), ['/demo/a.py', '/demo/b.py'])
})

test('parse codex: apply_patch without input notes and still counts one write', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'custom_tool_call', name: 'apply_patch' } }],
    'c.jsonl',
  )
  assert.equal(ir.tool_events.length, 1)
  assert.equal(ir.tool_events[0].kind, 'write')
  assert.equal(ir.tool_events[0].file_path, null)
  assert.ok(ir.notes.some((note) => note.code === 'apply_patch_input_missing'))
})

test('parse codex: apply_patch with non-string input notes and counts one write', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'custom_tool_call', name: 'apply_patch', input: 42 } }],
    'c.jsonl',
  )
  assert.equal(ir.tool_events.length, 1)
  assert.ok(ir.notes.some((note) => note.code === 'apply_patch_input_missing'))
})

test('parse codex: apply_patch with no file directive counts an unknown-path write', () => {
  const ir = parseCodexSession(
    [
      {
        type: 'response_item',
        payload: { type: 'custom_tool_call', name: 'apply_patch', input: '*** Begin Patch\n*** End Patch' },
      },
    ],
    'c.jsonl',
  )
  assert.equal(ir.tool_events.length, 1)
  assert.equal(ir.tool_events[0].file_path, null)
  assert.equal(ir.notes.length, 0)
})

test('parse codex: event_msg token usage uses declared total', () => {
  const ir = parseCodexSession(
    [
      {
        type: 'response_item',
        timestamp: '2026-01-01T00:00:01Z',
        payload: {
          type: 'event_msg',
          payload: { input_tokens: 10, output_tokens: 2, total_token_counts: 50, input_tokens_cached: 4 },
        },
      },
    ],
    'c.jsonl',
  )
  assert.equal(ir.token_events.length, 1)
  assert.equal(ir.token_events[0].total_tokens, 50)
  assert.equal(ir.token_events[0].cache_read_input_tokens, 4)
  assert.equal(ir.token_events[0].timestamp, '2026-01-01T00:00:01Z')
})

test('parse codex: declared zero total falls back to input+output', () => {
  const ir = parseCodexSession(
    [
      {
        type: 'response_item',
        payload: { type: 'event_msg', payload: { input_tokens: 10, output_tokens: 2, total_token_counts: 0 } },
      },
    ],
    'c.jsonl',
  )
  assert.equal(ir.token_events[0].total_tokens, 12)
})

test('parse codex: event_msg with non-object payload yields no token event', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'event_msg', payload: 'n/a' } }],
    'c.jsonl',
  )
  assert.deepEqual(ir.token_events, [])
})

test('parse codex: unverified payload type is noted with repr', () => {
  const ir = parseCodexSession(
    [{ type: 'response_item', payload: { type: 'reasoning' } }],
    'c.jsonl',
  )
  const note = ir.notes.find((item) => item.code === 'unverified_payload_type_skipped')
  assert.ok(note)
  assert.match(note.message, /payload\.type='reasoning'/)
  assert.deepEqual(ir.tool_events, [])
})

test('parse codex: lines without payload object are ignored', () => {
  const ir = parseCodexSession([{ type: 'response_item' }, {}], 'c.jsonl')
  assert.deepEqual(ir.tool_events, [])
  assert.deepEqual(ir.notes, [])
})

test('parse: harness detection prefers message vs payload shape', () => {
  assert.equal(detectHarness([{ message: { role: 'user' } }]), 'claude')
  assert.equal(detectHarness([{ payload: { type: 'session_meta' } }]), 'codex')
  assert.equal(detectHarness([{ type: 'summary' }, {}]), null)
})

// ===========================================================================
// 4. 返工判定
// ===========================================================================

function claudeEdit(seq, file, timestamp = null) {
  return toolEvent(seq, 'edit', file, timestamp, 'Edit')
}

function claudeWrite(seq, file, timestamp = null) {
  return toolEvent(seq, 'write', file, timestamp, 'Write')
}

function irOf(events, notes = [], sessionId = 's-1') {
  return {
    meta: {
      source: 'claude',
      session_id: sessionId,
      cwd: null,
      started_at: null,
      source_file: 's.jsonl',
      agent_version: null,
    },
    tool_events: events,
    token_events: [],
    notes,
    ir_version: 1,
  }
}

test('rework: three versions hits even with one edit', () => {
  const findings = analyzeRework(irOf([claudeEdit(4, '/a.py')]), new Map([['stem', [1, 2, 3]]]), {
    '/a.py': { backup_stem: 'stem', max_version: 3 },
  })
  assert.equal(findings.length, 1)
  assert.equal(findings[0].verdict, VERDICT_REWORK)
  assert.deepEqual([...findings[0].reasons], [REASON_VERSIONS])
  assert.equal(findings[0].version_count, 3)
})

test('rework: three edits hits even without a version chain', () => {
  const findings = analyzeRework(
    irOf([claudeEdit(1, '/a.py'), claudeEdit(2, '/a.py'), claudeEdit(3, '/a.py')]),
    new Map(),
    {},
  )
  assert.equal(findings[0].verdict, VERDICT_REWORK)
  assert.deepEqual([...findings[0].reasons], [REASON_EDITS])
  assert.equal(findings[0].version_count, null)
})

test('rework: exact threshold (2 versions / 2 edits) is not a hit', () => {
  const findings = analyzeRework(irOf([claudeEdit(1, '/a.py'), claudeEdit(2, '/a.py')]), new Map([['s', [1, 2]]]), {
    '/a.py': { backup_stem: 's', max_version: 2 },
  })
  assert.equal(findings[0].verdict, VERDICT_NOT_REWORK)
  assert.deepEqual([...findings[0].reasons], [REASON_NO_HIT])
})

test('rework: single write with no chain is not_rework (first write is not backed up)', () => {
  const findings = analyzeRework(irOf([claudeWrite(1, '/a.py')]), new Map(), {})
  assert.equal(findings[0].verdict, VERDICT_NOT_REWORK)
  assert.equal(findings[0].version_count, null)
  assert.deepEqual([...findings[0].reasons], [REASON_NO_HIT])
})

test('rework: edit-only with missing chain is insufficient_data (K4 no inference)', () => {
  const findings = analyzeRework(irOf([claudeEdit(1, '/a.py')]), new Map(), {})
  assert.equal(findings[0].verdict, VERDICT_INSUFFICIENT)
  assert.equal(findings[0].version_count, null)
  assert.deepEqual([...findings[0].reasons], [REASON_CHAIN_MISSING])
})

test('rework: write+edit with missing chain is not_rework, not insufficient', () => {
  const findings = analyzeRework(irOf([claudeWrite(1, '/a.py'), claudeEdit(2, '/a.py')]), new Map(), {})
  assert.equal(findings[0].verdict, VERDICT_NOT_REWORK)
  assert.deepEqual([...findings[0].reasons], [REASON_NO_HIT])
})

test('rework: snapshot maps to a stem absent from chains → version_count null', () => {
  const findings = analyzeRework(irOf([claudeEdit(1, '/a.py')]), new Map(), {
    '/a.py': { backup_stem: 'other', max_version: 3 },
  })
  assert.equal(findings[0].version_count, null)
  assert.equal(findings[0].verdict, VERDICT_INSUFFICIENT)
})

test('rework: file absent from snapshot map → version_count null', () => {
  const findings = analyzeRework(irOf([claudeWrite(1, '/a.py')]), new Map([['stem', [1, 2, 3]]]), {})
  assert.equal(findings[0].version_count, null)
})

test('rework: chain length counts versions, not the max version number', () => {
  const findings = analyzeRework(irOf([claudeEdit(1, '/a.py')]), new Map([['s', [2, 7]]]), {
    '/a.py': { backup_stem: 's', max_version: 7 },
  })
  assert.equal(findings[0].version_count, 2)
  assert.equal(findings[0].verdict, VERDICT_NOT_REWORK)
})

test('rework: multiple files are reported in sorted path order', () => {
  const findings = analyzeRework(
    irOf([claudeEdit(1, '/z.py'), claudeEdit(2, '/a.py'), claudeEdit(3, '/m.py')]),
    new Map(),
    {},
  )
  assert.deepEqual(findings.map((item) => item.file_path), ['/a.py', '/m.py', '/z.py'])
})

test('rework: writes without file_path are skipped (cannot attribute evidence)', () => {
  const findings = analyzeRework(irOf([claudeEdit(1, null), claudeWrite(2, null)]), new Map(), {})
  assert.deepEqual(findings, [])
})

test('rework: read/exec/other events do not count as writes', () => {
  const findings = analyzeRework(
    irOf([
      toolEvent(1, 'read', '/a.py'),
      toolEvent(2, 'exec', '/a.py'),
      toolEvent(3, 'other', '/a.py'),
      claudeEdit(4, '/a.py'),
    ]),
    new Map(),
    {},
  )
  assert.equal(findings[0].edit_count, 1)
  assert.equal(findings[0].first_edit_seq, 4)
})

test('rework: span uses min/max timestamps in seconds', () => {
  const findings = analyzeRework(
    irOf([
      claudeEdit(1, '/a.py', '2026-01-01T00:00:00Z'),
      claudeEdit(2, '/a.py', '2026-01-01T00:10:00Z'),
      claudeEdit(3, '/a.py', '2026-01-01T00:20:00Z'),
    ]),
    new Map(),
    {},
  )
  assert.equal(findings[0].span_seconds, 1200)
})

test('rework: fewer than two timestamps leaves span null', () => {
  const findings = analyzeRework(
    irOf([claudeEdit(1, '/a.py', '2026-01-01T00:00:00Z'), claudeEdit(2, '/a.py')]),
    new Map(),
    {},
  )
  assert.equal(findings[0].span_seconds, null)
})

test('rework: evidence anchors keep source_file:seq and stem@vN', () => {
  const findings = analyzeRework(irOf([claudeEdit(4, '/a.py')]), new Map([['stem', [1, 2, 3]]]), {
    '/a.py': { backup_stem: 'stem', max_version: 3 },
  })
  assert.deepEqual([...findings[0].evidence], ['s.jsonl:4', 'stem@v3'])
})

test('rework: first/last edit seq cover all write events', () => {
  const findings = analyzeRework(
    irOf([claudeEdit(4, '/a.py'), claudeWrite(7, '/a.py'), claudeEdit(10, '/a.py')]),
    new Map(),
    {},
  )
  assert.equal(findings[0].edit_count, 3)
  assert.equal(findings[0].first_edit_seq, 4)
  assert.equal(findings[0].last_edit_seq, 10)
})

test('rework: both criteria satisfied reports both reasons in frozen order', () => {
  const findings = analyzeRework(
    irOf([claudeEdit(1, '/a.py'), claudeEdit(2, '/a.py'), claudeEdit(3, '/a.py')]),
    new Map([['s', [1, 2, 3]]]),
    { '/a.py': { backup_stem: 's', max_version: 3 } },
  )
  assert.deepEqual([...findings[0].reasons], [REASON_VERSIONS, REASON_EDITS])
})

test('rework: files are judged independently', () => {
  const findings = analyzeRework(
    irOf([
      claudeEdit(1, '/hit.py'),
      claudeEdit(2, '/hit.py'),
      claudeEdit(3, '/hit.py'),
      claudeEdit(4, '/miss.py'),
    ]),
    new Map(),
    {},
  )
  assert.equal(findings.find((item) => item.file_path === '/hit.py').verdict, VERDICT_REWORK)
  assert.equal(findings.find((item) => item.file_path === '/miss.py').verdict, VERDICT_INSUFFICIENT)
})

test('rework: session id is propagated to findings', () => {
  const findings = analyzeRework(irOf([claudeEdit(1, '/a.py')], [], 'sess-42'), new Map(), {})
  assert.equal(findings[0].session_id, 'sess-42')
})

test('rework: empty session yields no findings', () => {
  assert.deepEqual(analyzeRework(irOf([]), new Map(), {}), [])
})

// ===========================================================================
// 5. 指标 / 符号 / 粗匹配
// ===========================================================================

test('metrics: countReadWrite uses configured kind sets', () => {
  assert.deepEqual(
    countReadWrite([
      toolEvent(1, 'read'),
      toolEvent(2, 'read'),
      toolEvent(3, 'edit'),
      toolEvent(4, 'write'),
      toolEvent(5, 'exec'),
      toolEvent(6, 'other'),
    ]),
    [2, 2],
  )
})

test('metrics: ratio is undefined when writes are zero', () => {
  assert.equal(computeReadEditRatio(5, 0), null)
  assert.equal(computeReadEditRatio(0, 0), null)
})

test('metrics: ratio keeps numeric value and zero-read case', () => {
  assert.equal(computeReadEditRatio(10, 4), 2.5)
  assert.equal(computeReadEditRatio(0, 2), 0)
})

test('metrics: writes_by_kind is sorted and omits zero kinds', () => {
  const metrics = computeSessionMetrics('s', [
    toolEvent(1, 'write'),
    toolEvent(2, 'edit'),
    toolEvent(3, 'edit'),
    toolEvent(4, 'multiedit'),
  ])
  assert.deepEqual(metrics.writes_by_kind, [
    ['edit', 2],
    ['multiedit', 1],
    ['write', 1],
  ])
})

test('metrics: session aggregate exposes reads/writes/ratio', () => {
  const metrics = computeSessionMetrics('s', [
    toolEvent(1, 'read'),
    toolEvent(2, 'read'),
    toolEvent(3, 'edit'),
    toolEvent(4, 'write'),
  ])
  assert.equal(metrics.session_id, 's')
  assert.equal(metrics.reads, 2)
  assert.equal(metrics.writes, 2)
  assert.equal(metrics.read_edit_ratio, 1)
  assert.deepEqual(metrics.dup_candidates, [])
})

test('symbols: extraction covers functions, classes, nested, private, async', () => {
  const text = [
    'import os',
    'def top_fn(value):',
    '    return value',
    'class TopClass:',
    '    async def inner_method(self):',
    '        pass',
    '    def _private_fn(self):',
    '        pass',
  ].join('\n')
  const symbols = extractDefinedSymbols(text, 'python')
  assert.deepEqual(
    symbols.map((item) => [item.name, item.kind, item.line_in_payload]),
    [
      ['top_fn', 'function', 2],
      ['TopClass', 'class', 4],
      ['inner_method', 'function', 5],
      ['_private_fn', 'function', 7],
    ],
  )
})

test('symbols: no definitions yields empty tuple', () => {
  assert.deepEqual(extractDefinedSymbols('x = 1\n', 'python'), [])
})

test('symbols: unsupported language yields null (explicit refusal)', () => {
  assert.equal(extractDefinedSymbols('function f() {}', 'javascript'), null)
  assert.equal(isSupportedLanguage('javascript'), false)
  assert.equal(isSupportedLanguage('python'), true)
})

test('symbols: symbolsFromWritePayloads skips unsupported languages', () => {
  const symbols = symbolsFromWritePayloads([
    ['python', 'def a():\n    pass\n'],
    ['javascript', 'function b() {}'],
  ])
  assert.deepEqual(symbols.map((item) => item.name), ['a'])
})

test('normalize: lowercases and maps hyphens to underscores', () => {
  assert.equal(normalizeSymbolName('Make_Compute-Wrapper'), 'compute')
})

test('normalize: strips prefix tokens iteratively', () => {
  assert.equal(normalizeSymbolName('get_fetch_compute'), 'compute')
})

test('normalize: strips suffix tokens iteratively', () => {
  assert.equal(normalizeSymbolName('compute_helper'), 'compute')
})

test('normalize: keeps middle tokens and only trims both ends', () => {
  assert.equal(normalizeSymbolName('helper_compute'), 'helpercompute')
})

test('normalize: strips surrounding underscores', () => {
  assert.equal(normalizeSymbolName('__compute__'), 'compute')
})

test('match: normalized equality wins before similarity', () => {
  assert.deepEqual(matchSymbols('make_compute_wrapper', 'make_compute_helper'), ['normalized_exact', null])
  assert.deepEqual(matchSymbols('fetch_data_impl', 'get_data_fn'), ['normalized_exact', null])
})

test('match: near-identical names hit high_similarity above threshold', () => {
  const matched = matchSymbols('make_compute_helpr', 'make_compute_helper')
  assert.equal(matched[0], 'high_similarity')
  assert.ok(matched[1] >= DUP_MATCH_THRESHOLD)
})

test('match: unrelated names return null', () => {
  assert.equal(matchSymbols('totally_different', 'xyz'), null)
})

test('dup candidates: same raw name is never a candidate', () => {
  const symbols = extractDefinedSymbols('def compute(v):\n    return v\n')
  assert.deepEqual(findDupCandidates(symbols, symbols), [])
})

test('dup candidates: deterministic sorted output and evidence passthrough', () => {
  const fresh = extractDefinedSymbols('def make_compute_wrapper(v):\n    return v\n')
  const existing = extractDefinedSymbols('def make_compute_helper(v):\n    return v\n')
  const candidates = findDupCandidates(fresh, existing, 'sess.jsonl:4', 'project/common.py:1')
  assert.equal(candidates.length, 1)
  assert.equal(candidates[0].new_symbol, 'make_compute_wrapper')
  assert.equal(candidates[0].existing_symbol, 'make_compute_helper')
  assert.equal(candidates[0].match_reason, 'normalized_exact')
  assert.equal(candidates[0].similarity, null)
  assert.equal(candidates[0].new_evidence, 'sess.jsonl:4')
  assert.equal(candidates[0].existing_evidence, 'project/common.py:1')
})

test('dup candidates: duplicates are collapsed by (new, existing, reason)', () => {
  const fresh = [
    { name: 'a_b', kind: 'function', line_in_payload: 1 },
    { name: 'a_b', kind: 'function', line_in_payload: 2 },
  ]
  const existing = [{ name: 'a_b_helper', kind: 'function', line_in_payload: 1 }]
  const candidates = findDupCandidates(fresh, existing)
  assert.equal(candidates.length, 1)
})

test('difflib: identical strings ratio 1; both empty ratio 1', () => {
  assert.equal(sequenceRatio('abc', 'abc'), 1)
  assert.equal(sequenceRatio('', ''), 1)
})

test('difflib: known partial ratio matches 2M/T', () => {
  assert.equal(sequenceRatio('abc', 'abd'), 4 / 6)
})

test('payloads: Write blocks are extracted with suffix language; other tools ignored', () => {
  const payloads = writePayloadsFromRecords([
    {
      type: 'assistant',
      message: {
        content: [
          { type: 'tool_use', name: 'Write', input: { file_path: '/a.py', content: 'def f():\n    pass\n' } },
          { type: 'tool_use', name: 'Write', input: { file_path: '/b.txt', content: 'hello' } },
          { type: 'tool_use', name: 'Edit', input: { file_path: '/c.py', old_string: 'a', new_string: 'b' } },
        ],
      },
    },
  ])
  assert.equal(payloads.length, 2)
  assert.deepEqual(
    payloads.map((payload) => [payload.path, payload.language]),
    [
      ['/a.py', 'python'],
      ['/b.txt', null],
    ],
  )
})

test('project files: exact path wins', () => {
  assert.deepEqual(resolveProjectFile('/a.py', { '/a.py': 'x' }), { path: '/a.py', content: 'x' })
})

test('project files: suffix fallback finds absolute read targets', () => {
  const resolved = resolveProjectFile('/demo/alpha/src/util.py', {
    'work/demo/alpha/src/util.py': 'content',
  })
  assert.equal(resolved.content, 'content')
})

test('project files: unrelated keys return null', () => {
  assert.equal(resolveProjectFile('/demo/alpha/src/util.py', { 'other.py': 'x' }), null)
})

test('project files: existing symbols dedupe files and report misses', () => {
  const missed = []
  const symbols = existingSymbolsFromReads(
    ['/demo/alpha/src/a.py', '/other/a.py', '/demo/alpha/src/missing.py'],
    { '/demo/alpha/src/a.py': 'def f():\n    pass\nclass C:\n    pass\n' },
    (target) => missed.push(target),
  )
  assert.deepEqual(symbols.map((item) => item.name), ['f', 'C'])
  assert.deepEqual(missed, ['/demo/alpha/src/missing.py'])
})

// ===========================================================================
// 6. 器官契约 / claim 判定
// ===========================================================================

test('organ: registry declares slug / version / summary / input fields', () => {
  assert.equal(reworkEvidenceVerb.slug, 'rework-evidence')
  assert.equal(reworkEvidenceVerb.version, '0.2.0')
  assert.equal(VERSION, '0.2.0')
  assert.match(reworkEvidenceVerb.summary, /返工取证/)
  assert.deepEqual([...reworkEvidenceVerb.input_fields], ['session', 'claims'])
  assert.deepEqual([...CHECKS], ['rework', 'duplicate-candidate', 'read-edit-ratio', 'parse-note'])
})

test('organ: asserted value sets are closed', () => {
  assert.deepEqual([...ASSERTED_VALUES.rework], ['rework', 'not_rework', 'insufficient_data', 'absent'])
  assert.deepEqual([...ASSERTED_VALUES['duplicate-candidate']], ['present', 'absent'])
  assert.deepEqual([...ASSERTED_VALUES['read-edit-ratio']], ['defined', 'undefined'])
  assert.deepEqual([...ASSERTED_VALUES['parse-note']], ['present', 'absent'])
})

test('organ: rework claim matches computed verdict', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [{ type: 'assistant', message: { role: 'assistant', content: [
      { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
      { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
      { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
    ] } }] },
    claims: [{ claim_id: 'rw', check: 'rework', asserted: 'rework', file: '/a.py', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].id, 'rw@s-rework-1#2#call-rework-2')
  assert.equal(records[0].evidence.computed, 'rework')
  assert.deepEqual(records[0].evidence.finding.reasons, ['edits>=M'])
})

test('organ: rework mismatch with node is refuted', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [{ type: 'assistant', message: { role: 'assistant', content: [
      { type: 'tool_use', name: 'Write', input: { file_path: '/a.py' } },
    ] } }] },
    claims: [{ claim_id: 'rw', check: 'rework', asserted: 'rework', file: '/a.py', node: NODE }],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /痕迹推翻主张/)
})

test('organ: mismatch without node is inconclusive (no refuted without anchor)', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [{ type: 'assistant', message: { role: 'assistant', content: [
      { type: 'tool_use', name: 'Write', input: { file_path: '/a.py' } },
    ] } }] },
    claims: [{ claim_id: 'rw', check: 'rework', asserted: 'rework', file: '/a.py' }],
  })
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.equal(records[0].node, null)
  assert.match(records[0].message, /不能下 refuted/)
})

test('organ: untouched file can be claimed absent', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [{ type: 'assistant', message: { role: 'assistant', content: [] } }] },
    claims: [{ claim_id: 'absent', check: 'rework', asserted: 'absent', file: '/a.py', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.computed, 'absent')
})

test('organ: expected_edits mismatch is refuted despite verdict match', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [{ type: 'assistant', message: { role: 'assistant', content: [
      { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
      { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
      { type: 'tool_use', name: 'Edit', input: { file_path: '/a.py' } },
    ] } }] },
    claims: [{ claim_id: 'rw', check: 'rework', asserted: 'rework', file: '/a.py', expected_edits: 4, node: NODE }],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /编辑\/版本计数与重算不符/)
})

test('organ: expected_versions null vs present chain is refuted', () => {
  const records = runOrgan(caseSubject('case-claude_code-rework-01', [
    { claim_id: 'rw', check: 'rework', asserted: 'rework', file: '/demo/alpha/src/alpha_a.py', expected_versions: null, node: NODE },
  ]).subject)
  assert.equal(records[0].verdict, REFUTED)
})

test('organ: duplicate-candidate present hits the truth pair', () => {
  const records = runOrgan(caseSubject('case-claude_code-duplicate-01', [
    {
      claim_id: 'dup',
      check: 'duplicate-candidate',
      asserted: 'present',
      new_symbol: 'make_compute_wrapper',
      existing_symbol: 'make_compute_helper',
      node: NODE,
    },
  ]).subject)
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.matched.match_reason, 'normalized_exact')
  assert.equal(records[0].evidence.disclosure, DUP_DISCLOSURE)
})

test('organ: duplicate-candidate wrong pair is refuted', () => {
  const records = runOrgan(caseSubject('case-claude_code-duplicate-01', [
    {
      claim_id: 'dup',
      check: 'duplicate-candidate',
      asserted: 'present',
      new_symbol: 'no_such_symbol',
      existing_symbol: 'make_compute_helper',
      node: NODE,
    },
  ]).subject)
  assert.equal(records[0].verdict, REFUTED)
})

test('organ: duplicate-candidate without project_files is inconclusive', () => {
  const records = runOrgan(caseSubject('case-claude_code-duplicate-01', [
    {
      claim_id: 'dup',
      check: 'duplicate-candidate',
      asserted: 'present',
      new_symbol: 'make_compute_wrapper',
      existing_symbol: 'make_compute_helper',
      node: NODE,
    },
  ], { withProject: false }).subject)
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /project_files/)
})

test('organ: duplicate-candidate on codex is inconclusive (symbol payload unsupported)', () => {
  const records = runOrgan(caseSubject('case-codex-rework-03', [
    {
      claim_id: 'dup',
      check: 'duplicate-candidate',
      asserted: 'absent',
      new_symbol: 'a',
      existing_symbol: 'b',
      node: NODE,
    },
  ]).subject)
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /符号候选未启用/)
})

test('organ: read-edit-ratio defined claim matches', () => {
  const records = runOrgan(caseSubject('case-claude_code-rework-01', [
    { claim_id: 'ratio', check: 'read-edit-ratio', asserted: 'defined', expected_ratio: 1 / 3, node: NODE },
  ]).subject)
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.reads, 1)
  assert.equal(records[0].evidence.writes, 3)
})

test('organ: read-edit-ratio is undefined with zero writes', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [{ type: 'assistant', message: { role: 'assistant', content: [
      { type: 'tool_use', name: 'Read', input: { file_path: '/a.py' } },
    ] } }] },
    claims: [{ claim_id: 'ratio', check: 'read-edit-ratio', asserted: 'undefined', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.read_edit_ratio, null)
})

test('organ: expected_ratio mismatch is refuted', () => {
  const records = runOrgan(caseSubject('case-claude_code-rework-01', [
    { claim_id: 'ratio', check: 'read-edit-ratio', asserted: 'defined', expected_ratio: 2, node: NODE },
  ]).subject)
  assert.equal(records[0].verdict, REFUTED)
})

test('organ: parse-note present with expected count matches', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [
      { type: 'assistant', message: { role: 'assistant', content: [{ type: 'tool_use', input: {} }] } },
    ] },
    claims: [{ claim_id: 'note', check: 'parse-note', asserted: 'present', code: 'unverified_field_skipped', count: 1, node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.note_count, 1)
})

test('organ: parse-note absent matches empty note set', () => {
  const records = runOrgan(caseSubject('case-claude_code-rework-01', [
    { claim_id: 'note', check: 'parse-note', asserted: 'absent', code: 'bad_line', node: NODE },
  ]).subject)
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.note_count, 0)
})

test('organ: parse-note count mismatch is refuted', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [
      {
        type: 'file-history-snapshot',
        snapshot: { trackedFileBackups: { '/a.py': null, '/b.py': null } },
      },
    ] },
    claims: [{ claim_id: 'note', check: 'parse-note', asserted: 'present', code: 'snapshot_entry_null', count: 1, node: NODE }],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.equal(records[0].evidence.note_count, 2)
})

test('organ: unknown claim field is a contract error', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'rework', asserted: 'rework', file: '/a.py', bogus: 1 }],
    }),
    ContractError,
  )
})

test('organ: invalid check is a contract error', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'bogus', asserted: 'x' }],
    }),
    ContractError,
  )
})

test('organ: asserted outside the closed set is a contract error', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'rework', asserted: 'maybe', file: '/a.py' }],
    }),
    ContractError,
  )
})

test('organ: duplicate claim ids are rejected', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [
        { claim_id: 'same', check: 'read-edit-ratio', asserted: 'undefined' },
        { claim_id: 'same', check: 'read-edit-ratio', asserted: 'undefined' },
      ],
    }),
    ContractError,
  )
})

test('organ: rework claim requires file', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'rework', asserted: 'rework' }],
    }),
    ContractError,
  )
})

test('organ: duplicate-candidate requires both symbols', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'duplicate-candidate', asserted: 'present', new_symbol: 'a' }],
    }),
    ContractError,
  )
})

test('organ: parse-note requires code', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'parse-note', asserted: 'present' }],
    }),
    ContractError,
  )
})

test('organ: fields outside a check are rejected (no silent ignore)', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined', file: '/a.py' }],
    }),
    ContractError,
  )
})

test('organ: missing trace node bubbles NodeMissing (exit 3 at CLI)', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined', node: NODE }],
    }, Basis.fromObject({ version: '1', nodes: [] })),
    NodeMissing,
  )
})

test('organ: non-integer node turn is a contract error', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined', node: { session_id: 's', turn: 1.5, tool_call_id: 'c' } }],
    }),
    ContractError,
  )
})

test('organ: incomplete node downgrades a matching claim to inconclusive', () => {
  const records = runOrgan(
    {
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined', node: { session_id: 's', tool_call_id: '' } }],
    },
    Basis.fromObject({ version: '1', nodes: [{ session_id: 's', turn: null, tool_call_id: '' }] }),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /痕迹节点不完整/)
})

test('organ: malformed session yields per-claim input_error inconclusive', () => {
  const records = runOrgan({
    session: { harness: 'claude', records: [] },
    claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'defined', node: NODE }],
  })
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /session\.records/)
})

test('organ: invalid harness value yields per-claim inconclusive', () => {
  const records = runOrgan({
    session: { harness: 'gemini', records: [{ message: { role: 'user' } }] },
    claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined' }],
  })
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /harness/)
})

test('organ: harness is auto-detected when omitted', () => {
  const claude = runOrgan({
    session: { records: [{ message: { role: 'user' } }] },
    claims: [{ claim_id: 'c', check: 'read-edit-ratio', asserted: 'undefined' }],
  })
  assert.equal(claude[0].verdict, CLAIM)
  const codex = runOrgan({
    session: { records: [{ payload: { type: 'session_meta', session_id: 's-codex' } }] },
    claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined' }],
  })
  assert.equal(codex[0].verdict, CLAIM)
  assert.equal(codex[0].evidence.session.source, 'codex')
})

test('organ: malformed version_chains is a contract error', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      version_chains: { stem: { versions: 'nope' } },
      claims: [{ claim_id: 'c', check: 'read-edit-ratio', asserted: 'undefined' }],
    }),
    ContractError,
  )
})

test('organ: malformed project_files is a contract error', () => {
  assert.throws(
    () => runOrgan({
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      project_files: { '/a.py': 42 },
      claims: [{ claim_id: 'c', check: 'read-edit-ratio', asserted: 'undefined' }],
    }),
    ContractError,
  )
})

test('organ: empty claims array is a contract error', () => {
  assert.throws(
    () => runOrgan({ session: { harness: 'claude', records: [{ message: { role: 'user' } }] }, claims: [] }),
    ContractError,
  )
})

test('organ: evaluation is deterministic (same subject → deep-equal records)', () => {
  const { subject } = caseSubject('case-claude_code-duplicate-01', [
    { claim_id: 'rw', check: 'rework', asserted: 'not_rework', file: '/demo/alpha/src/beta_b.py', node: NODE },
    { claim_id: 'ratio', check: 'read-edit-ratio', asserted: 'defined', node: NODE },
    {
      claim_id: 'dup',
      check: 'duplicate-candidate',
      asserted: 'present',
      new_symbol: 'make_compute_wrapper',
      existing_symbol: 'make_compute_helper',
      node: NODE,
    },
  ])
  const first = runOrgan(subject).map((record) => record.id + '|' + record.verdict + '|' + JSON.stringify(record.evidence))
  const second = runOrgan(subject).map((record) => record.id + '|' + record.verdict + '|' + JSON.stringify(record.evidence))
  assert.deepEqual(first, second)
})

// ===========================================================================
// 7. 冻结样例逐例对账（12 个 case）
// ===========================================================================

test('fixture: case-claude_code-rework-01 matches truth', () => {
  const records = assertCaseTruth('case-claude_code-rework-01')
  assert.equal(records.length, 1)
})

test('fixture: case-claude_code-rework-02 matches truth', () => {
  assertCaseTruth('case-claude_code-rework-02')
})

test('fixture: case-claude_code-threshold_exact-01 matches truth', () => {
  assertCaseTruth('case-claude_code-threshold_exact-01')
})

test('fixture: case-claude_code-near_miss-01 matches truth', () => {
  assertCaseTruth('case-claude_code-near_miss-01')
})

test('fixture: case-claude_code-normal-01 matches truth', () => {
  assertCaseTruth('case-claude_code-normal-01')
})

test('fixture: case-claude_code-single_edit-01 matches truth', () => {
  assertCaseTruth('case-claude_code-single_edit-01')
})

test('fixture: case-claude_code-missing_chain-01 matches truth', () => {
  const records = assertCaseTruth('case-claude_code-missing_chain-01')
  assert.equal(records[0].evidence.finding.verdict, 'insufficient_data')
})

test('fixture: case-claude_code-duplicate-01 matches truth', () => {
  const records = assertCaseTruth('case-claude_code-duplicate-01')
  assert.ok(records.some((record) => record.claim_id === 'dup:0'))
})

test('fixture: case-claude_code-duplicate-02 matches truth', () => {
  assertCaseTruth('case-claude_code-duplicate-02')
})

test('fixture: case-claude_code-duplicate-03 matches truth', () => {
  const records = assertCaseTruth('case-claude_code-duplicate-03')
  const dup = records.find((record) => record.claim_id === 'dup:0')
  assert.equal(dup.evidence.matched.match_reason, 'high_similarity')
})

test('fixture: case-codex-rework-03 matches truth', () => {
  const records = assertCaseTruth('case-codex-rework-03')
  assert.equal(records[0].evidence.finding.edit_count, 4)
})

test('fixture: case-codex-normal-02 matches truth', () => {
  assertCaseTruth('case-codex-normal-02')
})

test('fixture: all cases parse to their truth session id and source', () => {
  for (const caseId of readdirSync(FIXTURES)) {
    const data = caseData(caseId)
    const ir = data.truth.source === 'codex'
      ? parseCodexSession(data.records, 's.jsonl')
      : parseClaudeSession(data.records, 's.jsonl')
    assert.equal(ir.meta.session_id, data.truth.session_id)
    assert.equal(ir.meta.source, data.truth.source === 'codex' ? 'codex' : 'claude')
  }
})

test('fixture: rework-01 evidence carries version/edit/span values from source scan', () => {
  const records = assertCaseTruth('case-claude_code-rework-01')
  const finding = records[0].evidence.finding
  assert.equal(finding.version_count, 3)
  assert.equal(finding.edit_count, 3)
  assert.equal(finding.span_seconds, 1200)
  assert.deepEqual(finding.reasons, ['versions>=N', 'edits>=M'])
})

// ===========================================================================
// 8. 唯入口 / CLI
// ===========================================================================

test('registry: BUILTIN_MODULES includes 10 verbs in dictionary order', () => {
  assert.deepEqual([...BUILTIN_MODULES], [
    'agent-conflict',
    'anonymity-collapse',
    'archive-extraction',
    'email-evidence',
    'hazard-triage',
    'pattern-evidence',
    'pipeline-run',
    'rework-evidence',
    'session-replay',
    'tool-ops-attribution',
  ])
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
})

async function capture(fn) {
  const out = []
  const err = []
  const originalLog = console.log
  const originalWrite = process.stderr.write
  console.log = (...args) => {
    out.push(args.map(String).join(' '))
  }
  process.stderr.write = (chunk) => {
    err.push(String(chunk))
    return true
  }
  try {
    const code = await fn()
    return { code, out: out.join('\n'), err: err.join('') }
  } finally {
    console.log = originalLog
    process.stderr.write = originalWrite
  }
}

function tempFiles(subject, basis = { version: '2026.11.25', nodes: [NODE] }) {
  const dir = mkdtempSync(join(tmpdir(), 'rework-evidence-test-'))
  const subjectPath = join(dir, 'subject.json')
  const basisPath = join(dir, 'basis.json')
  writeFileSync(subjectPath, JSON.stringify(subject))
  writeFileSync(basisPath, JSON.stringify(basis))
  return { subjectPath, basisPath }
}

test('cli: list shows rework-evidence with its version', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /rework-evidence\s+0\.2\.0/)
})

test('cli: list --json includes the organ and input fields', async () => {
  const { code, out } = await capture(() => main(['list', '--json']))
  assert.equal(code, EXIT_OK)
  const parsed = JSON.parse(out)
  const organ = parsed.find((item) => item.slug === 'rework-evidence')
  assert.ok(organ)
  assert.deepEqual(organ.input_fields, ['session', 'claims'])
})

test('cli: sample check passes with exit code 0', async () => {
  const subject = join(PRODUCT_ROOT, 'samples', 'rework-evidence.json')
  const basis = join(PRODUCT_ROOT, 'samples', 'rework-evidence-traces.json')
  const { code, out } = await capture(() =>
    main(['check', 'rework-evidence', '--input', subject, '--basis', basis]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /合计 3 条，阻断 0 条/)
  assert.match(out, /\[claim\] rework-alpha-a/)
})

test('cli: sample check --json is deterministic across runs', async () => {
  const subject = join(PRODUCT_ROOT, 'samples', 'rework-evidence.json')
  const basis = join(PRODUCT_ROOT, 'samples', 'rework-evidence-traces.json')
  const first = await capture(() =>
    main(['check', 'rework-evidence', '--input', subject, '--basis', basis, '--json']),
  )
  const second = await capture(() =>
    main(['check', 'rework-evidence', '--input', subject, '--basis', basis, '--json']),
  )
  assert.equal(first.code, EXIT_OK)
  assert.equal(first.out, second.out)
  const parsed = JSON.parse(first.out)
  assert.equal(parsed.product, 'traceproof')
  assert.equal(parsed.verb, 'rework-evidence')
  assert.equal(parsed.verb_version, '0.2.0')
  assert.equal(parsed.summary.total, 3)
})

test('cli: missing required subject field exits 2', async () => {
  const files = tempFiles({ session: { harness: 'claude', records: [{ message: { role: 'user' } }] } })
  const { code, err } = await capture(() =>
    main(['check', 'rework-evidence', '--input', files.subjectPath]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /缺少必填字段：claims/)
})

test('cli: malformed claim exits 3 (contract violation)', async () => {
  const files = tempFiles({
    session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
    claims: [{ claim_id: 'x', check: 'bogus', asserted: 'x' }],
  })
  const { code, err } = await capture(() =>
    main(['check', 'rework-evidence', '--input', files.subjectPath]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /ContractError/)
})

test('cli: missing trace node exits 3', async () => {
  const files = tempFiles(
    {
      session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
      claims: [{ claim_id: 'x', check: 'read-edit-ratio', asserted: 'undefined', node: NODE }],
    },
    { version: '2026.11.25', nodes: [] },
  )
  const { code, err } = await capture(() =>
    main(['check', 'rework-evidence', '--input', files.subjectPath, '--basis', files.basisPath]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: refuted claim exits 1', async () => {
  const files = tempFiles({
    session: { harness: 'claude', records: [{ message: { role: 'user' } }] },
    claims: [{ claim_id: 'wrong', check: 'read-edit-ratio', asserted: 'defined', node: NODE }],
  })
  const { code, out } = await capture(() =>
    main(['check', 'rework-evidence', '--input', files.subjectPath, '--basis', files.basisPath]),
  )
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /\[refuted\] wrong/)
})