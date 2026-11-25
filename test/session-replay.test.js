/**
 * session-replay 器官的无损测试。
 *
 * 数据面：旧仓 `data/bench/` 的 9 个有效样本 + 1 个非法格式样本（只读拷贝）。
 * 每个样本逐字段对账：
 *  - 事件数 / 事件种类分布 / 工具集合（读日志归一）；
 *  - episode 条数与状态（bug-fix 切分）；
 *  - 修复 diff 还原的 status / confidence / before / after 全文（逐字符）。
 *
 * 另加读日志、语义词、失败判定、pass 判定、丢弃原因、器官契约的单元用例。
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
  makeNode,
  makeRecord,
} from '../lib/traceproof/core/ledger.js'
import { MASK } from '../lib/traceproof/core/redact.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  FormatProblem,
  detectHarness,
  normalizeSession,
  parseExitCode,
} from '../lib/traceproof/verbs/session-replay/readers.js'
import {
  failureEvidence,
  matchesBugTerm,
  reconstructAll,
  splitEpisodes,
  testCommandOf,
} from '../lib/traceproof/verbs/session-replay/episode.js'

await loadBuiltin()

const ROOT = fileURLToPath(new URL('./fixtures/session-replay/', import.meta.url))
const NODE = { session_id: 's-session-replay-1', turn: 2, tool_call_id: 'call-session-replay-2' }

function basisOf(nodes = [NODE]) {
  return Basis.fromObject({ version: '2026.11.25', nodes })
}

function runOrgan(subject, basis = basisOf()) {
  return [...get('session-replay').evaluate(subject, basis)]
}

function readRecords(harness, sample) {
  return readFileSync(join(ROOT, 'sessions', harness, `${sample}.jsonl`), 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line))
}

function repoFiles(sample, paths) {
  const files = {}
  for (const path of paths) {
    const candidate = join(ROOT, 'repo', sample, path.replace(/^\//, ''))
    if (existsSync(candidate)) files[path] = readFileSync(candidate, 'utf8')
  }
  return files
}

const samples = [
  ...readdirSync(join(ROOT, 'sessions', 'claude'))
    .filter((name) => name.endsWith('.jsonl'))
    .map((name) => ({ harness: 'claude', sample: name.replace(/\.jsonl$/, '') })),
  ...readdirSync(join(ROOT, 'sessions', 'codex'))
    .filter((name) => name.endsWith('.jsonl'))
    .map((name) => ({ harness: 'codex', sample: name.replace(/\.jsonl$/, '') })),
]

function loadSample({ harness, sample }) {
  const truth = JSON.parse(readFileSync(join(ROOT, 'truth', `${sample}.truth.json`), 'utf8'))
  const records = readRecords(harness, sample)
  const reconPaths = (truth.expect_reconstructions ?? []).map((item) => item.file)
  const files = repoFiles(sample, reconPaths)
  const events = normalizeSession(harness, records)
  const split = splitEpisodes(events)
  const recons = reconstructAll(events, files)
  const kindCounts = {}
  for (const event of events) kindCounts[event.kind] = (kindCounts[event.kind] ?? 0) + 1
  const tools = [
    ...new Set(
      events
        .filter((event) => event.kind === 'tool_call')
        .map((event) => event.tool)
        .filter((tool) => tool !== 'unknown'),
    ),
  ].sort()
  return { truth, records, files, events, split, recons, kindCounts, tools }
}

function sortObject(value) {
  const out = {}
  for (const key of Object.keys(value).sort()) out[key] = value[key]
  return out
}

function subjectFor(entry, claims) {
  const loaded = loadSample(entry)
  return {
    session: { harness: entry.harness, records: loaded.records },
    repo: { files: loaded.files },
    claims,
  }
}

// ════════════════════════════════════════════════════════════════════════
// 1. 基准样本逐字段对账
// ════════════════════════════════════════════════════════════════════════

for (const entry of samples) {
  const label = `${entry.harness}/${entry.sample}`
  const loaded = loadSample(entry)

  test(`session-replay ${label}: 事件数 = truth`, () => {
    assert.equal(loaded.events.length, loaded.truth.expect.event_count)
  })

  test(`session-replay ${label}: 事件种类分布 = truth`, () => {
    assert.deepEqual(sortObject(loaded.kindCounts), sortObject(loaded.truth.expect.kind_counts))
  })

  test(`session-replay ${label}: 工具集合 = truth`, () => {
    assert.deepEqual(loaded.tools, [...loaded.truth.expect.tools_used].sort())
  })

  test(`session-replay ${label}: episode 条数 = truth`, () => {
    assert.equal(loaded.split.episodes.length, loaded.truth.expect_episodes)
  })

  test(`session-replay ${label}: episode 状态序列 = truth`, () => {
    assert.deepEqual(
      loaded.split.episodes.map((episode) => episode.status),
      loaded.truth.expect_episode_statuses,
    )
  })

  for (const expected of loaded.truth.expect_reconstructions ?? []) {
    test(`session-replay ${label}: 还原 ${expected.file} status/confidence`, () => {
      const found = loaded.recons.filter((item) => item.path === expected.file).slice(-1)[0]
      assert.ok(found, `没有还原记录：${expected.file}`)
      assert.equal(found.status, expected.status)
      assert.equal(found.confidence, expected.confidence)
    })
    test(`session-replay ${label}: 还原 ${expected.file} before 逐字符`, () => {
      const found = loaded.recons.filter((item) => item.path === expected.file).slice(-1)[0]
      assert.equal(found.before, expected.before)
    })
    test(`session-replay ${label}: 还原 ${expected.file} after 逐字符`, () => {
      const found = loaded.recons.filter((item) => item.path === expected.file).slice(-1)[0]
      assert.equal(found.after, expected.after)
    })
  }

  const hasEpisode = loaded.truth.expect_episodes > 0
  test(`session-replay ${label}: episode 主张 -> claim`, () => {
    const record = runOrgan(
      subjectFor(entry, [
        {
          claim_id: 'episode',
          check: 'episode',
          asserted: hasEpisode ? 'present' : 'absent',
          status: hasEpisode ? loaded.truth.expect_episode_statuses[0] : undefined,
          node: NODE,
        },
      ]),
    )[0]
    assert.equal(record.verdict, CLAIM, record.message)
  })

  test(`session-replay ${label}: failure-signal 主张 -> claim`, () => {
    const asserted = entry.sample === 'no-failure-signal-1' ? 'absent' : 'present'
    const record = runOrgan(
      subjectFor(entry, [{ claim_id: 'fs', check: 'failure-signal', asserted, node: NODE }]),
    )[0]
    assert.equal(record.verdict, CLAIM, record.message)
  })

  for (const expected of loaded.truth.expect_reconstructions ?? []) {
    test(`session-replay ${label}: 还原主张 ${expected.file} -> claim`, () => {
      const record = runOrgan(
        subjectFor(entry, [
          { claim_id: 'recon', check: 'reconstruction', path: expected.file, asserted: expected.status, node: NODE },
        ]),
      )[0]
      assert.equal(record.verdict, CLAIM, record.message)
    })
  }
}

test('session-replay: 非法格式样本 -> FormatProblem（不静默产出空事件流）', () => {
  const records = readFileSync(join(ROOT, 'sessions', 'invalid', 'unsupported-format-1.jsonl'), 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line))
  assert.throws(() => normalizeSession(null, records), FormatProblem)
})

test('session-replay: 非法格式经器官 -> inconclusive 且说明会话不可归一', () => {
  const records = readFileSync(join(ROOT, 'sessions', 'invalid', 'unsupported-format-1.jsonl'), 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line))
  const record = runOrgan({
    session: { records },
    repo: { files: {} },
    claims: [{ claim_id: 'c1', check: 'episode', asserted: 'present', node: NODE }],
  })[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /不可归一/)
})

// ════════════════════════════════════════════════════════════════════════
// 2. 读日志（harness 判别 / 数值退出码 / patch 路径）
// ════════════════════════════════════════════════════════════════════════

test('readers: 按 message 键判 claude', () => {
  assert.equal(detectHarness([{ message: {} }]), 'claude')
})

test('readers: 按 payload 键判 codex', () => {
  assert.equal(detectHarness([{ payload: {} }]), 'codex')
})

test('readers: 未知形态显式报错', () => {
  assert.throws(() => detectHarness([{ foo: 1 }]), FormatProblem)
})

test('readers: 同时命中两种形态 -> 报错（不猜）', () => {
  assert.throws(() => detectHarness([{ message: {}, payload: {} }]), /同时命中/)
})

test('readers: parseExitCode 认 Process exited with code N', () => {
  assert.deepEqual(parseExitCode('Process exited with code 2\nOutput:'), { exit_code: 2, source: 'process_exited' })
})

test('readers: parseExitCode 认行首 Exit code: N', () => {
  assert.deepEqual(parseExitCode('Exit code: 0\nSuccess'), { exit_code: 0, source: 'exit_code_line' })
})

test('readers: parseExitCode 没有数值 -> null', () => {
  assert.deepEqual(parseExitCode('FAILED tests/x.py'), { exit_code: null, source: 'unknown' })
})

test('readers: seq 是源文件行号（跳过非会话行）', () => {
  const events = normalizeSession('claude', [
    { type: 'mode' },
    { type: 'user', sessionId: 's', message: { content: 'hello' }, timestamp: 't' },
  ])
  assert.equal(events.length, 1)
  assert.equal(events[0].seq, 2)
})

test('readers: codex developer 角色落 meta（不当成 bug 报告）', () => {
  const events = normalizeSession('codex', [
    { type: 'response_item', timestamp: 't', payload: { type: 'message', role: 'developer', content: 'rules' } },
  ])
  assert.equal(events[0].kind, 'meta')
})

test('readers: claude 空文本消息被跳过', () => {
  const events = normalizeSession('claude', [
    { type: 'user', sessionId: 's', message: { content: '   ' }, timestamp: 't' },
  ])
  assert.equal(events.length, 0)
})

test('readers: codex patch 路径只从指令行取（含多个文件）', () => {
  const events = normalizeSession('codex', [
    {
      type: 'response_item',
      timestamp: 't',
      payload: {
        type: 'custom_tool_call',
        name: 'apply_patch',
        call_id: 'c1',
        input: '*** Begin Patch\n*** Update File: a.py\n@@\n-x\n+y\n*** Add File: b.py\n+z\n*** End Patch',
      },
    },
  ])
  assert.deepEqual(events[0].payload.files, ['a.py', 'b.py'])
  assert.equal(events[0].payload.file_actions['b.py'], 'add')
})

// ════════════════════════════════════════════════════════════════════════
// 3. episode 判定原语
// ════════════════════════════════════════════════════════════════════════

test('episode: bug 语义词按词边界（debug 不命中 bug）', () => {
  assert.equal(matchesBugTerm('please debug this', ['bug']), null)
  assert.equal(matchesBugTerm('this is a bug', ['bug']), 'bug')
})

test('episode: 中文语义词按子串', () => {
  assert.equal(matchesBugTerm('这里报错了', ['报错']), '报错')
})

test('episode: 数值退出码优先（0 不因文本 RETRY 而判失败）', () => {
  const event = { kind: 'tool_result', payload: { exit_code: 0, text: 'FAILED but retried' } }
  assert.equal(failureEvidence(event), null)
})

test('episode: 非零退出码是失败证据', () => {
  assert.equal(failureEvidence({ kind: 'tool_result', payload: { exit_code: 1 } }), 'exit_code')
})

test('episode: is_error 是失败证据（无退出码时）', () => {
  assert.equal(failureEvidence({ kind: 'tool_result', payload: { is_error: true, text: 'x' } }), 'is_error')
})

test('episode: 文本信号是失败证据（无退出码时）', () => {
  assert.equal(
    failureEvidence({ kind: 'tool_result', payload: { text: 'AssertionError: 1 != 2' } }),
    'text_signal:AssertionError',
  )
})

test('episode: 测试命令按标记识别并归一空白', () => {
  assert.equal(
    testCommandOf({ kind: 'tool_call', payload: { command: 'python  -m   pytest  tests/x.py' } }),
    'python -m pytest tests/x.py',
  )
  assert.equal(testCommandOf({ kind: 'tool_call', payload: { command: 'ls -la' } }), null)
})

test('episode: docs_only 被丢弃并给 reason', () => {
  const events = normalizeSession('claude', [
    { type: 'user', sessionId: 's', message: { content: 'bug: docs wrong' }, timestamp: 't' },
    { type: 'user', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_result', tool_use_id: 'c0', is_error: true, content: [{ type: 'text', text: 'AssertionError' }] }] } },
    { type: 'assistant', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_use', id: 'c1', name: 'Edit', input: { file_path: 'README.md', old_string: 'a', new_string: 'b' } }] } },
    { type: 'user', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_result', tool_use_id: 'c1', content: [{ type: 'text', text: 'ok' }] }] }, toolUseResult: { originalFile: 'a\n' } },
  ])
  const split = splitEpisodes(events)
  assert.equal(split.episodes.length, 0)
  assert.ok(split.filtered.some((item) => item.reason === 'docs_only'))
})

test('episode: 没有失败证据 -> no_failure_evidence', () => {
  const events = normalizeSession('claude', [
    { type: 'user', sessionId: 's', message: { content: 'bug: x' }, timestamp: 't' },
    { type: 'assistant', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_use', id: 'c1', name: 'Edit', input: { file_path: 'x.py', old_string: 'a', new_string: 'b' } }] } },
  ])
  assert.ok(splitEpisodes(events).filtered.some((item) => item.reason === 'no_failure_evidence'))
})

test('episode: 失败后没有修复动作 -> no_fix_action', () => {
  const events = normalizeSession('claude', [
    { type: 'user', sessionId: 's', message: { content: 'bug: x' }, timestamp: 't' },
    { type: 'user', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_result', tool_use_id: 'c1', is_error: true, content: [{ type: 'text', text: 'AssertionError' }] }] } },
  ])
  assert.ok(splitEpisodes(events).filtered.some((item) => item.reason === 'no_fix_action'))
})

test('episode: 分数低于阈值 -> below_threshold', () => {
  const events = normalizeSession('claude', [
    { type: 'user', sessionId: 's', message: { content: 'bug: x' }, timestamp: 't' },
    { type: 'user', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_result', tool_use_id: 'c1', is_error: true, content: [{ type: 'text', text: 'AssertionError' }] }] } },
    { type: 'assistant', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_use', id: 'c2', name: 'Edit', input: { file_path: 'src/x.py' } }] } },
  ])
  assert.ok(splitEpisodes(events).filtered.some((item) => item.reason === 'below_threshold'))
})

test('episode: 同一测试命令转通过才 verified_by_run', () => {
  const loaded = loadSample({ harness: 'claude', sample: 'structured-patch-1' })
  assert.equal(loaded.split.episodes[0].status, 'verified_by_run')
})

test('episode: 没有转通过 -> ended_without_pass', () => {
  const loaded = loadSample({ harness: 'claude', sample: 'ambiguous-old-string-1' })
  assert.equal(loaded.split.episodes[0].status, 'ended_without_pass')
})

test('episode: 多 bug 各自成 episode（id 不撞）', () => {
  const loaded = loadSample({ harness: 'claude', sample: 'multi-bug-1' })
  assert.equal(loaded.split.episodes.length, 2)
  assert.notEqual(loaded.split.episodes[0].episode_id, loaded.split.episodes[1].episode_id)
})

// ════════════════════════════════════════════════════════════════════════
// 4. 还原层边界
// ════════════════════════════════════════════════════════════════════════

test('recon: 多 hunk unified diff 逐步应用', () => {
  const base = 'a\nb\nc\nd\n'
  const diff = '@@ -1,2 +1,2 @@\n a\n-b\n+B\n@@ -3,2 +3,2 @@\n c\n-d\n+D\n'
  const events = normalizeSession('codex', [
    { type: 'response_item', timestamp: 't', payload: { type: 'item_completed', item: { type: 'FileChange', changes: { 'x.txt': { unified_diff: diff } } } } },
  ])
  const recon = reconstructAll(events, { 'x.txt': base })[0]
  assert.equal(recon.status, 'ok')
  assert.equal(recon.after, 'a\nB\nc\nD\n')
})

test('recon: replace_all 时替换全部命中', () => {
  const events = normalizeSession('claude', [
    {
      type: 'assistant', sessionId: 's', timestamp: 't',
      message: { content: [{ type: 'tool_use', id: 'c1', name: 'Edit', input: { file_path: 'x.py', old_string: 'v', new_string: 'w', replace_all: true } }] },
    },
    {
      type: 'user', sessionId: 's', timestamp: 't',
      message: { content: [{ type: 'tool_result', tool_use_id: 'c1', content: 'ok' }] },
      toolUseResult: { originalFile: 'v v v\n', structuredPatch: [] },
    },
  ])
  const recon = reconstructAll(events, {})[0]
  assert.equal(recon.status, 'ok')
  assert.equal(recon.after, 'w w w\n')
})

test('recon: Write 有 before 时 ok，无 before 时 no_before_image', () => {
  const events = normalizeSession('claude', [
    { type: 'assistant', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_use', id: 'c1', name: 'Write', input: { file_path: 'new.py', content: 'x\n' } }] } },
  ])
  assert.equal(reconstructAll(events, {})[0].status, 'no_before_image')
  assert.equal(reconstructAll(events, { 'new.py': 'old\n' })[0].status, 'ok')
})

test('recon: 没有 diff 证据 -> unresolved', () => {
  const events = normalizeSession('claude', [
    { type: 'assistant', sessionId: 's', timestamp: 't', message: { content: [{ type: 'tool_use', id: 'c1', name: 'Edit', input: { file_path: 'x.py' } }] } },
  ])
  assert.equal(reconstructAll(events, {})[0].status, 'unresolved')
})

test('recon: codex patch 多文件只还原有证据的路径', () => {
  const loaded = loadSample({ harness: 'codex', sample: 'happy-path-1' })
  assert.equal(loaded.recons.length >= 1, true)
  assert.equal(loaded.recons.every((item) => item.path.startsWith('/demo/')), true)
})

// ════════════════════════════════════════════════════════════════════════
// 5. 器官契约与 CLI
// ════════════════════════════════════════════════════════════════════════

const HAPPY = { harness: 'claude', sample: 'structured-patch-1' }

test('organ: list 含 session-replay', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /session-replay/)
})

test('organ: episode 主张错误 + 有节点 -> refuted', () => {
  const record = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'absent', node: NODE }]),
  )[0]
  assert.equal(record.verdict, 'refuted')
})

test('organ: episode 主张错误 + 无节点 -> inconclusive', () => {
  const record = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'absent' }]),
  )[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /不能下 refuted/)
})

test('organ: episode status 不符 -> refuted', () => {
  const record = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'present', status: 'ended_without_pass', node: NODE }]),
  )[0]
  assert.equal(record.verdict, 'refuted')
  assert.match(record.message, /主张状态/)
})

test('organ: reconstruction 路径不存在 -> absent', () => {
  const record = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c1', check: 'reconstruction', path: 'no/such.py', asserted: 'absent', node: NODE }]),
  )[0]
  assert.equal(record.verdict, CLAIM)
})

test('organ: reconstruction 状态不符 -> refuted', () => {
  const record = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c1', check: 'reconstruction', path: '/demo/alpha/src/calc.py', asserted: 'partial', node: NODE }]),
  )[0]
  assert.equal(record.verdict, 'refuted')
})

test('organ: 节点不在 basis -> NodeMissing', () => {
  const record = subjectFor(HAPPY, [
    { claim_id: 'c1', check: 'episode', asserted: 'present', node: { session_id: 's-session-replay-1', turn: 99, tool_call_id: 'x' } },
  ])
  assert.throws(() => runOrgan(record), NodeMissing)
})

test('organ: claim_id 重复 -> ContractError', () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'dup', check: 'episode', asserted: 'present', node: NODE },
    { claim_id: 'dup', check: 'episode', asserted: 'present', node: NODE },
  ])
  assert.throws(() => runOrgan(subject), ContractError)
})

test('organ: 未知 claim 字段 -> ContractError', () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'c1', check: 'episode', asserted: 'present', node: NODE, extra: 1 },
  ])
  assert.throws(() => runOrgan(subject), /未知字段/)
})

test('organ: asserted 闭集之外 -> ContractError', () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'c1', check: 'episode', asserted: 'maybe', node: NODE },
  ])
  assert.throws(() => runOrgan(subject), /asserted 非法/)
})

test('organ: reconstruction 缺 path -> ContractError', () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'c1', check: 'reconstruction', asserted: 'ok', node: NODE },
  ])
  assert.throws(() => runOrgan(subject), /需要 path/)
})

test('organ: session.records 为空 -> inconclusive', () => {
  const record = runOrgan({
    session: { harness: 'claude', records: [] },
    repo: { files: {} },
    claims: [{ claim_id: 'c1', check: 'episode', asserted: 'present', node: NODE }],
  })[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /records/)
})

test('organ: 证据里不出现原始用户文本 / 文件内容', () => {
  const records = runOrgan(
    subjectFor(HAPPY, [
      { claim_id: 'c1', check: 'episode', asserted: 'present', status: 'verified_by_run', node: NODE },
      { claim_id: 'c2', check: 'reconstruction', path: '/demo/alpha/src/calc.py', asserted: 'ok', node: NODE },
    ]),
  )
  const serialized = JSON.stringify(records)
  assert.equal(serialized.includes('demo-user, bug:'), false)
  assert.equal(serialized.includes('return a / b'), false)
})

test('organ: 证据里没有绝对路径', () => {
  const records = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'present', node: NODE }]),
  )
  assert.equal(JSON.stringify(records).includes(ROOT), false)
})

test('organ: 两次运行账本字节一致', async () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'b', check: 'episode', asserted: 'present', status: 'verified_by_run', node: NODE },
    { claim_id: 'a', check: 'failure-signal', asserted: 'present', node: NODE },
  ])
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const args = ['check', 'session-replay', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json'), '--json']
  const first = await capture(() => main(args))
  const second = await capture(() => main(args))
  assert.equal(first.code, EXIT_OK)
  assert.equal(first.out, second.out)
  const payload = JSON.parse(first.out)
  assert.deepEqual(payload.records.map((record) => record.claim_id), ['a', 'b'])
})

test('cli: 全 claim -> 0', async () => {
  const subject = subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'present', node: NODE }])
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'session-replay', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_OK)
})

test('cli: 存在 refuted -> 1', async () => {
  const subject = subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'absent', node: NODE }])
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'session-replay', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_BLOCKED)
})

test('cli: 输入文件缺失 -> 2', async () => {
  const dir = tmpDir()
  const { code } = await capture(() => main(['check', 'session-replay', '--input', join(dir, 'nope.json')]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: 缺必填字段（session）-> 2', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ repo: { files: {} }, claims: [] }))
  const { code } = await capture(() => main(['check', 'session-replay', '--input', join(dir, 'in.json')]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: 节点缺失 -> 3', async () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'c1', check: 'episode', asserted: 'present', node: { session_id: 'nope', turn: 1, tool_call_id: 'x' } },
  ])
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code, err } = await capture(() =>
    main(['check', 'session-replay', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: 痕迹包缺版本 -> 3', async () => {
  const subject = subjectFor(HAPPY, [{ claim_id: 'c1', check: 'episode', asserted: 'present', node: NODE }])
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'session-replay', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
})

// ════════════════════════════════════════════════════════════════════════
// 6. 判定层口径（§3.0）：truth 字段逐项对账
// ════════════════════════════════════════════════════════════════════════

const SAMPLE = ['placeholder', 'value', 'not', 'a', 'secret'].join('-')
const DEFAULTS = JSON.parse(
  readFileSync(new URL('../lib/traceproof/verbs/session-replay/data/session-replay-defaults.json', import.meta.url), 'utf8'),
)

for (const entry of samples) {
  const label = `${entry.harness}/${entry.sample}`
  const loaded = loadSample(entry)
  for (const episode of loaded.split.episodes) {
    test(`session-replay truth ${label}: episode bug_term 来自词表并出现在用户报告`, () => {
      assert.ok(DEFAULTS.vocabulary.bug_terms.includes(episode.bug_term))
      const report = (loaded.truth.expect.user_report_fragments ?? []).join(' ').toLowerCase()
      assert.ok(report.includes(episode.bug_term.toLowerCase()))
    })

    test(`session-replay truth ${label}: score = breakdown 之和且不低于阈值`, () => {
      const sum = Object.values(episode.score_breakdown).reduce((total, value) => total + value, 0)
      assert.equal(episode.score, sum)
      assert.ok(episode.score >= DEFAULTS.scoring.min_score)
    })

    test(`session-replay truth ${label}: episode_id = <session>#<首次修复 seq>`, () => {
      assert.equal(episode.episode_id, `${episode.session_id}#${episode.edits[0].seq}`)
    })
  }

  for (const expected of loaded.truth.expect_reconstructions ?? []) {
    const found = loaded.recons.filter((item) => item.path === expected.file).slice(-1)[0]
    test(`session-replay truth ${label}: 还原来源 ${expected.file}`, () => {
      assert.equal(found.source, expected.source)
    })
    test(`session-replay truth ${label}: hunk 数 ${expected.file}`, () => {
      assert.equal(found.hunks, expected.hunk_count)
    })
  }
}

test('session-replay truth doc-only: 丢弃原因含 docs_only', () => {
  const loaded = loadSample({ harness: 'claude', sample: 'doc-only-1' })
  assert.ok(loaded.split.filtered.some((item) => item.reason === 'docs_only'))
})

test('session-replay truth no-failure: 丢弃原因含 no_failure_evidence', () => {
  const loaded = loadSample({ harness: 'claude', sample: 'no-failure-signal-1' })
  assert.ok(loaded.split.filtered.some((item) => item.reason === 'no_failure_evidence'))
})

// ════════════════════════════════════════════════════════════════════════
// 7. 三条判定 × 三态（claim / refuted / inconclusive）
// ════════════════════════════════════════════════════════════════════════

function verdictFor(subject, claim) {
  return runOrgan({ ...subject, claims: [claim] })[0].verdict
}

function invalidSubject() {
  const records = readFileSync(join(ROOT, 'sessions', 'invalid', 'unsupported-format-1.jsonl'), 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line))
  return { session: { records }, repo: { files: {} } }
}

function threeStates(name, buildSubject, claimBase, flipped, thirdMutator) {
  test(`three-state ${name}: claim`, () => {
    assert.equal(verdictFor(buildSubject(), { ...claimBase, asserted: claimBase.asserted, node: NODE }), CLAIM)
  })
  test(`three-state ${name}: refuted`, () => {
    assert.equal(verdictFor(buildSubject(), { ...claimBase, asserted: flipped, node: NODE }), 'refuted')
  })
  test(`three-state ${name}: inconclusive`, () => {
    const mutated = thirdMutator === undefined ? buildSubject() : thirdMutator(buildSubject())
    const claim = { ...claimBase, asserted: flipped, node: thirdMutator === undefined ? undefined : NODE }
    assert.equal(verdictFor(mutated, claim), INCONCLUSIVE)
  })
}

threeStates(
  'episode',
  () => subjectFor(HAPPY, []),
  { claim_id: 'c', check: 'episode', asserted: 'present' },
  'absent',
)

threeStates(
  'reconstruction',
  () => subjectFor(HAPPY, []),
  { claim_id: 'c', check: 'reconstruction', path: '/demo/alpha/src/calc.py', asserted: 'ok' },
  'partial',
  () => invalidSubject(),
)

threeStates(
  'failure-signal',
  () => subjectFor(HAPPY, []),
  { claim_id: 'c', check: 'failure-signal', asserted: 'present' },
  'absent',
  () => invalidSubject(),
)

// ════════════════════════════════════════════════════════════════════════
// 8. 节点不完整降级 + 脱敏前置
// ════════════════════════════════════════════════════════════════════════

test('node: 缺 turn -> 内核降级 inconclusive 并写明缺失项', () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'c', check: 'episode', asserted: 'present', node: { session_id: 's', tool_call_id: 't' } },
  ])
  const record = runOrgan(subject, Basis.fromObject({ version: 'v1', nodes: [{ session_id: 's', tool_call_id: 't' }] }))[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /痕迹节点不完整/)
  assert.match(record.message, /turn/)
})

test('node: 空 tool_call_id -> 内核降级并写明 tool_call_id', () => {
  const subject = subjectFor(HAPPY, [
    { claim_id: 'c', check: 'episode', asserted: 'present', node: { session_id: 's', turn: 1, tool_call_id: '' } },
  ])
  const record = runOrgan(subject, Basis.fromObject({ version: 'v1', nodes: [{ session_id: 's', turn: 1, tool_call_id: '' }] }))[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /tool_call_id/)
})

test('redaction: 敏感键在 makeRecord 内即被替换（不是先入库再打码）', () => {
  const record = makeRecord({
    claim_id: 'c0',
    verdict: CLAIM,
    message: 'x',
    node: makeNode({ session_id: 's', turn: 1, tool_call_id: 't' }),
    evidence: { api_key: SAMPLE, nested: { token: SAMPLE } },
  })
  assert.equal(record.evidence.api_key, MASK)
  assert.deepEqual(record.evidence.nested, { token: MASK })
  assert.equal(JSON.stringify(record).includes(SAMPLE), false)
})

test('redaction: 器官证据里不出现占位敏感串', () => {
  const records = runOrgan(
    subjectFor(HAPPY, [{ claim_id: 'c', check: 'episode', asserted: 'present', node: NODE }]),
  )
  assert.equal(JSON.stringify(records).includes(SAMPLE), false)
})

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'traceproof-session-replay-'))
}

async function capture(fn) {
  const out = []
  const err = []
  const stdout = process.stdout.write.bind(process.stdout)
  const stderr = process.stderr.write.bind(process.stderr)
  process.stdout.write = (chunk) => {
    out.push(String(chunk))
    return true
  }
  process.stderr.write = (chunk) => {
    err.push(String(chunk))
    return true
  }
  try {
    const code = await fn()
    return { code, out: out.join(''), err: err.join('') }
  } finally {
    process.stdout.write = stdout
    process.stderr.write = stderr
  }
}