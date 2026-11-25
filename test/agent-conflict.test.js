/**
 * agent-conflict 器官的无损测试。
 *
 * 数据面：旧仓 `bench/scenarios/` 的 7 个场景（truth.json + repo 基线文件，只读拷贝）。
 * 每个场景逐条对账：
 *  - `levels_expected` / `levels_forbidden`（粒度集合精确匹配，多报漏报都算失败）；
 *  - `pair.symbol_relation`（same / different / adjacent / cross_file）；
 *  - 三条主张（conflict / block / symbol-relation）的 verdict。
 *
 * 另加符号扫描 / 区间判定 / 降级纪律 / 器官契约的单元用例。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
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
  makeNode,
  makeRecord,
  recordToJSON,
} from '../lib/traceproof/core/ledger.js'
import { MASK, isSensitiveKey } from '../lib/traceproof/core/redact.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  detectConflicts,
  rangeGap as conflictRangeGap,
} from '../lib/traceproof/verbs/agent-conflict/index.js'
import {
  innermostPair,
  overlaps,
  pairSymbolHit,
  rangeGap,
  symbolSpans,
  symbolsTouching,
} from '../lib/traceproof/verbs/agent-conflict/symbols.js'

await loadBuiltin()

const ROOT = fileURLToPath(new URL('./fixtures/agent-conflict/', import.meta.url))
const SCENARIOS = ['negative_no_overlap', 'same_file_diff_symbol', 'same_symbol_diff_lines', 'subagent_derived', 'threshold_exact', 'threshold_near_miss', 'whole_file_overwrite']

const NODE = { session_id: 's-radar-1', turn: 4, tool_call_id: 'call-radar-4' }

function basisOf(nodes = [NODE]) {
  return Basis.fromObject({ version: '2026.11.25', nodes })
}

function runOrgan(subject, basis = basisOf()) {
  return [...get('agent-conflict').evaluate(subject, basis)]
}

function loadScenario(name) {
  const dir = join(ROOT, name)
  const truth = JSON.parse(readFileSync(join(dir, 'truth.json'), 'utf8'))
  const geometry = truth.geometry
  const files = {}
  for (const path of Object.keys(geometry.symbols)) {
    files[path] = readFileSync(join(dir, 'repo', path), 'utf8')
  }
  const sides = geometry.sides
  const sessions = sides.map((side, index) => ({
    id: side.session,
    workspace: index === 0 ? 'ws-1' : 'ws-2',
    derived_from: geometry.pair.derived_same_parent ? 'parent-1' : null,
    writes: [{ path: side.path, kind: side.kind, ranges: [side.changed] }],
  }))
  const conflictExpected = truth.git_expected_merge_exit === 1
  const mergeTrees = [
    {
      a: 'ws-1',
      b: 'ws-2',
      status: conflictExpected ? 'conflict' : truth.git_expected_merge_exit === 128 ? 'error' : 'ok',
      paths: conflictExpected ? [sides[0].path] : [],
    },
  ]
  const claimedRelation =
    truth.levels_expected.includes('symbol')
      ? geometry.pair.symbol_relation === 'same'
        ? 'same'
        : 'adjacent'
      : geometry.pair.symbol_relation === 'same'
        ? 'same'
        : geometry.pair.same_file
          ? 'different'
          : 'cross_file'
  const subject = {
    repo: { files },
    sessions,
    merge_trees: mergeTrees,
    claims: [
      {
        claim_id: 'c-conflict',
        check: 'conflict',
        path: sides[0].path,
        asserted: truth.levels_expected.length > 0 ? 'conflict' : 'none',
        node: NODE,
      },
      {
        claim_id: 'c-block',
        check: 'block',
        path: sides[0].path,
        workspace_a: 'ws-1',
        workspace_b: 'ws-2',
        asserted: conflictExpected ? 'conflict' : 'none',
        node: NODE,
      },
      {
        claim_id: 'c-symbol',
        check: 'symbol-relation',
        path: sides[0].path,
        session_a: sides[0].session,
        session_b: sides[1].session,
        asserted: claimedRelation,
        node: NODE,
      },
    ],
  }
  const conflicts = detectConflicts(files, sessions, mergeTrees)
  return { truth, geometry, files, sessions, mergeTrees, subject, conflicts, claimedRelation }
}

// ════════════════════════════════════════════════════════════════════════
// 1. 基准矩阵逐场景对账（7 × 4 字段）
// ════════════════════════════════════════════════════════════════════════

for (const name of SCENARIOS) {
  test(`agent-conflict bench ${name}: levels 精确匹配 expected`, () => {
    const { truth, conflicts } = loadScenario(name)
    const actual = conflicts.length === 0 ? [] : conflicts[0].levels
    assert.deepEqual([...actual].sort(), [...truth.levels_expected].sort())
  })

  test(`agent-conflict bench ${name}: levels 不含 forbidden`, () => {
    const { truth, conflicts } = loadScenario(name)
    const actual = conflicts.length === 0 ? [] : conflicts[0].levels
    for (const forbidden of truth.levels_forbidden) {
      assert.equal(actual.includes(forbidden), false, `不应命中 ${forbidden}`)
    }
  })

  test(`agent-conflict bench ${name}: 符号关系 = ${'pair.symbol_relation'}`, () => {
    const { truth, geometry, conflicts, claimedRelation } = loadScenario(name)
    if (truth.levels_expected.length === 0) {
      assert.equal(conflicts.length, 0)
      assert.equal(claimedRelation, geometry.pair.same_file ? 'same' : 'cross_file')
      return
    }
    if (!geometry.pair.same_file) {
      assert.equal(conflicts.length, 0)
      assert.equal(claimedRelation, 'cross_file')
      return
    }
    const conflict = conflicts[0]
    if (truth.levels_expected.includes('symbol')) {
      assert.ok(conflict.symbols.length > 0)
      if (geometry.pair.symbol_relation === 'same') {
        assert.equal(conflict.severity_key, 'same_symbol')
      } else {
        assert.equal(conflict.severity_key, 'adjacent_lines')
      }
    } else {
      assert.equal(conflict.symbols.length, 0)
    }
  })

  test(`agent-conflict bench ${name}: 三条主张全部 claim`, () => {
    const { subject } = loadScenario(name)
    const records = runOrgan(subject)
    assert.equal(records.length, 3)
    for (const record of records) {
      assert.equal(record.verdict, CLAIM, record.message)
    }
  })

  test(`agent-conflict bench ${name}: severity 取自 config 数据文件`, () => {
    const { conflicts } = loadScenario(name)
    if (conflicts.length === 0) return
    const allowed = new Set([50, 30, 20, 10])
    for (const conflict of conflicts) assert.ok(allowed.has(conflict.severity))
  })
}

// ════════════════════════════════════════════════════════════════════════
// 2. 符号扫描 / 区间
// ════════════════════════════════════════════════════════════════════════

const PY = [
  'def alpha():', // 1
  '    return 1', // 2
  '', // 3
  '', // 4
  'class Outer:', // 5
  '    def beta(self):', // 6
  '        return 2', // 7
  '', // 8
  '    class Inner:', // 9
  '        async def gamma(self):', // 10
  '            return 3', // 11
  'def delta():', // 12
  '    return 4', // 13
].join('\n')

test('symbols: 取 def / class / async def 的 1-based 闭区间', () => {
  const spans = symbolSpans(PY)
  assert.deepEqual(spans.map((span) => span.name).sort(), ['Outer', 'Outer.Inner', 'Outer.Inner.gamma', 'Outer.beta', 'alpha', 'delta'])
})

test('symbols: 嵌套符号用点连接限定名', () => {
  const spans = symbolSpans(PY)
  const gamma = spans.find((span) => span.name === 'Outer.Inner.gamma')
  assert.deepEqual([gamma.start, gamma.end], [10, 11])
})

test('symbols: 函数区间不越过下一条同级语句', () => {
  const spans = symbolSpans(PY)
  const alpha = spans.find((span) => span.name === 'alpha')
  assert.deepEqual([alpha.start, alpha.end], [1, 2])
})

test('symbols: 空文件没有符号', () => {
  assert.deepEqual(symbolSpans(''), [])
})

test('symbols: 非 Python 文本不误报符号', () => {
  assert.deepEqual(symbolSpans('hello\nworld\n'), [])
})

test('symbols: 装饰器不改变 def 的起始行（与 ast.lineno 一致）', () => {
  const spans = symbolSpans('@decorator\ndef f():\n    return 1\n')
  assert.deepEqual([spans[0].name, spans[0].start, spans[0].end], ['f', 2, 3])
})

test('rangeGap: 不重叠时给中间间隔行数', () => {
  assert.equal(rangeGap([1, 10], [14, 19]), 3)
  assert.equal(rangeGap([10, 10], [14, 14]), 3)
})

test('rangeGap: 重叠时为负', () => {
  assert.equal(rangeGap([1, 5], [4, 9]), -2)
  assert.equal(rangeGap([2, 2], [2, 2]), -1)
})

test('overlaps: 端点相接算重叠', () => {
  assert.equal(overlaps([1, 3], [3, 5]), true)
  assert.equal(overlaps([1, 3], [4, 5]), false)
})

test('symbolsTouching: 部分重叠也算触及', () => {
  const spans = symbolSpans(PY)
  assert.deepEqual(symbolsTouching(spans, [2, 2]), ['alpha'])
  assert.deepEqual(symbolsTouching(spans, [7, 7]), ['Outer', 'Outer.beta'])
})

test('pairSymbolHit: 同一符号 -> same，报最内层', () => {
  const spans = symbolSpans(PY)
  const hit = pairSymbolHit(spans, [7, 7], [7, 7], 3)
  assert.equal(hit.kind, 'same')
  assert.deepEqual(hit.symbols, ['Outer.beta'])
})

test('pairSymbolHit: 相邻符号在容差内 -> adjacent', () => {
  const spans = symbolSpans(PY)
  const hit = pairSymbolHit(spans, [2, 2], [13, 13], 10)
  assert.equal(hit.kind, 'adjacent')
  assert.deepEqual(hit.symbols, ['alpha', 'delta'])
})

test('pairSymbolHit: 超出容差不升格', () => {
  const spans = symbolSpans(PY)
  assert.equal(pairSymbolHit(spans, [2, 2], [13, 13], 9).kind, '')
})

test('pairSymbolHit: 容差边界（<= 语义）', () => {
  const spans = symbolSpans(PY)
  const gap = rangeGap([2, 2], [13, 13])
  assert.equal(pairSymbolHit(spans, [2, 2], [13, 13], gap).kind, 'adjacent')
  assert.equal(pairSymbolHit(spans, [2, 2], [13, 13], gap - 1).kind, '')
})

test('pairSymbolHit: 一落到符号外 -> 不升格', () => {
  const spans = symbolSpans('def f():\n    return 1\n\n# tail comment\n')
  assert.equal(pairSymbolHit(spans, [2, 2], [4, 4], 100).kind, '')
})

test('innermostPair: 取各自最内层符号', () => {
  const spans = symbolSpans(PY)
  assert.deepEqual(innermostPair(spans, [7, 7], [11, 11]), ['Outer.beta', 'Outer.Inner.gamma'])
})

test('agent-conflict rangeGap 与符号模块同口径', () => {
  assert.equal(conflictRangeGap([1, 10], [14, 19]), rangeGap([1, 10], [14, 19]))
})

// ════════════════════════════════════════════════════════════════════════
// 3. 检测单元
// ════════════════════════════════════════════════════════════════════════

function session(id, workspace, path, ranges, extra = {}) {
  return {
    id,
    workspace,
    derived_from: null,
    writes: [{ path, kind: 'edit', ranges }],
    ...extra,
  }
}

test('detect: 跨工作区同文件 -> 文件级', () => {
  const conflicts = detectConflicts({}, [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[5, 5]])], [])
  assert.equal(conflicts.length, 1)
  assert.deepEqual(conflicts[0].levels, ['file'])
})

test('detect: 同一工作区不产出（不是跨 agent）', () => {
  const conflicts = detectConflicts({}, [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-1', 'x.py', [[2, 2]])], [])
  assert.equal(conflicts.length, 0)
})

test('detect: 不同文件不产出', () => {
  const conflicts = detectConflicts({}, [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'y.py', [[2, 2]])], [])
  assert.equal(conflicts.length, 0)
})

test('detect: 同一 parent 派生的 subagent 整对不产出', () => {
  const conflicts = detectConflicts(
    {},
    [
      session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }),
      session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p1' }),
    ],
    [],
  )
  assert.equal(conflicts.length, 0)
})

test('detect: 不同 parent 的 subagent 仍产出', () => {
  const conflicts = detectConflicts(
    {},
    [
      session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }),
      session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p2' }),
    ],
    [],
  )
  assert.equal(conflicts.length, 1)
})

test('detect: merge-tree conflict 且路径命中 -> 区块级', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [{ a: 'ws-1', b: 'ws-2', status: 'conflict', paths: ['x.py'] }],
  )
  assert.deepEqual(conflicts[0].levels, ['file', 'block'])
})

test('detect: merge-tree conflict 但路径不在冲突清单 -> 无区块级', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [{ a: 'ws-1', b: 'ws-2', status: 'conflict', paths: ['other.py'] }],
  )
  assert.deepEqual(conflicts[0].levels, ['file'])
})

test('detect: 没有 merge-tree 证据 -> degraded 且只给文件级', () => {
  const conflicts = detectConflicts({}, [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], [])
  assert.equal(conflicts[0].degraded, true)
  assert.ok(conflicts[0].degrade_reasons.length > 0)
})

test('detect: merge-tree 环境错误 -> degraded（§降级纪律）', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [{ a: 'ws-1', b: 'ws-2', status: 'error', paths: [] }],
  )
  assert.equal(conflicts[0].degraded, true)
  assert.equal(conflicts[0].levels.includes('block'), false)
})

test('detect: Python 基线可有符号级', () => {
  const conflicts = detectConflicts(
    { 'x.py': PY },
    [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])],
    [],
  )
  assert.deepEqual(conflicts[0].levels, ['file', 'symbol'])
  assert.deepEqual(conflicts[0].symbols, ['alpha'])
})

test('detect: 非 Python 文件 approximate 且无符号级', () => {
  const conflicts = detectConflicts(
    { 'x.md': 'hello\nworld\n' },
    [session('a', 'ws-1', 'x.md', [[1, 1]]), session('b', 'ws-2', 'x.md', [[1, 1]])],
    [],
  )
  assert.equal(conflicts[0].approximate, true)
  assert.deepEqual(conflicts[0].levels, ['file'])
  assert.deepEqual(conflicts[0].symbols, [])
})

test('detect: 缺基线内容 -> approximate 且只给文件级', () => {
  const conflicts = detectConflicts({}, [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], [])
  assert.equal(conflicts[0].approximate, true)
})

test('detect: severity_key 按命中形态分档', () => {
  const same = detectConflicts({ 'x.py': PY }, [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])], [])
  assert.equal(same[0].severity_key, 'same_symbol')
  assert.equal(same[0].severity, 50)
})

test('detect: 同文件不同符号 -> same_file_diff_symbol', () => {
  const conflicts = detectConflicts(
    { 'x.py': PY },
    [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[7, 7]])],
    [],
  )
  assert.equal(conflicts[0].severity_key, 'same_file_diff_symbol')
})

test('detect: 非 Python -> file_only', () => {
  const conflicts = detectConflicts({ 'x.md': 'a\n' }, [session('a', 'ws-1', 'x.md', [[1, 1]]), session('b', 'ws-2', 'x.md', [[1, 1]])], [])
  assert.equal(conflicts[0].severity_key, 'file_only')
})

test('detect: 排序确定（同路径按粒度与严重度）', () => {
  const sessions = [
    session('a', 'ws-1', 'x.py', [[2, 2]]),
    session('b', 'ws-2', 'x.py', [[2, 2]]),
    session('c', 'ws-1', 'y.py', [[1, 1]]),
    session('d', 'ws-2', 'y.py', [[1, 1]]),
  ]
  const first = detectConflicts({ 'x.py': PY, 'y.py': 'def z():\n    return 1\n' }, sessions, [])
  const second = detectConflicts({ 'x.py': PY, 'y.py': 'def z():\n    return 1\n' }, [...sessions].reverse(), [])
  assert.deepEqual(first.map((item) => [item.path, item.levels]), second.map((item) => [item.path, item.levels]))
})

test('detect: 三条写记录在同文件不同区间仍只出一条组合', () => {
  const sessions = [
    { id: 'a', workspace: 'ws-1', derived_from: null, writes: [
      { path: 'x.md', kind: 'edit', ranges: [[1, 1]] },
      { path: 'x.md', kind: 'edit', ranges: [[3, 3]] },
    ] },
    session('b', 'ws-2', 'x.md', [[1, 1]]),
  ]
  assert.equal(detectConflicts({}, sessions, []).length, 1)
})

// ════════════════════════════════════════════════════════════════════════
// 4. 器官契约与 CLI
// ════════════════════════════════════════════════════════════════════════

test('organ: list 含 agent-conflict 且按 slug 排序', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  const slugs = out
    .split('\n')
    .filter(Boolean)
    .map((line) => line.trim().split(/\s+/)[0])
  assert.deepEqual(slugs, [...slugs].sort())
  assert.ok(slugs.includes('agent-conflict'))
})

test('organ: 主张错误 + 有节点 -> refuted', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'none', node: NODE },
  ]
  assert.equal(runOrgan(subject)[0].verdict, 'refuted')
})

test('organ: 主张错误 + 无节点 -> inconclusive', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'none' },
  ]
  const record = runOrgan(subject)[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /不能下 refuted/)
})

test('organ: 节点不在 basis -> NodeMissing', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'conflict', node: { session_id: 's-radar-1', turn: 99, tool_call_id: 'x' } },
  ]
  assert.throws(() => runOrgan(subject), NodeMissing)
})

test('organ: 缺 merge-tree 时 block 主张 -> inconclusive 并列出缺失项', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  delete subject.merge_trees
  subject.claims = [
    { claim_id: 'c1', check: 'block', path: 'src/alpha.py', workspace_a: 'ws-1', workspace_b: 'ws-2', asserted: 'none', node: NODE },
  ]
  const record = runOrgan(subject)[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /merge-tree/)
})

test('organ: 只有一个工作区时 block -> inconclusive', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.sessions = subject.sessions.map((session) => ({ ...session, workspace: 'ws-1' }))
  subject.claims = [
    { claim_id: 'c1', check: 'block', path: 'src/alpha.py', asserted: 'none', node: NODE },
  ]
  const record = runOrgan(subject)[0]
  assert.equal(record.verdict, INCONCLUSIVE)
})

test('organ: symbol-relation 缺 session_a/b -> inconclusive', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [{ claim_id: 'c1', check: 'symbol-relation', path: 'src/alpha.py', asserted: 'same', node: NODE }]
  assert.equal(runOrgan(subject)[0].verdict, INCONCLUSIVE)
})

test('organ: symbol-relation 会话不存在 -> inconclusive 并列出缺失项', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'c1', check: 'symbol-relation', path: 'src/alpha.py', session_a: 'nope-1', session_b: 'nope-2', asserted: 'same', node: NODE },
  ]
  const record = runOrgan(subject)[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /nope-1/)
})

test('organ: 同工作区两侧 -> cross_file', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.sessions = subject.sessions.map((session) => ({ ...session, workspace: 'ws-1' }))
  subject.claims = [
    { claim_id: 'c1', check: 'symbol-relation', path: 'src/alpha.py', session_a: 'sess-radar-0003', session_b: 'sess-radar-0004', asserted: 'cross_file', node: NODE },
  ]
  assert.equal(runOrgan(subject)[0].verdict, CLAIM)
})

test('organ: claim_id 重复 -> ContractError', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'dup', check: 'conflict', path: 'src/alpha.py', asserted: 'conflict', node: NODE },
    { claim_id: 'dup', check: 'conflict', path: 'src/alpha.py', asserted: 'conflict', node: NODE },
  ]
  assert.throws(() => runOrgan(subject), ContractError)
})

test('organ: 未知 claim 字段 -> ContractError', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'conflict', node: NODE, extra: true },
  ]
  assert.throws(() => runOrgan(subject), /未知字段/)
})

test('organ: asserted 闭集之外 -> ContractError', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [{ claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'maybe', node: NODE }]
  assert.throws(() => runOrgan(subject), /asserted 非法/)
})

test('organ: 非法 ranges -> ContractError', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.sessions[0].writes[0].ranges = [[0, 2]]
  assert.throws(() => runOrgan(subject), /1-based/)
})

test('organ: 证据里没有绝对路径', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  const records = runOrgan(subject)
  assert.equal(JSON.stringify(records).includes(ROOT), false)
})

test('organ: 两次运行账本字节一致', async () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const args = ['check', 'agent-conflict', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json'), '--json']
  const first = await capture(() => main(args))
  const second = await capture(() => main(args))
  assert.equal(first.code, EXIT_OK)
  assert.equal(first.out, second.out)
})

test('cli: 全 claim -> 0', async () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'agent-conflict', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_OK)
})

test('cli: 存在 refuted -> 1', async () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [{ claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'none', node: NODE }]
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'agent-conflict', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_BLOCKED)
})

test('cli: 输入文件缺失 -> 2', async () => {
  const dir = tmpDir()
  const { code } = await capture(() => main(['check', 'agent-conflict', '--input', join(dir, 'nope.json')]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: 缺必填字段（sessions）-> 2', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ repo: { files: {} }, claims: [] }))
  const { code } = await capture(() => main(['check', 'agent-conflict', '--input', join(dir, 'in.json')]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: 节点缺失 -> 3', async () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  subject.claims = [
    { claim_id: 'c1', check: 'conflict', path: 'src/alpha.py', asserted: 'conflict', node: { session_id: 'nope', turn: 1, tool_call_id: 'x' } },
  ]
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code, err } = await capture(() =>
    main(['check', 'agent-conflict', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: 痕迹包缺版本 -> 3', async () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'agent-conflict', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
})

test('organ: 内核脱敏结构面仍在', () => {
  const record = makeNode({ session_id: 's', turn: 1, tool_call_id: 'c' })
  assert.equal(record.complete, true)
})

// 目录里每个场景都有 truth.json（防夹具漏拷）
test('fixtures: 7 个场景的 truth.json 都在位', () => {
  const dirs = readdirSync(ROOT, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort()
  assert.deepEqual(dirs, [...SCENARIOS].sort())
  for (const name of SCENARIOS) assert.ok(readFileSync(join(ROOT, name, 'truth.json')).length > 0)
})

// ════════════════════════════════════════════════════════════════════════
// 6. 判定层口径（§3.0）：truth 字段逐项对账
// ════════════════════════════════════════════════════════════════════════

const SAMPLE = ['placeholder', 'value', 'not', 'a', 'secret'].join('-')
const SEVERITY = { same_symbol: 50, same_file_diff_symbol: 30, adjacent_lines: 20, file_only: 10 }

function symbolObject(source) {
  const out = {}
  for (const span of symbolSpans(source)) out[span.name] = [span.start, span.end]
  return out
}

function overlapCount(left, right) {
  let count = 0
  for (let line = left[0]; line <= left[1]; line += 1) {
    if (line >= right[0] && line <= right[1]) count += 1
  }
  return count
}

const FIELD_CHECKS = [
  ['same_file', ({ sessions, geometry }) =>
    assert.equal(sessions[0].writes[0].path === sessions[1].writes[0].path, geometry.pair.same_file)],
  ['gap_lines', ({ geometry }) => {
    if (!geometry.pair.same_file) {
      assert.equal(geometry.pair.gap_lines, null)
      return
    }
    assert.equal(rangeGap(geometry.sides[0].changed, geometry.sides[1].changed), geometry.pair.gap_lines)
  }],
  ['overlap_lines', ({ geometry }) => {
    if (!geometry.pair.same_file) {
      assert.equal(geometry.pair.overlap_lines, 0)
      return
    }
    assert.equal(overlapCount(geometry.sides[0].changed, geometry.sides[1].changed), geometry.pair.overlap_lines)
  }],
  ['derived_same_parent', ({ geometry, conflicts }) => {
    if (geometry.pair.derived_same_parent) assert.equal(conflicts.length, 0)
    else assert.ok(true)
  }],
  ['level_is_max', ({ conflicts }) => {
    if (conflicts.length === 0) return
    const rank = { file: 0, block: 1, symbol: 2 }
    const highest = [...conflicts[0].levels].sort((a, b) => rank[a] - rank[b]).pop()
    assert.equal(conflicts[0].level, highest)
  }],
  ['severity_key', ({ conflicts, claimedRelation }) => {
    if (conflicts.length === 0) return
    const expected = claimedRelation === 'same' ? 'same_symbol' : claimedRelation === 'adjacent' ? 'adjacent_lines' : 'same_file_diff_symbol'
    assert.equal(conflicts[0].severity_key, expected)
  }],
  ['severity_weight', ({ conflicts, claimedRelation }) => {
    if (conflicts.length === 0) return
    assert.equal(conflicts[0].severity, SEVERITY[conflicts[0].severity_key])
  }],
  ['line_ranges', ({ geometry, conflicts }) => {
    if (conflicts.length === 0) return
    assert.deepEqual(conflicts[0].line_ranges, [geometry.sides[0].changed, geometry.sides[1].changed])
  }],
  ['sessions_a_b', ({ geometry, conflicts }) => {
    if (conflicts.length === 0) return
    assert.deepEqual(conflicts[0].sessions_a, [geometry.sides[0].session])
    assert.deepEqual(conflicts[0].sessions_b, [geometry.sides[1].session])
  }],
  ['workspaces', ({ conflicts }) => {
    if (conflicts.length === 0) return
    assert.equal(conflicts[0].workspace_a, 'ws-1')
    assert.equal(conflicts[0].workspace_b, 'ws-2')
  }],
  ['symbols', ({ geometry, conflicts, claimedRelation }) => {
    if (conflicts.length === 0) return
    if (claimedRelation === 'different') {
      assert.deepEqual(conflicts[0].symbols, [])
      return
    }
    const expected = claimedRelation === 'adjacent'
      ? [...new Set([geometry.sides[0].symbol, geometry.sides[1].symbol])]
      : [geometry.sides[0].symbol]
    assert.deepEqual(conflicts[0].symbols, expected)
  }],
  ['flags', ({ conflicts, files, geometry }) => {
    if (conflicts.length === 0) return
    assert.equal(conflicts[0].approximate, false)
    assert.equal(conflicts[0].degraded, false)
    assert.equal(geometry.pair.same_file, true)
    assert.ok(files[geometry.sides[0].path].length > 0)
  }],
]

for (const name of SCENARIOS) {
  const context = loadScenario(name)
  for (const [field, check] of FIELD_CHECKS) {
    test(`agent-conflict truth ${name}: ${field}`, () => check(context))
  }
  for (const path of Object.keys(context.geometry.symbols)) {
    test(`agent-conflict truth ${name}: symbol_spans ${path}`, () => {
      assert.deepEqual(symbolObject(context.files[path]), context.geometry.symbols[path])
    })
  }
}

// ════════════════════════════════════════════════════════════════════════
// 7. 符号 / 区间判据的边界表
// ════════════════════════════════════════════════════════════════════════

const SPAN_CASES = [
  { name: '单函数', source: 'def f():\n    return 1\n', expect: { f: [1, 2] } },
  { name: '相邻函数', source: 'def a():\n    return 1\n\ndef b():\n    return 2\n', expect: { a: [1, 2], b: [4, 5] } },
  { name: '类与方法', source: 'class A:\n    def f(self):\n        return 1\n', expect: { A: [1, 3], 'A.f': [2, 3] } },
  { name: '嵌套类', source: 'class A:\n    class B:\n        def f(self):\n            return 1\n', expect: { A: [1, 4], 'A.B': [2, 4], 'A.B.f': [3, 4] } },
  { name: 'async', source: 'async def f():\n    return 1\n', expect: { f: [1, 2] } },
  { name: '装饰器', source: '@d\ndef f():\n    return 1\n', expect: { f: [2, 3] } },
  { name: '单行函数', source: 'def f(): return 1\n', expect: { f: [1, 1] } },
  { name: '尾注释不计入结束行', source: 'def f():\n    return 1\n    # trailing\n\n\ndef g():\n    return 2\n', expect: { f: [1, 2], g: [6, 7] } },
  { name: '函数内空行不截断', source: 'def f():\n    a = 1\n\n    b = 2\n\n\ndef g():\n    return 3\n', expect: { f: [1, 4], g: [7, 8] } },
  { name: 'tab 缩进', source: 'class K:' + '\n\tdef f(self):\n\t\treturn 1\n', expect: { K: [1, 3], 'K.f': [2, 3] } },
  { name: '空源', source: '', expect: {} },
  { name: '非 Python 文本', source: 'hello\nworld\n', expect: {} },
]

for (const testCase of SPAN_CASES) {
  test(`symbols case ${testCase.name}`, () => {
    assert.deepEqual(symbolObject(testCase.source), testCase.expect)
  })
}

const GAP_CASES = [
  ['区间之间隔 3 行', [1, 10], [14, 19], 3],
  ['同起点不同长度', [10, 10], [14, 14], 3],
  ['部分重叠', [1, 5], [4, 9], -2],
  ['完全相同', [2, 2], [2, 2], -1],
  ['首尾相接', [1, 3], [4, 5], 0],
  ['中间隔 1 行', [1, 1], [3, 3], 1],
  ['中间隔 2 行', [1, 2], [5, 6], 2],
  ['包含关系', [1, 10], [2, 3], -3],
]

for (const [name, left, right, expected] of GAP_CASES) {
  test(`rangeGap case ${name}`, () => assert.equal(rangeGap(left, right), expected))
}

const ADJ_SOURCE = 'def f():\n    return 1\n\ndef g():\n    return 2\n'
const NESTED_SOURCE = 'class A:\n    def f(self):\n        return 1\n'
const FAR_SOURCE = 'def f():\n    return 1\n\n\n\n\n\ndef g():\n    return 2\n'

const PAIR_CASES = [
  { name: '同符号同一行', source: ADJ_SOURCE, left: [2, 2], right: [2, 2], tolerance: 3, kind: 'same', symbols: ['f'] },
  { name: '同符号部分重叠', source: ADJ_SOURCE, left: [1, 2], right: [2, 2], tolerance: 3, kind: 'same', symbols: ['f'] },
  { name: '嵌套只报最内层', source: NESTED_SOURCE, left: [2, 2], right: [3, 3], tolerance: 3, kind: 'same', symbols: ['A.f'] },
  { name: '相邻容差内', source: ADJ_SOURCE, left: [2, 2], right: [4, 4], tolerance: 1, kind: 'adjacent', symbols: ['f', 'g'] },
  { name: '相邻容差外', source: ADJ_SOURCE, left: [2, 2], right: [4, 4], tolerance: 0, kind: '', symbols: [] },
  { name: '不同符号相距远', source: FAR_SOURCE, left: [2, 2], right: [10, 10], tolerance: 3, kind: '', symbols: [] },
  { name: '一侧落在符号外（空行）', source: ADJ_SOURCE, left: [3, 3], right: [2, 2], tolerance: 99, kind: '', symbols: [] },
  { name: '无符号', source: '', left: [1, 1], right: [2, 2], tolerance: 99, kind: '', symbols: [] },
  { name: '装饰器行不算符号内', source: '@d\ndef f():\n    return 1\n', left: [1, 1], right: [2, 2], tolerance: 99, kind: '', symbols: [] },
  { name: '类与自身方法', source: NESTED_SOURCE, left: [1, 1], right: [3, 3], tolerance: 99, kind: 'same', symbols: ['A'] },
  { name: '同符号多点改动', source: ADJ_SOURCE, left: [1, 1], right: [2, 2], tolerance: 0, kind: 'same', symbols: ['f'] },
  { name: '相邻容差 0 相接', source: ADJ_SOURCE, left: [2, 2], right: [3, 3], tolerance: 99, kind: '', symbols: [] },
]

for (const testCase of PAIR_CASES) {
  test(`pairSymbolHit case ${testCase.name}`, () => {
    const hit = pairSymbolHit(symbolSpans(testCase.source), testCase.left, testCase.right, testCase.tolerance)
    assert.equal(hit.kind, testCase.kind)
    assert.deepEqual(hit.symbols, testCase.symbols)
  })
}

// ════════════════════════════════════════════════════════════════════════
// 8. 检测判据表（每条规则一个独立输入）
// ════════════════════════════════════════════════════════════════════════

const BASIC = { 'x.py': ADJ_SOURCE }
const CONFLICT_MERGE = [{ a: 'ws-1', b: 'ws-2', status: 'conflict', paths: ['x.py'] }]

const DETECT_CASES = [
  { name: '无写记录', files: {}, sessions: [], merge: [], expect: { count: 0 } },
  { name: '同工作区不产出', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-1', 'x.py', [[2, 2]])], merge: [], expect: { count: 0 } },
  { name: '不同文件不产出', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'y.py', [[2, 2]])], merge: [], expect: { count: 0 } },
  { name: '缺 merge 证据', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[5, 5]])], merge: [], expect: { count: 1, levels: ['file'], degraded: true, approximate: true, severity_key: 'file_only', severity: 10 } },
  { name: 'merge 冲突命中路径', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: CONFLICT_MERGE, expect: { count: 1, levels: ['file', 'block'], degraded: false, level: 'block' } },
  { name: 'merge 冲突在别的路径', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [{ a: 'ws-1', b: 'ws-2', status: 'conflict', paths: ['y.py'] }], expect: { levels: ['file'] } },
  { name: 'merge ok', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [{ a: 'ws-1', b: 'ws-2', status: 'ok', paths: [] }], expect: { levels: ['file'], degraded: false } },
  { name: 'merge 环境错误', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [{ a: 'ws-1', b: 'ws-2', status: 'error', paths: [] }], expect: { levels: ['file'], degraded: true } },
  { name: 'merge 记录 a/b 反向', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [{ a: 'ws-2', b: 'ws-1', status: 'conflict', paths: ['x.py'] }], expect: { levels: ['file', 'block'] } },
  { name: '同符号', files: BASIC, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])], merge: [], expect: { levels: ['file', 'symbol'], symbols: ['f'], severity_key: 'same_symbol', severity: 50 } },
  { name: '相邻符号容差内', files: BASIC, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[4, 4]])], merge: [], expect: { levels: ['file', 'symbol'], symbols: ['f', 'g'], severity_key: 'adjacent_lines', severity: 20 } },
  { name: '符号相距远（不升格）', files: { 'x.py': FAR_SOURCE }, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[9, 9]])], merge: [], expect: { levels: ['file'], symbols: [], severity_key: 'same_file_diff_symbol', severity: 30 } },
  { name: '非 Python', files: { 'x.md': 'a\nb\n' }, sessions: [session('a', 'ws-1', 'x.md', [[1, 1]]), session('b', 'ws-2', 'x.md', [[1, 1]])], merge: [], expect: { levels: ['file'], approximate: true, symbols: [] } },
  { name: '缺基线内容', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [], expect: { levels: ['file'], approximate: true } },
  { name: 'subagent 同 parent', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }), session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p1' })], merge: [], expect: { count: 0 } },
  { name: 'subagent 不同 parent', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }), session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p2' })], merge: [], expect: { count: 1 } },
  { name: '三个工作区', files: {}, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]]), session('c', 'ws-3', 'x.py', [[1, 1]])], merge: [], expect: { count: 3 } },
  { name: '两条路径排序', files: {}, sessions: [session('a', 'ws-1', 'y.py', [[1, 1]]), session('b', 'ws-2', 'y.py', [[1, 1]]), session('c', 'ws-1', 'x.py', [[1, 1]]), session('d', 'ws-2', 'x.py', [[1, 1]])], merge: [], expect: { count: 2, paths: ['x.py', 'y.py'] } },
  { name: '一工作区多会话', files: {}, sessions: [session('a1', 'ws-1', 'x.py', [[1, 1]]), session('a2', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[3, 3]])], merge: [], expect: { count: 2 } },
  { name: '空 ranges 跳过', files: {}, sessions: [session('a', 'ws-1', 'x.py', []), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [], expect: { count: 0 } },
  { name: 'levels 规范序', files: { 'x.py': ADJ_SOURCE }, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])], merge: CONFLICT_MERGE, expect: { levels: ['file', 'block', 'symbol'] } },
  { name: 'level 取最高', files: { 'x.py': ADJ_SOURCE }, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])], merge: CONFLICT_MERGE, expect: { level: 'symbol' } },
  { name: '输入反序结果相同', files: { 'x.py': ADJ_SOURCE }, sessions: [session('b', 'ws-2', 'x.py', [[2, 2]]), session('a', 'ws-1', 'x.py', [[2, 2]])], merge: [], expect: { levels: ['file', 'symbol'], sessions: ['a', 'b'] } },
  { name: '多写记录合并成一条', files: { 'x.md': 'a\nb\nc\n' }, sessions: [{ id: 'a', workspace: 'ws-1', derived_from: null, writes: [{ path: 'x.md', kind: 'edit', ranges: [[1, 1]] }, { path: 'x.md', kind: 'edit', ranges: [[3, 3]] }] }, session('b', 'ws-2', 'x.md', [[1, 1]])], merge: [], expect: { count: 1, line_ranges: [[1, 1], [1, 1]] } },
  { name: '两个 session 同 workspace 各成一组', files: {}, sessions: [session('a1', 'ws-1', 'x.py', [[1, 1]]), session('a2', 'ws-1', 'y.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]]), session('c', 'ws-2', 'y.py', [[1, 1]])], merge: [], expect: { count: 2 } },
]

for (const testCase of DETECT_CASES) {
  test(`detect case ${testCase.name}`, () => {
    const conflicts = detectConflicts(testCase.files, testCase.sessions, testCase.merge)
    assert.equal(conflicts.length, testCase.expect.count ?? conflicts.length)
    if (testCase.expect.levels !== undefined) assert.deepEqual(conflicts[0].levels, testCase.expect.levels)
    if (testCase.expect.level !== undefined) assert.equal(conflicts[0].level, testCase.expect.level)
    if (testCase.expect.symbols !== undefined) assert.deepEqual(conflicts[0].symbols, testCase.expect.symbols)
    if (testCase.expect.severity_key !== undefined) assert.equal(conflicts[0].severity_key, testCase.expect.severity_key)
    if (testCase.expect.severity !== undefined) assert.equal(conflicts[0].severity, testCase.expect.severity)
    if (testCase.expect.degraded !== undefined) assert.equal(conflicts[0].degraded, testCase.expect.degraded)
    if (testCase.expect.approximate !== undefined) assert.equal(conflicts[0].approximate, testCase.expect.approximate)
    if (testCase.expect.paths !== undefined) assert.deepEqual(conflicts.map((item) => item.path), testCase.expect.paths)
    if (testCase.expect.sessions !== undefined) assert.deepEqual(conflicts[0].sessions, testCase.expect.sessions)
    if (testCase.expect.line_ranges !== undefined) assert.deepEqual(conflicts[0].line_ranges, testCase.expect.line_ranges)
  })
}

// ════════════════════════════════════════════════════════════════════════
// 9. 规则 × 三态（claim / refuted / inconclusive）
// ════════════════════════════════════════════════════════════════════════

function verdictFor(subject, claim) {
  return runOrgan({ ...subject, claims: [claim] })[0].verdict
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
  'file-level',
  () => ({ repo: { files: {} }, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[5, 5]])], merge_trees: [] }),
  { claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict' },
  'none',
)

threeStates(
  'block-level',
  () => ({ repo: { files: {} }, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge_trees: CONFLICT_MERGE }),
  { claim_id: 'c', check: 'block', path: 'x.py', workspace_a: 'ws-1', workspace_b: 'ws-2', asserted: 'conflict' },
  'none',
  (subject) => ({ ...subject, merge_trees: [] }),
)

threeStates(
  'symbol-same',
  () => ({ repo: { files: BASIC }, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])], merge_trees: [] }),
  { claim_id: 'c', check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'same' },
  'adjacent',
  (subject) => ({ ...subject, repo: { files: {} } }),
)

threeStates(
  'symbol-adjacent',
  () => ({ repo: { files: BASIC }, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[4, 4]])], merge_trees: [] }),
  { claim_id: 'c', check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'adjacent' },
  'same',
  (subject) => ({ ...subject, sessions: subject.sessions.map((item) => (item.id === 'b' ? { ...item, id: 'nope' } : item)) }),
)

threeStates(
  'symbol-different',
  () => ({ repo: { files: { 'x.py': FAR_SOURCE } }, sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[9, 9]])], merge_trees: [] }),
  { claim_id: 'c', check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'different' },
  'same',
)

threeStates(
  'subagent-suppressed',
  () => ({ repo: { files: {} }, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }), session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p1' })], merge_trees: [] }),
  { claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'none' },
  'conflict',
)

threeStates(
  'same-workspace',
  () => ({ repo: { files: {} }, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-1', 'x.py', [[1, 1]])], merge_trees: [] }),
  { claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'none' },
  'conflict',
)

threeStates(
  'non-python-symbol',
  () => ({ repo: { files: { 'x.md': 'a\nb\n' } }, sessions: [session('a', 'ws-1', 'x.md', [[1, 1]]), session('b', 'ws-2', 'x.md', [[1, 1]])], merge_trees: [] }),
  { claim_id: 'c', check: 'symbol-relation', path: 'x.md', session_a: 'a', session_b: 'b', asserted: 'unavailable' },
  'same',
  (subject) => ({ ...subject, repo: { files: {} } }),
)

// ════════════════════════════════════════════════════════════════════════
// 10. 节点不完整降级 + 脱敏前置
// ════════════════════════════════════════════════════════════════════════

test('node: 缺 turn -> 内核降级 inconclusive 并写明缺失项', () => {
  const subject = { repo: { files: {} }, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])] }
  const record = runOrgan(
    { ...subject, claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict', node: { session_id: 's', tool_call_id: 't' } }] },
    Basis.fromObject({ version: 'v1', nodes: [{ session_id: 's', tool_call_id: 't' }] }),
  )[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /痕迹节点不完整/)
  assert.match(record.message, /turn/)
})

test('node: 缺 tool_call_id -> 内核降级并写明 tool_call_id', () => {
  const subject = { repo: { files: {} }, sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])] }
  const record = runOrgan(
    { ...subject, claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict', node: { session_id: 's', turn: 1, tool_call_id: '' } }] },
    Basis.fromObject({ version: 'v1', nodes: [{ session_id: 's', turn: 1 }] }),
  )[0]
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
  const { subject } = loadScenario('same_symbol_diff_lines')
  assert.equal(JSON.stringify(runOrgan(subject)).includes(SAMPLE), false)
})

// ════════════════════════════════════════════════════════════════════════
// 11. 主张 × 判据矩阵（asserted × computed 的每个格子一条）
//     §9 的三态只覆盖了「每种规则一组输入」；本节补的是同一规则下
//     asserted 取值与重算结果错位的格子，尤其是闭集里**永远不会被重算产出**
//     的值（block / symbol-relation 的 undecidable）——它们不可能是 claim。
// ════════════════════════════════════════════════════════════════════════

const NO_SYMBOL_PY = 'hello\nworld\n'
const MERGE_CONFLICT = [{ a: 'ws-1', b: 'ws-2', status: 'conflict', paths: ['x.py'] }]
const MERGE_OK = [{ a: 'ws-1', b: 'ws-2', status: 'ok', paths: [] }]
const MERGE_ERROR = [{ a: 'ws-1', b: 'ws-2', status: 'error', paths: [] }]
const WS_PAIR = () => [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])]
const BLOCK_PAIR = { workspace_a: 'ws-1', workspace_b: 'ws-2' }

const MATRIX_CASES = [
  // block：undecidable 是降级结论，不是可主张的观测值
  { name: 'block·asserted undecidable 但试合并冲突', files: {}, sessions: WS_PAIR(), merge: MERGE_CONFLICT,
    claim: { check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'undecidable' }, verdict: REFUTED, computed: 'conflict' },
  { name: 'block·asserted undecidable 但试合并成功', files: {}, sessions: WS_PAIR(), merge: MERGE_OK,
    claim: { check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'undecidable' }, verdict: REFUTED, computed: 'none' },
  { name: 'block·asserted undecidable 且无证据', files: {}, sessions: WS_PAIR(), merge: [],
    claim: { check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'undecidable' }, verdict: INCONCLUSIVE, computed: 'undecidable' },
  { name: 'block·merge-tree 环境错误则不论主张', files: {}, sessions: WS_PAIR(), merge: MERGE_ERROR,
    claim: { check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'conflict' }, verdict: INCONCLUSIVE, computed: 'undecidable' },
  // block：工作区对可以从写记录推断，也可以完全不给
  { name: 'block·只给 workspace_a 时从写记录推断工作区对', files: {}, sessions: WS_PAIR(), merge: MERGE_CONFLICT,
    claim: { check: 'block', path: 'x.py', workspace_a: 'ws-1', asserted: 'conflict' }, verdict: CLAIM, computed: 'conflict' },
  { name: 'block·写记录跨三个工作区 -> 无法选定一对', files: {},
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]]), session('c', 'ws-3', 'x.py', [[1, 1]])],
    merge: [], claim: { check: 'block', path: 'x.py', asserted: 'none' }, verdict: INCONCLUSIVE, computed: 'undecidable' },
  { name: 'block·区块级只看 merge-tree，不要求两侧都有写记录', files: {},
    sessions: [session('a', 'ws-1', 'y.py', [[1, 1]]), session('b', 'ws-2', 'y.py', [[1, 1]])], merge: MERGE_CONFLICT,
    claim: { check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'conflict' }, verdict: CLAIM, computed: 'conflict' },
  { name: 'block·merge-tree 明确不冲突 -> none 成立', files: {}, sessions: WS_PAIR(), merge: MERGE_OK,
    claim: { check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'none' }, verdict: CLAIM, computed: 'none' },
  // symbol-relation：undecidable 同样是降级结论
  { name: 'symbol·asserted undecidable 但两侧同符号', files: { 'x.py': ADJ_SOURCE },
    sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[2, 2]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'undecidable' },
    verdict: REFUTED, computed: 'same' },
  { name: 'symbol·asserted undecidable 且会话缺失', files: {},
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'gone', asserted: 'undecidable' },
    verdict: INCONCLUSIVE, computed: 'undecidable' },
  // symbol-relation：cross_file 只看「有没有共同改过」，不看基线
  { name: 'symbol·另一侧没写这个路径 -> cross_file 成立', files: {},
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'y.py', [[1, 1]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'cross_file' },
    verdict: CLAIM, computed: 'cross_file' },
  { name: 'symbol·另一侧没写这个路径但主张 same', files: {},
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'y.py', [[1, 1]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'same' },
    verdict: REFUTED, computed: 'cross_file' },
  // symbol-relation：unavailable 有两种，只有「取不到基线」才是降级
  { name: 'symbol·Python 基线里没有符号 -> unavailable 可主张', files: { 'x.py': NO_SYMBOL_PY },
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'unavailable' },
    verdict: CLAIM, computed: 'unavailable' },
  { name: 'symbol·Python 基线缺失 -> unavailable 且强制降级', files: {},
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'unavailable' },
    verdict: INCONCLUSIVE, computed: 'unavailable' },
  { name: 'symbol·Python 基线缺失但主张 same', files: {},
    sessions: [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'same' },
    verdict: INCONCLUSIVE, computed: 'unavailable' },
  { name: 'symbol·asserted different 但实际相邻', files: { 'x.py': ADJ_SOURCE },
    sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[4, 4]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'different' },
    verdict: REFUTED, computed: 'adjacent' },
  { name: 'symbol·asserted adjacent 但实际不同符号', files: { 'x.py': FAR_SOURCE },
    sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-2', 'x.py', [[9, 9]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'adjacent' },
    verdict: REFUTED, computed: 'different' },
  { name: 'symbol·两侧同工作区 -> cross_file（不判决）', files: { 'x.py': ADJ_SOURCE },
    sessions: [session('a', 'ws-1', 'x.py', [[2, 2]]), session('b', 'ws-1', 'x.py', [[2, 2]])], merge: [],
    claim: { check: 'symbol-relation', path: 'x.py', session_a: 'a', session_b: 'b', asserted: 'same' },
    verdict: REFUTED, computed: 'cross_file' },
  // conflict：工作区对是过滤器，不是提示
  { name: 'conflict·主张的工作区对与记录不符 -> 不成立', files: {}, sessions: WS_PAIR(), merge: [],
    claim: { check: 'conflict', path: 'x.py', workspace_a: 'ws-1', workspace_b: 'ws-9', asserted: 'conflict' },
    verdict: REFUTED, computed: 'none' },
  { name: 'conflict·workspace_a 命中记录的 b 侧 -> 仍成立', files: {}, sessions: WS_PAIR(), merge: [],
    claim: { check: 'conflict', path: 'x.py', workspace_a: 'ws-2', asserted: 'conflict' },
    verdict: CLAIM, computed: 'conflict' },
  { name: 'conflict·asserted 大小写与空白归一', files: {}, sessions: WS_PAIR(), merge: [],
    claim: { check: 'conflict', path: 'x.py', asserted: '  CONFLICT  ' }, verdict: CLAIM, computed: 'conflict' },
  { name: 'conflict·无写记录的路径主张 none 成立', files: {}, sessions: WS_PAIR(), merge: [],
    claim: { check: 'conflict', path: 'z.py', asserted: 'none' }, verdict: CLAIM, computed: 'none' },
]

for (const row of MATRIX_CASES) {
  test(`matrix ${row.name}`, () => {
    const subject = {
      repo: { files: row.files },
      sessions: row.sessions,
      merge_trees: row.merge,
      claims: [{ claim_id: 'c', node: NODE, ...row.claim }],
    }
    const record = runOrgan(subject)[0]
    assert.equal(record.verdict, row.verdict, record.message)
    assert.equal(record.evidence.computed, row.computed)
  })
}

// ════════════════════════════════════════════════════════════════════════
// 12. 痕迹节点不完整 × 结论形态（降级优先于 refuted / claim）
// ════════════════════════════════════════════════════════════════════════

function incompleteBasis() {
  return Basis.fromObject({
    version: 'v1',
    nodes: [
      { session_id: 's-no-turn', tool_call_id: 't' },
      { session_id: 's-no-call', turn: 1 },
    ],
  })
}

test('node: 缺 turn 时「判据推翻主张」也只能落 inconclusive', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'none', node: { session_id: 's-no-turn', tool_call_id: 't' } }],
  }
  const record = runOrgan(subject, incompleteBasis())[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /判据推翻主张/)
  assert.match(record.message, /痕迹节点不完整：缺 turn/)
})

test('node: 缺 tool_call_id 时匹配结论也降级', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict', node: { session_id: 's-no-call', turn: 1, tool_call_id: '' } }],
  }
  const record = runOrgan(subject, incompleteBasis())[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /主张「conflict=conflict」被冲突判据支持/)
  assert.match(record.message, /痕迹节点不完整：缺 tool_call_id/)
})

test('node: 不完整节点 + 重算本身不可判定 -> 两条降级理由都在 message 里', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{
      claim_id: 'c',
      check: 'block',
      path: 'x.py',
      ...BLOCK_PAIR,
      asserted: 'none',
      node: { session_id: 's-no-turn', tool_call_id: 't' },
    }],
  }
  const record = runOrgan(subject, incompleteBasis())[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /痕迹不足以判定/)
  assert.match(record.message, /缺失项：merge-tree/)
  assert.match(record.message, /痕迹节点不完整：缺 turn/)
})

test('node: 无节点 + 不可判定 -> 只报缺失项，不出现节点降级话术', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'block', path: 'x.py', ...BLOCK_PAIR, asserted: 'conflict' }],
  }
  const record = runOrgan(subject)[0]
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /缺失项：merge-tree/)
  assert.equal(record.message.includes('痕迹节点不完整'), false)
  assert.equal(record.node, null)
})

test('node: basis 里的 quote 原样进入 basis_ref', () => {
  const basis = Basis.fromObject({
    version: 'v1',
    nodes: [{ session_id: 's-q', turn: 2, tool_call_id: 'call-q', quote: 'git merge-tree --write-tree ws-1 ws-2' }],
  })
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict', node: { session_id: 's-q', turn: 2, tool_call_id: 'call-q' } }],
  }
  const record = runOrgan(subject, basis)[0]
  assert.equal(record.verdict, CLAIM)
  assert.equal(record.node.quote, 'git merge-tree --write-tree ws-1 ws-2')
})

// ════════════════════════════════════════════════════════════════════════
// 13. 脱敏前置的结构面（不是「器官自觉打码」）
// ════════════════════════════════════════════════════════════════════════

test('redaction: 入账是深拷贝，调用方事后改原对象不影响账本', () => {
  const source = { api_key: SAMPLE, nested: { list: [{ token: SAMPLE }] } }
  const record = makeRecord({
    claim_id: 'c0',
    verdict: CLAIM,
    message: 'x',
    node: makeNode({ session_id: 's', turn: 1, tool_call_id: 't' }),
    evidence: source,
  })
  const before = JSON.stringify(record.evidence)
  source.api_key = 'mutated'
  source.nested.list[0].token = 'mutated'
  assert.equal(JSON.stringify(record.evidence), before)
  assert.equal(JSON.stringify(record.evidence).includes('mutated'), false)
})

test('redaction: 数组里嵌套的敏感键同样在入账时被替换', () => {
  const record = makeRecord({
    claim_id: 'c0',
    verdict: CLAIM,
    message: 'x',
    node: makeNode({ session_id: 's', turn: 1, tool_call_id: 't' }),
    evidence: { rows: [{ password: SAMPLE, keep: 'ok' }, [{ secret: SAMPLE }]] },
  })
  assert.deepEqual(record.evidence, { rows: [{ password: MASK, keep: 'ok' }, [{ secret: MASK }]] })
})

test('redaction: 键名变体（apiKey / API-KEY / refreshToken / Authorization）都命中', () => {
  for (const key of ['apiKey', 'API-KEY', 'refreshToken', 'Authorization']) {
    assert.equal(isSensitiveKey(key), true, key)
    const record = makeRecord({
      claim_id: 'c0',
      verdict: CLAIM,
      message: 'x',
      node: makeNode({ session_id: 's', turn: 1, tool_call_id: 't' }),
      evidence: { [key]: SAMPLE },
    })
    assert.equal(record.evidence[key], MASK, key)
  }
})

test('redaction: 非敏感键与标量原样保留', () => {
  const record = makeRecord({
    claim_id: 'c0',
    verdict: CLAIM,
    message: 'x',
    node: makeNode({ session_id: 's', turn: 1, tool_call_id: 't' }),
    evidence: { path: 'src/a.py', count: 3, ratio: 0, flag: false, none: null, note: 'keep' },
  })
  assert.deepEqual(record.evidence, { path: 'src/a.py', count: 3, ratio: 0, flag: false, none: null, note: 'keep' })
})

test('redaction: 器官产出的证据里没有敏感键名泄漏（递归扫描）', () => {
  const { subject } = loadScenario('same_symbol_diff_lines')
  const records = runOrgan(subject)
  const walk = (value, where) => {
    if (Array.isArray(value)) {
      value.forEach((item, index) => walk(item, `${where}[${index}]`))
      return
    }
    if (value === null || typeof value !== 'object') return
    for (const [key, inner] of Object.entries(value)) {
      assert.equal(isSensitiveKey(key) ? inner === MASK : true, true, `${where}.${key}`)
      walk(inner, `${where}.${key}`)
    }
  }
  for (const record of records) walk(record.evidence, record.claim_id)
})

// ════════════════════════════════════════════════════════════════════════
// 14. 输入校验边界表（每条一个必填/类型/闭集口径）
// ════════════════════════════════════════════════════════════════════════

function validSubject() {
  return {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict', node: NODE }],
  }
}

const VALIDATION_CASES = [
  ['claims 空数组', (s) => { s.claims = [] }, /claims 必须是非空数组/],
  ['claims 非数组', (s) => { s.claims = {} }, /claims 必须是非空数组/],
  ['缺 claim_id', (s) => { delete s.claims[0].claim_id }, /缺 claim_id/],
  ['check 非法', (s) => { s.claims[0].check = 'nope' }, /check 非法/],
  ['缺 path', (s) => { delete s.claims[0].path }, /缺 path/],
  ['缺 asserted', (s) => { delete s.claims[0].asserted }, /缺 asserted/],
  ['workspace_a 非字符串', (s) => { s.claims[0].workspace_a = 3 }, /workspace_a 必须是非空字符串/],
  ['sessions 非数组', (s) => { s.sessions = {} }, /sessions 必须是数组/],
  ['session 缺 id', (s) => { delete s.sessions[0].id }, /缺 id/],
  ['session 缺 workspace', (s) => { delete s.sessions[0].workspace }, /缺 workspace/],
  ['derived_from 非字符串', (s) => { s.sessions[0].derived_from = 3 }, /derived_from 必须是字符串或 null/],
  ['writes 非数组', (s) => { s.sessions[0].writes = 'x' }, /writes 必须是数组/],
  ['write 缺 path', (s) => { delete s.sessions[0].writes[0].path }, /writes\[0\] 缺 path/],
  ['write 缺 kind', (s) => { delete s.sessions[0].writes[0].kind }, /缺 kind/],
  ['ranges 非数组', (s) => { s.sessions[0].writes[0].ranges = 1 }, /ranges 必须是数组/],
  ['ranges 项长度不是 2', (s) => { s.sessions[0].writes[0].ranges = [[1, 2, 3]] }, /ranges 的每一项必须是 \[start, end\]/],
  ['ranges 非整数', (s) => { s.sessions[0].writes[0].ranges = [[1.5, 2]] }, /1-based 闭区间/],
  ['ranges end < start', (s) => { s.sessions[0].writes[0].ranges = [[5, 2]] }, /1-based 闭区间/],
  ['merge_trees 非数组', (s) => { s.merge_trees = {} }, /merge_trees 必须是数组/],
  ['merge 缺 a', (s) => { s.merge_trees = [{ b: 'ws-2', status: 'ok', paths: [] }] }, /merge_trees\[0\] 缺 a/],
  ['merge status 非法', (s) => { s.merge_trees = [{ a: 'ws-1', b: 'ws-2', status: 'maybe', paths: [] }] }, /status 必须是 conflict/],
  ['merge paths 非字符串', (s) => { s.merge_trees = [{ a: 'ws-1', b: 'ws-2', status: 'ok', paths: [1] }] }, /paths 必须是字符串数组/],
  ['repo 非对象', (s) => { s.repo = [] }, /repo 必须是对象/],
  ['repo.files 非对象', (s) => { s.repo = { files: [] } }, /repo.files 必须是对象/],
  ['repo 内容非字符串', (s) => { s.repo = { files: { 'x.py': 1 } } }, /repo\.files\[x\.py\] 必须是字符串/],
  ['node 非对象', (s) => { s.claims[0].node = 'x' }, /node 必须是对象/],
  ['node 缺 session_id', (s) => { s.claims[0].node = { turn: 1, tool_call_id: 't' } }, /node\.session_id 必须是非空字符串/],
  ['node.turn 非整数', (s) => { s.claims[0].node = { session_id: 's', turn: 1.5, tool_call_id: 't' } }, /node\.turn 必须是整数/],
  ['node.tool_call_id 非字符串', (s) => { s.claims[0].node = { session_id: 's', turn: 1 } }, /node\.tool_call_id 必须是字符串/],
]

for (const [name, mutate, pattern] of VALIDATION_CASES) {
  test(`validation ${name}`, () => {
    const subject = validSubject()
    mutate(subject)
    assert.throws(() => runOrgan(subject), pattern)
  })
}

test('validation: 依据包版本缺失 -> ContractError（不是 NodeMissing）', () => {
  assert.throws(() => new Basis(''), /痕迹包版本为空/)
})

// ════════════════════════════════════════════════════════════════════════
// 15. 确定性与账本形状
// ════════════════════════════════════════════════════════════════════════

test('determinism: sessions 顺序不影响账本字节', () => {
  const files = { 'x.py': ADJ_SOURCE }
  const sessions = [
    session('a', 'ws-1', 'x.py', [[2, 2]]),
    session('b', 'ws-2', 'x.py', [[2, 2]]),
    session('c', 'ws-2', 'x.py', [[4, 4]]),
  ]
  const claim = { claim_id: 'c1', check: 'conflict', path: 'x.py', asserted: 'conflict', node: NODE }
  const forward = runOrgan({ repo: { files }, sessions, merge_trees: [], claims: [claim] })
  const reversed = runOrgan({ repo: { files }, sessions: [...sessions].reverse(), merge_trees: [], claims: [claim] })
  assert.equal(JSON.stringify(forward.map(recordToJSON)), JSON.stringify(reversed.map(recordToJSON)))
})

test('determinism: claims 顺序只影响行序，不影响每条的结论', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [
      { claim_id: 'z', check: 'conflict', path: 'x.py', asserted: 'conflict', node: NODE },
      { claim_id: 'a', check: 'conflict', path: 'z.py', asserted: 'none', node: NODE },
    ],
  }
  const byId = (records) => Object.fromEntries(records.map((record) => [record.claim_id, recordToJSON(record)]))
  const forward = byId(runOrgan(subject))
  const reversed = byId(runOrgan({ ...subject, claims: [...subject.claims].reverse() }))
  assert.deepEqual(forward, reversed)
  assert.deepEqual(Object.keys(forward).sort(), ['a', 'z'])
})

test('shape: 账本 id = <claim_id>@<session>#<turn>#<tool_call>', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'same-file', check: 'conflict', path: 'x.py', asserted: 'conflict', node: NODE }],
  }
  assert.equal(runOrgan(subject)[0].id, 'same-file@s-radar-1#4#call-radar-4')
})

test('shape: 无节点的 id 以 @- 结尾', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'no-node', check: 'conflict', path: 'x.py', asserted: 'conflict' }],
  }
  const record = runOrgan(subject)[0]
  assert.equal(record.id, 'no-node@-')
  assert.equal(recordToJSON(record).basis_ref, null)
})

test('shape: 账本行字段顺序固定（--json 的确定性依赖）', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'conflict', node: NODE }],
  }
  const json = recordToJSON(runOrgan(subject)[0])
  assert.deepEqual(Object.keys(json), ['id', 'claim_id', 'verdict', 'message', 'basis_ref', 'evidence'])
  assert.deepEqual(Object.keys(json.basis_ref), ['session_id', 'turn', 'tool_call_id', 'quote'])
  assert.deepEqual(Object.keys(json.evidence), ['check', 'path', 'claimed', 'computed', 'comparison', 'conflicts', 'total_conflicts'])
})

// ════════════════════════════════════════════════════════════════════════
// 16. 基准场景 × 主张 × asserted 闭集全交叉（参数化）
//     期望值从 truth.json + defaults 独立重算，不读器官输出；
//     这样每条规则的「断言值 × 重算值」都被压一遍，而不只是选中的那一条。
// ════════════════════════════════════════════════════════════════════════

const DEFAULTS = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../src/traceproof/verbs/agent-conflict/data/agent-conflict-defaults.json', import.meta.url)),
    'utf8',
  ),
)
const TOLERANCE = DEFAULTS.symbol.adjacent_tolerance

const ASSERTED_SETS = {
  conflict: ['none', 'conflict'],
  block: ['none', 'conflict', 'undecidable'],
  'symbol-relation': ['same', 'adjacent', 'different', 'cross_file', 'unavailable', 'undecidable'],
}

/** 从 truth.json 独立重算每种 check 的应得结果（几何字段 → 判据）。 */
function expectedComputed(context) {
  const { truth, geometry } = context
  const sides = geometry.sides
  const symbol = !geometry.pair.same_file
    ? 'cross_file'
    : sides[0].symbol === sides[1].symbol
      ? 'same'
      : geometry.pair.gap_lines !== null && geometry.pair.gap_lines <= TOLERANCE
        ? 'adjacent'
        : 'different'
  return {
    conflict: truth.levels_expected.includes('file') ? 'conflict' : 'none',
    block:
      truth.git_expected_merge_exit === 1
        ? 'conflict'
        : truth.git_expected_merge_exit === 128
          ? 'undecidable'
          : 'none',
    'symbol-relation': symbol,
  }
}

function claimForCheck(context, check) {
  const sides = context.geometry.sides
  if (check === 'conflict') return { check, path: sides[0].path }
  if (check === 'block') return { check, path: sides[0].path, workspace_a: 'ws-1', workspace_b: 'ws-2' }
  return { check, path: sides[0].path, session_a: sides[0].session, session_b: sides[1].session }
}

for (const name of SCENARIOS) {
  const expected = expectedComputed(loadScenario(name))
  for (const [check, assertedValues] of Object.entries(ASSERTED_SETS)) {
    for (const asserted of assertedValues) {
      test(`sweep ${name} · ${check}=${asserted}`, () => {
        const context = loadScenario(name)
        const subject = {
          ...context.subject,
          claims: [{ claim_id: 'c', node: NODE, ...claimForCheck(context, check), asserted }],
        }
        const record = runOrgan(subject)[0]
        const computed = expected[check]
        const want = computed === 'undecidable' ? INCONCLUSIVE : asserted === computed ? CLAIM : REFUTED
        assert.equal(record.evidence.computed, computed)
        assert.equal(record.verdict, want, record.message)
        if (want === REFUTED) assert.match(record.message, /判据推翻主张/)
      })
    }
  }
}

// ════════════════════════════════════════════════════════════════════════
// 17. 检测边界（工作区组合 / subagent / merge 匹配 / 路径与扩展名）
// ════════════════════════════════════════════════════════════════════════

test('detect 边界: 四个工作区 -> 两两组合 6 条', () => {
  const sessions = ['ws-1', 'ws-2', 'ws-3', 'ws-4'].map((workspace, index) =>
    session(`s${index}`, workspace, 'x.py', [[1, 1]]),
  )
  const conflicts = detectConflicts({}, sessions, [])
  assert.equal(conflicts.length, 6)
  const pairs = [...new Set(conflicts.map((item) => `${item.workspace_a}/${item.workspace_b}`))].sort()
  assert.deepEqual(pairs, ['ws-1/ws-2', 'ws-1/ws-3', 'ws-1/ws-4', 'ws-2/ws-3', 'ws-2/ws-4', 'ws-3/ws-4'])
})

test('detect 边界: subagent 一侧 derived_from 为空 -> 仍产出', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [],
  )
  assert.equal(conflicts.length, 1)
})

test('detect 边界: 三个 subagent 只抑制同 parent 的那一对', () => {
  const conflicts = detectConflicts(
    {},
    [
      session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: 'p1' }),
      session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p1' }),
      session('c', 'ws-3', 'x.py', [[1, 1]], { derived_from: 'p2' }),
    ],
    [],
  )
  assert.equal(conflicts.length, 2)
  assert.deepEqual(conflicts.map((item) => item.sessions), [['a', 'c'], ['b', 'c']])
})

test('detect 边界: 同一路径按粒度再按严重度排序', () => {
  const files = { 'x.py': FAR_SOURCE }
  const sessions = [
    session('a', 'ws-1', 'x.py', [[2, 2]]),
    session('b', 'ws-2', 'x.py', [[2, 2]]),
    session('d', 'ws-3', 'x.py', [[9, 9]]),
  ]
  const conflicts = detectConflicts(files, sessions, [])
  assert.deepEqual(conflicts.map((item) => item.level), ['symbol', 'file', 'file'])
})

test('detect 边界: merge_trees 重复条目取第一条匹配', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [
      { a: 'ws-2', b: 'ws-1', status: 'ok', paths: [] },
      { a: 'ws-1', b: 'ws-2', status: 'conflict', paths: ['x.py'] },
    ],
  )
  assert.deepEqual(conflicts[0].levels, ['file'])
  assert.equal(conflicts[0].degraded, false)
})

test('detect 边界: merge 成功但 paths 列了本路径 -> 无区块级', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'x.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [{ a: 'ws-1', b: 'ws-2', status: 'ok', paths: ['x.py'] }],
  )
  assert.deepEqual(conflicts[0].levels, ['file'])
})

test('detect 边界: 一侧多写记录中有一条空 ranges 仍按其余区间判定', () => {
  const sessions = [
    { id: 'a', workspace: 'ws-1', derived_from: null, writes: [
      { path: 'x.py', kind: 'edit', ranges: [] },
      { path: 'x.py', kind: 'edit', ranges: [[2, 2]] },
    ] },
    session('b', 'ws-2', 'x.py', [[2, 2]]),
  ]
  const conflicts = detectConflicts({ 'x.py': ADJ_SOURCE }, sessions, [])
  assert.equal(conflicts.length, 1)
  assert.deepEqual(conflicts[0].levels, ['file', 'symbol'])
})

test('detect 边界: 路径大小写敏感（X.py 与 x.py 不是同一文件）', () => {
  const conflicts = detectConflicts(
    {},
    [session('a', 'ws-1', 'X.py', [[1, 1]]), session('b', 'ws-2', 'x.py', [[1, 1]])],
    [],
  )
  assert.equal(conflicts.length, 0)
})

test('detect 边界: 扩展名大写 .PY 不算 Python（approximate）', () => {
  const conflicts = detectConflicts(
    { 'x.PY': ADJ_SOURCE },
    [session('a', 'ws-1', 'x.PY', [[2, 2]]), session('b', 'ws-2', 'x.PY', [[2, 2]])],
    [],
  )
  assert.equal(conflicts[0].approximate, true)
  assert.deepEqual(conflicts[0].levels, ['file'])
})

test('detect 边界: a.py.bak 不以 .py 结尾，不给符号级', () => {
  const conflicts = detectConflicts(
    { 'a.py.bak': ADJ_SOURCE },
    [session('a', 'ws-1', 'a.py.bak', [[2, 2]]), session('b', 'ws-2', 'a.py.bak', [[2, 2]])],
    [],
  )
  assert.equal(conflicts[0].approximate, true)
  assert.deepEqual(conflicts[0].levels, ['file'])
})

test('detect 边界: Windows 反斜杠路径仍按 .py 取符号', () => {
  const path = 'src\\a.py'
  const conflicts = detectConflicts(
    { [path]: ADJ_SOURCE },
    [session('a', 'ws-1', path, [[2, 2]]), session('b', 'ws-2', path, [[2, 2]])],
    [],
  )
  assert.deepEqual(conflicts[0].levels, ['file', 'symbol'])
  assert.deepEqual(conflicts[0].symbols, ['f'])
})

// ════════════════════════════════════════════════════════════════════════
// 18. 器官入口的归一化边界（读入时 trim / derived_from 空白 / check 大小写）
// ════════════════════════════════════════════════════════════════════════

test('organ 边界: session id / workspace / claim 的空白在入账前归一', () => {
  const subject = {
    repo: { files: {} },
    sessions: [
      { id: ' a ', workspace: ' ws-1 ', derived_from: null, writes: [{ path: 'x.py', kind: ' edit ', ranges: [[1, 1]] }] },
      { id: ' b ', workspace: ' ws-2 ', derived_from: null, writes: [{ path: 'x.py', kind: ' edit ', ranges: [[2, 2]] }] },
    ],
    merge_trees: [],
    claims: [{ claim_id: ' c ', check: 'conflict', path: ' x.py ', asserted: 'conflict', node: NODE }],
  }
  const record = runOrgan(subject)[0]
  assert.equal(record.claim_id, 'c')
  assert.equal(record.verdict, CLAIM)
  assert.equal(record.id, 'c@s-radar-1#4#call-radar-4')
  assert.equal(record.evidence.path, 'x.py')
})

test('organ 边界: symbol-relation 的 session_a/b 空白也按归一后的 id 匹配', () => {
  const subject = {
    repo: { files: { 'x.py': ADJ_SOURCE } },
    sessions: [
      { id: ' a ', workspace: 'ws-1', derived_from: null, writes: [{ path: 'x.py', kind: 'edit', ranges: [[2, 2]] }] },
      { id: ' b ', workspace: 'ws-2', derived_from: null, writes: [{ path: 'x.py', kind: 'edit', ranges: [[2, 2]] }] },
    ],
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'symbol-relation', path: 'x.py', session_a: ' a ', session_b: ' b ', asserted: 'same', node: NODE }],
  }
  assert.equal(runOrgan(subject)[0].verdict, CLAIM)
})

test('organ 边界: derived_from 的空白被 trim 后再比较', () => {
  const subject = {
    repo: { files: {} },
    sessions: [
      session('a', 'ws-1', 'x.py', [[1, 1]], { derived_from: ' p1 ' }),
      session('b', 'ws-2', 'x.py', [[1, 1]], { derived_from: 'p1' }),
    ],
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'conflict', path: 'x.py', asserted: 'none', node: NODE }],
  }
  const record = runOrgan(subject)[0]
  assert.equal(record.verdict, CLAIM)
  assert.equal(record.evidence.computed, 'none')
})

test('organ 边界: check 大小写敏感（CONFLICT 不是闭集成员）', () => {
  const subject = {
    repo: { files: {} },
    sessions: WS_PAIR(),
    merge_trees: [],
    claims: [{ claim_id: 'c', check: 'CONFLICT', path: 'x.py', asserted: 'conflict', node: NODE }],
  }
  assert.throws(() => runOrgan(subject), /check 非法/)
})

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'traceproof-agent-conflict-'))
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