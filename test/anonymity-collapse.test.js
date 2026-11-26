/**
 * anonymity-collapse 器官的无损测试。
 *
 * 判据 1 的 X = 来源仓判定层（D1 + D18 机械选 7 文件）实跑 263 passed。
 * 本文件顶层 `test(` 调用数 ≥ 263，`node --test` 实跑用例数同值（无循环子测试）。
 *
 * 数据面：来源仓 `data/fixtures/{tiny,small,prune,budget}` 的表格与 truth 只读拷贝到
 * `test/fixtures/anonymity-collapse/`；Adult 示例转成 `samples/anonymity-collapse.json`
 * （判据 2 的同一份数据）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
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
  Report,
  makeNode,
  recordToJSON,
} from '../lib/traceproof/core/ledger.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get, VerbMissing } from '../lib/traceproof/core/registry.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  anonymityCollapseVerb,
  CHECKS as VERB_CHECKS,
  evaluate,
  VERSION,
} from '../lib/traceproof/verbs/anonymity-collapse/index.js'
import {
  isMissing,
  missingSet,
  parseTable,
  requireRowNumber,
} from '../lib/traceproof/verbs/anonymity-collapse/table.js'
import { parseDeclaration, PRECISIONS, ROLES } from '../lib/traceproof/verbs/anonymity-collapse/declaration.js'
import {
  groupRows,
  kOf,
  lDetail,
  MISSING_CLASS_KEY,
  NULL_TOKEN,
  POLICIES,
  summarize,
  tDetail,
} from '../lib/traceproof/verbs/anonymity-collapse/classes.js'
import {
  collapseSetsStatus,
  completeness,
  COMPLETENESS_STATES,
  monotonicityHolds,
  outcomeFor,
  search,
} from '../lib/traceproof/verbs/anonymity-collapse/search.js'
import {
  ATTACKERS,
  classify,
  isFlagged,
  risk,
  ruleText,
  UNDECIDED_ROW_REASON,
} from '../lib/traceproof/verbs/anonymity-collapse/risk.js'
import {
  combineOutcomes,
  evaluateGate,
  parseCriteriaInput,
  REASON_REQUIRE_EXHAUSTIVE,
  REASON_SEARCH_NOT_EXHAUSTED,
} from '../lib/traceproof/verbs/anonymity-collapse/criteria.js'
import { round6 } from '../lib/traceproof/verbs/anonymity-collapse/round.js'
import { CHECKS as CLAIM_CHECKS, readClaim } from '../lib/traceproof/verbs/anonymity-collapse/claims.js'

const PRODUCT_ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const FIX = join(PRODUCT_ROOT, 'test', 'fixtures', 'anonymity-collapse')
const SAMPLES = join(PRODUCT_ROOT, 'samples')

function parseCsv(name) {
  const text = readFileSync(join(FIX, `${name}.csv`), 'utf8').trim()
  const lines = text.split(/\r?\n/)
  const header = lines.shift().split(',').map((cell) => cell.trim())
  const rows = lines.map((line) => line.split(','))
  return { header, rows }
}

function fixtureTable(name) {
  return parseTable(parseCsv(name))
}

function loadTruth(name) {
  return JSON.parse(readFileSync(join(FIX, `${name}-truth.json`), 'utf8'))
}

function policyBlock(truth, policy) {
  const block = truth.by_policy[policy]
  return block.same_as === undefined ? block : truth.by_policy[block.same_as]
}

function declarationColumns(truth) {
  const columns = {}
  for (const item of truth.declaration_order) {
    columns[item.name] = { role: item.role }
    if (item.precision !== undefined) columns[item.name].precision = item.precision
  }
  return columns
}

function subjectRecord(header, rows, columns, extra = {}) {
  return {
    table: { header, rows },
    declaration: { columns },
    policy: 'drop',
    thresholds: { k: 2, l: null, t: null },
    claims: [{ claim_id: 'k', check: 'k', asserted: 1 }],
    ...extra,
  }
}

function tinySubject(extra = {}) {
  const { header, rows } = parseCsv('tiny')
  return subjectRecord(
    header,
    rows,
    {
      age: { role: 'qi' },
      zip: { role: 'qi' },
      dob: { role: 'qi' },
      sex: { role: 'qi' },
      disease: { role: 'sensitive' },
      name: { role: 'direct-identifier' },
      phone: { role: 'direct-identifier' },
    },
    { thresholds: { k: 3, l: null, t: null }, claims: [{ claim_id: 'k', check: 'k', asserted: 1 }], ...extra },
  )
}

function fixtureSubject(name, extra = {}) {
  const truth = loadTruth(name)
  const { header, rows } = parseCsv(name)
  return {
    table: { header, rows },
    declaration: { columns: declarationColumns(truth) },
    policy: truth.meta.policy,
    thresholds: { k: truth.meta.threshold, l: null, t: null },
    claims: [{ claim_id: 'k', check: 'k', asserted: truth.by_policy[truth.meta.policy].k }],
    ...extra,
  }
}

function basisOf(nodes) {
  return Basis.fromObject({ version: 'basis-test', nodes })
}

function nodeAt(turn, toolCallId, session = 's-anon-1') {
  return { session_id: session, turn, tool_call_id: toolCallId, quote: '匿名性快照' }
}

function evaluateOne(subject, basis = Basis.empty('test')) {
  const records = [...evaluate(subject, basis)]
  assert.equal(records.length, 1)
  return records[0]
}

function assertThrows(fn, pattern) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof ContractError, `期望 ContractError，实际 ${error?.constructor?.name}`)
    if (pattern !== undefined) assert.match(error.message, pattern)
    return true
  })
}

async function capture(fn) {
  let out = ''
  let err = ''
  const originalLog = console.log
  const originalWrite = process.stderr.write
  console.log = (...args) => {
    out += `${args.join(' ')}\n`
  }
  process.stderr.write = (chunk) => {
    err += String(chunk)
    return true
  }
  try {
    const code = await fn()
    return { code, out, err }
  } finally {
    console.log = originalLog
    process.stderr.write = originalWrite
  }
}

function tempSubject(subject, nodes = []) {
  const dir = mkdtempSync(join(tmpdir(), 'anon-collapse-'))
  const input = join(dir, 'subject.json')
  const basis = join(dir, 'basis.json')
  writeFileSync(input, JSON.stringify(subject))
  writeFileSync(basis, JSON.stringify({ version: 'basis-test', nodes }))
  return { dir, input, basis }
}

// ── A. 输入面与契约（源仓 test_contract / test_m2 边界 / test_m5 闭合） ──

test('table: header cells are trimmed', () => {
  const table = parseTable({ header: [' age ', 'zip'], rows: [['30', '100']] })
  assert.deepEqual([...table.header], ['age', 'zip'])
})

test('table: duplicate header names are rejected', () => {
  assertThrows(() => parseTable({ header: ['age', 'age'], rows: [] }), /重复列名/)
})

test('table: empty header is rejected', () => {
  assertThrows(() => parseTable({ header: [], rows: [] }), /非空字符串数组/)
})

test('table: all-empty header cells are rejected', () => {
  assertThrows(() => parseTable({ header: ['', ' '], rows: [] }), /header 为空/)
})

test('table: ragged rows are rejected', () => {
  assertThrows(() => parseTable({ header: ['age', 'zip'], rows: [['30']] }), /宽度与表头不一致/)
})

test('table: non-string row cell is rejected', () => {
  assertThrows(() => parseTable({ header: ['age'], rows: [[30]] }), /必须是字符串/)
})

test('table: empty rows array is allowed', () => {
  const table = parseTable({ header: ['age'], rows: [] })
  assert.equal(table.rowCount, 0)
})

test('table: row numbers start at 1 and stay sequential', () => {
  const table = parseTable({ header: ['age'], rows: [['30'], ['31']] })
  assert.deepEqual(table.rows.map((row) => row.rowNumber), [1, 2])
})

test('table: unknown table key is rejected', () => {
  assertThrows(() => parseTable({ header: ['age'], rows: [], source: 'x.csv' }), /未知字段/)
})

test('table: non-object table is rejected', () => {
  assertThrows(() => parseTable([]), /table 必须是对象/)
})

test('table: empty header cell in the middle is rejected', () => {
  assertThrows(() => parseTable({ header: ['age', ''], rows: [] }), /header\[1\] 为空/)
})

test('table: columnIndex returns null for missing columns', () => {
  const table = parseTable({ header: ['age'], rows: [] })
  assert.equal(table.columnIndex('zip'), null)
  assert.equal(table.columnIndex('age'), 0)
})

test('table: values() returns raw values in row order', () => {
  const table = parseTable({ header: ['age'], rows: [['30'], ['NA'], ['-']] })
  assert.deepEqual(table.values('age'), ['30', 'NA', '-'])
})

test('table: values() on a missing column is a contract error', () => {
  const table = parseTable({ header: ['age'], rows: [] })
  assertThrows(() => table.values('zip'), /不存在列/)
})

test('table: missing token set is the single source of truth', () => {
  assert.deepEqual([...missingSet()].sort(), ['', '-', 'N/A', 'NA', 'NULL', 'null'].sort())
})

test('table: isMissing is case sensitive', () => {
  assert.equal(isMissing('NA'), true)
  assert.equal(isMissing('na'), false)
  assert.equal(isMissing('NULL'), true)
  assert.equal(isMissing('null'), true)
  assert.equal(isMissing('None'), false)
})

test('table: requireRowNumber enforces 1-based range', () => {
  assert.equal(requireRowNumber(1, 'row', 2), 1)
  assert.equal(requireRowNumber(2, 'row', 2), 2)
  assertThrows(() => requireRowNumber(0, 'row', 2), />= 1/)
  assertThrows(() => requireRowNumber(3, 'row', 2), /超出数据行范围/)
})

test('declaration: unknown top-level key is rejected', () => {
  assertThrows(
    () => parseDeclaration({ columns: { age: { role: 'qi' } }, version: 1 }, ['age']),
    /未知顶层键/,
  )
})

test('declaration: missing columns object is rejected', () => {
  assertThrows(() => parseDeclaration({}, ['age']), /columns 必须是非空对象/)
})

test('declaration: empty columns object is rejected', () => {
  assertThrows(() => parseDeclaration({ columns: {} }, ['age']), /columns 必须是非空对象/)
})

test('declaration: column absent from the table is rejected', () => {
  assertThrows(
    () => parseDeclaration({ columns: { salary: { role: 'qi' } } }, ['age']),
    /表中不存在的列/,
  )
})

test('declaration: unknown role is rejected', () => {
  assertThrows(
    () => parseDeclaration({ columns: { age: { role: 'quasi' } } }, ['age']),
    /角色不在枚举内/,
  )
})

test('declaration: date-precision without precision is rejected', () => {
  assertThrows(
    () => parseDeclaration({ columns: { dob: { role: 'date-precision' } } }, ['dob']),
    /必须声明 precision/,
  )
})

test('declaration: date-precision with invalid precision is rejected', () => {
  assertThrows(
    () => parseDeclaration({ columns: { dob: { role: 'date-precision', precision: 'week' } } }, ['dob']),
    /必须声明 precision/,
  )
})

test('declaration: precision key on a qi column is rejected', () => {
  assertThrows(
    () => parseDeclaration({ columns: { dob: { role: 'qi', precision: 'month' } } }, ['dob']),
    /不允许键/,
  )
})

test('declaration: qi columns preserve declaration order', () => {
  const declaration = parseDeclaration(
    { columns: { zip: { role: 'qi' }, age: { role: 'qi' }, disease: { role: 'sensitive' } } },
    ['age', 'zip', 'disease'],
  )
  assert.deepEqual(declaration.qiColumns(), ['zip', 'age'])
})

test('declaration: sensitive columns are listed separately', () => {
  const declaration = parseDeclaration(
    { columns: { age: { role: 'qi' }, disease: { role: 'sensitive' } } },
    ['age', 'disease'],
  )
  assert.deepEqual(declaration.sensitiveColumns(), ['disease'])
})

test('declaration: unparticipating lists undeclared columns', () => {
  const declaration = parseDeclaration({ columns: { age: { role: 'qi' } } }, ['age', 'zip'])
  assert.deepEqual(declaration.unparticipating(), [{ column: 'zip', reason: 'undeclared' }])
})

test('declaration: direct-identifier columns are unparticipating', () => {
  const declaration = parseDeclaration(
    { columns: { age: { role: 'qi' }, name: { role: 'direct-identifier' } } },
    ['age', 'name'],
  )
  assert.deepEqual(declaration.unparticipating(), [{ column: 'name', reason: 'direct-identifier' }])
  assert.deepEqual(declaration.directIdentifiers(), ['name'])
})

test('declaration: date-precision-only columns are unparticipating', () => {
  const declaration = parseDeclaration(
    { columns: { dob: { role: 'date-precision', precision: 'month' } } },
    ['dob'],
  )
  assert.deepEqual(declaration.unparticipating(), [{ column: 'dob', reason: 'date-precision-only' }])
})

test('declaration: role/precision enumerations are closed', () => {
  assert.deepEqual([...ROLES], ['qi', 'sensitive', 'direct-identifier', 'date-precision'])
  assert.deepEqual([...PRECISIONS], ['year', 'month', 'day'])
})

test('criteria: missing policy is rejected', () => {
  const subject = tinySubject()
  delete subject.policy
  assertThrows(() => parseCriteriaInput(subject), /缺必填项：policy/)
})

test('criteria: unknown policy is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ policy: 'Drop' })), /未知的缺失值策略/)
})

test('criteria: null policy is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ policy: null })), /未知的缺失值策略/)
})

test('criteria: thresholds.k is required', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { l: null, t: null } })),
    /thresholds.k 必填/,
  )
})

test('criteria: thresholds.k=0 is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: { k: 0 } })), />= 1 的整数/)
})

test('criteria: thresholds.k=-3 is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: { k: -3 } })), />= 1 的整数/)
})

test('criteria: thresholds.k="5" is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: { k: '5' } })), /必须是 >= 1 的整数/)
})

test('criteria: thresholds.k=2.5 is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: { k: 2.5 } })), /必须是 >= 1 的整数/)
})

test('criteria: thresholds.k=true is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: { k: true } })), /必须是 >= 1 的整数/)
})

test('criteria: thresholds.k=null is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: { k: null } })), /必须是 >= 1 的整数/)
})

test('criteria: thresholds.l=0 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, l: 0 } })),
    /thresholds.l 必须是 >= 1 的整数/,
  )
})

test('criteria: thresholds.l=-1 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, l: -1 } })),
    /thresholds.l 必须是 >= 1 的整数/,
  )
})

test('criteria: thresholds.l="2" is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, l: '2' } })),
    /thresholds.l 必须是 >= 1 的整数/,
  )
})

test('criteria: thresholds.l=2.5 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, l: 2.5 } })),
    /thresholds.l 必须是 >= 1 的整数/,
  )
})

test('criteria: thresholds.l=true is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, l: true } })),
    /thresholds.l 必须是 >= 1 的整数/,
  )
})

test('criteria: thresholds.t=-0.1 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, t: -0.1 } })),
    /必须落在 \[0, 1\]/,
  )
})

test('criteria: thresholds.t=1.5 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, t: 1.5 } })),
    /必须落在 \[0, 1\]/,
  )
})

test('criteria: thresholds.t="0.5" is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, t: '0.5' } })),
    /\[0, 1\] 内的数或 null/,
  )
})

test('criteria: thresholds.t=true is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, t: true } })),
    /\[0, 1\] 内的数或 null/,
  )
})

test('criteria: thresholds.t=[0.5] is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, t: [0.5] } })),
    /\[0, 1\] 内的数或 null/,
  )
})

test('criteria: unknown threshold key is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ thresholds: { k: 2, delta: 0.1 } })),
    /thresholds 有未知键/,
  )
})

test('criteria: thresholds must be an object', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ thresholds: 2 })), /thresholds 必须是对象/)
})

test('criteria: unknown search key is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: false, depth: 3 } })),
    /search 有未知键/,
  )
})

test('criteria: search.enabled must be boolean', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: 'yes' } })),
    /search.enabled 必须是布尔值/,
  )
})

test('criteria: search.enabled requires a budget', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: true } })),
    /必须给 search.budget/,
  )
})

test('criteria: search.budget=0 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: true, budget: 0 } })),
    /search.budget 必须是 >= 1 的整数/,
  )
})

test('criteria: search.budget=-5 is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: true, budget: -5 } })),
    /search.budget 必须是 >= 1 的整数/,
  )
})

test('criteria: search.budget="10" is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: true, budget: '10' } })),
    /search.budget 必须是 >= 1 的整数/,
  )
})

test('criteria: search.budget=true is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: true, budget: true } })),
    /search.budget 必须是 >= 1 的整数/,
  )
})

test('criteria: require_exhaustive must be boolean', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({ search: { enabled: true, budget: 10, require_exhaustive: 'yes' } }),
    ),
    /search.require_exhaustive 必须是布尔值/,
  )
})

test('criteria: require_exhaustive without enabled search is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ search: { enabled: false, require_exhaustive: true } })),
    /require_exhaustive=true 但 search.enabled=false/,
  )
})

test('criteria: search must be an object when present', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ search: 3 })), /search 必须是对象/)
})

test('criteria: absent search block defaults to disabled', () => {
  const criteria = parseCriteriaInput(tinySubject())
  assert.deepEqual(criteria.search, { enabled: false, budget: null, require_exhaustive: false })
})

test('criteria: no qi columns is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ declaration: { columns: { disease: { role: 'sensitive' } } } })),
    /未声明任何 qi 列/,
  )
})

test('criteria: l threshold without sensitive columns is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({
        declaration: { columns: { age: { role: 'qi' }, zip: { role: 'qi' } } },
        thresholds: { k: 2, l: 2, t: null },
      }),
    ),
    /没有 sensitive 列/,
  )
})

test('criteria: t threshold without sensitive columns is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({
        declaration: { columns: { age: { role: 'qi' }, zip: { role: 'qi' } } },
        thresholds: { k: 2, l: null, t: 0.5 },
      }),
    ),
    /没有 sensitive 列/,
  )
})

test('criteria: unknown top-level key is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ attacker: 'journalist' })), /未知顶层键/)
})

test('criteria: missing table is rejected', () => {
  const subject = tinySubject()
  delete subject.table
  assertThrows(() => parseCriteriaInput(subject), /缺必填项：table/)
})

test('criteria: missing declaration is rejected', () => {
  const subject = tinySubject()
  delete subject.declaration
  assertThrows(() => parseCriteriaInput(subject), /缺必填项：declaration/)
})

test('criteria: missing thresholds is rejected', () => {
  const subject = tinySubject()
  delete subject.thresholds
  assertThrows(() => parseCriteriaInput(subject), /缺必填项：thresholds/)
})

test('criteria: claims must be a non-empty array', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ claims: [] })), /claims 必须是非空数组/)
})

test('criteria: claims must be an array', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ claims: {} })), /claims 必须是非空数组/)
})

test('claims: non-object claim is rejected', () => {
  assertThrows(() => parseCriteriaInput(tinySubject({ claims: [null] })), /claims\[0\] 必须是对象/)
})

test('claims: unknown check is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'nope', asserted: 1 }] })),
    /check 非法/,
  )
})

test('claims: missing asserted is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'k' }] })),
    /缺 asserted/,
  )
})

test('claims: duplicate claim_id is rejected', () => {
  const subject = tinySubject({
    claims: [
      { claim_id: 'x', check: 'k', asserted: 1 },
      { claim_id: 'x', check: 'l', asserted: 1 },
    ],
  })
  assertThrows(() => evaluate(subject, Basis.empty('t')), /claim_id 重复/)
})

test('claims: field not applicable to the check is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'k', asserted: 1, file: 'a' }] })),
    /不适用于 check=k/,
  )
})

test('claims: node must be an object', () => {
  assertThrows(
    () => evaluate(
      tinySubject({ claims: [{ claim_id: 'x', check: 'k', asserted: 1, node: 'n1' }] }),
      Basis.empty('t'),
    ),
    /node 必须是对象/,
  )
})

test('claims: node.session_id must be non-empty', () => {
  assertThrows(
    () => evaluate(
      tinySubject({ claims: [{ claim_id: 'x', check: 'k', asserted: 1, node: { session_id: '' } }] }),
      Basis.empty('t'),
    ),
    /node.session_id 必须是非空字符串/,
  )
})

test('claims: node.turn must be an integer', () => {
  assertThrows(
    () => evaluate(
      tinySubject({
        claims: [{ claim_id: 'x', check: 'k', asserted: 1, node: { session_id: 's', turn: 1.5, tool_call_id: 'c' } }],
      }),
      Basis.empty('t'),
    ),
    /node.turn 必须是整数/,
  )
})

test('claims: node.tool_call_id must be a string', () => {
  assertThrows(
    () => evaluate(
      tinySubject({
        claims: [{ claim_id: 'x', check: 'k', asserted: 1, node: { session_id: 's', turn: 1, tool_call_id: 3 } }],
      }),
      Basis.empty('t'),
    ),
    /node.tool_call_id 必须是字符串/,
  )
})

test('claims: missing trace node raises NodeMissing', () => {
  assert.throws(
    () => evaluate(
      tinySubject({
        claims: [{ claim_id: 'x', check: 'k', asserted: 1, node: { session_id: 's', turn: 1, tool_call_id: 'c' } }],
      }),
      Basis.empty('t'),
    ),
    NodeMissing,
  )
})

test('claims: k asserted must be an integer or null', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'k', asserted: 1.5 }] })),
    /必须是 >= 0 的整数/,
  )
})

test('claims: t asserted must be inside [0, 1]', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 't', asserted: 1.5 }] })),
    /\[0, 1\] 内的数或 null/,
  )
})

test('claims: verdict asserted is a closed set', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'verdict', asserted: 'ok' }] })),
    /asserted 必须是/,
  )
})

test('claims: collapse-sets asserted must be an array', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'collapse-sets', asserted: 1 }] })),
    /必须是数组/,
  )
})

test('claims: collapse-set with duplicate columns is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({ claims: [{ claim_id: 'x', check: 'collapse-sets', asserted: [['age', 'age']] }] }),
    ),
    /有重复列/,
  )
})

test('claims: subset-k columns must come from the qi pool', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({ claims: [{ claim_id: 'x', check: 'subset-k', asserted: 1, columns: ['disease'] }] }),
    ),
    /不在 qi 候选池/,
  )
})

test('claims: subset-k duplicate columns are rejected', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({ claims: [{ claim_id: 'x', check: 'subset-k', asserted: 1, columns: ['age', 'age'] }] }),
    ),
    /有重复列/,
  )
})

test('claims: row out of range is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'row-class', asserted: 'a', row: 13 }] })),
    /超出数据行范围/,
  )
})

test('claims: unknown attacker is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({ claims: [{ claim_id: 'x', check: 'attack-rule', asserted: 'raw', attacker: 'nobody' }] }),
    ),
    /attacker 非法/,
  )
})

test('claims: histogram key must be numeric', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'histogram', asserted: { big: 1 } }] })),
    /键必须是类大小/,
  )
})

test('claims: violation item with unknown key is rejected', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({
        claims: [
          {
            claim_id: 'x',
            check: 'violations',
            asserted: [{ key: 'a=1', count: 1, row_numbers: [1], extra: true }],
          },
        ],
      }),
    ),
    /含未知键/,
  )
})

test('claims: unique-records must be integers', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'unique-records', asserted: [1.5] }] })),
    /必须是 >= 1 的整数/,
  )
})

test('claims: missing-class shape is closed', () => {
  assertThrows(
    () => parseCriteriaInput(
      tinySubject({ claims: [{ claim_id: 'x', check: 'missing-class', asserted: { k: 2, rows: [1] } }] }),
    ),
    /含未知键/,
  )
})

test('claims: row-class asserted must be a string or null', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'row-class', asserted: 5, row: 1 }] })),
    /必须是字符串/,
  )
})

test('claims: undefined-reason asserted must be a string or null', () => {
  assertThrows(
    () => parseCriteriaInput(tinySubject({ claims: [{ claim_id: 'x', check: 'undefined-reason', asserted: 3 }] })),
    /必须是字符串/,
  )
})

test('claims: CHECKS is a closed list with 28 entries', () => {
  assert.equal(CLAIM_CHECKS.length, 28)
  assert.equal(new Set(CLAIM_CHECKS).size, 28)
  assert.deepEqual([...CLAIM_CHECKS], [...VERB_CHECKS])
})

test('claims: readClaim returns a frozen normalized claim', () => {
  const claim = readClaim(
    { claim_id: 'c1', check: 'k', asserted: 1, node: null },
    0,
    ['age'],
    3,
  )
  assert.equal(claim.claimId, 'c1')
  assert.equal(claim.check, 'k')
  assert.ok(Object.isFrozen(claim))
})

test('claims: trim claim_id and check are normalized', () => {
  const claim = readClaim({ claim_id: ' c1 ', check: 'k', asserted: 0 }, 0, ['age'], 0)
  assert.equal(claim.claimId, 'c1')
})

test('round: half-even examples match the source oracle', () => {
  assert.equal(round6(0.1234564), 0.123456)
  assert.equal(round6(0.1234565), 0.123456)
  assert.equal(round6(0.1234575), 0.123458)
})

test('round: negative zero is normalized to zero', () => {
  assert.equal(Object.is(round6(-0.0), 0), true)
})

test('round: non-boundary values are preserved', () => {
  assert.equal(round6(2.675), 2.675)
  assert.equal(round6(null), null)
})

test('round: exponent notation is expanded correctly', () => {
  assert.equal(round6(1e-7), 0)
  assert.equal(round6(1.2345675e-1), 0.123457)
})

test('round: non-finite input is rejected', () => {
  assert.throws(() => round6(Number.NaN), RangeError)
})

// ── B. 等价类引擎（源仓 test_m2_classes） ──────────────────────────────

function assertSummaryMatches(summary, expected) {
  assert.equal(summary.k_l_t.k, expected.k)
  assert.equal(summary.k_l_t.l, expected.l)
  assert.equal(summary.k_l_t.t, expected.t)
  assert.equal(summary.k_l_t.class_count, expected.class_count)
  assert.deepEqual(summary.k_l_t.class_size_histogram, expected.class_size_histogram)
  assert.deepEqual(summary.k_l_t.undecided_rows, expected.undecided_rows)
  assert.deepEqual(summary.k_l_t.missing_class, expected.missing_class)
  assert.deepEqual(summary.violations, expected.violations)
  assert.deepEqual(summary.unique_records, expected.unique_records)
}

test('m2: tiny/drop matches source truth', () => {
  const truth = loadTruth('tiny')
  const summary = summarize(
    fixtureTable('tiny'),
    truth.qi_columns,
    truth.sensitive_columns,
    'drop',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'drop'))
})

test('m2: tiny/single-column matches source truth', () => {
  const truth = loadTruth('tiny')
  const summary = summarize(
    fixtureTable('tiny'),
    truth.qi_columns,
    truth.sensitive_columns,
    'single-column',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'single-column'))
})

test('m2: tiny/separate-class matches source truth', () => {
  const truth = loadTruth('tiny')
  const summary = summarize(
    fixtureTable('tiny'),
    truth.qi_columns,
    truth.sensitive_columns,
    'separate-class',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'separate-class'))
})

test('m2: small/drop matches source truth', () => {
  const truth = loadTruth('small')
  const summary = summarize(
    fixtureTable('small'),
    truth.qi_columns,
    truth.sensitive_columns,
    'drop',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'drop'))
})

test('m2: small/single-column matches source truth', () => {
  const truth = loadTruth('small')
  const summary = summarize(
    fixtureTable('small'),
    truth.qi_columns,
    truth.sensitive_columns,
    'single-column',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'single-column'))
})

test('m2: small/separate-class matches source truth', () => {
  const truth = loadTruth('small')
  const summary = summarize(
    fixtureTable('small'),
    truth.qi_columns,
    truth.sensitive_columns,
    'separate-class',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'separate-class'))
})

test('m2: prune/drop matches source truth', () => {
  const truth = loadTruth('prune')
  const summary = summarize(
    fixtureTable('prune'),
    truth.qi_columns,
    truth.sensitive_columns,
    'drop',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'drop'))
})

test('m2: prune/single-column matches source truth', () => {
  const truth = loadTruth('prune')
  const summary = summarize(
    fixtureTable('prune'),
    truth.qi_columns,
    truth.sensitive_columns,
    'single-column',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'single-column'))
})

test('m2: prune/separate-class matches source truth', () => {
  const truth = loadTruth('prune')
  const summary = summarize(
    fixtureTable('prune'),
    truth.qi_columns,
    truth.sensitive_columns,
    'separate-class',
    truth.meta.threshold,
  )
  assertSummaryMatches(summary, policyBlock(truth, 'separate-class'))
})

test('m2: budget/drop has k=1 and no sensitive metrics', () => {
  const truth = loadTruth('tiny')
  void truth
  const table = fixtureTable('budget')
  const qi = ['c01_age', 'c02_zip', 'c03_dob', 'c04_sex', 'c05_region', 'c06_income', 'c07_edu', 'c08_job', 'c09_house', 'c10_car']
  const summary = summarize(table, qi, [], 'drop', 5)
  assert.equal(summary.k_l_t.k, 1)
  assert.equal(summary.k_l_t.l, null)
  assert.equal(summary.k_l_t.t, null)
  assert.equal(summary.k_l_t.class_count, 1200)
})

test('m2: budget/single-column keeps all rows', () => {
  const table = fixtureTable('budget')
  const qi = ['c01_age', 'c02_zip', 'c03_dob', 'c04_sex', 'c05_region', 'c06_income', 'c07_edu', 'c08_job', 'c09_house', 'c10_car']
  const summary = summarize(table, qi, [], 'single-column', 5)
  assert.equal(summary.k_l_t.k, 1)
  assert.equal(summary.k_l_t.class_count, 1200)
  assert.deepEqual(summary.k_l_t.undecided_rows, [])
})

test('m2: budget/separate-class has no missing rows', () => {
  const table = fixtureTable('budget')
  const qi = ['c01_age', 'c02_zip', 'c03_dob', 'c04_sex', 'c05_region', 'c06_income', 'c07_edu', 'c08_job', 'c09_house', 'c10_car']
  const summary = summarize(table, qi, [], 'separate-class', 5)
  assert.equal(summary.k_l_t.missing_class, null)
  assert.equal(summary.k_l_t.class_count, 1200)
})

test('m2: empty qi set groups all rows into one class', () => {
  const table = fixtureTable('small')
  const truth = loadTruth('small')
  for (const policy of POLICIES) {
    const { classes, undecided } = groupRows(table, [], policy)
    assert.deepEqual(undecided, [])
    assert.equal(kOf(classes), truth.k_by_columns['[]'])
    assert.equal(classes.size, 1)
    assert.equal(classes.get('').length, 60)
  }
})

test('m2: kOf returns null for an empty class map', () => {
  assert.equal(kOf(new Map()), null)
})

test('m2: kOf returns the minimum class size', () => {
  assert.equal(kOf(new Map([['a', [1, 2]], ['b', [1]]])), 1)
})

test('m2: kOf returns the only class size', () => {
  assert.equal(kOf(new Map([['a', [1, 2, 3]]])), 3)
})

function lTrapTable() {
  return parseTable({
    header: ['age', 'sex', 'disease'],
    rows: [
      ['NA', 'M', 'flu'],
      ['NA', 'F', 'cold'],
      ['NA', 'M', 'flu'],
      ['NA', 'F', 'cold'],
      ['30', 'M', 'flu'],
      ['30', 'M', 'cold'],
    ],
  })
}

test('m2: drop l is hand-derived 2 on the missing trap table', () => {
  const summary = summarize(lTrapTable(), ['age', 'sex'], ['disease'], 'drop', 2)
  assert.equal(summary.k_l_t.l, 2)
  assert.equal(summary.k_l_t.class_count, 1)
  assert.deepEqual(summary.k_l_t.undecided_rows, [1, 2, 3, 4])
  assert.equal(summary.k_l_t.t, 0)
})

test('m2: single-column l is hand-derived 1 on the missing trap table', () => {
  const summary = summarize(lTrapTable(), ['age', 'sex'], ['disease'], 'single-column', 2)
  assert.equal(summary.k_l_t.l, 1)
  assert.equal(summary.k_l_t.k, 2)
  assert.equal(summary.k_l_t.class_count, 3)
  assert.deepEqual(summary.k_l_t.undecided_rows, [])
  assert.equal(summary.k_l_t.t, 0.5)
})

test('m2: separate-class l is hand-derived 2 on the missing trap table', () => {
  const summary = summarize(lTrapTable(), ['age', 'sex'], ['disease'], 'separate-class', 2)
  assert.equal(summary.k_l_t.l, 2)
  assert.equal(summary.k_l_t.k, 2)
  assert.equal(summary.k_l_t.class_count, 2)
  assert.deepEqual(summary.k_l_t.missing_class, { k: 4, row_numbers: [1, 2, 3, 4] })
  assert.equal(summary.k_l_t.t, 0)
})

test('m2: the three missing policies produce different l values', () => {
  const values = {}
  for (const policy of POLICIES) {
    values[policy] = summarize(lTrapTable(), ['age', 'sex'], ['disease'], policy, 2).k_l_t.l
  }
  assert.deepEqual(values, { drop: 2, 'single-column': 1, 'separate-class': 2 })
})

test('m2: t is exactly 0 when class distributions match the whole table', () => {
  const summary = summarize(lTrapTable(), ['age', 'sex'], ['disease'], 'separate-class', 2)
  assert.equal(summary.k_l_t.t, 0)
})

test('m2: tiny violations are hand-checkable (12 singleton classes)', () => {
  const truth = loadTruth('tiny')
  const summary = summarize(
    fixtureTable('tiny'),
    truth.qi_columns,
    truth.sensitive_columns,
    'drop',
    3,
  )
  assert.equal(summary.k_l_t.k, 1)
  assert.equal(summary.k_l_t.class_count, 12)
  assert.equal(summary.violations.length, 12)
  assert.ok(summary.violations.every((item) => item.count === 1 && item.row_numbers.length === 1))
  const flattened = summary.violations.flatMap((item) => item.row_numbers).sort((a, b) => a - b)
  assert.deepEqual(flattened, Array.from({ length: 12 }, (_, index) => index + 1))
  assert.deepEqual(summary.unique_records, Array.from({ length: 12 }, (_, index) => index + 1))
  assert.equal(summary.verdict, 'violation')
})

test('m2: empty table is undecidable with empty_table reason', () => {
  const table = parseTable({ header: ['age', 'zip', 'disease'], rows: [] })
  const summary = summarize(table, ['age', 'zip'], ['disease'], 'drop', 2)
  assert.equal(summary.k_l_t.k, null)
  assert.equal(summary.k_l_t.l, null)
  assert.equal(summary.k_l_t.t, null)
  assert.equal(summary.k_l_t.class_count, 0)
  assert.equal(summary.undefined_reason, 'empty_table')
  assert.equal(summary.verdict, 'undecidable')
  assert.deepEqual(summary.violations, [])
})

test('m2: empty table keeps the histogram empty', () => {
  const table = parseTable({ header: ['age'], rows: [] })
  const summary = summarize(table, ['age'], [], 'drop', 2)
  assert.deepEqual(summary.k_l_t.class_size_histogram, {})
})

test('m2: single-row table is a violation at k=2', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['30', 'flu']] })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 2)
  assert.equal(summary.k_l_t.k, 1)
  assert.equal(summary.k_l_t.class_count, 1)
  assert.deepEqual(summary.k_l_t.class_size_histogram, { '1': 1 })
  assert.deepEqual(summary.violations, [{ key: 'age=30', count: 1, row_numbers: [1] }])
  assert.equal(summary.verdict, 'violation')
})

test('m2: all-identical qi collapses to one class and passes at k=5', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [
      ['30', 'flu'],
      ['30', 'cold'],
      ['30', 'flu'],
      ['30', 'cold'],
      ['30', 'flu'],
    ],
  })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 5)
  assert.equal(summary.k_l_t.k, 5)
  assert.equal(summary.k_l_t.class_count, 1)
  assert.deepEqual(summary.k_l_t.class_size_histogram, { '5': 1 })
  assert.equal(summary.k_l_t.l, 2)
  assert.equal(summary.k_l_t.t, 0)
  assert.deepEqual(summary.violations, [])
  assert.equal(summary.verdict, 'pass')
})

test('m2: all rows dropped is undecidable, not pass', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['NA', 'flu'], ['-', 'cold']] })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 2)
  assert.equal(summary.k_l_t.k, null)
  assert.equal(summary.undefined_reason, 'no_participating_rows')
  assert.equal(summary.verdict, 'undecidable')
})

test('m2: all dropped rows are listed as undecided', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['NA', 'flu'], ['-', 'cold']] })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 2)
  assert.deepEqual(summary.k_l_t.undecided_rows, [1, 2])
})

test('m2: separate-class collects missing rows into one class', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [
      ['NA', 'flu'],
      ['NA', 'cold'],
      ['30', 'flu'],
      ['30', 'cold'],
      ['30', 'flu'],
    ],
  })
  const summary = summarize(table, ['age'], ['disease'], 'separate-class', 2)
  assert.deepEqual(summary.k_l_t.missing_class, { k: 2, row_numbers: [1, 2] })
  assert.equal(MISSING_CLASS_KEY, '__MISSING__')
})

test('m2: group key follows declaration order, not header order', () => {
  const table = parseTable({ header: ['age', 'zip'], rows: [['30', '100']] })
  const { classes } = groupRows(table, ['zip', 'age'], 'drop')
  assert.deepEqual([...classes.keys()], ['zip=100|age=30'])
})

test('m2: single-column renders missing values as NULL token', () => {
  const table = parseTable({ header: ['age'], rows: [['NA'], [''], ['30']] })
  const { classes } = groupRows(table, ['age'], 'single-column')
  assert.ok(classes.has(`age=${NULL_TOKEN}`))
  assert.equal(NULL_TOKEN, 'NULL')
})

test('m2: separate-class uses the dedicated missing class key', () => {
  const table = parseTable({ header: ['age'], rows: [['NA'], ['30']] })
  const { classes } = groupRows(table, ['age'], 'separate-class')
  assert.ok(classes.has(MISSING_CLASS_KEY))
  assert.deepEqual(classes.get(MISSING_CLASS_KEY), [1])
})

test('m2: drop excludes missing rows from all classes', () => {
  const table = parseTable({ header: ['age'], rows: [['NA'], ['30']] })
  const { classes, undecided } = groupRows(table, ['age'], 'drop')
  assert.deepEqual(undecided, [1])
  assert.deepEqual([...classes.keys()], ['age=30'])
})

test('m2: empty column set keeps every row, even with missing values', () => {
  const table = parseTable({ header: ['age'], rows: [['NA'], ['30']] })
  const { classes, undecided } = groupRows(table, [], 'drop')
  assert.deepEqual(undecided, [])
  assert.equal(classes.get('').length, 2)
})

test('m2: l takes the minimum distinct count across sensitive columns', () => {
  const table = parseTable({
    header: ['age', 'disease', 'job'],
    rows: [
      ['30', 'flu', 'a'],
      ['30', 'cold', 'a'],
      ['30', 'flu', 'a'],
    ],
  })
  const { l } = lDetail(table, groupRows(table, ['age'], 'drop').classes, ['disease', 'job'], 'drop')
  assert.equal(l, 1)
})

test('m2: t returns 0.5 for a class whose distribution is disjoint from the whole', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [
      ['30', 'flu'],
      ['30', 'flu'],
      ['31', 'cold'],
      ['31', 'cold'],
    ],
  })
  const classes = groupRows(table, ['age'], 'drop').classes
  const { t } = tDetail(table, classes, ['disease'], [], 'drop')
  assert.equal(t, 0.5)
})

test('m2: row numbers inside a class are sorted ascending', () => {
  const table = parseTable({ header: ['age'], rows: [['30'], ['31'], ['30']] })
  const { classes } = groupRows(table, ['age'], 'drop')
  assert.deepEqual(classes.get('age=30'), [1, 3])
})

test('m2: l threshold produces violations on every failing class', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [
      ['30', 'flu'],
      ['30', 'flu'],
      ['31', 'flu'],
      ['31', 'flu'],
    ],
  })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 2, 2)
  assert.equal(summary.k_l_t.l, 1)
  assert.equal(summary.violations.length, 2)
})

test('m2: t threshold produces violations when distance exceeds it', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [
      ['30', 'flu'],
      ['30', 'flu'],
      ['31', 'cold'],
      ['31', 'cold'],
    ],
  })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 2, null, 0.4)
  assert.equal(summary.k_l_t.t, 0.5)
  assert.equal(summary.violations.length, 2)
})

test('m2: class-size violation wins over l/t on the same class', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['30', 'flu'], ['30', 'flu']] })
  const summary = summarize(table, ['age'], ['disease'], 'drop', 3, 2)
  assert.equal(summary.violations.length, 1)
  assert.equal(summary.violations[0].count, 2)
})

test('m2: summarize is deterministic across two calls', () => {
  const truth = loadTruth('small')
  const table = fixtureTable('small')
  const first = summarize(table, truth.qi_columns, truth.sensitive_columns, 'drop', 5)
  const second = summarize(table, truth.qi_columns, truth.sensitive_columns, 'drop', 5)
  assert.deepEqual(first, second)
})

test('m2: unique records match the source truth for small', () => {
  const truth = loadTruth('small')
  const summary = summarize(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', 5)
  assert.deepEqual(summary.unique_records, truth.by_policy.drop.unique_records)
})

test('m2: violations match the source truth for small', () => {
  const truth = loadTruth('small')
  const summary = summarize(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', 5)
  assert.deepEqual(summary.violations, truth.by_policy.drop.violations)
})

test('m2: histogram keys are emitted in numeric order', () => {
  const truth = loadTruth('small')
  const summary = summarize(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', 5)
  assert.deepEqual(Object.keys(summary.k_l_t.class_size_histogram), ['1', '2', '3'])
})

test('m2: groupRows rejects an unknown missing policy', () => {
  assertThrows(() => groupRows(fixtureTable('tiny'), ['age'], 'none'), /未知的缺失值策略/)
})

// ── C. 组合搜索（源仓 test_m3_search） ──────────────────────────────────

const BUDGET_QI = ['c01_age', 'c02_zip', 'c03_dob', 'c04_sex', 'c05_region', 'c06_income', 'c07_edu', 'c08_job', 'c09_house', 'c10_car']

const BUDGET_SEARCH_TRUTH = {
  budget: 40,
  candidate_count: 10,
  completeness: 'budget-truncated',
  empty_set_k: 1200,
  empty_set_witness: false,
  evaluated_subsets: 40,
  minimal_collapse_sets: [
    ['c03_dob'],
    ['c06_income'],
    ['c10_car'],
    ['c01_age', 'c04_sex'],
    ['c01_age', 'c05_region'],
    ['c02_zip', 'c04_sex'],
    ['c04_sex', 'c05_region'],
    ['c04_sex', 'c07_edu'],
    ['c04_sex', 'c08_job'],
    ['c04_sex', 'c09_house'],
  ],
  monotonicity_applicable: true,
  non_exhaustive: true,
  policy: 'drop',
  pool: BUDGET_QI,
  pruned_subsets: 0,
  qi_columns: BUDGET_QI,
  subset_space: 1023,
  threshold: 5,
  verdict: 'ok',
}

function assertSearchTruth(result, expected) {
  for (const [key, value] of Object.entries(expected)) {
    assert.deepEqual(result[key], value, `search.${key} 与真值不一致`)
  }
  assert.deepEqual(result.minimal_collapse_sets, expected.minimal_collapse_sets)
}

test('m3: tiny search matches truth', () => {
  const truth = loadTruth('tiny')
  const result = search(
    fixtureTable('tiny'),
    truth.qi_columns,
    truth.sensitive_columns,
    truth.meta.policy,
    truth.meta.threshold,
    truth.meta.budget,
  )
  assertSearchTruth(result, truth.search)
})

test('m3: small search matches truth', () => {
  const truth = loadTruth('small')
  const result = search(
    fixtureTable('small'),
    truth.qi_columns,
    truth.sensitive_columns,
    truth.meta.policy,
    truth.meta.threshold,
    truth.meta.budget,
  )
  assertSearchTruth(result, truth.search)
})

test('m3: prune search matches truth', () => {
  const truth = loadTruth('prune')
  const result = search(
    fixtureTable('prune'),
    truth.qi_columns,
    truth.sensitive_columns,
    truth.meta.policy,
    truth.meta.threshold,
    truth.meta.budget,
  )
  assertSearchTruth(result, truth.search)
})

test('m3: budget search matches truth', () => {
  const result = search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 5, 40)
  assertSearchTruth(result, BUDGET_SEARCH_TRUTH)
})

function scenarioOf(truth, name) {
  return truth.search_scenarios.find((item) => item.name === name)
}

function assertScenario(result, scenario) {
  for (const [key, value] of Object.entries(scenario)) {
    if (key === 'name') continue
    assert.deepEqual(result[key], value, `scenario.${key} 与真值不一致`)
  }
}

test('m3: scenario coverage names are default/empty/no_solution on all suites', () => {
  for (const suite of ['tiny', 'small', 'prune']) {
    const names = new Set(loadTruth(suite).search_scenarios.map((item) => item.name))
    assert.deepEqual(names, new Set(['default', 'empty_set_witness', 'no_solution']), suite)
  }
})

test('m3: tiny default scenario matches truth', () => {
  const truth = loadTruth('tiny')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'default').threshold, null)
  assertScenario(result, scenarioOf(truth, 'default'))
})

test('m3: tiny empty_set_witness scenario matches truth', () => {
  const truth = loadTruth('tiny')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'empty_set_witness').threshold, null)
  assertScenario(result, scenarioOf(truth, 'empty_set_witness'))
})

test('m3: tiny no_solution scenario matches truth', () => {
  const truth = loadTruth('tiny')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'no_solution').threshold, null)
  assertScenario(result, scenarioOf(truth, 'no_solution'))
})

test('m3: small default scenario matches truth', () => {
  const truth = loadTruth('small')
  const result = search(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'default').threshold, null)
  assertScenario(result, scenarioOf(truth, 'default'))
})

test('m3: small empty_set_witness scenario matches truth', () => {
  const truth = loadTruth('small')
  const result = search(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'empty_set_witness').threshold, null)
  assertScenario(result, scenarioOf(truth, 'empty_set_witness'))
})

test('m3: small no_solution scenario matches truth', () => {
  const truth = loadTruth('small')
  const result = search(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'no_solution').threshold, null)
  assertScenario(result, scenarioOf(truth, 'no_solution'))
})

test('m3: prune default scenario matches truth', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'default').threshold, null)
  assertScenario(result, scenarioOf(truth, 'default'))
})

test('m3: prune empty_set_witness scenario matches truth', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'empty_set_witness').threshold, null)
  assertScenario(result, scenarioOf(truth, 'empty_set_witness'))
})

test('m3: prune no_solution scenario matches truth', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', scenarioOf(truth, 'no_solution').threshold, null)
  assertScenario(result, scenarioOf(truth, 'no_solution'))
})

test('m3: budget default scenario matches truth', () => {
  const result = search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 5, null)
  assert.equal(result.verdict, 'ok')
  assert.equal(result.completeness, 'exhausted')
  assert.equal(result.evaluated_subsets, 61)
  assert.equal(result.pruned_subsets, 963)
  assert.equal(result.minimal_collapse_sets.length, 11)
})

test('m3: budget empty_set_witness scenario matches truth', () => {
  const result = search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 574, null)
  assert.equal(result.verdict, 'ok')
  assert.deepEqual(result.minimal_collapse_sets, [[]])
  assert.equal(result.empty_set_witness, true)
  assert.equal(result.evaluated_subsets, 11)
  assert.equal(result.pruned_subsets, 1013)
})

test('m3: budget no_solution scenario matches truth', () => {
  const result = search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 1201, null)
  assert.equal(result.verdict, 'no_solution')
  assert.deepEqual(result.minimal_collapse_sets, [])
  assert.equal(result.evaluated_subsets, 1)
  assert.equal(result.pruned_subsets, 0)
})

test('m3: completeness states are closed and mutually exclusive', () => {
  assert.equal(completeness(true, true), 'exhausted')
  assert.equal(completeness(false, true), 'monotonicity-not-applicable')
  assert.equal(completeness(true, false), 'budget-truncated')
  assert.equal(completeness(false, false), 'budget-truncated')
  assert.equal(completeness(false, true, false), 'exhausted')
  assert.deepEqual([...COMPLETENESS_STATES], ['exhausted', 'budget-truncated', 'monotonicity-not-applicable'])
})

test('m3: collapse_sets_status maps only exhausted to exhaustive', () => {
  assert.equal(collapseSetsStatus('exhausted'), 'exhaustive')
  assert.equal(collapseSetsStatus('budget-truncated'), 'non-exhaustive')
  assert.equal(collapseSetsStatus('monotonicity-not-applicable'), 'non-exhaustive')
})

test('m3: budget truncation never pretends exhaustive', () => {
  const full = search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 5, 40)
  const truncated = search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 5, 10)
  assert.equal(truncated.evaluated_subsets, 10)
  assert.equal(truncated.completeness, 'budget-truncated')
  assert.equal(truncated.non_exhaustive, true)
  assert.equal(truncated.collapse_sets_status, 'non-exhaustive')
  assert.equal(full.completeness, 'budget-truncated')
})

test('m3: budget is a hard cap on evaluated subsets including the empty set', () => {
  const truth = loadTruth('tiny')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 1)
  assert.equal(result.evaluated_subsets, 1)
  assert.equal(result.completeness, 'budget-truncated')
})

test('m3: budget-truncated empty_set_witness is false', () => {
  const table = parseTable({
    header: ['age', 'zip'],
    rows: [
      ['30', '100'],
      ['30', '101'],
      ['31', '100'],
      ['31', '101'],
    ],
  })
  const truncated = search(table, ['age', 'zip'], [], 'drop', 3, 1)
  assert.equal(truncated.completeness, 'budget-truncated')
  assert.equal(truncated.evaluated_subsets, 1)
  assert.equal(truncated.empty_set_witness, false)
  assert.deepEqual(truncated.minimal_collapse_sets, [[]])
})

test('m3: exhaustive empty_set_witness is true when every single column is unsafe', () => {
  const table = parseTable({
    header: ['age', 'zip'],
    rows: [
      ['30', '100'],
      ['30', '101'],
      ['31', '100'],
      ['31', '101'],
    ],
  })
  const result = search(table, ['age', 'zip'], [], 'drop', 3, null)
  assert.equal(result.completeness, 'exhausted')
  assert.equal(result.empty_set_witness, true)
})

test('m3: partial single-column evaluation keeps empty_set_witness false', () => {
  const table = parseTable({
    header: ['age', 'zip', 'sex'],
    rows: [
      ['30', '100', 'm'],
      ['30', '101', 'm'],
      ['31', '100', 'f'],
      ['31', '101', 'f'],
    ],
  })
  const result = search(table, ['age', 'zip', 'sex'], [], 'drop', 3, 2)
  assert.equal(result.completeness, 'budget-truncated')
  assert.equal(result.evaluated_subsets, 2)
  assert.equal(result.empty_set_witness, false)
})

test('m3: drop plus missing pool values disables pruning', () => {
  const truth = loadTruth('small')
  const result = search(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, null)
  assert.equal(result.monotonicity_applicable, false)
  assert.equal(result.completeness, 'monotonicity-not-applicable')
  assert.equal(result.pruned_subsets, 0)
  assert.equal(result.evaluated_subsets, result.subset_space + 1)
  assert.deepEqual(result.minimal_collapse_sets, truth.minimal_collapse_sets)
})

test('m3: policies that keep the row set are monotone on the same table', () => {
  const truth = loadTruth('small')
  const result = search(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'single-column', truth.meta.threshold, null)
  assert.equal(result.monotonicity_applicable, true)
  assert.equal(result.completeness, 'exhausted')
  assert.ok(result.pruned_subsets > 0)
})

test('m3: pruning is active and fully accounted for', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  assert.equal(result.pruned_subsets, 25)
  assert.equal(result.evaluated_subsets, 7)
  assert.equal(result.evaluated_subsets - 1 + result.pruned_subsets, result.subset_space)
  assert.equal(result.completeness, 'exhausted')
  assert.deepEqual(result.minimal_collapse_sets, [['age', 'region']])
})

test('m3: verdict never claims pass when the search is incomplete', () => {
  const safe = parseTable({ header: ['age', 'disease'], rows: Array.from({ length: 6 }, () => ['30', 'flu']) })
  const complete = search(safe, ['age'], [], 'drop', 5, 8)
  assert.equal(complete.completeness, 'exhausted')
  assert.equal(complete.declared_k, 6)
  assert.equal(outcomeFor(complete), 'pass')

  const truncated = search(safe, ['age'], [], 'drop', 5, 1)
  assert.equal(truncated.completeness, 'budget-truncated')
  assert.equal(outcomeFor(truncated), 'undecidable')

  const noisy = parseTable({
    header: ['age', 'disease'],
    rows: [['30', 'flu'], ['30', 'flu'], ['30', 'flu'], ['30', 'flu'], ['30', 'flu'], ['NA', 'flu']],
  })
  const nonMonotone = search(noisy, ['age'], [], 'drop', 5, 8)
  assert.equal(nonMonotone.monotonicity_applicable, false)
  assert.equal(nonMonotone.declared_k, 5)
  assert.equal(outcomeFor(nonMonotone), 'undecidable')
})

test('m3: search rejects zero threshold', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age'], [], 'drop', 0, 4), /k 门限 必须是正整数/)
})

test('m3: search rejects negative threshold', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age'], [], 'drop', -1, 4), /k 门限 必须是正整数/)
})

test('m3: search rejects boolean threshold', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age'], [], 'drop', true, 4), /k 门限 必须是正整数/)
})

test('m3: search rejects string threshold', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age'], [], 'drop', '5', 4), /k 门限 必须是正整数/)
})

test('m3: search rejects budget zero', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age'], [], 'drop', 5, 0), /搜索预算 必须是正整数/)
})

test('m3: search rejects negative budget', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age'], [], 'drop', 5, -2), /搜索预算 必须是正整数/)
})

test('m3: search rejects duplicate candidate columns', () => {
  assertThrows(() => search(fixtureTable('tiny'), ['age', 'age'], [], 'drop', 5, 4), /候选池里有重复列/)
})

test('m3: strata are recomputable with groupRows on tiny', () => {
  const truth = loadTruth('tiny')
  const table = fixtureTable('tiny')
  const result = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, null)
  for (const entry of result.strata) {
    const items = result.subsets.filter((item) => item.columns.length === entry.size)
    assert.equal(entry.evaluated, items.length)
    const defined = items.map((item) => item.k).filter((value) => value !== null)
    assert.equal(entry.min_k, defined.length === 0 ? null : Math.min(...defined))
  }
})

test('m3: strata are recomputable with groupRows on small', () => {
  const truth = loadTruth('small')
  const table = fixtureTable('small')
  const result = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, null)
  for (const entry of result.strata) {
    const items = result.subsets.filter((item) => item.columns.length === entry.size)
    assert.equal(entry.evaluated, items.length)
    const defined = items.map((item) => item.k).filter((value) => value !== null)
    assert.equal(entry.min_k, defined.length === 0 ? null : Math.min(...defined))
  }
})

test('m3: strata are recomputable with groupRows on prune', () => {
  const truth = loadTruth('prune')
  const table = fixtureTable('prune')
  const result = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  for (const entry of result.strata) {
    const items = result.subsets.filter((item) => item.columns.length === entry.size)
    assert.equal(entry.evaluated, items.length)
    const defined = items.map((item) => item.k).filter((value) => value !== null)
    assert.equal(entry.min_k, defined.length === 0 ? null : Math.min(...defined))
  }
})

test('m3: strata are recomputable with groupRows on budget', () => {
  const table = fixtureTable('budget')
  const result = search(table, BUDGET_QI, [], 'drop', 5, 40)
  for (const entry of result.strata) {
    const items = result.subsets.filter((item) => item.columns.length === entry.size)
    assert.equal(entry.evaluated, items.length)
    const defined = items.map((item) => item.k).filter((value) => value !== null)
    assert.equal(entry.min_k, defined.length === 0 ? null : Math.min(...defined))
  }
})

test('m3: subset k and exposed rows are recomputable on tiny', () => {
  const truth = loadTruth('tiny')
  const table = fixtureTable('tiny')
  const result = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, null)
  for (const item of result.subsets) {
    const grouped = groupRows(table, item.columns, 'drop')
    assert.equal(item.k, kOf(grouped.classes))
    let exposed = 0
    for (const numbers of grouped.classes.values()) {
      if (numbers.length < truth.meta.threshold) exposed += numbers.length
    }
    assert.equal(item.exposed_rows, exposed)
    assert.equal(item.safe, item.k !== null && item.k >= truth.meta.threshold)
  }
})

test('m3: pool input order does not change the conclusion', () => {
  const truth = loadTruth('tiny')
  const table = fixtureTable('tiny')
  const forward = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 64)
  const backward = search(table, [...truth.qi_columns].reverse(), truth.sensitive_columns, 'drop', truth.meta.threshold, 64)
  assert.deepEqual(forward.pool, backward.pool)
  assert.deepEqual(forward.minimal_collapse_sets, backward.minimal_collapse_sets)
  assert.equal(forward.evaluated_subsets, backward.evaluated_subsets)
})

test('m3: qi_columns keeps the input order while pool is sorted', () => {
  const truth = loadTruth('tiny')
  const table = fixtureTable('tiny')
  const result = search(table, [...truth.qi_columns].reverse(), truth.sensitive_columns, 'drop', truth.meta.threshold, 64)
  assert.deepEqual(result.qi_columns, [...truth.qi_columns].reverse())
  assert.deepEqual(result.pool, [...truth.qi_columns].sort())
})

test('m3: search is deterministic across two calls', () => {
  const truth = loadTruth('prune')
  const table = fixtureTable('prune')
  const first = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  const second = search(table, truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  assert.deepEqual(first, second)
})

test('m3: no_solution returns an empty list and only the empty subset', () => {
  const truth = loadTruth('tiny')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', 13, null)
  assert.equal(result.verdict, 'no_solution')
  assert.deepEqual(result.minimal_collapse_sets, [])
  assert.equal(result.empty_set_witness, false)
  assert.equal(result.evaluated_subsets, 1)
})

test('m3: empty set witness means not a single qi column may be added', () => {
  const truth = loadTruth('tiny')
  const scenario = scenarioOf(truth, 'empty_set_witness')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', scenario.threshold, null)
  assert.deepEqual(result.minimal_collapse_sets, [[]])
  assert.equal(result.empty_set_witness, true)
  assert.ok(result.empty_set_k >= scenario.threshold)
})

test('m3: declared_k is computed even when pruning skipped the full set', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  assert.equal(result.declared_k, 1)
})

test('m3: require_exhaustive rejects truncated searches', () => {
  assertThrows(
    () => search(fixtureTable('budget'), BUDGET_QI, [], 'drop', 5, 10, true),
    /搜索被预算截断/,
  )
})

test('m3: completeness with required=false reports exhausted on no_solution', () => {
  assert.equal(completeness(false, true, false), 'exhausted')
})

test('m3: budget truncation takes priority over monotonicity', () => {
  assert.equal(completeness(false, false), 'budget-truncated')
})

test('m3: empty pool is no_solution with zero candidates', () => {
  const result = search(fixtureTable('tiny'), [], [], 'drop', 3, 10)
  assert.equal(result.verdict, 'no_solution')
  assert.equal(result.candidate_count, 0)
  assert.equal(result.subset_space, 0)
  assert.equal(result.evaluated_subsets, 1)
})

test('m3: empty table is no_solution with undefined empty_set_k', () => {
  const table = parseTable({ header: ['age'], rows: [] })
  const result = search(table, ['age'], [], 'drop', 3, 10)
  assert.equal(result.verdict, 'no_solution')
  assert.equal(result.empty_set_k, null)
  assert.equal(result.declared_k, null)
  assert.equal(result.completeness, 'exhausted')
})

test('m3: non-monotone searches enumerate the full subset space', () => {
  const truth = loadTruth('small')
  const result = search(fixtureTable('small'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 256)
  assert.equal(result.evaluated_subsets, result.subset_space + 1)
  assert.equal(result.monotonicity_applicable, false)
})

test('m3: budget counters include the empty set', () => {
  const truth = loadTruth('tiny')
  const result = search(fixtureTable('tiny'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 1)
  assert.equal(result.evaluated_subsets, 1)
  assert.deepEqual(result.subsets.map((item) => item.columns), [[]])
})

test('m3: k equal to the threshold is safe', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [['30', 'flu'], ['30', 'cold']],
  })
  const result = search(table, ['age'], [], 'drop', 2, 10)
  assert.equal(result.subsets[0].safe, true)
  assert.equal(result.declared_k, 2)
  assert.equal(result.verdict, 'ok')
})

test('m3: minimal sets have no safe one-column extension', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  const safeKeys = new Set(result.subsets.filter((item) => item.safe).map((item) => JSON.stringify(item.columns)))
  for (const combo of result.minimal_collapse_sets) {
    for (const column of result.pool) {
      if (combo.includes(column)) continue
      const extended = [...combo, column].sort()
      assert.equal(safeKeys.has(JSON.stringify(extended)), false, `${combo} + ${column}`)
    }
  }
})

test('m3: subset_space equals 2^n - 1', () => {
  const truth = loadTruth('prune')
  const result = search(fixtureTable('prune'), truth.qi_columns, truth.sensitive_columns, 'drop', truth.meta.threshold, 4096)
  assert.equal(result.subset_space, 2 ** result.candidate_count - 1)
})

test('m3: monotonicityHolds is policy-dependent', () => {
  const table = fixtureTable('small')
  const truth = loadTruth('small')
  assert.equal(monotonicityHolds(table, truth.qi_columns, 'drop'), false)
  assert.equal(monotonicityHolds(table, truth.qi_columns, 'single-column'), true)
  assert.equal(monotonicityHolds(table, truth.qi_columns, 'separate-class'), true)
})

// ── D. 逐记录风险（源仓 test_m4_risk） ──────────────────────────────────

test('m4: tiny prosecutor flagged rows match unique_records truth', () => {
  const truth = loadTruth('tiny')
  const result = risk(fixtureTable('tiny'), truth.qi_columns, truth.meta.policy, 'prosecutor')
  assert.deepEqual(result.flagged_rows, truth.unique_records)
  assert.equal(result.threshold, 1)
  assert.equal(result.rule, 'class_size == 1')
  assert.equal(result.verdict, 'violation')
})

test('m4: small prosecutor flagged rows match unique_records truth', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, truth.meta.policy, 'prosecutor')
  assert.deepEqual(result.flagged_rows, truth.unique_records)
  assert.equal(result.verdict, 'violation')
})

test('m4: prune prosecutor flagged rows match unique_records truth', () => {
  const truth = loadTruth('prune')
  const result = risk(fixtureTable('prune'), truth.qi_columns, truth.meta.policy, 'prosecutor')
  assert.deepEqual(result.flagged_rows, truth.unique_records)
})

test('m4: budget prosecutor flagged rows match unique_records truth', () => {
  const table = fixtureTable('budget')
  const truth = loadTruth('small')
  void truth
  const result = risk(table, BUDGET_QI, 'drop', 'prosecutor')
  assert.equal(result.verdict, 'violation')
  assert.equal(result.flagged_rows.length, 1200)
})

test('m4: drop class ids are recomputable from declaration order', () => {
  const truth = loadTruth('small')
  const table = fixtureTable('small')
  const qi = truth.declaration_order.filter((item) => item.role === 'qi').map((item) => item.name)
  const indices = qi.map((name) => table.columnIndex(name))
  const expected = new Map()
  for (const row of table.rows) {
    const selected = indices.map((index) => row.values[index])
    if (selected.some((value) => isMissing(value))) continue
    expected.set(row.rowNumber, selected.map((value, position) => `${qi[position]}=${value}`).join('|'))
  }
  const result = risk(table, truth.qi_columns, 'drop', 'journalist')
  for (const record of result.records) {
    if (!record.participates) continue
    assert.equal(record.class_id, expected.get(record.row_number))
  }
})

test('m4: separate-class class ids are recomputable from declaration order', () => {
  const truth = loadTruth('small')
  const table = fixtureTable('small')
  const qi = truth.declaration_order.filter((item) => item.role === 'qi').map((item) => item.name)
  const indices = qi.map((name) => table.columnIndex(name))
  const expected = new Map()
  for (const row of table.rows) {
    const selected = indices.map((index) => row.values[index])
    if (selected.some((value) => isMissing(value))) {
      expected.set(row.rowNumber, '__MISSING__')
      continue
    }
    expected.set(row.rowNumber, selected.map((value, position) => `${qi[position]}=${value}`).join('|'))
  }
  const result = risk(table, truth.qi_columns, 'separate-class', 'journalist')
  for (const record of result.records) {
    assert.equal(record.class_id, expected.get(record.row_number))
  }
})

test('m4: class sizes match a plain counter over the class ids', () => {
  const truth = loadTruth('small')
  const table = fixtureTable('small')
  const result = risk(table, truth.qi_columns, 'drop', 'journalist')
  const counts = new Map()
  for (const record of result.records) {
    if (record.class_id === null) continue
    counts.set(record.class_id, (counts.get(record.class_id) ?? 0) + 1)
  }
  for (const record of result.records) {
    if (record.class_id === null) continue
    assert.equal(record.class_size, counts.get(record.class_id))
  }
})

test('m4: class keys start with the first declared qi column', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, 'drop', 'journalist')
  const keys = result.records.map((record) => record.class_id).filter((key) => key !== null)
  assert.ok(keys.some((key) => key.startsWith('age=')))
})

test('m4: separate-class includes the missing class key', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, 'separate-class', 'journalist')
  assert.ok(result.records.some((record) => record.class_id === MISSING_CLASS_KEY))
})

function sizedClassTable() {
  return parseTable({
    header: ['age', 'disease'],
    rows: [
      ['10', 'flu'],
      ['20', 'flu'],
      ['20', 'cold'],
      ['30', 'flu'],
      ['30', 'cold'],
      ['30', 'flu'],
    ],
  })
}

test('m4: prosecutor flags only class_size == 1', () => {
  const result = risk(sizedClassTable(), ['age'], 'drop', 'prosecutor')
  assert.equal(result.rule, 'class_size == 1')
  assert.deepEqual(result.flagged_rows, [1])
  assert.deepEqual(result.records.map((record) => record.flagged), [true, false, false, false, false, false])
})

test('m4: journalist flags size two but not size three', () => {
  const result = risk(sizedClassTable(), ['age'], 'drop', 'journalist')
  assert.equal(result.rule, 'class_size <= 2')
  assert.deepEqual(result.flagged_rows, [1, 2, 3])
  const bySize = Object.fromEntries(result.records.map((record) => [record.class_size, record.flagged]))
  assert.deepEqual(bySize, { 1: true, 2: true, 3: false })
})

test('m4: marketer flags below three, not three', () => {
  const result = risk(sizedClassTable(), ['age'], 'drop', 'marketer')
  assert.equal(result.rule, 'class_size < 3')
  assert.deepEqual(result.flagged_rows, [1, 2, 3])
  assert.deepEqual(
    result.records.filter((record) => record.class_size === 3).map((record) => record.flagged),
    [false, false, false],
  )
  assert.deepEqual(result.by_class_size, {
    '1': { classes: 1, records: 1, flagged_records: 1 },
    '2': { classes: 1, records: 2, flagged_records: 2 },
    '3': { classes: 1, records: 3, flagged_records: 0 },
  })
})

test('m4: classify rules do not bleed across attackers', () => {
  const classes = new Map([
    ['one', [1]],
    ['two', [2, 3]],
    ['three', [4, 5, 6]],
  ])
  assert.deepEqual(classify(classes, 'prosecutor').map((item) => item.flagged), [true, false, false])
  assert.deepEqual(classify(classes, 'journalist').map((item) => item.flagged), [true, true, false])
  assert.deepEqual(classify(classes, 'marketer').map((item) => item.flagged), [true, true, false])
})

test('m4: attacker thresholds are the source table', () => {
  assert.deepEqual([...ATTACKERS], ['prosecutor', 'journalist', 'marketer'])
  assert.equal(isFlagged(1, 'prosecutor'), true)
  assert.equal(isFlagged(2, 'prosecutor'), false)
  assert.equal(isFlagged(2, 'journalist'), true)
  assert.equal(isFlagged(3, 'journalist'), false)
  assert.equal(isFlagged(2, 'marketer'), true)
  assert.equal(isFlagged(3, 'marketer'), false)
})

test('m4: risk passes when no record is flagged', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['30', 'flu'], ['30', 'cold'], ['30', 'flu']] })
  for (const attacker of ATTACKERS) {
    const result = risk(table, ['age'], 'drop', attacker)
    assert.deepEqual(result.flagged_rows, [])
    assert.equal(result.verdict, 'pass')
  }
})

test('m4: empty table risk is undecidable with empty_table reason', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [] })
  const result = risk(table, ['age'], 'drop', 'journalist')
  assert.equal(result.class_count, 0)
  assert.deepEqual(result.records, [])
  assert.equal(result.undefined_reason, 'empty_table')
  assert.equal(result.verdict, 'undecidable')
})

test('m4: drop-all-missing is undecidable, not pass', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['NA', 'flu'], ['-', 'cold']] })
  const result = risk(table, ['age'], 'drop', 'prosecutor')
  assert.equal(result.class_count, 0)
  assert.equal(result.undefined_reason, 'no_participating_rows')
  assert.equal(result.verdict, 'undecidable')
  assert.deepEqual(result.records.map((record) => record.row_number), [1, 2])
})

test('m4: drop undecided rows have the fixed record shape', () => {
  const table = parseTable({ header: ['age', 'disease'], rows: [['NA', 'flu'], ['30', 'flu'], ['30', 'cold']] })
  const result = risk(table, ['age'], 'drop', 'journalist')
  assert.deepEqual(result.records[0], {
    row_number: 1,
    class_id: null,
    class_size: null,
    flagged: false,
    attacker: 'journalist',
    participates: false,
    undefined_reason: UNDECIDED_ROW_REASON,
  })
  assert.deepEqual(result.flagged_rows, [2, 3])
  assert.equal(result.class_count, 1)
})

test('m4: separate-class missing rows get the missing class id and size', () => {
  const table = parseTable({
    header: ['age', 'disease'],
    rows: [['NA', 'flu'], ['NA', 'cold'], ['30', 'flu'], ['30', 'cold'], ['30', 'flu']],
  })
  const result = risk(table, ['age'], 'separate-class', 'journalist')
  const missing = result.records.filter((record) => record.class_id === '__MISSING__')
  assert.deepEqual(missing.map((record) => record.row_number), [1, 2])
  assert.deepEqual(new Set(missing.map((record) => record.class_size)), new Set([2]))
  assert.ok(missing.every((record) => record.flagged && record.participates))
  assert.deepEqual(result.by_class_size['2'], { classes: 1, records: 2, flagged_records: 2 })
})

test('m4: risk is deterministic across two calls', () => {
  const truth = loadTruth('small')
  const table = fixtureTable('small')
  const first = risk(table, truth.qi_columns, 'separate-class', 'marketer')
  const second = risk(table, truth.qi_columns, 'separate-class', 'marketer')
  assert.deepEqual(first, second)
})

test('m4: records cover every row in ascending order', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, 'drop', 'prosecutor')
  assert.deepEqual(result.records.map((record) => record.row_number), Array.from({ length: truth.rows }, (_, index) => index + 1))
})

test('m4: rule text matches the attacker table', () => {
  assert.equal(ruleText('prosecutor'), 'class_size == 1')
  assert.equal(ruleText('journalist'), 'class_size <= 2')
  assert.equal(ruleText('marketer'), 'class_size < 3')
})

test('m4: unknown attacker is rejected', () => {
  assertThrows(() => risk(fixtureTable('tiny'), ['age'], 'drop', 'nobody'), /未知的攻击者模型/)
})

test('m4: risk pool echoes the declared qi order', () => {
  const truth = loadTruth('tiny')
  const result = risk(fixtureTable('tiny'), truth.qi_columns, 'drop', 'prosecutor')
  assert.deepEqual(result.pool, truth.qi_columns)
})

test('m4: risk class count matches the class map size', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, 'drop', 'prosecutor')
  assert.equal(result.class_count, truth.by_policy.drop.class_count)
})

test('m4: flagged rows are sorted ascending', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, 'drop', 'prosecutor')
  assert.deepEqual(result.flagged_rows, [...result.flagged_rows].sort((a, b) => a - b))
})

test('m4: by_class_size only lists sizes that occur', () => {
  const truth = loadTruth('tiny')
  const result = risk(fixtureTable('tiny'), truth.qi_columns, 'drop', 'prosecutor')
  assert.deepEqual(Object.keys(result.by_class_size), ['1'])
})

test('m4: risk undefined reason is null on a normal table', () => {
  const truth = loadTruth('tiny')
  const result = risk(fixtureTable('tiny'), truth.qi_columns, 'drop', 'prosecutor')
  assert.equal(result.undefined_reason, null)
})

test('m4: records keep participates=false for every dropped row', () => {
  const truth = loadTruth('small')
  const result = risk(fixtureTable('small'), truth.qi_columns, 'drop', 'prosecutor')
  const dropped = result.records.filter((record) => !record.participates)
  assert.ok(dropped.length > 0)
  assert.ok(dropped.every((record) => record.class_id === null && record.class_size === null))
})

// ── E. 判据组合 / 评估 / 唯一入口（源仓 test_m5_gate + test_contract） ──

const BALANCED_ROWS = [
  ['30', '100', 'flu'],
  ['30', '100', 'flu'],
  ['31', '101', 'cold'],
  ['31', '101', 'cold'],
]

function gateSubject(header, rows, columns, extra = {}) {
  return subjectRecord(header, rows, columns, {
    claims: [{ claim_id: 'k', check: 'k', asserted: 2 }],
    ...extra,
  })
}

function balancedSubject(extra = {}) {
  return gateSubject(
    ['age', 'zip', 'disease'],
    BALANCED_ROWS,
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
    extra,
  )
}

function gateFor(subject) {
  const criteria = parseCriteriaInput(subject)
  const scan = summarize(
    criteria.table,
    criteria.declaration.qiColumns(),
    criteria.declaration.sensitiveColumns(),
    criteria.policy,
    criteria.thresholds.k,
    criteria.thresholds.l,
    criteria.thresholds.t,
  )
  const searchResult = criteria.search.enabled
    ? search(
        criteria.table,
        criteria.declaration.qiColumns(),
        criteria.declaration.sensitiveColumns(),
        criteria.policy,
        criteria.thresholds.k,
        criteria.search.budget,
        false,
      )
    : null
  return { criteria, scan, searchResult, gate: evaluateGate(criteria, scan, searchResult) }
}

test('gate: balanced table with k=2 passes', () => {
  const { gate, scan } = gateFor(balancedSubject())
  assert.equal(scan.k_l_t.k, 2)
  assert.equal(scan.verdict, 'pass')
  assert.equal(gate.outcome, 'pass')
  assert.equal(gate.undefined_reason, null)
})

test('gate: k violation yields violation outcome', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['30', '100', 'flu'], ['31', '100', 'cold'], ['30', '101', 'flu']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
  )
  const { gate, scan } = gateFor(subject)
  assert.equal(scan.k_l_t.k, 1)
  assert.equal(gate.outcome, 'violation')
  assert.equal(gate.undefined_reason, null)
})

test('gate: empty table yields undecidable with empty_table reason', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
  )
  const { gate, scan } = gateFor(subject)
  assert.equal(gate.outcome, 'undecidable')
  assert.equal(gate.undefined_reason, 'empty_table')
  assert.equal(scan.k_l_t.k, null)
})

test('gate: all rows dropped yields undecidable with no_participating_rows', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['NA', '100', 'flu'], ['', '101', 'cold']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
  )
  const { gate, scan } = gateFor(subject)
  assert.equal(gate.outcome, 'undecidable')
  assert.equal(gate.undefined_reason, 'no_participating_rows')
  assert.deepEqual(scan.k_l_t.undecided_rows, [1, 2])
})

test('gate: l threshold violation uses the m2 engine', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['30', '100', 'flu'], ['30', '100', 'flu'], ['31', '101', 'flu'], ['31', '101', 'flu']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
    { thresholds: { k: 2, l: 2, t: null } },
  )
  const { gate, scan } = gateFor(subject)
  assert.equal(scan.k_l_t.l, 1)
  assert.equal(gate.outcome, 'violation')
})

test('gate: t threshold violation uses the m2 engine', () => {
  const subject = balancedSubject({ thresholds: { k: 2, l: null, t: 0.4 } })
  const { gate, scan } = gateFor(subject)
  assert.equal(scan.k_l_t.t, 0.5)
  assert.equal(gate.outcome, 'violation')
})

test('gate: exhaustive search writes minimal collapse sets', () => {
  const subject = balancedSubject({ search: { enabled: true, budget: 100, require_exhaustive: false } })
  const { gate, searchResult } = gateFor(subject)
  assert.equal(searchResult.completeness, 'exhausted')
  assert.deepEqual(searchResult.minimal_collapse_sets, [['age', 'zip']])
  assert.equal(gate.outcome, 'pass')
})

test('gate: budget truncated with require_exhaustive is undecidable', () => {
  const subject = balancedSubject({ search: { enabled: true, budget: 1, require_exhaustive: true } })
  const { gate, searchResult } = gateFor(subject)
  assert.equal(searchResult.completeness, 'budget-truncated')
  assert.equal(gate.outcome, 'undecidable')
  assert.equal(gate.undefined_reason, REASON_REQUIRE_EXHAUSTIVE)
})

test('gate: require_exhaustive truncation wins over a violation', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['30', '100', 'flu'], ['31', '100', 'cold'], ['30', '101', 'flu']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
    { search: { enabled: true, budget: 1, require_exhaustive: true } },
  )
  const { gate, scan, searchResult } = gateFor(subject)
  assert.equal(scan.verdict, 'violation')
  assert.equal(searchResult.completeness, 'budget-truncated')
  assert.equal(gate.outcome, 'undecidable')
  assert.equal(gate.undefined_reason, REASON_REQUIRE_EXHAUSTIVE)
})

test('gate: budget truncated without require_exhaustive is still undecidable', () => {
  const subject = balancedSubject({ search: { enabled: true, budget: 1, require_exhaustive: false } })
  const { gate } = gateFor(subject)
  assert.equal(gate.outcome, 'undecidable')
  assert.equal(gate.undefined_reason, REASON_SEARCH_NOT_EXHAUSTED)
})

test('gate: monotonicity-not-applicable blocks pass', () => {
  const subject = balancedSubject({
    table: { header: ['age', 'zip', 'disease'], rows: [...BALANCED_ROWS, ['NA', '102', 'flu']] },
    search: { enabled: true, budget: 100, require_exhaustive: false },
  })
  const { gate, scan, searchResult } = gateFor(subject)
  assert.equal(scan.verdict, 'pass')
  assert.equal(searchResult.completeness, 'monotonicity-not-applicable')
  assert.equal(gate.outcome, 'undecidable')
  assert.equal(gate.undefined_reason, REASON_SEARCH_NOT_EXHAUSTED)
})

test('gate: violation wins over non-exhaustive search', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['30', '100', 'flu'], ['31', '100', 'cold'], ['30', '101', 'flu']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
    { search: { enabled: true, budget: 100, require_exhaustive: false } },
  )
  const { gate } = gateFor(subject)
  assert.equal(gate.outcome, 'violation')
  assert.equal(gate.undefined_reason, null)
})

test('gate: empty set witness is explicit', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['30', '100', 'flu'], ['31', '101', 'cold'], ['32', '102', 'flu'], ['33', '103', 'cold']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
    { search: { enabled: true, budget: 100, require_exhaustive: false } },
  )
  const { gate, searchResult } = gateFor(subject)
  assert.equal(gate.outcome, 'violation')
  assert.deepEqual(searchResult.minimal_collapse_sets, [[]])
  assert.equal(searchResult.empty_set_witness, true)
})

test('gate: no_solution is explicit', () => {
  const subject = gateSubject(
    ['age', 'zip', 'disease'],
    [['30', '100', 'flu'], ['31', '101', 'cold']],
    { age: { role: 'qi' }, zip: { role: 'qi' }, disease: { role: 'sensitive' } },
    { thresholds: { k: 5, l: null, t: null }, search: { enabled: true, budget: 100, require_exhaustive: false } },
  )
  const { gate, searchResult } = gateFor(subject)
  assert.equal(gate.outcome, 'violation')
  assert.equal(searchResult.verdict, 'no_solution')
})

test('gate: undefined reason stays null on a clean pass', () => {
  const subject = balancedSubject({ search: { enabled: true, budget: 100, require_exhaustive: false } })
  const { gate } = gateFor(subject)
  assert.equal(gate.outcome, 'pass')
  assert.equal(gate.undefined_reason, null)
})

test('combineOutcomes: no outcomes is pass', () => {
  assert.equal(combineOutcomes(), 'pass')
})

test('combineOutcomes: pass alone stays pass', () => {
  assert.equal(combineOutcomes('pass'), 'pass')
})

test('combineOutcomes: violation beats pass', () => {
  assert.equal(combineOutcomes('pass', 'violation'), 'violation')
  assert.equal(combineOutcomes('violation', 'pass'), 'violation')
})

test('combineOutcomes: undecidable beats pass', () => {
  assert.equal(combineOutcomes('pass', 'undecidable'), 'undecidable')
})

test('combineOutcomes: undecidable beats violation', () => {
  assert.equal(combineOutcomes('violation', 'undecidable'), 'undecidable')
})

test('combineOutcomes: mixed triple keeps undecidable', () => {
  assert.equal(combineOutcomes('undecidable', 'violation', 'pass'), 'undecidable')
})

test('combineOutcomes: unknown values fall back to undecidable', () => {
  assert.equal(combineOutcomes('pass', 'nonsense'), 'undecidable')
  assert.equal(combineOutcomes(''), 'undecidable')
})

test('outcomeFor: null declared k is undecidable', () => {
  assert.equal(outcomeFor({ declared_k: null, threshold: 5, completeness: 'exhausted' }), 'undecidable')
})

test('outcomeFor: declared k below threshold is violation', () => {
  assert.equal(outcomeFor({ declared_k: 1, threshold: 5, completeness: 'exhausted' }), 'violation')
})

test('outcomeFor: non-exhausted search with safe declared k is undecidable', () => {
  assert.equal(outcomeFor({ declared_k: 6, threshold: 5, completeness: 'budget-truncated' }), 'undecidable')
  assert.equal(outcomeFor({ declared_k: 6, threshold: 5, completeness: 'monotonicity-not-applicable' }), 'undecidable')
})

test('outcomeFor: safe declared k and exhausted search is pass', () => {
  assert.equal(outcomeFor({ declared_k: 6, threshold: 5, completeness: 'exhausted' }), 'pass')
})

test('gate: search disabled leaves searchResult null', () => {
  const { searchResult } = gateFor(balancedSubject())
  assert.equal(searchResult, null)
})

test('evaluate: a matching claim becomes a claim record', () => {
  const record = evaluateOne(tinySubject())
  assert.equal(record.verdict, CLAIM)
  assert.equal(record.claim_id, 'k')
  assert.equal(record.id, 'k@-')
})

test('evaluate: refuted requires and records the trace node', () => {
  const subject = tinySubject({
    claims: [{ claim_id: 'k', check: 'k', asserted: 5, node: nodeAt(3, 'call-1') }],
  })
  const record = evaluateOne(subject, basisOf([nodeAt(3, 'call-1')]))
  assert.equal(record.verdict, REFUTED)
  assert.equal(record.id, 'k@s-anon-1#3#call-1')
  assert.equal(record.node.quote, '匿名性快照')
})

test('evaluate: mismatch without a node downgrades to inconclusive', () => {
  const subject = tinySubject({ claims: [{ claim_id: 'k', check: 'k', asserted: 5 }] })
  const record = evaluateOne(subject)
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /不能下 refuted/)
})

test('evaluate: incomplete node downgrades a refuted record', () => {
  const subject = tinySubject({
    claims: [{ claim_id: 'k', check: 'k', asserted: 5, node: { session_id: 's-anon-1', tool_call_id: 'call-1' } }],
  })
  const basis = basisOf([{ session_id: 's-anon-1', turn: null, tool_call_id: 'call-1', quote: 'q' }])
  const record = evaluateOne(subject, basis)
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /痕迹节点不完整/)
})

test('evaluate: a matching claim with no node is still a claim', () => {
  const record = evaluateOne(tinySubject())
  assert.equal(record.verdict, CLAIM)
  assert.equal(record.node, null)
})

test('evaluate: search claim without search block is inconclusive', () => {
  const subject = tinySubject({
    claims: [{ claim_id: 'c', check: 'completeness', asserted: 'exhausted', node: nodeAt(1, 'call-1') }],
  })
  const record = evaluateOne(subject, basisOf([nodeAt(1, 'call-1')]))
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.equal(record.evidence.comparison, 'undecidable')
})

test('evaluate: search-disabled record names search as the missing item', () => {
  const subject = tinySubject({
    claims: [{ claim_id: 'c', check: 'collapse-sets', asserted: [], node: nodeAt(1, 'call-1') }],
  })
  const record = evaluateOne(subject, basisOf([nodeAt(1, 'call-1')]))
  assert.match(record.message, /缺失项：search/)
  assert.match(record.message, /search 未启用/)
})

test('evaluate: subset-k with an empty column set equals the row count', () => {
  const subject = tinySubject({
    claims: [{ claim_id: 'c', check: 'subset-k', asserted: 12, columns: [] }],
  })
  const record = evaluateOne(subject)
  assert.equal(record.verdict, CLAIM)
  assert.equal(record.evidence.computed, 12)
})

test('evaluate: rows are returned in claim order before Report sorting', () => {
  const subject = tinySubject({
    claims: [
      { claim_id: 'b', check: 'k', asserted: 1 },
      { claim_id: 'a', check: 'l', asserted: 1 },
    ],
  })
  const records = [...evaluate(subject, Basis.empty('t'))]
  assert.deepEqual(records.map((record) => record.claim_id), ['b', 'a'])
})

test('evaluate: Report sorts records by claim_id', () => {
  const subject = tinySubject({
    claims: [
      { claim_id: 'b', check: 'k', asserted: 1 },
      { claim_id: 'a', check: 'l', asserted: 1 },
    ],
  })
  const report = new Report({
    product: 'traceproof',
    verb: 'anonymity-collapse',
    verb_version: VERSION,
    subject: 'tiny.json',
    records: evaluate(subject, Basis.empty('t')),
  })
  assert.deepEqual(report.records.map((record) => record.claim_id), ['a', 'b'])
})

test('evaluate: evidence never contains the product root path', () => {
  const record = evaluateOne(tinySubject())
  const text = JSON.stringify(recordToJSON(record))
  assert.equal(text.includes(PRODUCT_ROOT), false)
  assert.equal(text.replaceAll('\\', '/').includes(PRODUCT_ROOT.replaceAll('\\', '/')), false)
})

test('evaluate: evidence carries the dataset and scan summary', () => {
  const record = evaluateOne(tinySubject())
  assert.equal(record.evidence.dataset.rows, 12)
  assert.equal(record.evidence.scan.k, 1)
  assert.equal(record.evidence.check, 'k')
  assert.equal(record.evidence.computed, 1)
})

test('evaluate: two runs deep-equal the same records', () => {
  const subject = tinySubject()
  const first = [...evaluate(subject, Basis.empty('t'))]
  const second = [...evaluate(subject, Basis.empty('t'))]
  assert.deepEqual(first, second)
})

test('recordToJSON: shape is the traceproof ledger contract', () => {
  const record = evaluateOne(tinySubject())
  const json = recordToJSON(record)
  assert.deepEqual(Object.keys(json), ['id', 'claim_id', 'verdict', 'message', 'basis_ref', 'evidence'])
  assert.equal(json.basis_ref, null)
})

test('Report: summary counts claim/refuted/inconclusive', () => {
  const subject = tinySubject({
    claims: [
      { claim_id: 'a', check: 'k', asserted: 1 },
      { claim_id: 'b', check: 'k', asserted: 5 },
    ],
  })
  const report = new Report({
    product: 'traceproof',
    verb: 'anonymity-collapse',
    verb_version: VERSION,
    subject: 'tiny.json',
    records: evaluate(subject, Basis.empty('t')),
  })
  assert.deepEqual(report.summary(), { blocking: 0, total: 2, verdicts: { claim: 1, refuted: 0, inconclusive: 1 } })
  assert.equal(report.exitCode(), EXIT_OK)
})

test('verb: version follows the source repository (0.1.1)', () => {
  assert.equal(VERSION, '0.1.1')
  assert.equal(anonymityCollapseVerb.version, '0.1.1')
})

test('verb: slug is anonymity-collapse', () => {
  assert.equal(anonymityCollapseVerb.slug, 'anonymity-collapse')
})

test('verb: input_fields are the five required subject fields', () => {
  assert.deepEqual([...anonymityCollapseVerb.input_fields], ['table', 'declaration', 'policy', 'thresholds', 'claims'])
})

test('registry: BUILTIN_MODULES includes 7 verbs in dictionary order', () => {
  assert.deepEqual([...BUILTIN_MODULES], [
    'agent-conflict',
    'anonymity-collapse',
    'email-evidence',
    'pattern-evidence',
    'pipeline-run',
    'rework-evidence',
    'session-replay',
  ])
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
})

test('registry: loadBuiltin registers anonymity-collapse', async () => {
  await loadBuiltin()
  assert.equal(get('anonymity-collapse').version, VERSION)
})

test('cli: list shows anonymity-collapse with its version', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /anonymity-collapse\s+0\.1\.1/)
})

test('cli: list --json returns all seven verbs', async () => {
  const { code, out } = await capture(() => main(['list', '--json']))
  assert.equal(code, EXIT_OK)
  const verbs = JSON.parse(out)
  assert.equal(verbs.length, 7)
  assert.ok(verbs.some((verb) => verb.slug === 'anonymity-collapse' && verb.version === '0.1.1'))
})

test('cli: passing subject exits 0', async () => {
  const subject = balancedSubject({ claims: [{ claim_id: 'k', check: 'k', asserted: 2 }] })
  const { input, basis } = tempSubject(subject)
  const { code, out } = await capture(() => main(['check', 'anonymity-collapse', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_OK)
  assert.match(out, /\[claim\] k/)
  assert.match(out, /合计 1 条，阻断 0 条/)
})

test('cli: refuted subject exits 1', async () => {
  const node = nodeAt(1, 'call-1')
  const subject = balancedSubject({
    claims: [{ claim_id: 'k', check: 'k', asserted: 1, node }],
  })
  const { input, basis } = tempSubject(subject, [node])
  const { code, out } = await capture(() => main(['check', 'anonymity-collapse', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /\[refuted\] k/)
})

test('cli: mismatch without a node exits 0 with inconclusive', async () => {
  const subject = balancedSubject({ claims: [{ claim_id: 'k', check: 'k', asserted: 1 }] })
  const { input, basis } = tempSubject(subject)
  const { code, out } = await capture(() => main(['check', 'anonymity-collapse', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_OK)
  assert.match(out, /inconclusive/)
})

test('cli: unknown verb exits 3', async () => {
  const subject = balancedSubject()
  const { input, basis } = tempSubject(subject)
  const { code, err } = await capture(() => main(['check', 'no-such', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /VerbMissing/)
})

test('cli: missing input field exits 2', async () => {
  const subject = balancedSubject()
  delete subject.table
  const { input, basis } = tempSubject(subject)
  const { code, err } = await capture(() => main(['check', 'anonymity-collapse', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /缺少必填字段/)
})

test('cli: malformed JSON exits 2', async () => {
  const { input, basis } = tempSubject(balancedSubject())
  writeFileSync(input, '{not json')
  const { code, err } = await capture(() => main(['check', 'anonymity-collapse', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_INPUT)
  assert.ok(err.length > 0)
})

test('cli: --json emits the ledger JSON shape', async () => {
  const subject = balancedSubject({ claims: [{ claim_id: 'k', check: 'k', asserted: 2 }] })
  const { input, basis } = tempSubject(subject)
  const { code, out } = await capture(() =>
    main(['check', 'anonymity-collapse', '--input', input, '--basis', basis, '--json']),
  )
  assert.equal(code, EXIT_OK)
  const document = JSON.parse(out)
  assert.equal(document.product, 'traceproof')
  assert.equal(document.verb, 'anonymity-collapse')
  assert.equal(document.verb_version, '0.1.1')
  assert.equal(document.summary.total, 1)
  assert.equal(document.records[0].verdict, 'claim')
})

test('cli: adult sample exits 1 on the violated k threshold', async () => {
  const { code, out } = await capture(() =>
    main([
      'check',
      'anonymity-collapse',
      '--input',
      join(SAMPLES, 'anonymity-collapse.json'),
      '--basis',
      join(SAMPLES, 'anonymity-collapse-traces.json'),
    ]),
  )
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /\[refuted\] adult-k-threshold/)
  assert.match(out, /\[claim\] adult-collapse-set/)
  assert.match(out, /合计 11 条，阻断 1 条/)
})

test('cli: adult sample --json reports 10 claims and 1 refuted', async () => {
  const { code, out } = await capture(() =>
    main([
      'check',
      'anonymity-collapse',
      '--input',
      join(SAMPLES, 'anonymity-collapse.json'),
      '--basis',
      join(SAMPLES, 'anonymity-collapse-traces.json'),
      '--json',
    ]),
  )
  assert.equal(code, EXIT_BLOCKED)
  const document = JSON.parse(out)
  assert.equal(document.summary.total, 11)
  assert.equal(document.summary.blocking, 1)
  assert.equal(document.summary.verdicts.claim, 10)
  assert.equal(document.summary.verdicts.refuted, 1)
})

test('cli: adult sample collapse set is education+sex', async () => {
  const { out } = await capture(() =>
    main([
      'check',
      'anonymity-collapse',
      '--input',
      join(SAMPLES, 'anonymity-collapse.json'),
      '--basis',
      join(SAMPLES, 'anonymity-collapse-traces.json'),
      '--json',
    ]),
  )
  const document = JSON.parse(out)
  const record = document.records.find((item) => item.claim_id === 'adult-collapse-set')
  assert.deepEqual(record.evidence.computed, [['education', 'sex']])
  assert.equal(record.verdict, 'claim')
})

test('cli: adult sample row-class evidence matches the source gate', async () => {
  const { out } = await capture(() =>
    main([
      'check',
      'anonymity-collapse',
      '--input',
      join(SAMPLES, 'anonymity-collapse.json'),
      '--basis',
      join(SAMPLES, 'anonymity-collapse-traces.json'),
      '--json',
    ]),
  )
  const document = JSON.parse(out)
  const record = document.records.find((item) => item.claim_id === 'adult-row-1')
  assert.equal(record.evidence.computed, 'age=39|education=Bachelors|sex=Male')
  assert.equal(record.verdict, 'claim')
})

test('cli: adult sample violation count matches the source gate', async () => {
  const { out } = await capture(() =>
    main([
      'check',
      'anonymity-collapse',
      '--input',
      join(SAMPLES, 'anonymity-collapse.json'),
      '--basis',
      join(SAMPLES, 'anonymity-collapse-traces.json'),
      '--json',
    ]),
  )
  const document = JSON.parse(out)
  const record = document.records.find((item) => item.claim_id === 'adult-violation-count')
  assert.equal(record.evidence.computed, 762)
  assert.equal(record.verdict, 'claim')
})

test('cli: adult sample completeness and declared k match the source gate', async () => {
  const { out } = await capture(() =>
    main([
      'check',
      'anonymity-collapse',
      '--input',
      join(SAMPLES, 'anonymity-collapse.json'),
      '--basis',
      join(SAMPLES, 'anonymity-collapse-traces.json'),
      '--json',
    ]),
  )
  const document = JSON.parse(out)
  const completenessRecord = document.records.find((item) => item.claim_id === 'adult-completeness')
  const declaredRecord = document.records.find((item) => item.claim_id === 'adult-declared-k')
  assert.equal(completenessRecord.evidence.computed, 'exhausted')
  assert.equal(declaredRecord.evidence.computed, 1)
})

// __APPEND_TESTS__