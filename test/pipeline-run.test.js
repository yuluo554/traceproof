/**
 * pipeline-run 器官的无损测试。
 *
 * 数据面：旧仓 `data/pipelines`（7 份有效样例）、`data/snapshots`（7 份冻结快照）、
 * `data/invalid`（15 份失败样例 + index manifest）只读拷贝到
 * `test/fixtures/pipeline-run/`。判定层对齐：
 *  - schema：形状校验收集全部违规、path 语法；
 *  - ir：依赖 / 模板 / skip 引用 / outputSchema 子集 / M2 gates / 拓扑确定性；
 *  - compiler：7/7 快照**逐字节**一致 + 语法有效 + 失败策略形状；
 *  - form-model：定义 <-> 表单双向无损；
 *  - run-events：折叠 / 投影 / 中断 / 成本汇总；
 *  - 器官契约：6 类主张、verdict 映射、节点定位、确定性、CLI 退出码。
 *
 * 判据 1 的 X = 旧仓判定层 14 个文件实跑 86 passed（`node --test`）；本文件
 * `test(` 调用数 ≥ 86，实跑用例数 ≥ 86。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
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
import { get } from '../lib/traceproof/core/registry.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'
import { pipelineRunVerb } from '../lib/traceproof/verbs/pipeline-run/index.js'
import { validateDef } from '../lib/traceproof/verbs/pipeline-run/schema.js'
import {
  buildIR,
  INPUT_VARIABLE,
  PREV_VARIABLE,
  segmentTemplate,
} from '../lib/traceproof/verbs/pipeline-run/ir.js'
import { compileScript } from '../lib/traceproof/verbs/pipeline-run/compiler.js'
import {
  defToForm,
  formToDef,
  serializeDef,
} from '../lib/traceproof/verbs/pipeline-run/form-model.js'
import {
  foldStart,
  foldUpdate,
  projectPipelineRun,
  sumUsage,
} from '../lib/traceproof/verbs/pipeline-run/run-events.js'

await loadBuiltin()

const ROOT = fileURLToPath(new URL('./fixtures/pipeline-run/', import.meta.url))
const PRODUCT_ROOT = fileURLToPath(new URL('..', import.meta.url))
const NODE = { session_id: 's-pipe-1', turn: 2, tool_call_id: 'call-pipe-2' }

/** 旧仓 bench 的 canned office 技能块（冻结快照就是按它生成的）。 */
const SKILL_BLOCK = [
  '<skill_content name="office">',
  '<skill_resources>',
  'Resources for this skill are managed by provider "dsh-pipeline-bench".',
  'Load referenced resources only as needed.',
  '</skill_resources>',
  '',
  '<skill_instructions>',
  'Office skill (canned): draft the brief as .docx via the document tool, then verify with the structure checker.',
  '</skill_instructions>',
  '</skill_content>',
].join('\n')

const PIPELINE_NAMES = readdirSync(join(ROOT, 'pipelines')).filter((name) => name.endsWith('.json')).sort()
const INVALID_MANIFEST = JSON.parse(readFileSync(join(ROOT, 'invalid', 'index.json'), 'utf8'))

function fixture(name) {
  return JSON.parse(readFileSync(join(ROOT, 'pipelines', name), 'utf8'))
}

function invalidFixture(name) {
  return JSON.parse(readFileSync(join(ROOT, 'invalid', name), 'utf8'))
}

function snapshot(name) {
  // 快照以 `.js.txt` 只读副本保存：`node --test` 会把 `test/` 下的 `.js` 当测试文件执行。
  return readFileSync(join(ROOT, 'snapshots', name.replace(/\.json$/, '.js.txt')), 'utf8')
}

function skillMapFor(name) {
  return name === 'skills-and-tools.json' ? new Map([['draft', [SKILL_BLOCK]]]) : undefined
}

function compileFixture(name) {
  const checked = validateDef(fixture(name))
  if (!checked.ok) throw new Error(`${name}: ${JSON.stringify(checked.errors)}`)
  const ir = buildIR(checked.def)
  return { def: checked.def, ir, script: compileScript(ir, skillMapFor(name)) }
}

function basisOf(nodes = [NODE]) {
  return Basis.fromObject({ version: '2026.11.25', nodes })
}

function evaluateSubject(subject, nodes = [NODE]) {
  return [...get('pipeline-run').evaluate(subject, basisOf(nodes))]
}

function pipelineOf(definition, extra = {}) {
  return { definition, ...extra }
}

function claimOf(claims, id) {
  return claims.find((record) => record.claim_id === id)
}

function runStartEvent(nodes, startedAt = 1000) {
  return { type: 'pipeline-run/run-start', data: { runId: 'run-1', name: 'three-node-two-models', nodes, startedAt } }
}

function agentStartEvent(seq, label, options = {}) {
  return {
    type: 'pipeline-run/agent-start',
    data: {
      runId: 'run-1',
      seq,
      label,
      phase: options.phase ?? label,
      childId: options.childId ?? `child-${seq}`,
      startedAt: options.startedAt ?? 2000 + seq,
      ...(options.provider !== undefined ? { provider: options.provider } : {}),
      ...(options.model !== undefined ? { model: options.model } : {}),
    },
  }
}

function agentEndEvent(seq, outcome, options = {}) {
  return {
    type: 'pipeline-run/agent-end',
    data: {
      runId: 'run-1',
      seq,
      outcome,
      durationMs: options.durationMs ?? 100,
      ...(options.usage !== undefined ? { usage: options.usage } : {}),
    },
  }
}

function runEndEvent(stopReason, durationMs = 5000, error) {
  return {
    type: 'pipeline-run/run-end',
    data: { runId: 'run-1', stopReason, durationMs, ...(error !== undefined ? { error } : {}) },
  }
}

const PLAN = [
  { id: 'outline', label: 'Outline', provider: 'deepseek', model: 'deepseek-chat' },
  { id: 'review', label: 'Review' },
  { id: 'write', label: 'Write', provider: 'deepseek', model: 'deepseek-reasoner' },
]

function foldEvents(events, interrupted = false) {
  let state = foldStart(events[0].data)
  for (const event of events.slice(1)) state = foldUpdate(state, event)
  return projectPipelineRun(state, { interrupted })
}

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

function tempFiles(subject) {
  const dir = mkdtempSync(join(tmpdir(), 'pipeline-run-test-'))
  const subjectPath = join(dir, 'subject.json')
  const basisPath = join(dir, 'basis.json')
  writeFileSync(subjectPath, JSON.stringify(subject))
  writeFileSync(basisPath, JSON.stringify({ version: '2026.11.25', nodes: [NODE] }))
  return { dir, subjectPath, basisPath }
}

// ===========================================================================
// 1. schema：定义形状
// ===========================================================================

test('schema: every shipped pipeline fixture passes validateDef', () => {
  for (const name of PIPELINE_NAMES) {
    const result = validateDef(fixture(name))
    assert.equal(result.ok, true, `${name}: ${JSON.stringify(result.ok ? [] : result.errors)}`)
  }
})

test('schema: non-object input rejected with exactly one clear error', () => {
  for (const raw of [null, 42, 'x', [], true, undefined]) {
    const result = validateDef(raw)
    assert.equal(result.ok, false)
    assert.equal(result.errors.length, 1)
    assert.match(result.errors[0].message, /必须是 JSON 对象/)
  }
})

test('schema: shape errors are collected, not fail-fast', () => {
  const result = validateDef({ name: 'bad name!', description: '', nodes: [] })
  assert.equal(result.ok, false)
  const paths = result.errors.map((error) => error.path)
  assert.ok(paths.includes('name'))
  assert.ok(paths.includes('description'))
  assert.ok(paths.includes('nodes'))
})

test('schema: unknown top-level and node fields are rejected', () => {
  const def = fixture('single-node.json')
  def.unknownTopLevel = true
  def.nodes[0].unknownNodeField = true
  const result = validateDef(def)
  assert.equal(result.ok, false)
  const messages = result.errors.map((error) => `${error.path}: ${error.message}`).join('; ')
  assert.match(messages, /unknownTopLevel/)
  assert.match(messages, /unknownNodeField/)
})

test('schema: node id grammar enforced and reserved "input" stays shape-legal', () => {
  const bad = fixture('single-node.json')
  bad.nodes[0].id = 'my node!'
  assert.equal(validateDef(bad).ok, false)
  // 保留字是 IR 语义层拒绝，形状层必须放行（与旧仓一致）。
  assert.equal(validateDef(invalidFixture('ir-reserved-id.json')).ok, true)
})

test('schema: model.reasoningEffort is shape-legal; empty model strings rejected', () => {
  const def = fixture('three-node-two-models.json')
  def.nodes[0].model.reasoningEffort = 'high'
  assert.equal(validateDef(def).ok, true)
  const bad = fixture('three-node-two-models.json')
  bad.nodes[0].model.model = ''
  assert.equal(validateDef(bad).ok, false)
})

test('schema: dependsOn duplicates rejected at shape level', () => {
  const def = fixture('depends-explicit.json')
  def.nodes[2].dependsOn = ['facts', 'facts']
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => /重复依赖/.test(error.message)))
  assert.ok(result.errors.some((error) => /dependsOn\[1\]/.test(error.path)))
})

test('schema: tools must declare at least one of allow / deny', () => {
  const def = fixture('single-node.json')
  def.nodes[0].tools = {}
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.match(result.errors[0].message, /至少声明 allow \/ deny/)
})

test('schema: options.maxAgentsPerNode must be a positive integer', () => {
  for (const value of [0, -1, 1.5, '3', null]) {
    const def = fixture('single-node.json')
    def.options = { maxAgentsPerNode: value }
    const result = validateDef(def)
    assert.equal(result.ok, false, `value ${String(value)} should reject`)
    assert.ok(result.errors.some((error) => error.path === 'options.maxAgentsPerNode'))
  }
})

test('schema: options.defaultFailurePolicy closed to abort / skip', () => {
  const def = fixture('single-node.json')
  def.options = { defaultFailurePolicy: 'retry' }
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.path === 'options.defaultFailurePolicy'))
})

test('schema: unknown option fields rejected', () => {
  const def = fixture('single-node.json')
  def.options = { surprise: true }
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.path === 'options.surprise'))
})

test('schema: retry must be a non-negative integer', () => {
  for (const value of [-1, 1.5, '1']) {
    const def = fixture('single-node.json')
    def.nodes[0].retry = value
    const result = validateDef(def)
    assert.equal(result.ok, false, `retry ${String(value)} should reject`)
    assert.ok(result.errors.some((error) => error.path === 'nodes[0].retry'))
  }
})

test('schema: outputSchema must be an object', () => {
  const def = fixture('single-node.json')
  def.nodes[0].outputSchema = []
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.path === 'nodes[0].outputSchema'))
})

test('schema: skills must be a non-empty string array', () => {
  for (const value of [[], ['ok', ''], 'office']) {
    const def = fixture('single-node.json')
    def.nodes[0].skills = value
    const result = validateDef(def)
    assert.equal(result.ok, false, `skills ${JSON.stringify(value)} should reject`)
    assert.ok(result.errors.some((error) => error.path === 'nodes[0].skills'))
  }
})

test('schema: label must be non-blank when present', () => {
  const def = fixture('single-node.json')
  def.nodes[0].label = '   '
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.path === 'nodes[0].label'))
})

test('schema: description must be non-blank', () => {
  const def = fixture('single-node.json')
  def.description = '   '
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.path === 'description'))
})

test('schema: name must start with an alphanumeric character', () => {
  for (const name of ['-leading', '_leading', 'has space', '']) {
    const def = fixture('single-node.json')
    def.name = name
    const result = validateDef(def)
    assert.equal(result.ok, false, `name ${JSON.stringify(name)} should reject`)
    assert.ok(result.errors.some((error) => error.path === 'name'))
  }
})

test('schema: empty prompt entries are reported with their index and the array', () => {
  const def = fixture('single-node.json')
  def.nodes[0].prompts = ['ok', '']
  const result = validateDef(def)
  assert.equal(result.ok, false)
  const paths = result.errors.map((error) => error.path)
  assert.ok(paths.includes('nodes[0].prompts[1]'))
  assert.ok(paths.includes('nodes[0].prompts'))
})

test('schema: dependsOn entries must be syntactically valid ids', () => {
  const def = fixture('depends-explicit.json')
  def.nodes[2].dependsOn = ['bad id']
  const result = validateDef(def)
  assert.equal(result.ok, false)
  assert.ok(result.errors.some((error) => error.path === 'nodes[2].dependsOn'))
})

test('schema: valid definition assembles documented field order', () => {
  const def = fixture('single-node.json')
  const checked = validateDef(def)
  assert.equal(checked.ok, true)
  assert.deepEqual(Object.keys(checked.def), ['name', 'description', 'nodes'])
  assert.deepEqual(Object.keys(checked.def.nodes[0]), ['id', 'label', 'prompts'])
})

test('schema: optional valid fixture set covers all 7 pipelines', () => {
  assert.deepEqual(PIPELINE_NAMES, [
    'depends-explicit.json',
    'multi-prompt-node.json',
    'output-schema.json',
    'retry-skip.json',
    'single-node.json',
    'skills-and-tools.json',
    'three-node-two-models.json',
  ])
})

// ===========================================================================
// 2. IR：语义归一化
// ===========================================================================

test('ir: topological order is deterministic across repeated builds', () => {
  const first = buildIR(fixture('depends-explicit.json'))
  for (let index = 0; index < 5; index += 1) {
    assert.deepEqual(buildIR(fixture('depends-explicit.json')), first)
  }
  assert.deepEqual(first.nodes.map((node) => node.id), ['facts', 'quotes', 'brief'])
})

test('ir: explicit dependsOn overrides implicit chaining', () => {
  const ir = buildIR(fixture('depends-explicit.json'))
  assert.deepEqual(ir.nodes.map((node) => node.id), ['facts', 'quotes', 'brief'])
})

test('ir: implicit chaining applies when dependsOn is absent', () => {
  assert.deepEqual(
    buildIR(fixture('three-node-two-models.json')).nodes.map((node) => node.id),
    ['outline', 'review', 'write'],
  )
})

test('ir: semantic matrix matches the frozen 15-file manifest', () => {
  const entries = Object.entries(INVALID_MANIFEST).filter(([file]) => file.endsWith('.json'))
  assert.equal(entries.length, 15)
  for (const [file, expected] of entries) {
    const checked = validateDef(invalidFixture(file))
    if (!checked.ok) {
      assert.equal(expected, 'SCHEMA_INVALID', `${file}: shape-invalid fixtures must be SCHEMA_INVALID`)
      continue
    }
    try {
      buildIR(checked.def)
      assert.fail(`${file} compiled but must reject`)
    } catch (error) {
      assert.equal(error.code, expected, `${file}: ${error.message}`)
    }
  }
})

test('ir: unknown-variable message names the node location and the variable', () => {
  try {
    buildIR(invalidFixture('ir-unknown-variable.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_UNKNOWN_VARIABLE')
    assert.match(error.message, /nodes\[0\]\.prompts\[0\] \(node "a"\)/)
    assert.match(error.message, /\{\{ghost\}\}/)
  }
})

test('ir: template segmentation round-trips static and reference segments', () => {
  const segments = segmentTemplate('a {{input}} b {{outline}} c', 'loc')
  assert.deepEqual(
    segments.map((segment) => (segment.kind === 'static' ? segment.text : `{{${segment.ref.id ?? segment.ref.kind}}}`)),
    ['a ', '{{input}}', ' b ', '{{outline}}', ' c'],
  )
})

test('ir: malformed template expressions throw instead of becoming literals', () => {
  assert.throws(() => segmentTemplate('oops {{a b}}', 'loc'), /模板表达式不合法/)
  assert.throws(() => segmentTemplate('dangling {{', 'loc'), /模板表达式不合法/)
})

test('ir: reserved variable names are input / prev', () => {
  assert.equal(INPUT_VARIABLE, 'input')
  assert.equal(PREV_VARIABLE, 'prev')
})

test('ir: routing flags feed the capability precheck', () => {
  const ir = buildIR(fixture('three-node-two-models.json'))
  assert.deepEqual(ir.nodes.map((node) => node.needsAgentOptions), [true, false, true])
  const structured = buildIR(fixture('output-schema.json'))
  assert.deepEqual(structured.nodes.map((node) => node.needsOutputSchema), [true, false])
  assert.equal(ir.totalAgentCalls, 3)
})

test('ir: phaseTitle prefers the label and falls back to the id', () => {
  assert.deepEqual(
    buildIR(fixture('three-node-two-models.json')).nodes.map((node) => node.phaseTitle),
    ['Outline', 'Review', 'Write'],
  )
  const noLabel = validateDef({
    name: 'no-label',
    description: 'fallback',
    nodes: [{ id: 'solo', prompts: ['hi'] }],
  })
  assert.equal(noLabel.ok, true)
  assert.equal(buildIR(noLabel.def).nodes[0].phaseTitle, 'solo')
})

test('ir: failure policies resolve per node and inherit the pipeline default', () => {
  const ir = buildIR(fixture('retry-skip.json'))
  assert.deepEqual(ir.nodes.map((node) => `${node.id}:${node.failurePolicy}:${node.retry}`), [
    'fetch:skip:2',
    'enrich:skip:0',
    'report:abort:0',
    'verify:abort:1',
  ])
  const raw = fixture('retry-skip.json')
  const inherited = validateDef({
    ...raw,
    options: { defaultFailurePolicy: 'skip' },
    nodes: raw.nodes.map((node) => ({ ...node, failurePolicy: undefined, retry: undefined })),
  })
  assert.equal(inherited.ok, true)
  assert.deepEqual(
    buildIR(inherited.def).nodes.map((node) => `${node.id}:${node.failurePolicy}`),
    ['fetch:skip', 'enrich:skip', 'report:skip', 'verify:skip'],
  )
})

test('ir: skills routing stays in the IR', () => {
  const ir = buildIR(fixture('skills-and-tools.json'))
  assert.deepEqual(ir.nodes.map((node) => node.needsSkills), [true, false])
  assert.deepEqual(ir.nodes[0].skills, ['office'])
})

test('ir: skip-policy output reference is rejected with the fix', () => {
  try {
    buildIR(invalidFixture('ir-skip-reference.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_SKIP_REFERENCE')
    assert.match(error.message, /\{\{a\}\}/)
    assert.match(error.message, /failure policy "skip"/)
    assert.match(error.message, /dependsOn/)
  }
})

test('ir: dependsOn onto a skip node stays legal (ordering without consuming output)', () => {
  const checked = validateDef({
    name: 'order-only',
    description: 'ordering on a skip node is legal',
    nodes: [
      { id: 'a', prompts: ['flaky'], failurePolicy: 'skip' },
      { id: 'b', prompts: ['standalone'], dependsOn: ['a'] },
    ],
  })
  assert.equal(checked.ok, true)
  assert.deepEqual(buildIR(checked.def).nodes.map((node) => node.id), ['a', 'b'])
})

test('ir: self-dependency is rejected with its frozen code', () => {
  try {
    buildIR(invalidFixture('ir-self-dependency.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_SELF_DEPENDENCY')
  }
})

test('ir: unknown dependency is rejected with its frozen code', () => {
  try {
    buildIR(invalidFixture('ir-unknown-dependency.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_UNKNOWN_DEPENDENCY')
    assert.match(error.message, /依赖未知节点/)
  }
})

test('ir: output-schema fixture carries the object-rooted schema', () => {
  const ir = buildIR(fixture('output-schema.json'))
  assert.deepEqual(ir.nodes[0].outputSchema, {
    type: 'object',
    properties: { keywords: { type: 'array', items: { type: 'string' } } },
    required: ['keywords'],
    additionalProperties: false,
  })
})

test('ir: output schema must be object-rooted', () => {
  const checked = validateDef({
    name: 'scalar-root',
    description: 'root must be an object',
    nodes: [{ id: 'a', prompts: ['x'], outputSchema: { type: 'string' } }],
  })
  assert.equal(checked.ok, true)
  assert.throws(() => buildIR(checked.def), (error) => error.code === 'IR_OUTPUT_SCHEMA')
})

test('ir: unsupported schema keywords (format) are rejected, not ignored', () => {
  assert.throws(
    () => buildIR(invalidFixture('ir-output-schema-subset.json')),
    (error) => error.code === 'IR_OUTPUT_SCHEMA' && /format/.test(error.message),
  )
})

test('ir: template references create dependency edges', () => {
  const checked = validateDef({
    name: 'template-edge',
    description: 'second node references the first',
    nodes: [
      { id: 'consumer', prompts: ['use {{producer}}'], dependsOn: [] },
      { id: 'producer', prompts: ['produce'], dependsOn: [] },
    ],
  })
  assert.equal(checked.ok, true)
  assert.deepEqual(buildIR(checked.def).nodes.map((node) => node.id), ['producer', 'consumer'])
})

test('ir: reserved node id is rejected at the semantic layer', () => {
  try {
    buildIR(invalidFixture('ir-reserved-id.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_RESERVED_ID')
  }
})

test('ir: {{prev}} in the first prompt is rejected', () => {
  try {
    buildIR(invalidFixture('ir-prev-first-prompt.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_UNKNOWN_VARIABLE')
    assert.match(error.message, /首条 prompt/)
  }
})

test('ir: self-reference in a prompt is rejected', () => {
  const checked = validateDef({
    name: 'self-ref',
    description: 'prompt references its own node',
    nodes: [{ id: 'a', prompts: ['use {{a}}'] }],
  })
  assert.equal(checked.ok, true)
  assert.throws(() => buildIR(checked.def), (error) => error.code === 'IR_SELF_REFERENCE')
})

test('ir: maxAgentsPerNode stays gated (IR_UNSUPPORTED_FEATURE)', () => {
  const checked = validateDef({
    name: 'gated-max',
    description: 'gate',
    nodes: [{ id: 'a', prompts: ['x'] }],
    options: { maxAgentsPerNode: 3 },
  })
  assert.equal(checked.ok, true)
  assert.throws(() => buildIR(checked.def), (error) => error.code === 'IR_UNSUPPORTED_FEATURE')
})

test('ir: tools routing stays gated (IR_UNSUPPORTED_FEATURE)', () => {
  const checked = validateDef({
    name: 'gated-tools',
    description: 'gate',
    nodes: [{ id: 'a', prompts: ['x'], tools: { allow: ['search'] } }],
  })
  assert.equal(checked.ok, true)
  assert.throws(() => buildIR(checked.def), (error) => error.code === 'IR_UNSUPPORTED_FEATURE')
})

test('ir: reasoningEffort stays gated (IR_UNSUPPORTED_FEATURE)', () => {
  const checked = validateDef({
    name: 'gated-effort',
    description: 'gate',
    nodes: [{ id: 'a', prompts: ['x'], model: { reasoningEffort: 'high' } }],
  })
  assert.equal(checked.ok, true)
  assert.throws(() => buildIR(checked.def), (error) => error.code === 'IR_UNSUPPORTED_FEATURE')
})

test('ir: duplicate node id keeps its frozen code', () => {
  try {
    buildIR(invalidFixture('ir-duplicate-id.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_DUPLICATE_ID')
  }
})

test('ir: cycle keeps its frozen code and names the stuck nodes', () => {
  try {
    buildIR(invalidFixture('ir-dependency-cycle.json'))
    assert.fail('must reject')
  } catch (error) {
    assert.equal(error.code, 'IR_DEPENDENCY_CYCLE')
    assert.match(error.message, /无法拓扑排序/)
  }
})

test('ir: totalAgentCalls is the retry-aware upper bound', () => {
  assert.equal(buildIR(fixture('retry-skip.json')).totalAgentCalls, 7)
  assert.equal(buildIR(fixture('three-node-two-models.json')).totalAgentCalls, 3)
})

test('ir: IR nodes keep topological order and prompt counts', () => {
  const ir = buildIR(fixture('multi-prompt-node.json'))
  assert.deepEqual(ir.nodes.map((node) => node.prompts.length), [3])
  assert.equal(ir.totalAgentCalls, 3)
})

// ===========================================================================
// 3. compiler：冻结快照
// ===========================================================================

test('compiler: all 7 fixtures compile byte-exact against frozen snapshots', () => {
  for (const name of PIPELINE_NAMES) {
    assert.equal(compileFixture(name).script, snapshot(name), `${name}: snapshot drifted`)
  }
})

test('compiler: header line 2 is frozen (version / counts / policies)', () => {
  const script = compileFixture('three-node-two-models.json').script
  const lines = script.split('\n')
  assert.equal(lines[0], '// dsh-pipeline 0.2.2 — compiled pipeline "three-node-two-models".')
  assert.equal(lines[1], '// 3 nodes, 3 agent calls max; policies: outline=abort, review=abort, write=abort.')
})

test('compiler: retry policies append :retry in topology order', () => {
  const script = compileFixture('retry-skip.json').script
  assert.match(script, /policies: fetch=skip:2, enrich=skip, report=abort, verify=abort:1\./)
})

test('compiler: generated scripts are syntactically valid JS (compile-only)', () => {
  for (const name of PIPELINE_NAMES) {
    const script = compileFixture(name).script
    new Function('agent', 'phase', 'log', 'args', `"use strict";\nreturn (async () => {\n${script}\n})()`)
  }
})

test('compiler: multi-prompt nodes label every prompt with #k', () => {
  const script = compileFixture('multi-prompt-node.json').script
  assert.match(script, /label: "Planner #1"/)
  assert.match(script, /label: "Planner #2"/)
  assert.match(script, /label: "Planner #3"/)
})

test('compiler: skip policy settles null after the attempt loop', () => {
  const script = compileFixture('retry-skip.json').script
  assert.match(script, /out\["fetch"\] = null;/)
  assert.match(script, /while \(!__fetch_done && __fetch_attempt < 3\)/)
})

test('compiler: retry policy loops 1 + retry attempts and throws naming the prompt', () => {
  const script = compileFixture('retry-skip.json').script
  assert.match(script, /while \(!__verify_done && __verify_attempt < 2\)/)
  assert.match(script, /failed at prompt " \+ __verify_failedAt \+ " after 2 attempt\(s\)/)
})

test('compiler: default skip policy compiles the same shape as an explicit skip', () => {
  const checked = validateDef({
    name: 'default-skip',
    description: 'inherit default policy',
    nodes: [{ id: 'x', prompts: ['p'] }],
    options: { defaultFailurePolicy: 'skip' },
  })
  assert.equal(checked.ok, true)
  const script = compileScript(buildIR(checked.def))
  assert.match(script, /policies: x=skip\./)
  assert.match(script, /out\["x"\] = null;/)
})

test('compiler: outputSchema-node references interpolate through JSON.stringify', () => {
  const script = compileFixture('output-schema.json').script
  assert.match(script, /JSON\.stringify\(out\["keywords"\]\)/)
})

test('compiler: static text is JSON-escaped (quotes / newlines / backslashes)', () => {
  const prompt = 'say "hi"\nand \\ backslash'
  const checked = validateDef({
    name: 'escape',
    description: 'escaping',
    nodes: [{ id: 'a', prompts: [prompt] }],
  })
  assert.equal(checked.ok, true)
  const script = compileScript(buildIR(checked.def))
  assert.ok(script.includes('\\"hi\\"'))
  assert.ok(script.includes('\\n'))
  new Function('agent', 'phase', 'log', 'args', `"use strict";\nreturn (async () => {\n${script}\n})()`)
})

test('compiler: skill blocks are prefixed to every prompt of a skill node', () => {
  const checked = validateDef({
    name: 'skills',
    description: 'two prompts, one skill',
    nodes: [{ id: 'a', prompts: ['one', 'two {{prev}}'], skills: ['office'] }],
  })
  assert.equal(checked.ok, true)
  const ir = buildIR(checked.def)
  const script = compileScript(ir, new Map([['a', [SKILL_BLOCK]]]))
  assert.equal(script.split('<skill_instructions>').length - 1, 2)
})

test('compiler: skill node without resolved blocks fails loud with SKILL_MISSING', () => {
  const checked = validateDef({
    name: 'skills-missing',
    description: 'no blocks provided',
    nodes: [{ id: 'a', prompts: ['one'], skills: ['office'] }],
  })
  assert.equal(checked.ok, true)
  assert.throws(() => compileScript(buildIR(checked.def)), (error) => error.code === 'SKILL_MISSING')
})

test('compiler: compiling twice produces identical bytes', () => {
  assert.equal(compileFixture('retry-skip.json').script, compileFixture('retry-skip.json').script)
})

test('compiler: script never uses eval / Function', () => {
  for (const name of PIPELINE_NAMES) {
    const script = compileFixture(name).script
    assert.ok(!/\beval\s*\(/.test(script), `${name}: eval found`)
    assert.ok(!/\bFunction\s*\(/.test(script), `${name}: Function found`)
  }
})

// ===========================================================================
// 4. form-model：双向无损
// ===========================================================================

test('form: every fixture survives def -> form -> def with deep equality', () => {
  for (const name of PIPELINE_NAMES) {
    const original = fixture(name)
    const roundTripped = formToDef(defToForm(original))
    assert.ok(roundTripped.ok, `${name}: ${JSON.stringify(roundTripped.errors)}`)
    assert.deepEqual(roundTripped.def, original, `${name}: round-trip is not lossless`)
  }
})

test('form: canonical bytes are stable across the round trip', () => {
  for (const name of PIPELINE_NAMES) {
    const original = fixture(name)
    const roundTripped = formToDef(defToForm(original))
    assert.ok(roundTripped.ok)
    assert.equal(serializeDef(roundTripped.def), serializeDef(original))
  }
})

test('form: assembled definitions pass validateDef', () => {
  for (const name of PIPELINE_NAMES) {
    const original = fixture(name)
    const assembled = formToDef(defToForm(original))
    assert.ok(assembled.ok)
    assert.deepEqual(validateDef(assembled.def), { ok: true, def: assembled.def })
  }
})

test('form: loading handwritten JSON and saving it back keeps content identical', () => {
  const handwritten = fixture('three-node-two-models.json')
  const saved = formToDef(defToForm(handwritten))
  assert.ok(saved.ok)
  assert.deepEqual(JSON.parse(serializeDef(saved.def)), handwritten)
})

test('form: an edited form round-trips the edit and still validates', () => {
  const form = defToForm(fixture('single-node.json'))
  form.description = 'edited by the M3 test'
  form.nodes[0].label = 'Echo label'
  form.nodes[0].prompts.push('Second prompt: {{prev}}')
  form.nodes[0].skills = ['docx']
  form.nodes[0].failurePolicy = 'skip'
  form.nodes[0].retry = '2'
  const result = formToDef(form)
  assert.ok(result.ok)
  assert.deepEqual(validateDef(result.def), { ok: true, def: result.def })
  assert.equal(result.def.description, 'edited by the M3 test')
  assert.equal(result.def.nodes[0].label, 'Echo label')
  assert.equal(result.def.nodes[0].prompts.length, 2)
  assert.deepEqual(result.def.nodes[0].skills, ['docx'])
  assert.equal(result.def.nodes[0].failurePolicy, 'skip')
  assert.equal(result.def.nodes[0].retry, 2)
})

test('form: absent / explicit dependsOn distinction is preserved', () => {
  const implicit = formToDef(defToForm(fixture('three-node-two-models.json')))
  assert.ok(implicit.ok)
  assert.ok(implicit.def.nodes.every((node) => node.dependsOn === undefined))
  const explicit = formToDef(defToForm(fixture('depends-explicit.json')))
  assert.ok(explicit.ok)
  assert.ok(explicit.def.nodes.some((node) => node.dependsOn !== undefined))
  const empty = formToDef(defToForm({ name: 'x', description: 'x', nodes: [{ id: 'a', prompts: ['p'], dependsOn: [] }] }))
  assert.ok(empty.ok)
  assert.deepEqual(empty.def.nodes[0].dependsOn, [])
})

test('form: invalid outputSchema JSON is reported, not thrown', () => {
  const form = defToForm(fixture('single-node.json'))
  form.nodes[0].outputSchemaRaw = '{not json'
  const result = formToDef(form)
  assert.equal(result.ok, false)
  assert.match(result.errors[0].message, /JSON 不合法/)
})

test('form: non-object outputSchema JSON is reported', () => {
  const form = defToForm(fixture('single-node.json'))
  form.nodes[0].outputSchemaRaw = '[]'
  const result = formToDef(form)
  assert.equal(result.ok, false)
  assert.match(result.errors[0].message, /必须是 JSON 对象/)
})

test('form: invalid retry text is reported', () => {
  const form = defToForm(fixture('single-node.json'))
  form.nodes[0].retry = 'x'
  assert.equal(formToDef(form).ok, false)
})

test('form: gated fields ride the form losslessly', () => {
  const original = fixture('skills-and-tools.json')
  const result = formToDef(defToForm(original))
  assert.ok(result.ok)
  assert.deepEqual(result.def, original)
  const gated = formToDef(
    defToForm({
      name: 'x',
      description: 'x',
      nodes: [{ id: 'a', prompts: ['p'], model: { reasoningEffort: 'high' } }],
      options: { maxAgentsPerNode: 3 },
    }),
  )
  assert.ok(gated.ok)
  assert.deepEqual(gated.def.nodes[0].model, { reasoningEffort: 'high' })
  assert.equal(gated.def.options.maxAgentsPerNode, 3)
})

test('form: degenerate empty model / options normalize to absent', () => {
  const result = formToDef(
    defToForm({ name: 'x', description: 'x', nodes: [{ id: 'a', prompts: ['p'], model: {} }], options: {} }),
  )
  assert.ok(result.ok)
  assert.equal(result.def.nodes[0].model, undefined)
  assert.equal(result.def.options, undefined)
})

test('form: invalid failurePolicy / default policy are reported', () => {
  const form = defToForm(fixture('single-node.json'))
  form.nodes[0].failurePolicy = 'retry'
  const result = formToDef(form)
  assert.equal(result.ok, false)
  assert.equal(result.errors[0].path, 'nodes[0].failurePolicy')
  const pipeline = defToForm(fixture('single-node.json'))
  pipeline.defaultFailurePolicy = 'retry'
  assert.equal(formToDef(pipeline).ok, false)
})

test('form: tools allow/deny survive the round trip', () => {
  const def = {
    name: 'tools-form',
    description: 'tools',
    nodes: [{ id: 'a', prompts: ['p'], tools: { allow: ['search'], deny: ['shell'] } }],
  }
  const result = formToDef(defToForm(def))
  assert.ok(result.ok)
  assert.deepEqual(result.def, def)
})

// ===========================================================================
// 5. run-events：折叠与投影
// ===========================================================================

test('run-events: agent-start appends a member; agent-end patches the same seq', () => {
  const started = foldStart(runStartEvent(PLAN).data)
  assert.equal(started.members.length, 0)
  const withMember = foldUpdate(started, agentStartEvent(1, 'Outline'))
  assert.equal(withMember.members.length, 1)
  assert.equal(withMember.members[0].outcome, undefined)
  const settled = foldUpdate(
    withMember,
    agentEndEvent(1, 'completed', { durationMs: 1200, usage: { inputTokens: 100, outputTokens: 50 } }),
  )
  assert.equal(settled.members[0].outcome, 'completed')
  assert.equal(settled.members[0].durationMs, 1200)
  assert.deepEqual(settled.members[0].usage, { inputTokens: 100, outputTokens: 50 })
})

test('run-events: unrelated events return the same state reference', () => {
  const state = foldStart(runStartEvent(PLAN).data)
  assert.equal(foldUpdate(state, runStartEvent(PLAN)), state)
})

test('run-events: planned nodes render pending before any agent call', () => {
  const data = foldEvents([runStartEvent(PLAN), runEndEvent('completed')])
  assert.equal(data.status, 'completed')
  assert.deepEqual(data.nodes.map((node) => node.status), ['pending', 'pending', 'pending'])
  assert.equal(data.durationMs, 5000)
  assert.deepEqual(data.models, [])
})

test('run-events: node status follows the LAST member (retry recovery)', () => {
  const data = foldEvents([
    runStartEvent(PLAN),
    agentStartEvent(1, 'Outline'),
    agentEndEvent(1, 'failed', { durationMs: 300 }),
    agentStartEvent(2, 'Outline'),
    agentEndEvent(2, 'completed', { durationMs: 700, usage: { inputTokens: 10, outputTokens: 5 } }),
  ])
  const outline = data.nodes.find((node) => node.id === 'outline')
  assert.equal(outline.status, 'completed')
  assert.equal(outline.attempts, 2)
  assert.equal(outline.durationMs, 1000)
})

test('run-events: multi-prompt abort ends the node failed', () => {
  const data = foldEvents([
    runStartEvent(PLAN),
    agentStartEvent(1, 'Outline', { phase: 'Outline' }),
    agentEndEvent(1, 'completed'),
    agentStartEvent(2, 'Outline #2', { phase: 'Outline' }),
    agentEndEvent(2, 'failed'),
  ])
  assert.equal(data.nodes.find((node) => node.id === 'outline').status, 'failed')
})

test('run-events: skip failure settles the node failed', () => {
  const data = foldEvents([
    runStartEvent(PLAN),
    agentStartEvent(1, 'Outline'),
    agentEndEvent(1, 'failed'),
  ])
  assert.equal(data.nodes.find((node) => node.id === 'outline').status, 'failed')
})

test('run-events: live run shows running; stopReason maps to card status', () => {
  const live = foldEvents([runStartEvent(PLAN), agentStartEvent(1, 'Outline')])
  assert.equal(live.status, 'running')
  assert.equal(live.nodes.find((node) => node.id === 'outline').status, 'running')
  assert.equal(live.durationMs, undefined)
  assert.equal(
    foldEvents([runStartEvent(PLAN), agentStartEvent(1, 'Outline'), agentEndEvent(1, 'cancelled'), runEndEvent('cancelled')]).status,
    'cancelled',
  )
  assert.equal(
    foldEvents([runStartEvent(PLAN), agentStartEvent(1, 'Outline'), agentEndEvent(1, 'failed'), runEndEvent('error', 10)]).status,
    'failed',
  )
  const errored = foldEvents([runStartEvent(PLAN), runEndEvent('error', 10, 'boom')])
  assert.equal(errored.error, 'boom')
})

test('run-events: interrupted projection marks unfinished members', () => {
  const state = foldEvents(
    [runStartEvent(PLAN), agentStartEvent(1, 'Outline'), agentStartEvent(2, 'Review', { model: 'deepseek-reasoner' })],
    true,
  )
  assert.equal(state.status, 'interrupted')
  assert.equal(state.nodes.find((node) => node.id === 'outline').status, 'interrupted')
  assert.equal(state.nodes.find((node) => node.id === 'write').status, 'pending')
})

test('run-events: per-model totals group by declared route incl. failed attempts', () => {
  const data = foldEvents([
    runStartEvent(PLAN),
    agentStartEvent(1, 'Outline'),
    agentEndEvent(1, 'completed', { durationMs: 1000, usage: { inputTokens: 100, outputTokens: 40 } }),
    agentStartEvent(2, 'Review', { model: 'deepseek-reasoner' }),
    agentEndEvent(2, 'failed', { durationMs: 500, usage: { inputTokens: 200, outputTokens: 10 } }),
    agentStartEvent(3, 'Review', { model: 'deepseek-reasoner' }),
    agentEndEvent(3, 'completed', { durationMs: 900, usage: { inputTokens: 250, outputTokens: 60, cacheReadTokens: 30 } }),
    agentStartEvent(4, 'Write', { model: 'deepseek-chat' }),
    agentEndEvent(4, 'completed', { durationMs: 800, usage: { inputTokens: 50, outputTokens: 300 } }),
    runEndEvent('completed'),
  ])
  assert.equal(data.models.length, 3)
  const byModel = new Map(data.models.map((route) => [route.model, route]))
  assert.equal(byModel.get(null).calls, 1)
  assert.deepEqual(byModel.get(null).usage, { inputTokens: 100, outputTokens: 40 })
  assert.equal(byModel.get('deepseek-reasoner').calls, 2)
  assert.equal(byModel.get('deepseek-reasoner').durationMs, 1400)
  assert.deepEqual(byModel.get('deepseek-reasoner').usage, {
    inputTokens: 450,
    outputTokens: 70,
    cacheReadTokens: 30,
  })
  assert.deepEqual(byModel.get('deepseek-chat').usage, { inputTokens: 50, outputTokens: 300 })
})

test('run-events: members with a foreign phase surface as their own rows', () => {
  const data = foldEvents([
    runStartEvent(PLAN),
    agentStartEvent(1, '外来阶段', { phase: '外来阶段' }),
    agentEndEvent(1, 'completed'),
  ])
  assert.equal(data.nodes.length, 4)
  assert.equal(data.nodes.find((node) => node.id === '外来阶段').status, 'completed')
})

test('run-events: sumUsage keeps absent buckets absent', () => {
  assert.equal(sumUsage([]), undefined)
  assert.deepEqual(
    sumUsage([
      { inputTokens: 1, outputTokens: 2 },
      { inputTokens: 3, outputTokens: 4, totalTokens: 7 },
    ]),
    { inputTokens: 4, outputTokens: 6, totalTokens: 7 },
  )
  assert.deepEqual(
    sumUsage([
      { inputTokens: 1, outputTokens: 2, cacheReadTokens: 5 },
      { inputTokens: 1, outputTokens: 1 },
    ]),
    { inputTokens: 2, outputTokens: 3, cacheReadTokens: 5 },
  )
})

test('run-events: node duration sums real attempts including failures', () => {
  const data = foldEvents([
    runStartEvent(PLAN),
    agentStartEvent(1, 'Write'),
    agentEndEvent(1, 'failed', { durationMs: 400 }),
    agentStartEvent(2, 'Write'),
    agentEndEvent(2, 'completed', { durationMs: 600 }),
  ])
  const write = data.nodes.find((node) => node.id === 'write')
  assert.equal(write.attempts, 2)
  assert.equal(write.durationMs, 1000)
})

test('run-events: run-end carries stopReason and duration into the projection', () => {
  const data = foldEvents([runStartEvent(PLAN), runEndEvent('cancelled', 1234)])
  assert.equal(data.stopReason, 'cancelled')
  assert.equal(data.durationMs, 1234)
  assert.equal(data.status, 'cancelled')
})

// ===========================================================================
// 6. 器官：主张 × verdict
// ===========================================================================

test('organ: registry declares slug / version / summary / input fields', () => {
  assert.equal(pipelineRunVerb.slug, 'pipeline-run')
  assert.equal(pipelineRunVerb.version, '0.2.2')
  assert.match(pipelineRunVerb.summary, /流水线运行取证/)
  assert.deepEqual([...pipelineRunVerb.input_fields], ['pipeline', 'claims'])
})

test('organ: a valid definition claim is supported (no node -> claim)', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json')),
    claims: [{ claim_id: 'def', check: 'definition', asserted: 'valid' }],
  })
  assert.equal(records.length, 1)
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].id, 'def@-')
  assert.equal(records[0].evidence.computed, 'valid')
})

test('organ: definition invalid + matching error_paths is a claim', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf({ name: 'bad name!', description: '', nodes: [] }),
    claims: [
      {
        claim_id: 'def-bad',
        check: 'definition',
        asserted: 'invalid',
        error_paths: ['name', 'description', 'nodes'],
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.deepEqual(records[0].evidence.error_paths, ['description', 'name', 'nodes'])
})

test('organ: definition invalid with wrong error_paths is refuted by the node', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf({ name: 'bad name!', description: '', nodes: [] }),
    claims: [
      {
        claim_id: 'def-paths',
        check: 'definition',
        asserted: 'invalid',
        error_paths: ['name'],
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /判据推翻主张/)
})

test('organ: definition mismatch without a node downgrades to inconclusive', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json')),
    claims: [{ claim_id: 'def-wrong', check: 'definition', asserted: 'invalid' }],
  })
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.equal(records[0].node, null)
  assert.match(records[0].message, /没有挂痕迹节点/)
})

test('organ: compile claim carries order / total / script hash', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json')),
    claims: [
      {
        claim_id: 'compile',
        check: 'compile',
        asserted: 'compiles',
        order: ['outline', 'review', 'write'],
        total_agent_calls: 3,
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.computed, 'compiles')
  assert.deepEqual(records[0].evidence.order, ['outline', 'review', 'write'])
  assert.equal(records[0].evidence.total_agent_calls, 3)
  assert.match(records[0].evidence.script_sha256, /^[0-9a-f]{64}$/)
})

test('organ: compile order mismatch is refuted', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json')),
    claims: [
      {
        claim_id: 'compile-order',
        check: 'compile',
        asserted: 'compiles',
        order: ['write', 'review', 'outline'],
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /顺序不符/)
})

test('organ: compile total_agent_calls mismatch is refuted', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('retry-skip.json')),
    claims: [
      {
        claim_id: 'compile-calls',
        check: 'compile',
        asserted: 'compiles',
        total_agent_calls: 6,
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /调用上界不符/)
})

test('organ: compile rejection with the expected error code is a claim', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(invalidFixture('ir-dependency-cycle.json')),
    claims: [
      {
        claim_id: 'compile-cycle',
        check: 'compile',
        asserted: 'rejected',
        error_code: 'IR_DEPENDENCY_CYCLE',
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.error_code, 'IR_DEPENDENCY_CYCLE')
})

test('organ: compile rejection with a wrong error code is refuted', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(invalidFixture('ir-dependency-cycle.json')),
    claims: [
      {
        claim_id: 'compile-code',
        check: 'compile',
        asserted: 'rejected',
        error_code: 'IR_SELF_DEPENDENCY',
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /错误码不符/)
})

test('organ: schema-invalid definitions reject at the definition stage', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(invalidFixture('schema-no-nodes.json')),
    claims: [
      {
        claim_id: 'compile-schema',
        check: 'compile',
        asserted: 'rejected',
        error_code: 'SCHEMA_INVALID',
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.stage, 'definition')
})

test('organ: compile of a skill node without blocks is inconclusive (no guessing)', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('skills-and-tools.json')),
    claims: [{ claim_id: 'compile-skills', check: 'compile', asserted: 'compiles', node: NODE }],
  })
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /缺失项/)
  assert.match(records[0].message, /技能渲染块/)
})

test('organ: compile of a skill node with blocks succeeds', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('skills-and-tools.json'), { skills: { draft: [SKILL_BLOCK] } }),
    claims: [
      {
        claim_id: 'compile-skills-ok',
        check: 'compile',
        asserted: 'compiles',
        order: ['draft', 'review'],
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: preflight ok with full capabilities', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      capabilities: { agentOptions: true, outputSchema: true },
    }),
    claims: [{ claim_id: 'preflight', check: 'preflight', asserted: 'ok', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.deepEqual(records[0].evidence.needs_agent_options, ['outline', 'write'])
})

test('organ: preflight reports missing agentOptions and names the nodes', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      capabilities: { agentOptions: false, outputSchema: true },
    }),
    claims: [
      { claim_id: 'preflight-agent', check: 'preflight', asserted: 'missing-agent-options', node: NODE },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.deepEqual(records[0].evidence.needs_agent_options, ['outline', 'write'])
})

test('organ: preflight reports missing outputSchema', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('output-schema.json'), {
      capabilities: { agentOptions: true, outputSchema: false },
    }),
    claims: [
      { claim_id: 'preflight-schema', check: 'preflight', asserted: 'missing-output-schema', node: NODE },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.deepEqual(records[0].evidence.needs_output_schema, ['keywords'])
})

test('organ: pipeline without gated features passes with no capabilities', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      capabilities: { agentOptions: false, outputSchema: false },
    }),
    claims: [{ claim_id: 'preflight-bare', check: 'preflight', asserted: 'ok', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: preflight on an invalid definition is inconclusive', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(invalidFixture('ir-dependency-cycle.json'), {
      capabilities: { agentOptions: true, outputSchema: true },
    }),
    claims: [{ claim_id: 'preflight-bad', check: 'preflight', asserted: 'ok', node: NODE }],
  })
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /缺失项：可编译的定义/)
})

test('organ: run completed is supported by the folded record', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      run: {
        events: [
          runStartEvent(PLAN),
          agentStartEvent(1, 'Outline', { provider: 'deepseek', model: 'deepseek-chat' }),
          agentEndEvent(1, 'completed'),
          agentStartEvent(2, 'Review', { provider: 'deepseek', model: 'deepseek-reasoner' }),
          agentEndEvent(2, 'completed'),
          agentStartEvent(3, 'Write', { provider: 'deepseek', model: 'deepseek-reasoner' }),
          agentEndEvent(3, 'completed'),
          runEndEvent('completed'),
        ],
      },
    }),
    claims: [{ claim_id: 'run', check: 'run', asserted: 'completed', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.nodes.length, 3)
  assert.equal(records[0].evidence.models.length, 2)
})

test('organ: run error maps to failed', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }]), runEndEvent('error', 10, 'boom')] },
    }),
    claims: [{ claim_id: 'run-fail', check: 'run', asserted: 'failed', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.error, 'boom')
})

test('organ: run cancelled is supported', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }]), runEndEvent('cancelled')] },
    }),
    claims: [{ claim_id: 'run-cancel', check: 'run', asserted: 'cancelled', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: interrupted run is supported when the location closed', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      run: {
        interrupted: true,
        events: [runStartEvent([{ id: 'echo', label: 'Echo' }]), agentStartEvent(1, 'Echo')],
      },
    }),
    claims: [{ claim_id: 'run-interrupted', check: 'run', asserted: 'interrupted', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: a live run without run-end is running', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }]), agentStartEvent(1, 'Echo')] },
    }),
    claims: [{ claim_id: 'run-live', check: 'run', asserted: 'running', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: node status + attempts are checked at node level', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      run: {
        events: [
          runStartEvent(PLAN),
          agentStartEvent(1, 'Write'),
          agentEndEvent(1, 'completed', { durationMs: 900, usage: { inputTokens: 10, outputTokens: 20 } }),
          runEndEvent('completed'),
        ],
      },
    }),
    claims: [
      { claim_id: 'node-write', check: 'node', node_id: 'write', asserted: 'completed', attempts: 1, node: NODE },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.attempts, 1)
  assert.equal(records[0].evidence.duration_ms, 900)
  assert.deepEqual(records[0].evidence.usage, { inputTokens: 10, outputTokens: 20 })
})

test('organ: node retry recovery reports the last member and 2 attempts', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      run: {
        events: [
          runStartEvent(PLAN),
          agentStartEvent(1, 'Write'),
          agentEndEvent(1, 'failed', { durationMs: 100 }),
          agentStartEvent(2, 'Write'),
          agentEndEvent(2, 'completed', { durationMs: 200 }),
          runEndEvent('completed'),
        ],
      },
    }),
    claims: [
      { claim_id: 'node-retry', check: 'node', node_id: 'write', asserted: 'completed', attempts: 2, node: NODE },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: node failed last attempt is reported failed', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      run: {
        events: [
          runStartEvent(PLAN),
          agentStartEvent(1, 'Write'),
          agentEndEvent(1, 'completed'),
          agentStartEvent(2, 'Write'),
          agentEndEvent(2, 'failed'),
          runEndEvent('error', 10, 'last attempt failed'),
        ],
      },
    }),
    claims: [{ claim_id: 'node-failed', check: 'node', node_id: 'write', asserted: 'failed', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: an absent node claim is supported as absent', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }]), runEndEvent('completed')] },
    }),
    claims: [{ claim_id: 'node-absent', check: 'node', node_id: 'ghost', asserted: 'absent', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.attempts, 0)
})

test('organ: node attempts mismatch is refuted', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      run: {
        events: [
          runStartEvent(PLAN),
          agentStartEvent(1, 'Write'),
          agentEndEvent(1, 'completed'),
          runEndEvent('completed'),
        ],
      },
    }),
    claims: [
      { claim_id: 'node-attempts', check: 'node', node_id: 'write', asserted: 'completed', attempts: 2, node: NODE },
    ],
  })
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /尝试次数不符/)
})

test('organ: form roundtrip claim is supported for every fixture', () => {
  for (const name of PIPELINE_NAMES) {
    const records = evaluateSubject({
      pipeline: pipelineOf(fixture(name)),
      claims: [{ claim_id: `form-${name}`, check: 'form', asserted: 'roundtrip', node: NODE }],
    })
    assert.equal(records[0].verdict, CLAIM, name)
    assert.match(records[0].evidence.canonical_sha256, /^[0-9a-f]{64}$/)
  }
})

test('organ: form lossy claim on an invalid definition is supported', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf({ name: 'x' }),
    claims: [{ claim_id: 'form-lossy', check: 'form', asserted: 'lossy', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.computed, 'lossy')
})

test('organ: duplicate claim ids are a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json')),
        claims: [
          { claim_id: 'same', check: 'definition', asserted: 'valid' },
          { claim_id: 'same', check: 'definition', asserted: 'valid' },
        ],
      }),
    ContractError,
  )
})

test('organ: unknown claim fields are a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json')),
        claims: [{ claim_id: 'x', check: 'definition', asserted: 'valid', surprise: 1 }],
      }),
    ContractError,
  )
})

test('organ: unknown check names are a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json')),
        claims: [{ claim_id: 'x', check: 'deploy', asserted: 'valid' }],
      }),
    (error) => error instanceof ContractError && /check 非法/.test(error.message),
  )
})

test('organ: compile without pipeline.definition is a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: {},
        claims: [{ claim_id: 'x', check: 'compile', asserted: 'compiles' }],
      }),
    (error) => error instanceof ContractError && /pipeline\.definition/.test(error.message),
  )
})

test('organ: run claim without pipeline.run is a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: {},
        claims: [{ claim_id: 'x', check: 'run', asserted: 'completed' }],
      }),
    (error) => error instanceof ContractError && /pipeline\.run/.test(error.message),
  )
})

test('organ: preflight without capabilities is a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json')),
        claims: [{ claim_id: 'x', check: 'preflight', asserted: 'ok' }],
      }),
    (error) => error instanceof ContractError && /pipeline\.capabilities/.test(error.message),
  )
})

test('organ: a missing trace node bubbles as NodeMissing', () => {
  assert.throws(
    () =>
      evaluateSubject(
        {
          pipeline: pipelineOf(fixture('single-node.json')),
          claims: [{ claim_id: 'x', check: 'definition', asserted: 'valid', node: NODE }],
        },
        [],
      ),
    NodeMissing,
  )
})

test('organ: an incomplete trace node degrades even a matching claim', () => {
  const incomplete = { session_id: 's-pipe-1', turn: null, tool_call_id: 'call-incomplete' }
  const records = evaluateSubject(
    {
      pipeline: pipelineOf(fixture('single-node.json')),
      claims: [{
        claim_id: 'incomplete',
        check: 'definition',
        asserted: 'valid',
        node: { session_id: 's-pipe-1', turn: null, tool_call_id: 'call-incomplete' },
      }],
    },
    [incomplete],
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /痕迹节点不完整/)
})

test('organ: evaluation is deterministic byte-for-byte', () => {
  const subject = {
    pipeline: pipelineOf(fixture('three-node-two-models.json'), {
      run: { events: [runStartEvent(PLAN), agentStartEvent(1, 'Outline'), agentEndEvent(1, 'completed'), runEndEvent('completed')] },
    }),
    claims: [
      { claim_id: 'z', check: 'run', asserted: 'completed', node: NODE },
      { claim_id: 'a', check: 'compile', asserted: 'compiles', node: NODE },
    ],
  }
  const first = JSON.stringify(evaluateSubject(subject).map(recordToJSON))
  const second = JSON.stringify(evaluateSubject(subject).map(recordToJSON))
  assert.equal(first, second)
})

test('organ: a Report sorts records by claim_id', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json')),
    claims: [
      { claim_id: 'z', check: 'definition', asserted: 'valid' },
      { claim_id: 'a', check: 'form', asserted: 'roundtrip' },
    ],
  })
  const report = new Report({
    product: 'traceproof',
    verb: 'pipeline-run',
    verb_version: '0.2.2',
    subject: 'inline.json',
    records,
  })
  assert.deepEqual(report.records.map((record) => record.claim_id), ['a', 'z'])
})

test('organ: a matching claim does not require a node', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json')),
    claims: [{ claim_id: 'match-no-node', check: 'form', asserted: 'roundtrip' }],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].node, null)
})

test('organ: compile evidence carries the claimed error code when rejected', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(invalidFixture('ir-skip-reference.json')),
    claims: [
      {
        claim_id: 'skip-ref',
        check: 'compile',
        asserted: 'rejected',
        error_code: 'IR_SKIP_REFERENCE',
        node: NODE,
      },
    ],
  })
  assert.equal(records[0].verdict, CLAIM)
  assert.equal(records[0].evidence.error_code, 'IR_SKIP_REFERENCE')
  assert.equal(records[0].evidence.stage, 'ir')
})

test('organ: unknown run-event types are ignored by the fold', () => {
  const records = evaluateSubject({
    pipeline: pipelineOf(fixture('single-node.json'), {
      run: {
        events: [
          runStartEvent([{ id: 'echo', label: 'Echo' }]),
          { type: 'other/event', data: { anything: true } },
          runEndEvent('completed'),
        ],
      },
    }),
    claims: [{ claim_id: 'unknown-event', check: 'run', asserted: 'completed', node: NODE }],
  })
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: run.events must start with run-start', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json'), {
          run: { events: [agentStartEvent(1, 'Echo')] },
        }),
        claims: [{ claim_id: 'x', check: 'run', asserted: 'running' }],
      }),
    (error) => error instanceof ContractError && /run-start/.test(error.message),
  )
})

test('organ: invalid usage fields are a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json'), {
          run: {
            events: [
              runStartEvent([{ id: 'echo', label: 'Echo' }]),
              agentStartEvent(1, 'Echo'),
              agentEndEvent(1, 'completed', { usage: { inputTokens: 'x', outputTokens: 1 } }),
            ],
          },
        }),
        claims: [{ claim_id: 'x', check: 'run', asserted: 'running' }],
      }),
    ContractError,
  )
})

test('organ: error_paths on a valid assertion is a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json')),
        claims: [{ claim_id: 'x', check: 'definition', asserted: 'valid', error_paths: ['name'] }],
      }),
    ContractError,
  )
})

test('organ: attempts on an absent node is a contract error', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json'), {
          run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }])] },
        }),
        claims: [{ claim_id: 'x', check: 'node', node_id: 'ghost', asserted: 'absent', attempts: 1 }],
      }),
    ContractError,
  )
})

test('organ: node claim requires node_id', () => {
  assert.throws(
    () =>
      evaluateSubject({
        pipeline: pipelineOf(fixture('single-node.json'), {
          run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }])] },
        }),
        claims: [{ claim_id: 'x', check: 'node', asserted: 'pending' }],
      }),
    (error) => error instanceof ContractError && /node_id/.test(error.message),
  )
})

// ===========================================================================
// 7. 唯入口 / CLI
// ===========================================================================

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

test('cli: list shows pipeline-run with its version', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /pipeline-run\s+0\.2\.2/)
})

test('cli: sample subject exits 0 with 6 claim records', async () => {
  const subject = join(PRODUCT_ROOT, 'samples', 'pipeline-run.json')
  const basis = join(PRODUCT_ROOT, 'samples', 'pipeline-run-traces.json')
  const { code, out } = await capture(() =>
    main(['check', 'pipeline-run', '--input', subject, '--basis', basis]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /合计 6 条，阻断 0 条/)
})

test('cli: --json output is byte-identical across two runs', async () => {
  const subject = join(PRODUCT_ROOT, 'samples', 'pipeline-run.json')
  const basis = join(PRODUCT_ROOT, 'samples', 'pipeline-run-traces.json')
  const first = await capture(() =>
    main(['check', 'pipeline-run', '--input', subject, '--basis', basis, '--json']),
  )
  const second = await capture(() =>
    main(['check', 'pipeline-run', '--input', subject, '--basis', basis, '--json']),
  )
  assert.equal(first.code, EXIT_OK)
  assert.equal(first.out, second.out)
  const parsed = JSON.parse(first.out)
  assert.equal(parsed.verb, 'pipeline-run')
  assert.equal(parsed.summary.blocking, 0)
})

test('cli: a refuted claim exits 1', async () => {
  const def = fixture('single-node.json')
  const subject = {
    pipeline: {
      definition: def,
      run: { events: [runStartEvent([{ id: 'echo', label: 'Echo' }]), runEndEvent('completed')] },
    },
    claims: [{ claim_id: 'wrong-node', check: 'node', node_id: 'echo', asserted: 'failed', node: NODE }],
  }
  const files = tempFiles(subject)
  const { code, out } = await capture(() =>
    main(['check', 'pipeline-run', '--input', files.subjectPath, '--basis', files.basisPath]),
  )
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /\[refuted\] wrong-node/)
})

test('cli: missing required subject field exits 2', async () => {
  const files = tempFiles({ pipeline: {} })
  const { code, err } = await capture(() =>
    main(['check', 'pipeline-run', '--input', files.subjectPath]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /缺少必填字段：claims/)
})

test('cli: missing trace node exits 3', async () => {
  const subject = {
    pipeline: pipelineOf(fixture('single-node.json')),
    claims: [{ claim_id: 'x', check: 'definition', asserted: 'valid', node: NODE }],
  }
  const dir = mkdtempSync(join(tmpdir(), 'pipeline-run-test-'))
  const subjectPath = join(dir, 'subject.json')
  const basisPath = join(dir, 'basis.json')
  writeFileSync(subjectPath, JSON.stringify(subject))
  writeFileSync(basisPath, JSON.stringify({ version: '2026.11.25', nodes: [] }))
  const { code, err } = await capture(() =>
    main(['check', 'pipeline-run', '--input', subjectPath, '--basis', basisPath]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: malformed pipeline block exits 3 (contract violation)', async () => {
  const subject = { pipeline: 'not-an-object', claims: [{ claim_id: 'x', check: 'definition', asserted: 'valid' }] }
  const files = tempFiles(subject)
  const { code, err } = await capture(() =>
    main(['check', 'pipeline-run', '--input', files.subjectPath]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /pipeline 必须是对象/)
})

test('organ: makeNode / Basis round-trip keeps node coordinates', () => {
  const node = makeNode({ session_id: 's-pipe-1', turn: 2, tool_call_id: 'call-pipe-2', quote: 'q' })
  assert.equal(node.complete, true)
  const resolved = basisOf().ref('s-pipe-1', 2, 'call-pipe-2')
  assert.equal(resolved.session_id, 's-pipe-1')
  assert.equal(resolved.turn, 2)
  assert.equal(resolved.tool_call_id, 'call-pipe-2')
})