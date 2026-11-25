/**
 * traceproof 内核契约测试（Stage 1 · 骨架）。
 *
 * 锁四件事：
 *  1. 无痕迹节点不下 `refuted`（构造即拦，不靠文档）；
 *  2. 节点不完整 -> 降级 `inconclusive` 并写明缺失项；
 *  3. **脱敏前置**：证据在入账那一刻就脱敏（不存在「先入库再打码」）；
 *  4. 账本确定性 + 退出码 0/1/2/3 的边界（含「痕迹包缺节点 -> 3」）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

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
  makeRecord,
} from '../lib/traceproof/core/ledger.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { VerbMissing, allVerbs, get, register } from '../lib/traceproof/core/registry.js'
import { MASK, redactDeep } from '../lib/traceproof/core/redact.js'
import { BUILTIN_MODULES } from '../lib/traceproof/verbs/index.js'

//: 测试用占位串：只在运行时拼出来，源码里不出现任何形似凭据的字面量。
const SAMPLE = ['placeholder', 'value', 'not', 'a', 'secret'].join('-')

const NODE = makeNode({
  session_id: 's-1',
  turn: 3,
  tool_call_id: 'call-7',
  quote: '示例痕迹原文',
})

// ---------------------------------------------------------------- 注册表
test('registry: register / get / allVerbs 按 slug 排序', () => {
  const verb = {
    slug: 'probe-alpha',
    version: '0.0.1',
    summary: '测试用器官',
    input_fields: ['claim'],
    evaluate: () => [],
  }
  assert.equal(register(verb), verb)
  assert.equal(get('probe-alpha'), verb)
  const slugs = allVerbs().map((v) => v.slug)
  assert.deepEqual(slugs, [...slugs].sort())
  assert.ok(slugs.includes('probe-alpha'))
})

test('registry: 重复注册 / 非法 slug / 空字段都被拒', () => {
  const base = {
    slug: 'probe-dup',
    version: '1',
    summary: 'x',
    input_fields: ['a'],
    evaluate: () => [],
  }
  register(base)
  assert.throws(() => register({ ...base, version: '2' }), /重复注册/)
  assert.throws(() => register({ ...base, slug: 'Bad Slug' }), /slug 非法/)
  assert.throws(() => register({ ...base, slug: 'probe-b', input_fields: [] }), /未声明输入字段/)
  assert.throws(() => register({ ...base, slug: 'probe-c', version: '' }), /version/)
})

test('registry: 未注册器官抛 VerbMissing', () => {
  assert.throws(() => get('no-such-verb'), VerbMissing)
})

test('registry: 内置器官清单是字典序且空表可加载', async () => {
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
  const { code } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
})

// ---------------------------------------------------------------- 账本
test('ledger: 无节点的 refuted 是契约违约', () => {
  assert.throws(
    () => makeRecord({ claim_id: 'c1', verdict: REFUTED, message: '没用这个工具' }),
    ContractError,
  )
})

test('ledger: 无节点的 claim / inconclusive 允许（只记录不阻断）', () => {
  assert.equal(makeRecord({ claim_id: 'c1', verdict: CLAIM, message: 'x' }).verdict, CLAIM)
  assert.equal(
    makeRecord({ claim_id: 'c2', verdict: INCONCLUSIVE, message: 'x' }).verdict,
    INCONCLUSIVE,
  )
})

test('ledger: 非法结论被拒', () => {
  assert.throws(
    () => makeRecord({ claim_id: 'c1', verdict: 'maybe', message: 'x', node: NODE }),
    ContractError,
  )
})

test('ledger: 节点不完整 -> 降级 inconclusive 且写明缺失项', () => {
  const noTurn = makeRecord({
    claim_id: 'c1',
    verdict: REFUTED,
    message: 'x',
    node: makeNode({ session_id: 's-1', tool_call_id: 'call-1' }),
  })
  assert.equal(noTurn.verdict, INCONCLUSIVE)
  assert.match(noTurn.message, /turn/)
  assert.match(noTurn.message, /降级/)

  const noCall = makeRecord({
    claim_id: 'c2',
    verdict: REFUTED,
    message: 'x',
    node: makeNode({ session_id: 's-1', turn: 1 }),
  })
  assert.equal(noCall.verdict, INCONCLUSIVE)
  assert.match(noCall.message, /tool_call_id/)
})

test('ledger: id 由主张 + 节点派生（稳定）', () => {
  const first = makeRecord({ claim_id: 'c1', verdict: REFUTED, message: 'a', node: NODE })
  const second = makeRecord({ claim_id: 'c1', verdict: CLAIM, message: 'b', node: NODE })
  assert.equal(first.id, second.id)
  assert.equal(first.id, 'c1@s-1#3#call-7')
  assert.equal(makeRecord({ claim_id: 'c9', verdict: CLAIM, message: 'x' }).id, 'c9@-')
})

test('ledger: Report 排序确定、两次序列化字节一致', () => {
  const zeta = makeRecord({ claim_id: 'zeta', verdict: CLAIM, message: 'z', node: NODE })
  const alpha = makeRecord({ claim_id: 'alpha', verdict: REFUTED, message: 'a', node: NODE })
  const report = new Report({
    product: 'traceproof',
    verb: 'v',
    verb_version: '1',
    subject: 's',
    records: [zeta, alpha],
  })
  assert.deepEqual(
    report.records.map((r) => r.claim_id),
    ['alpha', 'zeta'],
  )
  assert.equal(JSON.stringify(report.toJSON()), JSON.stringify(report.toJSON()))
  assert.deepEqual(Object.keys(report.toJSON()), [
    'product',
    'verb',
    'verb_version',
    'subject',
    'summary',
    'records',
  ])
})

test('ledger: 退出码与汇总', () => {
  const blocking = new Report({
    product: 'traceproof',
    verb: 'v',
    verb_version: '1',
    subject: 's',
    records: [makeRecord({ claim_id: 'c', verdict: REFUTED, message: 'x', node: NODE })],
  })
  assert.equal(blocking.exitCode(), EXIT_BLOCKED)
  assert.equal(blocking.summary().blocking, 1)

  const clean = new Report({
    product: 'traceproof',
    verb: 'v',
    verb_version: '1',
    subject: 's',
    records: [makeRecord({ claim_id: 'c', verdict: CLAIM, message: 'x', node: NODE })],
  })
  assert.equal(clean.exitCode(), EXIT_OK)
  assert.deepEqual(clean.summary().verdicts, { claim: 1, refuted: 0, inconclusive: 0 })
})

test('ledger: 重复 id 被拒', () => {
  const record = makeRecord({ claim_id: 'c', verdict: CLAIM, message: 'x', node: NODE })
  assert.throws(
    () =>
      new Report({
        product: 'p',
        verb: 'v',
        verb_version: '1',
        subject: 's',
        records: [record, record],
      }),
    /id 冲突/,
  )
})

// ---------------------------------------------------------------- 脱敏前置
test('redact: 敏感键被整体替换，嵌套结构逐层脱敏', () => {
  const input = {
    ok: 1,
    apiKey: SAMPLE,
    nested: { authorization: SAMPLE, tool_call_id: 'call-1' },
    list: [{ password: SAMPLE }, { api_key: SAMPLE }],
  }
  const out = redactDeep(input)
  assert.deepEqual(out, {
    ok: 1,
    apiKey: MASK,
    nested: { authorization: MASK, tool_call_id: 'call-1' },
    list: [{ password: MASK }, { api_key: MASK }],
  })
  assert.equal(input.apiKey, SAMPLE, '不得改动调用方的对象')
})

test('redact: 证据在入账那一刻已脱敏（不是先入库再打码）', () => {
  const record = makeRecord({
    claim_id: 'c',
    verdict: REFUTED,
    message: 'x',
    node: NODE,
    evidence: { api_key: SAMPLE, detail: { token: SAMPLE } },
  })
  assert.equal(record.evidence.api_key, MASK)
  assert.deepEqual(record.evidence.detail, { token: MASK })
  assert.ok(!JSON.stringify(record).includes(SAMPLE))
})

// ---------------------------------------------------------------- 痕迹索引
test('basis: fromObject + ref 回报节点', () => {
  const basis = Basis.fromObject({
    version: '2026.1',
    nodes: [{ session_id: 's-1', turn: 3, tool_call_id: 'call-7', quote: 'q' }],
  })
  assert.equal(basis.size, 1)
  const node = basis.ref('s-1', 3, 'call-7')
  assert.equal(node.quote, 'q')
  assert.equal(node.complete, true)
})

test('basis: 缺节点抛 NodeMissing', () => {
  const basis = Basis.empty('2026.1')
  assert.throws(() => basis.ref('s-1', 1, 'call-1'), NodeMissing)
})

test('basis: 缺版本 / 节点重复被拒', () => {
  assert.throws(() => new Basis(''), ContractError)
  assert.throws(
    () =>
      new Basis('2026.1', [
        makeNode({ session_id: 's', turn: 1, tool_call_id: 'c' }),
        makeNode({ session_id: 's', turn: 1, tool_call_id: 'c' }),
      ]),
    /重复/,
  )
})

// ---------------------------------------------------------------- CLI
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

function tmpDir() {
  return mkdtempSync(join(tmpdir(), 'traceproof-test-'))
}

const PROBE = {
  slug: 'demo-probe',
  version: '0.0.1',
  summary: '契约测试用器官（非真实取证）',
  input_fields: ['claim'],
  evaluate(subject, basis) {
    if (subject.use_node !== true) {
      return [makeRecord({ claim_id: 'c', verdict: CLAIM, message: '未使用可核痕迹', node: null })]
    }
    return [
      makeRecord({
        claim_id: 'c',
        verdict: REFUTED,
        message: '主张与痕迹不符',
        node: basis.ref('s-1', 3, 'call-7'),
        evidence: { api_key: SAMPLE },
      }),
    ]
  },
}

const STRICT = {
  slug: 'demo-strict',
  version: '0.0.1',
  summary: '硬依赖痕迹包的器官',
  input_fields: ['claim'],
  evaluate(_subject, basis) {
    return [
      makeRecord({ claim_id: 'c', verdict: CLAIM, message: 'x', node: basis.ref('s-1', 3, 'call-7') }),
    ]
  },
}

register(PROBE)
register(STRICT)

test('cli: --version 退出 0', async () => {
  const { code, out } = await capture(() => main(['--version']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /traceproof/)
})

test('cli: list 与 list --json', async () => {
  const plain = await capture(() => main(['list']))
  assert.equal(plain.code, EXIT_OK)
  assert.match(plain.out, /demo-probe/)

  const json = await capture(() => main(['list', '--json']))
  assert.equal(json.code, EXIT_OK)
  assert.ok(Array.isArray(JSON.parse(json.out)))
})

test('cli: 未知器官 -> 3', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ claim: 'x' }))
  const { code, err } = await capture(() =>
    main(['check', 'no-such', '--input', join(dir, 'in.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /VerbMissing/)
})

test('cli: 输入文件缺失 -> 2', async () => {
  const dir = tmpDir()
  const { code } = await capture(() =>
    main(['check', 'demo-probe', '--input', join(dir, 'nope.json')]),
  )
  assert.equal(code, EXIT_INPUT)
})

test('cli: 缺必填字段 -> 2', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ other: 1 }))
  const { code, err } = await capture(() =>
    main(['check', 'demo-probe', '--input', join(dir, 'in.json')]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /claim/)
})

test('cli: 痕迹包缺节点 -> 3', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ claim: 'x' }))
  writeFileSync(join(dir, 'basis.json'), JSON.stringify({ version: '2026.1', nodes: [] }))
  const { code, err } = await capture(() =>
    main([
      'check',
      'demo-strict',
      '--input',
      join(dir, 'in.json'),
      '--basis',
      join(dir, 'basis.json'),
    ]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: 痕迹包缺版本 -> 3', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ claim: 'x' }))
  writeFileSync(join(dir, 'basis.json'), JSON.stringify({ nodes: [] }))
  const { code, err } = await capture(() =>
    main([
      'check',
      'demo-probe',
      '--input',
      join(dir, 'in.json'),
      '--basis',
      join(dir, 'basis.json'),
    ]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /版本为空/)
})

test('cli: 端到端 refuted + 确定性 + 无绝对路径 + 已脱敏', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ claim: 'x', use_node: true }))
  writeFileSync(
    join(dir, 'basis.json'),
    JSON.stringify({
      version: '2026.1',
      nodes: [{ session_id: 's-1', turn: 3, tool_call_id: 'call-7' }],
    }),
  )
  const args = [
    'check',
    'demo-probe',
    '--input',
    join(dir, 'in.json'),
    '--basis',
    join(dir, 'basis.json'),
    '--json',
  ]

  const first = await capture(() => main(args))
  assert.equal(first.code, EXIT_BLOCKED)
  assert.ok(!first.out.includes(dir), '输出不得含绝对路径')
  const payload = JSON.parse(first.out)
  assert.equal(payload.summary.blocking, 1)
  assert.equal(payload.records[0].basis_ref.session_id, 's-1')
  assert.equal(payload.records[0].basis_ref.tool_call_id, 'call-7')
  assert.equal(payload.records[0].evidence.api_key, MASK)
  assert.ok(!first.out.includes(SAMPLE))

  const second = await capture(() => main(args))
  assert.equal(second.out, first.out, '同一输入两次运行必须字节一致')
})