/**
 * 入口面防回退门（轨AD · 2026-11-25）。
 *
 * 锁一件事：`package.json` 的 `bin` 只允许**一个**入口，且必须是产品入口 `traceproof`。
 *
 * 与三个 Python 产品的差异（不是漏做，是事实）：
 * traceproof 的旧入口是**旧 dsh 插件**，从来不是 CLI 入口——`[project.scripts]` 等价物不存在，
 * 因此没有「过渡期双入口」可退。本仓的门是**防新增**：任何人再往 `bin` 里加第二个命令即红。
 *
 * 发行名 `dsh-prompt-polisher` **已发布 npm（2026-11-25 实测 registry HTTP 200）**，
 * 按 §三 D 的「已发布」分支**保留旧名**，只改 CLI / 仓库名；理由与迁移策略见
 * `records/old-entry-retirement-20261125.md` 与 `records/criterion-verdicts-20261125.md`。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const PRODUCT_ENTRY = 'traceproof'

/** 从一个 package.json 对象里取 bin 的键名，保持声明顺序。 */
function binKeys(pkg) {
  const bin = pkg.bin
  if (bin === undefined) return []
  if (typeof bin === 'string') return [pkg.name]
  return Object.keys(bin)
}

/** 返回违规说明数组；空 = 通过。 */
function checkBin(pkg) {
  const keys = binKeys(pkg)
  const problems = []
  if (keys.length === 0) {
    problems.push(`bin 为空：产品必须有一个可执行入口 ${PRODUCT_ENTRY}`)
  } else if (keys.length > 1) {
    problems.push(`bin 有 ${keys.length} 个入口 ${JSON.stringify(keys)} > 上限 1`)
  } else if (keys[0] !== PRODUCT_ENTRY) {
    problems.push(`bin 的入口是 ${JSON.stringify(keys[0])}，不是 ${PRODUCT_ENTRY}`)
  }
  return problems
}

// ------------------------------------------------------------ 实况断言

test('live package.json passes entry gate', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  assert.deepEqual(checkBin(pkg), [])
})

test('live bin points at ./bin/traceproof', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
  assert.equal(pkg.bin[PRODUCT_ENTRY], './bin/traceproof')
})

// ------------------------------------------------------------ 门的负控

test('negative control: three bins is red', () => {
  const pkg = { name: 'synth', bin: { a: './a', b: './b', traceproof: './bin/traceproof' } }
  assert.notDeepEqual(checkBin(pkg), [])
})

test('negative control: one product bin is green', () => {
  const pkg = { name: 'synth', bin: { traceproof: './bin/traceproof' } }
  assert.deepEqual(checkBin(pkg), [])
})

test('negative control: zero bins is red', () => {
  assert.notDeepEqual(checkBin({ name: 'synth' }), [])
})

test('negative control: renamed single bin is red', () => {
  const pkg = { name: 'synth', bin: { 'dsh-prompt-polisher': './bin/traceproof' } }
  assert.notDeepEqual(checkBin(pkg), [])
})