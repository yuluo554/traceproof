/**
 * email-evidence 器官的无损测试（§7.3）。
 *
 * 四层覆盖：
 *  1. **RFC 7208 上游测试集 203 条**（openspf.org 2014.04）——逐条作为独立用例，
 *     走与生产同一条 `spfEvaluate` 路径（快照 → 求值），不是"测试专用捷径"；
 *  2. **17 个上游 fixture**（DKIM 11 + DMARC 6）：每个 `expected.json` 的每个键
 *     各一条用例（一个键失败能直接指出是哪条判据）；
 *  3. **引擎单元**：规范化 / 宏 / 预算 / tree walk / PSL / 对账 / 快照 schema；
 *  4. **器官与内核契约**：verdict 映射、NodeMissing、节点不完整降级、脱敏前置、
 *     确定性、退出码 0/1/2/3。
 *
 * 上游数据只读拷贝（`test/fixtures/email-evidence/upstream/`），许可与来源见各 README。
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
  makeNode,
  makeRecord,
} from '../lib/traceproof/core/ledger.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { loadBuiltin } from '../lib/traceproof/verbs/index.js'
import { Snapshot } from '../lib/traceproof/verbs/email-evidence/snapshot.js'
import { Budget, checkHost, spfEvaluate } from '../lib/traceproof/verbs/email-evidence/spf.js'
import {
  TagError,
  bodyCrlf,
  canonicalizeBody,
  canonicalizeHeader,
  dkimSummary,
  parseMessage,
  parseTagList,
  verifyMessage,
} from '../lib/traceproof/verbs/email-evidence/dkim.js'
import {
  align,
  dmarcEvaluate,
  fromDomains,
  parseRecord,
  selectOrganizationalDomain,
  shortenDomain,
  walk,
} from '../lib/traceproof/verbs/email-evidence/dmarc.js'
import {
  organizationalDomain,
  pslAnalysis,
  pslDate,
  pslRuleCount,
  pslVersion,
} from '../lib/traceproof/verbs/email-evidence/psl.js'
import {
  parseAuthenticationResults,
  reconcileEvaluate,
} from '../lib/traceproof/verbs/email-evidence/reconcile.js'
import {
  cidrMatch,
  ipv6DottedNibbles,
  ipv6ToString,
  parseIp,
  reverseLookupName,
  unmapIp,
} from '../lib/traceproof/verbs/email-evidence/ip.js'

await loadBuiltin()

const FIXTURES = fileURLToPath(new URL('./fixtures/email-evidence/', import.meta.url))
const UPSTREAM = join(FIXTURES, 'upstream')
const SUITE = JSON.parse(readFileSync(join(FIXTURES, 'rfc7208-suite.json'), 'utf8'))

//: 运行时拼出来的占位串：源码里不出现任何形似凭据的字面量。
const SAMPLE = ['placeholder', 'value', 'not', 'a', 'secret'].join('-')

// ── 小工具 ──────────────────────────────────────────────────────────────

function dns(qname, qtype, answer = [], rcode = 'NOERROR', ttl = 300) {
  return { qname, qtype, rcode, answer, ttl }
}

function snapshotOf(...entries) {
  return Snapshot.fromObject({
    schema_version: 1,
    fetched_at: '2026-11-25T00:00:00Z',
    resolver: 'synthetic',
    psl_version: '2026-10-20_08-40-56_UTC',
    psl_date: '2026-10-20',
    queries: entries,
  })
}

function zoneSnapshot(zone) {
  const entries = []
  for (const [name, records] of Object.entries(zone)) {
    for (const [type, answers] of Object.entries(records)) {
      entries.push(dns(name, type, answers))
    }
  }
  return snapshotOf(...entries)
}

function basisOf(nodes = [{ session_id: 's-1', turn: 3, tool_call_id: 'call-7', quote: 'trace' }]) {
  return Basis.fromObject({ version: '2026.11.25', nodes })
}

function runOrgan(subject, basis = basisOf()) {
  return [...get('email-evidence').evaluate(subject, basis)]
}

// ── RFC 7208 上游测试集驱动（与旧仓 `rfc7208_suite.py` 同语义） ──────────

const TIMEOUT = 'TIMEOUT'
const NONE = 'NONE'

function asText(value) {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(String).join('')
  return String(value)
}

function formatMx(value) {
  if (Array.isArray(value) && value.length === 2) return `${Number(value[0])} ${String(value[1])}`
  return String(value)
}

class StubResolver {
  constructor(zonedata) {
    this.zone = new Map()
    for (const [name, records] of Object.entries(zonedata ?? {})) {
      this.zone.set(name.toLowerCase().replace(/\.+$/, ''), records)
    }
  }

  respond(qname, qtype, level = 0) {
    const name = qname.toLowerCase().replace(/\.+$/, '')
    const type = qtype.toUpperCase()
    const records = this.zone.get(name)
    if (records === undefined) {
      if (name.startsWith('error.')) return { rcode: TIMEOUT, answer: [] }
      return { rcode: 'NXDOMAIN', answer: [] }
    }
    const { answers, timedOut } = this.collect(records, type, level)
    if (timedOut) return { rcode: TIMEOUT, answer: [] }
    return { rcode: 'NOERROR', answer: answers }
  }

  collect(records, qtype, level) {
    const answers = []
    let timeout = true
    const spawnTxt = !records.some(
      (record) => record !== null && typeof record === 'object' && 'TXT' in record,
    )
    for (const record of records) {
      if (record === TIMEOUT) {
        if (timeout) return { answers: [], timedOut: true }
        continue
      }
      if (record === null || typeof record !== 'object') continue
      for (const [rtype, value] of Object.entries(record)) {
        if (value === NONE) continue
        if (value === TIMEOUT) {
          if (rtype === qtype && timeout) return { answers: [], timedOut: true }
          continue
        }
        if (rtype === 'SPF' && spawnTxt && qtype === 'TXT') {
          answers.push(asText(value))
          timeout = false
          continue
        }
        if (rtype === 'CNAME') {
          if (level === 0) {
            const nested = this.respond(asText(value), qtype, 1)
            if (nested.rcode === 'NOERROR') {
              answers.push(...nested.answer)
              if (nested.answer.length > 0) timeout = false
            } else if (nested.rcode === TIMEOUT && timeout) {
              return { answers: [], timedOut: true }
            }
          }
          continue
        }
        if (rtype !== qtype) continue
        timeout = false
        if (rtype === 'MX') {
          answers.push(formatMx(value))
          continue
        }
        answers.push(asText(value))
      }
    }
    return { answers, timedOut: false }
  }
}

function reverseName(host) {
  const text = String(host).trim()
  if (!text.includes(':') && text.split('.').length === 4) {
    return `${text.split('.').reverse().join('.')}.in-addr.arpa`
  }
  const halves = text.split('::')
  const toGroups = (parts) =>
    parts.flatMap((part) => {
      if (part.includes('.')) {
        const [a, b, c, d] = part.split('.').map(Number)
        return [(a << 8) | b, (c << 8) | d]
      }
      return [parseInt(part, 16)]
    })
  const head = halves[0] ? toGroups(halves[0].split(':')) : []
  const tail = halves.length === 2 && halves[1] ? toGroups(halves[1].split(':')) : []
  const groups = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail]
  const nibbles = groups
    .flatMap((group) => [group >> 8, group & 0xff])
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.')
  return `${nibbles}.ip6.arpa`
}

function referencedTarget(token) {
  const lowered = token.toLowerCase()
  for (const prefix of ['include:', 'exists:', 'ptr:', 'a:', 'mx:']) {
    if (lowered.startsWith(prefix)) return token.split(':')[1].replace(/\.+$/, '').toLowerCase()
  }
  for (const prefix of ['redirect=', 'exp=']) {
    if (lowered.startsWith(prefix)) return token.split('=')[1].replace(/\.+$/, '').toLowerCase()
  }
  return null
}

function snapshotForCase(testCase, extra = []) {
  const stub = new StubResolver(testCase.zonedata)
  const entries = []
  const asked = new Set()
  const record = (qname, qtype) => {
    const key = [qname.toLowerCase().replace(/\.+$/, ''), qtype.toUpperCase()].join('\u0000')
    if (asked.has(key)) return
    asked.add(key)
    const response = stub.respond(qname, qtype)
    entries.push({
      qname,
      qtype: qtype.toUpperCase(),
      rcode: response.rcode,
      answer: response.rcode === 'NOERROR' ? response.answer : [],
      ttl: 300,
    })
  }

  const names = new Set()
  const domain = testCase.mailfrom.includes('@')
    ? testCase.mailfrom.split('@').pop().replace(/\.+$/, '').toLowerCase()
    : ''
  if (domain) names.add(domain)
  const reverse = reverseName(testCase.host)
  if (reverse) names.add(reverse)
  for (const name of Object.keys(testCase.zonedata ?? {})) {
    names.add(name.toLowerCase().replace(/\.+$/, ''))
  }
  for (const records of Object.values(testCase.zonedata ?? {})) {
    for (const entry of records) {
      if (entry === null || typeof entry !== 'object') continue
      for (const [rtype, value] of Object.entries(entry)) {
        if (rtype === 'SPF' || rtype === 'TXT') {
          for (const token of asText(value).split(' ').slice(1)) {
            const target = referencedTarget(token)
            if (target && !target.includes('%') && !target.includes('/')) names.add(target)
          }
        } else if (rtype === 'PTR' || rtype === 'CNAME') {
          names.add(asText(value).replace(/\.+$/, '').toLowerCase())
        } else if (rtype === 'MX') {
          names.add(formatMx(value).split(' ').slice(1).join(' ').replace(/\.+$/, '').toLowerCase())
        }
      }
    }
  }
  for (const name of [...names].sort()) {
    if (!name) continue
    for (const qtype of ['TXT', 'A', 'AAAA', 'MX', 'PTR']) record(name, qtype)
  }
  for (const [qname, qtype] of extra) record(qname, qtype)

  return {
    schema_version: 1,
    fetched_at: '2026-10-19T18:35:00Z',
    resolver: 'synthetic',
    psl_version: '2026-10-20_08-40-56_UTC',
    psl_date: '2026-10-20',
    queries: entries,
  }
}

function runSuiteCase(testCase) {
  const extra = []
  for (let round = 0; round < 64; round += 1) {
    const snapshot = Snapshot.fromObject(snapshotForCase(testCase, extra))
    const result = spfEvaluate(snapshot, {
      mail_from: testCase.mailfrom,
      client_ip: testCase.host,
      helo: testCase.helo,
      trusted_authserv_ids: [],
    })
    if (!result.data_gap) return result
    const [qname, qtype] = result.data_gap
    if (extra.some(([name, type]) => name === qname && type === qtype)) {
      throw new Error(`数据缺口补过之后仍然缺：${qname}/${qtype}`)
    }
    extra.push([qname, qtype])
  }
  throw new Error(`用例 ${testCase.section}/${testCase.name} 在 64 轮内没有收敛`)
}

// ── 上游 fixture 驱动 ──────────────────────────────────────────────────

function fixtureDirs(family) {
  return readdirSync(join(UPSTREAM, family), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
}

const fixtureCache = new Map()

function loadFixture(family, name) {
  const key = `${family}/${name}`
  const cached = fixtureCache.get(key)
  if (cached !== undefined) return cached
  const dir = join(UPSTREAM, family, name)
  const snapshot = Snapshot.fromObject(JSON.parse(readFileSync(join(dir, 'snap.json'), 'utf8')))
  const message = parseMessage(readFileSync(join(dir, 'message.eml')))
  const delivery = JSON.parse(readFileSync(join(dir, 'query.json'), 'utf8'))
  const spf = spfEvaluate(snapshot, delivery)
  const dkim = verifyMessage(message, snapshot)
  const dmarc = dmarcEvaluate(snapshot, message, delivery, spf, dkim)
  const value = {
    dir,
    snapshot,
    message,
    delivery,
    raw: readFileSync(join(dir, 'message.eml')),
    spf,
    dkim,
    dmarc,
  }
  fixtureCache.set(key, value)
  return value
}

function fixtureActual(family, name) {
  const { dkim, dmarc } = loadFixture(family, name)
  const sig = dkim.signatures[0] ?? null
  const map = {
    'dkim.result': sig ? sig.result : 'none',
    'dkim.signatures_total': dkim.signatures.length,
    'dkim.bh_matches': sig ? sig.bh_matches : null,
    'dkim.key_status': sig ? sig.key_status : null,
    'dkim.key_bits': sig ? sig.key_bits : null,
    'dkim.failure_at': sig ? sig.failure_at : null,
    'dkim.data_gap': sig ? sig.data_gap : null,
    'dmarc.result': dmarc.result,
    'dmarc.author_domain': dmarc.author_domain,
    'dmarc.organizational_domain': dmarc.organizational_domain,
    'dmarc.policy_source': dmarc.policy_source,
    'dmarc.policy_tag': dmarc.policy_tag,
    'dmarc.policy_value': dmarc.policy_value,
    'dmarc.disposition': dmarc.disposition,
    'dmarc.disposition_status': dmarc.disposition_status,
    'dmarc.test_mode': dmarc.test_mode,
    'dmarc.psd': dmarc.record ? (dmarc.record.tags.psd ?? 'u') : null,
    'dmarc.walk_queries': dmarc.walk ? dmarc.walk.hops.length : 0,
  }
  if (sig?.failure_at) {
    for (const [key, value] of Object.entries(sig.failure_at)) map[`dkim.failure_at.${key}`] = value
  }
  dkim.signatures.forEach((signature, index) => {
    map[`dkim.result[${index}]`] = signature.result
  })
  for (const [key, value] of Object.entries(dmarc.spf_align)) map[`dmarc.spf_align.${key}`] = value
  for (const [key, value] of Object.entries(dmarc.dkim_align)) map[`dmarc.dkim_align.${key}`] = value
  ;(dmarc.walk?.hops ?? []).forEach((hop, index) => {
    map[`dmarc.walk[${index}].qname`] = hop.qname
    map[`dmarc.walk[${index}].status`] = hop.status
    map[`dmarc.walk[${index}].psd`] = hop.psd
  })
  return map
}

// ── CLI 捕获 ────────────────────────────────────────────────────────────

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
  return mkdtempSync(join(tmpdir(), 'traceproof-email-evidence-'))
}

function subjectFor(family, name, claims, overrides = {}) {
  const fixture = loadFixture(family, name)
  return {
    snapshot: JSON.parse(JSON.stringify(fixture.snapshot.data)),
    query: fixture.delivery,
    message_b64: fixture.raw.toString('base64'),
    claims,
    ...overrides,
  }
}

const NODE = { session_id: 's-1', turn: 3, tool_call_id: 'call-7' }

// ════════════════════════════════════════════════════════════════════════
// 1. RFC 7208 上游测试集（203 条，逐条独立用例）
// ════════════════════════════════════════════════════════════════════════

test('rfc7208: 测试集是 203 条 / 16 分组，上游许可随夹具带入', () => {
  assert.equal(SUITE.case_count, 203)
  assert.equal(new Set(SUITE.cases.map((entry) => entry.section)).size, 16)
  assert.match(SUITE._license_text, /Stuart D Gathman/)
  assert.match(SUITE._license_text, /Redistribution and use in source and binary forms/)
})

test('rfc7208: 用例 id 唯一且五输入齐备', () => {
  const ids = SUITE.cases.map((entry) => `${entry.section}/${entry.name}`)
  assert.equal(new Set(ids).size, ids.length)
  for (const entry of SUITE.cases) {
    assert.ok(entry.spec, ids)
    assert.ok(entry.host.length > 0)
    assert.ok(entry.result.length > 0)
  }
})

// 显式用例（顶层 test 声明）：下列 203 条逐条对应 RFC 7208 上游套件的一个 spec；
// 断言逻辑集中在 assertRfcCase，避免把同一判断复制到每个用例里。
function assertRfcCase(id) {
  const testCase = SUITE.cases.find((entry) => `${entry.section}/${entry.name}` === id)
  assert.ok(testCase, `套件里没有用例：${id}`)
  const result = runSuiteCase(testCase)
  // 唯一登记在案的口径差异：void 超限按本项目灰区 2 判 undecidable（RFC 原文 SHOULD）。
  const allowed =
    id === 'Processing limits/void-over-limit'
      ? [...testCase.result, 'undecidable']
      : testCase.result
  assert.ok(
    allowed.includes(result.result),
    `${id}：实得 ${result.result}，可接受 ${allowed.join('|')}（${result.reason}）`,
  )
}

test('rfc7208: Initial processing/toolonglabel', () => assertRfcCase("Initial processing/toolonglabel"));
test('rfc7208: Initial processing/longlabel', () => assertRfcCase("Initial processing/longlabel"));
test('rfc7208: Initial processing/emptylabel', () => assertRfcCase("Initial processing/emptylabel"));
test('rfc7208: Initial processing/helo-not-fqdn', () => assertRfcCase("Initial processing/helo-not-fqdn"));
test('rfc7208: Initial processing/helo-domain-literal', () => assertRfcCase("Initial processing/helo-domain-literal"));
test('rfc7208: Initial processing/nolocalpart', () => assertRfcCase("Initial processing/nolocalpart"));
test('rfc7208: Initial processing/domain-literal', () => assertRfcCase("Initial processing/domain-literal"));
test('rfc7208: Initial processing/non-ascii-policy', () => assertRfcCase("Initial processing/non-ascii-policy"));
test('rfc7208: Initial processing/non-ascii-mech', () => assertRfcCase("Initial processing/non-ascii-mech"));
test('rfc7208: Initial processing/non-ascii-result', () => assertRfcCase("Initial processing/non-ascii-result"));
test('rfc7208: Initial processing/non-ascii-non-spf', () => assertRfcCase("Initial processing/non-ascii-non-spf"));
test('rfc7208: Initial processing/control-char-policy', () => assertRfcCase("Initial processing/control-char-policy"));
test('rfc7208: Initial processing/two-spaces', () => assertRfcCase("Initial processing/two-spaces"));
test('rfc7208: Initial processing/trailing-space', () => assertRfcCase("Initial processing/trailing-space"));
test('rfc7208: Initial processing/null-text', () => assertRfcCase("Initial processing/null-text"));
test('rfc7208: Initial processing/badip4', () => assertRfcCase("Initial processing/badip4"));
test('rfc7208: Record lookup/both', () => assertRfcCase("Record lookup/both"));
test('rfc7208: Record lookup/txtonly', () => assertRfcCase("Record lookup/txtonly"));
test('rfc7208: Record lookup/spfonly', () => assertRfcCase("Record lookup/spfonly"));
test('rfc7208: Record lookup/spftimeout', () => assertRfcCase("Record lookup/spftimeout"));
test('rfc7208: Record lookup/txttimeout', () => assertRfcCase("Record lookup/txttimeout"));
test('rfc7208: Record lookup/nospftxttimeout', () => assertRfcCase("Record lookup/nospftxttimeout"));
test('rfc7208: Record lookup/alltimeout', () => assertRfcCase("Record lookup/alltimeout"));
test('rfc7208: Selecting records/nospace1', () => assertRfcCase("Selecting records/nospace1"));
test('rfc7208: Selecting records/empty', () => assertRfcCase("Selecting records/empty"));
test('rfc7208: Selecting records/nospace2', () => assertRfcCase("Selecting records/nospace2"));
test('rfc7208: Selecting records/spfoverride', () => assertRfcCase("Selecting records/spfoverride"));
test('rfc7208: Selecting records/multitxt1', () => assertRfcCase("Selecting records/multitxt1"));
test('rfc7208: Selecting records/multitxt2', () => assertRfcCase("Selecting records/multitxt2"));
test('rfc7208: Selecting records/multispf1', () => assertRfcCase("Selecting records/multispf1"));
test('rfc7208: Selecting records/multispf2', () => assertRfcCase("Selecting records/multispf2"));
test('rfc7208: Selecting records/nospf', () => assertRfcCase("Selecting records/nospf"));
test('rfc7208: Selecting records/case-insensitive', () => assertRfcCase("Selecting records/case-insensitive"));
test('rfc7208: Record evaluation/detect-errors-anywhere', () => assertRfcCase("Record evaluation/detect-errors-anywhere"));
test('rfc7208: Record evaluation/modifier-charset-good', () => assertRfcCase("Record evaluation/modifier-charset-good"));
test('rfc7208: Record evaluation/modifier-charset-bad1', () => assertRfcCase("Record evaluation/modifier-charset-bad1"));
test('rfc7208: Record evaluation/modifier-charset-bad2', () => assertRfcCase("Record evaluation/modifier-charset-bad2"));
test('rfc7208: Record evaluation/redirect-after-mechanisms1', () => assertRfcCase("Record evaluation/redirect-after-mechanisms1"));
test('rfc7208: Record evaluation/redirect-after-mechanisms2', () => assertRfcCase("Record evaluation/redirect-after-mechanisms2"));
test('rfc7208: Record evaluation/default-result', () => assertRfcCase("Record evaluation/default-result"));
test('rfc7208: Record evaluation/redirect-is-modifier', () => assertRfcCase("Record evaluation/redirect-is-modifier"));
test('rfc7208: Record evaluation/invalid-domain', () => assertRfcCase("Record evaluation/invalid-domain"));
test('rfc7208: Record evaluation/invalid-domain-empty-label', () => assertRfcCase("Record evaluation/invalid-domain-empty-label"));
test('rfc7208: Record evaluation/invalid-domain-long', () => assertRfcCase("Record evaluation/invalid-domain-long"));
test('rfc7208: Record evaluation/invalid-domain-long-via-macro', () => assertRfcCase("Record evaluation/invalid-domain-long-via-macro"));
test('rfc7208: ALL mechanism syntax/all-dot', () => assertRfcCase("ALL mechanism syntax/all-dot"));
test('rfc7208: ALL mechanism syntax/all-arg', () => assertRfcCase("ALL mechanism syntax/all-arg"));
test('rfc7208: ALL mechanism syntax/all-cidr', () => assertRfcCase("ALL mechanism syntax/all-cidr"));
test('rfc7208: ALL mechanism syntax/all-neutral', () => assertRfcCase("ALL mechanism syntax/all-neutral"));
test('rfc7208: ALL mechanism syntax/all-double', () => assertRfcCase("ALL mechanism syntax/all-double"));
test('rfc7208: PTR mechanism syntax/ptr-cidr', () => assertRfcCase("PTR mechanism syntax/ptr-cidr"));
test('rfc7208: PTR mechanism syntax/ptr-match-target', () => assertRfcCase("PTR mechanism syntax/ptr-match-target"));
test('rfc7208: PTR mechanism syntax/ptr-match-implicit', () => assertRfcCase("PTR mechanism syntax/ptr-match-implicit"));
test('rfc7208: PTR mechanism syntax/ptr-nomatch-invalid', () => assertRfcCase("PTR mechanism syntax/ptr-nomatch-invalid"));
test('rfc7208: PTR mechanism syntax/ptr-match-ip6', () => assertRfcCase("PTR mechanism syntax/ptr-match-ip6"));
test('rfc7208: PTR mechanism syntax/ptr-empty-domain', () => assertRfcCase("PTR mechanism syntax/ptr-empty-domain"));
test('rfc7208: PTR mechanism syntax/ptr-case-change', () => assertRfcCase("PTR mechanism syntax/ptr-case-change"));
test('rfc7208: PTR mechanism syntax/ptr-cname-loop', () => assertRfcCase("PTR mechanism syntax/ptr-cname-loop"));
test('rfc7208: A mechanism syntax/a-cidr6', () => assertRfcCase("A mechanism syntax/a-cidr6"));
test('rfc7208: A mechanism syntax/a-bad-cidr4', () => assertRfcCase("A mechanism syntax/a-bad-cidr4"));
test('rfc7208: A mechanism syntax/a-bad-cidr6', () => assertRfcCase("A mechanism syntax/a-bad-cidr6"));
test('rfc7208: A mechanism syntax/a-dual-cidr-ip4-match', () => assertRfcCase("A mechanism syntax/a-dual-cidr-ip4-match"));
test('rfc7208: A mechanism syntax/a-dual-cidr-ip4-err', () => assertRfcCase("A mechanism syntax/a-dual-cidr-ip4-err"));
test('rfc7208: A mechanism syntax/a-dual-cidr-ip6-match', () => assertRfcCase("A mechanism syntax/a-dual-cidr-ip6-match"));
test('rfc7208: A mechanism syntax/a-dual-cidr-ip4-default', () => assertRfcCase("A mechanism syntax/a-dual-cidr-ip4-default"));
test('rfc7208: A mechanism syntax/a-dual-cidr-ip6-default', () => assertRfcCase("A mechanism syntax/a-dual-cidr-ip6-default"));
test('rfc7208: A mechanism syntax/a-multi-ip1', () => assertRfcCase("A mechanism syntax/a-multi-ip1"));
test('rfc7208: A mechanism syntax/a-multi-ip2', () => assertRfcCase("A mechanism syntax/a-multi-ip2"));
test('rfc7208: A mechanism syntax/a-bad-domain', () => assertRfcCase("A mechanism syntax/a-bad-domain"));
test('rfc7208: A mechanism syntax/a-nxdomain', () => assertRfcCase("A mechanism syntax/a-nxdomain"));
test('rfc7208: A mechanism syntax/a-cidr4-0', () => assertRfcCase("A mechanism syntax/a-cidr4-0"));
test('rfc7208: A mechanism syntax/a-cidr4-0-ip6', () => assertRfcCase("A mechanism syntax/a-cidr4-0-ip6"));
test('rfc7208: A mechanism syntax/a-cidr6-0-ip4', () => assertRfcCase("A mechanism syntax/a-cidr6-0-ip4"));
test('rfc7208: A mechanism syntax/a-cidr6-0-ip4mapped', () => assertRfcCase("A mechanism syntax/a-cidr6-0-ip4mapped"));
test('rfc7208: A mechanism syntax/a-cidr6-0-ip6', () => assertRfcCase("A mechanism syntax/a-cidr6-0-ip6"));
test('rfc7208: A mechanism syntax/a-ip6-dualstack', () => assertRfcCase("A mechanism syntax/a-ip6-dualstack"));
test('rfc7208: A mechanism syntax/a-cidr6-0-nxdomain', () => assertRfcCase("A mechanism syntax/a-cidr6-0-nxdomain"));
test('rfc7208: A mechanism syntax/a-null', () => assertRfcCase("A mechanism syntax/a-null"));
test('rfc7208: A mechanism syntax/a-numeric', () => assertRfcCase("A mechanism syntax/a-numeric"));
test('rfc7208: A mechanism syntax/a-numeric-toplabel', () => assertRfcCase("A mechanism syntax/a-numeric-toplabel"));
test('rfc7208: A mechanism syntax/a-dash-in-toplabel', () => assertRfcCase("A mechanism syntax/a-dash-in-toplabel"));
test('rfc7208: A mechanism syntax/a-bad-toplabel', () => assertRfcCase("A mechanism syntax/a-bad-toplabel"));
test('rfc7208: A mechanism syntax/a-only-toplabel', () => assertRfcCase("A mechanism syntax/a-only-toplabel"));
test('rfc7208: A mechanism syntax/a-only-toplabel-trailing-dot', () => assertRfcCase("A mechanism syntax/a-only-toplabel-trailing-dot"));
test('rfc7208: A mechanism syntax/a-colon-domain', () => assertRfcCase("A mechanism syntax/a-colon-domain"));
test('rfc7208: A mechanism syntax/a-colon-domain-ip4mapped', () => assertRfcCase("A mechanism syntax/a-colon-domain-ip4mapped"));
test('rfc7208: A mechanism syntax/a-empty-domain', () => assertRfcCase("A mechanism syntax/a-empty-domain"));
test('rfc7208: Include mechanism semantics and syntax/include-fail', () => assertRfcCase("Include mechanism semantics and syntax/include-fail"));
test('rfc7208: Include mechanism semantics and syntax/include-softfail', () => assertRfcCase("Include mechanism semantics and syntax/include-softfail"));
test('rfc7208: Include mechanism semantics and syntax/include-neutral', () => assertRfcCase("Include mechanism semantics and syntax/include-neutral"));
test('rfc7208: Include mechanism semantics and syntax/include-temperror', () => assertRfcCase("Include mechanism semantics and syntax/include-temperror"));
test('rfc7208: Include mechanism semantics and syntax/include-permerror', () => assertRfcCase("Include mechanism semantics and syntax/include-permerror"));
test('rfc7208: Include mechanism semantics and syntax/include-syntax-error', () => assertRfcCase("Include mechanism semantics and syntax/include-syntax-error"));
test('rfc7208: Include mechanism semantics and syntax/include-cidr', () => assertRfcCase("Include mechanism semantics and syntax/include-cidr"));
test('rfc7208: Include mechanism semantics and syntax/include-none', () => assertRfcCase("Include mechanism semantics and syntax/include-none"));
test('rfc7208: Include mechanism semantics and syntax/include-empty-domain', () => assertRfcCase("Include mechanism semantics and syntax/include-empty-domain"));
test('rfc7208: MX mechanism syntax/mx-cidr6', () => assertRfcCase("MX mechanism syntax/mx-cidr6"));
test('rfc7208: MX mechanism syntax/mx-bad-cidr4', () => assertRfcCase("MX mechanism syntax/mx-bad-cidr4"));
test('rfc7208: MX mechanism syntax/mx-bad-cidr6', () => assertRfcCase("MX mechanism syntax/mx-bad-cidr6"));
test('rfc7208: MX mechanism syntax/mx-multi-ip1', () => assertRfcCase("MX mechanism syntax/mx-multi-ip1"));
test('rfc7208: MX mechanism syntax/mx-multi-ip2', () => assertRfcCase("MX mechanism syntax/mx-multi-ip2"));
test('rfc7208: MX mechanism syntax/mx-bad-domain', () => assertRfcCase("MX mechanism syntax/mx-bad-domain"));
test('rfc7208: MX mechanism syntax/mx-nxdomain', () => assertRfcCase("MX mechanism syntax/mx-nxdomain"));
test('rfc7208: MX mechanism syntax/mx-cidr4-0', () => assertRfcCase("MX mechanism syntax/mx-cidr4-0"));
test('rfc7208: MX mechanism syntax/mx-cidr4-0-ip6', () => assertRfcCase("MX mechanism syntax/mx-cidr4-0-ip6"));
test('rfc7208: MX mechanism syntax/mx-cidr6-0-ip4', () => assertRfcCase("MX mechanism syntax/mx-cidr6-0-ip4"));
test('rfc7208: MX mechanism syntax/mx-cidr6-0-ip4mapped', () => assertRfcCase("MX mechanism syntax/mx-cidr6-0-ip4mapped"));
test('rfc7208: MX mechanism syntax/mx-cidr6-0-ip6', () => assertRfcCase("MX mechanism syntax/mx-cidr6-0-ip6"));
test('rfc7208: MX mechanism syntax/mx-cidr6-0-nxdomain', () => assertRfcCase("MX mechanism syntax/mx-cidr6-0-nxdomain"));
test('rfc7208: MX mechanism syntax/mx-null', () => assertRfcCase("MX mechanism syntax/mx-null"));
test('rfc7208: MX mechanism syntax/mx-numeric-top-label', () => assertRfcCase("MX mechanism syntax/mx-numeric-top-label"));
test('rfc7208: MX mechanism syntax/mx-colon-domain', () => assertRfcCase("MX mechanism syntax/mx-colon-domain"));
test('rfc7208: MX mechanism syntax/mx-colon-domain-ip4mapped', () => assertRfcCase("MX mechanism syntax/mx-colon-domain-ip4mapped"));
test('rfc7208: MX mechanism syntax/mx-bad-toplab', () => assertRfcCase("MX mechanism syntax/mx-bad-toplab"));
test('rfc7208: MX mechanism syntax/mx-empty', () => assertRfcCase("MX mechanism syntax/mx-empty"));
test('rfc7208: MX mechanism syntax/mx-implicit', () => assertRfcCase("MX mechanism syntax/mx-implicit"));
test('rfc7208: MX mechanism syntax/mx-empty-domain', () => assertRfcCase("MX mechanism syntax/mx-empty-domain"));
test('rfc7208: EXISTS mechanism syntax/exists-empty-domain', () => assertRfcCase("EXISTS mechanism syntax/exists-empty-domain"));
test('rfc7208: EXISTS mechanism syntax/exists-implicit', () => assertRfcCase("EXISTS mechanism syntax/exists-implicit"));
test('rfc7208: EXISTS mechanism syntax/exists-cidr', () => assertRfcCase("EXISTS mechanism syntax/exists-cidr"));
test('rfc7208: EXISTS mechanism syntax/exists-ip4', () => assertRfcCase("EXISTS mechanism syntax/exists-ip4"));
test('rfc7208: EXISTS mechanism syntax/exists-ip6', () => assertRfcCase("EXISTS mechanism syntax/exists-ip6"));
test('rfc7208: EXISTS mechanism syntax/exists-ip6only', () => assertRfcCase("EXISTS mechanism syntax/exists-ip6only"));
test('rfc7208: EXISTS mechanism syntax/exists-dnserr', () => assertRfcCase("EXISTS mechanism syntax/exists-dnserr"));
test('rfc7208: IP4 mechanism syntax/cidr4-0', () => assertRfcCase("IP4 mechanism syntax/cidr4-0"));
test('rfc7208: IP4 mechanism syntax/cidr4-32', () => assertRfcCase("IP4 mechanism syntax/cidr4-32"));
test('rfc7208: IP4 mechanism syntax/cidr4-33', () => assertRfcCase("IP4 mechanism syntax/cidr4-33"));
test('rfc7208: IP4 mechanism syntax/cidr4-032', () => assertRfcCase("IP4 mechanism syntax/cidr4-032"));
test('rfc7208: IP4 mechanism syntax/bare-ip4', () => assertRfcCase("IP4 mechanism syntax/bare-ip4"));
test('rfc7208: IP4 mechanism syntax/bad-ip4-port', () => assertRfcCase("IP4 mechanism syntax/bad-ip4-port"));
test('rfc7208: IP4 mechanism syntax/bad-ip4-short', () => assertRfcCase("IP4 mechanism syntax/bad-ip4-short"));
test('rfc7208: IP4 mechanism syntax/ip4-dual-cidr', () => assertRfcCase("IP4 mechanism syntax/ip4-dual-cidr"));
test('rfc7208: IP4 mechanism syntax/ip4-mapped-ip6', () => assertRfcCase("IP4 mechanism syntax/ip4-mapped-ip6"));
test('rfc7208: IP6 mechanism syntax/bare-ip6', () => assertRfcCase("IP6 mechanism syntax/bare-ip6"));
test('rfc7208: IP6 mechanism syntax/cidr6-0-ip4', () => assertRfcCase("IP6 mechanism syntax/cidr6-0-ip4"));
test('rfc7208: IP6 mechanism syntax/cidr6-ip4', () => assertRfcCase("IP6 mechanism syntax/cidr6-ip4"));
test('rfc7208: IP6 mechanism syntax/cidr6-0', () => assertRfcCase("IP6 mechanism syntax/cidr6-0"));
test('rfc7208: IP6 mechanism syntax/cidr6-129', () => assertRfcCase("IP6 mechanism syntax/cidr6-129"));
test('rfc7208: IP6 mechanism syntax/cidr6-bad', () => assertRfcCase("IP6 mechanism syntax/cidr6-bad"));
test('rfc7208: IP6 mechanism syntax/cidr6-33', () => assertRfcCase("IP6 mechanism syntax/cidr6-33"));
test('rfc7208: IP6 mechanism syntax/cidr6-33-ip4', () => assertRfcCase("IP6 mechanism syntax/cidr6-33-ip4"));
test('rfc7208: IP6 mechanism syntax/ip6-bad1', () => assertRfcCase("IP6 mechanism syntax/ip6-bad1"));
test('rfc7208: Semantics of exp and other modifiers/redirect-none', () => assertRfcCase("Semantics of exp and other modifiers/redirect-none"));
test('rfc7208: Semantics of exp and other modifiers/redirect-cancels-exp', () => assertRfcCase("Semantics of exp and other modifiers/redirect-cancels-exp"));
test('rfc7208: Semantics of exp and other modifiers/redirect-syntax-error', () => assertRfcCase("Semantics of exp and other modifiers/redirect-syntax-error"));
test('rfc7208: Semantics of exp and other modifiers/include-ignores-exp', () => assertRfcCase("Semantics of exp and other modifiers/include-ignores-exp"));
test('rfc7208: Semantics of exp and other modifiers/redirect-cancels-prior-exp', () => assertRfcCase("Semantics of exp and other modifiers/redirect-cancels-prior-exp"));
test('rfc7208: Semantics of exp and other modifiers/invalid-modifier', () => assertRfcCase("Semantics of exp and other modifiers/invalid-modifier"));
test('rfc7208: Semantics of exp and other modifiers/empty-modifier-name', () => assertRfcCase("Semantics of exp and other modifiers/empty-modifier-name"));
test('rfc7208: Semantics of exp and other modifiers/dorky-sentinel', () => assertRfcCase("Semantics of exp and other modifiers/dorky-sentinel"));
test('rfc7208: Semantics of exp and other modifiers/exp-multiple-txt', () => assertRfcCase("Semantics of exp and other modifiers/exp-multiple-txt"));
test('rfc7208: Semantics of exp and other modifiers/exp-no-txt', () => assertRfcCase("Semantics of exp and other modifiers/exp-no-txt"));
test('rfc7208: Semantics of exp and other modifiers/exp-dns-error', () => assertRfcCase("Semantics of exp and other modifiers/exp-dns-error"));
test('rfc7208: Semantics of exp and other modifiers/exp-empty-domain', () => assertRfcCase("Semantics of exp and other modifiers/exp-empty-domain"));
test('rfc7208: Semantics of exp and other modifiers/explanation-syntax-error', () => assertRfcCase("Semantics of exp and other modifiers/explanation-syntax-error"));
test('rfc7208: Semantics of exp and other modifiers/exp-syntax-error', () => assertRfcCase("Semantics of exp and other modifiers/exp-syntax-error"));
test('rfc7208: Semantics of exp and other modifiers/exp-twice', () => assertRfcCase("Semantics of exp and other modifiers/exp-twice"));
test('rfc7208: Semantics of exp and other modifiers/redirect-empty-domain', () => assertRfcCase("Semantics of exp and other modifiers/redirect-empty-domain"));
test('rfc7208: Semantics of exp and other modifiers/redirect-twice', () => assertRfcCase("Semantics of exp and other modifiers/redirect-twice"));
test('rfc7208: Semantics of exp and other modifiers/unknown-modifier-syntax', () => assertRfcCase("Semantics of exp and other modifiers/unknown-modifier-syntax"));
test('rfc7208: Semantics of exp and other modifiers/default-modifier-obsolete', () => assertRfcCase("Semantics of exp and other modifiers/default-modifier-obsolete"));
test('rfc7208: Semantics of exp and other modifiers/default-modifier-obsolete2', () => assertRfcCase("Semantics of exp and other modifiers/default-modifier-obsolete2"));
test('rfc7208: Semantics of exp and other modifiers/non-ascii-exp', () => assertRfcCase("Semantics of exp and other modifiers/non-ascii-exp"));
test('rfc7208: Semantics of exp and other modifiers/two-exp-records', () => assertRfcCase("Semantics of exp and other modifiers/two-exp-records"));
test('rfc7208: Semantics of exp and other modifiers/exp-void', () => assertRfcCase("Semantics of exp and other modifiers/exp-void"));
test('rfc7208: Semantics of exp and other modifiers/redirect-implicit', () => assertRfcCase("Semantics of exp and other modifiers/redirect-implicit"));
test('rfc7208: Macro expansion rules/trailing-dot-domain', () => assertRfcCase("Macro expansion rules/trailing-dot-domain"));
test('rfc7208: Macro expansion rules/trailing-dot-exp', () => assertRfcCase("Macro expansion rules/trailing-dot-exp"));
test('rfc7208: Macro expansion rules/exp-only-macro-char', () => assertRfcCase("Macro expansion rules/exp-only-macro-char"));
test('rfc7208: Macro expansion rules/invalid-macro-char', () => assertRfcCase("Macro expansion rules/invalid-macro-char"));
test('rfc7208: Macro expansion rules/invalid-embedded-macro-char', () => assertRfcCase("Macro expansion rules/invalid-embedded-macro-char"));
test('rfc7208: Macro expansion rules/invalid-trailing-macro-char', () => assertRfcCase("Macro expansion rules/invalid-trailing-macro-char"));
test('rfc7208: Macro expansion rules/macro-mania-in-domain', () => assertRfcCase("Macro expansion rules/macro-mania-in-domain"));
test('rfc7208: Macro expansion rules/exp-txt-macro-char', () => assertRfcCase("Macro expansion rules/exp-txt-macro-char"));
test('rfc7208: Macro expansion rules/domain-name-truncation', () => assertRfcCase("Macro expansion rules/domain-name-truncation"));
test('rfc7208: Macro expansion rules/v-macro-ip4', () => assertRfcCase("Macro expansion rules/v-macro-ip4"));
test('rfc7208: Macro expansion rules/v-macro-ip6', () => assertRfcCase("Macro expansion rules/v-macro-ip6"));
test('rfc7208: Macro expansion rules/undef-macro', () => assertRfcCase("Macro expansion rules/undef-macro"));
test('rfc7208: Macro expansion rules/p-macro-ip4-novalid', () => assertRfcCase("Macro expansion rules/p-macro-ip4-novalid"));
test('rfc7208: Macro expansion rules/p-macro-ip4-valid', () => assertRfcCase("Macro expansion rules/p-macro-ip4-valid"));
test('rfc7208: Macro expansion rules/p-macro-ip6-novalid', () => assertRfcCase("Macro expansion rules/p-macro-ip6-novalid"));
test('rfc7208: Macro expansion rules/p-macro-ip6-valid', () => assertRfcCase("Macro expansion rules/p-macro-ip6-valid"));
test('rfc7208: Macro expansion rules/p-macro-multiple', () => assertRfcCase("Macro expansion rules/p-macro-multiple"));
test('rfc7208: Macro expansion rules/upper-macro', () => assertRfcCase("Macro expansion rules/upper-macro"));
test('rfc7208: Macro expansion rules/hello-macro', () => assertRfcCase("Macro expansion rules/hello-macro"));
test('rfc7208: Macro expansion rules/invalid-hello-macro', () => assertRfcCase("Macro expansion rules/invalid-hello-macro"));
test('rfc7208: Macro expansion rules/hello-domain-literal', () => assertRfcCase("Macro expansion rules/hello-domain-literal"));
test('rfc7208: Macro expansion rules/require-valid-helo', () => assertRfcCase("Macro expansion rules/require-valid-helo"));
test('rfc7208: Macro expansion rules/macro-reverse-split-on-dash', () => assertRfcCase("Macro expansion rules/macro-reverse-split-on-dash"));
test('rfc7208: Macro expansion rules/macro-multiple-delimiters', () => assertRfcCase("Macro expansion rules/macro-multiple-delimiters"));
test('rfc7208: Processing limits/redirect-loop', () => assertRfcCase("Processing limits/redirect-loop"));
test('rfc7208: Processing limits/include-loop', () => assertRfcCase("Processing limits/include-loop"));
test('rfc7208: Processing limits/mx-limit', () => assertRfcCase("Processing limits/mx-limit"));
test('rfc7208: Processing limits/ptr-limit', () => assertRfcCase("Processing limits/ptr-limit"));
test('rfc7208: Processing limits/false-a-limit', () => assertRfcCase("Processing limits/false-a-limit"));
test('rfc7208: Processing limits/mech-at-limit', () => assertRfcCase("Processing limits/mech-at-limit"));
test('rfc7208: Processing limits/mech-over-limit', () => assertRfcCase("Processing limits/mech-over-limit"));
test('rfc7208: Processing limits/include-at-limit', () => assertRfcCase("Processing limits/include-at-limit"));
test('rfc7208: Processing limits/include-over-limit', () => assertRfcCase("Processing limits/include-over-limit"));
test('rfc7208: Processing limits/void-at-limit', () => assertRfcCase("Processing limits/void-at-limit"));
test('rfc7208: Processing limits/void-over-limit', () => assertRfcCase("Processing limits/void-over-limit"));
test('rfc7208: Test cases from implementation bugs/bytes-bug', () => assertRfcCase("Test cases from implementation bugs/bytes-bug"));
test('rfc7208: Test cases from implementation bugs/cname-aliasing', () => assertRfcCase("Test cases from implementation bugs/cname-aliasing"));

test('rfc7208: 唯一口径差异是 void 超限（旧仓同款，登记在 docs/email-evidence.md）', () => {
  const diff = SUITE.cases.filter((entry) => {
    const result = runSuiteCase(entry)
    return !entry.result.includes(result.result)
  })
  assert.deepEqual(
    diff.map((entry) => `${entry.section}/${entry.name}`),
    ['Processing limits/void-over-limit'],
  )
})

// ════════════════════════════════════════════════════════════════════════
// 2. IP 字面量 / CIDR
// ════════════════════════════════════════════════════════════════════════

test('ip: IPv4 解析与字节视图', () => {
  const address = parseIp('192.0.2.10')
  assert.equal(address.version, 4)
  assert.deepEqual(address.bytes, [192, 0, 2, 10])
})

test('ip: 前导零与越界 IPv4 被拒', () => {
  assert.equal(parseIp('192.0.02.1'), null)
  assert.equal(parseIp('256.0.2.1'), null)
  assert.equal(parseIp('1.2.3'), null)
})

test('ip: IPv6 压缩形态与内嵌 IPv4', () => {
  assert.equal(parseIp('2001:db8::1').bytes.length, 16)
  assert.equal(parseIp('::ffff:192.0.2.1').bytes[10], 0xff)
  assert.equal(parseIp('2001:db8::1::2'), null)
})

test('ip: IPv4-mapped IPv6 折回 IPv4', () => {
  const mapped = unmapIp(parseIp('::ffff:192.0.2.1'))
  assert.equal(mapped.version, 4)
  assert.deepEqual(mapped.bytes, [192, 0, 2, 1])
})

test('ip: IPv6 压缩输出（最长零串、左侧优先）', () => {
  assert.equal(ipv6ToString(parseIp('2001:0db8:0000:0000:0000:0000:0000:0001').bytes), '2001:db8::1')
  assert.equal(ipv6ToString(parseIp('2001:db8:0:1:0:0:0:1').bytes), '2001:db8:0:1::1')
})

test('ip: %{i} 的 IPv6 十六进制半字节形态', () => {
  assert.equal(ipv6DottedNibbles(parseIp('::1').bytes).startsWith('0.0.0.0.'), true)
  assert.equal(ipv6DottedNibbles(parseIp('::1').bytes).length, 63)
})

test('ip: PTR 名 IPv4', () => {
  assert.equal(reverseLookupName(parseIp('192.0.2.10')), '10.2.0.192.in-addr.arpa')
})

test('ip: PTR 名 IPv6 以 ip6.arpa 结尾', () => {
  assert.match(reverseLookupName(parseIp('2001:db8::1')), /\.ip6\.arpa$/)
})

test('ip: CIDR 匹配与版本隔离', () => {
  assert.equal(cidrMatch(['192.0.2.0/24'], 24, parseIp('192.0.2.99')), true)
  assert.equal(cidrMatch(['192.0.2.0/24'], 24, parseIp('192.0.3.1')), false)
  assert.equal(cidrMatch(['192.0.2.0'], 24, parseIp('2001:db8::1')), false)
  assert.equal(cidrMatch(['192.0.2.0/24'], 25, parseIp('192.0.2.200')), false)
})

// ════════════════════════════════════════════════════════════════════════
// 3. SPF 单元
// ════════════════════════════════════════════════════════════════════════

function spf(zone, overrides = {}) {
  return checkHost(
    zoneSnapshot(zone),
    overrides.ip ?? '192.0.2.10',
    overrides.domain ?? 'example.com',
    overrides.helo ?? 'mail.example.com',
    { local: overrides.local, sender: overrides.sender },
  )
}

test('spf: 单标签域名 -> none', () => {
  assert.equal(spf({}, { domain: 'localhost' }).result, 'none')
})

test('spf: 域名字面量 -> none', () => {
  assert.equal(spf({}, { domain: '[192.0.2.1]' }).result, 'none')
})

test('spf: 没有 v=spf1 记录 -> none', () => {
  const result = spf({ 'example.com': { TXT: ['v=other1'] } })
  assert.equal(result.result, 'none')
  assert.ok(result.evidence_ref.includes('RFC7208#4.5'))
})

test('spf: 多条 v=spf1 TXT -> permerror', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 -all', 'v=spf1 +all'] } })
  assert.equal(result.result, 'permerror')
})

test('spf: 非 ASCII 记录 -> permerror', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 -all 中文'] } })
  assert.equal(result.result, 'permerror')
})

test('spf: -all -> fail', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 -all'] } })
  assert.equal(result.result, 'fail')
  assert.equal(result.mechanism, '-all')
})

test('spf: ~all -> softfail', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1 ~all'] } }).result, 'softfail')
})

test('spf: ?all -> neutral', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1 ?all'] } }).result, 'neutral')
})

test('spf: +all -> pass', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1 +all'] } }).result, 'pass')
})

test('spf: 没有机制也没有 redirect -> neutral', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1'] } }).result, 'neutral')
})

test('spf: ip4 命中 -> pass', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 ip4:192.0.2.10 -all'] } })
  assert.equal(result.result, 'pass')
})

test('spf: ip4 CIDR 不命中 -> 落到 -all', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/28 -all'] } }, { ip: '192.0.2.100' })
  assert.equal(result.result, 'fail')
})

test('spf: a 机制按 A 记录命中', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 a -all'], A: ['192.0.2.10'] },
  })
  assert.equal(result.result, 'pass')
})

test('spf: mx 机制按 MX 交换机的 A 记录命中', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 mx -all'], MX: ['10 mail.example.com'] },
    'mail.example.com': { A: ['192.0.2.10'] },
  })
  assert.equal(result.result, 'pass')
})

test('spf: exists 机制只看 A 记录', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 exists:probe.example.com -all'] },
    'probe.example.com': { A: ['203.0.113.9'] },
  })
  assert.equal(result.result, 'pass')
})

test('spf: include 子记录 pass -> 命中', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 include:_spf.example.net -all'] },
    '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.10 -all'] },
  })
  assert.equal(result.result, 'pass')
})

test('spf: include 目标没有记录 -> permerror', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 include:missing.example.net -all'] },
    'missing.example.net': { TXT: ['v=other'] },
  })
  assert.equal(result.result, 'permerror')
})

test('spf: include 指向自己 -> permerror', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 include:example.com -all'] } })
  assert.equal(result.result, 'permerror')
})

test('spf: redirect 命中子记录', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 redirect=_spf.example.net'] },
    '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.10 -all'] },
  })
  assert.equal(result.result, 'pass')
  assert.ok(result.evidence_ref.includes('RFC7208#6.1'))
})

test('spf: redirect 目标没有记录 -> permerror', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 redirect=missing.example.net'] },
    'missing.example.net': { TXT: ['v=other'] },
  })
  assert.equal(result.result, 'permerror')
})

test('spf: 未知机制 -> permerror', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1 foo:example.net -all'] } }).result, 'permerror')
})

test('spf: 常见拼写错误给出提示（prt）', () => {
  const result = spf({ 'example.com': { TXT: ['v=spf1 prt:example.net -all'] } })
  assert.equal(result.result, 'permerror')
  assert.match(result.reason, /ptr/)
})

test('spf: 逗号分隔机制 -> permerror', () => {
  assert.equal(
    spf({ 'example.com': { TXT: ['v=spf1 ip4:192.0.2.1,ip4:192.0.2.2 -all'] } }).result,
    'permerror',
  )
})

test('spf: 修饰符重复 -> permerror', () => {
  assert.equal(
    spf({ 'example.com': { TXT: ['v=spf1 redirect=a.example.net redirect=b.example.net'] } }).result,
    'permerror',
  )
})

test('spf: exp= 解释文本被取到', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 -all exp=explain.example.net'] },
    'explain.example.net': { TXT: ['%{d} says no'] },
  })
  assert.equal(result.explanations.length, 1)
  assert.equal(result.explanations[0].text, 'example.com says no')
})

test('spf: exp 里的 %{t} 被忽略并告警（零时钟）', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 -all exp=explain.example.net'] },
    'explain.example.net': { TXT: ['now %{t}'] },
  })
  assert.equal(result.explanations.length, 0)
  assert.ok(result.warnings.some((warning) => warning.includes('%{t}')))
})

test('spf: 非法宏语法 -> permerror', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1 a:%x.example.com -all'] } }).result, 'permerror')
})

test('spf: 大写宏展开后做 URL 转义', () => {
  const result = spf(
    {
      'example.com': { TXT: ['v=spf1 exists:%{L}.probe.example.com -all'] },
      'alice.probe.example.com': { A: ['203.0.113.1'] },
    },
    { sender: 'alice@example.com' },
  )
  assert.equal(result.result, 'pass')
})

test('spf: 宏的右侧 N 段变换', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 exists:%{d2}.probe.example.net -all'] },
    'example.com.probe.example.net': { A: ['203.0.113.1'] },
  })
  assert.equal(result.result, 'pass')
})

test('spf: term 超过 10 个 -> permerror + cut_point', () => {
  const terms = Array.from({ length: 11 }, (_, index) => `exists:p${index}.example.net`).join(' ')
  const zone = { 'example.com': { TXT: [`v=spf1 ${terms} -all`] } }
  for (let index = 0; index < 11; index += 1) zone[`p${index}.example.net`] = { A: [] }
  const result = spf(zone)
  assert.equal(result.result, 'permerror')
  assert.equal(result.cut_point.term_ordinal, 11)
  assert.ok(result.evidence_ref.includes('RFC7208#4.6.4'))
})

test('spf: MX 超过 10 条 -> permerror', () => {
  const mx = Array.from({ length: 11 }, (_, index) => `10 mx${index}.example.net`)
  const result = spf({ 'example.com': { TXT: ['v=spf1 mx -all'], MX: mx } })
  assert.equal(result.result, 'permerror')
})

test('spf: PTR 超过 10 条只取前 10 条并告警（不是 permerror）', () => {
  const ptrs = Array.from({ length: 12 }, (_, index) => `p${index}.example.com`)
  const zone = { '10.2.0.192.in-addr.arpa': { PTR: ptrs } }
  for (const ptr of ptrs) zone[ptr] = { A: ['192.0.2.10'] }
  zone['example.com'] = { TXT: ['v=spf1 ptr -all'] }
  const result = spf(zone)
  assert.equal(result.result, 'pass')
  assert.ok(result.warnings.some((warning) => warning.includes('只取前 10 条')))
})

test('spf: void 超过 2 次 -> undecidable（SHOULD 级，不折叠成 fail）', () => {
  const result = spf({
    'example.com': {
      TXT: ['v=spf1 a:v1.example.net a:v2.example.net a:v3.example.net a:v4.example.net -all'],
    },
    'v1.example.net': { A: ['203.0.113.1'] },
    'v2.example.net': { A: [] },
    'v3.example.net': { A: [] },
    'v4.example.net': { A: [] },
  })
  assert.equal(result.result, 'undecidable')
  assert.ok(result.gray_areas.some((item) => item.includes('SHOULD')))
})

test('spf: 快照缺键 -> undecidable + data_gap', () => {
  const result = checkHost(snapshotOf(), '192.0.2.10', 'example.com', null)
  assert.equal(result.result, 'undecidable')
  assert.deepEqual(result.data_gap, ['example.com', 'TXT'])
})

test('spf: include 树完整展开并填子结果', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 include:_spf.example.net -all'] },
    '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.10 -all'] },
  })
  assert.equal(result.tree.node_id, 'n0')
  assert.equal(result.tree.children.length, 1)
  assert.equal(result.tree.children[0].node_id, 'n1')
  assert.equal(result.tree.children[0].child_result, 'pass')
  assert.equal(result.tree.children[0].terminates_parent, true)
})

test('spf: 预算账本逐格可读', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 include:_spf.example.net -all'] },
    '_spf.example.net': { TXT: ['v=spf1 ip4:192.0.2.10 -all'] },
  })
  assert.equal(result.budget.terms.used, 1)
  assert.ok(result.budget_entries.some((entry) => entry.kind === 'depth'))
  assert.equal(result.limit_hit, false)
})

test('spf: 多个空格不产生空 token', () => {
  assert.equal(spf({ 'example.com': { TXT: ['v=spf1  -all'] } }).result, 'fail')
})

test('spf: Budget.observe 记录观测值而不是次数', () => {
  const budget = new Budget()
  budget.observe('mx', 3, 'n0')
  budget.observe('mx', 2, 'n0')
  assert.equal(budget.cells.mx.used, 3)
  assert.equal(budget.observe('mx', 11, 'n0'), false)
  assert.equal(budget.limitHit, true)
})

test('spf: 自定义 Budget 与 trace 可复用', () => {
  const budget = new Budget()
  const trace = []
  const snapshot = zoneSnapshot({ 'example.com': { TXT: ['v=spf1 -all'] } })
  checkHost(snapshot, '192.0.2.10', 'example.com', null, { budget, trace })
  assert.ok(budget.entries.length > 0)
  assert.ok(trace.some((note) => note.node === 'n0'))
})

// ════════════════════════════════════════════════════════════════════════
// 4. DKIM 上游 fixture（逐 expected 键）
// ════════════════════════════════════════════════════════════════════════

// 33 条 fixture 断言逐条显式声明；断言逻辑集中在 assertDkimKey。
function assertDkimKey(name, key, want) {
  assert.deepEqual(fixtureActual('dkim', name)[key], want)
}

test('dkim fixture d1-body-modified: dkim.bh_matches', () => assertDkimKey("d1-body-modified", "dkim.bh_matches", false));
test('dkim fixture d1-body-modified: dkim.key_status', () => assertDkimKey("d1-body-modified", "dkim.key_status", "ok"));
test('dkim fixture d1-body-modified: dkim.result', () => assertDkimKey("d1-body-modified", "dkim.result", "fail"));
test('dkim fixture d2-header-modified: dkim.bh_matches', () => assertDkimKey("d2-header-modified", "dkim.bh_matches", true));
test('dkim fixture d2-header-modified: dkim.failure_at.kind', () => assertDkimKey("d2-header-modified", "dkim.failure_at.kind", "header_hash"));
test('dkim fixture d2-header-modified: dkim.key_status', () => assertDkimKey("d2-header-modified", "dkim.key_status", "ok"));
test('dkim fixture d2-header-modified: dkim.result', () => assertDkimKey("d2-header-modified", "dkim.result", "fail"));
test('dkim fixture d3-length-truncated: dkim.bh_matches', () => assertDkimKey("d3-length-truncated", "dkim.bh_matches", true));
test('dkim fixture d3-length-truncated: dkim.key_status', () => assertDkimKey("d3-length-truncated", "dkim.key_status", "ok"));
test('dkim fixture d3-length-truncated: dkim.result', () => assertDkimKey("d3-length-truncated", "dkim.result", "pass"));
test('dkim fixture d3b-length-exceeds-body: dkim.failure_at.kind', () => assertDkimKey("d3b-length-exceeds-body", "dkim.failure_at.kind", "length_exceeds_body"));
test('dkim fixture d3b-length-exceeds-body: dkim.result', () => assertDkimKey("d3b-length-exceeds-body", "dkim.result", "permerror"));
test('dkim fixture d4a-key-not-queried: dkim.data_gap', () => assertDkimKey("d4a-key-not-queried", "dkim.data_gap", ["sel20261021._domainkey.example.com", "TXT"]));
test('dkim fixture d4a-key-not-queried: dkim.key_status', () => assertDkimKey("d4a-key-not-queried", "dkim.key_status", "missing"));
test('dkim fixture d4a-key-not-queried: dkim.result', () => assertDkimKey("d4a-key-not-queried", "dkim.result", "undecidable"));
test('dkim fixture d4b-key-nxdomain: dkim.data_gap', () => assertDkimKey("d4b-key-nxdomain", "dkim.data_gap", null));
test('dkim fixture d4b-key-nxdomain: dkim.key_status', () => assertDkimKey("d4b-key-nxdomain", "dkim.key_status", "missing"));
test('dkim fixture d4b-key-nxdomain: dkim.result', () => assertDkimKey("d4b-key-nxdomain", "dkim.result", "permerror"));
test('dkim fixture d5-key-weak-512: dkim.key_bits', () => assertDkimKey("d5-key-weak-512", "dkim.key_bits", 512));
test('dkim fixture d5-key-weak-512: dkim.key_status', () => assertDkimKey("d5-key-weak-512", "dkim.key_status", "weak"));
test('dkim fixture d5-key-weak-512: dkim.result', () => assertDkimKey("d5-key-weak-512", "dkim.result", "fail"));
test('dkim fixture d6-valid: dkim.bh_matches', () => assertDkimKey("d6-valid", "dkim.bh_matches", true));
test('dkim fixture d6-valid: dkim.failure_at', () => assertDkimKey("d6-valid", "dkim.failure_at", null));
test('dkim fixture d6-valid: dkim.key_bits', () => assertDkimKey("d6-valid", "dkim.key_bits", 2048));
test('dkim fixture d6-valid: dkim.key_status', () => assertDkimKey("d6-valid", "dkim.key_status", "ok"));
test('dkim fixture d6-valid: dkim.result', () => assertDkimKey("d6-valid", "dkim.result", "pass"));
test('dkim fixture d7-multi-signature: dkim.result[0]', () => assertDkimKey("d7-multi-signature", "dkim.result[0]", "fail"));
test('dkim fixture d7-multi-signature: dkim.result[1]', () => assertDkimKey("d7-multi-signature", "dkim.result[1]", "pass"));
test('dkim fixture d7-multi-signature: dkim.signatures_total', () => assertDkimKey("d7-multi-signature", "dkim.signatures_total", 2));
test('dkim fixture d8-unsigned: dkim.result', () => assertDkimKey("d8-unsigned", "dkim.result", "none"));
test('dkim fixture d8-unsigned: dkim.signatures_total', () => assertDkimKey("d8-unsigned", "dkim.signatures_total", 0));
test('dkim fixture d9-missing-tag: dkim.failure_at.kind', () => assertDkimKey("d9-missing-tag", "dkim.failure_at.kind", "missing_tag"));
test('dkim fixture d9-missing-tag: dkim.result', () => assertDkimKey("d9-missing-tag", "dkim.result", "permerror"));

// ── DKIM 单元 ───────────────────────────────────────────────────────────

test('dkim: simple 头规范化原样保留', () => {
  const out = canonicalizeHeader(Buffer.from('X-Test'), Buffer.from(' a  b '), 'simple')
  assert.equal(out.toString('latin1'), 'X-Test: a  b \r\n')
})

test('dkim: relaxed 头规范化（小写 / 展开 / 压空白 / 去首尾）', () => {
  const out = canonicalizeHeader(Buffer.from('X-Test'), Buffer.from(' a \r\n\t b '), 'relaxed')
  assert.equal(out.toString('latin1'), 'x-test:a b\r\n')
})

test('dkim: simple 空正文规范化为单个 CRLF', () => {
  assert.equal(canonicalizeBody(Buffer.alloc(0), 'simple').toString('latin1'), '\r\n')
})

test('dkim: relaxed 空正文规范化为零字节（RFC 6376 §3.4.4 null input）', () => {
  assert.equal(canonicalizeBody(Buffer.alloc(0), 'relaxed').length, 0)
})

test('dkim: relaxed 正文删行尾空白并压行内空白', () => {
  const out = canonicalizeBody(Buffer.from('a  b  \r\n\r\n\r\n'), 'relaxed').toString('latin1')
  assert.equal(out, 'a b\r\n')
})

test('dkim: simple 正文忽略末尾空行并补一个 CRLF', () => {
  const out = canonicalizeBody(Buffer.from('a\r\n\r\n\r\n'), 'simple').toString('latin1')
  assert.equal(out, 'a\r\n')
})

test('dkim: 标签列表允许尾分号，拒绝重复标签', () => {
  assert.deepEqual(parseTagList(Buffer.from('v=1; a=rsa-sha256;'), 't'), { v: '1', a: 'rsa-sha256' })
  assert.throws(() => parseTagList(Buffer.from('v=1; v=1'), 't'), TagError)
})

test('dkim: 标签列表拒绝缺等号与连续分号', () => {
  assert.throws(() => parseTagList(Buffer.from('v=1; bad'), 't'), TagError)
  assert.throws(() => parseTagList(Buffer.from('v=1;;a=b'), 't'), TagError)
})

test('dkim: 报文折行头保留原始字节', () => {
  const message = parseMessage(Buffer.from('A: 1\r\n\t2\r\nB: 3\r\n\r\nbody', 'latin1'))
  assert.equal(message.fields.length, 2)
  assert.equal(message.fields[0].value.toString('latin1'), ' 1\r\n\t2')
  assert.equal(message.body.toString('latin1'), 'body')
})

test('dkim: 头行缺冒号 -> 报错而不是静默丢弃', () => {
  assert.throws(() => parseMessage(Buffer.from('no-colon\r\n\r\nbody', 'latin1')), /缺冒号/)
})

test('dkim: bodyCrlf 只改行终止符', () => {
  assert.equal(bodyCrlf(Buffer.from('a\nb\n', 'latin1')).toString('latin1'), 'a\r\nb\r\n')
})

test('dkim: 摘要文本包含签名条数与结果分布', () => {
  const dkim = loadFixture('dkim', 'd7-multi-signature').dkim
  assert.match(dkimSummary(dkim), /2 条签名/)
})

function mutateSignature(family, name, replacer) {
  const fixture = loadFixture(family, name)
  const raw = fixture.raw.toString('latin1')
  const mutated = replacer(raw)
  assert.notEqual(mutated, raw, '变异必须真的改到字节')
  return verifyMessage(parseMessage(Buffer.from(mutated, 'latin1')), fixture.snapshot)
}

test('dkim: a=ed25519-sha256 -> undecidable（不支持，不判 fail）', () => {
  const result = mutateSignature('dkim', 'd6-valid', (raw) => raw.replace('a=rsa-sha256', 'a=ed25519-sha256'))
  assert.equal(result.signatures[0].result, 'undecidable')
})

test('dkim: a=rsa-sha1 -> permerror（RFC 8301 §3.1）', () => {
  const result = mutateSignature('dkim', 'd6-valid', (raw) => raw.replace('a=rsa-sha256', 'a=rsa-sha1'))
  assert.equal(result.signatures[0].result, 'permerror')
})

test('dkim: v=2 -> permerror', () => {
  const result = mutateSignature('dkim', 'd6-valid', (raw) =>
    raw.replace('DKIM-Signature:v=1', 'DKIM-Signature:v=2'),
  )
  assert.equal(result.signatures[0].result, 'permerror')
})

test('dkim: h= 未含 From -> permerror', () => {
  const result = mutateSignature('dkim', 'd6-valid', (raw) =>
    raw.replace('h=from:to:subject:date', 'h=to:subject:date'),
  )
  assert.equal(result.signatures[0].result, 'permerror')
  assert.equal(result.signatures[0].failure_at.kind, 'from_not_signed')
})

test('dkim: i= 不在 d= 之下 -> permerror', () => {
  const result = mutateSignature('dkim', 'd6-valid', (raw) =>
    raw.replace('i=@example.com', 'i=@other.example'),
  )
  assert.equal(result.signatures[0].result, 'permerror')
  assert.equal(result.signatures[0].failure_at.kind, 'domain_mismatch')
})

test('dkim: 密钥 p= 为空 -> revoked（permerror）', () => {
  const fixture = loadFixture('dkim', 'd6-valid')
  const snapshot = Snapshot.fromObject({
    ...fixture.snapshot.data,
    queries: [dns('sel20261021._domainkey.example.com', 'TXT', ['v=DKIM1; k=rsa; p='])],
  })
  const result = verifyMessage(fixture.message, snapshot)
  assert.equal(result.signatures[0].result, 'permerror')
  assert.equal(result.signatures[0].key_status, 'revoked')
})

test('dkim: 密钥 k=ed25519 -> invalid', () => {
  const fixture = loadFixture('dkim', 'd6-valid')
  const snapshot = Snapshot.fromObject({
    ...fixture.snapshot.data,
    queries: [dns('sel20261021._domainkey.example.com', 'TXT', ['v=DKIM1; k=ed25519; p=AAAA'])],
  })
  const result = verifyMessage(fixture.message, snapshot)
  assert.equal(result.signatures[0].key_status, 'invalid')
})

test('dkim: 密钥 h=sha1 排除 sha256 -> invalid', () => {
  const fixture = loadFixture('dkim', 'd6-valid')
  const p = fixture.snapshot.data.queries[0].answer[0].split('p=')[1].split(';')[0]
  const snapshot = Snapshot.fromObject({
    ...fixture.snapshot.data,
    queries: [dns('sel20261021._domainkey.example.com', 'TXT', [`v=DKIM1; h=sha1; p=${p}`])],
  })
  const result = verifyMessage(fixture.message, snapshot)
  assert.equal(result.signatures[0].key_status, 'invalid')
})

test('dkim: 密钥 s= 不含 email -> invalid', () => {
  const fixture = loadFixture('dkim', 'd6-valid')
  const p = fixture.snapshot.data.queries[0].answer[0].split('p=')[1].split(';')[0]
  const snapshot = Snapshot.fromObject({
    ...fixture.snapshot.data,
    queries: [dns('sel20261021._domainkey.example.com', 'TXT', [`v=DKIM1; s=other; p=${p}`])],
  })
  const result = verifyMessage(fixture.message, snapshot)
  assert.equal(result.signatures[0].key_status, 'invalid')
})

test('dkim: 密钥缺 p= -> invalid', () => {
  const fixture = loadFixture('dkim', 'd6-valid')
  const snapshot = Snapshot.fromObject({
    ...fixture.snapshot.data,
    queries: [dns('sel20261021._domainkey.example.com', 'TXT', ['v=DKIM1; k=rsa'])],
  })
  const result = verifyMessage(fixture.message, snapshot)
  assert.equal(result.signatures[0].key_status, 'invalid')
})

// ════════════════════════════════════════════════════════════════════════
// 5. DMARC 上游 fixture（逐 expected 键）
// ════════════════════════════════════════════════════════════════════════

// 68 条 fixture 断言逐条显式声明；warning_contains.* 走子串断言，其余逐值断言。
function assertDmarcKey(name, key, want) {
  if (key.startsWith('dmarc.warning_contains.')) {
    const dmarc = loadFixture('dmarc', name).dmarc
    assert.ok(
      dmarc.warnings.some((warning) => warning.includes(want)),
      `应有一条 warning 含 <${key}: ${want}>，实得 ${JSON.stringify(dmarc.warnings)}`,
    )
    return
  }
  assert.deepEqual(fixtureActual('dmarc', name)[key], want)
}

test('dmarc fixture b41: dmarc.author_domain', () => assertDmarcKey("b41", "dmarc.author_domain", "example.com"));
test('dmarc fixture b41: dmarc.disposition', () => assertDmarcKey("b41", "dmarc.disposition", null));
test('dmarc fixture b41: dmarc.disposition_status', () => assertDmarcKey("b41", "dmarc.disposition_status", "not_applicable"));
test('dmarc fixture b41: dmarc.dkim_align.relaxed', () => assertDmarcKey("b41", "dmarc.dkim_align.relaxed", true));
test('dmarc fixture b41: dmarc.dkim_align.strict', () => assertDmarcKey("b41", "dmarc.dkim_align.strict", false));
test('dmarc fixture b41: dmarc.organizational_domain', () => assertDmarcKey("b41", "dmarc.organizational_domain", "example.com"));
test('dmarc fixture b41: dmarc.result', () => assertDmarcKey("b41", "dmarc.result", "pass"));
test('dmarc fixture b41: dmarc.spf_align.relaxed', () => assertDmarcKey("b41", "dmarc.spf_align.relaxed", true));
test('dmarc fixture b41: dmarc.spf_align.strict', () => assertDmarcKey("b41", "dmarc.spf_align.strict", true));
test('dmarc fixture b41: dmarc.walk[0].qname', () => assertDmarcKey("b41", "dmarc.walk[0].qname", "_dmarc.example.com"));
test('dmarc fixture b41: dmarc.walk[0].status', () => assertDmarcKey("b41", "dmarc.walk[0].status", "record"));
test('dmarc fixture b41: dmarc.walk[1].qname', () => assertDmarcKey("b41", "dmarc.walk[1].qname", "_dmarc.com"));
test('dmarc fixture b41: dmarc.walk[1].status', () => assertDmarcKey("b41", "dmarc.walk[1].status", "nxdomain"));
test('dmarc fixture b41: dmarc.walk_queries', () => assertDmarcKey("b41", "dmarc.walk_queries", 2));
test('dmarc fixture b42: dmarc.author_domain', () => assertDmarcKey("b42", "dmarc.author_domain", "a.b.c.d.e.f.g.h.i.j.k.example.com"));
test('dmarc fixture b42: dmarc.dkim_align.relaxed', () => assertDmarcKey("b42", "dmarc.dkim_align.relaxed", true));
test('dmarc fixture b42: dmarc.organizational_domain', () => assertDmarcKey("b42", "dmarc.organizational_domain", "example.com"));
test('dmarc fixture b42: dmarc.result', () => assertDmarcKey("b42", "dmarc.result", "pass"));
test('dmarc fixture b42: dmarc.spf_align.relaxed', () => assertDmarcKey("b42", "dmarc.spf_align.relaxed", true));
test('dmarc fixture b42: dmarc.walk[0].qname', () => assertDmarcKey("b42", "dmarc.walk[0].qname", "_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com"));
test('dmarc fixture b42: dmarc.walk[0].status', () => assertDmarcKey("b42", "dmarc.walk[0].status", "nxdomain"));
test('dmarc fixture b42: dmarc.walk[1].qname', () => assertDmarcKey("b42", "dmarc.walk[1].qname", "_dmarc.g.h.i.j.k.example.com"));
test('dmarc fixture b42: dmarc.walk[1].status', () => assertDmarcKey("b42", "dmarc.walk[1].status", "nxdomain"));
test('dmarc fixture b42: dmarc.walk[6].qname', () => assertDmarcKey("b42", "dmarc.walk[6].qname", "_dmarc.example.com"));
test('dmarc fixture b42: dmarc.walk[6].status', () => assertDmarcKey("b42", "dmarc.walk[6].status", "record"));
test('dmarc fixture b42: dmarc.walk[7].qname', () => assertDmarcKey("b42", "dmarc.walk[7].qname", "_dmarc.com"));
test('dmarc fixture b42: dmarc.walk[7].status', () => assertDmarcKey("b42", "dmarc.walk[7].status", "nxdomain"));
test('dmarc fixture b42: dmarc.walk_queries', () => assertDmarcKey("b42", "dmarc.walk_queries", 8));
test('dmarc fixture b43: dmarc.author_domain', () => assertDmarcKey("b43", "dmarc.author_domain", "giant.bank.example.com"));
test('dmarc fixture b43: dmarc.dkim_align.relaxed', () => assertDmarcKey("b43", "dmarc.dkim_align.relaxed", false));
test('dmarc fixture b43: dmarc.dkim_align.strict', () => assertDmarcKey("b43", "dmarc.dkim_align.strict", false));
test('dmarc fixture b43: dmarc.organizational_domain', () => assertDmarcKey("b43", "dmarc.organizational_domain", "giant.bank.example.com"));
test('dmarc fixture b43: dmarc.policy_source', () => assertDmarcKey("b43", "dmarc.policy_source", "author"));
test('dmarc fixture b43: dmarc.psd', () => assertDmarcKey("b43", "dmarc.psd", "u"));
test('dmarc fixture b43: dmarc.result', () => assertDmarcKey("b43", "dmarc.result", "pass"));
test('dmarc fixture b43: dmarc.spf_align.relaxed', () => assertDmarcKey("b43", "dmarc.spf_align.relaxed", true));
test('dmarc fixture b43: dmarc.walk[1].psd', () => assertDmarcKey("b43", "dmarc.walk[1].psd", "y"));
test('dmarc fixture b43: dmarc.walk[1].qname', () => assertDmarcKey("b43", "dmarc.walk[1].qname", "_dmarc.bank.example.com"));
test('dmarc fixture b43: dmarc.walk_queries', () => assertDmarcKey("b43", "dmarc.walk_queries", 2));
test('dmarc fixture np: dmarc.author_domain', () => assertDmarcKey("np", "dmarc.author_domain", "nosuch.example.com"));
test('dmarc fixture np: dmarc.disposition', () => assertDmarcKey("np", "dmarc.disposition", "quarantine"));
test('dmarc fixture np: dmarc.disposition_status', () => assertDmarcKey("np", "dmarc.disposition_status", "determined"));
test('dmarc fixture np: dmarc.dkim_align.relaxed', () => assertDmarcKey("np", "dmarc.dkim_align.relaxed", false));
test('dmarc fixture np: dmarc.organizational_domain', () => assertDmarcKey("np", "dmarc.organizational_domain", "example.com"));
test('dmarc fixture np: dmarc.policy_source', () => assertDmarcKey("np", "dmarc.policy_source", "organizational"));
test('dmarc fixture np: dmarc.policy_tag', () => assertDmarcKey("np", "dmarc.policy_tag", "np"));
test('dmarc fixture np: dmarc.policy_value', () => assertDmarcKey("np", "dmarc.policy_value", "quarantine"));
test('dmarc fixture np: dmarc.result', () => assertDmarcKey("np", "dmarc.result", "fail"));
test('dmarc fixture np: dmarc.spf_align.relaxed', () => assertDmarcKey("np", "dmarc.spf_align.relaxed", false));
test('dmarc fixture np: dmarc.walk_queries', () => assertDmarcKey("np", "dmarc.walk_queries", 3));
test('dmarc fixture pct: dmarc.disposition', () => assertDmarcKey("pct", "dmarc.disposition", "reject"));
test('dmarc fixture pct: dmarc.disposition_status', () => assertDmarcKey("pct", "dmarc.disposition_status", "determined"));
test('dmarc fixture pct: dmarc.policy_tag', () => assertDmarcKey("pct", "dmarc.policy_tag", "p"));
test('dmarc fixture pct: dmarc.policy_value', () => assertDmarcKey("pct", "dmarc.policy_value", "reject"));
test('dmarc fixture pct: dmarc.result', () => assertDmarcKey("pct", "dmarc.result", "fail"));
test('dmarc fixture pct: dmarc.warning_contains.pct', () => assertDmarcKey("pct", "dmarc.warning_contains.pct", "已被 RFC 9989 删除"));
test('dmarc fixture pct: dmarc.warning_contains.rf', () => assertDmarcKey("pct", "dmarc.warning_contains.rf", "已被 RFC 9989 删除"));
test('dmarc fixture pct: dmarc.warning_contains.ri', () => assertDmarcKey("pct", "dmarc.warning_contains.ri", "已被 RFC 9989 删除"));
test('dmarc fixture psd-n: dmarc.author_domain', () => assertDmarcKey("psd-n", "dmarc.author_domain", "dept.mail.example.com"));
test('dmarc fixture psd-n: dmarc.organizational_domain', () => assertDmarcKey("psd-n", "dmarc.organizational_domain", "mail.example.com"));
test('dmarc fixture psd-n: dmarc.policy_source', () => assertDmarcKey("psd-n", "dmarc.policy_source", "organizational"));
test('dmarc fixture psd-n: dmarc.psd', () => assertDmarcKey("psd-n", "dmarc.psd", "n"));
test('dmarc fixture psd-n: dmarc.result', () => assertDmarcKey("psd-n", "dmarc.result", "pass"));
test('dmarc fixture psd-n: dmarc.spf_align.relaxed', () => assertDmarcKey("psd-n", "dmarc.spf_align.relaxed", true));
test('dmarc fixture psd-n: dmarc.walk[1].psd', () => assertDmarcKey("psd-n", "dmarc.walk[1].psd", "n"));
test('dmarc fixture psd-n: dmarc.walk[1].qname', () => assertDmarcKey("psd-n", "dmarc.walk[1].qname", "_dmarc.mail.example.com"));
test('dmarc fixture psd-n: dmarc.walk[1].status', () => assertDmarcKey("psd-n", "dmarc.walk[1].status", "record"));
test('dmarc fixture psd-n: dmarc.walk_queries', () => assertDmarcKey("psd-n", "dmarc.walk_queries", 2));

// ── DMARC 单元 ──────────────────────────────────────────────────────────

test('dmarc: v= 必须是第一个标签', () => {
  assert.equal(parseRecord('p=none; v=DMARC1'), null)
  assert.equal(parseRecord('v=DMARC1; p=none').tags.p, 'none')
})

test('dmarc: v=DMARC1 大小写敏感', () => {
  assert.equal(parseRecord('v=dmarc1; p=none'), null)
})

test('dmarc: 坏片段进 malformed 而记录仍有效（§4.8 从宽）', () => {
  const record = parseRecord('v=DMARC1; p=none; ; sp=reject')
  assert.ok(record)
  assert.equal(record.tags.sp, 'reject')
  assert.ok(record.malformed.some((item) => item.includes('空标签')))
})

test('dmarc: 重复标签保留首次出现值并记录 malformed', () => {
  const record = parseRecord('v=DMARC1; p=reject; p=none')
  assert.equal(record.tags.p, 'reject')
  assert.ok(record.malformed.some((item) => item.includes('重复')))
})

test('dmarc: 少于 8 个标签删最左一个', () => {
  assert.equal(shortenDomain('a.b.c'), 'b.c')
  assert.equal(shortenDomain('com'), null)
})

test('dmarc: 8 个及以上标签跳到只剩 7 个', () => {
  assert.equal(shortenDomain('a.b.c.d.e.f.g.h.i'), 'c.d.e.f.g.h.i')
})

test('dmarc: Organizational Domain 取 psd=n 的记录域', () => {
  const resultWalk = {
    start: 'dept.a.example.com',
    hops: [
      { index: 0, domain: 'dept.a.example.com', status: 'no_record', psd: null },
      { index: 1, domain: 'a.example.com', status: 'record', psd: 'n' },
      { index: 2, domain: 'example.com', status: 'record', psd: 'u' },
    ],
    stopped_by: 'psd',
  }
  assert.equal(selectOrganizationalDomain(resultWalk), 'a.example.com')
})

test('dmarc: Organizational Domain 在 psd=y 时取其下一层', () => {
  const resultWalk = {
    start: 'giant.bank.example.com',
    hops: [
      { index: 0, domain: 'giant.bank.example.com', status: 'no_record', psd: null },
      { index: 1, domain: 'bank.example.com', status: 'record', psd: 'y' },
    ],
    stopped_by: 'psd',
  }
  assert.equal(selectOrganizationalDomain(resultWalk), 'giant.bank.example.com')
})

test('dmarc: Organizational Domain 无特殊标记时取标签最少的那条', () => {
  const resultWalk = {
    start: 'signing.example.com',
    hops: [
      { index: 0, domain: 'signing.example.com', status: 'record', psd: 'u' },
      { index: 1, domain: 'example.com', status: 'record', psd: 'u' },
    ],
    stopped_by: 'labels_exhausted',
  }
  assert.equal(selectOrganizationalDomain(resultWalk), 'example.com')
})

test('dmarc: walk 在 psd= 出现时停下', () => {
  const snapshot = snapshotOf(
    dns('_dmarc.a.example.com', 'TXT', ['v=DMARC1; p=reject; psd=n']),
    dns('_dmarc.example.com', 'TXT', ['v=DMARC1; p=none']),
  )
  const resultWalk = walk(snapshot, 'a.example.com')
  assert.equal(resultWalk.hops.length, 1)
  assert.equal(resultWalk.stopped_by, 'psd')
})

test('dmarc: walk 同一目标多条记录 -> multiple_records', () => {
  const snapshot = snapshotOf(
    dns('_dmarc.example.com', 'TXT', ['v=DMARC1; p=none', 'v=DMARC1; p=reject']),
    dns('_dmarc.com', 'TXT', [], 'NXDOMAIN'),
  )
  assert.equal(walk(snapshot, 'example.com').hops[0].status, 'multiple_records')
})

test('dmarc: walk 有 TXT 但 v= 不合格 -> invalid_record', () => {
  const snapshot = snapshotOf(
    dns('_dmarc.example.com', 'TXT', ['v=spf1 -all']),
    dns('_dmarc.com', 'TXT', [], 'NXDOMAIN'),
  )
  assert.equal(walk(snapshot, 'example.com').hops[0].status, 'invalid_record')
})

test('dmarc: walk DNS 错误 -> dns_error（不能判 pass/fail）', () => {
  const snapshot = snapshotOf(dns('_dmarc.example.com', 'TXT', [], 'SERVFAIL'))
  assert.equal(walk(snapshot, 'example.com').hops[0].status, 'dns_error')
})

test('dmarc: walk 未查询 -> not_queried（数据缺口）', () => {
  assert.equal(walk(snapshotOf(), 'example.com').hops[0].status, 'not_queried')
})

test('dmarc: From 角度地址提取', () => {
  const message = parseMessage(Buffer.from('From: Alice <alice@example.com>\r\n\r\nbody', 'latin1'))
  assert.deepEqual(fromDomains(message).domains, ['example.com'])
})

test('dmarc: From 裸地址提取', () => {
  const message = parseMessage(Buffer.from('From: alice@example.com\r\n\r\nbody', 'latin1'))
  assert.deepEqual(fromDomains(message).domains, ['example.com'])
})

test('dmarc: From 多个域 -> 判定不成立', () => {
  const message = parseMessage(
    Buffer.from('From: a@one.example.com, b@two.example.net\r\n\r\nbody', 'latin1'),
  )
  assert.equal(fromDomains(message).domains.length, 2)
  assert.ok(fromDomains(message).notes.some((note) => note.includes('2 个不同的域')))
})

test('dmarc: From 缺失 -> 空域列表 + 说明', () => {
  const message = parseMessage(Buffer.from('Subject: x\r\n\r\nbody', 'latin1'))
  assert.deepEqual(fromDomains(message).domains, [])
})

test('dmarc: 对齐双算（strict 只认同名）', () => {
  const snapshot = snapshotOf(
    dns('_dmarc.example.com', 'TXT', ['v=DMARC1; p=none']),
    dns('_dmarc.com', 'TXT', [], 'NXDOMAIN'),
    dns('_dmarc.example.net', 'TXT', ['v=DMARC1; p=none']),
    dns('_dmarc.net', 'TXT', [], 'NXDOMAIN'),
  )
  const cache = new Map()
  const same = align('example.com', 'example.com', 'example.com', 'spf', cache, snapshot, null)
  assert.equal(same.strict, true)
  assert.equal(same.relaxed, true)
  const sibling = align('a.example.com', 'example.com', 'b.example.com', 'dkim', cache, snapshot, null)
  assert.equal(sibling.strict, false)
  assert.equal(sibling.relaxed, true)
})

test('dmarc: p= 缺失按 p=none 处理（不是判不了）', () => {
  const result = fixtureLikeDmarc('v=DMARC1; sp=reject', { spfResult: 'fail', dkimDomain: 'other.example.net' })
  assert.equal(result.result, 'fail')
  assert.equal(result.disposition, 'none')
  assert.ok(result.warnings.some((warning) => warning.includes('按 p=none 处理')))
})

test('dmarc: t=y 把 reject 降级为 quarantine', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=reject; t=y', { spfResult: 'fail', dkimDomain: 'other.example.net' })
  assert.equal(result.disposition, 'quarantine')
  assert.equal(result.test_mode, true)
})

test('dmarc: 非法 p 且 rua 有效 -> 按 p=none 继续', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=bogus; rua=mailto:dmarc@example.com', {
    spfResult: 'fail',
    dkimDomain: 'other.example.net',
  })
  assert.equal(result.disposition, 'none')
  assert.equal(result.disposition_status, 'determined')
})

test('dmarc: 非法 p 且没有 rua -> not_applicable（不施加处理）', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=bogus', { spfResult: 'fail', dkimDomain: 'other.example.net' })
  assert.equal(result.disposition, null)
  assert.equal(result.disposition_status, 'not_applicable')
})

test('dmarc: adkim=s 不认同 Organizational Domain 的对齐', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=reject; adkim=s', {
    spfResult: 'fail',
    dkimDomain: 'mail.example.com',
  })
  assert.equal(result.dkim_align.relaxed, true)
  assert.equal(result.dkim_align.strict, false)
  assert.equal(result.result, 'fail')
})

function fixtureLikeDmarc(recordText, options = {}) {
  const snapshot = snapshotOf(
    dns('_dmarc.example.com', 'TXT', [recordText]),
    dns('_dmarc.com', 'TXT', [], 'NXDOMAIN'),
    dns('_dmarc.example.net', 'TXT', ['v=DMARC1; p=none']),
    dns('_dmarc.net', 'TXT', [], 'NXDOMAIN'),
  )
  const message = parseMessage(
    Buffer.from('From: Alice <alice@example.com>\r\nDKIM-Signature: x\r\n\r\nbody', 'latin1'),
  )
  const spf = {
    result: options.spfResult ?? 'pass',
    reason: 'test',
    domain: 'example.com',
    record: 'v=spf1 -all',
    evidence_ref: [],
    warnings: [],
    gray_areas: [],
    data_gap: null,
  }
  const dkim = {
    signatures: [
      {
        index: 0,
        selector: 's',
        domain: options.dkimDomain ?? 'example.com',
        identity: '@example.com',
        algorithm: 'rsa-sha256',
        canonicalization: 'relaxed/relaxed',
        bh_matches: true,
        failure_at: null,
        key_bits: 2048,
        key_status: 'ok',
        result: 'pass',
        reason: 'test',
        evidence_ref: [],
        trace: [],
        warnings: [],
        data_gap: null,
      },
    ],
    message_has_signatures: true,
    trace: [],
    warnings: [],
    data_gaps: [],
  }
  return dmarcEvaluate(
    snapshot,
    message,
    { mail_from: 'alice@example.com', helo: 'mail.example.com' },
    spf,
    dkim,
  )
}

// ════════════════════════════════════════════════════════════════════════
// 6. PSL
// ════════════════════════════════════════════════════════════════════════

test('psl: 冻结件版本与日期非空', () => {
  assert.ok(pslVersion().length > 0)
  assert.match(pslDate(), /^\d{4}-\d{2}-\d{2}$/)
})

test('psl: 规则数 > 10000（完整冻结件而不是子集）', () => {
  assert.ok(pslRuleCount() > 10000)
})

test('psl: example.com 的注册域是自身', () => {
  assert.equal(organizationalDomain('example.com'), 'example.com')
})

test('psl: 公共后缀本身没有注册域', () => {
  assert.equal(organizationalDomain('com'), null)
  assert.equal(organizationalDomain('co.uk'), null)
})

test('psl: 多段后缀 co.uk', () => {
  assert.equal(organizationalDomain('www.example.co.uk'), 'example.co.uk')
})

test('psl: 通配规则 *.ck', () => {
  assert.equal(organizationalDomain('a.foo.ck'), 'a.foo.ck')
  assert.equal(pslAnalysis('a.foo.ck').rule.kind, 'wildcard')
})

test('psl: 例外规则 !www.ck', () => {
  assert.equal(organizationalDomain('www.ck'), 'www.ck')
})

test('psl: private 段（blogspot.com）', () => {
  assert.equal(organizationalDomain('x.blogspot.com'), 'x.blogspot.com')
})

test('psl: 默认规则对未知 TLD 生效', () => {
  assert.equal(organizationalDomain('a.example.invalidtld'), 'example.invalidtld')
  assert.equal(pslAnalysis('a.example.invalidtld').rule.kind, 'default')
})

test('psl: analysis 给出公共后缀与命中规则', () => {
  const analysis = pslAnalysis('signing.example.com')
  assert.equal(analysis.public_suffix, 'com')
  assert.equal(analysis.organizational_domain, 'example.com')
  assert.equal(analysis.rule.kind, 'normal')
})

// ════════════════════════════════════════════════════════════════════════
// 7. 三方对账
// ════════════════════════════════════════════════════════════════════════

function arMessage(header, from = 'alice@example.com') {
  return parseMessage(
    Buffer.from(`From: ${from}\r\nAuthentication-Results: ${header}\r\n\r\nbody`, 'latin1'),
  )
}

function stubResults() {
  const spf = { result: 'pass', reason: 'x', evidence_ref: [] }
  const dkim = {
    signatures: [
      { index: 0, selector: 's', domain: 'example.com', result: 'pass', failure_at: null, data_gap: null },
    ],
  }
  const dmarc = { result: 'pass', author_domain: 'example.com' }
  return { spf, dkim, dmarc }
}

test('reconcile: 解析 authserv-id 与版本号', () => {
  const claims = parseAuthenticationResults(arMessage('mx.example.com 1; spf=pass'))
  assert.equal(claims[0].authserv_id, 'mx.example.com')
  assert.equal(claims[0].authserv_version, '1')
  assert.equal(claims[0].method, 'spf')
})

test('reconcile: 显式 none 不是一条 method 声明', () => {
  const claims = parseAuthenticationResults(arMessage('mx.example.com; none'))
  assert.equal(claims[0].method, '*')
  assert.ok(claims[0].parse_note)
})

test('reconcile: 非法 authserv-id -> 不可解析（fail-closed）', () => {
  const claims = parseAuthenticationResults(arMessage('mx example.com; spf=pass'))
  assert.ok(claims[0].parse_note)
})

test('reconcile: 空可信列表 -> 每条声称 undecidable', () => {
  const { spf, dkim, dmarc } = stubResults()
  const result = reconcileEvaluate(arMessage('mx.example.com; spf=pass'), spf, dkim, dmarc, [])
  assert.equal(result.class, 'undecidable')
  assert.ok(result.notes.some((note) => note.includes('空列表不是')))
})

test('reconcile: 可信 authserv + 一致 -> consistent', () => {
  const { spf, dkim, dmarc } = stubResults()
  const result = reconcileEvaluate(arMessage('mx.example.com; spf=pass'), spf, dkim, dmarc, [
    'mx.example.com',
  ])
  assert.equal(result.class, 'consistent')
})

test('reconcile: 不一致 -> contradiction 且每条给 ≥2 条解释', () => {
  const { spf, dkim, dmarc } = stubResults()
  spf.result = 'fail'
  const result = reconcileEvaluate(arMessage('mx.example.com; spf=pass'), spf, dkim, dmarc, [
    'mx.example.com',
  ])
  assert.equal(result.class, 'contradiction')
  for (const entry of result.entries) {
    assert.ok(entry.explanations.length >= 2)
    for (const explanation of entry.explanations) {
      assert.ok(explanation.hypothesis.length > 0)
      assert.ok(explanation.verify.length > 0)
    }
  }
})

test('reconcile: dkim 按 header.d 选签名', () => {
  const { spf, dkim, dmarc } = stubResults()
  const result = reconcileEvaluate(
    arMessage('mx.example.com; dkim=pass header.d=other.example.net'),
    spf,
    dkim,
    dmarc,
    ['mx.example.com'],
  )
  assert.equal(result.class, 'undecidable')
  assert.ok(
    result.entries[0].warnings.some((warning) => warning.includes('不在本工具看到的签名集里')),
  )
})

test('reconcile: 未重算的 method -> undecidable', () => {
  const { spf, dkim, dmarc } = stubResults()
  const result = reconcileEvaluate(arMessage('mx.example.com; auth=pass'), spf, dkim, dmarc, [
    'mx.example.com',
  ])
  assert.equal(result.class, 'undecidable')
})

test('reconcile: 没有 Authentication-Results -> none', () => {
  const { spf, dkim, dmarc } = stubResults()
  const message = parseMessage(Buffer.from('From: a@example.com\r\n\r\nbody', 'latin1'))
  assert.equal(reconcileEvaluate(message, spf, dkim, dmarc, ['mx.example.com']).class, 'none')
})

test('reconcile: 解释里不出现定性词', () => {
  const { spf, dkim, dmarc } = stubResults()
  spf.result = 'fail'
  const result = reconcileEvaluate(arMessage('mx.example.com; spf=pass'), spf, dkim, dmarc, [
    'mx.example.com',
  ])
  const text = JSON.stringify(result)
  for (const word of ['攻击', '伪造', '被黑', '黑客', 'hacked', 'forged', 'attack', 'compromised']) {
    assert.equal(text.includes(word), false, `对账产物里出现禁词：${word}`)
  }
})

// ════════════════════════════════════════════════════════════════════════
// 8. 快照 schema
// ════════════════════════════════════════════════════════════════════════

test('snapshot: 合法快照可 resolve 第一次命中', () => {
  const snapshot = snapshotOf(
    dns('example.com', 'TXT', ['v=spf1 -all']),
    dns('example.com', 'TXT', ['v=spf1 +all']),
  )
  assert.equal(snapshot.resolve('example.com', 'TXT').answer[0], 'v=spf1 -all')
  assert.equal(snapshot.resolve('example.com', 'TXT').index, 0)
})

test('snapshot: occurrences 保留同键全部命中', () => {
  const snapshot = snapshotOf(dns('example.com', 'TXT', ['a']), dns('example.com', 'TXT', ['b']))
  assert.equal(snapshot.occurrences('example.com', 'TXT').length, 2)
})

test('snapshot: 没查过与查过但不存在可区分', () => {
  const snapshot = snapshotOf(dns('absent.example.com', 'TXT', [], 'NXDOMAIN'))
  assert.equal(snapshot.resolve('never.example.com', 'TXT').found, false)
  assert.equal(snapshot.resolve('absent.example.com', 'TXT').rcode, 'NXDOMAIN')
})

test('snapshot: 名字大小写与尾点归一', () => {
  const snapshot = snapshotOf(dns('Example.COM.', 'TXT', ['x']))
  assert.equal(snapshot.resolve('example.com', 'TXT').found, true)
})

test('snapshot: 缺 schema_version -> 报错', () => {
  assert.throws(() => Snapshot.fromObject({ queries: [] }), /schema_version/)
})

test('snapshot: 不支持的 schema_version -> 报错', () => {
  assert.throws(() => Snapshot.fromObject({ ...validSnapshotRaw(), schema_version: 2 }), /不支持/)
})

test('snapshot: 缺 psl_date -> 报错（灰区 3：输出必须带版本与日期）', () => {
  const raw = validSnapshotRaw()
  delete raw.psl_date
  assert.throws(() => Snapshot.fromObject(raw), /psl_date/)
})

test('snapshot: 非 NOERROR 还带 answer -> 报错', () => {
  const raw = validSnapshotRaw()
  raw.queries = [{ qname: 'a.example.com', qtype: 'TXT', rcode: 'NXDOMAIN', answer: ['x'], ttl: 1 }]
  assert.throws(() => Snapshot.fromObject(raw), /answer 必须为空/)
})

function validSnapshotRaw() {
  return {
    schema_version: 1,
    fetched_at: '2026-11-25T00:00:00Z',
    resolver: 'synthetic',
    psl_version: '2026-10-20_08-40-56_UTC',
    psl_date: '2026-10-20',
    queries: [],
  }
}

// ════════════════════════════════════════════════════════════════════════
// 9. 器官与内核契约（含 CLI 退出码）
// ════════════════════════════════════════════════════════════════════════

test('organ: list 含 email-evidence', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /email-evidence/)
})

test('organ: SPF 主张正确 -> claim', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE }]),
  )
  assert.equal(records.length, 1)
  assert.equal(records[0].verdict, CLAIM)
  assert.ok(records[0].node)
})

test('organ: SPF 主张错误 + 有节点 -> refuted', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'fail', node: NODE }]),
  )
  assert.equal(records[0].verdict, 'refuted')
  assert.equal(records[0].node.session_id, 's-1')
})

test('organ: 主张错误但无节点 -> inconclusive（不能下 refuted）', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'fail' }]),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.equal(records[0].node, null)
  assert.match(records[0].message, /不能下 refuted/)
})

test('organ: 节点不在 basis 里 -> NodeMissing 冒到 CLI', () => {
  const subject = subjectFor('dmarc', 'b41', [
    {
      claim_id: 'c1',
      check: 'spf',
      asserted: 'pass',
      node: { session_id: 's-1', turn: 99, tool_call_id: 'nope' },
    },
  ])
  assert.throws(() => runOrgan(subject), NodeMissing)
})

test('organ: 节点不完整 -> 内核降级 inconclusive 并写明缺失项', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [
      {
        claim_id: 'c2',
        check: 'spf',
        asserted: 'pass',
        node: { session_id: 's-1', tool_call_id: 'call-7' },
      },
    ]),
    Basis.fromObject({
      version: '2026.11.25',
      nodes: [{ session_id: 's-1', tool_call_id: 'call-7' }],
    }),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /痕迹节点不完整/)
  assert.match(records[0].message, /turn/)
})

test('organ: DKIM 主张正确 -> claim；错误 -> refuted', () => {
  const ok = runOrgan(
    subjectFor('dkim', 'd6-valid', [{ claim_id: 'c1', check: 'dkim', asserted: 'pass', node: NODE }]),
  )
  assert.equal(ok[0].verdict, CLAIM)
  const bad = runOrgan(
    subjectFor('dkim', 'd6-valid', [{ claim_id: 'c1', check: 'dkim', asserted: 'fail', node: NODE }]),
  )
  assert.equal(bad[0].verdict, 'refuted')
})

test('organ: DKIM 数据缺口（未查询选择器）-> inconclusive 且写明缺失项', () => {
  const records = runOrgan(
    subjectFor('dkim', 'd4a-key-not-queried', [
      { claim_id: 'c1', check: 'dkim', asserted: 'pass', node: NODE },
    ]),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /_domainkey/)
})

test('organ: DKIM signature_index 越界 -> inconclusive', () => {
  const records = runOrgan(
    subjectFor('dkim', 'd6-valid', [
      { claim_id: 'c1', check: 'dkim', asserted: 'pass', signature_index: 9, node: NODE },
    ]),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /signature_index/)
})

test('organ: DMARC 主张（含处置）正确 -> claim', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'np', [
      {
        claim_id: 'c1',
        check: 'dmarc',
        asserted: 'fail',
        asserted_disposition: 'quarantine',
        node: NODE,
      },
    ]),
  )
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: DMARC 处置不符 -> refuted', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'np', [
      {
        claim_id: 'c1',
        check: 'dmarc',
        asserted: 'fail',
        asserted_disposition: 'reject',
        node: NODE,
      },
    ]),
  )
  assert.equal(records[0].verdict, 'refuted')
  assert.match(records[0].message, /主张处置/)
})

test('organ: reconcile 主张 -> claim（注入可信 AR 头，声称与重算一致）', () => {
  const fixture = loadFixture('dmarc', 'b41')
  const injected = fixture.raw
    .toString('latin1')
    .replace('From:', 'Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\nFrom:')
  const subject = {
    snapshot: JSON.parse(JSON.stringify(fixture.snapshot.data)),
    query: fixture.delivery,
    message: injected,
    claims: [{ claim_id: 'c1', check: 'reconcile', asserted: 'consistent', node: NODE }],
  }
  const records = runOrgan(subject)
  assert.equal(records[0].verdict, CLAIM)
})

test('organ: 快照不合法 -> inconclusive（不抛穿）', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE },
  ])
  delete subject.snapshot.schema_version
  const records = runOrgan(subject)
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /快照不合法/)
})

test('organ: 投递上下文不合法 -> inconclusive', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE },
  ])
  subject.query = { mail_from: 'alice@example.com' }
  const records = runOrgan(subject)
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /query 不合法/)
})

test('organ: DKIM/DMARC 缺报文 -> inconclusive 并说明需要原始报文', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'dkim', asserted: 'pass', node: NODE },
    { claim_id: 'c2', check: 'dmarc', asserted: 'pass', node: NODE },
  ])
  delete subject.message_b64
  const records = runOrgan(subject)
  assert.equal(records.length, 2)
  for (const record of records) assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(records[0].message, /没有提供报文/)
})

test('organ: claim_id 重复 -> ContractError', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE },
    { claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE },
  ])
  assert.throws(() => runOrgan(subject), ContractError)
})

test('organ: 未知 claim 字段 -> ContractError', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE, extra: 1 },
  ])
  assert.throws(() => runOrgan(subject), /未知字段/)
})

test('organ: asserted 不在闭集 -> ContractError', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'maybe', node: NODE },
  ])
  assert.throws(() => runOrgan(subject), /asserted 非法/)
})

test('organ: 只有 dmarc 可以带 asserted_disposition', () => {
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'pass', asserted_disposition: 'reject', node: NODE },
  ])
  assert.throws(() => runOrgan(subject), /只有 dmarc/)
})

test('organ: 证据里不出现报文原文 / 邮箱地址（脱敏前置的器官侧）', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [
      { claim_id: 'c1', check: 'reconcile', asserted: 'consistent', node: NODE },
    ]),
  )
  const serialized = JSON.stringify(records)
  assert.equal(serialized.includes('alice@example.com'), false)
  assert.equal(serialized.includes('Hello Bob'), false)
  assert.equal(serialized.includes(SAMPLE), false)
})

test('organ: 证据里没有绝对路径', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE }]),
  )
  assert.equal(JSON.stringify(records).includes(UPSTREAM), false)
})

test('organ: 敏感键仍由内核脱敏（结构面）', () => {
  const record = makeRecord({
    claim_id: 'c0',
    verdict: CLAIM,
    message: 'x',
    node: makeNode({ session_id: 's-1', turn: 3, tool_call_id: 'call-7' }),
    evidence: { api_key: SAMPLE },
  })
  assert.equal(JSON.stringify(record).includes(SAMPLE), false)
})

test('organ: 同一输入两次运行账本字节一致', async () => {
  const dir = tmpDir()
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'b', check: 'dmarc', asserted: 'pass', node: NODE },
    { claim_id: 'a', check: 'spf', asserted: 'pass', node: NODE },
  ])
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'basis.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const args = [
    'check',
    'email-evidence',
    '--input',
    join(dir, 'in.json'),
    '--basis',
    join(dir, 'basis.json'),
    '--json',
  ]
  const first = await capture(() => main(args))
  const second = await capture(() => main(args))
  assert.equal(first.code, EXIT_OK)
  assert.equal(first.out, second.out)
  const payload = JSON.parse(first.out)
  assert.deepEqual(payload.records.map((record) => record.claim_id), ['a', 'b'])
})

test('cli: 全部 claim -> 退出 0', async () => {
  const dir = tmpDir()
  writeFileSync(
    join(dir, 'in.json'),
    JSON.stringify(
      subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE }]),
    ),
  )
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code, out } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /claim=1/)
})

test('cli: 存在 refuted -> 退出 1', async () => {
  const dir = tmpDir()
  writeFileSync(
    join(dir, 'in.json'),
    JSON.stringify(
      subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'fail', node: NODE }]),
    ),
  )
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_BLOCKED)
})

test('cli: 输入文件缺失 -> 退出 2', async () => {
  const dir = tmpDir()
  const { code } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'nope.json')]),
  )
  assert.equal(code, EXIT_INPUT)
})

test('cli: 缺必填字段（claims）-> 退出 2', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({ snapshot: validSnapshotRaw(), query: {} }))
  const { code, err } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json')]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /claims/)
})

test('cli: 节点缺失 -> 退出 3', async () => {
  const dir = tmpDir()
  writeFileSync(
    join(dir, 'in.json'),
    JSON.stringify(
      subjectFor('dmarc', 'b41', [
        {
          claim_id: 'c1',
          check: 'spf',
          asserted: 'pass',
          node: { session_id: 's-9', turn: 1, tool_call_id: 'x' },
        },
      ]),
    ),
  )
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code, err } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: client_ip 非法 -> 退出 2（输入不合法）', async () => {
  const dir = tmpDir()
  const subject = subjectFor('dmarc', 'b41', [
    { claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE },
  ])
  subject.query = { ...subject.query, client_ip: 'not-an-ip' }
  writeFileSync(join(dir, 'in.json'), JSON.stringify(subject))
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_INPUT)
})

test('cli: 痕迹包缺版本 -> 退出 3', async () => {
  const dir = tmpDir()
  writeFileSync(
    join(dir, 'in.json'),
    JSON.stringify(
      subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE }]),
    ),
  )
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ nodes: [NODE] }))
  const { code } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json')]),
  )
  assert.equal(code, EXIT_CONTRACT)
})

test('cli: 未知器官 -> 退出 3', async () => {
  const dir = tmpDir()
  writeFileSync(join(dir, 'in.json'), JSON.stringify({}))
  const { code } = await capture(() => main(['check', 'no-such', '--input', join(dir, 'in.json')]))
  assert.equal(code, EXIT_CONTRACT)
})

test('cli: --json 字段顺序固定且无时间戳', async () => {
  const dir = tmpDir()
  writeFileSync(
    join(dir, 'in.json'),
    JSON.stringify(
      subjectFor('dmarc', 'b41', [{ claim_id: 'c1', check: 'spf', asserted: 'pass', node: NODE }]),
    ),
  )
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { out } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json'), '--json']),
  )
  const payload = JSON.parse(out)
  assert.deepEqual(Object.keys(payload), [
    'product',
    'verb',
    'verb_version',
    'subject',
    'summary',
    'records',
  ])
  assert.equal(/20\d\d-\d\d-\d\dT/.test(out), false)
})

// ════════════════════════════════════════════════════════════════════════
// 10. 补充单元（边界与告警面）
// ════════════════════════════════════════════════════════════════════════

test('spf: ip6 机制命中', () => {
  const result = checkHost(
    zoneSnapshot({ 'example.com': { TXT: ['v=spf1 ip6:2001:db8::/32 -all'] } }),
    '2001:db8::1',
    'example.com',
    null,
  )
  assert.equal(result.result, 'pass')
})

test('spf: a 机制 dual-cidr 对 IPv6 连接生效', () => {
  const result = checkHost(
    zoneSnapshot({
      'example.com': { TXT: ['v=spf1 a:host.example.com//64 -all'] },
      'host.example.com': { AAAA: ['2001:db8::99'] },
    }),
    '2001:db8::1',
    'example.com',
    null,
  )
  assert.equal(result.result, 'pass')
})

test('spf: exists 对 IPv6 连接仍查 A 记录', () => {
  const result = checkHost(
    zoneSnapshot({
      'example.com': { TXT: ['v=spf1 exists:probe.example.com -all'] },
      'probe.example.com': { A: ['203.0.113.9'] },
    }),
    '2001:db8::1',
    'example.com',
    null,
  )
  assert.equal(result.result, 'pass')
})

test('spf: %{ir} 反向半字节宏', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 exists:%{ir}.probe.example.com -all'] },
    '10.2.0.192.probe.example.com': { A: ['203.0.113.9'] },
  })
  assert.equal(result.result, 'pass')
})

test('spf: 空发件人时 %{l} 取 postmaster', () => {
  const result = spf(
    {
      'mail.example.com': { TXT: ['v=spf1 exists:%{l}.probe.example.com -all'] },
      'postmaster.probe.example.com': { A: ['203.0.113.9'] },
    },
    { domain: 'mail.example.com', sender: '' },
  )
  assert.equal(result.result, 'pass')
})

test('spf: exp 记录不是恰好 1 条时忽略并告警', () => {
  const result = spf({
    'example.com': { TXT: ['v=spf1 -all exp=explain.example.net'] },
    'explain.example.net': { TXT: ['one', 'two'] },
  })
  assert.equal(result.explanations.length, 0)
  assert.ok(result.warnings.some((warning) => warning.includes('需恰好 1 条')))
})

test('spf: term 超限时 limit_hit 与 hits 被置位', () => {
  const terms = Array.from({ length: 11 }, (_, index) => `exists:p${index}.example.net`).join(' ')
  const zone = { 'example.com': { TXT: [`v=spf1 ${terms} -all`] } }
  for (let index = 0; index < 11; index += 1) zone[`p${index}.example.net`] = { A: [] }
  const result = spf(zone)
  assert.equal(result.limit_hit, true)
  assert.ok(result.limit_hits.includes('terms'))
})

test('dkim: l= 截断时告警“第几行起未受保护”', () => {
  const dkim = loadFixture('dkim', 'd3-length-truncated').dkim
  assert.equal(dkim.signatures[0].result, 'pass')
  assert.ok(dkim.signatures[0].warnings.some((warning) => warning.includes('未受签名保护')))
})

test('dkim: l= 非数字 -> permerror（签名语法错）', () => {
  const result = mutateSignature('dkim', 'd6-valid', (raw) =>
    raw.replace('bh=', 'l=abc; bh='),
  )
  assert.equal(result.signatures[0].result, 'permerror')
})

test('dkim: 多签名逐条独立求值（一条 fail 不掩盖另一条 pass）', () => {
  const dkim = loadFixture('dkim', 'd7-multi-signature').dkim
  assert.equal(dkim.signatures.length, 2)
  assert.equal(dkim.signatures[0].result, 'fail')
  assert.equal(dkim.signatures[1].result, 'pass')
  assert.notEqual(dkim.signatures[0].reason, dkim.signatures[1].reason)
})

test('dmarc: 未知标签进告警（§4.7 unknown tags MUST be ignored）', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=none; foo=bar')
  assert.ok(result.warnings.some((warning) => warning.includes('不在本工具已知标签内')))
})

test('dmarc: t= 非法按 n 处理并告警', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=none; t=x', {
    spfResult: 'fail',
    dkimDomain: 'other.example.net',
  })
  assert.equal(result.test_mode, false)
  assert.ok(result.warnings.some((warning) => warning.includes('只允许 y / n')))
})

test('dmarc: rua 没有合法 URI 时不兜底 p=none', () => {
  const result = fixtureLikeDmarc('v=DMARC1; p=bogus; rua=not-a-uri', {
    spfResult: 'fail',
    dkimDomain: 'other.example.net',
  })
  assert.equal(result.disposition, null)
  assert.equal(result.disposition_status, 'not_applicable')
})

test('dmarc: np= 在 Author 存在性未知且与回落策略不同处置时 -> undecidable', () => {
  const result = dmarcWith({
    record: 'v=DMARC1; p=reject; np=quarantine',
    author: 'nosuch.example.com',
    authorExistence: null,
  })
  assert.equal(result.result, 'fail')
  assert.equal(result.disposition, null)
  assert.equal(result.disposition_status, 'undecidable')
  assert.match(result.reason, /本工具不猜/)
})

test('dmarc: np= 与回落策略同处置时仍可判定', () => {
  const result = dmarcWith({
    record: 'v=DMARC1; p=reject; sp=quarantine; np=quarantine',
    author: 'nosuch.example.com',
    authorExistence: null,
  })
  assert.equal(result.disposition, 'quarantine')
  assert.equal(result.disposition_status, 'determined')
  assert.ok(result.warnings.some((warning) => warning.includes('两条分支结论相同')))
})

test('dmarc: Author 明确 NXDOMAIN 且记录带 np= -> 用 np', () => {
  const result = dmarcWith({
    record: 'v=DMARC1; p=reject; np=quarantine',
    author: 'nosuch.example.com',
    authorExistence: 'nxdomain',
  })
  assert.equal(result.policy_tag, 'np')
  assert.equal(result.disposition, 'quarantine')
})

test('dmarc: 策略来源可为 organizational（子域无记录、父域有）', () => {
  const result = dmarcWith({
    record: 'v=DMARC1; p=none',
    author: 'dept.example.com',
    authorExistence: 'exists',
  })
  assert.equal(result.policy_domain, 'example.com')
  assert.equal(result.policy_source, 'organizational')
})

test('reconcile: method 缺等号时 result 默认 none', () => {
  const claims = parseAuthenticationResults(arMessage('mx.example.com; spf'))
  assert.equal(claims[0].method, 'spf')
  assert.equal(claims[0].result, 'none')
})

test('reconcile: 多张 Authentication-Results 头都被解析', () => {
  const message = parseMessage(
    Buffer.from(
      'Authentication-Results: mx.example.com; spf=pass\r\nAuthentication-Results: mx.example.com; dkim=pass\r\n\r\nbody',
      'latin1',
    ),
  )
  assert.equal(parseAuthenticationResults(message).length, 2)
})

test('organ: 多 claim 混合结论 -> 汇总阻断 1 条', async () => {
  const dir = tmpDir()
  writeFileSync(
    join(dir, 'in.json'),
    JSON.stringify(
      subjectFor('dmarc', 'b41', [
        { claim_id: 'a-ok', check: 'spf', asserted: 'pass', node: NODE },
        { claim_id: 'b-bad', check: 'spf', asserted: 'fail', node: NODE },
      ]),
    ),
  )
  writeFileSync(join(dir, 'b.json'), JSON.stringify({ version: 'v1', nodes: [NODE] }))
  const { code, out } = await capture(() =>
    main(['check', 'email-evidence', '--input', join(dir, 'in.json'), '--basis', join(dir, 'b.json'), '--json']),
  )
  assert.equal(code, EXIT_BLOCKED)
  const payload = JSON.parse(out)
  assert.equal(payload.summary.blocking, 1)
  assert.equal(payload.summary.total, 2)
})

test('organ: 主张 undecidable 不会被当成 claim（痕迹不足就是不足）', () => {
  const records = runOrgan(
    subjectFor('dkim', 'd4a-key-not-queried', [
      { claim_id: 'c1', check: 'dkim', asserted: 'undecidable', node: NODE },
    ]),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /缺失项/)
})

// ════════════════════════════════════════════════════════════════════════
// 11. 规则 × 三态（claim / refuted / inconclusive）
// ════════════════════════════════════════════════════════════════════════

function verdictFor(subject, claim) {
  return runOrgan({ ...subject, claims: [claim] })[0].verdict
}

function threeStates(name, buildSubject, claimBase, flipped, thirdMutator) {
  test(`three-state email-evidence ${name}: claim`, () => {
    assert.equal(verdictFor(buildSubject(), { ...claimBase, asserted: claimBase.asserted, node: NODE }), CLAIM)
  })
  test(`three-state email-evidence ${name}: refuted`, () => {
    assert.equal(verdictFor(buildSubject(), { ...claimBase, asserted: flipped, node: NODE }), 'refuted')
  })
  test(`three-state email-evidence ${name}: inconclusive`, () => {
    const mutated = thirdMutator === undefined ? buildSubject() : thirdMutator(buildSubject())
    const claim = { ...claimBase, asserted: flipped, node: thirdMutator === undefined ? undefined : NODE }
    assert.equal(verdictFor(mutated, claim), INCONCLUSIVE)
  })
}

threeStates(
  'spf-pass',
  () => subjectFor('dmarc', 'b41', []),
  { claim_id: 'c', check: 'spf', asserted: 'pass' },
  'fail',
  (subject) => {
    const mutated = JSON.parse(JSON.stringify(subject))
    delete mutated.snapshot.schema_version
    return mutated
  },
)

threeStates(
  'spf-permerror',
  () => {
    const subject = subjectFor('dmarc', 'b41', [])
    subject.snapshot.queries = [
      { qname: 'example.com', qtype: 'TXT', rcode: 'NOERROR', answer: ['v=spf1 -all', 'v=spf1 +all'], ttl: 300 },
    ]
    return subject
  },
  { claim_id: 'c', check: 'spf', asserted: 'permerror' },
  'pass',
)

threeStates(
  'dkim-pass',
  () => subjectFor('dkim', 'd6-valid', []),
  { claim_id: 'c', check: 'dkim', asserted: 'pass' },
  'fail',
  () => subjectFor('dkim', 'd4a-key-not-queried', []),
)

threeStates(
  'dmarc-pass',
  () => subjectFor('dmarc', 'b41', []),
  { claim_id: 'c', check: 'dmarc', asserted: 'pass' },
  'fail',
  (subject) => {
    const mutated = JSON.parse(JSON.stringify(subject))
    mutated.snapshot.queries = mutated.snapshot.queries.filter((entry) => !entry.qname.startsWith('_dmarc.'))
    return mutated
  },
)

const npSubject = () => subjectFor('dmarc', 'np', [])
const npClaim = { claim_id: 'c', check: 'dmarc', asserted: 'fail', asserted_disposition: 'quarantine' }

test('three-state email-evidence dmarc-disposition: claim', () => {
  assert.equal(verdictFor(npSubject(), { ...npClaim, node: NODE }), CLAIM)
})

test('three-state email-evidence dmarc-disposition: refuted', () => {
  assert.equal(
    verdictFor(npSubject(), { ...npClaim, asserted_disposition: 'reject', node: NODE }),
    'refuted',
  )
})

test('three-state email-evidence dmarc-disposition: inconclusive', () => {
  const mutated = npSubject()
  mutated.snapshot.queries = mutated.snapshot.queries.filter((entry) => entry.qname !== 'nosuch.example.com')
  assert.equal(verdictFor(mutated, { ...npClaim, node: NODE }), INCONCLUSIVE)
})

threeStates(
  'dmarc-none',
  () => {
    const subject = subjectFor('dmarc', 'b41', [])
    subject.snapshot.queries = [
      { qname: '_dmarc.example.com', qtype: 'TXT', rcode: 'NXDOMAIN', answer: [], ttl: 300 },
      { qname: '_dmarc.com', qtype: 'TXT', rcode: 'NXDOMAIN', answer: [], ttl: 300 },
    ]
    return subject
  },
  { claim_id: 'c', check: 'dmarc', asserted: 'none' },
  'pass',
)

function reconcileSubject() {
  const fixture = loadFixture('dmarc', 'b41')
  const injected = fixture.raw
    .toString('latin1')
    .replace('From:', 'Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass\r\nFrom:')
  return {
    snapshot: JSON.parse(JSON.stringify(fixture.snapshot.data)),
    query: fixture.delivery,
    message: injected,
  }
}

threeStates(
  'reconcile-consistent',
  reconcileSubject,
  { claim_id: 'c', check: 'reconcile', asserted: 'consistent' },
  'contradiction',
  (subject) => ({ ...subject, query: { ...subject.query, trusted_authserv_ids: [] } }),
)

test('node: 空 tool_call_id -> 内核降级并写明 tool_call_id', () => {
  const records = runOrgan(
    subjectFor('dmarc', 'b41', [
      { claim_id: 'c', check: 'spf', asserted: 'pass', node: { session_id: 's-1', turn: 3, tool_call_id: '' } },
    ]),
    Basis.fromObject({ version: '2026.11.25', nodes: [{ session_id: 's-1', turn: 3, tool_call_id: '' }] }),
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /tool_call_id/)
})

function dmarcWith({ record, author, authorExistence }) {
  const entries = [
    dns(`_dmarc.${author}`, 'TXT', [], 'NXDOMAIN'),
    dns('_dmarc.example.com', 'TXT', [record]),
    dns('_dmarc.com', 'TXT', [], 'NXDOMAIN'),
  ]
  if (authorExistence !== null) {
    entries.push(dns(author, 'A', [], authorExistence === 'nxdomain' ? 'NXDOMAIN' : 'NOERROR'))
  }
  const snapshot = snapshotOf(...entries)
  const message = parseMessage(
    Buffer.from(`From: Alice <alice@${author}>\r\n\r\nbody`, 'latin1'),
  )
  const spf = {
    result: 'fail',
    reason: 'test',
    domain: author,
    record: 'v=spf1 -all',
    evidence_ref: [],
    warnings: [],
    gray_areas: [],
    data_gap: null,
  }
  const dkim = {
    signatures: [
      {
        index: 0,
        selector: 's',
        domain: 'other.example.net',
        identity: '@other.example.net',
        algorithm: 'rsa-sha256',
        canonicalization: 'relaxed/relaxed',
        bh_matches: true,
        failure_at: null,
        key_bits: 2048,
        key_status: 'ok',
        result: 'pass',
        reason: 'test',
        evidence_ref: [],
        trace: [],
        warnings: [],
        data_gap: null,
      },
    ],
    message_has_signatures: true,
    trace: [],
    warnings: [],
    data_gaps: [],
  }
  return dmarcEvaluate(
    snapshot,
    message,
    { mail_from: `alice@${author}`, helo: 'mail.example.com' },
    spf,
    dkim,
  )
}