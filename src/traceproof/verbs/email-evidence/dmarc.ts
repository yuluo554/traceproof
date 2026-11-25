/**
 * DMARC（RFC 9989）：DNS Tree Walk + 双算对齐 + 处置。
 *
 * 移植自旧仓 `modules/dmarc.py`，五条设计约束原样保留：
 *
 * 1. tree walk 按 §4.10 逐条实现（含标签数 ≥ 8 的跳步）；
 * 2. `psd=n` / `psd=y` 改变 Organizational Domain（§4.10.2），不只是"多一个标签"；
 * 3. 对齐**双算**：relaxed / strict 各出一个布尔值，不合并；
 * 4. "没查过" ≠ "没有记录"（`not_queried` → 数据缺口 → undecidable）；
 * 5. 已删除标签 `pct` / `rf` / `ri` 不静默忽略，逐条进 warnings。
 *
 * PSL 只用于对照（RFC 9989 §4.10.2 以 tree walk 为准）。
 */

import { domainToASCII } from 'node:url'

import { Snapshot, normalizeDnsName } from './snapshot.js'
import type { Message } from './dkim.js'
import { organizationalDomain, pslDate, pslVersion } from './psl.js'
import type { DkimResult, SpfResult, TraceNote } from './index-types.js'

export const REF_TREE_WALK = 'RFC9989#4.10'
export const REF_DISCOVERY = 'RFC9989#4.10.1'
export const REF_ALIGN = 'RFC9989#4.10.2'
export const REF_ALIGN_CONCEPT = 'RFC9989#4.4'
export const REF_DKIM_IDENTIFIER = 'RFC9989#4.4.1'
export const REF_SPF_IDENTIFIER = 'RFC9989#4.4.2'
export const REF_TAGS = 'RFC9989#4.7'
export const REF_ABNF = 'RFC9989#4.8'
export const REF_AUTHOR = 'RFC9989#5.3.1'
export const REF_VERDICT = 'RFC9989#5.3.5'
export const REF_APPLY = 'RFC9989#5.3.6'
export const REF_NONEXISTENT = 'RFC9989#3.2.13'
export const REF_PCT_REMOVED = 'RFC9989#appendix-A.6'
export const REF_TAGS_REMOVED = 'RFC9989#appendix-C.5.2'

export const DMARC_RECORD_LABEL = '_dmarc'
export const DMARC_VERSION = 'DMARC1'
export const DMARC_MAX_LABELS = 8
export const DMARC_TREE_KEEP_LABELS = 7
export const DMARC_DEFAULT_ALIGN = 'r'
export const DMARC_DEFAULT_PSD = 'u'
export const DMARC_DISPOSITIONS = ['none', 'quarantine', 'reject'] as const
export const DMARC_REMOVED_TAGS = ['pct', 'rf', 'ri'] as const
export const DMARC_TEST_MODE_DOWNGRADE: Record<string, string> = {
  none: 'none',
  quarantine: 'none',
  reject: 'quarantine',
}
export const DMARC_DNS_ERROR_RCODES = ['SERVFAIL', 'TIMEOUT', 'REFUSED', 'FORMERR', 'NOTIMP']
const KNOWN_TAGS = new Set('v adkim aspf fo np p psd rua ruf sp t'.split(' '))

export interface Hop {
  index: number
  domain: string
  qname: string
  status: string
  record: string | null
  psd: string | null
  rcode: string | null
  note: string
}

export interface Walk {
  start: string
  hops: Hop[]
  stopped_by: string
}

export interface DmarcRecord {
  text: string
  tags: Record<string, string>
  malformed: string[]
}

export interface Alignment {
  identifier: string
  source: string
  organizational_domain: string | null
  relaxed: boolean
  strict: boolean
  note: string
}

export interface DmarcResult {
  result: string
  reason: string
  author_domain: string | null
  organizational_domain: string | null
  policy_domain: string | null
  policy_source: string | null
  policy_tag: string | null
  policy_value: string | null
  disposition: string | null
  disposition_status: string
  test_mode: boolean
  record: DmarcRecord | null
  walk: Walk | null
  alignments: Alignment[]
  spf_align: { relaxed: boolean; strict: boolean }
  dkim_align: { relaxed: boolean; strict: boolean }
  psl_version: string
  psl_date: string
  psl_organizational_domain: string | null
  evidence_ref: string[]
  trace: TraceNote[]
  warnings: string[]
  data_gaps: Array<[string, string]>
}

export function parseRecord(text: string): DmarcRecord | null {
  if (typeof text !== 'string') return null
  const stripped = text.trim()
  if (!stripped) return null

  let parts = stripped.split(';').map((part) => part.trim())
  while (parts.length > 0 && !parts[parts.length - 1]) parts = parts.slice(0, -1)
  if (parts.length === 0) return null

  const first = parts[0]
  const equals = first.indexOf('=')
  if (equals < 0) return null
  const name = first.slice(0, equals).trim().toLowerCase()
  const value = first.slice(equals + 1).trim()
  if (name !== 'v' || value !== DMARC_VERSION) return null

  const tags: Record<string, string> = { v: value }
  const malformed: string[] = []
  for (const fragment of parts.slice(1)) {
    if (!fragment) {
      malformed.push('连续分号（空标签）')
      continue
    }
    const separator = fragment.indexOf('=')
    if (separator < 0) {
      malformed.push(`片段缺 '='：<${fragment.slice(0, 40)}>`)
      continue
    }
    const tagName = fragment.slice(0, separator).trim().toLowerCase()
    if (!tagName) {
      malformed.push(`片段缺 '='：<${fragment.slice(0, 40)}>`)
      continue
    }
    if (tagName in tags) {
      malformed.push(`标签 ${tagName}= 重复，保留首次出现的值`)
      continue
    }
    tags[tagName] = fragment.slice(separator + 1).trim()
  }
  return { text: stripped, tags, malformed }
}

export function validVersionRecord(text: string): boolean {
  return parseRecord(text) !== null
}

function labels(name: string): string[] {
  const normalized = normalizeDnsName(name)
  if (!normalized) return []
  return normalized.split('.').filter(Boolean)
}

function shorten(domain: string): string | null {
  const parts = labels(domain)
  if (parts.length <= 1) return null
  if (parts.length < DMARC_MAX_LABELS) return parts.slice(1).join('.')
  const keep = Math.min(DMARC_TREE_KEEP_LABELS, parts.length - 1)
  return parts.slice(parts.length - keep).join('.')
}

/** §4.10 步骤 4 的标签跳步（导出给单元测试逐条锁住）。 */
export const shortenDomain = shorten

export function walk(snap: Snapshot, start: string, trace: TraceNote[] | null = null): Walk {
  const hops: Hop[] = []
  let target = normalizeDnsName(start)
  let stoppedBy = 'labels_exhausted'

  while (target) {
    const qname = `${DMARC_RECORD_LABEL}.${target}`
    const hop = queryHop(snap, qname, target, hops.length, trace, normalizeDnsName(start))
    hops.push(hop)
    if (hop.status === 'record' && (hop.psd === 'y' || hop.psd === 'n')) {
      stoppedBy = 'psd'
      break
    }
    const shortened = shorten(target)
    if (shortened === null) {
      stoppedBy = 'labels_exhausted'
      break
    }
    target = shortened
  }
  return { start: normalizeDnsName(start), hops, stopped_by: stoppedBy }
}

function queryHop(
  snap: Snapshot,
  qname: string,
  domain: string,
  index: number,
  trace: TraceNote[] | null,
  label: string,
): Hop {
  const resolved = snap.resolve(qname, 'TXT')
  const node = { node: `walk.${label}.${index}`, note: '' }

  const emit = (note: string): void => {
    if (trace !== null) trace.push({ node: node.node, note })
  }

  if (!resolved.found) {
    emit(`${qname} 未在快照中查询（数据缺口，不等同于没有记录）`)
    return { index, domain, qname, status: 'not_queried', record: null, psd: null, rcode: null, note: '快照里没有这条查询' }
  }
  const rcode = (resolved.rcode ?? '').toUpperCase()
  if (DMARC_DNS_ERROR_RCODES.includes(rcode)) {
    emit(`${qname} → rcode=${rcode}（DNS 错误：不能据此判 pass 或 fail）`)
    return { index, domain, qname, status: 'dns_error', record: null, psd: null, rcode, note: 'DNS 错误，结论不可判定' }
  }
  if (rcode === 'NXDOMAIN') {
    emit(`${qname} → NXDOMAIN（问过了，没有这个域）`)
    return { index, domain, qname, status: 'nxdomain', record: null, psd: null, rcode, note: '该域不存在' }
  }
  if (rcode !== 'NOERROR') {
    emit(`${qname} → rcode=${rcode}（非 NOERROR，按 DNS 错误处理）`)
    return { index, domain, qname, status: 'dns_error', record: null, psd: null, rcode, note: '非 NOERROR 答复' }
  }
  if (resolved.answer.length === 0) {
    emit(`${qname} → NOERROR 但答复为空（问过了，没有记录）`)
    return { index, domain, qname, status: 'no_record', record: null, psd: null, rcode, note: '空答复' }
  }

  const candidates = resolved.answer.map((item) => parseRecord(item)).filter((item): item is DmarcRecord => item !== null)
  if (candidates.length === 0) {
    emit(`${qname} → ${resolved.answer.length} 条 TXT，但都不以 v=${DMARC_VERSION} 开头（§4.7：整条忽略）`)
    return { index, domain, qname, status: 'invalid_record', record: null, psd: null, rcode, note: '记录存在但 v= 不合格' }
  }
  if (candidates.length > 1) {
    emit(`${qname} → ${candidates.length} 条通过 v= 过滤的记录（§4.10 步骤 2：同一目标多条 → 全部丢弃）`)
    return { index, domain, qname, status: 'multiple_records', record: null, psd: null, rcode, note: '同一目标返回多条记录' }
  }
  const record = candidates[0]
  const psd = record.tags.psd ?? DMARC_DEFAULT_PSD
  emit(`${qname} → 记录 <${record.text}>（psd=${psd}）`)
  return { index, domain, qname, status: 'record', record: record.text, psd, rcode, note: '' }
}

export function selectOrganizationalDomain(resultWalk: Walk): string | null {
  const records = resultWalk.hops.filter((hop) => hop.status === 'record')
  if (records.length === 0) return null

  const ordered = [...records].sort((a, b) =>
    labels(b.domain).length === labels(a.domain).length
      ? a.index - b.index
      : labels(b.domain).length - labels(a.domain).length,
  )

  for (const hop of ordered) {
    if (hop.psd === 'n') return hop.domain
  }
  for (const hop of ordered) {
    if (hop.psd === 'y' && hop.domain !== resultWalk.start) {
      const below = oneLabelBelow(hop.domain, resultWalk.start)
      if (below !== null) return below
    }
  }
  return ordered[ordered.length - 1].domain
}

function oneLabelBelow(target: string, descendant: string): string | null {
  const targetLabels = labels(target)
  const startLabels = labels(descendant)
  if (targetLabels.length === 0 || startLabels.length <= targetLabels.length) return null
  return startLabels.slice(startLabels.length - targetLabels.length - 1).join('.')
}

// ── Author Domain（§5.3.1） ─────────────────────────────────────────────

export function fromDomains(message: Message): { domains: string[]; notes: string[] } {
  const values = message.fields
    .filter((field) => field.name.toString('latin1').trim().toLowerCase() === 'from')
    .map((field) => field.value.toString('latin1'))
  if (values.length === 0) {
    return { domains: [], notes: ['报文没有 From 头字段（§5.3.1 要求从 RFC5322.From 取 Author Domain）'] }
  }

  const notes: string[] = []
  const domains: string[] = []
  for (const value of values) {
    for (const spec of addrSpecs(value)) {
      const at = spec.lastIndexOf('@')
      const domain = at >= 0 ? spec.slice(at + 1).trim().replace(/\.+$/, '').toLowerCase() : ''
      if (!domain) {
        notes.push(`From 里的地址 <${spec}> 没有域部分`)
        continue
      }
      const converted = toALabel(domain)
      if (converted.note) notes.push(converted.note)
      if (converted.domain && !domains.includes(converted.domain)) domains.push(converted.domain)
    }
  }
  if (values.length > 1) {
    notes.push(`报文有 ${values.length} 个 From 头字段（§5.3.1：多于一个域时判定不成立）`)
  }
  if (domains.length > 1) {
    notes.push(`From 里出现 ${domains.length} 个不同的域：${domains.join('、')}`)
  }
  return { domains, notes }
}

function addrSpecs(value: string): string[] {
  const specs: string[] = []
  let cursor = 0
  for (;;) {
    const start = value.indexOf('<', cursor)
    if (start < 0) break
    const end = value.indexOf('>', start)
    if (end < 0) break
    specs.push(value.slice(start + 1, end).trim())
    cursor = end + 1
  }
  if (specs.length > 0) return specs
  for (const piece of value.split(',')) {
    const token = piece.trim()
    if (!token || !token.includes('@')) continue
    specs.push(token.split(/\s+/).slice(-1)[0])
  }
  return specs
}

function toALabel(domain: string): { domain: string | null; note: string | null } {
  if (/^[\x00-\x7f]*$/.test(domain)) return { domain, note: null }
  const converted = domainToASCII(domain)
  if (!converted) return { domain: null, note: `From 域 <${domain}> 无法转成 A-label` }
  return { domain: converted, note: 'From 域是非 ASCII（U-label），已按 §5.3.1 转成 A-label' }
}

// ── 对齐（§4.4 / §4.10.2） ─────────────────────────────────────────────

export function align(
  authorDomain: string,
  authorOrg: string | null,
  identifier: string,
  source: string,
  walkCache: Map<string, Walk>,
  snap: Snapshot,
  trace: TraceNote[] | null,
): Alignment {
  const normalized = normalizeDnsName(identifier)
  let identifierWalk = walkCache.get(normalized)
  if (identifierWalk === undefined) {
    identifierWalk = walk(snap, normalized, trace)
    walkCache.set(normalized, identifierWalk)
  }
  const identifierOrg = selectOrganizationalDomain(identifierWalk)

  const strict = authorDomain === normalized
  const relaxed = authorOrg !== null && identifierOrg !== null && authorOrg === identifierOrg

  const notes: string[] = []
  if (authorOrg === null) notes.push('Author Domain 没有 Organizational Domain（走查无命中），relaxed 不可能成立')
  else if (identifierOrg === null) notes.push(`${normalized} 没有 Organizational Domain（走查无命中），relaxed 不可能成立`)
  if (authorOrg !== null && identifierOrg !== null) {
    const pslAuthor = organizationalDomain(authorDomain)
    const pslIdentifier = organizationalDomain(normalized)
    if (pslAuthor !== null && pslIdentifier !== null && pslAuthor !== pslIdentifier) {
      notes.push(
        `PSL 口径下 ${authorDomain} 与 ${normalized} 不同域（${pslAuthor} / ${pslIdentifier}），但 RFC 9989 §4.10.2 的 tree walk 判定为同一 Organizational Domain（${authorOrg}）——以 tree walk 为准`,
      )
    }
  }
  if (trace !== null) {
    trace.push({
      node: `align.${source}`,
      note: `${source}：${authorDomain} vs ${normalized} → relaxed=${flag(relaxed)} / strict=${flag(strict)}（Organizational Domain：${authorOrg ?? 'null'} / ${identifierOrg ?? 'null'}）`,
    })
  }
  return {
    identifier: normalized,
    source,
    organizational_domain: identifierOrg,
    relaxed,
    strict,
    note: notes.join('；'),
  }
}

function flag(value: boolean): string {
  return value ? 'true' : 'false'
}

function discoverPolicy(
  author: string,
  authorOrg: string | null,
  authorWalk: Walk,
): { record: DmarcRecord | null; policyDomain: string | null; policySource: string | null } {
  const at = (domain: string): Hop | undefined => authorWalk.hops.find((hop) => hop.status === 'record' && hop.domain === domain)
  const own = at(author)
  if (own?.record) return { record: parseRecord(own.record), policyDomain: author, policySource: 'author' }
  if (authorOrg !== null && authorOrg !== author) {
    const org = at(authorOrg)
    if (org?.record) return { record: parseRecord(org.record), policyDomain: authorOrg, policySource: 'organizational' }
  }
  for (const hop of authorWalk.hops) {
    if (hop.status === 'record' && hop.psd === 'y' && hop.domain !== author && hop.record) {
      return { record: parseRecord(hop.record), policyDomain: hop.domain, policySource: 'psd' }
    }
  }
  return { record: null, policyDomain: null, policySource: null }
}

interface Selection {
  tag: string
  value: string | null
  disposition: string | null
  status: string
  warnings: string[]
  reason: string
}

function selectPolicy(snap: Snapshot, record: DmarcRecord, author: string, policyDomain: string | null): Selection {
  const warnings: string[] = []
  const isOwnRecord = policyDomain === null || normalizeDnsName(policyDomain) === author
  if (isOwnRecord) {
    return decide(record, 'p', record.tags.p ?? null, policyDomain, author, warnings, true)
  }

  const existence = authorExistence(snap, author)
  if (existence.note) warnings.push(existence.note)

  const npValue = record.tags.np ?? null
  const spValue = record.tags.sp ?? null
  const pValue = record.tags.p ?? null
  const fallbackTag = spValue !== null ? 'sp' : 'p'
  const fallbackValue = spValue !== null ? spValue : pValue

  if (existence.status === 'unknown' && npValue !== null) {
    const npDisposition = policyDisposition(npValue)
    const fallbackDisposition = policyDisposition(fallbackValue)
    if (npDisposition !== null && npDisposition === fallbackDisposition) {
      warnings.push(
        `np=<${npValue}> 与 ${fallbackTag}=<${fallbackValue}> 给出同一处置 ${npDisposition}：即使 Author Domain 的存在性未知，两条分支结论相同，因此仍可判定`,
      )
      return decide(record, 'np', npValue, policyDomain, author, warnings, false)
    }
    return {
      tag: 'np',
      value: npValue,
      disposition: null,
      status: 'undecidable',
      warnings,
      reason: `DMARC 判 fail，但记录带 np=<${npValue}>：要判定该用它还是 ${fallbackTag}=<${fallbackValue}>，必须先知道 Author Domain ${author} 是否存在（§3.2.13：以该名字的查询答复为准），而快照里没有这条查询。两条分支给出不同处置，本工具不猜`,
    }
  }
  if (existence.status === 'nxdomain' && npValue !== null) {
    return decide(record, 'np', npValue, policyDomain, author, warnings, false)
  }
  if (existence.status === 'nxdomain') {
    warnings.push(`Author Domain ${author} 不存在（快照答复 NXDOMAIN）且记录没有 np=：§4.7 规定回落到 ${fallbackTag}=`)
  }
  return decide(record, fallbackTag, fallbackValue, policyDomain, author, warnings, false)
}

function decide(
  record: DmarcRecord,
  tag: string,
  value: string | null,
  policyDomain: string | null,
  author: string,
  warnings: string[],
  ownRecord: boolean,
): Selection {
  const who = ownRecord ? 'Author Domain' : `策略域 ${policyDomain ?? author}`
  if (value === null) {
    if (tag === 'p' || tag === 'sp') {
      warnings.push(`${who} 没有 ${tag}= 标签：§4.7 规定按 p=none 处理（不是判不了）`)
      return determined(tag, 'none', 'none', warnings, `DMARC 判 fail；${who} 的 ${tag}= 缺失，§4.7 按 p=none 处理 → 处置 none`)
    }
    return determined(tag, null, 'none', warnings, 'DMARC 判 fail；无可用策略标签 → 处置 none')
  }
  if (!(DMARC_DISPOSITIONS as readonly string[]).includes(value)) {
    warnings.push(`${who}=<${value}> 不是合法策略（§4.8 的 dmarc-request 只允许 ${DMARC_DISPOSITIONS.join(' / ')}）`)
    if (hasValidReportUri(record.tags.rua)) {
      warnings.push(`§4.10.1：${tag}=<${value}> 非法但 rua= 含有效 URI → 按 p=none 继续处理`)
      return determined('p', 'none', 'none', warnings, `DMARC 判 fail；${who} 的 ${tag}=<${value}> 非法，但记录带有效 rua=，§4.10.1 规定按 p=none 处理 → 处置 none`)
    }
    warnings.push(`§4.10.1：${tag}=<${value}> 非法且 rua= 不可用 → 本工具不施加 DMARC 处理`)
    return {
      tag,
      value,
      disposition: null,
      status: 'not_applicable',
      warnings,
      reason: `DMARC 判 fail；${who} 的 ${tag}=<${value}> 非法且没有可用的 rua=，§4.10.1 规定不施加 DMARC 处理`,
    }
  }
  return determined(tag, value, value, warnings, `DMARC 判 fail；${who} 的 ${tag}=${value} → 处置 ${value}`)
}

function determined(tag: string, value: string | null, disposition: string, warnings: string[], reason: string): Selection {
  return { tag, value, disposition, status: 'determined', warnings, reason }
}

function policyDisposition(value: string | null): string | null {
  if (value === null) return 'none'
  return (DMARC_DISPOSITIONS as readonly string[]).includes(value) ? value : null
}

function authorExistence(snap: Snapshot, author: string): { status: string; note: string | null } {
  let seen = false
  for (const entry of snap.data.queries) {
    if (normalizeDnsName(entry.qname) !== author) continue
    seen = true
    if (entry.rcode.toUpperCase() === 'NXDOMAIN') return { status: 'nxdomain', note: null }
  }
  if (seen) return { status: 'exists', note: null }
  return {
    status: 'unknown',
    note: `快照里没有 Author Domain ${author} 本身的查询：sp= / np= 的选择依赖它是否存在（§3.2.13）`,
  }
}

function hasValidReportUri(value: string | undefined): boolean {
  if (!value) return false
  for (const item of value.split(',')) {
    const candidate = item.trim()
    const colon = candidate.indexOf(':')
    if (colon > 0 && candidate.slice(0, colon).trim() && candidate.slice(colon + 1).trim()) return true
  }
  return false
}

function testMode(record: DmarcRecord, warnings: string[]): boolean {
  const value = record.tags.t
  if (value === undefined) return false
  if (value !== 'y' && value !== 'n') {
    warnings.push(`t=<${value}> 非法（§4.8 只允许 y / n），按默认 t=n 处理`)
    return false
  }
  return value === 'y'
}

function alignMode(value: string | undefined, name: string, warnings: string[]): string {
  if (value === undefined) return 'relaxed'
  if (value === 's') return 'strict'
  if (value === 'r') return 'relaxed'
  warnings.push(`${name}=<${value}> 非法（§4.8 只允许 r / s），按默认 ${DMARC_DEFAULT_ALIGN} 处理`)
  return 'relaxed'
}

function recordWarnings(record: DmarcRecord, policyDomain: string): string[] {
  const warnings: string[] = []
  for (const tag of DMARC_REMOVED_TAGS) {
    if (!(tag in record.tags)) continue
    if (tag === 'pct') {
      warnings.push(
        `pct=<${record.tags[tag]}>：该标签已被 RFC 9989 删除（Appendix A.6 与 C.5.2），本工具不按百分比施加策略——按完整策略处理。记录在 ${policyDomain}`,
      )
    } else {
      warnings.push(
        `${tag}=<${record.tags[tag]}>：该标签已被 RFC 9989 删除（Appendix C.5.2），本工具不解释其语义，也不静默忽略。记录在 ${policyDomain}`,
      )
    }
  }
  for (const fragment of record.malformed) {
    warnings.push(`记录 ${policyDomain} 有可忽略的语法问题：${fragment}（§4.8 按默认值处理）`)
  }
  for (const name of Object.keys(record.tags).sort()) {
    if (KNOWN_TAGS.has(name) || (DMARC_REMOVED_TAGS as readonly string[]).includes(name)) continue
    warnings.push(`${name}= 不在本工具已知标签内（§4.7：unknown tags MUST be ignored）`)
  }
  return warnings
}

// ── 主入口 ──────────────────────────────────────────────────────────────

export function dmarcEvaluate(
  snap: Snapshot,
  message: Message | null,
  query: { mail_from: string; helo: string | null },
  spf: SpfResult | null,
  dkim: DkimResult | null,
  trace: TraceNote[] = [],
): DmarcResult {
  const shared = trace
  const pslVersionValue = snap.pslVersion
  const pslDateValue = snap.pslDate
  const warnings: string[] = []
  if (pslVersionValue !== pslVersion() || pslDateValue !== pslDate()) {
    warnings.push(
      `快照记录的 PSL 版本 ${pslVersionValue} / ${pslDateValue} 与随包冻结件 ${pslVersion()} / ${pslDate()} 不同：PSL 只用于对照，判定以 RFC 9989 §4.10.2 的 tree walk 为准`,
    )
  }

  const extracted = message === null
    ? { domains: [], notes: ['没有提供报文（message / message_b64）：无法提取 Author Domain'] }
    : fromDomains(message)
  warnings.push(...extracted.notes)
  shared.push({ node: 'dmarc.author', note: `RFC5322.From 提取到 ${extracted.domains.length} 个域：${extracted.domains.join('、') || '（无）'}` })

  if (extracted.domains.length === 0) {
    return degenerate('none', '报文没有可提取的 Author Domain（§5.3.1）→ DMARC 机制不适用，判 none', [REF_AUTHOR], pslVersionValue, pslDateValue, shared, warnings)
  }
  if (extracted.domains.length > 1) {
    return degenerate(
      'undecidable',
      `RFC5322.From 里出现 ${extracted.domains.length} 个不同的域（${extracted.domains.join('、')}）；§5.3.1 规定此时 DMARC 判定不成立，本工具不猜哪一个才是 Author Domain`,
      [REF_AUTHOR],
      pslVersionValue,
      pslDateValue,
      shared,
      warnings,
    )
  }

  const author = extracted.domains[0]
  const walkCache = new Map<string, Walk>()
  const authorWalk = walk(snap, author, shared)
  walkCache.set(author, authorWalk)
  const authorOrg = selectOrganizationalDomain(authorWalk)
  shared.push({ node: 'dmarc.org', note: `Author Domain ${author} 的 Organizational Domain：${authorOrg ?? '（走查无命中）'}` })

  const discovered = discoverPolicy(author, authorOrg, authorWalk)
  const record = discovered.record
  const policyDomain = discovered.policyDomain
  const policySource = discovered.policySource
  if (record !== null) warnings.push(...recordWarnings(record, policyDomain ?? author))
  const pslOrg = organizationalDomain(author)

  const gaps: Array<[string, string]> = authorWalk.hops
    .filter((hop) => hop.status === 'not_queried')
    .map((hop) => [hop.qname, 'TXT'] as [string, string])
  if (gaps.length > 0) {
    return undecidable({
      reason: `tree walk 有 ${gaps.length} 跳在快照里没有查询（${authorWalk.hops.filter((hop) => hop.status === 'not_queried').map((hop) => `_dmarc.${hop.domain}`).join('、')}）：这是数据缺口，不等于该域没有 DMARC 记录；补抓这些键后重跑即可判定`,
      refs: [REF_TREE_WALK, REF_DISCOVERY],
      snap, author, authorOrg, policyDomain, policySource, record, resultWalk: authorWalk,
      pslVersion: pslVersionValue, pslDate: pslDateValue, pslOrg, trace: shared, warnings, dataGaps: gaps,
    })
  }
  const errors = authorWalk.hops.filter((hop) => hop.status === 'dns_error')
  if (errors.length > 0) {
    return undecidable({
      reason: `tree walk 有 ${errors.length} 跳是 DNS 错误（rcode=${errors.map((hop) => hop.rcode).join('、')}）：§5.3.6 规定此时报文不能被认为 pass 或 fail，处置策略也无法施加`,
      refs: [REF_TREE_WALK, REF_APPLY],
      snap, author, authorOrg, policyDomain, policySource, record, resultWalk: authorWalk,
      pslVersion: pslVersionValue, pslDate: pslDateValue, pslOrg, trace: shared, warnings,
    })
  }

  if (record === null) {
    return {
      result: 'none',
      reason: `tree walk 逐跳都没有有效 DMARC Policy Record（${authorWalk.hops.length} 跳：${authorWalk.hops.map((hop) => `${hop.qname}=${hop.status}`).join('、')}）；§4.10.1：Mail Receivers MUST NOT apply the DMARC mechanism → none`,
      author_domain: author,
      organizational_domain: authorOrg,
      policy_domain: null,
      policy_source: null,
      policy_tag: null,
      policy_value: null,
      disposition: null,
      disposition_status: 'not_applicable',
      test_mode: false,
      record: null,
      walk: authorWalk,
      alignments: [],
      spf_align: { relaxed: false, strict: false },
      dkim_align: { relaxed: false, strict: false },
      psl_version: pslVersionValue,
      psl_date: pslDateValue,
      psl_organizational_domain: pslOrg,
      evidence_ref: [REF_TREE_WALK, REF_DISCOVERY],
      trace: [...shared],
      warnings: [...warnings],
      data_gaps: [],
    }
  }

  const alignResult = alignAll({ snap, query, spf, dkim, author, authorOrg, walkCache, trace: shared })
  warnings.push(...alignResult.notes)
  const adkimMode = alignMode(record.tags.adkim, 'adkim', warnings)
  const aspfMode = alignMode(record.tags.aspf, 'aspf', warnings)
  const evidence = [REF_TREE_WALK, REF_DISCOVERY, REF_ALIGN, REF_ALIGN_CONCEPT, REF_VERDICT]

  if (spf === null || dkim === null) {
    const missing = [spf === null ? 'SPF' : null, dkim === null ? 'DKIM' : null].filter(Boolean).join('、')
    return undecidable({
      reason: `缺少 ${missing} 的求值结论，无法判断 §5.3.5 的"是否有对齐的 Authenticated Identifier"；本工具不假定它 pass 也不假定它 fail`,
      refs: evidence,
      snap, author, authorOrg, policyDomain, policySource, record, resultWalk: authorWalk,
      pslVersion: pslVersionValue, pslDate: pslDateValue, pslOrg, trace: shared, warnings,
      alignments: alignResult.alignments, spfAlign: alignResult.spfAlign, dkimAlign: alignResult.dkimAlign,
    })
  }

  const spfAligned = alignResult.spfAlign[aspfMode as 'relaxed' | 'strict']
  const dkimAligned = alignResult.dkimAlign[adkimMode as 'relaxed' | 'strict']
  const decided = spfAligned || dkimAligned
  shared.push({
    node: 'dmarc.verdict',
    note: `aspf=${aspfMode} / adkim=${adkimMode}；SPF 在本侧模式下对齐=${flag(spfAligned)}、DKIM 在对齐模式下对齐=${flag(dkimAligned)} → ${decided ? 'pass' : 'fail'}`,
  })

  if (decided) {
    return {
      result: 'pass',
      reason: `至少一个 Authenticated Identifier 与 Author Domain 对齐（SPF 侧 ${aspfMode} 模式=${flag(spfAligned)} / DKIM 侧 ${adkimMode} 模式=${flag(dkimAligned)}）；§5.3.5 判 pass，不施加处置策略`,
      author_domain: author,
      organizational_domain: authorOrg,
      policy_domain: policyDomain,
      policy_source: policySource,
      policy_tag: null,
      policy_value: null,
      disposition: null,
      disposition_status: 'not_applicable',
      test_mode: false,
      record,
      walk: authorWalk,
      alignments: alignResult.alignments,
      spf_align: alignResult.spfAlign,
      dkim_align: alignResult.dkimAlign,
      psl_version: pslVersionValue,
      psl_date: pslDateValue,
      psl_organizational_domain: pslOrg,
      evidence_ref: evidence,
      trace: [...shared],
      warnings: [...warnings],
      data_gaps: [],
    }
  }

  const selection = selectPolicy(snap, record, author, policyDomain)
  warnings.push(...selection.warnings)
  let disposition = selection.disposition
  const test = testMode(record, warnings)
  if (test && disposition !== null) {
    const original = disposition
    disposition = DMARC_TEST_MODE_DOWNGRADE[original] ?? original
    if (disposition !== original) {
      shared.push({ node: 'dmarc.test_mode', note: `t=y：策略从 ${original} 降级为 ${disposition}（§4.7）` })
    }
    warnings.push(`t=y：§4.7 要求把 ${original} 降一级施加，实际处置 ${disposition}`)
  }

  const refs = [...evidence, REF_TAGS]
  if (selection.tag === 'np') refs.push(REF_NONEXISTENT)
  if (selection.status === 'determined') refs.push(REF_APPLY)

  return {
    result: 'fail',
    reason: selection.reason,
    author_domain: author,
    organizational_domain: authorOrg,
    policy_domain: policyDomain,
    policy_source: policySource,
    policy_tag: selection.tag,
    policy_value: selection.value,
    disposition,
    disposition_status: selection.status,
    test_mode: test,
    record,
    walk: authorWalk,
    alignments: alignResult.alignments,
    spf_align: alignResult.spfAlign,
    dkim_align: alignResult.dkimAlign,
    psl_version: pslVersionValue,
    psl_date: pslDateValue,
    psl_organizational_domain: pslOrg,
    evidence_ref: refs,
    trace: [...shared],
    warnings: [...warnings],
    data_gaps: [],
  }
}

function alignAll(init: {
  snap: Snapshot
  query: { mail_from: string; helo: string | null }
  spf: SpfResult | null
  dkim: DkimResult | null
  author: string
  authorOrg: string | null
  walkCache: Map<string, Walk>
  trace: TraceNote[]
}): {
  alignments: Alignment[]
  spfAlign: { relaxed: boolean; strict: boolean }
  dkimAlign: { relaxed: boolean; strict: boolean }
  notes: string[]
} {
  const alignments: Alignment[] = []
  const notes: string[] = []
  const spfAlign = { relaxed: false, strict: false }
  const dkimAlign = { relaxed: false, strict: false }

  const at = init.query.mail_from.lastIndexOf('@')
  const senderDomain = at >= 0 ? normalizeDnsName(init.query.mail_from.slice(at + 1)) : ''
  let identifierDomain: string
  let notePrefix = ''
  if (senderDomain) {
    identifierDomain = senderDomain
  } else {
    identifierDomain = normalizeDnsName(init.query.helo ?? '')
    notePrefix = `MAIL FROM 为空（null 反向路径）：按 RFC 7208 §2.4（§3.2.4 引用），SPF 的 MAIL FROM 身份是 postmaster@<HELO>，故 SPF 域取 HELO 域 ${identifierDomain || '（HELO 也为空）'}`
  }
  if (identifierDomain) {
    const alignment = align(init.author, init.authorOrg, identifierDomain, 'spf', init.walkCache, init.snap, init.trace)
    alignments.push(alignment)
    if (notePrefix) notes.push(notePrefix)
    if (init.spf !== null && init.spf.result === 'pass') {
      spfAlign.relaxed = alignment.relaxed
      spfAlign.strict = alignment.strict
    } else if (init.spf !== null) {
      notes.push(`SPF 结论是 ${init.spf.result}（非 pass）：${identifierDomain} 不构成 SPF-Authenticated Identifier（§4.4.2），两侧对齐均为 false`)
    }
  } else {
    notes.push('反向路径为空且没有 HELO 名：RFC 7208 §2.4 下 SPF 的 MAIL FROM 身份无从确定，没有 SPF-Authenticated Identifier，spf 两侧对齐均为 false')
  }

  if (init.dkim === null) return { alignments, spfAlign, dkimAlign, notes }
  const passed = init.dkim.signatures.filter((signature) => signature.result === 'pass' && signature.domain)
  if (passed.length === 0) {
    notes.push('没有结论为 pass 的 DKIM 签名：不构成 DKIM-Authenticated Identifier（§4.4.1），两侧对齐均为 false')
  }
  for (const signature of passed) {
    const alignment = align(init.author, init.authorOrg, signature.domain as string, 'dkim', init.walkCache, init.snap, init.trace)
    alignments.push(alignment)
    dkimAlign.relaxed = dkimAlign.relaxed || alignment.relaxed
    dkimAlign.strict = dkimAlign.strict || alignment.strict
  }
  if (passed.length > 1) {
    notes.push(`报文有 ${passed.length} 条 pass 的 DKIM 签名：任意一条对齐即满足（§4.4.1 "if any DKIM-Authenticated Identifier aligns"）`)
  }
  return { alignments, spfAlign, dkimAlign, notes }
}

function degenerate(
  result: string,
  reason: string,
  refs: string[],
  version: string,
  date: string,
  trace: TraceNote[],
  warnings: string[],
): DmarcResult {
  return {
    result,
    reason,
    author_domain: null,
    organizational_domain: null,
    policy_domain: null,
    policy_source: null,
    policy_tag: null,
    policy_value: null,
    disposition: null,
    disposition_status: result === 'undecidable' ? 'undecidable' : 'not_applicable',
    test_mode: false,
    record: null,
    walk: null,
    alignments: [],
    spf_align: { relaxed: false, strict: false },
    dkim_align: { relaxed: false, strict: false },
    psl_version: version,
    psl_date: date,
    psl_organizational_domain: null,
    evidence_ref: refs,
    trace: [...trace],
    warnings: [...warnings],
    data_gaps: [],
  }
}

function undecidable(init: {
  reason: string
  refs: string[]
  snap: Snapshot
  author: string
  authorOrg: string | null
  policyDomain: string | null
  policySource: string | null
  record: DmarcRecord | null
  resultWalk: Walk
  pslVersion: string
  pslDate: string
  pslOrg: string | null
  trace: TraceNote[]
  warnings: string[]
  dataGaps?: Array<[string, string]>
  alignments?: Alignment[]
  spfAlign?: { relaxed: boolean; strict: boolean }
  dkimAlign?: { relaxed: boolean; strict: boolean }
}): DmarcResult {
  return {
    result: 'undecidable',
    reason: init.reason,
    author_domain: init.author,
    organizational_domain: init.authorOrg,
    policy_domain: init.policyDomain,
    policy_source: init.policySource,
    policy_tag: null,
    policy_value: null,
    disposition: null,
    disposition_status: 'undecidable',
    test_mode: false,
    record: init.record,
    walk: init.resultWalk,
    alignments: init.alignments ?? [],
    spf_align: init.spfAlign ?? { relaxed: false, strict: false },
    dkim_align: init.dkimAlign ?? { relaxed: false, strict: false },
    psl_version: init.pslVersion,
    psl_date: init.pslDate,
    psl_organizational_domain: init.pslOrg,
    evidence_ref: init.refs,
    trace: [...init.trace],
    warnings: [...init.warnings],
    data_gaps: init.dataGaps ?? [],
  }
}