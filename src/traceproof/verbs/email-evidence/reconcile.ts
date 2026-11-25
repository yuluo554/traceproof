/**
 * 三方对账：报文里的 `Authentication-Results` **vs** 同一份快照上的重算结论。
 *
 * 移植自旧仓 `modules/reconcile.py` 的判定骨架，三分类原样保留：
 * `consistent` / `contradiction` / `undecidable`。三条 fail-closed 纪律：
 *
 * 1. `authserv-id` 不在 `trusted_authserv_ids` 里 → `undecidable`；
 * 2. 头不可解析 → `undecidable`（不把别人写的头当成有效证据）；
 * 3. 重算侧给不出可比结论 → `undecidable`。
 *
 * `trusted_authserv_ids` 为空**不等于**全部可信 —— 空列表下任何声称都不是证据。
 * 每条 `contradiction` 给 ≥2 条可能解释 + 各自要查什么；解释里不出现定性词。
 */

import { Snapshot, normalizeDnsName } from './snapshot.js'
import type { DkimResult, Message, SpfResult } from './index-types.js'
import type { DmarcResult } from './dmarc.js'

export const REF_AR_HEADER = 'RFC8601#2.5'
export const REF_AR_RESULTS = 'RFC8601#5'
export const REF_AR_PROPERTIES = 'RFC8601#4.1'
export const REF_AR_FOREIGN = 'RFC8601#7.1'
export const REF_RECEIVED = 'RFC5321#4.4'
export const REF_RECEIVED_DATE = 'RFC5322#3.6.7'
export const REF_SPF = 'RFC7208#4.6.4'
export const REF_DKIM = 'RFC6376#6.1.3'
export const REF_DMARC = 'RFC9989#4.10'

export const RECONCILE_MIN_EXPLANATIONS = 2
export const RECONCILE_CLASSES = ['consistent', 'contradiction', 'undecidable'] as const

const AUTHSERV_ID = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/
const METHOD = /^[a-z][a-z0-9-]*$/
const AR_RESULTS = new Set([
  'none',
  'neutral',
  'pass',
  'fail',
  'softfail',
  'temperror',
  'permerror',
  'undecidable',
  'unknown',
])

export interface ArClaim {
  index: number
  authserv_id: string | null
  authserv_version: string | null
  method: string
  result: string | null
  reason: string | null
  properties: Array<[string, string]>
  parse_note: string | null
}

export interface ReconcileEntry {
  class: string
  claimed: Record<string, unknown>
  recomputed: Record<string, unknown>
  explanations: Array<{ hypothesis: string; verify: string }>
  warnings: string[]
}

export interface ReconcileResult {
  class: string
  entries: ReconcileEntry[]
  authserv_ids: string[]
  trusted_authserv_ids: string[]
  notes: string[]
  evidence_ref: string[]
}

export function parseAuthenticationResults(message: Message): ArClaim[] {
  const values = message.fields
    .filter((field) => field.name.toString('latin1').trim().toLowerCase() === 'authentication-results')
    .map((field) => field.value.toString('latin1'))
  const claims: ArClaim[] = []
  values.forEach((value, index) => {
    claims.push(...parseOne(value, index))
  })
  return claims
}

function parseOne(value: string, index: number): ArClaim[] {
  const text = value.split(/\s+/).filter(Boolean).join(' ')
  if (!text) {
    return [broken(index, null, 'Authentication-Results 头为空')]
  }
  const segments = splitTopLevel(text, ';')
  const tokens = segments[0].trim().split(/\s+/).filter(Boolean)
  let authservId: string | null = null
  let authservVersion: string | null = null
  if (tokens.length === 1) {
    authservId = tokens[0]
  } else if (tokens.length === 2 && /^\d+$/.test(tokens[1])) {
    authservId = tokens[0]
    authservVersion = tokens[1]
  } else {
    return [broken(index, null, `authserv-id 段有 ${tokens.length} 个 token（${tokens.slice(0, 4).join(' ')}），既不是一个 authserv-id，也不是「authserv-id + 版本号」→ 按不可解析处理`)]
  }
  if (authservId === null || !AUTHSERV_ID.test(authservId)) {
    return [broken(index, authservId, `authserv-id <${authservId}> 不是合法的 dot-atom（RFC 8601 §2.5）`)]
  }

  const out: ArClaim[] = []
  for (const rawSegment of segments.slice(1)) {
    const segment = rawSegment.trim()
    if (!segment || segment.toLowerCase() === 'none') continue
    out.push(parseSegment(segment, index, authservId, authservVersion))
  }
  if (out.length === 0) {
    out.push({
      index,
      authserv_id: authservId,
      authserv_version: authservVersion,
      method: '*',
      result: null,
      reason: null,
      properties: [],
      parse_note: '这张头里没有任何 method=result 声明（只有 authserv-id / 显式 none）',
    })
  }
  return out
}

function parseSegment(segment: string, index: number, authservId: string, version: string | null): ArClaim {
  const reasonMatch = segment.match(/\(([^)]*)\)/)
  const reason = reasonMatch ? reasonMatch[1].trim() || null : null
  const core = segment.replace(/\([^)]*\)/g, ' ').trim()
  const parts = core.split(/\s+/).filter(Boolean)
  if (parts.length === 0) {
    return broken(index, authservId, `method 段只剩括号注释（<${segment.slice(0, 40)}>）`, version)
  }

  const head = parts[0]
  let method: string
  let result: string | null
  const equals = head.indexOf('=')
  if (equals >= 0) {
    method = head.slice(0, equals)
    result = head.slice(equals + 1).trim().toLowerCase() || null
  } else {
    method = head
    result = 'none'
  }
  method = method.trim().toLowerCase()

  const properties: Array<[string, string]> = []
  for (const token of parts.slice(1)) {
    const sep = token.indexOf('=')
    if (sep >= 0) properties.push([token.slice(0, sep).trim(), token.slice(sep + 1).trim()])
    else properties.push([token.trim(), ''])
  }

  let parseNote: string | null = null
  if (!METHOD.test(method)) {
    parseNote = `method <${method}> 不是合法关键字`
    result = null
  } else if (result !== null && !AR_RESULTS.has(result)) {
    parseNote = `result <${result}> 不在本工具的结果枚举里（RFC 8601 §2.7）`
    result = null
  }
  return {
    index,
    authserv_id: authservId,
    authserv_version: version,
    method,
    result,
    reason,
    properties,
    parse_note: parseNote,
  }
}

function broken(index: number, authservId: string | null, note: string, version: string | null = null): ArClaim {
  return {
    index,
    authserv_id: authservId,
    authserv_version: version,
    method: '*',
    result: null,
    reason: null,
    properties: [],
    parse_note: note,
  }
}

function splitTopLevel(text: string, delimiter: string): string[] {
  const parts: string[] = []
  let depth = 0
  let current = ''
  for (const char of text) {
    if (char === '(') depth += 1
    else if (char === ')' && depth > 0) depth -= 1
    if (char === delimiter && depth === 0) {
      parts.push(current)
      current = ''
      continue
    }
    current += char
  }
  parts.push(current)
  return parts
}

function property(claim: ArClaim, name: string): string | null {
  const wanted = name.toLowerCase()
  for (const [key, value] of claim.properties) {
    if (key.toLowerCase() === wanted) return value
  }
  return null
}

function recomputeIndex(spf: SpfResult | null, dkim: DkimResult | null, dmarc: DmarcResult | null): {
  spf: string | null
  dmarc: string | null
  dkim: string | null
  dkimPerDomain: Map<string, string>
  dkimSignatures: number
} {
  const perDomain = new Map<string, string>()
  const results: string[] = []
  for (const signature of dkim?.signatures ?? []) {
    results.push(signature.result)
    if (signature.domain) perDomain.set(normalizeDnsName(signature.domain), signature.result)
  }
  let aggregate: string | null = null
  if (dkim !== null) {
    if (results.includes('pass')) aggregate = 'pass'
    else if (results.some((item) => ['fail', 'permerror', 'softfail'].includes(item))) aggregate = 'fail'
    else if (results.includes('undecidable')) aggregate = 'undecidable'
    else aggregate = 'none'
  }
  return {
    spf: spf?.result ?? null,
    dmarc: dmarc?.result ?? null,
    dkim: aggregate,
    dkimPerDomain: perDomain,
    dkimSignatures: results.length,
  }
}

function recomputedResult(
  method: string,
  claim: ArClaim,
  index: ReturnType<typeof recomputeIndex>,
): { result: string | null; ref: string; note: string } {
  if (method === 'spf') return { result: index.spf, ref: REF_SPF, note: '' }
  if (method === 'dmarc') return { result: index.dmarc, ref: REF_DMARC, note: '' }
  if (method === 'dkim') {
    const domain = property(claim, 'header.d')
    if (domain) {
      const found = index.dkimPerDomain.get(domain.toLowerCase())
      if (found === undefined) {
        return {
          result: null,
          ref: REF_DKIM,
          note: `报文里没有 d=${domain} 的 DKIM 签名（claimed 提到的那条签名不在本工具看到的签名集里）→ 判无法判定`,
        }
      }
      return { result: found, ref: REF_DKIM, note: '' }
    }
    return { result: index.dkim, ref: REF_DKIM, note: 'claimed 的 dkim 段没有 header.d，按全部签名的聚合结果比较' }
  }
  if (method === 'auth' || method === 'iprev') {
    return { result: null, ref: REF_AR_RESULTS, note: `method <${method}> 不属于本工具重算的范围（只重算 spf / dkim / dmarc）→ 判无法判定` }
  }
  return { result: null, ref: REF_AR_RESULTS, note: `method <${method}> 本工具不重算 → 判无法判定（不猜）` }
}

function hypotheses(method: string): Array<{ hypothesis: string; verify: string }> {
  if (method === 'spf') {
    return [
      {
        hypothesis: '报文经过的中间 MTA 在 SPF 求值之后改写了信封发件人，两张记录描述的不是同一个 MAIL FROM 身份',
        verify: '查 Received 链里每一跳的 MAIL FROM 是否与 query.mail_from 一致',
      },
      {
        hypothesis: '快照抓取时点与报文声称的求值时点不同，SPF 记录在此期间被发布方修改',
        verify: '比较 snap.fetched_at 与报文 Received 里的字面时间，必要时重抓该域 TXT',
      },
    ]
  }
  if (method === 'dkim') {
    return [
      {
        hypothesis: '内容网关在验签之后重写了正文，报文头记录的是改写前的结论',
        verify: '按 l= 边界比对规范化正文，确认 bh 覆盖范围是否被改写',
      },
      {
        hypothesis: '报文在归档途中被重新编码（换行或字符集），正文哈希因此与签名时不同',
        verify: '用归档前的原始字节重算 bh=，并与快照里的选择器公钥重新验签',
      },
    ]
  }
  if (method === 'dmarc') {
    return [
      {
        hypothesis: '声称方使用的对齐模式（adkim/aspf）与本工具从记录里读到的不一致',
        verify: '核对快照里 _dmarc 记录的 adkim= / aspf= 与声称方公布的策略是否同一版',
      },
      {
        hypothesis: '声称方与本文具读到的策略记录不是同一时间点的版本',
        verify: '比较 snap.fetched_at 与声称头的 authserv-id 所在 MTA 的策略缓存时间',
      },
    ]
  }
  return [
    {
      hypothesis: '该方法不在本工具的重算范围内，声称值与重算值本就不在同一口径上',
      verify: '确认该 method 的重算能力边界（本工具只重算 spf / dkim / dmarc）',
    },
    {
      hypothesis: '声称头里的属性（如 header.d）指向的签名不在本工具看到的签名集里',
      verify: '逐条比对报文里的 DKIM-Signature d= / s= 与声称头属性',
    },
  ]
}

export function reconcileEvaluate(
  message: Message | null,
  spf: SpfResult | null,
  dkim: DkimResult | null,
  dmarc: DmarcResult | null,
  trustedAuthservIds: readonly string[],
): ReconcileResult {
  const trusted = [...trustedAuthservIds]
  const trustedLower = new Set(trusted.map((item) => item.toLowerCase()))
  const claims = message === null ? [] : parseAuthenticationResults(message)
  const index = recomputeIndex(spf, dkim, dmarc)
  const notes: string[] = []
  const entries: ReconcileEntry[] = []
  const authservSeen: string[] = []

  for (const claim of claims) {
    if (claim.authserv_id && !authservSeen.includes(claim.authserv_id)) authservSeen.push(claim.authserv_id)
    entries.push(reconcileOne(claim, index, trustedLower))
  }

  if (trusted.length === 0) {
    notes.push(
      'query 的 trusted_authserv_ids 为空：没有配置任何可信 MTA，因此报文头里的 Authentication-Results 一律不作为证据（判 undecidable）。空列表不是「全部可信」——那是把可信判断交给写信头的人（RFC 8601 §7.1）',
    )
  }
  if (claims.length === 0) notes.push('报文里没有 Authentication-Results 头，本次没有可对账的声称值')

  let overall = 'none'
  if (entries.some((entry) => entry.class === 'contradiction')) overall = 'contradiction'
  else if (entries.some((entry) => entry.class === 'undecidable')) overall = 'undecidable'
  else if (entries.length > 0) overall = 'consistent'

  return {
    class: overall,
    entries,
    authserv_ids: authservSeen,
    trusted_authserv_ids: trusted,
    notes,
    evidence_ref: [REF_AR_HEADER, REF_AR_RESULTS, REF_RECEIVED, REF_RECEIVED_DATE, REF_AR_FOREIGN],
  }
}

function reconcileOne(claim: ArClaim, index: ReturnType<typeof recomputeIndex>, trustedLower: Set<string>): ReconcileEntry {
  const claimed = {
    authserv_id: claim.authserv_id,
    authserv_version: claim.authserv_version,
    method: claim.method,
    result: claim.result,
    header_d: property(claim, 'header.d'),
  }
  const warnings: string[] = []
  const trusted = claim.authserv_id !== null && trustedLower.has(claim.authserv_id.toLowerCase())

  if (claim.parse_note !== null) {
    warnings.push(`头不可解析：${claim.parse_note} → fail-closed 判无法判定（RFC 8601 §2.5）`)
    return { class: 'undecidable', claimed, recomputed: { result: null, ref: REF_AR_HEADER }, explanations: [], warnings }
  }
  if (!trusted) {
    warnings.push(`authserv-id <${claim.authserv_id}> 不在 trusted_authserv_ids=${trustedLower.size > 0 ? [...trustedLower].sort().join('、') : '（空）'} 里 → fail-closed 判无法判定`)
    const view = recomputedResult(claim.method, claim, index)
    return { class: 'undecidable', claimed, recomputed: { result: view.result, ref: view.ref }, explanations: [], warnings }
  }

  const view = recomputedResult(claim.method, claim, index)
  if (view.note) warnings.push(view.note)
  if (claim.result === null || view.result === null || view.result === 'undecidable' || claim.result === 'unknown') {
    return { class: 'undecidable', claimed, recomputed: { result: view.result, ref: view.ref }, explanations: [], warnings }
  }
  if (claim.result === view.result) {
    return { class: 'consistent', claimed, recomputed: { result: view.result, ref: view.ref }, explanations: [], warnings }
  }
  const explanations = hypotheses(claim.method)
  return { class: 'contradiction', claimed, recomputed: { result: view.result, ref: view.ref }, explanations, warnings }
}

/** 一张头的 `authserv-id` 是否可信（给 claim 层做前置判断）。 */
export function hasTrustedAuthserv(result: ReconcileResult): boolean {
  return result.trusted_authserv_ids.length > 0
}

/** 未使用但保留：快照版本只用于证据，不参与对账判定。 */
export function snapshotVersionNote(snap: Snapshot): string {
  return `snapshot ${snap.data.resolver} @ ${snap.data.fetched_at}`
}