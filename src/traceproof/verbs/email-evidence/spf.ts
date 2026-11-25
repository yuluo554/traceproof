/**
 * SPF 求值器（RFC 7208 §4–§7）：确定性、可复算、预算逐格可读。
 *
 * 移植自旧仓 `modules/spf.py`，四条设计约束原样保留：
 *
 * 1. **只从快照取值**。`found=false` 一律记数据缺口 → `DataGap`，绝不落到 `none`；
 * 2. **先校验、后求值**（§4.6）：任何位置的语法错都是 `permerror`；
 * 3. **超限不抛异常**：`Budget` 只记账并置 `limit_hit`，后果由求值层决定
 *    （term / MX 超限 → permerror；void 超限 → `undecidable` + 告警）；
 * 4. **include 树完整展开**：诊断树用独立 shadow 上下文，不参与判定。
 *
 * 三处与 RFC 字面差异（与旧仓一致，见 `docs/email-evidence.md`）：void 超限判
 * `undecidable`（SHOULD 级）、PTR 超限只取前 10 条、`%{p}` 缺 PTR 且由含该宏的
 * 机制决定结果时降级 `undecidable`。
 */

import {
  DataGap,
  PermError,
  Snapshot,
  TempError,
  UndecidableError,
  normalizeDnsName,
} from './snapshot.js'
import { cidrMatch, ipAddressText, ipv6DottedNibbles, parseIp, reverseLookupName, unmapIp } from './ip.js'
import type { IpAddress } from './ip.js'

//: 预算常量（RFC 7208 §4.6.4）。
export const SPF_MAX_TERMS = 10
export const SPF_MAX_MX = 10
export const SPF_MAX_PTR = 10
export const SPF_MAX_VOID = 2
export const SPF_MAX_DEPTH = 20
export const SPF_TREE_MAX_NODES = 256

// ── 条款号（evidence_ref 的唯一来源） ───────────────────────────────────
export const REF_INITIAL = 'RFC7208#4.3'
export const REF_RESULTS = 'RFC7208#2.6'
export const REF_SELECT = 'RFC7208#4.5'
export const REF_SYNTAX = 'RFC7208#4.6.1'
export const REF_QUALIFIER = 'RFC7208#4.6.2'
export const REF_DEFAULT = 'RFC7208#4.7'
export const REF_LIMITS = 'RFC7208#4.6.4'
export const REF_INCLUDE = 'RFC7208#5.2'
export const REF_REDIRECT = 'RFC7208#6.1'
export const REF_EXP = 'RFC7208#6.2'
export const REF_MACRO = 'RFC7208#7.1'

const REF_BY_MECHANISM: Record<string, string> = {
  all: 'RFC7208#5.1',
  include: REF_INCLUDE,
  a: 'RFC7208#5.3',
  mx: 'RFC7208#5.4',
  ptr: 'RFC7208#5.5',
  ip4: 'RFC7208#5.6',
  ip6: 'RFC7208#5.6',
  exists: 'RFC7208#5.7',
}

// ── 语法 ────────────────────────────────────────────────────────────────
const RE_SPF = /^v=spf1$|^v=spf1 /i
const RE_MODIFIER = /^([a-z][a-z0-9_\-.]*)=/i
const RE_DUAL_CIDR = /\/\/(0|[1-9]\d*)$/
const RE_CIDR = /\/(0|[1-9]\d*)$/
const RE_IP4 = /^(?:(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/
const PAT_CHAR = '%(%|_|-|(\\{[^\\}]*\\}))'
const RE_CHAR = new RegExp(PAT_CHAR, 'g')
const RE_INVALID_MACRO = /(?<!%)%[^{%_-]|%$/
const RE_ARGS = /^([0-9]*)(r?)([^0-9a-zA-Z]*)/
const RE_TOPLAB_END = new RegExp(
  `(?:\\.(?:[0-9a-z]*[a-z][0-9a-z]*|[0-9a-z]+-[0-9a-z-]*[0-9a-z])\\.?|${PAT_CHAR})$`,
  'i',
)

const QUALIFIERS: Record<string, string> = { '+': 'pass', '-': 'fail', '?': 'neutral', '~': 'softfail' }
const MECHANISMS = ['a', 'mx', 'ptr', 'exists', 'include', 'ip4', 'ip6', 'all']
const TERM_MECHANISMS = ['a', 'mx', 'ptr', 'exists', 'include']
const COMMON_MISTAKES: Record<string, string> = {
  prt: 'ptr',
  ip: 'ip4',
  ipv4: 'ip4',
  ipv6: 'ip6',
  'all.': 'all',
}
const MACRO_LETTERS = 'slodipvhcrte' // e 不是宏字母；见下方校验（与旧仓白名单严格一致）
const EXP_ONLY_LETTERS = 'crt'
const JOINERS: Record<string, string> = { l: '.', s: '.' }
const UNRESERVED = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/'.split(''))
const MAX_NAME_LENGTH = 253

export interface TraceNote {
  readonly node: string
  readonly note: string
}

export interface BudgetCell {
  used: number
  limit: number | null
  ref: string
  limit_kind?: string
}

export interface BudgetEntry {
  kind: string
  node_id: string
  used: number
  ref: string
}

export class Budget {
  readonly cells: Record<string, BudgetCell> = {
    terms: { used: 0, limit: SPF_MAX_TERMS, ref: REF_LIMITS },
    mx: { used: 0, limit: SPF_MAX_MX, ref: REF_LIMITS },
    ptr: { used: 0, limit: SPF_MAX_PTR, ref: REF_LIMITS },
    void: { used: 0, limit: SPF_MAX_VOID, ref: REF_LIMITS, limit_kind: 'SHOULD' },
    depth: { used: 0, limit: SPF_MAX_DEPTH, ref: REF_INCLUDE },
  }
  readonly entries: BudgetEntry[] = []
  limitHit = false
  readonly hits: string[] = []

  consume(kind: string, nodeId: string, ref?: string): boolean {
    const cell = this.cells[kind]
    cell.used += 1
    this.entries.push({ kind, node_id: nodeId, used: cell.used, ref: ref ?? cell.ref })
    return this.within(kind)
  }

  observe(kind: string, count: number, nodeId: string, ref?: string): boolean {
    const cell = this.cells[kind]
    cell.used = Math.max(cell.used, count)
    this.entries.push({ kind, node_id: nodeId, used: cell.used, ref: ref ?? cell.ref })
    return this.within(kind)
  }

  private within(kind: string): boolean {
    const cell = this.cells[kind]
    if (cell.limit === null || cell.used <= cell.limit) return true
    this.limitHit = true
    if (!this.hits.includes(kind)) this.hits.push(kind)
    return false
  }

  toJSON(): Record<string, BudgetCell> {
    const out: Record<string, BudgetCell> = {}
    for (const [kind, cell] of Object.entries(this.cells)) out[kind] = { ...cell }
    return out
  }
}

export interface SpfResult {
  result: string
  reason: string
  domain: string
  record: string | null
  evidence_ref: string[]
  trace: TraceNote[]
  budget: Record<string, BudgetCell>
  budget_entries: BudgetEntry[]
  tree: TreeNode | null
  warnings: string[]
  gray_areas: string[]
  limit_hit: boolean
  limit_hits: string[]
  cut_point: Record<string, unknown> | null
  mechanism: string | null
  explanations: Array<{ domain: string; text: string; ref: string }>
  data_gap: [string, string] | null
}

export interface TreeNode {
  node_id: string
  parent: string | null
  domain: string
  record: string | null
  mechanism: string | null
  child_result: string | null
  consumes_term: boolean
  terminates_parent: boolean
  receiver_would_stop_here: boolean
  children: TreeNode[]
  note?: string
}

interface Lookup {
  status: 'ok' | 'empty' | 'nxdomain'
  answers: readonly string[]
  note: string
}

function isVoid(lookup: Lookup): boolean {
  return lookup.status === 'empty' || lookup.status === 'nxdomain'
}

function nameIsQueryable(name: string): boolean {
  if (!name) return false
  return name.split('.').every((label) => label.length > 0 && label.length <= 63)
}

interface Mechanism {
  token: string
  name: string
  arg: string | null
  cidr: number
  result: string
  rawArg: string | null
}

class Ctx {
  readonly ip: IpAddress
  readonly v: 'in-addr' | 'ip6'
  readonly aQtype: 'A' | 'AAAA'
  readonly cidrmax: number
  readonly i: string
  readonly h: string
  readonly r: string
  readonly c: string
  readonly l: string
  s: string
  o: string
  d: string
  readonly snap: Snapshot
  readonly budget: Budget
  readonly trace: TraceNote[]
  private readonly cache = new Map<string, Lookup>()
  private ptrCache: readonly string[] | null = null
  pUnavailable = false
  pDecided = false
  voidExceeded = false
  voidNote = ''
  readonly warnings: string[] = []
  readonly gray: string[] = []
  readonly explanations: Array<{ domain: string; text: string; ref: string }> = []

  constructor(
    snap: Snapshot,
    ipText: string,
    helo: string | null,
    options: {
      budget: Budget
      trace: TraceNote[]
      local?: string | null
      sender?: string | null
      receiver?: string | null
    },
  ) {
    const parsed = parseIp(String(ipText).trim())
    if (parsed === null) throw new PermError(`client_ip 不是合法 IP：<${ipText}>`)
    const address = unmapIp(parsed)
    this.ip = address
    if (address.version === 4) {
      this.v = 'in-addr'
      this.aQtype = 'A'
      this.cidrmax = 32
      this.i = ipAddressText(address)
    } else {
      this.v = 'ip6'
      this.aQtype = 'AAAA'
      this.cidrmax = 128
      this.i = ipv6DottedNibbles(address.bytes)
    }
    this.snap = snap
    this.budget = options.budget
    this.trace = options.trace
    this.h = helo ? helo : 'unknown'
    this.r = options.receiver ?? 'unknown'
    this.c = ipAddressText(address)

    if (options.sender !== undefined && options.sender !== null) {
      const sender = options.sender
      this.s = sender
      const at = sender.indexOf('@')
      const localPart = at >= 0 ? sender.slice(0, at) : sender
      const senderDomain = at >= 0 ? sender.slice(at + 1) : ''
      this.l = localPart || 'postmaster'
      this.o = senderDomain || ''
    } else {
      this.l = options.local ?? 'postmaster'
      this.o = ''
      this.s = this.o ? `${this.l}@${this.o}` : this.l
    }
    this.d = ''
  }

  lookup(name: string, qtype: string, nodeId: string, ignoreVoid = false): Lookup {
    const qname = normalizeDnsName(name)
    const type = qtype.toUpperCase()
    if (!nameIsQueryable(qname)) {
      this.trace.push({
        node: nodeId,
        note: `${qname}/${type} 名字不可查（非法域名），按不存在处理`,
      })
      return { status: 'empty', answers: [], note: '名字不可查（非法域名）' }
    }
    const cacheKey = `${qname}\u0000${type}`
    const cached = this.cache.get(cacheKey)
    if (cached !== undefined) return cached

    const resolved = this.snap.resolve(qname, type)
    if (!resolved.found) throw new DataGap(qname, type)
    const rcode = (resolved.rcode ?? '').toUpperCase()
    if (rcode === 'TIMEOUT') throw new TempError(`查询超时：${qname}/${type}`)
    let lookup: Lookup
    if (rcode === 'NXDOMAIN') {
      lookup = { status: 'nxdomain', answers: [], note: 'NXDOMAIN' }
    } else if (rcode !== 'NOERROR') {
      throw new TempError(`查询失败：${qname}/${type} → rcode=${rcode}`)
    } else if (resolved.answer.length > 0) {
      lookup = { status: 'ok', answers: resolved.answer, note: '' }
      this.cache.set(cacheKey, lookup)
    } else {
      lookup = { status: 'empty', answers: [], note: 'NOERROR 但无记录' }
    }

    this.trace.push({
      node: nodeId,
      note: resolved.found
        ? `${resolved.qname}/${resolved.qtype} → rcode=${resolved.rcode} answer=${resolved.answer.length} 条（queries[${String(resolved.index)}]）`
        : `${qname}/${type} 未在快照中查询（数据缺口，不等同于不存在）`,
    })
    if (isVoid(lookup) && !ignoreVoid) this.countVoid(nodeId, `${qname}/${type}`)
    return lookup
  }

  private countVoid(nodeId: string, what: string): void {
    if (this.budget.consume('void', nodeId, REF_LIMITS)) return
    // 项目口径：void 上限是 SHOULD，突破不硬判 permerror；由 checkHost 统一裁决。
    if (!this.voidExceeded) {
      this.voidExceeded = true
      this.voidNote = what
    }
  }

  spfRecord(domain: string, nodeId: string): string | null {
    const lookup = this.lookup(domain, 'TXT', nodeId)
    const candidates = lookup.answers.filter((text) => RE_SPF.test(text))
    if (candidates.length > 1) {
      throw new PermError(
        `${domain} 有 ${candidates.length} 条 v=spf1 TXT 记录（RFC 7208 §4.5/6：多条即 permerror）`,
      )
    }
    if (candidates.length === 0) return null
    const record = candidates[0]
    if (!isAscii(record)) {
      throw new PermError(
        `${domain} 的 SPF 记录含非 ASCII 字符（RFC 7208 §3.1：策略只许 7-bit ASCII）`,
      )
    }
    return record
  }

  dnsA(name: string, nodeId: string): readonly string[] {
    return this.lookup(name, this.aQtype, nodeId).answers
  }

  dnsMx(domain: string, nodeId: string): readonly string[] {
    const answers = this.lookup(domain, 'MX', nodeId).answers
    const within = this.budget.observe('mx', answers.length, nodeId)
    if (answers.length > SPF_MAX_MX || !within) {
      throw new PermError(
        `${domain} 返回 ${answers.length} 条 MX 记录，超过 ${SPF_MAX_MX} 条上限（RFC 7208 §4.6.4 MUST）`,
      )
    }
    const exchanges: Array<[number, string]> = []
    for (const answer of answers) {
      const space = answer.indexOf(' ')
      const preference = space >= 0 ? answer.slice(0, space) : answer
      const exchange = space >= 0 ? answer.slice(space + 1) : ''
      const numeric = Number(preference)
      if (space >= 0 && Number.isInteger(numeric)) {
        exchanges.push([numeric, exchange.trim().replace(/\.+$/, '')])
      } else {
        exchanges.push([0, answer.trim().replace(/\.+$/, '')])
      }
    }
    exchanges.sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0] - b[0]))
    const addresses: string[] = []
    for (const [, exchange] of exchanges) {
      if (exchange) addresses.push(...this.dnsA(exchange, nodeId))
    }
    return addresses
  }

  validatedPtrs(nodeId: string): readonly string[] {
    if (this.ptrCache !== null) return this.ptrCache
    const reverse = reverseLookupName(this.ip)
    let names = this.lookup(reverse, 'PTR', nodeId).answers
    this.budget.observe('ptr', names.length, nodeId)
    if (names.length > SPF_MAX_PTR) {
      this.warnings.push(
        `${reverse} 返回 ${names.length} 条 PTR，超过 ${SPF_MAX_PTR} 条；按 RFC 7208 §4.6.4 只取前 ${SPF_MAX_PTR} 条`,
      )
      names = names.slice(0, SPF_MAX_PTR)
    }
    const validated: string[] = []
    for (const name of names) {
      const target = name.trim().replace(/\.+$/, '')
      if (!target) continue
      if (cidrMatch(this.dnsA(target, nodeId), this.cidrmax, this.ip)) validated.push(target)
    }
    this.ptrCache = validated
    return this.ptrCache
  }

  pValue(nodeId: string): string {
    const validated = this.validatedPtrs(nodeId)
    if (validated.length === 0) {
      if (!this.pUnavailable) {
        this.pUnavailable = true
        this.gray.push(
          '%{p} 被使用，但连接 IP 没有可验证的 PTR（RFC 7208 §7.3 展开为 unknown）；本条不默认判 fail（灰区 4）',
        )
      }
      return 'unknown'
    }
    const current = normalizeDnsName(this.d)
    for (const name of validated) {
      if (normalizeDnsName(name) === current) return name
    }
    const suffix = `.${current}`
    for (const name of validated) {
      if (normalizeDnsName(name).endsWith(suffix)) return name
    }
    return validated[0]
  }

  expand(text: string, nodeId: string, options: { stripdot?: boolean; inExp?: boolean } = {}): string {
    const stripdot = options.stripdot ?? true
    const inExp = options.inExp ?? false
    if (RE_INVALID_MACRO.test(text)) {
      throw new PermError(
        `宏语法错：% 后面必须是 { / % / - / _（RFC 7208 §7.1/9）：<${text}>`,
      )
    }
    const pieces: string[] = []
    let end = 0
    for (const match of text.matchAll(RE_CHAR)) {
      const index = match.index ?? 0
      pieces.push(text.slice(end, index))
      const macro = match[0]
      if (macro === '%%') pieces.push('%')
      else if (macro === '%_') pieces.push(' ')
      else if (macro === '%-') pieces.push('%20')
      else pieces.push(this.expandMacro(macro, nodeId, inExp))
      end = index + macro.length
    }
    pieces.push(text.slice(end))
    let result = pieces.join('')
    if (stripdot && result.endsWith('.')) result = result.slice(0, -1)
    while (result.length > MAX_NAME_LENGTH && result.includes('.')) {
      result = result.slice(result.indexOf('.') + 1)
    }
    return result
  }

  private expandMacro(macro: string, nodeId: string, inExp: boolean): string {
    const letterRaw = macro[2]
    const letter = letterRaw.toLowerCase()
    if (!MACRO_LETTERS.includes(letter)) {
      throw new PermError(`未知宏字母 %{${letterRaw}}（允许：${MACRO_LETTERS}）`)
    }
    if (EXP_ONLY_LETTERS.includes(letter) && !inExp) {
      throw new PermError(`宏 %{${letterRaw}} 只允许出现在 exp 文本里（RFC 7208 §7.1/8）`)
    }
    let value: string
    if (letter === 'p') {
      value = this.pValue(nodeId)
    } else if (letter === 'd') {
      value = this.d
    } else if (letter === 't') {
      this.warnings.push(
        '%{t} 需要系统时钟；本项目判定路径零时钟，解释文本里的时间戳不展开',
      )
      throw new PermError('%{t} 需要系统时钟，判定路径按零时钟，无法展开')
    } else {
      const map: Record<string, string> = {
        s: this.s,
        l: this.l,
        o: this.o,
        i: this.i,
        h: this.h,
        v: this.v,
        c: this.c,
        r: this.r,
      }
      const found = map[letter]
      if (found === undefined) throw new PermError(`未知宏字母 %{${letterRaw}}`)
      value = found
    }
    const args = macro.slice(3, -1)
    let expansion = expandOne(value, args, JOINERS[letter])
    if (letter !== letterRaw) expansion = urlQuote(expansion)
    return expansion
  }

  expandDomain(raw: string | null, nodeId: string, inExp = false): string {
    if (raw === null) throw new PermError('domain-spec 缺失')
    if (!RE_TOPLAB_END.test(raw)) {
      throw new PermError(`domain-spec 不是合法域名（需以合法 toplabel 或宏结尾）：<${raw}>`)
    }
    return this.expand(raw, nodeId, { inExp })
  }
}

function isAscii(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) > 0x7f) return false
  }
  return true
}

function expandOne(value: string, args: string, joiner: string | undefined): string {
  if (!args) return value
  const match = args.match(RE_ARGS)
  if (match === null) return value
  let countText = match[1]
  const reverse = match[2] === 'r'
  let delimiters = match[3]
  if (!delimiters) delimiters = '.'
  let parts = splitKeep(value, delimiters, joiner)
  if (reverse) parts = [...parts].reverse()
  if (countText) {
    const count = Number(countText)
    const start = 1 - count * 2
    parts = start < 0 ? parts.slice(parts.length + start) : parts.slice(start)
  }
  return parts.join('')
}

function splitKeep(value: string, delimiters: string, joiner: string | undefined): string[] {
  const result: string[] = []
  let element = ''
  for (const char of value) {
    if (delimiters.includes(char)) {
      result.push(element)
      element = ''
      result.push(joiner ?? char)
    } else {
      element += char
    }
  }
  result.push(element)
  return result
}

function urlQuote(text: string): string {
  const bytes = Buffer.from(text, 'utf8')
  const out: string[] = []
  for (const byte of bytes) {
    const char = String.fromCharCode(byte)
    out.push(UNRESERVED.has(char) ? char : `%${byte.toString(16).toUpperCase().padStart(2, '0')}`)
  }
  return out.join('')
}

function parseMechanism(token: string, defaultDomain: string): {
  name: string
  arg: string | null
  cidr: number | null
  cidr6: number | null
} {
  let head = token
  let cidr6: number | null = null
  const dual = head.match(RE_DUAL_CIDR)
  if (dual !== null && dual.index !== undefined) {
    cidr6 = Number(dual[1])
    head = head.slice(0, dual.index)
  }
  let cidr: number | null = null
  const single = head.match(RE_CIDR)
  if (single !== null && single.index !== undefined) {
    cidr = Number(single[1])
    head = head.slice(0, single.index)
  }
  const colon = head.indexOf(':')
  const name = (colon >= 0 ? head.slice(0, colon) : head).toLowerCase()
  if (colon < 0) {
    return { name, arg: name === 'exists' ? null : defaultDomain, cidr, cidr6 }
  }
  return { name, arg: head.slice(colon + 1), cidr, cidr6 }
}

function validateMechanism(ctx: Ctx, token: string, domain: string, nodeId: string): Mechanism {
  if (token.endsWith(',')) {
    throw new PermError(`机制之间不能用逗号分隔（RFC 7208 §4.6.1/2）：<${token}>`)
  }
  const parsed = parseMechanism(token, domain)
  let name = parsed.name
  let result = 'pass'
  if (name && name[0] in QUALIFIERS) {
    result = QUALIFIERS[name[0]]
    name = name.slice(1)
  }
  if (name in COMMON_MISTAKES) {
    throw new PermError(`疑似拼写错误：<${token}> 应为 <${COMMON_MISTAKES[name]}>（RFC 7208 §4.6.1/4）`)
  }
  if (!MECHANISMS.includes(name)) {
    throw new PermError(`未知机制 <${token}>（RFC 7208 §4.6.1/4）`)
  }

  let cidr = parsed.cidr
  let cidr6 = parsed.cidr6
  let effective: number
  if (name === 'a' || name === 'mx') {
    if (cidr === null) cidr = 32
    else if (cidr > 32) throw new PermError(`IPv4 CIDR 超过 32：<${token}>`)
    if (cidr6 === null) cidr6 = 128
    else if (cidr6 > 128) throw new PermError(`IPv6 CIDR 超过 128：<${token}>`)
    effective = ctx.v === 'ip6' ? cidr6 : cidr
  } else if (name === 'ip4') {
    if (cidr6 !== null) throw new PermError(`ip4 不允许 dual-cidr：<${token}>`)
    if (cidr === null) cidr = 32
    else if (cidr > 32) throw new PermError(`IPv4 CIDR 超过 32：<${token}>`)
    if (!parsed.arg || !RE_IP4.test(parsed.arg)) {
      throw new PermError(`ip4 地址不合法（不允许省略段或带端口）：<${token}>`)
    }
    effective = cidr
  } else if (name === 'ip6') {
    if (cidr6 !== null) throw new PermError(`ip6 不允许 dual-cidr：<${token}>`)
    if (cidr === null) cidr = 128
    else if (cidr > 128) throw new PermError(`IPv6 CIDR 超过 128：<${token}>`)
    if (!parsed.arg) throw new PermError(`ip6 地址不合法：<${token}>`)
    const address = parseIp(parsed.arg)
    if (address === null || address.version !== 6 || parsed.arg.includes('/')) {
      throw new PermError(`ip6 地址不合法：<${token}>`)
    }
    effective = cidr
  } else {
    if (cidr !== null || cidr6 !== null) throw new PermError(`${name} 机制不接受 CIDR：<${token}>`)
    effective = ctx.cidrmax
  }

  if (name === 'all') {
    if (token.includes(':')) throw new PermError(`all 机制只允许限定符，不接受参数：<${token}>`)
    return { token, name, arg: null, cidr: effective, result, rawArg: null }
  }
  if (name === 'ip4' || name === 'ip6') {
    return { token, name, arg: parsed.arg, cidr: effective, result, rawArg: null }
  }
  if (TERM_MECHANISMS.includes(name)) {
    if (name === 'exists' && !parsed.arg) throw new PermError(`exists 必须带 domain-spec：<${token}>`)
    const raw = parsed.arg
    const expanded = ctx.expandDomain(raw, nodeId)
    if (!expanded) throw new PermError(`${name} 的 domain-spec 为空：<${token}>`)
    if (name === 'include' && normalizeDnsName(expanded) === normalizeDnsName(domain)) {
      throw new PermError(`include 指向自己（trivial recursion）：<${token}>`)
    }
    if (name === 'a' && RE_IP4.test(expanded)) {
      throw new PermError(`a 机制不要用 IP 字面量，请用 ip4：<${token}>`)
    }
    return { token, name, arg: expanded, cidr: effective, result, rawArg: raw }
  }
  throw new PermError(`未知机制 <${token}>`)
}

class Evaluation {
  reason = ''
  mechanism: string | null = null
  refs: string[] = []
  readonly nodeResults = new Map<string, string>()
  cutPoint: Record<string, unknown> | null = null
  termOrdinal = 0
}

function nodeId(path: readonly number[]): string {
  if (path.length === 0) return 'n0'
  return `n${path.join('.')}`
}

function evaluateRecord(
  ctx: Ctx,
  ev: Evaluation,
  domain: string,
  record: string,
  depth: number,
  path: readonly number[],
): string {
  const node = nodeId(path)
  if (depth > SPF_MAX_DEPTH) {
    throw new PermError(`include/redirect 嵌套超过 ${SPF_MAX_DEPTH} 层（RFC 7208 §4.6.4）`)
  }
  ctx.budget.observe('depth', depth, node, REF_INCLUDE)

  const previousDomain = ctx.d
  ctx.d = domain
  try {
    const tokens = record.split(' ').filter((token) => token.length > 0)
    if (tokens.length === 0 || tokens[0].toLowerCase() !== 'v=spf1') return 'none'

    const mechanisms: Array<{ mech: Mechanism; ordinal: number }> = []
    const seenModifiers = new Set<string>()
    let redirectTarget: string | null = null
    let includeOrdinal = 0

    for (const token of tokens.slice(1)) {
      const match = token.match(RE_MODIFIER)
      if (match !== null) {
        const name = match[1].toLowerCase()
        const arg = token.slice(match[0].length)
        if (seenModifiers.has(name)) {
          throw new PermError(`修饰符 ${name}= 出现了不止一次（RFC 7208 §6/2）`)
        }
        seenModifiers.add(name)
        if (name === 'exp') {
          if (!arg) throw new PermError('exp= 的 domain-spec 为空（RFC 7208 §6.2/1）')
          const spec = ctx.expandDomain(arg, node)
          if (depth === 0) fetchExplanation(ctx, spec, node)
        } else if (name === 'redirect') {
          redirectTarget = ctx.expandDomain(arg, node)
          if (!redirectTarget) throw new PermError('redirect= 的 domain-spec 为空（RFC 7208 §6.1/2）')
        } else {
          ctx.expand(arg, node)
        }
        continue
      }
      const mech = validateMechanism(ctx, token, domain, node)
      if (mech.name === 'include') includeOrdinal += 1
      mechanisms.push({ mech, ordinal: includeOrdinal })
    }

    for (const { mech, ordinal } of mechanisms) {
      if (TERM_MECHANISMS.includes(mech.name)) {
        ev.termOrdinal += 1
        if (!ctx.budget.consume('terms', node, REF_LIMITS)) {
          ev.cutPoint = {
            term_ordinal: ev.termOrdinal,
            mechanism: mech.name,
            token: mech.token,
            node_id: node,
            receiver_would_stop_here: true,
          }
          throw new PermError(
            `DNS 查询类 term 超过 ${SPF_MAX_TERMS} 个（RFC 7208 §4.6.4 MUST → permerror）；第 ${ev.termOrdinal} 个是 <${mech.token}>`,
          )
        }
      }
      const childPath = mech.name === 'include' ? [...path, ordinal] : path
      if (mechanismMatches(ctx, ev, mech, childPath, depth)) {
        ev.mechanism = mech.token
        ev.refs.push(REF_BY_MECHANISM[mech.name] ?? REF_RESULTS)
        ev.refs.push(REF_QUALIFIER)
        if (mech.rawArg && usesPMacro(mech.rawArg) && ctx.pUnavailable) ctx.pDecided = true
        return mech.result
      }
    }

    if (redirectTarget !== null) {
      ev.termOrdinal += 1
      if (!ctx.budget.consume('terms', node, REF_LIMITS)) {
        ev.cutPoint = {
          term_ordinal: ev.termOrdinal,
          mechanism: 'redirect',
          token: `redirect=${redirectTarget}`,
          node_id: node,
          receiver_would_stop_here: true,
        }
        throw new PermError(
          `DNS 查询类 term 超过 ${SPF_MAX_TERMS} 个（含 redirect，RFC 7208 §4.6.4）`,
        )
      }
      const childRecord = ctx.spfRecord(redirectTarget, node)
      if (childRecord === null) {
        throw new PermError(`redirect 目标 ${redirectTarget} 没有 SPF 记录（RFC 7208 §6.1/4 → permerror）`)
      }
      ev.refs.push(REF_REDIRECT)
      return evaluateRecord(ctx, ev, redirectTarget, childRecord, depth + 1, path)
    }

    ev.refs.push(REF_DEFAULT)
    return 'neutral'
  } finally {
    ctx.d = previousDomain
  }
}

function usesPMacro(raw: string): boolean {
  return raw.toLowerCase().includes('%{p')
}

function mechanismMatches(
  ctx: Ctx,
  ev: Evaluation,
  mech: Mechanism,
  path: readonly number[],
  depth: number,
): boolean {
  const node = nodeId(path)
  if (mech.name === 'all') return true
  if (mech.name === 'ip4') {
    return ctx.v === 'in-addr' && cidrMatch([mech.arg ?? ''], mech.cidr, ctx.ip)
  }
  if (mech.name === 'ip6') {
    return ctx.v === 'ip6' && cidrMatch([mech.arg ?? ''], mech.cidr, ctx.ip)
  }
  if (mech.name === 'a') return cidrMatch(ctx.dnsA(mech.arg ?? '', node), mech.cidr, ctx.ip)
  if (mech.name === 'mx') return cidrMatch(ctx.dnsMx(mech.arg ?? '', node), mech.cidr, ctx.ip)
  if (mech.name === 'exists') {
    return ctx.lookup(mech.arg ?? '', 'A', node).answers.length > 0
  }
  if (mech.name === 'ptr') {
    const target = normalizeDnsName(mech.arg ?? '')
    return ctx
      .validatedPtrs(node)
      .some((name) => {
        const lowered = normalizeDnsName(name)
        return lowered === target || lowered.endsWith(`.${target}`)
      })
  }
  if (mech.name === 'include') {
    const childRecord = ctx.spfRecord(mech.arg ?? '', node)
    if (childRecord === null) {
      throw new PermError(
        `include 目标 ${mech.arg} 没有 SPF 记录（RFC 7208 §5.2/9 → permerror）`,
      )
    }
    const child = evaluateRecord(ctx, ev, mech.arg ?? '', childRecord, depth + 1, path)
    ev.nodeResults.set(node, child)
    return child === 'pass'
  }
  throw new PermError(`未实现的机制 <${mech.name}>`)
}

function fetchExplanation(ctx: Ctx, spec: string, nodeIdValue: string): void {
  try {
    const lookup = ctx.lookup(spec, 'TXT', nodeIdValue, true)
    if (lookup.answers.length !== 1) {
      ctx.warnings.push(
        `exp=${spec} 的 TXT 记录有 ${lookup.answers.length} 条（需恰好 1 条），已忽略解释文本`,
      )
      return
    }
    const text = ctx.expand(lookup.answers[0], nodeIdValue, { stripdot: false, inExp: true })
    if (!isAscii(text)) {
      ctx.warnings.push(`exp=${spec} 的解释文本含非 ASCII 字符，已忽略`)
      return
    }
    ctx.explanations.push({ domain: spec, text, ref: REF_EXP })
  } catch (error) {
    ctx.warnings.push(`exp=${spec} 取解释文本失败（已忽略）：${(error as Error).message}`)
  }
}

// ── include 树（完整展开，不因第 11 个 term 截断） ──────────────────────

function buildTree(
  ctx: Ctx,
  domain: string,
  record: string,
  path: readonly number[],
  parent: string | null,
  termOrdinal: { value: number },
  seen: readonly string[],
  counter: { value: number },
  mechanism: string | null,
): TreeNode {
  const id = nodeId(path)
  const node: TreeNode = {
    node_id: id,
    parent,
    domain,
    record,
    mechanism,
    child_result: null,
    consumes_term: parent !== null,
    terminates_parent: false,
    receiver_would_stop_here: false,
    children: [],
  }

  const tokens = record.split(' ').filter((token) => token.length > 0)
  const includeTargets: string[] = []
  for (const token of tokens.slice(1)) {
    if (token.match(RE_MODIFIER) !== null) continue
    const parsed = parseMechanism(token, domain)
    let name = parsed.name
    if (name && name[0] in QUALIFIERS) name = name.slice(1)
    if (name !== 'include' || !parsed.arg) continue
    try {
      const expanded = ctx.expand(parsed.arg, id)
      if (expanded) includeTargets.push(expanded)
    } catch {
      // 展开失败不影响判定（树只是诊断）
    }
  }

  node.children = includeTargets.map((target, index) => {
    termOrdinal.value += 1
    return treeChild(ctx, target, [...path, index + 1], id, termOrdinal, seen, counter, 'include')
  })
  return node
}

function treeChild(
  ctx: Ctx,
  target: string,
  path: readonly number[],
  parent: string,
  termOrdinal: { value: number },
  seen: readonly string[],
  counter: { value: number },
  mechanism: string,
): TreeNode {
  const id = nodeId(path)
  const overLimit = termOrdinal.value > SPF_MAX_TERMS
  const normalized = normalizeDnsName(target)
  const child: TreeNode = {
    node_id: id,
    parent,
    domain: target,
    record: null,
    mechanism,
    child_result: null,
    consumes_term: true,
    terminates_parent: false,
    receiver_would_stop_here: overLimit,
    children: [],
  }
  counter.value += 1
  if (overLimit) {
    child.note = `第 ${termOrdinal.value} 个 DNS 查询类 term：收件方会在此处 permerror 停下（RFC 7208 §4.6.4）`
    return child
  }
  if (counter.value > SPF_TREE_MAX_NODES) {
    child.note = `树节点数超过 ${SPF_TREE_MAX_NODES}，停止展开（防环）`
    return child
  }
  if (seen.includes(normalized)) {
    child.note = 'include 成环（该域在本路径上已出现过），停止展开'
    return child
  }
  let record: string | null
  try {
    record = ctx.spfRecord(target, id)
  } catch (error) {
    child.note = `取记录失败：${(error as Error).message}`
    return child
  }
  if (record === null) {
    child.note = '目标域没有 SPF 记录'
    return child
  }
  const nested = buildTree(ctx, target, record, path, parent, termOrdinal, [...seen, normalized], counter, mechanism)
  nested.node_id = id
  nested.parent = parent
  nested.domain = target
  nested.mechanism = mechanism
  nested.consumes_term = true
  nested.receiver_would_stop_here = overLimit
  return nested
}

function fillTreeResults(node: TreeNode, results: Map<string, string>): void {
  for (const child of node.children) {
    child.child_result = results.get(child.node_id) ?? null
    if (child.child_result === 'pass') child.terminates_parent = true
    fillTreeResults(child, results)
  }
}

// ── 对外入口 ────────────────────────────────────────────────────────────

export function checkHost(
  snap: Snapshot,
  ip: string,
  domain: string,
  helo: string | null,
  options: { budget?: Budget; trace?: TraceNote[]; local?: string | null; sender?: string | null; receiver?: string | null } = {},
): SpfResult {
  const budget = options.budget ?? new Budget()
  const trace = options.trace ?? []
  const ctx = new Ctx(snap, ip, helo, {
    budget,
    trace,
    local: options.local,
    sender: options.sender,
    receiver: options.receiver,
  })

  const ev = new Evaluation()
  let record: string | null = null
  const checked = initialDomain(domain)
  ctx.d = checked ?? normalizeDnsName(domain)
  if (!ctx.o) {
    ctx.o = ctx.d
    ctx.s = `${ctx.l}@${ctx.o}`
  }
  let dataGap: [string, string] | null = null

  try {
    if (checked === null) {
      return result(ctx, ev, {
        result: 'none',
        reason: `<${domain}> 不是可检查的多标签域名（RFC 7208 §4.3/1）→ none`,
        domain,
        record: null,
        refs: [REF_INITIAL],
        trace,
        budget,
        tree: null,
      })
    }
    record = ctx.spfRecord(checked, 'n0')
    if (record === null) {
      return result(ctx, ev, {
        result: 'none',
        reason: `${checked} 没有 v=spf1 TXT 记录（RFC 7208 §4.5/1）→ none`,
        domain: checked,
        record: null,
        refs: [REF_SELECT],
        trace,
        budget,
        tree: null,
      })
    }
    trace.push({ node: 'n0', note: `选中记录：${record}` })
    let verdict = evaluateRecord(ctx, ev, checked, record, 0, [])

    if (ctx.pDecided && (verdict === 'fail' || verdict === 'softfail')) {
      ctx.gray.push(
        '结果由含 %{p} 的机制匹配决定，而连接 IP 没有可验证 PTR；按灰区 4 判 undecidable，不默认 fail',
      )
      verdict = 'undecidable'
    }
    if (ctx.voidExceeded && verdict !== 'permerror' && verdict !== 'temperror') {
      verdict = 'undecidable'
      ctx.gray.push(
        `void lookup 超过 ${SPF_MAX_VOID} 次（RFC 7208 §4.6.4 的**限制**是 SHOULD，不是 MUST）；本项目判 undecidable 而非 permerror。超限处：${ctx.voidNote}`,
      )
    }
    const refs = [...new Set(ev.refs)]
    if (refs.length === 0) refs.push(REF_RESULTS)
    if (ev.cutPoint !== null && !refs.includes(REF_LIMITS)) refs.push(REF_LIMITS)

    const root = buildDiagnosticTree(snap, ctx, checked, record, ev)
    return result(ctx, ev, {
      result: verdict,
      reason: reasonFor(verdict, checked, ev.mechanism),
      domain: checked,
      record,
      refs,
      trace,
      budget,
      tree: root,
    })
  } catch (error) {
    let verdict: string
    let reason: string
    let refs: string[]
    if (error instanceof PermError) {
      verdict = 'permerror'
      reason = `permerror：${error.message}`
      refs = ev.cutPoint !== null ? [REF_LIMITS, REF_SYNTAX] : [REF_SYNTAX]
    } else if (error instanceof TempError) {
      verdict = 'temperror'
      reason = `temperror：${error.message}`
      refs = [REF_RESULTS]
    } else if (error instanceof DataGap) {
      dataGap = [error.qname, error.qtype]
      verdict = 'undecidable'
      reason = `undecidable：${error.message}`
      refs = [REF_LIMITS]
    } else if (error instanceof UndecidableError) {
      verdict = 'undecidable'
      reason = `undecidable：${error.message}`
      refs = [REF_LIMITS]
    } else {
      throw error
    }
    const root = record !== null ? buildDiagnosticTree(snap, ctx, checked ?? domain, record, ev) : null
    return result(ctx, ev, {
      result: verdict,
      reason,
      domain: checked ?? normalizeDnsName(domain),
      record,
      refs,
      trace,
      budget,
      tree: root,
      dataGap,
    })
  }
}

function buildDiagnosticTree(
  snap: Snapshot,
  ctx: Ctx,
  checked: string,
  record: string,
  ev: Evaluation,
): TreeNode | null {
  try {
    const shadow = new Ctx(snap, ctx.c, ctx.h === 'unknown' ? null : ctx.h, {
      budget: new Budget(),
      trace: [],
      local: ctx.l,
      sender: ctx.s,
      receiver: ctx.r,
    })
    shadow.d = checked
    const root = buildTree(
      shadow,
      checked,
      record,
      [],
      null,
      { value: 0 },
      [normalizeDnsName(checked)],
      { value: 1 },
      null,
    )
    fillTreeResults(root, ev.nodeResults)
    return root
  } catch (error) {
    ctx.warnings.push(`include 树展开失败（不影响判定）：${(error as Error).message}`)
    return null
  }
}

function result(
  ctx: Ctx,
  ev: Evaluation,
  init: {
    result: string
    reason: string
    domain: string
    record: string | null
    refs: string[]
    trace: TraceNote[]
    budget: Budget
    tree: TreeNode | null
    dataGap?: [string, string] | null
  },
): SpfResult {
  return {
    result: init.result,
    reason: init.reason,
    domain: init.domain,
    record: init.record,
    evidence_ref: [...init.refs],
    trace: [...init.trace],
    budget: init.budget.toJSON(),
    budget_entries: [...init.budget.entries],
    tree: init.tree,
    warnings: [...ctx.warnings],
    gray_areas: [...ctx.gray],
    limit_hit: init.budget.limitHit,
    limit_hits: [...init.budget.hits],
    cut_point: ev.cutPoint,
    mechanism: ev.mechanism,
    explanations: [...ctx.explanations],
    data_gap: init.dataGap ?? null,
  }
}

function initialDomain(domain: string): string | null {
  const name = normalizeDnsName(domain ?? '')
  if (!name) return null
  if (name.includes('[') || name.includes(']')) return null
  const labels = name.split('.')
  if (labels.length < 2) return null
  if (labels.some((label) => !label || label.length > 63)) return null
  return name
}

function reasonFor(verdict: string, domain: string, mechanism: string | null): string {
  if (verdict === 'pass') return `${domain}：机制 ${mechanism ?? '?'} 匹配（RFC 7208 §5）`
  if (verdict === 'fail') return `${domain}：机制 ${mechanism ?? '?'} 匹配，限定符为 -（RFC 7208 §4.6.2）`
  if (verdict === 'softfail') return `${domain}：机制 ${mechanism ?? '?'} 匹配，限定符为 ~（RFC 7208 §4.6.2）`
  if (verdict === 'neutral') return `${domain}：没有机制匹配且无 redirect（默认 neutral，RFC 7208 §4.7）`
  if (verdict === 'none') return `${domain}：没有可求值的 SPF 记录（RFC 7208 §4.5）`
  if (verdict === 'undecidable') return `${domain}：数据不足或规则为灰区，判不可判定（不折叠为 fail）`
  return `${domain}：${verdict}`
}

export interface SpfQuery {
  readonly mail_from: string
  readonly client_ip: string
  readonly helo: string | null
  readonly trusted_authserv_ids: readonly string[]
}

export function spfEvaluate(snap: Snapshot, query: SpfQuery): SpfResult {
  const mailFrom = query.mail_from || ''
  const at = mailFrom.indexOf('@')
  const local = at >= 0 ? mailFrom.slice(0, at) : ''
  const domain = at >= 0 ? mailFrom.slice(at + 1) : ''
  const target = domain || query.helo || ''
  return checkHost(snap, query.client_ip, target, query.helo, {
    local: local || null,
    sender: mailFrom || null,
  })
}