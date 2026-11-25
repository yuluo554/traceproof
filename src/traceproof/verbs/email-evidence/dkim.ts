/**
 * DKIM 验签（RFC 6376 §3.4/§3.5/§3.7/§6.1 + RFC 8301 §3.1/§3.2）：多签名逐条独立求值。
 *
 * 移植自旧仓 `modules/dkim.py`：
 * - **遍历全部 DKIM-Signature，逐条独立、不短路**；
 * - 只从快照取密钥：`found=false` 是数据缺口 → `undecidable`，明确 NXDOMAIN / 空答复
 *   才是"没有密钥" → `permerror`；
 * - 零第三方依赖：DER 解析交给 `node:crypto`（标准库），不做自研 RSA；
 * - 判定路径零时钟：`t=` / `x=` 不参与判定（`x=` 只告警）；
 * - `l=` 大于规范化正文长度、`rsa-sha1` 均判 `permerror`（与旧仓一致）。
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import type { KeyObject } from 'node:crypto'

import { Snapshot, normalizeDnsName } from './snapshot.js'
import type { TraceNote } from './spf.js'

export const REF_SIMPLE_HEADER = 'RFC6376#3.4.1'
export const REF_RELAXED_HEADER = 'RFC6376#3.4.2'
export const REF_SIMPLE_BODY = 'RFC6376#3.4.3'
export const REF_RELAXED_BODY = 'RFC6376#3.4.4'
export const REF_SIG_FIELD = 'RFC6376#3.5'
export const REF_KEY_RECORD = 'RFC6376#3.6.1'
export const REF_HASHES = 'RFC6376#3.7'
export const REF_ALGS = 'RFC6376#3.3'
export const REF_EXTRACT = 'RFC6376#6.1'
export const REF_VALIDATE = 'RFC6376#6.1.1'
export const REF_GET_KEY = 'RFC6376#6.1.2'
export const REF_COMPUTE = 'RFC6376#6.1.3'
export const REF_RFC8301_ALGS = 'RFC8301#3.1'
export const REF_RFC8301_BITS = 'RFC8301#3.2'

export const DKIM_MIN_KEY_BITS = 1024
export const DKIM_SUPPORTED_ALGS = ['rsa-sha256'] as const
export const DKIM_FORBIDDEN_ALGS = ['rsa-sha1'] as const
export const DKIM_UNSUPPORTED_ALGS = ['ed25519-sha256'] as const
export const DKIM_KEY_STATUSES = ['ok', 'revoked', 'missing', 'weak', 'invalid'] as const

const REQUIRED_TAGS = ['v', 'a', 'b', 'bh', 'd', 'h', 's'] as const
const KNOWN_TAGS = new Set('v a b bh c d h i l q s t x z'.split(' '))
const HASH_BY_NAME: Record<string, string> = { sha1: 'sha1', sha256: 'sha256' }
const CANON_ALGOS = ['simple', 'relaxed'] as const

const BASIS_ONE_WAY_BODY = 'bh= 是单向摘要，没有原文无法反推是哪一行被改；本工具不猜行号'
const BASIS_ONE_WAY_HEADER = 'b= 覆盖的是已签名头字段的整体哈希，没有原文无法反推是哪个头被改；本工具不猜头名'

// ── 报文解析（字节级保真） ──────────────────────────────────────────────

export interface RawHeaderField {
  readonly name: Buffer
  readonly value: Buffer
}

export interface Message {
  readonly fields: readonly RawHeaderField[]
  readonly body: Buffer
  readonly rawHead: Buffer
}

export function parseMessage(raw: Buffer): Message {
  const { head, body } = splitHeadBody(raw)
  return { fields: rawHeaderFields(head), body, rawHead: head }
}

function splitHeadBody(raw: Buffer): { head: Buffer; body: Buffer } {
  const markers: Array<Buffer> = [
    Buffer.from('\r\n\r\n', 'latin1'),
    Buffer.from('\n\n', 'latin1'),
    Buffer.from('\r\n\n', 'latin1'),
    Buffer.from('\n\r\n', 'latin1'),
  ]
  for (const marker of markers) {
    const index = raw.indexOf(marker)
    if (index >= 0) return { head: raw.subarray(0, index), body: raw.subarray(index + marker.length) }
  }
  return { head: raw, body: Buffer.alloc(0) }
}

function splitLines(head: Buffer): Buffer[] {
  const lines: Buffer[] = []
  let start = 0
  for (let index = 0; index < head.length; index += 1) {
    if (head[index] === 0x0a) {
      const end = index > start && head[index - 1] === 0x0d ? index - 1 : index
      lines.push(head.subarray(start, end))
      start = index + 1
    }
  }
  if (start < head.length) lines.push(head.subarray(start))
  return lines
}

function rawHeaderFields(head: Buffer): RawHeaderField[] {
  if (head.length === 0) return []
  const lines = splitLines(head)
  const fields: RawHeaderField[] = []
  let name: Buffer = Buffer.alloc(0)
  let valueParts: Buffer[] = []
  let started = false

  const flush = (): void => {
    if (started) fields.push({ name, value: Buffer.concat(valueParts.flatMap((part, index) => (index === 0 ? [part] : [Buffer.from('\r\n', 'latin1'), part]))) })
  }

  for (const line of lines) {
    const first = line.length > 0 ? line[0] : -1
    if (first === 0x20 || first === 0x09) {
      if (!started) throw new Error('头部首行就是折行续行（缺字段名）')
      valueParts.push(line)
      continue
    }
    const colon = line.indexOf(0x3a)
    if (colon < 0) throw new Error(`头部行缺冒号：<${line.subarray(0, 80).toString('latin1')}>`)
    flush()
    name = line.subarray(0, colon)
    valueParts = [line.subarray(colon + 1)]
    started = true
  }
  flush()
  return fields
}

export function bodyCrlf(body: Buffer): Buffer {
  const text = body.toString('latin1')
  return Buffer.from(text.split(/\r?\n/).join('\r\n'), 'latin1')
}

// ── 规范化（RFC 6376 §3.4） ─────────────────────────────────────────────

export function canonicalizeHeader(name: Buffer, value: Buffer, algorithm: string): Buffer {
  if (algorithm === 'simple') {
    return Buffer.concat([name, Buffer.from(':', 'latin1'), value, Buffer.from('\r\n', 'latin1')])
  }
  if (algorithm !== 'relaxed') throw new Error(`未知头规范化算法：${algorithm}`)
  const lowered = name.toString('latin1').replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '').toLowerCase()
  const unfolded = value
    .toString('latin1')
    .replace(/\r\n/g, '')
    .replace(/\r/g, '')
    .replace(/\n/g, '')
  const collapsed = unfolded.replace(/[ \t]+/g, ' ').replace(/^[ ]+|[ ]+$/g, '')
  return Buffer.from(`${lowered}:${collapsed}\r\n`, 'latin1')
}

export function canonicalizeBody(body: Buffer, algorithm: string): Buffer {
  const text = body.toString('latin1')
  if (algorithm === 'simple') return Buffer.from(stripTrailingEmptyLines(text), 'latin1')
  if (algorithm !== 'relaxed') throw new Error(`未知正文规范化算法：${algorithm}`)
  const stripped = text.replace(/[ \t]+\r\n/g, '\r\n')
  const collapsed = stripped.replace(/[ \t]+/g, ' ')
  const canonical = stripTrailingEmptyLines(collapsed)
  if (canonical === '\r\n') return Buffer.alloc(0)
  return Buffer.from(canonical, 'latin1')
}

function stripTrailingEmptyLines(text: string): string {
  let end = text.length
  while (end >= 2 && text.slice(end - 2, end) === '\r\n') end -= 2
  return `${text.slice(0, end)}\r\n`
}

// ── 标签列表（RFC 6376 §3.2） ───────────────────────────────────────────

export class TagError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TagError'
  }
}

export function parseTagList(raw: Buffer, where: string): Record<string, string> {
  let parts = raw.toString('latin1').split(';')
  if (parts.length > 0 && !parts[parts.length - 1].trim()) parts = parts.slice(0, -1)
  const tags: Record<string, string> = {}
  parts.forEach((part, position) => {
    const text = part.trim()
    if (!text) throw new TagError(`${where}：第 ${position + 1} 段是空标签（连续分号）`)
    const equals = text.indexOf('=')
    if (equals < 0) {
      throw new TagError(`${where}：第 ${position + 1} 段缺 '='：<${text.slice(0, 60)}>`)
    }
    const rawName = text.slice(0, equals)
    const name = rawName.trim().toLowerCase()
    if (!name || !/^[a-z][a-z0-9_.-]*$/.test(name)) {
      throw new TagError(`${where}：第 ${position + 1} 段标签名非法：<${rawName}>`)
    }
    if (name in tags) throw new TagError(`${where}：标签 ${name}= 出现两次`)
    tags[name] = text.slice(equals + 1).trim()
  })
  return tags
}

function decodeBase64(value: string, where: string): Buffer {
  const compact = value.replace(/\s+/g, '')
  if (!compact) throw new TagError(`${where}：base64 值为空`)
  const padded = compact + '='.repeat((4 - (compact.length % 4)) % 4)
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(padded) || padded.length % 4 !== 0) {
    throw new TagError(`${where}：base64 解不开（长度 ${compact.length}）`)
  }
  return Buffer.from(padded, 'base64')
}

// ── 密钥记录（RFC 6376 §3.6.1） ─────────────────────────────────────────

interface KeyRecord {
  status: (typeof DKIM_KEY_STATUSES)[number]
  bits: number | null
  encoding: string | null
  key: KeyObject | null
  note: string
  dataGap: [string, string] | null
  ref: string
}

function loadKey(
  snapshot: Snapshot,
  selector: string,
  domain: string,
  hashName: string,
  trace: TraceNote[],
): KeyRecord {
  const qname = `${selector}._domainkey.${domain}`
  const resolved = snapshot.resolve(qname, 'TXT')
  trace.push({ node: 'dkim.key', note: `${domain} 的选择器 ${selector} → 查询 ${qname}` })
  if (!resolved.found) {
    return {
      status: 'missing',
      bits: null,
      encoding: null,
      key: null,
      note: `快照里没有 ${qname}/TXT 这条查询（数据缺口，不等同于密钥不存在）`,
      dataGap: [qname, 'TXT'],
      ref: REF_KEY_RECORD,
    }
  }
  if (resolved.rcode !== 'NOERROR' || resolved.answer.length === 0) {
    return {
      status: 'missing',
      bits: null,
      encoding: null,
      key: null,
      note: `快照答复 ${resolved.rcode}：${qname} 没有可用密钥记录`,
      dataGap: null,
      ref: REF_KEY_RECORD,
    }
  }
  const problems: string[] = []
  for (const [position, record] of resolved.answer.entries()) {
    const parsed = parseKeyRecord(record, hashName)
    if ('status' in parsed) {
      if (position > 0) {
        trace.push({ node: 'dkim.key', note: `取第 ${position + 1} 条 TXT 记录（前 ${position} 条不可用）` })
      }
      return parsed
    }
    problems.push(`记录 #${position + 1}：${parsed.problem}`)
  }
  return {
    status: 'invalid',
    bits: null,
    encoding: null,
    key: null,
    note: `密钥记录不可用（${problems.join('；')}）`,
    dataGap: null,
    ref: REF_KEY_RECORD,
  }
}

function parseKeyRecord(record: string, hashName: string): KeyRecord | { problem: string } {
  let tags: Record<string, string>
  try {
    tags = parseTagList(Buffer.from(record, 'utf8'), '密钥记录')
  } catch (error) {
    return { problem: (error as Error).message }
  }
  if (!('p' in tags)) return { problem: '缺 p=（RFC 6376 §3.6.1 标为 REQUIRED）' }
  const version = tags.v
  if (version !== undefined && version !== 'DKIM1') {
    return { problem: `v=<${version}> 不是 DKIM1（记录必须丢弃）` }
  }
  const keyType = (tags.k ?? 'rsa').toLowerCase()
  if (keyType !== 'rsa') return { problem: `k=<${keyType}> 不是 rsa（本工具只验 RSA）` }
  const services = tags.s ?? '*'
  const serviceTypes = new Set(services.split(':').map((item) => item.trim().toLowerCase()).filter(Boolean))
  if (!serviceTypes.has('*') && !serviceTypes.has('email')) {
    return { problem: `s=<${services}> 不含 email/*（§3.6.1）` }
  }
  const hashes = tags.h
  if (hashes) {
    const allowed = new Set(hashes.split(':').map((item) => item.trim().toLowerCase()).filter(Boolean))
    if (!allowed.has(hashName)) return { problem: `h=<${hashes}> 不含 ${hashName}（§6.1.2 第 6 步 → PERMFAIL）` }
  }
  if (!tags.p.trim()) {
    return {
      status: 'revoked',
      bits: null,
      encoding: null,
      key: null,
      note: 'p= 为空：该密钥已撤销（RFC 6376 §3.6.1）',
      dataGap: null,
      ref: REF_KEY_RECORD,
    }
  }
  let der: Buffer
  try {
    der = decodeBase64(tags.p, 'p=')
  } catch (error) {
    return { problem: (error as Error).message }
  }
  const parsedKey = parseRsaPublicKey(der)
  if (parsedKey === null) return { problem: 'p= 不是合法的 RSA 公钥 DER' }
  if (parsedKey.bits < DKIM_MIN_KEY_BITS) {
    return {
      status: 'weak',
      bits: parsedKey.bits,
      encoding: parsedKey.encoding,
      key: parsedKey.key,
      note: `RSA 密钥 ${parsedKey.bits} 位 < ${DKIM_MIN_KEY_BITS} 位（RFC 8301 §3.2 MUST NOT 视为有效）`,
      dataGap: null,
      ref: REF_RFC8301_BITS,
    }
  }
  return {
    status: 'ok',
    bits: parsedKey.bits,
    encoding: parsedKey.encoding,
    key: parsedKey.key,
    note: `RSA ${parsedKey.bits} 位（${parsedKey.encoding} 编码）`,
    dataGap: null,
    ref: REF_KEY_RECORD,
  }
}

function parseRsaPublicKey(der: Buffer): { key: KeyObject; bits: number; encoding: string } | null {
  for (const [type, encoding] of [
    ['spki', 'spki'],
    ['pkcs1', 'rsapublickey'],
  ] as const) {
    try {
      const key = createPublicKey({ key: der, format: 'der', type })
      const details = key.asymmetricKeyDetails as { modulusLength?: number } | undefined
      if (details?.modulusLength) {
        return { key, bits: details.modulusLength, encoding }
      }
      return null
    } catch {
      // 尝试下一种编码
    }
  }
  return null
}

// ── 结果模型 ────────────────────────────────────────────────────────────

export interface SignatureResult {
  index: number
  selector: string | null
  domain: string | null
  identity: string | null
  algorithm: string | null
  canonicalization: string | null
  bh_matches: boolean | null
  failure_at: Record<string, unknown> | null
  key_bits: number | null
  key_status: string | null
  result: string
  reason: string
  evidence_ref: string[]
  trace: TraceNote[]
  warnings: string[]
  data_gap: [string, string] | null
}

export interface DkimResult {
  signatures: SignatureResult[]
  message_has_signatures: boolean
  trace: TraceNote[]
  warnings: string[]
  data_gaps: Array<[string, string]>
}

export function verifyMessage(message: Message, snapshot: Snapshot, shared: TraceNote[] = []): DkimResult {
  const fields = message.fields
  const body = bodyCrlf(message.body)
  const signatureIndexes = fields
    .map((field, position) => ({ position, name: field.name.toString('latin1').trim().toLowerCase() }))
    .filter((entry) => entry.name === 'dkim-signature')
    .map((entry) => entry.position)

  shared.push({
    node: 'dkim.extract',
    note: `报文头 ${fields.length} 个，其中 DKIM-Signature ${signatureIndexes.length} 条（逐条独立求值，不短路）`,
  })

  const results: SignatureResult[] = []
  const warnings: string[] = []
  const gaps: Array<[string, string]> = []
  signatureIndexes.forEach((position, ordinal) => {
    const local: TraceNote[] = []
    const result = verifyOne({ ordinal, position, fields, body, snapshot, trace: local })
    shared.push(...local)
    results.push(result)
    if (result.data_gap) gaps.push(result.data_gap)
    for (const warning of result.warnings) {
      if (!warnings.includes(warning)) warnings.push(warning)
    }
  })

  return {
    signatures: results,
    message_has_signatures: signatureIndexes.length > 0,
    trace: shared,
    warnings,
    data_gaps: gaps,
  }
}

function verifyOne(init: {
  ordinal: number
  position: number
  fields: readonly RawHeaderField[]
  body: Buffer
  snapshot: Snapshot
  trace: TraceNote[]
}): SignatureResult {
  const { ordinal, position, fields, body, snapshot, trace } = init
  const warnings: string[] = []
  const field = fields[position]
  const base = { index: ordinal }
  trace.push({ node: 'dkim.sig', note: `#${ordinal} 位于报文第 ${position + 1} 个头字段` })

  let tags: Record<string, string>
  try {
    tags = parseTagList(field.value, `DKIM-Signature #${ordinal}`)
  } catch (error) {
    return bail(base, trace, 'permerror', `签名头语法错误：${(error as Error).message}`, REF_VALIDATE, warnings, {
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: firstBadOffset(field.value) },
    })
  }

  const missing = REQUIRED_TAGS.filter((tag) => !(tag in tags))
  if (missing.length > 0) {
    return bail(
      base,
      trace,
      'permerror',
      `缺必需标签 ${missing.map((tag) => `${tag}=`).join('、')}（RFC 6376 §3.5 REQUIRED）`,
      REF_VALIDATE,
      warnings,
      {
        failure_at: { kind: 'missing_tag', header: 'DKIM-Signature', offset: 0, tags: missing },
      },
    )
  }

  if (tags.v !== '1') {
    return bail(base, trace, 'permerror', `v=<${tags.v}> 与本规范不兼容（要求 v=1）`, REF_VALIDATE, warnings, {
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'v') },
      selector: tags.s,
      domain: tags.d,
      algorithm: tags.a,
      canonicalization: tags.c,
    })
  }

  const algorithm = tags.a.trim().toLowerCase()
  const domain = tags.d.trim().replace(/\.+$/, '').toLowerCase()
  const selector = tags.s.trim()
  const canonical = parseCanonicalization(tags.c, warnings)
  if (canonical === null) {
    return bail(
      base,
      trace,
      'permerror',
      `c=<${tags.c}> 不是合法的规范化组合（允许 simple/relaxed）`,
      REF_VALIDATE,
      warnings,
      {
        failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'c') },
        selector,
        domain,
        algorithm,
        canonicalization: tags.c,
      },
    )
  }
  const [canonHeader, canonBody] = canonical

  const identity = tags.i || `@${domain}`
  if (!identityUnderDomain(identity, domain)) {
    return bail(
      base,
      trace,
      'permerror',
      `i=${identity} 不在 d=${domain} 之下（RFC 6376 §6.1.1 domain mismatch）`,
      REF_VALIDATE,
      warnings,
      {
        failure_at: { kind: 'domain_mismatch', header: 'DKIM-Signature', offset: tagOffset(field.value, 'i') },
        selector,
        domain,
        algorithm,
        identity,
      },
    )
  }
  if (tags.i === undefined) trace.push({ node: 'dkim.i', note: `无 i=，按 §6.1.1 取默认值 @${domain}` })

  const signedNames = tags.h.split(':').map((item) => item.trim().toLowerCase()).filter(Boolean)
  if (signedNames.length === 0) {
    return bail(base, trace, 'permerror', 'h= 为空（RFC 6376 §3.5：列表 MUST NOT be empty）', REF_VALIDATE, warnings, {
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'h') },
      selector,
      domain,
      algorithm,
      identity,
    })
  }
  trace.push({ node: 'dkim.h=', note: signedNames.join(' ') })
  if (!signedNames.includes('from')) {
    return bail(
      base,
      trace,
      'permerror',
      'h= 未包含 From（RFC 6376 §6.1.1 要求 From 必须被签名）',
      REF_VALIDATE,
      warnings,
      {
        failure_at: { kind: 'from_not_signed', header: 'From', offset: 0 },
        selector,
        domain,
        algorithm,
        identity,
        canonicalization: tags.c,
      },
    )
  }

  if ('x' in tags) {
    warnings.push('含 x=（签名过期时间）：本工具判定路径零时钟，未校验是否过期；如需判断请对照报文接收时间人工核对')
    trace.push({ node: 'dkim.x', note: `x=${tags.x} 未校验（判定不读系统时钟）` })
  }
  if ('t' in tags) trace.push({ node: 'dkim.t', note: `t=${tags.t}（仅记录，不参与判定）` })
  const unknown = Object.keys(tags).filter((tag) => !KNOWN_TAGS.has(tag)).sort()
  if (unknown.length > 0) {
    trace.push({
      node: 'dkim.tags',
      note: `未知标签 ${unknown.map((tag) => `${tag}=`).join('、')}：按 §3.7 照样参与哈希，本模块不解释其语义`,
    })
  }

  const split = splitAlgorithm(algorithm)
  if (split.problem) {
    return bail(base, trace, 'permerror', split.problem, REF_SIG_FIELD, warnings, {
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'a') },
      selector,
      domain,
      algorithm,
      identity,
      canonicalization: tags.c,
    })
  }
  const hashName = split.hashName as string

  if ((DKIM_UNSUPPORTED_ALGS as readonly string[]).includes(algorithm)) {
    return bail(
      base,
      trace,
      'undecidable',
      `a=${algorithm} 本工具不支持（标准库无 Ed25519），未做判定`,
      REF_ALGS,
      [...warnings, `本工具不支持 ${algorithm} 算法：该签名的强弱未知`],
      { selector, domain, algorithm, identity, canonicalization: tags.c },
    )
  }
  if ((DKIM_FORBIDDEN_ALGS as readonly string[]).includes(algorithm)) {
    return bail(
      base,
      trace,
      'permerror',
      `a=${algorithm} 已被 RFC 8301 §3.1 禁止用于签名与验签（永久失败）`,
      REF_RFC8301_ALGS,
      warnings,
      { selector, domain, algorithm, identity, canonicalization: tags.c },
    )
  }
  if (!(DKIM_SUPPORTED_ALGS as readonly string[]).includes(algorithm)) {
    return bail(
      base,
      trace,
      'undecidable',
      `a=${algorithm} 不在本工具支持的算法清单内（${DKIM_SUPPORTED_ALGS.join('、')}），未做判定`,
      REF_ALGS,
      [...warnings, `本工具不判 ${algorithm}：该签名的强弱未知`],
      { selector, domain, algorithm, identity, canonicalization: tags.c },
    )
  }

  const keyRecord = loadKey(snapshot, selector, domain, hashName, trace)
  trace.push({ node: 'dkim.key_status', note: `${keyRecord.status}：${keyRecord.note}` })
  if (keyRecord.encoding) trace.push({ node: 'dkim.key_encoding', note: `p= 编码为 ${keyRecord.encoding}` })

  if (keyRecord.status === 'missing') {
    if (keyRecord.dataGap) {
      warnings.push(`缺 ${keyRecord.dataGap[0]}/TXT：本次无法判定该签名（数据缺口，不是密钥不存在）`)
      return {
        ...base,
        selector,
        domain,
        identity,
        algorithm,
        canonicalization: tags.c,
        bh_matches: null,
        failure_at: null,
        key_bits: null,
        key_status: 'missing',
        result: 'undecidable',
        reason: `${keyRecord.note}；没有公钥就无法完成验证，正文与头部哈希均未参与判定`,
        evidence_ref: [REF_GET_KEY],
        trace: [...trace],
        warnings: [...warnings],
        data_gap: keyRecord.dataGap,
      }
    }
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: null,
      failure_at: null,
      key_bits: null,
      key_status: 'missing',
      result: 'permerror',
      reason: `${keyRecord.note}（RFC 6376 §6.1.2 第 3 步：no key for signature）`,
      evidence_ref: [REF_GET_KEY],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  if (keyRecord.status === 'revoked') {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: null,
      failure_at: null,
      key_bits: null,
      key_status: 'revoked',
      result: 'permerror',
      reason: `${keyRecord.note}（RFC 6376 §6.1.2 第 7 步：key revoked）`,
      evidence_ref: [REF_GET_KEY, REF_KEY_RECORD],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  if (keyRecord.status === 'weak') {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: null,
      failure_at: null,
      key_bits: keyRecord.bits,
      key_status: 'weak',
      result: 'fail',
      reason: `${keyRecord.note}；按 RFC 8301 §3.2 MUST NOT 视为有效签名，未再验签`,
      evidence_ref: [REF_RFC8301_BITS],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  if (keyRecord.status !== 'ok' || keyRecord.key === null) {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: null,
      failure_at: null,
      key_bits: keyRecord.bits,
      key_status: keyRecord.status,
      result: 'permerror',
      reason: `${keyRecord.note}（RFC 6376 §6.1.2：密钥不可用）`,
      evidence_ref: [REF_GET_KEY],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  let bhRaw: Buffer | null
  try {
    bhRaw = decodeBase64(tags.bh, 'bh=')
  } catch {
    bhRaw = null
  }
  if (bhRaw === null) {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: null,
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'bh') },
      key_bits: keyRecord.bits,
      key_status: keyRecord.status,
      result: 'permerror',
      reason: 'bh= 不是合法 base64（RFC 6376 §3.5）',
      evidence_ref: [REF_SIG_FIELD],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  const canonicalBody = canonicalizeBody(body, canonBody)
  const [limit, limitError] = parseLength(tags.l)
  if (limitError) {
    return bail(base, trace, 'permerror', limitError, REF_SIG_FIELD, warnings, {
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'l') },
      selector,
      domain,
      algorithm,
      identity,
      canonicalization: tags.c,
    })
  }
  if (limit !== null && limit > canonicalBody.length) {
    return bail(
      base,
      trace,
      'permerror',
      `l=${limit} 大于规范化正文长度 ${canonicalBody.length}（RFC 6376 §3.5 MUST NOT），按签名语法错误处理`,
      REF_SIG_FIELD,
      warnings,
      {
        failure_at: {
          kind: 'length_exceeds_body',
          header: 'DKIM-Signature',
          offset: tagOffset(field.value, 'l'),
          body_line: 1,
          limit,
          canonical_length: canonicalBody.length,
        },
        selector,
        domain,
        algorithm,
        identity,
        canonicalization: tags.c,
      },
    )
  }

  const covered = limit === null ? canonicalBody : canonicalBody.subarray(0, limit)
  const digest = createHash(hashName).update(covered).digest()
  const bhMatches = digest.equals(bhRaw)
  trace.push({
    node: 'dkim.bh',
    note: `正文规范化（${canonBody}）${canonicalBody.length} 字节；覆盖 ${covered.length} 字节；bh ${bhMatches ? '匹配' : '不匹配'}`,
  })
  if (limit !== null && limit < canonicalBody.length) {
    const unsignedLine = firstLineBeyond(canonicalBody, limit)
    warnings.push(
      `l=${limit} 只覆盖前 ${limit} 字节（共 ${canonicalBody.length} 字节）：第 ${unsignedLine ?? '?'} 行起的正文未受签名保护（RFC 6376 §3.5 允许，但 §8.2 建议慎用）`,
    )
  }
  if (!bhMatches) {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: false,
      failure_at: {
        kind: 'body_hash',
        body_line: null,
        basis: BASIS_ONE_WAY_BODY,
        l: limit,
        canonical_length: canonicalBody.length,
      },
      key_bits: keyRecord.bits,
      key_status: keyRecord.status,
      result: 'fail',
      reason: '正文哈希与 bh= 不符（RFC 6376 §6.1.3 第 3 步：body hash did not verify）',
      evidence_ref: [REF_COMPUTE, REF_HASHES],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  const selection = selectHeaders(fields, signedNames, position)
  if (selection.problem) {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: true,
      failure_at: null,
      key_bits: keyRecord.bits,
      key_status: 'ok',
      result: 'permerror',
      reason: selection.problem,
      evidence_ref: [REF_VALIDATE, REF_SIG_FIELD],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  const chunks: Buffer[] = []
  for (const header of selection.selected) {
    chunks.push(canonicalizeHeader(header.name, header.value, canonHeader))
  }
  const stripped = stripBValue(field.value)
  let signatureHeader = canonicalizeHeader(field.name, stripped, canonHeader)
  if (signatureHeader.subarray(-2).toString('latin1') === '\r\n') {
    signatureHeader = signatureHeader.subarray(0, signatureHeader.length - 2)
  }
  chunks.push(signatureHeader)
  const signedData = Buffer.concat(chunks)
  trace.push({
    node: 'dkim.headers',
    note: `已签名 ${selection.selected.length} 个头字段（${canonHeader} 规范化）+ 签名头自身（b= 置空）`,
  })

  let signatureBytes: Buffer
  try {
    signatureBytes = decodeBase64(tags.b, 'b=')
  } catch (error) {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: true,
      failure_at: { kind: 'header_syntax', header: 'DKIM-Signature', offset: tagOffset(field.value, 'b') },
      key_bits: keyRecord.bits,
      key_status: 'ok',
      result: 'permerror',
      reason: `b= 不可用：${(error as Error).message}`,
      evidence_ref: [REF_SIG_FIELD],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  const verified = cryptoVerify(hashName, signedData, keyRecord.key, signatureBytes)
  if (!verified) {
    return {
      ...base,
      selector,
      domain,
      identity,
      algorithm,
      canonicalization: tags.c,
      bh_matches: true,
      failure_at: {
        kind: 'header_hash',
        header: null,
        offset: null,
        basis: BASIS_ONE_WAY_HEADER,
      },
      key_bits: keyRecord.bits,
      key_status: 'ok',
      result: 'fail',
      reason: '签名验不过：RSA PKCS#1 v1.5 校验失败（RFC 6376 §6.1.3 第 4 步：signature did not verify）',
      evidence_ref: [REF_COMPUTE, REF_VALIDATE],
      trace: [...trace],
      warnings: [...warnings],
      data_gap: null,
    }
  }

  return {
    ...base,
    selector,
    domain,
    identity,
    algorithm,
    canonicalization: tags.c,
    bh_matches: true,
    failure_at: null,
    key_bits: keyRecord.bits,
    key_status: 'ok',
    result: 'pass',
    reason: `正文哈希匹配，${algorithm} 签名在 ${keyRecord.bits} 位 RSA 公钥上验签通过`,
    evidence_ref: [REF_COMPUTE, REF_HASHES, REF_KEY_RECORD],
    trace: [...trace],
    warnings: [...warnings],
    data_gap: null,
  }
}

function bail(
  base: { index: number },
  trace: TraceNote[],
  result: string,
  reason: string,
  ref: string,
  warnings: string[],
  options: {
    failure_at?: Record<string, unknown> | null
    selector?: string | null
    domain?: string | null
    algorithm?: string | null
    identity?: string | null
    canonicalization?: string | null
  } = {},
): SignatureResult {
  trace.push({ node: 'dkim.stop', note: `${result}：${reason}` })
  return {
    ...base,
    selector: options.selector ?? null,
    domain: options.domain ?? null,
    identity: options.identity ?? null,
    algorithm: options.algorithm ?? null,
    canonicalization: options.canonicalization ?? null,
    bh_matches: null,
    failure_at: options.failure_at ?? null,
    key_bits: null,
    key_status: null,
    result,
    reason,
    evidence_ref: [ref],
    trace: [...trace],
    warnings: [...warnings],
    data_gap: null,
  }
}

function splitAlgorithm(algorithm: string): { hashName: string | null; problem: string | null } {
  const dash = algorithm.indexOf('-')
  if (dash <= 0 || dash === algorithm.length - 1) {
    return { hashName: null, problem: `a=<${algorithm}> 不是 'k-h' 形态（RFC 6376 §3.5 ABNF）` }
  }
  const keyType = algorithm.slice(0, dash)
  const hashPart = algorithm.slice(dash + 1)
  if (!keyType || !hashPart) {
    return { hashName: null, problem: `a=<${algorithm}> 不是 'k-h' 形态（RFC 6376 §3.5 ABNF）` }
  }
  if (!(hashPart in HASH_BY_NAME)) return { hashName: null, problem: null }
  return { hashName: HASH_BY_NAME[hashPart], problem: null }
}

function parseCanonicalization(value: string | undefined, warnings: string[]): [string, string] | null {
  if (value === undefined || !value.trim()) return ['simple', 'simple']
  const parts = value.split('/').map((item) => item.trim().toLowerCase())
  if (parts.length === 1) parts.push('simple')
  if (parts.length !== 2) return null
  if (parts.some((part) => !(CANON_ALGOS as readonly string[]).includes(part))) return null
  if (parts[0] !== 'simple' || parts[1] !== 'simple') {
    warnings.push(`规范化 ${parts[0]}/${parts[1]}：与默认值不同，已按 c= 声明求值`)
  }
  return [parts[0], parts[1]]
}

function identityUnderDomain(identity: string, domain: string): boolean {
  if (!identity.includes('@')) return false
  const at = identity.lastIndexOf('@')
  const identityDomain = identity.slice(at + 1).trim().replace(/\.+$/, '').toLowerCase()
  if (!domain) return false
  return identityDomain === domain || identityDomain.endsWith(`.${domain}`)
}

function parseLength(value: string | undefined): [number | null, string | null] {
  if (value === undefined) return [null, null]
  const text = value.trim()
  if (!/^\d+$/.test(text)) return [null, `l=<${value}> 不是十进制无符号整数（RFC 6376 §3.5）`]
  if (text.length > 76) return [null, `l= 长达 ${text.length} 位，超过 RFC 6376 §3.5 的 76 位上限`]
  return [Number(text), null]
}

function firstLineBeyond(body: Buffer, limit: number): number | null {
  if (limit >= body.length) return null
  const starts = [0]
  let index = body.indexOf(Buffer.from('\r\n', 'latin1'))
  while (index >= 0) {
    starts.push(index + 2)
    index = body.indexOf(Buffer.from('\r\n', 'latin1'), index + 2)
  }
  for (const [position, start] of starts.entries()) {
    if (start >= limit) return position + 1
  }
  return null
}

function selectHeaders(
  fields: readonly RawHeaderField[],
  signedNames: readonly string[],
  exclude: number,
): { selected: RawHeaderField[]; problem: string | null } {
  const selected: RawHeaderField[] = []
  const cursor = new Map<string, number>()
  const available = new Map<string, number>()
  fields.forEach((field, position) => {
    if (position === exclude) return
    const lowered = field.name.toString('latin1').trim().toLowerCase()
    available.set(lowered, (available.get(lowered) ?? 0) + 1)
  })

  const wanted = new Map<string, number>()
  for (const name of signedNames) wanted.set(name, (wanted.get(name) ?? 0) + 1)
  for (const [name, count] of wanted) {
    if (count > (available.get(name) ?? 0)) {
      if (name === 'dkim-signature') {
        return {
          selected: [],
          problem: `h= 引用了 ${count} 个 dkim-signature，但除本签名外只有 ${available.get(name) ?? 0} 个（RFC 6376 §3.5：不得包含正在验的签名头自身）`,
        }
      }
      break
    }
  }

  for (const name of signedNames) {
    const boundary = cursor.get(name) ?? fields.length
    let found: number | null = null
    for (let position = boundary - 1; position >= 0; position -= 1) {
      if (position === exclude) continue
      if (fields[position].name.toString('latin1').trim().toLowerCase() === name) {
        found = position
        break
      }
    }
    if (found === null) {
      cursor.set(name, 0)
      continue
    }
    selected.push(fields[found])
    cursor.set(name, found)
  }
  return { selected, problem: null }
}

function stripBValue(rawValue: Buffer): Buffer {
  const text = rawValue.toString('latin1')
  const match = text.match(/(^|;)([ \t\r\n]*)(b)([ \t\r\n]*)(=)/)
  if (match === null || match.index === undefined) return rawValue
  const valueStart = match.index + match[0].length
  const nextSemicolon = text.indexOf(';', valueStart)
  const valueEnd = nextSemicolon < 0 ? text.length : nextSemicolon
  return Buffer.from(text.slice(0, valueStart) + text.slice(valueEnd), 'latin1')
}

function tagOffset(rawValue: Buffer, tag: string): number {
  const text = rawValue.toString('latin1')
  const match = text.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=`))
  return match?.index ?? 0
}

function firstBadOffset(rawValue: Buffer): number {
  const text = rawValue.toString('latin1')
  let cursor = 0
  for (const part of text.split(';')) {
    if (part.trim() && !part.includes('=')) return cursor
    cursor += part.length + 1
  }
  return 0
}

/** 签名覆盖的头字段名（给 DMARC / 证据用）。 */
export function signedHeaderNames(result: SignatureResult): string[] {
  for (const node of result.trace) {
    if (node.node === 'dkim.h=') return node.note.split(' ')
  }
  return []
}

export function dkimSummary(result: DkimResult): string {
  if (result.signatures.length === 0) return '无 DKIM-Signature（none）'
  const counts = new Map<string, number>()
  for (const signature of result.signatures) {
    counts.set(signature.result, (counts.get(signature.result) ?? 0) + 1)
  }
  const parts = [...counts.keys()].sort().map((key) => `${key}×${counts.get(key)}`)
  return `${result.signatures.length} 条签名：${parts.join('、')}`
}

/** DMARC 对齐要用的 "d=" 规范化。 */
export function signatureDomain(result: SignatureResult): string {
  return normalizeDnsName(result.domain ?? '')
}