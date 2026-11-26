/**
 * archive-extraction · MOD-2 编码与 Unicode path extra field（迁移自源仓 `rules/encoding.py`）。
 *
 * 两层职责：
 *  1. 结构事实：原始名字节可逆、bit 11 原样、extra 切成 `(id, size)`、`0x7075` 的
 *     `version / name_crc32 / utf8_name` 与 CRC 校验；
 *  2. 推断：候选编码按固定顺序、`preferred` / `confidence` / `predictedNames`，
 *     外加 `encoding.UPATH_CRC_MISMATCH` finding。
 *
 * 候选顺序固定 `UTF-8 / CP437 / GBK / CP932 / CP949 / CP1251`；无法完整解码的候选**不出现**
 * 在候选列表里；不可解码时给 `null` + `reason`，不编造替代名。
 *
 * 四提取器模型（对着源仓实测矩阵）：python-zipfile 读 0x7075 → bit 11 → CP437；
 * info-zip-unzip 走 CP850 解码 + OEM→ANSI best-fit；7zip / libarchive 走声明 ANSI 码页
 * （不做字符集探测）。CP437 / CP850 / CP1251 表随包导入；GBK / CP932 / CP949 用宿主
 * `TextDecoder`（与源仓 Python codec 在全部 shipped fixtures 上逐值一致）。
 */

import type { Archive, EntryView } from './archive.js'
import { makeFinding, sortFindings } from './findings.js'
import type { Finding } from './findings.js'
import {
  CP1251,
  CP437,
  CP850,
  CP850_TRANSLITERATION,
  decodeSingleByte,
} from './platforms.js'
import { bytesToHex, crc32, decodeStrictUtf8, displayName } from './util.js'

export const FLAG_UTF8 = 0x0800
export const UPATH_ID = 0x7075
export const UCOMMENT_ID = 0x6375
export const EXT_TIMESTAMP_ID = 0x0008

export const CANDIDATE_ENCODINGS = ['UTF-8', 'CP437', 'GBK', 'CP932', 'CP949', 'CP1251'] as const
export type CandidateName = (typeof CANDIDATE_ENCODINGS)[number]

export const MULTIBYTE_CANDIDATES: ReadonlySet<string> = new Set([
  'UTF-8',
  'GBK',
  'CP932',
  'CP949',
])

export const UNZIP_CODEC = 'cp850'
export const ANSI_CODEC = 'gbk'
export const UPATH_CODEC = 'utf-8'

export const EXTRACTORS = ['python-zipfile', 'info-zip-unzip', '7zip', 'libarchive'] as const
export type Extractor = (typeof EXTRACTORS)[number]

export const PREDICTION_RULES = [
  'upath_override',
  'utf8_bit11',
  'ansi_codepage',
  'cp437_fallback',
  'cp850_oem_transliterated',
  'undecodable',
] as const

export const PRECEDENTS = ['apnote_d1_d2_encoding', 'apnote_d6_upath_crc'] as const

export const RECORD_ONLY_IDS = [UCOMMENT_ID, EXT_TIMESTAMP_ID] as const

export interface UpathField {
  readonly present: boolean
  readonly version: number | null
  readonly nameCrc32: number | null
  readonly utf8Name: string | null
  readonly crcValid: boolean | null
}

export function upathToJSON(field: UpathField): Record<string, unknown> {
  return {
    present: field.present,
    version: field.version,
    name_crc32: field.nameCrc32,
    utf8_name: field.utf8Name,
    crc_valid: field.crcValid,
  }
}

export interface NameFacts {
  readonly entryIndex: number
  readonly rawNameHex: string
  readonly rawNameLength: number
  readonly bit11: boolean
  readonly extraIds: readonly number[]
  readonly upath: UpathField
}

export function nameFactsToJSON(facts: NameFacts): Record<string, unknown> {
  return {
    entryIndex: facts.entryIndex,
    rawNameHex: facts.rawNameHex,
    rawNameLength: facts.rawNameLength,
    bit11: facts.bit11,
    extraIds: [...facts.extraIds],
    upath: upathToJSON(facts.upath),
  }
}

const NO_UPATH: UpathField = {
  present: false,
  version: null,
  nameCrc32: null,
  utf8Name: null,
  crcValid: null,
}

export function expectedNameCrc(entry: EntryView): number {
  return crc32(entry.cdName)
}

/** 解析 `0x7075`：`version(1) / name_crc32(4) / utf8_name(rest)`。结构不完整时 present=true。 */
export function parseUpath(entry: EntryView): UpathField {
  const field = entry.cdExtra.find((item) => item.fieldId === UPATH_ID)
  if (field === undefined) return NO_UPATH
  const data = field.data
  if (data.length < 5) return { ...NO_UPATH, present: true }
  const version = data[0]
  const nameCrc32 = (data[1] | (data[2] << 8) | (data[3] << 16) | (data[4] << 24)) >>> 0
  const utf8Name = decodeStrictUtf8(data.subarray(5))
  return {
    present: true,
    version,
    nameCrc32,
    utf8Name,
    crcValid: nameCrc32 === expectedNameCrc(entry),
  }
}

export function describe(entry: EntryView): NameFacts {
  return {
    entryIndex: entry.index,
    rawNameHex: bytesToHex(entry.cdName),
    rawNameLength: entry.cdName.length,
    bit11: (entry.cdFlags & FLAG_UTF8) !== 0,
    extraIds: entry.cdExtra.map((item) => item.fieldId),
    upath: parseUpath(entry),
  }
}

export function describeAll(archive: Archive): NameFacts[] {
  return archive.entries.map((entry) => describe(entry))
}

const SINGLE_BYTE: Readonly<Record<string, typeof CP437>> = {
  CP437,
  CP850,
  CP1251,
}

const MULTIBYTE_LABELS: Readonly<Record<string, string>> = {
  CP932: 'shift_jis',
  CP949: 'euc-kr',
}

function decodeTextDecoder(label: string, raw: Uint8Array): string | null {
  try {
    return new TextDecoder(label, { fatal: true }).decode(raw)
  } catch {
    return null
  }
}

/**
 * 严格 GBK：宿主 `TextDecoder('gbk')` 实现的是 WHATWG gb18030，比 Python `gbk` 宽两处
 * （单字节 0x80 → `€`；接受 GB18030 四字节序列）。这里先按 Python gbk 的字节语法预检，
 * 再交给宿主解码——两处宽化都被挡住，shipped fixtures 逐值一致。
 */
function decodeGbk(raw: Uint8Array): string | null {
  let index = 0
  while (index < raw.length) {
    const first = raw[index]
    if (first < 0x80) {
      index += 1
      continue
    }
    if (first === 0x80 || first === 0xff) return null
    if (index + 1 >= raw.length) return null
    const trail = raw[index + 1]
    if (trail >= 0x30 && trail <= 0x39) return null // GB18030 四字节，Python gbk 不接受
    if (!(trail >= 0x40 && trail <= 0xfe && trail !== 0x7f)) return null
    index += 2
  }
  return decodeTextDecoder('gbk', raw)
}

/** 按候选名解码；解不全返回 `null`（**不**用 replace/ignore 伪造结果）。 */
export function decode(raw: Uint8Array, encoding: string): string | null {
  if (encoding === 'UTF-8') return decodeStrictUtf8(raw)
  const single = SINGLE_BYTE[encoding]
  if (single !== undefined) return decodeSingleByte(single, raw)
  if (encoding === 'GBK' || encoding === ANSI_CODEC) return decodeGbk(raw)
  const label = MULTIBYTE_LABELS[encoding]
  if (label !== undefined) return decodeTextDecoder(label, raw)
  if (encoding === UNZIP_CODEC) return decodeSingleByte(CP850, raw)
  return null
}

const COMMON_ZONE = /[\p{L}\p{M}\p{N}]/u

/** "常用字区"：ASCII 可打印，或 Unicode 类别属于 L* / M* / N*。 */
export function isCommonZone(text: string): boolean {
  for (const ch of text) {
    const code = ch.codePointAt(0) as number
    if (code >= 0x20 && code <= 0x7e) continue
    if (COMMON_ZONE.test(ch)) continue
    return false
  }
  return true
}

export interface Candidate {
  readonly encoding: string
  readonly name: string
  readonly strongStructure: boolean
  readonly commonZone: boolean
}

export function candidates(raw: Uint8Array): Candidate[] {
  const out: Candidate[] = []
  for (const name of CANDIDATE_ENCODINGS) {
    const text = decode(raw, name)
    if (text === null) continue
    out.push({
      encoding: name,
      name: text,
      strongStructure: MULTIBYTE_CANDIDATES.has(name),
      commonZone: isCommonZone(text),
    })
  }
  return out
}

export function preferred(candidateList: readonly Candidate[]): Candidate | null {
  if (candidateList.length === 0) return null
  const order = new Map<string, number>(CANDIDATE_ENCODINGS.map((name, index) => [name, index]))
  const ranked = [...candidateList].sort((left, right) => {
    const leftRank = left.strongStructure ? 0 : 1
    const rightRank = right.strongStructure ? 0 : 1
    if (leftRank !== rightRank) return leftRank - rightRank
    return (order.get(left.encoding) as number) - (order.get(right.encoding) as number)
  })
  return ranked[0]
}

function transliterateOem(text: string): string {
  let out = ''
  for (const ch of text) out += CP850_TRANSLITERATION[ch] ?? ch
  return out
}

export interface Prediction {
  readonly name: string | null
  readonly rule: string
  readonly source?: string
  readonly reason?: string
}

export function predictNames(
  raw: Uint8Array,
  bit11: boolean,
  upath: UpathField,
  chosen: Candidate | null,
): Record<string, Prediction> {
  const upathHit = upath.present && upath.crcValid === true && upath.utf8Name !== null
  const utf8Text = bit11 ? decode(raw, 'UTF-8') : null
  const cp437Text = decode(raw, 'CP437')
  const cp850Text = decode(raw, UNZIP_CODEC)
  const ansiText = decode(raw, ANSI_CODEC)

  if (upathHit) {
    const override: Prediction = {
      name: upath.utf8Name,
      rule: 'upath_override',
      source: UPATH_CODEC,
    }
    return Object.fromEntries(EXTRACTORS.map((tool) => [tool, { ...override }]))
  }

  const out: Record<string, Prediction> = {}
  out['python-zipfile'] =
    utf8Text !== null
      ? { name: utf8Text, rule: 'utf8_bit11' }
      : { name: cp437Text, rule: 'cp437_fallback' }
  out['info-zip-unzip'] = {
    name: cp850Text === null ? null : transliterateOem(cp850Text),
    rule: 'cp850_oem_transliterated',
    source: UNZIP_CODEC,
  }
  for (const tool of ['7zip', 'libarchive'] as const) {
    if (utf8Text !== null) out[tool] = { name: utf8Text, rule: 'utf8_bit11' }
    else if (ansiText !== null) out[tool] = { name: ansiText, rule: 'ansi_codepage', source: ANSI_CODEC }
    else if (chosen !== null) {
      out[tool] = { name: chosen.name, rule: 'ansi_codepage', source: chosen.encoding }
    } else out[tool] = { name: null, rule: 'undecodable', reason: 'no_complete_candidate' }
  }
  return out
}

export function confidence(bit11: boolean, upath: UpathField, chosen: Candidate | null): string {
  if (bit11) return 'high'
  if (upath.present && upath.crcValid === true) return 'high'
  if (upath.present && upath.crcValid === false) return 'low'
  if (chosen !== null && chosen.commonZone) return 'medium'
  return 'low'
}

export interface EncodingBlockEntry {
  readonly entryIndex: number
  readonly rawNameHex: string
  readonly bit11: boolean
  readonly upath: Record<string, unknown>
  readonly candidates: Candidate[]
  readonly preferred: string | null
  readonly confidence: string
  readonly effectiveName: string | null
  readonly predictedNames: Record<string, Prediction>
}

/** MOD-2 的全部判定：`[findings, 报告块]`；块按 entry_index 升序。 */
export function checkEncoding(archive: Archive): [Finding[], EncodingBlockEntry[]] {
  const findings: Finding[] = []
  const block: EncodingBlockEntry[] = []
  for (const entry of archive.entries) {
    const facts = describe(entry)
    const candidateList = candidates(entry.cdName)
    const chosen = preferred(candidateList)
    const level = confidence(facts.bit11, facts.upath, chosen)
    const predictions = predictNames(entry.cdName, facts.bit11, facts.upath, chosen)

    if (facts.upath.present && facts.upath.crcValid === false) {
      findings.push(
        makeFinding({
          ruleId: 'encoding.UPATH_CRC_MISMATCH',
          message:
            'Unicode path extra field 的 NameCRC32 与条目原名字节不符：0x7075 的覆盖失效，按原名字节解释（不同工具会写出不同名字）',
          evidence: {
            fieldId: UPATH_ID,
            version: facts.upath.version,
            nameCrc32: facts.upath.nameCrc32,
            expectedCrc32: expectedNameCrc(entry),
            utf8Name: facts.upath.utf8Name,
            downgradedTo: level,
          },
          precedent: 'apnote_d6_upath_crc',
          entryIndex: entry.index,
          lfhOffset: entry.lfhOffset,
          cdOffset: entry.cdOffset,
          lfhName: displayName(entry.lfhName),
          cdName: displayName(entry.cdName),
        }),
      )
    }

    const sevenZip = predictions['7zip']
    block.push({
      entryIndex: entry.index,
      rawNameHex: facts.rawNameHex,
      bit11: facts.bit11,
      upath: upathToJSON(facts.upath),
      candidates: candidateList,
      preferred: chosen === null ? null : chosen.encoding,
      confidence: level,
      effectiveName:
        sevenZip.rule === 'upath_override' ? sevenZip.name : chosen === null ? null : chosen.name,
      predictedNames: predictions,
    })
  }
  return [sortFindings(findings), block]
}

export function countLowConfidence(block: readonly EncodingBlockEntry[]): number {
  return block.filter((item) => item.confidence === 'low').length
}