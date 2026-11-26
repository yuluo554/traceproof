/**
 * archive-extraction · MOD-5 容器约定（迁移自源仓 `rules/container.py`）。
 *
 * 五条规则，零解压到磁盘：`mimetype` 的内容按 method 在内存里取（stored 直接切片，
 * deflate 用原生 inflate 只取那一段流）。容器识别=`mimetype` 存在且（`META-INF/container.xml`
 * 存在或内容为 EPUB / ODF media type）；识别不出→不做容器检查，不猜。
 *
 * `container.MIMETYPE_PADDING` 在 ODF 上下文里 `evidence.inferred = true`（原文未明文禁止，
 * 从 media-type 相等约束推出）；EPUB 上下文里是原文明文，`inferred = false`。
 */

import { inflateRawSync } from 'node:zlib'

import type { Archive, EntryView } from './archive.js'
import { makeFinding, sortFindings } from './findings.js'
import type { Finding } from './findings.js'
import { decodeStrictUtf8, decodeSurrogateEscape, displayName } from './util.js'

export const CONTAINER_CODES = [
  'container.MIMETYPE_NOT_FIRST',
  'container.MIMETYPE_COMPRESSED',
  'container.MIMETYPE_EXTRA',
  'container.MIMETYPE_PADDING',
  'container.UTF8_REQUIRED',
] as const

export const PRECEDENTS = [
  'epub_ocf_zip_requirements',
  'odf_package_requirements',
  'odf_padding_inferred',
  'epub_ocf_utf8_names',
] as const

export const KINDS = ['epub', 'odf', 'none'] as const
export type ContainerKind = (typeof KINDS)[number]

export const MIMETYPE_NAME = 'mimetype'
export const CONTAINER_XML_NAME = 'META-INF/container.xml'
export const EPUB_MEDIA_TYPE = 'application/epub+zip'
export const ODF_MEDIA_TYPE_PREFIX = 'application/vnd.oasis.opendocument.'

export const METHOD_STORED = 0
export const METHOD_DEFLATE = 8
export const FLAG_ENCRYPTED = 0x0001
export const FLAG_UTF8 = 0x0800
export const MAX_MIMETYPE_BYTES = 4096

function base(
  entry: EntryView,
  ruleId: string,
  message: string,
  evidence: Record<string, unknown>,
  precedent: string,
): Finding {
  return makeFinding({
    ruleId,
    message,
    evidence,
    precedent,
    entryIndex: entry.index,
    lfhOffset: entry.lfhOffset,
    cdOffset: entry.cdOffset,
    lfhName: displayName(entry.lfhName),
    cdName: displayName(entry.cdName),
  })
}

function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let index = 0; index < text.length; index += 1) out[index] = text.charCodeAt(index)
  return out
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false
  }
  return true
}

export function findMimetype(archive: Archive): EntryView | null {
  const target = asciiBytes(MIMETYPE_NAME)
  return archive.entries.find((entry) => bytesEqual(entry.cdName, target)) ?? null
}

/** 在内存里取 `mimetype` 的未压缩内容；取不到返回 `null`（不猜、不落盘）。 */
export function readMimetypeBytes(archive: Archive, entry: EntryView): Uint8Array | null {
  if (archive.data.length === 0) return null
  const encrypted = (entry.cdFlags & FLAG_ENCRYPTED) !== 0
  const blob = archive.data.subarray(
    entry.dataOffset,
    entry.dataOffset + entry.cdCsize,
  )
  if (entry.method === METHOD_STORED && !encrypted) {
    return blob.subarray(0, Math.min(blob.length, MAX_MIMETYPE_BYTES + 1))
  }
  if (entry.method === METHOD_DEFLATE && !encrypted) {
    try {
      return new Uint8Array(
        inflateRawSync(blob, { maxOutputLength: MAX_MIMETYPE_BYTES + 1 }),
      )
    } catch {
      return null
    }
  }
  return null
}

export function detectKind(archive: Archive, mimetype: EntryView | null): ContainerKind {
  if (mimetype === null) return 'none'
  const containerXml = asciiBytes(CONTAINER_XML_NAME)
  const hasContainerXml = archive.entries.some((entry) => bytesEqual(entry.cdName, containerXml))
  const content = readMimetypeBytes(archive, mimetype)
  const text = content === null ? '' : decodeSurrogateEscape(content)
  const stripped = text.trim()
  if (stripped === EPUB_MEDIA_TYPE) return 'epub'
  if (stripped.startsWith(ODF_MEDIA_TYPE_PREFIX)) return 'odf'
  return hasContainerXml ? 'epub' : 'none'
}

export function checkNotFirst(archive: Archive, mimetype: EntryView): Finding | null {
  if (mimetype.index === 0) return null
  return base(
    mimetype,
    'container.MIMETYPE_NOT_FIRST',
    'mimetype 不是归档的首个条目：OCF/ODF 要求它排第一，否则读取器要扫全表才能认容器',
    {
      expectedIndex: 0,
      actualIndex: mimetype.index,
      firstEntryName:
        archive.entries.length === 0
          ? null
          : decodeSurrogateEscape(archive.entries[0].cdName),
    },
    'epub_ocf_zip_requirements',
  )
}

export function checkCompressed(mimetype: EntryView): Finding | null {
  const encrypted = (mimetype.cdFlags & FLAG_ENCRYPTED) !== 0
  if (mimetype.method === METHOD_STORED && !encrypted) return null
  return base(
    mimetype,
    'container.MIMETYPE_COMPRESSED',
    'mimetype 被压缩或加密：容器约定要求它以 stored（method=0）且未加密的形态存在',
    {
      method: mimetype.method,
      expectedMethod: METHOD_STORED,
      encrypted,
      cdFlags: mimetype.cdFlags,
    },
    'epub_ocf_zip_requirements',
  )
}

export function checkExtra(mimetype: EntryView): Finding | null {
  const ids = mimetype.cdExtra.map((item) => item.fieldId)
  if (ids.length === 0) return null
  return base(
    mimetype,
    'container.MIMETYPE_EXTRA',
    'mimetype 带了 extra field：容器约定要求这个条目不带附加字段',
    {
      extraIds: ids,
      lfhExtraIds: mimetype.lfhExtra.map((item) => item.fieldId),
    },
    'epub_ocf_zip_requirements',
  )
}

export function checkPadding(
  archive: Archive,
  mimetype: EntryView,
  kind: ContainerKind,
): Finding | null {
  const content = readMimetypeBytes(archive, mimetype)
  if (content === null) return null
  const text = decodeStrictUtf8(content)
  if (text === null) return null
  if (text === text.trim()) return null
  const inferred = kind === 'odf'
  return base(
    mimetype,
    'container.MIMETYPE_PADDING',
    'mimetype 内容前后有空白/padding：容器约定要求内容恰为 media type 本身',
    {
      leadingBytes: Array.from(text).length - Array.from(text.trimStart()).length,
      trailingBytes: Array.from(text).length - Array.from(text.trimEnd()).length,
      contentLength: content.length,
      inferred,
      evidence_strength: inferred ? 'inferred' : 'measured',
    },
    inferred ? 'odf_padding_inferred' : 'epub_ocf_zip_requirements',
  )
}

export function checkUtf8(archive: Archive, mimetype: EntryView, kind: ContainerKind): Finding | null {
  void mimetype
  if (kind !== 'epub') return null
  const offender = archive.entries.find(
    (entry) =>
      (entry.cdFlags & FLAG_UTF8) === 0 && entry.cdName.some((byte) => byte >= 0x80),
  )
  if (offender === undefined) return null
  return base(
    offender,
    'container.UTF8_REQUIRED',
    'OCF 要求归档内文件名用 UTF-8，但该条目的 bit 11 未置位：读取器会按历史 CP437 解释它',
    {
      bit11: (offender.cdFlags & FLAG_UTF8) !== 0,
      expectedBit11: true,
      rawNameHex: Array.from(offender.cdName, (byte) => byte.toString(16).padStart(2, '0')).join(''),
      container: kind,
    },
    'epub_ocf_utf8_names',
  )
}

/** MOD-5 的容器判定：`[findings, {kind}]`。 */
export function checkContainer(archive: Archive): [Finding[], { kind: ContainerKind }] {
  const mimetype = findMimetype(archive)
  const kind = detectKind(archive, mimetype)
  if (kind === 'none' || mimetype === null) return [[], { kind: 'none' }]
  const found: Finding[] = []
  for (const finding of [
    checkNotFirst(archive, mimetype),
    checkCompressed(mimetype),
    checkExtra(mimetype),
    checkPadding(archive, mimetype, kind),
    checkUtf8(archive, mimetype, kind),
  ]) {
    if (finding !== null) found.push(finding)
  }
  return [sortFindings(found), { kind }]
}