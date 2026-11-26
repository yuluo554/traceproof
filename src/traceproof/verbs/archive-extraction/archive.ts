/**
 * archive-extraction · 归档结构事实（迁移自源仓 `zip_reader.py` 的**已解析**形态）。
 *
 * 器官不读文件、不解析 ZIP 字节：EOCD / CD / LFH 三层事实由输入（`subject.archive`）提供，
 * 字段与源仓 `ZipProbe` / `EntryView` 一一对应。这里只做**形状校验**——非法载荷抛
 * `ArchivePayloadError`，由唯一入口映射为退出码 2（输入不合法），绝不降级成空结果。
 *
 * 字段命名保留源仓的 snake_case；名字与 extra 的精确字节用十六进制字符串表达
 * （`*_name_hex` / `data_hex`），判定内部再还原为字节。
 */

import { hexToBytes, isPlainObject, readBoolean, readInteger, readString } from './util.js'

export class ArchivePayloadError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ArchivePayloadError'
  }
}

export interface ExtraField {
  readonly fieldId: number
  readonly data: Uint8Array
}

export interface EntryView {
  readonly index: number
  readonly lfhOffset: number
  readonly lfhEnd: number
  readonly cdOffset: number
  readonly lfhName: Uint8Array
  readonly cdName: Uint8Array
  readonly lfhFlags: number
  readonly cdFlags: number
  readonly lfhCrc: number
  readonly cdCrc: number
  readonly lfhCsize: number
  readonly cdCsize: number
  readonly lfhUsize: number
  readonly cdUsize: number
  readonly lfhExtra: readonly ExtraField[]
  readonly cdExtra: readonly ExtraField[]
  readonly method: number
  readonly dataOffset: number
}

export interface ZipProbe {
  readonly archiveSize: number
  readonly eocdOffset: number
  readonly declaredEntries: number
  readonly declaredCdSize: number
  readonly declaredCdOffset: number
  readonly commentLength: number
}

export interface Archive {
  readonly probe: ZipProbe
  readonly entries: readonly EntryView[]
  readonly cdActualEntries: number
  readonly cdSpan: readonly [number, number]
  readonly zip64: boolean
  readonly data: Uint8Array
}

const PROBE_FIELDS = [
  'archive_size',
  'eocd_offset',
  'declared_entries',
  'declared_cd_size',
  'declared_cd_offset',
  'comment_length',
] as const

const ENTRY_FIELDS = [
  'index',
  'lfh_offset',
  'lfh_end',
  'cd_offset',
  'lfh_name_hex',
  'cd_name_hex',
  'lfh_flags',
  'cd_flags',
  'lfh_crc',
  'cd_crc',
  'lfh_csize',
  'cd_csize',
  'lfh_usize',
  'cd_usize',
  'lfh_extra',
  'cd_extra',
  'method',
  'data_offset',
] as const

const ARCHIVE_FIELDS = ['probe', 'entries', 'cd_span', 'zip64'] as const

function fail(message: string): never {
  throw new ArchivePayloadError(message)
}

function nonNegative(value: unknown, where: string): number {
  try {
    const number = readInteger(value, where)
    if (number < 0) fail(`${where} 不得为负`)
    return number
  } catch (error) {
    if (error instanceof ArchivePayloadError) throw error
    fail(`${where} 必须是整数（${(error as Error).message}）`)
  }
}

function parseExtra(raw: unknown, where: string): ExtraField[] {
  if (!Array.isArray(raw)) fail(`${where} 必须是数组`)
  return raw.map((item, position) => {
    const at = `${where}[${position}]`
    if (!isPlainObject(item)) fail(`${at} 必须是对象`)
    for (const key of Object.keys(item)) {
      if (key !== 'id' && key !== 'data_hex') fail(`${at} 含未知字段：${key}`)
    }
    const id = nonNegative(item.id, `${at}.id`)
    if (id > 0xffff) fail(`${at}.id 越界`)
    try {
      return { fieldId: id, data: hexToBytes(readString(item.data_hex, `${at}.data_hex`), `${at}.data_hex`) }
    } catch (error) {
      if (error instanceof ArchivePayloadError) throw error
      fail(`${at}.data_hex 非法（${(error as Error).message}）`)
    }
  })
}

function parseEntry(raw: unknown, position: number): EntryView {
  const where = `archive.entries[${position}]`
  if (!isPlainObject(raw)) fail(`${where} 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!(ENTRY_FIELDS as readonly string[]).includes(key)) {
      fail(`${where} 含未知字段：${key}`)
    }
  }
  for (const field of ENTRY_FIELDS) {
    if (!(field in raw)) fail(`${where} 缺字段：${field}`)
  }
  const index = nonNegative(raw.index, `${where}.index`)
  if (index !== position) fail(`${where}.index 必须等于数组下标（${position}）`)
  const readHex = (name: string): Uint8Array => {
    try {
      return hexToBytes(readString(raw[name], `${where}.${name}`), `${where}.${name}`)
    } catch (error) {
      if (error instanceof ArchivePayloadError) throw error
      fail(`${where}.${name} 非法（${(error as Error).message}）`)
    }
  }
  const flags = (name: string): number => {
    const value = nonNegative(raw[name], `${where}.${name}`)
    if (value > 0xffff) fail(`${where}.${name} 越界`)
    return value
  }
  const crc = (name: string): number => {
    const value = nonNegative(raw[name], `${where}.${name}`)
    if (value > 0xffffffff) fail(`${where}.${name} 越界`)
    return value
  }
  return {
    index,
    lfhOffset: nonNegative(raw.lfh_offset, `${where}.lfh_offset`),
    lfhEnd: nonNegative(raw.lfh_end, `${where}.lfh_end`),
    cdOffset: nonNegative(raw.cd_offset, `${where}.cd_offset`),
    lfhName: readHex('lfh_name_hex'),
    cdName: readHex('cd_name_hex'),
    lfhFlags: flags('lfh_flags'),
    cdFlags: flags('cd_flags'),
    lfhCrc: crc('lfh_crc'),
    cdCrc: crc('cd_crc'),
    lfhCsize: nonNegative(raw.lfh_csize, `${where}.lfh_csize`),
    cdCsize: nonNegative(raw.cd_csize, `${where}.cd_csize`),
    lfhUsize: nonNegative(raw.lfh_usize, `${where}.lfh_usize`),
    cdUsize: nonNegative(raw.cd_usize, `${where}.cd_usize`),
    lfhExtra: parseExtra(raw.lfh_extra, `${where}.lfh_extra`),
    cdExtra: parseExtra(raw.cd_extra, `${where}.cd_extra`),
    method: flags('method'),
    dataOffset: nonNegative(raw.data_offset, `${where}.data_offset`),
  }
}

function parseProbe(raw: unknown): ZipProbe {
  if (!isPlainObject(raw)) fail('archive.probe 必须是对象')
  for (const key of Object.keys(raw)) {
    if (!(PROBE_FIELDS as readonly string[]).includes(key)) {
      fail(`archive.probe 含未知字段：${key}`)
    }
  }
  for (const field of PROBE_FIELDS) {
    if (!(field in raw)) fail(`archive.probe 缺字段：${field}`)
  }
  return {
    archiveSize: nonNegative(raw.archive_size, 'archive.probe.archive_size'),
    eocdOffset: nonNegative(raw.eocd_offset, 'archive.probe.eocd_offset'),
    declaredEntries: nonNegative(raw.declared_entries, 'archive.probe.declared_entries'),
    declaredCdSize: nonNegative(raw.declared_cd_size, 'archive.probe.declared_cd_size'),
    declaredCdOffset: nonNegative(raw.declared_cd_offset, 'archive.probe.declared_cd_offset'),
    commentLength: nonNegative(raw.comment_length, 'archive.probe.comment_length'),
  }
}

function parseDataBase64(raw: unknown): Uint8Array {
  if (raw === undefined || raw === null) return new Uint8Array(0)
  if (typeof raw !== 'string') fail('archive.data_b64 必须是字符串')
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(raw) || raw.length % 4 !== 0) {
    fail('archive.data_b64 不是合法 base64')
  }
  return new Uint8Array(Buffer.from(raw, 'base64'))
}

export function readArchive(raw: unknown): Archive {
  if (!isPlainObject(raw)) fail('archive 必须是对象')
  for (const key of Object.keys(raw)) {
    if (
      !(ARCHIVE_FIELDS as readonly string[]).includes(key) &&
      key !== 'data_b64' &&
      key !== 'cd_actual_entries'
    ) {
      fail(`archive 含未知字段：${key}`)
    }
  }
  for (const field of ARCHIVE_FIELDS) {
    if (!(field in raw)) fail(`archive 缺字段：${field}`)
  }
  if (!Array.isArray(raw.entries)) fail('archive.entries 必须是数组')
  const entries = raw.entries.map((item, position) => parseEntry(item, position))
  if ('cd_actual_entries' in raw) {
    const actual = nonNegative(raw.cd_actual_entries, 'archive.cd_actual_entries')
    if (actual !== entries.length) {
      fail('archive.cd_actual_entries 与 entries 长度不一致')
    }
  }
  if (!Array.isArray(raw.cd_span) || raw.cd_span.length !== 2) {
    fail('archive.cd_span 必须是二元数组')
  }
  const spanStart = nonNegative(raw.cd_span[0], 'archive.cd_span[0]')
  const spanEnd = nonNegative(raw.cd_span[1], 'archive.cd_span[1]')
  if (spanEnd < spanStart) fail('archive.cd_span 结束不得早于开始')
  return {
    probe: parseProbe(raw.probe),
    entries,
    cdActualEntries: entries.length,
    cdSpan: [spanStart, spanEnd],
    zip64: readBoolean(raw.zip64, 'archive.zip64'),
    data: parseDataBase64(raw.data_b64),
  }
}