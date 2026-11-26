/**
 * archive-extraction · 平台语义表（迁移自源仓 `platforms.py` 的查表原语与 `encoding.py` 的
 * 单字节码表）。
 *
 * 三条契约（与源仓一致）：
 *  1. `source` 只能是 `volume_read` / `host_probe`——大小写近似不是合法来源；
 *  2. 表指纹与本体逐字节对得上：`data/ntfs-upcase.json` 以「非恒等映射」紧凑形式携带
 *     `$UpCase` 全表（65536 × uint16），装载时重建整表并核对 `sha256`，对不上即拒绝
 *     （器官不静默使用被换过的表）；
 *  3. 平台表是**数据**，不是判定；判定（折叠规则、判定顺序）在 `fold.ts` / `access.ts`。
 *
 * 单字节码表（CP437 / CP850 / CP1251）与 `unzip` 的 OEM→ANSI best-fit 替换表同样随包导入。
 * GBK / CP932 / CP949 走宿主 `TextDecoder`（WHATWG 标签），与源仓 Python codec 在全部
 * shipped fixtures 上逐字节一致（见 `docs/archive-extraction.md` §7）。
 */

import { createHash } from 'node:crypto'

import codecData from './data/codecs.json' with { type: 'json' }
import platformData from './data/platforms.json' with { type: 'json' }
import upcaseData from './data/ntfs-upcase.json' with { type: 'json' }

import { ContractError } from '../../core/ledger.js'

export const TABLE_CODEPOINTS = 65536
export const TABLE_BYTES = TABLE_CODEPOINTS * 2

export const VALID_SOURCES = ['volume_read', 'host_probe'] as const
export type TableSource = (typeof VALID_SOURCES)[number]

interface UpcasePayload {
  readonly entries: number
  readonly sha256: string
  readonly source: string
  readonly encoding: string
  readonly changes: readonly number[]
}

const UPCASE = upcaseData as UpcasePayload

let cachedTable: NtfsUpcase | null = null

export class NtfsUpcase {
  readonly entries: number
  readonly sha256: string
  readonly source: TableSource
  private readonly mapping: ReadonlyMap<number, number>

  constructor(payload: UpcasePayload) {
    if (payload.entries !== TABLE_CODEPOINTS || payload.encoding !== 'uint16-le') {
      throw new ContractError('NTFS $UpCase 表元数据与表结构不符')
    }
    if (!(VALID_SOURCES as readonly string[]).includes(payload.source)) {
      throw new ContractError(`NTFS $UpCase 表 source 非法：${String(payload.source)}`)
    }
    const changes = payload.changes
    if (!Array.isArray(changes) || changes.length % 2 !== 0) {
      throw new ContractError('NTFS $UpCase 表的 changes 必须是偶数长度数组')
    }
    const mapping = new Map<number, number>()
    for (let index = 0; index < changes.length; index += 2) {
      const codepoint = changes[index]
      const mapped = changes[index + 1]
      if (!Number.isInteger(codepoint) || !Number.isInteger(mapped)) {
        throw new ContractError('NTFS $UpCase 表的 changes 含非整数')
      }
      if (codepoint < 0 || codepoint >= TABLE_CODEPOINTS) {
        throw new ContractError(`NTFS $UpCase 表码点越界：${codepoint}`)
      }
      mapping.set(codepoint, mapped)
    }
    this.mapping = mapping
    this.entries = payload.entries
    this.source = payload.source as TableSource
    this.sha256 = payload.sha256
    this.verify()
  }

  /** 重建整表并核对 `sha256`；被换过的表直接拒绝（契约违约，退出码 3）。 */
  private verify(): void {
    const table = Buffer.alloc(TABLE_BYTES)
    for (let unit = 0; unit < TABLE_CODEPOINTS; unit += 1) {
      table.writeUInt16LE(this.mapUnit(unit), unit * 2)
    }
    const actual = createHash('sha256').update(table).digest('hex')
    if (actual !== this.sha256) {
      throw new ContractError(
        `NTFS $UpCase 表指纹对不上（期望 ${this.sha256}，实算 ${actual}）`,
      )
    }
  }

  mapUnit(unit: number): number {
    return this.mapping.get(unit) ?? unit
  }

  /** 按表折叠一个名字（逐 UTF-16 码元查表；非 BMP 码点原样保留）。 */
  fold(text: string): string {
    const parts: string[] = []
    for (const ch of text) {
      const codepoint = ch.codePointAt(0) as number
      if (codepoint < TABLE_CODEPOINTS && ch.length === 1) {
        parts.push(String.fromCharCode(this.mapUnit(codepoint)))
      } else {
        parts.push(ch)
      }
    }
    return parts.join('')
  }

  /** 报告里可出现的表指纹（`sha256` 前 16 位）。 */
  get tableId(): string {
    return this.sha256.slice(0, 16)
  }
}

export interface PlatformTables {
  readonly windows: NtfsUpcase
  readonly macos: Readonly<Record<string, unknown>>
  readonly linux: Readonly<Record<string, unknown>>
}

export function platformTables(): PlatformTables {
  if (cachedTable === null) {
    const platforms = platformData as Record<string, Record<string, unknown>>
    cachedTable = new NtfsUpcase(UPCASE)
    return {
      windows: cachedTable,
      macos: platforms.macos ?? {},
      linux: platforms.linux ?? {},
    }
  }
  const platforms = platformData as Record<string, Record<string, unknown>>
  return { windows: cachedTable, macos: platforms.macos ?? {}, linux: platforms.linux ?? {} }
}

export interface SingleByteCodec {
  readonly name: string
  readonly high: readonly (string | null)[]
}

function tableOf(name: string, raw: readonly (string | null)[]): SingleByteCodec {
  if (raw.length !== 128) throw new ContractError(`${name} 码表长度不是 128`)
  return { name, high: raw }
}

const CODECS = codecData as {
  readonly cp437: readonly (string | null)[]
  readonly cp850: readonly (string | null)[]
  readonly cp1251: readonly (string | null)[]
  readonly cp850_transliteration: Readonly<Record<string, string>>
}

export const CP437: SingleByteCodec = tableOf('cp437', CODECS.cp437)
export const CP850: SingleByteCodec = tableOf('cp850', CODECS.cp850)
export const CP1251: SingleByteCodec = tableOf('cp1251', CODECS.cp1251)
export const CP850_TRANSLITERATION: Readonly<Record<string, string>> =
  CODECS.cp850_transliteration

/** 单字节码表解码：任一字节能映射为空即整串不可解（`null`）。 */
export function decodeSingleByte(codec: SingleByteCodec, raw: Uint8Array): string | null {
  const parts: string[] = []
  for (const byte of raw) {
    if (byte < 0x80) {
      parts.push(String.fromCharCode(byte))
      continue
    }
    const mapped = codec.high[byte - 0x80]
    if (mapped === null) return null
    parts.push(mapped)
  }
  return parts.join('')
}