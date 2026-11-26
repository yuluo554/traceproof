/**
 * archive-extraction · MOD-1 双头差分与重叠（迁移自源仓 `rules/structure.py`）。
 *
 * **六条规则，零解码**：全部判定落在字节层给出的结构事实上。`precedent` 必填，取值只能是
 * 实现选择枚举或 `structural_self_evidence`；**不引**"规范要求 LFH 与 CD 一致"
 * （源仓逐字检索 APPNOTE 6.3.10 无此句）。
 */

import type { Archive, EntryView } from './archive.js'
import { makeFinding, sortFindings } from './findings.js'
import type { Finding } from './findings.js'
import { displayName } from './util.js'

export const PRECEDENTS = [
  'unzip_reads_cd',
  'libzip_reads_cd',
  'python_zipfile_reads_cd',
  'libarchive_reads_lfh',
  'structural_self_evidence',
] as const

/** general purpose bit flag bit 3 = 有 data descriptor。 */
export const FLAG_DATA_DESCRIPTOR = 0x0008

export const STRUCTURE_CODES = [
  'structure.NAME_DIVERGES',
  'structure.CRC_DIVERGES',
  'structure.SIZE_DIVERGES',
  'structure.FLAG_DIVERGES',
  'structure.LFH_OVERLAP',
  'structure.CD_COUNT_MISMATCH',
] as const

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

function dataDescriptorExempt(entry: EntryView, lfhValue: number): boolean {
  return (entry.lfhFlags & FLAG_DATA_DESCRIPTOR) !== 0 && lfhValue === 0
}

/** `structure.NAME_DIVERGES`：`lfh_name != cd_name`（字节比较，不解码）。 */
export function checkName(entry: EntryView): Finding | null {
  if (bytesEqual(entry.lfhName, entry.cdName)) return null
  return base(
    entry,
    'structure.NAME_DIVERGES',
    '本地头与中央目录的名字不同：不同工具会写出不同文件名',
    {
      lfhNameHex: hex(entry.lfhName),
      cdNameHex: hex(entry.cdName),
      lfhNameLength: entry.lfhName.length,
      cdNameLength: entry.cdName.length,
      readers: {
        libarchive: 'lfh',
        '7zip': 'lfh',
        'info-zip-unzip': 'cd',
        libzip: 'cd',
        'python-zipfile': 'cd',
      },
    },
    'libarchive_reads_lfh',
  )
}

/** `structure.CRC_DIVERGES`：`lfh_crc != cd_crc`（bit 3 + LFH 为 0 时豁免）。 */
export function checkCrc(entry: EntryView): Finding | null {
  if (dataDescriptorExempt(entry, entry.lfhCrc)) return null
  if (entry.lfhCrc === entry.cdCrc) return null
  return base(
    entry,
    'structure.CRC_DIVERGES',
    '本地头与中央目录的 CRC32 不同：一个工具报错、另一个照解',
    {
      lfhCrc: entry.lfhCrc,
      cdCrc: entry.cdCrc,
      lfhFlags: entry.lfhFlags,
      cdFlags: entry.cdFlags,
      dataDescriptor: (entry.lfhFlags & FLAG_DATA_DESCRIPTOR) !== 0,
    },
    'libarchive_reads_lfh',
  )
}

/** `structure.SIZE_DIVERGES`：压缩/未压缩大小任一不等（bit 3 豁免同上）。 */
export function checkSize(entry: EntryView): Finding | null {
  if (
    dataDescriptorExempt(entry, entry.lfhCsize) &&
    dataDescriptorExempt(entry, entry.lfhUsize)
  ) {
    return null
  }
  if (entry.lfhCsize === entry.cdCsize && entry.lfhUsize === entry.cdUsize) return null
  return base(
    entry,
    'structure.SIZE_DIVERGES',
    '本地头与中央目录的大小不同：按哪个头读会得到不同字节数',
    {
      lfhCompSize: entry.lfhCsize,
      cdCompSize: entry.cdCsize,
      lfhUncompSize: entry.lfhUsize,
      cdUncompSize: entry.cdUsize,
      lfhFlags: entry.lfhFlags,
      cdFlags: entry.cdFlags,
      dataDescriptor: (entry.lfhFlags & FLAG_DATA_DESCRIPTOR) !== 0,
    },
    'libarchive_reads_lfh',
  )
}

/** `structure.FLAG_DIVERGES`：`lfh_flags != cd_flags`（全 16 位比较）。 */
export function checkFlags(entry: EntryView): Finding | null {
  if (entry.lfhFlags === entry.cdFlags) return null
  const diff = entry.lfhFlags ^ entry.cdFlags
  const bits: number[] = []
  for (let bit = 0; bit < 16; bit += 1) {
    if ((diff & (1 << bit)) !== 0) bits.push(bit)
  }
  return base(
    entry,
    'structure.FLAG_DIVERGES',
    '本地头与中央目录的 general purpose flag 不同：同一份名字会按不同编码/加密语义解释',
    { lfhFlags: entry.lfhFlags, cdFlags: entry.cdFlags, differingBits: bits },
    'unzip_reads_cd',
  )
}

/** `structure.LFH_OVERLAP`：两个 LFH 的物理区间 `[start, end)` 相交（相邻不算）。 */
export function checkOverlap(entries: readonly EntryView[]): Finding[] {
  const ordered = [...entries].sort((left, right) => {
    if (left.lfhOffset !== right.lfhOffset) return left.lfhOffset - right.lfhOffset
    if (left.lfhEnd !== right.lfhEnd) return left.lfhEnd - right.lfhEnd
    return left.index - right.index
  })
  const found: Finding[] = []
  for (let position = 0; position + 1 < ordered.length; position += 1) {
    const left = ordered[position]
    const right = ordered[position + 1]
    if (right.lfhOffset >= left.lfhEnd) continue
    found.push(
      base(
        right,
        'structure.LFH_OVERLAP',
        '两个本地文件头记录物理相交：一个工具拒绝、另一些照解',
        {
          first: { entryIndex: left.index, start: left.lfhOffset, end: left.lfhEnd },
          second: { entryIndex: right.index, start: right.lfhOffset, end: right.lfhEnd },
          readers: {
            'python-zipfile': 'refused',
            'info-zip-unzip': 'extracted',
            '7zip': 'extracted',
            libarchive: 'extracted',
          },
        },
        // 重叠不是"读哪个头"的问题：它是物理布局的自证（区间相交）。
        'structural_self_evidence',
      ),
    )
  }
  return found
}

/** `structure.CD_COUNT_MISMATCH`：EOCD 声明条目数 ≠ 实际解析到的 CD 条目数。 */
export function checkCount(archive: Archive): Finding | null {
  const declared = archive.probe.declaredEntries
  const actual = archive.cdActualEntries
  if (declared === actual) return null
  return makeFinding({
    ruleId: 'structure.CD_COUNT_MISMATCH',
    message: 'EOCD 声明的条目数与中央目录实际条目数不同',
    evidence: {
      declared,
      actual,
      zip64: archive.zip64,
      cdSpanStart: archive.cdSpan[0],
      cdSpanEnd: archive.cdSpan[1],
    },
    precedent: 'structural_self_evidence',
  })
}

/** MOD-1 的全部判定（输出按 `(cd_offset, ruleId)` 升序）。 */
export function checkStructure(archive: Archive): Finding[] {
  const found: Finding[] = []
  for (const entry of archive.entries) {
    for (const rule of [checkName, checkCrc, checkSize, checkFlags]) {
      const finding = rule(entry)
      if (finding !== null) found.push(finding)
    }
  }
  found.push(...checkOverlap(archive.entries))
  const count = checkCount(archive)
  if (count !== null) found.push(count)
  return sortFindings(found)
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false
  }
  return true
}

function hex(raw: Uint8Array): string {
  let out = ''
  for (const byte of raw) out += byte.toString(16).padStart(2, '0')
  return out
}