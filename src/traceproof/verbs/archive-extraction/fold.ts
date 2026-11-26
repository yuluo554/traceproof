/**
 * archive-extraction · MOD-3 跨平台落盘折叠（迁移自源仓 `rules/fold.py`）。
 *
 * 四条规则，判定顺序固定 FILEDIR → CASEFOLD → NFC → TRIM；同一对名字可命中多条，全部输出。
 *
 * | 规则 | windows | macos | linux |
 * |---|---|---|---|
 * | `collision.FILEDIR` | 报 | 报 | 报 |
 * | `collision.CASEFOLD` | 真实 `$UpCase` 表 | 不报（无 macOS 折叠表） | 不报 |
 * | `collision.NFC` | 不报 | 报（NFD 比较） | 不报 |
 * | `collision.TRIM` | 报 | 不报 | 不报 |
 *
 * Windows 折叠只来自 `$UpCase` 表，本模块不出现任何大小写近似。写序 = CD 顺序；
 * `survivor` = 后写者（FILEDIR 例外：先写者存活，因为后写者根本没落盘）。
 */

import type { Archive, EntryView } from './archive.js'
import { makeCollision, sortCollisions } from './findings.js'
import type { Collision } from './findings.js'
import type { PlatformTables } from './platforms.js'
import { decodeSurrogateEscape } from './util.js'

export const PLATFORMS = ['windows', 'macos', 'linux'] as const
export type Platform = (typeof PLATFORMS)[number]

export const JUDGEMENT_ORDER = [
  'collision.FILEDIR',
  'collision.CASEFOLD',
  'collision.NFC',
  'collision.TRIM',
] as const

export const WINDOWS_TRAILING_CHARS = ' .'

export const EVIDENCE: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  'collision.FILEDIR': { windows: 'measured', macos: 'measured', linux: 'measured' },
  'collision.CASEFOLD': { windows: 'table_simulated' },
  'collision.NFC': { macos: 'medium' },
  'collision.TRIM': { windows: 'measured' },
}

export const SOURCES: Readonly<Record<string, string>> = {
  'collision.FILEDIR': 'structural_self_evidence',
  'collision.CASEFOLD': 'ntfs_upcase_table',
  'collision.NFC': 'TN1150 + UAX #15 + libfsapfs',
  'collision.TRIM': 'MS Learn naming conventions',
}

function asText(raw: Uint8Array): string {
  return decodeSurrogateEscape(raw)
}

/** Windows 裁剪：逐组件去掉尾随空格与点（不是整串）；裁成空串时保留原样。 */
export function trimTrailing(name: string): string {
  return name
    .split('/')
    .map((part) => {
      let end = part.length
      while (end > 0 && (part[end - 1] === ' ' || part[end - 1] === '.')) end -= 1
      const trimmed = part.slice(0, end)
      return trimmed.length === 0 ? part : trimmed
    })
    .join('/')
}

/** macOS 侧的比较形：NFD（TN1150 "fully decomposed and in canonical order"）。 */
export function nfd(name: string): string {
  return name.normalize('NFD')
}

function prefixView(name: string, platform: string, tables: PlatformTables): string {
  if (platform === 'windows') return tables.windows.fold(trimTrailing(name))
  if (platform === 'macos') return nfd(name)
  return name
}

function pairBase(
  code: string,
  platform: string,
  left: EntryView,
  right: EntryView,
  onDisk: readonly [string, string],
  evidence: Record<string, unknown>,
): Collision {
  return makeCollision({
    code,
    platform,
    names: [asText(left.cdName), asText(right.cdName)],
    onDiskNames: onDisk,
    writeOrder: [left.index, right.index],
    cdOffsets: [left.cdOffset, right.cdOffset],
    survivor: asText(right.cdName),
    survivorEntryIndex: right.index,
    verdict: 'overwritten',
    evidenceStrength: EVIDENCE[code][platform],
    evidence: { ...evidence, source: SOURCES[code] },
  })
}

/** `collision.FILEDIR`：同一路径既要当文件又要当目录（三平台都报）。 */
export function filedirPairs(
  archive: Archive,
  platform: string,
  tables: PlatformTables,
): Collision[] {
  const found: Collision[] = []
  const entries = archive.entries
  for (const left of entries) {
    for (const right of entries) {
      if (left.index >= right.index) continue
      for (const [fileEntry, dirEntry] of [
        [left, right],
        [right, left],
      ] as const) {
        const fileView = prefixView(asText(fileEntry.cdName), platform, tables)
        const dirView = prefixView(asText(dirEntry.cdName), platform, tables)
        if (
          !dirView.startsWith(`${fileView}/`) ||
          !(dirView.length > fileView.length + 1)
        ) {
          continue
        }
        const [first, second] =
          fileEntry.index <= dirEntry.index
            ? [fileEntry, dirEntry]
            : [dirEntry, fileEntry]
        found.push(
          makeCollision({
            code: 'collision.FILEDIR',
            platform,
            names: [asText(first.cdName), asText(second.cdName)],
            onDiskNames: [
              prefixView(asText(first.cdName), platform, tables),
              prefixView(asText(second.cdName), platform, tables),
            ],
            writeOrder: [first.index, second.index],
            cdOffsets: [first.cdOffset, second.cdOffset],
            // 先写者存活：后写者要么建不出文件（同名目录已在），要么建不出目录。
            survivor: asText(first.cdName),
            survivorEntryIndex: first.index,
            verdict: 'skipped',
            evidenceStrength: EVIDENCE['collision.FILEDIR'][platform],
            evidence: {
              fileEntryIndex: fileEntry.index,
              directoryEntryIndex: dirEntry.index,
              reason: '同一路径既是文件又要求作目录',
              readers: {
                'python-zipfile': 'error',
                'info-zip-unzip': 'error',
                '7zip': 'error',
                libarchive: 'coerced_to_directory',
              },
              source: SOURCES['collision.FILEDIR'],
            },
          }),
        )
        break // 一对条目最多产生一条 FILEDIR
      }
    }
  }
  return found
}

/** `collision.CASEFOLD`：目标平台大小写规则下相撞（仅 windows，逐码元查表）。 */
export function casefoldPairs(
  archive: Archive,
  platform: string,
  tables: PlatformTables,
): Collision[] {
  if (platform !== 'windows') return []
  const table = tables.windows
  const found: Collision[] = []
  const entries = archive.entries
  for (let position = 0; position < entries.length; position += 1) {
    const left = entries[position]
    for (const right of entries.slice(position + 1)) {
      const leftText = asText(left.cdName)
      const rightText = asText(right.cdName)
      const trimmedLeft = trimTrailing(leftText)
      const trimmedRight = trimTrailing(rightText)
      if (trimmedLeft === trimmedRight) continue // 纯裁剪差异 → 归 collision.TRIM
      const foldedLeft = table.fold(trimmedLeft)
      const foldedRight = table.fold(trimmedRight)
      if (foldedLeft !== foldedRight) continue
      found.push(
        pairBase('collision.CASEFOLD', platform, left, right, [trimmedLeft, trimmedRight], {
          algorithm: 'ntfs_upcase_table',
          tableSha256: table.tableId,
          compared: [trimmedLeft, trimmedRight],
          folded: [foldedLeft, foldedRight],
        }),
      )
    }
  }
  return found
}

/** `collision.NFC`：NFD 后相撞（仅 macos）。 */
export function nfcPairs(archive: Archive, platform: string): Collision[] {
  if (platform !== 'macos') return []
  const found: Collision[] = []
  const entries = archive.entries
  for (let position = 0; position < entries.length; position += 1) {
    const left = entries[position]
    for (const right of entries.slice(position + 1)) {
      const leftText = asText(left.cdName)
      const rightText = asText(right.cdName)
      if (leftText === rightText) continue // 逐字节相同：覆盖语义，不是归一化差异
      const normalizedLeft = nfd(leftText)
      const normalizedRight = nfd(rightText)
      if (normalizedLeft !== normalizedRight) continue
      found.push(
        pairBase('collision.NFC', platform, left, right, [normalizedLeft, normalizedRight], {
          form: 'NFD',
          normalized: [normalizedLeft, normalizedRight],
          note: '实现观察，非 Apple 官方规范（plan/00 决策 ④）',
        }),
      )
    }
  }
  return found
}

/** `collision.TRIM`：尾随空格/点裁剪后相撞（仅 Windows）。 */
export function trimPairs(archive: Archive, platform: string): Collision[] {
  if (platform !== 'windows') return []
  const found: Collision[] = []
  const entries = archive.entries
  for (let position = 0; position < entries.length; position += 1) {
    const left = entries[position]
    for (const right of entries.slice(position + 1)) {
      const leftText = asText(left.cdName)
      const rightText = asText(right.cdName)
      const trimmedLeft = trimTrailing(leftText)
      const trimmedRight = trimTrailing(rightText)
      if (trimmedLeft !== trimmedRight) continue
      if (leftText === trimmedLeft && rightText === trimmedRight) continue // 两条都没被裁剪过
      found.push(
        pairBase('collision.TRIM', platform, left, right, [trimmedLeft, trimmedRight], {
          trimmed: [trimmedLeft, trimmedRight],
          chars: WINDOWS_TRAILING_CHARS,
        }),
      )
    }
  }
  return found
}

/** MOD-3 的全部判定；评估顺序固定，输出按 `(min(cdOffset), code, platform, writeOrder)`。 */
export function checkFold(
  archive: Archive,
  targets: readonly string[],
  tables: PlatformTables,
): Collision[] {
  const unknown = targets.filter((name) => !(PLATFORMS as readonly string[]).includes(name))
  if (unknown.length > 0) throw new Error(`未知目标平台: ${unknown.join(', ')}`)
  const found: Collision[] = []
  for (const platform of PLATFORMS) {
    if (!targets.includes(platform)) continue
    for (const code of JUDGEMENT_ORDER) {
      if (code === 'collision.FILEDIR') found.push(...filedirPairs(archive, platform, tables))
      else if (code === 'collision.CASEFOLD') found.push(...casefoldPairs(archive, platform, tables))
      else if (code === 'collision.NFC') found.push(...nfcPairs(archive, platform))
      else found.push(...trimPairs(archive, platform))
    }
  }
  return sortCollisions(found)
}