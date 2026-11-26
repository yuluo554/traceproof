/**
 * archive-extraction · MOD-5 长度预算（迁移自源仓 `rules/budget.py`）。
 *
 * | 规则 | 计量口径 |
 * |---|---|
 * | `budget.PATH_OVER_260` | Windows：UTF-16 码元（260，含终止 NUL）；Linux：字节（4096） |
 * | `budget.COMPONENT_OVER_255` | Windows：UTF-16 码元；Linux：字节（POSIX `{NAME_MAX}`） |
 *
 * `PATH_OVER_260` 是**可移植性预算告警**，不是"本机截断事实"（`evidence.kind` 显式标
 * `portability_budget`）。按组件切的口径与 MOD-4 一致：`/` 是分隔符；不做任何规范化/裁剪。
 */

import type { Archive, EntryView } from './archive.js'
import { makeFinding, sortFindings } from './findings.js'
import type { Finding } from './findings.js'
import { decodeSurrogateEscape, displayName, utf16Units } from './util.js'

export const PLATFORMS = ['windows', 'macos', 'linux'] as const

export const BUDGET_CODES = ['budget.PATH_OVER_260', 'budget.COMPONENT_OVER_255'] as const

export const PRECEDENTS = ['ms_learn_max_path', 'posix_name_max_bytes'] as const

export const WIN_MAX_PATH = 260
export const LINUX_PATH_MAX = 4096
export const NAME_MAX_DEFAULT = 255
export const WIN_MAX_PATH_EXTENDED = 32767
export const PATH_BUDGET_KIND = 'portability_budget'
export const SEPARATOR = '/'

export function components(name: string): string[] {
  return name.split(SEPARATOR)
}

export function byteLength(raw: Uint8Array): number {
  return raw.length
}

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

/** `budget.PATH_OVER_260`（Windows）：整路径 UTF-16 码元数 + 终止 NUL > 260。 */
export function checkPathWindows(entry: EntryView): Finding | null {
  const name = decodeSurrogateEscape(entry.cdName)
  const parts = components(name)
  const units = parts.reduce((sum, part) => sum + utf16Units(part), 0) + Math.max(parts.length - 1, 0) + 1
  if (units <= WIN_MAX_PATH) return null
  return base(
    entry,
    'budget.PATH_OVER_260',
    '整路径超出默认 MAX_PATH 预算：未开启长路径支持的目标上不可移植（这是**预算告警**，不是本机能不能创建的结论——见 evidence.kind）',
    {
      kind: PATH_BUDGET_KIND,
      units,
      limit: WIN_MAX_PATH,
      extendedLimit: WIN_MAX_PATH_EXTENDED,
      componentCount: parts.length,
      longestComponentUnits: parts.reduce((max, part) => Math.max(max, utf16Units(part)), 0),
      platform: 'windows',
    },
    'ms_learn_max_path',
  )
}

/** `budget.COMPONENT_OVER_255`（Windows）：任一组件 > 255 个 UTF-16 码元。 */
export function checkComponentWindows(entry: EntryView): Finding | null {
  const name = decodeSurrogateEscape(entry.cdName)
  const parts = components(name)
  const over = parts
    .map((part, index) => ({
      index,
      characters: Array.from(part).length,
      units: utf16Units(part),
    }))
    .filter((item) => item.units > NAME_MAX_DEFAULT)
  if (over.length === 0) return null
  const first = over[0]
  return base(
    entry,
    'budget.COMPONENT_OVER_255',
    '单个路径组件超出 255 个 UTF-16 码元：目标平台在创建时即失败',
    {
      kind: 'platform_limit',
      limit: NAME_MAX_DEFAULT,
      units: first.units,
      characters: first.characters,
      componentIndex: first.index,
      violations: over.map((item) => ({
        componentIndex: item.index,
        characters: item.characters,
        units: item.units,
      })),
      platform: 'windows',
    },
    'ms_learn_max_path',
  )
}

/** `budget.COMPONENT_OVER_255`（Linux）：任一组件 > 255 字节（POSIX `{NAME_MAX}`）。 */
export function checkComponentLinux(entry: EntryView): Finding | null {
  const raw = entry.cdName
  const parts: Uint8Array[] = []
  let start = 0
  for (let index = 0; index < raw.length; index += 1) {
    if (raw[index] === 0x2f) {
      parts.push(raw.subarray(start, index))
      start = index + 1
    }
  }
  parts.push(raw.subarray(start))
  const violations = parts
    .map((part, index) => ({ componentIndex: index, bytes: byteLength(part) }))
    .filter((item) => item.bytes > NAME_MAX_DEFAULT)
  if (violations.length === 0) return null
  const first = violations[0]
  return base(
    entry,
    'budget.COMPONENT_OVER_255',
    '单个路径组件超出 255 字节：POSIX `{NAME_MAX}` 的上限，目标平台创建时即失败',
    {
      kind: 'platform_limit',
      limit: NAME_MAX_DEFAULT,
      bytes: first.bytes,
      componentIndex: first.componentIndex,
      violations,
      platform: 'linux',
    },
    'posix_name_max_bytes',
  )
}

/** `budget.PATH_OVER_260`（Linux）：整路径 > 4096 字节（不含终止 NUL）。 */
export function checkPathLinux(entry: EntryView): Finding | null {
  const size = byteLength(entry.cdName)
  if (size <= LINUX_PATH_MAX) return null
  return base(
    entry,
    'budget.PATH_OVER_260',
    '整路径超出 POSIX `{PATH_MAX}` 字节预算：目标平台创建时即失败',
    {
      kind: 'platform_limit',
      bytes: size,
      limit: LINUX_PATH_MAX,
      platform: 'linux',
    },
    'posix_name_max_bytes',
  )
}

/** MOD-5 的预算判定（不读平台表）。 */
export function checkBudget(archive: Archive, targets: readonly string[]): Finding[] {
  const unknown = targets.filter((name) => !(PLATFORMS as readonly string[]).includes(name))
  if (unknown.length > 0) throw new Error(`未知目标平台: ${unknown.join(', ')}`)
  const found: Finding[] = []
  for (const entry of archive.entries) {
    if (targets.includes('windows')) {
      for (const finding of [checkPathWindows(entry), checkComponentWindows(entry)]) {
        if (finding !== null) found.push(finding)
      }
    }
    if (targets.includes('linux')) {
      for (const finding of [checkPathLinux(entry), checkComponentLinux(entry)]) {
        if (finding !== null) found.push(finding)
      }
    }
  }
  return sortFindings(found)
}

/** 本模块不需要平台语义（空元组 = 不读平台表）。 */
export function declaredPlatforms(): readonly string[] {
  return []
}