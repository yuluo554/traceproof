/**
 * archive-extraction · MOD-4 非法名与可访问性分级（迁移自源仓 `rules/access.py`）。
 *
 * 四级取值 `BLOCKED` / `WRITTEN_UNREADABLE` / `WRITTEN_TRUNCATED` / `OK`；`OK` 是"无上述
 * 三情形"的标记，不是级别。**判定顺序固定**：BLOCKED 类 → 保留名 → 裁剪；
 * `reasons[]` / `evidence[]` 收集全部命中项（不是先命中先返回）。
 *
 * 按组件判定，`/` 是分隔符：真正让创建失败的是**空组件**（`a//b` / `/a` / `a/`）。
 * 保留名按**裁剪后**的组件匹配，键取最后一个点之前的整体；`COM0` / `LPT0` / `CLOCK$`
 * 也算保留名（源仓实测收窄），上标 ¹²³ 变体不算。
 */

import type { Archive } from './archive.js'
import type { PlatformTables } from './platforms.js'
import { decodeSurrogateEscape, utf16Units } from './util.js'

export const PLATFORMS = ['windows', 'macos', 'linux'] as const

export const LEVELS = ['BLOCKED', 'WRITTEN_UNREADABLE', 'WRITTEN_TRUNCATED', 'OK'] as const
export type Level = (typeof LEVELS)[number]

/** 真正的三级（`OK` 不在其中——分级评分只看这三个）。 */
export const GRADES = ['BLOCKED', 'WRITTEN_UNREADABLE', 'WRITTEN_TRUNCATED'] as const

/** Windows 非法字符（MS Learn 保留字符集，去掉 `:`——冒号按 ADS 截断归 WRITTEN_TRUNCATED）。 */
export const WINDOWS_ILLEGAL = '<>\\|?*'

export const WINDOWS_TRAILING_CHARS = ' .'

export const RESERVED_DEVICE_NAMES: ReadonlySet<string> = new Set([
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'CLOCK$',
  ...Array.from({ length: 10 }, (_, index) => `COM${index}`),
  ...Array.from({ length: 10 }, (_, index) => `LPT${index}`),
])

export const EVIDENCE_TOKENS = [
  'test_path_false',
  'get_content_error',
  'open_readable',
  'illegal_char',
  'nul_byte',
  'empty_component',
  'dot_component',
  'component_too_long',
  'reserved_device_name',
  'trailing_space_or_dot',
  'ads_colon_truncation',
] as const

export const RESERVED_EVIDENCE = ['test_path_false', 'get_content_error', 'open_readable'] as const

export const REASON_TOKENS = [
  'empty_name',
  'nul_byte',
  'empty_component',
  'dot_component',
  'illegal_char',
  'component_too_long',
  'reserved_device_name',
  'trailing_space_or_dot',
  'ads_colon_truncation',
] as const

export const WINDOWS_MAX_COMPONENT = 255

export interface AccessVerdict {
  readonly level: Level
  readonly reasons: readonly string[]
  readonly evidence: readonly string[]
}

function splitComponents(name: string): string[] {
  return name.split('/')
}

function stemBeforeLastDot(component: string): string {
  const index = component.lastIndexOf('.')
  return index < 0 ? component : component.slice(0, index)
}

function judgeWindows(
  name: string,
  components: readonly string[],
  tables: PlatformTables,
): AccessVerdict {
  const reasons: string[] = []
  const evidence: string[] = []

  if (name === '') {
    reasons.push('empty_name')
    evidence.push('empty_component')
  }
  if (name.includes('\u0000')) {
    reasons.push('nul_byte')
    evidence.push('nul_byte')
  }
  for (const component of components) {
    if (component === '') {
      if (!reasons.includes('empty_component')) {
        reasons.push('empty_component')
        evidence.push('empty_component')
      }
      continue
    }
    if (component === '.' || component === '..') {
      if (!reasons.includes('dot_component')) {
        reasons.push('dot_component')
        evidence.push('dot_component')
      }
      continue
    }
    let illegal = false
    let control = false
    for (const ch of component) {
      if (WINDOWS_ILLEGAL.includes(ch)) illegal = true
      const code = ch.charCodeAt(0)
      if (code >= 0x01 && code <= 0x1f) control = true
    }
    if ((illegal || control) && !reasons.includes('illegal_char')) {
      reasons.push('illegal_char')
      evidence.push('illegal_char')
    }
    if (utf16Units(component) > WINDOWS_MAX_COMPONENT) {
      if (!reasons.includes('component_too_long')) {
        reasons.push('component_too_long')
        evidence.push('component_too_long')
      }
    }
  }

  if (reasons.length > 0) return { level: 'BLOCKED', reasons, evidence }

  // 保留名按裁剪后的组件匹配：Windows 先裁尾随空格/点、再判设备名。
  let reservedHit = false
  for (const component of components) {
    let end = component.length
    while (end > 0 && (component[end - 1] === ' ' || component[end - 1] === '.')) end -= 1
    const trimmed = component.slice(0, end)
    const stem = stemBeforeLastDot(trimmed.length === 0 ? component : trimmed)
    if (RESERVED_DEVICE_NAMES.has(tables.windows.fold(stem))) {
      reservedHit = true
      break
    }
  }

  if (reservedHit) {
    reasons.push('reserved_device_name')
    evidence.push(...RESERVED_EVIDENCE)
  }

  for (const component of components) {
    let end = component.length
    while (end > 0 && (component[end - 1] === ' ' || component[end - 1] === '.')) end -= 1
    if (end !== component.length) {
      if (!reasons.includes('trailing_space_or_dot')) {
        reasons.push('trailing_space_or_dot')
        evidence.push('trailing_space_or_dot')
      }
    }
    if (component.includes(':')) {
      if (!reasons.includes('ads_colon_truncation')) {
        reasons.push('ads_colon_truncation')
        evidence.push('ads_colon_truncation')
      }
    }
  }

  if (reservedHit) return { level: 'WRITTEN_UNREADABLE', reasons, evidence }
  if (reasons.length > 0) return { level: 'WRITTEN_TRUNCATED', reasons, evidence }
  return { level: 'OK', reasons: [], evidence: [] }
}

function judgePosixLike(name: string, components: readonly string[]): AccessVerdict {
  const reasons: string[] = []
  const evidence: string[] = []

  if (name === '') {
    reasons.push('empty_name')
    evidence.push('empty_component')
  }
  if (name.includes('\u0000')) {
    reasons.push('nul_byte')
    evidence.push('nul_byte')
  }
  for (const component of components) {
    if (component === '') {
      if (!reasons.includes('empty_component')) {
        reasons.push('empty_component')
        evidence.push('empty_component')
      }
      continue
    }
    if (component === '.' || component === '..') {
      if (!reasons.includes('dot_component')) {
        reasons.push('dot_component')
        evidence.push('dot_component')
      }
    }
  }
  if (reasons.length > 0) return { level: 'BLOCKED', reasons, evidence }
  return { level: 'OK', reasons: [], evidence: [] }
}

/** 单条目在单平台上的可访问性判定（`{level, reasons, evidence}`）。 */
export function judgeName(
  name: string,
  platform: string,
  tables: PlatformTables,
): AccessVerdict {
  if (!(PLATFORMS as readonly string[]).includes(platform)) {
    throw new Error(`未知目标平台: ${platform}`)
  }
  const components = splitComponents(name)
  const verdict =
    platform === 'windows'
      ? judgeWindows(name, components, tables)
      : judgePosixLike(name, components)
  if (!(LEVELS as readonly string[]).includes(verdict.level)) {
    throw new Error(`非法级别: ${verdict.level}`)
  }
  return verdict
}

/** MOD-4 的全部判定：`{entryIndex: {platform: verdict}}`，只对本次 targets 出键。 */
export function checkAccess(
  archive: Archive,
  targets: readonly string[],
  tables: PlatformTables,
): Record<string, Record<string, AccessVerdict>> {
  const unknown = targets.filter((name) => !(PLATFORMS as readonly string[]).includes(name))
  if (unknown.length > 0) throw new Error(`未知目标平台: ${unknown.join(', ')}`)
  const verdicts: Record<string, Record<string, AccessVerdict>> = {}
  for (const entry of archive.entries) {
    const name = decodeSurrogateEscape(entry.cdName)
    const perPlatform: Record<string, AccessVerdict> = {}
    for (const platform of PLATFORMS) {
      if (!targets.includes(platform)) continue
      perPlatform[platform] = judgeName(name, platform, tables)
    }
    verdicts[String(entry.index)] = perPlatform
  }
  return verdicts
}

/** 非 `OK` 的 (条目, 平台) 对数。 */
export function countIssues(
  verdicts: Readonly<Record<string, Readonly<Record<string, AccessVerdict>>>>,
): number {
  let count = 0
  for (const perPlatform of Object.values(verdicts)) {
    for (const verdict of Object.values(perPlatform)) {
      if (verdict.level !== 'OK') count += 1
    }
  }
  return count
}