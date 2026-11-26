/**
 * archive-extraction · 判定输出的唯一形状（迁移自源仓 `findings.py`）。
 *
 * 两种形状刻意分开：
 *  - `Finding`：归档内部两处事实不一致（`structure.*` / `encoding.*` / `container.*` /
 *    `budget.*`），带 `precedent`（哪个实现读哪个头，或结构自证）；
 *  - `Collision`：目标平台上两个条目落到同一个名字上，带写序、存活者与证据强度。
 *
 * 排序口径沿用源仓：`Finding` 按 `(cdOffset, ruleId, entryIndex, evidence)` 全序；
 * `Collision` 按 `(min(cdOffsets), code, platform, writeOrder)` 全序。排序是全序，不依赖输入顺序。
 */

import { stableStringify } from './util.js'

export interface FindingInit {
  readonly ruleId: string
  readonly message: string
  readonly evidence: Readonly<Record<string, unknown>>
  readonly precedent: string
  readonly entryIndex?: number | null
  readonly lfhOffset?: number | null
  readonly cdOffset?: number | null
  readonly lfhName?: string | null
  readonly cdName?: string | null
}

export interface Finding {
  readonly ruleId: string
  readonly message: string
  readonly evidence: Readonly<Record<string, unknown>>
  readonly precedent: string
  readonly entryIndex: number | null
  readonly lfhOffset: number | null
  readonly cdOffset: number | null
  readonly lfhName: string | null
  readonly cdName: string | null
}

export function makeFinding(init: FindingInit): Finding {
  return Object.freeze({
    ruleId: init.ruleId,
    message: init.message,
    evidence: init.evidence,
    precedent: init.precedent,
    entryIndex: init.entryIndex ?? null,
    lfhOffset: init.lfhOffset ?? null,
    cdOffset: init.cdOffset ?? null,
    lfhName: init.lfhName ?? null,
    cdName: init.cdName ?? null,
  })
}

/** 报告里的固定键集（与源仓 `Finding.to_dict()` 同）。 */
export function findingToJSON(item: Finding): Record<string, unknown> {
  return {
    ruleId: item.ruleId,
    entryIndex: item.entryIndex,
    lfhOffset: item.lfhOffset,
    cdOffset: item.cdOffset,
    lfhName: item.lfhName,
    cdName: item.cdName,
    message: item.message,
    evidence: item.evidence,
    precedent: item.precedent,
  }
}

export interface CollisionInit {
  readonly code: string
  readonly platform: string
  readonly names: readonly string[]
  readonly onDiskNames: readonly string[]
  readonly writeOrder: readonly number[]
  readonly cdOffsets: readonly number[]
  readonly survivor: string
  readonly survivorEntryIndex: number
  readonly verdict: string
  readonly evidenceStrength: string
  readonly evidence: Readonly<Record<string, unknown>>
}

export interface Collision {
  readonly code: string
  readonly platform: string
  readonly names: readonly string[]
  readonly onDiskNames: readonly string[]
  readonly writeOrder: readonly number[]
  readonly cdOffsets: readonly number[]
  readonly survivor: string
  readonly survivorEntryIndex: number
  readonly verdict: string
  readonly evidenceStrength: string
  readonly evidence: Readonly<Record<string, unknown>>
}

export function makeCollision(init: CollisionInit): Collision {
  return Object.freeze({
    code: init.code,
    platform: init.platform,
    names: Object.freeze([...init.names]),
    onDiskNames: Object.freeze([...init.onDiskNames]),
    writeOrder: Object.freeze([...init.writeOrder]),
    cdOffsets: Object.freeze([...init.cdOffsets]),
    survivor: init.survivor,
    survivorEntryIndex: init.survivorEntryIndex,
    verdict: init.verdict,
    evidenceStrength: init.evidenceStrength,
    evidence: init.evidence,
  })
}

export function collisionToJSON(item: Collision): Record<string, unknown> {
  return {
    code: item.code,
    platform: item.platform,
    names: [...item.names],
    onDiskNames: [...item.onDiskNames],
    writeOrder: [...item.writeOrder],
    cdOffsets: [...item.cdOffsets],
    survivor: item.survivor,
    survivorEntryIndex: item.survivorEntryIndex,
    verdict: item.verdict,
    evidenceStrength: item.evidenceStrength,
    evidence: item.evidence,
  }
}

/** `(cd_offset, ruleId, entryIndex, evidence)` 全序；归档级 finding（无 CD 偏移）排最前。 */
export function findingSortKey(item: Finding): [number, string, number, string] {
  return [
    item.cdOffset === null ? -1 : item.cdOffset,
    item.ruleId,
    item.entryIndex === null ? -1 : item.entryIndex,
    stableStringify(item.evidence),
  ]
}

function compareTuple(
  left: readonly (number | string)[],
  right: readonly (number | string)[],
): number {
  for (let index = 0; index < left.length; index += 1) {
    const a = left[index]
    const b = right[index]
    if (a === b) continue
    return (a as number | string) < (b as number | string) ? -1 : 1
  }
  return 0
}

export function sortFindings(items: readonly Finding[]): Finding[] {
  return [...items].sort((left, right) => compareTuple(findingSortKey(left), findingSortKey(right)))
}

export function sortCollisions(items: readonly Collision[]): Collision[] {
  return [...items].sort((left, right) => {
    const leftKey: (number | string)[] = [
      left.cdOffsets.length === 0 ? -1 : Math.min(...left.cdOffsets),
      left.code,
      left.platform,
      ...left.writeOrder,
    ]
    const rightKey: (number | string)[] = [
      right.cdOffsets.length === 0 ? -1 : Math.min(...right.cdOffsets),
      right.code,
      right.platform,
      ...right.writeOrder,
    ]
    return compareTuple(leftKey, rightKey)
  })
}

/** MOD-3 的四条折叠判定（顺序即判定顺序）。 */
export const COLLISION_CODES = [
  'collision.FILEDIR',
  'collision.CASEFOLD',
  'collision.NFC',
  'collision.TRIM',
] as const

/** `collision.verdict` 的三个合法取值。 */
export const COLLISION_VERDICTS = ['overwritten', 'renamed', 'skipped'] as const