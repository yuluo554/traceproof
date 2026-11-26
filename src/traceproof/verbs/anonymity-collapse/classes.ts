/**
 * 等价类引擎（源仓 `m2_classes.py` 的判定层复刻）。
 *
 * 纪律：
 *  - 纯函数：不写盘、不读时钟 / 随机源 / 环境变量；
 *  - 等价类键按**声明顺序**拼接（不是表头顺序）；
 *  - 行号 = 数据行序号（1 起）；
 *  - 缺失判定只走 `table.isMissing`（单点定义）；
 *  - 空表 / 全被丢弃 → k = null + `undefined_reason`，绝不返回 0 冒充通过。
 */

import { ContractError } from '../../core/ledger.js'
import defaults from './data/anonymity-defaults.json' with { type: 'json' }
import { round6 } from './round.js'
import { isMissing } from './table.js'
import type { Table } from './table.js'
import { compareCodePoints } from './util.js'

export const POLICIES: readonly string[] = defaults.policies
export const NULL_TOKEN: string = defaults.null_token
export const MISSING_CLASS_KEY: string = defaults.missing_class_key

export interface Grouped {
  readonly classes: Map<string, number[]>
  readonly undecided: number[]
  readonly valuesByKey: Map<string, string[]>
}

export function requirePolicy(policy: unknown): string {
  if (typeof policy !== 'string' || !POLICIES.includes(policy)) {
    throw new ContractError(`未知的缺失值策略：<${String(policy)}>（可选 ${POLICIES.join(' / ')}）`)
  }
  return policy
}

function columnIndices(table: Table, columns: readonly string[]): number[] {
  return columns.map((name) => {
    const index = table.columnIndex(name)
    if (index === null) throw new ContractError(`分组列不在表头里：${name}`)
    return index
  })
}

export function groupRows(table: Table, columns: readonly string[], policy: string): Grouped {
  requirePolicy(policy)
  const indices = columnIndices(table, columns)
  const classes = new Map<string, number[]>()
  const valuesByKey = new Map<string, string[]>()
  const undecided: number[] = []

  for (const row of table.rows) {
    const selected = indices.map((index) => row.values[index])
    if (policy !== 'single-column' && selected.some((value) => isMissing(value))) {
      if (policy === 'drop') {
        undecided.push(row.rowNumber)
        continue
      }
      const bucket = classes.get(MISSING_CLASS_KEY)
      if (bucket === undefined) classes.set(MISSING_CLASS_KEY, [row.rowNumber])
      else bucket.push(row.rowNumber)
      if (!valuesByKey.has(MISSING_CLASS_KEY)) valuesByKey.set(MISSING_CLASS_KEY, [])
      continue
    }
    const rendered: string[] = []
    const parts: string[] = []
    for (const [position, name] of columns.entries()) {
      let value = selected[position]
      if (policy === 'single-column' && isMissing(value)) value = NULL_TOKEN
      rendered.push(value)
      parts.push(`${name}=${value}`)
    }
    const key = parts.join('|')
    const bucket = classes.get(key)
    if (bucket === undefined) classes.set(key, [row.rowNumber])
    else bucket.push(row.rowNumber)
    if (!valuesByKey.has(key)) valuesByKey.set(key, rendered)
  }
  for (const numbers of classes.values()) numbers.sort((a, b) => a - b)
  undecided.sort((a, b) => a - b)
  return { classes, undecided, valuesByKey }
}

export function kOf(classes: ReadonlyMap<string, readonly number[]>): number | null {
  if (classes.size === 0) return null
  let minimum: number | null = null
  for (const numbers of classes.values()) {
    if (minimum === null || numbers.length < minimum) minimum = numbers.length
  }
  return minimum
}

function valueLookup(table: Table, policy: string): Map<number, string[]> {
  const lookup = new Map<number, string[]>()
  for (const row of table.rows) {
    const values = row.values.map((value) =>
      policy === 'single-column' && isMissing(value) ? NULL_TOKEN : value,
    )
    lookup.set(row.rowNumber, values)
  }
  return lookup
}

export interface LDetail {
  readonly l: number | null
  readonly byClass: ReadonlyMap<string, ReadonlyMap<string, number>>
}

export function lDetail(
  table: Table,
  classes: ReadonlyMap<string, readonly number[]>,
  sensitive: readonly string[],
  policy: string,
): LDetail {
  if (classes.size === 0 || sensitive.length === 0) return { l: null, byClass: new Map() }
  const indices = new Map<string, number>()
  for (const name of sensitive) {
    const index = table.columnIndex(name)
    if (index === null) throw new ContractError(`敏感列不在表头里：${name}`)
    indices.set(name, index)
  }
  const lookup = valueLookup(table, policy)
  const byClass = new Map<string, ReadonlyMap<string, number>>()
  let minimum: number | null = null
  for (const [key, numbers] of classes.entries()) {
    const counts = new Map<string, number>()
    for (const name of sensitive) {
      const index = indices.get(name) as number
      const seen = new Set<string>()
      for (const number of numbers) seen.add((lookup.get(number) as string[])[index])
      counts.set(name, seen.size)
      if (minimum === null || seen.size < minimum) minimum = seen.size
    }
    byClass.set(key, counts)
  }
  return { l: minimum, byClass }
}

export interface TDetail {
  readonly t: number | null
  readonly byClass: ReadonlyMap<string, ReadonlyMap<string, number>>
}

function tvDistance(
  classCounts: ReadonlyMap<string, number>,
  allCounts: ReadonlyMap<string, number>,
): number {
  let classTotal = 0
  for (const count of classCounts.values()) classTotal += count
  let allTotal = 0
  for (const count of allCounts.values()) allTotal += count
  if (classTotal === 0 || allTotal === 0) return 0
  const values = new Set<string>([...classCounts.keys(), ...allCounts.keys()])
  let numerator = 0n
  const at = BigInt(allTotal)
  const ct = BigInt(classTotal)
  for (const value of values) {
    const classCount = BigInt(classCounts.get(value) ?? 0)
    const allCount = BigInt(allCounts.get(value) ?? 0)
    const delta = classCount * at - allCount * ct
    numerator += delta < 0n ? -delta : delta
  }
  const denominator = 2n * ct * at
  const value = Number(numerator) / Number(denominator)
  return round6(value) as number
}

export function tDetail(
  table: Table,
  classes: ReadonlyMap<string, readonly number[]>,
  sensitive: readonly string[],
  undecided: readonly number[],
  policy: string,
): TDetail {
  if (classes.size === 0 || sensitive.length === 0) return { t: null, byClass: new Map() }
  const indices = new Map<string, number>()
  for (const name of sensitive) {
    const index = table.columnIndex(name)
    if (index === null) throw new ContractError(`敏感列不在表头里：${name}`)
    indices.set(name, index)
  }
  const lookup = valueLookup(table, policy)
  const dropped = new Set(undecided)
  const included = table.rows.filter((row) => !dropped.has(row.rowNumber))
  if (included.length === 0) return { t: null, byClass: new Map() }

  const byClass = new Map<string, ReadonlyMap<string, number>>()
  let maximum: number | null = null
  for (const [key, numbers] of classes.entries()) {
    const distances = new Map<string, number>()
    for (const name of sensitive) {
      const index = indices.get(name) as number
      const classCounts = new Map<string, number>()
      for (const number of numbers) {
        const value = (lookup.get(number) as string[])[index]
        classCounts.set(value, (classCounts.get(value) ?? 0) + 1)
      }
      const allCounts = new Map<string, number>()
      for (const row of included) {
        const value = (lookup.get(row.rowNumber) as string[])[index]
        allCounts.set(value, (allCounts.get(value) ?? 0) + 1)
      }
      const distance = tvDistance(classCounts, allCounts)
      distances.set(name, distance)
      if (maximum === null || distance > maximum) maximum = distance
    }
    byClass.set(key, distances)
  }
  return { t: maximum, byClass }
}

export interface Violation {
  readonly key: string
  readonly count: number
  readonly row_numbers: number[]
}

export interface Klt {
  readonly k: number | null
  readonly l: number | null
  readonly t: number | null
  readonly class_count: number
  readonly class_size_histogram: Record<string, number>
  readonly undecided_rows: number[]
  readonly missing_class: { readonly k: number; readonly row_numbers: number[] } | null
}

export interface Summary {
  readonly missing_policy: string
  readonly k_l_t: Klt
  readonly violations: Violation[]
  readonly unique_records: number[]
  readonly undefined_reason: string | null
  readonly verdict: 'pass' | 'violation' | 'undecidable'
}

function violationsOf(
  classes: ReadonlyMap<string, readonly number[]>,
  kThreshold: number,
  lThreshold: number | null,
  tThreshold: number | null,
  lByClass: ReadonlyMap<string, ReadonlyMap<string, number>>,
  tByClass: ReadonlyMap<string, ReadonlyMap<string, number>>,
): Violation[] {
  const out: Violation[] = []
  for (const key of [...classes.keys()].sort(compareCodePoints)) {
    const numbers = classes.get(key) as number[]
    let hit = numbers.length < kThreshold
    if (!hit && lThreshold !== null && lByClass.size > 0) {
      const counts = lByClass.get(key)
      if (counts !== undefined) {
        for (const count of counts.values()) if (count < lThreshold) hit = true
      }
    }
    if (!hit && tThreshold !== null && tByClass.size > 0) {
      const counts = tByClass.get(key)
      if (counts !== undefined) {
        for (const count of counts.values()) if (count > tThreshold) hit = true
      }
    }
    if (hit) out.push({ key, count: numbers.length, row_numbers: [...numbers] })
  }
  return out
}

export function summarize(
  table: Table,
  qiColumns: readonly string[],
  sensitiveColumns: readonly string[],
  policy: string,
  kThreshold: number,
  lThreshold: number | null = null,
  tThreshold: number | null = null,
): Summary {
  requirePolicy(policy)
  const { classes, undecided } = groupRows(table, qiColumns, policy)
  const k = kOf(classes)
  const { l, byClass: lByClass } = lDetail(table, classes, sensitiveColumns, policy)
  const { t, byClass: tByClass } = tDetail(table, classes, sensitiveColumns, undecided, policy)

  const histogram = new Map<number, number>()
  for (const numbers of classes.values()) {
    histogram.set(numbers.length, (histogram.get(numbers.length) ?? 0) + 1)
  }
  const classSizeHistogram: Record<string, number> = {}
  for (const size of [...histogram.keys()].sort((a, b) => a - b)) {
    classSizeHistogram[String(size)] = histogram.get(size) as number
  }

  const violations = violationsOf(
    classes,
    kThreshold,
    lThreshold,
    tThreshold,
    lByClass,
    tByClass,
  )
  const uniqueRecords = [...classes.values()]
    .filter((numbers) => numbers.length === 1)
    .flatMap((numbers) => numbers)
    .sort((a, b) => a - b)

  let missingClass: { k: number; row_numbers: number[] } | null = null
  const missingNumbers = classes.get(MISSING_CLASS_KEY)
  if (missingNumbers !== undefined) {
    missingClass = { k: missingNumbers.length, row_numbers: [...missingNumbers] }
  }

  let undefinedReason: string | null = null
  if (table.rowCount === 0) undefinedReason = defaults.reasons.empty_table
  else if (classes.size === 0) undefinedReason = defaults.reasons.no_participating_rows

  let verdict: Summary['verdict']
  if (undefinedReason !== null) verdict = 'undecidable'
  else if (violations.length > 0) verdict = 'violation'
  else verdict = 'pass'

  return {
    missing_policy: policy,
    k_l_t: {
      k,
      l,
      t,
      class_count: classes.size,
      class_size_histogram: classSizeHistogram,
      undecided_rows: [...undecided],
      missing_class: missingClass,
    },
    violations,
    unique_records: uniqueRecords,
    undefined_reason: undefinedReason,
    verdict,
  }
}