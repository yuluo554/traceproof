/**
 * 组合攻击面搜索（源仓 `m3_search.py` 的判定层复刻）：
 * 子集枚举、反单调剪枝、预算、最小崩塌集、完整性三态。
 *
 * 纪律：
 *  - 分组只走 `classes.groupRows` / `kOf`（单一实现）；
 *  - 候选池 = 声明为 qi 的列；枚举按子集大小升序，同大小按列名码位序；
 *  - `drop` 且候选池含缺失 → 单调性不成立，**不剪枝**；
 *  - 完整性三态闭合互斥；非穷尽结果不得称为「最小崩塌集」；
 *  - 预算按**已评估子集数**计数（含空集）；剪枝与预算分开计数。
 */

import { ContractError } from '../../core/ledger.js'
import { groupRows, kOf, requirePolicy } from './classes.js'
import { isMissing } from './table.js'
import type { Table } from './table.js'
import { compareCodePoints, compareCombos } from './util.js'

export const COMPLETENESS_STATES = [
  'exhausted',
  'budget-truncated',
  'monotonicity-not-applicable',
] as const

export type Completeness = (typeof COMPLETENESS_STATES)[number]

export interface Stratum {
  size: number
  evaluated: number
  min_k: number | null
  exposed_rows: number
  worst_subset: string[] | null
}

export interface SubsetResult {
  columns: string[]
  k: number | null
  safe: boolean
  exposed_rows: number
}

export interface SearchResult {
  verdict: 'ok' | 'no_solution'
  completeness: Completeness
  collapse_sets_status: 'exhaustive' | 'non-exhaustive'
  non_exhaustive: boolean
  minimal_collapse_sets: string[][]
  empty_set_witness: boolean
  empty_set_k: number | null
  declared_k: number | null
  candidate_count: number
  subset_space: number
  budget: number | null
  monotonicity_applicable: boolean
  evaluated_subsets: number
  pruned_subsets: number
  pool: string[]
  qi_columns: string[]
  policy: string
  threshold: number
  strata: Stratum[]
  subsets: SubsetResult[]
}

function requirePositiveInt(label: string, value: unknown): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    throw new ContractError(`${label} 必须是正整数：${String(value)}`)
  }
  return value
}

export function monotonicityHolds(
  table: Table,
  pool: readonly string[],
  policy: string,
): boolean {
  requirePolicy(policy)
  if (policy !== 'drop') return true
  for (const name of pool) {
    if (table.values(name).some((value) => isMissing(value))) return false
  }
  return true
}

export function completeness(
  monotone: boolean,
  exhausted: boolean,
  required = true,
): Completeness {
  if (!exhausted) return 'budget-truncated'
  if (!required) return 'exhausted'
  if (!monotone) return 'monotonicity-not-applicable'
  return 'exhausted'
}

export function collapseSetsStatus(state: Completeness): 'exhaustive' | 'non-exhaustive' {
  return state === 'exhausted' ? 'exhaustive' : 'non-exhaustive'
}

function exposedRows(classes: ReadonlyMap<string, readonly number[]>, threshold: number): number {
  let total = 0
  for (const numbers of classes.values()) {
    if (numbers.length < threshold) total += numbers.length
  }
  return total
}

function comboKey(combo: readonly string[]): string {
  return JSON.stringify(combo)
}

function* combinations(items: readonly string[], size: number): Generator<string[]> {
  const indexes = Array.from({ length: size }, (_, index) => index)
  if (size === 0) {
    yield []
    return
  }
  if (size > items.length) return
  while (true) {
    yield indexes.map((index) => items[index])
    let cursor = size - 1
    while (cursor >= 0 && indexes[cursor] === cursor + items.length - size) cursor -= 1
    if (cursor < 0) return
    indexes[cursor] += 1
    for (let next = cursor + 1; next < size; next += 1) indexes[next] = indexes[next - 1] + 1
  }
}

interface CachedSubset {
  readonly combo: string[]
  readonly k: number | null
  readonly classes: ReadonlyMap<string, readonly number[]>
}

export function search(
  table: Table,
  pool: readonly string[],
  sensitive: readonly string[],
  policy: string,
  threshold: number,
  budget: number | null = null,
  requireExhaustive = false,
): SearchResult {
  void sensitive
  requirePolicy(policy)
  requirePositiveInt('k 门限', threshold)
  if (budget !== null) requirePositiveInt('搜索预算', budget)

  const candidates = [...pool].sort(compareCodePoints)
  const unique = [...new Set(candidates)]
  if (unique.length !== candidates.length) {
    const duplicates = unique.filter((name) => candidates.filter((other) => other === name).length > 1)
    throw new ContractError(`候选池里有重复列：${duplicates.sort().join(', ')}`)
  }

  const monotone = monotonicityHolds(table, candidates, policy)
  const cache = new Map<string, CachedSubset>()
  const pruned = new Set<string>()
  let exhausted = true

  const kFor = (combo: readonly string[]): number | null => {
    const key = comboKey(combo)
    if (pruned.has(key)) return null
    const cached = cache.get(key)
    if (cached !== undefined) return cached.k
    const grouped = groupRows(table, combo, policy)
    const value = kOf(grouped.classes)
    cache.set(key, { combo: [...combo], k: value, classes: grouped.classes })
    return value
  }

  const isSafe = (combo: readonly string[]): boolean => {
    const key = comboKey(combo)
    if (pruned.has(key)) return false
    const value = kFor(combo)
    return value !== null && value >= threshold
  }

  const budgetHit = (): boolean => budget !== null && cache.size >= budget

  const base = kFor([])
  const subsetSpace = 2 ** candidates.length - 1

  let minimalCollapseSets: string[][]
  let verdict: SearchResult['verdict']
  let state: Completeness

  if (candidates.length === 0 || base === null || base < threshold) {
    minimalCollapseSets = []
    verdict = 'no_solution'
    state = completeness(monotone, true, false)
  } else {
    for (let size = 1; size <= candidates.length; size += 1) {
      for (const combo of combinations(candidates, size)) {
        if (monotone) {
          let parentUnsafe = false
          for (let drop = 0; drop < combo.length; drop += 1) {
            const parent = combo.filter((_, index) => index !== drop)
            if (!isSafe(parent)) {
              parentUnsafe = true
              break
            }
          }
          if (parentUnsafe) {
            pruned.add(comboKey(combo))
            continue
          }
        }
        if (budgetHit()) {
          exhausted = false
          break
        }
        isSafe(combo)
      }
      if (!exhausted) break
    }

    const safeSets = new Set<string>()
    for (const item of cache.values()) {
      if (item.k !== null && item.k >= threshold) safeSets.add(comboKey(item.combo))
    }

    const ordered = [...cache.values()].sort((left, right) => compareCombos(left.combo, right.combo))
    minimalCollapseSets = []
    for (const item of ordered) {
      if (item.k === null || item.k < threshold) continue
      const extensions: Array<{ key: string; evaluated: boolean }> = []
      for (const column of candidates) {
        if (item.combo.includes(column)) continue
        const extension = [...item.combo, column].sort(compareCodePoints)
        const key = comboKey(extension)
        extensions.push({ key, evaluated: cache.has(key) })
      }
      if (extensions.some((extension) => safeSets.has(extension.key))) continue
      if (!monotone && extensions.some((extension) => !extension.evaluated)) continue
      minimalCollapseSets.push([...item.combo])
    }
    verdict = 'ok'
    state = completeness(monotone, exhausted)
  }

  if (requireExhaustive && state === 'budget-truncated') {
    throw new ContractError('搜索被预算截断，无法声称穷尽：提高 search.budget 或缩小候选池')
  }

  const levels = new Map<number, Stratum>()
  for (const item of [...cache.values()].sort((left, right) => compareCombos(left.combo, right.combo))) {
    const size = item.combo.length
    let level = levels.get(size)
    if (level === undefined) {
      level = { size, evaluated: 0, min_k: null, exposed_rows: 0, worst_subset: null }
      levels.set(size, level)
    }
    level.evaluated += 1
    if (item.k !== null && (level.min_k === null || item.k < level.min_k)) {
      level.min_k = item.k
      level.worst_subset = [...item.combo]
    }
  }
  const strata: Stratum[] = [...levels.keys()].sort((a, b) => a - b).map((size) => {
    const level = levels.get(size) as Stratum
    const worst = level.worst_subset
    return {
      size,
      evaluated: level.evaluated,
      min_k: level.min_k,
      exposed_rows:
        worst === null
          ? 0
          : exposedRows(
              (cache.get(comboKey(worst)) as CachedSubset).classes,
              threshold,
            ),
      worst_subset: worst,
    }
  })

  const subsets: SubsetResult[] = [...cache.values()]
    .sort((left, right) => compareCombos(left.combo, right.combo))
    .map((item) => ({
      columns: [...item.combo],
      k: item.k,
      safe: item.k !== null && item.k >= threshold,
      exposed_rows: exposedRows(item.classes, threshold),
    }))

  const declared = candidates
  let declaredK: number | null
  const declaredCached = cache.get(comboKey(declared))
  if (declaredCached !== undefined) declaredK = declaredCached.k
  else declaredK = kOf(groupRows(table, declared, policy).classes)

  const emptySetEvidenced =
    candidates.length > 0 && candidates.every((column) => cache.has(comboKey([column])))

  return {
    verdict,
    completeness: state,
    collapse_sets_status: collapseSetsStatus(state),
    non_exhaustive: state !== 'exhausted',
    minimal_collapse_sets: minimalCollapseSets,
    empty_set_witness: minimalCollapseSets.some((combo) => combo.length === 0) && emptySetEvidenced,
    empty_set_k: base,
    declared_k: declaredK,
    candidate_count: candidates.length,
    subset_space: subsetSpace,
    budget,
    monotonicity_applicable: monotone,
    evaluated_subsets: cache.size,
    pruned_subsets: pruned.size,
    pool: candidates,
    qi_columns: [...pool],
    policy,
    threshold,
    strata,
    subsets,
  }
}

export function outcomeFor(result: SearchResult): 'pass' | 'violation' | 'undecidable' {
  const declaredK = result.declared_k
  if (declaredK === null) return 'undecidable'
  if (declaredK < result.threshold) return 'violation'
  if (result.completeness !== 'exhausted') return 'undecidable'
  return 'pass'
}