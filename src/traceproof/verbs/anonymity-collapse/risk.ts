/**
 * 逐记录风险与攻击者模型（源仓 `m4_risk.py` 的判定层复刻）。
 *
 * 判定**只依赖等价类大小**，与敏感列取值无关：
 *   prosecutor → class_size == 1
 *   journalist → class_size <= 2
 *   marketer   → class_size <  3
 *
 * 记录按行号升序输出；`drop` 下未裁决的行以 `participates=false` + `class_id=null`
 * 显式出现，不静默消失；空表 / 无参与行 → `undefined_reason` + `undecidable`。
 */

import { ContractError } from '../../core/ledger.js'
import { groupRows, MISSING_CLASS_KEY, requirePolicy } from './classes.js'
import type { Table } from './table.js'
import defaults from './data/anonymity-defaults.json' with { type: 'json' }
import { compareCodePoints } from './util.js'

export const ATTACKERS: readonly string[] = defaults.attackers
export const UNDECIDED_ROW_REASON: string = defaults.undecided_row_reason

export interface AttackerRule {
  readonly compare: '==' | '<=' | '<'
  readonly threshold: number
}

const rules: Record<string, AttackerRule> = {}
for (const [name, rule] of Object.entries(defaults.attacker_rules)) {
  const compare = rule.compare
  if (compare !== '==' && compare !== '<=' && compare !== '<') {
    throw new Error(`攻击者规则口径非法：${name} → ${compare}`)
  }
  rules[name] = { compare, threshold: rule.threshold }
}
const RULE_TABLE: Readonly<Record<string, AttackerRule>> = Object.freeze(rules)

export function attackerRule(attacker: string): AttackerRule {
  if (!ATTACKERS.includes(attacker)) {
    throw new ContractError(`未知的攻击者模型：<${attacker}>（可选 ${ATTACKERS.join(' / ')}）`)
  }
  return RULE_TABLE[attacker]
}

export function ruleText(attacker: string): string {
  const rule = attackerRule(attacker)
  return `class_size ${rule.compare} ${rule.threshold}`
}

export function isFlagged(classSize: number, attacker: string): boolean {
  const rule = attackerRule(attacker)
  if (rule.compare === '==') return classSize === rule.threshold
  if (rule.compare === '<=') return classSize <= rule.threshold
  return classSize < rule.threshold
}

export interface ClassJudgement {
  readonly class_id: string
  readonly class_size: number
  readonly flagged: boolean
}

export function classify(
  classes: ReadonlyMap<string, readonly number[]>,
  attacker: string,
): ClassJudgement[] {
  attackerRule(attacker)
  const rows: ClassJudgement[] = [...classes.entries()].map(([key, numbers]) => ({
    class_id: key,
    class_size: numbers.length,
    flagged: isFlagged(numbers.length, attacker),
  }))
  rows.sort((left, right) =>
    left.class_size === right.class_size
      ? compareCodePoints(left.class_id, right.class_id)
      : left.class_size - right.class_size,
  )
  return rows
}

export interface RiskRecord {
  readonly row_number: number
  readonly class_id: string | null
  readonly class_size: number | null
  readonly flagged: boolean
  readonly attacker: string
  readonly participates: boolean
  readonly undefined_reason: string | null
}

export interface ClassSizeBucket {
  classes: number
  records: number
  flagged_records: number
}

export interface RiskResult {
  readonly attacker: string
  readonly threshold: number
  readonly rule: string
  readonly missing_policy: string
  readonly pool: string[]
  readonly class_count: number
  readonly records: RiskRecord[]
  readonly flagged_rows: number[]
  readonly by_class_size: Record<string, ClassSizeBucket>
  readonly undefined_reason: string | null
  readonly verdict: 'pass' | 'violation' | 'undecidable'
}

export function risk(
  table: Table,
  pool: readonly string[],
  policy: string,
  attacker: string,
): RiskResult {
  requirePolicy(policy)
  const rule = attackerRule(attacker)

  const { classes } = groupRows(table, pool, policy)
  const judgements = classify(classes, attacker)
  const byKey = new Map(judgements.map((item) => [item.class_id, item]))
  const rowClass = new Map<number, string>()
  for (const [key, numbers] of classes.entries()) {
    for (const rowNumber of numbers) rowClass.set(rowNumber, key)
  }

  const records: RiskRecord[] = []
  for (const row of table.rows) {
    const key = rowClass.get(row.rowNumber)
    if (key === undefined) {
      records.push({
        row_number: row.rowNumber,
        class_id: null,
        class_size: null,
        flagged: false,
        attacker,
        participates: false,
        undefined_reason: UNDECIDED_ROW_REASON,
      })
      continue
    }
    const judgement = byKey.get(key) as ClassJudgement
    records.push({
      row_number: row.rowNumber,
      class_id: key,
      class_size: judgement.class_size,
      flagged: judgement.flagged,
      attacker,
      participates: true,
      undefined_reason: null,
    })
  }

  let undefinedReason: string | null = null
  if (table.rowCount === 0) undefinedReason = defaults.reasons.empty_table
  else if (classes.size === 0) undefinedReason = defaults.reasons.no_participating_rows

  const flaggedRows = records.filter((record) => record.flagged).map((record) => record.row_number)

  let verdict: RiskResult['verdict']
  if (undefinedReason !== null) verdict = 'undecidable'
  else if (flaggedRows.length > 0) verdict = 'violation'
  else verdict = 'pass'

  const buckets = new Map<number, ClassSizeBucket>()
  for (const judgement of judgements) {
    let bucket = buckets.get(judgement.class_size)
    if (bucket === undefined) {
      bucket = { classes: 0, records: 0, flagged_records: 0 }
      buckets.set(judgement.class_size, bucket)
    }
    bucket.classes += 1
    bucket.records += judgement.class_size
    if (judgement.flagged) bucket.flagged_records += judgement.class_size
  }
  const byClassSize: Record<string, ClassSizeBucket> = {}
  for (const size of [...buckets.keys()].sort((a, b) => a - b)) {
    byClassSize[String(size)] = buckets.get(size) as ClassSizeBucket
  }

  return {
    attacker,
    threshold: rule.threshold,
    rule: ruleText(attacker),
    missing_policy: policy,
    pool: [...pool],
    class_count: classes.size,
    records,
    flagged_rows: flaggedRows,
    by_class_size: byClassSize,
    undefined_reason: undefinedReason,
    verdict,
  }
}

export { MISSING_CLASS_KEY }