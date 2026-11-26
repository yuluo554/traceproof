/**
 * hazard-triage · 配对差异检出（源仓 `benchmark.py::detect_paired_diffs`）。
 *
 * 施工日志版 vs 巡查记录版按规范化时间戳对齐，检出三类差异：
 *  - `missing`：日志有、巡查无（漏项）；
 *  - `extra`：巡查有、日志无（多报）；
 *  - `value`：同一时间戳两侧文本的数字多重集不同（数值不一致）。
 *
 * 时间戳相同的记录取首条（源仓 `setdefault` 语义）；结果按时间戳排序。
 */

import type { LogRecord } from './parse.js'

export type PairedDiffKind = 'missing' | 'extra' | 'value'

export interface PairedDiff {
  readonly kind: PairedDiffKind
  readonly timestamp: string
  readonly index_in_log?: number
  readonly index_in_patrol?: number
}

const DIGIT_RE = /\d+/g

export function digitMultiset(text: string): string {
  return (text.match(DIGIT_RE) ?? []).slice().sort().join(',')
}

export function detectPairedDiffs(
  logRecords: readonly LogRecord[],
  patrolRecords: readonly LogRecord[],
): PairedDiff[] {
  const logBy = new Map<string, LogRecord>()
  for (const record of logRecords) {
    if (!logBy.has(record.timestamp)) logBy.set(record.timestamp, record)
  }
  const patrolBy = new Map<string, LogRecord>()
  for (const record of patrolRecords) {
    if (!patrolBy.has(record.timestamp)) patrolBy.set(record.timestamp, record)
  }

  const diffs: PairedDiff[] = []
  for (const [timestamp, record] of logBy) {
    if (!patrolBy.has(timestamp)) {
      diffs.push({ kind: 'missing', timestamp, index_in_log: record.index })
    }
  }
  for (const [timestamp, record] of patrolBy) {
    if (!logBy.has(timestamp)) {
      diffs.push({ kind: 'extra', timestamp, index_in_patrol: record.index })
    }
  }
  for (const [timestamp, record] of logBy) {
    const patrol = patrolBy.get(timestamp)
    if (patrol === undefined) continue
    if (digitMultiset(record.text) !== digitMultiset(patrol.text)) {
      diffs.push({
        kind: 'value',
        timestamp,
        index_in_log: record.index,
        index_in_patrol: patrol.index,
      })
    }
  }
  diffs.sort((left, right) => (left.timestamp < right.timestamp ? -1 : left.timestamp > right.timestamp ? 1 : 0))
  return diffs
}