/**
 * hazard-triage · 基准指标（源仓 `benchmark.py` 的判定侧）。
 *
 * 口径（源仓 M1 v2）：
 *  - 主指标：预测集与真值集按 (记录序号, hazard_type_id) 键值对做微平均 P/R/F1；
 *  - 分级准确率：键值对齐且判定等级 == 期望等级的比例；
 *  - 字段级 P/R/F1：在键值对齐的命中对上比较 hazard_type / category / site_object；
 *  - 端到端：检出 = 命中且分级正确，误报 = 预测集多报。
 *
 * 真值由 `subject.gold` 提供；器官不读样例文件、不跑评测脚本。
 */

import { round4 } from './util.js'

export const FIELDS = ['hazard_type', 'category', 'site_object'] as const
export type MetricField = (typeof FIELDS)[number]

export interface GoldRecord {
  readonly index: number
  readonly quote?: string
  readonly hazard_type_id: string
  readonly hazard_type?: string
  readonly category?: string
  readonly site_object?: string
  readonly expected_level?: string
}

export interface MetricCard {
  readonly source: { readonly record_index: number }
  readonly hazard_type_id: string
  readonly hazard_type: string
  readonly category: string
  readonly site_object: string
  readonly judgment: { readonly risk_level: string }
}

export interface Prf {
  readonly precision: number
  readonly recall: number
  readonly f1: number
}

export interface FieldStat {
  tp: number
  fp: number
  fn: number
}

export function prf(tp: number, fp: number, fn: number): Prf {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0.0
  return { precision: round4(precision), recall: round4(recall), f1: round4(f1) }
}

export function fieldStats(
  matchedKeys: ReadonlySet<string>,
  cardsByKey: ReadonlyMap<string, MetricCard>,
  goldByKey: ReadonlyMap<string, GoldRecord>,
): Record<MetricField, FieldStat> {
  const stats: Record<MetricField, FieldStat> = {
    hazard_type: { tp: 0, fp: 0, fn: 0 },
    category: { tp: 0, fp: 0, fn: 0 },
    site_object: { tp: 0, fp: 0, fn: 0 },
  }
  for (const key of matchedKeys) {
    const card = cardsByKey.get(key) as MetricCard
    const gold = goldByKey.get(key) as GoldRecord
    for (const field of FIELDS) {
      const predicted = String(card[field] ?? '').trim()
      const expected = String(gold[field] ?? '').trim()
      if (predicted && expected) {
        if (predicted === expected) stats[field].tp += 1
        else {
          stats[field].fp += 1
          stats[field].fn += 1
        }
      } else if (predicted) {
        stats[field].fp += 1
      } else if (expected) {
        stats[field].fn += 1
      }
    }
  }
  return stats
}

export function metricKey(recordIndex: number, hazardTypeId: string): string {
  return `${recordIndex}\u0000${hazardTypeId}`
}

export interface Metrics {
  readonly micro: Prf & { readonly tp: number; readonly fp: number; readonly fn: number }
  readonly level_accuracy: number | null
  readonly field_f1: Record<MetricField, number>
  readonly detection_rate: number
  readonly false_positive_rate: number
  readonly pred_count: number
  readonly gold_count: number
  readonly level_hit: number
}

export function computeMetrics(cards: readonly MetricCard[], gold: readonly GoldRecord[]): Metrics {
  const goldByKey = new Map<string, GoldRecord>()
  for (const record of gold) goldByKey.set(metricKey(record.index, record.hazard_type_id), record)
  const cardsByKey = new Map<string, MetricCard>()
  for (const card of cards) cardsByKey.set(metricKey(card.source.record_index, card.hazard_type_id), card)

  const goldPairs = new Set(goldByKey.keys())
  const predPairs = new Set(cardsByKey.keys())
  let tp = 0
  for (const key of predPairs) if (goldPairs.has(key)) tp += 1
  const fp = predPairs.size - tp
  const fn = goldPairs.size - tp

  let levelTotal = 0
  let levelHit = 0
  for (const key of goldPairs) {
    if (!predPairs.has(key)) continue
    levelTotal += 1
    if (cardsByKey.get(key)?.judgment.risk_level === goldByKey.get(key)?.expected_level) levelHit += 1
  }

  const stats = fieldStats(
    new Set([...goldPairs].filter((key) => predPairs.has(key))),
    cardsByKey,
    goldByKey,
  )
  const fieldF1: Record<MetricField, number> = {
    hazard_type: prf(stats.hazard_type.tp, stats.hazard_type.fp, stats.hazard_type.fn).f1,
    category: prf(stats.category.tp, stats.category.fp, stats.category.fn).f1,
    site_object: prf(stats.site_object.tp, stats.site_object.fp, stats.site_object.fn).f1,
  }
  return {
    micro: { ...prf(tp, fp, fn), tp, fp, fn },
    level_accuracy: levelTotal > 0 ? round4(levelHit / levelTotal) : null,
    field_f1: fieldF1,
    detection_rate: goldPairs.size > 0 ? round4(levelHit / goldPairs.size) : 1.0,
    false_positive_rate: predPairs.size > 0 ? round4(fp / predPairs.size) : 0.0,
    pred_count: predPairs.size,
    gold_count: goldPairs.size,
    level_hit: levelHit,
  }
}