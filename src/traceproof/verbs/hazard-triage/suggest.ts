/**
 * hazard-triage · 整改建议生成（源仓 `reasoning/suggest.py`）。
 *
 * 纪律：建议文本必须携带出处（measure id / 条款编号），不得引入新的数值结论。
 */

import type { Knowledge } from './knowledge.js'
import type { HazardCard } from './extract.js'
import type { Judgment } from './judge.js'

export interface Suggestion {
  readonly text: string
  readonly source: string
}

export function buildSuggestions(card: HazardCard, judgment: Judgment, knowledge: Knowledge): Suggestion[] {
  const hazard = knowledge.hazardTypeById.get(card.hazard_type_id)
  const out: Suggestion[] = []
  const clauseText =
    judgment.clause_refs.map((ref) => `${ref.standard} ${ref.clause}`).join('、') || '受控词表'
  for (const measureId of hazard?.measure_ids ?? []) {
    const measure = knowledge.measureById.get(measureId)
    if (measure === undefined) continue
    out.push({ text: `${measure.text}（依据 ${clauseText}）`, source: measureId })
  }
  if (out.length === 0) {
    out.push({
      text: `现场复查并按 ${clauseText} 相关条款落实整改，整改结果拍照留档。`,
      source: 'fallback',
    })
  }
  return out
}