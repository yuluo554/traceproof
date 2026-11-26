/**
 * hazard-triage · 条款关联（源仓 `reasoning/clause_linker.py`）。
 *
 * 条款来源：受控词表 `clause_refs`；图谱 Regulation 节点命中时附原文摘录 `quote`。
 * 查不到时 `quote` 为空串，不硬造引用。
 */

import type { ClauseRef, Knowledge } from './knowledge.js'
import type { HazardCard } from './extract.js'
import type { SimpleGraph } from './graph.js'
import { kgNodeId } from './graph.js'

export interface LinkedClauseRef extends ClauseRef {
  readonly quote: string
}

export function linkClauses(
  card: HazardCard,
  knowledge: Knowledge,
  graph?: SimpleGraph,
): LinkedClauseRef[] {
  const hazard = knowledge.hazardTypeById.get(card.hazard_type_id)
  const refs: LinkedClauseRef[] = []
  for (const ref of hazard?.clause_refs ?? []) {
    let quote = ''
    if (graph !== undefined) {
      const node = graph.getNode(kgNodeId(ref.standard, ref.clause))
      if (node !== undefined && typeof node.text === 'string') quote = node.text
    }
    refs.push({ standard: ref.standard, clause: ref.clause, quote })
  }
  return refs
}