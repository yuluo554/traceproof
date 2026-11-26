/**
 * hazard-triage · 条款向量检索兜底（源仓 `retrieval/vector.py`）。
 *
 * 定位与纪律：**兜底候选不是判定依据**——只对 `clause_refs` 为空的卡片附加
 * `fallback_clauses` 候选，逐条标注「非判定依据」；不改动 `risk_level` /
 * `clause_refs` / `suggestions`。
 *
 * 纯本地实现：字符二元组 TF-IDF 词法向量 + 余弦相似度；embedder 可注入
 * （测试注入稠密向量，器官本身不联网、不调模型）。
 */

import type { Knowledge } from './knowledge.js'
import { round4 } from './util.js'

export const FALLBACK_NOTE = '向量检索兜底候选，非判定依据（以官方文本为准）'

const KEEP_RE = /[\u4e00-\u9fffA-Za-z0-9]+/g

export interface RegulationDoc {
  readonly id: string
  readonly text: string
  readonly standard: string
  readonly clause: string
  readonly std_name: string
}

export interface FallbackClause {
  readonly standard: string
  readonly clause: string
  readonly std_name: string
  readonly score: number
  readonly note: string
}

/** 文本 → 词法 token 计数（字符二元组；单字符取自身；空文本空表）。 */
export function tokenize(text: string): Record<string, number> {
  const normalized = (String(text).toLowerCase().match(KEEP_RE) ?? []).join('')
  if (!normalized) return {}
  if (normalized.length === 1) return { [normalized]: 1 }
  const grams: Record<string, number> = {}
  for (let index = 0; index < normalized.length - 1; index += 1) {
    const gram = normalized.slice(index, index + 2)
    grams[gram] = (grams[gram] ?? 0) + 1
  }
  return grams
}

function l2(weights: Record<string, number>): Record<string, number> {
  const norm = Math.sqrt(Object.values(weights).reduce((sum, weight) => sum + weight * weight, 0)) || 1.0
  const out: Record<string, number> = {}
  for (const [key, weight] of Object.entries(weights)) out[key] = weight / norm
  return out
}

function normDense(vector: readonly number[]): number[] {
  const values = vector.map((value) => Number(value))
  const norm = Math.sqrt(values.reduce((sum, value) => sum + value * value, 0)) || 1.0
  return values.map((value) => value / norm)
}

export class VectorIndex {
  readonly docs: readonly RegulationDoc[]
  private readonly embedder: ((text: string) => readonly number[]) | null
  private readonly sparse: Record<string, number>[]
  private readonly dense: number[][] | null

  constructor(docs: readonly RegulationDoc[], embedder?: (text: string) => readonly number[]) {
    this.docs = [...docs]
    this.embedder = embedder ?? null
    this.sparse = []
    this.dense = null
    if (this.embedder !== null) {
      this.dense = this.docs.map((doc) => normDense(this.embedder?.(doc.text) ?? []))
      return
    }
    const df: Record<string, number> = {}
    const tfs = this.docs.map((doc) => tokenize(doc.text))
    for (const tf of tfs) {
      for (const token of Object.keys(tf)) df[token] = (df[token] ?? 0) + 1
    }
    const n = Math.max(1, this.docs.length)
    for (const tf of tfs) {
      const weights: Record<string, number> = {}
      for (const [token, count] of Object.entries(tf)) {
        weights[token] = (1.0 + Math.log(count)) * (Math.log((1.0 + n) / (1.0 + df[token])) + 1.0)
      }
      this.sparse.push(l2(weights))
    }
  }

  search(query: string, topK = 3): Array<{ doc: RegulationDoc; score: number }> {
    const hits: Array<{ score: number; index: number }> = []
    if (this.embedder !== null) {
      const queryVector = normDense(this.embedder(String(query)))
      for (let index = 0; index < (this.dense ?? []).length; index += 1) {
        const docVector = (this.dense as number[][])[index]
        let score = 0
        for (let position = 0; position < queryVector.length; position += 1) {
          score += queryVector[position] * (docVector[position] ?? 0)
        }
        hits.push({ score, index })
      }
    } else {
      const queryWeights = l2(tokenize(query))
      if (Object.keys(queryWeights).length > 0) {
        this.sparse.forEach((docVector, index) => {
          if (Object.keys(docVector).length === 0) return
          let score = 0
          for (const [token, weight] of Object.entries(queryWeights)) {
            if (docVector[token] !== undefined) score += weight * docVector[token]
          }
          hits.push({ score, index })
        })
      }
    }
    hits.sort((left, right) => (right.score - left.score) || (left.index - right.index))
    const limit = Math.max(0, Math.trunc(topK))
    return hits.slice(0, limit).map((hit) => ({ doc: this.docs[hit.index], score: round4(hit.score) }))
  }
}

export function buildRegulationIndex(knowledge: Knowledge): VectorIndex {
  return new VectorIndex(
    knowledge.regulations.map((regulation) => ({
      id: `${regulation.std_id} ${regulation.clause}`,
      text: [regulation.std_name, regulation.text, regulation.keywords.join(' ')].join(' '),
      standard: regulation.std_id,
      clause: regulation.clause,
      std_name: regulation.std_name,
    })),
  )
}

/** 兜底候选只挂在「判定后的条目卡」上（需要看 judgment.clause_refs）。 */
export interface FallbackTarget {
  readonly quote: string
  readonly hazard_type: string
  readonly judgment: { readonly clause_refs: readonly unknown[] }
  fallback_clauses?: FallbackClause[]
}

/** 对 `clause_refs` 为空的卡片附加兜底候选；返回补充的卡片数。 */
export function fallbackClauses(
  cards: readonly FallbackTarget[],
  index: VectorIndex,
  topK = 2,
  minScore = 0.05,
): number {
  let annotated = 0
  for (const card of cards) {
    if (card.judgment.clause_refs.length > 0) continue
    const query = `${card.quote} ${card.hazard_type}`
    const candidates: FallbackClause[] = []
    for (const { doc, score } of index.search(query, topK)) {
      if (score < minScore) continue
      candidates.push({
        standard: doc.standard,
        clause: doc.clause,
        std_name: doc.std_name,
        score,
        note: FALLBACK_NOTE,
      })
    }
    if (candidates.length > 0) {
      card.fallback_clauses = candidates
      annotated += 1
    }
  }
  return annotated
}