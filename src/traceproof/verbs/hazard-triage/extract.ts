/**
 * hazard-triage · 规则抽取引擎（源仓 `extract/rules.py`）。
 *
 * 正则全部来自受控词表 `hazard_types[].patterns`，代码里不散落魔法字符串；
 * 命中即产 HazardCard（统一中间表示），后续条款关联 / 分级只认条目卡。
 */

import type { HazardType, Knowledge } from './knowledge.js'
import type { LogRecord } from './parse.js'
import { KnowledgePackError } from './knowledge.js'

export interface CardSource {
  readonly file: string
  readonly record_index: number
}

export interface HazardCard {
  card_id: string | null
  readonly source: CardSource
  readonly quote: string
  readonly extractor: string
  readonly hazard_type: string
  readonly hazard_type_id: string
  readonly category: string
  readonly work_type: string
  readonly site_object: string
  attrs: Record<string, unknown>
  evidence: Record<string, unknown>
  readonly confidence: number
  readonly merged_from: string[]
}

export interface CompiledHazard {
  readonly hazard: HazardType
  readonly patterns: readonly RegExp[]
}

export function newCard(
  sourceFile: string,
  recordIndex: number,
  quote: string,
  hazardDef: HazardType,
  extractor: string,
  siteObject: string,
  confidence: number,
): HazardCard {
  return {
    card_id: null,
    source: { file: sourceFile, record_index: recordIndex },
    quote,
    extractor,
    hazard_type: hazardDef.name,
    hazard_type_id: hazardDef.id,
    category: hazardDef.category,
    work_type: hazardDef.work_type,
    site_object: siteObject,
    attrs: {},
    evidence: { record_index: recordIndex },
    confidence,
    merged_from: [extractor],
  }
}

export interface RuleEngine {
  readonly compiled: readonly CompiledHazard[]
  extract(records: readonly LogRecord[], sourceFile?: string): HazardCard[]
}

/** 词表里每个隐患类型的 patterns 都必须可编译；坏规则包直接拒绝（退出码 2）。 */
export function compileHazards(knowledge: Knowledge): CompiledHazard[] {
  return knowledge.hazardTypes.map((hazard, position) => {
    if (hazard.patterns.length === 0) {
      throw new KnowledgePackError(`受控词表第 ${position} 项（${hazard.id}）缺少 patterns`)
    }
    const patterns = hazard.patterns.map((pattern) => {
      try {
        return new RegExp(pattern)
      } catch (error) {
        throw new KnowledgePackError(
          `受控词表 ${hazard.id} 的正则不可编译：${pattern}（${(error as Error).message}）`,
        )
      }
    })
    return { hazard, patterns }
  })
}

/** 最长匹配：如「分配电箱」同时命中「配电箱」与「分配电箱」时取更具体的部位。 */
export function findSiteObject(hazard: HazardType, text: string): string {
  const hits = hazard.site_objects.filter((object) => text.includes(object))
  if (hits.length === 0) return ''
  return hits.reduce((best, candidate) => (candidate.length > best.length ? candidate : best), hits[0])
}

export function createRuleEngine(knowledge: Knowledge): RuleEngine {
  const compiled = compileHazards(knowledge)
  return {
    compiled,
    extract(records: readonly LogRecord[], sourceFile = '<memory>'): HazardCard[] {
      const cards: HazardCard[] = []
      for (const record of records) {
        const text = record.text
        for (const { hazard, patterns } of compiled) {
          if (!patterns.some((pattern) => pattern.test(text))) continue
          cards.push(
            newCard(
              sourceFile,
              record.index,
              text,
              hazard,
              'rules',
              findSiteObject(hazard, text),
              0.95,
            ),
          )
        }
      }
      return cards
    },
  }
}