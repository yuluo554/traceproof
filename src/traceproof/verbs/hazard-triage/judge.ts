/**
 * hazard-triage · 四级风险判定引擎（源仓 `reasoning/risk_level.py`）。
 *
 * 判定顺序（从重原则，命中即停）：
 *  1. 规则库 `major_patterns` 命中 → 重大风险；
 *  2. 规则库 `overrides`（重大隐患判定情形）命中 → 取最高档（只升不降）；
 *  3. 严重词在基础上调一档，封顶重大；
 *  4. 阈值数值判定：条目卡 attrs 携带实测值且超限 → 取阈值表 `level_on_violation`；
 *  5. 否则取受控词表 `base_level`。
 *
 * `rule_id` 可溯源：override 命中 → override_id，阈值命中 → RT-*，否则 → RL-<类型后缀>。
 * 模块常量是规则库数据缺失时的兜底默认值（与源仓一致，迁移一致性由 `consistency` 主张核对）。
 */

import type { Knowledge } from './knowledge.js'
import type { HazardCard } from './extract.js'
import type { LinkedClauseRef } from './link.js'

export const LEVELS = ['低风险', '一般风险', '较大风险', '重大风险'] as const
export type RiskLevel = (typeof LEVELS)[number]

export const SEVERITY_WORDS = ['坠亡', '伤亡', '死亡', '触电身亡', '坠落伤人', '高坠事故'] as const

export const MAJOR_PATTERNS = [
  '塔吊.{0,10}(限位|保险)装置(失效|缺失)',
  '(深基坑|高支模).{0,12}未(编制|组织).{0,8}(专项施工方案|专家论证)',
  '(施工升降机|物料提升机).{0,8}超载(运行)?',
] as const

export interface Judgment {
  readonly card_id: string | null
  readonly hazard_type_id: string
  readonly hazard_type: string
  readonly category: string
  readonly risk_level: RiskLevel
  readonly base_level: RiskLevel
  readonly rule_id: string
  readonly clause_refs: readonly LinkedClauseRef[]
  readonly upgraded: {
    readonly major_pattern: string | null
    readonly severity_word: string | null
  }
  readonly override_id: string | null
  readonly threshold_id: string | null
  readonly human_confirm: boolean
}

export function levelIndex(level: string): number {
  const index = (LEVELS as readonly string[]).indexOf(level)
  return index < 0 ? 0 : index
}

interface EffectiveRules {
  majorPatterns: readonly string[]
  severityWords: readonly string[]
  overrides: Knowledge['rules']['overrides']
  thresholdRules: Knowledge['rules']['threshold_rules']
}

function effectiveRules(knowledge: Knowledge): EffectiveRules {
  const rules = knowledge.rules
  return {
    majorPatterns: rules.major_patterns.length > 0 ? rules.major_patterns : MAJOR_PATTERNS,
    severityWords: rules.severity_words.length > 0 ? rules.severity_words : SEVERITY_WORDS,
    overrides: rules.overrides,
    thresholdRules: rules.threshold_rules,
  }
}

function thresholdViolations(card: HazardCard, rules: EffectiveRules, knowledge: Knowledge) {
  const attrs = card.attrs
  if (!attrs || Object.keys(attrs).length === 0) return []
  const hits: Knowledge['rules']['threshold_rules'][number][] = []
  for (const thresholdRule of rules.thresholdRules) {
    const threshold = knowledge.thresholdById.get(thresholdRule.threshold_id)
    if (threshold === undefined) continue
    const typeIds = thresholdRule.hazard_type_ids
    if (typeIds.length > 0 && !typeIds.includes(card.hazard_type_id)) continue
    const value = attrs[threshold.param]
    if (typeof value !== 'number' || !Number.isFinite(value)) continue
    const limit = threshold.value
    let violated = false
    switch (threshold.op) {
      case '<':
        violated = limit !== undefined && value < limit
        break
      case '>':
        violated = limit !== undefined && value > limit
        break
      case '<=':
        violated = limit !== undefined && value <= limit
        break
      case '>=':
        violated = limit !== undefined && value >= limit
        break
      case 'not_in': {
        const range = threshold.range
        if (range === undefined) continue
        violated = !(value >= range[0] && value <= range[1])
        break
      }
      default:
        continue
    }
    if (violated) hits.push(thresholdRule)
  }
  return hits
}

export function judge(card: HazardCard, clauseRefs: readonly LinkedClauseRef[], knowledge: Knowledge): Judgment {
  const rules = effectiveRules(knowledge)
  const hazard = knowledge.hazardTypeById.get(card.hazard_type_id)
  const base = (hazard?.base_level ?? '一般风险') as RiskLevel
  const quote = card.quote
  let index = levelIndex(base)
  let majorHit: string | null = null
  let severityHit: string | null = null
  let overrideHit: Knowledge['rules']['overrides'][number] | null = null
  let thresholdHit: Knowledge['rules']['threshold_rules'][number] | null = null

  for (const pattern of rules.majorPatterns) {
    if (new RegExp(pattern).test(quote)) {
      majorHit = pattern
      index = levelIndex('重大风险')
      break
    }
  }
  for (const override of rules.overrides) {
    if (override.match.any_of.some((pattern) => new RegExp(pattern).test(quote))) {
      overrideHit = override
      index = Math.max(index, levelIndex(override.level || '重大风险'))
      break
    }
  }
  if (majorHit === null && overrideHit === null) {
    for (const word of rules.severityWords) {
      if (quote.includes(word)) {
        severityHit = word
        index = Math.min(index + 1, levelIndex('重大风险'))
        break
      }
    }
    if (severityHit === null) {
      const violations = thresholdViolations(card, rules, knowledge)
      if (violations.length > 0) {
        thresholdHit = violations[0]
        index = Math.max(index, levelIndex(thresholdHit.level_on_violation || '较大风险'))
      }
    }
  }

  return {
    card_id: card.card_id,
    hazard_type_id: card.hazard_type_id,
    hazard_type: card.hazard_type,
    category: card.category,
    risk_level: LEVELS[index],
    base_level: base,
    rule_id:
      overrideHit?.override_id ??
      thresholdHit?.rule_id ??
      `RL-${card.hazard_type_id.replace('HT-', '')}`,
    clause_refs: clauseRefs,
    upgraded: { major_pattern: majorHit, severity_word: severityHit },
    override_id: overrideHit?.override_id ?? null,
    threshold_id: thresholdHit?.threshold_id ?? null,
    human_confirm: (card.confidence ?? 1.0) < 0.6 || card.extractor === 'llm',
  }
}