/**
 * PSL（Public Suffix List）冻结件视图 + Organizational Domain。
 *
 * 与旧仓 `psl.py` 的两个关键差别（都写进 `docs/email-evidence.md`）：
 *
 * 1. 冻结件从 `.dat` 文本转成 **JSON**（`data/psl-rules.json`），符合本仓
 *    「器官静态数据只放 `data/*.json`」的约定；规则语义（例外 / 通配 / 默认）不变。
 * 2. 数据**随模块导入**（`import ... with { type: 'json' }`），器官运行期不读文件、
 *    不联网；版本与日期来自 `data/psl-meta.json`。
 *
 * RFC 9989 §4.10 已用 tree walk 取代 PSL 求 Organizational Domain；本文件只用于
 * **对照值**与告警，不参与判定。
 */

import pslMeta from './data/psl-meta.json' with { type: 'json' }
import pslRules from './data/psl-rules.json' with { type: 'json' }

export const RULE_NORMAL = 'normal'
export const RULE_WILDCARD = 'wildcard'
export const RULE_EXCEPTION = 'exception'
export const RULE_DEFAULT = 'default'

export interface Rule {
  readonly text: string
  readonly kind: string
  readonly section: string
  readonly labels: readonly string[]
}

export interface PslMeta {
  readonly version: string
  readonly date: string
  readonly source_url: string
  readonly sha256: string
  readonly license: string
}

interface RuleIndex {
  readonly rules: Map<string, Rule>
  readonly exceptions: Map<string, Rule>
}

function splitLabels(domain: string): string[] {
  const normalized = String(domain).trim().replace(/\.+$/, '').toLowerCase()
  if (!normalized) return []
  return normalized.split('.').filter((label) => label.length > 0)
}

function buildIndex(): RuleIndex {
  const rules = new Map<string, Rule>()
  const exceptions = new Map<string, Rule>()
  const sections: Array<[string, readonly string[]]> = [
    ['icann', pslRules.section_icann],
    ['private', pslRules.section_private],
  ]
  for (const [section, entries] of sections) {
    for (const text of entries) {
      const labels = splitLabels(text.startsWith('!') ? text.slice(1) : text)
      if (text.startsWith('!')) {
        exceptions.set(labels.join('.'), { text, kind: RULE_EXCEPTION, section, labels })
      } else if (text.startsWith('*.')) {
        rules.set(labels.join('.'), { text, kind: RULE_WILDCARD, section, labels })
      } else {
        rules.set(labels.join('.'), { text, kind: RULE_NORMAL, section, labels })
      }
    }
  }
  return { rules, exceptions }
}

const INDEX = buildIndex()

export function pslVersion(): string {
  return String((pslMeta as PslMeta).version)
}

export function pslDate(): string {
  return String((pslMeta as PslMeta).date)
}

export function pslMetaInfo(): PslMeta {
  return pslMeta as PslMeta
}

export function pslRuleCount(): number {
  return INDEX.rules.size + INDEX.exceptions.size
}

function publicSuffix(domain: string): Rule {
  const labels = splitLabels(domain)
  if (labels.length === 0) throw new Error('PSL：域名为空，无法判定公共后缀')

  for (let size = labels.length; size > 0; size -= 1) {
    const candidate = labels.slice(labels.length - size)
    const rule = INDEX.exceptions.get(candidate.join('.'))
    if (rule !== undefined) return rule
  }

  for (let size = labels.length; size > 0; size -= 1) {
    const candidate = labels.slice(labels.length - size)
    const rule = INDEX.rules.get(candidate.join('.'))
    if (rule !== undefined) return rule
    if (size >= 2) {
      const wildcard = ['*', ...candidate.slice(1)].join('.')
      const wildRule = INDEX.rules.get(wildcard)
      if (wildRule !== undefined) return wildRule
    }
  }

  return { text: '*', kind: RULE_DEFAULT, section: 'icann', labels: [labels[labels.length - 1]] }
}

export function organizationalDomain(domain: string): string | null {
  const labels = splitLabels(domain)
  const rule = publicSuffix(domain)
  const suffixLabels = rule.kind === RULE_EXCEPTION ? rule.labels.slice(1) : rule.labels
  if (labels.length <= suffixLabels.length) return null
  return labels.slice(labels.length - suffixLabels.length - 1).join('.')
}

export function pslAnalysis(domain: string): {
  domain: string
  public_suffix: string
  organizational_domain: string | null
  rule: Rule
} {
  const normalized = String(domain).trim().replace(/\.+$/, '').toLowerCase()
  const labels = splitLabels(normalized)
  const rule = publicSuffix(normalized)
  const suffixLabels = rule.kind === RULE_EXCEPTION ? rule.labels.slice(1) : rule.labels
  return {
    domain: normalized,
    public_suffix: suffixLabels.length > 0 ? labels.slice(labels.length - suffixLabels.length).join('.') : '',
    organizational_domain:
      labels.length > suffixLabels.length
        ? labels.slice(labels.length - suffixLabels.length - 1).join('.')
        : null,
    rule,
  }
}