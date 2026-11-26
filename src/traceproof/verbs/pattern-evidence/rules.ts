/**
 * 规则包校验与装载（迁移自旧仓 `src/lib/rules.js`）。
 *
 * 口径（与源仓一致）：缺字段 / 枚举越界 / 未知 detect 键 / 优先级漏项 → **拒绝加载并列出全部
 * 违规**，绝不部分加载。阈值 / 枚举 / 优先级只从规则包的 manifest 读，器官代码不写死第二份。
 */

import { isPlainObject } from './util.js'

export const REQUIRED_RULE_FIELDS = [
  'rule_id',
  'name',
  'category',
  'severity',
  'detect',
  'evidence_required',
  'locator_strategy',
  'explanation',
] as const

export const REQUIRED_THRESHOLD_KEYS = [
  'precision_min',
  'recall_min',
  'min_cases_per_rule',
  'scan_timeout_ms',
  'first_result_budget_ms',
  'fixture_page_count',
  'stress_node_count',
  'snippet_max_len',
] as const

export class RulePackError extends Error {
  readonly errors: readonly string[]

  constructor(errors: readonly string[]) {
    super(`规则包校验失败（${errors.length} 项）：\n- ${errors.join('\n- ')}`)
    this.name = 'RulePackError'
    this.errors = errors
  }
}

export interface RuleSpec {
  readonly rule_id: string
  readonly name: string
  readonly category: string
  readonly severity: string
  readonly detect: Readonly<Record<string, unknown>>
  readonly evidence_required: readonly string[]
  readonly locator_strategy: string
  readonly explanation: string
  readonly limits?: readonly string[]
  readonly remediation_hint?: string
  readonly [key: string]: unknown
}

export interface RuleManifest {
  readonly ruleset_version?: unknown
  readonly ruleset_hash?: unknown
  readonly rule_files?: unknown
  readonly thresholds?: Readonly<Record<string, unknown>>
  readonly severity_levels?: unknown
  readonly categories?: unknown
  readonly match_priority?: unknown
  readonly evidence_kinds?: unknown
  readonly detect_keys?: unknown
  readonly style_keys?: unknown
  readonly sort?: unknown
  readonly output?: unknown
  readonly [key: string]: unknown
}

/** 校验规则包，返回错误清单（空数组 = 通过）。 */
export function validateRulePack(manifest: unknown, specs: unknown): string[] {
  const errors: string[] = []
  if (!isPlainObject(manifest)) return ['manifest 不是对象']
  if (!Array.isArray(specs)) return ['specs 不是数组']

  if (typeof manifest.ruleset_version !== 'string' || manifest.ruleset_version.length === 0) {
    errors.push('manifest.ruleset_version 缺失')
  }
  if (typeof manifest.ruleset_hash !== 'string' || manifest.ruleset_hash.length === 0) {
    errors.push('manifest.ruleset_hash 缺失')
  } else if (manifest.ruleset_hash.includes('TBD')) {
    errors.push(`manifest.ruleset_hash 仍是占位值（${manifest.ruleset_hash}）——跑 npm run rules:hash`)
  }
  const thresholds = isPlainObject(manifest.thresholds) ? manifest.thresholds : undefined
  for (const key of REQUIRED_THRESHOLD_KEYS) {
    if (typeof thresholds?.[key] !== 'number') errors.push(`manifest.thresholds.${key} 缺失或非数值`)
  }
  for (const key of [
    'severity_levels',
    'categories',
    'match_priority',
    'rule_files',
    'evidence_kinds',
    'detect_keys',
    'style_keys',
  ]) {
    if (!Array.isArray(manifest[key]) || manifest[key].length === 0) errors.push(`manifest.${key} 缺失或为空`)
  }
  if (errors.length > 0) return errors

  const severityLevels = new Set(manifest.severity_levels as string[])
  const categories = new Set(manifest.categories as string[])
  const evidenceKinds = new Set(manifest.evidence_kinds as string[])
  const detectKeys = new Set(manifest.detect_keys as string[])
  const styleKeys = new Set(manifest.style_keys as string[])
  const seen = new Set<string>()

  for (const raw of specs) {
    const label = isPlainObject(raw) && typeof raw.rule_id === 'string' ? raw.rule_id : '<无 rule_id 的规则>'
    if (!isPlainObject(raw)) {
      errors.push(`${label}: 规则不是对象`)
      continue
    }
    const spec = raw as Record<string, unknown>
    for (const field of REQUIRED_RULE_FIELDS) {
      const value = spec[field]
      const empty =
        value === undefined ||
        value === null ||
        (typeof value === 'string' && value.trim().length === 0) ||
        (Array.isArray(value) && value.length === 0)
      if (empty) errors.push(`${label}: 缺字段 ${field}`)
    }
    if (seen.has(label)) errors.push(`${label}: rule_id 重复`)
    seen.add(label)

    if (!severityLevels.has(spec.severity as string)) {
      errors.push(`${label}: severity=${String(spec.severity)} 不在 manifest.severity_levels`)
    }
    if (!categories.has(spec.category as string)) {
      errors.push(`${label}: category=${String(spec.category)} 不在 manifest.categories`)
    }

    for (const kind of (spec.evidence_required as string[] | undefined) ?? []) {
      if (!evidenceKinds.has(kind)) errors.push(`${label}: evidence_required 含未知证据类型 ${kind}`)
    }
    if (isPlainObject(spec.detect)) {
      const detect = spec.detect
      for (const key of Object.keys(detect)) {
        if (!detectKeys.has(key)) {
          errors.push(`${label}: detect 含未知键 ${key}（未知键会让规则静默永不命中，故拒绝加载）`)
        }
      }
      const style = isPlainObject(detect.style) ? detect.style : {}
      for (const key of Object.keys(style)) {
        if (!styleKeys.has(key)) errors.push(`${label}: detect.style 含未知键 ${key}`)
      }
      const styleAny = Array.isArray(detect.style_any) ? detect.style_any : []
      for (const group of styleAny) {
        if (!isPlainObject(group)) continue
        for (const key of Object.keys(group)) {
          if (!styleKeys.has(key)) errors.push(`${label}: detect.style_any 含未知键 ${key}`)
        }
      }
    } else {
      errors.push(`${label}: detect 不是对象`)
    }
    if (!Array.isArray(spec.limits) || spec.limits.length === 0) {
      errors.push(`${label}: 缺 limits（每条规则必须显式声明"本工具不判断什么"）`)
    }
  }

  const ruleFiles = manifest.rule_files as unknown[]
  if (ruleFiles.length !== specs.length) {
    errors.push(`manifest.rule_files ${ruleFiles.length} 个 ≠ 实际规则 ${specs.length} 条`)
  }
  const priority = (manifest.match_priority as string[]) ?? []
  for (const id of priority) {
    if (!seen.has(id)) errors.push(`manifest.match_priority 含不存在的规则 ${id}`)
  }
  for (const id of seen) {
    if (!priority.includes(id)) {
      errors.push(`manifest.match_priority 漏掉了规则 ${id}（同一节点多命中时的归属必须唯一确定）`)
    }
  }
  if (priority.length !== new Set(priority).size) errors.push('manifest.match_priority 有重复项')
  return errors
}

export interface LoadedPack {
  readonly manifest: RuleManifest
  readonly specs: readonly RuleSpec[]
  readonly byId: ReadonlyMap<string, RuleSpec>
  readonly order: readonly RuleSpec[]
}

/** 校验并返回可用的规则包；不通过即抛 `RulePackError`（**绝不部分加载**）。 */
export function loadRulePack(manifest: unknown, specs: unknown): LoadedPack {
  const errors = validateRulePack(manifest, specs)
  if (errors.length > 0) throw new RulePackError(errors)
  const parsedManifest = manifest as RuleManifest
  const parsedSpecs = specs as RuleSpec[]
  const byId = new Map(parsedSpecs.map((spec) => [spec.rule_id, spec]))
  const order = (parsedManifest.match_priority as string[]).map((id) => byId.get(id) as RuleSpec)
  return { manifest: parsedManifest, specs: parsedSpecs, byId, order }
}

/** 严重度位次（越大越严重）；未知等级抛错。 */
export function severityRank(manifest: RuleManifest, severity: string): number {
  const levels = manifest.severity_levels as string[]
  const index = levels.indexOf(severity)
  if (index < 0) throw new Error(`未知严重度: ${severity}`)
  return index + 1
}

/** 分组顺序（紧迫/误导/障碍/价格）由 manifest.categories 决定。 */
export function categoryOrder(manifest: RuleManifest): string[] {
  return [...(manifest.categories as string[])]
}