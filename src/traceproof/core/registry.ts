/**
 * 器官注册表：一个器官（verb）= 一份声明，不是一个小框架。
 *
 * 器官只允许声明四件事：slug、版本、摘要、输入字段，外加一个 `evaluate` 函数。
 * slug 全局唯一；重复注册默认报错（防两个器官抢同一入口）。
 */

import type { Basis } from './trace-index.js'
import type { LedgerRecord } from './ledger.js'

export const SLUG_PATTERN = /^[a-z][a-z0-9-]*$/

export class VerbMissing extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VerbMissing'
  }
}

export interface Verb {
  readonly slug: string
  readonly version: string
  readonly summary: string
  readonly input_fields: readonly string[]
  evaluate(subject: Record<string, unknown>, basis: Basis): Iterable<LedgerRecord>
}

const REGISTRY = new Map<string, Verb>()

export function register(verb: Verb, options: { replace?: boolean } = {}): Verb {
  if (!SLUG_PATTERN.test(verb.slug ?? '')) {
    throw new Error(`器官 slug 非法（要求 ^[a-z][a-z0-9-]*$）：${String(verb.slug)}`)
  }
  if (!verb.version || !String(verb.version).trim()) throw new Error('器官字段为空：version')
  if (!verb.summary || !String(verb.summary).trim()) throw new Error('器官字段为空：summary')
  if (!verb.input_fields || verb.input_fields.length === 0) {
    throw new Error(`器官 ${verb.slug} 未声明输入字段`)
  }
  if (typeof verb.evaluate !== 'function') {
    throw new Error(`器官 ${verb.slug} 的 evaluate 不可调用`)
  }
  if (REGISTRY.has(verb.slug) && !options.replace) {
    throw new Error(`器官重复注册：${verb.slug}`)
  }
  REGISTRY.set(verb.slug, verb)
  return verb
}

export function get(slug: string): Verb {
  const found = REGISTRY.get(slug)
  if (found === undefined) throw new VerbMissing(`未注册的器官：${slug}`)
  return found
}

/** 按 slug 排序返回全部器官（顺序确定，输出可复现）。 */
export function allVerbs(): Verb[] {
  return [...REGISTRY.keys()].sort().map((slug) => REGISTRY.get(slug) as Verb)
}

export function verbToJSON(verb: Verb): Record<string, unknown> {
  return {
    slug: verb.slug,
    version: verb.version,
    summary: verb.summary,
    input_fields: [...verb.input_fields],
  }
}