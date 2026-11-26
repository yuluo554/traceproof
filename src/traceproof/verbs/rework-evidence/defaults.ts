/**
 * rework-evidence · 口径与阈值（迁自源仓 `config.py` 的单点定义）。
 *
 * 纪律沿用源仓 K1：阈值与词表只在**数据文件**里出现一次；代码只引用常量，
 * 文档不抄数值。数据随模块导入（`import ... with { type: 'json' }`），
 * 器官运行期不读文件、不读环境变量、不读时钟。
 */

import defaults from './data/rework-defaults.json' with { type: 'json' }

export interface ReworkDefaults {
  thresholds: {
    rework_min_versions: number
    rework_min_edits: number
    dup_match_threshold: number
  }
  read_event_kinds: readonly string[]
  write_event_kinds: readonly string[]
  symbol_prefix_tokens: readonly string[]
  symbol_suffix_tokens: readonly string[]
  supported_symbol_languages: readonly string[]
  symbol_language_by_suffix: Readonly<Record<string, string>>
  dup_disclosure: string
}

function freezeDeep<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value as Record<string, unknown>)) freezeDeep(item)
    Object.freeze(value)
  }
  return value
}

/** 冻结的默认口径（三道 `Object.freeze` 保证调用方不能就地改阈值）。 */
export const DEFAULTS: ReworkDefaults = freezeDeep(defaults as unknown as ReworkDefaults)

export const REWORK_MIN_VERSIONS = DEFAULTS.thresholds.rework_min_versions
export const REWORK_MIN_EDITS = DEFAULTS.thresholds.rework_min_edits
export const DUP_MATCH_THRESHOLD = DEFAULTS.thresholds.dup_match_threshold
export const READ_EVENT_KINDS: ReadonlySet<string> = new Set(DEFAULTS.read_event_kinds)
export const WRITE_EVENT_KINDS: ReadonlySet<string> = new Set(DEFAULTS.write_event_kinds)
export const SYMBOL_PREFIX_TOKENS: ReadonlySet<string> = new Set(DEFAULTS.symbol_prefix_tokens)
export const SYMBOL_SUFFIX_TOKENS: ReadonlySet<string> = new Set(DEFAULTS.symbol_suffix_tokens)
export const SUPPORTED_SYMBOL_LANGUAGES: ReadonlySet<string> = new Set(
  DEFAULTS.supported_symbol_languages,
)
export const SYMBOL_LANGUAGE_BY_SUFFIX: Readonly<Record<string, string>> =
  DEFAULTS.symbol_language_by_suffix
export const DUP_DISCLOSURE = DEFAULTS.dup_disclosure