/**
 * 页面模型（PageModel）契约 + 证据登记表 + detect 规格匹配。
 *
 * 迁移来源：旧仓 `src/lib/page-model.js`（判定层，target-map ④ 行）。浏览器采集层与
 * 基准层产出同一种节点对象；本器官只接收**已归一化**的节点，不碰 DOM、不读文件。
 *
 * 保留的判定语义（逐条对齐源仓）：
 *  - `kind` 三态（text / element / control）；`control` 元素可命中 `element` 规则；
 *  - `label` 由采集层给出（显式标签属性 → 控件自身文本 → value），本器官不重算 DOM 文本；
 *  - 证据登记表：取不到（undefined）= 丢弃候选并记 rejected；空串 = 取到了空值（合法证据）；
 *  - `detect.style` 是 AND、`detect.style_any` 是 OR；中和项（neutralizers）命中即 suppressed，
 *    `nearby_absent_any` 命中即 suppressed（"没命中"与"被中和"是两种事实）；
 *  - 颜色按 WCAG 相对亮度重算对比度；认不出的颜色 = 取不到证据（不是 1:1）。
 */

import { ContractError } from '../../core/ledger.js'
import { isPlainObject, readFiniteNumber, readInteger, readString } from './util.js'

export const KIND_TEXT = 'text'
export const KIND_ELEMENT = 'element'
export const KIND_CONTROL = 'control'

export const CONTROL_TAGS = ['input', 'button', 'select', 'textarea', 'a']

/** 周边文本 / 标签文本的截断长度（口径单点，与源仓一致）。 */
export const NEAR_TEXT_LIMIT = 200

/** 控件标签属性的优先级（口径单点，与源仓一致）。 */
export const LABEL_ATTRS = ['aria-label', 'title', 'placeholder', 'alt']

export type Kind = typeof KIND_TEXT | typeof KIND_ELEMENT | typeof KIND_CONTROL

export interface PageNodeStyle {
  color?: string
  backgroundColor?: string
  display?: string
  opacity?: number
  fontSizePx?: number
}

export interface PageNodeBox {
  widthPx?: number
  heightPx?: number
}

/** 归一化页面模型节点：字段与源仓 collector / fixture 解析器产出的对象同形。 */
export interface PageNode {
  readonly seq: number
  readonly kind: Kind
  readonly tag: string
  readonly text: string
  readonly label: string
  readonly attrs: Readonly<Record<string, string>>
  readonly style: Readonly<PageNodeStyle>
  readonly box: Readonly<PageNodeBox>
  readonly contrast?: number
  readonly nearText: string
  readonly path: string
}

export function kindOfTag(tag: unknown): Kind {
  const lower = String(tag || '').toLowerCase()
  if (!lower) return KIND_TEXT
  return CONTROL_TAGS.includes(lower) ? KIND_CONTROL : KIND_ELEMENT
}

/** 可读标签（口径单点）：显式标签属性 → **仅控件**的自身文本 → `value`。 */
export function labelFrom({
  tag = '',
  attrs = {},
  ownText = '',
}: {
  tag?: string
  attrs?: Record<string, unknown>
  ownText?: string
}): string {
  for (const name of LABEL_ATTRS) {
    const value = attrs?.[name]
    if (typeof value === 'string' && value.trim().length > 0) return value.trim().slice(0, NEAR_TEXT_LIMIT)
  }
  if (!CONTROL_TAGS.includes(String(tag).toLowerCase())) return ''
  const own = String(ownText ?? '').trim()
  if (own.length > 0) return own.slice(0, NEAR_TEXT_LIMIT)
  const value = attrs?.value
  return typeof value === 'string' && value.trim().length > 0 ? value.trim().slice(0, NEAR_TEXT_LIMIT) : ''
}

export function makeTextNode({
  seq,
  text,
  path,
  nearText = '',
  ownerTag = '#text',
}: {
  seq: number
  text: string
  path: string
  nearText?: string
  ownerTag?: string
}): PageNode {
  return {
    seq,
    kind: KIND_TEXT,
    tag: ownerTag,
    text: String(text ?? ''),
    label: '',
    attrs: {},
    style: {},
    box: {},
    contrast: undefined,
    nearText: String(nearText ?? ''),
    path,
  }
}

export function makeElementNode({
  seq,
  tag,
  path,
  attrs = {},
  text = '',
  label = '',
  nearText = '',
  style = {},
  box = {},
  contrast = undefined,
}: {
  seq: number
  tag: string
  path: string
  attrs?: Record<string, unknown>
  text?: string
  label?: string
  nearText?: string
  style?: PageNodeStyle
  box?: PageNodeBox
  contrast?: number
}): PageNode {
  const normalizedAttrs: Record<string, string> = {}
  for (const [name, value] of Object.entries(attrs)) normalizedAttrs[name] = String(value)
  return {
    seq,
    kind: kindOfTag(tag),
    tag: String(tag || '').toLowerCase(),
    text: String(text ?? ''),
    label: String(label ?? ''),
    attrs: normalizedAttrs,
    style: { ...style },
    box: { ...box },
    contrast,
    nearText: String(nearText ?? ''),
    path,
  }
}

/** 匹配用的文本池：自身文本 + 可读标签（控件通常只有标签）。 */
export function haystack(node: Pick<PageNode, 'text' | 'label'>): string {
  return [node.text, node.label].filter((part) => part && part.length > 0).join(' ').trim()
}

/** 文本归一：空白折叠为单空格 + 去首尾（口径单点）。 */
export function normalizeWs(text: unknown): string {
  return String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * 周边文本口径：**宿主元素的父容器文本 − 宿主元素文本**，归一空白后取前 `limit` 字符。
 * 空串是合法证据（"这个区域确实没有别的文本"）。
 */
export function limitNearText(ownText: unknown, parentText: unknown, limit = NEAR_TEXT_LIMIT): string {
  const own = String(ownText ?? '').trim()
  const all = String(parentText ?? '').trim()
  const stripped = own.length > 0 ? all.replace(own, '') : all
  let size = Math.min(stripped.length, limit * 2)
  let normalized = normalizeWs(stripped.slice(0, size))
  while (normalized.length < limit && size < stripped.length) {
    size = Math.min(stripped.length, size * 2)
    normalized = normalizeWs(stripped.slice(0, size))
  }
  return normalized.slice(0, limit)
}

const stringOrUndefined = (value: unknown): string | undefined =>
  typeof value === 'string' ? value : undefined
const numberOrUndefined = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isFinite(value) ? value : undefined

/** 证据登记表：每个 kind 一个取值函数；**取不到 → undefined → 候选被丢弃**（不是降级）。 */
export const EVIDENCE: Readonly<Record<string, (node: PageNode) => string | undefined>> = {
  text: (node) => stringOrUndefined(node.text),
  'label-text': (node) => {
    const label = node.label && node.label.length > 0 ? node.label : node.text
    return typeof label === 'string' ? label : undefined
  },
  'nearby-text': (node) => stringOrUndefined(node.nearText),
  'checked-state': (node) => {
    if (!node.attrs || !('checked' in node.attrs)) return undefined
    return node.attrs.checked === 'true' ? 'checked' : 'unchecked'
  },
  'box-size': (node) => {
    const width = numberOrUndefined(node.box?.widthPx)
    const height = numberOrUndefined(node.box?.heightPx)
    if (width === undefined || height === undefined) return undefined
    return `${width}x${height}`
  },
  'contrast-ratio': (node) => {
    const ratio = numberOrUndefined(node.contrast)
    return ratio === undefined ? undefined : ratio.toFixed(2)
  },
  'style-color': (node) => stringOrUndefined(node.style?.color),
  'style-background-color': (node) => stringOrUndefined(node.style?.backgroundColor),
  'style-display': (node) => stringOrUndefined(node.style?.display),
  'style-opacity': (node) => numberOrUndefined(node.style?.opacity)?.toString(),
  'style-font-size': (node) => numberOrUndefined(node.style?.fontSizePx)?.toString(),
  'dom-path': (node) => stringOrUndefined(node.path),
}

export interface EvidenceItem {
  readonly kind: string
  readonly value: string
}

/** 取一条证据；未知 kind 直接抛错（规则包校验会先拦下未知 kind）。 */
export function evidenceValue(node: PageNode, kind: string): string | undefined {
  const getter = EVIDENCE[kind]
  if (!getter) throw new Error(`未知证据类型: ${kind}`)
  return getter(node)
}

export function collectEvidence(
  node: PageNode,
  kinds: readonly string[],
): { evidence: EvidenceItem[]; missing: string[] } {
  const evidence: EvidenceItem[] = []
  const missing: string[] = []
  for (const kind of kinds) {
    const value = evidenceValue(node, kind)
    if (value === undefined) missing.push(kind)
    else evidence.push({ kind, value })
  }
  return { evidence, missing }
}

// ── 颜色工具（单点实现：与源仓同公式）────────────────────────────────────────
export interface ParsedColor {
  readonly r: number
  readonly g: number
  readonly b: number
  readonly a: number
}

const NAMED_COLORS: Readonly<Record<string, string>> = {
  black: '#000000',
  white: '#ffffff',
  transparent: '#00000000',
}

export function parseColor(input: unknown): ParsedColor | null {
  if (typeof input !== 'string') return null
  const text = input.trim().toLowerCase()
  if (text.length === 0) return null
  const named = NAMED_COLORS[text]
  const source = named ?? text
  if (source.startsWith('#')) {
    const hex = source.slice(1)
    if (hex.length === 3) {
      return {
        r: parseInt(hex[0] + hex[0], 16),
        g: parseInt(hex[1] + hex[1], 16),
        b: parseInt(hex[2] + hex[2], 16),
        a: 1,
      }
    }
    if (hex.length === 6 || hex.length === 8) {
      return {
        r: parseInt(hex.slice(0, 2), 16),
        g: parseInt(hex.slice(2, 4), 16),
        b: parseInt(hex.slice(4, 6), 16),
        a: hex.length === 8 ? parseInt(hex.slice(6, 8), 16) / 255 : 1,
      }
    }
    return null
  }
  const match = source.match(/^rgba?\(([^)]+)\)$/)
  if (match) {
    const parts = match[1]
      .split(/[\s,/]+/)
      .filter((part) => part.length > 0)
      .map(Number)
    if (parts.length < 3 || parts.some((n) => Number.isNaN(n))) return null
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 }
  }
  return null
}

/** 颜色等价判定（#fff 与 rgb(255,255,255) 视为同色；认不出的写法按字符串比较）。 */
export function colorsEqual(left: unknown, right: unknown): boolean {
  const a = parseColor(left)
  const b = parseColor(right)
  if (!a || !b) return String(left ?? '').trim().toLowerCase() === String(right ?? '').trim().toLowerCase()
  return a.r === b.r && a.g === b.g && a.b === b.b
}

function channelLuminance(value: number): number {
  const channel = value / 255
  return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
}

export function relativeLuminance(color: string | ParsedColor | null): number | null {
  const parsed = typeof color === 'string' ? parseColor(color) : color
  if (!parsed) return null
  return (
    0.2126 * channelLuminance(parsed.r) +
    0.7152 * channelLuminance(parsed.g) +
    0.0722 * channelLuminance(parsed.b)
  )
}

/** WCAG 相对对比度；任一颜色认不出 → null（= 取不到证据，不是 1:1）。 */
export function contrastRatio(foreground: unknown, background: unknown): number | null {
  const a = relativeLuminance(typeof foreground === 'string' ? foreground : parseColor(foreground))
  const b = relativeLuminance(typeof background === 'string' ? background : parseColor(background))
  if (a === null || b === null) return null
  const lighter = Math.max(a, b)
  const darker = Math.min(a, b)
  return (lighter + 0.05) / (darker + 0.05)
}

// ── detect 规格匹配 ─────────────────────────────────────────────────────────
export interface DetectStyleSpec {
  max_size_px?: number
  color_equals_background?: boolean
  opacity_max?: number
  contrast_below?: number
  min_font_size_px?: number
}

export interface DetectSpec {
  node_kinds?: readonly string[]
  text_any?: readonly string[]
  text_all?: readonly string[]
  near_text_any?: readonly string[]
  nearby_absent_any?: readonly string[]
  attrs?: Readonly<Record<string, unknown>>
  style?: DetectStyleSpec
  style_any?: readonly DetectStyleSpec[]
  neutralizers?: readonly string[]
}

export interface DetectVerdict {
  readonly matched: boolean
  readonly suppressed_by: string | null
}

const toRegexes = (patterns: unknown, where: string): RegExp[] => {
  if (!patterns) return []
  if (!Array.isArray(patterns)) throw new TypeError(`${where} 必须是正则字符串数组`)
  return patterns.map((pattern) => {
    try {
      return new RegExp(pattern as string)
    } catch (error) {
      throw new Error(`${where} 的正则无法编译（${(error as Error).message}）`)
    }
  })
}

function kindMatches(node: PageNode, kinds: unknown): boolean {
  if (!Array.isArray(kinds) || kinds.length === 0) return true
  if (kinds.includes(node.kind)) return true
  return node.kind === KIND_CONTROL && kinds.includes(KIND_ELEMENT)
}

function attrsMatch(node: PageNode, attrs: unknown): boolean {
  if (attrs === undefined || attrs === null) return true
  if (!isPlainObject(attrs)) throw new TypeError('detect.attrs 必须是对象')
  for (const [name, expected] of Object.entries(attrs)) {
    const actual = node.attrs?.[name]
    if (actual === undefined) return false
    if (String(actual) !== String(expected)) return false
  }
  return true
}

function styleMatches(node: PageNode, style: unknown): boolean {
  const spec = isPlainObject(style) ? (style as DetectStyleSpec) : {}
  const box = node.box || {}
  const computed = node.style || {}
  if (spec.max_size_px !== undefined) {
    const width = numberOrUndefined(box.widthPx)
    const height = numberOrUndefined(box.heightPx)
    if (width === undefined || height === undefined) return false
    if (Math.min(width, height) > spec.max_size_px) return false
  }
  if (spec.color_equals_background === true) {
    const color = computed.color
    const background = computed.backgroundColor
    if (typeof color !== 'string' || typeof background !== 'string') return false
    if (!colorsEqual(color, background)) return false
  }
  if (spec.opacity_max !== undefined) {
    const opacity = numberOrUndefined(computed.opacity)
    if (opacity === undefined || opacity > spec.opacity_max) return false
  }
  if (spec.contrast_below !== undefined) {
    const ratio = numberOrUndefined(node.contrast)
    if (ratio === undefined || ratio >= spec.contrast_below) return false
  }
  if (spec.min_font_size_px !== undefined) {
    const size = numberOrUndefined(computed.fontSizePx)
    if (size === undefined || size < spec.min_font_size_px) return false
  }
  return true
}

/** `style_any` = 任一条件组成立（OR）；空/缺省 = true。 */
function styleAnyMatches(node: PageNode, groups: unknown): boolean {
  if (!Array.isArray(groups) || groups.length === 0) return true
  return groups.some((group) => styleMatches(node, group))
}

/** 判定一个节点是否命中一条规则的 detect 规格。 */
export function matchesDetect(node: PageNode, detect: unknown): DetectVerdict {
  const spec = isPlainObject(detect) ? (detect as DetectSpec) : {}
  if (!kindMatches(node, spec.node_kinds)) return { matched: false, suppressed_by: null }
  if (!attrsMatch(node, spec.attrs)) return { matched: false, suppressed_by: null }

  const pool = haystack(node)
  const text = node.text || ''
  if (spec.text_any) {
    const hit = toRegexes(spec.text_any, 'detect.text_any').some((re) => re.test(pool))
    if (!hit) return { matched: false, suppressed_by: null }
  }
  if (spec.text_all) {
    const hit = toRegexes(spec.text_all, 'detect.text_all').every((re) => re.test(pool))
    if (!hit) return { matched: false, suppressed_by: null }
  }
  if (spec.near_text_any) {
    const hit = toRegexes(spec.near_text_any, 'detect.near_text_any').some((re) =>
      re.test(`${node.nearText}\n${pool}`),
    )
    if (!hit) return { matched: false, suppressed_by: null }
  }
  if (spec.nearby_absent_any) {
    const hit = toRegexes(spec.nearby_absent_any, 'detect.nearby_absent_any').some((re) =>
      re.test(node.nearText || ''),
    )
    if (hit) return { matched: false, suppressed_by: 'nearby_absent_any' }
  }
  if (!styleMatches(node, spec.style)) return { matched: false, suppressed_by: null }
  if (!styleAnyMatches(node, spec.style_any)) return { matched: false, suppressed_by: null }

  for (const pattern of toRegexes(spec.neutralizers, 'detect.neutralizers')) {
    if (pattern.test(pool) || pattern.test(text)) {
      return { matched: false, suppressed_by: `neutralizer:${pattern.source}` }
    }
  }
  return { matched: true, suppressed_by: null }
}

/** 截断 snippet：必须是宿主文本的**原样子串**；截断时记 `snippet_truncated: true`。 */
export function makeSnippet(
  node: PageNode,
  maxLen: number | null | undefined,
): { snippet: string; snippet_truncated: boolean } {
  const source = node.kind === KIND_TEXT ? node.text || node.label : node.label || node.text
  const text = typeof source === 'string' ? source : ''
  if (maxLen === undefined || maxLen === null || text.length <= maxLen) {
    return { snippet: text, snippet_truncated: false }
  }
  return { snippet: text.slice(0, maxLen), snippet_truncated: true }
}

// ── 输入解析：JSON 节点 → PageNode（未知字段拒绝，防静默漂移）─────────────────
const NODE_FIELDS = new Set([
  'seq',
  'kind',
  'tag',
  'text',
  'label',
  'attrs',
  'style',
  'box',
  'contrast',
  'nearText',
  'path',
])
const STYLE_FIELDS = new Set(['color', 'backgroundColor', 'display', 'opacity', 'fontSizePx'])
const BOX_FIELDS = new Set(['widthPx', 'heightPx'])

function parseAttrs(raw: unknown, where: string): Record<string, string> {
  if (raw === undefined) return {}
  if (!isPlainObject(raw)) throw new ContractError(`${where}.attrs 必须是对象`)
  const attrs: Record<string, string> = {}
  for (const [name, value] of Object.entries(raw)) {
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
      throw new ContractError(`${where}.attrs.${name} 必须是字符串 / 数字 / 布尔`)
    }
    attrs[name] = String(value)
  }
  return attrs
}

function parseStyle(raw: unknown, where: string): PageNodeStyle {
  if (raw === undefined) return {}
  if (!isPlainObject(raw)) throw new ContractError(`${where}.style 必须是对象`)
  const style: PageNodeStyle = {}
  for (const key of Object.keys(raw)) {
    if (!STYLE_FIELDS.has(key)) throw new ContractError(`${where}.style 含未知键 ${key}`)
  }
  for (const key of ['color', 'backgroundColor', 'display'] as const) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== 'string') throw new ContractError(`${where}.style.${key} 必须是字符串`)
      style[key] = raw[key] as string
    }
  }
  for (const key of ['opacity', 'fontSizePx'] as const) {
    if (raw[key] !== undefined) style[key] = readFiniteNumber(raw[key], `${where}.style.${key}`)
  }
  return style
}

function parseBox(raw: unknown, where: string): PageNodeBox {
  if (raw === undefined) return {}
  if (!isPlainObject(raw)) throw new ContractError(`${where}.box 必须是对象`)
  const box: PageNodeBox = {}
  for (const key of Object.keys(raw)) {
    if (!BOX_FIELDS.has(key)) throw new ContractError(`${where}.box 含未知键 ${key}`)
  }
  for (const key of ['widthPx', 'heightPx'] as const) {
    if (raw[key] !== undefined) box[key] = readFiniteNumber(raw[key], `${where}.box.${key}`)
  }
  return box
}

export function parsePageNode(raw: unknown, where: string): PageNode {
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  for (const key of Object.keys(raw)) {
    if (!NODE_FIELDS.has(key)) throw new ContractError(`${where} 含未知键 ${key}`)
  }
  const seq = readInteger(raw.seq, `${where}.seq`)
  const kind = raw.kind
  if (kind !== KIND_TEXT && kind !== KIND_ELEMENT && kind !== KIND_CONTROL) {
    throw new ContractError(`${where}.kind 必须是 ${KIND_TEXT} / ${KIND_ELEMENT} / ${KIND_CONTROL}`)
  }
  const tag = raw.tag === undefined ? (kind === KIND_TEXT ? '#text' : '') : readString(raw.tag, `${where}.tag`, true)
  const text = raw.text === undefined ? '' : readString(raw.text, `${where}.text`, true)
  const label = raw.label === undefined ? '' : readString(raw.label, `${where}.label`, true)
  const nearText = raw.nearText === undefined ? '' : readString(raw.nearText, `${where}.nearText`, true)
  const path = readString(raw.path, `${where}.path`)
  const attrs = parseAttrs(raw.attrs, where)
  const style = parseStyle(raw.style, where)
  const box = parseBox(raw.box, where)
  let contrast: number | undefined
  if (raw.contrast !== undefined) contrast = readFiniteNumber(raw.contrast, `${where}.contrast`)

  return {
    seq,
    kind,
    tag: tag.toLowerCase(),
    text,
    label,
    attrs,
    style,
    box,
    ...(contrast !== undefined ? { contrast } : {}),
    nearText,
    path,
  }
}

export function parsePageNodes(raw: unknown, where: string): PageNode[] {
  if (!Array.isArray(raw)) throw new ContractError(`${where} 必须是数组`)
  return raw.map((item, index) => parsePageNode(item, `${where}[${index}]`))
}