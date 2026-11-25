/**
 * Python 符号区间与「两个改动区间在符号上的关系」。
 *
 * 移植自旧仓 `detect.py` 的符号级判据（`symbol_spans` /
 * `symbols_touching` / `pair_symbol_hit`）。旧仓用 `ast`；器官不能起子进程，
 * 这里用**缩进扫描**求 `def` / `async def` / `class` 的区间——对基准矩阵里的
 * 纯函数/嵌套函数/类方法给出与 `ast` 相同的 `(限定名, 起, 止)`。
 *
 * 口径（与旧仓一致）：
 * - 限定名用 `.` 连接（嵌套 `A.B.f`），同名不同作用域是不同键；
 * - 区间是 1-based 闭区间；
 * - 「同一符号」= 两侧**触及**符号集合有交集；报交集里**最内层**的那些；
 * - 「相邻」= 各自落在某个符号**内部**，且区间间距 ≤ 容差；报各自最内层符号；
 * - 其余不升格（维持文件级）。
 */

export type Span = [number, number]
export interface SymbolSpan {
  readonly name: string
  readonly start: number
  readonly end: number
}

const DEF = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)/
const CLASS = /^(\s*)class\s+([A-Za-z_]\w*)/

function indentOf(line: string): number {
  let count = 0
  for (const char of line) {
    if (char === ' ') count += 1
    else if (char === '\t') count += 4
    else break
  }
  return count
}

/** 取 `def` / `async def` / `class` 的 `(限定名, 起, 止)`，按 `(起, 止, 名)` 排序。 */
export function symbolSpans(source: string): SymbolSpan[] {
  const lines = source.split(/\r?\n/)
  const spans: SymbolSpan[] = []
  const stack: Array<{ indent: number; name: string }> = []

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const def = line.match(DEF)
    const cls = def ? null : line.match(CLASS)
    const match = def ?? cls
    if (match === null) continue
    const indent = indentOf(line)
    const name = def ? def[2] : (cls as RegExpMatchArray)[2]
    while (stack.length > 0 && stack[stack.length - 1].indent >= indent) stack.pop()
    const qualified = [...stack.map((item) => item.name), name].join('.')

    let last = index
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const text = lines[cursor]
      const body = text.trim()
      if (!body || body.startsWith('#')) continue // ast 的 end_lineno 不含空行与注释
      if (indentOf(text) <= indent) break
      last = cursor
    }
    spans.push({ name: qualified, start: index + 1, end: last + 1 })
    stack.push({ indent, name })
  }

  spans.sort((a, b) => (a.start === b.start ? (a.end === b.end ? a.name.localeCompare(b.name) : a.end - b.end) : a.start - b.start))
  return spans
}

/** 两个 1-based 闭区间的**行间距**：不重叠时中间隔了几行，重叠时为负。 */
export function rangeGap(left: Span, right: Span): number {
  return Math.max(left[0] - right[1] - 1, right[0] - left[1] - 1)
}

export function overlaps(left: Span, right: Span): boolean {
  return !(left[1] < right[0] || left[0] > right[1])
}

/** 与区间**有交集**的符号（有序）。部分重叠也算「动了这个符号」。 */
export function symbolsTouching(spans: readonly SymbolSpan[], span: Span): string[] {
  return spans.filter((item) => overlaps([item.start, item.end], span)).map((item) => item.name)
}

function symbolsContaining(spans: readonly SymbolSpan[], span: Span): SymbolSpan[] {
  return spans.filter((item) => item.start <= span[0] && span[1] <= item.end)
}

function innermost(spans: readonly SymbolSpan[], span: Span): string | null {
  const containing = symbolsContaining(spans, span)
  if (containing.length === 0) return null
  const best = [...containing].sort((a, b) => (a.end - a.start === b.end - b.start ? a.start - b.start : a.end - a.start - (b.end - b.start)))[0]
  return best.name
}

function minimalSymbols(names: readonly string[], spans: readonly SymbolSpan[]): string[] {
  const index = new Map(spans.map((item) => [item.name, item]))
  const kept: string[] = []
  for (const name of names) {
    const inner = index.get(name)
    let contained = false
    for (const other of names) {
      if (other === name) continue
      const span = index.get(other)
      if (inner === undefined || span === undefined) continue
      if (span.start >= inner.start && span.end <= inner.end) {
        contained = true
        break
      }
    }
    if (!contained) kept.push(name)
  }
  return kept
}

export interface SymbolHit {
  readonly kind: 'same' | 'adjacent' | ''
  readonly symbols: string[]
}

/** 判定两个改动区间在符号上的关系（与旧仓 `pair_symbol_hit` 同语义）。 */
export function pairSymbolHit(
  spans: readonly SymbolSpan[],
  left: Span,
  right: Span,
  tolerance: number,
): SymbolHit {
  const touchingLeft = symbolsTouching(spans, left)
  const touchingRight = symbolsTouching(spans, right)
  const shared = touchingLeft.filter((name) => touchingRight.includes(name))
  if (shared.length > 0) return { kind: 'same', symbols: minimalSymbols(shared, spans) }
  const innerLeft = innermost(spans, left)
  const innerRight = innermost(spans, right)
  if (innerLeft === null || innerRight === null) return { kind: '', symbols: [] }
  if (rangeGap(left, right) <= tolerance) {
    return { kind: 'adjacent', symbols: [...new Set([innerLeft, innerRight])] }
  }
  return { kind: '', symbols: [] }
}

/** 两侧各取最内层符号（给「不同符号」判定用）。 */
export function innermostPair(spans: readonly SymbolSpan[], left: Span, right: Span): [string | null, string | null] {
  return [innermost(spans, left), innermost(spans, right)]
}