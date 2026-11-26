/**
 * 六位定点，四舍六入五成双（源仓 `canonical.round6` 的同口径实现）。
 *
 * 源仓用 `Decimal(str(float(x))).quantize(0.000001, ROUND_HALF_EVEN)`：
 * 先用 Python 的最短十进制表示，再按十进位做半偶舍入。这里复刻同一条路径
 * （JS `Number.toString()` 也是最短往返表示），避免浮点尾差改变最后一位。
 */

const SIX = 6

function expandExponent(text: string): string {
  const match = text.match(/^(-?)(\d+)(?:\.(\d+))?e([+-]?\d+)$/i)
  if (match === null) return text
  const sign = match[1]
  const integer = match[2]
  const fraction = match[3] ?? ''
  const exponent = Number(match[4])
  const digits = integer + fraction
  const point = integer.length + exponent
  if (point <= 0) {
    return `${sign}0.${'0'.repeat(-point)}${digits}`
  }
  if (point >= digits.length) {
    return `${sign}${digits}${'0'.repeat(point - digits.length)}`
  }
  return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`
}

/** 把非负数的最短十进制文本按 6 位半偶舍入，返回整数化的百万分位。 */
function quantizeMillions(text: string): { units: number; negative: boolean } {
  let body = text
  let negative = false
  if (body.startsWith('-')) {
    negative = true
    body = body.slice(1)
  }
  body = expandExponent(body)
  const [integerPart, fractionPart = ''] = body.split('.')
  const padded = (fractionPart + '0'.repeat(SIX + 1)).slice(0, SIX + 1)
  const kept = padded.slice(0, SIX)
  const firstDiscarded = Number(padded[SIX] ?? '0')
  const restNonZero = /[1-9]/.test(padded.slice(SIX + 1))
  let units = Number(integerPart) * 1_000_000 + Number(kept || '0')
  if (firstDiscarded > 5 || (firstDiscarded === 5 && restNonZero)) {
    units += 1
  } else if (firstDiscarded === 5 && !restNonZero) {
    if (units % 2 !== 0) units += 1
  }
  return { units, negative }
}

export function round6(value: number | null): number | null {
  if (value === null) return null
  if (!Number.isFinite(value)) throw new RangeError('round6 只接受有限数字')
  const { units, negative } = quantizeMillions(String(value))
  const magnitude = units / 1_000_000
  const result = negative ? -magnitude : magnitude
  return result === 0 ? 0 : result
}