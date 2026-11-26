/**
 * archive-extraction · 字节层小工具（迁移自源仓 `findings.display_name` 与判定模块共用的
 * 字节/文本换算）。
 *
 * 纪律：这里只做**确定性纯换算**——不解码归档、不读文件、不看时钟。名字字节的解释口径
 * 与源仓一致：
 *  - 判定内部用 `surrogateescape` 等价形（每个非法字节 → U+DC80–U+DCFF 的孤立代理项），
 *    逐字节可逆；
 *  - 展示形用 `backslashreplace`（非法字节显示为 `\\xNN`），JSON 安全且确定；
 *  - 精确字节一律保留在 `*_hex` 字段里，展示形不承担可逆性。
 */

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function hexToBytes(hex: string, where: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${where} 必须是偶数长度的十六进制字符串`)
  }
  const out = new Uint8Array(hex.length / 2)
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return out
}

export function bytesToHex(raw: Uint8Array): string {
  let out = ''
  for (const byte of raw) out += byte.toString(16).padStart(2, '0')
  return out
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false
  }
  return true
}

/** UTF-8 严格解码：不完整 / 过长 / 代理区 / 超范围一律 `null`（对应 Python `decode('utf-8')` 抛错）。 */
export function decodeStrictUtf8(raw: Uint8Array): string | null {
  let index = 0
  const parts: string[] = []
  while (index < raw.length) {
    const first = raw[index]
    if (first < 0x80) {
      parts.push(String.fromCharCode(first))
      index += 1
      continue
    }
    let need = 0
    let codepoint = 0
    if (first >= 0xc2 && first <= 0xdf) {
      need = 1
      codepoint = first & 0x1f
    } else if (first >= 0xe0 && first <= 0xef) {
      need = 2
      codepoint = first & 0x0f
    } else if (first >= 0xf0 && first <= 0xf4) {
      need = 3
      codepoint = first & 0x07
    } else {
      return null
    }
    if (index + need >= raw.length) return null
    for (let offset = 1; offset <= need; offset += 1) {
      const byte = raw[index + offset]
      if (byte === undefined || (byte & 0xc0) !== 0x80) return null
      codepoint = (codepoint << 6) | (byte & 0x3f)
    }
    // 过长编码 / 代理区 / 超 U+10FFFF
    if (need === 2 && (codepoint < 0x800 || (codepoint >= 0xd800 && codepoint <= 0xdfff))) return null
    if (need === 3 && codepoint < 0x10000) return null
    if (codepoint > 0x10ffff) return null
    parts.push(String.fromCodePoint(codepoint))
    index += need + 1
  }
  return parts.join('')
}

/** 一笔合法 UTF-8 序列的长度与码点；非法返回 `null`。 */
function utf8Sequence(raw: Uint8Array, index: number): { length: number; codepoint: number } | null {
  const first = raw[index]
  if (first < 0x80) return { length: 1, codepoint: first }
  let need = 0
  let codepoint = 0
  if (first >= 0xc2 && first <= 0xdf) {
    need = 1
    codepoint = first & 0x1f
  } else if (first >= 0xe0 && first <= 0xef) {
    need = 2
    codepoint = first & 0x0f
  } else if (first >= 0xf0 && first <= 0xf4) {
    need = 3
    codepoint = first & 0x07
  } else {
    return null
  }
  for (let offset = 1; offset <= need; offset += 1) {
    const byte = raw[index + offset]
    if (byte === undefined || (byte & 0xc0) !== 0x80) return null
    codepoint = (codepoint << 6) | (byte & 0x3f)
  }
  if (need === 2 && (codepoint < 0x800 || (codepoint >= 0xd800 && codepoint <= 0xdfff))) return null
  if (need === 3 && codepoint < 0x10000) return null
  if (codepoint > 0x10ffff) return null
  return { length: need + 1, codepoint }
}

/** Python `bytes.decode('utf-8', 'surrogateescape')` 的等价形（非法字节逐个 → 孤立代理项）。 */
export function decodeSurrogateEscape(raw: Uint8Array): string {
  let index = 0
  const parts: string[] = []
  while (index < raw.length) {
    const sequence = utf8Sequence(raw, index)
    if (sequence === null) {
      parts.push(String.fromCharCode(0xdc00 + raw[index]))
      index += 1
    } else {
      parts.push(String.fromCodePoint(sequence.codepoint))
      index += sequence.length
    }
  }
  return parts.join('')
}

/** Python `bytes.decode('utf-8', 'backslashreplace')` 的等价形（展示形）。 */
export function displayName(raw: Uint8Array | null): string | null {
  if (raw === null) return null
  let index = 0
  const parts: string[] = []
  while (index < raw.length) {
    const sequence = utf8Sequence(raw, index)
    if (sequence === null) {
      parts.push(`\\x${raw[index].toString(16).padStart(2, '0')}`)
      index += 1
    } else {
      parts.push(String.fromCodePoint(sequence.codepoint))
      index += sequence.length
    }
  }
  return parts.join('')
}

/** UTF-16 码元数（Windows 口径；JS 字符串的 `length` 就是码元数）。 */
export function utf16Units(text: string): number {
  return text.length
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let index = 0; index < 256; index += 1) {
    let value = index
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    }
    table[index] = value >>> 0
  }
  return table
})()

/** CRC32（IEEE 802.3，与 Python `zlib.crc32` 同值）。 */
export function crc32(raw: Uint8Array): number {
  let crc = 0xffffffff
  for (const byte of raw) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

/** 确定性序列化：对象键按字典序，数组保持顺序（用于排序兜底与证据比对）。 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(',')}}`
}

export function jsonEqual(left: unknown, right: unknown): boolean {
  return stableStringify(left) === stableStringify(right)
}

export function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

export function compareNumberArrays(left: readonly number[], right: readonly number[]): number {
  const size = Math.min(left.length, right.length)
  for (let index = 0; index < size; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1
  }
  return left.length === right.length ? 0 : left.length < right.length ? -1 : 1
}

export function readString(value: unknown, where: string): string {
  if (typeof value !== 'string') throw new Error(`${where} 必须是字符串`)
  return value
}

export function readInteger(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new Error(`${where} 必须是整数`)
  }
  return value
}

export function readBoolean(value: unknown, where: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${where} 必须是布尔值`)
  return value
}