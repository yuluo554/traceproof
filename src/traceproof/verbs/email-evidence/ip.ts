/**
 * IP 字面量解析 / 比较（SPF 求值需要的全部）。
 *
 * 只做 RFC 7208 用得到的三件事：
 * 1. 解析 IPv4 / IPv6（RFC 4291 文本形态，含 `::` 压缩）；
 * 2. IPv4-mapped IPv6 折回 IPv4（RFC 7208 §5/9/2：这类连接按 IPv4 处理）；
 * 3. 连接 IP 是否落在某个地址的 `/prefix` 内（§5.3/§5.4）。
 *
 * 为什么不用 `node:net`：`net.isIP` 判形态够用，但拿不到字节；SPF 的 CIDR 比较
 * 与 `%{i}` 的十六进制展开都要求字节级视图。
 */

export interface IpAddress {
  readonly version: 4 | 6
  /** IPv4 = 4 字节；IPv6 = 16 字节。 */
  readonly bytes: readonly number[]
}

function parseIPv4(text: string): IpAddress | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  const bytes: number[] = []
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null
    const value = Number(part)
    if (value > 255) return null
    bytes.push(value)
  }
  return { version: 4, bytes }
}

function parseIPv6(text: string): IpAddress | null {
  const source = text
  if (source.includes('%')) return null // 作用域标识不是地址的一部分
  const halves = source.split('::')
  if (halves.length > 2) return null
  const head = halves[0] === '' ? [] : halves[0].split(':')
  const tail = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : []

  const toGroups = (parts: string[]): number[] | null => {
    const groups: number[] = []
    for (const [index, part] of parts.entries()) {
      if (part.includes('.')) {
        // 末尾内嵌 IPv4（如 ::ffff:192.0.2.1）
        if (index !== parts.length - 1) return null
        const v4 = parseIPv4(part)
        if (v4 === null) return null
        groups.push((v4.bytes[0] << 8) | v4.bytes[1])
        groups.push((v4.bytes[2] << 8) | v4.bytes[3])
        continue
      }
      if (!/^[0-9a-f]{1,4}$/i.test(part)) return null
      groups.push(parseInt(part, 16))
    }
    return groups
  }

  const headGroups = toGroups(head)
  const tailGroups = toGroups(tail)
  if (headGroups === null || tailGroups === null) return null

  let groups: number[]
  if (halves.length === 2) {
    const zeros = 8 - headGroups.length - tailGroups.length
    if (zeros < 0) return null
    groups = [...headGroups, ...new Array(zeros).fill(0), ...tailGroups]
  } else {
    if (headGroups.length !== 8) return null
    groups = headGroups
  }
  if (groups.length !== 8) return null

  const bytes: number[] = []
  for (const group of groups) {
    bytes.push((group >> 8) & 0xff, group & 0xff)
  }
  return { version: 6, bytes }
}

export function parseIp(text: string): IpAddress | null {
  const value = String(text).trim()
  if (value.includes(':')) return parseIPv6(value)
  return parseIPv4(value)
}

/** IPv4-mapped IPv6 → 折回 IPv4（`::ffff:a.b.c.d`）。 */
export function unmapIp(address: IpAddress): IpAddress {
  if (address.version !== 6) return address
  const b = address.bytes
  for (let index = 0; index < 10; index += 1) {
    if (b[index] !== 0) return address
  }
  if (b[10] !== 0xff || b[11] !== 0xff) return address
  return { version: 4, bytes: b.slice(12) }
}

export function ipv4ToString(bytes: readonly number[]): string {
  return bytes.join('.')
}

/** RFC 5952 压缩形态（与 Python `str(ipaddress.IPv6Address)` 对齐：最长零串、左侧优先）。 */
export function ipv6ToString(bytes: readonly number[]): string {
  const groups: number[] = []
  for (let index = 0; index < 16; index += 2) {
    groups.push((bytes[index] << 8) | bytes[index + 1])
  }
  let bestStart = -1
  let bestLength = 0
  let start = -1
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === 0) {
      if (start < 0) start = index
      continue
    }
    if (start >= 0) {
      const length = index - start
      if (length > bestLength) {
        bestStart = start
        bestLength = length
      }
      start = -1
    }
  }
  if (bestLength < 2) bestStart = -1
  const hex = groups.map((group) => group.toString(16))
  if (bestStart < 0) return hex.join(':')
  const before = hex.slice(0, bestStart).join(':')
  const after = hex.slice(bestStart + bestLength).join(':')
  return `${before}::${after}`
}

/** `%{i}` 的 IPv6 形态（RFC 7208 §7.3：十六进制半字节用点分隔）。 */
export function ipv6DottedNibbles(bytes: readonly number[]): string {
  const hex = bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('')
  return hex.toUpperCase().split('').join('.')
}

export function ipAddressText(address: IpAddress): string {
  return address.version === 4 ? ipv4ToString(address.bytes) : ipv6ToString(address.bytes)
}

/** PTR 查询名（`4.3.2.1.in-addr.arpa` / `....ip6.arpa`）。 */
export function reverseLookupName(address: IpAddress): string {
  if (address.version === 4) {
    return `${[...address.bytes].reverse().join('.')}.in-addr.arpa`
  }
  const nibbles = ipv6DottedNibbles(address.bytes).toLowerCase().split('.')
  return `${nibbles.reverse().join('.')}.ip6.arpa`
}

function splitCidr(text: string): [string, number | null] {
  const match = text.match(/^(.*)\/(0|[1-9]\d*)$/)
  if (match === null) return [text, null]
  return [match[1], Number(match[2])]
}

/**
 * 连接 IP 是否落在任一地址的 `/prefix` 内。
 *
 * `addresses` 里的条目可以是裸地址，也可以是 `a.b.c.d/n`（RFC 7208 §5.3 允许 A 记录
 * 带前缀）。版本不同直接跳过（上游 `a-cidr4-0-ip6` 锁这条）。
 */
export function cidrMatch(
  addresses: readonly string[],
  prefix: number,
  client: IpAddress,
): boolean {
  for (const text of addresses) {
    const [addressPart] = splitCidr(text)
    const network = parseIp(addressPart)
    if (network === null) {
      throw new Error(`DNS 答复里的地址不合法：<${text}>`)
    }
    if (network.version !== client.version) continue
    const maxPrefix = network.version === 4 ? 32 : 128
    if (prefix > maxPrefix) continue
    const fullBytes = Math.floor(prefix / 8)
    const leftover = prefix % 8
    let matched = true
    for (let index = 0; index < fullBytes; index += 1) {
      if (network.bytes[index] !== client.bytes[index]) {
        matched = false
        break
      }
    }
    if (!matched) continue
    if (leftover > 0) {
      const mask = (0xff << (8 - leftover)) & 0xff
      if ((network.bytes[fullBytes] & mask) !== (client.bytes[fullBytes] & mask)) continue
    }
    return true
  }
  return false
}