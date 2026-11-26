/**
 * tool-ops-attribution 的输入读取小工具（只做 JSON 面校验，不读文件 / 环境 / 时钟）。
 *
 * 与 `pattern-evidence/util.ts` 同风格：坏输入直接 `ContractError`，让唯一入口映射退出码。
 */

import { ContractError } from '../../core/ledger.js'

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function readString(value: unknown, where: string, allowEmpty = false): string {
  if (typeof value !== 'string') throw new ContractError(`${where} 必须是字符串`)
  const text = value.trim()
  if (!allowEmpty && text.length === 0) throw new ContractError(`${where} 不能为空`)
  return text
}

/** 保留原始内容（不 trim）：事件流里的 error_text / timestamp 逐字参与匹配。 */
export function readExactString(value: unknown, where: string, allowEmpty = false): string {
  if (typeof value !== 'string') throw new ContractError(`${where} 必须是字符串`)
  if (!allowEmpty && value.trim().length === 0) throw new ContractError(`${where} 不能为空`)
  return value
}

export function readFiniteNumber(value: unknown, where: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum) {
    throw new ContractError(`${where} 必须是 >= ${minimum} 的有限数字`)
  }
  return value
}

export function readInteger(value: unknown, where: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    throw new ContractError(`${where} 必须是 >= ${minimum} 的整数`)
  }
  return value
}

export function readStringArray(value: unknown, where: string, allowEmpty = false): string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new ContractError(`${where} 必须是${allowEmpty ? '' : '非空'}字符串数组`)
  }
  return value.map((item, index) => readString(item, `${where}[${index}]`, true))
}

/** 稳定字符串比较（与 Python 对 ASCII 键的字典序一致；不用 locale）。 */
export function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

/** JSON 面深比较（对象键序无关；只用于输入里的小结构）。 */
export function jsonEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false
    return left.every((item, index) => jsonEqual(item, right[index]))
  }
  if (isPlainObject(left) || isPlainObject(right)) {
    if (!isPlainObject(left) || !isPlainObject(right)) return false
    const leftKeys = Object.keys(left).sort()
    const rightKeys = Object.keys(right).sort()
    if (!jsonEqual(leftKeys, rightKeys)) return false
    return leftKeys.every((key) => jsonEqual(left[key], right[key]))
  }
  return false
}

/**
 * 比率/均值舍入：与 Python `round(value, precision)` 同为**半偶舍入**。
 *
 * 源仓的 `round(float(numerator) / float(denominator), precision)` 落在六个小数位；
 * 这里按同一语义实现（恰好 5 时取偶数），极端二进制浮点边界才可能有末位差。
 */
export function roundTo(value: number, precision: number): number {
  const factor = 10 ** precision
  const scaled = value * factor
  const floor = Math.floor(scaled)
  const diff = scaled - floor
  if (diff > 0.5) return (floor + 1) / factor
  if (diff < 0.5) return floor / factor
  return (floor % 2 === 0 ? floor : floor + 1) / factor
}