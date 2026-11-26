/**
 * anonymity-collapse 的 JSON 面读取小工具。
 *
 * 器官只接收已解析对象：不读文件、不读环境变量、不读时钟、不打印。
 * 坏输入一律 `ContractError`，由唯一入口映射退出码 3。
 */

import { ContractError } from '../../core/ledger.js'

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function hasOwn(source: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(source, key)
}

export function readString(value: unknown, where: string, allowEmpty = false): string {
  if (typeof value !== 'string') throw new ContractError(`${where} 必须是字符串`)
  const text = value.trim()
  if (!allowEmpty && text.length === 0) throw new ContractError(`${where} 不能为空`)
  return text
}

export function readRawString(value: unknown, where: string): string {
  if (typeof value !== 'string') throw new ContractError(`${where} 必须是字符串`)
  return value
}

export function readInteger(value: unknown, where: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < minimum) {
    throw new ContractError(`${where} 必须是 >= ${minimum} 的整数`)
  }
  return value
}

export function readFiniteNumber(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ContractError(`${where} 必须是有限数字`)
  }
  return value
}

export function readStringArray(value: unknown, where: string, allowEmpty = false): string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new ContractError(`${where} 必须是${allowEmpty ? '' : ' 非空'}字符串数组`)
  }
  return value.map((item, index) => readString(item, `${where}[${index}]`))
}

export function readIntegerArray(value: unknown, where: string, minimum = 0): number[] {
  if (!Array.isArray(value)) throw new ContractError(`${where} 必须是整数数组`)
  return value.map((item, index) => readInteger(item, `${where}[${index}]`, minimum))
}

export function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean'
}

export function readBoolean(value: unknown, where: string): boolean {
  if (!isBoolean(value)) throw new ContractError(`${where} 必须是布尔值`)
  return value
}

/** 按 Unicode 码位比较（与 Python `str` 排序一致，不受 UTF-16 代理对影响）。 */
export function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left)
  const b = Array.from(right)
  const length = Math.min(a.length, b.length)
  for (let index = 0; index < length; index += 1) {
    const x = a[index].codePointAt(0) as number
    const y = b[index].codePointAt(0) as number
    if (x !== y) return x - y
  }
  return a.length - b.length
}

/** JSON 面深比较（对象键序无关）。 */
export function jsonEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false
    return left.every((item, index) => jsonEqual(item, right[index]))
  }
  if (isPlainObject(left) || isPlainObject(right)) {
    if (!isPlainObject(left) || !isPlainObject(right)) return false
    const leftKeys = Object.keys(left).sort(compareCodePoints)
    const rightKeys = Object.keys(right).sort(compareCodePoints)
    if (!jsonEqual(leftKeys, rightKeys)) return false
    return leftKeys.every((key) => jsonEqual(left[key], right[key]))
  }
  return false
}

/** 数值比较的稳定排序：长度升序，同长度按码位序（Python 的 `(len, tuple)`）。 */
export function compareCombos(left: readonly string[], right: readonly string[]): number {
  if (left.length !== right.length) return left.length - right.length
  for (let index = 0; index < left.length; index += 1) {
    const order = compareCodePoints(left[index], right[index])
    if (order !== 0) return order
  }
  return 0
}