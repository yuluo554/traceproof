/**
 * hazard-triage · 输入解析的共用小工具。
 *
 * 器官只接收已归一化的 JSON 面；坏形状一律 `ContractError`（唯一入口映射退出码 3）。
 * 这里不读文件、不读时钟、不读环境变量。
 */

import { ContractError } from '../../core/ledger.js'

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function readString(value: unknown, where: string): string {
  if (typeof value !== 'string') throw new ContractError(`${where} 必须是字符串`)
  return value
}

export function readNonEmptyString(value: unknown, where: string): string {
  const text = readString(value, where).trim()
  if (!text) throw new ContractError(`${where} 不能为空`)
  return text
}

export function readInteger(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ContractError(`${where} 必须是整数`)
  }
  return value
}

export function readFiniteNumber(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ContractError(`${where} 必须是有限数`)
  }
  return value
}

export function readStringArray(value: unknown, where: string): string[] {
  if (!Array.isArray(value)) throw new ContractError(`${where} 必须是字符串数组`)
  return value.map((item, index) => readString(item, `${where}[${index}]`))
}

export function readNumberArray(value: unknown, where: string): number[] {
  if (!Array.isArray(value)) throw new ContractError(`${where} 必须是数字数组`)
  return value.map((item, index) => readFiniteNumber(item, `${where}[${index}]`))
}

export function optionalString(raw: Record<string, unknown>, name: string, where: string): string | null {
  if (raw[name] === undefined) return null
  return readString(raw[name], `${where}.${name}`)
}

export function optionalBoolean(raw: Record<string, unknown>, name: string, where: string): boolean | null {
  if (raw[name] === undefined) return null
  if (typeof raw[name] !== 'boolean') throw new ContractError(`${where}.${name} 必须是布尔值`)
  return raw[name]
}

export function optionalInteger(raw: Record<string, unknown>, name: string, where: string): number | null {
  if (raw[name] === undefined) return null
  return readInteger(raw[name], `${where}.${name}`)
}

export function optionalFiniteNumber(raw: Record<string, unknown>, name: string, where: string): number | null {
  if (raw[name] === undefined) return null
  return readFiniteNumber(raw[name], `${where}.${name}`)
}

export function optionalStringArray(raw: Record<string, unknown>, name: string, where: string): string[] | null {
  if (raw[name] === undefined) return null
  return readStringArray(raw[name], `${where}.${name}`)
}

export function assertKnownKeys(raw: Record<string, unknown>, allowed: readonly string[], where: string): void {
  const set = new Set(allowed)
  for (const key of Object.keys(raw)) {
    if (!set.has(key)) throw new ContractError(`${where} 含未知字段：${key}`)
  }
}

export function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort()
}

/** 递归深比较（对象键顺序无关）。 */
export function jsonEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) return false
    if (left.length !== right.length) return false
    return left.every((item, index) => jsonEqual(item, right[index]))
  }
  if (isPlainObject(left) || isPlainObject(right)) {
    if (!isPlainObject(left) || !isPlainObject(right)) return false
    const leftKeys = Object.keys(left).sort()
    const rightKeys = Object.keys(right).sort()
    if (leftKeys.length !== rightKeys.length) return false
    if (!leftKeys.every((key, index) => key === rightKeys[index])) return false
    return leftKeys.every((key) => jsonEqual(left[key], right[key]))
  }
  return false
}

/** 基名（同时把 `\` 与 `/` 当分隔符；POSIX 的 basename 只认 `/`）。 */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter((part) => part.length > 0)
  return parts.length > 0 ? parts[parts.length - 1] : path
}

/** Python `round(x, 4)` 的常用近似（非半偶舍入；分值不落在 .00005 边界时一致）。 */
export function round4(value: number): number {
  return Math.round((value + Number.EPSILON) * 10000) / 10000
}