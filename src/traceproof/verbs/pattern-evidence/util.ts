/**
 * pattern-evidence 的输入读取小工具（只做 JSON 面校验，不读文件/环境/时钟）。
 *
 * 与 `pipeline-run/util.ts` 同风格：坏输入直接 `ContractError`，让唯一入口映射退出码。
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
  return value.map((item, index) => readString(item, `${where}[${index}]`))
}

export function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort()
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