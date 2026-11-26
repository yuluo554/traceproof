/**
 * 列角色声明（源仓 `declaration.py` 的判定层部分）。
 *
 * 角色枚举是闭合集合：qi / sensitive / direct-identifier / date-precision。
 * **未声明即不参与**——不做「猜它可能是 QI」的自动纳入。
 */

import { ContractError } from '../../core/ledger.js'
import defaults from './data/anonymity-defaults.json' with { type: 'json' }
import { isPlainObject } from './util.js'

export const ROLES: readonly string[] = defaults.roles
export const PRECISIONS: readonly string[] = defaults.precisions

type Role = 'qi' | 'sensitive' | 'direct-identifier' | 'date-precision'

interface ColumnSpec {
  readonly role: Role
  readonly precision: string | null
}

const COLUMN_KEYS: Readonly<Record<Role, readonly string[]>> = {
  qi: ['role'],
  sensitive: ['role'],
  'direct-identifier': ['role'],
  'date-precision': ['role', 'precision'],
}

export class Declaration {
  private readonly specs: ReadonlyMap<string, ColumnSpec>
  readonly tableColumns: readonly string[]

  constructor(specs: ReadonlyMap<string, ColumnSpec>, tableColumns: readonly string[]) {
    this.specs = specs
    this.tableColumns = Object.freeze([...tableColumns])
  }

  /** 声明为 qi 的列，按输入 `columns` 对象的书写顺序（等价类键序）。 */
  qiColumns(): string[] {
    return [...this.specs.entries()].filter(([, spec]) => spec.role === 'qi').map(([name]) => name)
  }

  sensitiveColumns(): string[] {
    return [...this.specs.entries()]
      .filter(([, spec]) => spec.role === 'sensitive')
      .map(([name]) => name)
  }

  directIdentifiers(): string[] {
    return [...this.specs.entries()]
      .filter(([, spec]) => spec.role === 'direct-identifier')
      .map(([name]) => name)
  }

  unparticipating(): Array<{ column: string; reason: string }> {
    const out: Array<{ column: string; reason: string }> = []
    for (const name of this.tableColumns) {
      if (!this.specs.has(name)) out.push({ column: name, reason: 'undeclared' })
    }
    for (const [name, spec] of this.specs.entries()) {
      if (spec.role === 'direct-identifier') out.push({ column: name, reason: 'direct-identifier' })
      if (spec.role === 'date-precision') out.push({ column: name, reason: 'date-precision-only' })
    }
    return out
  }
}

export function parseDeclaration(raw: unknown, tableColumns: readonly string[]): Declaration {
  if (!isPlainObject(raw)) throw new ContractError('declaration 必须是对象')
  for (const key of Object.keys(raw)) {
    if (key !== 'columns') throw new ContractError(`declaration 含未知顶层键：${key}`)
  }
  const columns = raw.columns
  if (!isPlainObject(columns) || Object.keys(columns).length === 0) {
    throw new ContractError('declaration.columns 必须是非空对象')
  }

  const missing = Object.keys(columns).filter((name) => !tableColumns.includes(name)).sort()
  if (missing.length > 0) {
    throw new ContractError(`declaration 声明了表中不存在的列：${missing.join(', ')}`)
  }

  const specs = new Map<string, ColumnSpec>()
  for (const [name, rawSpec] of Object.entries(columns)) {
    if (typeof name !== 'string' || name.trim() === '') {
      throw new ContractError('declaration.columns 的列名必须是非空字符串')
    }
    if (!isPlainObject(rawSpec)) throw new ContractError(`declaration.columns[${name}] 必须是对象`)
    const role = rawSpec.role
    if (typeof role !== 'string' || !ROLES.includes(role)) {
      throw new ContractError(
        `declaration.columns[${name}] 的角色不在枚举内：<${String(role)}>（可选 ${ROLES.join(' / ')}）`,
      )
    }
    const roleName = role as Role
    const allowed = COLUMN_KEYS[roleName]
    for (const key of Object.keys(rawSpec)) {
      if (!allowed.includes(key)) {
        throw new ContractError(`declaration.columns[${name}] 在该角色下不允许键：${key}`)
      }
    }
    let precision: string | null = null
    if (roleName === 'date-precision') {
      const value = rawSpec.precision
      if (typeof value !== 'string' || !PRECISIONS.includes(value)) {
        throw new ContractError(
          `declaration.columns[${name}] 的 date-precision 必须声明 precision（${PRECISIONS.join(' / ')}）`,
        )
      }
      precision = value
    }
    specs.set(name, Object.freeze({ role: roleName, precision }))
  }
  return new Declaration(specs, tableColumns)
}