/**
 * 表模型：`{header, rows}` 的 JSON 面（源仓 `tableio.read_table` 的判定层部分）。
 *
 * 纪律（与源仓一致）：
 *  - 行号 = 数据行序号，1 起，不含表头；JSON 里没有空行概念；
 *  - 表头按**原样**保留，只在读入时去掉首尾空白；重复列名直接报错；
 *  - 缺失值集合是**单点定义**（`data/anonymity-defaults.json` 的 `missing_tokens`）。
 */

import { ContractError } from '../../core/ledger.js'
import defaults from './data/anonymity-defaults.json' with { type: 'json' }
import { isPlainObject, readInteger, readRawString, readString } from './util.js'

const MISSING_TOKENS = new Set<string>(defaults.missing_tokens)

export function missingSet(): ReadonlySet<string> {
  return MISSING_TOKENS
}

export function isMissing(value: string): boolean {
  return MISSING_TOKENS.has(value)
}

export interface Row {
  readonly rowNumber: number
  readonly values: readonly string[]
}

export class Table {
  readonly header: readonly string[]
  readonly rows: readonly Row[]

  constructor(header: readonly string[], rows: readonly Row[]) {
    this.header = Object.freeze([...header])
    this.rows = Object.freeze([...rows])
  }

  get rowCount(): number {
    return this.rows.length
  }

  columnIndex(name: string): number | null {
    const index = this.header.indexOf(name)
    return index === -1 ? null : index
  }

  hasColumn(name: string): boolean {
    return this.columnIndex(name) !== null
  }

  values(name: string): string[] {
    const index = this.columnIndex(name)
    if (index === null) throw new ContractError(`表中不存在列：${name}`)
    return this.rows.map((row) => row.values[index])
  }
}

export function parseTable(raw: unknown): Table {
  if (!isPlainObject(raw)) throw new ContractError('table 必须是对象')
  for (const key of Object.keys(raw)) {
    if (key !== 'header' && key !== 'rows') throw new ContractError(`table 含未知字段：${key}`)
  }
  if (!Array.isArray(raw.header) || raw.header.length === 0) {
    throw new ContractError('table.header 必须是非空字符串数组')
  }
  const header: string[] = []
  for (const [index, cell] of raw.header.entries()) {
    if (typeof cell !== 'string') throw new ContractError(`table.header[${index}] 必须是字符串`)
    header.push(cell.trim())
  }
  if (header.every((name) => name === '')) throw new ContractError('table.header 为空')
  const duplicates = [...new Set(header.filter((name) => header.filter((other) => other === name).length > 1))]
  if (duplicates.length > 0) throw new ContractError(`table.header 有重复列名：${duplicates.join(', ')}`)
  for (const [index, name] of header.entries()) {
    if (name === '') throw new ContractError(`table.header[${index}] 为空`)
  }

  if (!Array.isArray(raw.rows)) throw new ContractError('table.rows 必须是数组')
  const rows: Row[] = []
  for (const [position, record] of raw.rows.entries()) {
    if (!Array.isArray(record)) throw new ContractError(`table.rows[${position}] 必须是数组`)
    if (record.length !== header.length) {
      throw new ContractError(
        `table.rows[${position}] 宽度与表头不一致：${record.length} 列（表头 ${header.length} 列）`,
      )
    }
    const values = record.map((cell, index) =>
      readRawString(cell, `table.rows[${position}][${index}]`),
    )
    rows.push(Object.freeze({ rowNumber: rows.length + 1, values: Object.freeze(values) }))
  }
  return new Table(header, rows)
}

export function requireRowNumber(raw: unknown, where: string, rowCount: number): number {
  const row = readInteger(raw, where, 1)
  if (row > rowCount) throw new ContractError(`${where} 超出数据行范围（1..${rowCount}）`)
  return row
}