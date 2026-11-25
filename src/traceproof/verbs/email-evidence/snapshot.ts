/**
 * DNS 快照视图（`snap.json`）：**唯一**的 DNS 取值来源。
 *
 * 移植自旧仓 `snapshot.py`，保留两条关键语义：
 *
 * 1. `queries` 是**有序列表**：同一 `(qname, qtype)` 可以出现多次，`resolve()` 取
 *    **列表顺序第一次命中**，并把下标带出来（"查了两次结果不同"必须可见）。
 * 2. **"没查过" ≠ "查过但没有"**：`found=false` 是数据缺口（→ `DataGap`），
 *    `found=true && rcode=NXDOMAIN` 才是"问过了，不存在"。
 *
 * 本模块不读文件：快照对象由调用方提供（CLI 负责文件 I/O）。
 */

export const SNAPSHOT_SCHEMA_VERSION = 1
export const RCODE_NOERROR = 'NOERROR'

/** 数据缺口：快照里没有这条查询。**不是**"没有记录"。 */
export class DataGap extends Error {
  readonly qname: string
  readonly qtype: string

  constructor(qname: string, qtype: string) {
    super(`快照里没有 ${qname}/${qtype} 这条查询（数据缺口，不等同于「没有记录」）`)
    this.name = 'DataGap'
    this.qname = qname
    this.qtype = qtype
  }
}

/** DNS 层临时故障 → temperror。 */
export class TempError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TempError'
  }
}

/** 记录本身有问题 → permerror。 */
export class PermError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PermError'
  }
}

/** 数据不足或规则本身是灰区 → undecidable（项目语义，不折叠成 fail）。 */
export class UndecidableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UndecidableError'
  }
}

export interface SnapshotQuery {
  readonly qname: string
  readonly qtype: string
  readonly rcode: string
  readonly answer: readonly string[]
  readonly ttl: number
}

export interface SnapshotData {
  readonly schema_version: number
  readonly fetched_at: string
  readonly resolver: string
  readonly psl_version: string
  readonly psl_date: string
  readonly queries: readonly SnapshotQuery[]
}

export interface Resolved {
  readonly found: boolean
  readonly index: number | null
  readonly rcode: string | null
  readonly answer: readonly string[]
  readonly ttl: number | null
  readonly qname: string
  readonly qtype: string
}

/** 快照结构不合法（schema / 必需字段 / 查询条目）。 */
export class SnapshotProblem extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SnapshotProblem'
  }
}

function normName(name: string): string {
  return String(name).trim().replace(/\.+$/, '').toLowerCase()
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireNonEmptyString(data: Record<string, unknown>, field: string): string {
  const value = data[field]
  if (typeof value !== 'string' || !value.trim()) {
    throw new SnapshotProblem(`快照字段 ${field} 必须是非空字符串`)
  }
  return value
}

export class Snapshot {
  readonly data: SnapshotData
  private readonly index = new Map<string, number[]>()

  constructor(data: SnapshotData) {
    this.data = data
    data.queries.forEach((entry, position) => {
      const key = `${normName(entry.qname)}\u0000${entry.qtype.toUpperCase()}`
      const bucket = this.index.get(key)
      if (bucket === undefined) this.index.set(key, [position])
      else bucket.push(position)
    })
  }

  static fromObject(raw: unknown): Snapshot {
    if (!isPlainObject(raw)) {
      throw new SnapshotProblem('快照顶层必须是对象')
    }
    const version = raw.schema_version
    if (version === undefined) {
      throw new SnapshotProblem(`快照缺 schema_version（本工具支持 ${SNAPSHOT_SCHEMA_VERSION}）`)
    }
    if (typeof version !== 'number' || !Number.isInteger(version)) {
      throw new SnapshotProblem(`schema_version 必须是整数，收到 ${String(version)}`)
    }
    if (version !== SNAPSHOT_SCHEMA_VERSION) {
      throw new SnapshotProblem(
        `不支持的 schema_version=${version}（本工具支持：${SNAPSHOT_SCHEMA_VERSION}）`,
      )
    }
    for (const field of ['fetched_at', 'resolver', 'psl_version', 'psl_date']) {
      requireNonEmptyString(raw, field)
    }
    const queries = raw.queries
    if (!Array.isArray(queries)) {
      throw new SnapshotProblem('queries 必须是有序列表')
    }
    const parsed: SnapshotQuery[] = queries.map((entry, position) => {
      const where = `queries[${position}]`
      if (!isPlainObject(entry)) throw new SnapshotProblem(`${where}：每条查询必须是对象`)
      for (const field of ['qname', 'qtype', 'rcode']) {
        const value = entry[field]
        if (typeof value !== 'string' || !value.trim()) {
          throw new SnapshotProblem(`${where}：${field} 必须是非空字符串`)
        }
      }
      const answer = entry.answer
      if (!Array.isArray(answer)) throw new SnapshotProblem(`${where}：answer 必须是列表`)
      for (const [index, item] of answer.entries()) {
        if (typeof item !== 'string') {
          throw new SnapshotProblem(`${where}：answer[${index}] 必须是字符串`)
        }
      }
      const ttl = entry.ttl
      if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < 0) {
        throw new SnapshotProblem(`${where}：ttl 必须是非负整数`)
      }
      const rcode = entry.rcode as string
      if (rcode.toUpperCase() !== RCODE_NOERROR && answer.length > 0) {
        throw new SnapshotProblem(
          `${where}：rcode=${rcode} 时 answer 必须为空列表，收到 ${answer.length} 条`,
        )
      }
      return {
        qname: entry.qname as string,
        qtype: (entry.qtype as string).toUpperCase(),
        rcode,
        answer: answer as string[],
        ttl,
      }
    })

    return new Snapshot({
      schema_version: version,
      fetched_at: raw.fetched_at as string,
      resolver: raw.resolver as string,
      psl_version: raw.psl_version as string,
      psl_date: raw.psl_date as string,
      queries: parsed,
    })
  }

  get pslVersion(): string {
    return this.data.psl_version
  }

  get pslDate(): string {
    return this.data.psl_date
  }

  get queryCount(): number {
    return this.data.queries.length
  }

  /** 按列表顺序取**第一次**命中；`found=false` 表示快照里没有这条查询。 */
  resolve(qname: string, qtype: string): Resolved {
    const key = `${normName(qname)}\u0000${qtype.toUpperCase()}`
    const positions = this.index.get(key)
    if (positions === undefined || positions.length === 0) {
      return {
        found: false,
        index: null,
        rcode: null,
        answer: [],
        ttl: null,
        qname: normName(qname),
        qtype: qtype.toUpperCase(),
      }
    }
    const position = positions[0]
    const entry = this.data.queries[position]
    return {
      found: true,
      index: position,
      rcode: entry.rcode,
      answer: entry.answer,
      ttl: entry.ttl,
      qname: entry.qname,
      qtype: entry.qtype,
    }
  }

  /** 同键的全部命中（保序），用于"同一个名字查了两次"。 */
  occurrences(qname: string, qtype: string): Resolved[] {
    const key = `${normName(qname)}\u0000${qtype.toUpperCase()}`
    return (this.index.get(key) ?? []).map((position) => {
      const entry = this.data.queries[position]
      return {
        found: true,
        index: position,
        rcode: entry.rcode,
        answer: entry.answer,
        ttl: entry.ttl,
        qname: entry.qname,
        qtype: entry.qtype,
      }
    })
  }
}

export function normalizeDnsName(name: string): string {
  return normName(name)
}