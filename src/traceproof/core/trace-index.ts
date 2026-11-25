/**
 * 痕迹索引：`session_id + turn + tool_call_id` 的唯一来源。
 *
 * 器官只能通过 `Basis.ref(session, turn, toolCallId)` 拿节点；拿不到就是
 * `NodeMissing`（痕迹包缺失 -> 契约违约，退出码 3），**不许自己编一个节点**。
 *
 * 本模块**不做文件 I/O**：读文件是唯一入口（`cli.ts`）的职责，内核只接收已解析的对象。
 * 节点按**字段比对**定位（不做字符串拼键）。
 */

import { ContractError, makeNode, nodeToJSON } from './ledger.js'
import type { TraceNode } from './ledger.js'

export class NodeMissing extends Error {
  constructor() {
    super('痕迹包无此节点')
    this.name = 'NodeMissing'
  }
}

function sameNode(
  node: TraceNode,
  sessionId: string,
  turn: number | null,
  toolCallId: string,
): boolean {
  return node.session_id === sessionId && node.turn === turn && node.tool_call_id === toolCallId
}

interface BasisData {
  version?: unknown
  nodes?: unknown
}

export class Basis {
  readonly version: string
  private readonly nodes: readonly TraceNode[]

  constructor(version: string, nodes: readonly TraceNode[] = []) {
    if (!version || !String(version).trim()) {
      throw new ContractError('痕迹包版本为空（依据包版本缺失）')
    }
    this.version = version
    const seen: TraceNode[] = []
    for (const node of nodes) {
      if (seen.some((other) => sameNode(other, node.session_id, node.turn, node.tool_call_id))) {
        throw new ContractError('痕迹节点重复')
      }
      seen.push(node)
    }
    this.nodes = Object.freeze(seen)
  }

  static empty(version = '0'): Basis {
    return new Basis(version)
  }

  static fromObject(data: unknown): Basis {
    if (data === null || typeof data !== 'object') {
      throw new ContractError('痕迹包必须是 JSON 对象')
    }
    const payload = data as BasisData
    const nodes = payload.nodes ?? []
    if (!Array.isArray(nodes)) throw new ContractError('nodes 必须是数组')
    const parsed = nodes.map((item: unknown) => {
      if (item === null || typeof item !== 'object') throw new ContractError('节点必须是对象')
      const raw = item as Record<string, unknown>
      const rawTurn = raw.turn === undefined || raw.turn === null ? null : Number(raw.turn)
      const turn = rawTurn !== null && Number.isInteger(rawTurn) ? rawTurn : null
      return makeNode({
        session_id: String(raw.session_id ?? ''),
        turn,
        tool_call_id: String(raw.tool_call_id ?? ''),
        quote: String(raw.quote ?? ''),
      })
    })
    return new Basis(String(payload.version ?? ''), parsed)
  }

  get size(): number {
    return this.nodes.length
  }

  node(sessionId: string, turn: number | null, toolCallId: string): TraceNode | undefined {
    return this.nodes.find((candidate) => sameNode(candidate, sessionId, turn, toolCallId))
  }

  require(sessionId: string, turn: number | null, toolCallId: string): TraceNode {
    const found = this.node(sessionId, turn, toolCallId)
    if (found === undefined) throw new NodeMissing()
    return found
  }

  /** 给器官用的唯一取节点入口。 */
  ref(sessionId: string, turn: number | null, toolCallId: string): TraceNode {
    return this.require(sessionId, turn, toolCallId)
  }

  toJSON(): Record<string, unknown> {
    return { version: this.version, nodes: this.nodes.map((node) => nodeToJSON(node)) }
  }
}