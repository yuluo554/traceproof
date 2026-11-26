/**
 * hazard-triage · 施工现场安全知识图谱（源仓 `kg/builder.py` + `kg/schema.py` + `kg/anchors.py`）。
 *
 * 轻量图结构（零依赖）：节点 `id -> {label, type, **props}`，边 `(src, relation, dst)` 去重。
 * 种子图谱关系：
 *   HazardType -风险分级-> RiskLevel
 *   HazardType -属于-> Category
 *   HazardType -整改用-> Measure
 *   HazardType -应依据-> Regulation
 *   HazardType -作业类型-> WorkType
 *   HazardType -发生于-> SiteObject
 *   Case -涉及-> HazardType
 *
 * 器官不渲染图谱、不导出 HTML；这里只做确定性建图与查询，供主张核对。
 */

import type { CaseRecord, HazardType, Knowledge, Measure, Regulation } from './knowledge.js'
import type { HazardCard } from './extract.js'

export const REL_LEVEL = '风险分级'
export const REL_CATEGORY = '属于'
export const REL_MEASURE = '整改用'
export const REL_CLAUSE = '应依据'
export const REL_INSTANCE = '实例化'
export const REL_OCCUR = '发生于'
export const REL_WORKTYPE = '作业类型'
export const REL_INVOLVE = '涉及'

export interface GraphNode {
  readonly id: string
  label: string
  type: string
  props: Record<string, unknown>
}

export interface GraphEdge {
  readonly src: string
  readonly relation: string
  readonly dst: string
  readonly props: Record<string, unknown>
}

function edgeKey(src: string, relation: string, dst: string): string {
  return `${src}\u0000${relation}\u0000${dst}`
}

export class SimpleGraph {
  private readonly nodes = new Map<string, GraphNode>()
  private readonly edges = new Map<string, GraphEdge>()

  addNode(nodeId: string, label: string, nodeType: string, props: Record<string, unknown> = {}): string {
    const existing = this.nodes.get(nodeId)
    if (existing !== undefined) {
      Object.assign(existing.props, props)
      return nodeId
    }
    this.nodes.set(nodeId, { id: nodeId, label, type: nodeType, props: { ...props } })
    return nodeId
  }

  addEdge(src: string, relation: string, dst: string, props: Record<string, unknown> = {}): string {
    const key = edgeKey(src, relation, dst)
    if (!this.edges.has(key)) {
      this.edges.set(key, { src, relation, dst, props: { ...props } })
    }
    return key
  }

  hasNode(nodeId: string): boolean {
    return this.nodes.has(nodeId)
  }

  getNode(nodeId: string): (GraphNode & Record<string, unknown>) | undefined {
    const node = this.nodes.get(nodeId)
    if (node === undefined) return undefined
    return { ...node, ...node.props }
  }

  neighbors(nodeId: string, relation?: string): Array<readonly [string, string]> {
    const out: Array<readonly [string, string]> = []
    for (const edge of this.edges.values()) {
      if (relation !== undefined && edge.relation !== relation) continue
      if (edge.src === nodeId) out.push([edge.dst, edge.relation])
      else if (edge.dst === nodeId) out.push([edge.src, edge.relation])
    }
    return out
  }

  nodeCount(): number {
    return this.nodes.size
  }

  edgeCount(): number {
    return this.edges.size
  }

  stats(): Record<string, unknown> {
    const nodesByType: Record<string, number> = {}
    for (const node of this.nodes.values()) {
      nodesByType[node.type] = (nodesByType[node.type] ?? 0) + 1
    }
    const edgesByRelation: Record<string, number> = {}
    for (const edge of this.edges.values()) {
      edgesByRelation[edge.relation] = (edgesByRelation[edge.relation] ?? 0) + 1
    }
    return {
      node_count: this.nodeCount(),
      edge_count: this.edgeCount(),
      nodes_by_type: Object.fromEntries(Object.keys(nodesByType).sort().map((key) => [key, nodesByType[key]])),
      edges_by_relation: Object.fromEntries(
        Object.keys(edgesByRelation).sort().map((key) => [key, edgesByRelation[key]]),
      ),
    }
  }

  toDict(): Record<string, unknown> {
    return {
      nodes: [...this.nodes.values()].map((node) => ({ id: node.id, label: node.label, type: node.type, ...node.props })),
      edges: [...this.edges.values()].map((edge) => ({ src: edge.src, relation: edge.relation, dst: edge.dst })),
    }
  }
}

function regulationNodeId(standard: string, clause: string): string {
  return `REG:${standard}#${clause}`
}

export function buildSeedGraph(knowledge: Knowledge): SimpleGraph {
  const graph = new SimpleGraph()

  for (const level of knowledge.riskLevels) graph.addNode(`RL:${level}`, level, 'RiskLevel')
  for (const category of knowledge.categories) graph.addNode(`CAT:${category}`, category, 'Category')

  const regulationByRef = new Map<string, string>()
  for (const regulation of knowledge.regulations as readonly Regulation[]) {
    const nodeId = regulationNodeId(regulation.std_id, regulation.clause)
    graph.addNode(
      nodeId,
      `[${regulation.std_id} ${regulation.clause}] ${regulation.std_name}`,
      'Regulation',
      { text: regulation.text },
    )
    regulationByRef.set(`${regulation.std_id}\u0000${regulation.clause}`, nodeId)
  }

  for (const measure of knowledge.measures as readonly Measure[]) {
    graph.addNode(`MS:${measure.id}`, measure.text, 'Measure')
  }

  for (const hazard of knowledge.hazardTypes as readonly HazardType[]) {
    const hazardId = `HT:${hazard.id}`
    graph.addNode(hazardId, hazard.name, 'HazardType', {
      base_level: hazard.base_level,
      category: hazard.category,
    })
    graph.addEdge(hazardId, REL_LEVEL, `RL:${hazard.base_level || '低风险'}`)
    graph.addEdge(hazardId, REL_CATEGORY, `CAT:${hazard.category || '其他'}`)
    for (const measureId of hazard.measure_ids) graph.addEdge(hazardId, REL_MEASURE, `MS:${measureId}`)
    for (const ref of hazard.clause_refs) {
      const regulationId = regulationByRef.get(`${ref.standard}\u0000${ref.clause}`)
      if (regulationId !== undefined) graph.addEdge(hazardId, REL_CLAUSE, regulationId)
    }
  }

  const workTypes = [...new Set(knowledge.hazardTypes.map((hazard) => hazard.work_type).filter(Boolean))].sort()
  for (const workType of workTypes) graph.addNode(`WT:${workType}`, workType, 'WorkType')
  for (const hazard of knowledge.hazardTypes) {
    if (hazard.work_type) graph.addEdge(`HT:${hazard.id}`, REL_WORKTYPE, `WT:${hazard.work_type}`)
    for (const object of hazard.site_objects) {
      graph.addNode(`SO:${object}`, object, 'SiteObject')
      graph.addEdge(`HT:${hazard.id}`, REL_OCCUR, `SO:${object}`)
    }
  }

  for (const item of knowledge.cases as readonly CaseRecord[]) {
    graph.addNode(`CASE:${item.case_id}`, item.title || item.case_id, 'Case', {
      risk_level: item.risk_level,
    })
    for (const hazardTypeId of item.hazard_type_ids) {
      graph.addEdge(`CASE:${item.case_id}`, REL_INVOLVE, `HT:${hazardTypeId}`)
    }
  }

  return graph
}

/** 把研判后的隐患实例挂到种子图谱上（动态节点，运行时增长）。 */
export function attachInstance(
  graph: SimpleGraph,
  card: HazardCard,
  judgment: { risk_level: string },
): string {
  const instanceId = `HI:${String(card.card_id)}`
  graph.addNode(instanceId, card.quote, 'HazardInstance', { risk_level: judgment.risk_level })
  graph.addEdge(instanceId, REL_INSTANCE, `HT:${card.hazard_type_id}`)
  if (card.site_object) {
    graph.addNode(`SO:${card.site_object}`, card.site_object, 'SiteObject')
    graph.addEdge(instanceId, REL_OCCUR, `SO:${card.site_object}`)
  }
  return instanceId
}

export function kgNodeId(standard: string, clause: string): string {
  return regulationNodeId(standard, clause)
}

/** Python `urllib.parse.quote(s, safe="")` 的等价实现（UTF-8，保留字符也编码）。 */
export function pyQuote(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (ch) => {
    return `%${ch.charCodeAt(0).toString(16).toUpperCase()}`
  })
}

export function anchorFor(nodeId: string, href = 'kg.html'): string {
  return `${href}#${pyQuote(nodeId)}`
}

export function clauseAnchor(standard: string, clause: string, href = 'kg.html'): string {
  return anchorFor(kgNodeId(standard, clause), href)
}