/**
 * hazard-triage · 施工现场安全风险隐患智能研判取证
 *
 * 一个 traceproof 器官：把「这组施工日志会抽出哪些隐患、关联哪些规范条款、
 * 定成哪一级风险、给出哪些整改建议」的主张，逐条对到**同一份输入**的确定性重算，
 * 再挂到痕迹节点（`session_id + turn + tool_call_id`）。
 *
 * 迁移来源：旧仓 `siteguard` 的判定层（ingest 解析 / extract 规则 / reasoning
 * 条款关联与分级 / kg 种子图谱与锚点 / vision 映射与融合 / vector 兜底 /
 * video 选帧 / benchmark 指标）。LLM 调用、Web 面板、报告导出、pyvis 可视化、
 * docx 解析、YOLO/opencv 推理与文件 IO **不迁**：器官只接收已归一化的输入事实，
 * 不读文件 / 环境变量 / 时钟，不联网。
 *
 * 版本沿用源仓 `pyproject.toml` 的 `0.1.1`（不随本产品升版）。
 */

import type { Basis } from '../../core/trace-index.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'
import { createRuleEngine } from './extract.js'
import type { HazardCard } from './extract.js'
import { buildSeedGraph, clauseAnchor, kgNodeId, SimpleGraph } from './graph.js'
import { judge, LEVELS, MAJOR_PATTERNS, SEVERITY_WORDS } from './judge.js'
import type { Judgment } from './judge.js'
import { buildKnowledge, KnowledgePackError } from './knowledge.js'
import type { ClauseRef, Knowledge } from './knowledge.js'
import { linkClauses } from './link.js'
import type { LinkedClauseRef } from './link.js'
import { computeMetrics, FIELDS } from './metrics.js'
import type { GoldRecord, MetricField, Metrics } from './metrics.js'
import { detectPairedDiffs } from './paired.js'
import type { PairedDiff } from './paired.js'
import { parseLogText, readRecords } from './parse.js'
import type { LogRecord } from './parse.js'
import { buildSuggestions } from './suggest.js'
import type { Suggestion } from './suggest.js'
import {
  assertKnownKeys,
  baseName,
  isPlainObject,
  jsonEqual,
  optionalBoolean,
  optionalFiniteNumber,
  optionalInteger,
  optionalString,
  optionalStringArray,
  readFiniteNumber,
  readInteger,
  readNumberArray,
  readString,
} from './util.js'
import { buildRegulationIndex, fallbackClauses, VectorIndex } from './vector.js'
import type { FallbackClause } from './vector.js'
import { cardFromDetection, detectionsToCards, mergeCards, readDetections } from './vision.js'
import type { Detection } from './vision.js'
import { selectKeyframes } from './video.js'

/** 版本沿用源仓 `pyproject.toml` 的 0.1.1（不随本产品升版）。 */
export const VERSION = '0.1.1'

export const CHECKS = [
  'hazard',
  'count',
  'level',
  'clause',
  'anchor',
  'suggestion',
  'graph',
  'node',
  'schema',
  'consistency',
  'vision',
  'merge',
  'fallback',
  'keyframes',
  'paired',
  'metric',
  'candidate',
  'record',
] as const
export type CheckName = (typeof CHECKS)[number]

export const LEVEL_ASSERTED = LEVELS
export const GRAPH_OPS = ['node-count', 'edge-count', 'nodes-of-type', 'edges-of-relation', 'neighbors'] as const
export const SCHEMA_OPS = [
  'hazard-types',
  'measures',
  'regulations',
  'thresholds',
  'overrides',
  'threshold-rules',
  'base-rules',
  'patterns',
] as const
export const CONSISTENCY_KINDS = [
  'base-rules',
  'pattern-coverage',
  'measure-refs',
  'clause-refs',
  'kg-nodes',
  'rule-fallback',
] as const
export const COUNT_OPS = ['records', 'hazards', 'type', 'level', 'suggestions', 'fallback'] as const
export const METRIC_OPS = [
  'micro-f1',
  'micro-precision',
  'micro-recall',
  'micro-fp',
  'level-accuracy',
  'detection-rate',
  'false-positive-rate',
  'field-f1',
] as const

const GLOBAL_FIELDS = ['claim_id', 'check', 'asserted', 'node'] as const

const CHECK_FIELDS: Readonly<Record<CheckName, readonly string[]>> = {
  hazard: ['record_index', 'hazard_type_id', 'quote', 'category', 'site_object', 'extractor'],
  count: ['of', 'hazard_type_id', 'risk_level'],
  level: [
    'record_index',
    'hazard_type_id',
    'rule_id',
    'override_id',
    'threshold_id',
    'upgraded',
    'human_confirm',
  ],
  clause: ['record_index', 'hazard_type_id', 'clause_refs', 'require_quotes'],
  anchor: ['standard', 'clause', 'href', 'anchor', 'require_node'],
  suggestion: ['record_index', 'hazard_type_id', 'sources', 'contains'],
  graph: ['of', 'node_type', 'relation', 'node_id'],
  node: ['node_id', 'node_type', 'relations'],
  schema: ['of'],
  consistency: ['kind'],
  vision: ['image', 'detection_index', 'hazard_type_id', 'bbox', 'confidence'],
  merge: ['record_index', 'hazard_type_id', 'merged_from', 'confidence', 'evidence_images'],
  fallback: ['record_index', 'hazard_type_id', 'clauses', 'min_score'],
  keyframes: ['total_frames', 'max_frames', 'frames'],
  paired: ['kind', 'timestamp'],
  metric: ['of', 'field', 'tolerance'],
  candidate: ['record_index', 'hazard_type_id', 'quote', 'category'],
  record: ['record_index', 'timestamp', 'text'],
}

const SUBJECT_FIELDS = new Set(['text', 'records', 'knowledge', 'vision', 'video', 'paired', 'gold', 'claims'])

const CLAIM_ASSERTED: Partial<Record<CheckName, readonly string[]>> = {
  hazard: ['reported', 'absent'],
  level: LEVELS,
  clause: ['linked', 'unlinked'],
  anchor: ['exact'],
  suggestion: ['sourced', 'fallback'],
  node: ['present', 'absent'],
  consistency: ['consistent', 'inconsistent'],
  vision: ['mapped', 'dropped'],
  merge: ['merged', 'unmerged'],
  fallback: ['candidates', 'none'],
  paired: ['present', 'absent'],
  candidate: ['valid', 'invalid'],
  record: ['exact'],
}

export interface JudgedCard extends HazardCard {
  card_id: string
  judgment: Judgment & { readonly suggestions: readonly Suggestion[] }
  fallback_clauses?: FallbackClause[]
}

interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: string
  readonly node: unknown
  readonly recordIndex: number | null
  readonly hazardTypeId: string | null
  readonly quote: string | null
  readonly category: string | null
  readonly siteObject: string | null
  readonly extractor: string | null
  readonly of: string | null
  readonly riskLevel: string | null
  readonly ruleId: string | null
  readonly overrideId: string | null
  readonly thresholdId: string | null
  readonly upgraded: string | null
  readonly humanConfirm: boolean | null
  readonly clauseRefs: readonly ClauseRef[] | null
  readonly clauses: readonly ClauseRef[] | null
  readonly requireQuotes: boolean | null
  readonly standard: string | null
  readonly clause: string | null
  readonly href: string | null
  readonly anchor: string | null
  readonly requireNode: boolean | null
  readonly sources: readonly string[] | null
  readonly contains: readonly string[] | null
  readonly nodeType: string | null
  readonly relation: string | null
  readonly nodeId: string | null
  readonly relations: readonly string[] | null
  readonly kind: string | null
  readonly image: string | null
  readonly detectionIndex: number | null
  readonly bbox: readonly number[] | null
  readonly confidence: number | null
  readonly mergedFrom: readonly string[] | null
  readonly evidenceImages: readonly string[] | null
  readonly minScore: number | null
  readonly totalFrames: number | null
  readonly maxFrames: number | null
  readonly frames: readonly number[] | null
  readonly timestamp: string | null
  readonly text: string | null
  readonly field: MetricField | null
  readonly tolerance: number | null
}

interface VisionInput {
  readonly images: readonly { readonly name: string; readonly detections: readonly Detection[] }[]
  readonly timeWindowMinutes: number
}

interface VideoInput {
  readonly totalFrames: number
  readonly maxFrames: number
}

interface PairedInput {
  readonly log: readonly LogRecord[]
  readonly patrol: readonly LogRecord[]
}

interface Computed {
  readonly result: string
  readonly matched: boolean
  readonly reason: string
  readonly evidence: Readonly<Record<string, unknown>>
}

// ---------------------------------------------------------------------------
// 输入解析
// ---------------------------------------------------------------------------

function readClauseRefList(value: unknown, where: string): ClauseRef[] {
  if (!Array.isArray(value)) throw new ContractError(`${where} 必须是数组`)
  return value.map((item, position) => {
    const at = `${where}[${position}]`
    if (!isPlainObject(item)) throw new ContractError(`${at} 必须是对象`)
    assertKnownKeys(item, ['standard', 'clause'], at)
    return {
      standard: readString(item.standard, `${at}.standard`),
      clause: readString(item.clause, `${at}.clause`),
    }
  })
}

function readRecordsOrText(value: unknown, where: string): LogRecord[] {
  if (typeof value === 'string') return parseLogText(value)
  return readRecords(value)
}

function readVision(value: unknown): VisionInput {
  if (!isPlainObject(value)) throw new ContractError('vision 必须是对象')
  assertKnownKeys(value, ['images', 'time_window_minutes'], 'vision')
  if (!Array.isArray(value.images)) throw new ContractError('vision.images 必须是数组')
  const images = value.images.map((item, position) => {
    const where = `vision.images[${position}]`
    if (!isPlainObject(item)) throw new ContractError(`${where} 必须是对象`)
    assertKnownKeys(item, ['name', 'detections'], where)
    return {
      name: readString(item.name, `${where}.name`),
      detections: readDetections(item.detections, `${where}.detections`),
    }
  })
  const timeWindow = value.time_window_minutes === undefined ? 60 : readFiniteNumber(value.time_window_minutes, 'vision.time_window_minutes')
  if (timeWindow < 0) throw new ContractError('vision.time_window_minutes 不能为负')
  return { images, timeWindowMinutes: timeWindow }
}

function readVideo(value: unknown): VideoInput {
  if (!isPlainObject(value)) throw new ContractError('video 必须是对象')
  assertKnownKeys(value, ['total_frames', 'max_frames'], 'video')
  const totalFrames = readInteger(value.total_frames, 'video.total_frames')
  if (totalFrames < 0) throw new ContractError('video.total_frames 不能为负')
  const maxFrames = value.max_frames === undefined ? 8 : readInteger(value.max_frames, 'video.max_frames')
  if (maxFrames < 1) throw new ContractError('video.max_frames 必须 ≥ 1')
  return { totalFrames, maxFrames }
}

function readPaired(value: unknown): PairedInput {
  if (!isPlainObject(value)) throw new ContractError('paired 必须是对象')
  assertKnownKeys(value, ['log', 'patrol'], 'paired')
  return {
    log: readRecordsOrText(value.log, 'paired.log'),
    patrol: readRecordsOrText(value.patrol, 'paired.patrol'),
  }
}

function readGold(value: unknown): GoldRecord[] {
  if (!isPlainObject(value)) throw new ContractError('gold 必须是对象')
  assertKnownKeys(value, ['records', 'file', 'seed', 'corpus'], 'gold')
  if (!Array.isArray(value.records)) throw new ContractError('gold.records 必须是数组')
  return value.records.map((item, position) => {
    const where = `gold.records[${position}]`
    if (!isPlainObject(item)) throw new ContractError(`${where} 必须是对象`)
    const index = readInteger(item.index, `${where}.index`)
    const hazardTypeId = readString(item.hazard_type_id, `${where}.hazard_type_id`)
    return {
      index,
      hazard_type_id: hazardTypeId,
      ...(typeof item.quote === 'string' ? { quote: item.quote } : {}),
      ...(typeof item.hazard_type === 'string' ? { hazard_type: item.hazard_type } : {}),
      ...(typeof item.category === 'string' ? { category: item.category } : {}),
      ...(typeof item.site_object === 'string' ? { site_object: item.site_object } : {}),
      ...(typeof item.expected_level === 'string' ? { expected_level: item.expected_level } : {}),
    }
  })
}

function readClaim(raw: unknown, position: number): Claim {
  const where = `claims[${position}]`
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const check = raw.check
  if (typeof check !== 'string' || !(CHECKS as readonly string[]).includes(check)) {
    throw new ContractError(`${where} 的 check 非法：<${String(check)}>（允许 ${CHECKS.join(' / ')}）`)
  }
  const checkName = check as CheckName
  assertKnownKeys(raw, [...GLOBAL_FIELDS, ...CHECK_FIELDS[checkName]], where)

  const claimId = readString(raw.claim_id, `${where}.claim_id`).trim()
  if (!claimId) throw new ContractError(`${where}.claim_id 不能为空`)
  if (typeof raw.asserted !== 'string' || !raw.asserted.trim()) throw new ContractError(`${where} 缺 asserted`)
  const asserted = raw.asserted.trim()

  const numeric =
    checkName === 'count' ||
    checkName === 'graph' ||
    checkName === 'schema' ||
    checkName === 'metric' ||
    (checkName === 'keyframes' && raw.frames === undefined)
  if (numeric) {
    if (!/^-?\d+(\.\d+)?$/.test(asserted)) {
      throw new ContractError(`${where} 的 asserted 必须是数字（收到 <${asserted}>）`)
    }
  }

  const of = optionalString(raw, 'of', where)
  const ofSets: Partial<Record<CheckName, readonly string[]>> = {
    count: COUNT_OPS,
    graph: GRAPH_OPS,
    schema: SCHEMA_OPS,
    metric: METRIC_OPS,
  }
  if (ofSets[checkName] !== undefined) {
    if (of === null || !(ofSets[checkName] as readonly string[]).includes(of)) {
      throw new ContractError(`${where} 的 of 非法：<${String(of)}>（允许 ${(ofSets[checkName] as readonly string[]).join(' / ')}）`)
    }
  }

  let upgraded: string | null = null
  if (checkName === 'level') {
    upgraded = optionalString(raw, 'upgraded', where)
    if (upgraded !== null && !['major', 'severity', 'none'].includes(upgraded)) {
      throw new ContractError(`${where}.upgraded 必须是 major / severity / none`)
    }
  }

  let kind: string | null = null
  if (checkName === 'consistency') {
    kind = optionalString(raw, 'kind', where)
    if (kind === null || !(CONSISTENCY_KINDS as readonly string[]).includes(kind)) {
      throw new ContractError(`${where}.kind 必须是 ${CONSISTENCY_KINDS.join(' / ')}`)
    }
  }
  if (checkName === 'paired') {
    kind = optionalString(raw, 'kind', where)
    if (kind === null || !['missing', 'extra', 'value'].includes(kind)) {
      throw new ContractError(`${where}.kind 必须是 missing / extra / value`)
    }
  }

  const clauseRefs = raw.clause_refs === undefined ? null : readClauseRefList(raw.clause_refs, `${where}.clause_refs`)
  const clauses = raw.clauses === undefined ? null : readClauseRefList(raw.clauses, `${where}.clauses`)
  const relations = optionalStringArray(raw, 'relations', where)
  const frames = raw.frames === undefined ? null : readNumberArray(raw.frames, `${where}.frames`)
  if (checkName === 'keyframes' && frames === null) {
    const maybeNumeric = /^-?\d+(\.\d+)?$/.test(asserted)
    if (!maybeNumeric) throw new ContractError(`${where} 的 asserted 必须是数字（收到 <${asserted}>）`)
  }
  if (checkName === 'keyframes' && frames !== null && asserted !== 'exact') {
    throw new ContractError(`${where} 的 asserted 必须是 exact（带 frames 清单时）`)
  }
  let field: MetricField | null = null
  if (checkName === 'metric') {
    field = optionalString(raw, 'field', where) as MetricField | null
    if (field !== null && !(FIELDS as readonly string[]).includes(field)) {
      throw new ContractError(`${where}.field 必须是 ${FIELDS.join(' / ')}`)
    }
  }

  if (checkName === 'hazard' && raw.hazard_type_id === undefined) {
    throw new ContractError(`${where}：hazard 主张必须带 hazard_type_id`)
  }
  if (checkName === 'hazard' && raw.record_index === undefined) {
    throw new ContractError(`${where}：hazard 主张必须带 record_index`)
  }
  if (['level', 'clause', 'suggestion', 'merge', 'fallback', 'candidate', 'record'].includes(checkName)) {
    if (raw.record_index === undefined) throw new ContractError(`${where}：${checkName} 主张必须带 record_index`)
  }
  if (['level', 'clause', 'suggestion', 'merge', 'fallback', 'candidate'].includes(checkName)) {
    if (raw.hazard_type_id === undefined) throw new ContractError(`${where}：${checkName} 主张必须带 hazard_type_id`)
  }
  if (checkName === 'anchor' && (raw.standard === undefined || raw.clause === undefined || raw.anchor === undefined)) {
    throw new ContractError(`${where}：anchor 主张必须带 standard / clause / anchor`)
  }
  if (checkName === 'node' && raw.node_id === undefined) throw new ContractError(`${where}：node 主张必须带 node_id`)
  if (checkName === 'graph' && raw.of === 'nodes-of-type' && raw.node_type === undefined) {
    throw new ContractError(`${where}：nodes-of-type 主张必须带 node_type`)
  }
  if (checkName === 'graph' && raw.of === 'edges-of-relation' && raw.relation === undefined) {
    throw new ContractError(`${where}：edges-of-relation 主张必须带 relation`)
  }
  if (checkName === 'graph' && raw.of === 'neighbors' && raw.node_id === undefined) {
    throw new ContractError(`${where}：neighbors 主张必须带 node_id`)
  }
  if (checkName === 'keyframes' && raw.total_frames === undefined) {
    throw new ContractError(`${where}：keyframes 主张必须带 total_frames`)
  }
  if (checkName === 'paired' && (raw.kind === undefined || raw.timestamp === undefined)) {
    throw new ContractError(`${where}：paired 主张必须带 kind / timestamp`)
  }
  if (checkName === 'vision' && (raw.image === undefined || raw.detection_index === undefined)) {
    throw new ContractError(`${where}：vision 主张必须带 image / detection_index`)
  }
  if (checkName === 'record' && (raw.timestamp === undefined || raw.text === undefined)) {
    throw new ContractError(`${where}：record 主张必须带 timestamp / text`)
  }
  if (checkName === 'count' && raw.of === 'type' && raw.hazard_type_id === undefined) {
    throw new ContractError(`${where}：count(of=type) 必须带 hazard_type_id`)
  }
  if (checkName === 'count' && raw.of === 'level' && raw.risk_level === undefined) {
    throw new ContractError(`${where}：count(of=level) 必须带 risk_level`)
  }
  if (checkName === 'metric' && raw.of === 'field-f1' && field === null) {
    throw new ContractError(`${where}：metric(of=field-f1) 必须带 field`)
  }
  const allowedAsserted = CLAIM_ASSERTED[checkName]
  if (allowedAsserted !== undefined && !allowedAsserted.includes(asserted)) {
    throw new ContractError(
      `${where} 的 asserted 非法：<${asserted}>（${checkName} 允许 ${allowedAsserted.join(' / ')}）`,
    )
  }

  return {
    claimId,
    check: checkName,
    asserted,
    node: raw.node,
    recordIndex: optionalInteger(raw, 'record_index', where),
    hazardTypeId: optionalString(raw, 'hazard_type_id', where),
    quote: optionalString(raw, 'quote', where),
    category: optionalString(raw, 'category', where),
    siteObject: optionalString(raw, 'site_object', where),
    extractor: optionalString(raw, 'extractor', where),
    of,
    riskLevel: optionalString(raw, 'risk_level', where),
    ruleId: optionalString(raw, 'rule_id', where),
    overrideId: optionalString(raw, 'override_id', where),
    thresholdId: optionalString(raw, 'threshold_id', where),
    upgraded,
    humanConfirm: optionalBoolean(raw, 'human_confirm', where),
    clauseRefs,
    clauses,
    requireQuotes: optionalBoolean(raw, 'require_quotes', where),
    standard: optionalString(raw, 'standard', where),
    clause: optionalString(raw, 'clause', where),
    href: optionalString(raw, 'href', where),
    anchor: optionalString(raw, 'anchor', where),
    requireNode: optionalBoolean(raw, 'require_node', where),
    sources: optionalStringArray(raw, 'sources', where),
    contains: optionalStringArray(raw, 'contains', where),
    nodeType: optionalString(raw, 'node_type', where),
    relation: optionalString(raw, 'relation', where),
    nodeId: optionalString(raw, 'node_id', where),
    relations,
    kind,
    image: optionalString(raw, 'image', where),
    detectionIndex: optionalInteger(raw, 'detection_index', where),
    bbox: raw.bbox === undefined ? null : readNumberArray(raw.bbox, `${where}.bbox`),
    confidence: optionalFiniteNumber(raw, 'confidence', where),
    mergedFrom: optionalStringArray(raw, 'merged_from', where),
    evidenceImages: optionalStringArray(raw, 'evidence_images', where),
    minScore: optionalFiniteNumber(raw, 'min_score', where),
    totalFrames: optionalInteger(raw, 'total_frames', where),
    maxFrames: optionalInteger(raw, 'max_frames', where),
    frames,
    timestamp: optionalString(raw, 'timestamp', where),
    text: optionalString(raw, 'text', where),
    field,
    tolerance: optionalFiniteNumber(raw, 'tolerance', where),
  }
}

// ---------------------------------------------------------------------------
// 重算上下文（懒加载；器官只在 evaluate 内持有）
// ---------------------------------------------------------------------------

class Context {
  private readonly knowledgeData: Knowledge
  private readonly text: string | null
  private readonly rawRecords: unknown
  private readonly visionData: VisionInput | null
  private readonly videoData: VideoInput | null
  private readonly pairedData: PairedInput | null
  private readonly goldData: GoldRecord[] | null
  private graphData: SimpleGraph | null = null
  private recordsData: LogRecord[] | null = null
  private cardsData: JudgedCard[] | null = null
  private vectorData: VectorIndex | null = null
  private metricData: Metrics | null = null
  private pairedDiffsData: PairedDiff[] | null = null

  constructor(subject: Record<string, unknown>) {
    for (const key of Object.keys(subject)) {
      if (!SUBJECT_FIELDS.has(key)) throw new ContractError(`输入含未知字段：${key}`)
    }
    if (subject.text !== undefined && subject.records !== undefined) {
      throw new ContractError('text 与 records 只能提供一个')
    }
    this.text = subject.text === undefined ? null : readString(subject.text, 'text')
    this.rawRecords = subject.records
    this.knowledgeData = buildKnowledge(subject.knowledge)
    this.visionData = subject.vision === undefined ? null : readVision(subject.vision)
    this.videoData = subject.video === undefined ? null : readVideo(subject.video)
    this.pairedData = subject.paired === undefined ? null : readPaired(subject.paired)
    this.goldData = subject.gold === undefined ? null : readGold(subject.gold)
  }

  get knowledge(): Knowledge {
    return this.knowledgeData
  }

  get vision(): VisionInput | null {
    return this.visionData
  }

  get video(): VideoInput | null {
    return this.videoData
  }

  graph(): SimpleGraph {
    if (this.graphData === null) this.graphData = buildSeedGraph(this.knowledge)
    return this.graphData
  }

  records(): LogRecord[] {
    if (this.recordsData !== null) return this.recordsData
    if (this.text !== null) this.recordsData = parseLogText(this.text)
    else if (this.rawRecords !== undefined) this.recordsData = readRecords(this.rawRecords)
    else throw new ContractError('该主张需要施工日志：缺少 text 或 records')
    return this.recordsData
  }

  findings(): JudgedCard[] {
    if (this.cardsData !== null) return this.cardsData
    const records = this.records()
    const engine = createRuleEngine(this.knowledge)
    let cards = engine.extract(records, '<input>')
    if (this.visionData !== null) {
      const visionCards: HazardCard[] = []
      for (const image of this.visionData.images) {
        visionCards.push(...detectionsToCards(this.knowledge, image.name, image.detections).cards)
      }
      cards = mergeCards(cards, visionCards, this.visionData.timeWindowMinutes).cards
    }
    this.cardsData = cards.map((card, position) => {
      card.card_id = `HC-${String(position + 1).padStart(5, '0')}`
      const refs = linkClauses(card, this.knowledge, this.graph())
      const judgment = judge(card, refs, this.knowledge)
      const suggestions = buildSuggestions(card, judgment, this.knowledge)
      return Object.assign(card, { judgment: { ...judgment, suggestions } }) as JudgedCard
    })
    return this.cardsData
  }

  findCard(recordIndex: number, hazardTypeId: string): JudgedCard | undefined {
    return this.findings().find(
      (card) => card.source.record_index === recordIndex && card.hazard_type_id === hazardTypeId,
    )
  }

  vectorIndex(): VectorIndex {
    if (this.vectorData === null) this.vectorData = buildRegulationIndex(this.knowledge)
    return this.vectorData
  }

  metrics(): Metrics {
    if (this.metricData !== null) return this.metricData
    if (this.goldData === null) throw new ContractError('metric 主张需要 gold.records')
    this.metricData = computeMetrics(this.findings(), this.goldData)
    return this.metricData
  }

  pairedDiffs(): PairedDiff[] {
    if (this.pairedDiffsData !== null) return this.pairedDiffsData
    if (this.pairedData === null) throw new ContractError('paired 主张需要 paired.log / paired.patrol')
    this.pairedDiffsData = detectPairedDiffs(this.pairedData.log, this.pairedData.patrol)
    return this.pairedDiffsData
  }
}

// ---------------------------------------------------------------------------
// 逐 check 重算
// ---------------------------------------------------------------------------

function findRecord(context: Context, claim: Claim): LogRecord | undefined {
  return context.records().find((record) => record.index === claim.recordIndex)
}

function compareFields(
  actual: Record<string, unknown>,
  pairs: ReadonlyArray<readonly [string, unknown]>,
): string[] {
  const problems: string[] = []
  for (const [name, expected] of pairs) {
    if (expected === null || expected === undefined) continue
    const computed = actual[name]
    if (!jsonEqual(computed, expected)) {
      problems.push(`${name} 不符（账本 ${JSON.stringify(computed)} ≠ 主张 ${JSON.stringify(expected)}）`)
    }
  }
  return problems
}

function computeRecord(context: Context, claim: Claim): Computed {
  const record = findRecord(context, claim)
  if (record === undefined) {
    return {
      result: 'absent',
      matched: claim.asserted === 'absent',
      reason: `记录序号 ${String(claim.recordIndex)} 不在解析结果中`,
      evidence: { record_index: claim.recordIndex, record_count: context.records().length },
    }
  }
  const problems = compareFields(
    { timestamp: record.timestamp, text: record.text },
    [
      ['timestamp', claim.timestamp],
      ['text', claim.text],
    ],
  )
  const recorded = { index: record.index, timestamp: record.timestamp, text: record.text }
  if (claim.asserted !== 'exact') {
    return {
      result: 'exact',
      matched: false,
      reason: `记录 ${String(record.index)} 存在，但主张值不是 exact（${claim.asserted}）`,
      evidence: { record: recorded, problems },
    }
  }
  return {
    result: 'exact',
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `记录 ${String(record.index)} 的规范化时间戳与文本逐字一致`
        : `记录 ${String(record.index)} 存在，但${problems.join('；')}`,
    evidence: { record: recorded, problems },
  }
}

function computeHazard(context: Context, claim: Claim): Computed {
  const recordIndex = claim.recordIndex as number
  const hazardTypeId = claim.hazardTypeId as string
  const card = context.findCard(recordIndex, hazardTypeId)
  if (card === undefined) {
    const actual = context.findings().filter((candidate) => candidate.source.record_index === recordIndex)
    return {
      result: 'absent',
      matched: claim.asserted === 'absent',
      reason:
        claim.asserted === 'absent'
          ? `记录 ${String(recordIndex)} 未抽出 ${hazardTypeId}`
          : `记录 ${String(recordIndex)} 未抽出 ${hazardTypeId}（不成立的主张）`,
      evidence: {
        record_index: recordIndex,
        hazard_type_id: hazardTypeId,
        record_hazard_type_ids: actual.map((candidate) => candidate.hazard_type_id),
      },
    }
  }
  const actual = {
    hazard_type_id: card.hazard_type_id,
    hazard_type: card.hazard_type,
    category: card.category,
    site_object: card.site_object,
    quote: card.quote,
    extractor: card.extractor,
  }
  const problems = compareFields(actual, [
    ['quote', claim.quote],
    ['category', claim.category],
    ['site_object', claim.siteObject],
    ['extractor', claim.extractor],
  ])
  return {
    result: 'reported',
    matched: claim.asserted === 'reported' && problems.length === 0,
    reason:
      claim.asserted !== 'reported'
        ? `记录 ${String(recordIndex)} 确实抽出 ${hazardTypeId}，主张却是 ${claim.asserted}`
        : problems.length === 0
          ? `记录 ${String(recordIndex)} 抽出 ${hazardTypeId}（${card.hazard_type}，部位 ${card.site_object || '—'}）`
          : `已抽出 ${hazardTypeId}，但明细不符：${problems.join('；')}`,
    evidence: actual,
  }
}

function computeCount(context: Context, claim: Claim): Computed {
  const cards = context.findings()
  let count: number
  let scope: string
  switch (claim.of) {
    case 'records':
      count = context.records().length
      scope = 'records'
      break
    case 'hazards':
      count = cards.length
      scope = 'hazards'
      break
    case 'type':
      count = cards.filter((card) => card.hazard_type_id === claim.hazardTypeId).length
      scope = `type(${claim.hazardTypeId ?? '?'})`
      break
    case 'level':
      count = cards.filter((card) => card.judgment.risk_level === claim.riskLevel).length
      scope = `level(${claim.riskLevel ?? '?'})`
      break
    case 'suggestions':
      count = cards.reduce((total, card) => total + card.judgment.suggestions.length, 0)
      scope = 'suggestions'
      break
    case 'fallback': {
      const annotated = cards.filter((card) => fallbackFor(context, card, claim, 0.05).length > 0).length
      count = annotated
      scope = 'fallback'
      break
    }
    default:
      throw new ContractError(`count 的 of 非法：${String(claim.of)}`)
  }
  const expected = Number(claim.asserted)
  return {
    result: String(count),
    matched: count === expected,
    reason: count === expected ? `重算 ${scope} = ${count}，与主张一致` : `重算 ${scope} = ${count} ≠ 主张 ${expected}`,
    evidence: { of: claim.of, count, ...(claim.hazardTypeId !== null ? { hazard_type_id: claim.hazardTypeId } : {}), ...(claim.riskLevel !== null ? { risk_level: claim.riskLevel } : {}) },
  }
}

function computeLevel(context: Context, claim: Claim): Computed {
  const card = context.findCard(claim.recordIndex as number, claim.hazardTypeId as string)
  if (card === undefined) {
    return {
      result: 'absent',
      matched: false,
      reason: `记录 ${String(claim.recordIndex)} / ${String(claim.hazardTypeId)} 没有条目卡，无法核对等级`,
      evidence: { record_index: claim.recordIndex, hazard_type_id: claim.hazardTypeId },
    }
  }
  const judgment = card.judgment
  const actual = {
    risk_level: judgment.risk_level,
    rule_id: judgment.rule_id,
    override_id: judgment.override_id,
    threshold_id: judgment.threshold_id,
    human_confirm: judgment.human_confirm,
    upgraded:
      judgment.upgraded.major_pattern !== null
        ? 'major'
        : judgment.upgraded.severity_word !== null
          ? 'severity'
          : 'none',
  }
  const problems = compareFields(actual, [
    ['risk_level', claim.asserted],
    ['rule_id', claim.ruleId],
    ['override_id', claim.overrideId],
    ['threshold_id', claim.thresholdId],
    ['upgraded', claim.upgraded],
    ['human_confirm', claim.humanConfirm],
  ])
  return {
    result: judgment.risk_level,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `记录 ${String(claim.recordIndex)} / ${card.hazard_type_id} 判定 ${judgment.risk_level}（rule_id=${judgment.rule_id}）`
        : `等级/追溯字段不符：${problems.join('；')}`,
    evidence: actual,
  }
}

function computeClause(context: Context, claim: Claim): Computed {
  const card = context.findCard(claim.recordIndex as number, claim.hazardTypeId as string)
  if (card === undefined) {
    return {
      result: 'absent',
      matched: false,
      reason: `记录 ${String(claim.recordIndex)} / ${String(claim.hazardTypeId)} 没有条目卡，无法核对条款`,
      evidence: { record_index: claim.recordIndex, hazard_type_id: claim.hazardTypeId },
    }
  }
  const actual = card.judgment.clause_refs.map((ref) => ({ standard: ref.standard, clause: ref.clause }))
  const result = actual.length > 0 ? 'linked' : 'unlinked'
  const problems: string[] = []
  if (claim.asserted !== result) {
    problems.push(`实际 ${result}，主张 ${claim.asserted}`)
  }
  if (claim.clauseRefs !== null) {
    if (!jsonEqual(actual, claim.clauseRefs)) {
      problems.push(
        `条款清单不符（账本 ${actual.map((ref) => `${ref.standard} ${ref.clause}`).join('、') || '空'} ≠ 主张 ${claim.clauseRefs.map((ref) => `${ref.standard} ${ref.clause}`).join('、') || '空'}）`,
      )
    }
  }
  if (claim.requireQuotes === true) {
    const missing = card.judgment.clause_refs.filter((ref) => !ref.quote).map((ref) => `${ref.standard} ${ref.clause}`)
    if (missing.length > 0) problems.push(`缺原文摘录：${missing.join('、')}`)
  }
  return {
    result,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `条款关联 ${result}（${actual.map((ref) => `${ref.standard} ${ref.clause}`).join('、') || '空'}）`
        : `条款关联不符：${problems.join('；')}`,
    evidence: {
      clause_refs: actual,
      quotes: card.judgment.clause_refs.map((ref) => ref.quote),
      require_quotes: claim.requireQuotes === true,
    },
  }
}

function computeAnchor(context: Context, claim: Claim): Computed {
  const standard = claim.standard as string
  const clause = claim.clause as string
  const href = claim.href ?? 'kg.html'
  const computed = clauseAnchor(standard, clause, href)
  const nodeId = kgNodeId(standard, clause)
  const present = context.graph().hasNode(nodeId)
  const problems: string[] = []
  if (!jsonEqual(computed, claim.anchor)) {
    problems.push(`锚点不符（账本 ${computed} ≠ 主张 ${String(claim.anchor)}）`)
  }
  if ((claim.requireNode ?? true) && !present) problems.push(`图谱缺条款节点 ${nodeId}`)
  return {
    result: computed,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `锚点 ${computed} 成立（节点 ${nodeId} 在图中）`
        : `锚点核对失败：${problems.join('；')}`,
    evidence: { node_id: nodeId, node_present: present, href, anchor: computed },
  }
}

function computeSuggestion(context: Context, claim: Claim): Computed {
  const card = context.findCard(claim.recordIndex as number, claim.hazardTypeId as string)
  if (card === undefined) {
    return {
      result: 'absent',
      matched: false,
      reason: `记录 ${String(claim.recordIndex)} / ${String(claim.hazardTypeId)} 没有条目卡，无法核对整改建议`,
      evidence: { record_index: claim.recordIndex, hazard_type_id: claim.hazardTypeId },
    }
  }
  const suggestions = card.judgment.suggestions
  const sources = suggestions.map((item) => item.source)
  const result =
    suggestions.length > 0 && suggestions.every((item) => item.source === 'fallback') ? 'fallback' : 'sourced'
  const problems: string[] = []
  if (claim.asserted !== result) problems.push(`实际 ${result}，主张 ${claim.asserted}`)
  if (claim.sources !== null && !jsonEqual(sources, claim.sources)) {
    problems.push(`来源不符（账本 [${sources.join(', ')}] ≠ 主张 [${claim.sources.join(', ')}]）`)
  }
  if (claim.contains !== null) {
    const text = suggestions.map((item) => item.text).join('\n')
    const missing = claim.contains.filter((term) => !text.includes(term))
    if (missing.length > 0) problems.push(`建议文本缺少：${missing.join('、')}`)
  }
  return {
    result,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `整改建议 ${result}（来源 ${sources.join('、')}）`
        : `整改建议不符：${problems.join('；')}`,
    evidence: { suggestions: suggestions.map((item) => ({ source: item.source, text: item.text })), sources },
  }
}

function computeGraph(context: Context, claim: Claim): Computed {
  const graph = context.graph()
  const stats = graph.stats() as {
    node_count: number
    edge_count: number
    nodes_by_type: Record<string, number>
    edges_by_relation: Record<string, number>
  }
  let count: number
  switch (claim.of) {
    case 'node-count':
      count = stats.node_count
      break
    case 'edge-count':
      count = stats.edge_count
      break
    case 'nodes-of-type':
      count = stats.nodes_by_type[claim.nodeType as string] ?? 0
      break
    case 'edges-of-relation':
      count = stats.edges_by_relation[claim.relation as string] ?? 0
      break
    case 'neighbors':
      count = graph.neighbors(claim.nodeId as string, claim.relation ?? undefined).length
      break
    default:
      throw new ContractError(`graph 的 of 非法：${String(claim.of)}`)
  }
  const expected = Number(claim.asserted)
  return {
    result: String(count),
    matched: count === expected,
    reason: count === expected ? `图谱 ${claim.of} = ${count}，与主张一致` : `图谱 ${claim.of} = ${count} ≠ 主张 ${expected}`,
    evidence: {
      of: claim.of,
      count,
      ...(claim.nodeType !== null ? { node_type: claim.nodeType } : {}),
      ...(claim.relation !== null ? { relation: claim.relation } : {}),
      ...(claim.nodeId !== null ? { node_id: claim.nodeId } : {}),
      node_count: stats.node_count,
      edge_count: stats.edge_count,
    },
  }
}

function computeNode(context: Context, claim: Claim): Computed {
  const nodeId = claim.nodeId as string
  const graph = context.graph()
  const node = graph.getNode(nodeId)
  const present = node !== undefined
  const problems: string[] = []
  if (claim.asserted !== (present ? 'present' : 'absent')) {
    problems.push(`实际 ${present ? 'present' : 'absent'}，主张 ${claim.asserted}`)
  }
  if (node !== undefined && claim.nodeType !== null && node.type !== claim.nodeType) {
    problems.push(`节点类型不符（账本 ${node.type} ≠ 主张 ${claim.nodeType}）`)
  }
  const relations = graph.neighbors(nodeId).map(([, relation]) => relation)
  if (node !== undefined && claim.relations !== null) {
    const missing = claim.relations.filter((relation) => !relations.includes(relation))
    if (missing.length > 0) problems.push(`缺关系：${missing.join('、')}`)
  }
  return {
    result: present ? 'present' : 'absent',
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `节点 ${nodeId} ${present ? `存在（${node?.type ?? '?'}）` : '不存在'}`
        : `节点核对失败：${problems.join('；')}`,
    evidence: {
      node_id: nodeId,
      node_present: present,
      node_type: node?.type ?? null,
      relations: [...new Set(relations)].sort(),
    },
  }
}

function computeSchema(context: Context, claim: Claim): Computed {
  const knowledge = context.knowledge
  let count: number
  switch (claim.of) {
    case 'hazard-types':
      count = knowledge.hazardTypes.length
      break
    case 'measures':
      count = knowledge.measures.length
      break
    case 'regulations':
      count = knowledge.regulations.length
      break
    case 'thresholds':
      count = knowledge.thresholds.length
      break
    case 'overrides':
      count = knowledge.rules.overrides.length
      break
    case 'threshold-rules':
      count = knowledge.rules.threshold_rules.length
      break
    case 'base-rules':
      count = knowledge.rules.base_rules.length
      break
    case 'patterns':
      count = knowledge.hazardTypes.filter((hazard) => hazard.patterns.length > 0).length
      break
    default:
      throw new ContractError(`schema 的 of 非法：${String(claim.of)}`)
  }
  const expected = Number(claim.asserted)
  return {
    result: String(count),
    matched: count === expected,
    reason: count === expected ? `知识库 ${claim.of} = ${count}，与主张一致` : `知识库 ${claim.of} = ${count} ≠ 主张 ${expected}`,
    evidence: { of: claim.of, count },
  }
}

function consistencyProblems(context: Context, kind: string): string[] {
  const knowledge = context.knowledge
  const problems: string[] = []
  if (kind === 'base-rules') {
    for (const hazard of knowledge.hazardTypes) {
      const rule = knowledge.rules.base_rules.find((candidate) => candidate.hazard_type_id === hazard.id)
      if (rule === undefined) problems.push(`${hazard.id} 缺少 base_rule`)
      else if (rule.base_level !== hazard.base_level) {
        problems.push(`${hazard.id} base_level 不一致（${hazard.base_level} ≠ ${rule.base_level}）`)
      }
    }
    return problems
  }
  if (kind === 'pattern-coverage') {
    for (const hazard of knowledge.hazardTypes) {
      if (hazard.patterns.length === 0) problems.push(`${hazard.id} 缺少 patterns`)
      for (const pattern of hazard.patterns) {
        try {
          new RegExp(pattern)
        } catch (error) {
          problems.push(`${hazard.id} 的 pattern 不可编译：${pattern}（${(error as Error).message}）`)
        }
      }
    }
    return problems
  }
  if (kind === 'measure-refs') {
    for (const hazard of knowledge.hazardTypes) {
      for (const measureId of hazard.measure_ids) {
        if (!knowledge.measureById.has(measureId)) problems.push(`${hazard.id} 引用不存在的措施 ${measureId}`)
      }
    }
    return problems
  }
  if (kind === 'clause-refs' || kind === 'kg-nodes') {
    const graph = kind === 'kg-nodes' ? context.graph() : null
    for (const hazard of knowledge.hazardTypes) {
      for (const ref of hazard.clause_refs) {
        if (graph !== null) {
          if (!graph.hasNode(kgNodeId(ref.standard, ref.clause))) {
            problems.push(`${hazard.id} 的条款节点不在图中：${ref.standard} ${ref.clause}`)
          }
        } else if (!knowledge.regulationByKey.has(`${ref.standard}\u0000${ref.clause}`)) {
          problems.push(`${hazard.id} 引用不存在的条款：${ref.standard} ${ref.clause}`)
        }
      }
    }
    return problems
  }
  if (kind === 'rule-fallback') {
    if (!jsonEqual(knowledge.rules.major_patterns, MAJOR_PATTERNS)) {
      problems.push('rules.major_patterns 与模块兜底常量不一致')
    }
    if (!jsonEqual(knowledge.rules.severity_words, SEVERITY_WORDS)) {
      problems.push('rules.severity_words 与模块兜底常量不一致')
    }
    return problems
  }
  throw new ContractError(`consistency 的 kind 非法：${kind}`)
}

function computeConsistency(context: Context, claim: Claim): Computed {
  const problems = consistencyProblems(context, claim.kind as string)
  const result = problems.length === 0 ? 'consistent' : 'inconsistent'
  return {
    result,
    matched: claim.asserted === result,
    reason:
      claim.asserted === result
        ? result === 'consistent'
          ? `一致性核对通过（${claim.kind}）`
          : `一致性核对失败 ${problems.length} 项（${claim.kind}）`
        : `实际 ${result}，主张 ${claim.asserted}`,
    evidence: { kind: claim.kind, problems, problem_count: problems.length },
  }
}

function computeVision(context: Context, claim: Claim): Computed {
  const vision = context.vision
  if (vision === null) throw new ContractError('vision 主张需要 vision.images')
  const image = vision.images.find(
    (candidate) => candidate.name === claim.image || baseName(candidate.name) === claim.image,
  )
  if (image === undefined) {
    return {
      result: 'absent',
      matched: false,
      reason: `vision.images 中没有 ${String(claim.image)}`,
      evidence: { image: claim.image },
    }
  }
  const index = claim.detectionIndex as number
  if (index < 1 || index > image.detections.length) {
    return {
      result: 'absent',
      matched: false,
      reason: `${image.name} 的第 ${index} 条检出不存在（共 ${image.detections.length} 条）`,
      evidence: { image: image.name, detection_index: index, detection_count: image.detections.length },
    }
  }
  const { card, warning } = cardFromDetection(image.name, index, image.detections[index - 1], context.knowledge)
  const result = card === null ? 'dropped' : 'mapped'
  const problems: string[] = []
  if (claim.asserted !== result) problems.push(`实际 ${result}，主张 ${claim.asserted}`)
  if (card !== null) {
    const actual = {
      hazard_type_id: card.hazard_type_id,
      hazard_type: card.hazard_type,
      confidence: card.confidence,
      bbox: card.attrs.bbox,
    }
    problems.push(
      ...compareFields(actual, [
        ['hazard_type_id', claim.hazardTypeId],
        ['confidence', claim.confidence],
        ['bbox', claim.bbox],
      ]),
    )
  }
  return {
    result,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? card !== null
          ? `${image.name} 第 ${index} 条检出映射 ${card.hazard_type_id}`
          : `${image.name} 第 ${index} 条检出被丢弃（${warning ?? '未登记类别'}）`
        : `视觉检出核对失败：${problems.join('；')}`,
    evidence: {
      image: image.name,
      detection_index: index,
      detection_class: image.detections[index - 1].class_name,
      warning,
      hazard_type_id: card?.hazard_type_id ?? null,
      bbox: card?.attrs.bbox ?? null,
      confidence: card?.confidence ?? null,
    },
  }
}

function computeMerge(context: Context, claim: Claim): Computed {
  const card = context.findCard(claim.recordIndex as number, claim.hazardTypeId as string)
  if (card === undefined) {
    return {
      result: 'absent',
      matched: false,
      reason: `记录 ${String(claim.recordIndex)} / ${String(claim.hazardTypeId)} 没有条目卡，无法核对融合`,
      evidence: { record_index: claim.recordIndex, hazard_type_id: claim.hazardTypeId },
    }
  }
  const merged = card.merged_from.includes('rules') && card.merged_from.includes('vision')
  const result = merged ? 'merged' : 'unmerged'
  const evidenceVision = Array.isArray(card.evidence.vision) ? (card.evidence.vision as Array<Record<string, unknown>>) : []
  const evidenceImages = evidenceVision.map((item) => String(item.image ?? ''))
  const problems: string[] = []
  if (claim.asserted !== result) problems.push(`实际 ${result}，主张 ${claim.asserted}`)
  if (claim.mergedFrom !== null && !jsonEqual(card.merged_from, claim.mergedFrom)) {
    problems.push(`merged_from 不符（账本 [${card.merged_from.join(', ')}] ≠ 主张 [${claim.mergedFrom.join(', ')}]）`)
  }
  if (claim.confidence !== null && card.confidence !== claim.confidence) {
    problems.push(`confidence 不符（账本 ${card.confidence} ≠ 主张 ${claim.confidence}）`)
  }
  if (claim.evidenceImages !== null && !jsonEqual(evidenceImages, claim.evidenceImages)) {
    problems.push(`证据图像不符（账本 [${evidenceImages.join(', ')}] ≠ 主张 [${claim.evidenceImages.join(', ')}]）`)
  }
  return {
    result,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `条目卡 ${result}（merged_from=[${card.merged_from.join(', ')}]，confidence=${card.confidence}）`
        : `融合核对失败：${problems.join('；')}`,
    evidence: {
      merged_from: card.merged_from,
      confidence: card.confidence,
      evidence_images: evidenceImages,
    },
  }
}

function fallbackFor(
  context: Context,
  card: JudgedCard,
  claim: Claim | null,
  minScoreOverride?: number,
): FallbackClause[] {
  if (card.judgment.clause_refs.length > 0) return []
  const minScore = minScoreOverride ?? claim?.minScore ?? 0.05
  const query = `${card.quote} ${card.hazard_type}`
  const candidates: FallbackClause[] = []
  for (const { doc, score } of context.vectorIndex().search(query, 2)) {
    if (score < minScore) continue
    candidates.push({
      standard: doc.standard,
      clause: doc.clause,
      std_name: doc.std_name,
      score,
      note: '向量检索兜底候选，非判定依据（以官方文本为准）',
    })
  }
  return candidates
}

function computeFallback(context: Context, claim: Claim): Computed {
  const card = context.findCard(claim.recordIndex as number, claim.hazardTypeId as string)
  if (card === undefined) {
    return {
      result: 'absent',
      matched: claim.asserted === 'none',
      reason: `记录 ${String(claim.recordIndex)} / ${String(claim.hazardTypeId)} 没有条目卡`,
      evidence: { record_index: claim.recordIndex, hazard_type_id: claim.hazardTypeId },
    }
  }
  const candidates = fallbackFor(context, card, claim)
  const result = candidates.length > 0 ? 'candidates' : 'none'
  const problems: string[] = []
  if (claim.asserted !== result) problems.push(`实际 ${result}，主张 ${claim.asserted}`)
  if (claim.clauses !== null) {
    const actual = candidates.map((item) => ({ standard: item.standard, clause: item.clause }))
    if (!jsonEqual(actual, claim.clauses)) {
      problems.push(`兜底候选不符（账本 ${actual.map((item) => `${item.standard} ${item.clause}`).join('、') || '空'} ≠ 主张 ${claim.clauses.map((item) => `${item.standard} ${item.clause}`).join('、') || '空'}）`)
    }
  }
  return {
    result,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `兜底候选 ${result}（${candidates.map((item) => `${item.standard} ${item.clause}`).join('、') || '空'}）`
        : `兜底候选核对失败：${problems.join('；')}`,
    evidence: {
      candidates: candidates.map((item) => ({
        standard: item.standard,
        clause: item.clause,
        std_name: item.std_name,
        score: item.score,
        note: item.note,
      })),
      clause_refs_empty: card.judgment.clause_refs.length === 0,
    },
  }
}

function computeKeyframes(context: Context, claim: Claim): Computed {
  const video = context.video
  const totalFrames = claim.totalFrames ?? video?.totalFrames
  const maxFrames = claim.maxFrames ?? video?.maxFrames ?? 8
  if (totalFrames === undefined) throw new ContractError('keyframes 主张需要 total_frames')
  const frames = selectKeyframes(totalFrames, maxFrames)
  const result = frames.join(',')
  const problems: string[] = []
  if (claim.frames === null) {
    if (String(Number(claim.asserted)) !== String(frames.length)) problems.push(`实际 ${frames.length} 帧，主张 ${claim.asserted}`)
  } else if (!jsonEqual(frames, claim.frames)) {
    problems.push(`帧号不符（账本 [${frames.join(', ')}] ≠ 主张 [${claim.frames.join(', ')}]）`)
  }
  return {
    result,
    matched: problems.length === 0,
    reason:
      problems.length === 0
        ? `关键帧选择成立（total=${totalFrames} max=${maxFrames} → [${frames.join(', ')}]）`
        : `关键帧选择不符：${problems.join('；')}`,
    evidence: { total_frames: totalFrames, max_frames: maxFrames, frames },
  }
}

function computePaired(context: Context, claim: Claim): Computed {
  const diffs = context.pairedDiffs()
  const hit = diffs.find((diff) => diff.kind === claim.kind && diff.timestamp === claim.timestamp)
  const present = hit !== undefined
  const result = present ? 'present' : 'absent'
  return {
    result,
    matched: claim.asserted === result,
    reason:
      claim.asserted === result
        ? `配对差异 ${result}（${String(claim.kind)}@${String(claim.timestamp)}）`
        : `实际 ${result}，主张 ${claim.asserted}（${String(claim.kind)}@${String(claim.timestamp)}）`,
    evidence: {
      kind: claim.kind,
      timestamp: claim.timestamp,
      diff: hit ?? null,
      diffs: diffs.map((diff) => ({ kind: diff.kind, timestamp: diff.timestamp })),
    },
  }
}

function metricValue(context: Context, claim: Claim): { value: number | null; label: string } {
  const metrics = context.metrics()
  switch (claim.of) {
    case 'micro-f1':
      return { value: metrics.micro.f1, label: 'micro.f1' }
    case 'micro-precision':
      return { value: metrics.micro.precision, label: 'micro.precision' }
    case 'micro-recall':
      return { value: metrics.micro.recall, label: 'micro.recall' }
    case 'micro-fp':
      return { value: metrics.micro.fp, label: 'micro.fp' }
    case 'level-accuracy':
      return { value: metrics.level_accuracy, label: 'level_accuracy' }
    case 'detection-rate':
      return { value: metrics.detection_rate, label: 'end_to_end.detection_rate' }
    case 'false-positive-rate':
      return { value: metrics.false_positive_rate, label: 'end_to_end.false_positive_rate' }
    case 'field-f1':
      if (claim.field === null) throw new ContractError('field-f1 主张必须带 field')
      return { value: metrics.field_f1[claim.field], label: `field_level.${claim.field}.f1` }
    default:
      throw new ContractError(`metric 的 of 非法：${String(claim.of)}`)
  }
}

function computeMetric(context: Context, claim: Claim): Computed {
  const { value, label } = metricValue(context, claim)
  if (value === null) {
    return {
      result: 'none',
      matched: false,
      reason: `${label} 不可计算（无对齐样本）`,
      evidence: { of: claim.of, field: claim.field, value: null, metrics: context.metrics() as unknown as Record<string, unknown> },
    }
  }
  const expected = Number(claim.asserted)
  const tolerance = claim.tolerance ?? 0
  const matched = Math.abs(value - expected) <= tolerance
  return {
    result: String(value),
    matched,
    reason: matched
      ? `重算 ${label} = ${value}，与主张 ${expected} 一致${tolerance > 0 ? `（容差 ${tolerance}）` : ''}`
      : `重算 ${label} = ${value} ≠ 主张 ${expected}（容差 ${tolerance}）`,
    evidence: {
      of: claim.of,
      field: claim.field,
      value,
      tolerance,
      metrics: context.metrics() as unknown as Record<string, unknown>,
    },
  }
}

function computeCandidate(context: Context, claim: Claim): Computed {
  const record = findRecord(context, claim)
  if (record === undefined) {
    return {
      result: 'absent',
      matched: false,
      reason: `记录序号 ${String(claim.recordIndex)} 不在解析结果中`,
      evidence: { record_index: claim.recordIndex },
    }
  }
  const quote = claim.quote ?? ''
  let valid = quote.length > 0 && record.text.includes(quote)
  if (!context.knowledge.hazardTypeById.has(claim.hazardTypeId as string)) valid = false
  if (claim.category !== null && !context.knowledge.categories.includes(claim.category)) valid = false
  const result = valid ? 'valid' : 'invalid'
  return {
    result,
    matched: claim.asserted === result,
    reason:
      claim.asserted === result
        ? `候选校验 ${result}${valid ? '' : `（${!quote || !record.text.includes(quote) ? '摘录不是原文子串' : '词表/类别未命中'}）`}`
        : `实际 ${result}，主张 ${claim.asserted}`,
    evidence: {
      record_index: record.index,
      hazard_type_id: claim.hazardTypeId,
      quote,
      quote_in_text: quote.length > 0 && record.text.includes(quote),
      hazard_type_known: context.knowledge.hazardTypeById.has(claim.hazardTypeId as string),
      category_known: claim.category === null ? null : context.knowledge.categories.includes(claim.category),
    },
  }
}

function computeClaim(context: Context, claim: Claim): Computed {
  switch (claim.check) {
    case 'hazard':
      return computeHazard(context, claim)
    case 'count':
      return computeCount(context, claim)
    case 'level':
      return computeLevel(context, claim)
    case 'clause':
      return computeClause(context, claim)
    case 'anchor':
      return computeAnchor(context, claim)
    case 'suggestion':
      return computeSuggestion(context, claim)
    case 'graph':
      return computeGraph(context, claim)
    case 'node':
      return computeNode(context, claim)
    case 'schema':
      return computeSchema(context, claim)
    case 'consistency':
      return computeConsistency(context, claim)
    case 'vision':
      return computeVision(context, claim)
    case 'merge':
      return computeMerge(context, claim)
    case 'fallback':
      return computeFallback(context, claim)
    case 'keyframes':
      return computeKeyframes(context, claim)
    case 'paired':
      return computePaired(context, claim)
    case 'metric':
      return computeMetric(context, claim)
    case 'candidate':
      return computeCandidate(context, claim)
    case 'record':
      return computeRecord(context, claim)
    default:
      throw new ContractError(`未知 check：${String(claim.check)}`)
  }
}

// ---------------------------------------------------------------------------
// 账本行
// ---------------------------------------------------------------------------

function claimLabel(claim: Claim): string {
  const target = `${String(claim.recordIndex ?? '-')}/${String(claim.hazardTypeId ?? '-')}`
  switch (claim.check) {
    case 'hazard':
      return `${target} = ${claim.asserted}`
    case 'count':
      return `${String(claim.of)} = ${claim.asserted}`
    case 'level':
      return `${target} level = ${claim.asserted}`
    case 'clause':
      return `${target} clause = ${claim.asserted}`
    case 'anchor':
      return `${String(claim.standard)} ${String(claim.clause)} anchor = ${String(claim.anchor)}`
    case 'suggestion':
      return `${target} suggestion = ${claim.asserted}`
    case 'graph':
      return `graph ${String(claim.of)} = ${claim.asserted}`
    case 'node':
      return `node ${String(claim.nodeId)} = ${claim.asserted}`
    case 'schema':
      return `schema ${String(claim.of)} = ${claim.asserted}`
    case 'consistency':
      return `consistency ${String(claim.kind)} = ${claim.asserted}`
    case 'vision':
      return `vision ${String(claim.image)}#${String(claim.detectionIndex)} = ${claim.asserted}`
    case 'merge':
      return `${target} merge = ${claim.asserted}`
    case 'fallback':
      return `${target} fallback = ${claim.asserted}`
    case 'keyframes':
      return `keyframes(${String(claim.totalFrames)}) = ${claim.asserted}`
    case 'paired':
      return `paired ${String(claim.kind)}@${String(claim.timestamp)} = ${claim.asserted}`
    case 'metric':
      return `metric ${String(claim.of)} = ${claim.asserted}`
    case 'candidate':
      return `${target} candidate = ${claim.asserted}`
    case 'record':
      return `record ${String(claim.recordIndex)} = ${claim.asserted}`
    default:
      return `${claim.check} = ${claim.asserted}`
  }
}

function resolveNode(basis: Basis, raw: unknown, claimId: string): TraceNode | null {
  if (raw === undefined || raw === null) return null
  if (!isPlainObject(raw)) throw new ContractError(`${claimId}：node 必须是对象`)
  const sessionId = raw.session_id
  if (typeof sessionId !== 'string' || !sessionId.trim()) {
    throw new ContractError(`${claimId}：node.session_id 必须是非空字符串`)
  }
  const turnRaw = raw.turn
  let turn: number | null = null
  if (turnRaw !== undefined && turnRaw !== null) {
    const numeric = Number(turnRaw)
    if (!Number.isInteger(numeric)) throw new ContractError(`${claimId}：node.turn 必须是整数`)
    turn = numeric
  }
  const toolCallId = raw.tool_call_id
  if (typeof toolCallId !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  return basis.ref(sessionId.trim(), turn, toolCallId)
}

function buildRecord(claim: Claim, computed: Computed, node: TraceNode | null): LedgerRecord {
  const verdict: Verdict = computed.matched ? CLAIM : node === null ? INCONCLUSIVE : REFUTED
  const message = computed.matched
    ? `主张「${claimLabel(claim)}」被同一份输入上的重算支持：${computed.reason}`
    : node === null
      ? `重算与主张不符（${computed.reason}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`
      : `重算推翻主张：${computed.reason}`
  return makeRecord({
    claim_id: claim.claimId,
    verdict,
    message,
    node,
    evidence: {
      check: claim.check,
      asserted: claim.asserted,
      computed: computed.result,
      comparison: computed.matched ? 'match' : 'mismatch',
      ...computed.evidence,
    },
  })
}

// ---------------------------------------------------------------------------
// 器官主体
// ---------------------------------------------------------------------------

export function evaluateHazardTriage(
  subject: Record<string, unknown>,
  basis: Basis,
): LedgerRecord[] {
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const context = new Context(subject)
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }
  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    records.push(buildRecord(claim, computeClaim(context, claim), node))
  }
  return records
}

export const hazardTriageVerb: Verb = register({
  slug: 'hazard-triage',
  version: VERSION,
  summary: '施工安全风险研判取证：日志解析 / 隐患抽取 / 条款关联 / 四级判定 / 整改建议，逐条核对主张',
  input_fields: ['claims'],
  evaluate: evaluateHazardTriage,
})

export { KnowledgePackError }
export default hazardTriageVerb