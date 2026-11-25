/**
 * pipeline-run · IR 归一化（迁自旧仓 `src/ir.ts`）：
 * `PipelineDef` -> 确定有序的执行图。
 *
 * 冻结规则（旧仓 HANDOFF 口径 1 / plan/04 真值语义）：
 * - 显式 `dependsOn` 覆盖隐式线性串接（隐式 = 定义顺序上的前一节点）；
 * - 模板引用 `{{var}}` 也产生依赖边；
 * - 未知模板变量在编译期拒绝；
 * - 引用 skip 策略节点的输出是语义错误（skip 节点输出为 null，消费它 = 值错误）；
 * - 拓扑序用 Kahn + 定义顺序 tie-break（同输入 -> 同 IR，永远）。
 *
 * M2 feature gates 原样保留：`tools` / `model.reasoningEffort` /
 * `options.maxAgentsPerNode` 仍以 IR_UNSUPPORTED_FEATURE 拒绝。
 */

import defaults from './data/pipeline-run-defaults.json' with { type: 'json' }
import { ErrorCode, PipelineError } from './errors.js'
import { assertObjectJsonSchema } from './json-schema.js'
import type { PipelineDef, PipelineNode } from './schema.js'
import { renderUnknown } from './util.js'

/** 保留模板变量：本次运行的输入。 */
export const INPUT_VARIABLE = defaults.reserved_ids[0]
/** 节点内变量：上一条 prompt 的输出。 */
export const PREV_VARIABLE = defaults.reserved_ids[1]

const TEMPLATE_PATTERN = defaults.template_pattern

export type TemplateRef =
  | { kind: 'input' }
  | { kind: 'prev' }
  | { kind: 'node'; id: string }

export interface IRPrompt {
  template: string
  refs: TemplateRef[]
}

export interface IRNode {
  id: string
  label: string | undefined
  /** phase() 标题与 agent() label 词干：有 label 用 label，否则 id。 */
  phaseTitle: string
  prompts: IRPrompt[]
  agentOptions: { provider?: string; model?: string }
  outputSchema: Record<string, unknown> | undefined
  /** 声明的技能名（定义序）；undefined = 无技能路由。 */
  skills: string[] | undefined
  /** 解析后的失败策略：node.failurePolicy ?? options.defaultFailurePolicy ?? 'abort'。 */
  failurePolicy: 'abort' | 'skip'
  /** 解析后的重试次数（首次尝试之外的整节点重跑次数）。 */
  retry: number
  needsAgentOptions: boolean
  needsOutputSchema: boolean
  needsSkills: boolean
}

export interface PipelineIR {
  name: string
  description: string
  /** 拓扑序节点（定义顺序 tie-break）。 */
  nodes: IRNode[]
  /** 编译脚本可能发起的 agent() 调用精确上界：sum(prompts.length * (1 + retry))。 */
  totalAgentCalls: number
}

interface ParsedPrompt {
  template: string
  refs: TemplateRef[]
  /** refs 的来源位置，如 `nodes[1].prompts[2]`（定义序）。 */
  location: string
}

export type TemplateSegment =
  | { kind: 'static'; text: string }
  | { kind: 'ref'; ref: TemplateRef }

function refFor(name: string): TemplateRef {
  if (name === INPUT_VARIABLE) return { kind: 'input' }
  if (name === PREV_VARIABLE) return { kind: 'prev' }
  return { kind: 'node', id: name }
}

/** 在 `template[from..]` 上匹配一个模板变量；不是从 from 开始的匹配返回 null。 */
function matchVariableAt(template: string, from: number): string | null {
  const rest = template.slice(from)
  const pattern = new RegExp(TEMPLATE_PATTERN)
  const match = rest.match(pattern)
  if (match === null || match.index !== 0) return null
  return match[0]
}

/**
 * 把 prompt 模板切成静态段与引用段（顺序保持）。
 * 任何不构成完整变量表达式的 `{{` 都是模板错误（fail loud，不静默当字面量）。
 */
export function segmentTemplate(template: string, location: string): TemplateSegment[] {
  const segments: TemplateSegment[] = []
  let cursor = 0
  while (cursor < template.length) {
    const open = template.indexOf('{{', cursor)
    if (open === -1) break
    const whole = matchVariableAt(template, open)
    if (whole === null) {
      throw new PipelineError(ErrorCode.unknownVariable, `模板表达式不合法：${location}（偏移 ${open}）`)
    }
    const name = whole.slice(2, -2).trim()
    if (open > cursor) segments.push({ kind: 'static', text: template.slice(cursor, open) })
    segments.push({ kind: 'ref', ref: refFor(name) })
    cursor = open + whole.length
  }
  if (cursor < template.length) segments.push({ kind: 'static', text: template.slice(cursor) })
  return segments
}

function parseTemplate(template: string, location: string): TemplateRef[] {
  return segmentTemplate(template, location)
    .filter((segment): segment is { kind: 'ref'; ref: TemplateRef } => segment.kind === 'ref')
    .map((segment) => segment.ref)
}

export function buildIR(def: PipelineDef): PipelineIR {
  assertM2FeatureGates(def)

  const byId = new Map<string, { node: PipelineNode; index: number }>()
  for (const [index, node] of def.nodes.entries()) {
    if (byId.has(node.id)) {
      throw new PipelineError(ErrorCode.duplicateId, `节点 id 重复："${node.id}"`)
    }
    if (node.id === INPUT_VARIABLE || node.id === PREV_VARIABLE) {
      throw new PipelineError(ErrorCode.reservedId, `节点 id "${node.id}" 是保留变量名`)
    }
    byId.set(node.id, { node, index })
  }

  // 失败策略按节点本地解析，先于任何引用检查（skip 引用规则需要目标策略）。
  const skipPolicyIds = new Set<string>()
  for (const node of def.nodes) {
    const policy = node.failurePolicy ?? def.options?.defaultFailurePolicy ?? 'abort'
    if (policy === 'skip') skipPolicyIds.add(node.id)
  }

  // 依赖边：显式 dependsOn / 隐式串接 / 模板引用。
  const deps = new Map<string, Set<string>>()
  const addEdge = (from: string, to: string, why: string): void => {
    if (from === to) {
      throw new PipelineError(ErrorCode.selfDependency, `节点 "${from}" 依赖自己（${why}）`)
    }
    const set = deps.get(from) ?? new Set<string>()
    set.add(to)
    deps.set(from, set)
  }

  const prompts: ParsedPrompt[][] = []
  for (const [index, node] of def.nodes.entries()) {
    const id = node.id
    const parsed: ParsedPrompt[] = []
    node.prompts.forEach((template, promptIndex) => {
      const location = `nodes[${index}].prompts[${promptIndex}] (node "${id}")`
      const refs = parseTemplate(template, location)
      for (const ref of refs) {
        if (ref.kind === 'prev' && promptIndex === 0) {
          throw new PipelineError(ErrorCode.unknownVariable, `首条 prompt 不能引用 {{prev}}：${location}`)
        }
        if (ref.kind === 'node') {
          if (ref.id === id) {
            throw new PipelineError(ErrorCode.selfReference, `节点 "${id}" 的 prompt 引用了自己：${location}`)
          }
          if (!byId.has(ref.id)) {
            const available = [...byId.keys()].map((key) => `"${key}"`).join(', ')
            throw new PipelineError(
              ErrorCode.unknownVariable,
              `未知模板变量 {{${ref.id}}}：${location}（可用：${available}）`,
            )
          }
          if (skipPolicyIds.has(ref.id)) {
            throw new PipelineError(
              ErrorCode.skipReference,
              `引用了 failure policy "skip" 的节点输出 {{${ref.id}}}：${location}；skip 节点输出为 null，请用 dependsOn 只表达顺序`,
            )
          }
        }
      }
      parsed.push({ template, refs, location })
    })
    prompts.push(parsed)

    const existing = node.dependsOn
    if (existing !== undefined) {
      for (const dep of existing) {
        if (!byId.has(dep)) {
          const available = [...byId.keys()].map((key) => `"${key}"`).join(', ')
          throw new PipelineError(
            ErrorCode.unknownDependency,
            `节点 "${id}" 依赖未知节点 "${dep}"（可用：${available}）`,
          )
        }
        addEdge(id, dep, 'dependsOn')
      }
    } else if (index > 0) {
      addEdge(id, def.nodes[index - 1].id, 'implicit linear chaining')
    }

    for (const { refs, location } of parsed) {
      for (const ref of refs) {
        if (ref.kind === 'node') addEdge(id, ref.id, `template reference in ${location}`)
      }
    }
  }

  const order = topologicalOrder(def, deps)
  const irNodes = order.map((index): IRNode => {
    const node = def.nodes[index]
    const agentOptions: { provider?: string; model?: string } = {}
    if (node.model?.provider !== undefined) agentOptions.provider = node.model.provider
    if (node.model?.model !== undefined) agentOptions.model = node.model.model

    let outputSchema: Record<string, unknown> | undefined
    if (node.outputSchema !== undefined) {
      try {
        assertObjectJsonSchema(node.outputSchema)
        outputSchema = node.outputSchema
      } catch (err) {
        throw new PipelineError(
          ErrorCode.outputSchema,
          `nodes[${index}] (node "${node.id}")：${renderUnknown(err)}`,
        )
      }
    }

    const failurePolicy = node.failurePolicy ?? def.options?.defaultFailurePolicy ?? 'abort'
    const retry = node.retry ?? 0
    return {
      id: node.id,
      label: node.label,
      phaseTitle: node.label ?? node.id,
      prompts: prompts[index].map(({ template, refs }) => ({ template, refs })),
      agentOptions,
      outputSchema,
      skills: node.skills,
      failurePolicy,
      retry,
      needsAgentOptions: agentOptions.provider !== undefined || agentOptions.model !== undefined,
      needsOutputSchema: outputSchema !== undefined,
      needsSkills: node.skills !== undefined,
    }
  })

  return {
    name: def.name,
    description: def.description,
    nodes: irNodes,
    totalAgentCalls: irNodes.reduce((sum, node) => sum + node.prompts.length * (1 + node.retry), 0),
  }
}

function topologicalOrder(def: PipelineDef, deps: Map<string, Set<string>>): number[] {
  const remaining = new Map<string, Set<string>>()
  for (const node of def.nodes) {
    remaining.set(node.id, new Set(deps.get(node.id) ?? []))
  }
  const dependents = new Map<string, Set<string>>()
  for (const [id, set] of remaining) {
    for (const dep of set) {
      const back = dependents.get(dep) ?? new Set<string>()
      back.add(id)
      dependents.set(dep, back)
    }
  }

  const order: number[] = []
  const emitted = new Set<string>()
  while (order.length < def.nodes.length) {
    let next = -1
    for (const [index, node] of def.nodes.entries()) {
      if (!emitted.has(node.id) && (remaining.get(node.id)?.size ?? 0) === 0) {
        next = index
        break
      }
    }
    if (next === -1) {
      const stuck = def.nodes.filter((n) => !emitted.has(n.id)).map((n) => `"${n.id}"`)
      throw new PipelineError(ErrorCode.dependencyCycle, `依赖成环，无法拓扑排序：${stuck.join(' -> ')}`)
    }
    const id = def.nodes[next].id
    emitted.add(id)
    order.push(next)
    for (const dependent of dependents.get(id) ?? []) {
      remaining.get(dependent)?.delete(id)
    }
  }
  return order
}

/**
 * M2 feature gates（旧仓 plan/06）：只有引擎无法兑现的路由继续拒绝。
 * 失败策略 / retry / 默认策略 / skills 已在 M2 解封（skills 在 runner 运行期解析，
 * 策略编译进脚本）；maxAgentsPerNode 仍 gated（引擎上限是引擎自有，没有节点级 seam）。
 */
function assertM2FeatureGates(def: PipelineDef): void {
  const gate = (message: string): PipelineError =>
    new PipelineError(ErrorCode.unsupportedFeature, message)

  if (def.options !== undefined && def.options.maxAgentsPerNode !== undefined) {
    throw gate(`options.maxAgentsPerNode 不被引擎支持（pipeline "${def.name}"）`)
  }

  for (const [index, node] of def.nodes.entries()) {
    const where = `nodes[${index}] (node "${node.id}")`
    if (node.tools !== undefined) throw gate(`${where} 声明了 tools：当前引擎没有 agent() toolFilter 通路`)
    if (node.model?.reasoningEffort !== undefined) throw gate(`${where} 声明了 model.reasoningEffort：当前引擎直接拒绝 effort`)
  }
}