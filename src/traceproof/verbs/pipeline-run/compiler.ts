/**
 * pipeline-run · 编译器（迁自旧仓 `src/compiler.ts`）：
 * `PipelineIR` -> 普通 JS workflow 引擎脚本。
 *
 * 产物序列化是**冻结格式**（旧仓 HANDOFF 口径 2）：2 空格缩进、`agent()` 选项字段序
 * = label / provider / model / schema、节点语句按 IR（拓扑）序、两行头（版本 /
 * 节点与调用计数 / 每节点策略）。任何排版改动都是口径变更，必须重冻快照并重跑 B1–B4。
 *
 * 安全规则（与旧仓一致）：
 * - 本模块不用 eval / Function；输出是普通字符串，交给引擎自己的 worker realm；
 * - 模板插值 JSON 安全：静态段是 JSON 转义后的 JS 字符串字面量，引用 outputSchema
 *   节点时包一层 JSON.stringify，对象不会渲染成 "[object Object]"。
 */

import defaults from './data/pipeline-run-defaults.json' with { type: 'json' }
import { ErrorCode, PipelineError } from './errors.js'
import { segmentTemplate } from './ir.js'
import type { IRNode, PipelineIR, TemplateRef } from './ir.js'

const IND = '  '
const PIPELINE_VERSION = defaults.pipeline_version

/** 每节点 id -> 已渲染的技能块（按声明顺序）。 */
export type ResolvedSkills = Map<string, string[]>

export function compileScript(ir: PipelineIR, skills?: ResolvedSkills): string {
  const lines: string[] = []
  lines.push(`// dsh-pipeline ${PIPELINE_VERSION} — compiled pipeline "${ir.name}".`)
  lines.push(`// ${headerStats(ir)}`)
  lines.push(`const out = {};`)
  for (const node of ir.nodes) {
    emitNode(ir, lines, node, skills)
  }
  lines.push(`return { nodes: out };`)
  return lines.join('\n') + '\n'
}

/**
 * 头行 2（冻结格式）：节点数、agent 调用精确上界（prompts × (1 + retry)）、
 * 以及拓扑序上每个节点的解析策略；有 retry 时追加 `:<retry>`。
 */
function headerStats(ir: PipelineIR): string {
  const nodeNoun = ir.nodes.length === 1 ? 'node' : 'nodes'
  const callNoun = ir.totalAgentCalls === 1 ? 'agent call' : 'agent calls'
  const policies = ir.nodes
    .map((node) => (node.retry > 0 ? `${node.id}=${node.failurePolicy}:${node.retry}` : `${node.id}=${node.failurePolicy}`))
    .join(', ')
  return `${ir.nodes.length} ${nodeNoun}, ${ir.totalAgentCalls} ${callNoun} max; policies: ${policies}.`
}

function emitNode(ir: PipelineIR, lines: string[], node: IRNode, skills: ResolvedSkills | undefined): void {
  lines.push(`phase(${JSON.stringify(node.phaseTitle)});`)
  if (node.failurePolicy === 'abort' && node.retry === 0) {
    emitAbortNode(ir, lines, node, skills)
  } else {
    emitPolicyNode(ir, lines, node, skills)
  }
}

/** M1 形状：裸块，失败时抛错并点名 prompt。 */
function emitAbortNode(ir: PipelineIR, lines: string[], node: IRNode, skills: ResolvedSkills | undefined): void {
  lines.push(`{`)
  node.prompts.forEach((_prompt, index) => {
    const k = index + 1
    const label = promptLabel(node, k)
    lines.push(`${IND}const __p${k} = await agent(${promptExpression(ir, node, index, skills)}, ${emitAgentOptions(node, label, 1)});`)
    lines.push(
      `${IND}if (__p${k} === null) throw new Error(${JSON.stringify(`node "${node.id}" failed at prompt ${k}`)});`,
    )
  })
  lines.push(`${IND}out[${JSON.stringify(node.id)}] = __p${node.prompts.length};`)
  lines.push(`}`)
}

/**
 * Skip / retry 形状：整节点尝试循环。某条 prompt 失败会跳出带标签的尝试块；
 * 只要还有尝试次数就重进。循环结束后按策略结算（skip -> null，abort -> throw）。
 */
function emitPolicyNode(ir: PipelineIR, lines: string[], node: IRNode, skills: ResolvedSkills | undefined): void {
  const attempts = 1 + node.retry
  const id = JSON.stringify(node.id)
  lines.push(`{`)
  lines.push(`${IND}let __${node.id}_attempt = 0;`)
  lines.push(`${IND}let __${node.id}_done = false;`)
  if (node.failurePolicy === 'abort') lines.push(`${IND}let __${node.id}_failedAt = 0;`)
  lines.push(`${IND}while (!__${node.id}_done && __${node.id}_attempt < ${attempts}) {`)
  lines.push(`${IND}${IND}__${node.id}_attempt += 1;`)
  lines.push(`${IND}${IND}__try_${node.id}: {`)
  node.prompts.forEach((_prompt, index) => {
    const k = index + 1
    const label = promptLabel(node, k)
    lines.push(`${IND}${IND}${IND}const __p${k} = await agent(${promptExpression(ir, node, index, skills)}, ${emitAgentOptions(node, label, 3)});`)
    if (node.failurePolicy === 'abort') {
      lines.push(`${IND}${IND}${IND}if (__p${k} === null) {`)
      lines.push(`${IND}${IND}${IND}${IND}__${node.id}_failedAt = ${k};`)
      lines.push(`${IND}${IND}${IND}${IND}break __try_${node.id};`)
      lines.push(`${IND}${IND}${IND}}`)
    } else {
      lines.push(`${IND}${IND}${IND}if (__p${k} === null) break __try_${node.id};`)
    }
  })
  lines.push(`${IND}${IND}${IND}out[${id}] = __p${node.prompts.length};`)
  lines.push(`${IND}${IND}${IND}__${node.id}_done = true;`)
  lines.push(`${IND}${IND}}`)
  lines.push(`${IND}}`)
  if (node.failurePolicy === 'skip') {
    lines.push(`${IND}if (!__${node.id}_done) out[${id}] = null;`)
  } else {
    lines.push(
      `${IND}if (!__${node.id}_done) throw new Error("node \\"${node.id}\\" failed at prompt " + __${node.id}_failedAt + " after ${attempts} attempt(s)");`,
    )
  }
  lines.push(`}`)
}

/** 多条 prompt 的节点在 label 后追加 ` #k`（冻结口径 2）。 */
function promptLabel(node: IRNode, k: number): string {
  return node.prompts.length > 1 ? `${node.phaseTitle} #${k}` : node.phaseTitle
}

/**
 * 选项字段序冻结：label / provider / model / schema。`callUnits` 是 `agent(`
 * 调用的缩进深度（以 IND 为单位），选项字段再深一层，收括号与调用对齐。
 */
function emitAgentOptions(node: IRNode, label: string, callUnits: number): string {
  const fields: string[] = []
  fields.push(`${IND.repeat(callUnits + 1)}label: ${JSON.stringify(label)},`)
  if (node.agentOptions.provider !== undefined) {
    fields.push(`${IND.repeat(callUnits + 1)}provider: ${JSON.stringify(node.agentOptions.provider)},`)
  }
  if (node.agentOptions.model !== undefined) {
    fields.push(`${IND.repeat(callUnits + 1)}model: ${JSON.stringify(node.agentOptions.model)},`)
  }
  if (node.outputSchema !== undefined) {
    const schemaJson = JSON.stringify(node.outputSchema, null, 2)
      .split('\n')
      .map((line, index) => (index === 0 ? line : IND.repeat(callUnits + 1) + line))
      .join('\n')
    fields.push(`${IND.repeat(callUnits + 1)}schema: ${schemaJson},`)
  }
  return `{\n${fields.join('\n')}\n${IND.repeat(callUnits)}}`
}

function promptExpression(ir: PipelineIR, node: IRNode, promptIndex: number, skills: ResolvedSkills | undefined): string {
  const parts: string[] = []
  if (node.needsSkills) {
    for (const block of resolvedSkillBlocks(skills, node)) {
      parts.push(JSON.stringify(`${block}\n\n`))
    }
  }
  const location = `node "${node.id}" prompt ${promptIndex + 1}`
  const segments = segmentTemplate(node.prompts[promptIndex].template, location)
  for (const segment of segments) {
    if (segment.kind === 'static') {
      if (segment.text.length > 0) parts.push(JSON.stringify(segment.text))
      continue
    }
    parts.push(variableExpression(ir, segment.ref, promptIndex))
  }
  if (parts.length === 0) parts.push('""')
  return parts.join(' + ')
}

function resolvedSkillBlocks(skills: ResolvedSkills | undefined, node: IRNode): string[] {
  const blocks = skills?.get(node.id)
  if (blocks === undefined || blocks.length === 0) {
    throw new PipelineError(
      ErrorCode.skill,
      `节点 "${node.id}" 声明了 skills（${(node.skills ?? []).map((s) => `"${s}"`).join(', ')}）但没有提供已渲染的技能块；` +
        'compileScript 需要 ResolvedSkills 映射（宿主在编译前解析技能注册表）',
    )
  }
  return blocks
}

function variableExpression(ir: PipelineIR, ref: TemplateRef, promptIndex: number): string {
  if (ref.kind === 'input') return 'args'
  if (ref.kind === 'prev') return `__p${promptIndex}`
  // 引用 outputSchema 节点时把结构化值按 JSON 插值（JSON 安全拼接，旧仓 plan/03）；
  // 字符串输出直接插值。
  const target = ir.nodes.find((n) => n.id === ref.id)
  if (target?.needsOutputSchema === true) return `JSON.stringify(out[${JSON.stringify(ref.id)}])`
  return `out[${JSON.stringify(ref.id)}]`
}