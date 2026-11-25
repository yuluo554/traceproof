/**
 * pipeline-run · 编辑器表单模型（迁自旧仓 `src/form-model.ts`）：
 * `PipelineDef` <-> 扁平表单状态的双向转换。
 *
 * 归一化决策（旧仓 plan/06）：
 * - `model: {}` / `options: {}`（退化空对象，形状合法）归一化为缺省；
 * - `dependsOn` 缺省（隐式串接）与显式出现（`[]` 合法）语义不同（IR 规则 1），
 *   表单用 `hasExplicitDeps` 保真；
 * - 往返一致性定义在已解析 JSON 的深比较上；规范字节由 `serializeDef` 产出。
 *
 * Gated 字段（旧仓口径 5/6）：`tools` / `model.reasoningEffort` 留在表单里
 * 保真往返，但 IR 仍以 IR_UNSUPPORTED_FEATURE 拒绝。
 */

import type { PipelineDef, PipelineNode } from './schema.js'

export interface DefForm {
  name: string
  description: string
  nodes: NodeForm[]
  /** `''` = 缺省；否则 abort | skip。 */
  defaultFailurePolicy: string
  /** `''` = 缺省；否则十进制字符串（编辑器中只读）。 */
  maxAgentsPerNode: string
}

export interface NodeForm {
  id: string
  /** `''` = 缺省。 */
  label: string
  prompts: string[]
  /** `''` = 缺省。 */
  provider: string
  /** `''` = 缺省。 */
  model: string
  /** 原样保留；编辑器中只读。 */
  reasoningEffort: string
  skills: string[]
  /** 原样保留；编辑器中只读。 */
  toolsAllow: string[]
  toolsDeny: string[]
  /** false = 省略 dependsOn（隐式线性串接）。 */
  hasExplicitDeps: boolean
  dependsOn: string[]
  /** `''` = 缺省；否则原始 JSON 文本。 */
  outputSchemaRaw: string
  /** `''` = 缺省；否则 abort | skip。 */
  failurePolicy: string
  /** `''` = 缺省；否则十进制字符串（`'0'` 有意义）。 */
  retry: string
}

export interface FormError {
  path: string
  message: string
}

/** 定义 -> 可编辑表单。全函数：接受任何已校验定义。 */
export function defToForm(def: PipelineDef): DefForm {
  return {
    name: def.name,
    description: def.description,
    nodes: def.nodes.map(nodeToForm),
    defaultFailurePolicy: def.options?.defaultFailurePolicy ?? '',
    maxAgentsPerNode: def.options?.maxAgentsPerNode !== undefined ? String(def.options.maxAgentsPerNode) : '',
  }
}

function nodeToForm(node: PipelineNode): NodeForm {
  return {
    id: node.id,
    label: node.label ?? '',
    prompts: [...node.prompts],
    provider: node.model?.provider ?? '',
    model: node.model?.model ?? '',
    reasoningEffort: node.model?.reasoningEffort ?? '',
    skills: node.skills !== undefined ? [...node.skills] : [],
    toolsAllow: node.tools?.allow !== undefined ? [...node.tools.allow] : [],
    toolsDeny: node.tools?.deny !== undefined ? [...node.tools.deny] : [],
    hasExplicitDeps: node.dependsOn !== undefined,
    dependsOn: node.dependsOn !== undefined ? [...node.dependsOn] : [],
    outputSchemaRaw: node.outputSchema !== undefined ? JSON.stringify(node.outputSchema, null, 2) : '',
    failurePolicy: node.failurePolicy ?? '',
    retry: node.retry !== undefined ? String(node.retry) : '',
  }
}

export type FormToDefResult =
  | { ok: true; def: PipelineDef }
  | { ok: false; errors: FormError[] }

/**
 * 可编辑表单 -> 定义。只做结构装配：调用方还要跑 `validateDef`（形状）
 * 与 IR 预检（语义）。装配对象的字段序固定（文档化的序列化序），
 * 编辑前后字节确定。
 */
export function formToDef(form: DefForm): FormToDefResult {
  const errors: FormError[] = []
  const nodes: PipelineNode[] = []
  form.nodes.forEach((node, index) => {
    const assembled = nodeFromForm(node, `nodes[${index}]`, errors)
    if (assembled !== undefined) nodes.push(assembled)
  })

  const options: PipelineDef['options'] = {}
  let optionsPresent = false
  if (form.defaultFailurePolicy !== '') {
    if (form.defaultFailurePolicy !== 'abort' && form.defaultFailurePolicy !== 'skip') {
      errors.push({
        path: 'options.defaultFailurePolicy',
        message: `非法取值 ${JSON.stringify(form.defaultFailurePolicy)}`,
      })
    } else {
      options.defaultFailurePolicy = form.defaultFailurePolicy
      optionsPresent = true
    }
  }
  if (form.maxAgentsPerNode !== '') {
    const parsed = Number(form.maxAgentsPerNode)
    if (form.maxAgentsPerNode.trim() === '' || !Number.isSafeInteger(parsed) || parsed < 1) {
      errors.push({
        path: 'options.maxAgentsPerNode',
        message: `不是正整数：${JSON.stringify(form.maxAgentsPerNode)}`,
      })
    } else {
      options.maxAgentsPerNode = parsed
      optionsPresent = true
    }
  }

  if (errors.length > 0) return { ok: false, errors }
  return {
    ok: true,
    def: {
      name: form.name,
      description: form.description,
      nodes,
      ...(optionsPresent ? { options } : {}),
    },
  }
}

function nodeFromForm(form: NodeForm, path: string, errors: FormError[]): PipelineNode | undefined {
  // 按 schema 文档字段序装配（id, label, prompts, model, skills, tools,
  // dependsOn, outputSchema, failurePolicy, retry），与旧仓规范序列化逐字节一致。
  const model: PipelineNode['model'] = {}
  if (form.provider !== '') model.provider = form.provider
  if (form.model !== '') model.model = form.model
  if (form.reasoningEffort !== '') model.reasoningEffort = form.reasoningEffort
  const modelPresent = model.provider !== undefined || model.model !== undefined || model.reasoningEffort !== undefined

  const tools: PipelineNode['tools'] = {}
  let toolsPresent = false
  if (form.toolsAllow.length > 0) {
    tools.allow = [...form.toolsAllow]
    toolsPresent = true
  }
  if (form.toolsDeny.length > 0) {
    tools.deny = [...form.toolsDeny]
    toolsPresent = true
  }

  let outputSchema: Record<string, unknown> | undefined
  if (form.outputSchemaRaw.trim() !== '') {
    try {
      const parsed: unknown = JSON.parse(form.outputSchemaRaw)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        errors.push({ path: `${path}.outputSchema`, message: 'outputSchema 必须是 JSON 对象' })
        return undefined
      }
      outputSchema = parsed as Record<string, unknown>
    } catch (err) {
      errors.push({ path: `${path}.outputSchema`, message: `JSON 不合法：${err instanceof Error ? err.message : String(err)}` })
      return undefined
    }
  }

  if (form.failurePolicy !== '' && form.failurePolicy !== 'abort' && form.failurePolicy !== 'skip') {
    errors.push({ path: `${path}.failurePolicy`, message: `非法取值 ${JSON.stringify(form.failurePolicy)}` })
    return undefined
  }
  let retry: number | undefined
  if (form.retry !== '') {
    const parsed = Number(form.retry)
    if (form.retry.trim() === '' || !Number.isSafeInteger(parsed) || parsed < 0) {
      errors.push({ path: `${path}.retry`, message: `不是非负整数：${JSON.stringify(form.retry)}` })
      return undefined
    }
    retry = parsed
  }

  return {
    id: form.id,
    ...(form.label.trim() !== '' ? { label: form.label } : {}),
    prompts: [...form.prompts],
    ...(modelPresent ? { model } : {}),
    ...(form.skills.length > 0 ? { skills: [...form.skills] } : {}),
    ...(toolsPresent ? { tools } : {}),
    ...(form.hasExplicitDeps ? { dependsOn: [...form.dependsOn] } : {}),
    ...(outputSchema !== undefined ? { outputSchema } : {}),
    ...(form.failurePolicy !== '' ? { failurePolicy: form.failurePolicy } : {}),
    ...(retry !== undefined ? { retry } : {}),
  }
}

/** 规范美化序列化（与旧仓 saveDef 写出的形状一致）。 */
export function serializeDef(def: PipelineDef): string {
  return JSON.stringify(def, null, 2) + '\n'
}