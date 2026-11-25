/**
 * pipeline-run · 流水线定义格式与**形状校验**（迁自旧仓 `src/schema.ts`）。
 *
 * 只做形状层：重复 id / 依赖解析 / 模板变量 / M2 feature gates 在 `ir.ts`。
 * 本模块**不抛异常**，一次收集全部违规（编辑器可以一次显示全部问题）。
 *
 * 口径差（登记在 `docs/pipeline-run.md`）：旧仓消息经 `locale/en.json` /
 * `locale/zh.json` 渲染；器官不得读文件、不得自带配置，因此消息直接内联中文。
 * 违规的 **path 语法**与旧仓一致（`nodes[0].prompts[1]`），判定结论不变。
 */

import defaults from './data/pipeline-run-defaults.json' with { type: 'json' }
import { isPlainObject } from './util.js'

export interface PipelineDef {
  name: string
  description: string
  nodes: PipelineNode[]
  options?: PipelineOptions
}

export interface PipelineOptions {
  maxAgentsPerNode?: number
  defaultFailurePolicy?: 'abort' | 'skip'
}

export interface PipelineNode {
  id: string
  label?: string
  /** >= 1 prompt，节点内按声明顺序投递。 */
  prompts: string[]
  model?: NodeModel
  skills?: string[]
  tools?: { allow?: string[]; deny?: string[] }
  /** 缺省 = 隐式串接上一节点；显式出现（含空数组）覆盖该规则。 */
  dependsOn?: string[]
  outputSchema?: Record<string, unknown>
  failurePolicy?: 'abort' | 'skip'
  retry?: number
}

export interface NodeModel {
  provider?: string
  model?: string
  reasoningEffort?: string
}

export interface DefError {
  /** JSON-pointer 风格的位置，如 `nodes[2].prompts[0]`。 */
  path: string
  message: string
}

/** 流水线名 / 节点 id 语法：文件名安全、模板引用安全。 */
export const ID_RE = new RegExp(defaults.id_pattern)

export function isValidDefName(name: string): boolean {
  return ID_RE.test(name)
}

export type ValidateResult =
  | { ok: true; def: PipelineDef }
  | { ok: false; errors: DefError[] }

export function validateDef(raw: unknown): ValidateResult {
  const errors: DefError[] = []
  const push = (path: string, message: string): void => {
    errors.push({ path, message })
  }

  if (!isPlainObject(raw)) {
    return { ok: false, errors: [{ path: '', message: '定义必须是 JSON 对象' }] }
  }
  const rec = raw

  for (const key of Object.keys(rec)) {
    if (!['name', 'description', 'nodes', 'options'].includes(key)) {
      push(key, `未知字段：${key}`)
    }
  }

  let name: string | undefined
  if (typeof rec.name !== 'string' || rec.name.length === 0) {
    push('name', 'name 必须是非空字符串')
  } else if (!isValidDefName(rec.name)) {
    push('name', `name 不符合 id 语法：${ID_RE.source}`)
  } else {
    name = rec.name
  }

  let description: string | undefined
  if (typeof rec.description !== 'string' || rec.description.trim().length === 0) {
    push('description', 'description 必须是非空字符串')
  } else {
    description = rec.description
  }

  let nodes: PipelineNode[] | undefined
  if (!Array.isArray(rec.nodes) || rec.nodes.length === 0) {
    push('nodes', 'nodes 必须是非空数组')
  } else {
    nodes = []
    rec.nodes.forEach((entry, index) => {
      const node = validateNode(entry, `nodes[${index}]`, push)
      if (node !== undefined) nodes!.push(node)
    })
  }

  let options: PipelineOptions | undefined
  if (rec.options !== undefined) {
    const checked = validateOptions(rec.options, 'options', push)
    if (checked !== undefined) options = checked
  }

  if (errors.length > 0 || name === undefined || description === undefined || nodes === undefined) {
    return { ok: false, errors }
  }
  return { ok: true, def: { name, description, nodes, ...(options !== undefined ? { options } : {}) } }
}

function validateOptions(
  raw: unknown,
  path: string,
  push: (path: string, message: string) => void,
): PipelineOptions | undefined {
  if (!isPlainObject(raw)) {
    push(path, 'options 必须是对象')
    return undefined
  }
  const out: PipelineOptions = {}
  let ok = true
  if (raw.maxAgentsPerNode !== undefined) {
    if (typeof raw.maxAgentsPerNode !== 'number' || !Number.isSafeInteger(raw.maxAgentsPerNode) || raw.maxAgentsPerNode < 1) {
      push(`${path}.maxAgentsPerNode`, 'maxAgentsPerNode 必须是正整数')
      ok = false
    } else {
      out.maxAgentsPerNode = raw.maxAgentsPerNode
    }
  }
  if (raw.defaultFailurePolicy !== undefined) {
    if (raw.defaultFailurePolicy !== 'abort' && raw.defaultFailurePolicy !== 'skip') {
      push(`${path}.defaultFailurePolicy`, 'defaultFailurePolicy 必须是 abort / skip')
      ok = false
    } else {
      out.defaultFailurePolicy = raw.defaultFailurePolicy
    }
  }
  for (const key of Object.keys(raw)) {
    if (key !== 'maxAgentsPerNode' && key !== 'defaultFailurePolicy') {
      push(`${path}.${key}`, `未知选项：${key}`)
      ok = false
    }
  }
  return ok ? out : undefined
}

function validateNode(
  raw: unknown,
  path: string,
  push: (path: string, message: string) => void,
): PipelineNode | undefined {
  if (!isPlainObject(raw)) {
    push(path, '节点必须是对象')
    return undefined
  }
  // 按文档字段序装配（id, label, prompts, model, skills, tools, dependsOn,
  // outputSchema, failurePolicy, retry），与旧仓 store.saveDef 的规范字节一致。
  const known = new Set(['id', 'label', 'prompts', 'model', 'skills', 'tools', 'dependsOn', 'outputSchema', 'failurePolicy', 'retry'])
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) push(`${path}.${key}`, `未知节点字段：${key}`)
  }
  const idOk = typeof raw.id === 'string' && ID_RE.test(raw.id)
  if (Array.isArray(raw.prompts)) {
    raw.prompts.forEach((prompt, index) => {
      if (typeof prompt !== 'string' || prompt.length === 0) push(`${path}.prompts[${index}]`, 'prompt 必须是非空字符串')
    })
  }
  const promptsOk = Array.isArray(raw.prompts) && raw.prompts.length > 0 && raw.prompts.every((prompt) => typeof prompt === 'string' && prompt.length > 0)
  let label: string | undefined
  if (raw.label !== undefined) {
    if (typeof raw.label !== 'string' || raw.label.trim().length === 0) {
      push(`${path}.label`, 'label 必须是非空字符串')
    } else {
      label = raw.label
    }
  }
  let model: NodeModel | undefined
  if (raw.model !== undefined) {
    model = validateModel(raw.model, `${path}.model`, push)
  }
  let skills: string[] | undefined
  if (raw.skills !== undefined) {
    if (!Array.isArray(raw.skills) || raw.skills.length === 0 || !raw.skills.every((s) => typeof s === 'string' && s.length > 0)) {
      push(`${path}.skills`, 'skills 必须是非空字符串数组')
    } else {
      skills = raw.skills as string[]
    }
  }
  let tools: { allow?: string[]; deny?: string[] } | undefined
  if (raw.tools !== undefined) {
    tools = validateTools(raw.tools, `${path}.tools`, push)
  }
  let dependsOn: string[] | undefined
  if (raw.dependsOn !== undefined) {
    if (!Array.isArray(raw.dependsOn) || !raw.dependsOn.every((d) => typeof d === 'string' && ID_RE.test(d))) {
      push(`${path}.dependsOn`, 'dependsOn 必须是合法 id 数组')
    } else {
      const deps = raw.dependsOn as string[]
      const seen = new Set<string>()
      deps.forEach((dep, index) => {
        if (seen.has(dep)) {
          push(`${path}.dependsOn[${index}]`, `重复依赖：${dep}`)
        }
        seen.add(dep)
      })
      dependsOn = deps
    }
  }
  let outputSchema: Record<string, unknown> | undefined
  if (raw.outputSchema !== undefined) {
    if (!isPlainObject(raw.outputSchema)) {
      push(`${path}.outputSchema`, 'outputSchema 必须是对象')
    } else {
      outputSchema = raw.outputSchema
    }
  }
  let failurePolicy: 'abort' | 'skip' | undefined
  if (raw.failurePolicy !== undefined) {
    if (raw.failurePolicy !== 'abort' && raw.failurePolicy !== 'skip') {
      push(`${path}.failurePolicy`, 'failurePolicy 必须是 abort / skip')
    } else {
      failurePolicy = raw.failurePolicy
    }
  }
  let retry: number | undefined
  if (raw.retry !== undefined) {
    if (typeof raw.retry !== 'number' || !Number.isSafeInteger(raw.retry) || raw.retry < 0) {
      push(`${path}.retry`, 'retry 必须是非负整数')
    } else {
      retry = raw.retry
    }
  }

  if (!idOk || !promptsOk) {
    if (!idOk) push(`${path}.id`, `id 不符合 id 语法：${ID_RE.source}`)
    if (!promptsOk) push(`${path}.prompts`, 'prompts 必须是非空字符串数组')
    return undefined
  }
  return {
    id: raw.id as string,
    ...(label !== undefined ? { label } : {}),
    prompts: raw.prompts as string[],
    ...(model !== undefined ? { model } : {}),
    ...(skills !== undefined ? { skills } : {}),
    ...(tools !== undefined ? { tools } : {}),
    ...(dependsOn !== undefined ? { dependsOn } : {}),
    ...(outputSchema !== undefined ? { outputSchema } : {}),
    ...(failurePolicy !== undefined ? { failurePolicy } : {}),
    ...(retry !== undefined ? { retry } : {}),
  }
}

function validateModel(
  raw: unknown,
  path: string,
  push: (path: string, message: string) => void,
): NodeModel | undefined {
  if (!isPlainObject(raw)) {
    push(path, 'model 必须是对象')
    return undefined
  }
  const out: NodeModel = {}
  let ok = true
  for (const field of ['provider', 'model', 'reasoningEffort'] as const) {
    const value = raw[field]
    if (value === undefined) continue
    if (typeof value !== 'string' || value.trim().length === 0) {
      push(`${path}.${field}`, `${field} 必须是非空字符串`)
      ok = false
    } else {
      out[field] = value
    }
  }
  for (const key of Object.keys(raw)) {
    if (!['provider', 'model', 'reasoningEffort'].includes(key)) {
      push(`${path}.${key}`, `未知 model 字段：${key}`)
      ok = false
    }
  }
  return ok ? out : undefined
}

function validateTools(
  raw: unknown,
  path: string,
  push: (path: string, message: string) => void,
): { allow?: string[]; deny?: string[] } | undefined {
  if (!isPlainObject(raw)) {
    push(path, 'tools 必须是对象')
    return undefined
  }
  const out: { allow?: string[]; deny?: string[] } = {}
  let ok = true
  for (const field of ['allow', 'deny'] as const) {
    const value = raw[field]
    if (value === undefined) continue
    if (!Array.isArray(value) || value.length === 0 || !value.every((t) => typeof t === 'string' && t.length > 0)) {
      push(`${path}.${field}`, `${field} 必须是非空字符串数组`)
      ok = false
    } else {
      out[field] = value as string[]
    }
  }
  for (const key of Object.keys(raw)) {
    if (key !== 'allow' && key !== 'deny') {
      push(`${path}.${key}`, `未知 tools 字段：${key}`)
      ok = false
    }
  }
  if (out.allow === undefined && out.deny === undefined) {
    push(path, 'tools 必须至少声明 allow / deny 之一')
    ok = false
  }
  return ok ? out : undefined
}