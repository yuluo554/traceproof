/**
 * pipeline-run · 流水线运行取证
 *
 * 一个 traceproof 器官：把「这份流水线定义能不能编译、这次运行到底怎么结算」的主张，
 * 对到**同一份定义 / 运行记录**上，逐条核对。判定层迁自旧仓（target-map ④ 行）的
 * `schema` / `ir` / `compiler` / `form-model` / `run-events` / `runner` 的能力预检；
 * 宿主接线（`entry` / `web` / `store` / `run-recorder` / `bench` / `mock-engine`）不迁。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "pipeline": {
 *     "definition": { "name": "three-node-two-models", "description": "…", "nodes": [ … ] },
 *     "skills": {"draft": ["<已渲染的技能块>"]},
 *     "capabilities": {"agentOptions": true, "outputSchema": false},
 *     "provider": "spawn",
 *     "run": {
 *       "interrupted": false,
 *       "events": [
 *         {"type": "pipeline-run/run-start", "data": {"runId": "run-1", "name": "…", "nodes": [ … ], "startedAt": 1000}},
 *         {"type": "pipeline-run/agent-start", "data": {…}},
 *         {"type": "pipeline-run/agent-end", "data": {…}},
 *         {"type": "pipeline-run/run-end", "data": {…}}
 *       ]
 *     }
 *   },
 *   "claims": [
 *     {"claim_id": "c1", "check": "compile", "asserted": "compiles",
 *      "order": ["outline", "review", "write"], "total_agent_calls": 3,
 *      "node": {"session_id": "s-pipe-1", "turn": 2, "tool_call_id": "call-pipe-2"}}
 *   ]
 * }
 * ```
 *
 * 这条 pipeline 是**判定层**：定义形状（schema）、IR 语义（依赖 / 模板 / gates）、
 * 编译快照（compiler）、表单往返（form-model）、运行事件折叠（run-events）与
 * 能力预检（runner 的纯判定部分）。它不跑引擎、不读工作区、不读时钟。
 */

import { createHash } from 'node:crypto'

import defaults from './data/pipeline-run-defaults.json' with { type: 'json' }
import type { Basis } from '../../core/trace-index.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import type { LedgerRecord, TraceNode, Verdict } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'
import { compileScript } from './compiler.js'
import type { ResolvedSkills } from './compiler.js'
import { ErrorCode, PipelineError } from './errors.js'
import { defToForm, formToDef, serializeDef } from './form-model.js'
import { buildIR } from './ir.js'
import type { PipelineIR } from './ir.js'
import { foldStart, foldUpdate, projectPipelineRun } from './run-events.js'
import type {
  PipelineRunAgentEndData,
  PipelineRunAgentStartData,
  PipelineRunEvent,
  PipelineRunNodePlan,
  PipelineRunNodeView,
  PipelineRunStartData,
  PipelineRunUsageTotals,
} from './run-events.js'
import { validateDef } from './schema.js'
import type { DefError } from './schema.js'
import { isPlainObject, jsonEqual, sortedUnique } from './util.js'

const CHECKS = ['definition', 'compile', 'preflight', 'run', 'node', 'form'] as const
type CheckName = (typeof CHECKS)[number]

const ASSERTED_VALUES: Record<CheckName, readonly string[]> = {
  definition: ['valid', 'invalid'],
  compile: ['compiles', 'rejected'],
  preflight: ['ok', 'missing-agent-options', 'missing-output-schema'],
  run: ['completed', 'failed', 'cancelled', 'interrupted', 'running'],
  node: ['pending', 'running', 'completed', 'failed', 'cancelled', 'interrupted', 'absent'],
  form: ['roundtrip', 'lossy'],
}

const CHECK_FIELDS: Record<CheckName, readonly string[]> = {
  definition: ['error_paths'],
  compile: ['error_code', 'order', 'total_agent_calls'],
  preflight: [],
  run: [],
  node: ['node_id', 'attempts'],
  form: [],
}

const GLOBAL_FIELDS = ['claim_id', 'check', 'asserted', 'node'] as const

interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: string
  readonly errorPaths: readonly string[] | null
  readonly errorCode: string | null
  readonly order: readonly string[] | null
  readonly totalAgentCalls: number | null
  readonly nodeId: string | null
  readonly attempts: number | null
  readonly node: unknown
}

interface Capabilities {
  readonly agentOptions: boolean
  readonly outputSchema: boolean
}

interface ParsedRun {
  readonly start: PipelineRunStartData
  readonly events: readonly Exclude<PipelineRunEvent, { type: 'pipeline-run/run-start' }>[]
  readonly interrupted: boolean
}

interface PipelineInput {
  /** 原样保留，由 `validateDef` 判形状。 */
  readonly definition: unknown
  readonly hasDefinition: boolean
  readonly skills: Record<string, readonly string[]> | undefined
  readonly capabilities: Capabilities | undefined
  readonly provider: string
  readonly run: ParsedRun | undefined
}

interface Computed {
  readonly result: string
  readonly matched: boolean
  readonly reason: string
  readonly evidence: Record<string, unknown>
  readonly inconclusive?: boolean
  readonly missing?: readonly string[]
}

// ---------------------------------------------------------------------------
// 输入解析（只认 JSON 面；坏输入 = 契约违约，冒到唯一入口）
// ---------------------------------------------------------------------------

function readString(value: unknown, where: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ContractError(`${where} 必须是非空字符串`)
  }
  return value.trim()
}

function readFiniteNumber(value: unknown, where: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum) {
    throw new ContractError(`${where} 必须是 >= ${minimum} 的有限数字`)
  }
  return value
}

function readInteger(value: unknown, where: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    throw new ContractError(`${where} 必须是 >= ${minimum} 的整数`)
  }
  return value
}

function readStringArray(value: unknown, where: string, allowEmpty = false): string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new ContractError(`${where} 必须是${allowEmpty ? '' : '非空'}字符串数组`)
  }
  return value.map((item, index) => readString(item, `${where}[${index}]`))
}

function readUsage(raw: unknown, where: string): PipelineRunUsageTotals | undefined {
  if (raw === undefined) return undefined
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const usage: PipelineRunUsageTotals = {
    inputTokens: readFiniteNumber(raw.inputTokens, `${where}.inputTokens`),
    outputTokens: readFiniteNumber(raw.outputTokens, `${where}.outputTokens`),
    ...(raw.totalTokens !== undefined
      ? { totalTokens: readFiniteNumber(raw.totalTokens, `${where}.totalTokens`) }
      : {}),
    ...(raw.cacheReadTokens !== undefined
      ? { cacheReadTokens: readFiniteNumber(raw.cacheReadTokens, `${where}.cacheReadTokens`) }
      : {}),
    ...(raw.cacheWriteTokens !== undefined
      ? { cacheWriteTokens: readFiniteNumber(raw.cacheWriteTokens, `${where}.cacheWriteTokens`) }
      : {}),
    ...(raw.reasoningTokens !== undefined
      ? { reasoningTokens: readFiniteNumber(raw.reasoningTokens, `${where}.reasoningTokens`) }
      : {}),
  }
  return usage
}

function readPlan(raw: unknown, where: string): PipelineRunNodePlan {
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  return {
    id: readString(raw.id, `${where}.id`),
    label: readString(raw.label, `${where}.label`),
    ...(raw.provider !== undefined ? { provider: readString(raw.provider, `${where}.provider`) } : {}),
    ...(raw.model !== undefined ? { model: readString(raw.model, `${where}.model`) } : {}),
  }
}

function readEvent(raw: unknown, where: string): PipelineRunEvent | null {
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const type = raw.type
  if (typeof type !== 'string') throw new ContractError(`${where}.type 必须是字符串`)
  const data = raw.data
  if (!isPlainObject(data)) throw new ContractError(`${where}.data 必须是对象`)

  if (type === 'pipeline-run/run-start') {
    const nodesRaw = data.nodes
    if (!Array.isArray(nodesRaw) || nodesRaw.length === 0) {
      throw new ContractError(`${where}.data.nodes 必须是非空数组`)
    }
    const start: PipelineRunStartData = {
      runId: readString(data.runId, `${where}.data.runId`),
      name: readString(data.name, `${where}.data.name`),
      nodes: nodesRaw.map((node, index) => readPlan(node, `${where}.data.nodes[${index}]`)),
      startedAt: readFiniteNumber(data.startedAt, `${where}.data.startedAt`),
    }
    return { type, data: start }
  }
  if (type === 'pipeline-run/agent-start') {
    const start: PipelineRunAgentStartData = {
      runId: readString(data.runId, `${where}.data.runId`),
      seq: readInteger(data.seq, `${where}.data.seq`, 1),
      label: readString(data.label, `${where}.data.label`),
      childId: readString(data.childId, `${where}.data.childId`),
      startedAt: readFiniteNumber(data.startedAt, `${where}.data.startedAt`),
      ...(data.phase !== undefined ? { phase: readString(data.phase, `${where}.data.phase`) } : {}),
      ...(data.provider !== undefined ? { provider: readString(data.provider, `${where}.data.provider`) } : {}),
      ...(data.model !== undefined ? { model: readString(data.model, `${where}.data.model`) } : {}),
    }
    return { type, data: start }
  }
  if (type === 'pipeline-run/agent-end') {
    if (data.outcome !== 'completed' && data.outcome !== 'failed' && data.outcome !== 'cancelled') {
      throw new ContractError(`${where}.data.outcome 必须是 completed / failed / cancelled`)
    }
    const end: PipelineRunAgentEndData = {
      runId: readString(data.runId, `${where}.data.runId`),
      seq: readInteger(data.seq, `${where}.data.seq`, 1),
      outcome: data.outcome,
      durationMs: readFiniteNumber(data.durationMs, `${where}.data.durationMs`),
      ...(data.usage !== undefined ? { usage: readUsage(data.usage, `${where}.data.usage`) } : {}),
    }
    return { type, data: end }
  }
  if (type === 'pipeline-run/run-end') {
    if (data.stopReason !== 'completed' && data.stopReason !== 'cancelled' && data.stopReason !== 'error') {
      throw new ContractError(`${where}.data.stopReason 必须是 completed / cancelled / error`)
    }
    if (data.error !== undefined && typeof data.error !== 'string') {
      throw new ContractError(`${where}.data.error 必须是字符串`)
    }
    return {
      type,
      data: {
        runId: readString(data.runId, `${where}.data.runId`),
        stopReason: data.stopReason,
        durationMs: readFiniteNumber(data.durationMs, `${where}.data.durationMs`),
        ...(data.error !== undefined ? { error: data.error as string } : {}),
      },
    }
  }
  // 未知事件类型：折叠契约是「忽略」（与旧仓 foldUpdate 一致）。
  return null
}

function readRun(raw: unknown): ParsedRun {
  if (!isPlainObject(raw) || !Array.isArray(raw.events) || raw.events.length === 0) {
    throw new ContractError('pipeline.run 必须是对象，且 run.events 是非空数组')
  }
  const events = raw.events.map((event, index) => readEvent(event, `pipeline.run.events[${index}]`))
  const first = events[0]
  if (first === null || first.type !== 'pipeline-run/run-start') {
    throw new ContractError('pipeline.run.events[0] 必须是 pipeline-run/run-start')
  }
  const rest = events.slice(1).filter(
    (event): event is Exclude<PipelineRunEvent, { type: 'pipeline-run/run-start' }> =>
      event !== null && event.type !== 'pipeline-run/run-start',
  )
  if (raw.interrupted !== undefined && typeof raw.interrupted !== 'boolean') {
    throw new ContractError('pipeline.run.interrupted 必须是布尔值')
  }
  return { start: first.data, events: rest, interrupted: raw.interrupted === true }
}

function readCapabilities(raw: unknown): Capabilities {
  if (!isPlainObject(raw)) throw new ContractError('pipeline.capabilities 必须是对象')
  if (typeof raw.agentOptions !== 'boolean' || typeof raw.outputSchema !== 'boolean') {
    throw new ContractError('pipeline.capabilities 需要布尔字段 agentOptions / outputSchema')
  }
  return { agentOptions: raw.agentOptions, outputSchema: raw.outputSchema }
}

function readSkills(raw: unknown): Record<string, readonly string[]> {
  if (!isPlainObject(raw)) throw new ContractError('pipeline.skills 必须是对象（nodeId -> 技能块数组）')
  const out: Record<string, readonly string[]> = {}
  for (const [nodeId, blocks] of Object.entries(raw)) {
    if (nodeId.trim().length === 0) throw new ContractError('pipeline.skills 的节点 id 不能为空')
    if (!Array.isArray(blocks) || blocks.some((block) => typeof block !== 'string')) {
      throw new ContractError(`pipeline.skills[${nodeId}] 必须是字符串数组`)
    }
    out[nodeId] = [...blocks]
  }
  return out
}

function readPipeline(raw: unknown): PipelineInput {
  if (!isPlainObject(raw)) throw new ContractError('pipeline 必须是对象')
  const provider = raw.provider === undefined ? 'spawn' : readString(raw.provider, 'pipeline.provider')
  return {
    definition: raw.definition,
    hasDefinition: Object.hasOwn(raw, 'definition'),
    skills: raw.skills === undefined ? undefined : readSkills(raw.skills),
    capabilities: raw.capabilities === undefined ? undefined : readCapabilities(raw.capabilities),
    provider,
    run: raw.run === undefined ? undefined : readRun(raw.run),
  }
}

function readClaim(raw: unknown, position: number): Claim {
  if (!isPlainObject(raw)) throw new ContractError(`claims[${position}] 必须是对象`)
  if (typeof raw.check !== 'string' || !(CHECKS as readonly string[]).includes(raw.check)) {
    throw new ContractError(`claims[${position}] 的 check 非法：<${String(raw.check)}>`)
  }
  const check = raw.check as CheckName
  const allowed = new Set<string>([...GLOBAL_FIELDS, ...CHECK_FIELDS[check]])
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new ContractError(`claims[${position}] 的字段 ${key} 不适用于 check=${check}`)
    }
  }
  const claimId = readString(raw.claim_id, `claims[${position}].claim_id`)
  if (typeof raw.asserted !== 'string' || !raw.asserted.trim()) {
    throw new ContractError(`claims[${position}] 缺 asserted`)
  }
  const asserted = raw.asserted.trim().toLowerCase()
  if (!ASSERTED_VALUES[check].includes(asserted)) {
    throw new ContractError(
      `claims[${position}] 的 asserted 非法：<${asserted}>（${check} 允许 ${ASSERTED_VALUES[check].join(' / ')}）`,
    )
  }

  const optionalStringArray = (name: string): readonly string[] | null => {
    if (raw[name] === undefined) return null
    if (!Array.isArray(raw[name]) || raw[name].length === 0) {
      throw new ContractError(`claims[${position}] 的 ${name} 必须是非空数组`)
    }
    return raw[name].map((item, index) => readString(item, `claims[${position}].${name}[${index}]`))
  }

  const errorPaths = optionalStringArray('error_paths')
  const order = optionalStringArray('order')

  let errorCode: string | null = null
  if (raw.error_code !== undefined) {
    errorCode = readString(raw.error_code, `claims[${position}].error_code`)
  }
  let totalAgentCalls: number | null = null
  if (raw.total_agent_calls !== undefined) {
    totalAgentCalls = readInteger(raw.total_agent_calls, `claims[${position}].total_agent_calls`)
  }
  let nodeId: string | null = null
  if (raw.node_id !== undefined) {
    nodeId = readString(raw.node_id, `claims[${position}].node_id`)
  }
  let attempts: number | null = null
  if (raw.attempts !== undefined) {
    attempts = readInteger(raw.attempts, `claims[${position}].attempts`)
  }

  // 字段组合约束：不让一个主张同时表达两种判据。
  if (check !== 'definition' && errorPaths !== null) {
    throw new ContractError(`claims[${position}]：error_paths 只适用于 definition`)
  }
  if (errorPaths !== null && asserted !== 'invalid') {
    throw new ContractError(`claims[${position}]：error_paths 只在 asserted=invalid 时有意义`)
  }
  if (check !== 'compile' && (errorCode !== null || order !== null || totalAgentCalls !== null)) {
    throw new ContractError(`claims[${position}]：error_code / order / total_agent_calls 只适用于 compile`)
  }
  if (errorCode !== null && asserted !== 'rejected') {
    throw new ContractError(`claims[${position}]：error_code 只在 asserted=rejected 时有意义`)
  }
  if (order !== null && asserted !== 'compiles') {
    throw new ContractError(`claims[${position}]：order 只在 asserted=compiles 时有意义`)
  }
  if (totalAgentCalls !== null && asserted !== 'compiles') {
    throw new ContractError(`claims[${position}]：total_agent_calls 只在 asserted=compiles 时有意义`)
  }
  if ((nodeId !== null || attempts !== null) && check !== 'node') {
    throw new ContractError(`claims[${position}]：node_id / attempts 只适用于 node`)
  }
  if (check === 'node' && nodeId === null) {
    throw new ContractError(`claims[${position}]：node 主张必须带 node_id`)
  }
  if (attempts !== null && asserted === 'absent') {
    throw new ContractError(`claims[${position}]：absent 节点不能断言 attempts`)
  }

  return {
    claimId,
    check,
    asserted,
    errorPaths,
    errorCode,
    order,
    totalAgentCalls,
    nodeId,
    attempts,
    node: raw.node,
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
  if (typeof raw.tool_call_id !== 'string') {
    throw new ContractError(`${claimId}：node.tool_call_id 必须是字符串`)
  }
  return basis.ref(sessionId.trim(), turn, raw.tool_call_id)
}

// ---------------------------------------------------------------------------
// 判定层
// ---------------------------------------------------------------------------

interface Built {
  readonly ir: PipelineIR
}

type BuildOutcome =
  | { readonly ok: true; readonly built: Built }
  | {
      readonly ok: false
      readonly stage: 'definition' | 'ir'
      readonly code: string
      readonly message: string
      readonly errors?: readonly DefError[]
    }

function buildPipeline(definition: unknown): BuildOutcome {
  const checked = validateDef(definition)
  if (!checked.ok) {
    return {
      ok: false,
      stage: 'definition',
      code: ErrorCode.schema,
      message: `定义形状不合法（${checked.errors.length} 个错误）`,
      errors: checked.errors,
    }
  }
  try {
    return { ok: true, built: { ir: buildIR(checked.def) } }
  } catch (err) {
    if (err instanceof PipelineError) {
      return { ok: false, stage: 'ir', code: err.code, message: err.message }
    }
    throw err
  }
}

function resolvedSkills(skills: Record<string, readonly string[]> | undefined): ResolvedSkills | undefined {
  if (skills === undefined) return undefined
  const map: ResolvedSkills = new Map()
  for (const [nodeId, blocks] of Object.entries(skills)) map.set(nodeId, [...blocks])
  return map
}

/** 技能节点必须有与声明技能数一致的已渲染块；否则判定为「证据不足」，不猜。 */
function missingSkillBlocks(ir: PipelineIR, skills: ResolvedSkills | undefined): string[] {
  const missing: string[] = []
  for (const node of ir.nodes) {
    if (!node.needsSkills) continue
    const blocks = skills?.get(node.id)
    const expected = node.skills?.length ?? 0
    if (blocks === undefined || blocks.length !== expected) {
      missing.push(`节点 "${node.id}" 的 ${expected} 个技能渲染块`)
    }
  }
  return missing
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function computeDefinition(definition: unknown, claim: Claim): Computed {
  const checked = validateDef(definition)
  const result = checked.ok ? 'valid' : 'invalid'
  const errors = checked.ok ? [] : checked.errors
  const actualPaths = sortedUnique(errors.map((error) => error.path))
  let matched = result === claim.asserted
  let reason = ''
  if (matched && claim.errorPaths !== null) {
    const claimed = sortedUnique(claim.errorPaths)
    matched = jsonEqual(actualPaths, claimed)
    reason = matched
      ? ''
      : `错误位置不符：重算 [${actualPaths.join(', ')}] ≠ 主张 [${claimed.join(', ')}]`
  }
  if (matched) {
    reason = result === 'valid' ? '定义通过形状校验' : `定义被形状判据判为 invalid（${errors.length} 个错误）`
  }
  return {
    result,
    matched,
    reason,
    evidence: {
      verdict_value: result,
      error_count: errors.length,
      error_paths: actualPaths,
      errors,
    },
  }
}

function computeCompile(
  definition: unknown,
  skills: Record<string, readonly string[]> | undefined,
  claim: Claim,
): Computed {
  const built = buildPipeline(definition)
  if (!built.ok) {
    const actual = 'rejected'
    let matched = actual === claim.asserted
    let reason =
      claim.asserted === 'rejected' ? `定义被拒绝：${built.code}` : `定义被拒绝：${built.code}（${built.message}）`
    if (matched && claim.errorCode !== null) {
      matched = claim.errorCode === built.code
      reason = matched
        ? `定义被拒绝，错误码 ${built.code}`
        : `错误码不符：重算 ${built.code} ≠ 主张 ${claim.errorCode}`
    }
    return {
      result: actual,
      matched,
      reason,
      evidence: {
        verdict_value: actual,
        stage: built.stage,
        error_code: built.code,
        error_message: built.message,
        ...(built.errors !== undefined ? { errors: built.errors } : {}),
      },
    }
  }

  const skillMap = resolvedSkills(skills)
  const missing = missingSkillBlocks(built.built.ir, skillMap)
  if (missing.length > 0) {
    return {
      result: 'undecidable',
      matched: false,
      inconclusive: true,
      missing,
      reason: '技能块缺失，无法重放编译',
      evidence: {
        verdict_value: 'undecidable',
        missing_skills: missing,
        order: built.built.ir.nodes.map((node) => node.id),
        total_agent_calls: built.built.ir.totalAgentCalls,
      },
    }
  }

  let script: string
  try {
    script = compileScript(built.built.ir, skillMap)
  } catch (err) {
    if (!(err instanceof PipelineError)) throw err
    const actual = 'rejected'
    let matched = actual === claim.asserted
    let reason =
      claim.asserted === 'rejected' ? `编译被拒绝：${err.code}` : `编译被拒绝：${err.code}（${err.message}）`
    if (matched && claim.errorCode !== null) {
      matched = claim.errorCode === err.code
      reason = matched ? `编译被拒绝，错误码 ${err.code}` : `错误码不符：重算 ${err.code} ≠ 主张 ${claim.errorCode}`
    }
    return {
      result: actual,
      matched,
      reason,
      evidence: { verdict_value: actual, stage: 'compile', error_code: err.code, error_message: err.message },
    }
  }

  const order = built.built.ir.nodes.map((node) => node.id)
  const total = built.built.ir.totalAgentCalls
  const actual = 'compiles'
  let matched = actual === claim.asserted
  let reason = ''
  const details: string[] = []
  if (matched && claim.order !== null && !jsonEqual(order, claim.order)) {
    matched = false
    details.push(`顺序不符：重算 [${order.join(', ')}] ≠ 主张 [${claim.order.join(', ')}]`)
  }
  if (matched && claim.totalAgentCalls !== null && claim.totalAgentCalls !== total) {
    matched = false
    details.push(`调用上界不符：重算 ${total} ≠ 主张 ${claim.totalAgentCalls}`)
  }
  if (matched) {
    reason = `编译通过：${order.length} 个节点 / ${total} 次 agent 调用上界 / 脚本 ${sha256(script).slice(0, 12)}…`
  }
  return {
    result: actual,
    matched,
    reason: matched ? reason : details.join('；'),
    evidence: {
      verdict_value: actual,
      order,
      total_agent_calls: total,
      script_sha256: sha256(script),
      script_lines: script.split('\n').length - 1,
      script_chars: script.length,
      ...(claim.errorCode !== null ? { claimed_error_code: claim.errorCode } : {}),
    },
  }
}

function computePreflight(
  definition: unknown,
  skills: Record<string, readonly string[]> | undefined,
  capabilities: Capabilities,
  provider: string,
  claim: Claim,
): Computed {
  const built = buildPipeline(definition)
  if (!built.ok) {
    return {
      result: 'undecidable',
      matched: false,
      inconclusive: true,
      missing: ['可编译的定义'],
      reason: `定义未通过形状/IR 校验：${built.code}（${built.message}）`,
      evidence: { verdict_value: 'undecidable', stage: built.stage, error_code: built.code },
    }
  }
  const skillMap = resolvedSkills(skills)
  const missing = missingSkillBlocks(built.built.ir, skillMap)
  if (missing.length > 0) {
    return {
      result: 'undecidable',
      matched: false,
      inconclusive: true,
      missing,
      reason: '技能块缺失，无法完成运行前预检',
      evidence: { verdict_value: 'undecidable', missing_skills: missing },
    }
  }

  const needingAgentOptions = built.built.ir.nodes.filter((node) => node.needsAgentOptions).map((node) => node.id)
  const needingOutputSchema = built.built.ir.nodes.filter((node) => node.needsOutputSchema).map((node) => node.id)
  let result = 'ok'
  if (!capabilities.agentOptions && needingAgentOptions.length > 0) {
    result = 'missing-agent-options'
  } else if (!capabilities.outputSchema && needingOutputSchema.length > 0) {
    result = 'missing-output-schema'
  }
  const matched = result === claim.asserted
  const reason = matched
    ? result === 'ok'
      ? `能力预检通过（provider "${provider}"）`
      : `能力预检失败：${result}（provider "${provider}"）`
    : `预检结果不符：重算 ${result} ≠ 主张 ${claim.asserted}`
  return {
    result,
    matched,
    reason,
    evidence: {
      verdict_value: result,
      provider,
      capabilities: { agentOptions: capabilities.agentOptions, outputSchema: capabilities.outputSchema },
      needs_agent_options: needingAgentOptions,
      needs_output_schema: needingOutputSchema,
    },
  }
}

function projectRun(run: ParsedRun): ReturnType<typeof projectPipelineRun> {
  let state = foldStart(run.start)
  for (const event of run.events) state = foldUpdate(state, event)
  return projectPipelineRun(state, { interrupted: run.interrupted })
}

function computeRun(run: ParsedRun, claim: Claim): Computed {
  const projection = projectRun(run)
  const matched = projection.status === claim.asserted
  const reason = matched
    ? `运行记录结算为 ${projection.status}${projection.stopReason !== undefined ? `（stopReason=${projection.stopReason}）` : ''}`
    : `运行状态不符：重算 ${projection.status} ≠ 主张 ${claim.asserted}`
  return {
    result: projection.status,
    matched,
    reason,
    evidence: {
      verdict_value: projection.status,
      run_name: projection.name,
      ...(projection.stopReason !== undefined ? { stop_reason: projection.stopReason } : {}),
      ...(projection.error !== undefined ? { error: projection.error } : {}),
      ...(projection.durationMs !== undefined ? { duration_ms: projection.durationMs } : {}),
      nodes: projection.nodes,
      models: projection.models,
    },
  }
}

function computeNode(run: ParsedRun, claim: Claim): Computed {
  const projection = projectRun(run)
  const view: PipelineRunNodeView | undefined = projection.nodes.find((node) => node.id === claim.nodeId)
  const status = view?.status ?? 'absent'
  let matched = status === claim.asserted
  const details: string[] = []
  if (matched && claim.attempts !== null && claim.attempts !== (view?.attempts ?? 0)) {
    matched = false
    details.push(`尝试次数不符：重算 ${view?.attempts ?? 0} ≠ 主张 ${claim.attempts}`)
  }
  const reason = matched
    ? status === 'absent'
      ? `运行记录里没有节点 "${claim.nodeId}"（按 absent 主张成立）`
      : `节点 "${claim.nodeId}" 结算为 ${status}（attempts=${view?.attempts ?? 0}）`
    : details.length > 0
      ? details.join('；')
      : `节点状态不符：重算 ${status} ≠ 主张 ${claim.asserted}`
  return {
    result: status,
    matched,
    reason,
    evidence: {
      verdict_value: status,
      node_id: claim.nodeId,
      ...(view !== undefined
        ? {
            label: view.label,
            ...(view.provider !== undefined ? { provider: view.provider } : {}),
            ...(view.model !== undefined ? { model: view.model } : {}),
            attempts: view.attempts,
            duration_ms: view.durationMs,
            ...(view.usage !== undefined ? { usage: view.usage } : {}),
          }
        : { attempts: 0 }),
      run_status: projection.status,
      run_nodes: projection.nodes.map((node) => ({ id: node.id, status: node.status, attempts: node.attempts })),
    },
  }
}

function computeForm(definition: unknown, claim: Claim): Computed {
  const checked = validateDef(definition)
  if (!checked.ok) {
    const matched = claim.asserted === 'lossy'
    return {
      result: 'lossy',
      matched,
      reason: `定义未通过形状校验，无法往返：${checked.errors.length} 个错误`,
      evidence: { verdict_value: 'lossy', errors: checked.errors },
    }
  }
  const form = defToForm(checked.def)
  const back = formToDef(form)
  if (!back.ok) {
    const matched = claim.asserted === 'lossy'
    return {
      result: 'lossy',
      matched,
      reason: `表单装配失败：${back.errors.length} 个错误`,
      evidence: { verdict_value: 'lossy', form_errors: back.errors },
    }
  }
  const revalidated = validateDef(back.def)
  const lossless = revalidated.ok && jsonEqual(back.def, checked.def)
  const result = lossless ? 'roundtrip' : 'lossy'
  const matched = result === claim.asserted
  const canonical = serializeDef(checked.def)
  const reason = matched
    ? result === 'roundtrip'
      ? '定义经 form -> def 往返后逐字段一致，且重新通过形状校验'
      : '定义经表单往返后发生漂移或重新校验失败'
    : `表单往返结果不符：重算 ${result} ≠ 主张 ${claim.asserted}`
  return {
    result,
    matched,
    reason,
    evidence: {
      verdict_value: result,
      canonical_sha256: sha256(canonical),
      canonical_bytes: Buffer.byteLength(canonical, 'utf8'),
      ...(revalidated.ok ? {} : { revalidation_errors: revalidated.errors }),
    },
  }
}

function compute(pipeline: PipelineInput, claim: Claim): Computed {
  switch (claim.check) {
    case 'definition':
      return computeDefinition(pipeline.definition, claim)
    case 'compile':
      return computeCompile(pipeline.definition, pipeline.skills, claim)
    case 'preflight':
      return computePreflight(
        pipeline.definition,
        pipeline.skills,
        pipeline.capabilities as Capabilities,
        pipeline.provider,
        claim,
      )
    case 'run':
      return computeRun(pipeline.run as ParsedRun, claim)
    case 'node':
      return computeNode(pipeline.run as ParsedRun, claim)
    case 'form':
      return computeForm(pipeline.definition, claim)
  }
}

function evaluate(subject: Record<string, unknown>, basis: Basis): LedgerRecord[] {
  const pipeline = readPipeline(subject.pipeline)
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const claims = rawClaims.map((item, position) => readClaim(item, position))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
    const needsDefinition = ['definition', 'compile', 'preflight', 'form'].includes(claim.check)
    if (needsDefinition && !pipeline.hasDefinition) {
      throw new ContractError(`${claim.claimId}：${claim.check} 主张需要 pipeline.definition`)
    }
    if (claim.check === 'preflight' && pipeline.capabilities === undefined) {
      throw new ContractError(`${claim.claimId}：preflight 主张需要 pipeline.capabilities`)
    }
    if ((claim.check === 'run' || claim.check === 'node') && pipeline.run === undefined) {
      throw new ContractError(`${claim.claimId}：${claim.check} 主张需要 pipeline.run.events`)
    }
  }

  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    const computed = compute(pipeline, claim)
    let verdict: Verdict
    const parts: string[] = []
    if (computed.inconclusive === true) {
      verdict = INCONCLUSIVE
      parts.push(`痕迹不足以判定：${computed.reason}`)
      if (computed.missing !== undefined && computed.missing.length > 0) {
        parts.push(`缺失项：${computed.missing.join('、')}`)
      }
    } else if (computed.matched) {
      verdict = CLAIM
      parts.push(`主张「${claim.check}=${claim.asserted}」被${claimDomain(claim.check)}支持`)
      if (computed.reason) parts.push(computed.reason)
    } else if (node !== null) {
      verdict = REFUTED
      parts.push(`判据推翻主张：重算 ${computed.result} ≠ 主张 ${claim.asserted}`)
      if (computed.reason) parts.push(computed.reason)
    } else {
      verdict = INCONCLUSIVE
      parts.push(
        `判据与主张不符（重算 ${computed.result} ≠ 主张 ${claim.asserted}），但主张没有挂痕迹节点 → 不能下 refuted，判 inconclusive`,
      )
      if (computed.reason) parts.push(computed.reason)
    }
    records.push(
      makeRecord({
        claim_id: claim.claimId,
        verdict,
        message: parts.join('；'),
        node,
        evidence: {
          check: claim.check,
          asserted: claim.asserted,
          computed: computed.result,
          comparison: computed.inconclusive === true ? 'undecidable' : computed.matched ? 'match' : 'mismatch',
          ...computed.evidence,
        },
      }),
    )
  }
  return records
}

function claimDomain(check: CheckName): string {
  switch (check) {
    case 'definition':
      return '定义形状判据'
    case 'compile':
      return '编译判据'
    case 'preflight':
      return '能力预检'
    case 'run':
      return '运行记录'
    case 'node':
      return '运行记录（节点级）'
    case 'form':
      return '表单往返判据'
  }
}

export const pipelineRunVerb: Verb = register({
  slug: 'pipeline-run',
  version: defaults.pipeline_version,
  summary: '流水线运行取证：定义校验 / 确定性编译 / 运行事件折叠，逐条核对主张',
  input_fields: ['pipeline', 'claims'],
  evaluate,
})

export {
  CHECKS,
  ASSERTED_VALUES,
  buildPipeline,
  computeCompile,
  computeDefinition,
  computeForm,
  computeNode,
  computePreflight,
  computeRun,
  projectRun,
}
export default pipelineRunVerb