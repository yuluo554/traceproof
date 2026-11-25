/**
 * pipeline-run · 运行事件词表 + 折叠（迁自旧仓 `src/run-events.ts`）。
 *
 * 一次运行在父会话持久日志里留下四类事件：
 * `pipeline-run/run-start` -> `agent-start` / `agent-end` 对 -> `run-end`。
 * 本模块是**纯函数**：给定已解析的事件，折叠出运行/节点状态、耗时与 token 汇总。
 * 记录器（`run-recorder.ts`）依赖宿主时钟与 session.append，属于产品级接线，**未迁**。
 *
 * 输出确定性：折叠只依赖事件顺序；同一输入两次运行结果一致。
 */

export type PipelineRunStopReason = 'completed' | 'cancelled' | 'error'
export type PipelineRunAgentOutcome = 'completed' | 'failed' | 'cancelled'
export type PipelineRunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted'

export interface PipelineRunUsageTotals {
  inputTokens: number
  outputTokens: number
  /** 只有至少一条汇总事件报告过该桶时才出现。 */
  totalTokens?: number
  cacheReadTokens?: number
  cacheWriteTokens?: number
  reasoningTokens?: number
}

export interface PipelineRunNodePlan {
  readonly id: string
  /** 该节点每次 agent() 调用携带的 phase 标题（编译器口径）。 */
  readonly label: string
  readonly provider?: string
  readonly model?: string
}

export interface PipelineRunStartData {
  readonly runId: string
  readonly name: string
  /** 计划节点链（IR 拓扑序）——任何 agent 启动前的 pending 行。 */
  readonly nodes: readonly PipelineRunNodePlan[]
  /** 宿主收到 engine.start 受理的时间（ms）。 */
  readonly startedAt: number
}

export interface PipelineRunAgentStartData {
  readonly runId: string
  /** 运行内 1-based 的调用序号。 */
  readonly seq: number
  readonly label: string
  /** 调用发生时的 phase() 标题（引擎没给时缺省）。 */
  readonly phase?: string
  readonly childId: string
  /** 节点声明的路由（定义意图）；缺省 = 跟随会话默认路由。 */
  readonly provider?: string
  readonly model?: string
  /** 宿主收到事件的时间（ms）——agent-end 的耗时基线。 */
  readonly startedAt: number
}

export interface PipelineRunAgentEndData {
  readonly runId: string
  /** 与同 seq 的 agent-start 配对。 */
  readonly seq: number
  readonly outcome: PipelineRunAgentOutcome
  readonly durationMs: number
  /** 子会话 token 汇总；适配器没报 usage 时缺省。 */
  readonly usage?: PipelineRunUsageTotals
}

export interface PipelineRunEndData {
  readonly runId: string
  readonly stopReason: PipelineRunStopReason
  readonly durationMs: number
  /** stopReason = error 时的失败详情。 */
  readonly error?: string
}

export type PipelineRunEvent =
  | { readonly type: 'pipeline-run/run-start'; readonly data: PipelineRunStartData }
  | { readonly type: 'pipeline-run/agent-start'; readonly data: PipelineRunAgentStartData }
  | { readonly type: 'pipeline-run/agent-end'; readonly data: PipelineRunAgentEndData }
  | { readonly type: 'pipeline-run/run-end'; readonly data: PipelineRunEndData }

export interface PipelineRunMemberState {
  readonly seq: number
  readonly label: string
  readonly phase?: string
  readonly childId: string
  readonly provider?: string
  readonly model?: string
  readonly startedAt: number
  readonly outcome?: PipelineRunAgentOutcome
  readonly durationMs?: number
  readonly usage?: PipelineRunUsageTotals
}

export interface PipelineRunState {
  readonly name: string
  readonly nodes: readonly PipelineRunNodePlan[]
  readonly stopReason?: PipelineRunStopReason
  readonly error?: string
  readonly durationMs?: number
  readonly members: readonly PipelineRunMemberState[]
}

export function foldStart(data: PipelineRunStartData): PipelineRunState {
  return { name: data.name, nodes: data.nodes, members: [] }
}

/**
 * 应用一条 start 之后的事件。未知类型（例如重放的 run-start）返回同一个
 * state 引用—— Conversation 引擎依赖这个「引用不变」契约跳过重算。
 */
export function foldUpdate(state: PipelineRunState, event: PipelineRunEvent): PipelineRunState {
  if (event.type === 'pipeline-run/agent-start') {
    const data = event.data
    const member: PipelineRunMemberState = {
      seq: data.seq,
      label: data.label,
      childId: data.childId,
      startedAt: data.startedAt,
      ...(data.phase !== undefined ? { phase: data.phase } : {}),
      ...(data.provider !== undefined ? { provider: data.provider } : {}),
      ...(data.model !== undefined ? { model: data.model } : {}),
    }
    return { ...state, members: [...state.members, member] }
  }
  if (event.type === 'pipeline-run/agent-end') {
    const data = event.data
    return {
      ...state,
      members: state.members.map((member) =>
        member.seq === data.seq
          ? {
              ...member,
              outcome: data.outcome,
              durationMs: data.durationMs,
              ...(data.usage !== undefined ? { usage: data.usage } : {}),
            }
          : member,
      ),
    }
  }
  if (event.type === 'pipeline-run/run-end') {
    const data = event.data
    return {
      ...state,
      stopReason: data.stopReason,
      durationMs: data.durationMs,
      ...(data.error !== undefined ? { error: data.error } : {}),
    }
  }
  return state
}

export interface PipelineRunNodeView {
  readonly id: string
  readonly label: string
  readonly provider?: string
  readonly model?: string
  readonly status: PipelineRunStatus
  /** 该节点已启动的 agent 调用数（retry 重跑会累加）。 */
  readonly attempts: number
  /** 成员 wall time 之和（失败/重试尝试计入——真实成本）。 */
  readonly durationMs: number
  /** 成员 token 之和；没有成员报 usage 时缺省。 */
  readonly usage?: PipelineRunUsageTotals
}

export interface PipelineRunModelTotal {
  /** 声明的 model id；null = 会话默认路由。 */
  readonly model: string | null
  readonly provider?: string
  readonly calls: number
  readonly durationMs: number
  readonly usage?: PipelineRunUsageTotals
}

export interface PipelineRunChatData {
  readonly name: string
  readonly status: PipelineRunStatus
  readonly stopReason?: PipelineRunStopReason
  readonly error?: string
  readonly durationMs?: number
  readonly nodes: readonly PipelineRunNodeView[]
  readonly models: readonly PipelineRunModelTotal[]
}

function memberStatus(member: PipelineRunMemberState, interrupted: boolean): PipelineRunStatus {
  if (member.outcome === undefined) return interrupted ? 'interrupted' : 'running'
  if (member.outcome === 'completed') return 'completed'
  return member.outcome
}

/**
 * 节点状态由成员决定：运行中优先；中断后未完成成员记 interrupted；
 * 否则**最后一条 seq 的成员**说了算——重试恢复则 completed，最后一次失败
 * （abort / skip / retry 耗尽）则 failed。
 */
function nodeStatus(members: readonly PipelineRunMemberState[], interrupted: boolean): PipelineRunStatus {
  if (members.length === 0) return 'pending'
  const statuses = members.map((member) => memberStatus(member, interrupted))
  if (statuses.includes('running')) return 'running'
  if (statuses.includes('interrupted')) return 'interrupted'
  const last = members.reduce((a, b) => (b.seq >= a.seq ? b : a))
  return memberStatus(last, interrupted)
}

/** 汇总 token 桶；在全部成员都缺省的桶保持缺省。 */
export function sumUsage(usages: readonly PipelineRunUsageTotals[]): PipelineRunUsageTotals | undefined {
  if (usages.length === 0) return undefined
  const totals: PipelineRunUsageTotals = { inputTokens: 0, outputTokens: 0 }
  let sawTotal = false
  let sawCacheRead = false
  let sawCacheWrite = false
  let sawReasoning = false
  for (const usage of usages) {
    totals.inputTokens += usage.inputTokens
    totals.outputTokens += usage.outputTokens
    if (usage.totalTokens !== undefined) {
      totals.totalTokens = (totals.totalTokens ?? 0) + usage.totalTokens
      sawTotal = true
    }
    if (usage.cacheReadTokens !== undefined) {
      totals.cacheReadTokens = (totals.cacheReadTokens ?? 0) + usage.cacheReadTokens
      sawCacheRead = true
    }
    if (usage.cacheWriteTokens !== undefined) {
      totals.cacheWriteTokens = (totals.cacheWriteTokens ?? 0) + usage.cacheWriteTokens
      sawCacheWrite = true
    }
    if (usage.reasoningTokens !== undefined) {
      totals.reasoningTokens = (totals.reasoningTokens ?? 0) + usage.reasoningTokens
      sawReasoning = true
    }
  }
  return {
    inputTokens: totals.inputTokens,
    outputTokens: totals.outputTokens,
    ...(sawTotal ? { totalTokens: totals.totalTokens } : {}),
    ...(sawCacheRead ? { cacheReadTokens: totals.cacheReadTokens } : {}),
    ...(sawCacheWrite ? { cacheWriteTokens: totals.cacheWriteTokens } : {}),
    ...(sawReasoning ? { reasoningTokens: totals.reasoningTokens } : {}),
  }
}

/**
 * 把折叠状态投影成运行卡数据。`interrupted` 标记「会话位置已关闭但从未折叠
 * run-end」的运行（断连/重连或宿主死亡）——无 outcome 的成员渲染 interrupted
 * 而不是永远 running。
 */
export function projectPipelineRun(state: PipelineRunState, options: { interrupted?: boolean } = {}): PipelineRunChatData {
  const interrupted = options.interrupted === true
  const membersByPhase = new Map<string, PipelineRunMemberState[]>()
  for (const member of state.members) {
    const key = member.phase ?? member.label
    const group = membersByPhase.get(key)
    if (group === undefined) membersByPhase.set(key, [member])
    else group.push(member)
  }
  const plannedLabels = new Set(state.nodes.map((node) => node.label))
  const views: PipelineRunNodeView[] = []
  for (const plan of state.nodes) {
    const members = membersByPhase.get(plan.label) ?? []
    const usage = sumUsage(members.map((member) => member.usage).filter((u): u is PipelineRunUsageTotals => u !== undefined))
    views.push({
      id: plan.id,
      label: plan.label,
      status: nodeStatus(members, interrupted),
      attempts: members.length,
      durationMs: members.reduce((sum, member) => sum + (member.durationMs ?? 0), 0),
      ...(plan.provider !== undefined ? { provider: plan.provider } : {}),
      ...(plan.model !== undefined ? { model: plan.model } : {}),
      ...(usage !== undefined ? { usage } : {}),
    })
  }
  // phase 匹配不到任何计划节点的成员（防御性：外来或漂移的 phase 标题）
  // 独立成行，不消失。
  for (const [phase, members] of membersByPhase) {
    if (plannedLabels.has(phase)) continue
    const usage = sumUsage(members.map((member) => member.usage).filter((u): u is PipelineRunUsageTotals => u !== undefined))
    views.push({
      id: phase,
      label: phase,
      status: nodeStatus(members, interrupted),
      attempts: members.length,
      durationMs: members.reduce((sum, member) => sum + (member.durationMs ?? 0), 0),
      ...(usage !== undefined ? { usage } : {}),
    })
  }
  // 成本对比：按声明路由（provider|model；null model = 会话默认）分组，
  // 汇总真实开销（含失败尝试）。
  const byRoute = new Map<string, { provider?: string; model: string | null; members: PipelineRunMemberState[] }>()
  for (const member of state.members) {
    const key = `${member.provider ?? ''}|${member.model ?? ''}`
    let route = byRoute.get(key)
    if (route === undefined) {
      route = {
        ...(member.provider !== undefined ? { provider: member.provider } : {}),
        model: member.model ?? null,
        members: [],
      }
      byRoute.set(key, route)
    }
    route.members.push(member)
  }
  const models: PipelineRunModelTotal[] = [...byRoute.values()].map((route) => {
    const usage = sumUsage(route.members.map((member) => member.usage).filter((u): u is PipelineRunUsageTotals => u !== undefined))
    return {
      model: route.model,
      ...(route.provider !== undefined ? { provider: route.provider } : {}),
      calls: route.members.length,
      durationMs: route.members.reduce((sum, member) => sum + (member.durationMs ?? 0), 0),
      ...(usage !== undefined ? { usage } : {}),
    }
  })
  const runStatus =
    state.stopReason === undefined
      ? interrupted
        ? 'interrupted'
        : 'running'
      : state.stopReason === 'error'
        ? 'failed'
        : state.stopReason
  return {
    name: state.name,
    status: runStatus,
    nodes: views,
    models,
    ...(state.stopReason !== undefined ? { stopReason: state.stopReason } : {}),
    ...(state.error !== undefined ? { error: state.error } : {}),
    ...(state.durationMs !== undefined ? { durationMs: state.durationMs } : {}),
  }
}