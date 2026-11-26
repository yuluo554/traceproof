/**
 * 判定核心（纯函数）：归一化页面模型 + 规则包 → `{findings, rejected, nodeCount}`。
 *
 * 迁移自旧仓 `src/lib/engine.js`。核心口径（与源仓逐条一致）：
 *  1. 证据门禁：`evidence_required` 取不到 → **丢弃并记 rejected**（不是降级、不是待确认）；
 *  2. 同一节点多规则命中 → 按 manifest.match_priority 归属（先到先得，一个节点只出一条 finding）；
 *  3. 被中和项抑制的候选也记 rejected（"没命中"与"被中和"是两种事实）；
 *  4. snippet 是宿主文本的**原样子串**，超长截断并记 snippet_truncated；
 *  5. explanation 逐字取规则包（不在器官里手写第二份）。
 */

import type { PageNode } from './page-model.js'
import { collectEvidence, makeSnippet, matchesDetect } from './page-model.js'
import type { NumberedFinding, Finding } from './ordering.js'
import { assignFindingIds, sortFindings } from './ordering.js'
import type { LoadedPack } from './rules.js'

export const REJECT_REASON = {
  missingEvidence: 'missing_evidence',
  suppressed: 'suppressed',
  duplicateLocator: 'duplicate_locator',
} as const

export type RejectReason = (typeof REJECT_REASON)[keyof typeof REJECT_REASON]

export const REJECT_REASONS: readonly RejectReason[] = [
  REJECT_REASON.missingEvidence,
  REJECT_REASON.suppressed,
  REJECT_REASON.duplicateLocator,
]

export interface Rejected {
  readonly rule_id: string
  readonly locator: string
  readonly reason: RejectReason
  readonly missing_evidence: readonly string[]
}

export interface ScanResult {
  readonly url: string
  readonly scanned_at: string
  readonly node_count: number
  readonly elapsed_ms: number
  readonly truncated: boolean
  readonly ruleset_version: string
  readonly ruleset_hash: string
  readonly disabled_rule_ids: readonly string[]
  readonly findings: readonly NumberedFinding[]
  readonly rejected: readonly Rejected[]
}

export interface ScanOptions {
  readonly disabledRuleIds?: readonly string[]
}

export interface ScanNodesResult {
  readonly findings: Finding[]
  readonly rejected: Rejected[]
  readonly nodeCount: number
}

/**
 * 逐节点 × 逐规则扫描。节点按 `seq` 升序稳定处理（输入数组顺序不影响结果）。
 */
export function scanNodes(
  nodes: readonly PageNode[],
  pack: LoadedPack,
  options: ScanOptions = {},
): ScanNodesResult {
  const disabled = new Set(options.disabledRuleIds ?? [])
  const maxLen = pack.manifest.thresholds?.snippet_max_len as number
  const ordered = [...nodes].sort((left, right) => left.seq - right.seq)
  const findings: Finding[] = []
  const rejected: Rejected[] = []
  // 去重键：同一 (rule_id, locator) 只出一条。一个 locator 上可能有两个节点——
  // 文本节点与其宿主控件元素共用同一个定位串。**先到先得**（文档序在前者胜），
  // 被丢弃的那条记 rejected（不静默）。
  const claimed = new Set<string>()

  for (const node of ordered) {
    for (const spec of pack.order) {
      if (disabled.has(spec.rule_id)) continue
      const verdict = matchesDetect(node, spec.detect)
      if (verdict.suppressed_by) {
        rejected.push({
          rule_id: spec.rule_id,
          locator: node.path,
          reason: REJECT_REASON.suppressed,
          missing_evidence: [verdict.suppressed_by],
        })
        continue
      }
      if (!verdict.matched) continue

      const key = `${spec.rule_id}|${node.path}`
      if (claimed.has(key)) {
        rejected.push({
          rule_id: spec.rule_id,
          locator: node.path,
          reason: REJECT_REASON.duplicateLocator,
          missing_evidence: [],
        })
        break // 同一 locator 已归属该规则：本节点不再参与更低优先级规则的匹配
      }

      const { evidence, missing } = collectEvidence(node, spec.evidence_required)
      if (missing.length > 0) {
        rejected.push({
          rule_id: spec.rule_id,
          locator: node.path,
          reason: REJECT_REASON.missingEvidence,
          missing_evidence: missing,
        })
        continue
      }

      const { snippet, snippet_truncated } = makeSnippet(node, maxLen)
      claimed.add(key)
      findings.push({
        rule_id: spec.rule_id,
        rule_name: spec.name,
        category: spec.category,
        severity: spec.severity,
        snippet,
        snippet_truncated,
        locator: node.path,
        evidence,
        explanation: spec.explanation,
        dom_order: node.seq,
      })
      break // 该节点已归属一条规则：不再参与更低优先级规则的匹配
    }
  }

  return { findings, rejected, nodeCount: ordered.length }
}

export interface ScanInit {
  readonly url: string
  readonly scannedAt: string
  readonly nodes: readonly PageNode[]
  readonly pack: LoadedPack
  readonly elapsedMs: number
  readonly truncated?: boolean
  readonly disabledRuleIds?: readonly string[]
}

/** 组出 ScanResult（字段顺序为输出契约的一部分）。 */
export function buildScanResult(init: ScanInit): ScanResult {
  const disabledRuleIds = init.disabledRuleIds ?? []
  const { findings, rejected, nodeCount } = scanNodes(init.nodes, init.pack, { disabledRuleIds })
  const numbered = assignFindingIds(sortFindings(findings, init.pack.manifest))
  return {
    url: init.url,
    scanned_at: init.scannedAt,
    node_count: nodeCount,
    elapsed_ms: init.elapsedMs,
    truncated: Boolean(init.truncated),
    ruleset_version: String(init.pack.manifest.ruleset_version ?? ''),
    ruleset_hash: String(init.pack.manifest.ruleset_hash ?? ''),
    disabled_rule_ids: [...disabledRuleIds].sort(),
    findings: numbered,
    rejected,
  }
}