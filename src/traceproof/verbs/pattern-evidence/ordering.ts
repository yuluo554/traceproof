/**
 * 排序与编号（迁移自旧仓 `src/lib/ordering.js`）。
 *
 * 规则：severity 降序 → DOM 文档序（dom_order 升序）；编号 F-01… 与排序后顺序一致。
 * 纯函数：不改入参数组。
 */

import type { RuleManifest } from './rules.js'
import { severityRank } from './rules.js'

export const FINDING_ID_PREFIX = 'F-'

export interface Finding {
  readonly rule_id: string
  readonly rule_name: string
  readonly category: string
  readonly severity: string
  readonly snippet: string
  readonly snippet_truncated: boolean
  readonly locator: string
  readonly evidence: readonly { readonly kind: string; readonly value: string }[]
  readonly explanation: string
  readonly dom_order: number
}

export interface NumberedFinding extends Finding {
  readonly finding_id: string
}

/** 返回**新数组**；同级按 dom_order 升序，稳定（同序保持输入顺序）。 */
export function sortFindings(
  findings: readonly Finding[],
  manifest: RuleManifest,
): Finding[] {
  return findings
    .map((finding, index) => ({ finding, index }))
    .sort((left, right) => {
      const delta =
        severityRank(manifest, right.finding.severity) - severityRank(manifest, left.finding.severity)
      if (delta !== 0) return delta
      const byDom = left.finding.dom_order - right.finding.dom_order
      if (byDom !== 0) return byDom
      return left.index - right.index
    })
    .map((entry) => entry.finding)
}

/** 编号：宽度 = max(2, 总数的位数)；同输入同顺序 → 同编号。 */
export function assignFindingIds(findings: readonly Finding[]): NumberedFinding[] {
  const width = Math.max(2, String(findings.length).length)
  return findings.map((finding, index) => ({
    ...finding,
    finding_id: `${FINDING_ID_PREFIX}${String(index + 1).padStart(width, '0')}`,
  }))
}