/**
 * 返工判定（迁自源仓 `engine/rework.py`，M3 口径）。
 *
 * 1. 版本数 ≥ N 或编辑次数 ≥ M → `rework`；
 * 2. 两条都不成立且**版本链缺失**（有 Edit、链应存在而缺失）→ `insufficient_data`；
 * 3. 两条都不成立且链存在 / 纯 Write 新建 → `not_rework`。
 *
 * 版本链只实读、不反推（源仓 K4）：链由输入 `version_chains` 提供，
 * 快照行（`trackedFileBackups`）只在会话记录里做 `file_path → backup_stem` 关联。
 */

import { REWORK_MIN_EDITS, REWORK_MIN_VERSIONS } from './defaults.js'
import type { SessionIR, SnapshotMapping, ToolUseEvent } from './parse.js'

export const VERDICT_REWORK = 'rework'
export const VERDICT_NOT_REWORK = 'not_rework'
export const VERDICT_INSUFFICIENT = 'insufficient_data'
export const VERDICTS: readonly string[] = [VERDICT_REWORK, VERDICT_NOT_REWORK, VERDICT_INSUFFICIENT]

export const REASON_VERSIONS = 'versions>=N'
export const REASON_EDITS = 'edits>=M'
export const REASON_NO_HIT = 'both_below_threshold'
export const REASON_CHAIN_MISSING = 'version_chain_missing'

export interface ReworkFinding {
  readonly file_path: string
  readonly session_id: string
  readonly verdict: string
  readonly version_count: number | null
  readonly edit_count: number
  readonly first_edit_seq: number
  readonly last_edit_seq: number
  readonly span_seconds: number | null
  readonly reasons: readonly string[]
  readonly evidence: readonly string[]
}

function parseTimestamp(value: string | null): number | null {
  if (typeof value !== 'string' || !value) return null
  let text = value.trim()
  if (text.endsWith('Z')) text = `${text.slice(0, -1)}+00:00`
  const parsed = Date.parse(text)
  return Number.isFinite(parsed) ? parsed : null
}

function spanSeconds(events: readonly ToolUseEvent[]): number | null {
  const times = events.map((event) => parseTimestamp(event.timestamp)).filter((time): time is number => time !== null)
  if (times.length < 2) return null
  return (Math.max(...times) - Math.min(...times)) / 1000
}

function groupWrites(ir: SessionIR): Map<string, ToolUseEvent[]> {
  const grouped = new Map<string, ToolUseEvent[]>()
  for (const event of ir.tool_events) {
    if (event.kind !== 'edit' && event.kind !== 'write') continue
    if (!event.file_path) continue
    const bucket = grouped.get(event.file_path)
    if (bucket === undefined) grouped.set(event.file_path, [event])
    else bucket.push(event)
  }
  return grouped
}

function versionCount(
  filePath: string,
  versionChains: ReadonlyMap<string, readonly number[]>,
  snapshotMap: Readonly<Record<string, SnapshotMapping>>,
): number | null {
  const mapping = snapshotMap[filePath]
  if (mapping === undefined) return null
  const chain = versionChains.get(mapping.backup_stem)
  if (chain === undefined) return null
  return chain.length
}

/** 对会话 IR 的每个被编辑/新建文件给出返工判定（确定性，不读时钟）。 */
export function analyzeRework(
  ir: SessionIR,
  versionChains: ReadonlyMap<string, readonly number[]>,
  snapshotMap: Readonly<Record<string, SnapshotMapping>>,
): ReworkFinding[] {
  const findings: ReworkFinding[] = []
  const grouped = groupWrites(ir)
  for (const filePath of [...grouped.keys()].sort()) {
    const events = grouped.get(filePath) as ToolUseEvent[]
    const writeEvents = events.filter((event) => event.kind === 'write')
    const editCount = events.length
    const versions = versionCount(filePath, versionChains, snapshotMap)
    const chainMissing = versions === null

    const reasons: string[] = []
    const hitVersions = versions !== null && versions >= REWORK_MIN_VERSIONS
    const hitEdits = editCount >= REWORK_MIN_EDITS
    if (hitVersions) reasons.push(REASON_VERSIONS)
    if (hitEdits) reasons.push(REASON_EDITS)

    let verdict: string
    if (hitVersions || hitEdits) {
      verdict = VERDICT_REWORK
    } else if (chainMissing && writeEvents.length === 0) {
      // 无 Write（非新建）且无链：编辑前备份应存在而缺失 → 证据不足（K4）
      verdict = VERDICT_INSUFFICIENT
      reasons.push(REASON_CHAIN_MISSING)
    } else {
      verdict = VERDICT_NOT_REWORK
      reasons.push(REASON_NO_HIT)
    }

    const evidence = events.map((event) => `${ir.meta.source_file}:${event.seq}`)
    if (versions !== null) {
      const stem = snapshotMap[filePath]?.backup_stem ?? ''
      if (stem) evidence.push(`${stem}@v${versions}`)
    }

    findings.push(
      Object.freeze({
        file_path: filePath,
        session_id: ir.meta.session_id,
        verdict,
        version_count: versions,
        edit_count: editCount,
        first_edit_seq: events[0].seq,
        last_edit_seq: events[events.length - 1].seq,
        span_seconds: spanSeconds(events),
        reasons: Object.freeze(reasons),
        evidence: Object.freeze(evidence),
      }),
    )
  }
  return findings
}