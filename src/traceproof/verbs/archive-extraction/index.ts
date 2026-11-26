/**
 * archive-extraction · 归档提取取证（迁移自 target-map ④ 行；源仓版本 1.0.1）。
 *
 * 一个 traceproof 器官：把「这份归档在目标平台上会写出什么名字、谁覆盖谁、谁被拒绝」的
 * 主张，逐条对到**同一份已解析结构事实**的确定性重算，再挂到痕迹节点
 * （`session_id + turn + tool_call_id`）。
 *
 * 迁移边界（D1/D18）：只迁判定层——structure 六条 / collision 四条 / accessibility 三级 /
 * encoding 推断 / container 五条 / budget 两条。字节层（EOCD/CD/LFH 解析）、CLI、报告排版、
 * fixture 生成、平台表探测与安装面**不迁**；结构事实由输入 `archive` 提供（已解析载荷）。
 *
 * 输入（`subject`）：
 * ```json
 * {
 *   "archive": {
 *     "probe": {"archive_size":200,"eocd_offset":178,"declared_entries":2,
 *               "declared_cd_size":92,"declared_cd_offset":100,"comment_length":0},
 *     "entries": [{"index":0,"lfh_offset":0,"lfh_end":49,"cd_offset":97,
 *                  "lfh_name_hex":"...","cd_name_hex":"...","lfh_flags":0,"cd_flags":0,
 *                  "lfh_crc":0,"cd_crc":0,"lfh_csize":10,"cd_csize":10,
 *                  "lfh_usize":10,"cd_usize":10,
 *                  "lfh_extra":[],"cd_extra":[{"id":28789,"data_hex":"..."}],
 *                  "method":0,"data_offset":40}],
 *     "cd_span": [100, 192], "zip64": false, "data_b64": "UEsDB..."
 *   },
 *   "targets": ["windows", "macos", "linux"],
 *   "claims": [
 *     {"claim_id":"c1","check":"finding","rule":"structure.NAME_DIVERGES",
 *      "entry_index":0,"asserted":true,
 *      "node":{"session_id":"s-arch-1","turn":1,"tool_call_id":"call-arch-1"}}
 *   ]
 * }
 * ```
 *
 * 判定：与重算一致 → `claim`；不一致且**有痕迹节点** → `refuted`；不一致且无节点 →
 * `inconclusive` 并写明原因。结构事实非法 → `ArchivePayloadError`（退出码 2）；
 * 主张字段非法 / 平台不在 targets → `ContractError`（退出码 3）。
 */

import type { Basis } from '../../core/trace-index.js'
import { CLAIM, ContractError, INCONCLUSIVE, REFUTED, makeRecord } from '../../core/ledger.js'
import type { LedgerRecord, TraceNode } from '../../core/ledger.js'
import { register } from '../../core/registry.js'
import type { Verb } from '../../core/registry.js'

import { readArchive } from './archive.js'
import type { Archive } from './archive.js'
import { checkAccess, countIssues, LEVELS } from './access.js'
import type { AccessVerdict } from './access.js'
import { checkBudget } from './budget.js'
import { checkContainer, findMimetype, CONTAINER_CODES } from './container.js'
import type { ContainerKind } from './container.js'
import {
  checkEncoding,
  countLowConfidence,
  describe,
  EXTRACTORS,
} from './encoding.js'
import type { EncodingBlockEntry } from './encoding.js'
import {
  COLLISION_CODES,
  collisionToJSON,
  findingToJSON,
  sortFindings,
} from './findings.js'
import type { Collision, Finding } from './findings.js'
import { checkFold, PLATFORMS } from './fold.js'
import { platformTables } from './platforms.js'
import type { PlatformTables } from './platforms.js'
import { checkStructure } from './structure.js'
import {
  displayName,
  isPlainObject,
  jsonEqual,
  stableStringify,
} from './util.js'

/** 版本沿用源仓 `src/extract_oracle/__init__.py` 的 `__version__`（不随本产品升版）。 */
export const VERSION = '1.0.1'

export const CHECKS = [
  'accessibility',
  'archive',
  'clean',
  'collision',
  'collision_count',
  'collision_field',
  'container',
  'display',
  'encoding',
  'finding',
  'finding_count',
  'finding_field',
  'platforms',
  'summary',
] as const
export type CheckName = (typeof CHECKS)[number]

export const FINDING_RULES = [
  'structure.NAME_DIVERGES',
  'structure.CRC_DIVERGES',
  'structure.SIZE_DIVERGES',
  'structure.FLAG_DIVERGES',
  'structure.LFH_OVERLAP',
  'structure.CD_COUNT_MISMATCH',
  'encoding.UPATH_CRC_MISMATCH',
  ...CONTAINER_CODES,
  'budget.PATH_OVER_260',
  'budget.COMPONENT_OVER_255',
] as const
export type FindingRule = (typeof FINDING_RULES)[number]

export const ENCODING_FIELDS = [
  'bit11',
  'upath',
  'confidence',
  'preferred',
  'candidate_encodings',
  'candidates',
  'effective_name',
  'predicted_name',
  'predicted_rule',
  'predicted_source',
  'raw_name_hex',
  'extra_ids',
] as const

export const ARCHIVE_FIELDS = [
  'entry_count',
  'declared_entries',
  'cd_actual_entries',
  'zip64',
  'cd_span',
] as const

export const PLATFORM_FIELDS = [
  'ntfs_entries',
  'ntfs_sha256',
  'ntfs_table_id',
  'ntfs_source',
  'macos_strength',
  'linux_strength',
] as const

export const SUMMARY_OFS = [
  'findings',
  'collisions',
  'accessibility_issues',
  'low_confidence',
  'container_findings',
] as const

const SUBJECT_FIELDS = new Set(['archive', 'targets', 'claims'])
const GLOBAL_FIELDS = ['claim_id', 'check', 'node', 'asserted'] as const

const CHECK_FIELDS: Readonly<Record<CheckName, readonly string[]>> = {
  accessibility: ['entry_index', 'platform', 'reasons', 'evidence'],
  archive: ['field'],
  clean: [],
  collision: ['code', 'platform', 'entry_a', 'entry_b'],
  collision_count: ['code', 'platform'],
  collision_field: ['code', 'platform', 'entry_a', 'entry_b', 'path'],
  container: ['field'],
  display: ['entry_index', 'side'],
  encoding: ['entry_index', 'field', 'tool'],
  finding: ['rule', 'entry_index', 'platform'],
  finding_count: ['rule', 'platform'],
  finding_field: ['rule', 'entry_index', 'platform', 'path'],
  platforms: ['field'],
  summary: ['of'],
}

interface Claim {
  readonly claimId: string
  readonly check: CheckName
  readonly asserted: unknown
  readonly node: unknown
  readonly rule: string | null
  readonly entryIndex: number | null
  readonly platform: string | null
  readonly code: string | null
  readonly entryA: number | null
  readonly entryB: number | null
  readonly path: string | null
  readonly field: string | null
  readonly tool: string | null
  readonly side: string | null
  readonly of: string | null
  readonly reasons: readonly string[] | null
  readonly evidence: readonly string[] | null
}

function optionalString(raw: Record<string, unknown>, name: string, where: string): string | null {
  const value = raw[name]
  if (value === undefined || value === null) return null
  if (typeof value !== 'string') throw new ContractError(`${where}.${name} 必须是字符串`)
  return value
}

function optionalInteger(
  raw: Record<string, unknown>,
  name: string,
  where: string,
): number | null {
  const value = raw[name]
  if (value === undefined || value === null) return null
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ContractError(`${where}.${name} 必须是整数`)
  }
  return value
}

function optionalStringArray(
  raw: Record<string, unknown>,
  name: string,
  where: string,
): readonly string[] | null {
  const value = raw[name]
  if (value === undefined || value === null) return null
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new ContractError(`${where}.${name} 必须是字符串数组`)
  }
  return value as string[]
}

function parseTargets(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ContractError('targets 必须是非空数组')
  }
  const picked: string[] = []
  for (const [position, item] of raw.entries()) {
    if (typeof item !== 'string') throw new ContractError(`targets[${position}] 必须是字符串`)
    if (!(PLATFORMS as readonly string[]).includes(item)) {
      throw new ContractError(
        `targets[${position}] 非法：<${item}>（允许 ${PLATFORMS.join(' / ')}）`,
      )
    }
    if (picked.includes(item)) throw new ContractError(`targets 重复：${item}`)
    picked.push(item)
  }
  return picked
}

function readClaim(
  raw: unknown,
  position: number,
  archive: Archive,
  targets: readonly string[],
): Claim {
  const where = `claims[${position}]`
  if (!isPlainObject(raw)) throw new ContractError(`${where} 必须是对象`)
  const check = raw.check
  if (typeof check !== 'string' || !(CHECKS as readonly string[]).includes(check)) {
    throw new ContractError(
      `${where} 的 check 非法：<${String(check)}>（允许 ${CHECKS.join(' / ')}）`,
    )
  }
  const checkName = check as CheckName
  const allowed = new Set<string>([...GLOBAL_FIELDS, ...CHECK_FIELDS[checkName]])
  for (const key of Object.keys(raw)) {
    if (!allowed.has(key)) {
      throw new ContractError(`${where} 的字段 ${key} 不适用于 check=${checkName}`)
    }
  }
  if (!('asserted' in raw)) throw new ContractError(`${where} 缺 asserted`)
  if (typeof raw.claim_id !== 'string') throw new ContractError(`${where}.claim_id 必须是字符串`)
  const claimId = raw.claim_id.trim()
  if (!claimId) throw new ContractError(`${where}.claim_id 不得为空`)

  const rule = optionalString(raw, 'rule', where)
  const platform = optionalString(raw, 'platform', where)
  const code = optionalString(raw, 'code', where)
  const path = optionalString(raw, 'path', where)
  const field = optionalString(raw, 'field', where)
  const tool = optionalString(raw, 'tool', where)
  const side = optionalString(raw, 'side', where)
  const of = optionalString(raw, 'of', where)
  const entryIndex = optionalInteger(raw, 'entry_index', where)
  const entryA = optionalInteger(raw, 'entry_a', where)
  const entryB = optionalInteger(raw, 'entry_b', where)
  const reasons = optionalStringArray(raw, 'reasons', where)
  const evidence = optionalStringArray(raw, 'evidence', where)

  const ensureEntry = (value: number | null, name: string): void => {
    if (value === null) throw new ContractError(`${where}：check=${checkName} 必须带 ${name}`)
    if (value < 0 || value >= archive.entries.length) {
      throw new ContractError(`${where}.${name} 越界：${value}（条目数 ${archive.entries.length}）`)
    }
  }
  const ensurePlatform = (value: string | null): string => {
    if (value === null) throw new ContractError(`${where}：check=${checkName} 必须带 platform`)
    if (!(PLATFORMS as readonly string[]).includes(value)) {
      throw new ContractError(`${where}.platform 非法：<${value}>（允许 ${PLATFORMS.join(' / ')}）`)
    }
    if (!targets.includes(value)) {
      throw new ContractError(`${where}.platform=${value} 不在本次 targets 内`)
    }
    return value
  }
  const ensureRule = (): string => {
    if (rule === null) throw new ContractError(`${where}：check=${checkName} 必须带 rule`)
    if (!(FINDING_RULES as readonly string[]).includes(rule)) {
      throw new ContractError(
        `${where}.rule 非法：<${rule}>（允许 ${FINDING_RULES.join(' / ')}）`,
      )
    }
    return rule
  }

  if (checkName === 'finding') {
    ensureRule()
    if (entryIndex !== null) ensureEntry(entryIndex, 'entry_index')
    if (platform !== null) ensurePlatform(platform)
    if (typeof raw.asserted !== 'boolean') {
      throw new ContractError(`${where}.asserted 必须是布尔值`)
    }
  } else if (checkName === 'finding_count') {
    if (rule !== null) ensureRule()
    if (platform !== null) ensurePlatform(platform)
    if (typeof raw.asserted !== 'number' || !Number.isInteger(raw.asserted)) {
      throw new ContractError(`${where}.asserted 必须是整数`)
    }
  } else if (checkName === 'finding_field') {
    ensureRule()
    if (entryIndex !== null) ensureEntry(entryIndex, 'entry_index')
    if (platform !== null) ensurePlatform(platform)
    if (path === null || path.length === 0) throw new ContractError(`${where} 必须带 path`)
  } else if (checkName === 'collision') {
    if (code === null) throw new ContractError(`${where} 必须带 code`)
    if (!(COLLISION_CODES as readonly string[]).includes(code)) {
      throw new ContractError(`${where}.code 非法：<${code}>`)
    }
    ensurePlatform(platform)
    if (entryA !== null) ensureEntry(entryA, 'entry_a')
    if (entryB !== null) ensureEntry(entryB, 'entry_b')
    if ((entryA === null) !== (entryB === null)) {
      throw new ContractError(`${where}：entry_a / entry_b 必须同时给或同时不给`)
    }
    if (typeof raw.asserted !== 'boolean') {
      throw new ContractError(`${where}.asserted 必须是布尔值`)
    }
  } else if (checkName === 'collision_count') {
    if (code !== null && !(COLLISION_CODES as readonly string[]).includes(code)) {
      throw new ContractError(`${where}.code 非法：<${code}>`)
    }
    if (platform !== null) ensurePlatform(platform)
    if (typeof raw.asserted !== 'number' || !Number.isInteger(raw.asserted)) {
      throw new ContractError(`${where}.asserted 必须是整数`)
    }
  } else if (checkName === 'collision_field') {
    if (code === null) throw new ContractError(`${where} 必须带 code`)
    if (!(COLLISION_CODES as readonly string[]).includes(code)) {
      throw new ContractError(`${where}.code 非法：<${code}>`)
    }
    ensurePlatform(platform)
    ensureEntry(entryA, 'entry_a')
    ensureEntry(entryB, 'entry_b')
    if (path === null || path.length === 0) throw new ContractError(`${where} 必须带 path`)
  } else if (checkName === 'accessibility') {
    ensureEntry(entryIndex, 'entry_index')
    ensurePlatform(platform)
    if (typeof raw.asserted !== 'string' || !(LEVELS as readonly string[]).includes(raw.asserted)) {
      throw new ContractError(`${where}.asserted 必须是 ${LEVELS.join(' / ')} 之一`)
    }
  } else if (checkName === 'encoding') {
    ensureEntry(entryIndex, 'entry_index')
    if (field === null || !(ENCODING_FIELDS as readonly string[]).includes(field)) {
      throw new ContractError(
        `${where}.field 非法：<${String(field)}>（允许 ${ENCODING_FIELDS.join(' / ')}）`,
      )
    }
    if (field.startsWith('predicted_')) {
      if (tool === null || !(EXTRACTORS as readonly string[]).includes(tool)) {
        throw new ContractError(`${where}.tool 必须是 ${EXTRACTORS.join(' / ')} 之一`)
      }
    } else if (tool !== null) {
      throw new ContractError(`${where}：tool 只适用于 predicted_*`)
    }
  } else if (checkName === 'container') {
    if (field === null || !['kind', 'mimetype_index'].includes(field)) {
      throw new ContractError(`${where}.field 必须是 kind 或 mimetype_index`)
    }
  } else if (checkName === 'archive') {
    if (field === null || !(ARCHIVE_FIELDS as readonly string[]).includes(field)) {
      throw new ContractError(`${where}.field 非法：<${String(field)}>`)
    }
  } else if (checkName === 'display') {
    ensureEntry(entryIndex, 'entry_index')
    if (side === null || !['lfh', 'cd'].includes(side)) {
      throw new ContractError(`${where}.side 必须是 lfh 或 cd`)
    }
  } else if (checkName === 'platforms') {
    if (field === null || !(PLATFORM_FIELDS as readonly string[]).includes(field)) {
      throw new ContractError(`${where}.field 非法：<${String(field)}>`)
    }
  } else if (checkName === 'clean') {
    if (typeof raw.asserted !== 'boolean') {
      throw new ContractError(`${where}.asserted 必须是布尔值`)
    }
  } else if (checkName === 'summary') {
    if (of === null || !(SUMMARY_OFS as readonly string[]).includes(of)) {
      throw new ContractError(`${where}.of 非法：<${String(of)}>（允许 ${SUMMARY_OFS.join(' / ')}）`)
    }
    if (typeof raw.asserted !== 'number' || !Number.isInteger(raw.asserted)) {
      throw new ContractError(`${where}.asserted 必须是整数`)
    }
  }

  return {
    claimId,
    check: checkName,
    asserted: raw.asserted,
    node: raw.node,
    rule,
    entryIndex,
    platform,
    code,
    entryA,
    entryB,
    path,
    field,
    tool,
    side,
    of,
    reasons,
    evidence,
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

interface Context {
  readonly archive: Archive
  readonly targets: readonly string[]
  readonly tables: PlatformTables
  readonly findings: readonly Finding[]
  readonly collisions: readonly Collision[]
  readonly accessibility: Record<string, Record<string, AccessVerdict>>
  readonly encoding: readonly EncodingBlockEntry[]
  readonly containerKind: ContainerKind
}

function buildContext(archive: Archive, targets: readonly string[]): Context {
  const tables = platformTables()
  const structureFindings = checkStructure(archive)
  const [encodingFindings, encodingBlock] = checkEncoding(archive)
  const [containerFindings, container] = checkContainer(archive)
  const budgetFindings = checkBudget(archive, targets)
  const findings = sortFindings([
    ...structureFindings,
    ...encodingFindings,
    ...containerFindings,
    ...budgetFindings,
  ])
  return {
    archive,
    targets,
    tables,
    findings,
    collisions: checkFold(archive, targets, tables),
    accessibility: checkAccess(archive, targets, tables),
    encoding: encodingBlock,
    containerKind: container.kind,
  }
}

interface Computed {
  readonly matched: boolean
  readonly actual: unknown
  readonly exists: boolean
  readonly detail: Readonly<Record<string, unknown>>
}

function readPath(value: unknown, path: string): { exists: boolean; value: unknown } {
  const parts = path.split('.')
  if (parts.some((part) => part.length === 0)) return { exists: false, value: null }
  let current: unknown = value
  for (const part of parts) {
    if (Array.isArray(current)) {
      const index = Number(part)
      if (!Number.isInteger(index) || index < 0 || index >= current.length) {
        return { exists: false, value: null }
      }
      current = current[index]
    } else if (isPlainObject(current)) {
      if (!Object.prototype.hasOwnProperty.call(current, part)) {
        return { exists: false, value: null }
      }
      current = current[part]
    } else {
      return { exists: false, value: null }
    }
  }
  return { exists: true, value: current }
}

function matchAsserted(asserted: unknown, actual: unknown, exists = true): boolean {
  return exists && jsonEqual(asserted, actual)
}

function findFinding(context: Context, claim: Claim): Finding | undefined {
  return context.findings.find(
    (item) =>
      item.ruleId === claim.rule &&
      (claim.entryIndex === null || item.entryIndex === claim.entryIndex) &&
      (claim.platform === null ||
        (isPlainObject(item.evidence) && item.evidence.platform === claim.platform)),
  )
}

function findCollision(context: Context, claim: Claim): Collision | undefined {
  return context.collisions.find((item) => {
    if (item.code !== claim.code || item.platform !== claim.platform) return false
    if (claim.entryA === null || claim.entryB === null) return true
    const wanted = [claim.entryA, claim.entryB].sort((a, b) => a - b)
    const actual = [...item.writeOrder].sort((a, b) => a - b)
    return wanted[0] === actual[0] && wanted[1] === actual[1]
  })
}

function computeClaim(claim: Claim, context: Context): Computed {
  const { archive } = context
  switch (claim.check) {
    case 'finding': {
      const found = findFinding(context, claim) !== undefined
      return {
        matched: claim.asserted === found,
        actual: found,
        exists: true,
        detail: { rule: claim.rule, entry_index: claim.entryIndex, platform: claim.platform },
      }
    }
    case 'finding_count': {
      const count = context.findings.filter(
        (item) =>
          (claim.rule === null || item.ruleId === claim.rule) &&
          (claim.platform === null ||
            (isPlainObject(item.evidence) && item.evidence.platform === claim.platform)),
      ).length
      return {
        matched: claim.asserted === count,
        actual: count,
        exists: true,
        detail: { rule: claim.rule, platform: claim.platform },
      }
    }
    case 'finding_field': {
      const finding = findFinding(context, claim)
      if (finding === undefined) {
        return {
          matched: false,
          actual: null,
          exists: false,
          detail: { rule: claim.rule, entry_index: claim.entryIndex, path: claim.path },
        }
      }
      const resolved = readPath(findingToJSON(finding), claim.path as string)
      return {
        matched: matchAsserted(claim.asserted, resolved.value, resolved.exists),
        actual: resolved.value,
        exists: resolved.exists,
        detail: { rule: claim.rule, entry_index: finding.entryIndex, path: claim.path },
      }
    }
    case 'collision': {
      const found = findCollision(context, claim) !== undefined
      return {
        matched: claim.asserted === found,
        actual: found,
        exists: true,
        detail: { code: claim.code, platform: claim.platform },
      }
    }
    case 'collision_count': {
      const count = context.collisions.filter(
        (item) =>
          (claim.code === null || item.code === claim.code) &&
          (claim.platform === null || item.platform === claim.platform),
      ).length
      return {
        matched: claim.asserted === count,
        actual: count,
        exists: true,
        detail: { code: claim.code, platform: claim.platform },
      }
    }
    case 'collision_field': {
      const collision = findCollision(context, claim)
      if (collision === undefined) {
        return {
          matched: false,
          actual: null,
          exists: false,
          detail: { code: claim.code, platform: claim.platform },
        }
      }
      const resolved = readPath(collisionToJSON(collision), claim.path as string)
      return {
        matched: matchAsserted(claim.asserted, resolved.value, resolved.exists),
        actual: resolved.value,
        exists: resolved.exists,
        detail: { code: claim.code, platform: claim.platform, path: claim.path },
      }
    }
    case 'accessibility': {
      const perPlatform = context.accessibility[String(claim.entryIndex)] ?? {}
      const verdict = perPlatform[claim.platform as string]
      if (verdict === undefined) {
        throw new ContractError(
          `accessibility：条目 ${claim.entryIndex} 在 ${claim.platform} 上没有判定`,
        )
      }
      let matched = claim.asserted === verdict.level
      if (matched && claim.reasons !== null) {
        matched = jsonEqual([...claim.reasons], [...verdict.reasons])
      }
      if (matched && claim.evidence !== null) {
        matched = jsonEqual([...claim.evidence], [...verdict.evidence])
      }
      return {
        matched,
        actual: {
          level: verdict.level,
          reasons: [...verdict.reasons],
          evidence: [...verdict.evidence],
        },
        exists: true,
        detail: { entry_index: claim.entryIndex, platform: claim.platform },
      }
    }
    case 'encoding': {
      const block = context.encoding.find((item) => item.entryIndex === claim.entryIndex)
      if (block === undefined) throw new ContractError(`encoding：条目 ${claim.entryIndex} 不存在`)
      const field = claim.field as string
      if (field === 'bit11') {
        return {
          matched: matchAsserted(claim.asserted, block.bit11),
          actual: block.bit11,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'upath') {
        return {
          matched: matchAsserted(claim.asserted, block.upath),
          actual: block.upath,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'confidence') {
        return {
          matched: matchAsserted(claim.asserted, block.confidence),
          actual: block.confidence,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'preferred') {
        return {
          matched: matchAsserted(claim.asserted, block.preferred),
          actual: block.preferred,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'candidate_encodings') {
        const encodings = block.candidates.map((item) => item.encoding)
        return {
          matched: matchAsserted(claim.asserted, encodings),
          actual: encodings,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'candidates') {
        return {
          matched: matchAsserted(claim.asserted, block.candidates),
          actual: block.candidates,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'effective_name') {
        return {
          matched: matchAsserted(claim.asserted, block.effectiveName),
          actual: block.effectiveName,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'raw_name_hex') {
        return {
          matched: matchAsserted(claim.asserted, block.rawNameHex),
          actual: block.rawNameHex,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      if (field === 'extra_ids') {
        const entry = archive.entries[claim.entryIndex as number]
        const ids = describe(entry).extraIds
        return {
          matched: matchAsserted(claim.asserted, ids),
          actual: ids,
          exists: true,
          detail: { entry_index: claim.entryIndex, field },
        }
      }
      const prediction = block.predictedNames[claim.tool as string]
      if (prediction === undefined) throw new ContractError(`encoding：未预言的提取器 ${claim.tool}`)
      let actual: unknown = null
      if (field === 'predicted_name') actual = prediction.name
      else if (field === 'predicted_rule') actual = prediction.rule
      else actual = prediction.source ?? null
      return {
        matched: matchAsserted(claim.asserted, actual),
        actual,
        exists: true,
        detail: { entry_index: claim.entryIndex, field, tool: claim.tool },
      }
    }
    case 'container': {
      if (claim.field === 'kind') {
        return {
          matched: matchAsserted(claim.asserted, context.containerKind),
          actual: context.containerKind,
          exists: true,
          detail: { field: 'kind' },
        }
      }
      const mimetype = findMimetype(archive)
      const index = mimetype === null ? null : mimetype.index
      return {
        matched: matchAsserted(claim.asserted, index),
        actual: index,
        exists: true,
        detail: { field: 'mimetype_index' },
      }
    }
    case 'archive': {
      let actual: unknown
      if (claim.field === 'entry_count') actual = archive.entries.length
      else if (claim.field === 'declared_entries') actual = archive.probe.declaredEntries
      else if (claim.field === 'cd_actual_entries') actual = archive.cdActualEntries
      else if (claim.field === 'zip64') actual = archive.zip64
      else actual = [archive.cdSpan[0], archive.cdSpan[1]]
      return {
        matched: matchAsserted(claim.asserted, actual),
        actual,
        exists: true,
        detail: { field: claim.field },
      }
    }
    case 'display': {
      const entry = archive.entries[claim.entryIndex as number]
      const actual = displayName(claim.side === 'lfh' ? entry.lfhName : entry.cdName)
      return {
        matched: matchAsserted(claim.asserted, actual),
        actual,
        exists: true,
        detail: { entry_index: claim.entryIndex, side: claim.side },
      }
    }
    case 'platforms': {
      const tables = context.tables
      let actual: unknown
      if (claim.field === 'ntfs_entries') actual = tables.windows.entries
      else if (claim.field === 'ntfs_sha256') actual = tables.windows.sha256
      else if (claim.field === 'ntfs_table_id') actual = tables.windows.tableId
      else if (claim.field === 'ntfs_source') actual = tables.windows.source
      else if (claim.field === 'macos_strength') actual = tables.macos.evidence_strength ?? null
      else actual = tables.linux.evidence_strength ?? null
      return {
        matched: matchAsserted(claim.asserted, actual),
        actual,
        exists: true,
        detail: { field: claim.field },
      }
    }
    case 'clean': {
      const actual =
        context.findings.length === 0 &&
        context.collisions.length === 0 &&
        countIssues(context.accessibility) === 0
      return {
        matched: claim.asserted === actual,
        actual,
        exists: true,
        detail: {
          findings: context.findings.length,
          collisions: context.collisions.length,
          accessibility_issues: countIssues(context.accessibility),
        },
      }
    }
    case 'summary': {
      let actual: number
      if (claim.of === 'findings') actual = context.findings.length
      else if (claim.of === 'collisions') actual = context.collisions.length
      else if (claim.of === 'accessibility_issues') actual = countIssues(context.accessibility)
      else if (claim.of === 'low_confidence') actual = countLowConfidence(context.encoding)
      else actual = context.findings.filter((item) => item.ruleId.startsWith('container.')).length
      return {
        matched: claim.asserted === actual,
        actual,
        exists: true,
        detail: { of: claim.of },
      }
    }
  }
}

function describeClaim(claim: Claim): string {
  const parts: string[] = [claim.check]
  if (claim.rule !== null) parts.push(`rule=${claim.rule}`)
  if (claim.code !== null) parts.push(`code=${claim.code}`)
  if (claim.platform !== null) parts.push(`platform=${claim.platform}`)
  if (claim.entryIndex !== null) parts.push(`entry=${claim.entryIndex}`)
  if (claim.entryA !== null) parts.push(`entries=${claim.entryA},${claim.entryB}`)
  if (claim.field !== null) parts.push(`field=${claim.field}`)
  if (claim.tool !== null) parts.push(`tool=${claim.tool}`)
  if (claim.of !== null) parts.push(`of=${claim.of}`)
  if (claim.path !== null) parts.push(`path=${claim.path}`)
  return parts.join(' ')
}

function buildRecord(claim: Claim, computed: Computed, node: TraceNode | null): LedgerRecord {
  const asserted = stableStringify(claim.asserted)
  const actual = computed.exists ? stableStringify(computed.actual) : '<不存在>'
  let verdict: 'claim' | 'refuted' | 'inconclusive' = CLAIM
  let message: string
  if (computed.matched) {
    message = `主张「${describeClaim(claim)} = ${asserted}」与重算一致`
  } else if (node !== null) {
    verdict = REFUTED
    message = `主张「${describeClaim(claim)} = ${asserted}」被重算推翻：实算 ${actual}`
  } else {
    verdict = INCONCLUSIVE
    message = `主张「${describeClaim(claim)} = ${asserted}」与重算不一致（实算 ${actual}），无痕迹节点，按契约降级为 inconclusive`
  }
  return makeRecord({
    claim_id: claim.claimId,
    verdict,
    message,
    node,
    evidence: {
      check: claim.check,
      asserted: claim.asserted,
      computed: computed.actual,
      exists: computed.exists,
      comparison: computed.matched ? 'match' : 'mismatch',
      ...computed.detail,
    },
  })
}

/** 器官主体：归档结构事实 + 目标平台 + 主张 → 取证账本行。 */
export function evaluateArchiveExtraction(
  subject: Record<string, unknown>,
  basis: Basis,
): LedgerRecord[] {
  for (const key of Object.keys(subject)) {
    if (!SUBJECT_FIELDS.has(key)) throw new ContractError(`输入含未知字段：${key}`)
  }
  if (!('archive' in subject)) throw new ContractError('输入缺少 archive')
  if (!('targets' in subject)) throw new ContractError('输入缺少 targets')
  if (!('claims' in subject)) throw new ContractError('输入缺少 claims')
  const archive = readArchive(subject.archive)
  const targets = parseTargets(subject.targets)
  const rawClaims = subject.claims
  if (!Array.isArray(rawClaims) || rawClaims.length === 0) {
    throw new ContractError('claims 必须是非空数组')
  }
  const claims = rawClaims.map((item, position) => readClaim(item, position, archive, targets))
  const seen = new Set<string>()
  for (const claim of claims) {
    if (seen.has(claim.claimId)) throw new ContractError(`claim_id 重复：${claim.claimId}`)
    seen.add(claim.claimId)
  }
  const context = buildContext(archive, targets)
  const records: LedgerRecord[] = []
  for (const claim of claims) {
    const node = resolveNode(basis, claim.node, claim.claimId)
    const computed = computeClaim(claim, context)
    records.push(buildRecord(claim, computed, node))
  }
  return records
}

export const archiveExtractionVerb: Verb = register({
  slug: 'archive-extraction',
  version: VERSION,
  summary: '归档提取取证：双头差分 / 跨平台折叠 / 可访问性 / 编码推断 / 容器与预算，逐条核对主张',
  input_fields: ['archive', 'targets', 'claims'],
  evaluate: evaluateArchiveExtraction,
})

export type { EncodingBlockEntry }