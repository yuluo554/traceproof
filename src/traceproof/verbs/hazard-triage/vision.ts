/**
 * hazard-triage · 视觉通路与图文融合（源仓 `extract/vision.py` 的判定侧）。
 *
 * 器官**不跑模型、不读图片**：`subject.vision.images[].detections` 是输入事实
 * （class_name / bbox / confidence）。这里只做两件确定性的事：
 *  1. 检出类别名 → 受控词表映射（`head` / `no_helmet` / `person_without_helmet`
 *     → 未佩戴安全帽 HT-GCZY-007；`helmet` 为合规佩戴，不构成隐患）；
 *  2. 同 site_object + 同 hazard_type_id 的文本/视觉卡融合（可带时间窗）。
 *
 * 未登记类别一律丢弃并记 warning（不得硬编码未登记 id）；无真实检出不得伪造。
 */

import { ContractError } from '../../core/ledger.js'
import type { Knowledge } from './knowledge.js'
import { newCard } from './extract.js'
import type { HazardCard } from './extract.js'
import { baseName, isPlainObject, readFiniteNumber, readNumberArray, readString } from './util.js'

export const CLASS_TO_HAZARD: Readonly<Record<string, string>> = {
  head: '未佩戴安全帽',
  no_helmet: '未佩戴安全帽',
  person_without_helmet: '未佩戴安全帽',
}

export interface Detection {
  readonly class_name: string
  readonly bbox: readonly number[]
  readonly confidence: number
}

const TIME_RE = /^(\d{1,2}):(\d{2})(?::(\d{2}))?$/

export function readDetections(value: unknown, where: string): Detection[] {
  if (!Array.isArray(value)) throw new ContractError(`${where} 必须是数组`)
  return value.map((item, index) => {
    const at = `${where}[${index}]`
    if (!isPlainObject(item)) throw new ContractError(`${at} 必须是对象`)
    return {
      class_name: readString(item.class_name, `${at}.class_name`),
      bbox: readNumberArray(item.bbox ?? [], `${at}.bbox`),
      confidence: readFiniteNumber(item.confidence, `${at}.confidence`),
    }
  })
}

/** 单条检出 → 条目卡（映射受控词表）。 */
export function cardFromDetection(
  imageName: string,
  index: number,
  detection: Detection,
  knowledge: Knowledge,
): { card: HazardCard | null; warning: string | null } {
  const hazardName = CLASS_TO_HAZARD[detection.class_name]
  if (hazardName === undefined) {
    return {
      card: null,
      warning: `检出类别 ${JSON.stringify(detection.class_name)} 未登记受控映射，已丢弃（词表缺条目须走受控流程补登记）`,
    }
  }
  const hazardDef = knowledge.hazardTypes.find((hazard) => hazard.name === hazardName)
  if (hazardDef === undefined) {
    return { card: null, warning: `受控词表缺条目 ${JSON.stringify(hazardName)}，已丢弃（不得硬编码未登记 id）` }
  }
  const card = newCard(
    imageName,
    index,
    `图像 ${baseName(imageName)} 检出：${hazardName}`,
    hazardDef,
    'vision',
    hazardDef.site_objects[0] ?? '',
    detection.confidence,
  )
  card.attrs = { bbox: [...detection.bbox], detection_class: detection.class_name }
  card.evidence = { image: baseName(imageName), bbox: [...detection.bbox] }
  return { card, warning: null }
}

export function detectionsToCards(
  knowledge: Knowledge,
  imageName: string,
  detections: readonly Detection[],
): { cards: HazardCard[]; warnings: string[] } {
  const cards: HazardCard[] = []
  const warnings: string[] = []
  detections.forEach((detection, position) => {
    const { card, warning } = cardFromDetection(imageName, position + 1, detection, knowledge)
    if (warning !== null) warnings.push(warning)
    if (card !== null) cards.push(card)
  })
  return { cards, warnings }
}

/** 卡片 attrs['time']（HH:MM[:SS]）→ 当日分钟数；缺时间或不可解析返回 null。 */
export function cardMinutes(card: HazardCard): number | null {
  const raw = card.attrs.time
  if (typeof raw !== 'string' || !raw) return null
  const match = raw.trim().match(TIME_RE)
  if (match === null) return null
  return Number(match[1]) * 60 + Number(match[2]) + Number(match[3] ?? 0) / 60
}

/**
 * 图文融合：同 site_object 且同 hazard_type_id 的文本/视觉卡合并。
 * 两侧均有可解析时间时施加时间窗（含边界）；任一侧缺时间不施加。
 */
export function mergeCards(
  textCards: readonly HazardCard[],
  visionCards: readonly HazardCard[],
  timeWindow = 60,
): { cards: HazardCard[]; warnings: string[] } {
  if (visionCards.length === 0) return { cards: [...textCards], warnings: [] }
  const merged = [...textCards]
  for (const visionCard of visionCards) {
    const visionTime = cardMinutes(visionCard)
    let hit = -1
    for (let index = 0; index < merged.length; index += 1) {
      const textCard = merged[index]
      if (!textCard.site_object || textCard.site_object !== visionCard.site_object) continue
      if (textCard.hazard_type_id !== visionCard.hazard_type_id) continue
      const textTime = cardMinutes(textCard)
      if (textTime !== null && visionTime !== null && Math.abs(textTime - visionTime) > timeWindow) continue
      hit = index
      break
    }
    if (hit < 0) {
      merged.push(visionCard)
      continue
    }
    const textCard = merged[hit]
    const mergedFrom = [...textCard.merged_from]
    for (const from of visionCard.merged_from) {
      if (!mergedFrom.includes(from)) mergedFrom.push(from)
    }
    const evidence: Record<string, unknown> = { ...textCard.evidence }
    const visionEvidence = Array.isArray(evidence.vision) ? (evidence.vision as unknown[]) : []
    evidence.vision = [
      ...visionEvidence,
      {
        image: visionCard.evidence.image,
        bbox: visionCard.evidence.bbox,
        confidence: visionCard.confidence,
      },
    ]
    const attrs: Record<string, unknown> = { ...textCard.attrs }
    for (const [key, value] of Object.entries(visionCard.attrs)) {
      if (!(key in attrs)) attrs[key] = value
    }
    merged[hit] = {
      ...textCard,
      confidence: Math.max(textCard.confidence, visionCard.confidence),
      merged_from: mergedFrom,
      evidence,
      attrs,
    }
  }
  return { cards: merged, warnings: [] }
}