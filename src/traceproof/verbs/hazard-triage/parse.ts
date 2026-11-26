/**
 * hazard-triage · 施工日志文本清洗与记录解析（源仓 `ingest/parsers.py` 的判定侧）。
 *
 * 记录行格式：`[日期 时间] 描述`；时间戳容错 `YYYY-MM-DD` / `YYYY/MM/DD` /
 * `YYYY.MM.DD` / `YYYY年MM月DD日`，时间 `HH:MM` / `HH:MM:SS` / `HH时MM分`（可省略）。
 * 续行合并：时间戳行开启新记录，其后非时间戳、非注释行并入上一条（中日韩相邻直接拼接，
 * ASCII 字母数字两侧补一个空格）。
 *
 * 器官不读文件：文本由 `subject.text` 提供，或 `subject.records` 直接提供已解析记录。
 */

import { ContractError } from '../../core/ledger.js'
import { isPlainObject, readInteger, readString } from './util.js'

export interface LogRecord {
  readonly index: number
  readonly timestamp: string
  readonly text: string
}

/** 记录行：`[YYYY-MM-DD[ HH:MM[:SS]]] 描述`（日期/时间分隔符容错）。 */
export const RECORD_RE =
  /^\[(\d{4})[-/.年](\d{1,2})[-/.月](\d{1,2})日?\s*(?:(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?|(\d{1,2})时(\d{1,2})分?)?\]\s*(.+)$/

/** 单行时间戳（不含方括号与描述），测试与声明用。 */
export const TS_RE =
  /^(\d{4})[-/.年](\d{1,2})[-/.月](\d{1,2})日?\s*(?:(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?|(\d{1,2})时(\d{1,2})分?)?/

export const SKIP_PREFIXES = ['#', '//', '备注', '注：', '注:'] as const

/** 清洗：零宽字符 / BOM、CRLF、全角空格、中文间伪空格；去空行。 */
export function cleanText(raw: string): string {
  let text = raw
  for (const ch of ['\u200b', '\u200c', '\u200d', '\ufeff']) {
    text = text.split(ch).join('')
  }
  text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  text = text.replace(/\u3000/g, ' ')
  text = text.replace(/([\u4e00-\u9fff])[ \t]+(?=[\u4e00-\u9fff])/g, '$1')
  const lines = text.split('\n').map((line) => line.trim())
  return lines.filter((line) => line.length > 0).join('\n')
}

/** `RECORD_RE` 的匹配结果 → 规范化 `YYYY-MM-DD HH:MM`（无时间则仅日期）。 */
export function normalizeTimestamp(match: RegExpMatchArray): string {
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hourRaw = match[4] !== undefined ? match[4] : match[7]
  const minuteRaw = match[5] !== undefined ? match[5] : match[8]
  const date = `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`
  if (hourRaw !== undefined && minuteRaw !== undefined) {
    return `${date} ${String(Number(hourRaw)).padStart(2, '0')}:${String(Number(minuteRaw)).padStart(2, '0')}`
  }
  return date
}

function isAsciiAlnum(ch: string): boolean {
  return /^[A-Za-z0-9]$/.test(ch)
}

/** 续行拼接：中日韩相邻直接拼接，两侧均为 ASCII 字母数字时补空格。 */
export function joinMerged(left: string, right: string): string {
  if (left && right) {
    const last = left[left.length - 1]
    const first = right[0]
    if (isAsciiAlnum(last) && isAsciiAlnum(first)) return `${left} ${right}`
  }
  return left + right
}

export function parseLines(text: string): LogRecord[] {
  const records: LogRecord[] = []
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line) continue
    const match = line.match(RECORD_RE)
    if (match !== null) {
      records.push({
        index: records.length + 1,
        timestamp: normalizeTimestamp(match),
        text: match[9].trim(),
      })
      continue
    }
    if (SKIP_PREFIXES.some((prefix) => line.startsWith(prefix))) continue
    if (records.length > 0) {
      const last = records[records.length - 1]
      records[records.length - 1] = { ...last, text: joinMerged(last.text, line) }
    }
    // 首条记录之前的行视为表头，跳过。
  }
  return records
}

/** 解析 `subject.text`。 */
export function parseLogText(raw: string): LogRecord[] {
  return parseLines(cleanText(raw))
}

/** 校验 `subject.records`（已解析记录由输入提供时使用）。 */
export function readRecords(value: unknown): LogRecord[] {
  if (!Array.isArray(value)) throw new ContractError('records 必须是数组')
  return value.map((item, position) => {
    const where = `records[${position}]`
    if (!isPlainObject(item)) throw new ContractError(`${where} 必须是对象`)
    const index = readInteger(item.index, `${where}.index`)
    if (index < 1) throw new ContractError(`${where}.index 必须从 1 起`)
    return {
      index,
      timestamp: readString(item.timestamp, `${where}.timestamp`),
      text: readString(item.text, `${where}.text`),
    }
  })
}

/** 时间戳单行匹配（测试与声明用）。 */
export function matchTimestampLine(line: string): RegExpMatchArray | null {
  return line.match(TS_RE)
}