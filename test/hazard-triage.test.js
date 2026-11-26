/**
 * hazard-triage 器官的无损测试。
 *
 * 数据面：源仓 `data/knowledge/`（词表 / 措施 / 阈值 / 规则 / 条文 / 案例）只读导出为
 * `src/traceproof/verbs/hazard-triage/data/*.json`；`samples/hazard-triage*.json` 是
 * 源仓 `demo_gczy` 样例的 67 条记录 + 2 条合成记录（未佩戴安全帽 / 塔吊限位失效）。
 *
 * 判定层对齐：
 *  - parse：四种时间戳格式 / 多行合并 / 注释与表头 / 零宽与全角清洗；
 *  - extract：受控词表正则 / 最长部位匹配 / 多隐患类型；
 *  - judge：四级判定（重大词形 / override / 严重词 / 阈值）/ 兜底规则；
 *  - link + suggest：条款锚点 / 原文摘录 / 建议出处；
 *  - kg：187 节点 / 238 边 / 关系语义 / 实例挂图；
 *  - vision：受控映射 / 时间窗融合；vector：TF-IDF 兜底；
 *  - video：选帧纯函数；paired：漏项 / 多报 / 数值不一致；metrics：F1 / 分级 / 字段级；
 *  - 器官契约：18 类主张、verdict 映射、痕迹节点、确定性、CLI 退出码。
 *
 * 判据 1 的 X = 源仓判定层（D1+D18 机械选 11 个文件）`pytest` 实跑 **128 passed**；
 * 本文件顶层 `test(` 调用数与实跑用例数均 ≥ 128（旧层 AST 函数 128 同样覆盖）。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { main } from '../lib/traceproof/cli.js'
import {
  CLAIM,
  ContractError,
  EXIT_BLOCKED,
  EXIT_CONTRACT,
  EXIT_INPUT,
  EXIT_OK,
  INCONCLUSIVE,
  REFUTED,
} from '../lib/traceproof/core/ledger.js'
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  CLASS_TO_HAZARD,
  cardFromDetection,
  cardMinutes,
  detectionsToCards,
  mergeCards,
  readDetections,
} from '../lib/traceproof/verbs/hazard-triage/vision.js'
import {
  findSiteObject,
  compileHazards,
  createRuleEngine,
  newCard,
} from '../lib/traceproof/verbs/hazard-triage/extract.js'
import {
  buildSeedGraph,
  clauseAnchor,
  kgNodeId,
  pyQuote,
  SimpleGraph,
  attachInstance,
} from '../lib/traceproof/verbs/hazard-triage/graph.js'
import {
  judge,
  LEVELS,
  levelIndex,
  MAJOR_PATTERNS,
  SEVERITY_WORDS,
} from '../lib/traceproof/verbs/hazard-triage/judge.js'
import { buildKnowledge, DEFAULT_KNOWLEDGE, KnowledgePackError } from '../lib/traceproof/verbs/hazard-triage/knowledge.js'
import { linkClauses } from '../lib/traceproof/verbs/hazard-triage/link.js'
import { computeMetrics, fieldStats, FIELDS, metricKey, prf } from '../lib/traceproof/verbs/hazard-triage/metrics.js'
import { detectPairedDiffs, digitMultiset } from '../lib/traceproof/verbs/hazard-triage/paired.js'
import { cleanText, joinMerged, matchTimestampLine, parseLines, parseLogText, readRecords } from '../lib/traceproof/verbs/hazard-triage/parse.js'
import { buildSuggestions } from '../lib/traceproof/verbs/hazard-triage/suggest.js'
import { buildRegulationIndex, fallbackClauses, FALLBACK_NOTE, tokenize, VectorIndex } from '../lib/traceproof/verbs/hazard-triage/vector.js'
import { selectKeyframes } from '../lib/traceproof/verbs/hazard-triage/video.js'
import {
  evaluateHazardTriage,
  hazardTriageVerb,
  VERSION,
} from '../lib/traceproof/verbs/hazard-triage/index.js'

await loadBuiltin()

const SAMPLE_PATH = fileURLToPath(new URL('../samples/hazard-triage.json', import.meta.url))
const TRACES_PATH = fileURLToPath(new URL('../samples/hazard-triage-traces.json', import.meta.url))
const SAMPLE = JSON.parse(readFileSync(SAMPLE_PATH, 'utf8'))
const SAMPLE_TRACES = JSON.parse(readFileSync(TRACES_PATH, 'utf8'))

const K = DEFAULT_KNOWLEDGE
const GRAPH = buildSeedGraph(K)

let claimSeq = 0
function c(overrides = {}) {
  claimSeq += 1
  return {
    claim_id: `c-${claimSeq}`,
    asserted: 'exact',
    node: { session_id: 's-ht-1', turn: claimSeq, tool_call_id: `call-ht-${claimSeq}` },
    ...overrides,
  }
}

function basisOf(nodes = []) {
  return Basis.fromObject({ version: '1', nodes })
}

function evalOne(claim, extra = {}) {
  const nodes = claim.node === undefined || claim.node === null ? [] : [claim.node]
  return [...evaluateHazardTriage({ ...extra, claims: [claim] }, basisOf(nodes))][0]
}

function assertClaim(record) {
  assert.equal(record.verdict, CLAIM, record.message)
}

function cardOf(quote, hazardTypeId, options = {}) {
  const hazard = K.hazardTypeById.get(hazardTypeId)
  assert.ok(hazard, `未知隐患类型 ${hazardTypeId}`)
  const card = newCard(
    '<memory>',
    options.recordIndex ?? 1,
    quote,
    hazard,
    options.extractor ?? 'rules',
    options.siteObject ?? findSiteObject(hazard, quote),
    options.confidence ?? 0.95,
  )
  card.card_id = options.cardId ?? 'HC-00001'
  Object.assign(card.attrs, options.attrs ?? {})
  return card
}

function visionCardOf(quote, hazardTypeId, options = {}) {
  const hazard = K.hazardTypeById.get(hazardTypeId)
  const card = newCard(
    options.image ?? 'img.jpg',
    options.recordIndex ?? 1,
    quote,
    hazard,
    'vision',
    options.siteObject ?? hazard.site_objects[0] ?? '',
    options.confidence ?? 0.7,
  )
  card.attrs = { ...(options.attrs ?? {}) }
  card.evidence = { image: options.image ?? 'img.jpg', bbox: options.bbox ?? [1, 2, 3, 4] }
  return card
}

async function capture(fn) {
  const out = []
  const err = []
  const originalLog = console.log
  const originalWrite = process.stderr.write
  console.log = (...args) => {
    out.push(args.map(String).join(' '))
  }
  process.stderr.write = (chunk) => {
    err.push(String(chunk))
    return true
  }
  try {
    const code = await fn()
    return { code, out: out.join('\n'), err: err.join('') }
  } finally {
    console.log = originalLog
    process.stderr.write = originalWrite
  }
}

function tempSubject(subject) {
  const dir = mkdtempSync(join(tmpdir(), 'hazard-triage-test-'))
  const subjectPath = join(dir, 'subject.json')
  writeFileSync(subjectPath, JSON.stringify(subject))
  return subjectPath
}

// ===========================================================================
// 1. parse
// ===========================================================================

test('parse: cleanText strips zero-width characters and BOM', () => {
  assert.equal(cleanText('\u200b临边\u200c未防护\ufeff'), '临边未防护')
})

test('parse: cleanText normalizes CRLF and CR', () => {
  assert.equal(cleanText('a\r\nb\rc'), 'a\nb\nc')
})

test('parse: full-width space between CJK is normalized then removed as a pseudo space', () => {
  assert.equal(cleanText('塔吊\u3000失效'), '塔吊失效')
})

test('parse: cleanText removes pseudo spaces between CJK characters', () => {
  assert.equal(cleanText('临 边 未 防 护'), '临边未防护')
})

test('parse: cleanText keeps ASCII word spacing', () => {
  assert.equal(cleanText('JGJ 80-2016'), 'JGJ 80-2016')
})

test('parse: cleanText drops blank lines', () => {
  assert.equal(cleanText('a\n\n  \nb'), 'a\nb')
})

test('parse: timestamp hyphen format', () => {
  const records = parseLines('[2026-09-21 08:30] 临边未防护')
  assert.equal(records[0].timestamp, '2026-09-21 08:30')
})

test('parse: timestamp slash format', () => {
  assert.equal(parseLines('[2026/09/22 08:53] x')[0].timestamp, '2026-09-22 08:53')
})

test('parse: timestamp dot format', () => {
  assert.equal(parseLines('[2026.09.23 09:16] x')[0].timestamp, '2026-09-23 09:16')
})

test('parse: timestamp Chinese format', () => {
  assert.equal(parseLines('[2026年09月24日 09:39] x')[0].timestamp, '2026-09-24 09:39')
})

test('parse: timestamp seconds are dropped in normalization', () => {
  assert.equal(parseLines('[2026-09-24 09:39:27] x')[0].timestamp, '2026-09-24 09:39')
})

test('parse: timestamp Chinese hour/minute form', () => {
  assert.equal(parseLines('[2026年9月25日 10时02分] x')[0].timestamp, '2026-09-25 10:02')
})

test('parse: date-only timestamp keeps date', () => {
  assert.equal(parseLines('[2026-09-21] x')[0].timestamp, '2026-09-21')
})

test('parse: single-digit month/day are zero padded', () => {
  assert.equal(parseLines('[2026-9-1 8:05] x')[0].timestamp, '2026-09-01 08:05')
})

test('parse: record index is 1-based and sequential', () => {
  const records = parseLines('[2026-09-21] a\n[2026-09-22] b')
  assert.deepEqual(records.map((record) => record.index), [1, 2])
})

test('parse: header lines before the first record are skipped', () => {
  const records = parseLines('项目：样例\n[2026-09-21] a')
  assert.deepEqual(records.map((record) => record.text), ['a'])
})

test('parse: comment prefixes are skipped', () => {
  const records = parseLines('[2026-09-21] a\n# 注释\n// 注释\n备注 注释\n注：注释')
  assert.equal(records.length, 1)
  assert.equal(records[0].text, 'a')
})

test('parse: CJK continuation lines are merged without a space', () => {
  const records = parseLines('[2026-09-21] 3#楼首层安全通\n    道被占用')
  assert.equal(records[0].text, '3#楼首层安全通道被占用')
})

test('parse: ASCII continuation words get one space', () => {
  assert.equal(joinMerged('abc', 'def'), 'abc def')
})

test('parse: CJK and ASCII continuation get no space', () => {
  assert.equal(joinMerged('塔吊', 'QZ'), '塔吊QZ')
})

test('parse: empty text yields no records', () => {
  assert.deepEqual(parseLines(''), [])
})

test('parse: malformed bracket line becomes a continuation', () => {
  const records = parseLines('[2026-09-21] a\n[bad] b')
  assert.equal(records.length, 1)
  assert.equal(records[0].text, 'a[bad] b')
})

test('parse: matchTimestampLine handles date only', () => {
  const match = matchTimestampLine('2026-09-21')
  assert.ok(match)
  assert.equal(match[1], '2026')
})

test('parse: readRecords validates index/timestamp/text', () => {
  assert.deepEqual(readRecords([{ index: 1, timestamp: 'x', text: 'y' }]), [
    { index: 1, timestamp: 'x', text: 'y' },
  ])
})

test('parse: readRecords rejects index 0', () => {
  assert.throws(() => readRecords([{ index: 0, timestamp: 'x', text: 'y' }]), ContractError)
})

test('parse: parseLogText cleans before parsing', () => {
  const records = parseLogText('临 边\n[2026-09-21] 临 边 未 防 护')
  assert.equal(records[0].text, '临边未防护')
})

// ===========================================================================
// 2. extract
// ===========================================================================

test('extract: known hazard line yields one card', () => {
  const cards = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '3#楼3层临边未设置防护栏杆' }])
  assert.equal(cards.length, 1)
  assert.equal(cards[0].hazard_type_id, 'HT-GCZY-001')
})

test('extract: benign line yields no cards', () => {
  const cards = createRuleEngine(K).extract([
    { index: 1, timestamp: 'x', text: '现场安全巡查总体受控，未发现新增隐患。' },
  ])
  assert.deepEqual(cards, [])
})

test('extract: site object is captured from controlled vocab', () => {
  const cards = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '2#楼5层配电箱无门无锁' }])
  assert.equal(cards[0].site_object, '配电箱')
})

test('extract: longest site object wins', () => {
  const hazard = K.hazardTypeById.get('HT-LSYD-003')
  assert.equal(findSiteObject(hazard, '分配电箱无门'), '分配电箱')
})

test('extract: one record can yield multiple hazard types', () => {
  const cards = createRuleEngine(K).extract([
    { index: 1, timestamp: 'x', text: '临边未设置防护栏杆，作业人员也未系安全带' },
  ])
  assert.deepEqual(cards.map((card) => card.hazard_type_id).sort(), ['HT-GCZY-001', 'HT-GCZY-002'])
})

test('extract: category and work type come from the hazard definition', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }])
  assert.equal(card.category, '高处作业')
  assert.equal(card.work_type, '高处作业')
})

test('extract: quote is the whole record text', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '下午 临边未设置防护栏杆' }])
  assert.equal(card.quote, '下午 临边未设置防护栏杆')
})

test('extract: rules extractor confidence is 0.95', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }])
  assert.equal(card.confidence, 0.95)
})

test('extract: extractor label is rules', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }])
  assert.equal(card.extractor, 'rules')
})

test('extract: attrs start empty', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }])
  assert.deepEqual(card.attrs, {})
})

test('extract: merged_from starts with rules', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }])
  assert.deepEqual(card.merged_from, ['rules'])
})

test('extract: card id is assigned by the pipeline, not the engine', () => {
  const [card] = createRuleEngine(K).extract([{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }])
  assert.equal(card.card_id, null)
})

test('extract: every hazard type has compiled patterns', () => {
  const compiled = compileHazards(K)
  assert.equal(compiled.length, K.hazardTypes.length)
  assert.ok(compiled.every((item) => item.patterns.length > 0))
})

test('extract: missing patterns rejects the knowledge pack', () => {
  const broken = buildKnowledge({
    hazard_types: [{ id: 'HT-X', name: 'X', category: '其他', patterns: [] }],
  })
  assert.throws(() => compileHazards(broken), KnowledgePackError)
})

test('extract: invalid pattern rejects the knowledge pack at build time', () => {
  assert.throws(
    () => buildKnowledge({ hazard_types: [{ id: 'HT-X', name: 'X', category: '其他', patterns: ['('] }] }),
    KnowledgePackError,
  )
})

test('extract: source file label is carried onto the card', () => {
  const [card] = createRuleEngine(K).extract(
    [{ index: 1, timestamp: 'x', text: '临边未设置防护栏杆' }],
    'demo.txt',
  )
  assert.equal(card.source.file, 'demo.txt')
})

test('extract: one hazard type is emitted once per record', () => {
  const cards = createRuleEngine(K).extract([
    { index: 1, timestamp: 'x', text: '临边未设置防护栏杆，另一处临边未设置防护栏杆' },
  ])
  assert.equal(cards.filter((card) => card.hazard_type_id === 'HT-GCZY-001').length, 1)
})

// ===========================================================================
// 3. judge
// ===========================================================================

test('judge: base level comes from the hazard definition', () => {
  const j = judge(cardOf('外架未挂设安全网', 'HT-GCZY-004'), [], K)
  assert.equal(j.risk_level, '一般风险')
})

test('judge: base rule id is RL-<type suffix>', () => {
  const j = judge(cardOf('外架未挂设安全网', 'HT-GCZY-004'), [], K)
  assert.equal(j.rule_id, 'RL-GCZY-004')
})

test('judge: severity word upgrades one level', () => {
  const j = judge(cardOf('外架未挂设安全网，此前已发生坠落伤人事件', 'HT-GCZY-004'), [], K)
  assert.equal(j.risk_level, '较大风险')
  assert.equal(j.upgraded.severity_word, '坠落伤人')
})

test('judge: severity upgrade is capped at major', () => {
  const j = judge(cardOf('深基坑未编制专项施工方案，可能造成伤亡', 'HT-JK-001'), [], K)
  assert.equal(j.risk_level, '重大风险')
})

test('judge: major pattern forces major level', () => {
  const j = judge(cardOf('塔吊回转限位装置失效仍在运行', 'HT-QZ-002'), [], K)
  assert.equal(j.risk_level, '重大风险')
})

test('judge: major pattern is recorded in upgraded', () => {
  const j = judge(cardOf('塔吊回转限位装置失效仍在运行', 'HT-QZ-002'), [], K)
  assert.ok(j.upgraded.major_pattern)
})

test('judge: override fires major level', () => {
  const j = judge(cardOf('附着式升降脚手架未经验收合格即投入使用', 'HT-SJA-002'), [], K)
  assert.equal(j.risk_level, '重大风险')
})

test('judge: override id becomes the rule id', () => {
  const j = judge(cardOf('附着式升降脚手架未经验收合格即投入使用', 'HT-SJA-002'), [], K)
  assert.equal(j.override_id, 'OV-2022-007-3')
  assert.equal(j.rule_id, 'OV-2022-007-3')
})

test('judge: override does not downgrade a major-pattern hit', () => {
  const j = judge(cardOf('塔吊回转限位装置失效仍在运行', 'HT-QZ-002'), [], K)
  assert.equal(j.risk_level, '重大风险')
  assert.equal(j.override_id, 'OV-2022-008-5')
  assert.ok(j.upgraded.major_pattern)
})

test('judge: threshold violation uses level_on_violation', () => {
  const card = cardOf('附着式升降脚手架使用中', 'HT-SJA-002', {
    attrs: { '附着式升降脚手架架体悬臂高度': 7.5 },
  })
  const j = judge(card, [], K)
  assert.equal(j.risk_level, '重大风险')
  assert.equal(j.threshold_id, 'TH-SJA-002')
  assert.equal(j.rule_id, 'RT-SJA-002')
})

test('judge: threshold in range does not fire', () => {
  const card = cardOf('附着式升降脚手架使用中', 'HT-SJA-002', {
    attrs: { '附着式升降脚手架架体悬臂高度': 5.0 },
  })
  const j = judge(card, [], K)
  assert.equal(j.risk_level, '较大风险')
  assert.equal(j.threshold_id, null)
})

test('judge: >= threshold fires for hole size', () => {
  const card = cardOf('预留洞口未防护', 'HT-GCZY-003', { attrs: { 洞口短边尺寸: 500 } })
  const j = judge(card, [], K)
  assert.equal(j.threshold_id, 'TH-GCZY-002')
})

test('judge: not_in range threshold fires outside the range', () => {
  const card = cardOf('配电箱安装高度不合规', 'HT-LSYD-003', {
    attrs: { 固定式配电箱中心点与地面垂直距离: 1.2 },
  })
  const j = judge(card, [], K)
  assert.equal(j.threshold_id, 'TH-LSYD-003')
  assert.equal(j.risk_level, '一般风险')
})

test('judge: threshold not_in does not fire inside the range', () => {
  const card = cardOf('配电箱安装高度不合规', 'HT-LSYD-003', {
    attrs: { 固定式配电箱中心点与地面垂直距离: 1.5 },
  })
  assert.equal(judge(card, [], K).threshold_id, null)
})

test('judge: threshold rules are filtered by hazard type', () => {
  const card = cardOf('漏电保护器失效', 'HT-LSYD-005', {
    attrs: { 漏电保护器额定动作电流: 100 },
  })
  const j = judge(card, [], K)
  assert.equal(j.threshold_id, 'TH-LSYD-001')
})

test('judge: missing attrs never triggers a threshold', () => {
  assert.equal(judge(cardOf('附着式升降脚手架使用中', 'HT-SJA-002'), [], K).threshold_id, null)
})

test('judge: non-number attr is ignored', () => {
  const card = cardOf('附着式升降脚手架使用中', 'HT-SJA-002', {
    attrs: { '附着式升降脚手架架体悬臂高度': '7.5' },
  })
  assert.equal(judge(card, [], K).threshold_id, null)
})

test('judge: first threshold violation wins', () => {
  const card = cardOf('附着式升降脚手架使用中', 'HT-SJA-002', {
    attrs: { '附着式升降脚手架架体悬臂高度': 7.5, '附着式升降脚手架架体悬臂高度与架体高度之比': 0.5 },
  })
  assert.equal(judge(card, [], K).threshold_id, 'TH-SJA-001')
})

test('judge: threshold rule id is RT-*', () => {
  const card = cardOf('附着式升降脚手架使用中', 'HT-SJA-002', {
    attrs: { '附着式升降脚手架架体悬臂高度': 7.5 },
  })
  assert.match(judge(card, [], K).rule_id, /^RT-/)
})

test('judge: low confidence asks for human confirmation', () => {
  const j = judge(cardOf('临边未设置防护栏杆', 'HT-GCZY-001', { confidence: 0.3 }), [], K)
  assert.equal(j.human_confirm, true)
})

test('judge: llm extractor asks for human confirmation', () => {
  const j = judge(cardOf('临边未设置防护栏杆', 'HT-GCZY-001', { extractor: 'llm' }), [], K)
  assert.equal(j.human_confirm, true)
})

test('judge: rules extractor with high confidence needs no confirmation', () => {
  assert.equal(judge(cardOf('临边未设置防护栏杆', 'HT-GCZY-001'), [], K).human_confirm, false)
})

test('judge: clause refs are carried through', () => {
  const refs = [{ standard: 'JGJ 80-2016', clause: '4.1.2', quote: '原文' }]
  const j = judge(cardOf('临边未设置防护栏杆', 'HT-GCZY-001'), refs, K)
  assert.equal(j.clause_refs[0].clause, '4.1.2')
})

test('judge: empty rules fall back to module constants', () => {
  const broken = buildKnowledge({ rules: {} })
  const j = judge(cardOf('塔吊回转限位装置失效仍在运行', 'HT-QZ-002'), [], broken)
  assert.equal(j.risk_level, '重大风险')
})

test('judge: level index of unknown level is 0', () => {
  assert.equal(levelIndex('未知'), 0)
})

test('judge: four levels are fixed', () => {
  assert.deepEqual([...LEVELS], ['低风险', '一般风险', '较大风险', '重大风险'])
})

test('judge: severity words match the source constants', () => {
  assert.deepEqual([...SEVERITY_WORDS], ['坠亡', '伤亡', '死亡', '触电身亡', '坠落伤人', '高坠事故'])
})

test('judge: major patterns match the source constants', () => {
  assert.equal(MAJOR_PATTERNS.length, 3)
})

test('judge: override can only raise the level', () => {
  const j = judge(cardOf('附着式升降脚手架未经验收合格即投入使用', 'HT-SJA-004'), [], K)
  assert.equal(j.risk_level, '重大风险')
})

test('judge: base level of unknown type defaults to general', () => {
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  card.hazard_type_id = 'HT-UNKNOWN'
  assert.equal(judge(card, [], K).base_level, '一般风险')
})

// ===========================================================================
// 4. link and suggest
// ===========================================================================

test('link: clause refs come from the controlled vocab', () => {
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const refs = linkClauses(card, K, GRAPH)
  assert.deepEqual(refs.map((ref) => [ref.standard, ref.clause]), [['JGJ 80-2016', '4.1.2']])
})

test('link: quote is attached from the regulation node', () => {
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const refs = linkClauses(card, K, GRAPH)
  assert.match(refs[0].quote, /防护栏杆/)
})

test('link: types without clause refs stay empty', () => {
  const card = cardOf('作业人员未佩戴安全帽', 'HT-GCZY-007')
  assert.deepEqual(linkClauses(card, K, GRAPH), [])
})

test('link: unknown hazard type has no refs', () => {
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  card.hazard_type_id = 'HT-UNKNOWN'
  assert.deepEqual(linkClauses(card, K, GRAPH), [])
})

test('link: without a graph the quote stays empty', () => {
  const refs = linkClauses(cardOf('临边未设置防护栏杆', 'HT-GCZY-001'), K)
  assert.equal(refs[0].quote, '')
})

test('anchor: clause anchor is kg.html + encoded node id', () => {
  assert.equal(clauseAnchor('JGJ 80-2016', '4.1.2'), 'kg.html#REG%3AJGJ%2080-2016%234.1.2')
})

test('anchor: Chinese clause is percent encoded', () => {
  const anchor = clauseAnchor('建质规〔2022〕2号', '第八条（五）')
  assert.match(anchor, /%E5%BB%BA%E8%B4%A8%E8%A7%84/)
  assert.ok(!anchor.includes(' '))
})

test('anchor: pyQuote encodes reserved characters', () => {
  assert.equal(pyQuote("a b#c'd"), 'a%20b%23c%27d')
})

test('anchor: kg node id format', () => {
  assert.equal(kgNodeId('JGJ 46-2005', '8.1.8'), 'REG:JGJ 46-2005#8.1.8')
})

test('suggest: measure source is carried', () => {
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const j = judge(card, linkClauses(card, K, GRAPH), K)
  assert.deepEqual(buildSuggestions(card, j, K).map((item) => item.source), ['ME-GCZY-001'])
})

test('suggest: suggestion text cites the clause label', () => {
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const j = judge(card, linkClauses(card, K, GRAPH), K)
  assert.match(buildSuggestions(card, j, K)[0].text, /依据 JGJ 80-2016 4\.1\.2/)
})

test('suggest: no measures falls back to the controlled vocab label', () => {
  const hazard = { ...K.hazardTypes[0], measure_ids: [] }
  const knowledge = { ...K, hazardTypeById: new Map([[hazard.id, hazard]]) }
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const out = buildSuggestions(card, judge(card, [], K), knowledge)
  assert.equal(out[0].source, 'fallback')
  assert.match(out[0].text, /受控词表/)
})

test('suggest: fallback keeps the clause label when present', () => {
  const hazard = { ...K.hazardTypeById.get('HT-GCZY-001'), measure_ids: [] }
  const knowledge = { ...K, hazardTypeById: new Map([[hazard.id, hazard]]) }
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const j = judge(card, linkClauses(card, K, GRAPH), K)
  const out = buildSuggestions(card, j, knowledge)
  assert.match(out[0].text, /JGJ 80-2016 4\.1\.2/)
})

test('suggest: unknown measure id is skipped', () => {
  const hazard = { ...K.hazardTypeById.get('HT-GCZY-001'), measure_ids: ['ME-NOPE'] }
  const knowledge = { ...K, hazardTypeById: new Map([[hazard.id, hazard]]) }
  const card = cardOf('临边未设置防护栏杆', 'HT-GCZY-001')
  const out = buildSuggestions(card, judge(card, [], K), knowledge)
  assert.equal(out[0].source, 'fallback')
})

// ===========================================================================
// 5. graph
// ===========================================================================

test('graph: seed graph has 187 nodes', () => {
  assert.equal(GRAPH.nodeCount(), 187)
})

test('graph: seed graph has 238 edges', () => {
  assert.equal(GRAPH.edgeCount(), 238)
})

test('graph: every hazard type has a node', () => {
  for (const hazard of K.hazardTypes) assert.ok(GRAPH.hasNode(`HT:${hazard.id}`), hazard.id)
})

test('graph: every regulation has a node', () => {
  assert.equal(new Set(K.regulations.map((r) => kgNodeId(r.std_id, r.clause))).size, 54)
  for (const regulation of K.regulations) {
    assert.ok(GRAPH.hasNode(kgNodeId(regulation.std_id, regulation.clause)))
  }
})

test('graph: every measure has a node', () => {
  for (const measure of K.measures) assert.ok(GRAPH.hasNode(`MS:${measure.id}`), measure.id)
})

test('graph: eight category nodes', () => {
  const stats = GRAPH.stats()
  assert.equal(stats.nodes_by_type.Category, 8)
})

test('graph: four risk level nodes', () => {
  assert.equal(GRAPH.stats().nodes_by_type.RiskLevel, 4)
})

test('graph: seven work type nodes', () => {
  assert.equal(GRAPH.stats().nodes_by_type.WorkType, 7)
})

test('graph: 44 site object nodes', () => {
  assert.equal(GRAPH.stats().nodes_by_type.SiteObject, 44)
})

test('graph: ten case nodes', () => {
  assert.equal(GRAPH.stats().nodes_by_type.Case, 10)
})

test('graph: hazard 001 has level/category/measure/clause relations', () => {
  const relations = new Set(GRAPH.neighbors('HT:HT-GCZY-001').map(([, relation]) => relation))
  assert.ok(relations.has('风险分级'))
  assert.ok(relations.has('属于'))
  assert.ok(relations.has('整改用'))
  assert.ok(relations.has('应依据'))
})

test('graph: regulation node carries source text', () => {
  const node = GRAPH.getNode('REG:JGJ 46-2005#8.1.3')
  assert.ok(node)
  assert.match(node.text, /开关箱/)
})

test('graph: stats shape has node/edge counts and grouped maps', () => {
  const stats = GRAPH.stats()
  assert.equal(stats.node_count, 187)
  assert.equal(stats.edge_count, 238)
  assert.equal(stats.nodes_by_type.HazardType, 31)
  assert.equal(stats.edges_by_relation.应依据, 28)
})

test('graph: duplicate edges are deduplicated', () => {
  const graph = new SimpleGraph()
  graph.addNode('a', 'A', 'T1')
  graph.addNode('b', 'B', 'T2')
  graph.addEdge('a', 'r', 'b')
  graph.addEdge('a', 'r', 'b')
  assert.equal(graph.edgeCount(), 1)
})

test('graph: missing node lookup returns undefined', () => {
  assert.equal(new SimpleGraph().getNode('nope'), undefined)
})

test('graph: neighbors are bidirectional', () => {
  const graph = new SimpleGraph()
  graph.addNode('a', 'A', 'T1')
  graph.addNode('b', 'B', 'T2')
  graph.addEdge('a', 'r', 'b')
  assert.deepEqual(graph.neighbors('b'), [['a', 'r']])
})

test('graph: addNode updates props on an existing node', () => {
  const graph = new SimpleGraph()
  graph.addNode('a', 'A', 'T1', { x: 1 })
  graph.addNode('a', 'A2', 'T2', { y: 2 })
  assert.equal(graph.getNode('a').label, 'A')
  assert.equal(graph.getNode('a').y, 2)
})

test('graph: attach instance adds hazard instance and edges', () => {
  const graph = buildSeedGraph(K)
  const card = cardOf('3#楼3层临边未设置防护栏杆', 'HT-GCZY-001', { cardId: 'HC-00001' })
  const instanceId = attachInstance(graph, card, { risk_level: '较大风险' })
  assert.equal(instanceId, 'HI:HC-00001')
  assert.ok(graph.hasNode(instanceId))
  assert.ok(graph.hasNode('SO:楼层临边'))
})

test('graph: attach instance records the risk level', () => {
  const graph = buildSeedGraph(K)
  const card = cardOf('3#楼3层临边未设置防护栏杆', 'HT-GCZY-001', { cardId: 'HC-00002' })
  attachInstance(graph, card, { risk_level: '重大风险' })
  assert.equal(graph.getNode('HI:HC-00002').risk_level, '重大风险')
})

// ===========================================================================
// 6. knowledge / schema
// ===========================================================================

test('knowledge: default hazard type count is 31', () => {
  assert.equal(K.hazardTypes.length, 31)
})

test('knowledge: default measure count is 29', () => {
  assert.equal(K.measures.length, 29)
})

test('knowledge: default regulation count is 54', () => {
  assert.equal(K.regulations.length, 54)
})

test('knowledge: default threshold count is 7', () => {
  assert.equal(K.thresholds.length, 7)
})

test('knowledge: default override count is 15', () => {
  assert.equal(K.rules.overrides.length, 15)
})

test('knowledge: default base rule count is 31', () => {
  assert.equal(K.rules.base_rules.length, 31)
})

test('knowledge: rule pack major patterns equal fallback constants', () => {
  assert.deepEqual(K.rules.major_patterns, [...MAJOR_PATTERNS])
})

test('knowledge: rule pack severity words equal fallback constants', () => {
  assert.deepEqual(K.rules.severity_words, [...SEVERITY_WORDS])
})

test('knowledge: override payload has any_of patterns', () => {
  for (const override of K.rules.overrides) assert.ok(override.match.any_of.length > 0)
})

test('knowledge: unknown knowledge key is a contract error', () => {
  assert.throws(() => buildKnowledge({ nope: 1 }), ContractError)
})

test('knowledge: invalid hazard type shape is a knowledge pack error', () => {
  assert.throws(() => buildKnowledge({ hazard_types: [{}] }), KnowledgePackError)
})

test('knowledge: duplicate hazard id is rejected', () => {
  assert.throws(
    () => buildKnowledge({
      hazard_types: [
        { id: 'HT-X', name: 'X', category: '其他', patterns: ['x'] },
        { id: 'HT-X', name: 'Y', category: '其他', patterns: ['y'] },
      ],
    }),
    KnowledgePackError,
  )
})

test('knowledge: threshold without value or range is rejected', () => {
  assert.throws(
    () => buildKnowledge({
      thresholds: [{ id: 'TH-X', param: 'p', op: '>' }],
    }),
    KnowledgePackError,
  )
})

test('knowledge: empty rules pack still builds', () => {
  assert.deepEqual(buildKnowledge({ rules: {} }).rules.major_patterns, [])
})

test('knowledge: categories retain the declared "other" category', () => {
  assert.ok(K.categories.includes('其他'))
})

test('schema: all hazard types have patterns', () => {
  assert.equal(K.hazardTypes.filter((hazard) => hazard.patterns.length > 0).length, 31)
})

test('schema: threshold rules count is 7', () => {
  assert.equal(K.rules.threshold_rules.length, 7)
})

// ===========================================================================
// 7. vision
// ===========================================================================

test('vision: head maps to the helmet hazard name', () => {
  assert.equal(CLASS_TO_HAZARD.head, '未佩戴安全帽')
})

test('vision: no_helmet maps to the helmet hazard name', () => {
  assert.equal(CLASS_TO_HAZARD.no_helmet, '未佩戴安全帽')
})

test('vision: person_without_helmet maps to the helmet hazard name', () => {
  assert.equal(CLASS_TO_HAZARD.person_without_helmet, '未佩戴安全帽')
})

test('vision: helmet is not a hazard mapping', () => {
  assert.equal(CLASS_TO_HAZARD.helmet, undefined)
})

test('vision: detection maps to hazard HT-GCZY-007', () => {
  const { card } = cardFromDetection('shwd_3.jpg', 1, {
    class_name: 'head', bbox: [1, 2, 3, 4], confidence: 0.7,
  }, K)
  assert.equal(card.hazard_type_id, 'HT-GCZY-007')
})

test('vision: bbox is carried into attrs', () => {
  const { card } = cardFromDetection('shwd_3.jpg', 1, {
    class_name: 'head', bbox: [1, 2, 3, 4], confidence: 0.7,
  }, K)
  assert.deepEqual(card.attrs.bbox, [1, 2, 3, 4])
})

test('vision: evidence image is the basename', () => {
  const { card } = cardFromDetection('dir/shwd_3.jpg', 1, {
    class_name: 'head', bbox: [1, 2, 3, 4], confidence: 0.7,
  }, K)
  assert.equal(card.evidence.image, 'shwd_3.jpg')
})

test('vision: confidence comes from the detection', () => {
  const { card } = cardFromDetection('x.jpg', 1, {
    class_name: 'head', bbox: [], confidence: 0.42,
  }, K)
  assert.equal(card.confidence, 0.42)
})

test('vision: site object is the first controlled object', () => {
  const { card } = cardFromDetection('x.jpg', 1, {
    class_name: 'head', bbox: [], confidence: 0.7,
  }, K)
  assert.equal(card.site_object, '外脚手架')
})

test('vision: unmapped class is dropped with a warning', () => {
  const { card, warning } = cardFromDetection('x.jpg', 1, {
    class_name: 'crane', bbox: [], confidence: 0.9,
  }, K)
  assert.equal(card, null)
  assert.match(warning, /crane/)
})

test('vision: unmapped class via detectionsToCards is dropped', () => {
  const out = detectionsToCards(K, 'x.jpg', [{ class_name: 'crane', bbox: [], confidence: 0.9 }])
  assert.equal(out.cards.length, 0)
  assert.equal(out.warnings.length, 1)
})

test('vision: multiple detections produce multiple cards', () => {
  const out = detectionsToCards(K, 'x.jpg', [
    { class_name: 'head', bbox: [], confidence: 0.7 },
    { class_name: 'no_helmet', bbox: [], confidence: 0.8 },
  ])
  assert.equal(out.cards.length, 2)
})

test('vision: empty detections produce no cards', () => {
  assert.deepEqual(detectionsToCards(K, 'x.jpg', []).cards, [])
})

test('vision: readDetections validates detection shapes', () => {
  assert.throws(() => readDetections([{ bbox: [], confidence: 1 }], 'v'), ContractError)
})

test('vision: same site and type merges', () => {
  const text = cardOf('1#楼外脚手架上作业工人未佩戴安全帽', 'HT-GCZY-007', { siteObject: '外脚手架' })
  const vision = visionCardOf('图像 img.jpg 检出：未佩戴安全帽', 'HT-GCZY-007', { siteObject: '外脚手架' })
  assert.equal(mergeCards([text], [vision]).cards.length, 1)
})

test('vision: different hazard type does not merge', () => {
  const text = cardOf('1#楼外脚手架上作业工人未佩戴安全帽', 'HT-GCZY-007', { siteObject: '外脚手架' })
  const vision = visionCardOf('图像 img.jpg 检出：未佩戴安全帽', 'HT-GCZY-002', { siteObject: '外脚手架' })
  assert.equal(mergeCards([text], [vision]).cards.length, 2)
})

test('vision: different site object does not merge', () => {
  const text = cardOf('1#楼外脚手架上作业工人未佩戴安全帽', 'HT-GCZY-007', { siteObject: '外脚手架' })
  const vision = visionCardOf('图像 img.jpg 检出：未佩戴安全帽', 'HT-GCZY-007', { siteObject: '屋面' })
  assert.equal(mergeCards([text], [vision]).cards.length, 2)
})

test('vision: time window inside 60 minutes merges', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '09:30' } })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '10:30' } })
  assert.equal(mergeCards([text], [vision]).cards.length, 1)
})

test('vision: time window boundary 60 minutes merges', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '09:30' } })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '10:30:00' } })
  assert.equal(mergeCards([text], [vision]).cards.length, 1)
})

test('vision: time window beyond 60 minutes does not merge', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '09:30' } })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '10:31' } })
  assert.equal(mergeCards([text], [vision]).cards.length, 2)
})

test('vision: missing time on one side skips the time window', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架' })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '23:59' } })
  assert.equal(mergeCards([text], [vision]).cards.length, 1)
})

test('vision: no vision cards returns a copy unchanged', () => {
  const text = [cardOf('x', 'HT-GCZY-007')]
  const out = mergeCards(text, [])
  assert.deepEqual(out.cards, text)
  assert.notEqual(out.cards, text)
})

test('vision: merged_from unions rules and vision', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架' })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架' })
  assert.deepEqual(mergeCards([text], [vision]).cards[0].merged_from, ['rules', 'vision'])
})

test('vision: fusion takes the higher confidence', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', confidence: 0.95 })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', confidence: 0.7 })
  assert.equal(mergeCards([text], [vision]).cards[0].confidence, 0.95)
})

test('vision: vision evidence is appended to the fused card', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架' })
  const vision = visionCardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', image: 'img.jpg', bbox: [1, 2, 3, 4] })
  const fused = mergeCards([text], [vision]).cards[0]
  assert.deepEqual(fused.evidence.vision, [{ image: 'img.jpg', bbox: [1, 2, 3, 4], confidence: 0.7 }])
})

test('vision: attrs are unioned with text side precedence', () => {
  const text = cardOf('x', 'HT-GCZY-007', { siteObject: '外脚手架', attrs: { time: '09:30' } })
  const vision = visionCardOf('x', 'HT-GCZY-007', {
    siteObject: '外脚手架', attrs: { time: '10:00', detection_class: 'head' },
  })
  const fused = mergeCards([text], [vision]).cards[0]
  assert.equal(fused.attrs.time, '09:30')
  assert.equal(fused.attrs.detection_class, 'head')
})

test('vision: card minutes parse HH:MM', () => {
  const text = cardOf('x', 'HT-GCZY-007', { attrs: { time: '09:30' } })
  assert.equal(cardMinutes(text), 570)
})

test('vision: card minutes parse HH:MM:SS', () => {
  const text = cardOf('x', 'HT-GCZY-007', { attrs: { time: '09:30:30' } })
  assert.equal(cardMinutes(text), 570.5)
})

test('vision: card minutes reject bad time', () => {
  assert.equal(cardMinutes(cardOf('x', 'HT-GCZY-007', { attrs: { time: '9:3' } })), null)
})

// ===========================================================================
// 8. vector
// ===========================================================================

test('vector: tokenize CJK text into character bigrams', () => {
  assert.deepEqual(tokenize('防护'), { 防护: 1 })
})

test('vector: tokenize single character as itself', () => {
  assert.deepEqual(tokenize('塔'), { 塔: 1 })
})

test('vector: tokenize empty text returns empty', () => {
  assert.deepEqual(tokenize(''), {})
})

test('vector: tokenize strips punctuation and spaces', () => {
  assert.deepEqual(tokenize('临边、未防护！'), tokenize('临边未防护'))
})

test('vector: lexical search top1 hits JGJ 80-2016 4.1.2', () => {
  const index = buildRegulationIndex(K)
  const hits = index.search('临边作业 防护栏杆 密目式安全立网 封闭', 3)
  assert.equal(hits[0].doc.standard, 'JGJ 80-2016')
  assert.equal(hits[0].doc.clause, '4.1.2')
})

test('vector: hit scores are non-negative and sorted', () => {
  const scores = buildRegulationIndex(K).search('配电箱 箱门 配锁 专人', 5).map((hit) => hit.score)
  assert.deepEqual(scores, [...scores].sort((left, right) => right - left))
  assert.ok(scores.every((score) => score >= 0))
})

test('vector: top_k bounds the result', () => {
  assert.equal(buildRegulationIndex(K).search('配电箱', 2).length, 2)
})

test('vector: empty index returns empty', () => {
  assert.deepEqual(new VectorIndex([]).search('任何查询'), [])
})

test('vector: empty query returns empty', () => {
  assert.deepEqual(buildRegulationIndex(K).search(''), [])
})

test('vector: injected embedder uses dense cosine path', () => {
  const docs = [
    { id: 'a', text: '安全带 高挂低用', standard: 'S', clause: '1', std_name: '' },
    { id: 'b', text: '配电箱 箱门配锁', standard: 'S', clause: '2', std_name: '' },
  ]
  const index = new VectorIndex(docs, (text) => (text.includes('安全带') ? [1, 0] : [0, 1]))
  assert.equal(index.search('安全带', 1)[0].doc.id, 'a')
})

test('vector: fallback only attaches to cards with empty clause refs', () => {
  const empty = {
    quote: '外脚手架临边未设置防护栏杆也未挂安全网',
    hazard_type: '临边防护缺失',
    judgment: { clause_refs: [] },
  }
  const linked = {
    quote: '配电箱箱门未配锁',
    hazard_type: '配电箱缺陷',
    judgment: { clause_refs: [{ standard: 'JGJ 46-2005', clause: '8.3.2' }] },
  }
  assert.equal(fallbackClauses([empty, linked], buildRegulationIndex(K), 2), 1)
})

test('vector: fallback note marks candidates as non-evidence', () => {
  const card = { quote: '作业人员未佩戴安全帽', hazard_type: '未佩戴安全帽', judgment: { clause_refs: [] } }
  fallbackClauses([card], buildRegulationIndex(K), 2)
  assert.ok(card.fallback_clauses.length > 0)
  assert.ok(card.fallback_clauses.every((item) => item.note === FALLBACK_NOTE))
})

test('vector: fallback respects min_score', () => {
  const card = { quote: '作业人员未佩戴安全帽', hazard_type: '未佩戴安全帽', judgment: { clause_refs: [] } }
  assert.equal(fallbackClauses([card], buildRegulationIndex(K), 2, 0.99), 0)
})

test('vector: fallback does not touch clause refs', () => {
  const card = { quote: '作业人员未佩戴安全帽', hazard_type: '未佩戴安全帽', judgment: { clause_refs: [] } }
  fallbackClauses([card], buildRegulationIndex(K), 2)
  assert.deepEqual(card.judgment.clause_refs, [])
})

// ===========================================================================
// 9. video / paired / metrics
// ===========================================================================

test('video: zero frames returns empty', () => {
  assert.deepEqual(selectKeyframes(0), [])
})

test('video: negative frames returns empty', () => {
  assert.deepEqual(selectKeyframes(-3), [])
})

test('video: fewer frames than max keeps all', () => {
  assert.deepEqual(selectKeyframes(5, 8), [0, 1, 2, 3, 4])
})

test('video: 100 frames at max 8 picks the source frame numbers', () => {
  assert.deepEqual(selectKeyframes(100, 8), [0, 12, 25, 37, 50, 62, 75, 87])
})

test('video: max frames lower bound is one', () => {
  assert.deepEqual(selectKeyframes(10, 0), [0])
})

test('video: selected frames are strictly ascending', () => {
  const frames = selectKeyframes(1000, 8)
  assert.ok(frames.every((frame, index) => index === 0 || frame > frames[index - 1]))
})

test('video: last frame is below the total', () => {
  assert.ok(selectKeyframes(100, 8).at(-1) < 100)
})

test('paired: digit multiset ignores order', () => {
  assert.equal(digitMultiset('5捆 3处'), digitMultiset('3处 5捆'))
})

test('paired: missing timestamp detected', () => {
  const diffs = detectPairedDiffs(
    [{ index: 1, timestamp: 't1', text: 'a' }],
    [],
  )
  assert.equal(diffs[0].kind, 'missing')
})

test('paired: extra timestamp detected', () => {
  const diffs = detectPairedDiffs(
    [],
    [{ index: 1, timestamp: 't1', text: 'a' }],
  )
  assert.equal(diffs[0].kind, 'extra')
})

test('paired: value difference detected by digit multiset', () => {
  const diffs = detectPairedDiffs(
    [{ index: 1, timestamp: 't1', text: '钢管5捆' }],
    [{ index: 1, timestamp: 't1', text: '钢管3捆' }],
  )
  assert.equal(diffs[0].kind, 'value')
})

test('paired: identical records produce no diffs', () => {
  assert.deepEqual(
    detectPairedDiffs([{ index: 1, timestamp: 't1', text: 'a' }], [{ index: 1, timestamp: 't1', text: 'a' }]),
    [],
  )
})

test('paired: diffs are sorted by timestamp', () => {
  const diffs = detectPairedDiffs(
    [{ index: 1, timestamp: 'b', text: 'x' }, { index: 2, timestamp: 'a', text: 'y' }],
    [],
  )
  assert.deepEqual(diffs.map((diff) => diff.timestamp), ['a', 'b'])
})

test('prf: perfect prediction is 1/1/1', () => {
  assert.deepEqual(prf(2, 0, 0), { precision: 1, recall: 1, f1: 1 })
})

test('prf: zero prediction is 1/0/0', () => {
  assert.deepEqual(prf(0, 0, 2), { precision: 1, recall: 0, f1: 0 })
})

test('fieldStats: matching fields count as tp', () => {
  const cards = new Map([['1\u0000001', { hazard_type: 'A', category: 'B', site_object: 'C' }]])
  const gold = new Map([['1\u0000001', { hazard_type: 'A', category: 'B', site_object: 'C' }]])
  const stats = fieldStats(new Set(['1\u0000001']), cards, gold)
  assert.deepEqual(stats.hazard_type, { tp: 1, fp: 0, fn: 0 })
})

test('fieldStats: mismatch counts as fp and fn', () => {
  const cards = new Map([['k', { hazard_type: 'A', category: 'B', site_object: 'C' }]])
  const gold = new Map([['k', { hazard_type: 'X', category: 'B', site_object: 'C' }]])
  const stats = fieldStats(new Set(['k']), cards, gold)
  assert.deepEqual(stats.hazard_type, { tp: 0, fp: 1, fn: 1 })
})

test('fieldStats: one-sided value counts as fp or fn', () => {
  const cards = new Map([['k', { hazard_type: 'A', category: '', site_object: '' }]])
  const gold = new Map([['k', { hazard_type: '', category: 'B', site_object: '' }]])
  const stats = fieldStats(new Set(['k']), cards, gold)
  assert.deepEqual(stats.hazard_type, { tp: 0, fp: 1, fn: 0 })
  assert.deepEqual(stats.category, { tp: 0, fp: 0, fn: 1 })
})

test('metrics: micro F1 is 1 on perfect extraction', () => {
  const cards = [{
    source: { record_index: 1 }, hazard_type_id: 'HT-X', hazard_type: 'X', category: 'C', site_object: 'S',
    judgment: { risk_level: '较大风险' },
  }]
  const gold = [{ index: 1, hazard_type_id: 'HT-X', hazard_type: 'X', category: 'C', site_object: 'S', expected_level: '较大风险' }]
  assert.equal(computeMetrics(cards, gold).micro.f1, 1)
})

test('metrics: false positives are counted', () => {
  const cards = [{
    source: { record_index: 1 }, hazard_type_id: 'HT-X', hazard_type: 'X', category: 'C', site_object: 'S',
    judgment: { risk_level: '较大风险' },
  }]
  assert.equal(computeMetrics(cards, []).micro.fp, 1)
})

test('metrics: level accuracy compares expected level', () => {
  const cards = [{
    source: { record_index: 1 }, hazard_type_id: 'HT-X', hazard_type: 'X', category: 'C', site_object: 'S',
    judgment: { risk_level: '一般风险' },
  }]
  const gold = [{ index: 1, hazard_type_id: 'HT-X', hazard_type: 'X', category: 'C', site_object: 'S', expected_level: '重大风险' }]
  assert.equal(computeMetrics(cards, gold).level_accuracy, 0)
})

test('metrics: field F1 is computed per field', () => {
  const cards = [{
    source: { record_index: 1 }, hazard_type_id: 'HT-X', hazard_type: 'X', category: 'C', site_object: 'S',
    judgment: { risk_level: '较大风险' },
  }]
  const gold = [{ index: 1, hazard_type_id: 'HT-X', hazard_type: 'Y', category: 'C', site_object: 'S', expected_level: '较大风险' }]
  const metrics = computeMetrics(cards, gold)
  assert.equal(metrics.field_f1.hazard_type, 0)
  assert.equal(metrics.field_f1.category, 1)
})

test('metrics: field list is fixed', () => {
  assert.deepEqual([...FIELDS], ['hazard_type', 'category', 'site_object'])
})

test('metrics: key joins record index and hazard type', () => {
  assert.equal(metricKey(7, 'HT-X'), '7\u0000HT-X')
})

// ===========================================================================
// 10. claims / evaluate
// ===========================================================================

test('claim: record exact matches normalized timestamp and text', () => {
  const record = evalOne(c({ check: 'record', asserted: 'exact', record_index: 1, timestamp: '2026-09-21 08:30', text: '临边未设置防护栏杆' }), {
    text: '[2026/09/21 08:30] 临边未设置防护栏杆',
  })
  assertClaim(record)
})

test('claim: record mismatch refutes with a node', () => {
  const record = evalOne(c({ check: 'record', asserted: 'exact', record_index: 1, timestamp: '2026-09-21 08:30', text: '别的文本' }), {
    text: '[2026-09-21 08:30] 临边未设置防护栏杆',
  })
  assert.equal(record.verdict, REFUTED)
})

test('claim: hazard reported matches extraction', () => {
  const record = evalOne(c({ check: 'hazard', asserted: 'reported', record_index: 1, hazard_type_id: 'HT-GCZY-001' }), {
    text: '[2026-09-21 08:30] 3#楼3层临边未设置防护栏杆',
  })
  assertClaim(record)
})

test('claim: hazard absent matches a benign record', () => {
  const record = evalOne(c({ check: 'hazard', asserted: 'absent', record_index: 1, hazard_type_id: 'HT-GCZY-001' }), {
    text: '[2026-09-21 08:30] 现场安全巡查总体受控',
  })
  assertClaim(record)
})

test('claim: hazard detail mismatch refutes', () => {
  const record = evalOne(c({
    check: 'hazard', asserted: 'reported', record_index: 1, hazard_type_id: 'HT-GCZY-001', site_object: '屋面',
  }), { text: '[2026-09-21 08:30] 3#楼3层临边未设置防护栏杆' })
  assert.equal(record.verdict, REFUTED)
})

test('claim: count records', () => {
  const record = evalOne(c({ check: 'count', asserted: '2', of: 'records' }), {
    text: '[2026-09-21] a\n[2026-09-22] b',
  })
  assertClaim(record)
})

test('claim: count hazards', () => {
  const record = evalOne(c({ check: 'count', asserted: '1', of: 'hazards' }), {
    text: '[2026-09-21] 临边未设置防护栏杆',
  })
  assertClaim(record)
})

test('claim: count by type', () => {
  const record = evalOne(c({ check: 'count', asserted: '1', of: 'type', hazard_type_id: 'HT-GCZY-001' }), {
    text: '[2026-09-21] 临边未设置防护栏杆',
  })
  assertClaim(record)
})

test('claim: count by level', () => {
  const record = evalOne(c({ check: 'count', asserted: '1', of: 'level', risk_level: '较大风险' }), {
    text: '[2026-09-21] 临边未设置防护栏杆',
  })
  assertClaim(record)
})

test('claim: count suggestions', () => {
  const record = evalOne(c({ check: 'count', asserted: '1', of: 'suggestions' }), {
    text: '[2026-09-21] 临边未设置防护栏杆',
  })
  assertClaim(record)
})

test('claim: count fallback cards', () => {
  const record = evalOne(c({ check: 'count', asserted: '1', of: 'fallback' }), {
    text: '[2026-09-21] 作业人员未佩戴安全帽',
  })
  assertClaim(record)
})

test('claim: level matches risk level and rule id', () => {
  const record = evalOne(c({
    check: 'level', asserted: '较大风险', record_index: 1, hazard_type_id: 'HT-GCZY-001', rule_id: 'RL-GCZY-001',
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: level mismatch refutes', () => {
  const record = evalOne(c({
    check: 'level', asserted: '重大风险', record_index: 1, hazard_type_id: 'HT-GCZY-001',
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assert.equal(record.verdict, REFUTED)
})

test('claim: clause linked matches clause refs', () => {
  const record = evalOne(c({
    check: 'clause', asserted: 'linked', record_index: 1, hazard_type_id: 'HT-GCZY-001',
    clause_refs: [{ standard: 'JGJ 80-2016', clause: '4.1.2' }], require_quotes: true,
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: clause unlinked matches a type without refs', () => {
  const record = evalOne(c({
    check: 'clause', asserted: 'unlinked', record_index: 1, hazard_type_id: 'HT-GCZY-007', clause_refs: [],
  }), { text: '[2026-09-21] 作业人员未佩戴安全帽' })
  assertClaim(record)
})

test('claim: clause mismatch refutes', () => {
  const record = evalOne(c({
    check: 'clause', asserted: 'unlinked', record_index: 1, hazard_type_id: 'HT-GCZY-001',
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assert.equal(record.verdict, REFUTED)
})

test('claim: anchor exact matches', () => {
  const record = evalOne(c({
    check: 'anchor', asserted: 'exact', standard: 'JGJ 80-2016', clause: '4.1.2',
    anchor: 'kg.html#REG%3AJGJ%2080-2016%234.1.2',
  }))
  assertClaim(record)
})

test('claim: anchor mismatch refutes', () => {
  const record = evalOne(c({
    check: 'anchor', asserted: 'exact', standard: 'JGJ 80-2016', clause: '4.1.2', anchor: 'kg.html#nope',
  }))
  assert.equal(record.verdict, REFUTED)
})

test('claim: anchor to a missing regulation node refutes', () => {
  const record = evalOne(c({
    check: 'anchor', asserted: 'exact', standard: 'NOPE', clause: '1',
    anchor: clauseAnchor('NOPE', '1'),
  }))
  assert.equal(record.verdict, REFUTED)
})

test('claim: suggestion sources match', () => {
  const record = evalOne(c({
    check: 'suggestion', asserted: 'sourced', record_index: 1, hazard_type_id: 'HT-GCZY-001',
    sources: ['ME-GCZY-001'],
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: suggestion contains terms match', () => {
  const record = evalOne(c({
    check: 'suggestion', asserted: 'sourced', record_index: 1, hazard_type_id: 'HT-GCZY-001',
    contains: ['依据 JGJ 80-2016 4.1.2'],
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: graph node count', () => {
  assertClaim(evalOne(c({ check: 'graph', asserted: '187', of: 'node-count' })))
})

test('claim: graph edge count', () => {
  assertClaim(evalOne(c({ check: 'graph', asserted: '238', of: 'edge-count' })))
})

test('claim: graph nodes of type', () => {
  assertClaim(evalOne(c({ check: 'graph', asserted: '31', of: 'nodes-of-type', node_type: 'HazardType' })))
})

test('claim: graph edges of relation', () => {
  assertClaim(evalOne(c({ check: 'graph', asserted: '28', of: 'edges-of-relation', relation: '应依据' })))
})

test('claim: node present with expected type', () => {
  assertClaim(evalOne(c({
    check: 'node', asserted: 'present', node_id: 'HT:HT-GCZY-001', node_type: 'HazardType',
    relations: ['风险分级', '属于', '整改用', '应依据'],
  })))
})

test('claim: node absent matches', () => {
  assertClaim(evalOne(c({ check: 'node', asserted: 'absent', node_id: 'HT:HT-NOPE' })))
})

test('claim: schema hazard type count', () => {
  assertClaim(evalOne(c({ check: 'schema', asserted: '31', of: 'hazard-types' })))
})

test('claim: schema measure count', () => {
  assertClaim(evalOne(c({ check: 'schema', asserted: '29', of: 'measures' })))
})

test('claim: schema regulation count', () => {
  assertClaim(evalOne(c({ check: 'schema', asserted: '54', of: 'regulations' })))
})

test('claim: consistency base rules', () => {
  assertClaim(evalOne(c({ check: 'consistency', asserted: 'consistent', kind: 'base-rules' })))
})

test('claim: consistency pattern coverage', () => {
  assertClaim(evalOne(c({ check: 'consistency', asserted: 'consistent', kind: 'pattern-coverage' })))
})

test('claim: consistency measure refs', () => {
  assertClaim(evalOne(c({ check: 'consistency', asserted: 'consistent', kind: 'measure-refs' })))
})

test('claim: consistency clause refs', () => {
  assertClaim(evalOne(c({ check: 'consistency', asserted: 'consistent', kind: 'clause-refs' })))
})

test('claim: consistency kg nodes', () => {
  assertClaim(evalOne(c({ check: 'consistency', asserted: 'consistent', kind: 'kg-nodes' })))
})

test('claim: consistency rule fallback', () => {
  assertClaim(evalOne(c({ check: 'consistency', asserted: 'consistent', kind: 'rule-fallback' })))
})

test('claim: vision mapped with bbox and confidence', () => {
  const record = evalOne(c({
    check: 'vision', asserted: 'mapped', image: 'shwd_3.jpg', detection_index: 1,
    hazard_type_id: 'HT-GCZY-007', bbox: [1, 2, 3, 4], confidence: 0.7,
  }), { vision: { images: [{ name: 'shwd_3.jpg', detections: [{ class_name: 'head', bbox: [1, 2, 3, 4], confidence: 0.7 }] }] } })
  assertClaim(record)
})

test('claim: vision dropped matches an unmapped class', () => {
  const record = evalOne(c({
    check: 'vision', asserted: 'dropped', image: 'x.jpg', detection_index: 1,
  }), { vision: { images: [{ name: 'x.jpg', detections: [{ class_name: 'crane', bbox: [], confidence: 0.9 }] }] } })
  assertClaim(record)
})

test('claim: merge detects rules + vision fusion', () => {
  const record = evalOne(c({
    check: 'merge', asserted: 'merged', record_index: 1, hazard_type_id: 'HT-GCZY-007',
    merged_from: ['rules', 'vision'], confidence: 0.95, evidence_images: ['img.jpg'],
  }), {
    text: '[2026-09-21] 1#楼外脚手架上作业工人未佩戴安全帽',
    vision: { images: [{ name: 'img.jpg', detections: [{ class_name: 'head', bbox: [1, 2], confidence: 0.7 }] }] },
  })
  assertClaim(record)
})

test('claim: merge unmerged when no vision input', () => {
  const record = evalOne(c({
    check: 'merge', asserted: 'unmerged', record_index: 1, hazard_type_id: 'HT-GCZY-007',
    merged_from: ['rules'],
  }), { text: '[2026-09-21] 1#楼外脚手架上作业人员未佩戴安全帽' })
  assertClaim(record)
})

test('claim: fallback candidates with expected clauses', () => {
  const record = evalOne(c({
    check: 'fallback', asserted: 'candidates', record_index: 1, hazard_type_id: 'HT-GCZY-007',
  }), { text: '[2026-09-21] 作业人员未佩戴安全帽' })
  assertClaim(record)
})

test('claim: fallback none for a linked card', () => {
  const record = evalOne(c({
    check: 'fallback', asserted: 'none', record_index: 1, hazard_type_id: 'HT-GCZY-001',
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: keyframes exact', () => {
  assertClaim(evalOne(c({
    check: 'keyframes', asserted: 'exact', total_frames: 100, max_frames: 8,
    frames: [0, 12, 25, 37, 50, 62, 75, 87],
  })))
})

test('claim: keyframes count assertion', () => {
  assertClaim(evalOne(c({ check: 'keyframes', asserted: '8', total_frames: 100, max_frames: 8 })))
})

test('claim: paired missing present', () => {
  const record = evalOne(c({ check: 'paired', asserted: 'present', kind: 'missing', timestamp: 't1' }), {
    paired: { log: [{ index: 1, timestamp: 't1', text: 'a' }], patrol: [] },
  })
  assertClaim(record)
})

test('claim: paired absent for unknown timestamp', () => {
  const record = evalOne(c({ check: 'paired', asserted: 'absent', kind: 'missing', timestamp: 't9' }), {
    paired: { log: [{ index: 1, timestamp: 't1', text: 'a' }], patrol: [] },
  })
  assertClaim(record)
})

test('claim: metric micro F1', () => {
  const record = evalOne(c({ check: 'metric', asserted: '1', of: 'micro-f1' }), {
    text: '[2026-09-21] 临边未设置防护栏杆',
    gold: { records: [{ index: 1, hazard_type_id: 'HT-GCZY-001', hazard_type: '临边防护缺失', category: '高处作业', site_object: '楼层临边', expected_level: '较大风险' }] },
  })
  assertClaim(record)
})

test('claim: metric field F1 with field', () => {
  const record = evalOne(c({ check: 'metric', asserted: '1', of: 'field-f1', field: 'site_object' }), {
    text: '[2026-09-21] 3#楼3层楼层临边未设置防护栏杆',
    gold: { records: [{ index: 1, hazard_type_id: 'HT-GCZY-001', hazard_type: '临边防护缺失', category: '高处作业', site_object: '楼层临边', expected_level: '较大风险' }] },
  })
  assertClaim(record)
})

test('claim: metric tolerance allows small drift', () => {
  const record = evalOne(c({ check: 'metric', asserted: '0.99', of: 'micro-f1', tolerance: 0.02 }), {
    text: '[2026-09-21] 临边未设置防护栏杆',
    gold: { records: [{ index: 1, hazard_type_id: 'HT-GCZY-001', hazard_type: '临边防护缺失', category: '高处作业', site_object: '楼层临边', expected_level: '较大风险' }] },
  })
  assertClaim(record)
})

test('claim: candidate valid when quote is a substring', () => {
  const record = evalOne(c({
    check: 'candidate', asserted: 'valid', record_index: 1, hazard_type_id: 'HT-GCZY-001', quote: '临边未设置防护栏杆',
  }), { text: '[2026-09-21] 3#楼3层楼层临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: candidate invalid for a fabricated quote', () => {
  const record = evalOne(c({
    check: 'candidate', asserted: 'invalid', record_index: 1, hazard_type_id: 'HT-GCZY-001', quote: '原文没有这句',
  }), { text: '[2026-09-21] 3#楼3层楼层临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: candidate invalid for an unknown category', () => {
  const record = evalOne(c({
    check: 'candidate', asserted: 'invalid', record_index: 1, hazard_type_id: 'HT-GCZY-001',
    quote: '临边未设置防护栏杆', category: '未知类别',
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assertClaim(record)
})

test('claim: mismatch without a node becomes inconclusive', () => {
  const record = evalOne(c({
    check: 'hazard', asserted: 'absent', record_index: 1, hazard_type_id: 'HT-GCZY-001', node: null,
  }), { text: '[2026-09-21] 临边未设置防护栏杆' })
  assert.equal(record.verdict, INCONCLUSIVE)
})

test('claim: incomplete node downgrades refuted to inconclusive', () => {
  const claim = c({
    check: 'hazard', asserted: 'absent', record_index: 1, hazard_type_id: 'HT-GCZY-001',
    node: { session_id: 's-ht-1', turn: null, tool_call_id: '' },
  })
  const record = evalOne(claim, { text: '[2026-09-21] 临边未设置防护栏杆' })
  assert.equal(record.verdict, INCONCLUSIVE)
  assert.match(record.message, /痕迹节点不完整/)
})

test('claim: missing basis node throws NodeMissing', () => {
  const claim = c({
    check: 'schema', asserted: '31', of: 'hazard-types',
    node: { session_id: 's-ht-nope', turn: 1, tool_call_id: 'call-nope' },
  })
  assert.throws(
    () => [...evaluateHazardTriage({ claims: [claim] }, basisOf([]))],
    NodeMissing,
  )
})

test('claim: duplicate claim ids are rejected', () => {
  const subject = { claims: [c({ check: 'schema', asserted: '31', of: 'hazard-types' }), c({ check: 'schema', asserted: '31', of: 'hazard-types' })] }
  subject.claims[1].claim_id = subject.claims[0].claim_id
  assert.throws(() => [...evaluateHazardTriage(subject, basisOf([subject.claims[0].node]))], ContractError)
})

test('claim: empty claims array is rejected', () => {
  assert.throws(() => evaluateHazardTriage({ claims: [] }, basisOf([])), ContractError)
})

test('claim: unknown check is rejected', () => {
  assert.throws(() => evalOne(c({ check: 'nope', asserted: 'x' })), ContractError)
})

test('claim: unknown claim field is rejected', () => {
  assert.throws(() => evalOne(c({ check: 'schema', asserted: '31', of: 'hazard-types', nope: 1 })), ContractError)
})

test('claim: unknown subject field is rejected', () => {
  assert.throws(() => evaluateHazardTriage({ claims: [c({ check: 'schema', asserted: '31', of: 'hazard-types' })], nope: 1 }, basisOf([])), ContractError)
})

test('claim: invalid asserted value is rejected', () => {
  assert.throws(() => evalOne(c({ check: 'hazard', asserted: 'maybe', record_index: 1, hazard_type_id: 'HT-GCZY-001' })), ContractError)
})

test('claim: non-numeric count asserted is rejected', () => {
  assert.throws(() => evalOne(c({ check: 'count', asserted: 'many', of: 'records' })), ContractError)
})

test('claim: missing required field is rejected', () => {
  assert.throws(() => evalOne(c({ check: 'hazard', asserted: 'reported', record_index: 1 })), ContractError)
})

test('claim: text and records are mutually exclusive', () => {
  assert.throws(() => evaluateHazardTriage({
    text: '[2026-09-21] a', records: [{ index: 1, timestamp: 't', text: 'a' }],
    claims: [c({ check: 'count', asserted: '1', of: 'records' })],
  }, basisOf([])), ContractError)
})

test('claim: missing records is rejected when founds are needed', () => {
  assert.throws(() => evalOne(c({ check: 'count', asserted: '1', of: 'records' })), ContractError)
})

test('claim: metric needs gold', () => {
  assert.throws(() => evalOne(c({ check: 'metric', asserted: '1', of: 'micro-f1' }), { text: '[2026-09-21] a' }), ContractError)
})

test('claim: paired needs paired input', () => {
  assert.throws(() => evalOne(c({ check: 'paired', asserted: 'present', kind: 'missing', timestamp: 't1' })), ContractError)
})

test('claim: vision needs vision input', () => {
  assert.throws(() => evalOne(c({ check: 'vision', asserted: 'mapped', image: 'x.jpg', detection_index: 1 })), ContractError)
})

test('claim: evaluation is deterministic byte-for-byte', () => {
  const claims = [
    c({ check: 'schema', asserted: '31', of: 'hazard-types' }),
    c({ check: 'graph', asserted: '187', of: 'node-count' }),
  ]
  const first = JSON.stringify([...evaluateHazardTriage({ claims }, basisOf(claims.map((claim) => claim.node)))])
  const second = JSON.stringify([...evaluateHazardTriage({ claims }, basisOf(claims.map((claim) => claim.node)))])
  assert.equal(first, second)
})

test('claim: sample subject has 57 claims and rc 0', async () => {
  const { code, out } = await capture(() =>
    main(['check', 'hazard-triage', '--input', SAMPLE_PATH, '--basis', TRACES_PATH]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /合计 57 条，阻断 0 条/)
})

test('claim: sample with --json rc 0 and summary', async () => {
  const { code, out } = await capture(() =>
    main(['check', 'hazard-triage', '--input', SAMPLE_PATH, '--basis', TRACES_PATH, '--json']),
  )
  assert.equal(code, EXIT_OK)
  const payload = JSON.parse(out)
  assert.equal(payload.verb, 'hazard-triage')
  assert.equal(payload.verb_version, '0.1.1')
  assert.equal(payload.summary.total, 57)
  assert.equal(payload.summary.blocking, 0)
})

test('claim: sample traces cover all 57 claims', () => {
  assert.equal(SAMPLE.claims.length, 57)
  assert.equal(SAMPLE_TRACES.nodes.length, 57)
  assert.deepEqual(SAMPLE.claims.map((claim) => claim.claim_id), [...SAMPLE.claims.map((claim) => claim.claim_id)].sort())
})

test('claim: version is sourced from the old repository', () => {
  assert.equal(VERSION, '0.1.1')
  assert.equal(get('hazard-triage').version, '0.1.1')
})

test('claim: registry contains 8 builtin verbs in dictionary order', () => {
  assert.deepEqual([...BUILTIN_MODULES], [
    'agent-conflict',
    'anonymity-collapse',
    'email-evidence',
    'hazard-triage',
    'pattern-evidence',
    'pipeline-run',
    'rework-evidence',
    'session-replay',
  ])
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
})

test('claim: verb declares only the claims input field', () => {
  assert.deepEqual([...hazardTriageVerb.input_fields], ['claims'])
})

// ===========================================================================
// 11. CLI exit codes
// ===========================================================================

test('cli: list shows hazard-triage with its version', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /hazard-triage\s+0\.1\.1/)
})

test('cli: refuted claim exits 1', async () => {
  const claim = c({
    check: 'hazard', asserted: 'absent', record_index: 1, hazard_type_id: 'HT-GCZY-001',
    node: { session_id: 's-site-1', turn: 1, tool_call_id: 'call-site-1' },
  })
  const subjectPath = tempSubject({
    text: '[2026-09-21] 临边未设置防护栏杆',
    claims: [claim],
  })
  const { code, out } = await capture(() =>
    main(['check', 'hazard-triage', '--input', subjectPath, '--basis', TRACES_PATH]),
  )
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /refuted/)
})

test('cli: contract error exits 3', async () => {
  const subjectPath = tempSubject({
    text: '[2026-09-21] 临边未设置防护栏杆',
    claims: [c({ check: 'hazard', asserted: 'absent', record_index: 1, hazard_type_id: 'HT-GCZY-001' })],
    nope: 1,
  })
  const { code, err } = await capture(() =>
    main(['check', 'hazard-triage', '--input', subjectPath]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /ContractError/)
})

test('cli: invalid knowledge exits 2', async () => {
  const subjectPath = tempSubject({
    knowledge: { hazard_types: [{}] },
    claims: [c({ check: 'schema', asserted: '1', of: 'hazard-types' })],
  })
  const { code, err } = await capture(() =>
    main(['check', 'hazard-triage', '--input', subjectPath]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /知识库|hazard_types|必须是/)
})

test('cli: missing claims field exits 2', async () => {
  const subjectPath = tempSubject({ text: '[2026-09-21] a' })
  const { code, err } = await capture(() =>
    main(['check', 'hazard-triage', '--input', subjectPath]),
  )
  assert.equal(code, EXIT_INPUT)
  assert.match(err, /claims/)
})

test('cli: bad JSON exits 2', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hazard-triage-test-'))
  const path = join(dir, 'bad.json')
  writeFileSync(path, '{ nope')
  const { code } = await capture(() => main(['check', 'hazard-triage', '--input', path]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: missing input file exits 2', async () => {
  const { code } = await capture(() =>
    main(['check', 'hazard-triage', '--input', join(tmpdir(), 'nope-hazard-triage.json')]),
  )
  assert.equal(code, EXIT_INPUT)
})

test('cli: missing basis node exits 3', async () => {
  const subjectPath = tempSubject({
    claims: [c({
      check: 'schema', asserted: '31', of: 'hazard-types',
      node: { session_id: 's-ht-nope', turn: 1, tool_call_id: 'call-nope' },
    })],
  })
  const { code, err } = await capture(() =>
    main(['check', 'hazard-triage', '--input', subjectPath, '--basis', TRACES_PATH]),
  )
  assert.equal(code, EXIT_CONTRACT)
  assert.match(err, /NodeMissing/)
})

test('cli: without --basis claims still evaluate', async () => {
  const subjectPath = tempSubject({
    claims: [{ claim_id: 'c-basis-free', check: 'schema', asserted: '31', of: 'hazard-types' }],
  })
  const { code, out } = await capture(() =>
    main(['check', 'hazard-triage', '--input', subjectPath]),
  )
  assert.equal(code, EXIT_OK)
  assert.match(out, /\[claim\] c-basis-free/)
})