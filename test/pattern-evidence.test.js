/**
 * pattern-evidence 器官的无损测试。
 *
 * 数据面：随器官打包的 12 条规则（`src/traceproof/verbs/pattern-evidence/data/ruleset.json`，
 * 从源仓 `rules/*.json` 只读导出）。判定层对齐：
 *  - page-model：kind / label / 文本池 / 周边文本 / 证据登记表 / WCAG 对比度 / detect 匹配；
 *  - rules：规则包校验（缺字段 / 枚举 / 未知键 / 优先级 / 哈希占位）；
 *  - engine：证据门禁、中和项、match_priority 归属、duplicate_locator、禁用规则、确定性；
 *  - ordering：severity 降序 → DOM 序、F-01 编号；
 *  - site-policy：黑白名单三态与规则开关；
 *  - 器官契约：6 类 claim、verdict 映射、痕迹节点、确定性、CLI 退出码。
 *
 * 判据 1 的 X = 源仓判定层（D1+D18 机械选 19 个文件）`node --test` 实跑 182 passed；
 * 本文件 `test(` 调用数与实跑用例数均 ≥ 182。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
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
  Report,
} from '../lib/traceproof/core/ledger.js'
import { Basis } from '../lib/traceproof/core/trace-index.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'
import {
  ASSERTED_VALUES,
  CHECKS,
  DEFAULT_RULESET,
  VERSION,
  patternEvidenceVerb,
} from '../lib/traceproof/verbs/pattern-evidence/index.js'
import {
  CONTROL_TAGS,
  EVIDENCE,
  KIND_CONTROL,
  KIND_ELEMENT,
  KIND_TEXT,
  NEAR_TEXT_LIMIT,
  collectEvidence,
  colorsEqual,
  contrastRatio,
  evidenceValue,
  haystack,
  kindOfTag,
  labelFrom,
  limitNearText,
  makeElementNode,
  makeSnippet,
  makeTextNode,
  matchesDetect,
  normalizeWs,
  parseColor,
  parsePageNode,
  parsePageNodes,
  relativeLuminance,
} from '../lib/traceproof/verbs/pattern-evidence/page-model.js'
import {
  RulePackError,
  categoryOrder,
  loadRulePack,
  severityRank,
  validateRulePack,
} from '../lib/traceproof/verbs/pattern-evidence/rules.js'
import {
  REJECT_REASON,
  buildScanResult,
  scanNodes,
} from '../lib/traceproof/verbs/pattern-evidence/engine.js'
import { assignFindingIds, sortFindings } from '../lib/traceproof/verbs/pattern-evidence/ordering.js'
import {
  activeRuleIds,
  hostOf,
  isSiteEnabled,
  normalizeSettings,
} from '../lib/traceproof/verbs/pattern-evidence/site-policy.js'

await loadBuiltin()

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const RULES = DEFAULT_RULESET.rules
const MANIFEST = DEFAULT_RULESET.manifest
const P = (tail) => `html:nth(0)>body:nth(0)>${tail}`
const LOC = {
  prechecked: P('input:nth(0)'),
  hiddenClose: P('button:nth(0)'),
  darkClose: P('button:nth(1)'),
  countdown: P('span:nth(0)'),
  scarcity: P('span:nth(1)'),
  confirmshaming: P('p:nth(0)'),
  anchored: P('span:nth(2)'),
  addon: P('input:nth(1)'),
  exit: P('p:nth(1)'),
  subscription: P('p:nth(2)'),
  fee: P('span:nth(3)'),
  signup: P('p:nth(3)'),
}
const NODE = { session_id: 's-ui-1', turn: 1, tool_call_id: 'call-ui-1' }
const BASIS = Basis.fromObject({
  version: '1',
  nodes: [{ session_id: 's-ui-1', turn: 1, tool_call_id: 'call-ui-1' }],
})

function pack() {
  return loadRulePack(MANIFEST, RULES)
}

function ruleIds() {
  return RULES.map((rule) => rule.rule_id)
}

function text(seq, body, nearText = '', tail = `span:nth(${seq})`) {
  return makeTextNode({ seq, text: body, nearText, path: P(tail) })
}

function control(seq, label, opts = {}) {
  return makeElementNode({
    seq,
    tag: opts.tag ?? 'button',
    label,
    text: opts.text ?? '',
    attrs: opts.attrs ?? {},
    style: opts.style ?? {},
    box: opts.box ?? { widthPx: 24, heightPx: 24 },
    contrast: opts.contrast,
    nearText: opts.nearText ?? '',
    path: opts.path ?? P(opts.tail ?? `button:nth(${seq})`),
  })
}

function checkbox(seq, label, opts = {}) {
  const checked = opts.checked ?? true
  return control(seq, label, {
    ...opts,
    tag: 'input',
    attrs: { type: 'checkbox', ...(checked ? { checked: 'true' } : {}) },
    box: { widthPx: 16, heightPx: 16 },
    tail: opts.tail ?? `input:nth(${seq})`,
  })
}

function closeButton(seq, { size = 24, contrast = 1.5, color = '#8a8a8a', background = '#909090', label = '关闭', tail = null } = {}) {
  return control(seq, label, {
    style: { color, backgroundColor: background, display: 'block', opacity: 1, fontSizePx: 14 },
    box: { widthPx: size, heightPx: size },
    contrast,
    tail: tail ?? `button:nth(${seq})`,
  })
}

function allNodes() {
  return [
    checkbox(1, '自动续订会员', { tail: 'input:nth(0)' }),
    closeButton(2, { size: 6, contrast: 1.2, tail: 'button:nth(0)' }),
    closeButton(3, { size: 24, contrast: 1.5, tail: 'button:nth(1)' }),
    text(4, '倒计时 09:59', '活动专区', 'span:nth(0)'),
    text(5, '仅剩 2 件', '示例商城（虚构）', 'span:nth(1)'),
    text(6, '放弃 5 元优惠', '', 'p:nth(0)'),
    text(7, '原价 199 现价 99', '优惠专区', 'span:nth(2)'),
    checkbox(8, '延保服务包', { tail: 'input:nth(1)' }),
    text(9, '确定要离开吗', '', 'p:nth(1)'),
    text(10, '取消请致电客服热线', '帮助中心', 'p:nth(2)'),
    text(11, '服务费 ¥9.9', '结算页', 'span:nth(3)'),
    text(12, '注册后才能查看完整评价', '', 'p:nth(3)'),
  ]
}

function pageOf(nodes, extra = {}) {
  return {
    url: 'https://example.invalid/checkout',
    scanned_at: '2026-10-18T00:00:00.000Z',
    elapsed_ms: 12,
    truncated: false,
    nodes,
    ...extra,
  }
}

function subjectOf(nodes, claims, extra = {}) {
  return { page: pageOf(nodes), claims, ...extra }
}

function scanOf(nodes, options = {}) {
  return buildScanResult({
    url: options.url ?? 'https://example.invalid/checkout',
    scannedAt: options.scannedAt ?? '2026-10-18T00:00:00.000Z',
    nodes,
    pack: options.pack ?? pack(),
    elapsedMs: options.elapsedMs ?? 12,
    truncated: options.truncated ?? false,
    disabledRuleIds: options.disabledRuleIds ?? [],
  })
}

function run(subject, basis = BASIS) {
  return [...patternEvidenceVerb.evaluate(subject, basis)]
}

function recordOf(records, claimId) {
  return records.find((record) => record.claim_id === claimId)
}

function mutatedPack() {
  return {
    manifest: structuredClone(MANIFEST),
    rules: structuredClone(RULES),
  }
}

async function capture(fn) {
  const logs = []
  const originalLog = console.log
  const originalWrite = process.stderr.write
  console.log = (...args) => logs.push(args.join(' '))
  process.stderr.write = (chunk) => {
    logs.push(String(chunk))
    return true
  }
  try {
    const code = await fn()
    return { code, out: logs.join('\n') }
  } finally {
    console.log = originalLog
    process.stderr.write = originalWrite
  }
}

// ===========================================================================
// 1. 规则包数据 + 校验
// ===========================================================================

test('规则包数据：12 条规则且 rule_id 唯一', () => {
  assert.equal(RULES.length, 12)
  assert.equal(new Set(ruleIds()).size, 12)
})

test('规则包数据：manifest.rule_files 与规则条数一致', () => {
  assert.equal(MANIFEST.rule_files.length, RULES.length)
  for (const [index, rule] of RULES.entries()) {
    assert.ok(MANIFEST.rule_files[index].includes(rule.rule_id.replace(/^dp-/, '')))
  }
})

test('规则包数据：阈值键齐且都是数值', () => {
  for (const key of [
    'precision_min',
    'recall_min',
    'min_cases_per_rule',
    'scan_timeout_ms',
    'first_result_budget_ms',
    'fixture_page_count',
    'stress_node_count',
    'snippet_max_len',
  ]) {
    assert.equal(typeof MANIFEST.thresholds[key], 'number', `缺 ${key}`)
  }
})

test('规则包数据：severity 与 category 都在 manifest 枚举内', () => {
  for (const rule of RULES) {
    assert.ok(MANIFEST.severity_levels.includes(rule.severity), `${rule.rule_id} severity 越界`)
    assert.ok(MANIFEST.categories.includes(rule.category), `${rule.rule_id} category 越界`)
  }
})

test('规则包数据：match_priority 覆盖全部规则且无重复', () => {
  assert.deepEqual([...MANIFEST.match_priority].sort(), [...ruleIds()].sort())
  assert.equal(new Set(MANIFEST.match_priority).size, MANIFEST.match_priority.length)
})

test('规则包数据：evidence_required 都在 evidence_kinds 闭集内', () => {
  for (const rule of RULES) {
    for (const kind of rule.evidence_required) {
      assert.ok(MANIFEST.evidence_kinds.includes(kind), `${rule.rule_id} 未知证据 ${kind}`)
    }
  }
})

test('规则包数据：detect / style 键都在 manifest 闭集内', () => {
  for (const rule of RULES) {
    for (const key of Object.keys(rule.detect)) {
      assert.ok(MANIFEST.detect_keys.includes(key), `${rule.rule_id} detect 未知键 ${key}`)
    }
    for (const key of Object.keys(rule.detect.style ?? {})) {
      assert.ok(MANIFEST.style_keys.includes(key), `${rule.rule_id} style 未知键 ${key}`)
    }
    for (const group of rule.detect.style_any ?? []) {
      for (const key of Object.keys(group)) {
        assert.ok(MANIFEST.style_keys.includes(key), `${rule.rule_id} style_any 未知键 ${key}`)
      }
    }
  }
})

test('规则包数据：ruleset_hash 是 64 位十六进制且不是占位值', () => {
  assert.match(MANIFEST.ruleset_hash, /^[0-9a-f]{64}$/)
  assert.equal(MANIFEST.ruleset_hash.includes('TBD'), false)
})

test('规则包数据：每条规则都有 limits 与非空 explanation', () => {
  for (const rule of RULES) {
    assert.ok(Array.isArray(rule.limits) && rule.limits.length > 0, `${rule.rule_id} 缺 limits`)
    assert.ok(rule.explanation.trim().length > 0, `${rule.rule_id} explanation 为空`)
  }
})

test('规则包校验：正常规则包零错误（阴性对照）', () => {
  assert.deepEqual(validateRulePack(MANIFEST, RULES), [])
})

test('规则包校验：缺 evidence_required 被拒', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /缺字段 evidence_required/)
})

test('规则包校验：缺 limits 被拒', () => {
  const bad = mutatedPack()
  bad.rules[0].limits = []
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /缺 limits/)
})

test('规则包校验：未知 detect 键被拒', () => {
  const bad = mutatedPack()
  bad.rules[0].detect.unknown_key = true
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /未知键 unknown_key/)
})

test('规则包校验：未知 severity 被拒', () => {
  const bad = mutatedPack()
  bad.rules[0].severity = 'critical'
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /severity=critical/)
})

test('规则包校验：未知 category 被拒', () => {
  const bad = mutatedPack()
  bad.rules[0].category = 'unknown'
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /category=unknown/)
})

test('规则包校验：未知证据类型被拒', () => {
  const bad = mutatedPack()
  bad.rules[0].evidence_required = ['checked-state', 'vibes']
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /未知证据类型 vibes/)
})

test('规则包校验：detect.style 未知键被拒', () => {
  const bad = mutatedPack()
  const hidden = bad.rules.find((rule) => rule.rule_id === 'dp-hidden-close')
  hidden.detect.style = { looks_suspicious: true }
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /detect\.style 含未知键/)
})

test('规则包校验：detect.style_any 未知键被拒', () => {
  const bad = mutatedPack()
  const hidden = bad.rules.find((rule) => rule.rule_id === 'dp-hidden-close')
  hidden.detect.style_any.push({ looks_suspicious: true })
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /detect\.style_any 含未知键/)
})

test('规则包校验：rule_id 重复被拒', () => {
  const bad = mutatedPack()
  bad.rules[1].rule_id = bad.rules[0].rule_id
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /rule_id 重复/)
})

test('规则包校验：match_priority 漏项被拒', () => {
  const bad = mutatedPack()
  bad.manifest.match_priority = bad.manifest.match_priority.filter((id) => id !== bad.rules[0].rule_id)
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /match_priority 漏掉了规则/)
})

test('规则包校验：match_priority 含不存在规则被拒', () => {
  const bad = mutatedPack()
  bad.manifest.match_priority.push('dp-no-such-rule')
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /含不存在的规则 dp-no-such-rule/)
})

test('规则包校验：match_priority 重复项被拒', () => {
  const bad = mutatedPack()
  bad.manifest.match_priority.push(bad.rules[0].rule_id)
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /match_priority 有重复项/)
})

test('规则包校验：rule_files 数量不符被拒', () => {
  const bad = mutatedPack()
  bad.manifest.rule_files.pop()
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /≠ 实际规则/)
})

test('规则包校验：ruleset_hash 占位值被拒', () => {
  const bad = mutatedPack()
  bad.manifest.ruleset_hash = 'TBD-COMPUTED'
  assert.match(validateRulePack(bad.manifest, bad.rules).join('\n'), /仍是占位值/)
})

test('规则包校验：manifest 非对象 / specs 非数组被拒', () => {
  assert.deepEqual(validateRulePack(null, []), ['manifest 不是对象'])
  assert.deepEqual(validateRulePack({}, 'x'), ['specs 不是数组'])
})

test('loadRulePack：order 按 match_priority 排列', () => {
  const loaded = pack()
  assert.equal(loaded.order.length, 12)
  assert.deepEqual(loaded.order.map((rule) => rule.rule_id), MANIFEST.match_priority)
})

test('loadRulePack：坏包抛 RulePackError 且列出全部错误', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  bad.rules[1].severity = 'critical'
  assert.throws(
    () => loadRulePack(bad.manifest, bad.rules),
    (error) => error instanceof RulePackError && error.errors.length >= 2,
  )
})

test('severityRank：low < medium < high', () => {
  assert.equal(severityRank(MANIFEST, 'low'), 1)
  assert.equal(severityRank(MANIFEST, 'medium'), 2)
  assert.equal(severityRank(MANIFEST, 'high'), 3)
})

test('severityRank：未知等级抛错', () => {
  assert.throws(() => severityRank(MANIFEST, 'critical'), /未知严重度/)
})

test('categoryOrder：返回 manifest 的分组顺序', () => {
  assert.deepEqual(categoryOrder(MANIFEST), MANIFEST.categories)
})

// ===========================================================================
// 2. 页面模型
// ===========================================================================

test('kindOfTag：五个控件标签都归为 control', () => {
  for (const tag of CONTROL_TAGS) assert.equal(kindOfTag(tag), KIND_CONTROL)
})

test('kindOfTag：普通元素归为 element', () => {
  assert.equal(kindOfTag('div'), KIND_ELEMENT)
})

test('kindOfTag：空标签归为 text', () => {
  assert.equal(kindOfTag(''), KIND_TEXT)
})

test('labelFrom：aria-label 优先', () => {
  assert.equal(
    labelFrom({ tag: 'button', attrs: { 'aria-label': 'A', title: 'B', placeholder: 'C', alt: 'D' }, ownText: 'E' }),
    'A',
  )
})

test('labelFrom：title 次之', () => {
  assert.equal(labelFrom({ tag: 'button', attrs: { title: 'B', placeholder: 'C', alt: 'D' }, ownText: 'E' }), 'B')
})

test('labelFrom：placeholder 第三', () => {
  assert.equal(labelFrom({ tag: 'input', attrs: { placeholder: 'C', alt: 'D' }, ownText: 'E' }), 'C')
})

test('labelFrom：alt 第四', () => {
  assert.equal(labelFrom({ tag: 'input', attrs: { alt: 'D' }, ownText: 'E' }), 'D')
})

test('labelFrom：控件自身文本回退', () => {
  assert.equal(labelFrom({ tag: 'button', attrs: {}, ownText: ' 自身 ' }), '自身')
})

test('labelFrom：控件 value 回退', () => {
  assert.equal(labelFrom({ tag: 'input', attrs: { value: 'V' } }), 'V')
})

test('labelFrom：非控件不取自身文本（D29）', () => {
  assert.equal(labelFrom({ tag: 'div', attrs: {}, ownText: 'DIV 全文' }), '')
})

test('labelFrom：标签截断到 200 字符', () => {
  const long = 'x'.repeat(250)
  assert.equal(labelFrom({ tag: 'button', attrs: { 'aria-label': long } }).length, NEAR_TEXT_LIMIT)
})

test('haystack：文本与标签用空格连接', () => {
  assert.equal(haystack({ text: 'T', label: 'L' }), 'T L')
})

test('haystack：两侧都空时返回空串', () => {
  assert.equal(haystack({ text: '', label: '' }), '')
})

test('normalizeWs：折叠空白并去首尾', () => {
  assert.equal(normalizeWs(' a  b\n c '), 'a b c')
})

test('normalizeWs：非字符串输入安全返回空串', () => {
  assert.equal(normalizeWs(null), '')
})

test('limitNearText：去掉宿主自身文本', () => {
  assert.equal(limitNearText('宿主', '宿主 周边 文本'), '周边 文本')
})

test('limitNearText：截断到 200 字符', () => {
  assert.equal(limitNearText('', 'y'.repeat(300)).length, NEAR_TEXT_LIMIT)
})

test('limitNearText：空周边是合法空串', () => {
  assert.equal(limitNearText('宿主', '宿主'), '')
})

test('makeTextNode：kind / tag / label 默认值', () => {
  const node = makeTextNode({ seq: 1, text: 'T', path: 'p' })
  assert.equal(node.kind, KIND_TEXT)
  assert.equal(node.tag, '#text')
  assert.equal(node.label, '')
  assert.equal(node.nearText, '')
})

test('makeElementNode：kindOfTag 推断且 tag 小写', () => {
  const node = makeElementNode({ seq: 1, tag: 'BUTTON', path: 'p' })
  assert.equal(node.kind, KIND_CONTROL)
  assert.equal(node.tag, 'button')
})

test('makeElementNode：attrs 值字符串化', () => {
  const node = makeElementNode({ seq: 1, tag: 'input', path: 'p', attrs: { checked: true, max: 3 } })
  assert.equal(node.attrs.checked, 'true')
  assert.equal(node.attrs.max, '3')
})

test('parsePageNode：完整节点逐字段读入', () => {
  const node = parsePageNode(
    {
      seq: 2,
      kind: 'control',
      tag: 'BUTTON',
      text: 'T',
      label: 'L',
      attrs: { type: 'button' },
      style: { color: '#111111', backgroundColor: '#ffffff', display: 'block', opacity: 1, fontSizePx: 14 },
      box: { widthPx: 6, heightPx: 8 },
      contrast: 1.5,
      nearText: 'N',
      path: 'p',
    },
    'n',
  )
  assert.equal(node.seq, 2)
  assert.equal(node.kind, KIND_CONTROL)
  assert.equal(node.tag, 'button')
  assert.equal(node.text, 'T')
  assert.equal(node.label, 'L')
  assert.equal(node.attrs.type, 'button')
  assert.equal(node.style.color, '#111111')
  assert.equal(node.box.widthPx, 6)
  assert.equal(node.contrast, 1.5)
  assert.equal(node.nearText, 'N')
  assert.equal(node.path, 'p')
})

test('parsePageNode：缺省字段补默认值', () => {
  const node = parsePageNode({ seq: 1, kind: 'text', path: 'p' }, 'n')
  assert.equal(node.tag, '#text')
  assert.equal(node.text, '')
  assert.equal(node.label, '')
  assert.deepEqual(node.attrs, {})
  assert.deepEqual(node.style, {})
  assert.deepEqual(node.box, {})
  assert.equal(node.nearText, '')
})

test('parsePageNode：kind 非法被拒', () => {
  assert.throws(() => parsePageNode({ seq: 1, kind: 'widget', path: 'p' }, 'n'), /kind 必须是/)
})

test('parsePageNode：seq 非整数被拒', () => {
  assert.throws(() => parsePageNode({ seq: 1.5, kind: 'text', path: 'p' }, 'n'), /seq 必须是/)
})

test('parsePageNode：path 为空被拒', () => {
  assert.throws(() => parsePageNode({ seq: 1, kind: 'text', path: '  ' }, 'n'), /path 不能为空/)
})

test('parsePageNode：未知顶层键被拒', () => {
  assert.throws(() => parsePageNode({ seq: 1, kind: 'text', path: 'p', extra: 1 }, 'n'), /未知键 extra/)
})

test('parsePageNode：style 未知键被拒', () => {
  assert.throws(
    () => parsePageNode({ seq: 1, kind: 'text', path: 'p', style: { looks: 1 } }, 'n'),
    /style 含未知键 looks/,
  )
})

test('parsePageNode：box 未知键被拒', () => {
  assert.throws(
    () => parsePageNode({ seq: 1, kind: 'text', path: 'p', box: { depth: 1 } }, 'n'),
    /box 含未知键 depth/,
  )
})

test('parsePageNode：attrs 值非法被拒', () => {
  assert.throws(
    () => parsePageNode({ seq: 1, kind: 'text', path: 'p', attrs: { x: { y: 1 } } }, 'n'),
    /attrs\.x 必须是/,
  )
})

test('parsePageNode：contrast 非数被拒', () => {
  assert.throws(() => parsePageNode({ seq: 1, kind: 'text', path: 'p', contrast: 'x' }, 'n'), /contrast 必须是/)
})

test('parsePageNodes：非数组被拒', () => {
  assert.throws(() => parsePageNodes('x', 'n'), /必须是数组/)
})

// ===========================================================================
// 3. 证据登记表
// ===========================================================================

const richNode = () =>
  control(1, '关闭', {
    tag: 'button',
    text: '按钮文本',
    attrs: { checked: 'true' },
    style: { color: '#111111', backgroundColor: '#eeeeee', display: 'block', opacity: 0.4, fontSizePx: 10 },
    box: { widthPx: 6, heightPx: 8 },
    contrast: 1.5,
    nearText: '周边',
    path: P('button:nth(0)'),
  })

test('EVIDENCE.text：返回节点文本', () => {
  assert.equal(EVIDENCE.text(richNode()), '按钮文本')
})

test('EVIDENCE.label-text：返回可读标签', () => {
  assert.equal(EVIDENCE['label-text'](richNode()), '关闭')
})

test('EVIDENCE.nearby-text：返回周边文本', () => {
  assert.equal(EVIDENCE['nearby-text'](richNode()), '周边')
})

test('EVIDENCE.checked-state：checked=true 产出 checked', () => {
  assert.equal(EVIDENCE['checked-state'](richNode()), 'checked')
})

test('EVIDENCE.box-size：宽高拼成 WxH', () => {
  assert.equal(EVIDENCE['box-size'](richNode()), '6x8')
})

test('EVIDENCE.contrast-ratio：两位小数', () => {
  assert.equal(EVIDENCE['contrast-ratio'](richNode()), '1.50')
})

test('EVIDENCE.style-color：返回前景色', () => {
  assert.equal(EVIDENCE['style-color'](richNode()), '#111111')
})

test('EVIDENCE.style-background-color：返回背景色', () => {
  assert.equal(EVIDENCE['style-background-color'](richNode()), '#eeeeee')
})

test('EVIDENCE.style-display：返回 display', () => {
  assert.equal(EVIDENCE['style-display'](richNode()), 'block')
})

test('EVIDENCE.style-opacity：返回透明度', () => {
  assert.equal(EVIDENCE['style-opacity'](richNode()), '0.4')
})

test('EVIDENCE.style-font-size：返回字号', () => {
  assert.equal(EVIDENCE['style-font-size'](richNode()), '10')
})

test('EVIDENCE.dom-path：返回定位串', () => {
  assert.equal(EVIDENCE['dom-path'](richNode()), P('button:nth(0)'))
})

test('EVIDENCE.checked-state：缺 checked 键 → undefined', () => {
  assert.equal(EVIDENCE['checked-state'](control(1, '关闭')), undefined)
})

test('EVIDENCE.box-size：缺高度 → undefined', () => {
  assert.equal(EVIDENCE['box-size'](makeElementNode({ seq: 1, tag: 'button', path: 'p', box: { widthPx: 5 } })), undefined)
})

test('EVIDENCE.contrast-ratio：缺 contrast → undefined', () => {
  assert.equal(EVIDENCE['contrast-ratio'](control(1, '关闭')), undefined)
})

test('EVIDENCE.style-color：缺 color → undefined', () => {
  assert.equal(EVIDENCE['style-color'](control(1, '关闭')), undefined)
})

test('evidenceValue：未知 kind 抛错', () => {
  assert.throws(() => evidenceValue(richNode(), 'vibes'), /未知证据类型/)
})

test('collectEvidence：证据齐时保持规则声明顺序', () => {
  const { evidence, missing } = collectEvidence(richNode(), ['label-text', 'checked-state'])
  assert.deepEqual(evidence.map((item) => item.kind), ['label-text', 'checked-state'])
  assert.deepEqual(missing, [])
})

test('collectEvidence：缺一项 → missing 列表精确', () => {
  const bare = control(1, '关闭', { style: {} })
  const { missing } = collectEvidence(bare, ['text', 'style-color'])
  assert.deepEqual(missing, ['style-color'])
})

test('collectEvidence：空串是取到了空值（合法证据）', () => {
  const node = makeTextNode({ seq: 1, text: '', path: 'p' })
  const { evidence, missing } = collectEvidence(node, ['text'])
  assert.deepEqual(missing, [])
  assert.deepEqual(evidence, [{ kind: 'text', value: '' }])
})

test('EVIDENCE.label-text：label 为空回退 text', () => {
  const node = makeElementNode({ seq: 1, tag: 'button', path: 'p', label: '', text: 'TXT' })
  assert.equal(EVIDENCE['label-text'](node), 'TXT')
})

// ===========================================================================
// 4. 颜色 / 对比度
// ===========================================================================

test('parseColor：#fff 展开为三位十六进制', () => {
  assert.deepEqual(parseColor('#fff'), { r: 255, g: 255, b: 255, a: 1 })
})

test('parseColor：#ffffff 六位', () => {
  assert.deepEqual(parseColor('#ffffff'), { r: 255, g: 255, b: 255, a: 1 })
})

test('parseColor：#ffffff80 八位带 alpha', () => {
  assert.equal(parseColor('#ffffff80').a, 128 / 255)
})

test('parseColor：rgb() 三通道', () => {
  assert.deepEqual(parseColor('rgb(10, 20, 30)'), { r: 10, g: 20, b: 30, a: 1 })
})

test('parseColor：rgba() 四通道', () => {
  assert.deepEqual(parseColor('rgba(10,20,30,0.5)'), { r: 10, g: 20, b: 30, a: 0.5 })
})

test('parseColor：命名色 white', () => {
  assert.deepEqual(parseColor('white'), { r: 255, g: 255, b: 255, a: 1 })
})

test('parseColor：transparent 透明黑', () => {
  assert.deepEqual(parseColor('transparent'), { r: 0, g: 0, b: 0, a: 0 })
})

test('parseColor：非法写法返回 null', () => {
  assert.equal(parseColor('#12'), null)
})

test('parseColor：非字符串返回 null', () => {
  assert.equal(parseColor(42), null)
})

test('colorsEqual：#fff 与 rgb(255,255,255) 同色', () => {
  assert.equal(colorsEqual('#fff', 'rgb(255,255,255)'), true)
})

test('colorsEqual：#000 与 #fff 不同色', () => {
  assert.equal(colorsEqual('#000', '#fff'), false)
})

test('colorsEqual：认不出的写法按字符串（忽略大小写/空白）', () => {
  assert.equal(colorsEqual('  CurrentColor ', 'currentcolor'), true)
})

test('relativeLuminance：white 为 1', () => {
  assert.equal(relativeLuminance('white'), 1)
})

test('relativeLuminance：black 为 0', () => {
  assert.equal(relativeLuminance('black'), 0)
})

test('contrastRatio：黑白为 21', () => {
  assert.equal(contrastRatio('#000000', '#ffffff'), 21)
})

test('contrastRatio：任一颜色认不出 → null', () => {
  assert.equal(contrastRatio('#000000', 'nope'), null)
})

// ===========================================================================
// 5. detect 匹配
// ===========================================================================

test('matchesDetect：text 节点不命中 element 规则', () => {
  assert.equal(matchesDetect(text(1, 'T'), { node_kinds: ['element'] }).matched, false)
})

test('matchesDetect：control 节点可命中 element 规则', () => {
  assert.equal(matchesDetect(control(1, 'L'), { node_kinds: ['element'] }).matched, true)
})

test('matchesDetect：node_kinds 缺省时任意 kind', () => {
  assert.equal(matchesDetect(text(1, 'T'), {}).matched, true)
})

test('matchesDetect：attrs 全等命中', () => {
  assert.equal(matchesDetect(checkbox(1, 'L'), { attrs: { type: 'checkbox', checked: 'true' } }).matched, true)
})

test('matchesDetect：attrs 值不等不命中', () => {
  assert.equal(matchesDetect(checkbox(1, 'L'), { attrs: { type: 'radio' } }).matched, false)
})

test('matchesDetect：attrs 缺属性不命中', () => {
  assert.equal(matchesDetect(checkbox(1, 'L', { checked: false }), { attrs: { checked: 'true' } }).matched, false)
})

test('matchesDetect：text_any 任一正则命中', () => {
  assert.equal(matchesDetect(text(1, '仅剩 2 件'), { text_any: ['不存在', '仅剩\\s*\\d+'] }).matched, true)
})

test('matchesDetect：text_any 全不命中', () => {
  assert.equal(matchesDetect(text(1, '仅剩 2 件'), { text_any: ['库存充足'] }).matched, false)
})

test('matchesDetect：text_all 全部正则命中', () => {
  assert.equal(matchesDetect(text(1, '原价 199 现价 99'), { text_all: ['原价', '现价'] }).matched, true)
})

test('matchesDetect：text_all 缺一个不命中', () => {
  assert.equal(matchesDetect(text(1, '原价 199'), { text_all: ['原价', '现价'] }).matched, false)
})

test('matchesDetect：near_text_any 读周边文本', () => {
  assert.equal(matchesDetect(control(1, '关闭', { nearText: '活动专区' }), { near_text_any: ['活动'] }).matched, true)
})

test('matchesDetect：near_text_any 也不命中时返回 false', () => {
  assert.equal(matchesDetect(control(1, '关闭', { nearText: '帮助中心' }), { near_text_any: ['活动'] }).matched, false)
})

test('matchesDetect：nearby_absent_any 命中 → suppressed', () => {
  const verdict = matchesDetect(text(1, '仅剩 2 件', '库存来源：后台'), { nearby_absent_any: ['库存来源'] })
  assert.equal(verdict.matched, false)
  assert.equal(verdict.suppressed_by, 'nearby_absent_any')
})

test('matchesDetect：nearby_absent_any 未命中 → 继续判定', () => {
  assert.equal(matchesDetect(text(1, '仅剩 2 件', '示例商城'), { nearby_absent_any: ['库存来源'] }).matched, true)
})

test('matchesDetect：style.max_size_px 小于等于阈值命中', () => {
  assert.equal(matchesDetect(control(1, 'L', { box: { widthPx: 6, heightPx: 6 } }), { style: { max_size_px: 8 } }).matched, true)
})

test('matchesDetect：style.max_size_px 超过阈值不命中', () => {
  assert.equal(matchesDetect(control(1, 'L', { box: { widthPx: 10, heightPx: 10 } }), { style: { max_size_px: 8 } }).matched, false)
})

test('matchesDetect：style.color_equals_background 等价色命中', () => {
  const node = control(1, 'L', { style: { color: '#fff', backgroundColor: '#ffffff' } })
  assert.equal(matchesDetect(node, { style: { color_equals_background: true } }).matched, true)
})

test('matchesDetect：style.opacity_max 低透明度命中', () => {
  const node = control(1, 'L', { style: { opacity: 0.4 } })
  assert.equal(matchesDetect(node, { style: { opacity_max: 0.5 } }).matched, true)
})

test('matchesDetect：style.contrast_below 低对比命中', () => {
  assert.equal(matchesDetect(control(1, 'L', { contrast: 1.5 }), { style: { contrast_below: 2 } }).matched, true)
})

test('matchesDetect：style.min_font_size_px 低于阈值不命中（源仓语义要求 ≥ 阈值）', () => {
  const node = control(1, 'L', { style: { fontSizePx: 10 } })
  assert.equal(matchesDetect(node, { style: { min_font_size_px: 12 } }).matched, false)
})

test('matchesDetect：style.min_font_size_px 达到阈值命中', () => {
  const node = control(1, 'L', { style: { fontSizePx: 12 } })
  assert.equal(matchesDetect(node, { style: { min_font_size_px: 12 } }).matched, true)
})

test('matchesDetect：style 条件缺字段不命中', () => {
  assert.equal(matchesDetect(control(1, 'L', { box: {} }), { style: { max_size_px: 8 } }).matched, false)
})

test('matchesDetect：style_any 任一组成立', () => {
  const node = control(1, 'L', { contrast: 1.5, style: { opacity: 1 } })
  assert.equal(matchesDetect(node, { style_any: [{ contrast_below: 2 }, { opacity_max: 0.3 }] }).matched, true)
})

test('matchesDetect：style_any 全不成立', () => {
  const node = control(1, 'L', { contrast: 3, style: { opacity: 0.9 } })
  assert.equal(matchesDetect(node, { style_any: [{ contrast_below: 2 }, { opacity_max: 0.3 }] }).matched, false)
})

test('matchesDetect：neutralizers 命中 → suppressed_by 带正则源', () => {
  const verdict = matchesDetect(checkbox(1, '订阅会员（取消订阅）'), { neutralizers: ['取消订阅'] })
  assert.equal(verdict.matched, false)
  assert.match(verdict.suppressed_by, /^neutralizer:取消订阅/)
})

test('matchesDetect：neutralizers 未命中 → 正常命中', () => {
  assert.equal(matchesDetect(checkbox(1, '订阅会员'), { neutralizers: ['取消订阅'] }).matched, true)
})

test('matchesDetect：detect 非对象按空规格处理', () => {
  assert.equal(matchesDetect(text(1, 'T'), 'not-an-object').matched, true)
})

test('matchesDetect：非法正则抛错', () => {
  assert.throws(() => matchesDetect(text(1, 'T'), { text_any: ['['] }), /无法编译/)
})

test('matchesDetect：text_any 非数组抛错', () => {
  assert.throws(() => matchesDetect(text(1, 'T'), { text_any: 42 }), /必须是正则字符串数组/)
})

// ===========================================================================
// 6. snippet
// ===========================================================================

test('makeSnippet：短文本原样返回且不标截断', () => {
  const result = makeSnippet(text(1, '仅剩 2 件'), 160)
  assert.equal(result.snippet, '仅剩 2 件')
  assert.equal(result.snippet_truncated, false)
})

test('makeSnippet：长文本截断为原串前缀并标记', () => {
  const body = '限时 09:59 '.repeat(60)
  const result = makeSnippet(text(1, body), 160)
  assert.equal(result.snippet.length, 160)
  assert.equal(body.startsWith(result.snippet), true)
  assert.equal(result.snippet_truncated, true)
})

test('makeSnippet：恰好等于上限不标截断', () => {
  const body = 'x'.repeat(160)
  assert.equal(makeSnippet(text(1, body), 160).snippet_truncated, false)
})

test('makeSnippet：超一个字符即标截断', () => {
  const body = 'x'.repeat(161)
  const result = makeSnippet(text(1, body), 160)
  assert.equal(result.snippet_truncated, true)
  assert.equal(result.snippet.length, 160)
})

test('makeSnippet：控件取 label', () => {
  assert.equal(makeSnippet(control(1, '关闭'), 160).snippet, '关闭')
})

test('makeSnippet：文本节点 text 优先', () => {
  assert.equal(makeSnippet(makeTextNode({ seq: 1, text: 'T', label: 'L', path: 'p' }), 160).snippet, 'T')
})

// ===========================================================================
// 7. engine
// ===========================================================================

test('engine：命中 + 证据齐 → 产出 finding，证据逐项可核', () => {
  const { findings } = scanNodes([closeButton(1)], pack())
  assert.equal(findings.length, 1)
  assert.equal(findings[0].rule_id, 'dp-dark-close')
  assert.deepEqual(findings[0].evidence.map((item) => item.kind).sort(), [
    'contrast-ratio',
    'label-text',
    'style-background-color',
    'style-color',
  ])
})

test('engine：命中但缺一项证据 → 零产出 + rejected 记缺失项', () => {
  const node = closeButton(1, { size: 24 })
  delete node.style.color
  const { findings, rejected } = scanNodes([node], pack())
  assert.deepEqual(findings, [])
  const gate = rejected.find((item) => item.rule_id === 'dp-dark-close')
  assert.equal(gate.reason, REJECT_REASON.missingEvidence)
  assert.deepEqual(gate.missing_evidence, ['style-color'])
})

test('engine：缺多项证据 → missing_evidence 按规则顺序列出', () => {
  const node = closeButton(1, { size: 24 })
  delete node.style.color
  const { rejected } = scanNodes([node], pack())
  assert.deepEqual(rejected[0].missing_evidence, ['style-color'])
})

test('engine：中和项命中 → 不产出且记 suppressed', () => {
  const node = checkbox(1, '同意并订阅会员服务（取消订阅）')
  const { findings, rejected } = scanNodes([node], pack())
  assert.deepEqual(findings, [])
  assert.ok(rejected.some((item) => item.reason === REJECT_REASON.suppressed && item.rule_id === 'dp-prechecked-optin'))
})

test('engine：同一节点多规则命中 → 按 match_priority 归属 hidden-close', () => {
  const node = closeButton(1, { size: 6, contrast: 1.2, color: '#8b8b8b', background: '#8b8b8b' })
  const { findings } = scanNodes([node], pack())
  assert.equal(findings.length, 1)
  assert.equal(findings[0].rule_id, 'dp-hidden-close')
})

test('engine：一个节点只出一条 finding', () => {
  const { findings } = scanNodes([closeButton(1, { size: 6, contrast: 1.2 })], pack())
  assert.equal(findings.length, 1)
})

test('engine：禁用规则不参与扫描', () => {
  const node = closeButton(1, { size: 6, contrast: 1.2 })
  const { findings } = scanNodes([node], pack(), {
    disabledRuleIds: ['dp-hidden-close', 'dp-dark-close'],
  })
  assert.deepEqual(findings, [])
})

test('engine：重复 locator → 第二条候选记 duplicate_locator', () => {
  const nodes = [text(1, '仅剩 2 件', '示例商城', 'span:nth(0)'), text(2, '仅剩 3 件', '示例商城', 'span:nth(0)')]
  const { findings, rejected } = scanNodes(nodes, pack())
  assert.equal(findings.length, 1)
  assert.ok(rejected.some((item) => item.reason === REJECT_REASON.duplicateLocator))
})

test('engine：节点数组乱序不影响结果', () => {
  const nodes = allNodes()
  const shuffled = [nodes[5], nodes[0], nodes[11], nodes[2], nodes[9], nodes[4], nodes[7], nodes[1], nodes[10], nodes[3], nodes[8], nodes[6]]
  assert.equal(JSON.stringify(scanOf(shuffled)), JSON.stringify(scanOf(nodes)))
})

test('engine：nodeCount 是节点总数', () => {
  assert.equal(scanOf(allNodes()).node_count, 12)
})

test('engine：buildScanResult 字段顺序固定', () => {
  assert.deepEqual(Object.keys(scanOf(allNodes())), [
    'url',
    'scanned_at',
    'node_count',
    'elapsed_ms',
    'truncated',
    'ruleset_version',
    'ruleset_hash',
    'disabled_rule_ids',
    'findings',
    'rejected',
  ])
})

test('engine：disabled_rule_ids 排序后写入结果', () => {
  const scan = scanOf(allNodes(), { disabledRuleIds: ['dp-hidden-close', 'dp-dark-close'] })
  assert.deepEqual(scan.disabled_rule_ids, ['dp-dark-close', 'dp-hidden-close'])
})

test('engine：findings 编号从 F-01 连续', () => {
  const scan = scanOf(allNodes())
  assert.deepEqual(
    scan.findings.map((finding) => finding.finding_id),
    scan.findings.map((_, index) => `F-${String(index + 1).padStart(2, '0')}`),
  )
})

test('engine：空页面 → 0 findings / 0 rejected', () => {
  const scan = scanOf([])
  assert.deepEqual(scan.findings, [])
  assert.deepEqual(scan.rejected, [])
})

// ===========================================================================
// 8. ordering
// ===========================================================================

test('ordering：severity 降序', () => {
  const scan = scanOf(allNodes())
  const ranks = scan.findings.map((finding) => severityRank(MANIFEST, finding.severity))
  assert.deepEqual(ranks, [...ranks].sort((left, right) => right - left))
})

test('ordering：同级按 DOM 文档序', () => {
  const scan = scanOf(allNodes())
  for (const severity of MANIFEST.severity_levels) {
    const dom = scan.findings.filter((finding) => finding.severity === severity).map((finding) => finding.dom_order)
    assert.deepEqual(dom, [...dom].sort((left, right) => left - right), `${severity} 组未按 DOM 序`)
  }
})

test('ordering：全部规则页的 finding_id 顺序固定', () => {
  const scan = scanOf(allNodes())
  assert.deepEqual(scan.findings.map((finding) => finding.finding_id), [
    'F-01',
    'F-02',
    'F-03',
    'F-04',
    'F-05',
    'F-06',
    'F-07',
    'F-08',
    'F-09',
    'F-10',
    'F-11',
    'F-12',
  ])
})

test('ordering：编号宽度至少两位', () => {
  const numbered = assignFindingIds([])
  assert.deepEqual(numbered, [])
  const one = assignFindingIds([{ rule_id: 'x', rule_name: 'x', category: 'x', severity: 'low', snippet: '', snippet_truncated: false, locator: 'p', evidence: [], explanation: 'x', dom_order: 1 }])
  assert.equal(one[0].finding_id, 'F-01')
})

test('ordering：编号宽度随总数增长（100 条 → F-001）', () => {
  const findings = Array.from({ length: 100 }, (_, index) => ({
    rule_id: 'x',
    rule_name: 'x',
    category: 'x',
    severity: 'low',
    snippet: '',
    snippet_truncated: false,
    locator: `p:${index}`,
    evidence: [],
    explanation: 'x',
    dom_order: index + 1,
  }))
  assert.equal(assignFindingIds(findings)[0].finding_id, 'F-001')
})

test('ordering：sortFindings 不改入参', () => {
  const input = scanOf(allNodes()).findings
  const before = JSON.stringify(input)
  sortFindings(input, MANIFEST)
  assert.equal(JSON.stringify(input), before)
})

test('ordering：未知 severity 抛错', () => {
  const base = { rule_id: 'x', rule_name: 'x', category: 'x', snippet: '', snippet_truncated: false, locator: 'p', evidence: [], explanation: 'x', dom_order: 1 }
  assert.throws(
    () => sortFindings([{ ...base, severity: 'low' }, { ...base, severity: 'critical' }], MANIFEST),
    /未知严重度/,
  )
})

// ===========================================================================
// 9. site-policy
// ===========================================================================

test('site：normalizeSettings 缺省值', () => {
  assert.deepEqual(normalizeSettings(undefined), { site_policy: { mode: 'blocklist', hosts: [] }, disabled_rule_ids: [] })
})

test('site：hosts 去重 / 小写 / 排序', () => {
  const settings = normalizeSettings({ site_policy: { mode: 'blocklist', hosts: [' B.example ', 'a.example', 'A.EXAMPLE', ''] } })
  assert.deepEqual(settings.site_policy.hosts, ['a.example', 'b.example'])
})

test('site：非法 mode 回退 blocklist', () => {
  assert.equal(normalizeSettings({ site_policy: { mode: 'nope', hosts: [] } }).site_policy.mode, 'blocklist')
})

test('site：disabled_rule_ids 去重排序', () => {
  assert.deepEqual(normalizeSettings({ disabled_rule_ids: ['b', 'a', 'b'] }).disabled_rule_ids, ['a', 'b'])
})

test('site：非对象设置回退默认值', () => {
  assert.deepEqual(normalizeSettings(42).site_policy.mode, 'blocklist')
})

test('site：hostOf 小写 host', () => {
  assert.equal(hostOf('https://Example.INVALID/x'), 'example.invalid')
})

test('site：hostOf 非法 URL 返回空串', () => {
  assert.equal(hostOf('not a url'), '')
})

test('site：黑名单命中 → disabled / blocklisted', () => {
  const settings = { site_policy: { mode: 'blocklist', hosts: ['example.invalid'] }, disabled_rule_ids: [] }
  assert.deepEqual(isSiteEnabled('https://example.invalid/p', settings), { enabled: false, reason: 'blocklisted' })
})

test('site：黑名单未命中 → enabled', () => {
  const settings = { site_policy: { mode: 'blocklist', hosts: ['other.invalid'] }, disabled_rule_ids: [] }
  assert.deepEqual(isSiteEnabled('https://example.invalid/p', settings), { enabled: true, reason: 'enabled' })
})

test('site：白名单命中 → enabled', () => {
  const settings = { site_policy: { mode: 'allowlist', hosts: ['example.invalid'] }, disabled_rule_ids: [] }
  assert.deepEqual(isSiteEnabled('https://example.invalid/p', settings), { enabled: true, reason: 'enabled' })
})

test('site：白名单未命中 → disabled / not_allowlisted', () => {
  const settings = { site_policy: { mode: 'allowlist', hosts: ['other.invalid'] }, disabled_rule_ids: [] }
  assert.deepEqual(isSiteEnabled('https://example.invalid/p', settings), { enabled: false, reason: 'not_allowlisted' })
})

test('site：URL 不可解析 → disabled / url_unparsable', () => {
  assert.deepEqual(isSiteEnabled('not a url', {}), { enabled: false, reason: 'url_unparsable' })
})

test('site：activeRuleIds 过滤禁用规则', () => {
  assert.deepEqual(activeRuleIds(['a', 'b', 'c'], { disabled_rule_ids: ['b'] }), ['a', 'c'])
})

test('site：activeRuleIds 保留未知 id', () => {
  assert.deepEqual(activeRuleIds(['a', 'unknown'], { disabled_rule_ids: ['b'] }), ['a', 'unknown'])
})

// ===========================================================================
// 10. 器官 claim
// ===========================================================================

const allScan = () => scanOf(allNodes())

test('claim rule：reported 命中 → claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：reported + snippet 一致 → claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet: '自动续订会员', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：snippet 不符 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet: '订阅', node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /snippet 不符/)
})

test('claim rule：snippet 不符且无节点 → inconclusive', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet: '订阅' }]))
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /没有挂痕迹节点/)
})

test('claim rule：evidence kind 列表一致 → claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, evidence: ['label-text', 'checked-state'], node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：evidence kind 列表不符 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, evidence: ['text'], node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /证据 kind 不符/)
})

test('claim rule：finding_id 一致 → claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, finding_id: 'F-01', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：finding_id 不符 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, finding_id: 'F-99', node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /finding_id 不符/)
})

test('claim rule：snippet_truncated 一致 → claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet_truncated: false, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：snippet_truncated 不符 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet_truncated: true, node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim rule：absent 正确（无 finding / 无 rejected）→ claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'absent', rule_id: 'dp-forced-signup', locator: P('p:nth(99)'), node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：absent 主张但实际 reported → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'absent', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim rule：suppressed 正确 → claim', () => {
  const nodes = [checkbox(1, '同意并订阅会员服务（取消订阅）', { tail: 'input:nth(0)' })]
  const records = run(subjectOf(nodes, [{ claim_id: 'c1', check: 'rule', asserted: 'suppressed', rule_id: 'dp-prechecked-optin', locator: P('input:nth(0)'), node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：suppressed 主张但实际 absent → refuted', () => {
  const nodes = [checkbox(1, '普通会员', { tail: 'input:nth(0)' })]
  const records = run(subjectOf(nodes, [{ claim_id: 'c1', check: 'rule', asserted: 'suppressed', rule_id: 'dp-prechecked-optin', locator: P('input:nth(0)'), node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim rule：missing-evidence 正确且列出缺失项 → claim', () => {
  const node = closeButton(1, { size: 24, tail: 'button:nth(0)' })
  delete node.style.color
  const records = run(subjectOf([node], [{ claim_id: 'c1', check: 'rule', asserted: 'missing-evidence', rule_id: 'dp-dark-close', locator: P('button:nth(0)'), missing_evidence: ['style-color'], node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim rule：missing_evidence 列表不符 → refuted', () => {
  const node = closeButton(1, { size: 24, tail: 'button:nth(0)' })
  delete node.style.color
  const records = run(subjectOf([node], [{ claim_id: 'c1', check: 'rule', asserted: 'missing-evidence', rule_id: 'dp-dark-close', locator: P('button:nth(0)'), missing_evidence: ['contrast-ratio'], node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /missing_evidence 不符/)
})

test('claim rule：节点不完整 → makeRecord 降级 inconclusive', () => {
  const basis = Basis.fromObject({ version: '1', nodes: [{ session_id: 's-ui-1', turn: null, tool_call_id: 'call-ui-1' }] })
  const records = run(
    subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet: '不符', node: { session_id: 's-ui-1', turn: null, tool_call_id: 'call-ui-1' } }]),
    basis,
  )
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /痕迹节点不完整/)
})

test('claim rule：未知字段 → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, foo: 1 }])),
    /字段 foo 不适用于/,
  )
})

test('claim rule：缺 rule_id → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'absent', locator: LOC.prechecked }])),
    /必须带 rule_id/,
  )
})

test('claim rule：缺 locator → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'absent', rule_id: 'dp-prechecked-optin' }])),
    /必须带 locator/,
  )
})

test('claim rule：snippet 用于非 reported → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'absent', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, snippet: 'x' }])),
    /只在 asserted=reported/,
  )
})

test('claim rule：missing_evidence 用于非 missing-evidence → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, missing_evidence: ['x'] }])),
    /只在 asserted=missing-evidence/,
  )
})

test('claim rule：rejected/absent 之外的主张值被拒（duplicate-locator 不单列）', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'duplicate-locator', rule_id: 'dp-fake-scarcity', locator: LOC.scarcity }])),
    /asserted 非法/,
  )
})

test('claim count：findings 数量正确 → claim', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '12', of: 'findings', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim count：findings 数量错误 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '11', of: 'findings', node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim count：rejected 数量正确 → claim', () => {
  const node = closeButton(1, { size: 24, tail: 'button:nth(0)' })
  delete node.style.color
  const records = run(subjectOf([node], [{ claim_id: 'c1', check: 'count', asserted: '1', of: 'rejected', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim count：rejected(reason) 过滤', () => {
  const nodes = [text(1, '仅剩 2 件', '示例商城', 'span:nth(0)'), text(2, '仅剩 3 件', '示例商城', 'span:nth(0)')]
  const records = run(subjectOf(nodes, [{ claim_id: 'c1', check: 'count', asserted: '1', of: 'rejected', reason: 'duplicate_locator', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim count：of 非法 → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '1', of: 'nope' }])),
    /of 必须是 findings 或 rejected/,
  )
})

test('claim count：reason 用于 findings → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '1', of: 'findings', reason: 'missing_evidence' }])),
    /reason 只适用于 of=rejected/,
  )
})

test('claim count：asserted 不是数字 → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: 'many', of: 'findings' }])),
    /必须是十进制数字/,
  )
})

test('claim order：exact rule_ids 正确 → claim', () => {
  const rules = allScan().findings.map((finding) => finding.rule_id)
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'exact', rule_ids: rules, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim order：exact + finding_ids 正确 → claim', () => {
  const scan = allScan()
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'exact', rule_ids: scan.findings.map((finding) => finding.rule_id), finding_ids: scan.findings.map((finding) => finding.finding_id), node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim order：exact 顺序错误 → refuted', () => {
  const rules = [...allScan().findings.map((finding) => finding.rule_id)].reverse()
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'exact', rule_ids: rules, node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim order：prefix 正确 → claim', () => {
  const rules = allScan().findings.slice(0, 3).map((finding) => finding.rule_id)
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'prefix', rule_ids: rules, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim order：prefix 错误 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'prefix', rule_ids: ['dp-forced-signup'], node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim order：缺 rule_ids → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'exact' }])),
    /必须带 rule_ids/,
  )
})

test('claim order：finding_ids 可选，缺省时只比 rule_ids', () => {
  const rules = allScan().findings.map((finding) => finding.rule_id)
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'order', asserted: 'exact', rule_ids: rules, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim ruleset：默认包 valid → claim', () => {
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'valid', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim ruleset：变异包 invalid + error_terms → claim', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'invalid', error_terms: ['evidence_required'], node: NODE }], { ruleset: bad }))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim ruleset：主张 invalid 但包有效 → refuted', () => {
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'invalid', node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim ruleset：主张 valid 但包无效 → refuted', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'valid', node: NODE }], { ruleset: bad }))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim ruleset：error_terms 缺项 → refuted', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'invalid', error_terms: ['不存在的错误'], node: NODE }], { ruleset: bad }))
  assert.equal(records[0].verdict, REFUTED)
  assert.match(records[0].message, /缺少主张点名的错误项/)
})

test('claim ruleset：error_terms 用于 valid → ContractError', () => {
  assert.throws(
    () => run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'valid', error_terms: ['x'] }])),
    /只在 asserted=invalid/,
  )
})

test('claim site：默认设置下 enabled → claim', () => {
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'site', asserted: 'enabled', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim site：黑名单 disabled → claim', () => {
  const settings = { site_policy: { mode: 'blocklist', hosts: ['example.invalid'] }, disabled_rule_ids: [] }
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'site', asserted: 'disabled', reason: 'blocklisted', node: NODE }], { settings }))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim site：reason 不符 → refuted', () => {
  const settings = { site_policy: { mode: 'blocklist', hosts: ['example.invalid'] }, disabled_rule_ids: [] }
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'site', asserted: 'disabled', reason: 'not_allowlisted', node: NODE }], { settings }))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim site：URL 不可解析 → disabled / url_unparsable', () => {
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'site', asserted: 'disabled', url: 'not a url', reason: 'url_unparsable', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim site：claim 自带 url/settings 覆盖 page', () => {
  const settings = { site_policy: { mode: 'allowlist', hosts: ['allowed.invalid'] }, disabled_rule_ids: [] }
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'site', asserted: 'enabled', url: 'https://allowed.invalid/x', settings, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim coverage：complete 正确', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'complete', node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim coverage：truncated 正确', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'truncated', node: NODE }], { page: pageOf(allNodes(), { truncated: true }) }))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim coverage：node_count 一致', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'complete', node_count: 12, node: NODE }]))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim coverage：node_count 不符 → refuted', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'complete', node_count: 11, node: NODE }]))
  assert.equal(records[0].verdict, REFUTED)
})

test('claim coverage：未知字段 → ContractError', () => {
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'complete', truncated: true }])),
    /字段 truncated 不适用于/,
  )
})

test('claim 输入：claims 为空 → ContractError', () => {
  assert.throws(() => run(subjectOf(allNodes(), [])), /claims 必须是非空数组/)
})

test('claim 输入：claim_id 重复 → ContractError', () => {
  assert.throws(
    () => run(
      subjectOf(allNodes(), [
        { claim_id: 'c1', check: 'coverage', asserted: 'complete' },
        { claim_id: 'c1', check: 'coverage', asserted: 'complete' },
      ]),
    ),
    /claim_id 重复/,
  )
})

test('claim 输入：subject 未知字段 → ContractError', () => {
  assert.throws(() => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'complete' }], { extra: 1 })), /输入含未知字段/)
})

test('claim 输入：page 未知字段 → ContractError', () => {
  assert.throws(
    () => run({ page: { ...pageOf(allNodes()), extra: 1 }, claims: [{ claim_id: 'c1', check: 'coverage', asserted: 'complete' }] }),
    /page 含未知字段/,
  )
})

test('claim 输入：自定义规则包覆盖默认（只留倒计时规则）', () => {
  const rule = RULES.find((item) => item.rule_id === 'dp-countdown-pressure')
  const custom = {
    manifest: { ...MANIFEST, rule_files: ['dp-03-countdown-pressure.json'], match_priority: ['dp-countdown-pressure'] },
    rules: [rule],
  }
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '1', of: 'findings', node: NODE }], { ruleset: custom }))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim 输入：disabled_rule_ids 生效（12 → 10）', () => {
  const settings = { site_policy: { mode: 'blocklist', hosts: [] }, disabled_rule_ids: ['dp-countdown-pressure', 'dp-dark-close'] }
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '10', of: 'findings', node: NODE }], { settings }))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim 输入：非法规则包用于 rule 主张 → RulePackError', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  assert.throws(
    () => run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'rule', asserted: 'reported', rule_id: 'dp-prechecked-optin', locator: LOC.prechecked, node: NODE }], { ruleset: bad })),
    (error) => error instanceof RulePackError,
  )
})

test('claim 输入：非法规则包用于 ruleset 主张不抛（可判 invalid）', () => {
  const bad = mutatedPack()
  delete bad.rules[0].evidence_required
  const records = run(subjectOf([], [{ claim_id: 'c1', check: 'ruleset', asserted: 'invalid', node: NODE }], { ruleset: bad }))
  assert.equal(records[0].verdict, CLAIM)
})

test('claim 确定性：同一输入两次 evaluate 输出相同', () => {
  const subject = subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '12', of: 'findings', node: NODE }])
  const first = run(subject).map((record) => JSON.stringify(record))
  const second = run(subject).map((record) => JSON.stringify(record))
  assert.deepEqual(first, second)
})

test('claim 确定性：Report 按 claim_id 排序', () => {
  const subject = subjectOf(allNodes(), [
    { claim_id: 'c-z', check: 'coverage', asserted: 'complete', node: NODE },
    { claim_id: 'c-a', check: 'site', asserted: 'enabled', node: NODE },
  ])
  const report = new Report({
    product: 'traceproof',
    verb: 'pattern-evidence',
    verb_version: VERSION,
    subject: 'test.json',
    records: run(subject),
  })
  assert.deepEqual(report.records.map((record) => record.claim_id), ['c-a', 'c-z'])
})

test('claim 契约：refuted 必有节点（无节点只判 inconclusive）', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'count', asserted: '1', of: 'findings' }]))
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.equal(records[0].node, null)
})

test('claim 契约：每条记录 id 形如 claim@session#turn#call', () => {
  const records = run(subjectOf(allNodes(), [{ claim_id: 'c1', check: 'coverage', asserted: 'complete', node: NODE }]))
  assert.match(records[0].id, /^c1@s-ui-1#1#call-ui-1$/)
})

// ===========================================================================
// 11. 接线 / CLI / 打包数据
// ===========================================================================

test('registry：BUILTIN_MODULES 含 5 个器官且字典序', () => {
  assert.deepEqual([...BUILTIN_MODULES], [
    'agent-conflict',
    'email-evidence',
    'pattern-evidence',
    'pipeline-run',
    'session-replay',
  ])
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
})

test('registry：pattern-evidence 已注册且版本沿用源仓 0.2.0', () => {
  assert.equal(patternEvidenceVerb.slug, 'pattern-evidence')
  assert.equal(patternEvidenceVerb.version, '0.2.0')
  assert.equal(VERSION, '0.2.0')
})

test('registry：input_fields 是 page / claims', () => {
  assert.deepEqual([...patternEvidenceVerb.input_fields], ['page', 'claims'])
})

test('registry：CHECKS 是 6 类闭集', () => {
  assert.deepEqual([...CHECKS], ['rule', 'count', 'order', 'ruleset', 'site', 'coverage'])
})

test('registry：ASSERTED_VALUES 不含 duplicate-locator（只经 count 观察）', () => {
  assert.deepEqual([...ASSERTED_VALUES.rule], ['reported', 'absent', 'suppressed', 'missing-evidence'])
})

test('data：随器官打包的 ruleset.json 可解析且 12 条规则', () => {
  const path = join(ROOT, 'lib', 'traceproof', 'verbs', 'pattern-evidence', 'data', 'ruleset.json')
  const payload = JSON.parse(readFileSync(path, 'utf8'))
  assert.equal(payload.manifest.ruleset_version, '0.1.0')
  assert.equal(payload.rules.length, 12)
})

test('cli：list 显示 pattern-evidence 0.2.0', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /pattern-evidence\s+0\.2\.0/)
})

test('cli：样例 subject 退出 0 且 7 条 claim', async () => {
  const subject = join(ROOT, 'samples', 'pattern-evidence.json')
  const basis = join(ROOT, 'samples', 'pattern-evidence-traces.json')
  const { code, out } = await capture(() => main(['check', 'pattern-evidence', '--input', subject, '--basis', basis]))
  assert.equal(code, EXIT_OK)
  assert.match(out, /合计 7 条，阻断 0 条/)
})

test('cli：--json 输出双跑逐字节一致', async () => {
  const subject = join(ROOT, 'samples', 'pattern-evidence.json')
  const basis = join(ROOT, 'samples', 'pattern-evidence-traces.json')
  const first = await capture(() => main(['check', 'pattern-evidence', '--input', subject, '--basis', basis, '--json']))
  const second = await capture(() => main(['check', 'pattern-evidence', '--input', subject, '--basis', basis, '--json']))
  assert.equal(first.code, EXIT_OK)
  assert.equal(first.out, second.out)
})

test('cli：--json 不含时间戳 / 绝对路径', async () => {
  const subject = join(ROOT, 'samples', 'pattern-evidence.json')
  const basis = join(ROOT, 'samples', 'pattern-evidence-traces.json')
  const { out } = await capture(() => main(['check', 'pattern-evidence', '--input', subject, '--basis', basis, '--json']))
  assert.equal(out.includes(ROOT.replaceAll('\\', '/')), false)
  assert.equal(out.includes(ROOT), false)
  assert.equal(/"generated_at"|"timestamp"/.test(out), false)
})

test('cli：refuted 样例退出 1（阻断）', async () => {
  const { writeFileSync, mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const dir = mkdtempSync(join(tmpdir(), 'pattern-evidence-cli-'))
  const path = join(dir, 'bad.json')
  const payload = JSON.parse(readFileSync(join(ROOT, 'samples', 'pattern-evidence.json'), 'utf8'))
  payload.claims[0].snippet = '不符'
  writeFileSync(path, JSON.stringify(payload))
  const basis = join(ROOT, 'samples', 'pattern-evidence-traces.json')
  const { code, out } = await capture(() => main(['check', 'pattern-evidence', '--input', path, '--basis', basis]))
  assert.equal(code, EXIT_BLOCKED)
  assert.match(out, /refuted=1/)
})

test('cli：缺 --input 退出 2', async () => {
  const { code } = await capture(() => main(['check', 'pattern-evidence']))
  assert.equal(code, EXIT_INPUT)
})

test('cli：缺必填字段退出 2', async () => {
  const { writeFileSync, mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const dir = mkdtempSync(join(tmpdir(), 'pattern-evidence-cli-'))
  const path = join(dir, 'missing.json')
  writeFileSync(path, JSON.stringify({ page: pageOf([]) }))
  const { code } = await capture(() => main(['check', 'pattern-evidence', '--input', path]))
  assert.equal(code, EXIT_INPUT)
})

test('cli：痕迹包缺节点退出 3（契约违约）', async () => {
  const subject = join(ROOT, 'samples', 'pattern-evidence.json')
  const { writeFileSync, mkdtempSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const dir = mkdtempSync(join(tmpdir(), 'pattern-evidence-cli-'))
  const basis = join(dir, 'empty-basis.json')
  writeFileSync(basis, JSON.stringify({ version: '1', nodes: [] }))
  const { code } = await capture(() => main(['check', 'pattern-evidence', '--input', subject, '--basis', basis]))
  assert.equal(code, EXIT_CONTRACT)
})

test('cli：未知器官仍退出 3（未注册）', async () => {
  const subject = join(ROOT, 'samples', 'pattern-evidence.json')
  const { code } = await capture(() => main(['check', 'no-such-verb', '--input', subject]))
  assert.equal(code, EXIT_CONTRACT)
})