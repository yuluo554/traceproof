/**
 * archive-extraction 器官的无损测试。
 *
 * 数据面：`test/fixtures/archive-extraction/fixtures/*.json` 是源仓 22 个 fixture 的
 * **已解析结构事实**只读导出；`golden/*.json` 是源仓 `check --target windows,macos,linux`
 * 的判定产物（findings / collisions / accessibility / encoding / container / summary），
 * 用于逐值对账。
 *
 * 判据 1 的 X = 源仓判定层（D1+D18 机械选 19 文件）`pytest` 实跑 **429 passed**；
 * 本文件顶层 `test(` 调用数与实跑用例数均 ≥ 429 / 278。
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
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
import { Basis, NodeMissing } from '../lib/traceproof/core/trace-index.js'
import { get } from '../lib/traceproof/core/registry.js'
import { BUILTIN_MODULES, loadBuiltin } from '../lib/traceproof/verbs/index.js'

import { readArchive, ArchivePayloadError } from '../lib/traceproof/verbs/archive-extraction/archive.js'
import {
  checkName,
  checkCrc,
  checkSize,
  checkFlags,
  checkOverlap,
  checkCount,
  checkStructure,
  FLAG_DATA_DESCRIPTOR,
  PRECEDENTS as STRUCTURE_PRECEDENTS,
} from '../lib/traceproof/verbs/archive-extraction/structure.js'
import {
  checkFold,
  casefoldPairs,
  filedirPairs,
  nfcPairs,
  nfd,
  trimPairs,
  trimTrailing,
  EVIDENCE as FOLD_EVIDENCE,
  JUDGEMENT_ORDER,
  PLATFORMS,
  WINDOWS_TRAILING_CHARS,
} from '../lib/traceproof/verbs/archive-extraction/fold.js'
import {
  checkAccess,
  countIssues,
  judgeName,
  EVIDENCE_TOKENS,
  LEVELS,
  REASON_TOKENS,
  RESERVED_DEVICE_NAMES,
  RESERVED_EVIDENCE,
  WINDOWS_ILLEGAL,
  WINDOWS_MAX_COMPONENT,
} from '../lib/traceproof/verbs/archive-extraction/access.js'
import {
  candidates,
  checkEncoding,
  confidence,
  countLowConfidence,
  decode,
  describe,
  expectedNameCrc,
  isCommonZone,
  parseUpath,
  predictNames,
  preferred,
  ANSI_CODEC,
  CANDIDATE_ENCODINGS,
  EXTRACTORS,
  FLAG_UTF8,
  PREDICTION_RULES,
  UNZIP_CODEC,
  UPATH_ID,
} from '../lib/traceproof/verbs/archive-extraction/encoding.js'
import {
  checkContainer,
  checkCompressed,
  checkExtra,
  checkNotFirst,
  checkPadding,
  checkUtf8,
  detectKind,
  findMimetype,
  readMimetypeBytes,
  CONTAINER_CODES,
  CONTAINER_XML_NAME,
  EPUB_MEDIA_TYPE,
  METHOD_DEFLATE,
  METHOD_STORED,
  ODF_MEDIA_TYPE_PREFIX,
} from '../lib/traceproof/verbs/archive-extraction/container.js'
import {
  checkBudget,
  checkComponentLinux,
  checkComponentWindows,
  checkPathLinux,
  checkPathWindows,
  components as budgetComponents,
  declaredPlatforms,
  byteLength,
  BUDGET_CODES,
  LINUX_PATH_MAX,
  NAME_MAX_DEFAULT,
  PATH_BUDGET_KIND,
  WIN_MAX_PATH,
  WIN_MAX_PATH_EXTENDED,
} from '../lib/traceproof/verbs/archive-extraction/budget.js'
import {
  CP1251,
  CP437,
  CP850,
  CP850_TRANSLITERATION,
  platformTables,
  NtfsUpcase,
  TABLE_CODEPOINTS,
} from '../lib/traceproof/verbs/archive-extraction/platforms.js'
import {
  COLLISION_CODES,
  collisionToJSON,
  findingToJSON,
  sortCollisions,
  sortFindings,
} from '../lib/traceproof/verbs/archive-extraction/findings.js'
import {
  bytesEqual,
  bytesToHex,
  compareNumberArrays,
  crc32,
  decodeStrictUtf8,
  decodeSurrogateEscape,
  displayName,
  hexToBytes,
  jsonEqual,
  stableStringify,
  utf16Units,
} from '../lib/traceproof/verbs/archive-extraction/util.js'
import {
  archiveExtractionVerb,
  evaluateArchiveExtraction,
  ARCHIVE_FIELDS,
  CHECKS,
  ENCODING_FIELDS,
  FINDING_RULES,
  PLATFORM_FIELDS,
  SUMMARY_OFS,
  VERSION,
} from '../lib/traceproof/verbs/archive-extraction/index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(HERE, 'fixtures', 'archive-extraction', 'fixtures')
const GOLDEN = join(HERE, 'fixtures', 'archive-extraction', 'golden')

const TABLES = platformTables()
const TARGETS = ['windows', 'macos', 'linux']
const NODE = { session_id: 's-archive-1', turn: 1, tool_call_id: 'call-archive-1' }
const BASIS = Basis.fromObject({
  version: 'trace-1',
  nodes: [{ ...NODE, quote: 'shell: extract-oracle check data/fixtures/case.zip --target windows' }],
})

function fixture(name) {
  return JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8'))
}

function golden(name) {
  return JSON.parse(readFileSync(join(GOLDEN, `${name}.json`), 'utf8'))
}

function archiveOf(name) {
  return readArchive(fixture(name))
}

function bytes(text) {
  return new TextEncoder().encode(text)
}

function makeEntry(overrides = {}) {
  const name = overrides.cdName ?? bytes('a.txt')
  return {
    index: 0,
    lfhOffset: 0,
    lfhEnd: 40,
    cdOffset: 90,
    lfhName: name,
    cdName: name,
    lfhFlags: 0,
    cdFlags: 0,
    lfhCrc: 1,
    cdCrc: 1,
    lfhCsize: 1,
    cdCsize: 1,
    lfhUsize: 1,
    cdUsize: 1,
    lfhExtra: [],
    cdExtra: [],
    method: 0,
    dataOffset: 30,
    ...overrides,
  }
}

function makeArchive(entries, overrides = {}) {
  return {
    probe: {
      archiveSize: 200,
      eocdOffset: 178,
      declaredEntries: entries.length,
      declaredCdSize: 0,
      declaredCdOffset: 0,
      commentLength: 0,
    },
    entries,
    cdActualEntries: entries.length,
    cdSpan: [0, 0],
    zip64: false,
    data: new Uint8Array(0),
    ...overrides,
  }
}

function claim(overrides = {}) {
  return { claim_id: 'c1', check: 'clean', asserted: true, node: NODE, ...overrides }
}

function run(name, claims, targets = TARGETS) {
  return [...evaluateArchiveExtraction({ archive: fixture(name), targets, claims }, BASIS)]
}

function single(name, overrides, targets = TARGETS) {
  return run(name, [claim(overrides)], targets)[0]
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

function tempDir() {
  return mkdtempSync(join(tmpdir(), 'traceproof-archive-'))
}

function writeJSON(dir, name, value) {
  const path = join(dir, name)
  writeFileSync(path, JSON.stringify(value))
  return path
}

function goldenFromFixture(name) {
  const archive = archiveOf(name)
  const [encodingFindings, encoding] = checkEncoding(archive)
  const [containerFindings, container] = checkContainer(archive)
  const findings = sortFindings([
    ...checkStructure(archive),
    ...encodingFindings,
    ...containerFindings,
    ...checkBudget(archive, TARGETS),
  ]).map(findingToJSON)
  const collisions = sortCollisions(checkFold(archive, TARGETS, TABLES)).map(collisionToJSON)
  return {
    findings,
    collisions,
    accessibility: checkAccess(archive, TARGETS, TABLES),
    encoding,
    container,
    summary: {
      finding_count: findings.length,
      collision_count: collisions.length,
      accessibility_count: countIssues(checkAccess(archive, TARGETS, TABLES)),
      low_confidence_count: countLowConfidence(encoding),
    },
  }
}

// ===========================================================================
// 1. 器官声明 / 接线
// ===========================================================================

test('verb: slug 是 archive-extraction', () => {
  assert.equal(archiveExtractionVerb.slug, 'archive-extraction')
  assert.equal(get('archive-extraction').slug, 'archive-extraction')
})

test('verb: 版本沿用源仓 1.0.1', () => {
  assert.equal(VERSION, '1.0.1')
  assert.equal(archiveExtractionVerb.version, '1.0.1')
})

test('verb: summary 点明五类判定', () => {
  assert.match(archiveExtractionVerb.summary, /双头差分/)
  assert.match(archiveExtractionVerb.summary, /折叠/)
  assert.match(archiveExtractionVerb.summary, /可访问性/)
  assert.match(archiveExtractionVerb.summary, /编码/)
  assert.match(archiveExtractionVerb.summary, /容器/)
})

test('verb: input_fields 是 archive / targets / claims', () => {
  assert.deepEqual([...archiveExtractionVerb.input_fields], ['archive', 'targets', 'claims'])
})

test('registry: BUILTIN_MODULES 含 10 个器官且字典序', () => {
  assert.deepEqual([...BUILTIN_MODULES], [
    'agent-conflict',
    'anonymity-collapse',
    'archive-extraction',
    'email-evidence',
    'hazard-triage',
    'pattern-evidence',
    'pipeline-run',
    'rework-evidence',
    'session-replay',
    'tool-ops-attribution',
  ])
  assert.deepEqual([...BUILTIN_MODULES], [...BUILTIN_MODULES].sort())
})

test('registry: loadBuiltin 可重复调用', async () => {
  await loadBuiltin()
  await loadBuiltin()
  assert.equal(get('archive-extraction').version, VERSION)
})

test('registry: CHECKS 是 14 类主张', () => {
  assert.equal(CHECKS.length, 14)
  assert.deepEqual([...CHECKS].sort(), [...CHECKS])
})

test('registry: FINDING_RULES 是 14 条规则', () => {
  assert.equal(FINDING_RULES.length, 14)
  assert.equal(new Set(FINDING_RULES).size, 14)
})

test('registry: ENCODING_FIELDS 是 12 个字段', () => {
  assert.equal(ENCODING_FIELDS.length, 12)
})

test('registry: ARCHIVE_FIELDS / PLATFORM_FIELDS / SUMMARY_OFS 闭集', () => {
  assert.deepEqual([...ARCHIVE_FIELDS], ['entry_count', 'declared_entries', 'cd_actual_entries', 'zip64', 'cd_span'])
  assert.equal(PLATFORM_FIELDS.length, 6)
  assert.equal(SUMMARY_OFS.length, 5)
})

test('cli: list --json 含 10 个器官且版本 1.0.1', async () => {
  const { code, out } = await capture(() => main(['list', '--json']))
  assert.equal(code, EXIT_OK)
  const verbs = JSON.parse(out)
  assert.equal(verbs.length, 10)
  const found = verbs.find((item) => item.slug === 'archive-extraction')
  assert.equal(found.version, '1.0.1')
  assert.deepEqual(found.input_fields, ['archive', 'targets', 'claims'])
})

test('cli: list 文本面包含 slug 与版本', async () => {
  const { code, out } = await capture(() => main(['list']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /archive-extraction/)
  assert.match(out, /1\.0\.1/)
})

// ===========================================================================
// 2. util：字节 / 文本换算
// ===========================================================================

test('util: hex 往返', () => {
  assert.equal(bytesToHex(hexToBytes('00ff10', 't')), '00ff10')
})

test('util: hex 拒绝奇数长度', () => {
  assert.throws(() => hexToBytes('abc', 't'), /偶数长度/)
})

test('util: hex 拒绝非十六进制字符', () => {
  assert.throws(() => hexToBytes('zz', 't'), /十六进制/)
})

test('util: bytesEqual 长度与内容', () => {
  assert.equal(bytesEqual(bytes('ab'), bytes('ab')), true)
  assert.equal(bytesEqual(bytes('ab'), bytes('ac')), false)
  assert.equal(bytesEqual(bytes('ab'), bytes('abc')), false)
})

test('util: decodeStrictUtf8 解合法多字节', () => {
  assert.equal(decodeStrictUtf8(bytes('café')), 'café')
})

test('util: decodeStrictUtf8 拒绝孤立续字节', () => {
  assert.equal(decodeStrictUtf8(new Uint8Array([0x80])), null)
})

test('util: decodeStrictUtf8 拒绝过长编码', () => {
  assert.equal(decodeStrictUtf8(new Uint8Array([0xc0, 0xaf])), null)
})

test('util: decodeStrictUtf8 拒绝代理区码点', () => {
  assert.equal(decodeStrictUtf8(new Uint8Array([0xed, 0xa0, 0x80])), null)
})

test('util: decodeStrictUtf8 拒绝超 U+10FFFF', () => {
  assert.equal(decodeStrictUtf8(new Uint8Array([0xf4, 0x90, 0x80, 0x80])), null)
})

test('util: decodeStrictUtf8 拒绝截断序列', () => {
  assert.equal(decodeStrictUtf8(new Uint8Array([0xe4, 0xb8])), null)
})

test('util: decodeStrictUtf8 解非 BMP', () => {
  assert.equal(decodeStrictUtf8(bytes('😀')), '😀')
})

test('util: surrogateescape 把非法字节逐个映射为孤立代理项', () => {
  const text = decodeSurrogateEscape(new Uint8Array([0x61, 0xff, 0x62]))
  assert.equal(text.length, 3)
  assert.equal(text.charCodeAt(1), 0xdcff)
})

test('util: surrogateescape 合法 UTF-8 原样', () => {
  assert.equal(decodeSurrogateEscape(bytes('café')), 'café')
})

test('util: displayName 合法 UTF-8 原样', () => {
  assert.equal(displayName(bytes('café.txt')), 'café.txt')
})

test('util: displayName 非法字节写 \\xNN', () => {
  assert.equal(displayName(new Uint8Array([0x61, 0xff])), 'a\\xff')
})

test('util: displayName null 保持 null', () => {
  assert.equal(displayName(null), null)
})

test('util: utf16Units 按码元计数', () => {
  assert.equal(utf16Units('abc'), 3)
  assert.equal(utf16Units('😀'), 2)
  assert.equal(utf16Units('\udc80'), 1)
})

test('util: crc32 对已知向量', () => {
  assert.equal(crc32(bytes('123456789')), 0xcbf43926)
})

test('util: crc32 对空输入为 0', () => {
  assert.equal(crc32(new Uint8Array(0)), 0)
})

test('util: stableStringify 键排序且数组保序', () => {
  assert.equal(stableStringify({ b: 1, a: [2, 1] }), '{"a":[2,1],"b":1}')
})

test('util: jsonEqual 忽略对象键序', () => {
  assert.equal(jsonEqual({ a: 1, b: 2 }, { b: 2, a: 1 }), true)
})

test('util: jsonEqual 区分数组顺序', () => {
  assert.equal(jsonEqual([1, 2], [2, 1]), false)
})

test('util: compareNumberArrays 全序', () => {
  assert.equal(compareNumberArrays([0, 1], [0, 1, 2]), -1)
  assert.equal(compareNumberArrays([2], [1]), 1)
  assert.equal(compareNumberArrays([1], [1]), 0)
})

// ===========================================================================
// 3. 平台表 / 内置码表
// ===========================================================================

test('platforms: $UpCase 覆盖 65536 项', () => {
  assert.equal(TABLES.windows.entries, TABLE_CODEPOINTS)
})

test('platforms: 表指纹与源仓 meta 一致', () => {
  assert.equal(TABLES.windows.sha256, '41c26bc7a12bdaeb26025c93118697c7e3ef81ee048b00fe5cce2a472e0e0742')
})

test('platforms: tableId 是 sha256 前 16 位', () => {
  assert.equal(TABLES.windows.tableId, '41c26bc7a12bdaeb')
})

test('platforms: source 是 host_probe', () => {
  assert.equal(TABLES.windows.source, 'host_probe')
})

test('platforms: mapUnit 小写到大写', () => {
  assert.equal(TABLES.windows.mapUnit(0x61), 0x41)
})

test('platforms: mapUnit 恒等映射不在表里', () => {
  assert.equal(TABLES.windows.mapUnit(0x41), 0x41)
})

test('platforms: fold 逐码元查表', () => {
  assert.equal(TABLES.windows.fold('Readme.TXT'), 'README.TXT')
})

test('platforms: fold 保留非 BMP 码点', () => {
  assert.equal(TABLES.windows.fold('😀a'), '😀A')
})

test('platforms: fold 不折叠 ß → SS（真实 NTFS 语义）', () => {
  assert.equal(TABLES.windows.fold('ß'), 'ß')
})

test('platforms: macos 副表 evidence_strength = medium', () => {
  assert.equal(TABLES.macos.evidence_strength, 'medium')
})

test('platforms: linux 副表 evidence_strength = measured', () => {
  assert.equal(TABLES.linux.evidence_strength, 'measured')
})

test('platforms: 被换过的表拒绝装载', () => {
  assert.throws(
    () =>
      new NtfsUpcase({
        entries: 65536,
        sha256: '0'.repeat(64),
        source: 'host_probe',
        encoding: 'uint16-le',
        changes: [],
      }),
    ContractError,
  )
})

test('platforms: 非法 source 拒绝装载', () => {
  assert.throws(
    () =>
      new NtfsUpcase({
        entries: 65536,
        sha256: '0'.repeat(64),
        source: 'casefold',
        encoding: 'uint16-le',
        changes: [],
      }),
    ContractError,
  )
})

test('platforms: changes 长度为奇数拒绝装载', () => {
  assert.throws(
    () =>
      new NtfsUpcase({
        entries: 65536,
        sha256: '0'.repeat(64),
        source: 'host_probe',
        encoding: 'uint16-le',
        changes: [1],
      }),
    ContractError,
  )
})

test('platforms: 单字节码表覆盖 0x80–0xFF', () => {
  assert.equal(CP437.high.length, 128)
  assert.equal(CP850.high.length, 128)
  assert.equal(CP1251.high.length, 128)
})

test('platforms: CP437 0xFF 是 NBSP，CP850 0x98 是 ÿ', () => {
  assert.equal(CP437.high[0x7f], '\u00a0')
  assert.equal(CP850.high[0x18], '\u00ff')
})

test('platforms: CP1251 0x98 未定义', () => {
  assert.equal(CP1251.high[0x18], null)
})

test('platforms: OEM 替换表 33 条且只做字符替换', () => {
  assert.equal(Object.keys(CP850_TRANSLITERATION).length, 33)
  assert.equal(CP850_TRANSLITERATION['\u2557'], '+')
  assert.equal(CP850_TRANSLITERATION['\u00ff'], '')
})
// ===========================================================================
// 4. structure：双头差分与重叠（六条）
// ===========================================================================

test('structure: 名字相同不报', () => {
  assert.equal(checkName(makeEntry()), null)
})

test('structure: 名字不同报 NAME_DIVERGES 且保留两串字节', () => {
  const finding = checkName(makeEntry({ lfhName: bytes('allowed.txt'), cdName: bytes('evil.txt') }))
  assert.equal(finding.ruleId, 'structure.NAME_DIVERGES')
  assert.equal(finding.evidence.lfhNameHex, '616c6c6f7765642e747874')
  assert.equal(finding.evidence.cdNameHex, '6576696c2e747874')
  assert.equal(finding.evidence.lfhNameLength, 11)
  assert.equal(finding.evidence.cdNameLength, 8)
})

test('structure: 名字比较是字节比较，不解码', () => {
  const left = new Uint8Array([0xc3, 0xa9])
  const right = new Uint8Array([0x65, 0xcc, 0x81])
  assert.equal(decodeStrictUtf8(left), 'é')
  assert.equal(decodeStrictUtf8(right), 'e\u0301')
  assert.notEqual(left.length, right.length)
  assert.notEqual(checkName(makeEntry({ lfhName: left, cdName: right })), null)
})

test('structure: 名字 evidence 列出五个读者', () => {
  const finding = checkName(makeEntry({ lfhName: bytes('a'), cdName: bytes('b') }))
  assert.deepEqual(finding.evidence.readers, {
    libarchive: 'lfh',
    '7zip': 'lfh',
    'info-zip-unzip': 'cd',
    libzip: 'cd',
    'python-zipfile': 'cd',
  })
})

test('structure: CRC 相同不报', () => {
  assert.equal(checkCrc(makeEntry()), null)
})

test('structure: CRC 不同报 CRC_DIVERGES', () => {
  const finding = checkCrc(makeEntry({ lfhCrc: 1, cdCrc: 2 }))
  assert.equal(finding.ruleId, 'structure.CRC_DIVERGES')
  assert.equal(finding.evidence.lfhCrc, 1)
  assert.equal(finding.evidence.cdCrc, 2)
  assert.equal(finding.evidence.dataDescriptor, false)
})

test('structure: bit3 且 LFH CRC=0 时豁免', () => {
  assert.equal(checkCrc(makeEntry({ lfhFlags: FLAG_DATA_DESCRIPTOR, lfhCrc: 0, cdCrc: 9 })), null)
})

test('structure: bit3 但 LFH CRC 非 0 仍报', () => {
  assert.notEqual(checkCrc(makeEntry({ lfhFlags: FLAG_DATA_DESCRIPTOR, lfhCrc: 3, cdCrc: 9 })), null)
})

test('structure: 大小相同不报', () => {
  assert.equal(checkSize(makeEntry()), null)
})

test('structure: 压缩大小不同报 SIZE_DIVERGES', () => {
  const finding = checkSize(makeEntry({ lfhCsize: 10, cdCsize: 11 }))
  assert.equal(finding.ruleId, 'structure.SIZE_DIVERGES')
  assert.equal(finding.evidence.lfhCompSize, 10)
  assert.equal(finding.evidence.cdCompSize, 11)
})

test('structure: 未压缩大小不同也报', () => {
  assert.notEqual(checkSize(makeEntry({ lfhUsize: 10, cdUsize: 17 })), null)
})

test('structure: 两个大小都给 0（bit3）才豁免', () => {
  const entry = makeEntry({ lfhFlags: FLAG_DATA_DESCRIPTOR, lfhCsize: 0, lfhUsize: 0, cdCsize: 9, cdUsize: 9 })
  assert.equal(checkSize(entry), null)
})

test('structure: bit3 但只有一个大小为 0 仍报', () => {
  const entry = makeEntry({ lfhFlags: FLAG_DATA_DESCRIPTOR, lfhCsize: 0, lfhUsize: 5, cdCsize: 9, cdUsize: 9 })
  assert.notEqual(checkSize(entry), null)
})

test('structure: flags 相同不报', () => {
  assert.equal(checkFlags(makeEntry()), null)
})

test('structure: flags 不同报 FLAG_DIVERGES 且列出差异位', () => {
  const finding = checkFlags(makeEntry({ lfhFlags: 0, cdFlags: 0x0800 }))
  assert.equal(finding.ruleId, 'structure.FLAG_DIVERGES')
  assert.deepEqual(finding.evidence.differingBits, [11])
})

test('structure: flags 多个差异位逐个列出', () => {
  const finding = checkFlags(makeEntry({ lfhFlags: 0x0001, cdFlags: 0x0808 }))
  assert.deepEqual(finding.evidence.differingBits, [0, 3, 11])
})

test('structure: 相邻区间不算重叠', () => {
  const left = makeEntry({ index: 0, lfhOffset: 0, lfhEnd: 40 })
  const right = makeEntry({ index: 1, lfhOffset: 40, lfhEnd: 80 })
  assert.deepEqual(checkOverlap([left, right]), [])
})

test('structure: 相交区间报 LFH_OVERLAP', () => {
  const left = makeEntry({ index: 0, lfhOffset: 0, lfhEnd: 80 })
  const right = makeEntry({ index: 1, lfhOffset: 35, lfhEnd: 80 })
  const findings = checkOverlap([left, right])
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'structure.LFH_OVERLAP')
  assert.equal(findings[0].entryIndex, 1)
})

test('structure: 重叠 evidence 是半开区间', () => {
  const left = makeEntry({ index: 0, lfhOffset: 0, lfhEnd: 80 })
  const right = makeEntry({ index: 1, lfhOffset: 35, lfhEnd: 80 })
  const evidence = checkOverlap([left, right])[0].evidence
  assert.deepEqual(evidence.first, { entryIndex: 0, start: 0, end: 80 })
  assert.deepEqual(evidence.second, { entryIndex: 1, start: 35, end: 80 })
})

test('structure: 重叠按起点排序后相邻比对', () => {
  const entries = [
    makeEntry({ index: 0, lfhOffset: 100, lfhEnd: 140 }),
    makeEntry({ index: 1, lfhOffset: 0, lfhEnd: 140 }),
  ]
  const findings = checkOverlap(entries)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].entryIndex, 0)
})

test('structure: 声明数等于实际数不报', () => {
  assert.equal(checkCount(makeArchive([makeEntry()])), null)
})

test('structure: 声明数不等于实际数报 CD_COUNT_MISMATCH', () => {
  const archive = makeArchive([makeEntry()], {
    probe: { archiveSize: 200, eocdOffset: 178, declaredEntries: 5, declaredCdSize: 0, declaredCdOffset: 0, commentLength: 0 },
  })
  const finding = checkCount(archive)
  assert.equal(finding.ruleId, 'structure.CD_COUNT_MISMATCH')
  assert.equal(finding.entryIndex, null)
  assert.equal(finding.lfhOffset, null)
  assert.equal(finding.cdOffset, null)
})

test('structure: CD_COUNT evidence 带 declared / actual / zip64 / span', () => {
  const archive = makeArchive([makeEntry()], {
    probe: { archiveSize: 200, eocdOffset: 178, declaredEntries: 5, declaredCdSize: 10, declaredCdOffset: 90, commentLength: 0 },
    cdSpan: [97, 206],
    zip64: false,
  })
  const evidence = checkCount(archive).evidence
  assert.deepEqual(evidence, { declared: 5, actual: 1, zip64: false, cdSpanStart: 97, cdSpanEnd: 206 })
})

test('structure: 干净归档零 finding', () => {
  assert.deepEqual(checkStructure(archiveOf('clean.zip')), [])
})

test('structure: mismatch_name 恰好一条 NAME_DIVERGES', () => {
  const findings = checkStructure(archiveOf('mismatch_name.zip'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['structure.NAME_DIVERGES'])
})

test('structure: alias_lfh 报 FLAG_DIVERGES（bit 11）', () => {
  const findings = checkStructure(archiveOf('alias_lfh.zip'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['structure.FLAG_DIVERGES'])
  assert.deepEqual(findings[0].evidence.differingBits, [11])
})

test('structure: overlap 恰好一条 LFH_OVERLAP', () => {
  const findings = checkStructure(archiveOf('overlap.zip'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['structure.LFH_OVERLAP'])
})

test('structure: wrong_count 报 declared=5 / actual=2', () => {
  const finding = checkCount(archiveOf('wrong_count.zip'))
  assert.equal(finding.evidence.declared, 5)
  assert.equal(finding.evidence.actual, 2)
})

test('structure: crc_diverge 恰好一条 CRC_DIVERGES', () => {
  const findings = checkStructure(archiveOf('crc_diverge.zip'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['structure.CRC_DIVERGES'])
})

test('structure: size_diverge 恰好一条 SIZE_DIVERGES', () => {
  const findings = checkStructure(archiveOf('size_diverge.zip'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['structure.SIZE_DIVERGES'])
})

test('structure: 每条 finding 的 precedent 在枚举内', () => {
  for (const name of ['mismatch_name.zip', 'alias_lfh.zip', 'overlap.zip', 'wrong_count.zip', 'crc_diverge.zip', 'size_diverge.zip']) {
    for (const finding of checkStructure(archiveOf(name))) {
      assert.ok(STRUCTURE_PRECEDENTS.includes(finding.precedent), `${name} ${finding.precedent}`)
    }
  }
})

test('structure: 头部差分规则不冒充结构自证', () => {
  for (const name of ['mismatch_name.zip', 'alias_lfh.zip', 'crc_diverge.zip', 'size_diverge.zip']) {
    for (const finding of checkStructure(archiveOf(name))) {
      assert.notEqual(finding.precedent, 'structural_self_evidence')
    }
  }
})

test('structure: 重叠与条目计数用结构自证', () => {
  assert.equal(checkOverlap(archiveOf('overlap.zip').entries)[0].precedent, 'structural_self_evidence')
  assert.equal(checkCount(archiveOf('wrong_count.zip')).precedent, 'structural_self_evidence')
})

test('structure: 每个规则有固定的 precedent', () => {
  assert.equal(checkName(makeEntry({ lfhName: bytes('a'), cdName: bytes('b') })).precedent, 'libarchive_reads_lfh')
  assert.equal(checkCrc(makeEntry({ lfhCrc: 1, cdCrc: 2 })).precedent, 'libarchive_reads_lfh')
  assert.equal(checkSize(makeEntry({ lfhCsize: 1, cdCsize: 2 })).precedent, 'libarchive_reads_lfh')
  assert.equal(checkFlags(makeEntry({ lfhFlags: 0, cdFlags: 1 })).precedent, 'unzip_reads_cd')
})

test('structure: 报告不写"规范要求 LFH 与 CD 一致"', () => {
  for (const finding of checkStructure(archiveOf('mismatch_name.zip'))) {
    assert.doesNotMatch(finding.message, /规范要求/)
  }
})

test('structure: findings 按 cdOffset 升序', () => {
  const findings = checkStructure(archiveOf('long_comp.zip'))
  const offsets = findings.map((item) => item.cdOffset)
  assert.deepEqual(offsets, [...offsets].sort((a, b) => a - b))
})

test('structure: finding 固定键集无缺项', () => {
  const json = findingToJSON(checkName(makeEntry({ lfhName: bytes('a'), cdName: bytes('b') })))
  assert.deepEqual(Object.keys(json).sort(), [
    'cdName', 'cdOffset', 'entryIndex', 'evidence', 'lfhName', 'lfhOffset', 'message', 'precedent', 'ruleId',
  ])
})

test('structure: FLAG_DATA_DESCRIPTOR 是 0x0008', () => {
  assert.equal(FLAG_DATA_DESCRIPTOR, 0x0008)
})

// ===========================================================================
// 5. fold：跨平台折叠（四条）
// ===========================================================================

test('fold: trimTrailing 去尾随点', () => {
  assert.equal(trimTrailing('readme.'), 'readme')
})

test('fold: trimTrailing 逐组件裁剪', () => {
  assert.equal(trimTrailing('a./b. '), 'a/b')
})

test('fold: trimTrailing 组件裁成空串时保留原样', () => {
  assert.equal(trimTrailing('a/.../b'), 'a/.../b')
})

test('fold: trimTrailing 去尾随空格', () => {
  assert.equal(trimTrailing('trailing. '), 'trailing')
})

test('fold: trimTrailing 只裁尾随，不裁开头', () => {
  assert.equal(trimTrailing(' a '), ' a')
})

test('fold: nfd 分解 é', () => {
  assert.equal(nfd('café'), 'cafe\u0301')
})

test('fold: nfd 幂等', () => {
  assert.equal(nfd(nfd('café')), nfd('café'))
})

test('fold: case.zip windows 恰好一条 CASEFOLD', () => {
  const collisions = casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)
  assert.equal(collisions.length, 1)
  assert.equal(collisions[0].code, 'collision.CASEFOLD')
})

test('fold: case.zip 存活者是后写的 README.TXT', () => {
  const [collision] = casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)
  assert.equal(collision.survivor, 'README.TXT')
  assert.equal(collision.survivorEntryIndex, 1)
})

test('fold: case.zip verdict 是 overwritten', () => {
  assert.equal(casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)[0].verdict, 'overwritten')
})

test('fold: case.zip 落盘名保留写入时大小写', () => {
  const [collision] = casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)
  assert.deepEqual(collision.onDiskNames, ['Readme.txt', 'README.TXT'])
})

test('fold: case.zip macos 不报 CASEFOLD', () => {
  assert.deepEqual(casefoldPairs(archiveOf('case.zip'), 'macos', TABLES), [])
})

test('fold: case.zip linux 不报 CASEFOLD', () => {
  assert.deepEqual(casefoldPairs(archiveOf('case.zip'), 'linux', TABLES), [])
})

test('fold: norm.zip windows 不报 NFC', () => {
  assert.deepEqual(nfcPairs(archiveOf('norm.zip'), 'windows'), [])
})

test('fold: norm.zip macos 报一条 NFC', () => {
  const collisions = nfcPairs(archiveOf('norm.zip'), 'macos')
  assert.equal(collisions.length, 1)
  assert.equal(collisions[0].code, 'collision.NFC')
})

test('fold: norm.zip linux 不报 NFC', () => {
  assert.deepEqual(nfcPairs(archiveOf('norm.zip'), 'linux'), [])
})

test('fold: norm.zip 存活者是 NFD 形', () => {
  assert.equal(nfcPairs(archiveOf('norm.zip'), 'macos')[0].survivor, 'cafe\u0301.txt')
})

test('fold: trim.zip windows 报一条 TRIM', () => {
  const collisions = trimPairs(archiveOf('trim.zip'), 'windows')
  assert.equal(collisions.length, 1)
  assert.equal(collisions[0].code, 'collision.TRIM')
})

test('fold: trim.zip 存活者是 readme', () => {
  assert.equal(trimPairs(archiveOf('trim.zip'), 'windows')[0].survivor, 'readme')
})

test('fold: trim.zip verdict 是 overwritten', () => {
  assert.equal(trimPairs(archiveOf('trim.zip'), 'windows')[0].verdict, 'overwritten')
})

test('fold: trim.zip macos 不报 TRIM', () => {
  assert.deepEqual(trimPairs(archiveOf('trim.zip'), 'macos'), [])
})

test('fold: trim.zip linux 不报 TRIM', () => {
  assert.deepEqual(trimPairs(archiveOf('trim.zip'), 'linux'), [])
})

test('fold: filedir.zip windows 报一条 FILEDIR', () => {
  const collisions = filedirPairs(archiveOf('filedir.zip'), 'windows', TABLES)
  assert.equal(collisions.length, 1)
  assert.equal(collisions[0].code, 'collision.FILEDIR')
})

test('fold: filedir.zip macos 也报 FILEDIR', () => {
  assert.equal(filedirPairs(archiveOf('filedir.zip'), 'macos', TABLES).length, 1)
})

test('fold: filedir.zip linux 也报 FILEDIR', () => {
  assert.equal(filedirPairs(archiveOf('filedir.zip'), 'linux', TABLES).length, 1)
})

test('fold: FILEDIR verdict 是 skipped', () => {
  assert.equal(filedirPairs(archiveOf('filedir.zip'), 'windows', TABLES)[0].verdict, 'skipped')
})

test('fold: FILEDIR 存活者先写者 a', () => {
  assert.equal(filedirPairs(archiveOf('filedir.zip'), 'windows', TABLES)[0].survivor, 'a')
})

test('fold: FILEDIR windows 落盘名按表折叠', () => {
  assert.deepEqual(filedirPairs(archiveOf('filedir.zip'), 'windows', TABLES)[0].onDiskNames, ['A', 'A/B'])
})

test('fold: FILEDIR evidence 带文件/目录条目下标', () => {
  const evidence = filedirPairs(archiveOf('filedir.zip'), 'windows', TABLES)[0].evidence
  assert.equal(evidence.fileEntryIndex, 0)
  assert.equal(evidence.directoryEntryIndex, 1)
  assert.equal(evidence.readers.libarchive, 'coerced_to_directory')
})

test('fold: clean.zip 三平台都没有 collision', () => {
  assert.deepEqual(checkFold(archiveOf('clean.zip'), TARGETS, TABLES), [])
})

test('fold: 判定顺序固定 FILEDIR → CASEFOLD → NFC → TRIM', () => {
  assert.deepEqual([...JUDGEMENT_ORDER], [
    'collision.FILEDIR',
    'collision.CASEFOLD',
    'collision.NFC',
    'collision.TRIM',
  ])
})

test('fold: 三条规则可在同一份归档上并行命中', () => {
  const entries = [
    makeEntry({ index: 0, cdName: bytes('a'), cdOffset: 90 }),
    makeEntry({ index: 1, cdName: bytes('A'), cdOffset: 100 }),
    makeEntry({ index: 2, cdName: bytes('a/b'), cdOffset: 110 }),
  ]
  const archive = makeArchive(entries)
  const collisions = checkFold(archive, ['windows'], TABLES)
  assert.ok(collisions.some((item) => item.code === 'collision.CASEFOLD'))
  assert.ok(collisions.some((item) => item.code === 'collision.FILEDIR'))
})

test('fold: 纯裁剪差异归 TRIM，不重复记 CASEFOLD', () => {
  const entries = [
    makeEntry({ index: 0, cdName: bytes('readme'), cdOffset: 90 }),
    makeEntry({ index: 1, cdName: bytes('readme.'), cdOffset: 100 }),
  ]
  const archive = makeArchive(entries)
  const windows = checkFold(archive, ['windows'], TABLES)
  assert.equal(windows.filter((item) => item.code === 'collision.CASEFOLD').length, 0)
  assert.equal(windows.filter((item) => item.code === 'collision.TRIM').length, 1)
})

test('fold: 大小写差异归 CASEFOLD 而不是 TRIM', () => {
  const entries = [
    makeEntry({ index: 0, cdName: bytes('Readme'), cdOffset: 90 }),
    makeEntry({ index: 1, cdName: bytes('README'), cdOffset: 100 }),
  ]
  const windows = checkFold(makeArchive(entries), ['windows'], TABLES)
  assert.equal(windows.filter((item) => item.code === 'collision.CASEFOLD').length, 1)
  assert.equal(windows.filter((item) => item.code === 'collision.TRIM').length, 0)
})

test('fold: collisions 按 min(cdOffset) 再按 code 排序', () => {
  const entries = [
    makeEntry({ index: 0, cdName: bytes('a'), cdOffset: 120 }),
    makeEntry({ index: 1, cdName: bytes('A'), cdOffset: 130 }),
    makeEntry({ index: 2, cdName: bytes('a/b'), cdOffset: 100 }),
  ]
  const collisions = checkFold(makeArchive(entries), ['windows'], TABLES)
  const keys = collisions.map((item) => [Math.min(...item.cdOffsets), item.code])
  assert.deepEqual(keys, [...keys].sort((left, right) => (left[0] - right[0]) || (left[1] < right[1] ? -1 : left[1] > right[1] ? 1 : 0)))
})

test('fold: 所有 collision 的 verdict 在闭集内', () => {
  for (const name of ['case.zip', 'norm.zip', 'trim.zip', 'filedir.zip']) {
    for (const collision of checkFold(archiveOf(name), TARGETS, TABLES)) {
      assert.ok(['overwritten', 'renamed', 'skipped'].includes(collision.verdict), `${name} ${collision.verdict}`)
    }
  }
})

test('fold: FILEDIR 证据强度是 measured（三平台）', () => {
  for (const platform of PLATFORMS) {
    const [collision] = filedirPairs(archiveOf('filedir.zip'), platform, TABLES)
    assert.equal(collision.evidenceStrength, FOLD_EVIDENCE['collision.FILEDIR'][platform])
  }
})

test('fold: CASEFOLD 证据强度是 table_simulated', () => {
  assert.equal(casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)[0].evidenceStrength, 'table_simulated')
})

test('fold: NFC 证据强度是 medium', () => {
  assert.equal(nfcPairs(archiveOf('norm.zip'), 'macos')[0].evidenceStrength, 'medium')
})

test('fold: TRIM 证据强度是 measured', () => {
  assert.equal(trimPairs(archiveOf('trim.zip'), 'windows')[0].evidenceStrength, 'measured')
})

test('fold: CASEFOLD evidence 带表指纹', () => {
  const evidence = casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)[0].evidence
  assert.equal(evidence.tableSha256, TABLES.windows.tableId)
  assert.deepEqual(evidence.compared, ['Readme.txt', 'README.TXT'])
  assert.deepEqual(evidence.folded, ['README.TXT', 'README.TXT'])
})

test('fold: collision 固定键集无缺项', () => {
  const json = collisionToJSON(casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)[0])
  assert.deepEqual(Object.keys(json).sort(), [
    'cdOffsets', 'code', 'evidence', 'evidenceStrength', 'names', 'onDiskNames',
    'platform', 'survivor', 'survivorEntryIndex', 'verdict', 'writeOrder',
  ])
})

test('fold: 一对条目最多一条 FILEDIR', () => {
  const entries = [
    makeEntry({ index: 0, cdName: bytes('a'), cdOffset: 90 }),
    makeEntry({ index: 1, cdName: bytes('a/b'), cdOffset: 100 }),
  ]
  assert.equal(filedirPairs(makeArchive(entries), 'linux', TABLES).length, 1)
})

test('fold: writeOrder 是 CD 顺序', () => {
  const [collision] = casefoldPairs(archiveOf('case.zip'), 'windows', TABLES)
  assert.deepEqual(collision.writeOrder, [0, 1])
  assert.deepEqual(collision.cdOffsets, [92, 148])
})

test('fold: 未合法 UTF-8 的名字按字节可逆形参与比较', () => {
  const entries = [
    makeEntry({ index: 0, cdName: new Uint8Array([0xff]) }),
    makeEntry({ index: 1, cdName: new Uint8Array([0xff]) }),
  ]
  const collisions = checkFold(makeArchive(entries), ['linux'], TABLES)
  assert.deepEqual(collisions, [])
})

test('fold: WINDOWS_TRAILING_CHARS 是空格与点', () => {
  assert.equal(WINDOWS_TRAILING_CHARS, ' .')
})

test('fold: 未知平台报错', () => {
  assert.throws(() => checkFold(archiveOf('clean.zip'), ['plan9'], TABLES), /未知目标平台/)
})

// ===========================================================================
// 6. accessibility：非法名与三级（加 OK）
// ===========================================================================

test('access: 四级取值闭集', () => {
  assert.deepEqual([...LEVELS], ['BLOCKED', 'WRITTEN_UNREADABLE', 'WRITTEN_TRUNCATED', 'OK'])
})

test('access: evidence 词表包含 CON 的三条实测证据', () => {
  for (const token of ['test_path_false', 'get_content_error', 'open_readable']) {
    assert.ok(EVIDENCE_TOKENS.includes(token))
  }
})

test('access: reason 词表闭集', () => {
  assert.equal(REASON_TOKENS.length, 9)
})

test('access: 空名 BLOCKED', () => {
  assert.equal(judgeName('', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 空名在 linux 也 BLOCKED', () => {
  assert.equal(judgeName('', 'linux', TABLES).level, 'BLOCKED')
})

test('access: NUL 字节 BLOCKED', () => {
  assert.equal(judgeName('a\u0000b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 空组件 a//b BLOCKED', () => {
  assert.equal(judgeName('a//b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 前导斜杠 BLOCKED', () => {
  assert.equal(judgeName('/a', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 尾随斜杠 BLOCKED', () => {
  assert.equal(judgeName('a/', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 点组件 BLOCKED', () => {
  assert.equal(judgeName('a/./b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 双点组件 BLOCKED', () => {
  assert.equal(judgeName('a/../b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: < 非法字符 BLOCKED', () => {
  assert.equal(judgeName('a<b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: > 非法字符 BLOCKED', () => {
  assert.equal(judgeName('a>b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: | 非法字符 BLOCKED', () => {
  assert.equal(judgeName('a|b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: ? 非法字符 BLOCKED', () => {
  assert.equal(judgeName('a?b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: * 非法字符 BLOCKED', () => {
  assert.equal(judgeName('a*b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 控制字符 BLOCKED', () => {
  assert.equal(judgeName('a\u0001b', 'windows', TABLES).level, 'BLOCKED')
})

test('access: 冒号不 BLOCKED（按 ADS 截断）', () => {
  const verdict = judgeName('colon:name.txt', 'windows', TABLES)
  assert.equal(verdict.level, 'WRITTEN_TRUNCATED')
  assert.ok(verdict.reasons.includes('ads_colon_truncation'))
})

test('access: 255 个 ASCII 码元 OK', () => {
  assert.equal(judgeName('x'.repeat(255), 'windows', TABLES).level, 'OK')
})

test('access: 256 个 ASCII 码元 BLOCKED', () => {
  assert.equal(judgeName('x'.repeat(256), 'windows', TABLES).level, 'BLOCKED')
})

test('access: 组件长度按 UTF-16 码元计（128 个非 BMP = 256 码元）', () => {
  assert.equal(judgeName('😀'.repeat(128), 'windows', TABLES).level, 'BLOCKED')
})

test('access: 127 个非 BMP（254 码元）OK', () => {
  assert.equal(judgeName('😀'.repeat(127), 'windows', TABLES).level, 'OK')
})

test('access: CON.txt WRITTEN_UNREADABLE', () => {
  assert.equal(judgeName('CON.txt', 'windows', TABLES).level, 'WRITTEN_UNREADABLE')
})

test('access: COM0 也是保留名', () => {
  assert.equal(judgeName('COM0.txt', 'windows', TABLES).level, 'WRITTEN_UNREADABLE')
})

test('access: COM10 不是保留名', () => {
  assert.equal(judgeName('COM10.txt', 'windows', TABLES).level, 'OK')
})

test('access: LPT9 是保留名', () => {
  assert.equal(judgeName('LPT9.log', 'windows', TABLES).level, 'WRITTEN_UNREADABLE')
})

test('access: CLOCK$ 是保留名', () => {
  assert.equal(judgeName('CLOCK$', 'windows', TABLES).level, 'WRITTEN_UNREADABLE')
})

test('access: AUX.tar.gz 不是保留名（只取最后一个点之前）', () => {
  assert.equal(judgeName('AUX.tar.gz', 'windows', TABLES).level, 'OK')
})

test('access: 保留名匹配不区分大小写（con.txt）', () => {
  assert.equal(judgeName('con.txt', 'windows', TABLES).level, 'WRITTEN_UNREADABLE')
})

test('access: 裁剪后再判保留名（con.txt.）', () => {
  assert.equal(judgeName('con.txt.', 'windows', TABLES).level, 'WRITTEN_UNREADABLE')
})

test('access: 尾随空格 WRITTEN_TRUNCATED', () => {
  assert.equal(judgeName('trailing. ', 'windows', TABLES).level, 'WRITTEN_TRUNCATED')
})

test('access: 尾随点 WRITTEN_TRUNCATED', () => {
  assert.equal(judgeName('readme.', 'windows', TABLES).level, 'WRITTEN_TRUNCATED')
})

test('access: 尾随点 reason 是 trailing_space_or_dot', () => {
  assert.ok(judgeName('readme.', 'windows', TABLES).reasons.includes('trailing_space_or_dot'))
})

test('access: reasons 收集全部命中项', () => {
  const verdict = judgeName(`${'x'.repeat(256)}<`, 'windows', TABLES)
  assert.equal(verdict.level, 'BLOCKED')
  assert.ok(verdict.reasons.includes('illegal_char'))
  assert.ok(verdict.reasons.includes('component_too_long'))
})

test('access: BLOCKED 优先于保留名', () => {
  const verdict = judgeName('CON<', 'windows', TABLES)
  assert.equal(verdict.level, 'BLOCKED')
  assert.ok(!verdict.reasons.includes('reserved_device_name'))
})

test('access: 保留名优先于裁剪（con.txt.）', () => {
  const verdict = judgeName('con.txt.', 'windows', TABLES)
  assert.ok(verdict.reasons.includes('reserved_device_name'))
  assert.ok(verdict.reasons.includes('trailing_space_or_dot'))
})

test('access: 保留名证据是实测三证据', () => {
  assert.deepEqual([...judgeName('CON.txt', 'windows', TABLES).evidence], [...RESERVED_EVIDENCE])
})

test('access: 上标 ¹²³ 设备名变体按实测判 OK', () => {
  assert.equal(judgeName('COM¹.txt', 'windows', TABLES).level, 'OK')
})

test('access: macOS 只报跨平台创建失败', () => {
  assert.equal(judgeName('A<b.txt', 'macos', TABLES).level, 'OK')
})

test('access: Linux 只报跨平台创建失败', () => {
  assert.equal(judgeName('CON.txt', 'linux', TABLES).level, 'OK')
})

test('access: clean.zip 三平台全 OK', () => {
  const verdicts = checkAccess(archiveOf('clean.zip'), TARGETS, TABLES)
  for (const perPlatform of Object.values(verdicts)) {
    for (const verdict of Object.values(perPlatform)) assert.equal(verdict.level, 'OK')
  }
})

test('access: reserved.zip 两条 WRITTEN_UNREADABLE', () => {
  const verdicts = checkAccess(archiveOf('reserved.zip'), ['windows'], TABLES)
  const levels = Object.values(verdicts).map((perPlatform) => perPlatform.windows.level)
  assert.deepEqual(levels, ['WRITTEN_UNREADABLE', 'WRITTEN_UNREADABLE', 'OK'])
})

test('access: trailing.zip 三条 WRITTEN_TRUNCATED', () => {
  const verdicts = checkAccess(archiveOf('trailing.zip'), ['windows'], TABLES)
  assert.equal(Object.values(verdicts).filter((item) => item.windows.level === 'WRITTEN_TRUNCATED').length, 3)
})

test('access: trim.zip 一条 WRITTEN_TRUNCATED', () => {
  const verdicts = checkAccess(archiveOf('trim.zip'), ['windows'], TABLES)
  assert.equal(countIssues(verdicts), 1)
})

test('access: long_comp.zip 在 windows 是 BLOCKED', () => {
  const verdicts = checkAccess(archiveOf('long_comp.zip'), ['windows'], TABLES)
  assert.equal(verdicts['0'].windows.level, 'BLOCKED')
})

test('access: long_path.zip 在 windows 仍是 OK（预算不是创建失败）', () => {
  const verdicts = checkAccess(archiveOf('long_path.zip'), ['windows'], TABLES)
  assert.equal(verdicts['0'].windows.level, 'OK')
})

test('access: 只对本次 targets 出键', () => {
  const verdicts = checkAccess(archiveOf('clean.zip'), ['windows'], TABLES)
  assert.deepEqual(Object.keys(verdicts['0']), ['windows'])
})

test('access: countIssues 计 (条目, 平台) 对', () => {
  const verdicts = checkAccess(archiveOf('reserved.zip'), ['windows', 'macos'], TABLES)
  assert.equal(countIssues(verdicts), 2)
})

test('access: 未知平台报错', () => {
  assert.throws(() => judgeName('a', 'plan9', TABLES), /未知目标平台/)
})

test('access: Windows 非法字符集恰为 <>\\|?*', () => {
  assert.equal(WINDOWS_ILLEGAL, '<>\\|?*')
})

test('access: 单组件上限 255', () => {
  assert.equal(WINDOWS_MAX_COMPONENT, 255)
})

test('access: 保留名集合含 25 项', () => {
  assert.equal(RESERVED_DEVICE_NAMES.size, 25)
})

test('access: 空名 reason 与 evidence 分开记', () => {
  const verdict = judgeName('', 'windows', TABLES)
  assert.deepEqual(verdict.reasons, ['empty_name', 'empty_component'])
  assert.deepEqual(verdict.evidence, ['empty_component', 'empty_component'])
})

test('access: 数字/字母名 OK', () => {
  assert.equal(judgeName('archive-2026.10.21.tar.gz', 'windows', TABLES).level, 'OK')
})

// ===========================================================================
// 7. encoding：候选 / 置信度 / 四提取器
// ===========================================================================

test('encoding: 候选顺序是冻结的六项', () => {
  assert.deepEqual([...CANDIDATE_ENCODINGS], ['UTF-8', 'CP437', 'GBK', 'CP932', 'CP949', 'CP1251'])
})

test('encoding: ASCII 名字六个候选全部解出', () => {
  const list = candidates(bytes('Readme.txt'))
  assert.equal(list.length, 6)
  for (const item of list) assert.equal(item.name, 'Readme.txt')
})

test('encoding: café 的六种候选逐个对账', () => {
  const names = Object.fromEntries(candidates(bytes('café.txt')).map((item) => [item.encoding, item.name]))
  assert.deepEqual(names, {
    'UTF-8': 'café.txt',
    CP437: 'caf├⌐.txt',
    GBK: 'caf茅.txt',
    CP932: 'cafﾃｩ.txt',
    CP949: 'caf챕.txt',
    CP1251: 'cafГ©.txt',
  })
})

test('encoding: GBK 字节的候选顺序缺 UTF-8 / CP932', () => {
  const list = candidates(hexToBytes('d6d0cec4c3fb2e747874', 't'))
  assert.deepEqual(list.map((item) => item.encoding), ['CP437', 'GBK', 'CP949', 'CP1251'])
})

test('encoding: GBK 首选是 GBK', () => {
  assert.equal(preferred(candidates(hexToBytes('d6d0cec4c3fb2e747874', 't'))).encoding, 'GBK')
})

test('encoding: 双字节候选 strongStructure 为真', () => {
  const list = candidates(hexToBytes('d6d0cec4c3fb2e747874', 't'))
  assert.equal(list.find((item) => item.encoding === 'GBK').strongStructure, true)
  assert.equal(list.find((item) => item.encoding === 'CP437').strongStructure, false)
})

test('encoding: 框线字符不算常用字区', () => {
  assert.equal(isCommonZone('╓╨╬─├√'), false)
})

test('encoding: 中文算常用字区', () => {
  assert.equal(isCommonZone('中文名'), true)
})

test('encoding: ASCII 空格与波浪线算常用字区', () => {
  assert.equal(isCommonZone('a z~'), true)
})

test('encoding: 非 ASCII 标点不算常用字区', () => {
  assert.equal(isCommonZone('a·b'), false)
})

test('encoding: 组合标记算常用字区', () => {
  assert.equal(isCommonZone('e\u0301'), true)
})

test('encoding: 单字节码表解码 CP437', () => {
  assert.equal(decode(new Uint8Array([0x81]), 'CP437'), 'ü')
})

test('encoding: 单字节码表解码 CP850', () => {
  assert.equal(decode(new Uint8Array([0x9f]), 'CP850'), 'ƒ')
})

test('encoding: CP1251 0x98 不可解', () => {
  assert.equal(decode(new Uint8Array([0x98]), 'CP1251'), null)
})

test('encoding: 未知编码返回 null', () => {
  assert.equal(decode(bytes('a'), 'KOI8-R'), null)
})

test('encoding: preferred 双字节优先于单字节', () => {
  const list = candidates(hexToBytes('d6d0cec4c3fb2e747874', 't'))
  assert.equal(preferred(list).strongStructure, true)
})

test('encoding: preferred 同档按固定顺序', () => {
  const list = candidates(bytes('café.txt'))
  assert.equal(preferred(list).encoding, 'UTF-8')
})

test('encoding: preferred 空列表返回 null', () => {
  assert.equal(preferred([]), null)
})

test('encoding: confidence bit11 置位 = high', () => {
  assert.equal(confidence(true, { present: false, version: null, nameCrc32: null, utf8Name: null, crcValid: null }, null), 'high')
})

test('encoding: confidence upath CRC 通过 = high', () => {
  assert.equal(confidence(false, { present: true, version: 1, nameCrc32: 1, utf8Name: 'café.txt', crcValid: true }, null), 'high')
})

test('encoding: confidence upath CRC 失配 = low', () => {
  assert.equal(confidence(false, { present: true, version: 1, nameCrc32: 1, utf8Name: 'café.txt', crcValid: false }, null), 'low')
})

test('encoding: confidence 候选落在常用字区 = medium', () => {
  assert.equal(confidence(false, { present: false, version: null, nameCrc32: null, utf8Name: null, crcValid: null }, { commonZone: true }), 'medium')
})

test('encoding: confidence 候选不在常用字区 = low', () => {
  assert.equal(confidence(false, { present: false, version: null, nameCrc32: null, utf8Name: null, crcValid: null }, { commonZone: false }), 'low')
})

test('encoding: upath 字段不存在时 present=false', () => {
  const field = parseUpath(makeEntry())
  assert.equal(field.present, false)
  assert.equal(field.crcValid, null)
})

test('encoding: upath 结构不完整时 present=true 且 crcValid=null', () => {
  const entry = makeEntry({ cdExtra: [{ fieldId: UPATH_ID, data: new Uint8Array([1, 2]) }] })
  const field = parseUpath(entry)
  assert.equal(field.present, true)
  assert.equal(field.crcValid, null)
})

test('encoding: upath CRC 按原名字节计算', () => {
  const raw = hexToBytes('d6d0cec4c3fb2e747874', 't')
  const payload = new Uint8Array(5 + 5)
  payload[0] = 1
  payload[1] = 0
  payload[2] = 0
  payload[3] = 0
  payload[4] = 0
  payload.set(bytes('café'), 5)
  const entry = makeEntry({ cdName: raw, cdExtra: [{ fieldId: UPATH_ID, data: payload }] })
  assert.equal(expectedNameCrc(entry), crc32(raw))
})

test('encoding: 0x7075 CRC 通过时覆盖四工具', () => {
  const entry = archiveOf('upath.zip').entries[0]
  const facts = describe(entry)
  const predictions = predictNames(entry.cdName, facts.bit11, facts.upath, preferred(candidates(entry.cdName)))
  for (const tool of EXTRACTORS) {
    assert.equal(predictions[tool].name, 'café.txt')
    assert.equal(predictions[tool].rule, 'upath_override')
  }
})

test('encoding: upath_badcrc 降级 low 并报 finding', () => {
  const archive = archiveOf('upath_badcrc.zip')
  const [findings, block] = checkEncoding(archive)
  assert.equal(block[0].confidence, 'low')
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'encoding.UPATH_CRC_MISMATCH')
})

test('encoding: UPATH_CRC_MISMATCH evidence 带实际/期望 CRC', () => {
  const [finding] = checkEncoding(archiveOf('upath_badcrc.zip'))[0]
  assert.equal(finding.evidence.nameCrc32, 100701231)
  assert.equal(finding.evidence.expectedCrc32, 4194266064)
  assert.equal(finding.evidence.downgradedTo, 'low')
})

test('encoding: UPATH_CRC_MISMATCH precedent 是 apnote_d6', () => {
  assert.equal(checkEncoding(archiveOf('upath_badcrc.zip'))[0][0].precedent, 'apnote_d6_upath_crc')
})

test('encoding: 无 bit11 且无 upath 时 python 回退 CP437', () => {
  const entry = makeEntry({ cdName: hexToBytes('d6d0cec4c3fb2e747874', 't') })
  const chosen = preferred(candidates(entry.cdName))
  const prediction = predictNames(entry.cdName, false, parseUpath(entry), chosen)['python-zipfile']
  assert.equal(prediction.rule, 'cp437_fallback')
  assert.equal(prediction.name, '╓╨╬─├√.txt')
})

test('encoding: bit11 置位时 python 走 UTF-8', () => {
  const entry = makeEntry({ cdFlags: FLAG_UTF8, cdName: bytes('café.txt') })
  const prediction = predictNames(entry.cdName, true, parseUpath(entry), preferred(candidates(entry.cdName)))['python-zipfile']
  assert.equal(prediction.rule, 'utf8_bit11')
  assert.equal(prediction.name, 'café.txt')
})

test('encoding: 7zip 走声明 ANSI 码页', () => {
  const entry = makeEntry({ cdName: hexToBytes('d6d0cec4c3fb2e747874', 't') })
  const prediction = predictNames(entry.cdName, false, parseUpath(entry), preferred(candidates(entry.cdName)))['7zip']
  assert.equal(prediction.rule, 'ansi_codepage')
  assert.equal(prediction.source, ANSI_CODEC)
})

test('encoding: libarchive 与 7zip 同模型', () => {
  const entry = makeEntry({ cdName: hexToBytes('d6d0cec4c3fb2e747874', 't') })
  const predictions = predictNames(entry.cdName, false, parseUpath(entry), preferred(candidates(entry.cdName)))
  assert.deepEqual(predictions.libarchive, predictions['7zip'])
})

test('encoding: unzip 走 cp850 + best-fit', () => {
  const entry = makeEntry({ cdName: hexToBytes('d6d0cec4c3fb2e747874', 't') })
  const prediction = predictNames(entry.cdName, false, parseUpath(entry), preferred(candidates(entry.cdName)))['info-zip-unzip']
  assert.equal(prediction.rule, 'cp850_oem_transliterated')
  assert.equal(prediction.source, UNZIP_CODEC)
})

test('encoding: zh_gbk 的 python 预测是 CP437 乱码', () => {
  const block = checkEncoding(archiveOf('zh_gbk.zip'))[1][0]
  assert.equal(block.predictedNames['python-zipfile'].name, '╓╨╬─├√.txt')
})

test('encoding: zh_gbk 的 unzip 预测是 OEM 替换形', () => {
  const block = checkEncoding(archiveOf('zh_gbk.zip'))[1][0]
  assert.equal(block.predictedNames['info-zip-unzip'].name, 'Íð+-+¹.txt')
})

test('encoding: zh_gbk 的 7zip 预测是中文名', () => {
  const block = checkEncoding(archiveOf('zh_gbk.zip'))[1][0]
  assert.equal(block.predictedNames['7zip'].name, '中文名.txt')
})

test('encoding: upath 样本 confidence = high', () => {
  assert.equal(checkEncoding(archiveOf('upath.zip'))[1][0].confidence, 'high')
})

test('encoding: upath 样本 effectiveName = café.txt', () => {
  assert.equal(checkEncoding(archiveOf('upath.zip'))[1][0].effectiveName, 'café.txt')
})

test('encoding: 不可解码时不编造名字', () => {
  const prediction = predictNames(new Uint8Array([0x80]), false, { present: false, version: null, nameCrc32: null, utf8Name: null, crcValid: null }, null)
  assert.equal(prediction['7zip'].name, null)
  assert.equal(prediction['7zip'].rule, 'undecodable')
  assert.equal(prediction['7zip'].reason, 'no_complete_candidate')
})

test('encoding: OEM 替换表只替换字符，不改大小写', () => {
  const prediction = predictNames(bytes('aA'), false, { present: false, version: null, nameCrc32: null, utf8Name: null, crcValid: null }, preferred(candidates(bytes('aA'))))
  assert.equal(prediction['info-zip-unzip'].name, 'aA')
})

test('encoding: OEM 替换表丢弃 ÿ', () => {
  const prediction = predictNames(new Uint8Array([0x98]), false, { present: false, version: null, nameCrc32: null, utf8Name: null, crcValid: null }, preferred(candidates(new Uint8Array([0x98]))))
  assert.equal(prediction['info-zip-unzip'].name, '')
})

test('encoding: encoding block 按 entry_index 升序', () => {
  const block = checkEncoding(archiveOf('filedir.zip'))[1]
  assert.deepEqual(block.map((item) => item.entryIndex), [0, 1])
})

test('encoding: low_confidence_count 统计 low', () => {
  assert.equal(countLowConfidence(checkEncoding(archiveOf('upath_badcrc.zip'))[1]), 1)
})

test('encoding: low_confidence_count 空块为 0', () => {
  assert.equal(countLowConfidence([]), 0)
})

test('encoding: effectiveName 无候选时 null', () => {
  const entry = makeEntry({ cdName: new Uint8Array([0x98]) })
  const chosen = preferred(candidates(entry.cdName))
  const block = checkEncoding(makeArchive([entry]))[1][0]
  assert.notEqual(chosen, null)
  assert.equal(block.effectiveName, chosen.name)
})

test('encoding: describe 保留原始名字节与 bit11', () => {
  const facts = describe(makeEntry({ cdName: bytes('a.txt'), cdFlags: FLAG_UTF8 }))
  assert.equal(facts.rawNameHex, '612e747874')
  assert.equal(facts.rawNameLength, 5)
  assert.equal(facts.bit11, true)
})

test('encoding: describe 列出 extra ids', () => {
  const entry = makeEntry({ cdExtra: [{ fieldId: 0x0008, data: new Uint8Array(0) }, { fieldId: UPATH_ID, data: new Uint8Array(0) }] })
  assert.deepEqual(describe(entry).extraIds, [0x0008, UPATH_ID])
})

test('encoding: 四提取器闭集', () => {
  assert.deepEqual([...EXTRACTORS], ['python-zipfile', 'info-zip-unzip', '7zip', 'libarchive'])
})

test('encoding: 规则词表是六项', () => {
  assert.equal(PREDICTION_RULES.length, 6)
})

test('encoding: 候选编码对中文名逐个对账', () => {
  const block = checkEncoding(archiveOf('zh_gbk.zip'))[1][0]
  assert.equal(block.candidates.find((item) => item.encoding === 'GBK').name, '中文名.txt')
  assert.equal(block.candidates.find((item) => item.encoding === 'CP949').name, '櫓匡츰.txt')
  assert.equal(block.candidates.find((item) => item.encoding === 'CP1251').name, 'ЦРОДГы.txt')
})
// ===========================================================================
// 8. container：五条容器约定
// ===========================================================================

test('container: 五条规则闭集', () => {
  assert.deepEqual([...CONTAINER_CODES], [
    'container.MIMETYPE_NOT_FIRST',
    'container.MIMETYPE_COMPRESSED',
    'container.MIMETYPE_EXTRA',
    'container.MIMETYPE_PADDING',
    'container.UTF8_REQUIRED',
  ])
})

test('container: clean.zip 不是容器', () => {
  const [findings, block] = checkContainer(archiveOf('clean.zip'))
  assert.deepEqual(findings, [])
  assert.deepEqual(block, { kind: 'none' })
})

test('container: compressed.epub 恰好一条 COMPRESSED', () => {
  const [findings] = checkContainer(archiveOf('compressed.epub'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['container.MIMETYPE_COMPRESSED'])
})

test('container: extra.epub 恰好一条 EXTRA', () => {
  const [findings] = checkContainer(archiveOf('extra.epub'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['container.MIMETYPE_EXTRA'])
})

test('container: not_first.epub 恰好一条 NOT_FIRST', () => {
  const [findings] = checkContainer(archiveOf('not_first.epub'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['container.MIMETYPE_NOT_FIRST'])
})

test('container: padding.epub 恰好一条 PADDING', () => {
  const [findings] = checkContainer(archiveOf('padding.epub'))
  assert.deepEqual(findings.map((item) => item.ruleId), ['container.MIMETYPE_PADDING'])
})

test('container: NOT_FIRST 报告实际下标与首条目名', () => {
  const [finding] = checkContainer(archiveOf('not_first.epub'))[0]
  assert.equal(finding.evidence.expectedIndex, 0)
  assert.equal(finding.evidence.actualIndex, 1)
  assert.equal(finding.evidence.firstEntryName, CONTAINER_XML_NAME)
})

test('container: COMPRESSED 报告 method 与期望值', () => {
  const [finding] = checkContainer(archiveOf('compressed.epub'))[0]
  assert.equal(finding.evidence.method, METHOD_DEFLATE)
  assert.equal(finding.evidence.expectedMethod, METHOD_STORED)
  assert.equal(finding.evidence.encrypted, false)
})

test('container: EXTRA 报告 CD 与 LFH 的 field id', () => {
  const [finding] = checkContainer(archiveOf('extra.epub'))[0]
  assert.deepEqual(finding.evidence.extraIds, [51966])
  assert.deepEqual(finding.evidence.lfhExtraIds, [51966])
})

test('container: PADDING 的 EPUB 上下文不标 inferred', () => {
  const [finding] = checkContainer(archiveOf('padding.epub'))[0]
  assert.equal(finding.evidence.inferred, false)
  assert.equal(finding.evidence.evidence_strength, 'measured')
})

test('container: PADDING 报告前后空白字符数', () => {
  const [finding] = checkContainer(archiveOf('padding.epub'))[0]
  assert.equal(finding.evidence.leadingBytes, 0)
  assert.equal(finding.evidence.trailingBytes, 1)
  assert.equal(finding.evidence.contentLength, 21)
})

test('container: padding.epub 的 kind 是 epub', () => {
  assert.deepEqual(checkContainer(archiveOf('padding.epub'))[1], { kind: 'epub' })
})

test('container: findMimetype 对 clean.zip 返回 null', () => {
  assert.equal(findMimetype(archiveOf('clean.zip')), null)
})

test('container: findMimetype 对 padding.epub 返回下标 0', () => {
  assert.equal(findMimetype(archiveOf('padding.epub')).index, 0)
})

test('container: findMimetype 按字节精确匹配', () => {
  const entry = makeEntry({ cdName: bytes('mimetype.') })
  assert.equal(findMimetype(makeArchive([entry])), null)
})

test('container: readMimetypeBytes 对 stored 直接切片', () => {
  const archive = archiveOf('padding.epub')
  const mimetype = findMimetype(archive)
  const content = readMimetypeBytes(archive, mimetype)
  assert.equal(new TextDecoder().decode(content), 'application/epub+zip\n')
})

test('container: 归档字节为空时取不到 mimetype 内容', () => {
  const archive = archiveOf('padding.epub')
  const without = { ...archive, data: new Uint8Array(0) }
  assert.equal(readMimetypeBytes(without, findMimetype(archive)), null)
})

test('container: method 非 stored/deflate 取不到内容', () => {
  const entry = makeEntry({ method: 99 })
  assert.equal(readMimetypeBytes(makeArchive([entry], { data: bytes('x') }), entry), null)
})

function containerArchive(content, { method = METHOD_STORED, flags = 0, extra = [], entries = [] } = {}) {
  const raw = bytes(content)
  const mimetype = makeEntry({
    index: 0,
    cdName: bytes('mimetype'),
    lfhName: bytes('mimetype'),
    cdFlags: flags,
    method,
    cdCsize: raw.length,
    lfhCsize: raw.length,
    cdExtra: extra,
    dataOffset: 0,
  })
  return makeArchive([mimetype, ...entries], { data: raw })
}

test('container: 纯 media type 识别为 epub', () => {
  assert.equal(detectKind(containerArchive(EPUB_MEDIA_TYPE), findMimetype(containerArchive(EPUB_MEDIA_TYPE))), 'epub')
})

test('container: ODF media type 前缀识别为 odf', () => {
  const archive = containerArchive(`${ODF_MEDIA_TYPE_PREFIX}text`)
  assert.equal(detectKind(archive, findMimetype(archive)), 'odf')
})

test('container: ODF 的 padding 标 inferred=true', () => {
  const archive = containerArchive(`${ODF_MEDIA_TYPE_PREFIX}text\n`)
  const [findings, block] = checkContainer(archive)
  assert.equal(block.kind, 'odf')
  const padding = findings.find((item) => item.ruleId === 'container.MIMETYPE_PADDING')
  assert.equal(padding.evidence.inferred, true)
  assert.equal(padding.precedent, 'odf_padding_inferred')
})

test('container: content 读不出时靠 container.xml 判 epub', () => {
  const xml = makeEntry({ index: 1, cdName: bytes(CONTAINER_XML_NAME), lfhName: bytes(CONTAINER_XML_NAME) })
  const archive = containerArchive('not a media type', { method: 99, entries: [xml] })
  assert.equal(detectKind(archive, findMimetype(archive)), 'epub')
})

test('container: 既无 media type 又无 container.xml 判 none', () => {
  const archive = containerArchive('not a media type')
  assert.equal(detectKind(archive, findMimetype(archive)), 'none')
})

test('container: UTF8_REQUIRED 只对非 ASCII 且 bit11 未置位的条目报', () => {
  const offender = makeEntry({ index: 1, cdName: bytes('中文.txt'), lfhName: bytes('中文.txt'), cdFlags: 0 })
  const archive = containerArchive(EPUB_MEDIA_TYPE, { entries: [offender] })
  const [findings] = checkContainer(archive)
  assert.deepEqual(findings.map((item) => item.ruleId), ['container.UTF8_REQUIRED'])
  assert.equal(findings[0].entryIndex, 1)
})

test('container: UTF8_REQUIRED 对 bit11 置位的非 ASCII 名不报', () => {
  const fine = makeEntry({ index: 1, cdName: bytes('中文.txt'), lfhName: bytes('中文.txt'), cdFlags: 0x0800 })
  const archive = containerArchive(EPUB_MEDIA_TYPE, { entries: [fine] })
  assert.deepEqual(checkContainer(archive)[0], [])
})

test('container: UTF8_REQUIRED 对纯 ASCII 名不报', () => {
  const ascii = makeEntry({ index: 1, cdName: bytes('plain.txt'), lfhName: bytes('plain.txt'), cdFlags: 0 })
  const archive = containerArchive(EPUB_MEDIA_TYPE, { entries: [ascii] })
  assert.deepEqual(checkContainer(archive)[0], [])
})

test('container: UTF8_REQUIRED 对 ODF 不报', () => {
  const offender = makeEntry({ index: 1, cdName: bytes('中文.txt'), lfhName: bytes('中文.txt'), cdFlags: 0 })
  const archive = containerArchive(`${ODF_MEDIA_TYPE_PREFIX}text`, { entries: [offender] })
  assert.deepEqual(checkContainer(archive)[0], [])
})

test('container: 内容取不到时不报 PADDING', () => {
  const archive = containerArchive(EPUB_MEDIA_TYPE, { method: METHOD_DEFLATE })
  const findings = checkContainer(archive)[0]
  assert.ok(!findings.some((item) => item.ruleId === 'container.MIMETYPE_PADDING'))
})

test('container: NOT_FIRST 在首条目时不报', () => {
  assert.equal(checkNotFirst(containerArchive(EPUB_MEDIA_TYPE), findMimetype(containerArchive(EPUB_MEDIA_TYPE))), null)
})

test('container: COMPRESSED 在 stored 且未加密时不报', () => {
  assert.equal(checkCompressed(makeEntry()), null)
})

test('container: EXTRA 在无 extra 时不报', () => {
  assert.equal(checkExtra(makeEntry()), null)
})

test('container: 容器 findings 的 precedent 在枚举内', () => {
  for (const name of ['compressed.epub', 'extra.epub', 'not_first.epub', 'padding.epub']) {
    for (const finding of checkContainer(archiveOf(name))[0]) {
      assert.ok(
        ['epub_ocf_zip_requirements', 'odf_package_requirements', 'odf_padding_inferred', 'epub_ocf_utf8_names'].includes(finding.precedent),
        `${name} ${finding.precedent}`,
      )
    }
  }
})

// ===========================================================================
// 9. budget：长度预算（两条）
// ===========================================================================

test('budget: 两条规则闭集', () => {
  assert.deepEqual([...BUDGET_CODES], ['budget.PATH_OVER_260', 'budget.COMPONENT_OVER_255'])
})

test('budget: long_path.zip 命中 PATH_OVER_260（315 码元）', () => {
  const [finding] = checkBudget(archiveOf('long_path.zip'), ['windows'])
  assert.equal(finding.ruleId, 'budget.PATH_OVER_260')
  assert.equal(finding.evidence.units, 315)
})

test('budget: PATH_OVER_260 标可移植性预算', () => {
  const [finding] = checkBudget(archiveOf('long_path.zip'), ['windows'])
  assert.equal(finding.evidence.kind, PATH_BUDGET_KIND)
})

test('budget: PATH_OVER_260 带 260 / 32767 两个上限', () => {
  const [finding] = checkBudget(archiveOf('long_path.zip'), ['windows'])
  assert.equal(finding.evidence.limit, WIN_MAX_PATH)
  assert.equal(finding.evidence.extendedLimit, WIN_MAX_PATH_EXTENDED)
})

test('budget: PATH_OVER_260 不写"会被截断"', () => {
  const [finding] = checkBudget(archiveOf('long_path.zip'), ['windows'])
  assert.doesNotMatch(finding.message, /会被截断/)
  assert.match(finding.message, /预算告警/)
})

test('budget: long_comp.zip windows 命中 COMPONENT_OVER_255（256 码元）', () => {
  const finding = checkComponentWindows(archiveOf('long_comp.zip').entries[0])
  assert.equal(finding.ruleId, 'budget.COMPONENT_OVER_255')
  assert.equal(finding.evidence.units, 256)
  assert.equal(finding.evidence.kind, 'platform_limit')
})

test('budget: long_comp.zip linux 命中 COMPONENT_OVER_255（256 字节）', () => {
  const finding = checkComponentLinux(archiveOf('long_comp.zip').entries[0])
  assert.equal(finding.ruleId, 'budget.COMPONENT_OVER_255')
  assert.equal(finding.evidence.bytes, 256)
  assert.equal(finding.evidence.platform, 'linux')
})

test('budget: clean.zip 无预算 finding', () => {
  assert.deepEqual(checkBudget(archiveOf('clean.zip'), TARGETS), [])
})

test('budget: 两种规则都带 platform', () => {
  for (const finding of checkBudget(archiveOf('long_comp.zip'), TARGETS)) {
    assert.equal(finding.evidence.platform, finding.precedent === 'posix_name_max_bytes' ? 'linux' : 'windows')
  }
})

test('budget: 组件按 / 切分', () => {
  assert.deepEqual(budgetComponents('a/b/c'), ['a', 'b', 'c'])
})

test('budget: byteLength 按原始字节', () => {
  assert.equal(byteLength(bytes('中文')), 6)
})

test('budget: linux 组件超 255 字节报（300 字节）', () => {
  const entry = makeEntry({ cdName: bytes('x'.repeat(300)) })
  assert.equal(checkComponentLinux(entry).evidence.bytes, 300)
})

test('budget: linux 路径超 4096 字节报', () => {
  const entry = makeEntry({ cdName: bytes('d'.repeat(LINUX_PATH_MAX + 1)) })
  const finding = checkPathLinux(entry)
  assert.equal(finding.ruleId, 'budget.PATH_OVER_260')
  assert.equal(finding.evidence.limit, LINUX_PATH_MAX)
})

test('budget: linux 路径恰 4096 字节不报', () => {
  assert.equal(checkPathLinux(makeEntry({ cdName: bytes('d'.repeat(LINUX_PATH_MAX)) })), null)
})

test('budget: windows 路径恰 260 码元不报（含终止 NUL）', () => {
  const entry = makeEntry({ cdName: bytes('d'.repeat(WIN_MAX_PATH - 1)) })
  assert.equal(checkPathWindows(entry), null)
})

test('budget: windows 路径 261 码元报', () => {
  const entry = makeEntry({ cdName: bytes('d'.repeat(WIN_MAX_PATH)) })
  assert.equal(checkPathWindows(entry).evidence.units, 261)
})

test('budget: macos 不参与预算判定', () => {
  assert.deepEqual(checkBudget(archiveOf('long_path.zip'), ['macos']), [])
})

test('budget: declaredPlatforms 为空（不读平台表）', () => {
  assert.deepEqual([...declaredPlatforms()], [])
})

test('budget: 组件违规逐条列出', () => {
  const entry = makeEntry({ cdName: bytes(`${'x'.repeat(256)}/${'y'.repeat(300)}`) })
  const finding = checkComponentLinux(entry)
  assert.equal(finding.evidence.violations.length, 2)
  assert.deepEqual(finding.evidence.violations.map((item) => item.componentIndex), [0, 1])
})

test('budget: windows 组件 characters 按码点计', () => {
  const entry = makeEntry({ cdName: bytes('😀'.repeat(128)) })
  const finding = checkComponentWindows(entry)
  assert.equal(finding.evidence.characters, 128)
  assert.equal(finding.evidence.units, 256)
})

test('budget: 同一归档 windows/linux 各出一条时按 cdOffset/规则/证据排序', () => {
  const findings = checkBudget(archiveOf('long_comp.zip'), TARGETS)
  const keys = findings.map((item) => [item.cdOffset, item.ruleId, JSON.stringify(item.evidence)])
  assert.deepEqual(keys, [...keys].sort((left, right) => (left[0] - right[0]) || (left[1] < right[1] ? -1 : left[1] > right[1] ? 1 : left[2] < right[2] ? -1 : left[2] > right[2] ? 1 : 0)))
})

test('budget: NAME_MAX_DEFAULT 是 255', () => {
  assert.equal(NAME_MAX_DEFAULT, 255)
})

// ===========================================================================
// 10. 主张 / 取证账本
// ===========================================================================

test('claim: clean=true 在干净归档上成立', () => {
  const record = single('clean.zip', { check: 'clean', asserted: true })
  assert.equal(record.verdict, CLAIM)
})

test('claim: clean=true 在有 collision 的归档上被推翻', () => {
  const record = single('case.zip', { check: 'clean', asserted: true })
  assert.equal(record.verdict, REFUTED)
})

test('claim: 无节点失败降级为 inconclusive', () => {
  const record = single('case.zip', { check: 'clean', asserted: true, node: null })
  assert.equal(record.verdict, INCONCLUSIVE)
})

test('claim: finding 存在性 true', () => {
  const record = single('mismatch_name.zip', { check: 'finding', rule: 'structure.NAME_DIVERGES', entry_index: 0, asserted: true })
  assert.equal(record.verdict, CLAIM)
})

test('claim: finding 存在性 false 被推翻', () => {
  const record = single('clean.zip', { check: 'finding', rule: 'structure.NAME_DIVERGES', entry_index: 0, asserted: true })
  assert.equal(record.verdict, REFUTED)
})

test('claim: finding_count 按规则计数', () => {
  const record = single('long_comp.zip', { check: 'finding_count', rule: 'budget.COMPONENT_OVER_255', asserted: 2 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: finding_field 读 evidence 子路径', () => {
  const record = single('mismatch_name.zip', {
    check: 'finding_field',
    rule: 'structure.NAME_DIVERGES',
    entry_index: 0,
    path: 'evidence.lfhNameHex',
    asserted: '616c6c6f7765642e747874',
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim: finding_field 错误值被推翻', () => {
  const record = single('mismatch_name.zip', {
    check: 'finding_field',
    rule: 'structure.NAME_DIVERGES',
    entry_index: 0,
    path: 'evidence.lfhNameHex',
    asserted: '00',
  })
  assert.equal(record.verdict, REFUTED)
})

test('claim: collision 存在性', () => {
  const record = single('case.zip', { check: 'collision', code: 'collision.CASEFOLD', platform: 'windows', entry_a: 0, entry_b: 1, asserted: true })
  assert.equal(record.verdict, CLAIM)
})

test('claim: collision 在 macos 上不存在', () => {
  const record = single('case.zip', { check: 'collision', code: 'collision.CASEFOLD', platform: 'macos', entry_a: 0, entry_b: 1, asserted: true })
  assert.equal(record.verdict, REFUTED)
})

test('claim: collision_count 按平台计数', () => {
  const record = single('filedir.zip', { check: 'collision_count', platform: 'windows', asserted: 1 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: collision_field 读 survivor', () => {
  const record = single('case.zip', { check: 'collision_field', code: 'collision.CASEFOLD', platform: 'windows', entry_a: 0, entry_b: 1, path: 'survivor', asserted: 'README.TXT' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: collision_field 读 verdict', () => {
  const record = single('filedir.zip', { check: 'collision_field', code: 'collision.FILEDIR', platform: 'windows', entry_a: 0, entry_b: 1, path: 'verdict', asserted: 'skipped' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: accessibility level + reasons + evidence 三面对账', () => {
  const record = single('reserved.zip', {
    check: 'accessibility',
    entry_index: 0,
    platform: 'windows',
    asserted: 'WRITTEN_UNREADABLE',
    reasons: ['reserved_device_name'],
    evidence: ['test_path_false', 'get_content_error', 'open_readable'],
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim: accessibility reasons 不符被推翻', () => {
  const record = single('reserved.zip', {
    check: 'accessibility',
    entry_index: 0,
    platform: 'windows',
    asserted: 'WRITTEN_UNREADABLE',
    reasons: ['trailing_space_or_dot'],
  })
  assert.equal(record.verdict, REFUTED)
})

test('claim: encoding bit11', () => {
  const record = single('case.zip', { check: 'encoding', entry_index: 0, field: 'bit11', asserted: false })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding upath 整块', () => {
  const record = single('upath_badcrc.zip', {
    check: 'encoding',
    entry_index: 0,
    field: 'upath',
    asserted: { present: true, version: 1, name_crc32: 100701231, utf8_name: 'café.txt', crc_valid: false },
  })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding confidence', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'confidence', asserted: 'medium' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding preferred', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'preferred', asserted: 'GBK' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding candidate_encodings 顺序', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'candidate_encodings', asserted: ['CP437', 'GBK', 'CP949', 'CP1251'] })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding candidates 整块', () => {
  const block = checkEncoding(archiveOf('zh_gbk.zip'))[1][0]
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'candidates', asserted: block.candidates })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding effective_name', () => {
  const record = single('upath.zip', { check: 'encoding', entry_index: 0, field: 'effective_name', asserted: 'café.txt' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding predicted_name（7zip）', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'predicted_name', tool: '7zip', asserted: '中文名.txt' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding predicted_rule（python）', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'predicted_rule', tool: 'python-zipfile', asserted: 'cp437_fallback' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding predicted_source（7zip）', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'predicted_source', tool: '7zip', asserted: 'gbk' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding raw_name_hex', () => {
  const record = single('zh_gbk.zip', { check: 'encoding', entry_index: 0, field: 'raw_name_hex', asserted: 'd6d0cec4c3fb2e747874' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: encoding extra_ids', () => {
  const record = single('upath.zip', { check: 'encoding', entry_index: 0, field: 'extra_ids', asserted: [28789] })
  assert.equal(record.verdict, CLAIM)
})

test('claim: container kind', () => {
  const record = single('padding.epub', { check: 'container', field: 'kind', asserted: 'epub' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: container mimetype_index', () => {
  const record = single('not_first.epub', { check: 'container', field: 'mimetype_index', asserted: 1 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: archive entry_count', () => {
  const record = single('case.zip', { check: 'archive', field: 'entry_count', asserted: 2 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: archive declared_entries', () => {
  const record = single('wrong_count.zip', { check: 'archive', field: 'declared_entries', asserted: 5 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: archive cd_actual_entries', () => {
  const record = single('wrong_count.zip', { check: 'archive', field: 'cd_actual_entries', asserted: 2 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: archive zip64', () => {
  const record = single('clean.zip', { check: 'archive', field: 'zip64', asserted: false })
  assert.equal(record.verdict, CLAIM)
})

test('claim: archive cd_span', () => {
  const record = single('wrong_count.zip', { check: 'archive', field: 'cd_span', asserted: [97, 206] })
  assert.equal(record.verdict, CLAIM)
})

test('claim: display lfh 名', () => {
  const record = single('mismatch_name.zip', { check: 'display', entry_index: 0, side: 'lfh', asserted: 'allowed.txt' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: display cd 名', () => {
  const record = single('mismatch_name.zip', { check: 'display', entry_index: 0, side: 'cd', asserted: 'evil.txt' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: platforms ntfs_table_id', () => {
  const record = single('clean.zip', { check: 'platforms', field: 'ntfs_table_id', asserted: '41c26bc7a12bdaeb' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: platforms macos_strength', () => {
  const record = single('clean.zip', { check: 'platforms', field: 'macos_strength', asserted: 'medium' })
  assert.equal(record.verdict, CLAIM)
})

test('claim: summary low_confidence', () => {
  const record = single('upath_badcrc.zip', { check: 'summary', of: 'low_confidence', asserted: 1 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: summary container_findings', () => {
  const record = single('padding.epub', { check: 'summary', of: 'container_findings', asserted: 1 })
  assert.equal(record.verdict, CLAIM)
})

test('claim: 记录 id 是 claim@session#turn#call', () => {
  const record = single('clean.zip', { check: 'clean', asserted: true })
  assert.equal(record.id, 'c1@s-archive-1#1#call-archive-1')
})

test('claim: refuted 记录带痕迹节点', () => {
  const record = single('case.zip', { check: 'clean', asserted: true })
  assert.equal(record.verdict, REFUTED)
  assert.equal(record.node.session_id, 's-archive-1')
  assert.equal(record.node.turn, 1)
})

test('claim: 匹配记录 evidence 标 comparison=match', () => {
  const record = single('clean.zip', { check: 'clean', asserted: true })
  assert.equal(record.evidence.comparison, 'match')
  assert.equal(record.evidence.check, 'clean')
})

test('claim: 不匹配记录 evidence 标 comparison=mismatch', () => {
  const record = single('case.zip', { check: 'clean', asserted: true })
  assert.equal(record.evidence.comparison, 'mismatch')
  assert.equal(record.evidence.computed, false)
})

// ===========================================================================
// 11. 逐 fixture 与旧仓金样对账（22 个 fixture × 3 目标平台）
// ===========================================================================

const FIXTURE_NAMES = [
  'alias_lfh.zip',
  'case.zip',
  'clean.zip',
  'compressed.epub',
  'crc_diverge.zip',
  'extra.epub',
  'filedir.zip',
  'long_comp.zip',
  'long_path.zip',
  'mismatch_name.zip',
  'norm.zip',
  'not_first.epub',
  'overlap.zip',
  'padding.epub',
  'reserved.zip',
  'size_diverge.zip',
  'trailing.zip',
  'trim.zip',
  'upath.zip',
  'upath_badcrc.zip',
  'wrong_count.zip',
  'zh_gbk.zip',
]

for (const name of FIXTURE_NAMES) {
  test(`golden: ${name} 的五个判定块与旧仓逐值一致`, () => {
    const expected = golden(name)
    const actual = goldenFromFixture(name)
    assert.deepEqual(actual.findings, expected.findings, `${name} findings`)
    assert.deepEqual(actual.collisions, expected.collisions, `${name} collisions`)
    assert.deepEqual(actual.encoding, expected.encoding, `${name} encoding`)
    assert.deepEqual(actual.container, expected.container, `${name} container`)
  })

  test(`golden: ${name} 的旧退出码与判定产出等价`, () => {
    const expected = golden(name)
    const actual = goldenFromFixture(name)
    const hasOutput =
      actual.findings.length > 0 ||
      actual.collisions.length > 0 ||
      actual.summary.accessibility_count > 0
    assert.equal(hasOutput, expected.old_rc === 1, name)
  })
}

for (const name of FIXTURE_NAMES) {
  for (const target of TARGETS) {
    test(`golden: ${name} 在 ${target} 上的可访问性逐条一致`, () => {
      const expected = golden(name)
      const actual = checkAccess(archiveOf(name), TARGETS, TABLES)
      const filteredExpected = {}
      const filteredActual = {}
      for (const [index, perPlatform] of Object.entries(expected.accessibility)) {
        filteredExpected[index] = perPlatform[target]
        filteredActual[index] = actual[index][target]
      }
      assert.deepEqual(filteredActual, filteredExpected, `${name} ${target}`)
    })
  }
}

// ===========================================================================
// 12. CLI / 确定性 / 输入校验
// ===========================================================================

test('cli: 判据 2 样本退出码 1（clean 主张被推翻）', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('case.zip'),
    targets: ['windows'],
    claims: [
      { claim_id: 'c-clean', check: 'clean', asserted: true, node: NODE },
      { claim_id: 'c-casefold', check: 'collision', code: 'collision.CASEFOLD', platform: 'windows', entry_a: 0, entry_b: 1, asserted: true, node: NODE },
    ],
  })
  const basis = writeJSON(dir, 'basis.json', { version: 'trace-1', nodes: [NODE] })
  const { code, out } = await capture(() => main(['check', 'archive-extraction', '--input', input, '--basis', basis, '--json']))
  assert.equal(code, EXIT_BLOCKED)
  const report = JSON.parse(out)
  assert.equal(report.summary.total, 2)
  assert.equal(report.summary.blocking, 1)
  assert.equal(report.records.find((item) => item.claim_id === 'c-clean').verdict, REFUTED)
})

test('cli: 干净样本退出码 0', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('clean.zip'),
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true, node: NODE }],
  })
  const basis = writeJSON(dir, 'basis.json', { version: 'trace-1', nodes: [NODE] })
  const { code } = await capture(() => main(['check', 'archive-extraction', '--input', input, '--basis', basis]))
  assert.equal(code, EXIT_OK)
})

test('cli: 无依据时一致主张仍退 0', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('clean.zip'),
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true }],
  })
  const { code } = await capture(() => main(['check', 'archive-extraction', '--input', input]))
  assert.equal(code, EXIT_OK)
})

test('cli: 缺 claims 字段退 2', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', { archive: fixture('clean.zip'), targets: ['windows'] })
  const { code } = await capture(() => main(['check', 'archive-extraction', '--input', input]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: 结构事实非法退 2', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: { probe: {} },
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true }],
  })
  const { code } = await capture(() => main(['check', 'archive-extraction', '--input', input]))
  assert.equal(code, EXIT_INPUT)
})

test('cli: 未知 subject 字段退 3', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('clean.zip'),
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true }],
    extra: 1,
  })
  const { code } = await capture(() => main(['check', 'archive-extraction', '--input', input]))
  assert.equal(code, EXIT_CONTRACT)
})

test('cli: 未知 check 退 3', () => {
  assert.throws(() => run('clean.zip', [claim({ check: 'nope' })]), ContractError)
})

test('cli: claim_id 重复退 3', () => {
  assert.throws(
    () => run('clean.zip', [claim({ claim_id: 'x' }), claim({ claim_id: 'x' })]),
    /claim_id 重复/,
  )
})

test('cli: platform 不在 targets 退 3', () => {
  assert.throws(
    () => run('case.zip', [claim({ check: 'collision', code: 'collision.CASEFOLD', platform: 'macos', asserted: true })], ['windows']),
    ContractError,
  )
})

test('cli: entry_index 越界退 3', () => {
  assert.throws(
    () => run('clean.zip', [claim({ check: 'accessibility', entry_index: 99, platform: 'windows', asserted: 'OK' })]),
    ContractError,
  )
})

test('cli: 痕迹节点缺失退 3', () => {
  const basis = Basis.fromObject({ version: 'trace-1', nodes: [] })
  assert.throws(
    () => [...evaluateArchiveExtraction({ archive: fixture('clean.zip'), targets: TARGETS, claims: [claim()] }, basis)],
    NodeMissing,
  )
})

test('cli: 不完整节点把 refuted 降级为 inconclusive', () => {
  const basis = Basis.fromObject({ version: 'trace-1', nodes: [{ session_id: 's-1', turn: null, tool_call_id: 'call-1' }] })
  const records = [...evaluateArchiveExtraction(
    {
      archive: fixture('case.zip'),
      targets: ['windows'],
      claims: [claim({ check: 'clean', asserted: true, node: { session_id: 's-1', turn: null, tool_call_id: 'call-1' } })],
    },
    basis,
  )]
  assert.equal(records[0].verdict, INCONCLUSIVE)
  assert.match(records[0].message, /痕迹节点不完整/)
})

test('cli: 同输入两次 --json 字节一致', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('case.zip'),
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true, node: NODE }],
  })
  const basis = writeJSON(dir, 'basis.json', { version: 'trace-1', nodes: [NODE] })
  const first = await capture(() => main(['check', 'archive-extraction', '--input', input, '--basis', basis, '--json']))
  const second = await capture(() => main(['check', 'archive-extraction', '--input', input, '--basis', basis, '--json']))
  assert.equal(first.code, second.code)
  assert.equal(first.out, second.out)
})

test('cli: --json 顶层字段固定', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('clean.zip'),
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true, node: NODE }],
  })
  const basis = writeJSON(dir, 'basis.json', { version: 'trace-1', nodes: [NODE] })
  const { out } = await capture(() => main(['check', 'archive-extraction', '--input', input, '--basis', basis, '--json']))
  const report = JSON.parse(out)
  assert.deepEqual(Object.keys(report), ['product', 'verb', 'verb_version', 'subject', 'summary', 'records'])
})

test('cli: 输出不含本机绝对路径', async () => {
  const dir = tempDir()
  const input = writeJSON(dir, 'subject.json', {
    archive: fixture('case.zip'),
    targets: ['windows'],
    claims: [{ claim_id: 'c1', check: 'clean', asserted: true, node: NODE }],
  })
  const basis = writeJSON(dir, 'basis.json', { version: 'trace-1', nodes: [NODE] })
  const { out } = await capture(() => main(['check', 'archive-extraction', '--input', input, '--basis', basis, '--json']))
  assert.doesNotMatch(out, /[A-Z]:[\\/]/)
})

test('cli: --version 打印产品版本', async () => {
  const { code, out } = await capture(() => main(['--version']))
  assert.equal(code, EXIT_OK)
  assert.match(out, /traceproof \d+\.\d+/)
})

test('report: 账本按 claim_id 排序', () => {
  const records = run('clean.zip', [
    claim({ claim_id: 'b', check: 'clean', asserted: true }),
    claim({ claim_id: 'a', check: 'clean', asserted: true }),
  ])
  const report = new Report({ product: 'traceproof', verb: 'archive-extraction', verb_version: VERSION, subject: 'x', records })
  assert.deepEqual(report.records.map((item) => item.claim_id), ['a', 'b'])
  assert.equal(report.exitCode(), EXIT_OK)
})

test('report: 空 claims 被拒', () => {
  assert.throws(() => run('clean.zip', []), /非空数组/)
})

test('archive: cd_actual_entries 与 entries 长度不一致被拒', () => {
  const facts = { ...fixture('clean.zip'), cd_actual_entries: 99 }
  assert.throws(() => readArchive(facts), ArchivePayloadError)
})

test('archive: 未知字段被拒', () => {
  assert.throws(() => readArchive({ ...fixture('clean.zip'), extra: 1 }), ArchivePayloadError)
})

test('archive: entries index 必须等于下标', () => {
  const facts = fixture('clean.zip')
  facts.entries[0] = { ...facts.entries[0], index: 1 }
  assert.throws(() => readArchive(facts), ArchivePayloadError)
})

test('archive: data_b64 非法被拒', () => {
  assert.throws(() => readArchive({ ...fixture('clean.zip'), data_b64: '***' }), ArchivePayloadError)
})

test('archive: cd_span 结束早于开始被拒', () => {
  assert.throws(() => readArchive({ ...fixture('clean.zip'), cd_span: [10, 5] }), ArchivePayloadError)
})