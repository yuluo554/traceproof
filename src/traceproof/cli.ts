/**
 * traceproof 唯一入口：`traceproof <subcommand> ...`。
 *
 * 子命令只有两个（器官不得自带 CLI / 配置文件 / 输出排版）：
 *
 *   traceproof list [--json]
 *   traceproof check <slug> --input <file|-> [--basis <file>] [--json]
 *
 * 退出码见 `core/ledger.ts`：0 无阻断 / 1 有阻断 / 2 输入不合法 / 3 契约违约。
 *
 * 文件读取只在这里发生：内核（core/*）只接收已解析对象，不碰路径。
 */

import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import { parseArgs } from 'node:util'

import { PRODUCT, VERSION } from './index.js'
import { Basis, NodeMissing } from './core/trace-index.js'
import { ContractError, EXIT_CONTRACT, EXIT_INPUT, EXIT_OK, Report } from './core/ledger.js'
import { allVerbs, get, VerbMissing, verbToJSON } from './core/registry.js'
import { loadBuiltin } from './verbs/index.js'

const HELP = `traceproof —— 取证账本引擎

用法：
  traceproof list [--json]                              列出器官
  traceproof check <slug> --input <file|-> [--basis <f>] [--json]
  traceproof --version

退出码：0 无阻断 / 1 有阻断（refuted）/ 2 输入不合法 / 3 契约违约`

function readJSON(source: string): unknown {
  const text = source === '-' ? readFileSync(0, 'utf8') : readFileSync(source, 'utf8')
  return JSON.parse(text)
}

function subjectLabel(source: string): string {
  return source === '-' ? '<stdin>' : basename(source)
}

export async function main(argv: readonly string[]): Promise<number> {
  await loadBuiltin()

  if (argv.length === 0) {
    console.log(HELP)
    return EXIT_OK
  }

  const command = argv[0]
  const rest = argv.slice(1)

  if (command === '--version' || command === '-v') {
    console.log(`${PRODUCT} ${VERSION}`)
    return EXIT_OK
  }
  if (command === '--help' || command === '-h') {
    console.log(HELP)
    return EXIT_OK
  }
  if (command === 'list') {
    return cmdList(rest)
  }
  if (command === 'check') {
    return cmdCheck(rest)
  }

  process.stderr.write(`未知子命令：${command}\n\n${HELP}\n`)
  return EXIT_INPUT
}

function cmdList(args: readonly string[]): number {
  const asJSON = args.includes('--json')
  const verbs = allVerbs()
  if (asJSON) {
    console.log(JSON.stringify(verbs.map(verbToJSON), null, 2))
    return EXIT_OK
  }
  if (verbs.length === 0) {
    console.log('（未注册任何器官）')
    return EXIT_OK
  }
  for (const verb of verbs) {
    console.log(`${verb.slug.padEnd(28)} ${verb.version.padEnd(10)} ${verb.summary}`)
  }
  return EXIT_OK
}

function cmdCheck(args: readonly string[]): number {
  let slug: string | undefined
  let input: string | undefined
  let basisPath: string | undefined
  let asJSON = false

  try {
    const parsed = parseArgs({
      args: [...args],
      allowPositionals: true,
      options: {
        input: { type: 'string' },
        basis: { type: 'string' },
        json: { type: 'boolean', default: false },
      },
    })
    slug = parsed.positionals[0]
    input = parsed.values.input
    basisPath = parsed.values.basis
    asJSON = parsed.values.json === true
  } catch (error) {
    process.stderr.write(`用法错误：${(error as Error).message}\n`)
    return EXIT_INPUT
  }

  if (!slug) {
    process.stderr.write('用法错误：check 需要器官 slug\n')
    return EXIT_INPUT
  }
  if (!input) {
    process.stderr.write('用法错误：check 需要 --input <file|->\n')
    return EXIT_INPUT
  }

  try {
    const verb = get(slug)
    const subject = readJSON(input)
    if (subject === null || typeof subject !== 'object' || Array.isArray(subject)) {
      throw new Error('输入必须是 JSON 对象')
    }
    const record = subject as Record<string, unknown>
    const missing = verb.input_fields.filter((field) => !(field in record))
    if (missing.length > 0) {
      throw new Error(`输入缺少必填字段：${missing.join(', ')}`)
    }
    const basis = basisPath ? Basis.fromObject(readJSON(basisPath)) : Basis.empty()

    const report = new Report({
      product: PRODUCT,
      verb: verb.slug,
      verb_version: verb.version,
      subject: subjectLabel(input),
      records: [...verb.evaluate(record, basis)],
    })

    if (asJSON) {
      console.log(JSON.stringify(report.toJSON(), null, 2))
    } else {
      for (const line of report.lines()) console.log(line)
    }
    return report.exitCode()
  } catch (error) {
    if (
      error instanceof ContractError ||
      error instanceof VerbMissing ||
      error instanceof NodeMissing
    ) {
      process.stderr.write(`${error.name}: ${error.message}\n`)
      return EXIT_CONTRACT
    }
    process.stderr.write(`输入不合法：${(error as Error).message}\n`)
    return EXIT_INPUT
  }
}