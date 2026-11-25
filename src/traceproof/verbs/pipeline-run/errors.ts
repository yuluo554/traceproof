/**
 * pipeline-run · 错误词汇（迁自旧仓 `src/errors.ts`）。
 *
 * `code` 是机器可路由的判定词汇（旧仓 B2 矩阵按 code 断言）；`message` 是人读中文。
 * 错误码表放在 `data/pipeline-run-defaults.json`，代码里不再内联第二份。
 */

import defaults from './data/pipeline-run-defaults.json' with { type: 'json' }

type CodeKey = keyof typeof defaults.error_codes

export const ErrorCode: Readonly<Record<CodeKey, string>> = defaults.error_codes

export class PipelineError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'PipelineError'
    this.code = code
  }
}