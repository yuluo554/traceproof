/**
 * 共享类型出口（仅类型，运行时为空）。
 *
 * 单独成文件是为了避免 `dmarc.ts` → `spf.ts` / `dkim.ts` 的值级循环依赖：
 * 三者只在这里汇合类型面，运行时不产生额外导入。
 */

export type { SpfResult, TraceNote, BudgetCell } from './spf.js'
export type { DkimResult, SignatureResult, Message } from './dkim.js'