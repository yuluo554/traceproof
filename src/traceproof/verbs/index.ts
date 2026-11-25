/**
 * 器官目录：每个器官一个子目录 `<slug>/index.ts`，导入时向注册表登记自己的 `Verb`。
 *
 * **显式清单，不做目录扫描**：扫描式加载会把「某个器官忘了登记」变成静默空跑，
 * 而显式清单在导入失败时立刻红。Stage 1 尚无器官迁入，清单为空。
 *
 * 新增器官三步（SKELETON-SPEC §1/§2）：
 *  1. 在 `src/traceproof/verbs/<slug>/index.ts` 里 `register({...})`；
 *  2. 把目录名加进下面的 `BUILTIN_MODULES`；
 *  3. 补 `test/<slug>.test.js` 与 `docs/<slug>.md`（输入 / 规则 / 输出示例）。
 */

/** 已迁入的内置器官目录名（相对 `traceproof/verbs`）。按 slug 字典序维护。 */
export const BUILTIN_MODULES: readonly string[] = []

export async function loadBuiltin(): Promise<void> {
  for (const name of BUILTIN_MODULES) {
    await import(`./${name}/index.js`)
  }
}