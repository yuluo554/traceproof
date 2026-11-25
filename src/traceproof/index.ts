/**
 * traceproof —— 取证账本引擎：把「主张」逐条对到痕迹节点上，判 `claim` / `refuted` /
 * `inconclusive`，并留下可复核的依据。
 *
 * 本包为 Stage 1 新建的内核；旧插件（`dsh-prompt-polisher` 的 host/client 两半）
 * 在过渡期内原样保留，器官（verb）逐个迁入 `traceproof/verbs` 后再收敛。
 */

export const VERSION = '0.1.0.dev0'

export const PRODUCT = 'traceproof'