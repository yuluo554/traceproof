/**
 * 脱敏前置（SKELETON-SPEC §4.4）：敏感字段在**入账之前**就被替换，
 * 账本里不存在「已入库、后打码」的中间态。
 *
 * 判据是**键名式**（不靠正则猜内容）：键名命中敏感集即整值替换为 MASK。
 * 这条比「事后扫描」强的地方在于：脱敏发生在 `makeRecord` 内部，
 * 器官没有绕过的通路。
 */

export const MASK = '***'

/** 键名命中即脱敏（小写比较，允许 `apiKey` / `api_key` / `API-KEY` 等形态）。 */
const SENSITIVE_KEYS = new Set([
  'api_key',
  'apikey',
  'api-key',
  'token',
  'access_token',
  'refresh_token',
  'authorization',
  'auth',
  'password',
  'passwd',
  'secret',
  'client_secret',
  'cookie',
  'set-cookie',
  'private_key',
  'session_key',
])

function normalizeKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[\s-]/g, '_')
}

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEYS.has(normalizeKey(key))
}

/**
 * 深拷贝 + 就地脱敏。返回**新对象**，不改调用方传进来的值
 * （器官拿到的证据原样保留，账本里只有脱敏后的副本）。
 */
export function redactDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => redactDeep(item))
  if (value === null || typeof value !== 'object') return value
  const source = value as Record<string, unknown>
  const out: Record<string, unknown> = {}
  for (const key of Object.keys(source)) {
    out[key] = isSensitiveKey(key) ? MASK : redactDeep(source[key])
  }
  return out
}