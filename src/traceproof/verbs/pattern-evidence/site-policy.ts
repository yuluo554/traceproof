/**
 * 站点开关（纯函数，迁移自旧仓 `src/lib/site-policy.js`）。
 *
 * 黑名单 = 永不在该站注入扫描；白名单 = 仅在这些站启用。
 * 返回 `{enabled, reason}`——reason 供账本明示（不静默跳过）。
 */

export const SITE_POLICY_MODES = ['allowlist', 'blocklist'] as const

export type SitePolicyMode = (typeof SITE_POLICY_MODES)[number]

export interface Settings {
  readonly site_policy: {
    readonly mode: SitePolicyMode
    readonly hosts: readonly string[]
  }
  readonly disabled_rule_ids: readonly string[]
}

export const DEFAULT_SETTINGS: Settings = {
  site_policy: { mode: 'blocklist', hosts: [] },
  disabled_rule_ids: [],
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function normalizeSettings(raw: unknown): Settings {
  const source = isPlainObject(raw) ? raw : {}
  const policy = isPlainObject(source.site_policy) ? source.site_policy : {}
  const mode = (SITE_POLICY_MODES as readonly string[]).includes(policy.mode as string)
    ? (policy.mode as SitePolicyMode)
    : DEFAULT_SETTINGS.site_policy.mode
  const hosts = Array.isArray(policy.hosts)
    ? [
        ...new Set(
          policy.hosts
            .map((host) => String(host).trim().toLowerCase())
            .filter((host) => host.length > 0),
        ),
      ].sort()
    : []
  const disabled = Array.isArray(source.disabled_rule_ids)
    ? [...new Set(source.disabled_rule_ids.map(String))].sort()
    : []
  return { site_policy: { mode, hosts }, disabled_rule_ids: disabled }
}

export function hostOf(url: unknown): string {
  try {
    return new URL(String(url)).host.toLowerCase()
  } catch {
    return ''
  }
}

export interface SiteGate {
  readonly enabled: boolean
  readonly reason: string
}

/** 该站点是否应被扫描。 */
export function isSiteEnabled(url: unknown, rawSettings: unknown): SiteGate {
  const settings = normalizeSettings(rawSettings)
  const host = hostOf(url)
  if (host.length === 0) return { enabled: false, reason: 'url_unparsable' }
  const { mode, hosts } = settings.site_policy
  if (mode === 'blocklist' && hosts.includes(host)) return { enabled: false, reason: 'blocklisted' }
  if (mode === 'allowlist' && !hosts.includes(host)) return { enabled: false, reason: 'not_allowlisted' }
  return { enabled: true, reason: 'enabled' }
}

/** 过滤掉被禁用的规则 id（未知 id 保留在集合里，由规则包校验另行报错）。 */
export function activeRuleIds(allRuleIds: readonly string[], rawSettings: unknown): string[] {
  const disabled = new Set(normalizeSettings(rawSettings).disabled_rule_ids)
  return allRuleIds.filter((id) => !disabled.has(id))
}