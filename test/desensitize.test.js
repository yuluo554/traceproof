/**
 * Desensitization gate (M4, plan/06 发布门 / ai-tool-project-sprint 阶段 7):
 * the four-step audit runs as part of the offline suite, so a secret or
 * personal-data leak cannot land without the suite going red. The script
 * itself (scripts/desensitize-audit.mjs) exits non-zero on any finding and
 * prints DESSENSITIZE_AUDIT_OK only when steps 1-3 are clean.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

/** 第一个用例跑审计时留下的 stdout —— 第二用例复用它，避免重复起进程。 */
let auditStdout = ''

/** 递归列出某目录下的全部文件（相对 ROOT，posix 风格）。 */
function walkRel(dir, out = []) {
  for (const name of readdirSync(join(ROOT, dir))) {
    const rel = `${dir}/${name}`
    if (statSync(join(ROOT, rel)).isDirectory()) walkRel(rel, out)
    else out.push(rel)
  }
  return out
}

test('desensitize audit: working tree is clean (steps 1-3) and the script passes', () => {
  let stdout
  try {
    stdout = execFileSync(process.execPath, ['scripts/desensitize-audit.mjs'], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, DESENSITIZE_AUDIT_VERBOSE: '1' },
    })
  } catch (error) {
    assert.fail(`desensitize audit FAILED:\n${error.stdout ?? ''}${error.stderr ?? ''}`)
  }
  assert.match(stdout, /DESENSITIZE_AUDIT_OK/, 'the audit must reach its OK marker')
  assert.ok(!/allowlisted/.test(stdout), 'the allowlist is empty — a tolerated hit means an entry needs re-review')
  auditStdout = stdout
})

/**
 * 2026-11-25 pinning：`VENDORED_UPSTREAM_RE` 只允许跳过
 * `test/fixtures/<器官>/upstream/**` 里的**上游语料**，且跳过数必须与该子树
 * 的真实文件数**逐一相等**。放宽成 `test/fixtures/**`（或整仓）时这条会红——
 * 免得上游豁免变成「整仓不扫」。
 */
test('desensitize audit: vendored skip stays inside test/fixtures/*/upstream/**', () => {
  const upstreamFiles = walkRel('test/fixtures').filter((rel) => /\/upstream\//.test(rel))
  assert.ok(upstreamFiles.length > 0, '上游语料子树为空 = 这条 pinning 已经没有观测面')
  assert.ok(auditStdout, '第一个用例没有产出审计输出（顺序假设被破坏？）')
  // 审计在 DESENSITIZE_AUDIT_VERBOSE=1 时逐条列出被跳过的路径。
  const skipped = [...auditStdout.matchAll(/\[vendored-file\] (.+)$/gm)]
    .map((m) => m[1].trim().replace(/\\/g, '/'))
  assert.ok(skipped.length > 0, '一个都没跳过 = 上游语料没被识别（或 verbose 输出被删）')
  // (a) 跳过集必须**全部**落在 `test/fixtures/<器官>/upstream/` 里 —— 这条挡「放宽到整仓」。
  for (const rel of skipped) {
    assert.match(rel, /^test\/fixtures\/[^/]+\/upstream\//, `upstream 之外的路径混进了跳过集：${rel}`)
  }
  // (b) 跳过数不得超过该子树真实文件数 —— 这条挡「凭空多跳」。
  assert.ok(skipped.length <= upstreamFiles.length, `跳过 ${skipped.length} > upstream 实际 ${upstreamFiles.length}`)
})

/**
 * T4 (2026-10-22): the personal-path regex was widened to catch
 * `<drive>:\ProgramData\...`, which the original rule missed entirely
 * (14 occurrences sat in the published repo while the audit printed OK).
 * This test pins the *widening itself*: the audit script must go red on the
 * new shapes and stay green on placeholders / system dirs / other people's
 * build machines. Without it, a later "simplification" of the regex would
 * silently restore the blind spot.
 */
test('desensitize audit: widened personal-path rule fires, and does not misfire', () => {
  let stdout
  try {
    stdout = execFileSync(process.execPath, ['scripts/desensitize-audit-selftest.mjs'], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
  } catch (error) {
    assert.fail(`desensitize negative controls FAILED:\n${error.stdout ?? ''}${error.stderr ?? ''}`)
  }
  assert.match(stdout, /负控 13 项全部符合预期/, 'all 13 positive/negative controls must hold')
})
