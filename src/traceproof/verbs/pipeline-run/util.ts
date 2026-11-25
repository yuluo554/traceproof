/** pipeline-run 内部小工具：JSON 面判定 / 深比较 / 稳定排序。 */

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * 深比较（忽略对象键顺序；数组顺序有意义）。
 * 只接受 JSON 面值：调用方都来自已解析 JSON 或本器官内部组装。
 */
export function jsonEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false
    return left.every((item, index) => jsonEqual(item, right[index]))
  }
  if (!isPlainObject(left) || !isPlainObject(right)) return false
  const leftKeys = Object.keys(left).sort()
  const rightKeys = Object.keys(right).sort()
  if (leftKeys.length !== rightKeys.length || leftKeys.some((key, index) => key !== rightKeys[index])) {
    return false
  }
  return leftKeys.every((key) => jsonEqual(left[key], right[key]))
}

export function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort()
}

export function renderUnknown(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}