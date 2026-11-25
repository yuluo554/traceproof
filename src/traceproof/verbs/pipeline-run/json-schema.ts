/**
 * pipeline-run · 引擎支持的 JSON Schema 子集（重写旧仓对
 * `@deepseek-ai/dsh-tools` `assertObjectJsonSchema` 的调用；器官不能新增运行时依赖）。
 *
 * 口径（与 dsh-tools 0.2.0-rc.1 的受控子集一致）：
 * - 根必须是 `type: "object"`；
 * - 支持 `type` / `oneOf` / `properties` / `required` /
 *   `additionalProperties` / `items` / `enum` / `const`；
 * - 注解 `description` / `title` / `default` / `examples` 原样放行；
 * - 其余关键字（如 `format`）**拒绝**，不做静默忽略。
 *
 * 违规一次列全（与旧仓一样 stop at none），由调用方包成 `IR_OUTPUT_SCHEMA`。
 */

import { ErrorCode, PipelineError } from './errors.js'
import { isPlainObject } from './util.js'

const CONSTRAINT_KEYWORDS = new Set([
  'type',
  'oneOf',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'enum',
  'const',
])

const ANNOTATION_KEYWORDS = new Set(['description', 'title', 'default', 'examples'])

const SCHEMA_TYPES = ['object', 'array', 'string', 'number', 'integer', 'boolean', 'null'] as const
type SchemaType = (typeof SCHEMA_TYPES)[number]

const ONE_OF_SIBLING_KEYWORDS = ['properties', 'required', 'additionalProperties', 'items', 'enum', 'const'] as const

function isLosslessJson(value: unknown, seen = new Set<object>()): boolean {
  if (value === null) return true
  if (typeof value === 'string' || typeof value === 'boolean') return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (Array.isArray(value)) {
    if (seen.has(value)) return false
    seen.add(value)
    const ok = value.every((item) => isLosslessJson(item, seen))
    seen.delete(value)
    return ok
  }
  if (!isPlainObject(value)) return false
  if (seen.has(value)) return false
  seen.add(value)
  const ok = Object.keys(value).every((key) => isLosslessJson(value[key], seen))
  seen.delete(value)
  return ok
}

function isSchemaRecord(value: unknown): value is Record<string, unknown> {
  return isPlainObject(value) && Object.keys(value).every((key) => typeof key === 'string')
}

function scalarMatches(type: SchemaType, value: unknown): boolean {
  switch (type) {
    case 'string':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number' && Number.isFinite(value)
    case 'integer':
      return typeof value === 'number' && Number.isFinite(value) && Number.isInteger(value)
    case 'boolean':
      return typeof value === 'boolean'
    case 'null':
      return value === null
    default:
      return false
  }
}

interface Frame {
  node: unknown
  path: string
}

export function collectSchemaViolations(root: unknown): string[] {
  const violations: string[] = []
  const seen = new Set<object>()
  const stack: Array<{ kind: 'enter'; node: unknown; path: string } | { kind: 'leave'; node: object }> = [
    { kind: 'enter', node: root, path: 'schema' },
  ]

  while (stack.length > 0) {
    const task = stack.pop()!
    if (task.kind === 'leave') {
      seen.delete(task.node)
      continue
    }
    const { node, path } = task
    if (!isSchemaRecord(node)) {
      violations.push(`${path} 必须是 schema 对象`)
      continue
    }
    if (seen.has(node)) {
      violations.push(`${path} 是循环引用`)
      continue
    }
    seen.add(node)
    stack.push({ kind: 'leave', node })

    for (const key of Object.keys(node)) {
      if (CONSTRAINT_KEYWORDS.has(key)) continue
      if (ANNOTATION_KEYWORDS.has(key)) {
        if (!isLosslessJson(node[key])) violations.push(`${path}.${key} 注解必须是无损 JSON`)
        continue
      }
      violations.push(`${path}.${key} 不是受支持的关键字（子集：type/oneOf/properties/required/additionalProperties/items/enum/const + 注解）`)
    }
    if (node.description !== undefined && typeof node.description !== 'string') {
      violations.push(`${path}.description 必须是字符串`)
    }
    if (node.title !== undefined && typeof node.title !== 'string') {
      violations.push(`${path}.title 必须是字符串`)
    }

    const hasType = Object.hasOwn(node, 'type')
    const hasOneOf = Object.hasOwn(node, 'oneOf')
    if (hasType && hasOneOf) {
      violations.push(`${path} 不能同时声明 type 与 oneOf`)
      continue
    }
    if (!hasType && !hasOneOf) {
      for (const key of ONE_OF_SIBLING_KEYWORDS) {
        if (Object.hasOwn(node, key)) violations.push(`${path}.${key} 需要先声明 type 或 oneOf`)
      }
      continue
    }
    if (hasOneOf) {
      for (const key of ONE_OF_SIBLING_KEYWORDS) {
        if (Object.hasOwn(node, key)) violations.push(`${path}.${key} 不能与 oneOf 并列`)
      }
      const oneOf = node.oneOf
      if (!Array.isArray(oneOf) || oneOf.length < 2) {
        violations.push(`${path}.oneOf 必须是至少两项的数组`)
      } else {
        for (let index = oneOf.length - 1; index >= 0; index -= 1) {
          stack.push({ kind: 'enter', node: oneOf[index], path: `${path}.oneOf[${index}]` })
        }
      }
      continue
    }

    const type = node.type
    if (typeof type !== 'string' || !(SCHEMA_TYPES as readonly string[]).includes(type)) {
      violations.push(
        Array.isArray(type)
          ? `${path}.type 必须是单个类型字符串（不支持类型数组）`
          : `${path}.type 必须是 ${SCHEMA_TYPES.join('/')} 之一`,
      )
      continue
    }
    const schemaType = type as SchemaType
    const misplaced: Record<string, readonly SchemaType[]> = {
      properties: ['object'],
      required: ['object'],
      additionalProperties: ['object'],
      items: ['array'],
      enum: ['string', 'number', 'integer', 'boolean', 'null'],
      const: ['string', 'number', 'integer', 'boolean', 'null'],
    }
    for (const [key, types] of Object.entries(misplaced)) {
      if (Object.hasOwn(node, key) && !types.includes(schemaType)) {
        violations.push(`${path}.${key} 不能用于 type="${schemaType}"`)
      }
    }

    switch (schemaType) {
      case 'object': {
        const properties = Object.hasOwn(node, 'properties') ? node.properties : undefined
        if (Object.hasOwn(node, 'properties')) {
          if (!isPlainObject(properties)) {
            violations.push(`${path}.properties 必须是 schema 对象映射`)
          } else {
            const entries = Object.entries(properties)
            for (let index = entries.length - 1; index >= 0; index -= 1) {
              const [key, schema] = entries[index]
              stack.push({ kind: 'enter', node: schema, path: `${path}.properties.${key}` })
            }
          }
        }
        if (Object.hasOwn(node, 'required')) {
          const required = node.required
          if (!Array.isArray(required) || required.some((entry) => typeof entry !== 'string')) {
            violations.push(`${path}.required 必须是字符串数组`)
          } else {
            const declared = isPlainObject(properties) ? properties : {}
            for (const key of required) {
              if (!Object.hasOwn(declared, key)) {
                violations.push(`${path}.required 指向不在 properties 里的 "${key}"`)
              }
            }
          }
        }
        if (Object.hasOwn(node, 'additionalProperties') && typeof node.additionalProperties !== 'boolean') {
          violations.push(`${path}.additionalProperties 必须是布尔值`)
        }
        break
      }
      case 'array':
        if (Object.hasOwn(node, 'items')) {
          stack.push({ kind: 'enter', node: node.items, path: `${path}.items` })
        }
        break
      case 'string':
      case 'number':
      case 'integer':
      case 'boolean':
      case 'null': {
        const hasEnum = Object.hasOwn(node, 'enum')
        const allowed = hasEnum ? node.enum : undefined
        const enumValid =
          Array.isArray(allowed) && allowed.length > 0 && allowed.every((entry) => scalarMatches(schemaType, entry))
        if (hasEnum && !enumValid) violations.push(`${path}.enum 必须是非空的 ${schemaType} 值数组`)
        const hasConst = Object.hasOwn(node, 'const')
        if (hasConst && !scalarMatches(schemaType, node.const)) {
          violations.push(`${path}.const 必须是 ${schemaType} 值`)
        } else if (hasConst && enumValid && !(allowed as unknown[]).includes(node.const)) {
          violations.push(`${path}.const 必须是 ${path}.enum 之一`)
        }
        break
      }
      default:
        break
    }
  }
  return violations
}

/** 旧仓 `assertObjectJsonSchema` 的等价断言（对象根 + 受控子集）。 */
export function assertObjectJsonSchema(schema: unknown): void {
  const violations = collectSchemaViolations(schema)
  if (violations.length === 0) {
    if (!isPlainObject(schema) || schema.type !== 'object') {
      violations.push('schema.type 必须是 "object"（结构化输出是对象根）')
    }
  }
  if (violations.length > 0) {
    throw new PipelineError(
      ErrorCode.outputSchema,
      `outputSchema 不在引擎支持的子集内：${violations.join('；')}`,
    )
  }
}