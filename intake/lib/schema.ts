/**
 * schema.ts — a JSON Schema (draft-07) evaluator for exactly the keyword subset the intake
 * schemas use. Any other keyword throws, so a schema cannot gain a rule this code does not
 * enforce: the schema file and the validator can never silently disagree. Zero dependencies.
 *
 * Supported: type (string or array), const, enum, required, properties,
 * additionalProperties (boolean), items (schema), pattern, minLength, minimum, maximum,
 * minItems, $ref (local "#/definitions/<name>"), plus the metadata keys $schema, $id, title,
 * description and the definitions container.
 */
export interface SchemaError { path: string; message: string }
export type Schema = Record<string, unknown>;

const METADATA = new Set(["$schema", "$id", "title", "description", "definitions"]);
const SUPPORTED = new Set(["type", "const", "enum", "required", "properties", "additionalProperties", "items", "pattern", "minLength", "minimum", "maximum", "minItems", "$ref"]);

export class UnsupportedKeyword extends Error {}

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

function matchesType(v: unknown, t: string): boolean {
  const actual = typeOf(v);
  if (t === "number") return actual === "number" || actual === "integer";
  return actual === t;
}

function resolveRef(ref: unknown, root: Schema): Schema {
  if (typeof ref !== "string" || !ref.startsWith("#/")) throw new UnsupportedKeyword(`$ref must be local, got ${String(ref)}`);
  let node: unknown = root;
  for (const part of ref.slice(2).split("/")) {
    if (typeof node !== "object" || node === null || !Object.hasOwn(node, part)) throw new UnsupportedKeyword(`$ref not found: ${ref}`);
    node = (node as Record<string, unknown>)[part];
  }
  return node as Schema;
}

export function validateAgainstSchema(doc: unknown, schema: Schema, root: Schema = schema, path = "root", errors: SchemaError[] = []): SchemaError[] {
  for (const key of Object.keys(schema)) {
    if (!METADATA.has(key) && !SUPPORTED.has(key)) throw new UnsupportedKeyword(`unsupported schema keyword "${key}" at ${path}`);
  }
  if ("$ref" in schema) return validateAgainstSchema(doc, resolveRef(schema.$ref, root), root, path, errors);

  const fail = (message: string) => { errors.push({ path, message }); };

  if ("type" in schema) {
    const types = Array.isArray(schema.type) ? (schema.type as string[]) : [schema.type as string];
    if (!types.some((t) => matchesType(doc, t))) { fail(`expected ${types.join("|")}, got ${typeOf(doc)}`); return errors; }
  }
  if ("const" in schema && JSON.stringify(doc) !== JSON.stringify(schema.const)) fail(`expected ${JSON.stringify(schema.const)}, got ${JSON.stringify(doc)}`);
  if ("enum" in schema && !(schema.enum as unknown[]).some((e) => JSON.stringify(e) === JSON.stringify(doc))) fail(`expected one of ${JSON.stringify(schema.enum)}, got ${JSON.stringify(doc)}`);

  if (typeof doc === "string") {
    if ("pattern" in schema && !new RegExp(schema.pattern as string).test(doc)) fail(`"${doc}" does not match ${schema.pattern}`);
    if ("minLength" in schema && doc.length < (schema.minLength as number)) fail(`string shorter than ${schema.minLength}`);
  }
  if (typeof doc === "number") {
    if ("minimum" in schema && doc < (schema.minimum as number)) fail(`${doc} is below minimum ${schema.minimum}`);
    if ("maximum" in schema && doc > (schema.maximum as number)) fail(`${doc} is above maximum ${schema.maximum}`);
  }
  if (Array.isArray(doc)) {
    if ("minItems" in schema && doc.length < (schema.minItems as number)) fail(`fewer than ${schema.minItems} items`);
    if ("items" in schema) doc.forEach((item, i) => validateAgainstSchema(item, schema.items as Schema, root, `${path}[${i}]`, errors));
  }
  if (typeOf(doc) === "object") {
    const obj = doc as Record<string, unknown>;
    const props = (schema.properties ?? {}) as Record<string, Schema>;
    // Own-property checks only: "constructor" or "toString" as a field name must not resolve to
    // Object.prototype and slip past additionalProperties.
    for (const r of (schema.required ?? []) as string[]) if (!Object.hasOwn(obj, r)) fail(`missing required field "${r}"`);
    for (const [k, v] of Object.entries(obj)) {
      if (Object.hasOwn(props, k)) validateAgainstSchema(v, props[k], root, `${path}.${k}`, errors);
      else if (schema.additionalProperties === false) fail(`unexpected field "${k}"`);
    }
  }
  return errors;
}
