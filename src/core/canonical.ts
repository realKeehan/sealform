// RFC 8785 JSON Canonicalization Scheme (JCS).
//
// The same logical value always serializes to the same bytes, so a hash of a record does not depend
// on key order or whitespace. ECMAScript's number and string serialization already match the RFC;
// what JCS adds is sorting object keys by UTF-16 code units, which is what the default
// Array.prototype.sort does for strings.

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function canonicalize(value: unknown): string {
  return serialize(value, '$');
}

function serialize(value: unknown, path: string): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      if (!value.isWellFormed()) throw new TypeError(`Lone surrogate in string at ${path}`);
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError(`Non-finite number at ${path}`);
      return JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) {
        return '[' + value.map((item, i) => {
          if (item === undefined) throw new TypeError(`Undefined array item at ${path}[${i}]`);
          return serialize(item, `${path}[${i}]`);
        }).join(',') + ']';
      }
      if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
        throw new TypeError(`Only plain objects can be canonicalized (at ${path})`);
      }
      {
        const entries = Object.entries(value as Record<string, unknown>)
          .filter(([, v]) => v !== undefined)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
        return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + serialize(v, `${path}.${k}`)).join(',') + '}';
      }
    default:
      throw new TypeError(`Cannot canonicalize ${typeof value} at ${path}`);
  }
}
