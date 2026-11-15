/** A display boundary, not authorization. Reads the steward's schema without copying it. */
export const MAX_SNAPSHOT_BYTES = 524288;

export class SnapshotError extends Error {
  constructor(message) { super(message); this.name = 'SnapshotError'; }
}

const fail = (message) => { throw new SnapshotError(message); };
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

/** JSON.parse alone silently accepts duplicate keys. This bounded parser rejects them. */
export function parseUniqueJSON(raw, maximumBytes = MAX_SNAPSHOT_BYTES) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > maximumBytes) {
    fail('Snapshot exceeds the display byte limit.');
  }
  let cursor = 0;
  let entries = 0;
  const whitespace = () => { while (/[\t\n\r ]/.test(raw[cursor] ?? '\0')) cursor += 1; };
  function string() {
    const start = cursor++;
    while (cursor < raw.length) {
      if (raw[cursor] === '\\') { cursor += 2; continue; }
      if (raw[cursor++] === '"') {
        try { return JSON.parse(raw.slice(start, cursor)); } catch { fail('Invalid JSON string.'); }
      }
    }
    fail('Unterminated JSON string.');
  }
  function value(depth = 0) {
    if (depth > 32 || ++entries > 16384) fail('Snapshot exceeds display complexity limits.');
    whitespace();
    const char = raw[cursor];
    if (char === '"') return string();
    if (char === '{') {
      cursor += 1;
      const result = Object.create(null);
      whitespace();
      if (raw[cursor] === '}') { cursor += 1; return result; }
      while (true) {
        whitespace();
        if (raw[cursor] !== '"') fail('Expected an object key.');
        const key = string();
        if (own(result, key)) fail('Duplicate JSON key.');
        whitespace();
        if (raw[cursor++] !== ':') fail('Expected a colon.');
        result[key] = value(depth + 1);
        whitespace();
        const separator = raw[cursor++];
        if (separator === '}') return result;
        if (separator !== ',') fail('Invalid object separator.');
      }
    }
    if (char === '[') {
      cursor += 1;
      const result = [];
      whitespace();
      if (raw[cursor] === ']') { cursor += 1; return result; }
      while (true) {
        result.push(value(depth + 1));
        whitespace();
        const separator = raw[cursor++];
        if (separator === ']') return result;
        if (separator !== ',') fail('Invalid array separator.');
      }
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (raw.startsWith(token, cursor)) { cursor += token.length; return result; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(raw.slice(cursor));
    if (!number) fail('Invalid JSON value.');
    cursor += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isSafeInteger(parsed)) fail('Numeric fields must be safe integers; amounts must be decimal strings.');
    return parsed;
  }
  const result = value();
  whitespace();
  if (cursor !== raw.length) fail('Trailing JSON content.');
  return result;
}

export function isUTCTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) return false;
  const time = new Date(value);
  return Number.isFinite(time.getTime()) && time.toISOString().slice(0, 19) === value.slice(0, 19);
}

export function utcMicroseconds(value) {
  if (!isUTCTimestamp(value)) fail('A valid UTC timestamp is required.');
  const fractional = /\.(\d{1,6})/.exec(value)?.[1] ?? '';
  return BigInt(Date.parse(`${value.slice(0, 19)}Z`)) * 1000n + BigInt(fractional.padEnd(6, '0'));
}

const SUPPORTED = new Set(['$schema', '$id', '$defs', '$ref', '$comment', 'title', 'description', 'type', 'const', 'enum', 'anyOf', 'properties', 'additionalProperties', 'required', 'items', 'maxItems', 'minItems', 'uniqueItems', 'pattern', 'format', 'minimum', 'maximum', 'minLength', 'maxLength']);

/** Deliberately supports only keywords used by the published cockpit schema. New keywords fail closed. */
export function assertSchema(value, schema, root = schema, path = '$') {
  for (const keyword of Object.keys(schema)) if (!SUPPORTED.has(keyword)) fail(`Unsupported schema keyword: ${keyword}`);
  if (schema.$ref) {
    if (!/^#\/\$defs\/[A-Za-z0-9_-]+$/.test(schema.$ref)) fail('Only local schema references are supported.');
    const target = root.$defs?.[schema.$ref.split('/').at(-1)];
    if (!target) fail('Unresolved shared schema reference.');
    assertSchema(value, target, root, path);
  }
  if (schema.anyOf) {
    const matched = schema.anyOf.some((choice) => {
      try { assertSchema(value, choice, root, path); return true; } catch (error) {
        if (!(error instanceof SnapshotError)) throw error;
        return false;
      }
    });
    if (!matched) fail(`${path}: value does not match the shared schema.`);
  }
  if (own(schema, 'const') && value !== schema.const) fail(`${path}: unsupported constant.`);
  if (schema.enum && !schema.enum.includes(value)) fail(`${path}: unsupported enum value.`);
  const types = {
    null: value === null,
    object: value !== null && typeof value === 'object' && !Array.isArray(value),
    array: Array.isArray(value), string: typeof value === 'string',
    boolean: typeof value === 'boolean', integer: Number.isSafeInteger(value),
  };
  if (schema.type && (!own(types, schema.type) || !types[schema.type])) fail(`${path}: invalid ${schema.type}.`);
  if (schema.type === 'object') {
    for (const key of schema.required ?? []) if (!own(value, key)) fail(`${path}: missing ${key}.`);
    for (const key of Object.keys(value)) {
      if (own(schema.properties ?? {}, key)) assertSchema(value[key], schema.properties[key], root, `${path}.${key}`);
      else if (schema.additionalProperties === false) fail(`${path}: unsupported field.`);
    }
  }
  if (schema.type === 'array') {
    if (value.length > (schema.maxItems ?? Infinity) || value.length < (schema.minItems ?? 0)) fail(`${path}: array size is outside limits.`);
    if (schema.uniqueItems && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) fail(`${path}: duplicate items.`);
    value.forEach((item, index) => assertSchema(item, schema.items, root, `${path}[${index}]`));
  }
  if (schema.type === 'string') {
    if ([...value].some((character) => character.codePointAt(0) >= 0xD800 && character.codePointAt(0) <= 0xDFFF)) fail(`${path}: text contains an unpaired Unicode surrogate.`);
    const length = [...value].length;
    if (length < (schema.minLength ?? 0) || length > (schema.maxLength ?? Infinity)) fail(`${path}: text length is outside limits.`);
    if (schema.pattern && !(new RegExp(schema.pattern)).test(value)) fail(`${path}: invalid string format.`);
    if (schema.format && schema.format !== 'date-time') fail('Unsupported shared schema format.');
    if (schema.format === 'date-time' && !isUTCTimestamp(value)) fail(`${path}: a valid UTC timestamp is required.`);
  }
  if (schema.type === 'integer' && (value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity))) fail(`${path}: integer outside limits.`);
}

function unique(values, field) {
  if (new Set(values).size !== values.length) fail(`${field}: duplicate identities.`);
}

export function decimalCoefficient(value) {
  if (typeof value !== 'string' || !/^-?(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,12})?$/.test(value)) fail('Invalid plain decimal string.');
  const [whole, fraction = ''] = value.replace(/^-/, '').split('.');
  return BigInt(whole + fraction.padEnd(12, '0')) * (value.startsWith('-') ? -1n : 1n);
}

export function assertCockpitSemantics(projection) {
  const p = projection.permissions;
  if ((p.new_risk !== 'UNKNOWN' || p.management !== 'UNKNOWN') && (p.generation === null || p.confirmed_barrier_id === null)) fail('Permission claims need their barrier and generation.');
  if (projection.admissions_enabled && (projection.recovery !== 'COHERENT' || projection.state_id === null || projection.observed_at === null || p.confirmed_barrier_id === null)) fail('Admissions require an observed coherent state and barrier.');
  for (const key of ['balance', 'equity', 'realized_pnl', 'open_pnl']) if (projection[key] !== null) decimalCoefficient(projection[key].amount);
  if (projection.positions !== null) {
    unique(projection.positions.map((position) => position.position_id), 'positions');
    for (const position of projection.positions) {
      if (decimalCoefficient(position.quantity) < 0n || decimalCoefficient(position.entry_price) <= 0n || (position.stop_price !== null && decimalCoefficient(position.stop_price) <= 0n)) fail('Position quantities/prices are invalid.');
    }
  }
  unique(projection.commands.map((command) => command.command_id), 'commands');
  unique(projection.unresolved_command_ids, 'unresolved_command_ids');
  if (projection.last_decision !== null) {
    const { selection, provenance } = projection.last_decision;
    unique(selection.evidence_ids, 'evidence_ids');
    if (!selection.reason.trim() || new TextEncoder().encode(selection.reason).length > 1024) fail('Decision reason exceeds its UTF-8 limit or is blank.');
    if (utcMicroseconds(provenance.completed_at) < utcMicroseconds(provenance.started_at)) fail('Decision completion precedes its start.');
    if (provenance.origin === 'ACTUAL_MODEL' && [provenance.model_id, provenance.model_artifact_sha256, provenance.inference_receipt_id].some((item) => item === null)) fail('Actual-model claims require complete provenance references.');
  }
}

export function freeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

export function decodeCockpit(raw, schema) {
  if (schema?.$id !== 'urn:cas-forex:cockpit:1.0') fail('The shared cockpit schema is unavailable or unsupported.');
  const projection = parseUniqueJSON(raw);
  assertSchema(projection, schema);
  assertCockpitSemantics(projection);
  return freeze(projection);
}
