// AUTHORED / NOT_RUN. Catalog doubles are not producer or semantic-verification evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { canonicalJSON } from '../../ui/src/decision-read.mjs';
import { collectCatalogReferences, inspectCatalogRecord, resolveCatalog, MAX_CATALOG_RECORD_BYTES } from '../../ui/src/catalog.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { fixture, displayState } from './helpers.mjs';

const schema = JSON.parse(await readFile(new URL('../../docs/contracts/decision-read.schema.json', import.meta.url), 'utf8'));
const raw = await readFile(new URL('../../docs/contracts/initial-decision-read.json', import.meta.url), 'utf8');
const hashBytes = async (bytes) => createHash('sha256').update(bytes).digest('hex');
const anchor = { anchor_id: 'read-1', producer_id: 'producer-1' };
const ref = (record, id = 'record-1') => ({ record_id: id, record_version: 7, record_sha256: createHash('sha256').update(canonicalJSON(record)).digest('hex'), unavailable_reason: null });
const response = (record, reference = ref(record)) => ({ schema_version: 'forex.catalog-record/1', ...anchor, reference, record });
function envelope(...references) { const value = JSON.parse(raw); value.current_state.observation_refs = references; return value; }
const resolve = (value, callback) => resolveCatalog({ envelope: value, schema, anchor, resolve: callback, hashBytes });

test('all exact non-null references deduplicate while original paths and missing reasons remain', () => {
  const reference = ref({ hello: 'world' }); const value = envelope(reference, reference);
  const collected = collectCatalogReferences(value, schema);
  assert.equal(collected.references.length, 1); assert.equal(collected.references[0].paths.length, 2);
  assert.ok(collected.absent.length > 0); assert.ok(collected.absent.every((entry) => entry.reason.length));
});

test('object, array and explicitly referenced null payloads retain exact canonical identity', async () => {
  for (const record of [{ z: '10.125', a: true }, [{ reason_code: 'VENUE_PROTECTIVE_STOP' }], null]) {
    const checked = await inspectCatalogRecord(response(record), anchor, ref(record), hashBytes);
    assert.equal(canonicalJSON(checked.record), canonicalJSON(record));
  }
});

test('another anchor, producer, record id, version or digest is never substituted', async () => {
  const record = { value: 'exact' }; const reference = ref(record);
  for (const mutate of [
    (x) => { x.anchor_id = 'other-read'; }, (x) => { x.producer_id = 'other-producer'; },
    (x) => { x.reference.record_id = 'other-record'; }, (x) => { x.reference.record_version += 1; },
    (x) => { x.reference.record_sha256 = 'a'.repeat(64); },
  ]) { const result = structuredClone(response(record)); mutate(result); await assert.rejects(inspectCatalogRecord(result, anchor, reference, hashBytes)); }
});

test('matching response labels cannot hide changed canonical record bytes', async () => {
  const original = response({ quantity: '10.125' }); original.record.quantity = '100.125';
  await assert.rejects(inspectCatalogRecord(original, anchor, original.reference, hashBytes), /record bytes/);
});

test('nonfinite, fractional money numbers and oversized payloads remain unavailable', async () => {
  for (const record of [{ amount: 0.125 }, { value: NaN }, { huge: 'x'.repeat(MAX_CATALOG_RECORD_BYTES + 1) }]) {
    const r = { ...response(null), record };
    await assert.rejects(inspectCatalogRecord(r, anchor, r.reference, hashBytes));
  }
});

test('missing extension returns UNAVAILABLE and never follows locator strings', async () => {
  const result = await resolve(envelope(ref({ value: 1 })), null);
  assert.equal(result.status, 'UNAVAILABLE'); assert.equal(result.matched_count, 0);
  assert.match(result.entries[0].reason, /no resolveEvidence/);
});

test('each reference resolves through its issued anchor once and is never rewritten', async () => {
  const record = [{ command_id: 'venue-stop-digest', reason_code: 'VENUE_PROTECTIVE_STOP' }];
  const reference = ref(record); const value = envelope(reference, reference); const before = canonicalJSON(value); const calls = [];
  const result = await resolve(value, async (input) => { calls.push(input); return response(record); });
  assert.equal(calls.length, 1); assert.deepEqual(calls[0], { anchor_id: anchor.anchor_id, reference });
  assert.equal(result.status, 'MATCHED_REFERENCES'); assert.equal(result.semantic_verification, 'NOT_ESTABLISHED');
  assert.equal(canonicalJSON(value), before); assert.equal(result.entries[0].record[0].reason_code, 'VENUE_PROTECTIVE_STOP');
});

test('partial success retains individual failure reason instead of blanket verification', async () => {
  const first = ref({ value: 1 }, 'first'); const second = ref({ value: 2 }, 'second');
  const result = await resolve(envelope(first, second), async ({ reference }) => {
    if (reference.record_id === 'second') throw new Error('expired retained catalog');
    return response({ value: 1 }, first);
  });
  assert.equal(result.status, 'PARTIAL'); assert.equal(result.matched_count, 1); assert.equal(result.unavailable_count, 1);
  assert.equal(result.entries[1].reason, 'expired retained catalog'); assert.equal(result.semantic_verification, 'NOT_ESTABLISHED');
});

test('no supplied non-null references is not vacuous verified coverage', async () => {
  const result = await resolve(envelope(), async () => { throw new Error('must not call'); });
  assert.equal(result.status, 'NO_REFERENCES'); assert.ok(result.absent.length > 0);
});

test('detachment during resolution invalidates the whole in-flight result', async () => {
  let active = true;
  await assert.rejects(resolveCatalog({ envelope: envelope(ref(null)), schema, anchor, hashBytes,
    resolve: async () => { active = false; return response(null); },
    checkActive: () => { if (!active) throw new Error('detached'); },
  }), /detached/);
});

test('List and Atlas expose identical escaped catalog records and semantic limits', async () => {
  const record = { reason: '<img src=x onerror=alert(1)>', quantities: { filled: '0' }, reason_code: 'VENUE_PROTECTIVE_STOP' };
  const value = envelope(ref(record)); const catalog = await resolve(value, async () => response(record));
  const state = displayState(fixture(), 'review'); state.reviewEnvelope = { envelope: value, anchor, catalog, local: { source_binding: 'BRIDGE_ANCHOR_MATCHED', reference_resolution: catalog.status, self_consistency: 'MATCHED' } };
  const list = renderApp(state); state.reviewView = 'atlas'; const atlas = renderApp(state);
  for (const html of [list, atlas]) { assert.match(html, /record-1/); assert.match(html, /VENUE_PROTECTIVE_STOP/); assert.match(html, /&lt;img/); assert.equal(html.includes('<img'), false); assert.match(html, /Semantic validity, current state, effects and inference are not established/); }
});
