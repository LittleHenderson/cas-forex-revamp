import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeCockpit, parseUniqueJSON, assertSchema, decimalCoefficient, isUTCTimestamp, utcMicroseconds } from '../../ui/src/wire.mjs';
import { schema, fixture, fixtureRaw, sampleDecision, samplePosition } from './helpers.mjs';

test('actual shared fixture retains unknown values and disabled admissions', () => {
  const p = decodeCockpit(fixtureRaw, schema);
  assert.equal(p.positions, null);
  assert.equal(p.balance, null);
  assert.equal(p.permissions.management, 'UNKNOWN');
  assert.equal(p.admissions_enabled, false);
  assert.ok(Object.isFrozen(p.scope));
});
test('duplicate keys cannot overwrite state, including escaped equivalent keys', () => {
  assert.throws(() => parseUniqueJSON('{"state_id":null,"state_id":"fake"}'), /Duplicate/);
  assert.throws(() => parseUniqueJSON('{"a":0,"\\u0061":1}'), /Duplicate/);
});
test('nested duplicates fail instead of returning a repaired projection', () => {
  assert.throws(() => parseUniqueJSON('{"p":{"a":0,"a":1}}'), /Duplicate/);
});
test('malformed and oversized input fails', () => {
  for (const raw of ['{"a":1,}', '[1,]', 'null null', '{', 'NaN', 'Infinity', '01', '']) assert.throws(() => parseUniqueJSON(raw));
  assert.throws(() => parseUniqueJSON(' '.repeat(524289)), /byte limit/);
  assert.throws(() => parseUniqueJSON('['.repeat(34) + '0' + ']'.repeat(34)), /complexity/);
});
test('unsafe integers and numeric amounts are rejected', () => {
  assert.throws(() => parseUniqueJSON('9007199254740993'), /safe integers/);
  const p = fixture(); p.balance = { amount: 10.25, currency: 'USD' };
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
});
test('shared schema admits normal fractional decimal strings', () => {
  const p = fixture(); p.balance = { amount: '1234.125', currency: 'USD' }; p.positions = [samplePosition()];
  const decoded = decodeCockpit(JSON.stringify(p), schema);
  assert.equal(decoded.balance.amount, '1234.125');
  assert.equal(decoded.positions[0].quantity, '10.125');
});
test('decimal precision survives beyond JavaScript floating point', () => {
  assert.equal(decimalCoefficient('999999999999999999.123456789012'), 999999999999999999123456789012n);
  for (const amount of ['1e2', 'NaN', '1000000000000000000', '1.0000000000001', '01', '1\\x1']) assert.throws(() => decimalCoefficient(amount));
});
test('schema rejects extra fields and live environments', () => {
  const p = fixture(); p.execute = true;
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema), /unsupported field/);
  delete p.execute; p.scope.environment = 'LIVE';
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
});
test('schema evolution cannot silently relax a new keyword', () => {
  assert.throws(() => assertSchema({}, { type: 'object', unevaluatedProperties: false }), /Unsupported schema keyword/);
});
test('known permission requires barrier identity and generation', () => {
  const p = fixture(); p.permissions.management = 'STOPPED';
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema), /barrier/);
});
test('local enabled flag cannot make an unobserved snapshot admissible', () => {
  const p = fixture(); p.admissions_enabled = true;
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema), /coherent/);
});
test('UTC validation rejects impossible dates and local clock strings', () => {
  assert.equal(isUTCTimestamp('2026-02-30T12:00:00Z'), false);
  assert.equal(isUTCTimestamp('2026-10-10T12:00:00'), false);
  assert.equal(isUTCTimestamp('2026-10-10T12:00:00-07:00'), false);
  assert.equal(isUTCTimestamp('2026-10-10T12:00:00.123456Z'), true);
});
test('negative quantity, zero entry and repeated targets fail', () => {
  const p = fixture(); p.positions = [samplePosition()];
  p.positions[0].quantity = '-1'; assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
  p.positions[0].quantity = '1'; p.positions[0].entry_price = '0'; assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
  p.positions = [samplePosition(), samplePosition()]; assert.throws(() => decodeCockpit(JSON.stringify(p), schema), /duplicate/);
});
test('model labels without artifact and receipt cannot satisfy provenance', () => {
  const p = fixture(); p.last_decision = sampleDecision('ACTUAL_MODEL');
  p.last_decision.provenance.model_id = 'named-model';
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema), /provenance/);
});
test('rationale UTF-8 byte cap and invalid Unicode are enforced', () => {
  const p = fixture(); p.last_decision = sampleDecision(); p.last_decision.selection.reason = '😀'.repeat(257);
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
  p.last_decision.selection.reason = '\uD800'; assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
});
test('WAIT is explicit null, not missing malformed response repair', () => {
  const p = fixture(); p.last_decision = sampleDecision();
  assert.equal(decodeCockpit(JSON.stringify(p), schema).last_decision.selection.selected_action_ref, null);
  delete p.last_decision.selection.selected_action_ref;
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema));
});
test('sub-millisecond reversal is not rounded away', () => {
  const p = fixture(); p.last_decision = sampleDecision();
  p.last_decision.provenance.started_at = '2026-10-10T20:00:00.000002Z';
  p.last_decision.provenance.completed_at = '2026-10-10T20:00:00.000001Z';
  assert.throws(() => decodeCockpit(JSON.stringify(p), schema), /precedes/);
  assert.equal(utcMicroseconds('2026-10-10T20:00:00.000002Z') - utcMicroseconds('2026-10-10T20:00:00.000001Z'), 1n);
});
