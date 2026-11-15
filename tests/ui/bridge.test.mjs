// AUTHORED / NOT_RUN. Synthetic bridge doubles, never a real transport or model.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { ScopedBridge, inspectCommandRead } from '../../ui/src/bridge.mjs';
import { canonicalJSON } from '../../ui/src/decision-read.mjs';
import { renderApp, renderPreparedClose } from '../../ui/src/render.mjs';
import { schema, fixture, samplePosition, displayState, time } from './helpers.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const readBytes = await readFile(new URL('../../docs/contracts/decision-read.schema.json', import.meta.url));
const readSchema = JSON.parse(readBytes);
const readFixture = JSON.parse(await readFile(new URL('../../docs/contracts/initial-decision-read.json', import.meta.url), 'utf8'));
const copy = (value) => structuredClone(value);
const key = (scope) => ({ account_id: scope.account_id, run_id: scope.run_id, environment: scope.environment });
function deferred() { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; }

function rig({ withPosition = false } = {}) {
  const projection = fixture();
  if (withPosition) { projection.state_id = 'state-1'; projection.observed_at = time; projection.positions = [samplePosition()]; }
  const boot = {
    schema_version: 'forex.ui-transport/1', scope: copy(projection.scope), request_time: time, fence_generation: 4,
    capabilities: { pause: true, stop: true, resume_new_risk: true, resume_management: true, reviewed_close: true },
    decision_schema_sha256: sha(readBytes),
    fence_receipt: { key: key(projection.scope), barrier_id: 'prior-4', generation: 4, new_risk_allowed: true, management_allowed: true, venue_sequence: 7, observed_at: time, applied: true, reason_code: null },
  };
  const calls = []; const snapshots = []; let sequence = 0; let prepared;
  const bridge = {
    async readBoot() { calls.push('boot'); return copy(boot); },
    async readCockpit() { calls.push('cockpit'); return copy(projection); },
    async readDecisionRead() {
      calls.push('review');
      return { envelope: copy(readFixture), anchor: { anchor_id: 'anchor-1', producer_id: 'test-producer', schema_sha256: sha(readBytes), domain_sha256: readFixture.domain_digest, scope_sha256: sha(canonicalJSON(readFixture.scope)), cursor_sha256: sha(canonicalJSON(readFixture.cursor)), issued_at: time, expires_at: '2026-10-10T20:01:00Z', reconciliation_confirmed: false } };
    },
    async prepareControl(input) {
      calls.push('prepare-control');
      return { key: key(input.scope), barrier_id: `barrier-${input.request_id}`, control: input.control, owner_request_id: input.request_id, expected_generation: input.expected_generation, next_generation: input.expected_generation + 1, requested_at: boot.request_time };
    },
    async requestControl(request) { calls.push('request-control'); return { request_id: request.owner_request_id, status: 'ACCEPTED', reason: null }; },
    async readControl(request) {
      calls.push('read-control');
      return { ...copy(boot.fence_receipt), barrier_id: request.barrier_id, generation: request.next_generation, venue_sequence: 8, new_risk_allowed: request.control === 'RESUME_NEW_RISK', management_allowed: request.control !== 'STOP_AUTOMATION' };
    },
    async prepareClose(input) {
      calls.push('prepare-close');
      const intent = { intent_id: 'intent-1', scope: copy(input.scope), decision_id: 'owner-decision-1', opportunity_id: 'owner-opportunity-1', action_ref: 'owner-close-1', source_state: { scope: copy(input.scope), state_id: input.source_state_id, version: 1, venue_sequence: 7, observed_at: time, valid_until: '2026-10-10T20:01:00Z' }, kind: 'CLOSE', instrument_id: 'EURUSD', origin: 'OWNER_REVIEWED', created_at: time, expires_at: '2026-10-10T20:00:30Z', quantity: input.quantity, side: null, target_id: input.position_id, target_version: input.position_version, limit_price: null, stop_price: null };
      prepared = { preview_id: 'preview-1', owner_request_id: input.owner_request_id, command_id: input.command_id, scope: copy(input.scope), intent, intent_sha256: sha(canonicalJSON(intent)), expires_at: intent.expires_at };
      return copy(prepared);
    },
    async requestReviewedClose(input) { calls.push('request-close'); return { request_id: input.owner_request_id, status: 'ACCEPTED', reason: null, command: null }; },
    async readCommand(commandId) { calls.push('read-command'); return { command: null, venue_lookup: { key: key(projection.scope), command_id: commandId, state: 'UNKNOWN', observed_sequence: null, receipt: null, reason_code: 'TEST_UNAVAILABLE' } }; },
  };
  const consumer = new ScopedBridge({ cockpitSchema: schema, newId: () => `request-${++sequence}`, onChange: (snapshot) => snapshots.push(snapshot) });
  return { consumer, bridge, boot, projection, calls, snapshots, preview: () => prepared };
}

test('construction is inert and attachment only reads', async () => {
  const r = rig(); assert.deepEqual(r.calls, []); assert.equal(r.consumer.canControl('STOP_AUTOMATION'), false);
  await r.consumer.attach(r.bridge); assert.deepEqual(r.calls, ['boot', 'cockpit']);
  assert.equal(r.projection.permissions.management, 'UNKNOWN');
  assert.equal(r.consumer.canControl('PAUSE_NEW_RISK'), true);
});

test('accepted Stop stays unconfirmed until exact independent fence arrives', async () => {
  const r = rig(); const gate = deferred(); const entered = deferred();
  const originalRead = r.bridge.readControl;
  r.bridge.readControl = async (request) => { entered.resolve(); await gate.promise; return originalRead(request); };
  await r.consumer.attach(r.bridge);
  const pending = r.consumer.control('STOP_AUTOMATION'); await entered.promise;
  assert.ok(r.snapshots.some((s) => s.controls[0]?.status === 'ACCEPTED_UNCONFIRMED'));
  assert.equal(r.consumer.controls[0].status, 'READING');
  gate.resolve(); await pending;
  assert.equal(r.consumer.controls[0].status, 'CONFIRMED');
});

test('lost acknowledgement reads exact receipt without resending', async () => {
  const r = rig(); r.bridge.requestControl = async () => { r.calls.push('request-control'); throw new Error('lost ACK'); };
  await r.consumer.attach(r.bridge); await r.consumer.control('STOP_AUTOMATION');
  assert.equal(r.consumer.controls[0].status, 'CONFIRMED');
  assert.equal(r.calls.filter((c) => c === 'request-control').length, 1);
  assert.equal(r.calls.filter((c) => c === 'read-control').length, 1);
});

test('newer fence with stopped flags does not confirm requested barrier', async () => {
  const r = rig(); const read = r.bridge.readControl;
  r.bridge.readControl = async (request) => ({ ...await read(request), barrier_id: 'different-barrier', generation: request.next_generation + 1 });
  await r.consumer.attach(r.bridge); await r.consumer.control('STOP_AUTOMATION');
  assert.equal(r.consumer.controls[0].status, 'UNCONFIRMED');
});

test('Pause preserves independently read management, even with unknown core grant', async () => {
  const r = rig(); await r.consumer.attach(r.bridge); await r.consumer.control('PAUSE_NEW_RISK');
  assert.equal(r.consumer.controls[0].status, 'CONFIRMED');
  assert.equal(r.consumer.controls[0].expected.management_allowed, true);
});

test('next explicit Stop uses the independently observed Pause generation', async () => {
  const r = rig(); await r.consumer.attach(r.bridge); await r.consumer.control('PAUSE_NEW_RISK');
  await r.consumer.control('STOP_AUTOMATION');
  assert.equal(r.consumer.controls[0].request.expected_generation, 4);
  assert.equal(r.consumer.controls[1].request.expected_generation, 5);
  assert.equal(r.consumer.controls[1].status, 'CONFIRMED');
});

test('null fence disables control without inventing a generation', async () => {
  const r = rig(); r.boot.fence_generation = null; r.boot.fence_receipt = null;
  await r.consumer.attach(r.bridge); await assert.rejects(r.consumer.control('STOP_AUTOMATION'), /unavailable/);
  assert.equal(r.calls.includes('prepare-control'), false);
});

test('prepared scope mismatch fails before dispatch', async () => {
  const r = rig(); const prepare = r.bridge.prepareControl;
  r.bridge.prepareControl = async (input) => { const result = await prepare(input); result.key.account_id = 'other-account'; return result; };
  await r.consumer.attach(r.bridge); await assert.rejects(r.consumer.control('STOP_AUTOMATION'), /differs/);
  assert.equal(r.calls.includes('request-control'), false);
});

test('detaching while preparation waits prevents later dispatch', async () => {
  const r = rig(); const gate = deferred(); const entered = deferred(); const prepare = r.bridge.prepareControl;
  r.bridge.prepareControl = async (input) => { entered.resolve(); await gate.promise; return prepare(input); };
  await r.consumer.attach(r.bridge); const pending = r.consumer.control('STOP_AUTOMATION'); await entered.promise;
  r.consumer.detach(); gate.resolve(); await assert.rejects(pending, /detached/);
  assert.equal(r.calls.includes('request-control'), false);
});

test('scope remains pinned after a failed refresh clears the displayed projection', async () => {
  const r = rig(); await r.consumer.attach(r.bridge);
  const original = r.bridge.readCockpit; r.bridge.readCockpit = async () => { throw new Error('read failed'); };
  await assert.rejects(r.consumer.refresh(), /read failed/);
  r.bridge.readCockpit = original; r.boot.scope.epoch += 1;
  await assert.rejects(r.consumer.refresh(), /scope cannot change/);
});

test('Close preparation requires a separate explicit reviewed submission', async () => {
  const r = rig({ withPosition: true }); await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1');
  assert.equal(r.consumer.close.status, 'REVIEW_REQUIRED'); assert.equal(r.calls.includes('request-close'), false);
  assert.equal(r.consumer.close.preview.intent.quantity, '10.125');
  const html = renderPreparedClose(r.consumer.snapshot());
  assert.match(html, /10.125 BASE_UNITS/); assert.match(html, /data-submit-close="preview-1"/);
  assert.match(html, /data-request-control="STOP_AUTOMATION"/);
  await r.consumer.submitClose('preview-1');
  assert.equal(r.consumer.close.status, 'UNKNOWN'); assert.equal(r.calls.includes('read-command'), true);
});

test('Close cannot be submitted twice or silently replaced while effect is unknown', async () => {
  const r = rig({ withPosition: true }); await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1'); await r.consumer.submitClose('preview-1');
  await assert.rejects(r.consumer.submitClose('preview-1'), /already submitted/);
  await assert.rejects(r.consumer.prepareClose('position-1'), /unavailable/);
  assert.equal(r.calls.filter((c) => c === 'request-close').length, 1);
});

test('expired synthetic-clock preview is not silently rebuilt or dispatched', async () => {
  const r = rig({ withPosition: true }); await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1');
  r.boot.request_time = '2026-10-10T20:00:30Z';
  await assert.rejects(r.consumer.submitClose('preview-1'), /expired/);
  assert.equal(r.calls.includes('request-close'), false); assert.equal(r.calls.filter((c) => c === 'prepare-close').length, 1);
  assert.equal(r.consumer.canClose(), true); // A fresh review must still be explicitly requested.
});

test('changed exact Close quantity is rejected even with a matching replacement hash', async () => {
  const r = rig({ withPosition: true }); const prepare = r.bridge.prepareClose;
  r.bridge.prepareClose = async (input) => { const result = await prepare(input); result.intent.quantity = '11'; result.intent_sha256 = sha(canonicalJSON(result.intent)); return result; };
  await r.consumer.attach(r.bridge); await assert.rejects(r.consumer.prepareClose('position-1'), /changed exact target/);
  assert.equal(r.calls.includes('request-close'), false);
});

test('Close ACK loss still reads the one command and never retries submission', async () => {
  const r = rig({ withPosition: true }); r.bridge.requestReviewedClose = async () => { r.calls.push('request-close'); throw new Error('ACK lost'); };
  await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1'); await r.consumer.submitClose('preview-1'); await r.consumer.checkClose();
  assert.equal(r.consumer.close.status, 'UNKNOWN'); assert.equal(r.calls.filter((c) => c === 'request-close').length, 1); assert.equal(r.calls.filter((c) => c === 'read-command').length, 2);
});

function filledRead(preview) {
  const receipt = { key: key(preview.scope), receipt_id: 'receipt-1', command_id: preview.command_id, payload_sha256: preview.intent_sha256, effect: 'CANCELLED', venue_sequence: 20, dispatch_generation: 5, observed_at: time, quantities: { ordered: '10.125', filled: '4', cancelled: '6.125', rejected: '0', remaining: '0' }, position_id: 'position-1', reason_code: null };
  return { command: null, venue_lookup: { key: key(preview.scope), command_id: preview.command_id, state: 'FOUND', observed_sequence: 20, receipt, reason_code: null } };
}

test('mixed cancellation keeps cumulative filled and cancelled quantities separate', async () => {
  const r = rig({ withPosition: true }); await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1');
  const result = inspectCommandRead(filledRead(r.preview()), r.preview(), schema);
  assert.equal(result.status, 'CANCELLED'); assert.equal(result.receipt.quantities.filled, '4'); assert.equal(result.receipt.quantities.cancelled, '6.125');
});

test('wrong command, target, cursor and nonconserving receipt cannot establish effects', async () => {
  const r = rig({ withPosition: true }); await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1');
  for (const mutate of [
    (x) => { x.venue_lookup.receipt.command_id = 'other'; },
    (x) => { x.venue_lookup.receipt.position_id = 'other'; },
    (x) => { x.venue_lookup.observed_sequence = 19; },
    (x) => { x.venue_lookup.receipt.quantities.filled = '5'; },
  ]) { const result = filledRead(r.preview()); mutate(result); assert.throws(() => inspectCommandRead(result, r.preview(), schema)); }
});

test('NOT_FOUND requires a successful cursor and never means a close was filled', async () => {
  const r = rig({ withPosition: true }); await r.consumer.attach(r.bridge); await r.consumer.prepareClose('position-1');
  const result = { command: null, venue_lookup: { key: key(r.boot.scope), command_id: r.preview().command_id, state: 'NOT_FOUND', observed_sequence: 0, receipt: null, reason_code: null } };
  assert.equal(inspectCommandRead(result, r.preview(), schema).status, 'NOT_FOUND'); result.venue_lookup.observed_sequence = null;
  assert.throws(() => inspectCommandRead(result, r.preview(), schema), /cursor/);
});

test('raw schema byte pin and attached anchor match do not claim catalog resolution', async () => {
  const r = rig(); await r.consumer.attach(r.bridge);
  const read = await r.consumer.readReview(readSchema, readBytes);
  assert.equal(read.local.source_binding, 'BRIDGE_ANCHOR_MATCHED'); assert.equal(read.local.reference_resolution, 'UNAVAILABLE');
  await assert.rejects(r.consumer.readReview(readSchema, new TextEncoder().encode(JSON.stringify(readSchema))), /schema pin/);
});

test('self-consistent envelope with different anchor scope is rejected', async () => {
  const r = rig(); const read = r.bridge.readDecisionRead;
  r.bridge.readDecisionRead = async () => { const result = await read(); result.anchor.scope_sha256 = 'a'.repeat(64); return result; };
  await r.consumer.attach(r.bridge); await assert.rejects(r.consumer.readReview(readSchema, readBytes), /scope\/cursor mismatch/);
});

test('expired anchor uses authoritative simulator clock, not browser time', async () => {
  const r = rig(); await r.consumer.attach(r.bridge); r.boot.request_time = '2026-10-10T20:01:00Z';
  await assert.rejects(r.consumer.readReview(readSchema, readBytes), /not valid/);
});

function addCatalog(r, record) {
  const reference = { record_id: 'catalog-item', record_version: 1, record_sha256: sha(canonicalJSON(record)), unavailable_reason: null };
  const original = r.bridge.readDecisionRead;
  r.bridge.readDecisionRead = async () => {
    const result = await original(); result.envelope.current_state.observation_refs = [reference];
    const { domain_digest: _digest, ...semantic } = result.envelope;
    result.envelope.domain_digest = sha(canonicalJSON(semantic)); result.anchor.domain_sha256 = result.envelope.domain_digest;
    return result;
  };
  r.bridge.resolveEvidence = async ({ anchor_id, reference: requested }) => {
    r.calls.push('catalog');
    return { schema_version: 'forex.catalog-record/1', anchor_id, producer_id: 'test-producer', reference: requested, record };
  };
}

test('optional catalog extension is consumed only after anchor binding and keeps semantic limits', async () => {
  const r = rig(); addCatalog(r, [{ reason_code: 'VENUE_PROTECTIVE_STOP' }]);
  await r.consumer.attach(r.bridge); const read = await r.consumer.readReview(readSchema, readBytes);
  assert.equal(read.local.reference_resolution, 'MATCHED_REFERENCES'); assert.equal(read.catalog.matched_count, 1);
  assert.equal(read.local.semantic_verification, 'NOT_ESTABLISHED'); assert.equal(r.calls.filter((call) => call === 'catalog').length, 1);
  assert.equal(read.catalog.entries[0].record[0].reason_code, 'VENUE_PROTECTIVE_STOP');
});

test('anchor expiry while resolving catalog rejects the completed read', async () => {
  const r = rig(); addCatalog(r, { value: 1 }); const resolve = r.bridge.resolveEvidence;
  r.bridge.resolveEvidence = async (input) => { r.boot.request_time = '2026-10-10T20:01:00Z'; return resolve(input); };
  await r.consumer.attach(r.bridge); await assert.rejects(r.consumer.readReview(readSchema, readBytes), /expired during catalog/);
});

test('clock receipt changes on a new boot read even when source JSON is identical', async () => {
  const r = rig(); let monotonic = 100;
  const consumer = new ScopedBridge({ cockpitSchema: schema, monotonicNow: () => monotonic });
  await consumer.attach(r.bridge); const before = consumer.snapshot();
  monotonic = 50100; await consumer.refresh(); const after = consumer.snapshot();
  assert.equal(after.clock.request_time, before.clock.request_time);
  assert.equal(after.clock.received_at_monotonic_ms, 50100);
  assert.equal(canonicalJSON(after.projection), canonicalJSON(before.projection));
  consumer.invalidateReadAge(); assert.equal(consumer.snapshot().clock.invalidated, true);
  await consumer.refresh(); assert.equal(consumer.snapshot().clock.invalidated, false);
  consumer.detach(); assert.equal(consumer.snapshot().clock, null);
});

test('control readback does not refresh the held authoritative clock age', async () => {
  const r = rig(); let monotonic = 100;
  const consumer = new ScopedBridge({ cockpitSchema: schema, newId: () => 'clock-age-test', monotonicNow: () => monotonic });
  await consumer.attach(r.bridge); monotonic = 20000;
  await consumer.control('PAUSE_NEW_RISK');
  assert.equal(consumer.snapshot().clock.received_at_monotonic_ms, 100);
});

test('every page exposes interruption controls while imports cannot replace attached data', async () => {
  const r = rig(); await r.consumer.attach(r.bridge);
  for (const route of ['operate', 'review', 'setup']) {
    const state = displayState(r.consumer.projection, route); state.transport = r.consumer.snapshot(); state.source = 'scoped simulator';
    const html = renderApp(state); assert.match(html, /data-request-control="STOP_AUTOMATION"/); assert.match(html, /Disconnected simulator/);
    if (route === 'setup') assert.match(html, /id="snapshot-file"[^>]*disabled/);
  }
});
