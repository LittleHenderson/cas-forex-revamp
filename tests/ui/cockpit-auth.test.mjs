// Phase 6 Finding [9] regression suite: session_epoch rotation & authenticated loopback RPC client.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { ScopedBridge, createAuthenticatedLoopbackBridge } from '../../ui/src/bridge.mjs';
import { canonicalJSON } from '../../ui/src/decision-read.mjs';
import { schema, fixture, samplePosition, time } from './helpers.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const readBytes = await readFile(new URL('../../docs/contracts/decision-read.schema.json', import.meta.url));
const copy = (value) => structuredClone(value);
const key = (scope) => ({ account_id: scope.account_id, run_id: scope.run_id, environment: scope.environment });

function sessionRig(initialEpoch = 'epoch-initial-0001') {
  const projection = fixture();
  projection.state_id = 'state-1';
  projection.observed_at = time;
  projection.positions = [samplePosition()];
  const boot = {
    schema_version: 'forex.ui-transport/1',
    session_epoch: initialEpoch,
    scope: copy(projection.scope),
    request_time: time,
    fence_generation: 4,
    capabilities: { pause: true, stop: true, resume_new_risk: true, resume_management: true, reviewed_close: true },
    decision_schema_sha256: sha(readBytes),
    fence_receipt: { key: key(projection.scope), barrier_id: 'prior-4', generation: 4, new_risk_allowed: true, management_allowed: true, venue_sequence: 7, observed_at: time, applied: true, reason_code: null },
  };
  const calls = [];
  let seq = 0;
  const bridge = {
    async readBoot() { calls.push('boot'); return copy(boot); },
    async readCockpit() { calls.push('cockpit'); return copy(projection); },
    async readDecisionRead() { throw new Error('unused'); },
    async prepareControl() { throw new Error('unused'); },
    async requestControl() { throw new Error('unused'); },
    async readControl() { throw new Error('unused'); },
    async prepareClose(input) {
      calls.push('prepare-close');
      const intent = { intent_id: 'intent-1', scope: copy(input.scope), decision_id: 'owner-decision-1', opportunity_id: 'owner-opportunity-1', action_ref: 'owner-close-1', source_state: { scope: copy(input.scope), state_id: input.source_state_id, version: 1, venue_sequence: 7, observed_at: time, valid_until: '2026-10-10T20:01:00Z' }, kind: 'CLOSE', instrument_id: 'EURUSD', origin: 'OWNER_REVIEWED', created_at: time, expires_at: '2026-10-10T20:00:30Z', quantity: input.quantity, side: null, target_id: input.position_id, target_version: input.position_version, limit_price: null, stop_price: null };
      return { preview_id: 'preview-1', owner_request_id: input.owner_request_id, command_id: input.command_id, scope: copy(input.scope), intent, intent_sha256: sha(canonicalJSON(intent)), expires_at: intent.expires_at };
    },
    async requestReviewedClose() { calls.push('request-close'); return { request_id: 'x', status: 'ACCEPTED', reason: null, command: null }; },
    async readCommand() { throw new Error('unused'); },
  };
  const consumer = new ScopedBridge({ cockpitSchema: schema, newId: () => `req-${++seq}` });
  return { consumer, bridge, boot, calls };
}

test('session_epoch rotation invalidates refresh and prepared Close across adapter restarts', async () => {
  const r = sessionRig();
  await r.consumer.attach(r.bridge);
  await r.consumer.prepareClose('position-1');
  assert.equal(r.consumer.close.status, 'REVIEW_REQUIRED');
  r.boot.session_epoch = 'epoch-rotated-0002';
  await assert.rejects(r.consumer.submitClose('preview-1'), /session epoch rotated/);
  assert.equal(r.calls.includes('request-close'), false);
  await assert.rejects(r.consumer.refresh(), /session epoch rotated/);
});

test('createAuthenticatedLoopbackBridge attaches Bearer header and rejects non-loopback origins', async () => {
  assert.throws(() => createAuthenticatedLoopbackBridge({ baseUrl: 'https://evil.example:8443', authToken: 'a'.repeat(32) }), /loopback origin/);
  const seen = [];
  const fakeFetch = async (url, init) => {
    seen.push({ url: String(url), auth: init.headers?.Authorization ?? null, credentials: init.credentials, method: init.method });
    return { ok: true, status: 200, async text() { return '{"ok":1}'; } };
  };
  const client = createAuthenticatedLoopbackBridge({ baseUrl: 'http://127.0.0.1:43111', authToken: 'tok_' + 'x'.repeat(32), fetchImpl: fakeFetch });
  const res = await client.prepareControl({ request_id: 'r1' });
  assert.equal(res.ok, 1);
  assert.equal(seen[0].auth, 'Bearer tok_' + 'x'.repeat(32));
  assert.equal(seen[0].credentials, 'same-origin');
  assert.equal(seen[0].method, 'POST');
});
