import test from 'node:test';
import assert from 'node:assert/strict';
import { compareFenceReadback } from '../../ui/src/control-observation.mjs';

const key = { account_id: 'account-1', run_id: 'run-1', environment: 'DISCONNECTED_SIMULATION' };
const request = { key, barrier_id: 'barrier-1', owner_request_id: 'owner-request-1', control: 'STOP_AUTOMATION', expected_generation: 2, next_generation: 3, requested_at: '2026-10-10T20:00:00Z' };
const observed = { key, barrier_id: 'barrier-1', generation: 3, new_risk_allowed: false, management_allowed: false, venue_sequence: 7, observed_at: '2026-10-10T20:00:01Z', applied: true, reason_code: null };
const expected = { new_risk_allowed: false, management_allowed: false };

test('request acceptance without independent fence cannot match', () => {
  assert.equal(compareFenceReadback(request, null, expected).matches, false);
});
test('exact independent fence comparison retains both stopped permissions', () => {
  assert.equal(compareFenceReadback(request, observed, expected).matches, true);
});
test('newer barrier never silently confirms the older control', () => {
  assert.equal(compareFenceReadback(request, { ...observed, barrier_id: 'barrier-2', generation: 4 }, expected).matches, false);
});
test('cross-account, false application and stale observation stay unconfirmed', () => {
  for (const receipt of [ { ...observed, key: { ...key, account_id: 'other' } }, { ...observed, applied: false }, { ...observed, observed_at: '2026-10-10T19:59:59Z' } ]) assert.equal(compareFenceReadback(request, receipt, expected).matches, false);
});
test('Pause preserves only the separately expected management result', () => {
  const pause = { ...request, control: 'PAUSE_NEW_RISK' };
  const expectedPause = { new_risk_allowed: false, management_allowed: true };
  assert.equal(compareFenceReadback(pause, observed, expectedPause).matches, false);
  assert.equal(compareFenceReadback(pause, { ...observed, management_allowed: true }, expectedPause).matches, true);
});
test('future generation gaps, missing expected permissions and partial Stop fail', () => {
  assert.equal(compareFenceReadback({ ...request, next_generation: 5 }, { ...observed, generation: 5 }, expected).matches, false);
  assert.equal(compareFenceReadback(request, observed, null).matches, false);
  assert.equal(compareFenceReadback(request, { ...observed, management_allowed: true }, { new_risk_allowed: false, management_allowed: true }).matches, false);
});
