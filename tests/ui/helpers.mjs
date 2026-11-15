// Reads the actual steward-owned fixtures. Synthetic mutations below are tests, not run evidence.
import { readFile } from 'node:fs/promises';
export const schema = JSON.parse(await readFile(new URL('../../docs/contracts/cockpit.schema.json', import.meta.url), 'utf8'));
export const fixtureRaw = await readFile(new URL('../../docs/contracts/initial-cockpit.json', import.meta.url), 'utf8');
export const fixture = () => JSON.parse(fixtureRaw);
export const time = '2026-10-10T20:00:00Z';
export function sampleDecision(origin = 'SCRIPTED') {
  return {
    decision_id: 'test-decision-1',
    selection: { request_id: 'request-1', opportunity_set_id: 'set-1', source_state_id: 'state-1', selected_action_ref: null, reason: 'WAIT: observation unavailable.', evidence_ids: [] },
    provenance: { origin, adapter_id: 'test-script', request_sha256: 'a'.repeat(64), response_sha256: 'b'.repeat(64), prompt_version: 'test-1', started_at: time, completed_at: time, model_id: null, model_artifact_sha256: null, inference_receipt_id: null },
  };
}
export function sampleCommand(state = 'SUBMITTED', receipt = null) {
  return { command_id: 'command-1', payload_sha256: 'c'.repeat(64), state, last_venue_receipt_id: receipt, reservation_held: true, reason_code: null };
}
export function samplePosition() {
  return { position_id: 'position-1', version: 2, instrument_id: 'EURUSD', side: 'BUY', quantity: '10.125', entry_price: '1.12345', stop_price: null };
}
export function displayState(projection, route = 'operate') {
  return { projection, route, source: 'shared fixture', loadedAt: time, schemaReady: true, theme: 'light', error: null, loading: false, reviewView: 'list', inspection: { focus_node_id: null, hypothesis_branch_id: null }, reviewEnvelope: null, reviewIssue: null };
}
