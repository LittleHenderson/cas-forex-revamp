import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { assertSchema } from '../../ui/src/wire.mjs';
import { decodeDecisionRead, semanticBytes, canonicalJSON, assertDecisionReadSemantics, envelopeRecords } from '../../ui/src/decision-read.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { fixture, displayState, time } from './helpers.mjs';

const readSchema = JSON.parse(await readFile(new URL('../../docs/contracts/decision-read.schema.json', import.meta.url), 'utf8'));
const readRaw = await readFile(new URL('../../docs/contracts/initial-decision-read.json', import.meta.url), 'utf8');
const canonicalFixture = await readFile(new URL('../../docs/contracts/initial-decision-read.canonical.json', import.meta.url));
const envelope = () => JSON.parse(readRaw);
const rehash = (value) => { value.domain_digest = createHash('sha256').update(semanticBytes(value)).digest('hex'); return JSON.stringify(value); };
const unavailable = () => ({ record_id: null, record_version: null, record_sha256: null, unavailable_reason: 'Not observed in authored test.' });
const parameters = () => ({ quantity: null, quantity_unit: 'BASE_UNITS', side: null, limit_price: null, stop_price: null, quote_currency: 'USD' });
function episode() {
  const p = fixture(); p.state_id = 'state-1'; p.observed_at = time;
  const view = envelope();
  view.cursor = { sequence: 1, ledger_prefix_sha256: 'a'.repeat(64), current_state_revision: 1, read_model_version: 'forex.decision-read/0.1' };
  Object.assign(view.current_state, { state_id: 'state-1', state_sha256: 'b'.repeat(64), revision: 1, observed_at: time });
  Object.assign(view.as_of, { observed_at: time, available_at: time, generated_at: time });
  view.decisions = [{
    decision_id: 'decision-1', revision: 0, decision_kind: 'entry', scope: structuredClone(view.scope), cursor: structuredClone(view.cursor),
    observation_set_sha256: 'c'.repeat(64), decided_at: time, opportunity_set_id: 'opportunity-1', opportunity_set_version: 1, opportunity_set_sha256: 'd'.repeat(64),
    candidates: [{ candidate_id: 'hold-1', strategy_id: 'strategy-a', strategy_version: '1', instrument_id: 'EURUSD', timeframe: 'H1', action_kind: 'HOLD', target: unavailable(), proposed_parameters: parameters(), preconditions: [], known_facts: [], assumptions: [], reason_ids: [], evidence_ids: [], evaluation: 'evaluated', eligibility: 'eligible', disposition: 'not_selected', status_event_ref: unavailable(), uncertainty: [] }],
    coverage: structuredClone(view.coverage),
    origin: { kind: 'scripted', provider: null, model_id: null, model_artifact_sha256: null, adapter_id: 'scripted-1', prompt_version: '1', policy_version: '1', request_sha256: 'e'.repeat(64), response_sha256: 'f'.repeat(64), invocation_sha256: null, effective_reasoning: null, started_at: time, completed_at: time, latency_ms: null, inference_receipt: unavailable(), budget_receipt: unavailable() },
    selection: { candidate_id: null, wait: true, public_rationale: 'WAIT while required observations are unavailable.', evidence_ids: [], reason_ids: [], unresolved_questions: [], proposed_bounds: parameters(), source_state_id: 'state-1', source_state_revision: 1, target: unavailable() },
    decision_status: 'proposed', status_reason: 'Scripted test selection only.', status_event_ref: unavailable(), admission_ref: unavailable(), intent_ref: unavailable(), dispatch_ref: unavailable(), outcome_refs: [], revision_of: unavailable(), revision_trigger_refs: [], superseded_by: unavailable(),
  }];
  view.coverage.retained_count = 1;
  return { p, view };
}

test('shared canonical bytes match without changing the steward fixture', () => {
  assert.deepEqual(Buffer.from(semanticBytes(envelope())), canonicalFixture);
});
test('initial empty/incomplete shared read remains unverified', async () => {
  const read = await decodeDecisionRead(readRaw, readSchema, fixture());
  assert.equal(read.envelope.coverage.complete, false);
  assert.equal(read.envelope.coverage.total_known_count, null);
  assert.equal(read.local.self_consistency, 'MATCHED');
  assert.equal(read.local.source_binding, 'UNVERIFIED');
  assert.equal(read.local.reference_resolution, 'UNAVAILABLE');
  assert.ok(Object.isFrozen(read.envelope.current_state));
});
test('changed semantics without new digest are rejected', async () => {
  const view = envelope(); view.coverage.reasons = ['Altered'];
  await assert.rejects(() => decodeDecisionRead(JSON.stringify(view), readSchema, fixture()), /digest/);
});
test('recomputed hash and supplied PASS cannot appoint a trusted verifier', async () => {
  const view = envelope(); view.validation.source_binding.status = 'PASS'; view.validation.source_binding.verifier_id = 'self-appointed';
  const read = await decodeDecisionRead(rehash(view), readSchema, fixture());
  assert.equal(read.local.source_binding, 'UNVERIFIED');
  assert.equal(read.envelope.validation.source_binding.status, 'PASS');
});
test('wrong run and wrong state cannot overwrite selected cockpit scope', async () => {
  const view = envelope(); view.scope.run_id = 'other-run';
  await assert.rejects(() => decodeDecisionRead(rehash(view), readSchema, fixture()), /run_id/);
  view.scope.run_id = fixture().scope.run_id; view.current_state.state_id = 'other-state';
  await assert.rejects(() => decodeDecisionRead(rehash(view), readSchema, fixture()), /state differs/);
});
test('newer page generation does not repair reversed observation times', () => {
  const view = envelope(); view.as_of.observed_at = '2026-10-10T20:01:00Z'; view.as_of.available_at = time;
  assert.throws(() => assertDecisionReadSemantics(view, fixture()), /times/);
});
test('missing reference reason cannot look like a resolved record', () => {
  const view = envelope(); view.current_state.permissions.fence_ref.unavailable_reason = '';
  assert.throws(() => assertDecisionReadSemantics(view, fixture()), /reference/);
});
test('complete claim with unknown totals and omitted records is rejected', () => {
  const view = envelope(); view.coverage.complete = true;
  assert.throws(() => assertDecisionReadSemantics(view, fixture()), /Complete coverage/);
});
test('scripted decision keeps unchosen eligible candidate and explicit WAIT', async () => {
  const { p, view } = episode();
  const read = await decodeDecisionRead(rehash(view), readSchema, p);
  const candidate = read.envelope.decisions[0].candidates[0];
  assert.equal(candidate.eligibility, 'eligible'); assert.equal(candidate.disposition, 'not_selected');
  assert.equal(read.envelope.decisions[0].selection.wait, true);
});
test('candidate selection cannot relabel or change exact geometry', () => {
  const { p, view } = episode(); const d = view.decisions[0];
  d.selection.wait = false; d.selection.candidate_id = 'hold-1';
  assert.throws(() => assertDecisionReadSemantics(view, p), /disposition/);
  d.candidates[0].disposition = 'selected'; d.selection.proposed_bounds.quantity = '4';
  assert.throws(() => assertDecisionReadSemantics(view, p), /parameters/);
});
test('missing inference is not silently converted to WAIT or actual-model proof', () => {
  const { p, view } = episode(); view.decisions[0].origin.kind = 'actual-inference';
  assert.throws(() => assertDecisionReadSemantics(view, p), /incomplete/);
});
test('missing evidence cannot masquerade as a resolved reference', () => {
  const { p, view } = episode(); view.decisions[0].selection.evidence_ids = ['fabricated-evidence'];
  assert.throws(() => assertDecisionReadSemantics(view, p), /unresolved ID/);
});
test('same-source List and Atlas retain full candidate facts and statuses', async () => {
  const { p, view } = episode(); const read = await decodeDecisionRead(rehash(view), readSchema, p);
  const state = displayState(p, 'review'); state.reviewEnvelope = read;
  const before = canonicalJSON(read.envelope); state.inspection.focus_node_id = envelopeRecords(read)[0].id;
  const list = renderApp(state); state.reviewView = 'atlas'; const atlas = renderApp(state);
  for (const html of [list, atlas]) { assert.match(html, /evaluated \/ eligible \/ not_selected/); assert.match(html, /source unverified/); assert.match(html, /Full immutable source record/); }
  assert.equal(canonicalJSON(read.envelope), before);
});
test('oversize Atlas reports limitation and leaves full List available', () => {
  const view = envelope(); view.events = Array.from({ length: 65 }, (_, index) => ({ event_id: `e-${index}`, event_kind: 'CONTROL', public_summary: 'Supplied test record', effect: null }));
  const state = displayState(fixture(), 'review'); state.reviewView = 'atlas';
  state.reviewEnvelope = { envelope: view, local: { self_consistency: 'NOT_CHECKED', source_binding: 'UNVERIFIED', reference_resolution: 'UNAVAILABLE' } };
  const html = renderApp(state); assert.match(html, /65 records exceed/); assert.match(html, /Use List/);
  state.reviewView = 'list'; assert.equal((renderApp(state).match(/data-record=/g) ?? []).length, 65);
});
test('semantic snapshots reject supplied external URLs as locator structure', () => {
  const view = envelope(); view.evidence = [{ url: 'https://hostile.test' }];
  assert.throws(() => assertSchema(view, readSchema));
});
test('review byte limit is separate from cockpit limit', async () => {
  await assert.rejects(() => decodeDecisionRead(' '.repeat(1048577), readSchema, fixture()), /byte limit/);
});
