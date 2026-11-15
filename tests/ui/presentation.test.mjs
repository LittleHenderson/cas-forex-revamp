import test from 'node:test';
import assert from 'node:assert/strict';
import { moneyLabel, positionSummary, observationAge, commandEffect, decisionIdentity, reviewRecords, inspectRecord, resetInspection, closeReview, pendingEffects } from '../../ui/src/model.mjs';
import { renderApp, renderControlDialog, renderCloseDialog, escapeHTML } from '../../ui/src/render.mjs';
import { fixture, sampleDecision, samplePosition, sampleCommand, displayState, time } from './helpers.mjs';

test('unknown money and inventory never become zero or flat', () => {
  assert.equal(moneyLabel(null).amount, 'Unknown');
  assert.equal(positionSummary(fixture()), 'Inventory unknown');
  const p = fixture(); p.positions = [];
  assert.equal(positionSummary(p), 'No positions in this snapshot');
});
test('money formatting uses exact strings', () => {
  assert.deepEqual(moneyLabel({ amount: '999999999999999999.123456789012', currency: 'USD' }), { amount: '999,999,999,999,999,999.123456789012', unit: 'USD' });
});
test('age is unknown or measured, never an invented freshness grant', () => {
  assert.equal(observationAge(null).label, 'Not observed');
  assert.equal(observationAge(time, Date.parse(time) - 1).label, 'Future timestamp');
  const age = observationAge(time, Date.parse(time) + 90000);
  assert.equal(age.label, '1m old'); assert.match(age.detail, /Validity unavailable/);
});
test('observed core state and referenced receipt do not imply fill', () => {
  assert.equal(commandEffect(sampleCommand('OBSERVED', 'receipt-1')), 'Receipt referenced · effect unverified');
  assert.equal(commandEffect(sampleCommand('SUBMITTED')), 'Venue effect unknown');
});
test('pending and unresolved IDs remain visible without double counting', () => {
  const p = fixture(); p.commands = [sampleCommand()]; p.unresolved_command_ids = ['command-1', 'unknown-2'];
  assert.deepEqual(pendingEffects(p), ['command-1', 'unknown-2']);
});
test('named model and receipt reference are still unverified display claims', () => {
  const d = sampleDecision('ACTUAL_MODEL'); d.provenance.model_id = 'model-a'; d.provenance.inference_receipt_id = 'receipt-a';
  assert.match(decisionIdentity(d).origin, /reported/);
  assert.match(decisionIdentity(d).verification, /independent validation unavailable/);
});
test('focus and layout cannot change source or current state', () => {
  const p = fixture(); p.last_decision = sampleDecision(); p.state_id = 'current-1';
  const before = JSON.stringify(p); const records = reviewRecords(p);
  const view = inspectRecord(resetInspection(), records[0].id, records);
  assert.equal(view.focus_node_id, 'decision:test-decision-1');
  assert.equal(view.hypothesis_branch_id, null); assert.equal(p.state_id, 'current-1');
  assert.equal(JSON.stringify(p), before); assert.ok(Object.isFrozen(records));
  assert.throws(() => inspectRecord(view, 'missing', records));
});
test('List and Atlas contain exactly the same record IDs and content', () => {
  const p = fixture(); p.last_decision = sampleDecision(); p.commands = [sampleCommand()];
  const state = displayState(p, 'review');
  const list = renderApp(state, Date.parse(time)); state.reviewView = 'atlas';
  const atlas = renderApp(state, Date.parse(time));
  const ids = (html) => [...html.matchAll(/data-record="([^"]+)"/g)].map((entry) => entry[1]);
  assert.deepEqual(ids(list), ids(atlas));
  for (const record of reviewRecords(p)) { assert.ok(list.includes(escapeHTML(record.detail))); assert.ok(atlas.includes(escapeHTML(record.detail))); }
});
test('source strings render as text, never executable markup or supplied links', () => {
  const p = fixture(); p.last_decision = sampleDecision(); p.last_decision.selection.reason = '<img src=x onerror=alert(1)> https://hostile.test';
  const html = renderApp(displayState(p));
  assert.equal(html.includes('<img'), false); assert.ok(html.includes('&lt;img'));
  assert.equal(html.includes('href="https://hostile.test"'), false);
});
test('permissions precede P/L, and runtime status stays NOT_RUN', () => {
  const html = renderApp(displayState(fixture()));
  assert.ok(html.indexOf('REPORTED PERMISSIONS') < html.indexOf('Account snapshot'));
  assert.match(html, /NOT_RUN/); assert.match(html, /No commands can be sent/);
});
test('Pause and Stop are separate disabled direct controls with optional explanations', () => {
  const html = renderApp(displayState(fixture()));
  assert.match(html, /disabled[^>]*>Pause new risk<\/button>/);
  assert.match(html, /disabled[^>]*>Stop automation<\/button>/);
  const pause = renderControlDialog('PAUSE_NEW_RISK'); const stop = renderControlDialog('STOP_AUTOMATION');
  assert.match(pause, /Already accepted orders may still fill/);
  assert.match(stop, /Stop does not close or cancel/);
  assert.match(stop, /Explanation only/);
  assert.throws(() => renderControlDialog('CLOSE_ALL'));
});
test('reviewed Close binds exact target version and quantity while sending nothing', () => {
  const p = fixture(); p.positions = [samplePosition()];
  const review = closeReview(p, 'position-1');
  assert.equal(review.version, 2); assert.equal(review.quantity, '10.125'); assert.equal(review.unit, 'BASE_UNITS'); assert.equal(review.send_enabled, false);
  assert.throws(() => closeReview(p, 'other-position'));
  const html = renderCloseDialog(p, 'position-1');
  assert.match(html, /No close request has been sent/); assert.match(html, /Scoped interruption controls/);
  assert.match(html, /10.125 BASE_UNITS/); assert.match(html, /disabled>Request reviewed Close/);
});
test('load failure is explicit and cannot retain old data as current', () => {
  const state = displayState(null); state.error = 'Invalid snapshot'; state.source = 'none';
  const html = renderApp(state);
  assert.match(html, /Snapshot unavailable/); assert.match(html, /No prior snapshot is shown as current/);
  assert.equal(html.includes('Account snapshot'), false);
});
test('Setup exposes A and B as NOT_RUN with no inferred model availability', () => {
  const html = renderApp(displayState(fixture(), 'setup'));
  assert.match(html, /Actual-model simulator/); assert.ok((html.match(/NOT_RUN/g) ?? []).length >= 3);
  assert.match(html, /No credentials or permissions are stored/);
});
