// Authored regression source; NOT_RUN in this redesign session.
// Intended destination: tests/ui/modernist.test.mjs.
// These are synthetic presentation inputs, not validated trading records or run evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { renderApp } from '../../ui/src/render.mjs';
import { fixture, displayState, time } from './helpers.mjs';

const readRaw = await readFile(new URL('../../docs/contracts/initial-decision-read.json', import.meta.url), 'utf8');
const visibleIds = html => [...html.matchAll(/data-record="([^"]+)"/g)].map(match => match[1]);
const unavailable = () => ({ record_id: null, record_version: null, record_sha256: null, unavailable_reason: 'Not observed in authored presentation test.' });

function mixedReadState() {
  const state = displayState(fixture(), 'review');
  const envelope = JSON.parse(readRaw);
  envelope.decisions = [{
    decision_id: 'decision-payload', revision: 0, selection: null,
    status_reason: 'Synthetic decision payload; no action selected.', decision_status: 'proposed',
    origin: { kind: 'scripted', model_id: null, provider: null, effective_reasoning: null },
    admission_ref: unavailable(), dispatch_ref: unavailable(), outcome_refs: [], candidates: [],
  }];
  envelope.events = [
    // DECISION is also a valid event_kind. It is not a decision payload and has no origin/candidates.
    { event_id: 'decision-event', event_kind: 'DECISION', effect: null, public_summary: 'Decision event record only.' },
    { event_id: 'control-event', event_kind: 'CONTROL', effect: null, public_summary: 'Control event record only.' },
  ];
  envelope.evidence = [{ evidence_id: 'evidence-1', producer_class: 'CORE', assessment: 'UNKNOWN', claim: 'Synthetic evidence record only.' }];
  envelope.coverage.retained_count = 4;
  state.reviewEnvelope = { envelope, local: { self_consistency: 'NOT_CHECKED', source_binding: 'UNVERIFIED', reference_resolution: 'UNAVAILABLE' } };
  return state;
}

test('DECISION-kind event remains in Events/core and can be inspected without decision payload fields', () => {
  const state = mixedReadState();
  state.reviewFilter = 'events';
  state.inspection.focus_node_id = 'read-event:decision-event';
  let html;
  assert.doesNotThrow(() => { html = renderApp(state, Date.parse(time)); });
  assert.deepEqual(visibleIds(html), ['read-event:decision-event', 'read-event:control-event']);
  assert.match(html, /Events \/ core \/ 2/);
  assert.match(html, /Decision event record only\./);
  assert.match(html, /Full immutable source record/);
  assert.doesNotMatch(html, /Candidate catalog/);
});

test('Decisions includes only decision payloads even when a supplied event has DECISION kind', () => {
  const state = mixedReadState();
  state.reviewFilter = 'decisions';
  state.inspection.focus_node_id = 'read-decision:decision-payload:0';
  const html = renderApp(state, Date.parse(time));
  assert.deepEqual(visibleIds(html), ['read-decision:decision-payload:0']);
  assert.match(html, /Decisions \/ 1/);
  assert.match(html, /Candidate catalog/);
  assert.match(html, /No selection supplied/);
});

test('List and Atlas keep the same filtered IDs without changing source records or coverage', () => {
  const state = mixedReadState();
  const before = JSON.stringify({ projection: state.projection, read: state.reviewEnvelope });
  const expected = {
    all: ['read-decision:decision-payload:0', 'read-event:decision-event', 'read-event:control-event', 'read-evidence:evidence-1'],
    decisions: ['read-decision:decision-payload:0'],
    events: ['read-event:decision-event', 'read-event:control-event'],
    evidence: ['read-evidence:evidence-1'],
  };
  for (const [filter, ids] of Object.entries(expected)) {
    state.reviewFilter = filter;
    state.reviewView = 'list';
    const list = renderApp(state, Date.parse(time));
    state.reviewView = 'atlas';
    const atlas = renderApp(state, Date.parse(time));
    assert.deepEqual(visibleIds(list), ids, `${filter} List`);
    assert.deepEqual(visibleIds(atlas), ids, `${filter} Atlas`);
    for (const html of [list, atlas]) {
      assert.match(html, /4 supplied records/);
      assert.match(html, /incomplete coverage/);
      assert.match(html, /source unverified/);
    }
  }
  assert.equal(JSON.stringify({ projection: state.projection, read: state.reviewEnvelope }), before);
});
