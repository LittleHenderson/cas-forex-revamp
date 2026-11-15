// AUTHORED / NOT_RUN: clock selection and rendering regressions, no service or browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { displayFreshness, CLOCK_READ_MAX_AGE_MS } from '../../ui/src/freshness.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { fixture, displayState } from './helpers.mjs';

function synthetic() {
  const p = fixture(); p.observed_at = '2020-01-01T00:00:00Z';
  const state = displayState(p); state.source = 'scoped simulator';
  state.transport = { attached: true, clock: { request_time: p.observed_at, received_at_monotonic_ms: 1000 }, controls: [], closeHistory: [], available: {} };
  return state;
}

test('historical simulator UTC uses independent clock instead of current wall time', () => {
  const state = synthetic();
  const read = displayFreshness(state, { wallNow: Date.parse('2040-01-01T00:00:00Z'), monotonicNow: 2000 });
  assert.equal(read.label, '0s old / simulator'); assert.equal(read.invalidated, false);
  assert.match(read.detail, /1s ago locally/);
});

test('elapsed local duration never advances frozen simulator time', () => {
  const state = synthetic(); const before = JSON.stringify(state);
  const first = displayFreshness(state, { monotonicNow: 1000 });
  const later = displayFreshness(state, { monotonicNow: 15000 });
  assert.equal(first.label, later.label); assert.equal(later.read_age_ms, 14000);
  assert.equal(JSON.stringify(state), before);
});

test('monotonic read-age boundary invalidates display without fabricating synthetic advancement', () => {
  const state = synthetic();
  assert.equal(displayFreshness(state, { monotonicNow: 1000 + CLOCK_READ_MAX_AGE_MS - 1 }).invalidated, false);
  const old = displayFreshness(state, { monotonicNow: 1000 + CLOCK_READ_MAX_AGE_MS });
  assert.equal(old.invalidated, true); assert.equal(old.label, 'Simulator read expired');
  assert.equal(old.request_time, state.projection.observed_at);
});

test('wall-clock jumps cannot change an attached simulator freshness result', () => {
  const state = synthetic();
  assert.deepEqual(displayFreshness(state, { wallNow: 0, monotonicNow: 1000 }), displayFreshness(state, { wallNow: 9e12, monotonicNow: 1000 }));
});

test('microsecond future observations fail rather than rounding into freshness', () => {
  const state = synthetic(); state.projection.observed_at = '2020-01-01T00:00:00.000001Z';
  assert.equal(displayFreshness(state, { monotonicNow: 1000 }).label, 'Future timestamp / simulator');
});

test('missing and reversed monotonic age remain unavailable', () => {
  const state = synthetic();
  for (const monotonicNow of [null, NaN, 999]) assert.equal(displayFreshness(state, { monotonicNow }).invalidated, true);
  state.transport.clock.request_time = null;
  assert.equal(displayFreshness(state, { monotonicNow: 1000 }).label, 'Simulator clock unavailable');
});

test('hidden or restored tab requires a new read even if its monotonic clock stopped', () => {
  const state = synthetic(); state.transport.clock.invalidated = true;
  const result = displayFreshness(state, { monotonicNow: 1000 });
  assert.equal(result.invalidated, true); assert.match(result.detail, /visibility changed/);
});

test('imported snapshot cannot acquire a clock from its own labels or fixture timestamp', () => {
  const state = synthetic(); state.transport.attached = false; state.source = 'local snapshot';
  const result = displayFreshness(state, { wallNow: Date.parse('2020-01-01T00:01:00Z'), monotonicNow: 1000 });
  assert.equal(result.clock_basis, 'UNBOUND'); assert.equal(result.label, '1m old'); assert.match(result.detail, /Unbound snapshot/);
});

test('G4 freshness class and explicit simulator clock label remain available', () => {
  const html = renderApp(synthetic(), Date.parse('2040-01-01T00:00:00Z'), 2000);
  assert.match(html, /class="freshness" data-clock-basis="SIMULATOR" data-read-invalidated="false"/);
  assert.match(html, /<strong>0s old \/ simulator<\/strong>/);
  assert.equal(html.includes('Future timestamp'), false);
});

test('detachment leaves an explicit unknown inventory panel and disabled controls', () => {
  const state = displayState(null); state.transport = { attached: false, controls: [], closeHistory: [], available: {} };
  const html = renderApp(state);
  assert.match(html, /class="panel positions-panel"/); assert.match(html, /Inventory unknown/);
  assert.match(html, /disabled data-request-control="STOP_AUTOMATION"/);
});
