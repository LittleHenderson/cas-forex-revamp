// Phase 6 regression suite for the 03 Setup "Broker & MetaTrader 5 Routing" card.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderApp, renderBrokerRoutingPanel } from '../../ui/src/render.mjs';
import { normalizeBrokerRouting, STATIC_BROKER_ROUTING, MAX_BROKER_ROUTING_BYTES } from '../../ui/src/broker-routing.mjs';
import { displayState, fixture } from './helpers.mjs';

function sampleRouting() {
  return {
    schema: 'cas-forex.broker-routing/2', architecture: 'DUAL_SHIELD_BARBELL', platform: 'MetaTrader 5', platform_code: 'MT5',
    demo_only: true, live_trading_locked: true, primary_broker: 'HUGOSWAY_MT5', active_broker: 'HUGOSWAY_MT5', transport_mode: 'SPOOL_BRIDGE',
    timeframes: 21,
    valve: { controller: 'tks_meta_valve_controller', parameters: 161, threshold: '0.55', weights_sha256: 'a'.repeat(64), required: true },
    chain: [
      { broker_id: 'HUGOSWAY_MT5', priority: 1, role: 'PRIMARY_MAIN', label: "Hugo's Way", platform: 'MetaTrader 5', server: 'Hugo demo PRO5', account_type: 'ECN demo', max_leverage: '1:500', configured: true, status: 'ACTIVE', failure: null },
      { broker_id: 'LHFX_MT5', priority: 2, role: 'SECONDARY_MT5', label: 'LHFX', platform: 'MetaTrader 5', server: 'LHFXSA-Demo', account_type: 'STP/ECN demo', max_leverage: '1:500', configured: true, status: 'STANDBY', failure: null },
      { broker_id: 'OANDA_PRACTICE', priority: 3, role: 'TERTIARY_REST_FALLBACK', label: 'OANDA', platform: 'OANDA v20 REST', server: 'https://api-fxpractice.oanda.com/v3', account_type: 'fxPractice', max_leverage: '1:50', configured: true, status: 'ACTIVE', failure: null },
    ],
    dual_shield: {
      quote_truth_oracle: { reference_source: 'OANDA_PRACTICE', max_divergence_bps_major: '15', max_divergence_bps_cross: '25', max_spread_bps: '30', max_oanda_spread_multiple: '3' },
      barbell: { oanda_reserve_share: '0.8', hugosway_share: '0.12', lhfx_share: '0.08', max_stop_loss_equity_risk_pct: '1' },
      safe_harbor: { broker_id: 'OANDA_PRACTICE', leverage: '1:50', conservative_mode: false, recent_degradations: [{ broker_id: 'HUGOSWAY_MT5', outcome: 'OFF_MARKET_QUOTE', reason: 'MID_DIVERGES_FROM_REGULATED_REFERENCE' }] },
      offset_planner: { name: 'OandaProtectiveOffsetPlanner', venue: 'OANDA_PRACTICE', leverage: '1:50' },
    },
  };
}

test('static Setup preview shows the MT5 hierarchy without any routing endpoint', () => {
  const html = renderApp(displayState(fixture(), 'setup'));
  assert.match(html, /Broker &amp; MetaTrader 5 Routing/);
  assert.match(html, /Static preview \(not connected\)/);
  assert.match(html, /HUGOSWAY_MT5/); assert.match(html, /Hugo demo PRO5/);
  assert.match(html, /LHFX_MT5/); assert.match(html, /LHFXSA-Demo/);
  assert.match(html, /OANDA_PRACTICE/); assert.match(html, /api-fxpractice\.oanda\.com/);
  assert.match(html, /Demo only · live trading locked/);
  assert.match(html, /80% OANDA reserve/);
  assert.equal(/\bstyle\s*=/.test(html), false);
  assert.equal(STATIC_BROKER_ROUTING.connected, false);
});

test('loopback routing payload is normalized and rendered read-only', () => {
  const routing = normalizeBrokerRouting(sampleRouting());
  assert.equal(routing.connected, true);
  assert.equal(routing.chain.length, 3);
  assert.equal(routing.chain[0].server, 'Hugo demo PRO5');
  assert.equal(routing.shield.degradations, '1');
  assert.ok(Object.isFrozen(routing));
  const html = renderBrokerRoutingPanel(routing);
  assert.match(html, /Loopback broker routing \(read only\)/);
  assert.match(html, /tks_meta_valve_controller · 161 params · threshold 0\.55/);
  assert.match(html, /12% Hugo&#39;s Way · 8% LHFX/);
  assert.match(html, /1 recent degradations/);
  assert.equal(html.includes('a'.repeat(64)), false);
  assert.ok(MAX_BROKER_ROUTING_BYTES >= 4096);
});

test('unsafe or live routing payloads are refused and hostile text is escaped', () => {
  for (const mutate of [
    (d) => { d.demo_only = false; },
    (d) => { d.live_trading_locked = false; },
    (d) => { d.schema = 'other'; },
    (d) => { d.chain[0].broker_id = 'LIVE_BROKER'; },
    (d) => { d.chain[0].max_leverage = '500'; },
    (d) => { d.chain = []; },
  ]) {
    const doc = sampleRouting(); mutate(doc);
    assert.throws(() => normalizeBrokerRouting(doc));
  }
  const hostile = sampleRouting();
  hostile.chain[0].label = '<img src=x onerror=alert(1)>';
  const html = renderBrokerRoutingPanel(normalizeBrokerRouting(hostile));
  assert.equal(html.includes('<img'), false);
  assert.ok(html.includes('&lt;img'));
});
