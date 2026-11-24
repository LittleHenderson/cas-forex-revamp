// PR #44 UI regression suite: Open-Positions table displays real entry_price, stop_loss, take_profit
// alongside legacy price_open/sl/tp aliases, with strict CSP & XSS escaping.

import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeAiTrader, normalizeIndexStream, renderAiOverseerPanel, STATIC_AI_MODELS } from '../../ui/src/ai-overseer.mjs';
import { computeChartGeometry } from '../../ui/src/chart.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { displayState, fixture, time } from './helpers.mjs';

function makeCanonicalTraderPayload(positions) {
  return {
    schema: 'cas-forex.ai-trader/1',
    governance_mode: 'ACTIVE',
    operating_mode: 'ACTIVE_TRADING',
    cycle_count: 14,
    veto_count: 3,
    last_action: 'WAIT',
    open_positions: positions,
    recent_actions: [],
    daily_quota: {
      session_date: '2026-11-24-ASIA',
      status: 'OPEN',
      new_risk_allowed: true,
      quota_mode: 'USD',
      starting_equity_usd: '196770.03',
      realized_net_pnl_usd: '0',
      soft_quota_usd: '34434.76',
      hard_quota_usd: '49192.51',
      max_daily_loss_usd: '39354.01',
      closed_trades: 0,
      win_count: 0,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
    },
  };
}

test('PR44-UI01 canonical entry_price, stop_loss, and take_profit render exact real numbers instead of 0/Missing/None', () => {
  const doc = makeCanonicalTraderPayload([
    {
      broker_id: 'LHFX_MT5',
      ticket: '13863586',
      symbol: 'XAUUSD',
      side: 'BUY',
      volume_lots: '0.43',
      entry_price: '3638.53',
      stop_loss: '3612.69',
      take_profit: '3693.10',
      profit: '-323.36',
      protection_stage: 'INITIAL_SL',
    },
    {
      broker_id: 'LHFX_MT5',
      ticket: '13863623',
      symbol: 'SPX500',
      side: 'SELL',
      volume_lots: '0.38',
      entry_price: '7249.00',
      stop_loss: '7277.40',
      take_profit: '7196.70',
      profit: '193.80',
      protection_stage: 'BREAKEVEN_LOCKED',
    },
  ]);

  const norm = normalizeAiTrader(doc);
  assert.equal(norm.openPositions.length, 2);
  assert.equal(norm.openPositions[0].entry_price, '3638.53');
  assert.equal(norm.openPositions[0].price_open, '3638.53');
  assert.equal(norm.openPositions[0].stop_loss, '3612.69');
  assert.equal(norm.openPositions[0].sl, '3612.69');
  assert.equal(norm.openPositions[0].take_profit, '3693.10');
  assert.equal(norm.openPositions[0].tp, '3693.10');

  const panelHtml = renderAiOverseerPanel({
    aiTrader: norm,
    aiModels: STATIC_AI_MODELS,
    brokerRouting: { executionMode: 'DEMO', liveArmed: false },
    ownerControlsAllowed: true,
    sessionScope: 'OWNER_FULL_CONTROL',
  });
  assert.match(panelHtml, /3638\.53/);
  assert.match(panelHtml, /3612\.69/);
  assert.match(panelHtml, /3693\.10/);
  assert.match(panelHtml, /7249\.00/);
  assert.match(panelHtml, /7277\.40/);
  assert.match(panelHtml, /7196\.70/);
  assert.equal(/>Missing</.test(panelHtml), false);
  assert.equal(/>None</.test(panelHtml), false);
  assert.equal(/<td class="numeric">0<\/td>/.test(panelHtml), false);
  assert.equal(/\bstyle\s*=/.test(panelHtml), false);

  const state = displayState(fixture(), 'operate');
  state.aiTrader = norm;
  const fullHtml = renderApp(state, Date.parse(time));
  assert.match(fullHtml, /3638\.53/);
  assert.match(fullHtml, /3612\.69/);
  assert.match(fullHtml, /3693\.10/);
  assert.equal(/\bstyle\s*=/.test(fullHtml), false);
});

test('PR44-UI02 legacy price_open/sl/tp and stop_price/take_profit_price fallbacks remain backward-compatible', () => {
  const norm = normalizeAiTrader(makeCanonicalTraderPayload([
    {
      broker_id: 'HUGOSWAY_MT5',
      ticket: '701',
      symbol: 'NAS100',
      side: 'BUY',
      volume_lots: '1.00',
      price_open: '20500.00',
      sl: '20501.00',
      tp: '20560.00',
      profit: '310.00',
      protection_stage: 'BREAKEVEN_LOCKED',
    },
    {
      broker_id: 'LHFX_MT5',
      ticket: '702',
      symbol: 'NAS100',
      side: 'BUY',
      quantity: '0.50',
      entry_price: '20510.00',
      stop_price: '20480.00',
      take_profit_price: '20580.00',
      profit: '45.00',
      protection_stage: 'INITIAL_SL',
    },
  ]));
  assert.equal(norm.openPositions[0].entry_price, '20500.00');
  assert.equal(norm.openPositions[0].stop_loss, '20501.00');
  assert.equal(norm.openPositions[0].take_profit, '20560.00');
  assert.equal(norm.openPositions[1].volume_lots, '0.50');
  assert.equal(norm.openPositions[1].sl, '20480.00');
  assert.equal(norm.openPositions[1].tp, '20580.00');
});

test('PR44-UI03 empty or null SL/TP strings display cleanly as Missing/None without breaking chart geometry', () => {
  const norm = normalizeAiTrader(makeCanonicalTraderPayload([
    {
      broker_id: 'LHFX_MT5',
      ticket: '801',
      symbol: 'NAS100',
      side: 'BUY',
      volume_lots: '0.20',
      entry_price: '20505.00',
      stop_loss: '',
      take_profit: null,
      profit: '10.00',
      protection_stage: 'INITIAL_SL',
    },
  ]));
  assert.equal(norm.openPositions[0].sl, null);
  assert.equal(norm.openPositions[0].tp, null);

  const panelHtml = renderAiOverseerPanel({ aiTrader: norm, aiModels: STATIC_AI_MODELS });
  assert.match(panelHtml, /20505\.00/);
  assert.match(panelHtml, />Missing</);
  assert.match(panelHtml, />None</);

  const sampleBars = [
    { t: '2026-11-23T17:59:00Z', o: '20495.00', h: '20505.00', l: '20492.00', c: '20500.00', v: '10', n: 1 },
    { t: '2026-11-23T18:00:00Z', o: '20500.00', h: '20515.00', l: '20495.00', c: '20511.00', v: '12', n: 1 },
  ];
  const idx = normalizeIndexStream({
    schema: 'cas-forex.index-stream/1',
    sequence: 1,
    observed_at: '2026-11-23T18:00:00Z',
    instruments: ['NAS100'],
    markets: [{
      pair: 'NAS100',
      display_pair: 'NAS100 / NDX',
      category: 'US_INDEX',
      base_currency: 'NAS100',
      quote_currency: 'USD',
      tick_size: '0.25',
      feed_mode: 'MT5_DIRECT_SPOOL_50MS',
      bid: '20510.00',
      ask: '20512.00',
      mid: '20511.00',
      spread_points: '2.00',
      observed_at: '2026-11-23T18:00:00Z',
      candles_m1: sampleBars,
      candles_m5: sampleBars,
      candles_h1: sampleBars,
    }],
  });
  const geom = computeChartGeometry(idx.markets[0], { timeframe: 'M1', brokerPositions: norm.openPositions });
  assert.equal(geom.positionLines.length, 1);
  assert.equal(geom.positionLines[0].kind, 'ENTRY');
});

test('PR44-UI04 hostile strings in open position prices are HTML-escaped with zero strict-CSP violations', () => {
  const norm = normalizeAiTrader(makeCanonicalTraderPayload([
    {
      broker_id: '<b>BAD</b>',
      ticket: '901',
      symbol: '<img src=x onerror=alert(1)>',
      side: 'BUY',
      volume_lots: '0.10',
      entry_price: '<script>alert(1)</script>',
      stop_loss: '"onload=alert(2)',
      take_profit: '<svg/onload=alert(3)>',
      profit: '5.00',
      protection_stage: 'INITIAL_SL',
    },
  ]));
  const html = renderAiOverseerPanel({ aiTrader: norm, aiModels: STATIC_AI_MODELS });
  assert.equal(/<script/i.test(html), false);
  assert.equal(/<img/i.test(html), false);
  assert.equal(/<svg/i.test(html), false);
  assert.equal(/\bstyle\s*=/.test(html), false);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});
