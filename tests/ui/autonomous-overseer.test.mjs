// Phase 6 UI tests for Autonomous AI Overseer, 9-model priority catalog, Daily Quota, and 18-market US Index charts.
// Uses flat top-level test() calls only (zero describe() suites).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  ALL_CHART_PAIRS,
  ALL_WATCHLIST_MARKETS,
  INDEX_INSTRUMENTS,
  computeChartGeometry,
  decodeMarketStream,
  matchPositionsForPair,
  renderMarketChartSection,
} from '../../ui/src/chart.mjs';
import {
  STATIC_AI_MODELS,
  STATIC_AI_TRADER,
  normalizeAiModels,
  normalizeAiTrader,
  normalizeIndexStream,
  renderAiModelCatalogPanel,
  renderAiOverseerPanel,
} from '../../ui/src/ai-overseer.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { displayState, fixture, samplePosition, time } from './helpers.mjs';

const marketSchema = JSON.parse(await readFile(new URL('../../docs/contracts/market-stream.schema.json', import.meta.url), 'utf8'));
const marketFixtureRaw = await readFile(new URL('../../docs/contracts/initial-market-stream.json', import.meta.url), 'utf8');

function sampleModelsPayload() {
  return {
    schema: 'cas-forex.ai-models/1',
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_provider: 'anthropic',
    active_tier: 'FRONTIER',
    active_provider_ready: true,
    active_status: 'READY',
    selection_mode: 'PRIORITY_AUTO',
    frontier_ahead_of_qwen: true,
    frontier_configured_count: 8,
    offline_fallback_enabled: false,
    fast_scout_enabled: true,
    fast_scout_model_id: 'gemini-decision-1',
    fast_scout_ready: true,
    min_decision_probability: '0.6',
    valve_required: true,
    models: STATIC_AI_MODELS.models.map((m, idx) => ({
      rank: idx + 1,
      model_id: m.modelId,
      display_name: m.displayName,
      provider: m.modelId === 'qwen3:0.6b' ? 'ollama' : 'frontier',
      provider_label: m.providerLabel,
      api_slug: m.modelId,
      tier: m.tier,
      is_fallback: m.isFallback,
      active: idx === 0,
      provider_ready: idx < 8,
      availability: idx < 8 ? 'READY' : 'OFFLINE_STANDBY',
      last_status: 'IDLE',
    })),
  };
}

function sampleTraderPayload() {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous AI trading loop active under ForexMetaValveGate.',
    effective_status: 'ACTIVE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    watchlist_markets: [...ALL_WATCHLIST_MARKETS],
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    fast_scout_enabled: true,
    fast_scout_ready: true,
    cycle_count: 14,
    last_cycle_ms: 42,
    last_action: 'OPEN',
    last_symbol: 'NAS100',
    last_reason: '50ms momentum burst cleared ForexMetaValveGate',
    last_valve_score: '0.94',
    veto_count: 1,
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-17',
      status: 'SOFT_QUOTA_REACHED',
      new_risk_allowed: true,
      lock_reason: null,
      quota_mode: 'USD',
      starting_equity_usd: '20000',
      realized_net_pnl_usd: '625.50',
      realized_pnl_pct: '3.12',
      soft_quota_usd: '500',
      hard_quota_usd: '1000',
      daily_quota_pct: null,
      quota_progress_pct: '62.55',
      risk_multiplier: '0.5',
      max_daily_loss_usd: '500',
      closed_trades: 3,
      win_count: 3,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
    },
    open_positions: [
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
    ],
    recent_actions: [
      { kind: 'PROTECTION', symbol: 'NAS100', detail: 'Snapped SL to breakeven 20501.00' },
    ],
  };
}

function sampleIndexPayload() {
  const bars = [
    { t: '2026-11-17T13:59:00Z', o: '20495.00', h: '20503.00', l: '20492.00', c: '20501.00', v: '12.00', n: 1 },
    { t: '2026-11-17T14:00:00Z', o: '20501.00', h: '20512.00', l: '20499.00', c: '20510.00', v: '15.00', n: 1 },
  ];
  const dowBars = [
    { t: '2026-11-17T13:59:00Z', o: '43795.00', h: '43805.00', l: '43790.00', c: '43802.00', v: '10.00', n: 1 },
    { t: '2026-11-17T14:00:00Z', o: '43802.00', h: '43815.00', l: '43800.00', c: '43812.00', v: '14.00', n: 1 },
  ];
  return {
    schema: 'cas-forex.index-stream/1',
    sequence: 7,
    observed_at: '2026-11-17T14:00:00Z',
    instruments: ['NAS100', 'US30'],
    markets: [
      {
        pair: 'NAS100',
        display_pair: 'NAS100 / NDX',
        category: 'US_INDEX',
        base_currency: 'NAS100',
        quote_currency: 'USD',
        tick_size: '0.25',
        feed_mode: 'MT5_DIRECT_SPOOL_50MS',
        bid: '20510.00',
        ask: '20512.50',
        mid: '20511.25',
        spread_points: '2.50',
        observed_at: '2026-11-17T14:00:00Z',
        candles_m1: bars,
        candles_m5: bars,
        candles_h1: bars,
      },
      {
        pair: 'US30',
        display_pair: 'US30 / DJIA',
        category: 'US_INDEX',
        base_currency: 'US30',
        quote_currency: 'USD',
        tick_size: '1.00',
        feed_mode: 'MT5_DIRECT_SPOOL_50MS',
        bid: '43810.00',
        ask: '43814.00',
        mid: '43812.00',
        spread_points: '4.00',
        observed_at: '2026-11-17T14:00:00Z',
        candles_m1: dowBars,
        candles_m5: dowBars,
        candles_h1: dowBars,
      },
    ],
  };
}

test('OVERSEER01 chart constants preserve 16 FX pairs while expanding watchlist to 20 with NAS100, US30, SPX500 & XAUUSD', () => {
  assert.equal(ALL_CHART_PAIRS.length, 16);
  assert.deepEqual(INDEX_INSTRUMENTS, ['NAS100', 'US30', 'SPX500', 'XAUUSD']);
  assert.equal(ALL_WATCHLIST_MARKETS.length, 20);
  assert.equal(ALL_WATCHLIST_MARKETS[0], 'NAS100');
  assert.equal(ALL_WATCHLIST_MARKETS[1], 'US30');
  assert.equal(ALL_WATCHLIST_MARKETS[2], 'SPX500');
  assert.equal(ALL_WATCHLIST_MARKETS[3], 'XAUUSD');
});

test('OVERSEER02 normalizeAiModels enforces 9-model priority catalog with qwen3:0.6b strictly #9 last', () => {
  const models = normalizeAiModels(sampleModelsPayload());
  assert.equal(models.models.length, 9);
  assert.equal(models.models[0].modelId, 'claude-fable-5.2');
  assert.equal(models.models[3].modelId, 'gemini-decision-1');
  assert.equal(models.models[8].modelId, 'qwen3:0.6b');
  assert.equal(models.fastScoutEnabled, true);
  assert.ok(Object.isFrozen(models));

  const bad = sampleModelsPayload();
  bad.models.reverse();
  assert.throws(() => normalizeAiModels(bad));
});

test('OVERSEER03 normalizeIndexStream & computeChartGeometry render NAS100 ENTRY, STOP, and TAKE_PROFIT lines cleanly', () => {
  const idx = normalizeIndexStream(sampleIndexPayload());
  const trader = normalizeAiTrader(sampleTraderPayload());
  assert.equal(idx.markets.length, 2);
  const nas = idx.markets[0];
  const geom = computeChartGeometry(nas, {
    timeframe: 'M5',
    brokerPositions: trader.openPositions,
    width: 860,
    height: 360,
  });
  assert.equal(geom.positionLines.length, 3);
  assert.deepEqual(geom.positionLines.map((l) => l.kind), ['ENTRY', 'STOP', 'TAKE_PROFIT']);

  const proj = fixture();
  proj.positions = [samplePosition()];
  const matched = matchPositionsForPair(proj, 'NAS100', [{ symbol: 'USTEC.pro', side: 'BUY', price_open: '20500.00', sl: '20501.00', tp: '20560.00' }]);
  assert.equal(matched.length, 1);
  assert.equal(matched[0].take_profit_price, '20560.00');
});

test('OVERSEER04 Operate and Setup panels render Human Overseer controls, quota progress, 20 markets, and zero inline styles', () => {
  const fx = decodeMarketStream(marketFixtureRaw, marketSchema);
  const state = displayState(fixture(), 'operate');
  state.marketStream = fx;
  state.indexStream = normalizeIndexStream(sampleIndexPayload());
  state.aiModels = normalizeAiModels(sampleModelsPayload());
  state.aiTrader = normalizeAiTrader(sampleTraderPayload());
  state.chartPair = 'NAS100';

  const operateHtml = renderApp(state, Date.parse(time));
  assert.match(operateHtml, /Autonomous AI Trader &amp; Daily Quota/);
  assert.match(operateHtml, /BREAKEVEN_LOCKED/);
  assert.match(operateHtml, /SOFT_QUOTA_REACHED/);
  assert.match(operateHtml, /Gemini Decision 1 Fast Scout: ON/);
  assert.match(operateHtml, /20 MARKETS/);
  assert.match(operateHtml, /data-market-canvas="NAS100"/);
  assert.match(operateHtml, /Indices &amp; Gold \/ 2/);
  assert.equal(/\bstyle\s*=/.test(operateHtml), false);
  assert.equal(/data-record=/.test(renderMarketChartSection(state.projection, state)), false);
  assert.equal(/data-record=/.test(renderAiOverseerPanel(state)), false);

  state.route = 'setup';
  const setupHtml = renderApp(state, Date.parse(time));
  assert.match(setupHtml, /Frontier &amp; Local Decision Models/);
  assert.match(setupHtml, /qwen3:0\.6b/);
  assert.match(setupHtml, /Offline fallback only/);
  assert.equal(/\bstyle\s*=/.test(setupHtml), false);
});

test('OVERSEER05 Hostile HTML payloads in AI trader & model catalog are escaped safely', () => {
  const badTrader = sampleTraderPayload();
  badTrader.governance_reason = '<img src=x onerror=alert(1)>';
  const norm = normalizeAiTrader(badTrader);
  const html = renderAiOverseerPanel({ aiTrader: norm, aiModels: normalizeAiModels(sampleModelsPayload()) });
  assert.equal(html.includes('<img'), false);
  assert.ok(html.includes('&lt;img'));

  const catHtml = renderAiModelCatalogPanel(STATIC_AI_MODELS);
  assert.match(catHtml, /AI catalog preview \(not attached\)/);
  assert.ok(STATIC_AI_TRADER.humanRole === 'OVERSEER_ONLY');
});
