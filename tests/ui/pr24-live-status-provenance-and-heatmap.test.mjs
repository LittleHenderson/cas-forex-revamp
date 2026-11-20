// PR #24 UI regression suite: Above-the-fold Live Trading Status & Last Real Trade Strip,
// Universal Realized P/L Provenance + Broker Account (LHFX / Hugo's Way / OANDA) Attribution,
// Thermal Market Signal Heatmap, Honest Recovery-to-Surplus Vault Gauge, and Obsidian 2D Canvases.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  LIVE_TRADING_STATE_CODES,
  STATIC_AI_MODELS,
  forexSessionLabelForUtc,
  formatPacificTimestamp,
  formatUtcTimestamp,
  friendlyBrokerLabel,
  isSyntheticSyncEntry,
  normalizeAiModels,
  normalizeAiTrader,
  normalizeIndexStream,
  renderBankedProfitsHeroBanner,
} from '../../ui/src/ai-overseer.mjs';
import {
  buildThermalMarketTiles,
  drawEquityAndDd,
  drawRaceLines,
  mountAnalyticsCanvases,
  normalizeParallelTiers,
  normalizeTreasury,
  renderEquityAndAnalyticsSection,
} from '../../ui/src/analytics.mjs';
import { decodeMarketStream } from '../../ui/src/chart.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { displayState, fixture, time } from './helpers.mjs';

function buildModelsDoc() {
  return {
    schema: 'cas-forex.ai-models/1',
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_provider: 'anthropic',
    active_status: 'READY',
    selection_mode: 'PRIORITY_AUTO',
    frontier_ahead_of_qwen: true,
    frontier_configured_count: 8,
    offline_fallback_enabled: false,
    models: STATIC_AI_MODELS.models.map((m, idx) => ({
      rank: idx + 1,
      model_id: m.modelId,
      display_name: m.displayName,
      provider_label: m.providerLabel,
      tier: m.tier,
      is_fallback: m.isFallback,
      active: idx === 0,
      provider_ready: true,
      availability: 'READY',
    })),
  };
}

function buildBaseTraderDoc(overrides = {}) {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous multi-market execution loop active.',
    effective_status: 'ACTIVE',
    respite_mode: false,
    operating_mode: 'ACTIVE_TRADING',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 320,
    last_cycle_ms: 29,
    last_action: 'BUY',
    last_symbol: 'XAUUSD',
    last_reason: 'Momentum breakout cleared 0.55 valve',
    bank_sweep_reserved_usd: '0',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20-ASIA',
      status: 'OPEN',
      new_risk_allowed: true,
      lock_reason: null,
      quota_mode: 'USD',
      starting_equity_usd: '277618.09',
      realized_net_pnl_usd: '4640.06',
      realized_pnl_pct: '1.67',
      soft_quota_usd: '2000',
      hard_quota_usd: '3000',
      quota_progress_pct: '100',
      risk_multiplier: '1',
      max_daily_loss_usd: '5000',
      closed_trades: 2,
      win_count: 2,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      peak_realized_pnl_usd: '4640.06',
      ratchet_armed: true,
      ratchet_activation_usd: '1000',
      protected_profit_floor_usd: '3248.04',
    },
    banked_session: {
      schema: 'cas-forex.banked-session/1',
      accounting_basis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
      session_date: '2026-11-20-ASIA',
      initial_capital_usd: '300000',
      current_total_equity_usd: '282258.15',
      net_surplus_usd: '-17741.85',
      net_surplus_pct: '-5.91',
      deficit_to_principal_usd: '17741.85',
      capital_status: 'RECOVERY_MODE',
      vault_sweeps_paused_for_recovery: true,
      session_cadence: 'AUTO',
      active_session_leg: 1,
      can_advance_recovery_session: false,
      active_region_window: 'ASIA (22:00–07:00 UTC / 14:00–23:00 PT)',
      banked_net_pnl_usd: '4640.06',
      realized_pnl_pct: '1.67',
      peak_realized_pnl_usd: '4640.06',
      protected_profit_floor_usd: '3248.04',
      ratchet_armed: true,
      closed_trades: 2,
      win_count: 2,
      loss_count: 0,
      vault_total_realized_usd: '4640.06',
      vault_swept_50pct_usd: '0',
      session_vault_reserved_50pct_usd: '0',
      vault_retained_50pct_usd: '4640.06',
      confirmed_bank_payouts_usd: '0',
      pending_unconfirmed_transfers_usd: '0',
      profits_locked_for_session: false,
      operating_mode: 'ACTIVE_TRADING',
      session_rollover_label: 'London Session 07:00 UTC / 23:00 PT',
      next_session_opens_utc: '2026-11-20T07:00:00Z',
    },
    open_positions: [],
    recent_actions: [],
    ...overrides,
  };
}

function createRecordingCanvas(width, height) {
  const calls = [];
  const ctx = {
    _fillStyle: '',
    _strokeStyle: '',
    lineWidth: 1,
    set fillStyle(val) {
      this._fillStyle = String(val);
      calls.push({ op: 'setFillStyle', value: String(val) });
    },
    get fillStyle() { return this._fillStyle; },
    set strokeStyle(val) {
      this._strokeStyle = String(val);
      calls.push({ op: 'setStrokeStyle', value: String(val) });
    },
    get strokeStyle() { return this._strokeStyle; },
    fillRect(x, y, w, h) { calls.push({ op: 'fillRect', x, y, w, h, fillStyle: this._fillStyle }); },
    strokeRect(x, y, w, h) { calls.push({ op: 'strokeRect', x, y, w, h, strokeStyle: this._strokeStyle }); },
    beginPath() { calls.push({ op: 'beginPath' }); },
    closePath() { calls.push({ op: 'closePath' }); },
    moveTo(x, y) { calls.push({ op: 'moveTo', x, y }); },
    lineTo(x, y) { calls.push({ op: 'lineTo', x, y }); },
    stroke() { calls.push({ op: 'stroke', strokeStyle: this._strokeStyle }); },
    fill() { calls.push({ op: 'fill', fillStyle: this._fillStyle }); },
    arc(x, y, r) { calls.push({ op: 'arc', x, y, r }); },
    setLineDash(dash) { calls.push({ op: 'setLineDash', dash: [...dash] }); },
    fillText(text, x, y) { calls.push({ op: 'fillText', text: String(text), x, y, fillStyle: this._fillStyle }); },
  };
  return {
    calls,
    canvas: {
      getAttribute(attr) {
        if (attr === 'width') return String(width);
        if (attr === 'height') return String(height);
        return null;
      },
      getContext(kind) {
        return kind === '2d' ? ctx : null;
      },
    },
  };
}

test('PR24_01 Live Trading Status headlines, friendly Broker Account mapping, and synthetic SESSION_SYNC exclusion', () => {
  assert.equal(LIVE_TRADING_STATE_CODES.length, 5);
  assert.equal(friendlyBrokerLabel('LHFX_MT5'), 'LHFX');
  assert.equal(friendlyBrokerLabel('HUGOSWAY_MT5'), "Hugo's Way");
  assert.equal(friendlyBrokerLabel('OANDA_PRACTICE'), 'OANDA');
  assert.equal(friendlyBrokerLabel('OANDA_LIVE'), 'OANDA');
  assert.equal(isSyntheticSyncEntry('SESSION_SYNC_2026-11-20_0001_0', 'NAS100'), true);
  assert.equal(isSyntheticSyncEntry('t-1', 'SESSION_BASKET'), true);
  assert.equal(isSyntheticSyncEntry('t-real-1', 'XAUUSD'), false);

  assert.equal(forexSessionLabelForUtc('2026-11-20T00:46:41Z'), 'Asia / Tokyo–Sydney');
  assert.equal(forexSessionLabelForUtc('2026-11-20T09:15:00Z'), 'London');
  assert.equal(forexSessionLabelForUtc('2026-11-20T15:30:00Z'), 'New York / US');
  assert.equal(formatUtcTimestamp('2026-11-20T00:46:41Z'), '2026-11-20 00:46:41 UTC');
  assert.match(formatPacificTimestamp('2026-11-20T00:46:41Z'), /^2026-11-19 16:46:41 P[SD]?T$/);

  // 1) Open positions -> TRADING NOW
  const tradingNow = normalizeAiTrader(buildBaseTraderDoc({
    open_positions: [
      { broker_id: 'HUGOSWAY_MT5', ticket: 101, symbol: 'NAS100', side: 'BUY', volume_lots: '1.00', price_open: '20500', sl: '20420', tp: '20700', profit: '240.00' },
      { broker_id: 'LHFX_MT5', ticket: 102, symbol: 'XAUUSD', side: 'BUY', volume_lots: '0.50', price_open: '2640', sl: '2625', tp: '2680', profit: '185.00' },
    ],
    last_trade: {
      trade_id: 'SESSION_SYNC_2026-11-20-ASIA_0001_464006',
      symbol: 'SESSION_BASKET',
      broker_id: 'HUGOSWAY_MT5',
      action: 'SYNC',
      realized_pnl_usd: '4640.06',
      occurred_at_utc: '2026-11-20T00:46:41Z',
    },
  }));
  assert.equal(tradingNow.liveTradingStatus.stateCode, 'TRADING_NOW_OPEN_POSITIONS');
  assert.equal(tradingNow.liveTradingStatus.headline, 'TRADING NOW — 2 OPEN POSITIONS: NAS100, XAUUSD');
  assert.equal(tradingNow.lastTrade, null, 'Synthetic SESSION_SYNC / SESSION_BASKET must never populate lastTrade');

  const emptyTradeHero = renderBankedProfitsHeroBanner({
    liveStreamConnected: true,
    aiTrader: tradingNow,
  });
  assert.match(emptyTradeHero, /data-live-trading-status-strip="true"/);
  assert.ok(emptyTradeHero.includes('TRADING NOW — 2 OPEN POSITIONS: NAS100, XAUUSD'));
  assert.ok(emptyTradeHero.includes('No executed trades recorded yet in this ledger'));
  assert.equal(emptyTradeHero.includes('SESSION_SYNC'), false);
  assert.equal(emptyTradeHero.includes('SESSION_BASKET'), false);

  // 2) Active scanning with 0 open positions
  const scanning = normalizeAiTrader(buildBaseTraderDoc());
  assert.equal(scanning.liveTradingStatus.stateCode, 'ACTIVE_SCANNING_MARKETS');
  assert.equal(scanning.liveTradingStatus.headline, 'ACTIVE — SCANNING MARKETS (0 OPEN TRADES)');

  // 3) Respite paused
  const respiteDoc = buildBaseTraderDoc({ respite_mode: true });
  respiteDoc.daily_quota.status = 'DAILY_QUOTA_LOCKED';
  const respite = normalizeAiTrader(respiteDoc);
  assert.equal(respite.liveTradingStatus.stateCode, 'PAUSED_RESEARCH_RESPITE');
  assert.equal(respite.liveTradingStatus.headline, 'PAUSED — RESEARCH RESPITE (PROFIT LOCKED)');

  // 4) Safety loss circuit tripped
  const lossDoc = buildBaseTraderDoc();
  lossDoc.daily_quota.status = 'DAILY_LOSS_CIRCUIT_TRIPPED';
  const lossLocked = normalizeAiTrader(lossDoc);
  assert.equal(lossLocked.liveTradingStatus.stateCode, 'PAUSED_SAFETY_LOCK');
  assert.equal(lossLocked.liveTradingStatus.headline, 'PAUSED — SAFETY LOCK');
});

test('PR24_02 Universal Realized P/L Provenance & Broker Account (Hugo\'s Way / LHFX / OANDA) attribution across all 5 surfaces with 0 SESSION_SYNC leaks', () => {
  const traderDoc = buildBaseTraderDoc({
    last_trade: {
      trade_id: 'mt5-hw-8841',
      symbol: 'XAUUSD',
      broker_id: 'HUGOSWAY_MT5',
      action: 'CLOSED_TRADE',
      realized_pnl_usd: '1332.15',
      occurred_at_utc: '2026-11-20T00:46:41Z',
      occurred_at_pacific: '2026-11-19 16:46:41 PST',
      session_label: 'Asia / Tokyo–Sydney',
    },
    realized_pnl_ledger: {
      entries: [
        {
          trade_id: 'mt5-hw-8841',
          symbol: 'XAUUSD',
          broker_id: 'HUGOSWAY_MT5',
          realized_pnl_usd: '1332.15',
          occurred_at_utc: '2026-11-20T00:46:41Z',
          occurred_at_pacific: '2026-11-19 16:46:41 PST',
          session_label: 'Asia / Tokyo–Sydney',
          session_key: '2026-11-20-ASIA',
        },
        {
          trade_id: 'mt5-lhfx-9912',
          symbol: 'NAS100',
          broker_id: 'LHFX_MT5',
          realized_pnl_usd: '3307.91',
          occurred_at_utc: '2026-11-20T00:12:09Z',
          occurred_at_pacific: '2026-11-19 16:12:09 PST',
          session_label: 'Asia / Tokyo–Sydney',
          session_key: '2026-11-20-ASIA',
        },
        {
          trade_id: 'SESSION_SYNC_2026-11-20-ASIA_0001_0',
          symbol: 'SESSION_BASKET',
          broker_id: 'HUGOSWAY_MT5',
          realized_pnl_usd: '0',
          occurred_at_utc: '2026-11-20T00:50:00Z',
        },
      ],
      session_by_market: [
        {
          symbol: 'XAUUSD',
          broker_id: 'HUGOSWAY_MT5',
          realized_pnl_usd: '1332.15',
          trade_count: 1,
          win_count: 1,
          loss_count: 0,
          last_occurred_at_utc: '2026-11-20T00:46:41Z',
          last_occurred_at_pacific: '2026-11-19 16:46:41 PST',
          last_session_label: 'Asia / Tokyo–Sydney',
        },
        {
          symbol: 'NAS100',
          broker_id: 'LHFX_MT5',
          realized_pnl_usd: '3307.91',
          trade_count: 1,
          win_count: 1,
          loss_count: 0,
          last_occurred_at_utc: '2026-11-20T00:12:09Z',
          last_occurred_at_pacific: '2026-11-19 16:12:09 PST',
          last_session_label: 'Asia / Tokyo–Sydney',
        },
      ],
      session_by_broker: [
        { broker_id: 'HUGOSWAY_MT5', realized_pnl_usd: '1332.15', trade_count: 1, win_count: 1, loss_count: 0 },
        { broker_id: 'LHFX_MT5', realized_pnl_usd: '3307.91', trade_count: 1, win_count: 1, loss_count: 0 },
      ],
    },
  });

  const treas = normalizeTreasury({
    schema: 'cas-forex.profit-vault/1',
    sweep_ratio: '0.5',
    sweep_ratio_pct: '50',
    auto_sweep_enabled: true,
    preferred_rail: 'COINBASE_ACH',
    total_realized_profit_usd: '4640.06',
    retained_trading_usd: '4640.06',
    bank_sweep_reserved_usd: '0',
    disbursed_to_bank_usd: '0',
    confirmed_settled_disbursed_usd: '0',
    pending_or_unconfirmed_transfers_usd: '0',
    pending_disbursement_usd: '0',
    recent_sweeps: [
      {
        trade_id: 'SESSION_SYNC_2026-11-20-ASIA_0001_0',
        symbol: 'SESSION_BASKET',
        broker_id: 'HUGOSWAY_MT5',
        realized_net_usd: '0',
        retained_trading_usd: '666.08',
        bank_sweep_usd: '-666.08',
        occurred_at: '2026-11-20T00:50:00Z',
        is_reconciliation_sync: true,
      },
      {
        trade_id: 'mt5-hw-8841',
        symbol: 'XAUUSD',
        broker_id: 'HUGOSWAY_MT5',
        realized_net_usd: '1332.15',
        retained_trading_usd: '1332.15',
        bank_sweep_usd: '0',
        occurred_at: '2026-11-20T00:46:41Z',
      },
    ],
    recent_transfers: [],
  });
  assert.equal(treas.tradeSweeps.length, 1);
  assert.equal(treas.tradeSweeps[0].symbol, 'XAUUSD');
  assert.equal(treas.tradeSweeps[0].brokerLabel, "Hugo's Way");
  assert.equal(treas.realizedByBroker[0].brokerLabel, "Hugo's Way");

  const proj = fixture();
  proj.equity = { amount: '282258.15', currency: 'USD' };
  proj.balance = { amount: '282258.15', currency: 'USD' };
  proj.open_pnl = { amount: '0', currency: 'USD' };
  proj.realized_pnl = null;

  const state = displayState(proj, 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = normalizeAiTrader(traderDoc);
  state.treasury = treas;

  const html = renderApp(state, Date.parse(time));
  assert.match(html, /data-last-real-trade-strip="true"/);
  assert.match(html, /data-card2-pnl-provenance="true"/);
  assert.match(html, /data-account-realized-provenance="true"/);
  assert.match(html, /data-quota-realized-provenance="true"/);
  assert.match(html, /data-vault-realized-provenance="true"/);
  assert.match(html, /data-realized-pnl-provenance-ledger="true"/);

  // Market + Broker Account + Session + Pacific/UTC timestamps present
  assert.ok(html.includes('XAUUSD (+$1,332.15 · Hugo&#39;s Way)'));
  assert.ok(html.includes('NAS100 (+$3,307.91 · LHFX)'));
  assert.ok(html.includes('Asia / Tokyo–Sydney'));
  assert.ok(html.includes('2026-11-19 16:46:41 PST · 2026-11-20 00:46:41 UTC'));

  // Strictly zero synthetic sync rows leaked into UI
  assert.equal(html.includes('SESSION_SYNC'), false);
  assert.equal(html.includes('SESSION_BASKET'), false);
  assert.equal(/\bstyle\s*=/i.test(html), false);
});

test('PR24_03 Thermal Market Signal Heatmap & Honest Recovery-to-Surplus Bank Vault Gauge render with zero inline styles', async () => {
  const mSchema = JSON.parse(await readFile(new URL('../../docs/contracts/market-stream.schema.json', import.meta.url), 'utf8'));
  const mRaw = await readFile(new URL('../../docs/contracts/initial-market-stream.json', import.meta.url), 'utf8');
  const marketStream = decodeMarketStream(mRaw, mSchema);

  const indexStream = normalizeIndexStream({
    schema: 'cas-forex.index-stream/1',
    sequence: 12,
    observed_at: '2026-11-20T01:00:00Z',
    markets: [
      {
        pair: 'NAS100',
        bid: '20550.00',
        ask: '20551.50',
        mid: '20550.75',
        spread_points: '1.50',
        change_24h_pct: '0.82',
        observed_at: '2026-11-20T01:00:00Z',
        candles_m1: [
          { t: '2026-11-20T00:58:00Z', o: '20520', h: '20540', l: '20518', c: '20538', v: '10', n: 5 },
          { t: '2026-11-20T00:59:00Z', o: '20538', h: '20555', l: '20536', c: '20551', v: '12', n: 6 },
        ],
      },
      {
        pair: 'US30',
        bid: '43400.00',
        ask: '43402.00',
        mid: '43401.00',
        spread_points: '2.00',
        change_24h_pct: '-0.64',
        observed_at: '2026-11-20T01:00:00Z',
        candles_m1: [
          { t: '2026-11-20T00:58:00Z', o: '43450', h: '43452', l: '43410', c: '43415', v: '9', n: 4 },
          { t: '2026-11-20T00:59:00Z', o: '43415', h: '43418', l: '43395', c: '43401', v: '11', n: 5 },
        ],
      },
      {
        pair: 'SPX500',
        bid: '5910.00',
        ask: '5910.50',
        mid: '5910.25',
        spread_points: '0.50',
        change_24h_pct: '0.00',
        observed_at: '2026-11-20T01:00:00Z',
        candles_m1: [
          { t: '2026-11-20T00:59:00Z', o: '5910', h: '5911', l: '5909', c: '5910', v: '8', n: 3 },
        ],
      },
      {
        pair: 'XAUUSD',
        bid: '2652.10',
        ask: '2652.40',
        mid: '2652.25',
        spread_points: '0.30',
        change_24h_pct: '0.18',
        observed_at: '2026-11-20T01:00:00Z',
        candles_m1: [
          { t: '2026-11-20T00:59:00Z', o: '2650', h: '2653', l: '2649.5', c: '2652.25', v: '15', n: 8 },
        ],
      },
    ],
  });

  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.marketStream = marketStream;
  state.indexStream = indexStream;
  state.aiTrader = normalizeAiTrader(buildBaseTraderDoc({
    recent_actions: [
      { observed_at: '2026-11-20T00:59:10Z', kind: 'BUY_SIGNAL', symbol: 'NAS100', detail: 'Valve cleared 0.71' },
    ],
  }));
  state.treasury = normalizeTreasury({
    schema: 'cas-forex.profit-vault/1',
    sweep_ratio: '0.5',
    sweep_ratio_pct: '50',
    auto_sweep_enabled: true,
    preferred_rail: 'COINBASE_ACH',
    total_realized_profit_usd: '4640.06',
    retained_trading_usd: '4640.06',
    bank_sweep_reserved_usd: '0',
    disbursed_to_bank_usd: '0',
    recent_sweeps: [],
    recent_transfers: [],
  });

  const tiles = buildThermalMarketTiles(state);
  assert.ok(tiles.length >= 20, `Expected 4 indices + 16 FX pairs, got ${tiles.length}`);
  const nasTile = tiles.find((t) => t.pair === 'NAS100');
  const us30Tile = tiles.find((t) => t.pair === 'US30');
  assert.equal(nasTile.heatClass, 'heat-hot-buy');
  assert.equal(nasTile.signalLabel, 'HOT BUY');
  assert.equal(us30Tile.heatClass, 'heat-cold-sell');
  assert.equal(us30Tile.signalLabel, 'COLD SELL');

  const sectionHtml = renderEquityAndAnalyticsSection(state);
  assert.match(sectionHtml, /data-thermal-market-heatmap="true"/);
  assert.match(sectionHtml, /heat-hot-buy/);
  assert.match(sectionHtml, /heat-cold-sell/);
  assert.match(sectionHtml, /Valve ≥ 0\.55 READY/);
  assert.match(sectionHtml, /100% Rebuilding Principal \(Recovery Mode\)/);
  assert.match(sectionHtml, /data-principal-recovery-gauge="true"/);
  assert.ok(sectionHtml.includes('$282,258.15 / $300,000.00 Principal (94.09%) · $17,741.85 to breakeven'));
  assert.equal(/\bstyle\s*=/i.test(sectionHtml), false);

  // Surplus mode switches Bank Vault Ledger label to 50% Compounding / 50% Internal Vault Reserve (Surplus Mode)
  const surplusDoc = buildBaseTraderDoc();
  surplusDoc.banked_session.current_total_equity_usd = '304000';
  surplusDoc.banked_session.net_surplus_usd = '4000';
  surplusDoc.banked_session.net_surplus_pct = '1.33';
  surplusDoc.banked_session.deficit_to_principal_usd = '0';
  surplusDoc.banked_session.capital_status = 'IN_SURPLUS';
  surplusDoc.banked_session.vault_sweeps_paused_for_recovery = false;
  state.aiTrader = normalizeAiTrader(surplusDoc);
  state.treasury = normalizeTreasury({
    schema: 'cas-forex.profit-vault/1',
    sweep_ratio: '0.5',
    sweep_ratio_pct: '50',
    auto_sweep_enabled: true,
    preferred_rail: 'COINBASE_ACH',
    total_realized_profit_usd: '4000',
    retained_trading_usd: '2000',
    bank_sweep_reserved_usd: '2000',
    disbursed_to_bank_usd: '0',
    recent_sweeps: [],
    recent_transfers: [],
  });
  const surplusHtml = renderEquityAndAnalyticsSection(state);
  assert.ok(surplusHtml.includes('50% Compounding / 50% Internal Vault Reserve (Surplus Mode)'));
  assert.ok(surplusHtml.includes('$304,000.00 / $300,000.00 Principal (100.00%) · +$4,000.00 True Surplus'));
  assert.equal(/\bstyle\s*=/i.test(surplusHtml), false);
});

test('PR24_04 Mocked 2D canvas context verifies dark obsidian background, zoomed non-zero equity range, $300k goal line, and real drawdown curve', () => {
  const eqRec = createRecordingCanvas(440, 190);
  const ddRec = createRecordingCanvas(440, 190);
  const raceRec = createRecordingCanvas(860, 220);

  const mockRoot = {
    querySelector(sel) {
      if (sel === 'canvas[data-equity-vault-canvas]') return eqRec.canvas;
      if (sel === 'canvas[data-drawdown-canvas]') return ddRec.canvas;
      if (sel === 'canvas[data-tiers-race-canvas]') return raceRec.canvas;
      return null;
    },
  };

  const parallelTiers = normalizeParallelTiers({
    schema: 'cas-forex.parallel-tiers/1',
    tiers: [
      { tier_id: 'TIER_1_CURRENT', label: 'Current Barbell ($300,000)', starting_capital_usd: '300000', equity_usd: '282258.15', growth_pct: '-5.91', net_gain_usd: '-17741.85', drawdown_pct: '5.91', bank_sweep_reserved_usd: '0', win_rate_pct: '70', profit_factor: '2.10', open_positions: 0 },
    ],
    growth_series: {
      TIER_1_CURRENT: [
        { observed_at: '2026-11-19T22:00:00Z', equity_usd: '300000', growth_pct: '0', drawdown_pct: '0' },
        { observed_at: '2026-11-19T23:30:00Z', equity_usd: '277618.09', growth_pct: '-7.46', drawdown_pct: '7.46' },
        { observed_at: '2026-11-20T00:46:41Z', equity_usd: '282258.15', growth_pct: '-5.91', drawdown_pct: '5.91' },
      ],
    },
  });

  const state = {
    aiTrader: normalizeAiTrader(buildBaseTraderDoc()),
    treasury: normalizeTreasury({
      schema: 'cas-forex.profit-vault/1',
      total_realized_profit_usd: '4640.06',
      retained_trading_usd: '4640.06',
      bank_sweep_reserved_usd: '2000',
      recent_sweeps: [],
      recent_transfers: [],
    }),
    parallelTiers,
  };

  mountAnalyticsCanvases(mockRoot, state);

  // Dark obsidian background (#0d1117), NEVER #faf9f5
  for (const [name, rec] of [['equity', eqRec], ['drawdown', ddRec], ['race', raceRec]]) {
    const fills = rec.calls.filter((c) => c.op === 'fillRect');
    assert.ok(fills.length >= 2, `${name} canvas must paint background and plot box`);
    assert.equal(fills[0].fillStyle, '#0d1117', `${name} canvas must use #0d1117 obsidian background`);
    assert.equal(rec.calls.some((c) => c.value === '#faf9f5'), false, `${name} canvas must never paint white #faf9f5`);
  }

  // Equity canvas: zoomed non-zero range + $300,000 Principal Goal line + Vault band
  const eqTexts = eqRec.calls.filter((c) => c.op === 'fillText').map((c) => c.text);
  assert.ok(eqTexts.some((t) => t.includes('$300,000 Principal Goal')), 'Missing $300,000 Principal Goal label');
  assert.equal(eqTexts.includes('$0'), false, 'Equity axis must zoom around ~$275k-$305k, never $0');
  assert.ok(eqRec.calls.some((c) => c.op === 'fill' && c.fillStyle.includes('245, 158, 11')), 'Missing gold Vault Reserve band fill');

  // Drawdown canvas: real multi-point crimson curve + Current DD callout
  const ddLines = ddRec.calls.filter((c) => c.op === 'lineTo');
  assert.ok(ddLines.length >= 6, 'Drawdown canvas must plot real multi-point curve and shaded polygon');
  const ddTexts = ddRec.calls.filter((c) => c.op === 'fillText').map((c) => c.text);
  assert.ok(ddTexts.some((t) => t.includes('Current DD: -5.91%')));
  assert.ok(ddTexts.some((t) => t.includes('-10.0% Soft Downshift Brake')));
});

test('PR24_05 ui/package.json registration, strict CSP, zero localStorage, zero focus() scroll jump, and CR=0 across PR #24 UI files', async () => {
  const pkgRaw = await readFile(new URL('../../ui/package.json', import.meta.url), 'utf8');
  const pkg = JSON.parse(pkgRaw);
  assert.ok(pkg.scripts.test.includes('../tests/ui/pr24-live-status-provenance-and-heatmap.test.mjs'));

  const files = [
    '../../ui/src/ai-overseer.mjs',
    '../../ui/src/analytics.mjs',
    '../../ui/src/render.mjs',
    '../../ui/src/app.mjs',
    '../../ui/styles.css',
    '../../ui/package.json',
  ];
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;

  for (const rel of files) {
    const src = await readFile(new URL(rel, import.meta.url), 'utf8');
    assert.equal(src.includes('\r'), false, `CR byte prohibited in ${rel}`);
    if (!rel.endsWith('.json')) {
      assert.equal(innerHtmlRe.test(src), false, `Forbidden HTML setter in ${rel}`);
      assert.equal(inlineStyleRe.test(src), false, `Forbidden inline style in ${rel}`);
    }
  }

  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  assert.equal(/localStorage/.test(appSrc), false);
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false, 'All focus() calls in app.mjs must pass { preventScroll: true }');
});
