// PR #27 UI Regression Suite: Offline Broker Zero-Equity & Drawdown Guard
// Covers:
// 1) All-online baseline (zero .offline-broker-banner rendered).
// 2) Single broker offline (HUGOSWAY_MT5 disconnected -> unmistakable amber .offline-broker-banner
//    with "BROKER OFFLINE (Hugo's Way) — NOT A TRADING LOSS", plain-English notice, and online deployable equity).
// 3) Multi-broker offline (HUGOSWAY_MT5 + LHFX_MT5 -> "BROKERS OFFLINE (Hugo's Way · LHFX) — NOT A TRADING LOSS").
// 4) BROKER_OFFLINE routing chain normalization & amber "OFFLINE" (.status-offline) badge distinct from
//    green "ACTIVE" (.status-active) and red "FAILED" (.status-failed).
// 5) Dark Obsidian CSS rules, XSS escaping, strict CSP (0 inline style=, 0 innerHTML), and LF (CR=0) hygiene.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  STATIC_AI_MODELS,
  STATIC_AI_TRADER,
  normalizeAiModels,
  normalizeAiTrader,
  renderBankedProfitsHeroBanner,
} from '../../ui/src/ai-overseer.mjs';
import { normalizeBrokerRouting } from '../../ui/src/broker-routing.mjs';
import { renderApp, renderBrokerRoutingPanel } from '../../ui/src/render.mjs';
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

function buildTraderDoc({ bankedSessionOverrides = {}, deployableEquityUsd = '300000.00' } = {}) {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous execution active across healthy online venues.',
    effective_status: 'ACTIVE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 108,
    last_cycle_ms: 27,
    last_action: 'WAIT',
    last_symbol: 'EURUSD',
    last_reason: 'Monitoring online venues',
    deployable_equity_usd: deployableEquityUsd,
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20',
      status: 'OPEN',
      new_risk_allowed: true,
      quota_mode: 'USD',
      starting_equity_usd: '300000',
      realized_net_pnl_usd: '0',
      realized_pnl_pct: '0',
      soft_quota_usd: '3150',
      hard_quota_usd: '4500',
      quota_progress_pct: '0',
      risk_multiplier: '1',
      max_daily_loss_usd: '2500',
      closed_trades: 0,
      win_count: 0,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
    },
    banked_session: {
      schema: 'cas-forex.banked-session/1',
      accounting_basis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
      session_date: '2026-11-20',
      initial_capital_usd: '300000',
      current_total_equity_usd: '300000',
      net_surplus_usd: '0',
      net_surplus_pct: '0',
      deficit_to_principal_usd: '0',
      capital_status: 'AT_PRINCIPAL',
      vault_sweeps_paused_for_recovery: true,
      session_cadence: 'AUTO',
      active_session_leg: 1,
      can_advance_recovery_session: false,
      active_region_window: 'DAILY_NY (17:00 America/New_York)',
      banked_net_pnl_usd: '0',
      realized_pnl_pct: '0',
      peak_realized_pnl_usd: '0',
      protected_profit_floor_usd: '0',
      ratchet_armed: false,
      closed_trades: 0,
      win_count: 0,
      loss_count: 0,
      vault_total_realized_usd: '0',
      vault_swept_50pct_usd: '0',
      session_vault_reserved_50pct_usd: '0',
      vault_retained_50pct_usd: '0',
      confirmed_bank_payouts_usd: '0',
      profits_locked_for_session: false,
      operating_mode: 'ACTIVE_TRADING',
      offline_brokers: [],
      offline_broker_notice: null,
      online_equity_usd: '300000.00',
      equity_incomplete_brokers_offline: false,
      ...bankedSessionOverrides,
    },
    open_positions: [],
    recent_actions: [],
  };
}

function buildRoutingDoc(chainStatuses = ['ACTIVE', 'ACTIVE', 'ACTIVE'], allocationOverrides = {}) {
  return {
    schema: 'cas-forex.broker-routing/2',
    architecture: 'DUAL_SHIELD_BARBELL',
    platform: 'MetaTrader 5',
    execution_mode: 'DEMO',
    demo_only: true,
    live_trading_locked: true,
    primary_broker: 'HUGOSWAY_MT5',
    active_broker: chainStatuses[0] === 'ACTIVE' ? 'HUGOSWAY_MT5' : 'LHFX_MT5',
    transport_mode: 'SPOOL_BRIDGE',
    valve: { controller: 'tks_meta_valve_controller', parameters: 161, threshold: '0.55' },
    chain: [
      { broker_id: 'HUGOSWAY_MT5', priority: 1, role: 'PRIMARY_MAIN', label: "Hugo's Way", platform: 'MetaTrader 5', server: 'Hugosway-Demo', account_type: 'ECN demo', max_leverage: '1:500', configured: true, status: chainStatuses[0] },
      { broker_id: 'LHFX_MT5', priority: 2, role: 'SECONDARY_MT5', label: 'LHFX', platform: 'MetaTrader 5', server: 'LHFXSA-Demo', account_type: 'STP/ECN demo', max_leverage: '1:500', configured: true, status: chainStatuses[1] },
      { broker_id: 'OANDA_PRACTICE', priority: 3, role: 'TERTIARY_REST_FALLBACK', label: 'OANDA', platform: 'OANDA v20 REST', server: 'https://api-fxpractice.oanda.com/v3', account_type: 'fxPractice', max_leverage: '1:50', configured: true, status: chainStatuses[2] },
    ],
    dual_shield: {
      quote_truth_oracle: { reference_source: 'OANDA_PRACTICE', max_divergence_bps_major: '15', max_divergence_bps_cross: '25', max_oanda_spread_multiple: '3.0' },
      barbell: { oanda_reserve_share: '0.80', hugosway_share: '0.12', lhfx_share: '0.08', max_stop_loss_equity_risk_pct: '1.00' },
      safe_harbor: { broker_id: 'OANDA_PRACTICE', leverage: '1:50', recent_degradations: [] },
      offset_planner: true,
      allocation: {
        total_equity: '300000.00',
        online_equity: '300000.00',
        offline_brokers: [],
        equity_incomplete: false,
        ...allocationOverrides,
      },
    },
  };
}

test('PR27_01 All-online baseline renders zero offline-broker warning banner and clean static defaults', () => {
  assert.deepEqual(STATIC_AI_TRADER.offlineBrokers, []);
  assert.equal(STATIC_AI_TRADER.equityIncompleteBrokersOffline, false);
  assert.equal(STATIC_AI_TRADER.offlineBrokerNotice, null);

  const trader = normalizeAiTrader(buildTraderDoc());
  assert.deepEqual(trader.offlineBrokers, []);
  assert.equal(trader.equityIncompleteBrokersOffline, false);
  assert.equal(trader.offlineBrokerNotice, null);
  assert.equal(trader.onlineEquityUsd, '300000.00');

  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = trader;
  state.brokerRouting = normalizeBrokerRouting(buildRoutingDoc(['ACTIVE', 'ACTIVE', 'ACTIVE']));

  const heroHtml = renderBankedProfitsHeroBanner(state);
  assert.equal(heroHtml.includes('data-offline-broker-banner="true"'), false);
  assert.equal(heroHtml.includes('NOT A TRADING LOSS'), false);

  const fullHtml = renderApp(state, Date.parse(time));
  assert.equal(fullHtml.includes('data-offline-broker-banner="true"'), false);
  assert.equal(/\bstyle\s*=/i.test(fullHtml), false);
});

test('PR27_02 Single broker offline (HUGOSWAY_MT5) renders amber warning banner, NOT A TRADING LOSS reassurance, and online deployable equity', () => {
  const noticeText = "Hugo's Way MT5 terminal is currently disconnected. Disconnected account equity is excluded from trade sizing and is NOT a trading loss.";
  const trader = normalizeAiTrader(buildTraderDoc({
    deployableEquityUsd: '197478.59',
    bankedSessionOverrides: {
      offline_brokers: ['HUGOSWAY_MT5'],
      offline_broker_notice: noticeText,
      online_equity_usd: '197478.59',
      equity_incomplete_brokers_offline: true,
    },
  }));
  assert.deepEqual(trader.offlineBrokers, ['HUGOSWAY_MT5']);
  assert.deepEqual(trader.offlineBrokerLabels, ["Hugo's Way"]);
  assert.equal(trader.equityIncompleteBrokersOffline, true);
  assert.equal(trader.onlineEquityUsd, '197478.59');
  assert.equal(trader.offlineBrokerNotice, noticeText);

  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = trader;
  state.brokerRouting = normalizeBrokerRouting(buildRoutingDoc(
    ['BROKER_OFFLINE', 'ACTIVE', 'ACTIVE'],
    { online_equity: '197478.59', offline_brokers: ['HUGOSWAY_MT5'], equity_incomplete: true },
  ));

  for (const route of ['operate', 'review', 'setup']) {
    state.route = route;
    const html = renderApp(state, Date.parse(time));
    assert.match(html, /class="offline-broker-banner"[^>]*data-offline-broker-banner="true"/);
    assert.match(html, /class="status-offline"[^>]*>OFFLINE<\/span>/);
    assert.ok(html.includes('BROKER OFFLINE (Hugo&#39;s Way) — NOT A TRADING LOSS'), `Missing headline on ${route}`);
    assert.ok(html.includes('Disconnected account equity is excluded from trade sizing and is NOT a trading loss.'));
    assert.ok(html.includes('Online deployable equity: $197,478.59'));
    assert.equal(/\bstyle\s*=/i.test(html), false);
  }
});

test('PR27_03 Multi-broker offline (HUGOSWAY_MT5 + LHFX_MT5) and omitted-notice fallback render friendly names & OANDA-only online equity', () => {
  const multiTrader = normalizeAiTrader(buildTraderDoc({
    deployableEquityUsd: '240000.00',
    bankedSessionOverrides: {
      offline_brokers: ['HUGOSWAY_MT5', 'LHFX_MT5'],
      offline_broker_notice: null, // Exercises deterministic client plain-English fallback
      online_equity_usd: '240000.00',
      equity_incomplete_brokers_offline: true,
    },
  }));
  assert.deepEqual(multiTrader.offlineBrokerLabels, ["Hugo's Way", 'LHFX']);
  assert.match(multiTrader.offlineBrokerNotice, /Hugo's Way & LHFX/);
  assert.match(multiTrader.offlineBrokerNotice, /NOT a trading loss/);

  const heroHtml = renderBankedProfitsHeroBanner({
    liveStreamConnected: true,
    aiTrader: multiTrader,
  });
  assert.ok(heroHtml.includes('BROKERS OFFLINE (Hugo&#39;s Way · LHFX) — NOT A TRADING LOSS'));
  assert.ok(heroHtml.includes('Online deployable equity: $240,000.00'));
});

test('PR27_04 BROKER_OFFLINE in /api/broker-routing normalizes cleanly and renders distinct amber OFFLINE badge vs ACTIVE green and FAILED red', () => {
  const routing = normalizeBrokerRouting(buildRoutingDoc(
    ['BROKER_OFFLINE', 'ACTIVE', 'FAILED'],
    { online_equity: '264000.00', offline_brokers: ['HUGOSWAY_MT5'], equity_incomplete: true },
  ));
  assert.equal(routing.chain[0].status, 'BROKER_OFFLINE');
  assert.equal(routing.chain[1].status, 'ACTIVE');
  assert.equal(routing.chain[2].status, 'FAILED');
  assert.deepEqual(routing.shield.offlineBrokers, ['HUGOSWAY_MT5']);
  assert.equal(routing.shield.onlineEquity, '264000.00');
  assert.equal(routing.shield.equityIncomplete, true);

  const panelHtml = renderBrokerRoutingPanel(routing);
  assert.match(panelHtml, /<span class="tag status-offline" data-broker-status="BROKER_OFFLINE"><span class="state-rule" aria-hidden="true"><\/span>OFFLINE<\/span>/);
  assert.match(panelHtml, /<span class="tag status-active" data-broker-status="ACTIVE"><span class="state-rule" aria-hidden="true"><\/span>ACTIVE<\/span>/);
  assert.match(panelHtml, /<span class="tag tag-warning status-failed" data-broker-status="FAILED"><span class="state-rule" aria-hidden="true"><\/span>FAILED<\/span>/);
  assert.ok(panelHtml.includes('Online deployable equity'));
  assert.ok(panelHtml.includes('$264000.00 (offline broker excluded — not a loss)'));
  assert.equal(/\bstyle\s*=/i.test(panelHtml), false);
});

test('PR27_05 Dark Obsidian CSS styling, hostile notice XSS escaping, strict CSP, and LF (CR=0) hygiene', async () => {
  const hostileTrader = normalizeAiTrader(buildTraderDoc({
    deployableEquityUsd: '200000.00',
    bankedSessionOverrides: {
      offline_brokers: ['HUGOSWAY_MT5'],
      offline_broker_notice: '<script>alert("xss")</script><img src=x onerror=alert(1)>',
      online_equity_usd: '200000.00',
      equity_incomplete_brokers_offline: true,
    },
  }));
  const heroHtml = renderBankedProfitsHeroBanner({ liveStreamConnected: true, aiTrader: hostileTrader });
  assert.equal(heroHtml.includes('<script>'), false);
  assert.equal(heroHtml.includes('<img'), false);
  assert.match(heroHtml, /&lt;script&gt;alert\(&quot;xss&quot;\)&lt;\/script&gt;/);

  const stylesCss = await readFile(new URL('../../ui/styles.css', import.meta.url), 'utf8');
  assert.match(stylesCss, /\.offline-broker-banner\b/);
  assert.match(stylesCss, /\.status-offline\b/);
  assert.match(stylesCss, /\.tag\.status-active\b/);
  assert.match(stylesCss, /\.tag\.status-failed\b/);

  const checkedFiles = [
    '../../ui/src/ai-overseer.mjs',
    '../../ui/src/broker-routing.mjs',
    '../../ui/src/render.mjs',
    '../../ui/styles.css',
    '../../ui/package.json',
  ];
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;
  for (const rel of checkedFiles) {
    const raw = await readFile(new URL(rel, import.meta.url), 'utf8');
    assert.equal(raw.includes('\r'), false, `CR byte prohibited in ${rel}`);
    if (rel.endsWith('.mjs')) {
      assert.equal(innerHtmlRe.test(raw), false, `innerHTML/outerHTML prohibited in ${rel}`);
      assert.equal(inlineStyleRe.test(raw), false, `Inline style prohibited in ${rel}`);
    }
  }
});
