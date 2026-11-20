// PR #19 UI regression suite: Daily Profit-Protection Ratchet ("High-Water Profit Floor")
// and RESEARCH_RESPITE profit-banked mode badge in Autonomous AI Overseer.
// Flat top-level test() calls only; strict CSP compliant.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  STATIC_AI_MODELS,
  STATIC_AI_TRADER,
  normalizeAiModels,
  normalizeAiTrader,
  renderAiOverseerPanel,
} from '../../ui/src/ai-overseer.mjs';
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

function buildTraderDoc(quotaOverrides = {}, traderOverrides = {}) {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous AI loop active.',
    effective_status: 'ACTIVE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 25,
    last_cycle_ms: 38,
    last_action: 'WAIT',
    last_symbol: 'NAS100',
    last_reason: 'Observing setup',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-19',
      status: 'OPEN',
      new_risk_allowed: true,
      lock_reason: null,
      quota_mode: 'USD',
      starting_equity_usd: '50000',
      realized_net_pnl_usd: '0',
      realized_pnl_pct: '0',
      soft_quota_usd: '2000',
      hard_quota_usd: '3000',
      quota_progress_pct: '0',
      risk_multiplier: '1',
      max_daily_loss_usd: '2500',
      closed_trades: 0,
      win_count: 0,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      ...quotaOverrides,
    },
    open_positions: [],
    recent_actions: [],
    ...traderOverrides,
  };
}

test('PR01 Legacy ai-trader payload without ratchet or respite fields normalizes cleanly with safe defaults', () => {
  assert.equal(STATIC_AI_TRADER.respiteMode, false);
  assert.equal(STATIC_AI_TRADER.operatingMode, 'ACTIVE_TRADING');
  assert.equal(STATIC_AI_TRADER.dailyQuota.peakRealizedPnlUsd, '0');
  assert.equal(STATIC_AI_TRADER.dailyQuota.ratchetArmed, false);
  assert.equal(STATIC_AI_TRADER.dailyQuota.ratchetActivationUsd, '0');
  assert.equal(STATIC_AI_TRADER.dailyQuota.protectedProfitFloorUsd, '0');

  const legacyNorm = normalizeAiTrader(buildTraderDoc());
  assert.equal(legacyNorm.respiteMode, false);
  assert.equal(legacyNorm.operatingMode, 'ACTIVE_TRADING');
  assert.equal(legacyNorm.dailyQuota.peakRealizedPnlUsd, '0');
  assert.equal(legacyNorm.dailyQuota.ratchetArmed, false);
  assert.equal(legacyNorm.dailyQuota.ratchetActivationUsd, '0');
  assert.equal(legacyNorm.dailyQuota.protectedProfitFloorUsd, '0');
});

test('PR02 Unhandcuffed pre-activation state displays activation threshold and omits RESEARCH_RESPITE badge', () => {
  const trader = normalizeAiTrader(buildTraderDoc({
    realized_net_pnl_usd: '600',
    peak_realized_pnl_usd: '600',
    ratchet_armed: false,
    ratchet_activation_usd: '1000',
    protected_profit_floor_usd: '0',
    quota_progress_pct: '20',
  }));
  const html = renderAiOverseerPanel({
    aiTrader: trader,
    aiModels: normalizeAiModels(buildModelsDoc()),
  });

  assert.match(html, /data-profit-ratchet-bar="true"/);
  assert.ok(html.includes('Peak Today: $600'));
  assert.ok(html.includes('Protected Floor (70%): $0'));
  assert.ok(html.includes('Unhandcuffed (arms at $1000)'));
  assert.equal(html.includes('RATCHET ARMED'), false);
  assert.equal(html.includes('data-research-respite-badge="true"'), false);
});

test('PR03 Armed 70% High-Water Profit Floor displays Peak Today: $2000, Protected Floor (70%): $1400, and RATCHET ARMED', () => {
  const trader = normalizeAiTrader(buildTraderDoc({
    status: 'SOFT_QUOTA_REACHED',
    realized_net_pnl_usd: '1550',
    peak_realized_pnl_usd: '2000',
    ratchet_armed: true,
    ratchet_activation_usd: '1000',
    protected_profit_floor_usd: '1400',
    quota_progress_pct: '51.67',
    risk_multiplier: '0.5',
  }));
  assert.equal(trader.dailyQuota.ratchetArmed, true);
  assert.equal(trader.dailyQuota.peakRealizedPnlUsd, '2000');
  assert.equal(trader.dailyQuota.protectedProfitFloorUsd, '1400');

  const html = renderAiOverseerPanel({
    aiTrader: trader,
    aiModels: normalizeAiModels(buildModelsDoc()),
  });

  assert.ok(html.includes('Peak Today: $2000'));
  assert.ok(html.includes('Protected Floor (70%): $1400'));
  assert.match(html, /class="ratchet-pill is-armed">RATCHET ARMED<\/span>/);
  // Still hunting hard cap above floor -> respite badge not shown yet
  assert.equal(html.includes('data-research-respite-badge="true"'), false);
});

test('PR04 PROFIT_FLOOR_LOCKED and RESEARCH_RESPITE render green profit-banked lock and unmistakable RESEARCH RESPITE badge', () => {
  const lockedTrader = normalizeAiTrader(buildTraderDoc(
    {
      status: 'PROFIT_FLOOR_LOCKED',
      new_risk_allowed: false,
      lock_reason: 'Protected daily profit floor locked (1390 <= 1400 USD from 2000 USD peak)',
      realized_net_pnl_usd: '1390',
      peak_realized_pnl_usd: '2000',
      ratchet_armed: true,
      ratchet_activation_usd: '1000',
      protected_profit_floor_usd: '1400',
      quota_progress_pct: '46.33',
      risk_multiplier: '0',
    },
    {
      effective_status: 'RESEARCH_RESPITE',
      respite_mode: true,
      operating_mode: 'RESEARCH_RESPITE',
      current_focus_status: 'RESEARCH_RESPITE: Profits Banked (1390 USD · Floor 1400 USD) · Observing NAS100',
    }
  ));

  assert.equal(lockedTrader.dailyQuota.status, 'PROFIT_FLOOR_LOCKED');
  assert.equal(lockedTrader.respiteMode, true);
  assert.equal(lockedTrader.operatingMode, 'RESEARCH_RESPITE');

  const html = renderAiOverseerPanel({
    aiTrader: lockedTrader,
    aiModels: normalizeAiModels(buildModelsDoc()),
  });

  assert.match(html, /data-daily-quota-status="PROFIT_FLOOR_LOCKED"/);
  assert.match(html, /tag-profit-locked" data-daily-quota-status="PROFIT_FLOOR_LOCKED"/);
  assert.match(html, /data-research-respite-badge="true"/);
  assert.ok(html.includes('RESEARCH RESPITE · PROFITS BANKED (0 New Risk · Observing Markets)'));
  assert.ok(html.includes('RESEARCH_RESPITE: Profits Banked'));

  //DAILY_QUOTA_LOCKED also displays the RESEARCH RESPITE · PROFITS BANKED badge
  const hardCapTrader = normalizeAiTrader(buildTraderDoc({
    status: 'DAILY_QUOTA_LOCKED',
    new_risk_allowed: false,
    realized_net_pnl_usd: '4094.46',
    peak_realized_pnl_usd: '4094.46',
    ratchet_armed: true,
    ratchet_activation_usd: '1000',
    protected_profit_floor_usd: '2866.12',
    quota_progress_pct: '100',
  }));
  const hardHtml = renderAiOverseerPanel({
    aiTrader: hardCapTrader,
    aiModels: normalizeAiModels(buildModelsDoc()),
  });
  assert.match(hardHtml, /data-research-respite-badge="true"/);
});

test('PR05 Operate integration, hostile input escaping, and strict CSP compliance (0 inline styles, 0 innerHTML)', async () => {
  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = normalizeAiTrader(buildTraderDoc(
    {
      status: 'PROFIT_FLOOR_LOCKED',
      new_risk_allowed: false,
      realized_net_pnl_usd: '1425.50',
      peak_realized_pnl_usd: '2000',
      ratchet_armed: true,
      ratchet_activation_usd: '1000',
      protected_profit_floor_usd: '1400',
    },
    {
      respite_mode: true,
      operating_mode: '<script>alert(1)</script>',
    }
  ));

  const appHtml = renderApp(state, Date.parse(time));
  assert.match(appHtml, /data-profit-ratchet-bar="true"/);
  assert.match(appHtml, /data-research-respite-badge="true"/);
  assert.equal(appHtml.includes('<script>'), false);
  assert.equal(/\bstyle\s*=/i.test(appHtml), false);

  const overseerSrc = await readFile(new URL('../../ui/src/ai-overseer.mjs', import.meta.url), 'utf8');
  const stylesSrc = await readFile(new URL('../../ui/styles.css', import.meta.url), 'utf8');
  assert.equal(/\binnerHTML\b/.test(overseerSrc), false);
  assert.equal(/\bouterHTML\b/.test(overseerSrc), false);
  assert.equal(/\bstyle\s*=\s*["']/i.test(overseerSrc), false);
  assert.match(stylesSrc, /\.profit-ratchet-row/);
  assert.match(stylesSrc, /\.ratchet-pill\.is-armed/);
  assert.match(stylesSrc, /\.respite-banked-badge/);
});
