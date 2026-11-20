// PR #21 UI regression suite: Institutional Principal High-Water Mark ($300,000.00 baseline),
// Underwater RECOVERY_MODE ($0.00 vault sweeps until above principal) vs IN_SURPLUS ($304,000 -> +$4,000 surplus),
// Automatic 3-Region Recovery Cadence (Asia · London · NY -> 17:00 NY Surplus), and 1-Click Recovery Session Advance.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  CAPITAL_STATUSES,
  SESSION_CADENCE_MODES,
  STATIC_AI_MODELS,
  STATIC_AI_TRADER,
  normalizeAiModels,
  normalizeAiTrader,
  renderBankedProfitsHeroBanner,
} from '../../ui/src/ai-overseer.mjs';
import { normalizeTreasury } from '../../ui/src/analytics.mjs';
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

function buildUnderwaterRecoveryDoc(withExplicitSurplusFields = true) {
  const doc = {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Asia session recovery leg locked at 70% profit floor; awaiting London 07:00 UTC auto-wakeup.',
    effective_status: 'DAILY_QUOTA_LOCKED',
    respite_mode: true,
    operating_mode: 'RESEARCH_RESPITE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 215,
    last_cycle_ms: 34,
    last_action: 'WAIT',
    last_symbol: 'NAS100',
    last_reason: 'Principal recovery respite active',
    bank_sweep_reserved_usd: '0',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20-ASIA',
      status: 'DAILY_QUOTA_LOCKED',
      new_risk_allowed: false,
      lock_reason: 'Asia recovery session quota reached',
      quota_mode: 'USD',
      starting_equity_usd: '277618.09',
      realized_net_pnl_usd: '4640.06',
      realized_pnl_pct: '1.67',
      soft_quota_usd: '2000',
      hard_quota_usd: '3000',
      quota_progress_pct: '100',
      risk_multiplier: '0',
      max_daily_loss_usd: '5000',
      closed_trades: 10,
      win_count: 7,
      loss_count: 3,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      peak_realized_pnl_usd: '4852.73',
      ratchet_armed: true,
      ratchet_activation_usd: '1000',
      protected_profit_floor_usd: '3396.91',
    },
    open_positions: [],
    recent_actions: [],
  };

  if (withExplicitSurplusFields) {
    doc.banked_session = {
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
      can_advance_recovery_session: true,
      active_region_window: 'ASIA (22:00–07:00 UTC / 14:00–23:00 PT)',
      banked_net_pnl_usd: '4640.06',
      realized_pnl_pct: '1.67',
      peak_realized_pnl_usd: '4852.73',
      protected_profit_floor_usd: '3396.91',
      ratchet_armed: true,
      closed_trades: 10,
      win_count: 7,
      loss_count: 3,
      vault_total_realized_usd: '22381.91',
      vault_swept_50pct_usd: '0',
      session_vault_reserved_50pct_usd: '0',
      vault_retained_50pct_usd: '4640.06',
      confirmed_bank_payouts_usd: '0',
      profits_locked_for_session: true,
      operating_mode: 'RESEARCH_RESPITE',
      session_rollover_label: 'London Session 07:00 UTC / 23:00 PT',
      next_session_opens_utc: '2026-11-20T07:00:00Z',
    };
  }
  return doc;
}

function buildSurplusTraderDoc() {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Principal recovered and $4,000.00 true surplus locked above $300,000.00 High-Water Mark.',
    effective_status: 'DAILY_QUOTA_LOCKED',
    respite_mode: true,
    operating_mode: 'RESEARCH_RESPITE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 410,
    last_cycle_ms: 31,
    last_action: 'WAIT',
    last_symbol: 'XAUUSD',
    last_reason: 'Surplus session quota locked',
    bank_sweep_reserved_usd: '2000',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20',
      status: 'DAILY_QUOTA_LOCKED',
      new_risk_allowed: false,
      lock_reason: 'Daily hard quota reached in surplus',
      quota_mode: 'USD',
      starting_equity_usd: '282258.15',
      realized_net_pnl_usd: '21741.85',
      realized_pnl_pct: '7.70',
      soft_quota_usd: '2000',
      hard_quota_usd: '3000',
      quota_progress_pct: '100',
      risk_multiplier: '0',
      max_daily_loss_usd: '5000',
      closed_trades: 14,
      win_count: 11,
      loss_count: 3,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      peak_realized_pnl_usd: '22100.00',
      ratchet_armed: true,
      ratchet_activation_usd: '1000',
      protected_profit_floor_usd: '15470.00',
    },
    banked_session: {
      schema: 'cas-forex.banked-session/1',
      accounting_basis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
      session_date: '2026-11-20',
      initial_capital_usd: '300000',
      current_total_equity_usd: '304000',
      net_surplus_usd: '4000',
      net_surplus_pct: '1.33',
      deficit_to_principal_usd: '0',
      capital_status: 'IN_SURPLUS',
      vault_sweeps_paused_for_recovery: false,
      session_cadence: 'AUTO',
      active_session_leg: 1,
      can_advance_recovery_session: false,
      active_region_window: 'DAILY_NY (17:00 America/New_York)',
      banked_net_pnl_usd: '21741.85',
      realized_pnl_pct: '7.70',
      peak_realized_pnl_usd: '22100.00',
      protected_profit_floor_usd: '15470.00',
      ratchet_armed: true,
      closed_trades: 14,
      win_count: 11,
      loss_count: 3,
      vault_total_realized_usd: '26381.91',
      vault_swept_50pct_usd: '2000',
      session_vault_reserved_50pct_usd: '2000',
      vault_retained_50pct_usd: '24381.91',
      confirmed_bank_payouts_usd: '0',
      profits_locked_for_session: true,
      operating_mode: 'RESEARCH_RESPITE',
      session_rollover_label: '17:00 America/New_York (14:00 Pacific)',
      next_session_opens_utc: '2026-11-20T22:00:00Z',
    },
    open_positions: [],
    recent_actions: [],
  };
}

test('PR21_01 normalizeAiTrader computes Principal High-Water Mark surplus/deficit deterministically when explicit or omitted', () => {
  assert.deepEqual(CAPITAL_STATUSES, ['RECOVERY_MODE', 'AT_PRINCIPAL', 'IN_SURPLUS']);
  assert.deepEqual(SESSION_CADENCE_MODES, ['AUTO', 'REGIONAL_RECOVERY', 'REGIONAL_8H', 'DAILY_NY']);
  assert.equal(STATIC_AI_TRADER.initialCapitalUsd, '300000');
  assert.equal(STATIC_AI_TRADER.sessionCadence, 'AUTO');

  // Explicit banked_session fields
  const explicitRec = normalizeAiTrader(buildUnderwaterRecoveryDoc(true));
  assert.equal(explicitRec.initialCapitalUsd, '300000');
  assert.equal(explicitRec.currentTotalEquityUsd, '282258.15');
  assert.equal(explicitRec.netSurplusUsd, '-17741.85');
  assert.equal(explicitRec.netSurplusPct, '-5.91');
  assert.equal(explicitRec.deficitToPrincipalUsd, '17741.85');
  assert.equal(explicitRec.capitalStatus, 'RECOVERY_MODE');
  assert.equal(explicitRec.vaultSweepsPausedForRecovery, true);
  assert.equal(explicitRec.sessionCadence, 'AUTO');
  assert.equal(explicitRec.activeSessionLeg, 1);
  assert.equal(explicitRec.canAdvanceRecoverySession, true);
  assert.equal(explicitRec.activeRegionWindow, 'ASIA (22:00–07:00 UTC / 14:00–23:00 PT)');

  // Deterministic fallback when banked_session is omitted: 277618.09 + 4640.06 = 282258.15 vs 300000 -> -17741.85 (-5.91%)
  const computedRec = normalizeAiTrader(buildUnderwaterRecoveryDoc(false));
  assert.equal(computedRec.initialCapitalUsd, '300000');
  assert.equal(computedRec.currentTotalEquityUsd, '282258.15');
  assert.equal(computedRec.netSurplusUsd, '-17741.85');
  assert.equal(computedRec.netSurplusPct, '-5.91');
  assert.equal(computedRec.deficitToPrincipalUsd, '17741.85');
  assert.equal(computedRec.capitalStatus, 'RECOVERY_MODE');
  assert.equal(computedRec.vaultSweepsPausedForRecovery, true);
  assert.equal(computedRec.bankedSession.vaultSwept50PctUsd, '0');
  assert.equal(computedRec.canAdvanceRecoverySession, true);

  // Exact breakeven AT_PRINCIPAL
  const breakevenDoc = buildUnderwaterRecoveryDoc(false);
  breakevenDoc.daily_quota.starting_equity_usd = '295000';
  breakevenDoc.daily_quota.realized_net_pnl_usd = '5000';
  const atPrincipal = normalizeAiTrader(breakevenDoc);
  assert.equal(atPrincipal.currentTotalEquityUsd, '300000');
  assert.equal(atPrincipal.netSurplusUsd, '0');
  assert.equal(atPrincipal.capitalStatus, 'AT_PRINCIPAL');
  assert.equal(atPrincipal.vaultSweepsPausedForRecovery, true);
  assert.equal(atPrincipal.canAdvanceRecoverySession, false);
});

test('PR21_02 Underwater RECOVERY_MODE ($282,258.15 vs $300,000.00) pauses vault sweeps ($0.00) and renders 3-Region Auto-Wakeup + Resume button', () => {
  const norm = normalizeAiTrader(buildUnderwaterRecoveryDoc(true));
  for (const route of ['operate', 'review', 'setup']) {
    const state = displayState(fixture(), route);
    state.liveStreamConnected = true;
    state.aiModels = normalizeAiModels(buildModelsDoc());
    state.aiTrader = norm;
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
      pending_disbursement_usd: '0',
      recent_sweeps: [],
      recent_transfers: [],
    });

    const html = renderApp(state, Date.parse(time));
    assert.match(html, /data-banked-profits-hero="true"/);
    assert.match(html, /data-accounting-disclaimer="true"/);
    assert.ok(html.includes('Internal Accounting Figure — Not a Confirmed Bank Payout'));
    assert.ok(html.includes('DEMO PRACTICE ACCOUNT (SIMULATED FUNDS)'));

    // Header badge & Card 1: exact -$17,741.85 (-5.91%) below $300,000.00 Principal
    assert.ok(html.includes('RECOVERY MODE: -$17,741.85 (-5.91%) BELOW $300,000.00 PRINCIPAL'));
    assert.match(html, /data-principal-surplus-card="true"/);
    assert.ok(html.includes('Net Surplus vs Starting Capital ($300,000.00)'));
    assert.ok(html.includes('-$17,741.85'));
    assert.ok(html.includes('Equity $282,258.15 vs $300,000.00 Principal · $17,741.85 to breakeven'));

    // Card 2: Session Recovery Today (NOT surplus profit)
    assert.ok(html.includes('Session Recovery Today (Internal Ledger)'));
    assert.ok(html.includes('+$4,640.06'));
    assert.ok(html.includes('Rebuilding principal — NOT surplus profit · 10 closed trades (7W / 3L) · 70% Session Floor: +$3,396.91'));

    // Card 3: $0.00 vault sweeps paused until > $300,000.00
    assert.ok(html.includes('50% Principal High-Water Vault &amp; Confirmed Payouts'));
    assert.ok(html.includes('Bank Vault Sweeps Paused ($0.00 until > $300,000.00)'));
    assert.ok(html.includes('100% of recovery stays in trading capital'));
    assert.ok(html.includes('Confirmed Settled Payouts: $0.00'));
    assert.equal(html.includes('Pending / Unconfirmed Transfers:'), false);
    assert.equal(html.includes('Internal Vault Reserve</div>'), false, 'Underwater recovery must never claim positive vault reserve');

    // Card 4: Automatic 3-Region wakeup + cadence toggles + 1-click Resume Next Region Session
    assert.ok(html.includes('ASIA (22:00–07:00 UTC / 14:00–23:00 PT)'));
    assert.ok(html.includes('Next Auto-Wakeup: London Session 07:00 UTC / 23:00 PT'));
    assert.match(html, /data-ai-session-cadence="AUTO"[^>]*aria-pressed="true"/);
    assert.match(html, /data-ai-session-cadence="REGIONAL_8H"/);
    assert.match(html, /data-ai-session-cadence="DAILY_NY"/);
    assert.match(html, /data-ai-overseer-action="ADVANCE_RECOVERY_SESSION"[^>]*>Resume Next Region Session<\/button>/);
    assert.equal(/\bstyle\s*=/i.test(html), false);
  }
});

test('PR21_03 Above-Principal IN_SURPLUS ($304,000.00 vs $300,000.00) sweeps 50% of true $4,000.00 surplus ($2,000.00) and hides recovery-only advance', () => {
  const norm = normalizeAiTrader(buildSurplusTraderDoc());
  assert.equal(norm.capitalStatus, 'IN_SURPLUS');
  assert.equal(norm.netSurplusUsd, '4000');
  assert.equal(norm.netSurplusPct, '1.33');
  assert.equal(norm.vaultSweepsPausedForRecovery, false);
  assert.equal(norm.canAdvanceRecoverySession, false);

  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = norm;
  state.treasury = normalizeTreasury({
    schema: 'cas-forex.profit-vault/1',
    sweep_ratio: '0.5',
    sweep_ratio_pct: '50',
    auto_sweep_enabled: true,
    preferred_rail: 'COINBASE_ACH',
    total_realized_profit_usd: '26381.91',
    retained_trading_usd: '24381.91',
    bank_sweep_reserved_usd: '2000',
    disbursed_to_bank_usd: '0',
    pending_disbursement_usd: '2000',
    recent_sweeps: [],
    recent_transfers: [],
  });

  const hero = renderBankedProfitsHeroBanner(state);
  assert.ok(hero.includes('IN SURPLUS: +$4,000.00 (+1.33%) ABOVE $300,000.00 PRINCIPAL'));
  assert.ok(hero.includes('+$4,000.00'));
  assert.ok(hero.includes('Equity $304,000.00 vs $300,000.00 Principal'));
  assert.ok(hero.includes('Session Realized Net P&amp;L (Today · Internal Ledger)'));
  assert.ok(hero.includes('70% Session Floor: +$15,470.00'));
  assert.ok(hero.includes('$2,000.00 Internal Vault Reserve'));
  assert.ok(hero.includes('$2,000.00 Surplus Compounding'));
  assert.ok(hero.includes('Internal Ledger Reserve — Not a Confirmed Bank Payout'));
  assert.ok(hero.includes('Confirmed Settled Payouts: $0.00'));
  assert.ok(hero.includes('17:00 America/New_York'));
  assert.equal(hero.includes('ADVANCE_RECOVERY_SESSION'), false, 'Recovery session advance must be hidden when IN_SURPLUS');
  assert.equal(/\bstyle\s*=/i.test(hero), false);
});

test('PR21_04 app.mjs, analytics.mjs & styles.css wire /api/ai-trader-control, in-place zero-jump rerender, 44px touch targets, and strict CSP/LF invariants', async () => {
  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  const overseerSrc = await readFile(new URL('../../ui/src/ai-overseer.mjs', import.meta.url), 'utf8');
  const analyticsSrc = await readFile(new URL('../../ui/src/analytics.mjs', import.meta.url), 'utf8');
  const stylesSrc = await readFile(new URL('../../ui/styles.css', import.meta.url), 'utf8');

  assert.match(appSrc, /\/api\/ai-trader-control/);
  assert.match(appSrc, /action:\s*'ADVANCE_RECOVERY_SESSION'/);
  assert.match(appSrc, /reason:\s*'Owner recovery session advance'/);
  assert.match(appSrc, /action:\s*'SET_SESSION_CADENCE'/);
  assert.match(appSrc, /function rerenderAiSectionsInPlace\(/);
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false, 'Every focus() call in app.mjs must pass { preventScroll: true }');
  assert.equal(/localStorage/.test(appSrc), false);

  assert.match(stylesSrc, /\.cadence-toggle-btn\s*\{[\s\S]*?min-height:\s*44px/);
  assert.match(stylesSrc, /\.recovery-advance-btn\s*\{[\s\S]*?min-height:\s*44px/);

  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;
  for (const [name, src] of [
    ['app.mjs', appSrc],
    ['ai-overseer.mjs', overseerSrc],
    ['analytics.mjs', analyticsSrc],
    ['styles.css', stylesSrc],
  ]) {
    assert.equal(innerHtmlRe.test(src), false, `Forbidden HTML setter in ${name}`);
    assert.equal(inlineStyleRe.test(src), false, `Forbidden inline style in ${name}`);
    assert.equal(src.includes('\r'), false, `CR byte prohibited in ${name}`);
  }
});

test('PR21_05 Pending or unconfirmed transfers ($5,000.00) with $0.00 settled never inflate surplus or settled payouts and keep RECOVERY MODE active', () => {
  const pendingDoc = buildUnderwaterRecoveryDoc(true);
  pendingDoc.daily_quota.starting_equity_usd = '296000';
  pendingDoc.daily_quota.realized_net_pnl_usd = '2000';
  pendingDoc.banked_session.current_total_equity_usd = '298000';
  pendingDoc.banked_session.net_surplus_usd = '-2000';
  pendingDoc.banked_session.net_surplus_pct = '-0.67';
  pendingDoc.banked_session.deficit_to_principal_usd = '2000';
  pendingDoc.banked_session.capital_status = 'RECOVERY_MODE';
  pendingDoc.banked_session.vault_sweeps_paused_for_recovery = true;
  pendingDoc.banked_session.confirmed_bank_payouts_usd = '0';
  pendingDoc.banked_session.pending_unconfirmed_transfers_usd = '5000';

  const normTrader = normalizeAiTrader(pendingDoc);
  assert.equal(normTrader.capitalStatus, 'RECOVERY_MODE');
  assert.equal(normTrader.confirmedBankPayoutsUsd, '0');
  assert.equal(normTrader.pendingUnconfirmedTransfersUsd, '5000');

  const normTreas = normalizeTreasury({
    schema: 'cas-forex.profit-vault/1',
    sweep_ratio: '0.5',
    sweep_ratio_pct: '50',
    auto_sweep_enabled: true,
    preferred_rail: 'COINBASE_ACH',
    total_realized_profit_usd: '5000',
    retained_trading_usd: '0',
    bank_sweep_reserved_usd: '5000',
    disbursed_to_bank_usd: '5000',
    confirmed_settled_disbursed_usd: '0',
    pending_or_unconfirmed_transfers_usd: '5000',
    pending_disbursement_usd: '0',
    recent_sweeps: [],
    recent_transfers: [
      {
        transfer_id: 'tx-pending-1',
        rail: 'COINBASE_ACH',
        destination_bank_id: 'bank-1',
        amount_usd: '5000',
        status: 'ACH_SUBMITTED',
        created_at: '2026-11-20T05:00:00Z',
      },
    ],
  });
  assert.equal(normTreas.disbursedToBankUsd, '5000');
  assert.equal(normTreas.confirmedSettledDisbursedUsd, '0');
  assert.equal(normTreas.pendingUnconfirmedTransfersUsd, '5000');

  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = normTrader;
  state.treasury = normTreas;

  const hero = renderBankedProfitsHeroBanner(state);
  assert.ok(hero.includes('RECOVERY MODE: -$2,000.00 (-0.67%) BELOW $300,000.00 PRINCIPAL'));
  assert.ok(hero.includes('Bank Vault Sweeps Paused ($0.00 until > $300,000.00)'));
  assert.ok(hero.includes('Confirmed Settled Payouts: $0.00'), 'Must never conflate disbursed_to_bank_usd pending rows with settled payouts');
  assert.ok(hero.includes('Pending / Unconfirmed Transfers: $5,000.00 (excluded from surplus)'));
  assert.equal(hero.includes('Confirmed Settled Payouts: $5,000.00'), false);
});
