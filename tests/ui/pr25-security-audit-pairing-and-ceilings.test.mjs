// PR #25 UI Security Audit Remediation Suite:
// - Finding [2] (High): Single-use ?pair_code= ephemeral pairing nonces (zero ?token= primary bearer in URLs/QR),
//   server-side revocation button (POST /api/pair-revoke), boot URL stripping, POST /api/pair-exchange,
//   GET /api/auth-session privilege sync, Least-Privilege DEVICE_READ_AND_EXPLAINER session badges,
//   owner control lockouts, and Primary Owner Key step-up unlock bar.
// - Finding [5] (High): Immutable 1.00% per-trade stop-loss risk & 10.00% drawdown constitutional ceilings
//   across 3-Gear Adaptive Risk (0.50% / 0.50%->0.75%->1.00% / 1.00%) and Money Flow scenario explorer.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  PAIRING_DEFAULT_TTL_SECONDS,
  SESSION_SCOPES,
  buildPairingUrl,
  extractAndStripBootPairingParams,
  isOwnerControlSession,
  normalizeAuthSessionResponse,
  normalizePairCodeMintResponse,
  normalizePairExchangeResponse,
  renderQrPairingDrawer,
  renderQrSvg,
} from '../../ui/src/qr-pairing.mjs';
import {
  CONSTITUTIONAL_MAX_DRAWDOWN_PCT,
  CONSTITUTIONAL_MAX_STOP_RISK_PCT,
  STATIC_AI_MODELS,
  STATIC_AI_TRADER,
  normalizeAiModels,
  normalizeAiTrader,
  renderAiOverseerPanel,
  renderBankedProfitsHeroBanner,
} from '../../ui/src/ai-overseer.mjs';
import {
  CONSTITUTIONAL_MAX_DRAWDOWN_PCT as MF_MAX_DD_PCT,
  CONSTITUTIONAL_MAX_STOP_RISK_PCT as MF_MAX_RISK_PCT,
  MONEY_FLOW_RISK_PRESETS,
  computeLotComparisonRows,
  computeMoneyFlowScenario,
  createDefaultMoneyFlowState,
  renderMoneyFlowSection,
} from '../../ui/src/money-flow.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { displayState, fixture, time } from './helpers.mjs';

function buildReadyModelsDoc() {
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
    fast_scout_enabled: true,
    fast_scout_model_id: 'gemini-decision-1',
    fast_scout_ready: true,
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

function buildActiveTraderDoc(overrides = {}) {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous execution active under constitutional caps.',
    effective_status: 'ACTIVE',
    respite_mode: true,
    operating_mode: 'RESEARCH_RESPITE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 88,
    last_cycle_ms: 28,
    last_action: 'WAIT',
    last_symbol: 'EURUSD',
    last_reason: 'Scanning under 1.00% stop-risk cap',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20-ASIA',
      status: 'DAILY_QUOTA_LOCKED',
      new_risk_allowed: false,
      quota_mode: 'USD',
      starting_equity_usd: '280000',
      realized_net_pnl_usd: '1200',
      realized_pnl_pct: '0.43',
      soft_quota_usd: '500',
      hard_quota_usd: '1000',
      quota_progress_pct: '100',
      risk_multiplier: '0',
      max_daily_loss_usd: '500',
      closed_trades: 3,
      win_count: 3,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      peak_realized_pnl_usd: '1200',
      ratchet_armed: true,
      ratchet_activation_usd: '500',
      protected_profit_floor_usd: '840',
    },
    banked_session: {
      schema: 'cas-forex.banked-session/1',
      accounting_basis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
      session_date: '2026-11-20-ASIA',
      initial_capital_usd: '300000',
      current_total_equity_usd: '281200',
      net_surplus_usd: '-18800',
      net_surplus_pct: '-6.27',
      deficit_to_principal_usd: '18800',
      capital_status: 'RECOVERY_MODE',
      vault_sweeps_paused_for_recovery: true,
      session_cadence: 'AUTO',
      active_session_leg: 1,
      can_advance_recovery_session: true,
      active_region_window: 'ASIA (22:00–07:00 UTC / 14:00–23:00 PT)',
      banked_net_pnl_usd: '1200',
      realized_pnl_pct: '0.43',
      peak_realized_pnl_usd: '1200',
      protected_profit_floor_usd: '840',
      ratchet_armed: true,
      closed_trades: 3,
      win_count: 3,
      loss_count: 0,
      vault_total_realized_usd: '1200',
      vault_swept_50pct_usd: '0',
      session_vault_reserved_50pct_usd: '0',
      vault_retained_50pct_usd: '1200',
      confirmed_bank_payouts_usd: '0',
      profits_locked_for_session: true,
      operating_mode: 'RESEARCH_RESPITE',
    },
    open_positions: [],
    recent_actions: [],
    ...overrides,
  };
}

test('PR25_01 buildPairingUrl & normalizePairCodeMintResponse enforce single-use ?pair_code= and block primary bearer reuse', () => {
  assert.equal(PAIRING_DEFAULT_TTL_SECONDS, 120);
  assert.deepEqual(SESSION_SCOPES, {
    OWNER_FULL_CONTROL: 'OWNER_FULL_CONTROL',
    DEVICE_READ_AND_EXPLAINER: 'DEVICE_READ_AND_EXPLAINER',
  });

  const sampleNonce = ['nonce', 'n'.repeat(32)].join('-');
  const ownerPrimary = ['owner', 'o'.repeat(36)].join('-');
  const url = buildPairingUrl('https://52-33-1-177.sslip.io', sampleNonce);
  assert.equal(url, `https://52-33-1-177.sslip.io/ui/index.html?pair_code=${sampleNonce}`);
  assert.equal(url.includes('?token='), false, 'buildPairingUrl must never emit ?token=');
  assert.equal(url.includes('&token='), false);

  assert.throws(() => buildPairingUrl('https://52-33-1-177.sslip.io', 'short'));
  assert.throws(() => buildPairingUrl('https://52-33-1-177.sslip.io', `token=${sampleNonce}`));
  assert.throws(() => buildPairingUrl('https://52-33-1-177.sslip.io', `${sampleNonce} extra`));
  assert.throws(() => buildPairingUrl('file:///C:/ui/index.html', sampleNonce));

  const minted = normalizePairCodeMintResponse({
    pair_code: sampleNonce,
    expires_at: '2026-11-20T17:02:00Z',
    ttl_seconds: 120,
    scope: 'DEVICE_READ_AND_EXPLAINER',
  }, ownerPrimary);
  assert.equal(minted.pairCode, sampleNonce);
  assert.equal(minted.ttlSeconds, 120);
  assert.equal(minted.expiresAt, '2026-11-20T17:02:00Z');
  assert.equal(minted.scope, 'DEVICE_READ_AND_EXPLAINER');

  assert.throws(
    () => normalizePairCodeMintResponse({ pair_code: ownerPrimary, ttl_seconds: 120 }, ownerPrimary),
    /matches primary owner bearer/,
  );
});

test('PR25_02 Boot URL parameter extraction strips ?pair_code= and rejects/strips legacy ?token= immediately', () => {
  const sampleNonce = ['boot', 'b'.repeat(30)].join('-');
  const legacyBearer = ['legacy', 'l'.repeat(34)].join('-');
  const calls = [];
  const fakeHistory = {
    replaceState(st, title, nextUrl) {
      calls.push(nextUrl);
    },
  };

  // 1) Valid ?pair_code= is extracted and immediately stripped from browser history
  const r1 = extractAndStripBootPairingParams(
    { pathname: '/ui/index.html', search: `?pair_code=${sampleNonce}&view=1`, hash: '#operate' },
    fakeHistory,
  );
  assert.equal(r1.pairCode, sampleNonce);
  assert.equal(r1.strippedLegacyToken, false);
  assert.equal(r1.cleanPath, '/ui/index.html?view=1#operate');
  assert.equal(calls.at(-1), '/ui/index.html?view=1#operate');

  // 2) Legacy ?token= is NEVER accepted as a credential and is stripped from URL history immediately
  const r2 = extractAndStripBootPairingParams(
    { pathname: '/ui/index.html', search: `?token=${legacyBearer}`, hash: '#setup' },
    fakeHistory,
  );
  assert.equal(r2.pairCode, null);
  assert.equal(r2.strippedLegacyToken, true);
  assert.equal(r2.cleanPath, '/ui/index.html#setup');
  assert.equal(calls.at(-1), '/ui/index.html#setup');

  // 3) Pair exchange & auth-session responses enforce least-privilege scope invariants
  const deviceHandle = ['dev', 'd'.repeat(35)].join('-');
  const exchanged = normalizePairExchangeResponse({
    session_token: deviceHandle,
    session_scope: 'DEVICE_READ_AND_EXPLAINER',
    owner_controls_allowed: true, // Server bug or tamper attempt must still force false under DEVICE_READ_AND_EXPLAINER!
    session_epoch: 'ep-1',
    expires_at: '2026-11-21T00:00:00Z',
  });
  assert.equal(exchanged.sessionToken, deviceHandle);
  assert.equal(exchanged.sessionScope, 'DEVICE_READ_AND_EXPLAINER');
  assert.equal(exchanged.ownerControlsAllowed, false);

  const authReadOnly = normalizeAuthSessionResponse({
    authenticated: true,
    session_scope: 'DEVICE_READ_AND_EXPLAINER',
    owner_controls_allowed: false,
    expires_at: '2026-11-21T00:00:00Z',
  });
  assert.equal(authReadOnly.sessionScope, 'DEVICE_READ_AND_EXPLAINER');
  assert.equal(authReadOnly.ownerControlsAllowed, false);

  const authOwner = normalizeAuthSessionResponse({
    authenticated: true,
    session_scope: 'OWNER_FULL_CONTROL',
    owner_controls_allowed: true,
    expires_at: null,
  });
  assert.equal(authOwner.sessionScope, 'OWNER_FULL_CONTROL');
  assert.equal(authOwner.ownerControlsAllowed, true);
});

test('PR25_03 QR Pairing Drawer renders Revoke Pairing Code, 120s server TTL, and Least-Privilege Read & Explainer disclosures', () => {
  const sampleNonce = ['qr', 'z'.repeat(34)].join('-');
  const svg = renderQrSvg(buildPairingUrl('https://52-33-1-177.sslip.io', sampleNonce));
  const drawer = renderQrPairingDrawer(svg, 'Single-use pairing link (?pair_code=...) copied to clipboard.', {
    ttlSeconds: 120,
    expiresAt: '2026-11-20T17:02:00Z',
    scopeLabel: 'DEVICE_READ_AND_EXPLAINER',
  });
  assert.match(drawer, /data-qr-pairing-panel="true"/);
  assert.match(drawer, /data-copy-unlock-link="true"/);
  assert.match(drawer, /data-revoke-qr-pairing="true">Revoke Pairing Code<\/button>/);
  assert.match(drawer, /data-toggle-qr-pairing="true">Hide QR<\/button>/);
  assert.match(drawer, /120s single-use TTL/);
  assert.match(drawer, /2026-11-20T17:02:00Z/);
  assert.match(drawer, /DEVICE_READ_AND_EXPLAINER/);
  assert.match(drawer, /\?pair_code=/);
  assert.match(drawer, /POST \/api\/pair-exchange/);
  assert.equal(drawer.includes('?token='), false);
  assert.equal(drawer.includes(sampleNonce), false, 'Nonce string must never be rendered in visible HTML');
});

test('PR25_04 Paired Device (DEVICE_READ_AND_EXPLAINER) locks owner controls, hides QR minting, shows Step-Up bar, and keeps Gemini 4 Neon Explainer enabled', () => {
  const models = normalizeAiModels(buildReadyModelsDoc());
  const trader = normalizeAiTrader(buildActiveTraderDoc());

  // 1) Owner Full Control session
  const ownerState = displayState(fixture(), 'setup');
  ownerState.liveStreamConnected = true;
  ownerState.sessionScope = 'OWNER_FULL_CONTROL';
  ownerState.ownerControlsAllowed = true;
  ownerState.canPairDevice = true;
  ownerState.aiModels = models;
  ownerState.aiTrader = trader;
  assert.equal(isOwnerControlSession(ownerState), true);

  const ownerSetupHtml = renderApp(ownerState, Date.parse(time));
  assert.match(ownerSetupHtml, /data-session-privilege-badge="OWNER_FULL_CONTROL">Owner Full Control<\/span>/);
  assert.match(ownerSetupHtml, /data-toggle-qr-pairing="true"/);
  assert.match(ownerSetupHtml, /data-revoke-qr-pairing="true">Revoke Paired Devices<\/button>/);
  assert.equal(ownerSetupHtml.includes('data-stepup-unlock-bar="true"'), false);

  // 2) Paired Device Read + Explainer session
  const pairedState = displayState(fixture(), 'operate');
  pairedState.liveStreamConnected = true;
  pairedState.sessionScope = 'DEVICE_READ_AND_EXPLAINER';
  pairedState.ownerControlsAllowed = false;
  pairedState.canPairDevice = false;
  pairedState.aiModels = models;
  pairedState.aiTrader = trader;
  assert.equal(isOwnerControlSession(pairedState), false);

  const pairedOperateHtml = renderApp(pairedState, Date.parse(time));
  assert.match(
    pairedOperateHtml,
    /data-session-privilege-badge="DEVICE_READ_AND_EXPLAINER">Paired Device \(Read \+ Explainer · Owner Controls Locked\)<\/span>/,
  );
  assert.match(pairedOperateHtml, /data-stepup-unlock-bar="true"/);
  assert.match(pairedOperateHtml, /id="stepup-cockpit-access-key"/);
  assert.match(pairedOperateHtml, />Step Up to Owner Control<\/button>/);
  assert.match(pairedOperateHtml, /data-paired-readonly-notice="true"/);
  assert.equal(pairedOperateHtml.includes('data-toggle-qr-pairing="true"'), false, 'Paired device cannot mint new pairing QR');

  // Verify owner controls in Overseer & Hero are disabled while Voice Explainer remains enabled
  const overseerHtml = renderAiOverseerPanel(pairedState);
  assert.match(overseerHtml, /id="ai-model-select"[^>]*disabled/);
  assert.match(overseerHtml, /data-ai-overseer-action="TOGGLE_FAST_SCOUT"[^>]*disabled/);
  assert.match(overseerHtml, /data-risk-gear="CONSERVATIVE"[^>]*disabled/);
  assert.match(overseerHtml, /data-risk-gear="AUTO_ADAPTIVE"[^>]*disabled/);
  assert.match(overseerHtml, /data-risk-gear="AGGRESSIVE"[^>]*disabled/);
  assert.match(overseerHtml, /data-ai-overseer-action="PAUSE_NEW_RISK"[^>]*disabled/);
  assert.match(overseerHtml, /data-ai-overseer-action="EMERGENCY_CLOSE_ALL"[^>]*disabled/);

  const heroHtml = renderBankedProfitsHeroBanner(pairedState);
  assert.match(heroHtml, /data-ai-overseer-action="ADVANCE_RECOVERY_SESSION"[^>]*disabled/);
  assert.match(heroHtml, /data-ai-session-cadence="AUTO"[^>]*disabled/);
  assert.match(heroHtml, /data-ai-session-cadence="REGIONAL_8H"[^>]*disabled/);
  assert.match(heroHtml, /data-ai-session-cadence="DAILY_NY"[^>]*disabled/);
  const voiceBtnMatch = heroHtml.match(/<button[^>]*data-open-voice-explainer="true"[^>]*>/);
  assert.ok(voiceBtnMatch, 'Gemini 4 Neon button must render');
  assert.equal(/\bdisabled\b/.test(voiceBtnMatch[0]), false, 'Gemini 4 Neon Explainer remains enabled on paired device');
});

test('PR25_05 Finding [5] Immutable 1.00% Stop-Risk & 10.00% Drawdown Constitutional Ceilings enforced in Overseer & Money Flow', () => {
  assert.equal(CONSTITUTIONAL_MAX_STOP_RISK_PCT, '1');
  assert.equal(CONSTITUTIONAL_MAX_DRAWDOWN_PCT, '0.1');
  assert.equal(MF_MAX_RISK_PCT, 1);
  assert.equal(MF_MAX_DD_PCT, 10);
  assert.deepEqual(MONEY_FLOW_RISK_PRESETS, [0.25, 0.5, 0.75, 1]);

  // Static defaults reflect 0.50% conservative start, 1.00% max stop risk, 10.00% max drawdown
  assert.equal(STATIC_AI_TRADER.riskGear.effectiveRiskPct, '0.5');
  assert.equal(STATIC_AI_TRADER.riskGear.ownerMaxRiskPct, '1');
  assert.equal(STATIC_AI_TRADER.riskGear.softDrawdownDownshiftPct, '0.05');
  assert.equal(STATIC_AI_TRADER.riskGear.ownerMaxDrawdownPct, '0.1');

  // Weakened backend values (> 1% risk or > 10% drawdown) are clamped to constitutional ceilings
  const clampedTrader = normalizeAiTrader(buildActiveTraderDoc({
    risk_gear: {
      owner_mode: 'AGGRESSIVE',
      active_gear: 'AGGRESSIVE',
      effective_risk_pct: '5.00',
      owner_max_risk_pct: '5.00',
      effective_soft_quota_usd: '2000',
      effective_hard_quota_usd: '3000',
      owner_hard_quota_usd: '3000',
      soft_drawdown_downshift_pct: '0.20',
      owner_max_drawdown_pct: '0.50',
      reason: 'Aggressive gear selected.',
    },
  }));
  assert.equal(clampedTrader.riskGear.effectiveRiskPct, '1');
  assert.equal(clampedTrader.riskGear.ownerMaxRiskPct, '1');
  assert.equal(clampedTrader.riskGear.softDrawdownDownshiftPct, '0.1');
  assert.equal(clampedTrader.riskGear.ownerMaxDrawdownPct, '0.1');

  const overseerHtml = renderAiOverseerPanel({ aiTrader: clampedTrader, aiModels: normalizeAiModels(buildReadyModelsDoc()) });
  assert.ok(overseerHtml.includes('Conservative (0.50% · $500–$1k)'));
  assert.ok(overseerHtml.includes('Auto-Adaptive (0.50% → 0.75% → 1.00% · $500→$3k)'));
  assert.ok(overseerHtml.includes('Aggressive (1.00% · $2k–$3k)'));
  assert.ok(overseerHtml.includes('Hard constitutional ceiling: 1.00% max stop risk · 10.00% max drawdown · $3000 daily cap.'));
  assert.equal(overseerHtml.includes('1%→2.5%→5%'), false);
  assert.equal(overseerHtml.includes('Aggressive (5%'), false);
  assert.equal(overseerHtml.includes('20% max drawdown'), false);

  // Money Flow blocks > 1.00% direct-lot risk even when 1,000% margin cushion passes!
  const blockedDirectLot = computeMoneyFlowScenario({
    capitalCents: 10000000, // $100,000
    marketId: 'EURUSD',
    lotMode: 'direct',
    directLotHundredths: 800, // 8.00 lots -> $2,000 stop loss = 2.00% risk (margin = $1,760 -> 5,681% >= 1,000%)
    ownerMaxRiskPct: 5, // Attempted 5% override must still be clamped to 1.00%
  });
  assert.equal(blockedDirectLot.marginOk, true);
  assert.equal(blockedDirectLot.ownerMaxRiskPct, 1);
  assert.equal(blockedDirectLot.allowed, false, '2.00% stop risk must be blocked by 1.00% constitutional ceiling');
  assert.match(blockedDirectLot.badge, /BLOCKED BY 1\.00% CONSTITUTIONAL RISK CAP/);

  const rows = computeLotComparisonRows({ capitalCents: 10000000, marketId: 'EURUSD' });
  assert.ok(rows.some((r) => r.key === 'risk:0.5' && r.scenario.allowed));
  assert.ok(rows.some((r) => r.key === 'risk:0.75' && r.scenario.allowed));
  assert.ok(rows.some((r) => r.key === 'risk:1' && r.scenario.allowed));
  assert.equal(rows.some((r) => r.key === 'risk:2' || r.key === 'risk:5'), false);

  const mfLotsHtml = renderMoneyFlowSection({ moneyFlow: { ...createDefaultMoneyFlowState(), tab: 'lots' } });
  assert.match(mfLotsHtml, /To 10\.00% Drawdown Lock/);
  assert.match(mfLotsHtml, /immutable constitutional ceiling 1\.00% max stop risk · 10\.00% max drawdown/);
  assert.equal(mfLotsHtml.includes('20% Lock'), false);
});

test('PR25_06 app.mjs wires /api/pair-code, /api/pair-revoke, /api/pair-exchange, /api/auth-session, and strict CSP / zero-localStorage invariants', async () => {
  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  assert.match(appSrc, /\/api\/pair-code/);
  assert.match(appSrc, /\/api\/pair-revoke/);
  assert.match(appSrc, /\/api\/pair-exchange/);
  assert.match(appSrc, /\/api\/auth-session/);
  assert.match(appSrc, /extractAndStripBootPairingParams/);
  assert.match(appSrc, /requireOwnerControlOrWarn/);
  assert.equal(appSrc.includes("bootParams.get('token')"), false, 'app.mjs must never accept ?token= query bearer');
  assert.equal(/buildPairingUrl\(\s*window\.location\.origin\s*,\s*loopbackAuthToken\s*\)/.test(appSrc), false, 'Primary bearer must never be passed to buildPairingUrl');
  assert.equal(/localStorage/.test(appSrc), false, 'Zero localStorage allowed');
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false, 'Every focus() call in app.mjs must pass { preventScroll: true }');

  const checkedFiles = [
    '../../ui/src/qr-pairing.mjs',
    '../../ui/src/app.mjs',
    '../../ui/src/render.mjs',
    '../../ui/src/ai-overseer.mjs',
    '../../ui/src/money-flow.mjs',
    '../../ui/styles.css',
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
