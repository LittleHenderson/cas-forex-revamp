// PR #17 UI regression suite: Real-Money LIVE Funding 80/12/8 calculator, 5-Gate preflight,
// Two-Key arming switch, Front-and-Center Live Cloud Unlock Bars, and 0.0px in-place scroll lock.
// Flat top-level test() calls only; zero inline styles or external URLs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  LIVE_FUNDING_PRESETS_USD,
  REQUIRED_LIVE_ARM_PHRASE,
  clampLiveCapitalUsd,
  computeBarbellFundingSplit,
  createDefaultLiveFundingState,
  evaluateLiveArmingPreflight,
  renderLiveFundingPanel,
} from '../../ui/src/live-funding.mjs';
import {
  STATIC_BROKER_ROUTING,
  STATIC_LIVE_READINESS,
  normalizeBrokerRouting,
} from '../../ui/src/broker-routing.mjs';
import {
  createDefaultMoneyFlowState,
  renderMoneyFlowSection,
} from '../../ui/src/money-flow.mjs';
import {
  normalizeAiModels,
  normalizeAiTrader,
  renderAiOverseerPanel,
  STATIC_AI_MODELS,
} from '../../ui/src/ai-overseer.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { displayState, fixture, time } from './helpers.mjs';

function buildRoutingDoc({ live = false, allGatesPassed = false } = {}) {
  return {
    schema: 'cas-forex.broker-routing/2',
    architecture: 'DUAL_SHIELD_BARBELL',
    platform: 'MetaTrader 5',
    execution_mode: live ? 'LIVE' : 'DEMO',
    demo_only: !live,
    live_trading_locked: !live,
    live_trading_armed: live,
    primary_broker: 'HUGOSWAY_MT5',
    active_broker: 'HUGOSWAY_MT5',
    transport_mode: 'SPOOL_BRIDGE',
    valve: { controller: 'tks_meta_valve_controller', parameters: 161, threshold: '0.55' },
    chain: [
      {
        broker_id: 'HUGOSWAY_MT5',
        priority: 1,
        role: 'PRIMARY_MAIN',
        label: "Hugo's Way",
        platform: 'MetaTrader 5',
        server: live ? 'Hugosway-Real3' : 'Hugosway-Demo',
        account_type: live ? 'ECN live' : 'ECN demo',
        max_leverage: '1:500',
        configured: true,
        status: 'ACTIVE',
      },
      {
        broker_id: 'LHFX_MT5',
        priority: 2,
        role: 'SECONDARY_MT5',
        label: 'LHFX',
        platform: 'MetaTrader 5',
        server: live ? 'LHFXSA-Live' : 'LHFXSA-Demo',
        account_type: live ? 'STP/ECN live' : 'STP/ECN demo',
        max_leverage: '1:500',
        configured: true,
        status: 'STANDBY',
      },
      {
        broker_id: live ? 'OANDA_LIVE' : 'OANDA_PRACTICE',
        priority: 3,
        role: 'TERTIARY_REST_FALLBACK',
        label: 'OANDA',
        platform: 'OANDA v20 REST',
        server: live ? 'https://api-fxtrade.oanda.com/v3' : 'https://api-fxpractice.oanda.com/v3',
        account_type: live ? 'fxTrade Live' : 'fxPractice',
        max_leverage: '1:50',
        configured: true,
        status: 'ACTIVE',
      },
    ],
    dual_shield: {
      quote_truth_oracle: { reference_source: live ? 'OANDA_LIVE' : 'OANDA_PRACTICE', max_divergence_bps_major: '15', max_divergence_bps_cross: '25', max_oanda_spread_multiple: '3.0' },
      barbell: { oanda_reserve_share: '0.80', hugosway_share: '0.12', lhfx_share: '0.08', max_stop_loss_equity_risk_pct: '1.00' },
      safe_harbor: { broker_id: live ? 'OANDA_LIVE' : 'OANDA_PRACTICE', leverage: '1:50', recent_degradations: [] },
      offset_planner: true,
      allocation: { total_equity: '25000' },
    },
    live_readiness: {
      execution_mode: live ? 'LIVE' : 'DEMO',
      live_armed: live,
      required_arm_phrase: 'ARM_LIVE_REAL_MONEY_TRADING',
      all_gates_ready: allGatesPassed,
      gates: [
        { id: 'LIVE_CREDENTIALS_STAGED', step: 1, title: 'Live Credentials Staged', passed: allGatesPassed, detail: 'OANDA Live + Hugosway-Real3 + LHFXSA-Live staged.' },
        { id: 'OWNER_ED25519_LIVE_TICKETS', step: 2, title: 'Owner Ed25519 Live Tickets', passed: allGatesPassed, detail: 'All 3 signed Ed25519 venue tickets verified.' },
        { id: 'REAL_BARBELL_80_12_8_CUSTODY', step: 3, title: 'Real 80/12/8 Custody', passed: allGatesPassed, detail: '80% / 12% / 8% balances within 2% tolerance.' },
        { id: 'VALVE_AND_DURABLE_JOURNALS', step: 4, title: 'Valve & Durable Journals', passed: allGatesPassed, detail: '161-param Valve + SQLite journals active.' },
        { id: 'TWO_KEY_LIVE_ARMED', step: 5, title: 'Two-Key Live Armed', passed: allGatesPassed, detail: 'CAS_FOREX_EXECUTION_MODE=LIVE + Key 2 confirmed.' },
      ],
    },
  };
}

test('LF01 Live Funding presets, clamping bounds, and exact integer-cent 80/12/8 barbell conservation', () => {
  assert.deepEqual(LIVE_FUNDING_PRESETS_USD, [1000, 2500, 5000, 10000, 25000, 50000, 100000]);
  assert.equal(REQUIRED_LIVE_ARM_PHRASE, 'ARM_LIVE_REAL_MONEY_TRADING');

  const def = createDefaultLiveFundingState();
  assert.deepEqual(def, { capitalUsd: 10000, armPhraseInput: '', verifyResult: null });

  assert.equal(clampLiveCapitalUsd(50), 300);
  assert.equal(clampLiveCapitalUsd(300), 300);
  assert.equal(clampLiveCapitalUsd(10000), 10000);
  assert.equal(clampLiveCapitalUsd(99999999), 10000000);
  assert.equal(clampLiveCapitalUsd('invalid'), 10000);
  assert.equal(clampLiveCapitalUsd(''), 10000);

  const split10k = computeBarbellFundingSplit(10000);
  assert.equal(split10k.totalCents, 1000000);
  assert.equal(split10k.oandaCents, 800000);
  assert.equal(split10k.hugoswayCents, 120000);
  assert.equal(split10k.lhfxCents, 80000);
  assert.equal(split10k.risk1PctCents, 10000);
  assert.equal(split10k.risk25PctCents, 25000);
  assert.equal(split10k.risk5PctCents, 50000);
  assert.equal(split10k.maxDrawdown20PctCents, 200000);

  for (const amount of [...LIVE_FUNDING_PRESETS_USD, 300, 301, 333, 777, 1234.56, 9999.99, 300000, 10000000]) {
    const s = computeBarbellFundingSplit(amount);
    assert.equal(Number.isSafeInteger(s.totalCents), true);
    assert.equal(Number.isSafeInteger(s.oandaCents), true);
    assert.equal(Number.isSafeInteger(s.hugoswayCents), true);
    assert.equal(Number.isSafeInteger(s.lhfxCents), true);
    assert.equal(s.oandaCents + s.hugoswayCents + s.lhfxCents, s.totalCents, `Cent conservation failed for ${amount}`);
  }
});

test('LF02 evaluateLiveArmingPreflight enforces both Key 2 phrase match and all 5 cloud gates', () => {
  const demoRouting = normalizeBrokerRouting(buildRoutingDoc({ live: false, allGatesPassed: false }));
  const liveReadyRouting = normalizeBrokerRouting(buildRoutingDoc({ live: true, allGatesPassed: true }));

  const v0 = evaluateLiveArmingPreflight({ capitalUsd: 10000, armPhraseInput: '' }, demoRouting);
  assert.equal(v0.phraseMatched, false);
  assert.equal(v0.gatesReady, false);
  assert.equal(v0.canArmLive, false);

  const v1 = evaluateLiveArmingPreflight({ capitalUsd: 10000, armPhraseInput: '  ARM_LIVE_REAL_MONEY_TRADING  ' }, demoRouting);
  assert.equal(v1.phraseMatched, true);
  assert.equal(v1.gatesReady, false);
  assert.equal(v1.canArmLive, false);
  assert.match(v1.detail, /Stage_Live_Funding_To_Cloud\.ps1/);

  const v2 = evaluateLiveArmingPreflight({ capitalUsd: 10000, armPhraseInput: 'WRONG_PHRASE' }, liveReadyRouting);
  assert.equal(v2.phraseMatched, false);
  assert.equal(v2.gatesReady, true);
  assert.equal(v2.canArmLive, false);

  const v3 = evaluateLiveArmingPreflight({ capitalUsd: 10000, armPhraseInput: 'ARM_LIVE_REAL_MONEY_TRADING' }, liveReadyRouting);
  assert.equal(v3.phraseMatched, true);
  assert.equal(v3.gatesReady, true);
  assert.equal(v3.canArmLive, true);
  assert.match(v3.headline, /READY FOR REAL-MONEY LIVE EXECUTION/);
});

test('LF03 normalizeBrokerRouting falls back to STATIC_LIVE_READINESS when live_readiness is omitted and escapes hostile text', () => {
  const legacyDoc = buildRoutingDoc({ live: false, allGatesPassed: false });
  delete legacyDoc.live_readiness;
  const normLegacy = normalizeBrokerRouting(legacyDoc);
  assert.equal(normLegacy.liveReadiness, STATIC_LIVE_READINESS);
  assert.equal(STATIC_BROKER_ROUTING.liveReadiness, STATIC_LIVE_READINESS);
  assert.equal(STATIC_LIVE_READINESS.gates.length, 5);

  const hostileDoc = buildRoutingDoc({ live: false, allGatesPassed: false });
  hostileDoc.live_readiness.gates[0].detail = '<script>alert("xss")</script>';
  const normHostile = normalizeBrokerRouting(hostileDoc);
  const panelHtml = renderLiveFundingPanel({
    liveFunding: createDefaultLiveFundingState(),
    brokerRouting: normHostile,
  });
  assert.equal(panelHtml.includes('<script>'), false);
  assert.match(panelHtml, /&lt;script&gt;alert/);
});

test('LF04 Prominent Live Cloud Unlock Bars render in Overseer and Top Workspace while preserving Connect live server and safety banner', () => {
  const disconnectedOverseer = renderAiOverseerPanel({ aiTrader: null, aiModels: null });
  assert.match(disconnectedOverseer, /data-connect-loopback="true"/);
  assert.match(disconnectedOverseer, />Connect live server<\/button>/);
  assert.match(disconnectedOverseer, /class="mobile-unlock-bar prominent-unlock-bar"/);
  assert.match(disconnectedOverseer, /id="overseer-access-key"/);
  assert.match(disconnectedOverseer, /Launch_24x7_Cloud_Cockpit\.cmd/);
  assert.match(disconnectedOverseer, />Unlock &amp; Connect Live Cloud<\/button>/);

  const offlineState = displayState(fixture(), 'operate');
  offlineState.liveStreamConnected = false;
  const offlineAppHtml = renderApp(offlineState, Date.parse(time));
  assert.match(offlineAppHtml, /Disconnected fixture - read only/);
  assert.match(offlineAppHtml, /id="top-cockpit-access-key"/);
  assert.match(offlineAppHtml, />Unlock Live Cockpit<\/button>/);
  assert.match(offlineAppHtml, />DEMO MODE<\/span>/);

  const connectedState = displayState(fixture(), 'operate');
  connectedState.liveStreamConnected = true;
  connectedState.brokerRouting = normalizeBrokerRouting(buildRoutingDoc({ live: true, allGatesPassed: true }));
  connectedState.aiModels = normalizeAiModels({
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
  });
  connectedState.aiTrader = normalizeAiTrader({
    schema: 'cas-forex.ai-trader/1',
    governance_mode: 'ACTIVE',
    daily_quota: {
      session_date: '2026-11-19',
      status: 'OPEN',
      quota_mode: 'USD',
      realized_net_pnl_usd: '0',
      realized_pnl_pct: '0',
      soft_quota_usd: '500',
      hard_quota_usd: '1000',
      max_daily_loss_usd: '500',
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      quota_progress_pct: '0',
      risk_multiplier: '1',
    },
  });
  const connectedAppHtml = renderApp(connectedState, Date.parse(time));
  assert.match(connectedAppHtml, /Connected · Live 24\/7 Cloud/);
  assert.equal(connectedAppHtml.includes('id="top-cockpit-access-key"'), false);
  assert.equal(connectedAppHtml.includes('id="overseer-access-key"'), false);
  assert.match(connectedAppHtml, />LIVE REAL-MONEY ARMED<\/span>/);
  assert.match(connectedAppHtml, /CURRENT MODE: REAL-MONEY LIVE ARMED/);
});

test('LF05 renderLiveFundingPanel renders prominently on both 01 Operate and 03 Setup with all 3 steps and 5 gates', () => {
  const opState = displayState(fixture(), 'operate');
  opState.liveFunding = { capitalUsd: 25000, armPhraseInput: '', verifyResult: null };
  const opHtml = renderApp(opState, Date.parse(time));
  assert.match(opHtml, /id="live-funding-section"/);
  assert.match(opHtml, /CURRENT MODE: DEMO PAPER ACCOUNTS — REAL-MONEY LIVE LOCKED/);
  assert.match(opHtml, /\$20,000\.00/); // 80% OANDA Live
  assert.match(opHtml, /\$3,000\.00/);  // 12% Hugo's Way Live MT5 (Hugosway-Real3)
  assert.match(opHtml, /\$2,000\.00/);  // 8% LHFX Live MT5 (LHFXSA-Live)
  assert.match(opHtml, /Hugosway-Real3/);
  assert.match(opHtml, /LHFXSA-Live/);
  assert.match(opHtml, /Stage_Live_Funding_To_Cloud\.ps1/);
  assert.match(opHtml, /data-lf-phrase-input="true"/);
  assert.match(opHtml, /data-lf-verify="true"/);
  assert.ok(opHtml.indexOf('id="live-funding-section"') < opHtml.indexOf('Autonomous AI Trader &amp; Daily Quota'));

  const setupState = displayState(fixture(), 'setup');
  const setupHtml = renderApp(setupState, Date.parse(time));
  assert.match(setupHtml, /id="live-funding-section"/);
  assert.ok(setupHtml.indexOf('id="live-funding-section"') < setupHtml.indexOf('Broker &amp; MetaTrader 5 Routing'));
});

test('LF06 Money Flow and Live Funding in-place no-jump IDs, scrollTo lock, preventScroll focus, strict CSP, and LF endings', async () => {
  const mfHtml = renderMoneyFlowSection({ moneyFlow: createDefaultMoneyFlowState() });
  assert.match(mfHtml, /id="money-flow-section"/);

  const lfHtml = renderLiveFundingPanel({ liveFunding: createDefaultLiveFundingState() });
  assert.match(lfHtml, /id="live-funding-section"/);

  for (const route of ['operate', 'review', 'setup']) {
    const html = renderApp(displayState(fixture(), route), Date.parse(time));
    assert.equal(/\bstyle\s*=/i.test(html), false, `Inline style prohibited on route ${route}`);
  }

  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  assert.match(appSrc, /function rerenderMoneyFlowInPlace\(/);
  assert.match(appSrc, /function rerenderLiveFundingInPlace\(/);
  assert.match(appSrc, /window\.scrollTo\(/);
  assert.match(appSrc, /preventScroll:\s*true/);
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false, 'All focus() calls in app.mjs must pass { preventScroll: true }');

  const checkedFiles = [
    '../../ui/src/live-funding.mjs',
    '../../ui/src/broker-routing.mjs',
    '../../ui/src/money-flow.mjs',
    '../../ui/src/ai-overseer.mjs',
    '../../ui/src/render.mjs',
    '../../ui/src/app.mjs',
    '../../ui/styles.css',
  ];
  for (const rel of checkedFiles) {
    const raw = await readFile(new URL(rel, import.meta.url), 'utf8');
    if (rel.endsWith('.mjs')) {
      assert.equal(/\binnerHTML\b/.test(raw), false, `innerHTML prohibited in ${rel}`);
      assert.equal(/\bouterHTML\b/.test(raw), false, `outerHTML prohibited in ${rel}`);
      assert.equal(/\bstyle\s*=\s*["']/.test(raw), false, `Inline style attribute prohibited in ${rel}`);
    }
  }
});
