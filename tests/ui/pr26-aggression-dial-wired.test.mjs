// PR #26 End-to-End UI Wiring Regression Suite:
// - Top-of-Operate Master Trading Aggression Dial (20..100 bps in 0.01% steps, 6 presets,
//   role="switch" AI Discretion pill, 4 instant metrics, unbreakable 0.55 Valve / 1,000% Margin / 1.00% Risk / 10.00% DD).
// - Section B.5 5-Tier Per-Account Aggression Dials wired directly inside renderParallelTiersSection
//   with 3 one-tap race presets (Sync All 5 to Master, Stagger Safe -> Extreme, All Balanced 0.60%).
// - Hydration from /api/aggression-dial, /api/ai-trader, and /api/parallel-tiers + LIVE mode & PR #25
//   paired-device (DEVICE_READ_AND_EXPLAINER -> disabled + "Owner Key Required") privilege fusion.
// - Zero-flicker patchAggressionDialInPlace + debounced POST /api/aggression-dial + CSS parity & strict CSP.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  AGGRESSION_DIAL_CSS_SNIPPET,
  AGGRESSION_DIAL_SCHEMA,
  DEFAULT_TIER_DEFINITIONS,
  applyAggressionDialPreset,
  applyMarketConditionPreview,
  normalizeAggressionDial,
  patchAggressionDialInPlace,
  resolveCockpitAggressionDial,
} from '../../ui/src/aggression-dial.mjs';
import {
  STATIC_AI_MODELS,
  normalizeAiModels,
  normalizeAiTrader,
  renderAiOverseerPanel,
} from '../../ui/src/ai-overseer.mjs';
import {
  normalizeParallelTiers,
  renderParallelTiersSection,
} from '../../ui/src/analytics.mjs';
import { normalizeBrokerRouting } from '../../ui/src/broker-routing.mjs';
import { renderApp, renderMasterAggressionDial } from '../../ui/src/render.mjs';
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

function buildTraderDoc(aggressionDialOverride = null) {
  return {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous execution active under Master Aggression Dial.',
    effective_status: 'ACTIVE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 45,
    last_cycle_ms: 29,
    last_action: 'BUY',
    last_symbol: 'NAS100',
    last_reason: 'Trend breakout cleared 0.55 valve',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20',
      status: 'OPEN',
      new_risk_allowed: true,
      quota_mode: 'USD',
      starting_equity_usd: '300000',
      realized_net_pnl_usd: '1250',
      realized_pnl_pct: '0.42',
      soft_quota_usd: '3150',
      hard_quota_usd: '4500',
      quota_progress_pct: '27.78',
      risk_multiplier: '1',
      max_daily_loss_usd: '2500',
      closed_trades: 2,
      win_count: 2,
      loss_count: 0,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
    },
    ...(aggressionDialOverride ? { aggression_dial: aggressionDialOverride } : {}),
    open_positions: [],
    recent_actions: [],
  };
}

function parseMiniDom(html) {
  const voids = new Set(['INPUT', 'IMG', 'BR', 'HR', 'META', 'LINK', 'CANVAS']);
  function createNode(tag, attrs = {}) {
    const attrMap = new Map(Object.entries(attrs));
    const classSet = new Set(String(attrs.class || '').split(/\s+/).filter(Boolean));
    const children = [];
    let textOverride = null;
    let valueVal = attrs.value ?? '';
    let disabledVal = attrs.disabled !== undefined;
    let hiddenVal = attrs.hidden !== undefined;
    const node = {
      tagName: tag.toUpperCase(),
      children,
      classList: {
        add(...items) { items.forEach((c) => c && classSet.add(c)); },
        remove(...items) { items.forEach((c) => classSet.delete(c)); },
        contains(c) { return classSet.has(c); },
        toggle(c, force) {
          const next = force !== undefined ? Boolean(force) : !classSet.has(c);
          if (next) classSet.add(c); else classSet.delete(c);
          return next;
        },
      },
      get textContent() {
        if (textOverride !== null) return textOverride;
        return children.map((c) => (typeof c === 'string' ? c : c.textContent)).join('');
      },
      set textContent(v) {
        textOverride = String(v ?? '');
        children.length = 0;
      },
      get value() { return valueVal; },
      set value(v) { valueVal = String(v ?? ''); },
      get disabled() { return disabledVal; },
      set disabled(v) { disabledVal = Boolean(v); },
      get hidden() { return hiddenVal; },
      set hidden(v) { hiddenVal = Boolean(v); },
      get innerHTML() { throw new Error('innerHTML prohibited'); },
      set innerHTML(_v) { throw new Error('innerHTML prohibited'); },
      get style() { throw new Error('inline style prohibited'); },
      getAttribute(k) { return attrMap.get(k.toLowerCase()) ?? null; },
      hasAttribute(k) { return attrMap.has(k.toLowerCase()); },
      setAttribute(k, v) {
        if (k.toLowerCase() === 'style') throw new Error('style attribute prohibited');
        attrMap.set(k.toLowerCase(), String(v));
      },
      removeAttribute(k) { attrMap.delete(k.toLowerCase()); },
      matches(sel) {
        const mEq = /^\[([a-z0-9_-]+)="([^"]*)"\]$/i.exec(sel.trim());
        if (mEq) return node.getAttribute(mEq[1]) === mEq[2];
        const mPres = /^\[([a-z0-9_-]+)\]$/i.exec(sel.trim());
        if (mPres) return node.hasAttribute(mPres[1]);
        if (sel.startsWith('.')) return classSet.has(sel.slice(1));
        return false;
      },
      querySelector(sel) {
        for (const ch of children) {
          if (typeof ch !== 'string') {
            if (ch.matches(sel)) return ch;
            const found = ch.querySelector(sel);
            if (found) return found;
          }
        }
        return null;
      },
      querySelectorAll(sel) {
        const out = [];
        for (const ch of children) {
          if (typeof ch !== 'string') {
            if (ch.matches(sel)) out.push(ch);
            out.push(...ch.querySelectorAll(sel));
          }
        }
        return out;
      },
    };
    return node;
  }

  const root = createNode('body');
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<\/([A-Za-z0-9-]+)\s*>|<([A-Za-z0-9-]+)([^>]*)>|([^<]+)/g;
  let m;
  while ((m = re.exec(String(html))) !== null) {
    if (m[1]) {
      const closing = m[1].toUpperCase();
      while (stack.length > 1 && stack[stack.length - 1].tagName !== closing) stack.pop();
      if (stack.length > 1) stack.pop();
    } else if (m[2]) {
      const attrs = {};
      const ar = /([A-Za-z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/g;
      let am;
      while ((am = ar.exec(m[3] || '')) !== null) {
        if (am[1] !== '/') attrs[am[1].toLowerCase()] = am[2] ?? am[3] ?? '';
      }
      const el = createNode(m[2], attrs);
      stack[stack.length - 1].children.push(el);
      if (!voids.has(el.tagName)) stack.push(el);
    } else if (m[4]) {
      stack[stack.length - 1].children.push(m[4]);
    }
  }
  return root;
}

test('PR26_01 Operate renders Master Trading Aggression Dial near top and Section B.5 5-Tier Dials inside Parallel Tiers card', () => {
  assert.equal(typeof renderMasterAggressionDial, 'function');
  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.sessionScope = 'OWNER_FULL_CONTROL';
  state.ownerControlsAllowed = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = normalizeAiTrader(buildTraderDoc({
    schema: AGGRESSION_DIAL_SCHEMA,
    master_risk_bps: 60,
    effective_risk_bps: 85,
    ai_discretion_enabled: true,
    ai_discretion_ceiling_bps: 100,
    ai_discretion_reason: 'TREND_IGNITION_BOOST',
    owner_controls_allowed: true,
    live_mode: false,
  }));

  const html = renderApp(state, Date.parse(time));
  assert.equal(/\bstyle\s*=/i.test(html), false, 'Zero inline style attributes on Operate');

  // Master Dial is placed right near the top of Operate (below AI Top Switcher, ahead of 01 Permissions & 02 Account snapshot)
  const idxSwitcher = html.indexOf('aria-label="Prominent AI Brain Switcher and Thinking Depth"');
  const idxMasterDial = html.indexOf('data-aggression-dial="master"');
  const idxSection01 = html.indexOf('Permissions &amp; control');
  const idxSection02 = html.indexOf('Account snapshot');
  assert.ok(idxSwitcher > 0 && idxMasterDial > idxSwitcher, 'Master Dial must appear immediately below AI Top Switcher');
  assert.ok(idxMasterDial < idxSection01 && idxMasterDial < idxSection02, 'Master Dial must appear near the top before Section 01/02');

  // Master Dial exposes all 6 presets, 20..100 bps slider, role="switch" AI Discretion pill, and 4 metric tiles
  for (const lbl of ['Safe 0.20%', 'Steady 0.40%', 'Balanced 0.60%', 'Risky 0.85%', 'High Risk 0.95%', 'Extreme 1.00%']) {
    assert.ok(html.includes(lbl), `Missing Master preset button ${lbl}`);
  }
  assert.match(html, /data-dial-master-slider="true"/);
  assert.match(html, /role="switch"[^>]*data-dial-action="TOGGLE_AI_DISCRETION"/);
  assert.match(html, /AI Discretion Active → 0\.85% Risky \(TREND_IGNITION_BOOST\)/);
  assert.match(html, /Base 0\.60% → AI 0\.85%/);
  assert.match(html, /Market Mode:/);
  assert.match(html, /AI boosted UP for Trend → 0\.85% \(Risky\)/);
  assert.match(html, /data-dial-metric="signal-bar"/);
  assert.match(html, /data-overseer-aggression-summary="true"/);
  assert.match(html, /Dial: 0\.85% Risky · AI Discretion ON/);

  // Section B.5 5-Tier Per-Account Dials render directly inside renderParallelTiersSection
  const tiersSectionHtml = renderParallelTiersSection(state);
  assert.match(tiersSectionHtml, /data-section="b5-tier-dials"/);
  assert.match(tiersSectionHtml, /5-Tier Account Aggression Dials \(0\.20%–1\.00% by 0\.01%\)/);
  assert.match(tiersSectionHtml, /Sync All 5 to Master/);
  assert.match(tiersSectionHtml, /Stagger Safe → Extreme/);
  assert.match(tiersSectionHtml, /All Balanced \(0\.60%\)/);
  assert.match(tiersSectionHtml, /Hard Safety Walls ON at every 0\.01% step: Stop Risk ≤ 1\.00%\s+Max DD ≤ 10\.00%\s+Valve ≥ 0\.55\s+1,000% Margin/);
  assert.match(tiersSectionHtml, /Exact 0\.01% Steps/);
  for (const def of DEFAULT_TIER_DEFINITIONS) {
    assert.match(tiersSectionHtml, new RegExp(`data-dial-tier-slider="${def.tierId}"`));
  }
});

test('PR26_02 Hydration from /api/parallel-tiers + LIVE mode & PR #25 paired-device (DEVICE_READ_AND_EXPLAINER) read-only lockouts', () => {
  const pt = normalizeParallelTiers({
    schema: 'cas-forex.parallel-tiers/1',
    aggression_dial: {
      schema: AGGRESSION_DIAL_SCHEMA,
      master_risk_bps: 40,
      effective_risk_bps: 40,
      ai_discretion_enabled: false,
      tiers: [
        { tier_id: 'TIER_1_CURRENT', risk_bps: 25, capital_usd: '300000.00' },
        { tier_id: 'TIER_4_6000', risk_bps: 45, capital_usd: '6000.00' },
        { tier_id: 'TIER_3_3000', risk_bps: 65, capital_usd: '3000.00' },
        { tier_id: 'TIER_2_1000', risk_bps: 85, capital_usd: '1000.00' },
        { tier_id: 'TIER_5_300', risk_bps: 100, capital_usd: '300.00' },
      ],
    },
    tiers: [
      { tier_id: 'TIER_5_300', label: 'Tier $300 Micro Challenge', starting_capital_usd: '300', equity_usd: '315', growth_pct: '5.00', net_gain_usd: '15', drawdown_pct: '0', bank_sweep_reserved_usd: '7.50', win_rate_pct: '100', profit_factor: '9.99', open_positions: 0, risk_bps: 100 },
    ],
    growth_series: {},
  });
  assert.ok(pt.aggressionDial);
  assert.equal(pt.aggressionDial.masterRiskBps, 40);
  assert.equal(pt.aggressionDial.aiDiscretionEnabled, false);
  assert.equal(pt.tiers[0].riskBps, 100);

  // Paired Read + Explainer session forces ownerControlsAllowed=false & disables all Master + Section B.5 controls
  const pairedState = displayState(fixture(), 'operate');
  pairedState.liveStreamConnected = true;
  pairedState.sessionScope = 'DEVICE_READ_AND_EXPLAINER';
  pairedState.ownerControlsAllowed = false;
  pairedState.parallelTiers = pt;
  const resolvedPaired = resolveCockpitAggressionDial(pairedState);
  assert.equal(resolvedPaired.ownerControlsAllowed, false);

  const masterPairedHtml = renderMasterAggressionDial(resolvedPaired);
  assert.match(masterPairedHtml, /data-owner-controls-allowed="false"/);
  assert.match(masterPairedHtml, /Owner Key Required/);
  for (const ctrl of [...masterPairedHtml.matchAll(/<(?:button|input)\b[^>]*>/g)].map((m) => m[0])) {
    assert.match(ctrl, /\bdisabled\b/, `Expected disabled Master dial control on paired tablet: ${ctrl}`);
  }

  const b5PairedHtml = renderParallelTiersSection(pairedState);
  assert.match(b5PairedHtml, /data-section="b5-tier-dials"[^>]*data-owner-controls-allowed="false"/);
  assert.match(b5PairedHtml, /data-dial-tier-slider="TIER_5_300"[^>]*disabled/);
  assert.match(b5PairedHtml, /data-dial-tier-preset="STAGGER_SAFE_TO_EXTREME"[^>]*disabled/);

  // Broker routing LIVE armed mode fuses liveMode=true into cockpit dial resolution
  const liveOwnerState = displayState(fixture(), 'operate');
  liveOwnerState.liveStreamConnected = true;
  liveOwnerState.sessionScope = 'OWNER_FULL_CONTROL';
  liveOwnerState.ownerControlsAllowed = true;
  liveOwnerState.brokerRouting = normalizeBrokerRouting({
    schema: 'cas-forex.broker-routing/2',
    execution_mode: 'LIVE',
    demo_only: false,
    live_trading_locked: false,
    live_trading_armed: true,
    primary_broker: 'HUGOSWAY_MT5',
    active_broker: 'HUGOSWAY_MT5',
    platform: 'MetaTrader 5',
    transport_mode: 'SPOOL_BRIDGE',
    valve: { controller: 'tks_meta_valve_controller', parameters: 161, threshold: '0.55' },
    chain: [
      { broker_id: 'HUGOSWAY_MT5', priority: 1, role: 'PRIMARY_MAIN', label: "Hugo's Way", platform: 'MetaTrader 5', server: 'Hugosway-Real3', max_leverage: '1:500', account_type: 'ECN live', configured: true, status: 'ACTIVE' },
    ],
  });
  const resolvedLive = resolveCockpitAggressionDial(liveOwnerState);
  assert.equal(resolvedLive.liveMode, true);
  assert.equal(resolvedLive.ownerControlsAllowed, true);
});

test('PR26_03 Zero-flicker patchAggressionDialInPlace patches rendered Operate DOM across 0.01% slider drags, AI Discretion switch, & presets', () => {
  const state = displayState(fixture(), 'operate');
  const html = renderApp(state, Date.parse(time));
  const domRoot = parseMiniDom(html);

  // Drag Master slider 60 -> 77 bps (0.77% Bold)
  const step1 = patchAggressionDialInPlace(domRoot, {
    masterRiskBps: 77,
    effectiveRiskBps: 77,
    aiDiscretionEnabled: false,
  });
  assert.equal(step1.patchedMaster, true);
  assert.equal(step1.patchedTiers, 5);
  assert.equal(domRoot.querySelector('[data-dial-master-slider="true"]').value, '77');
  assert.equal(domRoot.querySelector('[data-dial-bps-badge]').textContent, '0.77%');
  assert.equal(domRoot.querySelector('[data-dial-heading]').textContent, 'Bold');
  assert.equal(domRoot.querySelector('[data-dial-switch-label]').textContent, 'Manual Lock');
  assert.equal(domRoot.querySelector('[data-dial-metric-value="risk-per-trade"]').textContent, '0.77%');

  // Apply SYNC_ALL_TO_MASTER alias & STAGGER_SAFE_TO_EXTREME preset in-place
  const synced = applyAggressionDialPreset({ masterRiskBps: 77 }, 'SYNC_ALL_TO_MASTER');
  assert.deepEqual(synced.tiers.map((t) => t.riskBps), [77, 77, 77, 77, 77]);

  const staggered = applyAggressionDialPreset({ masterRiskBps: 60 }, 'STAGGER_SAFE_TO_EXTREME');
  const step2 = patchAggressionDialInPlace(domRoot, staggered);
  assert.equal(step2.patchedTiers, 5);
  assert.equal(domRoot.querySelector('[data-dial-tier-slider="TIER_1_CURRENT"]').value, '25');
  assert.equal(domRoot.querySelector('[data-dial-tier-slider="TIER_5_300"]').value, '100');

  const overseerSummary = renderAiOverseerPanel({
    aiTrader: normalizeAiTrader(buildTraderDoc({
      schema: AGGRESSION_DIAL_SCHEMA,
      master_risk_bps: 42,
      effective_risk_bps: 42,
      ai_discretion_enabled: false,
    })),
  });
  assert.match(overseerSummary, /Dial: 0\.42% Steady · Manual Lock/);
});

test('PR26_04 app.mjs & styles.css wire /api/aggression-dial, SSE aggression_dial, 0.0px scroll lock, CSS snippet, and strict CSP/LF hygiene', async () => {
  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  assert.match(appSrc, /\/api\/aggression-dial/);
  assert.match(appSrc, /SET_MASTER_RISK_BPS/);
  assert.match(appSrc, /SET_AI_DISCRETION/);
  assert.match(appSrc, /SET_TIER_RISK_BPS/);
  assert.match(appSrc, /APPLY_TIER_PRESET/);
  assert.match(appSrc, /eventName === 'aggression_dial'/);
  assert.match(appSrc, /HIGH_RISK_CONFIRMATION_REQUIRED/);
  assert.match(appSrc, /patchAggressionDialInPlace\(/);
  assert.match(appSrc, /applyMarketConditionPreview\(/);
  assert.equal(/localStorage/.test(appSrc), false);
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false);

  const afterLoss = applyMarketConditionPreview({ masterRiskBps: 60, aiDiscretionEnabled: true }, 'AFTER_LOSS');
  assert.equal(afterLoss.marketCondition, 'AFTER_LOSS');
  assert.equal(afterLoss.effectiveRiskBps, 30);

  const stylesCss = await readFile(new URL('../../ui/styles.css', import.meta.url), 'utf8');
  assert.equal(
    stylesCss.includes(AGGRESSION_DIAL_CSS_SNIPPET.trim()),
    true,
    'ui/styles.css must stay in 100% sync with AGGRESSION_DIAL_CSS_SNIPPET',
  );
  assert.match(stylesCss, /\.aggression-dial-panel\b/);
  assert.match(stylesCss, /\.dial-switch-thumb\b/);
  assert.match(stylesCss, /\.dial-market-box\b/);
  assert.match(stylesCss, /\.b5-tier-dials\b/);
  for (let lvl = 1; lvl <= 11; lvl += 1) {
    assert.match(stylesCss, new RegExp(`\\.dial-lvl-${lvl}\\b`));
  }

  const ownedFiles = [
    '../../ui/src/aggression-dial.mjs',
    '../../ui/src/ai-overseer.mjs',
    '../../ui/src/analytics.mjs',
    '../../ui/src/render.mjs',
    '../../ui/src/app.mjs',
    '../../ui/styles.css',
    '../../ui/package.json',
  ];
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;
  for (const rel of ownedFiles) {
    const raw = await readFile(new URL(rel, import.meta.url), 'utf8');
    assert.equal(raw.includes('\r'), false, `CR byte prohibited in ${rel}`);
    if (rel.endsWith('.mjs')) {
      assert.equal(innerHtmlRe.test(raw), false, `innerHTML/outerHTML prohibited in ${rel}`);
      assert.equal(inlineStyleRe.test(raw), false, `Inline style prohibited in ${rel}`);
    }
  }
});
