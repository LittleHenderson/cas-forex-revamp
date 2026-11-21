// Strict-CSP, Smooth 60fps Switch/Patching & Exact 405-Tuple BigInt Scaling tests for
// Trading Aggression Dial (20..100 bps = 0.20%..1.00% in 0.01% steps + AI Discretion)
// & Section B.5 5-Tier Per-Account Controls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  AGGRESSION_ANCHOR_KNOTS,
  AGGRESSION_DIAL_CSS_SNIPPET,
  AGGRESSION_DIAL_SCHEMA,
  DEFAULT_AI_DISCRETION_CEILING_BPS,
  DEFAULT_MASTER_RISK_BPS,
  DEFAULT_TIER_DEFINITIONS,
  HIGH_RISK_MIN_BPS,
  MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
  MAX_CONSTITUTIONAL_STOP_RISK_BPS,
  MAX_CONSTITUTIONAL_STOP_RISK_PCT,
  MAX_RISK_BPS,
  MIN_CONSTITUTIONAL_SIGNAL_PROB,
  MIN_RISK_BPS,
  RISK_BPS_PROFILES,
  RISK_BPS_PROFILE_LIST,
  RISK_BPS_STEP,
  STAGGER_SAFE_TO_EXTREME_BPS,
  STAGGER_SAFE_TO_HIGH_BPS,
  STATIC_AGGRESSION_DIAL,
  UNBREAKABLE_GUARDRAILS,
  applyAggressionDialPreset,
  formatCentsPlain,
  formatCentsSignedUsd,
  formatCentsUsd,
  formatProbBp,
  formatRiskBpsPct,
  getRiskBpsProfile,
  normalizeAggressionDial,
  patchAggressionDialInPlace,
  renderMasterAggressionDial,
  renderSectionB5TierDials,
  scaleTierTargets,
  usdToCentsBigInt,
  zoneForRiskBps,
} from '../../ui/src/aggression-dial.mjs';

const KNOTS_REF = [
  [20, 'Safe', 1, 78, 150000n, 75000n],
  [40, 'Steady', 2, 72, 300000n, 150000n],
  [60, 'Balanced', 3, 66, 450000n, 250000n],
  [85, 'Risky', 5, 59, 750000n, 475000n],
  [95, 'High Risk', 6, 55, 1000000n, 600000n],
  [100, 'Extreme High Risk', 8, 55, 1500000n, 850000n],
];

const TIER_CAPS = [30000000n, 600000n, 300000n, 100000n, 30000n];

function expectedInterp(bps) {
  let k0 = KNOTS_REF[0];
  let k1 = KNOTS_REF[KNOTS_REF.length - 1];
  for (let i = 0; i < KNOTS_REF.length - 1; i += 1) {
    if (bps >= KNOTS_REF[i][0] && bps <= KNOTS_REF[i + 1][0]) {
      k0 = KNOTS_REF[i];
      k1 = KNOTS_REF[i + 1];
      break;
    }
  }
  const dx = BigInt(bps - k0[0]);
  const span = BigInt(k1[0] - k0[0]);
  const half = span / 2n;
  const goal300k = k0[4] + ((k1[4] - k0[4]) * dx + half) / span;
  const loss300k = k0[5] + ((k1[5] - k0[5]) * dx + half) / span;
  const probBp = Math.max(55, Number(BigInt(k0[3]) - (BigInt(k0[3] - k1[3]) * dx + half) / span));
  const maxTrades = Number(BigInt(k0[2]) + (BigInt(k1[2] - k0[2]) * dx + half) / span);
  return { goal300k, loss300k, probBp, maxTrades };
}

function createStrictMockEl(attrs = {}, classes = [], children = []) {
  const attrMap = new Map(Object.entries(attrs));
  const classSet = new Set(classes);
  let textVal = '';
  let valueVal = attrs.value ?? '';
  let disabledVal = false;
  let hiddenVal = attrs.hidden !== undefined;

  const classList = {
    add(...items) { for (const c of items) classSet.add(c); },
    remove(...items) { for (const c of items) classSet.delete(c); },
    contains(c) { return classSet.has(c); },
    toggle(c, force) {
      if (force === undefined) {
        if (classSet.has(c)) { classSet.delete(c); return false; }
        classSet.add(c); return true;
      }
      if (force) classSet.add(c); else classSet.delete(c);
      return Boolean(force);
    },
  };

  function matchesSelector(el, sel) {
    const mEq = sel.match(/^\[([a-z0-9-]+)="([^"]*)"\]$/i);
    if (mEq) return el.getAttribute(mEq[1]) === mEq[2];
    const mPres = sel.match(/^\[([a-z0-9-]+)\]$/i);
    if (mPres) return el.hasAttribute(mPres[1]);
    return false;
  }

  const node = {
    classList,
    children,
    get textContent() { return textVal; },
    set textContent(v) { textVal = String(v); },
    get value() { return valueVal; },
    set value(v) { valueVal = String(v); },
    get disabled() { return disabledVal; },
    set disabled(v) { disabledVal = Boolean(v); },
    get hidden() { return hiddenVal; },
    set hidden(v) { hiddenVal = Boolean(v); },
    get innerHTML() { throw new Error('innerHTML read forbidden during in-place patch!'); },
    set innerHTML(_v) { throw new Error('innerHTML write forbidden during in-place patch!'); },
    get style() { throw new Error('Inline style mutation forbidden under strict CSP!'); },
    getAttribute(k) { return attrMap.has(k) ? attrMap.get(k) : null; },
    hasAttribute(k) { return attrMap.has(k); },
    setAttribute(k, v) {
      if (k.toLowerCase() === 'style') throw new Error('setAttribute("style") forbidden under strict CSP!');
      attrMap.set(k, String(v));
    },
    removeAttribute(k) { attrMap.delete(k); },
    matches(sel) { return matchesSelector(node, sel); },
    querySelector(sel) {
      for (const ch of children) {
        if (ch.matches(sel)) return ch;
        const found = ch.querySelector(sel);
        if (found) return found;
      }
      return null;
    },
    querySelectorAll(sel) {
      const out = [];
      for (const ch of children) {
        if (ch.matches(sel)) out.push(ch);
        out.push(...ch.querySelectorAll(sel));
      }
      return out;
    },
  };
  return node;
}

test('RISK_BPS_PROFILES defines exact frozen 81 positions (20..100 bps = 0.20%..1.00% by 0.01%) with 6 exact knots and constitutional ceilings', () => {
  assert.equal(Object.isFrozen(RISK_BPS_PROFILES), true);
  assert.equal(Object.isFrozen(RISK_BPS_PROFILE_LIST), true);
  assert.equal(Object.isFrozen(AGGRESSION_ANCHOR_KNOTS), true);
  assert.equal(MIN_RISK_BPS, 20);
  assert.equal(MAX_RISK_BPS, 100);
  assert.equal(RISK_BPS_STEP, 1);
  assert.equal(DEFAULT_MASTER_RISK_BPS, 60);
  assert.equal(HIGH_RISK_MIN_BPS, 80);
  assert.equal(DEFAULT_AI_DISCRETION_CEILING_BPS, 100);
  assert.equal(MAX_CONSTITUTIONAL_STOP_RISK_PCT, '1.00');
  assert.equal(MAX_CONSTITUTIONAL_STOP_RISK_BPS, 100);
  assert.equal(MAX_CONSTITUTIONAL_DRAWDOWN_PCT, '0.10');
  assert.equal(MIN_CONSTITUTIONAL_SIGNAL_PROB, '0.55');
  assert.equal(RISK_BPS_PROFILE_LIST.length, 81);

  for (const [bps, label, trades, probBp, goalCents, lossCents] of KNOTS_REF) {
    const p = getRiskBpsProfile(bps);
    assert.equal(Object.isFrozen(p), true);
    assert.equal(p.riskBps, bps);
    assert.equal(p.label, label);
    assert.equal(p.maxOpenTrades, trades);
    assert.equal(p.probBp, probBp);
    assert.equal(p.minSignalProb, formatProbBp(probBp));
    assert.equal(p.ref300kGoalCents, goalCents);
    assert.equal(p.ref300kLossCents, lossCents);
  }

  // Verify every single 0.01% step from 20..100 stays inside constitutional ceilings & matches zone map
  const zoneExpectations = [
    [20, 'Safe', 'dial-lvl-1'],
    [29, 'Safe', 'dial-lvl-1'],
    [30, 'Calm', 'dial-lvl-2'],
    [39, 'Calm', 'dial-lvl-2'],
    [40, 'Steady', 'dial-lvl-3'],
    [49, 'Steady', 'dial-lvl-3'],
    [50, 'Moderate', 'dial-lvl-4'],
    [59, 'Moderate', 'dial-lvl-4'],
    [60, 'Balanced', 'dial-lvl-5'],
    [69, 'Balanced', 'dial-lvl-5'],
    [70, 'Active', 'dial-lvl-6'],
    [74, 'Active', 'dial-lvl-6'],
    [75, 'Bold', 'dial-lvl-7'],
    [79, 'Bold', 'dial-lvl-7'],
    [80, 'Risky', 'dial-lvl-8'],
    [89, 'Risky', 'dial-lvl-8'],
    [90, 'High Risk', 'dial-lvl-10'],
    [95, 'High Risk', 'dial-lvl-10'],
    [96, 'Extreme High Risk', 'dial-lvl-11'],
    [100, 'Extreme High Risk', 'dial-lvl-11'],
  ];
  for (const [bps, expLabel, expCls] of zoneExpectations) {
    const z = zoneForRiskBps(bps);
    assert.equal(z.label, expLabel, `bps=${bps}`);
    assert.equal(z.cssClass, expCls, `bps=${bps}`);
  }

  for (let bps = 20; bps <= 100; bps += 1) {
    const p = RISK_BPS_PROFILES[bps];
    assert.ok(p, `Missing bps ${bps}`);
    assert.equal(p.riskPct, formatRiskBpsPct(bps));
    assert.ok(p.riskBps <= 100);
    assert.ok(p.probBp >= 55);
    assert.equal(p.maxDrawdownPct, '0.10');
    assert.equal(p.highRisk, bps >= 80);
  }
});

test('scaleTierTargets produces exact BigInt half-up penny parity across ALL 81 bps steps x 5 tiers = 405 combinations', () => {
  let checked = 0;
  for (const capCents of TIER_CAPS) {
    for (let bps = 20; bps <= 100; bps += 1) {
      const exp = expectedInterp(bps);
      const expGoalCents = (exp.goal300k * capCents + 15000000n) / 30000000n;
      const expLossCents = (exp.loss300k * capCents + 15000000n) / 30000000n;
      const scaled = scaleTierTargets(bps, capCents);
      assert.equal(Object.isFrozen(scaled), true);
      assert.equal(scaled.riskBps, bps);
      assert.equal(scaled.riskPct, formatRiskBpsPct(bps));
      assert.equal(scaled.maxOpenTrades, exp.maxTrades);
      assert.equal(scaled.probBp, exp.probBp);
      assert.equal(scaled.minSignalProb, formatProbBp(exp.probBp));
      assert.equal(scaled.sessionGoalCents, expGoalCents, `cap=${capCents} bps=${bps} goal`);
      assert.equal(scaled.dailyLossBrakeCents, expLossCents, `cap=${capCents} bps=${bps} brake`);
      assert.equal(scaled.sessionGoalUsd, formatCentsPlain(expGoalCents));
      assert.equal(scaled.dailyLossBrakeUsd, formatCentsPlain(expLossCents));
      checked += 1;
    }
  }
  assert.equal(checked, 405);

  // Single-unit 0.01% step verification (0.20%, 0.21%, 0.22%, ..., 1.00%)
  assert.equal(scaleTierTargets(21, 30000000n).riskPctLabel, '0.21%');
  assert.equal(scaleTierTargets(21, 30000000n).sessionGoalFormatted, '+$1,575.00');
  assert.equal(scaleTierTargets(21, 30000000n).dailyLossBrakeFormatted, '-$787.50');
  assert.equal(scaleTierTargets(100, 30000000n).sessionGoalFormatted, '+$15,000.00');
  assert.equal(scaleTierTargets(100, 30000000n).dailyLossBrakeFormatted, '-$8,500.00');
  assert.equal(scaleTierTargets(100, 100000n).sessionGoalFormatted, '+$50.00');
  assert.equal(scaleTierTargets(100, 100000n).dailyLossBrakeFormatted, '-$28.33');
  assert.equal(scaleTierTargets(100, 30000n).sessionGoalFormatted, '+$15.00');
  assert.equal(scaleTierTargets(100, 30000n).dailyLossBrakeFormatted, '-$8.50');

  assert.throws(() => getRiskBpsProfile(19), RangeError);
  assert.throws(() => getRiskBpsProfile(101), RangeError);
  assert.throws(() => getRiskBpsProfile(60.5), RangeError);
  assert.throws(() => scaleTierTargets(60, -100n), RangeError);
});

test('money cent formatters and usdToCentsBigInt handle edge cases without floats', () => {
  assert.equal(formatCentsPlain(1500000n), '15000.00');
  assert.equal(formatCentsUsd(30000000n), '$300,000.00');
  assert.equal(formatCentsSignedUsd(1500n, '+'), '+$15.00');
  assert.equal(formatCentsSignedUsd(850n, '-'), '-$8.50');
  assert.equal(usdToCentsBigInt('$300,000.00'), 30000000n);
  assert.equal(usdToCentsBigInt('1.125'), 113n);
  assert.equal(usdToCentsBigInt('invalid', 500n), 500n);
});

test('STATIC_AGGRESSION_DIAL and normalizeAggressionDial support bps AI Discretion UP/DOWN shifts, Manual Lock, and unbreakable guardrails', () => {
  assert.equal(STATIC_AGGRESSION_DIAL.schema, AGGRESSION_DIAL_SCHEMA);
  assert.equal(STATIC_AGGRESSION_DIAL.masterRiskBps, 60);
  assert.equal(STATIC_AGGRESSION_DIAL.aiDiscretionEnabled, true);
  assert.equal(STATIC_AGGRESSION_DIAL.autoShiftEnabled, true);
  assert.equal(STATIC_AGGRESSION_DIAL.aiDiscretionCeilingBps, 100);
  assert.equal(STATIC_AGGRESSION_DIAL.ownerControlsAllowed, true);
  assert.equal(STATIC_AGGRESSION_DIAL.tiers.length, 5);
  assert.deepEqual(
    STATIC_AGGRESSION_DIAL.tiers.map((t) => t.tierId),
    ['TIER_1_CURRENT', 'TIER_4_6000', 'TIER_3_3000', 'TIER_2_1000', 'TIER_5_300'],
  );

  const boosted = normalizeAggressionDial({
    schema: AGGRESSION_DIAL_SCHEMA,
    master_risk_bps: 60,
    effective_risk_bps: 100,
    ai_discretion_enabled: true,
    ai_discretion_ceiling_bps: 100,
    ai_discretion_reason: 'STRONG_TREND',
    live_mode: false,
    owner_controls_allowed: true,
    guardrails: { valve_required: false, valve_cutoff: '0.00' },
  });
  assert.equal(boosted.connected, true);
  assert.equal(boosted.masterRiskBps, 60);
  assert.equal(boosted.effectiveRiskBps, 100);
  assert.equal(boosted.effectiveLabel, 'Extreme High Risk');
  assert.equal(boosted.aiDiscretionReason, 'STRONG_TREND');
  assert.equal(boosted.masterTargets.sessionGoalFormatted, '+$15,000.00');
  assert.equal(boosted.masterTargets.dailyLossBrakeFormatted, '-$8,500.00');
  assert.equal(boosted.guardrails, UNBREAKABLE_GUARDRAILS);
  assert.equal(boosted.guardrails.valveRequired, true);
  assert.equal(boosted.guardrails.valveCutoff, '0.55');

  const capped = normalizeAggressionDial({
    master_risk_bps: 60,
    effective_risk_bps: 100,
    ai_discretion_enabled: true,
    ai_discretion_ceiling_bps: 85,
  });
  assert.equal(capped.effectiveRiskBps, 85);

  const locked = normalizeAggressionDial({
    master_risk_bps: 42,
    effective_risk_bps: 100,
    ai_discretion_enabled: false,
  });
  assert.equal(locked.aiDiscretionEnabled, false);
  assert.equal(locked.autoShiftEnabled, false);
  assert.equal(locked.effectiveRiskBps, 42);
});

test('applyAggressionDialPreset applies SYNC_MASTER, STAGGER_SAFE_TO_EXTREME/HIGH (25,45,65,85,100), ALL_BALANCED (60), ALL_SAFE (20)', () => {
  assert.deepEqual(STAGGER_SAFE_TO_EXTREME_BPS, STAGGER_SAFE_TO_HIGH_BPS);
  const base = normalizeAggressionDial({ masterRiskBps: 73 });

  const synced = applyAggressionDialPreset(base, 'SYNC_MASTER');
  assert.deepEqual(synced.tiers.map((t) => t.riskBps), [73, 73, 73, 73, 73]);

  const staggered = applyAggressionDialPreset(base, 'STAGGER_SAFE_TO_EXTREME');
  assert.deepEqual(
    staggered.tiers.map((t) => [t.tierId, t.riskBps]),
    [
      ['TIER_1_CURRENT', 25],
      ['TIER_4_6000', 45],
      ['TIER_3_3000', 65],
      ['TIER_2_1000', 85],
      ['TIER_5_300', 100],
    ],
  );

  const staggeredAlias = applyAggressionDialPreset(base, 'STAGGER_SAFE_TO_HIGH');
  assert.deepEqual(
    staggeredAlias.tiers.map((t) => [t.tierId, t.riskBps]),
    staggered.tiers.map((t) => [t.tierId, t.riskBps]),
  );

  const balanced = applyAggressionDialPreset(staggered, 'ALL_BALANCED');
  assert.deepEqual(balanced.tiers.map((t) => t.riskBps), [60, 60, 60, 60, 60]);

  const safe = applyAggressionDialPreset(staggered, 'ALL_SAFE');
  assert.deepEqual(safe.tiers.map((t) => t.riskBps), [20, 20, 20, 20, 20]);
});

test('renderMasterAggressionDial renders 20..100 bps (0.01% step) slider, 6 presets, sliding role="switch", 4 metric tiles, and guardrails', () => {
  const html = renderMasterAggressionDial({
    masterRiskBps: 60,
    effectiveRiskBps: 100,
    aiDiscretionEnabled: true,
    aiDiscretionCeilingBps: 100,
    aiDiscretionReason: 'STRONG_TREND',
    liveMode: false,
  });

  // Real sliding pill switch markup
  assert.match(html, /<button[^>]*role="switch"[^>]*aria-checked="true"[^>]*class="dial-switch is-on"[^>]*data-dial-action="TOGGLE_AI_DISCRETION"/);
  assert.match(html, /class="dial-switch-track"/);
  assert.match(html, /class="dial-switch-thumb"/);
  assert.match(html, /AI Discretion: ON/);

  // 20..100 bps slider with step="1" (0.01% increments)
  assert.match(html, /data-dial-master-slider="true"/);
  assert.match(html, /min="20" max="100" step="1" value="60"/);
  assert.match(html, /data-dial-ai-shifted="true"/);
  assert.match(html, /AI Discretion Active → 1\.00% Extreme High Risk \(STRONG_TREND\)/);

  const presets = [...html.matchAll(/data-dial-master-preset="(\d+)"/g)].map((m) => m[1]);
  assert.deepEqual(presets, ['20', '40', '60', '85', '95', '100']);
  assert.match(html, /Safe 0\.20%/);
  assert.match(html, /Steady 0\.40%/);
  assert.match(html, /Balanced 0\.60%/);
  assert.match(html, /Risky 0\.85%/);
  assert.match(html, /High Risk 0\.95%/);
  assert.match(html, /Extreme 1\.00%/);

  const metricTiles = [...html.matchAll(/class="dial-metric-tile"/g)];
  assert.equal(metricTiles.length, 4);
  assert.match(html, /1\.00%/);
  assert.match(html, /\+\$15,000\.00/);
  assert.match(html, /-\$8,500\.00/);
  assert.match(html, /Safety Valve 0\.55 · 1,000% Margin · 50ms Stop-Loss/);

  // Manual Lock renders switch in is-off / aria-checked="false" state and pins to exact 0.01% step (0.61%)
  const manualHtml = renderMasterAggressionDial({
    masterRiskBps: 61,
    effectiveRiskBps: 100,
    aiDiscretionEnabled: false,
  });
  assert.match(manualHtml, /<button[^>]*role="switch"[^>]*aria-checked="false"[^>]*class="dial-switch is-off"/);
  assert.match(manualHtml, /Manual Lock/);
  assert.match(manualHtml, /0\.61%/);
  assert.doesNotMatch(manualHtml, /data-dial-ai-shifted="true"/);
});

test('renderSectionB5TierDials renders all 5 tiers with 20..100 bps sliders, 3 quick presets, and 6 compact preset buttons', () => {
  const staggered = applyAggressionDialPreset(STATIC_AGGRESSION_DIAL, 'STAGGER_SAFE_TO_EXTREME');
  const html = renderSectionB5TierDials(staggered);

  assert.match(html, /SECTION B\.5 · SHARED 50MS STREAM · ZERO EXTRA AI API COST/);
  assert.match(html, /data-dial-tier-preset="SYNC_MASTER"/);
  assert.match(html, /Sync All 5 to Master/);
  assert.match(html, /data-dial-tier-preset="STAGGER_SAFE_TO_EXTREME"/);
  assert.match(html, /Stagger Safe → Extreme/);
  assert.match(html, /data-dial-tier-preset="ALL_BALANCED"/);
  assert.match(html, /All Balanced \(0\.60%\)/);

  for (const def of DEFAULT_TIER_DEFINITIONS) {
    assert.match(html, new RegExp(`data-tier-id="${def.tierId}"`));
    assert.match(html, new RegExp(`min="20" max="100" step="1"[^>]*data-dial-tier-slider="${def.tierId}"`));
    for (const bps of [20, 40, 60, 85, 95, 100]) {
      assert.match(html, new RegExp(`data-dial-tier-id="${def.tierId}" data-dial-tier-bps="${bps}"`));
    }
  }

  // Verify exact staggered 25/45/65/85/100 bps labels & values
  assert.match(html, /0\.25%/);
  assert.match(html, /0\.45%/);
  assert.match(html, /0\.65%/);
  assert.match(html, /0\.85%/);
  assert.match(html, /1\.00%/);
  assert.match(html, /\+\$15\.00/); // $300 at 1.00%
  assert.match(html, /-\$8\.50/);
});

test('patchAggressionDialInPlace updates 0.01% bps steps, classes, role="switch", sliders, and metrics in-place with 0 innerHTML teardown and 0 inline style=', () => {
  const badgeEl = createStrictMockEl({ 'data-dial-bps-badge': '60' }, ['dial-badge', 'dial-lvl-5']);
  const headingEl = createStrictMockEl({ 'data-dial-heading': 'true' });
  const sublineEl = createStrictMockEl({ 'data-dial-subline': 'true' });
  const shiftEl = createStrictMockEl({ 'data-dial-ai-shifted': 'false', hidden: '' }, ['dial-pill-tag', 'dial-lvl-5']);
  const lockEl = createStrictMockEl({ 'data-dial-owner-key-required': 'false', hidden: '' }, ['dial-pill-tag']);
  const switchLabel = createStrictMockEl({ 'data-dial-switch-label': 'true' });
  const switchBtn = createStrictMockEl(
    { 'data-dial-action': 'TOGGLE_AI_DISCRETION', role: 'switch', 'aria-checked': 'true' },
    ['dial-switch', 'is-on'],
    [switchLabel],
  );
  const sliderEl = createStrictMockEl({ 'data-dial-master-slider': 'true', value: '60' }, ['dial-slider', 'dial-lvl-5']);
  const tickEls = [20, 30, 40, 50, 60, 70, 80, 90, 100].map((bps) => createStrictMockEl({ 'data-dial-tick-bps': String(bps) }, ['dial-tick']));
  const presetBtns = [20, 40, 60, 85, 95, 100].map((bps) => createStrictMockEl(
    { 'data-dial-master-preset': String(bps), 'aria-pressed': bps === 60 ? 'true' : 'false' },
    ['dial-preset-btn'],
  ));
  const mRisk = createStrictMockEl({ 'data-dial-metric-value': 'risk-per-trade' });
  const mTrades = createStrictMockEl({ 'data-dial-metric-value': 'max-open-trades' });
  const mGoal = createStrictMockEl({ 'data-dial-metric-value': 'session-goal' });
  const mBrake = createStrictMockEl({ 'data-dial-metric-value': 'daily-loss-brake' });

  const masterEl = createStrictMockEl(
    { 'data-aggression-dial': 'master' },
    ['panel', 'aggression-dial-panel', 'dial-lvl-5'],
    [badgeEl, headingEl, sublineEl, shiftEl, lockEl, switchBtn, sliderEl, ...tickEls, ...presetBtns, mRisk, mTrades, mGoal, mBrake],
  );

  const quickBtns = ['SYNC_MASTER', 'STAGGER_SAFE_TO_EXTREME', 'ALL_BALANCED'].map((id) => createStrictMockEl({ 'data-dial-tier-preset': id }));
  const tierRows = {};
  const tierRowList = DEFAULT_TIER_DEFINITIONS.map((def) => {
    const tBadge = createStrictMockEl({ 'data-tier-bps-badge': '60' }, ['dial-badge', 'dial-lvl-5']);
    const tName = createStrictMockEl({ 'data-tier-level-name': 'true' });
    const tRisk = createStrictMockEl({ 'data-tier-metric': 'risk' });
    const tMax = createStrictMockEl({ 'data-tier-metric': 'max' });
    const tGoal = createStrictMockEl({ 'data-tier-metric': 'goal' });
    const tBrake = createStrictMockEl({ 'data-tier-metric': 'brake' });
    const tSlider = createStrictMockEl({ 'data-dial-tier-slider': def.tierId, value: '60' }, ['dial-slider', 'dial-lvl-5']);
    const tBtns = [20, 40, 60, 85, 95, 100].map((bps) => createStrictMockEl(
      { 'data-dial-tier-id': def.tierId, 'data-dial-tier-bps': String(bps) },
      ['dial-tier-btn'],
    ));
    const row = createStrictMockEl(
      { 'data-tier-id': def.tierId, 'data-tier-bps': '60' },
      ['b5-tier-row', 'dial-lvl-5'],
      [tBadge, tName, tRisk, tMax, tGoal, tBrake, tSlider, ...tBtns],
    );
    tierRows[def.tierId] = { row, tBadge, tName, tRisk, tMax, tGoal, tBrake, tSlider, tBtns };
    return row;
  });

  const b5El = createStrictMockEl(
    { 'data-section': 'b5-tier-dials' },
    ['b5-tier-dials'],
    [...quickBtns, ...tierRowList],
  );

  const root = createStrictMockEl({}, [], [masterEl, b5El]);

  // Step 1: Drag by a single 0.01% increment (60 -> 61 bps = 0.61%)
  const resDrag = patchAggressionDialInPlace(root, { masterRiskBps: 61, effectiveRiskBps: 61 });
  assert.equal(resDrag.patchedMaster, true);
  assert.equal(sliderEl.value, '61');
  assert.equal(badgeEl.textContent, '0.61%');
  assert.equal(mRisk.textContent, '0.61%');

  // Step 2: AI Discretion UP-shift (master 60 -> effective 100 STRONG_TREND) + staggered tiers (25,45,65,85,100)
  const staggered = applyAggressionDialPreset({
    masterRiskBps: 60,
    effectiveRiskBps: 100,
    aiDiscretionEnabled: true,
    aiDiscretionCeilingBps: 100,
    aiDiscretionReason: 'STRONG_TREND',
  }, 'STAGGER_SAFE_TO_EXTREME');

  const res1 = patchAggressionDialInPlace(root, staggered);
  assert.equal(res1.patchedMaster, true);
  assert.equal(res1.patchedTiers, 5);
  assert.equal(masterEl.classList.contains('dial-lvl-11'), true);
  assert.equal(masterEl.classList.contains('dial-lvl-5'), false);
  assert.equal(badgeEl.textContent, '1.00%');
  assert.equal(headingEl.textContent, 'Extreme High Risk');
  assert.equal(shiftEl.hidden, false);
  assert.equal(shiftEl.textContent, 'AI Discretion Active → 1.00% Extreme High Risk (STRONG_TREND)');
  assert.equal(switchBtn.classList.contains('is-on'), true);
  assert.equal(switchBtn.getAttribute('aria-checked'), 'true');
  assert.equal(switchLabel.textContent, 'AI Discretion: ON');
  assert.equal(mRisk.textContent, '1.00%');
  assert.equal(mTrades.textContent, '8');
  assert.equal(mGoal.textContent, '+$15,000.00');
  assert.equal(mBrake.textContent, '-$8,500.00');
  assert.equal(tickEls[4].classList.contains('is-current'), true);
  assert.equal(tickEls[8].classList.contains('is-ai-active'), true);

  assert.equal(tierRows.TIER_5_300.row.classList.contains('dial-lvl-11'), true);
  assert.equal(tierRows.TIER_5_300.tSlider.value, '100');
  assert.equal(tierRows.TIER_5_300.tGoal.textContent, '+$15.00');
  assert.equal(tierRows.TIER_5_300.tBrake.textContent, '-$8.50');
  assert.equal(tierRows.TIER_5_300.tBtns[5].classList.contains('is-active'), true);

  // Step 3: Manual Lock + Read-Only Tablet (ownerControlsAllowed: false)
  const res2 = patchAggressionDialInPlace(root, {
    masterRiskBps: 40,
    effectiveRiskBps: 100,
    aiDiscretionEnabled: false,
    ownerControlsAllowed: false,
  });
  assert.equal(res2.patchedMaster, true);
  assert.equal(masterEl.classList.contains('dial-lvl-3'), true);
  assert.equal(masterEl.classList.contains('is-readonly'), true);
  assert.equal(switchBtn.classList.contains('is-off'), true);
  assert.equal(switchBtn.classList.contains('is-on'), false);
  assert.equal(switchBtn.getAttribute('aria-checked'), 'false');
  assert.equal(switchLabel.textContent, 'Manual Lock');
  assert.equal(switchBtn.disabled, true);
  assert.equal(sliderEl.disabled, true);
  assert.equal(sliderEl.value, '40');
  assert.equal(shiftEl.hidden, true);
  assert.equal(lockEl.hidden, false);
  assert.equal(lockEl.textContent, 'Owner Key Required');
  assert.equal(mGoal.textContent, '+$3,000.00');
  assert.equal(mBrake.textContent, '-$1,500.00');
  assert.equal(tierRows.TIER_5_300.tSlider.disabled, true);
  assert.equal(quickBtns[0].disabled, true);
});

test('LIVE-mode high-risk (>=80 bps & AI ceiling >=80 bps) confirm banner appears ONLY when liveMode=true and never blocks Demo mode', () => {
  const demoMaster = renderMasterAggressionDial({
    liveMode: false,
    masterRiskBps: 60,
    pendingHighRiskBps: 100,
    pendingAiDiscretionCeilingBps: 100,
  });
  assert.doesNotMatch(demoMaster, /data-dial-confirm-high-risk="true"/);

  const demoB5 = renderSectionB5TierDials({
    liveMode: false,
    pendingHighRiskBps: 100,
    pendingHighRiskTierId: 'TIER_5_300',
  });
  assert.doesNotMatch(demoB5, /data-dial-confirm-high-risk="true"/);

  const liveBelow = renderMasterAggressionDial({ liveMode: true, masterRiskBps: 60, pendingHighRiskBps: 79 });
  assert.doesNotMatch(liveBelow, /data-dial-confirm-high-risk="true"/);

  for (const bps of [80, 85, 95, 100]) {
    const liveHigh = renderMasterAggressionDial({ liveMode: true, masterRiskBps: 60, pendingHighRiskBps: bps });
    assert.match(liveHigh, /data-dial-confirm-high-risk="true"/);
    assert.match(liveHigh, new RegExp(`data-dial-confirm-bps="${bps}"`));
  }

  const liveAiCeiling = renderMasterAggressionDial({
    liveMode: true,
    masterRiskBps: 60,
    pendingAiDiscretionCeilingBps: 100,
  });
  assert.match(liveAiCeiling, /data-dial-confirm-high-risk="true"/);
  assert.match(liveAiCeiling, /data-dial-confirm-kind="ai-ceiling"/);
  assert.match(liveAiCeiling, /Confirm Live AI Discretion Ceiling 1\.00%/);

  const liveB5 = renderSectionB5TierDials({
    liveMode: true,
    pendingHighRiskBps: 100,
    pendingHighRiskTierId: 'TIER_5_300',
  });
  assert.match(liveB5, /data-dial-confirm-high-risk="true"/);
  assert.match(liveB5, /data-dial-confirm-tier-id="TIER_5_300"/);
});

test('PR #25 Finding [2]: ownerControlsAllowed=false disables all sliders/buttons and shows Owner Key Required badge', () => {
  const tabletState = {
    aiTrader: { ownerControlsAllowed: false },
    aggressionDial: {
      masterRiskBps: 60,
      effectiveRiskBps: 100,
      aiDiscretionEnabled: true,
      aiDiscretionReason: 'STRONG_TREND',
      liveMode: true,
      pendingHighRiskBps: 100,
    },
  };

  const masterHtml = renderMasterAggressionDial(tabletState);
  assert.match(masterHtml, /data-owner-controls-allowed="false"/);
  assert.match(masterHtml, /data-dial-owner-key-required="true"/);
  assert.match(masterHtml, /Owner Key Required/);
  assert.doesNotMatch(masterHtml, /data-dial-confirm-high-risk="true"/);

  for (const tag of [...masterHtml.matchAll(/<(?:button|input)\b[^>]*>/g)].map((m) => m[0])) {
    assert.match(tag, /\bdisabled\b/, `Expected disabled on control: ${tag}`);
  }

  const b5Html = renderSectionB5TierDials({
    sessionRole: 'DEVICE_READ_AND_EXPLAINER',
    aggressionDial: { masterRiskBps: 60 },
  });
  assert.match(b5Html, /data-owner-controls-allowed="false"/);
  assert.match(b5Html, /Owner Key Required/);
  for (const tag of [...b5Html.matchAll(/<(?:button|input)\b[^>]*>/g)].map((m) => m[0])) {
    assert.match(tag, /\bdisabled\b/, `Expected disabled on Section B.5 control: ${tag}`);
  }
});

test('Strict CSP (zero inline style=) and XSS escaping across hostile inputs and sampled bps positions', () => {
  const hostile = {
    liveMode: true,
    pendingHighRiskBps: 100,
    aiDiscretionEnabled: true,
    aiDiscretionReason: '<script>alert("ai")</script>',
    tiers: [
      {
        tierId: 'TIER_1_CURRENT',
        label: '<script>alert("xss")</script>" onmouseover="alert(1)',
        riskBps: 100,
      },
      {
        tierId: 'TIER_5_300',
        label: '<img src=x onerror=alert(2)> & \'micro\'',
        riskBps: 85,
      },
    ],
  };

  for (const bps of [20, 21, 35, 40, 55, 60, 72, 79, 80, 85, 95, 96, 100]) {
    const mHtml = renderMasterAggressionDial({ ...hostile, masterRiskBps: bps, effectiveRiskBps: bps === 100 ? 60 : 100 });
    assert.doesNotMatch(mHtml, /\bstyle\s*=/i, `Inline style detected at master bps ${bps}`);
    assert.doesNotMatch(mHtml, /\bon(?:click|input|change|mouseover|error)\s*=/i);
    assert.doesNotMatch(mHtml, /javascript:/i);
    assert.doesNotMatch(mHtml, /<script>/i);
  }

  const b5Html = renderSectionB5TierDials(hostile);
  assert.doesNotMatch(b5Html, /\bstyle\s*=/i, 'Inline style detected in Section B.5 HTML');
  assert.doesNotMatch(b5Html, /<script>/i);
  assert.doesNotMatch(b5Html, /<img\s/i);
  assert.doesNotMatch(b5Html, /" onmouseover="/i);
  assert.match(b5Html, /&lt;script&gt;alert\(&quot;xss&quot;\)&lt;\/script&gt;/);
  assert.match(b5Html, /&lt;img src=x onerror=alert\(2\)&gt; &amp; &#39;micro&#39;/);
});

test('AGGRESSION_DIAL_CSS_SNIPPET defines .dial-lvl-1..11, smooth 60fps cubic-bezier transitions, pill switch, reduced-motion, and LF/0-BOM hygiene', () => {
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.aggression-dial-panel\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-switch\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-switch-track\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-switch-thumb\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /transform:\s*translateX\(22px\)/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /transition:\s*transform 220ms cubic-bezier\(0\.22, 1, 0\.36, 1\), background-color 220ms ease/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-slider::-webkit-slider-thumb/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-slider::-moz-range-thumb/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /transform:\s*scale\(1\.12\)/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-preset-btn\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-tier-btn\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-badge\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-pill-tag\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /\.dial-metric-value\b/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /font-variant-numeric:\s*tabular-nums/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /min-height:\s*44px/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /contain:\s*layout style/);
  assert.match(AGGRESSION_DIAL_CSS_SNIPPET, /@media \(prefers-reduced-motion: reduce\)/);
  for (let lvl = 1; lvl <= 11; lvl += 1) {
    assert.match(AGGRESSION_DIAL_CSS_SNIPPET, new RegExp(`\\.dial-lvl-${lvl}\\b`));
  }

  const srcBytes = readFileSync(new URL('../../ui/src/aggression-dial.mjs', import.meta.url));
  assert.equal(srcBytes.includes(13), false, 'Source file must use LF line endings only (0 CR)');
  assert.equal(srcBytes[0] === 0xef && srcBytes[1] === 0xbb && srcBytes[2] === 0xbf, false, 'Source file must have 0 UTF-8 BOM');
  const srcText = srcBytes.toString('utf8');
  assert.doesNotMatch(srcText, /\beval\s*\(/);
  assert.doesNotMatch(srcText, /\bnew\s+Function\s*\(/);
  assert.doesNotMatch(srcText, /style\s*=\s*["']/i);
});
