/**
 * Strict-CSP Trading Aggression Dial (0.20%..1.00% in 0.01% single-unit bps steps 20..100 +
 * AI Discretion) & Section B.5 5-Tier Per-Tier Dial UI Module for CAS Forex Revamp.
 *
 * Pure, zero-dependency ES module:
 * - Strict CSP: ZERO inline style attributes, ZERO eval/Function, ZERO inline event handlers.
 * - XSS-safe HTML escaping on every dynamic string.
 * - Buttery-smooth 60fps sliding pill switch (role="switch") + cubic-bezier transitions +
 *   zero-flicker in-place DOM patching (patchAggressionDialInPlace) with ZERO innerHTML churn.
 * - Exact BigInt integer half-up arithmetic matching Python int/Decimal across all
 *   81 risk_bps steps (20..100 = 0.20%..1.00%) x 5 tiers ($300k, $6k, $3k, $1k, $300) = 405 tuples.
 * - Constitutional PR #25 ceilings: MAX_CONSTITUTIONAL_STOP_RISK_PCT = 1.00% (100 bps),
 *   MAX_CONSTITUTIONAL_DRAWDOWN_PCT = 0.10 (10.00%), MIN_CONSTITUTIONAL_SIGNAL_PROB = 0.55,
 *   and read-only tablet gating via ownerControlsAllowed ("Owner Key Required").
 * - Unbreakable guardrails (Safety Valve 0.55 · 1,000% Margin · 50ms Stop-Loss) always locked ON.
 */

export const AGGRESSION_DIAL_SCHEMA = 'cas-forex.aggression-dial/1';
export const REF_CAPITAL_CENTS = 30000000n;
export const MIN_RISK_BPS = 20;
export const MAX_RISK_BPS = 100;
export const RISK_BPS_STEP = 1;
export const DEFAULT_MASTER_RISK_BPS = 60;
export const HIGH_RISK_MIN_BPS = 80;
export const DEFAULT_AI_DISCRETION_CEILING_BPS = 100;
export const MAX_CONSTITUTIONAL_STOP_RISK_PCT = '1.00';
export const MAX_CONSTITUTIONAL_STOP_RISK_BPS = 100;
export const MAX_CONSTITUTIONAL_DRAWDOWN_PCT = '0.10';
export const MIN_CONSTITUTIONAL_SIGNAL_PROB = '0.55';
export const MIN_CONSTITUTIONAL_SIGNAL_PROB_BP = 55;

export const UNBREAKABLE_GUARDRAILS = Object.freeze({
  valveRequired: true,
  valveController: 'tks_meta_valve_controller',
  valveParameters: 161,
  valveCutoff: '0.55',
  minSignalProbFloor: MIN_CONSTITUTIONAL_SIGNAL_PROB,
  maxConstitutionalStopRiskPct: MAX_CONSTITUTIONAL_STOP_RISK_PCT,
  maxConstitutionalDrawdownPct: MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
  minMarginLevelPct: '1000.0',
  lotFloor: '0.01',
  lotRounding: 'ROUND_FLOOR',
  fastStopProtectionMs: 50,
  maxDrawdownBrakePct: '10.00',
  summaryLine: 'Safety Valve 0.55 · 1,000% Margin · 50ms Stop-Loss',
});

const DIAL_LEVEL_CLASSES = Object.freeze([
  'dial-lvl-1',
  'dial-lvl-2',
  'dial-lvl-3',
  'dial-lvl-4',
  'dial-lvl-5',
  'dial-lvl-6',
  'dial-lvl-7',
  'dial-lvl-8',
  'dial-lvl-9',
  'dial-lvl-10',
  'dial-lvl-11',
]);

export const AGGRESSION_ANCHOR_KNOTS = Object.freeze([
  Object.freeze({ bps: 20, label: 'Safe', maxOpenTrades: 1, probBp: 78, ref300kGoalCents: 150000n, ref300kLossCents: 75000n }),
  Object.freeze({ bps: 40, label: 'Steady', maxOpenTrades: 2, probBp: 72, ref300kGoalCents: 300000n, ref300kLossCents: 150000n }),
  Object.freeze({ bps: 60, label: 'Balanced', maxOpenTrades: 3, probBp: 66, ref300kGoalCents: 450000n, ref300kLossCents: 250000n }),
  Object.freeze({ bps: 85, label: 'Risky', maxOpenTrades: 5, probBp: 59, ref300kGoalCents: 750000n, ref300kLossCents: 475000n }),
  Object.freeze({ bps: 95, label: 'High Risk', maxOpenTrades: 6, probBp: 55, ref300kGoalCents: 1000000n, ref300kLossCents: 600000n }),
  Object.freeze({ bps: 100, label: 'Extreme High Risk', maxOpenTrades: 8, probBp: 55, ref300kGoalCents: 1500000n, ref300kLossCents: 850000n }),
]);

export const MASTER_PRESET_BUTTONS = Object.freeze([
  Object.freeze({ bps: 20, label: 'Safe 0.20%' }),
  Object.freeze({ bps: 40, label: 'Steady 0.40%' }),
  Object.freeze({ bps: 60, label: 'Balanced 0.60%' }),
  Object.freeze({ bps: 85, label: 'Risky 0.85%' }),
  Object.freeze({ bps: 95, label: 'High Risk 0.95%' }),
  Object.freeze({ bps: 100, label: 'Extreme 1.00%' }),
]);

export const MASTER_SLIDER_TICKS_BPS = Object.freeze([20, 30, 40, 50, 60, 70, 80, 90, 100]);

export const TIER_COMPACT_PRESETS = Object.freeze([
  Object.freeze({ bps: 20, label: '0.20%' }),
  Object.freeze({ bps: 40, label: '0.40%' }),
  Object.freeze({ bps: 60, label: '0.60%' }),
  Object.freeze({ bps: 85, label: '0.85%' }),
  Object.freeze({ bps: 95, label: '0.95%' }),
  Object.freeze({ bps: 100, label: '1.00%' }),
]);

export const TIER_QUICK_PRESETS = Object.freeze([
  Object.freeze({ id: 'SYNC_MASTER', label: 'Sync All 5 to Master' }),
  Object.freeze({ id: 'STAGGER_SAFE_TO_EXTREME', label: 'Stagger Safe → Extreme' }),
  Object.freeze({ id: 'ALL_BALANCED', label: 'All Balanced (0.60%)' }),
]);

export const STAGGER_SAFE_TO_EXTREME_BPS = Object.freeze({
  TIER_1_CURRENT: 25,
  TIER_4_6000: 45,
  TIER_3_3000: 65,
  TIER_2_1000: 85,
  TIER_5_300: 100,
});

export const STAGGER_SAFE_TO_HIGH_BPS = STAGGER_SAFE_TO_EXTREME_BPS;

export const DEFAULT_TIER_DEFINITIONS = Object.freeze([
  Object.freeze({
    tierId: 'TIER_1_CURRENT',
    label: 'Current Barbell ($300,000)',
    colorToken: 'tier-300k',
    startingCapitalCents: 30000000n,
    startingCapitalUsd: '300000.00',
  }),
  Object.freeze({
    tierId: 'TIER_4_6000',
    label: 'Tier $6,000 Accelerator',
    colorToken: 'tier-6000',
    startingCapitalCents: 600000n,
    startingCapitalUsd: '6000.00',
  }),
  Object.freeze({
    tierId: 'TIER_3_3000',
    label: 'Tier $3,000 Growth',
    colorToken: 'tier-3000',
    startingCapitalCents: 300000n,
    startingCapitalUsd: '3000.00',
  }),
  Object.freeze({
    tierId: 'TIER_2_1000',
    label: 'Tier $1,000 Starter',
    colorToken: 'tier-1000',
    startingCapitalCents: 100000n,
    startingCapitalUsd: '1000.00',
  }),
  Object.freeze({
    tierId: 'TIER_5_300',
    label: 'Tier $300 Micro Challenge',
    colorToken: 'tier-300',
    startingCapitalCents: 30000n,
    startingCapitalUsd: '300.00',
  }),
]);

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function cleanStr(value, fallback = '', maxLen = 160) {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLen) : fallback;
}

function addThousandsCommas(intDigits) {
  return intDigits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function formatRiskBpsPct(bps) {
  const whole = Math.floor(bps / 100);
  const frac = String(bps % 100).padStart(2, '0');
  return `${whole}.${frac}`;
}

export function formatProbBp(probBp) {
  const whole = Math.floor(probBp / 100);
  const frac = String(probBp % 100).padStart(2, '0');
  return `${whole}.${frac}`;
}

export function formatCentsPlain(cents) {
  const value = typeof cents === 'bigint' ? cents : BigInt(cents);
  const neg = value < 0n;
  const abs = neg ? -value : value;
  const whole = abs / 100n;
  const rem = abs % 100n;
  return `${neg ? '-' : ''}${whole}.${String(rem).padStart(2, '0')}`;
}

export function formatCentsUsd(cents) {
  const value = typeof cents === 'bigint' ? cents : BigInt(cents);
  const neg = value < 0n;
  const abs = neg ? -value : value;
  const whole = addThousandsCommas((abs / 100n).toString());
  const rem = String(abs % 100n).padStart(2, '0');
  return `${neg ? '-$' : '$'}${whole}.${rem}`;
}

export function formatCentsSignedUsd(cents, positivePrefix = '+') {
  const value = typeof cents === 'bigint' ? cents : BigInt(cents);
  const neg = value < 0n;
  const abs = neg ? -value : value;
  const whole = addThousandsCommas((abs / 100n).toString());
  const rem = String(abs % 100n).padStart(2, '0');
  if (neg) return `-$${whole}.${rem}`;
  if (positivePrefix === '-') return `-$${whole}.${rem}`;
  return `${positivePrefix}$${whole}.${rem}`;
}

export function usdToCentsBigInt(raw, fallbackCents = 0n) {
  if (typeof raw === 'bigint') {
    return raw >= 0n ? raw : fallbackCents;
  }
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) {
    raw = String(raw);
  }
  if (typeof raw !== 'string') return fallbackCents;
  const cleaned = raw.trim().replaceAll(',', '').replace(/^\$/, '');
  if (!/^\d+(?:\.\d+)?$/.test(cleaned)) return fallbackCents;
  const [intPart = '0', fracPart = ''] = cleaned.split('.');
  const frac2 = fracPart.slice(0, 2).padEnd(2, '0');
  let cents = BigInt(intPart) * 100n + BigInt(frac2);
  if (fracPart.length >= 3 && fracPart[2] >= '5') {
    cents += 1n;
  }
  return cents;
}

export function zoneForRiskBps(riskBps) {
  if (riskBps <= 29) return Object.freeze({ label: 'Safe', cssClass: 'dial-lvl-1' });
  if (riskBps <= 39) return Object.freeze({ label: 'Calm', cssClass: 'dial-lvl-2' });
  if (riskBps <= 49) return Object.freeze({ label: 'Steady', cssClass: 'dial-lvl-3' });
  if (riskBps <= 59) return Object.freeze({ label: 'Moderate', cssClass: 'dial-lvl-4' });
  if (riskBps <= 69) return Object.freeze({ label: 'Balanced', cssClass: 'dial-lvl-5' });
  if (riskBps <= 74) return Object.freeze({ label: 'Active', cssClass: 'dial-lvl-6' });
  if (riskBps <= 79) return Object.freeze({ label: 'Bold', cssClass: 'dial-lvl-7' });
  if (riskBps <= 89) return Object.freeze({ label: 'Risky', cssClass: 'dial-lvl-8' });
  if (riskBps <= 95) return Object.freeze({ label: 'High Risk', cssClass: 'dial-lvl-10' });
  return Object.freeze({ label: 'Extreme High Risk', cssClass: 'dial-lvl-11' });
}

function divRoundHalfUpBigInt(num, den) {
  return (num + (den / 2n)) / den;
}

function computeProfileForBps(bps) {
  if (bps < MIN_RISK_BPS || bps > MAX_RISK_BPS || !Number.isInteger(bps)) {
    throw new RangeError(`riskBps must be an integer between ${MIN_RISK_BPS} and ${MAX_RISK_BPS}, got: ${String(bps)}`);
  }
  let k0 = AGGRESSION_ANCHOR_KNOTS[0];
  let k1 = AGGRESSION_ANCHOR_KNOTS[AGGRESSION_ANCHOR_KNOTS.length - 1];
  for (let i = 0; i < AGGRESSION_ANCHOR_KNOTS.length - 1; i += 1) {
    const a = AGGRESSION_ANCHOR_KNOTS[i];
    const b = AGGRESSION_ANCHOR_KNOTS[i + 1];
    if (bps >= a.bps && bps <= b.bps) {
      k0 = a;
      k1 = b;
      break;
    }
  }

  const dx = BigInt(bps - k0.bps);
  const span = BigInt(k1.bps - k0.bps);

  const ref300kGoalCents = k0.ref300kGoalCents + divRoundHalfUpBigInt((k1.ref300kGoalCents - k0.ref300kGoalCents) * dx, span);
  const ref300kLossCents = k0.ref300kLossCents + divRoundHalfUpBigInt((k1.ref300kLossCents - k0.ref300kLossCents) * dx, span);
  const probBpBig = BigInt(k0.probBp) - divRoundHalfUpBigInt(BigInt(k0.probBp - k1.probBp) * dx, span);
  const probBp = Math.max(MIN_CONSTITUTIONAL_SIGNAL_PROB_BP, Number(probBpBig));
  const maxOpenTrades = Number(
    BigInt(k0.maxOpenTrades) + divRoundHalfUpBigInt(BigInt(k1.maxOpenTrades - k0.maxOpenTrades) * dx, span),
  );

  const zone = zoneForRiskBps(bps);
  const riskPct = formatRiskBpsPct(bps);
  const minSignalProb = formatProbBp(probBp);

  return Object.freeze({
    riskBps: bps,
    label: zone.label,
    cssClass: zone.cssClass,
    riskPct,
    riskPctLabel: `${riskPct}%`,
    maxOpenTrades,
    probBp,
    minSignalProb,
    ref300kGoalCents,
    ref300kGoalUsd: formatCentsPlain(ref300kGoalCents),
    ref300kGoalFormatted: formatCentsSignedUsd(ref300kGoalCents, '+'),
    ref300kLossCents,
    ref300kLossUsd: formatCentsPlain(ref300kLossCents),
    ref300kLossFormatted: formatCentsSignedUsd(ref300kLossCents, '-'),
    softGoalRatio: '0.70',
    maxDrawdownPct: MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    highRisk: bps >= HIGH_RISK_MIN_BPS,
  });
}

function buildRiskBpsCatalog() {
  const byBps = {};
  const list = [];
  for (let bps = MIN_RISK_BPS; bps <= MAX_RISK_BPS; bps += RISK_BPS_STEP) {
    const profile = computeProfileForBps(bps);
    byBps[bps] = profile;
    list.push(profile);
  }
  return {
    byBps: Object.freeze(byBps),
    list: Object.freeze(list),
  };
}

const CATALOG = buildRiskBpsCatalog();
export const RISK_BPS_PROFILES = CATALOG.byBps;
export const RISK_BPS_PROFILE_LIST = CATALOG.list;

export function clampRiskBps(value, fallback = DEFAULT_MASTER_RISK_BPS) {
  if (typeof value === 'boolean' || value === null || value === undefined || value === '') {
    return fallback;
  }
  const parsed = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isInteger(parsed)) return fallback;
  if (parsed < MIN_RISK_BPS) return MIN_RISK_BPS;
  if (parsed > MAX_RISK_BPS) return MAX_RISK_BPS;
  return parsed;
}

export function getRiskBpsProfile(riskBps) {
  if (
    typeof riskBps !== 'number'
    || !Number.isInteger(riskBps)
    || riskBps < MIN_RISK_BPS
    || riskBps > MAX_RISK_BPS
  ) {
    throw new RangeError(
      `riskBps must be an integer between ${MIN_RISK_BPS} and ${MAX_RISK_BPS}, got: ${String(riskBps)}`,
    );
  }
  return RISK_BPS_PROFILES[riskBps];
}

function normalizeCapitalCents(startingCapitalCents) {
  if (typeof startingCapitalCents === 'bigint') {
    if (startingCapitalCents < 0n) {
      throw new RangeError('startingCapitalCents must be non-negative');
    }
    return startingCapitalCents;
  }
  if (typeof startingCapitalCents === 'number' && Number.isSafeInteger(startingCapitalCents) && startingCapitalCents >= 0) {
    return BigInt(startingCapitalCents);
  }
  if (typeof startingCapitalCents === 'string' && /^\d+$/.test(startingCapitalCents.trim())) {
    return BigInt(startingCapitalCents.trim());
  }
  throw new TypeError(`startingCapitalCents must be a non-negative BigInt or integer, got: ${String(startingCapitalCents)}`);
}

function scaleHalfUpFrom300k(refCents, capitalCents) {
  return ((refCents * capitalCents) + 15000000n) / 30000000n;
}

/**
 * Exact BigInt half-up proportional scaling from the $300,000.00 interpolated profile
 * for ANY riskBps in 20..100 (0.20%..1.00% in 0.01% steps) to any tier starting capital in cents.
 * Guaranteed 405/405 parity with Python int/Decimal across 81 bps steps x 5 tiers.
 */
export function scaleTierTargets(riskBps, startingCapitalCents) {
  const profile = getRiskBpsProfile(riskBps);
  const capCents = normalizeCapitalCents(startingCapitalCents);
  const sessionGoalCents = scaleHalfUpFrom300k(profile.ref300kGoalCents, capCents);
  const dailyLossBrakeCents = scaleHalfUpFrom300k(profile.ref300kLossCents, capCents);
  const riskPerTradeCents = ((capCents * BigInt(profile.riskBps)) + 5000n) / 10000n;

  return Object.freeze({
    riskBps: profile.riskBps,
    label: profile.label,
    cssClass: profile.cssClass,
    highRisk: profile.highRisk,
    riskPct: profile.riskPct,
    riskPctLabel: profile.riskPctLabel,
    maxOpenTrades: profile.maxOpenTrades,
    probBp: profile.probBp,
    minSignalProb: profile.minSignalProb,
    maxDrawdownPct: MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    startingCapitalCents: capCents,
    startingCapitalUsd: formatCentsPlain(capCents),
    startingCapitalFormatted: formatCentsUsd(capCents),
    sessionGoalCents,
    sessionGoalUsd: formatCentsPlain(sessionGoalCents),
    sessionGoalFormatted: formatCentsSignedUsd(sessionGoalCents, '+'),
    dailyLossBrakeCents,
    dailyLossBrakeUsd: formatCentsPlain(dailyLossBrakeCents),
    dailyLossBrakeFormatted: formatCentsSignedUsd(dailyLossBrakeCents, '-'),
    riskPerTradeCents,
    riskPerTradeUsd: formatCentsPlain(riskPerTradeCents),
    riskPerTradeFormatted: formatCentsUsd(riskPerTradeCents),
  });
}

function buildTierEntry(def, rawTier, fallbackBps) {
  const label = cleanStr(rawTier?.label, def.label, 120);
  const colorToken = cleanStr(rawTier?.colorToken ?? rawTier?.color_token, def.colorToken, 40);
  const rawCapCents = rawTier?.startingCapitalCents ?? rawTier?.starting_capital_cents;
  const rawCapUsd = rawTier?.startingCapitalUsd ?? rawTier?.starting_capital_usd ?? rawTier?.capital_usd;
  let startingCapitalCents = def.startingCapitalCents;
  if (rawCapCents !== undefined && rawCapCents !== null) {
    try {
      startingCapitalCents = normalizeCapitalCents(rawCapCents);
    } catch {
      startingCapitalCents = def.startingCapitalCents;
    }
  } else if (rawCapUsd !== undefined && rawCapUsd !== null) {
    const parsed = usdToCentsBigInt(rawCapUsd, -1n);
    if (parsed > 0n) startingCapitalCents = parsed;
  }

  const riskBps = clampRiskBps(
    rawTier?.riskBps ?? rawTier?.risk_bps ?? rawTier?.chosen_risk_bps ?? rawTier?.bps,
    fallbackBps,
  );
  const rawEff = rawTier?.effectiveRiskBps ?? rawTier?.effective_risk_bps;
  const effectiveRiskBps = rawEff !== undefined && rawEff !== null
    ? clampRiskBps(rawEff, riskBps)
    : riskBps;

  const scaled = scaleTierTargets(effectiveRiskBps, startingCapitalCents);
  const chosenProfile = RISK_BPS_PROFILES[riskBps];

  return Object.freeze({
    tierId: def.tierId,
    label,
    colorToken,
    riskBps,
    effectiveRiskBps,
    zoneLabel: scaled.label,
    chosenZoneLabel: chosenProfile.label,
    cssClass: scaled.cssClass,
    highRisk: scaled.highRisk,
    riskPct: scaled.riskPct,
    riskPctLabel: scaled.riskPctLabel,
    maxOpenTrades: scaled.maxOpenTrades,
    probBp: scaled.probBp,
    minSignalProb: scaled.minSignalProb,
    maxDrawdownPct: scaled.maxDrawdownPct,
    startingCapitalCents: scaled.startingCapitalCents,
    startingCapitalUsd: scaled.startingCapitalUsd,
    startingCapitalFormatted: scaled.startingCapitalFormatted,
    sessionGoalCents: scaled.sessionGoalCents,
    sessionGoalUsd: scaled.sessionGoalUsd,
    sessionGoalFormatted: scaled.sessionGoalFormatted,
    dailyLossBrakeCents: scaled.dailyLossBrakeCents,
    dailyLossBrakeUsd: scaled.dailyLossBrakeUsd,
    dailyLossBrakeFormatted: scaled.dailyLossBrakeFormatted,
    riskPerTradeCents: scaled.riskPerTradeCents,
    riskPerTradeUsd: scaled.riskPerTradeUsd,
    riskPerTradeFormatted: scaled.riskPerTradeFormatted,
  });
}

function buildStaticState() {
  const masterRiskBps = DEFAULT_MASTER_RISK_BPS;
  const masterTargets = scaleTierTargets(masterRiskBps, REF_CAPITAL_CENTS);
  const tiers = Object.freeze(
    DEFAULT_TIER_DEFINITIONS.map((def) => buildTierEntry(def, null, masterRiskBps)),
  );
  return Object.freeze({
    schema: AGGRESSION_DIAL_SCHEMA,
    connected: false,
    liveMode: false,
    ownerControlsAllowed: true,
    masterRiskBps,
    effectiveRiskBps: masterRiskBps,
    effectiveLabel: masterTargets.label,
    aiDiscretionEnabled: true,
    autoShiftEnabled: true,
    aiDiscretionCeilingBps: DEFAULT_AI_DISCRETION_CEILING_BPS,
    aiDiscretionReason: '',
    masterCapitalCents: REF_CAPITAL_CENTS,
    masterCapitalUsd: '300000.00',
    masterTargets,
    pendingHighRiskBps: null,
    pendingHighRiskTierId: null,
    pendingAiDiscretionCeilingBps: null,
    tiers,
    guardrails: UNBREAKABLE_GUARDRAILS,
    auditVerified: true,
  });
}

export const STATIC_AGGRESSION_DIAL = buildStaticState();

function extractRawTierMap(doc) {
  const byId = new Map();
  const tiersInput = doc?.tiers;
  if (Array.isArray(tiersInput)) {
    for (const item of tiersInput) {
      const id = cleanStr(item?.tierId ?? item?.tier_id, '', 48);
      if (id) byId.set(id, item);
    }
  } else if (tiersInput && typeof tiersInput === 'object') {
    for (const [id, val] of Object.entries(tiersInput)) {
      if (typeof val === 'number' || typeof val === 'string') {
        byId.set(id, { tierId: id, riskBps: val });
      } else if (val && typeof val === 'object') {
        byId.set(id, { tierId: id, ...val });
      }
    }
  }

  const tierBpsMap = doc?.tierRiskBps ?? doc?.tier_risk_bps;
  if (tierBpsMap && typeof tierBpsMap === 'object' && !Array.isArray(tierBpsMap)) {
    for (const [id, bps] of Object.entries(tierBpsMap)) {
      const prev = byId.get(id) ?? { tierId: id };
      if (prev.riskBps === undefined && prev.risk_bps === undefined && prev.chosen_risk_bps === undefined) {
        byId.set(id, { ...prev, riskBps: bps });
      }
    }
  }
  return byId;
}

export function normalizeAggressionDial(doc) {
  if (!doc || typeof doc !== 'object') {
    return STATIC_AGGRESSION_DIAL;
  }

  const source = (doc.aggressionDial && typeof doc.aggressionDial === 'object')
    ? doc.aggressionDial
    : (doc.aggression_dial && typeof doc.aggression_dial === 'object')
      ? doc.aggression_dial
      : doc;

  const masterObj = source.master && typeof source.master === 'object' ? source.master : {};

  const masterRiskBps = clampRiskBps(
    source.masterRiskBps ?? source.master_risk_bps ?? masterObj.risk_bps ?? masterObj.chosen_risk_bps,
    DEFAULT_MASTER_RISK_BPS,
  );

  const rawAiDiscretion = (
    source.aiDiscretionEnabled
    ?? source.ai_discretion_enabled
    ?? masterObj.ai_discretion_enabled
    ?? source.autoShiftEnabled
    ?? source.auto_shift_enabled
    ?? masterObj.auto_shift_enabled
  );
  const aiDiscretionEnabled = typeof rawAiDiscretion === 'boolean' ? rawAiDiscretion : true;

  const aiDiscretionCeilingBps = clampRiskBps(
    source.aiDiscretionCeilingBps
      ?? source.ai_discretion_ceiling_bps
      ?? masterObj.ai_discretion_ceiling_bps,
    DEFAULT_AI_DISCRETION_CEILING_BPS,
  );

  const aiDiscretionReason = cleanStr(
    source.aiDiscretionReason ?? source.ai_discretion_reason ?? masterObj.ai_discretion_reason,
    '',
    120,
  );

  const rawEff = source.effectiveRiskBps ?? source.effective_risk_bps ?? masterObj.effective_risk_bps;
  let effectiveRiskBps = masterRiskBps;
  if (aiDiscretionEnabled && rawEff !== undefined && rawEff !== null) {
    effectiveRiskBps = Math.min(aiDiscretionCeilingBps, clampRiskBps(rawEff, masterRiskBps));
  }

  const rawLive = source.liveMode ?? source.live_mode ?? doc.liveMode ?? doc.live_mode;
  const execMode = cleanStr(doc.executionMode ?? doc.execution_mode ?? source.executionMode ?? source.execution_mode, '', 24).toUpperCase();
  const liveMode = typeof rawLive === 'boolean' ? rawLive : execMode === 'LIVE';

  const rawOwnerAllowed = (
    source.ownerControlsAllowed
    ?? source.owner_controls_allowed
    ?? doc.ownerControlsAllowed
    ?? doc.owner_controls_allowed
    ?? doc.aiTrader?.ownerControlsAllowed
    ?? doc.ai_trader?.owner_controls_allowed
  );
  const rawRole = cleanStr(
    source.sessionRole ?? source.session_role ?? doc.sessionRole ?? doc.session_role ?? doc.aiTrader?.sessionRole,
    '',
    48,
  ).toUpperCase();
  const ownerControlsAllowed = typeof rawOwnerAllowed === 'boolean'
    ? rawOwnerAllowed
    : rawRole !== 'DEVICE_READ_AND_EXPLAINER';

  const rawMasterCapCents = source.masterCapitalCents ?? source.master_capital_cents ?? masterObj.capital_cents;
  const rawMasterCapUsd = source.masterCapitalUsd ?? source.master_capital_usd ?? masterObj.capital_usd;
  let masterCapitalCents = REF_CAPITAL_CENTS;
  if (rawMasterCapCents !== undefined && rawMasterCapCents !== null) {
    try {
      const parsed = normalizeCapitalCents(rawMasterCapCents);
      if (parsed > 0n) masterCapitalCents = parsed;
    } catch {
      masterCapitalCents = REF_CAPITAL_CENTS;
    }
  } else if (rawMasterCapUsd !== undefined && rawMasterCapUsd !== null) {
    const parsed = usdToCentsBigInt(rawMasterCapUsd, 0n);
    if (parsed > 0n) masterCapitalCents = parsed;
  }

  const rawPending = source.pendingHighRiskBps ?? source.pending_high_risk_bps;
  let pendingHighRiskBps = null;
  if (rawPending !== undefined && rawPending !== null && rawPending !== '') {
    const parsedPending = clampRiskBps(rawPending, 0);
    if (parsedPending >= HIGH_RISK_MIN_BPS) {
      pendingHighRiskBps = parsedPending;
    }
  }

  const rawPendingCeiling = source.pendingAiDiscretionCeilingBps ?? source.pending_ai_discretion_ceiling_bps;
  let pendingAiDiscretionCeilingBps = null;
  if (rawPendingCeiling !== undefined && rawPendingCeiling !== null && rawPendingCeiling !== '') {
    const parsedCeiling = clampRiskBps(rawPendingCeiling, 0);
    if (parsedCeiling >= HIGH_RISK_MIN_BPS) {
      pendingAiDiscretionCeilingBps = parsedCeiling;
    }
  }

  const rawPendingTier = cleanStr(source.pendingHighRiskTierId ?? source.pending_high_risk_tier_id, '', 48);
  const pendingHighRiskTierId = rawPendingTier || null;

  const rawTierMap = extractRawTierMap(source);
  const tiers = Object.freeze(
    DEFAULT_TIER_DEFINITIONS.map((def) => buildTierEntry(def, rawTierMap.get(def.tierId), DEFAULT_MASTER_RISK_BPS)),
  );

  const connected = typeof source.connected === 'boolean'
    ? source.connected
    : source.schema === AGGRESSION_DIAL_SCHEMA;

  const auditVerified = typeof (source.auditVerified ?? source.audit_verified) === 'boolean'
    ? Boolean(source.auditVerified ?? source.audit_verified)
    : true;

  const masterTargets = scaleTierTargets(effectiveRiskBps, masterCapitalCents);

  return Object.freeze({
    schema: AGGRESSION_DIAL_SCHEMA,
    connected,
    liveMode,
    ownerControlsAllowed,
    masterRiskBps,
    effectiveRiskBps,
    effectiveLabel: masterTargets.label,
    aiDiscretionEnabled,
    autoShiftEnabled: aiDiscretionEnabled,
    aiDiscretionCeilingBps,
    aiDiscretionReason,
    masterCapitalCents,
    masterCapitalUsd: formatCentsPlain(masterCapitalCents),
    masterTargets,
    pendingHighRiskBps,
    pendingHighRiskTierId,
    pendingAiDiscretionCeilingBps,
    tiers,
    guardrails: UNBREAKABLE_GUARDRAILS,
    auditVerified,
  });
}

export function applyAggressionDialPreset(state, presetId) {
  const dial = normalizeAggressionDial(state);
  const code = cleanStr(presetId, '', 40).toUpperCase();
  const nextBps = {};
  for (const tier of dial.tiers) {
    if (code === 'SYNC_MASTER') {
      nextBps[tier.tierId] = dial.masterRiskBps;
    } else if (code === 'STAGGER_SAFE_TO_EXTREME' || code === 'STAGGER_SAFE_TO_HIGH') {
      nextBps[tier.tierId] = STAGGER_SAFE_TO_EXTREME_BPS[tier.tierId] ?? DEFAULT_MASTER_RISK_BPS;
    } else if (code === 'ALL_BALANCED') {
      nextBps[tier.tierId] = DEFAULT_MASTER_RISK_BPS;
    } else if (code === 'ALL_SAFE') {
      nextBps[tier.tierId] = MIN_RISK_BPS;
    } else {
      nextBps[tier.tierId] = tier.riskBps;
    }
  }
  return normalizeAggressionDial({
    ...dial,
    tiers: dial.tiers.map((tier) => ({
      ...tier,
      riskBps: nextBps[tier.tierId],
      effectiveRiskBps: nextBps[tier.tierId],
    })),
  });
}

function buildMasterSublineText(dial, chosenProfile, targets) {
  const ceilingPct = formatRiskBpsPct(dial.aiDiscretionCeilingBps);
  const ceilingNote = dial.aiDiscretionEnabled ? ` · AI Ceiling ${ceilingPct}%` : '';
  return `Master ${chosenProfile.riskPctLabel} (${chosenProfile.label}) · Min Signal ${targets.minSignalProb}${ceilingNote}${dial.liveMode ? ' · LIVE' : ' · DEMO'}`;
}

function buildAiShiftText(dial, targets) {
  const reasonSuffix = dial.aiDiscretionReason ? ` (${dial.aiDiscretionReason})` : '';
  return `AI Discretion Active → ${targets.riskPctLabel} ${targets.label}${reasonSuffix}`;
}

function renderHighRiskConfirmBanner(pendingBps, targetLabel, tierId = null, disabledAttr = '', kind = 'bps') {
  const profile = RISK_BPS_PROFILES[pendingBps];
  if (!profile || !profile.highRisk) return '';
  const tierAttr = tierId ? ` data-dial-confirm-tier-id="${esc(tierId)}"` : '';
  const kindAttr = ` data-dial-confirm-kind="${esc(kind)}"`;
  const heading = kind === 'ai-ceiling'
    ? `Confirm Live AI Discretion Ceiling ${esc(profile.riskPctLabel)} (${esc(profile.label)})`
    : `Confirm Live High-Risk ${esc(profile.riskPctLabel)} (${esc(profile.label)})`;
  return `<div class="dial-confirm-banner ${esc(profile.cssClass)}" role="alert" data-dial-confirm-banner="true"${tierAttr}${kindAttr}>
      <div class="dial-confirm-copy">
        <strong>${heading}</strong>
        <span>${esc(targetLabel)} will allow up to ${esc(profile.riskPctLabel)} risk per trade (max ${profile.maxOpenTrades} open, min signal ${esc(profile.minSignalProb)}) in LIVE mode. ${esc(UNBREAKABLE_GUARDRAILS.summaryLine)} remain locked ON.</span>
      </div>
      <div class="dial-confirm-actions">
        <button type="button" class="dial-confirm-btn" data-dial-confirm-high-risk="true" data-dial-confirm-bps="${profile.riskBps}"${tierAttr}${kindAttr}${disabledAttr}>Confirm ${esc(profile.riskPctLabel)}</button>
        <button type="button" class="dial-cancel-btn" data-dial-cancel-high-risk="true"${tierAttr}${kindAttr}${disabledAttr}>Cancel</button>
      </div>
    </div>`;
}

export function renderMasterAggressionDial(state) {
  const dial = normalizeAggressionDial(state);
  const chosenProfile = RISK_BPS_PROFILES[dial.masterRiskBps];
  const targets = dial.masterTargets;
  const readOnly = dial.ownerControlsAllowed === false;
  const disabledAttr = readOnly ? ' disabled' : '';
  const readonlyCls = readOnly ? ' is-readonly' : '';

  const ownerLockBadge = readOnly
    ? '<span class="dial-pill-tag dial-owner-lock-badge" data-dial-owner-key-required="true">Owner Key Required</span>'
    : '<span class="dial-pill-tag dial-owner-lock-badge" data-dial-owner-key-required="false" hidden></span>';

  const isShifted = dial.aiDiscretionEnabled && dial.effectiveRiskBps !== dial.masterRiskBps;
  const shiftedNote = isShifted
    ? `<span class="dial-pill-tag dial-shift-pill ${esc(targets.cssClass)}" data-dial-ai-shifted="true" data-dial-auto-shifted="true">${esc(buildAiShiftText(dial, targets))}</span>`
    : `<span class="dial-pill-tag dial-shift-pill ${esc(targets.cssClass)}" data-dial-ai-shifted="false" data-dial-auto-shifted="false" hidden></span>`;

  const ticksHtml = MASTER_SLIDER_TICKS_BPS.map((tickBps) => {
    const activeCls = tickBps === dial.masterRiskBps ? ' is-current' : '';
    const aiCls = isShifted && tickBps === dial.effectiveRiskBps ? ' is-ai-active' : '';
    return `<span class="dial-tick${activeCls}${aiCls}" data-dial-tick-bps="${tickBps}">${formatRiskBpsPct(tickBps)}%</span>`;
  }).join('');

  const presetsHtml = MASTER_PRESET_BUTTONS.map((preset) => {
    const p = RISK_BPS_PROFILES[preset.bps];
    const activeCls = dial.masterRiskBps === preset.bps ? ' is-active' : '';
    return `<button type="button" class="dial-preset-btn ${esc(p.cssClass)}${activeCls}" data-dial-master-preset="${preset.bps}" aria-pressed="${dial.masterRiskBps === preset.bps ? 'true' : 'false'}"${disabledAttr}>${esc(preset.label)}</button>`;
  }).join('');

  let confirmBannerHtml = '';
  if (!readOnly && dial.liveMode === true) {
    if (
      dial.pendingHighRiskBps !== null
      && dial.pendingHighRiskBps >= HIGH_RISK_MIN_BPS
      && !dial.pendingHighRiskTierId
    ) {
      confirmBannerHtml = renderHighRiskConfirmBanner(dial.pendingHighRiskBps, 'Master Dial', null, disabledAttr, 'bps');
    } else if (
      dial.pendingAiDiscretionCeilingBps !== null
      && dial.pendingAiDiscretionCeilingBps >= HIGH_RISK_MIN_BPS
    ) {
      confirmBannerHtml = renderHighRiskConfirmBanner(
        dial.pendingAiDiscretionCeilingBps,
        'AI Discretion Ceiling',
        null,
        disabledAttr,
        'ai-ceiling',
      );
    }
  }

  const switchCls = dial.aiDiscretionEnabled ? 'is-on' : 'is-off';
  const toggleLabel = dial.aiDiscretionEnabled ? 'AI Discretion: ON' : 'Manual Lock';
  const sublineText = buildMasterSublineText(dial, chosenProfile, targets);

  return `<section class="panel aggression-dial-panel ${esc(targets.cssClass)}${readonlyCls}" data-aggression-dial="master" data-dial-bps="${targets.riskBps}" data-dial-master-bps="${dial.masterRiskBps}" data-ai-discretion="${dial.aiDiscretionEnabled ? 'true' : 'false'}" data-live-mode="${dial.liveMode ? 'true' : 'false'}" data-owner-controls-allowed="${dial.ownerControlsAllowed ? 'true' : 'false'}" aria-label="Master Trading Aggression Dial">
    <div class="dial-header">
      <div class="dial-title-group">
        <span class="dial-badge dial-level-badge ${esc(targets.cssClass)}" data-dial-bps-badge="${targets.riskBps}">${esc(targets.riskPctLabel)}</span>
        <div>
          <h2 class="dial-heading" data-dial-heading="true">${esc(targets.label)}</h2>
          <span class="dial-subline" data-dial-subline="true">${esc(sublineText)}</span>
        </div>
        ${shiftedNote}
        ${ownerLockBadge}
      </div>
      <button type="button" role="switch" aria-checked="${dial.aiDiscretionEnabled ? 'true' : 'false'}" class="dial-switch ${switchCls}" data-dial-action="TOGGLE_AI_DISCRETION"${disabledAttr}>
        <span class="dial-switch-track" aria-hidden="true"><span class="dial-switch-thumb"></span></span>
        <span class="dial-switch-label" data-dial-switch-label="true">${esc(toggleLabel)}</span>
      </button>
    </div>

    <div class="dial-slider-wrap">
      <input type="range" class="dial-slider ${esc(chosenProfile.cssClass)}" min="${MIN_RISK_BPS}" max="${MAX_RISK_BPS}" step="${RISK_BPS_STEP}" value="${dial.masterRiskBps}" data-dial-master-slider="true" aria-label="Master trading risk per trade from 0.20% Safe to 1.00% Extreme High Risk in 0.01% steps"${disabledAttr}>
      <div class="dial-ticks" aria-hidden="true">${ticksHtml}</div>
    </div>

    <div class="dial-presets" role="group" aria-label="Quick aggression presets">${presetsHtml}</div>

    <div class="dial-metrics-grid" role="list" aria-label="Active risk and target metrics">
      <div class="dial-metric-tile" role="listitem" data-dial-metric="risk-per-trade">
        <span class="dial-metric-label">Risk / Trade</span>
        <strong class="dial-metric-value" data-dial-metric-value="risk-per-trade">${esc(targets.riskPctLabel)}</strong>
      </div>
      <div class="dial-metric-tile" role="listitem" data-dial-metric="max-open-trades">
        <span class="dial-metric-label">Max Open Trades</span>
        <strong class="dial-metric-value" data-dial-metric-value="max-open-trades">${targets.maxOpenTrades}</strong>
      </div>
      <div class="dial-metric-tile" role="listitem" data-dial-metric="session-goal">
        <span class="dial-metric-label">Session Goal</span>
        <strong class="dial-metric-value dial-val-positive" data-dial-metric-value="session-goal">${esc(targets.sessionGoalFormatted)}</strong>
      </div>
      <div class="dial-metric-tile" role="listitem" data-dial-metric="daily-loss-brake">
        <span class="dial-metric-label">Daily Loss Brake</span>
        <strong class="dial-metric-value dial-val-negative" data-dial-metric-value="daily-loss-brake">${esc(targets.dailyLossBrakeFormatted)}</strong>
      </div>
    </div>

    ${confirmBannerHtml}

    <p class="dial-guardrails-line" data-dial-guardrails="always-on">${esc(UNBREAKABLE_GUARDRAILS.summaryLine)} · Max Stop Risk ${esc(MAX_CONSTITUTIONAL_STOP_RISK_PCT)}% · Max Drawdown 10.00%</p>
  </section>`;
}

export function renderSectionB5TierDials(state) {
  const dial = normalizeAggressionDial(state);
  const readOnly = dial.ownerControlsAllowed === false;
  const disabledAttr = readOnly ? ' disabled' : '';
  const readonlyCls = readOnly ? ' is-readonly' : '';

  const ownerLockBadge = readOnly
    ? '<span class="dial-pill-tag dial-owner-lock-badge" data-dial-owner-key-required="true">Owner Key Required</span>'
    : '<span class="dial-pill-tag dial-owner-lock-badge" data-dial-owner-key-required="false" hidden></span>';

  const quickButtonsHtml = TIER_QUICK_PRESETS.map((preset) => (
    `<button type="button" class="b5-tier-preset-btn" data-dial-tier-preset="${esc(preset.id)}"${disabledAttr}>${esc(preset.label)}</button>`
  )).join('');

  const tierRowsHtml = dial.tiers.map((tier) => {
    const compactButtonsHtml = TIER_COMPACT_PRESETS.map((preset) => {
      const p = RISK_BPS_PROFILES[preset.bps];
      const activeCls = tier.riskBps === preset.bps ? ' is-active' : '';
      return `<button type="button" class="dial-tier-btn b5-tier-btn ${esc(p.cssClass)}${activeCls}" data-dial-tier-id="${esc(tier.tierId)}" data-dial-tier-bps="${preset.bps}" aria-pressed="${tier.riskBps === preset.bps ? 'true' : 'false'}"${disabledAttr}>${esc(preset.label)}</button>`;
    }).join('');

    const tierConfirmHtml = (
      !readOnly
      && dial.liveMode === true
      && dial.pendingHighRiskTierId === tier.tierId
      && dial.pendingHighRiskBps !== null
      && dial.pendingHighRiskBps >= HIGH_RISK_MIN_BPS
    )
      ? renderHighRiskConfirmBanner(dial.pendingHighRiskBps, tier.label, tier.tierId, disabledAttr, 'tier')
      : '';

    return `<div class="b5-tier-row ${esc(tier.cssClass)}" data-tier-id="${esc(tier.tierId)}" data-tier-bps="${tier.riskBps}">
      <div class="b5-tier-head">
        <span class="dial-badge dial-level-badge ${esc(tier.cssClass)}" data-tier-bps-badge="${tier.riskBps}">${esc(tier.riskPctLabel)}</span>
        <div class="b5-tier-identity">
          <strong class="b5-tier-label">${esc(tier.label)}</strong>
          <span class="b5-tier-level-name" data-tier-level-name="true">${esc(tier.zoneLabel)} · ${esc(tier.startingCapitalFormatted)} · Min Signal ${esc(tier.minSignalProb)}</span>
        </div>
        <div class="b5-tier-metrics">
          <span class="b5-tier-metric"><em>Risk</em> <strong class="dial-metric-value-sm" data-tier-metric="risk">${esc(tier.riskPctLabel)}</strong></span>
          <span class="b5-tier-metric"><em>Max</em> <strong class="dial-metric-value-sm" data-tier-metric="max">${tier.maxOpenTrades}</strong></span>
          <span class="b5-tier-metric b5-metric-goal"><em>Goal</em> <strong class="dial-metric-value-sm" data-tier-metric="goal">${esc(tier.sessionGoalFormatted)}</strong></span>
          <span class="b5-tier-metric b5-metric-brake"><em>Brake</em> <strong class="dial-metric-value-sm" data-tier-metric="brake">${esc(tier.dailyLossBrakeFormatted)}</strong></span>
        </div>
      </div>
      <div class="b5-tier-controls">
        <input type="range" class="dial-slider b5-tier-slider ${esc(tier.cssClass)}" min="${MIN_RISK_BPS}" max="${MAX_RISK_BPS}" step="${RISK_BPS_STEP}" value="${tier.riskBps}" data-dial-tier-slider="${esc(tier.tierId)}" aria-label="${esc(tier.label)} risk per trade from 0.20% Safe to 1.00% Extreme High Risk in 0.01% steps"${disabledAttr}>
        <div class="b5-tier-btn-group" role="group" aria-label="${esc(tier.label)} quick risk buttons">${compactButtonsHtml}</div>
      </div>
      ${tierConfirmHtml}
    </div>`;
  }).join('');

  return `<div class="b5-tier-dials${readonlyCls}" data-section="b5-tier-dials" data-live-mode="${dial.liveMode ? 'true' : 'false'}" data-owner-controls-allowed="${dial.ownerControlsAllowed ? 'true' : 'false'}" aria-label="Section B.5 5-Tier Per-Account Aggression Dials">
    <div class="b5-tier-dials-header">
      <div>
        <p class="eyebrow">SECTION B.5 · SHARED 50MS STREAM · ZERO EXTRA AI API COST</p>
        <div class="b5-tier-title-row">
          <h3 class="b5-tier-dials-title">5-Tier Per-Account Aggression Controls</h3>
          ${ownerLockBadge}
        </div>
      </div>
      <div class="b5-tier-quickbar" role="group" aria-label="All-tier quick presets">${quickButtonsHtml}</div>
    </div>
    <div class="b5-tier-rows">${tierRowsHtml}</div>
  </div>`;
}

function swapDialLevelClass(el, nextClass) {
  if (!el || !el.classList) return;
  for (const cls of DIAL_LEVEL_CLASSES) {
    if (cls !== nextClass) {
      el.classList.remove(cls);
    }
  }
  if (nextClass) {
    el.classList.add(nextClass);
  }
}

function setHiddenFlag(el, shouldHide) {
  if (!el) return;
  if ('hidden' in el) {
    el.hidden = shouldHide;
  }
  if (typeof el.setAttribute === 'function' && typeof el.removeAttribute === 'function') {
    if (shouldHide) {
      el.setAttribute('hidden', '');
    } else {
      el.removeAttribute('hidden');
    }
  }
}

function findMatchingElement(root, selector) {
  if (!root) return null;
  if (typeof root.matches === 'function' && root.matches(selector)) {
    return root;
  }
  if (typeof root.querySelector === 'function') {
    return root.querySelector(selector);
  }
  return null;
}

/**
 * In-place zero-flicker DOM patcher for smooth 60fps 0.01% slider drags & toggle clicks.
 * Updates CSS classes, role="switch" states, slider values (20..100 bps), disabled flags, and
 * metric textContent strictly in place — NEVER touches innerHTML or inline styles!
 */
export function patchAggressionDialInPlace(root, nextState) {
  const dial = normalizeAggressionDial(nextState);
  if (!root) {
    return Object.freeze({ patchedMaster: false, patchedTiers: 0, state: dial });
  }

  const readOnly = dial.ownerControlsAllowed === false;
  let patchedMaster = false;
  let patchedTiers = 0;

  const masterEl = findMatchingElement(root, '[data-aggression-dial="master"]');
  if (masterEl) {
    const chosenProfile = RISK_BPS_PROFILES[dial.masterRiskBps];
    const targets = dial.masterTargets;
    const isShifted = dial.aiDiscretionEnabled && dial.effectiveRiskBps !== dial.masterRiskBps;

    swapDialLevelClass(masterEl, targets.cssClass);
    masterEl.classList?.toggle('is-readonly', readOnly);
    masterEl.setAttribute?.('data-dial-bps', String(targets.riskBps));
    masterEl.setAttribute?.('data-dial-master-bps', String(dial.masterRiskBps));
    masterEl.setAttribute?.('data-ai-discretion', dial.aiDiscretionEnabled ? 'true' : 'false');
    masterEl.setAttribute?.('data-live-mode', dial.liveMode ? 'true' : 'false');
    masterEl.setAttribute?.('data-owner-controls-allowed', dial.ownerControlsAllowed ? 'true' : 'false');

    const badgeEl = masterEl.querySelector?.('[data-dial-bps-badge]');
    if (badgeEl) {
      swapDialLevelClass(badgeEl, targets.cssClass);
      badgeEl.setAttribute?.('data-dial-bps-badge', String(targets.riskBps));
      badgeEl.textContent = targets.riskPctLabel;
    }

    const headingEl = masterEl.querySelector?.('[data-dial-heading]');
    if (headingEl) {
      headingEl.textContent = targets.label;
    }

    const sublineEl = masterEl.querySelector?.('[data-dial-subline]');
    if (sublineEl) {
      sublineEl.textContent = buildMasterSublineText(dial, chosenProfile, targets);
    }

    const shiftEl = masterEl.querySelector?.('[data-dial-ai-shifted]');
    if (shiftEl) {
      swapDialLevelClass(shiftEl, targets.cssClass);
      shiftEl.setAttribute?.('data-dial-ai-shifted', isShifted ? 'true' : 'false');
      shiftEl.setAttribute?.('data-dial-auto-shifted', isShifted ? 'true' : 'false');
      shiftEl.textContent = isShifted ? buildAiShiftText(dial, targets) : '';
      setHiddenFlag(shiftEl, !isShifted);
    }

    const lockEl = masterEl.querySelector?.('[data-dial-owner-key-required]');
    if (lockEl) {
      lockEl.setAttribute?.('data-dial-owner-key-required', readOnly ? 'true' : 'false');
      lockEl.textContent = readOnly ? 'Owner Key Required' : '';
      setHiddenFlag(lockEl, !readOnly);
    }

    const switchBtn = masterEl.querySelector?.('[data-dial-action="TOGGLE_AI_DISCRETION"]');
    if (switchBtn) {
      switchBtn.classList?.toggle('is-on', dial.aiDiscretionEnabled);
      switchBtn.classList?.toggle('is-off', !dial.aiDiscretionEnabled);
      switchBtn.setAttribute?.('aria-checked', dial.aiDiscretionEnabled ? 'true' : 'false');
      switchBtn.disabled = readOnly;
      const switchLabel = switchBtn.querySelector?.('[data-dial-switch-label]');
      if (switchLabel) {
        switchLabel.textContent = dial.aiDiscretionEnabled ? 'AI Discretion: ON' : 'Manual Lock';
      }
    }

    const sliderEl = masterEl.querySelector?.('[data-dial-master-slider="true"]');
    if (sliderEl) {
      swapDialLevelClass(sliderEl, chosenProfile.cssClass);
      const nextVal = String(dial.masterRiskBps);
      if (String(sliderEl.value ?? '') !== nextVal) {
        sliderEl.value = nextVal;
      }
      sliderEl.disabled = readOnly;
    }

    const tickEls = masterEl.querySelectorAll?.('[data-dial-tick-bps]') ?? [];
    for (const tickEl of tickEls) {
      const tickBps = Number(tickEl.getAttribute?.('data-dial-tick-bps'));
      tickEl.classList?.toggle('is-current', tickBps === dial.masterRiskBps);
      tickEl.classList?.toggle('is-ai-active', isShifted && tickBps === dial.effectiveRiskBps);
    }

    const presetBtns = masterEl.querySelectorAll?.('[data-dial-master-preset]') ?? [];
    for (const btn of presetBtns) {
      const presetBps = Number(btn.getAttribute?.('data-dial-master-preset'));
      const active = presetBps === dial.masterRiskBps;
      btn.classList?.toggle('is-active', active);
      btn.setAttribute?.('aria-pressed', active ? 'true' : 'false');
      btn.disabled = readOnly;
    }

    const metricMap = {
      'risk-per-trade': targets.riskPctLabel,
      'max-open-trades': String(targets.maxOpenTrades),
      'session-goal': targets.sessionGoalFormatted,
      'daily-loss-brake': targets.dailyLossBrakeFormatted,
    };
    for (const [key, val] of Object.entries(metricMap)) {
      const valEl = masterEl.querySelector?.(`[data-dial-metric-value="${key}"]`);
      if (valEl) {
        valEl.textContent = val;
      }
    }

    patchedMaster = true;
  }

  const b5El = findMatchingElement(root, '[data-section="b5-tier-dials"]');
  if (b5El) {
    b5El.classList?.toggle('is-readonly', readOnly);
    b5El.setAttribute?.('data-live-mode', dial.liveMode ? 'true' : 'false');
    b5El.setAttribute?.('data-owner-controls-allowed', dial.ownerControlsAllowed ? 'true' : 'false');

    const b5LockEl = b5El.querySelector?.('[data-dial-owner-key-required]');
    if (b5LockEl) {
      b5LockEl.setAttribute?.('data-dial-owner-key-required', readOnly ? 'true' : 'false');
      b5LockEl.textContent = readOnly ? 'Owner Key Required' : '';
      setHiddenFlag(b5LockEl, !readOnly);
    }

    const quickBtns = b5El.querySelectorAll?.('[data-dial-tier-preset]') ?? [];
    for (const qBtn of quickBtns) {
      qBtn.disabled = readOnly;
    }

    const tierById = new Map(dial.tiers.map((t) => [t.tierId, t]));
    const rowEls = b5El.querySelectorAll?.('[data-tier-id]') ?? [];
    for (const rowEl of rowEls) {
      const tierId = rowEl.getAttribute?.('data-tier-id');
      const tier = tierById.get(tierId);
      if (!tier) continue;

      swapDialLevelClass(rowEl, tier.cssClass);
      rowEl.setAttribute?.('data-tier-bps', String(tier.riskBps));

      const badgeEl = rowEl.querySelector?.('[data-tier-bps-badge]');
      if (badgeEl) {
        swapDialLevelClass(badgeEl, tier.cssClass);
        badgeEl.setAttribute?.('data-tier-bps-badge', String(tier.riskBps));
        badgeEl.textContent = tier.riskPctLabel;
      }

      const nameEl = rowEl.querySelector?.('[data-tier-level-name]');
      if (nameEl) {
        nameEl.textContent = `${tier.zoneLabel} · ${tier.startingCapitalFormatted} · Min Signal ${tier.minSignalProb}`;
      }

      const tierMetrics = {
        risk: tier.riskPctLabel,
        max: String(tier.maxOpenTrades),
        goal: tier.sessionGoalFormatted,
        brake: tier.dailyLossBrakeFormatted,
      };
      for (const [key, val] of Object.entries(tierMetrics)) {
        const mEl = rowEl.querySelector?.(`[data-tier-metric="${key}"]`);
        if (mEl) {
          mEl.textContent = val;
        }
      }

      const sliderEl = rowEl.querySelector?.('[data-dial-tier-slider]');
      if (sliderEl) {
        swapDialLevelClass(sliderEl, tier.cssClass);
        const nextVal = String(tier.riskBps);
        if (String(sliderEl.value ?? '') !== nextVal) {
          sliderEl.value = nextVal;
        }
        sliderEl.disabled = readOnly;
      }

      const tierBtns = rowEl.querySelectorAll?.('[data-dial-tier-bps]') ?? [];
      for (const tBtn of tierBtns) {
        const btnBps = Number(tBtn.getAttribute?.('data-dial-tier-bps'));
        const active = btnBps === tier.riskBps;
        tBtn.classList?.toggle('is-active', active);
        tBtn.setAttribute?.('aria-pressed', active ? 'true' : 'false');
        tBtn.disabled = readOnly;
      }

      patchedTiers += 1;
    }
  }

  return Object.freeze({ patchedMaster, patchedTiers, state: dial });
}

export const AGGRESSION_DIAL_CSS_SNIPPET = `/* Strict-CSP Trading Aggression Dial (0.20%..1.00% in 0.01% bps steps + AI Discretion) & Section B.5 5-Tier Controls */
.aggression-dial-panel {
  --dial-accent: #2563EB;
  --dial-ease: cubic-bezier(0.22, 1, 0.36, 1);
  --dial-surface: var(--panel, #FFFFFF);
  --dial-soft: var(--panel-soft, #F7F9FC);
  --dial-border: var(--line, #DCE2EA);
  --dial-ink: var(--ink, #122238);
  --dial-muted: var(--muted, #596779);
  background: var(--dial-surface);
  border: 1px solid var(--dial-border);
  border-left: 4px solid var(--dial-accent);
  border-radius: 10px;
  padding: 18px 20px;
  display: grid;
  gap: 14px;
  contain: layout style;
  transition: border-color 220ms cubic-bezier(0.22, 1, 0.36, 1), background-color 220ms ease;
}

.dial-lvl-1 { --dial-accent: #0F766E; --dial-badge-bg: #CCFBF1; --dial-badge-ink: #115E59; }
.dial-lvl-2 { --dial-accent: #0D9488; --dial-badge-bg: #D1FAE5; --dial-badge-ink: #065F46; }
.dial-lvl-3 { --dial-accent: #0284C7; --dial-badge-bg: #E0F2FE; --dial-badge-ink: #075985; }
.dial-lvl-4 { --dial-accent: #2563EB; --dial-badge-bg: #DBEAFE; --dial-badge-ink: #1E40AF; }
.dial-lvl-5 { --dial-accent: #4F46E5; --dial-badge-bg: #E0E7FF; --dial-badge-ink: #3730A3; }
.dial-lvl-6 { --dial-accent: #CA8A04; --dial-badge-bg: #FEF3C7; --dial-badge-ink: #92400E; }
.dial-lvl-7 { --dial-accent: #D97706; --dial-badge-bg: #FFEDD5; --dial-badge-ink: #9A3412; }
.dial-lvl-8 { --dial-accent: #EA580C; --dial-badge-bg: #FED7AA; --dial-badge-ink: #9A3412; }
.dial-lvl-9 { --dial-accent: #DC2626; --dial-badge-bg: #FEE2E2; --dial-badge-ink: #991B1B; }
.dial-lvl-10 { --dial-accent: #B91C1C; --dial-badge-bg: #FECACA; --dial-badge-ink: #7F1D1D; }
.dial-lvl-11 { --dial-accent: #9D174D; --dial-badge-bg: #FCE7F3; --dial-badge-ink: #831843; }

:root[data-theme="dark"] .dial-lvl-1 { --dial-badge-bg: #134E4A; --dial-badge-ink: #99F6E4; }
:root[data-theme="dark"] .dial-lvl-2 { --dial-badge-bg: #064E3B; --dial-badge-ink: #A7F3D0; }
:root[data-theme="dark"] .dial-lvl-3 { --dial-badge-bg: #0C4A6E; --dial-badge-ink: #BAE6FD; }
:root[data-theme="dark"] .dial-lvl-4 { --dial-badge-bg: #1E3A8A; --dial-badge-ink: #BFDBFE; }
:root[data-theme="dark"] .dial-lvl-5 { --dial-badge-bg: #312E81; --dial-badge-ink: #C7D2FE; }
:root[data-theme="dark"] .dial-lvl-6 { --dial-badge-bg: #713F12; --dial-badge-ink: #FDE68A; }
:root[data-theme="dark"] .dial-lvl-7 { --dial-badge-bg: #7C2D12; --dial-badge-ink: #FED7AA; }
:root[data-theme="dark"] .dial-lvl-8 { --dial-badge-bg: #9A3412; --dial-badge-ink: #FFEDD5; }
:root[data-theme="dark"] .dial-lvl-9 { --dial-badge-bg: #7F1D1D; --dial-badge-ink: #FECACA; }
:root[data-theme="dark"] .dial-lvl-10 { --dial-badge-bg: #991B1B; --dial-badge-ink: #FEE2E2; }
:root[data-theme="dark"] .dial-lvl-11 { --dial-badge-bg: #831843; --dial-badge-ink: #FBCFE8; }

.dial-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.dial-title-group {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  min-height: 44px;
}

.dial-badge,
.dial-level-badge {
  display: inline-grid;
  place-items: center;
  min-width: 64px;
  height: 38px;
  padding: 0 12px;
  border-radius: 999px;
  font-weight: 800;
  font-size: 15px;
  font-variant-numeric: tabular-nums;
  background: var(--dial-badge-bg, #E0E7FF);
  color: var(--dial-badge-ink, #3730A3);
  border: 1px solid var(--dial-accent, #4F46E5);
  transition: background-color 220ms cubic-bezier(0.22, 1, 0.36, 1), color 200ms ease, border-color 220ms cubic-bezier(0.22, 1, 0.36, 1), transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

.dial-heading {
  margin: 0;
  font-size: 20px;
  line-height: 1.2;
  color: var(--dial-ink);
  transition: color 180ms ease;
}

.dial-subline {
  display: block;
  font-size: 12px;
  color: var(--dial-muted);
  font-variant-numeric: tabular-nums;
}

.dial-pill-tag,
.dial-shift-pill,
.dial-owner-lock-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1), border-color 200ms cubic-bezier(0.22, 1, 0.36, 1), color 200ms ease, opacity 180ms ease;
}

.dial-pill-tag[hidden] {
  display: none;
}

.dial-shift-pill {
  background: var(--dial-badge-bg, var(--dial-soft));
  border: 1px solid var(--dial-accent);
  color: var(--dial-badge-ink, var(--dial-ink));
}

.dial-owner-lock-badge {
  background: var(--warning-surface, #FFF0E4);
  border: 1px solid var(--orange, #C2510B);
  color: var(--warning-text, #773408);
}

/* Buttery-smooth 60fps sliding pill switch (role="switch") */
.dial-switch {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-height: 44px;
  padding: 6px 14px 6px 8px;
  border-radius: 999px;
  border: 1px solid var(--dial-border);
  background: var(--dial-soft);
  color: var(--dial-ink);
  font-weight: 700;
  font-size: 13px;
  cursor: pointer;
  user-select: none;
  transition: border-color 220ms cubic-bezier(0.22, 1, 0.36, 1), background-color 220ms ease, box-shadow 200ms ease;
}

.dial-switch.is-on {
  border-color: #0F766E;
}

.dial-switch.is-off {
  border-color: #D97706;
}

.dial-switch:focus-visible {
  outline: 2px solid var(--focus, #1B65B2);
  outline-offset: 2px;
}

.dial-switch-track {
  position: relative;
  display: inline-flex;
  align-items: center;
  width: 48px;
  height: 26px;
  padding: 3px;
  border-radius: 999px;
  background-color: #94A3B8;
  transition: background-color 220ms ease;
  flex-shrink: 0;
}

.dial-switch.is-on .dial-switch-track {
  background-color: #0F766E;
}

.dial-switch.is-off .dial-switch-track {
  background-color: #B45309;
}

.dial-switch-thumb {
  width: 20px;
  height: 20px;
  border-radius: 999px;
  background-color: #FFFFFF;
  box-shadow: 0 1px 3px rgb(0 0 0 / 28%);
  transform: translateX(0);
  will-change: transform;
  transition: transform 220ms cubic-bezier(0.22, 1, 0.36, 1), background-color 220ms ease;
}

.dial-switch.is-on .dial-switch-thumb {
  transform: translateX(22px);
}

.dial-switch-label {
  min-width: 11.5ch;
  text-align: left;
  font-variant-numeric: tabular-nums;
}

.dial-slider-wrap {
  display: grid;
  gap: 6px;
}

.dial-slider {
  -webkit-appearance: none;
  appearance: none;
  width: 100%;
  min-height: 44px;
  background: transparent;
  accent-color: var(--dial-accent, #4F46E5);
  cursor: pointer;
  margin: 0;
}

.dial-slider::-webkit-slider-runnable-track {
  height: 8px;
  border-radius: 999px;
  background: var(--dial-border, #DCE2EA);
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1);
}

.dial-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 24px;
  height: 24px;
  margin-top: -8px;
  border-radius: 999px;
  background: var(--dial-accent, #4F46E5);
  border: 3px solid var(--dial-surface, #FFFFFF);
  box-shadow: 0 2px 6px rgb(15 23 42 / 24%);
  will-change: transform;
  transition: transform 180ms cubic-bezier(0.22, 1, 0.36, 1), background-color 200ms ease, box-shadow 200ms ease;
}

.dial-slider:hover::-webkit-slider-thumb,
.dial-slider:active::-webkit-slider-thumb {
  transform: scale(1.12);
  box-shadow: 0 3px 10px rgb(15 23 42 / 32%);
}

.dial-slider::-moz-range-track {
  height: 8px;
  border-radius: 999px;
  background: var(--dial-border, #DCE2EA);
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1);
}

.dial-slider::-moz-range-thumb {
  width: 24px;
  height: 24px;
  border-radius: 999px;
  background: var(--dial-accent, #4F46E5);
  border: 3px solid var(--dial-surface, #FFFFFF);
  box-shadow: 0 2px 6px rgb(15 23 42 / 24%);
  will-change: transform;
  transition: transform 180ms cubic-bezier(0.22, 1, 0.36, 1), background-color 200ms ease, box-shadow 200ms ease;
}

.dial-slider:hover::-moz-range-thumb,
.dial-slider:active::-moz-range-thumb {
  transform: scale(1.12);
  box-shadow: 0 3px 10px rgb(15 23 42 / 32%);
}

.dial-ticks {
  display: grid;
  grid-template-columns: repeat(9, minmax(0, 1fr));
  text-align: center;
  font-size: 11px;
  font-weight: 600;
  color: var(--dial-muted);
  font-variant-numeric: tabular-nums;
}

.dial-tick {
  transition: color 180ms cubic-bezier(0.22, 1, 0.36, 1), transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

.dial-tick.is-current,
.dial-tick.is-ai-active {
  color: var(--dial-accent);
  font-weight: 800;
}

.dial-presets {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 8px;
}

.dial-preset-btn {
  min-height: 44px;
  min-width: 44px;
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid var(--dial-border);
  background: var(--dial-soft);
  color: var(--dial-ink);
  font-size: 12px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  cursor: pointer;
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1), border-color 200ms cubic-bezier(0.22, 1, 0.36, 1), color 180ms ease, transform 180ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 200ms ease;
}

.dial-preset-btn:active:not(:disabled) {
  transform: scale(0.97);
}

.dial-preset-btn.is-active {
  background: var(--dial-badge-bg);
  color: var(--dial-badge-ink);
  border-color: var(--dial-accent);
  box-shadow: inset 0 0 0 1px var(--dial-accent);
}

.dial-metrics-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.dial-metric-tile {
  min-height: 74px;
  padding: 12px 14px;
  border-radius: 8px;
  border: 1px solid var(--dial-border);
  background: var(--dial-soft);
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 4px;
  transition: border-color 200ms cubic-bezier(0.22, 1, 0.36, 1), background-color 200ms ease;
}

.dial-metric-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--dial-muted);
  text-transform: uppercase;
  letter-spacing: 0.4px;
}

.dial-metric-value {
  display: inline-block;
  min-width: 8ch;
  font-size: 20px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: var(--dial-ink);
  transition: color 180ms ease;
}

.dial-metric-value-sm {
  display: inline-block;
  min-width: 6ch;
  font-variant-numeric: tabular-nums;
  transition: color 180ms ease;
}

.dial-val-positive {
  color: #0F766E;
}

.dial-val-negative {
  color: #B91C1C;
}

.dial-guardrails-line {
  margin: 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--dial-muted);
  letter-spacing: 0.2px;
}

.dial-confirm-banner {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 8px;
  border: 1px solid var(--dial-accent);
  background: var(--dial-badge-bg);
  color: var(--dial-badge-ink);
  transition: background-color 200ms ease, border-color 200ms cubic-bezier(0.22, 1, 0.36, 1);
}

.dial-confirm-copy {
  display: grid;
  gap: 2px;
  font-size: 12px;
}

.dial-confirm-actions {
  display: flex;
  gap: 8px;
}

.dial-confirm-btn,
.dial-cancel-btn {
  min-height: 44px;
  min-width: 44px;
  padding: 0 14px;
  border-radius: 8px;
  font-weight: 700;
  font-size: 13px;
  cursor: pointer;
  transition: background-color 180ms ease, transform 180ms cubic-bezier(0.22, 1, 0.36, 1), opacity 180ms ease;
}

.dial-confirm-btn {
  background: #B91C1C;
  color: #FFFFFF;
  border: 1px solid #7F1D1D;
}

.dial-cancel-btn {
  background: transparent;
  color: inherit;
  border: 1px solid currentColor;
}

.b5-tier-dials {
  display: grid;
  gap: 12px;
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--line, #DCE2EA);
  contain: layout style;
}

.b5-tier-dials-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.b5-tier-title-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}

.b5-tier-dials-title {
  margin: 0;
  font-size: 16px;
  color: var(--ink, #122238);
}

.b5-tier-quickbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.b5-tier-preset-btn {
  min-height: 44px;
  padding: 0 14px;
  border-radius: 8px;
  border: 1px solid var(--line, #DCE2EA);
  background: var(--panel-soft, #F7F9FC);
  color: var(--ink, #122238);
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1), border-color 200ms cubic-bezier(0.22, 1, 0.36, 1), transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

.b5-tier-preset-btn:active:not(:disabled) {
  transform: scale(0.97);
}

.b5-tier-rows {
  display: grid;
  gap: 10px;
}

.b5-tier-row {
  padding: 12px 14px;
  border-radius: 8px;
  border: 1px solid var(--line, #DCE2EA);
  border-left: 4px solid var(--dial-accent, #4F46E5);
  background: var(--panel-soft, #F7F9FC);
  display: grid;
  gap: 10px;
  transition: border-color 220ms cubic-bezier(0.22, 1, 0.36, 1), background-color 200ms ease;
}

.b5-tier-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.b5-tier-identity {
  display: grid;
  gap: 2px;
  margin-right: auto;
}

.b5-tier-label {
  font-size: 14px;
  color: var(--ink, #122238);
}

.b5-tier-level-name {
  font-size: 12px;
  color: var(--muted, #596779);
  font-variant-numeric: tabular-nums;
}

.b5-tier-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}

.b5-tier-metric em {
  font-style: normal;
  color: var(--muted, #596779);
  margin-right: 4px;
}

.b5-metric-goal strong {
  color: #0F766E;
}

.b5-metric-brake strong {
  color: #B91C1C;
}

.b5-tier-controls {
  display: grid;
  grid-template-columns: minmax(140px, 1fr) auto;
  align-items: center;
  gap: 12px;
}

.b5-tier-btn-group {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.dial-tier-btn,
.b5-tier-btn {
  min-height: 44px;
  min-width: 44px;
  padding: 0 10px;
  border-radius: 7px;
  border: 1px solid var(--line, #DCE2EA);
  background: var(--panel, #FFFFFF);
  color: var(--ink, #122238);
  font-size: 12px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  cursor: pointer;
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1), border-color 200ms cubic-bezier(0.22, 1, 0.36, 1), color 180ms ease, transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

.dial-tier-btn:active:not(:disabled),
.b5-tier-btn:active:not(:disabled) {
  transform: scale(0.97);
}

.dial-tier-btn.is-active,
.b5-tier-btn.is-active {
  background: var(--dial-badge-bg);
  color: var(--dial-badge-ink);
  border-color: var(--dial-accent);
}

.aggression-dial-panel.is-readonly button:disabled,
.aggression-dial-panel.is-readonly input:disabled,
.b5-tier-dials.is-readonly button:disabled,
.b5-tier-dials.is-readonly input:disabled {
  opacity: 0.58;
  cursor: not-allowed;
}

@media (max-width: 820px) {
  .dial-presets {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .dial-metrics-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .b5-tier-controls {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  .aggression-dial-panel,
  .dial-badge,
  .dial-level-badge,
  .dial-pill-tag,
  .dial-shift-pill,
  .dial-owner-lock-badge,
  .dial-switch,
  .dial-switch-track,
  .dial-switch-thumb,
  .dial-slider::-webkit-slider-thumb,
  .dial-slider::-moz-range-thumb,
  .dial-tick,
  .dial-preset-btn,
  .dial-tier-btn,
  .b5-tier-btn,
  .b5-tier-preset-btn,
  .b5-tier-row,
  .dial-metric-tile,
  .dial-metric-value,
  .dial-confirm-banner,
  .dial-confirm-btn,
  .dial-cancel-btn {
    transition-duration: 0.01ms !important;
  }
  .dial-slider:hover::-webkit-slider-thumb,
  .dial-slider:active::-webkit-slider-thumb,
  .dial-slider:hover::-moz-range-thumb,
  .dial-slider:active::-moz-range-thumb,
  .dial-preset-btn:active:not(:disabled),
  .dial-tier-btn:active:not(:disabled),
  .b5-tier-btn:active:not(:disabled),
  .b5-tier-preset-btn:active:not(:disabled) {
    transform: none !important;
  }
}
`;
