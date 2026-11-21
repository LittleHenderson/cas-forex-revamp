// Strict-CSP, 60fps Compounding Mode, House-Money Milestone & Live News Shield UI Module.
// Zero inline style attributes, zero eval/Function, zero float money arithmetic, XSS-safe escaping.

export const COMPOUNDING_PANEL_SCHEMA = 'cas-forex.compounding-controller/1';

export const COMPOUNDING_MODES = Object.freeze([
  'FULL_COMPOUND_100',
  'BALANCED_SPLIT_50_50',
  'CUSTOM_SPLIT',
]);

export const HOUSE_MONEY_STATUSES = Object.freeze([
  'BUILDING_TOWARD_PRINCIPAL',
  'COMPOUNDING_TO_DOUBLE',
  'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL',
  'PLAYING_ON_HOUSE_MONEY',
]);

export const COMPOUNDING_BROKERS = Object.freeze([
  "Hugo's Way",
  'LHFX',
  'OANDA',
]);

const DECIMAL_RE = /^[+-]?[0-9]+(?:\.[0-9]+)?$/;

const PCT_BUCKET_STEPS = Object.freeze([
  0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50,
  55, 60, 65, 70, 75, 80, 85, 90, 95, 100,
]);

const PCT_BUCKET_CLASSES = Object.freeze(
  PCT_BUCKET_STEPS.map((step) => `compound-pct-${step}`)
);

const STATUS_SLUG_MAP = Object.freeze({
  BUILDING_TOWARD_PRINCIPAL: 'recovery',
  COMPOUNDING_TO_DOUBLE: 'compounding',
  HOUSE_MONEY_READY_TO_PULL_PRINCIPAL: 'ready',
  PLAYING_ON_HOUSE_MONEY: 'house-money',
});

const STATUS_CLASS_TOKENS = Object.freeze(
  Object.values(STATUS_SLUG_MAP).map((slug) => `is-status-${slug}`)
);

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

function cleanText(raw, maxLen = 160) {
  if (typeof raw !== 'string') return '';
  const stripped = raw.replace(/[\u0000-\u001F\u007F]/g, ' ').trim();
  return stripped.length > maxLen ? stripped.slice(0, maxLen) : stripped;
}

function parseDecimalParts(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!DECIMAL_RE.test(trimmed)) return null;
  const neg = trimmed.startsWith('-');
  const unsigned = (neg || trimmed.startsWith('+')) ? trimmed.slice(1) : trimmed;
  const [rawInt, rawFrac = ''] = unsigned.split('.');
  const intPart = rawInt.replace(/^0+(?=\d)/, '') || '0';
  const isZero = intPart === '0' && /^0*$/.test(rawFrac);
  return { neg: neg && !isZero, intPart, fracPart: rawFrac };
}

export function normalizeDecimalString(raw, fallback = '0.00', minFracDigits = 2) {
  const candidate = typeof raw === 'string'
    ? raw
    : (typeof raw === 'number' && Number.isFinite(raw) ? raw.toFixed(minFracDigits) : '');
  const parts = parseDecimalParts(candidate) ?? parseDecimalParts(fallback) ?? { neg: false, intPart: '0', fracPart: '' };
  const frac = parts.fracPart.length >= minFracDigits
    ? parts.fracPart
    : parts.fracPart.padEnd(minFracDigits, '0');
  const sign = parts.neg ? '-' : '';
  return frac.length > 0 ? `${sign}${parts.intPart}.${frac}` : `${sign}${parts.intPart}`;
}

function toScaledBigInt(decStr, scale) {
  const p = parseDecimalParts(decStr) ?? { neg: false, intPart: '0', fracPart: '' };
  const frac = p.fracPart.length >= scale
    ? p.fracPart.slice(0, scale)
    : p.fracPart.padEnd(scale, '0');
  const mag = BigInt(p.intPart + frac);
  return p.neg ? -mag : mag;
}

function decimalScale(a, b, c = '0') {
  const pa = parseDecimalParts(a);
  const pb = parseDecimalParts(b);
  const pc = parseDecimalParts(c);
  return Math.max(2, pa ? pa.fracPart.length : 0, pb ? pb.fracPart.length : 0, pc ? pc.fracPart.length : 0);
}

export function compareDecimalStrings(a, b) {
  const scale = decimalScale(a, b);
  const av = toScaledBigInt(a, scale);
  const bv = toScaledBigInt(b, scale);
  if (av === bv) return 0;
  return av > bv ? 1 : -1;
}

function formatBigIntScaled(val, scale) {
  const neg = val < 0n;
  const abs = neg ? -val : val;
  const digits = abs.toString().padStart(scale + 1, '0');
  const intPart = digits.slice(0, digits.length - scale) || '0';
  const fracPart = digits.slice(digits.length - scale);
  return `${neg ? '-' : ''}${intPart}.${fracPart}`;
}

export function subtractDecimalStrings(a, b) {
  const scale = decimalScale(a, b);
  const diff = toScaledBigInt(a, scale) - toScaledBigInt(b, scale);
  return formatBigIntScaled(diff, scale);
}

export function multiplyDecimalByInt(decStr, intFactor) {
  const p = parseDecimalParts(decStr) ?? { neg: false, intPart: '0', fracPart: '00' };
  const scale = Math.max(2, p.fracPart.length);
  const scaled = toScaledBigInt(decStr, scale);
  return formatBigIntScaled(scaled * BigInt(intFactor), scale);
}

export function computeHouseMoneyProgressPct(startingPrincipalUsd, currentEquityUsd, houseMoneyTargetUsd) {
  const scale = decimalScale(startingPrincipalUsd, currentEquityUsd, houseMoneyTargetUsd);
  const startVal = toScaledBigInt(startingPrincipalUsd, scale);
  const currVal = toScaledBigInt(currentEquityUsd, scale);
  const targetVal = toScaledBigInt(houseMoneyTargetUsd, scale);
  if (targetVal <= startVal) {
    return currVal >= targetVal ? '100.00' : '0.00';
  }
  if (currVal <= startVal) return '0.00';
  if (currVal >= targetVal) return '100.00';
  const gained = currVal - startVal;
  const span = targetVal - startVal;
  const hundredths = (gained * 10000n) / span;
  const clamped = hundredths < 0n ? 0n : (hundredths > 10000n ? 10000n : hundredths);
  return formatBigIntScaled(clamped, 2);
}

export function computePctBucket(pctStr) {
  const clean = normalizeDecimalString(pctStr, '0.00', 2);
  const scaled = toScaledBigInt(clean, 2);
  if (scaled <= 0n) return 0;
  if (scaled >= 10000n) return 100;
  const bucket = Number(((scaled + 250n) / 500n) * 5n);
  return Math.max(0, Math.min(100, bucket));
}

export function formatExactUsd(raw) {
  const normalized = normalizeDecimalString(raw, '0.00', 2);
  const neg = normalized.startsWith('-');
  const unsigned = neg ? normalized.slice(1) : normalized;
  const [intPart, fracPart = '00'] = unsigned.split('.');
  const withCommas = intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${neg ? '-' : ''}$${withCommas}.${fracPart}`;
}

export function formatExactPct(raw) {
  return `${normalizeDecimalString(raw, '0.00', 2)}%`;
}

export function formatSweepRatioPct(ratioRaw) {
  const normalized = normalizeDecimalString(ratioRaw, '0.00', 2);
  const scale = Math.max(2, (parseDecimalParts(normalized)?.fracPart.length ?? 2));
  const scaled = toScaledBigInt(normalized, scale);
  const pctScaled = scaled * 100n;
  const str = formatBigIntScaled(pctScaled, scale);
  const trimmed = str.replace(/\.0+$/, '').replace(/(\.[0-9]*[1-9])0+$/, '$1');
  return `${trimmed}%`;
}

function normalizePositiveInt(raw, fallback, min = 0, max = 1440) {
  if (typeof raw === 'number' && Number.isInteger(raw) && raw >= min && raw <= max) return raw;
  if (typeof raw === 'string' && /^[0-9]+$/.test(raw.trim())) {
    const parsed = Number.parseInt(raw.trim(), 10);
    if (parsed >= min && parsed <= max) return parsed;
  }
  return fallback;
}

function normalizeSymbolList(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    const s = cleanText(String(item ?? ''), 32);
    if (s && !seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out;
}

function normalizeNewsShield(rawShield) {
  const base = {
    paused: false,
    overallStatus: 'CLEAR',
    blockingTitle: '',
    resumeAtUtc: '',
    affectedSymbols: [],
    preMinutes: 5,
    postMinutes: 5,
    protectiveActionsAlwaysAllowed: true,
    nextUpcomingTitle: '',
    nextUpcomingUtc: '',
  };
  if (!rawShield || typeof rawShield !== 'object' || Array.isArray(rawShield)) {
    return Object.freeze({ ...base, affectedSymbols: Object.freeze([]) });
  }

  const preMinutes = normalizePositiveInt(rawShield.preMinutes ?? rawShield.pre_minutes, 5, 1, 120);
  const postMinutes = normalizePositiveInt(rawShield.postMinutes ?? rawShield.post_minutes, 5, 1, 120);
  const rawOverall = cleanText(String(rawShield.overallStatus ?? rawShield.overall_status ?? ''), 48).toUpperCase();

  let paused = rawShield.paused === true
    || rawOverall === 'PAUSED_NEWS_WINDOW'
    || rawOverall === 'PAUSED_STALE_CALENDAR';
  let blockingTitle = cleanText(String(rawShield.blockingTitle ?? rawShield.blocking_title ?? ''), 120);
  let resumeAtUtc = cleanText(String(rawShield.resumeAtUtc ?? rawShield.resume_at_utc ?? ''), 64);
  let affectedSymbols = normalizeSymbolList(rawShield.affectedSymbols ?? rawShield.affected_symbols);
  let nextUpcomingTitle = cleanText(String(rawShield.nextUpcomingTitle ?? rawShield.next_upcoming_title ?? ''), 120);
  let nextUpcomingUtc = cleanText(String(rawShield.nextUpcomingUtc ?? rawShield.next_upcoming_utc ?? ''), 64);

  // Support native Python NewsShockShield.shield_status_snapshot() shape.
  if (rawShield.symbols && typeof rawShield.symbols === 'object' && !Array.isArray(rawShield.symbols)) {
    const blockedSyms = [];
    for (const [symKey, entry] of Object.entries(rawShield.symbols)) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.new_entries_allowed === false) {
        paused = true;
        const cleanSym = cleanText(String(entry.normalized_symbol ?? symKey), 32);
        if (cleanSym) blockedSyms.push(cleanSym);
        if (!blockingTitle && Array.isArray(entry.active_blocking_events) && entry.active_blocking_events.length > 0) {
          const firstEv = entry.active_blocking_events[0];
          blockingTitle = cleanText(String(firstEv?.title ?? firstEv?.category ?? ''), 120);
        }
        const entryResume = cleanText(String(entry.resume_at_utc ?? ''), 64);
        if (entryResume && (!resumeAtUtc || entryResume > resumeAtUtc)) {
          resumeAtUtc = entryResume;
        }
      }
    }
    if (affectedSymbols.length === 0 && blockedSyms.length > 0) {
      affectedSymbols = normalizeSymbolList(blockedSyms);
    }
  }

  if (!nextUpcomingTitle && Array.isArray(rawShield.upcoming_blackouts) && rawShield.upcoming_blackouts.length > 0) {
    const nextEv = rawShield.upcoming_blackouts[0];
    if (nextEv && typeof nextEv === 'object') {
      nextUpcomingTitle = cleanText(String(nextEv.title ?? nextEv.category ?? ''), 120);
      nextUpcomingUtc = cleanText(String(nextEv.blackout_starts_at_utc ?? nextEv.scheduled_utc ?? ''), 64);
    }
  }

  if (paused && !blockingTitle) {
    blockingTitle = rawOverall === 'PAUSED_STALE_CALENDAR'
      ? 'Economic Calendar Stale'
      : 'High-Impact Economic Release';
  }

  const overallStatus = paused
    ? (rawOverall === 'PAUSED_STALE_CALENDAR' ? 'PAUSED_STALE_CALENDAR' : 'PAUSED_NEWS_WINDOW')
    : 'CLEAR';

  return Object.freeze({
    paused,
    overallStatus,
    blockingTitle,
    resumeAtUtc,
    affectedSymbols: Object.freeze(affectedSymbols),
    preMinutes,
    postMinutes,
    protectiveActionsAlwaysAllowed: true,
    nextUpcomingTitle,
    nextUpcomingUtc,
  });
}

function buildDefaultMilestones(startingPrincipalUsd, currentEquityUsd) {
  const tiers = [
    { multiple: 2, label: '2x House Money' },
    { multiple: 5, label: '5x Accelerator' },
    { multiple: 10, label: '10x Growth' },
    { multiple: 50, label: '50x Institutional Income Tier' },
  ];
  return Object.freeze(tiers.map(({ multiple, label }) => {
    const targetUsd = multiplyDecimalByInt(startingPrincipalUsd, multiple);
    return Object.freeze({
      multiple,
      label,
      targetUsd,
      reached: compareDecimalStrings(currentEquityUsd, targetUsd) >= 0,
    });
  }));
}

function normalizeMilestones(rawMilestones, startingPrincipalUsd, currentEquityUsd) {
  if (!Array.isArray(rawMilestones) || rawMilestones.length === 0) {
    return buildDefaultMilestones(startingPrincipalUsd, currentEquityUsd);
  }
  const out = [];
  for (const item of rawMilestones) {
    if (!item || typeof item !== 'object') continue;
    const label = cleanText(String(item.label ?? item.name ?? ''), 64);
    const targetUsd = normalizeDecimalString(item.targetUsd ?? item.target_usd, '0.00', 2);
    const multiple = normalizePositiveInt(item.multiple, 2, 1, 1000);
    const reached = typeof item.reached === 'boolean'
      ? item.reached
      : compareDecimalStrings(currentEquityUsd, targetUsd) >= 0;
    if (label) {
      out.push(Object.freeze({ multiple, label, targetUsd, reached }));
    }
  }
  return out.length > 0 ? Object.freeze(out) : buildDefaultMilestones(startingPrincipalUsd, currentEquityUsd);
}

export const STATIC_COMPOUNDING_PANEL = Object.freeze({
  schema: COMPOUNDING_PANEL_SCHEMA,
  mode: 'FULL_COMPOUND_100',
  isFullCompound: true,
  startingPrincipalUsd: '5000.00',
  currentEquityUsd: '5000.00',
  compoundingTargetUsd: '10000.00',
  houseMoneyTargetUsd: '10000.00',
  houseMoneyStatus: 'COMPOUNDING_TO_DOUBLE',
  houseMoneyReady: false,
  principalWithdrawnAcknowledged: false,
  principalWithdrawnUsd: '0.00',
  suggestedPrincipalPulloutUsd: '0.00',
  progressToHouseMoneyPct: '0.00',
  progressBucket: 0,
  remainingToHouseMoneyUsd: '5000.00',
  effectiveVaultSweepRatio: '0.00',
  effectiveRetainRatio: '1.00',
  underwater: false,
  autoEnableVaultAtTarget: true,
  postTargetVaultRatio: '0.50',
  auditChainValid: true,
  ownerControlsAllowed: true,
  brokers: COMPOUNDING_BROKERS,
  milestones: buildDefaultMilestones('5000.00', '5000.00'),
  newsShield: Object.freeze({
    paused: false,
    overallStatus: 'CLEAR',
    blockingTitle: '',
    resumeAtUtc: '',
    affectedSymbols: Object.freeze([]),
    preMinutes: 5,
    postMinutes: 5,
    protectiveActionsAlwaysAllowed: true,
    nextUpcomingTitle: '',
    nextUpcomingUtc: '',
  }),
});

function resolveOwnerControlsAllowed(rootDoc, innerDoc) {
  const roleCandidates = [
    rootDoc?.sessionScope,
    rootDoc?.session_scope,
    rootDoc?.deviceRole,
    rootDoc?.device_role,
    innerDoc?.sessionScope,
    innerDoc?.session_scope,
    innerDoc?.deviceRole,
    innerDoc?.device_role,
    rootDoc?.aiTrader?.sessionScope,
    rootDoc?.aiTrader?.deviceRole,
  ];
  for (const rawRole of roleCandidates) {
    if (cleanText(String(rawRole ?? ''), 64).toUpperCase() === 'DEVICE_READ_AND_EXPLAINER') {
      return false;
    }
  }

  const flagCandidates = [
    rootDoc?.ownerControlsAllowed,
    rootDoc?.owner_controls_allowed,
    innerDoc?.ownerControlsAllowed,
    innerDoc?.owner_controls_allowed,
    rootDoc?.aiTrader?.ownerControlsAllowed,
    rootDoc?.aiTrader?.owner_controls_allowed,
  ];
  for (const rawFlag of flagCandidates) {
    if (rawFlag !== undefined) {
      if (rawFlag !== true) return false;
    }
  }
  return true;
}

export function normalizeCompoundingPanel(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return STATIC_COMPOUNDING_PANEL;
  }

  const inner = (
    doc.compoundingPanel
    ?? doc.compoundingController
    ?? doc.compounding_controller
    ?? doc.compounding
    ?? doc
  );
  const src = (inner && typeof inner === 'object' && !Array.isArray(inner)) ? inner : doc;

  const rawMode = cleanText(String(src.mode ?? src.compoundingMode ?? src.compounding_mode ?? ''), 48).toUpperCase();
  const mode = COMPOUNDING_MODES.includes(rawMode) ? rawMode : STATIC_COMPOUNDING_PANEL.mode;

  const startingPrincipalUsd = normalizeDecimalString(
    src.startingPrincipalUsd ?? src.starting_principal_usd,
    STATIC_COMPOUNDING_PANEL.startingPrincipalUsd,
    2
  );
  const currentEquityUsd = normalizeDecimalString(
    src.currentEquityUsd ?? src.current_equity_usd,
    startingPrincipalUsd,
    2
  );
  const defaultDoubleTarget = multiplyDecimalByInt(startingPrincipalUsd, 2);
  const houseMoneyTargetUsd = normalizeDecimalString(
    src.houseMoneyTargetUsd ?? src.house_money_target_usd,
    defaultDoubleTarget,
    2
  );
  const compoundingTargetUsd = normalizeDecimalString(
    src.compoundingTargetUsd ?? src.compounding_target_usd,
    houseMoneyTargetUsd,
    2
  );

  const rawStatus = cleanText(String(src.houseMoneyStatus ?? src.house_money_status ?? ''), 64).toUpperCase();
  const principalWithdrawnUsd = normalizeDecimalString(
    src.principalWithdrawnUsd ?? src.principal_withdrawn_usd,
    '0.00',
    2
  );
  const principalWithdrawnAcknowledged = Boolean(
    src.principalWithdrawnAcknowledged
    ?? src.principal_withdrawn_acknowledged
    ?? src.principalWithdrawn
    ?? src.principal_withdrawn
    ?? (rawStatus === 'PLAYING_ON_HOUSE_MONEY')
    ?? (compareDecimalStrings(principalWithdrawnUsd, '0.00') > 0)
  );

  const equityVsPrincipal = compareDecimalStrings(currentEquityUsd, startingPrincipalUsd);
  const equityVsTarget = compareDecimalStrings(currentEquityUsd, houseMoneyTargetUsd);
  const underwater = equityVsPrincipal < 0 || rawStatus === 'BUILDING_TOWARD_PRINCIPAL';

  let houseMoneyStatus;
  if (HOUSE_MONEY_STATUSES.includes(rawStatus)) {
    houseMoneyStatus = rawStatus;
  } else if (principalWithdrawnAcknowledged) {
    houseMoneyStatus = 'PLAYING_ON_HOUSE_MONEY';
  } else if (equityVsTarget >= 0 && compareDecimalStrings(houseMoneyTargetUsd, '0.00') > 0) {
    houseMoneyStatus = 'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL';
  } else if (equityVsPrincipal < 0) {
    houseMoneyStatus = 'BUILDING_TOWARD_PRINCIPAL';
  } else {
    houseMoneyStatus = 'COMPOUNDING_TO_DOUBLE';
  }

  const explicitReady = src.houseMoneyReady ?? src.house_money_ready;
  const houseMoneyReady = typeof explicitReady === 'boolean'
    ? (explicitReady && houseMoneyStatus !== 'PLAYING_ON_HOUSE_MONEY')
    : (houseMoneyStatus === 'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL');

  const rawSuggested = src.suggestedPrincipalPulloutUsd ?? src.suggested_principal_pullout_usd;
  const suggestedPrincipalPulloutUsd = rawSuggested !== undefined && rawSuggested !== null
    ? normalizeDecimalString(rawSuggested, '0.00', 2)
    : (houseMoneyReady ? startingPrincipalUsd : '0.00');

  const rawProgress = src.progressToHouseMoneyPct ?? src.progress_to_house_money_pct;
  const progressToHouseMoneyPct = rawProgress !== undefined && rawProgress !== null
    ? normalizeDecimalString(rawProgress, '0.00', 2)
    : (houseMoneyStatus === 'PLAYING_ON_HOUSE_MONEY'
      ? '100.00'
      : computeHouseMoneyProgressPct(startingPrincipalUsd, currentEquityUsd, houseMoneyTargetUsd));

  const rawRemaining = src.remainingToHouseMoneyUsd ?? src.remaining_to_house_money_usd;
  let remainingToHouseMoneyUsd;
  if (rawRemaining !== undefined && rawRemaining !== null) {
    remainingToHouseMoneyUsd = normalizeDecimalString(rawRemaining, '0.00', 2);
  } else if (houseMoneyStatus === 'PLAYING_ON_HOUSE_MONEY' || equityVsTarget >= 0) {
    remainingToHouseMoneyUsd = '0.00';
  } else {
    const diff = subtractDecimalStrings(houseMoneyTargetUsd, currentEquityUsd);
    remainingToHouseMoneyUsd = compareDecimalStrings(diff, '0.00') < 0 ? '0.00' : diff;
  }

  const autoEnableVaultAtTarget = typeof (src.autoEnableVaultAtTarget ?? src.auto_enable_vault_at_target) === 'boolean'
    ? Boolean(src.autoEnableVaultAtTarget ?? src.auto_enable_vault_at_target)
    : true;
  const postTargetVaultRatio = normalizeDecimalString(
    src.postTargetVaultRatio ?? src.post_target_vault_ratio,
    '0.50',
    2
  );

  const rawSweep = src.effectiveVaultSweepRatio ?? src.effective_vault_sweep_ratio;
  let effectiveVaultSweepRatio;
  if (equityVsPrincipal <= 0 && houseMoneyStatus !== 'PLAYING_ON_HOUSE_MONEY') {
    // Unbreakable recovery invariant: 0.00 vaulted while underwater or at starting principal.
    effectiveVaultSweepRatio = '0.00';
  } else if (rawSweep !== undefined && rawSweep !== null) {
    effectiveVaultSweepRatio = normalizeDecimalString(rawSweep, '0.00', 2);
  } else if (mode === 'FULL_COMPOUND_100') {
    const reachedCompTarget = compareDecimalStrings(currentEquityUsd, compoundingTargetUsd) >= 0;
    effectiveVaultSweepRatio = (reachedCompTarget && autoEnableVaultAtTarget) ? postTargetVaultRatio : '0.00';
  } else if (mode === 'BALANCED_SPLIT_50_50') {
    effectiveVaultSweepRatio = '0.50';
  } else {
    effectiveVaultSweepRatio = normalizeDecimalString(src.customVaultRatio ?? src.custom_vault_ratio, '0.25', 2);
  }

  const rawRetain = subtractDecimalStrings('1.00', effectiveVaultSweepRatio);
  const effectiveRetainRatio = compareDecimalStrings(rawRetain, '0.00') < 0 ? '0.00' : rawRetain;

  const progressBucket = computePctBucket(progressToHouseMoneyPct);
  const ownerControlsAllowed = resolveOwnerControlsAllowed(doc, src);
  const auditChainValid = typeof (src.auditChainValid ?? src.audit_chain_valid) === 'boolean'
    ? Boolean(src.auditChainValid ?? src.audit_chain_valid)
    : true;

  const rawBrokers = Array.isArray(src.brokers) && src.brokers.length > 0 ? src.brokers : COMPOUNDING_BROKERS;
  const brokers = Object.freeze(
    rawBrokers.map((b) => cleanText(String(b ?? ''), 48)).filter(Boolean)
  );

  const rawShield = doc.newsShield ?? doc.news_shield ?? src.newsShield ?? src.news_shield ?? null;
  const newsShield = normalizeNewsShield(rawShield);
  const milestones = normalizeMilestones(src.milestones, startingPrincipalUsd, currentEquityUsd);

  return Object.freeze({
    schema: COMPOUNDING_PANEL_SCHEMA,
    mode,
    isFullCompound: mode === 'FULL_COMPOUND_100',
    startingPrincipalUsd,
    currentEquityUsd,
    compoundingTargetUsd,
    houseMoneyTargetUsd,
    houseMoneyStatus,
    houseMoneyReady,
    principalWithdrawnAcknowledged,
    principalWithdrawnUsd,
    suggestedPrincipalPulloutUsd,
    progressToHouseMoneyPct,
    progressBucket,
    remainingToHouseMoneyUsd,
    effectiveVaultSweepRatio,
    effectiveRetainRatio,
    underwater,
    autoEnableVaultAtTarget,
    postTargetVaultRatio,
    auditChainValid,
    ownerControlsAllowed,
    brokers: brokers.length > 0 ? brokers : COMPOUNDING_BROKERS,
    milestones,
    newsShield,
  });
}

function buildPanelViewModel(panel) {
  const switchLabel = panel.mode === 'FULL_COMPOUND_100'
    ? '100% Compounding Mode'
    : (panel.mode === 'BALANCED_SPLIT_50_50'
      ? '50%/50% Vault Split'
      : `Custom Split (${formatSweepRatioPct(panel.effectiveVaultSweepRatio)} Vault)`);

  let modeSummary;
  if (panel.underwater) {
    modeSummary = `Recovery Lock: 0% vaulted until equity recovers above ${formatExactUsd(panel.startingPrincipalUsd)}.`;
  } else if (panel.mode === 'FULL_COMPOUND_100' && compareDecimalStrings(panel.effectiveVaultSweepRatio, '0.00') === 0) {
    modeSummary = `100% of realized profit stays compounding · 0% Bank Vault sweep toward ${formatExactUsd(panel.compoundingTargetUsd)}.`;
  } else {
    modeSummary = `${formatSweepRatioPct(panel.effectiveRetainRatio)} compounding · ${formatSweepRatioPct(panel.effectiveVaultSweepRatio)} swept to internal Bank Vault.`;
  }

  let remainingText;
  if (panel.houseMoneyStatus === 'PLAYING_ON_HOUSE_MONEY') {
    remainingText = 'Original principal secured · 100% house money';
  } else if (panel.houseMoneyReady) {
    remainingText = 'Doubled — House Money Ready!';
  } else if (panel.underwater) {
    remainingText = `${formatExactUsd(panel.remainingToHouseMoneyUsd)} to Double (recovering principal)`;
  } else {
    remainingText = `${formatExactUsd(panel.remainingToHouseMoneyUsd)} left to Double`;
  }

  const pulloutUsd = compareDecimalStrings(panel.suggestedPrincipalPulloutUsd, '0.00') > 0
    ? panel.suggestedPrincipalPulloutUsd
    : panel.startingPrincipalUsd;
  const houseMoneyBannerText = panel.houseMoneyReady
    ? `HOUSE MONEY READY — You doubled ${formatExactUsd(panel.startingPrincipalUsd)} to ${formatExactUsd(panel.houseMoneyTargetUsd)}+! Withdraw your original ${formatExactUsd(pulloutUsd)} anytime to trade 100% on house money.`
    : '';

  const isPlayingOnHouseMoney = panel.houseMoneyStatus === 'PLAYING_ON_HOUSE_MONEY';
  const withdrawnDisplay = compareDecimalStrings(panel.principalWithdrawnUsd, '0.00') > 0
    ? panel.principalWithdrawnUsd
    : panel.startingPrincipalUsd;
  const houseMoneyBadgeTitle = isPlayingOnHouseMoney ? 'PLAYING ON 100% HOUSE MONEY' : '';
  const houseMoneyBadgeSub = isPlayingOnHouseMoney
    ? `Original ${formatExactUsd(withdrawnDisplay)} principal withdrawn`
    : '';

  const shield = panel.newsShield;
  let newsShieldHeadline;
  let newsShieldMeta;
  if (shield.paused) {
    newsShieldHeadline = `NEWS PAUSE (${shield.preMinutes}m CPI/NFP/FOMC) — New Entries Paused · Stop Protection ALWAYS ACTIVE`;
    const metaParts = [];
    if (shield.blockingTitle) metaParts.push(shield.blockingTitle);
    if (shield.affectedSymbols.length > 0) metaParts.push(`Markets: ${shield.affectedSymbols.join(', ')}`);
    if (shield.resumeAtUtc) metaParts.push(`Resumes: ${shield.resumeAtUtc}`);
    newsShieldMeta = metaParts.join(' · ') || 'Waiting for blackout window to clear';
  } else {
    newsShieldHeadline = 'News Shield: CLEAR';
    const clearParts = ['New entries open · Stop Protection ALWAYS ACTIVE'];
    if (shield.nextUpcomingTitle) {
      clearParts.push(
        shield.nextUpcomingUtc
          ? `Next: ${shield.nextUpcomingTitle} (${shield.nextUpcomingUtc})`
          : `Next: ${shield.nextUpcomingTitle}`
      );
    }
    newsShieldMeta = clearParts.join(' · ');
  }

  return {
    switchLabel,
    modeSummary,
    remainingText,
    houseMoneyBannerText,
    isPlayingOnHouseMoney,
    houseMoneyBadgeTitle,
    houseMoneyBadgeSub,
    newsShieldHeadline,
    newsShieldMeta,
    ownerLockText: panel.ownerControlsAllowed ? '' : 'Owner Key Required',
    ackBtnText: panel.houseMoneyReady ? 'Mark Original Principal Withdrawn' : '',
    statusSlug: STATUS_SLUG_MAP[panel.houseMoneyStatus] ?? 'compounding',
    startingPrincipalDisplay: formatExactUsd(panel.startingPrincipalUsd),
    currentEquityDisplay: formatExactUsd(panel.currentEquityUsd),
    houseMoneyTargetDisplay: formatExactUsd(panel.houseMoneyTargetUsd),
    effectiveSweepDisplay: formatSweepRatioPct(panel.effectiveVaultSweepRatio),
    progressPctDisplay: formatExactPct(panel.progressToHouseMoneyPct),
    brokersDisplay: panel.brokers.join(' · '),
  };
}

export function renderCompoundingAndHouseMoneyPanel(state) {
  const panel = normalizeCompoundingPanel(state);
  const vm = buildPanelViewModel(panel);
  const ownerLocked = !panel.ownerControlsAllowed;
  const switchStateClass = panel.isFullCompound ? 'is-on' : 'is-off';
  const shieldStateClass = panel.newsShield.paused ? 'is-paused' : 'is-clear';
  const ownerBadgeVis = ownerLocked ? 'is-visible' : 'is-hidden';
  const bannerVis = panel.houseMoneyReady ? 'is-visible' : 'is-hidden';
  const houseBadgeVis = vm.isPlayingOnHouseMoney ? 'is-visible' : 'is-hidden';
  const ackDisabled = !panel.houseMoneyReady || ownerLocked;

  return `<section class="panel compounding-panel" id="compounding-house-money-panel" data-compounding-panel="true" data-compounding-schema="${escapeHtml(panel.schema)}" data-compounding-mode="${escapeHtml(panel.mode)}" data-house-money-status="${escapeHtml(panel.houseMoneyStatus)}" data-owner-locked="${ownerLocked ? 'true' : 'false'}">`
    + `<header class="compound-header">`
      + `<div class="compound-title-group">`
        + `<h2 class="compound-title">Compounding &amp; House Money</h2>`
        + `<p class="compound-brokers" data-compounding-field="brokers">${escapeHtml(vm.brokersDisplay)}</p>`
      + `</div>`
      + `<div class="compound-header-badges">`
        + `<span class="compound-pill compound-owner-lock-pill ${ownerBadgeVis}" data-compounding-field="ownerLockBadge" aria-hidden="${ownerLocked ? 'false' : 'true'}">${escapeHtml(vm.ownerLockText)}</span>`
        + `<div class="compound-news-pill ${shieldStateClass}" role="status" aria-live="polite" data-compounding-field="newsShieldPill" data-news-status="${escapeHtml(panel.newsShield.overallStatus)}">`
          + `<span class="compound-news-headline" data-compounding-field="newsShieldHeadline">${escapeHtml(vm.newsShieldHeadline)}</span>`
          + `<span class="compound-news-meta" data-compounding-field="newsShieldMeta">${escapeHtml(vm.newsShieldMeta)}</span>`
        + `</div>`
      + `</div>`
    + `</header>`
    + `<div class="compound-switch-row">`
      + `<button type="button" role="switch" aria-checked="${panel.isFullCompound ? 'true' : 'false'}" class="compound-switch ${switchStateClass}" data-compounding-action="TOGGLE_FULL_100" data-compounding-field="modeSwitch"${ownerLocked ? ' disabled' : ''}>`
        + `<span class="compound-switch-track" aria-hidden="true"><span class="compound-switch-thumb"></span></span>`
        + `<span class="compound-switch-label" data-compounding-field="modeSwitchLabel">${escapeHtml(vm.switchLabel)}</span>`
      + `</button>`
      + `<p class="compound-mode-summary" data-compounding-field="modeSummary">${escapeHtml(vm.modeSummary)}</p>`
    + `</div>`
    + `<div class="compound-metrics-grid">`
      + `<div class="compound-metric-card">`
        + `<span class="compound-metric-label">Starting Principal</span>`
        + `<strong class="compound-metric-value" data-compounding-field="startingPrincipalUsd">${escapeHtml(vm.startingPrincipalDisplay)}</strong>`
      + `</div>`
      + `<div class="compound-metric-card">`
        + `<span class="compound-metric-label">Current Equity</span>`
        + `<strong class="compound-metric-value" data-compounding-field="currentEquityUsd">${escapeHtml(vm.currentEquityDisplay)}</strong>`
      + `</div>`
      + `<div class="compound-metric-card">`
        + `<span class="compound-metric-label">House-Money Double</span>`
        + `<strong class="compound-metric-value" data-compounding-field="houseMoneyTargetUsd">${escapeHtml(vm.houseMoneyTargetDisplay)}</strong>`
      + `</div>`
      + `<div class="compound-metric-card">`
        + `<span class="compound-metric-label">Active Vault Sweep</span>`
        + `<strong class="compound-metric-value" data-compounding-field="effectiveVaultSweepRatio">${escapeHtml(vm.effectiveSweepDisplay)}</strong>`
      + `</div>`
    + `</div>`
    + `<div class="compound-progress-block">`
      + `<div class="compound-progress-head">`
        + `<span class="compound-progress-pct" data-compounding-field="progressPctText">${escapeHtml(vm.progressPctDisplay)}</span>`
        + `<span class="compound-progress-remaining" data-compounding-field="remainingText">${escapeHtml(vm.remainingText)}</span>`
      + `</div>`
      + `<div class="compound-progress-track" role="progressbar" aria-label="Progress to House Money double" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${panel.progressBucket}" data-compounding-field="progressTrack">`
        + `<div class="compound-progress-fill compound-pct-${panel.progressBucket} is-status-${vm.statusSlug}" data-compounding-field="progressFill"></div>`
      + `</div>`
    + `</div>`
    + `<div class="compound-house-banner ${bannerVis}" role="status" aria-live="polite" data-compounding-field="houseMoneyBanner" aria-hidden="${panel.houseMoneyReady ? 'false' : 'true'}">`
      + `<p class="compound-house-banner-text" data-compounding-field="houseMoneyBannerText">${escapeHtml(vm.houseMoneyBannerText)}</p>`
      + `<button type="button" class="compound-ack-btn ${bannerVis}" data-compounding-action="ACK_PRINCIPAL_WITHDRAWN" data-compounding-field="ackWithdrawBtn" aria-hidden="${panel.houseMoneyReady ? 'false' : 'true'}"${ackDisabled ? ' disabled' : ''}>${escapeHtml(vm.ackBtnText)}</button>`
    + `</div>`
    + `<div class="compound-house-badge ${houseBadgeVis}" role="status" aria-live="polite" data-compounding-field="houseMoneyBadge" aria-hidden="${vm.isPlayingOnHouseMoney ? 'false' : 'true'}">`
      + `<strong class="compound-house-badge-title" data-compounding-field="houseMoneyBadgeTitle">${escapeHtml(vm.houseMoneyBadgeTitle)}</strong>`
      + `<span class="compound-house-badge-sub" data-compounding-field="houseMoneyBadgeSub">${escapeHtml(vm.houseMoneyBadgeSub)}</span>`
    + `</div>`
  + `</section>`;
}

function updateClassTokens(el, addList, removeList) {
  if (!el) return;
  if (el.classList && typeof el.classList.add === 'function' && typeof el.classList.remove === 'function') {
    for (const token of removeList) el.classList.remove(token);
    for (const token of addList) el.classList.add(token);
    return;
  }
  const current = new Set(String(el.className ?? '').split(/\s+/).filter(Boolean));
  for (const token of removeList) current.delete(token);
  for (const token of addList) current.add(token);
  el.className = Array.from(current).join(' ');
}

function setAttr(el, name, value) {
  if (!el || typeof el.setAttribute !== 'function') return;
  el.setAttribute(name, value);
}

function setDisabled(el, isDisabled) {
  if (!el) return;
  el.disabled = Boolean(isDisabled);
  if (typeof el.setAttribute === 'function' && typeof el.removeAttribute === 'function') {
    if (isDisabled) {
      el.setAttribute('disabled', '');
    } else {
      el.removeAttribute('disabled');
    }
  }
}

export function patchCompoundingPanelInPlace(root, nextState) {
  const panel = normalizeCompoundingPanel(nextState);
  if (!root || typeof root.querySelector !== 'function') {
    return { patched: false, panel, updatedFields: [] };
  }

  const container = (typeof root.getAttribute === 'function' && root.getAttribute('data-compounding-panel') === 'true')
    ? root
    : (root.querySelector('[data-compounding-panel="true"]') ?? root);

  const vm = buildPanelViewModel(panel);
  const ownerLocked = !panel.ownerControlsAllowed;
  const updatedFields = [];

  const field = (name) => container.querySelector(`[data-compounding-field="${name}"]`);
  const setText = (name, value) => {
    const el = field(name);
    if (!el) return null;
    el.textContent = value;
    updatedFields.push(name);
    return el;
  };

  setAttr(container, 'data-compounding-schema', panel.schema);
  setAttr(container, 'data-compounding-mode', panel.mode);
  setAttr(container, 'data-house-money-status', panel.houseMoneyStatus);
  setAttr(container, 'data-owner-locked', ownerLocked ? 'true' : 'false');

  setText('brokers', vm.brokersDisplay);

  const ownerBadge = setText('ownerLockBadge', vm.ownerLockText);
  if (ownerBadge) {
    updateClassTokens(
      ownerBadge,
      [ownerLocked ? 'is-visible' : 'is-hidden'],
      [ownerLocked ? 'is-hidden' : 'is-visible']
    );
    setAttr(ownerBadge, 'aria-hidden', ownerLocked ? 'false' : 'true');
  }

  const shieldPill = field('newsShieldPill');
  if (shieldPill) {
    updateClassTokens(
      shieldPill,
      [panel.newsShield.paused ? 'is-paused' : 'is-clear'],
      [panel.newsShield.paused ? 'is-clear' : 'is-paused']
    );
    setAttr(shieldPill, 'data-news-status', panel.newsShield.overallStatus);
    updatedFields.push('newsShieldPill');
  }
  setText('newsShieldHeadline', vm.newsShieldHeadline);
  setText('newsShieldMeta', vm.newsShieldMeta);

  const modeSwitch = field('modeSwitch');
  if (modeSwitch) {
    updateClassTokens(
      modeSwitch,
      [panel.isFullCompound ? 'is-on' : 'is-off'],
      [panel.isFullCompound ? 'is-off' : 'is-on']
    );
    setAttr(modeSwitch, 'aria-checked', panel.isFullCompound ? 'true' : 'false');
    setDisabled(modeSwitch, ownerLocked);
    updatedFields.push('modeSwitch');
  }
  setText('modeSwitchLabel', vm.switchLabel);
  setText('modeSummary', vm.modeSummary);

  setText('startingPrincipalUsd', vm.startingPrincipalDisplay);
  setText('currentEquityUsd', vm.currentEquityDisplay);
  setText('houseMoneyTargetUsd', vm.houseMoneyTargetDisplay);
  setText('effectiveVaultSweepRatio', vm.effectiveSweepDisplay);

  setText('progressPctText', vm.progressPctDisplay);
  setText('remainingText', vm.remainingText);

  const progressTrack = field('progressTrack');
  if (progressTrack) {
    setAttr(progressTrack, 'aria-valuenow', String(panel.progressBucket));
    updatedFields.push('progressTrack');
  }

  const progressFill = field('progressFill');
  if (progressFill) {
    updateClassTokens(
      progressFill,
      [`compound-pct-${panel.progressBucket}`, `is-status-${vm.statusSlug}`],
      [...PCT_BUCKET_CLASSES, ...STATUS_CLASS_TOKENS]
    );
    updatedFields.push('progressFill');
  }

  const banner = field('houseMoneyBanner');
  if (banner) {
    updateClassTokens(
      banner,
      [panel.houseMoneyReady ? 'is-visible' : 'is-hidden'],
      [panel.houseMoneyReady ? 'is-hidden' : 'is-visible']
    );
    setAttr(banner, 'aria-hidden', panel.houseMoneyReady ? 'false' : 'true');
    updatedFields.push('houseMoneyBanner');
  }
  setText('houseMoneyBannerText', vm.houseMoneyBannerText);

  const ackBtn = setText('ackWithdrawBtn', vm.ackBtnText);
  if (ackBtn) {
    updateClassTokens(
      ackBtn,
      [panel.houseMoneyReady ? 'is-visible' : 'is-hidden'],
      [panel.houseMoneyReady ? 'is-hidden' : 'is-visible']
    );
    setAttr(ackBtn, 'aria-hidden', panel.houseMoneyReady ? 'false' : 'true');
    setDisabled(ackBtn, !panel.houseMoneyReady || ownerLocked);
  }

  const houseBadge = field('houseMoneyBadge');
  if (houseBadge) {
    updateClassTokens(
      houseBadge,
      [vm.isPlayingOnHouseMoney ? 'is-visible' : 'is-hidden'],
      [vm.isPlayingOnHouseMoney ? 'is-hidden' : 'is-visible']
    );
    setAttr(houseBadge, 'aria-hidden', vm.isPlayingOnHouseMoney ? 'false' : 'true');
    updatedFields.push('houseMoneyBadge');
  }
  setText('houseMoneyBadgeTitle', vm.houseMoneyBadgeTitle);
  setText('houseMoneyBadgeSub', vm.houseMoneyBadgeSub);

  return { patched: updatedFields.length > 0, panel, updatedFields };
}

const PCT_BUCKET_CSS_RULES = PCT_BUCKET_STEPS
  .map((step) => `.compound-progress-fill.compound-pct-${step} { width: ${step}%; }`)
  .join('\n');

export const COMPOUNDING_PANEL_CSS_SNIPPET = `/* Strict-CSP 60fps Compounding Mode, House-Money Milestone & Live News Shield Styles */
.compounding-panel {
  display: grid;
  gap: 16px;
  padding: 20px;
  border-radius: 16px;
  background: var(--panel, #FFFFFF);
  border: 1px solid var(--line, #DCE2EA);
  box-shadow: var(--shadow, 0 3px 6px rgb(18 34 56 / 8%));
  color: var(--ink, #122238);
}

.compound-header {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.compound-title-group {
  display: grid;
  gap: 4px;
}

.compound-title {
  font-size: 18px;
  font-weight: 700;
  line-height: 1.25;
}

.compound-brokers {
  font-size: 12px;
  font-weight: 600;
  color: var(--muted, #596779);
  letter-spacing: 0.02em;
}

.compound-header-badges {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.compound-pill,
.compound-news-pill {
  display: inline-flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 12px;
  border-radius: 12px;
  font-size: 12px;
  line-height: 1.35;
  font-variant-numeric: tabular-nums;
  border: 1px solid var(--line, #DCE2EA);
}

.compound-owner-lock-pill {
  flex-direction: row;
  align-items: center;
  min-height: 36px;
  font-weight: 700;
  background: var(--warning-surface, #FFF0E4);
  color: var(--warning-text, #773408);
  border-color: #E2A36B;
}

.compound-news-pill.is-clear {
  background: #EDF8F2;
  color: #115E3B;
  border-color: #9ED8B8;
}

.compound-news-pill.is-paused {
  background: var(--warning-surface, #FFF0E4);
  color: var(--warning-text, #773408);
  border-color: var(--orange, #C2510B);
}

.compound-news-headline {
  font-weight: 700;
}

.compound-news-meta {
  font-size: 11px;
  opacity: 0.9;
}

.compound-switch-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 14px;
  background: var(--panel-soft, #F7F9FC);
  border: 1px solid var(--line, #DCE2EA);
}

.compound-switch {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  min-height: 44px;
  min-width: 44px;
  padding: 6px 14px 6px 8px;
  border-radius: 999px;
  border: 1px solid var(--line, #DCE2EA);
  background: var(--panel, #FFFFFF);
  color: var(--ink, #122238);
  font-weight: 700;
  transition: border-color 240ms cubic-bezier(0.22, 1, 0.36, 1),
    background-color 240ms cubic-bezier(0.22, 1, 0.36, 1);
}

.compound-switch:focus-visible,
.compound-ack-btn:focus-visible {
  outline: 3px solid var(--focus, #1B65B2);
  outline-offset: 3px;
}

.compound-switch-track {
  position: relative;
  display: inline-flex;
  align-items: center;
  width: 56px;
  height: 32px;
  padding: 4px;
  border-radius: 999px;
  background: #8B9BB0;
  transition: background-color 240ms cubic-bezier(0.22, 1, 0.36, 1);
}

.compound-switch.is-on .compound-switch-track {
  background: #147A4C;
}

.compound-switch.is-off .compound-switch-track {
  background: #6B7B90;
}

.compound-switch-thumb {
  width: 24px;
  height: 24px;
  border-radius: 999px;
  background: #FFFFFF;
  box-shadow: 0 2px 5px rgb(18 34 56 / 26%);
  transform: translate3d(0, 0, 0);
  will-change: transform;
  transition: transform 260ms cubic-bezier(0.22, 1, 0.36, 1);
}

.compound-switch.is-on .compound-switch-thumb {
  transform: translate3d(24px, 0, 0);
}

.compound-switch.is-off .compound-switch-thumb {
  transform: translate3d(0, 0, 0);
}

.compound-switch-label {
  font-size: 14px;
  font-weight: 700;
}

.compound-mode-summary {
  font-size: 13px;
  color: var(--muted, #596779);
  font-variant-numeric: tabular-nums;
}

.compound-metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}

.compound-metric-card {
  display: grid;
  gap: 4px;
  padding: 12px 14px;
  border-radius: 12px;
  background: var(--panel-soft, #F7F9FC);
  border: 1px solid var(--line, #DCE2EA);
}

.compound-metric-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted, #596779);
}

.compound-metric-value {
  font-size: 18px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.compound-progress-block {
  display: grid;
  gap: 8px;
}

.compound-progress-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
}

.compound-progress-pct {
  font-size: 15px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

.compound-progress-remaining {
  font-size: 13px;
  color: var(--muted, #596779);
  font-variant-numeric: tabular-nums;
}

.compound-progress-track {
  position: relative;
  height: 14px;
  border-radius: 999px;
  overflow: hidden;
  background: var(--line, #DCE2EA);
}

.compound-progress-fill {
  height: 100%;
  border-radius: 999px;
  background: #1B65B2;
  transition: width 320ms cubic-bezier(0.22, 1, 0.36, 1),
    background-color 240ms cubic-bezier(0.22, 1, 0.36, 1);
}

.compound-progress-fill.is-status-recovery {
  background: var(--orange, #C2510B);
}

.compound-progress-fill.is-status-compounding {
  background: #1B65B2;
}

.compound-progress-fill.is-status-ready,
.compound-progress-fill.is-status-house-money {
  background: #147A4C;
}

${PCT_BUCKET_CSS_RULES}

.compound-house-banner {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 16px;
  border-radius: 14px;
  background: #E7F7EE;
  color: #0D4B2F;
  border: 2px solid #147A4C;
}

.compound-house-banner-text {
  font-size: 14px;
  font-weight: 700;
  line-height: 1.4;
  font-variant-numeric: tabular-nums;
}

.compound-ack-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  min-width: 44px;
  padding: 10px 16px;
  border-radius: 10px;
  border: 1px solid #0D4B2F;
  background: #147A4C;
  color: #FFFFFF;
  font-weight: 700;
  transition: background-color 200ms cubic-bezier(0.22, 1, 0.36, 1),
    transform 200ms cubic-bezier(0.22, 1, 0.36, 1);
}

.compound-ack-btn:hover:not(:disabled) {
  background: #0F623C;
}

.compound-switch:disabled,
.compound-ack-btn:disabled {
  opacity: 0.62;
  cursor: not-allowed;
}

.compound-house-badge {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-radius: 14px;
  background: #103F2B;
  color: #F2FFF8;
  border: 2px solid #2FB377;
  font-variant-numeric: tabular-nums;
}

.compound-house-badge-title {
  font-size: 14px;
  font-weight: 800;
  letter-spacing: 0.04em;
}

.compound-house-badge-sub {
  font-size: 13px;
  opacity: 0.92;
}

.compounding-panel .is-hidden {
  display: none;
}

@media (prefers-reduced-motion: reduce) {
  .compound-switch,
  .compound-switch-track,
  .compound-switch-thumb,
  .compound-progress-fill,
  .compound-ack-btn {
    transition: none;
  }
}
`;
