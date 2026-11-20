/**
 * Strict-CSP Thermal Market Signal Heatmap, Broker-Attributed Top Status /
 * Realized P/L Provenance Strip, and Dark-Mode Obsidian Equity/Vault &
 * Underwater Drawdown Analytics Engine for CAS Forex Revamp.
 *
 * Pure, zero-dependency ES module:
 * - Strict CSP: ZERO inline style attributes, ZERO eval/Function.
 * - XSS-safe HTML escaping on every dynamic string.
 * - Exact BigInt decimal arithmetic for money totals (zero float drift, never rounded).
 * - Dark Obsidian (#121316) 2D Canvas renderers for zoomed Equity/Vault & Drawdown.
 */

export const OBSIDIAN_BG_HEX = '#121316';
export const VALVE_SCORE_CUTOFF = 0.55;
export const DEFAULT_PRINCIPAL_USD = '300000';
export const MAX_DRAWDOWN_BRAKE_PCT = -10;

const SYNTHETIC_MARKERS = Object.freeze([
  'SESSION_SYNC',
  'SESSION_BASKET',
  'RECONCILIATION',
  'PORTFOLIO_RECONCILE',
  'LEDGER_RECONCILE',
  'BALANCE_RECONCILE',
  'SYNTHETIC',
  'INTERNAL_ADJUSTMENT',
  'MANUAL_ADJUSTMENT',
  'BOOTSTRAP_SYNC',
]);

const INDEX_SYMBOLS = new Set(['NAS100', 'US30', 'SPX500', 'XAUUSD']);
const TIGHT_INDEX_SYMBOLS = new Set(['SPX500', 'XAUUSD']);

const PACIFIC_DISPLAY_FMT = new Intl.DateTimeFormat('en-US', {
  timeZone: 'America/Los_Angeles',
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: true,
  timeZoneName: 'short',
});

const PACIFIC_DATE_FMT = new Intl.DateTimeFormat('en-US', {
  timeZone: 'America/Los_Angeles',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
});

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function cleanStr(value, fallback = '', maxLen = 180) {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, maxLen) : fallback;
}

function numStr(value, fallback = '0') {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^[+-]?\d+(?:\.\d+)?$/.test(trimmed)) {
      return trimmed.startsWith('+') ? trimmed.slice(1) : trimmed;
    }
    return fallback;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return fallback;
}

function parseDecimalScaled(raw) {
  const s = numStr(raw, '0');
  const neg = s.startsWith('-');
  const unsigned = neg ? s.slice(1) : s;
  const [intPartRaw, fracPartRaw = ''] = unsigned.split('.');
  const intPart = intPartRaw.replace(/^0+(?=\d)/, '') || '0';
  const digits = `${intPart}${fracPartRaw}`;
  const scale = fracPartRaw.length;
  const magnitude = BigInt(digits);
  return {
    value: neg ? -magnitude : magnitude,
    scale,
  };
}

function pow10BigInt(exp) {
  let result = 1n;
  for (let i = 0; i < exp; i += 1) result *= 10n;
  return result;
}

function scaledToDecimalString(value, scale, minFractionDigits = 2) {
  const neg = value < 0n;
  const absVal = neg ? -value : value;
  const rawDigits = absVal.toString();
  let intPart;
  let fracPart;
  if (scale === 0) {
    intPart = rawDigits;
    fracPart = '';
  } else if (rawDigits.length <= scale) {
    intPart = '0';
    fracPart = rawDigits.padStart(scale, '0');
  } else {
    intPart = rawDigits.slice(0, rawDigits.length - scale);
    fracPart = rawDigits.slice(rawDigits.length - scale);
  }
  let trimmedFrac = fracPart;
  while (trimmedFrac.length > minFractionDigits && trimmedFrac.endsWith('0')) {
    trimmedFrac = trimmedFrac.slice(0, -1);
  }
  if (trimmedFrac.length < minFractionDigits) {
    trimmedFrac = trimmedFrac.padEnd(minFractionDigits, '0');
  }
  const isZero = intPart === '0' && /^0*$/.test(trimmedFrac);
  const sign = neg && !isZero ? '-' : '';
  return trimmedFrac.length > 0 ? `${sign}${intPart}.${trimmedFrac}` : `${sign}${intPart}`;
}

function addDecimalStrings(a, b) {
  const da = parseDecimalScaled(a);
  const db = parseDecimalScaled(b);
  const maxScale = Math.max(da.scale, db.scale);
  const va = da.value * pow10BigInt(maxScale - da.scale);
  const vb = db.value * pow10BigInt(maxScale - db.scale);
  return scaledToDecimalString(va + vb, maxScale, 2);
}

function subDecimalStrings(a, b) {
  const da = parseDecimalScaled(a);
  const db = parseDecimalScaled(b);
  const maxScale = Math.max(da.scale, db.scale);
  const va = da.value * pow10BigInt(maxScale - da.scale);
  const vb = db.value * pow10BigInt(maxScale - db.scale);
  return scaledToDecimalString(va - vb, maxScale, 2);
}

function compareDecimalStrings(a, b) {
  const da = parseDecimalScaled(a);
  const db = parseDecimalScaled(b);
  const maxScale = Math.max(da.scale, db.scale);
  const va = da.value * pow10BigInt(maxScale - da.scale);
  const vb = db.value * pow10BigInt(maxScale - db.scale);
  if (va < vb) return -1;
  if (va > vb) return 1;
  return 0;
}

function absDecimalString(raw) {
  const d = parseDecimalScaled(raw);
  return scaledToDecimalString(d.value < 0n ? -d.value : d.value, d.scale, 2);
}

export function formatExactUsd(raw) {
  const s = numStr(raw, '0');
  const neg = s.startsWith('-');
  const unsigned = neg ? s.slice(1) : s;
  const [rawInt, rawFrac = ''] = unsigned.split('.');
  const cleanInt = rawInt.replace(/^0+(?=\d)/, '') || '0';
  const withCommas = cleanInt.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const frac = rawFrac.length >= 2 ? rawFrac : rawFrac.padEnd(2, '0');
  const isZero = cleanInt === '0' && /^0+$/.test(frac);
  return `${neg && !isZero ? '-' : ''}$${withCommas}.${frac}`;
}

export function formatSignedUsd(raw) {
  const formatted = formatExactUsd(raw);
  if (formatted === '$0.00' || formatted.startsWith('-')) return formatted;
  return `+${formatted}`;
}

function pnlToneClass(raw) {
  const cmp = compareDecimalStrings(raw, '0');
  if (cmp > 0) return 'pnl-pos';
  if (cmp < 0) return 'pnl-neg';
  return 'pnl-flat';
}

export function quantizeMeterPctClass(pct) {
  const n = Number(pct);
  const clamped = Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
  const bucket = Math.round(clamped / 5) * 5;
  return `meter-pct-${bucket}`;
}

function isSyntheticMarker(value) {
  if (typeof value !== 'string') return false;
  const normalized = value.trim().toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (!normalized) return false;
  for (const marker of SYNTHETIC_MARKERS) {
    if (
      normalized === marker
      || normalized.startsWith(`${marker}_`)
      || normalized.endsWith(`_${marker}`)
      || normalized.includes(marker)
    ) {
      return true;
    }
  }
  return false;
}

export function isSyntheticSweepRow(row) {
  if (!row || typeof row !== 'object') return true;
  if (row.isSynthetic === true || row.is_synthetic === true) return true;
  const symbol = cleanStr(row.symbol ?? row.instrument_id ?? '', '', 80);
  const brokerId = cleanStr(row.brokerId ?? row.broker_id ?? '', '', 80);
  const tradeId = cleanStr(row.tradeId ?? row.trade_id ?? '', '', 120);
  const kind = cleanStr(row.kind ?? row.source ?? '', '', 80);
  if (isSyntheticMarker(symbol) || isSyntheticMarker(brokerId) || isSyntheticMarker(tradeId) || isSyntheticMarker(kind)) {
    return true;
  }
  return false;
}

export function formatBrokerDisplayName(brokerId) {
  if (typeof brokerId !== 'string') return null;
  const trimmed = brokerId.trim();
  if (!trimmed || isSyntheticMarker(trimmed)) return null;
  const canonical = trimmed.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (!canonical || isSyntheticMarker(canonical)) return null;

  if (canonical === 'LHFX' || canonical.startsWith('LHFX_')) {
    return 'LHFX';
  }
  if (
    canonical === 'HUGOSWAY'
    || canonical.startsWith('HUGOSWAY_')
    || canonical === 'HUGOS_WAY'
    || canonical.startsWith('HUGOS_WAY_')
    || canonical === 'HUGO_S_WAY'
    || canonical.startsWith('HUGO_S_WAY_')
    || canonical === 'HUGO_WAY'
    || canonical.startsWith('HUGO_WAY_')
  ) {
    return "Hugo's Way";
  }
  if (canonical === 'OANDA' || canonical.startsWith('OANDA_')) {
    return 'OANDA';
  }
  if (canonical === 'COINBASE' || canonical.startsWith('COINBASE_')) {
    return 'Coinbase';
  }
  if (canonical === 'KRAKEN' || canonical.startsWith('KRAKEN_')) {
    return 'Kraken';
  }
  return trimmed.slice(0, 80);
}

function parseValidDate(isoUtc) {
  if (isoUtc instanceof Date) {
    return Number.isNaN(isoUtc.getTime()) ? null : isoUtc;
  }
  if (typeof isoUtc === 'number' && Number.isFinite(isoUtc)) {
    const d = new Date(isoUtc);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  if (typeof isoUtc !== 'string' || !isoUtc.trim()) return null;
  const d = new Date(isoUtc.trim());
  return Number.isNaN(d.getTime()) ? null : d;
}

export function classifySessionFromIso(isoUtc) {
  const d = parseValidDate(isoUtc);
  if (!d) {
    return Object.freeze({ sessionId: 'UNKNOWN', sessionLabel: 'Unknown Session' });
  }
  const hour = d.getUTCHours();
  if (hour >= 22 || hour < 7) {
    return Object.freeze({ sessionId: 'ASIA', sessionLabel: 'Asia / Tokyo\u2013Sydney' });
  }
  if (hour >= 7 && hour < 12) {
    return Object.freeze({ sessionId: 'LONDON', sessionLabel: 'London' });
  }
  return Object.freeze({ sessionId: 'NEW_YORK', sessionLabel: 'New York / US' });
}

export function formatDualDateTime(isoUtc) {
  const d = parseValidDate(isoUtc);
  if (!d) {
    return Object.freeze({
      localPt: 'Unknown PT',
      utc: 'Unknown UTC',
      datePt: 'Unknown',
      timePt: 'Unknown',
      isoUtc: '',
      combined: 'Unknown Time',
    });
  }
  const parts = Object.create(null);
  for (const part of PACIFIC_DISPLAY_FMT.formatToParts(d)) {
    if (part.type !== 'literal') parts[part.type] = part.value;
  }
  const dateParts = Object.create(null);
  for (const part of PACIFIC_DATE_FMT.formatToParts(d)) {
    if (part.type !== 'literal') dateParts[part.type] = part.value;
  }
  const tzLabel = parts.timeZoneName || 'PT';
  const timePt = `${parts.hour}:${parts.minute}:${parts.second} ${parts.dayPeriod} ${tzLabel}`;
  const localPt = `${parts.month} ${parts.day}, ${parts.year} \u00b7 ${timePt}`;
  const datePt = `${dateParts.year}-${dateParts.month}-${dateParts.day}`;

  const uYear = String(d.getUTCFullYear()).padStart(4, '0');
  const uMonth = String(d.getUTCMonth() + 1).padStart(2, '0');
  const uDay = String(d.getUTCDate()).padStart(2, '0');
  const uHour = String(d.getUTCHours()).padStart(2, '0');
  const uMin = String(d.getUTCMinutes()).padStart(2, '0');
  const uSec = String(d.getUTCSeconds()).padStart(2, '0');
  const utc = `${uYear}-${uMonth}-${uDay} ${uHour}:${uMin}:${uSec} UTC`;
  const canonicalIso = d.toISOString();

  return Object.freeze({
    localPt,
    utc,
    datePt,
    timePt,
    isoUtc: canonicalIso,
    combined: `${localPt} (${utc})`,
  });
}

function normalizeSymbolKey(raw) {
  return cleanStr(raw, '', 60).toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function uniqueStrings(items) {
  const out = [];
  const seen = new Set();
  for (const item of items) {
    if (typeof item !== 'string' || !item.trim()) continue;
    const val = item.trim();
    if (!seen.has(val)) {
      seen.add(val);
      out.push(val);
    }
  }
  return out;
}

function computeStatusFromState(state, openPositions) {
  const trader = state?.aiTrader ?? {};
  const bs = trader.bankedSession ?? trader.banked_session ?? {};
  const dq = trader.dailyQuota ?? trader.daily_quota ?? {};
  const openMarkets = uniqueStrings(
    openPositions
      .map((p) => cleanStr(p?.symbol ?? p?.instrument_id ?? '', '', 40))
      .filter((sym) => sym && !isSyntheticMarker(sym)),
  );
  const openBrokers = uniqueStrings(
    openPositions
      .map((p) => formatBrokerDisplayName(p?.broker_id ?? p?.brokerId ?? ''))
      .filter(Boolean),
  );
  const isCurrentlyTrading = openPositions.length > 0;

  if (isCurrentlyTrading) {
    const countWord = openPositions.length === 1 ? '1 OPEN TRADE' : `${openPositions.length} OPEN TRADES`;
    const mktSuffix = openMarkets.length ? `: ${openMarkets.join(', ')}` : '';
    return {
      isCurrentlyTrading: true,
      statusCode: 'TRADING_NOW',
      statusHeadline: `TRADING NOW \u2014 ${countWord}${mktSuffix}`,
      openPositionCount: openPositions.length,
      openMarkets,
      openBrokers,
    };
  }

  const govMode = cleanStr(trader.governanceMode ?? trader.governance_mode ?? '', '', 40).toUpperCase();
  const opMode = cleanStr(trader.operatingMode ?? trader.operating_mode ?? bs.operatingMode ?? bs.operating_mode ?? '', '', 40).toUpperCase();
  const effStatus = cleanStr(trader.effectiveStatus ?? trader.effective_status ?? '', '', 60).toUpperCase();
  const dqStatus = cleanStr(dq.status ?? '', '', 60).toUpperCase();
  const isHardLock = (
    dqStatus === 'DAILY_LOSS_CIRCUIT_TRIPPED'
    || govMode === 'STOPPED'
    || opMode === 'SAFETY_LOCK'
    || effStatus.includes('LOSS_CIRCUIT')
    || effStatus.includes('SAFETY_LOCK')
  );
  const isRespite = (
    opMode === 'RESEARCH_RESPITE'
    || Boolean(trader.respiteMode ?? trader.respite_mode)
    || Boolean(bs.profitsLockedForSession ?? bs.profits_locked_for_session)
    || dqStatus === 'DAILY_QUOTA_LOCKED'
    || dqStatus === 'PROFIT_FLOOR_LOCKED'
    || effStatus.includes('RESPITE')
    || effStatus.includes('QUOTA_LOCKED')
    || effStatus.includes('PROFIT_FLOOR')
  );
  const isPausedLock = govMode === 'PAUSED' || govMode === 'PAUSED_NEW_RISK';

  if (isHardLock) {
    return {
      isCurrentlyTrading: false,
      statusCode: 'PAUSED_SAFETY_LOCK',
      statusHeadline: 'PAUSED \u2014 SAFETY LOCK (NEW RISK BLOCKED)',
      openPositionCount: 0,
      openMarkets: [],
      openBrokers: [],
    };
  }
  if (isRespite) {
    return {
      isCurrentlyTrading: false,
      statusCode: 'PAUSED_RESEARCH_RESPITE',
      statusHeadline: 'PAUSED \u2014 RESEARCH RESPITE (PROFIT FLOOR PROTECTED)',
      openPositionCount: 0,
      openMarkets: [],
      openBrokers: [],
    };
  }
  if (isPausedLock) {
    return {
      isCurrentlyTrading: false,
      statusCode: 'PAUSED_SAFETY_LOCK',
      statusHeadline: 'PAUSED \u2014 SAFETY LOCK (OWNER / GOVERNANCE PAUSE)',
      openPositionCount: 0,
      openMarkets: [],
      openBrokers: [],
    };
  }
  return {
    isCurrentlyTrading: false,
    statusCode: 'ACTIVE_SCANNING',
    statusHeadline: 'ACTIVE \u2014 SCANNING MARKETS FOR QUALIFIED ENTRY',
    openPositionCount: 0,
    openMarkets: [],
    openBrokers: [],
  };
}

function normalizeProvenanceRow(rawRow, index) {
  const tradeId = cleanStr(rawRow?.tradeId ?? rawRow?.trade_id ?? '', `trade-${index + 1}`, 120);
  const symbol = cleanStr(rawRow?.symbol ?? rawRow?.instrument_id ?? '', 'UNKNOWN', 40);
  const brokerId = cleanStr(rawRow?.brokerId ?? rawRow?.broker_id ?? '', '', 80);
  const brokerLabel = formatBrokerDisplayName(rawRow?.brokerLabel ?? rawRow?.broker_label ?? brokerId)
    || formatBrokerDisplayName(brokerId)
    || 'Unattributed Broker';
  const realizedNetUsd = numStr(rawRow?.realizedNetUsd ?? rawRow?.realized_net_usd, '0');
  const retainedTradingUsd = numStr(rawRow?.retainedTradingUsd ?? rawRow?.retained_trading_usd, '0');
  const bankSweepUsd = numStr(rawRow?.bankSweepUsd ?? rawRow?.bank_sweep_usd, '0');
  const occurredAtRaw = cleanStr(rawRow?.occurredAtUtc ?? rawRow?.occurred_at_utc ?? rawRow?.occurredAt ?? rawRow?.occurred_at ?? '', '', 64);
  const dt = formatDualDateTime(occurredAtRaw);
  const session = classifySessionFromIso(occurredAtRaw);
  const parsedMs = parseValidDate(occurredAtRaw)?.getTime() ?? -1;

  const localPt = cleanStr(rawRow?.localPt ?? rawRow?.local_display ?? '', dt.localPt, 80);
  const utc = cleanStr(rawRow?.utc ?? rawRow?.utc_display ?? '', dt.utc, 60);
  const datePt = cleanStr(rawRow?.datePt ?? rawRow?.date_pt ?? '', dt.datePt, 32);
  const timePt = cleanStr(rawRow?.timePt ?? rawRow?.time_pt ?? '', dt.timePt, 40);
  const sessionId = cleanStr(rawRow?.sessionId ?? rawRow?.session_id ?? '', session.sessionId, 32);
  const sessionLabel = cleanStr(rawRow?.sessionLabel ?? rawRow?.session_label ?? '', session.sessionLabel, 64);

  return Object.freeze({
    tradeId,
    symbol,
    brokerId: brokerId || brokerLabel,
    brokerLabel,
    realizedNetUsd,
    retainedTradingUsd,
    bankSweepUsd,
    occurredAtUtc: dt.isoUtc || occurredAtRaw,
    localPt,
    utc,
    datePt,
    timePt,
    combined: `${localPt} (${utc})`,
    sessionId,
    sessionLabel,
    _sortMs: parsedMs,
    _sortIdx: index,
  });
}

function aggregateRealizedRows(realizedRows, syntheticTotalUsd, syntheticCount) {
  const byBrokerMap = new Map();
  const byMarketMap = new Map();
  const bySessionMap = new Map();
  let realTotalUsd = '0.00';

  for (const row of realizedRows) {
    realTotalUsd = addDecimalStrings(realTotalUsd, row.realizedNetUsd);
    const cmp = compareDecimalStrings(row.realizedNetUsd, '0');
    const isWin = cmp > 0 ? 1 : 0;
    const isLoss = cmp < 0 ? 1 : 0;

    const bKey = row.brokerLabel;
    if (!byBrokerMap.has(bKey)) {
      byBrokerMap.set(bKey, {
        brokerId: row.brokerId,
        brokerLabel: row.brokerLabel,
        totalRealizedUsd: '0.00',
        tradeCount: 0,
        winCount: 0,
        lossCount: 0,
        markets: [],
        sessions: [],
        lastOccurredAtUtc: row.occurredAtUtc,
        lastLocalPt: row.localPt,
        lastUtc: row.utc,
        lastSessionId: row.sessionId,
        lastSessionLabel: row.sessionLabel,
      });
    }
    const bAgg = byBrokerMap.get(bKey);
    bAgg.totalRealizedUsd = addDecimalStrings(bAgg.totalRealizedUsd, row.realizedNetUsd);
    bAgg.tradeCount += 1;
    bAgg.winCount += isWin;
    bAgg.lossCount += isLoss;
    if (!bAgg.markets.includes(row.symbol)) bAgg.markets.push(row.symbol);
    if (!bAgg.sessions.includes(row.sessionLabel)) bAgg.sessions.push(row.sessionLabel);

    const mKey = row.symbol;
    if (!byMarketMap.has(mKey)) {
      byMarketMap.set(mKey, {
        symbol: row.symbol,
        totalRealizedUsd: '0.00',
        tradeCount: 0,
        winCount: 0,
        lossCount: 0,
        brokers: [],
        sessions: [],
        lastOccurredAtUtc: row.occurredAtUtc,
        lastLocalPt: row.localPt,
        lastUtc: row.utc,
        lastSessionId: row.sessionId,
        lastSessionLabel: row.sessionLabel,
      });
    }
    const mAgg = byMarketMap.get(mKey);
    mAgg.totalRealizedUsd = addDecimalStrings(mAgg.totalRealizedUsd, row.realizedNetUsd);
    mAgg.tradeCount += 1;
    mAgg.winCount += isWin;
    mAgg.lossCount += isLoss;
    if (!mAgg.brokers.includes(row.brokerLabel)) mAgg.brokers.push(row.brokerLabel);
    if (!mAgg.sessions.includes(row.sessionLabel)) mAgg.sessions.push(row.sessionLabel);

    const sKey = row.sessionId;
    if (!bySessionMap.has(sKey)) {
      bySessionMap.set(sKey, {
        sessionId: row.sessionId,
        sessionLabel: row.sessionLabel,
        totalRealizedUsd: '0.00',
        tradeCount: 0,
        markets: [],
        brokers: [],
        lastOccurredAtUtc: row.occurredAtUtc,
        lastLocalPt: row.localPt,
        lastUtc: row.utc,
      });
    }
    const sAgg = bySessionMap.get(sKey);
    sAgg.totalRealizedUsd = addDecimalStrings(sAgg.totalRealizedUsd, row.realizedNetUsd);
    sAgg.tradeCount += 1;
    if (!sAgg.markets.includes(row.symbol)) sAgg.markets.push(row.symbol);
    if (!sAgg.brokers.includes(row.brokerLabel)) sAgg.brokers.push(row.brokerLabel);
  }

  const sortByAbsTotal = (a, b, tieKey) => {
    const absCmp = compareDecimalStrings(absDecimalString(b.totalRealizedUsd), absDecimalString(a.totalRealizedUsd));
    if (absCmp !== 0) return absCmp;
    return String(a[tieKey]).localeCompare(String(b[tieKey]));
  };

  const byBroker = [...byBrokerMap.values()]
    .sort((a, b) => sortByAbsTotal(a, b, 'brokerLabel'))
    .map((entry) => Object.freeze({
      ...entry,
      markets: Object.freeze(entry.markets),
      sessions: Object.freeze(entry.sessions),
    }));

  const byMarket = [...byMarketMap.values()]
    .sort((a, b) => sortByAbsTotal(a, b, 'symbol'))
    .map((entry) => Object.freeze({
      ...entry,
      brokers: Object.freeze(entry.brokers),
      sessions: Object.freeze(entry.sessions),
    }));

  const bySession = [...bySessionMap.values()]
    .sort((a, b) => sortByAbsTotal(a, b, 'sessionId'))
    .map((entry) => Object.freeze({
      ...entry,
      markets: Object.freeze(entry.markets),
      brokers: Object.freeze(entry.brokers),
    }));

  const combinedTotal = addDecimalStrings(realTotalUsd, syntheticTotalUsd);

  return {
    byBroker: Object.freeze(byBroker),
    byMarket: Object.freeze(byMarket),
    bySession: Object.freeze(bySession),
    totals: Object.freeze({
      realTradeRealizedUsd: realTotalUsd,
      syntheticAdjustmentUsd: syntheticTotalUsd,
      combinedTotalRealizedUsd: combinedTotal,
      realTradeCount: realizedRows.length,
      syntheticRowCount: syntheticCount,
    }),
  };
}

export function deriveRealizedProvenanceFromState(state) {
  const safeState = state && typeof state === 'object' ? state : {};
  const trader = safeState.aiTrader && typeof safeState.aiTrader === 'object' ? safeState.aiTrader : {};
  const treasury = safeState.treasury && typeof safeState.treasury === 'object' ? safeState.treasury : {};
  const openPositions = Array.isArray(trader.openPositions)
    ? trader.openPositions
    : (Array.isArray(trader.open_positions) ? trader.open_positions : []);

  const backendProv = trader.realizedProvenance
    ?? trader.realized_provenance
    ?? safeState.realizedProvenance
    ?? safeState.realized_provenance
    ?? null;

  if (backendProv && typeof backendProv === 'object' && !Array.isArray(backendProv)) {
    const rawEntries = Array.isArray(backendProv.realizedEntries)
      ? backendProv.realizedEntries
      : (Array.isArray(backendProv.realized_entries)
        ? backendProv.realized_entries
        : (Array.isArray(backendProv.realizedRows) ? backendProv.realizedRows : []));

    const realRows = [];
    let syntheticTotal = numStr(
      backendProv.totals?.syntheticAdjustmentUsd ?? backendProv.totals?.synthetic_adjustment_usd,
      '0.00',
    );
    let syntheticCount = Number.isSafeInteger(backendProv.totals?.syntheticRowCount ?? backendProv.totals?.synthetic_row_count)
      ? Number(backendProv.totals?.syntheticRowCount ?? backendProv.totals?.synthetic_row_count)
      : 0;

    rawEntries.forEach((row, idx) => {
      if (isSyntheticSweepRow(row)) {
        syntheticTotal = addDecimalStrings(syntheticTotal, numStr(row?.realizedNetUsd ?? row?.realized_net_usd, '0'));
        syntheticCount += 1;
        return;
      }
      realRows.push(normalizeProvenanceRow(row, idx));
    });

    realRows.sort((a, b) => (b._sortMs - a._sortMs) || (b._sortIdx - a._sortIdx));
    const cleanRows = Object.freeze(realRows.map(({ _sortMs, _sortIdx, ...rest }) => Object.freeze(rest)));
    const aggregated = aggregateRealizedRows(cleanRows, syntheticTotal, syntheticCount);

    const liveStatus = backendProv.liveTradingStatus ?? backendProv.live_trading_status ?? null;
    const derivedStatus = computeStatusFromState(safeState, openPositions);
    const statusCode = cleanStr(liveStatus?.stateCode ?? liveStatus?.state_code ?? backendProv.statusCode ?? '', derivedStatus.statusCode, 40);
    const isCurrentlyTrading = typeof (liveStatus?.isCurrentlyTrading ?? liveStatus?.is_currently_trading ?? backendProv.isCurrentlyTrading) === 'boolean'
      ? Boolean(liveStatus?.isCurrentlyTrading ?? liveStatus?.is_currently_trading ?? backendProv.isCurrentlyTrading)
      : derivedStatus.isCurrentlyTrading;
    const statusHeadline = cleanStr(liveStatus?.headline ?? backendProv.statusHeadline ?? '', derivedStatus.statusHeadline, 180);
    const openMarkets = Array.isArray(liveStatus?.openMarkets ?? liveStatus?.open_markets ?? backendProv.openMarkets)
      ? uniqueStrings((liveStatus?.openMarkets ?? liveStatus?.open_markets ?? backendProv.openMarkets).filter((m) => !isSyntheticMarker(m)))
      : derivedStatus.openMarkets;
    const openBrokers = Array.isArray(liveStatus?.openBrokers ?? liveStatus?.open_brokers ?? backendProv.openBrokers)
      ? uniqueStrings((liveStatus?.openBrokers ?? liveStatus?.open_brokers ?? backendProv.openBrokers).map((b) => formatBrokerDisplayName(b)).filter(Boolean))
      : derivedStatus.openBrokers;

    const rawLast = backendProv.lastRealTrade ?? backendProv.last_real_trade ?? null;
    let lastRealTrade = cleanRows[0] ?? null;
    if (!lastRealTrade && rawLast && typeof rawLast === 'object' && !isSyntheticSweepRow(rawLast)) {
      const { _sortMs, _sortIdx, ...normalizedLast } = normalizeProvenanceRow(rawLast, 0);
      lastRealTrade = Object.freeze(normalizedLast);
    }

    return Object.freeze({
      isCurrentlyTrading,
      statusCode,
      statusHeadline,
      openPositionCount: Number.isSafeInteger(liveStatus?.openPositionCount ?? liveStatus?.open_position_count)
        ? Number(liveStatus?.openPositionCount ?? liveStatus?.open_position_count)
        : openPositions.length,
      openMarkets: Object.freeze(openMarkets),
      openBrokers: Object.freeze(openBrokers),
      lastRealTrade,
      byBroker: aggregated.byBroker,
      byMarket: aggregated.byMarket,
      bySession: aggregated.bySession,
      realizedRows: cleanRows,
      totals: aggregated.totals,
    });
  }

  const rawSweeps = Array.isArray(treasury.recentSweeps)
    ? treasury.recentSweeps
    : (Array.isArray(treasury.recent_sweeps) ? treasury.recent_sweeps : []);

  const realRows = [];
  let syntheticTotal = '0.00';
  let syntheticCount = 0;

  rawSweeps.forEach((sweep, idx) => {
    if (isSyntheticSweepRow(sweep)) {
      syntheticTotal = addDecimalStrings(syntheticTotal, numStr(sweep?.realizedNetUsd ?? sweep?.realized_net_usd, '0'));
      syntheticCount += 1;
      return;
    }
    realRows.push(normalizeProvenanceRow(sweep, idx));
  });

  realRows.sort((a, b) => (b._sortMs - a._sortMs) || (b._sortIdx - a._sortIdx));
  const cleanRows = Object.freeze(realRows.map(({ _sortMs, _sortIdx, ...rest }) => Object.freeze(rest)));
  const aggregated = aggregateRealizedRows(cleanRows, syntheticTotal, syntheticCount);
  const status = computeStatusFromState(safeState, openPositions);

  return Object.freeze({
    isCurrentlyTrading: status.isCurrentlyTrading,
    statusCode: status.statusCode,
    statusHeadline: status.statusHeadline,
    openPositionCount: status.openPositionCount,
    openMarkets: Object.freeze(status.openMarkets),
    openBrokers: Object.freeze(status.openBrokers),
    lastRealTrade: cleanRows[0] ?? null,
    byBroker: aggregated.byBroker,
    byMarket: aggregated.byMarket,
    bySession: aggregated.bySession,
    realizedRows: cleanRows,
    totals: aggregated.totals,
  });
}

function statusBadgeDescriptor(statusCode) {
  switch (statusCode) {
    case 'TRADING_NOW':
      return { label: 'TRADING NOW', cls: 'status-badge status-trading-now status-pulse' };
    case 'PAUSED_RESEARCH_RESPITE':
      return { label: 'PAUSED \u2014 RESEARCH RESPITE', cls: 'status-badge status-respite' };
    case 'PAUSED_SAFETY_LOCK':
      return { label: 'PAUSED \u2014 SAFETY LOCK', cls: 'status-badge status-safety-lock' };
    default:
      return { label: 'ACTIVE \u2014 SCANNING', cls: 'status-badge status-scanning' };
  }
}

export function renderImmediateStatusAndLastTradeStrip(state) {
  const prov = deriveRealizedProvenanceFromState(state);
  const badge = statusBadgeDescriptor(prov.statusCode);
  const last = prov.lastRealTrade;

  const openContextHtml = prov.isCurrentlyTrading
    ? `<div class="top-strip-open-pills">${prov.openMarkets.map((m) => `<span class="open-market-pill">${esc(m)}</span>`).join('')}${prov.openBrokers.map((b) => `<span class="open-broker-pill">${esc(b)}</span>`).join('')}</div>`
    : '';

  const lastTradeHtml = last
    ? `<div class="last-trade-stamp" data-last-real-trade="${esc(last.tradeId)}">
        <span class="stamp-kicker">Last Real Trade</span>
        <strong class="stamp-pnl ${pnlToneClass(last.realizedNetUsd)}">${esc(formatSignedUsd(last.realizedNetUsd))}</strong>
        <span class="stamp-market">${esc(last.symbol)}</span>
        <span class="stamp-broker">${esc(last.brokerLabel)}</span>
        <span class="stamp-session">${esc(last.sessionLabel)}</span>
        <span class="stamp-time-pt">${esc(last.localPt)}</span>
        <span class="stamp-time-utc">${esc(last.utc)}</span>
      </div>`
    : `<div class="last-trade-stamp last-trade-empty" data-last-real-trade="NONE">
        <span class="stamp-kicker">Last Real Trade</span>
        <span class="stamp-empty-copy">No real closed trades recorded yet</span>
      </div>`;

  const brokerChipsHtml = prov.byBroker.length
    ? prov.byBroker.map((b) => (
      `<span class="broker-win-chip ${pnlToneClass(b.totalRealizedUsd)}" data-broker-chip="${esc(b.brokerLabel)}">`
      + `<span class="chip-name">${esc(b.brokerLabel)}</span>: `
      + `<strong class="chip-val">${esc(formatSignedUsd(b.totalRealizedUsd))}</strong>`
      + `</span>`
    )).join('')
    : '<span class="chip-empty">No broker-attributed closed wins yet</span>';

  const marketChipsHtml = prov.byMarket.length
    ? prov.byMarket.map((m) => (
      `<span class="market-win-chip ${pnlToneClass(m.totalRealizedUsd)}" data-market-chip="${esc(m.symbol)}">`
      + `<span class="chip-name">${esc(m.symbol)}</span>: `
      + `<strong class="chip-val">${esc(formatSignedUsd(m.totalRealizedUsd))}</strong>`
      + `</span>`
    )).join('')
    : '<span class="chip-empty">No market-attributed closed wins yet</span>';

  return `<section class="top-status-strip" data-top-status-strip data-trading-state="${esc(prov.statusCode)}" aria-label="Live trading status and realized trade provenance">
    <div class="top-strip-primary">
      <div class="top-strip-status-block">
        <span class="${badge.cls}" data-status-badge="${esc(prov.statusCode)}">${esc(badge.label)}</span>
        <span class="top-strip-headline">${esc(prov.statusHeadline)}</span>
        ${openContextHtml}
      </div>
      ${lastTradeHtml}
    </div>
    <div class="top-strip-attribution-row">
      <div class="chip-group" aria-label="Broker account realized P/L">
        <span class="chip-group-label">Broker Accounts</span>
        ${brokerChipsHtml}
      </div>
      <div class="chip-group" aria-label="Market realized P/L">
        <span class="chip-group-label">Markets</span>
        ${marketChipsHtml}
      </div>
    </div>
  </section>`;
}

export function renderRealizedPnlProvenanceTable(state) {
  const prov = deriveRealizedProvenanceFromState(state);
  const rowsHtml = prov.realizedRows.length
    ? prov.realizedRows.map((row) => (
      `<tr data-provenance-trade="${esc(row.tradeId)}">`
      + `<td class="prov-pnl ${pnlToneClass(row.realizedNetUsd)}"><strong>${esc(formatSignedUsd(row.realizedNetUsd))}</strong></td>`
      + `<td class="prov-datetime"><span class="prov-pt">${esc(row.localPt)}</span> <span class="prov-utc">${esc(row.utc)}</span></td>`
      + `<td class="prov-session">${esc(row.sessionLabel)}</td>`
      + `<td class="prov-market"><strong>${esc(row.symbol)}</strong></td>`
      + `<td class="prov-broker"><span class="broker-pill">${esc(row.brokerLabel)}</span></td>`
      + `</tr>`
    )).join('')
    : `<tr><td colspan="5" class="prov-empty-row">No real closed trades recorded yet. Synthetic reconciliation rows are excluded from trade attribution.</td></tr>`;

  const syntheticNote = prov.totals.syntheticRowCount > 0
    ? `<span class="prov-synthetic-note">Excluded ${esc(prov.totals.syntheticRowCount)} synthetic sync adjustment row(s): ${esc(formatSignedUsd(prov.totals.syntheticAdjustmentUsd))} (Combined ledger: ${esc(formatSignedUsd(prov.totals.combinedTotalRealizedUsd))})</span>`
    : '';

  return `<section class="provenance-ledger-section" data-realized-provenance-table aria-label="Realized profit and loss provenance ledger">
    <div class="provenance-summary-bar">
      <h3 class="provenance-heading">Realized P/L Provenance Ledger</h3>
      <span class="provenance-total ${pnlToneClass(prov.totals.realTradeRealizedUsd)}">Real Closed P/L (${esc(prov.totals.realTradeCount)}): <strong>${esc(formatSignedUsd(prov.totals.realTradeRealizedUsd))}</strong></span>
      ${syntheticNote}
    </div>
    <table class="provenance-table">
      <thead>
        <tr>
          <th>Exact P/L</th>
          <th>Date &amp; Time (PT + UTC)</th>
          <th>Session</th>
          <th>Market</th>
          <th>Broker Account</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    </table>
  </section>`;
}

// ---------------------------------------------------------------------------
// 2. True Thermal Market Signal Heatmap (Strict CSP, Zero Inline Styles)
// ---------------------------------------------------------------------------

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

function candleMovePct(bars) {
  if (!Array.isArray(bars) || bars.length === 0) return 0;
  const recent = bars.slice(-3);
  const firstOpen = Number(recent[0]?.o);
  const lastClose = Number(recent[recent.length - 1]?.c);
  if (!Number.isFinite(firstOpen) || !Number.isFinite(lastClose) || firstOpen <= 0) return 0;
  return ((lastClose - firstOpen) / firstOpen) * 100;
}

function classifyHeatBand(tempScore) {
  if (tempScore >= 50) return { heatClass: 'heat-hot-buy', heatLabel: 'HOT BUY' };
  if (tempScore >= 15) return { heatClass: 'heat-warm-buy', heatLabel: 'WARM BUY' };
  if (tempScore > -15) return { heatClass: 'heat-neutral', heatLabel: 'NEUTRAL' };
  if (tempScore > -50) return { heatClass: 'heat-cool-sell', heatLabel: 'COOL SELL' };
  return { heatClass: 'heat-cold-sell', heatLabel: 'COLD SELL' };
}

function classifySpread(pairKey, isIndex, spreadNum) {
  if (!Number.isFinite(spreadNum) || spreadNum < 0) {
    return { spreadClass: 'spread-normal', spreadLabel: 'NORMAL' };
  }
  if (isIndex) {
    const tightMax = TIGHT_INDEX_SYMBOLS.has(pairKey) ? 0.6 : 2.0;
    const normalMax = TIGHT_INDEX_SYMBOLS.has(pairKey) ? 1.5 : 5.0;
    if (spreadNum <= tightMax) return { spreadClass: 'spread-tight', spreadLabel: 'TIGHT' };
    if (spreadNum <= normalMax) return { spreadClass: 'spread-normal', spreadLabel: 'NORMAL' };
    return { spreadClass: 'spread-wide', spreadLabel: 'WIDE' };
  }
  if (spreadNum <= 1.2) return { spreadClass: 'spread-tight', spreadLabel: 'TIGHT' };
  if (spreadNum <= 2.5) return { spreadClass: 'spread-normal', spreadLabel: 'NORMAL' };
  return { spreadClass: 'spread-wide', spreadLabel: 'WIDE' };
}

function classifyValve(rawScore) {
  const s = numStr(rawScore, '');
  const numeric = s ? Number(s) : Number.NaN;
  if (!Number.isFinite(numeric)) {
    return {
      valveScore: 'Unknown',
      valveHeatClass: 'valve-blocked',
      valveLabel: 'VALVE PENDING',
      valveMeterClass: 'meter-pct-0',
    };
  }
  const normalized = clamp(numeric, 0, 1);
  let valveHeatClass = 'valve-blocked';
  let valveLabel = 'VALVE BLOCKED';
  if (normalized >= VALVE_SCORE_CUTOFF) {
    valveHeatClass = 'valve-pass';
    valveLabel = 'VALVE PASS';
  } else if (normalized >= 0.40) {
    valveHeatClass = 'valve-borderline';
    valveLabel = 'VALVE BORDERLINE';
  }
  return {
    valveScore: s,
    valveHeatClass,
    valveLabel,
    valveMeterClass: quantizeMeterPctClass(normalized * 100),
  };
}

function actionDirectionScore(actions) {
  if (!actions.length) return 0;
  let score = 0;
  for (const act of actions) {
    const token = `${cleanStr(act?.kind, '', 60)} ${cleanStr(act?.detail, '', 180)}`.toUpperCase();
    const isBuy = /\b(BUY|LONG|ADD_BUY|OPEN_BUY|BULLISH|BREAKOUT_UP)\b/.test(token);
    const isSell = /\b(SELL|SHORT|ADD_SELL|OPEN_SELL|BEARISH|BREAKDOWN_DOWN)\b/.test(token);
    if (isBuy && !isSell) score += 20;
    else if (isSell && !isBuy) score -= 20;
  }
  return clamp(score, -30, 30);
}

export function computeMarketTemperatureTiles(state) {
  const safeState = state && typeof state === 'object' ? state : {};
  const indexMarkets = Array.isArray(safeState.indexStream?.markets) ? safeState.indexStream.markets : [];
  const fxStreams = Array.isArray(safeState.marketStream?.streams) ? safeState.marketStream.streams : [];
  const trader = safeState.aiTrader && typeof safeState.aiTrader === 'object' ? safeState.aiTrader : {};
  const recentActions = Array.isArray(trader.recentActions) ? trader.recentActions : [];
  const openPositions = Array.isArray(trader.openPositions) ? trader.openPositions : [];
  const globalValveScore = trader.lastValveScore ?? trader.last_valve_score ?? 'Unknown';

  const merged = [];
  const seenKeys = new Set();

  const pushMarket = (row, defaultIsIndex) => {
    if (!row || typeof row !== 'object') return;
    const rawPair = cleanStr(row.pair ?? row.symbol ?? '', '', 40);
    const pairKey = normalizeSymbolKey(rawPair);
    if (!pairKey || seenKeys.has(pairKey) || isSyntheticMarker(pairKey)) return;
    seenKeys.add(pairKey);

    const isIndex = defaultIsIndex || INDEX_SYMBOLS.has(pairKey) || cleanStr(row.category, '', 32).toUpperCase() === 'US_INDEX';
    const displayPair = cleanStr(row.display_pair ?? row.displayPair ?? rawPair, rawPair, 60);
    const bid = numStr(row.bid, '0');
    const ask = numStr(row.ask, '0');
    const change24hPct = numStr(row.change_24h_pct ?? row.change24hPct, '0.00');
    const rawSpread = row.spread_points ?? row.spread_pips ?? row.spreadPoints ?? row.spreadPips;
    const spreadFallback = Number.isFinite(Number(ask) - Number(bid)) ? String(Math.max(0, Number(ask) - Number(bid))) : '0';
    const spreadValue = numStr(rawSpread, spreadFallback);
    const spreadUnit = isIndex ? 'pts' : 'pips';

    const m1Pct = candleMovePct(row.candles_m1 ?? row.candlesM1);
    const m5Pct = candleMovePct(row.candles_m5 ?? row.candlesM5);
    const change24hNum = Number(change24hPct);

    const matchingActions = recentActions.filter((a) => normalizeSymbolKey(a?.symbol ?? '') === pairKey);
    const matchingPos = openPositions.find((p) => normalizeSymbolKey(p?.symbol ?? p?.instrument_id ?? '') === pairKey) ?? null;

    const volScale = isIndex ? 0.25 : 0.10;
    const scale24h = isIndex ? 2.0 : 1.0;
    const m1Component = clamp((m1Pct / volScale) * 35, -40, 40);
    const m5Component = clamp((m5Pct / (volScale * 1.6)) * 25, -30, 30);
    const changeComponent = Number.isFinite(change24hNum) ? clamp((change24hNum / scale24h) * 40, -45, 45) : 0;
    const signalComponent = actionDirectionScore(matchingActions);

    const tempScore = Math.round(clamp(m1Component + m5Component + changeComponent + signalComponent, -100, 100));
    const heat = classifyHeatBand(tempScore);
    const spreadInfo = classifySpread(pairKey, isIndex, Number(spreadValue));
    const perMarketValve = row.valve_score ?? row.valveScore ?? globalValveScore;
    const valveInfo = classifyValve(perMarketValve);

    const combinedMom = m1Pct !== 0 ? m1Pct : (m5Pct !== 0 ? m5Pct : (Number.isFinite(change24hNum) ? change24hNum : 0));
    const momentumDirection = combinedMom > 0.0001 ? 'UP' : (combinedMom < -0.0001 ? 'DOWN' : 'FLAT');
    const lastAction = matchingActions.length ? matchingActions[matchingActions.length - 1] : null;

    merged.push(Object.freeze({
      pair: rawPair || pairKey,
      pairKey,
      displayPair,
      assetClass: isIndex ? 'INDEX_METAL' : 'FX',
      category: cleanStr(row.category, isIndex ? 'US_INDEX' : 'FX', 32),
      bid,
      ask,
      change24hPct,
      spreadValue,
      spreadUnit,
      spreadClass: spreadInfo.spreadClass,
      spreadLabel: spreadInfo.spreadLabel,
      tempScore,
      heatClass: heat.heatClass,
      heatLabel: heat.heatLabel,
      heatMeterClass: quantizeMeterPctClass(Math.abs(tempScore)),
      momentumDirection,
      signalCount: matchingActions.length,
      lastActionKind: lastAction ? cleanStr(lastAction.kind, 'INFO', 48) : 'SCANNING',
      lastActionDetail: lastAction ? cleanStr(lastAction.detail, 'Monitored', 160) : 'Live feed active',
      lastActionAt: lastAction ? cleanStr(lastAction.observedAt ?? lastAction.observed_at ?? '', '', 64) : '',
      hasOpenPosition: Boolean(matchingPos),
      openSide: matchingPos ? cleanStr(matchingPos.side, 'BUY', 12) : null,
      openBrokerLabel: matchingPos ? formatBrokerDisplayName(matchingPos.broker_id ?? matchingPos.brokerId ?? '') : null,
      valveScore: valveInfo.valveScore,
      valveHeatClass: valveInfo.valveHeatClass,
      valveLabel: valveInfo.valveLabel,
      valveMeterClass: valveInfo.valveMeterClass,
    }));
  };

  indexMarkets.forEach((m) => pushMarket(m, true));
  fxStreams.forEach((s) => pushMarket(s, false));

  return Object.freeze(merged);
}

export function renderThermalMarketHeatmap(state) {
  const tiles = computeMarketTemperatureTiles(state);
  const momGlyph = (dir) => (dir === 'UP' ? '\u25b2' : (dir === 'DOWN' ? '\u25bc' : '\u25ac'));
  const formatSignedPct = (raw) => {
    const s = numStr(raw, '0.00');
    if (s.startsWith('-') || Number(s) === 0) return `${s}%`;
    return `+${s}%`;
  };

  const tilesHtml = tiles.length
    ? tiles.map((tile) => {
      const openBadge = tile.hasOpenPosition
        ? `<span class="tile-open-badge">${esc(tile.openSide)}${tile.openBrokerLabel ? ` \u00b7 ${esc(tile.openBrokerLabel)}` : ''}</span>`
        : '';
      const scoreText = tile.tempScore > 0 ? `+${tile.tempScore}` : String(tile.tempScore);
      return `<article class="thermal-tile ${tile.heatClass}" data-thermal-tile="${esc(tile.pair)}" data-heat-band="${esc(tile.heatClass)}">
        <div class="thermal-tile-top">
          <div class="thermal-pair-group">
            <strong class="thermal-pair-name">${esc(tile.displayPair)}</strong>
            ${openBadge}
          </div>
          <span class="thermal-heat-badge ${tile.heatClass}">${esc(tile.heatLabel)} (${esc(scoreText)})</span>
        </div>
        <div class="thermal-quote-row">
          <span class="thermal-quote">Bid <strong>${esc(tile.bid)}</strong></span>
          <span class="thermal-quote">Ask <strong>${esc(tile.ask)}</strong></span>
        </div>
        <div class="thermal-metrics-row">
          <span class="thermal-change ${tile.tempScore >= 0 ? 'pnl-pos' : 'pnl-neg'}">${esc(momGlyph(tile.momentumDirection))} 24h ${esc(formatSignedPct(tile.change24hPct))}</span>
          <span class="spread-badge ${tile.spreadClass}">Spread ${esc(tile.spreadValue)} ${esc(tile.spreadUnit)} \u00b7 ${esc(tile.spreadLabel)}</span>
        </div>
        <div class="thermal-signals-row">
          <span class="thermal-signal-count">Signals: <strong>${esc(tile.signalCount)}</strong></span>
          <span class="thermal-last-action"><code>${esc(tile.lastActionKind)}</code> ${esc(tile.lastActionDetail)}</span>
        </div>
        <div class="thermal-valve-row">
          <div class="thermal-valve-meta">
            <span class="valve-badge ${tile.valveHeatClass}">${esc(tile.valveLabel)}</span>
            <span class="valve-score-readout">Valve ${esc(tile.valveScore)} / 0.55</span>
          </div>
          <div class="meter-track" role="progressbar" aria-label="Safety valve readiness for ${esc(tile.displayPair)}">
            <div class="meter-fill ${tile.valveHeatClass} ${tile.valveMeterClass}"></div>
          </div>
        </div>
      </article>`;
    }).join('')
    : '<p class="thermal-empty">Awaiting live index and FX market streams for thermal signal mapping.</p>';

  return `<section class="thermal-heatmap-section" data-thermal-heatmap aria-label="Thermal market signal heatmap">
    <div class="thermal-header">
      <h3 class="thermal-heading">Thermal Market Signal Heatmap (${esc(tiles.length)} Markets)</h3>
      <div class="thermal-legend" aria-label="Temperature scale legend">
        <span class="legend-chip heat-cold-sell">COLD SELL</span>
        <span class="legend-chip heat-cool-sell">COOL SELL</span>
        <span class="legend-chip heat-neutral">NEUTRAL</span>
        <span class="legend-chip heat-warm-buy">WARM BUY</span>
        <span class="legend-chip heat-hot-buy">HOT BUY</span>
      </div>
    </div>
    <div class="thermal-grid">${tilesHtml}</div>
  </section>`;
}

// ---------------------------------------------------------------------------
// 3. Dark-Mode Obsidian Vault Progress Card & Canvas Chart Renderers
// ---------------------------------------------------------------------------

function extractVaultMetrics(state) {
  const safeState = state && typeof state === 'object' ? state : {};
  const trader = safeState.aiTrader && typeof safeState.aiTrader === 'object' ? safeState.aiTrader : {};
  const bs = trader.bankedSession && typeof trader.bankedSession === 'object' ? trader.bankedSession : {};
  const treasury = safeState.treasury && typeof safeState.treasury === 'object' ? safeState.treasury : {};
  const tiers = Array.isArray(safeState.parallelTiers?.tiers) ? safeState.parallelTiers.tiers : [];
  const tier1 = tiers.find((t) => t?.tierId === 'TIER_1_CURRENT') ?? tiers[0] ?? null;

  const initialCapitalUsd = numStr(
    bs.initialCapitalUsd ?? trader.initialCapitalUsd ?? tier1?.startingCapitalUsd,
    DEFAULT_PRINCIPAL_USD,
  );
  const currentTotalEquityUsd = numStr(
    bs.currentTotalEquityUsd ?? trader.currentTotalEquityUsd ?? tier1?.equityUsd,
    initialCapitalUsd,
  );
  const confirmedSettledDisbursedUsd = numStr(
    treasury.confirmedSettledDisbursedUsd ?? bs.confirmedBankPayoutsUsd ?? trader.confirmedBankPayoutsUsd,
    '0.00',
  );
  const pendingUnconfirmedTransfersUsd = numStr(
    treasury.pendingUnconfirmedTransfersUsd ?? bs.pendingUnconfirmedTransfersUsd ?? trader.pendingUnconfirmedTransfersUsd,
    '0.00',
  );
  const totalRealizedProfitUsd = numStr(
    treasury.totalRealizedProfitUsd ?? bs.bankedNetPnlUsd,
    '0.00',
  );
  const retainedTradingUsd = numStr(
    treasury.retainedTradingUsd ?? bs.vaultRetained50PctUsd,
    '0.00',
  );
  const bankSweepReservedUsd = numStr(
    treasury.bankSweepReservedUsd ?? bs.vaultSwept50PctUsd ?? trader.bankSweepReservedUsd,
    '0.00',
  );

  const effectiveEquityUsd = addDecimalStrings(currentTotalEquityUsd, confirmedSettledDisbursedUsd);
  const diffFromPrincipal = subDecimalStrings(effectiveEquityUsd, initialCapitalUsd);
  const isUnderwater = compareDecimalStrings(diffFromPrincipal, '0') < 0;

  const explicitCapStatus = cleanStr(bs.capitalStatus ?? trader.capitalStatus ?? '', '', 32).toUpperCase();
  const inRecoveryMode = explicitCapStatus === 'RECOVERY_MODE'
    || (explicitCapStatus !== 'IN_SURPLUS' && (isUnderwater || Boolean(bs.vaultSweepsPausedForRecovery ?? trader.vaultSweepsPausedForRecovery)));

  const deficitToPrincipalUsd = isUnderwater
    ? absDecimalString(diffFromPrincipal)
    : numStr(bs.deficitToPrincipalUsd, '0.00');
  const netSurplusUsd = !isUnderwater ? diffFromPrincipal : '0.00';

  const initNum = Number(initialCapitalUsd);
  const effNum = Number(effectiveEquityUsd);
  const recoveryPct = initNum > 0 && Number.isFinite(effNum)
    ? clamp((effNum / initNum) * 100, 0, 100)
    : 0;

  return {
    initialCapitalUsd,
    currentTotalEquityUsd,
    effectiveEquityUsd,
    confirmedSettledDisbursedUsd,
    pendingUnconfirmedTransfersUsd,
    totalRealizedProfitUsd,
    retainedTradingUsd,
    bankSweepReservedUsd,
    deficitToPrincipalUsd,
    netSurplusUsd,
    inRecoveryMode,
    recoveryPct,
    recoveryMeterClass: quantizeMeterPctClass(inRecoveryMode ? recoveryPct : 100),
    peakEquityUsd: numStr(tier1?.peakEquityUsd ?? bs.peakEquityUsd, initialCapitalUsd),
    tierDrawdownPct: tier1?.drawdownPct ?? null,
  };
}

export function renderObsidianVaultProgressCard(state) {
  const m = extractVaultMetrics(state);
  const prov = deriveRealizedProvenanceFromState(state);

  const modeLabel = m.inRecoveryMode
    ? '100% Rebuilding Principal'
    : '50% Compounding / 50% Bank Vault';
  const modeClass = m.inRecoveryMode ? 'vault-mode-recovery' : 'vault-mode-surplus';
  const progressCaption = m.inRecoveryMode
    ? `${formatExactUsd(m.deficitToPrincipalUsd)} remaining to restore ${formatExactUsd(m.initialCapitalUsd)} Principal High-Water Mark ($0.00 new vault sweeps while underwater)`
    : `${formatExactUsd(m.netSurplusUsd)} net surplus above ${formatExactUsd(m.initialCapitalUsd)} Principal High-Water Mark`;

  const brokerSummaryHtml = prov.byBroker.length
    ? prov.byBroker.map((b) => (
      `<span class="broker-win-chip ${pnlToneClass(b.totalRealizedUsd)}" data-vault-broker="${esc(b.brokerLabel)}">`
      + `${esc(b.brokerLabel)}: <strong>${esc(formatSignedUsd(b.totalRealizedUsd))}</strong> (${esc(b.tradeCount)} trades)`
      + `</span>`
    )).join('')
    : '<span class="chip-empty">Awaiting broker-attributed realized closes</span>';

  return `<section class="obsidian-vault-card ${modeClass}" data-obsidian-vault-card data-vault-mode="${m.inRecoveryMode ? 'RECOVERY_MODE' : 'IN_SURPLUS'}" aria-label="Obsidian principal recovery and bank vault progress">
    <div class="obsidian-vault-header">
      <div>
        <h3 class="obsidian-vault-title">Principal Recovery &amp; Bank Vault Progress</h3>
        <span class="vault-mode-pill ${modeClass}" data-vault-mode-label>${esc(modeLabel)}</span>
      </div>
      <div class="obsidian-vault-equity">
        <span class="vault-eq-label">Current Equity</span>
        <strong class="vault-eq-value">${esc(formatExactUsd(m.currentTotalEquityUsd))}</strong>
        <span class="vault-eq-goal">Goal: ${esc(formatExactUsd(m.initialCapitalUsd))}</span>
      </div>
    </div>
    <div class="vault-progress-block">
      <div class="vault-progress-track" role="progressbar" aria-label="Principal recovery progress">
        <div class="vault-progress-fill ${modeClass} ${m.recoveryMeterClass}"></div>
      </div>
      <p class="vault-progress-caption">${esc(progressCaption)}</p>
    </div>
    <div class="obsidian-vault-metrics">
      <div class="vault-metric-cell">
        <span class="vault-metric-label">Total Realized Profit</span>
        <strong class="vault-metric-val ${pnlToneClass(m.totalRealizedProfitUsd)}">${esc(formatSignedUsd(m.totalRealizedProfitUsd))}</strong>
      </div>
      <div class="vault-metric-cell">
        <span class="vault-metric-label">Retained Trading Capital</span>
        <strong class="vault-metric-val">${esc(formatExactUsd(m.retainedTradingUsd))}</strong>
      </div>
      <div class="vault-metric-cell">
        <span class="vault-metric-label">Bank Vault Reserve (Internal)</span>
        <strong class="vault-metric-val">${esc(formatExactUsd(m.bankSweepReservedUsd))}</strong>
      </div>
      <div class="vault-metric-cell">
        <span class="vault-metric-label">Pending / Unconfirmed Transfers</span>
        <strong class="vault-metric-val">${esc(formatExactUsd(m.pendingUnconfirmedTransfersUsd))}</strong>
      </div>
      <div class="vault-metric-cell">
        <span class="vault-metric-label">Confirmed Settled Disbursed</span>
        <strong class="vault-metric-val">${esc(formatExactUsd(m.confirmedSettledDisbursedUsd))}</strong>
      </div>
    </div>
    <div class="vault-broker-attribution">
      <span class="chip-group-label">Per-Broker Realized Attribution</span>
      ${brokerSummaryHtml}
    </div>
  </section>`;
}

function extractEquitySeriesPoints(state, metrics) {
  const growthSeries = state?.parallelTiers?.growthSeries ?? {};
  const tier1Pts = Array.isArray(growthSeries.TIER_1_CURRENT) && growthSeries.TIER_1_CURRENT.length
    ? growthSeries.TIER_1_CURRENT
    : null;
  const rawSeries = tier1Pts
    || (Array.isArray(state?.equityHistory) && state.equityHistory.length ? state.equityHistory : null);

  if (rawSeries) {
    const parsed = rawSeries
      .map((pt) => Number(pt?.equityUsd ?? pt?.equity_usd ?? pt?.equity ?? pt))
      .filter((v) => Number.isFinite(v));
    if (parsed.length >= 2) return parsed;
    if (parsed.length === 1) {
      const startEq = Number(metrics.initialCapitalUsd);
      return [Number.isFinite(startEq) ? startEq : parsed[0], parsed[0]];
    }
  }
  const startEq = Number(metrics.initialCapitalUsd);
  const curEq = Number(metrics.currentTotalEquityUsd);
  const safeStart = Number.isFinite(startEq) ? startEq : 300000;
  const safeCur = Number.isFinite(curEq) ? curEq : safeStart;
  return [safeStart, safeCur];
}

export function drawObsidianEquityVaultChart(canvas, state) {
  if (!canvas || typeof canvas.getContext !== 'function') return null;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const w = Number(canvas.getAttribute?.('width') ?? canvas.width) || 460;
  const h = Number(canvas.getAttribute?.('height') ?? canvas.height) || 210;
  const m = extractVaultMetrics(state);
  const eqPoints = extractEquitySeriesPoints(state, m);
  const principalGoal = Number(m.initialCapitalUsd) || 300000;
  const vaultReserved = Math.max(0, Number(m.bankSweepReservedUsd) || 0);
  const currentEq = eqPoints[eqPoints.length - 1];

  ctx.fillStyle = OBSIDIAN_BG_HEX;
  ctx.fillRect(0, 0, w, h);

  const padLeft = 74;
  const padRight = 18;
  const padTop = 26;
  const padBottom = 26;
  const plotW = Math.max(40, w - padLeft - padRight);
  const plotH = Math.max(40, h - padTop - padBottom);

  const upperValues = [...eqPoints.map((v) => v + vaultReserved), principalGoal];
  const lowerValues = [...eqPoints, principalGoal];
  const rawMin = Math.min(...lowerValues);
  const rawMax = Math.max(...upperValues);
  const rawSpan = Math.max(rawMax - rawMin, Math.max(250, principalGoal * 0.005));
  const yMin = rawMin - rawSpan * 0.14;
  const yMax = rawMax + rawSpan * 0.16;
  const ySpan = Math.max(1, yMax - yMin);

  const xAt = (idx) => padLeft + (idx / Math.max(1, eqPoints.length - 1)) * plotW;
  const yAt = (val) => padTop + ((yMax - val) / ySpan) * plotH;

  ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';
  const gridSteps = 4;
  for (let i = 0; i <= gridSteps; i += 1) {
    const ratio = i / gridSteps;
    const y = padTop + ratio * plotH;
    const tickVal = yMax - ratio * ySpan;
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(w - padRight, y);
    ctx.stroke();

    ctx.fillStyle = 'rgba(226,232,240,0.68)';
    ctx.fillText(formatExactUsd(tickVal.toFixed(2)), 6, y + 4);
  }

  if (vaultReserved > 0) {
    ctx.fillStyle = 'rgba(234,179,8,0.22)';
    ctx.beginPath();
    eqPoints.forEach((v, i) => {
      const x = xAt(i);
      const y = yAt(v + vaultReserved);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    for (let i = eqPoints.length - 1; i >= 0; i -= 1) {
      ctx.lineTo(xAt(i), yAt(eqPoints[i]));
    }
    ctx.closePath?.();
    ctx.fill();

    ctx.strokeStyle = '#eab308';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    eqPoints.forEach((v, i) => {
      const x = xAt(i);
      const y = yAt(v + vaultReserved);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  const goalY = yAt(principalGoal);
  ctx.strokeStyle = '#eab308';
  ctx.lineWidth = 1.25;
  ctx.setLineDash?.([5, 4]);
  ctx.beginPath();
  ctx.moveTo(padLeft, goalY);
  ctx.lineTo(w - padRight, goalY);
  ctx.stroke();
  ctx.setLineDash?.([]);
  ctx.fillStyle = '#facc15';
  ctx.fillText(`${formatExactUsd(m.initialCapitalUsd)} Principal Goal`, padLeft + 6, Math.max(padTop + 10, goalY - 5));

  const fillStyle = typeof ctx.createLinearGradient === 'function'
    ? (() => {
      const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
      grad.addColorStop?.(0, 'rgba(16,185,129,0.34)');
      grad.addColorStop?.(1, 'rgba(16,185,129,0.02)');
      return grad;
    })()
    : 'rgba(16,185,129,0.22)';

  ctx.fillStyle = fillStyle;
  ctx.beginPath();
  eqPoints.forEach((v, i) => {
    const x = xAt(i);
    const y = yAt(v);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(xAt(eqPoints.length - 1), padTop + plotH);
  ctx.lineTo(xAt(0), padTop + plotH);
  ctx.closePath?.();
  ctx.fill();

  ctx.strokeStyle = '#10b981';
  ctx.lineWidth = 2.25;
  ctx.beginPath();
  eqPoints.forEach((v, i) => {
    const x = xAt(i);
    const y = yAt(v);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.fillStyle = '#f8fafc';
  const vaultCallout = vaultReserved > 0 ? ` \u00b7 Vault ${formatExactUsd(m.bankSweepReservedUsd)}` : '';
  ctx.fillText(`Equity ${formatExactUsd(m.currentTotalEquityUsd)}${vaultCallout}`, padLeft, 16);

  return Object.freeze({
    background: OBSIDIAN_BG_HEX,
    pointCount: eqPoints.length,
    principalGoalUsd: m.initialCapitalUsd,
    currentEquityUsd: m.currentTotalEquityUsd,
    vaultReservedUsd: m.bankSweepReservedUsd,
    currentEqNumeric: currentEq,
  });
}

function computeDrawdownSeriesPct(state, metrics) {
  const eqPoints = extractEquitySeriesPoints(state, metrics);
  const initCap = Number(metrics.initialCapitalUsd) || 300000;
  const peakRef = Math.max(initCap, Number(metrics.peakEquityUsd) || initCap, eqPoints[0] || initCap);

  if (eqPoints.length >= 3) {
    let runningPeak = Math.max(initCap, eqPoints[0]);
    return eqPoints.map((eq) => {
      if (eq > runningPeak) runningPeak = eq;
      if (runningPeak <= 0) return 0;
      const dd = ((eq - runningPeak) / runningPeak) * 100;
      return dd >= 0 ? 0 : dd;
    });
  }

  const curEq = Number(metrics.currentTotalEquityUsd);
  let curDd = peakRef > 0 && Number.isFinite(curEq) ? ((curEq - peakRef) / peakRef) * 100 : 0;
  if (curDd > 0) curDd = 0;

  if (metrics.tierDrawdownPct !== null && metrics.tierDrawdownPct !== undefined) {
    const explicitNum = Number(metrics.tierDrawdownPct);
    if (Number.isFinite(explicitNum) && explicitNum !== 0) {
      const signedExplicit = explicitNum > 0 ? -explicitNum : explicitNum;
      if (signedExplicit < curDd) curDd = signedExplicit;
    }
  }
  return [0, curDd];
}

export function drawObsidianDrawdownChart(canvas, state) {
  if (!canvas || typeof canvas.getContext !== 'function') return null;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const w = Number(canvas.getAttribute?.('width') ?? canvas.width) || 460;
  const h = Number(canvas.getAttribute?.('height') ?? canvas.height) || 210;
  const m = extractVaultMetrics(state);
  const ddSeries = computeDrawdownSeriesPct(state, m);

  ctx.fillStyle = OBSIDIAN_BG_HEX;
  ctx.fillRect(0, 0, w, h);

  const padLeft = 58;
  const padRight = 18;
  const padTop = 26;
  const padBottom = 24;
  const plotW = Math.max(40, w - padLeft - padRight);
  const plotH = Math.max(40, h - padTop - padBottom);

  const deepestDd = Math.min(0, ...ddSeries);
  const currentDd = ddSeries[ddSeries.length - 1];
  const floorPct = Math.min(MAX_DRAWDOWN_BRAKE_PCT, Math.floor((deepestDd - 1) / 2.5) * 2.5);
  const ySpan = Math.max(10, Math.abs(floorPct));

  const xAt = (idx) => padLeft + (idx / Math.max(1, ddSeries.length - 1)) * plotW;
  const yAt = (pct) => padTop + ((0 - pct) / ySpan) * plotH;

  ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';
  const gridPcts = [0, -2.5, -5.0, -7.5, -10.0];
  if (floorPct < -10) gridPcts.push(floorPct);
  for (const pct of gridPcts) {
    const y = yAt(pct);
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padLeft, y);
    ctx.lineTo(w - padRight, y);
    ctx.stroke();

    ctx.fillStyle = 'rgba(226,232,240,0.68)';
    ctx.fillText(`${pct.toFixed(2)}%`, 6, y + 4);
  }

  const zeroY = yAt(0);
  ctx.fillStyle = 'rgba(244,63,94,0.28)';
  ctx.beginPath();
  ctx.moveTo(xAt(0), zeroY);
  ddSeries.forEach((pct, i) => {
    ctx.lineTo(xAt(i), yAt(pct));
  });
  ctx.lineTo(xAt(ddSeries.length - 1), zeroY);
  ctx.closePath?.();
  ctx.fill();

  ctx.strokeStyle = '#fb7185';
  ctx.lineWidth = 2.25;
  ctx.beginPath();
  ddSeries.forEach((pct, i) => {
    const x = xAt(i);
    const y = yAt(pct);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  const brakeY = yAt(MAX_DRAWDOWN_BRAKE_PCT);
  ctx.strokeStyle = '#f43f5e';
  ctx.lineWidth = 1.25;
  ctx.setLineDash?.([5, 4]);
  ctx.beginPath();
  ctx.moveTo(padLeft, brakeY);
  ctx.lineTo(w - padRight, brakeY);
  ctx.stroke();
  ctx.setLineDash?.([]);
  ctx.fillStyle = '#fda4af';
  ctx.fillText('-10.00% Max Drawdown Brake', padLeft + 6, brakeY - 5);

  ctx.fillStyle = '#f8fafc';
  ctx.fillText(`Drawdown ${currentDd.toFixed(2)}% \u00b7 Peak Trough ${deepestDd.toFixed(2)}%`, padLeft, 16);

  return Object.freeze({
    background: OBSIDIAN_BG_HEX,
    pointCount: ddSeries.length,
    currentDrawdownPct: currentDd.toFixed(2),
    maxDrawdownPct: deepestDd.toFixed(2),
  });
}

// ---------------------------------------------------------------------------
// 4. Strict-CSP CSS Snippet (Zero Inline Styles — Merge into ui/styles.css)
// ---------------------------------------------------------------------------

const METER_PCT_RULES = Array.from({ length: 21 }, (_, idx) => {
  const pct = idx * 5;
  return `.meter-pct-${pct} { width: ${pct}%; }`;
}).join('\n');

export const OBSIDIAN_THERMAL_CSS_SNIPPET = `/* CAS Forex Obsidian Thermal Heatmap, Top Provenance Strip & Vault Analytics (Strict CSP) */
.top-status-strip {
  background: #121316;
  color: #f1f5f9;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 10px;
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.top-strip-primary {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.top-strip-status-block {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.status-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.04em;
}
.status-trading-now { background: rgba(16, 185, 129, 0.22); color: #34d399; border: 1px solid #10b981; }
.status-scanning { background: rgba(56, 189, 248, 0.18); color: #7dd3fc; border: 1px solid #0284c7; }
.status-respite { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }
.status-safety-lock { background: rgba(244, 63, 94, 0.22); color: #fda4af; border: 1px solid #f43f5e; }
.status-pulse { animation: cas-status-pulse 1.8s ease-in-out infinite; }
@keyframes cas-status-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.55); }
  50% { box-shadow: 0 0 0 7px rgba(16, 185, 129, 0); }
}
.top-strip-headline { font-weight: 600; font-size: 0.92rem; color: #e2e8f0; }
.top-strip-open-pills { display: inline-flex; flex-wrap: wrap; gap: 6px; }
.open-market-pill, .open-broker-pill, .broker-pill {
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  background: rgba(255, 255, 255, 0.08);
  color: #e2e8f0;
}
.last-trade-stamp {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  padding: 6px 10px;
  font-size: 0.82rem;
}
.stamp-kicker { color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.72rem; }
.stamp-time-utc { color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.top-strip-attribution-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  padding-top: 8px;
}
.chip-group { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.chip-group-label { color: #94a3b8; font-size: 0.74rem; font-weight: 600; text-transform: uppercase; }
.broker-win-chip, .market-win-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 9px;
  border-radius: 999px;
  font-size: 0.78rem;
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.12);
}
.pnl-pos { color: #34d399; }
.pnl-neg { color: #fb7185; }
.pnl-flat { color: #cbd5e1; }

.provenance-ledger-section {
  background: #121316;
  color: #e2e8f0;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 10px;
  padding: 14px 16px;
}
.provenance-summary-bar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; }
.provenance-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
.provenance-table th, .provenance-table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); }
.provenance-table th { color: #94a3b8; font-weight: 600; font-size: 0.76rem; text-transform: uppercase; }

.thermal-heatmap-section {
  background: #121316;
  color: #f1f5f9;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 10px;
  padding: 14px 16px;
}
.thermal-header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 12px; }
.thermal-legend { display: flex; flex-wrap: wrap; gap: 6px; }
.legend-chip { padding: 2px 8px; border-radius: 6px; font-size: 0.72rem; font-weight: 700; }
.thermal-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 10px;
}
.thermal-tile {
  border-radius: 8px;
  padding: 10px 12px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.heat-hot-buy { background: rgba(16, 185, 129, 0.24); border-color: #10b981; color: #ecfdf5; }
.heat-warm-buy { background: rgba(16, 185, 129, 0.12); border-color: rgba(52, 211, 153, 0.55); color: #d1fae5; }
.heat-neutral { background: rgba(148, 163, 184, 0.1); border-color: rgba(148, 163, 184, 0.35); color: #e2e8f0; }
.heat-cool-sell { background: rgba(244, 63, 94, 0.12); border-color: rgba(251, 113, 133, 0.55); color: #ffe4e6; }
.heat-cold-sell { background: rgba(244, 63, 94, 0.26); border-color: #f43f5e; color: #fff1f2; }

.spread-badge { padding: 2px 6px; border-radius: 5px; font-size: 0.72rem; font-weight: 600; }
.spread-tight { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }
.spread-normal { background: rgba(234, 179, 8, 0.18); color: #fde047; }
.spread-wide { background: rgba(244, 63, 94, 0.22); color: #fda4af; }

.valve-pass { background: #10b981; color: #052e16; }
.valve-borderline { background: #eab308; color: #422006; }
.valve-blocked { background: #f43f5e; color: #4c0519; }
.valve-badge { padding: 1px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }

.meter-track, .vault-progress-track {
  width: 100%;
  height: 8px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.1);
  overflow: hidden;
}
.meter-fill, .vault-progress-fill { height: 100%; border-radius: 999px; }
.vault-progress-fill.vault-mode-recovery { background: #eab308; }
.vault-progress-fill.vault-mode-surplus { background: #10b981; }

.obsidian-vault-card {
  background: #121316;
  color: #f1f5f9;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 10px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.obsidian-vault-header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 12px; }
.vault-mode-pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.78rem; font-weight: 700; }
.vault-mode-pill.vault-mode-recovery { background: rgba(234, 179, 8, 0.22); color: #fde047; border: 1px solid #eab308; }
.vault-mode-pill.vault-mode-surplus { background: rgba(16, 185, 129, 0.22); color: #34d399; border: 1px solid #10b981; }
.obsidian-vault-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}
.vault-metric-cell {
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 8px;
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.vault-metric-label { font-size: 0.74rem; color: #94a3b8; }
.vault-metric-val { font-size: 0.96rem; }
.obsidian-canvas-frame { background: #121316; border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 8px; }

${METER_PCT_RULES}
`;
