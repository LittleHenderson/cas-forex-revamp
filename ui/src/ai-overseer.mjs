// Pure display and normalization helpers for the 9-model AI catalog, 18-market US Index stream,
// Daily Profit Quota ($500-$1,000), and Human-as-Overseer Autonomous AI panel.
// No DOM, no storage, no inline styles; every dynamic string is normalized and escaped.

import {
  STATIC_AGGRESSION_DIAL,
  normalizeAggressionDial,
  resolveCockpitAggressionDial,
} from './aggression-dial.mjs';

export const MAX_AI_PAYLOAD_BYTES = 131072;

export const PRIORITY_AI_MODELS = Object.freeze([
  Object.freeze({ rank: 1, modelId: 'claude-fable-5.2', displayName: 'Claude Fable 5.2', providerLabel: 'Anthropic', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 2, modelId: 'claude-fable', displayName: 'Claude Fable', providerLabel: 'Anthropic', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 3, modelId: 'claude-5.5', displayName: 'Claude 5.5', providerLabel: 'Anthropic', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 4, modelId: 'gemini-decision-1', displayName: 'Gemini Decision 1', providerLabel: 'Google Gemini (:decide)', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 5, modelId: 'gemini-carbon', displayName: 'Gemini Carbon', providerLabel: 'Google Gemini', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 6, modelId: 'gemini-argon', displayName: 'Gemini Argon', providerLabel: 'Google Gemini', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 7, modelId: 'openai-astra', displayName: 'OpenAI Astra', providerLabel: 'OpenAI', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 8, modelId: 'deepseek-flash-1017', displayName: 'DeepSeek Flash 1017', providerLabel: 'DeepSeek', tier: 'FRONTIER', isFallback: false }),
  Object.freeze({ rank: 9, modelId: 'qwen3:0.6b', displayName: 'Qwen 3 0.6B (Air-Gapped Offline Fallback)', providerLabel: 'Ollama Local', tier: 'OFFLINE_FALLBACK', isFallback: true }),
]);

const GOVERNANCE_MODES = Object.freeze(['ACTIVE', 'PAUSED_NEW_RISK', 'PAUSED', 'STOPPED', 'STANDBY']);
const QUOTA_STATUSES = Object.freeze(['OPEN', 'SOFT_QUOTA_REACHED', 'DAILY_QUOTA_LOCKED', 'PROFIT_FLOOR_LOCKED', 'DAILY_LOSS_CIRCUIT_TRIPPED']);
const PROTECTION_STAGES = Object.freeze(['INITIAL_SL', 'BREAKEVEN_LOCKED', 'TRAILING_ACTIVE']);
export const RISK_GEAR_MODES = Object.freeze(['CONSERVATIVE', 'AUTO_ADAPTIVE', 'AGGRESSIVE']);
export const CONSTITUTIONAL_MAX_STOP_RISK_PCT = '1';
export const CONSTITUTIONAL_MAX_DRAWDOWN_PCT = '0.1';
export const CAPITAL_STATUSES = Object.freeze(['RECOVERY_MODE', 'AT_PRINCIPAL', 'IN_SURPLUS']);
export const SESSION_CADENCE_MODES = Object.freeze(['AUTO', 'REGIONAL_RECOVERY', 'REGIONAL_8H', 'DAILY_NY']);
export const LIVE_TRADING_STATE_CODES = Object.freeze([
  'TRADING_NOW_OPEN_POSITIONS',
  'ACTIVE_SCANNING_MARKETS',
  'PAUSED_RESEARCH_RESPITE',
  'PAUSED_SAFETY_LOCK',
  'STOPPED_OR_PAUSED',
]);
const INDEX_PAIRS = Object.freeze(['NAS100', 'US30', 'SPX500', 'XAUUSD']);

export function computeMarketSessions(nowMs = Date.now(), mt5TickFresh = false) {
  const safeMs = Number.isFinite(nowMs) ? nowMs : Date.now();
  const d = new Date(safeMs);
  const wd = d.getUTCDay(); // 0=Sun..6=Sat
  const hr = d.getUTCHours();
  const mn = d.getUTCMinutes();
  const hh = String(hr).padStart(2, '0');
  const mm = String(mn).padStart(2, '0');
  const forex245Open = (wd >= 1 && wd <= 4) || (wd === 0 && hr >= 22) || (wd === 5 && hr < 22);
  const sessions = Object.freeze([
    Object.freeze({ id: 'sydney', label: 'Sydney', windowUtc: '22:00-07:00 UTC', open: Boolean(forex245Open && (hr >= 22 || hr < 7)) }),
    Object.freeze({ id: 'tokyo', label: 'Tokyo', windowUtc: '00:00-09:00 UTC', open: Boolean(forex245Open && (hr >= 0 && hr < 9)) }),
    Object.freeze({ id: 'london', label: 'London', windowUtc: '07:00-16:00 UTC', open: Boolean(forex245Open && (hr >= 7 && hr < 16)) }),
    Object.freeze({ id: 'new_york', label: 'New York', windowUtc: '12:00-21:00 UTC', open: Boolean(forex245Open && (hr >= 12 && hr < 21)) }),
    Object.freeze({ id: 'london_ny_overlap', label: 'London-NY Overlap', windowUtc: '12:00-16:00 UTC', open: Boolean(forex245Open && (hr >= 12 && hr < 16)) }),
  ]);
  let usIndicesStatus = 'EXTENDED_OPEN';
  let usIndicesLabel = 'Extended Hours OPEN';
  if (!forex245Open) {
    usIndicesStatus = 'WEEKEND_CLOSED';
    usIndicesLabel = 'Weekend Closed';
  } else if (hr === 21) {
    usIndicesStatus = 'DAILY_BREAK';
    usIndicesLabel = 'Daily Break 21:00-22:00 UTC';
  } else if ((hr === 14 && mn >= 30) || (hr >= 15 && hr < 21)) {
    usIndicesStatus = 'CASH_OPEN';
    usIndicesLabel = 'Wall Street Cash OPEN 14:30-21:00 UTC';
  }
  return Object.freeze({
    utcTime: `${hh}:${mm} UTC`,
    forex245Open,
    forexLabel: forex245Open ? 'FOREX 24/5 OPEN' : 'WEEKEND CLOSED',
    usIndicesStatus,
    usIndicesLabel,
    mt5TickFresh: Boolean(mt5TickFresh),
    sessions,
  });
}

const esc = (value) => String(value).replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));
const str = (value, fallback = 'Unknown', maxLen = 240) => (
  typeof value === 'string' && value.length > 0 && value.length <= maxLen ? value : fallback
);
const numStr = (value, fallback = '0') => {
  if (typeof value === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(value)) return value;
  if (Number.isSafeInteger(value)) return String(value);
  return fallback;
};

function compareDecimalStrings(aRaw, bRaw) {
  const parseDec = (raw) => {
    const clean = typeof raw === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(raw.trim()) ? raw.trim() : '0';
    const neg = clean.startsWith('-');
    const unsigned = neg ? clean.slice(1) : clean;
    const [intPart, fracPart = ''] = unsigned.split('.');
    return { neg, intPart, fracPart };
  };
  const a = parseDec(aRaw);
  const b = parseDec(bRaw);
  const scale = Math.max(a.fracPart.length, b.fracPart.length);
  const aVal = BigInt(a.intPart + a.fracPart.padEnd(scale, '0')) * (a.neg ? -1n : 1n);
  const bVal = BigInt(b.intPart + b.fracPart.padEnd(scale, '0')) * (b.neg ? -1n : 1n);
  if (aVal === bVal) return 0;
  return aVal > bVal ? 1 : -1;
}

export function formatExactUsd(raw) {
  const s = typeof raw === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(raw.trim()) ? raw.trim() : '0';
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

function toCentsBigInt(raw) {
  const clean = typeof raw === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(raw.trim()) ? raw.trim() : '0';
  const neg = clean.startsWith('-');
  const unsigned = neg ? clean.slice(1) : clean;
  const [intPart = '0', fracPart = ''] = unsigned.split('.');
  const frac2 = fracPart.slice(0, 2).padEnd(2, '0');
  let mag = BigInt(intPart) * 100n + BigInt(frac2);
  if (fracPart.length >= 3 && fracPart[2] >= '5') {
    mag += 1n;
  }
  if (mag === 0n) return 0n;
  return neg ? -mag : mag;
}

function centsBigIntToDecimal(cents) {
  if (cents === 0n) return '0';
  const neg = cents < 0n;
  const abs = neg ? -cents : cents;
  const whole = abs / 100n;
  const rem = abs % 100n;
  if (rem === 0n) return `${neg ? '-' : ''}${whole}`;
  return `${neg ? '-' : ''}${whole}.${String(rem).padStart(2, '0')}`;
}

function computePctFromCents(diffCents, baseCents) {
  if (baseCents <= 0n || diffCents === 0n) return '0';
  const neg = diffCents < 0n;
  const absDiff = neg ? -diffCents : diffCents;
  const numer = absDiff * 10000n;
  const rem = numer % baseCents;
  const bps = (numer / baseCents) + (rem * 2n >= baseCents ? 1n : 0n);
  if (bps === 0n) return '0';
  return `${neg ? '-' : ''}${bps / 100n}.${String(bps % 100n).padStart(2, '0')}`;
}

function formatSignedPct(raw) {
  const bps = toCentsBigInt(raw);
  if (bps === 0n) return '0.00%';
  const neg = bps < 0n;
  const abs = neg ? -bps : bps;
  return `${neg ? '-' : '+'}${abs / 100n}.${String(abs % 100n).padStart(2, '0')}%`;
}

function defaultRegionWindowLabel(sessionDate, capitalStatus, sessionCadence) {
  if (capitalStatus === 'RECOVERY_MODE' && sessionCadence !== 'DAILY_NY') {
    const s = String(sessionDate ?? '');
    if (s.endsWith('-ASIA')) return 'ASIA (22:00–07:00 UTC / 14:00–23:00 PT)';
    if (s.endsWith('-LONDON')) return 'LONDON (07:00–12:00 UTC / 23:00–04:00 PT)';
    if (s.endsWith('-NY')) return 'NEW_YORK (12:00–22:00 UTC / 04:00–14:00 PT)';
    return 'ASIA (22:00–07:00 UTC / 14:00–23:00 PT)';
  }
  return 'DAILY_NY (17:00 America/New_York)';
}

export function isSyntheticSyncEntry(tradeId, symbol) {
  const tid = String(tradeId ?? '').trim().toUpperCase();
  const sym = String(symbol ?? '').trim().toUpperCase();
  return tid.startsWith('SESSION_SYNC') || sym === 'SESSION_BASKET' || sym.startsWith('SESSION_SYNC');
}

export function forexSessionLabelForUtc(isoUtc) {
  if (typeof isoUtc !== 'string' || !isoUtc.trim()) return 'Unknown Session';
  const ms = Date.parse(isoUtc.trim());
  if (!Number.isFinite(ms)) return 'Unknown Session';
  const hr = new Date(ms).getUTCHours();
  if (hr >= 22 || hr < 7) return 'Asia / Tokyo–Sydney';
  if (hr >= 7 && hr < 12) return 'London';
  return 'New York / US';
}

export function formatUtcTimestamp(isoUtc) {
  if (typeof isoUtc !== 'string' || !isoUtc.trim()) return '';
  const ms = Date.parse(isoUtc.trim());
  if (!Number.isFinite(ms)) return str(isoUtc, '', 64);
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

export function formatPacificTimestamp(isoUtc) {
  if (typeof isoUtc !== 'string' || !isoUtc.trim()) return '';
  const ms = Date.parse(isoUtc.trim());
  if (!Number.isFinite(ms)) return str(isoUtc, '', 64);
  try {
    const dtf = new Intl.DateTimeFormat('en-US', {
      timeZone: 'America/Los_Angeles',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      timeZoneName: 'short',
    });
    const parts = dtf.formatToParts(new Date(ms));
    const map = {};
    for (const p of parts) map[p.type] = p.value;
    const hh = map.hour === '24' ? '00' : map.hour;
    const tz = map.timeZoneName || 'PT';
    return `${map.year}-${map.month}-${map.day} ${hh}:${map.minute}:${map.second} ${tz}`;
  } catch {
    const pt = new Date(ms - 8 * 3600000);
    const pad = (n) => String(n).padStart(2, '0');
    return `${pt.getUTCFullYear()}-${pad(pt.getUTCMonth() + 1)}-${pad(pt.getUTCDate())} ${pad(pt.getUTCHours())}:${pad(pt.getUTCMinutes())}:${pad(pt.getUTCSeconds())} PST`;
  }
}

export function friendlyBrokerLabel(brokerId, explicitLabel = '') {
  if (typeof explicitLabel === 'string' && explicitLabel.trim().length > 0 && explicitLabel.trim().length <= 48) {
    return explicitLabel.trim();
  }
  const raw = String(brokerId ?? '').trim();
  const upper = raw.toUpperCase();
  if (upper.startsWith('LHFX')) return 'LHFX';
  if (upper.startsWith('HUGOSWAY') || upper.startsWith('HUGO')) return "Hugo's Way";
  if (upper.startsWith('OANDA')) return 'OANDA';
  return raw ? raw.slice(0, 40) : 'MT5';
}

function normalizeMarketBreakdownRows(rawRows) {
  if (!Array.isArray(rawRows)) return Object.freeze([]);
  const out = [];
  for (const row of rawRows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const sym = str(row.symbol, '', 32);
    if (!sym || isSyntheticSyncEntry('', sym)) continue;
    const occUtc = str(row.last_occurred_at_utc ?? row.last_occurred_at ?? '', '', 64);
    const brokerId = str(row.broker_id ?? row.last_broker_id ?? '', '', 40);
    const brokerLabel = brokerId || row.broker_label || row.last_broker_label
      ? friendlyBrokerLabel(brokerId, str(row.broker_label ?? row.last_broker_label ?? '', '', 48))
      : '';
    out.push(Object.freeze({
      symbol: sym,
      brokerId,
      brokerLabel,
      realizedPnlUsd: numStr(row.realized_pnl_usd ?? row.realized_net_usd, '0'),
      tradeCount: Number.isSafeInteger(row.trade_count) ? row.trade_count : 0,
      winCount: Number.isSafeInteger(row.win_count) ? row.win_count : 0,
      lossCount: Number.isSafeInteger(row.loss_count) ? row.loss_count : 0,
      lastOccurredAtUtc: occUtc,
      lastOccurredAtPacific: str(row.last_occurred_at_pacific, formatPacificTimestamp(occUtc), 80),
      lastSessionLabel: str(row.last_session_label, occUtc ? forexSessionLabelForUtc(occUtc) : 'Unknown Session', 64),
    }));
  }
  return Object.freeze(out);
}

function normalizeBrokerBreakdownRows(rawRows) {
  if (!Array.isArray(rawRows)) return Object.freeze([]);
  const out = [];
  for (const row of rawRows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const rawId = str(row.broker_id ?? row.broker_label ?? '', '', 40);
    if (!rawId || isSyntheticSyncEntry('', rawId)) continue;
    const occUtc = str(row.last_occurred_at_utc ?? row.last_occurred_at ?? '', '', 64);
    out.push(Object.freeze({
      brokerId: rawId,
      brokerLabel: friendlyBrokerLabel(rawId, str(row.broker_label ?? '', '', 48)),
      realizedPnlUsd: numStr(row.realized_pnl_usd ?? row.realized_net_usd, '0'),
      tradeCount: Number.isSafeInteger(row.trade_count) ? row.trade_count : 0,
      winCount: Number.isSafeInteger(row.win_count) ? row.win_count : 0,
      lossCount: Number.isSafeInteger(row.loss_count) ? row.loss_count : 0,
      lastOccurredAtUtc: occUtc,
      lastOccurredAtPacific: str(row.last_occurred_at_pacific, formatPacificTimestamp(occUtc), 80),
      lastSessionLabel: str(row.last_session_label, occUtc ? forexSessionLabelForUtc(occUtc) : 'Unknown Session', 64),
    }));
  }
  return Object.freeze(out);
}

function normalizeLiveTradingStatus(doc, govMode, quotaStatus, respiteMode, openPositions) {
  const raw = doc?.live_trading_status && typeof doc.live_trading_status === 'object' && !Array.isArray(doc.live_trading_status)
    ? doc.live_trading_status
    : null;
  const openCount = Number.isSafeInteger(raw?.open_positions_count) ? raw.open_positions_count : openPositions.length;
  const openSymbols = Object.freeze(
    Array.isArray(raw?.open_symbols)
      ? raw.open_symbols.map((s) => str(s, '', 32)).filter((s) => s && !isSyntheticSyncEntry('', s))
      : [...new Set(openPositions.map((p) => p.symbol).filter(Boolean))],
  );
  let defaultCode = 'ACTIVE_SCANNING_MARKETS';
  let defaultHeadline = 'ACTIVE — SCANNING MARKETS (0 OPEN TRADES)';
  let defaultTrading = true;
  if (openCount > 0 && govMode === 'ACTIVE') {
    defaultCode = 'TRADING_NOW_OPEN_POSITIONS';
    defaultHeadline = `TRADING NOW — ${openCount} OPEN POSITION${openCount === 1 ? '' : 'S'}: ${openSymbols.join(', ')}`;
    defaultTrading = true;
  } else if (respiteMode || quotaStatus === 'DAILY_QUOTA_LOCKED' || quotaStatus === 'PROFIT_FLOOR_LOCKED') {
    defaultCode = 'PAUSED_RESEARCH_RESPITE';
    defaultHeadline = 'PAUSED — RESEARCH RESPITE (PROFIT LOCKED)';
    defaultTrading = false;
  } else if (quotaStatus === 'DAILY_LOSS_CIRCUIT_TRIPPED') {
    defaultCode = 'PAUSED_SAFETY_LOCK';
    defaultHeadline = 'PAUSED — SAFETY LOCK';
    defaultTrading = false;
  } else if (govMode !== 'ACTIVE') {
    defaultCode = 'STOPPED_OR_PAUSED';
    defaultHeadline = `PAUSED — ${govMode}`;
    defaultTrading = false;
  }
  const rawCode = typeof raw?.state_code === 'string' ? raw.state_code.trim().toUpperCase() : '';
  const stateCode = LIVE_TRADING_STATE_CODES.includes(rawCode) ? rawCode : defaultCode;
  return Object.freeze({
    stateCode,
    headline: str(raw?.headline, defaultHeadline, 200),
    isCurrentlyTrading: typeof raw?.is_currently_trading === 'boolean' ? raw.is_currently_trading : defaultTrading,
    hasOpenPositions: typeof raw?.has_open_positions === 'boolean' ? raw.has_open_positions : (openCount > 0),
    openPositionsCount: openCount,
    openSymbols,
  });
}

function normalizeLastTrade(doc) {
  const lt = doc?.last_trade;
  if (!lt || typeof lt !== 'object' || Array.isArray(lt)) return null;
  const tradeId = str(lt.trade_id, '', 120);
  const symbol = str(lt.symbol, '', 32);
  if (!symbol || isSyntheticSyncEntry(tradeId, symbol)) return null;
  const occUtc = str(lt.occurred_at_utc ?? lt.occurred_at ?? '', '', 64);
  const brokerId = str(lt.broker_id, 'MT5', 40);
  const brokerLabel = friendlyBrokerLabel(brokerId, str(lt.broker_label ?? '', '', 48));
  return Object.freeze({
    tradeId,
    symbol,
    brokerId,
    brokerLabel,
    action: str(lt.action, 'CLOSED_TRADE', 40),
    realizedPnlUsd: lt.realized_pnl_usd === null || lt.realized_pnl_usd === undefined
      ? null
      : numStr(lt.realized_pnl_usd, '0'),
    occurredAtUtc: occUtc,
    occurredAtPacific: str(lt.occurred_at_pacific, formatPacificTimestamp(occUtc), 80),
    sessionLabel: str(lt.session_label, occUtc ? forexSessionLabelForUtc(occUtc) : 'Unknown Session', 64),
  });
}

function normalizeRealizedPnlLedger(doc) {
  const rpl = doc?.realized_pnl_ledger && typeof doc.realized_pnl_ledger === 'object' && !Array.isArray(doc.realized_pnl_ledger)
    ? doc.realized_pnl_ledger
    : null;
  const bs = doc?.banked_session && typeof doc.banked_session === 'object' && !Array.isArray(doc.banked_session)
    ? doc.banked_session
    : null;
  const rawEntries = Array.isArray(rpl?.entries) ? rpl.entries.slice(0, 50) : [];
  const entries = [];
  for (const item of rawEntries) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    const tradeId = str(item.trade_id, '', 120);
    const symbol = str(item.symbol, '', 32);
    if (!symbol || isSyntheticSyncEntry(tradeId, symbol)) continue;
    const occUtc = str(item.occurred_at_utc ?? item.occurred_at ?? '', '', 64);
    const brokerId = str(item.broker_id, 'MT5', 40);
    const brokerLabel = friendlyBrokerLabel(brokerId, str(item.broker_label ?? '', '', 48));
    entries.push(Object.freeze({
      tradeId,
      symbol,
      brokerId,
      brokerLabel,
      realizedPnlUsd: numStr(item.realized_pnl_usd ?? item.realized_net_usd, '0'),
      occurredAtUtc: occUtc,
      occurredAtPacific: str(item.occurred_at_pacific, formatPacificTimestamp(occUtc), 80),
      sessionLabel: str(item.session_label, occUtc ? forexSessionLabelForUtc(occUtc) : 'Unknown Session', 64),
      sessionKey: str(item.session_key, '', 64),
    }));
  }
  const sessionByMarket = normalizeMarketBreakdownRows(rpl?.session_by_market ?? bs?.session_by_market);
  const lifetimeByMarket = normalizeMarketBreakdownRows(rpl?.lifetime_by_market);
  const sessionByBroker = normalizeBrokerBreakdownRows(rpl?.session_by_broker ?? bs?.session_by_broker);
  const lifetimeByBroker = normalizeBrokerBreakdownRows(rpl?.lifetime_by_broker);
  const rawSummary = rpl?.session_provenance_summary ?? bs?.session_provenance_summary;
  let defaultSummary = 'No closed trades in current session yet';
  if (sessionByMarket.length > 0) {
    const parts = sessionByMarket.map((m) => `${m.symbol} (${formatSignedUsd(m.realizedPnlUsd)}${m.brokerLabel ? ` · ${m.brokerLabel}` : ''})`).join(' · ');
    const lead = sessionByMarket[0];
    defaultSummary = `${parts} · ${lead.lastSessionLabel}${lead.lastOccurredAtPacific ? ` · ${lead.lastOccurredAtPacific}` : ''}`;
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    sessionByMarket,
    lifetimeByMarket,
    sessionByBroker,
    lifetimeByBroker,
    sessionProvenanceSummary: str(rawSummary, defaultSummary, 240),
  });
}

function normalizeBankedSession(doc, dailyQuota, bankSweepReservedUsd, operatingMode) {
  const bs = doc?.banked_session && typeof doc.banked_session === 'object' && !Array.isArray(doc.banked_session)
    ? doc.banked_session
    : null;
  const lockedDefault = dailyQuota.status === 'DAILY_QUOTA_LOCKED' || dailyQuota.status === 'PROFIT_FLOOR_LOCKED';
  const defaultTotalRealized = compareDecimalStrings(dailyQuota.realizedNetPnlUsd, '0') > 0
    ? dailyQuota.realizedNetPnlUsd
    : '0';
  const sessionDate = str(bs?.session_date, dailyQuota.sessionDate, 64);
  const confirmedBankPayoutsUsd = numStr(bs?.confirmed_bank_payouts_usd, '0');
  const pendingUnconfirmedTransfersUsd = numStr(bs?.pending_unconfirmed_transfers_usd, '0');
  const initialCapitalUsd = numStr(bs?.initial_capital_usd ?? doc?.initial_capital_usd, '300000');
  const fallbackEquityUsd = compareDecimalStrings(dailyQuota.startingEquityUsd, '0') > 0
    ? centsBigIntToDecimal(toCentsBigInt(dailyQuota.startingEquityUsd) + toCentsBigInt(dailyQuota.realizedNetPnlUsd))
    : initialCapitalUsd;
  const currentTotalEquityUsd = numStr(
    bs?.current_total_equity_usd ?? doc?.current_total_equity_usd,
    fallbackEquityUsd,
  );

  const initCents = toCentsBigInt(initialCapitalUsd);
  const eqCents = toCentsBigInt(currentTotalEquityUsd);
  const payoutCents = toCentsBigInt(confirmedBankPayoutsUsd);
  const economicDiffCents = (eqCents + payoutCents) - initCents;
  const computedSurplusUsd = centsBigIntToDecimal(economicDiffCents);
  const computedSurplusPct = computePctFromCents(economicDiffCents, initCents);
  const computedDeficitUsd = economicDiffCents < 0n ? centsBigIntToDecimal(-economicDiffCents) : '0';
  const computedCapStatus = economicDiffCents < 0n
    ? 'RECOVERY_MODE'
    : (economicDiffCents === 0n ? 'AT_PRINCIPAL' : 'IN_SURPLUS');

  const netSurplusUsd = numStr(bs?.net_surplus_usd, computedSurplusUsd);
  const netSurplusPct = numStr(bs?.net_surplus_pct, computedSurplusPct);
  const deficitToPrincipalUsd = numStr(bs?.deficit_to_principal_usd, computedDeficitUsd);
  const rawCapStatus = typeof bs?.capital_status === 'string' ? bs.capital_status.trim().toUpperCase() : '';
  const capitalStatus = CAPITAL_STATUSES.includes(rawCapStatus) ? rawCapStatus : computedCapStatus;
  const vaultSweepsPausedForRecovery = typeof bs?.vault_sweeps_paused_for_recovery === 'boolean'
    ? bs.vault_sweeps_paused_for_recovery
    : (capitalStatus !== 'IN_SURPLUS');

  const rawCadence = typeof (bs?.session_cadence ?? doc?.session_cadence) === 'string'
    ? String(bs?.session_cadence ?? doc?.session_cadence).trim().toUpperCase()
    : 'AUTO';
  const sessionCadence = SESSION_CADENCE_MODES.includes(rawCadence) ? rawCadence : 'AUTO';
  const rawLeg = Number(bs?.active_session_leg ?? 1);
  const activeSessionLeg = Number.isSafeInteger(rawLeg) && rawLeg >= 1 ? rawLeg : 1;
  const canAdvanceRecoverySession = typeof bs?.can_advance_recovery_session === 'boolean'
    ? bs.can_advance_recovery_session
    : (capitalStatus === 'RECOVERY_MODE' && lockedDefault);
  const activeRegionWindow = str(
    bs?.active_region_window,
    defaultRegionWindowLabel(sessionDate, capitalStatus, sessionCadence),
    120,
  );

  const defaultSwept = vaultSweepsPausedForRecovery ? '0' : bankSweepReservedUsd;
  const vaultSwept50PctUsd = numStr(bs?.vault_swept_50pct_usd, defaultSwept);
  const vaultRetained50PctUsd = numStr(bs?.vault_retained_50pct_usd, bankSweepReservedUsd);
  const offlineBrokers = Object.freeze(
    Array.isArray(bs?.offline_brokers)
      ? bs.offline_brokers.map((b) => str(b, '', 48)).filter(Boolean)
      : [],
  );
  const offlineBrokerLabels = Object.freeze(offlineBrokers.map((id) => friendlyBrokerLabel(id)));
  const equityIncompleteBrokersOffline = typeof bs?.equity_incomplete_brokers_offline === 'boolean'
    ? bs.equity_incomplete_brokers_offline
    : offlineBrokers.length > 0;
  const defaultOnlineEquity = doc?.deployable_equity_usd !== undefined && doc?.deployable_equity_usd !== null
    ? numStr(doc.deployable_equity_usd, currentTotalEquityUsd)
    : currentTotalEquityUsd;
  const onlineEquityUsd = bs?.online_equity_usd !== undefined && bs?.online_equity_usd !== null
    ? numStr(bs.online_equity_usd, defaultOnlineEquity)
    : defaultOnlineEquity;
  let offlineBrokerNotice = null;
  if (typeof bs?.offline_broker_notice === 'string' && bs.offline_broker_notice.trim().length > 0) {
    offlineBrokerNotice = str(bs.offline_broker_notice.trim(), '', 400);
  } else if (equityIncompleteBrokersOffline || offlineBrokers.length > 0) {
    const names = offlineBrokerLabels.length > 0 ? offlineBrokerLabels.join(' & ') : 'One or more broker terminals';
    offlineBrokerNotice = `${names} is currently disconnected. Unreachable broker equity is excluded from active trade sizing and drawdown — this is a connection pause, NOT a trading loss.`;
  }
  return Object.freeze({
    schema: 'cas-forex.banked-session/1',
    accountingBasis: str(bs?.accounting_basis, 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT', 80),
    sessionDate,
    initialCapitalUsd,
    currentTotalEquityUsd,
    onlineEquityUsd,
    offlineBrokers,
    offlineBrokerLabels,
    offlineBrokerNotice,
    equityIncompleteBrokersOffline,
    netSurplusUsd,
    netSurplusPct,
    deficitToPrincipalUsd,
    capitalStatus,
    vaultSweepsPausedForRecovery,
    sessionCadence,
    activeSessionLeg,
    canAdvanceRecoverySession,
    activeRegionWindow,
    bankedNetPnlUsd: numStr(bs?.banked_net_pnl_usd, dailyQuota.realizedNetPnlUsd),
    realizedPnlPct: numStr(bs?.realized_pnl_pct, dailyQuota.realizedPnlPct),
    peakRealizedPnlUsd: numStr(bs?.peak_realized_pnl_usd, dailyQuota.peakRealizedPnlUsd),
    protectedProfitFloorUsd: numStr(bs?.protected_profit_floor_usd, dailyQuota.protectedProfitFloorUsd),
    ratchetArmed: typeof bs?.ratchet_armed === 'boolean' ? bs.ratchet_armed : Boolean(dailyQuota.ratchetArmed),
    closedTrades: numStr(bs?.closed_trades, dailyQuota.closedTrades),
    winCount: numStr(bs?.win_count, dailyQuota.winCount),
    lossCount: numStr(bs?.loss_count, dailyQuota.lossCount),
    vaultTotalRealizedUsd: numStr(bs?.vault_total_realized_usd, defaultTotalRealized),
    vaultSwept50PctUsd,
    sessionVaultReserved50PctUsd: numStr(bs?.session_vault_reserved_50pct_usd, vaultSwept50PctUsd),
    vaultRetained50PctUsd,
    confirmedBankPayoutsUsd,
    pendingUnconfirmedTransfersUsd,
    profitsLockedForSession: typeof bs?.profits_locked_for_session === 'boolean' ? bs.profits_locked_for_session : lockedDefault,
    operatingMode: str(bs?.operating_mode, operatingMode, 40),
    sessionRolloverLabel: str(bs?.session_rollover_label, '17:00 America/New_York (14:00 Pacific)', 120),
    nextSessionOpensUtc: bs?.next_session_opens_utc ? str(bs.next_session_opens_utc, '', 64) : null,
    sessionByMarket: normalizeMarketBreakdownRows(bs?.session_by_market),
    sessionByBroker: normalizeBrokerBreakdownRows(bs?.session_by_broker),
    sessionProvenanceSummary: str(bs?.session_provenance_summary, 'No closed trades in current session yet', 240),
  });
}

export const STATIC_AI_MODELS = Object.freeze({
  connected: false,
  activeModelId: 'claude-fable-5.2',
  activeDisplayName: 'Claude Fable 5.2',
  activeProvider: 'anthropic',
  activeStatus: 'AWAITING_PROVIDER_KEY',
  selectionMode: 'PRIORITY_AUTO',
  frontierAheadOfQwen: true,
  frontierConfiguredCount: '0',
  offlineFallbackEnabled: false,
  thinkingDepth: 'AUTO',
  validThinkingDepths: Object.freeze(['AUTO', 'LOW', 'MEDIUM', 'HIGH']),
  lastEffectiveEffort: 'low',
  lastLatencyMs: null,
  fastScoutEnabled: false,
  fastScoutModelId: 'gemini-decision-1',
  fastScoutReady: false,
  minDecisionProbability: '0.6',
  valveRequired: true,
  models: Object.freeze(PRIORITY_AI_MODELS.map((m) => Object.freeze({
    rank: String(m.rank),
    modelId: m.modelId,
    displayName: m.displayName,
    providerLabel: m.providerLabel,
    tier: m.tier,
    isFallback: m.isFallback,
    active: m.modelId === 'claude-fable-5.2',
    providerReady: false,
    availability: m.isFallback ? 'NOT_CONFIGURED' : 'AWAITING_PROVIDER_KEY',
    lastStatus: 'NOT_RUN',
  }))),
});

function clampConstitutionalDecimal(rawValue, maxNum, fallbackStr, maxFormattedStr) {
  const s = numStr(rawValue, fallbackStr);
  const n = Number(s);
  if (!Number.isFinite(n) || n <= 0) return fallbackStr;
  if (n > maxNum) return maxFormattedStr;
  return s;
}

export const STATIC_AI_TRADER = Object.freeze({
  connected: false,
  humanRole: 'OVERSEER_ONLY',
  governanceMode: 'STANDBY',
  governanceReason: 'AI trader standby (not attached). Connect loopback live server to observe AI autonomy.',
  effectiveStatus: 'STANDBY',
  respiteMode: false,
  operatingMode: 'ACTIVE_TRADING',
  fastTickMs: '50',
  cadence: '50ms_FAST_TICK',
  marketsEvaluated: '20',
  activeWorkingMarkets: Object.freeze([]),
  currentFocusSymbol: 'NAS100',
  currentFocusStatus: 'Standby preview (connect live server)',
  marketSessions: null,
  activeModelId: 'claude-fable-5.2',
  activeDisplayName: 'Claude Fable 5.2',
  activeModelStatus: 'AWAITING_PROVIDER_KEY',
  fastScoutEnabled: false,
  fastScoutReady: false,
  cycleCount: '0',
  lastCycleMs: '0',
  lastAction: 'WAIT',
  lastSymbol: 'None',
  lastReason: 'Not connected to autonomous AI trader.',
  lastValveScore: 'Unknown',
  vetoCount: '0',
  valveController: 'tks_meta_valve_controller',
  valveParameters: '161',
  valveThreshold: '0.55',
  riskGear: Object.freeze({
    ownerMode: 'AUTO_ADAPTIVE',
    activeGear: 'CONSERVATIVE',
    effectiveRiskPct: '0.5',
    ownerMaxRiskPct: '1',
    effectiveSoftQuotaUsd: '500',
    effectiveHardQuotaUsd: '1000',
    ownerHardQuotaUsd: '3000',
    softDrawdownDownshiftPct: '0.05',
    ownerMaxDrawdownPct: '0.1',
    reason: 'Auto-Adaptive Gear ready under immutable 1.00% stop-risk & 10.00% drawdown constitutional ceiling.',
  }),
  dailyQuota: Object.freeze({
    sessionDate: 'Unknown',
    status: 'OPEN',
    newRiskAllowed: true,
    lockReason: null,
    quotaMode: 'USD',
    startingEquityUsd: '0',
    realizedNetPnlUsd: '0',
    realizedPnlPct: '0',
    softQuotaUsd: '500',
    hardQuotaUsd: '1000',
    dailyQuotaPct: null,
    quotaProgressPct: '0',
    riskMultiplier: '1',
    maxDailyLossUsd: '500',
    closedTrades: '0',
    winCount: '0',
    lossCount: '0',
    consecutiveLosses: '0',
    maxConsecutiveLosses: '3',
    peakRealizedPnlUsd: '0',
    ratchetArmed: false,
    ratchetActivationUsd: '0',
    protectedProfitFloorUsd: '0',
  }),
  bankedSession: Object.freeze({
    schema: 'cas-forex.banked-session/1',
    accountingBasis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
    sessionDate: 'Unknown',
    initialCapitalUsd: '300000',
    currentTotalEquityUsd: '300000',
    onlineEquityUsd: '300000',
    offlineBrokers: Object.freeze([]),
    offlineBrokerLabels: Object.freeze([]),
    offlineBrokerNotice: null,
    equityIncompleteBrokersOffline: false,
    netSurplusUsd: '0',
    netSurplusPct: '0',
    deficitToPrincipalUsd: '0',
    capitalStatus: 'AT_PRINCIPAL',
    vaultSweepsPausedForRecovery: true,
    sessionCadence: 'AUTO',
    activeSessionLeg: 1,
    canAdvanceRecoverySession: false,
    activeRegionWindow: 'DAILY_NY (17:00 America/New_York)',
    bankedNetPnlUsd: '0',
    realizedPnlPct: '0',
    peakRealizedPnlUsd: '0',
    protectedProfitFloorUsd: '0',
    ratchetArmed: false,
    closedTrades: '0',
    winCount: '0',
    lossCount: '0',
    vaultTotalRealizedUsd: '0',
    vaultSwept50PctUsd: '0',
    sessionVaultReserved50PctUsd: '0',
    vaultRetained50PctUsd: '0',
    confirmedBankPayoutsUsd: '0',
    pendingUnconfirmedTransfersUsd: '0',
    profitsLockedForSession: false,
    operatingMode: 'ACTIVE_TRADING',
    sessionRolloverLabel: '17:00 America/New_York (14:00 Pacific)',
    nextSessionOpensUtc: null,
    sessionByMarket: Object.freeze([]),
    sessionByBroker: Object.freeze([]),
    sessionProvenanceSummary: 'No closed trades in current session yet',
  }),
  liveTradingStatus: Object.freeze({
    stateCode: 'STOPPED_OR_PAUSED',
    headline: 'PAUSED — STANDBY',
    isCurrentlyTrading: false,
    hasOpenPositions: false,
    openPositionsCount: 0,
    openSymbols: Object.freeze([]),
  }),
  lastTrade: null,
  realizedPnlLedger: Object.freeze({
    entries: Object.freeze([]),
    sessionByMarket: Object.freeze([]),
    lifetimeByMarket: Object.freeze([]),
    sessionByBroker: Object.freeze([]),
    lifetimeByBroker: Object.freeze([]),
    sessionProvenanceSummary: 'No closed trades in current session yet',
  }),
  accountingBasis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
  confirmedBankPayoutsUsd: '0',
  pendingUnconfirmedTransfersUsd: '0',
  sessionVaultReserved50PctUsd: '0',
  initialCapitalUsd: '300000',
  currentTotalEquityUsd: '300000',
  onlineEquityUsd: '300000',
  offlineBrokers: Object.freeze([]),
  offlineBrokerLabels: Object.freeze([]),
  offlineBrokerNotice: null,
  equityIncompleteBrokersOffline: false,
  netSurplusUsd: '0',
  netSurplusPct: '0',
  deficitToPrincipalUsd: '0',
  capitalStatus: 'AT_PRINCIPAL',
  vaultSweepsPausedForRecovery: true,
  sessionCadence: 'AUTO',
  activeSessionLeg: 1,
  canAdvanceRecoverySession: false,
  activeRegionWindow: 'DAILY_NY (17:00 America/New_York)',
  aggressionDial: STATIC_AGGRESSION_DIAL,
  openPositions: Object.freeze([]),
  recentActions: Object.freeze([]),
});

export function normalizeAiModels(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('AI models payload must be a JSON object.');
  if (doc.schema !== 'cas-forex.ai-models/1') throw new Error('Unexpected AI models schema.');
  if (!Array.isArray(doc.models) || doc.models.length !== 9) throw new Error('AI models catalog must contain exactly 9 ordered entries.');
  if (doc.models[8]?.model_id !== 'qwen3:0.6b') throw new Error('Qwen fallback must remain strictly rank #9 last.');
  const models = doc.models.map((item, idx) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('AI model entry must be an object.');
    if (!Number.isSafeInteger(item.rank) || item.rank !== idx + 1) throw new Error('AI model ranks must be sequential 1..9.');
    return Object.freeze({
      rank: String(item.rank),
      modelId: str(item.model_id),
      displayName: str(item.display_name),
      providerLabel: str(item.provider_label),
      tier: str(item.tier),
      isFallback: Boolean(item.is_fallback),
      active: Boolean(item.active),
      providerReady: Boolean(item.provider_ready),
      availability: str(item.availability),
      lastStatus: str(item.last_status, 'IDLE'),
    });
  });
  return Object.freeze({
    connected: true,
    activeModelId: str(doc.active_model_id),
    activeDisplayName: str(doc.active_display_name),
    activeProvider: str(doc.active_provider),
    activeStatus: str(doc.active_status),
    selectionMode: str(doc.selection_mode),
    frontierAheadOfQwen: Boolean(doc.frontier_ahead_of_qwen),
    frontierConfiguredCount: numStr(doc.frontier_configured_count, '0'),
    offlineFallbackEnabled: Boolean(doc.offline_fallback_enabled),
    thinkingDepth: str(doc.thinking_depth, 'AUTO').toUpperCase(),
    validThinkingDepths: Object.freeze(Array.isArray(doc.valid_thinking_depths) ? doc.valid_thinking_depths.map((d) => str(d)) : ['AUTO', 'LOW', 'MEDIUM', 'HIGH']),
    lastEffectiveEffort: str(doc.last_effective_effort, 'low').toLowerCase(),
    lastLatencyMs: Number.isSafeInteger(doc.last_latency_ms) ? doc.last_latency_ms : null,
    fastScoutEnabled: Boolean(doc.fast_scout_enabled),
    fastScoutModelId: str(doc.fast_scout_model_id, 'gemini-decision-1'),
    fastScoutReady: Boolean(doc.fast_scout_ready),
    minDecisionProbability: str(doc.min_decision_probability, '0.6'),
    valveRequired: Boolean(doc.valve_required),
    models: Object.freeze(models),
  });
}

export function normalizeAiTrader(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('AI trader payload must be a JSON object.');
  if (doc.schema !== 'cas-forex.ai-trader/1') throw new Error('Unexpected AI trader schema.');
  const q = doc.daily_quota;
  if (!q || typeof q !== 'object' || Array.isArray(q)) throw new Error('AI trader daily_quota must be an object.');
  const quotaStatus = QUOTA_STATUSES.includes(q.status) ? q.status : 'OPEN';
  const govMode = GOVERNANCE_MODES.includes(doc.governance_mode) ? doc.governance_mode : 'STANDBY';
  const rawPositions = Array.isArray(doc.open_positions) ? doc.open_positions : [];
  const openPositions = rawPositions.map((p) => {
    const rawVol = p.volume_lots ?? p.volume ?? p.quantity;
    const rawEntry = p.entry_price ?? p.price_open;
    const rawSl = p.stop_loss ?? p.sl ?? p.stop_price;
    const rawTp = p.take_profit ?? p.tp ?? p.take_profit_price;
    const normVol = (rawVol === null || rawVol === undefined || String(rawVol).trim() === '') ? '0' : str(rawVol, '0');
    const normEntry = (rawEntry === null || rawEntry === undefined || String(rawEntry).trim() === '') ? '0' : str(rawEntry, '0');
    const normSl = (rawSl === null || rawSl === undefined || String(rawSl).trim() === '') ? null : str(rawSl, '0');
    const normTp = (rawTp === null || rawTp === undefined || String(rawTp).trim() === '') ? null : str(rawTp, '0');
    return Object.freeze({
      broker_id: str(p.broker_id, 'MT5'),
      ticket: numStr(p.ticket, '0'),
      position_id: `${str(p.broker_id, 'MT5')}-${numStr(p.ticket, '0')}`,
      instrument_id: str(p.symbol, 'UNKNOWN'),
      symbol: str(p.symbol, 'UNKNOWN'),
      side: p.side === 'SELL' ? 'SELL' : 'BUY',
      volume_lots: normVol,
      quantity: normVol,
      entry_price: normEntry,
      price_open: normEntry,
      stop_price: normSl,
      stop_loss: normSl,
      sl: normSl,
      take_profit_price: normTp,
      take_profit: normTp,
      tp: normTp,
      profit: numStr(p.profit, '0'),
      protectionStage: PROTECTION_STAGES.includes(p.protection_stage) ? p.protection_stage : 'INITIAL_SL',
    });
  });
  const rawActions = Array.isArray(doc.recent_actions) ? doc.recent_actions.slice(-8) : [];
  const recentActions = rawActions.map((a) => Object.freeze({
    observedAt: str(a.observed_at, ''),
    kind: str(a.kind, 'INFO'),
    symbol: str(a.symbol ?? '', ''),
    detail: str(a.detail ?? a.reason ?? a.outcome ?? '', 'Recorded', 240),
  }));
  const operatingMode = str(doc.operating_mode, 'ACTIVE_TRADING', 40);
  const bankSweepReservedUsd = numStr(doc.bank_sweep_reserved_usd, '0');
  const dailyQuota = Object.freeze({
    sessionDate: str(q.session_date, 'Unknown'),
    status: quotaStatus,
    newRiskAllowed: Boolean(q.new_risk_allowed),
    lockReason: q.lock_reason ? str(q.lock_reason) : null,
    quotaMode: str(q.quota_mode, 'USD'),
    startingEquityUsd: numStr(q.starting_equity_usd, '0'),
    realizedNetPnlUsd: numStr(q.realized_net_pnl_usd, '0'),
    realizedPnlPct: numStr(q.realized_pnl_pct, '0'),
    softQuotaUsd: numStr(q.soft_quota_usd, '500'),
    hardQuotaUsd: numStr(q.hard_quota_usd, '1000'),
    dailyQuotaPct: q.daily_quota_pct ? numStr(q.daily_quota_pct) : null,
    quotaProgressPct: numStr(q.quota_progress_pct, '0'),
    riskMultiplier: numStr(q.risk_multiplier, '1'),
    maxDailyLossUsd: numStr(q.max_daily_loss_usd, '500'),
    closedTrades: numStr(q.closed_trades, '0'),
    winCount: numStr(q.win_count, '0'),
    lossCount: numStr(q.loss_count, '0'),
    consecutiveLosses: numStr(q.consecutive_losses, '0'),
    maxConsecutiveLosses: numStr(q.max_consecutive_losses, '3'),
    peakRealizedPnlUsd: numStr(q.peak_realized_pnl_usd, '0'),
    ratchetArmed: Boolean(q.ratchet_armed),
    ratchetActivationUsd: numStr(q.ratchet_activation_usd, '0'),
    protectedProfitFloorUsd: numStr(q.protected_profit_floor_usd, '0'),
  });
  const bankedSession = normalizeBankedSession(doc, dailyQuota, bankSweepReservedUsd, operatingMode);
  const liveTradingStatus = normalizeLiveTradingStatus(
    doc,
    govMode,
    quotaStatus,
    Boolean(doc.respite_mode),
    openPositions,
  );
  const lastTrade = normalizeLastTrade(doc);
  const realizedPnlLedger = normalizeRealizedPnlLedger(doc);
  return Object.freeze({
    connected: true,
    humanRole: str(doc.human_role, 'OVERSEER_ONLY'),
    governanceMode: govMode,
    governanceReason: str(doc.governance_reason, 'Autonomous loop active.'),
    effectiveStatus: str(doc.effective_status, govMode),
    respiteMode: Boolean(doc.respite_mode),
    operatingMode,
    fastTickMs: numStr(doc.fast_tick_ms, '50'),
    cadence: str(doc.cadence, '50ms_FAST_TICK'),
    marketsEvaluated: numStr(doc.markets_evaluated, '20'),
    activeWorkingMarkets: Object.freeze(
      Array.isArray(doc.active_working_markets)
        ? doc.active_working_markets.map((s) => str(s, '')).filter(Boolean)
        : openPositions.map((p) => p.symbol).filter((v, idx, a) => v && a.indexOf(v) === idx)
    ),
    currentFocusSymbol: str(doc.current_focus_symbol, 'NAS100', 32),
    currentFocusStatus: str(doc.current_focus_status, `SCANNING ${numStr(doc.markets_evaluated, '20')} MARKETS`, 180),
    marketSessions: doc.market_sessions && typeof doc.market_sessions === 'object' ? Object.freeze({
      utcTime: str(doc.market_sessions.utc_time, '00:00 UTC', 24),
      forex245Open: Boolean(doc.market_sessions.forex_24_5_open),
      forexLabel: str(doc.market_sessions.forex_label, 'FOREX 24/5 OPEN', 40),
      usIndicesStatus: str(doc.market_sessions.us_indices_status, 'EXTENDED_OPEN', 32),
      usIndicesLabel: str(doc.market_sessions.us_indices_label, 'Extended Hours OPEN', 64),
      mt5TickFresh: Boolean(doc.market_sessions.mt5_tick_fresh),
      sessions: Object.freeze(Array.isArray(doc.market_sessions.sessions) ? doc.market_sessions.sessions.map((s) => Object.freeze({
        id: str(s.id, 'session', 32),
        label: str(s.label, 'Session', 40),
        windowUtc: str(s.window_utc, '', 32),
        open: Boolean(s.open),
      })) : []),
    }) : null,
    activeModelId: str(doc.active_model_id, 'claude-fable-5.2'),
    activeDisplayName: str(doc.active_display_name, 'Claude Fable 5.2'),
    activeModelStatus: str(doc.active_model_status, 'AWAITING_PROVIDER_KEY'),
    fastScoutEnabled: Boolean(doc.fast_scout_enabled),
    fastScoutReady: Boolean(doc.fast_scout_ready),
    cycleCount: numStr(doc.cycle_count, '0'),
    lastCycleMs: numStr(doc.last_cycle_ms, '0'),
    thinkingDepth: str(doc.thinking_depth, 'AUTO').toUpperCase(),
    lastEffectiveEffort: str(doc.last_effective_effort, 'low').toLowerCase(),
    lastLatencyMs: Number.isSafeInteger(doc.last_latency_ms) ? doc.last_latency_ms : null,
    lastRegime: str(doc.last_regime, 'TREND_IGNITION'),
    deployableEquityUsd: numStr(doc.deployable_equity_usd, '0'),
    bankSweepReservedUsd,
    accountingBasis: bankedSession.accountingBasis,
    confirmedBankPayoutsUsd: bankedSession.confirmedBankPayoutsUsd,
    pendingUnconfirmedTransfersUsd: bankedSession.pendingUnconfirmedTransfersUsd,
    sessionVaultReserved50PctUsd: bankedSession.sessionVaultReserved50PctUsd,
    initialCapitalUsd: bankedSession.initialCapitalUsd,
    currentTotalEquityUsd: bankedSession.currentTotalEquityUsd,
    onlineEquityUsd: bankedSession.onlineEquityUsd,
    offlineBrokers: bankedSession.offlineBrokers,
    offlineBrokerLabels: bankedSession.offlineBrokerLabels,
    offlineBrokerNotice: bankedSession.offlineBrokerNotice,
    equityIncompleteBrokersOffline: bankedSession.equityIncompleteBrokersOffline,
    netSurplusUsd: bankedSession.netSurplusUsd,
    netSurplusPct: bankedSession.netSurplusPct,
    deficitToPrincipalUsd: bankedSession.deficitToPrincipalUsd,
    capitalStatus: bankedSession.capitalStatus,
    vaultSweepsPausedForRecovery: bankedSession.vaultSweepsPausedForRecovery,
    sessionCadence: bankedSession.sessionCadence,
    activeSessionLeg: bankedSession.activeSessionLeg,
    canAdvanceRecoverySession: bankedSession.canAdvanceRecoverySession,
    activeRegionWindow: bankedSession.activeRegionWindow,
    lastAction: str(doc.last_action, 'WAIT'),
    lastSymbol: doc.last_symbol ? str(doc.last_symbol) : 'None',
    lastReason: str(doc.last_reason, 'None'),
    lastValveScore: doc.last_valve_score ? str(doc.last_valve_score) : 'Unknown',
    vetoCount: numStr(doc.veto_count, '0'),
    valveController: str(doc.valve_controller, 'tks_meta_valve_controller'),
    valveParameters: numStr(doc.valve_parameters, '161'),
    valveThreshold: str(doc.valve_threshold, '0.55'),
    riskGear: doc.risk_gear && typeof doc.risk_gear === 'object' ? Object.freeze({
      ownerMode: RISK_GEAR_MODES.includes(str(doc.risk_gear.owner_mode, 'AUTO_ADAPTIVE').toUpperCase())
        ? str(doc.risk_gear.owner_mode, 'AUTO_ADAPTIVE').toUpperCase() : 'AUTO_ADAPTIVE',
      activeGear: str(doc.risk_gear.active_gear, 'CONSERVATIVE', 40),
      effectiveRiskPct: clampConstitutionalDecimal(doc.risk_gear.effective_risk_pct, 1, '0.5', CONSTITUTIONAL_MAX_STOP_RISK_PCT),
      ownerMaxRiskPct: clampConstitutionalDecimal(doc.risk_gear.owner_max_risk_pct, 1, '1', CONSTITUTIONAL_MAX_STOP_RISK_PCT),
      effectiveSoftQuotaUsd: numStr(doc.risk_gear.effective_soft_quota_usd, '500'),
      effectiveHardQuotaUsd: numStr(doc.risk_gear.effective_hard_quota_usd, '1000'),
      ownerHardQuotaUsd: numStr(doc.risk_gear.owner_hard_quota_usd, '3000'),
      softDrawdownDownshiftPct: clampConstitutionalDecimal(doc.risk_gear.soft_drawdown_downshift_pct, 0.1, '0.05', CONSTITUTIONAL_MAX_DRAWDOWN_PCT),
      ownerMaxDrawdownPct: clampConstitutionalDecimal(doc.risk_gear.owner_max_drawdown_pct, 0.1, '0.1', CONSTITUTIONAL_MAX_DRAWDOWN_PCT),
      reason: str(doc.risk_gear.reason, 'Owner-bounded adaptive risk gear under 1.00% stop-risk & 10.00% drawdown ceiling.', 200),
    }) : STATIC_AI_TRADER.riskGear,
    dailyQuota,
    bankedSession,
    liveTradingStatus,
    lastTrade,
    realizedPnlLedger,
    aggressionDial: doc.aggression_dial && typeof doc.aggression_dial === 'object'
      ? normalizeAggressionDial(doc.aggression_dial)
      : null,
    openPositions: Object.freeze(openPositions),
    recentActions: Object.freeze(recentActions),
  });
}

export function normalizeIndexStream(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Index stream payload must be a JSON object.');
  if (doc.schema !== 'cas-forex.index-stream/1') throw new Error('Unexpected index stream schema.');
  if (!Number.isSafeInteger(doc.sequence) || doc.sequence < 0) throw new Error('Index stream sequence must be a safe integer.');
  if (!Array.isArray(doc.markets)) throw new Error('Index stream markets must be an array.');
  const seen = new Set();
  const markets = doc.markets.map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Index market entry must be an object.');
    if (!INDEX_PAIRS.includes(row.pair)) throw new Error('Unsupported index instrument.');
    if (seen.has(row.pair)) throw new Error('Duplicate index instrument in index stream.');
    seen.add(row.pair);
    const bidNum = Number(row.bid);
    const askNum = Number(row.ask);
    if (!Number.isFinite(bidNum) || !Number.isFinite(askNum) || bidNum <= 0 || askNum <= bidNum) {
      throw new Error('Index stream bid/ask must be finite and ask > bid.');
    }
    const validateBars = (bars) => (Array.isArray(bars) ? bars : []).map((bar) => {
      const o = Number(bar.o); const h = Number(bar.h); const l = Number(bar.l); const c = Number(bar.c);
      if (![o, h, l, c].every(Number.isFinite) || h < Math.max(o, c) || l > Math.min(o, c) || l > h) {
        throw new Error('Invalid index candle OHLC envelope.');
      }
      return Object.freeze({
        t: str(bar.t), o: str(bar.o), h: str(bar.h), l: str(bar.l), c: str(bar.c), v: str(bar.v ?? '1.00'), n: Number.isSafeInteger(bar.n) ? bar.n : 1,
      });
    });
    const m1 = Object.freeze(validateBars(row.candles_m1));
    const m5 = Object.freeze(validateBars(row.candles_m5?.length ? row.candles_m5 : m1));
    const h1 = Object.freeze(validateBars(row.candles_h1?.length ? row.candles_h1 : m1));
    const spreadVal = str(row.spread_points ?? row.spread_pips ?? '0', '0');
    return Object.freeze({
      pair: row.pair,
      display_pair: str(row.display_pair, ({ NAS100: 'NAS100 / NDX', US30: 'US30 / DJIA', SPX500: 'SPX500 / S&P 500', XAUUSD: 'XAU/USD · Gold' }[row.pair] ?? row.pair)),
      category: 'US_INDEX',
      base_currency: str(row.base_currency, row.pair),
      quote_currency: str(row.quote_currency, 'USD'),
      tick_size: str(row.tick_size, '0.25'),
      feed_mode: str(row.feed_mode, 'PINNED_INDEX_REFERENCE_FEED'),
      bid: str(row.bid),
      ask: str(row.ask),
      mid: str(row.mid, str(row.bid)),
      spread_points: spreadVal,
      spread_pips: spreadVal,
      change_24h_pct: typeof row.change_24h_pct === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(row.change_24h_pct) ? row.change_24h_pct : '0.00',
      observed_at: str(row.observed_at),
      candles_m1: m1,
      candles_m5: m5,
      candles_h1: h1,
    });
  });
  return Object.freeze({
    schema: doc.schema,
    sequence: doc.sequence,
    observed_at: str(doc.observed_at),
    instruments: Object.freeze([...seen]),
    markets: Object.freeze(markets),
  });
}

export function shouldAutoConnectLiveFeed(loc, token) {
  if (typeof token !== 'string' || token.trim().length < 16 || /[\r\n\0]/.test(token)) return false;
  if (!loc || typeof loc !== 'object') return false;
  const proto = String(loc.protocol ?? '').toLowerCase();
  const host = String(loc.hostname ?? '').toLowerCase();
  if (proto === 'https:' && host.length > 0) return true;
  if (proto === 'http:' && (host === '127.0.0.1' || host === '[::1]' || host === '::1')) return true;
  return false;
}

export function renderAiOverseerPanel(state) {
  const trader = state?.aiTrader ?? STATIC_AI_TRADER;
  const models = state?.aiModels ?? STATIC_AI_MODELS;
  const busy = Boolean(state?.aiActionBusy);
  const q = trader.dailyQuota ?? STATIC_AI_TRADER.dailyQuota;
  const pctRaw = Number(q.quotaProgressPct);
  const pctVal = Number.isFinite(pctRaw) ? Math.max(0, Math.min(100, pctRaw)) : 0;
  const profitBankedLocked = q.status === 'DAILY_QUOTA_LOCKED' || q.status === 'PROFIT_FLOOR_LOCKED';
  const isRespiteBanked = Boolean(trader.respiteMode) || profitBankedLocked;
  const lossTripped = q.status === 'DAILY_LOSS_CIRCUIT_TRIPPED';
  const quotaTagClass = lossTripped ? ' tag-warning' : (profitBankedLocked ? ' tag-profit-locked' : '');
  const modeWarning = !trader.connected || (trader.governanceMode !== 'ACTIVE' && !isRespiteBanked) || lossTripped;

  const peakUsd = q.peakRealizedPnlUsd ?? '0';
  const floorUsd = q.protectedProfitFloorUsd ?? '0';
  const actUsd = q.ratchetActivationUsd ?? '0';
  const ratchetArmed = Boolean(q.ratchetArmed);
  const ratchetPill = ratchetArmed
    ? '<span class="ratchet-pill is-armed">RATCHET ARMED</span>'
    : `<span class="ratchet-pill">Unhandcuffed (arms at $${esc(actUsd)})</span>`;
  const profitRatchetRow = `<div class="profit-ratchet-row numeric" data-profit-ratchet-bar="true"><span>Peak Today: $${esc(peakUsd)}</span><span>Protected Floor (70%): $${esc(floorUsd)}</span>${ratchetPill}</div>`;
  const respiteBadge = isRespiteBanked
    ? '<span class="respite-banked-badge" data-research-respite-badge="true">RESEARCH RESPITE · PROFITS BANKED (0 New Risk · Observing Markets)</span>'
    : '';

  const modelOptions = models.models.map((m) => {
    const selected = m.modelId === models.activeModelId ? ' selected' : '';
    const suffix = m.isFallback ? ' [Offline Fallback Last]' : (m.providerReady ? ' [Key Ready]' : ' [Awaiting Key]');
    return `<option value="${esc(m.modelId)}"${selected}>#${esc(m.rank)} ${esc(m.displayName)} (${esc(m.providerLabel)})${esc(suffix)}</option>`;
  }).join('');

  const positionRows = trader.openPositions.length
    ? `<table class="ai-ticket-table" aria-label="AI-managed open positions"><thead><tr><th>Broker</th><th>Market</th><th>Side / Lots</th><th>Entry</th><th>Resting SL</th><th>Resting TP</th><th>Protection</th><th>P&amp;L</th></tr></thead><tbody>${
      trader.openPositions.map((p) => (
        `<tr><td>${esc(p.broker_id)} #${esc(p.ticket)}</td><td><strong>${esc(p.symbol)}</strong></td><td class="numeric">${esc(p.side)} ${esc(p.volume_lots)}</td><td class="numeric">${esc(p.price_open)}</td><td class="numeric">${esc(p.sl ?? 'Missing')}</td><td class="numeric">${esc(p.tp ?? 'None')}</td><td><span class="protection-badge">${esc(p.protectionStage)}</span></td><td class="numeric">${esc(p.profit)}</td></tr>`
      )).join('')
    }</tbody></table>`
    : '<p class="quiet-note">No open AI-managed MT5 tickets in this cycle.</p>';

  const recentFeed = trader.recentActions.length
    ? `<details class="catalog-inspection"><summary>Recent autonomous actions &amp; protection log (${esc(trader.recentActions.length)})</summary><ul class="overseer-action-log">${
      trader.recentActions.map((a) => `<li><code>${esc(a.kind)}</code> ${a.symbol ? `<strong>${esc(a.symbol)}</strong> ` : ''}${esc(a.detail)}</li>`).join('')
    }</ul></details>`
    : '';

  const issueNote = state?.aiIssue ? `<p class="quiet-note warning-text" role="alert">${esc(state.aiIssue)}</p>` : '';
  const ownerLocked = state?.sessionScope === 'DEVICE_READ_AND_EXPLAINER' || state?.ownerControlsAllowed === false;
  const modelDisabled = !models.connected || busy || ownerLocked;
  const traderDisabled = !trader.connected || busy || ownerLocked;
  const pairedNotice = trader.connected && ownerLocked
    ? '<p class="quiet-note paired-readonly-note" data-paired-readonly-notice="true">Paired Device Session (<code>DEVICE_READ_AND_EXPLAINER</code>): live observation &amp; Gemini 4 Neon Explainer are active; owner trading, risk-gear, and model controls require Primary Owner Key step-up.</p>'
    : '';
  const rg = trader.riskGear ?? STATIC_AI_TRADER.riskGear;
  const maxRiskFmt = Number(rg.ownerMaxRiskPct || 1).toFixed(2);
  const maxDdFmt = (Number(rg.ownerMaxDrawdownPct || 0.1) * 100).toFixed(2);
  const connectBtn = !trader.connected
    ? '<button type="button" class="button button-small button-primary" data-connect-loopback="true">Connect live server</button>'
    : '';
  const unlockInputType = state?.unlockKeyVisible ? 'text' : 'password';
  const unlockDraftVal = esc(state?.unlockDraft ?? '');
  const unlockVisLabel = state?.unlockKeyVisible ? 'Hide' : 'Show';
  const unlockBar = !trader.connected
    ? `<form class="mobile-unlock-bar prominent-unlock-bar" data-cockpit-unlock-form="true" autocomplete="on"><div class="unlock-bar-row"><label class="sr-only" for="overseer-access-key">Cockpit access key</label><input id="overseer-access-key" class="mobile-unlock-input" type="${unlockInputType}" name="cockpit_access_key" value="${unlockDraftVal}" autocomplete="current-password" spellcheck="false" autocapitalize="off" placeholder="Paste Cockpit access key here (or run D:\\MetaTrader5\\Launch_24x7_Cloud_Cockpit.cmd) to unlock live 24/7 cloud AI"><button type="button" class="button button-small button-secondary unlock-vis-btn" data-toggle-unlock-visibility="true" aria-pressed="${Boolean(state?.unlockKeyVisible)}">${unlockVisLabel}</button><button type="submit" class="button button-small button-primary">Unlock &amp; Connect Live Cloud</button></div><p class="unlock-helper-note">Paste your 43-character key from <code>D:\\MetaTrader5\\.cloud_cockpit.token</code> on your PC — or scan the single-use Pairing QR from an unlocked PC</p>${state?.aiIssue ? `<p class="unlock-inline-error warning-text" role="alert">${esc(state.aiIssue)}</p>` : ''}</form>`
    : '';
  const workingPill = `<span class="working-now-pill" data-working-now="true">WORKING NOW: ${esc(trader.currentFocusStatus ?? (`SCANNING ${trader.marketsEvaluated} MARKETS`))}</span>`;
  const dialSummary = resolveCockpitAggressionDial(state);
  const dialSummaryTag = `<span class="tag" data-overseer-aggression-summary="true"><span class="state-rule" aria-hidden="true"></span>Dial: ${esc(dialSummary.masterTargets.riskPctLabel)} ${esc(dialSummary.effectiveLabel)} · ${dialSummary.aiDiscretionEnabled ? 'AI Discretion ON' : 'Manual Lock'}</span>`;

  return `<section class="panel ai-overseer-panel" aria-label="AI Autonomous Trader and Human Overseer">
    <div class="section-heading">
      <div><p class="eyebrow">HUMAN AS OVERSEER · ${esc(trader.marketsEvaluated)} MARKETS (${esc(trader.fastTickMs)}ms MT5 FAST-TICK)</p><h2>Autonomous AI Trader &amp; Daily Quota</h2></div>
      <div class="market-chart-badges">
        ${connectBtn}
        ${respiteBadge}
        ${workingPill}
        ${dialSummaryTag}
        <span class="tag${modeWarning ? ' tag-warning' : (profitBankedLocked ? ' tag-profit-locked' : '')}" data-ai-status="${esc(trader.effectiveStatus)}"><span class="state-rule" aria-hidden="true"></span>${esc(trader.connected ? trader.effectiveStatus : 'AI standby (not attached)')}</span>
        <span class="tag"><span class="state-rule" aria-hidden="true"></span>${esc(trader.valveController)} · ${esc(trader.valveParameters)} params</span>
      </div>
    </div>
    <p class="panel-copy">${esc(trader.governanceReason)} Last signal: <strong>${esc(trader.lastAction)}</strong>${trader.lastSymbol !== 'None' ? ` on ${esc(trader.lastSymbol)}` : ''} · ${esc(trader.lastReason)}</p>
    ${issueNote}
    ${pairedNotice}
    ${unlockBar}
    <div class="ai-overseer-grid">
      <div class="ai-control-block">
        <label class="control-label" for="ai-model-select">Active AI Brain (#1-#8 Frontier, #9 Qwen Offline Fallback Last)</label>
        <div class="ai-model-row">
          <select id="ai-model-select" class="ai-model-select" data-select-ai-model="true" ${modelDisabled ? 'disabled' : ''}>${modelOptions}</select>
          <button type="button" class="button button-small ${models.fastScoutEnabled ? 'selected' : 'button-secondary'}" data-ai-overseer-action="TOGGLE_FAST_SCOUT" aria-pressed="${models.fastScoutEnabled}" ${modelDisabled ? 'disabled' : ''}>${models.fastScoutEnabled ? 'Gemini Decision 1 Fast Scout: ON' : 'Gemini Decision 1 Fast Scout: OFF'}</button>
        </div>
        <p class="quiet-note">Active: <strong>${esc(models.activeDisplayName)}</strong> (${esc(models.activeStatus)}) · Depth <strong>${esc(models.thinkingDepth)}</strong> (${esc(models.lastEffectiveEffort)}${models.lastLatencyMs !== null ? ` · ${esc(String(models.lastLatencyMs))}ms` : ''}) · Min prob ${esc(models.minDecisionProbability)} · Cycles ${esc(trader.cycleCount)} · Vetoes ${esc(trader.vetoCount)}</p>
      </div>
      <div class="ai-quota-block">
        <div class="quota-header">
          <strong>Daily Profit Quota &amp; Loss Circuit Breaker (${esc(q.quotaMode)})</strong>
          <span class="tag${quotaTagClass}" data-daily-quota-status="${esc(q.status)}"><span class="state-rule" aria-hidden="true"></span>${esc(q.status)}</span>
        </div>
        <progress class="quota-progress" value="${esc(pctVal)}" max="100" aria-label="Daily quota progress percent">${esc(pctVal)}%</progress>
        ${profitRatchetRow}
        <p class="quiet-note numeric">Realized today: $${esc(q.realizedNetPnlUsd)} (${esc(q.realizedPnlPct)}%) · Soft $${esc(q.softQuotaUsd)} (0.5x risk) / Hard $${esc(q.hardQuotaUsd)} lock · Max daily loss $${esc(q.maxDailyLossUsd)} · Streak ${esc(q.consecutiveLosses)}/${esc(q.maxConsecutiveLosses)} · Risk mult ${esc(q.riskMultiplier)}x</p>
        <p class="quiet-note provenance-inline" data-quota-realized-provenance="true">Provenance: ${esc(resolveRealizedPnlProvenance(state).compactSummary)}</p>
      </div>
    </div>
    <div class="risk-gear-block" role="group" aria-label="Owner risk gear and dynamic daily quota selector">
      <div class="quota-header">
        <strong>3-Gear Adaptive Risk &amp; Dynamic Daily Quota ($500 → $2,000 → $3,000)</strong>
        <span class="tag" data-active-risk-gear="${esc(rg.activeGear)}"><span class="state-rule" aria-hidden="true"></span>${esc(rg.activeGear)} · ${esc(rg.effectiveRiskPct)}% risk · $${esc(rg.effectiveSoftQuotaUsd)}/$${esc(rg.effectiveHardQuotaUsd)}</span>
      </div>
      <div class="risk-gear-buttons">
        <button type="button" class="button button-small ${rg.ownerMode === 'CONSERVATIVE' ? 'selected' : 'button-secondary'}" data-risk-gear="CONSERVATIVE" aria-pressed="${rg.ownerMode === 'CONSERVATIVE'}" ${traderDisabled ? 'disabled' : ''}>Conservative (0.50% · $500–$1k)</button>
        <button type="button" class="button button-small ${rg.ownerMode === 'AUTO_ADAPTIVE' ? 'selected' : 'button-secondary'}" data-risk-gear="AUTO_ADAPTIVE" aria-pressed="${rg.ownerMode === 'AUTO_ADAPTIVE'}" ${traderDisabled ? 'disabled' : ''}>Auto-Adaptive (0.50% → 0.75% → 1.00% · $500→$3k)</button>
        <button type="button" class="button button-small ${rg.ownerMode === 'AGGRESSIVE' ? 'selected' : 'button-secondary'}" data-risk-gear="AGGRESSIVE" aria-pressed="${rg.ownerMode === 'AGGRESSIVE'}" ${traderDisabled ? 'disabled' : ''}>Aggressive (1.00% · $2k–$3k)</button>
      </div>
      <p class="quiet-note">${esc(rg.reason)} Hard constitutional ceiling: ${esc(maxRiskFmt)}% max stop risk · ${esc(maxDdFmt)}% max drawdown · $${esc(rg.ownerHardQuotaUsd)} daily cap.</p>
    </div>
    <div class="overseer-controls" role="group" aria-label="Human overseer emergency controls">
      <button type="button" class="button button-small" data-ai-overseer-action="PAUSE_NEW_RISK" ${traderDisabled ? 'disabled' : ''}>Pause AI new risk</button>
      <button type="button" class="button button-small button-secondary" data-ai-overseer-action="RESUME_AUTONOMOUS" ${traderDisabled ? 'disabled' : ''}>Resume AI loop</button>
      <button type="button" class="button button-small button-secondary" data-ai-overseer-action="STOP_AUTOMATION" ${traderDisabled ? 'disabled' : ''}>Stop AI trader</button>
      <button type="button" class="button button-small button-warning" data-ai-overseer-action="EMERGENCY_CLOSE_ALL" ${traderDisabled ? 'disabled' : ''}>Emergency close all</button>
      <button type="button" class="button button-small button-secondary" data-ai-overseer-action="REARM_DRAWDOWN" ${traderDisabled ? 'disabled' : ''}>Re-arm &amp; unlock</button>
    </div>
    ${positionRows}
    ${recentFeed}
  </section>`;
}

export function renderAiModelCatalogPanel(aiModels) {
  const m = aiModels && typeof aiModels === 'object' && Array.isArray(aiModels.models) ? aiModels : STATIC_AI_MODELS;
  return `<section class="panel ai-catalog-panel" aria-label="AI model priority catalog">
    <div class="section-heading">
      <div><p class="eyebrow">AI MODEL HIERARCHY · QWEN #9 LAST</p><h2>Frontier &amp; Local Decision Models</h2></div>
      <span class="tag${m.connected ? '' : ' tag-warning'}"><span class="state-rule" aria-hidden="true"></span>${esc(m.connected ? `Active: ${m.activeDisplayName} (${m.activeStatus})` : 'AI catalog preview (not attached)')}</span>
    </div>
    <p class="panel-copy">All 9 models propose structured trades only; <strong>tks_meta_valve_controller</strong> (161 params) remains mandatory ahead of every MT5 or OANDA execution. Gemini Decision 1 optionally accelerates 18-market opportunity scouting.</p>
    <div class="broker-chain">${m.models.map((entry) => (
      `<div class="stage-row"><div><span class="stage-letter">#${esc(entry.rank)}</span><h3>${esc(entry.displayName)}${entry.isFallback ? ' · Offline fallback only' : ''}</h3><p>${esc(entry.providerLabel)} · <code>${esc(entry.modelId)}</code> · tier ${esc(entry.tier)}</p></div><span class="tag${entry.providerReady ? '' : ' tag-warning'}"><span class="state-rule" aria-hidden="true"></span>${esc(entry.availability)}${entry.active ? ' · SELECTED' : ''}</span></div>`
    )).join('')}</div>
  </section>`;
}

export function resolveRealizedPnlProvenance(state) {
  const trader = state?.aiTrader ?? STATIC_AI_TRADER;
  const bs = trader.bankedSession ?? STATIC_AI_TRADER.bankedSession;
  const rpl = trader.realizedPnlLedger ?? STATIC_AI_TRADER.realizedPnlLedger;
  const treasury = state?.treasury;

  const seenIds = new Set();
  const entries = [];
  const pushEntry = (raw) => {
    if (!raw || typeof raw !== 'object') return;
    const tradeId = str(raw.tradeId ?? raw.trade_id ?? '', '', 120);
    const symbol = str(raw.symbol ?? '', '', 32);
    if (!symbol || isSyntheticSyncEntry(tradeId, symbol)) return;
    const dedupKey = tradeId || `${symbol}:${raw.occurredAtUtc ?? raw.occurredAt ?? ''}:${raw.realizedPnlUsd ?? raw.realizedNetUsd ?? ''}`;
    if (seenIds.has(dedupKey)) return;
    seenIds.add(dedupKey);
    const occUtc = str(raw.occurredAtUtc ?? raw.occurredAt ?? raw.occurred_at_utc ?? raw.occurred_at ?? '', '', 64);
    const occUtcFmt = formatUtcTimestamp(occUtc);
    const occPac = str(raw.occurredAtPacific ?? raw.occurred_at_pacific ?? '', formatPacificTimestamp(occUtc), 80);
    const sessLbl = str(raw.sessionLabel ?? raw.session_label ?? '', occUtc ? forexSessionLabelForUtc(occUtc) : 'Unknown Session', 64);
    const brokerId = str(raw.brokerId ?? raw.broker_id ?? 'MT5', 'MT5', 40);
    const brokerLabel = friendlyBrokerLabel(brokerId, str(raw.brokerLabel ?? raw.broker_label ?? '', '', 48));
    entries.push(Object.freeze({
      tradeId,
      symbol,
      brokerId,
      brokerLabel,
      realizedPnlUsd: numStr(raw.realizedPnlUsd ?? raw.realizedNetUsd ?? raw.realized_pnl_usd ?? raw.realized_net_usd, '0'),
      occurredAtUtc: occUtc,
      occurredAtUtcFormatted: occUtcFmt,
      occurredAtPacific: occPac,
      sessionLabel: sessLbl,
    }));
  };

  for (const eItem of rpl.entries ?? []) pushEntry(eItem);
  for (const sItem of treasury?.tradeSweeps ?? []) pushEntry(sItem);
  for (const sItem of treasury?.recentSweeps ?? []) {
    if (!sItem?.isReconciliationSync) pushEntry(sItem);
  }

  let lastTrade = null;
  if (trader.lastTrade && !isSyntheticSyncEntry(trader.lastTrade.tradeId, trader.lastTrade.symbol)) {
    const ltBrokerId = str(trader.lastTrade.brokerId ?? 'MT5', 'MT5', 40);
    lastTrade = Object.freeze({
      ...trader.lastTrade,
      brokerId: ltBrokerId,
      brokerLabel: friendlyBrokerLabel(ltBrokerId, trader.lastTrade.brokerLabel ?? ''),
      occurredAtUtcFormatted: formatUtcTimestamp(trader.lastTrade.occurredAtUtc),
    });
  } else if (entries.length > 0) {
    const first = entries[0];
    lastTrade = Object.freeze({
      tradeId: first.tradeId,
      symbol: first.symbol,
      brokerId: first.brokerId,
      brokerLabel: first.brokerLabel,
      action: 'CLOSED_TRADE',
      realizedPnlUsd: first.realizedPnlUsd,
      occurredAtUtc: first.occurredAtUtc,
      occurredAtUtcFormatted: first.occurredAtUtcFormatted,
      occurredAtPacific: first.occurredAtPacific,
      sessionLabel: first.sessionLabel,
    });
  }

  const brokersBySym = new Map();
  for (const row of entries) {
    if (!brokersBySym.has(row.symbol)) brokersBySym.set(row.symbol, new Set());
    if (row.brokerLabel) brokersBySym.get(row.symbol).add(row.brokerLabel);
  }

  let marketRows = [];
  if ((rpl.sessionByMarket ?? []).length > 0) {
    marketRows = [...rpl.sessionByMarket];
  } else if ((bs.sessionByMarket ?? []).length > 0) {
    marketRows = [...bs.sessionByMarket];
  } else if ((rpl.lifetimeByMarket ?? []).length > 0) {
    marketRows = [...rpl.lifetimeByMarket];
  } else if (Array.isArray(treasury?.realizedByMarket) && treasury.realizedByMarket.length > 0) {
    marketRows = treasury.realizedByMarket
      .filter((m) => m?.symbol && !isSyntheticSyncEntry('', m.symbol))
      .map((m) => Object.freeze({
        symbol: m.symbol,
        brokerLabel: m.brokerLabel ?? '',
        realizedPnlUsd: m.realizedPnlUsd ?? m.realizedNetUsd ?? '0',
        tradeCount: m.tradeCount ?? 0,
        lastOccurredAtUtc: m.lastOccurredAtUtc ?? m.lastOccurredAt ?? '',
        lastOccurredAtPacific: m.lastOccurredAtPacific ?? '',
        lastSessionLabel: m.lastSessionLabel ?? 'Unknown Session',
      }));
  } else if (entries.length > 0) {
    const bySym = new Map();
    for (const row of entries) {
      const prev = bySym.get(row.symbol);
      const nextCents = (prev?.cents ?? 0n) + toCentsBigInt(row.realizedPnlUsd);
      bySym.set(row.symbol, {
        symbol: row.symbol,
        cents: nextCents,
        tradeCount: (prev?.tradeCount ?? 0) + 1,
        lastOccurredAtPacific: prev?.lastOccurredAtPacific || row.occurredAtPacific,
        lastOccurredAtUtc: prev?.lastOccurredAtUtc || row.occurredAtUtc,
        lastSessionLabel: prev?.lastSessionLabel || row.sessionLabel,
      });
    }
    marketRows = [...bySym.values()].map((m) => Object.freeze({
      symbol: m.symbol,
      brokerLabel: [...(brokersBySym.get(m.symbol) ?? [])].join(' / '),
      realizedPnlUsd: centsBigIntToDecimal(m.cents),
      tradeCount: m.tradeCount,
      lastOccurredAtUtc: m.lastOccurredAtUtc,
      lastOccurredAtPacific: m.lastOccurredAtPacific,
      lastSessionLabel: m.lastSessionLabel,
    }));
  }

  let brokerRows = [];
  if ((rpl.sessionByBroker ?? []).length > 0) {
    brokerRows = [...rpl.sessionByBroker];
  } else if ((bs.sessionByBroker ?? []).length > 0) {
    brokerRows = [...bs.sessionByBroker];
  } else if ((rpl.lifetimeByBroker ?? []).length > 0) {
    brokerRows = [...rpl.lifetimeByBroker];
  } else if (Array.isArray(treasury?.realizedByBroker) && treasury.realizedByBroker.length > 0) {
    brokerRows = [...treasury.realizedByBroker];
  } else if (entries.length > 0) {
    const byBrk = new Map();
    for (const row of entries) {
      const key = row.brokerLabel || friendlyBrokerLabel(row.brokerId);
      const prev = byBrk.get(key);
      byBrk.set(key, {
        brokerId: row.brokerId,
        brokerLabel: key,
        cents: (prev?.cents ?? 0n) + toCentsBigInt(row.realizedPnlUsd),
        tradeCount: (prev?.tradeCount ?? 0) + 1,
      });
    }
    brokerRows = [...byBrk.values()].map((b) => Object.freeze({
      brokerId: b.brokerId,
      brokerLabel: b.brokerLabel,
      realizedPnlUsd: centsBigIntToDecimal(b.cents),
      tradeCount: b.tradeCount,
    }));
  }

  const singleFallbackBroker = brokerRows.length === 1 ? brokerRows[0].brokerLabel : (lastTrade?.brokerLabel ?? '');
  const marketBreakdownText = marketRows.length > 0
    ? marketRows.map((m) => {
        const symBrokers = m.brokerLabel
          || [...(brokersBySym.get(m.symbol) ?? [])].join(' / ')
          || (marketRows.length === 1 ? singleFallbackBroker : '');
        return `${m.symbol} (${formatSignedUsd(m.realizedPnlUsd)}${symBrokers ? ` · ${symBrokers}` : ''})`;
      }).join(' · ')
    : 'No closed real-symbol trades attributed in this window';
  const brokerBreakdownText = brokerRows.length > 0
    ? brokerRows.map((b) => `${b.brokerLabel} (${formatSignedUsd(b.realizedPnlUsd ?? b.realizedNetUsd ?? '0')})`).join(' · ')
    : '';
  const sessionLabel = lastTrade?.sessionLabel
    || marketRows[0]?.lastSessionLabel
    || bs.activeRegionWindow
    || 'DAILY_NY (17:00 America/New_York)';
  const timestampText = lastTrade && (lastTrade.occurredAtPacific || lastTrade.occurredAtUtcFormatted)
    ? [lastTrade.occurredAtPacific, lastTrade.occurredAtUtcFormatted].filter(Boolean).join(' · ')
    : 'No closed-trade timestamp recorded in this session';
  const compactSummary = marketRows.length > 0 || lastTrade
    ? `${marketBreakdownText}${brokerBreakdownText ? ` · Accounts: ${brokerBreakdownText}` : ''} · Session: ${sessionLabel} · ${timestampText}`
    : (rpl.sessionProvenanceSummary && rpl.sessionProvenanceSummary !== 'No closed trades in current session yet'
      ? rpl.sessionProvenanceSummary
      : `Session: ${sessionLabel} · No closed real-symbol trades recorded yet`);

  return Object.freeze({
    lastTrade,
    entries: Object.freeze(entries.slice(0, 20)),
    marketRows: Object.freeze(marketRows),
    brokerRows: Object.freeze(brokerRows),
    marketBreakdownText,
    brokerBreakdownText,
    sessionLabel,
    timestampText,
    compactSummary,
  });
}

function resolveNextAutoWakeupLabel(bs) {
  const nextUtc = String(bs.nextSessionOpensUtc ?? '');
  const win = String(bs.activeRegionWindow ?? '').toUpperCase();
  const sdate = String(bs.sessionDate ?? '').toUpperCase();
  if (nextUtc.includes('T07:00') || win.startsWith('ASIA') || sdate.endsWith('-ASIA')) {
    return 'London Session 07:00 UTC / 23:00 PT';
  }
  if (nextUtc.includes('T12:00') || win.startsWith('LONDON') || sdate.endsWith('-LONDON')) {
    return 'New York Session 12:00 UTC / 04:00 PT';
  }
  if (nextUtc.includes('T22:00') || win.startsWith('NEW_YORK') || sdate.endsWith('-NY')) {
    return 'Asia Session 22:00 UTC / 14:00 PT';
  }
  if (bs.sessionRolloverLabel && !bs.sessionRolloverLabel.startsWith('17:00 America/New_York')) {
    return bs.sessionRolloverLabel;
  }
  return 'London Session 07:00 UTC / 23:00 PT';
}

export function renderBankedProfitsHeroBanner(state) {
  if (!state?.liveStreamConnected) {
    return `<section class="panel banked-profits-hero is-locked" data-banked-profits-locked="true" aria-label="Locked Cockpit Cloud Status">
      <div class="banked-locked-inner">
        <span class="eyebrow">24/7 CLOUD SERVER RUNNING · THIS TAB IS LOCKED</span>
        <h2>Cockpit Locked — Unlock Above or Scan Pairing QR to View Session Realized P&amp;L &amp; Internal Vault Reserve</h2>
        <p>Cockpit Locked — Your 24/7 Cloud Server is running in the background, but this browser tab is not unlocked yet. Enter your 43-character Cockpit Access Key in the Unlock bar above (or click &#39;Pair Phone / Tablet (QR)&#39; on your unlocked PC and scan with your camera) to view Session Realized P&amp;L &amp; Internal Vault Reserve, 3-Broker Equity, and Gemini 4 Neon Voice Explainer.</p>
      </div>
    </section>`;
  }

  const trader = state?.aiTrader ?? STATIC_AI_TRADER;
  const busy = Boolean(state?.aiActionBusy);
  const q = trader.dailyQuota ?? STATIC_AI_TRADER.dailyQuota;
  const bs = trader.bankedSession ?? normalizeBankedSession(null, q, trader.bankSweepReservedUsd ?? '0', trader.operatingMode ?? 'ACTIVE_TRADING');
  const liveStatus = trader.liveTradingStatus ?? normalizeLiveTradingStatus(
    null,
    trader.governanceMode ?? 'ACTIVE',
    q.status ?? 'OPEN',
    Boolean(trader.respiteMode),
    trader.openPositions ?? [],
  );
  const prov = resolveRealizedPnlProvenance(state);
  const isLiveArmed = state?.brokerRouting?.executionMode === 'LIVE' && state?.brokerRouting?.liveArmed === true;
  const isRespite = Boolean(bs.profitsLockedForSession || trader.respiteMode || bs.operatingMode === 'RESEARCH_RESPITE');
  const isUnderwater = bs.capitalStatus !== 'IN_SURPLUS';

  let statusStripTone = 'is-scanning';
  if (liveStatus.stateCode === 'TRADING_NOW_OPEN_POSITIONS') statusStripTone = 'is-trading-now';
  else if (liveStatus.stateCode === 'PAUSED_RESEARCH_RESPITE') statusStripTone = 'is-respite-paused';
  else if (liveStatus.stateCode === 'PAUSED_SAFETY_LOCK' || liveStatus.stateCode === 'STOPPED_OR_PAUSED') statusStripTone = 'is-safety-paused';

  const lt = prov.lastTrade;
  const lastTradeStripBody = lt
    ? `<span class="last-trade-label">LAST EXECUTED TRADE:</span> <strong>${esc(lt.symbol)}</strong> · Account: <strong>${esc(lt.brokerLabel || friendlyBrokerLabel(lt.brokerId))}</strong> · <span class="numeric">${esc(lt.action)}${lt.realizedPnlUsd !== null ? ` (${esc(formatSignedUsd(lt.realizedPnlUsd))})` : ''}</span> · Session: <strong>${esc(lt.sessionLabel)}</strong> · <span class="numeric">${esc([lt.occurredAtPacific, lt.occurredAtUtcFormatted].filter(Boolean).join(' · '))}</span>`
    : '<span class="last-trade-label">LAST EXECUTED TRADE:</span> No executed trades recorded yet in this ledger';

  const ledgerRowsHtml = prov.entries.length > 0
    ? `<div class="provenance-ledger-wrap" data-realized-pnl-provenance-ledger="true"><div class="provenance-ledger-head"><strong>Realized P&amp;L Per-Trade Provenance Ledger (Real Closed Trades Only)</strong><span class="quiet-note numeric">${esc(prov.marketBreakdownText)}${prov.brokerBreakdownText ? ` · Accounts: ${esc(prov.brokerBreakdownText)}` : ''}</span></div><table class="ai-ticket-table provenance-ledger-table" aria-label="Realized P&L per-trade provenance ledger"><thead><tr><th>Market</th><th>Broker Account</th><th>Session</th><th>Pacific &amp; UTC Timestamp</th><th>Realized P&amp;L</th></tr></thead><tbody>${
      prov.entries.slice(0, 8).map((row) => (
        `<tr><td><strong>${esc(row.symbol)}</strong></td><td><strong>${esc(row.brokerLabel || friendlyBrokerLabel(row.brokerId))}</strong></td><td>${esc(row.sessionLabel)}</td><td class="numeric">${esc([row.occurredAtPacific, row.occurredAtUtcFormatted].filter(Boolean).join(' · '))}</td><td class="numeric ${compareDecimalStrings(row.realizedPnlUsd, '0') < 0 ? 'is-neg' : 'is-pos'}"><strong>${esc(formatSignedUsd(row.realizedPnlUsd))}</strong></td></tr>`
      )).join('')
    }</tbody></table></div>`
    : `<div class="provenance-ledger-wrap is-empty" data-realized-pnl-provenance-ledger="true"><strong>Realized P&amp;L Per-Trade Provenance Ledger:</strong> <span class="quiet-note">No executed real-symbol closed trades recorded in this window yet (${esc(prov.sessionLabel)}).</span></div>`;

  const principalFormatted = formatExactUsd(bs.initialCapitalUsd ?? '300000');
  const signedSurplusPct = formatSignedPct(bs.netSurplusPct ?? '0');
  let principalBadgeClass = 'is-at-principal';
  let principalBadgeText = `AT PRINCIPAL: $0.00 (0.00%) AT ${principalFormatted} PRINCIPAL`;
  if (bs.capitalStatus === 'RECOVERY_MODE') {
    principalBadgeClass = 'is-recovery';
    principalBadgeText = `RECOVERY MODE: ${formatSignedUsd(bs.netSurplusUsd)} (${signedSurplusPct}) BELOW ${principalFormatted} PRINCIPAL`;
  } else if (bs.capitalStatus === 'IN_SURPLUS') {
    principalBadgeClass = 'is-in-surplus';
    principalBadgeText = `IN SURPLUS: ${formatSignedUsd(bs.netSurplusUsd)} (${signedSurplusPct}) ABOVE ${principalFormatted} PRINCIPAL`;
  }

  const sessReserveRaw = bs.sessionVaultReserved50PctUsd ?? bs.vaultSwept50PctUsd ?? '0';
  const reserveUsd = compareDecimalStrings(sessReserveRaw, '0') === 0
    && !bs.vaultSweepsPausedForRecovery
    && compareDecimalStrings(bs.bankedNetPnlUsd, '0') > 0
    && state?.treasury?.connected
    ? state.treasury.bankSweepReservedUsd
    : sessReserveRaw;
  const netSurplusCents = toCentsBigInt(bs.netSurplusUsd ?? '0');
  const totalVaultSweptCents = toCentsBigInt(bs.vaultSwept50PctUsd ?? '0');
  const surplusCompoundingUsd = netSurplusCents > 0n && netSurplusCents >= totalVaultSweptCents
    ? centsBigIntToDecimal(netSurplusCents - totalVaultSweptCents)
    : (bs.vaultRetained50PctUsd ?? '0');
  const rawTreasurySettled = state?.treasury?.connected
    ? state.treasury.confirmedSettledDisbursedUsd
    : (state?.treasury && state.treasury.connected === undefined ? state.treasury.confirmedSettledDisbursedUsd : undefined);
  const confirmedSettledUsd = rawTreasurySettled ?? bs.confirmedBankPayoutsUsd ?? '0';

  const rawTreasuryPending = state?.treasury?.connected
    ? state.treasury.pendingUnconfirmedTransfersUsd
    : (state?.treasury && state.treasury.connected === undefined ? state.treasury.pendingUnconfirmedTransfersUsd : undefined);
  const pendingUnconfirmedUsd = (rawTreasuryPending !== undefined && toCentsBigInt(rawTreasuryPending) !== 0n)
    ? rawTreasuryPending
    : (bs.pendingUnconfirmedTransfersUsd ?? rawTreasuryPending ?? '0');
  const hasPendingUnconfirmed = toCentsBigInt(pendingUnconfirmedUsd) !== 0n;

  const pctStr = String(bs.realizedPnlPct ?? '0');
  const signedPct = pctStr.startsWith('-') || pctStr === '0' || pctStr === '0.00' ? `${pctStr}%` : `+${pctStr}%`;
  const floorDisplay = compareDecimalStrings(bs.protectedProfitFloorUsd, '0') > 0
    ? formatSignedUsd(bs.protectedProfitFloorUsd)
    : '$0.00';
  const floorDetail = bs.ratchetArmed
    ? `Peak Today: ${formatSignedUsd(bs.peakRealizedPnlUsd)} · RATCHET ARMED`
    : `Peak Today: ${formatSignedUsd(bs.peakRealizedPnlUsd)} · Arms at ${formatExactUsd(q.ratchetActivationUsd)}`;
  const pnlNegative = compareDecimalStrings(bs.bankedNetPnlUsd, '0') < 0;
  const surplusNegative = compareDecimalStrings(bs.netSurplusUsd, '0') < 0;

  let card1Sub = `Equity ${formatExactUsd(bs.currentTotalEquityUsd)} vs ${principalFormatted} Principal · At starting principal`;
  if (bs.capitalStatus === 'RECOVERY_MODE') {
    card1Sub = `Equity ${formatExactUsd(bs.currentTotalEquityUsd)} vs ${principalFormatted} Principal · ${formatExactUsd(bs.deficitToPrincipalUsd)} to breakeven`;
  } else if (bs.capitalStatus === 'IN_SURPLUS') {
    card1Sub = `Equity ${formatExactUsd(bs.currentTotalEquityUsd)} vs ${principalFormatted} Principal · True surplus above High-Water Mark`;
  }

  const routingOfflineIds = [
    ...(Array.isArray(state?.brokerRouting?.shield?.offlineBrokers) ? state.brokerRouting.shield.offlineBrokers : []),
    ...(Array.isArray(state?.brokerRouting?.chain)
      ? state.brokerRouting.chain.filter((c) => c?.status === 'BROKER_OFFLINE').map((c) => c.brokerId)
      : []),
  ];
  const mergedOfflineIds = [...new Set([...(bs.offlineBrokers ?? []), ...routingOfflineIds].filter(Boolean))];
  const hasOfflineBroker = Boolean(
    bs.equityIncompleteBrokersOffline
    || state?.brokerRouting?.shield?.equityIncomplete
    || mergedOfflineIds.length > 0,
  );
  const mergedOfflineLabels = mergedOfflineIds.map((id) => friendlyBrokerLabel(id));
  const onlineDeployableRaw = bs.onlineEquityUsd
    ?? state?.brokerRouting?.shield?.onlineEquity
    ?? (trader.deployableEquityUsd && compareDecimalStrings(trader.deployableEquityUsd, '0') > 0
      ? trader.deployableEquityUsd
      : bs.currentTotalEquityUsd);
  let offlineBannerHtml = '';
  if (hasOfflineBroker) {
    const labelSummary = mergedOfflineLabels.length > 0
      ? mergedOfflineLabels.join(' · ')
      : 'MT5 Terminal';
    const offlineHeadline = mergedOfflineLabels.length > 1
      ? `BROKERS OFFLINE (${labelSummary}) — NOT A TRADING LOSS`
      : `BROKER OFFLINE (${labelSummary}) — NOT A TRADING LOSS`;
    const offlineCopy = bs.offlineBrokerNotice
      || `${mergedOfflineLabels.join(' & ') || 'One or more broker terminals'} is currently disconnected. Unreachable broker equity is excluded from active trade sizing and drawdown — this is a connection pause, NOT a trading loss.`;
    offlineBannerHtml = `<div class="offline-broker-banner" data-offline-broker-banner="true" role="status">
      <div class="offline-broker-banner-head">
        <span class="status-offline" data-offline-pill="true">OFFLINE</span>
        <strong>${esc(offlineHeadline)}</strong>
      </div>
      <p class="offline-broker-banner-copy">${esc(offlineCopy)} <strong>Online deployable equity: ${esc(formatExactUsd(onlineDeployableRaw))}</strong></p>
    </div>`;
    card1Sub = `${card1Sub} · Online deployable equity: ${formatExactUsd(onlineDeployableRaw)} (${labelSummary} offline — NOT a loss)`;
  }

  const card2Eyebrow = isUnderwater
    ? '2 · Session Recovery Today (Internal Ledger)'
    : '2 · Session Realized Net P&amp;L (Today · Internal Ledger)';
  const card2Sub = isUnderwater
    ? `Rebuilding principal — NOT surplus profit · ${bs.closedTrades} closed trades (${bs.winCount}W / ${bs.lossCount}L) · 70% Session Floor: ${floorDisplay} · ${floorDetail}`
    : `${signedPct} · ${bs.closedTrades} closed trades (${bs.winCount}W / ${bs.lossCount}L) · Internal ledger figure · 70% Session Floor: ${floorDisplay} · ${floorDetail} · Session ${bs.sessionDate}`;

  const pendingTransferHtml = hasPendingUnconfirmed
    ? ` · <strong class="pending-transfer-inline">Pending / Unconfirmed Transfers: ${esc(formatExactUsd(pendingUnconfirmedUsd))} (excluded from surplus)</strong>`
    : '';
  const settledPayoutSummaryHtml = `<strong class="confirmed-payout-inline">Confirmed Settled Payouts: ${esc(formatExactUsd(confirmedSettledUsd))}</strong> <span class="quiet-note">(Confirmed Bank Payouts: ${esc(formatExactUsd(confirmedSettledUsd))})</span>${pendingTransferHtml}`;

  const card3ValueHtml = bs.vaultSweepsPausedForRecovery
    ? `Bank Vault Sweeps Paused ($0.00 until > ${esc(principalFormatted)})`
    : `${esc(formatExactUsd(reserveUsd))} Internal Vault Reserve`;
  const card3SubHtml = bs.vaultSweepsPausedForRecovery
    ? `100% of recovery stays in trading capital · ${settledPayoutSummaryHtml}`
    : `${esc(formatExactUsd(surplusCompoundingUsd))} Surplus Compounding · Internal Ledger Reserve — Not a Confirmed Bank Payout · ${settledPayoutSummaryHtml}`;

  const legBadge = bs.activeSessionLeg > 1 ? ` (Leg #${esc(String(bs.activeSessionLeg))})` : '';
  const card4ModeHtml = isRespite
    ? `RESEARCH RESPITE · Quota Lock Active${legBadge} (0 New Risk · Observing 20 Markets)`
    : `ACTIVE TRADING${legBadge}`;
  const isRegionalActive = isUnderwater && bs.sessionCadence !== 'DAILY_NY';
  const nextWakeupLabel = resolveNextAutoWakeupLabel(bs);
  const card4ScheduleHtml = isRegionalActive
    ? `Window: ${esc(bs.activeRegionWindow)} · Next Auto-Wakeup: ${esc(nextWakeupLabel)}${bs.nextSessionOpensUtc ? ` · ${esc(bs.nextSessionOpensUtc)}` : ''} (17:00 America/New_York once in surplus)`
    : `Window: ${esc(bs.activeRegionWindow)} · Next Session Rollover: ${esc(bs.sessionRolloverLabel)}${bs.nextSessionOpensUtc ? ` · ${esc(bs.nextSessionOpensUtc)}` : ''}`;
  const ownerLocked = state?.sessionScope === 'DEVICE_READ_AND_EXPLAINER' || state?.ownerControlsAllowed === false;
  const cadenceDisabled = busy || ownerLocked;
  const isRegionalBtnSelected = bs.sessionCadence === 'REGIONAL_RECOVERY' || bs.sessionCadence === 'REGIONAL_8H';
  const advanceBtnHtml = bs.canAdvanceRecoverySession
    ? `<button type="button" class="button button-small button-warning recovery-advance-btn" data-ai-overseer-action="ADVANCE_RECOVERY_SESSION" ${cadenceDisabled ? 'disabled' : ''}>Resume Next Region Session</button>`
    : '';

  return `<section class="panel banked-profits-hero is-connected ${isUnderwater ? 'is-recovery-mode' : 'is-in-surplus'}" data-banked-profits-hero="true" aria-label="Principal High-Water Mark and Session Vault Scoreboard">
    <div class="hero-live-telemetry-bar">
      <div class="live-trading-status-strip ${statusStripTone}" data-live-trading-status-strip="true" data-trading-state-code="${esc(liveStatus.stateCode)}">
        <span class="live-pulse-dot" aria-hidden="true"></span>
        <strong>${esc(liveStatus.headline)}</strong>
      </div>
      <div class="last-real-trade-strip" data-last-real-trade-strip="true">${lastTradeStripBody}</div>
    </div>
    ${offlineBannerHtml}
    <div class="banked-hero-head">
      <div>
        <p class="eyebrow">PRINCIPAL HIGH-WATER MARK &amp; INTERNAL VAULT LEDGER · ZERO-SCROLL SCOREBOARD</p>
        <h2>${isUnderwater ? 'Principal Recovery Progress, 70% Session Floor &amp; High-Water Vault Gate' : 'True Surplus Above Principal, 70% Session Floor &amp; 50% Internal Vault Reserve'}</h2>
        <p class="banked-accounting-disclaimer" data-accounting-disclaimer="true"><strong>Internal Accounting Figure — Not a Confirmed Bank Payout</strong> · Basis: <code>${esc(bs.accountingBasis ?? 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT')}</code> · Zero vault sweeps occur while total equity is at or below ${esc(principalFormatted)} starting principal.</p>
      </div>
      <div class="banked-hero-actions">
        <span class="principal-status-badge ${principalBadgeClass}" data-principal-status-badge="${esc(bs.capitalStatus)}">${esc(principalBadgeText)}</span>
        <span class="exec-mode-badge ${isLiveArmed ? 'is-live-armed' : 'is-demo-mode'}" data-session-funding-mode="${isLiveArmed ? 'LIVE' : 'DEMO_PRACTICE'}">${isLiveArmed ? 'LIVE REAL-MONEY ACCOUNT' : 'DEMO PRACTICE ACCOUNT (SIMULATED FUNDS)'}</span>
        <span class="banked-status-pill ${isRespite ? 'is-respite' : 'is-active'}">${isRespite ? 'RESEARCH RESPITE · QUOTA LOCK ACTIVE' : 'ACTIVE SESSION P&amp;L TRACKER'}</span>
      </div>
    </div>
    <div class="banked-hero-grid">
      <article class="banked-hero-card ${isUnderwater ? 'is-recovery-card' : ''}" data-principal-surplus-card="true">
        <span class="eyebrow">1 · Net Surplus vs Starting Capital (${esc(principalFormatted)})</span>
        <div class="banked-hero-value numeric ${surplusNegative ? 'is-neg' : (bs.capitalStatus === 'IN_SURPLUS' ? 'is-pos' : '')}">${esc(formatSignedUsd(bs.netSurplusUsd))}</div>
        <p class="banked-hero-sub numeric">${esc(card1Sub)}</p>
      </article>
      <article class="banked-hero-card ${isUnderwater ? 'is-recovery-card' : ''}">
        <span class="eyebrow">${card2Eyebrow}</span>
        <div class="banked-hero-value numeric ${pnlNegative ? 'is-neg' : 'is-pos'}">${esc(formatSignedUsd(bs.bankedNetPnlUsd))}</div>
        <p class="banked-hero-sub numeric">${esc(card2Sub)}</p>
        <p class="banked-hero-sub provenance-sub numeric" data-card2-pnl-provenance="true">Provenance: ${esc(prov.compactSummary)}</p>
      </article>
      <article class="banked-hero-card ${bs.vaultSweepsPausedForRecovery ? 'is-recovery-card' : ''}">
        <span class="eyebrow">3 · 50% Principal High-Water Vault &amp; Confirmed Payouts</span>
        <div class="banked-hero-value numeric ${bs.vaultSweepsPausedForRecovery ? 'banked-hero-paused' : ''}">${card3ValueHtml}</div>
        <p class="banked-hero-sub numeric">${card3SubHtml}</p>
      </article>
      <article class="banked-hero-card">
        <span class="eyebrow">4 · Session Mode &amp; Recovery Cadence</span>
        <div class="banked-hero-value banked-hero-mode">${card4ModeHtml}</div>
        <p class="banked-hero-sub">${card4ScheduleHtml}</p>
        <div class="cadence-toggle-group" role="group" aria-label="Session cadence mode">
          <button type="button" class="button button-small cadence-toggle-btn ${bs.sessionCadence === 'AUTO' ? 'selected' : 'button-secondary'}" data-ai-session-cadence="AUTO" aria-pressed="${bs.sessionCadence === 'AUTO'}" ${cadenceDisabled ? 'disabled' : ''}>Auto (3-Region Recovery → 17:00 NY)</button>
          <button type="button" class="button button-small cadence-toggle-btn ${isRegionalBtnSelected ? 'selected' : 'button-secondary'}" data-ai-session-cadence="REGIONAL_8H" aria-pressed="${isRegionalBtnSelected}" ${cadenceDisabled ? 'disabled' : ''}>3-Region 8h (Asia · London · NY)</button>
          <button type="button" class="button button-small cadence-toggle-btn ${bs.sessionCadence === 'DAILY_NY' ? 'selected' : 'button-secondary'}" data-ai-session-cadence="DAILY_NY" aria-pressed="${bs.sessionCadence === 'DAILY_NY'}" ${cadenceDisabled ? 'disabled' : ''}>Daily 17:00 America/New_York</button>
        </div>
        <div class="banked-card-cta">${advanceBtnHtml}<button type="button" class="button button-small button-primary banked-voice-btn" data-open-voice-explainer="true">Ask / Speak to Gemini 4 Neon</button></div>
      </article>
    </div>
    ${ledgerRowsHtml}
  </section>`;
}
