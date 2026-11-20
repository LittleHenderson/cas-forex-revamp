// Pure display and normalization helpers for the 9-model AI catalog, 18-market US Index stream,
// Daily Profit Quota ($500-$1,000), and Human-as-Overseer Autonomous AI panel.
// No DOM, no storage, no inline styles; every dynamic string is normalized and escaped.

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

function normalizeBankedSession(doc, dailyQuota, bankSweepReservedUsd, operatingMode) {
  const bs = doc?.banked_session && typeof doc.banked_session === 'object' && !Array.isArray(doc.banked_session)
    ? doc.banked_session
    : null;
  const lockedDefault = dailyQuota.status === 'DAILY_QUOTA_LOCKED' || dailyQuota.status === 'PROFIT_FLOOR_LOCKED';
  const defaultTotalRealized = compareDecimalStrings(dailyQuota.realizedNetPnlUsd, '0') > 0
    ? dailyQuota.realizedNetPnlUsd
    : '0';
  const vaultSwept50PctUsd = numStr(bs?.vault_swept_50pct_usd, bankSweepReservedUsd);
  const vaultRetained50PctUsd = numStr(bs?.vault_retained_50pct_usd, bankSweepReservedUsd);
  return Object.freeze({
    schema: 'cas-forex.banked-session/1',
    accountingBasis: str(bs?.accounting_basis, 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT', 80),
    sessionDate: str(bs?.session_date, dailyQuota.sessionDate, 40),
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
    confirmedBankPayoutsUsd: numStr(bs?.confirmed_bank_payouts_usd, '0'),
    profitsLockedForSession: typeof bs?.profits_locked_for_session === 'boolean' ? bs.profits_locked_for_session : lockedDefault,
    operatingMode: str(bs?.operating_mode, operatingMode, 40),
    sessionRolloverLabel: str(bs?.session_rollover_label, '17:00 America/New_York (14:00 Pacific)', 80),
    nextSessionOpensUtc: bs?.next_session_opens_utc ? str(bs.next_session_opens_utc, '', 64) : null,
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
    effectiveRiskPct: '1',
    ownerMaxRiskPct: '5',
    effectiveSoftQuotaUsd: '500',
    effectiveHardQuotaUsd: '1000',
    ownerHardQuotaUsd: '3000',
    softDrawdownDownshiftPct: '0.1',
    ownerMaxDrawdownPct: '0.2',
    reason: 'Auto-Adaptive Gear ready under owner Valve ceiling.',
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
    profitsLockedForSession: false,
    operatingMode: 'ACTIVE_TRADING',
    sessionRolloverLabel: '17:00 America/New_York (14:00 Pacific)',
    nextSessionOpensUtc: null,
  }),
  accountingBasis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
  confirmedBankPayoutsUsd: '0',
  sessionVaultReserved50PctUsd: '0',
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
  const openPositions = rawPositions.map((p) => Object.freeze({
    broker_id: str(p.broker_id, 'MT5'),
    ticket: numStr(p.ticket, '0'),
    position_id: `${str(p.broker_id, 'MT5')}-${numStr(p.ticket, '0')}`,
    instrument_id: str(p.symbol, 'UNKNOWN'),
    symbol: str(p.symbol, 'UNKNOWN'),
    side: p.side === 'SELL' ? 'SELL' : 'BUY',
    volume_lots: str(p.volume_lots, '0'),
    quantity: str(p.volume_lots, '0'),
    entry_price: str(p.price_open, '0'),
    price_open: str(p.price_open, '0'),
    stop_price: p.sl === null || p.sl === undefined ? null : str(p.sl, '0'),
    sl: p.sl === null || p.sl === undefined ? null : str(p.sl, '0'),
    take_profit_price: p.tp === null || p.tp === undefined ? null : str(p.tp, '0'),
    tp: p.tp === null || p.tp === undefined ? null : str(p.tp, '0'),
    profit: numStr(p.profit, '0'),
    protectionStage: PROTECTION_STAGES.includes(p.protection_stage) ? p.protection_stage : 'INITIAL_SL',
  }));
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
    sessionVaultReserved50PctUsd: bankedSession.sessionVaultReserved50PctUsd,
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
      effectiveRiskPct: numStr(doc.risk_gear.effective_risk_pct, '1'),
      ownerMaxRiskPct: numStr(doc.risk_gear.owner_max_risk_pct, '5'),
      effectiveSoftQuotaUsd: numStr(doc.risk_gear.effective_soft_quota_usd, '500'),
      effectiveHardQuotaUsd: numStr(doc.risk_gear.effective_hard_quota_usd, '1000'),
      ownerHardQuotaUsd: numStr(doc.risk_gear.owner_hard_quota_usd, '3000'),
      softDrawdownDownshiftPct: numStr(doc.risk_gear.soft_drawdown_downshift_pct, '0.1'),
      ownerMaxDrawdownPct: numStr(doc.risk_gear.owner_max_drawdown_pct, '0.2'),
      reason: str(doc.risk_gear.reason, 'Owner-bounded adaptive risk gear.', 200),
    }) : STATIC_AI_TRADER.riskGear,
    dailyQuota,
    bankedSession,
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
  const connectBtn = !trader.connected
    ? '<button type="button" class="button button-small button-primary" data-connect-loopback="true">Connect live server</button>'
    : '';
  const unlockInputType = state?.unlockKeyVisible ? 'text' : 'password';
  const unlockDraftVal = esc(state?.unlockDraft ?? '');
  const unlockVisLabel = state?.unlockKeyVisible ? 'Hide' : 'Show';
  const unlockBar = !trader.connected
    ? `<form class="mobile-unlock-bar prominent-unlock-bar" data-cockpit-unlock-form="true" autocomplete="on"><div class="unlock-bar-row"><label class="sr-only" for="overseer-access-key">Cockpit access key</label><input id="overseer-access-key" class="mobile-unlock-input" type="${unlockInputType}" name="cockpit_access_key" value="${unlockDraftVal}" autocomplete="current-password" spellcheck="false" autocapitalize="off" placeholder="Paste Cockpit access key here (or run D:\\MetaTrader5\\Launch_24x7_Cloud_Cockpit.cmd) to unlock live 24/7 cloud AI"><button type="button" class="button button-small button-secondary unlock-vis-btn" data-toggle-unlock-visibility="true" aria-pressed="${Boolean(state?.unlockKeyVisible)}">${unlockVisLabel}</button><button type="submit" class="button button-small button-primary">Unlock &amp; Connect Live Cloud</button></div><p class="unlock-helper-note">Paste your 43-character key from <code>D:\\MetaTrader5\\.cloud_cockpit.token</code> on your PC — or scan the 1-second Pairing QR from an unlocked PC</p>${state?.aiIssue ? `<p class="unlock-inline-error warning-text" role="alert">${esc(state.aiIssue)}</p>` : ''}</form>`
    : '';
  const workingPill = `<span class="working-now-pill" data-working-now="true">WORKING NOW: ${esc(trader.currentFocusStatus ?? (`SCANNING ${trader.marketsEvaluated} MARKETS`))}</span>`;

  return `<section class="panel ai-overseer-panel" aria-label="AI Autonomous Trader and Human Overseer">
    <div class="section-heading">
      <div><p class="eyebrow">HUMAN AS OVERSEER · ${esc(trader.marketsEvaluated)} MARKETS (${esc(trader.fastTickMs)}ms MT5 FAST-TICK)</p><h2>Autonomous AI Trader &amp; Daily Quota</h2></div>
      <div class="market-chart-badges">
        ${connectBtn}
        ${respiteBadge}
        ${workingPill}
        <span class="tag${modeWarning ? ' tag-warning' : (profitBankedLocked ? ' tag-profit-locked' : '')}" data-ai-status="${esc(trader.effectiveStatus)}"><span class="state-rule" aria-hidden="true"></span>${esc(trader.connected ? trader.effectiveStatus : 'AI standby (not attached)')}</span>
        <span class="tag"><span class="state-rule" aria-hidden="true"></span>${esc(trader.valveController)} · ${esc(trader.valveParameters)} params</span>
      </div>
    </div>
    <p class="panel-copy">${esc(trader.governanceReason)} Last signal: <strong>${esc(trader.lastAction)}</strong>${trader.lastSymbol !== 'None' ? ` on ${esc(trader.lastSymbol)}` : ''} · ${esc(trader.lastReason)}</p>
    ${issueNote}
    ${unlockBar}
    <div class="ai-overseer-grid">
      <div class="ai-control-block">
        <label class="control-label" for="ai-model-select">Active AI Brain (#1-#8 Frontier, #9 Qwen Offline Fallback Last)</label>
        <div class="ai-model-row">
          <select id="ai-model-select" class="ai-model-select" data-select-ai-model="true" ${!models.connected || busy ? 'disabled' : ''}>${modelOptions}</select>
          <button type="button" class="button button-small ${models.fastScoutEnabled ? 'selected' : 'button-secondary'}" data-ai-overseer-action="TOGGLE_FAST_SCOUT" aria-pressed="${models.fastScoutEnabled}" ${!models.connected || busy ? 'disabled' : ''}>${models.fastScoutEnabled ? 'Gemini Decision 1 Fast Scout: ON' : 'Gemini Decision 1 Fast Scout: OFF'}</button>
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
      </div>
    </div>
    <div class="risk-gear-block" role="group" aria-label="Owner risk gear and dynamic daily quota selector">
      <div class="quota-header">
        <strong>3-Gear Adaptive Risk &amp; Dynamic Daily Quota ($500 → $2,000 → $3,000)</strong>
        <span class="tag" data-active-risk-gear="${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).activeGear)}"><span class="state-rule" aria-hidden="true"></span>${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).activeGear)} · ${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).effectiveRiskPct)}% risk · $${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).effectiveSoftQuotaUsd)}/$${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).effectiveHardQuotaUsd)}</span>
      </div>
      <div class="risk-gear-buttons">
        <button type="button" class="button button-small ${(trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMode === 'CONSERVATIVE' ? 'selected' : 'button-secondary'}" data-risk-gear="CONSERVATIVE" aria-pressed="${(trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMode === 'CONSERVATIVE'}" ${!trader.connected || busy ? 'disabled' : ''}>Conservative (1% · $500–$1k)</button>
        <button type="button" class="button button-small ${(trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMode === 'AUTO_ADAPTIVE' ? 'selected' : 'button-secondary'}" data-risk-gear="AUTO_ADAPTIVE" aria-pressed="${(trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMode === 'AUTO_ADAPTIVE'}" ${!trader.connected || busy ? 'disabled' : ''}>Auto-Adaptive (1%→2.5%→5% · $500→$3k)</button>
        <button type="button" class="button button-small ${(trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMode === 'AGGRESSIVE' ? 'selected' : 'button-secondary'}" data-risk-gear="AGGRESSIVE" aria-pressed="${(trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMode === 'AGGRESSIVE'}" ${!trader.connected || busy ? 'disabled' : ''}>Aggressive (5% · $2k–$3k)</button>
      </div>
      <p class="quiet-note">${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).reason)} Hard owner ceiling: ${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMaxRiskPct)}% max stop risk · ${esc(String(Math.round(Number((trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerMaxDrawdownPct) * 100)))}% max drawdown · $${esc((trader.riskGear ?? STATIC_AI_TRADER.riskGear).ownerHardQuotaUsd)} daily cap.</p>
    </div>
    <div class="overseer-controls" role="group" aria-label="Human overseer emergency controls">
      <button type="button" class="button button-small" data-ai-overseer-action="PAUSE_NEW_RISK" ${!trader.connected || busy ? 'disabled' : ''}>Pause AI new risk</button>
      <button type="button" class="button button-small button-secondary" data-ai-overseer-action="RESUME_AUTONOMOUS" ${!trader.connected || busy ? 'disabled' : ''}>Resume AI loop</button>
      <button type="button" class="button button-small button-secondary" data-ai-overseer-action="STOP_AUTOMATION" ${!trader.connected || busy ? 'disabled' : ''}>Stop AI trader</button>
      <button type="button" class="button button-small button-warning" data-ai-overseer-action="EMERGENCY_CLOSE_ALL" ${!trader.connected || busy ? 'disabled' : ''}>Emergency close all</button>
      <button type="button" class="button button-small button-secondary" data-ai-overseer-action="REARM_DRAWDOWN" ${!trader.connected || busy ? 'disabled' : ''}>Re-arm &amp; unlock</button>
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
  const q = trader.dailyQuota ?? STATIC_AI_TRADER.dailyQuota;
  const bs = trader.bankedSession ?? normalizeBankedSession(null, q, trader.bankSweepReservedUsd ?? '0', trader.operatingMode ?? 'ACTIVE_TRADING');
  const isLiveArmed = state?.brokerRouting?.executionMode === 'LIVE' && state?.brokerRouting?.liveArmed === true;
  const isRespite = Boolean(bs.profitsLockedForSession || trader.respiteMode || bs.operatingMode === 'RESEARCH_RESPITE');

  const sessReserveRaw = bs.sessionVaultReserved50PctUsd ?? bs.vaultSwept50PctUsd ?? '0';
  const reserveUsd = compareDecimalStrings(sessReserveRaw, '0') === 0
    && compareDecimalStrings(bs.bankedNetPnlUsd, '0') > 0
    && state?.treasury?.connected
    ? state.treasury.bankSweepReservedUsd
    : sessReserveRaw;
  const retainedRaw = bs.vaultRetained50PctUsd ?? '0';
  const retainedUsd = compareDecimalStrings(retainedRaw, '0') === 0
    && compareDecimalStrings(bs.bankedNetPnlUsd, '0') > 0
    && state?.treasury?.connected
    ? state.treasury.retainedTradingUsd
    : retainedRaw;
  const rawTreasuryDisbursed = state?.treasury?.connected
    ? state.treasury.disbursedToBankUsd
    : (state?.treasury && state.treasury.connected === undefined ? state.treasury.disbursedToBankUsd : undefined);
  const confirmedPayoutsUsd = rawTreasuryDisbursed ?? bs.confirmedBankPayoutsUsd ?? '0';

  const pctStr = String(bs.realizedPnlPct ?? '0');
  const signedPct = pctStr.startsWith('-') || pctStr === '0' || pctStr === '0.00' ? `${pctStr}%` : `+${pctStr}%`;
  const floorDisplay = compareDecimalStrings(bs.protectedProfitFloorUsd, '0') > 0
    ? formatSignedUsd(bs.protectedProfitFloorUsd)
    : '$0.00';
  const floorDetail = bs.ratchetArmed
    ? `Peak Today: ${formatSignedUsd(bs.peakRealizedPnlUsd)} · RATCHET ARMED`
    : `Peak Today: ${formatSignedUsd(bs.peakRealizedPnlUsd)} · Arms at ${formatExactUsd(q.ratchetActivationUsd)}`;
  const pnlNegative = compareDecimalStrings(bs.bankedNetPnlUsd, '0') < 0;

  return `<section class="panel banked-profits-hero is-connected" data-banked-profits-hero="true" aria-label="Session Realized P&amp;L and Internal Vault Reserve Scoreboard">
    <div class="banked-hero-head">
      <div>
        <p class="eyebrow">SESSION REALIZED P&amp;L &amp; INTERNAL VAULT LEDGER · ZERO-SCROLL SCOREBOARD</p>
        <h2>Today&#39;s Session Realized Net P&amp;L, 70% Protected Floor &amp; 50% Internal Vault Reserve</h2>
        <p class="banked-accounting-disclaimer" data-accounting-disclaimer="true"><strong>Internal Accounting Figure — Not a Confirmed Bank Payout</strong> · Basis: <code>${esc(bs.accountingBasis ?? 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT')}</code> · Settled bank transfers appear separately under Confirmed Bank Payouts.</p>
      </div>
      <div class="banked-hero-actions">
        <span class="exec-mode-badge ${isLiveArmed ? 'is-live-armed' : 'is-demo-mode'}" data-session-funding-mode="${isLiveArmed ? 'LIVE' : 'DEMO_PRACTICE'}">${isLiveArmed ? 'LIVE REAL-MONEY ACCOUNT' : 'DEMO PRACTICE ACCOUNT (SIMULATED FUNDS)'}</span>
        <span class="banked-status-pill ${isRespite ? 'is-respite' : 'is-active'}">${isRespite ? 'RESEARCH RESPITE · QUOTA LOCK ACTIVE' : 'ACTIVE SESSION P&amp;L TRACKER'}</span>
      </div>
    </div>
    <div class="banked-hero-grid">
      <article class="banked-hero-card">
        <span class="eyebrow">1 · Session Realized Net P&amp;L (Today · Internal Ledger)</span>
        <div class="banked-hero-value numeric ${pnlNegative ? 'is-neg' : 'is-pos'}">${esc(formatSignedUsd(bs.bankedNetPnlUsd))}</div>
        <p class="banked-hero-sub numeric">${esc(signedPct)} · ${esc(bs.closedTrades)} closed trades (${esc(bs.winCount)}W / ${esc(bs.lossCount)}L) · Internal ledger figure · Session ${esc(bs.sessionDate)}</p>
      </article>
      <article class="banked-hero-card">
        <span class="eyebrow">2 · 70% Protected Profit Floor (Session Rule)</span>
        <div class="banked-hero-value numeric is-pos">${esc(floorDisplay)}</div>
        <p class="banked-hero-sub numeric">${esc(floorDetail)}</p>
      </article>
      <article class="banked-hero-card">
        <span class="eyebrow">3 · 50% Internal Vault Reserve &amp; Confirmed Payouts</span>
        <div class="banked-hero-value numeric">${esc(formatExactUsd(reserveUsd))} Internal Vault Reserve</div>
        <p class="banked-hero-sub numeric">${esc(formatExactUsd(retainedUsd))} Retained Compounding · <strong class="confirmed-payout-inline">Confirmed Bank Payouts: ${esc(formatExactUsd(confirmedPayoutsUsd))}</strong></p>
      </article>
      <article class="banked-hero-card">
        <span class="eyebrow">4 · Session Mode &amp; 17:00 Rollover</span>
        <div class="banked-hero-value banked-hero-mode">${isRespite ? 'RESEARCH RESPITE · Quota Lock Active (0 New Risk · Observing 20 Markets)' : 'ACTIVE TRADING'}</div>
        <p class="banked-hero-sub">Next Session Rollover: ${esc(bs.sessionRolloverLabel)}${bs.nextSessionOpensUtc ? ` · ${esc(bs.nextSessionOpensUtc)}` : ''}</p>
        <div class="banked-card-cta"><button type="button" class="button button-small button-primary banked-voice-btn" data-open-voice-explainer="true">Ask / Speak to Gemini 4 Neon</button></div>
      </article>
    </div>
  </section>`;
}
