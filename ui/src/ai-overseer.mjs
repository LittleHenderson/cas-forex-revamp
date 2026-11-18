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
const QUOTA_STATUSES = Object.freeze(['OPEN', 'SOFT_QUOTA_REACHED', 'DAILY_QUOTA_LOCKED', 'DAILY_LOSS_CIRCUIT_TRIPPED']);
const PROTECTION_STAGES = Object.freeze(['INITIAL_SL', 'BREAKEVEN_LOCKED', 'TRAILING_ACTIVE']);
const INDEX_PAIRS = Object.freeze(['NAS100', 'US30', 'SPX500', 'XAUUSD']);

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
  fastTickMs: '50',
  cadence: '50ms_FAST_TICK',
  marketsEvaluated: '18',
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
  }),
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
  return Object.freeze({
    connected: true,
    humanRole: str(doc.human_role, 'OVERSEER_ONLY'),
    governanceMode: govMode,
    governanceReason: str(doc.governance_reason, 'Autonomous loop active.'),
    effectiveStatus: str(doc.effective_status, govMode),
    fastTickMs: numStr(doc.fast_tick_ms, '50'),
    cadence: str(doc.cadence, '50ms_FAST_TICK'),
    marketsEvaluated: numStr(doc.markets_evaluated, '18'),
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
    bankSweepReservedUsd: numStr(doc.bank_sweep_reserved_usd, '0'),
    lastAction: str(doc.last_action, 'WAIT'),
    lastSymbol: doc.last_symbol ? str(doc.last_symbol) : 'None',
    lastReason: str(doc.last_reason, 'None'),
    lastValveScore: doc.last_valve_score ? str(doc.last_valve_score) : 'Unknown',
    vetoCount: numStr(doc.veto_count, '0'),
    valveController: str(doc.valve_controller, 'tks_meta_valve_controller'),
    valveParameters: numStr(doc.valve_parameters, '161'),
    valveThreshold: str(doc.valve_threshold, '0.55'),
    dailyQuota: Object.freeze({
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
    }),
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

export function renderAiOverseerPanel(state) {
  const trader = state?.aiTrader ?? STATIC_AI_TRADER;
  const models = state?.aiModels ?? STATIC_AI_MODELS;
  const busy = Boolean(state?.aiActionBusy);
  const q = trader.dailyQuota;
  const pctRaw = Number(q.quotaProgressPct);
  const pctVal = Number.isFinite(pctRaw) ? Math.max(0, Math.min(100, pctRaw)) : 0;
  const quotaWarning = q.status === 'DAILY_QUOTA_LOCKED' || q.status === 'DAILY_LOSS_CIRCUIT_TRIPPED';
  const modeWarning = !trader.connected || trader.governanceMode !== 'ACTIVE' || quotaWarning;

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

  return `<section class="panel ai-overseer-panel" aria-label="AI Autonomous Trader and Human Overseer">
    <div class="section-heading">
      <div><p class="eyebrow">HUMAN AS OVERSEER · ${esc(trader.marketsEvaluated)} MARKETS (${esc(trader.fastTickMs)}ms MT5 FAST-TICK)</p><h2>Autonomous AI Trader &amp; Daily Quota</h2></div>
      <div class="market-chart-badges">
        <span class="tag${modeWarning ? ' tag-warning' : ''}" data-ai-status="${esc(trader.effectiveStatus)}"><span class="state-rule" aria-hidden="true"></span>${esc(trader.connected ? trader.effectiveStatus : 'AI standby (not attached)')}</span>
        <span class="tag"><span class="state-rule" aria-hidden="true"></span>${esc(trader.valveController)} · ${esc(trader.valveParameters)} params</span>
      </div>
    </div>
    <p class="panel-copy">${esc(trader.governanceReason)} Last signal: <strong>${esc(trader.lastAction)}</strong>${trader.lastSymbol !== 'None' ? ` on ${esc(trader.lastSymbol)}` : ''} · ${esc(trader.lastReason)}</p>
    ${issueNote}
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
          <span class="tag${quotaWarning ? ' tag-warning' : ''}" data-daily-quota-status="${esc(q.status)}"><span class="state-rule" aria-hidden="true"></span>${esc(q.status)}</span>
        </div>
        <progress class="quota-progress" value="${esc(pctVal)}" max="100" aria-label="Daily quota progress percent">${esc(pctVal)}%</progress>
        <p class="quiet-note numeric">Realized today: $${esc(q.realizedNetPnlUsd)} (${esc(q.realizedPnlPct)}%) · Soft $${esc(q.softQuotaUsd)} (0.5x risk) / Hard $${esc(q.hardQuotaUsd)} lock · Max daily loss $${esc(q.maxDailyLossUsd)} · Streak ${esc(q.consecutiveLosses)}/${esc(q.maxConsecutiveLosses)} · Risk mult ${esc(q.riskMultiplier)}x</p>
      </div>
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
