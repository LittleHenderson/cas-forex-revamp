/**
 * CAS Forex Profit Expansion Analytics, 5-Tier Parallel Race Board,
 * 50%/50% Profit-Sweep Bank Vault, Thermal Market Signal Heatmap & Dark-Mode Obsidian Canvases.
 * Strict CSP compliant: zero inline style attributes, zero eval, safe HTML escaping.
 */
import {
  computeMarketSessions,
  forexSessionLabelForUtc,
  formatExactUsd,
  formatPacificTimestamp,
  formatSignedUsd,
  formatUtcTimestamp,
  friendlyBrokerLabel,
  isSyntheticSyncEntry,
  resolveRealizedPnlProvenance,
} from './ai-overseer.mjs';

const e = (value) => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#39;');

export const MAX_TREASURY_BYTES = 131072;
export const THINKING_DEPTH_OPTIONS = Object.freeze([
  Object.freeze({ id: 'AUTO', label: 'Auto (2-Speed)' }),
  Object.freeze({ id: 'LOW', label: 'Fast (Low)' }),
  Object.freeze({ id: 'MEDIUM', label: 'Balanced (Medium)' }),
  Object.freeze({ id: 'HIGH', label: 'Deep (High)' }),
]);

const str = (v, fallback = '', maxLen = 160) => (
  typeof v === 'string' && v.trim() ? v.trim().slice(0, maxLen) : fallback
);
const numStr = (v, fallback = '0') => {
  if (typeof v === 'string' && /^-?\d+(?:\.\d+)?$/.test(v.trim())) return v.trim();
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return fallback;
};

function toCentsBigIntLocal(raw) {
  const clean = typeof raw === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(raw.trim()) ? raw.trim() : '0';
  const neg = clean.startsWith('-');
  const unsigned = neg ? clean.slice(1) : clean;
  const [intPart = '0', fracPart = ''] = unsigned.split('.');
  const frac2 = fracPart.slice(0, 2).padEnd(2, '0');
  let mag = BigInt(intPart) * 100n + BigInt(frac2);
  if (fracPart.length >= 3 && fracPart[2] >= '5') mag += 1n;
  if (mag === 0n) return 0n;
  return neg ? -mag : mag;
}

function centsToDecLocal(cents) {
  if (cents === 0n) return '0';
  const neg = cents < 0n;
  const abs = neg ? -cents : cents;
  const whole = abs / 100n;
  const rem = abs % 100n;
  if (rem === 0n) return `${neg ? '-' : ''}${whole}`;
  return `${neg ? '-' : ''}${whole}.${String(rem).padStart(2, '0')}`;
}

export const STATIC_TREASURY = Object.freeze({
  connected: false,
  sweepRatio: '0.5',
  sweepRatioPct: '50',
  autoSweepEnabled: true,
  preferredRail: 'BROKER_2FA_MANUAL',
  totalRealizedProfitUsd: '0',
  retainedTradingUsd: '0',
  bankSweepReservedUsd: '0',
  disbursedToBankUsd: '0',
  confirmedSettledDisbursedUsd: '0',
  pendingUnconfirmedTransfersUsd: '0',
  pending2faConfirmationUsd: '0',
  pendingDisbursementUsd: '0',
  recentSweeps: Object.freeze([]),
  tradeSweeps: Object.freeze([]),
  realizedByMarket: Object.freeze([]),
  realizedByBroker: Object.freeze([]),
  recentTransfers: Object.freeze([]),
});

export const STATIC_PARALLEL_TIERS = Object.freeze({
  connected: false,
  tierCount: 5,
  tiers: Object.freeze([
    Object.freeze({ tierId: 'TIER_1_CURRENT', label: 'Current Barbell ($300,000)', colorToken: 'tier-300k', startingCapitalUsd: '300000', balanceUsd: '300000', equityUsd: '300000', netGainUsd: '0', growthPct: '0', peakEquityUsd: '300000', drawdownPct: '0', openPositions: 0, closedTrades: 0, winRatePct: '0', profitFactor: '0.00', bankSweepReservedUsd: '0', retainedTradingUsd: '0', lastSkipReason: null }),
    Object.freeze({ tierId: 'TIER_2_1000', label: 'Tier $1,000 Starter', colorToken: 'tier-1000', startingCapitalUsd: '1000', balanceUsd: '1000', equityUsd: '1000', netGainUsd: '0', growthPct: '0', peakEquityUsd: '1000', drawdownPct: '0', openPositions: 0, closedTrades: 0, winRatePct: '0', profitFactor: '0.00', bankSweepReservedUsd: '0', retainedTradingUsd: '0', lastSkipReason: null }),
    Object.freeze({ tierId: 'TIER_3_3000', label: 'Tier $3,000 Growth', colorToken: 'tier-3000', startingCapitalUsd: '3000', balanceUsd: '3000', equityUsd: '3000', netGainUsd: '0', growthPct: '0', peakEquityUsd: '3000', drawdownPct: '0', openPositions: 0, closedTrades: 0, winRatePct: '0', profitFactor: '0.00', bankSweepReservedUsd: '0', retainedTradingUsd: '0', lastSkipReason: null }),
    Object.freeze({ tierId: 'TIER_4_6000', label: 'Tier $6,000 Accelerator', colorToken: 'tier-6000', startingCapitalUsd: '6000', balanceUsd: '6000', equityUsd: '6000', netGainUsd: '0', growthPct: '0', peakEquityUsd: '6000', drawdownPct: '0', openPositions: 0, closedTrades: 0, winRatePct: '0', profitFactor: '0.00', bankSweepReservedUsd: '0', retainedTradingUsd: '0', lastSkipReason: null }),
    Object.freeze({ tierId: 'TIER_5_300', label: 'Tier $300 Micro Challenge', colorToken: 'tier-300', startingCapitalUsd: '300', balanceUsd: '300', equityUsd: '300', netGainUsd: '0', growthPct: '0', peakEquityUsd: '300', drawdownPct: '0', openPositions: 0, closedTrades: 0, winRatePct: '0', profitFactor: '0.00', bankSweepReservedUsd: '0', retainedTradingUsd: '0', lastSkipReason: null }),
  ]),
  growthSeries: Object.freeze({}),
});

function normalizeSweepRow(s) {
  const tradeId = str(s?.trade_id, '');
  const symbol = str(s?.symbol, '');
  const brokerId = str(s?.broker_id, '');
  const brokerLabel = friendlyBrokerLabel(brokerId, str(s?.broker_label ?? '', '', 48));
  const occurredAt = str(s?.occurred_at, '');
  const isReconciliationSync = typeof s?.is_reconciliation_sync === 'boolean'
    ? s.is_reconciliation_sync
    : isSyntheticSyncEntry(tradeId, symbol);
  return Object.freeze({
    tradeId,
    symbol,
    brokerId,
    brokerLabel,
    realizedNetUsd: numStr(s?.realized_net_usd, '0'),
    retainedTradingUsd: numStr(s?.retained_trading_usd, '0'),
    bankSweepUsd: numStr(s?.bank_sweep_usd, '0'),
    occurredAt,
    occurredAtPacific: str(s?.occurred_at_pacific, formatPacificTimestamp(occurredAt), 80),
    sessionLabel: str(s?.session_label, occurredAt ? forexSessionLabelForUtc(occurredAt) : 'Unknown Session', 64),
    isReconciliationSync,
  });
}

export function normalizeTreasury(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Treasury payload must be a JSON object.');
  if (doc.schema !== 'cas-forex.profit-vault/1') throw new Error('Unexpected treasury schema.');
  const sweeps = Array.isArray(doc.recent_sweeps) ? doc.recent_sweeps.slice(0, 50).map(normalizeSweepRow) : [];
  const tradeSweeps = Array.isArray(doc.trade_sweeps)
    ? doc.trade_sweeps
        .slice(0, 50)
        .map(normalizeSweepRow)
        .filter((row) => !row.isReconciliationSync && Boolean(row.symbol) && !isSyntheticSyncEntry(row.tradeId, row.symbol))
    : sweeps.filter((row) => !row.isReconciliationSync && Boolean(row.symbol) && !isSyntheticSyncEntry(row.tradeId, row.symbol));

  let realizedByMarket = [];
  if (Array.isArray(doc.realized_by_market)) {
    realizedByMarket = doc.realized_by_market
      .filter((m) => m && typeof m === 'object' && !Array.isArray(m) && str(m.symbol, '') && !isSyntheticSyncEntry('', m.symbol))
      .map((m) => {
        const occ = str(m.last_occurred_at, '');
        return Object.freeze({
          symbol: str(m.symbol, ''),
          realizedNetUsd: numStr(m.realized_net_usd ?? m.realized_pnl_usd, '0'),
          tradeCount: Number.isSafeInteger(m.trade_count) ? m.trade_count : 0,
          winCount: Number.isSafeInteger(m.win_count) ? m.win_count : 0,
          lossCount: Number.isSafeInteger(m.loss_count) ? m.loss_count : 0,
          lastOccurredAt: occ,
          lastOccurredAtPacific: str(m.last_occurred_at_pacific, formatPacificTimestamp(occ), 80),
          lastSessionLabel: str(m.last_session_label, occ ? forexSessionLabelForUtc(occ) : 'Unknown Session', 64),
        });
      });
  } else if (tradeSweeps.length > 0) {
    const bySym = new Map();
    for (const row of tradeSweeps) {
      const prev = bySym.get(row.symbol);
      const rowCents = toCentsBigIntLocal(row.realizedNetUsd);
      bySym.set(row.symbol, {
        symbol: row.symbol,
        cents: (prev?.cents ?? 0n) + rowCents,
        tradeCount: (prev?.tradeCount ?? 0) + 1,
        winCount: (prev?.winCount ?? 0) + (rowCents > 0n ? 1 : 0),
        lossCount: (prev?.lossCount ?? 0) + (rowCents < 0n ? 1 : 0),
        lastOccurredAt: prev?.lastOccurredAt || row.occurredAt,
        lastOccurredAtPacific: prev?.lastOccurredAtPacific || row.occurredAtPacific,
        lastSessionLabel: prev?.lastSessionLabel || row.sessionLabel,
      });
    }
    realizedByMarket = [...bySym.values()]
      .sort((a, b) => a.symbol.localeCompare(b.symbol))
      .map((m) => Object.freeze({
        symbol: m.symbol,
        realizedNetUsd: centsToDecLocal(m.cents),
        tradeCount: m.tradeCount,
        winCount: m.winCount,
        lossCount: m.lossCount,
        lastOccurredAt: m.lastOccurredAt,
        lastOccurredAtPacific: m.lastOccurredAtPacific,
        lastSessionLabel: m.lastSessionLabel,
      }));
  }

  let realizedByBroker = [];
  if (Array.isArray(doc.realized_by_broker)) {
    realizedByBroker = doc.realized_by_broker
      .filter((b) => b && typeof b === 'object' && !Array.isArray(b) && str(b.broker_id ?? b.broker_label, '') && !isSyntheticSyncEntry('', b.broker_id ?? ''))
      .map((b) => {
        const bid = str(b.broker_id ?? b.broker_label, '');
        const occ = str(b.last_occurred_at, '');
        return Object.freeze({
          brokerId: bid,
          brokerLabel: friendlyBrokerLabel(bid, str(b.broker_label ?? '', '', 48)),
          realizedNetUsd: numStr(b.realized_net_usd ?? b.realized_pnl_usd, '0'),
          tradeCount: Number.isSafeInteger(b.trade_count) ? b.trade_count : 0,
          winCount: Number.isSafeInteger(b.win_count) ? b.win_count : 0,
          lossCount: Number.isSafeInteger(b.loss_count) ? b.loss_count : 0,
          lastOccurredAt: occ,
          lastOccurredAtPacific: str(b.last_occurred_at_pacific, formatPacificTimestamp(occ), 80),
          lastSessionLabel: str(b.last_session_label, occ ? forexSessionLabelForUtc(occ) : 'Unknown Session', 64),
        });
      });
  } else if (tradeSweeps.length > 0) {
    const byBrk = new Map();
    for (const row of tradeSweeps) {
      const key = row.brokerLabel || friendlyBrokerLabel(row.brokerId);
      const prev = byBrk.get(key);
      const rowCents = toCentsBigIntLocal(row.realizedNetUsd);
      byBrk.set(key, {
        brokerId: row.brokerId || key,
        brokerLabel: key,
        cents: (prev?.cents ?? 0n) + rowCents,
        tradeCount: (prev?.tradeCount ?? 0) + 1,
        winCount: (prev?.winCount ?? 0) + (rowCents > 0n ? 1 : 0),
        lossCount: (prev?.lossCount ?? 0) + (rowCents < 0n ? 1 : 0),
        lastOccurredAt: prev?.lastOccurredAt || row.occurredAt,
        lastOccurredAtPacific: prev?.lastOccurredAtPacific || row.occurredAtPacific,
        lastSessionLabel: prev?.lastSessionLabel || row.sessionLabel,
      });
    }
    realizedByBroker = [...byBrk.values()]
      .sort((a, b) => a.brokerLabel.localeCompare(b.brokerLabel))
      .map((b) => Object.freeze({
        brokerId: b.brokerId,
        brokerLabel: b.brokerLabel,
        realizedNetUsd: centsToDecLocal(b.cents),
        tradeCount: b.tradeCount,
        winCount: b.winCount,
        lossCount: b.lossCount,
        lastOccurredAt: b.lastOccurredAt,
        lastOccurredAtPacific: b.lastOccurredAtPacific,
        lastSessionLabel: b.lastSessionLabel,
      }));
  }

  const transfers = Array.isArray(doc.recent_transfers) ? doc.recent_transfers.slice(0, 20).map((t) => Object.freeze({
    transferId: str(t.transfer_id, ''),
    rail: str(t.rail, ''),
    destinationBankId: str(t.destination_bank_id, ''),
    amountUsd: numStr(t.amount_usd, '0'),
    status: str(t.status, ''),
    createdAt: str(t.created_at, ''),
  })) : [];

  return Object.freeze({
    connected: true,
    sweepRatio: numStr(doc.sweep_ratio, '0.5'),
    sweepRatioPct: numStr(doc.sweep_ratio_pct, '50'),
    autoSweepEnabled: Boolean(doc.auto_sweep_enabled),
    preferredRail: str(doc.preferred_rail, 'BROKER_2FA_MANUAL'),
    totalRealizedProfitUsd: numStr(doc.total_realized_profit_usd, '0'),
    retainedTradingUsd: numStr(doc.retained_trading_usd, '0'),
    bankSweepReservedUsd: numStr(doc.bank_sweep_reserved_usd, '0'),
    disbursedToBankUsd: numStr(doc.disbursed_to_bank_usd, '0'),
    confirmedSettledDisbursedUsd: numStr(doc.confirmed_settled_disbursed_usd, '0'),
    pendingUnconfirmedTransfersUsd: numStr(doc.pending_or_unconfirmed_transfers_usd, '0'),
    pending2faConfirmationUsd: numStr(doc.pending_2fa_confirmation_usd, '0'),
    pendingDisbursementUsd: numStr(doc.pending_disbursement_usd, '0'),
    recentSweeps: Object.freeze(sweeps),
    tradeSweeps: Object.freeze(tradeSweeps),
    realizedByMarket: Object.freeze(realizedByMarket),
    realizedByBroker: Object.freeze(realizedByBroker),
    recentTransfers: Object.freeze(transfers),
  });
}

export function normalizeParallelTiers(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Parallel tiers payload must be a JSON object.');
  if (doc.schema !== 'cas-forex.parallel-tiers/1') throw new Error('Unexpected parallel tiers schema.');
  const rawTiers = Array.isArray(doc.tiers) ? doc.tiers : [];
  const tiers = rawTiers.map((t) => Object.freeze({
    tierId: str(t.tier_id, ''),
    label: str(t.label, ''),
    colorToken: str(t.color_class || t.color_token, 'tier-300k'),
    startingCapitalUsd: numStr(t.starting_capital_usd, '0'),
    balanceUsd: numStr(t.balance_usd, '0'),
    equityUsd: numStr(t.equity_usd, '0'),
    netGainUsd: numStr(t.net_gain_usd, '0'),
    growthPct: numStr(t.growth_pct, '0'),
    peakEquityUsd: numStr(t.peak_equity_usd, '0'),
    drawdownPct: numStr(t.drawdown_pct, '0'),
    openPositions: Number.isSafeInteger(t.open_positions) ? t.open_positions : 0,
    closedTrades: Number.isSafeInteger(t.closed_trades) ? t.closed_trades : 0,
    winRatePct: numStr(t.win_rate_pct, '0'),
    profitFactor: str(t.profit_factor, '0.00'),
    bankSweepReservedUsd: numStr(t.bank_sweep_reserved_usd, '0'),
    retainedTradingUsd: numStr(t.retained_trading_usd, '0'),
    lastSkipReason: t.last_skip_reason ? str(t.last_skip_reason, '', 120) : null,
  }));
  const rawSeries = doc.growth_series && typeof doc.growth_series === 'object' ? doc.growth_series : {};
  const series = {};
  for (const [k, pts] of Object.entries(rawSeries)) {
    if (!Array.isArray(pts)) continue;
    series[k] = Object.freeze(pts.slice(-120).map((pt) => Object.freeze({
      observedAt: str(pt.observed_at, ''),
      equityUsd: numStr(pt.equity_usd, '0'),
      growthPct: numStr(pt.growth_pct, '0'),
      drawdownPct: numStr(pt.drawdown_pct, '0'),
    })));
  }
  return Object.freeze({
    connected: true,
    tierCount: tiers.length,
    tiers: Object.freeze(tiers),
    growthSeries: Object.freeze(series),
  });
}

export function renderAiTopSwitcherBar(state) {
  const models = state?.aiModels ?? {};
  const trader = state?.aiTrader ?? {};
  const modelList = Array.isArray(models.models) ? models.models : [];
  const busy = Boolean(state?.aiActionBusy);
  const connected = Boolean(models.connected);
  const activeDepth = str(models.thinkingDepth || trader.thinkingDepth, 'AUTO').toUpperCase();
  const effDepth = str(models.lastEffectiveEffort || trader.lastEffectiveEffort, 'low').toUpperCase();
  const latMs = models.lastLatencyMs ?? trader.lastLatencyMs;
  const regime = str(trader.lastRegime, 'TREND_IGNITION');
  const isPaused = trader.governanceMode && trader.governanceMode !== 'ACTIVE';
  const focusStatus = str(trader.currentFocusStatus, `SCANNING ${str(trader.marketsEvaluated, '20')} MARKETS`);
  const sessionsObj = trader.marketSessions ?? computeMarketSessions(Date.now(), Boolean(state?.liveStreamConnected && Number(trader.cycleCount) > 0));
  const sessionPills = (sessionsObj.sessions ?? []).map((s) => (
    `<span class="session-pill ${s.open ? 'session-open' : 'session-closed'}" title="${e(s.windowUtc)}">${e(s.label)}: ${s.open ? 'OPEN' : 'CLOSED'}</span>`
  )).join('');

  const optionsHtml = modelList.map((m) => {
    const sel = m.modelId === models.activeModelId ? ' selected' : '';
    const suffix = m.isFallback ? ' [Offline Fallback]' : (m.providerReady ? ' [Ready]' : ' [Needs Key]');
    return `<option value="${e(m.modelId)}"${sel}>#${e(m.rank)} ${e(m.displayName)} (${e(m.providerLabel)})${e(suffix)}</option>`;
  }).join('');

  const depthPills = THINKING_DEPTH_OPTIONS.map((opt) => {
    const active = opt.id === activeDepth;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-thinking-depth="${e(opt.id)}" aria-pressed="${active}" ${!connected || busy ? 'disabled' : ''}>${e(opt.label)}</button>`;
  }).join('');

  return `<section class="panel ai-top-switcher" aria-label="Prominent AI Brain Switcher and Thinking Depth">
    <div class="ai-top-row">
      <div class="ai-top-group">
        <span class="eyebrow">ACTIVE AI BRAIN · 2-SPEED DEPTH</span>
        <div class="ai-model-row">
          <select id="top-ai-model-select" class="ai-model-select" aria-label="Prominent Active AI Model Selector" data-select-ai-model="true" ${!connected || busy ? 'disabled' : ''}>${optionsHtml || '<option value="claude-fable-5.2">#1 Claude Fable 5.2 [Preview]</option>'}</select>
          <button type="button" class="button button-small ${models.fastScoutEnabled ? 'selected' : 'button-secondary'}" data-ai-overseer-action="TOGGLE_FAST_SCOUT" aria-pressed="${Boolean(models.fastScoutEnabled)}" ${!connected || busy ? 'disabled' : ''}>${models.fastScoutEnabled ? 'Scout: ON' : 'Scout: OFF'}</button>
          <button type="button" class="button button-small ${!isPaused ? 'selected' : 'button-secondary'}" data-ai-overseer-action="${isPaused ? 'RESUME_AUTONOMOUS' : 'PAUSE_NEW_RISK'}" ${!trader.connected || busy ? 'disabled' : ''}>${isPaused ? 'Resume Auto-Trade' : 'Auto-Trade ACTIVE'}</button>
        </div>
      </div>
      <div class="ai-top-group">
        <span class="eyebrow">THINKING DEPTH MODE (NON-BLOCKING 50MS PROTECTION)</span>
        <div class="segmented" role="group" aria-label="Thinking depth selector">${depthPills}</div>
        <div class="ai-depth-badges">
          <span class="working-now-pill" data-top-working-now="true">WORKING NOW: ${e(focusStatus)}</span>
          <span class="tag"><span class="state-rule" aria-hidden="true"></span>Depth: ${e(activeDepth)} → Effective ${e(effDepth)}${latMs !== null && latMs !== undefined ? ` (${e(String(latMs))}ms)` : ''}</span>
          <span class="tag"><span class="state-rule" aria-hidden="true"></span>Regime: ${e(regime)}</span>
        </div>
      </div>
    </div>
    <div class="session-strip" aria-label="Global Forex and US Indices market sessions">
      <span class="session-pill ${sessionsObj.forex245Open ? 'session-open' : 'session-closed'}">${e(sessionsObj.forexLabel)} (${e(sessionsObj.utcTime)})</span>
      ${sessionPills}
      <span class="session-pill ${sessionsObj.usIndicesStatus === 'WEEKEND_CLOSED' || sessionsObj.usIndicesStatus === 'DAILY_BREAK' ? 'session-closed' : 'session-open'}">US Indices &amp; Gold: ${e(sessionsObj.usIndicesLabel)}</span>
      <span class="session-pill ${sessionsObj.mt5TickFresh ? 'session-open' : 'session-closed'}">MT5 50ms Feed: ${sessionsObj.mt5TickFresh ? 'LIVE' : 'STANDBY'}</span>
    </div>
  </section>`;
}

export function renderParallelTiersSection(state) {
  const pt = state?.parallelTiers ?? STATIC_PARALLEL_TIERS;
  const rows = pt.tiers.map((t) => {
    const negGain = String(t.netGainUsd).startsWith('-');
    const skipLabel = t.lastSkipReason ? t.lastSkipReason : (t.openPositions > 0 ? 'EXECUTING' : 'READY');
    const warn = Boolean(t.lastSkipReason);
    return `<tr>
      <td><strong>${e(t.label)}</strong><br><small><code>${e(t.tierId)}</code></small></td>
      <td class="numeric">$${e(t.startingCapitalUsd)}</td>
      <td class="numeric"><strong>$${e(t.equityUsd)}</strong></td>
      <td class="numeric ${negGain ? 'delta-neg' : 'delta-pos'}">${negGain ? '' : '+'}${e(t.growthPct)}%</td>
      <td class="numeric ${negGain ? 'delta-neg' : 'delta-pos'}">$${e(t.netGainUsd)}</td>
      <td class="numeric">$${e(t.bankSweepReservedUsd)}</td>
      <td class="numeric">${e(t.drawdownPct)}%</td>
      <td class="numeric">${e(t.winRatePct)}% / PF ${e(t.profitFactor)}</td>
      <td class="numeric">${e(String(t.openPositions))}</td>
      <td><span class="tag${warn ? ' tag-warning' : ''}"><span class="state-rule" aria-hidden="true"></span>${e(skipLabel)}</span></td>
    </tr>`;
  }).join('');

  return `<section class="panel parallel-tiers-panel" aria-label="5-Tier Parallel Account Growth Race">
    <div class="section-heading">
      <div><p class="eyebrow">SECTION B.5 · SHARED 50MS STREAM · ZERO EXTRA AI API COST</p><h2>5-Tier Parallel Account Growth Race</h2></div>
      <span class="tag"><span class="state-rule" aria-hidden="true"></span>${pt.connected ? 'Live Parallel Engine' : 'Preview (Standby)'}</span>
    </div>
    <p class="panel-copy">All 5 account sizes ($300, $1,000, $3,000, $6,000, and $300,000) subscribe to the single 50ms stream with independent ForexMetaValveGate 1.00% stop-risk verification, ROUND_FLOOR 0.01 lot sizing, real bid/ask + ECN commissions, and 50%/50% Bank Vault sweeps.</p>
    <div class="tier-race-chart-wrap">
      <canvas class="analytics-canvas" data-tiers-race-canvas="true" width="860" height="220" aria-label="5-Tier normalized percentage ROI growth race chart"></canvas>
    </div>
    <table class="ai-ticket-table" aria-label="5-Tier parallel scoreboard">
      <thead><tr><th>Tier</th><th>Start</th><th>Equity</th><th>% ROI</th><th>Net $</th><th>50% Vault</th><th>DD %</th><th>Win / PF</th><th>Open</th><th>Status / Veto</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

export function buildThermalMarketTiles(state) {
  const trader = state?.aiTrader ?? {};
  const actions = Array.isArray(trader.recentActions) ? trader.recentActions : [];
  const openPos = [
    ...(Array.isArray(trader.openPositions) ? trader.openPositions : []),
    ...(Array.isArray(state?.projection?.positions) ? state.projection.positions : []),
  ];

  const actionStats = new Map();
  for (const a of actions) {
    const sym = str(a?.symbol, '').toUpperCase();
    if (!sym || isSyntheticSyncEntry('', sym)) continue;
    const prev = actionStats.get(sym) ?? { count: 0, lastKind: 'WAIT' };
    actionStats.set(sym, { count: prev.count + 1, lastKind: str(a.kind, prev.lastKind) });
  }
  const openSet = new Set(
    openPos
      .map((p) => str(p?.symbol ?? p?.instrument_id ?? '', '').toUpperCase())
      .filter(Boolean),
  );

  const rawItems = [];
  const seenPairs = new Set();
  for (const m of state?.indexStream?.markets ?? []) {
    const p = str(m?.pair, '').toUpperCase();
    if (!p || seenPairs.has(p)) continue;
    seenPairs.add(p);
    rawItems.push({ ...m, pair: p, isIndex: true });
  }
  for (const s of state?.marketStream?.streams ?? []) {
    const p = str(s?.pair, '').toUpperCase();
    if (!p || seenPairs.has(p)) continue;
    seenPairs.add(p);
    rawItems.push({ ...s, pair: p, isIndex: false });
  }

  const valveThreshold = numStr(trader.valveThreshold, '0.55');
  return Object.freeze(rawItems.map((item) => {
    const pair = item.pair;
    const chgNum = Number(item.change_24h_pct ?? 0);
    const candles = Array.isArray(item.candles_m1) && item.candles_m1.length
      ? item.candles_m1.slice(-6)
      : (Array.isArray(item.candles_m5) ? item.candles_m5.slice(-6) : []);
    let greenBars = 0;
    let redBars = 0;
    for (const c of candles) {
      const diff = Number(c.c) - Number(c.o);
      if (diff > 0) greenBars += 1;
      else if (diff < 0) redBars += 1;
    }
    const candleBias = candles.length > 0 ? (greenBars - redBars) / candles.length : 0;
    const compositeScore = chgNum + candleBias * 0.25;

    let heatClass = 'heat-neutral';
    let signalLabel = 'NEUTRAL';
    if (compositeScore >= 0.35) {
      heatClass = 'heat-hot-buy';
      signalLabel = 'HOT BUY';
    } else if (compositeScore > 0.05) {
      heatClass = 'heat-warm-buy';
      signalLabel = 'WARMING';
    } else if (compositeScore <= -0.35) {
      heatClass = 'heat-cold-sell';
      signalLabel = 'COLD SELL';
    } else if (compositeScore < -0.05) {
      heatClass = 'heat-cool-sell';
      signalLabel = 'COOLING';
    }

    const absIntensity = Math.min(100, Math.max(12, Math.round(Math.min(1, Math.abs(compositeScore) / 0.8) * 100)));
    const spreadStr = numStr(item.spread_points ?? item.spread_pips, '0');
    const spreadNum = Number(spreadStr);
    const spreadUnit = item.isIndex ? 'pts' : 'pips';
    const spreadTight = spreadNum <= (item.isIndex ? 3.5 : 2.0);
    const stats = actionStats.get(pair) ?? { count: 0, lastKind: 'SCAN' };
    const isVetoed = /VETO/i.test(stats.lastKind);
    const valveBadge = isVetoed
      ? `Valve < ${valveThreshold} VETO`
      : (spreadTight ? `Valve ≥ ${valveThreshold} READY` : `Valve ≥ ${valveThreshold} GUARD`);

    return Object.freeze({
      pair,
      displayLabel: str(item.display_pair, pair, 36),
      bid: numStr(item.bid, '0'),
      ask: numStr(item.ask, '0'),
      mid: numStr(item.mid ?? item.bid, '0'),
      change24hPct: numStr(item.change_24h_pct, '0.00'),
      changePositive: chgNum > 0,
      changeNegative: chgNum < 0,
      heatClass,
      signalLabel,
      momentumWidth: absIntensity,
      spreadText: `${spreadStr} ${spreadUnit} · ${spreadTight ? 'TIGHT' : 'WIDE'}`,
      signalCount: stats.count,
      lastKind: stats.lastKind,
      hasOpenPosition: openSet.has(pair),
      valveBadge,
    });
  }));
}

export function renderEquityAndAnalyticsSection(state) {
  const treasury = state?.treasury ?? STATIC_TREASURY;
  const trader = state?.aiTrader ?? {};
  const bs = trader.bankedSession ?? null;
  const busy = Boolean(state?.aiActionBusy);
  const actions = Array.isArray(trader.recentActions) ? trader.recentActions : [];
  const selectedIdx = Number.isInteger(state?.inspectedTradeIdx) ? state.inspectedTradeIdx : 0;
  const inspected = actions[selectedIdx] ?? null;
  const prov = resolveRealizedPnlProvenance(state);

  const capStatus = str(trader.capitalStatus ?? bs?.capitalStatus ?? '', '');
  const isUnderwater = capStatus
    ? capStatus !== 'IN_SURPLUS'
    : (toCentsBigIntLocal(treasury.bankSweepReservedUsd) === 0n && toCentsBigIntLocal(treasury.retainedTradingUsd) > 0n);

  const initPrincipalUsd = numStr(trader.initialCapitalUsd ?? bs?.initialCapitalUsd, '300000');
  const curEquityUsd = numStr(trader.currentTotalEquityUsd ?? bs?.currentTotalEquityUsd, initPrincipalUsd);
  const deficitUsd = numStr(trader.deficitToPrincipalUsd ?? bs?.deficitToPrincipalUsd, '0');
  const netSurplusUsd = numStr(trader.netSurplusUsd ?? bs?.netSurplusUsd, '0');
  const initCents = toCentsBigIntLocal(initPrincipalUsd);
  const curCents = toCentsBigIntLocal(curEquityUsd);
  const progressBps = initCents > 0n && curCents > 0n
    ? ((curCents * 10000n) / initCents) + (((curCents * 10000n) % initCents) * 2n >= initCents ? 1n : 0n)
    : 10000n;
  const rawProgressPct = initCents > 0n
    ? Math.min(100, Math.max(0, Number(progressBps) / 100))
    : 100;
  const progressText = rawProgressPct.toFixed(2);
  const svgBarWidth = Math.max(0, Math.min(200, Math.round(rawProgressPct * 2)));

  const allocationModeTitle = isUnderwater
    ? '100% Rebuilding Principal (Recovery Mode)'
    : '50% Compounding / 50% Internal Vault Reserve (Surplus Mode)';
  const gaugeCaption = isUnderwater
    ? `${formatExactUsd(curEquityUsd)} / ${formatExactUsd(initPrincipalUsd)} Principal (${progressText}%) · ${formatExactUsd(deficitUsd)} to breakeven`
    : `${formatExactUsd(curEquityUsd)} / ${formatExactUsd(initPrincipalUsd)} Principal (100.00%) · ${formatSignedUsd(netSurplusUsd)} True Surplus`;

  // Thermal Market Signal Heatmap tiles from live indexStream + marketStream
  const thermalTiles = buildThermalMarketTiles(state);
  const thermalGridHtml = thermalTiles.length > 0
    ? `<div class="thermal-heatmap-grid" data-thermal-market-heatmap="true" role="list" aria-label="Thermal market signal heatmap">${
      thermalTiles.map((tile) => {
        const chgSign = tile.changePositive && !String(tile.change24hPct).startsWith('+') ? '+' : '';
        return `<article class="thermal-tile ${e(tile.heatClass)}" role="listitem" data-thermal-pair="${e(tile.pair)}">
          <div class="thermal-tile-top">
            <strong>${e(tile.pair)}</strong>
            <span class="thermal-signal-badge">${e(tile.signalLabel)}${tile.hasOpenPosition ? ' · LIVE POS' : ''}</span>
          </div>
          <div class="thermal-price-row numeric">
            <span>Mid ${e(tile.mid)}</span>
            <span class="${tile.changeNegative ? 'delta-neg' : (tile.changePositive ? 'delta-pos' : '')}">${chgSign}${e(tile.change24hPct)}%</span>
          </div>
          <svg class="thermal-momentum-svg" viewBox="0 0 100 6" role="img" aria-label="${e(tile.pair)} candle momentum ${e(String(tile.momentumWidth))}%">
            <rect class="thermal-bar-track" x="0" y="0" width="100" height="6" rx="3"></rect>
            <rect class="thermal-bar-fill" x="0" y="0" width="${e(String(tile.momentumWidth))}" height="6" rx="3"></rect>
          </svg>
          <div class="thermal-meta-row numeric">
            <span>${e(tile.spreadText)}</span>
            <span>Signals: ${e(String(tile.signalCount))}</span>
          </div>
          <div class="thermal-valve-row"><code>${e(tile.valveBadge)}</code></div>
        </article>`;
      }).join('')
    }</div>`
    : `<div class="thermal-heatmap-grid is-standby" data-thermal-market-heatmap="true" role="list" aria-label="Thermal market signal heatmap"><div class="thermal-standby-note" role="listitem">Live 20-market thermal signal tiles populate automatically once the 50ms MT5 / Index stream attaches.</div></div>`;

  // Market breakdown from recent actions (excluding synthetic syncs)
  const symStats = new Map();
  for (const a of actions) {
    if (!a.symbol || isSyntheticSyncEntry('', a.symbol)) continue;
    const prev = symStats.get(a.symbol) ?? { count: 0, lastKind: a.kind };
    symStats.set(a.symbol, { count: prev.count + 1, lastKind: a.kind });
  }
  const mktRows = symStats.size
    ? [...symStats.entries()].map(([sym, info]) => `<tr><td><strong>${e(sym)}</strong></td><td class="numeric">${e(String(info.count))}</td><td>${e(info.lastKind)}</td></tr>`).join('')
    : '<tr><td colspan="3" class="quiet-note">Awaiting closed or active multi-market executions.</td></tr>';

  // Daily calendar cells from real trade sweeps (falling back to non-sync recentSweeps)
  const calSource = treasury.tradeSweeps?.length
    ? treasury.tradeSweeps
    : treasury.recentSweeps.filter((s) => !s.isReconciliationSync && !isSyntheticSyncEntry(s.tradeId, s.symbol));
  const dayMap = new Map();
  for (const s of calSource) {
    const day = (s.occurredAt || '').slice(0, 10) || 'Today';
    dayMap.set(day, (dayMap.get(day) ?? 0) + Number(s.realizedNetUsd || 0));
  }
  const calCells = dayMap.size
    ? [...dayMap.entries()].slice(-14).map(([day, net]) => {
        const cls = net > 0 ? 'cal-cell cal-pos' : (net < 0 ? 'cal-cell cal-neg' : 'cal-cell cal-flat');
        return `<div class="${cls}"><small>${e(day)}</small><strong class="numeric">${net >= 0 ? '+' : ''}${e(net.toFixed(2))}</strong></div>`;
      }).join('')
    : '<div class="cal-cell cal-flat"><small>Today</small><strong>$0.00</strong></div>';

  const vaultProvenanceRows = prov.entries.length > 0
    ? `<ul class="vault-provenance-list" data-vault-trade-provenance="true">${
      prov.entries.slice(0, 6).map((r) => (
        `<li><strong>${e(r.symbol)}</strong> · Account: <strong>${e(r.brokerLabel || friendlyBrokerLabel(r.brokerId))}</strong> · <span class="numeric">${e(formatSignedUsd(r.realizedPnlUsd))}</span> · ${e(r.sessionLabel)} · <span class="numeric">${e([r.occurredAtPacific, r.occurredAtUtcFormatted].filter(Boolean).join(' · '))}</span></li>`
      )).join('')
    }</ul>`
    : '<p class="quiet-note" data-vault-trade-provenance="true">No symbol-attributed closed trade rows recorded in vault ledger yet.</p>';

  const tradeButtons = actions.slice(0, 8).map((a, idx) => (
    `<button type="button" class="button button-small ${idx === selectedIdx ? 'selected' : 'button-secondary'}" data-inspect-trade="${e(String(idx))}">${e(a.kind)} ${e(a.symbol || '')}</button>`
  )).join('');

  const railButtons = [
    ['BROKER_2FA_MANUAL', 'Broker 2FA (Manual)'],
    ['COINBASE_ACH', 'Coinbase ACH'],
    ['KRAKEN_ACH', 'Kraken ACH'],
  ].map(([rail, lbl]) => {
    const active = treasury.preferredRail === rail;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-treasury-rail="${e(rail)}" aria-pressed="${active}" ${!treasury.connected || busy ? 'disabled' : ''}>${e(lbl)}</button>`;
  }).join('');

  return `<section class="panel analytics-vault-panel" aria-label="Profit Sweep Bank Vault and Analytics">
    <div class="section-heading">
      <div><p class="eyebrow">PRINCIPAL HIGH-WATER MARK · THERMAL MARKET SIGNALS · OBSIDIAN ANALYTICS</p><h2>Equity vs Bank Vault &amp; Drawdown Analytics</h2></div>
      <span class="tag" data-vault-allocation-mode="true"><span class="state-rule" aria-hidden="true"></span>${e(allocationModeTitle)} · ${e(treasury.preferredRail)}</span>
    </div>
    <div class="analytics-canvas-grid">
      <div class="market-canvas-card obsidian-canvas-card">
        <div class="market-canvas-header"><strong>Trading Equity vs $300,000 Principal Goal &amp; Vault Band</strong><span class="numeric">Vault $${e(treasury.bankSweepReservedUsd)}</span></div>
        <canvas class="analytics-canvas obsidian-canvas" data-equity-vault-canvas="true" width="440" height="190" aria-label="Equity versus bank vault chart"></canvas>
      </div>
      <div class="market-canvas-card obsidian-canvas-card">
        <div class="market-canvas-header"><strong>Underwater Drawdown Curve (0.0% to -10.0% Soft / -20.0% Ceiling)</strong><span class="numeric">Soft -10.0% · Cap -20.0%</span></div>
        <canvas class="analytics-canvas obsidian-canvas" data-drawdown-canvas="true" width="440" height="190" aria-label="Underwater drawdown chart"></canvas>
      </div>
    </div>
    <div class="ai-overseer-grid">
      <div class="ai-control-block">
        <strong class="control-label">${e(allocationModeTitle)}</strong>
        <div class="principal-recovery-gauge" data-principal-recovery-gauge="true">
          <div class="gauge-label-row numeric"><span>Recovery-to-$300,000.00-Principal Progress</span><strong>${e(progressText)}%</strong></div>
          <progress class="principal-recovery-progress" value="${e(progressText)}" max="100" aria-label="Recovery progress toward $300,000.00 principal">${e(progressText)}%</progress>
          <svg class="principal-gauge-svg" viewBox="0 0 200 10" role="img" aria-label="Principal recovery bar">
            <rect class="gauge-track" x="0" y="0" width="200" height="10" rx="4"></rect>
            <rect class="gauge-fill ${isUnderwater ? 'is-recovery' : 'is-surplus'}" x="0" y="0" width="${e(String(svgBarWidth))}" height="10" rx="4"></rect>
          </svg>
          <p class="quiet-note numeric">${e(gaugeCaption)}</p>
        </div>
        <dl class="metadata compact">
          <div class="meta-row"><dt>Total realized profits (internal ledger)</dt><dd class="numeric">$${e(treasury.totalRealizedProfitUsd)}</dd></div>
          <div class="meta-row"><dt>${isUnderwater ? '100% Rebuilding Principal (Recovery Mode)' : 'Retained compounding (50%)'}</dt><dd class="numeric">$${e(treasury.retainedTradingUsd)}</dd></div>
          <div class="meta-row"><dt>${isUnderwater ? 'Bank vault sweeps paused ($0.00 until > $300,000.00)' : 'Internal vault reserve (50%)'}</dt><dd class="numeric">$${e(isUnderwater ? '0' : treasury.bankSweepReservedUsd)}</dd></div>
          <div class="meta-row"><dt>Confirmed settled payouts</dt><dd class="numeric">$${e(treasury.confirmedSettledDisbursedUsd ?? '0')}</dd></div>
          <div class="meta-row"><dt>Pending / unconfirmed transfers</dt><dd class="numeric">$${e(treasury.pendingUnconfirmedTransfersUsd ?? '0')}</dd></div>
        </dl>
        <p class="quiet-note provenance-inline" data-vault-realized-provenance="true">Realized P&amp;L Provenance: ${e(prov.compactSummary)}</p>
        ${vaultProvenanceRows}
        <div class="overseer-controls">
          <button type="button" class="button button-small ${treasury.autoSweepEnabled ? 'selected' : 'button-secondary'}" data-treasury-action="TOGGLE_AUTO_SWEEP" ${!treasury.connected || busy ? 'disabled' : ''}>${treasury.autoSweepEnabled ? '50% Surplus Auto-Sweep: ON' : '50% Surplus Auto-Sweep: OFF'}</button>
          ${railButtons}
        </div>
      </div>
      <div class="ai-quota-block">
        <strong class="control-label">Thermal Market Signal Heatmap (50ms Stream + 0.55 Valve Gate)</strong>
        ${thermalGridHtml}
        <strong class="control-label">Daily Realized P&amp;L Calendar</strong>
        <div class="cal-heatmap" aria-label="Daily PnL calendar heatmap">${calCells}</div>
        <table class="ai-ticket-table" aria-label="Market breakdown">
          <thead><tr><th>Market</th><th>Signals</th><th>Last Action</th></tr></thead>
          <tbody>${mktRows}</tbody>
        </table>
      </div>
    </div>
    <div class="ai-control-block">
      <strong class="control-label">Clickable Trade Rationale &amp; Lifecycle Inspector</strong>
      <div class="overseer-controls">${tradeButtons || '<span class="quiet-note">No autonomous decisions recorded yet in this session.</span>'}</div>
      ${inspected ? `<p class="panel-copy">${e(inspected.observedAt)} · <code>${e(inspected.kind)}</code> <strong>${e(inspected.symbol || 'PORTFOLIO')}</strong> · ${e(inspected.detail)}</p>` : ''}
    </div>
  </section>`;
}

function formatCompactUsdTick(val) {
  const rounded = Math.round(val);
  const neg = rounded < 0;
  const abs = Math.abs(rounded);
  if (abs >= 1000) {
    return `${neg ? '-' : ''}$${abs.toLocaleString('en-US')}`;
  }
  return `${neg ? '-' : ''}$${abs}`;
}

export function drawRaceLines(canvas, pt) {
  const ctx = canvas?.getContext?.('2d');
  if (!ctx) return;
  const w = Number(canvas.getAttribute('width')) || 860;
  const h = Number(canvas.getAttribute('height')) || 220;
  const left = 54;
  const top = 16;
  const plotW = w - left - 18;
  const plotH = h - top - 30;

  ctx.fillStyle = '#0d1117';
  ctx.fillRect(0, 0, w, h);
  ctx.fillStyle = '#11161f';
  ctx.fillRect(left, top, plotW, plotH);
  ctx.strokeStyle = 'rgba(148, 163, 184, 0.22)';
  ctx.lineWidth = 1;
  ctx.strokeRect(left, top, plotW, plotH);

  const colors = ['#10b981', '#38bdf8', '#a78bfa', '#f59e0b', '#fb7185'];
  const series = pt?.growthSeries ?? {};
  const keys = pt?.tiers?.map((t) => t.tierId) ?? [];
  const allVals = [0];
  for (const k of keys) {
    for (const row of series[k] ?? []) {
      const v = Number(row.growthPct);
      if (Number.isFinite(v)) allVals.push(v);
    }
  }
  const rawMin = Math.min(...allVals);
  const rawMax = Math.max(...allVals);
  const pad = Math.max(0.5, (rawMax - rawMin) * 0.18);
  const minPct = rawMin - pad;
  const maxPct = rawMax + pad;
  const span = Math.max(0.5, maxPct - minPct);
  const toY = (pct) => top + ((maxPct - pct) / span) * plotH;

  // 0.0% breakeven reference line
  const zeroY = toY(0);
  ctx.setLineDash?.([4, 4]);
  ctx.strokeStyle = 'rgba(148, 163, 184, 0.45)';
  ctx.beginPath();
  ctx.moveTo(left, zeroY);
  ctx.lineTo(left + plotW, zeroY);
  ctx.stroke();
  ctx.setLineDash?.([]);
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('0.00%', 8, zeroY + 4);
  ctx.fillText(`${maxPct >= 0 ? '+' : ''}${maxPct.toFixed(1)}%`, 8, top + 10);
  ctx.fillText(`${minPct >= 0 ? '+' : ''}${minPct.toFixed(1)}%`, 8, top + plotH - 2);

  keys.forEach((k, idx) => {
    const pts = series[k] ?? [];
    const color = colors[idx % colors.length];
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.2;
    ctx.beginPath();
    if (pts.length === 0) {
      ctx.moveTo(left, zeroY);
      ctx.lineTo(left + plotW, zeroY);
    } else if (pts.length === 1) {
      const y1 = toY(Number(pts[0].growthPct || 0));
      ctx.moveTo(left, y1);
      ctx.lineTo(left + plotW, y1);
    } else {
      pts.forEach((p, i) => {
        const x = left + (i / (pts.length - 1)) * plotW;
        const y = toY(Number(p.growthPct || 0));
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
    }
    ctx.stroke();
    ctx.fillStyle = color;
    ctx.fillText(k.replace('TIER_', ''), left + 4 + idx * 150, h - 8);
  });
}

export function drawEquityAndDd(root, state) {
  const trader = state?.aiTrader ?? {};
  const bs = trader.bankedSession ?? null;
  const treasury = state?.treasury ?? STATIC_TREASURY;
  const principalGoal = Number(trader.initialCapitalUsd ?? bs?.initialCapitalUsd ?? 300000) || 300000;
  const currentEqFallback = Number(trader.currentTotalEquityUsd ?? bs?.currentTotalEquityUsd ?? principalGoal) || principalGoal;
  const startEqFallback = Number(trader.dailyQuota?.startingEquityUsd ?? 0) || currentEqFallback;
  const vaultReserve = Math.max(0, Number(treasury.bankSweepReservedUsd ?? 0) || 0);

  const t1Series = state?.parallelTiers?.growthSeries?.TIER_1_CURRENT ?? [];
  let eqVals = t1Series
    .map((p) => Number(p.equityUsd))
    .filter((v) => Number.isFinite(v) && v > 0);
  if (eqVals.length === 0) {
    eqVals = startEqFallback !== currentEqFallback
      ? [startEqFallback, currentEqFallback]
      : [principalGoal, currentEqFallback];
  } else if (eqVals.length === 1) {
    eqVals = [startEqFallback !== eqVals[0] ? startEqFallback : principalGoal, eqVals[0]];
  }

  const eqCanvas = root.querySelector('canvas[data-equity-vault-canvas]');
  if (eqCanvas) {
    const ctx = eqCanvas.getContext?.('2d');
    if (ctx) {
      const w = Number(eqCanvas.getAttribute('width')) || 440;
      const h = Number(eqCanvas.getAttribute('height')) || 190;
      const left = 64;
      const top = 22;
      const plotW = w - left - 16;
      const plotH = h - top - 24;

      ctx.fillStyle = '#0d1117';
      ctx.fillRect(0, 0, w, h);
      ctx.fillStyle = '#11161f';
      ctx.fillRect(left, top, plotW, plotH);
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.22)';
      ctx.lineWidth = 1;
      ctx.strokeRect(left, top, plotW, plotH);

      const stackedVals = eqVals.map((v) => v + vaultReserve);
      const dataMin = Math.min(...eqVals, principalGoal);
      const dataMax = Math.max(...stackedVals, principalGoal);
      const rawSpan = Math.max(1000, dataMax - dataMin);
      const pad = rawSpan * 0.16;
      const minV = Math.max(1, dataMin - pad);
      const maxV = dataMax + pad;
      const span = Math.max(1, maxV - minV);
      const toX = (idx) => left + (idx / Math.max(1, eqVals.length - 1)) * plotW;
      const toY = (val) => top + ((maxV - val) / span) * plotH;

      // Gridlines & $ ticks (zoomed non-zero minV..maxV)
      for (const ratio of [0, 0.5, 1]) {
        const tickVal = maxV - ratio * span;
        const ty = top + ratio * plotH;
        ctx.strokeStyle = 'rgba(148, 163, 184, 0.14)';
        ctx.beginPath();
        ctx.moveTo(left, ty);
        ctx.lineTo(left + plotW, ty);
        ctx.stroke();
        ctx.fillStyle = '#94a3b8';
        ctx.fillText(formatCompactUsdTick(tickVal), 6, ty + 4);
      }

      // $300,000.00 Principal Goal dashed reference line
      const goalY = toY(principalGoal);
      ctx.setLineDash?.([5, 4]);
      ctx.strokeStyle = '#f59e0b';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(left, goalY);
      ctx.lineTo(left + plotW, goalY);
      ctx.stroke();
      ctx.setLineDash?.([]);
      ctx.fillStyle = '#fbbf24';
      ctx.fillText(`${formatCompactUsdTick(principalGoal)} Principal Goal`, left + 6, Math.max(top + 11, goalY - 5));

      // Stacked gold Vault Reserve band when vaultReserve > 0
      if (vaultReserve > 0) {
        ctx.fillStyle = 'rgba(245, 158, 11, 0.28)';
        ctx.beginPath();
        eqVals.forEach((v, idx) => {
          const x = toX(idx);
          const y = toY(v + vaultReserve);
          if (idx === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        for (let idx = eqVals.length - 1; idx >= 0; idx -= 1) {
          ctx.lineTo(toX(idx), toY(eqVals[idx]));
        }
        ctx.closePath?.();
        ctx.fill?.();

        ctx.strokeStyle = '#fbbf24';
        ctx.lineWidth = 1.8;
        ctx.beginPath();
        eqVals.forEach((v, idx) => {
          const x = toX(idx);
          const y = toY(v + vaultReserve);
          if (idx === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();
      }

      // Shaded emerald equity fill + glowing curve
      ctx.fillStyle = 'rgba(16, 185, 129, 0.20)';
      ctx.beginPath();
      ctx.moveTo(toX(0), top + plotH);
      eqVals.forEach((v, idx) => ctx.lineTo(toX(idx), toY(v)));
      ctx.lineTo(toX(eqVals.length - 1), top + plotH);
      ctx.closePath?.();
      ctx.fill?.();

      ctx.strokeStyle = '#10b981';
      ctx.lineWidth = 2.4;
      ctx.beginPath();
      eqVals.forEach((v, idx) => {
        const x = toX(idx);
        const y = toY(v);
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();

      const latestEq = eqVals[eqVals.length - 1];
      ctx.fillStyle = '#34d399';
      ctx.fillText(
        `Live ${formatCompactUsdTick(latestEq)}${vaultReserve > 0 ? ` + Vault ${formatCompactUsdTick(vaultReserve)}` : ''}`,
        left + 6,
        top + 13,
      );
    }
  }

  const ddCanvas = root.querySelector('canvas[data-drawdown-canvas]');
  if (ddCanvas) {
    const ctx = ddCanvas.getContext?.('2d');
    if (ctx) {
      const w = Number(ddCanvas.getAttribute('width')) || 440;
      const h = Number(ddCanvas.getAttribute('height')) || 190;
      const left = 52;
      const top = 20;
      const plotW = w - left - 16;
      const plotH = h - top - 24;

      ctx.fillStyle = '#0d1117';
      ctx.fillRect(0, 0, w, h);
      ctx.fillStyle = '#11161f';
      ctx.fillRect(left, top, plotW, plotH);
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.22)';
      ctx.lineWidth = 1;
      ctx.strokeRect(left, top, plotW, plotH);

      let ddVals = [];
      if (t1Series.length >= 2) {
        let runningPeak = Math.max(principalGoal, Number(t1Series[0].equityUsd) || principalGoal);
        ddVals = t1Series.map((pt) => {
          const explicitDd = Number(pt.drawdownPct);
          const eq = Number(pt.equityUsd) || runningPeak;
          if (eq > runningPeak) runningPeak = eq;
          if (Number.isFinite(explicitDd) && explicitDd > 0) return -Math.abs(explicitDd);
          return runningPeak > 0 ? Math.min(0, ((eq - runningPeak) / runningPeak) * 100) : 0;
        });
      } else {
        let peak = principalGoal;
        ddVals = eqVals.map((eq) => {
          if (eq > peak) peak = eq;
          return peak > 0 ? Math.min(0, ((eq - peak) / peak) * 100) : 0;
        });
      }
      const surplusPctNum = Number(trader.netSurplusPct ?? bs?.netSurplusPct ?? 0);
      if (ddVals.every((v) => v === 0) && Number.isFinite(surplusPctNum) && surplusPctNum < 0) {
        ddVals = [0, surplusPctNum];
      }
      if (ddVals.length < 2) ddVals = [0, ddVals[0] ?? 0];

      const minObservedDd = Math.min(...ddVals, -10);
      const minAxis = Math.min(-10.8, minObservedDd - 1.0);
      const toX = (idx) => left + (idx / Math.max(1, ddVals.length - 1)) * plotW;
      const toY = (ddPct) => top + ((0 - ddPct) / (0 - minAxis)) * plotH;

      for (const tick of [0, -2.5, -5.0, -7.5, -10.0]) {
        const ty = toY(tick);
        ctx.strokeStyle = tick === -10.0 ? '#f43f5e' : 'rgba(148, 163, 184, 0.14)';
        if (tick === -10.0) ctx.setLineDash?.([4, 3]);
        ctx.beginPath();
        ctx.moveTo(left, ty);
        ctx.lineTo(left + plotW, ty);
        ctx.stroke();
        if (tick === -10.0) ctx.setLineDash?.([]);
        ctx.fillStyle = tick === -10.0 ? '#fb7185' : '#94a3b8';
        ctx.fillText(`${tick.toFixed(1)}%`, 6, ty + 4);
      }

      // Shaded crimson drawdown area from 0.0% baseline
      const zeroY = toY(0);
      ctx.fillStyle = 'rgba(244, 63, 94, 0.26)';
      ctx.beginPath();
      ctx.moveTo(toX(0), zeroY);
      ddVals.forEach((dd, idx) => ctx.lineTo(toX(idx), toY(dd)));
      ctx.lineTo(toX(ddVals.length - 1), zeroY);
      ctx.closePath?.();
      ctx.fill?.();

      ctx.strokeStyle = '#fb7185';
      ctx.lineWidth = 2.2;
      ctx.beginPath();
      ddVals.forEach((dd, idx) => {
        const x = toX(idx);
        const y = toY(dd);
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();

      const curDd = ddVals[ddVals.length - 1];
      const lastX = toX(ddVals.length - 1);
      const lastY = toY(curDd);
      ctx.fillStyle = '#fda4af';
      ctx.beginPath();
      ctx.arc?.(lastX, lastY, 3.5, 0, Math.PI * 2);
      ctx.fill?.();
      ctx.fillText(`Current DD: ${curDd.toFixed(2)}% (Ceiling -20.0%)`, left + 6, top + 13);
      ctx.fillStyle = '#fb7185';
      ctx.fillText('-10.0% Soft Downshift Brake', left + 6, toY(-10.0) - 5);
    }
  }
}

export function mountAnalyticsCanvases(root, state) {
  if (!root) return;
  const raceCanvas = root.querySelector('canvas[data-tiers-race-canvas]');
  if (raceCanvas) drawRaceLines(raceCanvas, state?.parallelTiers ?? STATIC_PARALLEL_TIERS);
  drawEquityAndDd(root, state);
}
