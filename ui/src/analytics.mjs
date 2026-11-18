/**
 * CAS Forex Profit Expansion Analytics, 5-Tier Parallel Race Board,
 * 50%/50% Profit-Sweep Bank Vault & Prominent AI Switcher / 2-Speed Thinking Depth Bar.
 * Strict CSP compliant: zero inline style attributes, zero eval, safe HTML escaping.
 */
import { computeMarketSessions } from './ai-overseer.mjs';
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
  pending2faConfirmationUsd: '0',
  pendingDisbursementUsd: '0',
  recentSweeps: Object.freeze([]),
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

export function normalizeTreasury(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Treasury payload must be a JSON object.');
  if (doc.schema !== 'cas-forex.profit-vault/1') throw new Error('Unexpected treasury schema.');
  const sweeps = Array.isArray(doc.recent_sweeps) ? doc.recent_sweeps.slice(0, 20).map((s) => Object.freeze({
    tradeId: str(s.trade_id, ''),
    symbol: str(s.symbol, ''),
    brokerId: str(s.broker_id, ''),
    realizedNetUsd: numStr(s.realized_net_usd, '0'),
    retainedTradingUsd: numStr(s.retained_trading_usd, '0'),
    bankSweepUsd: numStr(s.bank_sweep_usd, '0'),
    occurredAt: str(s.occurred_at, ''),
  })) : [];
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
    pending2faConfirmationUsd: numStr(doc.pending_2fa_confirmation_usd, '0'),
    pendingDisbursementUsd: numStr(doc.pending_disbursement_usd, '0'),
    recentSweeps: Object.freeze(sweeps),
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

export function renderEquityAndAnalyticsSection(state) {
  const treasury = state?.treasury ?? STATIC_TREASURY;
  const trader = state?.aiTrader ?? {};
  const busy = Boolean(state?.aiActionBusy);
  const actions = Array.isArray(trader.recentActions) ? trader.recentActions : [];
  const selectedIdx = Number.isInteger(state?.inspectedTradeIdx) ? state.inspectedTradeIdx : 0;
  const inspected = actions[selectedIdx] ?? null;

  // Market breakdown from recent actions & open positions
  const symStats = new Map();
  for (const a of actions) {
    if (!a.symbol) continue;
    const prev = symStats.get(a.symbol) ?? { count: 0, lastKind: a.kind };
    symStats.set(a.symbol, { count: prev.count + 1, lastKind: a.kind });
  }
  const mktRows = symStats.size
    ? [...symStats.entries()].map(([sym, info]) => `<tr><td><strong>${e(sym)}</strong></td><td class="numeric">${e(String(info.count))}</td><td>${e(info.lastKind)}</td></tr>`).join('')
    : '<tr><td colspan="3" class="quiet-note">Awaiting closed or active multi-market executions.</td></tr>';

  // Daily calendar cells from recent sweeps
  const dayMap = new Map();
  for (const s of treasury.recentSweeps) {
    const day = (s.occurredAt || '').slice(0, 10) || 'Today';
    dayMap.set(day, (dayMap.get(day) ?? 0) + Number(s.realizedNetUsd || 0));
  }
  const calCells = dayMap.size
    ? [...dayMap.entries()].slice(-14).map(([day, net]) => {
        const cls = net > 0 ? 'cal-cell cal-pos' : (net < 0 ? 'cal-cell cal-neg' : 'cal-cell cal-flat');
        return `<div class="${cls}"><small>${e(day)}</small><strong class="numeric">${net >= 0 ? '+' : ''}${e(net.toFixed(2))}</strong></div>`;
      }).join('')
    : '<div class="cal-cell cal-flat"><small>Today</small><strong>$0.00</strong></div>';

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
      <div><p class="eyebrow">COMPOUNDING + TREASURY · 50% TRADING / 50% OWNER BANK ACH</p><h2>Equity vs Bank Vault &amp; Drawdown Analytics</h2></div>
      <span class="tag"><span class="state-rule" aria-hidden="true"></span>Sweep ${e(treasury.sweepRatioPct)}% · ${e(treasury.preferredRail)}</span>
    </div>
    <div class="analytics-canvas-grid">
      <div class="market-canvas-card">
        <div class="market-canvas-header"><strong>Stacked Trading Equity vs 50% Bank Vault Reserve</strong><span class="numeric">Vault $${e(treasury.bankSweepReservedUsd)}</span></div>
        <canvas class="analytics-canvas" data-equity-vault-canvas="true" width="440" height="190" aria-label="Equity versus bank vault chart"></canvas>
      </div>
      <div class="market-canvas-card">
        <div class="market-canvas-header"><strong>Underwater Drawdown Curve (0% to -10.00% Hard Floor)</strong><span class="numeric">Floor -10.00%</span></div>
        <canvas class="analytics-canvas" data-drawdown-canvas="true" width="440" height="190" aria-label="Underwater drawdown chart"></canvas>
      </div>
    </div>
    <div class="ai-overseer-grid">
      <div class="ai-control-block">
        <strong class="control-label">50%/50% Profit-Sweep Bank Vault Ledger</strong>
        <dl class="metadata compact">
          <div class="meta-row"><dt>Total realized profits</dt><dd class="numeric">$${e(treasury.totalRealizedProfitUsd)}</dd></div>
          <div class="meta-row"><dt>Retained compounding (50%)</dt><dd class="numeric">$${e(treasury.retainedTradingUsd)}</dd></div>
          <div class="meta-row"><dt>Bank vault reserved (50%)</dt><dd class="numeric">$${e(treasury.bankSweepReservedUsd)}</dd></div>
          <div class="meta-row"><dt>Pending disbursement</dt><dd class="numeric">$${e(treasury.pendingDisbursementUsd)}</dd></div>
          <div class="meta-row"><dt>Disbursed to linked bank</dt><dd class="numeric">$${e(treasury.disbursedToBankUsd)}</dd></div>
        </dl>
        <div class="overseer-controls">
          <button type="button" class="button button-small ${treasury.autoSweepEnabled ? 'selected' : 'button-secondary'}" data-treasury-action="TOGGLE_AUTO_SWEEP" ${!treasury.connected || busy ? 'disabled' : ''}>${treasury.autoSweepEnabled ? '50% Auto-Sweep: ON' : '50% Auto-Sweep: OFF'}</button>
          ${railButtons}
        </div>
      </div>
      <div class="ai-quota-block">
        <strong class="control-label">Market Activity &amp; Daily P&amp;L Calendar Heatmap</strong>
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

function drawRaceLines(canvas, pt) {
  const ctx = canvas.getContext?.('2d');
  if (!ctx) return;
  const w = Number(canvas.getAttribute('width')) || 860;
  const h = Number(canvas.getAttribute('height')) || 220;
  ctx.fillStyle = '#faf9f5';
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = 'rgba(20,24,28,0.12)';
  ctx.strokeRect(48, 14, w - 64, h - 42);
  const colors = ['#0d7a52', '#1d5bbf', '#7c3aed', '#b85c00', '#be123c'];
  const series = pt?.growthSeries ?? {};
  const keys = pt?.tiers?.map((t) => t.tierId) ?? [];
  let minPct = -1;
  let maxPct = 5;
  for (const k of keys) {
    for (const row of series[k] ?? []) {
      const v = Number(row.growthPct);
      if (Number.isFinite(v)) { minPct = Math.min(minPct, v); maxPct = Math.max(maxPct, v); }
    }
  }
  const span = Math.max(1, maxPct - minPct);
  keys.forEach((k, idx) => {
    const pts = series[k] ?? [];
    ctx.strokeStyle = colors[idx % colors.length];
    ctx.lineWidth = 2;
    ctx.beginPath();
    if (pts.length === 0) {
      const y0 = 14 + ((maxPct - 0) / span) * (h - 42);
      ctx.moveTo(48, y0);
      ctx.lineTo(w - 16, y0);
    } else {
      pts.forEach((p, i) => {
        const x = 48 + (i / Math.max(1, pts.length - 1)) * (w - 64);
        const y = 14 + ((maxPct - Number(p.growthPct || 0)) / span) * (h - 42);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
    }
    ctx.stroke();
    ctx.fillStyle = colors[idx % colors.length];
    ctx.fillText(k.replace('TIER_', ''), 54 + idx * 145, h - 10);
  });
}

function drawEquityAndDd(root, state) {
  const eqCanvas = root.querySelector('canvas[data-equity-vault-canvas]');
  if (eqCanvas) {
    const ctx = eqCanvas.getContext?.('2d');
    if (ctx) {
      const w = Number(eqCanvas.getAttribute('width')) || 440;
      const h = Number(eqCanvas.getAttribute('height')) || 190;
      ctx.fillStyle = '#faf9f5';
      ctx.fillRect(0, 0, w, h);
      const t1 = (state?.parallelTiers?.growthSeries?.TIER_1_CURRENT ?? []);
      const pts = t1.length ? t1 : [{ equityUsd: state?.treasury?.retainedTradingUsd || '0' }];
      const vals = pts.map((p) => Number(p.equityUsd || 0));
      const minV = Math.min(...vals, 0);
      const maxV = Math.max(...vals, minV + 100);
      ctx.strokeStyle = '#0d7a52';
      ctx.lineWidth = 2;
      ctx.beginPath();
      vals.forEach((v, i) => {
        const x = 24 + (i / Math.max(1, vals.length - 1)) * (w - 48);
        const y = 16 + ((maxV - v) / Math.max(1, maxV - minV)) * (h - 36);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
  }
  const ddCanvas = root.querySelector('canvas[data-drawdown-canvas]');
  if (ddCanvas) {
    const ctx = ddCanvas.getContext?.('2d');
    if (ctx) {
      const w = Number(ddCanvas.getAttribute('width')) || 440;
      const h = Number(ddCanvas.getAttribute('height')) || 190;
      ctx.fillStyle = '#faf9f5';
      ctx.fillRect(0, 0, w, h);
      const floorY = h - 22;
      ctx.strokeStyle = '#be123c';
      ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.moveTo(20, floorY);
      ctx.lineTo(w - 20, floorY);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = '#be123c';
      ctx.fillText('-10.00% Max Drawdown Brake', 24, floorY - 6);
    }
  }
}

export function mountAnalyticsCanvases(root, state) {
  if (!root) return;
  const raceCanvas = root.querySelector('canvas[data-tiers-race-canvas]');
  if (raceCanvas) drawRaceLines(raceCanvas, state?.parallelTiers ?? STATIC_PARALLEL_TIERS);
  drawEquityAndDd(root, state);
}
