// Strict-CSP, 60fps Option B $5,000.00 US-Regulated CME Micro Futures Paper Demo Panel.
// Zero inline style attributes, zero eval/Function, zero unsafe HTML string injection,
// zero float money arithmetic, full XSS escaping, and 0.0px-jump in-place patching.

export const OPTION_B_DEMO_SCHEMA = 'cas-forex.option-b-demo/1';

export const OPTION_B_CONTRACT_ROOTS = Object.freeze(['MNQ', 'MYM', 'MES', 'MGC']);

const DECIMAL_RE = /^[+-]?[0-9]+(?:\.[0-9]+)?$/;

const PCT_BUCKET_STEPS = Object.freeze([
  0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50,
  55, 60, 65, 70, 75, 80, 85, 90, 95, 100,
]);

const PCT_BUCKET_CLASSES = Object.freeze(
  PCT_BUCKET_STEPS.map((step) => `ob-pct-${step}`)
);

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

export function normalizeDecimalString(value, fallback = '0.00') {
  const raw = String(value ?? '').trim();
  if (!DECIMAL_RE.test(raw)) return fallback;
  return raw;
}

export function formatSignedUsd(value) {
  const clean = normalizeDecimalString(value, '0.00');
  if (clean.startsWith('-')) return `-$${clean.slice(1)}`;
  if (clean === '0' || clean === '0.00' || clean === '+0.00') return '$0.00';
  return `+$${clean.replace(/^\+/, '')}`;
}

export function formatUsd(value) {
  const clean = normalizeDecimalString(value, '0.00');
  if (clean.startsWith('-')) return `-$${clean.slice(1)}`;
  return `$${clean.replace(/^\+/, '')}`;
}

export function pctBucketClass(pctString) {
  const clean = normalizeDecimalString(pctString, '0.00');
  const num = Number(clean);
  if (!Number.isFinite(num) || num <= 0) return 'ob-pct-0';
  if (num >= 100) return 'ob-pct-100';
  const rounded = Math.round(num / 5) * 5;
  const clamped = Math.max(0, Math.min(100, rounded));
  return `ob-pct-${clamped}`;
}

export const STATIC_OPTION_B_DEMO = Object.freeze({
  schema: OPTION_B_DEMO_SCHEMA,
  connected: false,
  accountId: 'OPTION-B-PAPER-5K',
  mode: 'DEMO',
  status: 'STANDBY_READY',
  paperDemoOnly: true,
  realMoneyAtRiskUsd: '0.00',
  tradovateSignupRequired: false,
  regulatedJurisdiction: 'US_CFTC_NFA_CME',
  startingEquityUsd: '5000.00',
  balanceUsd: '5000.00',
  equityUsd: '5000.00',
  unrealizedPnlUsd: '0.00',
  netPnlUsd: '0.00',
  netPnlPct: '0.00',
  peakEquityUsd: '5000.00',
  drawdownPct: '0.00',
  drawdownLocked: false,
  maxStopLossRiskPct: '1.00',
  maxDrawdownPct: '10.00',
  vault50PctReservedUsd: '0.00',
  retainedCompoundingUsd: '0.00',
  houseMoneyTargetUsd: '10000.00',
  houseMoneyProgressPct: '0.00',
  houseMoneyReady: false,
  houseMoneyReachedAt: null,
  closedTrades: 0,
  winCount: 0,
  lossCount: 0,
  winRatePct: '0.00',
  totalCommissionsUsd: '0.00',
  openPositions: Object.freeze([]),
  recentClosedTrades: Object.freeze([]),
  recentEvents: Object.freeze([]),
  supportedContracts: Object.freeze([
    Object.freeze({ rootSymbol: 'MNQ', casSymbol: 'NAS100', displayName: 'Micro E-mini Nasdaq-100', exchange: 'CME', contractCode: 'MNQ', pointValueUsd: '2', tickSize: '0.25', tickValueUsd: '0.50', openContracts: 0, bid: null, ask: null, mid: null, quoteObservedAt: null }),
    Object.freeze({ rootSymbol: 'MYM', casSymbol: 'US30', displayName: 'Micro E-mini Dow', exchange: 'CBOT', contractCode: 'MYM', pointValueUsd: '0.50', tickSize: '1', tickValueUsd: '0.50', openContracts: 0, bid: null, ask: null, mid: null, quoteObservedAt: null }),
    Object.freeze({ rootSymbol: 'MES', casSymbol: 'SPX500', displayName: 'Micro E-mini S&P 500', exchange: 'CME', contractCode: 'MES', pointValueUsd: '5', tickSize: '0.25', tickValueUsd: '1.25', openContracts: 0, bid: null, ask: null, mid: null, quoteObservedAt: null }),
    Object.freeze({ rootSymbol: 'MGC', casSymbol: 'XAUUSD', displayName: 'Micro Gold', exchange: 'COMEX', contractCode: 'MGC', pointValueUsd: '10', tickSize: '0.10', tickValueUsd: '1.00', openContracts: 0, bid: null, ask: null, mid: null, quoteObservedAt: null }),
  ]),
  auditChainValid: true,
  observedAt: null,
});

export function normalizeOptionBDemo(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return STATIC_OPTION_B_DEMO;
  }
  if (typeof raw.equityUsd === 'string' && raw.equity_usd === undefined && Array.isArray(raw.supportedContracts)) {
    return raw;
  }
  const contractsRaw = Array.isArray(raw.supported_contracts) ? raw.supported_contracts : [];
  const contracts = contractsRaw.length > 0
    ? contractsRaw.map((c) => Object.freeze({
        rootSymbol: String(c?.root_symbol ?? '').slice(0, 12),
        casSymbol: String(c?.cas_symbol ?? '').slice(0, 12),
        displayName: String(c?.display_name ?? '').slice(0, 80),
        exchange: String(c?.exchange ?? 'CME').slice(0, 16),
        contractCode: String(c?.contract_code ?? '').slice(0, 16),
        pointValueUsd: normalizeDecimalString(c?.point_value_usd, '0.00'),
        tickSize: normalizeDecimalString(c?.tick_size, '0.01'),
        tickValueUsd: normalizeDecimalString(c?.tick_value_usd, '0.00'),
        openContracts: Number.isInteger(c?.open_contracts) && c.open_contracts >= 0 ? c.open_contracts : 0,
        bid: c?.bid == null ? null : normalizeDecimalString(c.bid, '0.00'),
        ask: c?.ask == null ? null : normalizeDecimalString(c.ask, '0.00'),
        mid: c?.mid == null ? null : normalizeDecimalString(c.mid, '0.00'),
        quoteObservedAt: typeof c?.quote_observed_at === 'string' ? c.quote_observed_at : null,
      }))
    : STATIC_OPTION_B_DEMO.supportedContracts;

  const openPositions = Array.isArray(raw.open_positions)
    ? raw.open_positions.map((p) => Object.freeze({
        positionId: String(p?.position_id ?? '').slice(0, 48),
        casSymbol: String(p?.cas_symbol ?? '').slice(0, 16),
        rootSymbol: String(p?.root_symbol ?? '').slice(0, 16),
        contractCode: String(p?.contract_code ?? '').slice(0, 16),
        side: p?.side === 'SELL' ? 'SELL' : 'BUY',
        contracts: Number.isInteger(p?.contracts) && p.contracts > 0 ? p.contracts : 1,
        entryPrice: normalizeDecimalString(p?.entry_price, '0.00'),
        markPrice: normalizeDecimalString(p?.mark_price, '0.00'),
        stopLossPrice: p?.stop_loss_price == null ? null : normalizeDecimalString(p.stop_loss_price, '0.00'),
        takeProfitPrice: p?.take_profit_price == null ? null : normalizeDecimalString(p.take_profit_price, '0.00'),
        unrealizedPnlUsd: normalizeDecimalString(p?.unrealized_pnl_usd, '0.00'),
        openedAt: String(p?.opened_at ?? ''),
      }))
    : [];

  const recentClosedTrades = Array.isArray(raw.recent_closed_trades)
    ? raw.recent_closed_trades.map((t) => Object.freeze({
        tradeId: String(t?.trade_id ?? '').slice(0, 64),
        casSymbol: String(t?.cas_symbol ?? '').slice(0, 16),
        rootSymbol: String(t?.root_symbol ?? '').slice(0, 16),
        contractCode: String(t?.contract_code ?? '').slice(0, 16),
        side: String(t?.side ?? 'CLOSE').slice(0, 16),
        contracts: Number.isInteger(t?.contracts) && t.contracts >= 0 ? t.contracts : 0,
        exitPrice: normalizeDecimalString(t?.exit_price, '0.00'),
        realizedPnlUsd: normalizeDecimalString(t?.realized_pnl_usd, '0.00'),
        commissionUsd: normalizeDecimalString(t?.commission_usd, '0.00'),
        netPnlUsd: normalizeDecimalString(t?.net_pnl_usd, '0.00'),
        status: String(t?.status ?? '').slice(0, 32),
        reason: String(t?.reason ?? '').slice(0, 64),
        closedAt: String(t?.closed_at ?? ''),
      }))
    : [];

  const recentEvents = Array.isArray(raw.recent_events)
    ? raw.recent_events.slice(0, 10).map((ev) => Object.freeze({
        eventType: String(ev?.event_type ?? '').slice(0, 48),
        casSymbol: String(ev?.cas_symbol ?? '').slice(0, 16),
        rootSymbol: String(ev?.root_symbol ?? '').slice(0, 16),
        detail: String(ev?.detail ?? '').slice(0, 240),
        occurredAt: String(ev?.occurred_at ?? ''),
      }))
    : [];

  const statusVal = ['PAPER_DEMO_ACTIVE', 'DRAWDOWN_LOCKED', 'STANDBY_READY'].includes(raw.status)
    ? raw.status
    : 'PAPER_DEMO_ACTIVE';

  return Object.freeze({
    schema: OPTION_B_DEMO_SCHEMA,
    connected: true,
    accountId: String(raw.account_id ?? 'OPTION-B-PAPER-5K').slice(0, 64),
    mode: 'DEMO',
    status: statusVal,
    paperDemoOnly: true,
    realMoneyAtRiskUsd: '0.00',
    tradovateSignupRequired: false,
    regulatedJurisdiction: 'US_CFTC_NFA_CME',
    startingEquityUsd: normalizeDecimalString(raw.starting_equity_usd, '5000.00'),
    balanceUsd: normalizeDecimalString(raw.balance_usd, '5000.00'),
    equityUsd: normalizeDecimalString(raw.equity_usd, '5000.00'),
    unrealizedPnlUsd: normalizeDecimalString(raw.unrealized_pnl_usd, '0.00'),
    netPnlUsd: normalizeDecimalString(raw.net_pnl_usd, '0.00'),
    netPnlPct: normalizeDecimalString(raw.net_pnl_pct, '0.00'),
    peakEquityUsd: normalizeDecimalString(raw.peak_equity_usd, '5000.00'),
    drawdownPct: normalizeDecimalString(raw.drawdown_pct, '0.00'),
    drawdownLocked: raw.drawdown_locked === true,
    maxStopLossRiskPct: normalizeDecimalString(raw.max_stop_loss_risk_pct, '1.00'),
    maxDrawdownPct: normalizeDecimalString(raw.max_drawdown_pct, '10.00'),
    vault50PctReservedUsd: normalizeDecimalString(raw.vault_50pct_reserved_usd, '0.00'),
    retainedCompoundingUsd: normalizeDecimalString(raw.retained_compounding_usd, '0.00'),
    houseMoneyTargetUsd: normalizeDecimalString(raw.house_money_target_usd, '10000.00'),
    houseMoneyProgressPct: normalizeDecimalString(raw.house_money_progress_pct, '0.00'),
    houseMoneyReady: raw.house_money_ready === true,
    houseMoneyReachedAt: typeof raw.house_money_reached_at === 'string' ? raw.house_money_reached_at : null,
    closedTrades: Number.isInteger(raw.closed_trades) && raw.closed_trades >= 0 ? raw.closed_trades : 0,
    winCount: Number.isInteger(raw.win_count) && raw.win_count >= 0 ? raw.win_count : 0,
    lossCount: Number.isInteger(raw.loss_count) && raw.loss_count >= 0 ? raw.loss_count : 0,
    winRatePct: normalizeDecimalString(raw.win_rate_pct, '0.00'),
    totalCommissionsUsd: normalizeDecimalString(raw.total_commissions_usd, '0.00'),
    openPositions: Object.freeze(openPositions),
    recentClosedTrades: Object.freeze(recentClosedTrades),
    recentEvents: Object.freeze(recentEvents),
    supportedContracts: Object.freeze(contracts),
    auditChainValid: raw.audit_chain_valid === true,
    observedAt: typeof raw.observed_at === 'string' ? raw.observed_at : null,
  });
}

function pnlToneClass(netPnlUsd) {
  const clean = normalizeDecimalString(netPnlUsd, '0.00');
  if (clean.startsWith('-')) return 'is-negative';
  if (clean === '0' || clean === '0.00' || clean === '+0.00') return 'is-flat';
  return 'is-positive';
}

export function renderOptionBDemoPanel(demo) {
  const d = demo && typeof demo === 'object' ? demo : STATIC_OPTION_B_DEMO;
  const e = escapeHtml;
  const bucket = pctBucketClass(d.houseMoneyProgressPct);
  const pnlTone = pnlToneClass(d.netPnlUsd);
  const statusBadge = d.drawdownLocked
    ? 'DRAWDOWN BRAKE LOCKED (10.00%)'
    : d.connected
      ? 'PAPER DEMO LIVE · 0 TRADOVATE SIGNUP REQUIRED'
      : 'PAPER DEMO READY · STANDBY';

  const contractCards = d.supportedContracts.map((c) => {
    const quoteText = c.mid ? `${formatUsd(c.mid).slice(1)}` : 'Waiting for live tick';
    const openBadge = c.openContracts > 0 ? `${c.openContracts} OPEN` : '0 OPEN';
    return `<div class="ob-contract-pill" data-ob-contract="${e(c.rootSymbol)}">
      <div class="ob-contract-head">
        <strong>${e(c.contractCode)}</strong>
        <span class="ob-contract-map">${e(c.casSymbol)} · ${e(c.exchange)}</span>
      </div>
      <div class="ob-contract-meta numeric">
        <span data-ob-contract-mid="${e(c.rootSymbol)}">${e(quoteText)}</span>
        <span class="ob-open-count ${c.openContracts > 0 ? 'has-open' : ''}" data-ob-contract-open="${e(c.rootSymbol)}">${e(openBadge)}</span>
      </div>
      <div class="ob-contract-sub">$${e(c.pointValueUsd)}/pt · Tick $${e(c.tickValueUsd)}</div>
    </div>`;
  }).join('');

  const openPosSummary = d.openPositions.length > 0
    ? d.openPositions.map((p) => (
        `${p.side} ${p.contracts} ${p.contractCode} @ ${p.entryPrice} (SL ${p.stopLossPrice ?? '—'} / TP ${p.takeProfitPrice ?? '—'} · ${formatSignedUsd(p.unrealizedPnlUsd)})`
      )).join(' · ')
    : '0 open micro-futures contracts right now (waiting for valve-cleared signal).';

  const closedSummary = d.recentClosedTrades.length > 0
    ? d.recentClosedTrades.slice(0, 3).map((t) => (
        `${t.contractCode} x${t.contracts} ${formatSignedUsd(t.netPnlUsd)} (${t.status})`
      )).join(' · ')
    : 'No closed paper micro-futures trades yet.';

  return `<section class="panel ob-demo-panel" id="option-b-demo-section" data-option-b-demo="true" aria-label="Option B $5,000 US Micro Futures Paper Demo">
    <div class="ob-header-row">
      <div>
        <p class="eyebrow">OPTION B · US-REGULATED CME MICRO FUTURES PAPER DEMO</p>
        <h2>$5,000.00 Micro Futures Side-by-Side Proof (MNQ · MYM · MES · MGC)</h2>
      </div>
      <div class="ob-badge-strip">
        <span class="ob-badge ob-badge-safe" data-ob-real-money="true">$0.00 REAL MONEY AT RISK</span>
        <span class="ob-badge ${d.drawdownLocked ? 'ob-badge-danger' : 'ob-badge-active'}" data-ob-status-badge="true">${e(statusBadge)}</span>
      </div>
    </div>

    <div class="ob-kpi-grid">
      <div class="ob-kpi-card">
        <span class="ob-kpi-label">Paper Equity (Start ${e(formatUsd(d.startingEquityUsd))})</span>
        <strong class="ob-kpi-value numeric" data-ob-equity="true">${e(formatUsd(d.equityUsd))}</strong>
        <span class="ob-kpi-sub numeric" data-ob-dd="true">Peak ${e(formatUsd(d.peakEquityUsd))} · Drawdown ${e(d.drawdownPct)}% / ${e(d.maxDrawdownPct)}% cap</span>
      </div>
      <div class="ob-kpi-card">
        <span class="ob-kpi-label">Net Profit / Loss</span>
        <strong class="ob-kpi-value numeric ${pnlTone}" data-ob-net-pnl="true">${e(formatSignedUsd(d.netPnlUsd))} (${e(d.netPnlPct)}%)</strong>
        <span class="ob-kpi-sub numeric" data-ob-unrealized="true">Open P/L ${e(formatSignedUsd(d.unrealizedPnlUsd))} · Fees ${e(formatUsd(d.totalCommissionsUsd))}</span>
      </div>
      <div class="ob-kpi-card">
        <span class="ob-kpi-label">Win / Loss Record</span>
        <strong class="ob-kpi-value numeric" data-ob-record="true">${e(String(d.winCount))}W / ${e(String(d.lossCount))}L (${e(d.winRatePct)}%)</strong>
        <span class="ob-kpi-sub numeric" data-ob-closed-count="true">${e(String(d.closedTrades))} closed · Max stop risk &lt;= ${e(d.maxStopLossRiskPct)}%</span>
      </div>
      <div class="ob-kpi-card">
        <span class="ob-kpi-label">50% Profit Vault &amp; House-Money Goal</span>
        <strong class="ob-kpi-value numeric" data-ob-vault="true">${e(formatUsd(d.vault50PctReservedUsd))} Reserved</strong>
        <span class="ob-kpi-sub numeric" data-ob-house-money="true">${d.houseMoneyReady ? 'HOUSE-MONEY READY ($10,000.00+ REACHED!)' : `${e(d.houseMoneyProgressPct)}% toward ${e(formatUsd(d.houseMoneyTargetUsd))} double`}</span>
      </div>
    </div>

    <div class="ob-progress-wrap" aria-label="Progress to $10,000.00 House-Money milestone">
      <div class="ob-progress-track">
        <div class="ob-progress-fill ${bucket}" data-ob-progress-fill="true"></div>
      </div>
    </div>

    <div class="ob-contract-grid" role="list" aria-label="CME Micro Futures live contracts">${contractCards}</div>

    <div class="ob-footer-strip">
      <p class="ob-footer-line"><strong>Open Contracts:</strong> <span data-ob-open-summary="true">${e(openPosSummary)}</span></p>
      <p class="ob-footer-line"><strong>Recent Closed:</strong> <span data-ob-closed-summary="true">${e(closedSummary)}</span></p>
      <p class="ob-footer-note">Protected by 161-rule safety valve (0.55 cutoff), &lt;= 1.00% ($50.00) stop risk, and &lt;= 10.00% (-$500.00) drawdown brake. Real US bank vault transfer rules when live: $0.00 ACH (1-3 business days) or $30.00 domestic wire (same-day cutoff 10:00 AM PT).</p>
    </div>
  </section>`;
}

export function patchOptionBDemoPanelInPlace(rootEl, demo) {
  if (!rootEl) return false;
  const panel = rootEl.matches?.('[data-option-b-demo="true"]')
    ? rootEl
    : rootEl.querySelector?.('[data-option-b-demo="true"]');
  if (!panel) return false;
  const d = demo && typeof demo === 'object' ? demo : STATIC_OPTION_B_DEMO;

  const setText = (sel, txt) => {
    const node = panel.querySelector(sel);
    if (node) node.textContent = txt;
  };

  const statusBadge = panel.querySelector('[data-ob-status-badge="true"]');
  if (statusBadge) {
    statusBadge.textContent = d.drawdownLocked
      ? 'DRAWDOWN BRAKE LOCKED (10.00%)'
      : d.connected
        ? 'PAPER DEMO LIVE · 0 TRADOVATE SIGNUP REQUIRED'
        : 'PAPER DEMO READY · STANDBY';
    statusBadge.classList.toggle('ob-badge-danger', d.drawdownLocked);
    statusBadge.classList.toggle('ob-badge-active', !d.drawdownLocked);
  }

  setText('[data-ob-equity="true"]', formatUsd(d.equityUsd));
  setText('[data-ob-dd="true"]', `Peak ${formatUsd(d.peakEquityUsd)} · Drawdown ${d.drawdownPct}% / ${d.maxDrawdownPct}% cap`);

  const netEl = panel.querySelector('[data-ob-net-pnl="true"]');
  if (netEl) {
    netEl.textContent = `${formatSignedUsd(d.netPnlUsd)} (${d.netPnlPct}%)`;
    netEl.classList.remove('is-positive', 'is-negative', 'is-flat');
    netEl.classList.add(pnlToneClass(d.netPnlUsd));
  }
  setText('[data-ob-unrealized="true"]', `Open P/L ${formatSignedUsd(d.unrealizedPnlUsd)} · Fees ${formatUsd(d.totalCommissionsUsd)}`);
  setText('[data-ob-record="true"]', `${d.winCount}W / ${d.lossCount}L (${d.winRatePct}%)`);
  setText('[data-ob-closed-count="true"]', `${d.closedTrades} closed · Max stop risk <= ${d.maxStopLossRiskPct}%`);
  setText('[data-ob-vault="true"]', `${formatUsd(d.vault50PctReservedUsd)} Reserved`);
  setText(
    '[data-ob-house-money="true"]',
    d.houseMoneyReady
      ? 'HOUSE-MONEY READY ($10,000.00+ REACHED!)'
      : `${d.houseMoneyProgressPct}% toward ${formatUsd(d.houseMoneyTargetUsd)} double`,
  );

  const fillEl = panel.querySelector('[data-ob-progress-fill="true"]');
  if (fillEl) {
    for (const cls of PCT_BUCKET_CLASSES) fillEl.classList.remove(cls);
    fillEl.classList.add(pctBucketClass(d.houseMoneyProgressPct));
  }

  for (const c of d.supportedContracts) {
    const midNode = panel.querySelector(`[data-ob-contract-mid="${c.rootSymbol}"]`);
    if (midNode) midNode.textContent = c.mid ? formatUsd(c.mid).slice(1) : 'Waiting for live tick';
    const openNode = panel.querySelector(`[data-ob-contract-open="${c.rootSymbol}"]`);
    if (openNode) {
      openNode.textContent = c.openContracts > 0 ? `${c.openContracts} OPEN` : '0 OPEN';
      openNode.classList.toggle('has-open', c.openContracts > 0);
    }
  }

  const openPosSummary = d.openPositions.length > 0
    ? d.openPositions.map((p) => (
        `${p.side} ${p.contracts} ${p.contractCode} @ ${p.entryPrice} (SL ${p.stopLossPrice ?? '—'} / TP ${p.takeProfitPrice ?? '—'} · ${formatSignedUsd(p.unrealizedPnlUsd)})`
      )).join(' · ')
    : '0 open micro-futures contracts right now (waiting for valve-cleared signal).';
  setText('[data-ob-open-summary="true"]', openPosSummary);

  const closedSummary = d.recentClosedTrades.length > 0
    ? d.recentClosedTrades.slice(0, 3).map((t) => (
        `${t.contractCode} x${t.contracts} ${formatSignedUsd(t.netPnlUsd)} (${t.status})`
      )).join(' · ')
    : 'No closed paper micro-futures trades yet.';
  setText('[data-ob-closed-summary="true"]', closedSummary);

  return true;
}

export const OPTION_B_DEMO_CSS_SNIPPET = `
/* PR #38: Option B $5,000.00 US-Regulated CME Micro Futures Paper Demo Card */
.ob-demo-panel { background: #0d1117; border: 1px solid #1e293b; border-top: 3px solid #38bdf8; color: #e2e8f0; padding: 18px 20px; }
.ob-header-row { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 14px; }
.ob-badge-strip { display: flex; flex-wrap: wrap; gap: 8px; }
.ob-badge { display: inline-flex; align-items: center; padding: 4px 10px; font-size: 11px; font-weight: 700; letter-spacing: 0.04em; border-radius: 4px; border: 1px solid #334155; }
.ob-badge-safe { background: #0c2638; color: #7dd3fc; border-color: #0284c7; }
.ob-badge-active { background: #07291e; color: #6ee7b7; border-color: #10b981; }
.ob-badge-danger { background: #3b0d14; color: #fda4af; border-color: #f43f5e; }
.ob-kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 12px; }
.ob-kpi-card { background: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 12px; display: flex; flex-direction: column; gap: 4px; }
.ob-kpi-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.04em; }
.ob-kpi-value { font-size: 18px; font-weight: 800; color: #f8fafc; }
.ob-kpi-value.is-positive { color: #34d399; }
.ob-kpi-value.is-negative { color: #fb7185; }
.ob-kpi-sub { font-size: 11px; color: #94a3b8; }
.ob-progress-wrap { margin-bottom: 14px; }
.ob-progress-track { width: 100%; height: 8px; background: #1e293b; border-radius: 999px; overflow: hidden; }
.ob-progress-fill { height: 100%; background: linear-gradient(90deg, #38bdf8, #10b981); transition: width 220ms cubic-bezier(0.22, 1, 0.36, 1); }
.ob-pct-0 { width: 0%; } .ob-pct-5 { width: 5%; } .ob-pct-10 { width: 10%; } .ob-pct-15 { width: 15%; }
.ob-pct-20 { width: 20%; } .ob-pct-25 { width: 25%; } .ob-pct-30 { width: 30%; } .ob-pct-35 { width: 35%; }
.ob-pct-40 { width: 40%; } .ob-pct-45 { width: 45%; } .ob-pct-50 { width: 50%; } .ob-pct-55 { width: 55%; }
.ob-pct-60 { width: 60%; } .ob-pct-65 { width: 65%; } .ob-pct-70 { width: 70%; } .ob-pct-75 { width: 75%; }
.ob-pct-80 { width: 80%; } .ob-pct-85 { width: 85%; } .ob-pct-90 { width: 90%; } .ob-pct-95 { width: 95%; }
.ob-pct-100 { width: 100%; }
.ob-contract-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; margin-bottom: 12px; }
.ob-contract-pill { background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 10px 12px; }
.ob-contract-head, .ob-contract-meta { display: flex; justify-content: space-between; align-items: center; gap: 6px; }
.ob-contract-map, .ob-contract-sub { font-size: 11px; color: #94a3b8; }
.ob-open-count { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 3px; background: #1e293b; color: #cbd5e1; }
.ob-open-count.has-open { background: #064e3b; color: #6ee7b7; }
.ob-footer-strip { border-top: 1px solid #1e293b; padding-top: 10px; display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
.ob-footer-line { margin: 0; color: #e2e8f0; }
.ob-footer-note { margin: 4px 0 0; font-size: 11px; color: #94a3b8; }
`;
