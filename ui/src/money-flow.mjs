// Interactive Animated Money Movement Flowchart & Expanded Lot-Size Scenario Explorer.
// Strict CSP compliant: zero inline scripts, zero inline style attributes, zero external CDNs,
// deterministic integer-cent arithmetic, and pure DOM / SVG NS element construction.

export const MONEY_FLOW_CAPITAL_PRESETS = Object.freeze([
  300, 1000, 3000, 6000, 10000, 25000, 50000, 100000, 300000,
]);

export const MONEY_FLOW_RISK_PRESETS = Object.freeze([1, 2, 3, 5]);

export const MONEY_FLOW_LOT_PRESETS = Object.freeze([
  '0.01', '0.05', '0.09', '0.15', '0.25', '0.50', '0.90', '1.00', '2.00', '5.00', '10.00',
]);

export const MONEY_FLOW_MARKETS = Object.freeze({
  EURUSD: Object.freeze({
    id: 'EURUSD',
    label: 'EUR/USD',
    kind: 'FX',
    leverage: 500,
    unitLabel: 'pip',
    stopUnits: 25,
    winUnits: 55,
    usdPerUnitPerLotCents: 1000, // $10.00/pip/lot
    marginPerLotCents: 22000,    // $220.00/lot at 1.1000, 1:500
    commissionPerLotCents: 700,  // $7.00/lot round-turn ECN
    refPriceLabel: '1.1000',
  }),
  GBPUSD: Object.freeze({
    id: 'GBPUSD',
    label: 'GBP/USD',
    kind: 'FX',
    leverage: 500,
    unitLabel: 'pip',
    stopUnits: 25,
    winUnits: 55,
    usdPerUnitPerLotCents: 1000, // $10.00/pip/lot
    marginPerLotCents: 25600,    // $256.00/lot at 1.2800, 1:500
    commissionPerLotCents: 700,
    refPriceLabel: '1.2800',
  }),
  USDJPY: Object.freeze({
    id: 'USDJPY',
    label: 'USD/JPY',
    kind: 'FX',
    leverage: 500,
    unitLabel: 'pip',
    stopUnits: 25,
    winUnits: 55,
    usdPerUnitPerLotCents: 645,  // ~$6.45/pip/lot at 155.00
    marginPerLotCents: 20000,    // $200.00/lot at 1:500
    commissionPerLotCents: 700,
    refPriceLabel: '155.00',
  }),
  NAS100: Object.freeze({
    id: 'NAS100',
    label: 'NAS100',
    kind: 'INDEX',
    leverage: 200,
    unitLabel: 'pt',
    stopUnits: 30,
    winUnits: 66,
    usdPerUnitPerLotCents: 100,  // $1.00/pt/contract
    marginPerLotCents: 13750,    // $137.50/contract at 27,500, 1:200
    commissionPerLotCents: 100,  // $1.00/contract ECN
    refPriceLabel: '27,500',
  }),
  US30: Object.freeze({
    id: 'US30',
    label: 'US30',
    kind: 'INDEX',
    leverage: 200,
    unitLabel: 'pt',
    stopUnits: 50,
    winUnits: 110,
    usdPerUnitPerLotCents: 100,  // $1.00/pt/contract
    marginPerLotCents: 25250,    // $252.50/contract at 50,500, 1:200
    commissionPerLotCents: 100,
    refPriceLabel: '50,500',
  }),
  SPX500: Object.freeze({
    id: 'SPX500',
    label: 'SPX500',
    kind: 'INDEX',
    leverage: 200,
    unitLabel: 'pt',
    stopUnits: 10,
    winUnits: 22,
    usdPerUnitPerLotCents: 100,  // $1.00/pt/contract
    marginPerLotCents: 3700,     // $37.00/contract at 7,400, 1:200
    commissionPerLotCents: 100,
    refPriceLabel: '7,400',
  }),
  XAUUSD: Object.freeze({
    id: 'XAUUSD',
    label: 'XAU/USD Gold',
    kind: 'GOLD',
    leverage: 200,
    unitLabel: '$1',
    stopUnits: 15,
    winUnits: 33,
    usdPerUnitPerLotCents: 10000, // 100 oz/lot -> $100 per $1 move
    marginPerLotCents: 186750,    // $1,867.50/lot at $3,735, 1:200
    commissionPerLotCents: 700,   // $7.00/lot ECN
    refPriceLabel: '$3,735',
  }),
});

export const MONEY_FLOW_MARKET_ORDER = Object.freeze([
  'EURUSD', 'GBPUSD', 'USDJPY', 'NAS100', 'US30', 'SPX500', 'XAUUSD',
]);

const esc = (v) => String(v).replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));

export function formatCentsUsd(cents) {
  const safe = Number.isFinite(cents) ? Math.round(cents) : 0;
  const neg = safe < 0;
  const abs = Math.abs(safe);
  const dollars = Math.floor(abs / 100);
  const rem = String(abs % 100).padStart(2, '0');
  const withCommas = String(dollars).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${neg ? '-' : ''}$${withCommas}.${rem}`;
}

export function formatLots(lotHundredths) {
  const safe = Math.max(1, Math.min(5000, Math.round(lotHundredths)));
  const whole = Math.floor(safe / 100);
  const frac = String(safe % 100).padStart(2, '0');
  return `${whole}.${frac}`;
}

export function clampCapitalUsd(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return 1000;
  return Math.max(50, Math.min(10000000, Math.round(n)));
}

export function clampLotHundredths(rawLots) {
  const n = Number(rawLots);
  if (!Number.isFinite(n)) return 9;
  return Math.max(1, Math.min(5000, Math.round(n * 100)));
}

export function createDefaultMoneyFlowState() {
  return {
    tab: 'flow',         // 'flow' | 'lots'
    capitalUsd: 1000,
    lotMode: 'risk',     // 'risk' | 'direct'
    riskPct: 1,          // 1 | 2 | 3 | 5
    directLotHundredths: 9, // 0.09 lots
    market: 'EURUSD',
    splitMode: '50_50',  // '50_50' | '100_COMPOUND'
    simWins: 0,
    simLosses: 0,
    simCapitalCents: 100000,
    simBankCents: 0,
    pulseNonce: 0,
  };
}

export function resolveLiveAccountBalanceUsd(state) {
  const allocTotal = Number(state?.brokerRouting?.dualShield?.allocation?.totalEquity ?? state?.brokerRouting?.allocation?.total_equity);
  if (Number.isFinite(allocTotal) && allocTotal >= 50) return clampCapitalUsd(allocTotal);
  const deployable = Number(state?.aiTrader?.deployableEquityUsd);
  if (Number.isFinite(deployable) && deployable >= 50) return clampCapitalUsd(deployable);
  const projEq = Number(state?.projection?.account?.equity?.amount);
  if (Number.isFinite(projEq) && projEq >= 50) return clampCapitalUsd(projEq);
  return 100000;
}

export function computeMoneyFlowScenario({
  capitalCents,
  marketId = 'EURUSD',
  lotMode = 'risk',
  riskPct = 1,
  directLotHundredths = 9,
  splitMode = '50_50',
  ownerMaxRiskPct = 5,
}) {
  const mkt = MONEY_FLOW_MARKETS[marketId] ?? MONEY_FLOW_MARKETS.EURUSD;
  const capCents = Math.max(5000, Math.round(Number(capitalCents) || 100000));
  const stopLossPerLotCents = mkt.stopUnits * mkt.usdPerUnitPerLotCents;
  const winGrossPerLotCents = mkt.winUnits * mkt.usdPerUnitPerLotCents;

  let lotHundredths;
  if (lotMode === 'risk') {
    const safePct = Math.max(0.25, Math.min(5, Number(riskPct) || 1));
    const riskBudgetCents = Math.floor((capCents * safePct) / 100);
    const rawHundredths = Math.floor((riskBudgetCents * 100) / Math.max(1, stopLossPerLotCents));
    lotHundredths = Math.max(1, Math.min(5000, rawHundredths));
  } else {
    lotHundredths = clampLotHundredths(directLotHundredths / 100);
  }

  const lossGrossCents = Math.round((stopLossPerLotCents * lotHundredths) / 100);
  const winGrossCents = Math.round((winGrossPerLotCents * lotHundredths) / 100);
  const commCents = Math.round((mkt.commissionPerLotCents * lotHundredths) / 100);
  const winNetCents = Math.max(0, winGrossCents - commCents);
  const lossNetCents = lossGrossCents + commCents;
  const marginCents = Math.max(1, Math.round((mkt.marginPerLotCents * lotHundredths) / 100));

  const perUnitCents = Math.round((mkt.usdPerUnitPerLotCents * lotHundredths) / 100);
  const riskPctActual = (lossGrossCents * 100) / capCents;
  const netLossPctActual = (lossNetCents * 100) / capCents;
  const winPctActual = (winNetCents * 100) / capCents;
  const marginLevelPct = (capCents * 100) / marginCents;

  const bankAddCents = splitMode === '100_COMPOUND' ? 0 : Math.ceil(winNetCents / 2);
  const compAddCents = winNetCents - bankAddCents;

  // Dual-Shield 80/12/8 split of trading capital
  const oandaCents = Math.round(capCents * 0.80);
  const hugoCents = Math.round(capCents * 0.12);
  const lhfxCents = capCents - oandaCents - hugoCents;

  const marginOk = marginLevelPct >= 1000;
  const lotCapOk = lotHundredths <= 5000;
  const riskCapPct = Math.max(1, Math.min(5, Number(ownerMaxRiskPct) || 5));
  const riskWithin1Pct = riskPctActual <= 1.005;
  const riskWithinOwnerCap = riskPctActual <= (riskCapPct + 0.05);
  const allowed = marginOk && lotCapOk && riskWithinOwnerCap;

  let shortVerdict;
  let badge;
  if (!marginOk) {
    shortVerdict = `HARD BLOCKED: Margin ${marginLevelPct.toFixed(0)}% < 1,000%`;
    badge = `HARD BLOCKED · Fails 1,000% Margin Cushion (${marginLevelPct.toFixed(2)}%)`;
  } else if (!riskWithinOwnerCap) {
    shortVerdict = `BLOCKED: ${riskPctActual.toFixed(2)}% > ${riskCapPct.toFixed(0)}% Cap`;
    badge = `BLOCKED BY ${riskCapPct.toFixed(0)}% RISK CAP (${riskPctActual.toFixed(2)}% Risk · Margin OK)`;
  } else if (riskWithin1Pct) {
    shortVerdict = `ADMITTED (Safe ${riskPctActual.toFixed(2)}%)`;
    badge = `ALLOWED · Clears Valve & 1,000% Margin (${riskPctActual.toFixed(2)}% Risk)`;
  } else {
    shortVerdict = `ADMITTED (${riskPctActual.toFixed(2)}% <= ${riskCapPct.toFixed(0)}% Cap)`;
    badge = `ALLOWED · Within Owner ${riskCapPct.toFixed(0)}% Cap & 1,000% Margin`;
  }

  const to10dd = lossNetCents > 0 ? ((capCents * 0.10) / lossNetCents) : 0;
  const to20dd = lossNetCents > 0 ? ((capCents * 0.20) / lossNetCents) : 0;
  const toZero = lossNetCents > 0 ? (capCents / lossNetCents) : 0;

  return Object.freeze({
    marketId: mkt.id,
    marketLabel: mkt.label,
    marketKind: mkt.kind,
    leverage: mkt.leverage,
    unitLabel: mkt.unitLabel,
    stopUnits: mkt.stopUnits,
    winUnits: mkt.winUnits,
    refPriceLabel: mkt.refPriceLabel,
    capitalCents: capCents,
    lotHundredths,
    lotText: formatLots(lotHundredths),
    perUnitCents,
    commCents,
    winGrossCents,
    winNetCents,
    lossGrossCents,
    lossNetCents,
    marginCents,
    marginLevelPct,
    riskPctActual,
    netLossPctActual,
    winPctActual,
    bankAddCents,
    compAddCents,
    oandaCents,
    hugoCents,
    lhfxCents,
    allowed,
    marginOk,
    riskWithinOwnerCap,
    ownerMaxRiskPct: riskCapPct,
    shortVerdict,
    badge,
    to10ddLabel: to10dd < 1 ? `${to10dd.toFixed(2)} losses (1st loss!)` : `${to10dd.toFixed(2)} losses`,
    to20ddLabel: to20dd < 1 ? `${to20dd.toFixed(2)} losses (1st loss!)` : `${to20dd.toFixed(2)} losses`,
    toZeroLabel: `${toZero.toFixed(2)} losses`,
    splitMode,
  });
}

export function stepMoneyFlowSimulation(mfState, stepKind, ownerMaxRiskPct = 5) {
  const next = { ...mfState };
  if (stepKind === 'reset') {
    next.simWins = 0;
    next.simLosses = 0;
    next.simCapitalCents = clampCapitalUsd(next.capitalUsd) * 100;
    next.simBankCents = 0;
    next.pulseNonce = (next.pulseNonce || 0) + 1;
    return next;
  }
  const steps = stepKind === 'win5' ? 5 : 1;
  for (let i = 0; i < steps; i += 1) {
    const scen = computeMoneyFlowScenario({
      capitalCents: next.simCapitalCents,
      marketId: next.market,
      lotMode: next.lotMode,
      riskPct: next.riskPct,
      directLotHundredths: next.directLotHundredths,
      splitMode: next.splitMode,
      ownerMaxRiskPct,
    });
    if (stepKind === 'loss') {
      next.simLosses += 1;
      next.simCapitalCents = Math.max(5000, next.simCapitalCents - scen.lossNetCents);
    } else {
      next.simWins += 1;
      next.simCapitalCents += scen.compAddCents;
      next.simBankCents += scen.bankAddCents;
    }
  }
  next.pulseNonce = (next.pulseNonce || 0) + 1;
  return next;
}

export function computeLotComparisonRows({
  capitalCents,
  marketId = 'EURUSD',
  splitMode = '50_50',
  ownerMaxRiskPct = 5,
  selectedLotMode = 'risk',
  selectedRiskPct = 1,
  selectedDirectLotHundredths = 9,
}) {
  const candidates = [
    { key: 'risk:1', title: 'Safe 1% Rule', lotMode: 'risk', riskPct: 1, directLotHundredths: 9 },
    { key: 'risk:2', title: '2% Growth Risk', lotMode: 'risk', riskPct: 2, directLotHundredths: 9 },
    { key: 'risk:5', title: '5% Strong-Trend', lotMode: 'risk', riskPct: 5, directLotHundredths: 9 },
    { key: 'direct:9', title: '0.09 Lots Fixed', lotMode: 'direct', riskPct: 1, directLotHundredths: 9 },
    { key: 'direct:90', title: '0.90 Lots Fixed', lotMode: 'direct', riskPct: 1, directLotHundredths: 90 },
    { key: 'direct:500', title: '5.00 Lots Fixed', lotMode: 'direct', riskPct: 1, directLotHundredths: 500 },
  ];
  const activeKey = selectedLotMode === 'risk'
    ? `risk:${selectedRiskPct}`
    : `direct:${selectedDirectLotHundredths}`;
  if (!candidates.some((c) => c.key === activeKey)) {
    candidates.push({
      key: activeKey,
      title: selectedLotMode === 'risk'
        ? `${selectedRiskPct}% Custom Risk`
        : `${formatLots(selectedDirectLotHundredths)} Lots Custom`,
      lotMode: selectedLotMode,
      riskPct: selectedRiskPct,
      directLotHundredths: selectedDirectLotHundredths,
    });
  }
  return candidates.map((c) => ({
    ...c,
    selected: c.key === activeKey,
    scenario: computeMoneyFlowScenario({
      capitalCents,
      marketId,
      lotMode: c.lotMode,
      riskPct: c.riskPct,
      directLotHundredths: c.directLotHundredths,
      splitMode,
      ownerMaxRiskPct,
    }),
  }));
}

export function renderMoneyFlowSection(state) {
  const mf = state?.moneyFlow ?? createDefaultMoneyFlowState();
  const ownerMaxRisk = Number(state?.aiTrader?.riskGear?.ownerMaxRiskPct ?? state?.brokerRouting?.barbell?.maxStopLossEquityRiskPct ?? 5) || 5;
  const scen = computeMoneyFlowScenario({
    capitalCents: mf.simCapitalCents,
    marketId: mf.market,
    lotMode: mf.lotMode,
    riskPct: mf.riskPct,
    directLotHundredths: mf.directLotHundredths,
    splitMode: mf.splitMode,
    ownerMaxRiskPct: ownerMaxRisk,
  });
  const liveBalUsd = resolveLiveAccountBalanceUsd(state);

  const capButtons = MONEY_FLOW_CAPITAL_PRESETS.map((amt) => {
    const active = mf.capitalUsd === amt;
    const label = amt >= 1000 ? `$${String(amt).replace(/\B(?=(\d{3})+(?!\d))/g, ',')}` : `$${amt}`;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-mf-cap="${amt}" aria-pressed="${active}">${esc(label)}</button>`;
  }).join('');

  const riskButtons = MONEY_FLOW_RISK_PRESETS.map((pct) => {
    const active = mf.lotMode === 'risk' && mf.riskPct === pct;
    const lbl = pct === 1 ? 'Safe 1%' : `${pct}% Risk`;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-mf-risk="${pct}" aria-pressed="${active}">${esc(lbl)}</button>`;
  }).join('');

  const lotButtons = MONEY_FLOW_LOT_PRESETS.map((lotStr) => {
    const hund = Math.round(Number(lotStr) * 100);
    const active = mf.lotMode === 'direct' && mf.directLotHundredths === hund;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-mf-lot="${esc(lotStr)}" aria-pressed="${active}">${esc(lotStr)}</button>`;
  }).join('');

  const mktButtons = MONEY_FLOW_MARKET_ORDER.map((mid) => {
    const m = MONEY_FLOW_MARKETS[mid];
    const active = mf.market === mid;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-mf-market="${esc(mid)}" aria-pressed="${active}">${esc(m.label)}</button>`;
  }).join('');

  const compRows = computeLotComparisonRows({
    capitalCents: mf.simCapitalCents,
    marketId: mf.market,
    splitMode: mf.splitMode,
    ownerMaxRiskPct: ownerMaxRisk,
    selectedLotMode: mf.lotMode,
    selectedRiskPct: mf.riskPct,
    selectedDirectLotHundredths: mf.directLotHundredths,
  });

  const comparisonCards = compRows.map((row) => {
    const s = row.scenario;
    return `<article class="mf-lot-card${row.selected ? ' is-selected' : ''}">
      <div class="mf-lot-card-head">
        <strong>${esc(row.title)} (${esc(s.lotText)} lots)</strong>
        <span class="mf-verdict-pill ${s.allowed ? 'is-pass' : 'is-block'}">${s.allowed ? 'PASS' : 'BLOCKED'}</span>
      </div>
      <dl class="mf-lot-metrics numeric">
        <div><dt>${esc(s.winUnits)}-${esc(s.unitLabel)} Win Net</dt><dd class="mf-pos">+${esc(formatCentsUsd(s.winNetCents))} (+${esc(s.winPctActual.toFixed(2))}%)</dd></div>
        <div><dt>${esc(s.stopUnits)}-${esc(s.unitLabel)} Loss Net</dt><dd class="mf-neg">-${esc(formatCentsUsd(s.lossNetCents))} (-${esc(s.netLossPctActual.toFixed(2))}%)</dd></div>
        <div><dt>${mf.splitMode === '100_COMPOUND' ? '100% Compound / Bank' : '50% Bank / Compound'}</dt><dd>${esc(formatCentsUsd(s.bankAddCents))} / ${esc(formatCentsUsd(s.compAddCents))}</dd></div>
        <div><dt>1:${esc(s.leverage)} Margin</dt><dd>${esc(formatCentsUsd(s.marginCents))} (${esc(s.marginLevelPct.toFixed(0))}%)</dd></div>
        <div><dt>To 10% / 20% Lock</dt><dd>${esc(s.to10ddLabel)} · ${esc(s.to20ddLabel)}</dd></div>
        <div><dt>To $0</dt><dd>${esc(s.toZeroLabel)}</dd></div>
      </dl>
      <button type="button" class="button button-small button-secondary" ${row.lotMode === 'risk' ? `data-mf-risk="${row.riskPct}"` : `data-mf-lot="${esc(formatLots(row.directLotHundredths))}"`}>Inspect in Flowchart</button>
    </article>`;
  }).join('');

  return `<section class="panel money-flow-panel" aria-label="Interactive Money Movement Flowchart and Lot Scenario Explorer">
    <div class="section-heading">
      <div>
        <p class="eyebrow">LIVE MONEY MOVEMENT &amp; LOT EXPLORER · EXACT CENT MATH</p>
        <h2>Money Movement Flowchart &amp; Lot Scenarios</h2>
      </div>
      <div class="mf-top-tabs" role="tablist" aria-label="Money flow views">
        <button type="button" role="tab" class="button button-small ${mf.tab === 'flow' ? 'selected' : 'button-secondary'}" data-mf-tab="flow" aria-selected="${mf.tab === 'flow'}">Money Flow Chart</button>
        <button type="button" role="tab" class="button button-small ${mf.tab === 'lots' ? 'selected' : 'button-secondary'}" data-mf-tab="lots" aria-selected="${mf.tab === 'lots'}">Lot Comparison</button>
        <button type="button" class="button button-small ${mf.splitMode === '50_50' ? 'selected' : 'button-secondary'}" data-mf-split="50_50" aria-pressed="${mf.splitMode === '50_50'}">50% / 50% Bank Split</button>
        <button type="button" class="button button-small ${mf.splitMode === '100_COMPOUND' ? 'selected' : 'button-secondary'}" data-mf-split="100_COMPOUND" aria-pressed="${mf.splitMode === '100_COMPOUND'}">100% Compound</button>
      </div>
    </div>

    <div class="mf-control-rows">
      <div class="mf-control-group">
        <span class="control-label">Starting Capital</span>
        <div class="mf-btn-wrap">
          ${capButtons}
          <button type="button" class="button button-small button-secondary" data-mf-live-balance="true">Live Balance (${esc(formatCentsUsd(liveBalUsd * 100))})</button>
          <label class="mf-inline-input">Custom $ <input type="number" min="50" max="10000000" step="50" value="${esc(mf.capitalUsd)}" data-mf-custom-cap="true" aria-label="Custom starting capital in USD"></label>
        </div>
      </div>

      <div class="mf-control-group">
        <span class="control-label">Market (Exact Contract &amp; Margin Math)</span>
        <div class="mf-btn-wrap">${mktButtons}</div>
      </div>

      <div class="mf-control-group">
        <span class="control-label">Lot Size / Risk Choice (Active: ${esc(scen.lotText)} lots · ${esc(scen.riskPctActual.toFixed(2))}% stop risk)</span>
        <div class="mf-btn-wrap">
          ${riskButtons}
          ${lotButtons}
          <label class="mf-inline-input">Custom Lots <input type="number" min="0.01" max="50.00" step="0.01" value="${esc(scen.lotText)}" data-mf-custom-lot="true" aria-label="Custom lot size between 0.01 and 50.00"></label>
        </div>
      </div>

      <div class="mf-sim-bar">
        <span class="mf-verdict-pill ${scen.allowed ? 'is-pass' : 'is-block'}">${esc(scen.badge)}</span>
        <span class="mf-tally numeric">Wins: ${esc(mf.simWins)} · Losses: ${esc(mf.simLosses)} · Trading Capital: <strong>${esc(formatCentsUsd(mf.simCapitalCents))}</strong> · Bank Vault: <strong>${esc(formatCentsUsd(mf.simBankCents))}</strong></span>
        <div class="mf-sim-actions">
          <button type="button" class="button button-small button-primary" data-mf-step="win">+1 Win</button>
          <button type="button" class="button button-small button-warning" data-mf-step="loss">+1 Loss</button>
          <button type="button" class="button button-small button-secondary" data-mf-step="win5">+5 Wins</button>
          <button type="button" class="button button-small button-secondary" data-mf-step="reset">Reset</button>
        </div>
      </div>
    </div>

    ${mf.tab === 'flow'
      ? `<div class="mf-svg-wrap" data-money-flow-mount="true"></div>`
      : `<div class="mf-lots-panel">
          <p class="quiet-note">Comparing lot sizes on <strong>${esc(scen.marketLabel)}</strong> (${esc(scen.stopUnits)}-${esc(scen.unitLabel)} stop, ${esc(scen.winUnits)}-${esc(scen.unitLabel)} win, ${esc(formatCentsUsd(MONEY_FLOW_MARKETS[mf.market].commissionPerLotCents))}/lot ECN fee, 1:${esc(scen.leverage)} leverage at ${esc(scen.refPriceLabel)}, owner risk ceiling ${esc(ownerMaxRisk)}%).</p>
          <div class="mf-lots-grid">${comparisonCards}</div>
        </div>`}
  </section>`;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

function svgEl(tag, attrs = {}, textContent = null) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    el.setAttribute(k, String(v));
  }
  if (textContent !== null) el.textContent = String(textContent);
  return el;
}

export function mountMoneyFlowWidget(root, state) {
  if (!root || typeof document === 'undefined' || typeof document.createElementNS !== 'function') return;
  const host = root.querySelector('[data-money-flow-mount="true"]');
  if (!host) return;
  const mf = state?.moneyFlow ?? createDefaultMoneyFlowState();
  const ownerMaxRisk = Number(state?.aiTrader?.riskGear?.ownerMaxRiskPct ?? state?.brokerRouting?.barbell?.maxStopLossEquityRiskPct ?? 5) || 5;
  const s = computeMoneyFlowScenario({
    capitalCents: mf.simCapitalCents,
    marketId: mf.market,
    lotMode: mf.lotMode,
    riskPct: mf.riskPct,
    directLotHundredths: mf.directLotHundredths,
    splitMode: mf.splitMode,
    ownerMaxRiskPct: ownerMaxRisk,
  });

  const svg = svgEl('svg', {
    viewBox: '0 0 880 315',
    class: 'mf-flow-svg',
    role: 'img',
    'aria-label': `CAS Forex money movement flowchart for ${s.marketLabel} at ${s.lotText} lots`,
  });

  const defs = svgEl('defs');
  const markers = [
    ['mf-arr-primary', 'var(--mf-blue, #2563EB)'],
    ['mf-arr-success', 'var(--mf-green, #16A34A)'],
    ['mf-arr-warn', 'var(--mf-gold, #D97706)'],
    ['mf-arr-err', 'var(--mf-red, #DC2626)'],
  ];
  for (const [id, fill] of markers) {
    const mk = svgEl('marker', {
      id, viewBox: '0 0 10 10', refX: '8', refY: '5', markerWidth: '6', markerHeight: '6', orient: 'auto-start-reverse',
    });
    mk.appendChild(svgEl('path', { d: 'M 0 1 L 10 5 L 0 9 z', fill }));
    defs.appendChild(mk);
  }
  svg.appendChild(defs);

  const compLabel = mf.splitMode === '100_COMPOUND'
    ? `100% COMPOUNDED (+${formatCentsUsd(s.compAddCents)}) -> GROWS NEXT TRADE`
    : `50% COMPOUNDED (+${formatCentsUsd(s.compAddCents)}) -> GROWS NEXT TRADE`;
  const bankLabel = mf.splitMode === '100_COMPOUND'
    ? '100% COMPOUND MODE ($0.00 LOCKED TO BANK)'
    : `50% LOCKED TO BANK VAULT (+${formatCentsUsd(s.bankAddCents)})`;

  // Top green compounding return loop
  svg.appendChild(svgEl('path', {
    d: 'M 738 96 L 738 26 Q 738 14 726 14 L 92 14 Q 80 14 80 26 L 80 86',
    fill: 'none', stroke: 'var(--mf-green, #16A34A)', 'stroke-width': '2.5',
    class: 'pipe-flow', 'marker-end': 'url(#mf-arr-success)',
  }));
  svg.appendChild(svgEl('rect', {
    x: '250', y: '3', width: '380', height: '22', rx: '11',
    fill: 'var(--panel, #FFFFFF)', stroke: 'var(--mf-green, #16A34A)', 'stroke-width': '1.2',
  }));
  svg.appendChild(svgEl('text', {
    x: '440', y: '18', 'text-anchor': 'middle', 'font-size': '11.5', 'font-weight': '700', fill: 'var(--mf-green, #16A34A)',
  }, compLabel));

  // Main horizontal pipes
  svg.appendChild(svgEl('line', {
    x1: '172', y1: '134', x2: '214', y2: '134',
    stroke: 'var(--mf-blue, #2563EB)', 'stroke-width': '2.4', class: 'pipe-flow', 'marker-end': 'url(#mf-arr-primary)',
  }));
  svg.appendChild(svgEl('line', {
    x1: '384', y1: '134', x2: '424', y2: '134',
    stroke: 'var(--mf-blue, #2563EB)', 'stroke-width': '2.4', class: 'pipe-flow', 'marker-end': 'url(#mf-arr-primary)',
  }));
  svg.appendChild(svgEl('line', {
    x1: '610', y1: '134', x2: '650', y2: '134',
    stroke: s.allowed ? 'var(--mf-green, #16A34A)' : 'var(--mf-red, #DC2626)',
    'stroke-width': '2.4', class: 'pipe-flow',
    'marker-end': s.allowed ? 'url(#mf-arr-success)' : 'url(#mf-arr-err)',
  }));

  // Bottom gold bank vault loop
  const bankStroke = mf.splitMode === '100_COMPOUND' ? 'var(--muted, #596779)' : 'var(--mf-gold, #D97706)';
  svg.appendChild(svgEl('path', {
    d: 'M 738 178 L 738 210 L 146 210 L 146 228',
    fill: 'none', stroke: bankStroke, 'stroke-width': '2.4',
    class: 'pipe-flow-slow', 'marker-end': 'url(#mf-arr-warn)',
  }));
  svg.appendChild(svgEl('rect', {
    x: '295', y: '199', width: '290', height: '21', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: bankStroke, 'stroke-width': '1.2',
  }));
  svg.appendChild(svgEl('text', {
    x: '440', y: '213', 'text-anchor': 'middle', 'font-size': '11', 'font-weight': '700', fill: bankStroke,
  }, bankLabel));

  svg.appendChild(svgEl('line', {
    x1: '266', y1: '266', x2: '312', y2: '266',
    stroke: bankStroke, 'stroke-width': '2.2', class: 'pipe-flow-slow', 'marker-end': 'url(#mf-arr-warn)',
  }));
  svg.appendChild(svgEl('line', {
    x1: '574', y1: '266', x2: '620', y2: '266',
    stroke: 'var(--mf-green, #16A34A)', 'stroke-width': '2.2', class: 'pipe-flow-slow', 'marker-end': 'url(#mf-arr-success)',
  }));

  const pulseClass = mf.pulseNonce > 0 ? 'pulse-once' : '';

  // Box 1: Trading Capital
  const g1 = svgEl('g', { class: pulseClass });
  g1.appendChild(svgEl('rect', {
    x: '12', y: '92', width: '160', height: '84', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: 'var(--line, #DCE2EA)', 'stroke-width': '1.6',
  }));
  g1.appendChild(svgEl('text', { x: '92', y: '112', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: 'var(--muted, #596779)' }, '1. TRADING CAPITAL'));
  g1.appendChild(svgEl('text', { x: '92', y: '138', 'text-anchor': 'middle', 'font-size': '17', 'font-weight': '800', fill: 'var(--ink, #122238)' }, formatCentsUsd(s.capitalCents)));
  g1.appendChild(svgEl('text', { x: '92', y: '158', 'text-anchor': 'middle', 'font-size': '10.5', fill: 'var(--muted, #596779)' }, `${s.marketLabel} · 1:${s.leverage} · ${s.lotText} lots`));
  svg.appendChild(g1);

  // Box 2: Dual-Shield 80/12/8 Split
  const g2 = svgEl('g');
  g2.appendChild(svgEl('rect', {
    x: '218', y: '88', width: '166', height: '92', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: 'var(--mf-blue, #2563EB)', 'stroke-width': '1.6',
  }));
  g2.appendChild(svgEl('text', { x: '301', y: '107', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: 'var(--mf-blue, #2563EB)' }, '2. DUAL-SHIELD 80/12/8'));
  g2.appendChild(svgEl('text', { x: '301', y: '125', 'text-anchor': 'middle', 'font-size': '11', 'font-weight': '600', fill: 'var(--ink, #122238)' }, `OANDA 80%: ${formatCentsUsd(s.oandaCents)}`));
  g2.appendChild(svgEl('text', { x: '301', y: '142', 'text-anchor': 'middle', 'font-size': '11', fill: 'var(--ink, #122238)' }, `Hugo 12%: ${formatCentsUsd(s.hugoCents)}`));
  g2.appendChild(svgEl('text', { x: '301', y: '159', 'text-anchor': 'middle', 'font-size': '11', fill: 'var(--ink, #122238)' }, `LHFX 8%: ${formatCentsUsd(s.lhfxCents)}`));
  svg.appendChild(g2);

  // Box 3: AI + 161-Param Safety Valve & Margin Verdict
  const g3 = svgEl('g');
  const vStroke = s.allowed ? 'var(--mf-green, #16A34A)' : 'var(--mf-red, #DC2626)';
  g3.appendChild(svgEl('rect', {
    x: '428', y: '88', width: '182', height: '92', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: vStroke, 'stroke-width': '1.8',
  }));
  g3.appendChild(svgEl('text', { x: '519', y: '107', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: 'var(--muted, #596779)' }, '3. AI + 161-PARAM VALVE'));
  g3.appendChild(svgEl('text', { x: '519', y: '127', 'text-anchor': 'middle', 'font-size': '11.5', 'font-weight': '800', fill: vStroke }, s.shortVerdict));
  g3.appendChild(svgEl('text', { x: '519', y: '145', 'text-anchor': 'middle', 'font-size': '10.5', fill: 'var(--ink, #122238)' }, `Margin: ${formatCentsUsd(s.marginCents)} (${s.marginLevelPct.toFixed(0)}%)`));
  g3.appendChild(svgEl('text', { x: '519', y: '162', 'text-anchor': 'middle', 'font-size': '10.5', fill: 'var(--muted, #596779)' }, `Stop Loss: -${formatCentsUsd(s.lossNetCents)} (-${s.netLossPctActual.toFixed(2)}%)`));
  svg.appendChild(g3);

  // Box 4: Closed Win
  const g4 = svgEl('g', { class: pulseClass });
  g4.appendChild(svgEl('rect', {
    x: '654', y: '92', width: '210', height: '84', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: 'var(--mf-green, #16A34A)', 'stroke-width': '1.6',
  }));
  g4.appendChild(svgEl('text', { x: '759', y: '112', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: 'var(--muted, #596779)' }, `4. CLOSED WIN (${s.winUnits}-${s.unitLabel})`));
  g4.appendChild(svgEl('text', { x: '759', y: '138', 'text-anchor': 'middle', 'font-size': '17', 'font-weight': '800', fill: 'var(--mf-green, #16A34A)' }, `+${formatCentsUsd(s.winNetCents)}`));
  g4.appendChild(svgEl('text', { x: '759', y: '158', 'text-anchor': 'middle', 'font-size': '10.5', fill: 'var(--muted, #596779)' }, `+${s.winPctActual.toFixed(2)}% net · Fee ${formatCentsUsd(s.commCents)}`));
  svg.appendChild(g4);

  // Box 5: Profit-Sweep Bank Vault
  const g5 = svgEl('g');
  g5.appendChild(svgEl('rect', {
    x: '12', y: '232', width: '254', height: '70', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: bankStroke, 'stroke-width': '1.6',
  }));
  g5.appendChild(svgEl('text', { x: '139', y: '251', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: bankStroke }, '5. PROFIT-SWEEP VAULT'));
  g5.appendChild(svgEl('text', { x: '139', y: '272', 'text-anchor': 'middle', 'font-size': '15', 'font-weight': '800', fill: 'var(--ink, #122238)' }, `Locked: ${formatCentsUsd(mf.simBankCents)}`));
  g5.appendChild(svgEl('text', { x: '139', y: '290', 'text-anchor': 'middle', 'font-size': '10', fill: 'var(--muted, #596779)' }, 'Protected from future trade drawdown'));
  svg.appendChild(g5);

  // Box 5b: Regulated USD Off-Ramp
  const g5b = svgEl('g');
  g5b.appendChild(svgEl('rect', {
    x: '316', y: '232', width: '258', height: '70', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: 'var(--line, #DCE2EA)', 'stroke-width': '1.6',
  }));
  g5b.appendChild(svgEl('text', { x: '445', y: '251', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: 'var(--muted, #596779)' }, 'COINBASE / KRAKEN USD ACH'));
  g5b.appendChild(svgEl('text', { x: '445', y: '271', 'text-anchor': 'middle', 'font-size': '12', 'font-weight': '700', fill: 'var(--ink, #122238)' }, 'Pinned Bank Account Only'));
  g5b.appendChild(svgEl('text', { x: '445', y: '289', 'text-anchor': 'middle', 'font-size': '10', 'font-weight': '700', fill: 'var(--mf-red, #DC2626)' }, 'External Crypto Wallets HARD BLOCKED'));
  svg.appendChild(g5b);

  // Box 6: Your Bank Account
  const g6 = svgEl('g');
  g6.appendChild(svgEl('rect', {
    x: '624', y: '232', width: '240', height: '70', rx: '10',
    fill: 'var(--panel, #FFFFFF)', stroke: 'var(--mf-green, #16A34A)', 'stroke-width': '1.6',
  }));
  g6.appendChild(svgEl('text', { x: '744', y: '251', 'text-anchor': 'middle', 'font-size': '10.5', 'font-weight': '700', fill: 'var(--muted, #596779)' }, '6. YOUR BANK ACCOUNT'));
  g6.appendChild(svgEl('text', { x: '744', y: '272', 'text-anchor': 'middle', 'font-size': '13.5', 'font-weight': '800', fill: 'var(--mf-green, #16A34A)' }, 'Real USD via ACH'));
  g6.appendChild(svgEl('text', { x: '744', y: '290', 'text-anchor': 'middle', 'font-size': '10', fill: 'var(--muted, #596779)' }, 'Permanent SHA-256 audit receipt'));
  svg.appendChild(g6);

  host.replaceChildren(svg);
}
