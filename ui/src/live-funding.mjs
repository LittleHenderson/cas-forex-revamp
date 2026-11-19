// Apparent Real-Money LIVE Mode, 80%/12%/8% Barbell Deposit Calculator,
// 5-Gate Cloud Readiness Checklist, and Two-Key Arming Preflight Gate.
// Strict CSP compliant: zero inline scripts, zero inline CSS attributes, zero external URLs,
// deterministic integer-cent arithmetic, and safe HTML escaping on all text.

import { STATIC_BROKER_ROUTING, STATIC_LIVE_READINESS } from './broker-routing.mjs';
import { formatCentsUsd } from './money-flow.mjs';

export const LIVE_FUNDING_PRESETS_USD = Object.freeze([
  1000, 2500, 5000, 10000, 25000, 50000, 100000,
]);

export const REQUIRED_LIVE_ARM_PHRASE = 'ARM_LIVE_REAL_MONEY_TRADING';

const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));

export function createDefaultLiveFundingState() {
  return {
    capitalUsd: 10000,
    armPhraseInput: '',
    verifyResult: null,
  };
}

export function clampLiveCapitalUsd(raw) {
  if (raw === null || raw === undefined || raw === '' || typeof raw === 'boolean') return 10000;
  const n = Number(raw);
  if (!Number.isFinite(n)) return 10000;
  return Math.max(300, Math.min(10000000, Math.round(n)));
}

export function computeBarbellFundingSplit(capitalUsd) {
  const parsed = Number(capitalUsd);
  const safeUsd = Number.isFinite(parsed) && parsed > 0
    ? Math.max(300, Math.min(10000000, parsed))
    : 10000;
  const totalCents = Math.round(safeUsd * 100);
  const oandaCents = Math.round(totalCents * 0.80);
  const hugoswayCents = Math.round(totalCents * 0.12);
  const lhfxCents = totalCents - oandaCents - hugoswayCents;
  const risk1PctCents = Math.round(totalCents * 0.01);
  const risk25PctCents = Math.round(totalCents * 0.025);
  const risk5PctCents = Math.round(totalCents * 0.05);
  const maxDrawdown20PctCents = Math.round(totalCents * 0.20);

  return Object.freeze({
    capitalUsd: totalCents / 100,
    totalCents,
    oandaCents,
    hugoswayCents,
    lhfxCents,
    risk1PctCents,
    risk25PctCents,
    risk5PctCents,
    maxDrawdown20PctCents,
  });
}

export function evaluateLiveArmingPreflight(liveFundingState, brokerRouting) {
  const phraseRaw = typeof liveFundingState?.armPhraseInput === 'string'
    ? liveFundingState.armPhraseInput
    : '';
  const phraseMatched = phraseRaw.trim() === REQUIRED_LIVE_ARM_PHRASE;

  const rawGates = brokerRouting?.liveReadiness?.gates
    ?? brokerRouting?.live_readiness?.gates
    ?? STATIC_LIVE_READINESS.gates;
  const gates = Array.isArray(rawGates) && rawGates.length > 0
    ? rawGates
    : STATIC_LIVE_READINESS.gates;

  const passedCount = gates.filter((g) => Boolean(g?.passed)).length;
  const totalGates = gates.length;
  const gatesReady = totalGates >= 5 && gates.every((g) => Boolean(g?.passed));
  const canArmLive = phraseMatched && gatesReady;

  const pendingLabels = gates
    .filter((g) => !g?.passed)
    .map((g, idx) => `Gate ${Number.isSafeInteger(g?.step) ? g.step : idx + 1} (${String(g?.id ?? 'PENDING')})`);

  let headline;
  let detail;
  if (canArmLive) {
    headline = 'READY FOR REAL-MONEY LIVE EXECUTION — ALL 5 GATES & TWO-KEY PHRASE VERIFIED';
    detail = `All ${totalGates}/${totalGates} backend readiness gates passed and Key 2 phrase ${REQUIRED_LIVE_ARM_PHRASE} matched. Dual-Shield 80% / 12% / 8% live custody and 161-parameter ForexMetaValveGate are verified.`;
  } else if (phraseMatched && !gatesReady) {
    headline = 'KEY 2 PHRASE MATCHED — BLOCKED UNTIL ALL 5 CLOUD GATES ARE READY';
    detail = `Confirmation phrase matched (${passedCount}/${totalGates} gates ready). Pending before live arming: ${pendingLabels.join(', ')}. Stage live credentials and Ed25519 tickets via D:\\MetaTrader5\\LIVE_FUNDING_STEP\\Stage_Live_Funding_To_Cloud.ps1.`;
  } else if (!phraseMatched && gatesReady) {
    headline = 'ALL 5 CLOUD GATES READY — ENTER EXACT KEY 2 PHRASE TO CONFIRM';
    detail = `All ${totalGates}/${totalGates} backend readiness gates passed, but Key 2 confirmation phrase must match ${REQUIRED_LIVE_ARM_PHRASE} exactly.`;
  } else {
    headline = 'DEMO PAPER MODE LOCKED — 5 GATES & TWO-KEY PHRASE REQUIRED FOR REAL MONEY';
    detail = `${passedCount}/${totalGates} live gates ready (${pendingLabels.join(', ')}) and Key 2 confirmation phrase not entered. Execution stays locked to demo paper accounts.`;
  }

  return Object.freeze({
    phraseMatched,
    gatesReady,
    canArmLive,
    passedCount,
    totalGates,
    headline,
    detail,
  });
}

export function renderLiveFundingPanel(state) {
  const lf = state?.liveFunding ?? createDefaultLiveFundingState();
  const routing = state?.brokerRouting && typeof state.brokerRouting === 'object'
    ? state.brokerRouting
    : STATIC_BROKER_ROUTING;
  const readiness = routing.liveReadiness ?? STATIC_LIVE_READINESS;
  const gates = Array.isArray(readiness.gates) && readiness.gates.length > 0
    ? readiness.gates
    : STATIC_LIVE_READINESS.gates;
  const passedCount = gates.filter((g) => Boolean(g?.passed)).length;
  const isLiveArmed = routing.executionMode === 'LIVE' && routing.liveArmed === true;

  const capUsd = clampLiveCapitalUsd(lf.capitalUsd);
  const split = computeBarbellFundingSplit(capUsd);
  const preflight = evaluateLiveArmingPreflight(lf, routing);
  const activeVerdict = lf.verifyResult ?? preflight;

  const presetButtons = LIVE_FUNDING_PRESETS_USD.map((amt) => {
    const active = capUsd === amt;
    const label = `$${String(amt).replace(/\B(?=(\d{3})+(?!\d))/g, ',')}`;
    return `<button type="button" class="button button-small ${active ? 'selected' : 'button-secondary'}" data-lf-cap="${amt}" aria-pressed="${active}">${esc(label)}</button>`;
  }).join('');

  const gateItems = gates.map((g, idx) => {
    const stepNum = Number.isSafeInteger(g.step) ? g.step : idx + 1;
    const passed = Boolean(g.passed);
    return `<li class="lf-gate-item ${passed ? 'is-ready' : 'is-pending'}" data-lf-gate-id="${esc(g.id)}">
      <div class="lf-gate-main">
        <div class="lf-gate-title-row">
          <span class="lf-gate-step">Gate ${esc(stepNum)}</span>
          <strong>${esc(g.title)}</strong>
          <code>${esc(g.id)}</code>
        </div>
        <p class="lf-gate-detail">${esc(g.detail)}</p>
      </div>
      <span class="lf-gate-badge ${passed ? 'is-ready' : 'is-pending'}" data-lf-gate-status="${passed ? 'READY' : 'PENDING'}">${passed ? 'READY' : 'PENDING'}</span>
    </li>`;
  }).join('');

  const modeHeadline = isLiveArmed
    ? 'CURRENT MODE: REAL-MONEY LIVE ARMED'
    : 'CURRENT MODE: DEMO PAPER ACCOUNTS — REAL-MONEY LIVE LOCKED';
  const modeSubcopy = isLiveArmed
    ? 'Two-key owner authorization is active across OANDA Live (80%), Hugo\'s Way Hugosway-Real3 (12%), and LHFX LHFXSA-Live (8%). Demo servers are hard-refused and every order still clears tks_meta_valve_controller.'
    : 'Zero real money is at risk right now. Follow the 3 apparent steps below to calculate your 80% / 12% / 8% deposit split, verify all 5 cloud gates, and test two-key real-money arming.';

  const verdictClass = activeVerdict.canArmLive
    ? 'is-ready'
    : (activeVerdict.phraseMatched ? 'is-partial' : 'is-locked');

  return `<section class="panel live-funding-panel" id="live-funding-section" aria-label="Real-Money LIVE Funding and Two-Key Arming Gate">
    <div class="lf-mode-banner ${isLiveArmed ? 'is-live' : 'is-demo'}" data-lf-mode="${isLiveArmed ? 'LIVE' : 'DEMO'}">
      <div class="lf-mode-copy">
        <p class="eyebrow">EXECUTION MODE &amp; REAL-MONEY FUNDING GATE · ${esc(passedCount)}/${esc(gates.length)} CLOUD GATES READY</p>
        <h2>${esc(modeHeadline)}</h2>
        <p>${esc(modeSubcopy)}</p>
      </div>
      <div class="lf-mode-actions">
        <span class="tag${isLiveArmed ? ' tag-warning' : ''}"><span class="state-rule" aria-hidden="true"></span>${routing.connected ? 'Live Cloud Gate Readback' : 'Offline Preview · Unlock Cloud Above'}</span>
        <button type="button" class="button button-small button-primary" data-lf-verify="true">Verify 5 Gates &amp; Check LIVE Arming</button>
      </div>
    </div>

    <div class="lf-step-block">
      <div class="lf-step-head">
        <div>
          <span class="eyebrow">STEP 1 OF 3 · EXACT INTEGER-CENT BARBELL CUSTODY SPLIT</span>
          <h3>80% / 12% / 8% Real-Money Deposit Calculator</h3>
        </div>
        <span class="numeric lf-total-pill">Total Planned Capital: <strong>${esc(formatCentsUsd(split.totalCents))}</strong></span>
      </div>
      <div class="mf-btn-wrap lf-cap-controls" role="group" aria-label="Live funding capital presets">
        ${presetButtons}
        <label class="mf-inline-input">Custom USD $ <input type="number" min="300" max="10000000" step="100" value="${esc(capUsd)}" data-lf-custom-cap="true" aria-label="Custom live funding capital in USD"></label>
      </div>
      <div class="lf-split-grid">
        <article class="lf-venue-card is-reserve">
          <div class="lf-venue-head">
            <span class="eyebrow">80% REGULATED SAFE HARBOR</span>
            <strong>OANDA Live (80% Regulated Reserve)</strong>
          </div>
          <div class="lf-venue-amount numeric">${esc(formatCentsUsd(split.oandaCents))}</div>
          <p class="quiet-note">Server: <code>api-fxtrade.oanda.com</code> (<code>fxTrade Live</code> · <code>1:50</code> leverage) · Holds 80% treasury reserve &amp; quote-truth reference oracle.</p>
        </article>
        <article class="lf-venue-card is-primary">
          <div class="lf-venue-head">
            <span class="eyebrow">12% PRIMARY MT5 SLEEVE</span>
            <strong>Hugo&#39;s Way Live MT5 (12% Primary Sleeve, Hugosway-Real3)</strong>
          </div>
          <div class="lf-venue-amount numeric">${esc(formatCentsUsd(split.hugoswayCents))}</div>
          <p class="quiet-note">Server: <code>Hugosway-Real3</code> (<code>1:500</code> ECN live) · Primary 50ms fast-tick execution sleeve bounded to 12% custody exposure.</p>
        </article>
        <article class="lf-venue-card is-backup">
          <div class="lf-venue-head">
            <span class="eyebrow">8% SECONDARY MT5 FAILOVER</span>
            <strong>LHFX Live MT5 (8% Backup Sleeve, LHFXSA-Live)</strong>
          </div>
          <div class="lf-venue-amount numeric">${esc(formatCentsUsd(split.lhfxCents))}</div>
          <p class="quiet-note">Server: <code>LHFXSA-Live</code> (<code>1:500</code> STP/ECN live) · Automatic hot-standby MT5 sleeve bounded to 8% custody exposure.</p>
        </article>
      </div>
      <div class="lf-risk-strip numeric">
        <span>1% Safe Stop Risk: <strong>${esc(formatCentsUsd(split.risk1PctCents))}</strong></span>
        <span>2.5% Adaptive Risk: <strong>${esc(formatCentsUsd(split.risk25PctCents))}</strong></span>
        <span>5% Max Trend Ceiling: <strong>${esc(formatCentsUsd(split.risk5PctCents))}</strong></span>
        <span>20% Hard Drawdown Brake: <strong>${esc(formatCentsUsd(split.maxDrawdown20PctCents))}</strong></span>
      </div>
    </div>

    <div class="lf-step-block">
      <div class="lf-step-head">
        <div>
          <span class="eyebrow">STEP 2 OF 3 · NON-SECRET CLOUD READINESS AUDIT</span>
          <h3>Live 5-Gate Readiness Checklist</h3>
        </div>
        <span class="lf-gate-badge ${readiness.allGatesReady ? 'is-ready' : 'is-pending'}">${readiness.allGatesReady ? 'ALL 5 GATES READY' : `${esc(passedCount)} / 5 READY`}</span>
      </div>
      <ul class="lf-gate-list" aria-label="Five-gate live trading readiness checklist">${gateItems}</ul>
    </div>

    <div class="lf-step-block lf-arm-box">
      <div class="lf-step-head">
        <div>
          <span class="eyebrow">STEP 3 OF 3 · TWO-KEY OWNER AUTHORIZATION PREFLIGHT</span>
          <h3>Two-Key Real-Money Arming Switch</h3>
        </div>
        <span class="tag"><span class="state-rule" aria-hidden="true"></span>No secrets stored in browser</span>
      </div>
      <p class="panel-copy"><strong>Key 1 (Host PowerShell Staging):</strong> Run <code>D:\\MetaTrader5\\LIVE_FUNDING_STEP\\Stage_Live_Funding_To_Cloud.ps1</code> on your laptop to stage live broker credentials, owner Ed25519 live venue tickets, and <code>CAS_FOREX_EXECUTION_MODE=LIVE</code> onto the cloud server.</p>
      <div class="lf-arm-controls">
        <label class="sr-only" for="lf-arm-phrase-input">Key 2 confirmation phrase</label>
        <input id="lf-arm-phrase-input" class="lf-phrase-input" type="text" data-lf-phrase-input="true" autocomplete="off" spellcheck="false" value="${esc(lf.armPhraseInput)}" placeholder="Type ARM_LIVE_REAL_MONEY_TRADING to test 2-key readiness">
        <button type="button" class="button button-small button-primary" data-lf-verify="true">Verify 5 Gates &amp; Check LIVE Arming</button>
      </div>
      <div class="lf-verify-result ${verdictClass}" role="status" data-lf-verdict="${activeVerdict.canArmLive ? 'READY' : 'LOCKED'}">
        <strong>${esc(activeVerdict.headline)}</strong>
        <p>${esc(activeVerdict.detail)}</p>
      </div>
    </div>
  </section>`;
}
