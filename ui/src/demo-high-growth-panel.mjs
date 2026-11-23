// Strict-CSP, zero-jump DEMO-Only High-Growth Practice Profile Panel (PR #43).
// Zero inline style attributes, zero eval/Function, full XSS escaping, and 0.0px in-place patching.

export const DEMO_HIGH_GROWTH_SCHEMA = 'cas-forex.demo-high-growth-profile/1';

const DECIMAL_RE = /^[+-]?[0-9]+(?:\.[0-9]+)?$/;

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

function normalizeDecimal(value, fallback) {
  const raw = String(value ?? '').trim();
  return DECIMAL_RE.test(raw) ? raw : fallback;
}

export const STATIC_DEMO_HIGH_GROWTH = Object.freeze({
  schema: DEMO_HIGH_GROWTH_SCHEMA,
  connected: false,
  enabled: false,
  demoOnlyLocked: true,
  realMoneyAtRiskUsd: '0.00',
  targetRiskPct: '10.00',
  maxRiskPct: '12.00',
  maxDrawdownPct: '0.30',
  maxDrawdownDisplayPct: '30.00',
  compounding100Pct: true,
  sweepRatio: '0.00',
  letWinnersRun: true,
  pyramidingEnabled: true,
  postLossCooldownSeconds: 900,
  blockUsCloseChop: true,
  beScale: '1.50',
  trailScale: '1.75',
  tpScale: '1.50',
  valveGateEnforced: true,
  liveConstitutionalCeilingsIntact: true,
  executionMode: 'DEMO',
  liveModeBlocked: false,
  ownerControlsAllowed: false,
  sessionScope: 'UNBOUND',
  updatedAt: null,
});

export function normalizeDemoHighGrowth(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return STATIC_DEMO_HIGH_GROWTH;
  }
  const execRaw = String(raw.execution_mode ?? raw.executionMode ?? 'DEMO').trim().toUpperCase() || 'DEMO';
  const liveBlocked = Boolean(raw.live_mode_blocked ?? raw.liveModeBlocked) || execRaw !== 'DEMO';
  const enabled = liveBlocked ? false : Boolean(raw.enabled);
  const ownerAllowed = !liveBlocked && Boolean(raw.owner_controls_allowed ?? raw.ownerControlsAllowed);
  const cdRaw = raw.post_loss_cooldown_seconds ?? raw.postLossCooldownSeconds ?? 900;
  const cdSec = Number.isInteger(cdRaw) && cdRaw >= 0 && cdRaw <= 3600 ? cdRaw : 900;
  const updatedAt = typeof (raw.updated_at ?? raw.updatedAt) === 'string'
    ? String(raw.updated_at ?? raw.updatedAt)
    : null;
  const connected = typeof raw.connected === 'boolean'
    ? raw.connected
    : (raw.schema === DEMO_HIGH_GROWTH_SCHEMA && updatedAt !== null);

  return Object.freeze({
    schema: DEMO_HIGH_GROWTH_SCHEMA,
    connected,
    enabled,
    demoOnlyLocked: true,
    realMoneyAtRiskUsd: '0.00',
    targetRiskPct: normalizeDecimal(raw.target_risk_pct ?? raw.targetRiskPct, '10.00'),
    maxRiskPct: normalizeDecimal(raw.max_risk_pct ?? raw.maxRiskPct, '12.00'),
    maxDrawdownPct: normalizeDecimal(raw.max_drawdown_pct ?? raw.maxDrawdownPct, '0.30'),
    maxDrawdownDisplayPct: normalizeDecimal(raw.max_drawdown_display_pct ?? raw.maxDrawdownDisplayPct, '30.00'),
    compounding100Pct: raw.compounding_100pct ?? raw.compounding100Pct ?? true ? true : false,
    sweepRatio: normalizeDecimal(raw.sweep_ratio ?? raw.sweepRatio, enabled ? '0.00' : '0.50'),
    letWinnersRun: (raw.let_winners_run ?? raw.letWinnersRun ?? true) !== false,
    pyramidingEnabled: (raw.pyramiding_enabled ?? raw.pyramidingEnabled ?? true) !== false,
    postLossCooldownSeconds: cdSec,
    blockUsCloseChop: (raw.block_us_close_chop ?? raw.blockUsCloseChop ?? true) !== false,
    beScale: normalizeDecimal(raw.be_scale ?? raw.beScale, '1.50'),
    trailScale: normalizeDecimal(raw.trail_scale ?? raw.trailScale, '1.75'),
    tpScale: normalizeDecimal(raw.tp_scale ?? raw.tpScale, '1.50'),
    valveGateEnforced: true,
    liveConstitutionalCeilingsIntact: true,
    executionMode: execRaw,
    liveModeBlocked: liveBlocked,
    ownerControlsAllowed: ownerAllowed,
    sessionScope: String(raw.session_scope ?? raw.sessionScope ?? 'UNBOUND').slice(0, 48),
    updatedAt,
  });
}

export function resolveCockpitDemoHighGrowth(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    return STATIC_DEMO_HIGH_GROWTH;
  }
  const raw = state.demoHighGrowth ?? state.demo_high_growth_profile ?? state.aiTrader?.demo_high_growth_profile ?? null;
  const base = raw ? normalizeDemoHighGrowth(raw) : STATIC_DEMO_HIGH_GROWTH;
  const routingExec = String(state.brokerRouting?.execution_mode ?? base.executionMode ?? 'DEMO').trim().toUpperCase() || 'DEMO';
  const liveArmed = Boolean(state.brokerRouting?.live_trading_armed) || routingExec !== 'DEMO';
  const liveBlocked = base.liveModeBlocked || liveArmed;
  const connected = typeof state.liveStreamConnected === 'boolean' ? state.liveStreamConnected : base.connected;
  const ownerAllowed = typeof state.ownerControlsAllowed === 'boolean'
    ? (state.ownerControlsAllowed && !liveBlocked && connected)
    : (base.ownerControlsAllowed && !liveBlocked);
  return Object.freeze({
    ...base,
    connected,
    enabled: liveBlocked ? false : base.enabled,
    executionMode: liveArmed ? (routingExec === 'DEMO' ? 'LIVE' : routingExec) : 'DEMO',
    liveModeBlocked: liveBlocked,
    ownerControlsAllowed: ownerAllowed,
  });
}

function dhgDerivedText(profile) {
  const p = profile ?? STATIC_DEMO_HIGH_GROWTH;
  const mins = Math.round(p.postLossCooldownSeconds / 60);
  const canToggle = Boolean(p.connected && p.ownerControlsAllowed && !p.liveModeBlocked);
  return {
    safetyBadge: p.liveModeBlocked
      ? 'LIVE MODE BLOCKED (1.00% / 10.00% LOCKED)'
      : 'DEMO ONLY · $0.00 REAL MONEY',
    statusBadge: p.liveModeBlocked
      ? 'FORBIDDEN IN LIVE MODE'
      : (p.enabled
          ? `ACTIVE · ${p.targetRiskPct}% RISK / ${p.maxDrawdownDisplayPct}% DD / 100% COMP`
          : 'OFF · 1.00% / 10.00% STANDARD'),
    btnLabel: p.liveModeBlocked
      ? 'Blocked in LIVE Mode'
      : (p.enabled
          ? 'Disable High-Growth Mode (Restore 1% / 10%)'
          : `Enable ${p.targetRiskPct}% Risk · ${p.maxDrawdownDisplayPct}% DD · 100% Compound`),
    canToggle,
    riskText: p.enabled ? `${p.targetRiskPct}% / ${p.maxRiskPct}%` : '1.00% Standard',
    ddText: p.enabled ? `${p.maxDrawdownDisplayPct}% DD Freeze` : '10.00% DD Freeze',
    compText: p.enabled && p.compounding100Pct ? '100.00% Compound (0% Sweep)' : '50% Vault / 50% Comp',
    cooldownText: `${mins}m Post-Loss Cooldown`,
    cooldownSubText: `${p.postLossCooldownSeconds}s anti-whipsaw${p.blockUsCloseChop ? ' · US Close Guard' : ''}`,
    protectionText: p.blockUsCloseChop ? 'ATR Noise Floor + US Close Chop Guard' : 'ATR Noise Floor (2.5x M1)',
    protectionSubText: `${p.beScale}x BE · ${p.trailScale}x Trail · ${p.tpScale}x TP`,
    valveText: 'Valve Gate >= 0.55',
    valveSubText: 'LIVE 1.00% / 10.00% Locked',
  };
}

export function renderDemoHighGrowthPanel(profile = STATIC_DEMO_HIGH_GROWTH) {
  const p = normalizeDemoHighGrowth(profile);
  const t = dhgDerivedText(p);
  const safetyCls = p.liveModeBlocked ? 'dhg-badge dhg-badge-danger' : 'dhg-badge dhg-badge-safe';
  const statusCls = p.liveModeBlocked
    ? 'dhg-badge dhg-badge-danger'
    : (p.enabled ? 'dhg-badge dhg-badge-active' : 'dhg-badge dhg-badge-muted');
  const toggleCls = `button button-small ${p.enabled ? 'button-secondary' : 'button-primary'} dhg-toggle-btn`;
  return `<section class="panel dhg-panel" data-demo-high-growth="true" aria-label="DEMO High-Growth Practice Profile">
    <div class="dhg-header-row">
      <div>
        <p class="eyebrow">OPT-IN DEMO PRACTICE MODE · CONSTITUTIONAL LIVE WALLS UNCHANGED</p>
        <h3>DEMO High-Growth Practice Mode</h3>
      </div>
      <div class="dhg-badge-strip">
        <span class="${safetyCls}" data-dhg-safety-badge="true">${escapeHtml(t.safetyBadge)}</span>
        <span class="${statusCls}" data-dhg-status-badge="true">${escapeHtml(t.statusBadge)}</span>
        <button type="button" class="${toggleCls}" data-dhg-action="TOGGLE_ENABLED" ${t.canToggle ? '' : 'disabled'}>${escapeHtml(t.btnLabel)}</button>
      </div>
    </div>
    <div class="dhg-grid">
      <div class="dhg-chip"><span class="dhg-label">Risk / Trade · Trend Peak</span><strong class="dhg-val" data-dhg-risk="true">${escapeHtml(t.riskText)}</strong><span class="dhg-sub">Unblocks $300 &amp; $1,000 tiers</span></div>
      <div class="dhg-chip"><span class="dhg-label">Max Drawdown Freeze</span><strong class="dhg-val" data-dhg-dd="true">${escapeHtml(t.ddText)}</strong><span class="dhg-sub">Daily goal 25% · Brake 20%</span></div>
      <div class="dhg-chip"><span class="dhg-label">Compounding Mode</span><strong class="dhg-val" data-dhg-compound="true">${escapeHtml(t.compText)}</strong><span class="dhg-sub">Main + 5 Tiers + Option B</span></div>
      <div class="dhg-chip"><span class="dhg-label">Anti-Whipsaw Guard</span><strong class="dhg-val" data-dhg-cooldown="true">${escapeHtml(t.cooldownText)}</strong><span class="dhg-sub" data-dhg-cooldown-sub="true">${escapeHtml(t.cooldownSubText)}</span></div>
      <div class="dhg-chip"><span class="dhg-label">Winner Protection</span><strong class="dhg-val" data-dhg-protection="true">${escapeHtml(t.protectionText)}</strong><span class="dhg-sub" data-dhg-protection-sub="true">${escapeHtml(t.protectionSubText)}</span></div>
      <div class="dhg-chip"><span class="dhg-label">Safety Gate &amp; LIVE Lock</span><strong class="dhg-val" data-dhg-valve="true">${escapeHtml(t.valveText)}</strong><span class="dhg-sub">${escapeHtml(t.valveSubText)}</span></div>
    </div>
  </section>`;
}

export function patchDemoHighGrowthPanelInPlace(panelEl, profile) {
  if (!panelEl || typeof panelEl.querySelector !== 'function') return;
  const p = normalizeDemoHighGrowth(profile);
  const t = dhgDerivedText(p);

  const safetyEl = panelEl.querySelector('[data-dhg-safety-badge="true"]');
  if (safetyEl) {
    safetyEl.textContent = t.safetyBadge;
    safetyEl.classList?.toggle?.('dhg-badge-danger', Boolean(p.liveModeBlocked));
    safetyEl.classList?.toggle?.('dhg-badge-safe', !p.liveModeBlocked);
  }
  const statusEl = panelEl.querySelector('[data-dhg-status-badge="true"]');
  if (statusEl) {
    statusEl.textContent = t.statusBadge;
    statusEl.classList?.toggle?.('dhg-badge-danger', Boolean(p.liveModeBlocked));
    statusEl.classList?.toggle?.('dhg-badge-active', !p.liveModeBlocked && p.enabled);
    statusEl.classList?.toggle?.('dhg-badge-muted', !p.liveModeBlocked && !p.enabled);
  }
  const btnEl = panelEl.querySelector('[data-dhg-action="TOGGLE_ENABLED"]');
  if (btnEl) {
    btnEl.textContent = t.btnLabel;
    btnEl.disabled = !t.canToggle;
    btnEl.classList?.toggle?.('button-primary', !p.enabled);
    btnEl.classList?.toggle?.('button-secondary', Boolean(p.enabled));
  }
  const pairs = [
    ['[data-dhg-risk="true"]', t.riskText],
    ['[data-dhg-dd="true"]', t.ddText],
    ['[data-dhg-compound="true"]', t.compText],
    ['[data-dhg-cooldown="true"]', t.cooldownText],
    ['[data-dhg-cooldown-sub="true"]', t.cooldownSubText],
    ['[data-dhg-protection="true"]', t.protectionText],
    ['[data-dhg-protection-sub="true"]', t.protectionSubText],
    ['[data-dhg-valve="true"]', t.valveText],
  ];
  for (const [sel, text] of pairs) {
    const el = panelEl.querySelector(sel);
    if (el) el.textContent = text;
  }
}
