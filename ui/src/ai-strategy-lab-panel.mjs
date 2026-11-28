// Strict-CSP, 60fps Update 49 Self-Learning AI Strategy Lab & Two-Way Field Notebook Panel.
// Zero innerHTML, zero outerHTML, zero inline style attributes, zero eval/Function,
// full XSS escaping, and 0.0px-jump in-place patching preserving owner note drafts.

export const AI_STRATEGY_LAB_SCHEMA = 'cas-forex.ai-strategy-lab/1';

const DECIMAL_RE = /^[+-]?[0-9]+(?:\.[0-9]+)?$/;
const PCT_STEPS = Object.freeze([
  0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50,
  55, 60, 65, 70, 75, 80, 85, 90, 95, 100,
]);

export function escapeStrategyLabHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

export function normalizeLabDecimal(value, fallback = '0.00') {
  const raw = String(value ?? '').trim();
  return DECIMAL_RE.test(raw) ? raw : fallback;
}

export function formatLabSignedUsd(value) {
  const clean = normalizeLabDecimal(value, '0.00');
  if (clean.startsWith('-')) return `-$${clean.slice(1)}`;
  if (clean === '0' || clean === '0.00' || clean === '+0.00') return '$0.00';
  return `+$${clean.replace(/^\+/, '')}`;
}

export function formatLabUsd(value) {
  const clean = normalizeLabDecimal(value, '0.00');
  if (clean.startsWith('-')) return `-$${clean.slice(1)}`;
  return `$${clean.replace(/^\+/, '')}`;
}

export function slPctBucketClass(pctVal) {
  const num = Number(normalizeLabDecimal(pctVal, '0'));
  if (!Number.isFinite(num) || num <= 0) return 'sl-pct-0';
  if (num >= 100) return 'sl-pct-100';
  const rounded = Math.round(num / 5) * 5;
  const clamped = PCT_STEPS.includes(rounded) ? rounded : 0;
  return `sl-pct-${clamped}`;
}

export const STATIC_AI_STRATEGY_LAB = Object.freeze({
  schema: AI_STRATEGY_LAB_SCHEMA,
  connected: false,
  observedAtUtc: null,
  observedAtPacific: 'Awaiting live stream',
  executionMode: 'DEMO',
  accountingBasis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
  sessionScope: 'READ_ONLY_PAIR',
  ownerControlsAllowed: false,
  governanceSafety: Object.freeze({
    valveController: 'tks_meta_valve_controller',
    valveParameters: 161,
    valveThreshold: '0.55',
    allIntentsValveGated: true,
    newsShockShieldActive: true,
    correlatedOffsetGuardThreshold: '0.45',
    singleBrokerEquitySizing: true,
    maxStopRiskPct: '1.00',
    maxDrawdownPct: '10.00',
    effectiveStopRiskCeilingPct: '5.00',
    auditEntryCount: 0,
  }),
  capitalAttribution: Object.freeze({
    startingBalanceUsd: '200000.00',
    currentOnlineEquityUsd: '200000.00',
    capitalStatus: 'AT_PRINCIPAL',
    vaultSweepsPausedForRecovery: true,
    totalStrategyNetPnlUsd: '0.00',
    totalStartingBalanceContributionUsd: '0.00',
    totalVaultedProfitContributionUsd: '0.00',
    unattributedLegacyPnlUsd: '0.00',
  }),
  counts: Object.freeze({
    activeCount: 0,
    shadowCount: 0,
    quarantinedCount: 0,
    fieldNotesTotal: 0,
    shadowTradesTotal: 0,
    vetoedProposalsTotal: 0,
  }),
  activeStrategies: Object.freeze([]),
  shadowStrategies: Object.freeze([]),
  quarantinedStrategies: Object.freeze([]),
  fieldNotes: Object.freeze([]),
});

export function normalizeAiStrategyLab(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return STATIC_AI_STRATEGY_LAB;
  }
  if (raw.schema === AI_STRATEGY_LAB_SCHEMA && Object.isFrozen(raw) && Array.isArray(raw.activeStrategies)) {
    return raw;
  }
  const gs = raw.governance_safety ?? raw.governanceSafety ?? {};
  const ca = raw.capital_attribution_summary ?? raw.capitalAttribution ?? {};
  const cnt = raw.counts ?? {};
  const activeRaw = Array.isArray(raw.active_strategies ?? raw.activeStrategies)
    ? (raw.active_strategies ?? raw.activeStrategies)
    : [];
  const shadowRaw = Array.isArray(raw.shadow_strategies ?? raw.shadowStrategies)
    ? (raw.shadow_strategies ?? raw.shadowStrategies)
    : [];
  const quarRaw = Array.isArray(raw.quarantined_strategies ?? raw.quarantinedStrategies)
    ? (raw.quarantined_strategies ?? raw.quarantinedStrategies)
    : [];
  const notesRaw = Array.isArray(raw.field_notes ?? raw.fieldNotes)
    ? (raw.field_notes ?? raw.fieldNotes)
    : [];

  return Object.freeze({
    schema: AI_STRATEGY_LAB_SCHEMA,
    connected: true,
    observedAtUtc: String(raw.observed_at_utc ?? raw.observedAtUtc ?? ''),
    observedAtPacific: String(raw.observed_at_pacific ?? raw.observedAtPacific ?? 'Live'),
    executionMode: raw.execution_mode === 'LIVE' || raw.executionMode === 'LIVE' ? 'LIVE' : 'DEMO',
    accountingBasis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
    sessionScope: String(raw.session_scope ?? raw.sessionScope ?? 'READ_ONLY_PAIR'),
    ownerControlsAllowed: Boolean(raw.owner_controls_allowed ?? raw.ownerControlsAllowed),
    governanceSafety: Object.freeze({
      valveController: 'tks_meta_valve_controller',
      valveParameters: Number(gs.valve_parameters ?? gs.valveParameters ?? 161),
      valveThreshold: normalizeLabDecimal(gs.valve_threshold ?? gs.valveThreshold, '0.55'),
      allIntentsValveGated: true,
      newsShockShieldActive: Boolean(gs.news_shock_shield_active ?? gs.newsShockShieldActive ?? true),
      correlatedOffsetGuardThreshold: normalizeLabDecimal(
        gs.correlated_offset_guard_threshold ?? gs.correlatedOffsetGuardThreshold,
        '0.45',
      ),
      singleBrokerEquitySizing: true,
      maxStopRiskPct: '1.00',
      maxDrawdownPct: '10.00',
      effectiveStopRiskCeilingPct: normalizeLabDecimal(
        gs.effective_stop_risk_ceiling_pct ?? gs.effectiveStopRiskCeilingPct,
        '5.00',
      ),
      auditEntryCount: Number(gs.audit_entry_count ?? gs.auditEntryCount ?? 0),
    }),
    capitalAttribution: Object.freeze({
      startingBalanceUsd: normalizeLabDecimal(ca.starting_balance_usd ?? ca.startingBalanceUsd, '200000.00'),
      currentOnlineEquityUsd: normalizeLabDecimal(ca.current_online_equity_usd ?? ca.currentOnlineEquityUsd, '200000.00'),
      capitalStatus: String(ca.capital_status ?? ca.capitalStatus ?? 'RECOVERY_MODE'),
      vaultSweepsPausedForRecovery: Boolean(ca.vault_sweeps_paused_for_recovery ?? ca.vaultSweepsPausedForRecovery ?? true),
      totalStrategyNetPnlUsd: normalizeLabDecimal(ca.total_strategy_net_pnl_usd ?? ca.totalStrategyNetPnlUsd, '0.00'),
      totalStartingBalanceContributionUsd: normalizeLabDecimal(
        ca.total_starting_balance_contribution_usd ?? ca.totalStartingBalanceContributionUsd,
        '0.00',
      ),
      totalVaultedProfitContributionUsd: normalizeLabDecimal(
        ca.total_vaulted_profit_contribution_usd ?? ca.totalVaultedProfitContributionUsd,
        '0.00',
      ),
      unattributedLegacyPnlUsd: normalizeLabDecimal(ca.unattributed_legacy_pnl_usd ?? ca.unattributedLegacyPnlUsd, '0.00'),
    }),
    counts: Object.freeze({
      activeCount: Number(cnt.active_count ?? cnt.activeCount ?? activeRaw.length),
      shadowCount: Number(cnt.shadow_count ?? cnt.shadowCount ?? shadowRaw.length),
      quarantinedCount: Number(cnt.quarantined_count ?? cnt.quarantinedCount ?? quarRaw.length),
      fieldNotesTotal: Number(cnt.field_notes_total ?? cnt.fieldNotesTotal ?? notesRaw.length),
      shadowTradesTotal: Number(cnt.shadow_trades_total ?? cnt.shadowTradesTotal ?? 0),
      vetoedProposalsTotal: Number(cnt.vetoed_proposals_total ?? cnt.vetoedProposalsTotal ?? 0),
    }),
    activeStrategies: Object.freeze(activeRaw.map((item) => Object.freeze({
      strategyId: String(item.strategy_id ?? item.strategyId ?? ''),
      displayName: String(item.display_name ?? item.displayName ?? ''),
      origin: String(item.origin ?? 'CORE_BASELINE'),
      archetype: String(item.archetype ?? 'TREND_FOLLOW'),
      blueprintSummary: String(item.blueprint_summary ?? item.blueprintSummary ?? ''),
      riskWeightMultiplier: normalizeLabDecimal(item.risk_profile?.risk_weight_multiplier ?? item.riskWeightMultiplier, '1.00'),
      maxStopRiskPct: normalizeLabDecimal(item.risk_profile?.max_stop_risk_pct ?? item.maxStopRiskPct, '5.00'),
      closedTrades: Number(item.metrics?.closed_trades ?? item.closedTrades ?? 0),
      winRatePct: normalizeLabDecimal(item.metrics?.win_rate_pct ?? item.winRatePct, '0.00'),
      rExpectancy: normalizeLabDecimal(item.metrics?.r_expectancy ?? item.rExpectancy, '0.0000'),
      profitFactor: normalizeLabDecimal(item.metrics?.profit_factor ?? item.profitFactor, '1.00'),
      cusumDrift: normalizeLabDecimal(item.metrics?.cusum_drift ?? item.cusumDrift, '0.0000'),
      netPnlUsd: normalizeLabDecimal(item.attribution?.net_pnl_usd ?? item.netPnlUsd, '0.00'),
      startingBalanceContribUsd: normalizeLabDecimal(
        item.attribution?.starting_balance_contribution_usd ?? item.startingBalanceContribUsd,
        '0.00',
      ),
      vaultedProfitContribUsd: normalizeLabDecimal(
        item.attribution?.vaulted_profit_contribution_usd ?? item.vaultedProfitContribUsd,
        '0.00',
      ),
      openPositionsCount: Number(item.attribution?.open_positions_count ?? item.openPositionsCount ?? 0),
    }))),
    shadowStrategies: Object.freeze(shadowRaw.map((item) => Object.freeze({
      strategyId: String(item.strategy_id ?? item.strategyId ?? ''),
      displayName: String(item.display_name ?? item.displayName ?? ''),
      origin: String(item.origin ?? 'AI_EVOLVED'),
      hypothesis: String(item.hypothesis_plain_english ?? item.hypothesis ?? ''),
      shadowTrades: Number(item.shadow_metrics?.shadow_trades ?? item.shadowTrades ?? 0),
      shadowWinRatePct: normalizeLabDecimal(item.shadow_metrics?.shadow_win_rate_pct ?? item.shadowWinRatePct, '0.00'),
      shadowRExpectancy: normalizeLabDecimal(item.shadow_metrics?.shadow_r_expectancy ?? item.shadowRExpectancy, '0.0000'),
      shadowProfitFactor: normalizeLabDecimal(item.shadow_metrics?.shadow_profit_factor ?? item.shadowProfitFactor, '1.00'),
      shadowNetPnlUsd: normalizeLabDecimal(item.shadow_metrics?.shadow_net_pnl_usd ?? item.shadowNetPnlUsd, '0.00'),
      progressPct: normalizeLabDecimal(item.graduation?.progress_pct ?? item.progressPct, '0.00'),
      progressBucket: Number(item.graduation?.progress_bucket ?? item.progressBucket ?? 0),
      requiredTrades: Number(item.graduation?.required_trades ?? item.requiredTrades ?? 30),
      blockingReason: item.graduation?.blocking_reason ?? item.blockingReason ?? null,
    }))),
    quarantinedStrategies: Object.freeze(quarRaw.map((item) => Object.freeze({
      strategyId: String(item.strategy_id ?? item.strategyId ?? ''),
      displayName: String(item.display_name ?? item.displayName ?? ''),
      status: String(item.status ?? 'QUARANTINED'),
      retiredBy: String(item.retired_by ?? item.retiredBy ?? 'AI_SELF_AUDIT'),
      reasonPlainEnglish: String(item.retirement_reason_plain_english ?? item.reasonPlainEnglish ?? ''),
      closedTrades: Number(item.final_metrics?.closed_trades ?? item.closedTrades ?? 0),
      netPnlUsd: normalizeLabDecimal(item.final_metrics?.net_pnl_usd ?? item.netPnlUsd, '0.00'),
    }))),
    fieldNotes: Object.freeze(notesRaw.map((n) => Object.freeze({
      noteId: String(n.note_id ?? n.noteId ?? ''),
      seqNo: Number(n.seq_no ?? n.seqNo ?? 0),
      observedAtPacific: String(n.observed_at_pacific ?? n.observedAtPacific ?? ''),
      authorRole: String(n.author_role ?? n.authorRole ?? 'AI_STRATEGIST'),
      noteCategory: String(n.note_category ?? n.noteCategory ?? 'TRADE_LESSON'),
      headline: String(n.headline ?? ''),
      bodyPlainEnglish: String(n.body_plain_english ?? n.bodyPlainEnglish ?? ''),
      relatedSymbol: n.related_symbol ?? n.relatedSymbol ?? null,
      impactPnlUsd: n.impact_pnl_usd ?? n.impactPnlUsd ?? null,
      pinnedByOwner: Boolean(n.pinned_by_owner ?? n.pinnedByOwner),
      acknowledgedByAi: Boolean(n.acknowledged_by_ai ?? n.acknowledgedByAi),
    }))),
  });
}

function renderLabZonesInnerHtml(model) {
  const e = escapeStrategyLabHtml;
  const ca = model.capitalAttribution;
  const gs = model.governanceSafety;
  const canControl = Boolean(model.ownerControlsAllowed);

  const activeHtml = model.activeStrategies.length
    ? model.activeStrategies.map((s) => `<article class="sl-card sl-card-active" data-strategy-id="${e(s.strategyId)}">
        <div class="sl-card-head">
          <strong>${e(s.displayName)}</strong>
          <span class="sl-badge sl-badge-active">${e(s.origin === 'AI_EVOLVED' ? 'AI EVOLVED' : 'CORE')} · ${e(s.riskWeightMultiplier)}x (${e(s.maxStopRiskPct)}%)</span>
        </div>
        <p class="sl-blueprint">${e(s.blueprintSummary)}</p>
        <div class="sl-metrics-row">
          <span>Trades: <b>${e(s.closedTrades)}</b> (${e(s.winRatePct)}%)</span>
          <span>Exp: <b>${e(s.rExpectancy)}R</b></span>
          <span>PF: <b>${e(s.profitFactor)}</b></span>
          <span>Drift: <b>${e(s.cusumDrift)}</b></span>
        </div>
        <div class="sl-attrib-row">
          <span>Net: <b>${e(formatLabSignedUsd(s.netPnlUsd))}</b></span>
          <span>To Balance: <b>${e(formatLabSignedUsd(s.startingBalanceContribUsd))}</b></span>
          <span>To Vault: <b>${e(formatLabSignedUsd(s.vaultedProfitContribUsd))}</b></span>
          <button type="button" class="button-secondary sl-btn-sm" data-sl-action="QUARANTINE_STRATEGY" data-sl-strategy-id="${e(s.strategyId)}" ${canControl ? '' : 'disabled'}>Retire to Shadow</button>
        </div>
      </article>`).join('')
    : '<p class="quiet-note">All strategies currently in Shadow Incubator — waiting for verified positive edge.</p>';

  const shadowHtml = model.shadowStrategies.length
    ? model.shadowStrategies.map((s) => `<article class="sl-card sl-card-shadow" data-shadow-id="${e(s.strategyId)}">
        <div class="sl-card-head">
          <strong>${e(s.displayName)}</strong>
          <span class="sl-badge sl-badge-shadow">SHADOW INCUBATING · ${e(s.shadowTrades)}/${e(s.requiredTrades)}</span>
        </div>
        <p class="sl-blueprint">${e(s.hypothesis)}</p>
        <div class="sl-metrics-row">
          <span>Shadow Net: <b>${e(formatLabSignedUsd(s.shadowNetPnlUsd))}</b></span>
          <span>WR: <b>${e(s.shadowWinRatePct)}%</b></span>
          <span>Exp: <b>${e(s.shadowRExpectancy)}R</b></span>
          <span>PF: <b>${e(s.shadowProfitFactor)}</b></span>
        </div>
        <progress class="sl-grad-progress ${e(slPctBucketClass(s.progressPct))}" max="100" value="${e(s.progressBucket)}">${e(s.progressPct)}%</progress>
        ${s.blockingReason ? `<p class="quiet-note sl-gate-note">Gate: ${e(s.blockingReason)}</p>` : '<p class="quiet-note sl-gate-note">Ready for active promotion!</p>'}
      </article>`).join('')
    : '<p class="quiet-note">No shadow strategies incubating right now.</p>';

  const quarHtml = model.quarantinedStrategies.length
    ? model.quarantinedStrategies.map((s) => `<article class="sl-card sl-card-quar">
        <div class="sl-card-head">
          <strong>${e(s.displayName)}</strong>
          <span class="sl-badge sl-badge-quar">${e(s.status)} · ${e(s.retiredBy)}</span>
        </div>
        <p class="sl-blueprint">${e(s.reasonPlainEnglish)}</p>
        <div class="sl-attrib-row">
          <span>Closed: <b>${e(s.closedTrades)}</b></span>
          <span>Final Net: <b>${e(formatLabSignedUsd(s.netPnlUsd))}</b></span>
          <button type="button" class="button-secondary sl-btn-sm" data-sl-action="RESUME_TO_SHADOW" data-sl-strategy-id="${e(s.strategyId)}" ${canControl ? '' : 'disabled'}>Re-Test in Shadow</button>
        </div>
      </article>`).join('')
    : '<p class="quiet-note">0 quarantined or retired strategies — active lineup healthy.</p>';

  const notesHtml = model.fieldNotes.length
    ? model.fieldNotes.map((n) => `<article class="sl-note-item ${n.authorRole === 'OWNER_WAKIL' ? 'sl-note-owner' : 'sl-note-ai'}">
        <div class="sl-note-meta">
          <span class="sl-badge">${e(n.authorRole === 'OWNER_WAKIL' ? 'WAKIL DIRECTIVE' : 'AI NOTE')}</span>
          <span>#${e(n.seqNo)} · ${e(n.observedAtPacific)}</span>
          ${n.relatedSymbol ? `<span class="sl-sym-chip">${e(n.relatedSymbol)}</span>` : ''}
          ${n.impactPnlUsd ? `<b>${e(formatLabSignedUsd(n.impactPnlUsd))}</b>` : ''}
          ${n.pinnedByOwner ? '<span class="sl-pin-chip">PINNED FOR AI</span>' : ''}
          ${n.authorRole === 'OWNER_WAKIL' ? `<span class="quiet-note">${n.acknowledgedByAi ? 'Read by AI' : 'Queued for next cycle'}</span>` : ''}
        </div>
        <strong>${e(n.headline)}</strong>
        <p>${e(n.bodyPlainEnglish)}</p>
      </article>`).join('')
    : '<p class="quiet-note">AI Field Notebook ready — lessons appear automatically on every market shift and closed trade.</p>';

  return {
    summaryStripHtml: `<div class="sl-summary-strip" data-sl-zone="summary">
      <div class="sl-kpi"><span>Starting Balance Goal</span><strong>${e(formatLabUsd(ca.startingBalanceUsd))}</strong><small>Online: ${e(formatLabUsd(ca.currentOnlineEquityUsd))} (${e(ca.capitalStatus)})</small></div>
      <div class="sl-kpi"><span>Added to Starting Balance</span><strong>${e(formatLabSignedUsd(ca.totalStartingBalanceContributionUsd))}</strong><small>Active Strategies: ${e(model.counts.activeCount)}</small></div>
      <div class="sl-kpi"><span>Added to Vaulted Profits</span><strong>${e(formatLabSignedUsd(ca.totalVaultedProfitContributionUsd))}</strong><small>${ca.vaultSweepsPausedForRecovery ? '100% rebuilding principal' : 'Vault sweep active'}</small></div>
      <div class="sl-kpi"><span>Valve &amp; Safety Gate</span><strong>${e(gs.valveParameters)}p &ge; ${e(gs.valveThreshold)}</strong><small>Risk Cap: ${e(gs.effectiveStopRiskCeilingPct)}% · Notes: ${e(model.counts.fieldNotesTotal)}</small></div>
    </div>`,
    activeHtml,
    shadowHtml,
    quarHtml,
    notesHtml,
  };
}

export function renderAiStrategyLabPanel(rawModel) {
  const model = normalizeAiStrategyLab(rawModel);
  const e = escapeStrategyLabHtml;
  const zones = renderLabZonesInnerHtml(model);
  const canControl = Boolean(model.ownerControlsAllowed);

  return `<section class="panel sl-lab-panel" data-ai-strategy-lab="true" aria-label="Self-Learning AI Strategy Lab and Field Notebook">
    <div class="panel-heading">
      <div>
        <p class="eyebrow">UPDATE 49 · SELF-LEARNING STRATEGY ENGINE &amp; TWO-WAY FIELD NOTEBOOK</p>
        <h3>AI Strategy Lab — Keep Winners, Retire Losers &amp; Design Shadow Challengers</h3>
      </div>
      <span class="tag">${e(model.executionMode)} · ${e(model.counts.activeCount)} Active · ${e(model.counts.shadowCount)} Shadow · ${e(model.counts.quarantinedCount)} Retired</span>
    </div>
    <div data-sl-slot="summary">${zones.summaryStripHtml}</div>
    <div class="sl-grid">
      <div class="sl-col">
        <h4>Active Winning Lineup</h4>
        <div class="sl-scroll-box" data-sl-slot="active">${zones.activeHtml}</div>
      </div>
      <div class="sl-col">
        <h4>Shadow Practice Incubator (Live Tick Test)</h4>
        <div class="sl-scroll-box" data-sl-slot="shadow">${zones.shadowHtml}</div>
      </div>
      <div class="sl-col">
        <h4>Quarantined &amp; Retired Archive</h4>
        <div class="sl-scroll-box" data-sl-slot="quarantined">${zones.quarHtml}</div>
      </div>
    </div>
    <div class="sl-notebook-wrap">
      <div class="sl-notebook-col">
        <h4>Live AI &amp; Owner Field Notes (Newest First)</h4>
        <div class="sl-scroll-box sl-notes-box" data-sl-slot="notes">${zones.notesHtml}</div>
      </div>
      <div class="sl-form-col" data-sl-slot="owner-form">
        <h4>Leave a Note / Directive for the AI</h4>
        <p class="quiet-note">Pinned notes are injected directly into the AI prompt on every trade evaluation.</p>
        <label class="sl-field-label">Short Headline
          <input type="text" maxlength="120" data-sl-input="headline" placeholder="e.g. Favor US30 &amp; FX pullbacks in London" ${canControl ? '' : 'disabled'} />
        </label>
        <label class="sl-field-label">Plain-English Note for AI Memory
          <textarea rows="3" maxlength="500" data-sl-input="body" placeholder="Write guidance or market observations for the AI to remember..." ${canControl ? '' : 'disabled'}></textarea>
        </label>
        <div class="sl-form-actions">
          <button type="button" class="button-primary" data-sl-action="LEAVE_OWNER_NOTE" ${canControl ? '' : 'disabled'}>Pin Note to AI Memory</button>
        </div>
      </div>
    </div>
  </section>`;
}

export function patchAiStrategyLabPanelInPlace(panelEl, rawModel) {
  if (!panelEl || typeof panelEl.querySelector !== 'function') return;
  const doc = panelEl.ownerDocument;
  if (!doc || typeof DOMParser === 'undefined') return;
  const model = normalizeAiStrategyLab(rawModel);
  const zones = renderLabZonesInnerHtml(model);
  const parser = new DOMParser();

  const slotMap = [
    ['summary', zones.summaryStripHtml],
    ['active', zones.activeHtml],
    ['shadow', zones.shadowHtml],
    ['quarantined', zones.quarHtml],
    ['notes', zones.notesHtml],
  ];
  for (const [slotName, htmlFragment] of slotMap) {
    const slotNode = panelEl.querySelector(`[data-sl-slot="${slotName}"]`);
    if (!slotNode) continue;
    const parsed = parser.parseFromString(`<body>${htmlFragment}</body>`, 'text/html');
    slotNode.replaceChildren(...Array.from(parsed.body.childNodes).map((n) => doc.importNode(n, true)));
  }

  // Toggle disabled state on owner form controls WITHOUT clearing Wakil's in-progress draft text!
  const canControl = Boolean(model.ownerControlsAllowed);
  for (const ctrl of panelEl.querySelectorAll('[data-sl-slot="owner-form"] input, [data-sl-slot="owner-form"] textarea, [data-sl-slot="owner-form"] button')) {
    ctrl.disabled = !canControl;
  }
}
