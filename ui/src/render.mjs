import { CONTROL_COPY, moneyLabel, formatDecimal, positionSummary, pendingEffects, commandEffect, decisionIdentity, reviewRecords, closeReview } from './model.mjs';
import { envelopeRecords, canonicalJSON } from './decision-read.mjs';
import { displayFreshness } from './freshness.mjs';
import { renderMarketChartSection } from './chart.mjs';
import { STATIC_BROKER_ROUTING } from './broker-routing.mjs';
import {
  renderAiOverseerPanel,
  renderAiModelCatalogPanel,
  renderBankedProfitsHeroBanner,
  resolveRealizedPnlProvenance,
} from './ai-overseer.mjs';
import { renderMoneyFlowSection } from './money-flow.mjs';
import { renderLiveFundingPanel } from './live-funding.mjs';
import { renderLiveFeedStrip, renderTacticalValveHud, renderMarketRadarTable, computeValveHudModel } from './tactical-hud.mjs';
import { isOwnerControlSession, renderQrPairingDrawer } from './qr-pairing.mjs';
import {
  renderAiTopSwitcherBar,
  renderEquityAndAnalyticsSection,
  renderParallelTiersSection,
} from './analytics.mjs';
import {
  renderMasterAggressionDial,
  resolveCockpitAggressionDial,
} from './aggression-dial.mjs';
import {
  COMPOUNDING_PANEL_SCHEMA,
  STATIC_COMPOUNDING_PANEL,
  normalizeCompoundingPanel,
  renderCompoundingAndHouseMoneyPanel,
} from './compounding-panel.mjs';
import {
  STATIC_OPTION_B_DEMO,
  normalizeOptionBDemo,
  renderOptionBDemoPanel,
} from './option-b-demo-panel.mjs';
import {
  STATIC_DEMO_HIGH_GROWTH,
  normalizeDemoHighGrowth,
  renderDemoHighGrowthPanel,
  resolveCockpitDemoHighGrowth,
} from './demo-high-growth-panel.mjs';

export function resolveCockpitOptionBDemo(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    return STATIC_OPTION_B_DEMO;
  }
  const raw = state.optionBDemo ?? state.option_b_demo ?? null;
  return raw ? normalizeOptionBDemo(raw) : STATIC_OPTION_B_DEMO;
}

export function resolveCockpitCompounding(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    return STATIC_COMPOUNDING_PANEL;
  }
  if (
    state.schema === COMPOUNDING_PANEL_SCHEMA
    && !('route' in state)
    && !('projection' in state)
  ) {
    return normalizeCompoundingPanel(state);
  }
  const rawCompounding = state.compounding
    ?? state.compoundingPanel
    ?? state.compoundingController
    ?? state.compounding_controller
    ?? state.aiTrader?.compounding
    ?? state.aiTrader?.compounding_controller
    ?? STATIC_COMPOUNDING_PANEL;
  const base = normalizeCompoundingPanel(rawCompounding);

  const roleCandidates = [
    state.sessionScope,
    state.session_scope,
    state.sessionRole,
    state.session_role,
    state.deviceRole,
    state.device_role,
    state.aiTrader?.sessionScope,
    state.aiTrader?.sessionRole,
    state.aiTrader?.deviceRole,
  ];
  const roleDenied = roleCandidates.some(
    (r) => typeof r === 'string' && r.trim().toUpperCase() === 'DEVICE_READ_AND_EXPLAINER',
  );

  let flagDenied = !base.ownerControlsAllowed;
  if (state.liveStreamConnected === true) {
    if (!isOwnerControlSession(state)) {
      flagDenied = true;
    }
    if (state.ownerControlsAllowed !== undefined && state.ownerControlsAllowed !== true) {
      flagDenied = true;
    }
  } else if (!('liveStreamConnected' in state) && state.ownerControlsAllowed !== undefined) {
    if (state.ownerControlsAllowed !== true) {
      flagDenied = true;
    }
  }
  if (state.owner_controls_allowed !== undefined && state.owner_controls_allowed !== true) {
    flagDenied = true;
  }

  const fallbackShield = rawCompounding?.newsShield
    ?? rawCompounding?.news_shield
    ?? state.newsShield
    ?? state.news_shield
    ?? state.phase8Bridge?.news_shield
    ?? state.aiTrader?.newsShield
    ?? state.aiTrader?.news_shield
    ?? null;

  const effectiveAllowed = !roleDenied && !flagDenied;
  if (base.ownerControlsAllowed === effectiveAllowed && !fallbackShield) {
    return base;
  }
  return normalizeCompoundingPanel({
    ...base,
    ...(fallbackShield ? { newsShield: fallbackShield } : {}),
    ownerControlsAllowed: effectiveAllowed,
  });
}

export function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

export function replaceSafeHTML(target, markup) {
  const doc = new DOMParser().parseFromString(String(markup), 'text/html');
  target.replaceChildren(...doc.body.childNodes);
}
const e = escapeHTML;
const text = (value) => value === null || value === undefined ? 'Unknown' : String(value);
const tag = (label, warning = false) => `<span class="tag${warning ? ' tag-warning' : ''}"><span class="state-rule" aria-hidden="true"></span>${e(label)}</span>`;
const meta = (label, value) => `<div class="meta-row"><dt>${e(label)}</dt><dd>${e(text(value))}</dd></div>`;
const empty = (title, detail, icon = '—') => `<div class="empty-state"><span class="empty-icon" aria-hidden="true">${e(icon)}</span><h3>${e(title)}</h3><p>${e(detail)}</p></div>`;
const button = (label, attributes = '', className = '') => `<button type="button" class="button ${className}" ${attributes}>${e(label)}</button>`;
const sectionNumber = (number) => `<span class="section-number" aria-hidden="true">${e(number)}</span>`;
const heading = (eyebrow, title, aside = '', number = '') => `<div class="section-heading"><div><p class="eyebrow">${e(eyebrow)}</p><h2${number ? ' class="numbered-title"' : ''}>${number ? sectionNumber(number) : ''}${e(title)}</h2></div>${aside}</div>`;
const action = (label, control, transport, className = '') => button(label, `${transport?.available?.[control] ? '' : 'disabled'} data-request-control="${control}"`, className);
const directControls = (transport) => `<div class="direct-controls">${action('Pause new risk', 'PAUSE_NEW_RISK', transport)}${action('Stop automation', 'STOP_AUTOMATION', transport, 'button-warning')}</div>`;
const modalInterruption = (transport) => `<section class="modal-interruption" aria-label="Scoped interruption controls">${directControls(transport)}<p>${transport?.attached ? 'Requests need exact independent readback. Accepted orders and protective stops may still execute.' : 'Interruption unavailable: no authorized transport or independent readback. Backend state remains unconfirmed.'}</p>${controlHistory(transport)}</section>`;

function controlHistory(transport) {
  if (!transport?.controls.length) return '';
  return `<div class="request-history" aria-label="Control requests">${transport.controls.map((record) => `<details><summary>${e(CONTROL_COPY[record.control]?.title ?? record.control)} / ${e(record.status)}</summary><p>${e(record.reason)}</p><dl class="metadata compact">${meta('Request ID', record.id)}${meta('Account / run', `${record.scope.account_id} / ${record.scope.run_id}`)}${meta('Requested barrier', record.request?.barrier_id)}${meta('Requested generation', record.request?.next_generation)}${meta('Observed barrier', record.receipt?.barrier_id)}${meta('Observed generation', record.receipt?.generation)}${meta('Observed at', record.receipt?.observed_at)}</dl>${record.request ? button('Read fence again', `data-read-control="${e(record.id)}" ${!transport.attached || ['PREPARING', 'REQUESTING', 'READING'].includes(record.status) ? 'disabled' : ''}`, 'button-small') : ''}</details>`).join('')}</div>`;
}

function transportStatus(transport) {
  if (!transport) return '';
  const close = transport.close;
  return `<section class="transport-status" aria-label="Scoped request observations">${transport.issue ? `<p role="status">${e(transport.issue)}</p>` : ''}${controlHistory(transport)}${close ? `<div class="close-status"><strong>Reviewed Close / ${e(close.status)}</strong><p>${e(close.reason)}</p>${button('Inspect Close request', 'data-inspect-close="true"', 'button-small')}</div>` : ''}${transport.closeHistory?.length ? `<details><summary>Previous Close reviews / ${transport.closeHistory.length}</summary>${transport.closeHistory.map((entry) => `<dl class="metadata compact">${meta('Request', entry.input?.owner_request_id)}${meta('Status at replacement', entry.status)}${meta('Command', entry.preview?.command_id)}${meta('Reason', entry.reason)}</dl>`).join('')}</details>` : ''}</section>`;
}

function addExactDecimals(values) {
  let maxScale = 0;
  const parts = [];
  for (const raw of values) {
    if (typeof raw !== 'string' || !/^-?[0-9]+(\.[0-9]+)?$/.test(raw)) continue;
    const neg = raw.startsWith('-');
    const clean = neg ? raw.slice(1) : raw;
    const [intPart, fracPart = ''] = clean.split('.');
    maxScale = Math.max(maxScale, fracPart.length);
    parts.push({ neg, intPart, fracPart });
  }
  if (!parts.length) return '0';
  let sum = 0n;
  for (const { neg, intPart, fracPart } of parts) {
    const padded = intPart + fracPart.padEnd(maxScale, '0');
    const val = BigInt(padded);
    sum += neg ? -val : val;
  }
  const sign = sum < 0n ? '-' : '';
  const abs = (sum < 0n ? -sum : sum).toString().padStart(maxScale + 1, '0');
  if (maxScale === 0) return `${sign}${abs}`;
  const head = abs.slice(0, abs.length - maxScale);
  const tail = abs.slice(abs.length - maxScale).replace(/0+$/, '');
  return tail ? `${sign}${head}.${tail}` : `${sign}${head}`;
}

function metrics(projection, state) {
  let eqVal = projection.equity;
  let balVal = projection.balance;
  let openVal = projection.open_pnl;
  let realVal = projection.realized_pnl;

  if (state?.liveStreamConnected === true) {
    if (eqVal === null) {
      const shieldEq = state.brokerRouting?.shield?.totalEquity;
      const quotaEq = state.aiTrader?.dailyQuota?.startingEquityUsd;
      const chosenEq = shieldEq ?? (typeof quotaEq === 'string' && /^[0-9]+(\.[0-9]+)?$/.test(quotaEq) && quotaEq !== '0' ? quotaEq : null);
      if (chosenEq !== null) {
        eqVal = Object.freeze({ amount: chosenEq, currency: 'USD' });
        const posList = Array.isArray(state.aiTrader?.openPositions) ? state.aiTrader.openPositions : [];
        const openSum = addExactDecimals(posList.map((p) => p.profit));
        openVal = Object.freeze({ amount: openSum, currency: 'USD' });
        const negOpen = openSum.startsWith('-') ? openSum.slice(1) : `-${openSum}`;
        const balStr = addExactDecimals([chosenEq, negOpen]);
        balVal = Object.freeze({ amount: balStr, currency: 'USD' });
      }
    }
    if (realVal === null && state.aiTrader?.connected && typeof state.aiTrader.dailyQuota?.realizedNetPnlUsd === 'string') {
      realVal = Object.freeze({ amount: state.aiTrader.dailyQuota.realizedNetPnlUsd, currency: 'USD' });
    }
  }

  const lockedHint = !state?.liveStreamConnected
    ? '<p class="account-locked-hint" data-account-locked-hint="true">Locked preview — unlock Live Cockpit above to load live Hugo&#39;s Way, LHFX, and OANDA Equity, Balance, Open P/L, and Banked Realized P/L.</p>'
    : '';

  const realizedProvenanceHtml = state?.liveStreamConnected === true
    ? `<span class="metric-provenance" data-account-realized-provenance="true">${e(resolveRealizedPnlProvenance(state).compactSummary)}</span>`
    : '';

  return `${lockedHint}<section class="metrics" aria-label="Account snapshot">${[
    ['Equity', eqVal], ['Balance', balVal], ['Open P/L', openVal], ['Realized P/L', realVal],
  ].map(([label, value]) => {
    const money = moneyLabel(value);
    const extraProv = label === 'Realized P/L' ? realizedProvenanceHtml : '';
    return `<article class="metric"><h2>${label}</h2><div class="metric-value${value === null ? ' unknown' : ''}">${e(money.amount)}</div><span class="metric-unit">${e(money.unit)}</span>${extraProv}</article>`;
  }).join('')}</section>`;
}

function controls(transport) {
  return `<section class="panel controls-panel" aria-labelledby="controls-title">
    <div class="section-heading"><div><p class="eyebrow">CONTROL</p><h2 id="controls-title">Automation</h2></div>${tag(transport?.attached ? 'Scoped simulator' : 'No transport', true)}</div>
    <div class="control-row"><div><h3>Pause new risk</h3><p>Management requires separate permission.</p></div>${button('About Pause', 'data-control="PAUSE_NEW_RISK"', 'button-link')}</div>
    <div class="control-row"><div><h3>Stop automation</h3><p>Open positions and pending effects remain.</p></div>${button('About Stop', 'data-control="STOP_AUTOMATION"', 'button-link')}</div>
    ${directControls(transport)}<p class="quiet-note">${transport?.attached ? 'Explicit requests only. Accepted does not mean confirmed. Protective stops may still execute.' : 'Unavailable: no control transport. No request has been sent.'}</p>
  </section>`;
}

function positions(projection) {
  const title = heading('VENUE SNAPSHOT', 'Positions', tag(positionSummary(projection)));
  if (projection.positions === null) return `<section class="panel positions-panel">${title}${empty('Positions are unknown', 'No independent venue inventory has been read. Unknown does not mean flat.', '○')}</section>`;
  if (projection.positions.length === 0) return `<section class="panel positions-panel">${title}${empty('No positions in this snapshot', 'This is a historical read. It does not establish current venue exposure.', '○')}</section>`;
  return `<section class="panel positions-panel">${title}<div class="table-scroll" tabindex="0" role="region" aria-label="Positions table"><table><caption class="sr-only">Exact observed quantities in base units</caption><thead><tr><th scope="col">Instrument / target</th><th scope="col">Side</th><th scope="col">Base units</th><th scope="col">Entry / stop</th><th scope="col">Review</th></tr></thead><tbody>${projection.positions.map((position) => `<tr><th scope="row"><span class="strong">${e(position.instrument_id)}</span><span class="cell-detail">${e(position.position_id)} · v${e(position.version)}</span></th><td>${e(position.side)}</td><td class="numeric">${e(formatDecimal(position.quantity))}</td><td class="numeric">${e(formatDecimal(position.entry_price))}<span class="cell-detail">Stop ${position.stop_price === null ? 'unknown' : e(formatDecimal(position.stop_price))}</span></td><td>${button('Review Close', `data-close="${e(position.position_id)}"`, 'button-small')}</td></tr>`).join('')}</tbody></table></div><p class="quiet-note">Close is a separate, exact-target review. It does not send an order.</p></section>`;
}

function decision(projection) {
  const d = projection.last_decision;
  const identity = decisionIdentity(d);
  return `<section class="panel decision-panel">${heading('OPERATOR', 'Latest proposal', tag(d === null ? 'Not observed' : 'Proposal only'))}
    ${d === null ? empty('No decision observed', 'Scripted, replayed, and actual-model decisions will retain their own identities.', '↗') : `<div class="decision-lead"><p class="eyebrow">${e(identity.origin)}</p><h3>${e(d.selection.selected_action_ref ?? 'WAIT')}</h3><p class="reason">${e(d.selection.reason)}</p><p class="quiet-note">Source state: ${e(d.selection.source_state_id)}${d.selection.source_state_id !== projection.state_id ? ' · differs from cockpit state' : ''}</p></div>`}
    <dl class="metadata compact">${meta('Model', identity.model)}${meta('Inference', identity.verification)}</dl>
    ${button('Open Review →', 'data-route="review"', 'button-link')}
  </section>`;
}

function permissions(projection, transport) {
  const p = projection.permissions;
  return `<section class="panel permission-panel">${heading('REPORTED PERMISSIONS', 'Risk & management')}
    <div class="permission-grid"><div><span>New risk</span>${tag(p.new_risk, p.new_risk === 'UNKNOWN')}</div><div><span>Management</span>${tag(p.management, p.management === 'UNKNOWN')}</div></div>
    <dl class="metadata compact">${meta('Recovery', `${projection.recovery} · reported`)}${meta('Admission flag', projection.admissions_enabled ? 'Enabled in source snapshot' : 'Disabled in source snapshot')}${meta('Barrier reference', p.confirmed_barrier_id)}${meta('Generation', p.generation)}</dl>
    <p class="quiet-note">Core session grants are separate from venue fence configuration.</p>${transport?.boot?.fence_receipt ? `<details><summary>Independent venue fence / generation ${e(transport.boot.fence_generation)}</summary><dl class="metadata compact">${meta('Barrier', transport.boot.fence_receipt.barrier_id)}${meta('New risk configured', transport.boot.fence_receipt.new_risk_allowed)}${meta('Management configured', transport.boot.fence_receipt.management_allowed)}${meta('Observed at', transport.boot.fence_receipt.observed_at)}</dl><p>Configuration readback does not grant this core session permission.</p></details>` : '<p class="quiet-note">Independent barrier readback is not attached.</p>'}
  </section>`;
}

function effects(projection) {
  const pending = pendingEffects(projection);
  return `<section class="panel effects-panel">${heading('CORE / VENUE', 'Effects to resolve', tag(pending.length ? `${pending.length} pending / unknown` : 'Coverage unknown', true))}
    ${pending.length ? `<ul class="effect-list">${pending.map((id) => `<li><span class="status-dot warning" aria-hidden="true"></span><code>${e(id)}</code><span>Effect not established</span></li>`).join('')}</ul>` : `<p class="panel-copy">No unresolved IDs are listed. Full venue coverage is not established.</p>`}
    <p class="quiet-note">A local idle screen or a submitted request cannot confirm Stop.</p>
  </section>`;
}

function operate(projection, state) {
  return `<section class="workspace-intro" aria-label="Workspace introduction"><div><p class="eyebrow">PERSONAL FOREX / OBSERVATION FIRST</p><h2>Every decision, with its evidence.</h2></div><p>Inspect the account snapshot, oversee autonomous AI execution, monitor 5 parallel account tiers &amp; 50%/50% Bank Vault sweeps, and keep unobserved outcomes visible.</p></section>${renderAiTopSwitcherBar(state)}${renderDemoHighGrowthPanel(resolveCockpitDemoHighGrowth(state))}${renderMasterAggressionDial(resolveCockpitAggressionDial(state))}${renderCompoundingAndHouseMoneyPanel(resolveCockpitCompounding(state))}<div class="route-index">${sectionNumber('01')}<h2>Permissions &amp; control</h2></div><div class="context-grid">${permissions(projection, state.transport)}${controls(state.transport)}</div><div class="route-index">${sectionNumber('02')}<h2>Account snapshot</h2></div>${metrics(projection, state)}<p class="account-coverage">P/L period, fees and cashflow coverage are unavailable in this projection.</p>${renderLiveFundingPanel(state)}${renderAiOverseerPanel(state)}${renderTacticalValveHud(state)}${renderMarketRadarTable(state)}<div class="route-index">${sectionNumber('03')}<h2>Live market &amp; candlestick chart</h2></div>${renderMarketChartSection(projection, state)}${renderEquityAndAnalyticsSection(state)}${renderParallelTiersSection(state)}${renderOptionBDemoPanel(resolveCockpitOptionBDemo(state))}${renderMoneyFlowSection(state)}<div class="route-index">${sectionNumber('04')}<h2>Positions, proposals &amp; effects</h2></div><div class="operate-grid">${positions(projection)}${decision(projection)}${effects(projection)}</div>`;
}

function catalogInspection(read, source = null) {
  if (!read?.catalog) return '';
  const catalog = read.catalog;
  const identities = new Set();
  function visit(value) {
    if (value === null || typeof value !== 'object') return;
    if (Object.hasOwn(value, 'record_id') && Object.hasOwn(value, 'record_sha256') && value.record_id !== null) identities.add(canonicalJSON(value));
    else Object.values(value).forEach(visit);
  }
  if (source) visit(source);
  const entries = source ? catalog.entries.filter((entry) => identities.has(canonicalJSON(entry.reference))) : catalog.entries;
  return `<details class="catalog-inspection"><summary>Catalog inspection / ${source ? entries.filter((entry) => entry.status === 'MATCHED').length : catalog.matched_count} matched / ${entries.length} supplied references</summary><p class="quiet-note">Exact bytes for this retained read. Semantic validity, current state, effects and inference are not established by these matches.</p>${entries.map((entry) => `<details class="catalog-record" data-catalog-reference="${e(entry.reference.record_id)}"><summary>${e(entry.reference.record_id)} / v${e(entry.reference.record_version)} / ${e(entry.status)}</summary><p>${e(entry.reason)}</p><dl class="metadata compact">${meta('SHA-256', entry.reference.record_sha256)}${meta('Referenced at', entry.paths.join(', '))}${meta('Read anchor', read.anchor?.anchor_id)}${meta('Producer', read.anchor?.producer_id)}</dl>${entry.status === 'MATCHED' ? `<pre>${e(JSON.stringify(entry.record, null, 2))}</pre>` : ''}</details>`).join('')}${!source ? `<details><summary>Declared unavailable references / ${catalog.absent.length}</summary><ul>${catalog.absent.map((entry) => `<li><code>${e(entry.path)}</code>: ${e(entry.reason)}</li>`).join('')}</ul></details>` : ''}</details>`;
}

function recordDetails(record, read) {
  if (record.id.startsWith('read-')) {
    const source = record.source;
    const candidateContent = record.id.startsWith('read-decision:') ? `<dl class="metadata">${meta('Origin', `${source.origin.kind} · reported`)}${meta('Model / provider', `${source.origin.model_id ?? 'Unknown'} / ${source.origin.provider ?? 'Unknown'}`)}${meta('Effective reasoning', source.origin.effective_reasoning)}${meta('Decision status', source.decision_status)}${meta('Chosen candidate', source.selection === null ? 'No selection supplied' : source.selection.wait ? 'WAIT' : source.selection.candidate_id)}${meta('Source state', source.selection?.source_state_id)}${meta('Admission reference', source.admission_ref.record_id ?? source.admission_ref.unavailable_reason)}${meta('Dispatch reference', source.dispatch_ref.record_id ?? source.dispatch_ref.unavailable_reason)}${meta('Outcome references', source.outcome_refs.length ? source.outcome_refs.map((ref) => ref.record_id ?? ref.unavailable_reason).join(' · ') : 'Unavailable')}</dl><h4>Candidate catalog</h4><div class="candidate-catalog">${source.candidates.map((candidate) => `<details class="candidate"><summary><strong>${e(candidate.strategy_id)} / ${e(candidate.timeframe)}</strong><span>${e(candidate.candidate_id)} · ${e(candidate.action_kind)}</span><span>${e(candidate.evaluation)} / ${e(candidate.eligibility)} / ${e(candidate.disposition)}</span></summary><pre>${e(JSON.stringify(candidate, null, 2))}</pre></details>`).join('')}</div>` : '';
    return `<p class="reason">${e(record.detail)}</p>${candidateContent}${catalogInspection(read, source)}<p class="quiet-note">${read?.local.source_binding === 'BRIDGE_ANCHOR_MATCHED' ? 'Source anchor matched; semantic effects remain unverified.' : 'Supplied record; source unverified.'} Exact catalog records do not independently confirm current control or fill semantics.</p><details class="source-detail"><summary>Full immutable source record</summary><pre>${e(JSON.stringify(source, null, 2))}</pre></details>`;
  }
  if (record.kind === 'PROPOSAL') {
    const { selection: s, provenance: p } = record.source;
    return `<p class="reason">${e(s.reason)}</p><dl class="metadata">${meta('Decision ID', record.source.decision_id)}${meta('Request', s.request_id)}${meta('Opportunity set', s.opportunity_set_id)}${meta('Source state', s.source_state_id)}${meta('Selected action', s.selected_action_ref ?? 'WAIT')}${meta('Origin', `${p.origin} · reported`)}${meta('Model', p.model_id)}${meta('Adapter', p.adapter_id)}${meta('Prompt version', p.prompt_version)}${meta('Completed at', p.completed_at)}${meta('Inference receipt reference', p.inference_receipt_id)}${meta('Model artifact SHA-256', p.model_artifact_sha256)}${meta('Request SHA-256', p.request_sha256)}${meta('Response SHA-256', p.response_sha256)}</dl><h4>Evidence references</h4>${s.evidence_ids.length ? `<ul class="reference-list">${s.evidence_ids.map((id) => `<li><code>${e(id)}</code></li>`).join('')}</ul>` : '<p class="muted">None supplied.</p>'}<p class="quiet-note">References are not independent verification. Admission and venue outcome cannot be linked from this projection.</p>`;
  }
  const c = record.source;
  return `<dl class="metadata">${meta('Command ID', c.command_id)}${meta('Core state', c.state)}${meta('Reservation', c.reservation_held ? 'Held in source snapshot' : 'Not held in source snapshot')}${meta('Venue receipt reference', c.last_venue_receipt_id)}${meta('Venue effect', commandEffect(c))}${meta('Reason code', c.reason_code)}${meta('Payload SHA-256', c.payload_sha256)}</dl><p class="quiet-note">OBSERVED is a core state. It does not disclose filled quantity or prove a venue effect here.</p>`;
}

// Filtering changes only the visible record set, never source data or inspection authority.
function recordGroup(record) {
  if (record.id.startsWith('read-decision:') || record.id.startsWith('decision:')) return 'decisions';
  if (record.id.startsWith('read-evidence:')) return 'evidence';
  return 'events';
}

function review(projection, state) {
  const read = state.reviewEnvelope;
  const allRecords = read ? envelopeRecords(read) : reviewRecords(projection);
  const filter = ['all', 'decisions', 'events', 'evidence'].includes(state.reviewFilter) ? state.reviewFilter : 'all';
  const records = filter === 'all' ? allRecords : allRecords.filter((record) => recordGroup(record) === filter);
  const filters = [['all', 'All'], ['decisions', 'Decisions'], ['events', 'Events / core'], ['evidence', 'Evidence']].map(([key, label]) => {
    const count = key === 'all' ? allRecords.length : allRecords.filter((record) => recordGroup(record) === key).length;
    return button(`${label} / ${count}`, `data-review-filter="${key}" aria-pressed="${filter === key}"`, filter === key ? 'selected' : 'button-secondary');
  }).join('');
  const coverage = read?.envelope.coverage;
  const bindingLabel = read?.local.source_binding === 'BRIDGE_ANCHOR_MATCHED' ? `bridge anchor matched; ${read.catalog?.matched_count ?? 0}/${read.catalog?.requested_count ?? 0} supplied references matched` : 'source unverified';
  const atlasOversize = state.reviewView === 'atlas' && records.length > 64;
  const selected = records.find((record) => record.id === state.inspection.focus_node_id);
  const switcher = `<div class="segmented" role="group" aria-label="Decision presentation">${button('List', `data-view="list" aria-pressed="${state.reviewView === 'list'}"`, state.reviewView === 'list' ? 'selected' : '')}${button('Atlas', `data-view="atlas" aria-pressed="${state.reviewView === 'atlas'}"`, state.reviewView === 'atlas' ? 'selected' : '')}</div>`;
  return `<section class="review-toolbar">${heading('SAME RECORDS / TWO VIEWS', 'Decision review', switcher, '01')}<p class="quiet-note">${allRecords.length} supplied records · ${coverage ? (coverage.complete ? 'source claims complete coverage' : 'incomplete coverage') : 'partial cockpit projection'} · ${e(bindingLabel)}</p><div class="review-filters" role="group" aria-label="Filter supplied records">${filters}</div><p class="filter-note" role="status">Showing ${records.length} of ${allRecords.length} supplied records. Filtering does not change coverage or source state.</p></section>
    ${state.reviewIssue ? `<div class="review-warning" role="status">${e(state.reviewIssue)} Cockpit records remain available below.</div>` : ''}
    ${read ? `<details class="coverage-detail" data-source-binding="${e(read.local.source_binding)}" data-reference-resolution="${e(read.local.reference_resolution)}"><summary>Coverage & source · ${coverage.complete ? 'reported complete' : 'incomplete'} · ${e(bindingLabel)}</summary><dl class="metadata">${meta('Retained / total known', `${coverage.retained_count} / ${coverage.total_known_count ?? 'Unknown'}`)}${meta('Sequence range', `${coverage.from_sequence ?? 'Unknown'} – ${coverage.through_sequence ?? 'Unknown'}`)}${meta('Omitted IDs', coverage.omitted_ids.join(', ') || 'None declared')}${meta('Deferred IDs', coverage.deferred_ids.join(', ') || 'None declared')}${meta('Next page', coverage.next_cursor ?? 'None declared')}${meta('Domain digest', read.envelope.domain_digest)}${meta('Self-consistency', read.local.self_consistency)}${meta('Source binding', read.local.source_binding)}${meta('Reference resolution', read.local.reference_resolution)}${meta('Semantic verification', read.local.semantic_verification ?? 'NOT_ESTABLISHED')}</dl><ul>${coverage.reasons.map((reason) => `<li>${e(reason)}</li>`).join('')}</ul>${catalogInspection(read)}<p>Page tokens are displayed only. No paging service is attached.</p><details class="source-detail"><summary>Full source envelope, including reported checks and unknowns</summary><pre>${e(JSON.stringify(read.envelope, null, 2))}</pre></details></details>` : ''}
    <dl class="identity-strip">${meta('Current state', projection.state_id)}${meta('Inspection focus', state.inspection.focus_node_id)}${meta('Hypothesis', 'Unavailable in this projection')}</dl>
    <div class="review-grid"><section class="panel review-records" aria-label="${state.reviewView === 'atlas' ? 'Decision atlas' : 'Decision list'}">
      ${state.reviewView === 'atlas' ? '<p class="atlas-caption">Read-only record groups. No causal or execution links are inferred.</p>' : ''}
      ${atlasOversize ? `<div class="review-warning"><strong>Atlas incomplete: ${records.length} records exceed its 64-record visible limit.</strong><p>No records were discarded. Use List to inspect the full supplied page.</p>${button('Use List', 'data-view="list"')}</div>` : records.length ? `<div class="record-collection ${state.reviewView === 'atlas' ? 'atlas' : 'plain-list'}">${records.map((record) => `<button type="button" class="record-card ${selected?.id === record.id ? 'is-focused' : ''}" data-record="${e(record.id)}" aria-pressed="${selected?.id === record.id}"><span class="eyebrow">${e(record.kind)}</span><span class="record-title">${e(record.title)}</span><span class="record-detail">${e(record.detail)}</span><span class="record-id">${e(record.id)}</span><span class="inspect-label">Inspect →</span></button>`).join('')}</div>` : empty(filter === 'all' ? 'No records to inspect' : 'No records in this filter', filter === 'all' ? 'No records were supplied on this page. This does not establish an empty history.' : 'Other supplied records remain available under All. No source data was removed.', '◇')}
      <div class="evidence-stages" aria-label="Evidence stages"><div><span>01</span><strong>Proposal</strong><small>Operator selection</small></div><div><span>02</span><strong>Authorization</strong><small>Core admission / reservation</small></div><div><span>03</span><strong>Receipt</strong><small>Independent venue effect</small></div><div><span>04</span><strong>Observation</strong><small>What this UI has read</small></div></div>
    </section><aside class="panel inspection-panel" aria-labelledby="inspection-title"><p class="eyebrow">INSPECTION ONLY</p><h2 id="inspection-title" class="numbered-title">${sectionNumber('02')}${selected ? e(selected.title) : 'Record detail'}</h2>${selected ? recordDetails(selected, read) : '<p class="panel-copy">Choose a record to inspect its source identity and evidence references.</p>'}</aside></div>
    <section class="panel research-note"><div><h3>Optional organization</h3><p>U0 compares owner diagnosis using the same records. U1 compares model inputs with matched information and budgets.</p></div>${tag('Benefit not measured')}</section>`;
}

function setup(projection, state) {
  const capabilities = [
    ['Snapshot inspection', projection ? 'LOADED / READ ONLY' : 'UNAVAILABLE', projection ? 'A supplied snapshot is available for inspection. It does not establish current venue state.' : 'Load a valid source before inspecting account data.'],
    ['Decision records', state.reviewEnvelope ? 'LOADED / SOURCE CHECKS VARY' : 'NOT OBSERVED', state.reviewEnvelope ? 'The Review screen retains every supplied record and its source checks.' : 'No decision-read envelope is loaded. Cockpit proposals remain separate.'],
    ['Execution controls', state.transport?.attached ? 'SCOPED SIMULATOR ONLY' : 'UNAVAILABLE', 'Each control keeps its existing capability checks and independent readback requirements.'],
    ['AI explanations', 'UNAVAILABLE', state.explainerIssue ?? 'No AI provider is attached. The Explainer contains a local guide only; it sends no model requests.'],
  ];
  return `<section class="readiness-band" aria-labelledby="capability-heading"><div class="route-index">${sectionNumber('01')}<h2 id="capability-heading">Capabilities &amp; limits</h2></div><div class="capability-grid">${capabilities.map(([name, status, detail]) => `<article class="capability-item"><div class="capability-label"><span class="state-rule" aria-hidden="true"></span><h3>${e(name)}</h3></div><p class="capability-state">${e(status)}</p><p class="capability-detail">${e(detail)}</p></article>`).join('')}</div></section><div class="route-index">${sectionNumber('02')}<h2>Source &amp; workspace</h2></div><div class="setup-grid"><section class="panel">${heading('READ ONLY', 'Snapshot source', tag('Disconnected'))}
    <p class="panel-copy">Load an exported cockpit snapshot to inspect it. Loading data grants no permission and starts no worker.</p>
    <dl class="metadata">${meta('Source', state.source)}${meta('Schema', projection?.schema_version ?? 'Unavailable')}${meta('Transport', state.transport?.attached ? 'Explicit scoped bridge' : 'None attached')}${meta('Authoritative clock', state.transport?.boot?.request_time)}${meta('Loaded by UI', state.loadedAt ?? 'Not loaded')}</dl>
    <div class="upload-area"><label class="upload-label" for="snapshot-file">Load cockpit JSON</label><input id="snapshot-file" type="file" accept=".json,application/json" ${state.schemaReady && !state.transport?.attached ? '' : 'disabled'} aria-describedby="upload-help"><p id="upload-help">Shared v1 schema · maximum 512 KiB · processed in this tab</p></div>
    ${button('Read shared fixture', `data-reload="fixture" ${state.transport?.attached ? 'disabled' : ''}`, 'button-secondary')}
    ${state.transport?.attached ? button('Read current state', 'data-read-transport="true"') + button('Detach bridge', 'data-detach-transport="true"', 'button-secondary') : ''}
    <div class="upload-area"><label class="upload-label" for="decision-file">Load decision-read JSON</label><input id="decision-file" type="file" accept=".json,application/json" ${state.reviewSchemaReady && projection && !state.transport?.attached ? '' : 'disabled'} aria-describedby="decision-upload-help"><p id="decision-upload-help">Matched cockpit scope/state · maximum 1 MiB · source remains unverified</p></div>
    ${state.lastLoaded && !projection && !state.transport?.attached ? button('Inspect last loaded snapshot', 'data-restore-last="true"') : ''}
  </section><section class="panel">${heading('APPEARANCE', 'Your workspace')}
    <fieldset class="theme-options"><legend>Theme</legend>${['system', 'light', 'dark'].map((theme) => `<label><input type="radio" name="theme" value="${theme}" ${state.theme === theme ? 'checked' : ''}>${theme[0].toUpperCase() + theme.slice(1)}</label>`).join('')}</fieldset><p class="quiet-note">Theme is held in this tab. No credentials or permissions are stored.</p>
    <dl class="metadata">${meta('Default view', 'Operate')}${meta('Decision presentation', state.reviewView === 'atlas' ? 'Atlas' : 'List')}${meta('Control requests', state.transport?.attached ? 'Explicit scoped requests' : 'Unavailable')}</dl>
    ${state.liveStreamConnected && state.canPairDevice && isOwnerControlSession(state) ? `<div class="direct-controls"><button type="button" class="button button-small button-primary qr-pair-btn" data-toggle-qr-pairing="true" aria-expanded="${Boolean(state.qrPairingOpen)}">${state.qrPairingOpen ? 'Hide Pairing QR' : 'Pair Phone / Tablet (QR)'}</button><button type="button" class="button button-small button-warning" data-revoke-qr-pairing="true">Revoke Paired Devices</button></div>` : ''}
  </section><section class="panel">${heading('EXPLICIT OWNER REQUEST', 'Resume permissions')}<p class="panel-copy">Resume is separate from Pause, Stop and Close. Core checks recovery before granting permission.</p><div class="direct-controls">${action('Resume new risk', 'RESUME_NEW_RISK', state.transport)}${action('Resume management', 'RESUME_MANAGEMENT', state.transport)}</div></section><section class="panel scope-panel">${heading('SOURCE IDENTITY', 'Account & run')}${projection ? `<dl class="metadata">${Object.entries(projection.scope).map(([key, value]) => meta(key.replaceAll('_', ' '), value)).join('')}</dl>` : '<p class="panel-copy">No valid source loaded.</p>'}</section></div>
  ${renderLiveFundingPanel(state)}
  <div class="setup-grid">${renderBrokerRoutingPanel(state.brokerRouting)}${renderAiModelCatalogPanel(state.aiModels)}<section class="panel">${heading('READINESS', 'Rehearsal stages')}
    <div class="stage-row"><div><span class="stage-letter">A</span><h3>Scripted rehearsal</h3><p>Continuous operational management.</p></div>${tag('NOT_RUN')}</div>
    <div class="stage-row"><div><span class="stage-letter">B</span><h3>Actual-model simulator</h3><p>Real decisions and continuing management.</p></div>${tag('NOT_RUN')}</div>
    <p class="quiet-note">These are build validation states. Neither stage establishes trading profit or strategy edge.</p>
  </section></div>`;
}

const pct = (share) => { const n = Number(share); return Number.isFinite(n) ? `${Math.round(n * 10000) / 100}%` : 'Unknown'; };

function renderChainStatusBadge(status) {
  if (status === 'BROKER_OFFLINE') {
    return '<span class="tag status-offline" data-broker-status="BROKER_OFFLINE"><span class="state-rule" aria-hidden="true"></span>OFFLINE</span>';
  }
  if (status === 'ACTIVE') {
    return '<span class="tag status-active" data-broker-status="ACTIVE"><span class="state-rule" aria-hidden="true"></span>ACTIVE</span>';
  }
  if (status === 'FAILED' || status === 'FROZEN' || status === 'LIVE_FORBIDDEN') {
    return `<span class="tag tag-warning status-failed" data-broker-status="${e(status)}"><span class="state-rule" aria-hidden="true"></span>${e(status)}</span>`;
  }
  return `<span class="tag tag-warning" data-broker-status="${e(status)}"><span class="state-rule" aria-hidden="true"></span>${e(status)}</span>`;
}

/** 03 Setup card: Broker & MetaTrader 5 routing (demo only). Static preview when no loopback routing is attached. */
export function renderBrokerRoutingPanel(routing) {
  const r = routing && typeof routing === 'object' && Array.isArray(routing.chain) ? routing : STATIC_BROKER_ROUTING;
  const s = r.shield ?? STATIC_BROKER_ROUTING.shield;
  const isLive = r.executionMode === 'LIVE' && r.liveArmed === true;
  const eyebrow = isLive ? 'LIVE REAL-MONEY EXECUTION ARMED' : 'DEMO ACCOUNTS ONLY';
  const modeTag = isLive ? tag('LIVE MODE · real money armed', true) : tag('Demo only · live trading locked');
  const lead = isLive
    ? `Active platform ${e(r.platform)}. Hugo's Way (live), LHFX (live), and OANDA fxTrade Safe Harbor are armed under two-key authorization. Every trade still requires ForexMetaValveGate clearance and the 10% drawdown brake.`
    : `Active platform ${e(r.platform)}. Hugo's Way is the primary main venue, LHFX is the secondary MetaTrader 5 venue, and the OANDA practice account is the regulated safe harbor. Every trade still needs ForexMetaValveGate clearance first.`;
  const foot = isLive
    ? 'Live execution mode: two-key owner authorization is active; demo servers are refused to prevent mixing funds. No credentials are shown or stored in this page.'
    : 'Demo-only lock: live servers (Hugo PRO5, LHFXSA-Live, api-fxtrade.oanda.com) are refused in code. No credentials are shown or stored in this page.';
  const chain = r.chain.map((item) => `<div class="stage-row broker-row" data-broker-id="${e(item.brokerId)}"><div><span class="stage-letter">${e(item.priority)}</span><h3>${e(item.brokerId)} · ${e(item.label)}</h3><p>${e(item.role)} · ${e(item.platform)} · ${e(item.server)} · ${e(item.leverage)} ${e(item.accountType)}</p></div>${renderChainStatusBadge(item.status)}</div>`).join('');
  const hasOffline = Boolean(s.equityIncomplete || (s.offlineBrokers && s.offlineBrokers.length > 0) || r.chain.some((c) => c.status === 'BROKER_OFFLINE'));
  const onlineEqMeta = hasOffline && s.onlineEquity
    ? meta('Online deployable equity', `$${s.onlineEquity} (offline broker excluded — not a loss)`)
    : '';
  return `<section class="panel broker-routing-panel" aria-labelledby="broker-routing-title"><div class="section-heading"><div><p class="eyebrow">${eyebrow}</p><h2 id="broker-routing-title">Broker &amp; MetaTrader 5 Routing</h2></div>${modeTag}</div>
    <p class="panel-copy">${lead}</p>
    <dl class="metadata">${meta('Execution mode', isLive ? 'LIVE (two-key armed)' : 'DEMO (default locked)')}${meta('Active platform', r.platform)}${meta('Routing source', r.connected ? 'Loopback broker routing (read only)' : 'Static preview (not connected)')}${meta('Primary broker', r.primaryBroker)}${meta('Active broker', r.activeBroker)}${meta('MT5 transport', r.transportMode)}${meta('Safety valve', `${r.valve.controller} · ${r.valve.parameters} params · threshold ${r.valve.threshold}`)}${onlineEqMeta}</dl>
    <div class="broker-chain" aria-label="Broker priority chain">${chain}</div>
    <dl class="metadata" aria-label="Dual-shield barbell">${meta('Quote-truth shield', `${s.majorBps} bps majors / ${s.crossBps} bps crosses vs ${s.reference} · spread ≤ ${s.spreadMultiple}x`)}${meta('Barbell allocation', `${pct(s.reserveShare)} OANDA reserve · ${pct(s.hugoswayShare)} Hugo's Way · ${pct(s.lhfxShare)} LHFX`)}${meta('Stop-loss risk cap', `${s.maxStopRiskPct}% of total equity`)}${meta('Safe harbor', `${s.safeHarbor} ${s.safeHarborLeverage} · ${s.degradations} recent degradations`)}${meta('Protective offsets', s.offsetPlanner ? 'Delta-neutral OANDA hedge plan if an MT5 terminal freezes' : 'Unavailable')}</dl>
    <p class="quiet-note">${foot}</p>
  </section>`;
}

export function renderApp(state, now = Date.now(), monotonicNow = globalThis.performance?.now?.() ?? null) {
  const projection = state.projection;
  const page = ['operate', 'review', 'setup'].includes(state.route) ? state.route : 'operate';
  const titles = { operate: ['YOUR WORKSPACE', 'Operate'], review: ['DECISIONS & EVIDENCE', 'Review'], setup: ['SOURCE & PREFERENCES', 'Setup'] };
  const age = displayFreshness(state, { wallNow: now, monotonicNow });
  const sourceLabel = state.source === 'scoped simulator' ? 'Scoped simulator' : state.source === 'shared fixture' ? 'Shared fixture' : state.source === 'local snapshot' ? 'Local snapshot' : state.source === 'historical snapshot' ? 'Historical snapshot' : 'No valid source';
  const isLiveArmed = state.brokerRouting?.executionMode === 'LIVE' && state.brokerRouting?.liveArmed === true;
  const execModeBadge = `<span class="exec-mode-badge ${isLiveArmed ? 'is-live-armed' : 'is-demo-mode'}" data-execution-mode="${isLiveArmed ? 'LIVE' : 'DEMO'}">${isLiveArmed ? 'LIVE REAL-MONEY ARMED' : 'DEMO MODE'}</span>`;
  const ownerSession = isOwnerControlSession(state);
  const sessionScopeBadge = state.liveStreamConnected
    ? (ownerSession
      ? '<span class="session-scope-badge is-owner-control" data-session-privilege-badge="OWNER_FULL_CONTROL">Owner Full Control</span>'
      : '<span class="session-scope-badge is-paired-readonly" data-session-privilege-badge="DEVICE_READ_AND_EXPLAINER">Paired Device (Read + Explainer · Owner Controls Locked)</span>')
    : '';
  const pairQrBtn = state.liveStreamConnected && state.canPairDevice && ownerSession
    ? `<button type="button" class="button button-small button-secondary qr-pair-btn" data-toggle-qr-pairing="true" aria-expanded="${Boolean(state.qrPairingOpen)}">${state.qrPairingOpen ? 'Hide Pairing QR' : 'Pair Phone / Tablet (QR)'}</button>`
    : '';
  const qrDrawerMarkup = state.liveStreamConnected && ownerSession && state.qrPairingOpen && state.qrPairingSvg
    ? renderQrPairingDrawer(state.qrPairingSvg, state.qrPairingCopiedNotice, {
        ttlSeconds: state.qrPairingTtlSeconds ?? 120,
        expiresAt: state.qrPairingExpiresAt ?? null,
        scopeLabel: state.qrPairingScope ?? 'DEVICE_READ_AND_EXPLAINER',
      })
    : '';
  const unlockInputType = state.unlockKeyVisible ? 'text' : 'password';
  const unlockDraftVal = e(state.unlockDraft ?? '');
  const unlockVisLabel = state.unlockKeyVisible ? 'Hide' : 'Show';
  const topUnlockBar = !state.liveStreamConnected
    ? `<form class="mobile-unlock-bar prominent-unlock-bar" data-cockpit-unlock-form="true" autocomplete="on"><div class="unlock-bar-row"><label class="sr-only" for="top-cockpit-access-key">Cockpit access key</label><input id="top-cockpit-access-key" class="mobile-unlock-input" type="${unlockInputType}" name="cockpit_access_key" value="${unlockDraftVal}" autocomplete="current-password" spellcheck="false" autocapitalize="off" placeholder="Locked preview — paste Cockpit access key here to connect live 24/7 cloud server"><button type="button" class="button button-small button-secondary unlock-vis-btn" data-toggle-unlock-visibility="true" aria-pressed="${Boolean(state.unlockKeyVisible)}">${unlockVisLabel}</button><button type="submit" class="button button-small button-primary">Unlock Live Cockpit</button></div><p class="unlock-helper-note">Paste your 43-character key from <code>D:\\MetaTrader5\\.cloud_cockpit.token</code> on your PC — or scan the single-use Pairing QR from an unlocked PC</p>${state.aiIssue ? `<p class="unlock-inline-error warning-text" role="alert">${e(state.aiIssue)}</p>` : ''}</form>`
    : (!ownerSession
      ? `<form class="mobile-unlock-bar stepup-unlock-bar" data-cockpit-unlock-form="true" data-stepup-unlock-bar="true" autocomplete="on"><div class="unlock-bar-row"><span class="stepup-lock-label">Paired Read + Explainer Session · Owner Controls Locked</span><label class="sr-only" for="stepup-cockpit-access-key">Primary Owner Key for full control</label><input id="stepup-cockpit-access-key" class="mobile-unlock-input" type="${unlockInputType}" name="cockpit_access_key" value="${unlockDraftVal}" autocomplete="current-password" spellcheck="false" autocapitalize="off" placeholder="Paste Primary Owner Key to step up from Read + Explainer to Owner Full Control"><button type="button" class="button button-small button-secondary unlock-vis-btn" data-toggle-unlock-visibility="true" aria-pressed="${Boolean(state.unlockKeyVisible)}">${unlockVisLabel}</button><button type="submit" class="button button-small button-primary">Step Up to Owner Control</button></div>${state.aiIssue ? `<p class="unlock-inline-error warning-text" role="alert">${e(state.aiIssue)}</p>` : ''}</form>`
      : '');
  const safetyTitle = state.liveStreamConnected
    ? (isLiveArmed ? 'Connected · Live 24/7 Cloud — REAL-MONEY LIVE ARMED' : 'Connected · Live 24/7 Cloud — DEMO PAPER ACCOUNTS (real-money locked)')
    : (state.transport?.attached ? 'Disconnected simulator / explicit scoped bridge' : `Disconnected ${state.source === 'shared fixture' ? 'fixture' : state.source === 'historical snapshot' ? 'historical snapshot' : 'snapshot'} - read only`);
  const safetyCopy = state.liveStreamConnected
    ? 'Authenticated cloud stream attached. Every trade still requires 161-parameter ForexMetaValveGate clearance and independent venue receipts.'
    : (state.transport?.attached ? 'Acceptance is not an effect. Pause and Stop do not close positions or cancel accepted protective stops.' : 'No commands can be sent from this workspace. Effects and permissions need independent receipts.');
  return `<div class="shell"><aside class="sidebar"><a class="brand" href="#operate" aria-label="CAS Forex personal cockpit"><span class="brand-symbol" aria-hidden="true"><span class="brand-line"></span><span class="brand-line brand-line-short"></span></span><span>CAS<span class="brand-caption">FOREX</span></span></a>
    <nav aria-label="Primary">${[['operate', '01', 'Operate'], ['review', '02', 'Review'], ['setup', '03', 'Setup']].map(([key, number, label]) => `<a href="#${key}" class="nav-link${page === key ? ' active' : ''}" ${page === key ? 'aria-current="page"' : ''}><span class="nav-number" aria-hidden="true">${number}</span>${label}<span class="nav-arrow" aria-hidden="true">↗</span></a>`).join('')}</nav>
    <div class="sidebar-foot"><span class="status-dot${state.liveStreamConnected ? '' : ' warning'}" aria-hidden="true"></span><strong>${state.liveStreamConnected ? 'Connected · Live 24/7 Cloud' : 'Disconnected'}</strong><p>${state.liveStreamConnected ? (isLiveArmed ? 'LIVE real-money armed' : 'Live cloud stream attached') : (state.transport?.attached ? 'Scoped simulator only' : 'No execution transport')}</p><span class="version">COCKPIT / 0.1</span></div></aside>
    <div class="workspace"><header class="topbar"><span class="breadcrumb">CAS Forex <span>/</span> ${e(titles[page][1])}</span><div class="topbar-actions">${execModeBadge}${sessionScopeBadge}${pairQrBtn}${tag(sourceLabel)}${state.transport?.attached ? button('Read state', 'data-read-transport="true"', 'button-small') : ''}${button('Toggle theme', 'data-theme-toggle="true"', 'theme-toggle')}</div></header>${renderLiveFeedStrip(state)}
    <main id="main" tabindex="-1"><div class="page-heading"><div><p class="eyebrow">${titles[page][0]}</p><h1>${titles[page][1]}</h1></div><div class="freshness" data-clock-basis="${age.clock_basis}" data-read-invalidated="${age.invalidated}"><span class="status-dot ${age.tone === 'warning' ? 'warning' : ''}" aria-hidden="true"></span><strong>${e(age.label)}</strong><span>${e(age.detail)}</span>${projection?.observed_at ? `<time datetime="${e(projection.observed_at)}">${e(projection.observed_at)}</time>` : ''}</div></div>
    <div class="safety-banner"><span class="safety-mark" aria-hidden="true">!</span><div><strong>${safetyTitle}</strong><span>${safetyCopy}</span></div></div>
    ${topUnlockBar}
    ${qrDrawerMarkup}
    ${renderBankedProfitsHeroBanner(state)}
    ${page !== 'operate' || !projection ? directControls(state.transport) : ''}${transportStatus(state.transport)}
    ${state.error ? `<section class="load-error" role="alert"><h2>Snapshot unavailable</h2><p>${e(state.error)}</p><p>No prior snapshot is shown as current. Controls remain unavailable.</p>${button('Open Setup', 'data-route="setup"')}</section>` : ''}
    ${page === 'setup' ? setup(projection, state) : projection ? (page === 'review' ? review(projection, state) : operate(projection, state)) : `<section class="panel positions-panel" aria-label="Unobserved inventory">${empty('Inventory unknown', state.loading ? 'Reading shared source; no venue inventory observed.' : 'No valid snapshot. Open Setup to read a disconnected source.', '?')}</section>`}
    <footer class="footer"><span>Local UI observation · ${e(projection?.recovery ?? 'UNOBSERVED')}</span><span>Build & runtime verification: NOT_RUN</span></footer></main></div></div>`;
}

export function renderControlDialog(control, transport) {
  const copy = CONTROL_COPY[control];
  if (!copy) throw new Error('Unsupported control.');
  return `<div class="dialog-heading"><p class="eyebrow">CONTROL EXPLANATION</p><h2 id="dialog-title">${e(copy.title)}</h2></div><p>${e(copy.summary)}</p><p>${e(copy.consequence)}</p><div class="dialog-warning"><strong>Explanation only</strong><p>Only an independently read durable fence receipt can confirm a requested barrier. This explanation sends no request.</p></div><div class="dialog-actions">${button('Back', 'data-dialog-close="true"')}</div>${modalInterruption(transport)}`;
}

export function renderCloseDialog(projection, positionId) {
  const review = closeReview(projection, positionId);
  return `<div class="dialog-heading"><p class="eyebrow">EXACT TARGET REVIEW</p><h2 id="dialog-title">Review Close</h2></div><p>This reviews a snapshot target. Current closeable quantity, target version and owner authority must be checked again by core.</p><dl class="metadata">${meta('Account / run', `${review.account_id} / ${review.run_id}`)}${meta('Source state', review.state_id)}${meta('Observed at', review.observed_at)}${meta('Position', review.position_id)}${meta('Version', review.version)}${meta('Instrument / side', `${review.instrument_id} / ${review.side}`)}${meta('Exact snapshot quantity', `${formatDecimal(review.quantity)} BASE_UNITS`)}</dl><div class="dialog-warning"><strong>No close request has been sent</strong><p>${e(review.reason)}</p></div><div class="dialog-actions">${button('Back', 'data-dialog-close="true"')}${button('Request reviewed Close', 'disabled', 'button-primary')}</div>${modalInterruption()}`;
}

export function renderPreparedClose(transport) {
  const close = transport?.close;
  const preview = close?.preview;
  const intent = preview?.intent;
  const q = close?.observation?.receipt?.quantities;
  const canRead = transport?.attached && close?.submitted && preview && !['PREPARING', 'REVIEW_REQUIRED', 'PREPARATION_FAILED', 'CHECKING', 'REQUESTING', 'READING'].includes(close.status);
  return `<div class="dialog-heading"><p class="eyebrow">EXACT TARGET / OWNER REVIEW</p><h2 id="dialog-title">Reviewed Close</h2></div><div role="status"><strong>${e(close?.status ?? 'Unavailable')}</strong><p>${e(close?.reason ?? 'No target prepared.')}</p></div>${preview ? `<dl class="metadata">${meta('Account / run', `${preview.scope.account_id} / ${preview.scope.run_id}`)}${meta('Source state', intent.source_state.state_id)}${meta('Position / version', `${intent.target_id} / ${intent.target_version}`)}${meta('Instrument', intent.instrument_id)}${meta('Exact quantity', `${intent.quantity} BASE_UNITS`)}${meta('Owner request', preview.owner_request_id)}${meta('Command ID', preview.command_id)}${meta('Intent SHA-256', preview.intent_sha256)}${meta('Expires at (simulator)', preview.expires_at)}</dl><details><summary>Full exact intent</summary><pre>${e(JSON.stringify(intent, null, 2))}</pre></details>` : ''}${q ? `<h3>Independent receipt / cumulative base units</h3><dl class="metadata">${Object.entries(q).map(([key, value]) => meta(key, value)).join('')}${meta('Receipt ID', close.observation.receipt.receipt_id)}${meta('Observed at', close.observation.receipt.observed_at)}</dl>` : '<p class="quiet-note">No independent filled quantity established for this request.</p>'}<p class="quiet-note">Close does not resume automation. Partial fills and cancelled remainders stay separate.</p><div class="dialog-actions">${button('Back', 'data-dialog-close="true"')}${button('Request reviewed Close', `data-submit-close="${e(preview?.preview_id ?? '')}" ${transport?.attached && close?.status === 'REVIEW_REQUIRED' ? '' : 'disabled'}`, 'button-primary')}${canRead ? button('Read venue receipt', 'data-read-close="true"') : ''}</div>${modalInterruption(transport)}`;
}
export { renderLiveFeedStrip, renderTacticalValveHud, renderMarketRadarTable, computeValveHudModel, renderAiOverseerPanel, renderAiModelCatalogPanel, renderBankedProfitsHeroBanner, renderAiTopSwitcherBar, renderEquityAndAnalyticsSection, renderParallelTiersSection, renderLiveFundingPanel, renderMasterAggressionDial, renderCompoundingAndHouseMoneyPanel, renderOptionBDemoPanel, renderDemoHighGrowthPanel, resolveCockpitDemoHighGrowth };
