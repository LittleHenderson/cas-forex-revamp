// Pure presentation module for Midnight Blueprint Tactical HUD:
// Live Feed strip, Meta-Valve 0-100 semi-circle SVG gauge, Live AI Decision Console, and 20-Market Radar.
// Strict CSP safe: zero direct markup mutation, zero inline styling attributes, zero network calls.
import { ALL_WATCHLIST_MARKETS, INDEX_INSTRUMENTS, normalizePairSymbol } from './chart.mjs';

export const RADAR_FILTERS = Object.freeze(['all', 'active', 'held', 'indices', 'forex']);

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function numOrNull(raw) {
  if (raw === null || raw === undefined || raw === '') return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

function clamp(val, minVal, maxVal) {
  return Math.max(minVal, Math.min(maxVal, val));
}

function extractTelegramState(state) {
  const src = state?.telegramAlerts ?? state?.aiTrader?.telegramAlerts ?? null;
  if (!src || typeof src !== 'object') {
    return Object.freeze({
      status: 'STANDBY',
      enabled: false,
      configured: false,
      readOnly: true,
      tradingAuthority: 'NONE',
      sentCount: 0,
      errorCount: 0,
      lastEventKind: null,
      recentAlerts: Object.freeze([]),
    });
  }
  const enabled = Boolean(src.enabled);
  const rawRecent = src.recent_alerts ?? src.recentAlerts;
  return Object.freeze({
    status: src.status === 'ACTIVE' || enabled ? 'ACTIVE' : 'STANDBY',
    enabled,
    configured: Boolean(src.configured),
    readOnly: true,
    tradingAuthority: 'NONE',
    sentCount: Number.isSafeInteger(src.sent_count ?? src.sentCount) ? (src.sent_count ?? src.sentCount) : 0,
    errorCount: Number.isSafeInteger(src.error_count ?? src.errorCount) ? (src.error_count ?? src.errorCount) : 0,
    lastEventKind: src.last_event_kind ?? src.lastEventKind ?? null,
    recentAlerts: Object.freeze(Array.isArray(rawRecent) ? rawRecent.slice(0, 6) : []),
  });
}

function buildQuoteMap(state) {
  const map = new Map();
  const ingest = (items) => {
    if (!Array.isArray(items)) return;
    for (const row of items) {
      if (!row || typeof row !== 'object') continue;
      const sym = normalizePairSymbol(String(row.pair ?? '')) || String(row.pair ?? '').toUpperCase();
      if (sym) map.set(sym, row);
    }
  };
  ingest(state?.marketStream?.streams);
  ingest(state?.marketStream?.markets);
  ingest(state?.indexStream?.markets);
  return map;
}

function computeSpreadBps(quoteRow) {
  if (!quoteRow) return null;
  if (quoteRow.spread_bps !== undefined && quoteRow.spread_bps !== null) {
    const s = numOrNull(quoteRow.spread_bps);
    if (s !== null) return s;
  }
  const bid = numOrNull(quoteRow.bid);
  const ask = numOrNull(quoteRow.ask);
  if (bid !== null && ask !== null && bid > 0 && ask >= bid) {
    const mid = (bid + ask) / 2;
    return Number((((ask - bid) / mid) * 10000).toFixed(2));
  }
  return null;
}

export function computeValveHudModel(state) {
  const connected = Boolean(state?.liveStreamConnected && state?.aiTrader?.connected);
  const ai = state?.aiTrader ?? null;
  const br = state?.brokerRouting ?? null;
  const dhg = state?.demoHighGrowth ?? null;
  const telegram = extractTelegramState(state);

  if (!connected || !ai) {
    return Object.freeze({
      connected: false,
      score: null,
      verdict: 'STANDBY',
      verdictTone: 'standby',
      checks: Object.freeze([
        Object.freeze({ id: 'valve', label: 'Valve Signal', score: 0, max: 30, tone: 'standby', detail: 'Awaiting live AI cycle' }),
        Object.freeze({ id: 'spread', label: 'Spread Quality', score: 0, max: 20, tone: 'standby', detail: 'Awaiting market feed' }),
        Object.freeze({ id: 'trend', label: 'Trend Alignment', score: 0, max: 20, tone: 'standby', detail: 'Awaiting regime scan' }),
        Object.freeze({ id: 'drawdown', label: 'Drawdown Room', score: 0, max: 15, tone: 'standby', detail: 'Awaiting equity readback' }),
        Object.freeze({ id: 'quota', label: 'Margin & Quota', score: 0, max: 15, tone: 'standby', detail: 'Awaiting venue check' }),
      ]),
      reasons: Object.freeze([
        Object.freeze({ tone: 'warn', label: 'STANDBY', text: 'Unlock Live Cockpit to stream live Meta-Valve scores and 20-market checks.' }),
      ]),
      decisionLog: Object.freeze([]),
      telegram,
    });
  }

  const rawValve = numOrNull(ai.lastValveScore);
  const threshold = numOrNull(ai.valveThreshold) ?? 0.55;
  let valvePts = 15;
  if (rawValve !== null) {
    valvePts = Math.round(clamp(rawValve / 1.0, 0, 1) * 30);
  }
  const valveTone = rawValve === null ? 'warn' : (rawValve >= threshold ? 'ok' : 'danger');
  const valveDetail = rawValve === null ? 'Awaiting proposal' : `${rawValve.toFixed(2)} vs ${threshold.toFixed(2)} gate`;

  const qMap = buildQuoteMap(state);
  const focusSym = normalizePairSymbol(ai.currentFocusSymbol ?? ai.lastSymbol ?? 'NAS100') || 'NAS100';
  const focusQuote = qMap.get(focusSym);
  const spreadBps = computeSpreadBps(focusQuote);
  const spreadCap = INDEX_INSTRUMENTS.includes(focusSym) ? 150 : 30;
  let spreadPts = 12;
  let spreadTone = 'warn';
  let spreadDetail = `${focusSym} spread unknown`;
  if (spreadBps !== null) {
    if (spreadBps <= spreadCap * 0.4) {
      spreadPts = 20;
      spreadTone = 'ok';
    } else if (spreadBps <= spreadCap) {
      spreadPts = 14;
      spreadTone = 'ok';
    } else {
      spreadPts = 4;
      spreadTone = 'danger';
    }
    spreadDetail = `${focusSym} ${spreadBps.toFixed(1)} bps (cap ${spreadCap})`;
  }

  const regime = String(ai.lastRegime ?? 'SCANNING').toUpperCase();
  let trendPts = 12;
  let trendTone = 'warn';
  if (regime.includes('TREND_IGNITION') || regime.includes('TREND_CONTINUATION')) {
    trendPts = 20;
    trendTone = 'ok';
  } else if (regime.includes('PULLBACK')) {
    trendPts = 14;
    trendTone = 'ok';
  } else if (regime.includes('CHOP')) {
    trendPts = 6;
    trendTone = 'warn';
  } else if (regime.includes('SPREAD_SPIKE')) {
    trendPts = 0;
    trendTone = 'danger';
  }

  const ddRaw = numOrNull(br?.shield?.drawdownPct);
  const maxDd = dhg?.enabled ? 0.30 : 0.10;
  let ddPts = 12;
  let ddTone = 'ok';
  let ddDetail = 'Within ceiling';
  if (ddRaw !== null) {
    const usedRatio = clamp(ddRaw / Math.max(0.01, maxDd), 0, 1.2);
    ddPts = Math.round(clamp(1 - usedRatio * 0.85, 0, 1) * 15);
    ddTone = usedRatio >= 0.85 ? 'danger' : (usedRatio >= 0.55 ? 'warn' : 'ok');
    ddDetail = `${(ddRaw * 100).toFixed(2)}% / ${(maxDd * 100).toFixed(0)}% max`;
  }

  const quotaStatus = String(ai.dailyQuota?.status ?? 'OPEN').toUpperCase();
  const offlineCount = Array.isArray(ai.offlineBrokers) ? ai.offlineBrokers.length : 0;
  let quotaPts = quotaStatus === 'OPEN' ? 15 : (quotaStatus === 'SOFT_QUOTA_REACHED' ? 11 : 4);
  if (offlineCount > 0) quotaPts = Math.max(4, quotaPts - 3);
  const quotaTone = quotaPts >= 11 ? 'ok' : (quotaPts >= 7 ? 'warn' : 'danger');
  const quotaDetail = `${quotaStatus} · ${3 - Math.min(3, offlineCount)}/3 venues`;

  const checks = Object.freeze([
    Object.freeze({ id: 'valve', label: 'Valve Signal', score: valvePts, max: 30, tone: valveTone, detail: valveDetail }),
    Object.freeze({ id: 'spread', label: 'Spread Quality', score: spreadPts, max: 20, tone: spreadTone, detail: spreadDetail }),
    Object.freeze({ id: 'trend', label: 'Trend Alignment', score: trendPts, max: 20, tone: trendTone, detail: `${regime}` }),
    Object.freeze({ id: 'drawdown', label: 'Drawdown Room', score: ddPts, max: 15, tone: ddTone, detail: ddDetail }),
    Object.freeze({ id: 'quota', label: 'Margin & Quota', score: quotaPts, max: 15, tone: quotaTone, detail: quotaDetail }),
  ]);

  const totalScore = clamp(valvePts + spreadPts + trendPts + ddPts + quotaPts, 0, 100);
  let verdict = 'HOLD';
  let verdictTone = 'danger';
  if (totalScore >= 80) {
    verdict = 'CLEAR';
    verdictTone = 'ok';
  } else if (totalScore >= 60) {
    verdict = 'CAUTIOUS';
    verdictTone = 'ok';
  } else if (totalScore >= 40) {
    verdict = 'GUARDED';
    verdictTone = 'warn';
  }

  const reasons = [];
  if (ai.respiteMode || quotaStatus === 'PROFIT_FLOOR_LOCKED') {
    reasons.push(Object.freeze({ tone: 'ok', label: 'PROFIT LOCK', text: 'Research Respite active — session profits locked safely.' }));
  } else if (String(ai.capitalStatus ?? '') === 'RECOVERY_MODE') {
    reasons.push(Object.freeze({ tone: 'warn', label: 'RECOVERY', text: `Online equity recovery mode active (${ai.netSurplusPct ?? '-'}% vs baseline).` }));
  }
  if (regime.includes('CHOP') || regime.includes('SPREAD_SPIKE')) {
    reasons.push(Object.freeze({ tone: 'warn', label: 'REGIME HOLD', text: `${regime} active — spike-chasing entries blocked until clean trend.` }));
  }
  if (String(ai.lastAction ?? '') === 'VETOED') {
    reasons.push(Object.freeze({ tone: 'danger', label: 'VALVE VETO', text: ai.lastReason ?? 'Latest proposal vetoed by 161-parameter Meta-Valve.' }));
  }
  if (offlineCount > 0) {
    reasons.push(Object.freeze({ tone: 'warn', label: 'VENUE EXCLUDED', text: `${offlineCount} offline venue(s) (${(ai.offlineBrokerLabels ?? ai.offlineBrokers).join(', ')}) excluded from starting capital.` }));
  }
  if (!reasons.length) {
    reasons.push(Object.freeze({ tone: 'ok', label: 'ARMED', text: 'All 161-parameter Meta-Valve gates online with 1.00R winner protection active.' }));
  }

  const decisionLog = (Array.isArray(ai.recentActions) ? ai.recentActions : []).slice(0, 8).map((act) => {
    const kind = String(act.kind ?? 'INFO').toUpperCase();
    let tone = 'info';
    if (kind.includes('OPEN') || kind.includes('REPLENISH') || kind.includes('BREAKEVEN')) tone = 'ok';
    else if (kind.includes('WAIT') || kind.includes('RESPITE')) tone = 'warn';
    else if (kind.includes('VETO') || kind.includes('BLOCK') || kind.includes('STOP')) tone = 'danger';
    return Object.freeze({
      observedAt: act.observedAt ?? '',
      kind,
      symbol: act.symbol || 'PORTFOLIO',
      detail: act.detail ?? '',
      tone,
    });
  });

  return Object.freeze({
    connected: true,
    score: totalScore,
    verdict,
    verdictTone,
    checks,
    reasons: Object.freeze(reasons),
    decisionLog: Object.freeze(decisionLog),
    telegram,
  });
}

function buildGaugeNeedleCoords(score) {
  const cx = 110;
  const cy = 108;
  const r = 68;
  const pct = score === null ? 0 : clamp(score, 0, 100) / 100;
  const rad = Math.PI * (1 - pct);
  const x2 = (cx + r * Math.cos(rad)).toFixed(2);
  const y2 = (cy - r * Math.sin(rad)).toFixed(2);
  return { x2, y2 };
}

export function renderLiveFeedStrip(state) {
  const connected = Boolean(state?.liveStreamConnected);
  const ai = state?.aiTrader ?? null;
  const ob = state?.optionBDemo ?? null;
  const pt = state?.parallelTiers ?? null;
  const tg = extractTelegramState(state);
  const positions = Array.isArray(ai?.openPositions) ? ai.openPositions : [];

  const items = [];
  if (connected && ai?.connected) {
    items.push(`<span class="live-feed-item"><strong class="live-feed-tag tag-info">${esc(ai.lastRegime ?? 'SCANNING')}</strong><span>${esc(ai.currentFocusStatus ?? 'Scanning 20 markets')}</span></span>`);
    for (const pos of positions.slice(0, 3)) {
      const prof = numOrNull(pos.profit);
      const cls = prof !== null && prof < 0 ? 'tag-danger' : 'tag-ok';
      items.push(`<span class="live-feed-item"><strong class="live-feed-tag ${cls}">OPEN ${esc(pos.symbol)} ${esc(pos.side)}</strong><span>${esc(pos.volumeLots)} lots · ${esc(pos.protectionStage)} (${esc(pos.profit)} USD)</span></span>`);
    }
    const refillOn = Boolean(ob?.autoReplenishEnabled ?? true) && Boolean(pt?.autoReplenishEnabled ?? true);
    const floorPct = ob?.autoReplenishFloorPct ?? pt?.autoReplenishFloorPct ?? '70.00';
    items.push(`<span class="live-feed-item"><strong class="live-feed-tag ${refillOn ? 'tag-ok' : 'tag-warn'}">${refillOn ? 'AUTO-REFILL' : 'MANUAL'}</strong><span>${esc(floorPct)}% DEMO floor armed</span></span>`);
  } else {
    items.push('<span class="live-feed-item"><strong class="live-feed-tag tag-warn">STANDBY</strong><span>Disconnected preview — unlock Live Cockpit to stream live trades and AI checks.</span></span>');
  }

  return `<section class="tactical-live-feed" data-tactical-live-feed="true" aria-label="Live trading feed"><div class="live-feed-badge ${connected ? 'is-live' : 'is-standby'}"><span class="live-feed-dot" aria-hidden="true"></span><span>${connected ? 'LIVE FEED' : 'STANDBY'}</span></div><div class="live-feed-items">${items.join('')}</div><div class="live-feed-tg-pill ${tg.status === 'ACTIVE' ? 'is-active' : 'is-standby'}"><span>TELEGRAM: ${esc(tg.status)}</span></div></section>`;
}

export function renderTacticalValveHud(state) {
  const hud = computeValveHudModel(state);
  const ai = state?.aiTrader ?? null;
  const needle = buildGaugeNeedleCoords(hud.score);
  const scoreDisplay = hud.score === null ? 'N/A' : String(hud.score);

  const checkRows = hud.checks.map((chk) => {
    const fillW = hud.score === null ? 0 : Math.round((chk.score / Math.max(1, chk.max)) * 120);
    return `<li class="hud-check-row"><div class="hud-check-head"><span class="hud-check-label">${esc(chk.label)}</span><span class="hud-check-score">${hud.score === null ? 'N/A' : `${chk.score} / ${chk.max}`}</span></div><svg class="valve-bar-svg" viewBox="0 0 120 8" role="img" aria-label="${esc(chk.label)} ${chk.score} of ${chk.max}"><rect class="valve-bar-track" x="0" y="0" width="120" height="8" rx="2"/><rect class="valve-bar-fill tone-${esc(chk.tone)}" x="0" y="0" width="${fillW}" height="8" rx="2"/></svg><span class="hud-check-detail">${esc(chk.detail)}</span></li>`;
  }).join('');

  const reasonCards = hud.reasons.map((rsn) => `<div class="hud-reason-card tone-${esc(rsn.tone)}"><strong>${esc(rsn.label)}</strong><span>${esc(rsn.text)}</span></div>`).join('');

  const logRows = hud.decisionLog.length
    ? hud.decisionLog.map((entry) => `<li class="console-line tone-${esc(entry.tone)}"><span class="console-ts">${esc(entry.observedAt.slice(11, 19) || '--:--:--')}</span><span class="console-kind">${esc(entry.kind)}</span><span class="console-sym">${esc(entry.symbol)}</span><span class="console-msg">${esc(entry.detail)}</span></li>`).join('')
    : '<li class="console-line tone-warn"><span class="console-ts">--:--:--</span><span class="console-kind">STANDBY</span><span class="console-sym">20 MARKETS</span><span class="console-msg">No live AI cycles observed yet in this tab.</span></li>';

  const tgSummaryText = hud.telegram.status === 'ACTIVE'
    ? `ACTIVE · ${hud.telegram.sentCount} sent · READ-ONLY (0 trading power)`
    : 'STANDBY (Disabled by default · Set env vars to enable · READ-ONLY)';

  return `<section class="panel tactical-valve-hud" id="tactical-valve-hud" data-tactical-valve-hud="true" aria-labelledby="tactical-valve-heading"><div class="section-heading"><div><p class="eyebrow">TACTICAL HUD · 161-PARAMETER SAFETY GATE</p><h2 id="tactical-valve-heading">Meta-Valve Readiness &amp; Live AI Decision Log</h2></div><span class="tag verdict-pill tone-${esc(hud.verdictTone)}">${esc(hud.verdict)}</span></div><div class="tactical-hud-grid"><div class="hud-gauge-col"><div class="hud-gauge-card"><svg class="valve-gauge-svg" viewBox="0 0 220 130" role="img" aria-label="Meta-Valve Score ${esc(scoreDisplay)} out of 100"><path class="gauge-arc gauge-arc-danger" d="M 24 108 A 86 86 0 0 1 83 26" fill="none" stroke-width="12" stroke-linecap="round"/><path class="gauge-arc gauge-arc-warn" d="M 88 24 A 86 86 0 0 1 160 36" fill="none" stroke-width="12" stroke-linecap="round"/><path class="gauge-arc gauge-arc-ok" d="M 165 40 A 86 86 0 0 1 196 108" fill="none" stroke-width="12" stroke-linecap="round"/><line class="valve-gauge-needle" x1="110" y1="108" x2="${needle.x2}" y2="${needle.y2}" stroke-width="3" stroke-linecap="round"/><circle class="valve-gauge-hub" cx="110" cy="108" r="5"/><text class="gauge-end-label" x="20" y="124">0</text><text class="gauge-end-label" x="184" y="124">100</text></svg><div class="hud-score-readout"><strong class="hud-score-number">${esc(scoreDisplay)}</strong><span>${hud.score === null ? 'UNOBSERVED · CONNECT LIVE SERVER' : '100 = CLEANEST SAFETY ALIGNMENT'}</span></div></div><ul class="hud-checks-list">${checkRows}</ul><div class="hud-reason-stack">${reasonCards}</div></div><div class="hud-console-col"><div class="ai-decision-console"><div class="console-header"><span>LIVE AI DECISION CONSOLE</span><span>${ai?.connected ? `${esc(ai.activeDisplayName)} · ${esc(ai.thinkingDepth)} · cycle #${esc(ai.cycleCount)}` : 'OFFLINE PREVIEW'}</span></div><ul class="console-lines">${logRows}</ul><div class="console-footer"><span>TELEGRAM ALERTS (READ-ONLY):</span><span>${esc(tgSummaryText)}</span></div></div></div></div></section>`;
}

export function renderMarketRadarTable(state) {
  const filter = RADAR_FILTERS.includes(state?.radarFilter) ? state.radarFilter : 'all';
  const connected = Boolean(state?.liveStreamConnected);
  const ai = state?.aiTrader ?? null;
  const qMap = buildQuoteMap(state);
  const openPosBySym = new Map();
  for (const pos of (Array.isArray(ai?.openPositions) ? ai.openPositions : [])) {
    const sym = normalizePairSymbol(pos.symbol) || String(pos.symbol ?? '').toUpperCase();
    if (sym) openPosBySym.set(sym, pos);
  }
  const latestActionBySym = new Map();
  for (const act of (Array.isArray(ai?.recentActions) ? ai.recentActions : [])) {
    const sym = normalizePairSymbol(act.symbol) || String(act.symbol ?? '').toUpperCase();
    if (sym && !latestActionBySym.has(sym)) latestActionBySym.set(sym, act);
  }

  const quotaLocked = Boolean(ai?.respiteMode) || ['PROFIT_FLOOR_LOCKED', 'DAILY_QUOTA_LOCKED', 'DAILY_LOSS_TRIPPED'].includes(String(ai?.dailyQuota?.status ?? '').toUpperCase());
  const regime = String(ai?.lastRegime ?? 'SCANNING').toUpperCase();

  const rows = ALL_WATCHLIST_MARKETS.map((sym) => {
    const isIdx = INDEX_INSTRUMENTS.includes(sym);
    const quote = qMap.get(sym) ?? null;
    const bidStr = quote?.bid ? String(quote.bid) : 'N/A';
    const askStr = quote?.ask ? String(quote.ask) : 'N/A';
    const spreadBps = computeSpreadBps(quote);
    const spreadCap = isIdx ? 150 : 30;
    const pos = openPosBySym.get(sym) ?? null;
    const act = latestActionBySym.get(sym) ?? null;

    let badge = 'STANDBY';
    let tone = 'standby';
    let held = false;
    let reason = 'Awaiting live feed';

    if (pos) {
      badge = 'OPEN';
      tone = 'open';
      reason = `${pos.side} ${pos.volumeLots} lots · ${pos.protectionStage} (${pos.profit} USD)`;
    } else if (connected && quote) {
      if (quotaLocked) {
        badge = 'HELD';
        tone = 'held';
        held = true;
        reason = 'HELD · Profit lock / Research Respite active';
      } else if (spreadBps !== null && spreadBps > spreadCap) {
        badge = 'HELD';
        tone = 'held';
        held = true;
        reason = `HELD · spread ${spreadBps.toFixed(1)} bps > ${spreadCap} cap`;
      } else if (act && ['VETOED', 'WAIT', 'BLOCKED'].includes(String(act.kind ?? '').toUpperCase())) {
        badge = 'HELD';
        tone = 'held';
        held = true;
        reason = `HELD · ${String(act.detail ?? 'Blocked by safety filter').slice(0, 72)}`;
      } else if (regime.includes('CHOP') && ai?.lastSymbol === sym) {
        badge = 'HELD';
        tone = 'held';
        held = true;
        reason = `HELD · ${regime} chop gate`;
      } else {
        badge = 'PASS';
        tone = 'ok';
        reason = spreadBps !== null ? `Spread ${spreadBps.toFixed(1)} bps · Clear` : 'Feed live · Clear';
      }
    }

    const spreadFill = spreadBps === null ? 0 : Math.round(clamp(spreadBps / spreadCap, 0, 1) * 60);
    return Object.freeze({
      sym,
      category: isIdx ? 'INDEX' : 'FOREX',
      bidStr,
      askStr,
      spreadStr: spreadBps === null ? 'N/A' : `${spreadBps.toFixed(1)} bps`,
      spreadFill,
      badge,
      tone,
      held,
      reason,
      selected: state?.chartPair === sym,
    });
  });

  const filtered = rows.filter((r) => {
    if (filter === 'active') return r.badge === 'PASS' || r.badge === 'OPEN';
    if (filter === 'held') return r.badge === 'HELD';
    if (filter === 'indices') return r.category === 'INDEX';
    if (filter === 'forex') return r.category === 'FOREX';
    return true;
  });

  const heldCount = rows.filter((r) => r.badge === 'HELD').length;
  const openCount = rows.filter((r) => r.badge === 'OPEN').length;
  const passCount = rows.filter((r) => r.badge === 'PASS').length;

  const filterButtons = [
    ['all', `ALL (${rows.length})`],
    ['active', `PASS / OPEN (${passCount + openCount})`],
    ['held', `HELD (${heldCount})`],
    ['indices', 'INDICES & GOLD (4)'],
    ['forex', 'FOREX (16)'],
  ].map(([key, label]) => `<button type="button" class="button button-small radar-filter-btn${filter === key ? ' is-active' : ''}" data-radar-filter="${key}" aria-pressed="${filter === key}">${esc(label)}</button>`).join('');

  const bodyRows = filtered.length
    ? filtered.map((r) => `<tr class="radar-row${r.held ? ' radar-row-held' : ''}${r.selected ? ' radar-row-selected' : ''}"><td><strong>${esc(r.sym)}</strong> <span class="radar-cat">${esc(r.category)}</span></td><td class="mono-num">${esc(r.bidStr)}</td><td class="mono-num">${esc(r.askStr)}</td><td class="mono-num"><div class="radar-spread-cell"><span>${esc(r.spreadStr)}</span><svg class="radar-spread-svg" viewBox="0 0 60 6" aria-hidden="true"><rect class="valve-bar-track" x="0" y="0" width="60" height="6" rx="2"/><rect class="valve-bar-fill tone-${r.tone === 'held' ? 'warn' : 'ok'}" x="0" y="0" width="${r.spreadFill}" height="6" rx="2"/></svg></div></td><td><span class="radar-badge radar-badge-${esc(r.tone)}">${esc(r.badge)}</span></td><td class="radar-reason-cell">${esc(r.reason)}</td><td><button type="button" class="button button-small radar-inspect-btn" data-radar-inspect="${esc(r.sym)}">INSPECT</button></td></tr>`).join('')
    : '<tr><td colspan="7" class="radar-empty">No markets match this Radar filter.</td></tr>';

  return `<section class="panel market-radar-panel" id="market-radar-section" data-market-radar="true" aria-labelledby="market-radar-heading"><div class="section-heading"><div><p class="eyebrow">20-MARKET RADAR · SPREAD &amp; HELD TELEMETRY</p><h2 id="market-radar-heading">All 20 Markets · Live PASS / HELD Scanner</h2></div><div class="radar-summary-pills"><span class="tag">${openCount} OPEN · ${passCount} PASS · ${heldCount} HELD</span></div></div><div class="radar-filter-bar" role="group" aria-label="Market radar filter">${filterButtons}</div><div class="radar-table-wrap"><table class="radar-table"><thead><tr><th>Market</th><th>Bid</th><th>Ask</th><th>Spread</th><th>Gate</th><th>Status / Held Reason</th><th>Chart</th></tr></thead><tbody>${bodyRows}</tbody></table></div></section>`;
}
