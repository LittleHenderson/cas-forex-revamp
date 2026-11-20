// PR #28 UI Test Suite: Strict-CSP 60fps Compounding Mode, House-Money Milestone Alert
// & Live News Shield Panel (flat top-level node:test cases, zero inline styles, zero eval).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  COMPOUNDING_PANEL_SCHEMA,
  COMPOUNDING_MODES,
  HOUSE_MONEY_STATUSES,
  STATIC_COMPOUNDING_PANEL,
  COMPOUNDING_PANEL_CSS_SNIPPET,
  normalizeCompoundingPanel,
  renderCompoundingAndHouseMoneyPanel,
  patchCompoundingPanelInPlace,
  formatExactUsd,
  formatExactPct,
  formatSweepRatioPct,
  computePctBucket,
  computeHouseMoneyProgressPct,
} from '../../ui/src/compounding-panel.mjs';

function createStrictMockElement(initialClasses = [], initialAttrs = {}) {
  const classes = new Set(initialClasses);
  const attrs = new Map(Object.entries(initialAttrs));
  let text = '';
  let disabledFlag = false;
  let markupWrites = 0;
  let styleWrites = 0;

  const el = {
    get className() {
      return Array.from(classes).join(' ');
    },
    set className(val) {
      classes.clear();
      for (const tok of String(val ?? '').split(/\s+/).filter(Boolean)) {
        classes.add(tok);
      }
    },
    classList: {
      add(...tokens) {
        for (const t of tokens) classes.add(t);
      },
      remove(...tokens) {
        for (const t of tokens) classes.delete(t);
      },
      contains(token) {
        return classes.has(token);
      },
    },
    get textContent() {
      return text;
    },
    set textContent(val) {
      text = String(val ?? '');
    },
    get disabled() {
      return disabledFlag;
    },
    set disabled(val) {
      disabledFlag = Boolean(val);
    },
    getAttribute(name) {
      return attrs.has(name) ? attrs.get(name) : null;
    },
    setAttribute(name, value) {
      if (String(name).toLowerCase() === 'style') {
        styleWrites += 1;
        throw new Error('CSP violation: style attribute write prohibited');
      }
      attrs.set(name, String(value));
    },
    removeAttribute(name) {
      attrs.delete(name);
    },
    get _markupWrites() {
      return markupWrites;
    },
    get _styleWrites() {
      return styleWrites;
    },
  };

  Object.defineProperty(el, 'innerHTML', {
    get() {
      return '';
    },
    set() {
      markupWrites += 1;
      throw new Error('No-flicker violation: innerHTML teardown prohibited');
    },
  });

  Object.defineProperty(el, 'outerHTML', {
    get() {
      return '';
    },
    set() {
      markupWrites += 1;
      throw new Error('No-flicker violation: outerHTML teardown prohibited');
    },
  });

  Object.defineProperty(el, 'style', {
    get() {
      return new Proxy({}, {
        set() {
          styleWrites += 1;
          throw new Error('CSP violation: inline style mutation prohibited');
        },
      });
    },
    set() {
      styleWrites += 1;
      throw new Error('CSP violation: inline style assignment prohibited');
    },
  });

  return el;
}

function createStrictMockPanelRoot() {
  const fields = {
    brokers: createStrictMockElement(['compound-brokers']),
    ownerLockBadge: createStrictMockElement(['compound-pill', 'compound-owner-lock-pill', 'is-hidden'], { 'aria-hidden': 'true' }),
    newsShieldPill: createStrictMockElement(['compound-news-pill', 'is-clear'], { 'data-news-status': 'CLEAR' }),
    newsShieldHeadline: createStrictMockElement(['compound-news-headline']),
    newsShieldMeta: createStrictMockElement(['compound-news-meta']),
    modeSwitch: createStrictMockElement(['compound-switch', 'is-on'], { role: 'switch', 'aria-checked': 'true', 'data-compounding-action': 'TOGGLE_FULL_100' }),
    modeSwitchLabel: createStrictMockElement(['compound-switch-label']),
    modeSummary: createStrictMockElement(['compound-mode-summary']),
    startingPrincipalUsd: createStrictMockElement(['compound-metric-value']),
    currentEquityUsd: createStrictMockElement(['compound-metric-value']),
    houseMoneyTargetUsd: createStrictMockElement(['compound-metric-value']),
    effectiveVaultSweepRatio: createStrictMockElement(['compound-metric-value']),
    progressPctText: createStrictMockElement(['compound-progress-pct']),
    remainingText: createStrictMockElement(['compound-progress-remaining']),
    progressTrack: createStrictMockElement(['compound-progress-track'], { role: 'progressbar', 'aria-valuenow': '0' }),
    progressFill: createStrictMockElement(['compound-progress-fill', 'compound-pct-0', 'is-status-compounding']),
    houseMoneyBanner: createStrictMockElement(['compound-house-banner', 'is-hidden'], { 'aria-hidden': 'true' }),
    houseMoneyBannerText: createStrictMockElement(['compound-house-banner-text']),
    ackWithdrawBtn: createStrictMockElement(['compound-ack-btn', 'is-hidden'], { 'aria-hidden': 'true', 'data-compounding-action': 'ACK_PRINCIPAL_WITHDRAWN' }),
    houseMoneyBadge: createStrictMockElement(['compound-house-badge', 'is-hidden'], { 'aria-hidden': 'true' }),
    houseMoneyBadgeTitle: createStrictMockElement(['compound-house-badge-title']),
    houseMoneyBadgeSub: createStrictMockElement(['compound-house-badge-sub']),
  };

  const panelEl = createStrictMockElement(['panel', 'compounding-panel'], {
    'data-compounding-panel': 'true',
    'data-compounding-schema': COMPOUNDING_PANEL_SCHEMA,
  });

  panelEl.querySelector = (selector) => {
    if (selector === '[data-compounding-panel="true"]') return panelEl;
    const m = /^\[data-compounding-field="([^"]+)"\]$/.exec(selector);
    if (m && Object.prototype.hasOwnProperty.call(fields, m[1])) {
      return fields[m[1]];
    }
    return null;
  };

  return { panelEl, fields };
}

test('CP01 STATIC_COMPOUNDING_PANEL and exact string decimal formatting never round or use float money', () => {
  assert.equal(STATIC_COMPOUNDING_PANEL.schema, 'cas-forex.compounding-controller/1');
  assert.deepEqual(COMPOUNDING_MODES, ['FULL_COMPOUND_100', 'BALANCED_SPLIT_50_50', 'CUSTOM_SPLIT']);
  assert.deepEqual(HOUSE_MONEY_STATUSES, [
    'BUILDING_TOWARD_PRINCIPAL',
    'COMPOUNDING_TO_DOUBLE',
    'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL',
    'PLAYING_ON_HOUSE_MONEY',
  ]);
  assert.equal(formatExactUsd('5000.00'), '$5,000.00');
  assert.equal(formatExactUsd('10000.00'), '$10,000.00');
  assert.equal(formatExactUsd('12345.6789'), '$12,345.6789');
  assert.equal(formatExactUsd('-425.10'), '-$425.10');
  assert.equal(formatExactPct('50.00'), '50.00%');
  assert.equal(formatSweepRatioPct('0.00'), '0%');
  assert.equal(formatSweepRatioPct('0.50'), '50%');
  assert.equal(formatSweepRatioPct('0.125'), '12.5%');
  assert.equal(computeHouseMoneyProgressPct('5000.00', '7500.00', '10000.00'), '50.00');
  assert.equal(computePctBucket('0.00'), 0);
  assert.equal(computePctBucket('50.00'), 50);
  assert.equal(computePctBucket('48.75'), 50);
  assert.equal(computePctBucket('100.00'), 100);
});

test('CP02 normalizeCompoundingPanel handles Python snake_case controller + NewsShockShield snapshots', () => {
  const pySnapshot = {
    schema: 'cas-forex.compounding-controller/1',
    compounding_mode: 'FULL_COMPOUND_100',
    starting_principal_usd: '5000.00',
    current_equity_usd: '7500.00',
    compounding_target_usd: '10000.00',
    house_money_target_usd: '10000.00',
    house_money_status: 'COMPOUNDING_TO_DOUBLE',
    house_money_ready: false,
    suggested_principal_pullout_usd: '0.00',
    progress_to_house_money_pct: '50.00',
    remaining_to_house_money_usd: '2500.00',
    effective_vault_sweep_ratio: '0.00',
    audit_chain_valid: true,
    news_shield: {
      overall_status: 'PAUSED_NEWS_WINDOW',
      pre_minutes: 5,
      post_minutes: 5,
      protective_actions_always_allowed: true,
      symbols: {
        NAS100: {
          normalized_symbol: 'NAS100',
          new_entries_allowed: false,
          protective_actions_allowed: true,
          active_blocking_events: [{ title: 'US CPI YoY', category: 'CPI' }],
          resume_at_utc: '2026-11-20T13:35:00Z',
        },
        US30: {
          normalized_symbol: 'US30',
          new_entries_allowed: false,
          protective_actions_allowed: true,
          active_blocking_events: [{ title: 'US CPI YoY', category: 'CPI' }],
          resume_at_utc: '2026-11-20T13:35:00Z',
        },
      },
    },
  };

  const norm = normalizeCompoundingPanel(pySnapshot);
  assert.equal(norm.schema, COMPOUNDING_PANEL_SCHEMA);
  assert.equal(norm.mode, 'FULL_COMPOUND_100');
  assert.equal(norm.isFullCompound, true);
  assert.equal(norm.startingPrincipalUsd, '5000.00');
  assert.equal(norm.currentEquityUsd, '7500.00');
  assert.equal(norm.houseMoneyTargetUsd, '10000.00');
  assert.equal(norm.progressToHouseMoneyPct, '50.00');
  assert.equal(norm.progressBucket, 50);
  assert.equal(norm.remainingToHouseMoneyUsd, '2500.00');
  assert.equal(norm.effectiveVaultSweepRatio, '0.00');
  assert.equal(norm.newsShield.paused, true);
  assert.equal(norm.newsShield.blockingTitle, 'US CPI YoY');
  assert.equal(norm.newsShield.resumeAtUtc, '2026-11-20T13:35:00Z');
  assert.deepEqual(norm.newsShield.affectedSymbols, ['NAS100', 'US30']);
  assert.equal(norm.newsShield.protectiveActionsAlwaysAllowed, true);
});

test('CP03 ZERO inline style= attributes across ALL states (underwater, compounding, ready, house money, news paused, read-only)', () => {
  const states = [
    // 1. Underwater recovery lock
    {
      mode: 'BALANCED_SPLIT_50_50',
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '4600.00',
      houseMoneyTargetUsd: '10000.00',
      houseMoneyStatus: 'BUILDING_TOWARD_PRINCIPAL',
      effectiveVaultSweepRatio: '0.50', // must clamp to 0.00 while underwater
    },
    // 2. Compounding midway
    {
      mode: 'FULL_COMPOUND_100',
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '7500.00',
      houseMoneyTargetUsd: '10000.00',
    },
    // 3. House-Money Ready ($5,000 -> $10,000)
    {
      mode: 'FULL_COMPOUND_100',
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '10000.00',
      houseMoneyTargetUsd: '10000.00',
      houseMoneyStatus: 'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL',
      houseMoneyReady: true,
      suggestedPrincipalPulloutUsd: '5000.00',
    },
    // 4. Playing on 100% House Money
    {
      mode: 'BALANCED_SPLIT_50_50',
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '10500.00',
      houseMoneyTargetUsd: '10000.00',
      houseMoneyStatus: 'PLAYING_ON_HOUSE_MONEY',
      principalWithdrawnAcknowledged: true,
      principalWithdrawnUsd: '5000.00',
    },
    // 5. Custom Split + Live News Pause
    {
      mode: 'CUSTOM_SPLIT',
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '8250.00',
      effectiveVaultSweepRatio: '0.25',
      newsShield: {
        paused: true,
        blockingTitle: 'FOMC Rate Decision',
        resumeAtUtc: '2026-11-20T19:05:00Z',
        affectedSymbols: ['NAS100', 'US30', 'EURUSD'],
      },
    },
    // 6. Owner Read-Only Tablet (PR #25 Finding [2])
    {
      mode: 'FULL_COMPOUND_100',
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '10000.00',
      houseMoneyReady: true,
      ownerControlsAllowed: false,
      sessionScope: 'DEVICE_READ_AND_EXPLAINER',
    },
  ];

  for (const s of states) {
    const html = renderCompoundingAndHouseMoneyPanel(s);
    assert.equal(/\bstyle\s*=/i.test(html), false, 'Inline style attribute is strictly prohibited');
    assert.match(html, /compound-pct-(?:0|5|10|15|20|25|30|35|40|45|50|55|60|65|70|75|80|85|90|95|100)\b/);
  }

  // Verify underwater recovery invariant forces 0% vault sweep
  const underwaterNorm = normalizeCompoundingPanel(states[0]);
  assert.equal(underwaterNorm.effectiveVaultSweepRatio, '0.00');
  assert.equal(underwaterNorm.underwater, true);
  assert.equal(underwaterNorm.progressBucket, 0);
});

test('CP04 XSS escaping neutralizes hostile news titles, symbols, resume timestamps, and broker names', () => {
  const hostileHtml = renderCompoundingAndHouseMoneyPanel({
    mode: 'FULL_COMPOUND_100',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '6000.00',
    brokers: ['<script>alert("broker")</script>', "Hugo's Way"],
    newsShield: {
      paused: true,
      blockingTitle: '<img src=x onerror="alert(1)"> CPI',
      resumeAtUtc: '2026-11-20T13:35:00Z"><svg onload=alert(2)>',
      affectedSymbols: ['NAS100<script>', '"><b onmouseover=x>US30</b>'],
    },
  });

  assert.equal(hostileHtml.includes('<script>'), false);
  assert.equal(hostileHtml.includes('<img '), false);
  assert.equal(hostileHtml.includes('<svg '), false);
  assert.equal(hostileHtml.includes('<b '), false);
  assert.match(hostileHtml, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt; CPI/);
  assert.match(hostileHtml, /&lt;script&gt;alert\(&quot;broker&quot;\)&lt;\/script&gt;/);
  assert.match(hostileHtml, /Hugo&#39;s Way/);
});

test('CP05 Sliding pill role="switch" markup and strict-CSP CSS transitions + prefers-reduced-motion + 44px targets', () => {
  const onHtml = renderCompoundingAndHouseMoneyPanel({ mode: 'FULL_COMPOUND_100' });
  assert.match(onHtml, /role="switch"/);
  assert.match(onHtml, /aria-checked="true"/);
  assert.match(onHtml, /class="compound-switch is-on"/);
  assert.match(onHtml, /data-compounding-action="TOGGLE_FULL_100"/);
  assert.match(onHtml, /class="compound-switch-track"/);
  assert.match(onHtml, /class="compound-switch-thumb"/);
  assert.match(onHtml, /100% Compounding Mode/);

  const offHtml = renderCompoundingAndHouseMoneyPanel({ mode: 'BALANCED_SPLIT_50_50', currentEquityUsd: '6000.00' });
  assert.match(offHtml, /aria-checked="false"/);
  assert.match(offHtml, /class="compound-switch is-off"/);
  assert.match(offHtml, /50%\/50% Vault Split/);

  // Verify strict-CSP CSS snippet
  assert.match(COMPOUNDING_PANEL_CSS_SNIPPET, /cubic-bezier\(0\.22,\s*1,\s*0\.36,\s*1\)/);
  assert.match(COMPOUNDING_PANEL_CSS_SNIPPET, /\.compound-switch-track\b/);
  assert.match(COMPOUNDING_PANEL_CSS_SNIPPET, /\.compound-switch-thumb\b/);
  assert.match(COMPOUNDING_PANEL_CSS_SNIPPET, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  assert.match(COMPOUNDING_PANEL_CSS_SNIPPET, /font-variant-numeric:\s*tabular-nums/);
  assert.match(COMPOUNDING_PANEL_CSS_SNIPPET, /min-height:\s*44px/);
  for (let pct = 0; pct <= 100; pct += 5) {
    assert.match(
      COMPOUNDING_PANEL_CSS_SNIPPET,
      new RegExp(`\\.compound-progress-fill\\.compound-pct-${pct}\\s*\\{\\s*width:\\s*${pct}%;\\s*\\}`),
      `Missing discrete CSP width class .compound-pct-${pct}`
    );
  }
});

test('CP06 $5,000.00 -> $10,000.00 House-Money Ready alert, PLAYING_ON_HOUSE_MONEY badge, and owner read-only tablet gating', () => {
  const readyOwnerHtml = renderCompoundingAndHouseMoneyPanel({
    mode: 'FULL_COMPOUND_100',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '10000.00',
    houseMoneyTargetUsd: '10000.00',
    houseMoneyStatus: 'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL',
    houseMoneyReady: true,
    suggestedPrincipalPulloutUsd: '5000.00',
    ownerControlsAllowed: true,
  });

  assert.match(
    readyOwnerHtml,
    /HOUSE MONEY READY — You doubled \$5,000\.00 to \$10,000\.00\+! Withdraw your original \$5,000\.00 anytime to trade 100% on house money\./
  );
  assert.match(readyOwnerHtml, /data-compounding-action="ACK_PRINCIPAL_WITHDRAWN"/);
  assert.match(readyOwnerHtml, /Mark Original Principal Withdrawn/);
  assert.doesNotMatch(readyOwnerHtml, /Owner Key Required/);
  assert.doesNotMatch(readyOwnerHtml, /PLAYING ON 100% HOUSE MONEY/);

  // Paired read-only tablet (PR #25 Finding [2]): controls MUST be disabled + Owner Key Required shown
  const readyTabletHtml = renderCompoundingAndHouseMoneyPanel({
    mode: 'FULL_COMPOUND_100',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '10000.00',
    houseMoneyReady: true,
    ownerControlsAllowed: false,
  });
  assert.match(readyTabletHtml, /Owner Key Required/);
  assert.match(readyTabletHtml, /data-owner-locked="true"/);
  assert.match(readyTabletHtml, /data-compounding-action="TOGGLE_FULL_100"[^>]*disabled/);
  assert.match(readyTabletHtml, /data-compounding-action="ACK_PRINCIPAL_WITHDRAWN"[^>]*disabled/);

  // Acknowledged principal withdrawn -> celebratory PLAYING ON 100% HOUSE MONEY badge
  const playingHtml = renderCompoundingAndHouseMoneyPanel({
    mode: 'BALANCED_SPLIT_50_50',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '10250.00',
    houseMoneyTargetUsd: '10000.00',
    houseMoneyStatus: 'PLAYING_ON_HOUSE_MONEY',
    houseMoneyReady: false,
    principalWithdrawnAcknowledged: true,
    principalWithdrawnUsd: '5000.00',
    ownerControlsAllowed: true,
  });
  assert.match(playingHtml, /PLAYING ON 100% HOUSE MONEY/);
  assert.match(playingHtml, /Original \$5,000\.00 principal withdrawn/);
  assert.doesNotMatch(playingHtml, /HOUSE MONEY READY — You doubled/);
});

test('CP07 Live News Shield pill distinguishes CLEAR vs active 5m CPI/NFP/FOMC pause and explicitly keeps stop protection active', () => {
  const clearHtml = renderCompoundingAndHouseMoneyPanel({
    newsShield: { paused: false },
  });
  assert.match(clearHtml, /class="compound-news-pill is-clear"/);
  assert.match(clearHtml, /News Shield: CLEAR/);
  assert.match(clearHtml, /Stop Protection ALWAYS ACTIVE/);

  const pausedHtml = renderCompoundingAndHouseMoneyPanel({
    newsShield: {
      paused: true,
      blockingTitle: 'US Non-Farm Payrolls (NFP)',
      resumeAtUtc: '2026-11-20T13:35:00Z',
      affectedSymbols: ['NAS100', 'US30', 'XAUUSD'],
      preMinutes: 5,
    },
  });
  assert.match(pausedHtml, /class="compound-news-pill is-paused"/);
  assert.match(pausedHtml, /NEWS PAUSE \(5m CPI\/NFP\/FOMC\) — New Entries Paused · Stop Protection ALWAYS ACTIVE/);
  assert.match(pausedHtml, /US Non-Farm Payrolls \(NFP\)/);
  assert.match(pausedHtml, /Markets: NAS100, US30, XAUUSD/);
  assert.match(pausedHtml, /Resumes: 2026-11-20T13:35:00Z/);
});

test('CP08 patchCompoundingPanelInPlace updates DOM across full lifecycle with 0 innerHTML teardown and 0 inline styles', () => {
  const { panelEl, fields } = createStrictMockPanelRoot();

  // Step 1: Midway compounding ($5,000 -> $7,500)
  const res1 = patchCompoundingPanelInPlace(panelEl, {
    mode: 'FULL_COMPOUND_100',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '7500.00',
    houseMoneyTargetUsd: '10000.00',
  });
  assert.equal(res1.patched, true);
  assert.equal(fields.modeSwitch.classList.contains('is-on'), true);
  assert.equal(fields.modeSwitch.getAttribute('aria-checked'), 'true');
  assert.equal(fields.modeSwitch.disabled, false);
  assert.equal(fields.currentEquityUsd.textContent, '$7,500.00');
  assert.equal(fields.progressPctText.textContent, '50.00%');
  assert.equal(fields.progressFill.classList.contains('compound-pct-50'), true);
  assert.equal(fields.progressFill.classList.contains('compound-pct-0'), false);
  assert.equal(fields.progressTrack.getAttribute('aria-valuenow'), '50');
  assert.equal(fields.houseMoneyBanner.classList.contains('is-hidden'), true);

  // Step 2: Double reached ($10,000.00) + switch toggled to 50/50 + CPI news pause
  const res2 = patchCompoundingPanelInPlace(panelEl, {
    mode: 'BALANCED_SPLIT_50_50',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '10000.00',
    houseMoneyTargetUsd: '10000.00',
    houseMoneyReady: true,
    newsShield: {
      paused: true,
      blockingTitle: 'US CPI YoY',
      resumeAtUtc: '2026-11-20T13:35:00Z',
      affectedSymbols: ['NAS100', 'EURUSD'],
    },
  });
  assert.equal(res2.patched, true);
  assert.equal(fields.modeSwitch.classList.contains('is-off'), true);
  assert.equal(fields.modeSwitch.classList.contains('is-on'), false);
  assert.equal(fields.modeSwitch.getAttribute('aria-checked'), 'false');
  assert.equal(fields.progressFill.classList.contains('compound-pct-100'), true);
  assert.equal(fields.progressFill.classList.contains('compound-pct-50'), false);
  assert.equal(fields.houseMoneyBanner.classList.contains('is-visible'), true);
  assert.match(fields.houseMoneyBannerText.textContent, /HOUSE MONEY READY — You doubled \$5,000\.00 to \$10,000\.00\+!/);
  assert.equal(fields.ackWithdrawBtn.disabled, false);
  assert.equal(fields.ackWithdrawBtn.textContent, 'Mark Original Principal Withdrawn');
  assert.equal(fields.newsShieldPill.classList.contains('is-paused'), true);
  assert.match(fields.newsShieldHeadline.textContent, /Stop Protection ALWAYS ACTIVE/);
  assert.match(fields.newsShieldMeta.textContent, /2026-11-20T13:35:00Z/);

  // Step 3: Playing on House Money + Read-Only Tablet Lock
  const res3 = patchCompoundingPanelInPlace(panelEl, {
    mode: 'BALANCED_SPLIT_50_50',
    startingPrincipalUsd: '5000.00',
    currentEquityUsd: '10500.00',
    houseMoneyStatus: 'PLAYING_ON_HOUSE_MONEY',
    principalWithdrawnAcknowledged: true,
    principalWithdrawnUsd: '5000.00',
    ownerControlsAllowed: false,
    newsShield: { paused: false },
  });
  assert.equal(res3.patched, true);
  assert.equal(fields.houseMoneyBanner.classList.contains('is-hidden'), true);
  assert.equal(fields.houseMoneyBadge.classList.contains('is-visible'), true);
  assert.equal(fields.houseMoneyBadgeTitle.textContent, 'PLAYING ON 100% HOUSE MONEY');
  assert.equal(fields.ownerLockBadge.classList.contains('is-visible'), true);
  assert.equal(fields.ownerLockBadge.textContent, 'Owner Key Required');
  assert.equal(fields.modeSwitch.disabled, true);
  assert.equal(fields.ackWithdrawBtn.disabled, true);
  assert.equal(fields.newsShieldPill.classList.contains('is-clear'), true);

  // Assert zero markup teardowns and zero inline style writes on every node
  assert.equal(panelEl._markupWrites, 0);
  assert.equal(panelEl._styleWrites, 0);
  for (const el of Object.values(fields)) {
    assert.equal(el._markupWrites, 0);
    assert.equal(el._styleWrites, 0);
  }
});

test('CP09 Strict-boolean fail-closed PR #25 Finding [2] ownerControlsAllowed and deviceRole/sessionScope gating', () => {
  const nonBooleanPayloads = [
    { ownerControlsAllowed: 'false' },
    { ownerControlsAllowed: 'true' },
    { ownerControlsAllowed: 1 },
    { ownerControlsAllowed: 0 },
    { ownerControlsAllowed: null },
    { owner_controls_allowed: 'false' },
    { owner_controls_allowed: 'true' },
    { owner_controls_allowed: 1 },
    { owner_controls_allowed: 0 },
    { owner_controls_allowed: null },
    { compounding: { ownerControlsAllowed: 'false' } },
    { compounding: { owner_controls_allowed: null } },
    { aiTrader: { ownerControlsAllowed: 'true' } },
    { deviceRole: 'DEVICE_READ_AND_EXPLAINER' },
    { device_role: 'DEVICE_READ_AND_EXPLAINER' },
    { compounding: { device_role: 'DEVICE_READ_AND_EXPLAINER' } },
    { deviceRole: 'DEVICE_READ_AND_EXPLAINER', ownerControlsAllowed: true },
    { sessionScope: 'DEVICE_READ_AND_EXPLAINER', ownerControlsAllowed: true },
  ];

  for (const payload of nonBooleanPayloads) {
    const norm = normalizeCompoundingPanel(payload);
    assert.equal(
      norm.ownerControlsAllowed,
      false,
      `Expected fail-closed ownerControlsAllowed=false for ${JSON.stringify(payload)}`
    );
    const html = renderCompoundingAndHouseMoneyPanel({
      ...payload,
      startingPrincipalUsd: '5000.00',
      currentEquityUsd: '10000.00',
      houseMoneyReady: true,
    });
    assert.match(html, /Owner Key Required/);
    assert.match(html, /data-owner-locked="true"/);
    assert.match(html, /data-compounding-action="TOGGLE_FULL_100"[^>]*disabled/);
    assert.match(html, /data-compounding-action="ACK_PRINCIPAL_WITHDRAWN"[^>]*disabled/);
  }

  // Strict boolean true with no read-only role/scope remains unlocked
  const unlocked = normalizeCompoundingPanel({ ownerControlsAllowed: true, deviceRole: 'OWNER_FULL_CONTROL' });
  assert.equal(unlocked.ownerControlsAllowed, true);
});

test('CP10 Source hygiene: 0 inline style=, 0 eval/Function, 0 innerHTML/outerHTML, 0 CRLF/CR, 0 BOM', async () => {
  const modBytes = await readFile(new URL('../../ui/src/compounding-panel.mjs', import.meta.url));
  const testBytes = await readFile(new URL('./compounding-panel.test.mjs', import.meta.url));

  for (const [label, buf] of [['compounding-panel.mjs', modBytes], ['compounding-panel.test.mjs', testBytes]]) {
    assert.equal(buf.includes(0x0d), false, `${label} must use LF-only line endings (0 CR)`);
    assert.equal(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf, false, `${label} must have 0 UTF-8 BOM`);
  }

  const modSrc = modBytes.toString('utf8');
  assert.equal(/\bstyle\s*=\s*["']/.test(modSrc), false, 'Inline style attribute prohibited in compounding-panel.mjs');
  assert.equal(/\beval\s*\(/.test(modSrc), false, 'eval() prohibited in compounding-panel.mjs');
  assert.equal(/\bnew\s+Function\b/.test(modSrc), false, 'new Function prohibited in compounding-panel.mjs');
  assert.equal(/\binnerHTML\b/.test(modSrc), false, 'innerHTML prohibited in compounding-panel.mjs');
  assert.equal(/\bouterHTML\b/.test(modSrc), false, 'outerHTML prohibited in compounding-panel.mjs');
});
