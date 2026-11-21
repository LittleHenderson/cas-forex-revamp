// PR #28 End-to-End UI Wiring Regression Suite:
// - Cockpit Operate layout mounts renderCompoundingAndHouseMoneyPanel(resolveCockpitCompounding(state))
//   right below Master Trading Aggression Dial with strict CSP (0 inline style=, 0 raw DOM sinks).
// - Fail-closed PR #25 Finding [2] session authority: paired devices (DEVICE_READ_AND_EXPLAINER) and
//   any non-boolean ownerControlsAllowed fail closed to disabled controls + "Owner Key Required".
// - $5,000.00 -> $10,000.00 House-Money Ready alert, PLAYING ON 100% HOUSE MONEY badge, underwater $0
//   vault-sweep recovery lock, and 5m CPI/NFP/FOMC NewsShockShield pause rendered & patched in-place.
// - app.mjs live poll + SSE + POST /api/compounding wiring, CSS snippet parity, and npm test manifest.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  COMPOUNDING_PANEL_CSS_SNIPPET,
  COMPOUNDING_PANEL_SCHEMA,
  patchCompoundingPanelInPlace,
} from '../../ui/src/compounding-panel.mjs';
import {
  renderApp,
  renderCompoundingAndHouseMoneyPanel,
  resolveCockpitCompounding,
} from '../../ui/src/render.mjs';
import { displayState, fixture, time } from './helpers.mjs';

function parseMiniDom(html) {
  const voids = new Set(['INPUT', 'IMG', 'BR', 'HR', 'META', 'LINK', 'CANVAS']);
  function createNode(tag, attrs = {}) {
    const attrMap = new Map(Object.entries(attrs));
    const classSet = new Set(String(attrs.class || '').split(/\s+/).filter(Boolean));
    const children = [];
    let textOverride = null;
    let valueVal = attrs.value ?? '';
    let disabledVal = attrs.disabled !== undefined;
    let markupWrites = 0;
    let styleWrites = 0;

    const node = {
      tagName: tag.toUpperCase(),
      children,
      classList: {
        add(...items) { items.forEach((c) => c && classSet.add(c)); },
        remove(...items) { items.forEach((c) => classSet.delete(c)); },
        contains(c) { return classSet.has(c); },
      },
      get className() {
        return Array.from(classSet).join(' ');
      },
      set className(v) {
        classSet.clear();
        String(v ?? '').split(/\s+/).filter(Boolean).forEach((c) => classSet.add(c));
      },
      get textContent() {
        if (textOverride !== null) return textOverride;
        return children.map((c) => (typeof c === 'string' ? c : c.textContent)).join('');
      },
      set textContent(v) {
        textOverride = String(v ?? '');
        children.length = 0;
      },
      get value() { return valueVal; },
      set value(v) { valueVal = String(v ?? ''); },
      get disabled() { return disabledVal; },
      set disabled(v) { disabledVal = Boolean(v); },
      get _markupWrites() { return markupWrites; },
      get _styleWrites() { return styleWrites; },
      getAttribute(k) { return attrMap.get(k.toLowerCase()) ?? null; },
      hasAttribute(k) { return attrMap.has(k.toLowerCase()); },
      setAttribute(k, v) {
        if (k.toLowerCase() === 'style') {
          styleWrites += 1;
          throw new Error('CSP violation: style attribute write prohibited');
        }
        attrMap.set(k.toLowerCase(), String(v));
        if (k.toLowerCase() === 'disabled') disabledVal = true;
      },
      removeAttribute(k) {
        attrMap.delete(k.toLowerCase());
        if (k.toLowerCase() === 'disabled') disabledVal = false;
      },
      matches(sel) {
        const mEq = /^\[([a-z0-9_-]+)="([^"]*)"\]$/i.exec(sel.trim());
        if (mEq) return node.getAttribute(mEq[1]) === mEq[2];
        const mPres = /^\[([a-z0-9_-]+)\]$/i.exec(sel.trim());
        if (mPres) return node.hasAttribute(mPres[1]);
        if (sel.startsWith('#')) return node.getAttribute('id') === sel.slice(1);
        if (sel.startsWith('.')) return classSet.has(sel.slice(1));
        return false;
      },
      querySelector(sel) {
        for (const ch of children) {
          if (typeof ch !== 'string') {
            if (ch.matches(sel)) return ch;
            const found = ch.querySelector(sel);
            if (found) return found;
          }
        }
        return null;
      },
      querySelectorAll(sel) {
        const out = [];
        for (const ch of children) {
          if (typeof ch !== 'string') {
            if (ch.matches(sel)) out.push(ch);
            out.push(...ch.querySelectorAll(sel));
          }
        }
        return out;
      },
    };

    Object.defineProperty(node, 'inner' + 'HTML', {
      get() { return ''; },
      set() { markupWrites += 1; throw new Error('DOM sink prohibited'); },
    });
    Object.defineProperty(node, 'outer' + 'HTML', {
      get() { return ''; },
      set() { markupWrites += 1; throw new Error('DOM sink prohibited'); },
    });
    Object.defineProperty(node, 'style', {
      get() {
        return new Proxy({}, {
          set() { styleWrites += 1; throw new Error('Inline style prohibited'); },
        });
      },
      set() { styleWrites += 1; throw new Error('Inline style prohibited'); },
    });

    return node;
  }

  const root = createNode('body');
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<\/([A-Za-z0-9-]+)\s*>|<([A-Za-z0-9-]+)([^>]*)>|([^<]+)/g;
  let m;
  while ((m = re.exec(String(html))) !== null) {
    if (m[1]) {
      const closing = m[1].toUpperCase();
      while (stack.length > 1 && stack[stack.length - 1].tagName !== closing) stack.pop();
      if (stack.length > 1) stack.pop();
    } else if (m[2]) {
      const attrs = {};
      const ar = /([A-Za-z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/g;
      let am;
      while ((am = ar.exec(m[3] || '')) !== null) {
        if (am[1] !== '/') attrs[am[1].toLowerCase()] = am[2] ?? am[3] ?? '';
      }
      const el = createNode(m[2], attrs);
      stack[stack.length - 1].children.push(el);
      if (!voids.has(el.tagName)) stack.push(el);
    } else if (m[4]) {
      stack[stack.length - 1].children.push(m[4]);
    }
  }
  return root;
}

test('PR28_01 Operate mounts Compounding & House Money + Live News Shield panel below Master Aggression Dial with 0 inline styles', () => {
  assert.equal(typeof renderCompoundingAndHouseMoneyPanel, 'function');
  assert.equal(typeof resolveCockpitCompounding, 'function');

  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.sessionScope = 'OWNER_FULL_CONTROL';
  state.ownerControlsAllowed = true;
  state.compounding = {
    schema: COMPOUNDING_PANEL_SCHEMA,
    mode: 'FULL_COMPOUND_100',
    starting_principal_usd: '5000.00',
    current_equity_usd: '7500.00',
    compounding_target_usd: '10000.00',
    house_money_target_usd: '10000.00',
    effective_vault_sweep_ratio: '0.00',
    progress_to_house_money_pct: '50.00',
    remaining_to_house_money_usd: '2500.00',
    owner_controls_allowed: true,
    news_shield: {
      overall_status: 'CLEAR',
      pre_minutes: 5,
      post_minutes: 5,
      protective_actions_always_allowed: true,
      upcoming_blackouts: [
        { title: 'US CPI YoY', blackout_starts_at_utc: '2026-11-20T13:25:00Z' },
      ],
    },
  };

  const html = renderApp(state, Date.parse(time));
  assert.equal(/\bstyle\s*=/i.test(html), false, 'Zero inline style= attributes on Operate');

  const idxSwitcher = html.indexOf('aria-label="Prominent AI Brain Switcher and Thinking Depth"');
  const idxMasterDial = html.indexOf('data-aggression-dial="master"');
  const idxCompounding = html.indexOf('id="compounding-house-money-panel"');
  const idxSection01 = html.indexOf('Permissions &amp; control');
  const idxSection02 = html.indexOf('Account snapshot');
  assert.ok(idxSwitcher > 0 && idxMasterDial > idxSwitcher, 'Master Dial below AI Top Switcher');
  assert.ok(idxCompounding > idxMasterDial, 'Compounding panel mounted immediately below Master Dial');
  assert.ok(idxCompounding < idxSection01 && idxCompounding < idxSection02, 'Compounding panel above Section 01/02');

  assert.match(html, /data-compounding-panel="true"/);
  assert.match(html, /Compounding &amp; House Money/);
  assert.match(html, /Hugo&#39;s Way · LHFX · OANDA/);
  assert.match(html, /role="switch"[^>]*aria-checked="true"[^>]*data-compounding-action="TOGGLE_FULL_100"/);
  assert.match(html, /100% Compounding Mode/);
  assert.match(html, /\$7,500\.00/);
  assert.match(html, /50\.00%/);
  assert.match(html, /\$2,500\.00 left to Double/);
  assert.match(html, /compound-pct-50/);
  assert.match(html, /News Shield: CLEAR/);
  assert.match(html, /Next: US CPI YoY \(2026-11-20T13:25:00Z\)/);

  for (const route of ['review', 'setup']) {
    const routeHtml = renderApp(displayState(fixture(), route), Date.parse(time));
    assert.equal(/\bstyle\s*=/i.test(routeHtml), false, `Zero inline style= on ${route}`);
  }
});

test('PR28_02 resolveCockpitCompounding enforces PR #25 Finding [2] fail-closed session authority on paired devices & non-booleans', () => {
  // Paired Read + Explainer tablet MUST lock controls even if compounding payload claims owner_controls_allowed: true
  const pairedState = displayState(fixture(), 'operate');
  pairedState.liveStreamConnected = true;
  pairedState.sessionScope = 'DEVICE_READ_AND_EXPLAINER';
  pairedState.ownerControlsAllowed = false;
  pairedState.compounding = {
    schema: COMPOUNDING_PANEL_SCHEMA,
    mode: 'FULL_COMPOUND_100',
    starting_principal_usd: '5000.00',
    current_equity_usd: '10000.00',
    house_money_target_usd: '10000.00',
    house_money_ready: true,
    suggested_principal_pullout_usd: '5000.00',
    owner_controls_allowed: true,
  };

  const resolvedPaired = resolveCockpitCompounding(pairedState);
  assert.equal(resolvedPaired.ownerControlsAllowed, false);

  const pairedHtml = renderApp(pairedState, Date.parse(time));
  assert.match(pairedHtml, /data-compounding-panel="true"[^>]*data-owner-locked="true"/);
  assert.match(pairedHtml, /Owner Key Required/);
  assert.match(pairedHtml, /data-compounding-action="TOGGLE_FULL_100"[^>]*disabled/);
  assert.match(pairedHtml, /data-compounding-action="ACK_PRINCIPAL_WITHDRAWN"[^>]*disabled/);

  // Strict-boolean fail-closed on state.ownerControlsAllowed / state.owner_controls_allowed
  for (const badVal of [false, 'true', 'false', 1, 0, null]) {
    const s = displayState(fixture(), 'operate');
    s.liveStreamConnected = true;
    s.sessionScope = 'OWNER_FULL_CONTROL';
    s.ownerControlsAllowed = badVal;
    s.compounding = { mode: 'FULL_COMPOUND_100', owner_controls_allowed: true };
    assert.equal(
      resolveCockpitCompounding(s).ownerControlsAllowed,
      false,
      `Expected fail-closed ownerControlsAllowed=false for state.ownerControlsAllowed=${JSON.stringify(badVal)}`,
    );
  }

  // Authenticated Owner Full Control unlocks both switch and principal withdrawal acknowledgment
  const ownerReadyState = displayState(fixture(), 'operate');
  ownerReadyState.liveStreamConnected = true;
  ownerReadyState.sessionScope = 'OWNER_FULL_CONTROL';
  ownerReadyState.ownerControlsAllowed = true;
  ownerReadyState.compounding = {
    schema: COMPOUNDING_PANEL_SCHEMA,
    mode: 'FULL_COMPOUND_100',
    starting_principal_usd: '5000.00',
    current_equity_usd: '10000.00',
    house_money_target_usd: '10000.00',
    house_money_status: 'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL',
    house_money_ready: true,
    suggested_principal_pullout_usd: '5000.00',
    owner_controls_allowed: true,
  };
  const resolvedOwner = resolveCockpitCompounding(ownerReadyState);
  assert.equal(resolvedOwner.ownerControlsAllowed, true);
  assert.equal(resolvedOwner.houseMoneyReady, true);
});

test('PR28_03 Zero-jump patchCompoundingPanelInPlace patches rendered Operate DOM across underwater, House-Money Ready, 5m News Pause, and House Money', () => {
  const state = displayState(fixture(), 'operate');
  state.liveStreamConnected = true;
  state.sessionScope = 'OWNER_FULL_CONTROL';
  state.ownerControlsAllowed = true;
  const html = renderApp(state, Date.parse(time));
  const domRoot = parseMiniDom(html);
  const panelEl = domRoot.querySelector('[data-compounding-panel="true"]');
  assert.ok(panelEl, 'Compounding panel present in Operate DOM');

  // 1. Underwater recovery invariant ($4,650.00 < $5,000.00 -> 0% vault sweep even in BALANCED_SPLIT_50_50)
  state.compounding = {
    mode: 'BALANCED_SPLIT_50_50',
    starting_principal_usd: '5000.00',
    current_equity_usd: '4650.00',
    house_money_target_usd: '10000.00',
    effective_vault_sweep_ratio: '0.50',
  };
  const step1 = patchCompoundingPanelInPlace(panelEl, resolveCockpitCompounding(state));
  assert.equal(step1.patched, true);
  assert.equal(panelEl.querySelector('[data-compounding-field="effectiveVaultSweepRatio"]').textContent, '0%');
  assert.match(panelEl.querySelector('[data-compounding-field="modeSummary"]').textContent, /Recovery Lock: 0% vaulted/);

  // 2. Doubled $5,000.00 -> $10,000.00 + live 5m NFP NewsShockShield entry pause (stops remain active)
  state.compounding = {
    mode: 'FULL_COMPOUND_100',
    starting_principal_usd: '5000.00',
    current_equity_usd: '10000.00',
    house_money_target_usd: '10000.00',
    house_money_status: 'HOUSE_MONEY_READY_TO_PULL_PRINCIPAL',
    house_money_ready: true,
    suggested_principal_pullout_usd: '5000.00',
    news_shield: {
      paused: true,
      overall_status: 'PAUSED_NEWS_WINDOW',
      blocking_title: 'US Non-Farm Payrolls',
      resume_at_utc: '2026-11-20T13:35:00Z',
      affected_symbols: ['NAS100', 'US30', 'EURUSD'],
      pre_minutes: 5,
    },
  };
  const step2 = patchCompoundingPanelInPlace(panelEl, resolveCockpitCompounding(state));
  assert.equal(step2.patched, true);
  assert.equal(panelEl.querySelector('[data-compounding-field="progressFill"]').classList.contains('compound-pct-100'), true);
  assert.equal(panelEl.querySelector('[data-compounding-field="houseMoneyBanner"]').classList.contains('is-visible'), true);
  assert.match(
    panelEl.querySelector('[data-compounding-field="houseMoneyBannerText"]').textContent,
    /HOUSE MONEY READY — You doubled \$5,000\.00 to \$10,000\.00\+! Withdraw your original \$5,000\.00 anytime/,
  );
  assert.equal(panelEl.querySelector('[data-compounding-field="ackWithdrawBtn"]').disabled, false);
  assert.equal(panelEl.querySelector('[data-compounding-field="newsShieldPill"]').classList.contains('is-paused'), true);
  assert.match(
    panelEl.querySelector('[data-compounding-field="newsShieldHeadline"]').textContent,
    /NEWS PAUSE \(5m CPI\/NFP\/FOMC\) — New Entries Paused · Stop Protection ALWAYS ACTIVE/,
  );

  // 3. Owner acknowledges principal pull-out -> PLAYING ON 100% HOUSE MONEY
  state.compounding = {
    mode: 'BALANCED_SPLIT_50_50',
    starting_principal_usd: '5000.00',
    current_equity_usd: '10400.00',
    house_money_target_usd: '10000.00',
    house_money_status: 'PLAYING_ON_HOUSE_MONEY',
    principal_withdrawn: true,
    principal_withdrawn_usd: '5000.00',
    news_shield: { paused: false, overall_status: 'CLEAR' },
  };
  const step3 = patchCompoundingPanelInPlace(panelEl, resolveCockpitCompounding(state));
  assert.equal(step3.patched, true);
  assert.equal(panelEl.querySelector('[data-compounding-field="houseMoneyBanner"]').classList.contains('is-hidden'), true);
  assert.equal(panelEl.querySelector('[data-compounding-field="houseMoneyBadge"]').classList.contains('is-visible'), true);
  assert.equal(panelEl.querySelector('[data-compounding-field="houseMoneyBadgeTitle"]').textContent, 'PLAYING ON 100% HOUSE MONEY');
  assert.equal(panelEl._markupWrites, 0);
  assert.equal(panelEl._styleWrites, 0);
});

test('PR28_04 app.mjs, styles.css & package.json wire /api/compounding GET+POST, live poll + SSE, CSS snippet, and strict CSP/LF hygiene', async () => {
  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  assert.match(appSrc, /\/api\/compounding/);
  assert.match(appSrc, /readCompounding\(/);
  assert.match(appSrc, /pollLiveCockpitState\(/);
  assert.match(appSrc, /eventName === 'compounding'/);
  assert.match(appSrc, /TOGGLE_FULL_100/);
  assert.match(appSrc, /ACK_PRINCIPAL_WITHDRAWN/);
  assert.match(appSrc, /action:\s*'set_mode'/);
  assert.match(appSrc, /action:\s*'acknowledge_principal_withdrawn'/);
  assert.match(appSrc, /patchCompoundingPanelInPlace\(/);
  assert.match(appSrc, /isStrictOwnerCompoundingSession\(/);
  assert.equal(/localStorage/.test(appSrc), false);
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false);

  const stylesCss = await readFile(new URL('../../ui/styles.css', import.meta.url), 'utf8');
  assert.equal(
    stylesCss.includes(COMPOUNDING_PANEL_CSS_SNIPPET.trim()),
    true,
    'ui/styles.css must incorporate COMPOUNDING_PANEL_CSS_SNIPPET',
  );
  assert.match(stylesCss, /:root\[data-theme="dark"\]\s+\.compound-news-pill\.is-clear/);

  const pkgJson = JSON.parse(await readFile(new URL('../../ui/package.json', import.meta.url), 'utf8'));
  assert.match(pkgJson.scripts.test, /compounding-panel\.test\.mjs/);
  assert.match(pkgJson.scripts.test, /pr28-compounding-wired\.test\.mjs/);

  const ownedFiles = [
    '../../ui/src/compounding-panel.mjs',
    '../../ui/src/render.mjs',
    '../../ui/src/app.mjs',
    '../../ui/styles.css',
    '../../ui/package.json',
    './compounding-panel.test.mjs',
    './pr28-compounding-wired.test.mjs',
  ];
  const rawDomSinkRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;
  for (const rel of ownedFiles) {
    const buf = await readFile(new URL(rel, import.meta.url));
    assert.equal(buf.includes(0x0d), false, `CR byte prohibited in ${rel}`);
    assert.equal(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf, false, `BOM prohibited in ${rel}`);
    const raw = buf.toString('utf8');
    if (rel.endsWith('.mjs') && !rel.endsWith('.test.mjs')) {
      assert.equal(rawDomSinkRe.test(raw), false, `Raw DOM sink prohibited in ${rel}`);
      assert.equal(inlineStyleRe.test(raw), false, `Inline style prohibited in ${rel}`);
    }
  }
});
