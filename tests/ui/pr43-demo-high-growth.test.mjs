// PR #43 UI regression suite: Strict-CSP Dark Obsidian DEMO High-Growth Practice Profile bar,
// normalization, LIVE-mode lock, XSS escaping, 0.0px in-place patching, and app.mjs route wiring.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  renderApp,
  renderDemoHighGrowthPanel,
  resolveCockpitDemoHighGrowth,
} from '../../ui/src/render.mjs';
import {
  DEMO_HIGH_GROWTH_SCHEMA,
  STATIC_DEMO_HIGH_GROWTH,
  normalizeDemoHighGrowth,
  patchDemoHighGrowthPanelInPlace,
} from '../../ui/src/demo-high-growth-panel.mjs';
import { decodeCockpit } from '../../ui/src/wire.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

function makeMockPanel() {
  const nodes = new Map();
  const makeNode = (text = '', classes = []) => {
    const cls = new Set(classes);
    return {
      textContent: text,
      disabled: false,
      classList: {
        add: (c) => cls.add(c),
        remove: (c) => cls.delete(c),
        toggle: (c, force) => {
          if (force === undefined) {
            if (cls.has(c)) cls.delete(c); else cls.add(c);
          } else if (force) cls.add(c); else cls.delete(c);
        },
        contains: (c) => cls.has(c),
      },
    };
  };
  for (const sel of [
    '[data-dhg-safety-badge="true"]',
    '[data-dhg-status-badge="true"]',
    '[data-dhg-action="TOGGLE_ENABLED"]',
    '[data-dhg-risk="true"]',
    '[data-dhg-dd="true"]',
    '[data-dhg-compound="true"]',
    '[data-dhg-cooldown="true"]',
    '[data-dhg-cooldown-sub="true"]',
    '[data-dhg-protection="true"]',
    '[data-dhg-protection-sub="true"]',
    '[data-dhg-valve="true"]',
  ]) {
    nodes.set(sel, makeNode());
  }
  return {
    querySelector: (sel) => nodes.get(sel) ?? null,
    _nodes: nodes,
  };
}

test('PR43-UI01: default panel renders OFF safely with strict CSP and 0 inline styles', () => {
  const html = renderDemoHighGrowthPanel(STATIC_DEMO_HIGH_GROWTH);
  assert.match(html, /data-demo-high-growth="true"/);
  assert.match(html, /1\.00% \/ 10\.00% STANDARD/);
  assert.match(html, /900s anti-whipsaw/);
  assert.match(html, /data-dhg-action="TOGGLE_ENABLED" disabled/);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
});

test('PR43-UI02: enabled DEMO high-growth renders exact 10%/12%/30%/100%/900s metrics inside renderApp', () => {
  const schema = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, 'docs', 'contracts', 'cockpit.schema.json'), 'utf8'),
  );
  const fixtureText = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'contracts', 'initial-cockpit.json'), 'utf8');
  const state = {
    projection: decodeCockpit(fixtureText, schema),
    route: 'operate',
    liveStreamConnected: true,
    ownerControlsAllowed: true,
    brokerRouting: { execution_mode: 'DEMO', live_trading_armed: false },
    demoHighGrowth: {
      schema: DEMO_HIGH_GROWTH_SCHEMA,
      enabled: true,
      target_risk_pct: '10.00',
      max_risk_pct: '12.00',
      max_drawdown_display_pct: '30.00',
      compounding_100pct: true,
      post_loss_cooldown_seconds: 900,
      block_us_close_chop: true,
      owner_controls_allowed: true,
      execution_mode: 'DEMO',
      updated_at: '2026-11-23T21:00:00Z',
    },
  };
  const resolved = resolveCockpitDemoHighGrowth(state);
  assert.equal(resolved.enabled, true);
  assert.equal(resolved.liveModeBlocked, false);
  const html = renderApp(state);
  assert.match(html, /data-demo-high-growth="true"/);
  assert.match(html, /10\.00% \/ 12\.00%/);
  assert.match(html, /30\.00% DD Freeze/);
  assert.match(html, /100\.00% Compound \(0% Sweep\)/);
  assert.match(html, /15m Post-Loss Cooldown/);
  assert.match(html, /900s anti-whipsaw/);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
});

test('PR43-UI03: LIVE mode blocks and disables toggle while escaping untrusted input', () => {
  const resolved = resolveCockpitDemoHighGrowth({
    liveStreamConnected: true,
    ownerControlsAllowed: true,
    brokerRouting: { execution_mode: 'LIVE', live_trading_armed: true },
    demoHighGrowth: {
      enabled: true,
      target_risk_pct: '<script>alert(1)</script>',
      session_scope: '<img src=x onerror=alert(1)>',
    },
  });
  assert.equal(resolved.enabled, false);
  assert.equal(resolved.liveModeBlocked, true);
  assert.equal(resolved.ownerControlsAllowed, false);
  const html = renderDemoHighGrowthPanel(resolved);
  assert.match(html, /LIVE MODE BLOCKED/);
  assert.match(html, /data-dhg-action="TOGGLE_ENABLED" disabled/);
  assert.doesNotMatch(html, /<script>/i);
  assert.doesNotMatch(html, /<img/i);
});

test('PR43-UI04: patchDemoHighGrowthPanelInPlace updates DOM in-place without layout thrash', () => {
  const panel = makeMockPanel();
  const next = normalizeDemoHighGrowth({
    schema: DEMO_HIGH_GROWTH_SCHEMA,
    enabled: true,
    owner_controls_allowed: true,
    execution_mode: 'DEMO',
    updated_at: '2026-11-23T21:00:00Z',
  });
  patchDemoHighGrowthPanelInPlace(panel, next);
  assert.equal(panel.querySelector('[data-dhg-risk="true"]').textContent, '10.00% / 12.00%');
  assert.equal(panel.querySelector('[data-dhg-dd="true"]').textContent, '30.00% DD Freeze');
  assert.equal(panel.querySelector('[data-dhg-action="TOGGLE_ENABLED"]').disabled, false);
});

test('PR43-UI05: app.mjs & styles.css wire /api/demo-high-growth-profile, SSE, and Dark Obsidian CSS', () => {
  const appSrc = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'src', 'app.mjs'), 'utf8');
  assert.match(appSrc, /\/api\/demo-high-growth-profile/);
  assert.match(appSrc, /eventName === 'demo_high_growth_profile'/);
  assert.match(appSrc, /patchDemoHighGrowthPanelInPlace/);
  assert.match(appSrc, /syncDemoHighGrowthDom/);
  assert.equal(appSrc.includes('\r\n'), false, 'app.mjs must use LF line endings');

  const css = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'styles.css'), 'utf8');
  assert.match(css, /\.dhg-panel\s*\{[^}]*overflow-anchor:\s*none/);
  assert.equal(css.includes('\r\n'), false, 'styles.css must use LF line endings');
});
