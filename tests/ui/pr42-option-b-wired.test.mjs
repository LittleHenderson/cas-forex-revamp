import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  renderApp,
  renderOptionBDemoPanel,
  resolveCockpitOptionBDemo,
} from '../../ui/src/render.mjs';
import { STATIC_OPTION_B_DEMO } from '../../ui/src/option-b-demo-panel.mjs';
import { decodeCockpit } from '../../ui/src/wire.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

test('PR42-W01: renderApp mounts Option B $5,000.00 Micro Futures card next to Parallel Tiers', () => {
  const schema = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, 'docs', 'contracts', 'cockpit.schema.json'), 'utf8'),
  );
  const fixtureText = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'contracts', 'initial-cockpit.json'), 'utf8');
  const state = {
    projection: decodeCockpit(fixtureText, schema),
    route: 'operate',
    optionBDemo: {
      schema: 'cas-forex.option-b-demo/1',
      equity_usd: '5124.50',
      net_pnl_usd: '124.50',
      net_pnl_pct: '2.49',
    },
  };
  const resolved = resolveCockpitOptionBDemo(state);
  assert.equal(resolved.equityUsd, '5124.50');
  const html = renderApp(state);
  assert.match(html, /data-option-b-demo="true"/);
  assert.match(html, /\$5124\.50/);
  assert.match(html, /MNQ/);
  assert.match(html, /MGC/);
  assert.equal(typeof renderOptionBDemoPanel, 'function');
  assert.doesNotMatch(html, /\sstyle\s*=/i, 'Strict CSP: zero inline style attributes');
});

test('PR42-W02: app.mjs wires /api/option-b-demo, SSE option_b_demo, and zero-jump in-place patching', () => {
  const appSrc = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'src', 'app.mjs'), 'utf8');
  assert.match(appSrc, /\/api\/option-b-demo/);
  assert.match(appSrc, /eventName === 'option_b_demo'/);
  assert.match(appSrc, /patchOptionBDemoPanelInPlace/);
  assert.match(appSrc, /syncOptionBDemoDom/);
  assert.match(appSrc, /readOptionBDemo/);
  assert.equal(appSrc.includes('\r\n'), false, 'app.mjs must use LF line endings');
});

test('PR42-W03: styles.css includes Option B dark obsidian styling with overflow-anchor none and strict CSP', () => {
  const css = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'styles.css'), 'utf8');
  assert.match(css, /\.ob-demo-panel\s*\{[^}]*overflow-anchor:\s*none/);
  assert.match(css, /\.ob-pct-0\s*\{/);
  assert.match(css, /\.ob-pct-100\s*\{/);
  assert.match(css, /\.ob-contract-grid\s*\{/);
  assert.equal(css.includes('\r\n'), false, 'styles.css must use LF line endings');
});
