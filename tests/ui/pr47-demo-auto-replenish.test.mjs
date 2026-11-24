import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  STATIC_OPTION_B_DEMO,
  normalizeOptionBDemo,
  renderOptionBDemoPanel,
  patchOptionBDemoPanelInPlace,
} from '../../ui/src/option-b-demo-panel.mjs';
import {
  STATIC_PARALLEL_TIERS,
  normalizeParallelTiers,
  renderParallelTiersSection,
} from '../../ui/src/analytics.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

test('PR47-UI01 Option B panel renders 70.00% auto-replenish status, owner buttons, and zero inline style=', () => {
  assert.equal(STATIC_OPTION_B_DEMO.autoReplenishFloorPct, '70.00');
  assert.equal(STATIC_OPTION_B_DEMO.autoReplenishFloorUsd, '3500.00');
  const norm = normalizeOptionBDemo({
    status: 'PAPER_DEMO_ACTIVE',
    auto_replenish_enabled: true,
    auto_replenish_floor_pct: '70.00',
    auto_replenish_floor_usd: '3500.00',
    replenishment_count: 2,
    cumulative_replenished_usd: '1271.32',
    open_positions: [],
  });
  assert.equal(norm.replenishmentCount, 2);
  assert.equal(norm.cumulativeReplenishedUsd, '1271.32');
  const html = renderOptionBDemoPanel(norm);
  assert.match(html, /70\.00%/);
  assert.match(html, /data-ob-action="REPLENISH_DEMO_CAPITAL"/);
  assert.match(html, /data-ob-action="TOGGLE_AUTO_REPLENISH"/);
  assert.match(html, /2 top-ups \(\+\$1271\.32\)/);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
});

test('PR47-UI02 Parallel Tiers section renders 70.00% DEMO auto-replenish bar & REPLENISH_ALL_TIERS button safely', () => {
  assert.equal(STATIC_PARALLEL_TIERS.autoReplenishFloorPct, '70.00');
  const pt = normalizeParallelTiers({
    schema: 'cas-forex.parallel-tiers/1',
    tier_count: 1,
    auto_replenish_enabled: true,
    auto_replenish_floor_pct: '70.00',
    total_replenishment_count: 5,
    total_cumulative_replenished_usd: '70221.37',
    owner_controls_allowed: true,
    tiers: [{
      tier_id: 'TIER_5_300',
      label: 'Tier $300 <img src=x>',
      color_class: 'tier-300',
      starting_capital_usd: '300',
      balance_usd: '300',
      equity_usd: '300',
      net_gain_usd: '0',
      growth_pct: '0',
      peak_equity_usd: '300',
      drawdown_pct: '0',
      open_positions: 0,
      closed_trades: 4,
      win_rate_pct: '25',
      profit_factor: '0.25',
      bank_sweep_reserved_usd: '0',
      retained_trading_usd: '0',
      replenishment_count: 1,
      cumulative_replenished_usd: '61.64',
    }],
    growth_series: {},
  });
  assert.equal(pt.totalReplenishmentCount, 5);
  const html = renderParallelTiersSection({ parallelTiers: pt });
  assert.match(html, /data-pt-action="REPLENISH_ALL_TIERS"/);
  assert.match(html, /data-pt-action="TOGGLE_AUTO_REPLENISH"/);
  assert.match(html, /5 top-ups \(\+\$70221\.37\)/);
  assert.equal(html.includes('<img src=x>'), false);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
});

test('PR47-UI03 app.mjs & styles.css wire REPLENISH_DEMO_CAPITAL, REPLENISH_ALL_TIERS, and LF hygiene', () => {
  for (const rel of ['ui/src/option-b-demo-panel.mjs', 'ui/src/analytics.mjs', 'ui/src/app.mjs', 'ui/styles.css']) {
    const content = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
    assert.equal(content.includes('\r\n'), false, `${rel} must use LF line endings`);
  }
  const appSrc = fs.readFileSync(path.join(REPO_ROOT, 'ui', 'src', 'app.mjs'), 'utf8');
  assert.match(appSrc, /REPLENISH_DEMO_CAPITAL/);
  assert.match(appSrc, /REPLENISH_ALL_TIERS/);
  assert.match(appSrc, /\/api\/parallel-tiers/);
  assert.equal(typeof patchOptionBDemoPanelInPlace, 'function');
});
