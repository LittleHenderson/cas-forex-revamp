// Phase 6 UI tests: Prominent AI Switcher, 4 Thinking Depth Pills, 5-Tier Race, 50%/50% Treasury & 50ms Chart.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  THINKING_DEPTH_OPTIONS,
  normalizeParallelTiers,
  normalizeTreasury,
  renderAiTopSwitcherBar,
  renderEquityAndAnalyticsSection,
  renderParallelTiersSection,
} from '../../ui/src/analytics.mjs';
import { CHART_TIMEFRAMES, decodeMarketStream } from '../../ui/src/chart.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { displayState, fixture, time } from './helpers.mjs';

test('ANALYTICS01 top AI Switcher, 4 Thinking Depth pills, and 50ms chart timeframe render without inline style', async () => {
  assert.ok(CHART_TIMEFRAMES.includes('50ms'));
  assert.equal(THINKING_DEPTH_OPTIONS.length, 4);
  const mSchema = JSON.parse(await readFile(new URL('../../docs/contracts/market-stream.schema.json', import.meta.url), 'utf8'));
  const mRaw = await readFile(new URL('../../docs/contracts/initial-market-stream.json', import.meta.url), 'utf8');
  const state = displayState(fixture(), 'operate');
  state.marketStream = decodeMarketStream(mRaw, mSchema);
  const html = renderApp(state, Date.parse(time));
  assert.match(html, /data-thinking-depth="AUTO"/);
  assert.match(html, /data-thinking-depth="LOW"/);
  assert.match(html, /data-thinking-depth="MEDIUM"/);
  assert.match(html, /data-thinking-depth="HIGH"/);
  assert.match(html, /data-chart-tf="50ms"/);
  assert.match(html, /data-chart-zoom="in"/);
  assert.match(html, /5-Tier Parallel Account Growth Race/);
  assert.match(html, /Equity vs Bank Vault/);
  assert.equal(/\bstyle\s*=/.test(html), false);
});

test('ANALYTICS02 normalizeTreasury and normalizeParallelTiers validate schemas safely', () => {
  const treas = normalizeTreasury({
    schema: 'cas-forex.profit-vault/1',
    sweep_ratio: '0.5',
    sweep_ratio_pct: '50',
    auto_sweep_enabled: true,
    preferred_rail: 'COINBASE_ACH',
    total_realized_profit_usd: '1000',
    retained_trading_usd: '500',
    bank_sweep_reserved_usd: '500',
    disbursed_to_bank_usd: '250',
    pending_disbursement_usd: '250',
    recent_sweeps: [],
    recent_transfers: [],
  });
  assert.equal(treas.preferredRail, 'COINBASE_ACH');
  assert.equal(treas.bankSweepReservedUsd, '500');
  assert.throws(() => normalizeTreasury({ schema: 'wrong' }));

  const pt = normalizeParallelTiers({
    schema: 'cas-forex.parallel-tiers/1',
    tiers: [
      { tier_id: 'TIER_5_300', label: 'Tier $300', starting_capital_usd: '300', equity_usd: '300', growth_pct: '0', net_gain_usd: '0', drawdown_pct: '0', bank_sweep_reserved_usd: '0', win_rate_pct: '0', profit_factor: '0.00', open_positions: 0, last_skip_reason: 'LOT_FLOOR_RISK_EXCEEDED' },
    ],
    growth_series: { TIER_5_300: [{ observed_at: '2026-11-18T00:00:00Z', equity_usd: '300', growth_pct: '0' }] },
  });
  assert.equal(pt.tiers[0].lastSkipReason, 'LOT_FLOOR_RISK_EXCEEDED');
  assert.throws(() => normalizeParallelTiers({ schema: 'wrong' }));

  const html = renderParallelTiersSection({ parallelTiers: pt });
  assert.match(html, /LOT_FLOOR_RISK_EXCEEDED/);
  assert.equal(/\bstyle\s*=/.test(html), false);
});

test('ANALYTICS03 Profit Vault & Top Switcher escape hostile input and omit inline styles', () => {
  const html = renderEquityAndAnalyticsSection({
    treasury: normalizeTreasury({
      schema: 'cas-forex.profit-vault/1',
      preferred_rail: 'KRAKEN_ACH',
      auto_sweep_enabled: false,
      recent_sweeps: [],
      recent_transfers: [],
    }),
    aiTrader: {
      recentActions: [{ observedAt: '2026-11-18T00:00:00Z', kind: 'ADD_BUY', symbol: 'NAS100', detail: '<script>alert(1)</script>' }],
    },
  });
  assert.equal(html.includes('<script>'), false);
  assert.match(html, /&lt;script&gt;alert/);
  const bar = renderAiTopSwitcherBar({});
  assert.match(bar, /Auto \(2-Speed\)/);
});
