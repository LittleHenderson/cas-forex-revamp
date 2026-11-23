// PR #38 UI regression suite: Option B $5,000.00 Micro Futures Paper Demo card,
// normalization, XSS escaping, 0.0px-jump in-place patching, strict CSP, and LF hygiene.
// Flat top-level test() calls only; zero inline styles or external URLs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  OPTION_B_DEMO_CSS_SNIPPET,
  OPTION_B_DEMO_SCHEMA,
  STATIC_OPTION_B_DEMO,
  normalizeOptionBDemo,
  patchOptionBDemoPanelInPlace,
  pctBucketClass,
  renderOptionBDemoPanel,
} from '../../ui/src/option-b-demo-panel.mjs';

function makeMockPanel() {
  const nodes = new Map();
  const makeNode = (text = '', classes = []) => {
    const cls = new Set(classes);
    return {
      textContent: text,
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
    '[data-ob-status-badge="true"]',
    '[data-ob-equity="true"]',
    '[data-ob-dd="true"]',
    '[data-ob-net-pnl="true"]',
    '[data-ob-unrealized="true"]',
    '[data-ob-record="true"]',
    '[data-ob-closed-count="true"]',
    '[data-ob-vault="true"]',
    '[data-ob-house-money="true"]',
    '[data-ob-progress-fill="true"]',
    '[data-ob-open-summary="true"]',
    '[data-ob-closed-summary="true"]',
    '[data-ob-contract-mid="MNQ"]',
    '[data-ob-contract-open="MNQ"]',
    '[data-ob-contract-mid="MYM"]',
    '[data-ob-contract-open="MYM"]',
    '[data-ob-contract-mid="MES"]',
    '[data-ob-contract-open="MES"]',
    '[data-ob-contract-mid="MGC"]',
    '[data-ob-contract-open="MGC"]',
  ]) {
    nodes.set(sel, makeNode());
  }
  return {
    matches: (sel) => sel === '[data-option-b-demo="true"]',
    querySelector: (sel) => nodes.get(sel) ?? null,
    _nodes: nodes,
  };
}

test('OB01 normalizeOptionBDemo falls back safely and parses full Option B $5,000.00 payload', () => {
  assert.equal(normalizeOptionBDemo(null), STATIC_OPTION_B_DEMO);
  const norm = normalizeOptionBDemo({
    schema: OPTION_B_DEMO_SCHEMA,
    account_id: 'OPTION-B-PAPER-5K',
    status: 'PAPER_DEMO_ACTIVE',
    starting_equity_usd: '5000.00',
    balance_usd: '5240.50',
    equity_usd: '5295.00',
    unrealized_pnl_usd: '54.50',
    net_pnl_usd: '295.00',
    net_pnl_pct: '5.90',
    peak_equity_usd: '5300.00',
    drawdown_pct: '0.09',
    drawdown_locked: false,
    vault_50pct_reserved_usd: '120.25',
    retained_compounding_usd: '120.25',
    house_money_target_usd: '10000.00',
    house_money_progress_pct: '5.90',
    house_money_ready: false,
    closed_trades: 3,
    win_count: 2,
    loss_count: 1,
    win_rate_pct: '66.67',
    total_commissions_usd: '3.60',
    open_positions: [],
    recent_closed_trades: [],
    recent_events: [],
    supported_contracts: [
      { root_symbol: 'MNQ', cas_symbol: 'NAS100', display_name: 'Micro Nasdaq', exchange: 'CME', contract_code: 'MNQZ6', point_value_usd: '2', tick_size: '0.25', tick_value_usd: '0.50', open_contracts: 1, bid: '25640.00', ask: '25641.00', mid: '25640.50', quote_observed_at: '2026-11-22T23:50:00Z' },
    ],
    audit_chain_valid: true,
    observed_at: '2026-11-22T23:50:00Z',
  });
  assert.equal(norm.connected, true);
  assert.equal(norm.paperDemoOnly, true);
  assert.equal(norm.realMoneyAtRiskUsd, '0.00');
  assert.equal(norm.tradovateSignupRequired, false);
  assert.equal(norm.equityUsd, '5295.00');
  assert.equal(norm.vault50PctReservedUsd, '120.25');
  assert.equal(norm.winCount, 2);
});

test('OB02 renderOptionBDemoPanel renders $5,000.00 Micro Futures card, all 4 contracts, $0.00 real money badge, and zero inline style=', () => {
  const html = renderOptionBDemoPanel(STATIC_OPTION_B_DEMO);
  assert.match(html, /\$5,000\.00 Micro Futures Side-by-Side Proof/);
  assert.match(html, /\$0\.00 REAL MONEY AT RISK/);
  assert.match(html, /MNQ/);
  assert.match(html, /MYM/);
  assert.match(html, /MES/);
  assert.match(html, /MGC/);
  assert.equal(/\bstyle\s*=/i.test(html), false, 'Inline style attributes are forbidden');
});

test('OB03 renderOptionBDemoPanel escapes hostile HTML payloads safely', () => {
  const hostile = normalizeOptionBDemo({
    account_id: '<script>alert(1)</script>',
    status: 'PAPER_DEMO_ACTIVE',
    open_positions: [
      { position_id: 'p1', cas_symbol: 'NAS100', root_symbol: 'MNQ', contract_code: '<img src=x>', side: 'BUY', contracts: 1, entry_price: '25000.00', mark_price: '25010.00', unrealized_pnl_usd: '20.00', opened_at: '2026-11-22T23:50:00Z' },
    ],
  });
  const html = renderOptionBDemoPanel(hostile);
  assert.equal(html.includes('<script>'), false);
  assert.equal(html.includes('<img src=x>'), false);
});

test('OB04 patchOptionBDemoPanelInPlace updates equity, House-Money progress bucket, and live contracts with 0 DOM teardown', () => {
  const panel = makeMockPanel();
  const updated = normalizeOptionBDemo({
    status: 'PAPER_DEMO_ACTIVE',
    starting_equity_usd: '5000.00',
    equity_usd: '10150.00',
    net_pnl_usd: '5150.00',
    net_pnl_pct: '103.00',
    peak_equity_usd: '10150.00',
    drawdown_pct: '0.00',
    vault_50pct_reserved_usd: '2575.00',
    house_money_target_usd: '10000.00',
    house_money_progress_pct: '100.00',
    house_money_ready: true,
    closed_trades: 12,
    win_count: 9,
    loss_count: 3,
    win_rate_pct: '75.00',
    supported_contracts: [
      { root_symbol: 'MNQ', cas_symbol: 'NAS100', display_name: 'Micro Nasdaq', exchange: 'CME', contract_code: 'MNQZ6', point_value_usd: '2', tick_size: '0.25', tick_value_usd: '0.50', open_contracts: 2, bid: '25700.00', ask: '25701.00', mid: '25700.50', quote_observed_at: '2026-11-22T23:55:00Z' },
    ],
  });
  assert.equal(patchOptionBDemoPanelInPlace(panel, updated), true);
  assert.equal(panel._nodes.get('[data-ob-equity="true"]').textContent, '$10150.00');
  assert.equal(panel._nodes.get('[data-ob-net-pnl="true"]').classList.contains('is-positive'), true);
  assert.equal(panel._nodes.get('[data-ob-progress-fill="true"]').classList.contains('ob-pct-100'), true);
  assert.match(panel._nodes.get('[data-ob-house-money="true"]').textContent, /HOUSE-MONEY READY/);
  assert.equal(panel._nodes.get('[data-ob-contract-open="MNQ"]').textContent, '2 OPEN');
  assert.equal(pctBucketClass('48.20'), 'ob-pct-50');
});

test('OB05 Strict CSP, CSS snippet coverage, and LF (CR=0) hygiene across new PR #38 files', async () => {
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;
  for (const rel of [
    '../../ui/src/option-b-demo-panel.mjs',
    '../../docs/contracts/option-b-demo.schema.json',
    '../../src/cas_forex_revamp/composition/option_b_paper_runner.py',
  ]) {
    const raw = await readFile(new URL(rel, import.meta.url), 'utf8');
    assert.equal(raw.includes('\r'), false, `CRLF forbidden in ${rel}`);
    if (rel.endsWith('.mjs')) {
      assert.equal(innerHtmlRe.test(raw), false, `unsafe HTML property forbidden in ${rel}`);
      assert.equal(inlineStyleRe.test(raw), false, `inline style forbidden in ${rel}`);
    }
  }
  assert.match(OPTION_B_DEMO_CSS_SNIPPET, /\.ob-demo-panel/);
  assert.match(OPTION_B_DEMO_CSS_SNIPPET, /\.ob-pct-100/);
});
