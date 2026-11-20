import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  MONEY_FLOW_CAPITAL_PRESETS,
  MONEY_FLOW_LOT_PRESETS,
  MONEY_FLOW_MARKET_ORDER,
  MONEY_FLOW_MARKETS,
  MONEY_FLOW_RISK_PRESETS,
  computeLotComparisonRows,
  computeMoneyFlowScenario,
  createDefaultMoneyFlowState,
  formatCentsUsd,
  renderMoneyFlowSection,
  stepMoneyFlowSimulation,
} from '../../ui/src/money-flow.mjs';
import { normalizeAiTrader, renderAiOverseerPanel, STATIC_AI_TRADER } from '../../ui/src/ai-overseer.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

test('Money Flow catalog exposes all 9 capital presets, 4 constitutional risk %, 11 lot presets, and 7 markets', () => {
  assert.deepEqual(MONEY_FLOW_CAPITAL_PRESETS, [300, 1000, 3000, 6000, 10000, 25000, 50000, 100000, 300000]);
  assert.deepEqual(MONEY_FLOW_RISK_PRESETS, [0.25, 0.5, 0.75, 1]);
  assert.equal(MONEY_FLOW_LOT_PRESETS.length, 11);
  assert.deepEqual(MONEY_FLOW_MARKET_ORDER, ['EURUSD', 'GBPUSD', 'USDJPY', 'NAS100', 'US30', 'SPX500', 'XAUUSD']);
  for (const id of MONEY_FLOW_MARKET_ORDER) {
    assert.ok(MONEY_FLOW_MARKETS[id]);
  }
});

test('EURUSD integer-cent math matches Safe 1% and hard-blocks 0.90 lots on $1,000', () => {
  const safe = computeMoneyFlowScenario({
    capitalCents: 100000,
    marketId: 'EURUSD',
    lotMode: 'risk',
    riskPct: 1,
    splitMode: '50_50',
    ownerMaxRiskPct: 1,
  });
  assert.equal(safe.lotText, '0.04');
  assert.equal(safe.winNetCents, 2172); // 55 * $0.40 = $22.00 - $0.28 fee
  assert.equal(safe.lossNetCents, 1028); // 25 * $0.40 = $10.00 + $0.28 fee
  assert.equal(safe.bankAddCents, 1086);
  assert.equal(safe.compAddCents, 1086);
  assert.equal(safe.allowed, true);

  const over = computeMoneyFlowScenario({
    capitalCents: 100000,
    marketId: 'EURUSD',
    lotMode: 'direct',
    directLotHundredths: 90,
    splitMode: '50_50',
    ownerMaxRiskPct: 5,
  });
  assert.equal(over.allowed, false);
  assert.equal(over.marginOk, false); // $198 margin on $1,000 = 505.05% < 1,000%
  assert.equal(over.winNetCents, 48870);
  assert.equal(over.lossNetCents, 23130);
});

test('XAUUSD (100 oz/lot) and NAS100 index math + simulation steps (+1 Win, +1 Loss, +5 Wins, Reset, 100% Compound)', () => {
  const gold = computeMoneyFlowScenario({
    capitalCents: 10000000, // $100,000
    marketId: 'XAUUSD',
    lotMode: 'risk',
    riskPct: 1,
    ownerMaxRiskPct: 1,
  });
  assert.equal(gold.allowed, true);
  assert.equal(gold.leverage, 200);
  assert.ok(gold.lotHundredths > 0 && gold.lotHundredths <= 5000);

  const nas = computeMoneyFlowScenario({
    capitalCents: 10000000,
    marketId: 'NAS100',
    lotMode: 'risk',
    riskPct: 5,
    ownerMaxRiskPct: 5,
  });
  assert.equal(nas.allowed, true);
  assert.equal(nas.ownerMaxRiskPct, 1, 'Constitutional risk ceiling clamps ownerMaxRiskPct to 1.00%');
  assert.ok(nas.riskPctActual <= 1.005, 'Risk mode clamps per-trade stop risk <= 1.00%');
  assert.ok(nas.lotHundredths <= 5000);

  let s = createDefaultMoneyFlowState();
  s = stepMoneyFlowSimulation(s, 'win', 1);
  assert.equal(s.simWins, 1);
  assert.ok(s.simCapitalCents > 100000);
  assert.ok(s.simBankCents > 0);

  s = stepMoneyFlowSimulation(s, 'win5', 1);
  assert.equal(s.simWins, 6);

  const beforeLoss = s.simCapitalCents;
  s = stepMoneyFlowSimulation(s, 'loss', 1);
  assert.equal(s.simLosses, 1);
  assert.ok(s.simCapitalCents < beforeLoss);

  // 100% Compound mode routes $0 to bank vault
  let comp = { ...createDefaultMoneyFlowState(), splitMode: '100_COMPOUND' };
  comp = stepMoneyFlowSimulation(comp, 'win', 1);
  assert.equal(comp.simBankCents, 0);
  assert.equal(comp.simCapitalCents, 100000 + 2172);

  const reset = stepMoneyFlowSimulation(s, 'reset', 1);
  assert.equal(reset.simWins, 0);
  assert.equal(reset.simLosses, 0);
  assert.equal(reset.simCapitalCents, 100000);
  assert.equal(reset.simBankCents, 0);
});

test('Lot Comparison cards, strict CSP (no inline styles or CDN URLs), and 3-Gear Risk normalization', () => {
  const rows = computeLotComparisonRows({
    capitalCents: 300000,
    marketId: 'EURUSD',
    selectedLotMode: 'direct',
    selectedDirectLotHundredths: 25,
  });
  assert.ok(rows.some((r) => r.selected && r.scenario.lotText === '0.25'));

  const htmlFlow = renderMoneyFlowSection({ moneyFlow: createDefaultMoneyFlowState() });
  assert.match(htmlFlow, /Money Movement Flowchart/);
  assert.match(htmlFlow, /data-money-flow-mount="true"/);
  assert.match(htmlFlow, /Live Balance/);
  assert.equal(/style="/i.test(htmlFlow), false, 'strict CSP forbids inline style attributes');
  assert.equal(/<script/i.test(htmlFlow), false);

  const htmlLots = renderMoneyFlowSection({ moneyFlow: { ...createDefaultMoneyFlowState(), tab: 'lots' } });
  assert.match(htmlLots, /Safe 1% Rule/);
  assert.equal(/style="/i.test(htmlLots), false);

  const src = fs.readFileSync(path.join(REPO_ROOT, 'ui/src/money-flow.mjs'), 'utf8');
  assert.equal(/innerHTML/i.test(src), false);
  assert.equal(/https?:\/\/(cdn|www\.gstatic)/i.test(src), false);

  const normalized = normalizeAiTrader({
    schema: 'cas-forex.ai-trader/1',
    governance_mode: 'ACTIVE',
    daily_quota: {
      session_date: '2026-11-19',
      status: 'OPEN',
      quota_mode: 'USD',
      realized_net_pnl_usd: '250',
      realized_pnl_pct: '0.25',
      soft_quota_usd: '2000',
      hard_quota_usd: '3000',
      max_daily_loss_usd: '12500',
      consecutive_losses: '0',
      max_consecutive_losses: '3',
      quota_progress_pct: '8.33',
      risk_multiplier: '1',
    },
    risk_gear: {
      owner_mode: 'AUTO_ADAPTIVE',
      active_gear: 'STRONG_TREND_RUNNER',
      effective_risk_pct: '5',
      owner_max_risk_pct: '5',
      effective_soft_quota_usd: '2000',
      effective_hard_quota_usd: '3000',
      owner_hard_quota_usd: '3000',
      soft_drawdown_downshift_pct: '0.1',
      owner_max_drawdown_pct: '0.2',
      reason: 'Strong-Trend Runner Gear active.',
    },
  });
  assert.equal(normalized.riskGear.ownerMode, 'AUTO_ADAPTIVE');
  assert.equal(normalized.riskGear.activeGear, 'STRONG_TREND_RUNNER');
  assert.equal(normalized.riskGear.effectiveRiskPct, '1');
  assert.equal(normalized.riskGear.ownerMaxRiskPct, '1');
  assert.equal(normalized.riskGear.ownerMaxDrawdownPct, '0.1');
  assert.equal(normalized.riskGear.effectiveHardQuotaUsd, '3000');

  const panelHtml = renderAiOverseerPanel({ aiTrader: normalized });
  assert.match(panelHtml, /data-risk-gear="CONSERVATIVE"/);
  assert.match(panelHtml, /data-risk-gear="AUTO_ADAPTIVE"/);
  assert.match(panelHtml, /data-risk-gear="AGGRESSIVE"/);
  assert.match(panelHtml, /Hard constitutional ceiling: 1\.00% max stop risk · 10\.00% max drawdown/);
  assert.match(panelHtml, /STRONG_TREND_RUNNER/);
  assert.equal(formatCentsUsd(123456), '$1,234.56');
  assert.ok(STATIC_AI_TRADER.riskGear);
});
