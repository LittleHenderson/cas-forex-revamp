import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AI_STRATEGY_LAB_SCHEMA,
  STATIC_AI_STRATEGY_LAB,
  normalizeAiStrategyLab,
  renderAiStrategyLabPanel,
} from '../../ui/src/ai-strategy-lab-panel.mjs';
import { resolveCockpitAiStrategyLab } from '../../ui/src/render.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const panelSource = fs.readFileSync(
  path.resolve(__dirname, '../../ui/src/ai-strategy-lab-panel.mjs'),
  'utf8',
);

test('PR49-UI-01: ai-strategy-lab-panel.mjs enforces strict zero-XSS and zero inline style rules', () => {
  assert.equal(panelSource.includes('.innerHTML'), false);
  assert.equal(panelSource.includes('.outerHTML'), false);
  assert.equal(panelSource.includes('insertAdjacentHTML'), false);
  assert.equal(panelSource.includes('style='), false);
});

test('PR49-UI-02: normalizeAiStrategyLab is idempotent and renders all 4 zones + dual balance/vault attribution', () => {
  const sample = {
    schema: AI_STRATEGY_LAB_SCHEMA,
    observed_at_utc: '2026-11-27T22:00:00Z',
    observed_at_pacific: '2026-11-27 14:00:00 PST',
    execution_mode: 'DEMO',
    accounting_basis: 'INTERNAL_LEDGER_NOT_CONFIRMED_PAYOUT',
    session_scope: 'OWNER_FULL_CONTROL',
    owner_controls_allowed: true,
    governance_safety: {
      valve_controller: 'tks_meta_valve_controller',
      valve_parameters: 161,
      valve_threshold: '0.55',
      all_intents_valve_gated: true,
      news_shock_shield_active: true,
      correlated_offset_guard_threshold: '0.45',
      single_broker_equity_sizing: true,
      live_constitutional_ceilings: {
        max_stop_risk_pct: '1.00',
        max_drawdown_pct: '10.00',
        auto_replenish_allowed_in_live: false,
      },
      effective_stop_risk_ceiling_pct: '5.00',
      owner_controls_allowed: true,
      audit_head_sha256: 'a'.repeat(64),
      audit_entry_count: 2,
    },
    capital_attribution_summary: {
      starting_balance_usd: '200000.00',
      current_online_equity_usd: '204250.00',
      capital_status: 'IN_SURPLUS',
      vault_sweeps_paused_for_recovery: false,
      total_strategy_net_pnl_usd: '4250.00',
      total_starting_balance_contribution_usd: '2125.00',
      total_vaulted_profit_contribution_usd: '2125.00',
      unattributed_legacy_pnl_usd: '0.00',
    },
    counts: {
      active_count: 1,
      shadow_count: 1,
      quarantined_count: 1,
      field_notes_total: 1,
      shadow_trades_total: 12,
      vetoed_proposals_total: 0,
    },
    active_strategies: [
      {
        strategy_id: 'S1_M5_ALIGNED_TREND_PULLBACK',
        display_name: 'M5 Aligned Trend Pullback',
        version: 1,
        origin: 'CORE_BASELINE',
        status: 'ACTIVE',
        archetype: 'TREND_FOLLOW',
        target_markets: ['US30', 'EURUSD'],
        preferred_regimes: ['STRONG_TREND'],
        blueprint_summary: 'EMA_PULLBACK | KER 0.35..1.00',
        risk_profile: {
          risk_weight_multiplier: '0.95',
          max_stop_risk_pct: '4.75',
          min_valve_score: '0.55',
          allow_pyramiding: true,
        },
        metrics: {
          closed_trades: 10,
          win_count: 7,
          loss_count: 3,
          win_rate_pct: '70.00',
          r_expectancy: '0.6200',
          profit_factor: '2.45',
          cusum_drift: '0.0000',
          max_drawdown_r: '1.20',
        },
        attribution: {
          net_pnl_usd: '4250.00',
          starting_balance_contribution_usd: '2125.00',
          vaulted_profit_contribution_usd: '2125.00',
          open_positions_count: 1,
          last_trade_at_utc: '2026-11-27T21:55:00Z',
        },
        promoted_at_utc: '2026-11-27T00:00:00Z',
        status_reason: 'Active core trend playbook',
      },
    ],
    shadow_strategies: [
      {
        strategy_id: 'S5_FX_G10_PRECISION_PULLBACK_V1',
        display_name: 'G10 FX Challenger',
        version: 1,
        origin: 'AI_EVOLVED',
        status: 'SHADOW_INCUBATING',
        archetype: 'TREND_FOLLOW',
        hypothesis_plain_english: 'Dedicated 16-pair G10 FX challenger',
        target_markets: ['EURUSD'],
        preferred_regimes: ['STRONG_TREND'],
        blueprint_summary: 'EMA_PULLBACK',
        shadow_metrics: {
          shadow_trades: 15,
          shadow_win_count: 10,
          shadow_loss_count: 5,
          shadow_win_rate_pct: '66.67',
          shadow_r_expectancy: '0.4100',
          shadow_profit_factor: '1.88',
          shadow_net_pnl_usd: '310.00',
          shadow_max_drawdown_r: '2.10',
          simulated_valve_pass_rate_pct: '100.00',
        },
        graduation: {
          required_trades: 30,
          completed_trades: 15,
          required_min_profit_factor: '1.25',
          required_min_r_expectancy: '0.15',
          required_max_drawdown_r: '8.00',
          progress_pct: '50.00',
          progress_bucket: 50,
          ready_for_promotion: false,
          blocking_reason: 'SHADOW_N_BELOW_MIN (15/30)',
        },
        created_at_utc: '2026-11-27T00:00:00Z',
        last_shadow_trade_at_utc: '2026-11-27T21:50:00Z',
      },
    ],
    quarantined_strategies: [
      {
        strategy_id: 'AI_EVOLVED_CHOP01',
        display_name: 'Chop Test Variant',
        version: 2,
        origin: 'AI_EVOLVED',
        status: 'QUARANTINED',
        archetype: 'TREND_FOLLOW',
        retired_by: 'AI_SELF_AUDIT',
        retirement_reason_code: 'CELL_CUSUM_QUARANTINE',
        retirement_reason_plain_english: 'Retired after 4 chop losses to protect balance.',
        final_metrics: {
          closed_trades: 5,
          win_rate_pct: '20.00',
          r_expectancy: '-0.5500',
          net_pnl_usd: '-550.00',
          starting_balance_contribution_usd: '-550.00',
          vaulted_profit_contribution_usd: '0.00',
          max_drawdown_r: '3.66',
        },
        quarantined_at_utc: '2026-11-27T20:00:00Z',
        cooldown_until_utc: '2026-11-28T08:00:00Z',
      },
    ],
    field_notes: [
      {
        note_id: 'note-000001',
        seq_no: 1,
        observed_at_utc: '2026-11-27T21:58:00Z',
        observed_at_pacific: '2026-11-27 13:58:00 PST',
        author_role: 'OWNER_WAKIL',
        note_category: 'OWNER_DIRECTIVE',
        headline: 'Prioritize clean London FX & US30 pullbacks',
        body_plain_english: 'Avoid holiday midday chop <script>alert(1)</script>',
        related_strategy_id: null,
        related_symbol: 'US30',
        related_ticket: null,
        impact_pnl_usd: null,
        pinned_by_owner: true,
        acknowledged_by_ai: true,
        entry_sha256: 'b'.repeat(64),
      },
    ],
  };

  const norm1 = normalizeAiStrategyLab(sample);
  const norm2 = normalizeAiStrategyLab(norm1);
  assert.equal(norm1, norm2);
  assert.equal(resolveCockpitAiStrategyLab({ aiStrategyLab: norm1 }), norm1);
  assert.equal(resolveCockpitAiStrategyLab({}), STATIC_AI_STRATEGY_LAB);

  const html = renderAiStrategyLabPanel(norm1);
  assert.ok(html.includes('data-ai-strategy-lab="true"'));
  assert.ok(html.includes('+$2125.00'));
  assert.ok(html.includes('M5 Aligned Trend Pullback'));
  assert.ok(html.includes('G10 FX Challenger'));
  assert.ok(html.includes('Chop Test Variant'));
  assert.ok(html.includes('PINNED FOR AI'));
  assert.equal(html.includes('<script>alert(1)</script>'), false);
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});
