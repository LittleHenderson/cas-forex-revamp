import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { renderApp } from '../../ui/src/render.mjs';
import { normalizeAiTrader } from '../../ui/src/ai-overseer.mjs';
import {
  RADAR_FILTERS,
  computeValveHudModel,
  renderLiveFeedStrip,
  renderTacticalValveHud,
  renderMarketRadarTable,
} from '../../ui/src/tactical-hud.mjs';
import { fixture, displayState, time } from './helpers.mjs';

function connectedHudState(overrides = {}) {
  const st = displayState(fixture(), 'operate');
  st.liveStreamConnected = true;
  st.brokerRouting = {
    connected: true,
    executionMode: 'DEMO',
    activeBroker: 'LHFX_MT5',
    shield: { drawdownPct: '0.08', totalEquity: '150278.66' },
  };
  st.demoHighGrowth = { enabled: true };
  st.marketStream = {
    streams: [
      { pair: 'EURUSD', bid: '1.09800', ask: '1.09812', spread_pips: '1.2' },
      { pair: 'USDJPY', bid: '155.100', ask: '155.150', spread_pips: '5.0' },
    ],
  };
  st.indexStream = {
    markets: [
      { pair: 'NAS100', bid: '26750.0', ask: '26751.5', spread_bps: '0.56' },
      { pair: 'SPX500', bid: '7204.5', ask: '7205.1', spread_bps: '0.83' },
      { pair: 'XAUUSD', bid: '3558.20', ask: '3558.70', spread_bps: '1.40' },
    ],
  };
  st.aiTrader = normalizeAiTrader({
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Autonomous loop active',
    operating_mode: 'ACTIVE_TRADING',
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 14,
    last_action: 'OPEN_BUY',
    last_symbol: 'XAUUSD',
    last_regime: 'TREND_IGNITION',
    last_reason: 'Clean alignment',
    last_valve_score: '0.91',
    valve_threshold: '0.55',
    offline_brokers: ['HUGOSWAY_MT5'],
    offline_broker_labels: ["Hugo's Way"],
    daily_quota: {
      schema: 'cas-forex.daily-quota/1',
      session_date: '2026-11-25',
      status: 'OPEN',
      new_risk_allowed: true,
    },
    open_positions: [
      {
        ticket: '13919780',
        broker_id: 'LHFX_MT5',
        symbol: 'XAUUSD',
        side: 'BUY',
        volume_lots: '0.78',
        entry_price: '3558.53',
        stop_loss: '3498.88',
        take_profit: '3691.28',
        profit: '561.60',
        protection_stage: 'INITIAL_SL',
      },
    ],
    recent_actions: [
      {
        observed_at: '2026-11-25T03:00:05Z',
        kind: 'OPEN_BUY',
        symbol: 'XAUUSD',
        detail: 'Entered 0.78 lots with 1.00R protection',
      },
      {
        observed_at: '2026-11-25T03:01:05Z',
        kind: 'WAIT',
        symbol: 'EURUSD',
        detail: 'HELD by chop range filter',
      },
    ],
    telegram_alerts: {
      schema: 'cas-forex.telegram-alerts/1',
      read_only: true,
      trading_authority: 'NONE',
      enabled: true,
      configured: true,
      status: 'ACTIVE',
      sent_count: 3,
      dropped_count: 0,
      error_count: 0,
      last_sent_at: '2026-11-25T03:00:06Z',
      last_event_kind: 'TRADE_OPENED',
      recent_alerts: [],
    },
  });
  return { ...st, ...overrides };
}

test('PR48-UI01 Disconnected Tactical HUD stays STANDBY with null score (no invented values)', () => {
  const st = displayState(fixture(), 'operate');
  const model = computeValveHudModel(st);
  assert.equal(model.connected, false);
  assert.equal(model.score, null);
  assert.equal(model.verdict, 'STANDBY');

  const appHtml = renderApp(st, Date.parse(time));
  assert.match(appHtml, /data-tactical-live-feed="true"/);
  assert.match(appHtml, /data-tactical-valve-hud="true"/);
  assert.match(appHtml, /data-market-radar="true"/);
  assert.match(appHtml, /TELEGRAM: STANDBY/);
  assert.equal(/\bstyle\s*=/i.test(appHtml), false, 'Zero inline styling permitted');
});

test('PR48-UI02 Connected Meta-Valve Gauge, 5 Checks, Live Decision Console, and Live Feed Strip render accurately', () => {
  const st = connectedHudState();
  const model = computeValveHudModel(st);
  assert.equal(model.connected, true);
  assert.ok(typeof model.score === 'number' && model.score >= 60 && model.score <= 100);
  assert.equal(model.checks.length, 5);
  assert.equal(model.telegram.status, 'ACTIVE');
  assert.equal(model.telegram.readOnly, true);

  const feedHtml = renderLiveFeedStrip(st);
  assert.match(feedHtml, /LIVE FEED/);
  assert.match(feedHtml, /OPEN XAUUSD BUY/);
  assert.match(feedHtml, /70\.00% DEMO floor armed/);
  assert.match(feedHtml, /TELEGRAM: ACTIVE/);

  const hudHtml = renderTacticalValveHud(st);
  assert.match(hudHtml, /valve-gauge-svg/);
  assert.match(hudHtml, /LIVE AI DECISION CONSOLE/);
  assert.match(hudHtml, /Claude Fable 5\.2/);
  assert.match(hudHtml, /OPEN_BUY/);
  assert.match(hudHtml, /READ-ONLY \(0 trading power\)/);
  assert.equal(/\bstyle\s*=/i.test(feedHtml), false);
  assert.equal(/\bstyle\s*=/i.test(hudHtml), false);
});

test('PR48-UI03 20-Market Radar shows OPEN/PASS/HELD badges, filters, and HTML-escapes hostile details', () => {
  assert.deepEqual(RADAR_FILTERS, ['all', 'active', 'held', 'indices', 'forex']);
  const st = connectedHudState({
    radarFilter: 'held',
    aiTrader: {
      ...connectedHudState().aiTrader,
      recentActions: [
        {
          observed_at: '2026-11-25T03:01:05Z',
          kind: 'VETOED',
          symbol: 'EURUSD',
          detail: '<script>alert(1)</script> chop veto',
        },
      ],
    },
  });
  const heldHtml = renderMarketRadarTable(st);
  assert.match(heldHtml, /EURUSD/);
  assert.match(heldHtml, /radar-row-held/);
  assert.match(heldHtml, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.equal(heldHtml.includes('<script>alert(1)</script>'), false);

  const allHtml = renderMarketRadarTable({ ...st, radarFilter: 'all' });
  assert.match(allHtml, /ALL \(20\)/);
  assert.match(allHtml, /data-radar-inspect="XAUUSD"/);
  assert.match(allHtml, /radar-badge-open/);
  assert.equal(/\bstyle\s*=/i.test(allHtml), false);
});

test('PR48-UI04 Midnight Blueprint CSS, SVG asset, app.mjs wiring, strict CSP, and LF hygiene', async () => {
  const checked = [
    ['ui/src/tactical-hud.mjs', '../../ui/src/tactical-hud.mjs'],
    ['ui/src/render.mjs', '../../ui/src/render.mjs'],
    ['ui/src/app.mjs', '../../ui/src/app.mjs'],
    ['ui/src/ai-overseer.mjs', '../../ui/src/ai-overseer.mjs'],
    ['ui/modernist.css', '../../ui/modernist.css'],
    ['ui/styles.css', '../../ui/styles.css'],
    ['ui/assets/blueprint-grid.svg', '../../ui/assets/blueprint-grid.svg'],
  ];
  for (const [label, rel] of checked) {
    const raw = await readFile(new URL(rel, import.meta.url), 'utf8');
    assert.equal(raw.includes('\r'), false, `${label} must be LF-only`);
    if (label.endsWith('.mjs')) {
      assert.equal(raw.includes('.innerHTML'), false, `${label} must omit .innerHTML`);
      assert.equal(raw.includes('.outerHTML'), false, `${label} must omit .outerHTML`);
      assert.equal(/\bstyle\s*=/i.test(raw), false, `${label} must omit inline styles`);
    }
  }
  const modCss = await readFile(new URL('../../ui/modernist.css', import.meta.url), 'utf8');
  assert.match(modCss, /--canvas:\s*#060b14/);
  assert.match(modCss, /blueprint-grid\.svg/);
  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  assert.match(appSrc, /radarFilter:\s*'all'/);
  assert.match(appSrc, /\/api\/telegram-alerts/);
});
