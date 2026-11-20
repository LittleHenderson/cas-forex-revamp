// Strict-CSP tests for Thermal Market Signal Heatmap, Broker-Attributed Top Status /
// Realized P/L Provenance Strip, and Dark-Mode Obsidian Vault & Drawdown Analytics.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OBSIDIAN_BG_HEX,
  OBSIDIAN_THERMAL_CSS_SNIPPET,
  VALVE_SCORE_CUTOFF,
  classifySessionFromIso,
  computeMarketTemperatureTiles,
  deriveRealizedProvenanceFromState,
  drawObsidianDrawdownChart,
  drawObsidianEquityVaultChart,
  formatBrokerDisplayName,
  formatDualDateTime,
  formatExactUsd,
  formatSignedUsd,
  isSyntheticSweepRow,
  quantizeMeterPctClass,
  renderImmediateStatusAndLastTradeStrip,
  renderObsidianVaultProgressCard,
  renderRealizedPnlProvenanceTable,
  renderThermalMarketHeatmap,
} from '../../ui/src/market-thermal.mjs';

function createRecordingCanvas(width = 460, height = 210) {
  const ops = [];
  let fillStyle = '';
  let strokeStyle = '';
  let lineWidth = 1;
  let font = '';
  let lineDash = [];

  const ctx = {
    get fillStyle() { return fillStyle; },
    set fillStyle(v) { fillStyle = v; ops.push({ op: 'setFillStyle', value: v }); },
    get strokeStyle() { return strokeStyle; },
    set strokeStyle(v) { strokeStyle = v; ops.push({ op: 'setStrokeStyle', value: v }); },
    get lineWidth() { return lineWidth; },
    set lineWidth(v) { lineWidth = v; },
    get font() { return font; },
    set font(v) { font = v; },
    fillRect(x, y, w, h) { ops.push({ op: 'fillRect', x, y, w, h, fillStyle }); },
    beginPath() { ops.push({ op: 'beginPath' }); },
    closePath() { ops.push({ op: 'closePath' }); },
    moveTo(x, y) { ops.push({ op: 'moveTo', x, y }); },
    lineTo(x, y) { ops.push({ op: 'lineTo', x, y }); },
    stroke() { ops.push({ op: 'stroke', strokeStyle, lineDash: [...lineDash] }); },
    fill() { ops.push({ op: 'fill', fillStyle }); },
    setLineDash(arr) { lineDash = [...arr]; ops.push({ op: 'setLineDash', value: [...arr] }); },
    fillText(text, x, y) { ops.push({ op: 'fillText', text: String(text), x, y, fillStyle }); },
    createLinearGradient(x0, y0, x1, y1) {
      const stops = [];
      const grad = {
        kind: 'linearGradient',
        coords: [x0, y0, x1, y1],
        stops,
        addColorStop(offset, color) { stops.push([offset, color]); },
      };
      ops.push({ op: 'createLinearGradient', coords: [x0, y0, x1, y1] });
      return grad;
    },
  };

  return {
    width,
    height,
    ops,
    getAttribute(attr) {
      if (attr === 'width') return String(width);
      if (attr === 'height') return String(height);
      return null;
    },
    getContext(kind) {
      return kind === '2d' ? ctx : null;
    },
  };
}

function sampleRichState() {
  return {
    aiTrader: {
      connected: true,
      governanceMode: 'ACTIVE',
      operatingMode: 'ACTIVE_TRADING',
      effectiveStatus: 'ACTIVE',
      respiteMode: false,
      lastValveScore: '0.72',
      openPositions: [
        { broker_id: 'LHFX_MT5', ticket: '9001', symbol: 'NAS100', side: 'BUY', volume_lots: '0.50', price_open: '21150.25', profit: '412.50' },
        { broker_id: 'HUGOSWAY_MT5', ticket: '9002', symbol: 'US30', side: 'BUY', volume_lots: '0.25', price_open: '43510.00', profit: '188.25' },
      ],
      recentActions: [
        { observedAt: '2026-11-20T08:30:00Z', kind: 'OPEN_BUY', symbol: 'NAS100', detail: 'Momentum breakout above M5 high' },
        { observedAt: '2026-11-20T08:35:00Z', kind: 'ADD_BUY', symbol: 'NAS100', detail: 'Confirmed trend expansion' },
        { observedAt: '2026-11-20T08:36:00Z', kind: 'OPEN_BUY', symbol: 'US30', detail: 'Mild bullish drift' },
        { observedAt: '2026-11-20T08:38:00Z', kind: 'OPEN_SELL', symbol: 'GBPUSD', detail: 'Bearish breakdown below London low' },
      ],
      bankedSession: {
        initialCapitalUsd: '300000',
        currentTotalEquityUsd: '296420.75',
        confirmedBankPayoutsUsd: '0',
        pendingUnconfirmedTransfersUsd: '5000.00',
        capitalStatus: 'RECOVERY_MODE',
        vaultSweepsPausedForRecovery: true,
        bankedNetPnlUsd: '1245.55',
        vaultRetained50PctUsd: '1245.55',
        vaultSwept50PctUsd: '0',
      },
    },
    treasury: {
      connected: true,
      totalRealizedProfitUsd: '1245.55',
      retainedTradingUsd: '1245.55',
      bankSweepReservedUsd: '0.00',
      confirmedSettledDisbursedUsd: '0.00',
      pendingUnconfirmedTransfersUsd: '5000.00',
      recentSweeps: [
        { tradeId: 'tr-101', symbol: 'NAS100', brokerId: 'LHFX_MT5', realizedNetUsd: '612.40', retainedTradingUsd: '612.40', bankSweepUsd: '0', occurredAt: '2026-11-20T08:41:12Z' },
        { tradeId: 'tr-102', symbol: 'US30', brokerId: 'HUGOSWAY_MT5', realizedNetUsd: '420.15', retainedTradingUsd: '420.15', bankSweepUsd: '0', occurredAt: '2026-11-20T03:15:00Z' },
        { tradeId: 'tr-103', symbol: 'EUR/USD', brokerId: 'OANDA_PRACTICE', realizedNetUsd: '213.00', retainedTradingUsd: '213.00', bankSweepUsd: '0', occurredAt: '2026-11-19T16:20:00Z' },
        { tradeId: 'sync-999', symbol: 'SESSION_SYNC', brokerId: 'SESSION_BASKET', realizedNetUsd: '50.00', retainedTradingUsd: '50.00', bankSweepUsd: '0', occurredAt: '2026-11-20T09:00:00Z' },
      ],
    },
    indexStream: {
      markets: [
        {
          pair: 'NAS100',
          display_pair: 'NAS100 / NDX',
          category: 'US_INDEX',
          bid: '21280.50',
          ask: '21281.75',
          spread_points: '1.25',
          change_24h_pct: '2.15',
          candles_m1: [{ t: '2026-11-20T08:40:00Z', o: '21210.00', h: '21285.00', l: '21208.00', c: '21280.50' }],
          candles_m5: [{ t: '2026-11-20T08:35:00Z', o: '21170.00', h: '21285.00', l: '21165.00', c: '21280.50' }],
        },
        {
          pair: 'US30',
          display_pair: 'US30 / DJIA',
          category: 'US_INDEX',
          bid: '43590.00',
          ask: '43593.50',
          spread_points: '3.50',
          change_24h_pct: '0.65',
          candles_m1: [{ t: '2026-11-20T08:40:00Z', o: '43570.00', h: '43595.00', l: '43568.00', c: '43590.00' }],
          candles_m5: [{ t: '2026-11-20T08:35:00Z', o: '43550.00', h: '43595.00', l: '43548.00', c: '43590.00' }],
        },
        {
          pair: 'XAUUSD',
          display_pair: 'XAU/USD · Gold',
          category: 'US_INDEX',
          bid: '2640.10',
          ask: '2640.50',
          spread_points: '0.40',
          change_24h_pct: '0.02',
          candles_m1: [{ t: '2026-11-20T08:40:00Z', o: '2640.05', h: '2640.40', l: '2639.95', c: '2640.10' }],
          candles_m5: [{ t: '2026-11-20T08:35:00Z', o: '2640.00', h: '2640.40', l: '2639.90', c: '2640.10' }],
        },
      ],
    },
    marketStream: {
      streams: [
        {
          pair: 'EURUSD',
          display_pair: 'EUR/USD',
          category: 'MAJOR',
          bid: '1.08420',
          ask: '1.08428',
          spread_pips: '0.8',
          change_24h_pct: '-0.48',
          candles_m1: [{ t: '2026-11-20T08:40:00Z', o: '1.08455', h: '1.08460', l: '1.08415', c: '1.08420' }],
          candles_m5: [{ t: '2026-11-20T08:35:00Z', o: '1.08480', h: '1.08485', l: '1.08415', c: '1.08420' }],
          valve_score: '0.48',
        },
        {
          pair: 'GBPUSD',
          display_pair: 'GBP/USD',
          category: 'MAJOR',
          bid: '1.25100',
          ask: '1.25132',
          spread_pips: '3.2',
          change_24h_pct: '-1.35',
          candles_m1: [{ t: '2026-11-20T08:40:00Z', o: '1.25280', h: '1.25290', l: '1.25095', c: '1.25100' }],
          candles_m5: [{ t: '2026-11-20T08:35:00Z', o: '1.25410', h: '1.25420', l: '1.25095', c: '1.25100' }],
          valve_score: '0.29',
        },
      ],
    },
    parallelTiers: {
      tiers: [
        { tierId: 'TIER_1_CURRENT', startingCapitalUsd: '300000', equityUsd: '296420.75', peakEquityUsd: '301200.00', drawdownPct: '-1.59' },
      ],
      growthSeries: {
        TIER_1_CURRENT: [
          { observedAt: '2026-11-18T00:00:00Z', equityUsd: '300000.00', growthPct: '0.00' },
          { observedAt: '2026-11-18T12:00:00Z', equityUsd: '301200.00', growthPct: '0.40' },
          { observedAt: '2026-11-19T00:00:00Z', equityUsd: '294000.00', growthPct: '-2.00' },
          { observedAt: '2026-11-20T08:41:12Z', equityUsd: '296420.75', growthPct: '-1.19' },
        ],
      },
    },
  };
}

test('THERMAL01 broker display formatting maps real brokers cleanly and filters synthetic markers', () => {
  assert.equal(formatBrokerDisplayName('LHFX_MT5'), 'LHFX');
  assert.equal(formatBrokerDisplayName('LHFX_LIVE'), 'LHFX');
  assert.equal(formatBrokerDisplayName('HUGOSWAY_MT5'), "Hugo's Way");
  assert.equal(formatBrokerDisplayName('HUGOS_WAY'), "Hugo's Way");
  assert.equal(formatBrokerDisplayName('OANDA_PRACTICE'), 'OANDA');
  assert.equal(formatBrokerDisplayName('OANDA_LIVE'), 'OANDA');
  assert.equal(formatBrokerDisplayName('SESSION_SYNC'), null);
  assert.equal(formatBrokerDisplayName('SESSION_BASKET'), null);
  assert.equal(formatBrokerDisplayName('PORTFOLIO_RECONCILE'), null);
  assert.equal(formatBrokerDisplayName(''), null);

  assert.equal(isSyntheticSweepRow({ symbol: 'SESSION_SYNC', brokerId: 'LHFX_MT5' }), true);
  assert.equal(isSyntheticSweepRow({ symbol: 'NAS100', brokerId: 'SESSION_BASKET' }), true);
  assert.equal(isSyntheticSweepRow({ symbol: 'NAS100', brokerId: 'LHFX_MT5', tradeId: 'tr-1' }), false);
});

test('THERMAL02 exact 3-region UTC session classification and deterministic Pacific + UTC dual timestamps', () => {
  assert.deepEqual(classifySessionFromIso('2026-11-20T21:59:59Z'), { sessionId: 'NEW_YORK', sessionLabel: 'New York / US' });
  assert.deepEqual(classifySessionFromIso('2026-11-20T22:00:00Z'), { sessionId: 'ASIA', sessionLabel: 'Asia / Tokyo\u2013Sydney' });
  assert.deepEqual(classifySessionFromIso('2026-11-20T06:59:59Z'), { sessionId: 'ASIA', sessionLabel: 'Asia / Tokyo\u2013Sydney' });
  assert.deepEqual(classifySessionFromIso('2026-11-20T07:00:00Z'), { sessionId: 'LONDON', sessionLabel: 'London' });
  assert.deepEqual(classifySessionFromIso('2026-11-20T11:59:59Z'), { sessionId: 'LONDON', sessionLabel: 'London' });
  assert.deepEqual(classifySessionFromIso('2026-11-20T12:00:00Z'), { sessionId: 'NEW_YORK', sessionLabel: 'New York / US' });

  const winter = formatDualDateTime('2026-11-20T08:41:12Z');
  assert.equal(winter.utc, '2026-11-20 08:41:12 UTC');
  assert.equal(winter.datePt, '2026-11-20');
  assert.match(winter.localPt, /^Nov 20, 2026 \u00b7 12:41:12 AM PST$/);
  assert.match(winter.combined, /Nov 20, 2026 \u00b7 12:41:12 AM PST \(2026-11-20 08:41:12 UTC\)/);

  const summer = formatDualDateTime('2026-07-15T18:30:00Z');
  assert.equal(summer.utc, '2026-07-15 18:30:00 UTC');
  assert.match(summer.localPt, /^Jul 15, 2026 \u00b7 11:30:00 AM PDT$/);
});

test('THERMAL03 provenance derivation excludes SESSION_SYNC from lastRealTrade/markets/brokers and sums exact unrounded decimals', () => {
  const state = sampleRichState();
  const prov = deriveRealizedProvenanceFromState(state);

  assert.equal(prov.isCurrentlyTrading, true);
  assert.equal(prov.statusCode, 'TRADING_NOW');
  assert.deepEqual(prov.openMarkets, ['NAS100', 'US30']);
  assert.deepEqual(prov.openBrokers, ['LHFX', "Hugo's Way"]);

  // Synthetic SESSION_SYNC row occurred later (09:00Z) but MUST NOT become lastRealTrade or pollute byMarket/byBroker!
  assert.equal(prov.lastRealTrade.tradeId, 'tr-101');
  assert.equal(prov.lastRealTrade.symbol, 'NAS100');
  assert.equal(prov.lastRealTrade.brokerLabel, 'LHFX');
  assert.equal(prov.lastRealTrade.realizedNetUsd, '612.40');
  assert.equal(prov.lastRealTrade.sessionLabel, 'London');
  assert.equal(prov.realizedRows.length, 3);
  assert.equal(prov.byMarket.some((m) => m.symbol === 'SESSION_SYNC'), false);
  assert.equal(prov.byBroker.some((b) => b.brokerLabel === 'SESSION_BASKET'), false);

  assert.deepEqual(prov.byBroker.map((b) => [b.brokerLabel, b.totalRealizedUsd]), [
    ['LHFX', '612.40'],
    ["Hugo's Way", '420.15'],
    ['OANDA', '213.00'],
  ]);
  assert.equal(prov.totals.realTradeRealizedUsd, '1245.55');
  assert.equal(prov.totals.syntheticAdjustmentUsd, '50.00');
  assert.equal(prov.totals.combinedTotalRealizedUsd, '1295.55');
  assert.equal(prov.totals.realTradeCount, 3);
  assert.equal(prov.totals.syntheticRowCount, 1);

  // Exact unrounded USD formatting check
  assert.equal(formatExactUsd('1245.5575'), '$1,245.5575');
  assert.equal(formatSignedUsd('-42.10'), '-$42.10');
});

test('THERMAL04 backend snake_case realized_provenance payload integrates seamlessly', () => {
  const backendState = {
    aiTrader: {
      realized_provenance: {
        live_trading_status: {
          is_currently_trading: false,
          state_code: 'PAUSED_RESEARCH_RESPITE',
          headline: 'PAUSED — RESEARCH RESPITE (BANKED)',
          open_position_count: 0,
          open_markets: [],
          open_brokers: [],
        },
        realized_entries: [
          {
            trade_id: 'py-1',
            symbol: 'XAUUSD',
            broker_id: 'HUGOSWAY_MT5',
            broker_label: "Hugo's Way",
            realized_net_usd: '777.77',
            occurred_at_utc: '2026-11-20T14:05:00Z',
            session_id: 'NEW_YORK',
            session_label: 'New York / US',
          },
        ],
        totals: {
          synthetic_adjustment_usd: '12.50',
          synthetic_row_count: 1,
        },
      },
    },
  };
  const prov = deriveRealizedProvenanceFromState(backendState);
  assert.equal(prov.statusCode, 'PAUSED_RESEARCH_RESPITE');
  assert.equal(prov.isCurrentlyTrading, false);
  assert.equal(prov.lastRealTrade.symbol, 'XAUUSD');
  assert.equal(prov.lastRealTrade.brokerLabel, "Hugo's Way");
  assert.equal(prov.lastRealTrade.sessionLabel, 'New York / US');
  assert.equal(prov.totals.combinedTotalRealizedUsd, '790.27');
});

test('THERMAL05 top strip renders TRADING NOW vs PAUSED — RESEARCH RESPITE with Pacific+UTC timestamps, broker chips, and zero inline styles', () => {
  const tradingHtml = renderImmediateStatusAndLastTradeStrip(sampleRichState());
  assert.match(tradingHtml, /TRADING NOW/);
  assert.match(tradingHtml, /status-pulse/);
  assert.match(tradingHtml, /NAS100/);
  assert.match(tradingHtml, /LHFX/);
  assert.match(tradingHtml, /Hugo&#39;s Way/);
  assert.match(tradingHtml, /OANDA/);
  assert.match(tradingHtml, /Nov 20, 2026 \u00b7 12:41:12 AM PST/);
  assert.match(tradingHtml, /2026-11-20 08:41:12 UTC/);
  assert.match(tradingHtml, /London/);
  assert.match(tradingHtml, /\+\$612\.40/);
  assert.equal(tradingHtml.includes('SESSION_SYNC'), false);
  assert.equal(/\bstyle\s*=/i.test(tradingHtml), false);

  const respiteState = {
    aiTrader: {
      governanceMode: 'ACTIVE',
      operatingMode: 'RESEARCH_RESPITE',
      respiteMode: true,
      openPositions: [],
      bankedSession: { profitsLockedForSession: true, operatingMode: 'RESEARCH_RESPITE' },
    },
    treasury: { recentSweeps: [] },
  };
  const respiteHtml = renderImmediateStatusAndLastTradeStrip(respiteState);
  assert.match(respiteHtml, /PAUSED \u2014 RESEARCH RESPITE/);
  assert.equal(respiteHtml.includes('status-pulse'), false);
  assert.equal(/\bstyle\s*=/i.test(respiteHtml), false);

  const lockHtml = renderImmediateStatusAndLastTradeStrip({
    aiTrader: { governanceMode: 'STOPPED', openPositions: [], dailyQuota: { status: 'DAILY_LOSS_CIRCUIT_TRIPPED' } },
  });
  assert.match(lockHtml, /PAUSED \u2014 SAFETY LOCK/);
  assert.equal(/\bstyle\s*=/i.test(lockHtml), false);

  const tableHtml = renderRealizedPnlProvenanceTable(sampleRichState());
  assert.match(tableHtml, /Realized P\/L Provenance Ledger/);
  assert.match(tableHtml, /2026-11-20 08:41:12 UTC/);
  assert.match(tableHtml, /Hugo&#39;s Way/);
  assert.match(tableHtml, /Excluded 1 synthetic sync adjustment/);
  assert.equal(/\bstyle\s*=/i.test(tableHtml), false);
});

test('THERMAL06 thermal heatmap produces all 5 distinct heat bands across indices and FX with spread + 0.55 valve classes and zero inline styles', () => {
  assert.equal(VALVE_SCORE_CUTOFF, 0.55);
  assert.equal(quantizeMeterPctClass(72), 'meter-pct-70');
  assert.equal(quantizeMeterPctClass(55), 'meter-pct-55');
  assert.equal(quantizeMeterPctClass(112), 'meter-pct-100');
  assert.equal(quantizeMeterPctClass(-5), 'meter-pct-0');

  const state = sampleRichState();
  const tiles = computeMarketTemperatureTiles(state);
  assert.equal(tiles.length, 5);

  const byPair = Object.fromEntries(tiles.map((t) => [t.pair, t]));
  assert.equal(byPair.NAS100.heatClass, 'heat-hot-buy');
  assert.equal(byPair.NAS100.heatLabel, 'HOT BUY');
  assert.equal(byPair.NAS100.spreadClass, 'spread-tight');
  assert.equal(byPair.NAS100.valveHeatClass, 'valve-pass');
  assert.equal(byPair.NAS100.valveMeterClass, 'meter-pct-70');
  assert.equal(byPair.NAS100.signalCount, 2);

  assert.equal(byPair.US30.heatClass, 'heat-warm-buy');
  assert.equal(byPair.US30.heatLabel, 'WARM BUY');
  assert.equal(byPair.US30.spreadClass, 'spread-normal');

  assert.equal(byPair.XAUUSD.heatClass, 'heat-neutral');
  assert.equal(byPair.XAUUSD.heatLabel, 'NEUTRAL');
  assert.equal(byPair.XAUUSD.spreadClass, 'spread-tight');

  assert.equal(byPair.EURUSD.heatClass, 'heat-cool-sell');
  assert.equal(byPair.EURUSD.heatLabel, 'COOL SELL');
  assert.equal(byPair.EURUSD.spreadClass, 'spread-tight');
  assert.equal(byPair.EURUSD.valveHeatClass, 'valve-borderline');

  assert.equal(byPair.GBPUSD.heatClass, 'heat-cold-sell');
  assert.equal(byPair.GBPUSD.heatLabel, 'COLD SELL');
  assert.equal(byPair.GBPUSD.spreadClass, 'spread-wide');
  assert.equal(byPair.GBPUSD.valveHeatClass, 'valve-blocked');

  const html = renderThermalMarketHeatmap(state);
  for (const band of ['heat-hot-buy', 'heat-warm-buy', 'heat-neutral', 'heat-cool-sell', 'heat-cold-sell']) {
    assert.ok(html.includes(band), `Expected heatmap HTML to include ${band}`);
  }
  assert.match(html, /meter-pct-70/);
  assert.equal(/\bstyle\s*=/i.test(html), false);
});

test('THERMAL07 XSS adversarial strings in broker/symbol/detail are strictly escaped across ALL renderers with zero inline styles', () => {
  const xss = '<script>alert("xss")</script>\'"';
  const hostileState = {
    aiTrader: {
      governanceMode: 'ACTIVE',
      openPositions: [{ broker_id: xss, symbol: 'NAS<img src=x onerror=1>', side: 'BUY' }],
      recentActions: [{ observedAt: '2026-11-20T08:40:00Z', kind: 'BUY', symbol: 'NAS100', detail: xss }],
      lastValveScore: '0.60',
      bankedSession: { initialCapitalUsd: '300000', currentTotalEquityUsd: '299000' },
    },
    treasury: {
      recentSweeps: [
        { tradeId: xss, symbol: '<svg onload=alert(1)>', brokerId: xss, realizedNetUsd: '123.45', occurredAt: '2026-11-20T08:41:12Z' },
      ],
    },
    indexStream: {
      markets: [
        { pair: 'NAS100', display_pair: xss, bid: '21000', ask: '21001', spread_points: '1', change_24h_pct: '0.50' },
      ],
    },
  };

  const outputs = [
    renderImmediateStatusAndLastTradeStrip(hostileState),
    renderRealizedPnlProvenanceTable(hostileState),
    renderThermalMarketHeatmap(hostileState),
    renderObsidianVaultProgressCard(hostileState),
  ];

  for (const html of outputs) {
    assert.equal(html.includes('<script>'), false);
    assert.equal(html.includes('<svg'), false);
    assert.equal(html.includes('<img'), false);
    assert.equal(/\bstyle\s*=/i.test(html), false);
  }
  assert.match(outputs[0], /&lt;script&gt;alert\(&quot;xss&quot;\)&lt;\/script&gt;/);
  assert.match(outputs[2], /&lt;script&gt;alert\(&quot;xss&quot;\)&lt;\/script&gt;/);
});

test('THERMAL08 Obsidian Vault card shows 100% Rebuilding Principal while underwater vs 50% Compounding / 50% Bank Vault in surplus', () => {
  // Underwater below $300,000 even with $5,000 PENDING transfer (pending NEVER exits recovery!)
  const underwaterHtml = renderObsidianVaultProgressCard(sampleRichState());
  assert.match(underwaterHtml, /100% Rebuilding Principal/);
  assert.equal(underwaterHtml.includes('50% Compounding / 50% Bank Vault'), false);
  assert.match(underwaterHtml, /\$296,420\.75/);
  assert.match(underwaterHtml, /\$300,000\.00/);
  assert.match(underwaterHtml, /\$5,000\.00/);
  assert.match(underwaterHtml, /LHFX/);
  assert.match(underwaterHtml, /Hugo&#39;s Way/);
  assert.match(underwaterHtml, /OANDA/);
  assert.match(underwaterHtml, /meter-pct-100|meter-pct-95/);
  assert.equal(/\bstyle\s*=/i.test(underwaterHtml), false);

  // Surplus above $300,000
  const surplusState = {
    aiTrader: {
      bankedSession: {
        initialCapitalUsd: '300000',
        currentTotalEquityUsd: '304250.88',
        confirmedBankPayoutsUsd: '1000.00',
        pendingUnconfirmedTransfersUsd: '250.00',
        capitalStatus: 'IN_SURPLUS',
        vaultSweepsPausedForRecovery: false,
      },
    },
    treasury: {
      totalRealizedProfitUsd: '5250.88',
      retainedTradingUsd: '2625.44',
      bankSweepReservedUsd: '2625.44',
      confirmedSettledDisbursedUsd: '1000.00',
      pendingUnconfirmedTransfersUsd: '250.00',
      recentSweeps: [
        { tradeId: 's-1', symbol: 'NAS100', brokerId: 'LHFX_MT5', realizedNetUsd: '5250.88', occurredAt: '2026-11-20T15:00:00Z' },
      ],
    },
  };
  const surplusHtml = renderObsidianVaultProgressCard(surplusState);
  assert.match(surplusHtml, /50% Compounding \/ 50% Bank Vault/);
  assert.equal(surplusHtml.includes('100% Rebuilding Principal'), false);
  assert.match(surplusHtml, /\$304,250\.88/);
  assert.match(surplusHtml, /\$2,625\.44/);
  assert.match(surplusHtml, /meter-pct-100/);
  assert.equal(/\bstyle\s*=/i.test(surplusHtml), false);
});

test('THERMAL09 Obsidian 2D Canvases use #121316 background (never #faf9f5), plot equity + $300k goal + vault band, and actually plot real drawdown curves', () => {
  const surplusState = {
    ...sampleRichState(),
    treasury: { ...sampleRichState().treasury, bankSweepReservedUsd: '1500.00' },
  };

  // 1. Equity + Vault Canvas
  const eqCanvas = createRecordingCanvas(480, 220);
  const eqMeta = drawObsidianEquityVaultChart(eqCanvas, surplusState);
  assert.equal(eqMeta.background, OBSIDIAN_BG_HEX);
  assert.equal(eqMeta.pointCount, 4);

  const eqBgRect = eqCanvas.ops.find((o) => o.op === 'fillRect');
  assert.ok(eqBgRect);
  assert.equal(eqBgRect.fillStyle, '#121316');
  assert.equal(eqCanvas.ops.some((o) => o.fillStyle === '#faf9f5' || o.value === '#faf9f5'), false);

  // Verify $300,000.00 Principal Goal dashed gold line & emerald curve stroke > 1 point
  const eqTexts = eqCanvas.ops.filter((o) => o.op === 'fillText').map((o) => o.text);
  assert.ok(eqTexts.some((t) => t.includes('$300,000.00 Principal Goal')));
  assert.ok(eqTexts.some((t) => t.includes('Vault $1,500.00')));
  assert.ok(eqCanvas.ops.some((o) => o.op === 'stroke' && o.strokeStyle === '#10b981'));
  assert.ok(eqCanvas.ops.some((o) => o.op === 'stroke' && o.strokeStyle === '#eab308' && o.lineDash.length > 0));
  assert.ok(eqCanvas.ops.filter((o) => o.op === 'lineTo').length >= 6);

  // 2. Underwater Drawdown Canvas (multi-point history)
  const ddCanvas = createRecordingCanvas(480, 220);
  const ddMeta = drawObsidianDrawdownChart(ddCanvas, sampleRichState());
  assert.equal(ddMeta.background, '#121316');
  assert.equal(ddMeta.pointCount, 4);
  assert.ok(Number(ddMeta.maxDrawdownPct) < -2.0); // 301200 -> 294000 is -2.39%

  const ddBgRect = ddCanvas.ops.find((o) => o.op === 'fillRect');
  assert.equal(ddBgRect.fillStyle, '#121316');
  assert.equal(ddCanvas.ops.some((o) => o.fillStyle === '#faf9f5' || o.value === '#faf9f5'), false);
  assert.ok(ddCanvas.ops.some((o) => o.op === 'fill' && o.fillStyle === 'rgba(244,63,94,0.28)'));
  assert.ok(ddCanvas.ops.some((o) => o.op === 'stroke' && o.strokeStyle === '#fb7185'));
  const ddTexts = ddCanvas.ops.filter((o) => o.op === 'fillText').map((o) => o.text);
  assert.ok(ddTexts.some((t) => t.includes('-10.00% Max Drawdown Brake')));
  assert.ok(ddTexts.some((t) => t.includes('-2.50%')));
  assert.ok(ddCanvas.ops.filter((o) => o.op === 'lineTo').length >= 6);

  // 3. Drawdown Canvas single-snapshot fallback (no growthSeries -> STILL plots real drawdown, never blank!)
  const fallbackCanvas = createRecordingCanvas(440, 200);
  const fallbackMeta = drawObsidianDrawdownChart(fallbackCanvas, {
    aiTrader: { bankedSession: { initialCapitalUsd: '300000', currentTotalEquityUsd: '292500.00' } },
  });
  assert.equal(fallbackMeta.pointCount, 2);
  assert.equal(fallbackMeta.currentDrawdownPct, '-2.50');
  assert.ok(fallbackCanvas.ops.some((o) => o.op === 'stroke' && o.strokeStyle === '#fb7185'));
});

test('THERMAL10 exported OBSIDIAN_THERMAL_CSS_SNIPPET includes all strict-CSP heat, strip, vault, and meter-pct classes', () => {
  for (const selector of [
    '.top-status-strip',
    '.broker-win-chip',
    '.thermal-grid',
    '.heat-hot-buy',
    '.heat-warm-buy',
    '.heat-neutral',
    '.heat-cool-sell',
    '.heat-cold-sell',
    '.vault-progress-track',
    '.meter-pct-0',
    '.meter-pct-55',
    '.meter-pct-100',
  ]) {
    assert.ok(OBSIDIAN_THERMAL_CSS_SNIPPET.includes(selector), `Missing CSS selector ${selector}`);
  }
});
