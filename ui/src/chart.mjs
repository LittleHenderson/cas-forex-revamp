/** Read-only multi-currency candlestick chart & live tick visualizer for 01 Operate.
 * Strictly display-only: holds no credentials, sends no orders, and never fabricates quotes.
 * Zero inline style attributes to preserve strict CSP (style-src 'self').
 */
import { assertSchema, decimalCoefficient, freeze, parseUniqueJSON, SnapshotError } from './wire.mjs';
import { canonicalJSON } from './decision-read.mjs';

export const MAX_MARKET_STREAM_BYTES = 1048576;
export const CHART_TIMEFRAMES = Object.freeze(['1s', 'M1', 'M5', 'M15', 'H1']);
export const CHART_LAYOUTS = Object.freeze(['single', 'quad']);
export const ALL_CHART_PAIRS = Object.freeze([
  'EURUSD', 'GBPUSD', 'USDJPY', 'USDCHF', 'AUDUSD', 'USDCAD', 'NZDUSD',
  'EURGBP', 'EURJPY', 'GBPJPY', 'EURCHF', 'EURAUD', 'EURCAD', 'AUDJPY', 'CHFJPY', 'CADJPY',
]);

const fail = (message) => { throw new SnapshotError(message); };
const escapeText = (value) => String(value).replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));

export function assertMarketStreamSemantics(envelope) {
  const seen = new Set();
  for (const stream of envelope.streams) {
    if (seen.has(stream.pair)) fail(`Duplicate currency pair in market stream: ${stream.pair}`);
    seen.add(stream.pair);
    const bid = decimalCoefficient(stream.bid);
    const ask = decimalCoefficient(stream.ask);
    const mid = decimalCoefficient(stream.mid);
    const tick = decimalCoefficient(stream.tick_size);
    if (bid <= 0n || ask <= bid || tick <= 0n || mid < bid || mid > ask) {
      fail(`${stream.pair}: invalid bid/ask/mid/tick ordering.`);
    }
    decimalCoefficient(stream.spread_pips);
    decimalCoefficient(stream.change_24h_pct);
    if (stream.ecb_reference_mid !== null && decimalCoefficient(stream.ecb_reference_mid) <= 0n) {
      fail(`${stream.pair}: ECB reference midpoint must be positive.`);
    }
    if (stream.ecb_deviation_bps !== null && decimalCoefficient(stream.ecb_deviation_bps) < 0n) {
      fail(`${stream.pair}: ECB deviation bps cannot be negative.`);
    }
    for (const seriesKey of ['candles_m1', 'candles_m5', 'candles_h1']) {
      for (const bar of stream[seriesKey]) {
        const o = decimalCoefficient(bar.o);
        const h = decimalCoefficient(bar.h);
        const l = decimalCoefficient(bar.l);
        const c = decimalCoefficient(bar.c);
        const v = decimalCoefficient(bar.v);
        const lowBody = o < c ? o : c;
        const highBody = o > c ? o : c;
        if (l <= 0n || l > lowBody || h < highBody || v < 0n) {
          fail(`${stream.pair} ${seriesKey}: candle OHLCV envelope invalid.`);
        }
      }
    }
  }
}

export function decodeMarketStream(raw, schema) {
  if (schema?.$id !== 'urn:cas-forex:market-stream:1.0') {
    fail('The shared market-stream schema is unavailable or unsupported.');
  }
  const envelope = parseUniqueJSON(raw, MAX_MARKET_STREAM_BYTES);
  assertSchema(envelope, schema, schema);
  assertMarketStreamSemantics(envelope);
  return freeze(envelope);
}

export async function verifyMarketStreamDigest(envelope, hashBytes) {
  const { canonical_payload_sha256: expected, ...unsigned } = envelope;
  const bytes = new TextEncoder().encode(canonicalJSON(unsigned));
  const actual = await hashBytes(bytes);
  if (actual !== expected) fail('Market stream canonical SHA-256 mismatch.');
  return true;
}

export function normalizePairSymbol(instrumentId) {
  if (typeof instrumentId !== 'string') return '';
  const upper = instrumentId.toUpperCase().replace(/[^A-Z]/g, '');
  for (const pair of ALL_CHART_PAIRS) {
    if (upper === pair || upper.endsWith(pair)) return pair;
  }
  return upper;
}

export function matchPositionsForPair(projection, pair) {
  if (!projection?.positions?.length) return Object.freeze([]);
  const target = String(pair).toUpperCase();
  const matched = projection.positions
    .filter((pos) => normalizePairSymbol(pos.instrument_id) === target)
    .map((pos) => Object.freeze({
      position_id: pos.position_id,
      instrument_id: pos.instrument_id,
      side: pos.side,
      quantity: pos.quantity,
      entry_price: pos.entry_price,
      stop_price: pos.stop_price,
      version: pos.version,
    }));
  return Object.freeze(matched);
}

function rollupCandles(bars, groupSize) {
  const out = [];
  for (let idx = 0; idx < bars.length; idx += groupSize) {
    const slice = bars.slice(idx, idx + groupSize);
    if (!slice.length) continue;
    let high = Number(slice[0].h);
    let low = Number(slice[0].l);
    let highStr = slice[0].h;
    let lowStr = slice[0].l;
    let vol = 0;
    let trades = 0;
    for (const item of slice) {
      const hNum = Number(item.h);
      const lNum = Number(item.l);
      if (hNum > high) { high = hNum; highStr = item.h; }
      if (lNum < low) { low = lNum; lowStr = item.l; }
      vol += Number(item.v);
      trades += item.n;
    }
    out.push(Object.freeze({
      t: slice[0].t,
      o: slice[0].o,
      h: highStr,
      l: lowStr,
      c: slice[slice.length - 1].c,
      v: vol.toFixed(2),
      n: trades,
    }));
  }
  return Object.freeze(out);
}

export function deriveTimeframeCandles(pairStream, timeframe = 'M5', microBars = []) {
  if (!pairStream) return Object.freeze([]);
  if (timeframe === '1s') {
    if (Array.isArray(microBars) && microBars.length >= 2) return Object.freeze(microBars.slice(-48));
    return Object.freeze(pairStream.candles_m1.slice(-24));
  }
  if (timeframe === 'M1') return Object.freeze(pairStream.candles_m1.slice());
  if (timeframe === 'M15') return rollupCandles(pairStream.candles_m5, 3);
  if (timeframe === 'H1') return Object.freeze(pairStream.candles_h1.slice());
  return Object.freeze(pairStream.candles_m5.slice());
}

export function computeEMA(candles, period = 14) {
  if (!Array.isArray(candles) || candles.length === 0) return Object.freeze([]);
  const k = 2 / (period + 1);
  const values = [];
  let prev = Number(candles[0].c);
  for (let i = 0; i < candles.length; i += 1) {
    const close = Number(candles[i].c);
    prev = i === 0 ? close : close * k + prev * (1 - k);
    values.push(prev);
  }
  return Object.freeze(values);
}

export function computeChartGeometry(pairStream, {
  timeframe = 'M5',
  projection = null,
  valveStatus = null,
  microBars = [],
  width = 860,
  height = 360,
} = {}) {
  const candles = deriveTimeframeCandles(pairStream, timeframe, microBars);
  const padLeft = 14;
  const padRight = 84;
  const padTop = 18;
  const padBottom = 64;
  const plotW = Math.max(120, width - padLeft - padRight);
  const plotH = Math.max(100, height - padTop - padBottom);
  const volTop = padTop + plotH + 10;
  const volH = Math.max(24, padBottom - 26);

  const positions = matchPositionsForPair(projection, pairStream.pair);
  let lowMin = Infinity;
  let highMax = -Infinity;
  let maxVol = 0;

  for (const bar of candles) {
    const l = Number(bar.l);
    const h = Number(bar.h);
    const v = Number(bar.v);
    if (l < lowMin) lowMin = l;
    if (h > highMax) highMax = h;
    if (v > maxVol) maxVol = v;
  }
  const bidNum = Number(pairStream.bid);
  const askNum = Number(pairStream.ask);
  if (bidNum < lowMin) lowMin = bidNum;
  if (askNum > highMax) highMax = askNum;

  for (const pos of positions) {
    const entry = Number(pos.entry_price);
    if (Number.isFinite(entry)) {
      if (entry < lowMin) lowMin = entry;
      if (entry > highMax) highMax = entry;
    }
    if (pos.stop_price !== null) {
      const stop = Number(pos.stop_price);
      if (Number.isFinite(stop)) {
        if (stop < lowMin) lowMin = stop;
        if (stop > highMax) highMax = stop;
      }
    }
  }

  const rawSpan = highMax - lowMin;
  const minSpan = Number(pairStream.tick_size) * 20;
  const span = Math.max(rawSpan, minSpan, 1e-6);
  const margin = span * 0.08;
  const yMin = lowMin - margin;
  const yMax = highMax + margin;

  const priceToY = (price) => padTop + ((yMax - price) / (yMax - yMin)) * plotH;
  const stepX = plotW / Math.max(candles.length, 1);
  const bodyW = Math.max(3, Math.min(18, stepX * 0.64));

  const candleShapes = candles.map((bar, idx) => {
    const o = Number(bar.o);
    const h = Number(bar.h);
    const l = Number(bar.l);
    const c = Number(bar.c);
    const v = Number(bar.v);
    const cx = padLeft + stepX * (idx + 0.5);
    const yOpen = priceToY(o);
    const yClose = priceToY(c);
    const yHigh = priceToY(h);
    const yLow = priceToY(l);
    const top = Math.min(yOpen, yClose);
    const bodyHeight = Math.max(1.5, Math.abs(yClose - yOpen));
    const vRatio = maxVol > 0 ? v / maxVol : 0;
    const vBarH = Math.max(1, vRatio * volH);
    return Object.freeze({
      index: idx,
      time: bar.t,
      bullish: c >= o,
      cx,
      x: cx - bodyW / 2,
      width: bodyW,
      wickTopY: yHigh,
      wickBottomY: yLow,
      bodyTopY: top,
      bodyHeight,
      volTopY: volTop + (volH - vBarH),
      volHeight: vBarH,
      raw: bar,
    });
  });

  const emaValues = computeEMA(candles, 14);
  const emaPoints = emaValues.map((val, idx) => Object.freeze({
    x: padLeft + stepX * (idx + 0.5),
    y: priceToY(val),
    value: val,
  }));

  const positionLines = [];
  for (const pos of positions) {
    const entryNum = Number(pos.entry_price);
    positionLines.push(Object.freeze({
      kind: 'ENTRY',
      position_id: pos.position_id,
      side: pos.side,
      quantity: pos.quantity,
      price: pos.entry_price,
      y: priceToY(entryNum),
      label: `${pos.side} ${pos.quantity} @ ${pos.entry_price}`,
    }));
    if (pos.stop_price !== null) {
      const stopNum = Number(pos.stop_price);
      positionLines.push(Object.freeze({
        kind: 'STOP',
        position_id: pos.position_id,
        side: pos.side,
        quantity: pos.quantity,
        price: pos.stop_price,
        y: priceToY(stopNum),
        label: `STOP @ ${pos.stop_price}`,
      }));
    }
  }

  const effectiveValve = valveStatus ?? {
    gate_active: false,
    status: 'UNCONFIGURED',
    threshold: null,
    last_score: null,
    last_reason: null,
  };

  return Object.freeze({
    pair: pairStream.pair,
    displayPair: pairStream.display_pair,
    timeframe,
    width,
    height,
    plot: Object.freeze({ left: padLeft, top: padTop, width: plotW, height: plotH, volTop, volHeight: volH }),
    yMin,
    yMax,
    bidPrice: pairStream.bid,
    askPrice: pairStream.ask,
    bidY: priceToY(bidNum),
    askY: priceToY(askNum),
    candles: Object.freeze(candleShapes),
    emaPoints: Object.freeze(emaPoints),
    positionLines: Object.freeze(positionLines),
    valveBadge: Object.freeze({
      gate_active: Boolean(effectiveValve.gate_active),
      status: effectiveValve.status,
      threshold: effectiveValve.threshold,
      last_score: effectiveValve.last_score,
      last_reason: effectiveValve.last_reason,
    }),
  });
}

function formatValveSummary(valve) {
  if (!valve || !valve.gate_active) return { label: 'Valve gate · unconfigured', warning: true };
  const status = valve.status ?? 'STANDBY';
  const scorePart = valve.last_score !== null && valve.last_score !== undefined ? ` · p=${valve.last_score}` : '';
  const threshPart = valve.threshold ? ` (tau=${valve.threshold})` : '';
  return {
    label: `ForexMetaValveGate · ${status}${scorePart}${threshPart}`,
    warning: status === 'REFUSE' || status === 'UNCONFIGURED',
  };
}

export function renderMarketChartSection(projection, state) {
  const e = escapeText;
  const stream = state.marketStream ?? null;
  const selectedPair = ALL_CHART_PAIRS.includes(state.chartPair) ? state.chartPair : 'EURUSD';
  const timeframe = CHART_TIMEFRAMES.includes(state.chartTimeframe) ? state.chartTimeframe : 'M5';
  const layout = CHART_LAYOUTS.includes(state.chartLayout) ? state.chartLayout : 'single';
  const categoryFilter = ['all', 'MAJOR', 'CROSS'].includes(state.chartCategory) ? state.chartCategory : 'all';

  const valveInfo = formatValveSummary(stream?.valve_status ?? null);
  const streamBadge = stream
    ? (state.liveStreamConnected ? 'Live streaming feed' : (stream.source_mode === 'LIVE_EXTERNAL_PUBLIC_FEED' ? 'Verified market snapshot' : stream.source_mode))
    : 'No market stream';

  const connectBtn = !state.liveStreamConnected
    ? `<button type="button" class="button button-small" data-connect-loopback="true">Connect live broker stream</button>`
    : `<button type="button" class="button button-small button-secondary" data-disconnect-loopback="true">Pause live stream</button>`;

  if (!stream) {
    return `<section class="panel market-chart-panel" aria-label="Multi-currency market chart">
      <div class="section-heading">
        <div><p class="eyebrow">MULTI-CURRENCY FEED / 16 PAIRS</p><h2>Live candlestick chart</h2></div>
        <div class="market-chart-badges">
          <span class="tag tag-warning"><span class="state-rule" aria-hidden="true"></span>${e(valveInfo.label)}</span>
          <span class="tag tag-warning"><span class="state-rule" aria-hidden="true"></span>${e(streamBadge)}</span>
          ${connectBtn}
        </div>
      </div>
      <div class="empty-state"><span class="empty-icon" aria-hidden="true">candles</span><h3>Market stream not loaded</h3><p>Connect the loopback live broker stream or load a verified market-stream envelope to inspect real-time multi-currency candlesticks, entry/stop lines, and ForexMetaValveGate telemetry.</p></div>
    </section>`;
  }

  const visibleStreams = categoryFilter === 'all'
    ? stream.streams
    : stream.streams.filter((item) => item.category === categoryFilter);
  const activeStream = stream.streams.find((item) => item.pair === selectedPair) ?? stream.streams[0];
  const latestCandle = deriveTimeframeCandles(activeStream, timeframe, state.chartMicroBars?.[activeStream.pair]).at(-1);
  const matchedPositions = matchPositionsForPair(projection, activeStream.pair);

  const quadPairs = [activeStream.pair, 'EURUSD', 'GBPUSD', 'USDJPY', 'GBPJPY', 'AUDUSD']
    .filter((pair, idx, arr) => arr.indexOf(pair) === idx && stream.streams.some((s) => s.pair === pair))
    .slice(0, 4);

  const tfButtons = CHART_TIMEFRAMES.map((tf) => (
    `<button type="button" class="button button-small ${tf === timeframe ? 'selected' : 'button-secondary'}" data-chart-tf="${e(tf)}" aria-pressed="${tf === timeframe}">${e(tf)}</button>`
  )).join('');

  const layoutButtons = [
    ['single', 'Single chart'],
    ['quad', '4x Quad matrix'],
  ].map(([mode, label]) => (
    `<button type="button" class="button button-small ${mode === layout ? 'selected' : 'button-secondary'}" data-chart-layout="${e(mode)}" aria-pressed="${mode === layout}">${e(label)}</button>`
  )).join('');

  const catButtons = [
    ['all', `All / ${stream.streams.length}`],
    ['MAJOR', `Majors / ${stream.streams.filter((s) => s.category === 'MAJOR').length}`],
    ['CROSS', `Crosses / ${stream.streams.filter((s) => s.category === 'CROSS').length}`],
  ].map(([cat, label]) => (
    `<button type="button" class="button button-small ${cat === categoryFilter ? 'selected' : 'button-secondary'}" data-chart-cat="${e(cat)}" aria-pressed="${cat === categoryFilter}">${e(label)}</button>`
  )).join('');

  const watchlistItems = visibleStreams.map((item) => {
    const hasPos = matchPositionsForPair(projection, item.pair).length > 0;
    const neg = item.change_24h_pct.startsWith('-');
    const selected = item.pair === activeStream.pair;
    return `<button type="button" class="watchlist-row${selected ? ' is-selected' : ''}" data-chart-pair="${e(item.pair)}" aria-pressed="${selected}">
      <span class="watchlist-pair">
        <strong>${e(item.display_pair)}</strong>
        <small>${e(item.category)}${hasPos ? ' · OPEN POS' : ''}</small>
      </span>
      <span class="watchlist-quotes numeric">
        <span>${e(item.bid)} / ${e(item.ask)}</span>
        <small class="${neg ? 'delta-neg' : 'delta-pos'}">${neg ? '' : '+'}${e(item.change_24h_pct)}% · ${e(item.spread_pips)}p</small>
      </span>
    </button>`;
  }).join('');

  const canvasesHtml = layout === 'quad'
    ? `<div class="market-quad-grid">${quadPairs.map((qPair) => {
        const qs = stream.streams.find((s) => s.pair === qPair);
        return `<div class="market-canvas-card">
          <div class="market-canvas-header">
            <strong>${e(qs.display_pair)} · ${e(timeframe)}</strong>
            <span class="numeric">${e(qs.bid)} / ${e(qs.ask)} (${e(qs.spread_pips)}p)</span>
          </div>
          <canvas class="market-chart-canvas market-chart-canvas-quad" data-market-canvas="${e(qs.pair)}" width="460" height="220" aria-label="${e(qs.display_pair)} ${e(timeframe)} candlestick chart"></canvas>
        </div>`;
      }).join('')}</div>`
    : `<div class="market-canvas-card">
        <div class="market-canvas-header">
          <div>
            <strong>${e(activeStream.display_pair)} · ${e(timeframe)}</strong>
            <span class="quiet-inline">${e(activeStream.feed_mode.replaceAll('_', ' '))}</span>
          </div>
          <div class="numeric market-live-quote">
            <span>Bid <strong>${e(activeStream.bid)}</strong></span>
            <span>Ask <strong>${e(activeStream.ask)}</strong></span>
            <span>Spread <strong>${e(activeStream.spread_pips)} pips</strong></span>
          </div>
        </div>
        <canvas class="market-chart-canvas" data-market-canvas="${e(activeStream.pair)}" width="860" height="360" aria-label="${e(activeStream.display_pair)} ${e(timeframe)} candlestick chart"></canvas>
        <div class="market-crosshair-readout" data-chart-readout="${e(activeStream.pair)}">
          ${latestCandle ? `Bar ${e(latestCandle.t)} · O ${e(latestCandle.o)} · H ${e(latestCandle.h)} · L ${e(latestCandle.l)} · C ${e(latestCandle.c)} · Vol ${e(latestCandle.v)} (${e(latestCandle.n)} trades)` : 'No candle bar'}
        </div>
      </div>`;

  const positionSummaryText = matchedPositions.length
    ? matchedPositions.map((p) => `${p.side} ${p.quantity} @ ${p.entry_price} (Stop ${p.stop_price ?? 'none'})`).join(' · ')
    : 'No open position on selected pair';

  return `<section class="panel market-chart-panel" aria-label="Multi-currency market chart">
    <div class="section-heading">
      <div>
        <p class="eyebrow">VERIFIED BROKER FEED · ${e(stream.streams.length)} CURRENCY PAIRS · SEQ #${e(stream.sequence)}</p>
        <h2>Live multi-currency candlestick chart</h2>
      </div>
      <div class="market-chart-badges">
        <span class="tag${valveInfo.warning ? ' tag-warning' : ''}" data-valve-status="${e(stream.valve_status?.status ?? 'UNCONFIGURED')}"><span class="state-rule" aria-hidden="true"></span>${e(valveInfo.label)}</span>
        <span class="tag${state.liveStreamConnected ? '' : ' tag-warning'}"><span class="state-rule" aria-hidden="true"></span>${e(streamBadge)}</span>
        ${connectBtn}
      </div>
    </div>
    <div class="market-chart-toolbar" role="toolbar" aria-label="Chart controls">
      <div class="segmented" role="group" aria-label="Pair category">${catButtons}</div>
      <div class="segmented" role="group" aria-label="Candle timeframe">${tfButtons}</div>
      <div class="segmented" role="group" aria-label="Chart layout">${layoutButtons}</div>
    </div>
    <div class="market-workspace-grid">
      <aside class="market-watchlist" aria-label="Currency pair watchlist">${watchlistItems}</aside>
      <div class="market-stage">
        ${canvasesHtml}
        <dl class="metadata compact market-telemetry-strip">
          <div class="meta-row"><dt>Active pair / Position overlay</dt><dd>${e(activeStream.display_pair)} · ${e(positionSummaryText)}</dd></div>
          <div class="meta-row"><dt>ECB G10 reference (${e(stream.ecb_reference_date ?? 'N/A')})</dt><dd>${activeStream.ecb_reference_mid ? `${e(activeStream.ecb_reference_mid)} (${e(activeStream.ecb_deviation_bps)} bps diff)` : 'Unavailable'}</dd></div>
          <div class="meta-row"><dt>ForexMetaValveGate detail</dt><dd>${e(stream.valve_status?.last_reason ?? 'No active gate decision recorded in this frame.')}</dd></div>
          <div class="meta-row"><dt>Canonical stream SHA-256</dt><dd><code>${e(stream.canonical_payload_sha256.slice(0, 24))}…</code> (wire <code>${e(stream.raw_wire_sha256.slice(0, 16))}…</code>)</dd></div>
        </dl>
      </div>
    </div>
    <p class="quiet-note">Display-only market telemetry. Chart overlays reflect observed cockpit positions and ForexMetaValveGate status without granting execution permission.</p>
  </section>`;
}

function resolvePalette() {
  const dark = document.documentElement.dataset.theme === 'dark'
    || (document.documentElement.dataset.theme !== 'light' && globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches);
  return dark
    ? {
        bg: '#101418',
        grid: 'rgba(255, 255, 255, 0.07)',
        border: 'rgba(255, 255, 255, 0.16)',
        text: '#d7dde4',
        muted: '#8b96a3',
        bull: '#19b37a',
        bear: '#e05252',
        volBull: 'rgba(25, 179, 122, 0.25)',
        volBear: 'rgba(224, 82, 82, 0.25)',
        ema: '#63a4ff',
        bid: '#19b37a',
        ask: '#f09436',
        entry: '#38bdf8',
        stop: '#f43f5e',
        crosshair: 'rgba(215, 221, 228, 0.45)',
      }
    : {
        bg: '#faf9f5',
        grid: 'rgba(20, 24, 28, 0.07)',
        border: 'rgba(20, 24, 28, 0.18)',
        text: '#16191d',
        muted: '#5a626a',
        bull: '#0d7a52',
        bear: '#b83232',
        volBull: 'rgba(13, 122, 82, 0.20)',
        volBear: 'rgba(184, 50, 50, 0.20)',
        ema: '#1d5bbf',
        bid: '#0d7a52',
        ask: '#b85c00',
        entry: '#0369a1',
        stop: '#be123c',
        crosshair: 'rgba(22, 25, 29, 0.40)',
      };
}

function drawSingleCanvas(canvas, pairStream, state, hoverX = null) {
  const ctx = canvas.getContext?.('2d');
  if (!ctx) return;
  const dpr = Math.min(2, Math.max(1, globalThis.devicePixelRatio || 1));
  const cssW = Number(canvas.getAttribute('width')) || 860;
  const cssH = Number(canvas.getAttribute('height')) || 360;
  if (canvas.width !== Math.round(cssW * dpr) || canvas.height !== Math.round(cssH * dpr)) {
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
  }
  ctx.save();
  ctx.scale(dpr, dpr);

  const pal = resolvePalette();
  const timeframe = CHART_TIMEFRAMES.includes(state.chartTimeframe) ? state.chartTimeframe : 'M5';
  const geom = computeChartGeometry(pairStream, {
    timeframe,
    projection: state.projection,
    valveStatus: state.marketStream?.valve_status ?? null,
    microBars: state.chartMicroBars?.[pairStream.pair] ?? [],
    width: cssW,
    height: cssH,
  });

  ctx.fillStyle = pal.bg;
  ctx.fillRect(0, 0, cssW, cssH);

  const { left, top, width: plotW, height: plotH, volTop, volHeight } = geom.plot;
  const decimals = pairStream.tick_size.includes('.') ? Math.min(5, pairStream.tick_size.split('.')[1].length) : 2;

  // Horizontal price grid + right-axis labels
  ctx.strokeStyle = pal.grid;
  ctx.fillStyle = pal.muted;
  ctx.font = '11px ui-monospace, SFMono-Regular, Consolas, monospace';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = top + (plotH * i) / 4;
    const price = geom.yMax - ((geom.yMax - geom.yMin) * i) / 4;
    ctx.beginPath();
    ctx.moveTo(left, y);
    ctx.lineTo(left + plotW, y);
    ctx.stroke();
    ctx.fillText(price.toFixed(decimals), left + plotW + 6, y + 4);
  }

  // Separator above volume pane
  ctx.strokeStyle = pal.border;
  ctx.beginPath();
  ctx.moveTo(left, volTop - 4);
  ctx.lineTo(left + plotW, volTop - 4);
  ctx.stroke();

  // Volume histogram + Candlesticks
  for (const c of geom.candles) {
    ctx.fillStyle = c.bullish ? pal.volBull : pal.volBear;
    ctx.fillRect(c.x, c.volTopY, c.width, c.volHeight);

    ctx.strokeStyle = c.bullish ? pal.bull : pal.bear;
    ctx.fillStyle = c.bullish ? pal.bull : pal.bear;
    ctx.lineWidth = 1.25;
    ctx.beginPath();
    ctx.moveTo(c.cx, c.wickTopY);
    ctx.lineTo(c.cx, c.wickBottomY);
    ctx.stroke();
    ctx.fillRect(c.x, c.bodyTopY, c.width, c.bodyHeight);
  }

  // 14-period EMA overlay
  if (geom.emaPoints.length > 1) {
    ctx.strokeStyle = pal.ema;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    geom.emaPoints.forEach((pt, idx) => {
      if (idx === 0) ctx.moveTo(pt.x, pt.y);
      else ctx.lineTo(pt.x, pt.y);
    });
    ctx.stroke();
  }

  // Live Bid & Ask horizontal rays
  ctx.save();
  ctx.setLineDash([4, 4]);
  ctx.strokeStyle = pal.bid;
  ctx.beginPath();
  ctx.moveTo(left, geom.bidY);
  ctx.lineTo(left + plotW, geom.bidY);
  ctx.stroke();

  ctx.strokeStyle = pal.ask;
  ctx.beginPath();
  ctx.moveTo(left, geom.askY);
  ctx.lineTo(left + plotW, geom.askY);
  ctx.stroke();
  ctx.restore();

  // CAS Position Entry & Protective Stop lines
  for (const line of geom.positionLines) {
    ctx.save();
    ctx.strokeStyle = line.kind === 'ENTRY' ? pal.entry : pal.stop;
    ctx.lineWidth = 1.8;
    if (line.kind === 'STOP') ctx.setLineDash([6, 3]);
    ctx.beginPath();
    ctx.moveTo(left, line.y);
    ctx.lineTo(left + plotW, line.y);
    ctx.stroke();
    ctx.fillStyle = line.kind === 'ENTRY' ? pal.entry : pal.stop;
    ctx.fillText(line.label, left + 6, Math.max(top + 12, line.y - 4));
    ctx.restore();
  }

  // Crosshair hover inspection
  if (hoverX !== null && hoverX >= left && hoverX <= left + plotW && geom.candles.length) {
    let nearest = geom.candles[0];
    let bestDist = Math.abs(hoverX - nearest.cx);
    for (const c of geom.candles) {
      const dist = Math.abs(hoverX - c.cx);
      if (dist < bestDist) { nearest = c; bestDist = dist; }
    }
    ctx.save();
    ctx.setLineDash([3, 3]);
    ctx.strokeStyle = pal.crosshair;
    ctx.beginPath();
    ctx.moveTo(nearest.cx, top);
    ctx.lineTo(nearest.cx, volTop + volHeight);
    ctx.stroke();
    ctx.restore();
    const readout = canvas.parentElement?.querySelector(`[data-chart-readout="${pairStream.pair}"]`);
    if (readout) {
      const b = nearest.raw;
      readout.textContent = `Bar ${b.t} · O ${b.o} · H ${b.h} · L ${b.l} · C ${b.c} · Vol ${b.v} (${b.n} trades)`;
    }
  }

  ctx.restore();
}

export function mountMarketCharts(root, state) {
  const stream = state?.marketStream;
  if (!root || !stream) return;
  const canvases = root.querySelectorAll('canvas[data-market-canvas]');
  for (const canvas of canvases) {
    const pair = canvas.dataset.marketCanvas;
    const pairStream = stream.streams.find((s) => s.pair === pair);
    if (!pairStream) continue;
    drawSingleCanvas(canvas, pairStream, state, null);
    if (!canvas.dataset.boundHover) {
      canvas.dataset.boundHover = 'true';
      canvas.addEventListener('pointermove', (ev) => {
        const rect = canvas.getBoundingClientRect();
        const scaleX = (Number(canvas.getAttribute('width')) || rect.width) / Math.max(1, rect.width);
        drawSingleCanvas(canvas, pairStream, state, (ev.clientX - rect.left) * scaleX);
      });
      canvas.addEventListener('pointerleave', () => {
        drawSingleCanvas(canvas, pairStream, state, null);
      });
    }
  }
}
