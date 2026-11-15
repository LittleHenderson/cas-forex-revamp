// Phase 6 regression suite for ui/src/chart.mjs and 01 Operate multi-currency candlestick rendering.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import {
  ALL_CHART_PAIRS,
  computeChartGeometry,
  computeEMA,
  decodeMarketStream,
  deriveTimeframeCandles,
  matchPositionsForPair,
  renderMarketChartSection,
  verifyMarketStreamDigest,
} from '../../ui/src/chart.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { ScopedBridge } from '../../ui/src/bridge.mjs';
import { canonicalJSON } from '../../ui/src/decision-read.mjs';
import { fixture, samplePosition, displayState, schema, time } from './helpers.mjs';

const marketSchemaRaw = await readFile(new URL('../../docs/contracts/market-stream.schema.json', import.meta.url), 'utf8');
const marketSchema = JSON.parse(marketSchemaRaw);
const marketFixtureRaw = await readFile(new URL('../../docs/contracts/initial-market-stream.json', import.meta.url), 'utf8');
const shaHex = async (bytes) => createHash('sha256').update(bytes).digest('hex');

test('CHART01 initial 16-pair market stream decodes and matches canonical SHA-256', async () => {
  const decoded = decodeMarketStream(marketFixtureRaw, marketSchema);
  assert.equal(decoded.streams.length, 16);
  assert.deepEqual(decoded.streams.map((s) => s.pair), [...ALL_CHART_PAIRS]);
  assert.equal(await verifyMarketStreamDigest(decoded, shaHex), true);
  assert.ok(Object.isFrozen(decoded));
});

test('CHART02 inverted bid/ask, broken OHLC envelope, duplicate keys, and unsafe integers fail closed', () => {
  const valid = JSON.parse(marketFixtureRaw);
  const badSpread = structuredClone(valid);
  badSpread.streams[0].bid = badSpread.streams[0].ask;
  assert.throws(() => decodeMarketStream(JSON.stringify(badSpread), marketSchema), /bid\/ask/);

  const badBar = structuredClone(valid);
  badBar.streams[0].candles_m5[0].l = '999.99999';
  assert.throws(() => decodeMarketStream(JSON.stringify(badBar), marketSchema), /OHLCV envelope/);

  assert.throws(() => decodeMarketStream('{"a":1,"a":2}', marketSchema), /Duplicate JSON key/);
  const unsafeSeq = structuredClone(valid);
  unsafeSeq.sequence = 9007199254740993;
  assert.throws(() => decodeMarketStream(JSON.stringify(unsafeSeq), marketSchema), /safe integers/);
});

test('CHART03 timeframe derivation supports 1s, M1, M5, M15 3-bar rollup, and H1', () => {
  const decoded = decodeMarketStream(marketFixtureRaw, marketSchema);
  const eurusd = decoded.streams.find((s) => s.pair === 'EURUSD');
  assert.equal(deriveTimeframeCandles(eurusd, 'M1').length, eurusd.candles_m1.length);
  assert.equal(deriveTimeframeCandles(eurusd, 'M5').length, eurusd.candles_m5.length);
  assert.equal(deriveTimeframeCandles(eurusd, 'M15').length, Math.ceil(eurusd.candles_m5.length / 3));
  assert.equal(deriveTimeframeCandles(eurusd, 'H1').length, eurusd.candles_h1.length);
  const micro = [
    { t: '2026-11-15T10:00:00Z', o: '1.10000', h: '1.10020', l: '1.09990', c: '1.10010', v: '1.00', n: 1 },
    { t: '2026-11-15T10:00:01Z', o: '1.10010', h: '1.10030', l: '1.10005', c: '1.10025', v: '1.00', n: 1 },
  ];
  assert.equal(deriveTimeframeCandles(eurusd, '1s', micro).length, 2);
});

test('CHART04 EMA-14 and chart geometry map candles, Bid/Ask rays, Entry/Stop lines, and ForexMetaValveGate', () => {
  const decoded = decodeMarketStream(marketFixtureRaw, marketSchema);
  const gbpusd = decoded.streams.find((s) => s.pair === 'GBPUSD');
  const ema = computeEMA(gbpusd.candles_m5, 14);
  assert.equal(ema.length, gbpusd.candles_m5.length);
  assert.ok(ema.every((v) => Number.isFinite(v) && v > 0));

  const p = fixture();
  const pos = samplePosition();
  pos.instrument_id = 'synthetic-gbpusd';
  pos.entry_price = gbpusd.bid;
  pos.stop_price = (Number(gbpusd.bid) - 0.0040).toFixed(5);
  p.positions = [pos];

  const geom = computeChartGeometry(gbpusd, {
    timeframe: 'M5',
    projection: p,
    valveStatus: { gate_active: true, status: 'ALLOW', threshold: '0.55', last_score: '0.91', last_reason: 'Clean packet' },
    width: 860,
    height: 360,
  });
  assert.equal(geom.candles.length, gbpusd.candles_m5.length);
  assert.ok(geom.askY < geom.bidY);
  assert.equal(geom.positionLines.length, 2);
  assert.equal(geom.positionLines[0].kind, 'ENTRY');
  assert.equal(geom.positionLines[1].kind, 'STOP');
  assert.equal(geom.valveBadge.status, 'ALLOW');
});

test('CHART05 matchPositionsForPair normalizes synthetic, underscore, and canonical FX symbols', () => {
  const p = fixture();
  const pos1 = samplePosition();
  pos1.position_id = 'pos-jpy';
  pos1.instrument_id = 'USD_JPY';
  const pos2 = samplePosition();
  pos2.position_id = 'pos-eur';
  pos2.instrument_id = 'synthetic-eurusd';
  p.positions = [pos1, pos2];
  assert.equal(matchPositionsForPair(p, 'USDJPY').length, 1);
  assert.equal(matchPositionsForPair(p, 'EURUSD').length, 1);
  assert.equal(matchPositionsForPair(p, 'NZDUSD').length, 0);
});

test('CHART06 Operate renders honest empty chart state when marketStream is null with zero inline styles', () => {
  const state = displayState(fixture(), 'operate');
  const html = renderApp(state, Date.parse(time));
  assert.match(html, /Market stream not loaded/);
  assert.equal(/\bstyle\s*=/.test(html), false);
  assert.equal(/data-record=/.test(renderMarketChartSection(state.projection, state)), false);
});

test('CHART07 Operate renders all 16 major and cross pairs, canvas, Entry/Stop overlay, and Valve status', () => {
  const decoded = decodeMarketStream(marketFixtureRaw, marketSchema);
  const p = fixture();
  const pos = samplePosition();
  pos.instrument_id = 'EURUSD';
  pos.entry_price = decoded.streams[0].bid;
  pos.stop_price = (Number(decoded.streams[0].bid) - 0.0050).toFixed(5);
  p.positions = [pos];

  const state = displayState(p, 'operate');
  state.marketStream = decoded;
  state.chartPair = 'EURUSD';
  state.chartTimeframe = 'M5';
  const html = renderApp(state, Date.parse(time));

  for (const label of ['EUR/USD', 'GBP/USD', 'USD/JPY', 'USD/CHF', 'AUD/USD', 'USD/CAD', 'NZD/USD', 'EUR/GBP', 'EUR/JPY', 'GBP/JPY']) {
    assert.ok(html.includes(label), `Missing pair ${label}`);
  }
  assert.match(html, /data-market-canvas="EURUSD"/);
  assert.match(html, /ForexMetaValveGate · STANDBY/);
  assert.match(html, /OPEN POS/);
  assert.equal(/\bstyle\s*=/.test(html), false);
});

test('CHART08 Quad 4x matrix layout renders four distinct currency canvases without mutating source state', () => {
  const decoded = decodeMarketStream(marketFixtureRaw, marketSchema);
  const state = displayState(fixture(), 'operate');
  state.marketStream = decoded;
  state.chartPair = 'NZDUSD';
  state.chartLayout = 'quad';
  const before = JSON.stringify(state.projection);
  const html = renderApp(state, Date.parse(time));
  const canvases = [...html.matchAll(/data-market-canvas="([A-Z]{6})"/g)].map((m) => m[1]);
  assert.equal(canvases.length, 4);
  assert.equal(canvases[0], 'NZDUSD');
  assert.equal(JSON.stringify(state.projection), before);
});

test('CHART09 Valve REFUSE state surfaces warning badge and exact refusal reason in Operate', () => {
  const rawObj = JSON.parse(marketFixtureRaw);
  rawObj.valve_status = {
    gate_active: true,
    status: 'REFUSE',
    weights_sha256: 'a'.repeat(64),
    parameter_count: 161,
    threshold: '0.55',
    last_score: '0.02',
    last_reason: 'Blocked inverted stop hazard candidate',
  };
  const { canonical_payload_sha256: _old, ...unsigned } = rawObj;
  rawObj.canonical_payload_sha256 = createHash('sha256').update(canonicalJSON(unsigned)).digest('hex');
  const decoded = decodeMarketStream(JSON.stringify(rawObj), marketSchema);

  const state = displayState(fixture(), 'operate');
  state.marketStream = decoded;
  const html = renderApp(state, Date.parse(time));
  assert.match(html, /data-valve-status="REFUSE"/);
  assert.match(html, /Blocked inverted stop hazard candidate/);
});

test('CHART10 ScopedBridge optional readMarketStream verifies SHA-256 and rejects tampered stream', async () => {
  const projection = fixture();
  const readBytes = await readFile(new URL('../../docs/contracts/decision-read.schema.json', import.meta.url));
  const boot = {
    schema_version: 'forex.ui-transport/1',
    scope: structuredClone(projection.scope),
    request_time: time,
    fence_generation: 1,
    capabilities: { pause: true, stop: true, resume_new_risk: true, resume_management: true, reviewed_close: true },
    decision_schema_sha256: createHash('sha256').update(readBytes).digest('hex'),
    fence_receipt: {
      key: { account_id: projection.scope.account_id, run_id: projection.scope.run_id, environment: projection.scope.environment },
      barrier_id: 'b-1',
      generation: 1,
      new_risk_allowed: true,
      management_allowed: true,
      venue_sequence: 1,
      observed_at: time,
      applied: true,
      reason_code: null,
    },
  };
  let payload = JSON.parse(marketFixtureRaw);
  const bridge = {
    async readBoot() { return structuredClone(boot); },
    async readCockpit() { return structuredClone(projection); },
    async readDecisionRead() { throw new Error('unused'); },
    async prepareControl() { throw new Error('unused'); },
    async requestControl() { throw new Error('unused'); },
    async readControl() { throw new Error('unused'); },
    async prepareClose() { throw new Error('unused'); },
    async requestReviewedClose() { throw new Error('unused'); },
    async readCommand() { throw new Error('unused'); },
    async readMarketStream() { return structuredClone(payload); },
  };
  const consumer = new ScopedBridge({ cockpitSchema: schema });
  await consumer.attach(bridge);
  const okStream = await consumer.readMarketStream(marketSchema);
  assert.equal(okStream.streams.length, 16);

  payload = structuredClone(payload);
  payload.streams[0].mid = payload.streams[0].ask;
  await assert.rejects(consumer.readMarketStream(marketSchema), /SHA-256 mismatch/);
});
