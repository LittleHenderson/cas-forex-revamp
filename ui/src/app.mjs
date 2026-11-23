import { createExplainer } from './explainer.mjs';
import { decodeCockpit, parseUniqueJSON, MAX_SNAPSHOT_BYTES } from './wire.mjs';
import { resetInspection, reviewRecords, inspectRecord } from './model.mjs';
import { displayFreshness } from './freshness.mjs';
import { renderApp, renderControlDialog, renderCloseDialog, renderPreparedClose, replaceSafeHTML, resolveCockpitCompounding, resolveCockpitDemoHighGrowth, resolveCockpitOptionBDemo } from './render.mjs';
import { decodeDecisionRead, envelopeRecords, MAX_REVIEW_BYTES } from './decision-read.mjs';
import { ScopedBridge, createAuthenticatedLoopbackBridge } from './bridge.mjs';
import { ALL_WATCHLIST_MARKETS, CHART_LAYOUTS, CHART_TIMEFRAMES, decodeMarketStream, MAX_MARKET_STREAM_BYTES, mountMarketCharts, releaseDetachedCanvases } from './chart.mjs';
import { MAX_BROKER_ROUTING_BYTES, normalizeBrokerRouting } from './broker-routing.mjs';
import {
  MAX_AI_PAYLOAD_BYTES,
  SESSION_CADENCE_MODES,
  normalizeAiModels,
  normalizeAiTrader,
  normalizeIndexStream,
  renderAiOverseerPanel,
  renderBankedProfitsHeroBanner,
  shouldAutoConnectLiveFeed,
} from './ai-overseer.mjs';
import {
  MAX_TREASURY_BYTES,
  mountAnalyticsCanvases,
  normalizeParallelTiers,
  normalizeTreasury,
  renderEquityAndAnalyticsSection,
} from './analytics.mjs';
import {
  clampCapitalUsd,
  clampLotHundredths,
  createDefaultMoneyFlowState,
  mountMoneyFlowWidget,
  renderMoneyFlowSection,
  resolveLiveAccountBalanceUsd,
  stepMoneyFlowSimulation,
} from './money-flow.mjs';
import {
  clampLiveCapitalUsd,
  createDefaultLiveFundingState,
  evaluateLiveArmingPreflight,
  renderLiveFundingPanel,
} from './live-funding.mjs';
import {
  PAIRING_DEFAULT_TTL_SECONDS,
  SESSION_SCOPES,
  buildPairingUrl,
  extractAndStripBootPairingParams,
  isOwnerControlSession,
  normalizeAuthSessionResponse,
  normalizePairCodeMintResponse,
  normalizePairExchangeResponse,
  renderQrSvg,
} from './qr-pairing.mjs';
import {
  AGGRESSION_DIAL_SCHEMA,
  HIGH_RISK_MIN_BPS,
  STATIC_AGGRESSION_DIAL,
  applyAggressionDialPreset,
  applyMarketConditionPreview,
  clampRiskBps,
  normalizeAggressionDial,
  patchAggressionDialInPlace,
  renderMasterAggressionDial,
  renderSectionB5TierDials,
  resolveCockpitAggressionDial,
} from './aggression-dial.mjs';
import {
  COMPOUNDING_PANEL_SCHEMA,
  STATIC_COMPOUNDING_PANEL,
  compareDecimalStrings,
  normalizeCompoundingPanel,
  normalizeDecimalString,
  patchCompoundingPanelInPlace,
} from './compounding-panel.mjs';
import {
  STATIC_OPTION_B_DEMO,
  normalizeOptionBDemo,
  patchOptionBDemoPanelInPlace,
} from './option-b-demo-panel.mjs';
import {
  STATIC_DEMO_HIGH_GROWTH,
  normalizeDemoHighGrowth,
  patchDemoHighGrowthPanelInPlace,
} from './demo-high-growth-panel.mjs';
import {
  attachScrollActivityListeners,
  captureScrollSnapshot,
  createScrollActivityGuard,
} from './scroll-guard.mjs';

// Fixed same-origin assets. Only explicit trusted bootstrap may inject a scoped bridge.
const schemaURL = new URL('../docs/contracts/cockpit.schema.json', document.baseURI);
const fixtureURL = new URL('../docs/contracts/initial-cockpit.json', document.baseURI);
const reviewSchemaURL = new URL('../docs/contracts/decision-read.schema.json', document.baseURI);
const reviewFixtureURL = new URL('../docs/contracts/initial-decision-read.json', document.baseURI);
const marketSchemaURL = new URL('../docs/contracts/market-stream.schema.json', document.baseURI);
const marketFixtureURL = new URL('../docs/contracts/initial-market-stream.json', document.baseURI);
const root = document.querySelector('#app');
const dialog = document.querySelector('#review-dialog');
const announcer = document.querySelector('#announcer');
let sharedSchema = null;
let reviewSchema = null;
let rawReviewSchema = null;
let marketSchema = null;
const SESSION_TOKEN_KEY = 'cas_forex_bearer_token';
const SESSION_SCOPE_KEY = 'cas_forex_session_scope';
let liveSseAbort = null;
let controller = null;
let dialogContext = null;
let lastBridgeProjection = null;
let loadGeneration = 0;
let reviewGeneration = 0;
let dialogTrigger = null;
let explainer = null;
let activePointerPress = false;
let streamRenderTimer = null;
let deferredRenderPending = false;
let scrollListeners = null;
const scrollGuard = createScrollActivityGuard({
  onQuiet: () => { flushDeferredRender(); },
});

function restoreScrollPosition(scrollSnap) {
  scrollListeners?.syncWorkspace?.();
  scrollGuard.restoreSnapshot(scrollSnap, document, window, { skipWindow: true });
  if (typeof window.scrollTo === 'function') window.scrollTo(scrollSnap.windowX, scrollSnap.windowY);
}
let loopbackAuthToken = null;
let pendingBootPairCode = null;
let bootSecurityIssue = null;
let initialSessionScope = SESSION_SCOPES.OWNER_FULL_CONTROL;
let initialOwnerControlsAllowed = true;
try {
  const bootPairing = extractAndStripBootPairingParams(window.location, window.history);
  if (bootPairing.pairCode) {
    pendingBootPairCode = bootPairing.pairCode;
  } else {
    if (bootPairing.strippedLegacyToken) {
      bootSecurityIssue = 'URL ?token= bearer parameter is disabled for security. Paste your Owner Key or scan a single-use ?pair_code= QR.';
    }
    const stored = window.sessionStorage?.getItem?.(SESSION_TOKEN_KEY);
    if (stored && stored.trim().length >= 16 && !/[\r\n\0]/.test(stored)) {
      loopbackAuthToken = stored.trim();
      const storedScope = window.sessionStorage?.getItem?.(SESSION_SCOPE_KEY);
      if (storedScope === SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER) {
        initialSessionScope = SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER;
        initialOwnerControlsAllowed = false;
      }
    }
  }
} catch { /* Static preview has no pairing query. */ }

let qrAutoCloseTimer = null;
let activePairCode = null;

function closeQrPairingDrawer(shouldRender = false) {
  if (qrAutoCloseTimer !== null) {
    window.clearTimeout(qrAutoCloseTimer);
    qrAutoCloseTimer = null;
  }
  activePairCode = null;
  if (state.qrPairingOpen || state.qrPairingSvg || state.qrPairingCopiedNotice) {
    state = {
      ...state,
      qrPairingOpen: false,
      qrPairingSvg: null,
      qrPairingCopiedNotice: null,
      qrPairingExpiresAt: null,
      qrPairingTtlSeconds: PAIRING_DEFAULT_TTL_SECONDS,
      qrPairingScope: SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER,
    };
    if (shouldRender) render();
  }
}

/** Explicitly set or clear the origin-scoped loopback bearer token (sessionStorage + memory, zero cookies). */
export function setLoopbackAuthToken(token, options = {}) {
  if (token === null) {
    loopbackAuthToken = null;
    try {
      window.sessionStorage?.removeItem?.(SESSION_TOKEN_KEY);
      window.sessionStorage?.removeItem?.(SESSION_SCOPE_KEY);
    } catch { /* Ignore */ }
    if (typeof state === 'object' && state) {
      state.sessionScope = SESSION_SCOPES.OWNER_FULL_CONTROL;
      state.ownerControlsAllowed = false;
      state.canPairDevice = false;
      closeQrPairingDrawer(false);
    }
    return;
  }
  if (typeof token !== 'string' || token.trim().length < 16 || /[\r\n\0]/.test(token)) throw new Error('Invalid loopback auth token.');
  const scope = options?.scope === SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER
    ? SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER
    : SESSION_SCOPES.OWNER_FULL_CONTROL;
  const ownerAllowed = scope === SESSION_SCOPES.OWNER_FULL_CONTROL && options?.ownerControlsAllowed !== false;
  loopbackAuthToken = token.trim();
  try {
    window.sessionStorage?.setItem?.(SESSION_TOKEN_KEY, loopbackAuthToken);
    window.sessionStorage?.setItem?.(SESSION_SCOPE_KEY, scope);
  } catch { /* Ignore */ }
  if (typeof state === 'object' && state) {
    state.sessionScope = scope;
    state.ownerControlsAllowed = ownerAllowed;
    state.canPairDevice = Boolean(ownerAllowed);
    if (!ownerAllowed) closeQrPairingDrawer(false);
  }
}
let state = {
  projection: null, source: 'none', loadedAt: null, schemaReady: false,
  error: null, loading: false, route: routeFromHash(), theme: 'system',
  reviewView: 'list', reviewFilter: 'all', explainerIssue: null, inspection: resetInspection(),
  reviewEnvelope: null, reviewIssue: null, reviewSchemaReady: false, lastLoaded: null, transport: null,
  marketStream: null, chartPair: 'EURUSD', chartTimeframe: 'M5', chartLayout: 'single', chartCategory: 'all',
  liveStreamConnected: false, chartMicroBars: {}, brokerRouting: null,
  aiModels: null, aiTrader: null, indexStream: null, aiActionBusy: false, aiIssue: bootSecurityIssue,
  treasury: null, parallelTiers: null, chartZoomBars: 60, inspectedTradeIdx: 0,
  moneyFlow: createDefaultMoneyFlowState(),
  liveFunding: createDefaultLiveFundingState(),
  aggressionDial: STATIC_AGGRESSION_DIAL,
  compounding: STATIC_COMPOUNDING_PANEL,
  optionBDemo: STATIC_OPTION_B_DEMO,
  demoHighGrowth: STATIC_DEMO_HIGH_GROWTH,
  unlockDraft: '',
  unlockKeyVisible: false,
  sessionScope: initialSessionScope,
  ownerControlsAllowed: Boolean(loopbackAuthToken && initialOwnerControlsAllowed),
  canPairDevice: Boolean(loopbackAuthToken && initialOwnerControlsAllowed),
  qrPairingOpen: false,
  qrPairingSvg: null,
  qrPairingCopiedNotice: null,
  qrPairingExpiresAt: null,
  qrPairingTtlSeconds: PAIRING_DEFAULT_TTL_SECONDS,
  qrPairingScope: SESSION_SCOPES.DEVICE_READ_AND_EXPLAINER,
};

function routeFromHash() {
  const route = window.location.hash.slice(1);
  return ['operate', 'review', 'setup'].includes(route) ? route : 'operate';
}

function isInteractiveFormActive() {
  if (activePointerPress || scrollGuard.isScrolling()) return true;
  const active = document.activeElement;
  return Boolean(root.contains(active) && ['SELECT', 'INPUT', 'TEXTAREA'].includes(active?.tagName));
}

function flushDeferredRender() {
  if (!deferredRenderPending || isInteractiveFormActive()) return;
  deferredRenderPending = false;
  render();
}

function scheduleStreamRender() {
  if (isInteractiveFormActive()) {
    deferredRenderPending = true;
    return;
  }
  if (streamRenderTimer !== null) return;
  streamRenderTimer = window.setTimeout(() => {
    streamRenderTimer = null;
    if (isInteractiveFormActive()) {
      deferredRenderPending = true;
      return;
    }
    const doPaint = () => {
      if (isInteractiveFormActive()) {
        deferredRenderPending = true;
        return;
      }
      render();
    };
    if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(doPaint);
    else doPaint();
  }, 180);
}

function rerenderMoneyFlowInPlace(focusSelector = null) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const currentSec = root.querySelector('#money-flow-section');
  if (!currentSec) {
    render();
    return;
  }
  const nextSec = new DOMParser().parseFromString(renderMoneyFlowSection(state), 'text/html').body.firstElementChild;
  if (nextSec) {
    currentSec.replaceWith(nextSec);
    try { mountMoneyFlowWidget(root, state); } catch { /* SVG optional in headless environments. */ }
    if (focusSelector) {
      nextSec.querySelector(focusSelector)?.focus({ preventScroll: true });
    }
  }
  restoreScrollPosition(scrollSnap);
}

function rerenderLiveFundingInPlace(focusSelector = null) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const currentSec = root.querySelector('#live-funding-section');
  if (!currentSec) {
    render();
    return;
  }
  const nextSec = new DOMParser().parseFromString(renderLiveFundingPanel(state), 'text/html').body.firstElementChild;
  if (nextSec) {
    currentSec.replaceWith(nextSec);
    if (focusSelector) {
      nextSec.querySelector(focusSelector)?.focus({ preventScroll: true });
    }
  }
  restoreScrollPosition(scrollSnap);
}

function rerenderAiSectionsInPlace(focusSelector = null) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const currentHero = root.querySelector('[data-banked-profits-hero="true"]');
  const currentOverseer = root.querySelector('.ai-overseer-panel');
  const currentAnalytics = root.querySelector('.analytics-vault-panel');
  if (!currentHero && !currentOverseer && !currentAnalytics) {
    render();
    return;
  }
  if (currentHero) {
    const nextHero = new DOMParser().parseFromString(renderBankedProfitsHeroBanner(state), 'text/html').body.firstElementChild;
    if (nextHero) currentHero.replaceWith(nextHero);
  }
  if (currentOverseer) {
    const nextOverseer = new DOMParser().parseFromString(renderAiOverseerPanel(state), 'text/html').body.firstElementChild;
    if (nextOverseer) currentOverseer.replaceWith(nextOverseer);
  }
  if (currentAnalytics) {
    const nextAnalytics = new DOMParser().parseFromString(renderEquityAndAnalyticsSection(state), 'text/html').body.firstElementChild;
    if (nextAnalytics) {
      currentAnalytics.replaceWith(nextAnalytics);
      try { mountAnalyticsCanvases(root, state); } catch { /* Headless canvas optional. */ }
    }
  }
  if (focusSelector) {
    root.querySelector(focusSelector)?.focus({ preventScroll: true });
  }
  restoreScrollPosition(scrollSnap);
}

function rerenderAnalyticsInPlace(focusSelector = null) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const currentAnalytics = root.querySelector('.analytics-vault-panel');
  if (!currentAnalytics) {
    render();
    return;
  }
  const nextAnalytics = new DOMParser().parseFromString(renderEquityAndAnalyticsSection(state), 'text/html').body.firstElementChild;
  if (nextAnalytics) {
    currentAnalytics.replaceWith(nextAnalytics);
    try { mountAnalyticsCanvases(root, state); } catch { /* Headless canvas optional. */ }
    if (focusSelector) {
      nextAnalytics.querySelector(focusSelector)?.focus({ preventScroll: true });
    }
  }
  restoreScrollPosition(scrollSnap);
}

function render(focusMain = false) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const active = document.activeElement;
  const activeUnlock = root.contains(active) && active?.tagName === 'INPUT' && active?.name === 'cockpit_access_key'
    ? {
        id: active.id,
        value: String(active.value ?? ''),
        selStart: typeof active.selectionStart === 'number' ? active.selectionStart : null,
        selEnd: typeof active.selectionEnd === 'number' ? active.selectionEnd : null,
      }
    : null;
  if (activeUnlock && (!state.liveStreamConnected || !isOwnerControlSession(state))) {
    state.unlockDraft = activeUnlock.value;
  }
  const identity = root.contains(active) && active?.tagName === 'BUTTON' ? JSON.stringify(active.dataset) : null;
  document.documentElement.dataset.theme = state.theme;
  try { releaseDetachedCanvases(root); } catch { /* Best-effort buffer release. */ }
  replaceSafeHTML(root, renderApp(state));
  if (state.liveStreamConnected && !isOwnerControlSession(state)) {
    for (const el of root.querySelectorAll('[data-thinking-depth], [data-select-ai-model], [data-treasury-rail], [data-treasury-action], [data-dial-master-slider], [data-dial-master-preset], [data-dial-market-mode], [data-dial-action], [data-dial-tier-slider], [data-dial-tier-bps], [data-dial-tier-preset], [data-dial-confirm-high-risk], [data-dial-cancel-high-risk], [data-compounding-action]')) {
      el.disabled = true;
    }
  }
  try { mountMarketCharts(root, state); mountAnalyticsCanvases(root, state); mountMoneyFlowWidget(root, state); } catch { /* Chart/SVG optional in headless environments. */ }
  if (!focusMain) restoreScrollPosition(scrollSnap);
  try { explainer?.sync(); } catch { disableExplainer(); }
  document.title = `${state.route[0].toUpperCase() + state.route.slice(1)} / CAS Forex`;
  if (focusMain) document.querySelector('#main')?.focus({ preventScroll: true });
  else if (activeUnlock && (!state.liveStreamConnected || !isOwnerControlSession(state))) {
    const restoredInput = activeUnlock.id
      ? root.querySelector(`#${activeUnlock.id}`)
      : root.querySelector('input[name="cockpit_access_key"]');
    if (restoredInput) {
      restoredInput.value = state.unlockDraft ?? activeUnlock.value;
      restoredInput.focus({ preventScroll: true });
      try {
        if (activeUnlock.selStart !== null) {
          restoredInput.setSelectionRange(activeUnlock.selStart, activeUnlock.selEnd ?? activeUnlock.selStart);
        }
      } catch { /* Optional selection restore */ }
    }
  } else if (identity) {
    const replacement = [...root.querySelectorAll('button')].find((item) => !item.disabled && JSON.stringify(item.dataset) === identity);
    (replacement ?? document.querySelector('#main'))?.focus({ preventScroll: true });
  }
  if (!focusMain) restoreScrollPosition(scrollSnap);
}

function announce(message) { announcer.textContent = message; }

// Optional guidance must never interrupt a source read, control, or focus restore.
function disableExplainer() {
  try { explainer?.destroy(); } catch { /* Continue restoring the workspace. */ }
  explainer = null;
  document.querySelector('#forex-explainer')?.remove();
  const guideWorkspace = document.querySelector('#forex-explainer-workspace');
  if (root.parentNode === guideWorkspace) guideWorkspace.replaceWith(root);
  document.body.classList.remove('forex-explainer-ready', 'forex-explainer-open');
  delete document.body.dataset.forexExplainerEdge;
  delete document.body.dataset.forexExplainerSide;
  scrollListeners?.syncWorkspace?.();
  state.explainerIssue = 'The local guide is unavailable in this browser session.';
  announce(state.explainerIssue);
}

function bridgeChanged(snapshot) {
  const projectionIdentity = JSON.stringify(snapshot.projection);
  if (projectionIdentity !== lastBridgeProjection) {
    lastBridgeProjection = projectionIdentity;
    state.loadedAt = snapshot.projection ? new Date().toISOString() : null;
    state.reviewEnvelope = null;
    state.inspection = resetInspection();
    reviewGeneration += 1;
  }
  state.transport = snapshot;
  state.projection = snapshot.projection;
  state.source = snapshot.projection ? 'scoped simulator' : 'none';
  state.loading = false;
  state.error = snapshot.issue;
  render();
  updateDialog();
  const latest = snapshot.close ?? snapshot.controls.at(-1);
  if (latest) announce(`${latest.status}: ${latest.reason}`);
}

function updateDialog() {
  if (!dialog.open || !dialogContext) return;
  const active = document.activeElement;
  const identity = active?.tagName === 'BUTTON' ? JSON.stringify(active.dataset) : null;
  replaceSafeHTML(dialog, dialogContext === 'prepared' ? renderPreparedClose(state.transport) : renderControlDialog(dialogContext, state.transport));
  const matching = [...dialog.querySelectorAll('button')].find((item) => !item.disabled && JSON.stringify(item.dataset) === identity);
  (matching ?? dialog.querySelector('[data-dialog-close]'))?.focus({ preventScroll: true });
}

async function loadSchemas() {
  if (!sharedSchema) sharedSchema = parseUniqueJSON(await readStatic(schemaURL));
  if (!marketSchema) marketSchema = parseUniqueJSON(await readStatic(marketSchemaURL));
  if (!reviewSchema) {
    rawReviewSchema = await readStatic(reviewSchemaURL);
    reviewSchema = parseUniqueJSON(rawReviewSchema);
  }
  state.schemaReady = sharedSchema?.$id === 'urn:cas-forex:cockpit:1.0';
  state.reviewSchemaReady = reviewSchema?.$id === 'urn:cas-forex:decision-read:0.1';
  if (!state.schemaReady || !state.reviewSchemaReady) throw new Error('Expected shared schemas unavailable.');
}

/** Called only by an approved explicit bootstrap. No URL, file, storage, or global auto-discovery. */
export async function attachTransport(bridge) {
  if (controller?.attached) throw new Error('Detach the previous bridge before attaching another.');
  const generation = beginLoad();
  try {
    await loadSchemas();
    if (generation !== loadGeneration) throw new Error('Attachment superseded by a source change.');
    if (!controller) controller = new ScopedBridge({ cockpitSchema: sharedSchema, onChange: bridgeChanged });
    await controller.attach(bridge);
    await readBridgeReview();
    await readBridgeMarketStream();
    return { detach: detachTransport, read: readTransport };
  } catch (error) { failLoad(generation, error); throw error; }
}

export function detachTransport() {
  stopLoopbackStream();
  loadGeneration += 1; reviewGeneration += 1;
  state.reviewEnvelope = null; state.reviewIssue = 'Transport detached. Prior references are historical.';
  controller?.detach();
  announce('Bridge detached. Effects remain unobserved; nothing was resubmitted.');
}

async function readBridgeReview() {
  const generation = ++reviewGeneration;
  state.reviewEnvelope = null;
  state.reviewIssue = 'Reading scoped decision records.';
  try {
    const read = await controller.readReview(reviewSchema, new TextEncoder().encode(rawReviewSchema));
    if (generation !== reviewGeneration || !controller.attached) return;
    state.reviewEnvelope = read; state.reviewIssue = null; state.inspection = resetInspection();
  } catch (error) { if (generation === reviewGeneration) state.reviewIssue = error.message; }
  render();
}

async function readBridgeMarketStream() {
  if (!controller?.attached || !marketSchema) return;
  try {
    const mstream = await controller.readMarketStream(marketSchema);
    if (mstream) { state.marketStream = mstream; render(); }
  } catch { /* Keep prior verified market stream or empty state. */ }
}

function recordMicroTickItems(items) {
  if (!items) return;
  const nextMicro = { ...state.chartMicroBars };
  for (const s of items) {
    if (!s?.pair || !s?.mid) continue;
    const prev = Array.isArray(nextMicro[s.pair]) ? nextMicro[s.pair].slice(-47) : [];
    const lastClose = prev.length ? prev[prev.length - 1].c : s.mid;
    const hi = Number(s.mid) >= Number(lastClose) ? s.mid : lastClose;
    const lo = Number(s.mid) <= Number(lastClose) ? s.mid : lastClose;
    prev.push(Object.freeze({ t: s.observed_at || new Date().toISOString(), o: lastClose, h: hi, l: lo, c: s.mid, v: '1.00', n: 1 }));
    nextMicro[s.pair] = prev;
  }
  state.chartMicroBars = nextMicro;
}

function recordMicroTick(envelope) {
  recordMicroTickItems(envelope?.streams ?? []);
}

function stopLoopbackStream() {
  if (liveSseAbort) { liveSseAbort.abort(); liveSseAbort = null; }
  stopLiveCockpitPollLoop();
  state.liveStreamConnected = false;
  closeQrPairingDrawer(false);
}

function handleSseEvent(eventName, dataText) {
  if (eventName === 'market') {
    try {
      const nextEnv = decodeMarketStream(dataText, marketSchema);
      state.marketStream = nextEnv;
      recordMicroTick(nextEnv);
      if (controller?.attached) void controller.refresh().catch(() => {});
      else scheduleStreamRender();
    } catch { /* Ignore malformed frame. */ }
  } else if (eventName === 'index_stream') {
    try {
      const nextIdx = normalizeIndexStream(parseUniqueJSON(dataText, MAX_MARKET_STREAM_BYTES));
      state.indexStream = nextIdx;
      recordMicroTickItems(nextIdx.markets);
      scheduleStreamRender();
    } catch { /* Ignore malformed index_stream frame. */ }
  } else if (eventName === 'ai_trader') {
    try {
      state.aiTrader = normalizeAiTrader(parseUniqueJSON(dataText, MAX_AI_PAYLOAD_BYTES));
      refreshCompoundingFromTick();
      scheduleStreamRender();
    } catch { /* Ignore malformed ai_trader frame. */ }
  } else if (eventName === 'ai_models') {
    try {
      state.aiModels = normalizeAiModels(parseUniqueJSON(dataText, MAX_AI_PAYLOAD_BYTES));
      scheduleStreamRender();
    } catch { /* Ignore malformed ai_models frame. */ }
  } else if (eventName === 'treasury') {
    try {
      state.treasury = normalizeTreasury(parseUniqueJSON(dataText, MAX_TREASURY_BYTES));
      refreshCompoundingFromTick();
      scheduleStreamRender();
    } catch { /* Ignore malformed treasury frame. */ }
  } else if (eventName === 'parallel_tiers') {
    try {
      state.parallelTiers = normalizeParallelTiers(parseUniqueJSON(dataText, MAX_TREASURY_BYTES));
      scheduleStreamRender();
    } catch { /* Ignore malformed parallel_tiers frame. */ }
  } else if (eventName === 'aggression_dial') {
    try {
      const nextDial = normalizeAggressionDial(parseUniqueJSON(dataText, MAX_AI_PAYLOAD_BYTES));
      state.aggressionDial = nextDial;
      if (!isDialSliderDragging()) {
        syncAggressionDialDom();
      }
    } catch { /* Ignore malformed aggression_dial frame. */ }
  } else if (eventName === 'compounding') {
    try {
      state.compounding = normalizeCompoundingPanel(parseUniqueJSON(dataText, MAX_AI_PAYLOAD_BYTES));
      syncCompoundingDom();
    } catch { /* Ignore malformed compounding frame. */ }
  } else if (eventName === 'option_b_demo') {
    try {
      state.optionBDemo = normalizeOptionBDemo(parseUniqueJSON(dataText, MAX_AI_PAYLOAD_BYTES));
      syncOptionBDemoDom();
    } catch { /* Ignore malformed Option B demo frame. */ }
  } else if (eventName === 'demo_high_growth_profile') {
    try {
      state.demoHighGrowth = normalizeDemoHighGrowth(parseUniqueJSON(dataText, MAX_AI_PAYLOAD_BYTES));
      syncDemoHighGrowthDom();
    } catch { /* Ignore malformed DEMO high-growth profile frame. */ }
  }
}

async function startFetchSseStream(abortCtrl) {
  const sseURL = new URL('/api/market-events', window.location.origin);
  if (sseURL.origin !== window.location.origin) throw new Error('SSE requires same-origin loopback URL.');
  const headers = { Accept: 'text/event-stream' };
  if (loopbackAuthToken) headers.Authorization = `Bearer ${loopbackAuthToken}`;
  const resp = await fetch(sseURL, {
    method: 'GET',
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    headers,
    signal: abortCtrl.signal,
  });
  if (!resp.ok || !resp.body) throw new Error(`SSE stream failed (${resp.status}).`);
  const reader = resp.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let buffer = '';
  try {
    while (!abortCtrl.signal.aborted) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop() ?? '';
      for (const blk of blocks) {
        let evName = 'message';
        const dataLines = [];
        for (const line of blk.split(/\r?\n/)) {
          if (line.startsWith('event:')) evName = line.slice(6).trim();
          else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
        }
        if (dataLines.length > 0) handleSseEvent(evName, dataLines.join('\n'));
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

async function readAuthSession() {
  try {
    const raw = await readStatic(new URL('/api/auth-session', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    const info = normalizeAuthSessionResponse(parseUniqueJSON(raw, MAX_AI_PAYLOAD_BYTES));
    if (info) {
      state.sessionScope = info.sessionScope;
      state.ownerControlsAllowed = info.ownerControlsAllowed;
      state.canPairDevice = Boolean(loopbackAuthToken && info.ownerControlsAllowed);
      try { window.sessionStorage?.setItem?.(SESSION_SCOPE_KEY, info.sessionScope); } catch { /* Ignore */ }
      if (!info.ownerControlsAllowed) closeQrPairingDrawer(false);
    }
  } catch { /* Optional endpoint on older or fixture-only previews. */ }
}

async function exchangePairCodeAndConnect(pairCode) {
  const url = new URL('/api/pair-exchange', window.location.origin);
  if (url.origin !== window.location.origin || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Pairing exchange requires same-origin HTTP or HTTPS preview.');
  }
  const resp = await fetch(url, {
    method: 'POST',
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ pair_code: pairCode }),
    signal: AbortSignal.timeout(10000),
  });
  const raw = await resp.text();
  const parsed = parseUniqueJSON(raw, MAX_AI_PAYLOAD_BYTES);
  if (!resp.ok) {
    throw new Error(parsed?.error || `Pairing code expired, already used, or revoked (${resp.status}).`);
  }
  const exchanged = normalizePairExchangeResponse(parsed);
  setLoopbackAuthToken(exchanged.sessionToken, {
    scope: exchanged.sessionScope,
    ownerControlsAllowed: exchanged.ownerControlsAllowed,
  });
  await connectLoopbackLiveFeed();
  announce('Paired device connected in Least-Privilege Read + Explainer mode. Owner trading controls remain locked.');
}

function requireOwnerControlOrWarn(actionLabel) {
  if (isOwnerControlSession(state)) return true;
  state.aiIssue = `${actionLabel} blocked: paired device session is Read + Explainer only. Paste Primary Owner Key to step up to Owner Full Control.`;
  render();
  announce(state.aiIssue);
  return false;
}

async function connectLoopbackLiveFeed() {
  if (!marketSchema) marketSchema = parseUniqueJSON(await readStatic(marketSchemaURL));
  const streamURL = new URL('/api/market-stream', window.location.origin);
  const initialRaw = await readStatic(streamURL, MAX_MARKET_STREAM_BYTES);
  const decoded = decodeMarketStream(initialRaw, marketSchema);
  state.marketStream = decoded;
  recordMicroTick(decoded);
  stopLoopbackStream();
  if (loopbackAuthToken) {
    const abortCtrl = new AbortController();
    liveSseAbort = abortCtrl;
    void startFetchSseStream(abortCtrl).catch(() => {
      if (liveSseAbort === abortCtrl) { stopLoopbackStream(); render(); }
    });
  }
  state.liveStreamConnected = true;
  await readAuthSession();
  state.canPairDevice = Boolean(loopbackAuthToken && isOwnerControlSession(state));
  state.aiIssue = null;
  state.unlockDraft = '';
  state.unlockKeyVisible = false;
  if (!controller?.attached && isOwnerControlSession(state)) {
    try {
      const health = parseUniqueJSON(await readStatic(new URL('/api/health', window.location.origin)));
      if (health.bridge_attached) {
        await attachTransport(createAuthenticatedLoopbackBridge({
          baseUrl: window.location.origin,
          authToken: loopbackAuthToken,
          maxBytes: MAX_MARKET_STREAM_BYTES,
          maxReviewBytes: MAX_REVIEW_BYTES,
        }));
      }
    } catch { /* Operate with verified market stream even if ScopedUIService is absent. */ }
  }
  await readBrokerRouting();
  await readAiCockpitFeeds();
  startLiveCockpitPollLoop();
  render();
  announce('Connected to verified loopback market stream and autonomous AI overseer.');
}

// Optional loopback-only broker routing summary. Any failure keeps the static Setup preview.
async function readBrokerRouting() {
  try {
    const raw = await readStatic(new URL('/api/broker-routing', window.location.origin), MAX_BROKER_ROUTING_BYTES);
    state.brokerRouting = normalizeBrokerRouting(parseUniqueJSON(raw, MAX_BROKER_ROUTING_BYTES));
  } catch {
    state.brokerRouting = null; // Static/offline mode: no routing endpoint, nothing changes.
  }
}

async function readAiCockpitFeeds() {
  try {
    const rawModels = await readStatic(new URL('/api/ai-models', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    state.aiModels = normalizeAiModels(parseUniqueJSON(rawModels, MAX_AI_PAYLOAD_BYTES));
  } catch { state.aiModels = null; }
  try {
    const rawTrader = await readStatic(new URL('/api/ai-trader', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    state.aiTrader = normalizeAiTrader(parseUniqueJSON(rawTrader, MAX_AI_PAYLOAD_BYTES));
  } catch { state.aiTrader = null; }
  try {
    const rawIndex = await readStatic(new URL('/api/index-stream', window.location.origin), MAX_MARKET_STREAM_BYTES);
    state.indexStream = normalizeIndexStream(parseUniqueJSON(rawIndex, MAX_MARKET_STREAM_BYTES));
    recordMicroTickItems(state.indexStream.markets);
  } catch { state.indexStream = null; }
  try {
    const rawTreas = await readStatic(new URL('/api/treasury', window.location.origin), MAX_TREASURY_BYTES);
    state.treasury = normalizeTreasury(parseUniqueJSON(rawTreas, MAX_TREASURY_BYTES));
  } catch { state.treasury = null; }
  try {
    const rawTiers = await readStatic(new URL('/api/parallel-tiers', window.location.origin), MAX_TREASURY_BYTES);
    state.parallelTiers = normalizeParallelTiers(parseUniqueJSON(rawTiers, MAX_TREASURY_BYTES));
  } catch { state.parallelTiers = null; }
  await readAggressionDial();
  await readCompounding();
  await readOptionBDemo();
  await readDemoHighGrowth();
}

const LIVE_COCKPIT_POLL_MS = 4000;
let liveCockpitPollTimer = null;
let liveCockpitPollInFlight = false;
let compoundingTickRefreshInFlight = false;

function isStrictOwnerCompoundingSession() {
  if (state.liveStreamConnected !== true) return false;
  if (!loopbackAuthToken) return false;
  if (state.sessionScope !== SESSION_SCOPES.OWNER_FULL_CONTROL) return false;
  if (state.ownerControlsAllowed !== true) return false;
  return isOwnerControlSession(state);
}

async function readCompounding() {
  try {
    const rawComp = await readStatic(new URL('/api/compounding', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    state.compounding = normalizeCompoundingPanel(parseUniqueJSON(rawComp, MAX_AI_PAYLOAD_BYTES));
  } catch {
    if (state.aiTrader?.compounding) {
      state.compounding = normalizeCompoundingPanel(state.aiTrader.compounding);
    }
  }
}

function syncCompoundingDom(focusSelector = null) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const resolved = resolveCockpitCompounding(state);
  const panelEl = root.querySelector('[data-compounding-panel="true"]');
  if (panelEl) {
    patchCompoundingPanelInPlace(panelEl, resolved);
    if (focusSelector) {
      panelEl.querySelector(focusSelector)?.focus({ preventScroll: true });
    }
  }
  restoreScrollPosition(scrollSnap);
}

async function readOptionBDemo() {
  try {
    const rawOb = await readStatic(new URL('/api/option-b-demo', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    state.optionBDemo = normalizeOptionBDemo(parseUniqueJSON(rawOb, MAX_AI_PAYLOAD_BYTES));
  } catch { /* Keep prior verified Option B paper demo snapshot. */ }
}

function syncOptionBDemoDom() {
  const scrollSnap = captureScrollSnapshot(document, window);
  const panelEl = root.querySelector('[data-option-b-demo="true"]');
  if (panelEl) {
    patchOptionBDemoPanelInPlace(panelEl, resolveCockpitOptionBDemo(state));
  }
  restoreScrollPosition(scrollSnap);
}

async function readDemoHighGrowth() {
  try {
    const rawDhg = await readStatic(new URL('/api/demo-high-growth-profile', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    state.demoHighGrowth = normalizeDemoHighGrowth(parseUniqueJSON(rawDhg, MAX_AI_PAYLOAD_BYTES));
  } catch { /* Keep prior verified DEMO high-growth profile snapshot. */ }
}

function syncDemoHighGrowthDom(focusSelector = null) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const panelEl = root.querySelector('[data-demo-high-growth="true"]');
  if (panelEl) {
    patchDemoHighGrowthPanelInPlace(panelEl, resolveCockpitDemoHighGrowth(state));
    if (focusSelector) {
      panelEl.querySelector(focusSelector)?.focus({ preventScroll: true });
    }
  }
  restoreScrollPosition(scrollSnap);
}

async function submitDemoHighGrowthMutation(payload, focusSelector = null) {
  if (!state.liveStreamConnected) return;
  if (!isStrictOwnerCompoundingSession()) {
    requireOwnerControlOrWarn('DEMO High-Growth Practice Profile toggle');
    syncDemoHighGrowthDom();
    return;
  }
  try {
    const res = await postLoopbackJson('/api/demo-high-growth-profile', payload);
    state.demoHighGrowth = normalizeDemoHighGrowth(res);
    state.aiIssue = null;
    await Promise.all([readAggressionDial(), readCompounding(), readOptionBDemo()]);
    syncDemoHighGrowthDom(focusSelector);
    if (!isDialSliderDragging()) syncAggressionDialDom();
    syncCompoundingDom();
    syncOptionBDemoDom();
    announce(state.demoHighGrowth.enabled
      ? 'DEMO High-Growth Practice Mode enabled (10% risk, 30% DD freeze, 100% compounding).'
      : 'DEMO High-Growth Practice Mode disabled (restored 1.00% / 10.00% standard caps).');
  } catch (error) {
    if (error?.status === 403) {
      state.ownerControlsAllowed = false;
      state.canPairDevice = false;
    }
    state.aiIssue = error instanceof Error ? error.message : 'DEMO high-growth profile update failed.';
    announce(state.aiIssue);
    await readDemoHighGrowth();
    if (error?.status === 403) render();
    else syncDemoHighGrowthDom(focusSelector);
  }
}

function refreshCompoundingFromTick() {
  if (!state.liveStreamConnected || compoundingTickRefreshInFlight) return;
  compoundingTickRefreshInFlight = true;
  void readCompounding()
    .then(() => { syncCompoundingDom(); })
    .finally(() => { compoundingTickRefreshInFlight = false; });
}

async function pollLiveCockpitState() {
  if (!state.liveStreamConnected || document.hidden || liveCockpitPollInFlight) return;
  liveCockpitPollInFlight = true;
  try {
    try {
      const rawTrader = await readStatic(new URL('/api/ai-trader', window.location.origin), MAX_AI_PAYLOAD_BYTES);
      state.aiTrader = normalizeAiTrader(parseUniqueJSON(rawTrader, MAX_AI_PAYLOAD_BYTES));
    } catch { /* Keep prior verified trader snapshot. */ }
    await readAggressionDial();
    await readCompounding();
    await readOptionBDemo();
    await readDemoHighGrowth();
    if (!isDialSliderDragging()) {
      syncAggressionDialDom();
    }
    syncCompoundingDom();
    syncOptionBDemoDom();
    syncDemoHighGrowthDom();
  } finally {
    liveCockpitPollInFlight = false;
  }
}

function startLiveCockpitPollLoop() {
  stopLiveCockpitPollLoop();
  if (!state.liveStreamConnected) return;
  liveCockpitPollTimer = window.setInterval(() => {
    void pollLiveCockpitState();
  }, LIVE_COCKPIT_POLL_MS);
}

function stopLiveCockpitPollLoop() {
  if (liveCockpitPollTimer !== null) {
    window.clearInterval(liveCockpitPollTimer);
    liveCockpitPollTimer = null;
  }
}

async function submitCompoundingMutation(payload, focusSelector = null) {
  if (!state.liveStreamConnected) return;
  if (!isStrictOwnerCompoundingSession()) {
    requireOwnerControlOrWarn('Compounding control update');
    syncCompoundingDom();
    return;
  }
  try {
    const res = await postLoopbackJson('/api/compounding', payload);
    if (res && typeof res === 'object' && (res.schema === COMPOUNDING_PANEL_SCHEMA || res.mode !== undefined || res.compounding_mode !== undefined)) {
      state.compounding = normalizeCompoundingPanel(res);
    } else {
      await readCompounding();
    }
    state.aiIssue = null;
    syncCompoundingDom(focusSelector);
    announce(
      payload.action === 'acknowledge_principal_withdrawn'
        ? `Original principal withdrawal ($${payload.amount_usd}) acknowledged. Trading on 100% house money.`
        : `Compounding mode updated to ${state.compounding.mode}.`,
    );
  } catch (error) {
    if (error?.status === 403) {
      state.ownerControlsAllowed = false;
      state.canPairDevice = false;
    }
    state.aiIssue = error instanceof Error ? error.message : 'Compounding update failed.';
    announce(state.aiIssue);
    await readCompounding();
    if (error?.status === 403) {
      render();
    } else {
      syncCompoundingDom(focusSelector);
    }
  }
}

let dialDebounceTimer = null;
let pendingDialPresetConfirm = null;

function isDialSliderDragging() {
  if (!activePointerPress) return false;
  const active = document.activeElement;
  return Boolean(active?.dataset?.dialMasterSlider || active?.dataset?.dialTierSlider);
}

async function readAggressionDial() {
  try {
    const rawDial = await readStatic(new URL('/api/aggression-dial', window.location.origin), MAX_AI_PAYLOAD_BYTES);
    state.aggressionDial = normalizeAggressionDial(parseUniqueJSON(rawDial, MAX_AI_PAYLOAD_BYTES));
  } catch {
    if (state.aiTrader?.aggressionDial) state.aggressionDial = state.aiTrader.aggressionDial;
    else if (state.parallelTiers?.aggressionDial) state.aggressionDial = state.parallelTiers.aggressionDial;
  }
}

function syncAggressionDialDom(focusSelector = null, forceSectionReplace = false) {
  const scrollSnap = captureScrollSnapshot(document, window);
  const resolved = resolveCockpitAggressionDial(state);
  const hasConfirmDom = Boolean(root.querySelector('[data-dial-confirm-banner="true"]'));
  const needsConfirmDom = Boolean(
    resolved.ownerControlsAllowed
    && resolved.liveMode
    && (
      (resolved.pendingHighRiskBps !== null && resolved.pendingHighRiskBps >= HIGH_RISK_MIN_BPS)
      || (resolved.pendingAiDiscretionCeilingBps !== null && resolved.pendingAiDiscretionCeilingBps >= HIGH_RISK_MIN_BPS)
    ),
  );
  if (forceSectionReplace || hasConfirmDom !== needsConfirmDom) {
    const masterEl = root.querySelector('[data-aggression-dial="master"]');
    if (masterEl) {
      const nextMaster = new DOMParser().parseFromString(renderMasterAggressionDial(resolved), 'text/html').body.firstElementChild;
      if (nextMaster) masterEl.replaceWith(nextMaster);
    }
    const b5El = root.querySelector('[data-section="b5-tier-dials"]');
    if (b5El) {
      const nextB5 = new DOMParser().parseFromString(renderSectionB5TierDials(resolved), 'text/html').body.firstElementChild;
      if (nextB5) b5El.replaceWith(nextB5);
    }
  } else {
    patchAggressionDialInPlace(root, resolved);
  }
  const overseerDialTag = root.querySelector('[data-overseer-aggression-summary="true"]');
  if (overseerDialTag) {
    const ruleSpan = overseerDialTag.querySelector('.state-rule');
    overseerDialTag.textContent = `Dial: ${resolved.masterTargets.riskPctLabel} ${resolved.effectiveLabel} · ${resolved.aiDiscretionEnabled ? 'AI Discretion ON' : 'Manual Lock'}`;
    if (ruleSpan) overseerDialTag.prepend(ruleSpan);
  }
  if (focusSelector) {
    root.querySelector(focusSelector)?.focus({ preventScroll: true });
  }
  restoreScrollPosition(scrollSnap);
}

function buildHighRiskDialConfirmation(scopeId, action, { tierId = null, targetBps = null, aiCeilingBps = null, preset = null } = {}) {
  return {
    phrase: 'CONFIRM_LIVE_HIGH_RISK_DIAL',
    scope: String(scopeId || 'dual-shield-barbell'),
    action: String(action || '').toUpperCase(),
    tier_id: tierId ? String(tierId).toUpperCase() : null,
    target_bps: typeof targetBps === 'number' ? targetBps : null,
    ai_ceiling_bps: typeof aiCeilingBps === 'number' ? aiCeilingBps : null,
    preset: preset ? String(preset).toUpperCase() : null,
  };
}

function submitAggressionDialMutation(payload, { debounceMs = 0, onHighRiskConflict = null } = {}) {
  if (!state.liveStreamConnected) return;
  if (!requireOwnerControlOrWarn('Aggression dial update')) return;
  if (dialDebounceTimer !== null) {
    window.clearTimeout(dialDebounceTimer);
    dialDebounceTimer = null;
  }
  const execPost = async () => {
    dialDebounceTimer = null;
    try {
      const res = await postLoopbackJson('/api/aggression-dial', payload);
      if (res && typeof res === 'object' && (res.schema === AGGRESSION_DIAL_SCHEMA || res.master_risk_bps !== undefined)) {
        state.aggressionDial = normalizeAggressionDial(res);
      } else {
        await readAggressionDial();
      }
      state.aiIssue = null;
      syncAggressionDialDom();
    } catch (error) {
      if (error?.status === 409 || error?.code === 'HIGH_RISK_CONFIRMATION_REQUIRED') {
        if (typeof onHighRiskConflict === 'function') onHighRiskConflict();
        return;
      }
      state.aiIssue = error instanceof Error ? error.message : 'Aggression dial update failed.';
      announce(state.aiIssue);
      await readAggressionDial();
      syncAggressionDialDom(null, true);
    }
  };
  if (debounceMs > 0) {
    dialDebounceTimer = window.setTimeout(() => { void execPost(); }, debounceMs);
  } else {
    void execPost();
  }
}

function applyMasterDialSelection(bps, focusSelector = null, debounceMs = 0, highRiskConfirmed = false) {
  if (state.liveStreamConnected && !requireOwnerControlOrWarn('Master aggression dial update')) return;
  const cur = resolveCockpitAggressionDial(state);
  const safeBps = clampRiskBps(bps, cur.masterRiskBps);
  if (cur.liveMode && safeBps >= HIGH_RISK_MIN_BPS && !highRiskConfirmed) {
    pendingDialPresetConfirm = null;
    state.aggressionDial = normalizeAggressionDial({
      ...cur,
      pendingHighRiskBps: safeBps,
      pendingHighRiskTierId: null,
      pendingAiDiscretionCeilingBps: null,
    });
    syncAggressionDialDom('[data-dial-confirm-high-risk="true"]', true);
    announce(`Confirm live high-risk ${safeBps / 100}% setting on Master Aggression Dial.`);
    return;
  }
  pendingDialPresetConfirm = null;
  state.aggressionDial = normalizeAggressionDial({
    ...cur,
    masterRiskBps: safeBps,
    effectiveRiskBps: cur.aiDiscretionEnabled ? Math.min(cur.aiDiscretionCeilingBps, Math.max(safeBps, cur.effectiveRiskBps)) : safeBps,
    pendingHighRiskBps: null,
    pendingHighRiskTierId: null,
    pendingAiDiscretionCeilingBps: null,
  });
  syncAggressionDialDom(focusSelector);
  submitAggressionDialMutation(
    {
      action: 'SET_MASTER_RISK_BPS',
      risk_bps: safeBps,
      high_risk_confirmed: Boolean(highRiskConfirmed),
      ...(highRiskConfirmed
        ? { high_risk_confirmation: buildHighRiskDialConfirmation(cur.scopeId, 'SET_MASTER_RISK_BPS', { targetBps: safeBps }) }
        : {}),
    },
    {
      debounceMs,
      onHighRiskConflict: () => applyMasterDialSelection(safeBps, focusSelector, 0, false),
    },
  );
}

function applyTierDialSelection(tierId, bps, focusSelector = null, debounceMs = 0, highRiskConfirmed = false) {
  if (state.liveStreamConnected && !requireOwnerControlOrWarn('Section B.5 tier dial update')) return;
  const cleanTierId = String(tierId || '').replace(/[^A-Z0-9_]/gi, '');
  if (!cleanTierId) return;
  const cur = resolveCockpitAggressionDial(state);
  const safeBps = clampRiskBps(bps, cur.masterRiskBps);
  if (cur.liveMode && safeBps >= HIGH_RISK_MIN_BPS && !highRiskConfirmed) {
    pendingDialPresetConfirm = null;
    state.aggressionDial = normalizeAggressionDial({
      ...cur,
      pendingHighRiskBps: safeBps,
      pendingHighRiskTierId: cleanTierId,
      pendingAiDiscretionCeilingBps: null,
    });
    syncAggressionDialDom('[data-dial-confirm-high-risk="true"]', true);
    announce(`Confirm live high-risk setting for ${cleanTierId}.`);
    return;
  }
  pendingDialPresetConfirm = null;
  state.aggressionDial = normalizeAggressionDial({
    ...cur,
    pendingHighRiskBps: null,
    pendingHighRiskTierId: null,
    pendingAiDiscretionCeilingBps: null,
    tiers: cur.tiers.map((t) => (
      t.tierId === cleanTierId ? { ...t, riskBps: safeBps, effectiveRiskBps: safeBps } : t
    )),
  });
  syncAggressionDialDom(focusSelector);
  submitAggressionDialMutation(
    {
      action: 'SET_TIER_RISK_BPS',
      tier_id: cleanTierId,
      risk_bps: safeBps,
      high_risk_confirmed: Boolean(highRiskConfirmed),
      ...(highRiskConfirmed
        ? { high_risk_confirmation: buildHighRiskDialConfirmation(cur.scopeId, 'SET_TIER_RISK_BPS', { tierId: cleanTierId, targetBps: safeBps }) }
        : {}),
    },
    {
      debounceMs,
      onHighRiskConflict: () => applyTierDialSelection(cleanTierId, safeBps, focusSelector, 0, false),
    },
  );
}

function applyAllTiersPresetSelection(presetId, focusSelector = null, highRiskConfirmed = false) {
  if (state.liveStreamConnected && !requireOwnerControlOrWarn('Section B.5 all-tier preset')) return;
  const cleanPreset = String(presetId || '').replace(/[^A-Z0-9_]/gi, '').toUpperCase();
  if (!cleanPreset) return;
  const cur = resolveCockpitAggressionDial(state);
  const nextPreview = applyAggressionDialPreset(cur, cleanPreset);
  const maxTierBps = Math.max(...nextPreview.tiers.map((t) => t.riskBps));
  if (cur.liveMode && maxTierBps >= HIGH_RISK_MIN_BPS && !highRiskConfirmed) {
    pendingDialPresetConfirm = cleanPreset;
    state.aggressionDial = normalizeAggressionDial({
      ...cur,
      pendingHighRiskBps: maxTierBps,
      pendingHighRiskTierId: null,
      pendingAiDiscretionCeilingBps: null,
    });
    syncAggressionDialDom('[data-dial-confirm-high-risk="true"]', true);
    announce(`Confirm live high-risk preset ${cleanPreset}.`);
    return;
  }
  pendingDialPresetConfirm = null;
  state.aggressionDial = normalizeAggressionDial({
    ...nextPreview,
    pendingHighRiskBps: null,
    pendingHighRiskTierId: null,
    pendingAiDiscretionCeilingBps: null,
  });
  syncAggressionDialDom(focusSelector);
  submitAggressionDialMutation({
    action: 'APPLY_TIER_PRESET',
    preset: cleanPreset,
    high_risk_confirmed: Boolean(highRiskConfirmed),
    ...(highRiskConfirmed
      ? { high_risk_confirmation: buildHighRiskDialConfirmation(cur.scopeId, 'APPLY_TIER_PRESET', { preset: cleanPreset }) }
      : {}),
  });
}

async function postLoopbackJson(pathname, payload) {
  const url = new URL(pathname, window.location.origin);
  if (url.origin !== window.location.origin || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Loopback action requires same-origin HTTP preview.');
  }
  const headers = { 'Content-Type': 'application/json' };
  if (loopbackAuthToken) headers.Authorization = `Bearer ${loopbackAuthToken}`;
  const response = await fetch(url, {
    method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(10000),
  });
  const raw = await response.text();
  const parsed = parseUniqueJSON(raw, MAX_AI_PAYLOAD_BYTES);
  if (!response.ok) {
    const err = new Error(parsed?.error || `Request failed (${response.status}).`);
    err.status = response.status;
    err.code = parsed?.code || null;
    throw err;
  }
  return parsed;
}

async function postTraderControlJson(payload) {
  try {
    return await postLoopbackJson('/api/ai-trader-control', payload);
  } catch (error) {
    if (error instanceof Error && /\b404\b/.test(error.message)) {
      return postLoopbackJson('/api/ai-overseer-action', payload);
    }
    throw error;
  }
}

async function advanceRecoverySession() {
  if (!requireOwnerControlOrWarn('Recovery session advance')) return;
  if (state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  rerenderAiSectionsInPlace('[data-ai-overseer-action="ADVANCE_RECOVERY_SESSION"]');
  try {
    const res = await postTraderControlJson({
      action: 'ADVANCE_RECOVERY_SESSION',
      reason: 'Owner recovery session advance',
    });
    if (res?.schema === 'cas-forex.ai-trader/1') state.aiTrader = normalizeAiTrader(res);
    else await readAiCockpitFeeds();
    announce('Recovery session advanced to next active leg.');
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Recovery session advance failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    rerenderAiSectionsInPlace('[data-open-voice-explainer="true"]');
  }
}

async function setSessionCadence(rawCadence) {
  if (!requireOwnerControlOrWarn('Session cadence update')) return;
  const cadence = String(rawCadence ?? '').trim().toUpperCase();
  if (!SESSION_CADENCE_MODES.includes(cadence) || state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  rerenderAiSectionsInPlace(`[data-ai-session-cadence="${cadence}"]`);
  try {
    const res = await postTraderControlJson({
      action: 'SET_SESSION_CADENCE',
      session_cadence: cadence,
      reason: 'Owner session cadence update',
    });
    if (res?.schema === 'cas-forex.ai-trader/1') state.aiTrader = normalizeAiTrader(res);
    else await readAiCockpitFeeds();
    announce(`Session cadence set to ${cadence}.`);
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Session cadence update failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    rerenderAiSectionsInPlace(`[data-ai-session-cadence="${cadence}"]`);
  }
}

async function sendOverseerAction(action) {
  if (!requireOwnerControlOrWarn(`Overseer action ${action}`)) return;
  if (state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  render();
  try {
    const res = await postLoopbackJson('/api/ai-overseer-action', { action });
    if (res?.schema === 'cas-forex.ai-models/1') state.aiModels = normalizeAiModels(res);
    else await readAiCockpitFeeds();
    announce(`Overseer action ${action} applied.`);
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Overseer action failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    render();
  }
}

async function setRiskGearMode(riskGear) {
  if (!requireOwnerControlOrWarn('Risk gear update')) return;
  if (state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  render();
  try {
    const res = await postLoopbackJson('/api/ai-overseer-action', { action: 'SET_RISK_GEAR', risk_gear: riskGear });
    if (res?.schema === 'cas-forex.ai-trader/1') state.aiTrader = normalizeAiTrader(res);
    else await readAiCockpitFeeds();
    announce(`Risk gear set to ${riskGear}.`);
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Risk gear update failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    render();
  }
}

async function setThinkingDepth(depth) {
  if (!requireOwnerControlOrWarn('Thinking depth update')) return;
  if (state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  render();
  try {
    const res = await postLoopbackJson('/api/thinking-depth', { thinking_depth: depth });
    state.aiModels = normalizeAiModels(res);
    await readAiCockpitFeeds();
    announce(`Thinking depth set to ${depth}.`);
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Thinking depth update failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    render();
  }
}

async function updateTreasuryConfig(patch) {
  if (!requireOwnerControlOrWarn('Treasury configuration update')) return;
  if (state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  render();
  try {
    const res = await postLoopbackJson('/api/treasury-config', patch);
    state.treasury = normalizeTreasury(res);
    announce('Profit-Sweep Bank Vault configuration updated.');
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Treasury config update failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    render();
  }
}

async function selectAiModel(modelId) {
  if (!requireOwnerControlOrWarn('AI model switch')) return;
  if (state.aiActionBusy) return;
  state.aiActionBusy = true;
  state.aiIssue = null;
  render();
  try {
    const res = await postLoopbackJson('/api/select-ai-model', { model_id: modelId });
    state.aiModels = normalizeAiModels(res);
    await readAiCockpitFeeds();
    announce(`Active AI model switched to ${modelId}.`);
  } catch (error) {
    state.aiIssue = error instanceof Error ? error.message : 'Model switch failed.';
    announce(state.aiIssue);
  } finally {
    state.aiActionBusy = false;
    render();
  }
}

async function readTransport() {
  if (!controller?.attached) throw new Error('Transport unavailable.');
  await controller.refresh();
  await readBridgeReview();
  await readBridgeMarketStream();
}

function report(promise) {
  void promise.catch((error) => announce(error instanceof Error ? error.message : 'Request unavailable. No effect established.'));
}

function transportClick(target) {
  if (target.dataset.detachTransport) { detachTransport(); return true; }
  if (target.dataset.readTransport) { report(readTransport()); return true; }
  if (target.dataset.requestControl) { report(controller ? controller.control(target.dataset.requestControl) : Promise.reject(new Error('Transport unavailable.'))); return true; }
  if (target.dataset.readControl) { report(controller.checkControl(target.dataset.readControl)); return true; }
  if (target.dataset.readClose) { report(controller.checkClose()); return true; }
  if (target.dataset.submitClose) { report(controller.submitClose(target.dataset.submitClose)); return true; }
  if (target.dataset.inspectClose) { dialogContext = 'prepared'; openDialog(renderPreparedClose(state.transport), target); return true; }
  return false;
}

function beginLoad() {
  const generation = ++loadGeneration;
  reviewGeneration += 1;
  if (dialog.open) dialog.close();
  state = { ...state, projection: null, source: 'none', loadedAt: null, error: null, loading: true, inspection: resetInspection(), reviewEnvelope: null, reviewIssue: null };
  render();
  return generation;
}

function failLoad(generation, error) {
  if (generation !== loadGeneration) return;
  state = { ...state, projection: null, source: 'none', loadedAt: null, error: error instanceof Error ? error.message : 'Snapshot could not be read.', loading: false };
  render();
  announce('Snapshot unavailable. No current data is displayed.');
}

function acceptSnapshot(generation, raw, source) {
  if (generation !== loadGeneration) return;
  const projection = decodeCockpit(raw, sharedSchema);
  state = { ...state, projection, source, loadedAt: new Date().toISOString(), schemaReady: true, error: null, loading: false, inspection: resetInspection() };
  state.lastLoaded = { projection, source, loadedAt: state.loadedAt };
  render();
  announce('Disconnected snapshot loaded for inspection. No request was sent.');
}

async function readStatic(url, maximumBytes = MAX_SNAPSHOT_BYTES) {
  if (url.origin !== window.location.origin || !['http:', 'https:'].includes(url.protocol)) throw new Error('Static assets require an approved same-origin HTTP preview. File-URL loading is unavailable.');
  const isApi = url.pathname === '/api' || url.pathname.startsWith('/api/');
  const headers = isApi && loopbackAuthToken ? { Authorization: `Bearer ${loopbackAuthToken}` } : {};
  const response = await fetch(url, { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', headers, signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`Shared static asset unavailable (${response.status}).`);
  if (Number(response.headers.get('content-length')) > maximumBytes) throw new Error('Shared static asset exceeds the display size limit.');
  if (!response.body) throw new Error('Shared static asset has no readable body.');
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let length = 0;
  let result = '';
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) throw new Error('Shared static asset exceeds the display size limit.');
      result += decoder.decode(value, { stream: true });
    }
    return result + decoder.decode();
  } finally { await reader.cancel(); }
}

async function loadFixture() {
  if (controller?.attached) return;
  const generation = beginLoad();
  try {
    // Path resolution is from ui/index.html, so one parent reaches the canonical root.
    const schemaRaw = await readStatic(schemaURL);
    if (generation !== loadGeneration) return;
    sharedSchema = parseUniqueJSON(schemaRaw);
    state.schemaReady = sharedSchema?.$id === 'urn:cas-forex:cockpit:1.0';
    const raw = await readStatic(fixtureURL);
    if (generation !== loadGeneration) return;
    acceptSnapshot(generation, raw, 'shared fixture');
    await loadReviewFixture(generation);
    try {
      marketSchema = parseUniqueJSON(await readStatic(marketSchemaURL));
      const mRaw = await readStatic(marketFixtureURL, MAX_MARKET_STREAM_BYTES);
      if (generation === loadGeneration) { state.marketStream = decodeMarketStream(mRaw, marketSchema); render(); }
    } catch { /* Market stream fixture optional. */ }
  } catch (error) { failLoad(generation, error); }
}

async function loadReviewFixture(cockpitGeneration) {
  if (cockpitGeneration !== loadGeneration) return;
  const generation = ++reviewGeneration;
  try {
    const schemaRaw = await readStatic(reviewSchemaURL);
    if (cockpitGeneration !== loadGeneration || generation !== reviewGeneration) return;
    reviewSchema = parseUniqueJSON(schemaRaw);
    rawReviewSchema = schemaRaw;
    state.reviewSchemaReady = reviewSchema?.$id === 'urn:cas-forex:decision-read:0.1';
    const raw = await readStatic(reviewFixtureURL, MAX_REVIEW_BYTES);
    const read = await decodeDecisionRead(raw, reviewSchema, state.projection);
    if (cockpitGeneration !== loadGeneration || generation !== reviewGeneration) return;
    state.reviewEnvelope = read;
    state.reviewIssue = null;
    state.inspection = resetInspection();
    render();
  } catch (error) {
    if (cockpitGeneration !== loadGeneration || generation !== reviewGeneration) return;
    state.reviewEnvelope = null;
    state.reviewIssue = error.message;
    render();
  }
}

function openDialog(html, trigger) {
  dialogTrigger = trigger;
  replaceSafeHTML(dialog, html);
  dialog.showModal();
  dialog.querySelector('[data-dialog-close]')?.focus({ preventScroll: true });
}

root.addEventListener('click', (event) => {
  const target = event.target.closest('button');
  if (!target || target.disabled) return;
  if (transportClick(target)) return;
  if (target.dataset.connectLoopback) { report(connectLoopbackLiveFeed()); return; }
  if (target.dataset.disconnectLoopback) { stopLoopbackStream(); render(); announce('Live market stream paused.'); return; }
  if (target.dataset.openVoiceExplainer) {
    explainer?.open?.({ focusPrompt: true });
    return;
  }
  if (target.dataset.toggleUnlockVisibility) {
    const nextVis = !state.unlockKeyVisible;
    state.unlockKeyVisible = nextVis;
    for (const inp of root.querySelectorAll('input[name="cockpit_access_key"]')) {
      inp.type = nextVis ? 'text' : 'password';
    }
    for (const btn of root.querySelectorAll('[data-toggle-unlock-visibility="true"]')) {
      btn.textContent = nextVis ? 'Hide' : 'Show';
      btn.setAttribute('aria-pressed', String(nextVis));
    }
    target.focus({ preventScroll: true });
    return;
  }
  if (target.dataset.toggleQrPairing) {
    if (state.qrPairingOpen) {
      closeQrPairingDrawer(true);
      announce('Pairing QR hidden.');
      return;
    }
    if (!state.liveStreamConnected || !loopbackAuthToken || !isOwnerControlSession(state)) {
      requireOwnerControlOrWarn('Device QR pairing');
      return;
    }
    void (async () => {
      try {
        const res = await postLoopbackJson('/api/pair-code', {});
        const minted = normalizePairCodeMintResponse(res, loopbackAuthToken);
        activePairCode = minted.pairCode;
        const pairUrl = buildPairingUrl(window.location.origin, activePairCode);
        const svg = renderQrSvg(pairUrl, { ariaLabel: 'Scan with tablet or phone camera for single-use Read and Explainer pairing' });
        if (qrAutoCloseTimer !== null) window.clearTimeout(qrAutoCloseTimer);
        state = {
          ...state,
          aiIssue: null,
          qrPairingOpen: true,
          qrPairingSvg: svg,
          qrPairingCopiedNotice: null,
          qrPairingExpiresAt: minted.expiresAt,
          qrPairingTtlSeconds: minted.ttlSeconds,
          qrPairingScope: minted.scope,
        };
        qrAutoCloseTimer = window.setTimeout(() => {
          qrAutoCloseTimer = null;
          closeQrPairingDrawer(true);
          announce(`Pairing QR auto-closed after ${minted.ttlSeconds} seconds.`);
        }, minted.ttlSeconds * 1000);
        render();
        announce(`Single-use device pairing QR opened (${minted.ttlSeconds}s server expiry).`);
      } catch (error) {
        activePairCode = null;
        state.aiIssue = error instanceof Error ? error.message : 'Unable to mint single-use pairing QR.';
        render();
        announce(state.aiIssue);
      }
    })();
    return;
  }
  if (target.dataset.copyUnlockLink) {
    if (!activePairCode || !isOwnerControlSession(state)) {
      state.qrPairingCopiedNotice = 'Pairing code expired — reopen QR to mint a fresh single-use code.';
      render();
      announce(state.qrPairingCopiedNotice);
      return;
    }
    void (async () => {
      try {
        const pairUrl = buildPairingUrl(window.location.origin, activePairCode);
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(pairUrl);
          state.qrPairingCopiedNotice = 'Single-use pairing link (?pair_code=...) copied to clipboard.';
        } else {
          state.qrPairingCopiedNotice = 'Clipboard unavailable in this browser — scan the QR square above.';
        }
      } catch {
        state.qrPairingCopiedNotice = 'Could not copy automatically — scan the QR square above.';
      }
      render();
      announce(state.qrPairingCopiedNotice);
    })();
    return;
  }
  if (target.dataset.revokeQrPairing) {
    if (!state.liveStreamConnected || !loopbackAuthToken || !isOwnerControlSession(state)) {
      requireOwnerControlOrWarn('Pairing revocation');
      return;
    }
    const codeToRevoke = activePairCode;
    void (async () => {
      let notice = 'Pairing code and paired device sessions revoked on server.';
      try {
        const payload = codeToRevoke
          ? { pair_code: codeToRevoke, revoke_sessions: true }
          : { revoke_sessions: true };
        const res = await postLoopbackJson('/api/pair-revoke', payload);
        const rc = Number.isSafeInteger(res?.revoked_codes) ? res.revoked_codes : 0;
        const rs = Number.isSafeInteger(res?.revoked_sessions) ? res.revoked_sessions : 0;
        notice = `Server revoked ${rc} pairing code(s) and ${rs} paired device session(s).`;
        state.aiIssue = null;
      } catch (error) {
        notice = error instanceof Error ? error.message : 'Pairing revocation failed.';
        state.aiIssue = notice;
      } finally {
        closeQrPairingDrawer(false);
        render();
        announce(notice);
      }
    })();
    return;
  }
  if (target.dataset.dhgAction === 'TOGGLE_ENABLED') {
    if (state.liveStreamConnected && !isStrictOwnerCompoundingSession()) {
      requireOwnerControlOrWarn('DEMO High-Growth Practice Profile toggle');
      syncDemoHighGrowthDom();
      return;
    }
    const cur = resolveCockpitDemoHighGrowth(state);
    if (cur.liveModeBlocked || !cur.ownerControlsAllowed) return;
    const nextEnabled = !cur.enabled;
    state.demoHighGrowth = normalizeDemoHighGrowth({ ...cur, enabled: nextEnabled });
    syncDemoHighGrowthDom('[data-dhg-action="TOGGLE_ENABLED"]');
    void submitDemoHighGrowthMutation({ enabled: nextEnabled }, '[data-dhg-action="TOGGLE_ENABLED"]');
    return;
  }
  if (target.dataset.compoundingAction === 'TOGGLE_FULL_100') {
    if (state.liveStreamConnected && !isStrictOwnerCompoundingSession()) {
      requireOwnerControlOrWarn('Compounding mode toggle');
      syncCompoundingDom();
      return;
    }
    const cur = resolveCockpitCompounding(state);
    if (!cur.ownerControlsAllowed) return;
    const nextMode = cur.isFullCompound ? 'BALANCED_SPLIT_50_50' : 'FULL_COMPOUND_100';
    state.compounding = normalizeCompoundingPanel({
      ...cur,
      mode: nextMode,
      effectiveVaultSweepRatio: null,
    });
    syncCompoundingDom('[data-compounding-action="TOGGLE_FULL_100"]');
    void submitCompoundingMutation(
      { action: 'set_mode', mode: nextMode },
      '[data-compounding-action="TOGGLE_FULL_100"]',
    );
    return;
  }
  if (target.dataset.compoundingAction === 'ACK_PRINCIPAL_WITHDRAWN') {
    if (state.liveStreamConnected && !isStrictOwnerCompoundingSession()) {
      requireOwnerControlOrWarn('Acknowledge principal withdrawn');
      syncCompoundingDom();
      return;
    }
    const cur = resolveCockpitCompounding(state);
    if (!cur.houseMoneyReady || !cur.ownerControlsAllowed) return;
    const pulloutUsd = compareDecimalStrings(cur.suggestedPrincipalPulloutUsd, '0.00') > 0
      ? normalizeDecimalString(cur.suggestedPrincipalPulloutUsd, cur.startingPrincipalUsd, 2)
      : normalizeDecimalString(cur.startingPrincipalUsd, '5000.00', 2);
    state.compounding = normalizeCompoundingPanel({
      ...cur,
      houseMoneyStatus: 'PLAYING_ON_HOUSE_MONEY',
      houseMoneyReady: false,
      principalWithdrawnAcknowledged: true,
      principalWithdrawnUsd: pulloutUsd,
      suggestedPrincipalPulloutUsd: '0.00',
    });
    syncCompoundingDom('[data-compounding-field="modeSwitch"]');
    void submitCompoundingMutation(
      { action: 'acknowledge_principal_withdrawn', amount_usd: pulloutUsd },
      '[data-compounding-field="modeSwitch"]',
    );
    return;
  }
  if (target.dataset.dialMarketMode) {
    if (state.liveStreamConnected && !requireOwnerControlOrWarn('Market mode preview')) return;
    const cur = resolveCockpitAggressionDial(state);
    if (!cur.ownerControlsAllowed) return;
    const modeId = String(target.dataset.dialMarketMode || '').replace(/[^A-Z_]/gi, '').toUpperCase();
    if (!modeId) return;
    state.aggressionDial = applyMarketConditionPreview(cur, modeId);
    syncAggressionDialDom(`[data-dial-market-mode="${modeId}"]`);
    return;
  }
  if (target.dataset.dialAction === 'TOGGLE_AI_DISCRETION') {
    if (state.liveStreamConnected && !requireOwnerControlOrWarn('AI Discretion toggle')) return;
    const cur = resolveCockpitAggressionDial(state);
    const nextEnabled = !cur.aiDiscretionEnabled;
    if (cur.liveMode && nextEnabled && cur.aiDiscretionCeilingBps >= HIGH_RISK_MIN_BPS) {
      pendingDialPresetConfirm = null;
      state.aggressionDial = normalizeAggressionDial({
        ...cur,
        pendingAiDiscretionCeilingBps: cur.aiDiscretionCeilingBps,
        pendingHighRiskBps: null,
        pendingHighRiskTierId: null,
      });
      syncAggressionDialDom('[data-dial-confirm-high-risk="true"]', true);
      announce('Confirm live AI Discretion high-risk ceiling.');
      return;
    }
    pendingDialPresetConfirm = null;
    state.aggressionDial = normalizeAggressionDial({
      ...cur,
      aiDiscretionEnabled: nextEnabled,
      pendingHighRiskBps: null,
      pendingHighRiskTierId: null,
      pendingAiDiscretionCeilingBps: null,
    });
    syncAggressionDialDom('[data-dial-action="TOGGLE_AI_DISCRETION"]');
    submitAggressionDialMutation({
      action: 'SET_AI_DISCRETION',
      ai_discretion_enabled: nextEnabled,
      high_risk_confirmed: false,
    });
    return;
  }
  if (target.dataset.dialMasterPreset) {
    const bps = clampRiskBps(target.dataset.dialMasterPreset);
    applyMasterDialSelection(bps, `[data-dial-master-preset="${bps}"]`, 0, false);
    return;
  }
  if (target.dataset.dialTierBps) {
    const tierId = String(target.dataset.dialTierId || '').replace(/[^A-Z0-9_]/gi, '');
    const bps = clampRiskBps(target.dataset.dialTierBps);
    applyTierDialSelection(tierId, bps, `[data-dial-tier-id="${tierId}"][data-dial-tier-bps="${bps}"]`, 0, false);
    return;
  }
  if (target.dataset.dialTierPreset) {
    const presetId = String(target.dataset.dialTierPreset || '').replace(/[^A-Z0-9_]/gi, '').toUpperCase();
    applyAllTiersPresetSelection(presetId, `[data-dial-tier-preset="${presetId}"]`, false);
    return;
  }
  if (target.dataset.dialConfirmHighRisk) {
    if (state.liveStreamConnected && !requireOwnerControlOrWarn('High-risk aggression confirmation')) return;
    const kind = String(target.dataset.dialConfirmKind || 'bps');
    const confirmBps = clampRiskBps(target.dataset.dialConfirmBps);
    const confirmTierId = String(target.dataset.dialConfirmTierId || '').replace(/[^A-Z0-9_]/gi, '');
    if (pendingDialPresetConfirm) {
      const presetToRun = pendingDialPresetConfirm;
      pendingDialPresetConfirm = null;
      applyAllTiersPresetSelection(presetToRun, `[data-dial-tier-preset="${presetToRun}"]`, true);
      return;
    }
    if (kind === 'ai-ceiling') {
      const cur = resolveCockpitAggressionDial(state);
      state.aggressionDial = normalizeAggressionDial({
        ...cur,
        aiDiscretionEnabled: true,
        aiDiscretionCeilingBps: confirmBps,
        pendingHighRiskBps: null,
        pendingHighRiskTierId: null,
        pendingAiDiscretionCeilingBps: null,
      });
      syncAggressionDialDom('[data-dial-action="TOGGLE_AI_DISCRETION"]', true);
      submitAggressionDialMutation({
        action: 'SET_AI_DISCRETION',
        ai_discretion_enabled: true,
        ai_discretion_ceiling_bps: confirmBps,
        high_risk_confirmed: true,
        high_risk_confirmation: buildHighRiskDialConfirmation(cur.scopeId, 'SET_AI_DISCRETION', { aiCeilingBps: confirmBps }),
      });
      return;
    }
    if (confirmTierId) {
      applyTierDialSelection(confirmTierId, confirmBps, `[data-dial-tier-slider="${confirmTierId}"]`, 0, true);
      return;
    }
    applyMasterDialSelection(confirmBps, '[data-dial-master-slider="true"]', 0, true);
    return;
  }
  if (target.dataset.dialCancelHighRisk) {
    const cur = resolveCockpitAggressionDial(state);
    pendingDialPresetConfirm = null;
    state.aggressionDial = normalizeAggressionDial({
      ...cur,
      pendingHighRiskBps: null,
      pendingHighRiskTierId: null,
      pendingAiDiscretionCeilingBps: null,
    });
    syncAggressionDialDom('[data-dial-master-slider="true"]', true);
    announce('High-risk aggression change cancelled.');
    return;
  }
  if (target.dataset.aiOverseerAction === 'ADVANCE_RECOVERY_SESSION') {
    void advanceRecoverySession();
    return;
  }
  if (target.dataset.aiSessionCadence) {
    void setSessionCadence(target.dataset.aiSessionCadence);
    return;
  }
  if (target.dataset.aiOverseerAction) { void sendOverseerAction(target.dataset.aiOverseerAction); return; }
  if (target.dataset.riskGear) { void setRiskGearMode(target.dataset.riskGear); return; }
  if (target.dataset.lfCap) {
    const cap = clampLiveCapitalUsd(target.dataset.lfCap);
    const nextLf = { ...state.liveFunding, capitalUsd: cap };
    if (nextLf.verifyResult) nextLf.verifyResult = evaluateLiveArmingPreflight(nextLf, state.brokerRouting);
    state.liveFunding = nextLf;
    rerenderLiveFundingInPlace(`[data-lf-cap="${cap}"]`);
    return;
  }
  if (target.dataset.lfVerify) {
    const phraseEl = root.querySelector('[data-lf-phrase-input="true"]');
    const currentPhrase = phraseEl ? String(phraseEl.value ?? '') : state.liveFunding.armPhraseInput;
    state.liveFunding = { ...state.liveFunding, armPhraseInput: currentPhrase };
    const finishVerify = () => {
      const res = evaluateLiveArmingPreflight(state.liveFunding, state.brokerRouting);
      state.liveFunding = { ...state.liveFunding, verifyResult: res };
      rerenderLiveFundingInPlace('[data-lf-verify="true"]');
      announce(res.headline);
    };
    if (state.liveStreamConnected) void readBrokerRouting().finally(finishVerify);
    else finishVerify();
    return;
  }
  if (target.dataset.mfTab) {
    const nextTab = target.dataset.mfTab === 'lots' ? 'lots' : 'flow';
    state.moneyFlow = { ...state.moneyFlow, tab: nextTab };
    rerenderMoneyFlowInPlace(`[data-mf-tab="${nextTab}"]`);
    return;
  }
  if (target.dataset.mfSplit) {
    const nextSplit = target.dataset.mfSplit === '100_COMPOUND' ? '100_COMPOUND' : '50_50';
    state.moneyFlow = { ...state.moneyFlow, splitMode: nextSplit };
    rerenderMoneyFlowInPlace(`[data-mf-split="${nextSplit}"]`);
    return;
  }
  if (target.dataset.mfCap) {
    const cap = clampCapitalUsd(target.dataset.mfCap);
    state.moneyFlow = { ...state.moneyFlow, capitalUsd: cap, simWins: 0, simLosses: 0, simCapitalCents: cap * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace(`[data-mf-cap="${cap}"]`);
    return;
  }
  if (target.dataset.mfLiveBalance) {
    const cap = resolveLiveAccountBalanceUsd(state);
    state.moneyFlow = { ...state.moneyFlow, capitalUsd: cap, simWins: 0, simLosses: 0, simCapitalCents: cap * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace('[data-mf-live-balance="true"]');
    return;
  }
  if (target.dataset.mfMarket) {
    const safeMkt = String(target.dataset.mfMarket).replace(/[^A-Z0-9_]/gi, '');
    state.moneyFlow = { ...state.moneyFlow, market: safeMkt, simWins: 0, simLosses: 0, simCapitalCents: state.moneyFlow.capitalUsd * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace(`[data-mf-market="${safeMkt}"]`);
    return;
  }
  if (target.dataset.mfRisk) {
    const pct = Math.max(0.25, Math.min(1, Number(target.dataset.mfRisk) || 1));
    state.moneyFlow = { ...state.moneyFlow, lotMode: 'risk', riskPct: pct, simWins: 0, simLosses: 0, simCapitalCents: state.moneyFlow.capitalUsd * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace(`[data-mf-risk="${pct}"]`);
    return;
  }
  if (target.dataset.mfLot) {
    const safeLot = String(target.dataset.mfLot).replace(/[^0-9.]/g, '');
    const hund = clampLotHundredths(safeLot);
    state.moneyFlow = { ...state.moneyFlow, lotMode: 'direct', directLotHundredths: hund, simWins: 0, simLosses: 0, simCapitalCents: state.moneyFlow.capitalUsd * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace(`[data-mf-lot="${safeLot}"]`);
    return;
  }
  if (target.dataset.mfStep) {
    const safeStep = String(target.dataset.mfStep).replace(/[^a-z0-9]/gi, '');
    const maxRisk = Math.min(1, Number(state.aiTrader?.riskGear?.ownerMaxRiskPct ?? 1) || 1);
    state.moneyFlow = stepMoneyFlowSimulation(state.moneyFlow, safeStep, maxRisk);
    rerenderMoneyFlowInPlace(`[data-mf-step="${safeStep}"]`);
    return;
  }
  if (target.dataset.chartPair && ALL_WATCHLIST_MARKETS.includes(target.dataset.chartPair)) {
    state.chartPair = target.dataset.chartPair; render();
    root.querySelector(`[data-chart-pair="${state.chartPair}"]`)?.focus({ preventScroll: true }); return;
  }
  if (target.dataset.chartTf && CHART_TIMEFRAMES.includes(target.dataset.chartTf)) {
    state.chartTimeframe = target.dataset.chartTf; render();
    root.querySelector(`[data-chart-tf="${state.chartTimeframe}"]`)?.focus({ preventScroll: true }); return;
  }
  if (target.dataset.chartLayout && CHART_LAYOUTS.includes(target.dataset.chartLayout)) {
    state.chartLayout = target.dataset.chartLayout; render();
    root.querySelector(`[data-chart-layout="${state.chartLayout}"]`)?.focus({ preventScroll: true }); return;
  }
  if (target.dataset.chartCat && ['all', 'US_INDEX', 'MAJOR', 'CROSS'].includes(target.dataset.chartCat)) {
    state.chartCategory = target.dataset.chartCat; render();
    root.querySelector(`[data-chart-cat="${state.chartCategory}"]`)?.focus({ preventScroll: true }); return;
  }
  if (target.dataset.chartZoom) {
    const z = target.dataset.chartZoom;
    if (z === 'reset') state.chartZoomBars = 60;
    else if (z === 'in') state.chartZoomBars = Math.max(20, (state.chartZoomBars ?? 60) - 15);
    else if (z === 'out') state.chartZoomBars = Math.min(200, (state.chartZoomBars ?? 60) + 15);
    render(); return;
  }
  if (target.dataset.thinkingDepth) {
    void setThinkingDepth(target.dataset.thinkingDepth); return;
  }
  if (target.dataset.treasuryRail) {
    void updateTreasuryConfig({ preferred_rail: target.dataset.treasuryRail }); return;
  }
  if (target.dataset.treasuryAction === 'TOGGLE_AUTO_SWEEP') {
    const nextAuto = !(state.treasury?.autoSweepEnabled ?? true);
    void updateTreasuryConfig({ auto_sweep_enabled: nextAuto }); return;
  }
  if (target.dataset.inspectTrade) {
    state.inspectedTradeIdx = Math.max(0, Number(target.dataset.inspectTrade) || 0);
    rerenderAnalyticsInPlace(`[data-inspect-trade="${state.inspectedTradeIdx}"]`);
    return;
  }
  if (target.dataset.route) { window.location.hash = target.dataset.route; return; }
  if (target.dataset.control) { dialogContext = target.dataset.control; openDialog(renderControlDialog(target.dataset.control, state.transport), target); return; }
  if (target.dataset.close && state.projection) {
    if (controller?.attached) {
      if (!controller.canClose()) { announce('Another Close has an unresolved outcome, or current owner capability is unavailable. Inspect its request or read current state.'); return; }
      const pending = controller.prepareClose(target.dataset.close);
      dialogContext = 'prepared'; openDialog(renderPreparedClose(state.transport), target); report(pending);
    } else { dialogContext = null; openDialog(renderCloseDialog(state.projection, target.dataset.close), target); }
    return;
  }
  if (target.dataset.reload) { void loadFixture(); return; }
  if (target.dataset.restoreLast && state.lastLoaded && !controller?.attached) {
    loadGeneration += 1; reviewGeneration += 1;
    state = { ...state, ...state.lastLoaded, source: 'historical snapshot', error: null, loading: false, reviewEnvelope: null, reviewIssue: 'Last loaded snapshot restored for historical inspection only.', inspection: resetInspection() };
    render(); announce('Last loaded snapshot restored. Historical inspection only.'); return;
  }
  if (target.dataset.themeToggle) {
    const dark = state.theme === 'dark' || (state.theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    state.theme = dark ? 'light' : 'dark';
    render();
    root.querySelector('[data-theme-toggle]')?.focus({ preventScroll: true });
  }
  if (target.dataset.reviewFilter) {
    if (!['all', 'decisions', 'events', 'evidence'].includes(target.dataset.reviewFilter)) return;
    state.reviewFilter = target.dataset.reviewFilter;
    state.inspection = resetInspection();
    render();
    root.querySelector(`[data-review-filter="${state.reviewFilter}"]`)?.focus({ preventScroll: true });
    announce('Record filter changed. Source state and coverage are unchanged.');
    return;
  }
  if (target.dataset.view) {
    state.reviewView = target.dataset.view === 'atlas' ? 'atlas' : 'list';
    render();
    root.querySelector(`[data-view="${state.reviewView}"]`)?.focus({ preventScroll: true });
    announce(`${state.reviewView === 'atlas' ? 'Atlas' : 'List'} view. Same supplied records.`);
  }
  if (target.dataset.record && state.projection) {
    state.inspection = inspectRecord(state.inspection, target.dataset.record, state.reviewEnvelope ? envelopeRecords(state.reviewEnvelope) : reviewRecords(state.projection));
    render();
    [...root.querySelectorAll('[data-record]')].find((node) => node.dataset.record === state.inspection.focus_node_id)?.focus({ preventScroll: true });
    announce('Inspection focus changed. Source state is unchanged.');
  }
});

root.addEventListener('submit', async (event) => {
  const form = event.target?.closest?.('[data-cockpit-unlock-form]');
  if (!form) return;
  event.preventDefault();
  const input = form.querySelector('input[name="cockpit_access_key"]');
  const val = String(input?.value || state.unlockDraft || '').trim();
  if (!val) { state.aiIssue = 'Enter your 43-character Cockpit access key to unlock live feeds.'; render(); return; }
  try {
    setLoopbackAuthToken(val);
    state.unlockDraft = '';
    state.unlockKeyVisible = false;
    state.aiIssue = null;
    if (input) input.value = '';
    await connectLoopbackLiveFeed();
  } catch (error) {
    state.unlockDraft = val;
    state.aiIssue = error instanceof Error ? error.message : 'Cockpit unlock failed.';
    render();
  }
});

root.addEventListener('input', (event) => {
  if (event.target?.name === 'cockpit_access_key') {
    state.unlockDraft = String(event.target.value ?? '');
    return;
  }
  if (event.target?.dataset?.dialMasterSlider) {
    applyMasterDialSelection(clampRiskBps(event.target.value), null, 140, false);
    return;
  }
  if (event.target?.dataset?.dialTierSlider) {
    applyTierDialSelection(event.target.dataset.dialTierSlider, clampRiskBps(event.target.value), null, 140, false);
    return;
  }
  if (event.target?.dataset?.lfPhraseInput) {
    state.liveFunding = { ...state.liveFunding, armPhraseInput: String(event.target.value ?? '') };
  }
});

root.addEventListener('change', async (event) => {
  if (event.target?.dataset?.dialMasterSlider) {
    applyMasterDialSelection(clampRiskBps(event.target.value), null, 0, false);
    return;
  }
  if (event.target?.dataset?.dialTierSlider) {
    applyTierDialSelection(event.target.dataset.dialTierSlider, clampRiskBps(event.target.value), null, 0, false);
    return;
  }
  if (event.target?.dataset?.lfCustomCap) {
    const cap = clampLiveCapitalUsd(event.target.value);
    const nextLf = { ...state.liveFunding, capitalUsd: cap };
    if (nextLf.verifyResult) nextLf.verifyResult = evaluateLiveArmingPreflight(nextLf, state.brokerRouting);
    state.liveFunding = nextLf;
    rerenderLiveFundingInPlace('[data-lf-custom-cap="true"]');
    return;
  }
  if (event.target?.dataset?.lfPhraseInput) {
    const nextPhrase = String(event.target.value ?? '');
    const nextLf = { ...state.liveFunding, armPhraseInput: nextPhrase };
    if (nextLf.verifyResult) nextLf.verifyResult = evaluateLiveArmingPreflight(nextLf, state.brokerRouting);
    state.liveFunding = nextLf;
    rerenderLiveFundingInPlace('[data-lf-phrase-input="true"]');
    return;
  }
  if (event.target?.dataset?.mfCustomCap) {
    const cap = clampCapitalUsd(event.target.value);
    state.moneyFlow = { ...state.moneyFlow, capitalUsd: cap, simWins: 0, simLosses: 0, simCapitalCents: cap * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace('[data-mf-custom-cap="true"]');
    return;
  }
  if (event.target?.dataset?.mfCustomLot) {
    const hund = clampLotHundredths(event.target.value);
    state.moneyFlow = { ...state.moneyFlow, lotMode: 'direct', directLotHundredths: hund, simWins: 0, simLosses: 0, simCapitalCents: state.moneyFlow.capitalUsd * 100, simBankCents: 0 };
    rerenderMoneyFlowInPlace('[data-mf-custom-lot="true"]');
    return;
  }
  if (event.target.dataset?.selectAiModel) { void selectAiModel(event.target.value); return; }
  if (event.target.name === 'theme') {
    const theme = event.target.value;
    if (!['system', 'light', 'dark'].includes(theme)) return;
    state.theme = theme;
    render();
    root.querySelector(`input[name="theme"][value="${theme}"]`)?.focus({ preventScroll: true });
  }
  if (event.target.id === 'decision-file') {
    if (controller?.attached) return;
    const file = event.target.files?.[0];
    if (!file || !state.projection) return;
    const generation = ++reviewGeneration;
    const cockpitGeneration = loadGeneration;
    state.reviewEnvelope = null;
    state.inspection = resetInspection();
    state.reviewIssue = 'Reading decision records. Prior inspection has been cleared.';
    render();
    try {
      if (file.size > MAX_REVIEW_BYTES) throw new Error('Decision-read page exceeds 1 MiB.');
      const raw = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      const read = await decodeDecisionRead(raw, reviewSchema, state.projection);
      if (generation !== reviewGeneration || cockpitGeneration !== loadGeneration) return;
      state.reviewEnvelope = read; state.reviewIssue = null;
      render(); announce('Decision records loaded. Source remains unverified. Inspection focus cleared.');
    } catch (error) {
      if (generation !== reviewGeneration || cockpitGeneration !== loadGeneration) return;
      state.reviewIssue = error.message; render(); announce('Decision-read page rejected. Cockpit records remain available.');
    }
    return;
  }
  if (event.target.id !== 'snapshot-file') return;
  if (controller?.attached) return;
  const file = event.target.files?.[0];
  if (!file) return;
  const generation = beginLoad();
  try {
    if (!sharedSchema) throw new Error('Shared cockpit schema must be read first.');
    if (file.size > MAX_SNAPSHOT_BYTES) throw new Error('Snapshot exceeds the 512 KiB display limit.');
    const raw = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    acceptSnapshot(generation, raw, 'local snapshot');
  } catch (error) { failLoad(generation, error); }
});

dialog.addEventListener('click', (event) => {
  const target = event.target.closest('button');
  if (!target || target.disabled) return;
  if (target.dataset.dialogClose) { dialog.close(); return; }
  transportClick(target);
});
dialog.addEventListener('close', () => {
  if (dialogTrigger?.isConnected) dialogTrigger.focus({ preventScroll: true });
  else document.querySelector('#main')?.focus({ preventScroll: true });
  dialogTrigger = null;
  dialogContext = null;
  dialog.replaceChildren();
});
window.addEventListener('hashchange', () => {
  if (dialog.open) dialog.close();
  closeQrPairingDrawer(false);
  state.route = routeFromHash();
  render(true);
});

root.addEventListener('pointerdown', () => { activePointerPress = true; });
const releasePointer = () => { if (activePointerPress) { activePointerPress = false; flushDeferredRender(); } };
window.addEventListener('pointerup', releasePointer);
window.addEventListener('pointercancel', releasePointer);
window.addEventListener('blur', releasePointer);
root.addEventListener('focusout', () => { window.setTimeout(flushDeferredRender, 0); });
scrollListeners = attachScrollActivityListeners({ doc: document, win: window, guard: scrollGuard });

const MAX_EXPLAINER_TTS_BYTES = 4 * 1024 * 1024;

// This local presentation helper has no execution or order authority.
try {
  explainer = createExplainer({
    getContext: () => ({
      projection: state.projection,
      reviewEnvelope: state.reviewEnvelope,
      route: state.route,
      source: state.source,
      aiConnected: Boolean(state.liveStreamConnected && state.aiModels?.connected),
      voiceExplainerModel: 'Gemini 4 Neon',
      activeModelLabel: state.aiModels?.activeDisplayName ?? null,
      liveAccountLabel: state.brokerRouting?.connected ? `${state.brokerRouting.executionMode} (${state.brokerRouting.activeBroker})` : null,
      liveRunLabel: state.aiTrader?.connected ? `${state.aiTrader.activeDisplayName} / ${state.aiTrader.thinkingDepth}` : null,
      liveStateLabel: state.aiTrader?.connected ? `cycle-${state.aiTrader.cycleCount}` : null,
    }),
    askModel: async (question, extra = null) => {
      const headers = { Accept: 'application/json', 'Content-Type': 'application/json' };
      if (loopbackAuthToken) headers.Authorization = `Bearer ${loopbackAuthToken}`;
      const payload = { question };
      if (extra && typeof extra === 'object') {
        if (typeof extra.audio_base64 === 'string' && extra.audio_base64.length > 0) {
          payload.audio_base64 = extra.audio_base64;
        }
        if (typeof extra.audio_mime_type === 'string' && extra.audio_mime_type.length > 0) {
          payload.audio_mime_type = extra.audio_mime_type;
        }
      }
      const resp = await fetch(new URL('/api/explainer-ask', window.location.origin), {
        method: 'POST',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        headers,
        body: JSON.stringify(payload),
      });
      const txt = await resp.text();
      const doc = parseUniqueJSON(txt, MAX_AI_PAYLOAD_BYTES);
      if (!resp.ok) throw new Error(doc?.error || `Explainer request failed (${resp.status}).`);
      return doc;
    },
    synthesizeSpeech: async (text, voiceName = 'Kore') => {
      const headers = { Accept: 'application/json', 'Content-Type': 'application/json' };
      if (loopbackAuthToken) headers.Authorization = `Bearer ${loopbackAuthToken}`;
      const resp = await fetch(new URL('/api/explainer-tts', window.location.origin), {
        method: 'POST',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        headers,
        body: JSON.stringify({ text, voice_name: voiceName }),
      });
      const txt = await resp.text();
      const doc = parseUniqueJSON(txt, MAX_EXPLAINER_TTS_BYTES);
      if (!resp.ok) throw new Error(doc?.error || `Explainer TTS failed (${resp.status}).`);
      return doc;
    },
  });
  scrollListeners?.syncWorkspace?.();
} catch { disableExplainer(); }

// This entry point runs only when the UI document is explicitly opened.
render();
void (async () => {
  await loadFixture();
  if (pendingBootPairCode) {
    const codeToExchange = pendingBootPairCode;
    pendingBootPairCode = null;
    try {
      await exchangePairCodeAndConnect(codeToExchange);
    } catch (error) {
      setLoopbackAuthToken(null);
      state.aiIssue = error instanceof Error ? error.message : 'Single-use pairing exchange failed.';
      render();
      announce(state.aiIssue);
    }
    return;
  }
  if (shouldAutoConnectLiveFeed(window.location, loopbackAuthToken)) {
    await connectLoopbackLiveFeed().catch(() => {});
  }
})();

// Age the held read only. Never add local elapsed time to the simulator clock.
function updateObservationAge() {
  const age = displayFreshness(state);
  const label = root.querySelector('.freshness strong');
  if (label) label.textContent = age.label;
  const dot = root.querySelector('.freshness .status-dot');
  if (dot) dot.classList.toggle('warning', age.tone === 'warning');
  const detail = root.querySelector('.freshness > span:not(.status-dot)');
  if (detail) detail.textContent = age.detail;
  const freshness = root.querySelector('.freshness');
  if (freshness) { freshness.dataset.clockBasis = age.clock_basis; freshness.dataset.readInvalidated = String(age.invalidated); }
}
let ageTimer = window.setInterval(updateObservationAge, 1000);
document.addEventListener('visibilitychange', () => { if (document.hidden) controller?.invalidateReadAge(); updateObservationAge(); });
window.addEventListener('pagehide', () => { controller?.invalidateReadAge(); stopLiveCockpitPollLoop(); scrollGuard.reset(); window.clearInterval(ageTimer); ageTimer = null; });
window.addEventListener('pageshow', () => { updateObservationAge(); if (ageTimer === null) ageTimer = window.setInterval(updateObservationAge, 1000); if (state.liveStreamConnected) startLiveCockpitPollLoop(); });
