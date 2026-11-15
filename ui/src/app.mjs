import { createExplainer } from './explainer.mjs';
import { decodeCockpit, parseUniqueJSON, MAX_SNAPSHOT_BYTES } from './wire.mjs';
import { resetInspection, reviewRecords, inspectRecord } from './model.mjs';
import { displayFreshness } from './freshness.mjs';
import { renderApp, renderControlDialog, renderCloseDialog, renderPreparedClose } from './render.mjs';
import { decodeDecisionRead, envelopeRecords, MAX_REVIEW_BYTES } from './decision-read.mjs';
import { ScopedBridge } from './bridge.mjs';

// Fixed same-origin assets. Only explicit trusted bootstrap may inject a scoped bridge.
const schemaURL = new URL('../docs/contracts/cockpit.schema.json', document.baseURI);
const fixtureURL = new URL('../docs/contracts/initial-cockpit.json', document.baseURI);
const reviewSchemaURL = new URL('../docs/contracts/decision-read.schema.json', document.baseURI);
const reviewFixtureURL = new URL('../docs/contracts/initial-decision-read.json', document.baseURI);
const root = document.querySelector('#app');
const dialog = document.querySelector('#review-dialog');
const announcer = document.querySelector('#announcer');
let sharedSchema = null;
let reviewSchema = null;
let rawReviewSchema = null;
let controller = null;
let dialogContext = null;
let lastBridgeProjection = null;
let loadGeneration = 0;
let reviewGeneration = 0;
let dialogTrigger = null;
let explainer = null;
let state = {
  projection: null, source: 'none', loadedAt: null, schemaReady: false,
  error: null, loading: false, route: routeFromHash(), theme: 'system',
  reviewView: 'list', reviewFilter: 'all', explainerIssue: null, inspection: resetInspection(),
  reviewEnvelope: null, reviewIssue: null, reviewSchemaReady: false, lastLoaded: null, transport: null,
};

function routeFromHash() {
  const route = window.location.hash.slice(1);
  return ['operate', 'review', 'setup'].includes(route) ? route : 'operate';
}

function render(focusMain = false) {
  const active = document.activeElement;
  const identity = root.contains(active) && active?.tagName === 'BUTTON' ? JSON.stringify(active.dataset) : null;
  document.documentElement.dataset.theme = state.theme;
  root.innerHTML = renderApp(state);
  try { explainer?.sync(); } catch { disableExplainer(); }
  document.title = `${state.route[0].toUpperCase() + state.route.slice(1)} / CAS Forex`;
  if (focusMain) document.querySelector('#main').focus({ preventScroll: true });
  else if (identity) {
    const replacement = [...root.querySelectorAll('button')].find((item) => !item.disabled && JSON.stringify(item.dataset) === identity);
    (replacement ?? document.querySelector('#main')).focus({ preventScroll: true });
  }
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
  dialog.innerHTML = dialogContext === 'prepared' ? renderPreparedClose(state.transport) : renderControlDialog(dialogContext, state.transport);
  const matching = [...dialog.querySelectorAll('button')].find((item) => !item.disabled && JSON.stringify(item.dataset) === identity);
  (matching ?? dialog.querySelector('[data-dialog-close]'))?.focus();
}

async function loadSchemas() {
  if (!sharedSchema) sharedSchema = parseUniqueJSON(await readStatic(schemaURL));
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
    return { detach: detachTransport, read: readTransport };
  } catch (error) { failLoad(generation, error); throw error; }
}

export function detachTransport() {
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

async function readTransport() {
  if (!controller?.attached) throw new Error('Transport unavailable.');
  await controller.refresh();
  await readBridgeReview();
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
  const response = await fetch(url, { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000) });
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
  dialog.innerHTML = html;
  dialog.showModal();
  dialog.querySelector('[data-dialog-close]').focus();
}

root.addEventListener('click', (event) => {
  const target = event.target.closest('button');
  if (!target || target.disabled) return;
  if (transportClick(target)) return;
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
    root.querySelector('[data-theme-toggle]').focus();
  }
  if (target.dataset.reviewFilter) {
    if (!['all', 'decisions', 'events', 'evidence'].includes(target.dataset.reviewFilter)) return;
    state.reviewFilter = target.dataset.reviewFilter;
    state.inspection = resetInspection();
    render();
    root.querySelector(`[data-review-filter="${state.reviewFilter}"]`)?.focus();
    announce('Record filter changed. Source state and coverage are unchanged.');
    return;
  }
  if (target.dataset.view) {
    state.reviewView = target.dataset.view === 'atlas' ? 'atlas' : 'list';
    render();
    root.querySelector(`[data-view="${state.reviewView}"]`).focus();
    announce(`${state.reviewView === 'atlas' ? 'Atlas' : 'List'} view. Same supplied records.`);
  }
  if (target.dataset.record && state.projection) {
    state.inspection = inspectRecord(state.inspection, target.dataset.record, state.reviewEnvelope ? envelopeRecords(state.reviewEnvelope) : reviewRecords(state.projection));
    render();
    [...root.querySelectorAll('[data-record]')].find((node) => node.dataset.record === state.inspection.focus_node_id)?.focus();
    announce('Inspection focus changed. Source state is unchanged.');
  }
});

root.addEventListener('change', async (event) => {
  if (event.target.name === 'theme') {
    const theme = event.target.value;
    if (!['system', 'light', 'dark'].includes(theme)) return;
    state.theme = theme;
    render();
    root.querySelector(`input[name="theme"][value="${theme}"]`).focus();
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
  if (dialogTrigger?.isConnected) dialogTrigger.focus();
  else document.querySelector('#main')?.focus({ preventScroll: true });
  dialogTrigger = null;
  dialogContext = null;
  dialog.innerHTML = '';
});
window.addEventListener('hashchange', () => {
  if (dialog.open) dialog.close();
  state.route = routeFromHash();
  render(true);
});

// This local presentation helper has no transport, model client, or execution authority.
try {
  explainer = createExplainer({ getContext: () => ({ projection: state.projection, reviewEnvelope: state.reviewEnvelope, route: state.route, source: state.source }) });
} catch { disableExplainer(); }

// This entry point runs only when the UI document is explicitly opened.
render();
void loadFixture();

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
window.addEventListener('pagehide', () => { controller?.invalidateReadAge(); window.clearInterval(ageTimer); ageTimer = null; });
window.addEventListener('pageshow', () => { updateObservationAge(); if (ageTimer === null) ageTimer = window.setInterval(updateObservationAge, 1000); });
