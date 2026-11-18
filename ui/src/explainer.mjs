/* Modernist Explainer interaction, authored from the supplied written spec.
 * Local guide only: no model, network, transport, control dispatch or authority.
 * Persistence is limited to the three visual layout preferences below.
 */
import { replaceSafeHTML } from './render.mjs';

const STORAGE_KEY = 'cas.forex.explainer.layout.v1';
const EDGES = ['left', 'right', 'top', 'bottom'];
const DEFAULT_LAYOUT = Object.freeze({ edge: 'right', frac: 0.62, collapsed: false });
const clamp = (value, lo, hi) => Math.min(hi, Math.max(lo, value));

function readLayout() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
    if (saved && EDGES.includes(saved.edge) && Number.isFinite(saved.frac) && typeof saved.collapsed === 'boolean') {
      return { edge: saved.edge, frac: clamp(saved.frac, 0, 1), collapsed: saved.collapsed };
    }
  } catch { /* Storage is optional; a blocked store must not block the UI. */ }
  return { ...DEFAULT_LAYOUT };
}

function scalar(value, fallback = 'Unknown') {
  return value === null || value === undefined || value === '' ? fallback : String(value);
}

function localExplanation(topic, context) {
  const p = context.projection;
  const route = ['operate', 'review', 'setup'].includes(context.route) ? context.route : 'operate';
  if (topic === 'controls') {
    return 'Pause stops admission of new risk; it does not grant management permission. Stop also blocks automation admission, but does not close positions or establish that accepted orders have stopped. Close is a separate exact-target review and submission.\n\nOnly the existing workspace controls can prepare an authorized request. Acceptance is not an observed effect. Independent receipts and readback are still required. This guide sends no request.';
  }
  if (!p) return 'No valid cockpit snapshot is loaded. The workspace cannot establish account values, positions, permission or a current venue state. Open Setup to inspect an allowed snapshot. This local guide cannot fill those gaps or authorize an action.';
  if (topic === 'unknowns') {
    const missing = [];
    if (p.observed_at == null) missing.push('No venue observation time is supplied.');
    if (p.state_id == null) missing.push('The current state identity is unknown.');
    if (['equity', 'balance', 'open_pnl', 'realized_pnl'].some(key => p[key] == null)) missing.push('One or more account amounts are unknown; they are not zero.');
    if (p.positions == null) missing.push('Position inventory is unknown; that does not mean flat.');
    if (!['ALLOWED', 'PAUSED'].includes(p.permissions?.new_risk)) missing.push('New-risk permission is absent, unknown or not recognized; no permission is established.');
    if (!['ALLOWED', 'STOPPED'].includes(p.permissions?.management)) missing.push('Management permission is absent, unknown or not recognized; no permission is established.');
    if (p.last_decision == null) missing.push('No latest operator decision is supplied.');
    const coverage = context.reviewEnvelope?.envelope?.coverage;
    if (!coverage?.complete) missing.push('Complete decision/evidence coverage has not been established.');
    return `${missing.length ? missing.join('\n\n') : 'These supplied fields are populated; that alone does not establish current or independently verified state.'}\n\nThe source remains a bounded read. P/L period, fees and cashflow coverage are not established here. No model has produced this explanation.`;
  }
  const descriptions = {
    operate: 'Operate separates reported permissions, account amounts, position inventory, the latest proposal and unresolved effects. An amount or reference is shown only when the supplied snapshot contains it.',
    review: 'Review inspects supplied decisions and evidence. List and Atlas refer to the same records. A referenced receipt is not by itself an independently observed fill. Coverage and source checks remain visible.',
    setup: 'Setup shows the snapshot source, scope, theme and rehearsal readiness. Loading a file grants no permission and starts no worker. Resume and Close remain separate actions with their own checks.',
  };
  return `${descriptions[route]}\n\nSource: ${scalar(context.source, 'No valid source')}. Run: ${scalar(p.scope?.run_id)}. State: ${scalar(p.state_id)}.\n\nThis is authored, deterministic UI guidance about the supplied read. It is not model output, a live venue observation or trading advice.`;
}

export function createExplainer({ getContext, askModel = null }) {
  if (typeof getContext !== 'function') throw new TypeError('Explainer requires a read-only context getter.');
  if (document.querySelector('#forex-explainer')) throw new Error('Explainer already mounted.');
  const app = document.getElementById('app');
  if (!app?.parentNode) throw new Error('Explainer requires the existing workspace root.');
  if (document.querySelector('#forex-explainer-workspace')) throw new Error('Explainer workspace already mounted.');
  const initialScroll = { left: window.scrollX, top: window.scrollY };
  const workspace = document.createElement('div');
  workspace.id = 'forex-explainer-workspace';
  workspace.className = 'forex-explainer-workspace';
  workspace.tabIndex = 0;
  workspace.setAttribute('role', 'region');
  workspace.setAttribute('aria-label', 'Forex workspace scroll area');
  let layout = readLayout();
  let open = false;
  let selectedTopic = 'overview';
  let answerMode = 'local';
  let askBusy = false;
  let askAnswer = null;
  let lastAskedQuestion = '';
  let pointer = null;
  let suppressClick = false;
  let destroyed = false;
  let mounted = false;
  let returnScroll = null;
  const wide = window.matchMedia('(min-width: 1100px)');
  const host = document.createElement('div');
  host.id = 'forex-explainer';
  host.className = 'forex-explainer-host';
  // This template contains only authored UI strings. Source data uses textContent.
  replaceSafeHTML(host, `
    <div class="forex-explainer-zones" aria-hidden="true">
      <span data-dock-zone="left"></span><span data-dock-zone="right"></span>
      <span data-dock-zone="top"></span><span data-dock-zone="bottom"></span>
    </div>
    <button type="button" class="forex-explainer-mark" aria-label="Open Explainer local guide" aria-controls="forex-explainer-panel" aria-expanded="false" aria-describedby="forex-explainer-move-help" title="Explainer: drag to dock; click for local guidance">
      <span aria-hidden="true"></span><span aria-hidden="true"></span>
    </button>
    <span id="forex-explainer-move-help" class="forex-explainer-sr-only">Drag to move. Arrow keys move along the dock; Alt plus an arrow docks to that edge. Home restores the default position. C collapses the mark. Enter or Space opens the local guide.</span>
    <aside id="forex-explainer-panel" class="forex-explainer-panel" aria-labelledby="forex-explainer-title" hidden>
      <header class="forex-explainer-heading">
        <span class="forex-explainer-small-mark" aria-hidden="true"><span></span><span></span></span>
        <div><h2 id="forex-explainer-title">Explainer</h2><p data-guide-subtitle>Local guide - no model</p></div>
        <button type="button" class="forex-explainer-close" aria-label="Close Explainer">×</button>
      </header>
      <div class="forex-explainer-suggestions" role="group" aria-label="Local guide questions">
        <button type="button" data-explainer-topic="overview" aria-pressed="true">What am I looking at?</button>
        <button type="button" data-explainer-topic="unknowns" aria-pressed="false">What remains unknown?</button>
        <button type="button" data-explainer-topic="controls" aria-pressed="false">What do these controls do?</button>
      </div>
      <div class="forex-explainer-content">
        <h3 class="forex-explainer-question">What am I looking at?</h3>
        <p class="forex-explainer-answer"></p>
        <dl class="forex-explainer-source">
          <div><dt>Source</dt><dd data-guide-source></dd></div>
          <div><dt>Account</dt><dd data-guide-account></dd></div>
          <div><dt>Run</dt><dd data-guide-run></dd></div>
          <div><dt>State</dt><dd data-guide-state></dd></div>
          <div><dt>Model</dt><dd data-guide-model>None — authored local guide</dd></div>
        </dl>
        <details class="forex-explainer-record"><summary>Open the supplied record</summary><p>Inspection only. This is the currently supplied UI data, not an independent venue receipt.</p><pre tabindex="0" aria-label="Supplied JSON record"></pre></details>
        <details class="forex-explainer-layout"><summary>Position the Explainer</summary>
          <p>Drag the mark, or choose an edge. Only its position and collapsed state are saved in this browser.</p>
          <div class="forex-explainer-dock-buttons" role="group" aria-label="Dock edge">
            <button type="button" data-guide-dock="left">Left</button><button type="button" data-guide-dock="right">Right</button><button type="button" data-guide-dock="top">Top</button><button type="button" data-guide-dock="bottom">Bottom</button>
          </div>
          <div class="forex-explainer-layout-actions"><button type="button" data-guide-collapse>Collapse to tab</button><button type="button" data-guide-reset>Reset position</button></div>
        </details>
      </div>
      <footer class="forex-explainer-footer"><label for="forex-explainer-prompt">Ask a model</label><div class="forex-explainer-ask-row"><input id="forex-explainer-prompt" type="text" disabled placeholder="No AI provider attached" aria-describedby="forex-explainer-unavailable"><button type="button" class="button button-small button-primary" data-explainer-ask-submit hidden>Ask</button></div><p id="forex-explainer-unavailable">AI explanations are unavailable. The local guide and all source records remain readable.</p></footer>
    </aside>
    <div class="forex-explainer-sr-only" role="status" aria-live="polite" data-guide-announcement></div>`);
  const mark = host.querySelector('.forex-explainer-mark');
  const panel = host.querySelector('.forex-explainer-panel');
  const closeButton = host.querySelector('.forex-explainer-close');
  const announcement = host.querySelector('[data-guide-announcement]');
  const say = message => { announcement.textContent = message; };

  function persist() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ edge: layout.edge, frac: layout.frac, collapsed: layout.collapsed })); } catch { /* No storage is required for use. */ }
  }
  function frame() {
    const width = Math.max(48, document.documentElement.clientWidth);
    const height = Math.max(48, window.innerHeight);
    const side = layout.edge === 'left' ? 'left' : 'right';
    const inset = open && wide.matches ? 396 : 0;
    return { x: side === 'left' ? inset : 0, y: 0, width: width - inset, height, side };
  }
  function setMarkBox(x, y, width, height) {
    // CSSOM values are only bounded local numbers, never source-provided CSS.
    mark.style.left = `${x}px`;
    mark.style.top = `${y}px`;
    mark.style.width = `${width}px`;
    mark.style.height = `${height}px`;
  }
  function position() {
    if (destroyed || pointer?.dragging) return;
    const f = frame();
    const vertical = layout.edge === 'left' || layout.edge === 'right';
    const thickness = layout.collapsed ? 12 : 48;
    const length = layout.collapsed ? 64 : 48;
    const width = vertical ? thickness : length;
    const height = vertical ? length : thickness;
    let x = f.x, y = f.y;
    if (vertical) {
      x += layout.edge === 'right' ? f.width - width : 0;
      y += clamp(layout.frac * f.height - height / 2, 8, Math.max(8, f.height - height - 8));
    } else {
      x += clamp(layout.frac * f.width - width / 2, 8, Math.max(8, f.width - width - 8));
      y += layout.edge === 'bottom' ? f.height - height : 0;
      // While a side sheet is open, its mark uses the reserved rail, not the data.
      if (open && wide.matches) x = f.x + f.width - width;
    }
    setMarkBox(x, y, width, height);
    mark.dataset.collapsed = String(layout.collapsed);
    mark.dataset.edge = layout.edge;
    mark.setAttribute('aria-expanded', String(open));
    mark.setAttribute('aria-label', layout.collapsed ? 'Restore Explainer mark' : open ? 'Close Explainer local guide' : 'Open Explainer local guide');
    document.body.dataset.forexExplainerEdge = layout.edge;
    document.body.dataset.forexExplainerSide = f.side;
    for (const button of host.querySelectorAll('[data-guide-dock]')) button.setAttribute('aria-pressed', String(button.dataset.guideDock === layout.edge));
  }
  const promptInput = host.querySelector('#forex-explainer-prompt');
  const askButton = host.querySelector('[data-explainer-ask-submit]');
  const footerNote = host.querySelector('#forex-explainer-unavailable');
  const modelField = host.querySelector('[data-guide-model]');
  const subtitleField = host.querySelector('[data-guide-subtitle]');

  function updateContent() {
    const context = getContext() || {};
    const projection = context.projection;
    const selected = host.querySelector(`[data-explainer-topic="${selectedTopic}"]`);
    if (answerMode === 'ask' && askAnswer) {
      host.querySelector('.forex-explainer-question').textContent = lastAskedQuestion || 'Live AI explanation';
      host.querySelector('.forex-explainer-answer').textContent = askAnswer;
    } else {
      host.querySelector('.forex-explainer-question').textContent = selected.textContent;
      host.querySelector('.forex-explainer-answer').textContent = localExplanation(selectedTopic, context);
    }
    host.querySelector('[data-guide-source]').textContent = scalar(context.source, context.aiConnected ? 'Live server stream' : 'No valid source');
    host.querySelector('[data-guide-account]').textContent = scalar(projection?.scope?.account_id ?? context.liveAccountLabel);
    host.querySelector('[data-guide-run]').textContent = scalar(projection?.scope?.run_id ?? context.liveRunLabel);
    host.querySelector('[data-guide-state]').textContent = scalar(projection?.state_id ?? context.liveStateLabel);
    const raw = { cockpit: projection ?? null, decision_read: context.reviewEnvelope ?? null };
    try { host.querySelector('.forex-explainer-record pre').textContent = JSON.stringify(raw, null, 2); }
    catch { host.querySelector('.forex-explainer-record pre').textContent = 'The supplied UI record could not be serialized. No substitute record is shown.'; }
    for (const button of host.querySelectorAll('[data-explainer-topic]')) button.setAttribute('aria-pressed', String(answerMode === 'local' && button.dataset.explainerTopic === selectedTopic));

    const aiReady = Boolean(context.aiConnected && typeof askModel === 'function');
    if (aiReady) {
      const mName = scalar(context.activeModelLabel, 'Connected Frontier AI');
      modelField.textContent = `${mName} (read-only Q&A)`;
      subtitleField.textContent = `Live read-only guide · ${mName}`;
      promptInput.disabled = askBusy;
      promptInput.placeholder = 'Ask about markets, sessions, positions, or valve gates…';
      askButton.hidden = false;
      askButton.disabled = askBusy;
      footerNote.textContent = askBusy ? 'Asking connected AI model…' : `Read-only live explanations (${mName}). Zero execution authority.`;
    } else {
      modelField.textContent = 'None — authored local guide';
      subtitleField.textContent = 'Local guide - no model';
      promptInput.disabled = true;
      promptInput.placeholder = 'No AI provider attached';
      askButton.hidden = true;
      askButton.disabled = true;
      footerNote.textContent = 'AI explanations are unavailable. The local guide and all source records remain readable.';
    }
  }

  async function submitQuestion() {
    const context = getContext() || {};
    if (!context.aiConnected || typeof askModel !== 'function' || askBusy) return;
    const q = String(promptInput.value ?? '').trim();
    if (!q) return;
    askBusy = true;
    lastAskedQuestion = q;
    updateContent();
    try {
      const reply = await askModel(q);
      askAnswer = scalar(typeof reply === 'string' ? reply : reply?.answer, 'No answer text returned.');
      answerMode = 'ask';
      promptInput.value = '';
      say('Live AI explanation updated (read-only).');
    } catch (err) {
      answerMode = 'ask';
      askAnswer = err instanceof Error ? err.message : 'Unable to reach live Explainer endpoint.';
      say('Live AI explanation request failed.');
    } finally {
      askBusy = false;
      updateContent();
    }
  }
  function setOpen(next, { focus = false } = {}) {
    if (next && !open && !wide.matches) returnScroll = { left: workspace.scrollLeft, top: workspace.scrollTop };
    open = Boolean(next);
    panel.hidden = !open;
    document.body.classList.toggle('forex-explainer-open', open);
    if (open) { layout.collapsed = false; updateContent(); }
    position();
    if (!open && returnScroll) {
      workspace.scrollTo({ ...returnScroll, behavior: 'auto' });
      returnScroll = null;
    }
    if (focus) {
      if (open) {
        closeButton.focus({ preventScroll: true });
        if (!wide.matches) panel.scrollIntoView({ block: 'start', behavior: 'auto' });
      } else mark.focus({ preventScroll: true });
    }
  }
  function savePosition(message) { persist(); position(); if (message) say(message); }
  function nearestEdge(x, y, f) {
    const distances = { left: x, right: f.width - x, top: y, bottom: f.height - y };
    const minimum = Math.min(...Object.values(distances));
    const tied = EDGES.filter(edge => Math.abs(distances[edge] - minimum) < 0.5);
    return tied.includes(layout.edge) ? layout.edge : tied[0];
  }
  function releaseAt(clientX, clientY) {
    const f = frame();
    const x = clamp(clientX - f.x, 0, f.width), y = clamp(clientY - f.y, 0, f.height);
    const left = x < 44, right = f.width - x < 44, top = y < 44, bottom = f.height - y < 44;
    const corner = (left || right) && (top || bottom);
    let edge = nearestEdge(x, y, f);
    if (corner) {
      const adjacent = [left ? 'left' : 'right', top ? 'top' : 'bottom'];
      edge = f.height > f.width ? adjacent[0] : f.width > f.height ? adjacent[1] : adjacent.includes(layout.edge) ? layout.edge : adjacent[0];
    }
    layout.edge = edge;
    const vertical = edge === 'left' || edge === 'right';
    layout.frac = clamp((vertical ? y : x) / (vertical ? f.height : f.width), 0, 1);
    layout.collapsed = corner;
    if (corner) setOpen(false);
    savePosition(`Explainer docked ${edge}${corner ? ', collapsed to a tab' : ''}.`);
  }
  promptInput.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); void submitQuestion(); } });
  mark.addEventListener('pointerdown', event => {
    if (!event.isPrimary || event.button !== 0) return;
    const box = mark.getBoundingClientRect();
    pointer = {
      id: event.pointerId, x: event.clientX, y: event.clientY, dragging: false,
      offsetX: clamp((event.clientX - box.left) / box.width, 0, 1) * 48,
      offsetY: clamp((event.clientY - box.top) / box.height, 0, 1) * 48,
    };
    mark.setPointerCapture(event.pointerId);
  });
  mark.addEventListener('pointermove', event => {
    if (!pointer || pointer.id !== event.pointerId) return;
    if (!pointer.dragging && Math.hypot(event.clientX - pointer.x, event.clientY - pointer.y) < 4) return;
    pointer.dragging = true;
    event.preventDefault();
    mark.classList.add('is-dragging');
    mark.dataset.collapsed = 'false';
    host.classList.add('is-dragging');
    const f = frame();
    const x = clamp(event.clientX - f.x, 0, f.width), y = clamp(event.clientY - f.y, 0, f.height);
    setMarkBox(clamp(event.clientX - pointer.offsetX, f.x, f.x + f.width - 48), clamp(event.clientY - pointer.offsetY, 0, f.height - 48), 48, 48);
    const edge = nearestEdge(x, y, f);
    for (const zone of host.querySelectorAll('[data-dock-zone]')) zone.classList.toggle('is-target', zone.dataset.dockZone === edge);
  });
  function endPointer(event, cancelled = false) {
    if (!pointer || event.pointerId !== pointer.id) return;
    const dragged = pointer.dragging;
    pointer = null;
    mark.classList.remove('is-dragging');host.classList.remove('is-dragging');
    for (const zone of host.querySelectorAll('[data-dock-zone]')) zone.classList.remove('is-target');
    if (mark.hasPointerCapture(event.pointerId)) mark.releasePointerCapture(event.pointerId);
    suppressClick = dragged;
    if (dragged && !cancelled) releaseAt(event.clientX, event.clientY);
    else position();
    // Suppress only the click generated by this pointer gesture, never the next key click.
    if (dragged) window.setTimeout(() => { suppressClick = false; }, 0);
  }
  mark.addEventListener('pointerup', event => endPointer(event));
  mark.addEventListener('pointercancel', event => endPointer(event, true));
  mark.addEventListener('click', () => {
    if (suppressClick) return;
    if (layout.collapsed) { layout.collapsed = false; savePosition('Explainer mark restored.'); return; }
    setOpen(!open, { focus: true });
  });
  mark.addEventListener('keydown', event => {
    const arrows = { ArrowLeft: 'left', ArrowRight: 'right', ArrowUp: 'top', ArrowDown: 'bottom' };
    if (arrows[event.key] && event.altKey) {
      event.preventDefault();layout.edge = arrows[event.key];layout.collapsed = false;savePosition(`Explainer docked ${layout.edge}.`);
    } else if (arrows[event.key]) {
      event.preventDefault();layout.frac = clamp(layout.frac + (event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1) * (event.shiftKey ? 0.1 : 0.025), 0, 1);savePosition();
    } else if (event.key === 'Home') {
      event.preventDefault();layout = { ...DEFAULT_LAYOUT };savePosition('Explainer position reset.');
    } else if (event.key.toLowerCase() === 'c' && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();setOpen(false);layout.collapsed = true;savePosition('Explainer collapsed to a tab.');
    }
  });
  closeButton.addEventListener('click', () => setOpen(false, { focus: true }));
  host.addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button || button.disabled) return;
    if (button.dataset.explainerTopic) { selectedTopic = button.dataset.explainerTopic; answerMode = 'local'; updateContent(); say('Local guide answer updated. No model was called.'); }
    if (button.hasAttribute('data-explainer-ask-submit')) { void submitQuestion(); }
    if (button.dataset.guideDock) { layout.edge = button.dataset.guideDock;layout.collapsed = false;savePosition(`Explainer docked ${layout.edge}.`); }
    if (button.hasAttribute('data-guide-collapse')) { setOpen(false, { focus: true });layout.collapsed = true;savePosition('Explainer collapsed to a tab.'); }
    if (button.hasAttribute('data-guide-reset')) { layout = { ...DEFAULT_LAYOUT };savePosition('Explainer position reset.'); }
  });
  function onEscape(event) {
    // A trading review dialog owns Escape while it is open; never interfere with it.
    if (event.key === 'Escape' && open && !document.querySelector('dialog[open]')) { event.preventDefault();setOpen(false, { focus: true }); }
  }
  const onResize = () => position();
  function destroy() {
    if (destroyed) return;
    destroyed = true;
    const scroll = returnScroll || (mounted ? { left: workspace.scrollLeft, top: workspace.scrollTop } : initialScroll);
    document.removeEventListener('keydown', onEscape);
    window.removeEventListener('resize', onResize);
    wide.removeEventListener('change', onResize);
    if (workspace.parentNode) {
      if (app.parentNode === workspace) workspace.replaceWith(app);
      else workspace.remove();
    }
    host.remove();
    document.body.classList.remove('forex-explainer-ready', 'forex-explainer-open');
    delete document.body.dataset.forexExplainerEdge;
    delete document.body.dataset.forexExplainerSide;
    window.scrollTo({ ...scroll, behavior: 'auto' });
  }
  // Mount once, after all detached UI is prepared. A partial mount restores #app.
  try {
    app.parentNode.insertBefore(workspace, app);
    workspace.append(app, host);
    document.addEventListener('keydown', onEscape);
    window.addEventListener('resize', onResize);
    wide.addEventListener('change', onResize);
    document.body.classList.add('forex-explainer-ready');
    position();
    workspace.scrollTo({ ...initialScroll, behavior: 'auto' });
    mounted = true;
    window.scrollTo({ left: 0, top: 0, behavior: 'auto' });
  } catch (error) {
    destroy();
    throw error;
  }
  return Object.freeze({
    sync() { if (!destroyed) { if (open) updateContent();position(); } },
    destroy,
  });
}
