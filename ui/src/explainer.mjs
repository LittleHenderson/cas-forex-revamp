/* Modernist Explainer & Real-Time Gemini 4 Neon Audible Voice Briefing Panel.
 * Read-only advisory assistant: zero trading authority, zero control dispatch,
 * strict CSP compliant (pure Web Audio API PCM/buffer synthesis + Web Speech fallback,
 * zero HTML media tags, zero object URLs, zero inline CSS attributes).
 */
import { replaceSafeHTML } from './render.mjs';

const STORAGE_KEY = 'cas.forex.explainer.layout.v1';
const AUTOSPEAK_STORAGE_KEY = 'cas.forex.explainer.autospeak.v1';
const EDGES = ['left', 'right', 'top', 'bottom'];
const DEFAULT_LAYOUT = Object.freeze({ edge: 'right', frac: 0.62, collapsed: false });
const ALLOWED_AUDIO_MIMES = Object.freeze(['audio/webm', 'audio/ogg', 'audio/wav', 'audio/mp4', 'audio/mpeg']);
const clamp = (value, lo, hi) => Math.min(hi, Math.max(lo, value));

export const EXPLAINER_QUICK_QUESTIONS = Object.freeze([
  'Give me a full live status briefing',
  'Explain my open trades, risk gear, and stop protection',
  'How much is in my 3 brokers, Bank Vault, and 5 parallel tiers?',
  'Explain the CAS Forex architecture and 5-gate LIVE readiness',
]);

const escAttr = (v) => String(v ?? '').replace(/[&<>"']/g, (ch) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
));

function decodeBase64ToBytes(base64Str) {
  const cleaned = String(base64Str ?? '').replace(/\s+/g, '');
  if (!cleaned) return new Uint8Array(0);
  if (typeof globalThis.atob === 'function') {
    const bin = globalThis.atob(cleaned);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      bytes[i] = bin.charCodeAt(i) & 0xff;
    }
    return bytes;
  }
  if (typeof globalThis.Buffer === 'function') {
    const buf = globalThis.Buffer.from(cleaned, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  throw new Error('Base64 decoder unavailable.');
}

function encodeBytesToBase64(bytes) {
  if (typeof globalThis.btoa === 'function') {
    const chunkSize = 0x8000;
    let bin = '';
    for (let i = 0; i < bytes.length; i += chunkSize) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return globalThis.btoa(bin);
  }
  if (typeof globalThis.Buffer === 'function') {
    return globalThis.Buffer.from(bytes).toString('base64');
  }
  throw new Error('Base64 encoder unavailable.');
}

/** Decode 16-bit signed little-endian PCM base64 audio into normalized [-1.0, 1.0) Float32 samples. */
export function decodePcm16LeBase64ToFloat32(base64Str) {
  const bytes = decodeBase64ToBytes(base64Str);
  const sampleCount = Math.floor(bytes.byteLength / 2);
  const out = new Float32Array(sampleCount);
  if (sampleCount === 0) return out;
  const view = new DataView(bytes.buffer, bytes.byteOffset, sampleCount * 2);
  for (let i = 0; i < sampleCount; i += 1) {
    out[i] = view.getInt16(i * 2, true) / 32768;
  }
  return out;
}

function parseSampleRateHz(ttsDoc) {
  if (Number.isSafeInteger(ttsDoc?.sample_rate_hz) && ttsDoc.sample_rate_hz >= 8000 && ttsDoc.sample_rate_hz <= 96000) {
    return ttsDoc.sample_rate_hz;
  }
  const m = /rate\s*=\s*([0-9]{4,6})/i.exec(String(ttsDoc?.mime_type ?? ''));
  if (m) {
    const parsed = Number(m[1]);
    if (Number.isSafeInteger(parsed) && parsed >= 8000 && parsed <= 96000) return parsed;
  }
  return 24000;
}

function readLayout() {
  try {
    const saved = JSON.parse(globalThis.localStorage?.getItem?.(STORAGE_KEY) || 'null');
    if (saved && EDGES.includes(saved.edge) && Number.isFinite(saved.frac) && typeof saved.collapsed === 'boolean') {
      return { edge: saved.edge, frac: clamp(saved.frac, 0, 1), collapsed: saved.collapsed };
    }
  } catch { /* Storage is optional; a blocked store must not block the UI. */ }
  return { ...DEFAULT_LAYOUT };
}

function readAutoSpeak() {
  try {
    const saved = globalThis.sessionStorage?.getItem?.(AUTOSPEAK_STORAGE_KEY);
    if (saved === 'false') return false;
    if (saved === 'true') return true;
  } catch { /* Optional storage */ }
  return true;
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

export function createExplainer({ getContext, askModel = null, synthesizeSpeech = null }) {
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
  let autoSpeak = readAutoSpeak();
  let open = false;
  let selectedTopic = 'overview';
  let answerMode = 'local';
  let askBusy = false;
  let askAnswer = null;
  let lastAskedQuestion = '';
  let isListening = false;
  let isSpeaking = false;
  let speakGeneration = 0;
  let voiceStatusNote = null;
  let activeRecognition = null;
  let activeMediaRecorder = null;
  let activeMediaStream = null;
  let activeBufferSource = null;
  let audioCtx = null;
  let pointer = null;
  let suppressClick = false;
  let destroyed = false;
  let mounted = false;
  let returnScroll = null;
  const wide = window.matchMedia('(min-width: 1100px)');
  const host = document.createElement('div');
  host.id = 'forex-explainer';
  host.className = 'forex-explainer-host';

  const quickChipButtons = EXPLAINER_QUICK_QUESTIONS.map((q) => (
    `<button type="button" data-explainer-quick-ask="${escAttr(q)}">${escAttr(q)}</button>`
  )).join('');

  // Authored UI template only; dynamic source data always uses textContent.
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
      <div class="forex-explainer-quick-chips" role="group" aria-label="Quick live voice briefings" hidden>
        ${quickChipButtons}
      </div>
      <div class="forex-explainer-locked-banner" data-explainer-locked-banner>
        <p>Cockpit locked — unlock with your Cockpit access key at the top of the page (or scan the Pairing QR from your PC) to talk to Gemini 4 Neon</p>
        <button type="button" class="forex-explainer-goto-unlock" data-explainer-goto-unlock="true">Go to Unlock Bar</button>
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
      <footer class="forex-explainer-footer">
        <label for="forex-explainer-prompt" data-explainer-prompt-label>Ask a model</label>
        <div class="forex-explainer-ask-row">
          <input id="forex-explainer-prompt" type="text" disabled placeholder="No AI provider attached" aria-describedby="forex-explainer-unavailable">
          <button type="button" class="button button-small button-primary" data-explainer-ask-submit hidden>Ask</button>
        </div>
        <div class="forex-explainer-voice-bar" role="group" aria-label="Voice controls">
          <button type="button" data-explainer-mic aria-pressed="false" disabled>Talk (Mic)</button>
          <button type="button" data-explainer-autospeak aria-pressed="true">Auto-Speak: ON</button>
          <button type="button" data-explainer-speak>Speak Answer</button>
        </div>
        <p id="forex-explainer-unavailable">AI explanations are unavailable. The local guide and all source records remain readable.</p>
      </footer>
    </aside>
    <div class="forex-explainer-sr-only" role="status" aria-live="polite" data-guide-announcement></div>`);

  const mark = host.querySelector('.forex-explainer-mark');
  const panel = host.querySelector('.forex-explainer-panel');
  const closeButton = host.querySelector('.forex-explainer-close');
  const announcement = host.querySelector('[data-guide-announcement]');
  const say = message => { announcement.textContent = message; };

  function persist() {
    try { globalThis.localStorage?.setItem?.(STORAGE_KEY, JSON.stringify({ edge: layout.edge, frac: layout.frac, collapsed: layout.collapsed })); } catch { /* No storage is required for use. */ }
  }
  function persistAutoSpeak() {
    try { globalThis.sessionStorage?.setItem?.(AUTOSPEAK_STORAGE_KEY, String(autoSpeak)); } catch { /* Optional storage */ }
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

  const promptLabel = host.querySelector('[data-explainer-prompt-label]');
  const promptInput = host.querySelector('#forex-explainer-prompt');
  const askButton = host.querySelector('[data-explainer-ask-submit]');
  const micButton = host.querySelector('[data-explainer-mic]');
  const autoSpeakButton = host.querySelector('[data-explainer-autospeak]');
  const speakButton = host.querySelector('[data-explainer-speak]');
  const quickChipsWrap = host.querySelector('.forex-explainer-quick-chips');
  const lockedBanner = host.querySelector('[data-explainer-locked-banner]');
  const footerNote = host.querySelector('#forex-explainer-unavailable');
  const modelField = host.querySelector('[data-guide-model]');
  const subtitleField = host.querySelector('[data-guide-subtitle]');

  function updateVoiceControls() {
    if (destroyed) return;
    const context = getContext() || {};
    const aiReady = Boolean(context.aiConnected && typeof askModel === 'function');
    if (micButton) {
      micButton.disabled = !aiReady || (askBusy && !isListening);
      micButton.classList.toggle('is-listening', isListening);
      micButton.setAttribute('aria-pressed', String(isListening));
      micButton.textContent = isListening ? 'Listening… tap to finish' : 'Talk (Mic)';
    }
    if (autoSpeakButton) {
      autoSpeakButton.setAttribute('aria-pressed', String(autoSpeak));
      autoSpeakButton.textContent = autoSpeak ? 'Auto-Speak: ON' : 'Auto-Speak: OFF';
    }
    if (speakButton) {
      speakButton.classList.toggle('is-speaking', isSpeaking);
      speakButton.setAttribute('aria-pressed', String(isSpeaking));
      speakButton.textContent = isSpeaking ? 'Stop Audio' : 'Speak Answer';
    }
  }

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
      const voiceModel = scalar(context.voiceExplainerModel, 'Gemini 4 Neon');
      const mName = scalar(context.activeModelLabel, 'Connected Frontier AI');
      modelField.textContent = `${voiceModel} (voice Q&A · trading: ${mName})`;
      subtitleField.textContent = 'Gemini 4 Neon · Real-Time Voice Explainer';
      if (promptLabel) promptLabel.textContent = 'Ask Gemini 4 Neon (voice or text)';
      promptInput.disabled = askBusy;
      promptInput.placeholder = isListening
        ? 'Listening… speak your question now'
        : 'Ask or tap Mic for a live spoken briefing…';
      askButton.hidden = false;
      askButton.disabled = askBusy;
      if (quickChipsWrap) {
        quickChipsWrap.hidden = false;
        for (const chip of quickChipsWrap.querySelectorAll('[data-explainer-quick-ask]')) {
          chip.disabled = askBusy;
        }
      }
      if (lockedBanner) lockedBanner.hidden = true;
      footerNote.textContent = voiceStatusNote
        ?? (askBusy
          ? `Asking ${voiceModel}…`
          : `Real-time voice & text explanations (${voiceModel}). Read-only — zero execution authority.`);
    } else {
      modelField.textContent = 'None — authored local guide';
      subtitleField.textContent = 'Local guide - no model';
      if (promptLabel) promptLabel.textContent = 'Ask a model';
      promptInput.disabled = true;
      promptInput.placeholder = 'No AI provider attached';
      askButton.hidden = true;
      askButton.disabled = true;
      if (quickChipsWrap) quickChipsWrap.hidden = true;
      if (lockedBanner) lockedBanner.hidden = false;
      footerNote.textContent = voiceStatusNote
        ?? 'AI explanations are unavailable. The local guide and all source records remain readable.';
    }
    updateVoiceControls();
  }

  function stopAudio({ silent = false } = {}) {
    speakGeneration += 1;
    if (activeBufferSource) {
      const src = activeBufferSource;
      activeBufferSource = null;
      try { src.onended = null; } catch { /* Ignore */ }
      try { src.stop(0); } catch { /* Already stopped */ }
      try { src.disconnect?.(); } catch { /* Ignore */ }
    }
    const synth = globalThis.window?.speechSynthesis ?? globalThis.speechSynthesis;
    try { synth?.cancel?.(); } catch { /* Ignore */ }
    isSpeaking = false;
    if (!silent && !destroyed) {
      say('Voice playback stopped.');
      updateVoiceControls();
    }
  }

  function unlockWebAudioSync() {
    if (destroyed) return;
    const AudioCtxCtor = globalThis.window?.AudioContext
      ?? globalThis.window?.webkitAudioContext
      ?? globalThis.AudioContext
      ?? globalThis.webkitAudioContext;
    if (typeof AudioCtxCtor !== 'function') return;
    try {
      if (!audioCtx) audioCtx = new AudioCtxCtor();
      if (audioCtx.state === 'suspended' && typeof audioCtx.resume === 'function') {
        void Promise.resolve(audioCtx.resume()).catch(() => {});
      }
    } catch { /* Best-effort synchronous iOS/Android gesture unlock. */ }
  }

  async function speakText(rawText) {
    const cleanText = String(rawText ?? '').trim().slice(0, 1800);
    if (!cleanText || destroyed) return;
    stopAudio({ silent: true });
    const myToken = speakGeneration;
    isSpeaking = true;
    updateVoiceControls();

    if (typeof synthesizeSpeech === 'function') {
      try {
        const ttsDoc = await synthesizeSpeech(cleanText, 'Kore');
        if (destroyed || myToken !== speakGeneration) return;
        if (ttsDoc && ttsDoc.ok === true && typeof ttsDoc.audio_base64 === 'string' && ttsDoc.audio_base64.length > 0) {
          const AudioCtxCtor = globalThis.window?.AudioContext
            ?? globalThis.window?.webkitAudioContext
            ?? globalThis.AudioContext
            ?? globalThis.webkitAudioContext;
          if (typeof AudioCtxCtor === 'function') {
            if (!audioCtx) audioCtx = new AudioCtxCtor();
            if (audioCtx.state === 'suspended' && typeof audioCtx.resume === 'function') {
              await audioCtx.resume().catch(() => {});
            }
            if (destroyed || myToken !== speakGeneration) return;
            const mime = String(ttsDoc.mime_type ?? 'audio/L16;rate=24000').toLowerCase();
            let audioBuffer;
            if (mime.includes('l16') || mime.includes('pcm')) {
              const floatSamples = decodePcm16LeBase64ToFloat32(ttsDoc.audio_base64);
              if (floatSamples.length === 0) throw new Error('Empty PCM sample stream.');
              const rate = parseSampleRateHz(ttsDoc);
              audioBuffer = audioCtx.createBuffer(1, floatSamples.length, rate);
              const ch0 = audioBuffer.getChannelData(0);
              ch0.set(floatSamples);
            } else {
              const bytes = decodeBase64ToBytes(ttsDoc.audio_base64);
              const sliced = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
              audioBuffer = await audioCtx.decodeAudioData(sliced);
            }
            if (destroyed || myToken !== speakGeneration) return;
            const sourceNode = audioCtx.createBufferSource();
            sourceNode.buffer = audioBuffer;
            sourceNode.connect(audioCtx.destination);
            activeBufferSource = sourceNode;
            sourceNode.onended = () => {
              if (activeBufferSource === sourceNode) activeBufferSource = null;
              if (myToken === speakGeneration) {
                isSpeaking = false;
                updateVoiceControls();
              }
            };
            sourceNode.start(0);
            say('Playing Gemini 4 Neon voice explanation.');
            updateVoiceControls();
            return;
          }
        }
      } catch {
        if (destroyed || myToken !== speakGeneration) return;
        // Fall through seamlessly to browser speechSynthesis fallback.
      }
    }

    if (destroyed || myToken !== speakGeneration) return;
    const synth = globalThis.window?.speechSynthesis ?? globalThis.speechSynthesis;
    const UtterCtor = globalThis.window?.SpeechSynthesisUtterance ?? globalThis.SpeechSynthesisUtterance;
    if (synth && typeof synth.speak === 'function') {
      try { synth.cancel?.(); } catch { /* Ignore */ }
      const utter = typeof UtterCtor === 'function' ? new UtterCtor(cleanText) : { text: cleanText };
      utter.rate = 1.02;
      utter.onend = () => {
        if (myToken === speakGeneration) {
          isSpeaking = false;
          updateVoiceControls();
        }
      };
      utter.onerror = () => {
        if (myToken === speakGeneration) {
          isSpeaking = false;
          updateVoiceControls();
        }
      };
      synth.speak(utter);
      say('Speaking explanation via browser voice fallback.');
      updateVoiceControls();
      return;
    }

    isSpeaking = false;
    updateVoiceControls();
  }

  function stopMicCaptureOnly() {
    if (activeRecognition) {
      const rec = activeRecognition;
      activeRecognition = null;
      try { rec.onresult = null; rec.onend = null; rec.onerror = null; } catch { /* Ignore */ }
      try { rec.abort?.(); } catch { /* Ignore */ }
      try { rec.stop?.(); } catch { /* Ignore */ }
    }
    if (activeMediaRecorder) {
      const mr = activeMediaRecorder;
      activeMediaRecorder = null;
      try { mr.ondataavailable = null; mr.onstop = null; mr.onerror = null; } catch { /* Ignore */ }
      try { if (mr.state !== 'inactive') mr.stop?.(); } catch { /* Ignore */ }
    }
    if (activeMediaStream) {
      const stream = activeMediaStream;
      activeMediaStream = null;
      try { stream.getTracks?.().forEach((t) => t.stop?.()); } catch { /* Ignore */ }
    }
    isListening = false;
  }

  async function submitQuestion({ overrideQuestion = null, extraAudio = null, forceSpeak = false } = {}) {
    const context = getContext() || {};
    if (!context.aiConnected || typeof askModel !== 'function' || askBusy) return;
    const rawQ = overrideQuestion !== null ? overrideQuestion : promptInput.value;
    const q = String(rawQ ?? '').trim() || (extraAudio ? 'Voice question' : '');
    if (!q) return;
    voiceStatusNote = null;
    askBusy = true;
    lastAskedQuestion = q;
    updateContent();
    let shouldSpeak = false;
    try {
      const hasAudio = Boolean(
        extraAudio
        && typeof extraAudio === 'object'
        && typeof extraAudio.audio_base64 === 'string'
        && extraAudio.audio_base64.length > 0
      );
      const reply = hasAudio ? await askModel(q, extraAudio) : await askModel(q);
      if (reply && typeof reply === 'object' && typeof reply.spoken_question === 'string' && reply.spoken_question.trim()) {
        lastAskedQuestion = reply.spoken_question.trim();
      }
      askAnswer = scalar(typeof reply === 'string' ? reply : reply?.answer, 'No answer text returned.');
      answerMode = 'ask';
      promptInput.value = '';
      shouldSpeak = Boolean((autoSpeak || forceSpeak) && askAnswer);
      say('Live AI explanation updated (read-only).');
    } catch (err) {
      answerMode = 'ask';
      askAnswer = err instanceof Error ? err.message : 'Unable to reach live Explainer endpoint.';
      say('Live AI explanation request failed.');
    } finally {
      askBusy = false;
      updateContent();
    }
    if (shouldSpeak && !destroyed) {
      await speakText(askAnswer);
    }
  }

  async function toggleMicrophone() {
    const context = getContext() || {};
    if (!context.aiConnected || typeof askModel !== 'function') return;

    if (isListening) {
      if (activeRecognition) {
        try { activeRecognition.stop(); } catch { stopMicCaptureOnly(); updateContent(); }
        return;
      }
      if (activeMediaRecorder && activeMediaRecorder.state !== 'inactive') {
        try { activeMediaRecorder.stop(); } catch { stopMicCaptureOnly(); updateContent(); }
        return;
      }
      stopMicCaptureOnly();
      updateContent();
      return;
    }

    autoSpeak = true;
    persistAutoSpeak();
    stopAudio({ silent: true });
    voiceStatusNote = null;

    const SpeechRecCtor = globalThis.window?.SpeechRecognition
      ?? globalThis.window?.webkitSpeechRecognition
      ?? globalThis.SpeechRecognition
      ?? globalThis.webkitSpeechRecognition;

    if (typeof SpeechRecCtor === 'function') {
      try {
        const rec = new SpeechRecCtor();
        rec.lang = 'en-US';
        rec.interimResults = true;
        rec.continuous = false;
        let capturedTranscript = '';
        let submitted = false;
        activeRecognition = rec;
        isListening = true;
        voiceStatusNote = 'Listening… speak your question clearly.';
        updateContent();

        rec.onresult = (ev) => {
          const parts = [];
          const list = ev?.results ?? [];
          for (let i = 0; i < list.length; i += 1) {
            const alt = list[i]?.[0] ?? list[i];
            const piece = typeof alt?.transcript === 'string' ? alt.transcript : '';
            if (piece) parts.push(piece);
          }
          const combined = parts.join(' ').trim();
          if (combined) {
            capturedTranscript = combined;
            promptInput.value = combined;
          }
        };

        rec.onerror = (ev) => {
          submitted = true;
          if (activeRecognition === rec) activeRecognition = null;
          isListening = false;
          const code = String(ev?.error ?? 'unavailable');
          voiceStatusNote = code === 'not-allowed' || code === 'service-not-allowed'
            ? 'Microphone permission denied. Allow mic access, or tap the prompt box and use your phone keyboard microphone.'
            : `Voice recognition unavailable (${code}). You can also use your phone keyboard microphone or type below.`;
          updateContent();
        };

        rec.onend = () => {
          if (activeRecognition === rec) activeRecognition = null;
          isListening = false;
          voiceStatusNote = null;
          const spoken = String(capturedTranscript || promptInput.value || '').trim();
          if (!destroyed && !submitted && spoken) {
            submitted = true;
            promptInput.value = spoken;
            void submitQuestion({ overrideQuestion: spoken, forceSpeak: true });
          } else {
            updateContent();
          }
        };

        rec.start();
        say('Listening for your spoken question.');
        return;
      } catch {
        stopMicCaptureOnly();
      }
    }

    const mediaDevices = globalThis.navigator?.mediaDevices ?? globalThis.window?.navigator?.mediaDevices;
    const RecorderCtor = globalThis.window?.MediaRecorder ?? globalThis.MediaRecorder;
    if (mediaDevices && typeof mediaDevices.getUserMedia === 'function' && typeof RecorderCtor === 'function') {
      try {
        const stream = await mediaDevices.getUserMedia({ audio: true });
        if (destroyed) {
          stream.getTracks?.().forEach((t) => t.stop?.());
          return;
        }
        const preferredMime = ALLOWED_AUDIO_MIMES.find(
          (m) => typeof RecorderCtor.isTypeSupported !== 'function' || RecorderCtor.isTypeSupported(m)
        ) || 'audio/webm';
        const recorder = new RecorderCtor(stream, { mimeType: preferredMime });
        const chunks = [];
        activeMediaStream = stream;
        activeMediaRecorder = recorder;
        isListening = true;
        voiceStatusNote = 'Recording voice clip… tap Mic again to send to Gemini 4 Neon.';
        updateContent();

        recorder.ondataavailable = (ev) => {
          if (ev?.data && ev.data.size > 0) chunks.push(ev.data);
        };
        recorder.onerror = () => {
          stopMicCaptureOnly();
          voiceStatusNote = 'Audio recording interrupted. Type your question below.';
          updateContent();
        };
        recorder.onstop = async () => {
          const usedMime = String(recorder.mimeType || preferredMime).split(';')[0].trim().toLowerCase();
          const safeMime = ALLOWED_AUDIO_MIMES.includes(usedMime) ? usedMime : 'audio/webm';
          stopMicCaptureOnly();
          voiceStatusNote = null;
          try {
            let totalLen = 0;
            const partArrays = [];
            for (const c of chunks) {
              const ab = await c.arrayBuffer();
              const arr = new Uint8Array(ab);
              partArrays.push(arr);
              totalLen += arr.byteLength;
            }
            if (totalLen > 0 && !destroyed) {
              const merged = new Uint8Array(totalLen);
              let offset = 0;
              for (const arr of partArrays) {
                merged.set(arr, offset);
                offset += arr.byteLength;
              }
              const audioBase64 = encodeBytesToBase64(merged);
              await submitQuestion({
                overrideQuestion: String(promptInput.value ?? '').trim() || 'Voice question',
                extraAudio: { audio_base64: audioBase64, audio_mime_type: safeMime },
                forceSpeak: true,
              });
              return;
            }
          } catch {
            voiceStatusNote = 'Unable to encode recorded voice clip.';
          }
          updateContent();
        };
        recorder.start();
        say('Recording voice question.');
        return;
      } catch {
        stopMicCaptureOnly();
        voiceStatusNote = 'Microphone permission denied or unavailable. You can also tap the prompt box and use your phone keyboard microphone.';
        updateContent();
        return;
      }
    }

    voiceStatusNote = 'In-page SpeechRecognition is unavailable in this mobile WebView — tap the prompt box and use your phone keyboard microphone, or type below.';
    updateContent();
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
  promptInput.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); unlockWebAudioSync(); void submitQuestion(); } });
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
    if (button.dataset.explainerTopic) {
      selectedTopic = button.dataset.explainerTopic;
      answerMode = 'local';
      updateContent();
      say('Local guide answer updated. No model was called.');
      return;
    }
    const quickQ = button.getAttribute('data-explainer-quick-ask');
    if (quickQ) {
      unlockWebAudioSync();
      void submitQuestion({ overrideQuestion: quickQ });
      return;
    }
    if (button.hasAttribute('data-explainer-goto-unlock')) {
      if (!wide.matches) setOpen(false);
      const topUnlock = document.querySelector('#top-cockpit-access-key') ?? document.querySelector('input[name="cockpit_access_key"]');
      if (topUnlock) {
        try { topUnlock.scrollIntoView?.({ block: 'center', behavior: 'auto' }); } catch { /* Optional */ }
        topUnlock.focus({ preventScroll: true });
      }
      say('Moved focus to the Cockpit access key unlock bar.');
      return;
    }
    if (button.hasAttribute('data-explainer-ask-submit')) {
      unlockWebAudioSync();
      void submitQuestion();
      return;
    }
    if (button.hasAttribute('data-explainer-mic')) {
      unlockWebAudioSync();
      void toggleMicrophone();
      return;
    }
    if (button.hasAttribute('data-explainer-autospeak')) {
      unlockWebAudioSync();
      autoSpeak = !autoSpeak;
      persistAutoSpeak();
      updateVoiceControls();
      say(autoSpeak ? 'Auto-speak enabled.' : 'Auto-speak disabled.');
      return;
    }
    if (button.hasAttribute('data-explainer-speak')) {
      if (isSpeaking) stopAudio();
      else {
        unlockWebAudioSync();
        const currentText = host.querySelector('.forex-explainer-answer')?.textContent ?? '';
        void speakText(currentText);
      }
      return;
    }
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
    stopMicCaptureOnly();
    stopAudio({ silent: true });
    if (audioCtx) {
      const ctx = audioCtx;
      audioCtx = null;
      try { void ctx.close?.(); } catch { /* Ignore */ }
    }
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
    open({ focusPrompt = false } = {}) {
      if (destroyed) return;
      unlockWebAudioSync();
      setOpen(true, { focus: !focusPrompt });
      if (focusPrompt && !promptInput.disabled) {
        promptInput.focus({ preventScroll: true });
      }
    },
    destroy,
  });
}
