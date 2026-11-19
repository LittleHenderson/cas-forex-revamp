// PR #18 UI regression suite: Gemini 4 Neon Real-Time Voice Explainer,
// PCM16LE base64 Web Audio decoding, SpeechRecognition hands-free mic flow,
// Web Speech fallback, 1-tap quick-ask chips, and strict CSP compliance.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  EXPLAINER_QUICK_QUESTIONS,
  createExplainer,
  decodePcm16LeBase64ToFloat32,
} from '../../ui/src/explainer.mjs';
import { fixture } from './helpers.mjs';

function decodeHtmlEntities(str) {
  return String(str)
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&');
}

function toCamelDatasetKey(attrName) {
  return attrName
    .slice(5)
    .replace(/-([a-z0-9])/gi, (_, ch) => ch.toUpperCase());
}

function matchesSimpleSelector(el, selector) {
  if (!el || el.nodeType !== 1) return false;
  let rest = selector.trim();
  if (!rest) return false;

  const tagMatch = /^[a-zA-Z][a-zA-Z0-9-]*/.exec(rest);
  if (tagMatch) {
    if (el.tagName !== tagMatch[0].toUpperCase()) return false;
    rest = rest.slice(tagMatch[0].length);
  }

  const tokenRe = /#([A-Za-z0-9_-]+)|\.([A-Za-z0-9_-]+)|\[([A-Za-z0-9_:-]+)(?:="([^"]*)")?\]/g;
  let consumed = 0;
  let m;
  while ((m = tokenRe.exec(rest)) !== null) {
    if (m.index !== consumed) return false;
    consumed += m[0].length;
    if (m[1]) {
      if (el.id !== m[1]) return false;
    } else if (m[2]) {
      if (!el.classList.contains(m[2])) return false;
    } else if (m[3]) {
      const attr = m[3].toLowerCase();
      if (!el.hasAttribute(attr)) return false;
      if (m[4] !== undefined && el.getAttribute(attr) !== m[4]) return false;
    }
  }
  return consumed === rest.length;
}

function matchesSelectorChain(el, fullSelector) {
  const parts = fullSelector.trim().split(/\s+/);
  let cur = el;
  for (let i = parts.length - 1; i >= 0; i -= 1) {
    if (i === parts.length - 1) {
      if (!matchesSimpleSelector(cur, parts[i])) return false;
    } else {
      let anc = cur.parentNode;
      while (anc && !matchesSimpleSelector(anc, parts[i])) {
        anc = anc.parentNode;
      }
      if (!anc) return false;
      cur = anc;
    }
  }
  return true;
}

class MockNode {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.parentNode = null;
    this.childNodes = [];
  }
  remove() {
    if (!this.parentNode) return;
    const idx = this.parentNode.childNodes.indexOf(this);
    if (idx !== -1) this.parentNode.childNodes.splice(idx, 1);
    this.parentNode = null;
  }
}

class MockTextNode extends MockNode {
  constructor(text = '') {
    super(3);
    this._text = String(text);
  }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v ?? ''); }
}

class MockElement extends MockNode {
  constructor(tagName) {
    super(1);
    this.tagName = String(tagName).toUpperCase();
    this.attrs = new Map();
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.value = '';
    this.tabIndex = -1;
    const self = this;
    this.classList = {
      _set() {
        const cls = self.attrs.get('class') || '';
        return new Set(cls.split(/\s+/).filter(Boolean));
      },
      _sync(set) {
        const joined = [...set].join(' ');
        if (joined) self.attrs.set('class', joined);
        else self.attrs.delete('class');
      },
      add(...names) {
        const s = this._set();
        names.forEach((n) => { if (n) s.add(n); });
        this._sync(s);
      },
      remove(...names) {
        const s = this._set();
        names.forEach((n) => s.delete(n));
        this._sync(s);
      },
      toggle(name, force) {
        const s = this._set();
        const next = force !== undefined ? Boolean(force) : !s.has(name);
        if (next) s.add(name);
        else s.delete(name);
        this._sync(s);
        return next;
      },
      contains(name) {
        return this._set().has(name);
      },
    };
  }

  get id() { return this.attrs.get('id') ?? ''; }
  set id(v) { if (v) this.attrs.set('id', String(v)); else this.attrs.delete('id'); }

  get className() { return this.attrs.get('class') ?? ''; }
  set className(v) { if (v) this.attrs.set('class', String(v)); else this.attrs.delete('class'); }

  get hidden() { return this.attrs.has('hidden'); }
  set hidden(v) { if (v) this.attrs.set('hidden', ''); else this.attrs.delete('hidden'); }

  get disabled() { return this.attrs.has('disabled'); }
  set disabled(v) { if (v) this.attrs.set('disabled', ''); else this.attrs.delete('disabled'); }

  get placeholder() { return this.attrs.get('placeholder') ?? ''; }
  set placeholder(v) { this.attrs.set('placeholder', String(v ?? '')); }

  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }
  set textContent(v) {
    this.childNodes = v === '' || v === null || v === undefined ? [] : [new MockTextNode(String(v))];
    for (const c of this.childNodes) c.parentNode = this;
  }

  setAttribute(name, val) {
    const lower = String(name).toLowerCase();
    const strVal = String(val);
    this.attrs.set(lower, strVal);
    if (lower.startsWith('data-')) {
      this.dataset[toCamelDatasetKey(lower)] = strVal;
    }
  }
  getAttribute(name) {
    const lower = String(name).toLowerCase();
    return this.attrs.has(lower) ? this.attrs.get(lower) : null;
  }
  hasAttribute(name) {
    return this.attrs.has(String(name).toLowerCase());
  }
  removeAttribute(name) {
    const lower = String(name).toLowerCase();
    this.attrs.delete(lower);
    if (lower.startsWith('data-')) delete this.dataset[toCamelDatasetKey(lower)];
  }

  append(...nodes) {
    for (const n of nodes) {
      const child = typeof n === 'string' ? new MockTextNode(n) : n;
      if (child.parentNode) child.remove();
      child.parentNode = this;
      this.childNodes.push(child);
    }
  }
  replaceChildren(...nodes) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    this.append(...nodes);
  }
  insertBefore(newNode, refNode) {
    if (newNode.parentNode) newNode.remove();
    const idx = this.childNodes.indexOf(refNode);
    newNode.parentNode = this;
    if (idx === -1) this.childNodes.push(newNode);
    else this.childNodes.splice(idx, 0, newNode);
    return newNode;
  }
  replaceWith(newNode) {
    if (!this.parentNode) return;
    const p = this.parentNode;
    const idx = p.childNodes.indexOf(this);
    if (newNode.parentNode) newNode.remove();
    newNode.parentNode = p;
    if (idx !== -1) p.childNodes.splice(idx, 1, newNode);
    this.parentNode = null;
  }

  querySelectorAll(selector) {
    const results = [];
    const visit = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType === 1) {
          if (matchesSelectorChain(child, selector)) results.push(child);
          visit(child);
        }
      }
    };
    visit(this);
    return results;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] ?? null;
  }
  closest(selector) {
    let cur = this;
    while (cur && cur.nodeType === 1) {
      if (matchesSelectorChain(cur, selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
  }
  removeEventListener(type, fn) {
    this.listeners.get(type)?.delete(fn);
  }
  dispatchEvent(ev) {
    const eventObj = {
      target: this,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      ...ev,
    };
    let cur = this;
    while (cur && cur.nodeType === 1) {
      const fns = cur.listeners.get(eventObj.type);
      if (fns) {
        for (const fn of [...fns]) fn(eventObj);
      }
      cur = cur.parentNode;
    }
    return !eventObj.defaultPrevented;
  }
  click() {
    if (this.disabled) return;
    this.dispatchEvent({ type: 'click', target: this });
  }
  focus() {}
  scrollTo() {}
  scrollIntoView() {}
  getBoundingClientRect() { return { left: 0, top: 0, width: 48, height: 48 }; }
  setPointerCapture() {}
  hasPointerCapture() { return false; }
  releasePointerCapture() {}
}

const VOID_TAGS = new Set(['INPUT', 'IMG', 'BR', 'HR', 'META', 'LINK']);

function parseHtmlFragment(markup) {
  const rootBody = new MockElement('body');
  const stack = [rootBody];
  const tagRe = /<!--[\s\S]*?-->|<\/([A-Za-z0-9-]+)\s*>|<([A-Za-z0-9-]+)([^>]*)>|([^<]+)/g;
  let m;
  while ((m = tagRe.exec(String(markup))) !== null) {
    if (m[1]) {
      const closeTag = m[1].toUpperCase();
      while (stack.length > 1 && stack[stack.length - 1].tagName !== closeTag) {
        stack.pop();
      }
      if (stack.length > 1) stack.pop();
    } else if (m[2]) {
      const el = new MockElement(m[2]);
      const rawAttrs = m[3] || '';
      const attrRe = /([A-Za-z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
      let am;
      while ((am = attrRe.exec(rawAttrs)) !== null) {
        const attrName = am[1];
        if (attrName === '/') continue;
        const val = am[2] ?? am[3] ?? am[4] ?? '';
        el.setAttribute(attrName, decodeHtmlEntities(val));
      }
      stack[stack.length - 1].append(el);
      const selfClosing = rawAttrs.trim().endsWith('/') || VOID_TAGS.has(el.tagName);
      if (!selfClosing) stack.push(el);
    } else if (m[4]) {
      const text = decodeHtmlEntities(m[4]);
      if (text) stack[stack.length - 1].append(new MockTextNode(text));
    }
  }
  return rootBody;
}

function createMemoryStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
  };
}

function installExplainerEnv(extraGlobals = {}) {
  const saved = new Map();
  const keys = [
    'window', 'document', 'DOMParser', 'localStorage', 'sessionStorage',
    'AudioContext', 'SpeechRecognition', 'speechSynthesis', 'SpeechSynthesisUtterance',
  ];
  for (const k of keys) {
    saved.set(k, Object.getOwnPropertyDescriptor(globalThis, k));
  }

  const htmlEl = new MockElement('html');
  htmlEl.clientWidth = 1440;
  const bodyEl = new MockElement('body');
  const appEl = new MockElement('div');
  appEl.id = 'app';
  bodyEl.append(appEl);
  htmlEl.append(bodyEl);

  const docListeners = new Map();
  const mockDoc = {
    documentElement: htmlEl,
    body: bodyEl,
    createElement: (tag) => new MockElement(tag),
    querySelector: (sel) => htmlEl.querySelector(sel),
    querySelectorAll: (sel) => htmlEl.querySelectorAll(sel),
    getElementById: (id) => htmlEl.querySelector(`#${id}`),
    addEventListener: (t, fn) => {
      if (!docListeners.has(t)) docListeners.set(t, new Set());
      docListeners.get(t).add(fn);
    },
    removeEventListener: (t, fn) => { docListeners.get(t)?.delete(fn); },
  };

  const localStore = createMemoryStorage();
  const sessionStore = createMemoryStorage();
  const mockWin = {
    scrollX: 0,
    scrollY: 0,
    innerHeight: 900,
    scrollTo: () => {},
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    addEventListener: () => {},
    removeEventListener: () => {},
    matchMedia: () => ({ matches: true, addEventListener: () => {}, removeEventListener: () => {} }),
    localStorage: localStore,
    sessionStorage: sessionStore,
    ...extraGlobals,
  };

  class MockDOMParser {
    parseFromString(markup) {
      return { body: parseHtmlFragment(markup) };
    }
  }

  Object.defineProperty(globalThis, 'document', { value: mockDoc, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'window', { value: mockWin, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'DOMParser', { value: MockDOMParser, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'localStorage', { value: localStore, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'sessionStorage', { value: sessionStore, configurable: true, writable: true });
  for (const [k, v] of Object.entries(extraGlobals)) {
    Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  }

  return {
    doc: mockDoc,
    win: mockWin,
    restore() {
      for (const [k, desc] of saved.entries()) {
        if (desc) Object.defineProperty(globalThis, k, desc);
        else delete globalThis[k];
      }
    },
  };
}

function encodeInt16SamplesBase64(int16Values) {
  const buf = Buffer.alloc(int16Values.length * 2);
  int16Values.forEach((v, idx) => buf.writeInt16LE(v, idx * 2));
  return buf.toString('base64');
}

async function flushAsync() {
  for (let i = 0; i < 6; i += 1) {
    await Promise.resolve();
  }
}

test('VE01 decodePcm16LeBase64ToFloat32 converts signed 16-bit little-endian PCM bytes with exact math', () => {
  assert.equal(decodePcm16LeBase64ToFloat32('').length, 0);

  const rawSamples = [0, 16384, -16384, -32768, 32767];
  const b64 = encodeInt16SamplesBase64(rawSamples);
  const spaced = `  ${b64.slice(0, 6)}\n${b64.slice(6)}  `;
  const floats = decodePcm16LeBase64ToFloat32(spaced);

  assert.equal(floats instanceof Float32Array, true);
  assert.equal(floats.length, 5);
  assert.equal(floats[0], 0);
  assert.equal(floats[1], 0.5);
  assert.equal(floats[2], -0.5);
  assert.equal(floats[3], -1);
  assert.equal(floats[4], Math.fround(32767 / 32768));

  // Trailing odd byte is safely ignored without throwing
  const oddB64 = Buffer.from([0x00, 0x40, 0xff]).toString('base64');
  const oddFloats = decodePcm16LeBase64ToFloat32(oddB64);
  assert.equal(oddFloats.length, 1);
  assert.equal(oddFloats[0], 0.5);
});

test('VE02 Explainer subtitle switches between Local guide - no model and Gemini 4 Neon · Real-Time Voice Explainer', () => {
  const env = installExplainerEnv();
  let connected = false;
  let exp = null;
  try {
    exp = createExplainer({
      getContext: () => ({
        projection: fixture(),
        route: 'operate',
        source: 'shared fixture',
        aiConnected: connected,
        voiceExplainerModel: 'Gemini 4 Neon',
        activeModelLabel: 'Claude Fable 5.2',
      }),
      askModel: async () => ({ answer: 'Stub' }),
    });

    const mark = env.doc.querySelector('.forex-explainer-mark');
    mark.click(); // Open panel

    const subtitle = env.doc.querySelector('[data-guide-subtitle]');
    const modelDd = env.doc.querySelector('[data-guide-model]');
    const promptInput = env.doc.querySelector('#forex-explainer-prompt');
    const quickChips = env.doc.querySelector('.forex-explainer-quick-chips');
    const micBtn = env.doc.querySelector('[data-explainer-mic]');

    assert.equal(subtitle.textContent, 'Local guide - no model');
    assert.equal(modelDd.textContent, 'None — authored local guide');
    assert.equal(promptInput.disabled, true);
    assert.equal(quickChips.hidden, true);
    assert.equal(micBtn.disabled, true);

    connected = true;
    exp.sync();

    assert.equal(subtitle.textContent, 'Gemini 4 Neon · Real-Time Voice Explainer');
    assert.match(modelDd.textContent, /Gemini 4 Neon/);
    assert.equal(promptInput.disabled, false);
    assert.equal(quickChips.hidden, false);
    assert.equal(micBtn.disabled, false);
  } finally {
    exp?.destroy();
    env.restore();
  }
});

test('VE03 Simulated SpeechRecognition mic capture auto-asks Gemini 4 Neon, plays Web Audio PCM16, and Stop Audio cancels', async () => {
  let activeRecInstance = null;
  class FakeSpeechRecognition {
    constructor() {
      this.lang = '';
      this.interimResults = false;
      this.continuous = false;
      this.started = false;
      activeRecInstance = this;
    }
    start() { this.started = true; }
    stop() { this.onend?.(); }
    abort() {}
  }

  const audioEvents = { createdBuffers: [], startedSources: 0, stoppedSources: 0 };
  class FakeAudioContext {
    constructor() {
      this.state = 'running';
      this.destination = { kind: 'speakers' };
    }
    createBuffer(channels, length, sampleRate) {
      const ch0 = new Float32Array(length);
      const buf = {
        channels,
        length,
        sampleRate,
        data: ch0,
        getChannelData: () => ch0,
      };
      audioEvents.createdBuffers.push(buf);
      return buf;
    }
    createBufferSource() {
      return {
        buffer: null,
        onended: null,
        connect() {},
        disconnect() {},
        start() { audioEvents.startedSources += 1; },
        stop() { audioEvents.stoppedSources += 1; },
      };
    }
    async close() {}
  }

  const askedCalls = [];
  const ttsCalls = [];
  const pcmBase64 = encodeInt16SamplesBase64([0, 16384, -16384, 8192]);

  const env = installExplainerEnv({
    SpeechRecognition: FakeSpeechRecognition,
    AudioContext: FakeAudioContext,
  });
  let exp = null;
  try {
    exp = createExplainer({
      getContext: () => ({
        projection: fixture(),
        route: 'operate',
        source: 'Live server stream',
        aiConnected: true,
        voiceExplainerModel: 'Gemini 4 Neon',
        activeModelLabel: 'Claude Fable 5.2',
      }),
      askModel: async (...args) => {
        askedCalls.push(args);
        return {
          schema: 'cas-forex.explainer-answer/1',
          spoken_question: 'How are my open NAS100 trades doing?',
          answer: 'Your NAS100 sleeve is protected at breakeven with 50% Bank Vault sweeps active.',
        };
      },
      synthesizeSpeech: async (text, voiceName) => {
        ttsCalls.push({ text, voiceName });
        return {
          schema: 'cas-forex.explainer-tts/1',
          ok: true,
          model_id: 'gemini-3.8-flash-tts',
          voice_name: voiceName,
          mime_type: 'audio/L16;rate=24000',
          sample_rate_hz: 24000,
          audio_base64: pcmBase64,
        };
      },
    });

    env.doc.querySelector('.forex-explainer-mark').click();
    const micBtn = env.doc.querySelector('[data-explainer-mic]');
    const speakBtn = env.doc.querySelector('[data-explainer-speak]');
    const promptInput = env.doc.querySelector('#forex-explainer-prompt');

    micBtn.click();
    assert.ok(activeRecInstance?.started);
    assert.equal(micBtn.classList.contains('is-listening'), true);
    assert.match(micBtn.textContent, /Listening/);

    activeRecInstance.onresult({
      results: [[{ transcript: 'How are my open NAS100 trades' }]],
    });
    assert.equal(promptInput.value, 'How are my open NAS100 trades');

    activeRecInstance.onend();
    await flushAsync();

    assert.equal(askedCalls.length, 1);
    assert.equal(askedCalls[0].length, 1); // 1-arg backward-compatible call when no raw audio blob
    assert.equal(askedCalls[0][0], 'How are my open NAS100 trades');
    assert.equal(env.doc.querySelector('.forex-explainer-question').textContent, 'How are my open NAS100 trades doing?');
    assert.match(env.doc.querySelector('.forex-explainer-answer').textContent, /50% Bank Vault sweeps active/);

    assert.equal(ttsCalls.length, 1);
    assert.equal(ttsCalls[0].voiceName, 'Kore');
    assert.equal(audioEvents.createdBuffers.length, 1);
    assert.equal(audioEvents.createdBuffers[0].sampleRate, 24000);
    assert.equal(audioEvents.createdBuffers[0].data[1], 0.5);
    assert.equal(audioEvents.startedSources, 1);
    assert.equal(speakBtn.classList.contains('is-speaking'), true);
    assert.equal(speakBtn.textContent, 'Stop Audio');

    // Clicking Stop Audio cancels playback immediately
    speakBtn.click();
    assert.equal(audioEvents.stoppedSources, 1);
    assert.equal(speakBtn.classList.contains('is-speaking'), false);
    assert.equal(speakBtn.textContent, 'Speak Answer');
  } finally {
    exp?.destroy();
    env.restore();
  }
});

test('VE04 Graceful speechSynthesis fallback when synthesizeSpeech returns ok: false, plus clean destroy()', async () => {
  const spokenUtterances = [];
  let cancelCount = 0;
  class FakeUtterance {
    constructor(text) {
      this.text = text;
      this.rate = 1;
      this.onend = null;
      this.onerror = null;
    }
  }
  const fakeSpeechSynthesis = {
    speak(u) { spokenUtterances.push(u); },
    cancel() { cancelCount += 1; },
  };

  const env = installExplainerEnv({
    speechSynthesis: fakeSpeechSynthesis,
    SpeechSynthesisUtterance: FakeUtterance,
  });
  let exp = null;
  try {
    exp = createExplainer({
      getContext: () => ({
        projection: fixture(),
        route: 'operate',
        source: 'Live server stream',
        aiConnected: true,
        voiceExplainerModel: 'Gemini 4 Neon',
      }),
      askModel: async (q) => ({ answer: `Fallback spoken briefing for: ${q}` }),
      synthesizeSpeech: async () => ({
        schema: 'cas-forex.explainer-tts/1',
        ok: false,
        fallback: 'WEB_SPEECH',
        reason: 'Key absent in offline test',
      }),
    });

    env.doc.querySelector('.forex-explainer-mark').click();
    const promptInput = env.doc.querySelector('#forex-explainer-prompt');
    const askBtn = env.doc.querySelector('[data-explainer-ask-submit]');
    promptInput.value = 'Summarize risk gear';
    askBtn.click();
    await flushAsync();

    assert.equal(spokenUtterances.length, 1);
    assert.match(spokenUtterances[0].text, /Fallback spoken briefing for: Summarize risk gear/);
    assert.equal(env.doc.querySelector('[data-explainer-speak]').classList.contains('is-speaking'), true);

    exp.destroy();
    exp = null;
    assert.ok(cancelCount >= 1);
  } finally {
    exp?.destroy();
    env.restore();
  }
});

test('VE05 1-tap quick-ask chips and Auto-Speak toggle operate cleanly', async () => {
  const asked = [];
  let ttsCount = 0;
  const env = installExplainerEnv();
  let exp = null;
  try {
    exp = createExplainer({
      getContext: () => ({
        projection: fixture(),
        route: 'operate',
        source: 'Live server stream',
        aiConnected: true,
        voiceExplainerModel: 'Gemini 4 Neon',
      }),
      askModel: async (q) => {
        asked.push(q);
        return { answer: `Answered: ${q}` };
      },
      synthesizeSpeech: async () => {
        ttsCount += 1;
        return { ok: false, fallback: 'WEB_SPEECH' };
      },
    });

    env.doc.querySelector('.forex-explainer-mark').click();
    const chips = env.doc.querySelectorAll('[data-explainer-quick-ask]');
    assert.equal(chips.length, 4);
    assert.deepEqual(
      chips.map((c) => c.getAttribute('data-explainer-quick-ask')),
      [...EXPLAINER_QUICK_QUESTIONS]
    );

    // Toggle Auto-Speak OFF before tapping a quick chip
    const autoBtn = env.doc.querySelector('[data-explainer-autospeak]');
    assert.equal(autoBtn.getAttribute('aria-pressed'), 'true');
    autoBtn.click();
    assert.equal(autoBtn.getAttribute('aria-pressed'), 'false');

    chips[0].click();
    await flushAsync();

    assert.deepEqual(asked, ['Give me a full live status briefing']);
    assert.equal(ttsCount, 0);
    assert.match(env.doc.querySelector('.forex-explainer-answer').textContent, /Give me a full live status briefing/);
  } finally {
    exp?.destroy();
    env.restore();
  }
});

test('VE06 Strict CSP & zero-jump preservation across explainer.mjs, app.mjs, and explainer.css', async () => {
  const explainerSrc = await readFile(new URL('../../ui/src/explainer.mjs', import.meta.url), 'utf8');
  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  const cssSrc = await readFile(new URL('../../ui/explainer.css', import.meta.url), 'utf8');

  const audioTagRe = new RegExp('<' + 'audio\\b', 'i');
  const newAudioRe = new RegExp('\\bnew\\s+' + 'Audio\\s*\\(');
  const objUrlRe = new RegExp('create' + 'ObjectURL');
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;

  for (const [name, src] of [
    ['ui/src/explainer.mjs', explainerSrc],
    ['ui/src/app.mjs', appSrc],
    ['ui/explainer.css', cssSrc],
  ]) {
    assert.equal(audioTagRe.test(src), false, `Media tag forbidden by CSP in ${name}`);
    assert.equal(newAudioRe.test(src), false, `Audio constructor forbidden by CSP in ${name}`);
    assert.equal(objUrlRe.test(src), false, `Blob object URL forbidden by CSP in ${name}`);
    assert.equal(innerHtmlRe.test(src), false, `innerHTML/outerHTML forbidden in ${name}`);
    assert.equal(inlineStyleRe.test(src), false, `Inline style attribute forbidden in ${name}`);
  }

  assert.match(appSrc, /voiceExplainerModel:\s*'Gemini 4 Neon'/);
  assert.match(appSrc, /\/api\/explainer-tts/);
  assert.match(appSrc, /audio_base64/);
  assert.match(appSrc, /audio_mime_type/);
  assert.match(appSrc, /function rerenderMoneyFlowInPlace\(/);
  assert.match(appSrc, /function rerenderLiveFundingInPlace\(/);

  assert.match(cssSrc, /\.forex-explainer-voice-bar/);
  assert.match(cssSrc, /min-height:\s*44px/);
  assert.match(cssSrc, /\[data-explainer-mic\]\.is-listening/);
  assert.match(cssSrc, /\[data-explainer-speak\]\.is-speaking/);
  assert.match(cssSrc, /\[data-explainer-autospeak\]\[aria-pressed="true"\]/);
  assert.match(cssSrc, /\.forex-explainer-quick-chips/);
});

test('VE07 Mobile PWA iOS/Android synchronous AudioContext resume on tap before async TTS settles + WebView keyboard mic hint', async () => {
  let constructedSync = 0;
  let resumedSync = 0;
  class SuspendedMobileAudioContext {
    constructor() {
      constructedSync += 1;
      this.state = 'suspended';
      this.destination = {};
    }
    resume() {
      resumedSync += 1;
      this.state = 'running';
      return Promise.resolve();
    }
    createBuffer(_ch, len) {
      const ch0 = new Float32Array(len);
      return { getChannelData: () => ch0 };
    }
    createBufferSource() {
      return {
        buffer: null,
        onended: null,
        connect() {},
        disconnect() {},
        start() {},
        stop() {},
      };
    }
    async close() {}
  }

  let resolveAsk = null;
  let askSettled = false;
  const deferredAsk = new Promise((res) => { resolveAsk = res; });

  const env = installExplainerEnv({ AudioContext: SuspendedMobileAudioContext });
  let exp = null;
  try {
    exp = createExplainer({
      getContext: () => ({
        projection: fixture(),
        route: 'operate',
        source: 'Live server stream',
        aiConnected: true,
        voiceExplainerModel: 'Gemini 4 Neon',
      }),
      askModel: async () => {
        const out = await deferredAsk;
        askSettled = true;
        return out;
      },
      synthesizeSpeech: async () => ({
        ok: true,
        mime_type: 'audio/L16;rate=24000',
        sample_rate_hz: 24000,
        audio_base64: encodeInt16SamplesBase64([0, 8192]),
      }),
    });

    env.doc.querySelector('.forex-explainer-mark').click();

    // Also verify WebView without SpeechRecognition shows friendly phone keyboard mic hint on Mic tap
    const micBtn = env.doc.querySelector('[data-explainer-mic]');
    micBtn.click();
    // Synchronous Web Audio unlock already ran inside micBtn.click()!
    assert.equal(constructedSync, 1);
    assert.equal(resumedSync, 1);
    assert.match(env.doc.querySelector('#forex-explainer-unavailable').textContent, /phone keyboard microphone/);

    // Reset state to 'suspended' on a fresh context check via quick-ask tap while askModel is still pending
    const chip = env.doc.querySelector('[data-explainer-quick-ask]');
    chip.click();
    assert.equal(askSettled, false, 'askModel has not settled yet');
    assert.equal(constructedSync, 1, 'AudioContext already unlocked synchronously in tap gesture');
    assert.equal(resumedSync, 1);

    resolveAsk({ answer: 'Mobile PWA unlocked voice answer.' });
    await flushAsync();
    assert.equal(askSettled, true);
  } finally {
    exp?.destroy();
    env.restore();
  }
});
