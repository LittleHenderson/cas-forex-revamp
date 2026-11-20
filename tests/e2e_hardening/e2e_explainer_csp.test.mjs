// E2E FA-5 Node.js UI & Strict-CSP Tests for ui/src/explainer.mjs (10 tests: E2E-T1-21..25, E2E-T2-21..25)
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createExplainer } from '../../ui/src/explainer.mjs';

function camelToKebab(str) {
  return str.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
}
function kebabToCamel(str) {
  return str.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
}

class MockNode {
  constructor(tagName = '#text') {
    this.tagName = tagName.toUpperCase();
    this.childNodes = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.listeners = new Map();
    this._textContent = '';
    this.style = {};
    this.tabIndex = 0;
    this.scrollLeft = 0;
    this.scrollTop = 0;
    this.value = '';
    this.clientWidth = 1280;
    this.clientHeight = 800;
    const self = this;
    this.classList = {
      add(...cls) {
        const cur = new Set(String(self.className || '').split(/\s+/).filter(Boolean));
        for (const c of cls) cur.add(c);
        self.className = [...cur].join(' ');
      },
      remove(...cls) {
        const cur = new Set(String(self.className || '').split(/\s+/).filter(Boolean));
        for (const c of cls) cur.delete(c);
        self.className = [...cur].join(' ');
      },
      toggle(c, force) {
        const has = this.contains(c);
        const next = force === undefined ? !has : Boolean(force);
        if (next) this.add(c);
        else this.remove(c);
        return next;
      },
      contains(c) {
        return String(self.className || '').split(/\s+/).filter(Boolean).includes(c);
      },
    };
    this.dataset = new Proxy({}, {
      get(_, prop) {
        return self.attributes.get(`data-${camelToKebab(String(prop))}`);
      },
      set(_, prop, val) {
        self.attributes.set(`data-${camelToKebab(String(prop))}`, String(val));
        return true;
      },
      deleteProperty(_, prop) {
        self.attributes.delete(`data-${camelToKebab(String(prop))}`);
        return true;
      },
    });
  }

  get id() { return this.attributes.get('id') || ''; }
  set id(v) { this.attributes.set('id', String(v)); }

  get className() { return this.attributes.get('class') || ''; }
  set className(v) { this.attributes.set('class', String(v)); }

  get hidden() { return this.attributes.has('hidden'); }
  set hidden(v) { if (v) this.attributes.set('hidden', ''); else this.attributes.delete('hidden'); }

  get disabled() { return this.attributes.has('disabled'); }
  set disabled(v) { if (v) this.attributes.set('disabled', ''); else this.attributes.delete('disabled'); }

  get textContent() {
    if (this.tagName === '#TEXT') return this._textContent;
    if (this.childNodes.length === 0) return this._textContent;
    return this.childNodes.map((c) => c.textContent).join('');
  }
  set textContent(v) {
    this.childNodes = [];
    this._textContent = v == null ? '' : String(v);
  }

  setAttribute(k, v) {
    this.attributes.set(String(k), String(v));
    if (k.startsWith('data-')) {
      void kebabToCamel(k.slice(5));
    }
  }
  getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
  hasAttribute(k) { return this.attributes.has(k); }
  removeAttribute(k) { this.attributes.delete(k); }

  appendChild(child) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }
  append(...nodes) {
    for (const n of nodes) this.appendChild(n);
  }
  insertBefore(newNode, refNode) {
    if (newNode.parentNode) newNode.parentNode.removeChild(newNode);
    const idx = this.childNodes.indexOf(refNode);
    newNode.parentNode = this;
    if (idx < 0) this.childNodes.push(newNode);
    else this.childNodes.splice(idx, 0, newNode);
    return newNode;
  }
  removeChild(child) {
    const idx = this.childNodes.indexOf(child);
    if (idx >= 0) {
      this.childNodes.splice(idx, 1);
      child.parentNode = null;
    }
    return child;
  }
  replaceChildren(...nodes) {
    for (const c of [...this.childNodes]) c.parentNode = null;
    this.childNodes = [];
    this._textContent = '';
    for (const n of nodes) this.appendChild(n);
  }
  replaceWith(node) {
    if (!this.parentNode) return;
    const p = this.parentNode;
    const idx = p.childNodes.indexOf(this);
    if (node.parentNode) node.parentNode.removeChild(node);
    node.parentNode = p;
    p.childNodes.splice(idx, 1, node);
    this.parentNode = null;
  }
  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
  }
  removeEventListener(type, fn) {
    this.listeners.get(type)?.delete(fn);
  }
  dispatchEvent(evt) {
    evt.target = evt.target || this;
    evt.preventDefault = evt.preventDefault || (() => {});
    for (const fn of [...(this.listeners.get(evt.type) || [])]) fn(evt);
    if (this.parentNode) this.parentNode.dispatchEvent(evt);
  }
  click() {
    this.dispatchEvent({ type: 'click', target: this });
  }
  focus() {}
  scrollTo({ left = 0, top = 0 } = {}) { this.scrollLeft = left; this.scrollTop = top; }
  scrollIntoView() {}
  getBoundingClientRect() { return { left: 100, top: 100, width: 48, height: 48 }; }
  setPointerCapture() {}
  hasPointerCapture() { return false; }
  releasePointerCapture() {}

  _matches(sel) {
    const parts = sel.trim().split(/\s+/);
    if (parts.length > 1) {
      if (!this._matches(parts[parts.length - 1])) return false;
      let cur = this.parentNode;
      for (let i = parts.length - 2; i >= 0; i--) {
        while (cur && !cur._matches(parts[i])) cur = cur.parentNode;
        if (!cur) return false;
        cur = cur.parentNode;
      }
      return true;
    }
    const s = parts[0];
    if (s.startsWith('#')) return this.id === s.slice(1);
    if (s.startsWith('.')) return this.classList.contains(s.slice(1));
    const attrEq = s.match(/^\[([^=\]]+)="([^"]*)"\]$/);
    if (attrEq) return this.getAttribute(attrEq[1]) === attrEq[2];
    const attrHas = s.match(/^\[([^\]]+)\]$/);
    if (attrHas) return this.hasAttribute(attrHas[1]);
    const tagAttr = s.match(/^([a-zA-Z0-9_-]+)\[([^\]]+)\]$/);
    if (tagAttr) return this.tagName === tagAttr[1].toUpperCase() && this.hasAttribute(tagAttr[2]);
    return this.tagName === s.toUpperCase();
  }
  querySelectorAll(selector) {
    const out = [];
    const visit = (node) => {
      for (const ch of node.childNodes) {
        if (ch.tagName !== '#TEXT' && ch._matches(selector)) out.push(ch);
        visit(ch);
      }
    };
    visit(this);
    return out;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
  closest(selector) {
    let cur = this;
    while (cur && cur.tagName !== '#DOCUMENT') {
      if (cur.tagName !== '#TEXT' && cur._matches(selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }
}

function parseHtmlFragment(markup) {
  const body = new MockNode('body');
  const stack = [body];
  const voidTags = new Set(['input', 'br', 'hr', 'img', 'meta', 'link']);
  const tokenRe = /<(\/?)([a-zA-Z0-9_-]+)([^>]*)>|([^<]+)/g;
  let m;
  while ((m = tokenRe.exec(markup)) !== null) {
    if (m[4] !== undefined) {
      const txt = new MockNode('#TEXT');
      txt._textContent = m[4];
      stack[stack.length - 1].appendChild(txt);
      continue;
    }
    const isClose = m[1] === '/';
    const tag = m[2].toLowerCase();
    const attrText = m[3] || '';
    if (isClose) {
      while (stack.length > 1 && stack[stack.length - 1].tagName !== tag.toUpperCase()) stack.pop();
      if (stack.length > 1) stack.pop();
      continue;
    }
    const el = new MockNode(tag);
    const attrRe = /([a-zA-Z0-9_:-]+)(?:="([^"]*)")?/g;
    let am;
    while ((am = attrRe.exec(attrText)) !== null) {
      el.setAttribute(am[1], am[2] ?? '');
    }
    stack[stack.length - 1].appendChild(el);
    if (!voidTags.has(tag) && !attrText.trim().endsWith('/')) {
      stack.push(el);
    }
  }
  return body;
}

function setupMockEnv({ withApp = true } = {}) {
  const storageMap = new Map();
  const docEl = new MockNode('html');
  docEl.clientWidth = 1280;
  const body = new MockNode('body');
  docEl.appendChild(body);
  if (withApp) {
    const app = new MockNode('main');
    app.id = 'app';
    body.appendChild(app);
  }
  const docListeners = new Map();
  const winListeners = new Map();

  globalThis.localStorage = {
    getItem: (k) => (storageMap.has(k) ? storageMap.get(k) : null),
    setItem: (k, v) => storageMap.set(k, String(v)),
    removeItem: (k) => storageMap.delete(k),
  };
  globalThis.DOMParser = class {
    parseFromString(markup) {
      return { body: parseHtmlFragment(String(markup)) };
    }
  };
  globalThis.document = {
    documentElement: docEl,
    body,
    createElement: (tag) => new MockNode(tag),
    getElementById: (id) => body.querySelector(`#${id}`),
    querySelector: (sel) => body.querySelector(sel),
    querySelectorAll: (sel) => body.querySelectorAll(sel),
    addEventListener: (t, fn) => {
      if (!docListeners.has(t)) docListeners.set(t, new Set());
      docListeners.get(t).add(fn);
    },
    removeEventListener: (t, fn) => docListeners.get(t)?.delete(fn),
    dispatchDocEvent: (evt) => {
      evt.preventDefault = evt.preventDefault || (() => {});
      for (const fn of [...(docListeners.get(evt.type) || [])]) fn(evt);
    },
  };
  globalThis.window = {
    scrollX: 0,
    scrollY: 0,
    innerWidth: 1280,
    innerHeight: 800,
    scrollTo: ({ left = 0, top = 0 } = {}) => {
      globalThis.window.scrollX = left;
      globalThis.window.scrollY = top;
    },
    matchMedia: () => ({
      matches: true,
      addEventListener: () => {},
      removeEventListener: () => {},
    }),
    addEventListener: (t, fn) => {
      if (!winListeners.has(t)) winListeners.set(t, new Set());
      winListeners.get(t).add(fn);
    },
    removeEventListener: (t, fn) => winListeners.get(t)?.delete(fn),
    setTimeout,
  };
  return { body, storageMap };
}

function sampleContext(overrides = {}) {
  return {
    route: 'operate',
    source: 'LoopbackCockpitServer',
    aiConnected: false,
    projection: {
      scope: { account_id: 'acct-demo-1', run_id: 'run-demo-1' },
      state_id: 'state-1234',
      observed_at: '2026-11-18T13:00:00Z',
      equity: '100000',
      balance: '100000',
      open_pnl: '0',
      realized_pnl: '0',
      positions: [],
      permissions: { new_risk: 'ALLOWED', management: 'ALLOWED' },
      last_decision: { decision_id: 'dec-1' },
    },
    ...overrides,
  };
}

// --- Tier 1: Feature Coverage (E2E-T1-21 .. E2E-T1-25) ---

test('E2E-T1-21 mount createExplainer without askModel exposes local guide and aria-expanded=false', () => {
  setupMockEnv();
  const exp = createExplainer({ getContext: () => sampleContext() });
  const ws = document.querySelector('#forex-explainer-workspace');
  assert.ok(ws);
  const mark = document.querySelector('.forex-explainer-mark');
  assert.equal(mark.getAttribute('aria-expanded'), 'false');
  mark.click();
  assert.equal(mark.getAttribute('aria-expanded'), 'true');
  const answer = document.querySelector('.forex-explainer-answer').textContent;
  assert.match(answer, /Operate separates/);
  exp.destroy();
});

test('E2E-T1-22 switch topics and render supplied JSON record safely via textContent', () => {
  setupMockEnv();
  const exp = createExplainer({ getContext: () => sampleContext() });
  document.querySelector('.forex-explainer-mark').click();
  const controlsBtn = document.querySelector('[data-explainer-topic="controls"]');
  controlsBtn.click();
  assert.equal(document.querySelector('.forex-explainer-question').textContent, 'What do these controls do?');
  assert.match(document.querySelector('.forex-explainer-answer').textContent, /Pause stops admission/);
  const preText = document.querySelector('.forex-explainer-record pre').textContent;
  assert.match(preText, /acct-demo-1/);
  exp.destroy();
});

test('E2E-T1-23 keyboard Alt+Arrow dock movement and Home reset persist layout', () => {
  const { storageMap } = setupMockEnv();
  const exp = createExplainer({ getContext: () => sampleContext() });
  const mark = document.querySelector('.forex-explainer-mark');
  mark.dispatchEvent({ type: 'keydown', key: 'ArrowLeft', altKey: true });
  assert.equal(document.body.dataset.forexExplainerEdge, 'left');
  const savedLeft = JSON.parse(storageMap.get('cas.forex.explainer.layout.v1'));
  assert.equal(savedLeft.edge, 'left');
  mark.dispatchEvent({ type: 'keydown', key: 'Home', altKey: false });
  assert.equal(document.body.dataset.forexExplainerEdge, 'right');
  exp.destroy();
});

test('E2E-T1-24 connected askModel submits question once and resets askBusy', async () => {
  setupMockEnv();
  const asked = [];
  const exp = createExplainer({
    getContext: () => sampleContext({ aiConnected: true, activeModelLabel: 'Claude Fable' }),
    askModel: async (q) => {
      asked.push(q);
      return { answer: 'Valve threshold is 0.55 in DEMO mode.' };
    },
  });
  document.querySelector('.forex-explainer-mark').click();
  const input = document.querySelector('#forex-explainer-prompt');
  const submit = document.querySelector('[data-explainer-ask-submit]');
  assert.equal(input.disabled, false);
  assert.equal(submit.hidden, false);
  input.value = 'What is the valve threshold?';
  submit.click();
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(asked, ['What is the valve threshold?']);
  assert.equal(document.querySelector('.forex-explainer-answer').textContent, 'Valve threshold is 0.55 in DEMO mode.');
  assert.equal(input.disabled, false);
  exp.destroy();
});

test('E2E-T1-25 destroy restores #app cleanly and is idempotent on second call', () => {
  const { body } = setupMockEnv();
  const exp = createExplainer({ getContext: () => sampleContext() });
  document.querySelector('.forex-explainer-mark').click();
  exp.destroy();
  exp.destroy();
  assert.equal(document.querySelector('#forex-explainer'), null);
  assert.equal(document.querySelector('#forex-explainer-workspace'), null);
  assert.equal(body.querySelector('#app')?.parentNode, body);
  assert.equal(body.classList.contains('forex-explainer-ready'), false);
});

// --- Tier 2: Boundary & Corner Cases (E2E-T2-21 .. E2E-T2-25) ---

test('E2E-T2-21 createExplainer fails closed when #app missing or mounted twice', () => {
  setupMockEnv({ withApp: false });
  assert.throws(() => createExplainer({ getContext: () => sampleContext() }), /workspace root/);

  setupMockEnv({ withApp: true });
  const exp = createExplainer({ getContext: () => sampleContext() });
  assert.throws(() => createExplainer({ getContext: () => sampleContext() }), /already mounted/);
  exp.destroy();
});

test('E2E-T2-22 hostile HTML markup in context or askModel reply is rendered as plain textContent', async () => {
  setupMockEnv();
  const xssPayload = '<img src=x onerror="alert(1)">';
  const exp = createExplainer({
    getContext: () => sampleContext({ source: xssPayload, aiConnected: true }),
    askModel: async () => ({ answer: xssPayload }),
  });
  document.querySelector('.forex-explainer-mark').click();
  assert.equal(document.querySelector('[data-guide-source]').textContent, xssPayload);
  assert.equal(document.querySelector('[data-guide-source]').childNodes.length, 0);

  const input = document.querySelector('#forex-explainer-prompt');
  input.value = 'check xss';
  document.querySelector('[data-explainer-ask-submit]').click();
  await new Promise((r) => setTimeout(r, 20));
  const ansEl = document.querySelector('.forex-explainer-answer');
  assert.equal(ansEl.textContent, xssPayload);
  assert.equal(ansEl.childNodes.length, 0);
  exp.destroy();
});

test('E2E-T2-23 askModel rejection resets askBusy and displays error text safely', async () => {
  setupMockEnv();
  const exp = createExplainer({
    getContext: () => sampleContext({ aiConnected: true }),
    askModel: async () => { throw new Error('HTTP 503'); },
  });
  document.querySelector('.forex-explainer-mark').click();
  const input = document.querySelector('#forex-explainer-prompt');
  input.value = 'trigger 503';
  document.querySelector('[data-explainer-ask-submit]').click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(document.querySelector('.forex-explainer-answer').textContent, 'HTTP 503');
  assert.equal(input.disabled, false);
  assert.equal(document.querySelector('[data-explainer-ask-submit]').disabled, false);
  exp.destroy();
});

test('E2E-T2-24 Escape does not close explainer while dialog[open] is active', () => {
  const { body } = setupMockEnv();
  const exp = createExplainer({ getContext: () => sampleContext() });
  const mark = document.querySelector('.forex-explainer-mark');
  mark.click();
  assert.equal(mark.getAttribute('aria-expanded'), 'true');

  const dlg = new MockNode('dialog');
  dlg.setAttribute('open', '');
  body.appendChild(dlg);
  document.dispatchDocEvent({ type: 'keydown', key: 'Escape' });
  assert.equal(mark.getAttribute('aria-expanded'), 'true');

  dlg.remove();
  document.dispatchDocEvent({ type: 'keydown', key: 'Escape' });
  assert.equal(mark.getAttribute('aria-expanded'), 'false');
  exp.destroy();
});

test('E2E-T2-25 static scan of ui/src/explainer.mjs finds zero forbidden XSS or CSP sinks', async () => {
  const src = await readFile(new URL('../../ui/src/explainer.mjs', import.meta.url), 'utf8');
  const forbidden = [
    '.' + 'inner' + 'HTML',
    '.' + 'outer' + 'HTML',
    'ev' + 'al(',
    'sty' + 'le=',
  ];
  for (const tok of forbidden) {
    assert.equal(src.includes(tok), false, `Forbidden sink found: ${tok}`);
  }
});
