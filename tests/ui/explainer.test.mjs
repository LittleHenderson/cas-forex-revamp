// Phase 6 unit & strict-CSP tests for ui/src/explainer.mjs (createExplainer).
// Uses flat top-level test() calls only and zero external dependencies.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createExplainer } from '../../ui/src/explainer.mjs';

function camelToKebab(name) {
  return String(name).replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
}

function kebabToCamel(name) {
  return String(name).replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
}

function matchesSimpleSelector(el, sel) {
  if (!el || !el.tagName) return false;
  const s = sel.trim();
  if (!s) return false;
  let rest = s;
  const tagMatch = rest.match(/^[a-zA-Z0-9_-]+/);
  if (tagMatch) {
    if (el.tagName !== tagMatch[0].toUpperCase()) return false;
    rest = rest.slice(tagMatch[0].length);
  }
  while (rest.length > 0) {
    if (rest.startsWith('#')) {
      const m = rest.match(/^#([A-Za-z0-9_-]+)/);
      if (!m || el.id !== m[1]) return false;
      rest = rest.slice(m[0].length);
    } else if (rest.startsWith('.')) {
      const m = rest.match(/^\.([A-Za-z0-9_-]+)/);
      if (!m || !el.classList.contains(m[1])) return false;
      rest = rest.slice(m[0].length);
    } else if (rest.startsWith('[')) {
      const m = rest.match(/^\[([A-Za-z0-9_-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/);
      if (!m) return false;
      const attr = m[1];
      const expected = m[2] ?? m[3] ?? m[4];
      if (!el.hasAttribute(attr)) return false;
      if (expected !== undefined && el.getAttribute(attr) !== expected) return false;
      rest = rest.slice(m[0].length);
    } else {
      return false;
    }
  }
  return true;
}

function matchesSelector(el, selector) {
  const parts = String(selector).trim().split(/\s+/);
  if (parts.length === 1) return matchesSimpleSelector(el, parts[0]);
  let cur = el;
  if (!matchesSimpleSelector(cur, parts[parts.length - 1])) return false;
  for (let i = parts.length - 2; i >= 0; i -= 1) {
    cur = cur.parentNode;
    while (cur && !matchesSimpleSelector(cur, parts[i])) cur = cur.parentNode;
    if (!cur) return false;
  }
  return true;
}

class MockTextNode {
  constructor(text) {
    this.nodeType = 3;
    this.textContent = String(text);
    this.parentNode = null;
  }
}

class MockElement {
  constructor(tagName, ownerDocument) {
    this.nodeType = 1;
    this.tagName = String(tagName).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
    this.childNodes = [];
    this._attrs = new Map();
    this._listeners = new Map();
    this._capturedPointers = new Set();
    this._style = {};
    this.scrollLeft = 0;
    this.scrollTop = 0;
    this.clientWidth = 1280;
    this.tabIndex = -1;
    this.value = '';
    const self = this;
    this.style = new Proxy(this._style, {
      set(targetObj, prop, val) {
        targetObj[prop] = String(val);
        return true;
      },
    });
    this.classList = {
      add(...tokens) {
        const cur = new Set(String(self.getAttribute('class') || '').split(/\s+/).filter(Boolean));
        for (const t of tokens) cur.add(t);
        self.setAttribute('class', [...cur].join(' '));
      },
      remove(...tokens) {
        const cur = new Set(String(self.getAttribute('class') || '').split(/\s+/).filter(Boolean));
        for (const t of tokens) cur.delete(t);
        if (cur.size === 0) self.removeAttribute('class');
        else self.setAttribute('class', [...cur].join(' '));
      },
      toggle(token, force) {
        const has = this.contains(token);
        const next = force === undefined ? !has : Boolean(force);
        if (next) this.add(token);
        else this.remove(token);
        return next;
      },
      contains(token) {
        return String(self.getAttribute('class') || '').split(/\s+/).filter(Boolean).includes(token);
      },
    };
    this.dataset = new Proxy({}, {
      get(_, prop) {
        const attr = `data-${camelToKebab(prop)}`;
        return self._attrs.has(attr) ? self._attrs.get(attr) : undefined;
      },
      set(_, prop, val) {
        self.setAttribute(`data-${camelToKebab(prop)}`, String(val));
        return true;
      },
      deleteProperty(_, prop) {
        self.removeAttribute(`data-${camelToKebab(prop)}`);
        return true;
      },
      ownKeys() {
        return [...self._attrs.keys()]
          .filter((k) => k.startsWith('data-'))
          .map((k) => kebabToCamel(k.slice(5)));
      },
      getOwnPropertyDescriptor(_, prop) {
        const attr = `data-${camelToKebab(prop)}`;
        if (!self._attrs.has(attr)) return undefined;
        return { configurable: true, enumerable: true, value: self._attrs.get(attr) };
      },
    });
  }

  get id() {
    return this._attrs.get('id') || '';
  }
  set id(v) {
    this.setAttribute('id', String(v));
  }
  get className() {
    return this._attrs.get('class') || '';
  }
  set className(v) {
    this.setAttribute('class', String(v));
  }
  get hidden() {
    return this._attrs.has('hidden');
  }
  set hidden(v) {
    if (v) this._attrs.set('hidden', '');
    else this._attrs.delete('hidden');
  }
  get disabled() {
    return this._attrs.has('disabled');
  }
  set disabled(v) {
    if (v) this._attrs.set('disabled', '');
    else this._attrs.delete('disabled');
  }
  get children() {
    return this.childNodes.filter((n) => n.nodeType === 1);
  }
  get textContent() {
    return this.childNodes.map((n) => n.textContent).join('');
  }
  set textContent(v) {
    this.childNodes = [];
    if (v !== null && v !== undefined && String(v) !== '') {
      const txt = new MockTextNode(String(v));
      txt.parentNode = this;
      this.childNodes.push(txt);
    }
  }
  setAttribute(name, val) {
    this._attrs.set(String(name), String(val));
  }
  getAttribute(name) {
    return this._attrs.has(String(name)) ? this._attrs.get(String(name)) : null;
  }
  hasAttribute(name) {
    return this._attrs.has(String(name));
  }
  removeAttribute(name) {
    this._attrs.delete(String(name));
  }
  append(...nodes) {
    for (const node of nodes) {
      const item = typeof node === 'string' ? new MockTextNode(node) : node;
      if (item.parentNode && item.parentNode !== this && typeof item.remove === 'function') {
        item.remove();
      }
      item.parentNode = this;
      this.childNodes.push(item);
    }
  }
  replaceChildren(...nodes) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    this.append(...nodes);
  }
  insertBefore(newNode, refNode) {
    if (newNode.parentNode && typeof newNode.remove === 'function') newNode.remove();
    const idx = refNode ? this.childNodes.indexOf(refNode) : -1;
    newNode.parentNode = this;
    if (idx === -1) this.childNodes.push(newNode);
    else this.childNodes.splice(idx, 0, newNode);
    return newNode;
  }
  remove() {
    if (!this.parentNode) return;
    const idx = this.parentNode.childNodes.indexOf(this);
    if (idx >= 0) this.parentNode.childNodes.splice(idx, 1);
    this.parentNode = null;
  }
  replaceWith(...nodes) {
    const parent = this.parentNode;
    if (!parent) return;
    const idx = parent.childNodes.indexOf(this);
    this.parentNode = null;
    const prepared = nodes.map((n) => {
      if (n.parentNode && typeof n.remove === 'function') n.remove();
      n.parentNode = parent;
      return n;
    });
    parent.childNodes.splice(idx, 1, ...prepared);
  }
  querySelectorAll(selector) {
    const results = [];
    const walk = (node) => {
      for (const child of node.children) {
        if (matchesSelector(child, selector)) results.push(child);
        walk(child);
      }
    };
    walk(this);
    return results;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
  closest(selector) {
    let cur = this;
    while (cur && cur.nodeType === 1) {
      if (matchesSelector(cur, selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }
  addEventListener(type, fn) {
    if (!this._listeners.has(type)) this._listeners.set(type, new Set());
    this._listeners.get(type).add(fn);
  }
  removeEventListener(type, fn) {
    this._listeners.get(type)?.delete(fn);
  }
  dispatchEvent(event) {
    const evt = {
      type: event.type,
      target: event.target ?? this,
      currentTarget: this,
      key: event.key ?? '',
      altKey: Boolean(event.altKey),
      shiftKey: Boolean(event.shiftKey),
      ctrlKey: Boolean(event.ctrlKey),
      metaKey: Boolean(event.metaKey),
      isPrimary: event.isPrimary ?? true,
      button: event.button ?? 0,
      pointerId: event.pointerId ?? 1,
      clientX: event.clientX ?? 0,
      clientY: event.clientY ?? 0,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
    };
    for (const fn of [...(this._listeners.get(evt.type) || [])]) fn(evt);
    if (evt.type === 'click' && this.parentNode && typeof this.parentNode.dispatchEvent === 'function') {
      this.parentNode.dispatchEvent({ ...evt, currentTarget: this.parentNode });
    }
    return evt;
  }
  focus() {
    this.ownerDocument.activeElement = this;
  }
  scrollIntoView() {}
  scrollTo(opts) {
    if (opts && typeof opts === 'object') {
      if (Number.isFinite(opts.left)) this.scrollLeft = opts.left;
      if (Number.isFinite(opts.top)) this.scrollTop = opts.top;
    }
  }
  setPointerCapture(id) { this._capturedPointers.add(id); }
  hasPointerCapture(id) { return this._capturedPointers.has(id); }
  releasePointerCapture(id) { this._capturedPointers.delete(id); }
  getBoundingClientRect() {
    const parsePx = (v, fallback) => {
      const n = Number.parseFloat(v);
      return Number.isFinite(n) ? n : fallback;
    };
    const left = parsePx(this._style.left, 0);
    const top = parsePx(this._style.top, 0);
    const width = parsePx(this._style.width, 48);
    const height = parsePx(this._style.height, 48);
    return { left, top, width, height, right: left + width, bottom: top + height };
  }
}

function decodeHtmlEntities(str) {
  return str
    .replaceAll('&amp;', '&')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'");
}

function parseHtmlIntoBody(html, doc) {
  const body = new MockElement('body', doc);
  const stack = [body];
  const tokenRe = /<(\/?)([a-zA-Z0-9_-]+)([^>]*)>|([^<]+)/g;
  const attrRe = /([a-zA-Z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  const voidTags = new Set(['input', 'br', 'hr', 'img', 'meta', 'link']);
  let m;
  while ((m = tokenRe.exec(html)) !== null) {
    if (m[4] !== undefined) {
      if (m[4].length > 0) stack[stack.length - 1].append(decodeHtmlEntities(m[4]));
      continue;
    }
    const isClose = m[1] === '/';
    const tag = m[2].toLowerCase();
    const rawAttrs = m[3] || '';
    if (isClose) {
      for (let i = stack.length - 1; i >= 1; i -= 1) {
        if (stack[i].tagName === tag.toUpperCase()) {
          stack.length = i;
          break;
        }
      }
      continue;
    }
    const el = new MockElement(tag, doc);
    let am;
    attrRe.lastIndex = 0;
    while ((am = attrRe.exec(rawAttrs)) !== null) {
      const attrName = am[1];
      const attrVal = am[2] ?? am[3] ?? am[4] ?? '';
      el.setAttribute(attrName, decodeHtmlEntities(attrVal));
    }
    stack[stack.length - 1].append(el);
    if (!voidTags.has(tag) && !rawAttrs.trim().endsWith('/')) stack.push(el);
  }
  return body;
}


function createMockEnvironment({ wideMatches = true, storageThrows = false } = {}) {
  const doc = {
    activeElement: null,
    _listeners: new Map(),
    createElement(tag) { return new MockElement(tag, doc); },
    getElementById(id) { return doc.querySelector(`#${id}`); },
    querySelector(sel) { return doc.documentElement.querySelector(sel); },
    querySelectorAll(sel) { return doc.documentElement.querySelectorAll(sel); },
    addEventListener(type, fn) {
      if (!doc._listeners.has(type)) doc._listeners.set(type, new Set());
      doc._listeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      doc._listeners.get(type)?.delete(fn);
    },
    dispatchEvent(event) {
      const evt = {
        type: event.type,
        key: event.key ?? '',
        defaultPrevented: false,
        preventDefault() { this.defaultPrevented = true; },
      };
      for (const fn of [...(doc._listeners.get(evt.type) || [])]) fn(evt);
      return evt;
    },
  };
  doc.documentElement = new MockElement('html', doc);
  doc.documentElement.clientWidth = 1280;
  doc.body = new MockElement('body', doc);
  doc.documentElement.append(doc.body);
  const app = new MockElement('main', doc);
  app.id = 'app';
  doc.body.append(app);

  const mqlListeners = new Set();
  const mql = {
    matches: wideMatches,
    addEventListener(type, fn) { if (type === 'change') mqlListeners.add(fn); },
    removeEventListener(type, fn) { if (type === 'change') mqlListeners.delete(fn); },
    setMatches(v) { this.matches = Boolean(v); for (const fn of [...mqlListeners]) fn({ matches: this.matches }); },
  };

  const winListeners = new Map();
  const win = {
    innerWidth: 1280,
    innerHeight: 800,
    scrollX: 0,
    scrollY: 0,
    scrollTo(opts) {
      if (opts && typeof opts === 'object') {
        if (Number.isFinite(opts.left)) win.scrollX = opts.left;
        if (Number.isFinite(opts.top)) win.scrollY = opts.top;
      }
    },
    matchMedia() { return mql; },
    addEventListener(type, fn) {
      if (!winListeners.has(type)) winListeners.set(type, new Set());
      winListeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      winListeners.get(type)?.delete(fn);
    },
    setTimeout(fn) { fn(); return 1; },
  };

  const store = new Map();
  const storage = {
    getItem(k) {
      if (storageThrows) throw new Error('Storage blocked');
      return store.has(k) ? store.get(k) : null;
    },
    setItem(k, v) {
      if (storageThrows) throw new Error('Storage blocked');
      store.set(String(k), String(v));
    },
    removeItem(k) { store.delete(String(k)); },
    clear() { store.clear(); },
  };

  class MockDOMParser {
    parseFromString(html, mimeType) {
      assert.equal(mimeType, 'text/html');
      return { body: parseHtmlIntoBody(String(html), doc) };
    }
  }

  return { doc, win, app, mql, store, storage, MockDOMParser };
}

function withMockBrowser(opts, fn) {
  const env = createMockEnvironment(opts);
  const keys = ['document', 'window', 'DOMParser', 'localStorage'];
  const saved = new Map(keys.map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  Object.defineProperty(globalThis, 'document', { value: env.doc, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'window', { value: env.win, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'DOMParser', { value: env.MockDOMParser, configurable: true, writable: true });
  Object.defineProperty(globalThis, 'localStorage', { value: env.storage, configurable: true, writable: true });
  return Promise.resolve()
    .then(() => fn(env))
    .finally(() => {
      for (const k of keys) {
        const desc = saved.get(k);
        if (desc === undefined) delete globalThis[k];
        else Object.defineProperty(globalThis, k, desc);
      }
    });
}

function sampleContext(overrides = {}) {
  return {
    route: 'operate',
    source: 'Loopback live stream',
    aiConnected: false,
    projection: {
      scope: { account_id: 'acct-demo-1', run_id: 'run-2026-01' },
      state_id: 'state-001',
      observed_at: '2026-11-17T14:00:00Z',
      equity: '10000.00',
      balance: '10000.00',
      open_pnl: '0.00',
      realized_pnl: '0.00',
      positions: [],
      permissions: { new_risk: 'ALLOWED', management: 'ALLOWED' },
      last_decision: { decision_id: 'dec-1' },
    },
    reviewEnvelope: { envelope: { coverage: { complete: true } } },
    ...overrides,
  };
}

test('createExplainer validates required context getter and workspace preconditions', async () => {
  await withMockBrowser({}, ({ doc, app }) => {
    assert.throws(() => createExplainer({ getContext: null }), TypeError);

    app.remove();
    assert.throws(() => createExplainer({ getContext: () => sampleContext() }), /workspace root/);

    doc.body.append(app);
    const exp = createExplainer({ getContext: () => sampleContext() });
    assert.throws(() => createExplainer({ getContext: () => sampleContext() }), /already mounted/);
    exp.destroy();

    const ws = doc.createElement('div');
    ws.id = 'forex-explainer-workspace';
    doc.body.append(ws);
    assert.throws(() => createExplainer({ getContext: () => sampleContext() }), /workspace already mounted/);
  });
});

test('createExplainer renders local topics (overview, unknowns, controls) and JSON record', async () => {
  await withMockBrowser({}, ({ doc }) => {
    let ctx = sampleContext({ route: 'operate' });
    const exp = createExplainer({ getContext: () => ctx });
    const mark = doc.querySelector('.forex-explainer-mark');
    const panel = doc.querySelector('#forex-explainer-panel');
    assert.equal(panel.hidden, true);

    mark.dispatchEvent({ type: 'click' });
    assert.equal(panel.hidden, false);
    assert.equal(mark.getAttribute('aria-expanded'), 'true');
    assert.equal(doc.body.classList.contains('forex-explainer-open'), true);
    assert.match(doc.querySelector('.forex-explainer-answer').textContent, /Operate separates reported permissions/);
    assert.equal(doc.querySelector('[data-guide-account]').textContent, 'acct-demo-1');
    assert.equal(doc.querySelector('[data-guide-run]').textContent, 'run-2026-01');
    assert.equal(doc.querySelector('[data-guide-state]').textContent, 'state-001');
    assert.match(doc.querySelector('.forex-explainer-record pre').textContent, /"state_id": "state-001"/);

    ctx = sampleContext({ route: 'review' });
    exp.sync();
    assert.match(doc.querySelector('.forex-explainer-answer').textContent, /Review inspects supplied decisions/);

    ctx = sampleContext({ route: 'setup' });
    exp.sync();
    assert.match(doc.querySelector('.forex-explainer-answer').textContent, /Setup shows the snapshot source/);

    // Unknowns with missing fields and null projection
    ctx = sampleContext({
      projection: { permissions: {}, scope: {} },
      reviewEnvelope: { envelope: { coverage: { complete: false } } },
    });
    doc.querySelector('[data-explainer-topic="unknowns"]').dispatchEvent({ type: 'click' });
    const unkTxt = doc.querySelector('.forex-explainer-answer').textContent;
    assert.match(unkTxt, /No venue observation time is supplied/);
    assert.match(unkTxt, /New-risk permission is absent/);
    assert.match(unkTxt, /Complete decision\/evidence coverage has not been established/);

    ctx = sampleContext({ projection: null });
    exp.sync();
    assert.match(doc.querySelector('.forex-explainer-answer').textContent, /No valid cockpit snapshot is loaded/);

    // Controls topic
    doc.querySelector('[data-explainer-topic="controls"]').dispatchEvent({ type: 'click' });
    assert.match(doc.querySelector('.forex-explainer-answer').textContent, /Pause stops admission of new risk/);

    // Circular record falls back safely
    const circular = {};
    circular.self = circular;
    ctx = sampleContext({ projection: circular });
    exp.sync();
    assert.match(doc.querySelector('.forex-explainer-record pre').textContent, /could not be serialized/);

    exp.destroy();
  });
});

test('createExplainer live askModel Q&A handles busy guard, replies, errors, and local reset', async () => {
  await withMockBrowser({}, async ({ doc }) => {
    let calls = 0;
    let resolveAsk;
    let rejectNext = false;
    const askModel = (q) => {
      calls += 1;
      if (rejectNext) return Promise.reject(new Error(`Backend error for ${q}`));
      return new Promise((res) => { resolveAsk = res; });
    };
    const ctx = sampleContext({ aiConnected: true, activeModelLabel: 'Claude Fable 5.2' });
    const exp = createExplainer({ getContext: () => ctx, askModel });

    doc.querySelector('.forex-explainer-mark').dispatchEvent({ type: 'click' });
    const input = doc.querySelector('#forex-explainer-prompt');
    const askBtn = doc.querySelector('[data-explainer-ask-submit]');
    assert.equal(askBtn.hidden, false);
    assert.equal(input.disabled, false);

    // Empty / whitespace question is ignored
    input.value = '   ';
    askBtn.dispatchEvent({ type: 'click' });
    assert.equal(calls, 0);

    // Submit valid question via Enter key; busy guard prevents concurrent submit
    input.value = 'Why is EURUSD paused?';
    input.dispatchEvent({ type: 'keydown', key: 'Enter' });
    assert.equal(calls, 1);
    assert.equal(input.disabled, true);
    assert.equal(askBtn.disabled, true);

    askBtn.dispatchEvent({ type: 'click' });
    assert.equal(calls, 1);

    resolveAsk({ answer: 'Daily quota reached.' });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(input.disabled, false);
    assert.equal(input.value, '');
    assert.equal(doc.querySelector('.forex-explainer-question').textContent, 'Why is EURUSD paused?');
    assert.equal(doc.querySelector('.forex-explainer-answer').textContent, 'Daily quota reached.');

    // Rejected promise error path
    rejectNext = true;
    input.value = 'Check spread';
    askBtn.dispatchEvent({ type: 'click' });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(input.disabled, false);
    assert.equal(doc.querySelector('.forex-explainer-answer').textContent, 'Backend error for Check spread');

    // Clicking local topic returns to local mode
    doc.querySelector('[data-explainer-topic="controls"]').dispatchEvent({ type: 'click' });
    assert.match(doc.querySelector('.forex-explainer-answer').textContent, /Pause stops admission of new risk/);

    exp.destroy();
  });
});

test('createExplainer enforces strict CSP and XSS neutralization via textContent', async () => {
  const explainerSource = await readFile(new URL('../../ui/src/explainer.mjs', import.meta.url), 'utf8');
  assert.equal(/\.innerHTML\b/.test(explainerSource), false);
  assert.equal(/\.outerHTML\b/.test(explainerSource), false);
  assert.equal(/\bstyle\s*=\s*["']/.test(explainerSource), false);

  await withMockBrowser({}, async ({ doc }) => {
    const xssPayload = '<script>alert(1)</script><img src=x onerror=alert(1)>';
    const ctx = sampleContext({
      source: xssPayload,
      aiConnected: true,
      projection: { ...sampleContext().projection, state_id: xssPayload },
    });
    const exp = createExplainer({
      getContext: () => ctx,
      askModel: async () => xssPayload,
    });
    doc.querySelector('.forex-explainer-mark').dispatchEvent({ type: 'click' });
    assert.equal(doc.querySelector('[data-guide-source]').children.length, 0);
    assert.equal(doc.querySelector('[data-guide-source]').textContent, xssPayload);
    assert.equal(doc.querySelector('[data-guide-state]').children.length, 0);
    assert.equal(doc.querySelector('[data-guide-state]').textContent, xssPayload);

    const input = doc.querySelector('#forex-explainer-prompt');
    input.value = xssPayload;
    doc.querySelector('[data-explainer-ask-submit]').dispatchEvent({ type: 'click' });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(doc.querySelector('.forex-explainer-question').children.length, 0);
    assert.equal(doc.querySelector('.forex-explainer-answer').children.length, 0);
    assert.equal(doc.querySelector('.forex-explainer-answer').textContent, xssPayload);

    exp.destroy();
  });
});

test('createExplainer handles Escape with dialog[open], keyboard docking, storage resilience, and idempotent destroy', async () => {
  await withMockBrowser({}, ({ doc, app, store }) => {
    const exp = createExplainer({ getContext: () => sampleContext() });
    const mark = doc.querySelector('.forex-explainer-mark');
    const panel = doc.querySelector('#forex-explainer-panel');

    mark.dispatchEvent({ type: 'click' });
    assert.equal(panel.hidden, false);

    // Open <dialog open> blocks Escape from closing Explainer
    const dlg = doc.createElement('dialog');
    dlg.setAttribute('open', '');
    doc.body.append(dlg);
    doc.dispatchEvent({ type: 'keydown', key: 'Escape' });
    assert.equal(panel.hidden, false);

    dlg.removeAttribute('open');
    doc.dispatchEvent({ type: 'keydown', key: 'Escape' });
    assert.equal(panel.hidden, true);

    // Keyboard docking, shift movement, collapse, restore, and reset
    mark.dispatchEvent({ type: 'keydown', key: 'ArrowLeft', altKey: true });
    assert.equal(mark.dataset.edge, 'left');
    assert.equal(doc.body.dataset.forexExplainerEdge, 'left');

    mark.dispatchEvent({ type: 'keydown', key: 'ArrowDown', shiftKey: true });
    const savedAfterMove = JSON.parse(store.get('cas.forex.explainer.layout.v1'));
    assert.ok(savedAfterMove.frac > 0.62);

    mark.dispatchEvent({ type: 'keydown', key: 'c' });
    assert.equal(mark.dataset.collapsed, 'true');

    // Click while collapsed restores mark rather than opening panel
    mark.dispatchEvent({ type: 'click' });
    assert.equal(mark.dataset.collapsed, 'false');
    assert.equal(panel.hidden, true);

    mark.dispatchEvent({ type: 'keydown', key: 'Home' });
    assert.equal(mark.dataset.edge, 'right');

    // Dock/collapse/reset buttons inside panel
    doc.querySelector('[data-guide-dock="top"]').dispatchEvent({ type: 'click' });
    assert.equal(mark.dataset.edge, 'top');
    doc.querySelector('[data-guide-reset]').dispatchEvent({ type: 'click' });
    assert.equal(mark.dataset.edge, 'right');

    // Idempotent destroy restores #app directly under body and cleans classes/dataset
    exp.destroy();
    exp.destroy();
    exp.sync();
    assert.equal(app.parentNode, doc.body);
    assert.equal(doc.querySelector('#forex-explainer'), null);
    assert.equal(doc.querySelector('#forex-explainer-workspace'), null);
    assert.equal(doc.body.classList.contains('forex-explainer-ready'), false);
    assert.equal(doc.body.dataset.forexExplainerEdge, undefined);
  });

  // Storage throwing must not break createExplainer or docking
  await withMockBrowser({ storageThrows: true }, ({ doc }) => {
    const exp = createExplainer({ getContext: () => sampleContext() });
    doc.querySelector('.forex-explainer-mark').dispatchEvent({ type: 'keydown', key: 'ArrowLeft', altKey: true });
    assert.equal(doc.querySelector('.forex-explainer-mark').dataset.edge, 'left');
    exp.destroy();
  });
});
