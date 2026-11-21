// PR #30 UI regression suite: Zero-jump scroll preservation across #forex-explainer-workspace,
// .market-watchlist, active wheel/touch/scroll deferral, programmatic-restore loop prevention,
// overflow-anchor: none CSS lock, strict CSP, and LF hygiene.
// Flat top-level test() calls only; zero inline styles or external URLs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  EXPLAINER_WORKSPACE_ID,
  PROGRAMMATIC_SCROLL_GRACE_MS,
  SCROLL_QUIET_MS,
  WATCHLIST_SCROLL_SELECTOR,
  attachScrollActivityListeners,
  captureScrollSnapshot,
  createScrollActivityGuard,
  restoreScrollSnapshot,
} from '../../ui/src/scroll-guard.mjs';

function makeEventTarget(extra = {}) {
  const listeners = new Map();
  return {
    ...extra,
    _listeners: listeners,
    addEventListener(type, fn, opts) {
      const list = listeners.get(type) ?? [];
      list.push({ fn, opts });
      listeners.set(type, list);
    },
    removeEventListener(type, fn) {
      const list = listeners.get(type) ?? [];
      listeners.set(type, list.filter((entry) => entry.fn !== fn));
    },
    emit(type, event = {}) {
      for (const entry of listeners.get(type) ?? []) {
        entry.fn(event);
      }
    },
  };
}

test('SS01 captureScrollSnapshot and restoreScrollSnapshot preserve #forex-explainer-workspace, .market-watchlist, and window with 0.0px drift', () => {
  const workspace = { id: EXPLAINER_WORKSPACE_ID, scrollLeft: 12, scrollTop: 3420 };
  const watchlist = { scrollTop: 185 };
  const doc = {
    getElementById: (id) => (id === EXPLAINER_WORKSPACE_ID ? workspace : null),
    querySelector: (sel) => {
      if (sel === `#${EXPLAINER_WORKSPACE_ID}`) return workspace;
      if (sel === WATCHLIST_SCROLL_SELECTOR) return watchlist;
      return null;
    },
  };
  let winScrollCalls = [];
  const win = {
    scrollX: 0,
    scrollY: 0,
    scrollTo(x, y) {
      winScrollCalls.push([x, y]);
      this.scrollX = x;
      this.scrollY = y;
    },
  };

  const snap = captureScrollSnapshot(doc, win);
  assert.equal(snap.hasWorkspace, true);
  assert.equal(snap.workspaceTop, 3420);
  assert.equal(snap.workspaceLeft, 12);
  assert.equal(snap.watchlistTop, 185);
  assert.equal(snap.windowY, 0);

  // Simulate full-page DOM teardown clamping workspace & watchlist back to 0px
  workspace.scrollTop = 0;
  workspace.scrollLeft = 0;
  watchlist.scrollTop = 0;

  const res = restoreScrollSnapshot(snap, doc, win);
  assert.equal(res.workspaceRestored, true);
  assert.equal(res.watchlistRestored, true);
  assert.equal(res.windowRestored, true);
  assert.equal(workspace.scrollTop, 3420);
  assert.equal(workspace.scrollLeft, 12);
  assert.equal(watchlist.scrollTop, 185);
  assert.deepEqual(winScrollCalls, [[0, 0]]);
});

test('SS02 createScrollActivityGuard defers renders during wheel/touch scrolling and releases after SCROLL_QUIET_MS', () => {
  let clock = 1000;
  let nextTimerId = 1;
  const timers = new Map();
  let quietCalls = 0;

  const guard = createScrollActivityGuard({
    quietMs: SCROLL_QUIET_MS,
    now: () => clock,
    onQuiet: () => { quietCalls += 1; },
    setTimer: (fn, ms) => {
      const id = nextTimerId++;
      timers.set(id, { fn, fireAt: clock + ms });
      return id;
    },
    clearTimer: (id) => { timers.delete(id); },
  });

  assert.equal(guard.isScrolling(), false);
  guard.markUserInputScroll();
  assert.equal(guard.isScrolling(), true);
  assert.equal(timers.size, 1);

  // Continuous scrolling 200ms later extends the quiet timer without releasing
  clock += 200;
  guard.markUserInputScroll();
  assert.equal(guard.isScrolling(), true);
  assert.equal(timers.size, 1);
  assert.equal(quietCalls, 0);

  // Advance past quietMs (350ms) and fire timer
  clock += SCROLL_QUIET_MS;
  for (const [id, entry] of [...timers.entries()]) {
    if (entry.fireAt <= clock) {
      timers.delete(id);
      entry.fn();
    }
  }
  assert.equal(guard.isScrolling(), false);
  assert.equal(quietCalls, 1);
});

test('SS03 restoreSnapshot suppresses self-triggered scroll events within grace window while catching real user scrolls > 1px', () => {
  let clock = 5000;
  const workspace = { id: EXPLAINER_WORKSPACE_ID, scrollLeft: 0, scrollTop: 2950 };
  const doc = { getElementById: (id) => (id === EXPLAINER_WORKSPACE_ID ? workspace : null) };
  const win = { scrollX: 0, scrollY: 0, scrollTo() {} };

  const guard = createScrollActivityGuard({
    quietMs: SCROLL_QUIET_MS,
    programmaticGraceMs: PROGRAMMATIC_SCROLL_GRACE_MS,
    now: () => clock,
    setTimer: () => 1,
    clearTimer: () => {},
  });

  const snap = captureScrollSnapshot(doc, win);
  workspace.scrollTop = 0;
  guard.restoreSnapshot(snap, doc, win);
  assert.equal(workspace.scrollTop, 2950);

  // Async browser scroll event 16ms later at same restored offset must NOT lock scrolling
  clock += 16;
  assert.equal(guard.handleContainerScroll(doc, win), false);
  assert.equal(guard.isScrolling(), false);

  // Real user scroll movement (+80px) even inside grace window MUST defer renders
  workspace.scrollTop = 3030;
  assert.equal(guard.handleContainerScroll(doc, win), true);
  assert.equal(guard.isScrolling(), true);

  guard.reset();
  assert.equal(guard.isScrolling(), false);
});

test('SS04 attachScrollActivityListeners registers passive wheel/touchmove/scroll hooks and tracks dynamic #forex-explainer-workspace', () => {
  let ws = null;
  const doc = makeEventTarget({
    getElementById: (id) => (id === EXPLAINER_WORKSPACE_ID ? ws : null),
  });
  const win = makeEventTarget({ scrollX: 0, scrollY: 0 });
  const guard = createScrollActivityGuard({
    setTimer: () => 1,
    clearTimer: () => {},
  });

  const handle = attachScrollActivityListeners({ doc, win, guard });
  assert.equal(win._listeners.get('wheel')?.[0]?.opts?.passive, true);
  assert.equal(win._listeners.get('touchmove')?.[0]?.opts?.passive, true);
  assert.equal(win._listeners.get('scroll')?.[0]?.opts?.passive, true);

  // Mount workspace dynamically (as createExplainer does) and sync
  ws = makeEventTarget({ id: EXPLAINER_WORKSPACE_ID, scrollLeft: 0, scrollTop: 1800 });
  handle.syncWorkspace();
  assert.equal(ws._listeners.get('scroll')?.length, 1);
  assert.equal(ws._listeners.get('scroll')?.[0]?.opts?.passive, true);

  // Idempotent sync does not double-bind
  handle.syncWorkspace();
  assert.equal(ws._listeners.get('scroll')?.length, 1);

  ws.scrollTop = 1940;
  ws.emit('scroll');
  assert.equal(guard.isScrolling(), true);

  guard.reset();
  win.emit('wheel');
  assert.equal(guard.isScrolling(), true);

  guard.reset();
  handle.detach();
  assert.equal(ws._listeners.get('scroll')?.length, 0);
  assert.equal(win._listeners.get('wheel')?.length, 0);
});

test('SS05 app.mjs, scroll-guard.mjs, explainer.css, and styles.css wire full-page scroll lock, overflow-anchor: none, strict CSP, and LF hygiene', async () => {
  const files = [
    ['ui/src/scroll-guard.mjs', '../../ui/src/scroll-guard.mjs'],
    ['ui/src/app.mjs', '../../ui/src/app.mjs'],
    ['ui/explainer.css', '../../ui/explainer.css'],
    ['ui/styles.css', '../../ui/styles.css'],
  ];
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;
  const loaded = {};

  for (const [label, rel] of files) {
    const raw = await readFile(new URL(rel, import.meta.url), 'utf8');
    loaded[label] = raw;
    assert.equal(raw.includes('\r'), false, `CRLF forbidden in ${label}`);
    assert.equal(innerHtmlRe.test(raw), false, `innerHTML/outerHTML forbidden in ${label}`);
    assert.equal(inlineStyleRe.test(raw), false, `Inline style attribute forbidden in ${label}`);
  }

  const appSrc = loaded['ui/src/app.mjs'];
  assert.match(appSrc, /from '\.\/scroll-guard\.mjs'/);
  assert.match(appSrc, /scrollGuard\.isScrolling\(\)/);
  assert.match(appSrc, /function restoreScrollPosition\(/);
  assert.match(appSrc, /window\.scrollTo\(/);
  assert.match(appSrc, /scrollListeners\?\.syncWorkspace\?\.\(\)/);
  assert.equal((appSrc.match(/captureScrollSnapshot\(/g) ?? []).length >= 7, true, 'All 7 render/rerender paths must capture scroll snapshot');
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false, 'All focus() calls in app.mjs must pass { preventScroll: true }');
  assert.equal(/localStorage/.test(appSrc), false, 'app.mjs must never write to localStorage');

  assert.match(loaded['ui/explainer.css'], /\.forex-explainer-workspace\s*\{[^}]*overflow-anchor:\s*none;/);
  assert.match(loaded['ui/styles.css'], /body\s*\{[^}]*overflow-anchor:\s*none;/);
});
