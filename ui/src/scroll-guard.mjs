// Zero-jump scroll preservation for the #forex-explainer-workspace inner scroll container,
// .market-watchlist sub-scroller, and window fallback during live SSE stream redraws.
// Pure ES module; strict CSP compliant with zero raw markup injection or inline styles.

export const SCROLL_QUIET_MS = 350;
export const PROGRAMMATIC_SCROLL_GRACE_MS = 120;
export const EXPLAINER_WORKSPACE_ID = 'forex-explainer-workspace';
export const WATCHLIST_SCROLL_SELECTOR = '.market-watchlist';

function finiteScroll(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

export function findWorkspaceScroller(doc) {
  if (!doc) return null;
  if (typeof doc.getElementById === 'function') {
    const byId = doc.getElementById(EXPLAINER_WORKSPACE_ID);
    if (byId) return byId;
  }
  if (typeof doc.querySelector === 'function') {
    return doc.querySelector(`#${EXPLAINER_WORKSPACE_ID}`);
  }
  return null;
}

export function findWatchlistScroller(doc) {
  if (!doc || typeof doc.querySelector !== 'function') return null;
  return doc.querySelector(WATCHLIST_SCROLL_SELECTOR);
}

export function captureScrollSnapshot(doc, win) {
  const ws = findWorkspaceScroller(doc);
  const wl = findWatchlistScroller(doc);
  return {
    windowX: finiteScroll(win?.scrollX),
    windowY: finiteScroll(win?.scrollY),
    workspaceLeft: finiteScroll(ws?.scrollLeft),
    workspaceTop: finiteScroll(ws?.scrollTop),
    watchlistTop: finiteScroll(wl?.scrollTop),
    hasWorkspace: Boolean(ws),
  };
}

export function restoreScrollSnapshot(snapshot, doc, win, { skipWindow = false } = {}) {
  const snap = snapshot ?? { windowX: 0, windowY: 0, workspaceLeft: 0, workspaceTop: 0, watchlistTop: 0 };
  let workspaceRestored = false;
  let watchlistRestored = false;
  let windowRestored = false;

  const ws = findWorkspaceScroller(doc);
  if (ws) {
    ws.scrollLeft = finiteScroll(snap.workspaceLeft);
    ws.scrollTop = finiteScroll(snap.workspaceTop);
    workspaceRestored = true;
  }

  const wl = findWatchlistScroller(doc);
  if (wl) {
    wl.scrollTop = finiteScroll(snap.watchlistTop);
    watchlistRestored = true;
  }

  if (!skipWindow && typeof win?.scrollTo === 'function') {
    win.scrollTo(finiteScroll(snap.windowX), finiteScroll(snap.windowY));
    windowRestored = true;
  }

  return { workspaceRestored, watchlistRestored, windowRestored };
}

export function createScrollActivityGuard({
  quietMs = SCROLL_QUIET_MS,
  programmaticGraceMs = PROGRAMMATIC_SCROLL_GRACE_MS,
  onQuiet = () => {},
  now = () => Date.now(),
  setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimer = (id) => globalThis.clearTimeout(id),
} = {}) {
  let scrolling = false;
  let quietTimer = null;
  let lastProgrammatic = null;

  function scheduleQuietRelease() {
    if (quietTimer !== null) clearTimer(quietTimer);
    quietTimer = setTimer(() => {
      quietTimer = null;
      scrolling = false;
      onQuiet();
    }, quietMs);
  }

  function markUserInputScroll() {
    scrolling = true;
    scheduleQuietRelease();
    return true;
  }

  function handleContainerScroll(doc, win) {
    if (lastProgrammatic && now() <= lastProgrammatic.untilMs) {
      const cur = captureScrollSnapshot(doc, win);
      const wsTopClose = Math.abs(cur.workspaceTop - lastProgrammatic.workspaceTop) <= 1;
      const wsLeftClose = Math.abs(cur.workspaceLeft - lastProgrammatic.workspaceLeft) <= 1;
      const winYClose = Math.abs(cur.windowY - lastProgrammatic.windowY) <= 1;
      const winXClose = Math.abs(cur.windowX - lastProgrammatic.windowX) <= 1;
      if (wsTopClose && wsLeftClose && winYClose && winXClose) {
        return false;
      }
    }
    return markUserInputScroll();
  }

  function restoreSnapshot(snapshot, doc, win, options = {}) {
    const snap = snapshot ?? { windowX: 0, windowY: 0, workspaceLeft: 0, workspaceTop: 0, watchlistTop: 0 };
    lastProgrammatic = {
      workspaceTop: finiteScroll(snap.workspaceTop),
      workspaceLeft: finiteScroll(snap.workspaceLeft),
      windowY: finiteScroll(snap.windowY),
      windowX: finiteScroll(snap.windowX),
      untilMs: now() + programmaticGraceMs,
    };
    return restoreScrollSnapshot(snap, doc, win, options);
  }

  function reset() {
    if (quietTimer !== null) {
      clearTimer(quietTimer);
      quietTimer = null;
    }
    scrolling = false;
    lastProgrammatic = null;
  }

  return {
    isScrolling: () => scrolling,
    markUserInputScroll,
    handleContainerScroll,
    restoreSnapshot,
    reset,
  };
}

export function attachScrollActivityListeners({ doc, win, guard, onPointerDown = null } = {}) {
  let attachedWorkspace = null;
  const passiveOpts = { passive: true };

  const onWheelOrTouch = () => {
    guard?.markUserInputScroll?.();
  };
  const onScroll = () => {
    guard?.handleContainerScroll?.(doc, win);
  };
  const onDocPointerDown = () => {
    if (typeof onPointerDown === 'function') onPointerDown();
  };

  win?.addEventListener?.('wheel', onWheelOrTouch, passiveOpts);
  win?.addEventListener?.('touchmove', onWheelOrTouch, passiveOpts);
  win?.addEventListener?.('scroll', onScroll, passiveOpts);
  if (typeof onPointerDown === 'function') {
    doc?.addEventListener?.('pointerdown', onDocPointerDown, passiveOpts);
  }

  function syncWorkspace() {
    const ws = findWorkspaceScroller(doc);
    if (ws === attachedWorkspace) return ws;
    if (attachedWorkspace) {
      attachedWorkspace.removeEventListener?.('scroll', onScroll, passiveOpts);
      attachedWorkspace = null;
    }
    if (ws) {
      ws.addEventListener?.('scroll', onScroll, passiveOpts);
      attachedWorkspace = ws;
    }
    return attachedWorkspace;
  }

  function detach() {
    win?.removeEventListener?.('wheel', onWheelOrTouch, passiveOpts);
    win?.removeEventListener?.('touchmove', onWheelOrTouch, passiveOpts);
    win?.removeEventListener?.('scroll', onScroll, passiveOpts);
    if (typeof onPointerDown === 'function') {
      doc?.removeEventListener?.('pointerdown', onDocPointerDown, passiveOpts);
    }
    if (attachedWorkspace) {
      attachedWorkspace.removeEventListener?.('scroll', onScroll, passiveOpts);
      attachedWorkspace = null;
    }
  }

  syncWorkspace();
  return { syncWorkspace, detach };
}
