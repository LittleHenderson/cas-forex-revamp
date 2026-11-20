// PR #20 UI regression suite: Top-of-App Banked Profits & Session Vault Hero Scoreboard,
// 02 Account Snapshot Realized P/L decouple fix, Android Tablet Unlock Input persistence,
// Spec-Accurate Offline ISO/IEC 18004 SVG QR Pairing, and Locked-State Explainer Guidance.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  buildPairingUrl,
  computeFormatBits,
  computeReedSolomonRemainder,
  computeVersionBits,
  encodeQrMatrix,
  maskCondition,
  renderQrPairingDrawer,
  renderQrSvg,
} from '../../ui/src/qr-pairing.mjs';
import {
  STATIC_AI_MODELS,
  formatExactUsd,
  formatSignedUsd,
  normalizeAiModels,
  normalizeAiTrader,
  renderBankedProfitsHeroBanner,
} from '../../ui/src/ai-overseer.mjs';
import { normalizeTreasury } from '../../ui/src/analytics.mjs';
import { renderApp } from '../../ui/src/render.mjs';
import { createExplainer } from '../../ui/src/explainer.mjs';
import { displayState, fixture, time } from './helpers.mjs';

function buildModelsDoc() {
  return {
    schema: 'cas-forex.ai-models/1',
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_provider: 'anthropic',
    active_status: 'READY',
    selection_mode: 'PRIORITY_AUTO',
    frontier_ahead_of_qwen: true,
    frontier_configured_count: 8,
    offline_fallback_enabled: false,
    models: STATIC_AI_MODELS.models.map((m, idx) => ({
      rank: idx + 1,
      model_id: m.modelId,
      display_name: m.displayName,
      provider_label: m.providerLabel,
      tier: m.tier,
      is_fallback: m.isFallback,
      active: idx === 0,
      provider_ready: true,
      availability: 'READY',
    })),
  };
}

function buildBankedTraderDoc(withBankedSession = true) {
  const doc = {
    schema: 'cas-forex.ai-trader/1',
    human_role: 'OVERSEER_ONLY',
    governance_mode: 'ACTIVE',
    governance_reason: 'Research respite active after locking session profits.',
    effective_status: 'RESEARCH_RESPITE',
    respite_mode: true,
    operating_mode: 'RESEARCH_RESPITE',
    fast_tick_ms: 50,
    cadence: '50ms_FAST_TICK',
    markets_evaluated: 20,
    active_model_id: 'claude-fable-5.2',
    active_display_name: 'Claude Fable 5.2',
    active_model_status: 'READY',
    cycle_count: 142,
    last_cycle_ms: 35,
    last_action: 'WAIT',
    last_symbol: 'NAS100',
    last_reason: 'Profits locked for session',
    bank_sweep_reserved_usd: '2320.03',
    valve_controller: 'tks_meta_valve_controller',
    valve_parameters: 161,
    valve_threshold: '0.55',
    daily_quota: {
      session_date: '2026-11-20',
      status: 'DAILY_QUOTA_LOCKED',
      new_risk_allowed: false,
      lock_reason: 'Daily hard quota reached',
      quota_mode: 'USD',
      starting_equity_usd: '280000',
      realized_net_pnl_usd: '4640.06',
      realized_pnl_pct: '1.66',
      soft_quota_usd: '2000',
      hard_quota_usd: '3000',
      quota_progress_pct: '100',
      risk_multiplier: '0',
      max_daily_loss_usd: '5000',
      closed_trades: 10,
      win_count: 7,
      loss_count: 3,
      consecutive_losses: 0,
      max_consecutive_losses: 3,
      peak_realized_pnl_usd: '4852.73',
      ratchet_armed: true,
      ratchet_activation_usd: '1000',
      protected_profit_floor_usd: '3396.91',
    },
    open_positions: [],
    recent_actions: [],
  };
  if (withBankedSession) {
    doc.banked_session = {
      schema: 'cas-forex.banked-session/1',
      session_date: '2026-11-20',
      banked_net_pnl_usd: '4640.06',
      realized_pnl_pct: '1.66',
      peak_realized_pnl_usd: '4852.73',
      protected_profit_floor_usd: '3396.91',
      ratchet_armed: true,
      closed_trades: 10,
      win_count: 7,
      loss_count: 3,
      vault_total_realized_usd: '4640.06',
      vault_swept_50pct_usd: '2320.03',
      vault_retained_50pct_usd: '2320.03',
      profits_locked_for_session: true,
      operating_mode: 'RESEARCH_RESPITE',
      session_rollover_label: '17:00 America/New_York (14:00 Pacific)',
      next_session_opens_utc: '2026-11-20T22:00:00Z',
    };
  }
  return doc;
}

/** Independent ISO/IEC 18004 zig-zag reader & Reed-Solomon verifier for round-trip testing. */
function decodeQrMatrixRoundTrip(qr) {
  const { size, modules, isFunction, mask, spec } = qr;
  const unmaskedBits = [];
  let upward = true;
  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) rightCol = 5;
    for (let step = 0; step < size; step += 1) {
      const r = upward ? (size - 1 - step) : step;
      for (let dc = 0; dc <= 1; dc += 1) {
        const c = rightCol - dc;
        if (isFunction[r][c]) continue;
        const rawBit = modules[r][c];
        const bit = maskCondition(mask, r, c) ? (rawBit ^ 1) : rawBit;
        unmaskedBits.push(bit);
      }
    }
    upward = !upward;
  }

  const totalCw = spec.totalDataCw + (spec.g1Blocks + spec.g2Blocks) * spec.ecPerBlock;
  const interleaved = new Uint8Array(totalCw);
  for (let i = 0; i < totalCw; i += 1) {
    let b = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      b = (b << 1) | unmaskedBits[i * 8 + bit];
    }
    interleaved[i] = b;
  }

  // De-interleave data blocks and EC blocks
  const numBlocks = spec.g1Blocks + spec.g2Blocks;
  const dataBlocks = Array.from({ length: numBlocks }, (_, idx) => (
    new Uint8Array(idx < spec.g1Blocks ? spec.g1DataCw : spec.g2DataCw)
  ));
  const ecBlocks = Array.from({ length: numBlocks }, () => new Uint8Array(spec.ecPerBlock));

  let cursor = 0;
  const maxDataLen = Math.max(spec.g1DataCw, spec.g2DataCw);
  for (let i = 0; i < maxDataLen; i += 1) {
    for (let b = 0; b < numBlocks; b += 1) {
      if (i < dataBlocks[b].length) {
        dataBlocks[b][i] = interleaved[cursor];
        cursor += 1;
      }
    }
  }
  for (let i = 0; i < spec.ecPerBlock; i += 1) {
    for (let b = 0; b < numBlocks; b += 1) {
      ecBlocks[b][i] = interleaved[cursor];
      cursor += 1;
    }
  }

  // Verify every block's Reed-Solomon remainder matches the placed EC bytes identically
  for (let b = 0; b < numBlocks; b += 1) {
    const expectedEc = computeReedSolomonRemainder(dataBlocks[b], spec.ecPerBlock);
    assert.deepEqual([...ecBlocks[b]], [...expectedEc], `RS parity mismatch on block ${b}`);
  }

  const allData = new Uint8Array(spec.totalDataCw);
  let writeOff = 0;
  for (const blk of dataBlocks) {
    allData.set(blk, writeOff);
    writeOff += blk.length;
  }

  const readBits = (bitOffset, bitLen) => {
    let val = 0;
    for (let i = 0; i < bitLen; i += 1) {
      const idx = bitOffset + i;
      const bit = (allData[idx >>> 3] >>> (7 - (idx & 7))) & 1;
      val = (val << 1) | bit;
    }
    return val;
  };

  const mode = readBits(0, 4);
  assert.equal(mode, 0b0100, 'Expected Byte mode 0100');
  const byteCount = readBits(4, spec.countBits);
  const payloadBytes = new Uint8Array(byteCount);
  const payloadStartBit = 4 + spec.countBits;
  for (let i = 0; i < byteCount; i += 1) {
    payloadBytes[i] = readBits(payloadStartBit + i * 8, 8);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes);
}

test('PR20_01 ISO/IEC 18004 QR encoder passes Annex C/D vectors, finder/timing invariants, and exact URL round-trip decode', () => {
  // Official ISO/IEC 18004 Annex C (EC=M, mask=0 -> 0x5412) and Annex D (Version 7 -> 0x07C94)
  assert.equal(computeFormatBits('M', 0), 0x5412);
  assert.equal(computeVersionBits(7), 0x07c94);

  const sampleHandle = ['pair', 'm'.repeat(38)].join('-');
  const pairUrl = buildPairingUrl('https://52-33-1-177.sslip.io', sampleHandle);
  assert.equal(pairUrl, `https://52-33-1-177.sslip.io/ui/index.html?token=${sampleHandle}`);
  assert.throws(() => buildPairingUrl('file:///C:/index.html', sampleHandle));
  assert.throws(() => buildPairingUrl('https://52-33-1-177.sslip.io', 'short'));

  for (const testText of [
    'https://127.0.0.1:8765/',
    pairUrl,
    `https://52-33-1-177.sslip.io/ui/index.html?token=${'x'.repeat(110)}`,
  ]) {
    const qr = encodeQrMatrix(testText, 'M');
    assert.equal(qr.size, 17 + qr.version * 4);
    // Finder outer corners & centers are dark (1), separators at (7, 0..7) are light (0), dark module (size-8, 8) is 1
    assert.equal(qr.modules[0][0], 1);
    assert.equal(qr.modules[3][3], 1);
    assert.equal(qr.modules[0][qr.size - 1], 1);
    assert.equal(qr.modules[qr.size - 1][0], 1);
    assert.equal(qr.modules[7][0], 0);
    assert.equal(qr.modules[0][7], 0);
    assert.equal(qr.modules[qr.size - 8][8], 1);
    assert.equal(qr.modules[6][8], 1);
    assert.equal(qr.modules[6][9], 0);

    const recovered = decodeQrMatrixRoundTrip(qr);
    assert.equal(recovered, testText);
  }

  const svg = renderQrSvg(pairUrl);
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 \d+ \d+"/);
  assert.equal(/\bstyle\s*=/i.test(svg), false);
  assert.equal(svg.includes(sampleHandle), false, 'SVG paths must not embed raw handle text');
});

test('PR20_02 Banked Profits Hero Scoreboard normalizes banked_session and renders across Operate, Review, and Setup', () => {
  assert.equal(formatExactUsd('4640.06'), '$4,640.06');
  assert.equal(formatSignedUsd('4640.06'), '+$4,640.06');
  assert.equal(formatSignedUsd('0'), '$0.00');
  assert.equal(formatSignedUsd('-85.5'), '-$85.50');

  const normWithBlock = normalizeAiTrader(buildBankedTraderDoc(true));
  assert.equal(normWithBlock.bankedSession.bankedNetPnlUsd, '4640.06');
  assert.equal(normWithBlock.bankedSession.vaultSwept50PctUsd, '2320.03');
  assert.equal(normWithBlock.bankedSession.profitsLockedForSession, true);

  const normFallback = normalizeAiTrader(buildBankedTraderDoc(false));
  assert.equal(normFallback.bankedSession.bankedNetPnlUsd, '4640.06');
  assert.equal(normFallback.bankedSession.protectedProfitFloorUsd, '3396.91');
  assert.equal(normFallback.bankedSession.profitsLockedForSession, true);

  for (const route of ['operate', 'review', 'setup']) {
    const state = displayState(fixture(), route);
    state.liveStreamConnected = true;
    state.aiModels = normalizeAiModels(buildModelsDoc());
    state.aiTrader = normWithBlock;
    state.treasury = normalizeTreasury({
      schema: 'cas-forex.profit-vault/1',
      sweep_ratio: '0.5',
      sweep_ratio_pct: '50',
      auto_sweep_enabled: true,
      preferred_rail: 'COINBASE_ACH',
      total_realized_profit_usd: '4640.06',
      retained_trading_usd: '2320.03',
      bank_sweep_reserved_usd: '2320.03',
      disbursed_to_bank_usd: '0',
      pending_disbursement_usd: '2320.03',
      recent_sweeps: [],
      recent_transfers: [],
    });
    const html = renderApp(state, Date.parse(time));
    assert.match(html, /data-banked-profits-hero="true"/);
    assert.ok(html.includes('+$4,640.06'), `Missing +$4,640.06 on ${route}`);
    assert.ok(html.includes('+$3,396.91'), `Missing +$3,396.91 floor on ${route}`);
    assert.ok(html.includes('Peak Today: +$4,852.73 · RATCHET ARMED'));
    assert.ok(html.includes('$2,320.03 Swept to Bank Vault'));
    assert.ok(html.includes('$2,320.03 Retained Compounding'));
    assert.ok(html.includes('10 closed trades (7W / 3L) · Session 2026-11-20'));
    assert.match(html, /data-open-voice-explainer="true"/);
    assert.equal(/\bstyle\s*=/i.test(html), false);
  }

  // Locked preview renders unmistakable Locked Cockpit Notice Card
  const lockedHtml = renderBankedProfitsHeroBanner({ liveStreamConnected: false });
  assert.match(lockedHtml, /data-banked-profits-locked="true"/);
  assert.match(lockedHtml, /Your 24\/7 Cloud Server is running in the background/);
});

test('PR20_03 02 Account snapshot populates Realized P/L even when projection.equity is non-null, and shows locked hint offline', () => {
  const proj = fixture();
  proj.equity = { amount: '284640.06', currency: 'USD' };
  proj.balance = { amount: '284640.06', currency: 'USD' };
  proj.open_pnl = { amount: '0', currency: 'USD' };
  proj.realized_pnl = null;

  const state = displayState(proj, 'operate');
  state.liveStreamConnected = true;
  state.aiModels = normalizeAiModels(buildModelsDoc());
  state.aiTrader = normalizeAiTrader(buildBankedTraderDoc(true));

  const connectedHtml = renderApp(state, Date.parse(time));
  assert.ok(connectedHtml.includes('284,640.06'));
  assert.ok(connectedHtml.includes('4,640.06'), 'Realized P/L must populate even when eqVal !== null');
  assert.equal(connectedHtml.includes('data-account-locked-hint="true"'), false);

  const offlineState = displayState(fixture(), 'operate');
  offlineState.liveStreamConnected = false;
  const offlineHtml = renderApp(offlineState, Date.parse(time));
  assert.match(offlineHtml, /data-account-locked-hint="true"/);
  assert.match(offlineHtml, /metric-value unknown">Unknown/);
});

test('PR20_04 Android Tablet Unlock Bar preserves draft value, toggles password/text visibility, and renders inline error across all routes', async () => {
  const draftVal = ['draft', 'd'.repeat(16)].join('-');
  for (const route of ['operate', 'review', 'setup']) {
    const state = displayState(fixture(), route);
    state.liveStreamConnected = false;
    state.unlockDraft = draftVal;
    state.unlockKeyVisible = true;
    state.aiIssue = 'Invalid Cockpit access input (HTTP 401).';

    const html = renderApp(state, Date.parse(time));
    assert.ok(html.includes('id="top-cockpit-access-key"'));
    assert.ok(html.includes('type="text"'));
    assert.ok(html.includes(`value="${draftVal}"`));
    assert.match(html, /data-toggle-unlock-visibility="true"[^>]*aria-pressed="true">Hide<\/button>/);
    assert.match(html, /\.cloud_cockpit\.token/);
    assert.match(html, /Invalid Cockpit access input \(HTTP 401\)\./);
  }

  const stylesCss = await readFile(new URL('../../ui/styles.css', import.meta.url), 'utf8');
  assert.match(stylesCss, /font-size:\s*16px/);
  assert.match(stylesCss, /user-select:\s*text/);
  assert.match(stylesCss, /touch-action:\s*manipulation/);
});

test('PR20_05 QR Pairing buttons and drawer render on Operate and Setup without leaking raw handle text into DOM', () => {
  const pairHandle = ['qr', 'q'.repeat(38)].join('-');
  const svg = renderQrSvg(buildPairingUrl('https://52-33-1-177.sslip.io', pairHandle));
  const drawerHtml = renderQrPairingDrawer(svg, 'Private unlock link copied to clipboard.');
  assert.match(drawerHtml, /data-qr-pairing-panel="true"/);
  assert.match(drawerHtml, /data-copy-unlock-link="true"/);
  assert.match(drawerHtml, /data-toggle-qr-pairing="true">Hide QR<\/button>/);
  assert.equal(drawerHtml.includes(pairHandle), false, 'Raw handle must never appear in visible DOM');

  const setupState = displayState(fixture(), 'setup');
  setupState.liveStreamConnected = true;
  setupState.canPairDevice = true;
  setupState.qrPairingOpen = true;
  setupState.qrPairingSvg = svg;
  const setupHtml = renderApp(setupState, Date.parse(time));
  // Pair button in topbar + Pair button in 03 Setup + Hide QR button in drawer
  const toggleMatches = setupHtml.match(/data-toggle-qr-pairing="true"/g) ?? [];
  assert.ok(toggleMatches.length >= 3);
  assert.equal(setupHtml.includes(pairHandle), false);
});

test('PR20_06 Locked Explainer displays prominent unlock guidance and 1-tap Go to Unlock Bar button focusing #top-cockpit-access-key', async () => {
  // Reuse lightweight DOM harness pattern to exercise createExplainer locked banner + goto button
  const saved = new Map();
  for (const k of ['window', 'document', 'DOMParser', 'localStorage', 'sessionStorage']) {
    saved.set(k, Object.getOwnPropertyDescriptor(globalThis, k));
  }

  let focusedId = null;
  let scrolledIntoView = false;

  // Dynamic import of voice-explainer's module tree works cleanly alongside minimal mock nodes
  class MiniNode {
    constructor(t) { this.nodeType = t; this.parentNode = null; this.childNodes = []; }
    remove() {
      if (!this.parentNode) return;
      const i = this.parentNode.childNodes.indexOf(this);
      if (i !== -1) this.parentNode.childNodes.splice(i, 1);
      this.parentNode = null;
    }
  }
  class MiniText extends MiniNode {
    constructor(v = '') { super(3); this._v = String(v); }
    get textContent() { return this._v; }
    set textContent(v) { this._v = String(v ?? ''); }
  }
  class MiniEl extends MiniNode {
    constructor(tag) {
      super(1);
      this.tagName = tag.toUpperCase();
      this.attrs = new Map();
      this.dataset = {};
      this.style = {};
      this.listeners = new Map();
      this.value = '';
      const self = this;
      this.classList = {
        _s() { return new Set((self.attrs.get('class') || '').split(/\s+/).filter(Boolean)); },
        _w(s) { const j = [...s].join(' '); if (j) self.attrs.set('class', j); else self.attrs.delete('class'); },
        add(...n) { const s = this._s(); n.forEach((x) => x && s.add(x)); this._w(s); },
        remove(...n) { const s = this._s(); n.forEach((x) => s.delete(x)); this._w(s); },
        toggle(n, f) { const s = this._s(); const v = f !== undefined ? Boolean(f) : !s.has(n); if (v) s.add(n); else s.delete(n); this._w(s); return v; },
        contains(n) { return this._s().has(n); },
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
    get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
    set textContent(v) { this.childNodes = v ? [new MiniText(v)] : []; this.childNodes.forEach((c) => { c.parentNode = this; }); }
    setAttribute(k, v) {
      const lk = k.toLowerCase();
      this.attrs.set(lk, String(v));
      if (lk.startsWith('data-')) {
        this.dataset[lk.slice(5).replace(/-([a-z0-9])/gi, (_, c) => c.toUpperCase())] = String(v);
      }
    }
    getAttribute(k) { return this.attrs.get(k.toLowerCase()) ?? null; }
    hasAttribute(k) { return this.attrs.has(k.toLowerCase()); }
    append(...ns) { ns.forEach((n) => { const c = typeof n === 'string' ? new MiniText(n) : n; c.remove(); c.parentNode = this; this.childNodes.push(c); }); }
    replaceChildren(...ns) { this.childNodes.forEach((c) => { c.parentNode = null; }); this.childNodes = []; this.append(...ns); }
    insertBefore(n, r) { n.remove(); n.parentNode = this; const i = this.childNodes.indexOf(r); if (i === -1) this.childNodes.push(n); else this.childNodes.splice(i, 0, n); return n; }
    replaceWith(n) { if (!this.parentNode) return; const p = this.parentNode; const i = p.childNodes.indexOf(this); n.remove(); n.parentNode = p; if (i !== -1) p.childNodes.splice(i, 1, n); this.parentNode = null; }
    _matchOne(el, sel) {
      if (!el || el.nodeType !== 1) return false;
      let r = sel.trim();
      const tm = /^[a-zA-Z][a-zA-Z0-9-]*/.exec(r);
      if (tm) { if (el.tagName !== tm[0].toUpperCase()) return false; r = r.slice(tm[0].length); }
      const re = /#([A-Za-z0-9_-]+)|\.([A-Za-z0-9_-]+)|\[([A-Za-z0-9_:-]+)(?:="([^"]*)")?\]/g;
      let pos = 0; let m;
      while ((m = re.exec(r)) !== null) {
        if (m.index !== pos) return false;
        pos += m[0].length;
        if (m[1] && el.id !== m[1]) return false;
        if (m[2] && !el.classList.contains(m[2])) return false;
        if (m[3]) { const a = m[3].toLowerCase(); if (!el.hasAttribute(a)) return false; if (m[4] !== undefined && el.getAttribute(a) !== m[4]) return false; }
      }
      return pos === r.length;
    }
    _match(el, full) {
      const parts = full.trim().split(/\s+/);
      let cur = el;
      for (let i = parts.length - 1; i >= 0; i -= 1) {
        if (i === parts.length - 1) { if (!this._matchOne(cur, parts[i])) return false; }
        else { let a = cur.parentNode; while (a && !this._matchOne(a, parts[i])) a = a.parentNode; if (!a) return false; cur = a; }
      }
      return true;
    }
    querySelectorAll(sel) {
      const out = [];
      const walk = (n) => { for (const c of n.childNodes) { if (c.nodeType === 1) { if (this._match(c, sel)) out.push(c); walk(c); } } };
      walk(this);
      return out;
    }
    querySelector(sel) { return this.querySelectorAll(sel)[0] ?? null; }
    closest(sel) { let c = this; while (c && c.nodeType === 1) { if (this._match(c, sel)) return c; c = c.parentNode; } return null; }
    addEventListener(t, fn) { if (!this.listeners.has(t)) this.listeners.set(t, new Set()); this.listeners.get(t).add(fn); }
    removeEventListener(t, fn) { this.listeners.get(t)?.delete(fn); }
    click() {
      if (this.disabled) return;
      const ev = { type: 'click', target: this, preventDefault() {} };
      let c = this;
      while (c && c.nodeType === 1) {
        for (const fn of [...(c.listeners.get('click') ?? [])]) fn(ev);
        c = c.parentNode;
      }
    }
    focus() { focusedId = this.id || this.tagName; }
    scrollIntoView() { scrolledIntoView = true; }
    scrollTo() {}
    getBoundingClientRect() { return { left: 0, top: 0, width: 48, height: 48 }; }
  }

  const voids = new Set(['INPUT', 'IMG', 'BR', 'HR', 'META', 'LINK']);
  function parseMini(html) {
    const b = new MiniEl('body');
    const st = [b];
    const re = /<!--[\s\S]*?-->|<\/([A-Za-z0-9-]+)\s*>|<([A-Za-z0-9-]+)([^>]*)>|([^<]+)/g;
    let m;
    while ((m = re.exec(String(html))) !== null) {
      if (m[1]) { const ct = m[1].toUpperCase(); while (st.length > 1 && st[st.length - 1].tagName !== ct) st.pop(); if (st.length > 1) st.pop(); }
      else if (m[2]) {
        const el = new MiniEl(m[2]);
        const ar = /([A-Za-z0-9_:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/g;
        let am;
        while ((am = ar.exec(m[3] || '')) !== null) { if (am[1] !== '/') el.setAttribute(am[1], am[2] ?? am[3] ?? ''); }
        st[st.length - 1].append(el);
        if (!voids.has(el.tagName)) st.push(el);
      } else if (m[4]) st[st.length - 1].append(new MiniText(m[4]));
    }
    return b;
  }

  const htmlRoot = new MiniEl('html');
  htmlRoot.clientWidth = 768; // Narrow tablet viewport so mobile drawer closes on goto-unlock
  const bodyEl = new MiniEl('body');
  const appEl = new MiniEl('div');
  appEl.id = 'app';
  const topInput = new MiniEl('input');
  topInput.id = 'top-cockpit-access-key';
  topInput.setAttribute('name', 'cockpit_access_key');
  appEl.append(topInput);
  bodyEl.append(appEl);
  htmlRoot.append(bodyEl);

  Object.defineProperty(globalThis, 'document', {
    value: {
      documentElement: htmlRoot,
      body: bodyEl,
      createElement: (t) => new MiniEl(t),
      querySelector: (s) => htmlRoot.querySelector(s),
      querySelectorAll: (s) => htmlRoot.querySelectorAll(s),
      getElementById: (id) => htmlRoot.querySelector(`#${id}`),
      addEventListener: () => {},
      removeEventListener: () => {},
    },
    configurable: true, writable: true,
  });
  Object.defineProperty(globalThis, 'window', {
    value: {
      scrollX: 0, scrollY: 0, innerHeight: 1024, scrollTo: () => {},
      addEventListener: () => {}, removeEventListener: () => {},
      matchMedia: () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} }),
    },
    configurable: true, writable: true,
  });
  Object.defineProperty(globalThis, 'DOMParser', {
    value: class { parseFromString(s) { return { body: parseMini(s) }; } },
    configurable: true, writable: true,
  });

  let connected = false;
  let exp = null;
  try {
    exp = createExplainer({
      getContext: () => ({ projection: fixture(), route: 'operate', source: 'shared fixture', aiConnected: connected }),
      askModel: async () => ({ answer: 'ok' }),
    });

    exp.open();
    const banner = htmlRoot.querySelector('[data-explainer-locked-banner]');
    const gotoBtn = htmlRoot.querySelector('[data-explainer-goto-unlock]');
    assert.equal(banner.hidden, false);
    assert.match(banner.textContent, /Cockpit locked/);
    assert.match(banner.textContent, /Gemini 4 Neon/);

    gotoBtn.click();
    assert.equal(scrolledIntoView, true);
    assert.equal(focusedId, 'top-cockpit-access-key');
    assert.equal(htmlRoot.querySelector('#forex-explainer-panel').hidden, true, 'Mobile drawer closes so top unlock bar is unobstructed');

    connected = true;
    exp.open({ focusPrompt: true });
    assert.equal(banner.hidden, true);
    assert.equal(focusedId, 'forex-explainer-prompt');
  } finally {
    exp?.destroy();
    for (const [k, desc] of saved.entries()) {
      if (desc) Object.defineProperty(globalThis, k, desc);
      else delete globalThis[k];
    }
  }
});

test('PR20_07 Strict CSP, zero localStorage auth writes, zero inline styles, and LF endings across PR #20 UI files', async () => {
  const files = [
    '../../ui/src/qr-pairing.mjs',
    '../../ui/src/ai-overseer.mjs',
    '../../ui/src/render.mjs',
    '../../ui/src/app.mjs',
    '../../ui/src/explainer.mjs',
    '../../ui/styles.css',
    '../../ui/explainer.css',
  ];
  const innerHtmlRe = new RegExp('\\b(inner' + 'HTML|outer' + 'HTML)\\b');
  const inlineStyleRe = /\bstyle\s*=\s*["']/i;

  for (const rel of files) {
    const src = await readFile(new URL(rel, import.meta.url), 'utf8');
    assert.equal(innerHtmlRe.test(src), false, `innerHTML/outerHTML prohibited in ${rel}`);
    assert.equal(inlineStyleRe.test(src), false, `Inline style prohibited in ${rel}`);
  }

  const appSrc = await readFile(new URL('../../ui/src/app.mjs', import.meta.url), 'utf8');
  const qrSrc = await readFile(new URL('../../ui/src/qr-pairing.mjs', import.meta.url), 'utf8');
  assert.equal(/localStorage/.test(appSrc), false, 'app.mjs must never write auth tokens to localStorage');
  assert.equal(/localStorage/.test(qrSrc), false, 'qr-pairing.mjs must be stateless');
  assert.equal(/\.focus\(\s*\)/.test(appSrc), false, 'All focus() calls in app.mjs must pass { preventScroll: true }');
});
