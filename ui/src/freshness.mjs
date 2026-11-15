/** Display-only clock selection. Elapsed local time never advances synthetic UTC. */
import { isUTCTimestamp, utcMicroseconds } from './wire.mjs';
import { observationAge } from './model.mjs';

// Local display invalidation, not a venue expiry, owner lease, or execution grant.
export const CLOCK_READ_MAX_AGE_MS = 30000;
const monotonicTime = () => globalThis.performance?.now?.() ?? null;

export function displayFreshness(state, { wallNow = Date.now(), monotonicNow = monotonicTime() } = {}) {
  const observedAt = state.projection?.observed_at ?? null;
  if (!state.transport?.attached) {
    const age = observationAge(observedAt, wallNow);
    return { ...age, detail: `Unbound snapshot; wall-clock comparison. ${age.detail}`, clock_basis: 'UNBOUND', invalidated: true, read_age_ms: null };
  }
  const clock = state.transport.clock;
  const requestTime = clock?.request_time;
  const elapsed = Number.isFinite(monotonicNow) && Number.isFinite(clock?.received_at_monotonic_ms) ? monotonicNow - clock.received_at_monotonic_ms : null;
  const base = { clock_basis: 'SIMULATOR', request_time: requestTime ?? null, read_age_ms: elapsed };
  if (!isUTCTimestamp(requestTime)) return { ...base, label: 'Simulator clock unavailable', detail: 'Read the scoped clock. Browser time cannot replace it.', tone: 'warning', invalidated: true };
  if (clock.invalidated) return { ...base, label: 'Simulator read unconfirmed', detail: 'Tab visibility changed. Read current state again; no simulated advancement inferred.', tone: 'warning', invalidated: true };
  if (elapsed === null || elapsed < 0) return { ...base, label: 'Simulator read unconfirmed', detail: 'Local read age is unavailable. Read current state again.', tone: 'warning', invalidated: true };
  if (elapsed >= CLOCK_READ_MAX_AGE_MS) return { ...base, label: 'Simulator read expired', detail: `Clock read ${Math.floor(elapsed / 1000)}s ago locally. Read state again; no simulated advancement inferred.`, tone: 'warning', invalidated: true };
  if (!isUTCTimestamp(observedAt)) return { ...base, label: 'Not observed / simulator', detail: `No venue observation time. Clock read ${Math.floor(elapsed / 1000)}s ago locally.`, tone: 'warning', invalidated: true };
  const age = utcMicroseconds(requestTime) - utcMicroseconds(observedAt);
  if (age < 0n) return { ...base, label: 'Future timestamp / simulator', detail: 'Observation exceeds the independently read simulator clock. Read current state again.', tone: 'warning', invalidated: true };
  const seconds = age / 1000000n;
  const label = seconds < 60n ? `${seconds}s` : seconds < 3600n ? `${seconds / 60n}m` : `${seconds / 3600n}h`;
  return { ...base, label: `${label} old / simulator`, detail: `Simulator time at read; clock read ${Math.floor(elapsed / 1000)}s ago locally. Validity not established.`, tone: 'neutral', invalidated: false };
}
