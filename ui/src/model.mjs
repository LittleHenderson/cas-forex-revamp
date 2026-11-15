/** UI-only views derived from CockpitProjection v1. No dispatch, authority, or model adapter. */
export const CONTROL_COPY = Object.freeze({
  PAUSE_NEW_RISK: Object.freeze({ title: 'Pause new risk', summary: 'Blocks new OPEN / ADD requests.', consequence: 'Already accepted orders may still fill. Resting protective stops may execute independently. Management needs its own current permission.' }),
  STOP_AUTOMATION: Object.freeze({ title: 'Stop automation', summary: 'Blocks automated risk and management.', consequence: 'Positions remain open. Pending venue effects and resting protective stops can continue. Stop does not close or cancel them.' }),
});

export function formatDecimal(value) {
  const [whole, fraction] = value.split('.');
  const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return fraction === undefined ? grouped : `${grouped}.${fraction}`;
}

export function moneyLabel(value) {
  return value === null ? { amount: 'Unknown', unit: 'Not observed' } : { amount: formatDecimal(value.amount), unit: value.currency };
}

export function observationAge(observedAt, now = Date.now()) {
  if (observedAt === null) return { label: 'Not observed', detail: 'No venue observation time.', tone: 'warning' };
  const age = now - Date.parse(observedAt);
  if (age < 0) return { label: 'Future timestamp', detail: 'Clock mismatch. Validity unavailable.', tone: 'warning' };
  const seconds = Math.floor(age / 1000);
  const label = seconds < 60 ? `${seconds}s old` : seconds < 3600 ? `${Math.floor(seconds / 60)}m old` : `${Math.floor(seconds / 3600)}h old`;
  return { label, detail: 'Snapshot age only. Validity unavailable.', tone: 'neutral' };
}

export function positionSummary(projection) {
  if (projection.positions === null) return 'Inventory unknown';
  if (projection.positions.length === 0) return 'No positions in this snapshot';
  return `${projection.positions.length} position${projection.positions.length === 1 ? '' : 's'} in snapshot`;
}

export function pendingEffects(projection) {
  return [...new Set([
    ...projection.unresolved_command_ids,
    ...projection.commands.filter((command) => ['RESERVED', 'QUEUED', 'SUBMITTED', 'UNRESOLVED'].includes(command.state)).map((command) => command.command_id),
  ])];
}

/** References can be inspected but do not establish independently read effects. */
export function commandEffect(command) {
  return command.last_venue_receipt_id === null ? 'Venue effect unknown' : 'Receipt referenced · effect unverified';
}

export function decisionIdentity(decision) {
  if (decision === null) return { origin: 'No decision observed', model: 'Not observed', verification: 'No inference receipt attached.' };
  const p = decision.provenance;
  return {
    origin: `${p.origin.replaceAll('_', ' ')} · reported`,
    model: p.model_id ?? 'No model reported',
    verification: p.inference_receipt_id === null ? 'No inference receipt attached.' : 'Inference receipt referenced; independent validation unavailable.',
  };
}

/** Both List and Atlas render this same frozen record collection, without joining unrelated commands. */
export function reviewRecords(projection) {
  const decision = projection.last_decision;
  const decisionEntries = decision === null ? [] : [Object.freeze({
    id: `decision:${decision.decision_id}`, kind: 'PROPOSAL',
    title: decision.selection.selected_action_ref ?? 'WAIT',
    detail: decision.selection.reason, source: decision,
  })];
  return Object.freeze([...decisionEntries, ...projection.commands.map((command) => Object.freeze({
    id: `command:${command.command_id}`, kind: 'CORE RECORD', title: command.command_id,
    detail: commandEffect(command), source: command,
  }))]);
}

export function inspectRecord(view, recordId, records) {
  if (!records.some((record) => record.id === recordId)) throw new Error('Unknown inspection record.');
  return { ...view, focus_node_id: recordId };
}

export function resetInspection() {
  return { focus_node_id: null, hypothesis_branch_id: null };
}

/** Exact target review only; deliberately creates no owner request or command. */
export function closeReview(projection, positionId) {
  const position = projection.positions?.find((entry) => entry.position_id === positionId);
  if (!position) throw new Error('Position is unavailable in this snapshot.');
  return Object.freeze({
    account_id: projection.scope.account_id, run_id: projection.scope.run_id,
    state_id: projection.state_id, observed_at: projection.observed_at,
    position_id: position.position_id, version: position.version, instrument_id: position.instrument_id,
    side: position.side, quantity: position.quantity, unit: 'BASE_UNITS',
    send_enabled: false, reason: 'No authorized control transport is attached. Current target and authority must be checked by core.',
  });
}
