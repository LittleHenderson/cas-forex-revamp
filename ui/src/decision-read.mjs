import { SnapshotError, parseUniqueJSON, assertSchema, freeze, decimalCoefficient, utcMicroseconds } from './wire.mjs';

export const MAX_REVIEW_BYTES = 1048576;
const fail = (message) => { throw new SnapshotError(message); };
const equal = (left, right) => canonicalJSON(left) === canonicalJSON(right);
const unique = (values, field) => { if (new Set(values).size !== values.length) fail(`${field}: duplicate identities.`); };

export function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
}

export function semanticBytes(envelope) {
  const { domain_digest: _digest, ...content } = envelope;
  return new TextEncoder().encode(canonicalJSON(content));
}

export function assertSelectedScope(envelope, cockpit) {
  if (!cockpit) fail('Load a cockpit snapshot before its decision records.');
  for (const field of ['account_id', 'run_id', 'epoch', 'build_id', 'policy_id', 'scenario_id', 'adapter_id']) {
    if (envelope.scope[field] !== cockpit.scope[field]) fail(`Review ${field} differs from the selected cockpit.`);
  }
  if (envelope.scope.environment_id !== cockpit.scope.environment) fail('Review environment differs from the selected cockpit.');
  if (envelope.current_state.state_id !== cockpit.state_id) fail('Review state differs from the selected cockpit snapshot.');
}

function orderedTimes(values) {
  const known = values.filter((value) => value !== null).map(utcMicroseconds);
  if (known.some((value, index) => index && value < known[index - 1])) fail('Review observation, availability or generation times are inconsistent.');
}

function coverage(value) {
  unique(value.omitted_ids, 'omitted_ids'); unique(value.deferred_ids, 'deferred_ids');
  if (value.total_known_count !== null && value.total_known_count < value.retained_count) fail('Coverage total is below retained count.');
  if (value.from_sequence !== null && value.through_sequence !== null && value.from_sequence > value.through_sequence) fail('Coverage range is reversed.');
  if (value.complete && (value.total_known_count === null || value.total_known_count !== value.retained_count || value.from_sequence === null || value.through_sequence === null || value.omitted_ids.length || value.deferred_ids.length || value.next_cursor !== null)) fail('Complete coverage requires known totals/ranges and no omitted records or page.');
  if (!value.complete && !value.reasons.some((reason) => reason.trim())) fail('Incomplete coverage needs a reason.');
}

function walkReferences(value) {
  if (typeof value === 'string') {
    if (new TextEncoder().encode(value).length > 1024) fail('Review text exceeds the UTF-8 byte limit.');
    return;
  }
  if (value === null || typeof value !== 'object') return;
  if (Object.hasOwn(value, 'unavailable_reason') && Object.hasOwn(value, 'record_id')) {
    if (value.record_id === null) {
      if (value.record_version !== null || value.record_sha256 !== null || !value.unavailable_reason?.trim()) fail('Unavailable reference requires a reason and null version/hash.');
    } else if (value.record_version === null || value.record_sha256 === null || value.unavailable_reason !== null) fail('Present reference needs exact version/hash and no unavailable reason.');
  }
  Object.values(value).forEach(walkReferences);
}

function assertParameters(parameters, actionKind) {
  const passive = ['WAIT', 'HOLD', 'STAND_DOWN'].includes(actionKind);
  if (passive && [parameters.quantity, parameters.limit_price, parameters.stop_price, parameters.side].some((value) => value !== null)) fail('WAIT/HOLD/STAND_DOWN cannot fabricate action geometry.');
  for (const field of ['quantity', 'limit_price', 'stop_price']) if (parameters[field] !== null && decimalCoefficient(parameters[field]) <= 0n) fail('Proposed quantity/price must be positive.');
}

export function assertDecisionReadSemantics(envelope, cockpit) {
  assertSelectedScope(envelope, cockpit);
  walkReferences(envelope);
  coverage(envelope.coverage);
  orderedTimes([envelope.as_of.observed_at, envelope.as_of.available_at, envelope.as_of.generated_at]);
  if (envelope.current_state.revision !== envelope.cursor.current_state_revision) fail('Current state and cursor revisions differ.');
  const current = envelope.current_state;
  if (current.observed_at !== null && current.valid_until !== null && utcMicroseconds(current.observed_at) >= utcMicroseconds(current.valid_until)) fail('Current-state expiry must follow observation.');
  if (current.freshness === 'CURRENT' && [current.state_id, current.state_sha256, current.revision, current.observed_at, current.valid_until, envelope.cursor.sequence, envelope.cursor.ledger_prefix_sha256].some((value) => value === null)) fail('Reported current state is missing observation/cursor identity.');
  for (const [records, id] of [[envelope.decisions, 'decision_id'], [envelope.events, 'event_id'], [envelope.evidence, 'evidence_id']]) unique(records.map((record) => record[id]), id);
  unique(envelope.events.map((event) => event.sequence), 'event sequences');
  const deferred = new Set([...envelope.coverage.omitted_ids, ...envelope.coverage.deferred_ids]);
  const eventIds = new Set(envelope.events.map((event) => event.event_id));
  const evidenceIds = new Set(envelope.evidence.map((evidence) => evidence.evidence_id));
  const requireRefs = (ids, available, field) => {
    unique(ids, field);
    if (ids.some((id) => !available.has(id) && !deferred.has(id))) fail(`${field}: unresolved ID without explicit coverage.`);
  };
  for (const record of [...envelope.decisions, ...envelope.events, ...envelope.evidence]) {
    if (!equal(record.scope, envelope.scope)) fail('Mixed-scope Review records.');
    const available = record.available_at ?? record.decided_at;
    if (available && envelope.as_of.available_at && utcMicroseconds(available) > utcMicroseconds(envelope.as_of.available_at)) fail('Record arrives after the Review checkpoint.');
  }
  for (const event of envelope.events) {
    orderedTimes([event.observed_at, event.available_at]);
    if (envelope.cursor.sequence === null || event.sequence > envelope.cursor.sequence) fail('Event lies beyond the Review cursor.');
    requireRefs(event.predecessor_ids, eventIds, 'event predecessors');
    if (event.predecessor_ids.includes(event.event_id)) fail('An event cannot precede itself.');
  }
  for (const evidence of envelope.evidence) orderedTimes([evidence.observed_at, evidence.available_at]);
  for (const decision of envelope.decisions) {
    coverage(decision.coverage);
    unique(decision.candidates.map((candidate) => candidate.candidate_id), 'candidate IDs');
    if (decision.cursor.sequence === null || envelope.cursor.sequence === null || decision.cursor.sequence > envelope.cursor.sequence) fail('Decision cursor is unavailable or beyond the page.');
    if (decision.cursor.sequence === envelope.cursor.sequence && decision.cursor.ledger_prefix_sha256 !== envelope.cursor.ledger_prefix_sha256) fail('Equal cursor sequences have different ledger prefixes.');
    for (const candidate of decision.candidates) {
      assertParameters(candidate.proposed_parameters, candidate.action_kind);
      requireRefs(candidate.evidence_ids, evidenceIds, 'candidate evidence');
      unique(candidate.known_facts.map((fact) => fact.fact_id), 'candidate facts');
      for (const fact of candidate.known_facts) requireRefs(fact.evidence_ids, evidenceIds, 'fact evidence');
    }
    const selection = decision.selection;
    const selected = decision.candidates.filter((candidate) => candidate.disposition === 'selected');
    if (selection === null) {
      if (selected.length) fail('Candidate is selected without a selection record.');
    } else {
      requireRefs(selection.evidence_ids, evidenceIds, 'selection evidence');
      if (selection.wait !== (selection.candidate_id === null)) fail('Selection must name a candidate or explicitly WAIT.');
      if (selection.wait) {
        if (selected.length) fail('WAIT cannot mark another candidate selected.');
        assertParameters(selection.proposed_bounds, 'WAIT');
      } else {
        const candidate = decision.candidates.find((item) => item.candidate_id === selection.candidate_id);
        if (!candidate || selected.length !== 1 || selected[0] !== candidate) fail('Selection and candidate disposition differ.');
        if (!equal(candidate.target, selection.target) || !equal(candidate.proposed_parameters, selection.proposed_bounds)) fail('Selection changed exact target or proposed parameters.');
      }
    }
    const origin = decision.origin;
    orderedTimes([origin.started_at, origin.completed_at, decision.decided_at]);
    if (origin.kind === 'actual-inference' && [origin.provider, origin.model_id, origin.model_artifact_sha256, origin.invocation_sha256, origin.inference_receipt.record_id, origin.budget_receipt.record_id].some((value) => value === null)) fail('Actual-inference claim has incomplete receipt/model/invocation references.');
  }
}

/** Hash equality is self-consistency only. There is intentionally no trust=true input. */
export async function decodeDecisionRead(raw, schema, cockpit) {
  if (schema?.$id !== 'urn:cas-forex:decision-read:0.1') fail('Shared decision-read schema unavailable or unsupported.');
  const envelope = parseUniqueJSON(raw, MAX_REVIEW_BYTES);
  assertSchema(envelope, schema);
  assertDecisionReadSemantics(envelope, cockpit);
  if (!globalThis.crypto?.subtle) fail('Review hash inspection is unavailable in this browser context.');
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', semanticBytes(envelope));
  const digest = [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, '0')).join('');
  if (digest !== envelope.domain_digest) fail('Decision-read semantic digest differs from the supplied content.');
  return freeze({ envelope, local: { shape: 'CHECKED', self_consistency: 'MATCHED', source_binding: 'UNVERIFIED', reference_resolution: 'UNAVAILABLE', reason: 'No external trusted producer, cursor anchor or controlled catalog is attached.' } });
}

export function envelopeRecords(read) {
  if (!read) return [];
  const envelope = read.envelope;
  return Object.freeze([
    ...envelope.decisions.map((decision) => Object.freeze({ id: `read-decision:${decision.decision_id}:${decision.revision}`, kind: 'DECISION', title: decision.decision_id, detail: decision.selection?.public_rationale ?? decision.status_reason, source: decision })),
    ...envelope.events.map((event) => Object.freeze({ id: `read-event:${event.event_id}`, kind: event.event_kind, title: event.event_id, detail: `${event.effect ?? 'No venue effect supplied'} · ${event.public_summary}`, source: event })),
    ...envelope.evidence.map((evidence) => Object.freeze({ id: `read-evidence:${evidence.evidence_id}`, kind: 'EVIDENCE', title: evidence.evidence_id, detail: `${evidence.producer_class} · ${evidence.assessment} · ${evidence.claim}`, source: evidence })),
  ]);
}
