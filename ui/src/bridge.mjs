/** Consumer of steward-owned docs/contracts/UI_TRANSPORT_V1.md. No HTTP adapter or auto-attachment. */
import { decodeCockpit, assertSchema, freeze, decimalCoefficient, isUTCTimestamp, utcMicroseconds } from './wire.mjs';
import { canonicalJSON, decodeDecisionRead } from './decision-read.mjs';
import { compareFenceReadback } from './control-observation.mjs';
import { resolveCatalog } from './catalog.mjs';

const METHODS = ['readBoot', 'readCockpit', 'readDecisionRead', 'prepareControl', 'requestControl', 'readControl', 'prepareClose', 'requestReviewedClose', 'readCommand'];
const CAPABILITY = { PAUSE_NEW_RISK: 'pause', STOP_AUTOMATION: 'stop', RESUME_NEW_RISK: 'resume_new_risk', RESUME_MANAGEMENT: 'resume_management' };
const id = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(value);
const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const equal = (left, right) => canonicalJSON(left) === canonicalJSON(right);
const require = (condition, message) => { if (!condition) throw new Error(message); };
const copy = (value) => freeze(structuredClone(value));
const keyFor = (scope) => ({ account_id: scope.account_id, run_id: scope.run_id, environment: scope.environment });

export async function sha256Bytes(bytes) {
  require(globalThis.crypto?.subtle, 'Hash verification unavailable.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, '0')).join('');
}

function validateFence(receipt, scope) {
  require(receipt && equal(receipt.key, keyFor(scope)), 'Independent fence scope mismatch.');
  require(id(receipt.barrier_id) && Number.isSafeInteger(receipt.generation) && receipt.generation >= 0 && Number.isSafeInteger(receipt.venue_sequence) && receipt.venue_sequence >= 0, 'Malformed independent fence identity.');
  require(['applied', 'new_risk_allowed', 'management_allowed'].every((field) => typeof receipt[field] === 'boolean') && isUTCTimestamp(receipt.observed_at), 'Malformed independent fence result.');
  return receipt;
}

function expectedPermissions(control, fence) {
  const result = { new_risk_allowed: fence.new_risk_allowed, management_allowed: fence.management_allowed };
  if (control === 'PAUSE_NEW_RISK') result.new_risk_allowed = false;
  if (control === 'STOP_AUTOMATION') { result.new_risk_allowed = false; result.management_allowed = false; }
  if (control === 'RESUME_NEW_RISK') result.new_risk_allowed = true;
  if (control === 'RESUME_MANAGEMENT') result.management_allowed = true;
  return result;
}

function validateBoot(boot, schema) {
  require(boot?.schema_version === 'forex.ui-transport/1', 'Unsupported transport version.');
  assertSchema(boot.scope, schema.$defs.scope, schema);
  require(boot.request_time === null || isUTCTimestamp(boot.request_time), 'Invalid transport clock.');
  require(boot.fence_generation === null || (Number.isSafeInteger(boot.fence_generation) && boot.fence_generation >= 0), 'Invalid transport generation.');
  require(boot.capabilities && ['pause', 'stop', 'resume_new_risk', 'resume_management', 'reviewed_close'].every((field) => typeof boot.capabilities[field] === 'boolean'), 'Invalid trusted capabilities.');
  require(hash(boot.decision_schema_sha256), 'Missing pinned decision schema hash.');
  if (boot.fence_receipt !== null) {
    validateFence(boot.fence_receipt, boot.scope);
    require(boot.fence_receipt.applied && boot.fence_receipt.generation === boot.fence_generation, 'Boot fence/generation mismatch.');
  } else require(boot.fence_generation === null, 'Generation cannot exist without independent fence.');
  return copy(boot);
}

function validateOutcome(result, requestId) {
  require(result?.request_id === requestId && ['ACCEPTED', 'REJECTED', 'UNKNOWN'].includes(result.status), 'Request outcome identity/status mismatch.');
  require(result.reason === null || typeof result.reason === 'string', 'Malformed request reason.');
  return result;
}

/** Validate exact independent command read; quantity buckets stay cumulative and separate. */
export function inspectCommandRead(result, preview, schema) {
  require(result && Object.hasOwn(result, 'command') && result.venue_lookup, 'Command read unavailable.');
  if (result.command !== null) {
    assertSchema(result.command, schema.$defs.command, schema);
    require(result.command.command_id === preview.command_id && result.command.payload_sha256 === preview.intent_sha256, 'Core command identity differs from reviewed Close.');
  }
  const lookup = result.venue_lookup;
  require(equal(lookup.key, keyFor(preview.scope)) && lookup.command_id === preview.command_id, 'Venue lookup belongs to another command/scope.');
  require(['FOUND', 'NOT_FOUND', 'UNKNOWN'].includes(lookup.state), 'Unsupported venue lookup state.');
  if (lookup.state !== 'FOUND') {
    require(lookup.receipt === null, 'Non-found lookup cannot carry a receipt.');
    if (lookup.state === 'NOT_FOUND') require(Number.isSafeInteger(lookup.observed_sequence) && lookup.observed_sequence >= 0, 'NOT_FOUND needs a successful journal cursor.');
    return copy({ status: lookup.state, reason: lookup.state === 'NOT_FOUND' ? 'Not found at this journal cursor. No automatic resend.' : 'Venue effect remains unknown.', command: result.command, receipt: null });
  }
  const receipt = lookup.receipt;
  require(receipt && equal(receipt.key, lookup.key) && receipt.command_id === preview.command_id && receipt.payload_sha256 === preview.intent_sha256, 'Receipt does not bind the reviewed command.');
  require(id(receipt.receipt_id) && Number.isSafeInteger(receipt.venue_sequence) && receipt.venue_sequence >= 0 && Number.isSafeInteger(lookup.observed_sequence) && lookup.observed_sequence >= receipt.venue_sequence, 'Receipt is outside its independent read cursor.');
  require(Number.isSafeInteger(receipt.dispatch_generation) && receipt.dispatch_generation >= 0 && isUTCTimestamp(receipt.observed_at), 'Receipt generation/time unavailable.');
  require(receipt.position_id === null || receipt.position_id === preview.intent.target_id, 'Receipt target differs from reviewed position.');
  require(utcMicroseconds(receipt.observed_at) >= utcMicroseconds(preview.intent.created_at), 'Receipt predates the reviewed intent.');
  require(['ACKNOWLEDGED', 'PARTIALLY_FILLED', 'FILLED', 'CANCELLED', 'REJECTED', 'APPLIED', 'UNKNOWN'].includes(receipt.effect), 'Unsupported venue effect.');
  const q = receipt.quantities;
  if (q !== null) {
    require(q && ['ordered', 'filled', 'cancelled', 'rejected', 'remaining'].every((field) => Object.hasOwn(q, field)), 'Receipt quantities incomplete.');
    const units = Object.fromEntries(['ordered', 'filled', 'cancelled', 'rejected', 'remaining'].map((field) => [field, decimalCoefficient(q[field])]));
    require(units.ordered > 0n && Object.values(units).every((value) => value >= 0n), 'Receipt quantities invalid.');
    require(units.ordered === decimalCoefficient(preview.intent.quantity), 'Observed order quantity differs from exact reviewed Close.');
    require(units.ordered === units.filled + units.cancelled + units.rejected + units.remaining, 'Receipt quantity conservation failed.');
    if (receipt.effect === 'ACKNOWLEDGED') require(units.filled === 0n && units.remaining === units.ordered, 'ACK cannot claim a fill.');
    if (receipt.effect === 'FILLED') require(units.filled === units.ordered, 'Full fill lacks complete observed quantity.');
    if (receipt.effect === 'PARTIALLY_FILLED') require(units.filled > 0n && units.filled < units.ordered && units.remaining > 0n, 'Partial fill requires an open remainder.');
    if (receipt.effect === 'CANCELLED') require(units.cancelled > 0n && units.remaining === 0n, 'Cancellation lacks cancelled remainder.');
    if (receipt.effect === 'REJECTED') require(units.rejected > 0n && units.remaining === 0n, 'Rejection lacks rejected remainder.');
  } else require(!['FILLED', 'PARTIALLY_FILLED'].includes(receipt.effect), 'Fill receipt lacks quantities.');
  return copy({ status: receipt.effect, reason: 'Independent venue receipt observed. Quantities are cumulative BASE_UNITS.', command: result.command, receipt });
}

export class ScopedBridge {
  #bridge = null; #generation = 0; #readGeneration = 0; #boundScope = null; #schema; #onChange; #newId; #monotonicNow;
  boot = null; clock = null; projection = null; controls = []; close = null; closeHistory = []; issue = null;
  constructor({ cockpitSchema, onChange = () => {}, newId = () => `ui-${globalThis.crypto.randomUUID()}`, monotonicNow = () => globalThis.performance?.now?.() ?? null }) {
    this.#schema = cockpitSchema; this.#onChange = onChange; this.#newId = newId; this.#monotonicNow = monotonicNow;
  }
  get attached() { return this.#bridge !== null; }
  snapshot() { return copy({ attached: this.attached, boot: this.boot, clock: this.clock, projection: this.projection, controls: this.controls, close: this.close, closeHistory: this.closeHistory, issue: this.issue, available: { ...Object.fromEntries(Object.keys(CAPABILITY).map((control) => [control, this.canControl(control)])), close: this.canClose() } }); }
  #observeClock(boot, receivedAt) { this.clock = copy({ request_time: boot.request_time, received_at_monotonic_ms: receivedAt, invalidated: false }); }
  invalidateReadAge() {
    if (!this.clock) return;
    this.clock = copy({ ...this.clock, invalidated: true }); this.#emit();
  }
  #emit() { this.#onChange(this.snapshot()); }
  #active(generation) { require(this.#bridge !== null && generation === this.#generation, 'Transport detached or scope changed.'); }
  async attach(bridge) {
    require(!this.attached, 'Detach the previous bridge before changing scope.');
    require(bridge && METHODS.every((method) => typeof bridge[method] === 'function'), 'Explicit scoped bridge methods are required.');
    this.#bridge = bridge; this.#boundScope = null; this.#generation += 1;
    try { await this.refresh(); } catch (error) { this.detach(); throw error; }
    return this.snapshot();
  }
  detach() {
    this.#generation += 1; this.#bridge = null; this.boot = null; this.clock = null; this.projection = null;
    this.controls = this.controls.map((item) => ({ ...item, status: 'UNCONFIRMED', reason: 'Transport detached. Historical request identity retained; effect not re-observed.' }));
    if (this.close) this.close = { ...this.close, status: 'UNCONFIRMED', reason: 'Transport detached; no automatic resubmission.' };
    this.issue = 'Transport unavailable. Backend state is unobserved.'; this.#emit();
  }
  async refresh() {
    require(this.attached, 'Transport unavailable.');
    const generation = this.#generation; const readGeneration = ++this.#readGeneration; const bridge = this.#bridge;
    try {
      const boot = validateBoot(await bridge.readBoot(), this.#schema); this.#active(generation);
      const receivedAt = this.#monotonicNow();
      if (this.#boundScope) require(equal(boot.scope, this.#boundScope), 'Bridge scope cannot change after attachment.');
      else this.#boundScope = boot.scope;
      const projection = decodeCockpit(JSON.stringify(await bridge.readCockpit()), this.#schema); this.#active(generation);
      require(equal(projection.scope, boot.scope), 'Cockpit differs from attached scope.');
      if (readGeneration !== this.#readGeneration) return this.snapshot();
      if (this.close && !equal(this.close.input.scope, boot.scope)) {
        this.closeHistory = [...this.closeHistory, copy(this.close)]; this.close = null;
      }
      this.boot = boot; this.#observeClock(boot, receivedAt); this.projection = projection; this.issue = null; this.#emit(); return this.snapshot();
    } catch (error) { if (generation === this.#generation && readGeneration === this.#readGeneration) { this.boot = null; this.clock = null; this.projection = null; this.issue = error.message; this.#emit(); } throw error; }
  }
  canControl(control) {
    return Boolean(this.attached && this.boot?.capabilities[CAPABILITY[control]] && this.boot.request_time !== null && this.boot.fence_receipt?.applied && !this.controls.some((item) => item.control === control && ['PREPARING', 'REQUESTING', 'READING'].includes(item.status)));
  }
  async control(control) {
    require(this.canControl(control), 'Scoped control is unavailable. Read current boot/fence first.');
    const generation = this.#generation; const bridge = this.#bridge; const boot = this.boot;
    const requestId = this.#newId(); require(id(requestId), 'Invalid local request identity.');
    const record = { id: requestId, control, scope: boot.scope, status: 'PREPARING', reason: 'Preparing exact request; no effect confirmed.', request: null, expected: expectedPermissions(control, boot.fence_receipt), receipt: null };
    this.controls = [...this.controls, record]; this.#emit();
    try {
      const request = await bridge.prepareControl({ request_id: requestId, scope: boot.scope, control, expected_generation: boot.fence_generation }); this.#active(generation);
      require(request?.owner_request_id === requestId && request.control === control && equal(request.key, keyFor(boot.scope)) && request.expected_generation === boot.fence_generation && request.next_generation === boot.fence_generation + 1 && id(request.barrier_id) && isUTCTimestamp(request.requested_at), 'Prepared control differs from explicit request.');
      require(utcMicroseconds(request.requested_at) >= utcMicroseconds(boot.request_time), 'Prepared request clock precedes boot observation.');
      record.request = copy(request); record.status = 'REQUESTING'; record.reason = 'Request sent; awaiting independent readback.'; this.#emit();
      try {
        const result = validateOutcome(await bridge.requestControl(record.request), requestId); this.#active(generation);
        record.status = result.status === 'ACCEPTED' ? 'ACCEPTED_UNCONFIRMED' : result.status; record.reason = result.reason ?? 'No independent effect established.'; this.#emit();
        if (result.status === 'REJECTED') return this.snapshot();
      } catch (error) { this.#active(generation); record.status = 'UNKNOWN'; record.reason = error.message; this.#emit(); }
      await this.checkControl(requestId); return this.snapshot();
    } catch (error) { if (generation === this.#generation) { record.status = record.request ? 'UNCONFIRMED' : 'PREPARATION_FAILED'; record.reason = error.message; this.#emit(); } throw error; }
  }
  async checkControl(requestId) {
    const record = this.controls.find((item) => item.id === requestId);
    require(this.attached && record?.request && equal(record.scope, this.boot?.scope), 'Exact control readback unavailable.');
    const generation = this.#generation; const bridge = this.#bridge;
    record.status = 'READING'; record.reason = 'Reading independent fence. Acceptance alone is not confirmation.'; this.#emit();
    try {
      const receipt = copy(await bridge.readControl(record.request)); this.#active(generation);
      const result = compareFenceReadback(record.request, receipt, record.expected);
      record.receipt = receipt; record.status = result.matches ? 'CONFIRMED' : 'UNCONFIRMED'; record.reason = result.reason;
      // This is a new independent observation, not a retry or an inferred core grant.
      validateFence(receipt, record.scope);
      if (receipt.applied && this.boot && (this.boot.fence_generation === null || receipt.generation >= this.boot.fence_generation)) {
        this.boot = copy({ ...this.boot, fence_generation: receipt.generation, fence_receipt: receipt });
      }
      this.#emit();
    } catch (error) { if (generation === this.#generation) { record.status = 'UNCONFIRMED'; record.reason = error.message; this.#emit(); } }
    return this.snapshot();
  }
  canClose() { return Boolean(this.attached && this.boot?.capabilities.reviewed_close && this.boot.request_time !== null && this.projection?.state_id && this.projection?.positions && (!this.close || (!this.close.submitted && !['PREPARING', 'CHECKING', 'REQUESTING', 'READING'].includes(this.close.status)) || ['FILLED', 'CANCELLED', 'REJECTED'].includes(this.close.status))); }
  async prepareClose(positionId) {
    require(this.canClose(), 'Reviewed Close is unavailable.');
    const generation = this.#generation; const bridge = this.#bridge; const boot = this.boot;
    const position = this.projection.positions.find((item) => item.position_id === positionId);
    require(position, 'Exact position is absent.');
    if (this.close) this.closeHistory = [...this.closeHistory, copy(this.close)];
    const input = { owner_request_id: this.#newId(), command_id: this.#newId(), scope: boot.scope, source_state_id: this.projection.state_id, position_id: position.position_id, position_version: position.version, quantity: position.quantity, quantity_unit: 'BASE_UNITS' };
    this.close = { status: 'PREPARING', reason: 'Preparing exact target for review.', preview: null, input, observation: null, submitted: false }; this.#emit();
    try {
      const preview = await bridge.prepareClose(input); this.#active(generation);
      require(id(preview?.preview_id) && preview.owner_request_id === input.owner_request_id && preview.command_id === input.command_id && equal(preview.scope, input.scope), 'Close preview identity differs from request.');
      const intent = preview.intent;
      require(intent?.kind === 'CLOSE' && intent.origin === 'OWNER_REVIEWED' && equal(intent.scope, input.scope) && intent.source_state?.state_id === input.source_state_id && equal(intent.source_state.scope, input.scope), 'Close preview source/scope differs.');
      require(intent.target_id === input.position_id && intent.target_version === input.position_version && intent.quantity === input.quantity && intent.instrument_id === position.instrument_id, 'Close preview changed exact target/version/quantity.');
      require(['intent_id', 'decision_id', 'opportunity_id', 'action_ref'].every((field) => id(intent[field])) && isUTCTimestamp(intent.created_at) && isUTCTimestamp(intent.source_state.observed_at) && isUTCTimestamp(intent.source_state.valid_until), 'Close intent identity/lifetime unavailable.');
      require(['version', 'venue_sequence'].every((field) => Number.isSafeInteger(intent.source_state[field]) && intent.source_state[field] >= 0), 'Close source version/cursor unavailable.');
      require(utcMicroseconds(intent.source_state.observed_at) <= utcMicroseconds(intent.created_at) && utcMicroseconds(intent.created_at) < utcMicroseconds(intent.expires_at) && utcMicroseconds(intent.expires_at) <= utcMicroseconds(intent.source_state.valid_until), 'Close intent lifetime is outside source validity.');
      require(hash(preview.intent_sha256) && isUTCTimestamp(preview.expires_at) && preview.expires_at === intent.expires_at && utcMicroseconds(preview.expires_at) > utcMicroseconds(boot.request_time), 'Close preview expired or malformed.');
      require(await sha256Bytes(new TextEncoder().encode(canonicalJSON(intent))) === preview.intent_sha256, 'Close intent hash differs from reviewed content.'); this.#active(generation);
      this.close = { ...this.close, preview: copy(preview), status: 'REVIEW_REQUIRED', reason: 'Review exact intent before requesting Close.' }; this.#emit(); return this.snapshot();
    } catch (error) { if (generation === this.#generation) { this.close = { ...this.close, status: 'PREPARATION_FAILED', reason: error.message }; this.#emit(); } throw error; }
  }
  async submitClose(previewId) {
    require(this.attached && this.close?.status === 'REVIEW_REQUIRED' && this.close.preview.preview_id === previewId, 'Exact reviewed preview unavailable or already submitted.');
    const generation = this.#generation; const bridge = this.#bridge; const preview = this.close.preview;
    this.close = { ...this.close, status: 'CHECKING', reason: 'Checking current owner clock before submission.' }; this.#emit();
    try {
      const boot = validateBoot(await bridge.readBoot(), this.#schema); this.#active(generation);
      require(equal(boot.scope, preview.scope) && boot.capabilities.reviewed_close && boot.request_time !== null && utcMicroseconds(boot.request_time) < utcMicroseconds(preview.expires_at), 'Close preview expired or owner scope changed. Review a fresh target.');
      this.close = { ...this.close, status: 'REQUESTING', reason: 'Close requested; no fill established.', submitted: true }; this.#emit();
      try {
        const outcome = validateOutcome(await bridge.requestReviewedClose({ preview_id: preview.preview_id, owner_request_id: preview.owner_request_id, command_id: preview.command_id, scope: preview.scope, intent_sha256: preview.intent_sha256 }), preview.owner_request_id); this.#active(generation);
        if (outcome.command !== null) { assertSchema(outcome.command, this.#schema.$defs.command, this.#schema); require(outcome.command.command_id === preview.command_id && outcome.command.payload_sha256 === preview.intent_sha256, 'Accepted command differs from reviewed intent.'); }
        this.close = { ...this.close, status: outcome.status === 'ACCEPTED' ? 'ACCEPTED_UNCONFIRMED' : outcome.status, reason: outcome.reason ?? 'No venue effect established.' }; this.#emit();
        if (outcome.status === 'REJECTED') return this.snapshot();
      } catch (error) { this.#active(generation); this.close = { ...this.close, status: 'UNKNOWN', reason: error.message }; this.#emit(); }
      return await this.checkClose();
    } catch (error) { if (generation === this.#generation) { this.close = { ...this.close, status: this.close.submitted ? 'UNCONFIRMED' : 'PREPARATION_FAILED', reason: error.message }; this.#emit(); } throw error; }
  }
  async checkClose() {
    require(this.attached && this.close?.preview && this.close.submitted && equal(this.close.preview.scope, this.#boundScope) && !['PREPARING', 'REVIEW_REQUIRED', 'PREPARATION_FAILED', 'CHECKING', 'REQUESTING', 'READING'].includes(this.close.status), 'No submitted Close to observe.');
    const generation = this.#generation; const bridge = this.#bridge; const preview = this.close.preview;
    this.close = { ...this.close, status: 'READING', reason: 'Reading exact command and independent venue receipt.' }; this.#emit();
    try {
      const observation = inspectCommandRead(await bridge.readCommand(preview.command_id), preview, this.#schema); this.#active(generation);
      this.close = { ...this.close, status: observation.status, reason: observation.reason, observation }; this.#emit();
    } catch (error) { if (generation === this.#generation) { this.close = { ...this.close, status: 'UNKNOWN', reason: error.message }; this.#emit(); } }
    return this.snapshot();
  }
  async readReview(schema, rawSchemaBytes) {
    require(this.attached && this.boot && this.projection, 'Bound Review source unavailable.');
    const generation = this.#generation; const bridge = this.#bridge; const boot = this.boot; const projection = this.projection;
    require(await sha256Bytes(rawSchemaBytes) === boot.decision_schema_sha256, 'Bridge schema pin differs from exact shared schema bytes.'); this.#active(generation);
    const result = await bridge.readDecisionRead(); this.#active(generation);
    const read = await decodeDecisionRead(JSON.stringify(result.envelope), schema, projection); this.#active(generation);
    const anchor = result.anchor;
    const fields = ['anchor_id', 'producer_id', 'schema_sha256', 'domain_sha256', 'scope_sha256', 'cursor_sha256', 'issued_at', 'expires_at', 'reconciliation_confirmed'];
    require(anchor && Object.keys(anchor).length === fields.length && fields.every((field) => Object.hasOwn(anchor, field)) && id(anchor.anchor_id) && id(anchor.producer_id) && isUTCTimestamp(anchor.issued_at) && isUTCTimestamp(anchor.expires_at) && typeof anchor.reconciliation_confirmed === 'boolean', 'Trusted bridge anchor unavailable.');
    let current = validateBoot(await bridge.readBoot(), this.#schema); this.#active(generation);
    let receivedAt = this.#monotonicNow();
    require(equal(current.scope, boot.scope) && current.decision_schema_sha256 === boot.decision_schema_sha256, 'Bridge identity changed during Review read.');
    require(current.request_time !== null && utcMicroseconds(anchor.issued_at) <= utcMicroseconds(current.request_time) && utcMicroseconds(current.request_time) < utcMicroseconds(anchor.expires_at), 'Read anchor is not valid at the selected authoritative clock.');
    require(anchor.schema_sha256 === boot.decision_schema_sha256 && anchor.domain_sha256 === read.envelope.domain_digest, 'Read anchor schema/domain mismatch.');
    require(anchor.scope_sha256 === await sha256Bytes(new TextEncoder().encode(canonicalJSON(read.envelope.scope))) && anchor.cursor_sha256 === await sha256Bytes(new TextEncoder().encode(canonicalJSON(read.envelope.cursor))), 'Read anchor scope/cursor mismatch.'); this.#active(generation);
    require(this.projection === projection, 'Cockpit changed while Review was being read. Read the current state again.');
    const checkActive = () => { this.#active(generation); require(this.projection === projection, 'Cockpit changed during catalog inspection. Read current state again.'); };
    const catalog = await resolveCatalog({ envelope: read.envelope, schema, anchor, resolve: typeof bridge.resolveEvidence === 'function' ? (input) => bridge.resolveEvidence(input) : null, hashBytes: sha256Bytes, checkActive });
    checkActive();
    if (catalog.requested_count && typeof bridge.resolveEvidence === 'function') {
      current = validateBoot(await bridge.readBoot(), this.#schema); receivedAt = this.#monotonicNow(); checkActive();
      require(equal(current.scope, boot.scope) && current.decision_schema_sha256 === boot.decision_schema_sha256, 'Bridge identity changed during catalog inspection.');
      require(current.request_time !== null && utcMicroseconds(anchor.issued_at) <= utcMicroseconds(current.request_time) && utcMicroseconds(current.request_time) < utcMicroseconds(anchor.expires_at), 'Read anchor expired during catalog inspection.');
    }
    this.boot = current; this.#observeClock(current, receivedAt); this.#emit();
    return copy({ envelope: read.envelope, local: { ...read.local, source_binding: 'BRIDGE_ANCHOR_MATCHED', reference_resolution: catalog.status, semantic_verification: 'NOT_ESTABLISHED', reason: catalog.reason }, anchor, catalog });
  }
}
