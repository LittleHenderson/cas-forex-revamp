"""Explicit read-only projection over independent stores; no reconcile or grants.

The injected sources select trust. An imported envelope cannot appoint them.
Catalogs freeze each read as canonical bytes, and references never resolve to a
newer record. This finite-run producer intentionally rejects oversized histories.
"""
from __future__ import annotations

from dataclasses import fields, replace
from datetime import timedelta
from hashlib import sha256
import json

from ..contracts import (ContractError, DecisionResult, InferenceBudget, Permissions, RecoveryState, canonical_bytes,
                         content_digest)
from ..contracts.primitives import digest, integer, utc_time
from ..core.storage import decode
from ..rpa.read_binding import TrustedReadAnchor
from ..rpa.schema_validation import PinnedDecisionReadValidator


def wire(value):
    return json.loads(canonical_bytes(value))


def require_model_source(source):
    """Check the selected reader's output shape, never independent model proof.

    ModelDecisionReader owns receipt/invocation verification. Fake software
    readers remain test fixtures; a structurally valid record proves no inference.
    Freeze the returned data so later callback mutation cannot change this read.
    """
    required = {'receipt', 'sources', 'invocation_sha256', 'budget', 'latency_ms'}
    if type(source) is not dict or not required <= source.keys():
        raise ContractError('model reader evidence is missing required fields')
    if type(source['budget']) not in (dict, InferenceBudget):
        raise ContractError('model reader budget has no supported schema')
    snapshot = wire(source)
    if type(snapshot['receipt']) is not dict or not snapshot['receipt']:
        raise ContractError('model reader receipt is missing or malformed')
    if (type(snapshot['sources']) is not list
            or any(type(record) is not dict or not record for record in snapshot['sources'])):
        raise ContractError('model reader source records are malformed')
    digest(snapshot['invocation_sha256'], 'model invocation sha256')
    integer(snapshot['latency_ms'], 'model latency_ms', minimum=0)
    budget = snapshot['budget']
    if type(budget) is not dict or set(budget) != {f.name for f in fields(InferenceBudget)}:
        raise ContractError('model reader budget fields differ from schema')
    InferenceBudget(**budget)
    return snapshot


def absent(reason):
    return dict(record_id=None, record_version=None, record_sha256=None, unavailable_reason=reason)


def read_scope(scope):
    result = wire(scope)
    result['environment_id'] = result.pop('environment')
    return {**result, 'mode': 'SIMULATED', 'ledger_schema': 'core.sqlite/1', 'policy_version': '1'}


def coverage(count, sequence, *, reasons=(), omitted=()):
    return dict(complete=not reasons and not omitted, from_sequence=0, through_sequence=sequence,
                retained_count=count, total_known_count=count + len(omitted), omitted_ids=list(omitted),
                deferred_ids=[], reasons=list(reasons), next_cursor=None)


def uncertainty(field, reason):
    return dict(field_or_claim=field, reason=reason, action_effect='No authority or effect inferred.',
                required_observation='A matching independent source record.', origin_record_id=None)


class _Catalog:
    def __init__(self):
        self.records = {}

    def add(self, kind, value, version=1):
        raw = canonical_bytes(value)
        digest = sha256(raw).hexdigest()
        record_id = kind + '-' + digest
        ref = dict(record_id=record_id, record_version=version, record_sha256=digest, unavailable_reason=None)
        prior = self.records.get(record_id)
        if prior is not None and prior != (ref, raw):
            raise ContractError('catalog identity conflict')
        self.records[record_id] = (ref, raw)
        return ref


class DecisionReadService:
    """Constructor inert; callers explicitly read one selected current RunScope.

    This service does not repair incoherence. Its bounded catalog is retained in
    this process for at most eight issued reads; expiry always invalidates it.
    Whole-file rollback still needs the independently retained store checkpoints.
    """
    def __init__(self, *, scope, core, venue, journal, clock, schema_bytes, schema_sha256,
                 instruments, producer_id='composition-read-1', model_reader=None):
        self.scope, self.core, self.venue, self.journal, self.clock = scope, core, venue, journal, clock
        self.schema_sha256, self.producer_id = schema_sha256, producer_id
        self.validator = PinnedDecisionReadValidator(schema_bytes, expected_sha256=schema_sha256)
        self.instruments = {i.instrument_id: i for i in instruments}
        self._issued = {}
        self.model_reader = model_reader

    def _decision_source(self, request, result):
        provenance = result['provenance']
        if content_digest(request) != provenance['request_sha256']:
            raise ContractError('decision request digest conflict')
        if provenance['origin'] == 'SCRIPTED':
            if content_digest(result['selection']) != provenance['response_sha256']:
                raise ContractError('scripted selection digest conflict')
            return None
        if provenance['origin'] != 'ACTUAL_MODEL' or not callable(self.model_reader):
            raise ContractError('independently bound inference source unavailable')
        return require_model_source(self.model_reader(request, result))

    def _capture(self):
        now = utc_time(self.clock(), 'read clock')
        key = self.scope.key
        first = self.core.read_snapshot(key)
        venue = self.venue.snapshot(key, now=now)
        journal = self.journal.records()
        receipts = self.venue.receipt_history(key)
        projection = self.core.inspect(key, now=now)
        second = self.core.read_snapshot(key)
        venue_after = self.venue.snapshot(key, now=now)
        journal_after = self.journal.records()
        if (first != second or venue != venue_after or journal != journal_after
                or first.account.scope != self.scope or projection.scope != self.scope):
            raise ContractError('sources changed during read; no mixed-cursor projection')
        if any(r.venue_sequence > venue.sequence or r.observed_at > now for r in receipts):
            raise ContractError('venue receipt exceeds read checkpoint')
        cached, state = first.account.snapshot, first.account.source_state
        coherent = bool(cached is not None and state is not None
                        and cached.sequence == venue.sequence and state.venue_sequence == venue.sequence
                        and cached.fence == venue.fence and cached.positions == venue.positions
                        and cached.balance == venue.balance and cached.equity == venue.equity
                        and cached.open_command_ids == venue.open_command_ids
                        and first.account.recovery is RecoveryState.COHERENT)
        if not coherent:
            projection = replace(projection, recovery=RecoveryState.UNRESOLVED,
                                 permissions=Permissions(), admissions_enabled=False,
                                 state_id=None, observed_at=None, balance=None, equity=None,
                                 realized_pnl=None, open_pnl=None, positions=None)
        latest = next((x for x in reversed(journal) if x.scope == wire(self.scope) and x.kind == 'DECISION'), None)
        if latest is not None:
            result = latest.payload['result']
            self._decision_source(latest.payload['request'], result)
            projection = replace(projection, last_decision=decode(canonical_bytes(result).decode('utf-8'), DecisionResult))
        return now, first, venue, journal, receipts, projection, coherent

    def read_cockpit(self):
        return self._capture()[5]

    def read(self):
        now, core, venue, history, receipts, projection, coherent = self._capture()
        scope, source_scope = read_scope(self.scope), wire(self.scope)
        at = wire(now)
        state = core.account.source_state
        cursor = dict(sequence=core.event_sequence, ledger_prefix_sha256=core.event_sha256,
                      current_state_revision=state.version if state else None,
                      read_model_version='forex.decision-read/0.1')
        catalog = _Catalog()
        core_ref = catalog.add('core-read', core, core.event_sequence)
        venue_ref = catalog.add('venue-read', venue, venue.sequence)
        catalog.add('evidence-prefix', history, len(history))
        fence_ref = catalog.add('fence', venue.fence, venue.fence.generation)
        pos_refs = [catalog.add('position', p, p.version) for p in venue.positions]
        snapshot_ref = catalog.add('state', state, state.version) if state else absent('Core state is unavailable.')
        # Prefix reads retain original scope. They are not rewritten as current-epoch decisions.
        current = [x for x in history if x.scope == source_scope]
        older = [x.event_id for x in history if x.scope != source_scope and x.kind == 'DECISION']
        decisions = [x for x in current if x.kind == 'DECISION']
        inputs = {x.payload['request']['request_id']: x for x in current if x.kind == 'DECISION_INPUT'}
        if len(decisions) > 16 or len(older) > 128:
            raise ContractError('finite read limit exceeded; archive paging is required')
        refs = {x.sequence: catalog.add('core-event', x, x.sequence) for x in core.events}
        commands = {x.command.command_id: x for x in core.commands}
        current_commands = {k: v for k, v in commands.items() if v.command.intent.scope == self.scope}
        receipt_refs = {r.receipt_id: catalog.add('venue-receipt', r, r.venue_sequence) for r in receipts}
        receipt_history_ref = catalog.add('venue-history', receipts, venue.sequence)
        events, source_evidence, result_decisions = [], [], []
        # Every known receipt is cataloged, including independent venue-stop-*.
        # Without an original epoch on a venue-only effect, do not fabricate one.
        venue_only = [r for r in receipts if r.command_id not in commands]
        reasons = []
        recorded_decision_ids = {x.payload['result']['decision_id'] for x in decisions}
        unrecorded = sorted({x.command.intent.decision_id for x in current_commands.values()} - recorded_decision_ids)
        if unrecorded:
            reasons.append('Some core commands, including possible owner-reviewed actions, have no retained operator decision record. Their core and venue records remain available.')
        if older:
            reasons.append('Earlier-epoch decisions remain in the original durable prefix/catalog; archive paging is unavailable.')
        if venue_only:
            reasons.append('Venue-only effects are retained in the venue catalog; their original epoch is not asserted.')
        active_scope = None
        for event in core.events:
            payload = json.loads(event.payload_json)
            if event.kind == 'SESSION_INERT':
                active_scope = payload.get('scope')
            if active_scope != source_scope:
                continue
            mapped = {'ADMISSION': 'ADMISSION', 'DISPATCH_CLAIM': 'DISPATCH',
                      'VENUE_RECEIPT_OBSERVED': 'VENUE_RECEIPT', 'RECONCILED': 'RECONCILIATION',
                      'CONTROL_REQUESTED': 'CONTROL', 'CONTROL_CONFIRMED': 'CONTROL',
                      'CONTROL_RECOVERED_NO_GRANTS': 'CONTROL', 'CONTROL_SUPERSEDED': 'CONTROL',
                      'LOCAL_RETIREMENT': 'REVISION'}.get(event.kind)
            if mapped is None:
                continue
            command_wire = payload.get('command') if type(payload) is dict else None
            command_id = command_wire.get('command_id') if type(command_wire) is dict else payload.get('command_id')
            record = current_commands.get(command_id)
            if command_id is not None and record is None:
                continue
            # Core events lack one universal timestamp. These times mean read availability,
            # not an invented historical admission/dispatch execution timestamp.
            events.append(dict(event_id='core-event-' + str(event.sequence), sequence=event.sequence,
                               event_kind=mapped, record=refs[event.sequence], scope=scope,
                               observed_at=at, available_at=at, predecessor_ids=[],
                               decision_id=record.command.intent.decision_id if record else None,
                               command_id=command_id, effect=payload.get('effect'),
                               public_summary='Read core record: ' + event.kind + '. Historical time is in its source payload if present.'))
        for entry in decisions:
            request, result = entry.payload['request'], entry.payload['result']
            provenance, selection = result['provenance'], result['selection']
            model_source = self._decision_source(request, result)
            actual_model = provenance['origin'] == 'ACTUAL_MODEL'
            if len(request['options']) > 8 or request['state']['scope'] != source_scope:
                raise ContractError('decision scope/candidate coverage is not supported')
            recorded_input = inputs.get(request['request_id'])
            if recorded_input is None or recorded_input.payload['request'] != request:
                raise ContractError('exact decision input is absent from the journal')
            observation = recorded_input.payload['observation']
            if observation['sequence'] != request['state']['venue_sequence']:
                raise ContractError('decision observation cursor conflict')
            supplied_refs = request['evidence']
            observation_ref = catalog.add('decision-observation', observation, observation['sequence'])
            for supplied in supplied_refs:
                if supplied['kind'] == 'OBSERVATION' and supplied['content_sha256'] == content_digest(observation):
                    evidence_ref, producer_class, assessment = observation_ref, 'SIMULATOR_EVENT', 'supported'
                    claim = 'Exact observed simulator snapshot supplied to the source choice.'
                elif (supplied['kind'] == 'IMPORTED_CLAIM'
                      and 'reviewed_case_facts' in recorded_input.payload
                      and supplied['content_sha256'] == content_digest(recorded_input.payload['reviewed_case_facts'])):
                    evidence_ref = catalog.add('authored-case-facts', recorded_input.payload['reviewed_case_facts'])
                    producer_class, assessment = 'AUTHORED_FIXTURE', 'unresolved'
                    claim = 'Exact supplied toy-case facts. Digest binding does not independently establish their truth or oracle correctness.'
                else:
                    raise ContractError('unsupported decision evidence source; cannot fabricate catalog resolution')
                source_evidence.append(dict(evidence_id=supplied['evidence_id'], source_record=evidence_ref,
                    producer_class=producer_class, scope=scope, observed_at=supplied['observed_at'],
                    available_at=recorded_input.recorded_at, claim=claim, assessment=assessment,
                    locator=dict(catalog_id=self.producer_id, record_id=evidence_ref['record_id']),
                    validation=self._check('PASS', scope, cursor, 'Exact supplied source digest checked by this read; semantic truth is separate.')))
            decision_ref = catalog.add('decision', entry, entry.sequence)
            matched = [v for v in current_commands.values() if v.command.intent.decision_id == result['decision_id']]
            if len(matched) > 1:
                raise ContractError('ambiguous command relation for one decision')
            record = matched[0] if matched else None
            decision_cursor = entry.payload.get('core_cursor')
            if decision_cursor is None or decision_cursor['event_sequence'] > core.event_sequence:
                raise ContractError('decision has no compatible captured core cursor')
            captured_seq = decision_cursor['event_sequence']
            captured_event = next((x for x in core.events if x.sequence == captured_seq), None)
            if captured_seq and (captured_event is None or captured_event.event_sha256 != decision_cursor['event_sha256']):
                raise ContractError('decision core prefix anchor differs')
            options = []
            for option in request['options']:
                intent = option['intent']
                if intent['decision_id'] != result['decision_id']:
                    raise ContractError('decision identity differs from its exact supplied intent')
                target = self._target(catalog, observation, intent)
                selected = option['action_ref'] == selection['selected_action_ref']
                options.append(dict(candidate_id=option['action_ref'], strategy_id=option['strategy_id'],
                    strategy_version='unversioned-source', instrument_id=intent['instrument_id'], timeframe=option['timeframe'],
                    action_kind=intent['kind'], target=target, proposed_parameters=self._parameters(intent),
                    preconditions=['Exact source state and independent core admission required.'],
                    known_facts=request['facts'], assumptions=[], reason_ids=[], evidence_ids=[e['evidence_id'] for e in supplied_refs],
                    evaluation='evaluated' if selected else 'not_evaluated', eligibility='unknown',
                    disposition='selected' if selected else 'not_selected', status_event_ref=decision_ref,
                    uncertainty=[uncertainty('eligibility', 'Operator selection does not prove policy eligibility.')]))
            chosen = next((x for x in options if x['candidate_id'] == selection['selected_action_ref']), None)
            if selection['selected_action_ref'] is not None and chosen is None:
                raise ContractError('selection outside source candidate set')
            command_id = record.command.command_id if record else None
            admission = next((x for x in events if x['command_id'] == command_id and x['event_kind'] == 'ADMISSION'), None) if record else None
            dispatch = next((x for x in events if x['command_id'] == command_id and x['event_kind'] == 'DISPATCH'), None) if record else None
            outcomes = [receipt_refs[r.receipt_id] for r in receipts if r.command_id == command_id] if record else []
            intent_ref = catalog.add('intent', wire(record.command.intent)) if record else absent('No admitted intent for this decision.')
            result_decisions.append(dict(decision_id=result['decision_id'], revision=0,
                decision_kind='entry' if any(x['action_kind'] in ('OPEN', 'ADD') for x in options) else 'management',
                scope=scope, cursor=dict(sequence=captured_seq, ledger_prefix_sha256=decision_cursor['event_sha256'],
                                        current_state_revision=request['state']['version'], read_model_version='forex.decision-read/0.1'),
                observation_set_sha256=content_digest(supplied_refs), decided_at=provenance['completed_at'],
                opportunity_set_id=request['opportunity_set_id'], opportunity_set_version=0,
                opportunity_set_sha256=content_digest(request['options']), candidates=options,
                coverage=coverage(len(options), captured_seq),
                origin=dict(kind='actual-inference' if actual_model else 'scripted',
                            provider='ollama' if actual_model else None,
                            model_id=provenance['model_id'] if actual_model else None,
                            model_artifact_sha256=provenance['model_artifact_sha256'] if actual_model else None,
                            adapter_id=provenance['adapter_id'], prompt_version=provenance['prompt_version'], policy_version='1',
                            request_sha256=provenance['request_sha256'], response_sha256=provenance['response_sha256'],
                            invocation_sha256=model_source['invocation_sha256'] if actual_model else None,
                            effective_reasoning=None, started_at=provenance['started_at'],
                            completed_at=provenance['completed_at'], latency_ms=model_source['latency_ms'] if actual_model else None,
                            inference_receipt=catalog.add('model-inference', model_source) if actual_model else absent('Scripted choice; no model invocation.'),
                            budget_receipt=catalog.add('model-budget', model_source['budget']) if actual_model else absent('No model budget used.')),
                selection=dict(candidate_id=selection['selected_action_ref'], wait=chosen is None,
                               public_rationale=selection['reason'], evidence_ids=selection['evidence_ids'], reason_ids=[],
                               unresolved_questions=[], proposed_bounds=chosen['proposed_parameters'] if chosen else self._parameters(None),
                               source_state_id=request['state']['state_id'], source_state_revision=request['state']['version'],
                               target=chosen['target'] if chosen else absent('WAIT has no target.')),
                decision_status='proposed', status_reason='Historical source choice; current execution eligibility is not asserted.',
                status_event_ref=decision_ref, admission_ref=admission['record'] if admission else absent('No admission event observed.'),
                intent_ref=intent_ref, dispatch_ref=dispatch['record'] if dispatch else absent('No dispatch event observed.'),
                outcome_refs=outcomes, revision_of=absent('Initial source decision revision.'), revision_trigger_refs=[],
                superseded_by=absent('No source revision event is asserted.')))
        if len(events) > 256 or len(source_evidence) > 64:
            raise ContractError('finite read limit exceeded; paging is required')
        fresh = bool(state and state.observed_at <= now < state.valid_until)
        state_wire = dict(state_id=state.state_id if coherent else None,
            state_sha256=snapshot_ref['record_sha256'] if coherent else None,
            revision=state.version if state else None, observation_refs=[core_ref, venue_ref, receipt_history_ref],
            permissions=dict(new_risk=projection.permissions.new_risk.value,
                             management=projection.permissions.management.value, fence_ref=fence_ref),
            exposure_facts=[], position_refs=pos_refs if coherent else None,
            unknowns=[] if coherent else [uncertainty('current_state', 'Independent core/venue sources are not reconciled.')],
            observed_at=wire(state.observed_at) if state else None, valid_until=wire(state.valid_until) if state else None,
            freshness='CURRENT' if coherent and fresh else 'STALE' if state else 'UNKNOWN',
            reconciliation='COHERENT' if coherent else 'UNRESOLVED')
        envelope = dict(schema_version='forex.decision-read/0.1', scope=scope, cursor=cursor,
            as_of=dict(observed_at=at, available_at=at, generated_at=at, clock_basis='SYNTHETIC_UTC', sequence_basis='CORE_LEDGER'),
            current_state=state_wire, decisions=result_decisions, events=events, evidence=source_evidence,
            validation={name: self._check('PASS' if name != 'reconciliation' or coherent else 'UNKNOWN', scope, cursor,
                        'Producer checked this retained source read; this is not application test evidence.')
                        for name in ('schema', 'integrity', 'source_binding', 'reconciliation')},
            coverage=coverage(len(result_decisions), core.event_sequence, reasons=reasons, omitted=older + unrecorded))
        envelope['domain_digest'] = content_digest(envelope)
        self.validator(envelope)
        raw = canonical_bytes(envelope)
        if len(raw) > 1_048_576:
            raise ContractError('read envelope exceeds 1 MiB')
        anchor = TrustedReadAnchor('read-' + content_digest((envelope['domain_digest'], now)), self.producer_id,
            self.schema_sha256, envelope['domain_digest'], content_digest(scope), content_digest(cursor),
            now, now + timedelta(seconds=15), coherent)
        self._issued[anchor.anchor_id] = (anchor, raw, catalog.records)
        while len(self._issued) > 8:
            del self._issued[next(iter(self._issued))]
        return dict(envelope=json.loads(raw), anchor=wire(anchor))

    def _parameters(self, intent):
        spec = self.instruments[intent['instrument_id']] if intent else next(iter(self.instruments.values()))
        return dict(quantity=intent.get('quantity') if intent else None, quantity_unit='BASE_UNITS',
                    side=intent.get('side') if intent else None, limit_price=intent.get('limit_price') if intent else None,
                    stop_price=intent.get('stop_price') if intent else None, quote_currency=spec.quote_currency)

    @staticmethod
    def _target(catalog, observation, intent):
        if intent['target_id'] is None:
            return absent('New position has no existing target.')
        position = next((p for p in observation['positions'] if p['position_id'] == intent['target_id']
                         and p['version'] == intent['target_version']), None)
        return catalog.add('position', position, position['version']) if position else absent('Target version not present in captured position set.')

    def _check(self, status, scope, cursor, reason):
        return dict(status=status, verifier_id=self.producer_id, verifier_version='1',
                    checked_scope_sha256=content_digest(scope), checked_cursor_sha256=content_digest(cursor),
                    external_anchor_id=None, reason=reason)

    def anchor(self, anchor_id):
        stored = self._issued.get(anchor_id)
        if stored is None or not stored[0].issued_at <= self.clock() < stored[0].expires_at:
            raise ContractError('unknown or expired read anchor')
        return stored[0]

    def resolve(self, anchor_id, reference):
        anchor = self.anchor(anchor_id)
        stored = self._issued[anchor_id][2].get(reference.get('record_id'))
        if stored is None or reference != stored[0]:
            raise ContractError('catalog reference id/version/hash mismatch')
        return dict(schema_version='forex.catalog-record/1', anchor_id=anchor_id,
                    producer_id=anchor.producer_id, reference=wire(stored[0]), record=json.loads(stored[1]))

    def validate_bound(self, payload, anchor):
        """Callback for read_binding, selected in-process outside payload labels."""
        issued = self.anchor(anchor.anchor_id)
        if issued != anchor or canonical_bytes(payload) != self._issued[anchor.anchor_id][1]:
            raise ContractError('payload differs from independently retained source read')
        def visit(value):
            if type(value) is dict:
                if set(value) == {'record_id', 'record_version', 'record_sha256', 'unavailable_reason'}:
                    if value['record_id'] is not None:
                        self.resolve(anchor.anchor_id, value)
                    elif not value['unavailable_reason'] or any(value[k] is not None for k in ('record_version', 'record_sha256')):
                        raise ContractError('malformed missing reference')
                else:
                    for v in value.values():
                        visit(v)
            elif type(value) is list:
                for v in value:
                    visit(v)
        visit(payload)
        return True
