"""Finite real-model trajectories over separate durable synthetic ledgers.

Explicit caller only. No model start, inference fallback, hidden keys, or U1
allocation. Wall UTC is shared by inference and simulator; time never freezes
to make an expired model reply appear current.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import json
import time
from hashlib import sha256

from ..contracts import (ActionIntent, ActionKind, ActionOption, CommandState, ContractError,
    ControlKind, DecisionFact, DecisionOrigin, DecisionRequest, EvidenceKind,
    EvidenceReference, Instrument, MarketObservation, Money, RunScope, Side,
    canonical_bytes, content_digest)
from ..core import InstrumentPolicy, RiskPolicy
from ..operator.decisions import StaleDecision
from ..venue.fixtures import VenueScenario
from .application import RuntimeConfig
from .assembly import assemble_inert_simulation
from .continuous_driver import _control
from .evidence_journal import EvidenceJournal
from .owner_requests import OwnerRequestBook
from .read_service import DecisionReadService, require_model_source


def utc_now():
    return datetime.now(timezone.utc)


def _quote(app, clock, values):
    before = app.venue.snapshot(app.config.scope.key, now=clock())
    now = clock()
    event = MarketObservation(app.config.scope.key, 'market-' + str(before.sequence+1),
        'synthetic-eurusd', before.sequence+1, now, now, Decimal(values['bid']), Decimal(values['ask']))
    app.wiring.advance_market(event)
    return event


def build_request(app, step, clock, *, previous_command=None):
    scope = app.config.scope
    state = app.core.current_state(scope.key, now=clock())
    observation = app.venue.snapshot(scope.key, now=clock())
    decision_id = 'decision-' + step['step_id']
    evidence = EvidenceReference('evidence-' + step['step_id'], EvidenceKind.OBSERVATION,
        'independent-simulator-1', content_digest(observation), observation.observed_at)
    case_evidence = EvidenceReference('case-' + step['step_id'], EvidenceKind.IMPORTED_CLAIM,
        'reviewed-toy-case-source', content_digest(step['facts']), observation.observed_at)
    positions = observation.positions
    current = {'positions': [{'id': p.position_id, 'version': p.version,
        'quantity': p.quantity, 'side': p.side, 'stop': p.stop_price} for p in positions],
        'new_risk': observation.fence.new_risk_allowed,
        'management': observation.fence.management_allowed,
        'balance': observation.balance,
        'market': [{'bid': q.bid, 'ask': q.ask, 'observed_at': q.observed_at} for q in observation.market]}
    # Bound display facts to the same actually observed data. The full snapshot
    # stays in the journal and the evidence digest binds it independently.
    fact_value = canonical_bytes(current).decode()
    if len(fact_value.encode()) > 1024:
        raise ContractError('observed context exceeds single-position B fixture bound')
    facts = [DecisionFact('observed-' + step['step_id'], 'Independent observed state', fact_value, (evidence.evidence_id,))]
    facts.extend(DecisionFact(f"fact-{step['step_id']}-{i}", f['label'], f['value'], (case_evidence.evidence_id,))
                 for i, f in enumerate(step['facts']))
    options = []
    for item in step['options']:
        kind = ActionKind(item['kind'])
        quantity = item.get('quantity')
        target_id = target_version = None
        if kind is ActionKind.CANCEL_ORDER:
            if previous_command is None:
                raise ContractError('no retained previous command to cancel')
            receipt = app.venue.lookup(scope.key, previous_command).receipt
            if receipt is None:
                raise ContractError('cancel has no independently observed order version')
            target_id, target_version = previous_command, receipt.venue_sequence
        elif kind is not ActionKind.OPEN:
            if len(positions) != 1:
                raise ContractError('management needs one actual observed position')
            target_id, target_version = positions[0].position_id, positions[0].version
        if quantity == 'ALL':
            if len(positions) != 1:
                raise ContractError('ALL needs exact current position quantity')
            amount = positions[0].quantity
        else:
            amount = Decimal(quantity) if quantity is not None else None
        now = clock()
        intent = ActionIntent('intent-' + item['action_ref'], scope, decision_id,
            'opportunity-' + item['action_ref'], item['action_ref'], state, kind,
            'synthetic-eurusd', DecisionOrigin.ACTUAL_MODEL, now, state.valid_until,
            quantity=amount, side=Side(item['side']) if item.get('side') else None,
            target_id=target_id, target_version=target_version,
            limit_price=Decimal(item['limit_price']) if item.get('limit_price') else None,
            stop_price=Decimal(item['stop_price']) if item.get('stop_price') else None)
        options.append(ActionOption(item['action_ref'], item['strategy_id'], item['timeframe'], item['label'], intent))
    return DecisionRequest('request-' + step['step_id'], 'set-' + step['step_id'], state,
                           tuple(options), tuple(facts), (evidence, case_evidence)), observation


def _pending_tick(app, request, step, store, clock):
    """Observe a retained attempt and change state before the reply is retained.

    This proves an outstanding inference request, not internal token-generation
    timing. If the response wins the race, this mandatory case cannot pass and
    no replacement attempt is permitted.
    """
    previous = {r['receipt_id'] for r in store.records()}
    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(app.wiring.propose, request)
    changed_at = None
    try:
        until = time.monotonic() + 120
        while not future.done() and time.monotonic() < until:
            attempted = [r for r in store.records() if r['receipt_id'] not in previous
                         and r['kind'] == 'MODEL_HTTP_ATTEMPT' and r['payload']['operation'] == 'generation']
            if attempted and not future.done():
                event = _quote(app, clock, step['pending_market'])
                changed_at = event.available_at
                break
            time.sleep(0.01)
        try:
            proposal = future.result(timeout=max(0.01, until-time.monotonic()))
            return proposal, None, changed_at
        except StaleDecision as exc:
            return None, type(exc).__name__, changed_at
    finally:
        # The process/sandbox absolute supervisor owns termination if native I/O
        # cannot unwind. There is no second call or substitute decision.
        pool.shutdown(wait=False, cancel_futures=True)


def run_trajectory(case, *, directory: Path, execution_id: str, build_id: str,
                   adapter, model_store, model_reader, clock=utc_now, valve_gate=None, reviewed_close: bool = False, return_runtime: bool = False):
    directory.mkdir()  # exclusive: existing effects/history are never replaced
    scope = RunScope('synthetic-b', execution_id + '-' + case['case_id'], 1,
        build_id, 'synthetic-b-policy-1', case['case_id'], 'independent-simulator-1')
    instrument = Instrument('synthetic-eurusd', 'EURUSD', 'EUR', 'USD',
                            Decimal('0.0001'), Decimal('1'), Decimal('1'))
    owner = OwnerRequestBook(scope, controls=frozenset(ControlKind), reviewed_close=reviewed_close)
    app = assemble_inert_simulation(RuntimeConfig(scope, directory),
        policy=RiskPolicy('USD', Decimal('100'), observation_ttl_seconds=300),
        instruments=(InstrumentPolicy(instrument, Decimal('2')),), decision_adapter=adapter,
        owner_verifier=owner, clock=clock, expected_origin=DecisionOrigin.ACTUAL_MODEL, max_decisions=max(4, len(case['steps']) + 2), valve_gate=valve_gate)
    journal = EvidenceJournal(directory/'account.evidence.sqlite3', scope.key)
    journal.initialize(create=True)
    app.venue.initialize(scope.key, opening_balance=Money(Decimal('10000'), 'USD'),
                         instruments=(instrument,), now=clock(), scenario=VenueScenario(scope.scenario_id))
    app.core.initialize(create=True)
    _quote(app, clock, case['initial_market'])
    _control(app, owner, journal, clock, ControlKind.STOP_AUTOMATION, 'b-start-stop')
    _control(app, owner, journal, clock, ControlKind.RESUME_NEW_RISK, 'b-risk')
    _control(app, owner, journal, clock, ControlKind.RESUME_MANAGEMENT, 'b-management')
    attempts, previous_command = [], None
    for step in case['steps']:
        row = {'case_id': case['case_id'], 'step_id': step['step_id'],
               'actual_receipt_verified': False, 'stale_rejected': False, 'venue_changed': False,
               'error_type': None, 'selected_action_ref': None, 'evidence_ids': []}
        attempts.append(row)
        try:
            # A fresh causal quote is explicit, not a frozen clock or invented
            # timestamp on an old observation. Case provider supplies its facts.
            _quote(app, clock, step['market_before'])
            request, observation = build_request(app, step, clock, previous_command=previous_command)
            row['request_state_sha256'] = content_digest(request.state)
            journal.append('input-' + step['step_id'], 'DECISION_INPUT', scope,
                {'request': request, 'observation': observation, 'reviewed_case_facts': step['facts']}, now=clock())
            changed_at = None
            if step['invalidate_while_pending']:
                proposal, error, changed_at = _pending_tick(app, request, step, model_store, clock)
                row['error_type'] = error
                result = app.operator.attempts[-1].result
            else:
                proposal = app.wiring.propose(request)
                result = proposal.result
            # The selected reader verifies independent evidence; reject incomplete
            # output before any verification claim, journaled decision or admission.
            source = require_model_source(model_reader(
                json.loads(canonical_bytes(request)), json.loads(canonical_bytes(result))))
            row.update(actual_receipt_verified=True, selected_action_ref=result.selection.selected_action_ref,
                evidence_ids=list(result.selection.evidence_ids), inference_receipt_id=result.provenance.inference_receipt_id,
                inference_source_sha256=content_digest(source))
            row['action_kind'] = next((x.intent.kind.value for x in request.options
                if x.action_ref == result.selection.selected_action_ref), 'WAIT')
            journal.append('decision-' + step['step_id'], 'DECISION', scope,
                {'request': request, 'result': result, 'core_cursor': app.core.checkpoint(scope.key)}, now=clock())
            if step['invalidate_while_pending']:
                wire = source['sources'][0]['payload']
                start = datetime.fromisoformat(wire['started_at'].replace('Z', '+00:00'))
                finish = datetime.fromisoformat(wire['completed_at'].replace('Z', '+00:00'))
                row['stale_rejected'] = bool(proposal is None and row['error_type'] == 'StaleDecision'
                    and changed_at and start <= changed_at < finish)
                row['pending_state_changed_at'] = changed_at
                if not row['stale_rejected']:
                    raise ContractError('mandatory pending stale-response proof not established')
            elif proposal.intent is not None:
                command_id = 'command-' + step['step_id']
                row['action_kind'] = proposal.intent.kind.value
                row['position_id'] = proposal.intent.target_id
                try:
                    view = app.wiring.admit(proposal, command_id=command_id)
                except Exception as valve_exc:
                    if type(valve_exc).__name__ == 'ValveRefusalError':
                        vdec = json.loads(canonical_bytes(valve_exc.decision.to_dict())) if getattr(valve_exc, 'decision', None) is not None else None
                        row['valve_blocked'] = True
                        row['error_type'] = 'ValveRefusalError'
                        row['valve_decision'] = vdec
                        journal.append('valve-blocked-' + step['step_id'], 'MODEL_VALVE_BLOCKED', scope,
                            {'decision_id': result.decision_id, 'valve_decision': vdec}, now=clock())
                        app.wiring.observe()
                        view = None
                    else:
                        raise
                if not row.get('valve_blocked'):
                    if app.wiring.last_valve_decision is not None:
                        row['valve_blocked'] = False
                        row['valve_decision'] = json.loads(canonical_bytes(app.wiring.last_valve_decision.to_dict()))
                    journal.append('admission-' + step['step_id'], 'ADMISSION', scope,
                        {'decision_id': result.decision_id, 'command': view}, now=clock())
                    if view is None or view.state is not CommandState.QUEUED:
                        raise ContractError('model choice failed independent admission')
                    app.core.dispatch_command(scope.key, command_id, now=clock())
                    previous_command = command_id
                    for market in step['market_after']:
                        _quote(app, clock, market)
                    app.wiring.observe()
                    receipt = app.venue.lookup(scope.key, command_id).receipt
                    after = app.venue.snapshot(scope.key, now=clock())
                else:
                    receipt = None
                    after = app.venue.snapshot(scope.key, now=clock())
                if not row.get('valve_blocked'):
                    row.update(effect=receipt.effect.value if receipt else None,
                        receipt_id=receipt.receipt_id if receipt else None,
                        venue_changed=bool(receipt and receipt.quantities and receipt.quantities.filled > 0)
                                      or bool(receipt and receipt.effect.value in ('APPLIED', 'CANCELLED')),
                        positions_after=len(after.positions))
                    if proposal.intent.kind is ActionKind.OPEN and after.positions:
                        row['position_id'] = after.positions[0].position_id
                    row['position_quantity_after'] = str(next((p.quantity for p in after.positions
                        if p.position_id == row['position_id']), Decimal('0')))
                    journal.append('outcome-' + step['step_id'], 'MODEL_ACTION_OUTCOME', scope,
                        {'receipt': receipt, 'snapshot': after}, now=clock())
                else:
                    row.update(effect=None, receipt_id=None, venue_changed=False, positions_after=len(after.positions))
            else:
                row['action_kind'] = 'WAIT'
            row['observed_at'] = clock()
        except Exception as exc:
            row['error_type'] = type(exc).__name__
            journal.append('failure-' + step['step_id'], 'MODEL_TRAJECTORY_FAILURE', scope, row, now=clock())
            break  # no repaired input, fallback or retry can enter this case
        finally:
            journal.append('attempt-' + step['step_id'], 'MODEL_TRAJECTORY_ATTEMPT', scope, row, now=clock())
    schema = (Path(__file__).resolve().parents[3]/'docs/contracts/decision-read.schema.json').read_bytes()
    service = DecisionReadService(scope=scope, core=app.core, venue=app.venue, journal=journal, clock=clock,
        schema_bytes=schema, schema_sha256=sha256(schema).hexdigest(), instruments=(instrument,), model_reader=model_reader)
    review = service.read()
    anchor = service.anchor(review['anchor']['anchor_id'])
    service.validate_bound(review['envelope'], anchor)
    references = {}
    def visit(value):
        if type(value) is dict:
            if set(value) == {'record_id', 'record_version', 'record_sha256', 'unavailable_reason'}:
                if value['record_id'] is not None:
                    references[value['record_id']] = service.resolve(anchor.anchor_id, value)
            else:
                for item in value.values(): visit(item)
        elif type(value) is list:
            for item in value: visit(item)
    visit(review['envelope'])
    for filename, payload in (('decision-read.json', review), ('decision-catalog.json', references)):
        with (directory/filename).open('xb') as handle:
            handle.write(canonical_bytes(payload)+b'\n')
    meta_out = {'scope': scope, 'core': app.core.checkpoint(scope.key),
        'venue': app.venue.inspect_journal(scope.key)[-1], 'journal': journal.checkpoint(),
        'directory': str(directory)}
    if return_runtime:
        return attempts, meta_out, {'app': app, 'owner': owner, 'journal': journal, 'service': service, 'instrument': instrument}
    return attempts, meta_out
