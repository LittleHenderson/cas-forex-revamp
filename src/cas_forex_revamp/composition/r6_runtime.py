"""Explicit finite fixture controller. No keys, pair roles or scoring inputs.

Current context is a declared fixture fact; market, money and positions are
independently observed. Every policy change replaces the core writer under a
greater epoch and creates explicit fixture-owner fences; it never edits a live
coordinator's policy or restores grants from imported history.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from decimal import Decimal, localcontext
from threading import RLock

from ..contracts import (ActionIntent, ActionKind, ActionOption, CommandState, ContractError,
    ControlKind, DecisionFact, DecisionOrigin, DecisionRequest, EffectState, EvidenceKind,
    EvidenceReference, FenceRequest, Instrument, MarketObservation, Money, RunScope, Side,
    canonical_bytes, content_digest, assert_current_request, decimal_text)
from ..core import CoreCoordinator, InstrumentPolicy, RiskPolicy, SQLiteStore
from ..operator.decisions import OperatorSession
from ..valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    PeakEquityStore,
    _extract_money_decimal,
    compute_drawdown_pct,
)
from ..venue import SQLiteVenue
from ..venue.fixtures import OrderPlan, VenueScenario
from .custody_adapter import PROFILE, need, validate_context
from .evidence_journal import EvidenceJournal
from .owner_requests import OwnerRequestBook
from .r6_observation import read_venue_state, wire

_PACKET_VIEW_KEYS = (
    'account_id',
    'plan_id',
    'balance',
    'equity',
    'available_margin',
    'margin_provenance',
    'position_inventory',
    'current_market',
    'policy_revision',
    'context_version',
)


def packet_json(request):
    """A current-only, lossless-for-choice projection of the exact frozen request.

    Full intents remain in the request/evidence journal. Duplicate scope/state
    records are represented once; the selected ref binds the unchanged intent.
    No hidden rule result, eligibility label, next event, oracle or pair data.
    """
    options = []
    for option in request.options:
        intent = option.intent
        options.append({'action_ref': option.action_ref, 'strategy_id': option.strategy_id,
            'timeframe': option.timeframe, 'label': option.label, 'kind': intent.kind,
            'quantity': intent.quantity, 'side': intent.side, 'target_id': intent.target_id,
            'target_version': intent.target_version, 'limit_price': intent.limit_price,
            'stop_price': intent.stop_price, 'exact_intent_sha256': content_digest(intent)})
    return canonical_bytes({'schema': 'forex.current-decision-packet/2',
        'request_id': request.request_id, 'opportunity_set_id': request.opportunity_set_id,
        'source_state_id': request.state.state_id, 'state': request.state,
        'options': options, 'facts': request.facts, 'evidence': request.evidence,
        'exact_request_sha256': content_digest(request)}).decode()


class CaseRuntime:
    def __init__(self, case, *, directory, execution_id, build_id, adapter, clock, valve_gate=None, peak_equity_store=None):
        self.case = deepcopy(case)
        self.directory, self.adapter, self.clock = directory, adapter, clock
        self.valve_gate = valve_gate
        self.last_valve_decision = None
        self.lock = RLock()
        self.policy = deepcopy(case['policy'])
        raw_dd = self.policy.get('max_drawdown_pct', DEFAULT_MAX_DRAWDOWN_PCT)
        self.max_drawdown_pct = Decimal(str(raw_dd)) if raw_dd is not None else None
        self.context, self.context_version = None, 0
        self.scope = RunScope(case['account_id'], execution_id+'-'+case['case_id'], 1,
            build_id, 'policy-'+content_digest(self.policy), case['plan_id'], 'independent-simulator-1')
        self._drawdown_scope_id = f"{self.scope.account_id}:{self.scope.run_id}"
        self.drawdown_store = peak_equity_store if peak_equity_store is not None else PeakEquityStore(directory/'account.drawdown.sqlite3')
        self.instrument = Instrument('synthetic-eurusd', 'EURUSD', 'EUR', 'USD',
            Decimal(PROFILE['price_tick']), Decimal(PROFILE['quantity_step']), Decimal(PROFILE['quantity_step']))
        self.core_path, self.venue_path = directory/'account.core.sqlite3', directory/'account.venue.sqlite3'
        self.core = None
        self.venue = SQLiteVenue(self.venue_path,
            owner_close_verifier=lambda command, now: self.core.verify_owner_close(command, now))
        self.journal = EvidenceJournal(directory/'account.evidence.sqlite3', self.scope.key)
        self.previous_observation = None
        self.last_position_id = None
        self.sessions = []
        self.used_step_ids = set()
        self.event_index = 0

    def effective_valve_policy(self):
        dd_val = self.policy['max_drawdown_pct'] if 'max_drawdown_pct' in self.policy else (
            decimal_text(self.max_drawdown_pct) if self.max_drawdown_pct is not None else None
        )
        return {**self.policy, 'max_drawdown_pct': dd_val, 'require_peak_equity': True}

    def append(self, kind, payload):
        self.event_index += 1
        return self.journal.append('r6-event-'+str(self.event_index), kind, self.scope, payload, now=self.clock())

    def initialize(self, *, allow_existing_drawdown: bool = False):
        if allow_existing_drawdown:
            self.directory.mkdir(exist_ok=True)
        else:
            self.directory.mkdir(exist_ok=False)
        self.journal.initialize(create=True)
        plans = []
        for step in self.case['steps']:
            quotas = step['schedule']['fill_quotas']
            if quotas is not None:
                plans.append(('command-'+step['step_id'], OrderPlan(tuple(Decimal(x) for x in quotas))))
        self.venue.initialize(self.scope.key,
            opening_balance=Money(Decimal(self.case['initial_account']['balance']), 'USD'),
            instruments=(self.instrument,), now=self.clock(),
            scenario=VenueScenario(self.scope.scenario_id, order_plans=tuple(plans), money_quantum=Decimal(PROFILE['money_quantum'])))
        first = self.venue.snapshot(self.scope.key, now=self.clock())
        need(first.equity.amount == Decimal(self.case['initial_account']['equity']) and not first.positions,
             'initial declaration does not equal independently created venue state')
        self.drawdown_store.observe_equity(
            self._drawdown_scope_id,
            current_equity=first.equity.amount,
            opening_balance=Decimal(self.case['initial_account']['balance']),
            now=self.clock(),
        )
        self.append('R6_INITIAL_OBSERVATION', {'snapshot': first, 'margin_provenance': 'DECLARED_FIXTURE_SAFETY_FACT'})
        self._new_core(create=True)
        self.market(self.case['initial_market'])
        self._declared_permissions()

    def _new_core(self, *, create):
        checkpoint = self.core.checkpoint(self.scope.key) if self.core is not None else None
        self.owner = OwnerRequestBook(self.scope, controls=frozenset(ControlKind), reviewed_close=False)
        with localcontext() as context:
            context.prec = 80
            capacity = max(Decimal(PROFILE['money_quantum']), Decimal(self.policy['max_entry_quantity'])*Decimal(PROFILE['price_ceiling']))
        self.core = CoreCoordinator(scope=self.scope, store=SQLiteStore(self.core_path), venue=self.venue,
            policy=RiskPolicy('USD', capacity, Decimal(PROFILE['money_quantum']), PROFILE['observation_ttl_seconds']),
            instruments=(InstrumentPolicy(self.instrument, Decimal(PROFILE['price_ceiling'])),), owner_verifier=self.owner)
        self.core.initialize(create=create, expected_checkpoint=checkpoint)
        self.append('R6_CORE_POLICY_BINDING', {'policy': self.policy, 'scope': self.scope,
            'profile': PROFILE, 'maximum_gross_notional': capacity,
            'restored_checkpoint': checkpoint, 'initial_permissions': 'INERT'})

    def control(self, kind):
        fence = self.venue.snapshot(self.scope.key, now=self.clock()).fence
        rid = 'fixture-owner-'+str(self.scope.epoch)+'-'+str(fence.generation+1)
        request = FenceRequest(self.scope.key, 'barrier-'+rid, kind, rid,
            fence.generation, fence.generation+1, self.clock())
        self.owner.register(request, request_id=rid, now=self.clock())
        returned = self.core.control(request, now=self.clock())
        actual = self.venue.snapshot(self.scope.key, now=self.clock()).fence
        need(returned == actual and actual.applied and actual.barrier_id == request.barrier_id
             and actual.generation == request.next_generation, 'fixture fence lacks exact independent readback')
        self.append('R6_FIXTURE_OWNER_CONTROL', {'request': request, 'returned': returned, 'observed': actual})
        self.core.reconcile(self.scope.key, now=self.clock())

    def rearm_drawdown(self, *, owner_request_id: str) -> Decimal:
        """Authenticated owner recovery re-arming peak_equity to current venue equity."""
        with self.lock:
            now = self.clock()
            snap = self.venue.snapshot(self.scope.key, now=now)
            fence = snap.fence
            request = FenceRequest(
                self.scope.key,
                'barrier-' + owner_request_id,
                ControlKind.RESUME_NEW_RISK,
                owner_request_id,
                fence.generation,
                fence.generation + 1,
                now,
            )
            self.owner.register(request, request_id=owner_request_id, now=now)
            returned = self.core.control(request, now=now)
            actual = self.venue.snapshot(self.scope.key, now=self.clock()).fence
            need(returned == actual and actual.applied, 'owner drawdown re-arm fence failed readback')
            new_peak = self.drawdown_store.rearm_after_drawdown(
                self._drawdown_scope_id,
                new_peak_equity=snap.equity.amount,
                owner_verifier=self.owner,
                owner_request_id=owner_request_id,
                fence_request=request,
                now=now,
            )
            self.core.reconcile(self.scope.key, now=self.clock())
            self.append('R6_OWNER_DRAWDOWN_REARM', {
                'owner_request_id': owner_request_id,
                'new_peak_equity': decimal_text(new_peak),
                'fence': actual,
            })
            return new_peak

    def _declared_permissions(self):
        self.control(ControlKind.STOP_AUTOMATION)
        if self.policy['new_risk_permission'] == 'ALLOWED' and Decimal(self.policy['max_entry_quantity']) > 0:
            self.control(ControlKind.RESUME_NEW_RISK)
        if self.policy['management_permission'] == 'ALLOWED':
            self.control(ControlKind.RESUME_MANAGEMENT)

    def market(self, quote):
        with self.lock:
            before = self.venue.snapshot(self.scope.key, now=self.clock())
            now = self.clock()
            event = MarketObservation(self.scope.key, 'market-'+str(before.sequence+1),
                self.instrument.instrument_id, before.sequence+1, now, now,
                Decimal(quote['bid']), Decimal(quote['ask']))
            after_snap = self.venue.advance_market(event)
            self.drawdown_store.observe_equity(
                self._drawdown_scope_id,
                current_equity=after_snap.equity.amount,
                now=now,
            )
            self.core.reconcile(self.scope.key, now=self.clock())
            self.append('R6_MARKET_EVENT', {'event': event, 'observed': self.observe()})
            return event

    def set_context(self, value):
        with self.lock:
            validate_context(value)
            if self.context == value:
                return False
            previous = deepcopy(self.context)
            self.context = deepcopy(value); self.context_version += 1
            # Reconcile actually reads the venue; it does not mint a new quote.
            self.core.reconcile(self.scope.key, now=self.clock())
            self.append('R6_CONTEXT_BINDING', {'previous': previous, 'current': self.context,
                'version': self.context_version, 'source_state': self.current_state()})
            return True

    def change_policy(self, patch):
        with self.lock:
            allowed_keys = {'policy_revision', 'max_entry_quantity'}
            if 'max_drawdown_pct' in patch:
                allowed_keys = {'policy_revision', 'max_entry_quantity', 'max_drawdown_pct'}
            need(set(patch) == allowed_keys
                 and patch['policy_revision'] == self.policy['policy_revision']+1,
                 'only declared next policy revision/entry-limit patch is supported')
            previous = deepcopy(self.policy)
            self.policy.update(deepcopy(patch))
            if 'max_drawdown_pct' in patch:
                self.max_drawdown_pct = Decimal(str(patch['max_drawdown_pct'])) if patch['max_drawdown_pct'] is not None else None
            self.scope = replace(self.scope, epoch=self.scope.epoch+1,
                                 policy_id='policy-'+content_digest(self.policy))
            self._new_core(create=False)
            self.core.reconcile(self.scope.key, now=self.clock())
            self._declared_permissions()
            self.append('R6_POLICY_TRANSITION', {'previous': previous, 'current': self.policy,
                'source_state': self.current_state()})

    def observe(self):
        return read_venue_state(self.venue, self.scope.key, now=self.clock(), path=self.venue_path)

    def current_state(self):
        with self.lock:
            return self.core.current_state(self.scope.key, now=self.clock())

    def new_operator(self):
        # A policy epoch never resets the shared actual-model adapter budget.
        session = OperatorSession(self.adapter, current_state=self.current_state,
                                  clock=self.clock, max_decisions=5)
        self.sessions.append(session)
        return session

    def prepare(self, step):
        with self.lock:
            sid = step['step_id']; need(sid not in self.used_step_ids, 'no trajectory retry')
            self.used_step_ids.add(sid)
            schedule = step['schedule']
            before_preparation = self.observe()
            if schedule['before_mode'] == 'REUSE_LAST_OBSERVATION':
                need(not schedule['before_events'], 'REUSE cannot apply a quote')
            else:
                for event in schedule['before_events']: self.market(event['quote'])
            self.set_context(step['context'])
            need(self.policy['policy_revision'] == step['policy_revision'], 'current policy revision differs')
            observed = self.observe(); snap = observed['snapshot']
            need(len(snap['market']) == 1 and all(Decimal(snap['market'][0][k]) == Decimal(step['current_market'][k]) for k in ('bid', 'ask')),
                 'declared current quote differs from actual observation')
            self._market_current(snap)
            state = self.current_state()
            observed_peak = self.drawdown_store.observe_equity(
                self._drawdown_scope_id,
                current_equity=Decimal(snap['equity']['amount']),
                opening_balance=Decimal(self.case['initial_account']['balance']),
                now=self.clock(),
            )
            has_override = 'observed_accounting_override' in step
            override = step['observed_accounting_override'] if (has_override and isinstance(step['observed_accounting_override'], dict)) else {}
            if has_override and ('available_margin' in override or not override):
                margin = override.get('available_margin', None)
            else:
                margin = self.case['initial_account']['available_margin']
            equity_view = override['equity'] if (has_override and 'equity' in override) else snap['equity']
            peak_view = override['peak_equity'] if (has_override and 'peak_equity' in override) else decimal_text(observed_peak)

            current = {'account_id': self.scope.account_id, 'plan_id': self.case['plan_id'],
                'balance': snap['balance'], 'equity': equity_view,
                'available_margin': margin, 'margin_provenance': 'DECLARED_FIXTURE_SAFETY_FACT' if margin is not None else 'UNAVAILABLE',
                'position_inventory': snap['positions'], 'current_market': snap['market'],
                'policy_revision': self.policy['policy_revision'], 'context_version': self.context_version,
                'peak_equity': peak_view}
            context = deepcopy(self.context)
            untrusted = context.pop('imported_note', None)
            source = {'context': context, 'presentation_note': step['presentation_note']}
            if untrusted is not None: source['untrusted_imported_note'] = untrusted
            evidence = (
                EvidenceReference('evidence-'+sid, EvidenceKind.OBSERVATION, 'independent-simulator-1',
                    content_digest({'current': observed, 'prior': self.previous_observation,
                                    'declared_safety_view': current}), self.clock()),
                EvidenceReference('case-'+sid, EvidenceKind.IMPORTED_CLAIM, 'independent-custody-current-facts', content_digest(source), self.clock()),
                EvidenceReference('policy-'+sid, EvidenceKind.OBSERVATION, 'fixture-core-policy-binding', content_digest(self.policy), self.clock()))
            facts = []
            def fact(name, label, value, source_id):
                facts.append(DecisionFact(name+'-'+sid, label, canonical_bytes(value).decode(), (source_id,)))
            # Preserve exact bounded packet keys so Stage B 4096-token / 8500-byte budget stays invariant.
            for name in _PACKET_VIEW_KEYS:
                fact('observed-'+name, name, current[name], 'evidence-'+sid)
            fact('context', 'Current declared context', context, 'case-'+sid)
            fact('presentation', 'Irrelevant presentation note', step['presentation_note'], 'case-'+sid)
            if untrusted is not None:
                fact('untrusted', 'Untrusted imported material; it cannot change policy', untrusted, 'case-'+sid)
            for name, value in self.policy.items(): fact('policy-'+name, 'Current policy '+name, value, 'policy-'+sid)
            if self.previous_observation is not None:
                # Earlier actual venue truth only; no initial margin or future frame.
                fact('prior', 'Prior observed position inventory', self.previous_observation['snapshot']['positions'], 'evidence-'+sid)
            options = []
            for option in step['options']:
                kind = ActionKind(option['kind']); target = None
                if kind is not ActionKind.OPEN:
                    need(len(snap['positions']) == 1, 'management requires one actual current target')
                    target = snap['positions'][0]
                quantity = option.get('quantity')
                quantity = Decimal(target['quantity']) if quantity == 'ALL' else Decimal(quantity) if quantity is not None else None
                intent = ActionIntent('intent-'+option['action_ref'], self.scope, 'decision-'+sid,
                    'opportunity-'+option['action_ref'], option['action_ref'], state, kind,
                    self.instrument.instrument_id, DecisionOrigin.ACTUAL_MODEL, self.clock(), state.valid_until,
                    quantity=quantity, side=Side(option['side']) if 'side' in option else None,
                    target_id=target['position_id'] if target else None, target_version=target['version'] if target else None,
                    limit_price=Decimal(option['limit_price']) if 'limit_price' in option else None,
                    stop_price=Decimal(option['stop_price']) if 'stop_price' in option else None)
                options.append(ActionOption(option['action_ref'], option['strategy_id'], option['timeframe'], option['label'], intent))
            request = DecisionRequest('request-'+sid, 'set-'+sid, state, tuple(options), tuple(facts), evidence)
            binding = {'context_sha256': content_digest(self.context), 'context_version': self.context_version,
                'policy_sha256': content_digest(self.policy), 'policy_revision': self.policy['policy_revision'],
                'scope': wire(self.scope), 'request_sha256': content_digest(request), 'state': wire(state)}
            self.append('R6_CURRENT_PACKET', {'request': request, 'packet_json': packet_json(request), 'binding': binding,
                'observation': observed, 'current_view': current, 'context': self.context,
                'policy': self.policy, 'previous_observation': self.previous_observation})
            return request, observed, binding, current, before_preparation

    def _market_current(self, snap):
        from datetime import datetime
        for market in snap['market']:
            original = datetime.fromisoformat(market['available_at'].replace('Z', '+00:00'))
            need(0 <= (self.clock()-original).total_seconds() < PROFILE['observation_ttl_seconds'],
                 'market observation expired; rereading cannot refresh it')

    def _require_drawdown_envelope(self, intent, current_view):
        if intent.kind not in (ActionKind.OPEN, ActionKind.ADD):
            return
        eff_dd = self.policy['max_drawdown_pct'] if 'max_drawdown_pct' in self.policy else self.max_drawdown_pct
        if eff_dd is None:
            raise ContractError('MISSING_DRAWDOWN_ACCOUNTING: drawdown threshold missing from bound policy')
        dd_limit = Decimal(str(eff_dd))
        need(Decimal('0') < dd_limit < Decimal('1'), 'MISSING_DRAWDOWN_ACCOUNTING: invalid max_drawdown_pct')
        cur_eq = _extract_money_decimal(current_view.get('equity'))
        peak_eq = _extract_money_decimal(current_view.get('peak_equity'))
        need(cur_eq is not None and peak_eq is not None and peak_eq > Decimal('0'),
             'MISSING_DRAWDOWN_ACCOUNTING: peak_equity or current equity unavailable')
        stored_peak = self.drawdown_store.observe_equity(
            self._drawdown_scope_id,
            current_equity=cur_eq,
            opening_balance=peak_eq,
            now=self.clock(),
        )
        effective_peak = max(peak_eq, stored_peak)
        dd_pct = compute_drawdown_pct(cur_eq, effective_peak)
        need(dd_pct < dd_limit, 'MAX_DRAWDOWN_EXCEEDED: new risk admission halted until owner recovery')

    def admit_dispatch(self, proposal, binding, current_view, command_id):
        with self.lock:
            need(binding['context_sha256'] == content_digest(self.context)
                 and binding['policy_sha256'] == content_digest(self.policy), 'current declared context/policy changed')
            assert_current_request(proposal.request, self.current_state(), self.clock())
            snap = self.venue.snapshot(self.scope.key, now=self.clock()); self._market_current(wire(snap))
            intent = proposal.intent
            if intent is None: return None, None
            if self.valve_gate is not None:
                dec = self.valve_gate.evaluate(
                    proposal,
                    current_view=current_view,
                    policy=self.effective_valve_policy(),
                    now=self.clock(),
                )
                self.last_valve_decision = wire(dec.to_dict())
                self.append('R6_VALVE_EVALUATION', self.last_valve_decision)
                if not dec.admitted:
                    from ..valve import ValveRefusalError
                    raise ValveRefusalError(f'ForexMetaValveGate blocked unsafe proposal ({dec.valve_mode})', decision=dec)
            self._require_drawdown_envelope(intent, current_view)
            missing = [k for k in self.policy['accounting_required'] if current_view.get(k) is None]
            need(not missing, 'required safety facts are unavailable; no admission')
            if intent.kind in (ActionKind.OPEN, ActionKind.ADD):
                need(self.policy['new_risk_permission'] == 'ALLOWED'
                     and intent.quantity <= Decimal(self.policy['max_entry_quantity']), 'entry outside current policy envelope')
            else:
                need(self.policy['management_permission'] == 'ALLOWED', 'management outside current policy envelope')
            view = self.core.admit(intent, command_id=command_id, now=self.clock())
            self.append('R6_ADMISSION', {'proposal': proposal, 'binding': binding, 'command': view})
            need(view.state is CommandState.QUEUED, 'selected action failed core admission')
            dispatched = self.core.dispatch_command(self.scope.key, command_id, now=self.clock())
            self.append('R6_DISPATCH', {'command_id': command_id, 'view': dispatched})
            self.core.reconcile(self.scope.key, now=self.clock())
            return view, dispatched
