"""Scoped in-process UI service, explicitly attached by a trusted bootstrap.

No HTTP listener is supplied by this class. Loopback HTTP adapters must
authenticate callers via per-launch constant-time bearer/cookie credentials,
enforce exact loopback Host/Origin headers, and rotate `rotate_adapter_session`
on every launch/restart so prior in-memory prepared requests are invalidated.
Preparation/read methods grant nothing; request methods retain identities before
crossing core/venue boundaries and never retry an uncertain attempted request.
"""
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
import secrets
from threading import RLock

from ..contracts import (ActionIntent, ActionKind, CommandState, ContractError, ControlKind,
                         DecisionOrigin, FenceRequest, canonical_bytes, content_digest)
from ..contracts.primitives import identifier
from ..core.storage import decode
from .read_service import wire


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ContractError('unsupported or missing UI fields')


class ScopedUIService:
    def __init__(self, *, app, owner, journal, reader, clock, market_stream_provider=None):
        if app.config.scope != owner.scope or app.config.scope != reader.scope:
            raise ContractError('trusted bootstrap scope mismatch')
        self.app, self.owner, self.journal, self.reader, self.clock = app, owner, journal, reader, clock
        self.scope = app.config.scope
        self._prepared_controls = {}
        self._prepared_close = {}
        self._lock = RLock()
        self._market_stream_provider = market_stream_provider
        self._adapter_session_epoch = 'epoch-' + secrets.token_hex(16)

    @property
    def session_epoch(self) -> str:
        with self._lock:
            return self._adapter_session_epoch

    def rotate_adapter_session(self, session_epoch: str | None = None) -> str:
        """Rotate adapter session epoch and invalidate all prior prepared control/close objects."""
        next_epoch = ('epoch-' + secrets.token_hex(16)) if session_epoch is None else identifier(session_epoch, 'session_epoch')
        with self._lock:
            self._adapter_session_epoch = next_epoch
            self._prepared_controls.clear()
            self._prepared_close.clear()
            return self._adapter_session_epoch

    def _scope(self, value):
        if value != wire(self.scope):
            raise ContractError('UI request differs from selected owner scope')

    def readBoot(self):
        now = self.clock()
        fence = self.app.venue.snapshot(self.scope.key, now=now).fence
        caps = self.owner.controls
        with self._lock:
            epoch = self._adapter_session_epoch
        return dict(schema_version='forex.ui-transport/1', scope=wire(self.scope), request_time=wire(now),
                    session_epoch=epoch,
                    fence_generation=fence.generation, fence_receipt=wire(fence),
                    decision_schema_sha256=self.reader.schema_sha256,
                    capabilities=dict(pause=ControlKind.PAUSE_NEW_RISK in caps,
                        stop=ControlKind.STOP_AUTOMATION in caps,
                        resume_new_risk=ControlKind.RESUME_NEW_RISK in caps,
                        resume_management=ControlKind.RESUME_MANAGEMENT in caps,
                        reviewed_close=self.owner.reviewed_close and callable(getattr(self.app.core, 'dispatch_command', None))))

    def readCockpit(self):
        return wire(self.reader.read_cockpit())

    def readDecisionRead(self):
        return self.reader.read()

    def resolveEvidence(self, request):
        exact(request, ('anchor_id', 'reference'))
        return self.reader.resolve(request['anchor_id'], request['reference'])

    def prepareControl(self, request):
        exact(request, ('request_id', 'scope', 'control', 'expected_generation'))
        self._scope(request['scope'])
        identifier(request['request_id'], 'request_id')
        kind = ControlKind(request['control'])
        if kind not in self.owner.controls:
            raise ContractError('selected owner lacks control capability')
        with self._lock:
            previous = self._prepared_controls.get(request['request_id'])
            if previous is not None and previous[0] == self._adapter_session_epoch:
                if previous[1] != request:
                    raise ContractError('control preparation identity conflict')
                return wire(previous[2])
            now = self.clock()
            fence = self.app.venue.snapshot(self.scope.key, now=now).fence
            if type(request['expected_generation']) is not int or request['expected_generation'] != fence.generation:
                raise ContractError('control generation changed; refresh independent state')
            result = FenceRequest(self.scope.key, 'ui-barrier-' + content_digest((self.scope, self._adapter_session_epoch, request)),
                                  kind, request['request_id'], fence.generation, fence.generation + 1, now)
            self._prepared_controls[request['request_id']] = (self._adapter_session_epoch, wire(request), result)
            return wire(result)

    def _retained(self, request_id, subject):
        records = [x for x in self.journal.records() if x.kind in ('UI_REQUEST', 'UI_OUTCOME')
                   and x.payload.get('request_id') == request_id]
        if any(x.scope != wire(self.scope) for x in records):
            raise ContractError('request identity belongs to another epoch/session')
        started = next((x for x in records if x.kind == 'UI_REQUEST'), None)
        if started is None:
            return None
        if started.payload['subject'] != wire(subject):
            raise ContractError('durable owner request identity conflict')
        outcome = next((x for x in records if x.kind == 'UI_OUTCOME'), None)
        return outcome.payload['outcome'] if outcome else dict(request_id=request_id, status='UNKNOWN',
            reason='Prior request crossed the durable attempt boundary; inspect independent state, do not resend.')

    def _start(self, request_id, subject):
        self.journal.append('ui-request-' + content_digest((self.scope.key, request_id)), 'UI_REQUEST', self.scope,
                            dict(request_id=request_id, subject=wire(subject)), now=self.clock())

    def _finish(self, request_id, outcome):
        self.journal.append('ui-outcome-' + content_digest((self.scope.key, request_id)), 'UI_OUTCOME', self.scope,
                            dict(request_id=request_id, outcome=outcome), now=self.clock())
        return outcome

    def requestControl(self, raw):
        exact(raw, ('key', 'barrier_id', 'control', 'owner_request_id', 'expected_generation', 'next_generation', 'requested_at'))
        exact(raw['key'], ('account_id', 'run_id', 'environment'))
        request = decode(canonical_bytes(raw).decode('utf-8'), FenceRequest)
        with self._lock:
            if request.key != self.scope.key:
                raise ContractError('control account/run mismatch')
            retained = self._retained(request.owner_request_id, request)
            if retained is not None:
                return wire(retained)
            prepared = self._prepared_controls.get(request.owner_request_id)
            if (prepared is None or prepared[0] != self._adapter_session_epoch
                    or prepared[2] != request or request.control not in self.owner.controls):
                raise ContractError('request was not prepared in this trusted owner context')
            now = self.clock()
            if not request.requested_at <= now < request.requested_at + timedelta(seconds=30):
                raise ContractError('prepared control expired')
            self._start(request.owner_request_id, request)
            try:
                self.owner.register(request, request_id=request.owner_request_id, now=now)
                self.app.core.control(request, now=now)
                # Explicit command processing may observe; GET/read methods never reconcile.
                self.app.core.reconcile(self.scope.key, now=now)
                status, reason = 'ACCEPTED', 'Request processed; confirm exact independent fence readback.'
            except Exception:
                # Failure may follow a commit. No generic exception means rejection/Stop.
                status, reason = 'UNKNOWN', 'Request outcome is uncertain; read the exact independent fence.'
            return self._finish(request.owner_request_id,
                dict(request_id=request.owner_request_id, status=status, reason=reason))

    def readControl(self, raw):
        exact(raw, ('key', 'barrier_id', 'control', 'owner_request_id', 'expected_generation', 'next_generation', 'requested_at'))
        exact(raw['key'], ('account_id', 'run_id', 'environment'))
        request = decode(canonical_bytes(raw).decode('utf-8'), FenceRequest)
        if request.key != self.scope.key:
            raise ContractError('control read scope mismatch')
        # Return actual current receipt, even when superseded; consumer compares exact identity.
        return wire(self.app.venue.snapshot(self.scope.key, now=self.clock()).fence)

    def prepareClose(self, request):
        exact(request, ('owner_request_id', 'command_id', 'scope', 'source_state_id',
                        'position_id', 'position_version', 'quantity', 'quantity_unit'))
        self._scope(request['scope'])
        for field in ('owner_request_id', 'command_id', 'source_state_id', 'position_id'):
            identifier(request[field], field)
        if not self.owner.reviewed_close or not callable(getattr(self.app.core, 'dispatch_command', None)):
            raise ContractError('exact reviewed Close capability unavailable')
        if request['quantity_unit'] != 'BASE_UNITS' or type(request['quantity']) is not str:
            raise ContractError('Close requires exact decimal base units')
        with self._lock:
            old = self._prepared_close.get(request['owner_request_id'])
            if old is not None and old[0] == self._adapter_session_epoch:
                if old[1] != request:
                    raise ContractError('Close preparation identity conflict')
                return wire(old[3])
            now = self.clock()
            state = self.app.core.current_state(self.scope.key, now=now)
            snapshot = self.app.venue.snapshot(self.scope.key, now=now)
            target = next((x for x in snapshot.positions if x.position_id == request['position_id']), None)
            amount = Decimal(request['quantity'])
            if (state.state_id != request['source_state_id'] or state.venue_sequence != snapshot.sequence
                    or target is None or type(request['position_version']) is not int
                    or target.version != request['position_version'] or target.quantity != amount):
                raise ContractError('review target/state/version/quantity changed')
            bind_seed = (self._adapter_session_epoch, request)
            intent = ActionIntent('ui-intent-' + content_digest(bind_seed), self.scope,
                'ui-close-decision-' + content_digest(bind_seed), 'ui-close-opportunity-' + content_digest(bind_seed),
                'ui-close-action-' + content_digest(bind_seed), state, ActionKind.CLOSE, target.instrument_id,
                DecisionOrigin.OWNER_REVIEWED, now, min(state.valid_until, now + timedelta(seconds=30)),
                quantity=amount, target_id=target.position_id, target_version=target.version)
            preview = dict(preview_id='preview-' + content_digest((self._adapter_session_epoch, request, intent)),
                           owner_request_id=request['owner_request_id'], command_id=request['command_id'],
                           scope=wire(self.scope), intent=wire(intent), intent_sha256=content_digest(intent),
                           expires_at=wire(intent.expires_at))
            self._prepared_close[request['owner_request_id']] = (self._adapter_session_epoch, wire(request), intent, preview)
            return wire(preview)

    def requestReviewedClose(self, request):
        exact(request, ('preview_id', 'owner_request_id', 'command_id', 'scope', 'intent_sha256'))
        self._scope(request['scope'])
        with self._lock:
            retained = self._retained(request['owner_request_id'], request)
            if retained is not None:
                return {**wire(retained), 'command': retained.get('command')}
            prepared = self._prepared_close.get(request['owner_request_id'])
            if prepared is None or prepared[0] != self._adapter_session_epoch:
                raise ContractError('Close was not reviewed in this owner context')
            _, _, intent, preview = prepared
            if request != {k: preview[k] for k in request}:
                raise ContractError('Close submission differs from exact reviewed preview')
            now = self.clock()
            if not intent.created_at <= now < intent.expires_at:
                raise ContractError('reviewed Close expired')
            state = self.app.core.current_state(self.scope.key, now=now)
            snapshot = self.app.venue.snapshot(self.scope.key, now=now)
            if state != intent.source_state or snapshot.sequence != state.venue_sequence:
                raise ContractError('reviewed Close source changed before submission')
            self._start(request['owner_request_id'], request)
            command = None
            try:
                self.owner.register(intent, request_id=request['owner_request_id'], command_id=request['command_id'], now=now)
                command = self.app.core.admit(intent, command_id=request['command_id'], now=now)
                if command.state is CommandState.REJECTED:
                    status, reason = 'REJECTED', command.reason_code or 'CORE_REJECTED'
                else:
                    dispatched = self.app.core.dispatch_command(self.scope.key, request['command_id'], now=now)
                    command = dispatched or command
                    status, reason = 'ACCEPTED', 'Exact Close recorded; independent venue quantities establish the effect.'
                    self.app.core.reconcile(self.scope.key, now=now)
            except Exception:
                status, reason = 'UNKNOWN', 'Close outcome uncertain; read its exact identity without resending.'
            return self._finish(request['owner_request_id'], dict(request_id=request['owner_request_id'],
                                status=status, reason=reason, command=wire(command)))

    def readCommand(self, command_id):
        identifier(command_id, 'command_id')
        core = self.app.core.read_snapshot(self.scope.key)
        record = next((x for x in core.commands if x.command.command_id == command_id), None)
        if record is not None and record.command.intent.scope != self.scope:
            raise ContractError('command belongs to another exact scope')
        command = None if record is None else dict(command_id=command_id, payload_sha256=record.command.payload_sha256,
            state=record.state.value, last_venue_receipt_id=record.receipt.receipt_id if record.receipt else None,
            reservation_held=record.reservation_held, reason_code=record.reason_code)
        return dict(command=command, venue_lookup=wire(self.app.venue.lookup(self.scope.key, command_id)))

    def readMarketStream(self):
        """Read-only multi-currency market stream accessor; never reconciles or mutates durable state."""
        if callable(self._market_stream_provider):
            return self._market_stream_provider()
        reader_fn = getattr(self.app.venue, 'read_market_stream', None)
        if callable(reader_fn):
            return reader_fn()
        return None
