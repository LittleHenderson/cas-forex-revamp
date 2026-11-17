"""Transactional, explicitly stepped coordinator for disconnected simulation.

No background workers, automatic grants, retries of attempted commands, broker
clients, model calls, or cross-store transactions are implemented here.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal, localcontext
from uuid import uuid4

from cas_forex_revamp.contracts import (
    AccountRunKey, ActionIntent, ActionKind, AuthorizedCommand, CockpitProjection,
    CommandState, CommandView, ControlKind, DecisionOrigin, EffectState,
    FenceReceipt, FenceRequest, LookupState, ManagementPermission,
    NewRiskPermission, Permissions, RecoveryState, RunScope, Side,
    StateReference, VenuePort, VenueReceipt, VenueSnapshot, content_digest,
    intent_digest,
)
from cas_forex_revamp.contracts.primitives import identifier, utc_time
from .policy import InstrumentPolicy, RiskPolicy, exposure, upward
from .records import (
    AccountRecord, AdmissionDenied, CommandRecord, CoreCheckpoint, CoreError, CoreReadSnapshot, EvidenceConflict,
    IdentityConflict, OutcomeUnknown, OwnerApproval, OwnerVerifier, StaleWriter,
)
from .storage import SQLiteStore, encode

ZERO = Decimal("0")
RISK_ACTIONS = (ActionKind.OPEN, ActionKind.ADD)
QUANTITY_ACTIONS = (ActionKind.OPEN, ActionKind.ADD, ActionKind.REDUCE, ActionKind.CLOSE)
RISK_CHANGING_ACTIONS = (
    ActionKind.OPEN,
    ActionKind.ADD,
    ActionKind.AMEND_STOP,
    ActionKind.REDUCE,
    ActionKind.CLOSE,
)
RESUMES = (ControlKind.RESUME_NEW_RISK, ControlKind.RESUME_MANAGEMENT)


def _view(record: CommandRecord) -> CommandView:
    return CommandView(record.command.command_id, record.command.payload_sha256,
                       record.state, record.receipt.receipt_id if record.receipt else None,
                       record.reservation_held, record.reason_code)


def _retire(record: CommandRecord, reason: str) -> CommandRecord:
    return replace(record, state=CommandState.REJECTED, reserved_notional=ZERO,
                   target_remaining=ZERO, reservation_held=False, reason_code=reason)


def _expected_permissions(request: FenceRequest, before: FenceReceipt) -> tuple[bool, bool]:
    if request.control is ControlKind.STOP_AUTOMATION:
        return False, False
    if request.control is ControlKind.PAUSE_NEW_RISK:
        return False, before.management_allowed
    if request.control is ControlKind.RESUME_NEW_RISK:
        return True, before.management_allowed
    return before.new_risk_allowed, True


class CoreCoordinator:
    def __init__(self, *, scope: RunScope, store: SQLiteStore, venue: VenuePort,
                 policy: RiskPolicy, instruments: tuple[InstrumentPolicy, ...],
                 owner_verifier: OwnerVerifier | None = None):
        self.scope = scope
        self.store = store
        self.venue = venue
        self.policy = policy
        self.instruments = {x.instrument.instrument_id: x for x in instruments}
        if not instruments or len(self.instruments) != len(instruments):
            raise ValueError("instrument policies must be nonempty and unique")
        if any(x.instrument.quote_currency != policy.account_currency for x in instruments):
            raise ValueError("v1 core requires quote currency equal to account currency")
        self.owner_verifier = owner_verifier
        self.writer_id = "writer-" + uuid4().hex

    def initialize(self, *, create: bool = False, expected_checkpoint: CoreCheckpoint | None = None) -> None:
        """Explicit create/reopen; persist a new inert session, never resume.

        A new build/policy/scenario/adapter scope requires a greater epoch. Old
        commands remain under the same stable account/run namespace.
        """
        if create and expected_checkpoint is not None:
            raise CoreError("NEW_STORE_CANNOT_RESTORE_CHECKPOINT")
        self.store.initialize(create=create)
        with self.store.transaction() as db:
            if expected_checkpoint is not None:
                self._check_checkpoint(db, expected_checkpoint)
            exists = db.execute("SELECT 1 FROM accounts WHERE account_key=?", (self.store.key(self.scope.key),)).fetchone()
            if exists:
                previous = self.store.account(db, self.scope.key)
                self.store.commands(db, self.scope.key)
                self.store.events(db, self.scope.key)
                if previous.scope != self.scope and self.scope.epoch <= previous.scope.epoch:
                    raise CoreError("SCOPE_CHANGE_REQUIRES_GREATER_EPOCH")
                self.store.event(db, self.scope.key, "SESSION_REPLACED", previous)
                account = AccountRecord(self.scope, self.writer_id,
                                        revision=previous.revision + 1,
                                        snapshot=previous.snapshot)
            else:
                account = AccountRecord(self.scope, self.writer_id)
            self.store.save_account(db, account)
            self.store.event(db, self.scope.key, "SESSION_INERT", {"scope": self.scope, "writer_id": self.writer_id})

    def checkpoint(self, key: AccountRunKey) -> CoreCheckpoint:
        """Export a read-only high-water mark for a separately trusted holder."""
        snapshot = self.read_snapshot(key)
        return CoreCheckpoint(key, snapshot.event_sequence, snapshot.event_sha256,
                              snapshot.account.snapshot.sequence if snapshot.account.snapshot else 0)

    def read_snapshot(self, key: AccountRunKey) -> CoreReadSnapshot:
        """Read account, commands and validated event prefix in ONE RO transaction.

        No reconcile, venue call, clock call, grant mutation, or event is emitted.
        Consumers must keep cached venue provenance and independent venue reads
        separate, and must not interpret this core cursor as a venue cursor.
        """
        with self.store.read() as db:
            account = self._account(db, key)
            commands = self.store.commands(db, key)
            events = self.store.events(db, key)
            if not events:
                raise CoreError("CORE_EVENT_HISTORY_MISSING")
            return CoreReadSnapshot(account, commands, events, events[-1].sequence, events[-1].event_sha256)

    def _check_checkpoint(self, db, checkpoint: CoreCheckpoint) -> None:
        if checkpoint.key != self.scope.key:
            raise CoreError("CHECKPOINT_SCOPE_MISMATCH")
        event = next((x for x in self.store.events(db, checkpoint.key) if x.sequence == checkpoint.event_sequence), None)
        if event is None or event.event_sha256 != checkpoint.event_sha256:
            raise CoreError("CORE_CHECKPOINT_ROLLBACK_OR_DIVERGENCE")
        account = self.store.account(db, checkpoint.key)
        if checkpoint.venue_sequence > (account.snapshot.sequence if account.snapshot else 0):
            raise CoreError("CORE_VENUE_HIGH_WATER_ROLLBACK")

    def _account(self, db, key: AccountRunKey) -> AccountRecord:
        if key != self.scope.key:
            raise AdmissionDenied("ACCOUNT_RUN_MISMATCH")
        account = self.store.account(db, key)
        if account.writer_id != self.writer_id or account.scope != self.scope:
            raise StaleWriter("WRITER_REPLACED")
        return account

    def _save_account(self, db, account: AccountRecord, **changes) -> AccountRecord:
        updated = replace(account, revision=account.revision + 1, **changes)
        self.store.save_account(db, updated)
        return updated

    def current_state(self, key: AccountRunKey, *, now: datetime) -> StateReference:
        utc_time(now, "now")
        with self.store.read() as db:
            if any(x.state in (CommandState.SUBMITTED, CommandState.UNRESOLVED) for x in self.store.commands(db, key)):
                raise AdmissionDenied("STATE_HAS_UNRESOLVED_COMMANDS")
            return self._fresh(self._account(db, key), now)

    @staticmethod
    def _fresh(account: AccountRecord, now: datetime) -> StateReference:
        state = account.source_state
        if (account.recovery is not RecoveryState.COHERENT or account.pending_fence is not None
                or state is None or not state.observed_at <= now < state.valid_until):
            raise AdmissionDenied("STATE_NOT_CURRENT")
        return state

    def _approval(self, subject: ActionIntent | FenceRequest, now: datetime,
                  *, command_id: str | None = None) -> OwnerApproval:
        if self.owner_verifier is None:
            raise AdmissionDenied("OWNER_VERIFIER_UNAVAILABLE")
        approval = self.owner_verifier.verify(subject, now=now)
        if not isinstance(approval, OwnerApproval):
            raise AdmissionDenied("OWNER_APPROVAL_INVALID")
        approval.check(subject, self.scope, now, command_id=command_id)
        return approval

    def verify_owner_close(self, command: AuthorizedCommand, now: datetime) -> bool:
        """Read-only venue callback; does not consume approval or call venue.

        Core commits dispatch before venue entry, so venue -> core read locking
        cannot form a core-write -> venue-write lock cycle. A replaced session,
        expired approval or copied enum denies. Corrupted/missing storage raises
        unavailable instead of masquerading as an ordinary permission rejection.
        """
        try:
            utc_time(now, "now")
            if (command.intent.kind is not ActionKind.CLOSE
                    or command.intent.origin is not DecisionOrigin.OWNER_REVIEWED):
                return False
            with self.store.read() as db:
                account = self._account(db, command.intent.scope.key)
                self._fresh(account, now)
                record = next((x for x in self.store.commands(db, self.scope.key)
                               if x.command.command_id == command.command_id), None)
                if (record is None or record.command != command or not record.attempted
                        or command.writer_id != self.writer_id or command.intent.scope != self.scope
                        or account.snapshot is None or not account.safe_fence
                        or command.dispatch_generation != account.snapshot.fence.generation
                        or not command.intent.created_at <= now < command.intent.expires_at):
                    return False
                approval = self.store.owner_approval(db, self.scope.key, command.authority_id, "command:" + command.command_id)
                approval.check(command.intent, self.scope, now, command_id=command.command_id)
                return True
        except (AdmissionDenied, StaleWriter):
            return False

    def _market(self, snapshot: VenueSnapshot, instrument_id: str, now: datetime):
        quotes = [x for x in snapshot.market if x.instrument_id == instrument_id]
        if not quotes:
            raise AdmissionDenied("MARKET_UNOBSERVED")
        quote = max(quotes, key=lambda x: x.sequence)
        if not quote.observed_at <= quote.available_at <= now or now - quote.observed_at > timedelta(seconds=self.policy.observation_ttl_seconds):
            raise AdmissionDenied("MARKET_STALE")
        return quote

    def _admission(self, db, account: AccountRecord, records: tuple[CommandRecord, ...],
                   intent: ActionIntent, command_id: str, now: datetime) -> tuple[Decimal, Decimal, str]:
        if intent.scope != self.scope:
            raise AdmissionDenied("SCOPE_MISMATCH")
        if any(x.state in (CommandState.SUBMITTED, CommandState.UNRESOLVED) for x in records):
            raise AdmissionDenied("UNRESOLVED_COMMANDS")
        if intent.source_state != self._fresh(account, now):
            raise AdmissionDenied("SOURCE_STATE_CHANGED")
        if not intent.created_at <= now < intent.expires_at:
            raise AdmissionDenied("INTENT_EXPIRED_OR_FUTURE")
        if not account.safe_fence or account.snapshot is None or not account.snapshot.fence.applied:
            raise AdmissionDenied("FRESH_FENCE_REQUIRED")
        spec = self.instruments.get(intent.instrument_id)
        if spec is None:
            raise AdmissionDenied("UNKNOWN_INSTRUMENT")
        spec.validate_geometry(intent)
        if intent.kind is ActionKind.CANCEL_ORDER and any(
                x is not None for x in (intent.side, intent.limit_price, intent.stop_price, intent.take_profit_price)):
            raise AdmissionDenied("UNSUPPORTED_ACTION_GEOMETRY")
        if intent.kind is ActionKind.AMEND_STOP and (intent.side is not None or intent.limit_price is not None):
            raise AdmissionDenied("UNSUPPORTED_ACTION_GEOMETRY")
        if intent.kind in (ActionKind.CLOSE, ActionKind.REDUCE) and (
                intent.stop_price is not None or intent.take_profit_price is not None):
            raise AdmissionDenied("UNSUPPORTED_ACTION_GEOMETRY")
        owner_close = intent.origin is DecisionOrigin.OWNER_REVIEWED
        if owner_close and intent.kind is not ActionKind.CLOSE:
            raise AdmissionDenied("OWNER_REVIEW_ONLY_FOR_EXACT_CLOSE")
        fence = account.snapshot.fence
        if intent.kind in RISK_ACTIONS:
            if not account.armed_new_risk or not fence.new_risk_allowed:
                raise AdmissionDenied("NEW_RISK_NOT_ARMED")
        elif not owner_close and (not account.armed_management or not fence.management_allowed):
            raise AdmissionDenied("MANAGEMENT_NOT_ARMED")

        target_quantity = ZERO
        if intent.kind is ActionKind.CANCEL_ORDER:
            original = next((x for x in records if x.command.command_id == intent.target_id), None)
            receipt = original.receipt if original is not None else None
            if (original is None or receipt is None or not original.attempted
                    or receipt.effect is EffectState.UNKNOWN or receipt.quantities is None
                    or receipt.quantities.remaining <= 0
                    or receipt.venue_sequence != intent.target_version
                    or original.command.intent.instrument_id != intent.instrument_id
                    or intent.target_id not in account.snapshot.open_command_ids):
                raise AdmissionDenied("ORDER_VERSION_NOT_CURRENT")
            # Receipt came from the last coherent independent lookup; accept will
            # compare its exact version again atomically with any racing fill.
            if any(x.reservation_held and x.command.intent.kind is ActionKind.CANCEL_ORDER
                   and x.command.intent.target_id == intent.target_id for x in records):
                raise AdmissionDenied("ORDER_ALREADY_RESERVED")
        elif intent.kind is not ActionKind.OPEN:
            position = next((x for x in account.snapshot.positions if x.position_id == intent.target_id), None)
            if (position is None or position.version != intent.target_version
                    or position.instrument_id != intent.instrument_id or position.quantity <= 0):
                raise AdmissionDenied("TARGET_VERSION_NOT_CURRENT")
            peers = [x for x in records if x.reservation_held
                     and (x.command.intent.target_id == intent.target_id or
                          (x.receipt is not None and x.receipt.position_id == intent.target_id))
                     and x.command.intent.kind is not ActionKind.CANCEL_ORDER]
            # The initial venue supports one pending quantity action per target.
            # Serialize all mutations to that target, including stop amendments.
            if peers:
                raise AdmissionDenied("TARGET_ALREADY_RESERVED")
            if intent.kind in (ActionKind.REDUCE, ActionKind.CLOSE):
                if intent.quantity > position.quantity:
                    raise AdmissionDenied("INSUFFICIENT_CLOSEABLE_QUANTITY")
                if intent.kind is ActionKind.CLOSE and intent.quantity != position.quantity:
                    raise AdmissionDenied("CLOSE_REQUIRES_EXACT_POSITION_QUANTITY")
                if intent.side is not None and intent.side is position.side:
                    raise AdmissionDenied("EXIT_SIDE_MISMATCH")
                target_quantity = intent.quantity
            if intent.kind is ActionKind.ADD and intent.side is not None and intent.side is not position.side:
                raise AdmissionDenied("ADD_SIDE_MISMATCH")
            if intent.kind is ActionKind.AMEND_STOP:
                # Protection may tighten; increasing risk needs another reviewed
                # capability rather than hiding expansion in management.
                quote = self._market(account.snapshot, intent.instrument_id, now)
                if intent.stop_price is not None:
                    if position.side is Side.BUY:
                        if intent.stop_price >= quote.bid or (position.stop_price is not None and intent.stop_price < position.stop_price):
                            raise AdmissionDenied("STOP_EXPANDS_OR_CROSSES_MARKET")
                    elif intent.stop_price <= quote.ask or (position.stop_price is not None and intent.stop_price > position.stop_price):
                        raise AdmissionDenied("STOP_EXPANDS_OR_CROSSES_MARKET")
                if intent.take_profit_price is not None:
                    if position.side is Side.BUY and intent.take_profit_price <= quote.ask:
                        raise AdmissionDenied("TAKE_PROFIT_CROSSES_MARKET")
                    if position.side is Side.SELL and intent.take_profit_price >= quote.bid:
                        raise AdmissionDenied("TAKE_PROFIT_CROSSES_MARKET")

        reserve = ZERO
        if intent.kind in RISK_ACTIONS:
            if intent.limit_price is None or intent.limit_price > spec.reservation_price_ceiling:
                raise AdmissionDenied("BOUNDED_ENTRY_PRICE_REQUIRED")
            if self._market(account.snapshot, intent.instrument_id, now).ask > spec.reservation_price_ceiling:
                raise AdmissionDenied("MARKET_OUTSIDE_PRICE_ENVELOPE")
            reserve = spec.notional(intent.quantity, self.policy)
            with localcontext() as ctx:
                ctx.prec = 80
                committed = sum((x.reserved_notional for x in records), ZERO)
                capacity = min(self.policy.maximum_gross_notional, account.snapshot.equity.amount)
                if exposure(account.snapshot, self.instruments, self.policy) + committed + reserve > capacity:
                    raise AdmissionDenied("GROSS_NOTIONAL_CAPACITY")
        authority_id = "fence-" + content_digest(fence)
        if owner_close:
            approval = self._approval(intent, now, command_id=command_id)
            self.store.bind_owner(db, approval, "command:" + command_id)
            authority_id = approval.request_id
        return reserve, target_quantity, authority_id

    def admit(self, intent: ActionIntent, *, command_id: str, now: datetime) -> CommandView:
        utc_time(now, "now")
        identifier(command_id, "command_id")
        if command_id.startswith("venue-stop-"):
            raise AdmissionDenied("VENUE_COMMAND_NAMESPACE_RESERVED")
        payload_hash = intent_digest(intent)
        # Existing core identities need no network/venue availability to replay.
        # New identities must also be absent at the independently observed cursor,
        # detecting an accepted identity missing from a restored core database.
        with self.store.read() as db:
            self._account(db, intent.scope.key)
            existing = next((x for x in self.store.commands(db, self.scope.key)
                             if x.command.command_id == command_id), None)
            if existing is not None:
                if existing.command.payload_sha256 != payload_hash:
                    raise IdentityConflict("COMMAND_PAYLOAD_CONFLICT")
                return _view(existing)
        lookup = self.venue.lookup(self.scope.key, command_id)
        if lookup.key != self.scope.key or lookup.command_id != command_id:
            self._quarantine(self.scope.key, "IDENTITY_LOOKUP_MISMATCH")
            raise EvidenceConflict("IDENTITY_LOOKUP_MISMATCH")
        with self.store.transaction() as db:
            account = self._account(db, intent.scope.key)
            records = self.store.commands(db, self.scope.key)
            existing = next((x for x in records if x.command.command_id == command_id), None)
            if existing is not None:
                if existing.command.payload_sha256 != payload_hash:
                    raise IdentityConflict("COMMAND_PAYLOAD_CONFLICT")
                return _view(existing)
            if lookup.state is LookupState.FOUND:
                self._save_account(db, account, source_state=None, recovery=RecoveryState.QUARANTINED,
                                   armed_new_risk=False, armed_management=False, safe_fence=False)
                self.store.event(db, self.scope.key, "MISSING_CORE_IDENTITY", lookup)
            else:
                return self._admit_claim(db, account, records, lookup, intent, command_id, payload_hash, now)
        raise EvidenceConflict("ACCEPTED_IDENTITY_MISSING_FROM_CORE")

    def _admit_claim(self, db, account, records, lookup, intent, command_id, payload_hash, now):
        reason = None
        try:
            if (lookup.state is not LookupState.NOT_FOUND or account.source_state is None
                    or lookup.observed_sequence != account.source_state.venue_sequence):
                raise AdmissionDenied("IDENTITY_LOOKUP_NOT_CURRENT")
            reserve, target_quantity, authority = self._admission(db, account, records, intent, command_id, now)
        except AdmissionDenied as exc:
            reserve, target_quantity, authority = ZERO, ZERO, "denied"
            reason = str(exc)
            identifier(reason, "admission reason")
        generation = account.snapshot.fence.generation if account.snapshot else 0
        price = self.instruments[intent.instrument_id].reservation_price_ceiling if reserve else ZERO
        command = AuthorizedCommand(command_id, intent, payload_hash,
                                    "reservation-" + content_digest((self.scope.key, command_id)),
                                    authority, generation, self.writer_id,
                                    risk_price_ceiling=price if reason is None and intent.kind in RISK_ACTIONS else None)
        record = CommandRecord(command, CommandState.REJECTED if reason else CommandState.QUEUED,
                               reserve, target_quantity, reservation_price=price, reservation_held=reason is None,
                               reason_code=reason)
        self.store.save_command(db, record)
        state = account.source_state
        if reason is None and state is not None:
            state = replace(state, state_id="state-" + content_digest((state, command_id)), version=account.revision + 1)
        self._save_account(db, account, source_state=state)
        self.store.event(db, self.scope.key, "ADMISSION", record)
        return _view(record)

    def _dispatch_allowed(self, account: AccountRecord, record: CommandRecord, now: datetime) -> str | None:
        command, intent = record.command, record.command.intent
        if intent.kind in RISK_ACTIONS:
            if command.risk_price_ceiling is None:
                return "MISSING_EXECUTION_PRICE_CEILING"
            spec = self.instruments.get(intent.instrument_id)
            if (spec is None or command.risk_price_ceiling != spec.reservation_price_ceiling
                    or record.reservation_price != command.risk_price_ceiling
                    or not record.reservation_held or record.target_remaining != ZERO
                    or record.reserved_notional != spec.notional(intent.quantity, self.policy)):
                return "EXECUTION_PRICE_RESERVATION_MISMATCH"
        try:
            current = self._fresh(account, now)
            if (intent.source_state.scope != current.scope or intent.source_state.venue_sequence != current.venue_sequence
                    or not intent.source_state.observed_at <= now < intent.source_state.valid_until):
                return "SOURCE_STATE_CHANGED_BEFORE_DISPATCH"
        except AdmissionDenied:
            return "STATE_NOT_CURRENT_BEFORE_DISPATCH"
        if not account.safe_fence or command.writer_id != self.writer_id or intent.scope != self.scope:
            return "WRITER_OR_SCOPE_CHANGED"
        if not intent.created_at <= now < intent.expires_at:
            return "EXPIRED_BEFORE_DISPATCH"
        fence = account.snapshot.fence
        if command.dispatch_generation != fence.generation:
            return "FENCED_BEFORE_SUBMISSION"
        if intent.kind in RISK_ACTIONS and not (account.armed_new_risk and fence.new_risk_allowed):
            return "NEW_RISK_NOT_ARMED"
        if intent.kind not in RISK_ACTIONS and intent.origin is not DecisionOrigin.OWNER_REVIEWED and not (
                account.armed_management and fence.management_allowed):
            return "MANAGEMENT_NOT_ARMED"
        return None

    def dispatch_next(self, key: AccountRunKey, *, now: datetime) -> CommandView | None:
        return self._dispatch(key, command_id=None, now=now)

    def dispatch_command(self, key: AccountRunKey, command_id: str, *, now: datetime) -> CommandView | None:
        """Claim only this queued identity; never fall through to another command.

        Already attempted/terminal identities return their retained view without
        submission. Missing identities or another unresolved attempt return None.
        """
        identifier(command_id, "command_id")
        return self._dispatch(key, command_id=command_id, now=now)

    def _dispatch(self, key: AccountRunKey, *, command_id: str | None, now: datetime) -> CommandView | None:
        utc_time(now, "now")
        with self.store.transaction() as db:
            account = self._account(db, key)
            records = self.store.commands(db, key)
            if command_id is None:
                record = next((x for x in records if x.state is CommandState.QUEUED), None)
            else:
                record = next((x for x in records if x.command.command_id == command_id), None)
            if record is None:
                return None
            if record.state is not CommandState.QUEUED:
                return _view(record)
            if any(x.state in (CommandState.SUBMITTED, CommandState.UNRESOLVED) for x in records):
                return None
            reason = self._dispatch_allowed(account, record, now)
            if reason is None and record.command.intent.origin is DecisionOrigin.OWNER_REVIEWED:
                approval = self.store.owner_approval(db, key, record.command.authority_id, "command:" + record.command.command_id)
                try:
                    approval.check(record.command.intent, self.scope, now, command_id=record.command.command_id)
                except AdmissionDenied:
                    reason = "OWNER_APPROVAL_EXPIRED"
            if reason:
                record = _retire(record, reason)
            else:
                record = replace(record, state=CommandState.SUBMITTED, attempted=True)
            self.store.save_command(db, record)
            self._save_account(db, account)
            self.store.event(db, key, "DISPATCH_CLAIM" if not reason else "LOCAL_RETIREMENT", record)
        if reason:
            return _view(record)
        # Commit the attempt BEFORE crossing the independent venue boundary.
        try:
            receipt = self.venue.accept(record.command, now=now)
        except Exception as exc:
            self._mark_unknown(key, record.command.command_id, "SUBMISSION_OUTCOME_UNKNOWN")
            raise OutcomeUnknown("SUBMISSION_OUTCOME_UNKNOWN") from exc
        try:
            with self.store.transaction() as db:
                # A delayed receipt remains useful after another session takes
                # ownership. It cannot grant authority or advance a new session.
                current = next(x for x in self.store.commands(db, key) if x.command.command_id == record.command.command_id)
                current = self._observe(db, current, receipt, now)
                self.store.save_command(db, current)
                account = self.store.account(db, key)
                self._save_account(db, account, source_state=None, recovery=RecoveryState.RECONCILING)
                return _view(current)
        except EvidenceConflict:
            self._quarantine(key, "RECEIPT_CONFLICT")
            raise

    def _mark_unknown(self, key: AccountRunKey, command_id: str, reason: str) -> None:
        with self.store.transaction() as db:
            record = next(x for x in self.store.commands(db, key) if x.command.command_id == command_id)
            # Never overwrite independently read truth with transport uncertainty.
            if record.receipt is None:
                self.store.save_command(db, replace(record, state=CommandState.UNRESOLVED, reason_code=reason))
            account = self.store.account(db, key)
            self._save_account(db, account, source_state=None, recovery=RecoveryState.UNRESOLVED,
                               armed_new_risk=False, armed_management=False)
            self.store.event(db, key, reason, {"command_id": command_id})

    def _observe(self, db, record: CommandRecord, receipt: VenueReceipt, now: datetime) -> CommandRecord:
        c = record.command
        if (not isinstance(receipt, VenueReceipt) or receipt.key != c.intent.scope.key
                or receipt.command_id != c.command_id or receipt.payload_sha256 != c.payload_sha256
                or receipt.dispatch_generation != c.dispatch_generation or receipt.observed_at > now):
            raise EvidenceConflict("RECEIPT_IDENTITY_MISMATCH")
        if receipt.effect is EffectState.UNKNOWN:
            if record.receipt is not None:
                return record
            return replace(record, state=CommandState.UNRESOLVED, reason_code="VENUE_EFFECT_UNKNOWN")
        raw = encode(receipt)
        same = db.execute("SELECT payload FROM receipts WHERE account_key=? AND command_id=? AND venue_sequence=?",
                          (self.store.key(receipt.key), c.command_id, receipt.venue_sequence)).fetchone()
        if same is not None and same[0] != raw:
            raise EvidenceConflict("SAME_SEQUENCE_DIFFERENT_RECEIPT")
        old = record.receipt
        if old is not None and receipt.venue_sequence <= old.venue_sequence:
            if receipt.venue_sequence == old.venue_sequence and receipt != old:
                raise EvidenceConflict("RECEIPT_SEQUENCE_CONFLICT")
            return record
        q = receipt.quantities
        if c.intent.kind in QUANTITY_ACTIONS:
            if receipt.effect is EffectState.APPLIED or (q is not None and q.ordered != c.intent.quantity):
                raise EvidenceConflict("RECEIPT_QUANTITY_IDENTITY")
        elif q is not None:
            raise EvidenceConflict("NON_QUANTITY_RECEIPT_HAS_QUANTITIES")
        if old is not None:
            if old.quantities is not None:
                if q is None or any(getattr(q, x) < getattr(old.quantities, x) for x in ("filled", "cancelled", "rejected")) or q.remaining > old.quantities.remaining:
                    raise EvidenceConflict("CUMULATIVE_QUANTITY_REGRESSION")
            if old.effect in (EffectState.APPLIED, EffectState.REJECTED, EffectState.CANCELLED, EffectState.FILLED) and (
                    receipt.effect != old.effect or receipt.quantities != old.quantities):
                raise EvidenceConflict("TERMINAL_RECEIPT_CHANGED")
        duplicate_id = db.execute("SELECT payload FROM receipts WHERE account_key=? AND receipt_id=?",
                                  (self.store.key(receipt.key), receipt.receipt_id)).fetchone()
        if duplicate_id is not None and duplicate_id[0] != raw:
            raise EvidenceConflict("RECEIPT_ID_REUSED")
        db.execute("INSERT OR IGNORE INTO receipts VALUES (?,?,?,?,?)",
                   (self.store.key(receipt.key), c.command_id, receipt.venue_sequence, receipt.receipt_id, raw))
        self.store.event(db, receipt.key, "VENUE_RECEIPT_OBSERVED", receipt)
        return replace(record, receipt=receipt, state=CommandState.OBSERVED,
                       reason_code=receipt.reason_code)

    def _quarantine(self, key: AccountRunKey, reason: str) -> None:
        with self.store.transaction() as db:
            account = self.store.account(db, key)
            self._save_account(db, account, source_state=None, recovery=RecoveryState.QUARANTINED,
                               armed_new_risk=False, armed_management=False, safe_fence=False)
            self.store.event(db, key, "QUARANTINED", {"reason": reason})

    def control(self, request: FenceRequest, *, now: datetime) -> FenceReceipt:
        utc_time(now, "now")
        if request.key != self.scope.key or request.requested_at > now:
            raise AdmissionDenied("CONTROL_SCOPE_OR_TIME")
        with self.store.read() as db:
            prior_account = self._account(db, request.key)
            prior = db.execute("SELECT payload FROM controls WHERE account_key=? AND barrier_id=?",
                               (self.store.key(request.key), request.barrier_id)).fetchone()
            if prior is not None and prior[0] != encode(request):
                raise IdentityConflict("BARRIER_PAYLOAD_CONFLICT")
        prior_fence = prior_account.snapshot.fence if prior_account.snapshot else None
        if (prior is not None and prior_fence is not None and prior_fence.barrier_id == request.barrier_id
                and prior_fence.generation == request.next_generation and prior_account.pending_fence is None):
            # Exact retry observes an existing barrier. It never renews a grant
            # or reuses a historical approval to advance another generation.
            observed = self.venue.snapshot(request.key, now=now)
            self._snapshot_valid(observed, prior_account.snapshot, now)
            if observed.fence != prior_fence:
                raise OutcomeUnknown("CONTROL_SUPERSEDED")
            return observed.fence
        approval = self._approval(request, now)
        with self.store.transaction() as db:
            account = self._account(db, request.key)
            if account.pending_fence is not None and account.pending_fence != request:
                raise AdmissionDenied("CONTROL_ALREADY_PENDING")
            if request.control in RESUMES:
                self._fresh(account, now)
                if not account.safe_fence:
                    raise AdmissionDenied("FRESH_FENCE_REQUIRED")
            before = account.snapshot.fence if account.snapshot else None
            if before is None or before.generation != request.expected_generation:
                raise AdmissionDenied("CONTROL_REQUIRES_CURRENT_FENCE")
            desired = _expected_permissions(request, before)
            previous_request = db.execute("SELECT payload FROM controls WHERE account_key=? AND barrier_id=?",
                                          (self.store.key(request.key), request.barrier_id)).fetchone()
            if previous_request is not None and previous_request[0] != encode(request):
                raise IdentityConflict("BARRIER_PAYLOAD_CONFLICT")
            self.store.bind_owner(db, approval, "barrier:" + request.barrier_id)
            db.execute("INSERT OR IGNORE INTO controls VALUES (?,?,?)",
                       (self.store.key(request.key), request.barrier_id, encode(request)))
            # One local serialization point fences admissions and dispatch claims
            # before the remote compare-and-set. Already claimed sends may race;
            # venue generation comparison determines their real outcome.
            self._save_account(db, account, pending_fence=request, source_state=None,
                               recovery=RecoveryState.RECONCILING,
                               armed_new_risk=False, armed_management=False)
            self.store.event(db, request.key, "CONTROL_REQUESTED", request)
        try:
            self.venue.advance_fence(request, now=now)
            snapshot = self.venue.snapshot(request.key, now=now)
            confirmed = snapshot.fence
            if (snapshot.key != request.key or not request.requested_at <= snapshot.observed_at <= now
                    or now - snapshot.observed_at >= timedelta(seconds=self.policy.observation_ttl_seconds)
                    or confirmed.barrier_id != request.barrier_id or confirmed.generation != request.next_generation
                    or not confirmed.applied or (confirmed.new_risk_allowed, confirmed.management_allowed) != desired):
                raise OutcomeUnknown("CONTROL_NOT_INDEPENDENTLY_CONFIRMED")
        except Exception as exc:
            if isinstance(exc, OutcomeUnknown):
                raise
            raise OutcomeUnknown("CONTROL_OUTCOME_UNKNOWN") from exc
        with self.store.transaction() as db:
            latest = self._account(db, request.key)
            if latest.pending_fence != request:
                raise OutcomeUnknown("CONTROL_SUPERSEDED")
            armed_new = request.control is ControlKind.RESUME_NEW_RISK or (
                request.control is ControlKind.RESUME_MANAGEMENT and account.armed_new_risk)
            armed_manage = request.control is ControlKind.RESUME_MANAGEMENT or (
                request.control in (ControlKind.PAUSE_NEW_RISK, ControlKind.RESUME_NEW_RISK) and account.armed_management)
            self._save_account(db, latest, snapshot=snapshot, pending_fence=None, safe_fence=True,
                               armed_new_risk=armed_new, armed_management=armed_manage)
            for record in self.store.commands(db, request.key):
                if not record.attempted and record.reservation_held:
                    self.store.save_command(db, _retire(record, "FENCED_BEFORE_SUBMISSION"))
            self.store.event(db, request.key, "CONTROL_CONFIRMED", confirmed)
        return confirmed

    def _snapshot_valid(self, snapshot: VenueSnapshot, previous: VenueSnapshot | None, now: datetime) -> None:
        if not isinstance(snapshot, VenueSnapshot) or snapshot.key != self.scope.key or snapshot.observed_at > now:
            raise EvidenceConflict("SNAPSHOT_SCOPE_OR_TIME")
        if previous is not None and (snapshot.sequence < previous.sequence or snapshot.fence.generation < previous.fence.generation):
            raise EvidenceConflict("VENUE_CURSOR_ROLLBACK")
        if now - snapshot.observed_at >= timedelta(seconds=self.policy.observation_ttl_seconds):
            raise AdmissionDenied("SNAPSHOT_STALE")
        if previous is not None:
            if snapshot.observed_at < previous.observed_at:
                raise EvidenceConflict("OBSERVATION_CLOCK_REGRESSION")
            if snapshot.fence.generation == previous.fence.generation and snapshot.fence != previous.fence:
                raise EvidenceConflict("FENCE_CHANGED_WITHOUT_GENERATION")
            if snapshot.sequence == previous.sequence and replace(previous, snapshot_id=snapshot.snapshot_id,
                                                                  observed_at=snapshot.observed_at) != snapshot:
                raise EvidenceConflict("SAME_CURSOR_DIFFERENT_SNAPSHOT")
        if not snapshot.fence.applied:
            raise EvidenceConflict("SNAPSHOT_FENCE_NOT_APPLIED")

    def reconcile(self, key: AccountRunKey, *, now: datetime) -> CockpitProjection:
        utc_time(now, "now")
        with self.store.transaction() as db:
            account = self._account(db, key)
            records = self.store.commands(db, key)
        try:
            first = self.venue.snapshot(key, now=now)
            self._snapshot_valid(first, account.snapshot, now)
            lookups = {x.command.command_id: self.venue.lookup(key, x.command.command_id)
                       for x in records if x.attempted}
            snapshot = self.venue.snapshot(key, now=now)
            self._snapshot_valid(snapshot, first, now)
            if any(x.key != key or x.command_id != command_id for command_id, x in lookups.items()):
                raise EvidenceConflict("LOOKUP_IDENTITY_MISMATCH")
            coherent = first.sequence == snapshot.sequence and all(
                x.state is not LookupState.UNKNOWN and x.observed_sequence == snapshot.sequence
                and (x.receipt is None or x.receipt.effect is not EffectState.UNKNOWN) for x in lookups.values())
            if first.sequence == snapshot.sequence and replace(first, snapshot_id=snapshot.snapshot_id,
                                                                observed_at=snapshot.observed_at) != snapshot:
                raise EvidenceConflict("SAME_CURSOR_DIFFERENT_SNAPSHOT")
            with self.store.transaction() as db:
                latest = self._account(db, key)
                if latest.revision != account.revision:
                    raise CoreError("CORE_CHANGED_DURING_RECONCILIATION")
                if not coherent:
                    latest = self._save_account(db, latest, source_state=None, recovery=RecoveryState.UNRESOLVED,
                                                armed_new_risk=False, armed_management=False)
                    return self._projection(latest, records, now)
                updated = []
                unresolved = False
                for record in records:
                    lookup = lookups.get(record.command.command_id)
                    if lookup is not None:
                        if lookup.state is LookupState.FOUND:
                            record = self._observe(db, record, lookup.receipt, now)
                            record = self._settle(record, snapshot)
                        elif record.receipt is not None:
                            raise EvidenceConflict("VENUE_RECEIPT_DISAPPEARED")
                        elif snapshot.fence.generation > record.command.dispatch_generation:
                            record = _retire(record, "ABSENT_AFTER_NEWER_FENCE")
                        else:
                            record = replace(record, state=CommandState.UNRESOLVED, reason_code="ABSENT_WITHOUT_NEWER_FENCE")
                    elif record.reservation_held and (record.command.writer_id != self.writer_id
                            or record.command.dispatch_generation != snapshot.fence.generation
                            or (record.command.intent.kind in RISK_CHANGING_ACTIONS
                                and (record.command.intent.source_state.version > 0
                                     or record.command.intent.source_state.venue_sequence > 0)
                                and record.command.intent.source_state.venue_sequence != snapshot.sequence)
                            or now >= record.command.intent.expires_at):
                        record = _retire(record, "UNSENT_STALE_COMMAND")
                    unresolved |= record.state in (CommandState.SUBMITTED, CommandState.UNRESOLVED)
                    self.store.save_command(db, record)
                    updated.append(record)
                known = {x.command.command_id for x in updated if x.attempted}
                if not set(snapshot.open_command_ids) <= known:
                    raise EvidenceConflict("UNOWNED_PENDING_VENUE_COMMAND")
                pending = latest.pending_fence
                safe = latest.safe_fence
                arm_new, arm_manage = latest.armed_new_risk, latest.armed_management
                if account.snapshot is None or snapshot.fence.generation != account.snapshot.fence.generation:
                    arm_new, arm_manage = False, False
                if pending is not None:
                    # Observation can resolve a control but never restore grants.
                    if (snapshot.fence.barrier_id == pending.barrier_id and snapshot.fence.generation == pending.next_generation
                            and account.snapshot is not None
                            and (snapshot.fence.new_risk_allowed, snapshot.fence.management_allowed)
                            == _expected_permissions(pending, account.snapshot.fence)):
                        safe = True
                        self.store.event(db, key, "CONTROL_RECOVERED_NO_GRANTS", snapshot.fence)
                        pending = None
                    elif snapshot.fence.generation >= pending.next_generation:
                        self.store.event(db, key, "CONTROL_SUPERSEDED", pending)
                        pending = None
                        safe = False
                    else:
                        unresolved = True
                    arm_new, arm_manage = False, False
                recovery = RecoveryState.UNRESOLVED if unresolved else RecoveryState.COHERENT
                # Quarantine is sticky within a session; a compatible reader and
                # explicit new session/fence are needed after conflicting truth.
                if latest.recovery is RecoveryState.QUARANTINED:
                    recovery = RecoveryState.QUARANTINED
                state = None
                if recovery is RecoveryState.COHERENT:
                    state = StateReference("state-" + content_digest((self.scope, snapshot.sequence, latest.revision + 1)),
                                           self.scope, latest.revision + 1, snapshot.observed_at,
                                           snapshot.observed_at + timedelta(seconds=self.policy.observation_ttl_seconds), snapshot.sequence)
                latest = self._save_account(db, latest, snapshot=snapshot, source_state=state, recovery=recovery,
                                            pending_fence=pending, safe_fence=safe,
                                            armed_new_risk=arm_new, armed_management=arm_manage)
                self.store.event(db, key, "RECONCILED", {"venue_sequence": snapshot.sequence, "state": state,
                                                       "recovery": recovery})
                return self._projection(latest, tuple(updated), now)
        except EvidenceConflict:
            self._quarantine(key, "RECONCILIATION_CONFLICT")
            raise
        except Exception:
            # Preserve the exception, previous truth, and all reservations. No
            # storage/transport error becomes an empty account or NOT_FOUND.
            with self.store.transaction() as db:
                latest = self._account(db, key)
                self._save_account(db, latest, source_state=None, recovery=RecoveryState.UNRESOLVED,
                                   armed_new_risk=False, armed_management=False)
            raise

    def _settle(self, record: CommandRecord, snapshot: VenueSnapshot) -> CommandRecord:
        receipt = record.receipt
        if receipt is None:
            return replace(record, state=CommandState.UNRESOLVED, reason_code="RECEIPT_UNAVAILABLE")
        q = receipt.quantities
        kind = record.command.intent.kind
        if kind in QUANTITY_ACTIONS:
            if q is None:
                return replace(record, state=CommandState.UNRESOLVED, reason_code="QUANTITY_UNOBSERVED")
            open_at_venue = record.command.command_id in snapshot.open_command_ids
            if (q.remaining > 0) != open_at_venue:
                raise EvidenceConflict("RECEIPT_SNAPSHOT_REMAINDER_MISMATCH")
            reserve = ZERO
            if kind in RISK_ACTIONS:
                spec = self.instruments.get(record.command.intent.instrument_id)
                if spec is None:
                    raise EvidenceConflict("PENDING_INSTRUMENT_POLICY_MISSING")
                with localcontext() as ctx:
                    ctx.prec = 80
                    reserve = upward(q.remaining * max(record.reservation_price, spec.reservation_price_ceiling), self.policy.currency_quantum)
            # Full coherent snapshot now includes filled exposure. Only remaining
            # quantity retains a reservation; cumulative fills are never added.
            return replace(record, reserved_notional=reserve,
                           target_remaining=q.remaining if kind in (ActionKind.CLOSE, ActionKind.REDUCE) else ZERO,
                           reservation_held=q.remaining > 0)
        if receipt.effect in (EffectState.APPLIED, EffectState.REJECTED):
            return replace(record, reserved_notional=ZERO, target_remaining=ZERO, reservation_held=False)
        return replace(record, state=CommandState.UNRESOLVED, reason_code="NON_QUANTITY_EFFECT_PENDING")

    def _projection(self, account: AccountRecord, records: tuple[CommandRecord, ...], now: datetime) -> CockpitProjection:
        snapshot = account.snapshot
        permissions = Permissions()
        if snapshot is not None and account.pending_fence is None and account.recovery is not RecoveryState.UNOBSERVED:
            permissions = Permissions(generation=snapshot.fence.generation)
        if (snapshot is not None and account.pending_fence is None and account.safe_fence
                and account.recovery is RecoveryState.COHERENT):
            fence = snapshot.fence
            permissions = Permissions(NewRiskPermission.ALLOWED if fence.new_risk_allowed else NewRiskPermission.PAUSED,
                                      ManagementPermission.ALLOWED if fence.management_allowed else ManagementPermission.STOPPED,
                                      fence.generation, fence.barrier_id)
        state = account.source_state
        enabled = bool(state and account.recovery is RecoveryState.COHERENT and account.safe_fence
                       and account.pending_fence is None and state.observed_at <= now < state.valid_until
                       and (account.armed_new_risk or account.armed_management))
        return CockpitProjection(scope=self.scope, recovery=account.recovery, permissions=permissions,
                                 observed_at=snapshot.observed_at if snapshot else None,
                                 state_id=state.state_id if state else None,
                                 balance=snapshot.balance if snapshot else None,
                                 equity=snapshot.equity if snapshot else None,
                                 realized_pnl=snapshot.realized_pnl if snapshot else None,
                                 open_pnl=snapshot.open_pnl if snapshot else None,
                                 positions=snapshot.positions if snapshot else None,
                                 commands=tuple(_view(x) for x in records),
                                 unresolved_command_ids=tuple(x.command.command_id for x in records
                                                              if x.state in (CommandState.SUBMITTED, CommandState.UNRESOLVED)),
                                 admissions_enabled=enabled)

    def inspect(self, key: AccountRunKey, *, now: datetime) -> CockpitProjection:
        """Local persisted observation only; does not poll or claim freshness."""
        utc_time(now, "now")
        with self.store.read() as db:
            return self._projection(self._account(db, key), self.store.commands(db, key), now)

    def reservations(self, key: AccountRunKey) -> tuple[CommandRecord, ...]:
        """Read-only core diagnostics for integration/replay, without grants."""
        with self.store.read() as db:
            self._account(db, key)
            return self.store.commands(db, key)

