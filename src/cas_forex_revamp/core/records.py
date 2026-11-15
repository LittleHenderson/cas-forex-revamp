"""Core-private durable records; shared messages remain steward-owned."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Protocol

from cas_forex_revamp.contracts import (
    AccountRunKey, ActionIntent, AuthorizedCommand, CommandState, FenceRequest, RecoveryState,
    RunScope, StateReference, VenueReceipt, VenueSnapshot, content_digest,
)
from cas_forex_revamp.contracts.primitives import decimal_value, digest, identifier, integer, utc_time


class CoreError(RuntimeError):
    """Fail-closed core error. Never implies a venue outcome."""


class IdentityConflict(CoreError):
    pass


class AdmissionDenied(CoreError):
    pass


class EvidenceConflict(CoreError):
    pass


class OutcomeUnknown(CoreError):
    pass


class StaleWriter(CoreError):
    pass


@dataclass(frozen=True, slots=True)
class CoreCheckpoint:
    """Optional high-water mark held OUTSIDE the database being restored.

    Self-consistency is not independent anchoring. The caller must obtain this
    from its trusted run manifest/observer; never infer it from a restored file.
    """
    key: AccountRunKey
    event_sequence: int
    event_sha256: str
    venue_sequence: int

    def __post_init__(self):
        from cas_forex_revamp.contracts.primitives import integer
        if not isinstance(self.key, AccountRunKey):
            raise ValueError("checkpoint requires stable key")
        integer(self.event_sequence, "event sequence", minimum=1)
        integer(self.venue_sequence, "venue sequence")
        digest(self.event_sha256)


@dataclass(frozen=True, slots=True)
class OwnerApproval:
    """Returned only by a trusted, separately authenticated owner boundary.

    This is an in-process verifier result, not a bearer token or model input.
    No default verifier grants authority and no credential is persisted here.
    """

    request_id: str
    scope: RunScope
    subject_sha256: str
    approved_at: datetime
    expires_at: datetime
    command_id: str | None = None

    def __post_init__(self) -> None:
        identifier(self.request_id, "owner request ID")
        if not isinstance(self.scope, RunScope):
            raise ValueError("owner approval requires typed scope")
        if self.command_id is not None:
            identifier(self.command_id, "reviewed command ID")
        digest(self.subject_sha256)
        utc_time(self.approved_at, "approved_at")
        utc_time(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("owner approval requires a positive lifetime")

    def check(self, subject: ActionIntent | FenceRequest, scope: RunScope, now: datetime,
              *, command_id: str | None = None) -> None:
        if self.scope != scope or self.subject_sha256 != content_digest(subject):
            raise AdmissionDenied("OWNER_SUBJECT_MISMATCH")
        if not self.approved_at <= now < self.expires_at:
            raise AdmissionDenied("OWNER_APPROVAL_EXPIRED")
        if isinstance(subject, FenceRequest) and self.request_id != subject.owner_request_id:
            raise AdmissionDenied("OWNER_REQUEST_MISMATCH")
        if isinstance(subject, ActionIntent) and (command_id is None or self.command_id != command_id):
            raise AdmissionDenied("OWNER_COMMAND_MISMATCH")
        if isinstance(subject, FenceRequest) and self.command_id is not None:
            raise AdmissionDenied("CONTROL_APPROVAL_HAS_COMMAND")


class OwnerVerifier(Protocol):
    def verify(self, subject: ActionIntent | FenceRequest, *, now: datetime) -> OwnerApproval:
        """Verify an authenticated, exact owner review; otherwise raise."""
        ...


@dataclass(frozen=True, slots=True)
class AccountRecord:
    scope: RunScope
    writer_id: str
    revision: int = 0
    snapshot: VenueSnapshot | None = None
    source_state: StateReference | None = None
    recovery: RecoveryState = RecoveryState.UNOBSERVED
    armed_new_risk: bool = False
    armed_management: bool = False
    safe_fence: bool = False
    pending_fence: FenceRequest | None = None

    def __post_init__(self):
        identifier(self.writer_id, "writer_id")
        integer(self.revision, "core revision")
        if self.source_state is not None and self.source_state.scope != self.scope:
            raise CoreError("SOURCE_SCOPE_MISMATCH")
        if self.snapshot is not None and self.snapshot.key != self.scope.key:
            raise CoreError("SNAPSHOT_KEY_MISMATCH")
        if self.pending_fence is not None and self.pending_fence.key != self.scope.key:
            raise CoreError("PENDING_CONTROL_KEY_MISMATCH")
        if (not self.safe_fence or self.pending_fence is not None) and (self.armed_new_risk or self.armed_management):
            raise CoreError("LOCAL_GRANT_WITHOUT_SAFE_FENCE")


@dataclass(frozen=True, slots=True)
class CommandRecord:
    command: AuthorizedCommand
    state: CommandState
    reserved_notional: Decimal
    target_remaining: Decimal
    reservation_price: Decimal = Decimal("0")
    reservation_held: bool = True
    attempted: bool = False
    receipt: VenueReceipt | None = None
    reason_code: str | None = None

    def __post_init__(self):
        for name in ("reserved_notional", "target_remaining", "reservation_price"):
            if decimal_value(getattr(self, name), name) < 0:
                raise CoreError("NEGATIVE_RESERVATION")
        if not self.reservation_held and (self.reserved_notional or self.target_remaining):
            raise CoreError("RELEASED_RESERVATION_HAS_CAPACITY")
        if self.receipt is not None:
            if (not self.attempted or self.receipt.key != self.command.intent.scope.key
                    or self.receipt.command_id != self.command.command_id
                    or self.receipt.payload_sha256 != self.command.payload_sha256):
                raise CoreError("DURABLE_RECEIPT_BINDING_MISMATCH")
        if self.state is CommandState.QUEUED and self.attempted:
            raise CoreError("ATTEMPTED_COMMAND_CANNOT_BE_QUEUED")
        if self.reason_code is not None:
            identifier(self.reason_code, "reason_code")


@dataclass(frozen=True, slots=True)
class CoreEvent:
    sequence: int
    key: AccountRunKey
    kind: str
    payload_json: str
    previous_sha256: str
    event_sha256: str


@dataclass(frozen=True, slots=True)
class CoreReadSnapshot:
    """One core DB read, not a simultaneous read of the independent venue.

    event_sha256 binds the complete ordered event prefix through event_sequence.
    A hash without an independently held anchor is self-consistency only.
    """
    account: AccountRecord
    commands: tuple[CommandRecord, ...]
    events: tuple[CoreEvent, ...]
    event_sequence: int
    event_sha256: str
    schema_version: str = "core.read/1"

