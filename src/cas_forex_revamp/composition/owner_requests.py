"""Explicit in-process owner boundary. Client JSON never supplies approval."""

from __future__ import annotations

from datetime import datetime, timedelta

from ..contracts import ActionIntent, ActionKind, ContractError, ControlKind, FenceRequest, RunScope, content_digest
from ..core import OwnerApproval


class OwnerRequestBook:
    """Injected by trusted bootstrap; empty on every process/session restart.

    register() is called by an authenticated transport boundary after an explicit
    click/review, or by the clearly labeled finite synthetic test owner. It must
    never be exposed as a public JSON method or populated from imported history.
    """

    def __init__(self, scope: RunScope, *, controls: frozenset[ControlKind] = frozenset(),
                 reviewed_close: bool = False) -> None:
        if not isinstance(scope, RunScope) or type(controls) is not frozenset:
            raise ContractError("typed immutable owner scope/capabilities required")
        if any(not isinstance(x, ControlKind) for x in controls) or type(reviewed_close) is not bool:
            raise ContractError("invalid owner capability")
        self.scope = scope
        self.controls = controls
        self.reviewed_close = reviewed_close
        self._requests: dict[str, OwnerApproval] = {}

    def register(self, subject: FenceRequest | ActionIntent, *, request_id: str,
                 now: datetime, command_id: str | None = None) -> OwnerApproval:
        if isinstance(subject, FenceRequest):
            if subject.key != self.scope.key or subject.control not in self.controls:
                raise ContractError("owner control capability unavailable")
            if request_id != subject.owner_request_id or command_id is not None:
                raise ContractError("control request binding mismatch")
            expires = now + timedelta(seconds=30)
        elif isinstance(subject, ActionIntent):
            if (not self.reviewed_close or subject.kind is not ActionKind.CLOSE
                    or subject.scope != self.scope or command_id is None):
                raise ContractError("owner exact-Close capability unavailable")
            expires = min(subject.expires_at, now + timedelta(seconds=30))
        else:
            raise ContractError("unsupported owner subject")
        approval = OwnerApproval(request_id, self.scope, content_digest(subject), now, expires, command_id)
        old = self._requests.get(request_id)
        if old is not None:
            if (old.subject_sha256, old.command_id, old.scope) != (
                approval.subject_sha256, approval.command_id, approval.scope
            ):
                raise ContractError("owner request identity conflict")
            old.check(subject, self.scope, now, command_id=command_id)
            return old
        self._requests[request_id] = approval
        return approval

    def verify(self, subject: FenceRequest | ActionIntent, *, now: datetime) -> OwnerApproval:
        expected = content_digest(subject)
        matches = [a for a in self._requests.values() if a.subject_sha256 == expected
                   and a.scope == self.scope and a.approved_at <= now < a.expires_at]
        if len(matches) != 1:
            raise ContractError("no unique current explicit owner approval")
        return matches[0]
