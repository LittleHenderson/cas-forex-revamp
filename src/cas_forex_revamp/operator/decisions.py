"""Explicit proposal checks and bounded management sessions, with no core access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from cas_forex_revamp.contracts import (
    ActionIntent, ContractError, DecisionAdapter, DecisionOrigin, DecisionRequest,
    DecisionResult, DecisionSelection, StateReference, assert_current_request,
    bind_selection, content_digest,
)
from cas_forex_revamp.contracts.primitives import integer, utc_time


class OperatorUnavailable(ContractError):
    """A decision cannot be produced; this is not a WAIT selection."""


class StaleDecision(ContractError):
    """An old decision remains reviewable but cannot become a current proposal."""


def decision_identity(request: DecisionRequest) -> str:
    """Use the identity already frozen into supplied intents; never rewrite one."""
    identities = {option.intent.decision_id for option in request.options}
    if len(identities) > 1:
        raise ContractError("all options in a decision must share one preassigned decision_id")
    return next(iter(identities)) if identities else "wait-" + content_digest(request)


def check_request_time(request: DecisionRequest, now: datetime) -> None:
    assert_current_request(request, request.state, now)
    if any(item.observed_at > now for item in request.evidence):
        raise ContractError("request contains future evidence")


def check_result(request: DecisionRequest, result: DecisionResult) -> None:
    """Shape/identity checks only; source authenticity is a separate boundary."""
    if not isinstance(result, DecisionResult):
        raise ContractError("adapter must return a typed DecisionResult")
    bind_selection(result.selection, request)
    if result.decision_id != decision_identity(request):
        raise ContractError("decision identity differs from supplied immutable intents")
    if result.provenance.request_sha256 != content_digest(request):
        raise ContractError("decision provenance must bind the canonical DecisionRequest")
    if result.provenance.started_at < request.state.observed_at:
        raise ContractError("decision precedes its source observation")


@dataclass(frozen=True, slots=True)
class DecisionProposal:
    """A checked exact supplied intent or explicit WAIT, never authorization."""

    request: DecisionRequest
    result: DecisionResult
    intent: ActionIntent | None

    def __post_init__(self) -> None:
        check_result(self.request, self.result)
        selected = self.result.selection.selected_action_ref
        expected = next((x.intent for x in self.request.options if x.action_ref == selected), None)
        if self.intent != expected:
            raise ContractError("proposal must retain the exact supplied intent")


def prepare_proposal(
    request: DecisionRequest, result: DecisionResult, *, current: StateReference, now: datetime,
) -> DecisionProposal:
    """Core must repeat freshness/permission/target checks inside its transaction."""
    check_result(request, result)
    try:
        assert_current_request(request, current, now)
    except ContractError as exc:
        raise StaleDecision(str(exc)) from exc
    if result.provenance.completed_at > now:
        raise ContractError("decision completion is in the future")
    if result.provenance.origin is DecisionOrigin.REPLAY:
        raise ContractError("archived replay is review-only and cannot create a proposal")
    selected = result.selection.selected_action_ref
    intent = next((x.intent for x in request.options if x.action_ref == selected), None)
    if intent is not None:
        if intent.origin is not result.provenance.origin:
            raise ContractError("supplied intent origin differs from the actual decision origin")
        if not intent.created_at <= now < intent.expires_at:
            raise StaleDecision("selected intent has expired or is not yet current")
    return DecisionProposal(request, result, intent)


@dataclass(frozen=True, slots=True)
class DecisionAttempt:
    """Retains a completed response even when a later state check rejects it."""

    request: DecisionRequest
    result: DecisionResult
    proposal: DecisionProposal | None
    rejection: str | None


@dataclass(frozen=True, slots=True)
class DecisionFailure:
    request_id: str
    request_sha256: str
    error_type: str


class OperatorSession:
    """One explicit bounded tick at a time; no loop, thread, database or dispatch.

    The caller supplies a fresh entry or management opportunity set on each tick.
    A continuous rehearsal scheduler may call tick repeatedly after independently
    advancing/reconciling the simulator. Constructors never call dependencies.
    """

    def __init__(self, adapter: DecisionAdapter, *, current_state: Callable[[], StateReference],
                 clock: Callable[[], datetime], max_decisions: int = 256) -> None:
        integer(max_decisions, "max_decisions", minimum=1)
        self._adapter = adapter
        self._current_state = current_state
        self._clock = clock
        self._max_decisions = max_decisions
        self._attempts: list[DecisionAttempt] = []
        self._failures: list[DecisionFailure] = []
        self._scope = None
        self._request_ids: set[str] = set()

    @property
    def attempts(self) -> tuple[DecisionAttempt, ...]:
        return tuple(self._attempts)

    @property
    def failures(self) -> tuple[DecisionFailure, ...]:
        return tuple(self._failures)

    def tick(self, request: DecisionRequest) -> DecisionProposal:
        if len(self._request_ids) >= self._max_decisions:
            raise OperatorUnavailable("bounded session exhausted; do not discard review history")
        if request.request_id in self._request_ids:
            raise ContractError("a session cannot silently retry a request identity")
        if self._scope is not None and request.state.scope != self._scope:
            raise ContractError("new scope/epoch/build requires a new explicit operator session")
        assert_current_request(request, self._current_state(), self._clock())
        self._scope = request.state.scope
        self._request_ids.add(request.request_id)  # Failure is not permission to retry inference.
        try:
            result = self._adapter.decide(request)
            check_result(request, result)
        except Exception as exc:
            self._failures.append(DecisionFailure(request.request_id, content_digest(request), type(exc).__name__))
            raise
        try:
            proposal = prepare_proposal(request, result, current=self._current_state(), now=self._clock())
        except Exception as exc:
            self._attempts.append(DecisionAttempt(request, result, None, type(exc).__name__))
            raise
        self._attempts.append(DecisionAttempt(request, result, proposal, None))
        return proposal