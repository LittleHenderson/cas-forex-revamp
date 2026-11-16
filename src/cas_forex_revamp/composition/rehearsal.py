"""Explicit integration steps; constructing the wiring calls no dependency.

This module is source preparation. A caller still needs the separately approved
execution environment. No approval string or configuration flag grants it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Protocol

from ..contracts import (
    AccountRunKey, CockpitProjection, CommandView, ContractError, ControlKind,
    CorePort, DecisionOrigin, DecisionRequest, FenceReceipt, FenceRequest,
    MarketObservation, RunScope, StateReference, VenuePort, VenueSnapshot,
    assert_current_request, decimal_text,
)
from ..operator.decisions import DecisionProposal
from ..valve.tks_meta_valve_controller import PeakEquityStore
from .application import RuntimeConfig


class ProposalPort(Protocol):
    def tick(self, request: DecisionRequest) -> DecisionProposal: ...


class StateReader(Protocol):
    def current_state(self, key: AccountRunKey, *, now: datetime) -> StateReference: ...


@dataclass(frozen=True, slots=True)
class ControlObservation:
    requested: FenceRequest
    returned: FenceReceipt
    observed: FenceReceipt
    confirmed: bool


@dataclass(frozen=True, slots=True)
class ReconciledObservation:
    """Two explicit reads, retained separately without claiming atomicity."""

    venue: VenueSnapshot
    cockpit: CockpitProjection


def _request_has_accounting_override(request: DecisionRequest) -> bool:
    for f in request.facts:
        low_val = f.value.lower()
        if ("margin" in f.label.lower() or "equity" in f.label.lower() or f.fact_id.startswith("observed-")) and (
            "null" in low_val or "unavailable" in low_val
        ):
            return True
    return False


class RehearsalWiring:
    """No loop, initialization, model fallback, grants or recovery in __init__.

    Core owns all persistent admission/recovery. OperatorSession owns bounded
    inference and its before/after state checks. Venue owns independent effects.
    This wiring must not become another ledger or authority store.
    """

    def __init__(
        self, config: RuntimeConfig, *, core: CorePort, state_reader: StateReader,
        venue: VenuePort, operator: ProposalPort, clock: Callable[[], datetime],
        expected_origin: DecisionOrigin = DecisionOrigin.SCRIPTED,
        valve_gate: object | None = None,
    ) -> None:
        if not isinstance(config, RuntimeConfig):
            raise ContractError("explicit RuntimeConfig required")
        if expected_origin not in (DecisionOrigin.SCRIPTED, DecisionOrigin.ACTUAL_MODEL):
            raise ContractError("rehearsal A is SCRIPTED; required B is ACTUAL_MODEL")
        self.config = config
        self._core = core
        self._state_reader = state_reader
        self._venue = venue
        self._operator = operator
        self._clock = clock
        self.expected_origin = expected_origin
        self._valve_gate = valve_gate
        self._peak_equity_store = PeakEquityStore(config.state_directory / "rehearsal.drawdown.sqlite3")
        self.last_valve_decision = None

    @property
    def scope(self) -> RunScope:
        return self.config.scope

    def _scope_check(self, scope: RunScope) -> None:
        if scope != self.scope:
            raise ContractError("wrong account/run/epoch/build/policy/scenario/adapter")

    def _build_valve_view(self, proposal: DecisionProposal, now: datetime) -> dict[str, Any] | None:
        if _request_has_accounting_override(proposal.request):
            return None
        snap = self._venue.snapshot(self.scope.key, now=now)
        peak = self._peak_equity_store.observe_equity(
            f"{self.scope.account_id}:{self.scope.run_id}",
            current_equity=snap.equity.amount,
            opening_balance=snap.balance.amount,
            now=now,
        )
        return {
            "account_id": self.scope.account_id,
            "balance": decimal_text(snap.balance.amount),
            "equity": decimal_text(snap.equity.amount),
            "peak_equity": decimal_text(peak),
            "available_margin": decimal_text(snap.equity.amount),
            "position_inventory": [p.position_id for p in snap.positions],
        }

    def propose(self, request: DecisionRequest) -> DecisionProposal:
        """One explicit operator call. It never admits or dispatches an action."""
        self._scope_check(request.state.scope)
        now = self._clock()
        current = self._state_reader.current_state(self.scope.key, now=now)
        assert_current_request(request, current, now)
        proposal = self._operator.tick(request)
        if not isinstance(proposal, DecisionProposal) or proposal.request != request:
            raise ContractError("operator must retain the exact supplied request")
        if proposal.result.provenance.origin is not self.expected_origin:
            raise ContractError("decision origin does not match this A/B branch")
        return proposal

    def admit(self, proposal: DecisionProposal, *, command_id: str) -> CommandView | None:
        """Recheck current state after any delay; explicit WAIT admits nothing."""
        if not isinstance(proposal, DecisionProposal):
            raise ContractError("a typed immutable proposal is required")
        self._scope_check(proposal.request.state.scope)
        if proposal.result.provenance.origin is not self.expected_origin:
            raise ContractError("decision origin does not match this A/B branch")
        now = self._clock()
        current = self._state_reader.current_state(self.scope.key, now=now)
        assert_current_request(proposal.request, current, now)
        if proposal.intent is None:
            return None
        if self._valve_gate is not None:
            view = self._build_valve_view(proposal, now)
            self.last_valve_decision = self._valve_gate.require_admissible(proposal, current_view=view, now=now)
        # Core repeats freshness and all authority/risk/target checks atomically.
        return self._core.admit(proposal.intent, command_id=command_id, now=now)

    def dispatch_once(self) -> CommandView | None:
        """One durable outbox step. Exceptions propagate; there is no retry loop."""
        return self._core.dispatch_next(self.scope.key, now=self._clock())

    def observe(self) -> CockpitProjection:
        """Explicit reconciliation does not restore a grant."""
        projection = self._core.reconcile(self.scope.key, now=self._clock())
        self._scope_check(projection.scope)
        return projection

    def independent_read(self) -> ReconciledObservation:
        """Read independent venue truth and reconcile, without assuming atomicity.

        Values are retained separately. A concurrent venue change can produce
        different cursors; downstream evidence must not label them one snapshot.
        """
        snapshot = self._venue.snapshot(self.scope.key, now=self._clock())
        if snapshot.key != self.scope.key:
            raise ContractError("independent snapshot belongs to another run")
        return ReconciledObservation(snapshot, self.observe())

    def advance_market(self, observation: MarketObservation) -> CockpitProjection:
        """One declared synthetic observation, then explicit reconciliation."""
        if observation.key != self.scope.key:
            raise ContractError("market observation belongs to another run")
        self._venue.advance_market(observation)
        snap = self._venue.snapshot(self.scope.key, now=self._clock())
        self._peak_equity_store.observe_equity(
            f"{self.scope.account_id}:{self.scope.run_id}",
            current_equity=snap.equity.amount,
            opening_balance=snap.balance.amount,
            now=self._clock(),
        )
        return self.observe()

    def control(self, request: FenceRequest) -> ControlObservation:
        """Core verifies owner authority; an independent read confirms the result.

        No transport failure is caught and converted into success. A newer or
        mismatched barrier is unconfirmed for this particular request.
        """
        if request.key != self.scope.key:
            raise ContractError("control belongs to another run")
        returned = self._core.control(request, now=self._clock())
        observed = self._venue.snapshot(self.scope.key, now=self._clock()).fence
        confirmed = (
            returned.key == observed.key == request.key
            and returned.barrier_id == observed.barrier_id == request.barrier_id
            and returned.generation == observed.generation == request.next_generation
            and returned.applied and observed.applied
            and returned.new_risk_allowed == observed.new_risk_allowed
            and returned.management_allowed == observed.management_allowed
        )
        if request.control is ControlKind.PAUSE_NEW_RISK:
            confirmed = confirmed and not observed.new_risk_allowed
        elif request.control is ControlKind.STOP_AUTOMATION:
            confirmed = confirmed and not observed.new_risk_allowed and not observed.management_allowed
        elif request.control is ControlKind.RESUME_NEW_RISK:
            confirmed = confirmed and observed.new_risk_allowed
        elif request.control is ControlKind.RESUME_MANAGEMENT:
            confirmed = confirmed and observed.management_allowed
        return ControlObservation(request, returned, observed, confirmed)
