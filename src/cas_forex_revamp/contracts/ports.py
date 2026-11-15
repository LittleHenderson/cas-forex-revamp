"""Dependency directions only. Protocols do not instantiate workers or IO."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from .commands import ActionIntent, AuthorizedCommand, CommandView, FenceReceipt, FenceRequest, VenueReceipt
from .decisions import AtlasContent, DecisionRequest, DecisionResult
from .primitives import AccountRunKey
from .views import CockpitProjection, MarketObservation, VenueLookup, VenueSnapshot


class VenuePort(Protocol):
    def accept(self, command: AuthorizedCommand, *, now: datetime) -> VenueReceipt:
        """Atomically check digest, identity, generation, action permission and effect."""
        ...

    def advance_fence(self, request: FenceRequest, *, now: datetime) -> FenceReceipt:
        """Durable compare-and-set barrier. A requested barrier is not a confirmation."""
        ...

    def lookup(self, key: AccountRunKey, command_id: str) -> VenueLookup:
        """Read independent journal; do not turn failure into NOT_FOUND."""
        ...

    def snapshot(self, key: AccountRunKey, *, now: datetime) -> VenueSnapshot:
        """Coherent venue-owned account/positions/cursor; fail if unavailable."""
        ...

    def advance_market(self, observation: MarketObservation) -> VenueSnapshot:
        """Explicit synthetic scenario step; never starts a market feed or timer."""
        ...


class CorePort(Protocol):
    def admit(self, intent: ActionIntent, *, command_id: str, now: datetime) -> CommandView:
        """One transaction claims immutable identity, target and aggregate reservation."""
        ...

    def control(self, request: FenceRequest, *, now: datetime) -> FenceReceipt:
        """Serialize admissions with the venue fence; no close hidden inside Stop."""
        ...

    def dispatch_next(self, key: AccountRunKey, *, now: datetime) -> CommandView | None:
        """One bounded outbox step; no implicit loop, resend or grant restoration."""
        ...

    def reconcile(self, key: AccountRunKey, *, now: datetime) -> CockpitProjection:
        """Automatic observation may proceed; new authority never restores implicitly."""
        ...


class DecisionAdapter(Protocol):
    def decide(self, request: DecisionRequest) -> DecisionResult:
        """Scripted/replay/model identity is explicit. No fallback or dispatch port."""
        ...


class AtlasProjector(Protocol):
    def project(self, request: DecisionRequest) -> AtlasContent:
        """Pure bounded organization; no authority, model call or second truth store."""
        ...
