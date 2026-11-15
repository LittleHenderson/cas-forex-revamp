"""Deliberate transport/process failures for disconnected rehearsal only."""
from __future__ import annotations


class SimulatedInterruption(RuntimeError):
    """The caller must reconcile; this exception never proves absence of an effect."""

    def __init__(self, point: str):
        self.point = point
        super().__init__(f"deliberate venue interruption at {point}")


class FaultSchedule:
    """One-shot failpoints; no monkeypatched storage or optimistic success receipts.

    Points are <operation>.before_commit / <operation>.after_commit, plus
    lookup.unavailable. Operations: initialize, accept, advance_fence, advance_market.
    A process-kill test can subclass hit() to exit at the same real commit boundary.
    This schedule is process-local; committed venue truth is independently durable.
    """

    def __init__(self) -> None:
        self._remaining: dict[str, int] = {}

    def arm(self, point: str, *, occurrence: int = 1) -> None:
        valid = {f"{op}.{phase}" for op in (
            "initialize", "accept", "advance_fence", "advance_market"
        ) for phase in ("before_commit", "after_commit")} | {"lookup.unavailable"}
        if point not in valid or type(occurrence) is not int or occurrence < 1:
            raise ValueError("invalid venue failpoint or occurrence")
        self._remaining[point] = occurrence

    def hit(self, point: str) -> None:
        count = self._remaining.get(point)
        if count is None:
            return
        if count == 1:
            del self._remaining[point]
            raise SimulatedInterruption(point)
        self._remaining[point] = count - 1
