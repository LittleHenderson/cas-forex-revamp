"""Venue-owned deterministic execution fixtures; they carry no execution authority."""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal

from cas_forex_revamp.contracts import ContractError, EffectState
from cas_forex_revamp.contracts.primitives import decimal_value, identifier


@dataclass(frozen=True, slots=True)
class OrderPlan:
    # One quota per eligible market event. Zero deliberately leaves the order pending.
    fill_quantities: tuple[Decimal, ...] = ()
    terminal: EffectState | None = None
    reject_on_accept: bool = False

    def __post_init__(self) -> None:
        if type(self.fill_quantities) is not tuple:
            raise ContractError("fill quotas must be an immutable tuple")
        for value in self.fill_quantities:
            if decimal_value(value, "fill quota") < 0:
                raise ContractError("fill quotas must be nonnegative")
        if self.terminal is not None and (not isinstance(self.terminal, EffectState)
                or self.terminal not in (EffectState.CANCELLED, EffectState.REJECTED)):
            raise ContractError("terminal plan must cancel or reject the remaining quantity")
        if type(self.reject_on_accept) is not bool:
            raise ContractError("reject_on_accept requires a boolean")


@dataclass(frozen=True, slots=True)
class VenueScenario:
    scenario_id: str = "deterministic-default"
    # Tuple pairs are immutable, serializable and ordered. Missing plans fill in full.
    order_plans: tuple[tuple[str, OrderPlan], ...] = ()
    fill_limit_per_order: Decimal | None = None
    money_quantum: Decimal = Decimal("0.01")

    def __post_init__(self) -> None:
        identifier(self.scenario_id, "scenario_id")
        if type(self.order_plans) is not tuple:
            raise ContractError("order_plans must be immutable")
        seen: set[str] = set()
        for entry in self.order_plans:
            if type(entry) is not tuple or len(entry) != 2:
                raise ContractError("order plan entries must be (command_id, OrderPlan)")
            command_id, plan = entry
            identifier(command_id, "command_id")
            if command_id in seen or not isinstance(plan, OrderPlan):
                raise ContractError("duplicate or malformed order plan")
            seen.add(command_id)
        if self.fill_limit_per_order is not None:
            decimal_value(self.fill_limit_per_order, "fill limit", positive=True)
        quantum = decimal_value(self.money_quantum, "money quantum", positive=True)
        if quantum not in (Decimal("1"), Decimal("0.1"), Decimal("0.01"),
                           Decimal("0.001"), Decimal("0.0001")):
            raise ContractError("money quantum must be a supported currency decimal unit")

