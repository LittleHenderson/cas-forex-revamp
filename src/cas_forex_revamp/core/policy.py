"""Conservative gross-notional capacity, not a promised market-loss ceiling."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING, localcontext

from cas_forex_revamp.contracts import ActionIntent, Instrument, VenueSnapshot
from cas_forex_revamp.contracts.primitives import decimal_value
from .records import AdmissionDenied


def upward(value: Decimal, quantum: Decimal) -> Decimal:
    """Round costs up to a currency quantum without ambient precision effects."""
    with localcontext() as ctx:
        ctx.prec = 80
        result = (value / quantum).to_integral_value(rounding=ROUND_CEILING) * quantum
        return decimal_value(result, "rounded notional")


@dataclass(frozen=True, slots=True)
class RiskPolicy:
    account_currency: str
    maximum_gross_notional: Decimal
    currency_quantum: Decimal = Decimal("0.01")
    observation_ttl_seconds: int = 30

    def __post_init__(self):
        from cas_forex_revamp.contracts import Money
        Money(self.maximum_gross_notional, self.account_currency)
        decimal_value(self.maximum_gross_notional, "maximum gross notional", positive=True)
        decimal_value(self.currency_quantum, "currency quantum", positive=True)
        if type(self.observation_ttl_seconds) is not int or not 1 <= self.observation_ttl_seconds <= 300:
            raise ValueError("observation TTL must be 1..300 seconds")


@dataclass(frozen=True, slots=True)
class InstrumentPolicy:
    instrument: Instrument
    reservation_price_ceiling: Decimal

    def __post_init__(self):
        decimal_value(self.reservation_price_ceiling, "reservation price ceiling", positive=True)
        with localcontext() as ctx:
            ctx.prec = 80
            if self.reservation_price_ceiling % self.instrument.price_tick:
                raise ValueError("reservation ceiling must align with instrument tick")

    def notional(self, quantity: Decimal, policy: RiskPolicy) -> Decimal:
        with localcontext() as ctx:
            ctx.prec = 80
            return upward(quantity * self.reservation_price_ceiling, policy.currency_quantum)

    def validate_geometry(self, intent: ActionIntent) -> None:
        instrument = self.instrument
        with localcontext() as ctx:
            ctx.prec = 80
            if intent.quantity is not None and (
                intent.quantity < instrument.minimum_quantity or intent.quantity % instrument.quantity_step
            ):
                raise AdmissionDenied("QUANTITY_STEP_OR_MINIMUM")
            for price in (intent.limit_price, intent.stop_price):
                if price is not None and price % instrument.price_tick:
                    raise AdmissionDenied("PRICE_TICK")


def exposure(snapshot: VenueSnapshot, policies: dict[str, InstrumentPolicy], policy: RiskPolicy) -> Decimal:
    if snapshot.equity.currency != policy.account_currency:
        raise AdmissionDenied("ACCOUNT_CURRENCY_MISMATCH")
    with localcontext() as ctx:
        ctx.prec = 80
        amount = Decimal(0)
        for position in snapshot.positions:
            spec = policies.get(position.instrument_id)
            if spec is None or spec.instrument.quote_currency != policy.account_currency:
                raise AdmissionDenied("UNPRICED_POSITION")
            quotes = [m.ask for m in snapshot.market if m.instrument_id == position.instrument_id]
            price = max(position.entry_price, spec.reservation_price_ceiling, *quotes)
            amount += upward(position.quantity * price, policy.currency_quantum)
        return decimal_value(amount, "observed gross exposure")

