"""Dual-Shield Barbell broker routing for CAS Forex Revamp (Phase 6 owner architecture).

Owner instruction (2026-11-16): "TAKE ADVANTAGE OF THE HIGHER LEVERAGES HUGOSWAY AND LHFX PROVIDE
BUT ALSO THE SAFETY OANDA PROVIDES AS WELL TO OFFSET ANY RISK HUGOSWAY AND LHFX MAY CARRY."

Four layers, all demo/practice-only and all behind ForexMetaValveGate
(``tks_meta_valve_controller``, 161 parameters, threshold 0.55):

1. :class:`OandaQuoteTruthOracle` -- regulated price-integrity / anti-stop-hunt shield. Every
   offshore ``HUGOSWAY_MT5`` / ``LHFX_MT5`` (1:500) quote is cross-checked against OANDA's
   regulated practice pricing (or a verified Kraken/ECB reference when OANDA is uncredentialed)
   before admission. Off-market quotes raise :class:`OffMarketBrokerQuoteError`.
2. :class:`BarbellCapitalPolicy` -- 80% regulated OANDA reserve + 20% high-leverage MT5 sleeve
   (Hugo's Way 12%, LHFX 8%), plus a hard cap on stop-loss risk (1.00% of total equity).
3. :class:`DualShieldBrokerRouter` + :class:`OandaProtectiveOffsetPlanner` -- Hugo's Way first,
   LHFX second, automatic safe-harbor degradation to ``OANDA_PRACTICE`` (1:50) whenever an
   offshore venue fails the quote-truth shield, exceeds its sleeve, or is disconnected; and exact
   delta-neutral OANDA offset plans if an open MT5 position becomes unreachable.
4. ``routing_snapshot()`` surfaces all four pillars for ``GET /api/broker-routing`` and the
   ``03 Setup`` cockpit card.

Importing this module and constructing every class in it is strictly inert (no network, disk,
thread, or subprocess side effects). An order whose outcome is unknown is never re-routed.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
import logging
from typing import Any

from cas_forex_revamp.contracts import ActionKind, ContractError, Side, decimal_text, parse_decimal
from cas_forex_revamp.contracts.primitives import decimal_value
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
    ValveDecision,
    compute_drawdown_pct,
)
from .external_paper_broker import EXECUTION_MODE_LIVE, EXPANDED_FX_PAIRS, OandaPracticePaperClient, assert_safe_json_numbers
from .mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_LIVE,
    BROKER_OANDA_PRACTICE,
    BROKER_SPECS,
    BrokerFailoverExhaustedError,
    BrokerHierarchyRouter,
    LiveBrokerEndpointForbiddenError,
    Mt5AccountSnapshot,
    Mt5BridgeError,
    Mt5ExecutionResult,
    Mt5MarginCalculator,
    Mt5MarginCheck,
    Mt5MarginRefusalError,
    Mt5OutcomeUnknownError,
    Mt5PaperBrokerVenue,
    Mt5Position,
    Mt5Tick,
    Mt5TransportError,
    OandaPracticeFallbackVenue,
    OrderIntent,
    require_valve_clearance,
)

__all__ = [
    "BarbellCapitalPolicy",
    "BarbellPolicyRefusalError",
    "DualShieldBrokerRouter",
    "ENV_BARBELL_MAX_DRAWDOWN_PCT",
    "DualShieldExecution",
    "MAJOR_FX_PAIRS",
    "OandaProtectiveOffsetPlanner",
    "OandaQuoteTruthOracle",
    "OffMarketBrokerQuoteError",
    "OffsetOrder",
    "OffsetPlan",
    "QuoteReferenceUnavailableError",
    "QuoteTruthVerdict",
]

logger = logging.getLogger(__name__)

ENV_BARBELL_OANDA_RESERVE_SHARE = "CAS_FOREX_BARBELL_OANDA_RESERVE_SHARE"
ENV_BARBELL_HUGOSWAY_SHARE = "CAS_FOREX_BARBELL_HUGOSWAY_SHARE"
ENV_BARBELL_LHFX_SHARE = "CAS_FOREX_BARBELL_LHFX_SHARE"
ENV_BARBELL_MAX_STOP_RISK_PCT = "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT"
ENV_BARBELL_MAX_DRAWDOWN_PCT = "CAS_FOREX_MAX_DRAWDOWN_PCT"

OANDA_SAFE_HARBOR_LEVERAGE = 50
MAJOR_FX_PAIRS: tuple[str, ...] = tuple(p for p in EXPANDED_FX_PAIRS if "USD" in p)
_MAX_TRAIL = 32


class OffMarketBrokerQuoteError(Mt5BridgeError):
    """Offshore MT5 quote diverges from the regulated reference or its spread is abnormal."""

    def __init__(self, message: str, verdict: "QuoteTruthVerdict | None" = None) -> None:
        super().__init__(message)
        self.verdict = verdict


class QuoteReferenceUnavailableError(OffMarketBrokerQuoteError):
    """No regulated reference quote is available; offshore admission fails closed."""


class BarbellPolicyRefusalError(Mt5BridgeError):
    """A trade would breach the barbell reserve/sleeve allocation or the stop-loss equity-risk cap."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _bps(numerator: Decimal, denominator: Decimal) -> Decimal:
    with localcontext() as ctx:
        ctx.prec = 40
        return (numerator / denominator * Decimal(10_000)).quantize(Decimal("0.0001"))


def _price_tick(symbol: str) -> Decimal:
    return Decimal("0.001") if symbol.endswith("JPY") else Decimal("0.00001")


def _validated_quote(symbol: str, bid: Any, ask: Any, label: str) -> tuple[Decimal, Decimal]:
    decimal_value(bid, f"{label} {symbol} bid", positive=True)
    decimal_value(ask, f"{label} {symbol} ask", positive=True)
    if ask <= bid:
        raise OffMarketBrokerQuoteError(f"{label} {symbol} quote must satisfy bid < ask")
    return bid, ask


# ---------------------------------------------------------------------------
# Layer 1 -- OANDA quote-truth oracle
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuoteTruthVerdict:
    broker_id: str
    symbol: str
    reference_source: str
    bid: Decimal
    ask: Decimal
    mid: Decimal
    spread_bps: Decimal
    reference_bid: Decimal
    reference_ask: Decimal
    reference_mid: Decimal
    reference_spread_bps: Decimal
    divergence_bps: Decimal
    max_divergence_bps: Decimal
    max_spread_bps: Decimal
    spread_multiple: Decimal
    max_spread_multiple: Decimal
    passed: bool
    reason: str | None

    def to_wire_dict(self) -> dict[str, Any]:
        out = {
            "broker_id": self.broker_id,
            "symbol": self.symbol,
            "reference_source": self.reference_source,
            "bid": decimal_text(self.bid),
            "ask": decimal_text(self.ask),
            "mid": decimal_text(self.mid),
            "spread_bps": decimal_text(self.spread_bps),
            "reference_bid": decimal_text(self.reference_bid),
            "reference_ask": decimal_text(self.reference_ask),
            "reference_mid": decimal_text(self.reference_mid),
            "reference_spread_bps": decimal_text(self.reference_spread_bps),
            "divergence_bps": decimal_text(self.divergence_bps),
            "max_divergence_bps": decimal_text(self.max_divergence_bps),
            "max_spread_bps": decimal_text(self.max_spread_bps),
            "spread_multiple": decimal_text(self.spread_multiple),
            "max_spread_multiple": decimal_text(self.max_spread_multiple),
            "passed": self.passed,
            "reason": self.reason,
        }
        assert_safe_json_numbers(out)
        return out


ReferenceSource = Callable[[tuple[str, ...]], Mapping[str, tuple[Decimal, Decimal]]]


class OandaQuoteTruthOracle:
    """Cross-checks offshore MT5 quotes against a regulated reference before any admission.

    Limits (all exact ``Decimal``): mid divergence <= 15 bps on USD majors / 25 bps on crosses,
    offshore spread <= ``max_spread_bps`` and <= ``max_oanda_spread_multiple`` x reference spread.
    """

    def __init__(
        self,
        *,
        reference_source: ReferenceSource,
        reference_name: str,
        max_divergence_bps_major: Decimal = Decimal("15"),
        max_divergence_bps_cross: Decimal = Decimal("25"),
        max_spread_bps: Decimal = Decimal("30"),
        max_oanda_spread_multiple: Decimal = Decimal("3.0"),
    ) -> None:
        if not callable(reference_source):
            raise ContractError("reference_source must be callable")
        if not isinstance(reference_name, str) or not reference_name:
            raise ContractError("reference_name must be a non-empty string")
        self._source = reference_source
        self.reference_name = reference_name
        self.max_divergence_bps_major = decimal_value(max_divergence_bps_major, "max_divergence_bps_major", positive=True)
        self.max_divergence_bps_cross = decimal_value(max_divergence_bps_cross, "max_divergence_bps_cross", positive=True)
        self.max_spread_bps = decimal_value(max_spread_bps, "max_spread_bps", positive=True)
        self.max_oanda_spread_multiple = decimal_value(max_oanda_spread_multiple, "max_oanda_spread_multiple", positive=True)

    def __repr__(self) -> str:
        return f"OandaQuoteTruthOracle(reference={self.reference_name!r})"

    @classmethod
    def from_oanda_client(cls, client: OandaPracticePaperClient, **kwargs: Any) -> "OandaQuoteTruthOracle":
        if not isinstance(client, OandaPracticePaperClient):
            raise ContractError("client must be OandaPracticePaperClient")

        def source(symbols: tuple[str, ...]) -> dict[str, tuple[Decimal, Decimal]]:
            snap = client.fetch_pricing(pairs=tuple(symbols))
            return {sym: (q.bid, q.ask) for sym, q in snap.quotes.items()}

        ref_name = BROKER_OANDA_LIVE if client.execution_mode == EXECUTION_MODE_LIVE else BROKER_OANDA_PRACTICE
        return cls(reference_source=source, reference_name=ref_name, **kwargs)

    @classmethod
    def from_market_stream(cls, envelope_provider: Callable[[], Any], **kwargs: Any) -> "OandaQuoteTruthOracle":
        """Use a verified Kraken/ECB ``MarketStreamEnvelope`` when OANDA is uncredentialed."""

        def source(symbols: tuple[str, ...]) -> dict[str, tuple[Decimal, Decimal]]:
            pmap = envelope_provider().pair_map()
            return {sym: (pmap[sym].bid, pmap[sym].ask) for sym in symbols if sym in pmap}

        return cls(reference_source=source, reference_name="KRAKEN_ECB_REFERENCE", **kwargs)

    @classmethod
    def from_static_quotes(
        cls, quotes: Mapping[str, tuple[Decimal, Decimal]], *, reference_name: str = "STATIC_REFERENCE", **kwargs: Any
    ) -> "OandaQuoteTruthOracle":
        frozen = dict(quotes)
        return cls(reference_source=lambda symbols: {s: frozen[s] for s in symbols if s in frozen},
                   reference_name=reference_name, **kwargs)

    def max_divergence_for(self, symbol: str) -> Decimal:
        return self.max_divergence_bps_major if symbol in MAJOR_FX_PAIRS else self.max_divergence_bps_cross

    def reference_quotes(self, symbols: Iterable[str]) -> dict[str, tuple[Decimal, Decimal]]:
        wanted = tuple(dict.fromkeys(symbols))
        for sym in wanted:
            Mt5MarginCalculator.split_symbol(sym)
        try:
            raw = self._source(wanted)
        except OffMarketBrokerQuoteError:
            raise
        except (ContractError, OSError, KeyError) as exc:
            raise QuoteReferenceUnavailableError(
                f"regulated reference {self.reference_name} unavailable ({type(exc).__name__}); offshore admission fails closed"
            ) from None
        out: dict[str, tuple[Decimal, Decimal]] = {}
        for sym in wanted:
            pair = raw.get(sym)
            if pair is None:
                raise QuoteReferenceUnavailableError(f"regulated reference {self.reference_name} has no {sym} quote")
            out[sym] = _validated_quote(sym, pair[0], pair[1], "reference")
        return out

    def verify(
        self,
        broker_id: str,
        symbol: str,
        bid: Decimal,
        ask: Decimal,
        *,
        reference: Mapping[str, tuple[Decimal, Decimal]] | None = None,
    ) -> QuoteTruthVerdict:
        bid, ask = _validated_quote(symbol, bid, ask, broker_id)
        ref = reference if reference is not None and symbol in reference else self.reference_quotes((symbol,))
        rbid, rask = _validated_quote(symbol, ref[symbol][0], ref[symbol][1], "reference")
        with localcontext() as ctx:
            ctx.prec = 40
            mid = (bid + ask) / 2
            rmid = (rbid + rask) / 2
            spread_bps = _bps(ask - bid, mid)
            rspread_bps = _bps(rask - rbid, rmid)
            divergence = _bps(abs(mid - rmid), rmid)
            multiple = ((ask - bid) / (rask - rbid)).quantize(Decimal("0.0001"))
        max_div = self.max_divergence_for(symbol)
        reason: str | None = None
        if divergence > max_div:
            reason = "MID_DIVERGES_FROM_REGULATED_REFERENCE"
        elif spread_bps > self.max_spread_bps:
            reason = "OFFSHORE_SPREAD_EXCEEDS_MAX_BPS"
        elif multiple > self.max_oanda_spread_multiple:
            reason = "OFFSHORE_SPREAD_EXCEEDS_REFERENCE_MULTIPLE"
        return QuoteTruthVerdict(
            broker_id=broker_id,
            symbol=symbol,
            reference_source=self.reference_name,
            bid=bid,
            ask=ask,
            mid=mid,
            spread_bps=spread_bps,
            reference_bid=rbid,
            reference_ask=rask,
            reference_mid=rmid,
            reference_spread_bps=rspread_bps,
            divergence_bps=divergence,
            max_divergence_bps=max_div,
            max_spread_bps=self.max_spread_bps,
            spread_multiple=multiple,
            max_spread_multiple=self.max_oanda_spread_multiple,
            passed=reason is None,
            reason=reason,
        )

    def require_truthful(
        self,
        broker_id: str,
        symbol: str,
        bid: Decimal,
        ask: Decimal,
        *,
        reference: Mapping[str, tuple[Decimal, Decimal]] | None = None,
    ) -> QuoteTruthVerdict:
        verdict = self.verify(broker_id, symbol, bid, ask, reference=reference)
        if not verdict.passed:
            raise OffMarketBrokerQuoteError(
                f"{broker_id} {symbol} quote refused by OandaQuoteTruthOracle: {verdict.reason} "
                f"(divergence {decimal_text(verdict.divergence_bps)} bps, spread {decimal_text(verdict.spread_bps)} bps)",
                verdict,
            )
        return verdict

    def guard(
        self,
        reference: Mapping[str, tuple[Decimal, Decimal]] | None = None,
        sink: list[QuoteTruthVerdict] | None = None,
    ) -> Callable[[str, Mt5Tick], None]:
        """Return a ``quote_guard`` for :meth:`Mt5PaperBrokerVenue.execute`."""

        def _guard(broker_id: str, tick: Mt5Tick) -> None:
            verdict = self.verify(broker_id, tick.symbol, tick.bid, tick.ask, reference=reference)
            if sink is not None:
                sink.append(verdict)
            if not verdict.passed:
                raise OffMarketBrokerQuoteError(
                    f"{broker_id} {tick.symbol} quote refused by OandaQuoteTruthOracle: {verdict.reason}", verdict
                )

        return _guard

    def config_dict(self) -> dict[str, Any]:
        return {
            "name": "OandaQuoteTruthOracle",
            "reference_source": self.reference_name,
            "max_divergence_bps_major": decimal_text(self.max_divergence_bps_major),
            "max_divergence_bps_cross": decimal_text(self.max_divergence_bps_cross),
            "max_spread_bps": decimal_text(self.max_spread_bps),
            "max_oanda_spread_multiple": decimal_text(self.max_oanda_spread_multiple),
        }


# ---------------------------------------------------------------------------
# Layer 2 -- barbell capital policy
# ---------------------------------------------------------------------------


def _share(value: Any, field: str) -> Decimal:
    dec = value if isinstance(value, Decimal) else parse_decimal(str(value), field)
    decimal_value(dec, field)
    if not (Decimal("0") <= dec <= Decimal("1")):
        raise ContractError(f"{field} must be within [0, 1]")
    return dec


class BarbellCapitalPolicy:
    """80% regulated OANDA reserve + 20% high-leverage MT5 sleeve (Hugo's Way 12%, LHFX 8%).

    For a new MT5 OPEN on venue ``v`` with total barbell equity ``E``:

    - reserve attested: ``equity[OANDA_PRACTICE] >= (reserve_share - tolerance) * E``;
    - venue custody: ``equity[v] <= (share[v] + tolerance) * E``;
    - venue sleeve: ``used_margin_after[v] <= share[v] * E``;
    - stop-loss risk: ``abs(entry - stop) * units * quote_to_account <= max_pct% * E``.
    """

    def __init__(
        self,
        *,
        oanda_reserve_share: Decimal = Decimal("0.80"),
        hugosway_share: Decimal = Decimal("0.12"),
        lhfx_share: Decimal = Decimal("0.08"),
        max_stop_loss_equity_risk_pct: Decimal = Decimal("1.00"),
        max_drawdown_pct: Decimal = DEFAULT_MAX_DRAWDOWN_PCT,
        allocation_tolerance_share: Decimal = Decimal("0.02"),
        account_currency: str = "USD",
    ) -> None:
        self.shares: dict[str, Decimal] = {
            BROKER_OANDA_PRACTICE: _share(oanda_reserve_share, "oanda_reserve_share"),
            BROKER_HUGOSWAY_MT5: _share(hugosway_share, "hugosway_share"),
            BROKER_LHFX_MT5: _share(lhfx_share, "lhfx_share"),
        }
        if sum(self.shares.values()) != Decimal("1"):
            raise ContractError("barbell shares (OANDA reserve + Hugo's Way + LHFX) must sum to exactly 1")
        if self.shares[BROKER_OANDA_PRACTICE] < Decimal("0.5"):
            raise ContractError("the regulated OANDA reserve must hold at least 50% of barbell equity")
        self.max_stop_loss_equity_risk_pct = decimal_value(
            max_stop_loss_equity_risk_pct, "max_stop_loss_equity_risk_pct", positive=True
        )
        if self.max_stop_loss_equity_risk_pct > Decimal("5"):
            raise ContractError("max_stop_loss_equity_risk_pct must not exceed 5%")
        self.max_drawdown_pct = decimal_value(max_drawdown_pct, "max_drawdown_pct", positive=True)
        if self.max_drawdown_pct >= Decimal("1"):
            raise ContractError("max_drawdown_pct must be strictly below 1 (100%)")
        self.tolerance = _share(allocation_tolerance_share, "allocation_tolerance_share")
        self._calc = Mt5MarginCalculator(account_currency=account_currency)

    @classmethod
    def from_environ(cls, environ: Mapping[str, str], **kwargs: Any) -> "BarbellCapitalPolicy":
        def pick(name: str, default: str) -> Decimal:
            raw = environ.get(name, "")
            raw = raw.strip() if isinstance(raw, str) else ""
            return parse_decimal(raw or default, name)

        return cls(
            oanda_reserve_share=pick(ENV_BARBELL_OANDA_RESERVE_SHARE, "0.80"),
            hugosway_share=pick(ENV_BARBELL_HUGOSWAY_SHARE, "0.12"),
            lhfx_share=pick(ENV_BARBELL_LHFX_SHARE, "0.08"),
            max_stop_loss_equity_risk_pct=pick(ENV_BARBELL_MAX_STOP_RISK_PCT, "1.00"),
            max_drawdown_pct=pick(ENV_BARBELL_MAX_DRAWDOWN_PCT, "0.10"),
            **kwargs,
        )

    def share_for(self, broker_id: str) -> Decimal:
        key = BROKER_OANDA_PRACTICE if broker_id == BROKER_OANDA_LIVE else broker_id
        if key not in self.shares:
            raise ContractError(f"unknown barbell venue {broker_id}")
        return self.shares[key]

    @staticmethod
    def _oanda_equity(equities: Mapping[str, Decimal]) -> Decimal:
        val = Decimal("0")
        if BROKER_OANDA_PRACTICE in equities:
            val += equities[BROKER_OANDA_PRACTICE]
        if BROKER_OANDA_LIVE in equities:
            val += equities[BROKER_OANDA_LIVE]
        decimal_value(val, "equity[OANDA]")
        return val

    @staticmethod
    def total_equity(equities: Mapping[str, Decimal]) -> Decimal:
        total = BarbellCapitalPolicy._oanda_equity(equities)
        for broker_id in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            value = equities.get(broker_id, Decimal("0"))
            decimal_value(value, f"equity[{broker_id}]")
            total += value
        return total

    def quote_conversion_symbols(self, symbol: str) -> tuple[str, ...]:
        _, quote = Mt5MarginCalculator.split_symbol(symbol)
        conv = self._calc.conversion_symbol(quote)
        return (symbol,) if conv is None or conv == symbol else (symbol, conv)

    def stop_loss_risk(
        self,
        *,
        symbol: str,
        units: Decimal,
        entry_price: Decimal,
        stop_price: Decimal,
        quotes: Mapping[str, tuple[Decimal, Decimal]],
    ) -> Decimal:
        """Exact account-currency loss if the protective stop fills: ``abs(entry - stop) * units``."""
        _, quote = Mt5MarginCalculator.split_symbol(symbol)
        for name, value in (("units", units), ("entry_price", entry_price), ("stop_price", stop_price)):
            decimal_value(value, name, positive=True)
        with localcontext() as ctx:
            ctx.prec = 40
            loss_quote = abs(entry_price - stop_price) * units
            rate = self._calc.conversion_rate(quote, quotes)
            return (loss_quote * rate).quantize(Decimal("0.01"), rounding=ROUND_CEILING)

    def max_stop_risk_amount(self, total_equity: Decimal) -> Decimal:
        with localcontext() as ctx:
            ctx.prec = 40
            return (total_equity * self.max_stop_loss_equity_risk_pct / Decimal(100)).quantize(
                Decimal("0.01"), rounding=ROUND_FLOOR
            )

    def require_drawdown(self, *, current_equity: Decimal | None, peak_equity: Decimal | None) -> Decimal:
        if current_equity is None or peak_equity is None or peak_equity <= Decimal("0"):
            raise BarbellPolicyRefusalError(
                "peak_equity and current_equity are required before opening new risk",
                "MISSING_DRAWDOWN_ACCOUNTING",
            )
        dd_pct = compute_drawdown_pct(current_equity, peak_equity)
        if dd_pct >= self.max_drawdown_pct:
            raise BarbellPolicyRefusalError(
                f"barbell drawdown {decimal_text(dd_pct)} >= max_drawdown_pct {decimal_text(self.max_drawdown_pct)}",
                "MAX_DRAWDOWN_EXCEEDED",
            )
        return dd_pct

    def require_stop_risk(self, risk: Decimal, equities: Mapping[str, Decimal]) -> Decimal:
        total = self.total_equity(equities)
        if total <= 0:
            raise BarbellPolicyRefusalError("barbell total equity is not positive", "NON_POSITIVE_TOTAL_EQUITY")
        cap = self.max_stop_risk_amount(total)
        if risk > cap:
            raise BarbellPolicyRefusalError(
                f"stop-loss risk {decimal_text(risk)} exceeds {decimal_text(self.max_stop_loss_equity_risk_pct)}% "
                f"of barbell equity ({decimal_text(cap)})",
                "STOP_RISK_EXCEEDS_EQUITY_PCT",
            )
        return cap

    def require_sleeve(self, broker_id: str, *, equities: Mapping[str, Decimal], used_margin_after: Decimal) -> dict[str, str]:
        total = self.total_equity(equities)
        if total <= 0:
            raise BarbellPolicyRefusalError("barbell total equity is not positive", "NON_POSITIVE_TOTAL_EQUITY")
        share = self.share_for(broker_id)
        decimal_value(used_margin_after, "used_margin_after")
        with localcontext() as ctx:
            ctx.prec = 40
            sleeve_cap = (share * total).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
            if broker_id not in (BROKER_OANDA_PRACTICE, BROKER_OANDA_LIVE):
                reserve_floor = (self.shares[BROKER_OANDA_PRACTICE] - self.tolerance) * total
                if self._oanda_equity(equities) < reserve_floor:
                    raise BarbellPolicyRefusalError(
                        "regulated OANDA reserve is below its barbell floor; high-leverage MT5 risk refused",
                        "RESERVE_UNDERFUNDED",
                    )
                custody_cap = (share + self.tolerance) * total
                if equities.get(broker_id, Decimal("0")) > custody_cap:
                    raise BarbellPolicyRefusalError(
                        f"{broker_id} custody exceeds its barbell share; sweep profits to the OANDA reserve",
                        "VENUE_CUSTODY_OVER_ALLOCATED",
                    )
        if used_margin_after > sleeve_cap:
            raise BarbellPolicyRefusalError(
                f"{broker_id} margin after trade {decimal_text(used_margin_after)} exceeds its "
                f"{decimal_text(share * 100)}% sleeve ({decimal_text(sleeve_cap)})",
                "SLEEVE_CAP_EXCEEDED",
            )
        return {"broker_id": broker_id, "sleeve_cap": decimal_text(sleeve_cap), "used_margin_after": decimal_text(used_margin_after)}

    def allocation_report(self, equities: Mapping[str, Decimal]) -> dict[str, Any]:
        total = self.total_equity(equities)
        oanda_key = BROKER_OANDA_LIVE if (BROKER_OANDA_LIVE in equities and BROKER_OANDA_PRACTICE not in equities) else BROKER_OANDA_PRACTICE
        rows = []
        for broker_id in (oanda_key, BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            equity = equities.get(broker_id, Decimal("0"))
            with localcontext() as ctx:
                ctx.prec = 40
                actual = Decimal("0") if total <= 0 else (equity / total).quantize(Decimal("0.0001"))
            rows.append({
                "broker_id": broker_id,
                "target_share": decimal_text(self.share_for(broker_id)),
                "actual_share": decimal_text(actual),
                "equity": decimal_text(equity),
            })
        return {"total_equity": decimal_text(total), "venues": rows}

    def config_dict(self) -> dict[str, Any]:
        return {
            "name": "BarbellCapitalPolicy",
            "oanda_reserve_share": decimal_text(self.shares[BROKER_OANDA_PRACTICE]),
            "hugosway_share": decimal_text(self.shares[BROKER_HUGOSWAY_MT5]),
            "lhfx_share": decimal_text(self.shares[BROKER_LHFX_MT5]),
            "max_stop_loss_equity_risk_pct": decimal_text(self.max_stop_loss_equity_risk_pct),
            "max_drawdown_pct": decimal_text(self.max_drawdown_pct),
            "allocation_tolerance_share": decimal_text(self.tolerance),
        }


# ---------------------------------------------------------------------------
# Layer 3b -- OANDA protective offset planner
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OffsetOrder:
    order_id: str
    action_ref: str
    symbol: str
    side: Side
    units: Decimal
    reference_entry: Decimal
    stop_price: Decimal
    required_margin: Decimal
    covers_tickets: tuple[str, ...]

    def to_order_intent(self) -> OrderIntent:
        return OrderIntent(
            order_id=self.order_id,
            action_ref=self.action_ref,
            kind=ActionKind.OPEN,
            symbol=self.symbol,
            quantity_units=self.units,
            side=self.side,
            stop_price=self.stop_price,
        )

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "order_id": self.order_id,
            "action_ref": self.action_ref,
            "symbol": self.symbol,
            "side": self.side.value,
            "units": decimal_text(self.units),
            "reference_entry": decimal_text(self.reference_entry),
            "stop_price": decimal_text(self.stop_price),
            "required_margin": decimal_text(self.required_margin),
            "covers_tickets": list(self.covers_tickets),
        }


@dataclass(frozen=True, slots=True)
class OffsetPlan:
    broker_id: str
    venue: str
    orders: tuple[OffsetOrder, ...]
    exposure_before: dict[str, Decimal]
    exposure_after: dict[str, Decimal]
    total_required_margin: Decimal
    oanda_margin_available: Decimal | None
    fully_funded: bool

    @property
    def delta_neutral(self) -> bool:
        return all(v == 0 for v in self.exposure_after.values())

    def to_order_intents(self) -> tuple[OrderIntent, ...]:
        return tuple(o.to_order_intent() for o in self.orders)

    def to_wire_dict(self) -> dict[str, Any]:
        out = {
            "broker_id": self.broker_id,
            "venue": self.venue,
            "orders": [o.to_wire_dict() for o in self.orders],
            "exposure_before": {k: decimal_text(v) for k, v in sorted(self.exposure_before.items())},
            "exposure_after": {k: decimal_text(v) for k, v in sorted(self.exposure_after.items())},
            "total_required_margin": decimal_text(self.total_required_margin),
            "oanda_margin_available": None if self.oanda_margin_available is None else decimal_text(self.oanda_margin_available),
            "fully_funded": self.fully_funded,
            "delta_neutral": self.delta_neutral,
        }
        assert_safe_json_numbers(out)
        return out


class OandaProtectiveOffsetPlanner:
    """Plans exact opposing delta-neutral OANDA (1:50) offsets for unreachable MT5 positions.

    Plans are advisory: each offset is an ordinary OPEN that must still be cleared by
    ForexMetaValveGate before :meth:`DualShieldBrokerRouter.execute_offset_plan` sends it. Each
    offset carries a catastrophe stop mirroring the frozen position's stop distance (or
    ``default_catastrophe_stop_bps`` when the MT5 position had no stop).
    """

    def __init__(
        self,
        *,
        oanda_leverage: int = OANDA_SAFE_HARBOR_LEVERAGE,
        account_currency: str = "USD",
        default_catastrophe_stop_bps: Decimal = Decimal("100"),
        venue_id: str = BROKER_OANDA_PRACTICE,
    ) -> None:
        self._calc = Mt5MarginCalculator(leverage=oanda_leverage, account_currency=account_currency)
        self.oanda_leverage = oanda_leverage
        self.venue_id = venue_id
        self.default_catastrophe_stop_bps = decimal_value(
            default_catastrophe_stop_bps, "default_catastrophe_stop_bps", positive=True
        )

    def config_dict(self) -> dict[str, Any]:
        return {
            "name": "OandaProtectiveOffsetPlanner",
            "venue": self.venue_id,
            "leverage": f"1:{self.oanda_leverage}",
            "default_catastrophe_stop_bps": decimal_text(self.default_catastrophe_stop_bps),
            "requires_valve_clearance": True,
        }

    def plan(
        self,
        *,
        broker_id: str,
        frozen_positions: Iterable[Mt5Position],
        reference_quotes: Mapping[str, tuple[Decimal, Decimal]],
        oanda_margin_available: Decimal | None,
    ) -> OffsetPlan:
        if broker_id not in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            raise ContractError("offset plans cover offshore MT5 venues only")
        exposure: dict[str, Decimal] = {}
        stop_distance: dict[str, Decimal] = {}
        tickets: dict[str, list[str]] = {}
        for pos in frozen_positions:
            if not isinstance(pos, Mt5Position):
                raise ContractError("frozen_positions must be Mt5Position records")
            units = self._calc.lots_to_units(pos.volume_lots)
            signed = units if pos.side is Side.BUY else -units
            exposure[pos.symbol] = exposure.get(pos.symbol, Decimal("0")) + signed
            tickets.setdefault(pos.symbol, []).append(pos.ticket)
            if pos.stop_loss is not None:
                dist = abs(pos.price_open - pos.stop_loss)
                stop_distance[pos.symbol] = max(stop_distance.get(pos.symbol, Decimal("0")), dist)
        orders: list[OffsetOrder] = []
        after: dict[str, Decimal] = {}
        total_margin = Decimal("0")
        for idx, symbol in enumerate(sorted(exposure), start=1):
            net = exposure[symbol]
            if net == 0:
                after[symbol] = Decimal("0")
                continue
            side = Side.SELL if net > 0 else Side.BUY
            units = abs(net)
            if symbol not in reference_quotes:
                raise QuoteReferenceUnavailableError(f"no regulated reference quote for offset symbol {symbol}")
            bid, ask = _validated_quote(symbol, reference_quotes[symbol][0], reference_quotes[symbol][1], "reference")
            entry = bid if side is Side.SELL else ask
            tick = _price_tick(symbol)
            with localcontext() as ctx:
                ctx.prec = 40
                dist = stop_distance.get(symbol) or (entry * self.default_catastrophe_stop_bps / Decimal(10_000))
                if side is Side.SELL:
                    stop = (entry + dist).quantize(tick, rounding=ROUND_CEILING)
                else:
                    stop = (entry - dist).quantize(tick, rounding=ROUND_FLOOR)
            required = self._calc.required_margin(symbol, side, units, reference_quotes)
            total_margin += required
            slug = f"{broker_id.lower().replace('_', '-')}-{symbol.lower()}-{idx:03d}"
            orders.append(OffsetOrder(
                order_id=f"offset-{slug}",
                action_ref=f"offset-{slug}",
                symbol=symbol,
                side=side,
                units=units,
                reference_entry=entry,
                stop_price=stop,
                required_margin=required,
                covers_tickets=tuple(tickets[symbol]),
            ))
            after[symbol] = net + (units if side is Side.BUY else -units)
        funded = oanda_margin_available is not None and total_margin <= oanda_margin_available
        return OffsetPlan(
            broker_id=broker_id,
            venue=self.venue_id,
            orders=tuple(orders),
            exposure_before=dict(exposure),
            exposure_after=after,
            total_required_margin=total_margin,
            oanda_margin_available=oanda_margin_available,
            fully_funded=funded,
        )


# ---------------------------------------------------------------------------
# Layer 3a -- dual-shield router
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DualShieldExecution:
    result: Mt5ExecutionResult
    executed_on: str
    safe_harbor: bool
    trail: tuple[dict[str, Any], ...]
    quote_verdicts: tuple[QuoteTruthVerdict, ...]
    stop_loss_risk: Decimal
    stop_loss_risk_cap: Decimal

    def to_wire_dict(self) -> dict[str, Any]:
        out = {
            "executed_on": self.executed_on,
            "safe_harbor": self.safe_harbor,
            "trail": list(self.trail),
            "quote_verdicts": [v.to_wire_dict() for v in self.quote_verdicts],
            "stop_loss_risk": decimal_text(self.stop_loss_risk),
            "stop_loss_risk_cap": decimal_text(self.stop_loss_risk_cap),
            "accepted": self.result.accepted,
        }
        assert_safe_json_numbers(out)
        return out


class DualShieldBrokerRouter(BrokerHierarchyRouter):
    """Hugo's Way (1:500) -> LHFX (1:500) -> OANDA practice safe harbor (1:50), all Valve-gated.

    Unlike the plain hierarchy, every configured venue is connected at once (``activate_all``)
    because the barbell holds the regulated reserve and the offshore sleeves simultaneously.
    Setting ``CAS_FOREX_PRIMARY_BROKER=OANDA_PRACTICE`` routes every new trade straight to the
    regulated safe harbor (conservative mode).
    """

    def __init__(
        self,
        *,
        environ: Mapping[str, str],
        valve_gate: ForexMetaValveGate,
        oracle: OandaQuoteTruthOracle | None = None,
        barbell: BarbellCapitalPolicy | None = None,
        offset_planner: OandaProtectiveOffsetPlanner | None = None,
        equity_attestations: Mapping[str, Decimal] | None = None,
        peak_equity_store: PeakEquityStore | None = None,
        initial_peak_equity: Decimal | None = None,
        drawdown_scope_id: str = "dual-shield-barbell",
        **kwargs: Any,
    ) -> None:
        super().__init__(environ=environ, valve_gate=valve_gate, **kwargs)
        self._oracle_override = oracle
        self._oracle_cache: OandaQuoteTruthOracle | None = None
        self.barbell = barbell or BarbellCapitalPolicy.from_environ(self._env)
        self.offset_planner = offset_planner or OandaProtectiveOffsetPlanner(venue_id=self._oanda_broker_id)
        self._attestations = dict(equity_attestations or {})
        for key, value in self._attestations.items():
            if key not in BROKER_SPECS:
                raise ContractError(f"unknown attested venue {key}")
            decimal_value(value, f"attested equity {key}")
        if initial_peak_equity is not None:
            decimal_value(initial_peak_equity, "initial_peak_equity", positive=True)
        if not isinstance(drawdown_scope_id, str) or not drawdown_scope_id.strip():
            raise ContractError("drawdown_scope_id must be a non-empty string")
        self._peak_store = peak_equity_store if peak_equity_store is not None else PeakEquityStore()
        self._initial_peak_equity = initial_peak_equity
        self._drawdown_scope_id = drawdown_scope_id.strip()
        self._venues: dict[str, Mt5PaperBrokerVenue | OandaPracticeFallbackVenue] = {}
        self._last_equity: dict[str, Decimal] = {}
        self._degradations: list[dict[str, Any]] = []
        self._safe_harbor_calc = Mt5MarginCalculator(leverage=OANDA_SAFE_HARBOR_LEVERAGE)

    @property
    def venues(self) -> dict[str, Mt5PaperBrokerVenue | OandaPracticeFallbackVenue]:
        return dict(self._venues)

    def attach_venue(self, venue: Mt5PaperBrokerVenue | OandaPracticeFallbackVenue) -> None:
        """Attach an already-connected venue (used by rehearsals that build venues explicitly)."""
        if not isinstance(venue, (Mt5PaperBrokerVenue, OandaPracticeFallbackVenue)):
            raise ContractError("venue must be an MT5 or OANDA practice venue")
        self._venues[venue.broker_id] = venue
        self._status[venue.broker_id] = "ACTIVE"
        if self._active is None:
            self._active = venue

    def activate_all(self) -> dict[str, str]:
        for broker_id in self.priority_order:
            if broker_id in self._venues:
                continue
            if not self.is_configured(broker_id):
                self._status[broker_id] = "NOT_CONFIGURED"
                continue
            try:
                venue = self._build_venue(broker_id)
                venue.connect()
            except LiveBrokerEndpointForbiddenError:
                self._status[broker_id] = "LIVE_FORBIDDEN"
                raise
            except (ContractError, OSError) as exc:
                self._status[broker_id] = "FAILED"
                self._failures[broker_id] = type(exc).__name__
                logger.warning("dual-shield venue %s activation failed (%s)", broker_id, type(exc).__name__)
                continue
            self._venues[broker_id] = venue
            self._status[broker_id] = "ACTIVE"
        first = next((b for b in self.priority_order if b in self._venues), None)
        self._active = None if first is None else self._venues[first]
        return dict(self._status)

    def activate(self) -> str:
        self.activate_all()
        if self._active is None:
            raise BrokerFailoverExhaustedError("no venue in the dual-shield barbell could be activated")
        return self._active.broker_id

    def oracle(self) -> OandaQuoteTruthOracle:
        if self._oracle_override is not None:
            return self._oracle_override
        oanda = self._venues.get(self._oanda_broker_id)
        if isinstance(oanda, OandaPracticeFallbackVenue):
            if self._oracle_cache is None:
                self._oracle_cache = OandaQuoteTruthOracle.from_oanda_client(oanda.client)
            return self._oracle_cache
        raise QuoteReferenceUnavailableError(
            "no regulated quote reference (OANDA practice or verified Kraken/ECB stream); offshore admission fails closed"
        )

    def equities(self) -> dict[str, Decimal]:
        out: dict[str, Decimal] = {}
        for broker_id in (self._oanda_broker_id, BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            venue = self._venues.get(broker_id)
            value: Decimal | None = None
            if isinstance(venue, Mt5PaperBrokerVenue) and venue.account is not None:
                value = venue.account.equity
            elif isinstance(venue, OandaPracticeFallbackVenue):
                value = venue.nav
            if value is None:
                value = self._last_equity.get(broker_id, self._attestations.get(broker_id, Decimal("0")))
            self._last_equity[broker_id] = value
            out[broker_id] = value
        total = self.barbell.total_equity(out)
        if total > Decimal("0"):
            self._peak_store.observe_equity(
                self._drawdown_scope_id,
                current_equity=total,
                opening_balance=self._initial_peak_equity if self._initial_peak_equity is not None else total,
                now=self._clock(),
            )
        return out

    def peak_equity(self) -> Decimal | None:
        return self._peak_store.read_peak(self._drawdown_scope_id)

    def rearm_drawdown(
        self,
        *,
        new_peak_equity: Decimal,
        owner_verifier: Any,
        owner_request_id: str,
        fence_request: Any | None = None,
        now: datetime | None = None,
    ) -> Decimal:
        return self._peak_store.rearm_after_drawdown(
            self._drawdown_scope_id,
            new_peak_equity=new_peak_equity,
            owner_verifier=owner_verifier,
            owner_request_id=owner_request_id,
            fence_request=fence_request,
            now=now or self._clock(),
        )

    def _offshore_route(self) -> tuple[str, ...]:
        if self.primary_broker in (BROKER_OANDA_PRACTICE, BROKER_OANDA_LIVE):
            return ()
        return tuple(b for b in self.priority_order if b in (BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5))

    def _record(self, trail: list[dict[str, Any]], broker_id: str, outcome: str, reason: str | None) -> None:
        entry = {"broker_id": broker_id, "outcome": outcome, "reason": reason}
        trail.append(entry)
        if outcome not in ("EXECUTED", "NOT_CONFIGURED"):
            self._degradations.append(entry)
            del self._degradations[:-_MAX_TRAIL]

    def execute_open(self, order: OrderIntent, *, valve_decision: ValveDecision) -> DualShieldExecution:
        if not isinstance(order, OrderIntent) or order.kind is not ActionKind.OPEN:
            raise ContractError("execute_open requires an OPEN OrderIntent; use execute_management otherwise")
        require_valve_clearance(order, valve_decision, expected_weights_sha256=self._valve_gate.weights_sha256)
        oracle = self.oracle()
        reference = oracle.reference_quotes(
            tuple(dict.fromkeys(
                self.barbell.quote_conversion_symbols(order.symbol)
                + self._safe_harbor_calc.required_symbols(order.symbol)
            ))
        )
        rbid, rask = reference[order.symbol]
        entry = rask if order.side is Side.BUY else rbid
        equities = self.equities()
        total_eq = self.barbell.total_equity(equities)
        peak_eq = self.peak_equity()
        self.barbell.require_drawdown(current_equity=total_eq, peak_equity=peak_eq)
        risk = self.barbell.stop_loss_risk(
            symbol=order.symbol,
            units=order.quantity_units,  # type: ignore[arg-type]
            entry_price=entry,
            stop_price=order.stop_price,  # type: ignore[arg-type]
            quotes=reference,
        )
        cap = self.barbell.require_stop_risk(risk, equities)
        trail: list[dict[str, Any]] = []
        verdicts: list[QuoteTruthVerdict] = []

        for broker_id in self._offshore_route():
            venue = self._venues.get(broker_id)
            if not isinstance(venue, Mt5PaperBrokerVenue):
                self._record(trail, broker_id, "NOT_CONFIGURED" if not self.is_configured(broker_id) else "NOT_CONNECTED", None)
                continue
            try:
                venue.probe()
            except (Mt5TransportError, OSError) as exc:
                self._status[broker_id] = "DISCONNECTED"
                self._record(trail, broker_id, "DISCONNECTED", type(exc).__name__)
                continue
            equities = self.equities()

            def margin_guard(check: Mt5MarginCheck, _account: Mt5AccountSnapshot, _b: str = broker_id) -> None:
                self.barbell.require_sleeve(_b, equities=equities, used_margin_after=check.used_margin_after)

            try:
                result = venue.execute(
                    order,
                    valve_decision=valve_decision,
                    quote_guard=oracle.guard(reference, verdicts),
                    margin_guard=margin_guard,
                )
            except Mt5OutcomeUnknownError:
                self._record(trail, broker_id, "OUTCOME_UNKNOWN", "never re-routed")
                raise
            except OffMarketBrokerQuoteError as exc:
                self._record(trail, broker_id, "OFF_MARKET_QUOTE", exc.verdict.reason if exc.verdict else type(exc).__name__)
                continue
            except BarbellPolicyRefusalError as exc:
                self._record(trail, broker_id, "BARBELL_REFUSED", exc.reason)
                continue
            except Mt5MarginRefusalError as exc:
                self._record(trail, broker_id, "MARGIN_REFUSED", str(exc)[:120])
                continue
            except Mt5TransportError as exc:
                self._status[broker_id] = "DISCONNECTED"
                self._record(trail, broker_id, "DISCONNECTED", type(exc).__name__)
                continue
            self._record(trail, broker_id, "EXECUTED", None)
            return DualShieldExecution(
                result=result, executed_on=broker_id, safe_harbor=False, trail=tuple(trail),
                quote_verdicts=tuple(verdicts), stop_loss_risk=risk, stop_loss_risk_cap=cap,
            )

        oanda = self._venues.get(self._oanda_broker_id)
        if not isinstance(oanda, OandaPracticeFallbackVenue):
            self._record(trail, self._oanda_broker_id, "NOT_CONNECTED", None)
            raise BrokerFailoverExhaustedError(
                "offshore venues refused/unavailable and the OANDA safe harbor is not connected: "
                + "; ".join(f"{t['broker_id']}={t['outcome']}" for t in trail)
            )
        required = self._safe_harbor_calc.required_margin(
            order.symbol, order.side, order.quantity_units, reference  # type: ignore[arg-type]
        )
        available = oanda.margin_available
        nav = oanda.nav
        if available is None or nav is None or required > available:
            self._record(trail, self._oanda_broker_id, "MARGIN_REFUSED", "safe-harbor margin unavailable")
            raise Mt5MarginRefusalError("OANDA safe harbor lacks margin for this order at 1:50")
        self.barbell.require_sleeve(
            self._oanda_broker_id, equities=self.equities(), used_margin_after=(nav - available) + required
        )
        result = oanda.execute(order, valve_decision=valve_decision)
        self._record(trail, self._oanda_broker_id, "EXECUTED", "SAFE_HARBOR")
        return DualShieldExecution(
            result=result, executed_on=self._oanda_broker_id, safe_harbor=True, trail=tuple(trail),
            quote_verdicts=tuple(verdicts), stop_loss_risk=risk, stop_loss_risk_cap=cap,
        )

    def execute_management(self, broker_id: str, order: OrderIntent, *, valve_decision: ValveDecision) -> Mt5ExecutionResult:
        """AMEND_STOP is quote-truth checked (anti-stop-hunt); REDUCE/CLOSE always reach the venue."""
        venue = self._venues.get(broker_id)
        if venue is None:
            raise Mt5TransportError(f"{broker_id} is not connected")
        if not isinstance(venue, Mt5PaperBrokerVenue):
            return venue.execute(order, valve_decision=valve_decision)
        guard = self.oracle().guard() if order.kind is ActionKind.AMEND_STOP else None
        return venue.execute(order, valve_decision=valve_decision, quote_guard=guard)

    def detect_frozen_positions(self, broker_id: str) -> tuple[Mt5Position, ...] | None:
        """Return the last known positions if ``broker_id``'s terminal is unreachable, else ``None``."""
        venue = self._venues.get(broker_id)
        if not isinstance(venue, Mt5PaperBrokerVenue):
            raise ContractError(f"{broker_id} is not a connected MT5 venue")
        try:
            venue.probe()
        except (Mt5TransportError, OSError) as exc:
            self._status[broker_id] = "FROZEN"
            self._record([], broker_id, "TERMINAL_FROZEN", type(exc).__name__)
            return venue.positions
        return None

    def plan_protective_offsets(self, broker_id: str) -> OffsetPlan | None:
        frozen = self.detect_frozen_positions(broker_id)
        if not frozen:
            return None
        symbols: list[str] = []
        for pos in frozen:
            symbols.extend(self._safe_harbor_calc.required_symbols(pos.symbol))
        reference = self.oracle().reference_quotes(symbols)
        oanda = self._venues.get(self._oanda_broker_id)
        available = oanda.margin_available if isinstance(oanda, OandaPracticeFallbackVenue) else None
        return self.offset_planner.plan(
            broker_id=broker_id, frozen_positions=frozen, reference_quotes=reference, oanda_margin_available=available
        )

    def execute_offset_plan(
        self, plan: OffsetPlan, *, valve_decisions: Mapping[str, ValveDecision]
    ) -> tuple[Mt5ExecutionResult, ...]:
        oanda = self._venues.get(self._oanda_broker_id)
        if not isinstance(oanda, OandaPracticeFallbackVenue):
            raise BrokerFailoverExhaustedError("OANDA safe harbor is not connected; offsets cannot be placed")
        if not plan.fully_funded:
            raise Mt5MarginRefusalError("offset plan is not fully funded by OANDA practice margin")
        results = []
        for intent in plan.to_order_intents():
            results.append(oanda.execute(intent, valve_decision=valve_decisions.get(intent.action_ref)))  # type: ignore[arg-type]
        return tuple(results)

    def routing_snapshot(self) -> dict[str, Any]:
        snap = super().routing_snapshot()
        try:
            oracle_cfg = self.oracle().config_dict()
        except QuoteReferenceUnavailableError:
            oracle_cfg = OandaQuoteTruthOracle.from_static_quotes({}, reference_name="UNAVAILABLE").config_dict()
        snap["schema"] = "cas-forex.broker-routing/2"
        snap["architecture"] = "DUAL_SHIELD_BARBELL"
        eq_map = self.equities()
        alloc = self.barbell.allocation_report(eq_map)
        total_eq = self.barbell.total_equity(eq_map)
        peak_eq = self.peak_equity()
        alloc["peak_equity"] = None if peak_eq is None else decimal_text(peak_eq)
        alloc["drawdown_pct"] = (
            "0"
            if (peak_eq is None or peak_eq <= Decimal("0") or total_eq <= Decimal("0"))
            else decimal_text(compute_drawdown_pct(total_eq, peak_eq).quantize(Decimal("0.0001")))
        )
        snap["dual_shield"] = {
            "quote_truth_oracle": oracle_cfg,
            "barbell": self.barbell.config_dict(),
            "allocation": alloc,
            "safe_harbor": {
                "broker_id": self._oanda_broker_id,
                "leverage": f"1:{OANDA_SAFE_HARBOR_LEVERAGE}",
                "conservative_mode": self.primary_broker == self._oanda_broker_id,
                "recent_degradations": list(self._degradations[-8:]),
            },
            "offset_planner": self.offset_planner.config_dict(),
        }
        assert_safe_json_numbers(snap)
        return snap
