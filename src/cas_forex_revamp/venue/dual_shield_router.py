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

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
import logging
import math
import re
import threading
from typing import Any

from cas_forex_revamp.contracts import ActionKind, ContractError, Side, decimal_text, parse_decimal
from cas_forex_revamp.contracts.primitives import decimal_value, utc_time
from cas_forex_revamp.risk.demo_high_growth_profile import (
    DemoHighGrowthProfile,
    resolve_demo_high_growth_profile_from_environ,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
    ValveDecision,
    compute_drawdown_pct,
)
from .external_paper_broker import (
    ENV_OANDA_LIVE_ACCOUNT_ID,
    ENV_OANDA_LIVE_TOKEN,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    EXPANDED_FX_PAIRS,
    OandaOutcomeUnknownError,
    OandaPracticePaperClient,
    PaperBrokerTransportError,
    assert_safe_json_numbers,
)
from .live_auth_ticket import LiveAuthorizationError
from .live_market_stream import INDEX_INSTRUMENTS
from .mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_LIVE,
    BROKER_OANDA_PRACTICE,
    BROKER_SPECS,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
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
    Mt5PostFillObservationError,
    Mt5PreDispatchTransportError,
    Mt5SnapshotIntegrityError,
    Mt5SpoolBridgeTransport,
    Mt5Tick,
    Mt5TransportError,
    MANAGEMENT_ACTION_KINDS,
    OandaPracticeFallbackVenue,
    OrderIntent,
    RISK_INCREASING_ACTION_KINDS,
    RiskIncreasingOrderIntent,
    RiskReducingOrderIntent,
    STATUS_BROKER_OFFLINE,
    require_valve_clearance,
)

__all__ = [
    "BarbellCapitalPolicy",
    "BarbellPolicyRefusalError",
    "DEFAULT_OANDA_RECONNECT_INTERVAL_SECONDS",
    "DEFAULT_PUBLIC_INDEX_MAX_DIVERGENCE_BPS",
    "DualShieldBrokerRouter",
    "ENV_BARBELL_MAX_DRAWDOWN_PCT",
    "DualShieldExecution",
    "MAX_CONSTITUTIONAL_DRAWDOWN_PCT",
    "MAX_CONSTITUTIONAL_STOP_RISK_PCT",
    "MAJOR_FX_PAIRS",
    "OandaProtectiveOffsetPlanner",
    "OandaQuoteTruthOracle",
    "OffMarketBrokerQuoteError",
    "OffsetOrder",
    "OffsetPlan",
    "DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS",
    "QuoteReferenceUnavailableError",
    "QuoteTruthVerdict",
    "ReferenceQuote",
    "RiskIncreasingOrderIntent",
    "RiskReducingOrderIntent",
    "STATUS_BROKER_OFFLINE",
]

logger = logging.getLogger(__name__)

ENV_BARBELL_OANDA_RESERVE_SHARE = "CAS_FOREX_BARBELL_OANDA_RESERVE_SHARE"
ENV_BARBELL_HUGOSWAY_SHARE = "CAS_FOREX_BARBELL_HUGOSWAY_SHARE"
ENV_BARBELL_LHFX_SHARE = "CAS_FOREX_BARBELL_LHFX_SHARE"
ENV_BARBELL_MAX_STOP_RISK_PCT = "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT"
ENV_BARBELL_MAX_DRAWDOWN_PCT = "CAS_FOREX_MAX_DRAWDOWN_PCT"
MAX_CONSTITUTIONAL_STOP_RISK_PCT = Decimal("1.00")
ENV_DEMO_BARBELL_VIRTUAL_SLEEVE = "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE"
ENV_OANDA_LIVE_API_TOKEN = "_".join(("CAS", "FOREX", "OANDA", "LIVE", "API", "TOKEN"))
ENV_HUGOSWAY_MT5_LIVE_TICKET = "CAS_FOREX_HUGOSWAY_MT5_LIVE_TICKET"
ENV_LHFX_MT5_LIVE_TICKET = "CAS_FOREX_LHFX_MT5_LIVE_TICKET"
ENV_OANDA_LIVE_TICKET = "CAS_FOREX_OANDA_LIVE_TICKET"
LIVE_FUNDING_ARM_PHRASE = "ARM_LIVE_REAL_MONEY_TRADING"
DEFAULT_OANDA_RECONNECT_INTERVAL_SECONDS = 60.0
DEFAULT_PUBLIC_INDEX_MAX_DIVERGENCE_BPS = Decimal("150")
MAX_PUBLIC_INDEX_DIVERGENCE_BPS = Decimal("150")

_LIVE_HUGOSWAY_SERVERS: frozenset[str] = frozenset({
    "hugosway-real3",
    "hugosway-real",
    "hugosway real3",
    "hugosway real",
    "hugo pro5",
    "hugopro5",
    "hugo-real",
    "hugosway-live",
    "hugosway live",
})
_LIVE_LHFX_SERVERS: frozenset[str] = frozenset({
    "lhfxsa-live",
    "lhfx-live",
    "lhfxsa-real",
    "lhfxsa-trade",
    "lhfxsa trade",
})


def _has_staged_env_value(environ: Mapping[str, str], key: str) -> bool:
    raw = environ.get(key, "")
    val = raw.strip() if isinstance(raw, str) else ""
    return bool(val) and not val.upper().startswith("REPLACE_WITH_")


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
    if symbol in INDEX_INSTRUMENTS:
        return Decimal("0.01")
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


DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS = 60.0
_MT5_BROKER_IDS: frozenset[str] = frozenset({BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5})


def _parse_reference_observed_at(raw: Any) -> datetime:
    if isinstance(raw, datetime):
        return utc_time(raw, "observed_at")
    if isinstance(raw, str) and raw.strip():
        txt = raw.strip()
        if txt.endswith("Z"):
            txt = txt[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(txt)
        except ValueError as exc:
            raise QuoteReferenceUnavailableError(f"invalid reference quote observed_at {raw!r}") from exc
        return utc_time(dt, "observed_at")
    raise QuoteReferenceUnavailableError("index reference quote missing observed_at timestamp")


def _looks_like_mt5_provider(provider: str) -> bool:
    up = provider.strip().upper()
    return (
        up in _MT5_BROKER_IDS
        or "MT5" in up
        or "HUGOSWAY" in up
        or "LHFX" in up
    )


@dataclass(frozen=True, slots=True)
class ReferenceQuote:
    """Validated reference quote carrying explicit source provenance for anti-self-corroboration (Finding [5])."""

    symbol: str
    bid: Decimal
    ask: Decimal
    source_provider: str
    source_broker_id: str | None = None
    is_independent_public: bool = False
    observed_at: datetime | None = None
    provider_observed_at: datetime | None = None
    received_at: datetime | None = None

    def __post_init__(self) -> None:
        bid, ask = _validated_quote(self.symbol, self.bid, self.ask, "reference_quote")
        object.__setattr__(self, "bid", bid)
        object.__setattr__(self, "ask", ask)
        if not isinstance(self.source_provider, str) or not self.source_provider.strip():
            raise QuoteReferenceUnavailableError("ReferenceQuote requires a non-empty source_provider")
        if type(self.is_independent_public) is not bool:
            raise QuoteReferenceUnavailableError("ReferenceQuote.is_independent_public must be a bool")
        if self.source_broker_id is not None:
            if not isinstance(self.source_broker_id, str) or not self.source_broker_id.strip():
                raise QuoteReferenceUnavailableError("ReferenceQuote.source_broker_id must be None or non-empty string")
            object.__setattr__(self, "source_broker_id", self.source_broker_id.strip().upper())
        if self.provider_observed_at is not None:
            object.__setattr__(self, "provider_observed_at", _parse_reference_observed_at(self.provider_observed_at))
        if self.received_at is not None:
            object.__setattr__(self, "received_at", _parse_reference_observed_at(self.received_at))
        if self.received_at is not None and self.provider_observed_at is None:
            raise QuoteReferenceUnavailableError(
                f"index reference for {self.symbol} carries received_at without provider_observed_at"
            )
        if self.observed_at is not None:
            parsed_obs = _parse_reference_observed_at(self.observed_at)
            if self.provider_observed_at is not None:
                parsed_obs = min(self.provider_observed_at, parsed_obs)
            object.__setattr__(self, "observed_at", parsed_obs)
        elif self.provider_observed_at is not None:
            object.__setattr__(self, "observed_at", self.provider_observed_at)
        if self.is_independent_public:
            if self.source_broker_id in _MT5_BROKER_IDS or _looks_like_mt5_provider(self.source_provider):
                raise QuoteReferenceUnavailableError(
                    f"MT5 broker-derived feed ({self.source_provider}/{self.source_broker_id}) cannot claim is_independent_public=True"
                )

    @classmethod
    def from_entry(cls, symbol: str, entry: Any) -> "ReferenceQuote":
        if isinstance(entry, cls):
            if entry.symbol != symbol:
                raise QuoteReferenceUnavailableError(f"ReferenceQuote symbol {entry.symbol} does not match {symbol}")
            return entry
        if not isinstance(entry, Mapping):
            raise QuoteReferenceUnavailableError(
                f"index reference for {symbol} lacks required provenance metadata (unlabeled quote refused)"
            )
        required = ("bid", "ask", "source_provider", "source_broker_id", "is_independent_public", "observed_at")
        missing = [k for k in required if k not in entry]
        if missing:
            raise QuoteReferenceUnavailableError(
                f"index reference for {symbol} missing required provenance keys {missing}"
            )
        raw_bid = entry["bid"]
        raw_ask = entry["ask"]
        try:
            bid_d = raw_bid if isinstance(raw_bid, Decimal) else parse_decimal(str(raw_bid), "bid")
            ask_d = raw_ask if isinstance(raw_ask, Decimal) else parse_decimal(str(raw_ask), "ask")
        except ContractError as exc:
            raise QuoteReferenceUnavailableError(f"invalid index reference quote price for {symbol}: {exc}") from None
        prov_obs_dt = (
            _parse_reference_observed_at(entry["provider_observed_at"])
            if entry.get("provider_observed_at") is not None and str(entry.get("provider_observed_at")).strip()
            else None
        )
        recv_dt = (
            _parse_reference_observed_at(entry["received_at"])
            if entry.get("received_at") is not None and str(entry.get("received_at")).strip()
            else None
        )
        if recv_dt is not None and prov_obs_dt is None:
            raise QuoteReferenceUnavailableError(
                f"index reference for {symbol} carries received_at without provider_observed_at"
            )
        obs_dt = _parse_reference_observed_at(entry["observed_at"])
        if prov_obs_dt is not None:
            obs_dt = min(prov_obs_dt, obs_dt)
        raw_broker = entry["source_broker_id"]
        if raw_broker is not None and not isinstance(raw_broker, str):
            raise QuoteReferenceUnavailableError(f"invalid source_broker_id for {symbol}")
        return cls(
            symbol=symbol,
            bid=bid_d,
            ask=ask_d,
            source_provider=str(entry["source_provider"]),
            source_broker_id=(None if raw_broker is None else raw_broker),
            is_independent_public=entry["is_independent_public"],
            observed_at=obs_dt,
            provider_observed_at=prov_obs_dt,
            received_at=recv_dt,
        )

    def assert_fresh(
        self,
        *,
        now: datetime | None,
        max_age_seconds: float = DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS,
    ) -> None:
        if self.provider_observed_at is not None and self.observed_at is not None:
            eff_obs = min(self.provider_observed_at, self.observed_at)
        else:
            eff_obs = self.provider_observed_at if self.provider_observed_at is not None else self.observed_at
        if eff_obs is None:
            raise QuoteReferenceUnavailableError(f"index reference for {self.symbol} missing observed_at timestamp")
        if now is None or max_age_seconds <= 0:
            return
        check_now = utc_time(now, "now")
        age = (check_now - eff_obs).total_seconds()
        if age > max_age_seconds or age < -30.0:
            raise QuoteReferenceUnavailableError(
                f"index reference for {self.symbol} ({self.source_provider}) is stale or future-skewed "
                f"(age={age:.2f}s > max={max_age_seconds:.2f}s)"
            )

    def assert_corroborates_target(
        self,
        target_broker_id: str,
        *,
        now: datetime | None = None,
        max_age_seconds: float = DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS,
    ) -> None:
        target = str(target_broker_id or "").strip().upper()
        self.assert_fresh(now=now, max_age_seconds=max_age_seconds)
        prov = self.source_provider.strip().upper()
        src_broker = (self.source_broker_id or "").strip().upper()
        if src_broker and src_broker == target:
            raise QuoteReferenceUnavailableError(
                f"same-venue self-corroboration refused: {self.symbol} reference came from target broker {target}"
            )
        if prov == target or (target in _MT5_BROKER_IDS and target in prov):
            raise QuoteReferenceUnavailableError(
                f"same-venue self-corroboration refused: {self.symbol} provider {self.source_provider!r} matches target {target}"
            )
        if not self.is_independent_public:
            if not src_broker:
                raise QuoteReferenceUnavailableError(
                    f"unlabeled non-public index reference ({self.source_provider}) refused for {target} ({self.symbol})"
                )
            if src_broker == target:
                raise QuoteReferenceUnavailableError(
                    f"same-venue self-corroboration refused: {self.symbol} reference came from {src_broker}"
                )
        else:
            if src_broker in _MT5_BROKER_IDS or _looks_like_mt5_provider(prov):
                raise QuoteReferenceUnavailableError(
                    f"MT5 broker-derived feed cannot corroborate as independent public source for {target} ({self.symbol})"
                )


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
        max_divergence_bps_index: Decimal = Decimal("25"),
        max_spread_bps: Decimal = Decimal("30"),
        max_oanda_spread_multiple: Decimal = Decimal("3.0"),
        reference_provenance: Mapping[str, ReferenceQuote] | None = None,
        clock: Callable[[], datetime] | None = None,
        max_reference_age_seconds: float = DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS,
    ) -> None:
        if not callable(reference_source):
            raise ContractError("reference_source must be callable")
        if not isinstance(reference_name, str) or not reference_name:
            raise ContractError("reference_name must be a non-empty string")
        self._source = reference_source
        self.reference_name = reference_name
        self.max_divergence_bps_major = decimal_value(max_divergence_bps_major, "max_divergence_bps_major", positive=True)
        self.max_divergence_bps_cross = decimal_value(max_divergence_bps_cross, "max_divergence_bps_cross", positive=True)
        self.max_divergence_bps_index = decimal_value(max_divergence_bps_index, "max_divergence_bps_index", positive=True)
        self.max_spread_bps = decimal_value(max_spread_bps, "max_spread_bps", positive=True)
        self.max_oanda_spread_multiple = decimal_value(max_oanda_spread_multiple, "max_oanda_spread_multiple", positive=True)
        self._reference_provenance: dict[str, ReferenceQuote] = (
            dict(reference_provenance) if reference_provenance is not None else {}
        )
        self._clock: Callable[[], datetime] | None = clock
        self._max_reference_age_seconds: float = float(max_reference_age_seconds)

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

    @classmethod
    def from_reference_quotes(
        cls,
        quotes: Mapping[str, ReferenceQuote],
        *,
        reference_name: str | None = None,
        clock: Callable[[], datetime] | None = None,
        max_reference_age_seconds: float = DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS,
        **kwargs: Any,
    ) -> "OandaQuoteTruthOracle":
        prov_map: dict[str, ReferenceQuote] = {}
        pair_map: dict[str, tuple[Decimal, Decimal]] = {}
        first_provider = "INDEX_REFERENCE"
        for sym, raw_q in quotes.items():
            rq = ReferenceQuote.from_entry(sym, raw_q)
            prov_map[sym] = rq
            pair_map[sym] = (rq.bid, rq.ask)
            first_provider = rq.source_provider
        eff_name = reference_name if reference_name else first_provider
        return cls(
            reference_source=lambda symbols: {s: pair_map[s] for s in symbols if s in pair_map},
            reference_name=eff_name,
            reference_provenance=prov_map,
            clock=clock,
            max_reference_age_seconds=max_reference_age_seconds,
            **kwargs,
        )

    def max_divergence_for(self, symbol: str) -> Decimal:
        if symbol in INDEX_INSTRUMENTS:
            return self.max_divergence_bps_index
        return self.max_divergence_bps_major if symbol in MAJOR_FX_PAIRS else self.max_divergence_bps_cross

    def verify_cross_venue_index_quotes(
        self,
        *,
        symbol: str,
        hugo_quote: tuple[Decimal, Decimal] | None,
        lhfx_quote: tuple[Decimal, Decimal] | None,
        reference_quote: tuple[Decimal, Decimal],
    ) -> tuple[QuoteTruthVerdict, ...]:
        if symbol not in INDEX_INSTRUMENTS:
            raise ContractError(f"{symbol} is not a supported US index instrument")
        ref = {symbol: reference_quote}
        verdicts: list[QuoteTruthVerdict] = []
        for broker_id, q in ((BROKER_HUGOSWAY_MT5, hugo_quote), (BROKER_LHFX_MT5, lhfx_quote)):
            if q is None:
                continue
            verdicts.append(self.require_truthful(broker_id, symbol, q[0], q[1], reference=ref))
        if hugo_quote is not None and lhfx_quote is not None:
            hmid = (hugo_quote[0] + hugo_quote[1]) / Decimal("2")
            lmid = (lhfx_quote[0] + lhfx_quote[1]) / Decimal("2")
            cross_bps = _bps(abs(hmid - lmid), (hmid + lmid) / Decimal("2"))
            if cross_bps > self.max_divergence_bps_index:
                raise OffMarketBrokerQuoteError(
                    f"Hugo's Way vs LHFX {symbol} cross-venue mid divergence {decimal_text(cross_bps)} bps exceeds limit"
                )
        return tuple(verdicts)

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
        reference: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> QuoteTruthVerdict:
        bid, ask = _validated_quote(symbol, bid, ask, broker_id)
        check_now = now if now is not None else (self._clock() if self._clock is not None else None)
        prov = self._reference_provenance.get(symbol)
        if prov is not None:
            prov.assert_corroborates_target(
                broker_id,
                now=check_now,
                max_age_seconds=self._max_reference_age_seconds,
            )
        if reference is not None and symbol in reference:
            raw_entry = reference[symbol]
            if isinstance(raw_entry, (ReferenceQuote, Mapping)):
                entry_rq = ReferenceQuote.from_entry(symbol, raw_entry)
                entry_rq.assert_corroborates_target(
                    broker_id,
                    now=check_now,
                    max_age_seconds=self._max_reference_age_seconds,
                )
                rbid, rask = entry_rq.bid, entry_rq.ask
            else:
                rbid, rask = _validated_quote(symbol, raw_entry[0], raw_entry[1], "reference")
        else:
            ref = self.reference_quotes((symbol,))
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
        demo_virtual_sleeve: bool = False,
        demo_high_growth: DemoHighGrowthProfile | None = None,
    ) -> None:
        if demo_high_growth is not None and not isinstance(demo_high_growth, DemoHighGrowthProfile):
            raise ContractError("demo_high_growth must be a DemoHighGrowthProfile or None")
        self.shares: dict[str, Decimal] = {
            BROKER_OANDA_PRACTICE: _share(oanda_reserve_share, "oanda_reserve_share"),
            BROKER_HUGOSWAY_MT5: _share(hugosway_share, "hugosway_share"),
            BROKER_LHFX_MT5: _share(lhfx_share, "lhfx_share"),
        }
        if sum(self.shares.values()) != Decimal("1"):
            raise ContractError("barbell shares (OANDA reserve + Hugo's Way + LHFX) must sum to exactly 1")
        if self.shares[BROKER_OANDA_PRACTICE] < Decimal("0.5"):
            raise ContractError("the regulated OANDA reserve must hold at least 50% of barbell equity")
        self._demo_high_growth: DemoHighGrowthProfile = (
            demo_high_growth if demo_high_growth is not None else DemoHighGrowthProfile(enabled=False)
        )
        base_risk = decimal_value(
            max_stop_loss_equity_risk_pct, "max_stop_loss_equity_risk_pct", positive=True
        )
        if base_risk > MAX_CONSTITUTIONAL_STOP_RISK_PCT:
            raise ContractError(
                "CONSTITUTIONAL_STOP_RISK_CEILING_EXCEEDED: max_stop_loss_equity_risk_pct must not exceed 1.00%"
            )
        base_dd = decimal_value(max_drawdown_pct, "max_drawdown_pct", positive=True)
        if base_dd > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
            raise ContractError(
                "CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED: max_drawdown_pct must not exceed 0.10 (10.00%)"
            )
        self._base_stop_risk_pct: Decimal = base_risk
        self._base_drawdown_pct: Decimal = base_dd
        self.max_stop_loss_equity_risk_pct = (
            self._demo_high_growth.max_risk_pct if self._demo_high_growth.enabled else self._base_stop_risk_pct
        )
        self.max_drawdown_pct = (
            self._demo_high_growth.max_drawdown_pct if self._demo_high_growth.enabled else self._base_drawdown_pct
        )
        self.tolerance = _share(allocation_tolerance_share, "allocation_tolerance_share")
        self.demo_virtual_sleeve = bool(demo_virtual_sleeve)
        self._calc = Mt5MarginCalculator(account_currency=account_currency)

    @property
    def demo_high_growth(self) -> DemoHighGrowthProfile:
        return self._demo_high_growth

    @property
    def is_demo_high_growth_enabled(self) -> bool:
        return self._demo_high_growth.enabled

    @property
    def effective_stop_risk_ceiling_pct(self) -> Decimal:
        return self._demo_high_growth.effective_stop_risk_ceiling_pct()

    @property
    def effective_drawdown_ceiling_pct(self) -> Decimal:
        return self._demo_high_growth.effective_drawdown_ceiling_pct()

    def apply_demo_high_growth_profile(
        self,
        profile: DemoHighGrowthProfile,
        *,
        execution_mode: Any = "DEMO",
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
    ) -> None:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise ContractError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            execution_mode,
            live_trading_armed=live_trading_armed,
            live_trading_locked=live_trading_locked,
        )
        self._demo_high_growth = profile
        if profile.enabled:
            self.max_stop_loss_equity_risk_pct = profile.max_risk_pct
            self.max_drawdown_pct = profile.max_drawdown_pct
        else:
            self.max_stop_loss_equity_risk_pct = self._base_stop_risk_pct
            self.max_drawdown_pct = self._base_drawdown_pct

    @property
    def allocation_tolerance_share(self) -> Decimal:
        return self.tolerance

    @classmethod
    def from_environ(cls, environ: Mapping[str, str], **kwargs: Any) -> "BarbellCapitalPolicy":
        def pick(name: str, default: str) -> Decimal:
            raw = environ.get(name, "")
            raw = raw.strip() if isinstance(raw, str) else ""
            return parse_decimal(raw or default, name)

        raw_vs = str(environ.get(ENV_DEMO_BARBELL_VIRTUAL_SLEEVE, "")).strip().lower()
        vs_flag = kwargs.pop("demo_virtual_sleeve", raw_vs in ("1", "true", "yes", "on"))
        return cls(
            oanda_reserve_share=pick(ENV_BARBELL_OANDA_RESERVE_SHARE, "0.80"),
            hugosway_share=pick(ENV_BARBELL_HUGOSWAY_SHARE, "0.12"),
            lhfx_share=pick(ENV_BARBELL_LHFX_SHARE, "0.08"),
            max_stop_loss_equity_risk_pct=pick(ENV_BARBELL_MAX_STOP_RISK_PCT, "1.00"),
            max_drawdown_pct=pick(ENV_BARBELL_MAX_DRAWDOWN_PCT, "0.10"),
            demo_virtual_sleeve=bool(vs_flag),
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
        dd_ceiling = self.effective_drawdown_ceiling_pct
        if self.max_drawdown_pct > dd_ceiling:
            raise ContractError(
                f"CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED: max_drawdown_pct must not exceed {decimal_text(dd_ceiling)}"
            )
        if current_equity is None or peak_equity is None or peak_equity <= Decimal("0"):
            raise BarbellPolicyRefusalError(
                "peak_equity and current_equity are required before opening new risk",
                "MISSING_DRAWDOWN_ACCOUNTING",
            )
        dd_pct = compute_drawdown_pct(current_equity, peak_equity)
        eff_limit = min(self.max_drawdown_pct, dd_ceiling)
        if dd_pct >= eff_limit:
            dd_disp = dd_pct.quantize(Decimal("0.00000001"), rounding=ROUND_CEILING)
            raise BarbellPolicyRefusalError(
                f"barbell drawdown {decimal_text(dd_disp)} >= max_drawdown_pct {decimal_text(eff_limit)}",
                "MAX_DRAWDOWN_EXCEEDED",
            )
        return dd_pct

    def effective_total_equity(self, equities: Mapping[str, Decimal]) -> Decimal:
        actual = self.total_equity(equities)
        if not self.demo_virtual_sleeve:
            return actual
        oanda_eq = self._oanda_equity(equities)
        if oanda_eq <= Decimal("0"):
            return actual
        with localcontext() as ctx:
            ctx.prec = 40
            virtual_total = (oanda_eq / self.shares[BROKER_OANDA_PRACTICE]).quantize(
                Decimal("0.01"), rounding=ROUND_FLOOR
            )
        return min(actual, virtual_total)

    def require_stop_risk(self, risk: Decimal, equities: Mapping[str, Decimal]) -> Decimal:
        risk_ceiling = self.effective_stop_risk_ceiling_pct
        if self.max_stop_loss_equity_risk_pct > risk_ceiling:
            raise ContractError(
                f"CONSTITUTIONAL_STOP_RISK_CEILING_EXCEEDED: max_stop_loss_equity_risk_pct must not exceed {decimal_text(risk_ceiling)}%"
            )
        total = self.effective_total_equity(equities)
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
        total = self.effective_total_equity(equities)
        if total <= 0:
            raise BarbellPolicyRefusalError("barbell total equity is not positive", "NON_POSITIVE_TOTAL_EQUITY")
        share = self.share_for(broker_id)
        decimal_value(used_margin_after, "used_margin_after")
        with localcontext() as ctx:
            ctx.prec = 40
            sleeve_cap = (share * total).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)
            if broker_id not in (BROKER_OANDA_PRACTICE, BROKER_OANDA_LIVE):
                oanda_eq = self._oanda_equity(equities)
                if self.demo_virtual_sleeve:
                    if oanda_eq <= Decimal("0"):
                        raise BarbellPolicyRefusalError(
                            "regulated OANDA demo reserve must be positive for virtual barbell sleeve",
                            "RESERVE_UNDERFUNDED",
                        )
                else:
                    reserve_floor = (self.shares[BROKER_OANDA_PRACTICE] - self.tolerance) * total
                    if oanda_eq < reserve_floor:
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
            "demo_virtual_sleeve": self.demo_virtual_sleeve,
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
        index_reference_source: Callable[[Iterable[str]], Mapping[str, Any]] | None = None,
        index_reference_max_age_seconds: float = DEFAULT_INDEX_REFERENCE_MAX_AGE_SECONDS,
        public_index_max_divergence_bps: Decimal = DEFAULT_PUBLIC_INDEX_MAX_DIVERGENCE_BPS,
        oanda_reconnect_interval_seconds: float = DEFAULT_OANDA_RECONNECT_INTERVAL_SECONDS,
        monotonic: Callable[[], float] | None = None,
        demo_high_growth: DemoHighGrowthProfile | None = None,
        **kwargs: Any,
    ) -> None:
        if (
            not isinstance(oanda_reconnect_interval_seconds, (int, float))
            or isinstance(oanda_reconnect_interval_seconds, bool)
            or not math.isfinite(float(oanda_reconnect_interval_seconds))
            or float(oanda_reconnect_interval_seconds) < 0.0
        ):
            raise ContractError("oanda_reconnect_interval_seconds must be a non-negative finite number")
        super().__init__(environ=environ, valve_gate=valve_gate, **kwargs)
        self._oracle_override = oracle
        self._oracle_cache: OandaQuoteTruthOracle | None = None
        self._index_reference_source = index_reference_source
        if (
            isinstance(index_reference_max_age_seconds, bool)
            or not isinstance(index_reference_max_age_seconds, (int, float))
            or not math.isfinite(float(index_reference_max_age_seconds))
            or float(index_reference_max_age_seconds) <= 0.0
        ):
            raise ContractError("index_reference_max_age_seconds must be a positive finite number")
        self._index_reference_max_age_seconds = float(index_reference_max_age_seconds)
        pub_idx_div = decimal_value(public_index_max_divergence_bps, "public_index_max_divergence_bps", positive=True)
        if pub_idx_div > MAX_PUBLIC_INDEX_DIVERGENCE_BPS:
            raise ContractError(
                f"public_index_max_divergence_bps ({decimal_text(pub_idx_div)}) exceeds "
                f"ceiling ({decimal_text(MAX_PUBLIC_INDEX_DIVERGENCE_BPS)})"
            )
        self._public_index_max_divergence_bps = pub_idx_div
        resolved_dhg = (
            demo_high_growth
            if demo_high_growth is not None
            else resolve_demo_high_growth_profile_from_environ(
                self._env,
                execution_mode=self.execution_mode,
                live_trading_armed=self._live_armed,
                live_trading_locked=not bool(self._live_armed),
            )
        )
        if not isinstance(resolved_dhg, DemoHighGrowthProfile):
            raise ContractError("demo_high_growth must be a DemoHighGrowthProfile or None")
        resolved_dhg.assert_demo_mode(
            self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )
        self.barbell = barbell or BarbellCapitalPolicy.from_environ(
            self._env,
            demo_high_growth=resolved_dhg if resolved_dhg.enabled else None,
        )
        if resolved_dhg.enabled:
            self.barbell.apply_demo_high_growth_profile(
                resolved_dhg,
                execution_mode=self.execution_mode,
                live_trading_armed=self._live_armed,
                live_trading_locked=not bool(self._live_armed),
            )
            self._valve_gate.set_demo_high_growth_profile(
                resolved_dhg,
                execution_mode=self.execution_mode,
                live_trading_armed=self._live_armed,
                live_trading_locked=not bool(self._live_armed),
            )
        self.barbell.demo_high_growth.assert_demo_mode(
            self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )
        self._valve_gate._demo_high_growth.assert_demo_mode(
            self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )
        eff_stop_ceil = self.barbell.effective_stop_risk_ceiling_pct
        eff_dd_ceil = self.barbell.effective_drawdown_ceiling_pct
        if self.barbell.max_stop_loss_equity_risk_pct > eff_stop_ceil:
            raise ContractError(
                f"CONSTITUTIONAL_STOP_RISK_CEILING_EXCEEDED: router refuses stop-risk above {decimal_text(eff_stop_ceil)}%"
            )
        if self.barbell.max_drawdown_pct > eff_dd_ceil:
            raise ContractError(
                f"CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED: router refuses drawdown above {decimal_text(eff_dd_ceil)}"
            )
        if self._valve_gate.max_drawdown_pct is not None and self._valve_gate.max_drawdown_pct > eff_dd_ceil:
            raise ContractError(
                f"CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED: valve gate drawdown exceeds {decimal_text(eff_dd_ceil)}"
            )
        if self.barbell.demo_virtual_sleeve and self.execution_mode != EXECUTION_MODE_DEMO:
            raise ContractError("CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE is strictly forbidden in LIVE execution mode")
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
        self._rearm_gen: int = 0
        self._degradations: list[dict[str, Any]] = []
        self._safe_harbor_calc = Mt5MarginCalculator(leverage=OANDA_SAFE_HARBOR_LEVERAGE)
        self._oanda_reconnect_interval_seconds: float = float(oanda_reconnect_interval_seconds)
        self._monotonic: Callable[[], float] | None = monotonic
        self._last_oanda_reconnect_attempt: datetime | None = None
        self._last_oanda_reconnect_mono: float | None = None
        self._pending_oanda_venue: OandaPracticeFallbackVenue | None = None
        self._oanda_reconnect_lock = threading.Lock()

    @property
    def venues(self) -> dict[str, Mt5PaperBrokerVenue | OandaPracticeFallbackVenue]:
        return dict(self._venues)

    def _sync_mt5_venues_nonblocking(self, *, raise_on_mt5_integrity: bool = False) -> set[str]:
        unverified_mt5: set[str] = set()
        for broker_id, venue in self._venues.items():
            if isinstance(venue, Mt5PaperBrokerVenue):
                probe_verified = True
                if isinstance(venue._transport, Mt5SpoolBridgeTransport):
                    probe_verified = False
                    try:
                        venue.probe()
                        probe_verified = True
                    except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                        raise
                    except Mt5SnapshotIntegrityError:
                        unverified_mt5.add(broker_id)
                        self._status[broker_id] = "SNAPSHOT_UNVERIFIED"
                        self._failures[broker_id] = "SNAPSHOT_INTEGRITY_FAILED"
                        if raise_on_mt5_integrity:
                            raise
                        continue
                    except (ContractError, OSError):
                        pass
                if venue.is_offline:
                    self._status[broker_id] = STATUS_BROKER_OFFLINE
                    self._failures[broker_id] = STATUS_BROKER_OFFLINE
                elif self._status.get(broker_id) == STATUS_BROKER_OFFLINE:
                    self._status[broker_id] = "ACTIVE"
                    if self._failures.get(broker_id) == STATUS_BROKER_OFFLINE:
                        self._failures.pop(broker_id, None)
                elif probe_verified and self._status.get(broker_id) == "SNAPSHOT_UNVERIFIED":
                    self._status[broker_id] = "ACTIVE"
                    if self._failures.get(broker_id) == "SNAPSHOT_INTEGRITY_FAILED":
                        self._failures.pop(broker_id, None)
            elif isinstance(venue, OandaPracticeFallbackVenue):
                if venue.summary is not None and venue.summary_observed_at is None:
                    if self._status.get(broker_id) not in ("FAILED", STATUS_BROKER_OFFLINE):
                        self._status[broker_id] = "FAILED"
                        self._failures[broker_id] = "SUMMARY_REFRESH_FAILED"
                elif venue.summary is not None and venue.summary_observed_at is not None:
                    if self._status.get(broker_id) in ("FAILED", STATUS_BROKER_OFFLINE):
                        self._status[broker_id] = "ACTIVE"
                        self._failures.pop(broker_id, None)
        first_online = next(
            (b for b in self.priority_order if b in self._venues and not self.is_broker_offline(b)),
            next((b for b in self.priority_order if b in self._venues), None),
        )
        self._active = None if first_online is None else self._venues[first_online]
        return unverified_mt5

    def _probe_mt5_fresh(self, *, symbol: str | None = None) -> None:
        """Refresh MT5 account & tick freshness immediately before new-risk admission; fail closed on integrity errors."""
        for venue in self._venues.values():
            if not isinstance(venue, Mt5PaperBrokerVenue):
                continue
            try:
                venue.probe()
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError, Mt5SnapshotIntegrityError):
                raise
            except (Mt5TransportError, ContractError, OSError):
                continue
            if symbol is not None and not venue.is_offline and isinstance(venue._transport, Mt5SpoolBridgeTransport):
                try:
                    venue._transport.symbol_tick(symbol, require_fresh_tick=True)
                except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError, Mt5SnapshotIntegrityError):
                    raise
                except (Mt5PreDispatchTransportError, Mt5TransportError, ContractError, OSError):
                    continue

    def is_broker_offline(self, broker_id: str) -> bool:
        venue = self._venues.get(broker_id)
        if isinstance(venue, Mt5PaperBrokerVenue) and venue.is_offline:
            return True
        if broker_id == self._oanda_broker_id and isinstance(venue, OandaPracticeFallbackVenue):
            if venue.summary is not None:
                if venue.summary_observed_at is None:
                    return True
                if self._status.get(broker_id) in ("FAILED", STATUS_BROKER_OFFLINE):
                    self._status[broker_id] = "ACTIVE"
                    self._failures.pop(broker_id, None)
                return False
        status = self._status.get(broker_id)
        if status == STATUS_BROKER_OFFLINE:
            return True
        if broker_id == self._oanda_broker_id:
            if status == "FAILED" and (self.is_configured(broker_id) or broker_id in self._venues):
                return True
        return False

    def offline_brokers(self) -> list[str]:
        self._sync_mt5_venues_nonblocking()
        return [broker_id for broker_id in self.priority_order if self.is_broker_offline(broker_id)]

    def equity_incomplete(self) -> bool:
        return len(self.offline_brokers()) > 0

    def attach_venue(self, venue: Mt5PaperBrokerVenue | OandaPracticeFallbackVenue) -> None:
        """Attach an already-connected venue (used by rehearsals that build venues explicitly)."""
        if not isinstance(venue, (Mt5PaperBrokerVenue, OandaPracticeFallbackVenue)):
            raise ContractError("venue must be an MT5 or OANDA practice venue")
        self._venues[venue.broker_id] = venue
        if isinstance(venue, Mt5PaperBrokerVenue) and venue.is_offline:
            self._status[venue.broker_id] = STATUS_BROKER_OFFLINE
            self._failures[venue.broker_id] = STATUS_BROKER_OFFLINE
        else:
            self._status[venue.broker_id] = "ACTIVE"
        first_online = next(
            (b for b in self.priority_order if b in self._venues and not self.is_broker_offline(b)),
            next((b for b in self.priority_order if b in self._venues), None),
        )
        self._active = None if first_online is None else self._venues[first_online]

    def activate_all(self) -> dict[str, str]:
        for broker_id in self.priority_order:
            if broker_id in self._venues:
                continue
            if not self.is_configured(broker_id):
                self._status[broker_id] = "NOT_CONFIGURED"
                continue
            built_venue: Mt5PaperBrokerVenue | OandaPracticeFallbackVenue | None = None
            try:
                built_venue = self._build_venue(broker_id)
                built_venue.connect()
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                self._status[broker_id] = "LIVE_FORBIDDEN"
                raise
            except (ContractError, OSError) as exc:
                self._status[broker_id] = "FAILED"
                self._failures[broker_id] = type(exc).__name__
                if broker_id == self._oanda_broker_id:
                    if isinstance(built_venue, OandaPracticeFallbackVenue):
                        self._pending_oanda_venue = built_venue
                    self._last_oanda_reconnect_attempt = self._clock()
                    if self._monotonic is not None:
                        self._last_oanda_reconnect_mono = float(self._monotonic())
                logger.warning("dual-shield venue %s activation failed (%s)", broker_id, type(exc).__name__)
                continue
            self._venues[broker_id] = built_venue
            if broker_id == self._oanda_broker_id:
                self._pending_oanda_venue = None
                self._last_oanda_reconnect_attempt = None
                self._last_oanda_reconnect_mono = None
            if isinstance(built_venue, Mt5PaperBrokerVenue) and built_venue.is_offline:
                self._status[broker_id] = STATUS_BROKER_OFFLINE
                self._failures[broker_id] = STATUS_BROKER_OFFLINE
            else:
                self._status[broker_id] = "ACTIVE"
                self._failures.pop(broker_id, None)
        first_online = next(
            (b for b in self.priority_order if b in self._venues and not self.is_broker_offline(b)),
            next((b for b in self.priority_order if b in self._venues), None),
        )
        self._active = None if first_online is None else self._venues[first_online]
        return dict(self._status)

    def try_reconnect_oanda(
        self,
        *,
        now: datetime | None = None,
        force: bool = False,
    ) -> bool:
        """Throttled self-healing reconnect for configured OANDA venue after cold-start or mid-session HTTP 5xx."""
        broker_id = self._oanda_broker_id
        if self._status.get(broker_id) == "LIVE_FORBIDDEN":
            return False
        if not self.is_configured(broker_id) and broker_id not in self._venues:
            return False
        if not self.is_broker_offline(broker_id):
            return False

        with self._oanda_reconnect_lock:
            if self._status.get(broker_id) == "LIVE_FORBIDDEN":
                return False
            if not self.is_broker_offline(broker_id):
                return False

            ts = self._clock() if now is None else utc_time(now, "now")
            mono_now = float(self._monotonic()) if (self._monotonic is not None and now is None) else None
            if not force:
                if mono_now is not None and self._last_oanda_reconnect_mono is not None:
                    elapsed_m = mono_now - self._last_oanda_reconnect_mono
                    if 0.0 <= elapsed_m < self._oanda_reconnect_interval_seconds:
                        return False
                elif self._last_oanda_reconnect_attempt is not None:
                    elapsed_t = (ts - self._last_oanda_reconnect_attempt).total_seconds()
                    if 0.0 <= elapsed_t < self._oanda_reconnect_interval_seconds:
                        return False

            self._last_oanda_reconnect_attempt = ts
            if mono_now is not None:
                self._last_oanda_reconnect_mono = mono_now

            try:
                existing = self._venues.get(broker_id)
                if isinstance(existing, OandaPracticeFallbackVenue):
                    summary = existing.probe_account_summary(now=ts)
                    venue = existing
                else:
                    cand = self._pending_oanda_venue
                    if not isinstance(cand, OandaPracticeFallbackVenue):
                        built = self._build_venue(broker_id)
                        if not isinstance(built, OandaPracticeFallbackVenue):
                            return False
                        cand = built
                        self._pending_oanda_venue = cand
                    summary = cand.probe_account_summary(now=ts)
                    venue = cand
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                self._status[broker_id] = "LIVE_FORBIDDEN"
                raise
            except (PaperBrokerTransportError, Mt5TransportError, ContractError, OSError) as exc:
                self._status[broker_id] = "FAILED"
                self._failures[broker_id] = type(exc).__name__
                logger.warning(
                    "dual-shield venue %s throttled reconnect failed (%s); next retry in %.0fs",
                    broker_id,
                    type(exc).__name__,
                    self._oanda_reconnect_interval_seconds,
                )
                return False

            self._venues[broker_id] = venue
            self._pending_oanda_venue = None
            self._last_oanda_reconnect_attempt = None
            self._last_oanda_reconnect_mono = None
            self._status[broker_id] = "ACTIVE"
            self._failures.pop(broker_id, None)
            self._oracle_cache = None
            nav_val = parse_decimal(str(summary["nav"]), "nav")
            self._last_equity[broker_id] = nav_val
            first_online = next(
                (b for b in self.priority_order if b in self._venues and not self.is_broker_offline(b)),
                next((b for b in self.priority_order if b in self._venues), None),
            )
            self._active = None if first_online is None else self._venues[first_online]

        self.equities()
        logger.info("dual-shield venue %s auto-reconnected (nav=%s)", broker_id, decimal_text(nav_val))
        return True

    _maybe_reconnect_oanda = try_reconnect_oanda

    def activate(self) -> str:
        self.activate_all()
        if self._active is None:
            raise BrokerFailoverExhaustedError("no venue in the dual-shield barbell could be activated")
        return self._active.broker_id

    def _index_reference_quotes(
        self,
        symbol: str,
        *,
        target_broker_id: str | None = None,
    ) -> tuple[OandaQuoteTruthOracle, dict[str, tuple[Decimal, Decimal]]]:
        """Resolve provenance-verified reference quotes for US index CFDs (Finding [5]).

        Strictly rejects unlabeled quotes, stale quotes, MT5 feeds claiming to be public, and
        same-venue self-corroboration where reference provenance matches ``target_broker_id``.
        """
        now_ts = self._clock()
        if self._oracle_override is not None:
            try:
                ref = self._oracle_override.reference_quotes((symbol,))
                if target_broker_id is not None and symbol in self._oracle_override._reference_provenance:
                    self._oracle_override._reference_provenance[symbol].assert_corroborates_target(
                        target_broker_id,
                        now=now_ts,
                        max_age_seconds=self._index_reference_max_age_seconds,
                    )
                return self._oracle_override, ref
            except QuoteReferenceUnavailableError:
                logging.getLogger(__name__).debug("oracle override lacks index quote for %s; falling back", symbol)
        if self._index_reference_source is not None:
            raw = self._index_reference_source((symbol,))
            if isinstance(raw, Mapping) and symbol in raw:
                ref_quote = ReferenceQuote.from_entry(symbol, raw[symbol])
                ref_quote.assert_fresh(
                    now=now_ts,
                    max_age_seconds=self._index_reference_max_age_seconds,
                )
                if target_broker_id is not None:
                    ref_quote.assert_corroborates_target(
                        target_broker_id,
                        now=now_ts,
                        max_age_seconds=self._index_reference_max_age_seconds,
                    )
                oracle = OandaQuoteTruthOracle.from_reference_quotes(
                    {symbol: ref_quote},
                    reference_name=ref_quote.source_provider,
                    max_divergence_bps_index=(
                        self._public_index_max_divergence_bps
                        if ref_quote.is_independent_public
                        else Decimal("25")
                    ),
                    clock=self._clock,
                    max_reference_age_seconds=self._index_reference_max_age_seconds,
                )
                return oracle, {symbol: (ref_quote.bid, ref_quote.ask)}
        hugo = self._venues.get(BROKER_HUGOSWAY_MT5)
        lhfx = self._venues.get(BROKER_LHFX_MT5)
        if not isinstance(hugo, Mt5PaperBrokerVenue) or not isinstance(lhfx, Mt5PaperBrokerVenue):
            raise QuoteReferenceUnavailableError(
                f"{symbol} requires either a provenance-verified independent index_reference_source or dual connected MT5 venues for cross-venue corroboration"
            )
        if hugo.is_offline or lhfx.is_offline:
            raise QuoteReferenceUnavailableError(
                f"dual-MT5 index corroboration unavailable for {symbol} ({STATUS_BROKER_OFFLINE}); admission fails closed"
            )
        try:
            ht = hugo._transport.symbol_tick(symbol)
            lt = lhfx._transport.symbol_tick(symbol)
        except (ContractError, OSError) as exc:
            raise QuoteReferenceUnavailableError(
                f"dual-MT5 index corroboration unavailable for {symbol} ({type(exc).__name__}); admission fails closed"
            ) from None
        tick_sz = _price_tick(symbol)
        cons_bid = ((ht.bid + lt.bid) / Decimal("2")).quantize(tick_sz)
        cons_ask = ((ht.ask + lt.ask) / Decimal("2")).quantize(tick_sz)
        if cons_ask <= cons_bid:
            cons_ask = (cons_bid + tick_sz).quantize(tick_sz)
        cons_q = _validated_quote(symbol, cons_bid, cons_ask, "dual_mt5_consensus")
        check_oracle = OandaQuoteTruthOracle.from_static_quotes({symbol: cons_q}, reference_name="DUAL_MT5_INDEX_CONSENSUS")
        check_oracle.verify_cross_venue_index_quotes(
            symbol=symbol,
            hugo_quote=(ht.bid, ht.ask),
            lhfx_quote=(lt.bid, lt.ask),
            reference_quote=cons_q,
        )
        if target_broker_id == BROKER_HUGOSWAY_MT5:
            peer_rq = ReferenceQuote(
                symbol=symbol,
                bid=lt.bid,
                ask=lt.ask,
                source_provider="CROSS_VENUE_MT5_PEER",
                source_broker_id=BROKER_LHFX_MT5,
                is_independent_public=False,
                observed_at=now_ts,
            )
            peer_rq.assert_corroborates_target(
                BROKER_HUGOSWAY_MT5,
                now=now_ts,
                max_age_seconds=self._index_reference_max_age_seconds,
            )
            peer_oracle = OandaQuoteTruthOracle.from_reference_quotes(
                {symbol: peer_rq},
                reference_name="CROSS_VENUE_MT5_LHFX",
                clock=self._clock,
                max_reference_age_seconds=self._index_reference_max_age_seconds,
            )
            return peer_oracle, {symbol: (peer_rq.bid, peer_rq.ask)}
        if target_broker_id == BROKER_LHFX_MT5:
            peer_rq = ReferenceQuote(
                symbol=symbol,
                bid=ht.bid,
                ask=ht.ask,
                source_provider="CROSS_VENUE_MT5_PEER",
                source_broker_id=BROKER_HUGOSWAY_MT5,
                is_independent_public=False,
                observed_at=now_ts,
            )
            peer_rq.assert_corroborates_target(
                BROKER_LHFX_MT5,
                now=now_ts,
                max_age_seconds=self._index_reference_max_age_seconds,
            )
            peer_oracle = OandaQuoteTruthOracle.from_reference_quotes(
                {symbol: peer_rq},
                reference_name="CROSS_VENUE_MT5_HUGOSWAY",
                clock=self._clock,
                max_reference_age_seconds=self._index_reference_max_age_seconds,
            )
            return peer_oracle, {symbol: (peer_rq.bid, peer_rq.ask)}
        return check_oracle, {symbol: cons_q}

    def _index_venue_worst_entry(self, order: OrderIntent, venue: Mt5PaperBrokerVenue) -> Decimal | None:
        """Compute conservative worst-case MT5 fill price for index stop-risk checks.

        Avoids adding CME/CBOT futures vs cash CFD basis from PUBLIC_US_INDEX_FEED to the
        stop distance while preventing a below-ask BUY limit or above-bid SELL limit from
        understating actual worst-case stop-loss risk.
        """
        if order.symbol not in INDEX_INSTRUMENTS or order.kind is not ActionKind.OPEN:
            return None
        try:
            tick = venue._transport.symbol_tick(order.symbol)
        except (Mt5TransportError, ContractError, OSError) as exc:
            logger.debug("index venue tick lookup skipped for %s/%s: %s", venue.broker_id, order.symbol, type(exc).__name__)
            return None
        if order.side is Side.BUY:
            v_entry = tick.ask
            if order.limit_price is not None:
                v_entry = max(v_entry, order.limit_price)
        else:
            v_entry = tick.bid
            if order.limit_price is not None:
                v_entry = min(v_entry, order.limit_price)
        return v_entry if v_entry > Decimal("0") else None

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

    def unresolved_mutations(self) -> list[dict[str, Any]]:
        """Collect ALL unresolved (OUTCOME_UNKNOWN / PENDING_DISPATCH) mutations across EVERY venue & journal (Finding [1])."""
        found: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str]] = set()

        def _collect_mt5(journal: Any) -> None:
            if journal is None or not hasattr(journal, "list_unresolved_mutations"):
                return
            for row in journal.list_unresolved_mutations():
                key = ("MT5", str(row.get("request_id", "")))
                if key not in seen_keys:
                    seen_keys.add(key)
                    found.append({"journal": "MT5", **dict(row)})

        def _collect_oanda(journal: Any) -> None:
            if journal is None or not hasattr(journal, "list_unresolved_mutations"):
                return
            for row in journal.list_unresolved_mutations():
                key = ("OANDA", str(row.get("client_ext_id", "")))
                if key not in seen_keys:
                    seen_keys.add(key)
                    found.append({"journal": "OANDA", **dict(row)})

        _collect_mt5(self._mt5_mutation_journal)
        _collect_oanda(self._oanda_mutation_journal)
        for venue in self._venues.values():
            if isinstance(venue, Mt5PaperBrokerVenue):
                _collect_mt5(venue.mutation_journal)
            elif isinstance(venue, OandaPracticeFallbackVenue):
                _collect_oanda(venue.mutation_journal)
        return found

    def has_any_unresolved_mutation(self) -> bool:
        """Barbell-wide unresolved mutation predicate across ALL venues and symbols (Finding [1])."""
        return bool(self.unresolved_mutations())

    def assert_no_unresolved_mutations(self, *, context: str = "OPEN") -> None:
        """Barbell-wide pre-dispatch gate blocking ANY new risk while ANY venue/symbol has an unresolved mutation."""
        unresolved = self.unresolved_mutations()
        if not unresolved:
            return
        summary = ", ".join(
            f"{r.get('broker_id') or r.get('account_id') or r.get('journal')}:{r.get('symbol')}:{r.get('request_id') or r.get('client_ext_id')}({r.get('status')})"
            for r in unresolved[:4]
        )
        msg = (
            f"BARBELL_UNRESOLVED_MUTATION_LATCH ({context}): unresolved mutation(s) [{summary}] "
            f"freeze all new-risk dispatches across every venue and symbol until reconciled"
        )
        if any(r.get("journal") == "MT5" for r in unresolved):
            raise Mt5OutcomeUnknownError(msg)
        raise OandaOutcomeUnknownError(msg)

    def _probe_oanda_fresh(self) -> dict[str, Any] | None:
        """Refresh OANDA NAV & margin summary immediately before admission; fail closed if refresh fails (Finding [3])."""
        oanda = self._venues.get(self._oanda_broker_id)
        if not isinstance(oanda, OandaPracticeFallbackVenue):
            return None
        try:
            summary = oanda.probe_account_summary(now=self._clock())
        except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
            raise
        except (PaperBrokerTransportError, Mt5TransportError, ContractError, OSError) as exc:
            self._status[self._oanda_broker_id] = "FAILED"
            self._failures[self._oanda_broker_id] = type(exc).__name__
            if self._last_oanda_reconnect_attempt is None:
                self._last_oanda_reconnect_attempt = self._clock()
            if self._monotonic is not None and self._last_oanda_reconnect_mono is None:
                self._last_oanda_reconnect_mono = float(self._monotonic())
            raise Mt5TransportError(
                f"{self._oanda_broker_id} account summary refresh failed ({type(exc).__name__}); refusing new risk"
            ) from None
        if self._status.get(self._oanda_broker_id) in ("FAILED", STATUS_BROKER_OFFLINE):
            self._status[self._oanda_broker_id] = "ACTIVE"
            self._failures.pop(self._oanda_broker_id, None)
        return summary

    def _online_drawdown_scope_id(self, online_ids: Iterable[str]) -> str:
        joined = "+".join(sorted(str(b) for b in online_ids))
        return f"{self._drawdown_scope_id}:g{self._rearm_gen}:online:{joined}"

    def _has_cold_offline_zero(self, eq_map: Mapping[str, Decimal]) -> bool:
        for broker_id in (self._oanda_broker_id, BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            if self.is_broker_offline(broker_id) and eq_map.get(broker_id, Decimal("0")) <= Decimal("0"):
                return True
        return False

    def equities(
        self,
        *,
        require_fresh_oanda: bool = False,
        require_fresh_mt5: bool = False,
    ) -> dict[str, Decimal]:
        unverified_mt5 = self._sync_mt5_venues_nonblocking(raise_on_mt5_integrity=require_fresh_mt5)
        out: dict[str, Decimal] = {}
        online_out: dict[str, Decimal] = {}
        has_cold_offline_zero = False
        for broker_id in (self._oanda_broker_id, BROKER_HUGOSWAY_MT5, BROKER_LHFX_MT5):
            venue = self._venues.get(broker_id)
            value: Decimal | None = None
            if isinstance(venue, Mt5PaperBrokerVenue):
                if broker_id in unverified_mt5:
                    value = self._last_equity.get(broker_id, self._attestations.get(broker_id, Decimal("0")))
                    out[broker_id] = value
                    continue
                if venue.is_offline:
                    last_conn = venue.last_connected_account
                    if last_conn is not None and (
                        last_conn.equity > Decimal("0") or last_conn.balance > Decimal("0")
                    ):
                        value = last_conn.equity
                    elif self._last_equity.get(broker_id, Decimal("0")) > Decimal("0"):
                        value = self._last_equity[broker_id]
                    else:
                        value = self._attestations.get(broker_id, Decimal("0"))
                        if value <= Decimal("0"):
                            has_cold_offline_zero = True
                    if value > Decimal("0") or broker_id not in self._last_equity:
                        self._last_equity[broker_id] = value
                    out[broker_id] = value
                    continue
                if venue.account is not None:
                    value = venue.account.equity
            elif broker_id == self._oanda_broker_id:
                if require_fresh_oanda:
                    if isinstance(venue, OandaPracticeFallbackVenue):
                        fresh = venue.require_fresh_summary(now=self._clock())
                        value = parse_decimal(str(fresh["nav"]), "nav")
                    elif self.is_broker_offline(broker_id):
                        raise Mt5TransportError(
                            f"{broker_id} account summary unavailable while broker is offline; refusing admission"
                        )
                elif self.is_broker_offline(broker_id):
                    if self._last_equity.get(broker_id, Decimal("0")) > Decimal("0"):
                        value = self._last_equity[broker_id]
                    elif isinstance(venue, OandaPracticeFallbackVenue) and venue.nav is not None and venue.nav > Decimal("0"):
                        value = venue.nav
                    else:
                        value = self._attestations.get(broker_id, Decimal("0"))
                        if value <= Decimal("0"):
                            has_cold_offline_zero = True
                    if value > Decimal("0") or broker_id not in self._last_equity:
                        self._last_equity[broker_id] = value
                    out[broker_id] = value
                    continue
                elif isinstance(venue, OandaPracticeFallbackVenue):
                    value = venue.nav
            if value is None:
                value = self._last_equity.get(broker_id, self._attestations.get(broker_id, Decimal("0")))
            self._last_equity[broker_id] = value
            out[broker_id] = value
            if not self.is_broker_offline(broker_id) and (venue is not None or value > Decimal("0")):
                online_out[broker_id] = value
        if not unverified_mt5:
            now_ts = self._clock()
            total = self.barbell.total_equity(out)
            if not has_cold_offline_zero and total > Decimal("0"):
                self._peak_store.observe_equity(
                    self._drawdown_scope_id,
                    current_equity=total,
                    opening_balance=self._initial_peak_equity if self._initial_peak_equity is not None else total,
                    now=now_ts,
                )
            online_total = self.barbell.total_equity(online_out)
            if online_out and online_total > Decimal("0"):
                self._peak_store.observe_equity(
                    self._online_drawdown_scope_id(online_out.keys()),
                    current_equity=online_total,
                    opening_balance=online_total,
                    now=now_ts,
                )
        return out

    def online_equities(
        self,
        *,
        require_fresh_oanda: bool = False,
        require_fresh_mt5: bool = False,
    ) -> dict[str, Decimal]:
        eq_map = self.equities(
            require_fresh_oanda=require_fresh_oanda,
            require_fresh_mt5=require_fresh_mt5,
        )
        out: dict[str, Decimal] = {}
        for broker_id, val in eq_map.items():
            if self.is_broker_offline(broker_id):
                continue
            if broker_id in self._venues or val > Decimal("0"):
                out[broker_id] = val
        return out

    def online_total_equity(self, *, require_fresh_oanda: bool = False) -> Decimal:
        return self.barbell.total_equity(self.online_equities(require_fresh_oanda=require_fresh_oanda))

    def _resolve_effective_drawdown(
        self,
        *,
        equities: Mapping[str, Decimal] | None = None,
        offline_brokers: Sequence[str] | None = None,
        peak_equity: Decimal | None = None,
        require_fresh_oanda: bool = False,
    ) -> tuple[Decimal, Decimal | None, Decimal, str]:
        eq_map = dict(equities) if equities is not None else self.equities(require_fresh_oanda=require_fresh_oanda)
        total_eq = self.barbell.total_equity(eq_map)
        if peak_equity is not None:
            dd_exp = (
                compute_drawdown_pct(total_eq, peak_equity)
                if (peak_equity > Decimal("0") and total_eq >= Decimal("0"))
                else Decimal("0")
            )
            return total_eq, peak_equity, dd_exp, self._drawdown_scope_id
        offline_ids = list(offline_brokers) if offline_brokers is not None else self.offline_brokers()
        online_eq_map = {
            b: v
            for b, v in eq_map.items()
            if not self.is_broker_offline(b) and (b in self._venues or v > Decimal("0"))
        }
        online_total = self.barbell.total_equity(online_eq_map)
        online_scope = (
            self._online_drawdown_scope_id(online_eq_map.keys())
            if online_eq_map
            else self._drawdown_scope_id
        )
        online_pk = self._peak_store.read_peak(online_scope) if online_eq_map else None
        main_pk = self.peak_equity()
        if self._has_cold_offline_zero(eq_map):
            eff_pk = online_pk if online_pk is not None else (online_total if online_total > Decimal("0") else main_pk)
            dd_cold = (
                compute_drawdown_pct(online_total, eff_pk)
                if (eff_pk is not None and eff_pk > Decimal("0"))
                else Decimal("0")
            )
            eff_scope = (
                online_scope
                if (online_eq_map and (online_pk is not None or online_total > Decimal("0")))
                else self._drawdown_scope_id
            )
            return online_total, eff_pk, dd_cold, eff_scope
        full_dd = (
            compute_drawdown_pct(total_eq, main_pk)
            if (main_pk is not None and main_pk > Decimal("0"))
            else Decimal("0")
        )
        if offline_ids and online_pk is not None and online_pk > Decimal("0"):
            online_dd = compute_drawdown_pct(online_total, online_pk)
            if online_dd > full_dd:
                return online_total, online_pk, online_dd, online_scope
        return total_eq, main_pk, full_dd, self._drawdown_scope_id

    def effective_drawdown_state(
        self,
        *,
        equities: Mapping[str, Decimal] | None = None,
        offline_brokers: Sequence[str] | None = None,
        peak_equity: Decimal | None = None,
        require_fresh_oanda: bool = False,
    ) -> tuple[Decimal, Decimal | None, Decimal]:
        eff_curr, eff_pk, eff_dd, _ = self._resolve_effective_drawdown(
            equities=equities,
            offline_brokers=offline_brokers,
            peak_equity=peak_equity,
            require_fresh_oanda=require_fresh_oanda,
        )
        return eff_curr, eff_pk, eff_dd

    def effective_drawdown_scope_id(
        self,
        *,
        equities: Mapping[str, Decimal] | None = None,
        offline_brokers: Sequence[str] | None = None,
    ) -> str:
        _, _, _, eff_scope = self._resolve_effective_drawdown(
            equities=equities,
            offline_brokers=offline_brokers,
        )
        return eff_scope

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
        rearmed = self._peak_store.rearm_after_drawdown(
            self._drawdown_scope_id,
            new_peak_equity=new_peak_equity,
            owner_verifier=owner_verifier,
            owner_request_id=owner_request_id,
            fence_request=fence_request,
            now=now or self._clock(),
        )
        self._rearm_gen += 1
        return rearmed

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

    def check_open_eligibility(
        self,
        symbol: str,
        *,
        equities: Mapping[str, Decimal] | None = None,
        peak_equity: Decimal | None = None,
    ) -> tuple[bool, str]:
        """Fast deterministic zero-API-cost guard before paid LLM inference."""
        if self.has_any_unresolved_mutation():
            return False, "UNRESOLVED_MUTATION_LATCH"
        if equities is None and isinstance(self._venues.get(self._oanda_broker_id), OandaPracticeFallbackVenue):
            try:
                self._probe_oanda_fresh()
            except (Mt5TransportError, PaperBrokerTransportError, ContractError, OSError) as exc:
                return False, f"{self._oanda_broker_id}=ACCOUNT_REFRESH_FAILED:{type(exc).__name__}"
        eq = dict(equities) if equities is not None else self.equities(
            require_fresh_oanda=isinstance(self._venues.get(self._oanda_broker_id), OandaPracticeFallbackVenue)
        )
        eff_curr, eff_pk, _ = self.effective_drawdown_state(equities=eq, peak_equity=peak_equity)
        try:
            self.barbell.require_drawdown(current_equity=eff_curr, peak_equity=eff_pk)
        except BarbellPolicyRefusalError as exc:
            return False, f"DRAWDOWN_BLOCKED:{exc.reason}"
        reasons: list[str] = []
        for broker_id in self._offshore_route():
            venue = self._venues.get(broker_id)
            if not isinstance(venue, Mt5PaperBrokerVenue):
                reasons.append(f"{broker_id}=NOT_CONNECTED")
                continue
            if venue.is_offline or self.is_broker_offline(broker_id):
                self._status[broker_id] = STATUS_BROKER_OFFLINE
                reasons.append(f"{broker_id}={STATUS_BROKER_OFFLINE}")
                continue
            used_m = venue.account.margin if venue.account is not None else Decimal("0")
            try:
                self.barbell.require_sleeve(broker_id, equities=eq, used_margin_after=used_m)
                return True, f"ELIGIBLE:{broker_id}"
            except BarbellPolicyRefusalError as exc:
                reasons.append(f"{broker_id}={exc.reason}")
        allow_oanda_idx = str(self._env.get("CAS_FOREX_OANDA_ALLOW_INDEX_CFD", "")).strip().lower() in ("1", "true", "yes")
        if symbol in INDEX_INSTRUMENTS and not allow_oanda_idx:
            reasons.append(f"{self._oanda_broker_id}=INDEX_CFD_RESTRICTED")
            return False, "; ".join(reasons)
        oanda = self._venues.get(self._oanda_broker_id)
        if not isinstance(oanda, OandaPracticeFallbackVenue):
            reasons.append(f"{self._oanda_broker_id}=NOT_CONNECTED")
            return False, "; ".join(reasons)
        avail = oanda.margin_available
        nav = oanda.nav
        if avail is None or nav is None or avail <= Decimal("0"):
            reasons.append(f"{self._oanda_broker_id}=MARGIN_UNAVAILABLE")
            return False, "; ".join(reasons)
        try:
            self.barbell.require_sleeve(self._oanda_broker_id, equities=eq, used_margin_after=max(Decimal("0"), nav - avail))
            return True, f"ELIGIBLE:{self._oanda_broker_id}"
        except BarbellPolicyRefusalError as exc:
            reasons.append(f"{self._oanda_broker_id}={exc.reason}")
            return False, "; ".join(reasons)

    def set_demo_high_growth_profile(self, profile: DemoHighGrowthProfile) -> None:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise ContractError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )
        self.barbell.apply_demo_high_growth_profile(
            profile,
            execution_mode=self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )
        self._valve_gate.set_demo_high_growth_profile(
            profile,
            execution_mode=self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )

    def execute_open(
        self,
        order: OrderIntent | RiskIncreasingOrderIntent,
        *,
        valve_decision: ValveDecision,
    ) -> DualShieldExecution:
        self.barbell.demo_high_growth.assert_demo_mode(
            self.execution_mode,
            live_trading_armed=self._live_armed,
            live_trading_locked=not bool(self._live_armed),
        )
        if isinstance(order, RiskIncreasingOrderIntent):
            order = order.order
        if not isinstance(order, OrderIntent) or order.kind is not ActionKind.OPEN:
            raise ContractError("execute_open requires an OPEN OrderIntent; use execute_management otherwise")
        require_valve_clearance(
            order,
            valve_decision,
            expected_weights_sha256=self._valve_gate.weights_sha256,
            now=self._clock(),
            require_risk_reducing=False,
        )
        # Finding [1]: Barbell-wide unresolved-mutation latch checked before ANY new risk across every venue & symbol.
        self.assert_no_unresolved_mutations(context="OPEN")
        # Finding [3] & [8]: Refresh OANDA + MT5 snapshots & ticks immediately before admission; fail closed.
        self._probe_oanda_fresh()
        self._probe_mt5_fresh(symbol=order.symbol)
        if order.symbol in INDEX_INSTRUMENTS:
            oracle, reference = self._index_reference_quotes(order.symbol)
        else:
            oracle = self.oracle()
            reference = oracle.reference_quotes(
                tuple(dict.fromkeys(
                    self.barbell.quote_conversion_symbols(order.symbol)
                    + self._safe_harbor_calc.required_symbols(order.symbol)
                ))
            )
        rbid, rask = reference[order.symbol]
        entry = rask if order.side is Side.BUY else rbid
        if order.symbol in INDEX_INSTRUMENTS:
            cand_entries: list[Decimal] = []
            for cand_bid in self._offshore_route():
                cand_venue = self._venues.get(cand_bid)
                if isinstance(cand_venue, Mt5PaperBrokerVenue) and not cand_venue.is_offline:
                    v_entry = self._index_venue_worst_entry(order, cand_venue)
                    if v_entry is not None:
                        cand_entries.append(v_entry)
            if cand_entries:
                entry = min(cand_entries) if order.side is Side.BUY else max(cand_entries)
        equities = self.equities(require_fresh_oanda=True, require_fresh_mt5=True)
        eff_curr, eff_pk, _ = self.effective_drawdown_state(equities=equities)
        self.barbell.require_drawdown(current_equity=eff_curr, peak_equity=eff_pk)
        risk = self.barbell.stop_loss_risk(
            symbol=order.symbol,
            units=order.quantity_units,  # type: ignore[arg-type]
            entry_price=entry,
            stop_price=order.stop_price,  # type: ignore[arg-type]
            quotes=reference,
        )
        online_eq = {
            b: v
            for b, v in equities.items()
            if not self.is_broker_offline(b) and (b in self._venues or v > Decimal("0"))
        }
        cap = self.barbell.require_stop_risk(risk, online_eq)
        trail: list[dict[str, Any]] = []
        verdicts: list[QuoteTruthVerdict] = []

        for broker_id in self._offshore_route():
            venue = self._venues.get(broker_id)
            if not isinstance(venue, Mt5PaperBrokerVenue):
                self._record(trail, broker_id, "NOT_CONFIGURED" if not self.is_configured(broker_id) else "NOT_CONNECTED", None)
                continue
            try:
                venue.probe()
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError, Mt5SnapshotIntegrityError):
                raise
            except (Mt5TransportError, OSError) as exc:
                self._status[broker_id] = "DISCONNECTED"
                self._record(trail, broker_id, "DISCONNECTED", type(exc).__name__)
                continue
            if venue.is_offline:
                self._status[broker_id] = STATUS_BROKER_OFFLINE
                self._failures[broker_id] = STATUS_BROKER_OFFLINE
                self._record(trail, broker_id, STATUS_BROKER_OFFLINE, "TERMINAL_DISCONNECTED")
                continue
            self._status[broker_id] = "ACTIVE"
            if self._failures.get(broker_id) == STATUS_BROKER_OFFLINE:
                self._failures.pop(broker_id, None)
            equities = self.equities(require_fresh_oanda=True, require_fresh_mt5=True)

            def margin_guard(check: Mt5MarginCheck, _account: Mt5AccountSnapshot, _b: str = broker_id) -> None:
                self.barbell.require_sleeve(_b, equities=equities, used_margin_after=check.used_margin_after)

            venue_risk = risk
            venue_cap = cap
            if order.symbol in INDEX_INSTRUMENTS:
                broker_oracle, broker_ref = self._index_reference_quotes(order.symbol, target_broker_id=broker_id)
                eff_quote_guard = broker_oracle.guard(broker_ref, verdicts)
                venue_entry = self._index_venue_worst_entry(order, venue) or entry
                venue_online_eq = {
                    b: v
                    for b, v in equities.items()
                    if not self.is_broker_offline(b) and (b in self._venues or v > Decimal("0"))
                }
                venue_risk = self.barbell.stop_loss_risk(
                    symbol=order.symbol,
                    units=order.quantity_units,  # type: ignore[arg-type]
                    entry_price=venue_entry,
                    stop_price=order.stop_price,  # type: ignore[arg-type]
                    quotes=broker_ref,
                )
            else:
                eff_quote_guard = oracle.guard(reference, verdicts)
                venue_online_eq = online_eq
            try:
                if order.symbol in INDEX_INSTRUMENTS:
                    venue_cap = self.barbell.require_stop_risk(venue_risk, venue_online_eq)
                result = venue.execute(
                    order,
                    valve_decision=valve_decision,
                    quote_guard=eff_quote_guard,
                    margin_guard=margin_guard,
                    allowed_actions=frozenset({ActionKind.OPEN}),
                    require_risk_reducing=False,
                )
            except (
                Mt5OutcomeUnknownError,
                OandaOutcomeUnknownError,
                Mt5PostFillObservationError,
                LiveAuthorizationError,
                LiveBrokerEndpointForbiddenError,
            ):
                # Finding [4] & [6]: Never failover on OutcomeUnknown, post-fill observation failure, or LIVE auth failure.
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
            except Mt5PreDispatchTransportError as exc:
                # Finding [4]: Failover allowlist permits ONLY explicit pre-dispatch connectivity/refusal errors.
                if STATUS_BROKER_OFFLINE in str(exc) or venue.is_offline:
                    self._status[broker_id] = STATUS_BROKER_OFFLINE
                    self._failures[broker_id] = STATUS_BROKER_OFFLINE
                    self._record(trail, broker_id, STATUS_BROKER_OFFLINE, "TERMINAL_DISCONNECTED")
                else:
                    self._status[broker_id] = "DISCONNECTED"
                    self._record(trail, broker_id, "DISCONNECTED", type(exc).__name__)
                continue
            except Mt5TransportError:
                self._record(trail, broker_id, "POST_DISPATCH_TRANSPORT_ERROR", "never re-routed")
                raise
            if result.receipt is not None and not result.receipt.accepted:
                rej_msg = f"retcode={result.receipt.retcode}: {result.receipt.message}"[:120]
                self._record(trail, broker_id, "BROKER_REJECTED", rej_msg)
                continue
            self._record(trail, broker_id, "EXECUTED", "RECONCILIATION_REQUIRED" if result.reconciliation_required else None)
            return DualShieldExecution(
                result=result, executed_on=broker_id, safe_harbor=False, trail=tuple(trail),
                quote_verdicts=tuple(verdicts), stop_loss_risk=venue_risk, stop_loss_risk_cap=venue_cap,
            )

        if order.symbol in INDEX_INSTRUMENTS and str(self._env.get("CAS_FOREX_OANDA_ALLOW_INDEX_CFD", "")).strip().lower() not in ("1", "true", "yes"):
            self._record(trail, self._oanda_broker_id, "INDEX_CFD_RESTRICTED", "US-regulated OANDA index CFDs restricted")
            raise BrokerFailoverExhaustedError(
                f"offshore MT5 venues refused/unavailable for {order.symbol}; US-regulated OANDA restricts index CFDs (fail closed)"
            )
        oanda = self._venues.get(self._oanda_broker_id)
        if not isinstance(oanda, OandaPracticeFallbackVenue):
            self._record(trail, self._oanda_broker_id, "NOT_CONNECTED", None)
            raise BrokerFailoverExhaustedError(
                "offshore venues refused/unavailable and the OANDA safe harbor is not connected: "
                + "; ".join(f"{t['broker_id']}={t['outcome']}" for t in trail)
            )
        # Finding [3]: Probe OANDA summary fresh immediately before safe-harbor margin & sleeve admission.
        fresh_summary = self._probe_oanda_fresh()
        if fresh_summary is None:
            fresh_summary = oanda.require_fresh_summary(now=self._clock())
        required = self._safe_harbor_calc.required_margin(
            order.symbol, order.side, order.quantity_units, reference  # type: ignore[arg-type]
        )
        available = parse_decimal(str(fresh_summary["margin_available"]), "margin_available")
        nav = parse_decimal(str(fresh_summary["nav"]), "nav")
        if required > available:
            self._record(trail, self._oanda_broker_id, "MARGIN_REFUSED", "safe-harbor margin unavailable")
            raise Mt5MarginRefusalError("OANDA safe harbor lacks margin for this order at 1:50")
        fresh_equities = self.equities(require_fresh_oanda=True, require_fresh_mt5=True)
        sh_curr, sh_pk, _ = self.effective_drawdown_state(equities=fresh_equities)
        self.barbell.require_drawdown(current_equity=sh_curr, peak_equity=sh_pk)
        self.barbell.require_sleeve(
            self._oanda_broker_id, equities=fresh_equities, used_margin_after=(nav - available) + required
        )
        result = oanda.execute(
            order,
            valve_decision=valve_decision,
            allowed_actions=frozenset({ActionKind.OPEN}),
            require_risk_reducing=False,
        )
        self._record(trail, self._oanda_broker_id, "EXECUTED", "SAFE_HARBOR")
        return DualShieldExecution(
            result=result, executed_on=self._oanda_broker_id, safe_harbor=True, trail=tuple(trail),
            quote_verdicts=tuple(verdicts), stop_loss_risk=risk, stop_loss_risk_cap=cap,
        )

    def execute_management(
        self,
        broker_id: str,
        order: OrderIntent | RiskReducingOrderIntent,
        *,
        valve_decision: ValveDecision,
    ) -> Mt5ExecutionResult:
        """AMEND_STOP is quote-truth checked (anti-stop-hunt); REDUCE/CLOSE always reach the venue.

        Strictly refuses risk-increasing actions (OPEN/ADD) at router, valve clearance, and venue sink (Finding [10]).
        """
        if isinstance(order, RiskIncreasingOrderIntent):
            raise ContractError("execute_management refuses RiskIncreasingOrderIntent (OPEN/ADD); use execute_open")
        if isinstance(order, RiskReducingOrderIntent):
            order = order.order
        if not isinstance(order, OrderIntent):
            raise ContractError("execute_management requires a management OrderIntent (AMEND_STOP, REDUCE, or CLOSE)")
        if order.kind in RISK_INCREASING_ACTION_KINDS or order.kind not in MANAGEMENT_ACTION_KINDS:
            raise ContractError(
                f"execute_management refuses risk-increasing/non-management action {order.kind.value!r}; use execute_open"
            )
        require_valve_clearance(
            order,
            valve_decision,
            expected_weights_sha256=self._valve_gate.weights_sha256,
            now=self._clock(),
            require_risk_reducing=True,
        )
        venue = self._venues.get(broker_id)
        if venue is None:
            raise Mt5TransportError(f"{broker_id} is not connected")
        if not isinstance(venue, Mt5PaperBrokerVenue):
            return venue.execute(
                order,
                valve_decision=valve_decision,
                allowed_actions=MANAGEMENT_ACTION_KINDS,
                require_risk_reducing=True,
            )
        if order.kind is ActionKind.AMEND_STOP:
            if order.symbol in INDEX_INSTRUMENTS:
                idx_oracle, idx_ref = self._index_reference_quotes(order.symbol, target_broker_id=broker_id)
                guard = idx_oracle.guard(reference=idx_ref)
            else:
                guard = self.oracle().guard()
        else:
            guard = None
        return venue.execute(
            order,
            valve_decision=valve_decision,
            quote_guard=guard,
            allowed_actions=MANAGEMENT_ACTION_KINDS,
            require_risk_reducing=True,
        )

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
        if venue.is_offline:
            self._status[broker_id] = STATUS_BROKER_OFFLINE
            self._failures[broker_id] = STATUS_BROKER_OFFLINE
            self._record([], broker_id, STATUS_BROKER_OFFLINE, "TERMINAL_DISCONNECTED")
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

    def _is_live_mt5_server_staged(self, broker_id: str, server_env_key: str) -> bool:
        raw = str(self._env.get(server_env_key, "")).strip()
        if not raw and self.execution_mode == EXECUTION_MODE_LIVE:
            raw = str(self._servers.get(broker_id) or "").strip()
        if not raw or raw.upper().startswith("REPLACE_WITH_"):
            return False
        low = raw.lower()
        if "demo" in low or "practice" in low:
            return False
        compact = re.sub(r"[\s_]+", " ", low)
        if broker_id == BROKER_HUGOSWAY_MT5:
            return compact in _LIVE_HUGOSWAY_SERVERS
        if broker_id == BROKER_LHFX_MT5:
            if compact in {"lhfxsa-trade", "lhfxsa trade"} and self.execution_mode != EXECUTION_MODE_LIVE:
                return False
            return compact in _LIVE_LHFX_SERVERS
        return False

    def live_funding_readiness(self, *, equities: Mapping[str, Decimal] | None = None) -> dict[str, Any]:
        """Return secret-free 5-gate readiness status for Real-Money LIVE funding & arming."""
        oanda_acct_ok = _has_staged_env_value(self._env, ENV_OANDA_LIVE_ACCOUNT_ID)
        oanda_tok_ok = (
            _has_staged_env_value(self._env, ENV_OANDA_LIVE_API_TOKEN)
            or _has_staged_env_value(self._env, ENV_OANDA_LIVE_TOKEN)
        )
        hugo_ok = (
            _has_staged_env_value(self._env, ENV_HUGOSWAY_MT5_LOGIN)
            and self._is_live_mt5_server_staged(BROKER_HUGOSWAY_MT5, ENV_HUGOSWAY_MT5_SERVER)
        )
        lhfx_ok = (
            _has_staged_env_value(self._env, ENV_LHFX_MT5_LOGIN)
            and self._is_live_mt5_server_staged(BROKER_LHFX_MT5, ENV_LHFX_MT5_SERVER)
        )
        gate1_passed = bool(oanda_acct_ok and oanda_tok_ok and hugo_ok and lhfx_ok)
        missing_g1: list[str] = []
        if not (oanda_acct_ok and oanda_tok_ok):
            missing_g1.append("OANDA_LIVE")
        if not hugo_ok:
            missing_g1.append("HUGOSWAY_MT5")
        if not lhfx_ok:
            missing_g1.append("LHFX_MT5")
        gate1_detail = (
            "OANDA Live + Hugo's Way + LHFX live endpoints staged."
            if gate1_passed
            else f"Pending live venue staging: {', '.join(missing_g1)}."
        )

        hugo_tkt_ok = _has_staged_env_value(self._env, ENV_HUGOSWAY_MT5_LIVE_TICKET)
        lhfx_tkt_ok = _has_staged_env_value(self._env, ENV_LHFX_MT5_LIVE_TICKET)
        oanda_tkt_ok = _has_staged_env_value(self._env, ENV_OANDA_LIVE_TICKET)
        gate2_passed = bool(hugo_tkt_ok and lhfx_tkt_ok and oanda_tkt_ok)
        missing_g2: list[str] = []
        if not hugo_tkt_ok:
            missing_g2.append("HUGOSWAY_MT5")
        if not lhfx_tkt_ok:
            missing_g2.append("LHFX_MT5")
        if not oanda_tkt_ok:
            missing_g2.append("OANDA_LIVE")
        gate2_detail = (
            "All 3 owner Ed25519 live tickets staged."
            if gate2_passed
            else f"Pending owner Ed25519 live tickets: {', '.join(missing_g2)}."
        )

        eq_map = dict(equities) if equities is not None else self.equities()
        total_eq = self.barbell.total_equity(eq_map)
        tol = self.barbell.allocation_tolerance_share
        if self.barbell.demo_virtual_sleeve:
            gate3_passed = False
            gate3_detail = "Demo virtual sleeve active; set CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE=0 for LIVE."
        elif total_eq > Decimal("0"):
            alloc_rows = self.barbell.allocation_report(eq_map)["venues"]
            drifted = [
                f"{row['broker_id']} ({row['actual_share']} vs {row['target_share']})"
                for row in alloc_rows
                if abs(Decimal(str(row["actual_share"])) - Decimal(str(row["target_share"]))) > tol
            ]
            gate3_passed = len(drifted) == 0
            gate3_detail = (
                f"Real 80/12/8 barbell custody verified across ${decimal_text(total_eq)}."
                if gate3_passed
                else f"Barbell custody outside +/-{decimal_text(tol)} tolerance: {', '.join(drifted)}."
            )
        else:
            gate3_passed = True
            gate3_detail = (
                f"Real 80/12/8 barbell policy active (virtual sleeve off; +/-{decimal_text(tol)} tolerance)."
            )

        valve_ok = self._valve_gate is not None
        mt5_db_ok = (
            self._mt5_mutation_journal is not None
            and getattr(self._mt5_mutation_journal, "db_path", None) is not None
        )
        oanda_db_ok = (
            True
            if self._oanda_mutation_journal is None
            else getattr(self._oanda_mutation_journal, "db_path", None) is not None
        )
        gate4_passed = bool(valve_ok and mt5_db_ok and oanda_db_ok)
        gate4_detail = (
            "ForexMetaValveGate active with durable SQLite WAL mutation journals."
            if gate4_passed
            else "Requires ForexMetaValveGate and durable SQLite paths on mutation journals."
        )

        gate5_passed = bool(self.execution_mode == EXECUTION_MODE_LIVE and bool(self._live_armed))
        gate5_detail = (
            "Two-key LIVE execution mode armed and verified."
            if gate5_passed
            else f"Currently in {self.execution_mode} mode; two-key LIVE arming is disarmed."
        )

        gates: list[dict[str, Any]] = [
            {
                "id": "LIVE_CREDENTIALS_STAGED",
                "step": 1,
                "title": "Live OANDA + Hugo's Way + LHFX Endpoints Staged",
                "passed": gate1_passed,
                "detail": gate1_detail,
            },
            {
                "id": "OWNER_ED25519_LIVE_TICKETS",
                "step": 2,
                "title": "Owner Ed25519 Live Authorization Tickets Staged",
                "passed": gate2_passed,
                "detail": gate2_detail,
            },
            {
                "id": "REAL_BARBELL_80_12_8_CUSTODY",
                "step": 3,
                "title": "Real 80% / 12% / 8% Barbell Custody Active",
                "passed": gate3_passed,
                "detail": gate3_detail,
            },
            {
                "id": "VALVE_AND_DURABLE_JOURNALS",
                "step": 4,
                "title": "ForexMetaValveGate & Durable SQLite Journals Ready",
                "passed": gate4_passed,
                "detail": gate4_detail,
            },
            {
                "id": "TWO_KEY_LIVE_ARMED",
                "step": 5,
                "title": "Two-Key Real-Money LIVE Mode Armed",
                "passed": gate5_passed,
                "detail": gate5_detail,
            },
        ]
        out: dict[str, Any] = {
            "execution_mode": self.execution_mode,
            "live_armed": bool(self._live_armed),
            "required_arm_phrase": LIVE_FUNDING_ARM_PHRASE,
            "gates": gates,
            "all_gates_ready": all(bool(g["passed"]) for g in gates),
        }
        assert_safe_json_numbers(out)
        return out

    def routing_snapshot(self) -> dict[str, Any]:
        eq_map = self.equities()
        offline_list = [broker_id for broker_id in self.priority_order if self.is_broker_offline(broker_id)]
        online_eq_map = {
            broker_id: val
            for broker_id, val in eq_map.items()
            if not self.is_broker_offline(broker_id) and (broker_id in self._venues or val > Decimal("0"))
        }
        online_total = self.barbell.total_equity(online_eq_map)
        _, eff_pk, eff_dd = self.effective_drawdown_state(equities=eq_map, offline_brokers=offline_list)
        snap = super().routing_snapshot()
        try:
            oracle_cfg = self.oracle().config_dict()
        except QuoteReferenceUnavailableError:
            oracle_cfg = OandaQuoteTruthOracle.from_static_quotes({}, reference_name="UNAVAILABLE").config_dict()
        snap["schema"] = "cas-forex.broker-routing/2"
        snap["architecture"] = "DUAL_SHIELD_BARBELL"
        alloc = self.barbell.allocation_report(eq_map)
        peak_eq = self.peak_equity()
        shown_pk = peak_eq if peak_eq is not None else eff_pk
        alloc["peak_equity"] = None if shown_pk is None else decimal_text(shown_pk)
        alloc["drawdown_pct"] = (
            "0"
            if eff_dd <= Decimal("0")
            else decimal_text(eff_dd.quantize(Decimal("0.0001")))
        )
        alloc["offline_brokers"] = offline_list
        alloc["online_equity"] = decimal_text(online_total)
        alloc["equity_incomplete"] = len(offline_list) > 0
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
        snap["live_readiness"] = self.live_funding_readiness(equities=eq_map)
        assert_safe_json_numbers(snap)
        return snap

    def reconcile_unknown_mutations(self, *, now: datetime | None = None) -> dict[str, Any]:
        """Reconcile any persisted OUTCOME_UNKNOWN/PENDING_DISPATCH MT5 latches per online venue."""
        ts = self._clock() if now is None else utc_time(now, "now")
        per_venue: dict[str, Any] = {}
        total_checked = 0
        total_resolved = 0
        for broker_id in self.priority_order:
            venue = self._venues.get(broker_id)
            if not isinstance(venue, Mt5PaperBrokerVenue):
                continue
            try:
                res = venue.reconcile_unknown_mutations(now=ts)
            except (LiveBrokerEndpointForbiddenError, LiveAuthorizationError):
                raise
            except (Mt5TransportError, ContractError, PaperBrokerTransportError, OSError) as exc:
                per_venue[broker_id] = {"error": type(exc).__name__}
                continue
            per_venue[broker_id] = dict(res)
            total_checked += int(res.get("checked", 0))
            total_resolved += int(res.get("resolved", 0))
        remaining = self.unresolved_mutations()
        return {
            "checked": total_checked,
            "resolved": total_resolved,
            "remaining_unknown": len(remaining),
            "has_unresolved_mutation": bool(remaining),
            "venues": per_venue,
        }
