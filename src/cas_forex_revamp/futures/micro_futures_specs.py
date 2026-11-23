"""CME Micro Futures Contract Specifications, Front-Month Roll Resolver & Constitutional Sizing Engine.

Exact Decimal arithmetic only (zero float money), fail-closed constitutional ceilings
(PR #25 Finding [5]), and zero `assert` statements (Bandit B101 clean).
"""
from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import (
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    ROUND_HALF_DOWN,
    ROUND_HALF_EVEN,
    ROUND_HALF_UP,
    ROUND_UP,
    Decimal,
    localcontext,
)
import re
from types import MappingProxyType
from typing import Final, Mapping

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.risk.demo_high_growth_profile import DEMO_HIGH_GROWTH_MAX_RISK_PCT

# Constitutional risk & margin ceilings (PR #25 Finding [5])
MAX_CONSTITUTIONAL_STOP_RISK_PCT: Final[Decimal] = Decimal("1.00")
MAX_CONSTITUTIONAL_DRAWDOWN_PCT: Final[Decimal] = Decimal("0.10")
DEFAULT_MIN_MARGIN_LEVEL_PCT: Final[Decimal] = Decimal("1000.0")
DEFAULT_ROLL_BUFFER_DAYS: Final[int] = 7

# Exact CME Globex futures delivery month codes
MONTH_CODE_MAP: Final[Mapping[int, str]] = MappingProxyType(
    {
        1: "F",
        2: "G",
        3: "H",
        4: "J",
        5: "K",
        6: "M",
        7: "N",
        8: "Q",
        9: "U",
        10: "V",
        11: "X",
        12: "Z",
    }
)
CODE_TO_MONTH_MAP: Final[Mapping[str, int]] = MappingProxyType(
    {code: month for month, code in MONTH_CODE_MAP.items()}
)

_ZERO: Final[Decimal] = Decimal("0")
_ONE_HUNDRED: Final[Decimal] = Decimal("100")
_CENT: Final[Decimal] = Decimal("0.01")
_PCT_QUANT: Final[Decimal] = Decimal("0.0001")
_ALLOWED_ROUNDING_MODES: Final[frozenset[str]] = frozenset(
    {
        ROUND_CEILING,
        ROUND_DOWN,
        ROUND_FLOOR,
        ROUND_HALF_DOWN,
        ROUND_HALF_EVEN,
        ROUND_HALF_UP,
        ROUND_UP,
    }
)
_CONTRACT_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"^([A-Z]{2,5})([FGHJKMNQUVXZ])(\d{1}|\d{2}|\d{4})$"
)
_EXPIRY_RULE_THIRD_FRIDAY: Final[str] = "THIRD_FRIDAY"
_EXPIRY_RULE_THIRD_LAST_BUSINESS_DAY: Final[str] = "THIRD_LAST_BUSINESS_DAY"
_VALID_EXPIRY_RULES: Final[frozenset[str]] = frozenset(
    {_EXPIRY_RULE_THIRD_FRIDAY, _EXPIRY_RULE_THIRD_LAST_BUSINESS_DAY}
)


class MicroFuturesError(ContractError):
    """Base fail-closed error for CME micro futures specifications and sizing."""


class UnsupportedMicroFuturesSymbolError(MicroFuturesError):
    """Raised when a symbol or contract code is not a supported CME micro future."""


class ExpiredFuturesContractError(MicroFuturesError):
    """Raised when a futures contract is expired or inside its pre-expiry roll lockout."""


class MicroFuturesSizingRefusalError(MicroFuturesError):
    """Raised when a whole-contract order cannot satisfy constitutional risk or margin rules."""


def _require_decimal(
    value: object,
    field_name: str,
    *,
    allow_zero: bool = False,
    allow_negative: bool = False,
    error_cls: type[MicroFuturesError] = MicroFuturesError,
) -> Decimal:
    if isinstance(value, bool):
        raise error_cls(f"{field_name} must be an exact Decimal, not bool")
    if isinstance(value, float):
        raise error_cls(f"{field_name} must be an exact Decimal, not float")
    if not isinstance(value, Decimal):
        raise error_cls(f"{field_name} must be an exact Decimal, got {type(value).__name__}")
    if not value.is_finite():
        raise error_cls(f"{field_name} must be a finite Decimal")
    if not allow_negative and value < _ZERO:
        raise error_cls(f"{field_name} must be non-negative, got {value}")
    if not allow_zero and value == _ZERO:
        raise error_cls(f"{field_name} must be strictly positive, got {value}")
    return value


def _require_int(
    value: object,
    field_name: str,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
    error_cls: type[MicroFuturesError] = MicroFuturesError,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise error_cls(f"{field_name} must be an int, got {type(value).__name__}")
    if min_value is not None and value < min_value:
        raise error_cls(f"{field_name} must be >= {min_value}, got {value}")
    if max_value is not None and value > max_value:
        raise error_cls(f"{field_name} must be <= {max_value}, got {value}")
    return value


def _require_utc_datetime(value: datetime | None, *, field_name: str = "as_of_utc") -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise MicroFuturesError(f"{field_name} must be a datetime instance")
    if value.tzinfo is None or value.utcoffset() is None:
        raise MicroFuturesError(
            f"{field_name} must be timezone-aware UTC (naive datetime rejected)"
        )
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class MicroFuturesContractSpec:
    """Immutable specification for a CME Group US-regulated micro futures contract."""

    root: str
    name: str
    cas_symbol: str
    exchange: str
    point_value_usd: Decimal
    tick_size: Decimal
    tick_value_usd: Decimal
    roll_months: tuple[int, ...]
    default_intraday_margin_usd: Decimal
    default_exchange_initial_margin_usd: Decimal
    default_round_turn_commission_usd: Decimal
    cas_aliases: tuple[str, ...]
    expiry_rule: str = _EXPIRY_RULE_THIRD_FRIDAY

    def __post_init__(self) -> None:
        if not self.root or self.root != self.root.upper():
            raise MicroFuturesError(f"root must be non-empty uppercase, got {self.root!r}")
        if not self.name:
            raise MicroFuturesError("name must be non-empty")
        if not self.cas_symbol or self.cas_symbol != self.cas_symbol.upper():
            raise MicroFuturesError(f"cas_symbol must be non-empty uppercase, got {self.cas_symbol!r}")
        if not self.exchange:
            raise MicroFuturesError("exchange must be non-empty")
        _require_decimal(self.point_value_usd, "point_value_usd")
        _require_decimal(self.tick_size, "tick_size")
        _require_decimal(self.tick_value_usd, "tick_value_usd")
        if (self.point_value_usd * self.tick_size) != self.tick_value_usd:
            raise MicroFuturesError(
                f"{self.root} tick_value_usd ({self.tick_value_usd}) must equal "
                f"point_value_usd ({self.point_value_usd}) * tick_size ({self.tick_size})"
            )
        _require_decimal(self.default_intraday_margin_usd, "default_intraday_margin_usd")
        _require_decimal(
            self.default_exchange_initial_margin_usd,
            "default_exchange_initial_margin_usd",
        )
        _require_decimal(
            self.default_round_turn_commission_usd,
            "default_round_turn_commission_usd",
            allow_zero=True,
        )
        if not self.roll_months:
            raise MicroFuturesError(f"{self.root} roll_months must be non-empty")
        if tuple(sorted(set(self.roll_months))) != self.roll_months:
            raise MicroFuturesError(f"{self.root} roll_months must be strictly sorted and unique")
        for month in self.roll_months:
            if month not in MONTH_CODE_MAP:
                raise MicroFuturesError(f"{self.root} has invalid roll month: {month}")
        if self.cas_symbol not in self.cas_aliases:
            raise MicroFuturesError(
                f"{self.root} primary cas_symbol {self.cas_symbol!r} must be in cas_aliases"
            )
        if self.root not in self.cas_aliases:
            raise MicroFuturesError(f"{self.root} root must be in cas_aliases")
        if self.expiry_rule not in _VALID_EXPIRY_RULES:
            raise MicroFuturesError(f"{self.root} unsupported expiry_rule: {self.expiry_rule!r}")

    @property
    def roll_month_codes(self) -> tuple[str, ...]:
        """CME month letter codes for this contract's active roll cycle."""
        return tuple(MONTH_CODE_MAP[m] for m in self.roll_months)


CME_MICRO_FUTURES_SPECS: Final[Mapping[str, MicroFuturesContractSpec]] = MappingProxyType(
    {
        "MNQ": MicroFuturesContractSpec(
            root="MNQ",
            name="Micro E-mini Nasdaq-100",
            cas_symbol="NAS100",
            exchange="CME",
            point_value_usd=Decimal("2.00"),
            tick_size=Decimal("0.25"),
            tick_value_usd=Decimal("0.50"),
            roll_months=(3, 6, 9, 12),
            default_intraday_margin_usd=Decimal("100.00"),
            default_exchange_initial_margin_usd=Decimal("2200.00"),
            default_round_turn_commission_usd=Decimal("1.24"),
            cas_aliases=("NAS100", "USTEC", "US100", "NDX", "MNQ"),
            expiry_rule=_EXPIRY_RULE_THIRD_FRIDAY,
        ),
        "MYM": MicroFuturesContractSpec(
            root="MYM",
            name="Micro E-mini Dow",
            cas_symbol="US30",
            exchange="CBOT",
            point_value_usd=Decimal("0.50"),
            tick_size=Decimal("1.00"),
            tick_value_usd=Decimal("0.50"),
            roll_months=(3, 6, 9, 12),
            default_intraday_margin_usd=Decimal("50.00"),
            default_exchange_initial_margin_usd=Decimal("1100.00"),
            default_round_turn_commission_usd=Decimal("1.24"),
            cas_aliases=("US30", "DJ30", "DJI", "MYM"),
            expiry_rule=_EXPIRY_RULE_THIRD_FRIDAY,
        ),
        "MES": MicroFuturesContractSpec(
            root="MES",
            name="Micro E-mini S&P 500",
            cas_symbol="SPX500",
            exchange="CME",
            point_value_usd=Decimal("5.00"),
            tick_size=Decimal("0.25"),
            tick_value_usd=Decimal("1.25"),
            roll_months=(3, 6, 9, 12),
            default_intraday_margin_usd=Decimal("50.00"),
            default_exchange_initial_margin_usd=Decimal("1500.00"),
            default_round_turn_commission_usd=Decimal("1.24"),
            cas_aliases=("SPX500", "US500", "SPX", "MES"),
            expiry_rule=_EXPIRY_RULE_THIRD_FRIDAY,
        ),
        "MGC": MicroFuturesContractSpec(
            root="MGC",
            name="Micro Gold 10 oz",
            cas_symbol="XAUUSD",
            exchange="COMEX",
            point_value_usd=Decimal("10.00"),
            tick_size=Decimal("0.10"),
            tick_value_usd=Decimal("1.00"),
            roll_months=(2, 4, 6, 8, 10, 12),
            default_intraday_margin_usd=Decimal("100.00"),
            default_exchange_initial_margin_usd=Decimal("1200.00"),
            default_round_turn_commission_usd=Decimal("1.24"),
            cas_aliases=("XAUUSD", "XAU_USD", "GOLD", "MGC"),
            expiry_rule=_EXPIRY_RULE_THIRD_LAST_BUSINESS_DAY,
        ),
    }
)

_CAS_ALIAS_TO_ROOT: Final[Mapping[str, str]] = MappingProxyType(
    {
        alias.upper(): root
        for root, spec in CME_MICRO_FUTURES_SPECS.items()
        for alias in spec.cas_aliases
    }
)


@dataclass(frozen=True)
class FrontMonthContract:
    """Resolved active CME micro futures contract with roll and expiration metadata."""

    root: str
    cas_symbol: str
    contract_code: str
    month_code: str
    expiry_date: date
    roll_date: date
    days_to_expiry: int
    contract_code_4digit: str


@dataclass(frozen=True)
class MicroFuturesSizingResult:
    """Exact Decimal whole-contract risk and margin sizing decision."""

    root: str
    cas_symbol: str
    contracts: int
    contracts_by_risk: int
    contracts_by_margin: int
    equity_usd: Decimal
    risk_pct_limit: Decimal
    stop_distance_points: Decimal
    risk_budget_usd: Decimal
    risk_per_contract_usd: Decimal
    total_stop_risk_usd: Decimal
    effective_risk_pct: Decimal
    margin_per_contract_usd: Decimal
    required_margin_usd: Decimal
    projected_total_used_margin_usd: Decimal
    projected_margin_level_pct: Decimal
    estimated_round_turn_commission_usd: Decimal
    used_exchange_margin: bool


def _parse_contract_code_parts(contract_code: str) -> tuple[str, str, int, str]:
    if not isinstance(contract_code, str) or not contract_code.strip():
        raise UnsupportedMicroFuturesSymbolError(
            f"Contract code must be a non-empty string, got {contract_code!r}"
        )
    cleaned = contract_code.strip().upper()
    match = _CONTRACT_CODE_RE.match(cleaned)
    if match is None:
        raise UnsupportedMicroFuturesSymbolError(
            f"Unrecognized CME micro futures contract code: {contract_code!r}"
        )
    root, month_code, year_digits = match.groups()
    if root not in CME_MICRO_FUTURES_SPECS:
        raise UnsupportedMicroFuturesSymbolError(
            f"Unsupported micro futures root {root!r} in contract code {contract_code!r}"
        )
    spec = CME_MICRO_FUTURES_SPECS[root]
    month = CODE_TO_MONTH_MAP[month_code]
    if month not in spec.roll_months:
        raise UnsupportedMicroFuturesSymbolError(
            f"Month code {month_code!r} (month {month}) is not a valid roll month for {root} "
            f"(valid: {spec.roll_month_codes})"
        )
    return root, month_code, month, year_digits


def translate_cas_symbol_to_micro_root(symbol: str) -> str:
    """Translate a CAS symbol, alias, root, or CME contract code into a canonical micro root."""
    if not isinstance(symbol, str) or not symbol.strip():
        raise UnsupportedMicroFuturesSymbolError(
            f"Symbol must be a non-empty string, got {symbol!r}"
        )
    cleaned = symbol.strip().upper()
    if cleaned in _CAS_ALIAS_TO_ROOT:
        return _CAS_ALIAS_TO_ROOT[cleaned]
    match = _CONTRACT_CODE_RE.match(cleaned)
    if match is not None:
        root, month_code, _year_digits = match.groups()
        if root in CME_MICRO_FUTURES_SPECS:
            month = CODE_TO_MONTH_MAP[month_code]
            if month in CME_MICRO_FUTURES_SPECS[root].roll_months:
                return root
    raise UnsupportedMicroFuturesSymbolError(
        f"Unsupported symbol {symbol!r}: only CME micro futures roots "
        f"{tuple(CME_MICRO_FUTURES_SPECS.keys())} and their CAS aliases are supported"
    )


def translate_micro_root_to_cas_symbol(root: str) -> str:
    """Translate a CME micro futures root (or full contract code) into its primary CAS symbol."""
    if not isinstance(root, str) or not root.strip():
        raise UnsupportedMicroFuturesSymbolError(
            f"Micro futures root must be a non-empty string, got {root!r}"
        )
    cleaned = root.strip().upper()
    if cleaned in CME_MICRO_FUTURES_SPECS:
        return CME_MICRO_FUTURES_SPECS[cleaned].cas_symbol
    match = _CONTRACT_CODE_RE.match(cleaned)
    if match is not None:
        parsed_root, month_code, _year_digits = match.groups()
        if parsed_root in CME_MICRO_FUTURES_SPECS:
            month = CODE_TO_MONTH_MAP[month_code]
            if month in CME_MICRO_FUTURES_SPECS[parsed_root].roll_months:
                return CME_MICRO_FUTURES_SPECS[parsed_root].cas_symbol
    raise UnsupportedMicroFuturesSymbolError(
        f"Unsupported micro futures root {root!r}: expected one of "
        f"{tuple(CME_MICRO_FUTURES_SPECS.keys())}"
    )


def get_contract_spec(symbol_or_root: str) -> MicroFuturesContractSpec:
    """Return the immutable CME micro futures specification for a CAS symbol, root, or contract."""
    root = translate_cas_symbol_to_micro_root(symbol_or_root)
    return CME_MICRO_FUTURES_SPECS[root]


def _third_friday_of_month(year: int, month: int) -> date:
    first_day = date(year, month, 1)
    days_until_friday = (4 - first_day.weekday()) % 7
    first_friday = first_day + timedelta(days=days_until_friday)
    return first_friday + timedelta(days=14)


def _third_to_last_business_day_of_month(year: int, month: int) -> date:
    last_day_num = calendar.monthrange(year, month)[1]
    business_days_seen = 0
    for day_num in range(last_day_num, 0, -1):
        candidate = date(year, month, day_num)
        if candidate.weekday() < 5:
            business_days_seen += 1
            if business_days_seen == 3:
                return candidate
    raise MicroFuturesError(f"Unable to compute 3rd-to-last business day for {year}-{month:02d}")


def compute_contract_expiry_date(root_or_cas_symbol: str, year: int, month: int) -> date:
    """Compute the exact CME/COMEX/CBOT contract expiration date for a roll month."""
    spec = get_contract_spec(root_or_cas_symbol)
    _require_int(year, "year", min_value=1970, max_value=2999)
    _require_int(month, "month", min_value=1, max_value=12)
    if month not in spec.roll_months:
        raise UnsupportedMicroFuturesSymbolError(
            f"Month {month} is not in {spec.root} roll cycle {spec.roll_months}"
        )
    if spec.expiry_rule == _EXPIRY_RULE_THIRD_FRIDAY:
        return _third_friday_of_month(year, month)
    if spec.expiry_rule == _EXPIRY_RULE_THIRD_LAST_BUSINESS_DAY:
        return _third_to_last_business_day_of_month(year, month)
    raise MicroFuturesError(f"Unsupported expiry_rule {spec.expiry_rule!r} for {spec.root}")


def _build_front_month_contract(
    spec: MicroFuturesContractSpec,
    year: int,
    month: int,
    as_of_date: date,
    roll_buffer_days: int,
) -> FrontMonthContract:
    month_code = MONTH_CODE_MAP[month]
    expiry_date = compute_contract_expiry_date(spec.root, year, month)
    roll_date = expiry_date - timedelta(days=roll_buffer_days)
    days_to_expiry = (expiry_date - as_of_date).days
    contract_code = f"{spec.root}{month_code}{year % 10}"
    contract_code_4digit = f"{spec.root}{month_code}{year % 100:02d}"
    return FrontMonthContract(
        root=spec.root,
        cas_symbol=spec.cas_symbol,
        contract_code=contract_code,
        month_code=month_code,
        expiry_date=expiry_date,
        roll_date=roll_date,
        days_to_expiry=days_to_expiry,
        contract_code_4digit=contract_code_4digit,
    )


def resolve_front_month_contract(
    root_or_cas_symbol: str,
    as_of_utc: datetime | None = None,
    *,
    roll_buffer_days: int = DEFAULT_ROLL_BUFFER_DAYS,
) -> FrontMonthContract:
    """Resolve the active front-month contract, automatically rolling forward at roll_date."""
    spec = get_contract_spec(root_or_cas_symbol)
    ref_utc = _require_utc_datetime(as_of_utc, field_name="as_of_utc")
    _require_int(roll_buffer_days, "roll_buffer_days", min_value=0, max_value=45)
    as_of_date = ref_utc.date()

    for year in (as_of_date.year, as_of_date.year + 1, as_of_date.year + 2):
        for month in spec.roll_months:
            candidate = _build_front_month_contract(
                spec=spec,
                year=year,
                month=month,
                as_of_date=as_of_date,
                roll_buffer_days=roll_buffer_days,
            )
            if as_of_date < candidate.roll_date:
                return candidate

    raise MicroFuturesError(
        f"Unable to resolve active front-month contract for {spec.root} as of {as_of_date.isoformat()}"
    )


def _resolve_year_from_digits(year_digits: str, ref_year: int) -> int:
    if len(year_digits) == 4:
        return int(year_digits)
    if len(year_digits) == 2:
        yy = int(year_digits)
        century = (ref_year // 100) * 100
        candidates = (century - 100 + yy, century + yy, century + 100 + yy)
        return min(candidates, key=lambda y: (abs(y - ref_year), y))
    digit = int(year_digits)
    decade = (ref_year // 10) * 10
    candidates = (decade - 10 + digit, decade + digit, decade + 10 + digit)
    # Tie-breaker prefers the earlier year so ambiguous old single-digit codes fail closed.
    return min(candidates, key=lambda y: (abs(y - ref_year), y))


def validate_contract_not_expired(
    contract_code: str,
    as_of_utc: datetime | None = None,
    *,
    roll_buffer_days: int = DEFAULT_ROLL_BUFFER_DAYS,
) -> FrontMonthContract:
    """Parse a CME micro futures contract code and refuse if expired or inside roll lockout."""
    root, _month_code, month, year_digits = _parse_contract_code_parts(contract_code)
    spec = CME_MICRO_FUTURES_SPECS[root]
    ref_utc = _require_utc_datetime(as_of_utc, field_name="as_of_utc")
    _require_int(roll_buffer_days, "roll_buffer_days", min_value=0, max_value=45)
    as_of_date = ref_utc.date()
    year = _resolve_year_from_digits(year_digits, as_of_date.year)

    contract = _build_front_month_contract(
        spec=spec,
        year=year,
        month=month,
        as_of_date=as_of_date,
        roll_buffer_days=roll_buffer_days,
    )
    if as_of_date > contract.expiry_date:
        raise ExpiredFuturesContractError(
            f"Contract {contract_code.strip().upper()} ({contract.contract_code_4digit}) "
            f"expired on {contract.expiry_date.isoformat()} (as of {as_of_date.isoformat()})"
        )
    if as_of_date >= contract.roll_date:
        raise ExpiredFuturesContractError(
            f"Contract {contract_code.strip().upper()} ({contract.contract_code_4digit}) "
            f"is inside roll lockout window starting {contract.roll_date.isoformat()} "
            f"(expiry {contract.expiry_date.isoformat()}, as of {as_of_date.isoformat()})"
        )
    return contract


def align_price_to_tick(
    symbol_or_root: str,
    price: Decimal,
    *,
    rounding: str = ROUND_HALF_UP,
) -> Decimal:
    """Align an exact Decimal price to the contract's minimum CME tick increment."""
    spec = get_contract_spec(symbol_or_root)
    exact_price = _require_decimal(price, "price", allow_zero=False, allow_negative=False)
    if rounding not in _ALLOWED_ROUNDING_MODES:
        raise MicroFuturesError(f"Unsupported Decimal rounding mode: {rounding!r}")
    with localcontext() as ctx:
        ctx.prec = 28
        ticks = (exact_price / spec.tick_size).to_integral_value(rounding=rounding)
        aligned = (ticks * spec.tick_size).quantize(spec.tick_size)
    if aligned <= _ZERO:
        raise MicroFuturesError(
            f"Tick-aligned price for {spec.root} must remain strictly positive, got {aligned}"
        )
    return aligned


def _normalize_side(side: object) -> str:
    raw = side.value if hasattr(side, "value") and isinstance(side.value, str) else side
    if not isinstance(raw, str) or not raw.strip():
        raise MicroFuturesError(f"side must be BUY/LONG or SELL/SHORT, got {side!r}")
    normalized = raw.strip().upper()
    if normalized in {"BUY", "LONG"}:
        return "BUY"
    if normalized in {"SELL", "SHORT"}:
        return "SELL"
    raise MicroFuturesError(f"Unsupported trade side {side!r}; expected BUY/LONG or SELL/SHORT")


def compute_contract_pnl_usd(
    symbol_or_root: str,
    side: str,
    entry_price: Decimal,
    exit_price: Decimal,
    contracts: int,
    *,
    include_commission: bool = True,
) -> Decimal:
    """Compute exact Decimal USD P&L (optionally net of round-turn commissions)."""
    spec = get_contract_spec(symbol_or_root)
    normalized_side = _normalize_side(side)
    exact_entry = _require_decimal(entry_price, "entry_price")
    exact_exit = _require_decimal(exit_price, "exit_price")
    exact_contracts = _require_int(contracts, "contracts", min_value=1)
    if not isinstance(include_commission, bool):
        raise MicroFuturesError("include_commission must be a bool")

    price_delta = (exact_exit - exact_entry) if normalized_side == "BUY" else (exact_entry - exact_exit)
    with localcontext() as ctx:
        ctx.prec = 28
        gross_pnl = (
            price_delta * spec.point_value_usd * Decimal(exact_contracts)
        ).quantize(_CENT, rounding=ROUND_HALF_UP)
        commission = (
            (spec.default_round_turn_commission_usd * Decimal(exact_contracts)).quantize(
                _CENT, rounding=ROUND_HALF_UP
            )
            if include_commission
            else Decimal("0.00")
        )
        return (gross_pnl - commission).quantize(_CENT, rounding=ROUND_HALF_UP)


def size_micro_futures_order(
    *,
    symbol_or_root: str,
    equity_usd: Decimal,
    stop_distance_points: Decimal,
    risk_pct: Decimal = Decimal("1.00"),
    existing_used_margin_usd: Decimal = Decimal("0.00"),
    min_margin_level_pct: Decimal = DEFAULT_MIN_MARGIN_LEVEL_PCT,
    use_exchange_margin: bool = False,
    max_contracts: int = 20,
    demo_max_stop_risk_pct: Decimal | None = None,
) -> MicroFuturesSizingResult:
    """Size an exact whole-contract micro futures position under constitutional risk & margin ceilings."""
    spec = get_contract_spec(symbol_or_root)
    exact_equity = _require_decimal(
        equity_usd,
        "equity_usd",
        allow_zero=False,
        allow_negative=False,
        error_cls=MicroFuturesSizingRefusalError,
    )
    exact_stop_pts = _require_decimal(
        stop_distance_points,
        "stop_distance_points",
        allow_zero=False,
        allow_negative=False,
        error_cls=MicroFuturesSizingRefusalError,
    )
    exact_risk_pct = _require_decimal(
        risk_pct,
        "risk_pct",
        allow_zero=False,
        allow_negative=False,
        error_cls=MicroFuturesSizingRefusalError,
    )
    if demo_max_stop_risk_pct is not None:
        eff_stop_ceiling = _require_decimal(
            demo_max_stop_risk_pct,
            "demo_max_stop_risk_pct",
            allow_zero=False,
            allow_negative=False,
            error_cls=MicroFuturesSizingRefusalError,
        )
        if eff_stop_ceiling > DEMO_HIGH_GROWTH_MAX_RISK_PCT:
            raise MicroFuturesSizingRefusalError(
                f"demo_max_stop_risk_pct {eff_stop_ceiling}% exceeds DEMO high-growth ceiling "
                f"{DEMO_HIGH_GROWTH_MAX_RISK_PCT}%"
            )
    else:
        eff_stop_ceiling = MAX_CONSTITUTIONAL_STOP_RISK_PCT
    if exact_risk_pct > eff_stop_ceiling:
        raise MicroFuturesSizingRefusalError(
            f"Requested risk_pct {exact_risk_pct}% exceeds constitutional stop-risk ceiling "
            f"of {eff_stop_ceiling}%"
        )
    exact_used_margin = _require_decimal(
        existing_used_margin_usd,
        "existing_used_margin_usd",
        allow_zero=True,
        allow_negative=False,
        error_cls=MicroFuturesSizingRefusalError,
    )
    exact_min_margin_level = _require_decimal(
        min_margin_level_pct,
        "min_margin_level_pct",
        allow_zero=False,
        allow_negative=False,
        error_cls=MicroFuturesSizingRefusalError,
    )
    if not isinstance(use_exchange_margin, bool):
        raise MicroFuturesSizingRefusalError(
            f"use_exchange_margin must be a bool, got {type(use_exchange_margin).__name__}"
        )
    exact_max_contracts = _require_int(
        max_contracts,
        "max_contracts",
        min_value=1,
        error_cls=MicroFuturesSizingRefusalError,
    )

    margin_per_contract = (
        spec.default_exchange_initial_margin_usd
        if use_exchange_margin
        else spec.default_intraday_margin_usd
    )

    with localcontext() as ctx:
        ctx.prec = 28
        risk_budget_usd = (
            exact_equity * exact_risk_pct / _ONE_HUNDRED
        ).quantize(_CENT, rounding=ROUND_FLOOR)
        risk_per_contract_usd = (
            exact_stop_pts * spec.point_value_usd
        ).quantize(_CENT, rounding=ROUND_CEILING)
        if risk_per_contract_usd <= _ZERO:
            raise MicroFuturesSizingRefusalError(
                f"Computed risk_per_contract_usd must be positive, got {risk_per_contract_usd}"
            )
        contracts_by_risk = int(risk_budget_usd // risk_per_contract_usd)

        max_total_margin_allowed = (
            exact_equity * _ONE_HUNDRED / exact_min_margin_level
        ).quantize(_CENT, rounding=ROUND_FLOOR)
        remaining_margin_budget = max(Decimal("0.00"), max_total_margin_allowed - exact_used_margin)
        contracts_by_margin = int(remaining_margin_budget // margin_per_contract)

        contracts = min(contracts_by_risk, contracts_by_margin, exact_max_contracts)
        if contracts < 1:
            if contracts_by_risk < 1:
                raise MicroFuturesSizingRefusalError(
                    f"Honest refusal: cannot size 1 whole {spec.root} contract within "
                    f"${risk_budget_usd} risk budget ({exact_risk_pct}% of ${exact_equity}); "
                    f"a {exact_stop_pts}-point stop costs ${risk_per_contract_usd}/contract "
                    f"(will not round up above risk budget)."
                )
            raise MicroFuturesSizingRefusalError(
                f"Honest refusal: cannot size 1 whole {spec.root} contract within "
                f"{exact_min_margin_level}% margin floor; max allowed margin is "
                f"${max_total_margin_allowed}, existing used margin is ${exact_used_margin}, "
                f"remaining budget is ${remaining_margin_budget}, and 1 {spec.root} contract "
                f"requires ${margin_per_contract}."
            )

        total_stop_risk_usd = (risk_per_contract_usd * Decimal(contracts)).quantize(_CENT)
        if total_stop_risk_usd > risk_budget_usd:
            raise MicroFuturesSizingRefusalError(
                f"Sized stop risk ${total_stop_risk_usd} exceeds budget ${risk_budget_usd}"
            )
        effective_risk_pct = (
            (total_stop_risk_usd / exact_equity) * _ONE_HUNDRED
        ).quantize(_PCT_QUANT, rounding=ROUND_CEILING)
        required_margin_usd = (margin_per_contract * Decimal(contracts)).quantize(_CENT)
        projected_total_used_margin_usd = (exact_used_margin + required_margin_usd).quantize(_CENT)
        projected_margin_level_pct = (
            (exact_equity * _ONE_HUNDRED) / projected_total_used_margin_usd
        ).quantize(_CENT, rounding=ROUND_FLOOR)
        if projected_margin_level_pct < exact_min_margin_level:
            raise MicroFuturesSizingRefusalError(
                f"Projected margin level {projected_margin_level_pct}% falls below "
                f"required floor {exact_min_margin_level}%"
            )
        estimated_commission_usd = (
            spec.default_round_turn_commission_usd * Decimal(contracts)
        ).quantize(_CENT, rounding=ROUND_HALF_UP)

    return MicroFuturesSizingResult(
        root=spec.root,
        cas_symbol=spec.cas_symbol,
        contracts=contracts,
        contracts_by_risk=contracts_by_risk,
        contracts_by_margin=contracts_by_margin,
        equity_usd=exact_equity.quantize(_CENT),
        risk_pct_limit=exact_risk_pct,
        stop_distance_points=exact_stop_pts,
        risk_budget_usd=risk_budget_usd,
        risk_per_contract_usd=risk_per_contract_usd,
        total_stop_risk_usd=total_stop_risk_usd,
        effective_risk_pct=effective_risk_pct,
        margin_per_contract_usd=margin_per_contract,
        required_margin_usd=required_margin_usd,
        projected_total_used_margin_usd=projected_total_used_margin_usd,
        projected_margin_level_pct=projected_margin_level_pct,
        estimated_round_turn_commission_usd=estimated_commission_usd,
        used_exchange_margin=use_exchange_margin,
    )


__all__ = [
    "CME_MICRO_FUTURES_SPECS",
    "CODE_TO_MONTH_MAP",
    "DEFAULT_MIN_MARGIN_LEVEL_PCT",
    "DEFAULT_ROLL_BUFFER_DAYS",
    "ExpiredFuturesContractError",
    "FrontMonthContract",
    "MAX_CONSTITUTIONAL_DRAWDOWN_PCT",
    "MAX_CONSTITUTIONAL_STOP_RISK_PCT",
    "MONTH_CODE_MAP",
    "MicroFuturesContractSpec",
    "MicroFuturesError",
    "MicroFuturesSizingRefusalError",
    "MicroFuturesSizingResult",
    "UnsupportedMicroFuturesSymbolError",
    "align_price_to_tick",
    "compute_contract_expiry_date",
    "compute_contract_pnl_usd",
    "get_contract_spec",
    "resolve_front_month_contract",
    "size_micro_futures_order",
    "translate_cas_symbol_to_micro_root",
    "translate_micro_root_to_cas_symbol",
    "validate_contract_not_expired",
]
