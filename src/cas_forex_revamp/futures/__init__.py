"""US-Regulated CME Micro Futures package (Option B).

Re-exports contract specifications, roll resolver, and constitutional sizing cleanly
while loading optional venue adapters lazily so modules remain independently testable.
"""
from __future__ import annotations

import importlib

from .micro_futures_specs import (
    CME_MICRO_FUTURES_SPECS,
    CODE_TO_MONTH_MAP,
    DEFAULT_MIN_MARGIN_LEVEL_PCT,
    DEFAULT_ROLL_BUFFER_DAYS,
    MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
    MAX_CONSTITUTIONAL_STOP_RISK_PCT,
    MONTH_CODE_MAP,
    ExpiredFuturesContractError,
    FrontMonthContract,
    MicroFuturesContractSpec,
    MicroFuturesError,
    MicroFuturesSizingRefusalError,
    MicroFuturesSizingResult,
    UnsupportedMicroFuturesSymbolError,
    align_price_to_tick,
    compute_contract_expiry_date,
    compute_contract_pnl_usd,
    get_contract_spec,
    resolve_front_month_contract,
    size_micro_futures_order,
    translate_cas_symbol_to_micro_root,
    translate_micro_root_to_cas_symbol,
    validate_contract_not_expired,
)


def __getattr__(name: str) -> object:
    """Lazily expose symbols from `tradovate_venue` once that module is present."""
    if name == "tradovate_venue":
        return importlib.import_module(f"{__name__}.tradovate_venue")
    try:
        venue_module = importlib.import_module(f"{__name__}.tradovate_venue")
    except ModuleNotFoundError as exc:
        if exc.name == f"{__name__}.tradovate_venue":
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
        raise
    if hasattr(venue_module, name):
        return getattr(venue_module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
