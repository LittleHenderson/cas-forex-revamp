"""Private persistence decoding of the steward's shared types, not new wire schemas."""
from __future__ import annotations
from datetime import datetime
import json
from typing import Any

from cas_forex_revamp.contracts import (
    AccountRunKey, ContractError, EffectState, Environment, FenceReceipt, Instrument,
    MarketObservation, PositionView, QuantityReport, Side, VenueReceipt, parse_decimal,
)


def loads(raw: str) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("duplicate key in venue storage")
            result[key] = value
        return result
    def invalid(value):
        raise ContractError("nonfinite number in venue storage")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def key(value: dict) -> AccountRunKey:
    return AccountRunKey(value["account_id"], value["run_id"], Environment(value["environment"]))


def instrument(value: dict) -> Instrument:
    return Instrument(**{**value, **{n: parse_decimal(value[n]) for n in (
        "price_tick", "quantity_step", "minimum_quantity"
    )}})


def receipt(value: dict) -> VenueReceipt:
    data = dict(value)
    data["key"] = key(data["key"])
    data["observed_at"] = time(data["observed_at"])
    data["effect"] = EffectState(data["effect"])
    if data["quantities"] is not None:
        data["quantities"] = QuantityReport(**{
            k: parse_decimal(v) for k, v in data["quantities"].items()
        })
    return VenueReceipt(**data)


def fence(value: dict) -> FenceReceipt:
    return FenceReceipt(**{**value, "key": key(value["key"]),
                           "observed_at": time(value["observed_at"])})


def market(value: dict) -> MarketObservation:
    return MarketObservation(**{**value, "key": key(value["key"]),
        "observed_at": time(value["observed_at"]), "available_at": time(value["available_at"]),
        "bid": parse_decimal(value["bid"]), "ask": parse_decimal(value["ask"])})


def position(value: dict) -> PositionView:
    return PositionView(**{**value, "side": Side(value["side"]),
        "quantity": parse_decimal(value["quantity"]),
        "entry_price": parse_decimal(value["entry_price"]),
        "stop_price": None if value["stop_price"] is None else parse_decimal(value["stop_price"])})
