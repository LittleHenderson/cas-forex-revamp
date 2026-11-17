"""Versioned deterministic wire encoding and a strict model-selection boundary."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
import json
from typing import Any

from .commands import ActionIntent, AuthorizedCommand
from .decisions import AtlasContent, AtlasView, DecisionRequest, DecisionSelection
from .primitives import ContractError, StateReference, decimal_text, utc_time

MAX_DECISION_BYTES = 16_384


def to_wire(value: Any) -> Any:
    """Decimals are strings. Unknown/nonfinite/numeric-coercion cases fail closed."""
    if isinstance(value, Decimal):
        return decimal_text(value)
    if isinstance(value, datetime):
        return utc_time(value, "wire timestamp").isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return to_wire(value.value)
    if is_dataclass(value) and not isinstance(value, type):
        if isinstance(value, ActionIntent):
            return {
                f.name: to_wire(getattr(value, f.name))
                for f in fields(value)
                if not (f.name == "take_profit_price" and getattr(value, f.name) is None)
            }
        return {f.name: to_wire(getattr(value, f.name)) for f in fields(value)}
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) in (tuple, list):
        return [to_wire(x) for x in value]
    if type(value) is dict and all(type(k) is str for k in value):
        return {k: to_wire(v) for k, v in value.items()}
    raise ContractError(f"unsupported wire type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(to_wire(value), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise ContractError("value cannot be represented in canonical UTF-8 JSON") from exc


def content_digest(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def intent_digest(intent: ActionIntent) -> str:
    if not isinstance(intent, ActionIntent):
        raise ContractError("intent_digest requires ActionIntent")
    return content_digest(intent)


def atlas_domain_digest(atlas: AtlasContent | AtlasView) -> str:
    content = atlas.content if isinstance(atlas, AtlasView) else atlas
    if not isinstance(content, AtlasContent):
        raise ContractError("atlas digest requires typed domain content")
    return content_digest(content)


def assert_command_integrity(command: AuthorizedCommand) -> None:
    if not isinstance(command, AuthorizedCommand) or command.payload_sha256 != intent_digest(command.intent):
        raise ContractError("command payload digest does not bind the complete immutable intent")


def assert_current_request(request: DecisionRequest, current: StateReference, now: datetime) -> None:
    utc_time(now, "now")
    if request.state != current:
        raise ContractError("decision request is not bound to the exact current state/build/epoch")
    if now < current.observed_at or now >= current.valid_until:
        raise ContractError("decision request is stale or from a future observation")


def bind_selection(selection: DecisionSelection, request: DecisionRequest) -> None:
    if (selection.request_id, selection.opportunity_set_id, selection.source_state_id) != (
        request.request_id, request.opportunity_set_id, request.state.state_id
    ):
        raise ContractError("selection request/state identity mismatch")
    if selection.selected_action_ref is not None and selection.selected_action_ref not in {
        option.action_ref for option in request.options
    }:
        raise ContractError("selection is outside the supplied action references")
    if not set(selection.evidence_ids) <= {x.evidence_id for x in request.evidence}:
        raise ContractError("selection cites evidence not supplied to this request")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON keys are not permitted")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ContractError(f"nonfinite JSON constant is not permitted: {value}")


def selection_from_json(raw: str, request: DecisionRequest) -> DecisionSelection:
    if not isinstance(raw, str):
        raise ContractError("decision response must be UTF-8 JSON text")
    try:
        if len(raw.encode("utf-8")) > MAX_DECISION_BYTES:
            raise ContractError("decision response exceeds its byte limit")
        payload = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ContractError("decision response is malformed") from exc
    expected = {"request_id", "opportunity_set_id", "source_state_id", "selected_action_ref", "reason", "evidence_ids"}
    if type(payload) is not dict or set(payload) != expected:
        raise ContractError("decision response must contain exactly the v1 selection fields")
    evidence = payload["evidence_ids"]
    if type(evidence) is not list or len(evidence) > 128:
        raise ContractError("evidence_ids must be a bounded list")
    selection = DecisionSelection(
        request_id=payload["request_id"], opportunity_set_id=payload["opportunity_set_id"],
        source_state_id=payload["source_state_id"], selected_action_ref=payload["selected_action_ref"],
        reason=payload["reason"], evidence_ids=tuple(evidence),
    )
    bind_selection(selection, request)
    return selection
