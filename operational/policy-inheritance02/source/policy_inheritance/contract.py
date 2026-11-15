"""Strict exact-field and canonical-byte checks for the accepted design05 pin.

This module does not read a file or authenticate a signature. The caller supplies
the exact pinned specification bytes. Its parsed state is private and copied on
read. All validation is pure and bounded to the design's declared sizes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .errors import ContractViolation, require

SPEC_SHA256 = "19240b1c8ef186bd1e09965595f1ce0a53c54c9de34d2b3d8eeb2fb6b9b15e45"
MAX_RECORD = 1_048_576
MAX_OBJECT = 4_194_304
MAX_RAW = 67_108_864
MAX_DEPTH = 32
ZERO = "0" * 64


def digest(data: bytes) -> str:
    require(type(data) is bytes, "RAW_BYTES_MISMATCH", "bytes")
    return hashlib.sha256(data).hexdigest()


def _json_tree(value: Any, depth: int = 0) -> None:
    require(depth <= MAX_DEPTH, "NONCANONICAL_RECORD", "depth")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-(2**63) <= value <= 2**63 - 1, "NONCANONICAL_RECORD", "integer")
        return
    if type(value) is str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ContractViolation("NONCANONICAL_RECORD", "unicode") from None
        return
    if type(value) is list:
        for item in value:
            _json_tree(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str, "NONCANONICAL_RECORD", "key")
            _json_tree(key, depth + 1)
            _json_tree(item, depth + 1)
        return
    raise ContractViolation("NONCANONICAL_RECORD", "json_type")


def canonical_bytes(value: Any, *, limit: int = MAX_RECORD) -> bytes:
    require(type(limit) is int and 1 <= limit <= MAX_RAW,
            "NONCANONICAL_RECORD", "limit")
    try:
        _json_tree(value)
        result = json.dumps(value, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (RecursionError, OverflowError, UnicodeError):
        raise ContractViolation("NONCANONICAL_RECORD", "encoding") from None
    require(0 < len(result) <= limit, "NONCANONICAL_RECORD", "bytes")
    return result


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "NONCANONICAL_RECORD", "duplicate_key")
        result[key] = value
    return result


def _integer(text: str) -> int:
    require(len(text) <= 20, "NONCANONICAL_RECORD", "integer_length")
    value = int(text)
    require(-(2**63) <= value <= 2**63 - 1, "NONCANONICAL_RECORD", "integer")
    return value


def _no_number(_: str) -> None:
    raise ContractViolation("NONCANONICAL_RECORD", "float_or_nonfinite")


def decode_json(data: bytes, *, limit: int = MAX_RECORD) -> Any:
    """Strict JSON parsing; callers still choose whether canonical bytes are required."""
    require(type(limit) is int and 1 <= limit <= MAX_RAW,
            "NONCANONICAL_RECORD", "limit")
    require(type(data) is bytes and 0 < len(data) <= limit,
            "NONCANONICAL_RECORD", "bytes")
    require(not data.startswith(b"\xef\xbb\xbf"), "NONCANONICAL_RECORD", "bom")
    try:
        value = json.loads(data.decode("utf-8", errors="strict"),
                           object_pairs_hook=_pairs, parse_int=_integer,
                           parse_float=_no_number, parse_constant=_no_number)
        _json_tree(value)
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise ContractViolation("NONCANONICAL_RECORD", "json") from None
    return value


def decode_canonical(data: bytes, *, limit: int = MAX_RECORD) -> Any:
    value = decode_json(data, limit=limit)
    require(canonical_bytes(value, limit=limit) == data,
            "NONCANONICAL_RECORD", "canonical_encoding")
    return value


def utc(value: str) -> datetime:
    require(type(value) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value) is not None,
        "NONCANONICAL_RECORD", "utc")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ContractViolation("NONCANONICAL_RECORD", "utc_calendar") from None


class Contract:
    """An inert, hash-pinned evaluator for every exact design05 object type."""

    def __init__(self, spec_bytes: bytes) -> None:
        require(digest(spec_bytes) == SPEC_SHA256, "CONTEXT_MISMATCH", "method_spec")
        spec = decode_json(spec_bytes)
        require(type(spec) is dict, "NONCANONICAL_RECORD", "spec")
        self._spec = spec

    @property
    def spec(self) -> dict[str, Any]:
        return copy.deepcopy(self._spec)

    def validate(self, type_name: str, value: Any) -> None:
        require(type(type_name) is str and type_name in self._spec["exact_object_fields"],
                "DECODER_UNAVAILABLE", "type_name")
        canonical_bytes(value)
        self._check(type_name, value, type_name, 0)

    def decode(self, type_name: str, data: bytes) -> dict[str, Any]:
        value = decode_canonical(data)
        self.validate(type_name, value)
        return value

    def validate_value(self, expression: str, value: Any) -> None:
        """For pure semantic validators, never an authority or raw decoder."""
        _json_tree(value)
        self._check(expression, value, "value", 0)

    def _check(self, expr: str, value: Any, field: str, depth: int) -> None:
        require(depth <= MAX_DEPTH, "NONCANONICAL_RECORD", "depth")
        require(self._known_expression(expr), "DECODER_UNAVAILABLE", "type_expression")
        types, enums = self._spec["exact_object_fields"], self._spec["enums"]
        if expr in types:
            shape = types[expr]
            require(type(value) is dict and set(value) == set(shape),
                    "NONCANONICAL_RECORD", field + ".fields")
            for name, nested in shape.items():
                self._check(nested, value[name], field + "." + name, depth + 1)
            if expr == "ObjectRef":
                require(value["object_id"] == value["sha256"],
                        "RAW_BYTES_MISMATCH", field + ".object_id")
            return
        if expr in enums:
            require(type(value) is str and value in enums[expr],
                    "NONCANONICAL_RECORD", field)
            return
        if expr.startswith("Nullable<") and expr.endswith(">"):
            if value is not None:
                self._check(expr[9:-1], value, field, depth + 1)
            return
        match = re.fullmatch(r"array<(.+)>\[([0-9]+),([0-9]+)\]", expr)
        if match:
            nested, lo, hi = match.groups()
            require(type(value) is list and int(lo) <= len(value) <= int(hi),
                    "NONCANONICAL_RECORD", field + ".length")
            for item in value:
                self._check(nested, item, field + "[]", depth + 1)
            return
        if expr.startswith("literal:"):
            require(type(value) is str and value == expr[8:], "NONCANONICAL_RECORD", field)
            return
        if expr.startswith("literal-integer:"):
            require(type(value) is int and value == int(expr[16:]),
                    "NONCANONICAL_RECORD", field)
            return
        if expr.startswith("literal-bool:"):
            require(type(value) is bool and value == (expr[13:] == "true"),
                    "NONCANONICAL_RECORD", field)
            return
        if expr == "exact:fixed_unsupported_routes":
            require(value == self._spec["fixed_unsupported_routes"] and type(value) is list,
                    "UNSUPPORTED_ROUTE_RELABELED", field)
            return
        bounds = {"UInt": (0, 2**63 - 1), "PositiveInt": (1, 2**63 - 1),
                  "SignedInt": (-(2**63), 2**63 - 1)}
        match = re.fullmatch(r"Int\[(-?[0-9]+),(-?[0-9]+)\]", expr)
        if match:
            bounds[expr] = (int(match[1]), int(match[2]))
        if expr in bounds:
            lo, hi = bounds[expr]
            require(type(value) is int and lo <= value <= hi, "NONCANONICAL_RECORD", field)
            return
        if expr == "Bool":
            require(type(value) is bool, "NONCANONICAL_RECORD", field)
            return
        patterns = {"Id": r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}",
                    "Sha256": r"[0-9a-f]{64}", "Hex128": r"[0-9a-f]{128}"}
        if expr in patterns:
            require(type(value) is str and re.fullmatch(patterns[expr], value) is not None,
                    "NONCANONICAL_RECORD", field)
            return
        if expr == "Utc":
            utc(value)
            return
        if expr == "Uuid":
            require(type(value) is str, "NONCANONICAL_RECORD", field)
            try:
                require(str(uuid.UUID(value)) == value, "NONCANONICAL_RECORD", field)
            except (ValueError, AttributeError):
                raise ContractViolation("NONCANONICAL_RECORD", field) from None
            return
        raise ContractViolation("DECODER_UNAVAILABLE", "type_expression")

    def _known_expression(self, expr: str, depth: int = 0) -> bool:
        if type(expr) is not str or depth > MAX_DEPTH:
            return False
        if expr in self._spec["exact_object_fields"] or expr in self._spec["enums"]:
            return True
        if expr in {"Id", "Sha256", "Hex128", "Uuid", "Utc", "UInt", "PositiveInt", "SignedInt", "Bool",
                    "exact:fixed_unsupported_routes", "literal-bool:true", "literal-bool:false"}:
            return True
        if expr.startswith("literal:"):
            return True
        if expr.startswith("literal-integer:"):
            value = expr[16:]
            return len(value) <= 20 and re.fullmatch(r"-?(0|[1-9][0-9]*)", value) is not None and -(2**63) <= int(value) <= 2**63-1
        if expr.startswith("Nullable<") and expr.endswith(">"):
            return self._known_expression(expr[9:-1], depth + 1)
        match = re.fullmatch(r"array<(.+)>\[([0-9]{1,10}),([0-9]{1,10})\]", expr)
        if match:
            return 0 <= int(match[2]) <= int(match[3]) and self._known_expression(match[1], depth + 1)
        match = re.fullmatch(r"Int\[(-?[0-9]{1,19}),(-?[0-9]{1,19})\]", expr)
        return bool(match and -(2**63) <= int(match[1]) <= int(match[2]) <= 2**63-1)

    def object_bytes(self, reference: dict[str, Any], data: bytes,
                     *, expected_kind: str | None = None) -> None:
        self.validate("ObjectRef", reference)
        require(type(data) is bytes and len(data) == reference["bytes"]
                and digest(data) == reference["sha256"], "RAW_BYTES_MISMATCH", "object")
        if expected_kind is not None:
            require(reference["artifact_kind"] == expected_kind,
                    "PURPOSE_MISMATCH", "artifact_kind")


def object_ref(data: bytes, kind: str) -> dict[str, Any]:
    """Build a content reference only. It has no authenticity or authority."""
    require(type(data) is bytes and 0 < len(data) <= MAX_OBJECT,
            "RAW_BYTES_MISMATCH", "object")
    value = digest(data)
    return {"object_id": value, "bytes": len(data), "sha256": value,
            "artifact_kind": kind}
