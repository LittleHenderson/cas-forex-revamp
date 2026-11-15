"""Pure wire primitives. No file, clock, network, process or credential access."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Protocol, TypeAlias, Union

JSONValue: TypeAlias = Union[None, bool, int, str, list["JSONValue"], dict[str, "JSONValue"]]
MAX_RECORD = 1_048_576
MAX_OBJECT = 4_194_304
MAX_GRAPH = 67_108_864
MAX_DEPTH = 32
ZERO_SHA256 = "0" * 64

class ContractError(ValueError):
    """Safe structural error: codes/known field paths, never raw record values."""
    def __init__(self, code: str, field: str = "") -> None:
        self.code, self.field = code, field
        super().__init__(code + (":" + field if field else ""))

class DependencyUnavailable(ContractError):
    """No successful fallback for a missing selected dependency."""
    def __init__(self, field: str = "") -> None:
        super().__init__("DEPENDENCY_UNAVAILABLE", field)

def require(condition: bool, code: str, field: str = "") -> None:
    if not condition:
        raise ContractError(code, field)

def digest(data: bytes) -> str:
    require(type(data) is bytes, "BYTES_REQUIRED")
    return hashlib.sha256(data).hexdigest()

def _tree(value: Any, depth: int, budget: list[int]) -> None:
    budget[0] -= 1
    require(depth <= MAX_DEPTH and budget[0] >= 0, "JSON_BOUNDS")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-(2**63) <= value < 2**63, "INTEGER_BOUNDS")
        return
    if type(value) is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeError:
            raise ContractError("INVALID_UNICODE") from None
        return
    if type(value) is list:
        for child in value:
            _tree(child, depth + 1, budget)
        return
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str, "JSON_KEY")
            _tree(key, depth + 1, budget)
            _tree(child, depth + 1, budget)
        return
    raise ContractError("JSON_TYPE")

def canonical_bytes(value: Any, *, limit: int = MAX_RECORD) -> bytes:
    require(type(limit) is int and 0 < limit <= MAX_GRAPH, "LIMIT")
    _tree(value, 0, [limit])
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (RecursionError, OverflowError, UnicodeError):
        raise ContractError("JSON_ENCODING") from None
    require(0 < len(raw) <= limit, "RECORD_SIZE")
    return raw

def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        require(key not in result, "DUPLICATE_KEY")
        result[key] = value
    return result

def _int(text: str) -> int:
    require(len(text) <= 20, "INTEGER_BOUNDS")
    value = int(text)
    require(-(2**63) <= value < 2**63, "INTEGER_BOUNDS")
    return value

def _forbid_number(_: str) -> None:
    raise ContractError("FLOAT_OR_NONFINITE")

def decode_json(raw: bytes, *, limit: int = MAX_RECORD) -> JSONValue:
    require(type(limit) is int and 0 < limit <= MAX_GRAPH, "LIMIT")
    require(type(raw) is bytes and 0 < len(raw) <= limit, "RECORD_SIZE")
    require(not raw.startswith(b"\xef\xbb\xbf"), "BOM")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_int=_int, parse_float=_forbid_number,
                           parse_constant=_forbid_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise ContractError("JSON_ENCODING") from None
    _tree(value, 0, [limit])
    return value

def decode_canonical(raw: bytes, *, limit: int = MAX_RECORD) -> JSONValue:
    value = decode_json(raw, limit=limit)
    require(canonical_bytes(value, limit=limit) == raw, "NONCANONICAL")
    return value

def utc(value: str) -> datetime:
    require(type(value) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z",
        value) is not None, "UTC_FORMAT")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ContractError("UTC_CALENDAR") from None

def safe_path(value: str, *, absolute: bool) -> None:
    require(type(value) is str, "PATH_TYPE")
    require(0 < len(value.encode("utf-8")) <= 4096 and "\x00" not in value
            and "\\" not in value, "PATH_ENCODING")
    require(value.startswith("/") == absolute, "PATH_ROOT")
    parts = value[1:].split("/") if absolute else value.split("/")
    require(all(part not in ("", ".", "..") for part in parts), "PATH_COMPONENT")

def signing_bytes(domain: bytes, body: JSONValue, *, limit: int = MAX_OBJECT) -> bytes:
    """Callers select a pinned domain constant; no payload-selected domain."""
    require(type(domain) is bytes and domain.endswith(b"\n")
            and domain.count(b"\n") == 1 and len(domain) <= 128, "DOMAIN")
    require(all(byte < 128 for byte in domain), "DOMAIN")
    return domain + canonical_bytes(body, limit=limit)

@dataclass(frozen=True, slots=True)
class StructuralRecord:
    """A byte snapshot after structural checks. NOT authenticated authority."""
    namespace: str
    type_name: str
    raw: bytes
    limit: int = MAX_OBJECT

    def __post_init__(self) -> None:
        require(type(self.namespace) is str and type(self.type_name) is str, "RECORD_TYPE")
        require(type(self.limit) is int and 0 < self.limit <= MAX_GRAPH, "LIMIT")
        require(type(self.raw) is bytes and 0 < len(self.raw) <= self.limit, "RECORD_BYTES")

    @property
    def sha256(self) -> str:
        return digest(self.raw)

    def payload(self) -> JSONValue:
        """Return a fresh tree; callers cannot mutate the retained bytes."""
        return decode_canonical(self.raw, limit=self.limit)

@dataclass(frozen=True, slots=True)
class FieldContext:
    namespace: str
    type_name: str
    field_name: str
    expression: str
    parent_raw: bytes
    contract_bundle_sha256: str

class SelectedShapeValidator(Protocol):
    """Custody-owned, separately pinned private schema mapping; no authority result."""
    def validate(self, *, context: FieldContext, raw_value: bytes) -> None: ...

@dataclass(frozen=True, slots=True)
class ValidationLimits:
    """Selected parser limits only; not clock, role or execution authorization."""
    stream_bytes: int | None = None

class SignatureVerifier(Protocol):
    """Actual verifier is implemented by authority owner, never this shape library."""
    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> None: ...

class SignatureSigner(Protocol):
    """Externally selected signer; constructors/imports must not load credentials."""
    def sign(self, *, domain: bytes, canonical_body: bytes) -> bytes: ...

