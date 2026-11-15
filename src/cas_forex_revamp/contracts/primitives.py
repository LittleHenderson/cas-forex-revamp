"""Small strict primitives shared across independently owned application lanes.

These objects validate data shape, not authorization or independent evidence.
No imports from old Forex, network clients, databases or model runtimes belong here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
import re

SCHEMA_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """A boundary value is malformed; never repair it into an empty/default state."""


def identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ContractError(f"{field} must be a nonempty bounded opaque identifier")
    return value


def digest(value: str, field: str = "sha256") -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ContractError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def integer(value: int, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ContractError(f"{field} must be an integer >= {minimum}")
    return value


def decimal_value(value: Decimal, field: str, *, positive: bool = False) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ContractError(f"{field} requires a finite Decimal, never a float")
    if value.copy_abs() >= Decimal("1e18") or not -12 <= value.as_tuple().exponent <= 18:
        raise ContractError(f"{field} exceeds the v1 magnitude/12-decimal-place boundary")
    if positive and value <= 0:
        raise ContractError(f"{field} must be positive")
    return value


def parse_decimal(value: str, field: str = "amount") -> Decimal:
    if not isinstance(value, str) or len(value) > 48 or not re.fullmatch(
        r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value
    ):
        raise ContractError(f"{field} must be a plain bounded decimal string")
    try:
        return decimal_value(Decimal(value), field)
    except InvalidOperation as exc:
        raise ContractError(f"{field} is not a decimal") from exc


def decimal_text(value: Decimal) -> str:
    decimal_value(value, "decimal")
    if value == 0:
        return "0"
    result = format(value, "f")
    return result.rstrip("0").rstrip(".") if "." in result else result


def utc_time(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ContractError(f"{field} must be an aware timestamp")
    if value.utcoffset().total_seconds() != 0:
        raise ContractError(f"{field} must be UTC")
    return value.astimezone(timezone.utc)


class Environment(StrEnum):
    DISCONNECTED_SIMULATION = "DISCONNECTED_SIMULATION"


class ActionKind(StrEnum):
    OPEN = "OPEN"
    ADD = "ADD"
    REDUCE = "REDUCE"
    CLOSE = "CLOSE"
    AMEND_STOP = "AMEND_STOP"
    CANCEL_ORDER = "CANCEL_ORDER"


class Side(StrEnum):
    BUY = "BUY"
    SELL = "SELL"


class DecisionOrigin(StrEnum):
    SCRIPTED = "SCRIPTED"
    REPLAY = "REPLAY"
    ACTUAL_MODEL = "ACTUAL_MODEL"
    OWNER_REVIEWED = "OWNER_REVIEWED"
    POLICY = "POLICY"


class ControlKind(StrEnum):
    PAUSE_NEW_RISK = "PAUSE_NEW_RISK"
    STOP_AUTOMATION = "STOP_AUTOMATION"
    RESUME_NEW_RISK = "RESUME_NEW_RISK"
    RESUME_MANAGEMENT = "RESUME_MANAGEMENT"


class NewRiskPermission(StrEnum):
    ALLOWED = "ALLOWED"
    PAUSED = "PAUSED"
    UNKNOWN = "UNKNOWN"


class ManagementPermission(StrEnum):
    ALLOWED = "ALLOWED"
    STOPPED = "STOPPED"
    UNKNOWN = "UNKNOWN"


class EffectState(StrEnum):
    ACKNOWLEDGED = "ACKNOWLEDGED"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"
    APPLIED = "APPLIED"  # Non-fill effect such as an observed stop amendment.
    UNKNOWN = "UNKNOWN"


class CommandState(StrEnum):
    RESERVED = "RESERVED"
    QUEUED = "QUEUED"
    SUBMITTED = "SUBMITTED"
    UNRESOLVED = "UNRESOLVED"
    OBSERVED = "OBSERVED"
    REJECTED = "REJECTED"


class EvidenceKind(StrEnum):
    VENUE_RECEIPT = "VENUE_RECEIPT"
    CORE_EVENT = "CORE_EVENT"
    OBSERVATION = "OBSERVATION"
    MODEL_RESPONSE = "MODEL_RESPONSE"
    IMPORTED_CLAIM = "IMPORTED_CLAIM"


class CheckStatus(StrEnum):
    PASS = "PASS"  # nosec B105: check status enum literal, not a password
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_RUN = "NOT_RUN"
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True, slots=True)
class Money:
    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        decimal_value(self.amount, "amount")
        if not isinstance(self.currency, str) or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ContractError("currency must be an explicit uppercase three-letter code")


@dataclass(frozen=True, slots=True)
class AccountRunKey:
    """Stable business namespace; survives process/build/epoch changes."""

    account_id: str
    run_id: str
    environment: Environment = Environment.DISCONNECTED_SIMULATION

    def __post_init__(self) -> None:
        identifier(self.account_id, "account_id")
        identifier(self.run_id, "run_id")
        if self.environment is not Environment.DISCONNECTED_SIMULATION:
            raise ContractError("v1 admits only disconnected simulation")


@dataclass(frozen=True, slots=True)
class RunScope:
    account_id: str
    run_id: str
    epoch: int
    build_id: str
    policy_id: str
    scenario_id: str
    adapter_id: str
    environment: Environment = Environment.DISCONNECTED_SIMULATION

    def __post_init__(self) -> None:
        for field in ("account_id", "run_id", "build_id", "policy_id", "scenario_id", "adapter_id"):
            identifier(getattr(self, field), field)
        integer(self.epoch, "epoch", minimum=1)
        if self.environment is not Environment.DISCONNECTED_SIMULATION:
            raise ContractError("v1 admits only disconnected simulation")

    @property
    def key(self) -> AccountRunKey:
        return AccountRunKey(self.account_id, self.run_id, self.environment)


@dataclass(frozen=True, slots=True)
class StateReference:
    state_id: str
    scope: RunScope
    version: int
    observed_at: datetime
    valid_until: datetime
    venue_sequence: int

    def __post_init__(self) -> None:
        identifier(self.state_id, "state_id")
        if not isinstance(self.scope, RunScope):
            raise ContractError("scope must be RunScope")
        integer(self.version, "version")
        integer(self.venue_sequence, "venue_sequence")
        utc_time(self.observed_at, "observed_at")
        utc_time(self.valid_until, "valid_until")
        if self.valid_until <= self.observed_at:
            raise ContractError("state validity must end after observation")


@dataclass(frozen=True, slots=True)
class Permissions:
    new_risk: NewRiskPermission = NewRiskPermission.UNKNOWN
    management: ManagementPermission = ManagementPermission.UNKNOWN
    generation: int | None = None
    confirmed_barrier_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.new_risk, NewRiskPermission) or not isinstance(
            self.management, ManagementPermission
        ):
            raise ContractError("permissions must use the shared enums")
        if self.generation is not None:
            integer(self.generation, "generation")
        if self.confirmed_barrier_id is not None:
            identifier(self.confirmed_barrier_id, "confirmed_barrier_id")
        if (self.new_risk is not NewRiskPermission.UNKNOWN or self.management is not ManagementPermission.UNKNOWN) and (
            self.generation is None or self.confirmed_barrier_id is None
        ):
            raise ContractError("observed permissions require a generation and confirmed barrier")
