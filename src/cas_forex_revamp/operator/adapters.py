"""Finite scripted/replay adapters. Neither can call another adapter as fallback."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Callable

from cas_forex_revamp.contracts import (
    ContractError, DecisionOrigin, DecisionProvenance, DecisionRequest, DecisionResult,
    DecisionSelection, bind_selection, canonical_bytes, content_digest, selection_from_json,
)
from cas_forex_revamp.contracts.primitives import digest, identifier

from .decisions import OperatorUnavailable, check_request_time, decision_identity


@dataclass(frozen=True, slots=True)
class ScriptStep:
    """Sealed expected request and exact choice; WAIT is an explicit selection."""

    request_sha256: str
    selection: DecisionSelection

    def __post_init__(self) -> None:
        digest(self.request_sha256, "request_sha256")
        if not isinstance(self.selection, DecisionSelection):
            raise ContractError("script step requires an explicit typed selection")


class ScriptedDecisionAdapter:
    """Stage A decision schedule; no strategy-edge or actual-model claim."""

    def __init__(self, steps: tuple[ScriptStep, ...], *, adapter_id: str,
                 clock: Callable[[], datetime], prompt_version: str = "script-v1") -> None:
        if type(steps) is not tuple or not 1 <= len(steps) <= 4096 or any(
            not isinstance(x, ScriptStep) for x in steps
        ):
            raise ContractError("script must be a nonempty bounded immutable step tuple")
        self._steps = steps
        self._index = 0
        self._adapter_id = identifier(adapter_id, "adapter_id")
        self._prompt_version = identifier(prompt_version, "prompt_version")
        self._clock = clock

    @property
    def remaining(self) -> int:
        return len(self._steps) - self._index

    def decide(self, request: DecisionRequest) -> DecisionResult:
        if self._index == len(self._steps):
            raise OperatorUnavailable("script exhausted; no WAIT or model fallback")
        step = self._steps[self._index]
        if content_digest(request) != step.request_sha256:
            raise ContractError("script request mismatch; step was not consumed")
        start = self._clock()
        check_request_time(request, start)
        bind_selection(step.selection, request)
        result = DecisionResult(decision_identity(request), step.selection, DecisionProvenance(
            origin=DecisionOrigin.SCRIPTED, adapter_id=self._adapter_id,
            request_sha256=content_digest(request), response_sha256=content_digest(step.selection),
            prompt_version=self._prompt_version, started_at=start, completed_at=self._clock(),
        ))
        self._index += 1
        return result


@dataclass(frozen=True, slots=True)
class ReplayEntry:
    request_sha256: str
    raw_selection_json: str
    captured_response_sha256: str
    source_receipt_id: str

    def __post_init__(self) -> None:
        digest(self.request_sha256, "request_sha256")
        digest(self.captured_response_sha256, "captured_response_sha256")
        identifier(self.source_receipt_id, "source_receipt_id")
        if not isinstance(self.raw_selection_json, str) or len(self.raw_selection_json.encode("utf-8")) > 16384:
            raise ContractError("replay response exceeds selection byte bound")
        if sha256(self.raw_selection_json.encode("utf-8")).hexdigest() != self.captured_response_sha256:
            raise ContractError("replay bytes do not match the captured response digest")


class ReplayDecisionAdapter:
    """Read-only response replay, visibly REPLAY even when its source was a model."""

    def __init__(self, entries: tuple[ReplayEntry, ...], *, adapter_id: str,
                 clock: Callable[[], datetime]) -> None:
        if type(entries) is not tuple or not 1 <= len(entries) <= 4096 or any(
            not isinstance(x, ReplayEntry) for x in entries
        ):
            raise ContractError("replay requires a bounded immutable entry tuple")
        self._entries = entries
        self._index = 0
        self._adapter_id = identifier(adapter_id, "adapter_id")
        self._clock = clock

    def decide(self, request: DecisionRequest) -> DecisionResult:
        if self._index == len(self._entries):
            raise OperatorUnavailable("replay exhausted; no external fallback")
        entry = self._entries[self._index]
        if content_digest(request) != entry.request_sha256:
            raise ContractError("replay request mismatch")
        start = self._clock()
        selection = selection_from_json(entry.raw_selection_json, request)
        result = DecisionResult(decision_identity(request), selection, DecisionProvenance(
            origin=DecisionOrigin.REPLAY, adapter_id=self._adapter_id,
            request_sha256=entry.request_sha256, response_sha256=entry.captured_response_sha256,
            prompt_version="replay-v1", started_at=start, completed_at=self._clock(),
        ))
        self._index += 1
        return result

from .frontier_backends import (
    FRONTIER_MODEL_CATALOG,
    FrontierChatBackend,
    FrontierConfigurationError,
    FrontierModelCatalogEntry,
    FrontierModelRegistry,
    FrontierReceiptVerifier,
    FrontierTransportError,
)
