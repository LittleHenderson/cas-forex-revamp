"""Bind the steward's read-envelope bytes to an independently supplied anchor.

This consumer does not produce ledger records, appoint its verifier from payload
labels, fetch URLs, or claim that a self-consistent import is a trusted source.
The pinned stdlib schema validator can be supplied explicitly; a trusted reader
and independent semantic/source validation remain required.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Callable

from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.contracts.primitives import digest, identifier, utc_time


SCHEMA_VERSION = "forex.decision-read/0.1"
_FIELDS = {"schema_version", "scope", "cursor", "as_of", "current_state", "decisions",
           "events", "evidence", "validation", "coverage", "domain_digest"}


@dataclass(frozen=True, slots=True)
class TrustedReadAnchor:
    """Obtained from the caller's configured read service, never from imported JSON.

    The read service must bind this to the selected run manifest and coherent
    ledger read. Constructing this Python object is not independent verification.
    """

    anchor_id: str
    producer_id: str
    schema_sha256: str
    domain_sha256: str
    scope_sha256: str
    cursor_sha256: str
    issued_at: datetime
    expires_at: datetime
    reconciliation_confirmed: bool

    def __post_init__(self) -> None:
        identifier(self.anchor_id, "anchor_id")
        identifier(self.producer_id, "producer_id")
        for field in ("schema_sha256", "domain_sha256", "scope_sha256", "cursor_sha256"):
            digest(getattr(self, field), field)
        utc_time(self.issued_at, "issued_at")
        utc_time(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at or type(self.reconciliation_confirmed) is not bool:
            raise ContractError("anchor needs a bounded lifetime and independent reconciliation flag")


@dataclass(frozen=True, slots=True)
class BoundDecisionRead:
    """Validated bytes plus locally established trust facts, without action methods."""

    canonical_json: str
    anchor_id: str
    producer_id: str
    domain_sha256: str
    source_bound: bool
    current_state_claim_allowed: bool
    incomplete: bool
    unknown_or_stale: bool


def _unique(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("duplicate read-envelope key")
        value[key] = item
    return value


def _timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise ContractError(field + " requires a UTC timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(field + " is not a valid timestamp") from exc
    return utc_time(result, field)


def bind_decision_read(raw_json: str, *, now: datetime, expected_scope_sha256: str,
                       schema_sha256: str, schema_validator: Callable[[dict], bool],
                       anchor_reader: Callable[[], TrustedReadAnchor],
                       semantic_validator: Callable[[dict, TrustedReadAnchor], bool]) -> BoundDecisionRead:
    """Strict fail-closed consumption; callbacks are chosen outside the payload.

    schema_validator must validate against the exact steward-owned schema bytes
    named by schema_sha256, including format assertions and nested unknown keys.
    semantic_validator must independently resolve the controlled catalog, reference
    versions/hashes, inference/fence receipts and remaining DECISION_READ_V01 rules.
    No built-in always-true validator or anchor factory is supplied.
    """
    utc_time(now, "now")
    digest(expected_scope_sha256, "expected_scope_sha256")
    digest(schema_sha256, "schema_sha256")
    if not isinstance(raw_json, str) or len(raw_json.encode("utf-8")) > 1_048_576:
        raise ContractError("read envelope exceeds 1 MiB")
    try:
        payload = json.loads(raw_json, object_pairs_hook=_unique)
    except (ValueError, RecursionError) as exc:
        raise ContractError("read envelope is malformed") from exc
    if type(payload) is not dict or set(payload) != _FIELDS or payload["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported read envelope version or semantic fields")
    frozen_bytes = canonical_bytes(payload)
    if schema_validator(payload) is not True:
        raise ContractError("read envelope did not pass the pinned schema validator")
    if canonical_bytes(payload) != frozen_bytes:
        raise ContractError("schema validation mutated immutable source content")
    semantic = {key: value for key, value in payload.items() if key != "domain_digest"}
    actual = content_digest(semantic)
    if payload["domain_digest"] != actual:
        raise ContractError("read envelope self digest does not match its semantic bytes")
    # A new hash or payload VERIFIED label cannot select/replace this trust source.
    anchor = anchor_reader()
    if not isinstance(anchor, TrustedReadAnchor):
        raise ContractError("trusted read service did not supply a typed independent anchor")
    if not anchor.issued_at <= now < anchor.expires_at:
        raise ContractError("independent source anchor is stale or from the future")
    if (anchor.schema_sha256, anchor.domain_sha256, anchor.scope_sha256, anchor.cursor_sha256) != (
        schema_sha256, actual, expected_scope_sha256, content_digest(payload["cursor"])
    ) or content_digest(payload["scope"]) != expected_scope_sha256:
        raise ContractError("imported content differs from selected scope/cursor/producer anchor")
    if semantic_validator(payload, anchor) is not True:
        raise ContractError("controlled catalog and semantic source validation failed")
    if canonical_bytes(payload) != frozen_bytes:
        raise ContractError("semantic validation mutated immutable source content")
    scope = payload["scope"]
    sequence = payload["cursor"]["sequence"]
    as_of = payload["as_of"]
    checkpoint = _timestamp(as_of["available_at"], "available_at") if as_of["available_at"] else None
    if checkpoint is not None and checkpoint > now:
        raise ContractError("read checkpoint is in the future")
    for collection, id_field in (("decisions", "decision_id"), ("events", "event_id"), ("evidence", "evidence_id")):
        items = payload[collection]
        if len({x[id_field] for x in items}) != len(items):
            raise ContractError("duplicate source identities in " + collection)
        for item in items:
            if item["scope"] != scope:
                raise ContractError("read envelope mixes scopes/builds/epochs")
            if collection == "decisions":
                if sequence is None or item["cursor"]["sequence"] is None or item["cursor"]["sequence"] > sequence:
                    raise ContractError("decision cursor is unavailable or ahead of this read")
                if checkpoint is None or _timestamp(item["decided_at"], "decided_at") > checkpoint:
                    raise ContractError("future decision leaked into the read checkpoint")
                candidate_ids = [x["candidate_id"] for x in item["candidates"]]
                if len(set(candidate_ids)) != len(candidate_ids):
                    raise ContractError("duplicate candidate identities")
                selection = item["selection"]
                if selection is None:
                    continue
                if selection["wait"] is True:
                    if selection["candidate_id"] is not None:
                        raise ContractError("WAIT cannot also select a candidate")
                elif selection["candidate_id"] not in candidate_ids:
                    raise ContractError("selection refers outside the candidate catalog")
            else:
                observed = _timestamp(item["observed_at"], "observed_at")
                available = _timestamp(item["available_at"], "available_at")
                if checkpoint is None or not observed <= available <= checkpoint:
                    raise ContractError("record is unavailable at this causal checkpoint")
                if collection == "events" and (sequence is None or item["sequence"] > sequence):
                    raise ContractError("event lies beyond the read cursor")
    state = payload["current_state"]
    complete = payload["coverage"]["complete"] is True
    has_cursor = sequence is not None and payload["cursor"]["ledger_prefix_sha256"] is not None
    observed = _timestamp(state["observed_at"], "state observed_at") if state["observed_at"] else None
    valid_until = _timestamp(state["valid_until"], "state valid_until") if state["valid_until"] else None
    fresh = observed is not None and valid_until is not None and observed <= now < valid_until
    coherent = (has_cursor and state["state_id"] is not None and state["state_sha256"] is not None
                and state["revision"] == payload["cursor"]["current_state_revision"]
                and anchor.reconciliation_confirmed and state["reconciliation"] == "COHERENT")
    current = bool(coherent and fresh and complete and state["freshness"] == "CURRENT")
    return BoundDecisionRead(canonical_bytes(payload).decode("utf-8"), anchor.anchor_id,
                             anchor.producer_id, actual, True, current, not complete, not current)