"""Operator choices and optional decision organization, without dispatch authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .commands import ActionIntent
from .primitives import ContractError, DecisionOrigin, EvidenceKind, StateReference, digest, identifier, integer, utc_time


def text_value(value: str, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be nonempty text of at most {maximum} UTF-8 bytes")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise ContractError(f"{field} exceeds {maximum} UTF-8 bytes")
    except UnicodeError as exc:
        raise ContractError(f"{field} must be valid UTF-8 text") from exc
    return value


def ids(value: tuple[str, ...], field: str, maximum: int = 128) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum:
        raise ContractError(f"{field} must be a bounded immutable tuple")
    for item in value:
        identifier(item, field)
    if len(set(value)) != len(value):
        raise ContractError(f"{field} must not contain duplicate IDs")
    return value


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    evidence_id: str
    kind: EvidenceKind
    producer_id: str
    content_sha256: str
    observed_at: datetime
    receipt_id: str | None = None

    def __post_init__(self) -> None:
        identifier(self.evidence_id, "evidence_id")
        identifier(self.producer_id, "producer_id")
        digest(self.content_sha256, "content_sha256")
        utc_time(self.observed_at, "observed_at")
        if not isinstance(self.kind, EvidenceKind):
            raise ContractError("evidence kind requires EvidenceKind")
        if self.receipt_id is not None:
            identifier(self.receipt_id, "receipt_id")
        if self.kind is EvidenceKind.VENUE_RECEIPT and self.receipt_id is None:
            raise ContractError("venue evidence must reference a receipt")


@dataclass(frozen=True, slots=True)
class DecisionFact:
    fact_id: str
    label: str
    value: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        identifier(self.fact_id, "fact_id")
        text_value(self.label, "label", 160)
        text_value(self.value, "value", 1024)
        ids(self.evidence_ids, "evidence_ids")


@dataclass(frozen=True, slots=True)
class ActionOption:
    action_ref: str
    strategy_id: str
    timeframe: str
    label: str
    intent: ActionIntent

    def __post_init__(self) -> None:
        identifier(self.action_ref, "action_ref")
        identifier(self.strategy_id, "strategy_id")
        identifier(self.timeframe, "timeframe")
        text_value(self.label, "label", 240)
        if not isinstance(self.intent, ActionIntent) or self.action_ref != self.intent.action_ref:
            raise ContractError("an action option must retain its exact typed intent/reference")


@dataclass(frozen=True, slots=True)
class DecisionRequest:
    request_id: str
    opportunity_set_id: str
    state: StateReference
    options: tuple[ActionOption, ...]
    facts: tuple[DecisionFact, ...]
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        identifier(self.request_id, "request_id")
        identifier(self.opportunity_set_id, "opportunity_set_id")
        if not isinstance(self.state, StateReference):
            raise ContractError("decision request requires typed state")
        for field, kind, cap in (("options", ActionOption, 64), ("facts", DecisionFact, 128), ("evidence", EvidenceReference, 128)):
            values = getattr(self, field)
            if type(values) is not tuple or len(values) > cap or any(not isinstance(x, kind) for x in values):
                raise ContractError(f"{field} must be an immutable bounded tuple of {kind.__name__}")
        ids(tuple(x.action_ref for x in self.options), "action_refs", 64)
        ids(tuple(x.fact_id for x in self.facts), "fact_ids")
        evidence_ids = set(ids(tuple(x.evidence_id for x in self.evidence), "evidence_ids"))
        if any(x.intent.source_state != self.state for x in self.options):
            raise ContractError("all options must bind the request's exact state")
        if any(not set(x.evidence_ids) <= evidence_ids for x in self.facts):
            raise ContractError("facts may reference only supplied evidence")


@dataclass(frozen=True, slots=True)
class DecisionSelection:
    """No quantities, authority grants, tool calls or executable instructions."""

    request_id: str
    opportunity_set_id: str
    source_state_id: str
    selected_action_ref: str | None  # None means WAIT, never a fallback order.
    reason: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for field in ("request_id", "opportunity_set_id", "source_state_id"):
            identifier(getattr(self, field), field)
        if self.selected_action_ref is not None:
            identifier(self.selected_action_ref, "selected_action_ref")
        text_value(self.reason, "reason", 1024)
        ids(self.evidence_ids, "evidence_ids")


@dataclass(frozen=True, slots=True)
class DecisionProvenance:
    origin: DecisionOrigin
    adapter_id: str
    request_sha256: str
    response_sha256: str
    prompt_version: str
    started_at: datetime
    completed_at: datetime
    model_id: str | None = None
    model_artifact_sha256: str | None = None
    inference_receipt_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.origin, DecisionOrigin):
            raise ContractError("origin must use DecisionOrigin")
        identifier(self.adapter_id, "adapter_id")
        identifier(self.prompt_version, "prompt_version")
        digest(self.request_sha256, "request_sha256")
        digest(self.response_sha256, "response_sha256")
        utc_time(self.started_at, "started_at")
        utc_time(self.completed_at, "completed_at")
        if self.completed_at < self.started_at:
            raise ContractError("decision completion precedes its start")
        if self.model_id is not None:
            identifier(self.model_id, "model_id")
        if self.model_artifact_sha256 is not None:
            digest(self.model_artifact_sha256, "model_artifact_sha256")
        if self.inference_receipt_id is not None:
            identifier(self.inference_receipt_id, "inference_receipt_id")
        if self.origin is DecisionOrigin.ACTUAL_MODEL and any(
            x is None for x in (self.model_id, self.model_artifact_sha256, self.inference_receipt_id)
        ):
            raise ContractError("ACTUAL_MODEL requires model identity and an inference receipt reference")


@dataclass(frozen=True, slots=True)
class DecisionResult:
    decision_id: str
    selection: DecisionSelection
    provenance: DecisionProvenance

    def __post_init__(self) -> None:
        identifier(self.decision_id, "decision_id")
        if not isinstance(self.selection, DecisionSelection) or not isinstance(self.provenance, DecisionProvenance):
            raise ContractError("decision result requires typed selection and provenance")


class AtlasNodeKind(StrEnum):
    FACT = "FACT"
    ALTERNATIVE = "ALTERNATIVE"
    HYPOTHESIS = "HYPOTHESIS"
    REASON = "REASON"
    REVISION = "REVISION"


class AtlasAudience(StrEnum):
    OWNER_DIAGNOSIS = "OWNER_DIAGNOSIS"
    MATCHED_MODEL_INPUT = "MATCHED_MODEL_INPUT"


@dataclass(frozen=True, slots=True)
class AtlasNode:
    node_id: str
    kind: AtlasNodeKind
    label: str
    evidence_ids: tuple[str, ...]
    related_node_ids: tuple[str, ...] = ()
    action_ref: str | None = None
    rejected_reason: str | None = None

    def __post_init__(self) -> None:
        identifier(self.node_id, "node_id")
        if not isinstance(self.kind, AtlasNodeKind):
            raise ContractError("atlas node kind requires AtlasNodeKind")
        text_value(self.label, "label")
        ids(self.evidence_ids, "evidence_ids")
        ids(self.related_node_ids, "related_node_ids")
        if self.action_ref is not None:
            identifier(self.action_ref, "action_ref")
        if self.rejected_reason is not None:
            text_value(self.rejected_reason, "rejected_reason")


@dataclass(frozen=True, slots=True)
class AtlasContent:
    """Domain content only. UI focus is deliberately absent from this digest domain."""

    atlas_id: str
    revision: int
    request_id: str
    current_state_id: str
    source_request_sha256: str
    audience: AtlasAudience
    nodes: tuple[AtlasNode, ...]
    previous_content_sha256: str | None = None
    model_selection_id: str | None = None
    admission_event_ids: tuple[str, ...] = ()
    observed_receipt_ids: tuple[str, ...] = ()
    revision_reason: str | None = None

    def __post_init__(self) -> None:
        for field in ("atlas_id", "request_id", "current_state_id"):
            identifier(getattr(self, field), field)
        integer(self.revision, "revision")
        digest(self.source_request_sha256, "source_request_sha256")
        if not isinstance(self.audience, AtlasAudience):
            raise ContractError("atlas audience must be explicit")
        if type(self.nodes) is not tuple or len(self.nodes) > 128 or any(not isinstance(x, AtlasNode) for x in self.nodes):
            raise ContractError("atlas nodes must be an immutable bounded tuple")
        node_ids = set(ids(tuple(x.node_id for x in self.nodes), "node_ids", 128))
        if any(not set(x.related_node_ids) <= node_ids for x in self.nodes):
            raise ContractError("atlas links must target nodes in this content revision")
        if self.previous_content_sha256 is not None:
            digest(self.previous_content_sha256, "previous_content_sha256")
        if self.revision > 0 and (self.previous_content_sha256 is None or self.revision_reason is None):
            raise ContractError("a revision requires previous content identity and a reason")
        if self.model_selection_id is not None:
            identifier(self.model_selection_id, "model_selection_id")
        ids(self.admission_event_ids, "admission_event_ids")
        ids(self.observed_receipt_ids, "observed_receipt_ids")
        if self.revision_reason is not None:
            text_value(self.revision_reason, "revision_reason")


@dataclass(frozen=True, slots=True)
class AtlasView:
    content: AtlasContent
    focus_node_id: str | None = None
    hypothesis_branch_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, AtlasContent):
            raise ContractError("atlas view requires AtlasContent")
        if self.focus_node_id is not None and self.focus_node_id not in {x.node_id for x in self.content.nodes}:
            raise ContractError("UI focus must reference a node; it never changes actual state")
        if self.hypothesis_branch_id is not None and self.hypothesis_branch_id not in {
            x.node_id for x in self.content.nodes if x.kind is AtlasNodeKind.HYPOTHESIS
        }:
            raise ContractError("hypothesis navigation must reference a hypothesis, not current state")
