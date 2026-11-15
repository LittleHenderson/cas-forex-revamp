"""Small immutable Review projection over supplied shared records.

This is not the pending trusted ledger read envelope, a second ledger, native
CNCM compatibility, or a source-authentication service. Callers must obtain
records from trusted scoped readers. Self hashes only bind supplied content.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from cas_forex_revamp.contracts import (
    AtlasAudience, AtlasContent, AtlasNode, AtlasNodeKind, AtlasView, CommandView,
    ContractError, DecisionRequest, DecisionResult, VenueReceipt, atlas_domain_digest,
    content_digest, intent_digest,
)
from cas_forex_revamp.contracts.decisions import ids, text_value
from cas_forex_revamp.contracts.primitives import digest, identifier, utc_time
from cas_forex_revamp.operator.decisions import check_result


class AlternativeDisposition(StrEnum):
    UNCHOSEN = "UNCHOSEN"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"


class AlternativeEvaluation(StrEnum):
    EVALUATED = "EVALUATED"
    NOT_EVALUATED = "NOT_EVALUATED"
    DEFERRED = "DEFERRED"


class AlternativeEligibility(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class AlternativeNote:
    """An explicit sourced public annotation, never an invented model judgment."""

    action_ref: str
    disposition: AlternativeDisposition
    reason: str
    evidence_ids: tuple[str, ...]
    evaluation: AlternativeEvaluation = AlternativeEvaluation.NOT_EVALUATED
    eligibility: AlternativeEligibility = AlternativeEligibility.UNKNOWN

    def __post_init__(self) -> None:
        identifier(self.action_ref, "action_ref")
        if not isinstance(self.disposition, AlternativeDisposition):
            raise ContractError("alternative disposition must be explicit")
        if not isinstance(self.evaluation, AlternativeEvaluation) or not isinstance(self.eligibility, AlternativeEligibility):
            raise ContractError("evaluation, eligibility and disposition are separate typed dimensions")
        text_value(self.reason, "reason", 1024)
        ids(self.evidence_ids, "evidence_ids")


@dataclass(frozen=True, slots=True)
class HypothesisNote:
    """A supplied possibility, explicitly separate from real positions/outcomes."""

    hypothesis_id: str
    public_condition: str
    evidence_ids: tuple[str, ...]
    action_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.hypothesis_id, "hypothesis_id")
        text_value(self.public_condition, "public_condition", 1024)
        ids(self.evidence_ids, "evidence_ids")
        ids(self.action_refs, "action_refs", 64)

@dataclass(frozen=True, slots=True)
class ReviewRecord:
    """Decision-local read data. admission and receipts remain independent fields."""

    request: DecisionRequest
    as_of: datetime
    result: DecisionResult | None = None
    alternatives: tuple[AlternativeNote, ...] = ()
    admission_event_ids: tuple[str, ...] = ()
    command: CommandView | None = None
    receipts: tuple[VenueReceipt, ...] = ()
    hypotheses: tuple[HypothesisNote, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.request, DecisionRequest):
            raise ContractError("review requires a typed request")
        utc_time(self.as_of, "as_of")
        if self.as_of < self.request.state.observed_at:
            raise ContractError("review checkpoint predates its source state")
        if any(x.observed_at > self.as_of for x in self.request.evidence):
            raise ContractError("future evidence cannot enter this review checkpoint")
        if self.result is not None:
            check_result(self.request, self.result)
            if self.result.provenance.completed_at > self.as_of:
                raise ContractError("future decision cannot enter this review checkpoint")
        if type(self.alternatives) is not tuple or len(self.alternatives) > 64 or any(
            not isinstance(x, AlternativeNote) for x in self.alternatives
        ):
            raise ContractError("alternatives require a bounded immutable tuple")
        ids(tuple(x.action_ref for x in self.alternatives), "alternative_refs", 64)
        choices = {x.action_ref for x in self.request.options}
        evidence = {x.evidence_id for x in self.request.evidence}
        if type(self.hypotheses) is not tuple or len(self.hypotheses) > 32 or any(
            not isinstance(x, HypothesisNote) for x in self.hypotheses
        ):
            raise ContractError("hypotheses require a bounded immutable tuple")
        ids(tuple(x.hypothesis_id for x in self.hypotheses), "hypothesis_ids", 32)
        if any(not set(x.evidence_ids) <= evidence or not set(x.action_refs) <= choices for x in self.hypotheses):
            raise ContractError("hypothesis cites unsupplied evidence or action")
        selected = self.result.selection.selected_action_ref if self.result else None
        for note in self.alternatives:
            if note.action_ref not in choices or not set(note.evidence_ids) <= evidence:
                raise ContractError("alternative annotation refers outside the supplied catalog")
            if note.action_ref == selected:
                raise ContractError("selected action cannot be relabeled a rejected/unchosen alternative")
        ids(self.admission_event_ids, "admission_event_ids")
        if type(self.receipts) is not tuple or len(self.receipts) > 128 or any(
            not isinstance(x, VenueReceipt) for x in self.receipts
        ):
            raise ContractError("receipts require a bounded immutable tuple")
        ids(tuple(x.receipt_id for x in self.receipts), "receipt_ids")
        intent = next((x.intent for x in self.request.options if x.action_ref == selected), None)
        if (self.command is not None or self.receipts or self.admission_event_ids) and intent is None:
            raise ContractError("WAIT/unselected request cannot own an action admission or outcome")
        if self.command is not None:
            if not isinstance(self.command, CommandView) or self.command.payload_sha256 != intent_digest(intent):
                raise ContractError("core command does not bind the selected exact intent")
        sequences = [x.venue_sequence for x in self.receipts]
        if sequences != sorted(set(sequences)):
            raise ContractError("receipt observations must have strictly increasing independent cursors")
        if len({x.command_id for x in self.receipts}) > 1:
            raise ContractError("one decision review cannot merge different command identities")
        for receipt in self.receipts:
            if receipt.key != self.request.state.scope.key or receipt.payload_sha256 != intent_digest(intent):
                raise ContractError("receipt belongs to a different account/run or selected intent")
            if receipt.observed_at > self.as_of:
                raise ContractError("future receipt cannot enter a checkpoint")
            if self.command is not None and receipt.command_id != self.command.command_id:
                raise ContractError("receipt command differs from the supplied core command")


@dataclass(frozen=True, slots=True)
class DecisionList:
    """Strong baseline: preserves every fact, intent, note, selection and receipt."""

    source: ReviewRecord
    source_sha256: str
    wait_available: bool = True

    def __post_init__(self) -> None:
        if self.source_sha256 != content_digest(self.source) or self.wait_available is not True:
            raise ContractError("list must bind its full source and explicit WAIT option")


def decision_list(record: ReviewRecord) -> DecisionList:
    return DecisionList(record, content_digest(record))


def _node_id(category: str, value: object) -> str:
    # Exact content identity prevents focus silently retargeting to changed text.
    return category + "-" + content_digest(value)


def _nodes(record: ReviewRecord) -> tuple[AtlasNode, ...]:
    request = record.request
    nodes: list[AtlasNode] = []
    for fact in request.facts:
        nodes.append(AtlasNode(_node_id("fact", fact), AtlasNodeKind.FACT,
                               fact.label + ": " + fact.value, fact.evidence_ids))
    notes = {x.action_ref: x for x in record.alternatives}
    selected = record.result.selection.selected_action_ref if record.result else None
    for option in request.options:
        note = notes.get(option.action_ref)
        disposition = "SELECTED" if selected == option.action_ref else (
            note.disposition.value if note else ("UNCHOSEN" if record.result else "NOT_EVALUATED")
        )
        label = f"{option.strategy_id} / {option.timeframe}: {option.label} [{disposition}]"
        if note:
            label += f" [evaluation={note.evaluation.value}; eligibility={note.eligibility.value}]: " + note.reason
        nodes.append(AtlasNode(
            _node_id("alternative", (option, note, disposition)), AtlasNodeKind.ALTERNATIVE,
            label, note.evidence_ids if note else (), action_ref=option.action_ref,
            rejected_reason=note.reason if note and note.disposition is AlternativeDisposition.REJECTED else None,
        ))
    nodes.append(AtlasNode(_node_id("wait", (request.request_id, selected, record.result is not None)),
                           AtlasNodeKind.ALTERNATIVE,
                           "WAIT [SELECTED]" if record.result and selected is None else "WAIT [AVAILABLE]", ()))
    if record.result:
        nodes.append(AtlasNode(_node_id("reason", record.result), AtlasNodeKind.REASON,
                               record.result.selection.reason, record.result.selection.evidence_ids))
    for hypothesis in record.hypotheses:
        nodes.append(AtlasNode(_node_id("hypothesis", hypothesis), AtlasNodeKind.HYPOTHESIS,
                               "HYPOTHETICAL: " + hypothesis.public_condition, hypothesis.evidence_ids))
    if len(nodes) > 128:
        raise ContractError("atlas exceeds 128 nodes; list remains available; no silent truncation")
    return tuple(nodes)


class DecisionAtlasProjector:
    """Pure optional projection. Intents and actual outcomes live in the same list source."""

    def __init__(self, audience: AtlasAudience = AtlasAudience.OWNER_DIAGNOSIS) -> None:
        if not isinstance(audience, AtlasAudience):
            raise ContractError("atlas audience must be explicit")
        self._audience = audience

    def project(self, request: DecisionRequest) -> AtlasContent:
        return self.project_review(ReviewRecord(request, request.state.observed_at))

    def project_review(self, record: ReviewRecord) -> AtlasContent:
        # source_request_sha256 retains the shared field's exact request semantics.
        return AtlasContent(
            "atlas-" + content_digest(record), 0, record.request.request_id,
            record.request.state.state_id, content_digest(record.request), self._audience, _nodes(record),
            model_selection_id=record.result.decision_id if record.result else None,
            admission_event_ids=record.admission_event_ids,
            observed_receipt_ids=tuple(x.receipt_id for x in record.receipts),
        )

    def revise(self, previous_record: ReviewRecord, previous: AtlasContent,
               record: ReviewRecord, *, reason: str) -> AtlasContent:
        text_value(reason, "revision_reason", 1024)
        if previous_record.request.state.scope != record.request.state.scope:
            raise ContractError("scope/epoch/build change requires a new atlas, not a late revision")
        expected = self.project_review(previous_record)
        if previous.audience is not expected.audience:
            raise ContractError("cannot revise a different atlas audience")
        if (previous.request_id, previous.current_state_id, previous.source_request_sha256, previous.nodes,
            previous.model_selection_id, previous.admission_event_ids, previous.observed_receipt_ids) != (
            expected.request_id, expected.current_state_id, expected.source_request_sha256, expected.nodes,
            expected.model_selection_id, expected.admission_event_ids, expected.observed_receipt_ids
        ):
            raise ContractError("previous atlas does not project the supplied previous record")
        if record.as_of < previous_record.as_of or record.request.state.version < previous_record.request.state.version:
            raise ContractError("late older observations cannot replace the active review")
        next_content = self.project_review(record)
        return replace(next_content, atlas_id=previous.atlas_id, revision=previous.revision + 1,
                       previous_content_sha256=atlas_domain_digest(previous), revision_reason=reason)


@dataclass(frozen=True, slots=True)
class ViewUpdate:
    view: AtlasView
    reset_reason: str | None


def navigate(view: AtlasView, *, focus_node_id: str | None,
             hypothesis_branch_id: str | None = None) -> AtlasView:
    """Navigation only. It cannot select an action or call the operator."""
    return AtlasView(view.content, focus_node_id, hypothesis_branch_id)


def refresh_view(previous: AtlasView, content: AtlasContent) -> ViewUpdate:
    if content.atlas_id != previous.content.atlas_id or content.revision != previous.content.revision + 1:
        raise ContractError("refresh requires the next revision of this same atlas")
    if content.previous_content_sha256 != atlas_domain_digest(previous.content):
        raise ContractError("refresh must bind the previously inspected content")
    old_nodes = {x.node_id: x for x in previous.content.nodes}
    new_nodes = {x.node_id: x for x in content.nodes}
    stable = {key for key in old_nodes.keys() & new_nodes.keys() if old_nodes[key] == new_nodes[key]}
    focus = previous.focus_node_id if previous.focus_node_id in stable else None
    hypothesis = previous.hypothesis_branch_id if previous.hypothesis_branch_id in stable else None
    changed = (focus, hypothesis) != (previous.focus_node_id, previous.hypothesis_branch_id)
    return ViewUpdate(AtlasView(content, focus, hypothesis),
                      "Previously inspected entity/version is no longer present." if changed else None)