"""U1: concrete equal-information flat/typed model-input preparation and scoring.

No hidden permissible-action key is accepted by packet construction or inference.
No model is run by construction. This study has its own budget and approval;
Stage B acceptance calls may not be silently reused as U1 study allowance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
import json
from typing import Callable

from cas_forex_revamp.contracts import (
    CheckStatus, ContractError, DecisionOrigin, DecisionRequest, DecisionResult,
    InferenceBudget, ModelInputComparisonPlan, canonical_bytes, content_digest, to_wire,
)
from cas_forex_revamp.contracts.decisions import ids
from cas_forex_revamp.contracts.primitives import digest, identifier, integer, utc_time

from .decisions import check_result
from .model import (
    ActualModelDecisionAdapter, InferenceReceiptVerifier, ModelBackend,
    ModelInvocation, ModelSpecification, OUTPUT_SCHEMA_ID,
)


@dataclass(frozen=True, slots=True)
class EvidenceAvailability:
    """Study sidecar until availability is supplied by the shared trusted reader."""

    evidence_id: str
    content_sha256: str
    available_at: datetime

    def __post_init__(self) -> None:
        identifier(self.evidence_id, "evidence_id")
        digest(self.content_sha256, "content_sha256")
        utc_time(self.available_at, "available_at")


def _check_availability(request: DecisionRequest, availability: tuple[EvidenceAvailability, ...],
                        cutoff: datetime) -> None:
    if type(availability) is not tuple or any(not isinstance(x, EvidenceAvailability) for x in availability):
        raise ContractError("evidence availability must be an immutable typed tuple")
    ids(tuple(x.evidence_id for x in availability), "availability_ids")
    mapped = {x.evidence_id: x for x in availability}
    if set(mapped) != {x.evidence_id for x in request.evidence}:
        raise ContractError("every evidence item needs exactly one availability record")
    for evidence in request.evidence:
        item = mapped[evidence.evidence_id]
        if item.content_sha256 != evidence.content_sha256 or not evidence.observed_at <= item.available_at <= cutoff:
            raise ContractError("evidence identity is wrong or unavailable at the decision cutoff")


@dataclass(frozen=True, slots=True)
class PriorDecision:
    request: DecisionRequest
    result: DecisionResult
    available_at: datetime
    evidence_availability: tuple[EvidenceAvailability, ...]

    def __post_init__(self) -> None:
        check_result(self.request, self.result)
        utc_time(self.available_at, "available_at")
        if self.available_at < self.result.provenance.completed_at:
            raise ContractError("history cannot be available before the decision completed")
        _check_availability(self.request, self.evidence_availability, self.result.provenance.started_at)


@dataclass(frozen=True, slots=True)
class ComparisonCase:
    """Visible case facts only. Opaque case IDs must not encode scoring answers."""

    case_id: str
    request: DecisionRequest
    cutoff: datetime
    evidence_availability: tuple[EvidenceAvailability, ...]
    history: tuple[PriorDecision, ...] = ()
    require_two_distinct_choices: bool = False

    def __post_init__(self) -> None:
        identifier(self.case_id, "case_id")
        if not isinstance(self.request, DecisionRequest):
            raise ContractError("case requires a typed request")
        utc_time(self.cutoff, "cutoff")
        if not self.request.state.observed_at <= self.cutoff < self.request.state.valid_until:
            raise ContractError("case cutoff is outside its current observation window")
        _check_availability(self.request, self.evidence_availability, self.cutoff)
        if type(self.history) is not tuple or len(self.history) > 16 or any(
            not isinstance(x, PriorDecision) for x in self.history
        ):
            raise ContractError("history must be a bounded immutable tuple")
        ids(tuple(x.request.request_id for x in self.history), "history_requests", 16)
        if any(x.available_at > self.cutoff or x.request.state.scope != self.request.state.scope
               or x.request.request_id == self.request.request_id for x in self.history):
            raise ContractError("history is future, cross-scope, or self-referential")
        if tuple(x.available_at for x in self.history) != tuple(sorted(x.available_at for x in self.history)):
            raise ContractError("history must preserve chronological availability order")
        if type(self.require_two_distinct_choices) is not bool:
            raise ContractError("case alternative requirement must be boolean")
        if self.require_two_distinct_choices and len({(x.strategy_id, x.timeframe) for x in self.request.options}) < 2:
            raise ContractError("this sealed case needs two distinct strategy/timeframe choices plus WAIT")
        if any(x.intent.origin is not DecisionOrigin.ACTUAL_MODEL for x in self.request.options):
            raise ContractError("U1 requires actual-model intents, not scripted/owner capabilities")


def _semantic_payload(case: ComparisonCase) -> dict:
    """Both representations contain precisely these rows and typed relations."""
    request = case.request
    records = []
    def add(kind: str, key: str, payload: object) -> None:
        records.append({"ordinal": len(records), "kind": kind, "id": key, "value": to_wire(payload)})
    add("PRESENT", "present", {"request_id": request.request_id,
                                "opportunity_set_id": request.opportunity_set_id,
                                "state": request.state, "cutoff": case.cutoff})
    add("WAIT", "wait", {"selected_action_ref": None, "meaning": "explicit WAIT; no action"})
    for index, option in enumerate(request.options):
        add("ALTERNATIVE", f"alternative-{index}", option)
    for index, fact in enumerate(request.facts):
        add("FACT", f"fact-{index}", fact)
    for index, evidence in enumerate(request.evidence):
        add("EVIDENCE", f"evidence-{index}", evidence)
    for index, item in enumerate(case.evidence_availability):
        add("AVAILABILITY", f"availability-{index}", item)
    for index, item in enumerate(case.history):
        add("HISTORY", f"history-{index}", item)
    evidence_nodes = {x.evidence_id: f"evidence-{i}" for i, x in enumerate(request.evidence)}
    relations = []
    for index, fact in enumerate(request.facts):
        for evidence_id in fact.evidence_ids:
            relations.append({"kind": "CITES", "source": f"fact-{index}", "target": evidence_nodes[evidence_id]})
    for index, _ in enumerate(request.options):
        relations.append({"kind": "PROPOSED_FROM", "source": f"alternative-{index}", "target": "present"})
    for index, _ in enumerate(case.history):
        relations.append({"kind": "AVAILABLE_BEFORE", "source": f"history-{index}", "target": "present"})
    return {"records": records, "relations": relations}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate packet key")
        result[key] = value
    return result


def decode_packet(packet_json: str) -> dict:
    """Normalize either concrete representation for independent parity checks."""
    if not isinstance(packet_json, str) or len(packet_json.encode("utf-8")) > 1_048_576:
        raise ContractError("packet exceeds 1 MiB")
    try:
        packet = json.loads(packet_json, object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError) as exc:
        raise ContractError("packet JSON is malformed") from exc
    if type(packet) is not dict:
        raise ContractError("packet must be an object")
    if packet.get("format") == "FLAT_LIST" and set(packet) == {"format", "records", "relations"}:
        records = packet["records"]
    elif packet.get("format") == "TYPED_ATLAS" and set(packet) == {"format", "groups", "relations"}:
        if type(packet["groups"]) is not list:
            raise ContractError("typed groups must be a list")
        records = []
        kinds = set()
        for group in packet["groups"]:
            if type(group) is not dict or set(group) != {"kind", "records"} or type(group["records"]) is not list:
                raise ContractError("invalid typed group")
            if not isinstance(group["kind"], str) or group["kind"] in kinds:
                raise ContractError("typed group kind must be unique")
            kinds.add(group["kind"])
            for row in group["records"]:
                if type(row) is not dict or row.get("kind") != group["kind"]:
                    raise ContractError("typed group changed a record kind")
                records.append(row)
    else:
        raise ContractError("unsupported packet format or extra semantic fields")
    if type(records) is not list or len(records) > 512:
        raise ContractError("invalid packet record bound")
    for row in records:
        if type(row) is not dict or set(row) != {"ordinal", "kind", "id", "value"}:
            raise ContractError("invalid semantic row")
        integer(row["ordinal"], "ordinal")
        identifier(row["id"], "row_id")
        identifier(row["kind"], "row_kind")
    if sorted(x["ordinal"] for x in records) != list(range(len(records))) or len({x["id"] for x in records}) != len(records):
        raise ContractError("missing/duplicate semantic row")
    relations = packet["relations"]
    node_ids = {x["id"] for x in records}
    if type(relations) is not list or len(relations) > 4096:
        raise ContractError("relations exceed bounded list")
    for relation in relations:
        if type(relation) is not dict or set(relation) != {"kind", "source", "target"}:
            raise ContractError("invalid typed relation")
        if relation["kind"] not in {"CITES", "PROPOSED_FROM", "AVAILABLE_BEFORE"} or (
            relation["source"] not in node_ids or relation["target"] not in node_ids
        ):
            raise ContractError("unsupported relation or missing endpoint")
    normalized = {"records": sorted(records, key=lambda x: x["ordinal"]), "relations": relations}
    canonical_bytes(normalized)  # Reject float/nonfinite payloads, even in nested imported data.
    return normalized


@dataclass(frozen=True, slots=True)
class InputPair:
    case: ComparisonCase
    flat_json: str
    atlas_json: str
    semantic_sha256: str

    def __post_init__(self) -> None:
        expected = _semantic_payload(self.case)
        if decode_packet(self.flat_json) != expected or decode_packet(self.atlas_json) != expected:
            raise ContractError("flat/atlas packet differs from the complete causal source")
        if self.semantic_sha256 != content_digest(expected):
            raise ContractError("semantic packet hash does not match actual paired content")


def prepare_pair(case: ComparisonCase) -> InputPair:
    semantic = _semantic_payload(case)
    flat = {"format": "FLAT_LIST", **semantic}
    kinds = tuple(dict.fromkeys(x["kind"] for x in semantic["records"]))
    atlas = {"format": "TYPED_ATLAS", "groups": [
        {"kind": kind, "records": [x for x in semantic["records"] if x["kind"] == kind]} for kind in kinds
    ], "relations": semantic["relations"]}
    return InputPair(case, canonical_bytes(flat).decode("utf-8"), canonical_bytes(atlas).decode("utf-8"),
                     content_digest(semantic))


@dataclass(frozen=True, slots=True)
class PreparedComparison:
    plan: ModelInputComparisonPlan
    model: ModelSpecification
    pairs: tuple[InputPair, ...]
    seed: int | None = None

    def __post_init__(self) -> None:
        if type(self.pairs) is not tuple or not 1 <= len(self.pairs) <= 128:
            raise ContractError("study requires 1..128 immutable paired cases")
        ids(tuple(x.case.case_id for x in self.pairs), "case_ids")
        ids(tuple(x.case.request.request_id for x in self.pairs), "request_ids")
        if len(self.pairs) > self.plan.budget_per_arm.max_calls:
            raise ContractError("fixed study does not fit its per-arm call ceiling")
        if len(self.pairs) * self.plan.budget_per_arm.max_seconds_per_call > self.plan.budget_per_arm.max_total_seconds:
            raise ContractError("conservative case time reservations do not fit the declared arm budget")
        if (self.plan.model_id, self.plan.model_artifact_sha256, self.plan.prompt_policy_id,
            self.plan.output_schema_id) != (self.model.model_id, self.model.artifact_sha256,
                                           self.model.prompt_version, OUTPUT_SCHEMA_ID):
            raise ContractError("study model/prompt/output settings do not match its frozen plan")
        actual = (content_digest(tuple(x.semantic_sha256 for x in self.pairs)),
                  content_digest(tuple(x.case.request.options for x in self.pairs)),
                  content_digest(tuple(x.case.history for x in self.pairs)))
        if actual != (self.plan.causal_information_sha256, self.plan.candidate_catalog_sha256, self.plan.history_sha256):
            raise ContractError("study plan digests must bind actual paired inputs")
        if any(x.case.request.state.scope.build_id != self.plan.operator_build_id for x in self.pairs):
            raise ContractError("case operator build differs from the plan")
        if self.seed is not None:
            integer(self.seed, "seed")


def prepare_comparison(*, study_id: str, cases: tuple[ComparisonCase, ...], model: ModelSpecification,
                       operator_build_id: str, sealed_case_set_sha256: str,
                       budget_per_arm: InferenceBudget, execution_approval_id: str | None = None,
                       seed: int | None = None) -> PreparedComparison:
    pairs = tuple(prepare_pair(case) for case in cases)
    plan = ModelInputComparisonPlan(
        study_id, model.model_id, model.artifact_sha256, model.prompt_version, operator_build_id,
        content_digest(tuple(x.semantic_sha256 for x in pairs)),
        content_digest(tuple(x.case.request.options for x in pairs)),
        content_digest(tuple(x.case.history for x in pairs)), OUTPUT_SCHEMA_ID,
        sealed_case_set_sha256, budget_per_arm, execution_approval_id=execution_approval_id,
    )
    return PreparedComparison(plan, model, pairs, seed)


@dataclass(frozen=True, slots=True)
class ArmAttempt:
    case_id: str
    arm_id: str
    status: CheckStatus
    result: DecisionResult | None
    error_type: str | None
    input_tokens: int | None = None
    generated_tokens: int | None = None
    latency_ms: int | None = None

    def __post_init__(self) -> None:
        identifier(self.case_id, "case_id")
        if self.arm_id not in {"FLAT_LIST", "TYPED_ATLAS"} or not isinstance(self.status, CheckStatus):
            raise ContractError("invalid arm attempt identity/status")
        for field in ("input_tokens", "generated_tokens", "latency_ms"):
            if getattr(self, field) is not None:
                integer(getattr(self, field), field)


class MatchedModelHarness:
    """Explicit future runner. No inference during construction and no dispatch.

    Fresh session IDs differ across arms. The backend must honor isolated sessions
    and attest effective settings; hidden scoring keys never enter this object.
    Every first attempt is retained; an error ends the study rather than prompting
    tuning/retries. Its incomplete denominators remain visible.
    """

    def __init__(self, prepared: PreparedComparison, *, backend: ModelBackend,
                 receipt_verifier: InferenceReceiptVerifier,
                 execution_gate: Callable[[ModelInvocation], None], clock: Callable[[], datetime]) -> None:
        self.prepared = prepared
        self._attempts: list[ArmAttempt] = []
        self._next = 0
        self._stopped = False
        lookup = {content_digest(x.case.request): x for x in prepared.pairs}
        self._adapters = {}
        for arm in ("FLAT_LIST", "TYPED_ATLAS"):
            def packet_builder(request: DecisionRequest, arm_id: str = arm) -> str:
                pair = lookup.get(content_digest(request))
                if pair is None:
                    raise ContractError("request is not a frozen study case")
                return pair.flat_json if arm_id == "FLAT_LIST" else pair.atlas_json
            self._adapters[arm] = ActualModelDecisionAdapter(
                adapter_id="u1-" + arm, model=prepared.model, budget=prepared.plan.budget_per_arm,
                backend=backend, receipt_verifier=receipt_verifier, execution_gate=execution_gate,
                clock=clock, packet_builder=packet_builder,
                session_prefix="u1-" + content_digest((prepared.plan.study_id, arm)), seed=prepared.seed,
            )

    @property
    def attempts(self) -> tuple[ArmAttempt, ...]:
        return tuple(self._attempts)

    @property
    def status(self) -> CheckStatus:
        if not self._attempts:
            return CheckStatus.NOT_RUN
        if self._stopped or self._next < len(self.prepared.pairs):
            return CheckStatus.INCOMPLETE
        return CheckStatus.PASS  # Completed transport/protocol only; capability is scored separately.

    def run_next(self) -> tuple[ArmAttempt, ...]:
        if self.prepared.plan.execution_approval_id is None:
            raise ContractError("U1 has no separately recorded execution approval")
        if self._stopped or self._next == len(self.prepared.pairs):
            raise ContractError("study ended; no retries or replacement cases in this run")
        pair = self.prepared.pairs[self._next]
        order = ("FLAT_LIST", "TYPED_ATLAS") if self._next % 2 == 0 else ("TYPED_ATLAS", "FLAT_LIST")
        current = []
        for arm in order:
            try:
                result = self._adapters[arm].decide(pair.case.request)
                reply = self._adapters[arm].replies[-1]
                elapsed = reply.completed_at - reply.started_at
                elapsed_ms = elapsed.days * 86400000 + elapsed.seconds * 1000 + elapsed.microseconds // 1000
                attempt = ArmAttempt(pair.case.case_id, arm, CheckStatus.PASS, result, None,
                                     reply.input_tokens, reply.generated_tokens, elapsed_ms)
            except Exception as exc:
                # Error type only: arbitrary provider exception strings may contain sensitive data.
                attempt = ArmAttempt(pair.case.case_id, arm, CheckStatus.ERROR, None, type(exc).__name__)
                self._stopped = True
            self._attempts.append(attempt)
            current.append(attempt)
            if self._stopped:
                break
        self._next += 1
        return tuple(current)


@dataclass(frozen=True, slots=True)
class HiddenActionKey:
    """Scorer sidecar. Never passed to prepare_pair, model, UI, search or exports."""

    case_id: str
    allowed_action_refs: tuple[str | None, ...]
    required_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.case_id, "case_id")
        if type(self.allowed_action_refs) is not tuple or not self.allowed_action_refs:
            raise ContractError("scorer key requires at least one permissible action/WAIT")
        non_wait = tuple(x for x in self.allowed_action_refs if x is not None)
        ids(non_wait, "allowed_action_refs", 64)
        if self.allowed_action_refs.count(None) > 1:
            raise ContractError("duplicate WAIT key")
        ids(self.required_evidence_ids, "required_evidence_ids")


@dataclass(frozen=True, slots=True)
class ArmScore:
    arm_id: str
    planned: int
    attempted: int
    valid_decisions: int
    permissible_decisions: int
    evidence_complete: int
    explicit_waits: int
    errors: int
    status: CheckStatus
    measured_input_tokens: int | None
    measured_generated_tokens: int | None
    measured_latency_ms: int | None


def score_attempts(prepared: PreparedComparison, attempts: tuple[ArmAttempt, ...],
                   hidden_keys: tuple[HiddenActionKey, ...], *,
                   attempt_verifier: Callable[[ArmAttempt], bool] | None = None) -> tuple[ArmScore, ...]:
    """Report raw denominators; guard rejection is not a successful model answer."""
    case_map = {x.case.case_id: x.case for x in prepared.pairs}
    keys = {x.case_id: x for x in hidden_keys}
    if len(keys) != len(hidden_keys) or set(keys) != set(case_map):
        raise ContractError("scorer keys must cover the exact frozen study once")
    for case_id, key in keys.items():
        case = case_map[case_id]
        if not set(key.allowed_action_refs) <= {None, *(x.action_ref for x in case.request.options)}:
            raise ContractError("key names an unsupplied action")
        if not set(key.required_evidence_ids) <= {x.evidence_id for x in case.request.evidence}:
            raise ContractError("key names unsupplied evidence")
    seen = set()
    for attempt in attempts:
        identity = (attempt.case_id, attempt.arm_id)
        if identity in seen or attempt.case_id not in case_map or attempt.arm_id not in {"FLAT_LIST", "TYPED_ATLAS"}:
            raise ContractError("unknown or duplicate first attempt")
        seen.add(identity)
        if attempt.status is CheckStatus.PASS:
            if attempt.result is None or attempt.result.provenance.origin is not DecisionOrigin.ACTUAL_MODEL:
                raise ContractError("U1 scoring requires actual-model provenance, never fixtures/replay")
            check_result(case_map[attempt.case_id].request, attempt.result)
            if attempt_verifier is None or attempt_verifier(attempt) is not True:
                raise ContractError("actual-model scoring requires independent arm/case/inference evidence")
        elif attempt.result is not None:
            raise ContractError("failed attempt cannot claim a valid result")
    scores = []
    for arm in ("FLAT_LIST", "TYPED_ATLAS"):
        rows = [x for x in attempts if x.arm_id == arm]
        valid = [x for x in rows if x.status is CheckStatus.PASS]
        permissible = sum(x.result.selection.selected_action_ref in keys[x.case_id].allowed_action_refs for x in valid)
        evidence_complete = sum(set(keys[x.case_id].required_evidence_ids) <= set(x.result.selection.evidence_ids) for x in valid)
        waits = sum(x.result.selection.selected_action_ref is None for x in valid)
        errors = len(rows) - len(valid)
        status = CheckStatus.NOT_RUN if not rows else (
            CheckStatus.INCOMPLETE if len(rows) != len(case_map) else (
                CheckStatus.PASS if permissible == len(case_map) and evidence_complete == len(case_map) else CheckStatus.FAIL
            )
        )
        # Missing/failed inference usage is unknown, not a false zero-cost result.
        def measured_total(field: str) -> int | None:
            values = [getattr(row, field) for row in rows]
            return sum(values) if values and all(value is not None for value in values) else None
        scores.append(ArmScore(arm, len(case_map), len(rows), len(valid), permissible,
                               evidence_complete, waits, errors, status,
                               measured_total("input_tokens"), measured_total("generated_tokens"),
                               measured_total("latency_ms")))
    return tuple(scores)