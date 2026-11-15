"""Incremental, in-memory analysis of the design05 protocol.

There is intentionally no operational success/exposure API. Public fixture
inputs may model successful transitions, but every result is ANALYSIS_ONLY and
all cryptographic/durable/live adapters remain UnsupportedAuthority. This class
does not read files, sign, call a clock, spawn, write storage or issue authority.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from functools import wraps
from typing import Any

from .checkpoint import validate_request, validate_transition, require_current_exact, require_recovery_match, require_initial_absence, PublicInitialView
from .contract import Contract, ZERO, canonical_bytes, digest, object_ref, utc
from .errors import ContractViolation, UnsupportedAuthority, require
from .evidence import PublicEvidence, PublicSelections
from .guards import GuardModel, PublicGuardSample, stamp_le, stamp_lt
from .plan import Coverage
from .semantics import Semantics


@dataclass(frozen=True)
class AnalysisResult:
    phase: str
    accepted_record_count: int
    retained_head_sha256: str
    checkpoint_generation: int
    terminal: bool = False
    classification: str = field(default="PUBLIC_SYNTHETIC_ANALYSIS_ONLY", init=False)
    runtime_authority: bool = field(default=False, init=False)
    release_enabled: bool = field(default=False, init=False)


def _terminal_on_error(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        require(not self._terminal, "REPLAY_OR_EQUIVOCATION", "analysis.terminal")
        try:
            return method(self, *args, **kwargs)
        except ContractViolation:
            # A failing analysis branch cannot quietly become a new success.
            # Keep its accepted prefix and exact pending output for inspection.
            self._terminal = True
            self._phase = "FAILED_ANALYSIS_ONLY"
            raise
        except Exception:
            # Malformed nested input cannot leave an ACTIVE retryable branch.
            # Keep raw values and exception text out of the public error.
            self._terminal = True
            self._phase = "FAILED_ANALYSIS_ONLY"
            raise ContractViolation("DECODER_UNAVAILABLE", "analysis.invalid_input") from None
    return wrapped


class ProtocolModel:
    classification = "PUBLIC_SYNTHETIC_ANALYSIS_ONLY"

    def __init__(self, contract: Contract, *, scope: dict[str, Any], plan: dict[str, Any],
                 appointment: dict[str, Any], budget: dict[str, Any]) -> None:
        self.contract = contract
        self.coverage = Coverage(contract, plan, selected_scope=scope)
        self.guards = GuardModel(contract, appointment, budget, selected_scope=scope,
                                 plan_sha256=self.coverage.sha256)
        self._phase = "NEW"
        self._terminal = False
        self._accepted: tuple[dict[str, Any], ...] = ()
        self._checkpoint: dict[str, Any] | None = None
        self._checkpoint_envelope: dict[str, Any] | None = None
        self._pending: dict[str, Any] | None = None
        self._validated_event: dict[str, Any] | None = None
        self._last_ns: int | None = None
        self._expiries: tuple[dict[str, Any], ...] = ()
        self._record_ids: set[str] = set()
        self._attestation_ids: set[str] = set()
        self._checkpoint_ids: set[str] = set()
        self._transition_ids: set[str] = set()
        self._prepare_ids: set[str] = set()
        self._used_raw: set[str] = set()
        self._raw_sizes: dict[str, int] = {}
        self._failure_record: dict[str, Any] | None = None
        self._checkpoint_request_bytes: bytes | None = None
        self._checkpoint_request_history: tuple[bytes, ...] = ()
        self._checkpoint_attempted_at: dict[str, Any] | None = None

    @property
    def accepted(self) -> tuple[dict[str, Any], ...]:
        return copy.deepcopy(self._accepted)

    @property
    def checkpoint(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._checkpoint)

    @property
    def pending_output(self) -> dict[str, Any] | None:
        return None if self._pending is None else copy.deepcopy(self._pending["output"])

    @property
    def retained_checkpoint_requests(self) -> tuple[bytes, ...]:
        return self._checkpoint_request_history

    def _pin_checkpoint_request(self, request_bytes: bytes) -> dict[str, Any]:
        request = self.contract.decode("CheckpointAdvanceRequest", request_bytes)
        require(request["transition_id"] not in self._transition_ids,
                "REPLAY_OR_EQUIVOCATION", "checkpoint.prepared_transition_id")
        self._checkpoint_request_bytes = request_bytes
        self._checkpoint_attempted_at = None
        self._checkpoint_request_history += (request_bytes,)
        self._transition_ids.add(request["transition_id"])
        return request

    def _require_retained_request(self, request) -> None:
        self.contract.validate("CheckpointAdvanceRequest", request)
        require(self._checkpoint_request_bytes is not None
                and canonical_bytes(request) == self._checkpoint_request_bytes,
                "CHECKPOINT_LEDGER_DIVERGENCE", "checkpoint.original_request_bytes")

    def inspect(self) -> AnalysisResult:
        return AnalysisResult(self._phase, len(self._accepted),
                              ZERO if not self._accepted else self._accepted[-1]["event_sha256"],
                              0 if self._checkpoint is None else self._checkpoint["generation"], terminal=self._terminal)

    def _guard(self, sample: PublicGuardSample, *, extra_expiries=()) -> dict[str, Any]:
        now = self.guards.check(sample, previous_ns=self._last_ns,
                                dependency_expiries=self._expiries + tuple(extra_expiries))
        self._last_ns = now["boottime_ns"]
        return now

    def _pending_expiries(self) -> tuple[dict[str, Any], ...]:
        require(self._pending is not None, "OUTPUT_NOT_CHECKPOINTED", "pending.expiries")
        result = [self._pending["envelope"]["body"]["expires"]]
        if self._pending["record"] is not None:
            result.append(self._pending["record"]["witness_envelope"]["body"]["expires"])
        return tuple(result)

    def _envelope(self, record, envelope, purpose, producer, sample, recorded, is_budget=False):
        self.guards.envelope_shape(record, envelope, purpose=purpose, producer_id=producer,
                                   sample=sample, recorded=recorded, is_budget=is_budget)
        aid = envelope["body"]["attestation_id"]
        require(aid not in self._attestation_ids, "REPLAY_OR_EQUIVOCATION", "attestation.id")

    @_terminal_on_error
    def prepare_reservation(self, request_bytes: bytes, *, before: PublicGuardSample,
                            after: PublicGuardSample, initial_view: PublicInitialView) -> AnalysisResult:
        require(self._phase == "NEW" and self._checkpoint is None,
                "BUDGET_ALREADY_CLAIMED", "analysis.reservation")
        self._guard(before)
        now = self._guard(after)
        require_initial_absence(self.contract, self.guards, initial_view, now)
        request = self.contract.decode("CheckpointAdvanceRequest", request_bytes)
        validate_request(self.contract, self.guards, None, request,
            expected_kind="SETUP_RESERVATION", expected_sequence=0, expected_head=ZERO,
            expected_output={"kind": "NONE", "body_ref": None, "attestation_ref": None},
            expected_prepare_id=request["consumer_prepare_commit_id"], now=now)
        self._pin_checkpoint_request(request_bytes)
        self._phase = "RESERVATION_REQUEST_PREPARED"
        return self.inspect()

    @_terminal_on_error
    def model_checkpoint_attempt(self, *, sample: PublicGuardSample) -> AnalysisResult:
        require(self._phase in {"RESERVATION_REQUEST_PREPARED", "CHECKPOINT_REQUEST_PREPARED"}
                and self._checkpoint_request_bytes is not None,
                "CHECKPOINT_LEDGER_DIVERGENCE", "checkpoint.attempt_without_request")
        self._checkpoint_attempted_at = self._guard(sample, extra_expiries=() if self._pending is None else self._pending_expiries())
        self._phase = "RESERVATION_ATTEMPTED" if self._pending is None else "CHECKPOINT_ATTEMPTED"
        return self.inspect()

    @_terminal_on_error
    def reserve(self, request, checkpoint, checkpoint_envelope, *, before: PublicGuardSample,
                after: PublicGuardSample) -> AnalysisResult:
        require(self._phase in {"RESERVATION_ATTEMPTED", "RESERVATION_AMBIGUOUS"} and self._checkpoint is None,
                "BUDGET_ALREADY_CLAIMED", "reservation.attempted")
        self._require_retained_request(request)
        self.contract.validate("ConsumerCheckpoint", checkpoint)
        require(self._checkpoint_attempted_at is not None and stamp_le(self._checkpoint_attempted_at, checkpoint["checkpointed_at"]),
                "CHECKPOINT_MISMATCH", "reservation.before_attempt")
        self._guard(before)
        now = self._guard(after)
        validate_transition(self.contract, self.guards, None, request, checkpoint,
            expected_kind="SETUP_RESERVATION", expected_sequence=0, expected_head=ZERO,
            expected_output={"kind": "NONE", "body_ref": None, "attestation_ref": None},
            expected_prepare_id=request["consumer_prepare_commit_id"], now=now)
        self._envelope(canonical_bytes(checkpoint), checkpoint_envelope,
                       "policy-inheritance-checkpoint-v2", self.guards.role("INDEPENDENT_CHECKPOINT_CUSTODIAN"),
                       after, checkpoint["checkpointed_at"])
        self._checkpoint = copy.deepcopy(checkpoint)
        self._checkpoint_envelope = copy.deepcopy(checkpoint_envelope)
        self._checkpoint_ids.add(checkpoint["checkpoint_id"])
        self._prepare_ids.add(request["consumer_prepare_commit_id"])
        self._attestation_ids.add(checkpoint_envelope["body"]["attestation_id"])
        self._expiries += (copy.deepcopy(checkpoint_envelope["body"]["expires"]),)
        self._phase = "RESERVATION_UNCONFIRMED"
        return self.inspect()

    @_terminal_on_error
    def confirm_reservation(self, observed, *, before, after) -> AnalysisResult:
        require(self._phase == "RESERVATION_UNCONFIRMED", "CHECKPOINT_MISMATCH", "reservation.confirm_phase")
        self._guard(before); require_current_exact(self._checkpoint, observed); self._guard(after)
        self._phase = "RESERVED"
        return self.inspect()

    @_terminal_on_error
    def prepare_budget(self, envelope, *, prepare_id: str, sample: PublicGuardSample) -> AnalysisResult:
        require(self._phase == "RESERVED" and self._pending is None,
                "BUDGET_ALREADY_CLAIMED", "budget.prepare_phase")
        self.contract.validate_value("Id", prepare_id)
        now = self._guard(sample)
        b = self.guards.budget
        self._envelope(canonical_bytes(b), envelope, "policy-inheritance-setup-budget-v2",
                       b["issuer_id"], sample, b["started"], True)
        self._set_pending("BUDGET_CLAIM", b, envelope, "SETUP_BUDGET", prepare_id, 0, ZERO, prepared_at=now)
        return self.inspect()

    def _set_pending(self, transition, body, envelope, kind, prepare_id, sequence, head, record=None, *, prepared_at):
        require(prepare_id not in self._prepare_ids, "REPLAY_OR_EQUIVOCATION", "prepare.commit_id")
        self._prepare_ids.add(prepare_id)
        self._pending = {"transition": transition, "body": copy.deepcopy(body), "envelope": copy.deepcopy(envelope),
                         "output": {"kind": kind, "body_ref": object_ref(canonical_bytes(body), kind),
                                    "attestation_ref": object_ref(canonical_bytes(envelope), "SIGNED_ENVELOPE")},
                         "prepare_id": prepare_id, "sequence": sequence, "head": head,
                         "record": copy.deepcopy(record), "prior_checkpoint": copy.deepcopy(self._checkpoint),
                         "prepared_at": copy.deepcopy(prepared_at)}
        self._checkpoint_request_bytes = None
        self._attestation_ids.add(envelope["body"]["attestation_id"])
        self._phase = "PREPARED"

    @_terminal_on_error
    def validate_event(self, event_bytes: bytes, payload_bytes: bytes, evidence: PublicEvidence,
                      event_envelope, *, selections: PublicSelections,
                      sample: PublicGuardSample) -> AnalysisResult:
        require(self._phase == "ACTIVE" and self._pending is None and len(self._accepted) < 19,
                "INCOMPLETE_STREAM", "event.prepare_phase")
        now = self._guard(sample)
        event = self.contract.decode("Event", event_bytes)
        require(event["kind"] != "FAILURE", "INCOMPLETE_STREAM", "event.failure_is_terminal")
        payload = self.contract.decode(self.contract.spec["payload_type_by_event_kind"][event["kind"]], payload_bytes)
        self.contract.object_bytes(event["payload_ref"], payload_bytes, expected_kind="CANONICAL_PAYLOAD")
        require(event["binding"] == self.guards.binding and event["budget_sha256"] == self.guards.budget_sha256
                and event["stream_id"] == self.guards.appointment["stream_id"]
                and event["producer_id"] == self.guards.role("TRUSTED_CONTROLLER_WITNESS"),
                "CONTEXT_MISMATCH", "event.binding")
        expected_class = self.contract.spec["event_origin_and_evidence_class"][event["kind"]]
        require(event["origin"] == expected_class["origin"] and event["evidence_class"] == expected_class["evidence_class"],
                "CONTEXT_MISMATCH", "event.origin_evidence")
        require(event["sequence"] == len(self._accepted) + 1 and event["previous_record_sha256"] ==
                (ZERO if not self._accepted else self._accepted[-1]["event_sha256"]),
                "SEQUENCE_GAP", "event.chain")
        require(event["record_id"] not in self._record_ids, "REPLAY_OR_EQUIVOCATION", "event.record_id")
        self.coverage.require_next(event, tuple(r["event"]["slot_id"] for r in self._accepted))
        require(stamp_le(self.guards.budget["started"], event["observed_start"])
                and stamp_le(event["observed_start"], event["observed_end"])
                and stamp_le(event["observed_end"], event["recorded"]) and stamp_le(event["recorded"], now),
                "CONTEXT_MISMATCH", "event.time")
        if self._accepted:
            require(stamp_le(self._accepted[-1]["event"]["recorded"], event["recorded"]),
                    "CONTEXT_MISMATCH", "event.recording_order")
        self._envelope(event_bytes, event_envelope, "policy-inheritance-witness-v2",
                       event["producer_id"], sample, event["recorded"])
        require(type(evidence) is PublicEvidence and evidence.total_bytes <= self.coverage.plan["max_raw_bytes"],
                "RAW_EVIDENCE_UNAVAILABLE", "event.evidence_limit")
        require(evidence.decoder_sha256 == self.coverage.slot(event["slot_id"])["payload_decoder_sha256"],
                "DECODER_UNAVAILABLE", "event.decoder_pin")
        combined_sizes = dict(self._raw_sizes)
        combined_sizes.update(evidence.sizes)
        require(sum(combined_sizes.values()) <= self.coverage.plan["max_raw_bytes"],
                "RAW_EVIDENCE_UNAVAILABLE", "stream.evidence_limit")
        semantics = Semantics(self.contract, self.coverage, selections)
        semantics.validate(event, payload, evidence, self._accepted, now=now)
        self._validated_event = {
            "event": event, "payload": payload, "event_sha256": digest(event_bytes),
            "witness_envelope": copy.deepcopy(event_envelope), "raw_objects": evidence.snapshot(),
            "selected_values": selections.values, "decoder_sha256": evidence.decoder_sha256,
            "raw_ids": sorted(evidence.resolve_nested(event) | evidence.resolve_nested(payload)),
            "raw_sizes": evidence.sizes}
        self._attestation_ids.add(event_envelope["body"]["attestation_id"])
        self._phase = "EVENT_VALIDATED"
        return self.inspect()

    @_terminal_on_error
    def prepare_ack(self, ack, ack_envelope, *, sample: PublicGuardSample) -> AnalysisResult:
        require(self._phase == "EVENT_VALIDATED" and self._validated_event is not None and self._pending is None,
                "INCOMPLETE_STREAM", "ack.validated_event")
        record = self._validated_event
        event = record["event"]
        now = self._guard(sample, extra_expiries=(record["witness_envelope"]["body"]["expires"],))
        self.contract.validate("IngestionAck", ack)
        require(ack["binding"] == self.guards.binding and ack["budget_sha256"] == self.guards.budget_sha256
                and ack["consumer_id"] == self.guards.role("INDEPENDENT_SETUP_CONSUMER")
                and ack["stream_id"] == event["stream_id"] and ack["sequence"] == event["sequence"]
                and ack["record_sha256"] == record["event_sha256"] and stamp_le(event["recorded"], ack["acknowledged"])
                and stamp_le(ack["acknowledged"], now), "CONTEXT_MISMATCH", "ack.exact_event")
        self._envelope(canonical_bytes(ack), ack_envelope, "policy-inheritance-ingestion-ack-v2",
                       ack["consumer_id"], sample, ack["acknowledged"])
        self._set_pending("ACK_EXPOSURE", ack, ack_envelope, "INGESTION_ACK", ack["retention_commit_id"],
                          event["sequence"], record["event_sha256"], record, prepared_at=now)
        self._validated_event = None
        return self.inspect()

    @_terminal_on_error
    def prepare_event(self, event_bytes: bytes, payload_bytes: bytes, evidence: PublicEvidence,
                      event_envelope, ack, ack_envelope, *, selections: PublicSelections,
                      sample: PublicGuardSample) -> AnalysisResult:
        """Public-fixture convenience only; the split API has no future ACK input."""
        self.validate_event(event_bytes, payload_bytes, evidence, event_envelope,
                            selections=selections, sample=sample)
        return self.prepare_ack(ack, ack_envelope, sample=sample)

    @_terminal_on_error
    def prepare_checkpoint(self, request_bytes: bytes, *, sample: PublicGuardSample) -> AnalysisResult:
        require(self._phase == "PREPARED" and self._pending is not None,
                "OUTPUT_NOT_CHECKPOINTED", "checkpoint.prepare_without_output")
        now = self._guard(sample, extra_expiries=self._pending_expiries())
        pending = self._pending
        request = self.contract.decode("CheckpointAdvanceRequest", request_bytes)
        validate_request(self.contract, self.guards, pending["prior_checkpoint"], request,
            expected_kind=pending["transition"], expected_sequence=pending["sequence"], expected_head=pending["head"],
            expected_output=pending["output"], expected_prepare_id=pending["prepare_id"], now=now,
            not_before=(pending["prepared_at"], pending["envelope"]["body"]["issued"]))
        self._pin_checkpoint_request(request_bytes)
        self._phase = "CHECKPOINT_REQUEST_PREPARED"
        return self.inspect()

    @_terminal_on_error
    def record_checkpoint(self, request, checkpoint, checkpoint_envelope, *, before, after) -> AnalysisResult:
        self.contract.validate("CheckpointAdvanceRequest", request)
        self.contract.validate("ConsumerCheckpoint", checkpoint)
        require(self._phase in {"CHECKPOINT_ATTEMPTED", "AMBIGUOUS"} and self._pending is not None,
                "OUTPUT_NOT_CHECKPOINTED", "checkpoint.pending")
        self._require_retained_request(request)
        require(self._checkpoint_attempted_at is not None and stamp_le(self._checkpoint_attempted_at, checkpoint["checkpointed_at"]),
                "CHECKPOINT_MISMATCH", "checkpoint.before_attempt")
        pending = self._pending
        self._guard(before, extra_expiries=self._pending_expiries())
        now = self._guard(after, extra_expiries=self._pending_expiries())
        require(checkpoint["checkpoint_id"] not in self._checkpoint_ids,
                "REPLAY_OR_EQUIVOCATION", "checkpoint.ids")
        validate_transition(self.contract, self.guards, pending["prior_checkpoint"], request, checkpoint,
                            expected_kind=pending["transition"], expected_sequence=pending["sequence"],
                            expected_head=pending["head"], expected_output=pending["output"],
                            expected_prepare_id=pending["prepare_id"], now=now,
                            not_before=(pending["prepared_at"], pending["envelope"]["body"]["issued"]))
        self._envelope(canonical_bytes(checkpoint), checkpoint_envelope, "policy-inheritance-checkpoint-v2",
                       self.guards.role("INDEPENDENT_CHECKPOINT_CUSTODIAN"), after, checkpoint["checkpointed_at"])
        self._checkpoint = copy.deepcopy(checkpoint)
        self._checkpoint_envelope = copy.deepcopy(checkpoint_envelope)
        self._checkpoint_ids.add(checkpoint["checkpoint_id"])
        self._attestation_ids.add(checkpoint_envelope["body"]["attestation_id"])
        self._expiries += (copy.deepcopy(checkpoint_envelope["body"]["expires"]),)
        self._phase = "CHECKPOINTED_UNCONFIRMED"
        return self.inspect()

    @_terminal_on_error
    def mark_checkpoint_response_unknown(self) -> AnalysisResult:
        require(self._phase in {"CHECKPOINT_ATTEMPTED", "RESERVATION_ATTEMPTED"}
                and self._checkpoint_request_bytes is not None,
                "CHECKPOINT_LEDGER_DIVERGENCE", "unknown.pending")
        self._phase = "RESERVATION_AMBIGUOUS" if self._pending is None else "AMBIGUOUS"
        return self.inspect()

    @_terminal_on_error
    def recover_reservation(self, request, checkpoint, envelope, *, before, after) -> AnalysisResult:
        require(self._phase == "RESERVATION_AMBIGUOUS", "CHECKPOINT_LEDGER_DIVERGENCE", "recovery.reservation_phase")
        return self.reserve(request, checkpoint, envelope, before=before, after=after)

    @_terminal_on_error
    def recover_checkpoint(self, request, checkpoint, envelope, *, before, after) -> AnalysisResult:
        require(self._phase == "AMBIGUOUS" and self._pending is not None,
                "CHECKPOINT_LEDGER_DIVERGENCE", "recovery.pending")
        self._require_retained_request(request)
        require_recovery_match(self._pending["output"], self._pending["prepare_id"], checkpoint)
        return self.record_checkpoint(request, checkpoint, envelope, before=before, after=after)

    @_terminal_on_error
    def confirm_current(self, observed, *, before, after) -> AnalysisResult:
        require(self._phase == "CHECKPOINTED_UNCONFIRMED" and self._pending is not None,
                "CHECKPOINT_ADVANCE_UNCONFIRMED", "confirmation.phase")
        self._guard(before, extra_expiries=self._pending_expiries())
        require_current_exact(self._checkpoint, observed)
        self._guard(after, extra_expiries=self._pending_expiries())
        self._phase = "CONFIRMED_NOT_EXPOSED"
        return self.inspect()

    @_terminal_on_error
    def model_exposure(self, *, sample: PublicGuardSample) -> AnalysisResult:
        """Model the final guard/order only; never return a signed runtime output."""
        require(self._phase == "CONFIRMED_NOT_EXPOSED" and self._pending is not None,
                "OUTPUT_NOT_CHECKPOINTED", "exposure.phase")
        pending = self._pending
        extra = [pending["envelope"]["body"]["expires"]]
        if pending["record"] is not None:
            extra.append(pending["record"]["witness_envelope"]["body"]["expires"])
        self._guard(sample, extra_expiries=extra)
        if pending["transition"] == "ACK_EXPOSURE":
            record = copy.deepcopy(pending["record"])
            self._accepted += (record,)
            self._record_ids.add(record["event"]["record_id"])
            self._used_raw.update(record["raw_ids"])
            self._raw_sizes.update(record["raw_sizes"])
            self._phase = "SEALED" if len(self._accepted) == 19 else "ACTIVE"
        elif pending["transition"] == "BUDGET_CLAIM":
            self._phase = "ACTIVE"
        else:
            self._phase = "DECIDED_ANALYSIS_ONLY"
            self._terminal = True
        self._expiries += tuple(copy.deepcopy(extra))
        self._pending = None
        return self.inspect()

    @_terminal_on_error
    def prepare_decision(self, decision, envelope, *, sample: PublicGuardSample,
                         independently_observed_checkpoint: dict[str, Any] | None) -> AnalysisResult:
        require(self._phase == "SEALED" and len(self._accepted) == 19 and self._pending is None
                and self._checkpoint is not None and self._checkpoint["event_sequence"] == 19
                and self._checkpoint["generation"] == 21,
                "INCOMPLETE_STREAM", "decision.sealed_prefix")
        now = self._guard(sample)
        require_current_exact(self._checkpoint, independently_observed_checkpoint)
        # Recheck retained bytes and semantics, not only the count/seal label.
        # These are immutable public premises, not fresh OS observations.
        for index, record in enumerate(self._accepted):
            event_bytes = canonical_bytes(record["event"])
            require(digest(event_bytes) == record["event_sha256"], "RAW_BYTES_MISMATCH", "decision.retained_event")
            self.contract.validate("Event", record["event"])
            retained = PublicEvidence(self.contract, record["raw_objects"], decoder_sha256=record["decoder_sha256"])
            self.contract.object_bytes(record["event"]["payload_ref"], canonical_bytes(record["payload"]),
                                       expected_kind="CANONICAL_PAYLOAD")
            self.guards.envelope_shape(event_bytes, record["witness_envelope"],
                purpose="policy-inheritance-witness-v2", producer_id=record["event"]["producer_id"],
                sample=sample, recorded=record["event"]["recorded"])
            Semantics(self.contract, self.coverage, PublicSelections(record["selected_values"])).validate(
                record["event"], record["payload"], retained, self._accepted[:index], now=now)
        self.contract.validate("ConsumerDecision", decision)
        expected_evidence = list(dict.fromkeys(r["event"]["evidence_class"] for r in self._accepted))
        interval = self.contract.decode("AuthenticatedInterval", sample.interval_json)
        require(decision["binding"] == self.guards.binding
                and decision["budget_sha256"] == self.guards.budget_sha256
                and decision["stream_id"] == self.guards.appointment["stream_id"]
                and decision["consumer_id"] == self.guards.role("INDEPENDENT_SETUP_CONSUMER")
                and decision["status"] == "ACCEPTED_NARROW_METHOD" and decision["failure_code"] is None
                and decision["retained_record_count"] == 19
                and decision["sealed_head_sha256"] == decision["retained_prefix_head_sha256"] == self._accepted[-1]["event_sha256"]
                and decision["accepted_claims"] == self.contract.spec["enums"]["AcceptedClaim"]
                and decision["evidence_classes"] == expected_evidence
                and decision["authenticated_interval_ref"] == object_ref(sample.interval_json, "AUTHENTICATED_INTERVAL"),
                "CLAIM_OUTSIDE_METHOD_SCOPE", "decision.exact_scope")
        require(stamp_le(self._accepted[-1]["event"]["recorded"], decision["decided"])
                and stamp_le(decision["decided"], now) and stamp_lt(now, decision["expires"])
                and stamp_le(decision["expires"], self.guards.budget["deadline"])
                and utc(decision["expires"]["utc"]) <= utc(interval["expires_at_utc"]),
                "AUTHENTICATED_INTERVAL_EXPIRED", "decision.interval")
        for expiry in self._expiries:
            require(stamp_le(decision["expires"], expiry),
                    "AUTHENTICATED_INTERVAL_EXPIRED", "decision.dependency_expiry")
        self._envelope(canonical_bytes(decision), envelope, "policy-inheritance-method-decision-v2",
                       decision["consumer_id"], sample, decision["decided"])
        require(stamp_le(envelope["body"]["expires"], decision["expires"]),
                "AUTHENTICATED_INTERVAL_EXPIRED", "decision.envelope_expiry")
        self._set_pending("DECISION_EXPOSURE", decision, envelope, "METHOD_DECISION", decision["retention_commit_id"],
                          19, decision["sealed_head_sha256"], prepared_at=now)
        return self.inspect()

    def operational_output(self):
        raise UnsupportedAuthority("convert_analysis_to_operational_output")

    def release_consume(self):
        raise UnsupportedAuthority("release_consume")

    @_terminal_on_error
    def record_failure(self, event_bytes: bytes, payload_bytes: bytes, evidence: PublicEvidence,
                       envelope, *, sample: PublicGuardSample) -> AnalysisResult:
        require(self._phase == "ACTIVE" and self._pending is None,
                "INCOMPLETE_STREAM", "failure.phase")
        now = self._guard(sample)
        event = self.contract.decode("Event", event_bytes)
        payload = self.contract.decode("FailurePayload", payload_bytes)
        self.contract.object_bytes(event["payload_ref"], payload_bytes, expected_kind="CANONICAL_PAYLOAD")
        require(event["kind"] == "FAILURE" and event["slot_id"] == "terminal-failure"
                and event["origin"] == "CONTROLLER" and event["evidence_class"] == "CONTROLLER_STREAM_METADATA"
                and event["binding"] == self.guards.binding and event["budget_sha256"] == self.guards.budget_sha256
                and event["stream_id"] == self.guards.appointment["stream_id"]
                and event["producer_id"] == self.guards.role("TRUSTED_CONTROLLER_WITNESS")
                and event["sequence"] == len(self._accepted) + 1
                and event["previous_record_sha256"] == self.inspect().retained_head_sha256,
                "CONTEXT_MISMATCH", "failure.context")
        require(stamp_le(self.guards.budget["started"], event["observed_start"])
                and stamp_le(event["observed_start"], event["observed_end"])
                and stamp_le(event["observed_end"], event["recorded"]) and stamp_le(event["recorded"], now),
                "CONTEXT_MISMATCH", "failure.time")
        require(payload["last_retained_record_id"] == (None if not self._accepted else self._accepted[-1]["event"]["record_id"]),
                "CONTEXT_MISMATCH", "failure.prefix")
        if payload["failed_slot_id"] is not None:
            self.coverage.slot(payload["failed_slot_id"])
        self._envelope(event_bytes, envelope, "policy-inheritance-witness-v2", event["producer_id"], sample, event["recorded"])
        require(type(evidence) is PublicEvidence, "RAW_EVIDENCE_UNAVAILABLE", "failure.raw")
        evidence.resolve_nested(event); evidence.resolve_nested(payload)
        self._failure_record = {"event": event, "payload": payload, "event_sha256": digest(event_bytes)}
        self._terminal = True
        self._phase = "FAILED_ANALYSIS_ONLY"
        return self.inspect()
