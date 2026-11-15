"""Pure checkpoint transition rules. No storage, signatures or durability claim."""

from __future__ import annotations

from typing import Any
from dataclasses import dataclass

from .contract import Contract, ZERO, canonical_bytes, digest, object_ref
from .errors import require
from .guards import GuardModel, stamp_le


def original_key(binding: dict[str, Any]) -> dict[str, Any]:
    scope = binding["scope"]
    return {k: scope[k] for k in ["run_id", "original_window_sha256", "setup_identity"]}


@dataclass(frozen=True)
class PublicInitialView:
    """Explicit synthetic read premise. Never authenticated absence or authority."""
    state: str
    original_key_json: bytes
    observed_at_json: bytes
    checkpoint_json: bytes | None


def require_initial_absence(contract: Contract, guards: GuardModel, view: PublicInitialView,
                            now: dict[str, Any]) -> None:
    require(type(view) is PublicInitialView and view.state in {"ABSENT", "PRESENT", "UNAVAILABLE"},
            "CHECKPOINT_AUTHORITY_UNAVAILABLE", "initial.explicit_read")
    require(contract.decode("OriginalSetupKey", view.original_key_json) == original_key(guards.binding)
            and contract.decode("Stamp", view.observed_at_json) == now,
            "CHECKPOINT_AUTHORITY_UNAVAILABLE", "initial.current_key_read")
    require(view.state != "UNAVAILABLE", "CHECKPOINT_AUTHORITY_UNAVAILABLE", "initial.unavailable")
    require(view.state == "ABSENT" and view.checkpoint_json is None,
            "BUDGET_ALREADY_CLAIMED", "initial.existing_or_ambiguous_claim")


def validate_request(contract: Contract, guards: GuardModel, previous, request, *,
                     expected_kind, expected_sequence, expected_head, expected_output,
                     expected_prepare_id, now, not_before=()) -> None:
    """Check the exact request before a modeled attempt; no response is needed."""
    contract.validate("CheckpointAdvanceRequest", request)
    contract.validate("Stamp", now)
    contract.validate("OutputBinding", expected_output)
    if previous is not None:
        contract.validate("ConsumerCheckpoint", previous)
    budget = guards.budget
    generation = 0 if previous is None else previous["generation"]
    prior_hash = ZERO if previous is None else digest(canonical_bytes(previous))
    require(expected_kind in {"SETUP_RESERVATION", "BUDGET_CLAIM", "ACK_EXPOSURE", "DECISION_EXPOSURE", "TERMINAL_ABORT"},
            "CHECKPOINT_MISMATCH", "request.kind")
    require(request["binding"] == budget["binding"] and request["original_setup_key"] == original_key(budget["binding"])
            and request["transition_kind"] == expected_kind and request["expected_generation"] == generation
            and request["expected_checkpoint_sha256"] == prior_hash,
            "CHECKPOINT_MISMATCH", "request.context_order")
    require(request["budget_id"] == budget["budget_id"] and request["budget_sha256"] == guards.budget_sha256
            and request["stream_id"] == guards.appointment["stream_id"]
            and request["original_budget_body_ref"] == object_ref(canonical_bytes(budget), "SETUP_BUDGET"),
            "BUDGET_RESET_ATTEMPT", "request.budget")
    require(request["event_sequence"] == expected_sequence and request["event_head_sha256"] == expected_head
            and canonical_bytes(request["output"]) == canonical_bytes(expected_output)
            and request["consumer_prepare_commit_id"] == expected_prepare_id,
            "CHECKPOINT_MISMATCH", "request.exact_output")
    issuer = budget["issuer_id"] if expected_kind in {"SETUP_RESERVATION", "BUDGET_CLAIM"} else guards.role("INDEPENDENT_SETUP_CONSUMER")
    require(request["requester_id"] == issuer, "SIGNER_UNAPPOINTED", "request.requester")
    earliest = (budget["started"],) + tuple(not_before)
    if previous is not None:
        earliest += (previous["checkpointed_at"],)
    for lower in earliest:
        contract.validate("Stamp", lower)
        require(stamp_le(lower, request["prepared_at"]), "CHECKPOINT_MISMATCH", "request.preparation_order")
    require(stamp_le(request["prepared_at"], now), "CHECKPOINT_MISMATCH", "request.future_preparation")
    if expected_kind == "SETUP_RESERVATION":
        require(previous is None and expected_sequence == 0 and expected_head == ZERO
                and expected_output == {"kind": "NONE", "body_ref": None, "attestation_ref": None}
                and request["claim_state"] == "RESERVED", "BUDGET_ALREADY_CLAIMED", "request.reservation")
        return
    require(previous is not None and previous["binding"] == budget["binding"]
            and previous["original_setup_key"] == original_key(budget["binding"])
            and previous["budget_sha256"] == guards.budget_sha256
            and previous["claim_state"] != "ABORTED" and previous["transition_kind"] != "DECISION_EXPOSURE",
            "CHECKPOINT_LEDGER_DIVERGENCE", "request.previous")
    if expected_kind == "BUDGET_CLAIM":
        require(generation == 1 and previous["transition_kind"] == "SETUP_RESERVATION"
                and previous["claim_state"] == "RESERVED" and expected_sequence == 0 and expected_head == ZERO
                and expected_output["kind"] == "SETUP_BUDGET", "BUDGET_ALREADY_CLAIMED", "request.claim")
    elif expected_kind == "ACK_EXPOSURE":
        require(previous["claim_state"] == "CLAIMED" and previous["transition_kind"] in {"BUDGET_CLAIM", "ACK_EXPOSURE"}
                and expected_sequence == previous["event_sequence"] + 1 and 1 <= expected_sequence <= 19
                and expected_output["kind"] == "INGESTION_ACK", "CHECKPOINT_MISMATCH", "request.ack")
    elif expected_kind == "DECISION_EXPOSURE":
        require(previous["claim_state"] == "CLAIMED" and expected_sequence == previous["event_sequence"] == 19
                and expected_head == previous["event_head_sha256"] and expected_output["kind"] == "METHOD_DECISION",
                "CHECKPOINT_MISMATCH", "request.decision")
    else:
        require(expected_output == {"kind": "NONE", "body_ref": None, "attestation_ref": None}
                and expected_sequence == previous["event_sequence"] and expected_head == previous["event_head_sha256"]
                and request["claim_state"] == "ABORTED", "CHECKPOINT_MISMATCH", "request.abort")
        return
    require(request["claim_state"] == "CLAIMED" and expected_output["body_ref"] is not None
            and expected_output["attestation_ref"] is not None, "CHECKPOINT_MISMATCH", "request.claimed_output")


def validate_transition(contract: Contract, guards: GuardModel,
                        previous: dict[str, Any] | None,
                        request: dict[str, Any], checkpoint: dict[str, Any], *,
                        expected_kind: str, expected_sequence: int, expected_head: str,
                        expected_output: dict[str, Any], expected_prepare_id: str,
                        now: dict[str, Any], not_before=()) -> None:
    validate_request(contract, guards, previous, request, expected_kind=expected_kind,
                     expected_sequence=expected_sequence, expected_head=expected_head,
                     expected_output=expected_output, expected_prepare_id=expected_prepare_id,
                     now=now, not_before=not_before)
    contract.validate("CheckpointAdvanceRequest", request)
    contract.validate("ConsumerCheckpoint", checkpoint)
    contract.validate("OutputBinding", expected_output)
    contract.validate("Stamp", now)
    if previous is not None:
        contract.validate("ConsumerCheckpoint", previous)
    b = guards.budget
    key = original_key(b["binding"])
    generation = 0 if previous is None else previous["generation"]
    prior_hash = ZERO if previous is None else digest(canonical_bytes(previous))
    require(request["binding"] == checkpoint["binding"] == b["binding"]
            and request["original_setup_key"] == checkpoint["original_setup_key"] == key,
            "CONTEXT_MISMATCH", "checkpoint.original_binding")
    require(request["transition_kind"] == checkpoint["transition_kind"] == expected_kind
            and request["expected_generation"] == generation
            and request["expected_checkpoint_sha256"] == prior_hash
            and checkpoint["generation"] == generation + 1
            and checkpoint["previous_checkpoint_sha256"] == prior_hash,
            "CHECKPOINT_MISMATCH", "checkpoint.order")
    require(request["budget_id"] == checkpoint["budget_id"] == b["budget_id"]
            and request["budget_sha256"] == checkpoint["budget_sha256"] == guards.budget_sha256
            and request["stream_id"] == checkpoint["stream_id"] == guards.appointment["stream_id"]
            and request["original_budget_body_ref"] == checkpoint["original_budget_body_ref"] ==
            object_ref(canonical_bytes(b), "SETUP_BUDGET"), "BUDGET_RESET_ATTEMPT", "checkpoint.budget")
    require(request["event_sequence"] == checkpoint["event_sequence"] == expected_sequence
            and request["event_head_sha256"] == checkpoint["event_head_sha256"] == expected_head
            and canonical_bytes(request["output"]) == canonical_bytes(checkpoint["output"]) == canonical_bytes(expected_output)
            and request["consumer_prepare_commit_id"] == checkpoint["consumer_prepare_commit_id"] == expected_prepare_id,
            "CHECKPOINT_MISMATCH", "checkpoint.exact_output")
    require(checkpoint["transition_request_ref"] == object_ref(canonical_bytes(request), "CHECKPOINT_TRANSITION")
            and checkpoint["checkpoint_authority_id"] == guards.appointment["checkpoint_authority_id"],
            "CHECKPOINT_MISMATCH", "checkpoint.request_authority")
    issuer = b["issuer_id"] if expected_kind in {"SETUP_RESERVATION", "BUDGET_CLAIM"} else guards.role("INDEPENDENT_SETUP_CONSUMER")
    require(request["requester_id"] == issuer, "SIGNER_UNAPPOINTED", "checkpoint.requester")
    require(stamp_le(b["started"], request["prepared_at"])
            and stamp_le(request["prepared_at"], checkpoint["checkpointed_at"])
            and stamp_le(checkpoint["checkpointed_at"], now),
            "CHECKPOINT_MISMATCH", "checkpoint.time")
    if expected_kind == "SETUP_RESERVATION":
        require(previous is None and expected_sequence == 0 and expected_head == ZERO
                and expected_output == {"kind": "NONE", "body_ref": None, "attestation_ref": None}
                and request["claim_state"] == checkpoint["claim_state"] == "RESERVED",
                "BUDGET_ALREADY_CLAIMED", "checkpoint.reservation")
        return
    require(previous is not None and previous["binding"] == b["binding"]
            and previous["original_setup_key"] == key and previous["budget_sha256"] == guards.budget_sha256
            and previous["claim_state"] != "ABORTED"
            and previous["transition_kind"] != "DECISION_EXPOSURE",
            "CHECKPOINT_LEDGER_DIVERGENCE", "checkpoint.previous")
    if expected_kind == "BUDGET_CLAIM":
        require(generation == 1 and previous["transition_kind"] == "SETUP_RESERVATION"
                and previous["claim_state"] == "RESERVED" and expected_sequence == 0 and expected_head == ZERO
                and expected_output["kind"] == "SETUP_BUDGET",
                "BUDGET_ALREADY_CLAIMED", "checkpoint.claim")
    elif expected_kind == "ACK_EXPOSURE":
        require(previous["claim_state"] == "CLAIMED"
                and previous["transition_kind"] in {"BUDGET_CLAIM", "ACK_EXPOSURE"}
                and expected_sequence == previous["event_sequence"] + 1 and 1 <= expected_sequence <= 19
                and expected_output["kind"] == "INGESTION_ACK",
                "CHECKPOINT_MISMATCH", "checkpoint.ack")
    elif expected_kind == "DECISION_EXPOSURE":
        require(previous["claim_state"] == "CLAIMED"
                and expected_sequence == previous["event_sequence"]
                and expected_head == previous["event_head_sha256"]
                and expected_output["kind"] == "METHOD_DECISION",
                "CHECKPOINT_MISMATCH", "checkpoint.decision")
    elif expected_kind == "TERMINAL_ABORT":
        require(expected_output == {"kind": "NONE", "body_ref": None, "attestation_ref": None}
                and expected_sequence == previous["event_sequence"] and expected_head == previous["event_head_sha256"]
                and request["claim_state"] == checkpoint["claim_state"] == "ABORTED",
                "CHECKPOINT_MISMATCH", "checkpoint.abort")
        return
    else:
        require(False, "CHECKPOINT_MISMATCH", "checkpoint.transition_kind")
    require(request["claim_state"] == checkpoint["claim_state"] == "CLAIMED"
            and expected_output["body_ref"] is not None and expected_output["attestation_ref"] is not None,
            "CHECKPOINT_MISMATCH", "checkpoint.claimed_output")


def require_current_exact(expected: dict[str, Any], observed: dict[str, Any] | None) -> None:
    require(observed is not None and canonical_bytes(expected) == canonical_bytes(observed),
            "CHECKPOINT_ADVANCE_UNCONFIRMED", "checkpoint.current_readback")


def require_recovery_match(pending_output: dict[str, Any] | None,
                           pending_prepare_id: str | None,
                           observed_checkpoint: dict[str, Any] | None) -> None:
    require(pending_output is not None and pending_prepare_id is not None and observed_checkpoint is not None,
            "CHECKPOINT_LEDGER_DIVERGENCE", "recovery.missing_local_or_independent")
    require(canonical_bytes(pending_output) == canonical_bytes(observed_checkpoint["output"])
            and pending_prepare_id == observed_checkpoint["consumer_prepare_commit_id"],
            "CHECKPOINT_LEDGER_DIVERGENCE", "recovery.exact_pending")
