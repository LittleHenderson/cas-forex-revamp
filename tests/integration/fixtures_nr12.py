"""Public synthetic records for future unit tests; no real signatures/observations.

Nothing here establishes authority, timing, OS isolation or SQLite durability.
This module and all tests are authored NOT_RUN.
"""
from copy import deepcopy
import json
from pathlib import Path

from cas_forex_operational_contracts.common import canonical_bytes, digest
from authority_component.operational_consumer import ConsumptionContext, ConsumptionHooks, make_preparation

ROOT = Path(__file__).resolve().parents[2]


def stamp(seconds: int) -> dict:
    return {"utc": f"2030-01-01T00:{seconds // 60:02d}:{seconds % 60:02d}.000000Z",
            "boottime_ns": seconds * 1_000_000_000}


def ref(kind: str, raw: bytes = b"public-unused-placeholder") -> dict:
    h = digest(raw)
    return {"object_id": h, "bytes": len(raw), "sha256": h, "artifact_kind": kind}


def packet(*, setup_deadline_seconds=180, outer_deadline_seconds=180) -> dict:
    example = json.loads((ROOT / "shared-interface/accepted-contracts/examples/role-release-evidence.json").read_text(encoding="utf-8"))
    scope = example["role_evidence"]["method_binding"]["scope"]
    process = example["controller_fresh_read_request"]["body"]["consumption_binding"]["controller_process"]
    clock_domain = {"boot_id": process["boot_id"], "time_namespace_inode": 1001, "clock_id": "CLOCK_BOOTTIME"}
    controller = example["release_receipt"]["controller_id"]
    appointment = {
        "format": "forex.policy-inheritance-appointment/3", "appointment_id": "public-appointment",
        "scope": scope, "coverage_plan_sha256": "1" * 64,
        "principals": [{"principal_id": who, "role": role, "component_manifest_sha256": str(n) * 64,
            "signer_public_sha256": str(n) * 64, "allowed_purposes": [purpose],
            "not_before_utc": stamp(0)["utc"], "expires_at_utc": stamp(180)["utc"]}
            for n, who, role, purpose in (
                (1, controller, "TRUSTED_CONTROLLER_WITNESS", "policy-inheritance-witness-v3"),
                (2, "public-consumer", "INDEPENDENT_SETUP_CONSUMER", "policy-inheritance-method-decision-v3"),
                (3, "public-checkpoint", "INDEPENDENT_CHECKPOINT_CUSTODIAN", "policy-inheritance-checkpoint-v3"))],
        "clock_domain": clock_domain, "not_before_utc": stamp(0)["utc"], "expires_at_utc": stamp(180)["utc"],
        "producer_staging_root_id": "public-producer", "consumer_retention_root_id": "public-consumer-root",
        "independent_checkpoint_root_id": "public-checkpoint-root", "approved_runtime_topology_ref": ref("TOPOLOGY_APPROVAL"),
        "watchdog_binding_ref": ref("WATCHDOG_BINDING"), "stream_id": "public-stream", "checkpoint_authority_id": "public-checkpoint",
    }
    binding = {"scope": scope, "appointment_sha256": digest(canonical_bytes(appointment))}
    key = {k: scope[k] for k in ("run_id", "original_window_sha256", "setup_identity")}
    budget = {"format": "forex.policy-inheritance-setup-budget/3", "binding": binding,
        "budget_id": "public-budget", "issuer_id": "public-consumer", "clock_domain": clock_domain,
        "started": stamp(0), "deadline": stamp(setup_deadline_seconds), "outer_deadline": stamp(outer_deadline_seconds), "maximum_seconds": 180,
        "coverage_plan_sha256": "1" * 64, "appointment_interval_ref": ref("AUTHENTICATED_INTERVAL")}
    budget_hash = digest(canonical_bytes(budget))
    access = {"format": "forex.checkpoint-access-selection/2", "binding": binding,
        "checkpoint_authority_id": "public-checkpoint", "store_instance_id": "public-checkpoint-store",
        "endpoint_id": "public-checkpoint-endpoint", "endpoint_binding_sha256": "3" * 64,
        "callers": [{"principal_id": controller, "signer_public_sha256": "1" * 64,
            "component_manifest_sha256": "1" * 64, "actual_process": process,
            "operations": ["READ_CURRENT"], "uses": ["RELEASE_CONSUMPTION"]},
            {"principal_id": "public-consumer", "signer_public_sha256": "2" * 64,
            "component_manifest_sha256": "2" * 64, "actual_process": {**process, "role": "SETUP_CONSUMER", "pid": process["pid"] + 1},
            "operations": ["READ_CURRENT", "ADVANCE", "LOOKUP_TRANSITION"], "uses": ["SETUP_PROTOCOL"]}],
        "authorizer_id": "public-authorizer", "not_before_utc": stamp(0)["utc"], "expires_at_utc": stamp(180)["utc"]}
    decision_ref, decision_attestation = ref("METHOD_DECISION", b"public-decision"), ref("SIGNED_ENVELOPE", b"public-decision-envelope")
    history, previous = [], "0" * 64
    for generation in range(1, 23):
        kind = "SETUP_RESERVATION" if generation == 1 else "BUDGET_CLAIM" if generation == 2 else "DECISION_EXPOSURE" if generation == 22 else "ACK_EXPOSURE"
        cert = {"format": "forex.policy-inheritance-checkpoint/3", "binding": binding, "original_setup_key": key,
            "checkpoint_authority_id": "public-checkpoint", "checkpoint_id": f"public-checkpoint-{generation}",
            "generation": generation, "previous_checkpoint_sha256": previous,
            "transition_request_ref": ref("CHECKPOINT_TRANSITION", f"public-transition-{generation}".encode()),
            "transition_kind": kind, "budget_id": budget["budget_id"], "budget_sha256": budget_hash,
            "stream_id": "public-stream", "event_sequence": max(0, min(19, generation - 2)), "event_head_sha256": "4" * 64,
            "consumer_prepare_commit_id": f"public-commit-{generation}",
            "output": {"kind": "METHOD_DECISION", "body_ref": decision_ref, "attestation_ref": decision_attestation}
                if generation == 22 else {"kind": "NONE", "body_ref": None, "attestation_ref": None},
            "claim_state": "RESERVED" if generation == 1 else "CLAIMED", "checkpointed_at": stamp(generation),
            "original_budget_body_ref": ref("SETUP_BUDGET", canonical_bytes(budget))}
        raw = canonical_bytes(cert)
        envelope = {"body": {"format": "forex.policy-inheritance-attestation/3", "binding": binding,
            "attestation_id": f"public-attestation-{generation}", "purpose": "policy-inheritance-checkpoint-v3",
            "producer_id": "public-checkpoint", "record_sha256": digest(raw), "record_bytes": len(raw),
            "budget_sha256": budget_hash, "issued": stamp(generation), "expires": stamp(180)},
            "algorithm": "Ed25519", "signer_sha256": "3" * 64, "signature_hex": "0" * 128}
        previous = digest(raw)
        history.append({"generation": generation, "request_sha256": cert["transition_request_ref"]["sha256"],
            "checkpoint_sha256": previous, "checkpoint_utf8": raw.decode(),
            "checkpoint_attestation_utf8": canonical_bytes(envelope).decode()})
    exposed = {"format": "forex.policy-inheritance-exposed-output/3", "binding": binding, "kind": "METHOD_DECISION",
        "body_ref": decision_ref, "attestation_ref": decision_attestation,
        "checkpoint_ref": ref("CHECKPOINT_CERTIFICATE", history[-1]["checkpoint_utf8"].encode()),
        "checkpoint_attestation_ref": ref("SIGNED_ENVELOPE", history[-1]["checkpoint_attestation_utf8"].encode())}
    receipt = deepcopy(example["release_receipt"])
    receipt.update(method_decision_ref=decision_ref, method_exposure_ref=ref("EXPOSED_OUTPUT", canonical_bytes(exposed)),
        original_setup_key=key, setup_budget_sha256=budget_hash, method_appointment_sha256=binding["appointment_sha256"],
        checkpoint_access_selection_sha256=digest(canonical_bytes(access)), expected_decision_generation=22,
        expected_decision_head_sha256=previous, issued_at_utc=stamp(100)["utc"], not_before_utc=stamp(100)["utc"], expires_at_utc=stamp(170)["utc"])
    receipt_ref = deepcopy(example["release_receipt_ref"])
    receipt_raw = canonical_bytes(receipt)
    receipt_ref.update(object_id=digest(receipt_raw), sha256=digest(receipt_raw), bytes=len(receipt_raw))
    prep, request = make_preparation(receipt=receipt, receipt_ref=receipt_ref, budget=budget,
        controller_process=process, now=stamp(130), deadline=stamp(160))
    context = ConsumptionContext.bind(receipt_ref=receipt_ref, budget=budget, appointment=appointment,
        access=access, controller_process=process, exposure=exposed, request=request)
    authority = {"format": "forex.runtime-authority-status/1", "appointment_sha256": binding["appointment_sha256"],
        "authorizer_id": "public-authorizer", "revision": 1, "status": "ACTIVE",
        "principal_ids": [p["principal_id"] for p in appointment["principals"]],
        "not_before_utc": stamp(0)["utc"], "expires_at_utc": stamp(180)["utc"]}
    response = {"format": "forex.checkpoint-rpc-response/2", "request_sha256": digest(canonical_bytes(request)),
        "nonce_hex": request["nonce_hex"], "binding": binding, "original_setup_key": key,
        "checkpoint_authority_id": "public-checkpoint", "store_instance_id": "public-checkpoint-store",
        "status": "PRESENT", "observed": stamp(130), "clock_domain": clock_domain,
        "authority_view_sha256": digest(canonical_bytes(authority)), "generation": 22, "head_sha256": previous,
        "checkpoint_utf8": history[-1]["checkpoint_utf8"], "checkpoint_attestation_utf8": history[-1]["checkpoint_attestation_utf8"],
        "history": history, "failure_code": None, "access_selection_sha256": digest(canonical_bytes(access))}
    return {"receipt": receipt, "preparation": prep, "context": context, "authority": authority,
            "response": response, "request": request}


class FakeDependencies:
    """Unit-test fakes only, not an implementation of real authentication."""
    def __init__(self, data):
        self.data, self.time, self.calls = data, stamp(130), []
        self.fail_before = self.fail_after = False
        self.mutate_certificate = False

    def clock(self):
        return deepcopy(self.time)

    def before(self, receipt, preparation, context):
        self.calls.append("before")
        if self.fail_before:
            raise RuntimeError("public fake dependency failure")

    def authority(self, now):
        return deepcopy(self.data["authority"])

    def certificate(self, raw, envelope, now):
        self.calls.append("certificate")
        assert envelope["body"]["record_sha256"] == digest(raw)
        if self.mutate_certificate:
            now["boottime_ns"] += 1

    def after(self, preparation, now):
        self.calls.append("after")
        if self.fail_after:
            raise RuntimeError("public fake continuity failure")

    def hooks(self):
        return ConsumptionHooks(self.before, self.authority, self.certificate, self.after)


class FakeClient:
    def __init__(self, response):
        self.response, self.calls = response, []
        self.failure = None
        self.on_read = None

    def read_current(self, request, *, now):
        self.calls.append(deepcopy(request))
        if self.on_read:
            self.on_read()
        if self.failure:
            raise self.failure
        return deepcopy(self.response)

    def advance(self, *args, **kwargs):
        raise AssertionError("controller must never ADVANCE")

    def lookup_transition(self, *args, **kwargs):
        raise AssertionError("no implicit alternate checkpoint read")
