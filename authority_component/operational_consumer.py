"""NR12 controller consumption against the frozen S0 ports.

This module never starts a service, appoints an authority, signs an observation,
or reads private input. Selected dependency hooks are mandatory. In particular,
shape validation is never a substitute for custody NR01..NR11 or authentication.
The final response verifier must use already loaded public keys/records: it may
perform bounded computation, but must not acquire further external evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import logging
import secrets
from threading import Lock
from typing import Callable

from cas_forex_operational_contracts import capture, checkpoint, method, protected, release
from cas_forex_operational_contracts.common import (
    ContractError, MAX_OBJECT, canonical_bytes, decode_canonical, digest, require, utc,
)
from .consumption_store import ConsumptionStore

_logger = logging.getLogger(__name__)


def _copy(value):
    return decode_canonical(canonical_bytes(value, limit=MAX_OBJECT), limit=MAX_OBJECT)


def _before(left: dict, right: dict, *, strict: bool = False) -> bool:
    a, b = utc(left["utc"]), utc(right["utc"])
    if strict:
        return a < b and left["boottime_ns"] < right["boottime_ns"]
    return a <= b and left["boottime_ns"] <= right["boottime_ns"]


@dataclass(frozen=True, slots=True)
class ConsumptionContext:
    """Local immutable selection, not a new wire record or trust credential."""
    raw: bytes

    @classmethod
    def bind(cls, *, receipt_ref, budget, appointment, access, controller_process,
             exposure, request) -> "ConsumptionContext":
        records = {
            "receipt_ref": protected.validate("ProtectedRecordRef", receipt_ref).payload(),
            "budget": method.validate("SetupBudget", budget).payload(),
            "appointment": method.validate("Appointment", appointment).payload(),
            "access": checkpoint.validate("CheckpointAccessSelection", access).payload(),
            "controller_process": capture.validate("CaptureSubject", controller_process).payload(),
            "exposure": method.validate("ExposedOutput", exposure).payload(),
            "request": checkpoint.validate("CheckpointRpcRequest", request).payload(),
        }
        return cls(canonical_bytes(records, limit=MAX_OBJECT))

    def records(self) -> dict:
        return decode_canonical(self.raw, limit=MAX_OBJECT)


@dataclass(frozen=True, slots=True)
class ConsumptionHooks:
    # Raises unless all selected custody/completion/method/role dependencies
    # authenticate. May do I/O, always called BEFORE the final checkpoint read.
    before_read: Callable[[dict, dict, dict], None]
    # Returns independently authenticated CURRENT AuthorityStatus. This final
    # gap hook MUST be a nonblocking local authority view, never file/RPC reads.
    current_authority: Callable[[dict], dict]
    # Pure verification of every signed checkpoint using preloaded trust roots.
    # No bool fallback. Return None only on verified success; otherwise raise.
    verify_checkpoint_certificate: Callable[[bytes, dict, dict], None]
    # Actual process/channel/clock-domain continuity observation after commit.
    # May do bounded I/O. It creates no new admission or model budget.
    post_commit: Callable[[dict, dict], None]


def make_preparation(*, receipt: protected.ReleaseReceipt3, receipt_ref: protected.ProtectedRecordRef,
                     budget: method.SetupBudget, controller_process: capture.CaptureSubject,
                     now: method.Stamp, deadline: method.Stamp) -> tuple[dict, dict]:
    """Explicit fresh controller IDs; no send, file access or authority here."""
    receipt = protected.validate("ReleaseReceipt3", receipt).payload()
    method.validate("Stamp", now)
    method.validate("Stamp", deadline)
    attempt_id = "consume-" + secrets.token_hex(16)
    request = {
        "format": "forex.checkpoint-rpc-request/2", "request_id": "read-" + secrets.token_hex(16),
        "binding": _copy(budget["binding"]), "original_setup_key": _copy(receipt["original_setup_key"]),
        "caller_id": receipt["controller_id"], "operation": "READ_CURRENT",
        "nonce_hex": secrets.token_hex(32), "issued": _copy(now), "deadline": _copy(deadline),
        "use": "RELEASE_CONSUMPTION", "body": {
            "minimum_generation": 22, "minimum_head_sha256": receipt["expected_decision_head_sha256"],
            "consumption_binding": {
                "release_ref": _copy(receipt_ref), "release_id": receipt["release_id"],
                "consume_attempt_id": attempt_id, "controller_id": receipt["controller_id"],
                "controller_process": _copy(controller_process),
                "channel_binding_sha256": receipt["channel_binding_sha256"],
                "method_decision_ref": _copy(receipt["method_decision_ref"]),
                "method_exposure_ref": _copy(receipt["method_exposure_ref"]),
                "expected_decision_generation": 22,
                "expected_decision_head_sha256": receipt["expected_decision_head_sha256"],
            },
        },
    }
    request = checkpoint.validate("CheckpointRpcRequest", request).payload()
    preparation = {
        "format": "forex.release-consumption-preparation/1", "binding": _copy(receipt["binding"]),
        "preparation_id": "prepare-" + secrets.token_hex(16), "consume_attempt_id": attempt_id,
        "release_ref": _copy(receipt_ref), "controller_id": receipt["controller_id"],
        "controller_process": _copy(controller_process),
        "channel_binding_sha256": receipt["channel_binding_sha256"],
        "original_setup_key": _copy(receipt["original_setup_key"]),
        "setup_budget_sha256": receipt["setup_budget_sha256"],
        "method_appointment_sha256": receipt["method_appointment_sha256"],
        "checkpoint_access_selection_sha256": receipt["checkpoint_access_selection_sha256"],
        "prepared_at": _copy(now), "deadline": _copy(deadline),
        "read_request_sha256": digest(canonical_bytes(request)),
    }
    return release.validate("ConsumptionPreparation", preparation).payload(), request


class ControllerReleaseConsumer:
    """Implements ReleaseConsumptionPort; retained records are audit data only.

    One live instance owns one exact attempt. expose_once is the sole transient
    bridge to private work. Replays/read_retained never regenerate that bridge.
    """
    def __init__(self, *, store: ConsumptionStore, context: ConsumptionContext,
                 hooks: ConsumptionHooks, clock: Callable[[], method.Stamp]) -> None:
        require(type(context) is ConsumptionContext and type(hooks) is ConsumptionHooks, "SELECTED_DEPENDENCIES")
        require(all(callable(x) for x in (hooks.before_read, hooks.current_authority,
                hooks.verify_checkpoint_certificate, hooks.post_commit, clock)), "MISSING_DEPENDENCY")
        self.store, self.context, self.hooks, self.clock = store, context, hooks, clock
        self._lock = Lock()
        self._last = None
        self._live_attempt: str | None = None

    def _now(self, supplied=None) -> dict:
        now = method.validate("Stamp", self.clock()).payload()
        if supplied is not None:
            method.validate("Stamp", supplied)
            require(_before(supplied, now), "CLOCK_INPUT_FROM_FUTURE")
        if self._last is not None:
            require(_before(self._last, now), "CLOCK_REVERSED")
        self._last = _copy(now)
        return now

    def _bounded(self, now: dict, receipt: dict, preparation: dict) -> None:
        data = self.context.records()
        budget, appointment, access = data["budget"], data["appointment"], data["access"]
        require(_before(budget["started"], now), "SETUP_NOT_STARTED")
        require(_before(budget["started"], preparation["prepared_at"])
                and _before(preparation["prepared_at"], now), "PREPARATION_TIME")
        for end in (budget["deadline"], budget["outer_deadline"], preparation["deadline"]):
            require(_before(now, end, strict=True), "ORIGINAL_DEADLINE_EXPIRED")
        require(_before(preparation["deadline"], budget["deadline"]), "PREPARATION_EXTENDS_BUDGET")
        require(budget["maximum_seconds"] == 180
                and utc(budget["deadline"]["utc"]) == min(
                    utc(budget["started"]["utc"]) + timedelta(seconds=180), utc(budget["outer_deadline"]["utc"]))
                and budget["deadline"]["boottime_ns"] == min(
                    budget["started"]["boottime_ns"] + 180_000_000_000, budget["outer_deadline"]["boottime_ns"]),
                "ORIGINAL_SETUP_DEADLINE_MISMATCH")
        elapsed = utc(now["utc"]) - utc(budget["started"]["utc"])
        elapsed_ns = ((elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds) * 1000
        require(abs(elapsed_ns - (now["boottime_ns"] - budget["started"]["boottime_ns"])) <= 1_000_000_000,
                "CLOCK_DRIFT")
        for timed in (receipt, appointment, access, *appointment["principals"]):
            require(utc(timed["not_before_utc"]) <= utc(now["utc"]) < utc(timed["expires_at_utc"]),
                    "AUTHORITY_OR_RELEASE_EXPIRED")

    def _authority(self, now: dict) -> dict:
        arg = _copy(now)
        try:
            status = self.hooks.current_authority(arg)
        except Exception:
            raise ContractError("AUTHORITY_VIEW_UNAVAILABLE") from None
        require(arg == now, "AUTHORITY_CALLBACK_MUTATION")
        status = checkpoint.validate("AuthorityStatus", status).payload()
        data = self.context.records()
        require(status["status"] == "ACTIVE" and
                status["appointment_sha256"] == digest(canonical_bytes(data["appointment"])), "AUTHORITY_UNAVAILABLE")
        require(utc(status["not_before_utc"]) <= utc(now["utc"]) < utc(status["expires_at_utc"]), "AUTHORITY_EXPIRED")
        principals = {p["principal_id"] for p in data["appointment"]["principals"]}
        require(principals == set(status["principal_ids"]), "AUTHORITY_PRINCIPAL_MISMATCH")
        return status

    def _before_read(self, receipt: dict, prep: dict) -> None:
        args = [_copy(receipt), _copy(prep), self.context.records()]
        frozen = canonical_bytes(args, limit=MAX_OBJECT)
        try:
            result = self.hooks.before_read(*args)
        except Exception:
            raise ContractError("SELECTED_RELEASE_DEPENDENCIES_UNAVAILABLE") from None
        require(result is None and canonical_bytes(args, limit=MAX_OBJECT) == frozen, "DEPENDENCY_CALLBACK_RESULT")

    def _bindings(self, receipt: dict, prep: dict) -> None:
        data = self.context.records()
        ref, budget, appointment, access = (data[n] for n in ("receipt_ref", "budget", "appointment", "access"))
        request, exposed = data["request"], data["exposure"]
        raw = canonical_bytes(receipt)
        require(ref["sha256"] == digest(raw) and ref["bytes"] == len(raw)
                and ref["record_kind"] == "RELEASE_RECEIPT" and ref["purpose"] == "custody-release-receipt",
                "EXACT_RELEASE_REFERENCE")
        require(ref["publisher_id"] == receipt["issuer_id"], "RELEASE_ISSUER")
        require(ref["binding"] == receipt["binding"] == prep["binding"], "RELEASE_BINDING")
        require(self.store.binding_sha256 == digest(canonical_bytes(receipt["binding"])), "LOCAL_STORE_BINDING")
        scope = budget["binding"]["scope"]
        require({k: scope[k] for k in receipt["binding"]} == receipt["binding"], "EVALUATION_METHOD_BINDING")
        require(budget["binding"]["appointment_sha256"] == digest(canonical_bytes(appointment))
                == receipt["method_appointment_sha256"] == prep["method_appointment_sha256"], "APPOINTMENT_BINDING")
        require(appointment["scope"] == scope and access["binding"] == budget["binding"], "METHOD_CONTEXT")
        require(access["checkpoint_authority_id"] == appointment["checkpoint_authority_id"], "CHECKPOINT_APPOINTMENT")
        require(digest(canonical_bytes(budget)) == receipt["setup_budget_sha256"] == prep["setup_budget_sha256"], "BUDGET_BINDING")
        require(digest(canonical_bytes(access)) == receipt["checkpoint_access_selection_sha256"]
                == prep["checkpoint_access_selection_sha256"], "CHECKPOINT_SELECTION")
        require(appointment["clock_domain"] == budget["clock_domain"], "CLOCK_DOMAIN")
        expected_key = {k: scope[k] for k in ("run_id", "original_window_sha256", "setup_identity")}
        require(expected_key == receipt["original_setup_key"] == prep["original_setup_key"] == request["original_setup_key"], "ORIGINAL_KEY")
        require(prep["release_ref"] == ref and prep["controller_process"] == data["controller_process"], "PREPARATION_SELECTION")
        require(data["controller_process"]["role"] == "CONTROLLER" and
                data["controller_process"]["boot_id"] == budget["clock_domain"]["boot_id"], "CONTROLLER_ROLE")
        for name in ("controller_id", "channel_binding_sha256"):
            require(prep[name] == receipt[name], "CONTROLLER_CHANNEL_BINDING")
        grants = [g for g in access["callers"] if g["principal_id"] == receipt["controller_id"]]
        require(len(grants) == 1 and grants[0]["operations"] == ["READ_CURRENT"]
                and grants[0]["uses"] == ["RELEASE_CONSUMPTION"]
                and grants[0]["actual_process"] == data["controller_process"], "CONTROLLER_READ_ONLY_GRANT")
        witnesses = [p for p in appointment["principals"] if p["principal_id"] == receipt["controller_id"]]
        require(len(witnesses) == 1 and witnesses[0]["role"] == "TRUSTED_CONTROLLER_WITNESS"
                and witnesses[0]["signer_public_sha256"] == grants[0]["signer_public_sha256"]
                and witnesses[0]["component_manifest_sha256"] == grants[0]["component_manifest_sha256"], "CONTROLLER_WITNESS_GRANT")
        require(exposed["kind"] == "METHOD_DECISION" and exposed["binding"] == budget["binding"]
                and exposed["body_ref"] == receipt["method_decision_ref"], "EXPOSED_DECISION")
        require(digest(canonical_bytes(exposed)) == receipt["method_exposure_ref"]["sha256"]
                and len(canonical_bytes(exposed)) == receipt["method_exposure_ref"]["bytes"], "EXPOSURE_REFERENCE")
        require(request["binding"] == budget["binding"] and request["caller_id"] == receipt["controller_id"]
                and request["operation"] == "READ_CURRENT" and request["use"] == "RELEASE_CONSUMPTION", "FINAL_READ_ROUTE")
        expected_binding = {
            "release_ref": ref, "release_id": receipt["release_id"], "consume_attempt_id": prep["consume_attempt_id"],
            "controller_id": receipt["controller_id"], "controller_process": data["controller_process"],
            "channel_binding_sha256": receipt["channel_binding_sha256"],
            "method_decision_ref": receipt["method_decision_ref"], "method_exposure_ref": receipt["method_exposure_ref"],
            "expected_decision_generation": 22, "expected_decision_head_sha256": receipt["expected_decision_head_sha256"],
        }
        require(receipt["expected_decision_generation"] == 22 and request["body"] == {
            "minimum_generation": 22, "minimum_head_sha256": receipt["expected_decision_head_sha256"],
            "consumption_binding": expected_binding}, "FINAL_READ_BINDING")
        require(digest(canonical_bytes(request)) == prep["read_request_sha256"]
                and request["issued"] == prep["prepared_at"] and request["deadline"] == prep["deadline"], "EXACT_PREPARED_REQUEST")

    def _empty_record(self, prep: dict) -> dict:
        return {
            "format": "forex.release-consumption-record/1", "binding": _copy(prep["binding"]),
            "consume_attempt_id": prep["consume_attempt_id"], "preparation_sha256": digest(canonical_bytes(prep)),
            "release_ref": _copy(prep["release_ref"]), "controller_id": prep["controller_id"],
            "controller_process": _copy(prep["controller_process"]), "channel_binding_sha256": prep["channel_binding_sha256"],
            "checkpoint_request_sha256": prep["read_request_sha256"], "checkpoint_response_sha256": None,
            "verified_checkpoint_generation": None, "verified_checkpoint_head_sha256": None,
            "authority_status_sha256": None, "validated_at": None, "committed_at": None,
            "post_commit_checked_at": None, "status": "UNAVAILABLE",
        }

    def prepare(self, receipt: protected.ReleaseReceipt3, preparation: release.ConsumptionPreparation,
                *, now: method.Stamp) -> release.ConsumptionPreparation:
        with self._lock:
            receipt = protected.validate("ReleaseReceipt3", receipt).payload()
            prep = release.validate("ConsumptionPreparation", preparation).payload()
            self._bindings(receipt, prep)
            observed = self._now(now)
            self._bounded(observed, receipt, prep)
            self._before_read(receipt, prep)
            self._bounded(self._now(), receipt, prep)
            self._authority(self._now())
            self.store.prepare(prep, receipt, self.context.records()["request"], self._empty_record(prep))
            self._bounded(self._now(), receipt, prep)
            return _copy(prep)

    def _response(self, response: dict, request: dict, receipt: dict, before: dict, after: dict,
                  authority: dict) -> None:
        data = self.context.records()
        require(response["status"] == "PRESENT" and response["failure_code"] is None, "FINAL_READ_UNAVAILABLE")
        require(response["request_sha256"] == digest(canonical_bytes(request))
                and response["nonce_hex"] == request["nonce_hex"], "FINAL_READ_FRESHNESS")
        for name in ("binding", "original_setup_key"):
            require(response[name] == request[name], "FINAL_READ_CONTEXT")
        require(response["checkpoint_authority_id"] == data["access"]["checkpoint_authority_id"]
                and response["store_instance_id"] == data["access"]["store_instance_id"]
                and response["access_selection_sha256"] == digest(canonical_bytes(data["access"]))
                and response["clock_domain"] == data["budget"]["clock_domain"]
                and response["authority_view_sha256"] == digest(canonical_bytes(authority)), "FINAL_READ_AUTHORITY")
        require(_before(before, response["observed"]) and _before(response["observed"], after), "FINAL_READ_TIME")
        require(response["generation"] == 22 and response["head_sha256"] == receipt["expected_decision_head_sha256"]
                and len(response["history"]) == 22, "FINAL_READ_HEAD")
        previous = "0" * 64
        last = None
        for generation, row in enumerate(response["history"], 1):
            raw = row["checkpoint_utf8"].encode("utf-8")
            cert = method.decode("ConsumerCheckpoint", raw).payload()
            attestation = method.decode("SignedEnvelope", row["checkpoint_attestation_utf8"].encode("utf-8")).payload()
            require(row["generation"] == cert["generation"] == generation and digest(raw) == row["checkpoint_sha256"], "CHECKPOINT_HISTORY_HASH")
            require(row["request_sha256"] == cert["transition_request_ref"]["sha256"], "CHECKPOINT_TRANSITION_REQUEST_HASH")
            require(cert["previous_checkpoint_sha256"] == previous and cert["binding"] == request["binding"]
                    and cert["original_setup_key"] == request["original_setup_key"]
                    and cert["budget_sha256"] == receipt["setup_budget_sha256"]
                    and cert["checkpoint_authority_id"] == response["checkpoint_authority_id"], "CHECKPOINT_HISTORY_CONTEXT")
            require(cert["budget_id"] == data["budget"]["budget_id"] and cert["stream_id"] == data["appointment"]["stream_id"]
                    and cert["original_budget_body_ref"]["sha256"] == receipt["setup_budget_sha256"]
                    and cert["original_budget_body_ref"]["bytes"] == len(canonical_bytes(data["budget"]))
                    and cert["original_budget_body_ref"]["artifact_kind"] == "SETUP_BUDGET"
                    and cert["event_sequence"] == max(0, min(19, generation - 2)), "CHECKPOINT_STREAM_BINDING")
            kind = "SETUP_RESERVATION" if generation == 1 else "BUDGET_CLAIM" if generation == 2 else "DECISION_EXPOSURE" if generation == 22 else "ACK_EXPOSURE"
            require(cert["transition_kind"] == kind and cert["claim_state"] == ("RESERVED" if generation == 1 else "CLAIMED"), "CHECKPOINT_HISTORY_TRANSITION")
            require(_before(cert["checkpointed_at"], response["observed"]), "CHECKPOINT_FROM_FUTURE")
            if last is not None:
                require(_before(last["checkpointed_at"], cert["checkpointed_at"]), "CHECKPOINT_TIME_ORDER")
            body = attestation["body"]
            require(body["binding"] == request["binding"] and body["purpose"] == "policy-inheritance-checkpoint-v3"
                    and body["producer_id"] == response["checkpoint_authority_id"]
                    and body["record_sha256"] == digest(raw) and body["record_bytes"] == len(raw)
                    and body["budget_sha256"] == receipt["setup_budget_sha256"], "CHECKPOINT_ATTESTATION_BINDING")
            require(_before(cert["checkpointed_at"], body["issued"]) and _before(body["issued"], after)
                    and _before(after, body["expires"], strict=True), "CHECKPOINT_ATTESTATION_TIME")
            args = [_copy(attestation), _copy(after)]
            frozen = canonical_bytes(args)
            require(self.hooks.verify_checkpoint_certificate(raw, args[0], args[1]) is None
                    and canonical_bytes(args) == frozen, "CHECKPOINT_CERTIFICATE_REJECTED")
            previous, last = row["checkpoint_sha256"], cert
        require(previous == response["head_sha256"] and response["checkpoint_utf8"] == response["history"][-1]["checkpoint_utf8"]
                and response["checkpoint_attestation_utf8"] == response["history"][-1]["checkpoint_attestation_utf8"], "CURRENT_CHECKPOINT_HISTORY")
        exposed = data["exposure"]
        require(last["output"]["kind"] == "METHOD_DECISION" and last["output"]["body_ref"] == receipt["method_decision_ref"]
                and last["output"]["attestation_ref"] == exposed["attestation_ref"]
                and exposed["checkpoint_ref"]["sha256"] == previous
                and exposed["checkpoint_attestation_ref"]["sha256"] == digest(response["checkpoint_attestation_utf8"].encode()), "DECISION_CHECKPOINT_BINDING")

    def consume_exact(self, preparation: release.ConsumptionPreparation, *,
                      checkpoint_client: checkpoint.CheckpointClientPort, now: method.Stamp) -> release.ConsumptionRecord:
        with self._lock:
            prep = release.validate("ConsumptionPreparation", preparation).payload()
            prior = self.store.read(prep["consume_attempt_id"])
            require(prior["preparation"] == prep, "PREPARATION_CONFLICT")
            if prior["state"] != "PREPARED":
                return _copy(prior["record"])  # audit only; never recreate _live_attempt
            receipt, request, record = prior["receipt"], prior["request"], prior["record"]
            require(request == self.context.records()["request"], "RETAINED_REQUEST_CHANGED")
            self._bindings(receipt, prep)
            self._bounded(self._now(now), receipt, prep)
            self._before_read(receipt, prep)
            self.store.transition(prep["consume_attempt_id"], expected=("PREPARED",), state="READ_STARTED", record=record)
            try:
                # All DB open/read/lock work precedes the final external acquisition.
                with self.store.final_commit(prep["consume_attempt_id"]) as slot:
                    before = self._now()
                    self._bounded(before, receipt, prep)
                    authority = self._authority(before)
                    sent = _copy(request)
                    response = checkpoint_client.read_current(sent, now=_copy(before))
                    require(sent == request, "CHECKPOINT_CLIENT_MUTATION")
                    response = checkpoint.validate("CheckpointRpcResponse", response).payload()
                    record = {**record, "checkpoint_response_sha256": digest(canonical_bytes(response, limit=MAX_OBJECT))}
                    after = self._now()
                    self._bounded(after, receipt, prep)
                    require(self._authority(after) == authority, "AUTHORITY_CHANGED_DURING_READ")
                    self._response(response, request, receipt, before, after, authority)
                    checked = self._now()
                    self._bounded(checked, receipt, prep)
                    require(self._authority(checked) == authority, "AUTHORITY_CHANGED_BEFORE_COMMIT")
                    record = {**record, "checkpoint_response_sha256": digest(canonical_bytes(response, limit=MAX_OBJECT)),
                        "verified_checkpoint_generation": 22, "verified_checkpoint_head_sha256": response["head_sha256"],
                        "authority_status_sha256": digest(canonical_bytes(authority)), "validated_at": checked,
                        "status": "SPENT_NO_EXPOSURE"}
                    # committed_at is recorded only AFTER commit returns successfully.
                    slot.commit(record)
                committed = self._now()
                record = {**record, "committed_at": committed}
                self._bounded(committed, receipt, prep)
                args = [_copy(prep), _copy(committed)]
                frozen = canonical_bytes(args)
                require(self.hooks.post_commit(*args) is None and canonical_bytes(args) == frozen, "POST_COMMIT_CONTINUITY")
                post = self._now()
                self._bounded(post, receipt, prep)
                require(self._authority(post) == authority, "AUTHORITY_CHANGED_AFTER_COMMIT")
                record = {**record, "post_commit_checked_at": post, "status": "CONSUMED_VALID"}
                release.validate("ConsumptionRecord", record)
                self.store.transition(prep["consume_attempt_id"], expected=("COMMITTED",), state="CHECKED", record=record)
                self._bounded(self._now(), receipt, prep)
                self._live_attempt = prep["consume_attempt_id"]
                return _copy(record)
            except Exception:
                self._live_attempt = None
                self._retain_failure(prep["consume_attempt_id"], record)
                raise ContractError("CONSUMPTION_UNAVAILABLE_NO_EXPOSURE") from None

    def _retain_failure(self, attempt_id: str, record: dict) -> None:
        try:
            prior = self.store.read(attempt_id)
            spent = prior["state"] in ("COMMITTED", "CHECKED", "EXPOSURE_STARTED")
            result = {**record, "status": "SPENT_NO_EXPOSURE" if spent else "UNAVAILABLE"}
            self.store.transition(attempt_id, expected=(prior["state"],), state="FAILED", record=result)
        except Exception as exc:
            # Persistence unavailable: original READ_STARTED/COMMITTED remains
            # non-replayable. Never replace missing timestamps with guessed ones.
            _logger.debug("Retaining original non-replayable state on failure write error: %s", exc)

    def read_retained(self, *, consume_attempt_id: str, now: method.Stamp) -> release.ConsumptionRecord:
        with self._lock:
            self._now(now)
            return release.validate("ConsumptionRecord", self.store.read(consume_attempt_id)["record"]).payload()

    def expose_once(self, *, consume_attempt_id: str, private_action: Callable[[], object]):
        """Trusted composition only; callbacks/IDs are never selected by wire data."""
        with self._lock:
            require(self._live_attempt == consume_attempt_id, "NO_LIVE_EXPOSURE_CAPABILITY")
            self._live_attempt = None  # Lost callback return cannot be retried.
            prior = self.store.read(consume_attempt_id)
            record, prep, receipt = prior["record"], prior["preparation"], prior["receipt"]
            try:
                require(record["status"] == "CONSUMED_VALID", "CONSUMPTION_NOT_VALID")
                self.store.transition(consume_attempt_id, expected=("CHECKED",), state="EXPOSURE_STARTED", record=record)
                observed = self._now()
                self._bounded(observed, receipt, prep)
                args = [_copy(prep), _copy(observed)]
                frozen = canonical_bytes(args)
                require(self.hooks.post_commit(*args) is None and canonical_bytes(args) == frozen, "EXPOSURE_CONTINUITY")
                current = self._now()
                self._bounded(current, receipt, prep)
                require(digest(canonical_bytes(self._authority(current))) == record["authority_status_sha256"], "EXPOSURE_AUTHORITY_CHANGED")
            except Exception:
                self._retain_failure(consume_attempt_id, record)
                raise ContractError("SPENT_NO_EXPOSURE") from None
            # Any exception after entry means exposure may have occurred. Retain
            # EXPOSURE_STARTED; do not mislabel it SPENT_NO_EXPOSURE or retry.
            try:
                return private_action()
            except Exception:
                raise ContractError("PRIVATE_EXPOSURE_CALLBACK_UNCERTAIN") from None
