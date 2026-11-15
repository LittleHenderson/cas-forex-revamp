"""Authentication of exact fresh responses and the full retained certificate chain."""
from __future__ import annotations

import os
from cas_forex_operational_contracts import checkpoint as ck, method
from cas_forex_operational_contracts.common import canonical_bytes, digest
from .authentication import ZERO, need, original_key, same, stamp_le


class CheckpointClient:
    def __init__(self, *, authentication, transport, signer, caller_id):
        self.auth, self.transport, self.signer, self.caller_id = authentication, transport, signer, caller_id
        self._requests = set()

    def request(self, operation, body, *, use="SETUP_PROTOCOL", now):
        """Fresh read/RPC nonce only. It never regenerates a transition or output."""
        actual = self.auth.guard.check(now)
        nonce = os.urandom(32).hex()
        result = {"format": "forex.checkpoint-rpc-request/2", "request_id": "rpc-" + nonce,
                  "binding": self.auth.binding, "original_setup_key": original_key(self.auth.binding),
                  "caller_id": self.caller_id, "operation": operation, "nonce_hex": nonce, "issued": actual,
                  "deadline": self.auth.guard.budget["deadline"], "body": body, "use": use}
        return ck.validate("CheckpointRpcRequest", result).payload()

    def _exchange(self, request, *, operation, now):
        raw = ck.validate("CheckpointRpcRequest", request).raw
        need(request["operation"] == operation and request["caller_id"] == self.caller_id
             and same(request["binding"], self.auth.binding)
             and same(request["original_setup_key"], original_key(self.auth.binding)), "CONTEXT_MISMATCH")
        status, actual = self.auth.current(now)
        need(stamp_le(request["issued"], actual), "CLOCK_DRIFT")
        self.auth.guard.remaining(request["deadline"])
        grants = [g for g in self.auth.access["callers"] if g["principal_id"] == self.caller_id]
        need(len(grants) == 1 and operation in grants[0]["operations"] and request["use"] in grants[0]["uses"], "PURPOSE_MISMATCH")
        identity = (request["request_id"], request["nonce_hex"])
        need(len(self._requests) < 1024 and identity not in self._requests, "REPLAY_OR_EQUIVOCATION")
        self._requests.add(identity)
        signature = self.signer.sign(domain=ck.REQUEST_DOMAIN, canonical_body=raw)
        envelope = {"body_utf8": raw.decode("utf-8"), "signer_sha256": digest(self.auth.key(self.caller_id)),
                    "algorithm": "Ed25519", "signature_hex": signature.hex()}
        self.auth.current()
        returned = self.transport.exchange(envelope, deadline=request["deadline"])
        authority = self.auth.principal("INDEPENDENT_CHECKPOINT_CUSTODIAN")["principal_id"]
        response = self.auth.verify_rpc(returned, domain=ck.RESPONSE_DOMAIN, public_key=self.auth.key(authority), type_name="CheckpointRpcResponse")
        latest, actual = self.auth.current()
        self.auth.guard.remaining(request["deadline"])
        need(same(status, latest) and response["authority_view_sha256"] == digest(canonical_bytes(latest)), "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        need(response["request_sha256"] == digest(raw) and response["nonce_hex"] == request["nonce_hex"]
             and same(response["binding"], request["binding"])
             and same(response["original_setup_key"], request["original_setup_key"])
             and response["checkpoint_authority_id"] == authority
             and response["store_instance_id"] == self.auth.access["store_instance_id"]
             and response["access_selection_sha256"] == self.auth.selection.access_sha256
             and same(response["clock_domain"], self.auth.guard.budget["clock_domain"])
             and stamp_le(request["issued"], response["observed"]) and stamp_le(response["observed"], actual), "CHECKPOINT_MISMATCH")
        allowed = {"READ_CURRENT": {"ABSENT", "PRESENT"}, "ADVANCE": {"COMMITTED", "EXACT_RECOVERY"},
                   "LOOKUP_TRANSITION": {"EXACT_RECOVERY"}}[operation]
        need(response["status"] in allowed and response["failure_code"] is None, "CHECKPOINT_ADVANCE_UNCONFIRMED")
        previous, certificates = ZERO, []
        for index, item in enumerate(response["history"], 1):
            cert_raw = item["checkpoint_utf8"].encode("utf-8")
            cert = method.decode("ConsumerCheckpoint", cert_raw).payload()
            cert_env = method.decode("SignedEnvelope", item["checkpoint_attestation_utf8"].encode("utf-8")).payload()
            self.auth.verify_attestation(cert_raw, cert_env, expected_purpose="policy-inheritance-checkpoint-v3",
                                         appointment=self.auth.appointment, now=self.auth.guard.check())
            need(item["generation"] == cert["generation"] == index and digest(cert_raw) == item["checkpoint_sha256"]
                 and cert["previous_checkpoint_sha256"] == previous
                 and cert["transition_request_ref"]["sha256"] == item["request_sha256"]
                 and cert["checkpoint_authority_id"] == authority and same(cert["binding"], request["binding"])
                 and same(cert["original_setup_key"], request["original_setup_key"])
                 and cert["budget_sha256"] == digest(self.auth._budget_bytes())
                 and cert["stream_id"] == self.auth.appointment["stream_id"], "CHECKPOINT_LEDGER_DIVERGENCE")
            previous = item["checkpoint_sha256"]
            certificates.append(cert)
        need(response["generation"] == len(certificates) and response["head_sha256"] == previous, "CHECKPOINT_MISMATCH")
        if certificates:
            need(response["checkpoint_utf8"] == response["history"][-1]["checkpoint_utf8"]
                 and response["checkpoint_attestation_utf8"] == response["history"][-1]["checkpoint_attestation_utf8"], "CHECKPOINT_MISMATCH")
        if operation in ("READ_CURRENT", "LOOKUP_TRANSITION"):
            minimum, head = request["body"]["minimum_generation"], request["body"]["minimum_head_sha256"]
            need(minimum <= len(certificates) and ((minimum == 0 and head == ZERO)
                 or (minimum > 0 and response["history"][minimum - 1]["checkpoint_sha256"] == head)), "CHECKPOINT_MISMATCH")
        if operation != "READ_CURRENT":
            if operation == "ADVANCE":
                transition_raw = request["body"]["transition_utf8"].encode("utf-8")
                expected_hash = digest(transition_raw)
                transition = method.decode("CheckpointAdvanceRequest", transition_raw).payload()
                matching = [c for c in certificates if c["transition_request_ref"]["sha256"] == expected_hash]
                need(len(matching) == 1, "CHECKPOINT_MISMATCH")
                for field in ("binding", "original_setup_key", "transition_kind", "budget_id", "budget_sha256", "stream_id",
                              "event_sequence", "event_head_sha256", "consumer_prepare_commit_id", "output", "claim_state", "original_budget_body_ref"):
                    need(same(matching[0][field], transition[field]), "CHECKPOINT_MISMATCH")
            else:
                need(any(x["request_sha256"] == request["body"]["exact_request_sha256"] for x in response["history"]), "CHECKPOINT_MISMATCH")
        self.auth.current()
        return response

    def read_current(self, request, *, now):
        return self._exchange(request, operation="READ_CURRENT", now=now)

    def advance(self, request, *, now):
        return self._exchange(request, operation="ADVANCE", now=now)

    def lookup_transition(self, request, *, now):
        return self._exchange(request, operation="LOOKUP_TRANSITION", now=now)
