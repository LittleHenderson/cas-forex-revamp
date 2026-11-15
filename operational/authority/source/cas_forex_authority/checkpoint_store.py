"""Separate authority-owned SQLite compare/append journal; never a consumer table."""
from __future__ import annotations

from cas_forex_operational_contracts import checkpoint as ck, method
from cas_forex_operational_contracts.common import canonical_bytes, decode_canonical, digest
from .authentication import AuthorityError, ZERO, need, original_key, ref, same, stamp_le
from .consumer_store import ConsumerStore, DurableDatabase

SCHEMA = (
    "CREATE TABLE attempts (key_raw BLOB PRIMARY KEY,binding_raw BLOB NOT NULL,budget_raw BLOB NOT NULL,authorization_id TEXT NOT NULL UNIQUE,authorization_raw BLOB NOT NULL,generation INTEGER NOT NULL,head_sha TEXT NOT NULL)",
    "CREATE TABLE transitions (key_raw BLOB NOT NULL REFERENCES attempts(key_raw),generation INTEGER NOT NULL,transition_id TEXT NOT NULL UNIQUE,request_raw BLOB NOT NULL,request_sha TEXT NOT NULL,attachments_raw BLOB NOT NULL,checkpoint_raw BLOB NOT NULL,checkpoint_sha TEXT NOT NULL,envelope_raw BLOB NOT NULL,PRIMARY KEY(key_raw,generation))",
    "CREATE TABLE authority_highwater (appointment TEXT PRIMARY KEY,revision INTEGER NOT NULL,sha TEXT NOT NULL)",
)


class CheckpointStore:
    def __init__(self, selection, *, authentication, signer):
        self.auth, self.signer = authentication, signer
        self.database = DurableDatabase(selection, schema="cas-fx-checkpoint/1", guard=authentication.guard)
        need(selection.store_instance_id == authentication.access["store_instance_id"], "CHECKPOINT_AUTHORITY_UNAVAILABLE")
        self.authority_id = authentication.principal("INDEPENDENT_CHECKPOINT_CUSTODIAN")["principal_id"]

    def initialize(self, *, consume_initialization):
        self.database.initialize(SCHEMA, consume_initialization=consume_initialization)

    def reopen(self):
        self.database.reopen()

    def _context(self, request, caller, now):
        request = ck.validate("CheckpointRpcRequest", request).payload()
        caller = ck.validate("CheckpointCallerGrant", caller).payload()
        status, actual = self.auth.current(now)
        self.auth.guard.remaining(request["deadline"])
        need(stamp_le(request["issued"], actual) and same(request["binding"], self.auth.binding)
             and same(request["original_setup_key"], original_key(self.auth.binding)), "CONTEXT_MISMATCH")
        selected = next((g for g in self.auth.access["callers"] if g["principal_id"] == request["caller_id"]), None)
        need(selected is not None and same(selected, caller) and request["operation"] in caller["operations"]
             and request["use"] in caller["uses"], "SIGNER_UNAPPOINTED")
        return request, status, actual

    def _history(self, db, key):
        rows = db.execute("SELECT generation,request_raw,request_sha,checkpoint_raw,checkpoint_sha,envelope_raw FROM transitions WHERE key_raw=? ORDER BY generation",
                          (canonical_bytes(key),)).fetchall()
        need(len(rows) <= 23, "CHECKPOINT_LEDGER_DIVERGENCE")
        history, previous = [], ZERO
        for generation, raw_request, request_sha, raw_cert, cert_sha, raw_env in rows:
            raw_request, raw_cert, raw_env = bytes(raw_request), bytes(raw_cert), bytes(raw_env)
            transition = method.decode("CheckpointAdvanceRequest", raw_request).payload()
            cert = method.decode("ConsumerCheckpoint", raw_cert).payload()
            env = method.decode("SignedEnvelope", raw_env).payload()
            need(generation == len(history) + 1 and digest(raw_request) == request_sha and digest(raw_cert) == cert_sha
                 and cert["generation"] == generation and cert["previous_checkpoint_sha256"] == previous
                 and cert["transition_request_ref"] == ref(raw_request, "CHECKPOINT_TRANSITION")
                 and transition["expected_generation"] == generation - 1
                 and transition["expected_checkpoint_sha256"] == previous
                 and same(cert["original_setup_key"], key) and same(cert["binding"], self.auth.binding), "CHECKPOINT_LEDGER_DIVERGENCE")
            self.auth.verify_attestation(raw_cert, env, expected_purpose="policy-inheritance-checkpoint-v3",
                                         appointment=self.auth.appointment, now=self.auth.guard.check())
            history.append({"generation": generation, "request_sha256": request_sha, "checkpoint_sha256": cert_sha,
                            "checkpoint_utf8": raw_cert.decode("utf-8"), "checkpoint_attestation_utf8": raw_env.decode("utf-8")})
            previous = cert_sha
        attempt = db.execute("SELECT generation,head_sha FROM attempts WHERE key_raw=?", (canonical_bytes(key),)).fetchone()
        need((attempt is None and not history) or (attempt is not None and tuple(attempt) == (len(history), previous)), "CHECKPOINT_LEDGER_DIVERGENCE")
        return history

    @staticmethod
    def _minimum(history, generation, head):
        need(type(generation) is int and 0 <= generation <= len(history), "CHECKPOINT_MISMATCH")
        need((generation == 0 and head == ZERO) or (generation > 0 and history[generation - 1]["checkpoint_sha256"] == head),
             "CHECKPOINT_MISMATCH")

    def _response(self, request, status, history, *, outcome):
        _, now = self.auth.current()
        self.auth.guard.remaining(request["deadline"])
        last = history[-1] if history else None
        result = {"format": "forex.checkpoint-rpc-response/2", "request_sha256": digest(canonical_bytes(request)),
                  "nonce_hex": request["nonce_hex"], "binding": request["binding"], "original_setup_key": request["original_setup_key"],
                  "checkpoint_authority_id": self.authority_id, "store_instance_id": self.database.selection.store_instance_id,
                  "status": outcome, "observed": now, "clock_domain": self.auth.guard.budget["clock_domain"],
                  "authority_view_sha256": digest(canonical_bytes(status)), "generation": len(history),
                  "head_sha256": last["checkpoint_sha256"] if last else ZERO,
                  "checkpoint_utf8": last["checkpoint_utf8"] if last else None,
                  "checkpoint_attestation_utf8": last["checkpoint_attestation_utf8"] if last else None,
                  "history": history, "failure_code": None, "access_selection_sha256": self.auth.selection.access_sha256}
        return ck.validate("CheckpointRpcResponse", result).payload()

    def read_current(self, request, *, authenticated_caller, now):
        request, status, _ = self._context(request, authenticated_caller, now)
        need(request["operation"] == "READ_CURRENT", "PURPOSE_MISMATCH")
        # Read also durably remembers current external revision; it never changes
        # an attempt/generation, and is not a substitute for a caller's one-use commit.
        with self.database.transaction(final_guard=self.auth.current) as db:
            ConsumerStore.remember_authority(db, status)
            history = self._history(db, request["original_setup_key"])
            self._minimum(history, request["body"]["minimum_generation"], request["body"]["minimum_head_sha256"])
            return self._response(request, status, history, outcome="PRESENT" if history else "ABSENT")

    def lookup_exact(self, request, *, authenticated_caller, now):
        request, status, _ = self._context(request, authenticated_caller, now)
        need(request["operation"] == "LOOKUP_TRANSITION", "PURPOSE_MISMATCH")
        with self.database.transaction(final_guard=self.auth.current) as db:
            ConsumerStore.remember_authority(db, status)
            history = self._history(db, request["original_setup_key"])
            body = request["body"]
            self._minimum(history, body["minimum_generation"], body["minimum_head_sha256"])
            row = db.execute("SELECT request_sha FROM transitions WHERE key_raw=? AND transition_id=?",
                             (canonical_bytes(request["original_setup_key"]), body["transition_id"])).fetchone()
            need(row is not None and row[0] == body["exact_request_sha256"], "CHECKPOINT_ADVANCE_UNCONFIRMED")
            return self._response(request, status, history, outcome="EXACT_RECOVERY")

    def _attachments(self, request, caller, actual):
        body = request["body"]
        raw = body["transition_utf8"].encode("utf-8")
        transition = method.decode("CheckpointAdvanceRequest", raw).payload()
        envelope = method.decode("SignedEnvelope", body["transition_attestation_utf8"].encode("utf-8")).payload()
        need(transition["requester_id"] == caller["principal_id"] == envelope["body"]["producer_id"]
             and same(transition["binding"], request["binding"])
             and same(transition["original_setup_key"], request["original_setup_key"]), "CONTEXT_MISMATCH")
        self.auth.verify_attestation(raw, envelope, expected_purpose="policy-inheritance-checkpoint-transition-v3",
                                     appointment=self.auth.appointment, now=actual)
        budget_raw = body["unsigned_budget_utf8"].encode("utf-8")
        budget = method.decode("SetupBudget", budget_raw).payload()
        need(same(budget, self.auth.guard.budget) and transition["budget_sha256"] == digest(budget_raw)
             and transition["budget_id"] == budget["budget_id"] and transition["stream_id"] == self.auth.appointment["stream_id"]
             and transition["original_budget_body_ref"] == ref(budget_raw, "SETUP_BUDGET")
             and stamp_le(budget["started"], transition["prepared_at"])
             and stamp_le(transition["prepared_at"], actual), "CONTEXT_MISMATCH")
        output = transition["output"]
        if output["kind"] == "NONE":
            need(output["body_ref"] is None and output["attestation_ref"] is None
                 and body["output_body_utf8"] is None and body["output_attestation_utf8"] is None, "CONTEXT_MISMATCH")
            output_value = None
        else:
            types = {"SETUP_BUDGET": ("SetupBudget", "policy-inheritance-setup-budget-v3"),
                     "INGESTION_ACK": ("IngestionAck", "policy-inheritance-ingestion-ack-v3"),
                     "METHOD_DECISION": ("ConsumerDecision", "policy-inheritance-method-decision-v3")}
            name, purpose = types[output["kind"]]
            output_raw = body["output_body_utf8"].encode("utf-8")
            output_env_raw = body["output_attestation_utf8"].encode("utf-8")
            output_value = method.decode(name, output_raw).payload()
            output_env = method.decode("SignedEnvelope", output_env_raw).payload()
            need(output["body_ref"] == ref(output_raw, output["kind"])
                 and output["attestation_ref"] == ref(output_env_raw, "SIGNED_ENVELOPE")
                 and same(output_value["binding"], self.auth.binding), "RAW_BYTES_MISMATCH")
            self.auth.verify_attestation(output_raw, output_env, expected_purpose=purpose,
                                         appointment=self.auth.appointment, now=self.auth.guard.check())
        return transition, budget, output_value

    def _transition(self, transition, budget, output_value, prior, initial, caller):
        kind, output = transition["transition_kind"], transition["output"]
        issuer = budget["issuer_id"]
        consumer = self.auth.principal("INDEPENDENT_SETUP_CONSUMER")["principal_id"]
        need(caller["principal_id"] == (issuer if kind in ("SETUP_RESERVATION", "BUDGET_CLAIM") else consumer), "SIGNER_UNAPPOINTED")
        if prior is None:
            need(kind == "SETUP_RESERVATION" and transition["expected_generation"] == 0
                 and transition["expected_checkpoint_sha256"] == ZERO and transition["claim_state"] == "RESERVED"
                 and transition["event_sequence"] == 0 and transition["event_head_sha256"] == ZERO
                 and output["kind"] == "NONE" and initial is not None, "BUDGET_ALREADY_CLAIMED")
            need(initial["authorized_issuer_id"] == issuer, "SIGNER_UNAPPOINTED")
            return
        need(initial is None and prior["transition_kind"] not in ("TERMINAL_ABORT", "DECISION_EXPOSURE"), "BUDGET_ALREADY_CLAIMED")
        for field in ("binding", "original_setup_key", "budget_id", "budget_sha256", "stream_id", "original_budget_body_ref"):
            need(same(transition[field], prior[field]), "BUDGET_RESET_ATTEMPT")
        if kind == "BUDGET_CLAIM":
            need(prior["generation"] == 1 and prior["claim_state"] == "RESERVED"
                 and transition["claim_state"] == "CLAIMED" and transition["event_sequence"] == 0
                 and transition["event_head_sha256"] == ZERO and output["kind"] == "SETUP_BUDGET"
                 and same(output_value, budget), "BUDGET_ALREADY_CLAIMED")
        elif kind == "ACK_EXPOSURE":
            need(prior["claim_state"] == "CLAIMED" and transition["claim_state"] == "CLAIMED"
                 and transition["event_sequence"] == prior["event_sequence"] + 1 <= 19
                 and output["kind"] == "INGESTION_ACK"
                 and output_value["sequence"] == transition["event_sequence"]
                 and output_value["record_sha256"] == transition["event_head_sha256"]
                 and output_value["budget_sha256"] == transition["budget_sha256"]
                 and output_value["consumer_id"] == consumer
                 and output_value["stream_id"] == transition["stream_id"]
                 and output_value["retention_commit_id"] == transition["consumer_prepare_commit_id"], "SEQUENCE_GAP")
        elif kind == "DECISION_EXPOSURE":
            need(prior["claim_state"] == "CLAIMED" and transition["claim_state"] == "CLAIMED"
                 and transition["event_sequence"] == prior["event_sequence"]
                 and transition["event_head_sha256"] == prior["event_head_sha256"] and output["kind"] == "METHOD_DECISION"
                 and output_value["budget_sha256"] == transition["budget_sha256"]
                 and output_value["consumer_id"] == consumer
                 and output_value["stream_id"] == transition["stream_id"]
                 and output_value["retained_record_count"] == prior["event_sequence"]
                 and output_value["retained_prefix_head_sha256"] == prior["event_head_sha256"]
                 and output_value["retention_commit_id"] == transition["consumer_prepare_commit_id"], "INCOMPLETE_STREAM")
            if output_value["status"] == "ACCEPTED_NARROW_METHOD":
                need(prior["generation"] == 21 and prior["event_sequence"] == 19
                     and output_value["sealed_head_sha256"] == prior["event_head_sha256"], "INCOMPLETE_STREAM")
        elif kind == "TERMINAL_ABORT":
            need(transition["claim_state"] == "ABORTED" and output["kind"] == "NONE"
                 and transition["event_sequence"] == prior["event_sequence"]
                 and transition["event_head_sha256"] == prior["event_head_sha256"], "CONTEXT_MISMATCH")
        else:
            raise AuthorityError("BUDGET_ALREADY_CLAIMED")

    def compare_and_append(self, request, *, authenticated_caller, now):
        request, status, actual = self._context(request, authenticated_caller, now)
        need(request["operation"] == "ADVANCE" and request["use"] == "SETUP_PROTOCOL", "PURPOSE_MISMATCH")
        transition, budget, output_value = self._attachments(request, authenticated_caller, actual)
        raw_transition = canonical_bytes(transition)
        initial_text = request["body"]["initial_authorization_utf8"]
        initial = ck.decode("InitialSetupAuthorization", initial_text.encode("utf-8")).payload() if initial_text is not None else None
        if initial is not None:
            self.auth.authorize_initial(initial, now=self.auth.guard.check())
        key = transition["original_setup_key"]
        with self.database.transaction(final_guard=self.auth.current) as db:
            ConsumerStore.remember_authority(db, status)
            history = self._history(db, key)
            existing = db.execute("SELECT request_raw,attachments_raw FROM transitions WHERE transition_id=?", (transition["transition_id"],)).fetchone()
            if existing is not None:
                need(bytes(existing[0]) == raw_transition and bytes(existing[1]) == canonical_bytes(request["body"]), "REPLAY_OR_EQUIVOCATION")
                return self._response(request, status, history, outcome="EXACT_RECOVERY")
            need(transition["expected_generation"] == len(history)
                 and transition["expected_checkpoint_sha256"] == (history[-1]["checkpoint_sha256"] if history else ZERO), "CHECKPOINT_MISMATCH")
            prior = method.decode("ConsumerCheckpoint", history[-1]["checkpoint_utf8"].encode("utf-8")).payload() if history else None
            self._transition(transition, budget, output_value, prior, initial, authenticated_caller)
            key_raw = canonical_bytes(key)
            attempt = db.execute("SELECT binding_raw,budget_raw FROM attempts WHERE key_raw=?", (key_raw,)).fetchone()
            if attempt is None:
                need(initial is not None and not history, "BUDGET_ALREADY_CLAIMED")
                db.execute("INSERT INTO attempts VALUES (?,?,?,?,?,0,?)", (key_raw, canonical_bytes(transition["binding"]), canonical_bytes(budget),
                           initial["authorization_id"], canonical_bytes(initial), ZERO))
            else:
                need(bytes(attempt[0]) == canonical_bytes(transition["binding"])
                     and bytes(attempt[1]) == canonical_bytes(budget), "BUDGET_RESET_ATTEMPT")
            status, actual = self.auth.current()
            ConsumerStore.remember_authority(db, status)
            certificate = {k: transition[k] for k in ("binding", "original_setup_key", "transition_kind", "budget_id", "budget_sha256",
                           "stream_id", "event_sequence", "event_head_sha256", "consumer_prepare_commit_id", "output", "claim_state", "original_budget_body_ref")}
            certificate.update({"format": "forex.policy-inheritance-checkpoint/3", "checkpoint_authority_id": self.authority_id,
                                "checkpoint_id": "checkpoint-" + digest(raw_transition), "generation": len(history) + 1,
                                "previous_checkpoint_sha256": transition["expected_checkpoint_sha256"],
                                "transition_request_ref": ref(raw_transition, "CHECKPOINT_TRANSITION"), "checkpointed_at": actual})
            cert_raw = method.validate("ConsumerCheckpoint", certificate).raw
            envelope = self.auth.attest(cert_raw, purpose="policy-inheritance-checkpoint-v3", producer_id=self.authority_id,
                                       signer=self.signer, now=self.auth.guard.check())
            env_raw = canonical_bytes(envelope)
            db.execute("INSERT INTO transitions VALUES (?,?,?,?,?,?,?,?,?)", (key_raw, certificate["generation"], transition["transition_id"],
                       raw_transition, digest(raw_transition), canonical_bytes(request["body"]), cert_raw, digest(cert_raw), env_raw))
            db.execute("UPDATE attempts SET generation=?,head_sha=? WHERE key_raw=?", (certificate["generation"], digest(cert_raw), key_raw))
            history.append({"generation": certificate["generation"], "request_sha256": digest(raw_transition), "checkpoint_sha256": digest(cert_raw),
                            "checkpoint_utf8": cert_raw.decode("utf-8"), "checkpoint_attestation_utf8": env_raw.decode("utf-8")})
            result = self._response(request, status, history, outcome="COMMITTED")
        # A commit failure/expired post-commit guard never reaches this return.
        return result
