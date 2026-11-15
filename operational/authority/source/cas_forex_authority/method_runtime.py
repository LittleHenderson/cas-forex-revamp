"""Prepare/anchor/confirm/expose implementation over the fixed method ports.

Positive event ACKs require the separately selected substantive event verifier.
No fixture, shape validator or decoder alone is installed as that verifier.
"""
from __future__ import annotations

from threading import RLock
from cas_forex_operational_contracts import checkpoint as ck, method
from cas_forex_operational_contracts.common import canonical_bytes, decode_canonical, digest, MAX_OBJECT
from .authentication import AuthorityError, ZERO, need, original_key, ref, same, stamp_le

CALIBRATIONS = ("POSITIVE_INERT", "BAD_MAC", "BAD_SEQUENCE", "BAD_CHANNEL_ID", "BAD_FRAME",
                "DELIVERED_RIGHTS", "TRUNCATED_RIGHTS", "WRONG_PEER_PID")
UNSUPPORTED = ("PROC_ROOT_ACQUISITION", "PROC_FD_REOPEN_OR_DUPLICATION", "PROC_MEM_ACCESS", "PTRACE_ACCESS",
               "PROCESS_VM_READ_WRITE", "PIDFD_GETFD", "ARBITRARY_IPC_CAPABILITY_ACQUISITION",
               "COMPROMISED_ADAPTER_KEY_OR_DESCRIPTOR_FORWARDING")


class MethodRuntime:
    def __init__(self, *, authentication, store, checkpoint_client, signer, plan, evidence,
                 event_envelope, semantic_verifier=None, validate_event=None, validate_sealed=None):
        self.auth, self.store, self.client, self.signer = authentication, store, checkpoint_client, signer
        self._plan = method.validate("CoveragePlan", plan).raw
        self.evidence, self.event_envelope = evidence, event_envelope
        if semantic_verifier is not None:
            from .semantic_verifier import OperationalSemanticVerifier
            need(type(semantic_verifier) is OperationalSemanticVerifier and validate_event is None and validate_sealed is None,
                 "DECODER_UNAVAILABLE")
            validate_event, validate_sealed = semantic_verifier.validate_event, semantic_verifier.validate_sealed
        if validate_event is not None or validate_sealed is not None:
            from .semantic_verifier import OperationalSemanticVerifier
            owner = getattr(validate_event, "__self__", None)
            need(type(owner) is OperationalSemanticVerifier and getattr(validate_sealed, "__self__", None) is owner,
                 "DECODER_UNAVAILABLE")
        self.validate_event, self.validate_sealed = validate_event, validate_sealed
        self._lock = RLock()
        need(digest(self._plan) == authentication.appointment["coverage_plan_sha256"], "CONTEXT_MISMATCH")
        self._validate_plan(plan)

    @property
    def plan(self):
        return decode_canonical(self._plan)

    def _validate_plan(self, plan):
        slots = plan["slots"]
        kinds = [s["kind"] for s in slots]
        need(len(slots) == 19 and len({s["slot_id"] for s in slots}) == 19
             and kinds[0] == "SETUP_BEGIN" and kinds[1] == "CALIBRATION_BEGIN"
             and kinds[2:10] == ["CALIBRATION_CASE"] * 8
             and kinds[-2:] == ["POLICY_ARGUMENT", "SETUP_SEAL"]
             and tuple(plan["unsupported_routes"]) == UNSUPPORTED, "DEPENDENCY_ORDER")
        order = {s["slot_id"]: i for i, s in enumerate(slots)}
        positions = {}
        for i, slot in enumerate(slots):
            need(all(parent in order and order[parent] < i for parent in slot["after_slots"]), "DEPENDENCY_ORDER")
            positions.setdefault(slot["kind"], []).append(i)
        required = {"CALIBRATION_RETIRED", "FINAL_CHANNEL_CREATED", "RUNNER_INSTALL", "MODEL_INSTALL", "ASSET_BINDINGS", "MODEL_POST_EXEC", "FINAL_PEER_BOUND"}
        need(set(kinds[10:17]) == required, "MISSING_SLOT")
        for earlier, later in (("CALIBRATION_RETIRED", "FINAL_CHANNEL_CREATED"), ("FINAL_CHANNEL_CREATED", "RUNNER_INSTALL"),
                               ("RUNNER_INSTALL", "MODEL_INSTALL"), ("MODEL_INSTALL", "MODEL_POST_EXEC"),
                               ("ASSET_BINDINGS", "MODEL_POST_EXEC"), ("MODEL_POST_EXEC", "FINAL_PEER_BOUND")):
            need(positions[earlier][0] < positions[later][0], "DEPENDENCY_ORDER")
        need(tuple(c["case_kind"] for c in plan["calibration_plan"]) == CALIBRATIONS
             and [c["slot_id"] for c in plan["calibration_plan"]] == [s["slot_id"] for s in slots[2:10]], "CALIBRATION_INCOMPLETE")

        need(len({c["case_id"] for c in plan["calibration_plan"]}) == 8
             and all(c["case_id"] == slots[order[c["slot_id"]]]["expected_subject_id"] for c in plan["calibration_plan"]),
             "CALIBRATION_BASELINE_MISMATCH")
        # Require mandatory dependencies through explicit selected edges.
        ancestors = {}
        for slot in slots:
            parents = set(slot["after_slots"])
            need(len(parents) == len(slot["after_slots"]), "DEPENDENCY_ORDER")
            ancestors[slot["slot_id"]] = parents | set().union(*(ancestors[p] for p in parents))
        def dependency(earlier, later):
            need(slots[earlier]["slot_id"] in ancestors[slots[later]["slot_id"]], "DEPENDENCY_ORDER")
        for i in range(1, 10): dependency(i - 1, i)
        retired = positions["CALIBRATION_RETIRED"][0]
        for i in range(1, 10): dependency(i, retired)
        edges = (("CALIBRATION_RETIRED", "FINAL_CHANNEL_CREATED"), ("SETUP_BEGIN", "RUNNER_INSTALL"),
                 ("FINAL_CHANNEL_CREATED", "RUNNER_INSTALL"), ("RUNNER_INSTALL", "MODEL_INSTALL"),
                 ("SETUP_BEGIN", "ASSET_BINDINGS"), ("RUNNER_INSTALL", "MODEL_POST_EXEC"),
                 ("MODEL_INSTALL", "MODEL_POST_EXEC"), ("ASSET_BINDINGS", "MODEL_POST_EXEC"),
                 ("FINAL_CHANNEL_CREATED", "FINAL_PEER_BOUND"), ("RUNNER_INSTALL", "FINAL_PEER_BOUND"),
                 ("MODEL_POST_EXEC", "FINAL_PEER_BOUND"))
        for earlier, later in edges: dependency(positions[earlier][0], positions[later][0])
        for i in range(17): dependency(i, 17)
        for i in range(18): dependency(i, 18)

    def _read(self, minimum=0, head=ZERO):
        request = self.client.request("READ_CURRENT", {"minimum_generation": minimum, "minimum_head_sha256": head,
                                      "consumption_binding": None}, now=self.auth.guard.check())
        return self.client.read_current(request, now=self.auth.guard.check())

    def _prepare(self, *, logical_id, kind, prior, output_body=None, output_kind="NONE", output_purpose=None,
                 initial=None, event=None, artifacts=(), event_head=None, event_sequence=None, output_expiry=None):
        status, now = self.auth.current()
        budget = self.auth.guard.budget
        prepared_id = "prepare-" + digest(canonical_bytes([logical_id, self.auth.binding]))
        output_raw, envelope_raw = None, None
        output = {"kind": output_kind, "body_ref": None, "attestation_ref": None}
        retained = list(artifacts)
        if output_body is not None:
            output_raw = canonical_bytes(output_body)
            issuer = budget["issuer_id"] if output_kind == "SETUP_BUDGET" else self.auth.principal("INDEPENDENT_SETUP_CONSUMER")["principal_id"]
            envelope = self.auth.attest(output_raw, purpose=output_purpose, producer_id=issuer,
                                        signer=self.signer, now=now, expires=output_expiry)
            envelope_raw = canonical_bytes(envelope)
            output = {"kind": output_kind, "body_ref": ref(output_raw, output_kind), "attestation_ref": ref(envelope_raw, "SIGNED_ENVELOPE")}
            retained.extend(((output["body_ref"], output_raw), (output["attestation_ref"], envelope_raw)))
        budget_raw = self.auth._budget_bytes()
        retained.append((ref(budget_raw, "SETUP_BUDGET"), budget_raw))
        if prior["history"]:
            previous = method.decode("ConsumerCheckpoint", prior["checkpoint_utf8"].encode("utf-8")).payload()
            previous_sequence, previous_head = previous["event_sequence"], previous["event_head_sha256"]
        else:
            previous_sequence, previous_head = 0, ZERO
        transition = {"format": "forex.policy-inheritance-checkpoint-transition/3", "binding": self.auth.binding,
                      "original_setup_key": original_key(self.auth.binding), "transition_id": "transition-" + digest(canonical_bytes([logical_id, self.auth.binding])),
                      "transition_kind": kind, "requester_id": self.client.caller_id,
                      "expected_generation": prior["generation"], "expected_checkpoint_sha256": prior["head_sha256"],
                      "budget_id": budget["budget_id"], "budget_sha256": digest(budget_raw), "stream_id": self.auth.appointment["stream_id"],
                      "event_sequence": previous_sequence if event_sequence is None else event_sequence,
                      "event_head_sha256": previous_head if event_head is None else event_head,
                      "consumer_prepare_commit_id": prepared_id, "output": output,
                      "claim_state": "RESERVED" if kind == "SETUP_RESERVATION" else "ABORTED" if kind == "TERMINAL_ABORT" else "CLAIMED",
                      "prepared_at": self.auth.guard.check(), "original_budget_body_ref": ref(budget_raw, "SETUP_BUDGET")}
        transition_raw = method.validate("CheckpointAdvanceRequest", transition).raw
        transition_env = self.auth.attest(transition_raw, purpose="policy-inheritance-checkpoint-transition-v3",
                                          producer_id=self.client.caller_id, signer=self.signer, now=self.auth.guard.check())
        retained.extend(((ref(transition_raw, "CHECKPOINT_TRANSITION"), transition_raw),
                         (ref(canonical_bytes(transition_env), "SIGNED_ENVELOPE"), canonical_bytes(transition_env))))
        body = {"transition_utf8": transition_raw.decode("utf-8"), "transition_attestation_utf8": canonical_bytes(transition_env).decode("utf-8"),
                "initial_authorization_utf8": canonical_bytes(initial).decode("utf-8") if initial is not None else None,
                "unsigned_budget_utf8": budget_raw.decode("utf-8"),
                "output_body_utf8": output_raw.decode("utf-8") if output_raw is not None else None,
                "output_attestation_utf8": envelope_raw.decode("utf-8") if envelope_raw is not None else None}
        ck.validate("CheckpointAdvanceBody", body)
        record = {"logical_id": logical_id, "transition": transition, "attachments": body,
                  "event": event, "artifact_refs": [r for r, _ in retained]}
        status, _ = self.auth.current()
        self.store.prepare(record, artifacts=tuple(retained), status=status)
        self.auth.current()
        return record

    def _finish(self, preparation, *, first_attempt):
        transition = preparation["transition"]
        if preparation["event"] is not None:
            need(digest(method.validate("Event", preparation["event"]).raw) == transition["event_head_sha256"]
                 and preparation["event"]["sequence"] == transition["event_sequence"], "CHECKPOINT_LEDGER_DIVERGENCE")
        if first_attempt:
            self.store.claim_advance(transition["transition_id"])
            request = self.client.request("ADVANCE", preparation["attachments"], now=self.auth.guard.check())
            response = self.client.advance(request, now=self.auth.guard.check())
        else:
            body = {"transition_id": transition["transition_id"], "exact_request_sha256": digest(canonical_bytes(transition)),
                    "minimum_generation": transition["expected_generation"] + 1,
                    "minimum_head_sha256": ZERO}
            # The certificate's head is not reconstructible from the transition.
            # Fresh current read supplies it, followed by exact read-only lookup.
            current = self._read(transition["expected_generation"], transition["expected_checkpoint_sha256"])
            self.store.assert_history(current)
            matches = [x for x in current["history"] if x["request_sha256"] == body["exact_request_sha256"]]
            need(len(matches) == 1, "CHECKPOINT_ADVANCE_UNCONFIRMED")
            body["minimum_generation"], body["minimum_head_sha256"] = matches[0]["generation"], matches[0]["checkpoint_sha256"]
            request = self.client.request("LOOKUP_TRANSITION", body, now=self.auth.guard.check())
            response = self.client.lookup_transition(request, now=self.auth.guard.check())
        matching = [x for x in response["history"] if x["request_sha256"] == digest(canonical_bytes(transition))]
        need(len(matching) == 1, "CHECKPOINT_MISMATCH")
        row = matching[0]
        fresh = self._read(row["generation"], row["checkpoint_sha256"])
        self.store.assert_history(fresh)
        cert = method.decode("ConsumerCheckpoint", row["checkpoint_utf8"].encode("utf-8")).payload()
        envelope = method.decode("SignedEnvelope", row["checkpoint_attestation_utf8"].encode("utf-8")).payload()
        for key in ("binding", "original_setup_key", "output", "consumer_prepare_commit_id", "event_sequence", "event_head_sha256", "budget_sha256"):
            need(same(cert[key], transition[key]), "CHECKPOINT_MISMATCH")
        self.store.confirm(preparation, certificate=cert, envelope=envelope, event=preparation["event"], final_guard=self.auth.current)
        for reference in preparation["artifact_refs"]:
            self.store.resolve(reference)
            self.auth.current()
        if transition["output"]["kind"] == "NONE":
            return None
        output = transition["output"]
        raw, output_env = self.store.resolve(output["body_ref"]), method.decode("SignedEnvelope", self.store.resolve(output["attestation_ref"])).payload()
        purpose = {"SETUP_BUDGET": "policy-inheritance-setup-budget-v3", "INGESTION_ACK": "policy-inheritance-ingestion-ack-v3",
                   "METHOD_DECISION": "policy-inheritance-method-decision-v3"}[output["kind"]]
        self.auth.verify_attestation(raw, output_env, expected_purpose=purpose, appointment=self.auth.appointment, now=self.auth.guard.check())
        # Checkpoint persistence cannot revive an expired/revoked raw dependency.
        # Exact recovery keeps the old signature bytes but repeats semantic trust.
        if output["kind"] == "INGESTION_ACK":
            need(self.validate_event is not None and preparation["event"] is not None, "DECODER_UNAVAILABLE")
            event = preparation["event"]
            accepted = self.store.accepted_events(original_key(self.auth.binding))
            prefix = accepted[:event["sequence"] - 1]
            need(len(prefix) == event["sequence"] - 1, "CHECKPOINT_LEDGER_DIVERGENCE")
            checked = self.validate_event(event_raw=canonical_bytes(event), accepted_raw=tuple(canonical_bytes(x) for x in prefix),
                       plan_raw=self._plan, budget_raw=self.auth._budget_bytes(), now=self.auth.guard.check())
            for reference, data in checked:
                need(self.store.resolve(reference) == data, "RETENTION_UNAVAILABLE")
        elif output["kind"] == "METHOD_DECISION":
            need(self.validate_sealed is not None, "DECODER_UNAVAILABLE")
            accepted = self.store.accepted_events(original_key(self.auth.binding))
            interval = self.validate_sealed(accepted_raw=tuple(canonical_bytes(x) for x in accepted), plan_raw=self._plan,
                         budget_raw=self.auth._budget_bytes(), now=self.auth.guard.check())
            from .authentication import utc
            decision = method.decode("ConsumerDecision", raw).payload()
            need(utc(decision["expires"]["utc"]) <= utc(interval["expires_at_utc"]), "AUTHENTICATED_INTERVAL_EXPIRED")
        self.auth.current()
        exposed = {"format": "forex.policy-inheritance-exposed-output/3", "binding": self.auth.binding, **output,
                   "checkpoint_ref": ref(canonical_bytes(cert), "CHECKPOINT_CERTIFICATE"),
                   "checkpoint_attestation_ref": ref(canonical_bytes(envelope), "SIGNED_ENVELOPE")}
        method.validate("ExposedOutput", exposed)
        self.auth.current()
        return exposed

    def reserve(self, authorization, budget, *, now):
        with self._lock:
            need(same(budget, self.auth.guard.budget), "BUDGET_RESET_ATTEMPT")
            self.auth.authorize_initial(authorization, now=now)
            self.store.bind_attempt(original_key(self.auth.binding), self.auth.binding, budget)
            pending = self.store.prepared(logical_id="reservation")
            if pending is None:
                current = self._read()
                need(current["status"] == "ABSENT", "BUDGET_ALREADY_CLAIMED")
                pending = (self._prepare(logical_id="reservation", kind="SETUP_RESERVATION", prior=current, initial=authorization), None)
                self._finish(pending[0], first_attempt=True)
            else:
                # Recovery cannot sign a claim that is absent from the retained
                # local preparation, even if only reservation g1 is visible.
                claim = self.store.prepared(logical_id="budget")
                need(claim is not None, "CHECKPOINT_LEDGER_DIVERGENCE")
                return self._finish(claim[0], first_attempt=False)
            claim = self.store.prepared(logical_id="budget")
            if claim is not None:
                return self._finish(claim[0], first_attempt=False)
            current = self._read()
            need(current["generation"] == 1, "BUDGET_ALREADY_CLAIMED")
            claim = self._prepare(logical_id="budget", kind="BUDGET_CLAIM", prior=current, output_body=budget,
                                  output_kind="SETUP_BUDGET", output_purpose="policy-inheritance-setup-budget-v3")
            return self._finish(claim, first_attempt=True)

    def ingest(self, event, *, now):
        with self._lock:
            event_raw = method.validate("Event", event).raw
            self.auth.current(now)
            logical_id = "event-" + str(event["sequence"])
            pending = self.store.prepared(logical_id=logical_id)
            if pending is not None:
                need(same(pending[0]["event"], event), "REPLAY_OR_EQUIVOCATION")
                return self._finish(pending[0], first_attempt=False)
            accepted = self.store.accepted_events(original_key(self.auth.binding))
            need(event["sequence"] == len(accepted) + 1 <= 19 and event["previous_record_sha256"] == (digest(canonical_bytes(accepted[-1])) if accepted else ZERO), "SEQUENCE_GAP")
            slot = self.plan["slots"][len(accepted)]
            need(all(event[k] == slot[j] for k, j in (("slot_id", "slot_id"), ("kind", "kind"), ("origin", "origin")))
                 and same(event["binding"], self.auth.binding) and event["budget_sha256"] == digest(self.auth._budget_bytes())
                 and event["stream_id"] == self.auth.appointment["stream_id"], "CONTEXT_MISMATCH")
            need(stamp_le(self.auth.guard.budget["started"], event["observed_start"])
                 and stamp_le(event["observed_start"], event["observed_end"]) and stamp_le(event["observed_end"], event["recorded"])
                 and stamp_le(event["recorded"], self.auth.guard.check())
                 and (not accepted or stamp_le(accepted[-1]["recorded"], event["recorded"])), "CLOCK_DRIFT")
            try:
                envelope = self.event_envelope(ref(event_raw, "EVENT_RECORD"))
            except AuthorityError:
                raise
            except Exception:
                raise AuthorityError("RAW_EVIDENCE_UNAVAILABLE") from None
            self.auth.verify_attestation(event_raw, envelope, expected_purpose="policy-inheritance-witness-v3",
                                         appointment=self.auth.appointment, now=self.auth.guard.check())
            need(envelope["body"]["producer_id"] == event["producer_id"], "SIGNER_UNAPPOINTED")
            need(self.validate_event is not None, "DECODER_UNAVAILABLE")
            # The selected validator must authenticate the COMPLETE EventInputs
            # graph, redo decoding and all applicable PAYLOAD/calibration checks.
            # It returns exact graph bytes for atomic retention, never a PASS label.
            try:
                artifacts = self.validate_event(event_raw=event_raw, accepted_raw=tuple(canonical_bytes(x) for x in accepted),
                                                plan_raw=self._plan, budget_raw=self.auth._budget_bytes(), now=self.auth.guard.check())
            except AuthorityError:
                raise
            except Exception:
                raise AuthorityError("RAW_EVIDENCE_UNAVAILABLE") from None
            need(type(artifacts) is tuple and artifacts, "RAW_EVIDENCE_UNAVAILABLE")
            references = {canonical_bytes(r) for r, _ in artifacts}
            need(all(canonical_bytes(r) in references for r in event["raw_refs"] + [event["payload_ref"], event["input_bundle_ref"], event["input_bundle_envelope_ref"]]), "RAW_EVIDENCE_UNAVAILABLE")
            retained = artifacts + ((ref(event_raw, "EVENT_RECORD"), event_raw), (ref(canonical_bytes(envelope), "SIGNED_ENVELOPE"), canonical_bytes(envelope)))
            self.auth.current()
            current = self._read()
            self.store.assert_history(current)
            need(current["generation"] == len(accepted) + 2, "CHECKPOINT_LEDGER_DIVERGENCE")
            commit_id = "prepare-" + digest(canonical_bytes([logical_id, self.auth.binding]))
            ack = {"format": "forex.policy-inheritance-ingestion-ack/3", "binding": self.auth.binding,
                   "consumer_id": self.auth.principal("INDEPENDENT_SETUP_CONSUMER")["principal_id"], "stream_id": event["stream_id"],
                   "sequence": event["sequence"], "record_sha256": digest(event_raw), "retention_commit_id": commit_id,
                   "acknowledged": self.auth.guard.check(), "budget_sha256": event["budget_sha256"]}
            method.validate("IngestionAck", ack)
            preparation = self._prepare(logical_id=logical_id, kind="ACK_EXPOSURE", prior=current, output_body=ack, output_kind="INGESTION_ACK",
                                        output_purpose="policy-inheritance-ingestion-ack-v3", event=event, artifacts=retained,
                                        event_head=digest(event_raw), event_sequence=event["sequence"])
            return self._finish(preparation, first_attempt=True)

    def decide(self, *, binding, budget_sha256, now):
        with self._lock:
            need(same(binding, self.auth.binding) and budget_sha256 == digest(self.auth._budget_bytes()), "CONTEXT_MISMATCH")
            self.auth.current(now)
            pending = self.store.prepared(logical_id="decision")
            if pending is not None:
                return self._finish(pending[0], first_attempt=False)
            accepted = self.store.accepted_events(original_key(binding))
            need(len(accepted) == 19 and accepted[-1]["kind"] == "SETUP_SEAL", "INCOMPLETE_STREAM")
            need(self.validate_sealed is not None, "DECODER_UNAVAILABLE")
            # Must revalidate all dependency attestations and return the actual
            # authenticated intersection, with its references, not shape success.
            try:
                interval = self.validate_sealed(accepted_raw=tuple(canonical_bytes(x) for x in accepted),
                                                plan_raw=self._plan, budget_raw=self.auth._budget_bytes(), now=self.auth.guard.check())
            except AuthorityError:
                raise
            except Exception:
                raise AuthorityError("RAW_EVIDENCE_UNAVAILABLE") from None
            method.validate("AuthenticatedInterval", interval)
            need(same(interval["binding"], binding), "CONTEXT_MISMATCH")
            current = self._read()
            self.store.assert_history(current)
            need(current["generation"] == 21, "OUTPUT_NOT_CHECKPOINTED")
            from .authentication import utc, micros
            budget = self.auth.guard.budget
            expiry_utc = min(utc(interval["expires_at_utc"]), utc(budget["deadline"]["utc"]))
            from .authentication import stamp_text
            expires = {"utc": stamp_text(expiry_utc), "boottime_ns": min(budget["deadline"]["boottime_ns"],
                       budget["started"]["boottime_ns"] + micros(expiry_utc - utc(budget["started"]["utc"])) * 1000)}
            decided = self.auth.guard.check()
            need(utc(interval["not_before_utc"]) <= utc(decided["utc"]) < expiry_utc and decided["boottime_ns"] < expires["boottime_ns"], "AUTHENTICATED_INTERVAL_EXPIRED")
            interval_raw = canonical_bytes(interval)
            head = digest(canonical_bytes(accepted[-1]))
            decision = {"format": "forex.policy-inheritance-method-decision/3", "binding": binding,
                        "consumer_id": self.auth.principal("INDEPENDENT_SETUP_CONSUMER")["principal_id"],
                        "decision_id": "decision-" + head, "budget_sha256": budget_sha256, "stream_id": self.auth.appointment["stream_id"],
                        "status": "ACCEPTED_NARROW_METHOD", "failure_code": None, "sealed_head_sha256": head,
                        "retained_prefix_head_sha256": head, "retained_record_count": 19,
                        "retention_commit_id": "prepare-" + digest(canonical_bytes(["decision", binding])), "decided": decided, "expires": expires,
                        "accepted_claims": ["TRUSTED_INSTALLATION_AND_INHERITANCE", "PUBLIC_RECEIVER_CALIBRATION"],
                        "unsupported_routes": list(UNSUPPORTED), "evidence_classes": sorted({x["evidence_class"] for x in accepted}),
                        "completion_scoring_publication_authority": False, "authenticated_interval_ref": ref(interval_raw, "AUTHENTICATED_INTERVAL")}
            method.validate("ConsumerDecision", decision)
            preparation = self._prepare(logical_id="decision", kind="DECISION_EXPOSURE", prior=current, output_body=decision,
                                        output_kind="METHOD_DECISION", output_purpose="policy-inheritance-method-decision-v3",
                                        artifacts=((ref(interval_raw, "AUTHENTICATED_INTERVAL"), interval_raw),), output_expiry=expires)
            return self._finish(preparation, first_attempt=True)

    def recover_exact(self, output, *, now):
        with self._lock:
            method.validate("OutputBinding", output)
            self.auth.current(now)
            pending = self.store.prepared(output=output)
            need(pending is not None and output["kind"] != "NONE", "CHECKPOINT_LEDGER_DIVERGENCE")
            return self._finish(pending[0], first_attempt=False)
