"""Entirely public, invented unit fixtures. NOT observations or sealed R6 cases.

No factory runs on import. No I/O, real signature, private key, model or collector.
Fixed values are test data only and grant no authority.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from source.authority_provider import canonical, hash_value, need, parse
from source.completion_provider import CompletionProvider, GROUPS
from source.terminal_scorer import TerminalScorer, PUBLISHER_ROLE
from source.redaction_provider import RedactionProvider


def pin(label):
    return sha256(("PUBLIC-FIXTURE:" + label).encode()).hexdigest()


def at(seconds):
    return (datetime(2000, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


class FixtureStore:
    """Purpose-aware in-memory stub; expressly not an independent authority."""
    def __init__(self):
        self.selection = {"format": "forex.custody-provider-selection/1", "run_id": "public-fixture-run", "epoch": 1,
            "source_manifest_sha256": pin("source"), "config_sha256": pin("configuration"),
            "topology_sha256": pin("topology"), "original_window_sha256": pin("clock"),
            "not_before_utc": at(0), "expires_at_utc": at(5400), "publishers": {}, "records": {}}
        self.values, self.order = {}, []

    def add(self, value, *, purpose, publisher):
        raw = canonical(value)
        reference = {"path": "/opt/cas-forex/public-fixture/" + hash_value(value) + ".json", "bytes": len(raw), "sha256": hash_value(value)}
        existing = self.values.get(reference["sha256"])
        if existing is not None:
            need(existing[1:] == (purpose, publisher), "FIXTURE_ROLE_COLLISION")
        self.values[reference["sha256"]] = (raw, purpose, publisher)
        self.order.append(reference)
        return deepcopy(reference)

    def read(self, reference):
        raw = self.values[reference["sha256"]][0]
        need(len(raw) == reference["bytes"] and sha256(raw).hexdigest() == reference["sha256"])
        return raw, parse(raw)

    def record(self, reference, *, purpose, publisher_sha256):
        raw, wanted_purpose, wanted_publisher = self.values[reference["sha256"]]
        need(purpose == wanted_purpose and publisher_sha256 == wanted_publisher, "FIXTURE_PURPOSE_BINDING")
        return self.read(reference)[1]


class FakeSignatureVerifier:
    """Synthetic allowlisted-message verifier. NEVER use outside unit tests."""
    def __init__(self, signer, messages):
        self.signer, self.messages = signer, set(messages)

    def verify(self, *, signer_sha256, message, signature_hex):
        need(signer_sha256 == self.signer and message in self.messages and signature_hex == "00" * 64, "FAKE_SIGNATURE_REJECTED")


def authentication_fixture(*, attestation_expires_at=None):
    store = FixtureStore()
    publisher, signer = pin("fixture-publisher"), pin("fixture-verifier-NOT-a-key")
    record = store.add({"public_fixture_only": True}, purpose="fixture-purpose", publisher=publisher)
    body = {"format": "forex.independent-record-attestation/1", "attestation_id": "public-fixture-attestation",
        "record_sha256": record["sha256"], "record_bytes": record["bytes"], "purpose": "fixture-purpose", "publisher_sha256": publisher,
        **{k: store.selection[k] for k in ("run_id", "epoch", "source_manifest_sha256", "config_sha256", "topology_sha256", "original_window_sha256", "not_before_utc", "expires_at_utc")}}
    if attestation_expires_at is not None: body["expires_at_utc"] = attestation_expires_at
    attestation = store.add({"body": body, "algorithm": "Ed25519", "signer_sha256": signer, "signature_hex": "00" * 64},
                            purpose="fixture-attestation", publisher=publisher)
    store.selection["publishers"] = {publisher: signer}
    store.selection["records"] = {record["sha256"]: {"reference": record, "publisher_sha256": publisher, "attestations": {"fixture-purpose": attestation}}}
    return store, record, publisher, signer, FakeSignatureVerifier(signer, [canonical(body)])


def terminal_fixture(*, mode="complete"):
    store = FixtureStore()
    roles = {r: pin("role-"+r) for r in ("custody", "mapper", "reviewer", "transport", "core", "venue")}
    common = {k: store.selection[k] for k in ("run_id", "epoch", "source_manifest_sha256", "config_sha256")}
    steps, assertions, rows, attempt_order = [], [], [], []
    for i in range(30):
        sid, aid = "public-step-"+str(i), "public-assertion-"+str(i)
        steps.append({"step_id": sid, "permissible_action_refs": ["public-choice-"+str(i)], "required_disposition": "ACT",
            "expected_pre": {"ledger_sequence": i, "account_id": "public-account"},
            "expected_post": {"ledger_sequence": i+1, "account_id": "public-account"},
            "requires_dispatch": True, "requires_venue_effect": True, "required_evidence_ids": ["public-evidence"], "assertion_ids": [aid]})
        assertions.append({"assertion_id": aid, "operator": "STRICT_INCREASE", "operands": [
            {"step_id": sid, "kind": "PRE_STATE", "path": ["ledger_sequence"]},
            {"step_id": sid, "kind": "POST_STATE", "path": ["ledger_sequence"]}], "expected": None})
    if mode == "unsupported_predicate": assertions[0]["operator"] = "UNIMPLEMENTED_PUBLIC_FIXTURE"
    plan = {"format": "forex.independent-scoring-plan/1", "run_id": common["run_id"], "epoch": 1, "frozen_at_utc": at(0),
        "expected_outcome_author_sha256": roles["mapper"], "accepted_mapping_sha256": pin("PUBLIC-mapping-only"), "steps": steps, "assertions": assertions}
    plan_ref = store.add(plan, purpose="independent-scoring-plan", publisher=roles["mapper"])
    review_ref = store.add({"format": "forex.independent-scoring-plan-review/1", "plan_sha256": plan_ref["sha256"],
        "accepted_mapping_sha256": pin("PUBLIC-mapping-only"), "expected_outcome_author_sha256": roles["mapper"],
        "required_step_ids": [s["step_id"] for s in steps], "required_assertion_ids": [a["assertion_id"] for a in assertions],
        "coverage": "ALL_REQUIRED_ASSERTIONS"}, purpose="scoring-plan-review", publisher=roles["reviewer"])

    def fact(kind, sid, payload):
        value = {"format": "forex.retained-fact/1", "record_id": "public-record-"+str(len(rows)), **common,
                 "kind": kind, "step_id": sid, "payload": payload}
        reference = store.add(value, purpose="retained-"+kind.lower(), publisher=roles[PUBLISHER_ROLE[kind]])
        rows.append({"kind": kind, "reference": reference})

    count = 6 if mode == "incomplete" else 32
    for n in range(count):
        i, sid = n-2, None if n < 2 else steps[n-2]["step_id"]
        attempt_id = "public-attempt-"+str(n)
        attempt_order.append(attempt_id)
        request = {"request_id": "public-request-"+str(n), "opportunity_set_id": "public-set-"+str(n), "source_state_id": "public-state-"+str(n)}
        attempt = {"attempt_id": attempt_id, "phase": "PROBE" if n < 2 else "MANDATORY", "step_id": sid, "attempt_index": 1,
            **request, "request_sha256": pin("request-"+str(n)), "invocation_sha256": pin("invocation-"+str(n)),
            "model_identity_sha256": pin("not-an-actual-model"), "tokenizer_sha256": pin("not-an-actual-tokenizer"),
            "started_at_utc": at(100+n*2), "original_window_sha256": store.selection["original_window_sha256"],
            "input_tokens": 100, "generated_token_limit": 256 if n < 2 else 512, "timeout_seconds": 60 if n < 2 else 120}
        if n == 2 and mode == "wrong_model": attempt["model_identity_sha256"] = pin("wrong-model")
        fact("ATTEMPT", sid, attempt)
        response = {**request, "selected_action_ref": None if n < 2 else "public-choice-"+str(i),
                    "reason": "Invented public fixture response.", "evidence_ids": ["public-evidence"]}
        if n == 0 and mode == "action_probe": response["selected_action_ref"] = "public-prohibited-probe-choice"
        if n == 2 and mode == "safety_only": response["selected_action_ref"] = None
        raw = canonical(response).decode()
        outcome = {"attempt_id": attempt_id, "status": "COMPLETE", "finished_at_utc": at(101+n*2),
            "response_utf8": raw, "response_raw_sha256": sha256(raw.encode()).hexdigest(), "input_tokens": 100, "generated_tokens": 40}
        if n == 2 and mode in ("failed", "unknown"): outcome["status"] = mode.upper()
        if n == 2 and mode == "bad_response_pin": outcome["response_raw_sha256"] = pin("wrong-response")
        if n == 2 and mode == "token_overrun": outcome["generated_tokens"] = 513
        fact("OUTCOME", sid, outcome)
        if sid is None: continue
        fact("PRE_STATE", sid, {"ledger_sequence": i, "account_id": "public-account"})
        fact("POST_STATE", sid, {"ledger_sequence": i if n == 2 and mode == "wrong_state" else i+1, "account_id": "public-account"})
        links = {"attempt_id": attempt_id, "selected_action_ref": "public-choice-"+str(i), "command_id": "public-command-"+str(i)}
        fact("AUTHORIZATION", sid, {**links, "reservation_id": "public-reservation-"+str(i), "authorization_id": "public-auth-"+str(i)})
        fact("DISPATCH", sid, links)
        fact("VENUE_EFFECT", sid, {"attempt_id": attempt_id, "command_id": links["command_id"], "receipt_id": "public-receipt-"+str(i), "observation_id": "public-observation-"+str(i)})
        if n == 2 and mode == "retry":
            retry = deepcopy(attempt); retry["attempt_id"] = "public-retry"; retry["attempt_index"] = 2
            fact("ATTEMPT", sid, retry); attempt_order.append(retry["attempt_id"])
    final = {"format": "forex.retained-bundle-finalization/1", "run_id": common["run_id"], "epoch": 1,
        "lifecycle": "ABORTED" if mode == "aborted" else "FINAL", "records_content_sha256": hash_value(rows),
        "original_attempt_order": attempt_order, "terminal_at_utc": at(300), "broad_failure_codes": []}
    if mode == "omitted_record": rows.pop()
    final_ref = store.add(final, purpose="retained-bundle-finalization", publisher=roles["custody"])
    bundle = {"format": "forex.retained-attempt-bundle/1", **common, "records": rows, "finalization": final_ref}
    bundle_ref = store.add(bundle, purpose="complete-retained-evaluation-bundle", publisher=roles["custody"])
    scorer = TerminalScorer(publishers=roles, plan_reference=plan_ref, plan_review_reference=review_ref, bundle_reference=bundle_ref,
        source_freeze_manifest_sha256=pin("source-freeze"), custody_public_manifest_sha256=pin("custody-manifest"),
        accepted_private_mapping_sha256=pin("PUBLIC-mapping-only"), model_identity_sha256=pin("not-an-actual-model"), tokenizer_sha256=pin("not-an-actual-tokenizer"))
    bindings = {"format": "forex.approved-public-aggregate-bindings/1", "run_id": common["run_id"],
        "source_freeze_manifest_sha256": scorer.source_pin, "custody_public_manifest_sha256": scorer.custody_pin,
        "retained_evaluation_bundle_sha256": bundle_ref["sha256"], "reviewer_binding_sha256": roles["reviewer"]}
    bindings_ref = store.add(bindings, purpose="approved-public-aggregate-bindings", publisher=roles["reviewer"])
    redactor = RedactionProvider(scorer=scorer, public_bindings_reference=bindings_ref, reviewer_sha256=roles["reviewer"], application_sha256=roles["core"])
    selected = {**bindings, "public_run_id": common["run_id"], "epoch": 1, "accepted_private_mapping_sha256": scorer.mapping_pin,
        "mandatory_step_ids": [s["step_id"] for s in steps], "mandatory_assertion_ids": [a["assertion_id"] for a in assertions]}
    return store, scorer, redactor, bundle, selected


def completion_fixture(*, mode="complete"):
    store = FixtureStore()
    observer, custody, application = pin("observer"), pin("custody"), pin("application")
    common = {k: store.selection[k] for k in ("run_id", "epoch", "source_manifest_sha256", "config_sha256")}
    clock = {"bootstrap_started_utc": at(0), "test_deadline_utc": at(900), "model_window": {"started_at": at(1000)}}
    store.selection["original_window_sha256"] = hash_value(clock)
    original = {"status": "PASS", "finished_utc": at(100), "original_bootstrap_started_utc": at(0), "test_deadline_utc": at(900)}
    original_ref = store.add(original, purpose="original-source-test-report", publisher=custody)
    specs, processes = {}, []
    for i, group in enumerate(GROUPS):
        specs[group] = {"command_sha256": pin(group+"-command"), "executable_sha256": pin(group+"-executable")}
        process = {"group_id": group, "process_id": i+100, "start_ticks": i+1000, "started_at_utc": at(1+i*10),
                   "finished_at_utc": at(9+i*10), "exit_code": 0}
        for stream in ("stdout", "stderr"):
            content = "v24.21.0\n" if group == "node-version" else "# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n" if group == "ui" else "public fixture output\n"
            if stream == "stderr": content = ""
            if mode == "ui_failure" and group == "ui" and stream == "stdout": content = content.replace("# fail 0", "# fail 1")
            process[stream] = store.add({"format": "forex.test-stream/1", "run_id": common["run_id"], "epoch": 1,
                "process_id": process["process_id"], "start_ticks": process["start_ticks"], "stream": stream, "utf8": content,
                "raw_sha256": sha256(content.encode()).hexdigest()}, purpose="test-stream", publisher=observer)
        events = [{"sequence": 1, "kind": "SPAWN", "process_id": process["process_id"], "start_ticks": process["start_ticks"], "at_utc": process["started_at_utc"], "exit_code": None},
                  {"sequence": 2, "kind": "EXIT", "process_id": process["process_id"], "start_ticks": process["start_ticks"], "at_utc": process["finished_at_utc"], "exit_code": 0}]
        if mode == "failed_exit" and i == 0: events[1]["exit_code"] = 1
        process["capture"] = store.add({"format": "forex.test-process-capture/1", **common, "group_id": group, **specs[group],
            "events": events, "lost_events": 1 if mode == "lost_events" and i == 0 else 0,
            "stdout_sha256": process["stdout"]["sha256"], "stderr_sha256": process["stderr"]["sha256"]}, purpose="test-process-capture", publisher=observer)
        process["report"] = None
        if group not in ("node-version", "ui"):
            counts = {"discovered": 1, "ran": 1, "skipped": 0, "failures": 0, "errors": 0}
            original_group = {"group": group, **counts, "status": "PASS"}
            if mode == "original_mismatch" and i == 0: original_group["ran"] = 0
            group_ref = store.add(original_group, purpose="original-test-group-report", publisher=custody)
            process["report"] = store.add({"format": "forex.observed-test-group/1", "group_id": group,
                "process_id": process["process_id"], "start_ticks": process["start_ticks"], **counts, "original_report": group_ref}, purpose="test-group-report", publisher=observer)
        processes.append(process)
    if mode == "missing_group": processes.pop()
    observation = {"format": "forex.source-test-observation/1", **common, "observer_binding_sha256": observer,
        "original_report_sha256": original_ref["sha256"], "completed_at_utc": at(100), "groups": processes}
    observation_ref = store.add(observation, purpose="source-test-observation", publisher=observer)
    completion = {"format": "forex.observed-source-test-completion/1", **common, "observer_binding_sha256": observer,
        "original_clock_record_content_sha256": hash_value(clock), "completed_at_utc": at(100),
        "original_source_test_report": original_ref, "observation_evidence": observation_ref}
    completion_ref = store.add(completion, purpose="source-test-completion", publisher=observer)
    selected = {**common, "source_test_observer_binding_sha256": observer, "source_test_completion": completion_ref, "original_clock_record": clock}
    dependencies = {"original_clock_record": clock, "original_source_test_report": original, "observation_evidence": observation}
    provider = CompletionProvider(observer_sha256=observer, custody_sha256=custody, application_sha256=application, group_specs=specs)
    return store, provider, completion, dependencies, selected
