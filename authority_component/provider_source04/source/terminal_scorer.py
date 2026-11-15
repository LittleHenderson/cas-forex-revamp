"""Independent original-attempt scoring over a proposed normalized fact graph.

No application imports, expected-value computation, persistence or model calls.
An independently authored/reviewed plan supplies expected values. The generic
public-fixture plan is not a mapping of the sealed R6 cases. Unknown predicates
block preflight; mapping/semantic coverage and actual capture remain dependencies.
"""
from decimal import Decimal, InvalidOperation
from hashlib import sha256

from .authority_provider import EvidenceError, canonical, digest, hash_value, identifier, integer, need, parse, ref, shape, utc

KINDS = frozenset(("ATTEMPT", "OUTCOME", "PRE_STATE", "POST_STATE", "AUTHORIZATION", "DISPATCH", "VENUE_EFFECT", "CONTEXT"))
OPERATORS = frozenset(("EQUALS", "EQUAL_FIELDS", "ORDERED_TIMES", "STRICT_INCREASE"))
PUBLISHER_ROLE = {"ATTEMPT": "transport", "OUTCOME": "transport", "PRE_STATE": "venue", "POST_STATE": "venue",
                  "AUTHORIZATION": "core", "DISPATCH": "core", "VENUE_EFFECT": "venue", "CONTEXT": "custody"}
MISSING = object()
FAILURE_CODES = frozenset(("CUSTODY_GATE", "ISOLATION_GATE", "PIN_MISMATCH", "TOKEN_GATE", "TRANSPORT_GATE",
    "MODEL_PROTOCOL_GATE", "MANDATORY_CHECK_FAILED", "TIME_BUDGET", "CALL_BUDGET", "EVIDENCE_UNAVAILABLE"))


def _same(left, right):
    return canonical(left) == canonical(right)


def _project(actual, expected):
    """Exact typed comparison of every independently specified field; no defaults."""
    if type(expected) is dict:
        if type(actual) is not dict or not set(expected) <= set(actual): return None
        values = [_project(actual[k], v) for k, v in expected.items()]
        return None if any(v is None for v in values) else all(values)
    return _same(actual, expected)


class TerminalScorer:
    def __init__(self, *, publishers, plan_reference, plan_review_reference, bundle_reference,
                 source_freeze_manifest_sha256, custody_public_manifest_sha256, accepted_private_mapping_sha256,
                 model_identity_sha256, tokenizer_sha256):
        shape(publishers, ("custody", "mapper", "reviewer", "transport", "core", "venue"))
        for value in publishers.values(): digest(value)
        need(publishers["mapper"] not in {publishers[k] for k in ("core", "transport", "venue")}
             and publishers["reviewer"] not in {publishers[k] for k in ("mapper", "custody", "core", "transport", "venue")}
             and publishers["custody"] not in {publishers[k] for k in ("core", "transport", "venue")}
             and publishers["venue"] != publishers["core"], "INDEPENDENCE_BINDING")
        self.publishers = dict(publishers)
        self.plan_ref, self.review_ref, self.bundle_ref = (parse(canonical(ref(v))) for v in (plan_reference, plan_review_reference, bundle_reference))
        self.source_pin, self.custody_pin, self.mapping_pin = map(digest,
            (source_freeze_manifest_sha256, custody_public_manifest_sha256, accepted_private_mapping_sha256))
        self.model_pin, self.tokenizer_pin = digest(model_identity_sha256), digest(tokenizer_sha256)

    def _record(self, reference, *, role, purpose, authority):
        return authority.record(reference, purpose=purpose, publisher_sha256=self.publishers[role])

    def _plan(self, authority):
        plan = self._record(self.plan_ref, role="mapper", purpose="independent-scoring-plan", authority=authority)
        shape(plan, ("format", "run_id", "epoch", "frozen_at_utc", "expected_outcome_author_sha256",
            "accepted_mapping_sha256", "steps", "assertions"))
        need(plan["format"] == "forex.independent-scoring-plan/1" and plan["run_id"] == authority.selection["run_id"]
             and plan["epoch"] == authority.selection["epoch"] and plan["expected_outcome_author_sha256"] == self.publishers["mapper"]
             and plan["accepted_mapping_sha256"] == self.mapping_pin, "PLAN_BINDING")
        review = self._record(self.review_ref, role="reviewer", purpose="scoring-plan-review", authority=authority)
        shape(review, ("format", "plan_sha256", "accepted_mapping_sha256", "expected_outcome_author_sha256",
            "required_step_ids", "required_assertion_ids", "coverage"))
        need(review["format"] == "forex.independent-scoring-plan-review/1" and review["plan_sha256"] == self.plan_ref["sha256"]
             and review["accepted_mapping_sha256"] == self.mapping_pin and review["expected_outcome_author_sha256"] == self.publishers["mapper"]
             and review["coverage"] == "ALL_REQUIRED_ASSERTIONS", "PLAN_REVIEW")
        need(type(plan["steps"]) is list and len(plan["steps"]) == 30, "MANDATORY_DENOMINATOR")
        step_ids = []
        for step in plan["steps"]:
            shape(step, ("step_id", "permissible_action_refs", "required_disposition", "expected_pre", "expected_post",
                "requires_dispatch", "requires_venue_effect", "required_evidence_ids", "assertion_ids"))
            step_ids.append(identifier(step["step_id"]))
            need(type(step["permissible_action_refs"]) is list and step["permissible_action_refs"])
            need(len({canonical(v) for v in step["permissible_action_refs"]}) == len(step["permissible_action_refs"]))
            for value in step["permissible_action_refs"]:
                if value is not None: identifier(value)
            need(step["required_disposition"] in ("ACT", "WAIT", "HOLD", "STAND_DOWN"))
            need(type(step["requires_dispatch"]) is bool and type(step["requires_venue_effect"]) is bool)
            need(not step["requires_venue_effect"] or step["requires_dispatch"], "PLAN_EFFECT_WITHOUT_DISPATCH")
            need(step["required_disposition"] == "ACT" or not step["requires_dispatch"], "PLAN_DISPOSITION")
            need(type(step["expected_pre"]) is dict and type(step["expected_post"]) is dict)
            need(type(step["required_evidence_ids"]) is list and type(step["assertion_ids"]) is list)
            for value in step["required_evidence_ids"]: identifier(value)
        need(len(set(step_ids)) == 30 and step_ids == review["required_step_ids"], "STEP_COVERAGE")
        need(type(plan["assertions"]) is list and plan["assertions"])
        assertion_ids = []
        for assertion in plan["assertions"]:
            shape(assertion, ("assertion_id", "operator", "operands", "expected"))
            assertion_ids.append(identifier(assertion["assertion_id"]))
            need(assertion["operator"] in OPERATORS, "UNIMPLEMENTED_PREDICATE")
            need(type(assertion["operands"]) is list and assertion["operands"])
            count = len(assertion["operands"])
            need((assertion["operator"] == "EQUALS" and count == 1)
                 or (assertion["operator"] == "EQUAL_FIELDS" and count == 2)
                 or (assertion["operator"] in ("ORDERED_TIMES", "STRICT_INCREASE") and count >= 2))
            if assertion["operator"] != "EQUALS": need(assertion["expected"] is None)
            for operand in assertion["operands"]:
                shape(operand, ("step_id", "kind", "path"))
                need(operand["step_id"] in step_ids and operand["kind"] in KINDS and type(operand["path"]) is list)
                need(all(type(k) is str and k for k in operand["path"]))
        need(len(set(assertion_ids)) == len(assertion_ids) and assertion_ids == review["required_assertion_ids"], "ASSERTION_COVERAGE")
        linked = [a for s in plan["steps"] for a in s["assertion_ids"]]
        need(set(linked) == set(assertion_ids) and all(s["assertion_ids"] for s in plan["steps"]))
        return plan

    def derive(self, *, retained_bundle, authority):
        plan = self._plan(authority)
        bundle = self._record(self.bundle_ref, role="custody", purpose="complete-retained-evaluation-bundle", authority=authority)
        need(_same(bundle, retained_bundle), "BUNDLE_SUBSTITUTED")
        shape(bundle, ("format", "run_id", "epoch", "source_manifest_sha256", "config_sha256", "records", "finalization"))
        need(bundle["format"] == "forex.retained-attempt-bundle/1")
        for key in ("run_id", "epoch", "source_manifest_sha256", "config_sha256"):
            need(bundle[key] == authority.selection[key], "BUNDLE_BINDING")
        final = self._record(bundle["finalization"], role="custody", purpose="retained-bundle-finalization", authority=authority)
        shape(final, ("format", "run_id", "epoch", "lifecycle", "records_content_sha256", "original_attempt_order", "terminal_at_utc", "broad_failure_codes"))
        need(final["format"] == "forex.retained-bundle-finalization/1" and final["run_id"] == bundle["run_id"]
             and final["epoch"] == bundle["epoch"] and final["lifecycle"] in ("FINAL", "ABORTED")
             and final["records_content_sha256"] == hash_value(bundle["records"]), "BUNDLE_FINALIZATION")
        need(type(bundle["records"]) is list and len(bundle["records"]) <= 16384)
        need(type(final["broad_failure_codes"]) is list and set(final["broad_failure_codes"]) <= FAILURE_CODES)
        need(len(set(final["broad_failure_codes"])) == len(final["broad_failure_codes"]))
        facts, references, identities = {}, {}, set()
        attempts, outcomes = [], {}
        for row in bundle["records"]:
            shape(row, ("kind", "reference")); need(row["kind"] in KINDS)
            value = self._record(row["reference"], role=PUBLISHER_ROLE[row["kind"]], purpose="retained-"+row["kind"].lower(), authority=authority)
            shape(value, ("format", "record_id", "run_id", "epoch", "source_manifest_sha256", "config_sha256", "kind", "step_id", "payload"))
            need(value["format"] == "forex.retained-fact/1" and value["kind"] == row["kind"])
            rid = identifier(value["record_id"])
            need(rid not in identities, "DUPLICATE_ORIGINAL_RECORD"); identities.add(rid)
            for key in ("run_id", "epoch", "source_manifest_sha256", "config_sha256"):
                need(value[key] == bundle[key])
            kind, sid, payload = value["kind"], value["step_id"], value["payload"]
            if kind == "ATTEMPT":
                self._attempt(payload, sid=sid, plan=plan, authority=authority)
                attempts.append((payload, row["reference"]))
            elif kind == "OUTCOME":
                shape(payload, ("attempt_id", "status", "finished_at_utc", "response_utf8", "response_raw_sha256", "input_tokens", "generated_tokens"))
                aid = identifier(payload["attempt_id"])
                need(aid not in outcomes and payload["status"] in ("COMPLETE", "FAILED", "UNKNOWN"), "ORIGINAL_OUTCOME_CONFLICT")
                outcomes[aid] = (payload, row["reference"], sid)
            else:
                need(sid in {s["step_id"] for s in plan["steps"]} and type(payload) is dict)
                key = (sid, kind)
                need(key not in facts, "AMBIGUOUS_FACT")
                facts[key], references[key] = payload, row["reference"]
        need(len(attempts) <= 32, "CALL_BUDGET")
        order = [a["attempt_id"] for a, _ in attempts]
        need(order == final["original_attempt_order"] and len(set(order)) == len(order), "ORIGINAL_ATTEMPT_LOG")
        need(set(outcomes) == set(order), "ORIGINAL_OUTCOME_MISSING_OR_EXTRA")
        seen_steps, probes, generation_rows, selected = set(), 0, [], {}
        failures, invalid_attempts = set(final["broad_failure_codes"]), set()
        previous_finish = utc(authority.selection["not_before_utc"])
        for index, (attempt, attempt_ref) in enumerate(attempts):
            outcome, outcome_ref, outcome_sid = outcomes[attempt["attempt_id"]]
            sid = attempt["step_id"]
            need(outcome_sid == sid and utc(attempt["started_at_utc"]) <= utc(outcome["finished_at_utc"])
                 <= utc(final["terminal_at_utc"]) <= utc(authority.selection["expires_at_utc"]), "ATTEMPT_TIME")
            need(previous_finish <= utc(attempt["started_at_utc"]), "ORIGINAL_ATTEMPT_ORDER")
            previous_finish = utc(outcome["finished_at_utc"])
            if attempt["phase"] == "PROBE":
                need(index < 2 and sid is None, "PROBE_ORDER"); probes += 1
            else:
                need(probes == 2 and sid not in seen_steps, "FIRST_ATTEMPT_REPLACED")
                need(sid == plan["steps"][len(seen_steps)]["step_id"], "FROZEN_STEP_ORDER")
                seen_steps.add(sid)
            integer(outcome["input_tokens"], 0); integer(outcome["generated_tokens"], 0)
            need(outcome["input_tokens"] == attempt["input_tokens"], "TOKEN_RECEIPT_BINDING")
            if outcome["generated_tokens"] > attempt["generated_token_limit"]:
                failures.add("TOKEN_GATE"); invalid_attempts.add(attempt["attempt_id"])
            if (utc(outcome["finished_at_utc"])-utc(attempt["started_at_utc"])).total_seconds() > attempt["timeout_seconds"]:
                failures.add("TIME_BUDGET"); invalid_attempts.add(attempt["attempt_id"])
            selection = None
            if outcome["status"] == "COMPLETE":
                need(type(outcome["response_utf8"]) is str and sha256(outcome["response_utf8"].encode()).hexdigest() == outcome["response_raw_sha256"], "RAW_RESPONSE_PIN")
                try:
                    selection = parse(outcome["response_utf8"].encode())
                    shape(selection, ("request_id", "opportunity_set_id", "source_state_id", "selected_action_ref", "reason", "evidence_ids"))
                    need(all(selection[k] == attempt[k] for k in ("request_id", "opportunity_set_id", "source_state_id")))
                    need(type(selection["reason"]) is str and selection["reason"].strip()
                         and type(selection["evidence_ids"]) is list and all(type(e) is str for e in selection["evidence_ids"]))
                    if selection["selected_action_ref"] is not None: identifier(selection["selected_action_ref"])
                    for evidence_id in selection["evidence_ids"]: identifier(evidence_id)
                    need(len(set(selection["evidence_ids"])) == len(selection["evidence_ids"]))
                except EvidenceError:
                    failures.add("MODEL_PROTOCOL_GATE"); selection = None
                # B08 availability probes have no actions and must return WAIT.
                # Preserve COMPLETE as the original transport outcome and keep
                # the attempt spent; the fixed semantic failure prevents ACCEPT.
                if attempt["phase"] == "PROBE" and selection is not None and selection["selected_action_ref"] is not None:
                    failures.add("MODEL_PROTOCOL_GATE")
            else:
                if outcome["response_utf8"] is None:
                    need(outcome["response_raw_sha256"] is None, "FAILED_REPLY_MISREPRESENTED")
                else:
                    need(type(outcome["response_utf8"]) is str and sha256(outcome["response_utf8"].encode()).hexdigest()
                         == outcome["response_raw_sha256"], "RAW_RESPONSE_PIN")
                # A retained partial/error response never replaces the failed or unknown outcome.
                failures.add("EVIDENCE_UNAVAILABLE" if outcome["status"] == "UNKNOWN" else "TRANSPORT_GATE")
            if sid is not None:
                selected[sid] = (selection, attempt, outcome, outcome_ref)
                facts[(sid, "ATTEMPT")], references[(sid, "ATTEMPT")] = attempt, attempt_ref
                facts[(sid, "OUTCOME")], references[(sid, "OUTCOME")] = outcome, outcome_ref
            generation_rows.append({"attempt_id": attempt["attempt_id"], "phase": attempt["phase"], "outcome": outcome["status"],
                "original_attempt_receipt": attempt_ref, "original_outcome_receipt": outcome_ref})
        assertion_rows = []
        for assertion in plan["assertions"]:
            result, anchor = self._assertion(assertion, facts, references)
            assertion_rows.append({"assertion_id": assertion["assertion_id"], "outcome": result, "independent_evidence_receipt": anchor})
            if result == "FAIL": failures.add("MANDATORY_CHECK_FAILED")
        assertion_status = {r["assertion_id"]: r["outcome"] for r in assertion_rows}
        steps = []
        for expected in plan["steps"]:
            sid = expected["step_id"]
            if sid not in selected:
                steps.append({"step_id": sid, "attempt_id": None, "outcome": "INCOMPLETE", "independent_evidence_receipt": None})
                continue
            selection, attempt, outcome, outcome_ref = selected[sid]
            if outcome["status"] == "UNKNOWN": result = "INCOMPLETE"
            elif outcome["status"] == "FAILED" or selection is None or attempt["attempt_id"] in invalid_attempts: result = "FAIL"
            else: result = self._step(expected, selection, attempt, facts)
            mandatory = [assertion_status[a] for a in expected["assertion_ids"]]
            if result == "PASS" and "FAIL" in mandatory: result = "FAIL"
            if result == "PASS" and "INCOMPLETE" in mandatory: result = "INCOMPLETE"
            if result == "FAIL": failures.add("MANDATORY_CHECK_FAILED")
            steps.append({"step_id": sid, "attempt_id": attempt["attempt_id"], "outcome": result, "independent_evidence_receipt": outcome_ref})
        return {"format": "forex.independent-terminal-score/1", "run_id": bundle["run_id"], "epoch": bundle["epoch"], "lifecycle": final["lifecycle"],
            "source_freeze_manifest_sha256": self.source_pin, "custody_public_manifest_sha256": self.custody_pin,
            "retained_evaluation_bundle_sha256": self.bundle_ref["sha256"], "accepted_private_mapping_sha256": self.mapping_pin,
            "mandatory_step_ids": [s["step_id"] for s in plan["steps"]], "mandatory_assertion_ids": [a["assertion_id"] for a in plan["assertions"]],
            "steps": steps, "assertions": assertion_rows, "generation_attempts": generation_rows, "broad_failure_codes": sorted(failures)}

    def _attempt(self, value, *, sid, plan, authority):
        shape(value, ("attempt_id", "phase", "step_id", "attempt_index", "request_id", "opportunity_set_id", "source_state_id",
            "request_sha256", "invocation_sha256", "model_identity_sha256", "tokenizer_sha256", "started_at_utc", "original_window_sha256",
            "input_tokens", "generated_token_limit", "timeout_seconds"))
        for field in ("attempt_id", "request_id", "opportunity_set_id", "source_state_id"): identifier(value[field])
        for field in ("request_sha256", "invocation_sha256", "model_identity_sha256", "tokenizer_sha256"): digest(value[field])
        need(value["model_identity_sha256"] == self.model_pin and value["tokenizer_sha256"] == self.tokenizer_pin, "INFERENCE_IDENTITY_PIN")
        integer(value["attempt_index"], 1, 1)
        need(value["step_id"] == sid and value["phase"] in ("PROBE", "MANDATORY")
             and value["original_window_sha256"] == authority.selection["original_window_sha256"])
        need(utc(plan["frozen_at_utc"]) <= utc(value["started_at_utc"])
             and utc(authority.selection["not_before_utc"]) <= utc(value["started_at_utc"]) < utc(authority.selection["expires_at_utc"]))
        if value["phase"] == "MANDATORY": need(sid in {s["step_id"] for s in plan["steps"]})
        caps = (1024, 256, 60) if value["phase"] == "PROBE" else (4096, 512, 120)
        integer(value["input_tokens"], 1, caps[0]); integer(value["generated_token_limit"], 1, caps[1]); integer(value["timeout_seconds"], 1, caps[2])

    @staticmethod
    def _step(expected, selection, attempt, facts):
        sid, action = expected["step_id"], selection["selected_action_ref"]
        if not any(_same(action, a) for a in expected["permissible_action_refs"]): return "FAIL"
        if not set(expected["required_evidence_ids"]) <= set(selection["evidence_ids"]): return "FAIL"
        if (expected["required_disposition"] == "ACT") != (action is not None): return "FAIL"
        pre, post = facts.get((sid, "PRE_STATE"), MISSING), facts.get((sid, "POST_STATE"), MISSING)
        if pre is MISSING or post is MISSING: return "INCOMPLETE"
        comparisons = [_project(pre, expected["expected_pre"]), _project(post, expected["expected_post"])]
        if any(v is False for v in comparisons): return "FAIL"
        if any(v is None for v in comparisons): return "INCOMPLETE"
        auth, dispatch, effect = (facts.get((sid, k), MISSING) for k in ("AUTHORIZATION", "DISPATCH", "VENUE_EFFECT"))
        if expected["requires_dispatch"]:
            if auth is MISSING or dispatch is MISSING: return "INCOMPLETE"
            for record, fields in ((auth, ("attempt_id", "selected_action_ref", "command_id", "reservation_id", "authorization_id")),
                                   (dispatch, ("attempt_id", "selected_action_ref", "command_id"))):
                if not all(field in record for field in fields): return "INCOMPLETE"
                for field in fields: identifier(record[field])
            if not (auth.get("attempt_id") == attempt["attempt_id"] == dispatch.get("attempt_id")
                    and auth.get("selected_action_ref") == action == dispatch.get("selected_action_ref")
                    and auth.get("command_id") == dispatch.get("command_id")
                    and auth.get("reservation_id") and auth.get("authorization_id")): return "FAIL"
        elif auth is not MISSING or dispatch is not MISSING: return "FAIL"
        if expected["requires_venue_effect"]:
            if effect is MISSING or dispatch is MISSING: return "INCOMPLETE"
            fields = ("command_id", "attempt_id", "receipt_id", "observation_id")
            if not all(field in effect for field in fields): return "INCOMPLETE"
            for field in fields: identifier(effect[field])
            if not (effect.get("command_id") == dispatch.get("command_id") and effect.get("attempt_id") == attempt["attempt_id"]
                    and effect.get("receipt_id") and effect.get("observation_id")): return "FAIL"
        elif effect is not MISSING: return "FAIL"
        return "PASS"

    @staticmethod
    def _assertion(assertion, facts, references):
        values, anchor = [], None
        for operand in assertion["operands"]:
            key = (operand["step_id"], operand["kind"])
            if key not in facts: return "INCOMPLETE", None
            anchor = references[key] if anchor is None else anchor
            value = facts[key]
            for field in operand["path"]:
                if type(value) is not dict or field not in value: return "INCOMPLETE", anchor
                value = value[field]
            values.append(value)
        operator = assertion["operator"]
        if operator == "EQUALS": passed = _same(values[0], assertion["expected"])
        elif operator == "EQUAL_FIELDS": passed = _same(values[0], values[1])
        elif operator == "ORDERED_TIMES": passed = all(utc(a) < utc(b) for a,b in zip(values, values[1:]))
        elif operator == "STRICT_INCREASE":
            try:
                need(all(type(v) in (int, str) for v in values))
                decimals = [Decimal(v) for v in values]
                need(all(v.is_finite() for v in decimals))
                passed = all(a < b for a,b in zip(decimals, decimals[1:]))
            except (InvalidOperation, ValueError):
                return "FAIL", anchor
        else: raise EvidenceError("UNIMPLEMENTED_PREDICATE")
        return ("PASS" if passed else "FAIL"), anchor

    def verify(self, *, record, retained_bundle, selection, authority):
        expected = self.derive(retained_bundle=retained_bundle, authority=authority)
        for field in ("run_id", "epoch", "source_freeze_manifest_sha256", "custody_public_manifest_sha256",
                      "retained_evaluation_bundle_sha256", "accepted_private_mapping_sha256", "mandatory_step_ids", "mandatory_assertion_ids"):
            need(expected[field] == selection[field], "SCORING_SELECTION_PIN")
        need(_same(record, expected), "APPLICATION_SCORE_LABEL_REJECTED")
