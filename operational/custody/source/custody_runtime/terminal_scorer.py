"""Independent original-attempt scoring through exact protected V2 records.

The separately selected private shape/mapping implementation is mandatory. No
expectation is inferred from an application result or from the public fixtures.
"""
from decimal import Decimal, InvalidOperation
from cas_forex_operational_contracts import common, protected
from .selection_provider import require, same, fresh


def _project(actual, expected):
    if type(expected) is dict:
        if type(actual) is not dict or not set(expected) <= set(actual): return None
        checks = [_project(actual[k], v) for k,v in expected.items()]
        return None if None in checks else all(checks)
    return same(actual, expected)


class TerminalScorer:
    def __init__(self, *, assembler, plan_use, review_use, bundle_use, shape_validator, accepted_mapping_sha256,
                 custody_public_manifest_sha256, model_identity_sha256, tokenizer_sha256,
                 model_window, clock, current_authority_guard, original_deadline):
        self.assembler = assembler
        self.plan_use, self.review_use, self.bundle_use = [common.decode_canonical(common.canonical_bytes(v)) for v in (plan_use, review_use, bundle_use)]
        self.mapper, self.mapping_pin = shape_validator, accepted_mapping_sha256
        self.custody_pin, self.model_pin, self.tokenizer_pin = custody_public_manifest_sha256, model_identity_sha256, tokenizer_sha256
        self.window = common.decode_canonical(common.canonical_bytes(model_window))
        self.clock, self.guard = clock, current_authority_guard
        self.deadline = common.decode_canonical(common.canonical_bytes(original_deadline))

    def _load(self, use, type_name, now):
        require(use["required_use"] == "RETAINED_EVALUATION", "SCORING_USE")
        routes={"ScoringPlan2":("SCORING_PLAN","independent-scoring-plan"),
                "ScoringPlanReview2":("SCORING_PLAN_REVIEW","scoring-plan-review"),
                "RetainedBundle2":("RETAINED_ATTEMPT_BUNDLE","complete-retained-evaluation-bundle"),
                "BundleFinalization2":("BUNDLE_FINALIZATION","retained-bundle-finalization")}
        require(type_name in routes and (use["reference"]["record_kind"],use["reference"]["purpose"])==routes[type_name],"SCORING_ROUTE")
        raw = self.assembler.resolver.resolve(use, selection=self.assembler.publishers, now=now)
        return protected.decode(type_name, raw, shape_validator=self.mapper).payload()

    def score(self, bundle, finalization, *, plan, review, now):
        now = fresh(self.clock, self.guard, now, self.deadline)
        require(same(plan, self._load(self.plan_use, "ScoringPlan2", now)) and same(review, self._load(self.review_use, "ScoringPlanReview2", now))
                and same(bundle, self._load(self.bundle_use, "RetainedBundle2", now)), "SCORING_ARGUMENT_SUBSTITUTION")
        require(same(bundle, self.assembler.assemble_original(tuple(bundle["records"]), binding=bundle["binding"], now=now)), "ORIGINAL_BUNDLE")
        require(same(finalization, self._load(bundle["finalization"], "BundleFinalization2", now)), "ORIGINAL_FINALIZATION")
        require(plan["accepted_mapping_sha256"] == review["accepted_mapping_sha256"] == self.mapping_pin
                and review["plan_sha256"] == self.plan_use["reference"]["sha256"]
                and plan["expected_outcome_author_sha256"] == review["expected_outcome_author_sha256"], "INDEPENDENT_PLAN_PIN")
        require(plan["run_id"] == bundle["binding"]["run_id"] and plan["epoch"] == bundle["binding"]["epoch"], "PLAN_BINDING")
        require(self.plan_use["reference"]["publisher_id"] != self.review_use["reference"]["publisher_id"],"INDEPENDENT_PLAN_REVIEWER")
        step_ids = [s["step_id"] for s in plan["steps"]]
        assertion_ids = [a["assertion_id"] for a in plan["assertions"]]
        require(len(step_ids) == len(set(step_ids)) == 30 and step_ids == review["required_step_ids"]
                and assertion_ids and len(assertion_ids) == len(set(assertion_ids)) and assertion_ids == review["required_assertion_ids"], "MANDATORY_DENOMINATOR")
        require({a for s in plan["steps"] for a in s["assertion_ids"]} == set(assertion_ids)
                and all(s["assertion_ids"] for s in plan["steps"]), "ASSERTION_COVERAGE")
        observations, references, attempts, outcomes = {}, {}, [], {}
        for entry in bundle["records"]:
            fact = self.assembler.fact(entry, binding=bundle["binding"], now=now)
            value, kind, sid = fact["payload"], fact["kind"], fact["step_id"]
            if kind == "ATTEMPT": attempts.append((value, entry["fact"], sid))
            elif kind == "OUTCOME": outcomes[value["attempt_id"]] = (value, entry["fact"], sid)
            else:
                require(sid in step_ids, "UNSELECTED_STEP")
                observations[(sid,kind)], references[(sid,kind)] = value, entry["fact"]
        require(0 < (common.utc(self.window["deadline"])-common.utc(self.window["started_at"])).total_seconds() <= 5400, "ORIGINAL_MODEL_WINDOW")
        previous = common.utc(self.window["started_at"])
        codes, rows, selected, probes, mandatory = set(finalization["broad_failure_codes"]), [], {}, 0, 0
        for attempt, attempt_ref, sid in attempts:
            outcome, outcome_ref, outcome_sid = outcomes[attempt["attempt_id"]]
            require(outcome_sid == sid == attempt["step_id"] and attempt["original_window_sha256"] == bundle["binding"]["original_window_sha256"]
                    and attempt["model_identity_sha256"] == self.model_pin and attempt["tokenizer_sha256"] == self.tokenizer_pin, "ATTEMPT_PINS")
            start, end = common.utc(attempt["started_at_utc"]), common.utc(outcome["finished_at_utc"])
            require(common.utc(plan["frozen_at_utc"]) <= start and previous <= start <= end <= common.utc(self.window["deadline"])
                    and end <= common.utc(finalization["terminal_at_utc"]), "ORIGINAL_ATTEMPT_TIME")
            previous = end
            probe = attempt["phase"] == "PROBE"
            if probe:
                require(probes < 2 and mandatory == 0 and sid is None, "PROBE_ORDER"); probes += 1
            else:
                require(attempt["phase"] == "MANDATORY" and probes == 2 and mandatory < 30 and sid == step_ids[mandatory], "MANDATORY_ORDER")
                mandatory += 1
            caps = (1024,256,60) if probe else (4096,512,120)
            for key, cap in zip(("input_tokens", "generated_token_limit", "timeout_seconds"), caps):
                require(type(attempt[key]) is int and 0 < attempt[key] <= cap, "ATTEMPT_BUDGET")
            require(outcome["input_tokens"] == attempt["input_tokens"] and type(outcome["generated_tokens"]) is int and outcome["generated_tokens"] >= 0, "TOKEN_RECEIPT")
            valid = True
            if outcome["generated_tokens"] > attempt["generated_token_limit"]: codes.add("TOKEN_GATE"); valid = False
            if (end-start).total_seconds() > attempt["timeout_seconds"]: codes.add("TIME_BUDGET"); valid = False
            response = None
            if outcome["response_utf8"] is not None:
                require(type(outcome["response_utf8"]) is str and common.digest(outcome["response_utf8"].encode()) == outcome["response_raw_sha256"], "RAW_RESPONSE_PIN")
            else: require(outcome["response_raw_sha256"] is None, "RAW_RESPONSE_ABSENCE")
            if outcome["status"] == "COMPLETE":
                try:
                    response = common.decode_json(outcome["response_utf8"].encode())
                    require(set(response) == {"request_id", "opportunity_set_id", "source_state_id", "selected_action_ref", "reason", "evidence_ids"}, "SELECTION_SHAPE")
                    require(all(response[k] == attempt[k] for k in ("request_id", "opportunity_set_id", "source_state_id")), "SELECTION_BINDING")
                    require(type(response["reason"]) is str and bool(response["reason"].strip()) and type(response["evidence_ids"]) is list
                            and all(type(v) is str for v in response["evidence_ids"]) and len(set(response["evidence_ids"])) == len(response["evidence_ids"])
                            and (response["selected_action_ref"] is None or type(response["selected_action_ref"]) is str), "SELECTION_VALUES")
                    if probe: require(response["selected_action_ref"] is None, "WAIT_ONLY_PROBE")
                except (common.ContractError, AttributeError, TypeError):
                    codes.add("MODEL_PROTOCOL_GATE"); response = None; valid = False
            else:
                require(outcome["status"] in ("FAILED", "UNKNOWN"), "OUTCOME_ENUM")
                codes.add("EVIDENCE_UNAVAILABLE" if outcome["status"] == "UNKNOWN" else "TRANSPORT_GATE")
            if sid is not None:
                selected[sid] = (attempt, outcome, outcome_ref, response, valid)
                observations[(sid,"ATTEMPT")], references[(sid,"ATTEMPT")] = attempt, attempt_ref
                observations[(sid,"OUTCOME")], references[(sid,"OUTCOME")] = outcome, outcome_ref
            rows.append({"attempt_id": attempt["attempt_id"], "phase": attempt["phase"], "outcome": outcome["status"],
                         "original_attempt_receipt": attempt_ref, "original_outcome_receipt": outcome_ref})
        assertions = []
        for assertion in plan["assertions"]:
            status, anchor = self._assertion(assertion, observations, references)
            assertions.append({"assertion_id": assertion["assertion_id"], "outcome": status, "independent_evidence_receipt": anchor})
            if status == "FAIL": codes.add("MANDATORY_CHECK_FAILED")
        assertion_status = {a["assertion_id"]: a["outcome"] for a in assertions}
        steps = []
        for expected in plan["steps"]:
            sid = expected["step_id"]
            if sid not in selected:
                steps.append({"step_id":sid,"attempt_id":None,"outcome":"INCOMPLETE","independent_evidence_receipt":None}); continue
            attempt, outcome, anchor, response, valid = selected[sid]
            status = "INCOMPLETE" if outcome["status"] == "UNKNOWN" else "FAIL"
            if outcome["status"] == "COMPLETE" and valid and response is not None:
                status = self._step(expected, attempt, response, observations)
            checks = [assertion_status[a] for a in expected["assertion_ids"]]
            if status == "PASS" and "FAIL" in checks: status = "FAIL"
            if status == "PASS" and "INCOMPLETE" in checks: status = "INCOMPLETE"
            if status == "FAIL": codes.add("MANDATORY_CHECK_FAILED")
            steps.append({"step_id":sid,"attempt_id":attempt["attempt_id"],"outcome":status,"independent_evidence_receipt":anchor})
        result = {"format":"forex.independent-terminal-score/2","run_id":bundle["binding"]["run_id"],"epoch":bundle["binding"]["epoch"],
            "lifecycle":finalization["lifecycle"],"source_freeze_manifest_sha256":bundle["binding"]["source_manifest_sha256"],
            "custody_public_manifest_sha256":self.custody_pin,"retained_evaluation_bundle_sha256":self.bundle_use["reference"]["sha256"],
            "accepted_private_mapping_sha256":self.mapping_pin,"mandatory_step_ids":step_ids,"mandatory_assertion_ids":assertion_ids,
            "steps":steps,"assertions":assertions,"generation_attempts":rows,"broad_failure_codes":sorted(codes)}
        fresh(self.clock, self.guard, now, self.deadline)
        return protected.validate("TerminalScore2", result).payload()

    @staticmethod
    def _step(expected, attempt, response, facts):
        action, sid = response["selected_action_ref"], expected["step_id"]
        if not any(same(action, permitted) for permitted in expected["permissible_action_refs"]): return "FAIL"
        if (expected["required_disposition"] == "ACT") != (action is not None): return "FAIL"
        if not set(expected["required_evidence_ids"]) <= set(response["evidence_ids"]): return "FAIL"
        if (sid,"PRE_STATE") not in facts or (sid,"POST_STATE") not in facts: return "INCOMPLETE"
        checks = [_project(facts[(sid,"PRE_STATE")],expected["expected_pre"]), _project(facts[(sid,"POST_STATE")],expected["expected_post"])]
        if False in checks: return "FAIL"
        if None in checks: return "INCOMPLETE"
        auth, dispatch, effect = [facts.get((sid,k)) for k in ("AUTHORIZATION","DISPATCH","VENUE_EFFECT")]
        if expected["requires_dispatch"]:
            if auth is None or dispatch is None: return "INCOMPLETE"
            if not (auth.get("attempt_id") == dispatch.get("attempt_id") == attempt["attempt_id"] and auth.get("selected_action_ref") == dispatch.get("selected_action_ref") == action
                    and type(auth.get("command_id")) is str and auth["command_id"] and auth.get("command_id") == dispatch.get("command_id")
                    and type(auth.get("authorization_id")) is str and auth["authorization_id"]
                    and type(auth.get("reservation_id")) is str and auth["reservation_id"]): return "FAIL"
        elif auth is not None or dispatch is not None: return "FAIL"
        if expected["requires_venue_effect"]:
            if effect is None or dispatch is None: return "INCOMPLETE"
            if not (effect.get("command_id") == dispatch.get("command_id") and effect.get("attempt_id") == attempt["attempt_id"]
                    and type(effect.get("receipt_id")) is str and effect["receipt_id"] and type(effect.get("observation_id")) is str and effect["observation_id"]): return "FAIL"
        elif effect is not None: return "FAIL"
        return "PASS"

    @staticmethod
    def _assertion(assertion, facts, references):
        values, anchor = [], None
        for operand in assertion["operands"]:
            key=(operand["step_id"],operand["kind"])
            if key not in facts: return "INCOMPLETE",None
            anchor=anchor or references[key]; value=facts[key]
            for field in operand["path"]:
                if type(value) is not dict or field not in value: return "INCOMPLETE",anchor
                value=value[field]
            values.append(value)
        operator=assertion["operator"]
        if operator=="EQUALS": require(len(values)==1,"PREDICATE_ARITY"); passed=same(values[0],assertion["expected"])
        elif operator=="EQUAL_FIELDS": require(len(values)==2,"PREDICATE_ARITY"); passed=same(values[0],values[1])
        elif operator=="ORDERED_TIMES":
            require(len(values)>=2,"PREDICATE_ARITY"); passed=all(common.utc(a)<common.utc(b) for a,b in zip(values,values[1:]))
        elif operator=="STRICT_INCREASE":
            require(len(values)>=2 and all(type(v) in (str,int) for v in values),"PREDICATE_ARITY")
            try:
                numbers=[Decimal(v) for v in values]
                passed=all(v.is_finite() for v in numbers) and all(a<b for a,b in zip(numbers,numbers[1:]))
            except InvalidOperation: passed=False
        else: raise common.DependencyUnavailable("predicate")
        return ("PASS" if passed else "FAIL"),anchor
