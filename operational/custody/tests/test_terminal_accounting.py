"""Synthetic unit records only; not the sealed R6 suite. NOT_RUN.

Memory authentication and private-shape callbacks below are deliberate mocks.
Their positive results test scoring arithmetic only and establish no authority.
"""
import json
import unittest
from cas_forex_operational_contracts import common
from custody_runtime.fact_assembler import FactAssembler
from custody_runtime.terminal_scorer import TerminalScorer
from public_fixtures import packet, stamp


def scoring_fixture(*, bad_probe=False, outcome_status="COMPLETE", wrong_last_state=False, omit_last_outcome=False):
    binding=packet()["release_receipt"]["binding"]
    storage={}
    def retain(body,kind,purpose,publisher="public-custody"):
        raw=common.canonical_bytes(body);pin=common.digest(raw);storage[pin]=raw
        return {"reference":{"format":"forex.protected-record-ref/1","binding":binding,"publisher_selection_sha256":"1"*64,
            "root_id":"public-unit-root","object_id":pin,"bytes":len(raw),"sha256":pin,"record_kind":kind,
            "publisher_id":publisher,"purpose":purpose},"registration_sha256":"2"*64,"required_use":"RETAINED_EVALUATION"}
    class MemoryResolver:
        def resolve(self,use,**kwargs): return storage[use["reference"]["sha256"]]
    class PublicMockShape:
        def validate(self,**kwargs): return None
    steps=[]; assertions=[]
    for index in range(30):
        sid=f"public-step-{index:02d}";aid=f"public-assertion-{index:02d}"
        steps.append({"step_id":sid,"permissible_action_refs":[None],"required_disposition":"WAIT",
            "expected_pre":{"units":"10"},"expected_post":{"units":"10"},"requires_dispatch":False,
            "requires_venue_effect":False,"required_evidence_ids":[],"assertion_ids":[aid]})
        assertions.append({"assertion_id":aid,"operator":"EQUALS","operands":[{"step_id":sid,"kind":"POST_STATE","path":["units"]}],"expected":"10"})
    plan={"format":"forex.independent-scoring-plan/2","run_id":binding["run_id"],"epoch":binding["epoch"],
          "frozen_at_utc":stamp(1)["utc"],"expected_outcome_author_sha256":"3"*64,"accepted_mapping_sha256":"4"*64,
          "steps":steps,"assertions":assertions}
    plan_use=retain(plan,"SCORING_PLAN","independent-scoring-plan","public-mapper")
    review={"format":"forex.independent-scoring-plan-review/2","plan_sha256":plan_use["reference"]["sha256"],
            "accepted_mapping_sha256":"4"*64,"expected_outcome_author_sha256":"3"*64,"required_step_ids":[s["step_id"] for s in steps],
            "required_assertion_ids":[a["assertion_id"] for a in assertions],"coverage":"ALL_REQUIRED_ASSERTIONS"}
    review_use=retain(review,"SCORING_PLAN_REVIEW","scoring-plan-review","public-reviewer")
    records=[]; attempt_ids=[]
    def fact(kind,sid,payload):
        body={"format":"forex.retained-fact/2","binding":binding,"record_id":f"public-record-{len(records)}",
              "kind":kind,"step_id":sid,"payload_schema_sha256":"5"*64,"payload":payload}
        records.append({"kind":kind,"fact":retain(body,"RETAINED_FACT","retained-"+kind.lower())})
    for index in range(32):
        probe=index<2;sid=None if probe else steps[index-2]["step_id"];start=10+index*3
        aid=f"public-attempt-{index:02d}";attempt_ids.append(aid)
        attempt={"attempt_id":aid,"attempt_index":1,"phase":"PROBE" if probe else "MANDATORY","step_id":sid,
            "original_window_sha256":binding["original_window_sha256"],"model_identity_sha256":"6"*64,"tokenizer_sha256":"7"*64,
            "started_at_utc":stamp(start)["utc"],"input_tokens":100,"generated_token_limit":256 if probe else 512,
            "timeout_seconds":60 if probe else 120,"request_id":f"public-request-{index}","opportunity_set_id":f"public-set-{index}","source_state_id":f"public-state-{index}"}
        response={**{k:attempt[k] for k in ("request_id","opportunity_set_id","source_state_id")},
                  "selected_action_ref":"public-forbidden-probe-action" if bad_probe and index==0 else None,"reason":"Public unit fixture.","evidence_ids":[]}
        text=json.dumps(response,separators=(",",":"))
        status=outcome_status if index==31 else "COMPLETE"
        outcome={"attempt_id":aid,"finished_at_utc":stamp(start+1)["utc"],"input_tokens":100,"generated_tokens":20,
                 "response_utf8":text,"response_raw_sha256":common.digest(text.encode()),"status":status}
        fact("ATTEMPT",sid,attempt)
        if not (omit_last_outcome and index==31): fact("OUTCOME",sid,outcome)
        if not probe:
            fact("PRE_STATE",sid,{"units":"10"})
            fact("POST_STATE",sid,{"units":"9" if wrong_last_state and index==31 else "10"})
    final={"format":"forex.retained-bundle-finalization/2","binding":binding,"lifecycle":"FINAL",
           "records_content_sha256":common.digest(common.canonical_bytes(records,limit=common.MAX_GRAPH)),
           "original_attempt_order":attempt_ids,"terminal_at_utc":stamp(500)["utc"],"broad_failure_codes":[]}
    final_use=retain(final,"BUNDLE_FINALIZATION","retained-bundle-finalization")
    bundle={"format":"forex.retained-attempt-bundle/2","binding":binding,"records":records,"finalization":final_use}
    bundle_use=retain(bundle,"RETAINED_ATTEMPT_BUNDLE","complete-retained-evaluation-bundle")
    assembler=FactAssembler(resolver=MemoryResolver(),publishers={},finalization_use=final_use,shape_validator=PublicMockShape(),
                            clock=lambda:stamp(1000),current_authority_guard=lambda now:None,original_deadline=stamp(1200))
    scorer=TerminalScorer(assembler=assembler,plan_use=plan_use,review_use=review_use,bundle_use=bundle_use,shape_validator=PublicMockShape(),
        accepted_mapping_sha256="4"*64,custody_public_manifest_sha256="8"*64,model_identity_sha256="6"*64,tokenizer_sha256="7"*64,
        model_window={"started_at":stamp(0)["utc"],"deadline":stamp(1100)["utc"]},clock=lambda:stamp(1000),
        current_authority_guard=lambda now:None,original_deadline=stamp(1200))
    return scorer,bundle,final,plan,review


class OriginalAccountingTests(unittest.TestCase):
    def score(self,**options):
        scorer,bundle,final,plan,review=scoring_fixture(**options)
        return scorer.score(bundle,final,plan=plan,review=review,now=stamp(900))

    def test_all_thirty_steps_and_assertions_preserved(self):
        result=self.score()
        self.assertEqual(len(result["steps"]),30);self.assertEqual(len(result["assertions"]),30)
        self.assertTrue(all(s["outcome"]=="PASS" for s in result["steps"]))
        self.assertEqual(len(result["generation_attempts"]),32)

    def test_nonwait_probe_remains_spent_complete_but_invalid(self):
        result=self.score(bad_probe=True)
        self.assertEqual(result["generation_attempts"][0]["outcome"],"COMPLETE")
        self.assertEqual(len(result["generation_attempts"]),32)
        self.assertIn("MODEL_PROTOCOL_GATE",result["broad_failure_codes"])

    def test_original_failed_outcome_is_not_promoted_by_response_text(self):
        result=self.score(outcome_status="FAILED")
        self.assertEqual(result["generation_attempts"][-1]["outcome"],"FAILED")
        self.assertEqual(result["steps"][-1]["outcome"],"FAIL")

    def test_original_unknown_outcome_is_not_erased(self):
        result=self.score(outcome_status="UNKNOWN")
        self.assertEqual(result["generation_attempts"][-1]["outcome"],"UNKNOWN")
        self.assertEqual(result["steps"][-1]["outcome"],"INCOMPLETE")

    def test_last_assertion_failure_is_not_averaged_away(self):
        result=self.score(wrong_last_state=True)
        self.assertEqual(result["assertions"][-1]["outcome"],"FAIL")
        self.assertIn("MANDATORY_CHECK_FAILED",result["broad_failure_codes"])

    def test_missing_original_outcome_blocks_instead_of_shrinking_denominator(self):
        with self.assertRaises(common.ContractError): self.score(omit_last_outcome=True)
