"""Development negative scoring regressions. AUTHORED/NOT_RUN."""
from copy import deepcopy
import unittest
from cas_forex_revamp.contracts import ContractError,content_digest
from cas_forex_revamp.composition.r6_reason import semantic_result
from cas_forex_revamp.composition.r6_scoring import status,expected_state_checks,score_suite,GLOBALS


class R6ScoringTests(unittest.TestCase):
    def test_fail_cannot_be_averaged_away(self):self.assertEqual(status({'a':True,'b':False,'c':None}),'FAIL')
    def test_missing_evidence_is_incomplete(self):self.assertEqual(status({'a':True,'b':None}),'INCOMPLETE')
    def test_payload_pass_label_is_not_boolean(self):
        with self.assertRaises(ContractError):status({'a':'PASS'})
    def test_no_checks_cannot_pass(self):
        with self.assertRaises(ContractError):status({})

    def semantic(self):
        a={k:{} for k in ('request','result','current_view','context_before','policy_before','observed_before')}
        a.update(inference_source_sha256='a'*64,inference_receipt_id='test',selected_action_ref=None)
        subject={k:a[k] for k in ('request','result','current_view','context_before','policy_before','observed_before','inference_source_sha256')}
        r=dict(reviewer_id='independent',subject_sha256=content_digest(subject),inference_receipt_id='test',selected_action_ref=None,
            disposition='HOLD',reason_supported_by_current_evidence=True,envelope_expansion_refused=False,
            none_eligible_from_current_policy_and_facts=False,review_evidence_sha256='b'*64)
        return a,r

    def test_bound_semantic_review_accepted(self):
        a,r=self.semantic();self.assertEqual(semantic_result(a,r,trusted_reviewer_id='independent'),r)
    def test_changed_reason_cannot_reuse_review(self):
        a,r=self.semantic();a['result']['reason']='changed';self.assertIsNone(semantic_result(a,r,trusted_reviewer_id='independent'))
    def test_imported_reviewer_label_cannot_appoint_trust(self):
        a,r=self.semantic();self.assertIsNone(semantic_result(a,r,trusted_reviewer_id=None))
    def test_semantic_truthy_string_is_not_evidence(self):
        a,r=self.semantic();r['none_eligible_from_current_policy_and_facts']='yes'
        self.assertIsNone(semantic_result(a,r,trusted_reviewer_id='independent'))

    def state(self):
        expected=dict(open_quantity='0',balance='999',position_version=3,side='BUY',stop_price='1',receipt_effect='FILLED',decision_outcome='ACT')
        a=dict(actual_after=dict(open_quantity='0',realized_balance='999',position_version=3,side='BUY',stop='1',terminal_record_available=True),
            observed_after={},selected_action_ref='dev',effect='FILLED',stale_rejected=False)
        return expected,a
    def test_ack_is_not_expected_fill(self):
        e,a=self.state();a['effect']='ACKNOWLEDGED'
        self.assertFalse(expected_state_checks(e,a,before=False,disposition='ACT',previous=None)['receipt_effect'])
    def test_missing_terminal_record_cannot_be_inferred_from_empty_inventory(self):
        e,a=self.state();a['actual_after']['terminal_record_available']=False
        self.assertFalse(expected_state_checks(e,a,before=False,disposition='ACT',previous=None)['retained_terminal_record'])
    def test_changed_balance_fails_exact_expected_state(self):
        e,a=self.state();a['actual_after']['realized_balance']='998.99'
        self.assertFalse(expected_state_checks(e,a,before=False,disposition='ACT',previous=None)['balance'])
    def test_absent_expected_pre_is_not_computed(self):
        self.assertEqual(expected_state_checks(None,{},before=True,disposition=None,previous=None),{'standalone_numerical_prestate_not_authored':True})
    def test_unknown_global_predicate_blocks(self):
        with self.assertRaises(ContractError):score_suite({'schema':'forex.model-suite/2'},{'global_assertions':['invented']},[],verify_attempt=lambda _:True)
