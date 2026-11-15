"""AUTHORED/NOT_RUN. Visible fake fixtures test software, never sealed/model evidence."""
import copy
import unittest
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.model_suite import validate_suite, validate_keys, validate_obligations, score_suite


def visible_fixture():
    obligations = ['obligation-'+str(i) for i in range(8)]
    suite = dict(schema='forex.model-suite/1', purpose='SEALED_B_ACCEPTANCE',
        r6_definition_sha256='d'*64, obligations=obligations, trajectories=[])
    keys = dict(schema='forex.model-keys/1', steps=[])
    definitions = dict(schema='forex.r6-obligations/1', obligations=[dict(obligation_id=o,
        definition='Visible software fixture only', assertions=['fixture-choice']) for o in obligations])
    attempts = []
    for i in range(16):
        case = dict(case_id=f'{i:032x}', obligation_id=obligations[i//2], wording='AB'[i%2],
                    continuous_required=i < 2, initial_market={'bid': '1.1', 'ask': '1.1002'}, steps=[])
        for j in range(4 if i < 2 else 1):
            sid = f'{i*8+j:024x}'
            options = [dict(action_ref=f'{1000+i*8+j*2+k:024x}', strategy_id='strategy-'+str(k),
                timeframe=('M5','H1')[k], label='Visible fake alternative', kind='OPEN', side='BUY',
                quantity='10', limit_price='1.1002', stop_price='1.09') for k in range(2)]
            step = dict(step_id=sid, options=options, facts=[{'label': 'Toy fact', 'value': 'visible fixture'}],
                invalidate_while_pending=i<2 and j==1, market_before={'bid': '1.1','ask':'1.1002'}, market_after=[])
            case['steps'].append(step)
            keys['steps'].append(dict(case_id=case['case_id'], step_id=sid, permissible_action_refs=[None],
                required_evidence_ids=[], must_change_venue=False, required_effect=None, required_action_kind=None,
                obligation_assertions={'fixture-choice': 'model_choice'}))
            kind = ('OPEN', 'WAIT', 'REDUCE', 'CLOSE')[j] if i<2 else 'WAIT'
            attempts.append(dict(case_id=case['case_id'], step_id=sid, actual_receipt_verified=True,
                selected_action_ref=None, evidence_ids=[], stale_rejected=step['invalidate_while_pending'],
                error_type='StaleDecision' if step['invalidate_while_pending'] else None,
                venue_changed=kind!='WAIT', action_kind=kind, effect='FILLED' if kind!='WAIT' else None,
                position_id='position-'+str(i), positions_after=0 if kind=='CLOSE' else 1,
                position_quantity_after='0' if kind=='CLOSE' else '6' if kind=='REDUCE' else '10',
                request_state_sha256=sid))
        suite['trajectories'].append(case)
    review = dict(suite_sha256='a'*64, keys_sha256='b'*64, r6_definition_sha256='d'*64,
        independent_reviewer_id='VISIBLE_FAKE_UNIT_FIXTURE', counterpart_semantics_checked=True,
        answer_leakage_checked=True, material_options_checked=True, causal_facts_checked=True, planned_calls=22)
    exposure = dict(suite_sha256='a'*64, previous_generation_attempts=0, development_exposure=False)
    return suite, keys, definitions, review, exposure, attempts


class ModelAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.suite, self.keys, self.defs, self.review, self.exposure, self.attempts = visible_fixture()

    def validate(self):
        return validate_suite(self.suite, self.review, self.exposure, suite_sha256='a'*64, keys_sha256='b'*64)

    def test_visible_fixture_coverage_fits_fixed_calls(self):
        self.assertEqual(self.validate(), 22)

    def test_missing_trajectory_cannot_reduce_denominator(self):
        self.suite['trajectories'].pop()
        with self.assertRaises(ContractError): self.validate()

    def test_development_label_rejected(self):
        self.suite['purpose']='DEVELOPMENT'
        with self.assertRaises(ContractError): self.validate()

    def test_previous_generation_consumes_seal(self):
        self.exposure['previous_generation_attempts']=1
        with self.assertRaises(ContractError): self.validate()

    def test_false_is_not_zero_attempt_count(self):
        self.exposure['previous_generation_attempts']=False
        with self.assertRaises(ContractError): self.validate()

    def test_reviewer_counterpart_check_required(self):
        self.review['counterpart_semantics_checked']=False
        with self.assertRaises(ContractError): self.validate()

    def test_repeated_request_identity_across_cases_rejected(self):
        self.suite['trajectories'][1]['steps'][0]['step_id']=self.suite['trajectories'][0]['steps'][0]['step_id']
        with self.assertRaises(ContractError): self.validate()

    def test_answer_field_in_model_input_rejected(self):
        self.suite['trajectories'][0]['steps'][0]['answer_key']='first'
        with self.assertRaises(ContractError): self.validate()

    def test_one_strategy_disguised_as_two_options_rejected(self):
        options=self.suite['trajectories'][0]['steps'][0]['options']
        options[1]['strategy_id']=options[0]['strategy_id']; options[1]['timeframe']=options[0]['timeframe']
        with self.assertRaises(ContractError): self.validate()

    def test_unknown_key_condition_is_not_success(self):
        self.keys['steps'][0]['obligation_assertions']['profit']='profitable'
        with self.assertRaises(ContractError): validate_keys(self.suite,self.keys)

    def test_missing_keys_block_scoring(self):
        self.keys['steps'].pop()
        with self.assertRaises(ContractError): score_suite(self.suite,self.keys,self.attempts)

    def test_missing_required_assertion_mapping_blocks(self):
        self.defs['obligations'][0]['assertions'].append('unimplemented-obligation')
        with self.assertRaises(ContractError): validate_obligations(self.suite,self.keys,self.defs)

    def test_complete_visible_fake_output_scores_logic_only(self):
        self.assertTrue(validate_obligations(self.suite,self.keys,self.defs))
        result=score_suite(self.suite,self.keys,self.attempts)
        self.assertEqual(result['status'],'PASS'); self.assertFalse(result['profit_or_learning_claim'])
        self.assertIn('NOT_RUN',result['u0']); self.assertIn('NOT_RUN',result['u1'])

    def test_exhausted_run_is_incomplete_with_full_denominator(self):
        result=score_suite(self.suite,self.keys,self.attempts[:-1])
        self.assertEqual(result['status'],'INCOMPLETE'); self.assertEqual(len(result['trajectories']),16)

    def test_guard_rejection_does_not_count_as_model_success(self):
        self.attempts[0]['error_type']='AdmissionDenied'
        self.assertEqual(score_suite(self.suite,self.keys,self.attempts)['status'],'FAIL')

    def test_fabricated_label_without_verified_receipt_fails(self):
        self.attempts[0]['actual_receipt_verified']=False
        self.assertEqual(score_suite(self.suite,self.keys,self.attempts)['status'],'FAIL')

    def test_pending_response_without_actual_stale_rejection_fails(self):
        self.attempts[1]['stale_rejected']=False
        self.assertEqual(score_suite(self.suite,self.keys,self.attempts)['status'],'FAIL')

    def test_ack_is_not_continuous_fill(self):
        self.attempts[0]['effect']='ACKNOWLEDGED'
        self.assertEqual(score_suite(self.suite,self.keys,self.attempts)['status'],'FAIL')

    def test_unrelated_position_exit_is_not_continuity(self):
        self.attempts[3]['position_id']='unrelated'
        self.assertEqual(score_suite(self.suite,self.keys,self.attempts)['status'],'FAIL')

    def test_full_exit_mislabeled_as_partial_reduction_fails(self):
        self.attempts[2]['position_quantity_after']='0'
        self.assertEqual(score_suite(self.suite,self.keys,self.attempts)['status'],'FAIL')

    def test_repaired_second_answer_cannot_replace_first(self):
        with self.assertRaises(ContractError): score_suite(self.suite,self.keys,self.attempts+[copy.deepcopy(self.attempts[0])])
