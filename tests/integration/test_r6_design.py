"""Public design fixtures only; all authored tests NOT_RUN. No hidden cases."""
import unittest
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.r6_design import (
    R6_DESIGN, require_r6_evaluator_readiness, validate_recovered_design,
)


def public_definitions():
    return {'schema': 'forex.r6-obligations/2', 'obligations': [
        {'obligation_id': 'local-' + ident, 'definition': text}
        for ident, text in R6_DESIGN
    ]}


class RecoveredR6Tests(unittest.TestCase):
    def test_all_recovered_clauses_bind_to_local_ids(self):
        result = validate_recovered_design(public_definitions())
        self.assertEqual(set(result.values()), {ident for ident, _ in R6_DESIGN})

    def test_source_order_is_not_an_answer_key(self):
        value = public_definitions()
        value['obligations'].reverse()
        self.assertEqual(validate_recovered_design(value), validate_recovered_design(public_definitions()))

    def test_original_terminal_conjunction_is_accepted(self):
        value = public_definitions()
        value['obligations'][-1]['definition'] = 'and ' + value['obligations'][-1]['definition'] + '.'
        self.assertEqual(validate_recovered_design(value)['local-R6-08'], 'R6-08')

    def test_replacement_task_cannot_claim_recovered_design(self):
        value = public_definitions()
        value['obligations'][0]['definition'] = 'maximize profit'
        with self.assertRaises(ContractError):
            validate_recovered_design(value)

    def test_duplicate_clause_cannot_hide_missing_obligation(self):
        value = public_definitions()
        value['obligations'][0]['definition'] = value['obligations'][1]['definition']
        with self.assertRaises(ContractError):
            validate_recovered_design(value)

    def test_stage_names_cannot_replace_strategy_a_and_b(self):
        value = public_definitions()
        value['obligations'][0]['definition'] = 'complete Stage A'
        with self.assertRaises(ContractError):
            validate_recovered_design(value)

    def test_missing_clause_cannot_reduce_denominator(self):
        value = public_definitions()
        value['obligations'].pop()
        with self.assertRaises(ContractError):
            validate_recovered_design(value)

    def test_known_source_gaps_block_generation(self):
        with self.assertRaisesRegex(ContractError, 'R6_EVALUATOR_SOURCE_INCOMPLETE'):
            require_r6_evaluator_readiness()

    def test_explicit_public_custodian_wording_and_format_bind(self):
        value = public_definitions()
        value['format'] = value.pop('schema')
        value['obligations'][1]['definition'] = 'Select materially different strategy/timeframe B after a relevant change.'
        value['obligations'][2]['definition'] = 'Wait when no strategy is eligible.'
        value['obligations'][3]['definition'] = 'Stand down when safety facts are missing.'
        value['obligations'][4]['definition'] = 'Hold a valid existing position.'
        value['obligations'][5]['definition'] = 'Modify protection after changed context.'
        self.assertEqual(validate_recovered_design(value), validate_recovered_design(public_definitions()))

    def test_conflicting_schema_and_format_are_rejected(self):
        value = public_definitions(); value['format'] = 'forex.r6-obligations/1'
        with self.assertRaises(ContractError): validate_recovered_design(value)

    def test_unreviewed_semantic_paraphrase_is_not_guessed(self):
        value = public_definitions(); value['obligations'][7]['definition'] = 'Accept broader trading authority if profitable.'
        with self.assertRaises(ContractError): validate_recovered_design(value)
