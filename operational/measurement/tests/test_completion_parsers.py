"""Frozen parser regressions, authored only. No application tests have run."""
import unittest
from cas_forex_operational_contracts.common import ContractError,canonical_bytes
from cas_forex_measurement.completion import parse_flat_tap,parse_python,python_framework_report

TAP=b'''TAP version 13
# Subtest: alpha
ok 1 - alpha
  ---
  duration_ms: 1.25
  ...
1..1
# tests 1
# suites 0
# pass 1
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 4.2
'''

class CompletionParserTests(unittest.TestCase):
    def test_flat_tap_preserves_observed_name(self):
        self.assertEqual(parse_flat_tap(TAP)['collected_test_ids'],['alpha'])
    def test_tap_count_mismatch_rejected(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP.replace(b'# pass 1',b'# pass 2'))
    def test_tap_incomplete_plan_rejected(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP.replace(b'1..1',b'1..2'))
    def test_tap_result_name_mismatch_rejected(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP.replace(b'ok 1 - alpha',b'ok 1 - beta'))
    def test_tap_nested_case_is_unavailable(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP.replace(b'ok 1 - alpha',b'    # Subtest: hidden\nok 1 - alpha'))
    def test_tap_duplicate_count_rejected(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP+b'# pass 1\n')
    def test_tap_unterminated_diagnostic_rejected(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP.replace(b'  ...\n',b''))
    def test_tap_unknown_tail_rejected(self):
        with self.assertRaises(ContractError):parse_flat_tap(TAP+b'success\n')
    def test_tap_invalid_utf8_rejected(self):
        with self.assertRaises(UnicodeDecodeError):parse_flat_tap(TAP+b'\xff')
    def test_python_group_substitution_rejected(self):
        report={'format':'forex.python-framework-report/2','group_id':'operator','collected_test_ids':['public.Case.test_one'],
            'executed_test_ids':['public.Case.test_one'],'counts':dict(discovered=1,ran=1,passed=1,skipped=0,failures=0,errors=0,cancelled=0,todo=0),'status':'PASS'}
        with self.assertRaises(ContractError):parse_python(canonical_bytes(report),group_id='core')
    def test_framework_records_actual_failure(self):
        class PublicFail(unittest.TestCase):
            def runTest(self):self.fail('public unit negative control')
        observed=python_framework_report(unittest.TestSuite([PublicFail()]),group_id='operational-measurement')
        self.assertEqual((observed['status'],observed['counts']['failures']),('FAIL',1))
        self.assertEqual(observed['collected_test_ids'],observed['executed_test_ids'])
