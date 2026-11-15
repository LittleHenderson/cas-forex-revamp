"""Public source-only clock branch regression source. NOT_RUN."""
import unittest
from cas_forex_operational_contracts import common
from custody_runtime.source_test_clock import source_test_clock_bytes, completion_clock_bytes, SourceTestClockSchema
from custody_runtime.gate_adapters import original_clock_bytes


def source_clock():
    return {'format':'forex.original-source-test-clock/1','bootstrap_started_utc':'2030-01-01T00:00:00.000000Z',
            'test_deadline_utc':'2030-01-01T02:00:00.000000Z'}


class SourceClockSuccessorTests(unittest.TestCase):
    def test_source_clock_hash_includes_original_tag(self):
        raw=common.canonical_bytes(source_clock());self.assertEqual(source_test_clock_bytes(raw),raw)
        self.assertEqual(completion_clock_bytes(raw),raw)

    def test_schema_returns_detached_exact_body(self):
        value=source_clock();self.assertEqual(SourceTestClockSchema('1'*64).decode(common.canonical_bytes(value)),value)

    def test_source_clock_cannot_smuggle_model_budget(self):
        value=source_clock();value['model_calls']=32
        with self.assertRaises(common.ContractError):source_test_clock_bytes(common.canonical_bytes(value))

    def test_zero_model_budget_field_also_not_in_contract(self):
        value=source_clock();value['model_calls']=0
        with self.assertRaises(common.ContractError):source_test_clock_bytes(common.canonical_bytes(value))

    def test_deadline_cannot_equal_bootstrap(self):
        value=source_clock();value['test_deadline_utc']=value['bootstrap_started_utc']
        with self.assertRaises(common.ContractError):source_test_clock_bytes(common.canonical_bytes(value))

    def test_deadline_cannot_exceed_original_two_hours(self):
        value=source_clock();value['test_deadline_utc']='2030-01-01T02:00:00.000001Z'
        with self.assertRaises(common.ContractError):source_test_clock_bytes(common.canonical_bytes(value))

    def test_source_clock_is_not_accepted_by_unchanged_model_clock_parser(self):
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes(source_clock()))

    def test_historical_original_record_keeps_identity(self):
        value={'model_calls':32,'retry_calls':0,'bootstrap_started_utc':'2030-01-01T00:00:00.000000Z',
            'test_deadline_utc':'2030-01-01T02:00:00.000000Z','model_window':{'started_at':'2030-01-01T02:00:00+00:00',
            'deadline':'2030-01-01T03:30:00+00:00','total_generation_limit':32,'probe_limit':2,'acceptance_limit':30,
            'includes':['startup','render','tokenize','probes','acceptance','export','shutdown']}}
        raw=common.canonical_bytes(value);self.assertEqual(completion_clock_bytes(raw),original_clock_bytes(raw))

    def test_unknown_format_is_not_source_clock(self):
        value=source_clock();value['format']='forex.original-source-test-clock/2'
        with self.assertRaises(common.ContractError):completion_clock_bytes(common.canonical_bytes(value))
