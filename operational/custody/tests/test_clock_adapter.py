"""Original clock migration and bounded arithmetic, authored NOT_RUN.

All dates and content here are public synthetic unit fixtures, not a live window.
"""
import copy
import unittest
from datetime import datetime, timedelta, timezone
from cas_forex_operational_contracts import common
from custody_runtime.gate_adapters import CLOCK_FORMAT, OriginalClockGate, OriginalClockSchema, original_clock_bytes
from public_fixtures import fixture_selection, stamp


def utc(seconds):
    return (datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def original():
    return {"model_window":{"started_at":utc(7200),"deadline":utc(12600),
        "total_generation_limit":32,"probe_limit":2,"acceptance_limit":30,
        "includes":["startup","render","tokenize","probes","acceptance","export","shutdown"]},
        "model_calls":32,"retry_calls":0,"bootstrap_started_utc":utc(100),"test_deadline_utc":utc(7300)}


class OriginalClockAdapterTests(unittest.TestCase):
    def check(self, value, **overrides):
        args={"work_started_utc":utc(0),"work_deadline_utc":utc(13200),"completed_at_utc":utc(7000),"now_utc":utc(7500)}
        args.update(overrides)
        OriginalClockGate.check_global(common.canonical_bytes(value),**args)

    def test_tagged_record_retains_original_content_identity(self):
        value=original();raw=common.canonical_bytes(value);tagged=common.canonical_bytes({**value,"format":CLOCK_FORMAT})
        self.assertEqual(original_clock_bytes(tagged),raw)
        self.assertNotEqual(common.digest(tagged),common.digest(raw))

    def test_successor_schema_requires_explicit_tag(self):
        with self.assertRaises(common.ContractError):OriginalClockSchema("1"*64).decode(common.canonical_bytes(original()))

    def test_successor_schema_validates_original_fields(self):
        tagged={**original(),"format":CLOCK_FORMAT};route=OriginalClockSchema("1"*64)
        self.assertEqual(route.decode(common.canonical_bytes(tagged)),tagged)

    def test_unknown_successor_format_is_rejected(self):
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes({**original(),"format":"forex.unselected/1"}))

    def test_added_verified_flag_is_not_accepted(self):
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes({**original(),"verified":True}))

    def test_retries_are_not_hidden_inside_32_calls(self):
        value=original();value["retry_calls"]=1
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes(value))

    def test_boolean_zero_is_not_retry_budget(self):
        value=original();value["retry_calls"]=False
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes(value))

    def test_probe_and_mandatory_split_cannot_change(self):
        value=original();value["model_window"].update(probe_limit=3,acceptance_limit=29)
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes(value))

    def test_original_window_timestamp_text_is_not_rewritten(self):
        value=original();value["model_window"]["started_at"]="2030-01-01T02:00:00+00:00"
        raw=common.canonical_bytes(value)
        self.assertEqual(original_clock_bytes(common.canonical_bytes({**value,"format":CLOCK_FORMAT})),raw)
        self.check(value)

    def test_non_utc_window_is_rejected(self):
        value=original();value["model_window"]["started_at"]="2030-01-01T02:00:00+01:00"
        with self.assertRaises(common.ContractError):original_clock_bytes(common.canonical_bytes(value))

    def test_full_original_window_and_completion_fit(self):
        self.check(original())

    def test_global_deadline_may_shorten_model_window(self):
        value=original();value["model_window"].update(started_at=utc(9000),deadline=utc(13200))
        self.check(value,now_utc=utc(10000))

    def test_arbitrary_shorter_window_is_not_the_original_minimum(self):
        value=original();value["model_window"]["deadline"]=utc(12500)
        with self.assertRaises(common.ContractError):self.check(value)

    def test_global_deadline_cannot_be_extended(self):
        with self.assertRaises(common.ContractError):self.check(original(),work_deadline_utc=utc(13201))

    def test_completion_after_model_start_is_rejected(self):
        with self.assertRaises(common.ContractError):self.check(original(),completed_at_utc=utc(7250))

    def test_current_time_at_original_deadline_is_rejected(self):
        with self.assertRaises(common.ContractError):self.check(original(),now_utc=utc(12600))

    def test_test_deadline_over_120_minutes_is_rejected(self):
        value=original();value["test_deadline_utc"]=utc(7301)
        with self.assertRaises(common.ContractError):self.check(value)

    def test_selected_schema_pin_mismatch_is_rejected(self):
        _,authority,_=fixture_selection();authority.schemas={"1"*64:OriginalClockSchema("2"*64)}
        with self.assertRaises(common.ContractError):authority.validate_payload(common.canonical_bytes({**original(),"format":CLOCK_FORMAT}),{"payload_schema_sha256":"1"*64})

    def test_gate_cannot_appoint_original_from_proposed_record(self):
        publishers,_,_=fixture_selection();value=original()
        subject=OriginalClockGate(original_clock_raw=common.canonical_bytes(value),work_started_utc=utc(0),work_deadline_utc=utc(13200),
            component_sha256="1"*64,resolver=None,publishers=publishers,clock=lambda:stamp(100),
            current_authority_guard=lambda now:None,original_deadline=stamp(180))
        changed=copy.deepcopy(value);changed["model_window"]["started_at"]=utc(7201)
        with self.assertRaises(common.ContractError):subject.verify(record=common.canonical_bytes({**changed,"format":CLOCK_FORMAT}),
            selection=b"{}",dependencies=(),component_sha256="1"*64,now=stamp(90))
