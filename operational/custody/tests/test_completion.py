"""Public parser and completion boundary regressions; NOT_RUN."""
import copy
import unittest
from cas_forex_operational_contracts import common, completion
from custody_runtime.completion_verifier import FrameworkParser, CompletionVerifier
from public_fixtures import packet, stamp, completion_selection


def parser_fixture(mode="NODE_TAP"):
    parser={"component_manifest_sha256":"1"*64,"entrypoint":"custody-strict-framework-v1","mode":mode,
            "maximum_report_bytes":1048576,"maximum_stream_bytes":524288,
            "expected_stdout_utf8":None,"expected_stderr_utf8":None}
    counts={"discovered":1,"ran":1,"passed":1,"skipped":0,"failures":0,"errors":0,"cancelled":0,"todo":0}
    report={"format":"forex.node-tap-report/1","group_id":"ui","collected_test_ids":["public-unit"],
            "test_results":[{"test_id":"public-unit","result":"PASS"}],"counts":counts,"complete":True}
    stdout="TAP version 13\nok 1 - public-unit\n1..1\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"
    return parser,report,stdout


class CompletionTests(unittest.TestCase):
    def parse(self,parser,report,stdout,stderr=""):
        return FrameworkParser(component_sha256="1"*64).parse(parser,stdout=stdout,stderr=stderr,
            framework_raw=common.canonical_bytes(report),group_id="ui")

    def test_flat_tap_reparsed_from_raw_stream(self):
        parser,report,stdout=parser_fixture()
        self.assertEqual(self.parse(parser,report,stdout),report)

    def test_framework_pass_does_not_hide_raw_failure(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout.replace("ok 1","not ok 1"))

    def test_framework_cannot_replace_test_id(self):
        parser,report,stdout=parser_fixture();report["test_results"][0]["test_id"]="replacement"
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout)

    def test_nested_tap_fails_closed(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,"    ok 1 - hidden\n"+stdout)

    def test_duplicate_plan_fails_closed(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout+"1..1\n")

    def test_bailout_fails_closed(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout+"Bail out! public error\n")

    def test_malformed_negative_result_is_not_ignored(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout+"not ok invalid\n")

    def test_skip_directive_fails_closed(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout.replace("public-unit","public-unit # SKIP"))

    def test_duplicate_summary_fails_closed(self):
        parser,report,stdout=parser_fixture()
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout+"# tests 1\n")

    def test_changed_parser_component_fails_closed(self):
        parser,report,stdout=parser_fixture();parser["component_manifest_sha256"]="2"*64
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout)

    def test_exact_stderr_includes_whitespace(self):
        parser,report,stdout=parser_fixture();parser["expected_stderr_utf8"]=""
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout,"\n")

    def test_stream_overflow_fails_closed(self):
        parser,report,stdout=parser_fixture();parser["maximum_stream_bytes"]=1
        with self.assertRaises(common.ContractError): self.parse(parser,report,stdout)

    def test_duplicate_discovery_identifier_fails_closed(self):
        with self.assertRaises(common.ContractError): CompletionVerifier._ids(["public-id","public-id"])

    def test_discovery_order_is_not_a_denominator_change(self):
        self.assertEqual(CompletionVerifier._ids(["public-b","public-a"]),["public-a","public-b"])

    def test_thirteen_group_selection_cannot_drop_group(self):
        selected=completion_selection()
        completion.validate("CompletionSelection2",selected)
        selected["groups"].pop()
        with self.assertRaises(common.ContractError): completion.validate("CompletionSelection2",selected)

    def test_same_test_process_cannot_relabel_lost_event(self):
        example=packet();selected=completion_selection()
        process=example["controller_fresh_read_request"]["body"]["consumption_binding"]["controller_process"]
        body={"format":"forex.test-process-capture/2","binding":selected["binding"],"selection_sha256":"1"*64,
            "group_id":"contracts","command_sha256":"2"*64,"executable_sha256":"3"*64,"events":[
                {"sequence":1,"kind":"SPAWN","process":process,"at_utc":stamp(1)["utc"],"exit_code":None},
                {"sequence":2,"kind":"EXIT","process":process,"at_utc":stamp(2)["utc"],"exit_code":0}],
            "lost_events":0,"stdout_ref":selected["original_clock_ref"],"stderr_ref":selected["original_clock_ref"]}
        completion.validate("ProcessCapture2",body)
        body["lost_events"]=1
        with self.assertRaises(common.ContractError): completion.validate("ProcessCapture2",body)
