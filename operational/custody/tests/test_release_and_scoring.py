"""Public-only release/scoring boundaries. No private mappings. NOT_RUN."""
import copy
import unittest
from types import SimpleNamespace
from cas_forex_operational_contracts import common, protected, release
from custody_runtime.release_issuer import CurrentReadbacks, ReleaseIssuer, _stat, _status, _latest
from custody_runtime.terminal_scorer import TerminalScorer
from public_fixtures import packet, stamp, journal_row


def current_operation():
    identity=packet()["role_evidence"]["roles"]["controller"]["process"]
    subject={k:identity[k] for k in ("boot_id","pid","start_ticks","parent_pid","uid","gid")}
    operation={"operation_index":7,"kind":"PROC_READ","started":stamp(111),"finished":stamp(112),"data":{"subject":subject}}
    batch={"reporting_origin":"CONTROLLER","evidence_class":"CONTROLLER_OS_READBACK","producer_id":"public-witness",
           "binding":{},"budget_sha256":"1"*64,"subject":subject,"started":stamp(110),"finished":stamp(115),"operations":[operation]}
    class FakeGraph:
        def authenticated(self,*args): return copy.deepcopy(batch)
    current=CurrentReadbacks.__new__(CurrentReadbacks)
    current.graph=FakeGraph(); current.witness="public-witness";current.now=stamp(120)
    current.evidence={"method_binding":{},"setup_budget_sha256":"1"*64,"observed":stamp(116)}
    current.decision={"decided":stamp(100)};current.batches={};current.operations={};current.batch_pairs={};current.process_contexts={}
    use={"operation_kind":"PROC_READ","operation_index":7,"capture":{"object_ref":{"sha256":"2"*64}}}
    return current,use,identity,batch


class CurrentReadbackTests(unittest.TestCase):
    def test_explicit_operation_value_not_array_offset(self):
        current,use,identity,_=current_operation()
        self.assertEqual(current._operation(use,"PROC_READ",identity)["operation_index"],7)

    def test_zero_based_offset_cannot_select_operation(self):
        current,use,identity,_=current_operation();use["operation_index"]=0
        with self.assertRaises(common.ContractError): current._operation(use,"PROC_READ",identity)

    def test_duplicate_explicit_index_rejected(self):
        current,use,identity,batch=current_operation();batch["operations"].append(copy.deepcopy(batch["operations"][0]))
        with self.assertRaises(common.ContractError): current._operation(use,"PROC_READ",identity)

    def test_other_witness_cannot_be_relabelled(self):
        current,use,identity,batch=current_operation();batch["producer_id"]="different-witness"
        with self.assertRaises(common.ContractError): current._operation(use,"PROC_READ",identity)

    def test_predecision_observation_is_not_current(self):
        current,use,identity,batch=current_operation();batch["started"]=stamp(99)
        with self.assertRaises(common.ContractError): current._operation(use,"PROC_READ",identity)

    def test_different_process_start_is_rejected(self):
        current,use,identity,batch=current_operation();identity["start_ticks"]+=1
        with self.assertRaises(common.ContractError): current._operation(use,"PROC_READ",identity)

    def test_wrong_reporting_origin_rejected(self):
        current,use,identity,batch=current_operation();batch["reporting_origin"]="MODEL"
        with self.assertRaises(common.ContractError): current._operation(use,"PROC_READ",identity)

    def test_proc_stat_handles_spaces_and_closing_parenthesis(self):
        raw=("7 (public ) worker) "+" ".join(["S","4"]+["0"]*17+["123"])).encode()
        self.assertEqual(_stat(raw),{"pid":7,"parent_pid":4,"start_ticks":123})

    def test_ambiguous_effective_uid_rejected(self):
        raw=b"Pid:\t7\nPPid:\t4\nUid:\t1 2 1 1\nGid:\t1 1 1 1\nThreads:\t1\n"
        with self.assertRaises(common.ContractError): _status(raw)

    def test_paired_clock_cannot_pick_inconsistent_latest(self):
        with self.assertRaises(common.ContractError): _latest([stamp(100),{**stamp(101),"boottime_ns":99_000_000_000}])

    def test_unused_support_is_not_ignored(self):
        current=CurrentReadbacks.__new__(CurrentReadbacks)
        current.used=set();current.support={"unexpected":None};current.batches={};current.operations={}
        with self.assertRaises(common.ContractError): current.complete()

    def test_unresolved_batch_operation_rejected(self):
        current,use,identity,_=current_operation();current._operation(use,"PROC_READ",identity)
        current.used=set();current.support={};current.operations["2"*64]=set()
        with self.assertRaises(common.ContractError): current.complete()

    def test_no_extra_isolation_claim(self):
        body=packet()["role_evidence"];body["broad_role_read_denial_claimed"]=True
        with self.assertRaises(common.ContractError): release.validate("NarrowRoleReleaseEvidence1",body)

    def test_missing_seventeenth_gate_rejected(self):
        body=packet()["release_selection"];body["release_evidence"].pop()
        with self.assertRaises(common.ContractError): protected.validate("ReleaseSelection3",body)

    def test_duplicate_issuance_identity_cannot_choose_one(self):
        row=journal_row()
        with self.assertRaises(common.ContractError): ReleaseIssuer.__new__(ReleaseIssuer)._original([row,row],row["receipt"]["release_id"])


def step_fixture():
    expected={"step_id":"public-step","permissible_action_refs":["public-a","public-b"],"required_disposition":"ACT",
        "required_evidence_ids":["public-observation"],"expected_pre":{"units":"10"},"expected_post":{"units":"5"},
        "requires_dispatch":True,"requires_venue_effect":True}
    attempt={"attempt_id":"public-attempt"}
    response={"selected_action_ref":"public-a","evidence_ids":["public-observation"]}
    facts={("public-step","PRE_STATE"):{"units":"10"},("public-step","POST_STATE"):{"units":"5"},
           ("public-step","AUTHORIZATION"):{"attempt_id":"public-attempt","selected_action_ref":"public-a","command_id":"public-command","authorization_id":"public-auth","reservation_id":"public-reservation"},
           ("public-step","DISPATCH"):{"attempt_id":"public-attempt","selected_action_ref":"public-a","command_id":"public-command"},
           ("public-step","VENUE_EFFECT"):{"attempt_id":"public-attempt","command_id":"public-command","receipt_id":"public-receipt","observation_id":"public-venue-observation"}}
    return expected,attempt,response,facts


class ScoringTests(unittest.TestCase):
    def test_valid_selection_requires_actual_state_and_effect(self):
        self.assertEqual(TerminalScorer._step(*step_fixture()),"PASS")

    def test_equivalent_permitted_action_is_accepted(self):
        expected,attempt,response,facts=step_fixture();response["selected_action_ref"]="public-b"
        for kind in ("AUTHORIZATION","DISPATCH"):facts[("public-step",kind)]["selected_action_ref"]="public-b"
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"PASS")

    def test_safety_rejection_does_not_pass_required_valid_action(self):
        expected,attempt,response,facts=step_fixture();response["selected_action_ref"]=None
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"FAIL")

    def test_missing_venue_truth_is_incomplete(self):
        expected,attempt,response,facts=step_fixture();facts.pop(("public-step","VENUE_EFFECT"))
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"INCOMPLETE")

    def test_wrong_successive_state_is_failure(self):
        expected,attempt,response,facts=step_fixture();facts[("public-step","POST_STATE")]["units"]="10"
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"FAIL")

    def test_missing_state_field_is_incomplete(self):
        expected,attempt,response,facts=step_fixture();facts[("public-step","POST_STATE")].clear()
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"INCOMPLETE")

    def test_other_attempt_receipt_cannot_establish_effect(self):
        expected,attempt,response,facts=step_fixture();facts[("public-step","VENUE_EFFECT")]["attempt_id"]="other-attempt"
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"FAIL")

    def test_missing_required_observation_cannot_pass(self):
        expected,attempt,response,facts=step_fixture();response["evidence_ids"]=[]
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"FAIL")

    def test_wait_has_no_authorization_or_dispatch(self):
        expected,attempt,response,facts=step_fixture()
        expected.update(permissible_action_refs=[None],required_disposition="WAIT",requires_dispatch=False,requires_venue_effect=False)
        response["selected_action_ref"]=None
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"FAIL")

    def test_wait_with_stable_observed_state_can_pass(self):
        expected,attempt,response,facts=step_fixture()
        expected.update(permissible_action_refs=[None],required_disposition="WAIT",requires_dispatch=False,requires_venue_effect=False)
        response["selected_action_ref"]=None
        expected["expected_post"]={"units":"10"}
        facts[("public-step","POST_STATE")]["units"]="10"
        for kind in ("AUTHORIZATION","DISPATCH","VENUE_EFFECT"):facts.pop(("public-step",kind))
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"PASS")

    def test_missing_command_identity_does_not_pass(self):
        expected,attempt,response,facts=step_fixture()
        for kind in ("AUTHORIZATION","DISPATCH","VENUE_EFFECT"):facts[("public-step",kind)]["command_id"]=None
        self.assertEqual(TerminalScorer._step(expected,attempt,response,facts),"FAIL")

    def assertion(self,operator,values,expected=None):
        facts={(f"public-{i}","POST_STATE"):{"value":v} for i,v in enumerate(values)}
        refs={k:{"public":"anchor"} for k in facts}
        rule={"operator":operator,"expected":expected,"operands":[{"step_id":k[0],"kind":k[1],"path":["value"]} for k in facts]}
        return TerminalScorer._assertion(rule,facts,refs)[0]

    def test_stable_identity_assertion(self):
        self.assertEqual(self.assertion("EQUAL_FIELDS",["public-account","public-account"]),"PASS")

    def test_changed_identity_fails(self):
        self.assertEqual(self.assertion("EQUAL_FIELDS",["public-account","different-account"]),"FAIL")

    def test_equal_timestamp_is_not_successive_observation(self):
        self.assertEqual(self.assertion("ORDERED_TIMES",[stamp(1)["utc"],stamp(1)["utc"]]),"FAIL")

    def test_nonfinite_accounting_does_not_pass(self):
        self.assertEqual(self.assertion("STRICT_INCREASE",["1","NaN"]),"FAIL")

    def test_numeric_accounting_not_lexical_order(self):
        self.assertEqual(self.assertion("STRICT_INCREASE",["9","10"]),"PASS")
