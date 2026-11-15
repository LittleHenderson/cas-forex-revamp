import copy
import unittest

from policy_inheritance.errors import ContractViolation
from policy_inheritance.plan import Coverage
from support import Fixture


class PlanTests(unittest.TestCase):
    def setUp(self):self.f=Fixture()
    def check(self,plan):return Coverage(self.f.contract,plan,selected_scope=self.f.scope)
    def test_complete_transitive_plan_valid(self):self.assertEqual(len(self.check(self.f.plan).plan["slots"]),19)
    def test_creation_cannot_wait_for_runner(self):
        p=copy.deepcopy(self.f.plan);p["slots"][11]["after_slots"].append("slot-e13")
        with self.assertRaises(ContractViolation):self.check(p)
    def test_creation_cannot_wait_for_model_postexec(self):
        p=copy.deepcopy(self.f.plan);p["slots"][11]["after_slots"].append("slot-e16")
        with self.assertRaises(ContractViolation):self.check(p)
    def test_creation_cannot_wait_for_peer(self):
        p=copy.deepcopy(self.f.plan);p["slots"][11]["after_slots"].append("slot-e17")
        with self.assertRaises(ContractViolation):self.check(p)
    def test_policy_seal_cycle_rejected(self):
        p=copy.deepcopy(self.f.plan);p["slots"][17]["after_slots"].append("slot-e19")
        with self.assertRaises(ContractViolation):self.check(p)
    def test_self_and_unknown_edges_rejected(self):
        for edge in ["slot-e12","absent-slot"]:
            p=copy.deepcopy(self.f.plan);p["slots"][11]["after_slots"].append(edge)
            with self.subTest(edge=edge),self.assertRaises(ContractViolation):self.check(p)
    def test_missing_semantic_dependency_rejected(self):
        p=copy.deepcopy(self.f.plan);p["slots"][11]["after_slots"]=[]
        with self.assertRaises(ContractViolation):self.check(p)
    def test_missing_or_duplicate_case_rejected(self):
        p=copy.deepcopy(self.f.plan);p["calibration_plan"][7]=copy.deepcopy(p["calibration_plan"][6])
        with self.assertRaises(ContractViolation):self.check(p)
    def test_baseline_cannot_be_redefined(self):
        p=copy.deepcopy(self.f.plan);p["calibration_plan"][1]["expected_exchange_verdicts"]=["ACCEPTED_INERT"]
        with self.assertRaises(ContractViolation):self.check(p)
    def test_case_subject_and_origin_bound(self):
        for mutate in [lambda p:p["slots"][2].update(expected_subject_id="wrong"),lambda p:p["slots"][12].update(origin="CONTROLLER")]:
            p=copy.deepcopy(self.f.plan);mutate(p)
            with self.assertRaises(ContractViolation):self.check(p)
    def test_coverage_defensively_copies_selected_plan(self):
        p=copy.deepcopy(self.f.plan);coverage=self.check(p);p["slots"][0]["slot_id"]="changed"
        self.assertEqual(coverage.plan["slots"][0]["slot_id"],"slot-e01")
    def test_seal_before_policy_is_not_eligible(self):
        coverage=self.check(self.f.plan)
        event={"slot_id":"slot-e19","kind":"SETUP_SEAL","origin":"CONTROLLER","sequence":18}
        with self.assertRaises(ContractViolation):coverage.require_next(event,tuple(f"slot-e{i:02}" for i in range(1,18)))
