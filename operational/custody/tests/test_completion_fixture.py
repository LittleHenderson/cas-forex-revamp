"""Synthetic selection-fixture regressions, never observed completion evidence.

AUTHORED/NOT_RUN until the parent records a separately admitted Linux execution.
Original test_completion assertions and public placeholder bytes stay unchanged.
"""
import json
from pathlib import Path
import unittest

from cas_forex_operational_contracts import common, completion
from public_fixtures import completion_selection, packet


class SyntheticCompletionFixtureTests(unittest.TestCase):
    def test_selection_reaches_the_original_shape_validator(self):
        selected=completion_selection()
        validated=completion.validate("CompletionSelection2",selected).payload()
        self.assertEqual(validated,selected)
        self.assertEqual(selected["selection_id"],"public-test-only-completion-selection")

    def test_original_structural_rows_order_modes_and_counts_preserved(self):
        rows=json.loads((Path(__file__).parent/"public-completion-rows.json").read_text(encoding="utf-8"))
        selected=completion_selection()
        self.assertEqual(selected["groups"],rows["groups"])
        self.assertEqual([g["group_id"] for g in selected["groups"]],list(completion.GROUP_ORDER))
        self.assertEqual([g["expected_test_count"] for g in selected["groups"]],[1]*11+[0,1])

    def test_original_completion_placeholder_stays_unobserved(self):
        example=packet()
        placeholders=[v["body"] for v in example["objects"].values()
                      if v["record_kind"]=="SOURCE_TEST_COMPLETION"]
        self.assertEqual(placeholders,[{"format":"public.external-completion-dependency/1",
            "warning":"Not an observed completion; all runtime tests NOT_RUN."}])
        self.assertIs(example["valid_runtime_signature"],False)
        self.assertIs(example["private_cases_included"],False)
        self.assertEqual(example["runtime_expected_result"],
                         "REJECT_UNAUTHENTICATED_AND_UNRESOLVED_DEPENDENCIES")
        completion_selection()
        self.assertEqual(packet(),example)

    def test_each_call_returns_detached_mutable_test_input(self):
        before=completion_selection()
        changed=completion_selection()
        changed["binding"]["run_id"]="CHANGED-TEST-INPUT"
        changed["groups"][0]["command"]["reference"]["bytes"]=123456
        changed["original_clock_ref"]["reference"]["binding"]["epoch"]=999
        self.assertEqual(completion_selection(),before)

    def test_selection_cannot_be_misused_as_observed_completion_receipt(self):
        selected=completion_selection()
        completion.validate("CompletionSelection2",selected)
        with self.assertRaises(common.ContractError):
            completion.validate("CompletionReceipt2",selected)

    def test_new_dependency_references_are_unresolved_with_explicit_routes(self):
        selected=completion_selection()
        objects=packet()["objects"]
        for field,kind,purpose in (
            ("original_clock_ref","EXTERNAL_RELEASE_EVIDENCE",
             "release-evidence:original_clock_and_budget_binding_sha256"),
            ("source_inventory_ref","SOURCE_INVENTORY","completion-source-inventory")):
            with self.subTest(field=field):
                use=selected[field]
                self.assertEqual(use["required_use"],"SOURCE_COMPLETION")
                self.assertEqual(use["reference"]["record_kind"],kind)
                self.assertEqual(use["reference"]["purpose"],purpose)
                self.assertEqual(use["reference"]["binding"],selected["binding"])
                self.assertEqual(use["reference"]["publisher_selection_sha256"],
                                 selected["publisher_selection_sha256"])
                self.assertNotIn(use["reference"]["object_id"],objects)

    def test_fake_provenance_envelope_is_not_inserted_into_schema_body(self):
        envelope=json.loads((Path(__file__).parent/"public-test-only-completion-selection.json").read_text(encoding="utf-8"))
        self.assertEqual(set(envelope),{"classification","warning","selection"})
        self.assertEqual(envelope["classification"],
                         "SYNTHETIC_TEST_ONLY_SELECTION_NOT_COMPLETION_EVIDENCE")
        self.assertIn("No observed completion",envelope["warning"])
        self.assertEqual(envelope["selection"],completion_selection())
        self.assertNotIn("classification",completion_selection())
        self.assertNotIn("warning",completion_selection())
