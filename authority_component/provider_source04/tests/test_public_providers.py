"""Regression SOURCE only. Execution status remains NOT_RUN.

Future isolated invocation requires explicit approval. No auto-run main block.
These invented public fixtures never establish runtime authority or R6 success.
"""
from copy import deepcopy
from datetime import datetime, timezone
import unittest

from source.authority_provider import AuthorityProvider, EvidenceError, hash_value, parse
from public_fixtures import authentication_fixture, completion_fixture, terminal_fixture, pin


class AuthenticationTests(unittest.TestCase):
    def make(self, *, expired=False, boolean_verifier=False):
        store, reference, publisher, signer, verifier = authentication_fixture()
        if boolean_verifier:
            class BooleanVerifier:
                def verify(self, **kwargs): return True
            verifier = BooleanVerifier()
        authority = AuthorityProvider(selection=store.selection, selection_content_sha256=hash_value(store.selection),
            resolver=store, signature_verifiers={signer: verifier},
            clock=lambda: datetime(2000, 1, 1, 2 if expired else 0, tzinfo=timezone.utc), require_remaining=lambda: None)
        return authority, reference, publisher

    def test_selected_exact_record(self):
        authority, reference, publisher = self.make()
        self.assertEqual(authority.record(reference, purpose="fixture-purpose", publisher_sha256=publisher), {"public_fixture_only": True})

    def test_wrong_purpose_expiry_and_boolean_provider_rejected(self):
        for options in ({"expired": True}, {"boolean_verifier": True}, {}):
            with self.subTest(options=options):
                authority, reference, publisher = self.make(**options)
                with self.assertRaises(EvidenceError):
                    authority.record(reference, purpose="wrong-purpose" if not options else "fixture-purpose", publisher_sha256=publisher)

    def test_mutated_reference_and_unavailable_collector_rejected(self):
        authority, reference, publisher = self.make()
        reference["bytes"] += 1
        with self.assertRaises(EvidenceError): authority.record(reference, purpose="fixture-purpose", publisher_sha256=publisher)
        with self.assertRaisesRegex(EvidenceError, "UNSUPPORTED"): authority.verify_observation(record={})
        with self.assertRaisesRegex(EvidenceError, "UNSUPPORTED"): authority.verify_inventory(record={})

    def test_duplicate_and_noninteger_json_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(EvidenceError): parse(raw)


class CompletionTests(unittest.TestCase):
    def verify(self, mode):
        store, provider, record, dependencies, selected = completion_fixture(mode=mode)
        return provider.verify(record=record, dependencies=dependencies, selection=selected, authority=store)

    def test_all_observed_groups_match_originals(self):
        self.assertIsNone(self.verify("complete"))

    def test_pass_label_cannot_cover_missing_or_failed_observations(self):
        for mode in ("missing_group", "failed_exit", "lost_events", "ui_failure", "original_mismatch"):
            with self.subTest(mode=mode), self.assertRaises(EvidenceError): self.verify(mode)


class ScoringTests(unittest.TestCase):
    def test_independent_full_public_fixture(self):
        store, scorer, redactor, bundle, selected = terminal_fixture()
        report = scorer.derive(retained_bundle=bundle, authority=store)
        self.assertIsNone(scorer.verify(record=report, retained_bundle=bundle, selection=selected, authority=store))
        body = redactor.derive_body(retained_bundle=bundle, authority=store)
        self.assertEqual(body["status"], "ACCEPT")
        self.assertEqual(body["generation_attempts_spent"], 32)
        self.assertEqual(body["mandatory_steps_accounted"], 30)

    def test_original_failures_and_unknowns_remain_spent(self):
        for mode, step_status in (("failed", "FAIL"), ("unknown", "INCOMPLETE")):
            with self.subTest(mode=mode):
                store, scorer, redactor, bundle, _ = terminal_fixture(mode=mode)
                report = scorer.derive(retained_bundle=bundle, authority=store)
                self.assertEqual(report["generation_attempts"][2]["outcome"], mode.upper())
                self.assertEqual(report["steps"][0]["outcome"], step_status)
                body = redactor.derive_body(retained_bundle=bundle, authority=store)
                self.assertEqual(body["generation_attempts_spent"], 32)
                self.assertFalse(body["all_mandatory_assertions_passed"])

    def test_safety_only_changed_state_and_token_overrun_fail(self):
        for mode in ("safety_only", "wrong_state", "token_overrun"):
            with self.subTest(mode=mode):
                store, scorer, _, bundle, _ = terminal_fixture(mode=mode)
                report = scorer.derive(retained_bundle=bundle, authority=store)
                self.assertEqual(report["steps"][0]["outcome"], "FAIL")

    def test_missing_graph_and_abort_cannot_accept(self):
        for mode in ("incomplete", "aborted"):
            with self.subTest(mode=mode):
                store, _, redactor, bundle, _ = terminal_fixture(mode=mode)
                body = redactor.derive_body(retained_bundle=bundle, authority=store)
                self.assertNotEqual(body["status"], "ACCEPT")
                self.assertFalse(body["all_mandatory_assertions_passed"])

    def test_retries_missing_records_unsupported_predicates_and_pins_block(self):
        for mode in ("retry", "omitted_record", "unsupported_predicate", "wrong_model", "bad_response_pin"):
            with self.subTest(mode=mode), self.assertRaises(EvidenceError):
                store, scorer, _, bundle, _ = terminal_fixture(mode=mode)
                scorer.derive(retained_bundle=bundle, authority=store)

    def test_application_pass_substitution_rejected(self):
        store, scorer, _, bundle, selected = terminal_fixture(mode="wrong_state")
        report = scorer.derive(retained_bundle=bundle, authority=store)
        report["steps"][0]["outcome"] = "PASS"
        with self.assertRaises(EvidenceError): scorer.verify(record=report, retained_bundle=bundle, selection=selected, authority=store)


class RedactionTests(unittest.TestCase):
    def test_exact_body_and_selected_reviewer_receipt(self):
        store, scorer, redactor, bundle, selected = terminal_fixture()
        body = redactor.derive_body(retained_bundle=bundle, authority=store)
        approval = {"format": "forex.independent-aggregate-redaction/1", "reviewer_binding_sha256": redactor.reviewer,
            "run_id": body["run_id"], "final_or_aborted": True, "retained_evaluation_bundle_sha256": scorer.bundle_ref["sha256"],
            "approved_aggregate_body_sha256": hash_value(body), "independent_complete_scoring_accepted": True}
        selected["redaction_receipt_reference"] = store.add(approval, purpose="independent-aggregate-redaction", publisher=redactor.reviewer)
        self.assertIsNone(redactor.verify_approval(record=approval, dependencies={"body": body}, selection=selected, authority=store))
        approval["approved_aggregate_body_sha256"] = pin("different-body")
        selected["redaction_receipt_reference"] = store.add(approval, purpose="independent-aggregate-redaction", publisher=redactor.reviewer)
        with self.assertRaises(EvidenceError): redactor.verify_approval(record=approval, dependencies={"body": body}, selection=selected, authority=store)

    def test_unknown_field_public_hash_and_score_claim_rejected(self):
        store, _, redactor, bundle, selected = terminal_fixture(mode="failed")
        original = redactor.derive_body(retained_bundle=bundle, authority=store)
        for field, value in (("case_parameter", "invented-public-test-marker"), ("source_freeze_manifest_sha256", pin("unapproved")),
                             ("all_mandatory_assertions_passed", True), ("status", "ACCEPT")):
            body = deepcopy(original); body[field] = value
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                redactor.verify_body(body=body, retained_bundle=bundle, selection=selected, authority=store)
