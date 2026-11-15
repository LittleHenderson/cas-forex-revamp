"""Focused PROV-01/PROV-02 regression SOURCE. NOT_RUN; no real keys or calls.

All times and records are invented public unit fixtures. Slow work is represented
by moving a fake clock, never sleeping, launching a process or using a real key.
"""
from datetime import datetime
import unittest

from source.authority_provider import AuthorityProvider, EvidenceError, hash_value
from public_fixtures import at, authentication_fixture, terminal_fixture


class AttestationBoundaryTests(unittest.TestCase):
    def make(self, *, expire_on_read=None, expire_on_verification=False, expired_second=11):
        store, reference, publisher, signer, verifier = authentication_fixture(attestation_expires_at=at(10))
        clock = {"second": 9}

        class Resolver:
            def __init__(self): self.reads = 0

            def read(self, selected):
                self.reads += 1
                result = store.read(selected)
                if self.reads == expire_on_read: clock["second"] = expired_second
                return result

        class Verifier:
            def verify(self, **kwargs):
                result = verifier.verify(**kwargs)
                if expire_on_verification: clock["second"] = expired_second
                return result

        provider = AuthorityProvider(selection=store.selection, selection_content_sha256=hash_value(store.selection),
            resolver=Resolver(), signature_verifiers={signer: Verifier()}, require_remaining=lambda: None,
            clock=lambda: datetime.fromisoformat(at(clock["second"]).replace("Z", "+00:00")))
        kwargs = {"raw_sha256": reference["sha256"], "purpose": "fixture-purpose", "publisher_sha256": publisher,
                  "run_id": store.selection["run_id"], "epoch": store.selection["epoch"]}
        return provider, reference, publisher, kwargs

    def test_expiry_during_original_record_read_rejected(self):
        for second in (10, 11):
            provider, _, _, kwargs = self.make(expire_on_read=1, expired_second=second)
            with self.subTest(second=second), self.assertRaisesRegex(EvidenceError, "ATTESTATION_TIME"):
                provider.authenticate(**kwargs)

    def test_expiry_during_attestation_read_rejected(self):
        for second in (10, 11):
            provider, _, _, kwargs = self.make(expire_on_read=2, expired_second=second)
            with self.subTest(second=second), self.assertRaisesRegex(EvidenceError, "ATTESTATION_TIME"):
                provider.authenticate(**kwargs)

    def test_expiry_during_signature_verification_rejected(self):
        for second in (10, 11):
            provider, _, _, kwargs = self.make(expire_on_verification=True, expired_second=second)
            with self.subTest(second=second), self.assertRaisesRegex(EvidenceError, "ATTESTATION_TIME"):
                provider.authenticate(**kwargs)

    def test_expiry_during_final_record_reread_rejected(self):
        for second in (10, 11):
            provider, reference, publisher, _ = self.make(expire_on_read=3, expired_second=second)
            with self.subTest(second=second), self.assertRaisesRegex(EvidenceError, "ATTESTATION_TIME"):
                provider.record(reference, purpose="fixture-purpose", publisher_sha256=publisher)

    def test_unexpired_short_attestation_retains_public_protocol(self):
        provider, reference, publisher, kwargs = self.make()
        self.assertIsNone(provider.authenticate(**kwargs))
        self.assertEqual(provider.record(reference, purpose="fixture-purpose", publisher_sha256=publisher), {"public_fixture_only": True})


class ProbeWaitOnlyTests(unittest.TestCase):
    def test_complete_action_probe_remains_spent_and_prevents_accept(self):
        store, scorer, redactor, bundle, _ = terminal_fixture(mode="action_probe")
        report = scorer.derive(retained_bundle=bundle, authority=store)
        probe = report["generation_attempts"][0]
        self.assertEqual(probe["phase"], "PROBE")
        self.assertEqual(probe["outcome"], "COMPLETE")
        self.assertEqual(len(report["generation_attempts"]), 32)
        original = store.record(probe["original_outcome_receipt"], purpose="retained-outcome", publisher_sha256=scorer.publishers["transport"])
        self.assertEqual(original["payload"]["status"], "COMPLETE")
        self.assertIn("public-prohibited-probe-choice", original["payload"]["response_utf8"])
        self.assertTrue(all(step["outcome"] == "PASS" for step in report["steps"]))
        self.assertTrue(all(assertion["outcome"] == "PASS" for assertion in report["assertions"]))
        self.assertEqual(report["broad_failure_codes"], ["MODEL_PROTOCOL_GATE"])
        body = redactor.derive_body(retained_bundle=bundle, authority=store)
        self.assertEqual(body["status"], "FAIL")
        self.assertEqual(body["generation_attempts_spent"], 32)
        self.assertEqual(body["mandatory_steps_accounted"], 30)
        self.assertFalse(body["all_mandatory_assertions_passed"])
