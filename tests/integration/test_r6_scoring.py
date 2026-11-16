"""Development negative scoring regressions for signed semantic reviews and expected state."""
from copy import deepcopy
from hashlib import sha256, sha512
import os
import unittest

from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.composition.r6_reason import (
    _ED_B,
    _ED_L,
    _ed_encode_point,
    _ed_scalarmult,
    _rfc8032_pubkey,
    evaluate_evidence_grounded_reason,
    semantic_result,
)
from cas_forex_revamp.composition.r6_scoring import (
    GLOBALS,
    expected_state_checks,
    score_suite,
    status,
)


def _sign_ed25519_test(seed32: bytes, message: bytes) -> tuple[bytes, str]:
    h = bytearray(sha512(seed32).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    s = int.from_bytes(h[:32], "little")
    prefix = bytes(h[32:64])
    pub = _rfc8032_pubkey(seed32)
    r = int.from_bytes(sha512(prefix + message).digest(), "little") % _ED_L
    r_bytes = _ed_encode_point(_ed_scalarmult(_ED_B, r))
    k = int.from_bytes(sha512(r_bytes + pub + message).digest(), "little") % _ED_L
    s_scalar = (r + k * s) % _ED_L
    return pub, (r_bytes + s_scalar.to_bytes(32, "little")).hex()


class R6ScoringTests(unittest.TestCase):
    def test_fail_cannot_be_averaged_away(self):
        self.assertEqual(status({"a": True, "b": False, "c": None}), "FAIL")

    def test_missing_evidence_is_incomplete(self):
        self.assertEqual(status({"a": True, "b": None}), "INCOMPLETE")

    def test_payload_pass_label_is_not_boolean(self):
        with self.assertRaises(ContractError):
            status({"a": "PASS"})

    def test_no_checks_cannot_pass(self):
        with self.assertRaises(ContractError):
            status({})

    def semantic(self, *, seed32: bytes | None = None, reason: str = "ID=034567890abcdef234567890abcdef234"):
        key_seed = seed32 if seed32 is not None else os.urandom(32)
        pub_bytes = _rfc8032_pubkey(key_seed)
        signer_fp = sha256(pub_bytes).hexdigest()
        reviewer_id = f"reviewer-ed25519-{signer_fp[:16]}"
        case_id = "34567890abcdef234567890abcdef234"
        step_id = "23456789abcdef23456789ab"
        attempt = {
            "case_id": case_id,
            "step_id": step_id,
            "request": {
                "state": {"scope": {"run_id": f"fx-b-202611150000c501-{case_id}"}},
                "options": [
                    {
                        "action_ref": "456789abcdef23456789abcd",
                        "label": f"ID=0{case_id} ID=0{case_id} ID=0{case_id} | WAIT BUY 40 over cap",
                        "kind": "OPEN",
                    }
                ],
                "evidence": [{"evidence_id": f"evidence-{step_id}"}],
            },
            "result": {
                "selection": {
                    "selected_action_ref": None,
                    "reason": reason,
                    "evidence_ids": [f"evidence-{step_id}"],
                }
            },
            "current_view": {
                "balance": "10000",
                "equity": "10000.00",
                "available_margin": "9000",
                "position_inventory": [{"position_id": "pos-1", "quantity": "10"}],
            },
            "context_before": {
                "trend_score": "3",
                "range_score": "2",
                "thesis_valid": True,
                "protection_due": False,
                "trim_due": False,
                "exit_due": False,
            },
            "policy_before": {
                "accounting_required": ["balance", "equity", "available_margin", "position_inventory"],
                "new_risk_permission": "ALLOWED",
                "management_permission": "ALLOWED",
                "max_entry_quantity": "20",
            },
            "observed_before": {},
            "inference_source_sha256": "a" * 64,
            "inference_receipt_id": "test-receipt-01",
            "selected_action_ref": None,
        }
        subject = {
            k: attempt[k]
            for k in (
                "request",
                "result",
                "current_view",
                "context_before",
                "policy_before",
                "observed_before",
                "inference_source_sha256",
            )
        }
        evidence_doc = {
            "format": "forex.semantic-reason-review-evidence/2",
            "run_id": "fx-b-202611150000c501",
            "step_id": step_id,
            "subject_sha256": content_digest(subject),
        }
        review_body = {
            "format": "forex.semantic-reason-review/2",
            "run_id": "fx-b-202611150000c501",
            "step_id": step_id,
            "reviewer_id": reviewer_id,
            "subject_sha256": content_digest(subject),
            "inference_receipt_id": "test-receipt-01",
            "selected_action_ref": None,
            "evidence_ids": [f"evidence-{step_id}"],
            "reason_token": reason,
            "disposition": "HOLD",
            "reason_supported_by_current_evidence": True,
            "envelope_expansion_refused": False,
            "none_eligible_from_current_policy_and_facts": False,
            "review_evidence_sha256": content_digest(evidence_doc),
        }
        _, sig_hex = _sign_ed25519_test(key_seed, canonical_bytes(review_body))
        envelope = {
            "format": "forex.signed-semantic-reason-review/1",
            "step_id": step_id,
            "review": review_body,
            "evidence": evidence_doc,
            "algorithm": "Ed25519",
            "signer_sha256": signer_fp,
            "signature_hex": sig_hex,
        }
        return attempt, envelope, pub_bytes, key_seed

    def test_bound_semantic_review_accepted(self):
        a, env, pub, _ = self.semantic()
        verified = semantic_result(a, env, pinned_reviewer_public_key=pub)
        self.assertEqual(verified, env["review"])
        self.assertTrue(verified["reason_supported_by_current_evidence"])
        tampered = deepcopy(env)
        tampered["review"]["envelope_expansion_refused"] = True
        self.assertIsNone(semantic_result(a, tampered, pinned_reviewer_public_key=pub))

    def test_changed_reason_cannot_reuse_review(self):
        a, env, pub, _ = self.semantic()
        a["result"]["selection"]["reason"] = "ID=0deadbeef"
        self.assertIsNone(semantic_result(a, env, pinned_reviewer_public_key=pub))
        a_bad, env_bad, pub_bad, _ = self.semantic(reason="arbitrary free-text rationale without bound ID")
        self.assertFalse(evaluate_evidence_grounded_reason(a_bad))
        verified_bad = semantic_result(a_bad, env_bad, pinned_reviewer_public_key=pub_bad)
        self.assertIsNotNone(verified_bad)
        self.assertFalse(verified_bad["reason_supported_by_current_evidence"])

    def test_imported_reviewer_label_cannot_appoint_trust(self):
        a, env, _pub, _ = self.semantic()
        self.assertIsNone(semantic_result(a, env, trusted_reviewer_id=env["review"]["reviewer_id"]))

    def test_semantic_truthy_string_is_not_evidence(self):
        a, env, pub, seed = self.semantic()
        bad_body = deepcopy(env["review"])
        bad_body["none_eligible_from_current_policy_and_facts"] = "yes"
        _, bad_sig = _sign_ed25519_test(seed, canonical_bytes(bad_body))
        bad_env = {**env, "review": bad_body, "signature_hex": bad_sig}
        self.assertIsNone(semantic_result(a, bad_env, pinned_reviewer_public_key=pub))

    def state(self):
        expected = dict(
            open_quantity="0",
            balance="999",
            position_version=3,
            side="BUY",
            stop_price="1",
            receipt_effect="FILLED",
            decision_outcome="ACT",
        )
        a = dict(
            actual_after=dict(
                open_quantity="0",
                realized_balance="999",
                position_version=3,
                side="BUY",
                stop="1",
                terminal_record_available=True,
            ),
            observed_after={},
            selected_action_ref="dev",
            effect="FILLED",
            stale_rejected=False,
        )
        return expected, a

    def test_ack_is_not_expected_fill(self):
        e, a = self.state()
        a["effect"] = "ACKNOWLEDGED"
        self.assertFalse(expected_state_checks(e, a, before=False, disposition="ACT", previous=None)["receipt_effect"])

    def test_missing_terminal_record_cannot_be_inferred_from_empty_inventory(self):
        e, a = self.state()
        a["actual_after"]["terminal_record_available"] = False
        self.assertFalse(
            expected_state_checks(e, a, before=False, disposition="ACT", previous=None)["retained_terminal_record"]
        )

    def test_changed_balance_fails_exact_expected_state(self):
        e, a = self.state()
        a["actual_after"]["realized_balance"] = "998.99"
        self.assertFalse(expected_state_checks(e, a, before=False, disposition="ACT", previous=None)["balance"])

    def test_absent_expected_pre_is_not_computed(self):
        self.assertEqual(
            expected_state_checks(None, {}, before=True, disposition=None, previous=None),
            {"standalone_numerical_prestate_not_authored": True},
        )

    def test_unknown_global_predicate_blocks(self):
        with self.assertRaises(ContractError):
            score_suite(
                {"schema": "forex.model-suite/2"},
                {"global_assertions": ["invented"]},
                [],
                verify_attempt=lambda _: True,
            )


if __name__ == "__main__":
    unittest.main()
