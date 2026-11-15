"""Authored boundary tests. NOT_RUN until the approved verification environment exists."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import unittest

from cas_forex_revamp.contracts import (
    ActionIntent, ActionKind, ActionOption, AtlasAudience, AtlasContent, AtlasNode,
    AtlasNodeKind, AtlasView, AuthorizedCommand, ContractError, DecisionOrigin,
    DecisionRequest, EffectState, EvidenceKind, EvidenceReference, Money,
    QuantityReport, RunScope, Side, StateReference, VenueReceipt,
    assert_command_integrity, assert_current_request, atlas_domain_digest,
    canonical_bytes, intent_digest, parse_decimal, selection_from_json,
)


T0 = datetime(2026, 10, 10, 20, 0, tzinfo=timezone.utc)


def context() -> tuple[RunScope, StateReference, ActionIntent, DecisionRequest]:
    scope = RunScope("account-1", "run-1", 1, "build-1", "policy-1", "scenario-1", "venue-1")
    state = StateReference("state-1", scope, 1, T0, T0 + timedelta(seconds=60), 5)
    intent = ActionIntent(
        intent_id="intent-1", scope=scope, decision_id="decision-1", opportunity_id="opportunity-1",
        action_ref="action-1", source_state=state, kind=ActionKind.OPEN, instrument_id="EURUSD-1",
        origin=DecisionOrigin.SCRIPTED, created_at=T0, expires_at=T0 + timedelta(seconds=30),
        quantity=Decimal("10"), side=Side.BUY, stop_price=Decimal("1.08"),
    )
    evidence = EvidenceReference("evidence-1", EvidenceKind.OBSERVATION, "scenario-1", "a" * 64, T0)
    request = DecisionRequest("request-1", "options-1", state,
                              (ActionOption("action-1", "strategy-1", "H1", "Synthetic entry", intent),),
                              (), (evidence,))
    return scope, state, intent, request


def selection_payload() -> dict:
    return {"request_id": "request-1", "opportunity_set_id": "options-1", "source_state_id": "state-1",
            "selected_action_ref": "action-1", "reason": "Select the supplied synthetic option.",
            "evidence_ids": ["evidence-1"]}


class NumericBoundaryTests(unittest.TestCase):
    def test_float_never_becomes_money(self):
        with self.assertRaises(ContractError):
            Money(0.1, "USD")

    def test_nonfinite_exponent_and_boolean_wire_values_are_rejected(self):
        for raw in ("NaN", "Infinity", "1e3", "01", True, 0.1):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                parse_decimal(raw)

    def test_zero_with_extreme_exponent_is_bounded(self):
        with self.assertRaises(ContractError):
            Money(Decimal("0E+999999"), "USD")

    def test_numeric_identity_ignores_redundant_decimal_zeroes(self):
        self.assertEqual(canonical_bytes(Money(Decimal("1.0"), "USD")),
                         canonical_bytes(Money(Decimal("1.00"), "USD")))

    def test_quantity_cannot_be_lost_or_double_counted(self):
        with self.assertRaises(ContractError):
            QuantityReport(Decimal("10"), Decimal("4"), Decimal("6"), Decimal("0"), Decimal("1"))


class IdentityBoundaryTests(unittest.TestCase):
    def test_payload_change_cannot_reuse_its_old_digest(self):
        _, _, intent, _ = context()
        command = AuthorizedCommand("command-1", replace(intent, quantity=Decimal("11")),
                                    intent_digest(intent), "reservation-1", "grant-1", 2, "writer-1")
        with self.assertRaises(ContractError):
            assert_command_integrity(command)

    def test_recovery_namespace_survives_epoch_and_build_change(self):
        scope, _, _, _ = context()
        restarted = replace(scope, epoch=2, build_id="build-2")
        self.assertEqual(scope.key, restarted.key)
        self.assertNotEqual(scope, restarted)

    def test_stale_model_request_is_rejected_even_with_same_account(self):
        _, state, _, request = context()
        with self.assertRaises(ContractError):
            assert_current_request(request, replace(state, state_id="state-2", version=2), T0)

    def test_expiry_is_exclusive(self):
        _, state, _, request = context()
        with self.assertRaises(ContractError):
            assert_current_request(request, state, state.valid_until)


class SelectionBoundaryTests(unittest.TestCase):
    def test_wait_is_explicit_and_never_an_order_fallback(self):
        *_, request = context()
        payload = selection_payload()
        payload["selected_action_ref"] = None
        result = selection_from_json(json.dumps(payload), request)
        self.assertIsNone(result.selected_action_ref)

    def test_model_cannot_inject_quantity_or_authority(self):
        *_, request = context()
        for field in ("quantity", "authority_id", "dispatch_generation", "tool_call"):
            payload = selection_payload()
            payload[field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(ContractError):
                selection_from_json(json.dumps(payload), request)

    def test_duplicate_keys_are_not_last_value_wins(self):
        *_, request = context()
        raw = json.dumps(selection_payload())[:-1] + ',"selected_action_ref":null}'
        with self.assertRaises(ContractError):
            selection_from_json(raw, request)

    def test_unknown_action_or_evidence_cannot_be_invented(self):
        *_, request = context()
        for field, value in (("selected_action_ref", "invented"), ("evidence_ids", ["invented"])):
            payload = selection_payload()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                selection_from_json(json.dumps(payload), request)


class ReceiptBoundaryTests(unittest.TestCase):
    def test_ack_is_not_a_fill(self):
        scope, _, intent, _ = context()
        with self.assertRaises(ContractError):
            VenueReceipt(scope.key, "receipt-1", "command-1", intent_digest(intent),
                         EffectState.ACKNOWLEDGED, 6, 2, T0,
                         QuantityReport(Decimal("10"), Decimal("4"), Decimal("0"), Decimal("0"), Decimal("6")))

    def test_partial_fill_and_cancel_remain_two_observed_quantities(self):
        scope, _, intent, _ = context()
        receipt = VenueReceipt(scope.key, "receipt-1", "command-1", intent_digest(intent),
                               EffectState.CANCELLED, 6, 2, T0,
                               QuantityReport(Decimal("10"), Decimal("4"), Decimal("6"), Decimal("0"), Decimal("0")))
        self.assertEqual(receipt.quantities.filled, Decimal("4"))
        self.assertEqual(receipt.quantities.cancelled, Decimal("6"))


class AtlasBoundaryTests(unittest.TestCase):
    def test_focus_and_hypothesis_navigation_do_not_change_domain_identity(self):
        content = AtlasContent("atlas-1", 0, "request-1", "state-1", "b" * 64,
                               AtlasAudience.OWNER_DIAGNOSIS,
                               (AtlasNode("fact-1", AtlasNodeKind.FACT, "Known observation", ()),
                                AtlasNode("hyp-1", AtlasNodeKind.HYPOTHESIS, "Possible successor", ())))
        first = AtlasView(content, "fact-1")
        second = AtlasView(content, "hyp-1", "hyp-1")
        self.assertEqual(atlas_domain_digest(first), atlas_domain_digest(second))
        self.assertEqual(second.content.current_state_id, "state-1")
        self.assertNotEqual(canonical_bytes(first), canonical_bytes(second))

    def test_changed_domain_reason_changes_identity(self):
        content = AtlasContent("atlas-1", 0, "request-1", "state-1", "b" * 64,
                               AtlasAudience.MATCHED_MODEL_INPUT,
                               (AtlasNode("reason-1", AtlasNodeKind.REASON, "Original reason", ()),))
        changed = replace(content, nodes=(replace(content.nodes[0], label="Different reason"),))
        self.assertNotEqual(atlas_domain_digest(content), atlas_domain_digest(changed))


if __name__ == "__main__":
    unittest.main()
