"""Authored RPA/source-boundary tests. NOT_RUN; hashes do not prove authenticity."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import unittest

from cas_forex_revamp.contracts import (
    ActionIntent, ActionKind, ActionOption, AtlasNodeKind, AtlasView, CommandState,
    CommandView, ContractError, DecisionFact, DecisionOrigin, DecisionRequest,
    DecisionSelection, EffectState, EvidenceKind, EvidenceReference, QuantityReport,
    RunScope, Side, StateReference, VenueReceipt, atlas_domain_digest, content_digest,
    intent_digest,
)
from cas_forex_revamp.operator.adapters import ScriptedDecisionAdapter, ScriptStep
from cas_forex_revamp.rpa.projection import (
    AlternativeDisposition, AlternativeEvaluation, AlternativeEligibility, AlternativeNote, DecisionAtlasProjector, HypothesisNote,
    ReviewRecord, decision_list, navigate, refresh_view,
)
from cas_forex_revamp.rpa.read_binding import TrustedReadAnchor, bind_decision_read


T0 = datetime(2026, 10, 10, 20, 0, tzinfo=timezone.utc)


def review():
    scope = RunScope("account", "run", 1, "build", "policy", "scenario", "venue")
    state = StateReference("state", scope, 1, T0, T0 + timedelta(seconds=60), 1)
    first = ActionIntent("intent", scope, "decision", "opportunity", "first", state,
                         ActionKind.OPEN, "EURUSD", DecisionOrigin.SCRIPTED, T0,
                         T0 + timedelta(seconds=30), Decimal("10"), Side.BUY)
    second = replace(first, intent_id="intent-second", action_ref="second")
    options = (ActionOption("first", "trend", "H1", "First option", first),
               ActionOption("second", "range", "H4", "Second option", second))
    evidence = EvidenceReference("evidence", EvidenceKind.OBSERVATION, "scenario", "a" * 64, T0)
    req = DecisionRequest("request", "options", state, options,
                          (DecisionFact("fact", "Unknown effect", "No venue outcome yet", ("evidence",)),), (evidence,))
    selected = DecisionSelection("request", "options", "state", "first", "Public original reason", ("evidence",))
    result = ScriptedDecisionAdapter((ScriptStep(content_digest(req), selected),), adapter_id="script",
                                     clock=lambda: T0).decide(req)
    return ReviewRecord(req, T0, result)


def receipt(record, *, effect=EffectState.ACKNOWLEDGED, filled="0", remaining="10", sequence=2):
    return VenueReceipt(record.request.state.scope.key, f"receipt-{sequence}", "command",
                         intent_digest(record.request.options[0].intent), effect, sequence, 1, T0,
                         QuantityReport(Decimal("10"), Decimal(filled), Decimal("0"), Decimal("0"), Decimal(remaining)))


class ProjectionTests(unittest.TestCase):
    def test_plain_list_retains_exact_all_source_fields(self):
        record = review()
        baseline = decision_list(record)
        self.assertIs(baseline.source, record)
        self.assertEqual(len(baseline.source.request.options), 2)
        self.assertTrue(baseline.wait_available)

    def test_unchosen_is_not_mislabeled_rejected(self):
        atlas = DecisionAtlasProjector().project_review(review())
        alternative = next(x for x in atlas.nodes if x.action_ref == "second")
        self.assertIn("UNCHOSEN", alternative.label)
        self.assertIsNone(alternative.rejected_reason)

    def test_explicit_rejected_public_reason_is_preserved(self):
        record = replace(review(), alternatives=(AlternativeNote("second", AlternativeDisposition.REJECTED,
                                                                "Explicit fixture rejection", ("evidence",)),))
        atlas = DecisionAtlasProjector().project_review(record)
        alternative = next(x for x in atlas.nodes if x.action_ref == "second")
        self.assertEqual(alternative.rejected_reason, "Explicit fixture rejection")
        self.assertEqual(decision_list(record).source.alternatives[0], record.alternatives[0])

    def test_blocked_and_deferred_do_not_become_rejected_disposition(self):
        note = AlternativeNote("second", AlternativeDisposition.UNCHOSEN, "Awaiting constraint evidence",
                               ("evidence",), evaluation=AlternativeEvaluation.DEFERRED,
                               eligibility=AlternativeEligibility.BLOCKED)
        record = replace(review(), alternatives=(note,))
        node = next(x for x in DecisionAtlasProjector().project_review(record).nodes if x.action_ref == "second")
        self.assertIn("UNCHOSEN", node.label)
        self.assertIn("eligibility=BLOCKED", node.label)
        self.assertIn("evaluation=DEFERRED", node.label)
        self.assertIsNone(node.rejected_reason)

    def test_hypothesis_focus_never_changes_state_or_selection(self):
        record = replace(review(), hypotheses=(HypothesisNote("possible", "Only if an independent receipt arrives",
                                                              ("evidence",), ("second",)),))
        atlas = DecisionAtlasProjector().project_review(record)
        hypothesis = next(x for x in atlas.nodes if x.kind is AtlasNodeKind.HYPOTHESIS)
        before = AtlasView(atlas)
        after = navigate(before, focus_node_id=hypothesis.node_id, hypothesis_branch_id=hypothesis.node_id)
        self.assertEqual(atlas_domain_digest(before), atlas_domain_digest(after))
        self.assertEqual(after.content.current_state_id, "state")
        self.assertEqual(after.content.model_selection_id, "decision")
        self.assertEqual(record.result.selection.selected_action_ref, "first")

    def test_ack_and_partial_fill_remain_independent_quantities(self):
        record = review()
        ack = receipt(record)
        partial = receipt(record, effect=EffectState.PARTIALLY_FILLED, filled="4", remaining="6", sequence=3)
        command = CommandView("command", ack.payload_sha256, CommandState.UNRESOLVED, ack.receipt_id, True)
        record = replace(record, command=command, admission_event_ids=("admission",), receipts=(ack, partial))
        atlas = DecisionAtlasProjector().project_review(record)
        self.assertEqual(atlas.model_selection_id, "decision")
        self.assertEqual(atlas.admission_event_ids, ("admission",))
        self.assertEqual(atlas.observed_receipt_ids, ("receipt-2", "receipt-3"))
        self.assertEqual(decision_list(record).source.receipts[0].quantities.filled, Decimal("0"))
        self.assertEqual(decision_list(record).source.receipts[1].quantities.remaining, Decimal("6"))

    def test_venue_receipt_remains_visible_without_core_command(self):
        record = review()
        record = replace(record, receipts=(receipt(record),))
        self.assertEqual(DecisionAtlasProjector().project_review(record).observed_receipt_ids, ("receipt-2",))
        self.assertIsNone(decision_list(record).source.command)

    def test_wrong_run_or_payload_receipt_rejected(self):
        record = review()
        original = receipt(record)
        for changed in (replace(original, payload_sha256="b" * 64),
                        replace(original, key=replace(original.key, run_id="other"))):
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                replace(record, receipts=(changed,))

    def test_future_receipt_cannot_enter_checkpoint(self):
        record = review()
        with self.assertRaises(ContractError):
            replace(record, receipts=(replace(receipt(record), observed_at=T0 + timedelta(seconds=1)),))

    def test_revision_retains_prior_content_and_clears_changed_entity_focus(self):
        record = review()
        projector = DecisionAtlasProjector()
        old = projector.project_review(record)
        old_alternative = next(x for x in old.nodes if x.action_ref == "second")
        changed = replace(record, alternatives=(AlternativeNote("second", AlternativeDisposition.UNCHOSEN,
                                                               "Waiting for evidence", ("evidence",), evaluation=AlternativeEvaluation.DEFERRED),))
        new = projector.revise(record, old, changed, reason="New public annotation")
        updated = refresh_view(AtlasView(old, old_alternative.node_id), new)
        self.assertEqual(new.previous_content_sha256, atlas_domain_digest(old))
        self.assertIn("UNCHOSEN", old_alternative.label)
        self.assertIsNone(updated.view.focus_node_id)
        self.assertIsNotNone(updated.reset_reason)

    def test_atlas_oversize_does_not_drop_facts_or_break_list(self):
        record = review()
        facts = tuple(DecisionFact(f"fact-{i}", "fact", "value", ("evidence",)) for i in range(128))
        record = replace(record, request=replace(record.request, facts=facts), result=None)
        with self.assertRaises(ContractError):
            DecisionAtlasProjector().project_review(record)
        self.assertEqual(len(decision_list(record).source.request.facts), 128)

    def test_projection_has_no_execution_or_model_dependency(self):
        projector = DecisionAtlasProjector()
        for name in ("dispatch", "admit", "infer", "execute", "authorize"):
            self.assertFalse(hasattr(projector, name))


class ReadAnchorTests(unittest.TestCase):
    """Schema/catalog callbacks below are unit fixtures, not genuine verification."""
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.payload = json.loads((root / "docs/contracts/initial-decision-read.json").read_text(encoding="utf-8"))
        self.schema_hash = sha256((root / "docs/contracts/decision-read.schema.json").read_bytes()).hexdigest()
        self.scope_hash = content_digest(self.payload["scope"])
        self.anchor = TrustedReadAnchor("unit-anchor", "unit-reader", self.schema_hash,
                                       self.payload["domain_digest"], self.scope_hash,
                                       content_digest(self.payload["cursor"]), T0, T0 + timedelta(seconds=30), False)

    def bind(self, payload=None, *, anchor=None, raw=None, semantic=True):
        return bind_decision_read(raw or json.dumps(self.payload if payload is None else payload), now=T0,
                                  expected_scope_sha256=self.scope_hash, schema_sha256=self.schema_hash,
                                  schema_validator=lambda x: True, anchor_reader=lambda: anchor or self.anchor,
                                  semantic_validator=lambda data, actual: semantic)

    def test_incomplete_unknown_fixture_cannot_claim_current_state(self):
        bound = self.bind()
        self.assertTrue(bound.source_bound)
        self.assertTrue(bound.incomplete)
        self.assertFalse(bound.current_state_claim_allowed)
        self.assertTrue(bound.unknown_or_stale)

    def test_recomputed_self_hash_and_pass_label_do_not_replace_anchor(self):
        changed = json.loads(json.dumps(self.payload))
        changed["validation"]["source_binding"]["status"] = "PASS"
        changed["domain_digest"] = content_digest({k: v for k, v in changed.items() if k != "domain_digest"})
        with self.assertRaises(ContractError):
            self.bind(changed)

    def test_wrong_scope_and_expired_anchor_rejected(self):
        for anchor in (replace(self.anchor, scope_sha256="d" * 64),
                       replace(self.anchor, issued_at=T0 - timedelta(seconds=60), expires_at=T0)):
            with self.subTest(anchor=anchor), self.assertRaises(ContractError):
                self.bind(anchor=anchor)

    def test_duplicate_and_oversize_envelopes_rejected(self):
        raw = json.dumps(self.payload)
        with self.assertRaises(ContractError):
            self.bind(raw=raw[:-1] + ',"coverage":{}}')
        with self.assertRaises(ContractError):
            self.bind(raw=" " * 1_048_577)

    def test_validator_cannot_rewrite_anchored_payload(self):
        def mutating(data, anchor):
            data["coverage"]["complete"] = True
            return True
        with self.assertRaises(ContractError):
            bind_decision_read(json.dumps(self.payload), now=T0, expected_scope_sha256=self.scope_hash,
                               schema_sha256=self.schema_hash, schema_validator=lambda data: True,
                               anchor_reader=lambda: self.anchor, semantic_validator=mutating)

    def test_unresolved_catalog_validation_blocks_bound_claim(self):
        with self.assertRaises(ContractError):
            self.bind(semantic=False)


if __name__ == "__main__":
    unittest.main()