"""Authored operator boundary tests. NOT_RUN; future approved execution only."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
import unittest

from cas_forex_revamp.contracts import (
    ActionIntent, ActionKind, ActionOption, ContractError, DecisionFact, DecisionOrigin,
    DecisionRequest, DecisionSelection, EvidenceKind, EvidenceReference, InferenceBudget,
    RunScope, Side, StateReference, canonical_bytes, content_digest,
)
from cas_forex_revamp.operator.adapters import (
    ReplayDecisionAdapter, ReplayEntry, ScriptedDecisionAdapter, ScriptStep,
)
from cas_forex_revamp.operator.decisions import (
    OperatorSession, OperatorUnavailable, StaleDecision, prepare_proposal,
)
from cas_forex_revamp.operator.model import (
    ActualModelDecisionAdapter, InferenceReply, ModelSpecification,
)
from cas_forex_revamp.operator.opportunities import OpportunityBuilder, ManagementOpportunityBuilder


T0 = datetime(2026, 10, 10, 20, 0, tzinfo=timezone.utc)


def request(kind=ActionKind.OPEN, *, index=1, origin=DecisionOrigin.SCRIPTED):
    scope = RunScope("account", "run", 1, "build", "policy", "scenario", "venue")
    observed = T0 + timedelta(seconds=index - 1)
    state = StateReference(f"state-{index}", scope, index, observed, observed + timedelta(seconds=60), index)
    kwargs = {"quantity": Decimal("10"), "side": Side.BUY}
    if kind is not ActionKind.OPEN:
        kwargs.update(target_id="position-1", target_version=index)
    if kind in (ActionKind.AMEND_STOP, ActionKind.CANCEL_ORDER):
        kwargs["quantity"] = None
    if kind is ActionKind.AMEND_STOP:
        kwargs["stop_price"] = Decimal("1.01")
    if kind is ActionKind.CANCEL_ORDER:
        kwargs["target_id"] = "original-command"
    intent = ActionIntent(f"intent-{index}", scope, f"decision-{index}", f"opportunity-{index}",
                          f"action-{index}", state, kind, "EURUSD", origin, observed,
                          observed + timedelta(seconds=30), **kwargs)
    option = ActionOption(intent.action_ref, "strategy", "H1", "Synthetic option", intent)
    evidence = EvidenceReference(f"evidence-{index}", EvidenceKind.OBSERVATION, "scenario", "a" * 64, observed)
    fact = DecisionFact(f"fact-{index}", "Context", "Known synthetic observation", (evidence.evidence_id,))
    return DecisionRequest(f"request-{index}", f"options-{index}", state, (option,), (fact,), (evidence,))


def selection(req, *, wait=False):
    return DecisionSelection(req.request_id, req.opportunity_set_id, req.state.state_id,
                             None if wait else req.options[0].action_ref, "Public fixture reason.",
                             tuple(x.evidence_id for x in req.evidence))


def scripted(req, *, clock=None, wait=False):
    return ScriptedDecisionAdapter((ScriptStep(content_digest(req), selection(req, wait=wait)),),
                                   adapter_id="script", clock=clock or (lambda: req.state.observed_at))


class ScriptAndManagementTests(unittest.TestCase):
    def test_exact_preallocated_decision_and_intent_survive(self):
        req = request()
        result = scripted(req).decide(req)
        proposal = prepare_proposal(req, result, current=req.state, now=T0)
        self.assertIs(proposal.intent, req.options[0].intent)
        self.assertEqual(result.decision_id, req.options[0].intent.decision_id)
        self.assertIs(result.provenance.origin, DecisionOrigin.SCRIPTED)

    def test_wait_is_explicit_and_script_exhaustion_is_error(self):
        req = request()
        adapter = scripted(req, wait=True)
        result = adapter.decide(req)
        self.assertIsNone(prepare_proposal(req, result, current=req.state, now=T0).intent)
        with self.assertRaises(OperatorUnavailable):
            adapter.decide(req)

    def test_mismatch_does_not_consume_sealed_step(self):
        req = request()
        adapter = scripted(req)
        with self.assertRaises(ContractError):
            adapter.decide(replace(req, opportunity_set_id="different"))
        self.assertEqual(adapter.remaining, 1)
        self.assertEqual(adapter.decide(req).selection, selection(req))

    def test_continuing_management_uses_new_targets_and_keeps_history(self):
        requests = tuple(request(kind, index=i + 1) for i, kind in enumerate((
            ActionKind.OPEN, ActionKind.AMEND_STOP, ActionKind.REDUCE, ActionKind.CLOSE,
        )))
        active = [requests[0]]
        adapter = ScriptedDecisionAdapter(tuple(ScriptStep(content_digest(x), selection(x)) for x in requests),
                                           adapter_id="script", clock=lambda: active[0].state.observed_at)
        session = OperatorSession(adapter, current_state=lambda: active[0].state,
                                  clock=lambda: active[0].state.observed_at)
        for req in requests:
            active[0] = req
            proposal = session.tick(req)
            self.assertEqual(proposal.intent.target_version, req.options[0].intent.target_version)
        self.assertEqual(len(session.attempts), 4)
        self.assertFalse(hasattr(session, "dispatch"))

    def test_stale_after_adapter_is_retained_and_not_proposed(self):
        req = request()
        current = [req.state]
        base = scripted(req)
        class Delayed:
            def decide(self, supplied):
                result = base.decide(supplied)
                current[0] = replace(req.state, state_id="changed", version=2)
                return result
        session = OperatorSession(Delayed(), current_state=lambda: current[0], clock=lambda: T0)
        with self.assertRaises(StaleDecision):
            session.tick(req)
        self.assertIsNone(session.attempts[0].proposal)
        self.assertEqual(session.attempts[0].result.selection, selection(req))

    def test_expired_action_rejected_even_when_state_is_fresh(self):
        req = request()
        with self.assertRaises(StaleDecision):
            prepare_proposal(req, scripted(req).decide(req), current=req.state, now=T0 + timedelta(seconds=30))

    def test_options_cannot_preallocate_different_decisions(self):
        req = request()
        changed = replace(req.options[0], action_ref="second", intent=replace(req.options[0].intent,
                          action_ref="second", decision_id="other"))
        with self.assertRaises(ContractError):
            OpportunityBuilder().build(request_id=req.request_id, opportunity_set_id=req.opportunity_set_id,
                                       state=req.state, options=req.options + (changed,), facts=req.facts, evidence=req.evidence)

    def test_entry_and_management_builders_do_not_mix_purposes(self):
        req = request(ActionKind.AMEND_STOP)
        kwargs = dict(request_id=req.request_id, opportunity_set_id=req.opportunity_set_id,
                      state=req.state, options=req.options, facts=req.facts, evidence=req.evidence)
        with self.assertRaises(ContractError):
            OpportunityBuilder().build(**kwargs)
        self.assertEqual(ManagementOpportunityBuilder().build(**kwargs), req)

    def test_required_real_alternatives_are_not_fabricated(self):
        req = request()
        with self.assertRaises(ContractError):
            OpportunityBuilder(require_two_distinct_choices=True).build(
                request_id=req.request_id, opportunity_set_id=req.opportunity_set_id, state=req.state,
                options=req.options, facts=req.facts, evidence=req.evidence)

    def test_archived_model_or_script_replay_cannot_emit_action_proposal(self):
        req = request()
        raw = canonical_bytes(selection(req)).decode()
        entry = ReplayEntry(content_digest(req), raw, sha256(raw.encode()).hexdigest(), "old-receipt")
        adapter = ReplayDecisionAdapter((entry,), adapter_id="replay", clock=lambda: T0)
        result = adapter.decide(req)
        self.assertIs(result.provenance.origin, DecisionOrigin.REPLAY)
        with self.assertRaises(ContractError):
            prepare_proposal(req, result, current=req.state, now=T0)
        with self.assertRaises(OperatorUnavailable):
            adapter.decide(req)

    def test_failure_cannot_evade_session_attempt_bound(self):
        class Broken:
            def decide(self, supplied):
                raise OperatorUnavailable("fixture failure")
        req = request()
        active = [req]
        session = OperatorSession(Broken(), current_state=lambda: active[0].state,
                                  clock=lambda: active[0].state.observed_at, max_decisions=1)
        with self.assertRaises(OperatorUnavailable):
            session.tick(req)
        active[0] = request(index=2)
        with self.assertRaises(OperatorUnavailable):
            session.tick(active[0])


class FakeBackend:
    """Unit fixture only. It does not demonstrate actual-model operation."""
    def __init__(self, req, *, extra_field=False, fail=False):
        self.req, self.extra_field, self.fail = req, extra_field, fail
        self.calls = []
    def count_input_tokens(self, invocation):
        return 100
    def infer(self, invocation):
        self.calls.append(invocation)
        if self.fail:
            raise RuntimeError("fixture transport failure")
        payload = json.loads(canonical_bytes(selection(self.req)).decode())
        if self.extra_field:
            payload["quantity"] = "999"
        return InferenceReply(json.dumps(payload), "unit-fake-receipt", content_digest(invocation), invocation.model,
                              T0, T0, 100, 30)


class FakeVerifier:
    def __init__(self, answer=True):
        self.answer = answer
    def verify(self, reply, invocation):
        return self.answer


class ActualModelBoundaryTests(unittest.TestCase):
    def make_adapter(self, backend=None, verifier=None, gate=None):
        return ActualModelDecisionAdapter(adapter_id="model", model=ModelSpecification(
            "fixture-model", "b" * 64, "xhigh", "prompt-v1"),
            budget=InferenceBudget(1, 1024, 256, 60, 60), backend=backend,
            receipt_verifier=verifier, execution_gate=gate, clock=lambda: T0)

    def test_default_constructor_is_disabled(self):
        with self.assertRaises(OperatorUnavailable):
            self.make_adapter().decide(request(origin=DecisionOrigin.ACTUAL_MODEL))

    def test_external_gate_denial_precedes_tokenization_and_inference(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        backend = FakeBackend(req)
        def denied(invocation):
            raise OperatorUnavailable("no bounded AWS approval")
        with self.assertRaises(OperatorUnavailable):
            self.make_adapter(backend, FakeVerifier(), denied).decide(req)
        self.assertEqual(backend.calls, [])

    def test_invented_authority_or_quantity_cannot_enter_result(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        backend = FakeBackend(req, extra_field=True)
        adapter = self.make_adapter(backend, FakeVerifier(), lambda x: None)
        with self.assertRaises(ContractError):
            adapter.decide(req)
        self.assertEqual(adapter.attempted_calls, 1)
        self.assertEqual(len(adapter.replies), 1)

    def test_independent_receipt_failure_blocks_model_claim(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        adapter = self.make_adapter(FakeBackend(req), FakeVerifier(False), lambda x: None)
        with self.assertRaises(ContractError):
            adapter.decide(req)

    def test_unknown_transport_consumes_call_and_never_retries(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        backend = FakeBackend(req, fail=True)
        adapter = self.make_adapter(backend, FakeVerifier(), lambda x: None)
        with self.assertRaises(RuntimeError):
            adapter.decide(req)
        with self.assertRaises(OperatorUnavailable):
            adapter.decide(req)
        self.assertEqual(len(backend.calls), 1)

    def test_input_ceiling_is_checked_before_call(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        backend = FakeBackend(req)
        backend.count_input_tokens = lambda invocation: 1025
        with self.assertRaises(OperatorUnavailable):
            self.make_adapter(backend, FakeVerifier(), lambda x: None).decide(req)
        self.assertEqual(backend.calls, [])

    def test_observed_model_mismatch_is_rejected(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        backend = FakeBackend(req)
        original = backend.infer
        backend.infer = lambda invocation: replace(original(invocation), model=replace(invocation.model, model_id="other"))
        with self.assertRaises(ContractError):
            self.make_adapter(backend, FakeVerifier(), lambda x: None).decide(req)

    def test_unit_fake_has_exact_invocation_and_request_hashes(self):
        req = request(origin=DecisionOrigin.ACTUAL_MODEL)
        backend = FakeBackend(req)
        result = self.make_adapter(backend, FakeVerifier(), lambda x: None).decide(req)
        self.assertEqual(result.provenance.request_sha256, content_digest(req))
        self.assertEqual(backend.calls[0].request_sha256, content_digest(req))
        self.assertNotEqual(content_digest(backend.calls[0]), content_digest(req))
        self.assertEqual(result.provenance.inference_receipt_id, "unit-fake-receipt")


if __name__ == "__main__":
    unittest.main()