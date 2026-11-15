"""Authored U0/U1 protocol tests. All runtime execution remains NOT_RUN."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
import json
import unittest

from cas_forex_revamp.contracts import (
    CheckStatus, ContractError, DecisionOrigin, InferenceBudget, canonical_bytes,
)
from cas_forex_revamp.operator.comparison import (
    ArmAttempt, ComparisonCase, EvidenceAvailability, HiddenActionKey, InputPair,
    MatchedModelHarness, decode_packet, prepare_comparison, prepare_pair, score_attempts,
)
from cas_forex_revamp.operator.diagnosis import (
    BlindResponse, BlindScore, DiagnosticEpisode, DiagnosticFamily, DiagnosisPlan,
    EpisodePair, prepare_diagnosis, score_diagnosis,
)
from cas_forex_revamp.operator.model import ModelSpecification
from cas_forex_revamp.rpa.projection import ReviewRecord

# Helpers are in this same owned test directory; no production fixture import.
from test_operator import T0, FakeBackend, FakeVerifier, request, scripted


def case(index=1):
    req = request(index=index, origin=DecisionOrigin.ACTUAL_MODEL)
    availability = tuple(EvidenceAvailability(x.evidence_id, x.content_sha256, req.state.observed_at)
                         for x in req.evidence)
    return ComparisonCase(f"case-{index}", req, req.state.observed_at, availability)


def study(*, approval=None):
    return prepare_comparison(study_id="unit-study", cases=(case(),),
                              model=ModelSpecification("unit-model", "b" * 64, "xhigh", "prompt-v1"),
                              operator_build_id="build", sealed_case_set_sha256="c" * 64,
                              budget_per_arm=InferenceBudget(1, 1024, 256, 60, 60),
                              execution_approval_id=approval, seed=17)


class MatchedInputTests(unittest.TestCase):
    def test_flat_and_typed_have_identical_full_semantic_content(self):
        pair = prepare_pair(case())
        self.assertNotEqual(pair.flat_json, pair.atlas_json)
        self.assertEqual(decode_packet(pair.flat_json), decode_packet(pair.atlas_json))
        normalized = decode_packet(pair.flat_json)
        self.assertTrue(any(x["kind"] == "WAIT" for x in normalized["records"]))
        self.assertTrue(any(x["kind"] == "CITES" for x in normalized["relations"]))
        self.assertIn('"quantity":"10"', pair.flat_json)

    def test_extra_atlas_information_fails_parity(self):
        pair = prepare_pair(case())
        changed = json.loads(pair.atlas_json)
        changed["groups"][0]["records"][0]["value"]["oracle_answer"] = "hidden"
        with self.assertRaises(ContractError):
            replace(pair, atlas_json=json.dumps(changed))

    def test_omitted_flat_relation_is_not_equal_information(self):
        pair = prepare_pair(case())
        changed = json.loads(pair.flat_json)
        changed["relations"] = []
        with self.assertRaises(ContractError):
            replace(pair, flat_json=json.dumps(changed))

    def test_duplicate_packet_keys_fail(self):
        pair = prepare_pair(case())
        altered = pair.flat_json[:-1] + ',"relations":[]}'
        with self.assertRaises(ContractError):
            decode_packet(altered)

    def test_future_availability_and_missing_coverage_fail(self):
        original = case()
        for availability in ((), (replace(original.evidence_availability[0],
                                          available_at=original.cutoff + timedelta(seconds=1)),)):
            with self.subTest(availability=availability), self.assertRaises(ContractError):
                replace(original, evidence_availability=availability)

    def test_claimed_plan_hash_is_checked_against_actual_packets(self):
        prepared = study()
        with self.assertRaises(ContractError):
            replace(prepared, plan=replace(prepared.plan, causal_information_sha256="d" * 64))

    def test_preparation_does_not_embed_hidden_key_or_approve_execution(self):
        prepared = study()
        self.assertIsNone(prepared.plan.execution_approval_id)
        self.assertNotIn("allowed_action_refs", prepared.pairs[0].flat_json)
        self.assertNotIn("sealed_case_set_sha256", prepared.pairs[0].atlas_json)
        backend = FakeBackend(prepared.pairs[0].case.request)
        runner = MatchedModelHarness(prepared, backend=backend, receipt_verifier=FakeVerifier(),
                                     execution_gate=lambda x: None, clock=lambda: T0)
        self.assertIs(runner.status, CheckStatus.NOT_RUN)
        with self.assertRaises(ContractError):
            runner.run_next()
        self.assertEqual(backend.calls, [])

    def test_fake_unit_calls_use_independent_sessions_and_matched_settings(self):
        prepared = study(approval="unit-fixture-only")
        backend = FakeBackend(prepared.pairs[0].case.request)
        runner = MatchedModelHarness(prepared, backend=backend, receipt_verifier=FakeVerifier(),
                                     execution_gate=lambda x: None, clock=lambda: T0)
        attempts = runner.run_next()
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(backend.calls[0].session_id, backend.calls[1].session_id)
        for field in ("model", "system_policy", "budget", "output_schema_id", "seed"):
            self.assertEqual(getattr(backend.calls[0], field), getattr(backend.calls[1], field))
        self.assertEqual(decode_packet(backend.calls[0].packet_json), decode_packet(backend.calls[1].packet_json))
        with self.assertRaises(ContractError):
            runner.run_next()

    def test_failed_first_attempt_stops_without_tuning_or_hidden_retry(self):
        prepared = study(approval="unit-fixture-only")
        backend = FakeBackend(prepared.pairs[0].case.request, fail=True)
        runner = MatchedModelHarness(prepared, backend=backend, receipt_verifier=FakeVerifier(),
                                     execution_gate=lambda x: None, clock=lambda: T0)
        attempts = runner.run_next()
        self.assertEqual(len(attempts), 1)
        self.assertIs(runner.status, CheckStatus.INCOMPLETE)
        self.assertEqual(len(backend.calls), 1)
        keys = (HiddenActionKey("case-1", ("action-1",)),)
        scores = score_attempts(prepared, attempts, keys)
        self.assertEqual(scores[0].valid_decisions, 0)
        self.assertEqual(scores[1].attempted, 0)

    def test_scripted_response_cannot_count_as_model_answer(self):
        prepared = study()
        req = prepared.pairs[0].case.request
        result = scripted(req).decide(req)
        attempt = ArmAttempt("case-1", "FLAT_LIST", CheckStatus.PASS, result, None)
        with self.assertRaises(ContractError):
            score_attempts(prepared, (attempt,), (HiddenActionKey("case-1", ("action-1",)),))

    def test_model_label_and_fixture_receipt_alone_cannot_pass_scoring(self):
        prepared = study(approval="unit-fixture-only")
        backend = FakeBackend(prepared.pairs[0].case.request)
        runner = MatchedModelHarness(prepared, backend=backend, receipt_verifier=FakeVerifier(),
                                     execution_gate=lambda x: None, clock=lambda: T0)
        attempts = runner.run_next()
        with self.assertRaises(ContractError):
            score_attempts(prepared, attempts, (HiddenActionKey("case-1", ("action-1",)),))

    def test_untouched_denominators_are_not_zero_error_success(self):
        scores = score_attempts(study(), (), (HiddenActionKey("case-1", (None, "action-1")),))
        self.assertEqual([x.planned for x in scores], [1, 1])
        self.assertTrue(all(x.status is CheckStatus.NOT_RUN for x in scores))


def diagnosis_plan():
    pairs = []
    for i in range(8):
        episodes = []
        family = tuple(DiagnosticFamily)[i // 2]
        for offset in (0, 1):
            index = i * 2 + offset + 1
            req = request(index=index)
            episodes.append(DiagnosticEpisode(f"episode-{index}", family,
                            ReviewRecord(req, req.state.observed_at, scripted(req).decide(req))))
        pairs.append(EpisodePair(f"pair-{i}", *episodes, "unit-twin-review", "e" * 64))
    return DiagnosisPlan("u0-unit", tuple(pairs), ("training-list", "training-atlas"))


def full_responses(plan, *, atlas_errors=0, atlas_seconds=100, list_seconds=100):
    responses, scores = [], []
    for trial in prepare_diagnosis(plan):
        atlas = trial.presentation == "ATLAS"
        responses.append(BlindResponse(trial.trial_id, ("state", "choice", "evidence", "outcome"), (),
                                        atlas_seconds if atlas else list_seconds, 2))
        scores.append(BlindScore(trial.trial_id, (True, True, True, atlas), atlas_errors if atlas else 0,
                                 0, "blind-unit-scorer", "e" * 64))
    return tuple(responses), tuple(scores)


class OwnerDiagnosisTests(unittest.TestCase):
    def test_schedule_has_eight_tasks_per_view_and_no_repeated_episode(self):
        trials = prepare_diagnosis(diagnosis_plan())
        self.assertEqual(len(trials), 16)
        self.assertEqual(sum(x.presentation == "LIST" for x in trials), 8)
        self.assertEqual(len({x.episode.episode_id for x in trials}), 16)
        self.assertTrue(all(x.seconds_allowed == 180 for x in trials))

    def test_training_cannot_be_promoted_to_measured_trial(self):
        plan = diagnosis_plan()
        with self.assertRaises(ContractError):
            replace(plan, training_episode_ids=(plan.pairs[0].left.episode_id, "training-other"))

    def test_unrun_and_partial_keep_denominators_and_no_benefit_claim(self):
        plan = diagnosis_plan()
        self.assertIs(score_diagnosis(plan, (), ()).status, CheckStatus.NOT_RUN)
        responses, scores = full_responses(plan)
        summary = score_diagnosis(plan, responses[:1], scores[:1])
        self.assertIs(summary.status, CheckStatus.INCOMPLETE)
        self.assertIsNone(summary.retention_threshold_met)

    def test_critical_errors_block_retention_even_with_more_correct_answers(self):
        plan = diagnosis_plan()
        responses, scores = full_responses(plan, atlas_errors=1)
        summary = score_diagnosis(plan, responses, scores)
        self.assertIs(summary.status, CheckStatus.FAIL)
        self.assertFalse(summary.retention_threshold_met)

    def test_time_overhead_blocks_retention(self):
        plan = diagnosis_plan()
        responses, scores = full_responses(plan, atlas_seconds=112)
        self.assertFalse(score_diagnosis(plan, responses, scores).retention_threshold_met)

    def test_blind_score_key_mismatch_rejected(self):
        plan = diagnosis_plan()
        responses, scores = full_responses(plan)
        with self.assertRaises(ContractError):
            score_diagnosis(plan, responses, (replace(scores[0], answer_key_sha256="f" * 64),) + scores[1:])

    def test_owner_specific_threshold_cannot_be_called_ai_benefit(self):
        plan = diagnosis_plan()
        responses, scores = full_responses(plan)
        summary = score_diagnosis(plan, responses, scores)
        self.assertTrue(summary.retention_threshold_met)
        self.assertIn("OWNER_DIAGNOSIS_ONLY", summary.claim_scope)
        self.assertEqual(dict(summary.correct_per_view), {"LIST": 24, "ATLAS": 32})


if __name__ == "__main__":
    unittest.main()