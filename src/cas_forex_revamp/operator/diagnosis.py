"""U0 owner diagnosis protocol: fixed twins, counterbalancing and blind scoring.

Zero model calls. Preparing this protocol proves no user usefulness or semantic
twin validity. Independent case/key review and authorized UI execution remain
required. Development examples must never be relabeled unseen measured cases.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from statistics import median

from cas_forex_revamp.contracts import CheckStatus, ContractError, content_digest
from cas_forex_revamp.contracts.decisions import ids, text_value
from cas_forex_revamp.contracts.primitives import digest, identifier, integer
from cas_forex_revamp.rpa.projection import ReviewRecord


class DiagnosticFamily(StrEnum):
    SELECTION_ALTERNATIVES = "SELECTION_ALTERNATIVES"
    BLOCKED_UNKNOWN = "BLOCKED_UNKNOWN"
    SELECTION_EFFECT = "SELECTION_EFFECT"
    STALE_REVISION = "STALE_REVISION"


QUESTIONS = (
    "Identify the supported state and any important unknown effect.",
    "Identify the selected candidate and the relevant unchosen or blocked alternative.",
    "Identify the exact evidence or constraint, including its version and time.",
    "Identify the observed outcome or unresolved effect and the relevant revision.",
)


@dataclass(frozen=True, slots=True)
class DiagnosticEpisode:
    episode_id: str
    family: DiagnosticFamily
    record: ReviewRecord

    def __post_init__(self) -> None:
        identifier(self.episode_id, "episode_id")
        if not isinstance(self.family, DiagnosticFamily) or not isinstance(self.record, ReviewRecord):
            raise ContractError("diagnostic episode requires a family and frozen typed record")


@dataclass(frozen=True, slots=True)
class EpisodePair:
    """Human-authored independent audit reference is required, not invented by layout."""

    pair_id: str
    left: DiagnosticEpisode
    right: DiagnosticEpisode
    independent_twin_review_id: str
    hidden_answer_key_sha256: str

    def __post_init__(self) -> None:
        identifier(self.pair_id, "pair_id")
        identifier(self.independent_twin_review_id, "independent_twin_review_id")
        digest(self.hidden_answer_key_sha256, "hidden_answer_key_sha256")
        if self.left.family is not self.right.family or self.left.episode_id == self.right.episode_id:
            raise ContractError("pair needs distinct episode identities in the same diagnostic family")
        if content_digest(self.left.record) == content_digest(self.right.record):
            raise ContractError("measured twins cannot display the same exact source twice")


@dataclass(frozen=True, slots=True)
class DiagnosisPlan:
    study_id: str
    pairs: tuple[EpisodePair, ...]
    training_episode_ids: tuple[str, str]
    seconds_per_episode: int = 180
    minimum_correct_gain: int = 4
    max_atlas_time_ratio: Decimal = Decimal("1.10")

    def __post_init__(self) -> None:
        identifier(self.study_id, "study_id")
        if type(self.pairs) is not tuple or len(self.pairs) != 8 or any(not isinstance(x, EpisodePair) for x in self.pairs):
            raise ContractError("U0 requires exactly eight independently reviewed twin pairs")
        ids(tuple(x.pair_id for x in self.pairs), "pair_ids", 8)
        episode_ids = tuple(x.episode_id for pair in self.pairs for x in (pair.left, pair.right))
        ids(episode_ids, "episode_ids", 16)
        for family in DiagnosticFamily:
            if sum(pair.left.family is family for pair in self.pairs) != 2:
                raise ContractError("U0 needs two pairs from each of the four diagnostic families")
        if type(self.training_episode_ids) is not tuple or len(self.training_episode_ids) != 2:
            raise ContractError("two separate training examples are required")
        ids(self.training_episode_ids, "training_episode_ids", 2)
        if set(self.training_episode_ids) & set(episode_ids):
            raise ContractError("training/developer-tuned examples cannot enter the measured set")
        if (self.seconds_per_episode, self.minimum_correct_gain, self.max_atlas_time_ratio) != (180, 4, Decimal("1.10")):
            raise ContractError("this frozen U0 protocol uses 180s, +4/32 correct, and at most 10% slower")


@dataclass(frozen=True, slots=True)
class DiagnosisTrial:
    """Assignment belongs to the UI runner; never included in the blind score item."""

    trial_id: str
    episode: DiagnosticEpisode
    presentation: str
    order: int
    seconds_allowed: int
    questions: tuple[str, ...] = QUESTIONS


def prepare_diagnosis(plan: DiagnosisPlan) -> tuple[DiagnosisTrial, ...]:
    trials = []
    # Both twin assignment and view order are fixed before anyone sees outcomes.
    # Four pairs use each mapping and each order; the schedule is reproducible.
    for index, pair in enumerate(plan.pairs):
        assignments = ((pair.left, "LIST"), (pair.right, "ATLAS")) if index % 2 == 0 else (
            (pair.left, "ATLAS"), (pair.right, "LIST")
        )
        if (index // 2) % 2:
            assignments = tuple(reversed(assignments))
        for episode, presentation in assignments:
            trials.append(DiagnosisTrial("trial-" + content_digest((plan.study_id, episode.episode_id)),
                                         episode, presentation, len(trials), plan.seconds_per_episode))
    return tuple(trials)


@dataclass(frozen=True, slots=True)
class BlindResponse:
    """No condition, pair label, presentation or outcome key in the scorer input."""

    trial_id: str
    answers: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    elapsed_seconds: int
    navigation_actions: int

    def __post_init__(self) -> None:
        identifier(self.trial_id, "trial_id")
        if type(self.answers) is not tuple or len(self.answers) != 4:
            raise ContractError("exactly four answer slots are required; empty means unanswered")
        for answer in self.answers:
            if not isinstance(answer, str) or len(answer.encode("utf-8")) > 2048:
                raise ContractError("answer text exceeds the bounded public response size")
        ids(self.evidence_ids, "evidence_ids")
        integer(self.elapsed_seconds, "elapsed_seconds")
        integer(self.navigation_actions, "navigation_actions")


@dataclass(frozen=True, slots=True)
class BlindScore:
    """Independent scorer's item, joined with presentation only after scoring."""

    trial_id: str
    correct: tuple[bool, bool, bool, bool]
    critical_errors: int
    evidence_errors: int
    scorer_id: str
    answer_key_sha256: str

    def __post_init__(self) -> None:
        identifier(self.trial_id, "trial_id")
        identifier(self.scorer_id, "scorer_id")
        digest(self.answer_key_sha256, "answer_key_sha256")
        if type(self.correct) is not tuple or len(self.correct) != 4 or any(type(x) is not bool for x in self.correct):
            raise ContractError("blind scoring requires four boolean answers")
        integer(self.critical_errors, "critical_errors")
        integer(self.evidence_errors, "evidence_errors")


@dataclass(frozen=True, slots=True)
class DiagnosisSummary:
    status: CheckStatus
    completed_per_view: tuple[tuple[str, int], ...]
    correct_per_view: tuple[tuple[str, int], ...]
    critical_errors_per_view: tuple[tuple[str, int], ...]
    median_seconds_per_view: tuple[tuple[str, Decimal | None], ...]
    retention_threshold_met: bool | None
    claim_scope: str = "OWNER_DIAGNOSIS_ONLY; no AI-decision, learning, or trading-edge claim"


def score_diagnosis(plan: DiagnosisPlan, responses: tuple[BlindResponse, ...],
                    scores: tuple[BlindScore, ...]) -> DiagnosisSummary:
    trials = {x.trial_id: x for x in prepare_diagnosis(plan)}
    response_map = {x.trial_id: x for x in responses}
    score_map = {x.trial_id: x for x in scores}
    if len(response_map) != len(responses) or len(score_map) != len(scores):
        raise ContractError("retain the first response/score; duplicate retries are not permitted")
    if set(response_map) != set(score_map) or not set(response_map) <= set(trials):
        raise ContractError("responses and blinded scores must refer to the same known trials")
    key_by_episode = {episode.episode_id: pair.hidden_answer_key_sha256
                      for pair in plan.pairs for episode in (pair.left, pair.right)}
    for trial_id, score in score_map.items():
        if score.answer_key_sha256 != key_by_episode[trials[trial_id].episode.episode_id]:
            raise ContractError("blind score used a different frozen answer key")
        if response_map[trial_id].elapsed_seconds > plan.seconds_per_episode:
            raise ContractError("response exceeded the fixed review window; cannot score it as on-time")
        if any(ok and not answer.strip() for ok, answer in zip(score.correct, response_map[trial_id].answers)):
            raise ContractError("an unanswered slot cannot be correct")
    counts, correct, critical, times = {}, {}, {}, {}
    for view in ("LIST", "ATLAS"):
        ids_for_view = [key for key in response_map if trials[key].presentation == view]
        counts[view] = len(ids_for_view)
        correct[view] = sum(sum(score_map[key].correct) for key in ids_for_view)
        critical[view] = sum(score_map[key].critical_errors for key in ids_for_view)
        durations = [Decimal(response_map[key].elapsed_seconds) for key in ids_for_view]
        times[view] = median(durations) if durations else None
    if not response_map:
        status, retained = CheckStatus.NOT_RUN, None
    elif len(response_map) != 16:
        status, retained = CheckStatus.INCOMPLETE, None
    else:
        # Completed study with no practical benefit remains a scoped negative result.
        retained = (correct["ATLAS"] - correct["LIST"] >= plan.minimum_correct_gain
                    and sum(critical.values()) == 0
                    and times["ATLAS"] <= times["LIST"] * plan.max_atlas_time_ratio)
        status = CheckStatus.PASS if retained else CheckStatus.FAIL
    return DiagnosisSummary(status, tuple(counts.items()), tuple(correct.items()),
                            tuple(critical.items()), tuple(times.items()), retained)