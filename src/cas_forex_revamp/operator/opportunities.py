"""Assemble exact supplied opportunities without inventing strategy or risk policy."""

from __future__ import annotations

from cas_forex_revamp.contracts import (
    ActionKind, ActionOption, ContractError, DecisionFact, DecisionRequest,
    EvidenceReference, StateReference,
)

from .decisions import decision_identity


class OpportunityBuilder:
    """Entry catalog assembly. Eligibility/risk is independently rechecked by core."""

    _allowed_kinds = frozenset((ActionKind.OPEN, ActionKind.ADD))

    def __init__(self, *, require_two_distinct_choices: bool = False) -> None:
        if type(require_two_distinct_choices) is not bool:
            raise ContractError("distinct-choice requirement must be explicit boolean")
        self._require_two = require_two_distinct_choices

    def build(self, *, request_id: str, opportunity_set_id: str, state: StateReference,
              options: tuple[ActionOption, ...], facts: tuple[DecisionFact, ...],
              evidence: tuple[EvidenceReference, ...]) -> DecisionRequest:
        request = DecisionRequest(request_id, opportunity_set_id, state, options, facts, evidence)
        decision_identity(request)
        if any(x.intent.kind not in self._allowed_kinds for x in request.options):
            raise ContractError("action kind is outside this opportunity builder's purpose")
        if len({x.intent.origin for x in request.options}) > 1:
            raise ContractError("one request cannot mix scripted/model/owner intent origins")
        if self._require_two and len({(x.strategy_id, x.timeframe) for x in request.options}) < 2:
            raise ContractError("this case requires two distinct strategy/timeframe alternatives plus WAIT")
        # WAIT is always available through the shared null selection, even with no options.
        return request


class ManagementOpportunityBuilder(OpportunityBuilder):
    """Exact target/version management, including hold via explicit WAIT.

    CANCEL_ORDER targets the original command ID at its independently observed
    receipt sequence. This assembler never obtains or guesses that version.
    """

    _allowed_kinds = frozenset((ActionKind.REDUCE, ActionKind.CLOSE,
                                ActionKind.AMEND_STOP, ActionKind.CANCEL_ORDER))