"""Declared study limits are separate from execution approval and measured results."""

from dataclasses import dataclass

from .primitives import ContractError, digest, identifier, integer


@dataclass(frozen=True, slots=True)
class InferenceBudget:
    max_calls: int
    max_input_tokens_per_call: int
    max_generated_tokens_per_call: int
    max_seconds_per_call: int
    max_total_seconds: int

    def __post_init__(self) -> None:
        for field in ("max_calls", "max_input_tokens_per_call", "max_generated_tokens_per_call", "max_seconds_per_call", "max_total_seconds"):
            integer(getattr(self, field), field, minimum=1)
        if self.max_seconds_per_call > self.max_total_seconds:
            raise ContractError("per-call time cannot exceed the entire declared study limit")


@dataclass(frozen=True, slots=True)
class ModelInputComparisonPlan:
    """U1: same information and operator; only flat/atlas representation differs.

    Digests require independent verification against the actual paired packets.
    Constructing this object neither approves calls nor proves information parity.
    """

    study_id: str
    model_id: str
    model_artifact_sha256: str
    prompt_policy_id: str
    operator_build_id: str
    causal_information_sha256: str
    candidate_catalog_sha256: str
    history_sha256: str
    output_schema_id: str
    sealed_case_set_sha256: str
    budget_per_arm: InferenceBudget
    flat_arm_id: str = "FLAT_LIST"
    atlas_arm_id: str = "TYPED_ATLAS"
    execution_approval_id: str | None = None

    def __post_init__(self) -> None:
        for field in ("study_id", "model_id", "prompt_policy_id", "operator_build_id", "output_schema_id"):
            identifier(getattr(self, field), field)
        for field in ("model_artifact_sha256", "causal_information_sha256", "candidate_catalog_sha256", "history_sha256", "sealed_case_set_sha256"):
            digest(getattr(self, field), field)
        if not isinstance(self.budget_per_arm, InferenceBudget):
            raise ContractError("comparison requires an identical explicit budget for both arms")
        if (self.flat_arm_id, self.atlas_arm_id) != ("FLAT_LIST", "TYPED_ATLAS"):
            raise ContractError("U1 compares the declared flat and typed-atlas representations")
        if self.execution_approval_id is not None:
            identifier(self.execution_approval_id, "execution_approval_id")

    @property
    def total_call_ceiling(self) -> int:
        return self.budget_per_arm.max_calls * 2
