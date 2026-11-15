"""Accepted candidate03 wire types. Shape validation is not authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypedDict
from .common import JSONValue, StructuralRecord, SelectedShapeValidator, ValidationLimits
if TYPE_CHECKING:
    from . import method, capture, protected, completion, release, checkpoint

ProtectedRecordKind: TypeAlias = Literal['RECORD_ATTESTATION', 'PROTECTED_REGISTRATION', 'ROOT_OBSERVATION', 'PROVIDER_SELECTION', 'COMPLETION_SELECTION', 'COMMAND_PIN', 'PARSER_PIN', 'COLLECTION_INVENTORY', 'TEST_STREAM', 'TEST_PROCESS_CAPTURE', 'TEST_GROUP_REPORT', 'SOURCE_TEST_REPORT', 'SOURCE_TEST_OBSERVATION', 'SOURCE_TEST_COMPLETION', 'RETAINED_FACT', 'SCORING_PLAN', 'SCORING_PLAN_REVIEW', 'RETAINED_ATTEMPT_BUNDLE', 'BUNDLE_FINALIZATION', 'TERMINAL_SCORE', 'AGGREGATE_BODY', 'REDACTION_APPROVAL', 'RELEASE_SELECTION', 'RELEASE_RECEIPT', 'EXTERNAL_CUSTODY_AUTHORITY', 'RELEASE_CONSUMPTION', 'EXTERNAL_RELEASE_EVIDENCE', 'TEST_FRAMEWORK_REPORT', 'SOURCE_INVENTORY', 'TEST_DISCOVERY_REPORT', 'PUBLIC_AGGREGATE_BINDINGS']
PublisherRole: TypeAlias = Literal['EXTERNAL_AUTHORIZER', 'REGISTRY_CUSTODIAN', 'COMPLETION_OBSERVER', 'TRANSPORT_OBSERVER', 'CORE_OBSERVER', 'VENUE_OBSERVER', 'CUSTODY', 'PRIVATE_MAPPER', 'INDEPENDENT_REVIEWER', 'RELEASE_ISSUER', 'INDEPENDENT_SCORER', 'INDEPENDENT_REDACTOR', 'CONTROLLER']
FactKind: TypeAlias = Literal['ATTEMPT', 'OUTCOME', 'PRE_STATE', 'POST_STATE', 'AUTHORIZATION', 'DISPATCH', 'VENUE_EFFECT', 'CONTEXT']
ProtectedPurpose: TypeAlias = Literal['record-attestation', 'protected-record-registration', 'protected-root-observation', 'independent-observer-selection', 'independent-runtime-selection', 'independent-aggregate-selection', 'completion-selection', 'test-command-pin', 'test-parser-pin', 'test-collection-inventory', 'test-stream', 'test-process-capture', 'test-group-report', 'original-source-test-report', 'source-test-observation', 'source-test-completion', 'retained-attempt', 'retained-outcome', 'retained-pre_state', 'retained-post_state', 'retained-authorization', 'retained-dispatch', 'retained-venue_effect', 'retained-context', 'independent-scoring-plan', 'scoring-plan-review', 'complete-retained-evaluation-bundle', 'retained-bundle-finalization', 'independent-terminal-score', 'public-aggregate-body', 'independent-aggregate-redaction', 'custody-release-selection', 'custody-release-receipt', 'external-custody-authority', 'release-consumption', 'release-evidence:scope_sha256', 'release-evidence:issuer_binding_sha256', 'release-evidence:issuer_authentication_evidence_sha256', 'release-evidence:execution_identity_sha256', 'release-evidence:separate_execution_authorization_sha256', 'release-evidence:stop_egress_deadline_proofs_sha256', 'release-evidence:original_clock_and_budget_binding_sha256', 'release-evidence:complete_freeze_manifest_sha256', 'release-evidence:custody_manifest_sha256', 'release-evidence:inherited_exposure_heads_sha256', 'release-evidence:accepted_private_mapping_sha256', 'release-evidence:independent_review_attestation_sha256', 'release-evidence:approved_topology_sha256', 'release-evidence:trusted_observer_binding_sha256', 'release-evidence:role_read_isolation_receipt_sha256', 'release-evidence:controller_identity_sha256', 'release-evidence:authorized_current_frame_channel_sha256', 'test-framework-report', 'completion-source-inventory', 'test-discovery-report', 'approved-public-aggregate-bindings']
ReleaseEvidenceSlot: TypeAlias = Literal['scope_sha256', 'issuer_binding_sha256', 'issuer_authentication_evidence_sha256', 'execution_identity_sha256', 'separate_execution_authorization_sha256', 'stop_egress_deadline_proofs_sha256', 'original_clock_and_budget_binding_sha256', 'complete_freeze_manifest_sha256', 'custody_manifest_sha256', 'inherited_exposure_heads_sha256', 'accepted_private_mapping_sha256', 'independent_review_attestation_sha256', 'approved_topology_sha256', 'trusted_observer_binding_sha256', 'role_read_isolation_receipt_sha256', 'controller_identity_sha256', 'authorized_current_frame_channel_sha256']
EvidenceUse: TypeAlias = Literal['METHOD_SETUP_ONLY', 'SOURCE_COMPLETION', 'RETAINED_EVALUATION', 'PRIVATE_RELEASE', 'FINAL_AGGREGATE', 'AUTHORITY_METADATA']
Source04FailureCode: TypeAlias = Literal['CUSTODY_GATE', 'ISOLATION_GATE', 'PIN_MISMATCH', 'TOKEN_GATE', 'TRANSPORT_GATE', 'MODEL_PROTOCOL_GATE', 'MANDATORY_CHECK_FAILED', 'TIME_BUDGET', 'CALL_BUDGET', 'EVIDENCE_UNAVAILABLE']

class EvaluationBinding(TypedDict):
    run_id: str
    epoch: int
    source_manifest_sha256: str
    config_sha256: str
    topology_sha256: str
    original_window_sha256: str

class ProtectedRecordRef(TypedDict):
    format: Literal['forex.protected-record-ref/1']
    binding: EvaluationBinding
    publisher_selection_sha256: str
    root_id: str
    object_id: str
    bytes: int
    sha256: str
    record_kind: ProtectedRecordKind
    publisher_id: str
    purpose: ProtectedPurpose

class ProtectedRootSelection(TypedDict):
    root_id: str
    root_instance_id: str
    absolute_directory: str
    owner_principal_id: str
    expected_uid: int
    expected_gid: int
    expected_mode: int
    expected_device: int
    expected_inode: int
    reader_principal_ids: list[str]
    writer_principal_ids: list[str]
    restore_authority_id: str
    object_layout: Literal['objects/<lowercase-sha256>']
    maximum_object_bytes: Literal[4194304]

class PublisherGrant(TypedDict):
    publisher_id: str
    role: PublisherRole
    signer_public_sha256: str
    component_manifest_sha256: str
    not_before_utc: str
    expires_at_utc: str
    grants: list[PublicationGrant]

class PublicationGrant(TypedDict):
    root_id: str
    record_kind: ProtectedRecordKind
    purpose: ProtectedPurpose
    permitted_use: EvidenceUse
    payload_schema_sha256: str

class PublisherRootSelection(TypedDict):
    format: Literal['forex.publisher-root-selection/1']
    selection_id: str
    binding: EvaluationBinding
    authorizer_id: str
    not_before_utc: str
    expires_at_utc: str
    roots: list[ProtectedRootSelection]
    publishers: list[PublisherGrant]
    registry_authority_id: str
    registry_root_id: str
    registry_signer_public_sha256: str
    registry_component_sha256: str

class ProtectedRootObservation(TypedDict):
    format: Literal['forex.protected-root-observation/1']
    binding: EvaluationBinding
    publisher_selection_sha256: str
    root_id: str
    root_instance_id: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    mount_inventory_sha256: str
    observed: method.Stamp

class ProtectedAttestationBody(TypedDict):
    format: Literal['forex.protected-record-attestation/1']
    record_ref: ProtectedRecordRef
    attestation_id: str
    publisher_id: str
    purpose: ProtectedPurpose
    issued_at_utc: str
    expires_at_utc: str

class ProtectedRecordEnvelope(TypedDict):
    body: ProtectedAttestationBody
    algorithm: Literal['Ed25519']
    signer_sha256: str
    signature_hex: str

class ProtectedRegistration(TypedDict):
    format: Literal['forex.protected-record-registration/2']
    binding: EvaluationBinding
    publisher_selection_sha256: str
    registry_authority_id: str
    sequence: int
    previous_entry_sha256: str
    record_ref: ProtectedRecordRef
    attestation_ref: ProtectedRecordRef
    registered_at_utc: str

class RegistrySignature(TypedDict):
    registration: ProtectedRegistration
    algorithm: Literal['Ed25519']
    signer_sha256: str
    signature_hex: str

class ProtectedReferenceUse(TypedDict):
    reference: ProtectedRecordRef
    registration_sha256: str
    required_use: EvidenceUse

class RetainedFact2(TypedDict):
    format: Literal['forex.retained-fact/2']
    binding: EvaluationBinding
    record_id: str
    kind: FactKind
    step_id: str | None
    payload_schema_sha256: str
    payload: JSONValue

class RetainedBundle2(TypedDict):
    format: Literal['forex.retained-attempt-bundle/2']
    binding: EvaluationBinding
    records: list[RetainedFactUse]
    finalization: ProtectedReferenceUse

class RetainedFactUse(TypedDict):
    kind: FactKind
    fact: ProtectedReferenceUse

class BundleFinalization2(TypedDict):
    format: Literal['forex.retained-bundle-finalization/2']
    binding: EvaluationBinding
    lifecycle: Literal['FINAL', 'ABORTED']
    records_content_sha256: str
    original_attempt_order: list[str]
    terminal_at_utc: str
    broad_failure_codes: list[Source04FailureCode]

class ReleaseEvidenceUse(TypedDict):
    slot: ReleaseEvidenceSlot
    evidence: ProtectedReferenceUse

class ReleaseSelection3(TypedDict):
    format: Literal['forex.independent-release-selection/3']
    binding: EvaluationBinding
    release_id: str
    publisher_selection_sha256: str
    issuer_id: str
    observer_id: str
    controller_id: str
    channel_binding_sha256: str
    scope_sha256: str
    release_evidence: list[ReleaseEvidenceUse]
    source_test_completion: ProtectedReferenceUse
    method_decision: method.ObjectRef
    method_exposure: method.ObjectRef
    setup_original_key: method.OriginalSetupKey
    setup_budget_sha256: str
    method_appointment_sha256: str
    checkpoint_access_selection_sha256: str
    expected_decision_generation: int
    expected_decision_head_sha256: str
    not_before_utc: str
    expires_at_utc: str

class ReleaseReceipt3(TypedDict):
    format: Literal['forex.custody-release-receipt/3']
    binding: EvaluationBinding
    release_id: str
    selection_ref: ProtectedRecordRef
    issuer_id: str
    controller_id: str
    channel_binding_sha256: str
    scope_sha256: str
    evidence_uses_sha256: str
    completion_ref: ProtectedRecordRef
    method_decision_ref: method.ObjectRef
    method_exposure_ref: method.ObjectRef
    original_setup_key: method.OriginalSetupKey
    setup_budget_sha256: str
    method_appointment_sha256: str
    checkpoint_access_selection_sha256: str
    expected_decision_generation: int
    expected_decision_head_sha256: str
    issued_at_utc: str
    not_before_utc: str
    expires_at_utc: str

class ExternalCustodyAuthority2(TypedDict):
    format: Literal['forex.external-custody-authority/2']
    binding: EvaluationBinding
    publisher_selection_sha256: str
    selection: ProtectedReferenceUse
    release: ProtectedReferenceUse

class ScoringPlan2(TypedDict):
    format: Literal['forex.independent-scoring-plan/2']
    run_id: str
    epoch: int
    frozen_at_utc: str
    expected_outcome_author_sha256: str
    accepted_mapping_sha256: str
    steps: list[ScoringStep]
    assertions: list[ScoringAssertion]

class ScoringStep(TypedDict):
    step_id: str
    permissible_action_refs: list[str | None]
    required_disposition: Literal['ACT', 'WAIT', 'HOLD', 'STAND_DOWN']
    expected_pre: JSONValue
    expected_post: JSONValue
    requires_dispatch: bool
    requires_venue_effect: bool
    required_evidence_ids: list[str]
    assertion_ids: list[str]

class ScoringAssertion(TypedDict):
    assertion_id: str
    operator: Literal['EQUALS', 'EQUAL_FIELDS', 'ORDERED_TIMES', 'STRICT_INCREASE']
    operands: list[ScoringOperand]
    expected: JSONValue

class ScoringOperand(TypedDict):
    step_id: str
    kind: FactKind
    path: list[str]

class ScoringPlanReview2(TypedDict):
    format: Literal['forex.independent-scoring-plan-review/2']
    plan_sha256: str
    accepted_mapping_sha256: str
    expected_outcome_author_sha256: str
    required_step_ids: list[str]
    required_assertion_ids: list[str]
    coverage: Literal['ALL_REQUIRED_ASSERTIONS']

class TerminalScore2(TypedDict):
    format: Literal['forex.independent-terminal-score/2']
    run_id: str
    epoch: int
    lifecycle: Literal['FINAL', 'ABORTED']
    source_freeze_manifest_sha256: str
    custody_public_manifest_sha256: str
    retained_evaluation_bundle_sha256: str
    accepted_private_mapping_sha256: str
    mandatory_step_ids: list[str]
    mandatory_assertion_ids: list[str]
    steps: list[TerminalStep]
    assertions: list[TerminalAssertion]
    generation_attempts: list[TerminalAttempt]
    broad_failure_codes: list[Source04FailureCode]

class TerminalStep(TypedDict):
    step_id: str
    attempt_id: str | None
    outcome: Literal['PASS', 'FAIL', 'INCOMPLETE']
    independent_evidence_receipt: ProtectedReferenceUse | None

class TerminalAssertion(TypedDict):
    assertion_id: str
    outcome: Literal['PASS', 'FAIL', 'INCOMPLETE']
    independent_evidence_receipt: ProtectedReferenceUse | None

class TerminalAttempt(TypedDict):
    attempt_id: str
    phase: Literal['PROBE', 'MANDATORY']
    outcome: Literal['COMPLETE', 'FAILED', 'UNKNOWN']
    original_attempt_receipt: ProtectedReferenceUse
    original_outcome_receipt: ProtectedReferenceUse

class RedactionApproval2(TypedDict):
    format: Literal['forex.independent-aggregate-redaction/2']
    reviewer_binding_sha256: str
    run_id: str
    final_or_aborted: bool
    retained_evaluation_bundle_sha256: str
    approved_aggregate_body_sha256: str
    independent_complete_scoring_accepted: bool

class PublicAggregateBindings1(TypedDict):
    format: Literal['forex.approved-public-aggregate-bindings/1']
    run_id: str
    source_freeze_manifest_sha256: str
    custody_public_manifest_sha256: str
    retained_evaluation_bundle_sha256: str
    reviewer_binding_sha256: str

def validate(type_name: str, value: JSONValue, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import validate_record
    return validate_record('protected', type_name, value, shape_validator=shape_validator, limits=limits)

def decode(type_name: str, raw: bytes, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import decode_record
    return decode_record('protected', type_name, raw, shape_validator=shape_validator, limits=limits)

RECORD_DOMAIN = b"CAS_FOREX_PROTECTED_RECORD_V1\n"
REGISTRATION_DOMAIN = b"CAS_FOREX_PROTECTED_REGISTRATION_V2\n"
PUBLISHER_SELECTION_DOMAIN = b"CAS_FOREX_PUBLISHER_ROOT_SELECTION_V1\n"

def record_signing_bytes(body: ProtectedAttestationBody) -> bytes:
    return RECORD_DOMAIN + validate("ProtectedAttestationBody", body).raw

def registration_signing_bytes(body: ProtectedRegistration) -> bytes:
    return REGISTRATION_DOMAIN + validate("ProtectedRegistration", body).raw

def selection_signing_bytes(body: PublisherRootSelection) -> bytes:
    return PUBLISHER_SELECTION_DOMAIN + validate("PublisherRootSelection", body).raw

class ProtectedResolverPort(Protocol):
    """Must enforce exact externally selected root/grant; no supplied paths."""
    def resolve(self, use: ProtectedReferenceUse, *, selection: PublisherRootSelection,
                now: method.Stamp) -> bytes: ...

class RegistryPort(Protocol):
    def register_exact_record(self, raw: bytes, reference: ProtectedRecordRef,
                              publisher_envelope: ProtectedRecordEnvelope, *,
                              selection: PublisherRootSelection, now: method.Stamp) -> ProtectedRegistration: ...
    def read_registration(self, registration_sha256: str, *, selection: PublisherRootSelection,
                          now: method.Stamp) -> ProtectedRegistration: ...

class FactAssemblerPort(Protocol):
    def assemble_original(self, facts: tuple[RetainedFactUse, ...], *,
                          binding: EvaluationBinding, now: method.Stamp) -> RetainedBundle2: ...

class TerminalScorerPort(Protocol):
    def score(self, bundle: RetainedBundle2, finalization: BundleFinalization2, *,
              plan: ScoringPlan2, review: ScoringPlanReview2, now: method.Stamp) -> TerminalScore2: ...

class RedactionPort(Protocol):
    def redact(self, score: TerminalScore2, *, selected: PublicAggregateBindings1,
               now: method.Stamp) -> tuple[RedactionApproval2, bytes]: ...

