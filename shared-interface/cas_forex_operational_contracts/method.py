"""Accepted candidate03 wire types. Shape validation is not authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypedDict
from .common import JSONValue, StructuralRecord, SelectedShapeValidator, ValidationLimits
if TYPE_CHECKING:
    from . import method, capture, protected, completion, release, checkpoint

AuthorityRole: TypeAlias = Literal['TRUSTED_CONTROLLER_WITNESS', 'INDEPENDENT_SETUP_CONSUMER', 'SETUP_BUDGET_ISSUER', 'INDEPENDENT_CHECKPOINT_CUSTODIAN']
Purpose: TypeAlias = Literal['policy-inheritance-witness-v3', 'policy-inheritance-setup-budget-v3', 'policy-inheritance-method-decision-v3', 'policy-inheritance-ingestion-ack-v3', 'policy-inheritance-checkpoint-v3', 'policy-inheritance-checkpoint-transition-v3']
Origin: TypeAlias = Literal['CONTROLLER', 'DECISION_BOOTSTRAP', 'MODEL_BOOTSTRAP']
EventKind: TypeAlias = Literal['SETUP_BEGIN', 'CALIBRATION_BEGIN', 'CALIBRATION_CASE', 'CALIBRATION_RETIRED', 'FINAL_CHANNEL_CREATED', 'RUNNER_INSTALL', 'MODEL_INSTALL', 'ASSET_BINDINGS', 'MODEL_POST_EXEC', 'FINAL_PEER_BOUND', 'POLICY_ARGUMENT', 'SETUP_SEAL', 'FAILURE']
EvidenceClass: TypeAlias = Literal['TRUSTED_BOOTSTRAP_REPORT', 'CONTROLLER_OS_READBACK', 'PUBLIC_RECEIVER_OBSERVATION', 'TRUSTED_SOURCE_ARGUMENT', 'INSTALLATION_INHERITANCE_ARGUMENT', 'CONTROLLER_STREAM_METADATA']
ArtifactKind: TypeAlias = Literal['CANONICAL_PAYLOAD', 'COVERAGE_PLAN', 'PUBLIC_FIXTURE', 'EXECUTABLE_PIN', 'PROC_IDENTITY', 'NAMESPACE_INVENTORY', 'MOUNT_INVENTORY', 'DESCRIPTOR_INVENTORY', 'INSTALL_ARGUMENTS', 'NORMALIZED_RULES', 'RULE_TARGET_INVENTORY', 'ASSET_INVENTORY', 'LISTENER_IDENTITY', 'EXEC_LINEAGE', 'IPC_SEND', 'IPC_RECEIVE', 'DESCRIPTOR_CLOSES', 'ENDPOINT_RETIREMENT', 'PROCESS_RETIREMENT', 'SOURCE_ARGUMENT', 'CHECKPOINT', 'TOPOLOGY_APPROVAL', 'WATCHDOG_BINDING', 'SETUP_BUDGET', 'SIGNED_ENVELOPE', 'EVENT_RECORD', 'METHOD_DECISION', 'INGESTION_ACK', 'AUTHENTICATED_INTERVAL', 'CHECKPOINT_TRANSITION', 'CHECKPOINT_CERTIFICATE', 'EXPOSED_OUTPUT', 'VERIFIER_TRACE', 'TRUSTED_CAPTURE_BATCH', 'RUNTIME_DECODE_BINDING', 'TRUSTED_SPAWN_SELECTION', 'RUNTIME_SELECTION_BINDING', 'RUNTIME_SELECTED_VALUES', 'AUTHENTICATED_EVENT_INPUTS', 'NATIVE_CAPTURE_BYTES', 'RAW_BLOB_MANIFEST']
CalibrationKind: TypeAlias = Literal['POSITIVE_INERT', 'BAD_MAC', 'BAD_SEQUENCE', 'BAD_CHANNEL_ID', 'BAD_FRAME', 'DELIVERED_RIGHTS', 'TRUNCATED_RIGHTS', 'WRONG_PEER_PID']
CalibrationVerdict: TypeAlias = Literal['ACCEPTED_INERT', 'AUTH_REJECTED', 'FRAMING_REJECTED', 'RIGHTS_REJECTED']
DescriptorType: TypeAlias = Literal['REGULAR', 'PIPE', 'SOCKET', 'CHAR', 'ANON', 'OTHER']
InstallOperation: TypeAlias = Literal['LANDLOCK_CREATE_RULESET', 'LANDLOCK_ADD_RULE', 'PR_SET_NO_NEW_PRIVS', 'LANDLOCK_RESTRICT_SELF']
DecisionStatus: TypeAlias = Literal['ACCEPTED_NARROW_METHOD', 'REJECTED', 'UNAVAILABLE']
AcceptedClaim: TypeAlias = Literal['TRUSTED_INSTALLATION_AND_INHERITANCE', 'PUBLIC_RECEIVER_CALIBRATION']
CleanupStatus: TypeAlias = Literal['CONFIRMED', 'FAILED', 'UNKNOWN']
FailureCode: TypeAlias = Literal['APPOINTMENT_UNAVAILABLE', 'SIGNER_UNAPPOINTED', 'SIGNATURE_DEPENDENCY_UNAVAILABLE', 'SIGNATURE_REJECTED', 'RAW_BYTES_MISMATCH', 'NONCANONICAL_RECORD', 'CONTEXT_MISMATCH', 'PURPOSE_MISMATCH', 'CLAIM_OUTSIDE_METHOD_SCOPE', 'UNSUPPORTED_ROUTE_RELABELED', 'CLOCK_DOMAIN_UNSUPPORTED', 'CLOCK_DRIFT', 'SETUP_DEADLINE_EXPIRED', 'BUDGET_RESET_ATTEMPT', 'SOURCE_OR_EXEC_IDENTITY_MISMATCH', 'INSTALLATION_FAILED_OR_UNOBSERVED', 'DESCRIPTOR_IDENTITY_MISMATCH', 'CALIBRATION_INCOMPLETE', 'CALIBRATION_WRONG_ORIGIN', 'CALIBRATION_UNEXPECTED_OUTCOME', 'CLEANUP_UNCONFIRMED', 'AUTHORITY_CREATED_EARLY', 'MISSING_SLOT', 'EXTRA_SLOT', 'SEQUENCE_GAP', 'DEPENDENCY_ORDER', 'REPLAY_OR_EQUIVOCATION', 'RETENTION_UNAVAILABLE', 'RETENTION_COMMIT_FAILED', 'CHECKPOINT_MISMATCH', 'INCOMPLETE_STREAM', 'DECODER_UNAVAILABLE', 'RAW_EVIDENCE_UNAVAILABLE', 'INDEPENDENT_WATCHDOG_UNAVAILABLE', 'RUNTIME_APPROVAL_ABSENT', 'APPOINTMENT_INTERVAL_INSUFFICIENT', 'APPOINTMENT_EXPIRED_OR_UNAVAILABLE', 'AUTHENTICATED_INTERVAL_EXPIRED', 'CALIBRATION_BASELINE_MISMATCH', 'CALIBRATION_REPLAY_NOT_DEMONSTRATED', 'CALIBRATION_EMPTY_RIGHTS', 'CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE', 'CHECKPOINT_ADVANCE_UNCONFIRMED', 'CHECKPOINT_AUTHORITY_UNAVAILABLE', 'CHECKPOINT_LEDGER_DIVERGENCE', 'BUDGET_ALREADY_CLAIMED', 'OUTPUT_NOT_CHECKPOINTED']
RejectionStage: TypeAlias = Literal['NONE', 'MAC', 'SEQUENCE', 'CHANNEL_ID', 'FRAME', 'ANCILLARY', 'PEER_CREDENTIALS']
CheckpointTransitionKind: TypeAlias = Literal['SETUP_RESERVATION', 'BUDGET_CLAIM', 'ACK_EXPOSURE', 'DECISION_EXPOSURE', 'TERMINAL_ABORT']
CheckpointClaimState: TypeAlias = Literal['RESERVED', 'CLAIMED', 'ABORTED']
OutputKind: TypeAlias = Literal['SETUP_BUDGET', 'INGESTION_ACK', 'METHOD_DECISION', 'NONE']
ExposedKind: TypeAlias = Literal['SETUP_BUDGET', 'INGESTION_ACK', 'METHOD_DECISION']

class Scope(TypedDict):
    method_id: Literal['POLICY_INHERITANCE_TRUSTED_ADAPTER_V1']
    method_spec_sha256: str
    source_manifest_sha256: str
    config_sha256: str
    topology_sha256: str
    run_id: str
    epoch: int
    original_window_sha256: str
    setup_identity: str

class Binding(TypedDict):
    scope: Scope
    appointment_sha256: str

class ClockDomain(TypedDict):
    boot_id: str
    time_namespace_inode: int
    clock_id: Literal['CLOCK_BOOTTIME']

class Stamp(TypedDict):
    utc: str
    boottime_ns: int

class ObjectRef(TypedDict):
    object_id: str
    bytes: int
    sha256: str
    artifact_kind: ArtifactKind

class Principal(TypedDict):
    principal_id: str
    role: AuthorityRole
    component_manifest_sha256: str
    signer_public_sha256: str
    allowed_purposes: list[Purpose]
    not_before_utc: str
    expires_at_utc: str

class CoverageSlot(TypedDict):
    slot_id: str
    kind: EventKind
    origin: Origin
    after_slots: list[str]
    payload_decoder_sha256: str
    expected_subject_id: str
    required_raw_kinds: list[ArtifactKind]

class CoveragePlan(TypedDict):
    format: Literal['forex.policy-inheritance-coverage-plan/3']
    scope: Scope
    plan_id: str
    slots: list[CoverageSlot]
    calibration_plan: list[CalibrationExpectation]
    max_records: Literal[19]
    max_raw_bytes: int
    unsupported_routes: list[str]

class CalibrationExpectation(TypedDict):
    case_id: str
    slot_id: str
    fixture_ref: ObjectRef
    case_kind: CalibrationKind
    expected_exchange_verdicts: list[CalibrationVerdict]
    receiver_component_sha256: str
    requires_foreign_pid: bool

class Appointment(TypedDict):
    format: Literal['forex.policy-inheritance-appointment/3']
    appointment_id: str
    scope: Scope
    coverage_plan_sha256: str
    principals: list[Principal]
    clock_domain: ClockDomain
    not_before_utc: str
    expires_at_utc: str
    producer_staging_root_id: str
    consumer_retention_root_id: str
    independent_checkpoint_root_id: str
    approved_runtime_topology_ref: ObjectRef
    watchdog_binding_ref: ObjectRef
    stream_id: str
    checkpoint_authority_id: str

class SetupBudget(TypedDict):
    format: Literal['forex.policy-inheritance-setup-budget/3']
    binding: Binding
    budget_id: str
    issuer_id: str
    clock_domain: ClockDomain
    started: Stamp
    deadline: Stamp
    outer_deadline: Stamp
    maximum_seconds: Literal[180]
    coverage_plan_sha256: str
    appointment_interval_ref: ObjectRef

class AttestationBody(TypedDict):
    format: Literal['forex.policy-inheritance-attestation/3']
    binding: Binding
    attestation_id: str
    purpose: Purpose
    producer_id: str
    record_sha256: str
    record_bytes: int
    budget_sha256: str | None
    issued: Stamp
    expires: Stamp

class SignedEnvelope(TypedDict):
    body: AttestationBody
    algorithm: Literal['Ed25519']
    signer_sha256: str
    signature_hex: str

class Event(TypedDict):
    format: Literal['forex.policy-inheritance-event/3']
    binding: Binding
    budget_sha256: str
    stream_id: str
    record_id: str
    producer_id: str
    sequence: int
    previous_record_sha256: str
    slot_id: str
    kind: EventKind
    origin: Origin
    evidence_class: EvidenceClass
    observed_start: Stamp
    observed_end: Stamp
    recorded: Stamp
    payload_ref: ObjectRef
    raw_refs: list[ObjectRef]
    input_bundle_ref: ObjectRef
    input_bundle_envelope_ref: ObjectRef

class ProcessIdentity(TypedDict):
    boot_id: str
    pid: int
    start_ticks: int
    parent_pid: int
    uid: int
    gid: int
    exe_device: int
    exe_inode: int
    namespace_inventory_ref: ObjectRef
    mount_inventory_ref: ObjectRef
    exe_asset: ExecutableAssetIdentity

class ThreadIdentity(TypedDict):
    tid: int
    start_ticks: int

class DescriptorIdentity(TypedDict):
    fd: int
    object_type: DescriptorType
    device: int
    inode: int
    access_flags: int
    close_on_exec: bool
    selected_target_id: str

class SyscallOutcome(TypedDict):
    operation: InstallOperation
    arguments_ref: ObjectRef
    return_value: int
    errno: int
    observed: Stamp

class SetupBeginPayload(TypedDict):
    coverage_plan_sha256: str
    producer_identity: ProcessIdentity
    budget_sha256: str

class CalibrationBeginPayload(TypedDict):
    receiver_identity: ProcessIdentity
    receiver_component_sha256: str
    planned_case_ids: list[str]
    final_key_created: Literal[False]
    private_documents_opened: Literal[False]

class CalibrationCasePayload(TypedDict):
    case_id: str
    case_kind: CalibrationKind
    slot_id: str
    fixture_ref: ObjectRef
    receiver_identity: ProcessIdentity
    receiver_component_sha256: str
    expected_peer_identity: ProcessIdentity
    channel_instance_id: str
    verifier_instance_id: str
    channel_object_ids: list[str]
    public_fixture_key_id: str
    exchanges: list[CalibrationExchange]

class CalibrationRetiredPayload(TypedDict):
    completed_case_ids: list[str]
    endpoint_retirement_ref: ObjectRef
    challenger_identity: ProcessIdentity
    process_retirement_ref: ObjectRef
    remaining_challenger_descendants: Literal[0]
    unclosed_delivered_fds: Literal[0]
    final_key_created: Literal[False]

class FinalChannelCreatedPayload(TypedDict):
    channel_id: str
    endpoint_inventory_ref: ObjectRef
    key_generation_operation_id: str
    calibration_retired_record_id: str
    key_material_recorded: Literal[False]

class InstallationPayload(TypedDict):
    process_identity: ProcessIdentity
    threads: list[ThreadIdentity]
    initial_descriptors: list[DescriptorIdentity]
    expected_descriptor_plan_ref: ObjectRef
    normalized_rules_ref: ObjectRef
    rule_target_inventory_ref: ObjectRef
    landlock_abi: int
    handled_fs: int
    syscalls: list[SyscallOutcome]
    no_new_privs_readback: Literal[1]
    parent_installation_record_id: str | None

class AssetBindingsPayload(TypedDict):
    selected_asset_manifest_sha256: str
    actual_file_inventory_ref: ObjectRef
    hash_scan_started: Stamp
    hash_scan_completed: Stamp

class PostExecPayload(TypedDict):
    wrapper_installation_record_id: str
    actual_server_identity: ProcessIdentity
    asset_binding_record_id: str
    owned_listener_ref: ObjectRef
    wrapper_to_exec_identity_ref: ObjectRef

class FinalPeerPayload(TypedDict):
    channel_created_record_id: str
    channel_id: str
    actual_peer_identity: ProcessIdentity
    first_packet_ref: ObjectRef
    actual_ucred: list[int]
    model_post_exec_record_id: str

class PolicyArgumentPayload(TypedDict):
    installation_record_ids: list[str]
    post_exec_record_id: str
    source_argument_ref: ObjectRef
    claim: Literal['TRUSTED_INSTALLATION_AND_INHERITANCE']
    non_forwarding_status: Literal['ASSUMPTION_BOUND_NON_FORWARDING']
    unsupported_routes: list[str]
    every_task_post_exec_probes_claimed: Literal[False]

class SealEntry(TypedDict):
    sequence: int
    record_id: str
    record_sha256: str

class SetupSealPayload(TypedDict):
    entries: list[SealEntry]
    covered_slot_ids: list[str]
    previous_head_sha256: str
    previous_record_count: Literal[18]
    unsupported_routes: list[str]

class FailurePayload(TypedDict):
    failed_slot_id: str | None
    code: FailureCode
    last_retained_record_id: str | None
    authority_created: bool
    cleanup_status: CleanupStatus

class ConsumerDecision(TypedDict):
    format: Literal['forex.policy-inheritance-method-decision/3']
    binding: Binding
    consumer_id: str
    decision_id: str
    budget_sha256: str
    stream_id: str
    status: DecisionStatus
    failure_code: FailureCode | None
    sealed_head_sha256: str | None
    retained_prefix_head_sha256: str | None
    retained_record_count: int
    retention_commit_id: str
    decided: Stamp
    expires: Stamp
    accepted_claims: list[AcceptedClaim]
    unsupported_routes: list[str]
    evidence_classes: list[EvidenceClass]
    completion_scoring_publication_authority: Literal[False]
    authenticated_interval_ref: ObjectRef

class IngestionAck(TypedDict):
    format: Literal['forex.policy-inheritance-ingestion-ack/3']
    binding: Binding
    consumer_id: str
    stream_id: str
    sequence: int
    record_sha256: str
    retention_commit_id: str
    acknowledged: Stamp
    budget_sha256: str

class ConsumerCheckpoint(TypedDict):
    format: Literal['forex.policy-inheritance-checkpoint/3']
    binding: Binding
    original_setup_key: OriginalSetupKey
    checkpoint_authority_id: str
    checkpoint_id: str
    generation: int
    previous_checkpoint_sha256: str
    transition_request_ref: ObjectRef
    transition_kind: CheckpointTransitionKind
    budget_id: str
    budget_sha256: str
    stream_id: str
    event_sequence: int
    event_head_sha256: str
    consumer_prepare_commit_id: str
    output: OutputBinding
    claim_state: CheckpointClaimState
    checkpointed_at: Stamp
    original_budget_body_ref: ObjectRef

class EvaluationResult(TypedDict):
    status: DecisionStatus
    decision_ref: ObjectRef | None
    failure_code: FailureCode | None

class CloseOutcome(TypedDict):
    descriptor: DescriptorIdentity
    close_return: Literal[0]
    close_errno: Literal[0]
    closed_at: Stamp
    raw_close_ref: ObjectRef

class CalibrationExchange(TypedDict):
    exchange_index: int
    observed_start: Stamp
    observed_end: Stamp
    actual_sender_identity: ProcessIdentity
    sent_record_ref: ObjectRef
    recv_record_ref: ObjectRef
    sent_application_packet_sha256: str
    sent_frames_sha256: str
    received_frames_sha256: str
    send_return: int
    send_errno: Literal[0]
    recv_return: int
    recv_errno: Literal[0]
    actual_ucred: CredentialTriple | None
    msg_trunc: bool
    msg_ctrunc: bool
    recv_seq_before: int
    recv_seq_after: int
    receiver_closed_before: bool
    receiver_closed_after: bool
    verdict: CalibrationVerdict
    rejection_stage: RejectionStage
    verifier_trace_ref: ObjectRef
    handler_entries_before: Literal[0]
    handler_entries_after: Literal[0]
    delivered_fds: list[DescriptorIdentity]
    close_outcomes: list[CloseOutcome]

class CredentialTriple(TypedDict):
    pid: int
    uid: int
    gid: int

class AuthenticatedInterval(TypedDict):
    binding: Binding
    not_before_utc: str
    expires_at_utc: str
    appointment_authentication_refs: list[ObjectRef]
    principal_authority_refs: list[ObjectRef]
    dependency_attestation_refs: list[ObjectRef]
    validated_at: Stamp

class OriginalSetupKey(TypedDict):
    run_id: str
    original_window_sha256: str
    setup_identity: str

class OutputBinding(TypedDict):
    kind: OutputKind
    body_ref: ObjectRef | None
    attestation_ref: ObjectRef | None

class CheckpointAdvanceRequest(TypedDict):
    format: Literal['forex.policy-inheritance-checkpoint-transition/3']
    binding: Binding
    original_setup_key: OriginalSetupKey
    transition_id: str
    transition_kind: CheckpointTransitionKind
    requester_id: str
    expected_generation: int
    expected_checkpoint_sha256: str
    budget_id: str
    budget_sha256: str
    stream_id: str
    event_sequence: int
    event_head_sha256: str
    consumer_prepare_commit_id: str
    output: OutputBinding
    claim_state: CheckpointClaimState
    prepared_at: Stamp
    original_budget_body_ref: ObjectRef

class ExposedOutput(TypedDict):
    format: Literal['forex.policy-inheritance-exposed-output/3']
    binding: Binding
    kind: ExposedKind
    body_ref: ObjectRef
    attestation_ref: ObjectRef
    checkpoint_ref: ObjectRef
    checkpoint_attestation_ref: ObjectRef

class ExecutableAssetIdentity(TypedDict):
    asset_id: str
    selected_path: str
    bytes: int
    sha256: str
    device: int
    inode: int

def validate(type_name: str, value: JSONValue, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import validate_record
    return validate_record('method', type_name, value, shape_validator=shape_validator, limits=limits)

def decode(type_name: str, raw: bytes, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import decode_record
    return decode_record('method', type_name, raw, shape_validator=shape_validator, limits=limits)

SIGNATURE_DOMAIN = b"CAS_FOREX_POLICY_INHERITANCE_V3\n"

def attestation_signing_bytes(body: AttestationBody) -> bytes:
    return SIGNATURE_DOMAIN + validate("AttestationBody", body).raw

class MethodAuthenticationPort(Protocol):
    def authenticate_appointment(self, appointment: Appointment, *, authority_status: checkpoint.AuthorityStatus,
                                 budget: SetupBudget, now: Stamp) -> AuthenticatedInterval: ...
    def verify_attestation(self, body: bytes, envelope: SignedEnvelope, *,
                           expected_purpose: Purpose, appointment: Appointment, now: Stamp) -> None: ...

class MethodEvidencePort(Protocol):
    def resolve(self, reference: ObjectRef) -> bytes: ...
    def retain_exact(self, reference: ObjectRef, raw: bytes) -> ObjectRef: ...

class MethodRuntimePort(Protocol):
    def reserve(self, authorization: checkpoint.InitialSetupAuthorization, budget: SetupBudget, *,
                now: Stamp) -> ExposedOutput: ...
    def ingest(self, event: Event, *, now: Stamp) -> ExposedOutput: ...
    def decide(self, *, binding: Binding, budget_sha256: str, now: Stamp) -> ExposedOutput: ...
    def recover_exact(self, output: OutputBinding, *, now: Stamp) -> ExposedOutput: ...

