"""Accepted candidate03 wire types. Shape validation is not authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypedDict
from .common import JSONValue, StructuralRecord, SelectedShapeValidator, ValidationLimits
if TYPE_CHECKING:
    from . import method, capture, protected, completion, release, checkpoint


class ConsumptionReadBinding(TypedDict):
    release_ref: protected.ProtectedRecordRef
    release_id: str
    consume_attempt_id: str
    controller_id: str
    controller_process: capture.CaptureSubject
    channel_binding_sha256: str
    method_decision_ref: method.ObjectRef
    method_exposure_ref: method.ObjectRef
    expected_decision_generation: int
    expected_decision_head_sha256: str

class ConsumptionPreparation(TypedDict):
    format: Literal['forex.release-consumption-preparation/1']
    binding: protected.EvaluationBinding
    preparation_id: str
    consume_attempt_id: str
    release_ref: protected.ProtectedRecordRef
    controller_id: str
    controller_process: capture.CaptureSubject
    channel_binding_sha256: str
    original_setup_key: method.OriginalSetupKey
    setup_budget_sha256: str
    method_appointment_sha256: str
    checkpoint_access_selection_sha256: str
    prepared_at: method.Stamp
    deadline: method.Stamp
    read_request_sha256: str

class ConsumptionRecord(TypedDict):
    format: Literal['forex.release-consumption-record/1']
    binding: protected.EvaluationBinding
    consume_attempt_id: str
    preparation_sha256: str
    release_ref: protected.ProtectedRecordRef
    controller_id: str
    controller_process: capture.CaptureSubject
    channel_binding_sha256: str
    checkpoint_request_sha256: str
    checkpoint_response_sha256: str | None
    verified_checkpoint_generation: int | None
    verified_checkpoint_head_sha256: str | None
    authority_status_sha256: str | None
    validated_at: method.Stamp | None
    committed_at: method.Stamp | None
    post_commit_checked_at: method.Stamp | None
    status: Literal['CONSUMED_VALID', 'SPENT_NO_EXPOSURE', 'UNAVAILABLE']

class NarrowRoleReleaseEvidence1(TypedDict):
    format: Literal['forex.narrow-role-release-evidence/1']
    binding: protected.EvaluationBinding
    evidence_id: str
    method_binding: method.Binding
    observer_id: str
    observer_binding: protected.ProtectedReferenceUse
    controller_id: str
    channel_id: str
    channel_binding_sha256: str
    boot_id: str
    setup_budget_sha256: str
    method_decision: capture.AuthenticatedMethodObject
    method_exposure: method.ObjectRef
    decision_generation: Literal[22]
    decision_head_sha256: str
    setup_records: RoleSetupRecords
    role_setup_sha256: str
    roles: CurrentRoles
    channel: CurrentChannel
    model_listener: CurrentListener
    observed: method.Stamp
    observed_at_utc: str
    issued: method.Stamp
    not_before_utc: str
    expires: method.Stamp
    expires_at_utc: str
    original_clock_binding: protected.ProtectedReferenceUse
    accepted_claims: list[str]
    non_forwarding_status: Literal['ASSUMPTION_BOUND_NON_FORWARDING']
    unsupported_routes: list[str]
    every_task_post_exec_probes_claimed: Literal[False]
    broad_role_read_denial_claimed: Literal[False]
    completion_scoring_publication_authority: Literal[False]
    supporting_objects: list[capture.AuthenticatedMethodObject]

class RoleSetupRecords(TypedDict):
    runner_install: capture.AuthenticatedMethodObject
    model_install: capture.AuthenticatedMethodObject
    model_post_exec: capture.AuthenticatedMethodObject
    final_peer_bound: capture.AuthenticatedMethodObject
    policy_argument: capture.AuthenticatedMethodObject

class CurrentRoles(TypedDict):
    controller: CurrentRoleReadback
    decision_runner: CurrentRoleReadback
    model_service: CurrentRoleReadback

class CurrentRoleReadback(TypedDict):
    role: Literal['CONTROLLER', 'DECISION_RUNNER', 'MODEL_SERVICE']
    process: method.ProcessIdentity
    parent: ParentIdentity
    process_boundary: CapturedOperationUse
    observed: method.Stamp

class CapturedOperationUse(TypedDict):
    capture: capture.AuthenticatedMethodObject
    operation_index: int
    operation_kind: Literal['PROCESS_BOUNDARY', 'PROC_READ', 'LISTENER_READ']

class CurrentChannel(TypedDict):
    channel_id: str
    channel_binding_sha256: str
    key_operation_id: str
    created_record_id: str
    peer_record_id: str
    controller_endpoint: method.DescriptorIdentity
    runner_endpoint: method.DescriptorIdentity
    controller_fd_link: CapturedOperationUse
    controller_fdinfo: CapturedOperationUse
    runner_fd_link: CapturedOperationUse
    runner_fdinfo: CapturedOperationUse
    accepted_first_receive: method.ObjectRef
    accepted_ucred: method.CredentialTriple
    observed: method.Stamp

class CurrentListener(TypedDict):
    listener: CapturedOperationUse
    observed: method.Stamp

class ParentIdentity(TypedDict):
    boot_id: str
    pid: int
    start_ticks: int
    uid: int
    gid: int

def validate(type_name: str, value: JSONValue, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import validate_record
    return validate_record('release', type_name, value, shape_validator=shape_validator, limits=limits)

def decode(type_name: str, raw: bytes, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import decode_record
    return decode_record('release', type_name, raw, shape_validator=shape_validator, limits=limits)

class NarrowRoleEvidencePort(Protocol):
    """Custody NR01-NR11; a shape-checked wrapper alone cannot satisfy this port."""
    def verify(self, evidence: NarrowRoleReleaseEvidence1, *,
               selected: protected.ReleaseSelection3, publishers: protected.PublisherRootSelection,
               resolver: protected.ProtectedResolverPort, now: method.Stamp) -> None: ...

class ReleaseIssuerPort(Protocol):
    def issue(self, selection: protected.ReleaseSelection3, *, now: method.Stamp) -> protected.ReleaseReceipt3: ...
    def publish_exact(self, receipt: protected.ReleaseReceipt3, *,
                      now: method.Stamp) -> protected.ProtectedReferenceUse: ...

class ReleaseConsumptionPort(Protocol):
    """Integration NR12; exact retained identity, final fresh read, one-use commit."""
    def prepare(self, receipt: protected.ReleaseReceipt3, preparation: ConsumptionPreparation, *,
                now: method.Stamp) -> ConsumptionPreparation: ...
    def consume_exact(self, preparation: ConsumptionPreparation, *,
                      checkpoint_client: checkpoint.CheckpointClientPort,
                      now: method.Stamp) -> ConsumptionRecord: ...
    def read_retained(self, *, consume_attempt_id: str, now: method.Stamp) -> ConsumptionRecord: ...

