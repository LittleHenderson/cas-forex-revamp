"""Accepted candidate03 wire types. Shape validation is not authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypedDict
from .common import JSONValue, StructuralRecord, SelectedShapeValidator, ValidationLimits
if TYPE_CHECKING:
    from . import method, capture, protected, completion, release, checkpoint

CaptureKind: TypeAlias = Literal['PROC_READ', 'PROCESS_BOUNDARY', 'FD_INVENTORY', 'RULE_TARGET_OPEN', 'INSTALL_CALL', 'FILE_HASH', 'SEND', 'RECV', 'VERIFIER_GATE', 'CLOSE', 'ENDPOINT_CREATE', 'CHILD_RETIREMENT', 'LISTENER_READ', 'SPAWN', 'STREAM_MARKER']

class ExecutableAssetIdentity(TypedDict):
    asset_id: str
    selected_path: str
    bytes: int
    sha256: str
    device: int
    inode: int

class CaptureSubject(TypedDict):
    role: Literal['CONTROLLER', 'DECISION_BOOTSTRAP', 'MODEL_BOOTSTRAP', 'MODEL_SERVICE', 'TEMPORARY_CHALLENGER', 'SETUP_CONSUMER', 'CHECKPOINT_CUSTODIAN', 'COMPLETION_OBSERVER']
    boot_id: str
    pid: int
    start_ticks: int
    parent_pid: int
    parent_start_ticks: int
    uid: int
    gid: int

class CaptureBatch(TypedDict):
    format: Literal['forex.trusted-setup-capture/2']
    binding: method.Binding
    budget_sha256: str
    capture_id: str
    producer_id: str
    reporting_origin: method.Origin
    evidence_class: method.EvidenceClass
    subject: CaptureSubject
    receiver_component_sha256: str | None
    started: method.Stamp
    finished: method.Stamp
    operations: list[CaptureOperation]
    previous_batch_sha256: str

class CaptureOperation(TypedDict):
    operation_index: int
    kind: CaptureKind
    started: method.Stamp
    finished: method.Stamp
    data: JSONValue

class ProcRead(TypedDict):
    subject: CaptureSubject
    selector: Literal['STAT', 'STATUS', 'TASK_STAT', 'NAMESPACE_LINK', 'MOUNTINFO', 'EXE_LINK', 'FD_LINK', 'FDINFO', 'NET_TCP', 'NET_TCP6']
    selector_argument: str | None
    raw_ref: method.ObjectRef
    return_value: int
    errno: int

class ProcessBoundary(TypedDict):
    subject: CaptureSubject
    parent_subject: CaptureSubject
    before_stat_ref: method.ObjectRef
    after_stat_ref: method.ObjectRef
    status_ref: method.ObjectRef
    task_stat_refs: list[method.ObjectRef]
    namespace_reads: list[NamespaceRead]
    mountinfo_ref: method.ObjectRef
    exe_link_ref: method.ObjectRef
    exe_stat: StatObservation

class NamespaceRead(TypedDict):
    namespace: Literal['mnt', 'pid', 'net', 'time', 'user', 'ipc', 'uts', 'cgroup']
    link_text: str
    device: int
    inode: int
    raw_ref: method.ObjectRef

class StatObservation(TypedDict):
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    bytes: int
    mtime_ns: int
    ctime_ns: int

class FdInventory(TypedDict):
    subject: CaptureSubject
    paused_boundary_id: str
    before_process_ref: method.ObjectRef
    after_process_ref: method.ObjectRef
    enumerated_fds: list[int]
    entries: list[FdObservation]
    enumeration_complete: Literal[True]

class FdObservation(TypedDict):
    descriptor: method.DescriptorIdentity
    link_ref: method.ObjectRef
    fdinfo_ref: method.ObjectRef
    stat: StatObservation
    fstat_return: int
    fstat_errno: int

class SpawnSelection(TypedDict):
    format: Literal['forex.trusted-spawn-selection/2']
    binding: method.Binding
    budget_sha256: str
    spawn_id: str
    role: Literal['RUNNER_INSTALL', 'MODEL_INSTALL']
    parent: CaptureSubject
    child: CaptureSubject
    component_sha256: str
    selected_executable_asset_id: str
    selected_policy_sha256: str
    descriptor_bindings: list[SpawnDescriptor]
    created: method.Stamp
    selection_origin: Literal['AUTHENTICATED_CONTROLLER_SPAWN']
    spawn_capture_ref: method.ObjectRef
    spawn_operation_index: int

class SpawnDescriptor(TypedDict):
    parent_fd: int
    child_fd: int
    object_identity: method.DescriptorIdentity
    target_id: str
    inheritance: Literal['PASS_FDS', 'STDIO_DUP']
    parent_observation_ref: method.ObjectRef

class RuleTargetOpen(TypedDict):
    target_id: str
    selected_path: str
    access_mask: int
    open_flags: int
    returned_fd: int
    errno: int
    stat: StatObservation | None
    resolved_link_ref: method.ObjectRef | None

class InstallCall(TypedDict):
    subject: CaptureSubject
    operation: Literal['ABI_QUERY', 'RULESET_CREATE', 'ADD_PATH_RULE', 'PR_SET_NO_NEW_PRIVS', 'RESTRICT_SELF', 'PR_GET_NO_NEW_PRIVS']
    abi_layout_sha256: str
    arguments: JSONValue
    return_value: int
    errno: int

class FileHashMeasurement(TypedDict):
    asset_id: str
    selected_path: str
    fd_stat_before: StatObservation
    fd_stat_after: StatObservation
    opened_read_only: Literal[True]
    mount_read_only_evidence_ref: method.ObjectRef
    bytes_read: int
    content_sha256: str
    hash_started: method.Stamp
    hash_finished: method.Stamp

class SendCall(TypedDict):
    exchange_id: str
    sender: CaptureSubject
    socket_descriptor: method.DescriptorIdentity
    frame_ref: method.ObjectRef
    application_ref: method.ObjectRef
    ancillary_sent: list[AncillaryInput]
    return_value: int
    errno: int

class RecvCall(TypedDict):
    exchange_id: str
    receiver: CaptureSubject
    socket_descriptor: method.DescriptorIdentity
    data_ref: method.ObjectRef
    ancillary_raw_ref: method.ObjectRef
    msg_flags: int
    return_value: int
    errno: int
    ucred: CredentialTriple | None
    delivered_descriptors: list[method.DescriptorIdentity]

class AncillaryInput(TypedDict):
    level: int
    type: int
    raw_ref: method.ObjectRef

class CredentialTriple(TypedDict):
    pid: int
    uid: int
    gid: int

class VerifierGate(TypedDict):
    exchange_id: str
    receiver_component_sha256: str
    instance_id: str
    channel_instance_id: str
    key_operation_id: str
    gate: Literal['FRAME', 'ANCILLARY', 'PEER_CREDENTIALS', 'MAC', 'CHANNEL_ID', 'SEQUENCE', 'VERDICT', 'EXPOSURE']
    input_refs: list[method.ObjectRef]
    outcome: Literal['CHECK_PASS', 'CHECK_FAIL', 'ACCEPTED_INERT', 'AUTH_REJECTED', 'FRAMING_REJECTED', 'RIGHTS_REJECTED']
    sequence_before: int
    sequence_after: int
    handler_entries_before: Literal[0]
    handler_entries_after: Literal[0]
    receiver_closed: bool

class DescriptorClose(TypedDict):
    exchange_id: str | None
    descriptor: method.DescriptorIdentity
    return_value: int
    errno: int

class EndpointCreate(TypedDict):
    channel_id: str
    owner: CaptureSubject
    endpoints: list[method.DescriptorIdentity]
    key_operation_id: str
    random_source_call_succeeded: bool
    key_material_recorded: Literal[False]

class ChildRetirement(TypedDict):
    subject: CaptureSubject
    known_descendants: list[CaptureSubject]
    wait_result: Literal['EXITED', 'SIGNALED', 'UNAVAILABLE']
    wait_status: int | None
    remaining_live_subjects: list[CaptureSubject]
    endpoint_close_refs: list[method.ObjectRef]
    delivered_close_refs: list[method.ObjectRef]

class ListenerRead(TypedDict):
    subject: CaptureSubject
    address: Literal['127.0.0.1']
    port: int
    socket_descriptor: method.DescriptorIdentity
    process_snapshot_ref: method.ObjectRef
    tcp_table_ref: method.ObjectRef
    fd_inventory_ref: method.ObjectRef

class DecodeBinding(TypedDict):
    format: Literal['forex.runtime-decode-binding/2']
    binding: method.Binding
    budget_sha256: str
    event_kind: method.EventKind
    decoder_component_sha256: str
    decoder_format_sha256: str
    capture_refs: list[method.ObjectRef]
    capture_envelope_refs: list[method.ObjectRef]
    selected_input_refs: list[method.ObjectRef]
    normalized_ref: method.ObjectRef
    normalized_artifact_kind: method.ArtifactKind
    decoded: method.Stamp

class RuntimeSelectionBinding(TypedDict):
    format: Literal['forex.runtime-selection-binding/2']
    binding: method.Binding
    budget_sha256: str
    slot_id: str
    subject_id: str
    selected_source_refs: list[method.ObjectRef]
    selected_decoder_sha256: str
    selection_ref: method.ObjectRef
    selected_at: method.Stamp

class AuthenticatedMethodObject(TypedDict):
    object_ref: method.ObjectRef
    envelope_ref: method.ObjectRef

class SpawnCapture(TypedDict):
    spawn_id: str
    role: Literal['RUNNER_INSTALL', 'MODEL_INSTALL']
    parent: CaptureSubject
    selected_component_sha256: str
    selected_executable_asset_id: str
    selected_policy_sha256: str
    descriptor_bindings: list[SpawnDescriptor]
    returned_pid: int
    errno: int
    paused_child: CaptureSubject | None
    child_process_boundary_ref: method.ObjectRef | None
    result: Literal['SPAWNED_AND_PAUSED', 'FAILED', 'UNAVAILABLE']

class StreamMarker(TypedDict):
    marker: Literal['SETUP_BEGIN', 'CALIBRATION_BEGIN', 'POLICY_ARGUMENT', 'SETUP_SEAL']
    slot_id: str
    sequence: int
    accepted_predecessor_refs: list[method.ObjectRef]
    source_argument_ref: method.ObjectRef | None

class EventInputs(TypedDict):
    format: Literal['forex.authenticated-event-inputs/1']
    binding: method.Binding
    budget_sha256: str
    stream_id: str
    record_id: str
    slot_id: str
    event_kind: method.EventKind
    capture_objects: list[AuthenticatedMethodObject]
    decode_objects: list[AuthenticatedMethodObject]
    runtime_selection: AuthenticatedMethodObject
    selected_values: AuthenticatedMethodObject
    spawn_selection: AuthenticatedMethodObject | None
    selected_source_refs: list[method.ObjectRef]
    raw_blob_manifests: list[AuthenticatedMethodObject]

class RuntimeSelectedValues(TypedDict):
    format: Literal['forex.runtime-selected-values/1']
    binding: method.Binding
    budget_sha256: str
    slot_id: str
    event_kind: method.EventKind
    subject_id: str
    values: JSONValue

class CalibrationSelection(TypedDict):
    receiver_component_sha256: str
    expected_peer: method.ProcessIdentity
    foreign_sender: method.ProcessIdentity
    retired_pids: list[int]
    temporary_actors: list[method.ProcessIdentity]

class InstallationSelection(TypedDict):
    process: method.ProcessIdentity
    descriptors: list[method.DescriptorIdentity]
    descriptor_plan_ref: method.ObjectRef
    rules: list[RuleSelection]
    targets: list[TargetSelection]
    abi: int
    handled_fs: int

class RuleSelection(TypedDict):
    target_id: str
    rights: int

class TargetSelection(TypedDict):
    target_id: str
    device: int
    inode: int
    resolved_path: str

class AssetSelection(TypedDict):
    asset_id: str
    path: str
    bytes: int
    sha256: str
    device: int
    inode: int
    read_only: Literal[True]

class ChannelSelection(TypedDict):
    channel_id: str
    endpoint_ids: list[str]
    owner: method.ProcessIdentity
    key_operation_id: str
    created_at: method.Stamp

class PostExecSelection(TypedDict):
    process: method.ProcessIdentity
    parent: method.ProcessIdentity
    exe_path: str
    executable_asset_id: str
    listener: SelectedListener

class SelectedListener(TypedDict):
    process: method.ProcessIdentity
    address: Literal['127.0.0.1']
    port: int
    socket_inode: int
    observed: method.Stamp

class PeerSelection(TypedDict):
    first_packet_ref: method.ObjectRef
    current_peer_ref: method.ObjectRef

class RawBlobManifest(TypedDict):
    format: Literal['forex.raw-capture-blob/1']
    binding: method.Binding
    budget_sha256: str
    producer_id: str
    origin: method.Origin
    subject: CaptureSubject
    started: method.Stamp
    finished: method.Stamp
    blob_ref: method.ObjectRef | None
    encoding: str
    source_selector: Literal['STAT', 'STATUS', 'TASK_STAT', 'NAMESPACE_LINK', 'MOUNTINFO', 'EXE_LINK', 'FD_LINK', 'FDINFO', 'NET_TCP', 'NET_TCP6', 'WIRE_FRAME', 'APPLICATION_PACKET', 'ANCILLARY_BYTES', 'NATIVE_INSTALL_ARGUMENTS']
    raw_bytes: int
    raw_sha256: str

def validate(type_name: str, value: JSONValue, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import validate_record
    return validate_record('capture', type_name, value, shape_validator=shape_validator, limits=limits)

def decode(type_name: str, raw: bytes, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import decode_record
    return decode_record('capture', type_name, raw, shape_validator=shape_validator, limits=limits)

class CaptureSinkPort(Protocol):
    """Durable exact bytes; returning a reference does not authenticate it."""
    def retain(self, raw: bytes, *, artifact_kind: method.ArtifactKind) -> method.ObjectRef: ...
    def readback(self, reference: method.ObjectRef) -> bytes: ...

class CapturePort(Protocol):
    """Explicit calls only. Implementations must not start work on construction."""
    def capture_setup(self, plan: method.CoveragePlan, original_budget: method.SetupBudget,
                      selected_spawns: tuple[SpawnSelection, ...], *,
                      sink: CaptureSinkPort) -> tuple[CaptureBatch, ...]: ...
    def capture_current_roles(self, accepted: method.ExposedOutput, plan: method.CoveragePlan, original_budget: method.SetupBudget, *,
                              sink: CaptureSinkPort) -> tuple[CaptureBatch, ...]: ...

class DecodePort(Protocol):
    def decode_actual(self, captures: tuple[AuthenticatedMethodObject, ...], *,
                      selection: RuntimeSelectedValues, decoder_component_sha256: str,
                      decoder_format_sha256: str, now: method.Stamp) -> tuple[DecodeBinding, bytes]: ...

class WatchdogPort(Protocol):
    def arm_original(self, budget: method.SetupBudget, *, selected_processes: tuple[CaptureSubject, ...]) -> method.ObjectRef: ...
    def observe(self, original_binding: method.ObjectRef, *, now: method.Stamp) -> method.ObjectRef: ...

