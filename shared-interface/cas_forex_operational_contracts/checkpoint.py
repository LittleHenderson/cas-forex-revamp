"""Accepted candidate03 wire types. Shape validation is not authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypedDict
from .common import JSONValue, StructuralRecord, SelectedShapeValidator, ValidationLimits
if TYPE_CHECKING:
    from . import method, capture, protected, completion, release, checkpoint

CheckpointOperation: TypeAlias = Literal['READ_CURRENT', 'ADVANCE', 'LOOKUP_TRANSITION']
CheckpointUse: TypeAlias = Literal['SETUP_PROTOCOL', 'RELEASE_ISSUANCE', 'RELEASE_CONSUMPTION']

class CheckpointRpcRequest(TypedDict):
    format: Literal['forex.checkpoint-rpc-request/2']
    request_id: str
    binding: method.Binding
    original_setup_key: method.OriginalSetupKey
    caller_id: str
    operation: Literal['READ_CURRENT', 'ADVANCE', 'LOOKUP_TRANSITION']
    nonce_hex: str
    issued: method.Stamp
    deadline: method.Stamp
    body: JSONValue
    use: CheckpointUse

class CheckpointReadBody(TypedDict):
    minimum_generation: int
    minimum_head_sha256: str
    consumption_binding: release.ConsumptionReadBinding | None

class CheckpointLookupBody(TypedDict):
    transition_id: str
    exact_request_sha256: str
    minimum_generation: int
    minimum_head_sha256: str

class CheckpointAdvanceBody(TypedDict):
    transition_utf8: str
    transition_attestation_utf8: str
    initial_authorization_utf8: str | None
    unsigned_budget_utf8: str
    output_body_utf8: str | None
    output_attestation_utf8: str | None

class CheckpointRpcResponse(TypedDict):
    format: Literal['forex.checkpoint-rpc-response/2']
    request_sha256: str
    nonce_hex: str
    binding: method.Binding
    original_setup_key: method.OriginalSetupKey
    checkpoint_authority_id: str
    store_instance_id: str
    status: Literal['ABSENT', 'PRESENT', 'COMMITTED', 'EXACT_RECOVERY', 'REJECTED', 'UNAVAILABLE']
    observed: method.Stamp
    clock_domain: method.ClockDomain
    authority_view_sha256: str
    generation: int | None
    head_sha256: str | None
    checkpoint_utf8: str | None
    checkpoint_attestation_utf8: str | None
    history: list[RetainedTransition]
    failure_code: method.FailureCode | None
    access_selection_sha256: str

class RetainedTransition(TypedDict):
    generation: int
    request_sha256: str
    checkpoint_sha256: str
    checkpoint_utf8: str
    checkpoint_attestation_utf8: str

class RpcSignature(TypedDict):
    body_utf8: str
    signer_sha256: str
    algorithm: Literal['Ed25519']
    signature_hex: str

class AuthorityStatus(TypedDict):
    format: Literal['forex.runtime-authority-status/1']
    appointment_sha256: str
    authorizer_id: str
    revision: int
    status: Literal['ACTIVE', 'WITHDRAWN']
    principal_ids: list[str]
    not_before_utc: str
    expires_at_utc: str

class InitialSetupAuthorization(TypedDict):
    format: Literal['forex.original-setup-authorization/1']
    authorization_id: str
    authorizer_id: str
    binding: method.Binding
    original_setup_key: method.OriginalSetupKey
    authorized_issuer_id: str
    budget_id: str
    clock_domain: method.ClockDomain
    original_outer_window_ref: method.ObjectRef
    not_before_utc: str
    expires_at_utc: str
    maximum_seconds: Literal[180]
    max_reservations: Literal[1]

class CheckpointAccessSelection(TypedDict):
    format: Literal['forex.checkpoint-access-selection/2']
    binding: method.Binding
    checkpoint_authority_id: str
    store_instance_id: str
    endpoint_id: str
    endpoint_binding_sha256: str
    callers: list[CheckpointCallerGrant]
    authorizer_id: str
    not_before_utc: str
    expires_at_utc: str

class CheckpointCallerGrant(TypedDict):
    principal_id: str
    signer_public_sha256: str
    component_manifest_sha256: str
    actual_process: capture.CaptureSubject
    operations: list[CheckpointOperation]
    uses: list[CheckpointUse]

def validate(type_name: str, value: JSONValue, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import validate_record
    return validate_record('checkpoint', type_name, value, shape_validator=shape_validator, limits=limits)

def decode(type_name: str, raw: bytes, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import decode_record
    return decode_record('checkpoint', type_name, raw, shape_validator=shape_validator, limits=limits)

REQUEST_DOMAIN = b"CAS_FOREX_CHECKPOINT_RPC_REQUEST_V2\n"
RESPONSE_DOMAIN = b"CAS_FOREX_CHECKPOINT_RPC_RESPONSE_V2\n"
AUTHORITY_STATUS_DOMAIN = b"CAS_FOREX_RUNTIME_AUTHORITY_STATUS_V1\n"
ORIGINAL_SETUP_AUTHORIZATION_DOMAIN = b"CAS_FOREX_ORIGINAL_SETUP_AUTHORIZATION_V1\n"

class CheckpointTransportPort(Protocol):
    """Implementor owns actual peer/fragment credentials and bounded framing."""
    def exchange(self, request: RpcSignature, *, deadline: method.Stamp) -> RpcSignature: ...

class CheckpointClientPort(Protocol):
    """Implementor authenticates the returned response; no implicit retries."""
    def read_current(self, request: CheckpointRpcRequest, *, now: method.Stamp) -> CheckpointRpcResponse: ...
    def advance(self, request: CheckpointRpcRequest, *, now: method.Stamp) -> CheckpointRpcResponse: ...
    def lookup_transition(self, request: CheckpointRpcRequest, *, now: method.Stamp) -> CheckpointRpcResponse: ...

class CheckpointStorePort(Protocol):
    """Authority-owned store. No store initialization or reset via RPC."""
    def read_current(self, request: CheckpointRpcRequest, *, authenticated_caller: CheckpointCallerGrant,
                     now: method.Stamp) -> CheckpointRpcResponse: ...
    def compare_and_append(self, request: CheckpointRpcRequest, *,
                           authenticated_caller: CheckpointCallerGrant, now: method.Stamp) -> CheckpointRpcResponse: ...
    def lookup_exact(self, request: CheckpointRpcRequest, *, authenticated_caller: CheckpointCallerGrant,
                     now: method.Stamp) -> CheckpointRpcResponse: ...

def encode_frame(envelope: RpcSignature) -> bytes:
    """Pure framing only: no signature, peer or permission acceptance."""
    from .common import MAX_OBJECT, require
    raw = validate("RpcSignature", envelope).raw
    require(len(raw) + 4 <= MAX_OBJECT, "RPC_FRAME_SIZE")
    return len(raw).to_bytes(4, "big") + raw

def decode_frame(frame: bytes) -> StructuralRecord:
    from .common import MAX_OBJECT, require
    require(type(frame) is bytes and 4 < len(frame) <= MAX_OBJECT, "RPC_FRAME_SIZE")
    require(int.from_bytes(frame[:4], "big") == len(frame) - 4, "RPC_FRAME_LENGTH")
    return decode("RpcSignature", frame[4:])

def request_signing_bytes(request: CheckpointRpcRequest) -> bytes:
    return REQUEST_DOMAIN + validate("CheckpointRpcRequest", request).raw

def response_signing_bytes(response: CheckpointRpcResponse) -> bytes:
    return RESPONSE_DOMAIN + validate("CheckpointRpcResponse", response).raw

