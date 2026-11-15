"""Accepted candidate03 wire types. Shape validation is not authentication."""
from __future__ import annotations
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias, TypedDict
from .common import JSONValue, StructuralRecord, SelectedShapeValidator, ValidationLimits
if TYPE_CHECKING:
    from . import method, capture, protected, completion, release, checkpoint

CompletionGroup: TypeAlias = Literal['contracts', 'core', 'venue', 'operator', 'rpa', 'integration', 'provider04', 'policy-inheritance02', 'operational-measurement', 'operational-authority', 'operational-custody', 'node-version', 'ui']

class CompletionSelection2(TypedDict):
    format: Literal['forex.runtime-completion-selection/2']
    selection_id: str
    binding: protected.EvaluationBinding
    publisher_selection_sha256: str
    observer_id: str
    verifier_id: str
    verifier_component_sha256: str
    original_clock_ref: protected.ProtectedReferenceUse
    source_inventory_ref: protected.ProtectedReferenceUse
    groups: list[GroupSelection]
    not_before_utc: str
    expires_at_utc: str

class GroupSelection(TypedDict):
    group_id: CompletionGroup
    command: protected.ProtectedReferenceUse
    parser: protected.ProtectedReferenceUse
    expected_inventory: protected.ProtectedReferenceUse
    expected_test_count: int
    mode: Literal['PYTHON_METHODS', 'NODE_TAP', 'NODE_VERSION']

class CommandPin(TypedDict):
    format: Literal['forex.test-command-pin/1']
    binding: protected.EvaluationBinding
    group_id: CompletionGroup
    executable: method.ExecutableAssetIdentity
    argv: list[str]
    cwd: str
    environment_profile_sha256: str
    stdin_policy: Literal['CLOSED']
    source_manifest_sha256: str
    command_sha256: str

class ParserPin(TypedDict):
    format: Literal['forex.test-parser-pin/1']
    binding: protected.EvaluationBinding
    parser_id: str
    component_manifest_sha256: str
    entrypoint: str
    mode: Literal['PYTHON_METHODS', 'NODE_TAP', 'NODE_VERSION']
    accepted_report_format: Literal['forex.python-framework-report/2', 'forex.node-tap-report/1', 'forex.node-version-report/1']
    report_schema_sha256: str
    test_id_encoding: Literal['QUALIFIED_UNITTEST_ID', 'FULL_NODE_TEST_NAME', 'NO_TEST_IDS']
    expected_stdout_utf8: str | None
    maximum_stream_bytes: int
    maximum_report_bytes: int
    expected_stderr_utf8: str | None

class CollectionInventory(TypedDict):
    format: Literal['forex.test-collection-inventory/1']
    binding: protected.EvaluationBinding
    group_id: CompletionGroup
    source_manifest_sha256: str
    entries: list[TestInventoryEntry]
    expected_count: int
    test_ids_sha256: str

class TestInventoryEntry(TypedDict):
    test_id: str
    source_relative_path: str
    source_file_sha256: str

class SourceInventory(TypedDict):
    format: Literal['forex.completion-source-inventory/1']
    binding: protected.EvaluationBinding
    source_manifest_sha256: str
    test_files: list[TestFileAssignment]
    group_order: list[CompletionGroup]
    test_roots: list[SourceTestRoot]

class TestFileAssignment(TypedDict):
    source_relative_path: str
    source_file_sha256: str
    group_id: CompletionGroup

class TestStream2(TypedDict):
    format: Literal['forex.test-stream/2']
    binding: protected.EvaluationBinding
    group_id: CompletionGroup
    process: capture.CaptureSubject
    stream: Literal['STDOUT', 'STDERR']
    encoding: Literal['UTF8_STRICT']
    utf8: JSONValue
    raw_sha256: str
    bytes: int
    complete: Literal[True]

class ProcessCapture2(TypedDict):
    format: Literal['forex.test-process-capture/2']
    binding: protected.EvaluationBinding
    selection_sha256: str
    group_id: CompletionGroup
    command_sha256: str
    executable_sha256: str
    events: list[TestProcessEvent]
    lost_events: Literal[0]
    stdout_ref: protected.ProtectedReferenceUse
    stderr_ref: protected.ProtectedReferenceUse

class TestProcessEvent(TypedDict):
    sequence: int
    kind: Literal['SPAWN', 'EXIT']
    process: capture.CaptureSubject
    at_utc: str
    exit_code: int | None

class GroupReport2(TypedDict):
    format: Literal['forex.observed-test-group/2']
    binding: protected.EvaluationBinding
    selection_sha256: str
    group_id: CompletionGroup
    process: capture.CaptureSubject
    command_ref: protected.ProtectedReferenceUse
    parser_ref: protected.ProtectedReferenceUse
    expected_inventory_ref: protected.ProtectedReferenceUse
    capture_ref: protected.ProtectedReferenceUse
    stdout_ref: protected.ProtectedReferenceUse
    stderr_ref: protected.ProtectedReferenceUse
    original_framework_report_ref: protected.ProtectedReferenceUse
    started_at_utc: str
    finished_at_utc: str
    exit_code: int
    collected_test_ids: list[str]
    executed_test_ids: list[str]
    counts: CompletionCounts
    node_version_utf8: str | None
    discovery_report_ref: protected.ProtectedReferenceUse

class CompletionCounts(TypedDict):
    discovered: int
    ran: int
    passed: int
    skipped: int
    failures: int
    errors: int
    cancelled: int
    todo: int

class CompletionObservation2(TypedDict):
    format: Literal['forex.source-test-observation/2']
    binding: protected.EvaluationBinding
    selection_sha256: str
    observer_id: str
    groups: list[protected.ProtectedReferenceUse]
    completed_at_utc: str

class SourceTestReport2(TypedDict):
    format: Literal['forex.original-source-test-report/2']
    binding: protected.EvaluationBinding
    selection_sha256: str
    group_reports: list[protected.ProtectedReferenceUse]
    status: Literal['PASS', 'FAIL', 'INCOMPLETE']
    finished_utc: str
    original_bootstrap_started_utc: str
    test_deadline_utc: str

class CompletionReceipt2(TypedDict):
    format: Literal['forex.observed-source-test-completion/2']
    binding: protected.EvaluationBinding
    selection_ref: protected.ProtectedReferenceUse
    observer_id: str
    verifier_id: str
    verifier_component_sha256: str
    original_clock_record_content_sha256: str
    completed_at_utc: str
    original_source_test_report: protected.ProtectedReferenceUse
    observation_evidence: protected.ProtectedReferenceUse
    group_reports_sha256: str

class PythonFrameworkReport2(TypedDict):
    format: Literal['forex.python-framework-report/2']
    group_id: Literal['contracts', 'core', 'venue', 'operator', 'rpa', 'integration', 'provider04', 'policy-inheritance02', 'operational-measurement', 'operational-authority', 'operational-custody']
    collected_test_ids: list[str]
    executed_test_ids: list[str]
    counts: CompletionCounts
    status: Literal['PASS', 'FAIL', 'INCOMPLETE']

class NodeTapReport1(TypedDict):
    format: Literal['forex.node-tap-report/1']
    group_id: Literal['ui']
    collected_test_ids: list[str]
    test_results: list[NodeTestResult]
    counts: CompletionCounts
    complete: bool

class NodeTestResult(TypedDict):
    test_id: str
    result: Literal['PASS', 'FAIL', 'SKIP', 'CANCELLED', 'TODO']

class NodeVersionReport1(TypedDict):
    format: Literal['forex.node-version-report/1']
    group_id: Literal['node-version']
    stdout_utf8: str
    stderr_utf8: str

class SourceTestRoot(TypedDict):
    source_relative_directory: str
    suffixes: list[Literal['.py', '.mjs']]
    group_id: CompletionGroup

class TestDiscoveryReport(TypedDict):
    format: Literal['forex.test-discovery-report/1']
    binding: protected.EvaluationBinding
    selection_sha256: str
    group_id: CompletionGroup
    process: capture.CaptureSubject
    source_inventory_sha256: str
    collected_test_ids: list[str]
    collected_at_utc: str

def validate(type_name: str, value: JSONValue, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import validate_record
    return validate_record('completion', type_name, value, shape_validator=shape_validator, limits=limits)

def decode(type_name: str, raw: bytes, *, shape_validator: SelectedShapeValidator | None = None, limits: ValidationLimits | None = None) -> StructuralRecord:
    from .validation import decode_record
    return decode_record('completion', type_name, raw, shape_validator=shape_validator, limits=limits)

GROUP_ORDER = ("contracts", "core", "venue", "operator", "rpa", "integration", "provider04",
               "policy-inheritance02", "operational-measurement", "operational-authority",
               "operational-custody", "node-version", "ui")

class CompletionObserverPort(Protocol):
    """Measurement produces observations, not a completion acceptance."""
    def observe(self, selection: CompletionSelection2, *,
                group: GroupSelection) -> tuple[ProcessCapture2, TestStream2, TestStream2, GroupReport2]: ...

class CompletionVerifierPort(Protocol):
    """Custody exclusively implements substantive collection/stream/clock checks."""
    def verify(self, selection: CompletionSelection2, report: SourceTestReport2,
               observation: CompletionObservation2, *, resolver: protected.ProtectedResolverPort,
               publishers: protected.PublisherRootSelection, now: method.Stamp) -> CompletionReceipt2: ...

