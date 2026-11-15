"""Concrete source-completion caller. Nothing runs on import or construction."""
from dataclasses import dataclass
from cas_forex_operational_contracts import common, completion, protected
from .operational_test_clock import wire_source_completion


@dataclass(frozen=True)
class SourceCompletionOutcome:
    receipt_raw: bytes
    receipt_use_raw: bytes
    report_use_raw: bytes
    observation_use_raw: bytes


class SourceCompletionBootstrap:
    """One explicit attempt; custody's result is independently read back.

    The fixed production factory creates authenticated selected bindings.
    Injecting public test doubles here cannot issue production authorization.
    """
    def __init__(self, *, bindings, wire_arguments):
        required = ('execution_gate', 'verify_completion', 'publish_completion',
                    'authenticate_selection', 'observer_publish', 'custody_publish')
        common.require(all(callable(getattr(bindings, k, None)) for k in required),
                       'SOURCE_BINDINGS_UNAVAILABLE')
        common.require(type(wire_arguments) is dict, 'SOURCE_WIRE_ARGUMENTS')
        self._bindings = bindings
        self._arguments = dict(wire_arguments)
        for name in ('resolver', 'observer_publish', 'custody_publish',
                     'authenticate_selection', 'execution_gate'):
            common.require(name not in self._arguments, 'DUPLICATE_AUTHORITY_BINDING')
        self.state = 'NEW'
        self.failure_type = None
        self.retained_result = None
        self.verified_receipt_raw = None
        self.published_receipt_use_raw = None

    def execute(self):
        common.require(self.state == 'NEW', 'SOURCE_ATTEMPT_ALREADY_USED')
        self.state = 'ATTEMPTED'
        b = self._bindings
        try:
            common.require(b.execution_gate() is None, 'SOURCE_EXECUTION_UNAVAILABLE')
            args = dict(self._arguments)
            components = wire_source_completion(**args, resolver=b.resolver,
                observer_publish=b.observer_publish, custody_publish=b.custody_publish,
                authenticate_selection=b.authenticate_selection, execution_gate=b.execution_gate)
            # Actual measurement composition, not the historical six-group CLI.
            result = components.run.run()
            self.retained_result = result
            common.require(result.selection_raw == completion.validate(
                'CompletionSelection2', args['completion_selection']).raw, 'RUN_SELECTION_CHANGED')
            report_use = protected.decode('ProtectedReferenceUse', result.report_use_raw).payload()
            observation_use = protected.decode('ProtectedReferenceUse', result.observation_use_raw).payload()
            common.require(b.execution_gate() is None, 'SOURCE_EXECUTION_UNAVAILABLE')
            verified = b.verify_completion(report_use, observation_use, now=components.guard.now())
            common.require(type(verified) is bytes, 'COMPLETION_RECEIPT_BYTES')
            receipt = completion.decode('CompletionReceipt2', verified).payload()
            common.require(receipt['original_source_test_report'] == report_use
                           and receipt['observation_evidence'] == observation_use
                           and receipt['selection_ref'] == args['selection_use'],
                           'COMPLETION_RECEIPT_SUBSTITUTION')
            self.verified_receipt_raw = verified
            self.state = 'VERIFIED_AWAITING_PUBLICATION'
            common.require(b.execution_gate() is None, 'SOURCE_EXECUTION_UNAVAILABLE')
            use, published_raw = b.publish_completion(report_use, observation_use,
                                                       now=components.guard.now())
            # Publication rechecks originals. It must retain the same completed
            # body, not create a later completion time or accept a different run.
            common.require(published_raw == verified, 'COMPLETION_REVERIFICATION_CHANGED')
            use = protected.validate('ProtectedReferenceUse', use).payload()
            ref = use['reference']
            selected = protected.validate('PublisherRootSelection', args['publishers']).payload()
            common.require(use['required_use'] == 'SOURCE_COMPLETION'
                           and ref['record_kind'] == 'SOURCE_TEST_COMPLETION'
                           and ref['purpose'] == 'source-test-completion'
                           and ref['binding'] == receipt['binding']
                           and ref['publisher_selection_sha256'] == common.digest(
                               protected.validate('PublisherRootSelection', selected).raw)
                           and ref['sha256'] == common.digest(verified)
                           and ref['bytes'] == len(verified), 'COMPLETION_PUBLICATION_SUBSTITUTED')
            self.published_receipt_use_raw = protected.validate('ProtectedReferenceUse', use).raw
            actual = b.resolver.resolve(use, selection=selected, now=components.guard.now())
            common.require(actual == verified, 'COMPLETION_RECEIPT_READBACK')
            common.require(b.execution_gate() is None, 'SOURCE_EXECUTION_UNAVAILABLE')
            self.state = 'SOURCE_COMPLETION_PUBLISHED'
            return SourceCompletionOutcome(verified, self.published_receipt_use_raw,
                                           result.report_use_raw, result.observation_use_raw)
        except BaseException as error:
            self.failure_type = type(error).__name__
            self.state = 'INCOMPLETE'
            raise


def build_source_bootstrap(*, config, public_keys, base_execution_gate,
                           source_manifest_raw, completion_material_raw,
                           completion_selection_raw, selection_use,
                           original_clock_raw, clock_domain, clock_anchor_stamp,
                           capture_directory, environment,
                           environment_profile_sha256, parser_component_sha256,
                           parser_schema_sha256, work_started_utc, work_deadline_utc):
    """Fixed concrete factory; inert until execute(). No module names from JSON."""
    from cas_forex_authority.authentication import LinuxOriginalClock
    from cas_forex_measurement.capture import DirectoryCaptureSink
    from custody_runtime.source_completion import bind_source_completion
    from custody_runtime.source_test_clock import source_test_clock_bytes
    from .operational_test_clock import OriginalPairedStampReader

    selection = completion.decode('CompletionSelection2', completion_selection_raw).payload()
    original = source_test_clock_bytes(original_clock_raw)
    raw_clock = OriginalPairedStampReader(original_clock_raw=original,
        expected_window_sha256=selection['binding']['original_window_sha256'],
        work_started_utc=work_started_utc, work_deadline_utc=work_deadline_utc,
        clock_domain=clock_domain, clock_anchor_stamp=clock_anchor_stamp,
        clock=LinuxOriginalClock())
    bindings = bind_source_completion(config=config, public_keys=public_keys,
        clock=raw_clock.read_stamp,
        original_deadline=raw_clock.original_deadline,
        base_execution_gate=base_execution_gate, source_manifest_raw=source_manifest_raw,
        completion_material_raw=completion_material_raw,
        completion_selection_raw=completion_selection_raw, selection_use=selection_use)
    capture = DirectoryCaptureSink(capture_directory, execution_gate=bindings.execution_gate)
    return SourceCompletionBootstrap(bindings=bindings, wire_arguments={
        'original_clock_raw': original, 'work_started_utc': work_started_utc,
        'work_deadline_utc': work_deadline_utc, 'clock_domain': clock_domain,
        'clock_anchor_stamp': clock_anchor_stamp, 'completion_selection': selection,
        'selection_use': selection_use, 'publishers': config['publisher_selection'],
        'capture_sink': capture, 'custody_publisher_id': config['custody_publisher_id'],
        'environment': environment, 'environment_profile_sha256': environment_profile_sha256,
        'parser_component_sha256': parser_component_sha256, 'parser_schema_sha256': parser_schema_sha256})
