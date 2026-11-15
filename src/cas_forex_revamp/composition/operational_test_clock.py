"""Original source-test window, separate from the later 180-second method.

Construction validates selected values only. The deployment authorizer supplies
the original clock/domain/anchor and live execution gate. This module never
creates approval, a clock allowance, a method budget, or a supervisor.
"""
from dataclasses import dataclass
from datetime import timedelta
from threading import RLock

from cas_forex_operational_contracts import common, method, completion, protected
from custody_runtime.gate_adapters import clock_utc
from custody_runtime.source_test_clock import completion_clock_bytes, SOURCE_CLOCK_FORMAT


def _copy(value):
    return common.decode_canonical(common.canonical_bytes(value))


def _nanoseconds(delta):
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000


class OriginalPairedStampReader:
    """Bounded clock-only reader. read_stamp() grants no execution authority.

    Selected original UTC endpoints are mapped from a truthful observed paired
    anchor, never from object creation or first use. The pure mapping is
    local configuration, not a new wire record. Fresh domain reads are allowed
    here: source testing precedes the method's final consumption gap.
    """

    def __init__(self, *, original_clock_raw, expected_window_sha256,
                 work_started_utc, work_deadline_utc, clock_domain,
                 clock, work_start_stamp=None, clock_anchor_stamp=None):
        common.require(type(original_clock_raw) is bytes, 'ORIGINAL_CLOCK_BYTES')
        original = completion_clock_bytes(original_clock_raw)
        common.require(original == original_clock_raw, 'ORIGINAL_CLOCK_REQUIRED')
        common.require(common.digest(original) == expected_window_sha256, 'ORIGINAL_CLOCK_PIN')
        common.require(callable(getattr(clock, 'observe', None)),
                       'TEST_CLOCK_DEPENDENCY')
        self._original = original
        self._domain = method.validate('ClockDomain', clock_domain).raw
        common.require((work_start_stamp is None) != (clock_anchor_stamp is None), 'EXACT_CLOCK_ANCHOR')
        self._anchor = method.validate('Stamp', work_start_stamp if clock_anchor_stamp is None else clock_anchor_stamp).raw
        self._clock = clock
        self._lock, self._last, self._failed = RLock(), None, False
        value = common.decode_canonical(original)
        self._work_start = clock_utc(work_started_utc)
        work_end = clock_utc(work_deadline_utc)
        self._begin = clock_utc(value['bootstrap_started_utc'])
        test_end = clock_utc(value['test_deadline_utc'])
        anchor = method.decode('Stamp', self._anchor).payload()
        self._anchor_time = common.utc(anchor['utc'])
        common.require(work_end - self._work_start == timedelta(seconds=13200)
                       and self._work_start <= self._begin < test_end <= work_end,
                       'ORIGINAL_GLOBAL_CLOCK')
        if value.get('format') == SOURCE_CLOCK_FORMAT:
            common.require(clock_anchor_stamp is not None
                           and self._work_start <= self._anchor_time < test_end,
                           'ACTUAL_POSTBOOT_ANCHOR_REQUIRED')
            self._end = min(test_end, work_end)
        else:
            common.require(self._anchor_time == self._work_start, 'ORIGINAL_ANCHOR_TIME')
            model_start = clock_utc(value['model_window']['started_at'], window=True)
            model_end = clock_utc(value['model_window']['deadline'], window=True)
            common.require(self._begin < model_start < model_end <= work_end
                           and model_end == min(model_start + timedelta(seconds=5400), work_end),
                           'ORIGINAL_GLOBAL_CLOCK')
            self._end = min(test_end, model_start, work_end)
        common.require(self._begin < self._end, 'ORIGINAL_TEST_WINDOW')
        self._begin_ns = anchor['boottime_ns'] + _nanoseconds(self._begin - self._anchor_time)
        self._end_ns = anchor['boottime_ns'] + _nanoseconds(self._end - self._anchor_time)

    @property
    def original_clock_raw(self):
        return self._original

    @property
    def failed(self):
        return self._failed

    @property
    def original_deadline(self):
        """Fixed paired endpoint mapped from the actual selected anchor."""
        return {'utc': self._end.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                'boottime_ns': self._end_ns}

    def read_stamp(self):
        with self._lock:
            common.require(not self._failed, 'TEST_CLOCK_UNAVAILABLE')
            try:
                domain, supplied = self._clock.observe()
                current = method.validate('Stamp', supplied).payload()
                common.require(method.validate('ClockDomain', domain).raw == self._domain,
                               'CLOCK_DOMAIN_UNSUPPORTED')
                when = common.utc(current['utc'])
                ticks = current['boottime_ns']
                common.require(max(self._begin, self._anchor_time) <= when < self._end
                               and self._begin_ns <= ticks < self._end_ns, 'ORIGINAL_TEST_WINDOW')
                anchor = method.decode('Stamp', self._anchor).payload()
                common.require(abs(_nanoseconds(when - self._anchor_time)
                                   - (ticks - anchor['boottime_ns'])) <= 1000000000, 'CLOCK_DRIFT')
                if self._last is not None:
                    common.require(when >= common.utc(self._last['utc'])
                                   and ticks >= self._last['boottime_ns'], 'CLOCK_DRIFT')
                self._last = _copy(current)
                return _copy(current)
            except BaseException:
                self._failed = True
                raise

class OriginalTestClock(OriginalPairedStampReader):
    """Time reader plus separately authenticated execution permission."""
    def __init__(self, *, execution_gate, **kwargs):
        common.require(callable(execution_gate), 'TEST_CLOCK_DEPENDENCY')
        super().__init__(**kwargs)
        self._gate = execution_gate

    def now(self):
        with self._lock:
            common.require(not self._failed, 'TEST_CLOCK_UNAVAILABLE')
            try:
                common.require(self._gate() is None, 'EXECUTION_APPROVAL_UNAVAILABLE')
                current = self.read_stamp()
                common.require(self._gate() is None, 'EXECUTION_APPROVAL_UNAVAILABLE')
                return current
            except BaseException:
                self._failed = True
                raise

    def remaining(self):
        current = self.now()
        return min((self._end_ns - current['boottime_ns']) / 1000000000,
                   (self._end - common.utc(current['utc'])).total_seconds())


class OriginalTestClockReference:
    """Resolve the exact independently selected clock through protected storage.

    The resolver owns publisher/root/grant/signature checks. This adapter binds
    its returned bytes to the clock already selected by the deployment and the
    completion selection. Shape/hash checks alone do not establish authority.
    """

    def __init__(self, *, selected_use, publishers, resolver, guard):
        use = protected.validate('ProtectedReferenceUse', selected_use).payload()
        selected = protected.validate('PublisherRootSelection', publishers).payload()
        reference = use['reference']
        common.require(use['required_use'] == 'SOURCE_COMPLETION'
                       and reference['record_kind'] == 'EXTERNAL_RELEASE_EVIDENCE'
                       and reference['purpose'] == 'release-evidence:original_clock_and_budget_binding_sha256'
                       and reference['binding'] == selected['binding']
                       and reference['publisher_selection_sha256'] == common.digest(common.canonical_bytes(selected)),
                       'COMPLETION_CLOCK_ROUTE')
        common.require(type(guard) is OriginalTestClock
                       and reference['binding']['original_window_sha256'] == common.digest(guard.original_clock_raw),
                       'ORIGINAL_CLOCK_PIN')
        self._use, self._publishers = common.canonical_bytes(use), common.canonical_bytes(selected)
        self._resolver, self._guard = resolver, guard

    def __call__(self, use, now):
        common.require(protected.validate('ProtectedReferenceUse', use).raw == self._use,
                       'ORIGINAL_CLOCK_REFERENCE_CHANGED')
        supplied = method.validate('Stamp', now).payload()
        current = self._guard.now()
        common.require(common.utc(supplied['utc']) <= common.utc(current['utc'])
                       and supplied['boottime_ns'] <= current['boottime_ns'], 'CLOCK_FUTURE')
        selected = protected.decode('PublisherRootSelection', self._publishers).payload()
        raw = self._resolver.resolve(protected.decode('ProtectedReferenceUse', self._use).payload(),
                                     selection=selected, now=current)
        reference = protected.decode('ProtectedReferenceUse', self._use).payload()['reference']
        common.require(type(raw) is bytes and len(raw) == reference['bytes']
                       and common.digest(raw) == reference['sha256'], 'ORIGINAL_CLOCK_RECORD_BYTES')
        common.require(completion_clock_bytes(raw) == self._guard.original_clock_raw,
                       'ORIGINAL_CLOCK_SUBSTITUTION')
        self._guard.now()


@dataclass(frozen=True)
class SourceCompletionComponents:
    guard: OriginalTestClock
    clock_reference: OriginalTestClockReference
    capture: object
    observer: object
    run: object


def wire_source_completion(*, original_clock_raw, work_started_utc, work_deadline_utc,
                           clock_domain, completion_selection, work_start_stamp=None, clock_anchor_stamp=None,
                           selection_use, publishers, resolver, capture_sink,
                           observer_publish, custody_publish, custody_publisher_id,
                           authenticate_selection, execution_gate, environment,
                           environment_profile_sha256, parser_component_sha256,
                           parser_schema_sha256):
    """Inert composition with concrete Linux clock, inventory and process capture.

    Trusted bootstrap supplies the separately authenticated selections and real
    publication/authorization ports. Calling this function does not read a clock,
    resolve a record, initialize storage, run a test, or create a supervisor.
    Explicit components.run.run() remains the future execution boundary.
    """
    from cas_forex_authority.authentication import LinuxOriginalClock
    from cas_forex_measurement.inventory import LinuxInventory
    from cas_forex_measurement.completion import ForkExecCapture, CompletionObserver
    from .operational_completion import CompletionRun

    selected = completion.validate('CompletionSelection2', completion_selection).payload()
    use = protected.validate('ProtectedReferenceUse', selection_use).payload()
    raw = completion.validate('CompletionSelection2', selected).raw
    common.require(use['required_use'] == 'SOURCE_COMPLETION'
                   and use['reference']['record_kind'] == 'COMPLETION_SELECTION'
                   and use['reference']['purpose'] == 'completion-selection'
                   and use['reference']['binding'] == selected['binding']
                   and use['reference']['sha256'] == common.digest(raw)
                   and use['reference']['bytes'] == len(raw), 'COMPLETION_SELECTION_BINDING')
    guard = OriginalTestClock(original_clock_raw=original_clock_raw,
        expected_window_sha256=selected['binding']['original_window_sha256'],
        work_started_utc=work_started_utc, work_deadline_utc=work_deadline_utc,
        clock_domain=clock_domain, work_start_stamp=work_start_stamp, clock_anchor_stamp=clock_anchor_stamp,
        clock=LinuxOriginalClock(), execution_gate=execution_gate)
    reference = OriginalTestClockReference(selected_use=selected['original_clock_ref'],
        publishers=publishers, resolver=resolver, guard=guard)
    capture = ForkExecCapture(inventory=LinuxInventory(), guard=guard,
        execution_gate=execution_gate, capture_sink=capture_sink)
    observer = CompletionObserver(resolver=resolver, publishers=_copy(publishers),
        publish_record=observer_publish, guard=guard, original_clock_verifier=reference,
        environment=dict(environment), environment_profile_sha256=environment_profile_sha256,
        process_capture=capture, observer_id=selected['observer_id'],
        parser_component_sha256=parser_component_sha256,
        authenticate_selection=authenticate_selection, parser_schema_sha256=parser_schema_sha256)
    run = CompletionRun(observer=observer, resolver=resolver, publishers=publishers,
        selection_use=use, observer_publish=observer_publish, custody_publish=custody_publish,
        custody_publisher_id=custody_publisher_id, authenticate_selection=authenticate_selection,
        guard=guard, execution_gate=execution_gate)
    return SourceCompletionComponents(guard, reference, capture, observer, run)
