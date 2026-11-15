"""Explicit host-side consumer of reviewed custody source02. Drafts only.

No provider appointment, collection, publication, ledger, process or permission
operation is implemented here. The caller must pin this source and independently
appoint the original-window guard and authentic providers. No workload imports.
"""
from .source.evidence_types import (
    Blocked, canonical, decode, digest, identifier, integer, need, reference,
    shape, timestamp, utc_now_value,
)
from .source.evidence_validator import validate_release_selection
from .source.observer_adapter import ObserverAdapter
from .source.protected_resolver import ProtectedResolver
from .source.release_issuer import ReleaseIssuer
from .source.aggregate_redactor import assemble_body, attach_independent_approval
from .source.trust_ports import StrictAuthority, UnsupportedAuthority

RELEASE_ENABLED = False
SOURCE02_MANIFEST_SHA256 = '7044632108c820034c0f4cd5bc57f05e227cd3fd71656db4d0b4b91d5ac8f102'
COMPLETION_CONTRACT_SHA256 = '8a65cded2f2e42ed3645a5b06b0266834c0fda5d3358f70faa2c1906f8d1c092'
MEASUREMENT_CONTRACT_SHA256 = 'f991b79beebef07119fc04d9093f2a97d9f5c6fb3ed260e8085f551fc632ed90'
BINDING_FIELDS = frozenset((
    'run_id', 'epoch', 'config_sha256', 'source_manifest_sha256', 'asset_manifest_sha256',
    'custody_public_manifest_sha256', 'issuer_binding_sha256', 'observer_binding_sha256',
    'source_test_observer_binding_sha256', 'original_clock_record', 't0_utc', 'work_deadline_utc',
))
AGGREGATE_SELECTION_FIELDS = frozenset((
    'format', 'run_id', 'epoch', 'source_freeze_manifest_sha256', 'custody_public_manifest_sha256',
    'retained_evaluation_bundle_sha256', 'accepted_private_mapping_sha256', 'mandatory_step_ids',
    'mandatory_assertion_ids', 'report_reference', 'retained_bundle_reference', 'scorer_binding_sha256',
    'custody_binding_sha256', 'public_run_id', 'reviewer_binding_sha256', 'redaction_receipt_reference',
))


class _BoundAuthority:
    """Guard/mutation checks around injected callbacks; not authentication."""
    def __init__(self, provider, guard):
        self.provider, self.guard = StrictAuthority(provider), guard

    def _call(self, name, kwargs):
        self.guard()
        before = canonical(kwargs)
        result = getattr(self.provider, name)(**kwargs)
        need(canonical(kwargs) == before, 'AUTHORITY_MUTATED_INPUT')
        self.guard()
        return result

    def authenticate(self, **kwargs): return self._call('authenticate', kwargs)
    def verify_semantics(self, **kwargs): return self._call('verify_semantics', kwargs)
    def verify_observation(self, **kwargs): return self._call('verify_observation', kwargs)
    def verify_inventory(self, **kwargs): return self._call('verify_inventory', kwargs)
    def verify_complete_scoring(self, **kwargs): return self._call('verify_complete_scoring', kwargs)
    def verify_redaction(self, **kwargs): return self._call('verify_redaction', kwargs)


class PublicCustodyConsumer:
    """Inert construction. All reads/assembly require explicit method calls.

    binding is the caller's independently selected original runtime binding,
    never copied from an incoming receipt. No callback return appoints that caller.
    The only supplied production authority rejects every trust operation.
    """
    def __init__(self, *, selected_base, binding, require_remaining, authority=None):
        shape(binding, BINDING_FIELDS)
        identifier(binding['run_id']); integer(binding['epoch'], 1)
        for name in BINDING_FIELDS:
            if name.endswith('_sha256'): digest(binding[name])
        timestamp(binding['t0_utc']); timestamp(binding['work_deadline_utc'])
        clock = binding['original_clock_record']
        shape(clock, ('model_window', 'model_calls', 'retry_calls', 'bootstrap_started_utc', 'test_deadline_utc'))
        shape(clock['model_window'], ('started_at', 'deadline', 'total_generation_limit', 'probe_limit', 'acceptance_limit', 'includes'))
        for value in (clock['model_window']['started_at'], clock['model_window']['deadline']): timestamp(value, z=False)
        need(callable(require_remaining), 'ORIGINAL_DEADLINE_GUARD_REQUIRED')
        self._binding = canonical(binding)
        self._guard = require_remaining
        self._resolver = ProtectedResolver(selected_base, require_remaining=self._remaining)
        self._authority = _BoundAuthority(authority if authority is not None else UnsupportedAuthority(), self._remaining)

    def _remaining(self):
        need(self._guard() is None, 'ORIGINAL_DEADLINE_GUARD_PROTOCOL')

    def _now(self, now):
        self._remaining()
        binding = decode(self._binding)
        window = binding['original_clock_record']['model_window']
        need(timestamp(window['started_at'], z=False) <= utc_now_value(now)
             < timestamp(window['deadline'], z=False), 'TIME_BUDGET')
        return binding

    def _selection(self, ref, publisher, purpose, *, now):
        binding = self._now(now)
        ref = decode(canonical(reference(ref))); digest(publisher)
        raw, selected = self._resolver.read(ref)
        # Resolver supplies exact raw bytes; authentication appointment is external.
        self._authority.authenticate(raw_sha256=ref['sha256'], purpose=purpose,
            publisher_sha256=publisher, run_id=binding['run_id'], epoch=binding['epoch'])
        need(selected['run_id'] == binding['run_id'] and type(selected['epoch']) is int
             and selected['epoch'] == binding['epoch'], 'PIN_MISMATCH')
        self._authority.verify_semantics(purpose=purpose, record=selected, dependencies={}, selection=selected)
        self._remaining()
        return decode(canonical(selected)), binding

    @staticmethod
    def _same(selected, binding, fields):
        need(all(selected[name] == binding[name] for name in fields), 'PIN_MISMATCH')

    def observer_draft(self, *, selection_reference, selection_authority_sha256, now):
        selected, binding = self._selection(selection_reference, selection_authority_sha256,
                                            'independent-observer-selection', now=now)
        self._same(selected, binding, ('run_id', 'epoch', 'source_manifest_sha256', 'config_sha256', 'observer_binding_sha256'))
        need(timestamp(selected['expires_at_utc']) <= timestamp(binding['original_clock_record']['model_window']['deadline'], z=False), 'TIME_BUDGET')
        draft = ObserverAdapter(resolver=self._resolver, selection_reference=selection_reference,
            selection_authority_sha256=selection_authority_sha256, run_id=binding['run_id'],
            epoch=binding['epoch'], authority=self._authority).assemble_disabled_draft(now=now)
        self._remaining()
        need(draft['format'] == 'forex.disabled-observer-draft/1', 'DISABLED_ENVELOPE_REQUIRED')
        return decode(canonical(draft))

    def release_draft(self, *, selection_reference, selection_authority_sha256,
                      release_id, issued_at_utc, not_before_utc, expires_at_utc, now):
        selected, binding = self._selection(selection_reference, selection_authority_sha256,
                                            'independent-runtime-selection', now=now)
        validate_release_selection(selected)  # /2 plus both completion additions
        self._same(selected, binding, ('run_id', 'epoch', 'config_sha256', 'source_manifest_sha256',
            'asset_manifest_sha256', 'issuer_binding_sha256', 'observer_binding_sha256',
            'source_test_observer_binding_sha256', 'original_clock_record', 't0_utc', 'work_deadline_utc'))
        need(selected['expected_release_bindings']['custody_manifest_sha256'] == binding['custody_public_manifest_sha256'], 'PIN_MISMATCH')
        draft = ReleaseIssuer(resolver=self._resolver, selection_reference=selection_reference,
            selection_authority_sha256=selection_authority_sha256, run_id=binding['run_id'],
            epoch=binding['epoch'], authority=self._authority).assemble_disabled_draft(
                release_id=release_id, issued_at_utc=issued_at_utc, not_before_utc=not_before_utc,
                expires_at_utc=expires_at_utc, now=now)
        self._remaining()
        need(draft['format'] == 'forex.disabled-release-draft/1', 'DISABLED_ENVELOPE_REQUIRED')
        return decode(canonical(draft))

    def aggregate_draft(self, *, selection_reference, selection_authority_sha256, now):
        selected, binding = self._selection(selection_reference, selection_authority_sha256,
                                            'independent-aggregate-selection', now=now)
        shape(selected, AGGREGATE_SELECTION_FIELDS)
        need(selected['format'] == 'forex.independent-aggregate-selection/1', 'PIN_MISMATCH')
        need(selected['source_freeze_manifest_sha256'] == binding['source_manifest_sha256']
             and selected['custody_public_manifest_sha256'] == binding['custody_public_manifest_sha256']
             and selected['public_run_id'] == binding['run_id'], 'PIN_MISMATCH')
        body = assemble_body(report_reference=selected['report_reference'],
            retained_bundle_reference=selected['retained_bundle_reference'], selected=selected,
            resolver=self._resolver, authority=self._authority)
        aggregate = attach_independent_approval(body=body,
            approval_reference=selected['redaction_receipt_reference'], selected=selected,
            resolver=self._resolver, authority=self._authority)
        self._remaining()
        # Caller receives a disabled wrapper, never a public-export file or grant.
        return {'format': 'forex.disabled-aggregate-draft/1', 'aggregate': decode(canonical(aggregate))}

    def issue(self, *args, **kwargs):
        raise Blocked('RELEASE_DISABLED_SOURCE_ONLY')

    def publish(self, *args, **kwargs):
        raise Blocked('PROTECTED_PUBLICATION_UNIMPLEMENTED')
