"""Unimplemented external authority ports. Payloads cannot select a provider.

No ready/verified boolean is accepted. Implementations must be selected and
pinned outside workload inputs in a separately reviewed successor. This package
deliberately supplies no authentication, syscall collector or private scorer.
"""
from .evidence_types import Blocked, need


class StrictAuthority:
    """Selected provider contract: raise on failure, return None on success.

    A provider must be independently appointed/pinned outside payloads. This
    wrapper rejects returned booleans/labels; it does not appoint that provider.
    """
    def __init__(self, provider):
        self.provider = provider

    def authenticate(self, **kwargs):
        need(self.provider.authenticate(**kwargs) is None, "AUTHENTICATION_PROVIDER_PROTOCOL")

    def verify_semantics(self, **kwargs):
        need(self.provider.verify_semantics(**kwargs) is None, "SEMANTIC_PROVIDER_PROTOCOL")

    def verify_observation(self, **kwargs):
        need(self.provider.verify_observation(**kwargs) is None, "OBSERVER_PROVIDER_PROTOCOL")

    def verify_inventory(self, **kwargs):
        need(self.provider.verify_inventory(**kwargs) is None, "OBSERVER_PROVIDER_PROTOCOL")

    def verify_complete_scoring(self, **kwargs):
        need(self.provider.verify_complete_scoring(**kwargs) is None, "SCORER_PROVIDER_PROTOCOL")

    def verify_redaction(self, **kwargs):
        need(self.provider.verify_redaction(**kwargs) is None, "REDACTION_PROVIDER_PROTOCOL")


class UnsupportedAuthority:
    def authenticate(self, *, raw_sha256, purpose, publisher_sha256, run_id, epoch):
        raise Blocked("AUTHENTICATION_PROVIDER_UNIMPLEMENTED")

    def verify_semantics(self, *, purpose, record, dependencies, selection):
        raise Blocked("INDEPENDENT_SEMANTIC_PROVIDER_UNIMPLEMENTED")

    def verify_observation(self, *, raw_record, source_artifacts, selection):
        raise Blocked("POST_EXEC_COLLECTOR_UNIMPLEMENTED")

    def verify_inventory(self, *, kind, record, selection):
        raise Blocked("POST_EXEC_COLLECTOR_UNIMPLEMENTED")

    def verify_complete_scoring(self, *, record, retained_bundle, selection):
        raise Blocked("INDEPENDENT_SCORER_UNIMPLEMENTED")

    def verify_redaction(self, *, body, retained_bundle, selection):
        raise Blocked("INDEPENDENT_REDACTION_REVIEW_UNIMPLEMENTED")


class UnsupportedPublisher:
    def publish_once(self, *, prepared_identity, records):
        raise Blocked("PROTECTED_PUBLICATION_UNIMPLEMENTED")

