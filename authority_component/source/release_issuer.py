"""Validated candidate assembly only. All receipt issuance is disabled."""
from .evidence_types import Blocked, canonical, decode, digest, identifier, integer, need, reference, timestamp
from .evidence_validator import validate_reference_set, validate_release_shape
from .trust_ports import StrictAuthority, UnsupportedAuthority


class ReleaseIssuer:
    def __init__(self, *, resolver, selection_reference, selection_authority_sha256, run_id, epoch, authority=None):
        self.resolver = resolver
        self.authority = StrictAuthority(authority if authority is not None else UnsupportedAuthority())
        self.selection_reference = decode(canonical(reference(selection_reference)))
        self.selection_authority_sha256 = digest(selection_authority_sha256)
        self.run_id, self.epoch = identifier(run_id), integer(epoch, 1)

    def assemble_disabled_draft(self, *, release_id, issued_at_utc, not_before_utc, expires_at_utc, now):
        # The selection's raw reference/author are selected outside its payload.
        # No self-hash field is embedded in the selected record.
        _, selected = self.resolver.read(self.selection_reference)
        need(selected["run_id"] == self.run_id and selected["epoch"] == self.epoch
             and selected["release_id"] == release_id, "PIN_MISMATCH")
        self.authority.authenticate(raw_sha256=self.selection_reference["sha256"], purpose="independent-runtime-selection",
            publisher_sha256=self.selection_authority_sha256, run_id=self.run_id, epoch=self.epoch)
        self.authority.verify_semantics(purpose="independent-runtime-selection", record=selected, dependencies={}, selection=selected)
        validate_reference_set(selected=selected, references=selected["references"], resolver=self.resolver,
                               authority=self.authority, now=now)
        expected = selected["expected_release_bindings"]
        receipt = {"format": "forex.custody-release-receipt/2", "release_id": release_id,
            "issued_at_utc": issued_at_utc, "not_before_utc": not_before_utc, "expires_at_utc": expires_at_utc, **expected}
        deadline = timestamp(selected["original_clock_record"]["model_window"]["deadline"], z=False)
        validate_release_shape(receipt, expected=expected, now=now, deadline=deadline)
        need(timestamp(expires_at_utc) <= timestamp(selected["independently_validated_observed_roles"]["expires_at_utc"]), "ISOLATION_GATE")
        authority = {"format": "forex.external-custody-authority/1", "config_sha256": selected["config_sha256"],
            "issuer_binding_sha256": selected["issuer_binding_sha256"], "observer_binding_sha256": selected["observer_binding_sha256"],
            "run_id": selected["run_id"], "references": selected["references"], "expected_release_bindings": expected}
        # Envelope is intentionally NOT an accepted wire release/authority record.
        return {"format": "forex.disabled-release-draft/1", "release": receipt, "authority": authority}

    def issue(self, *args, **kwargs):
        # No flag/environment/config can enable this frozen source version.
        raise Blocked("RELEASE_DISABLED_SOURCE_ONLY")

    def publish(self, *args, **kwargs):
        raise Blocked("PROTECTED_PUBLICATION_UNIMPLEMENTED")
