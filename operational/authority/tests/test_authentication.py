"""Authored public trust/clock regressions. NOT_RUN; fake signatures only."""
from copy import deepcopy
from dataclasses import replace
from unittest import TestCase
from cas_forex_operational_contracts import checkpoint as ck
from cas_forex_operational_contracts.common import canonical_bytes, digest
from cas_forex_authority.authentication import (AuthorityError, OriginalGuard, LiveAuthorityView,
    PreloadedEd25519Verifier, MethodAuthenticator)
from support import fixture, stamp, FixtureClock, FixtureVerifier, FixtureSigner, signed_rpc, fixture_preloaded_verifier


class AuthenticationTests(TestCase):
    def test_constructor_never_calls_authority_provider(self):
        f = fixture()
        def forbidden(*args): raise AssertionError("constructor performed I/O")
        MethodAuthenticator(f.auth.selection, guard=f.guard, verifier=FixtureVerifier(),
                            current_status=forbidden, initial_authorization=forbidden)

    def test_witness_signature_roundtrip(self):
        f = fixture(); raw = canonical_bytes({"observed": stamp()})
        envelope = f.auth.attest(raw, purpose="policy-inheritance-witness-v3", producer_id="witness",
                                signer=FixtureSigner(f.keys["witness"]), now=f.guard.check())
        self.assertIsNone(f.auth.verify_attestation(raw, envelope, expected_purpose="policy-inheritance-witness-v3",
                                                   appointment=f.appointment, now=f.guard.check()))

    def test_changed_bytes_reject_even_well_formed_envelope(self):
        f = fixture(); raw = canonical_bytes({"x": 1})
        e = f.auth.attest(raw, purpose="policy-inheritance-witness-v3", producer_id="witness",
                          signer=FixtureSigner(f.keys["witness"]), now=f.guard.check())
        with self.assertRaises(AuthorityError):
            f.auth.verify_attestation(canonical_bytes({"x": 2}), e, expected_purpose="policy-inheritance-witness-v3",
                                      appointment=f.appointment, now=f.guard.check())

    def test_valid_signature_wrong_purpose_rejects(self):
        f = fixture(); raw = canonical_bytes({"x": 1})
        e = f.auth.attest(raw, purpose="policy-inheritance-witness-v3", producer_id="witness",
                          signer=FixtureSigner(f.keys["witness"]), now=f.guard.check())
        with self.assertRaises(AuthorityError):
            f.auth.verify_attestation(raw, e, expected_purpose="policy-inheritance-checkpoint-v3", appointment=f.appointment, now=f.guard.check())

    def test_revocation_invalidates_prior_authority(self):
        f = fixture(); f.auth.current(); f.status["status"] = "WITHDRAWN"; f.status["revision"] += 1
        with self.assertRaises(AuthorityError): f.auth.current()

    def test_same_revision_changed_body_rejects(self):
        f = fixture(); f.auth.current(); f.status["expires_at_utc"] = stamp(590)["utc"]
        with self.assertRaises(AuthorityError): f.auth.current()

    def test_revision_rollback_rejects(self):
        f = fixture(); f.status["revision"] = 3; f.auth.current(); f.status["revision"] = 2
        with self.assertRaises(AuthorityError): f.auth.current()

    def test_shortened_appointment_cannot_shorten_original_budget(self):
        f = fixture(); f.status["expires_at_utc"] = stamp(179)["utc"]
        with self.assertRaises(AuthorityError): f.auth.current()

    def test_exact_deadline_is_expired(self):
        f = fixture(); f.clock.now = stamp(180)
        with self.assertRaises(AuthorityError): f.guard.check()

    def test_boot_identity_change_rejects(self):
        f = fixture(); f.clock.domain = {**f.clock.domain, "boot_id": "different"}
        with self.assertRaises(AuthorityError): f.guard.check()

    def test_utc_rollback_with_advancing_boottime_rejects(self):
        f = fixture(); f.clock.now = stamp(2); f.guard.check()
        f.clock.now = {**stamp(1), "boottime_ns": stamp(2)["boottime_ns"] + 1}
        with self.assertRaises(AuthorityError): f.guard.check()

    def test_deadline_extension_constructor_rejects(self):
        f = fixture(); changed = deepcopy(f.budget); changed["deadline"] = stamp(181)
        with self.assertRaises(AuthorityError): OriginalGuard(changed, clock=f.clock)

    def test_unprepared_crypto_fails_closed_without_loading(self):
        v = PreloadedEd25519Verifier((bytes([1])*32,))
        with self.assertRaises(AuthorityError): v.verify(public_key=bytes([1])*32, message=b"public", signature=bytes(64))

    def test_live_view_needs_authenticated_publish(self):
        f = fixture(); view = LiveAuthorityView(selection=f.auth.selection, budget=f.budget, verifier=fixture_preloaded_verifier(f))
        with self.assertRaises(AuthorityError): view.current_authority(stamp(1))
        view.publish_authenticated(signed_rpc(f.status, ck.AUTHORITY_STATUS_DOMAIN, bytes([4])*32), observed=stamp(1))
        self.assertEqual(view.current_authority(stamp(1)), f.status)
        view.invalidate()
        with self.assertRaises(AuthorityError): view.current_authority(stamp(1))

    def test_live_view_rejects_stale_status_without_io(self):
        f = fixture(); view = LiveAuthorityView(selection=f.auth.selection, budget=f.budget, verifier=fixture_preloaded_verifier(f))
        view.publish_authenticated(signed_rpc(f.status, ck.AUTHORITY_STATUS_DOMAIN, bytes([4])*32), observed=stamp(1))
        with self.assertRaises(AuthorityError): view.current_authority(stamp(2))

    def test_live_view_rejects_root_signature_forgery(self):
        f = fixture(); view = LiveAuthorityView(selection=f.auth.selection, budget=f.budget, verifier=fixture_preloaded_verifier(f))
        envelope = signed_rpc(f.status, ck.AUTHORITY_STATUS_DOMAIN, bytes([4])*32); envelope["signature_hex"] = "00"*64
        with self.assertRaises(Exception): view.publish_authenticated(envelope, observed=stamp(1))

    def test_live_envelope_returns_exact_external_signature_without_remint(self):
        f=fixture();view=LiveAuthorityView(selection=f.auth.selection,budget=f.budget,verifier=fixture_preloaded_verifier(f))
        envelope=signed_rpc(f.status,ck.AUTHORITY_STATUS_DOMAIN,bytes([4])*32)
        view.publish_authenticated(envelope,observed=stamp(1))
        self.assertEqual(view.current_envelope(stamp(1)),envelope)
        view.invalidate()
        with self.assertRaises(AuthorityError):view.current_envelope(stamp(1))

    def test_drift_above_one_second_below_two_seconds_is_rejected(self):
        f=fixture(); f.clock.now={**stamp(2), "boottime_ns": stamp(0)["boottime_ns"] + 500_000_000}
        with self.assertRaises(AuthorityError): f.guard.check()

    def test_live_view_nonblocking_read_fails_while_other_thread_holds_lock(self):
        from threading import Thread, Event
        f=fixture(); view=LiveAuthorityView(selection=f.auth.selection,budget=f.budget,verifier=fixture_preloaded_verifier(f))
        view.publish_authenticated(signed_rpc(f.status,ck.AUTHORITY_STATUS_DOMAIN,bytes([4])*32),observed=stamp(1))
        held, release=Event(),Event()
        def holder():
            with view._lock:
                held.set(); release.wait(2)
        thread=Thread(target=holder); thread.start()
        try:
            self.assertTrue(held.wait(1))
            with self.assertRaises(AuthorityError):view.current_envelope(stamp(1))
        finally:
            release.set();thread.join(2)
        self.assertFalse(thread.is_alive())


class PrincipalAuthorityFixtureTests(TestCase):
    """Public synthetic fixture regressions, never operational authority evidence."""

    def test_exactly_one_reference_per_appointed_principal(self):
        f = fixture()
        self.assertEqual([p["principal_id"] for p in f.appointment["principals"]],
                         ["witness", "consumer", "checkpoint"])
        self.assertEqual(len(f.auth.selection.principal_authority_refs), 3)
        self.assertEqual(len(f.auth.selection.principal_authority_refs),
                         len(f.appointment["principals"]))

    def test_reference_content_is_distinct(self):
        import json
        f = fixture()
        refs = [json.loads(raw) for raw in f.auth.selection.principal_authority_refs]
        self.assertEqual(len(refs), 3)
        self.assertEqual(len(set(f.auth.selection.principal_authority_refs)), 3)
        self.assertEqual(len({item["sha256"] for item in refs}), 3)
        self.assertEqual(len({item["object_id"] for item in refs}), 3)
        self.assertTrue(all(item["artifact_kind"] == "PUBLIC_FIXTURE" for item in refs))

    def test_reference_bytes_match_public_principal_content(self):
        import hashlib
        import json
        f = fixture()
        self.assertEqual(len(f.auth.selection.principal_authority_refs), 3)
        for principal, actual_raw in zip(f.appointment["principals"],
                                         f.auth.selection.principal_authority_refs):
            with self.subTest(principal=principal["principal_id"]):
                # Independent JSON and hash oracle, not support.ref or its builder.
                payload = {
                    "fixture_notice": "PUBLIC TEST FIXTURE ONLY; NOT OPERATIONAL AUTHORITY",
                    "principal_id": principal["principal_id"],
                    "role": principal["role"],
                    "component_manifest_sha256": principal["component_manifest_sha256"],
                    "signer_public_sha256": principal["signer_public_sha256"],
                }
                raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
                sha256 = hashlib.sha256(raw).hexdigest()
                expected = {"object_id": sha256, "sha256": sha256, "bytes": len(raw),
                            "artifact_kind": "PUBLIC_FIXTURE"}
                expected_raw = json.dumps(expected, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False, allow_nan=False).encode("utf-8")
                self.assertEqual(actual_raw, expected_raw)

    def test_authenticate_appointment_preserves_fixture_references(self):
        import json
        from cas_forex_operational_contracts import method
        f = fixture()
        interval = f.auth.authenticate_appointment(
            f.appointment, authority_status=f.status, budget=f.budget, now=f.guard.check())
        self.assertEqual(interval["principal_authority_refs"],
                         [json.loads(raw) for raw in f.auth.selection.principal_authority_refs])
        self.assertEqual(interval["appointment_authentication_refs"],
                         [json.loads(raw) for raw in f.auth.selection.appointment_authentication_refs])
        self.assertEqual(interval["binding"], f.binding)
        self.assertEqual(method.validate("AuthenticatedInterval", interval).payload(), interval)

    def test_interval_validation_rejects_zero_one_or_two_references(self):
        from cas_forex_operational_contracts import method
        from cas_forex_operational_contracts.common import ContractError
        f = fixture()
        interval = f.auth.authenticate_appointment(
            f.appointment, authority_status=f.status, budget=f.budget, now=f.guard.check())
        for count in (0, 1, 2):
            with self.subTest(reference_count=count):
                insufficient = {**interval, "principal_authority_refs": interval["principal_authority_refs"][:count]}
                with self.assertRaises(ContractError) as raised:
                    method.validate("AuthenticatedInterval", insufficient)
                self.assertEqual(raised.exception.code, "ARRAY_LENGTH")
                self.assertEqual(raised.exception.field, "principal_authority_refs")

    def test_authentication_rejects_one_or_two_selected_references(self):
        from cas_forex_operational_contracts.common import ContractError
        for count in (1, 2):
            with self.subTest(reference_count=count):
                f = fixture()
                selected = replace(f.auth.selection,
                                   principal_authority_refs=f.auth.selection.principal_authority_refs[:count])
                authentication = MethodAuthenticator(
                    selected, guard=f.guard, verifier=FixtureVerifier(),
                    current_status=lambda: signed_rpc(f.status, ck.AUTHORITY_STATUS_DOMAIN, bytes([4]) * 32),
                    initial_authorization=lambda _: self.fail("initial authorization was unexpectedly requested"))
                with self.assertRaises(ContractError) as raised:
                    authentication.authenticate_appointment(
                        f.appointment, authority_status=f.status, budget=f.budget, now=f.guard.check())
                self.assertEqual(raised.exception.code, "ARRAY_LENGTH")
                self.assertEqual(raised.exception.field, "principal_authority_refs")
