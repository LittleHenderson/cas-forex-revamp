"""Public synthetic regression source. Tests are authored, NOT_RUN."""
import copy
import os
import tempfile
import unittest
from cas_forex_operational_contracts import common, protected
from custody_runtime.selection_provider import fresh, call_none
from custody_runtime.release_issuer import IssuanceJournal
from public_fixtures import fixture_selection, stamp, journal_row


class SelectionTests(unittest.TestCase):
    def test_selected_exact_grant_is_resolved(self):
        selection,authority,reference=fixture_selection()
        self.assertEqual(authority.check_grant(reference,selection,stamp(90),required_use="PRIVATE_RELEASE")[1]["publisher_id"],"public-issuer")

    def test_other_root_rejected(self):
        selection,authority,reference=fixture_selection(); reference["root_id"]="not-selected"
        with self.assertRaises(common.ContractError): authority.check_grant(reference,selection,stamp(90))

    def test_selected_smaller_object_limit_is_enforced(self):
        selection,authority,reference=fixture_selection();selection["roots"][0]["maximum_object_bytes"]=1
        authority.raw=common.canonical_bytes(selection);authority.pin=common.digest(authority.raw)
        reference["publisher_selection_sha256"]=authority.pin;reference["bytes"]=2
        with self.assertRaises(common.ContractError):authority.check_grant(reference,selection,stamp(90))

    def test_use_relabel_rejected(self):
        selection,authority,reference=fixture_selection()
        with self.assertRaises(common.ContractError): authority.check_grant(reference,selection,stamp(90),required_use="FINAL_AGGREGATE")

    def test_selection_payload_cannot_appoint_itself(self):
        selection,authority,reference=fixture_selection(); selection["authorizer_id"]="replacement"
        with self.assertRaises(common.ContractError): authority.current(selection,stamp(90))

    def test_publisher_expiry_is_rechecked(self):
        selection,authority,reference=fixture_selection(); authority.clock=lambda:stamp(175)
        with self.assertRaises(common.ContractError): authority.check_grant(reference,selection,stamp(90))

    def test_missing_schema_cannot_pass(self):
        _,authority,_=fixture_selection()
        with self.assertRaises(common.DependencyUnavailable): authority.validate_payload(b"{}",{"payload_schema_sha256":"9"*64})

    def test_public_example_has_no_signature_authority(self):
        selection,authority,_=fixture_selection()
        def reject(**kwargs): raise common.ContractError("FAKE_SIGNATURE")
        authority.verifier.verify=reject
        with self.assertRaises(common.ContractError): authority.current(selection,stamp(90))

    def test_boolean_callback_is_not_success(self):
        with self.assertRaises(common.ContractError): call_none(lambda:True)

    def test_callback_failure_does_not_expose_detail(self):
        def reject(): raise ValueError("synthetic-private-detail")
        with self.assertRaises(common.DependencyUnavailable) as caught: call_none(reject)
        self.assertNotIn("synthetic-private-detail",str(caught.exception))

    def test_expiry_during_guard_rejected(self):
        times=iter([stamp(179),stamp(180)])
        with self.assertRaises(common.ContractError): fresh(lambda:next(times),lambda now:None,stamp(170),stamp(180))

    def test_boottime_regression_rejected(self):
        bad={**stamp(100),"boottime_ns":1}
        with self.assertRaises(common.ContractError): fresh(lambda:bad,lambda now:None,stamp(90),stamp(180))

    def test_clock_regression_after_guard_rejected(self):
        times=iter([stamp(100),stamp(99)])
        with self.assertRaises(common.ContractError): fresh(lambda:next(times),lambda now:None,stamp(90),stamp(180))


class JournalFramingTests(unittest.TestCase):
    def rows(self, raw):
        row=journal_row()
        class FakeAuthority:
            def signature_check(self,**kwargs): return None
            def current(self,*args): return stamp(100)
        publishers={"binding":row["receipt"]["binding"],"publishers":[{"publisher_id":row["receipt"]["issuer_id"],
                    "role":"RELEASE_ISSUER","signer_public_sha256":row["envelope"]["signer_sha256"]}]}
        journal=IssuanceJournal(files=None,authority=FakeAuthority(),root_id="unused")
        # A future unit-test temporary file only, never an actual protected root.
        with tempfile.TemporaryFile() as stream:
            stream.write(raw);stream.flush()
            return journal.rows(stream.fileno(),publishers,stamp(100))

    def test_original_signed_row_preserved_exactly(self):
        row=journal_row()
        self.assertEqual(self.rows(common.canonical_bytes(row)+b"\n"),[row])

    def test_incomplete_tail_is_not_repaired(self):
        with self.assertRaises(common.ContractError): self.rows(common.canonical_bytes(journal_row()))

    def test_duplicate_release_not_reminted(self):
        raw=common.canonical_bytes(journal_row())+b"\n"
        with self.assertRaises(common.ContractError): self.rows(raw+raw)

    def test_changed_receipt_does_not_match_original_envelope(self):
        row=journal_row(); row["receipt"]["release_id"]="changed"
        with self.assertRaises(common.ContractError): self.rows(common.canonical_bytes(row)+b"\n")

    def test_journal_does_not_accept_added_status_flag(self):
        row=journal_row(); row["verified"]=True
        with self.assertRaises(common.ContractError): self.rows(common.canonical_bytes(row)+b"\n")

    def test_unsigned_empty_journal_does_not_create_receipt(self):
        self.assertEqual(self.rows(b""),[])
