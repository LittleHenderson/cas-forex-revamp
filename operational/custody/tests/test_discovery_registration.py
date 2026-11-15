"""OC-01 public synthetic regression source. Authored, NOT_RUN.

Registry doubles exercise custody binding checks only. They are not signatures,
actual child observations or proof that the pipe mechanism ran.
"""
import copy
import unittest
from cas_forex_operational_contracts import common, protected
from custody_runtime.completion_verifier import CompletionVerifier
from public_fixtures import fixture_selection, stamp


def registration_fixture():
    publishers,_,reference=fixture_selection()
    reference={**reference,"record_kind":"TEST_DISCOVERY_REPORT","purpose":"test-discovery-report"}
    attestation={**reference,"record_kind":"RECORD_ATTESTATION","purpose":"record-attestation",
                 "sha256":"5"*64,"object_id":"5"*64}
    row={"format":"forex.protected-record-registration/2","binding":publishers["binding"],
         "publisher_selection_sha256":common.digest(protected.validate("PublisherRootSelection",publishers).raw),
         "registry_authority_id":publishers["registry_authority_id"],"sequence":1,"previous_entry_sha256":"0"*64,
         "record_ref":reference,"attestation_ref":attestation,"registered_at_utc":stamp(12)["utc"]}
    use={"reference":reference,"registration_sha256":common.digest(protected.validate("ProtectedRegistration",row).raw),
         "required_use":"SOURCE_COMPLETION"}
    return publishers,row,use


class DiscoveryOrderingTests(unittest.TestCase):
    def order(self, values):
        CompletionVerifier._discovery_order(**{k:stamp(v)["utc"] for k,v in
            zip(("spawn","discovery","registered","released","exited"),values,strict=True)})

    def test_spawn_precedes_collection_and_release(self):
        self.order([1,10,12,15,40])

    def test_equal_resolution_does_not_invent_a_distinct_clock_tick(self):
        self.order([1,10,10,10,40])

    def test_collection_after_release_is_rejected(self):
        with self.assertRaises(common.ContractError):self.order([1,16,17,15,40])

    def test_registration_after_release_is_rejected(self):
        with self.assertRaises(common.ContractError):self.order([1,10,16,15,40])

    def test_release_after_exit_is_rejected(self):
        with self.assertRaises(common.ContractError):self.order([1,10,12,41,40])

    def test_collection_before_spawn_is_rejected(self):
        with self.assertRaises(common.ContractError):self.order([11,10,12,15,40])

    def test_registration_before_collection_is_rejected(self):
        with self.assertRaises(common.ContractError):self.order([1,13,12,15,40])


class OriginalDiscoveryRegistrationTests(unittest.TestCase):
    def subject(self, row):
        calls=[]
        class RegistryDouble:
            def read_registration(self, digest, *, selection, now):
                calls.append((digest,copy.deepcopy(selection),copy.deepcopy(now)))
                return copy.deepcopy(row)
        subject=object.__new__(CompletionVerifier)
        subject.registry=RegistryDouble();subject.clock=lambda:stamp(100)
        subject.guard=lambda now:None;subject.deadline=stamp(180)
        return subject,calls

    def test_original_registration_is_read_by_original_hash(self):
        publishers,row,use=registration_fixture();subject,calls=self.subject(row)
        self.assertEqual(subject._discovery_registration(use,publishers=publishers,now=stamp(90)),stamp(12)["utc"])
        self.assertEqual(calls,[(use["registration_sha256"],publishers,stamp(100))])

    def test_missing_authenticated_registry_cannot_pass(self):
        publishers,row,use=registration_fixture();subject,_=self.subject(row);subject.registry=None
        with self.assertRaises(common.DependencyUnavailable):subject._discovery_registration(use,publishers=publishers,now=stamp(90))

    def test_later_reminted_row_cannot_replace_original_registration(self):
        publishers,row,use=registration_fixture();row["registered_at_utc"]=stamp(14)["utc"]
        subject,_=self.subject(row)
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))

    def test_matching_row_hash_does_not_allow_another_record(self):
        publishers,row,use=registration_fixture();row["record_ref"]={**row["record_ref"],"sha256":"7"*64,"object_id":"7"*64}
        use["registration_sha256"]=common.digest(protected.validate("ProtectedRegistration",row).raw)
        subject,_=self.subject(row)
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))

    def test_matching_row_hash_does_not_allow_another_registry_authority(self):
        publishers,row,use=registration_fixture();row["registry_authority_id"]="other-public-registry"
        use["registration_sha256"]=common.digest(protected.validate("ProtectedRegistration",row).raw)
        subject,_=self.subject(row)
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))

    def test_matching_row_hash_does_not_allow_another_selection(self):
        publishers,row,use=registration_fixture();row["publisher_selection_sha256"]="8"*64
        use["registration_sha256"]=common.digest(protected.validate("ProtectedRegistration",row).raw)
        subject,_=self.subject(row)
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))

    def test_framework_report_cannot_substitute_discovery(self):
        publishers,row,use=registration_fixture();use["reference"]={**use["reference"],"record_kind":"TEST_FRAMEWORK_REPORT","purpose":"test-framework-report"}
        subject,calls=self.subject(row)
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))
        self.assertEqual(calls,[])

    def test_expired_guard_prevents_registry_read(self):
        publishers,row,use=registration_fixture();subject,calls=self.subject(row);subject.clock=lambda:stamp(180)
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))
        self.assertEqual(calls,[])

    def test_registry_rejection_is_not_converted_to_success(self):
        publishers,row,use=registration_fixture();subject,_=self.subject(row)
        class RejectingRegistry:
            def read_registration(self,*args,**kwargs):raise common.ContractError("PUBLIC_SIGNATURE_REJECTION")
        subject.registry=RejectingRegistry()
        with self.assertRaises(common.ContractError):subject._discovery_registration(use,publishers=publishers,now=stamp(90))
