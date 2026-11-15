"""Future actual-signature tests with an explicitly public unit key. NOT_RUN.

These fixture signatures appoint no runtime role and are never deployment keys.
"""
import copy
import unittest
from cas_forex_operational_contracts import common, protected as pr
from cas_forex_authority.authentication import Ed25519Verifier, AuthorityError
from custody_runtime.source_completion import validate_registry_chain, selected_schema_routes
from public_fixtures import fixture_selection, stamp


def signed_fixture():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public=key.public_key().public_bytes_raw();pin=common.digest(public)
    selected,_,ref=fixture_selection();selected['registry_signer_public_sha256']=pin
    selected['publishers'][0]['role']='CUSTODY'
    selected['publishers'][0]['grants']=[{'root_id':'public-root','record_kind':'SOURCE_TEST_REPORT',
        'purpose':'original-source-test-report','permitted_use':'SOURCE_COMPLETION','payload_schema_sha256':'2'*64}]
    selected_hash=common.digest(pr.validate('PublisherRootSelection',selected).raw)
    ref={**ref,'record_kind':'SOURCE_TEST_REPORT','purpose':'original-source-test-report','publisher_selection_sha256':selected_hash}
    att={**ref,'record_kind':'RECORD_ATTESTATION','purpose':'record-attestation','object_id':'5'*64,'sha256':'5'*64}
    row={'format':'forex.protected-record-registration/2','binding':selected['binding'],'publisher_selection_sha256':selected_hash,
         'registry_authority_id':selected['registry_authority_id'],'sequence':1,'previous_entry_sha256':'0'*64,
         'record_ref':ref,'attestation_ref':att,'registered_at_utc':stamp(10)['utc']}
    def sign(value):return {'registration':value,'algorithm':'Ed25519','signer_sha256':pin,
                            'signature_hex':key.sign(pr.registration_signing_bytes(value)).hex()}
    class ActualUnitSignatureVerifier:
        def signature_check(self,*,signer_pin,message,signature):
            common.require(signer_pin==pin,'UNIT_KEY_PIN')
            Ed25519Verifier().verify(public_key=public,message=message,signature=signature)
    return selected,row,sign,ActualUnitSignatureVerifier()


class SourceRegistryAuthenticationTests(unittest.TestCase):
    def check(self, selected, chain, authority, **kwargs):
        return validate_registry_chain({'registry_chain':chain},publishers=selected,authority=authority,
            now=stamp(100),maximum_entries=256,**kwargs)

    def test_original_signed_row_is_verified(self):
        selected,row,sign,authority=signed_fixture()
        digest=common.digest(pr.validate('ProtectedRegistration',row).raw)
        self.assertEqual(self.check(selected,[sign(row)],authority,expected_hash=digest,expected_reference=row['record_ref']),row)

    def test_changed_row_with_old_signature_rejected(self):
        selected,row,sign,authority=signed_fixture();envelope=sign(row);envelope['registration']=copy.deepcopy(row)
        envelope['registration']['registered_at_utc']=stamp(11)['utc']
        with self.assertRaises(AuthorityError) as rejected:self.check(selected,[envelope],authority)
        self.assertEqual(str(rejected.exception),'SIGNATURE_REJECTED')

    def test_wrong_selected_registry_key_rejected(self):
        selected,row,sign,authority=signed_fixture();envelope=sign(row);envelope['signer_sha256']='9'*64
        with self.assertRaises(common.ContractError):self.check(selected,[envelope],authority)

    def test_signed_wrong_requested_hash_rejected(self):
        selected,row,sign,authority=signed_fixture()
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority,expected_hash='9'*64)

    def test_signed_other_record_cannot_answer_request(self):
        selected,row,sign,authority=signed_fixture();other={**row['record_ref'],'sha256':'9'*64,'object_id':'9'*64}
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority,expected_reference=other)

    def test_signed_chain_without_parent_cannot_pass(self):
        selected,row,sign,authority=signed_fixture();row['sequence']=2;row['previous_entry_sha256']='8'*64
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority)

    def test_signed_wrong_registry_authority_rejected(self):
        selected,row,sign,authority=signed_fixture();row['registry_authority_id']='other-registry'
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority)

    def test_signed_future_registration_rejected(self):
        selected,row,sign,authority=signed_fixture();row['registered_at_utc']=stamp(101)['utc']
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority)

    def test_private_use_is_not_relabelled_as_source_completion(self):
        selected,row,sign,authority=signed_fixture();selected['publishers'][0]['grants'][0]['permitted_use']='PRIVATE_RELEASE'
        # Selection changes are independently signed in real execution; this
        # unit fixture updates only content pins so the use guard is exercised.
        pin=common.digest(pr.validate('PublisherRootSelection',selected).raw)
        row['publisher_selection_sha256']=pin;row['record_ref']['publisher_selection_sha256']=pin;row['attestation_ref']['publisher_selection_sha256']=pin
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority)

    def test_raw_caller_built_registration_is_not_signature_envelope(self):
        selected,row,sign,authority=signed_fixture()
        with self.assertRaises(common.ContractError):self.check(selected,[row],authority)

    def test_unselected_schema_module_name_is_rejected(self):
        with self.assertRaises(common.ContractError):selected_schema_routes([{'schema_sha256':'1'*64,'namespace':'arbitrary.module',
            'type_name':'RunCode','maximum_stream_bytes':None}])

    def test_source_clock_route_uses_fixed_adapter(self):
        routes=selected_schema_routes([{'schema_sha256':'1'*64,'namespace':'clock','type_name':'SourceTestClock','maximum_stream_bytes':None}])
        self.assertEqual(type(routes['1'*64]).__name__,'SourceTestClockSchema')

    @staticmethod
    def successor(row):
        second=copy.deepcopy(row)
        second['sequence']=2
        second['previous_entry_sha256']=common.digest(pr.validate('ProtectedRegistration',row).raw)
        second['registered_at_utc']=stamp(11)['utc']
        second['record_ref']['sha256']=second['record_ref']['object_id']='7'*64
        second['attestation_ref']['sha256']=second['attestation_ref']['object_id']='8'*64
        return second

    def test_complete_original_signed_prefix_accepted(self):
        selected,row,sign,authority=signed_fixture();second=self.successor(row)
        self.assertEqual(self.check(selected,[sign(row),sign(second)],authority,
            expected_hash=common.digest(pr.validate('ProtectedRegistration',second).raw)),second)

    def test_valid_signatures_do_not_hide_broken_prefix_link(self):
        selected,row,sign,authority=signed_fixture();second=self.successor(row);second['previous_entry_sha256']='9'*64
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row),sign(second)],authority)

    def test_valid_signatures_do_not_hide_registration_time_regression(self):
        selected,row,sign,authority=signed_fixture();second=self.successor(row);second['registered_at_utc']=stamp(9)['utc']
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row),sign(second)],authority)

    def test_original_attestation_reference_cannot_be_substituted(self):
        selected,row,sign,authority=signed_fixture();other={**row['attestation_ref'],'sha256':'9'*64,'object_id':'9'*64}
        with self.assertRaises(common.ContractError):self.check(selected,[sign(row)],authority,expected_attestation=other)
