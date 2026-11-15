"""Future source publisher boundary tests with public doubles only. NOT_RUN."""
import unittest
from cas_forex_operational_contracts import common, protected as pr
from custody_runtime.completion_hosts import SourcePublisherHost
from public_fixtures import fixture_selection, stamp


def host_fixture(*, role='CUSTODY', principal='public-issuer'):
    selected,_,_=fixture_selection();selected['publishers'][0]['role']=role
    class Authority:
        local_principal_id=principal
        deadline=stamp(180)
        def current(self,selection,now):return now
        def check_grant(self,reference,selection,now,required_use=None):
            return {},selection['publishers'][0],{'payload_schema_sha256':'2'*64},now
        def validate_payload(self,raw,grant):return common.decode_canonical(raw)
        def attest(self,*args):return stamp(100)
    class Signer:
        calls=0
        def sign(self,**kwargs):self.calls+=1;raise RuntimeError('public unit signing failure')
    signer=Signer()
    host=SourcePublisherHost(authority=Authority(),files=None,registry=None,resolver=None,
        publishers=selected,publisher_id='public-issuer',signer=signer,
        routes=[{'record_kind':'SOURCE_TEST_REPORT','purpose':'original-source-test-report',
                 'format':'public.unit.report/1','root_id':'public-root','schema_sha256':'2'*64}],
        expires_at_utc=stamp(160)['utc'],clock=lambda:stamp(100))
    raw=common.canonical_bytes({'format':'public.unit.report/1','binding':selected['binding']})
    request={'operation':'PUBLISH','publisher_selection_sha256':common.digest(pr.validate('PublisherRootSelection',selected).raw),
        'payload':{'record_hex':raw.hex(),'record_kind':'SOURCE_TEST_REPORT','purpose':'original-source-test-report'}}
    return host,request,signer


class SourcePublicationHostTests(unittest.TestCase):
    def test_actual_local_principal_must_match_selected_publisher(self):
        with self.assertRaises(common.ContractError):host_fixture(principal='not-the-publisher')

    def test_observer_cannot_publish_custody_source_report(self):
        with self.assertRaises(common.ContractError):host_fixture(role='COMPLETION_OBSERVER')

    def test_source_publisher_cannot_accept_registry_operation(self):
        host,request,signer=host_fixture();request['operation']='REGISTER_EXACT_RECORD'
        with self.assertRaises(common.ContractError):host(request)
        self.assertEqual(signer.calls,0)

    def test_payload_cannot_select_additional_fields(self):
        host,request,signer=host_fixture();request['payload']['retry']=True
        with self.assertRaises(common.ContractError):host(request)
        self.assertEqual(signer.calls,0)

    def test_signed_selection_hash_cannot_be_substituted(self):
        host,request,signer=host_fixture();request['publisher_selection_sha256']='9'*64
        with self.assertRaises(common.ContractError):host(request)
        self.assertEqual(signer.calls,0)

    def test_uncertain_signing_attempt_latches_without_retry(self):
        host,request,signer=host_fixture()
        with self.assertRaises(RuntimeError):host(request)
        with self.assertRaises(common.ContractError):host(request)
        self.assertEqual(signer.calls,1)
        self.assertTrue(host._failed)
