"""Pure framing/domain test source. Does not create a socket or authenticate a key."""
import json
from pathlib import Path
import unittest
from cas_forex_operational_contracts import checkpoint, protected
from cas_forex_operational_contracts.common import ContractError, canonical_bytes

class RpcDomainTests(unittest.TestCase):
    def envelope(self):
        return {"body_utf8":"{}","signer_sha256":"1"*64,"algorithm":"Ed25519","signature_hex":"2"*128}
    def test_frame_round_trip(self):
        value=self.envelope()
        self.assertEqual(checkpoint.decode_frame(checkpoint.encode_frame(value)).payload(),value)
    def test_frame_extra_bytes_rejected(self):
        with self.assertRaises(ContractError): checkpoint.decode_frame(checkpoint.encode_frame(self.envelope())+b"x")
    def test_frame_truncation_rejected(self):
        with self.assertRaises(ContractError): checkpoint.decode_frame(checkpoint.encode_frame(self.envelope())[:-1])
    def test_frame_wrong_length_rejected(self):
        frame=checkpoint.encode_frame(self.envelope())
        with self.assertRaises(ContractError): checkpoint.decode_frame(b"\0\0\0\1"+frame[4:])
    def test_inner_noncanonical_json_rejected(self):
        value=self.envelope(); value["body_utf8"]='{ "x":1}'
        with self.assertRaises(ContractError): checkpoint.encode_frame(value)
    def test_domains_distinct_and_lf_terminated(self):
        values=[checkpoint.REQUEST_DOMAIN,checkpoint.RESPONSE_DOMAIN,protected.RECORD_DOMAIN,protected.REGISTRATION_DOMAIN]
        self.assertEqual(len(values),len(set(values)))
        self.assertTrue(all(v.endswith(b"\n") and v.count(b"\n")==1 for v in values))
    def test_retired_registry_domain_not_exposed(self):
        self.assertEqual(protected.REGISTRATION_DOMAIN,b"CAS_FOREX_PROTECTED_REGISTRATION_V2\n")
        self.assertFalse(hasattr(checkpoint,"REGISTRY_ENTRY_DOMAIN"))
    def test_request_signing_prefix_fixed(self):
        root=Path(__file__).resolve().parents[2]
        value=json.loads((root/"shared-interface"/"accepted-contracts"/"examples"/"role-release-evidence.json").read_text(encoding="utf-8"))["controller_fresh_read_request"]
        self.assertEqual(checkpoint.request_signing_bytes(value),checkpoint.REQUEST_DOMAIN+canonical_bytes(value,limit=4194304))

