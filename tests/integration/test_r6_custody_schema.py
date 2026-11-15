"""Published structural schemas and invented data only. AUTHORED/NOT_RUN."""
from copy import deepcopy
from pathlib import Path
import unittest
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.custody_schema import CustodySchemas,load_json
from cas_forex_revamp.composition.custody_adapter import validate_context,validate_quote
from r6_development_fixture import context


class CustodySchemaTests(unittest.TestCase):
    def setUp(self):
        self.v=CustodySchemas(Path(__file__).resolve().parents[2]/'docs/contracts/custody-interface-02')

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ContractError):load_json(b'{"a":1,"a":2}')

    def test_float_and_nonfinite_rejected(self):
        for raw in (b'{"a":1.0}',b'{"a":NaN}',b'{"a":Infinity}'):
            with self.assertRaises(ContractError):load_json(raw)

    def test_bool_does_not_satisfy_integer(self):
        with self.assertRaises(ContractError):self.v._validate({'type':'integer'},True,0)

    def test_unknown_schema_keyword_blocks(self):
        with self.assertRaises(ContractError):self.v._inspect({'type':'string','format':'invented'},())

    def test_unknown_remote_ref_blocks(self):
        with self.assertRaises(ContractError):self.v._resolve('https://example.invalid/schema')

    def test_real_published_context_reference_resolves(self):
        self.v._validate({'$ref':'urn:forex:custody-interface:common#/$defs/context'},context(),0)

    def test_explicit_unavailable_prestate_is_preserved(self):
        self.v._validate({'anyOf':[{'type':'null'},{'$ref':'urn:forex:custody-interface:common#/$defs/expected_state'}]},None,0)

    def test_extra_context_property_rejected(self):
        value=context();value['answer']='buy'
        with self.assertRaises(ContractError):self.v._validate({'$ref':'urn:forex:custody-interface:common#/$defs/context'},value,0)

    def test_reversed_quote_and_off_tick_rejected(self):
        for value in ({'bid':'2','ask':'1'},{'bid':'1.00001','ask':'1.0002'}):
            with self.assertRaises(ContractError):validate_quote(value)

    def test_trigger_requires_public_typed_facts(self):
        with self.assertRaises(ContractError):validate_context(context(protection_due=True))
