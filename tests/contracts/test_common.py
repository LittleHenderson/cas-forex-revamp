"""Authored boundary regressions. NOT_RUN during source preparation."""
import unittest
from cas_forex_operational_contracts.common import (
    ContractError, canonical_bytes, decode_canonical, decode_json, utc, safe_path)
from cas_forex_operational_contracts import method

class CommonBoundaryTests(unittest.TestCase):
    def test_duplicate_key_rejected(self):
        with self.assertRaises(ContractError): decode_json(b'{"x":1,"x":2}')
    def test_float_rejected(self):
        with self.assertRaises(ContractError): decode_json(b'{"x":1.0}')
    def test_nonfinite_rejected(self):
        for raw in (b'NaN',b'Infinity',b'-Infinity'):
            with self.subTest(raw=raw),self.assertRaises(ContractError): decode_json(raw)
    def test_bom_rejected(self):
        with self.assertRaises(ContractError): decode_json(b'\xef\xbb\xbf{}')
    def test_noncanonical_spacing_rejected(self):
        with self.assertRaises(ContractError): decode_canonical(b'{"x": 1}')
    def test_signed_integer_overflow_rejected(self):
        with self.assertRaises(ContractError): canonical_bytes(2**63)
    def test_surrogate_rejected(self):
        with self.assertRaises(ContractError): canonical_bytes("\ud800")
    def test_depth_limit_rejected(self):
        x=None
        for _ in range(40): x=[x]
        with self.assertRaises(ContractError): canonical_bytes(x)
    def test_byte_limit_rejected(self):
        with self.assertRaises(ContractError): canonical_bytes("12345",limit=4)
    def test_utc_requires_six_digits(self):
        for text in ("2030-01-01T00:00:00Z","2030-01-01T00:00:00.00000Z","2030-01-01T00:00:00.000000+00:00"):
            with self.subTest(text=text),self.assertRaises(ContractError): utc(text)
    def test_impossible_utc_rejected(self):
        with self.assertRaises(ContractError): utc("2030-02-30T00:00:00.000000Z")
    def test_parent_path_rejected(self):
        with self.assertRaises(ContractError): safe_path("/safe/../escape",absolute=True)
    def test_repeated_path_separator_rejected(self):
        with self.assertRaises(ContractError): safe_path("tests//suite.py",absolute=False)
    def test_boolean_is_not_integer(self):
        with self.assertRaises(ContractError):
            method.validate("Stamp",{"utc":"2030-01-01T00:00:00.000000Z","boottime_ns":True})
    def test_structural_snapshot_immutable(self):
        value={"utc":"2030-01-01T00:00:00.000000Z","boottime_ns":1}
        record=method.validate("Stamp",value)
        value["boottime_ns"]=2
        decoded=record.payload(); decoded["boottime_ns"]=3
        self.assertEqual(record.payload()["boottime_ns"],1)
    def test_unknown_fields_rejected(self):
        with self.assertRaises(ContractError):
            method.validate("Stamp",{"utc":"2030-01-01T00:00:00.000000Z","boottime_ns":1,"verified":True})

