"""Authored regression source. Tests have NOT_RUN status."""

import copy
import unittest

from policy_inheritance.contract import Contract, canonical_bytes, decode_canonical, object_ref
from policy_inheritance.errors import ContractViolation, UnsupportedAuthority
from policy_inheritance.operational import OperationalAdapters
from support import Fixture, h, stamp


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_exact_accepted_pin_required(self):
        with self.assertRaises(ContractViolation): Contract(b"{}")

    def test_roundtrip_exact_scope(self):
        raw = canonical_bytes(self.f.scope)
        self.assertEqual(self.f.contract.decode("Scope", raw), self.f.scope)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ContractViolation): decode_canonical(b'{"x":1,"x":1}')

    def test_whitespace_and_bom_rejected(self):
        for raw in [b'{ "x":1}', b'\xef\xbb\xbf{}', b'{}\n']:
            with self.subTest(raw=raw), self.assertRaises(ContractViolation): decode_canonical(raw)

    def test_floats_nonfinite_and_negative_zero_rejected(self):
        for raw in [b'1.0', b'NaN', b'Infinity', b'-Infinity', b'-0']:
            with self.subTest(raw=raw), self.assertRaises(ContractViolation): decode_canonical(raw)

    def test_invalid_unicode_and_surrogates_rejected(self):
        for raw in [b'"\xff"', b'"\\ud800"']:
            with self.subTest(raw=raw), self.assertRaises(ContractViolation): decode_canonical(raw)

    def test_unknown_missing_and_extra_fields_rejected(self):
        for mutation in [lambda x:x.pop("epoch"), lambda x:x.update(extra=True), lambda x:x.update(method_id="ALIAS")]:
            value=copy.deepcopy(self.f.scope);mutation(value)
            with self.assertRaises(ContractViolation):self.f.contract.validate("Scope",value)

    def test_bool_is_never_an_integer(self):
        value=copy.deepcopy(self.f.scope);value["epoch"]=True
        with self.assertRaises(ContractViolation):self.f.contract.validate("Scope",value)
        with self.assertRaises(ContractViolation):self.f.contract.validate_value("literal-integer:0",False)

    def test_integer_bounds_and_depth(self):
        for raw in [str(2**63).encode(),b"1"*100]:
            with self.assertRaises(ContractViolation):decode_canonical(raw)
        value=[]
        for _ in range(34):value=[value]
        with self.assertRaises(ContractViolation):canonical_bytes(value)

    def test_actual_utc_calendar_and_exact_spelling(self):
        for value in ["2026-02-30T00:00:00.000000Z","2026-10-11T00:00:00Z","2026-10-11T00:00:00.000000+00:00"]:
            with self.subTest(value=value),self.assertRaises(ContractViolation):self.f.contract.validate_value("Utc",value)

    def test_object_hash_length_role_and_id(self):
        raw=b"public";ref=object_ref(raw,"PUBLIC_FIXTURE")
        self.f.contract.object_bytes(ref,raw,expected_kind="PUBLIC_FIXTURE")
        for mutation in [lambda r:r.update(bytes=99),lambda r:r.update(object_id=h("wrong")),lambda r:r.update(artifact_kind="IPC_SEND")]:
            value=copy.deepcopy(ref);mutation(value)
            with self.assertRaises(ContractViolation):self.f.contract.object_bytes(value,raw,expected_kind="PUBLIC_FIXTURE")

    def test_unknown_type_expression_rejected(self):
        with self.assertRaises(ContractViolation):self.f.contract.validate_value("Unregistered",{})

    def test_empty_nullable_and_array_cannot_hide_unknown_types(self):
        for expression,value in [("Nullable<Unregistered>",None),("array<Unregistered>[0,1]",[]),("literal-bool:maybe",False)]:
            with self.subTest(expression=expression),self.assertRaises(ContractViolation):self.f.contract.validate_value(expression,value)

    def test_spec_property_is_not_mutable_state(self):
        value=self.f.contract.spec;value["enums"]["EventKind"].append("BROKEN")
        self.assertNotIn("BROKEN",self.f.contract.spec["enums"]["EventKind"])

    def test_all_operational_adapters_reject(self):
        ports=OperationalAdapters()
        for name in ["authenticate_appointment","verify_ed25519","capture_actual_role","decode_actual_evidence",
                     "reserve_original_setup","checkpoint_compare_and_append","checkpoint_read_current","retain_durably",
                     "issue_setup_budget","expose_output","release_consume","start_watchdog"]:
            with self.subTest(operation=name),self.assertRaises(UnsupportedAuthority):getattr(ports,name)({"verified":True})

    def test_analysis_cannot_be_converted_to_authority(self):
        model=self.f.new_model()
        with self.assertRaises(UnsupportedAuthority):model.operational_output()
        with self.assertRaises(UnsupportedAuthority):model.release_consume()
        self.assertFalse(model.inspect().runtime_authority)
        self.assertFalse(model.inspect().release_enabled)
