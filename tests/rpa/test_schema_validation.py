"""Negative controls for the pinned schema subset. Runtime status: NOT_RUN."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.rpa.schema_validation import PinnedDecisionReadValidator

ROOT = Path(__file__).resolve().parents[2]


def validator(schema):
    raw = json.dumps(schema, ensure_ascii=False).encode("utf-8")
    return PinnedDecisionReadValidator(raw, expected_sha256=sha256(raw).hexdigest())


def root_schema(**keywords):
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:cas-forex:decision-read:0.1", **keywords}


class PinnedSchemaTests(unittest.TestCase):
    def test_published_incomplete_fixture_shape_only(self):
        raw = (ROOT / "docs/contracts/decision-read.schema.json").read_bytes()
        # Test fixture pin only; production pin must come from trusted build.
        check = PinnedDecisionReadValidator(raw, expected_sha256=sha256(raw).hexdigest())
        data = json.loads((ROOT / "docs/contracts/initial-decision-read.json").read_bytes())
        before = deepcopy(data)
        self.assertTrue(check(data))
        self.assertEqual(before, data)
        self.assertFalse(data["coverage"]["complete"])

    def test_hash_mismatch_before_schema_parse(self):
        with self.assertRaises(ContractError):
            PinnedDecisionReadValidator(b"not json", expected_sha256="0" * 64)

    def test_unknown_keyword_even_unused_definition(self):
        for word in ("not", "oneOf", "if", "unevaluatedProperties", "dependentSchemas"):
            with self.subTest(word=word), self.assertRaises(ContractError):
                validator(root_schema(**{"$defs": {"unused": {word: {}}}}))

    def test_local_reference_resolution_and_siblings(self):
        check = validator(root_schema(**{"$defs": {"value": {"type": "integer"}},
                                         "$ref": "#/$defs/value", "maximum": 2}))
        self.assertTrue(check(2))
        for bad in (True, 3, "2", 2.0):
            with self.subTest(value=bad), self.assertRaises(ContractError):
                check(bad)

    def test_remote_missing_and_recursive_refs(self):
        for ref in ("https://example.invalid/schema", "#/$defs/missing", "#/$defs/loop"):
            with self.subTest(ref=ref), self.assertRaises(ContractError):
                validator(root_schema(**{"$defs": {"loop": {"$ref": ref}}}))

    def test_required_extra_props_and_array_item_bounds(self):
        check = validator(root_schema(type="object", required=["rows"], additionalProperties=False,
            properties={"rows": {"type": "array", "maxItems": 2, "items": {"type": "integer", "minimum": 0}}}))
        for bad in ({}, {"rows": [], "extra": 1}, {"rows": [1, 2, 3]}, {"rows": [-1]}, {"rows": [True]}):
            with self.subTest(value=bad), self.assertRaises(ContractError):
                check(bad)

    def test_anyof_null_const_and_bool_distinction(self):
        check = validator(root_schema(anyOf=[{"type": "null"}, {"type": "integer", "enum": [1]}]))
        self.assertTrue(check(None))
        self.assertTrue(check(1))
        with self.assertRaises(ContractError):
            check(True)
        with self.assertRaises(ContractError):
            validator(root_schema(const=True))(1)

    def test_timestamp_calendar_and_exact_utc(self):
        check = validator(root_schema(type="string", format="date-time", pattern="Z$"))
        self.assertTrue(check("2026-10-10T21:00:00.123456789Z"))
        for bad in ("2026-02-30T00:00:00Z", "2026-10-10T21:00:00+00:00", "2026-10-10 21:00:00Z", "2026-10-10T21:00:00Z\n"):
            with self.subTest(value=bad), self.assertRaises(ContractError):
                check(bad)

    def test_utf8_reason_bound_is_not_character_count_only(self):
        check = validator(root_schema(type="string", maxLength=1024))
        with self.assertRaises(ContractError):
            check("é" * 513)

    def test_unreviewed_regex_and_format_rejected(self):
        for node in ({"pattern": "(a+)+"}, {"format": "uri"}, {"type": "number"}):
            with self.subTest(node=node), self.assertRaises(ContractError):
                validator(root_schema(**node))

    def test_duplicate_schema_keys_rejected(self):
        raw = b'{"type":"integer","type":"boolean"}'
        with self.assertRaises(ContractError):
            PinnedDecisionReadValidator(raw, expected_sha256=sha256(raw).hexdigest())

    def test_invalid_utf8_surrogates_nan_and_cycles_fail_closed(self):
        check = validator(root_schema())
        cyclic = []
        cyclic.append(cyclic)
        for value in (float("nan"), "\ud800", cyclic):
            with self.assertRaises(ContractError):
                check(value)
