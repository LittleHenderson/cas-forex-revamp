"""Pinned, closed JSON-Schema subset for the steward's decision-read envelope.

No schema fetching, dependencies, default acceptance, or source-authenticity claim.
All keywords are reviewed at construction, including unreachable definitions.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import re

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.contracts.primitives import digest


_METADATA = {"$schema", "$id", "title", "description", "$comment"}
_SEMANTIC = {"$defs", "$ref", "type", "enum", "const", "required", "properties",
             "additionalProperties", "items", "maxItems", "minItems", "uniqueItems",
             "pattern", "maxLength", "minLength", "minimum", "maximum", "anyOf", "format"}
_TYPES = {"object": dict, "array": list, "string": str, "integer": int,
          "boolean": bool, "null": type(None)}
_PATTERNS = {r"Z$", r"^-?(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,12})?$",
             r"^[0-9a-f]{64}$", r"^[A-Z]{3}$", r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$"}
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate schema key")
        result[key] = value
    return result


def _nonfinite(value):
    raise ContractError("nonfinite JSON value")


def _json_identity(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _json_tree(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if depth > 64 or counter[0] > 100000:
        raise ContractError("JSON structure exceeds inspection limits")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError("JSON keys must be strings")
            _json_tree(item, depth + 1, counter)
    elif type(value) is list:
        for item in value:
            _json_tree(item, depth + 1, counter)
    elif type(value) not in (str, int, bool, type(None)):
        raise ContractError("decision-read requires exact JSON types; decimals are strings")


class PinnedDecisionReadValidator:
    """Callable for read_binding.schema_validator, with an external raw-byte pin.

    expected_sha256 must come from the selected trusted build, not the envelope.
    Enforces UTC Z format and UTF-8 text ceilings in addition to schema lengths.
    This deliberately accepts less than general JSON Schema 2020-12. A new
    keyword, regex, format, or recursive schema needs a source review, not fallback.
    """

    def __init__(self, schema_bytes: bytes, *, expected_sha256: str):
        digest(expected_sha256, "expected_schema_sha256")
        if type(schema_bytes) is not bytes or not 0 < len(schema_bytes) <= 1048576:
            raise ContractError("schema must be bounded raw bytes")
        if sha256(schema_bytes).hexdigest() != expected_sha256:
            raise ContractError("raw schema bytes differ from the external pin")
        try:
            schema = json.loads(schema_bytes.decode("utf-8"), object_pairs_hook=_pairs,
                                parse_constant=_nonfinite)
            _json_tree(schema)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ContractError("invalid schema JSON") from exc
        if type(schema) is not dict or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("unsupported schema dialect")
        if schema.get("$id") != "urn:cas-forex:decision-read:0.1":
            raise ContractError("wrong decision-read schema identity")
        self._schema = schema
        self._review_work = 0
        self.schema_sha256 = expected_sha256
        self._review(schema, (), 0)

    def _resolve(self, reference):
        if type(reference) is not str or not re.fullmatch(r"#/[\$]defs/[A-Za-z][A-Za-z0-9_]*", reference):
            raise ContractError("only direct local definition references are supported")
        name = reference.split("/")[-1]
        defs = self._schema.get("$defs", {})
        if name not in defs:
            raise ContractError("unresolved local schema reference")
        return defs[name]

    def _review(self, schema, refs, depth):
        self._review_work += 1
        if self._review_work > 100000:
            raise ContractError("schema review exceeds work bound")
        if depth > 64 or type(schema) is not dict:
            raise ContractError("unsupported schema structure")
        if set(schema) - _METADATA - _SEMANTIC:
            raise ContractError("unsupported semantic schema keyword")
        for key in _METADATA & schema.keys():
            if type(schema[key]) is not str:
                raise ContractError("schema metadata must be text")
        if "$schema" in schema and schema["$schema"] != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("unsupported nested dialect")
        if "$id" in schema and schema is not self._schema:
            raise ContractError("nested reference bases are unsupported")
        if "$ref" in schema:
            ref = schema["$ref"]
            target = self._resolve(ref)
            if ref in refs:
                raise ContractError("recursive schema references are unsupported")
            self._review(target, refs + (ref,), depth + 1)
        if "type" in schema and (type(schema["type"]) is not str or schema["type"] not in _TYPES):
            raise ContractError("unsupported schema type")
        for key in ("$defs", "properties"):
            if key in schema:
                if type(schema[key]) is not dict:
                    raise ContractError("schema map required")
                for child in schema[key].values():
                    self._review(child, refs, depth + 1)
        if "required" in schema:
            required = schema["required"]
            if type(required) is not list or any(type(x) is not str for x in required) or len(set(required)) != len(required):
                raise ContractError("invalid required-property list")
        if "additionalProperties" in schema and type(schema["additionalProperties"]) is not bool:
            raise ContractError("only boolean additionalProperties supported")
        if "items" in schema:
            self._review(schema["items"], refs, depth + 1)
        if "anyOf" in schema:
            if type(schema["anyOf"]) is not list or not 1 <= len(schema["anyOf"]) <= 16:
                raise ContractError("bounded nonempty anyOf required")
            for branch in schema["anyOf"]:
                self._review(branch, refs, depth + 1)
        for key in ("minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum"):
            if key in schema and (type(schema[key]) is not int or (key not in ("minimum", "maximum") and schema[key] < 0)):
                raise ContractError("invalid integer schema bound")
        if "enum" in schema and (type(schema["enum"]) is not list or not schema["enum"]):
            raise ContractError("nonempty enum required")
        if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
            raise ContractError("invalid uniqueness assertion")
        if "pattern" in schema and (type(schema["pattern"]) is not str or schema["pattern"] not in _PATTERNS):
            raise ContractError("unreviewed schema regular expression")
        if "format" in schema and schema["format"] != "date-time":
            raise ContractError("unreviewed schema format")

    def __call__(self, payload):
        try:
            _json_tree(payload)
            if len(_json_identity(payload).encode("utf-8")) > 1048576:
                raise ContractError("read envelope exceeds byte bound")
            self._validate(self._schema, payload, [0], 0)
        except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
            raise ContractError("invalid bounded read envelope") from exc
        return True

    def _validate(self, schema, value, work, depth):
        work[0] += 1
        if work[0] > 200000 or depth > 96:
            raise ContractError("schema validation exceeds work bound")
        if "$ref" in schema:
            self._validate(self._resolve(schema["$ref"]), value, work, depth + 1)
        if "type" in schema and type(value) is not _TYPES[schema["type"]]:
            raise ContractError("schema type mismatch")
        if "enum" in schema and not any(_json_identity(value) == _json_identity(x) for x in schema["enum"]):
            raise ContractError("schema enum mismatch")
        if "const" in schema and _json_identity(value) != _json_identity(schema["const"]):
            raise ContractError("schema constant mismatch")
        if "anyOf" in schema:
            matched = False
            for branch in schema["anyOf"]:
                try:
                    self._validate(branch, value, work, depth + 1)
                    matched = True
                    break
                except ContractError:
                    pass
            if not matched:
                raise ContractError("no schema alternative matches")
        if type(value) is dict:
            if set(schema.get("required", ())) - value.keys():
                raise ContractError("required schema property missing")
            props = schema.get("properties", {})
            if schema.get("additionalProperties") is False and value.keys() - props.keys():
                raise ContractError("unknown schema property")
            for key in value.keys() & props.keys():
                self._validate(props[key], value[key], work, depth + 1)
        elif type(value) is list:
            if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 100000):
                raise ContractError("schema array bound exceeded")
            if schema.get("uniqueItems") is True and len({_json_identity(x) for x in value}) != len(value):
                raise ContractError("schema array entries are not unique")
            if "items" in schema:
                for item in value:
                    self._validate(schema["items"], item, work, depth + 1)
        elif type(value) is str:
            upper = schema.get("maxLength", 1048576)
            if len(value) < schema.get("minLength", 0) or len(value) > upper or len(value.encode("utf-8")) > upper:
                raise ContractError("schema character or UTF-8 byte bound exceeded")
            if "pattern" in schema:
                pattern = schema["pattern"]
                # JSON-Schema search semantics; no terminal newline accepted for
                # reviewed identifier/digest/decimal patterns with a trailing $.
                if re.search(pattern, value) is None or value.endswith("\n"):
                    raise ContractError("schema string pattern mismatch")
            if schema.get("format") == "date-time":
                if not _UTC.fullmatch(value):
                    raise ContractError("timestamp must be explicit UTC Z")
                try:
                    datetime.fromisoformat(value[:-1] + "+00:00")
                except ValueError as exc:
                    raise ContractError("invalid calendar timestamp") from exc
        elif type(value) is int:
            if ("minimum" in schema and value < schema["minimum"]) or ("maximum" in schema and value > schema["maximum"]):
                raise ContractError("schema integer outside bounds")
