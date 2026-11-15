"""In-memory public evidence premises for pure regression analysis.

The normalized JSON shapes used by semantic checks are proposed public-fixture
formats. They are not kernel capture formats or authenticated runtime decoders.
Operational decoding and cryptographic verification remain unsupported.
"""

from __future__ import annotations

import copy
from typing import Any

from .contract import Contract, MAX_OBJECT, MAX_RAW, canonical_bytes, decode_canonical, digest
from .errors import require


class PublicEvidence:
    classification = "PUBLIC_SYNTHETIC_ANALYSIS_ONLY"

    def __init__(self, contract: Contract, objects: dict[str, bytes], *, decoder_sha256: str) -> None:
        contract.validate_value("Sha256", decoder_sha256)
        require(type(objects) is dict and len(objects) <= 4096,
                "RAW_EVIDENCE_UNAVAILABLE", "public_objects")
        total = 0
        retained: dict[str, bytes] = {}
        for key, data in objects.items():
            contract.validate_value("Sha256", key)
            require(type(data) is bytes and 0 < len(data) <= MAX_OBJECT and digest(data) == key,
                    "RAW_BYTES_MISMATCH", "public_object")
            retained[key] = data
            total += len(data)
        require(total <= MAX_RAW, "RAW_EVIDENCE_UNAVAILABLE", "public_raw_limit")
        self._objects = retained
        self.total_bytes = total
        self._contract = contract
        self.decoder_sha256 = decoder_sha256

    def raw(self, reference: dict[str, Any], *, kind: str | None = None) -> bytes:
        self._contract.validate("ObjectRef", reference)
        data = self._objects.get(reference["object_id"])
        require(data is not None, "RAW_EVIDENCE_UNAVAILABLE", "reference")
        self._contract.object_bytes(reference, data, expected_kind=kind)
        return data

    def snapshot(self) -> dict[str, bytes]:
        return dict(self._objects)

    @property
    def sizes(self) -> dict[str, int]:
        return {key: len(data) for key, data in self._objects.items()}

    def object(self, reference: dict[str, Any], *, kind: str | None = None) -> Any:
        return decode_canonical(self.raw(reference, kind=kind), limit=MAX_OBJECT)

    def one(self, event: dict[str, Any], kind: str) -> Any:
        refs = [r for r in event["raw_refs"] if r["artifact_kind"] == kind]
        require(len(refs) == 1, "RAW_EVIDENCE_UNAVAILABLE", "required_raw_kind")
        return self.object(refs[0], kind=kind)

    def resolve_nested(self, value: Any) -> set[str]:
        """Require all declared ObjectRefs, with bounded traversal and cycle checks."""
        found: set[str] = set()
        def visit(item: Any, depth: int) -> None:
            require(depth <= 32, "RAW_EVIDENCE_UNAVAILABLE", "nested_depth")
            if type(item) is dict:
                if set(item) == {"object_id", "bytes", "sha256", "artifact_kind"}:
                    self.raw(item)
                    found.add(item["object_id"])
                else:
                    for child in item.values(): visit(child, depth + 1)
            elif type(item) is list:
                for child in item: visit(child, depth + 1)
        visit(value, 0)
        return found


class PublicSelections:
    """Caller-supplied expected public fixture values, copied before inspection.

    Expected spawn/policy/asset/channel facts are kept separate from observed
    evidence. No production caller or model may choose these as authority.
    """

    classification = "PUBLIC_SYNTHETIC_ANALYSIS_ONLY"

    def __init__(self, values: dict[str, Any]) -> None:
        require(type(values) is dict and set(values) <= {
            "controller", "installations", "assets", "asset_manifest_sha256",
            "channel", "post_exec", "peer", "source_argument_ref", "calibration", "subject_id"},
            "CONTEXT_MISMATCH", "public_selections.fields")
        self._bytes = canonical_bytes(values, limit=MAX_OBJECT)

    @property
    def values(self) -> dict[str, Any]:
        return decode_canonical(self._bytes, limit=MAX_OBJECT)


def exact_fields(value: Any, names: set[str], field: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == names, "DECODER_UNAVAILABLE", field)
    return copy.deepcopy(value)
