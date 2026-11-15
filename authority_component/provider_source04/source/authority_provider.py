"""Independent signed-record verification; source proposal, never an issuer.

No filesystem/network I/O or signature operation occurs on import/construction.
The four providers accept only externally selected records/signers. Actual-role
measurement stays unsupported under the reviewed unchanged topology.
"""
from datetime import datetime
from hashlib import sha256
import json
import re

RELEASE_ENABLED = False
PUBLIC_FORMAT_STATUS = "PROPOSED_PUBLIC_FIXTURE_INTERFACE_NOT_RUNTIME_APPOINTMENT"


class EvidenceError(ValueError):
    """Fixed code only; do not copy private values or caught exception text."""


def need(value, code="EVIDENCE_UNAVAILABLE"):
    if not value:
        raise EvidenceError(code)


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields), "RECORD_SHAPE")


def integer(value, low=0, high=2**63-1):
    need(type(value) is int and low <= value <= high, "RECORD_INTEGER")
    return value


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "RECORD_DIGEST")
    return value


def identifier(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}", value) is not None, "RECORD_ID")
    return value


def utc(value):
    need(type(value) is str)
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        need(result.tzinfo is not None and result.utcoffset().total_seconds() == 0, "RECORD_TIME")
        return result
    except (ValueError, AttributeError, OverflowError):
        raise EvidenceError("RECORD_TIME") from None


def _wire(value, depth=0):
    need(depth <= 64, "RECORD_DEPTH")
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is list:
        return [_wire(v, depth+1) for v in value]
    if type(value) is dict and all(type(k) is str for k in value):
        return {k: _wire(v, depth+1) for k, v in value.items()}
    raise EvidenceError("RECORD_TYPE")


def canonical(value):
    try:
        return json.dumps(_wire(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceError("RECORD_ENCODING") from None


def hash_value(value):
    return sha256(canonical(value)).hexdigest()


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4_194_304, "RECORD_SIZE")
    def pairs(items):
        result = {}
        for key, item in items:
            need(key not in result, "DUPLICATE_FIELD")
            result[key] = item
        return result
    def reject(_):
        raise EvidenceError("NONINTEGER_JSON_NUMBER")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
        _wire(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise EvidenceError("RECORD_ENCODING") from None


def ref(value):
    shape(value, ("path", "bytes", "sha256"))
    need(type(value["path"]) is str and value["path"].startswith("/opt/cas-forex/")
         and "\\" not in value["path"] and "\x00" not in value["path"]
         and all(p not in ("", ".", "..") for p in value["path"].split("/")[1:]), "RECORD_PATH")
    integer(value["bytes"], 1, 4_194_304); digest(value["sha256"])
    return value


class PinnedEd25519Verifier:
    """Verification only. Future approved caller supplies public bytes; no key I/O.

    The public key is selected outside signed records. This source neither loads
    it nor generates signatures/credentials. Dependency availability is untested.
    """
    def __init__(self, *, public_bytes, expected_fingerprint):
        need(type(public_bytes) is bytes and len(public_bytes) == 32)
        need(sha256(public_bytes).hexdigest() == digest(expected_fingerprint), "SIGNER_PIN")
        self.public_bytes = bytes(public_bytes)
        self.fingerprint = expected_fingerprint

    def verify(self, *, signer_sha256, message, signature_hex):
        need(signer_sha256 == self.fingerprint, "SIGNER_PIN")
        need(type(signature_hex) is str and re.fullmatch(r"[0-9a-f]{128}", signature_hex) is not None, "SIGNATURE_SHAPE")
        need(type(message) is bytes, "SIGNATURE_REJECTED")
        try:
            from importlib.metadata import version as _pkg_version
            need(_pkg_version("cryptography") == "50.0.2", "SIGNATURE_DEPENDENCY_UNAVAILABLE")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError("SIGNATURE_DEPENDENCY_UNAVAILABLE") from None
        try:
            Ed25519PublicKey.from_public_bytes(self.public_bytes).verify(bytes.fromhex(signature_hex), message)
        except Exception:
            raise EvidenceError("SIGNATURE_REJECTED") from None


ATTESTATION_BODY_FIELDS = frozenset(("format", "attestation_id", "record_sha256", "record_bytes", "purpose",
    "publisher_sha256", "run_id", "epoch", "source_manifest_sha256", "config_sha256", "topology_sha256",
    "original_window_sha256", "not_before_utc", "expires_at_utc"))


class AuthorityProvider:
    """Substantive authentication of exact selected bytes/purpose/identity/time.

    Selection, resolver, clock, deadline guard and signer implementations are
    independently pinned constructor inputs. Hashes do not appoint these inputs.
    No payload can install a handler, select a signer or authorize publication.
    """
    def __init__(self, *, selection, selection_content_sha256, resolver, signature_verifiers,
                 clock, require_remaining, completion=None, scorer=None, redactor=None):
        need(hash_value(selection) == digest(selection_content_sha256), "SELECTION_PIN")
        self.selection = parse(canonical(selection))
        shape(self.selection, ("format", "run_id", "epoch", "source_manifest_sha256", "config_sha256", "topology_sha256",
            "original_window_sha256", "not_before_utc", "expires_at_utc", "publishers", "records"))
        need(self.selection["format"] == "forex.custody-provider-selection/1")
        identifier(self.selection["run_id"]); integer(self.selection["epoch"], 1)
        for name in ("source_manifest_sha256", "config_sha256", "topology_sha256", "original_window_sha256"):
            digest(self.selection[name])
        duration = (utc(self.selection["expires_at_utc"])-utc(self.selection["not_before_utc"])).total_seconds()
        need(0 < duration <= 90*60, "ORIGINAL_WINDOW_BOUND")
        need(type(self.selection["publishers"]) is dict and type(self.selection["records"]) is dict)
        for publisher, signer in self.selection["publishers"].items():
            digest(publisher); digest(signer)
            need(signer in signature_verifiers, "SIGNER_UNAVAILABLE")
        for raw_hash, entry in self.selection["records"].items():
            digest(raw_hash); shape(entry, ("reference", "publisher_sha256", "attestations"))
            need(ref(entry["reference"])["sha256"] == raw_hash and entry["publisher_sha256"] in self.selection["publishers"])
            need(type(entry["attestations"]) is dict and entry["attestations"])
            for purpose, attestation in entry["attestations"].items():
                identifier(purpose); ref(attestation)
        need(callable(clock) and callable(require_remaining))
        self.resolver, self.verifiers = resolver, dict(signature_verifiers)
        self.clock, self.guard = clock, require_remaining
        self.completion, self.scorer, self.redactor = completion, scorer, redactor

    def _remaining(self):
        need(self.guard() is None, "ORIGINAL_DEADLINE_GUARD_PROTOCOL")
        now = self.clock()
        need(type(now) is datetime and now.tzinfo is not None and now.utcoffset().total_seconds() == 0)
        need(utc(self.selection["not_before_utc"]) <= now < utc(self.selection["expires_at_utc"]), "ORIGINAL_WINDOW_EXPIRED")
        return now

    def _read(self, reference):
        self._remaining(); ref(reference)
        raw, _ = self.resolver.read(reference)
        need(type(raw) is bytes and len(raw) == reference["bytes"] and sha256(raw).hexdigest() == reference["sha256"], "RAW_RECORD_PIN")
        value = parse(raw)
        self._remaining()
        return value

    def authenticate(self, *, raw_sha256, purpose, publisher_sha256, run_id, epoch):
        # Preserve the public None-on-success protocol. The private helper also
        # returns the authenticated validity interval for record's final read.
        self._authenticate_selected(raw_sha256=raw_sha256, purpose=purpose,
            publisher_sha256=publisher_sha256, run_id=run_id, epoch=epoch)

    def _attestation_current(self, interval):
        now = self._remaining()
        need(interval[0] <= now < interval[1], "ATTESTATION_TIME")

    def _authenticate_selected(self, *, raw_sha256, purpose, publisher_sha256, run_id, epoch):
        self._remaining()
        digest(raw_sha256); identifier(purpose); integer(epoch, 1)
        need(run_id == self.selection["run_id"] and epoch == self.selection["epoch"], "AUTH_IDENTITY")
        need(raw_sha256 in self.selection["records"], "UNSELECTED_RECORD")
        entry = self.selection["records"][raw_sha256]
        need(entry["publisher_sha256"] == publisher_sha256 and purpose in entry["attestations"], "AUTH_PURPOSE")
        self._read(entry["reference"])
        attestation = self._read(entry["attestations"][purpose])
        shape(attestation, ("body", "algorithm", "signer_sha256", "signature_hex"))
        body = attestation["body"]; shape(body, ATTESTATION_BODY_FIELDS)
        need(body["format"] == "forex.independent-record-attestation/1" and attestation["algorithm"] == "Ed25519")
        identifier(body["attestation_id"]); integer(body["record_bytes"], 1); integer(body["epoch"], 1)
        need(body["record_sha256"] == raw_sha256 and body["record_bytes"] == entry["reference"]["bytes"]
             and body["purpose"] == purpose and body["publisher_sha256"] == publisher_sha256, "ATTESTATION_BINDING")
        for field in ("run_id", "epoch", "source_manifest_sha256", "config_sha256", "topology_sha256", "original_window_sha256"):
            need(body[field] == self.selection[field], "ATTESTATION_BINDING")
        interval = (utc(body["not_before_utc"]), utc(body["expires_at_utc"]))
        need(utc(self.selection["not_before_utc"]) <= interval[0] < interval[1]
             <= utc(self.selection["expires_at_utc"]), "ATTESTATION_TIME")
        # Fresh time after both resolver reads; the enclosing window alone does
        # not establish that this shorter-lived attestation is still valid.
        self._attestation_current(interval)
        signer = self.selection["publishers"][publisher_sha256]
        need(attestation["signer_sha256"] == signer, "SIGNER_PIN")
        need(self.verifiers[signer].verify(signer_sha256=signer, message=canonical(body),
             signature_hex=attestation["signature_hex"]) is None, "SIGNATURE_PROVIDER_PROTOCOL")
        # Verification can consume time. Never reuse its entry timestamp.
        self._attestation_current(interval)
        return interval

    def record(self, reference, *, purpose, publisher_sha256):
        ref(reference)
        need(reference["sha256"] in self.selection["records"] and
             reference == self.selection["records"][reference["sha256"]]["reference"], "UNSELECTED_REFERENCE")
        interval = self._authenticate_selected(raw_sha256=reference["sha256"], purpose=purpose, publisher_sha256=publisher_sha256,
                                               run_id=self.selection["run_id"], epoch=self.selection["epoch"])
        # Re-read and repin after authentication; never return caller-owned data.
        value = self._read(reference)
        # Final boundary: no further resolver or verifier work after this check.
        self._attestation_current(interval)
        return value

    def verify_semantics(self, *, purpose, record, dependencies, selection):
        if purpose == "source-test-completion" and self.completion is not None:
            need(self.completion.verify(record=record, dependencies=dependencies, selection=selection, authority=self) is None,
                 "COMPLETION_PROVIDER_PROTOCOL")
        elif purpose == "independent-aggregate-redaction" and self.redactor is not None:
            need(self.redactor.verify_approval(record=record, dependencies=dependencies, selection=selection, authority=self) is None,
                 "REDACTION_PROVIDER_PROTOCOL")
        else:
            raise EvidenceError("SEMANTIC_PURPOSE_UNIMPLEMENTED")

    def verify_complete_scoring(self, *, record, retained_bundle, selection):
        need(self.scorer is not None, "SCORER_UNAVAILABLE")
        need(self.scorer.verify(record=record, retained_bundle=retained_bundle, selection=selection, authority=self) is None,
             "SCORER_PROVIDER_PROTOCOL")

    def verify_redaction(self, *, body, retained_bundle, selection):
        need(self.redactor is not None, "REDACTION_UNAVAILABLE")
        need(self.redactor.verify_body(body=body, retained_bundle=retained_bundle, selection=selection, authority=self) is None,
             "REDACTION_PROVIDER_PROTOCOL")

    def verify_observation(self, **kwargs):
        raise EvidenceError("ACTUAL_ROLE_COLLECTOR_UNSUPPORTED_UNCHANGED_TOPOLOGY")

    def verify_inventory(self, **kwargs):
        raise EvidenceError("ACTUAL_ROLE_INVENTORY_DECODER_UNSUPPORTED")
