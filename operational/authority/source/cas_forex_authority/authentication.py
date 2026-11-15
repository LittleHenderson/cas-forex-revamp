"""Inert, externally selected Ed25519 and original-clock authentication.

No constructor loads keys, reads the clock, accesses a store or appoints anyone.
All selectors below are trusted deployment inputs, never record-selected values.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
from threading import RLock
from typing import Callable
import os
import time

from cas_forex_operational_contracts import checkpoint as ck, method
from cas_forex_operational_contracts.common import canonical_bytes, decode_canonical, digest, utc

CRYPTOGRAPHY_VERSION = "50.0.2"
METHOD_SPEC_SHA256 = "5fb660b27da026777f1e511f86b79e9330ee4e5786535c990cd54d6a42805af6"
ZERO = "0" * 64
PURPOSE_ROLES = {
    "policy-inheritance-witness-v3": {"TRUSTED_CONTROLLER_WITNESS"},
    "policy-inheritance-setup-budget-v3": {"SETUP_BUDGET_ISSUER", "INDEPENDENT_SETUP_CONSUMER"},
    "policy-inheritance-method-decision-v3": {"INDEPENDENT_SETUP_CONSUMER"},
    "policy-inheritance-ingestion-ack-v3": {"INDEPENDENT_SETUP_CONSUMER"},
    "policy-inheritance-checkpoint-v3": {"INDEPENDENT_CHECKPOINT_CUSTODIAN"},
    "policy-inheritance-checkpoint-transition-v3": {"SETUP_BUDGET_ISSUER", "INDEPENDENT_SETUP_CONSUMER"},
}


class AuthorityError(RuntimeError):
    """Stable public code only; dependency exception details are suppressed."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def need(condition: bool, code: str) -> None:
    if not condition:
        raise AuthorityError(code)


def same(a, b) -> bool:
    return canonical_bytes(a) == canonical_bytes(b)


def ref(raw: bytes, kind: str) -> method.ObjectRef:
    value = {"object_id": digest(raw), "sha256": digest(raw), "bytes": len(raw), "artifact_kind": kind}
    return method.validate("ObjectRef", value).payload()


def stamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def micros(delta: timedelta) -> int:
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def stamp_le(a, b) -> bool:
    return utc(a["utc"]) <= utc(b["utc"]) and a["boottime_ns"] <= b["boottime_ns"]


def original_key(binding) -> dict:
    scope = binding["scope"]
    return {k: scope[k] for k in ("run_id", "original_window_sha256", "setup_identity")}


@contextmanager
def _guarded_lock(lock, *, nonblocking, code):
    need(lock.acquire(blocking=not nonblocking), code)
    try:
        yield
    finally:
        lock.release()


class LinuxOriginalClock:
    """Explicit Linux observation; it does not establish launch approval."""

    def observe(self) -> tuple[method.ClockDomain, method.Stamp]:
        try:
            need(os.name == "posix" and hasattr(time, "CLOCK_BOOTTIME"), "CLOCK_DOMAIN_UNSUPPORTED")
            before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            value = datetime.now(timezone.utc)
            domain = {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      "time_namespace_inode": os.stat("/proc/self/ns/time").st_ino,
                      "clock_id": "CLOCK_BOOTTIME"}
            after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            need(0 <= after - before <= 1_000_000_000, "CLOCK_DRIFT")
            return method.validate("ClockDomain", domain).payload(), {
                "utc": stamp_text(value), "boottime_ns": after}
        except AuthorityError:
            raise
        except Exception:
            raise AuthorityError("CLOCK_DOMAIN_UNSUPPORTED") from None


class OriginalGuard:
    def __init__(self, budget: method.SetupBudget, *, clock, nonblocking_lock=False):
        self._budget_raw = method.validate("SetupBudget", budget).raw
        self.clock = clock
        need(type(nonblocking_lock) is bool, "CONTEXT_MISMATCH")
        self._nonblocking_lock = nonblocking_lock
        self._last_ns = None
        self._last_utc = None
        self._lock = RLock()
        start, end, outer = budget["started"], budget["deadline"], budget["outer_deadline"]
        need(utc(end["utc"]) == min(utc(start["utc"]) + timedelta(seconds=180), utc(outer["utc"]))
             and end["boottime_ns"] == min(start["boottime_ns"] + 180_000_000_000, outer["boottime_ns"]),
             "BUDGET_RESET_ATTEMPT")
        need(stamp_le(start, end) and start != end, "SETUP_DEADLINE_EXPIRED")

    @property
    def budget(self):
        return decode_canonical(self._budget_raw)

    def check(self, supplied: method.Stamp | None = None) -> method.Stamp:
        with _guarded_lock(self._lock, nonblocking=self._nonblocking_lock, code="CLOCK_GUARD_BUSY"):
            domain, actual = self.clock.observe()
            method.validate("Stamp", actual)
            budget = self.budget
            need(same(domain, budget["clock_domain"]), "CLOCK_DOMAIN_UNSUPPORTED")
            start, end = budget["started"], budget["deadline"]
            ns = actual["boottime_ns"]
            need(stamp_le(start, actual) and utc(actual["utc"]) < utc(end["utc"])
                 and ns < end["boottime_ns"], "SETUP_DEADLINE_EXPIRED")
            need(self._last_ns is None or ns >= self._last_ns, "CLOCK_DRIFT")
            need(self._last_utc is None or utc(actual["utc"]) >= self._last_utc, "CLOCK_DRIFT")
            need(abs(micros(utc(actual["utc"]) - utc(start["utc"])) * 1000
                     - (ns - start["boottime_ns"])) <= 1_000_000_000, "CLOCK_DRIFT")
            if supplied is not None:
                method.validate("Stamp", supplied)
                need(stamp_le(supplied, actual) and ns - supplied["boottime_ns"] <= 1_000_000_000
                     and micros(utc(actual["utc"]) - utc(supplied["utc"])) <= 1_000_000, "CLOCK_DRIFT")
            self._last_ns = ns
            self._last_utc = utc(actual["utc"])
            return actual

    def remaining(self, deadline: method.Stamp | None = None) -> float:
        actual = self.check()
        end = self.budget["deadline"]
        if deadline is not None:
            method.validate("Stamp", deadline)
            need(stamp_le(deadline, end), "BUDGET_RESET_ATTEMPT")
            end = deadline
        seconds = min((end["boottime_ns"] - actual["boottime_ns"]) / 1e9,
                      micros(utc(end["utc"]) - utc(actual["utc"])) / 1e6)
        need(seconds > 0, "SETUP_DEADLINE_EXPIRED")
        return seconds


class Ed25519Verifier:
    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> None:
        need(type(public_key) is bytes and len(public_key) == 32
             and type(signature) is bytes and len(signature) == 64 and type(message) is bytes,
             "SIGNATURE_REJECTED")
        try:
            need(version("cryptography") == CRYPTOGRAPHY_VERSION, "SIGNATURE_DEPENDENCY_UNAVAILABLE")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except Exception:
            raise AuthorityError("SIGNATURE_DEPENDENCY_UNAVAILABLE") from None
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        except Exception:
            raise AuthorityError("SIGNATURE_REJECTED") from None


class Ed25519Signer:
    def __init__(self, *, load_selected_private_bytes: Callable[[], bytes], public_key: bytes,
                 allowed_domains: frozenset[bytes]):
        need(callable(load_selected_private_bytes), "SIGNER_UNAPPOINTED")
        need(type(public_key) is bytes and len(public_key) == 32, "SIGNER_UNAPPOINTED")
        need(isinstance(allowed_domains, (set, frozenset)) and len(allowed_domains) > 0
             and all(type(d) is bytes and len(d) > 0 for d in allowed_domains), "PURPOSE_MISMATCH")
        self._load = load_selected_private_bytes
        self.public_key = public_key
        self.allowed_domains = frozenset(allowed_domains)

    def sign(self, *, domain: bytes, canonical_body: bytes) -> bytes:
        need(type(domain) is bytes and domain in self.allowed_domains, "PURPOSE_MISMATCH")
        need(type(canonical_body) is bytes, "RAW_BYTES_MISMATCH")
        decode_canonical(canonical_body)
        try:
            need(version("cryptography") == CRYPTOGRAPHY_VERSION, "SIGNATURE_DEPENDENCY_UNAVAILABLE")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except AuthorityError:
            raise
        except Exception:
            raise AuthorityError("SIGNATURE_DEPENDENCY_UNAVAILABLE") from None
        raw_priv = self._load()
        need(type(raw_priv) is bytes and len(raw_priv) == 32, "SIGNER_UNAPPOINTED")
        try:
            key = Ed25519PrivateKey.from_private_bytes(raw_priv)
        except Exception:
            raise AuthorityError("SIGNER_UNAPPOINTED") from None
        need(key.public_key().public_bytes_raw() == self.public_key, "SIGNER_UNAPPOINTED")
        return key.sign(domain + canonical_body)


class PreloadedEd25519Verifier:
    """Explicit preload before the final read; verify performs no acquisition."""
    def __init__(self, selected_public_keys: tuple[bytes, ...]):
        self._selected, self._keys = tuple(selected_public_keys), None
        need(self._selected and all(type(k) is bytes and len(k) == 32 for k in self._selected), "SIGNER_UNAPPOINTED")

    def prepare(self):
        need(self._keys is None, "REPLAY_OR_EQUIVOCATION")
        try:
            need(version("cryptography") == CRYPTOGRAPHY_VERSION, "SIGNATURE_DEPENDENCY_UNAVAILABLE")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            keys = {k: Ed25519PublicKey.from_public_bytes(k) for k in self._selected}
        except Exception:
            raise AuthorityError("SIGNATURE_DEPENDENCY_UNAVAILABLE") from None
        self._keys = keys

    def verify(self, *, public_key, message, signature):
        need(self._keys is not None and public_key in self._keys, "SIGNATURE_DEPENDENCY_UNAVAILABLE")
        need(type(message) is bytes and type(signature) is bytes and len(signature) == 64, "SIGNATURE_REJECTED")
        try:
            self._keys[public_key].verify(signature, message)
        except Exception:
            raise AuthorityError("SIGNATURE_REJECTED") from None


@dataclass(frozen=True)
class AuthoritySelection:
    """Out-of-band authenticated deployment selections, not a new wire schema.

    Constructor injection must come from the independent launch administrator.
    No record or peer can replace these public keys/pins/authority references.
    """
    appointment_raw: bytes
    appointment_sha256: str
    principal_keys: tuple[tuple[str, bytes], ...]
    authorizer_id: str
    authorizer_public_key: bytes
    appointment_authentication_refs: tuple[bytes, ...]
    principal_authority_refs: tuple[bytes, ...]
    access_raw: bytes
    access_sha256: str


class MethodAuthenticator:
    def __init__(self, selection: AuthoritySelection, *, guard: OriginalGuard,
                 verifier, current_status: Callable[[], ck.RpcSignature],
                 initial_authorization: Callable[[str], ck.RpcSignature], nonblocking_status_lock=False):
        self.selection, self.guard, self.verifier = selection, guard, verifier
        self._status_provider, self._initial_provider = current_status, initial_authorization
        need(type(nonblocking_status_lock) is bool, "CONTEXT_MISMATCH")
        self._nonblocking_status_lock = nonblocking_status_lock
        self._revision = -1
        self._status_hash = None
        self._lock = RLock()
        need(digest(selection.appointment_raw) == selection.appointment_sha256
             and digest(selection.access_raw) == selection.access_sha256, "APPOINTMENT_UNAVAILABLE")
        appointment = method.decode("Appointment", selection.appointment_raw).payload()
        need(appointment["scope"]["method_spec_sha256"] == METHOD_SPEC_SHA256, "CONTEXT_MISMATCH")
        access = ck.decode("CheckpointAccessSelection", selection.access_raw).payload()
        need(same(access["binding"], self.binding) and access["checkpoint_authority_id"] == appointment["checkpoint_authority_id"],
             "CONTEXT_MISMATCH")
        need(access["authorizer_id"] == selection.authorizer_id, "SIGNER_UNAPPOINTED")
        principals = appointment["principals"]
        need(len({p["principal_id"] for p in principals}) == len(principals), "SIGNER_UNAPPOINTED")
        keys = dict(selection.principal_keys)
        expected_ids = {p["principal_id"] for p in principals} | {g["principal_id"] for g in access["callers"]}
        need(len(keys) == len(selection.principal_keys) and set(keys) == expected_ids, "SIGNER_UNAPPOINTED")
        for p in principals:
            key = keys.get(p["principal_id"])
            need(type(key) is bytes and len(key) == 32 and digest(key) == p["signer_public_sha256"], "SIGNER_UNAPPOINTED")
        for grant in access["callers"]:
            key = keys[grant["principal_id"]]
            need(type(key) is bytes and len(key) == 32 and digest(key) == grant["signer_public_sha256"], "SIGNER_UNAPPOINTED")
            principal = next((p for p in principals if p["principal_id"] == grant["principal_id"]), None)
            if principal is not None:
                need(grant["component_manifest_sha256"] == principal["component_manifest_sha256"], "CONTEXT_MISMATCH")
        required = [self.principal(role) for role in ("TRUSTED_CONTROLLER_WITNESS", "INDEPENDENT_SETUP_CONSUMER", "INDEPENDENT_CHECKPOINT_CUSTODIAN")]
        need(len({p["principal_id"] for p in required}) == 3
             and len({p["signer_public_sha256"] for p in required}) == 3, "SIGNER_UNAPPOINTED")
        need(appointment["checkpoint_authority_id"] == required[2]["principal_id"], "CHECKPOINT_AUTHORITY_UNAVAILABLE")
        need(len({appointment[k] for k in ("producer_staging_root_id", "consumer_retention_root_id", "independent_checkpoint_root_id")}) == 3,
             "RETENTION_UNAVAILABLE")
        need(selection.appointment_authentication_refs and selection.principal_authority_refs, "APPOINTMENT_UNAVAILABLE")
        for raw in selection.appointment_authentication_refs + selection.principal_authority_refs:
            method.decode("ObjectRef", raw)

    @property
    def appointment(self):
        return method.decode("Appointment", self.selection.appointment_raw).payload()

    @property
    def binding(self):
        return {"scope": self.appointment["scope"], "appointment_sha256": self.selection.appointment_sha256}

    @property
    def access(self):
        return ck.decode("CheckpointAccessSelection", self.selection.access_raw).payload()

    def principal(self, role: str):
        rows = [p for p in self.appointment["principals"] if p["role"] == role]
        need(len(rows) == 1, "SIGNER_UNAPPOINTED")
        return rows[0]

    def key(self, principal_id: str) -> bytes:
        key = dict(self.selection.principal_keys).get(principal_id)
        need(key is not None, "SIGNER_UNAPPOINTED")
        return key

    def verify_rpc(self, envelope, *, domain: bytes, public_key: bytes, type_name: str):
        wire = ck.validate("RpcSignature", envelope).payload()
        need(wire["signer_sha256"] == digest(public_key), "SIGNER_UNAPPOINTED")
        body = ck.decode(type_name, wire["body_utf8"].encode("utf-8"))
        try:
            result = self.verifier.verify(public_key=public_key, message=domain + body.raw,
                                          signature=bytes.fromhex(wire["signature_hex"]))
            need(result is None, "SIGNATURE_REJECTED")
        except AuthorityError:
            raise
        except Exception:
            raise AuthorityError("SIGNATURE_REJECTED") from None
        return body.payload()

    def current(self, now=None) -> tuple[dict, dict]:
        self.guard.check(now)
        try:
            envelope = self._status_provider()
        except Exception:
            raise AuthorityError("APPOINTMENT_EXPIRED_OR_UNAVAILABLE") from None
        status = self.verify_rpc(envelope, domain=ck.AUTHORITY_STATUS_DOMAIN,
                                 public_key=self.selection.authorizer_public_key, type_name="AuthorityStatus")
        actual = self.guard.check()
        need(status["authorizer_id"] == self.selection.authorizer_id
             and status["appointment_sha256"] == self.selection.appointment_sha256
             and status["status"] == "ACTIVE", "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        with _guarded_lock(self._lock, nonblocking=self._nonblocking_status_lock, code="AUTHORITY_STATUS_BUSY"):
            h = digest(canonical_bytes(status))
            need(status["revision"] >= self._revision
                 and (status["revision"] != self._revision or h == self._status_hash), "REPLAY_OR_EQUIVOCATION")
            self._revision, self._status_hash = status["revision"], h
        principals = self.appointment["principals"]
        need(set(status["principal_ids"]) == {p["principal_id"] for p in principals}, "SIGNER_UNAPPOINTED")
        rows = [self.appointment, self.access, status] + principals
        start = max(utc(r["not_before_utc"]) for r in rows)
        end = min(utc(r["expires_at_utc"]) for r in rows)
        budget = self.guard.budget
        need(same(budget["binding"], self.binding) and same(budget["clock_domain"], self.appointment["clock_domain"])
             and budget["coverage_plan_sha256"] == self.appointment["coverage_plan_sha256"], "CONTEXT_MISMATCH")
        need(start <= utc(budget["started"]["utc"]) and utc(budget["deadline"]["utc"]) <= end,
             "APPOINTMENT_INTERVAL_INSUFFICIENT")
        need(start <= utc(actual["utc"]) < end, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        return status, actual

    def authenticate_appointment(self, appointment, *, authority_status, budget, now):
        need(same(appointment, self.appointment) and same(budget, self.guard.budget), "CONTEXT_MISMATCH")
        status, actual = self.current(now)
        need(same(authority_status, status), "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        rows = [appointment, status, self.access] + appointment["principals"]
        interval = {"binding": self.binding,
                    "not_before_utc": stamp_text(max(utc(r["not_before_utc"]) for r in rows)),
                    "expires_at_utc": stamp_text(min(utc(r["expires_at_utc"]) for r in rows)),
                    "appointment_authentication_refs": [decode_canonical(x) for x in self.selection.appointment_authentication_refs],
                    "principal_authority_refs": [decode_canonical(x) for x in self.selection.principal_authority_refs],
                    "dependency_attestation_refs": [], "validated_at": actual}
        return method.validate("AuthenticatedInterval", interval).payload()

    def verify_attestation(self, body, envelope, *, expected_purpose, appointment, now):
        need(same(appointment, self.appointment), "CONTEXT_MISMATCH")
        _, actual = self.current(now)
        wire = method.validate("SignedEnvelope", envelope).payload()
        att = wire["body"]
        need(expected_purpose in PURPOSE_ROLES and att["purpose"] == expected_purpose, "PURPOSE_MISMATCH")
        p = next((p for p in appointment["principals"] if p["principal_id"] == att["producer_id"]), None)
        need(p is not None and p["role"] in PURPOSE_ROLES[expected_purpose]
             and expected_purpose in p["allowed_purposes"]
             and wire["signer_sha256"] == p["signer_public_sha256"], "SIGNER_UNAPPOINTED")
        need(same(att["binding"], self.binding) and att["record_sha256"] == digest(body)
             and att["record_bytes"] == len(body), "RAW_BYTES_MISMATCH")
        expected_budget = None if expected_purpose == "policy-inheritance-setup-budget-v3" else digest(self._budget_bytes())
        need(att["budget_sha256"] == expected_budget, "CONTEXT_MISMATCH")
        need(stamp_le(self.guard.budget["started"], att["issued"]) and stamp_le(att["issued"], actual) and utc(actual["utc"]) < utc(att["expires"]["utc"])
             and actual["boottime_ns"] < att["expires"]["boottime_ns"]
             and stamp_le(att["expires"], self.guard.budget["deadline"]), "AUTHENTICATED_INTERVAL_EXPIRED")
        value = decode_canonical(body, limit=4_194_304)
        if type(value) is dict:
            for field in ("recorded", "acknowledged", "decided", "checkpointed_at", "prepared_at", "finished", "decoded", "selected_at", "validated_at", "started"):
                if field in value and type(value[field]) is dict and set(value[field]) == {"utc", "boottime_ns"}:
                    need(stamp_le(value[field], att["issued"]), "CLOCK_DRIFT")
        try:
            result = self.verifier.verify(public_key=self.key(p["principal_id"]), message=method.attestation_signing_bytes(att),
                                          signature=bytes.fromhex(wire["signature_hex"]))
            need(result is None, "SIGNATURE_REJECTED")
        except AuthorityError:
            raise
        except Exception:
            raise AuthorityError("SIGNATURE_REJECTED") from None
        self.current()

    def _budget_bytes(self):
        return method.validate("SetupBudget", self.guard.budget).raw

    def authorize_initial(self, authorization, *, now):
        ck.validate("InitialSetupAuthorization", authorization)
        self.current(now)
        try:
            envelope = self._initial_provider(authorization["authorization_id"])
        except Exception:
            raise AuthorityError("RUNTIME_APPROVAL_ABSENT") from None
        checked = self.verify_rpc(envelope, domain=ck.ORIGINAL_SETUP_AUTHORIZATION_DOMAIN,
                                  public_key=self.selection.authorizer_public_key, type_name="InitialSetupAuthorization")
        _, actual = self.current()
        need(same(authorization, checked) and same(checked["binding"], self.binding)
             and same(checked["original_setup_key"], original_key(self.binding))
             and checked["authorizer_id"] == self.selection.authorizer_id
             and checked["budget_id"] == self.guard.budget["budget_id"]
             and same(checked["clock_domain"], self.guard.budget["clock_domain"]), "CONTEXT_MISMATCH")
        need(utc(checked["not_before_utc"]) <= utc(self.guard.budget["started"]["utc"])
             and utc(self.guard.budget["deadline"]["utc"]) <= utc(checked["expires_at_utc"])
             and utc(actual["utc"]) < utc(checked["expires_at_utc"]), "APPOINTMENT_INTERVAL_INSUFFICIENT")
        return checked

    def attest(self, raw: bytes, *, purpose: str, producer_id: str, signer, now, expires=None):
        _, actual = self.current(now)
        expiry = expires or self.guard.budget["deadline"]
        body = {"format": "forex.policy-inheritance-attestation/3", "binding": self.binding,
                "attestation_id": "att-" + digest(raw + purpose.encode("ascii")), "purpose": purpose,
                "producer_id": producer_id, "record_sha256": digest(raw), "record_bytes": len(raw),
                "budget_sha256": None if purpose == "policy-inheritance-setup-budget-v3" else digest(self._budget_bytes()),
                "issued": actual, "expires": expiry}
        body_raw = method.validate("AttestationBody", body).raw
        try:
            signature = signer.sign(domain=method.SIGNATURE_DOMAIN, canonical_body=body_raw)
        except Exception:
            raise AuthorityError("SIGNATURE_DEPENDENCY_UNAVAILABLE") from None
        result = {"body": body, "algorithm": "Ed25519", "signer_sha256": digest(self.key(producer_id)),
                  "signature_hex": signature.hex()}
        self.verify_attestation(raw, result, expected_purpose=purpose, appointment=self.appointment, now=self.guard.check())
        return result


class LiveAuthorityView:
    """Nonblocking authenticated mailbox for the final local commit gap.

    A separately selected live authority feed must publish signed status and
    invalidate on loss. This class does not create that feed or infer liveness.
    A caller-selected positive boolean cannot populate it. Short freshness is a
    local lease, never an extension of original budget or authority validity.
    """
    def __init__(self, *, selection: AuthoritySelection, budget, verifier,
                 maximum_age_ns: int = 250_000_000):
        self.selection = selection
        self._budget = method.validate("SetupBudget", budget).raw
        self._appointment = method.decode("Appointment", selection.appointment_raw).payload()
        need(type(verifier) is PreloadedEd25519Verifier, "SIGNATURE_DEPENDENCY_UNAVAILABLE")
        self.verifier = verifier
        need(type(maximum_age_ns) is int and 0 < maximum_age_ns <= 1_000_000_000, "CONTEXT_MISMATCH")
        self.maximum_age_ns = maximum_age_ns
        self._lock, self._value = RLock(), None
        self._available, self._revision, self._hash = False, -1, None
        self._envelope_raw = None
        self._invalidated = False

    def invalidate(self):
        # Terminal for this attempt-local mailbox, including an in-flight publish.
        # No refresh is permitted to undo an observed loss/uncertainty.
        self._invalidated = True
        self._available = False

    def publish_authenticated(self, envelope, *, observed):
        """Called by an external live feed before the final-read gap."""
        need(not self._invalidated, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        method.validate("Stamp", observed)
        wire = ck.validate("RpcSignature", envelope).payload()
        raw = wire["body_utf8"].encode("utf-8")
        value = ck.decode("AuthorityStatus", raw).payload()
        need(wire["signer_sha256"] == digest(self.selection.authorizer_public_key), "SIGNER_UNAPPOINTED")
        need(self.verifier.verify(public_key=self.selection.authorizer_public_key,
             message=ck.AUTHORITY_STATUS_DOMAIN + raw, signature=bytes.fromhex(wire["signature_hex"])) is None, "SIGNATURE_REJECTED")
        self._validate(value, observed)
        with self._lock:
            need(not self._invalidated, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
            need(value["revision"] >= self._revision and (value["revision"] != self._revision or digest(raw) == self._hash), "REPLAY_OR_EQUIVOCATION")
            self._revision, self._hash = value["revision"], digest(raw)
            self._value = (raw, canonical_bytes(observed))
            self._envelope_raw = canonical_bytes(wire)
            self._available = value["status"] == "ACTIVE" and not self._invalidated
            if value["status"] != "ACTIVE":self.invalidate()

    def _validate(self, value, now):
        budget = decode_canonical(self._budget)
        need(value["authorizer_id"] == self.selection.authorizer_id
             and value["appointment_sha256"] == self.selection.appointment_sha256
             and digest(self.selection.appointment_raw) == self.selection.appointment_sha256
             and same(budget["binding"], {"scope": self._appointment["scope"], "appointment_sha256": self.selection.appointment_sha256})
             and set(value["principal_ids"]) == {p["principal_id"] for p in self._appointment["principals"]}, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        rows = [value, self._appointment, ck.decode("CheckpointAccessSelection", self.selection.access_raw).payload()] + self._appointment["principals"]
        start, end = max(utc(r["not_before_utc"]) for r in rows), min(utc(r["expires_at_utc"]) for r in rows)
        need(start <= utc(budget["started"]["utc"]) and utc(budget["deadline"]["utc"]) <= end, "APPOINTMENT_INTERVAL_INSUFFICIENT")
        need(stamp_le(budget["started"], now) and utc(now["utc"]) < min(end, utc(budget["deadline"]["utc"]))
             and now["boottime_ns"] < budget["deadline"]["boottime_ns"], "SETUP_DEADLINE_EXPIRED")
        need(abs(micros(utc(now["utc"]) - utc(budget["started"]["utc"])) * 1000
                 - (now["boottime_ns"] - budget["started"]["boottime_ns"])) <= 1_000_000_000, "CLOCK_DRIFT")

    def current_authority(self, now):
        """Pure local read. Busy/unavailable/stale is a failure, never a wait."""
        method.validate("Stamp", now)
        need(self._lock.acquire(blocking=False), "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        try:
            need(not self._invalidated and self._available and self._value is not None, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
            raw, stamp_raw = self._value
            value, observed = decode_canonical(raw), decode_canonical(stamp_raw)
            need(stamp_le(observed, now) and now["boottime_ns"] - observed["boottime_ns"] <= self.maximum_age_ns
                 and micros(utc(now["utc"]) - utc(observed["utc"])) * 1000 <= self.maximum_age_ns, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
            self._validate(value, now)
            need(not self._invalidated and self._available and value["status"] == "ACTIVE", "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
            return value
        finally:
            self._lock.release()

    def current_envelope(self, now):
        """Exact externally authenticated RPC envelope; no signature remint."""
        need(self._lock.acquire(blocking=False), "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        try:
            status = self.current_authority(now)
            need(self._envelope_raw is not None, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
            envelope = ck.decode("RpcSignature", self._envelope_raw).payload()
            need(envelope["body_utf8"].encode("utf-8") == canonical_bytes(status)
                 and not self._invalidated and self._available, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
            return envelope
        finally:
            self._lock.release()

    def verify_checkpoint_certificate(self, raw, envelope, now):
        """Pure bounded certificate verification using already preloaded keys."""
        status = self.current_authority(now)
        certificate = method.decode("ConsumerCheckpoint", raw).payload()
        wire = method.validate("SignedEnvelope", envelope).payload()
        att = wire["body"]
        principals = [p for p in self._appointment["principals"] if p["role"] == "INDEPENDENT_CHECKPOINT_CUSTODIAN"]
        need(len(principals) == 1, "SIGNER_UNAPPOINTED")
        principal = principals[0]
        budget = decode_canonical(self._budget)
        need(att["purpose"] == "policy-inheritance-checkpoint-v3" and att["producer_id"] == principal["principal_id"]
             and att["purpose"] in principal["allowed_purposes"] and wire["signer_sha256"] == principal["signer_public_sha256"]
             and certificate["checkpoint_authority_id"] == principal["principal_id"], "SIGNER_UNAPPOINTED")
        need(same(att["binding"], budget["binding"]) and same(certificate["binding"], budget["binding"])
             and att["budget_sha256"] == certificate["budget_sha256"] == digest(self._budget)
             and att["record_sha256"] == digest(raw) and att["record_bytes"] == len(raw), "RAW_BYTES_MISMATCH")
        need(stamp_le(budget["started"], certificate["checkpointed_at"])
             and stamp_le(certificate["checkpointed_at"], att["issued"]) and stamp_le(att["issued"], now)
             and utc(now["utc"]) < utc(att["expires"]["utc"]) and now["boottime_ns"] < att["expires"]["boottime_ns"]
             and stamp_le(att["expires"], budget["deadline"]), "AUTHENTICATED_INTERVAL_EXPIRED")
        key = dict(self.selection.principal_keys).get(principal["principal_id"])
        need(key is not None and digest(key) == principal["signer_public_sha256"], "SIGNER_UNAPPOINTED")
        need(self.verifier.verify(public_key=key, message=method.attestation_signing_bytes(att), signature=bytes.fromhex(wire["signature_hex"])) is None, "SIGNATURE_REJECTED")
        need(same(status, self.current_authority(now)), "APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
