"""PUBLIC TEST FIXTURES ONLY. Not operational keys, grants or observations.

The deterministic hash signatures below are deliberately NOT Ed25519 and must
never be supplied to an operational assembly. Tests are authored, NOT_RUN.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib

from cas_forex_operational_contracts import checkpoint as ck, method
from cas_forex_operational_contracts.common import canonical_bytes, digest, decode_canonical
from cas_forex_authority.authentication import AuthoritySelection, MethodAuthenticator, OriginalGuard, ref, stamp_text
from cas_forex_authority.consumer_store import ConsumerStore, StoreSelection
from cas_forex_authority.checkpoint_store import CheckpointStore
from cas_forex_authority.method_runtime import UNSUPPORTED, CALIBRATIONS

START = datetime(2026, 10, 11, 19, 0, tzinfo=timezone.utc)


def stamp(seconds=0):
    return {"utc": stamp_text(START + timedelta(seconds=seconds)), "boottime_ns": 1_000_000_000 + seconds * 1_000_000_000}


class FixtureClock:
    def __init__(self, domain):
        self.domain, self.now = domain, stamp(1)
    def observe(self):
        return dict(self.domain), dict(self.now)


class FixtureSigner:
    def __init__(self, public):
        self.public, self.calls = public, []
    def sign(self, *, domain, canonical_body):
        self.calls.append((domain, canonical_body))
        return hashlib.sha512(self.public + domain + canonical_body).digest()


class FixtureVerifier:
    def verify(self, *, public_key, message, signature):
        if hashlib.sha512(public_key + message).digest() != signature:
            raise ValueError("public test fixture signature mismatch")


def signed_rpc(value, domain, public):
    raw = canonical_bytes(value)
    return {"body_utf8": raw.decode(), "signer_sha256": digest(public), "algorithm": "Ed25519",
            "signature_hex": FixtureSigner(public).sign(domain=domain, canonical_body=raw).hex()}


def process(role, pid, uid):
    return {"role": role, "boot_id": "00000000-0000-4000-8000-000000000001", "pid": pid, "start_ticks": pid * 10,
            "parent_pid": 1, "parent_start_ticks": 1, "uid": uid, "gid": uid}


def fixture():
    scope = {"method_id": "POLICY_INHERITANCE_TRUSTED_ADAPTER_V1", "method_spec_sha256": "5fb660b27da026777f1e511f86b79e9330ee4e5786535c990cd54d6a42805af6",
             "source_manifest_sha256": "b" * 64, "config_sha256": "c" * 64, "topology_sha256": "d" * 64,
             "run_id": "public-run", "epoch": 1, "original_window_sha256": "e" * 64, "setup_identity": "public-setup"}
    kinds = ["SETUP_BEGIN", "CALIBRATION_BEGIN"] + ["CALIBRATION_CASE"] * 8 + ["CALIBRATION_RETIRED", "FINAL_CHANNEL_CREATED",
             "RUNNER_INSTALL", "MODEL_INSTALL", "ASSET_BINDINGS", "MODEL_POST_EXEC", "FINAL_PEER_BOUND", "POLICY_ARGUMENT", "SETUP_SEAL"]
    slots = [{"slot_id": f"s{i}", "kind": kind, "origin": "CONTROLLER", "after_slots": [f"s{i-1}"] if i else [],
              "payload_decoder_sha256": "f" * 64, "expected_subject_id": f"case{i-2}" if kind == "CALIBRATION_CASE" else "subject",
              "required_raw_kinds": ["CANONICAL_PAYLOAD"]} for i, kind in enumerate(kinds)]
    verdicts = {"POSITIVE_INERT": ["ACCEPTED_INERT"], "BAD_SEQUENCE": ["ACCEPTED_INERT", "AUTH_REJECTED"],
                "BAD_FRAME": ["FRAMING_REJECTED"], "DELIVERED_RIGHTS": ["RIGHTS_REJECTED"], "TRUNCATED_RIGHTS": ["FRAMING_REJECTED"]}
    plan = {"format": "forex.policy-inheritance-coverage-plan/3", "scope": scope, "plan_id": "public-plan", "slots": slots,
            "calibration_plan": [{"case_id": f"case{i}", "slot_id": f"s{i+2}", "fixture_ref": ref(b"public fixture", "PUBLIC_FIXTURE"),
                                  "case_kind": kind, "expected_exchange_verdicts": verdicts.get(kind, ["AUTH_REJECTED"]),
                                  "receiver_component_sha256": "9" * 64, "requires_foreign_pid": kind == "WRONG_PEER_PID"}
                                 for i, kind in enumerate(CALIBRATIONS)], "max_records": 19, "max_raw_bytes": 64 * 1024 * 1024,
            "unsupported_routes": list(UNSUPPORTED)}
    domain = {"boot_id": "00000000-0000-4000-8000-000000000001", "time_namespace_inode": 77, "clock_id": "CLOCK_BOOTTIME"}
    public_keys = {"witness": bytes([1]) * 32, "consumer": bytes([2]) * 32, "checkpoint": bytes([3]) * 32}
    roles = {"witness": "TRUSTED_CONTROLLER_WITNESS", "consumer": "INDEPENDENT_SETUP_CONSUMER", "checkpoint": "INDEPENDENT_CHECKPOINT_CUSTODIAN"}
    purposes = {"witness": ["policy-inheritance-witness-v3"],
                "consumer": ["policy-inheritance-setup-budget-v3", "policy-inheritance-ingestion-ack-v3", "policy-inheritance-method-decision-v3", "policy-inheritance-checkpoint-transition-v3"],
                "checkpoint": ["policy-inheritance-checkpoint-v3"]}
    principals = [{"principal_id": name, "role": roles[name], "component_manifest_sha256": digest(name.encode()),
                   "signer_public_sha256": digest(key), "allowed_purposes": purposes[name],
                   "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(600)["utc"]} for name, key in public_keys.items()]
    appointment = {"format": "forex.policy-inheritance-appointment/3", "appointment_id": "public-appointment", "scope": scope,
                   "coverage_plan_sha256": digest(canonical_bytes(plan)), "principals": principals, "clock_domain": domain,
                   "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(600)["utc"], "producer_staging_root_id": "witness-root",
                   "consumer_retention_root_id": "consumer-root", "independent_checkpoint_root_id": "checkpoint-root",
                   "approved_runtime_topology_ref": ref(b"public topology", "TOPOLOGY_APPROVAL"),
                   "watchdog_binding_ref": ref(b"public watchdog", "WATCHDOG_BINDING"), "stream_id": "public-stream", "checkpoint_authority_id": "checkpoint"}
    appointment_raw = canonical_bytes(appointment)
    binding = {"scope": scope, "appointment_sha256": digest(appointment_raw)}
    budget = {"format": "forex.policy-inheritance-setup-budget/3", "binding": binding, "budget_id": "public-budget", "issuer_id": "consumer",
              "clock_domain": domain, "started": stamp(), "deadline": stamp(180), "outer_deadline": stamp(600), "maximum_seconds": 180,
              "coverage_plan_sha256": appointment["coverage_plan_sha256"], "appointment_interval_ref": ref(b"public interval", "AUTHENTICATED_INTERVAL")}
    callers = [{"principal_id": "consumer", "signer_public_sha256": digest(public_keys["consumer"]),
                "component_manifest_sha256": digest(b"consumer"), "actual_process": process("SETUP_CONSUMER", 20, 1001),
                "operations": ["READ_CURRENT", "ADVANCE", "LOOKUP_TRANSITION"], "uses": ["SETUP_PROTOCOL"]},
               {"principal_id": "witness", "signer_public_sha256": digest(public_keys["witness"]),
                "component_manifest_sha256": digest(b"witness"), "actual_process": process("CONTROLLER", 10, 1000),
                "operations": ["READ_CURRENT"], "uses": ["RELEASE_CONSUMPTION"]}]
    access = {"format": "forex.checkpoint-access-selection/2", "binding": binding, "checkpoint_authority_id": "checkpoint",
              "store_instance_id": "public-checkpoint-instance", "endpoint_id": "public-endpoint", "endpoint_binding_sha256": "1" * 64,
              "callers": callers, "authorizer_id": "external", "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(600)["utc"]}
    authority_key = bytes([4]) * 32
    status = {"format": "forex.runtime-authority-status/1", "appointment_sha256": digest(appointment_raw), "authorizer_id": "external",
              "revision": 1, "status": "ACTIVE", "principal_ids": list(public_keys),
              "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(600)["utc"]}
    original = {k: scope[k] for k in ("run_id", "original_window_sha256", "setup_identity")}
    initial = {"format": "forex.original-setup-authorization/1", "authorization_id": "public-authorization", "authorizer_id": "external",
               "binding": binding, "original_setup_key": original, "authorized_issuer_id": "consumer", "budget_id": budget["budget_id"],
               "clock_domain": domain, "original_outer_window_ref": ref(b"public original window", "CANONICAL_PAYLOAD"),
               "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(600)["utc"], "maximum_seconds": 180, "max_reservations": 1}
    authority_ref = canonical_bytes(ref(b"public selected authority", "CANONICAL_PAYLOAD"))
    # Public synthetic correspondence only, not operational authority or provenance.
    principal_authority_refs = tuple(
        canonical_bytes(ref(canonical_bytes({
            "fixture_notice": "PUBLIC TEST FIXTURE ONLY; NOT OPERATIONAL AUTHORITY",
            "principal_id": principal["principal_id"], "role": principal["role"],
            "component_manifest_sha256": principal["component_manifest_sha256"],
            "signer_public_sha256": principal["signer_public_sha256"],
        }), "PUBLIC_FIXTURE")) for principal in principals)
    selection = AuthoritySelection(appointment_raw, digest(appointment_raw), tuple(public_keys.items()), "external", authority_key,
                                   (authority_ref,), principal_authority_refs, canonical_bytes(access), digest(canonical_bytes(access)))
    clock = FixtureClock(domain)
    guard = OriginalGuard(budget, clock=clock)
    auth = MethodAuthenticator(selection, guard=guard, verifier=FixtureVerifier(),
                               current_status=lambda: signed_rpc(status, ck.AUTHORITY_STATUS_DOMAIN, authority_key),
                               initial_authorization=lambda _: signed_rpc(initial, ck.ORIGINAL_SETUP_AUTHORIZATION_DOMAIN, authority_key))
    return SimpleNamespace(auth=auth, guard=guard, clock=clock, appointment=appointment, budget=budget, plan=plan, binding=binding,
                           original=original, initial=initial, status=status, access=access, keys=public_keys,
                           consumer_signer=FixtureSigner(public_keys["consumer"]), checkpoint_signer=FixtureSigner(public_keys["checkpoint"]))


def sqlite_stores(f, root):
    """SQLite-only fixture: production filesystem ownership is NOT exercised."""
    consumer_root, checkpoint_root = Path(root) / "consumer", Path(root) / "checkpoint"
    consumer_root.mkdir(); checkpoint_root.mkdir()
    consumer = ConsumerStore(StoreSelection(consumer_root, "consumer.sqlite3", 1001, 1001, "public-consumer-instance", "2" * 64, "init-consumer", "3" * 64), guard=f.guard)
    checkpoint = CheckpointStore(StoreSelection(checkpoint_root, "checkpoint.sqlite3", 1002, 1002, "public-checkpoint-instance", "4" * 64, "init-checkpoint", "5" * 64),
                                 authentication=f.auth, signer=f.checkpoint_signer)
    for store in (consumer, checkpoint):
        # Explicit test seam isolates SQLite behavior from protected Linux roots.
        def test_path(*, existing=True, path=store.database.path):
            if existing:
                info = path.stat()
                return info.st_dev, info.st_ino
        store.database._verify_path = test_path
        store.initialize(consume_initialization=lambda _: None)
    return consumer, checkpoint


class FixtureTransport:
    """Direct test dispatcher. Provides NO peer-credential/isolation evidence."""
    def __init__(self, f, store):
        self.f, self.store, self.calls, self.lose_after_commit = f, store, [], False
    def exchange(self, request, *, deadline):
        value = ck.decode("CheckpointRpcRequest", request["body_utf8"].encode()).payload()
        self.calls.append(value)
        function = {"READ_CURRENT": self.store.read_current, "ADVANCE": self.store.compare_and_append, "LOOKUP_TRANSITION": self.store.lookup_exact}[value["operation"]]
        result = function(value, authenticated_caller=self.f.access["callers"][0], now=self.f.guard.check())
        if self.lose_after_commit and value["operation"] == "ADVANCE":
            self.lose_after_commit = False
            raise TimeoutError("public fixture lost response")
        return signed_rpc(result, ck.RESPONSE_DOMAIN, self.f.keys["checkpoint"])


def fixture_preloaded_verifier(f):
    """Explicit private test seam, never an operational crypto preload."""
    from cas_forex_authority.authentication import PreloadedEd25519Verifier
    keys=tuple(f.keys.values())+(bytes([4])*32,)
    result=PreloadedEd25519Verifier(keys)
    class FakeLoadedKey:
        def __init__(self,public):self.public=public
        def verify(self,signature,message):
            return FixtureVerifier().verify(public_key=self.public,message=message,signature=signature)
    result._keys={key:FakeLoadedKey(key) for key in keys}
    return result
