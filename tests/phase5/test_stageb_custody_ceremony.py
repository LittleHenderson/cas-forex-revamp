"""Deterministic Phase 5 tests for Owner Stage B Custody Ceremony & Release Overlay."""
from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import errno
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from authority_component.ceremony_release_gate import (
    CEREMONY_RELEASE_ENABLED,
    require_ceremony_release_enabled,
)
from authority_component.release_gate import RELEASE_ENABLED, require_release_enabled
from cas_forex_revamp.contracts import (
    ContractError,
    DecisionOrigin,
    DecisionProvenance,
    DecisionResult,
    DecisionSelection,
    RunScope,
    canonical_bytes,
    content_digest,
)
from cas_forex_revamp.composition.continuous_model_driver_v2 import run_trajectory
from cas_forex_revamp.composition.custody_adapter import FORMATS, adapt_custody
from cas_forex_revamp.composition.custody_protocol import ReleaseLedger, contract, validate_release
from cas_forex_revamp.composition.custody_schema import CustodySchemas, load_json
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from cas_forex_revamp.composition.generation_transport import PendingChangeBridge
from cas_forex_revamp.composition.r6_design import validate_recovered_design
from cas_forex_revamp.composition.r6_observation import wire
from cas_forex_revamp.composition.r6_readback import AttemptReader
from cas_forex_revamp.composition.r6_runtime import packet_json
from cas_forex_revamp.composition.r6_scoring import GLOBALS, PREDICATES, score_suite
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from ceremony_generator import (
    DEFAULT_CEREMONY_SEED,
    Ed25519Keypair,
    PureRFC8032Verifier,
    audit_counterpart_traps_with_valve_gate,
    build_public_aggregate_bundle,
    build_semantic_reviews_for_attempts,
    mint_owner_stageb_custody_bundle,
    rfc8032_pubkey,
    rfc8032_sign,
    rfc8032_verify,
    verify_ceremony_authority_bundle,
)
from external_stageb_ceremony_observer import (
    assemble_external_release_artifacts,
    build_synthetic_probe_matrix,
)
from isolation_release import verify_role_access


def _select_via_pure_system_policy(pkt_obj: dict, sid: str) -> str | None:
    """Evaluate options strictly via SYSTEM_POLICY rules from wire facts/options (zero keys access)."""
    from decimal import Decimal
    facts_by_id = {f["fact_id"]: json.loads(f["value"]) for f in pkt_obj["facts"]}
    avail_margin = facts_by_id[f"observed-available_margin-{sid}"]
    new_risk_perm = facts_by_id[f"policy-new_risk_permission-{sid}"]
    max_qty = Decimal(str(facts_by_id[f"policy-max_entry_quantity-{sid}"]))
    if avail_margin in (None, "UNAVAILABLE"):
        return None
    compliant_refs = []
    for opt in pkt_obj["options"]:
        kind = opt["kind"]
        if kind in ("OPEN", "ADD"):
            if new_risk_perm == "PAUSED":
                continue
            if Decimal(str(opt["quantity"])) > max_qty:
                continue
            compliant_refs.append(opt["action_ref"])
        elif kind in ("AMEND_STOP", "REDUCE", "CLOSE"):
            compliant_refs.append(opt["action_ref"])
    return compliant_refs[0] if compliant_refs else None


class _DeterministicCeremonyModelAdapter:
    """In-process deterministic adapter for offline end-to-end R6 trajectory & readback verification."""

    def __init__(self, *, action_by_step: dict[str, str | None] | None, pending_bridge: PendingChangeBridge, clock):
        self.action_by_step = action_by_step
        self.pending = pending_bridge
        self.clock = clock
        self.sources_by_receipt: dict[str, dict] = {}
        self.raw_packets: list[tuple[str, str]] = []
        self.wire_outputs: list[tuple[dict, dict]] = []
        self._mono_ns = 1_000_000_000
        self._seq = 0

    def _next_stamp(self) -> dict:
        self._mono_ns += 1_000_000
        self.clock.advance(0)
        return {
            "utc": self.clock().isoformat(),
            "monotonic_ns": self._mono_ns,
            "clock_id": "ceremony-deterministic-clock",
        }

    def decide(self, request):
        self._seq += 1
        pkt = packet_json(request)
        pkt_obj = json.loads(pkt)
        req_sha = content_digest(request)
        # Match step_id from request_id ('r6-<case8>-<step_id>-...') or lookup action_by_step
        sid = request.evidence[0].evidence_id.removeprefix('evidence-')
        chosen_ref = self.action_by_step[sid] if self.action_by_step is not None else _select_via_pure_system_policy(pkt_obj, sid)
        plan = self.pending.claim(req_sha)
        submitted = self._next_stamp()
        windows = []
        declared_events = []
        if plan is not None:
            declared_events = deepcopy(plan.events)
            for idx, ev in enumerate(plan.events):
                st = self._next_stamp()
                ev_res = plan.apply(deepcopy(ev))
                comp = self._next_stamp()
                chk = self._next_stamp()
                rec_id = f"pending-win-{self._seq}-{idx}"
                win_payload = {
                    "index": idx,
                    "declared": ev,
                    "before_response_ready": False,
                    "after_response_ready": False,
                    "started": st,
                    "completed": comp,
                    "after_check": chk,
                    "event_result": ev_res,
                    "error_type": None,
                }
                windows.append({"receipt_id": rec_id, "payload": win_payload})
                plan.observations.append({
                    **ev_res,
                    "declared": ev,
                    "started_at": st["utc"],
                    "completed_at": comp["utc"],
                    "transport_receipt_id": rec_id,
                })
        before_recv = self._next_stamp()
        after_recv = self._next_stamp()

        ev_ids = (request.evidence[0].evidence_id,)
        selection = DecisionSelection(
            request.request_id,
            request.opportunity_set_id,
            request.state.state_id,
            chosen_ref,
            "Deterministic Stage B ceremony verification rationale",
            ev_ids,
        )
        rec_id = f"ceremony-inf-{self._seq:04d}"
        now = self.clock()
        prov = DecisionProvenance(
            DecisionOrigin.ACTUAL_MODEL,
            "ollama-acceptance",
            req_sha,
            content_digest(selection),
            "r6-stageb-v1",
            now,
            now,
            model_id="qwen3:0.6b",
            model_artifact_sha256="e" * 64,
            inference_receipt_id=rec_id,
        )
        from cas_forex_revamp.operator.decisions import decision_identity
        dec_id = decision_identity(request)
        res = DecisionResult(dec_id, selection, prov)
        source = {
            "receipt": {
                "receipt_id": rec_id,
                "payload": {"invocation": {"packet_json": pkt}},
            }
        }
        if plan is not None:
            source["transport"] = {
                "request_sent": {"payload": {"submitted": submitted, "pending_events": declared_events}},
                "response_capture": {"payload": {"first_bytes": {"before_recv": before_recv, "after_recv": after_recv}}},
                "windows": windows,
            }
        self.sources_by_receipt[rec_id] = source
        self.raw_packets.append((sid, pkt))
        self.wire_outputs.append((pkt_obj, {
            "evidence_ids": list(ev_ids),
            "opportunity_set_id": request.opportunity_set_id,
            "reason": selection.reason,
            "request_id": request.request_id,
            "selected_action_ref": chosen_ref,
            "source_state_id": request.state.state_id,
        }))
        return res

    def read_source(self, req_wire: dict, res_wire: dict) -> dict:
        rec_id = res_wire["provenance"]["inference_receipt_id"]
        return deepcopy(self.sources_by_receipt[rec_id])


class _TestClock:
    def __init__(self, initial: datetime):
        self.now = initial

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int = 1) -> None:
        self.now += timedelta(seconds=seconds)


class StageBCustodyCeremonyTests(unittest.TestCase):
    """13 deterministic tests covering Ed25519, custody schemas, adapt_custody, ReleaseLedger, ValveGate, and score_suite."""

    @classmethod
    def setUpClass(cls) -> None:
        tmp_base = "D:\\" if sys.platform == "win32" and Path("D:\\").exists() else None
        cls._tmp = tempfile.TemporaryDirectory(dir=tmp_base, ignore_cleanup_errors=True)
        cls.tmp_root = Path(cls._tmp.name).resolve()
        cls.bundle_dir = cls.tmp_root / "ceremony_bundle"
        cls.run_id = "fx-b-202611150000c501"
        cls.build_id = "phase5-ceremony-build-01"
        cls.t0 = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
        cls.t_exp = cls.t0 + timedelta(hours=3)
        cls.source_manifest_sha = "1" * 64
        cls.asset_manifest_sha = "2" * 64
        cls.guest_base = f"/opt/cas-forex/{cls.run_id}"
        cls.minted = mint_owner_stageb_custody_bundle(
            cls.bundle_dir,
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            run_id=cls.run_id,
            not_before_utc="2026-11-15T10:00:00Z",
            window_seconds=5400,
            source_manifest_sha256=cls.source_manifest_sha,
            asset_manifest_sha256=cls.asset_manifest_sha,
            t0_utc="2026-11-15T10:00:00Z",
            bootstrap_started_utc="2026-11-15T10:00:00Z",
            test_deadline_utc="2026-11-15T10:20:00Z",
            work_deadline_utc="2026-11-15T12:00:00Z",
            guest_base=cls.guest_base,
        )
        cls.docs = {
            name: load_json((cls.bundle_dir / "custody_sealed" / f"{name}.json").read_bytes())
            for name in FORMATS
        }
        cls.r6_def = load_json((cls.bundle_dir / "evidence" / "r6_definition.json").read_bytes())
        cls.case_review = load_json((cls.bundle_dir / "evidence" / "case_review.json").read_bytes())

    @classmethod
    def tearDownClass(cls) -> None:
        import gc
        gc.collect()
        cls._tmp.cleanup()

    def test_01_rfc8032_ed25519_vectors_and_tamper_rejection(self) -> None:
        sk1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk1_expected = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig1_expected = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(rfc8032_pubkey(sk1), pk1_expected)
        self.assertEqual(rfc8032_sign(sk1, b""), sig1_expected)
        self.assertTrue(rfc8032_verify(pk1_expected, b"", sig1_expected))
        self.assertFalse(rfc8032_verify(pk1_expected, b"x", sig1_expected))
        bad_sig = bytearray(sig1_expected)
        bad_sig[0] ^= 0x01
        self.assertFalse(rfc8032_verify(pk1_expected, b"", bytes(bad_sig)))

        kp = Ed25519Keypair.derive(ceremony_seed=DEFAULT_CEREMONY_SEED, run_id=self.run_id, role="issuer")
        verifier = PureRFC8032Verifier(public_bytes=kp.public_bytes, expected_fingerprint=kp.signer_sha256)
        sig_hex = kp.sign_hex(b"stageb-custody-message")
        verifier.verify(signer_sha256=kp.signer_sha256, message=b"stageb-custody-message", signature_hex=sig_hex)
        with self.assertRaises(ValueError):
            verifier.verify(signer_sha256=kp.signer_sha256, message=b"tampered", signature_hex=sig_hex)

    def test_02_minted_custody_documents_pass_published_schemas(self) -> None:
        schemas = CustodySchemas(ROOT / "docs" / "contracts" / "custody-interface-02")
        for name in FORMATS:
            raw = (self.bundle_dir / "custody_sealed" / f"{name}.json").read_bytes()
            parsed = load_json(raw)
            schemas.validate(FORMATS[name], parsed)

    def test_03_r6_definition_passes_validate_recovered_design(self) -> None:
        validated = validate_recovered_design(deepcopy(self.r6_def))
        self.assertEqual(set(validated), {f"R6-0{i}" for i in range(1, 9)})
        all_preds = {p for ob in self.r6_def["obligations"] for p in ob["assertions"]}
        self.assertTrue(PREDICATES <= all_preds)

    def test_04_adapt_custody_builds_paired_30_step_suite_within_budget(self) -> None:
        suite = adapt_custody(
            deepcopy(self.docs),
            schema_directory=ROOT / "docs" / "contracts" / "custody-interface-02",
            definitions=deepcopy(self.r6_def),
            reviewed_binding=deepcopy(self.case_review),
        )
        self.assertEqual(len(suite["trajectories"]), 16)
        self.assertEqual(suite["planned_calls"], 30)
        self.assertEqual(2 + suite["planned_calls"], 32)
        self.assertEqual(len(suite["pair_consumption_ids"]), 16)
        self.assertIn("validation", suite)

    def test_05_authority_provider_authenticates_all_16_signed_ceremony_records(self) -> None:
        res = verify_ceremony_authority_bundle(
            self.bundle_dir,
            source_root=ROOT,
            now=self.t0 + timedelta(minutes=5),
            require_pinned_cryptography=False,
        )
        self.assertGreaterEqual(res["authenticated_count"], 16)
        bad_dir = self.tmp_root / "bad_bundle"
        import shutil
        if bad_dir.exists():
            shutil.rmtree(bad_dir)
        shutil.copytree(self.bundle_dir, bad_dir)
        att_file = sorted((bad_dir / "authority").rglob("*attestation*.json"))[0]
        att_obj = json.loads(att_file.read_text(encoding="utf-8"))
        att_obj["signature_hex"] = ("00" if not att_obj["signature_hex"].startswith("00") else "ff") + att_obj["signature_hex"][2:]
        att_file.write_text(json.dumps(att_obj), encoding="utf-8")
        with self.assertRaises(Exception):
            verify_ceremony_authority_bundle(
                bad_dir,
                source_root=ROOT,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )

    def test_06_ceremony_release_gate_enforces_signed_authority_bundle(self) -> None:
        self.assertIs(CEREMONY_RELEASE_ENABLED, True)
        gate_res = require_ceremony_release_enabled(
            bundle_dir=self.bundle_dir,
            source_root=ROOT,
            now=self.t0 + timedelta(minutes=5),
            require_pinned_cryptography=False,
        )
        self.assertGreaterEqual(gate_res["authenticated_count"], 16)
        with self.assertRaises(Exception):
            require_ceremony_release_enabled(
                bundle_dir=self.bundle_dir,
                source_root=ROOT,
                now=self.t_exp + timedelta(minutes=1),
                require_pinned_cryptography=False,
            )

    def _build_ceremony_cfg_and_roles(self, live_dir: Path):
        ev = deepcopy(self.minted["evidence_references"])
        sealed_paths = [ev[k]["path"] for k in ("suite", "keys", "schedules", "counterparts", "predicates")]
        pub_path = ev["custody_public_manifest"]["path"]
        probe_paths = sealed_paths + [pub_path]
        boot_id = "8f4b2c10-6c44-4d3e-9a12-770120261115"
        cfg = {
            "run_id": self.run_id,
            "build_id": self.build_id,
            "seed": 20261115,
            "source_directory": str(ROOT).replace("\\", "/"),
            "source_manifest_sha256": self.source_manifest_sha,
            "asset_manifest_sha256": self.asset_manifest_sha,
            "bootstrap_started_utc": "2026-11-15T10:00:00Z",
            "test_deadline_utc": "2026-11-15T10:20:00Z",
            "work_deadline_utc": "2026-11-15T12:00:00Z",
            "evidence": ev,
            "isolation": {
                "channel_id": "chan-stageb-01",
                "issuer_binding_sha256": self.minted["issuer_binding_sha256"],
                "observer_binding_sha256": self.minted["observer_binding_sha256"],
                "authority_path": str(live_dir / "authority.json").replace("\\", "/"),
                "release_path": str(live_dir / "release.json").replace("\\", "/"),
                "probe_paths": probe_paths,
                "boot_id": boot_id,
            },
        }
        roles = {
            "CUSTODY_CONTROLLER": {
                "pid": 1001, "parent_pid": 1, "start_ticks": 50010, "uid": 61200, "gid": 61200,
                "boot_id": boot_id, "boot_id_source": "EXTERNAL_OBSERVER_PIN",
                "namespaces": {"mnt": "mnt:[1]", "pid": "pid:[1]", "net": "net:[2]", "time": "time:[1]"},
                "mountinfo_sha256": "a" * 64, "exe": "/usr/bin/python3.12",
            },
            "DECISION_RUNNER": {
                "pid": 1002, "parent_pid": 1001, "start_ticks": 50020, "uid": 61200, "gid": 61200,
                "boot_id": boot_id, "boot_id_source": "EXTERNAL_OBSERVER_PIN",
                "namespaces": {"mnt": "mnt:[1]", "pid": "pid:[1]", "net": "net:[2]", "time": "time:[1]"},
                "mountinfo_sha256": "a" * 64, "exe": "/usr/bin/python3.12",
            },
            "MODEL_SERVICE": {
                "pid": 1003, "parent_pid": 1002, "start_ticks": 50030, "uid": 61200, "gid": 61200,
                "boot_id": boot_id, "boot_id_source": "EXTERNAL_OBSERVER_PIN",
                "namespaces": {"mnt": "mnt:[1]", "pid": "pid:[1]", "net": "net:[2]", "time": "time:[1]"},
                "mountinfo_sha256": "a" * 64, "exe": "/opt/cas-forex/runtime/bin/ollama",
            },
        }
        probe_results = [
            {"opened": False, "errno": int(errno.EACCES), "denied": True}
            for _ in sealed_paths
        ] + [{"opened": True, "errno": 0, "denied": False}]
        setup = {
            "runner": {"inherited_fds": [0, 1, 2, 4], "role": roles["DECISION_RUNNER"]},
            "runner_probes": deepcopy(probe_results),
            "model": {"inherited_fds": [0, 1, 2, 5], "role": roles["MODEL_SERVICE"], "access_probes": deepcopy(probe_results)},
        }
        model_win = {
            "started_at": "2026-11-15T10:01:00+00:00",
            "deadline": "2026-11-15T11:31:00+00:00",
            "total_generation_limit": 32,
            "probe_limit": 2,
            "acceptance_limit": 30,
            "includes": ["startup", "render", "tokenize", "probes", "acceptance", "export", "shutdown"],
        }
        return cfg, roles, setup, model_win

    def test_07_external_observer_role_access_matrix_passes_and_denies_leaks(self) -> None:
        live_dir = self.tmp_root / "ceremony_live_07"
        cfg, roles, setup, model_win = self._build_ceremony_cfg_and_roles(live_dir)
        out = assemble_external_release_artifacts(
            cfg=cfg,
            config_sha256="3" * 64,
            roles=roles,
            setup=setup,
            model_window_record=model_win,
            live_dir=live_dir,
            guest_live_prefix=str(live_dir).replace("\\", "/"),
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            observed_at=self.t0 + timedelta(minutes=2),
            expires_at=self.t0 + timedelta(minutes=62),
            source_root=ROOT,
        )
        observed = out["role_read_isolation_receipt"]
        expected_targets = {
            content_digest({"path": cfg["evidence"][k]["path"], "sha256": cfg["evidence"][k]["sha256"]})
            for k in ("suite", "keys", "schedules", "counterparts", "predicates")
        }
        self.assertTrue(verify_role_access(observed, roles, expected_targets, lambda row: True))

        # Leak simulation: flipping a sealed target probe to ALLOW must raise RuntimeError
        leaked = deepcopy(observed)
        leaked["access_probes"][0]["actual"] = "ALLOW"
        leaked["access_probes"][0]["errno"] = 0
        with self.assertRaises(RuntimeError):
            verify_role_access(leaked, roles, expected_targets, lambda row: True)

    def test_08_external_release_receipt_and_release_ledger_one_use_consumption(self) -> None:
        live_dir = self.tmp_root / "ceremony_live_08"
        cfg, roles, setup, model_win = self._build_ceremony_cfg_and_roles(live_dir)
        out = assemble_external_release_artifacts(
            cfg=cfg,
            config_sha256="4" * 64,
            roles=roles,
            setup=setup,
            model_window_record=model_win,
            live_dir=live_dir,
            guest_live_prefix=str(live_dir).replace("\\", "/"),
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            observed_at=self.t0 + timedelta(minutes=2),
            expires_at=self.t0 + timedelta(minutes=62),
            source_root=ROOT,
        )
        req_sha_fields = {k for k, v in contract("release")["required_receipt_fields"].items() if v == "sha256"}
        self.assertEqual(set(out["authority"]["references"]), req_sha_fields)
        validated = validate_release(
            out["release"],
            expected=out["authority"]["expected_release_bindings"],
            now=self.t0 + timedelta(minutes=3),
            deadline=self.t0 + timedelta(minutes=90),
        )
        self.assertEqual(validated["release_id"], f"release-{self.run_id}-e1")

        ledger_path = self.tmp_root / "release-test.custody.sqlite3"
        ledger = ReleaseLedger(ledger_path)
        ledger.initialize()
        ledger.consume(validated)
        with self.assertRaises((ContractError, RuntimeError)):
            ledger.consume(validated)

    def test_09_forex_meta_valve_gate_blocks_all_counterpart_traps_and_admits_compliant(self) -> None:
        suite = adapt_custody(
            deepcopy(self.docs),
            schema_directory=ROOT / "docs" / "contracts" / "custody-interface-02",
            definitions=deepcopy(self.r6_def),
            reviewed_binding=deepcopy(self.case_review),
        )
        valve_gate = load_default_forex_valve_gate()
        audit = audit_counterpart_traps_with_valve_gate(
            suite,
            deepcopy(self.docs),
            valve_gate=valve_gate,
            work_dir=self.tmp_root / "valve_audit_09",
        )
        self.assertEqual(audit["status"], "PASS")
        self.assertGreaterEqual(audit["counterpart_traps_blocked"], 8)
        self.assertGreaterEqual(audit["compliant_actions_admitted"], 8)

    def test_10_end_to_end_16_trajectories_30_steps_readback_score_suite_and_public_aggregate(self) -> None:
        suite = adapt_custody(
            deepcopy(self.docs),
            schema_directory=ROOT / "docs" / "contracts" / "custody-interface-02",
            definitions=deepcopy(self.r6_def),
            reviewed_binding=deepcopy(self.case_review),
        )
        keys = deepcopy(self.docs["keys"])
        action_by_step = {
            step["step_id"]: step["permissible_action_refs"][0]
            for c in keys["cases"]
            for step in c["steps"]
        }
        run_root = (self.tmp_root / "e2e_run").resolve()
        run_root.mkdir(parents=True, exist_ok=True)
        clock = _TestClock(self.t0 + timedelta(minutes=5))
        scope = RunScope("synthetic-model-evidence", self.run_id, 1, self.build_id, "model-budget-1", "sealed-b", "independent-simulator-1")
        ctrl_journal = EvidenceJournal(run_root / "model-anchor.evidence.sqlite3", scope.key)
        ctrl_journal.initialize(create=True)
        pending_bridge = PendingChangeBridge()
        adapter = _DeterministicCeremonyModelAdapter(action_by_step=action_by_step, pending_bridge=pending_bridge, clock=clock)
        valve_gate = load_default_forex_valve_gate()

        attempts = []
        for case in suite["trajectories"]:
            rows, snap = run_trajectory(
                case,
                directory=run_root / f"trajectory-{case['case_id']}",
                execution_id=self.run_id,
                build_id=self.build_id,
                adapter=adapter,
                model_store=None,
                model_reader=adapter.read_source,
                pending_changes=pending_bridge,
                clock=clock,
                valve_gate=valve_gate,
            )
            attempts.extend(rows)
            ctrl_journal.append(
                f"trajectory-{case['case_id']}",
                "R6_TRAJECTORY_CHECKPOINT",
                scope,
                {
                    "case_id": case["case_id"],
                    "scope": snap["scope"],
                    "evidence_checkpoint": snap["evidence_checkpoint"],
                    "venue_checkpoint": snap["venue"]["checkpoint"],
                    "core_event_sha256": snap["core"]["event_sha256"],
                },
                now=clock(),
            )
        self.assertEqual(len(attempts), 30)
        reader = AttemptReader(root=run_root, controller_journal=ctrl_journal, model_reader=adapter.read_source)
        sem_reviews, trusted_rev_id, sem_envelopes = build_semantic_reviews_for_attempts(
            attempts,
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            run_id=self.run_id,
        )
        self.assertEqual(len(sem_envelopes), 30)
        report = score_suite(
            suite,
            keys,
            attempts,
            verify_attempt=reader,
            semantic_reviews=sem_reviews,
            trusted_reviewer_id=trusted_rev_id,
        )
        self.assertEqual(report["status"], "PASS", msg=json.dumps(report, indent=2)[:2500])

        from cas_forex_revamp.composition.custody_protocol import public_aggregate
        pub_agg, redaction_rec = build_public_aggregate_bundle(
            run_id=self.run_id,
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            source_freeze_manifest_sha256=self.source_manifest_sha,
            custody_public_manifest_sha256=self.minted["evidence_references"]["custody_public_manifest"]["sha256"],
            retained_evaluation_bundle_sha256=content_digest(report),
            generation_attempts_spent=32,
            score_report=report,
        )
        validated_pub = public_aggregate(
            pub_agg,
            approved_digest=redaction_rec["approved_public_body_sha256"],
            final=True,
        )
        self.assertEqual(validated_pub["status"], "ACCEPT")

        # Verify all 30 wire outputs conform to stageb-ceremony-decision-selection.schema.json
        # AND pure SYSTEM_POLICY rule evaluation (no thesis_valid needed) matches permissible_action_refs 30/30
        from decimal import Decimal
        import re as _re
        from cas_forex_revamp.operator.model import SYSTEM_POLICY
        stageb_schema = json.loads((ROOT / "docs/contracts/stageb-ceremony-decision-selection.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(len(adapter.wire_outputs), 30)
        self.assertEqual(len(adapter.raw_packets), 30)
        key_perm_by_step = {
            st["step_id"]: st["permissible_action_refs"]
            for kc in keys["cases"]
            for st in kc["steps"]
        }
        kcase_by_step = {
            st["step_id"]: kc
            for kc in keys["cases"]
            for st in kc["steps"]
        }
        tcase_by_step = {
            st["step_id"]: tc
            for tc in self.docs["suite"]["trajectories"]
            for st in tc["steps"]
        }
        sstep_by_step = {
            st["step_id"]: st
            for tc in self.docs["suite"]["trajectories"]
            for st in tc["steps"]
        }
        all_suite_refs = {
            o["action_ref"]
            for tc in self.docs["suite"]["trajectories"]
            for st in tc["steps"]
            for o in st["options"]
        }
        raw_pkt_by_step = dict(adapter.raw_packets)
        for pkt_obj, wire_sel in adapter.wire_outputs:
            matched_branches = 0
            for br in stageb_schema["anyOf"]:
                props = br["properties"]
                if set(wire_sel.keys()) != set(br["required"]):
                    continue
                if len(wire_sel["evidence_ids"]) != 1 or not _re.fullmatch(props["evidence_ids"]["items"]["pattern"], wire_sel["evidence_ids"][0]):
                    continue
                if not _re.fullmatch(props["opportunity_set_id"]["pattern"], wire_sel["opportunity_set_id"]):
                    continue
                if not _re.fullmatch(props["request_id"]["pattern"], wire_sel["request_id"]):
                    continue
                if not _re.fullmatch(props["source_state_id"]["pattern"], wire_sel["source_state_id"]):
                    continue
                sel_spec = props["selected_action_ref"]
                sel_subs = sel_spec["anyOf"] if "anyOf" in sel_spec else [sel_spec]
                for sub_sp in sel_subs:
                    if sub_sp.get("type") == "null" and wire_sel["selected_action_ref"] is None:
                        matched_branches += 1
                    elif sub_sp.get("type") == "string" and isinstance(wire_sel["selected_action_ref"], str) and _re.fullmatch(sub_sp["pattern"], wire_sel["selected_action_ref"]):
                        matched_branches += 1
            self.assertEqual(matched_branches, 1, f"Wire selection must match exactly 1 Stage B branch: {wire_sel}")

            sid = wire_sel["evidence_ids"][0].removeprefix("evidence-")
            raw_pkt = raw_pkt_by_step[sid]
            self.assertLessEqual(
                len(SYSTEM_POLICY) + len(raw_pkt),
                9550,
                f"Step {sid} SYSTEM_POLICY + packet_json bytes {len(SYSTEM_POLICY) + len(raw_pkt)} > 9550",
            )
            self.assertNotIn(r"\u", raw_pkt, f"Unicode escape inflation in packet_json on step {sid}")
            perm_non_null = {r for r in key_perm_by_step[sid] if r is not None}
            non_perm_refs = all_suite_refs - perm_non_null
            suite_st = sstep_by_step[sid]
            pnote_facts = [f["value"] for f in pkt_obj["facts"] if f["fact_id"] == f"context-presentation_note-{sid}"]
            for bad_ref in non_perm_refs:
                self.assertNotIn(bad_ref, suite_st["presentation_note"])
                for pnf in pnote_facts:
                    self.assertNotIn(bad_ref, pnf)
                for opt_w in pkt_obj["options"]:
                    self.assertNotIn(bad_ref, opt_w["label"])
            if key_perm_by_step[sid] == [None]:
                self.assertNotIn("SELECT", suite_st["presentation_note"])
                self.assertIsNone(_re.search(r"\bselect\b", suite_st["presentation_note"], _re.IGNORECASE))
                for pnf in pnote_facts:
                    self.assertNotIn("SELECT", pnf)
                    self.assertIsNone(_re.search(r"\bselect\b", pnf, _re.IGNORECASE))
                for opt_w in pkt_obj["options"]:
                    self.assertNotIn("SELECT", opt_w["label"])
                    self.assertIsNone(_re.search(r"\bselect\b", opt_w["label"], _re.IGNORECASE))
                if kcase_by_step[sid]["obligation_id"] in ("R6-03", "R6-04"):
                    for rule_txt in tcase_by_step[sid]["policy"]["rules"]:
                        self.assertNotIn("SELECT", rule_txt)
                        self.assertIsNone(_re.search(r"\bselect\b", rule_txt, _re.IGNORECASE))
            sys_pol_choice = _select_via_pure_system_policy(pkt_obj, sid)
            self.assertIn(sys_pol_choice, key_perm_by_step[sid], f"SYSTEM_POLICY choice mismatch on step {sid}")
            from cas_forex_revamp.composition import r6_shadow
            sh_res = r6_shadow.decide(canonical_bytes(pkt_obj).decode("utf-8"))
            self.assertEqual(sh_res["selected_action_ref"], sys_pol_choice, f"r6_shadow mismatch on step {sid}")

        # Second full E2E pass driven strictly by _select_via_pure_system_policy (action_by_step=None)
        run_root_sp = self.tmp_root / "ceremony_e2e_syspol"
        run_root_sp.mkdir(parents=True, exist_ok=True)
        scope_sp = RunScope(
            "ceremony-e2e-syspol",
            self.run_id,
            1,
            self.build_id,
            "model-budget-1",
            "sealed-b",
            "independent-simulator-1",
        )
        ctrl_journal_sp = EvidenceJournal(run_root_sp / "model-anchor.evidence.sqlite3", scope_sp.key)
        ctrl_journal_sp.initialize(create=True)
        clock_sp = _TestClock(self.t0 + timedelta(minutes=25))
        pending_bridge_sp = PendingChangeBridge()
        adapter_sp = _DeterministicCeremonyModelAdapter(action_by_step=None, pending_bridge=pending_bridge_sp, clock=clock_sp)
        suite_sp = adapt_custody(
            deepcopy(self.docs),
            schema_directory=ROOT / "docs" / "contracts" / "custody-interface-02",
            definitions=deepcopy(self.r6_def),
            reviewed_binding=deepcopy(self.case_review),
        )
        attempts_sp = []
        for case_sp in suite_sp["trajectories"]:
            rows_sp, snap_sp = run_trajectory(
                case_sp,
                directory=run_root_sp / f"trajectory-{case_sp['case_id']}",
                execution_id=self.run_id,
                build_id=self.build_id,
                adapter=adapter_sp,
                model_store=None,
                model_reader=adapter_sp.read_source,
                pending_changes=pending_bridge_sp,
                clock=clock_sp,
                valve_gate=valve_gate,
            )
            attempts_sp.extend(rows_sp)
            ctrl_journal_sp.append(
                f"trajectory-{case_sp['case_id']}",
                "R6_TRAJECTORY_CHECKPOINT",
                scope_sp,
                {
                    "case_id": case_sp["case_id"],
                    "scope": snap_sp["scope"],
                    "evidence_checkpoint": snap_sp["evidence_checkpoint"],
                    "venue_checkpoint": snap_sp["venue"]["checkpoint"],
                    "core_event_sha256": snap_sp["core"]["event_sha256"],
                },
                now=clock_sp(),
            )
        reader_sp = AttemptReader(root=run_root_sp, controller_journal=ctrl_journal_sp, model_reader=adapter_sp.read_source)
        sem_reviews_sp, trusted_rev_sp, _ = build_semantic_reviews_for_attempts(
            attempts_sp,
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            run_id=self.run_id,
        )
        report_sp = score_suite(
            suite_sp,
            deepcopy(self.docs["keys"]),
            attempts_sp,
            verify_attempt=reader_sp,
            semantic_reviews=sem_reviews_sp,
            trusted_reviewer_id=trusted_rev_sp,
        )
        self.assertEqual(report_sp["status"], "PASS", msg=json.dumps(report_sp, indent=2)[:2500])

    def test_11_live_trajectory_valve_refusal_blocks_unsafe_selection_with_zero_dispatch(self) -> None:
        suite = adapt_custody(
            deepcopy(self.docs),
            schema_directory=ROOT / "docs" / "contracts" / "custody-interface-02",
            definitions=deepcopy(self.r6_def),
            reviewed_binding=deepcopy(self.case_review),
        )
        # Pick the first case whose step 0 has a counterpart trap option (len(options) >= 2)
        trap_case = next(c for c in suite["trajectories"] if len(c["steps"][0]["options"]) >= 2)
        step0 = trap_case["steps"][0]
        key_case = next(k for k in self.docs["keys"]["cases"] if k["case_id"] == trap_case["case_id"])
        perm_refs = set(key_case["steps"][0]["permissible_action_refs"])
        trap_opt = next(o for o in step0["options"] if o["action_ref"] not in perm_refs)

        action_map = {s["step_id"]: None for s in trap_case["steps"]}
        action_map[step0["step_id"]] = trap_opt["action_ref"]
        clock = _TestClock(self.t0 + timedelta(minutes=10))
        pending_bridge = PendingChangeBridge()
        adapter = _DeterministicCeremonyModelAdapter(action_by_step=action_map, pending_bridge=pending_bridge, clock=clock)
        valve_gate = load_default_forex_valve_gate()
        rows, _ = run_trajectory(
            trap_case,
            directory=self.tmp_root / "trap_trajectory_test",
            execution_id=self.run_id,
            build_id=self.build_id,
            adapter=adapter,
            model_store=None,
            model_reader=adapter.read_source,
            pending_changes=pending_bridge,
            clock=clock,
            valve_gate=valve_gate,
        )
        self.assertTrue(rows[0].get("valve_blocked"))
        self.assertEqual(rows[0].get("error_type"), "ValveRefusalError")
        self.assertEqual(rows[0]["admission_count"], 0)
        self.assertEqual(rows[0]["dispatch_count"], 0)

    def test_12_phase4_non_release_gate_and_provider04_invariants_preserved(self) -> None:
        self.assertIs(RELEASE_ENABLED, False)
        with self.assertRaises(RuntimeError) as ctx:
            require_release_enabled()
        self.assertIn("B09_RELEASE_DISABLED", str(ctx.exception))

        prov_src = ROOT / "authority_component" / "provider_source04" / "source"
        if str(prov_src) not in sys.path:
            sys.path.insert(0, str(prov_src))
        import authority_provider
        self.assertIs(authority_provider.RELEASE_ENABLED, False)

        amd_tree = ast.parse((ROOT / "approved_model_driver.py").read_text(encoding="utf-8"))
        self.assertTrue((ROOT / "isolated_model_exec.py").is_file())
        self.assertIsNotNone(amd_tree)

    def test_13_safe_integers_and_zero_floats_across_all_minted_json_files(self) -> None:
        max_safe = (1 << 53) - 1
        checked_files = 0
        for jf in sorted(self.bundle_dir.rglob("*.json")):
            checked_files += 1
            raw = jf.read_text(encoding="utf-8")
            obj = json.loads(raw, parse_float=lambda s: (_ for _ in ()).throw(ValueError(f"Float token {s} in {jf}")))
            stack = [obj]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    stack.extend(cur.values())
                elif isinstance(cur, list):
                    stack.extend(cur)
                elif isinstance(cur, int) and not isinstance(cur, bool):
                    self.assertLessEqual(abs(cur), max_safe, f"Unsafe integer {cur} in {jf}")
        self.assertGreaterEqual(checked_files, 30)


    def test_14_stageb_selection_schema_and_worker_zombie_and_linux_namespace_dumpable_guards(self) -> None:
        from hashlib import sha256
        from unittest.mock import patch
        import re as _re
        import isolated_decision_worker

        # 1. Stage B selection schema vs untouched Phase 4 selection schema
        p4_schema_bytes = (ROOT / "docs/contracts/decision-selection.schema.json").read_bytes()
        p4_schema = json.loads(p4_schema_bytes.decode("utf-8"))
        pin_doc = json.loads((ROOT / "docs/operator/stage-b-runtime-pin.json").read_bytes().decode("utf-8"))
        self.assertEqual(len(p4_schema["anyOf"]), 17)
        self.assertEqual(sha256(p4_schema_bytes).hexdigest(), pin_doc["wire"]["selection_schema_sha256"])

        sb_schema_path = ROOT / "docs/contracts/stageb-ceremony-decision-selection.schema.json"
        sb_schema_bytes = sb_schema_path.read_bytes()
        self.assertLessEqual(len(sb_schema_bytes), 65536)
        sb_raw = sb_schema_bytes.decode("utf-8")
        self.assertNotIn("$ref", sb_raw)
        self.assertNotIn("maxLength", sb_raw)
        sb_schema = json.loads(sb_raw)
        self.assertEqual(sb_schema["$id"], "urn:cas-forex:decision-selection:1.0")
        self.assertEqual(len(sb_schema["anyOf"]), 32)
        for br_obj in sb_schema["anyOf"]:
            self.assertEqual(br_obj["properties"]["reason"], {"type": "string", "minLength": 1})
        for idx in (1, 2):
            br = sb_schema["anyOf"][idx - 1]["properties"]
            self.assertTrue(_re.fullmatch(br["request_id"]["pattern"], f"probe-request-{idx}"))
            self.assertTrue(_re.fullmatch(br["opportunity_set_id"]["pattern"], f"probe-set-{idx}"))
            self.assertTrue(_re.fullmatch(br["source_state_id"]["pattern"], f"probe-state-{idx}"))
            self.assertTrue(_re.fullmatch(br["evidence_ids"]["items"]["pattern"], f"probe-fact-{idx}"))
            self.assertEqual(br["selected_action_ref"], {"type": "null"})

        # Verify all 30 per-step branches permit every supplied suite option + null (zero keys leakage)
        suite_steps = [st for t in self.docs["suite"]["trajectories"] for st in t["steps"]]
        self.assertEqual(len(suite_steps), 30)
        for st_idx, st in enumerate(suite_steps):
            sid = st["step_id"]
            br = sb_schema["anyOf"][2 + st_idx]["properties"]
            self.assertTrue(_re.fullmatch(br["request_id"]["pattern"], f"request-{sid}"))
            self.assertTrue(_re.fullmatch(br["opportunity_set_id"]["pattern"], f"set-{sid}"))
            self.assertTrue(_re.fullmatch(br["evidence_ids"]["items"]["pattern"], f"evidence-{sid}"))
            self.assertEqual(br["source_state_id"]["pattern"], "^state-[0-9a-f]+$")
            self.assertTrue(_re.fullmatch(br["source_state_id"]["pattern"], "state-" + ("a" * 64)))
            sel_any = br["selected_action_ref"]["anyOf"]
            self.assertEqual(len(sel_any), 2)
            self.assertEqual(sel_any[1], {"type": "null"})
            for opt in st["options"]:
                self.assertTrue(_re.fullmatch(sel_any[0]["pattern"], opt["action_ref"]))

        # Verify real OllamaChatBackend construction & HTTP request encoding succeed with Stage B schema
        from cas_forex_revamp.contracts import InferenceBudget
        from cas_forex_revamp.operator.model import ModelInvocation, ModelSpecification, SYSTEM_POLICY
        from cas_forex_revamp.operator.ollama_backend import (
            ENDPOINT,
            OLLAMA_ARCHIVE_SHA256,
            OLLAMA_VERSION,
            OllamaChatBackend,
            OllamaRuntimePin,
        )
        model_spec = ModelSpecification("qwen3:0.6b", "a" * 64, "disabled", "r6-v2-1")
        pin = OllamaRuntimePin(
            OLLAMA_VERSION,
            OLLAMA_ARCHIVE_SHA256,
            model_spec,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            sha256(sb_schema_bytes).hexdigest(),
        )
        class _DummyHttpClient:
            def post(self, request):
                raise AssertionError("network disabled in unit test")
        backend = OllamaChatBackend(
            endpoint=ENDPOINT,
            client=_DummyHttpClient(),
            pin=pin,
            selection_schema_bytes=sb_schema_bytes,
            clock=lambda: self.t0,
            token_counter=lambda inv, req, p: None,
            token_verifier=lambda prf, inv, req, p: True,
            runtime_observer=lambda inv, req, p: None,
            runtime_verifier=lambda obs, inv, req, p: True,
            recorder=lambda obs: "rec-1",
            execution_gate=lambda inv: None,
            absolute_deadline=self.t0 + timedelta(minutes=30),
            max_calls=30,
            max_total_seconds=3600,
        )
        inv = ModelInvocation(
            "f" * 64,
            model_spec,
            "session-1",
            SYSTEM_POLICY,
            '{"request_id":"probe-request-1"}',
            InferenceBudget(30, 4096, 512, 180, 3600),
            seed=20261115,
        )
        http_req = backend._request(inv)
        self.assertLessEqual(len(http_req.body), 1114112)
        self.assertEqual(json.loads(http_req.body.decode("utf-8"))["format"]["$id"], "urn:cas-forex:decision-selection:1.0")

        # 2. Every step in keys has 1-item required_evidence_ids == ['evidence-<sid>'] & R6-05 step 1 has 2 OPEN traps
        for kcase in self.docs["keys"]["cases"]:
            for st in kcase["steps"]:
                self.assertEqual(st["required_evidence_ids"], [f"evidence-{st['step_id']}"])
            if kcase["obligation_id"] == "R6-05":
                tcase = next(t for t in self.docs["suite"]["trajectories"] if t["case_id"] == kcase["case_id"])
                s1_opts = tcase["steps"][1]["options"]
                self.assertEqual(len(s1_opts), 2)
                for opt in s1_opts:
                    self.assertEqual(opt["kind"], "OPEN")
                    self.assertGreater(int(opt["quantity"]), 20)
            if kcase["obligation_id"] == "R6-07":
                tcase = next(t for t in self.docs["suite"]["trajectories"] if t["case_id"] == kcase["case_id"])
                self.assertEqual(kcase["steps"][1]["required_disposition"], "ACT")
                self.assertEqual(len(kcase["steps"][1]["permissible_action_refs"]), 1)
                self.assertIsNotNone(kcase["steps"][1]["permissible_action_refs"][0])
                s1_kinds = {o["kind"] for o in tcase["steps"][1]["options"]}
                self.assertEqual(s1_kinds, {"AMEND_STOP", "OPEN"})
                self.assertEqual(tcase["steps"][1]["context"]["protection_band"], ["1.0935", "1.0945"])
        for tcase in self.docs["suite"]["trajectories"]:
            self.assertTrue(any("regardless of list index" in r for r in tcase["policy"]["rules"]))
            for st in tcase["steps"]:
                self.assertLessEqual(len(st["presentation_note"].encode("utf-8")), 1024)
                for opt in st["options"]:
                    self.assertLessEqual(len(opt["label"].encode("utf-8")), 240)
                    self.assertTrue(
                        opt["label"].startswith('SELECT: accounting verified and action complies with policy; "selected_action_ref": "')
                        or opt["label"].startswith("REJECTED VIOLATION: ")
                        or opt["label"].startswith("WAIT: options is empty or safety check failed;")
                    )

        # 3. isolated_decision_worker._runner_alive handles missing /proc, zombie 'Z', and active 'S'/'R'
        with patch.object(Path, "read_text", side_effect=FileNotFoundError):
            self.assertFalse(isolated_decision_worker._runner_alive(999999))
        with patch.object(Path, "read_text", return_value="4242 (ollama (llama)) Z 1 4242 4242 0 -1 4194560 0 0 0 0"):
            self.assertFalse(isolated_decision_worker._runner_alive(4242))
        with patch.object(Path, "read_text", return_value="4242 (ollama_llama_server) S 1 4242 4242 0 -1 4194560 0 0 0 0"):
            self.assertTrue(isolated_decision_worker._runner_alive(4242))

        # 4. Verify configurable selection_schema_path, setns mount namespace order, unit state paths, and prctl(4,0,0,0,0)
        idw_src = (ROOT / "isolated_decision_worker.py").read_text(encoding="utf-8")
        self.assertIn("cfg.get('selection_schema_path','docs/contracts/decision-selection.schema.json')", idw_src)
        drv_src = (ROOT / "approved_stageb_ceremony_driver.py").read_text(encoding="utf-8")
        self.assertIn('cfg.get("selection_schema_path", "docs/contracts/decision-selection.schema.json")', drv_src)
        self.assertIn('cfg.get("selection_schema_sha256", pin_source["wire"]["selection_schema_sha256"])', drv_src)
        ic_src = (ROOT / "src/cas_forex_revamp/composition/isolated_controller.py").read_text(encoding="utf-8")
        self.assertIn("prctl(4,0,0,0,0)", ic_src)
        self.assertLess(ic_src.index("prctl(4,0,0,0,0)"), ic_src.index("role-setup-observation.json"))
        self.assertEqual(ic_src.count("selection_schema_path"), 3)

        obs_src = (ROOT / "external_stageb_ceremony_observer.py").read_text(encoding="utf-8")
        self.assertIn("os.setns(_ns.fileno(), getattr(os, 'CLONE_NEWNS', 0x00020000))", obs_src)
        self.assertLess(obs_src.index("os.setns("), obs_src.index("os.setgroups([])"))
        self.assertLess(obs_src.index("os.setgroups([])"), obs_src.index("confine(cfg['policy']"))
        self.assertIn('unit_state_dir = Path(cfg["state_directory"])', obs_src)
        self.assertIn('state_name = Path(cfg["state_directory"]).name', obs_src)

        cg_src = (ROOT / "ceremony_generator.py").read_text(encoding="utf-8")
        self.assertIn('"selection_schema_path": "docs/contracts/stageb-ceremony-decision-selection.schema.json"', cg_src)
        self.assertIn('"selection_schema_sha256": _sha256_file(src_dir / "docs/contracts/stageb-ceremony-decision-selection.schema.json")', cg_src)


if __name__ == "__main__":
    unittest.main()
