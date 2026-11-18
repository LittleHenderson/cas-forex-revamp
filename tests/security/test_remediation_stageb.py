"""Security regression tests for Stage B Ceremony remediations [1], [2], and [7]."""
from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from authority_component.ceremony_release_gate import require_ceremony_release_enabled
from cas_forex_revamp.contracts import RunScope, content_digest
from cas_forex_revamp.composition.continuous_model_driver_v2 import run_trajectory
from cas_forex_revamp.composition.custody_adapter import FORMATS, adapt_custody
from cas_forex_revamp.composition.custody_schema import load_json
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from cas_forex_revamp.composition.generation_transport import PendingChangeBridge
from cas_forex_revamp.composition.r6_readback import AttemptReader
from cas_forex_revamp.composition.r6_reason import evaluate_evidence_grounded_reason, semantic_result
from cas_forex_revamp.composition.r6_scoring import score_suite
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from ceremony_generator import (
    CEREMONY_ROLES,
    DEFAULT_CEREMONY_SEED,
    Ed25519Keypair,
    _cleanup_partial_tree,
    _materialize_regular_tree,
    apply_verified_directory_mode,
    apply_verified_regular_file_mode,
    build_semantic_reviews_for_attempts,
    canonical_json_bytes,
    canonical_sha256,
    mint_rehearsal_stageb_custody_bundle,
    mint_owner_stageb_custody_bundle,
    render_stageb_selection_schema_bytes,
    sign_attestation_record,
    verify_ceremony_authority_bundle,
)
from external_stageb_ceremony_observer import assemble_external_release_artifacts
from tests.phase5.test_stageb_custody_ceremony import _DeterministicCeremonyModelAdapter, _TestClock

EXPECTED_STAGEB_SCHEMA_SHA256 = "ace43a47b6b78a79df5329f5b7c995fbfb48be1293c5258940ef8ad7b33b9e5a"


def _create_dir_link_or_junction(target_dir: Path, link_path: Path) -> None:
    try:
        os.symlink(target_dir, link_path, target_is_directory=True)
    except OSError:
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link_path), str(target_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            raise


class StageBSecurityRemediationTests(unittest.TestCase):
    """Mandatory regression suite for Stage B security findings [1], [2], and [7] (0 skips)."""

    @classmethod
    def setUpClass(cls) -> None:
        tmp_base = "D:\\" if sys.platform == "win32" and Path("D:\\").exists() else None
        cls._tmp = tempfile.TemporaryDirectory(dir=tmp_base, ignore_cleanup_errors=True)
        cls.tmp_root = Path(cls._tmp.name).resolve()
        cls.run_id = "fx-b-2026111600005ec1"
        cls.build_id = "phase6-sec-stageb-01"
        cls.t0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)

        cls.bundle_dir = cls.tmp_root / "valid_bundle"
        cls.vault_dir = cls.tmp_root / "external_vault"
        cls.trust_roots_path = cls.tmp_root / "pinned_trust_roots.json"
        cls.minted = mint_rehearsal_stageb_custody_bundle(
            cls.bundle_dir,
            ceremony_seed=DEFAULT_CEREMONY_SEED,
            run_id=cls.run_id,
            not_before_utc="2026-11-16T12:00:00Z",
            window_seconds=5400,
            source_manifest_sha256="1" * 64,
            asset_manifest_sha256="2" * 64,
            config_sha256="3" * 64,
            t0_utc="2026-11-16T12:00:00Z",
            bootstrap_started_utc="2026-11-16T12:00:00Z",
            test_deadline_utc="2026-11-16T12:20:00Z",
            work_deadline_utc="2026-11-16T15:40:00Z",
            guest_base=f"/opt/cas-forex/{cls.run_id}",
            key_vault_dir=cls.vault_dir,
            trust_roots_path=cls.trust_roots_path,
        )
        cls.trust_roots = json.loads(cls.trust_roots_path.read_text(encoding="utf-8"))
        cls.pinned_reviewer_pub = bytes.fromhex(
            cls.trust_roots["roles"]["semantic_reviewer"]["public_key_hex"]
        )
        cls.docs = {
            name: load_json((cls.bundle_dir / "custody_sealed" / f"{name}.json").read_bytes())
            for name in FORMATS
        }
        cls.r6_def = load_json((cls.bundle_dir / "evidence" / "r6_definition.json").read_bytes())
        cls.case_review = load_json((cls.bundle_dir / "evidence" / "case_review.json").read_bytes())
        cls.suite = adapt_custody(
            deepcopy(cls.docs),
            schema_directory=ROOT / "docs/contracts/custody-interface-02",
            definitions=deepcopy(cls.r6_def),
            reviewed_binding=deepcopy(cls.case_review),
        )
        cls.keys = deepcopy(cls.docs["keys"])

        # Run a lightweight deterministic 30-step offline trajectory set once for [7] scoring tests
        action_by_step = {
            st["step_id"]: st["permissible_action_refs"][0]
            for c in cls.keys["cases"]
            for st in c["steps"]
        }
        case_id_by_step = {
            st["step_id"]: tc["case_id"]
            for tc in cls.suite["trajectories"]
            for st in tc["steps"]
        }
        cls.e2e_root = cls.tmp_root / "e2e_stageb_sec"
        cls.e2e_root.mkdir(parents=True, exist_ok=True)
        clock = _TestClock(cls.t0 + timedelta(minutes=5))
        scope = RunScope(
            "sec-stageb-evidence",
            cls.run_id,
            1,
            cls.build_id,
            "model-budget-1",
            "sealed-b",
            "independent-simulator-1",
        )
        cls.ctrl_journal = EvidenceJournal(cls.e2e_root / "model-anchor.evidence.sqlite3", scope.key)
        cls.ctrl_journal.initialize(create=True)
        pending_bridge = PendingChangeBridge()
        cls.adapter = _DeterministicCeremonyModelAdapter(
            action_by_step=action_by_step,
            pending_bridge=pending_bridge,
            clock=clock,
            case_id_by_step=case_id_by_step,
        )
        valve_gate = load_default_forex_valve_gate()
        cls.attempts: list[dict] = []
        for case in cls.suite["trajectories"]:
            rows, snap = run_trajectory(
                case,
                directory=cls.e2e_root / f"trajectory-{case['case_id']}",
                execution_id=cls.run_id,
                build_id=cls.build_id,
                adapter=cls.adapter,
                model_store=None,
                model_reader=cls.adapter.read_source,
                pending_changes=pending_bridge,
                clock=clock,
                valve_gate=valve_gate,
            )
            cls.attempts.extend(rows)
            cls.ctrl_journal.append(
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
        cls.reader = AttemptReader(
            root=cls.e2e_root,
            controller_journal=cls.ctrl_journal,
            model_reader=cls.adapter.read_source,
        )
        cls.valid_reviews, _, _ = build_semantic_reviews_for_attempts(
            cls.attempts,
            run_id=cls.run_id,
            key_vault_dir=cls.vault_dir,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        import gc
        gc.collect()
        _cleanup_partial_tree(cls.tmp_root)
        cls._tmp.cleanup()

    def _re_sign_bundle_copy(self, dst_bundle: Path, role_keypairs: dict[str, Ed25519Keypair]) -> dict:
        if dst_bundle.exists():
            _cleanup_partial_tree(dst_bundle)
        shutil.copytree(self.bundle_dir, dst_bundle)
        sel_file = dst_bundle / "authority/provider_selection.json"
        selection = json.loads(sel_file.read_text(encoding="utf-8"))
        common_sel = {
            k: selection[k]
            for k in (
                "format",
                "run_id",
                "epoch",
                "source_manifest_sha256",
                "config_sha256",
                "topology_sha256",
                "original_window_sha256",
                "not_before_utc",
                "expires_at_utc",
            )
        }
        purpose_to_role = {
            "custody-suite": "authority_publisher",
            "custody-keys": "authority_publisher",
            "custody-schedules": "authority_publisher",
            "custody-counterparts": "authority_publisher",
            "custody-predicates": "authority_publisher",
            "r6-definition": "authority_publisher",
            "case-exposure": "authority_publisher",
            "custody-public-manifest": "authority_publisher",
            "accepted-private-mapping": "authority_publisher",
            "independent-source-review": "semantic_reviewer",
            "separate-execution-authorization": "custody_issuer",
            "cloud-stop-proof": "independent_observer",
            "cloud-egress-seal": "independent_observer",
            "stage-a-acceptance": "redaction_approver",
            "issuer-binding": "custody_issuer",
            "observer-binding": "independent_observer",
        }
        for _raw_sha, entry in selection["records"].items():
            for purpose, att_ref in list(entry["attestations"].items()):
                kp = role_keypairs[purpose_to_role[purpose]]
                entry["publisher_sha256"] = kp.publisher_sha256
                att_doc = sign_attestation_record(
                    keypair=kp,
                    attestation_id=f"att-{self.run_id}-{purpose}",
                    record_ref=entry["reference"],
                    purpose=purpose,
                    common_selection=common_sel,
                )
                att_raw = canonical_json_bytes(att_doc)
                local_att = dst_bundle / f"authority/attestations/{purpose}.attestation.json"
                local_att.write_bytes(att_raw)
                entry["attestations"][purpose] = {
                    "path": att_ref["path"],
                    "bytes": len(att_raw),
                    "sha256": sha256(att_raw).hexdigest(),
                }
        selection["publishers"] = {kp.publisher_sha256: kp.signer_sha256 for kp in role_keypairs.values()}
        sel_raw = canonical_json_bytes(selection)
        sel_file.write_bytes(sel_raw)
        sel_sha = canonical_sha256(selection)
        pub_doc = {
            "format": "forex.stageb-ceremony-public-keys/1",
            "run_id": self.run_id,
            "key_origin": "ATTACKER_FORGED",
            "bundle_carries_trust_authority": False,
            "trusted_reviewer_id": f"reviewer-ed25519-{role_keypairs['semantic_reviewer'].signer_sha256[:16]}",
            "mapper_id": f"mapper-ed25519-{role_keypairs['authority_publisher'].signer_sha256[:16]}",
            "roles": {
                r: {
                    "public_key_hex": kp.public_bytes.hex(),
                    "signer_sha256": kp.signer_sha256,
                    "publisher_sha256": kp.publisher_sha256,
                }
                for r, kp in role_keypairs.items()
            },
            "selection_content_sha256": sel_sha,
            "selection_reference": {
                "path": f"/opt/cas-forex/{self.run_id}/authority/provider_selection.json",
                "bytes": len(sel_raw),
                "sha256": sha256(sel_raw).hexdigest(),
            },
        }
        (dst_bundle / "authority/public_keys.json").write_bytes(canonical_json_bytes(pub_doc))
        return selection

    # --- Finding [1] Tests ---

    def test_1a_historical_default_seed_derived_keys_rejected(self) -> None:
        self.assertFalse(hasattr(Ed25519Keypair, "derive"))
        seed_kps = {
            role: Ed25519Keypair(
                role=role,
                seed32=sha256(
                    f"ed25519-stageb-v1|{DEFAULT_CEREMONY_SEED}|{self.run_id}|{role}".encode("utf-8")
                ).digest(),
            )
            for role in CEREMONY_ROLES
        }
        forged_dir = self.tmp_root / "seed_forged_bundle"
        selection = self._re_sign_bundle_copy(forged_dir, seed_kps)
        forged_roots = self.tmp_root / "seed_forged_trust_roots.json"
        forged_roots.write_bytes(
            canonical_json_bytes({
                "format": "forex.stageb-pinned-trust-roots/1",
                "run_id": self.run_id,
                "epoch": 1,
                "config_sha256": "3" * 64,
                "source_manifest_sha256": "1" * 64,
                "selection_content_sha256": canonical_sha256(selection),
                "trusted_reviewer_id": f"reviewer-ed25519-{seed_kps['semantic_reviewer'].signer_sha256[:16]}",
                "roles": {
                    r: {
                        "public_key_hex": kp.public_bytes.hex(),
                        "signer_sha256": kp.signer_sha256,
                        "publisher_sha256": kp.publisher_sha256,
                    }
                    for r, kp in seed_kps.items()
                },
            })
        )
        with self.assertRaisesRegex(RuntimeError, "FORBIDDEN_SEED_DERIVED_KEY"):
            verify_ceremony_authority_bundle(
                forged_dir,
                source_root=ROOT,
                trust_roots_path=forged_roots,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )
        with self.assertRaisesRegex(RuntimeError, "FORBIDDEN_SEED_DERIVED_KEY"):
            require_ceremony_release_enabled(
                bundle_dir=forged_dir,
                source_root=ROOT,
                trust_roots_path=forged_roots,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )

    def test_1b_bundle_carried_roots_and_re_signed_public_keys_replacement_rejected(self) -> None:
        # 1. Missing external trust_roots_path fails closed
        with self.assertRaisesRegex(RuntimeError, "PINNED_TRUST_ROOTS_REQUIRED"):
            verify_ceremony_authority_bundle(
                self.bundle_dir,
                source_root=ROOT,
                trust_roots_path=None,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )

        # 2. Trust roots inside bundle_dir fails closed
        inside_roots = self.bundle_dir / "embedded_trust_roots.json"
        inside_roots.write_bytes(self.trust_roots_path.read_bytes())
        try:
            with self.assertRaisesRegex(RuntimeError, "BUNDLE_CARRIED_TRUST_ROOT_FORBIDDEN"):
                require_ceremony_release_enabled(
                    bundle_dir=self.bundle_dir,
                    source_root=ROOT,
                    trust_roots_path=inside_roots,
                    now=self.t0 + timedelta(minutes=5),
                    require_pinned_cryptography=False,
                )
        finally:
            inside_roots.unlink(missing_ok=True)

        # 3. Replacing public_keys.json and re-signing every bundle record with fresh attacker keys fails against pinned root
        attacker_kps = {role: Ed25519Keypair.generate(role) for role in CEREMONY_ROLES}
        forged_dir = self.tmp_root / "attacker_resigned_bundle"
        self._re_sign_bundle_copy(forged_dir, attacker_kps)
        with self.assertRaises(RuntimeError):
            verify_ceremony_authority_bundle(
                forged_dir,
                source_root=ROOT,
                trust_roots_path=self.trust_roots_path,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )

    def test_1c_duplicate_observer_issuer_role_custody_rejected(self) -> None:
        shared_seed = os.urandom(32)
        dup_kps = {role: Ed25519Keypair.generate(role) for role in CEREMONY_ROLES}
        dup_kps["independent_observer"] = Ed25519Keypair("independent_observer", shared_seed)
        dup_kps["custody_issuer"] = Ed25519Keypair("custody_issuer", shared_seed)

        dup_bundle = self.tmp_root / "dup_role_bundle"
        selection = self._re_sign_bundle_copy(dup_bundle, dup_kps)
        dup_roots = self.tmp_root / "dup_trust_roots.json"
        dup_roots.write_bytes(
            canonical_json_bytes({
                "format": "forex.stageb-pinned-trust-roots/1",
                "run_id": self.run_id,
                "epoch": 1,
                "config_sha256": "3" * 64,
                "source_manifest_sha256": "1" * 64,
                "selection_content_sha256": canonical_sha256(selection),
                "trusted_reviewer_id": f"reviewer-ed25519-{dup_kps['semantic_reviewer'].signer_sha256[:16]}",
                "roles": {
                    r: {
                        "public_key_hex": kp.public_bytes.hex(),
                        "signer_sha256": kp.signer_sha256,
                        "publisher_sha256": kp.publisher_sha256,
                    }
                    for r, kp in dup_kps.items()
                },
            })
        )
        with self.assertRaisesRegex(RuntimeError, "DUPLICATE_ROLE_CUSTODY_FORBIDDEN"):
            require_ceremony_release_enabled(
                bundle_dir=dup_bundle,
                source_root=ROOT,
                trust_roots_path=dup_roots,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )

        # Also rejected directly in assemble_external_release_artifacts
        ev = deepcopy(self.minted["evidence_references"])
        sealed_paths = [ev[k]["path"] for k in ("suite", "keys", "schedules", "counterparts", "predicates")]
        probe_paths = sealed_paths + [ev["custody_public_manifest"]["path"]]
        boot_id = "8f4b2c10-6c44-4d3e-9a12-770120261116"
        cfg = {
            "run_id": self.run_id,
            "build_id": self.build_id,
            "seed": 20261116,
            "source_directory": str(ROOT).replace("\\", "/"),
            "source_manifest_sha256": "1" * 64,
            "asset_manifest_sha256": "2" * 64,
            "bootstrap_started_utc": "2026-11-16T12:00:00Z",
            "test_deadline_utc": "2026-11-16T12:20:00Z",
            "work_deadline_utc": "2026-11-16T15:40:00Z",
            "evidence": ev,
            "isolation": {
                "channel_id": "chan-sec-01",
                "issuer_binding_sha256": self.minted["issuer_binding_sha256"],
                "observer_binding_sha256": self.minted["observer_binding_sha256"],
                "authority_path": str(self.tmp_root / "dup_live/authority.json").replace("\\", "/"),
                "release_path": str(self.tmp_root / "dup_live/release.json").replace("\\", "/"),
                "probe_paths": probe_paths,
                "boot_id": boot_id,
            },
        }
        role_row = {
            "pid": 2001, "parent_pid": 1, "start_ticks": 60010, "uid": 61200, "gid": 61200,
            "boot_id": boot_id, "boot_id_source": "EXTERNAL_OBSERVER_PIN",
            "namespaces": {"mnt": "mnt:[1]", "pid": "pid:[1]", "net": "net:[2]", "time": "time:[1]"},
            "mountinfo_sha256": "a" * 64, "exe": "/usr/bin/python3.12",
        }
        roles = {
            "CUSTODY_CONTROLLER": deepcopy(role_row),
            "DECISION_RUNNER": {**deepcopy(role_row), "pid": 2002, "parent_pid": 2001},
            "MODEL_SERVICE": {**deepcopy(role_row), "pid": 2003, "parent_pid": 2002},
        }
        probes = [{"opened": False, "errno": int(errno.EACCES), "denied": True} for _ in sealed_paths] + [
            {"opened": True, "errno": 0, "denied": False}
        ]
        setup = {
            "runner": {"inherited_fds": [0, 1, 2], "role": roles["DECISION_RUNNER"]},
            "runner_probes": probes,
            "model": {"inherited_fds": [0, 1, 2], "role": roles["MODEL_SERVICE"], "access_probes": probes},
        }
        with self.assertRaisesRegex(RuntimeError, "DUPLICATE_ROLE_CUSTODY_FORBIDDEN"):
            assemble_external_release_artifacts(
                cfg=cfg,
                config_sha256="3" * 64,
                roles=roles,
                setup=setup,
                model_window_record={"started_at": "2026-11-16T12:01:00+00:00", "deadline": "2026-11-16T13:31:00+00:00"},
                live_dir=self.tmp_root / "dup_live",
                guest_live_prefix=str(self.tmp_root / "dup_live").replace("\\", "/"),
                observed_at=self.t0 + timedelta(minutes=2),
                expires_at=self.t0 + timedelta(minutes=62),
                observer_keypair=dup_kps["independent_observer"],
                issuer_keypair=dup_kps["custody_issuer"],
            )

    def test_1d_mismatched_pinned_selection_or_config_digest_rejected(self) -> None:
        ok = require_ceremony_release_enabled(
            bundle_dir=self.bundle_dir,
            source_root=ROOT,
            trust_roots_path=self.trust_roots_path,
            expected_selection_sha256=self.minted["selection_content_sha256"],
            expected_config_sha256="3" * 64,
            now=self.t0 + timedelta(minutes=5),
            require_pinned_cryptography=False,
        )
        self.assertEqual(ok["authenticated_count"], 16)

        with self.assertRaisesRegex(RuntimeError, "SELECTION_DIGEST_PIN_MISMATCH"):
            require_ceremony_release_enabled(
                bundle_dir=self.bundle_dir,
                source_root=ROOT,
                trust_roots_path=self.trust_roots_path,
                expected_selection_sha256="f" * 64,
                expected_config_sha256="3" * 64,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )
        with self.assertRaisesRegex(RuntimeError, "CONFIG_DIGEST_PIN_MISMATCH"):
            require_ceremony_release_enabled(
                bundle_dir=self.bundle_dir,
                source_root=ROOT,
                trust_roots_path=self.trust_roots_path,
                expected_selection_sha256=self.minted["selection_content_sha256"],
                expected_config_sha256="e" * 64,
                now=self.t0 + timedelta(minutes=5),
                require_pinned_cryptography=False,
            )

    def test_1e_external_key_vault_modes_and_stageb_schema_sha256_unchanged(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "BUNDLE_CARRIED_TRUST_ROOT_FORBIDDEN"):
            mint_owner_stageb_custody_bundle(
                self.tmp_root / "bad_vault_bundle",
                run_id=self.run_id,
                key_vault_dir=self.tmp_root / "bad_vault_bundle" / "vault",
            )

        key_files = sorted(self.vault_dir.glob("*.key.json"))
        self.assertEqual(len(key_files), 5)
        self.assertEqual({p.name.removesuffix(".key.json") for p in key_files}, set(CEREMONY_ROLES))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.lstat(self.vault_dir).st_mode), 0o700)
            for kf in key_files:
                self.assertEqual(stat.S_IMODE(os.lstat(kf).st_mode), 0o400)
        else:
            for kf in key_files:
                self.assertFalse(os.access(kf, os.W_OK))

        sb_schema_path = ROOT / "docs/contracts/stageb-ceremony-decision-selection.schema.json"
        sb_bytes = sb_schema_path.read_bytes()
        self.assertEqual(sha256(sb_bytes).hexdigest(), EXPECTED_STAGEB_SCHEMA_SHA256)
        self.assertEqual(sb_bytes, render_stageb_selection_schema_bytes(self.docs["suite"]))

    # --- Finding [2] Tests ---

    def test_2a_file_symlink_to_sensitive_host_file_rejected_before_any_dst_creation(self) -> None:
        src_tree = self.tmp_root / "src_file_symlink"
        dst_tree = self.tmp_root / "dst_file_symlink"
        src_tree.mkdir(parents=True, exist_ok=True)
        (src_tree / "00_legit_first.txt").write_bytes(b"legitimate file before symlink alphabetically")
        sensitive_target = Path("/etc/shadow") if sys.platform == "linux" else (self.tmp_root / "host_shadow_secret.txt")
        if sys.platform != "linux":
            sensitive_target.write_bytes(b"root:$6$secret_hash")
        os.symlink(sensitive_target, src_tree / "zz_shadow_link.txt")

        with self.assertRaisesRegex(RuntimeError, "symlink"):
            _materialize_regular_tree(src_tree, dst_tree)
        self.assertFalse(dst_tree.exists(), "Destination directory must not be created when pre-scan rejects file symlink")

    def test_2b_directory_symlink_escaping_src_dir_rejected_without_traversal(self) -> None:
        outside_secret_dir = self.tmp_root / "outside_host_secrets"
        outside_secret_dir.mkdir(parents=True, exist_ok=True)
        (outside_secret_dir / "cred.txt").write_bytes(b"SECRET_HOST_DATA")

        src_tree = self.tmp_root / "src_dir_symlink"
        dst_tree = self.tmp_root / "dst_dir_symlink"
        (src_tree / "sub").mkdir(parents=True, exist_ok=True)
        (src_tree / "sub/ok.txt").write_bytes(b"ok")
        _create_dir_link_or_junction(outside_secret_dir, src_tree / "sub/escape_dir")

        with self.assertRaisesRegex(RuntimeError, "symlink"):
            _materialize_regular_tree(src_tree, dst_tree)
        self.assertFalse(dst_tree.exists())

    def test_2c_concurrent_symlink_and_inode_swap_rejected(self) -> None:
        outside_secret = self.tmp_root / "swap_secret.txt"
        outside_secret.write_bytes(b"SWAPPED_SECRET")

        # 1. Swap regular file with symlink between Phase 1 lstat and Phase 2 open+fstat
        src_swap_sym = self.tmp_root / "src_swap_sym"
        dst_swap_sym = self.tmp_root / "dst_swap_sym"
        src_swap_sym.mkdir(parents=True, exist_ok=True)
        victim_sym = src_swap_sym / "victim.txt"
        victim_sym.write_bytes(b"benign")

        def _swap_to_symlink(target_path: Path) -> None:
            if target_path == victim_sym.resolve():
                target_path.unlink()
                os.symlink(outside_secret, target_path)

        with self.assertRaisesRegex(RuntimeError, "swap|symlink"):
            _materialize_regular_tree(src_swap_sym, dst_swap_sym, _pre_open_hook=_swap_to_symlink)
        self.assertFalse(dst_swap_sym.exists())

        # 2. Swap regular file with a DIFFERENT regular file inode between Phase 1 lstat and Phase 2 open+fstat
        src_swap_ino = self.tmp_root / "src_swap_ino"
        dst_swap_ino = self.tmp_root / "dst_swap_ino"
        src_swap_ino.mkdir(parents=True, exist_ok=True)
        victim_ino = src_swap_ino / "victim_ino.txt"
        victim_ino.write_bytes(b"original_inode_content")
        replacement_ino = self.tmp_root / "replacement_inode.txt"
        replacement_ino.write_bytes(b"different_inode_content")

        def _swap_to_other_inode(target_path: Path) -> None:
            if target_path == victim_ino.resolve():
                os.replace(replacement_ino, target_path)

        with self.assertRaisesRegex(RuntimeError, "swap|inode"):
            _materialize_regular_tree(src_swap_ino, dst_swap_ino, _pre_open_hook=_swap_to_other_inode)
        self.assertFalse(dst_swap_ino.exists())

    def test_2d_least_privilege_modes_enforced_and_world_readable_0o444_rejected(self) -> None:
        src_clean = self.tmp_root / "src_clean_tree"
        dst_clean = self.tmp_root / "dst_clean_tree"
        (src_clean / "nested").mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(src_clean, 0o755)
            os.chmod(src_clean / "nested", 0o755)
        (src_clean / "nested/data.json").write_bytes(b'{"clean":true}')
        (src_clean / "nested/run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        if os.name == "posix":
            os.chmod(src_clean / "nested/data.json", 0o644)
            os.chmod(src_clean / "nested/run.sh", 0o755)

        _materialize_regular_tree(src_clean, dst_clean, dir_mode=0o550, file_mode=0o440, exec_file_mode=0o550)
        try:
            self.assertEqual((dst_clean / "nested/data.json").read_bytes(), b'{"clean":true}')
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.lstat(dst_clean).st_mode), 0o550)
                self.assertEqual(stat.S_IMODE(os.lstat(dst_clean / "nested").st_mode), 0o550)
                self.assertEqual(stat.S_IMODE(os.lstat(dst_clean / "nested/data.json").st_mode), 0o440)
                self.assertEqual(stat.S_IMODE(os.lstat(dst_clean / "nested/run.sh").st_mode), 0o550)

            with self.assertRaises(ValueError):
                apply_verified_regular_file_mode(dst_clean / "nested/data.json", 0o444)
            with self.assertRaises(ValueError):
                apply_verified_regular_file_mode(dst_clean / "nested/run.sh", 0o555)
            with self.assertRaises(ValueError):
                apply_verified_directory_mode(dst_clean, 0o777)
        finally:
            _cleanup_partial_tree(dst_clean)

        for mod_name in ("ceremony_generator.py", "external_stageb_ceremony_observer.py"):
            src_txt = (ROOT / mod_name).read_text(encoding="utf-8")
            self.assertNotIn("0o444", src_txt, f"World-readable 0o444 found in {mod_name}")
            self.assertNotIn("0o555", src_txt, f"World-executable 0o555 found in {mod_name}")

    # --- Finding [7] Tests ---

    def test_7a_driver_removes_in_process_semantic_review_authoring_and_signing(self) -> None:
        drv_src = (ROOT / "approved_stageb_ceremony_driver.py").read_text(encoding="utf-8")
        self.assertNotIn("build_semantic_reviews_for_attempts", drv_src)
        self.assertNotIn("build_public_aggregate_bundle", drv_src)
        self.assertIn("pinned_reviewer_public_key=", drv_src)
        self.assertNotIn("trusted_reviewer_id=", drv_src)
        drv_tree = ast.parse(drv_src)
        self.assertIsNotNone(drv_tree)

    def test_7b_flipping_any_review_boolean_post_signing_invalidates_review(self) -> None:
        baseline = score_suite(
            self.suite,
            self.keys,
            self.attempts,
            verify_attempt=self.reader,
            semantic_reviews=self.valid_reviews,
            pinned_reviewer_public_key=self.pinned_reviewer_pub,
        )
        self.assertEqual(baseline["status"], "PASS")

        first_sid = self.attempts[0]["step_id"]
        for bool_field in (
            "reason_supported_by_current_evidence",
            "envelope_expansion_refused",
            "none_eligible_from_current_policy_and_facts",
        ):
            flipped_reviews = deepcopy(self.valid_reviews)
            orig_val = flipped_reviews[first_sid]["review"][bool_field]
            flipped_reviews[first_sid]["review"][bool_field] = not orig_val
            self.assertIsNone(
                semantic_result(
                    self.attempts[0],
                    flipped_reviews[first_sid],
                    pinned_reviewer_public_key=self.pinned_reviewer_pub,
                )
            )
            scored = score_suite(
                self.suite,
                self.keys,
                self.attempts,
                verify_attempt=self.reader,
                semantic_reviews=flipped_reviews,
                pinned_reviewer_public_key=self.pinned_reviewer_pub,
            )
            self.assertEqual(scored["status"], "FAIL", f"Flipping {bool_field} must fail suite scoring")

    def test_7c_driver_supplied_trusted_reviewer_id_outside_pinned_registry_rejected(self) -> None:
        rogue_kp = Ed25519Keypair.generate("semantic_reviewer")
        rogue_reviews, _, _ = build_semantic_reviews_for_attempts(
            self.attempts,
            run_id=self.run_id,
            reviewer_keypair=rogue_kp,
        )
        rogue_id = rogue_reviews[self.attempts[0]["step_id"]]["review"]["reviewer_id"]

        # Supplying trusted_reviewer_id without pinned_reviewer_public_key fails closed
        self.assertIsNone(
            semantic_result(
                self.attempts[0],
                rogue_reviews[self.attempts[0]["step_id"]],
                trusted_reviewer_id=rogue_id,
            )
        )
        # Supplying rogue reviews with rogue trusted_reviewer_id against pinned reviewer key fails closed
        scored = score_suite(
            self.suite,
            self.keys,
            self.attempts,
            verify_attempt=self.reader,
            semantic_reviews=rogue_reviews,
            pinned_reviewer_public_key=self.pinned_reviewer_pub,
            trusted_reviewer_id=rogue_id,
        )
        self.assertEqual(scored["status"], "FAIL")

    def test_7d_nonempty_unsupported_reason_fails_semantic_scoring(self) -> None:
        act_attempt = deepcopy(next(a for a in self.attempts if a["selected_action_ref"] is not None))
        wait_attempt = deepcopy(next(a for a in self.attempts if a["selected_action_ref"] is None))

        for bad_reason in (
            "Looks profitable based on momentum",
            "ID=0deadbeef1234567890abcdef",
            f"ID=0{act_attempt['case_id']}",
        ):
            mut = deepcopy(act_attempt)
            mut["result"]["selection"]["reason"] = bad_reason
            self.assertFalse(evaluate_evidence_grounded_reason(mut), f"Expected False on ACT reason {bad_reason!r}")

        trap_ref = next(
            o["action_ref"]
            for o in act_attempt["request"]["options"]
            if o["action_ref"] != act_attempt["selected_action_ref"]
        )
        trap_mut = deepcopy(act_attempt)
        trap_mut["selected_action_ref"] = trap_ref
        trap_mut["result"]["selection"]["selected_action_ref"] = trap_ref
        trap_mut["result"]["selection"]["reason"] = f"ID=0{trap_ref}"
        self.assertFalse(evaluate_evidence_grounded_reason(trap_mut))

        wait_opt_ref = wait_attempt["request"]["options"][0]["action_ref"]
        for bad_wait_reason in ("Standing aside cautiously", f"ID=0{wait_opt_ref}", "ID=0999999999999"):
            wmut = deepcopy(wait_attempt)
            wmut["result"]["selection"]["reason"] = bad_wait_reason
            self.assertFalse(evaluate_evidence_grounded_reason(wmut))

        # Full suite scoring fails when an attempt carries a nonempty unsupported reason
        bad_attempts = deepcopy(self.attempts)
        bad_attempts[0]["result"]["selection"]["reason"] = "Nonempty unsupported prose rationale"
        kp_rev = Ed25519Keypair(
            "semantic_reviewer",
            bytes.fromhex(
                json.loads((self.vault_dir / "semantic_reviewer.key.json").read_text(encoding="utf-8"))["seed_hex"]
            ),
        )
        bad_reviews, _, _ = build_semantic_reviews_for_attempts(
            bad_attempts,
            run_id=self.run_id,
            reviewer_keypair=kp_rev,
        )
        self.assertFalse(bad_reviews[bad_attempts[0]["step_id"]]["review"]["reason_supported_by_current_evidence"])
        scored = score_suite(
            self.suite,
            self.keys,
            bad_attempts,
            verify_attempt=lambda _: True,
            semantic_reviews=bad_reviews,
            pinned_reviewer_public_key=self.pinned_reviewer_pub,
        )
        self.assertEqual(scored["status"], "FAIL")

    def test_7e_missing_signed_review_envelope_fails_closed(self) -> None:
        scored_empty = score_suite(
            self.suite,
            self.keys,
            self.attempts,
            verify_attempt=self.reader,
            semantic_reviews={},
            pinned_reviewer_public_key=self.pinned_reviewer_pub,
        )
        self.assertEqual(scored_empty["status"], "INCOMPLETE")
        self.assertNotEqual(scored_empty["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
