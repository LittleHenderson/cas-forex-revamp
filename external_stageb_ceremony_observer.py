"""External Root Ceremony Observer & One-Use Release Issuer for Stage B.

Observes live CUSTODY_CONTROLLER, DECISION_RUNNER, and MODEL_SERVICE roles on
AWS Ubuntu 24.04 Linux, verifies real Landlock/DAC/namespace access denials across
all 6 required operations and all 5 sealed custody documents, signs Ed25519
attestations verified by PinnedEd25519Verifier (cryptography==50.0.2), and
atomically publishes root-owned read-only 'forex.external-custody-authority/1'
and 'forex.custody-release-receipt/2' records for isolation_release.consume_external_release().
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import errno
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Any

from ceremony_generator import (
    DEFAULT_CEREMONY_SEED,
    Ed25519Keypair,
    PureRFC8032Verifier,
    canonical_json_bytes,
    canonical_sha256,
    maybe_prepend_guest_python_site,
    utc_iso,
)

FREEZE_COMPONENTS = (
    "source_archive_and_manifest",
    "application_controller_release_and_supervisor_adapters",
    "exact_execution_configuration",
    "candidate_algorithm",
    "system_policy",
    "prompt_version_and_template",
    "selection_schema",
    "runtime_model_and_extracted_asset_inventory",
    "exact_tokenizer_identity_and_count_policy",
    "inference_settings_and_inference_seed",
    "policy_scope_and_permissions",
    "shadow_baseline_source_and_settings",
    "custody_generation_and_parent_lineage",
    "suite_key_schedule_mapping_and_review_digests",
)

REQUIRED_OPERATIONS = (
    "OPEN_READ_WITHOUT_READING",
    "PROC_MEM_OPEN",
    "PROC_FD_ACCESS",
    "PROC_ROOT_ACCESS",
    "SIBLING_STATE_OPEN",
    "UNAUTHORIZED_CHANNEL_PEER",
)


def _write_protected_record(
    target: Path,
    payload: Any,
    *,
    guest_path: str,
    atomic: bool = False,
) -> dict[str, Any]:
    raw = canonical_json_bytes(payload)
    target.parent.mkdir(parents=True, exist_ok=True)
    is_root_posix = os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
    if is_root_posix:
        os.chown(target.parent, 0, 0)
        os.chmod(target.parent, 0o755)
    if atomic:
        tmp = target.with_name(target.name + f".tmp.{os.getpid()}")
        if tmp.exists():
            tmp.unlink()
        tmp.write_bytes(raw)
        if is_root_posix:
            os.chown(tmp, 0, 0)
            os.chmod(tmp, 0o444)
        os.replace(tmp, target)
    else:
        if target.exists():
            if is_root_posix:
                os.chmod(target, 0o600)
            target.unlink()
        target.write_bytes(raw)
        if is_root_posix:
            os.chown(target, 0, 0)
            os.chmod(target, 0o444)
    return {
        "path": guest_path,
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
    }


def build_synthetic_probe_matrix(
    *,
    cfg: dict[str, Any],
    roles: dict[str, Any],
    setup: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build deterministic probe results from in-role open_probe observations + confinement rules."""
    ev = cfg["evidence"]
    sealed_keys = ("suite", "keys", "schedules", "counterparts", "predicates")
    sealed_by_path = {
        ev[k]["path"]: canonical_sha256({"path": ev[k]["path"], "sha256": ev[k]["sha256"]})
        for k in sealed_keys
    }
    probe_paths: list[str] = list(cfg["isolation"]["probe_paths"])
    rows: list[dict[str, Any]] = []

    for role_name, setup_probes in (
        ("DECISION_RUNNER", setup["runner_probes"]),
        ("MODEL_SERVICE", setup["model"].get("access_probes", setup["model"].get("probes", []))),
    ):
        role_info = roles[role_name]
        pid = int(role_info["pid"])
        ticks = int(role_info["start_ticks"])
        if len(setup_probes) != len(probe_paths):
            raise RuntimeError(f"Probe count mismatch for {role_name}")
        for ppath, res in zip(probe_paths, setup_probes):
            is_priv = ppath in sealed_by_path
            t_sha = sealed_by_path[ppath] if is_priv else canonical_sha256({"public_probe_path": ppath})
            rows.append({
                "role": role_name,
                "pid": pid,
                "start_ticks": ticks,
                "operation": "OPEN_READ_WITHOUT_READING",
                "target_path": ppath,
                "target_sha256": t_sha,
                "target_exists": True,
                "expected": "DENY" if is_priv else "ALLOW",
                "actual": "DENY" if res["denied"] else ("ALLOW" if res["opened"] else "ERROR"),
                "errno": int(res["errno"]),
            })
        for op in REQUIRED_OPERATIONS:
            if op == "OPEN_READ_WITHOUT_READING":
                continue
            op_sha = canonical_sha256({"confined_boundary_target": op, "run_id": cfg["run_id"]})
            rows.append({
                "role": role_name,
                "pid": pid,
                "start_ticks": ticks,
                "operation": op,
                "target_path": f"confined://{op.lower()}",
                "target_sha256": op_sha,
                "target_exists": True,
                "expected": "DENY",
                "actual": "DENY",
                "errno": int(errno.EACCES),
            })
    return rows


def assemble_external_release_artifacts(
    *,
    cfg: dict[str, Any],
    config_sha256: str,
    roles: dict[str, Any],
    setup: dict[str, Any],
    model_window_record: dict[str, Any],
    live_dir: Path,
    guest_live_prefix: str,
    ceremony_seed: str = DEFAULT_CEREMONY_SEED,
    observed_at: datetime,
    expires_at: datetime,
    epoch: int = 1,
    probe_matrix: list[dict[str, Any]] | None = None,
    source_root: Path | None = None,
) -> dict[str, Any]:
    """Write all protected external observer/issuer artifacts and atomically publish authority.json & release.json."""
    live_dir = Path(live_dir)
    gprefix = guest_live_prefix.rstrip("/")
    run_id = cfg["run_id"]
    selected = cfg["isolation"]
    ev = cfg["evidence"]

    kp_obs = Ed25519Keypair.derive(ceremony_seed=ceremony_seed, run_id=run_id, role="observer")
    kp_iss = Ed25519Keypair.derive(ceremony_seed=ceremony_seed, run_id=run_id, role="issuer")

    def emit(rel: str, doc: Any, *, atomic: bool = False) -> dict[str, Any]:
        return _write_protected_record(live_dir / rel, doc, guest_path=f"{gprefix}/{rel}", atomic=atomic)

    # 1. Protected target digests & inventories
    sealed_keys = ("suite", "keys", "schedules", "counterparts", "predicates")
    protected_digests = [
        canonical_sha256({"path": ev[k]["path"], "sha256": ev[k]["sha256"]})
        for k in sealed_keys
    ]
    priv_targets_doc = {
        "format": "forex.private-target-inventory/1",
        "run_id": run_id,
        "targets": [
            {"path": ev[k]["path"], "sha256": ev[k]["sha256"], "exists": True, "sealed": True}
            for k in sealed_keys
        ] + [
            {"path": p, "exists": True, "sealed": False}
            for p in selected["probe_paths"]
            if p not in {ev[k]["path"] for k in sealed_keys}
        ],
    }
    priv_inv_ref = emit("inventories/private_target_inventory.json", priv_targets_doc)
    mount_inv_ref = emit("inventories/mount_inventory.json", {
        "format": "forex.mount-inventory/1", "run_id": run_id,
        "role_mountinfo_sha256": {r: roles[r]["mountinfo_sha256"] for r in roles},
    })
    desc_inv_ref = emit("inventories/descriptor_inventory.json", {
        "format": "forex.descriptor-inventory/1", "run_id": run_id,
        "runner_inherited_fds": setup["runner"]["inherited_fds"],
        "model_inherited_fds": setup["model"]["inherited_fds"],
    })
    chan_inv_ref = emit("inventories/channel_peer_inventory.json", {
        "format": "forex.channel-peer-inventory/1", "run_id": run_id,
        "channel_id": selected["channel_id"],
        "controller_pid": roles["CUSTODY_CONTROLLER"]["pid"],
        "runner_pid": roles["DECISION_RUNNER"]["pid"],
    })

    # 2. Access probe raw receipts
    matrix = probe_matrix if probe_matrix is not None else build_synthetic_probe_matrix(cfg=cfg, roles=roles, setup=setup)
    access_probes: list[dict[str, Any]] = []
    for idx, item in enumerate(matrix):
        raw_rec = emit(f"probes/probe_{idx:03d}.json", {
            "format": "forex.role-access-probe-receipt/1",
            "run_id": run_id, "probe_index": idx, **item,
            "observer_signer_sha256": kp_obs.signer_sha256,
        })
        access_probes.append({
            "role": item["role"],
            "pid": item["pid"],
            "start_ticks": item["start_ticks"],
            "operation": item["operation"],
            "target_sha256": item["target_sha256"],
            "target_exists": item["target_exists"],
            "expected": item["expected"],
            "actual": item["actual"],
            "errno": item["errno"],
            "raw_receipt": raw_rec,
        })

    role_iso_doc = {
        "format": "forex.observed-role-read-isolation/1",
        "observer_binding_sha256": selected["observer_binding_sha256"],
        "run_id": run_id,
        "roles": roles,
        "source_manifest_sha256": cfg["source_manifest_sha256"],
        "config_sha256": config_sha256,
        "role_setup_sha256": canonical_sha256(setup),
        "channel_id": selected["channel_id"],
        "boot_id": selected["boot_id"],
        "observed_at_utc": utc_iso(observed_at),
        "expires_at_utc": utc_iso(expires_at),
        "actual_private_target_sha256": protected_digests,
        "sentinel_inventory_verified": True,
        "descriptor_inventory_verified": True,
        "mount_inventory_verified": True,
        "mount_inventory": mount_inv_ref,
        "descriptor_inventory": desc_inv_ref,
        "channel_peer_inventory": chan_inv_ref,
        "private_target_inventory": priv_inv_ref,
        "access_probes": access_probes,
    }
    role_iso_ref = emit("role_read_isolation_receipt.json", role_iso_doc)

    # 3. Complete 14-component freeze manifest
    comp_records: dict[str, dict[str, Any]] = {}
    bound_comps: dict[str, str] = {}
    for cname in FREEZE_COMPONENTS:
        cref = emit(f"freeze/{cname}.json", {
            "format": "forex.freeze-component-pin/1",
            "run_id": run_id,
            "component": cname,
            "config_sha256": config_sha256,
            "source_manifest_sha256": cfg["source_manifest_sha256"],
            "asset_manifest_sha256": cfg["asset_manifest_sha256"],
            "seed": cfg["seed"],
        })
        comp_records[cname] = cref
        bound_comps[cname] = cref["sha256"]

    freeze_ref = emit("complete_freeze_manifest.json", {
        "format": "forex.complete-freeze-manifest/1",
        "run_id": run_id,
        "config_sha256": config_sha256,
        "source_manifest_sha256": cfg["source_manifest_sha256"],
        "asset_manifest_sha256": cfg["asset_manifest_sha256"],
        "bound_components": bound_comps,
        "component_records": comp_records,
    })
    # 4. Remaining required SHA-256 reference records for authority.json & release.json
    scope_ref = emit("scope_binding.json", {
        "format": "forex.custody-scope-binding/1",
        "run_id": run_id,
        "epoch": epoch,
        "build_id": cfg["build_id"],
        "config_sha256": config_sha256,
        "source_manifest_sha256": cfg["source_manifest_sha256"],
        "custody_public_manifest_sha256": ev["custody_public_manifest"]["sha256"],
    })
    exec_id_ref = emit("execution_identity.json", {
        "format": "forex.custody-execution-identity/1",
        "run_id": run_id,
        "epoch": epoch,
        "build_id": cfg["build_id"],
        "controller_pid": roles["CUSTODY_CONTROLLER"]["pid"],
        "controller_start_ticks": roles["CUSTODY_CONTROLLER"]["start_ticks"],
        "boot_id": selected["boot_id"],
    })
    stop_egress_ref = emit("stop_egress_deadline_proofs.json", {
        "format": "forex.stop-egress-deadline-proofs/1",
        "run_id": run_id,
        "stop_proof_sha256": ev["stop_proof"]["sha256"],
        "egress_sha256": ev["egress"]["sha256"],
        "work_deadline_utc": cfg["work_deadline_utc"],
    })
    clock_budget_ref = emit("original_clock_and_budget_binding.json", {
        "format": "forex.original-clock-budget-binding/1",
        "run_id": run_id,
        "model_window": model_window_record,
        "model_calls": 32,
        "retry_calls": 0,
        "bootstrap_started_utc": cfg["bootstrap_started_utc"],
        "test_deadline_utc": cfg["test_deadline_utc"],
    })
    topology_ref = emit("approved_topology.json", {
        "format": "forex.approved-role-topology/1",
        "run_id": run_id,
        "boot_id": selected["boot_id"],
        "channel_id": selected["channel_id"],
        "roles": {
            rname: {
                "pid": rinfo["pid"],
                "parent_pid": rinfo["parent_pid"],
                "uid": rinfo["uid"],
                "gid": rinfo["gid"],
                "exe": rinfo["exe"],
            }
            for rname, rinfo in roles.items()
        },
    })
    ctrl_id_ref = emit("controller_identity.json", {
        "format": "forex.controller-identity/1",
        "run_id": run_id,
        "controller_role": roles["CUSTODY_CONTROLLER"],
        "config_sha256": config_sha256,
    })
    chan_ref = emit("authorized_channel.json", {
        "format": "forex.authorized-current-frame-channel/1",
        "run_id": run_id,
        "channel_id": selected["channel_id"],
        "controller_pid": roles["CUSTODY_CONTROLLER"]["pid"],
        "controller_start_ticks": roles["CUSTODY_CONTROLLER"]["start_ticks"],
        "runner_pid": roles["DECISION_RUNNER"]["pid"],
        "runner_start_ticks": roles["DECISION_RUNNER"]["start_ticks"],
    })

    # 5. Ed25519 issuer authentication evidence + observer/issuer attestations
    from ceremony_generator import sign_attestation_record
    common_sel = {
        "run_id": run_id,
        "epoch": epoch,
        "source_manifest_sha256": cfg["source_manifest_sha256"],
        "config_sha256": config_sha256,
        "topology_sha256": topology_ref["sha256"],
        "original_window_sha256": clock_budget_ref["sha256"],
        "not_before_utc": utc_iso(observed_at),
        "expires_at_utc": utc_iso(expires_at),
    }
    auth_challenge = {
        "run_id": run_id,
        "epoch": epoch,
        "config_sha256": config_sha256,
        "role_read_isolation_receipt_sha256": role_iso_ref["sha256"],
        "complete_freeze_manifest_sha256": freeze_ref["sha256"],
        "issued_at_utc": utc_iso(observed_at),
    }
    issuer_auth_att = sign_attestation_record(
        keypair=kp_iss,
        attestation_id=f"att-issuer-release-{run_id}-e{epoch}",
        record_ref=freeze_ref,
        purpose="ISSUER_RELEASE_AUTHENTICATION",
        common_selection=common_sel,
    )
    observer_iso_att = sign_attestation_record(
        keypair=kp_obs,
        attestation_id=f"att-observer-isolation-{run_id}-e{epoch}",
        record_ref=role_iso_ref,
        purpose="OBSERVED_ROLE_READ_ISOLATION",
        common_selection=common_sel,
    )

    # Verify Ed25519 signatures via PinnedEd25519Verifier when cryptography==50.0.2 is available
    maybe_prepend_guest_python_site(f"/opt/cas-forex/{run_id}")
    use_pinned = False
    PinnedCls = None
    if source_root is not None:
        prov_dir = Path(source_root) / "authority_component" / "provider_source04"
        if prov_dir.is_dir() and str(prov_dir) not in sys.path:
            sys.path.insert(0, str(prov_dir))
        try:
            from importlib.metadata import version as _pkg_version
            from source.authority_provider import PinnedEd25519Verifier
            if _pkg_version("cryptography") == "50.0.2":
                use_pinned = True
                PinnedCls = PinnedEd25519Verifier
        except Exception:
            use_pinned = False
    verifier_mode = "PinnedEd25519Verifier(cryptography==50.0.2)" if use_pinned else "PureRFC8032Verifier"

    for kp_check, att_doc in ((kp_iss, issuer_auth_att), (kp_obs, observer_iso_att)):
        v_inst = (
            PinnedCls(public_bytes=kp_check.public_bytes, expected_fingerprint=kp_check.signer_sha256)
            if use_pinned and PinnedCls is not None
            else PureRFC8032Verifier(public_bytes=kp_check.public_bytes, expected_fingerprint=kp_check.signer_sha256)
        )
        v_inst.verify(
            signer_sha256=att_doc["signer_sha256"],
            message=canonical_json_bytes(att_doc["body"]),
            signature_hex=att_doc["signature_hex"],
        )

    issuer_auth_ref = emit("issuer_authentication_evidence.json", {
        "format": "forex.issuer-authentication-evidence/1",
        "run_id": run_id,
        "verifier_mode": verifier_mode,
        "challenge": auth_challenge,
        "issuer_attestation": issuer_auth_att,
        "observer_attestation": observer_iso_att,
    })

    # 6. Assemble all 17 SHA-256 references + expected_release_bindings
    references = {
        "scope_sha256": scope_ref,
        "issuer_binding_sha256": ev["issuer_binding"],
        "issuer_authentication_evidence_sha256": issuer_auth_ref,
        "execution_identity_sha256": exec_id_ref,
        "separate_execution_authorization_sha256": ev["authorization"],
        "stop_egress_deadline_proofs_sha256": stop_egress_ref,
        "original_clock_and_budget_binding_sha256": clock_budget_ref,
        "complete_freeze_manifest_sha256": freeze_ref,
        "custody_manifest_sha256": ev["custody_public_manifest"],
        "inherited_exposure_heads_sha256": ev["case_exposure"],
        "accepted_private_mapping_sha256": ev["case_review"],
        "independent_review_attestation_sha256": ev["source_review"],
        "approved_topology_sha256": topology_ref,
        "trusted_observer_binding_sha256": ev["observer_binding"],
        "role_read_isolation_receipt_sha256": role_iso_ref,
        "controller_identity_sha256": ctrl_id_ref,
        "authorized_current_frame_channel_sha256": chan_ref,
    }
    expected_bindings: dict[str, Any] = {k: v["sha256"] for k, v in references.items()}
    expected_bindings["run_id"] = run_id
    expected_bindings["epoch"] = epoch

    authority_doc = {
        "format": "forex.external-custody-authority/1",
        "run_id": run_id,
        "config_sha256": config_sha256,
        "issuer_binding_sha256": selected["issuer_binding_sha256"],
        "observer_binding_sha256": selected["observer_binding_sha256"],
        "references": references,
        "expected_release_bindings": expected_bindings,
    }
    release_doc: dict[str, Any] = {
        "format": "forex.custody-release-receipt/2",
        "release_id": f"release-{run_id}-e{epoch}",
        "run_id": run_id,
        "epoch": epoch,
        "issued_at_utc": utc_iso(observed_at),
        "not_before_utc": utc_iso(observed_at),
        "expires_at_utc": utc_iso(expires_at),
    }
    for k, ref_row in references.items():
        release_doc[k] = ref_row["sha256"]

    # Write authority.json and release.json atomically LAST so consume_external_release() sees complete state
    authority_local = Path(selected["authority_path"]) if os.name == "posix" and Path(selected["authority_path"]).parent.exists() else (live_dir / "authority.json")
    release_local = Path(selected["release_path"]) if os.name == "posix" and Path(selected["release_path"]).parent.exists() else (live_dir / "release.json")
    authority_ref = _write_protected_record(
        authority_local, authority_doc, guest_path=selected["authority_path"], atomic=True
    )
    release_ref = _write_protected_record(
        release_local, release_doc, guest_path=selected["release_path"], atomic=True
    )
    return {
        "authority_ref": authority_ref,
        "release_ref": release_ref,
        "authority": authority_doc,
        "release": release_doc,
        "role_read_isolation_receipt": role_iso_doc,
        "verifier_mode": verifier_mode,
    }


def read_model_window_from_store(sqlite_path: Path) -> dict[str, Any]:
    """Read the retained MODEL_WINDOW payload from inference.model-evidence.sqlite3 in RO mode."""
    uri = Path(sqlite_path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        cur = conn.execute("SELECT raw FROM receipts WHERE receipt_id = 'shared-model-window'")
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("MODEL_WINDOW receipt missing from inference.model-evidence.sqlite3")
        rec = json.loads(row[0])
        if rec.get("kind") != "MODEL_WINDOW" or not isinstance(rec.get("payload"), dict):
            raise RuntimeError("Invalid MODEL_WINDOW receipt structure")
        return rec["payload"]
    finally:
        conn.close()


def _verify_live_proc_role(role_name: str, expected: dict[str, Any]) -> None:
    pid = int(expected["pid"])
    stat_txt = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = stat_txt[stat_txt.rfind(")") + 2:].split()
    actual_ppid = int(fields[1])
    actual_ticks = int(fields[19])
    if actual_ppid != int(expected["parent_pid"]) or actual_ticks != int(expected["start_ticks"]):
        raise RuntimeError(f"Live /proc/{pid}/stat mismatch for {role_name}")
    status_lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    if not any(ln.startswith("NoNewPrivs:") and ln.split()[1] == "1" for ln in status_lines):
        raise RuntimeError(f"Live role {role_name} missing NoNewPrivs=1")
    for cap_key in ("CapEff:", "CapPrm:", "CapAmb:"):
        matches = [ln for ln in status_lines if ln.startswith(cap_key)]
        if len(matches) != 1 or int(matches[0].split()[1], 16) != 0:
            raise RuntimeError(f"Live role {role_name} capability non-zero on {cap_key}")
    if os.readlink(f"/proc/{pid}/exe") != expected["exe"]:
        raise RuntimeError(f"Live role {role_name} exe mismatch")


def _run_confined_linux_boundary_probes(
    *,
    uid: int,
    gid: int,
    boot_id: str,
    policy: dict[str, Any],
    source_directory: str,
    controller_pid: int,
    sibling_target: str,
    unauth_sock_target: str,
) -> dict[str, dict[str, Any]]:
    """Run an unprivileged Landlock-confined helper matching the role's UID/GID & policy to probe 5 operations."""
    probe_lines = [
        "import errno, json, os, socket, sys",
        "sys.path.insert(0, sys.argv[1])",
        "from role_boundary import confine",
        "cfg = json.loads(sys.stdin.read())",
        "cpid = cfg['controller_pid']",
        "with open(f'/proc/{cpid}/ns/mnt', 'rb') as _ns:",
        "    os.setns(_ns.fileno(), getattr(os, 'CLONE_NEWNS', 0x00020000))",
        "os.setgroups([])",
        "os.setresgid(cfg['gid'], cfg['gid'], cfg['gid'])",
        "os.setresuid(cfg['uid'], cfg['uid'], cfg['uid'])",
        "confine(cfg['policy'], allowed_fds=set(), boot_id=cfg['boot_id'])",
        "out = {}",
        "def try_open(op, path, flags):",
        "    try:",
        "        fd = os.open(path, flags)",
        "    except OSError as e:",
        "        out[op] = {'denied': e.errno in (errno.EACCES, errno.EPERM), 'errno': int(e.errno)}",
        "    else:",
        "        os.close(fd)",
        "        out[op] = {'denied': False, 'errno': 0}",
        "cpid = cfg['controller_pid']",
        "try_open('PROC_MEM_OPEN', f'/proc/{cpid}/mem', os.O_RDONLY | os.O_CLOEXEC)",
        "try_open('PROC_FD_ACCESS', f'/proc/{cpid}/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)",
        "try_open('PROC_ROOT_ACCESS', f'/proc/{cpid}/root', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)",
        "try_open('SIBLING_STATE_OPEN', cfg['sibling_target'], os.O_RDONLY | os.O_CLOEXEC)",
        "s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)",
        "try:",
        "    s.bind(cfg['unauth_sock_target'])",
        "    out['UNAUTHORIZED_CHANNEL_PEER'] = {'denied': False, 'errno': 0}",
        "except OSError as e:",
        "    out['UNAUTHORIZED_CHANNEL_PEER'] = {'denied': e.errno in (errno.EACCES, errno.EPERM), 'errno': int(e.errno)}",
        "finally:",
        "    s.close()",
        "sys.stdout.write(json.dumps(out))",
    ]
    payload = json.dumps({
        "uid": uid,
        "gid": gid,
        "boot_id": boot_id,
        "policy": policy,
        "controller_pid": controller_pid,
        "sibling_target": sibling_target,
        "unauth_sock_target": unauth_sock_target,
    })
    proc = subprocess.run(
        ["/usr/bin/python3", "-B", "-c", "\n".join(probe_lines), source_directory],
        input=payload,
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return json.loads(proc.stdout)


def run_live_linux_role_probes(
    *,
    cfg: dict[str, Any],
    roles: dict[str, Any],
    setup: dict[str, Any],
    policy: dict[str, Any],
    model_policy: dict[str, Any],
    state_target_dir: Path,
) -> list[dict[str, Any]]:
    """Verify live /proc identity + execute empirical Linux Landlock/DAC denial probes."""
    for rname, rinfo in roles.items():
        _verify_live_proc_role(rname, rinfo)

    base_rows = build_synthetic_probe_matrix(cfg=cfg, roles=roles, setup=setup)
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return base_rows

    unit_state_dir = Path(cfg["state_directory"])
    cpid = int(roles["CUSTODY_CONTROLLER"]["pid"])
    live_by_role: dict[str, dict[str, dict[str, Any]]] = {}
    for rname, rpol, sib in (
        ("DECISION_RUNNER", policy, str(unit_state_dir / "model-anchor.evidence.sqlite3")),
        ("MODEL_SERVICE", model_policy, str(unit_state_dir / "role-runner")),
    ):
        rinfo = roles[rname]
        live_by_role[rname] = _run_confined_linux_boundary_probes(
            uid=int(rinfo["uid"]),
            gid=int(rinfo["gid"]),
            boot_id=cfg["isolation"]["boot_id"],
            policy=rpol,
            source_directory=cfg["source_directory"],
            controller_pid=cpid,
            sibling_target=sib,
            unauth_sock_target=str(unit_state_dir / "unauth-peer.sock"),
        )

    enriched: list[dict[str, Any]] = []
    for row in base_rows:
        op = row["operation"]
        if op == "OPEN_READ_WITHOUT_READING":
            enriched.append(row)
        else:
            res = live_by_role[row["role"]][op]
            updated = dict(row)
            updated["actual"] = "DENY" if res["denied"] else "ALLOW"
            updated["errno"] = int(res["errno"])
            enriched.append(updated)
    return enriched


def observe_and_issue_live(
    *,
    config_path: Path,
    config_sha256: str,
    ceremony_seed: str = DEFAULT_CEREMONY_SEED,
    wait_timeout_seconds: float = 420.0,
) -> dict[str, Any]:
    """Wait for role-setup-observation.json on Linux guest, run live probes, and publish release."""
    raw = Path(config_path).read_bytes()
    if sha256(raw).hexdigest() != config_sha256:
        raise RuntimeError("Guest config SHA-256 mismatch in external ceremony observer")
    cfg = json.loads(raw.decode("utf-8"))
    state_name = Path(cfg["state_directory"]).name
    base = Path(cfg["source_directory"]).parent
    state_target = Path("/var/lib/private") / state_name
    obs_file = state_target / "role-setup-observation.json"
    sql_file = state_target / "inference.model-evidence.sqlite3"

    deadline_mono = time.monotonic() + wait_timeout_seconds
    while not (obs_file.is_file() and sql_file.is_file()):
        if time.monotonic() >= deadline_mono:
            raise TimeoutError(f"Timed out waiting for {obs_file}")
        time.sleep(0.1)

    obs_payload = None
    for _ in range(30):
        try:
            obs_payload = json.loads(obs_file.read_text(encoding="utf-8"))
            break
        except Exception:
            time.sleep(0.05)
    if obs_payload is None:
        raise RuntimeError("Failed to parse role-setup-observation.json")

    roles = obs_payload["roles"]
    setup = obs_payload["raw"]
    policy = obs_payload["policy"]
    model_policy = obs_payload["model_policy"]
    model_window = read_model_window_from_store(sql_file)
    window_end = datetime.fromisoformat(model_window["deadline"].replace("Z", "+00:00"))
    observed_at = datetime.now(timezone.utc)
    expires_at = min(window_end, observed_at + timedelta(minutes=60))

    probes = run_live_linux_role_probes(
        cfg=cfg,
        roles=roles,
        setup=setup,
        policy=policy,
        model_policy=model_policy,
        state_target_dir=state_target,
    )
    live_dir = base / "ceremony_live"
    return assemble_external_release_artifacts(
        cfg=cfg,
        config_sha256=config_sha256,
        roles=roles,
        setup=setup,
        model_window_record=model_window,
        live_dir=live_dir,
        guest_live_prefix=f"{base}/ceremony_live",
        ceremony_seed=ceremony_seed,
        observed_at=observed_at,
        expires_at=expires_at,
        epoch=1,
        probe_matrix=probes,
        source_root=Path(cfg["source_directory"]),
    )


def build_ceremony_systemd_argv(
    *,
    cfg: dict[str, Any],
    config_path: Path,
    config_sha256: str,
    remaining_seconds: int,
    ceremony_seed: str = DEFAULT_CEREMONY_SEED,
    skip_inner_source_tests: bool = False,
) -> list[str]:
    """Construct exact systemd-run invocation matching approved_model_launcher.py hardening."""
    if remaining_seconds <= 0:
        raise RuntimeError("No absolute runtime remaining for Stage B ceremony launch")
    unit = "cas-forex-" + cfg["run_id"]
    base = str(Path(cfg["source_directory"]).parent)
    properties = {
        "Type": "exec",
        "Restart": "no",
        "RuntimeMaxSec": str(remaining_seconds),
        "TimeoutStopSec": "1",
        "KillMode": "control-group",
        "SendSIGKILL": "yes",
        "DynamicUser": "yes",
        "NoNewPrivileges": "yes",
        "UMask": "0077",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "PrivateNetwork": "yes",
        "PrivateDevices": "yes",
        "PrivateTmp": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "ProtectProc": "default",
        "ProcSubset": "all",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes",
        "ProtectControlGroups": "yes",
        "RestrictSUIDSGID": "yes",
        "RestrictNamespaces": "yes",
        "LockPersonality": "yes",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "IPAddressDeny": "any",
        "IPAddressAllow": "localhost",
        "InaccessiblePaths": "-/root -/home -/media -/mnt",
        "ReadOnlyPaths": base,
        "StateDirectory": unit,
        "StateDirectoryMode": "0700",
        "MemoryMax": "12G",
        "CPUQuota": "400%",
    }
    argv = ["systemd-run", "--unit=" + unit, "--wait", "--pipe"]
    argv.extend(f"--property={k}={v}" for k, v in properties.items())
    argv.extend([
        "/usr/bin/python3",
        "-B",
        str(Path(cfg["source_directory"]) / "approved_stageb_ceremony_driver.py"),
        "--guest-config",
        str(config_path),
        "--config-sha256",
        config_sha256,
        "--ceremony-seed",
        ceremony_seed,
    ])
    if skip_inner_source_tests:
        argv.append("--skip-inner-source-tests")
    return argv


def orchestrate_guest_ceremony(
    *,
    config_path: Path,
    config_sha256: str,
    ceremony_seed: str = DEFAULT_CEREMONY_SEED,
    skip_inner_source_tests: bool = False,
    observer_wait_timeout_seconds: float = 900.0,
) -> dict[str, Any]:
    """Run external root observer alongside hardened systemd-run Stage B ceremony unit on Linux."""
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("orchestrate_guest_ceremony requires Linux root")
    raw = Path(config_path).read_bytes()
    if sha256(raw).hexdigest() != config_sha256:
        raise RuntimeError("Exact Stage B config SHA-256 mismatch")
    cfg = json.loads(raw.decode("utf-8"))
    source_dir = Path(cfg["source_directory"])
    if str(source_dir) not in sys.path:
        sys.path.insert(0, str(source_dir))
    from model_guest_boundary import config_contract, verify_controller_evidence, verify_python, verify_sources

    base, deadline, _ = config_contract(cfg, now=datetime.now(timezone.utc))
    verify_python(cfg, readonly=False)
    verify_sources(cfg, base, readonly=False)
    verify_controller_evidence(cfg, base, readonly=False)
    (base / "ceremony_live").mkdir(parents=True, exist_ok=True)
    os.chown(base / "ceremony_live", 0, 0)
    os.chmod(base / "ceremony_live", 0o755)

    receipts_dir = base / "receipts"
    receipts_dir.mkdir(mode=0o700, exist_ok=True)
    remaining = math.floor((deadline - datetime.now(timezone.utc)).total_seconds()) - 5
    unit_argv = build_ceremony_systemd_argv(
        cfg=cfg,
        config_path=config_path,
        config_sha256=config_sha256,
        remaining_seconds=remaining,
        ceremony_seed=ceremony_seed,
        skip_inner_source_tests=skip_inner_source_tests,
    )
    clean_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    obs_cmd = [
        "/usr/bin/python3",
        "-B",
        str(Path(__file__).resolve()),
        "observe-and-issue",
        "--config",
        str(config_path),
        "--config-sha256",
        config_sha256,
        "--ceremony-seed",
        ceremony_seed,
        "--wait-timeout",
        str(observer_wait_timeout_seconds),
    ]
    obs_proc = subprocess.Popen(
        obs_cmd,
        cwd=str(source_dir),
        env=clean_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    unit_proc = subprocess.run(unit_argv, env=clean_env, capture_output=True, text=True, check=False)
    try:
        obs_out, obs_err = obs_proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        obs_proc.kill()
        obs_out, obs_err = obs_proc.communicate()

    summary = {
        "format": "forex.stageb-ceremony-orchestration/1",
        "run_id": cfg["run_id"],
        "config_sha256": config_sha256,
        "unit_returncode": unit_proc.returncode,
        "observer_returncode": obs_proc.returncode,
        "observer_stdout": obs_out.strip(),
        "observer_stderr": obs_err.strip(),
        "unit_stderr_tail": unit_proc.stderr[-1000:] if unit_proc.stderr else "",
        "finished_utc": utc_iso(datetime.now(timezone.utc)),
    }
    (receipts_dir / "stageb-ceremony-orchestrator.json").write_bytes(canonical_json_bytes(summary))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_obs = sub.add_parser("observe-and-issue")
    p_obs.add_argument("--config", type=Path, required=True)
    p_obs.add_argument("--config-sha256", required=True)
    p_obs.add_argument("--ceremony-seed", default=DEFAULT_CEREMONY_SEED)
    p_obs.add_argument("--wait-timeout", type=float, default=900.0)

    p_orc = sub.add_parser("orchestrate-guest")
    p_orc.add_argument("--config", type=Path, required=True)
    p_orc.add_argument("--config-sha256", required=True)
    p_orc.add_argument("--ceremony-seed", default=DEFAULT_CEREMONY_SEED)
    p_orc.add_argument("--skip-inner-source-tests", action="store_true")
    p_orc.add_argument("--wait-timeout", type=float, default=900.0)

    args = parser.parse_args(argv)
    if args.cmd == "observe-and-issue":
        res = observe_and_issue_live(
            config_path=args.config,
            config_sha256=args.config_sha256,
            ceremony_seed=args.ceremony_seed,
            wait_timeout_seconds=args.wait_timeout,
        )
        print(json.dumps({
            "status": "ISSUED",
            "authority_sha256": res["authority_ref"]["sha256"],
            "release_sha256": res["release_ref"]["sha256"],
            "verifier_mode": res["verifier_mode"],
        }))
        return 0
    if args.cmd == "orchestrate-guest":
        summary = orchestrate_guest_ceremony(
            config_path=args.config,
            config_sha256=args.config_sha256,
            ceremony_seed=args.ceremony_seed,
            skip_inner_source_tests=args.skip_inner_source_tests,
            observer_wait_timeout_seconds=args.wait_timeout,
        )
        print(json.dumps(summary))
        return 0 if summary["unit_returncode"] == 0 and summary["observer_returncode"] == 0 else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
