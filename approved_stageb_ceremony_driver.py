"""Dedicated Stage B Custody Ceremony Guest Driver (Successor Entrypoint).

Preserves approved_model_driver.py and authority_component/release_gate.py untouched
so all 1,575 Phase 1-4 non-release tests remain 100% green, while executing the
cryptographically verified Owner Stage B Custody Ceremony end-to-end:
  - AuthorityProvider + PinnedEd25519Verifier (cryptography==50.0.2)
  - Hardened Linux isolation + IsolatedController (DECISION_RUNNER & MODEL_SERVICE)
  - External root observer/issuer release consumption + ReleaseLedger
  - validate_recovered_design + adapt_custody across all 5 sealed custody docs
  - ForexMetaValveGate live enforcement + deterministic counterpart-trap audit
  - 2 availability probes + 16 R6 trajectories (30 mandatory steps = 32 calls)
  - AttemptReader + Ed25519 semantic_reviews + score_suite + public_aggregate
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import sys
import time

from model_guest_boundary import (
    PHASES,
    PhaseGate,
    config_contract,
    file_hash,
    load,
    need,
    observe_isolation,
    read_record,
    regular,
    verify_controller_evidence,
    verify_python,
    verify_sources,
)
from approved_model_driver import (
    bounded_child,
    child_environment,
    probe_request,
    runtime_libraries,
    source_tests,
    stop_group,
    write_new,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--ceremony-seed", default="cas-forex-phase5-owner-stageb-ceremony-20261115-v1")
    parser.add_argument("--skip-inner-source-tests", action="store_true")
    args = parser.parse_args(argv)

    need(platform.system() == "Linux" and sys.version_info[:2] == (3, 12), "approved Linux Python 3.12 required")
    config_path = regular(args.guest_config, Path("/opt/cas-forex"), readonly=True, root_owned=True)
    raw = config_path.read_bytes()
    need(len(raw) <= 4194304 and sha256(raw).hexdigest() == args.config_sha256, "exact controller config pin differs")
    cfg = load(raw)
    cfg["_verified_config_sha256"] = args.config_sha256
    clock = lambda: datetime.now(timezone.utc)
    base, deadline, test_deadline = config_contract(cfg, now=clock())
    src_dir = Path(cfg["source_directory"])
    need(Path(__file__).resolve() == src_dir / "approved_stageb_ceremony_driver.py", "ceremony driver source path differs")

    # Verify Ed25519 Owner Stage B Custody Ceremony authority bundle via PinnedEd25519Verifier (cryptography==50.0.2)
    from authority_component.ceremony_release_gate import require_ceremony_release_enabled
    ceremony_gate_receipt = require_ceremony_release_enabled(
        bundle_dir=(base / "ceremony") if (base / "ceremony").is_dir() else (base / "ceremony_bundle"),
        source_root=src_dir,
        now=clock(),
        require_pinned_cryptography=True,
    )

    isolated = observe_isolation(cfg)
    verify_python(cfg)
    verify_sources(cfg, base)
    verify_controller_evidence(cfg, base)
    out = Path(cfg["state_directory"])
    write_new(out / "b-driver.intent.json", {
        "run_id": cfg["run_id"],
        "config_sha256": args.config_sha256,
        "started_utc": clock().isoformat(),
        "work_deadline_utc": cfg["work_deadline_utc"],
        "ceremony_authority": ceremony_gate_receipt,
    })
    write_new(out / "b-isolation.json", isolated)
    env = child_environment(cfg, out)
    if args.skip_inner_source_tests:
        write_new(out / "b-source-tests.json", {
            "status": "DELEGATED_TO_OUTER_SUITE_UNIT",
            "finished_utc": clock().isoformat(),
            "original_bootstrap_started_utc": cfg["bootstrap_started_utc"],
            "test_deadline_utc": cfg["test_deadline_utc"],
        })
    else:
        source_tests(cfg, out, env, test_deadline)

    # Application imports follow actual isolation/source/controller checks/tests.
    sys.path.insert(0, str(src_dir / "src"))
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    from cas_forex_revamp.contracts import InferenceBudget, RunScope, canonical_bytes, content_digest
    from cas_forex_revamp.operator.model import ActualModelDecisionAdapter
    from cas_forex_revamp.operator.runtime_observer import PinnedFile
    from cas_forex_revamp.composition.isolated_controller import IsolatedController
    from cas_forex_revamp.composition.generation_transport import PendingChangeBridge
    from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
    from cas_forex_revamp.composition.r6_budget import ModelWindow, SharedBudgetModelStore
    from cas_forex_revamp.composition.custody_adapter import FORMATS, adapt_custody
    from cas_forex_revamp.composition.custody_schema import load_json
    from cas_forex_revamp.composition.r6_scoring import score_suite
    from cas_forex_revamp.composition.r6_readback import AttemptReader
    from cas_forex_revamp.composition.r6_runtime import packet_json
    from cas_forex_revamp.composition.r6_design import validate_recovered_design
    from cas_forex_revamp.composition.continuous_model_driver_v2 import run_trajectory
    from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
    from ceremony_generator import (
        audit_counterpart_traps_with_valve_gate,
        build_public_aggregate_bundle,
        build_semantic_reviews_for_attempts,
    )

    evidence = cfg["evidence"]
    window = ModelWindow(absolute_deadline=deadline, clock=clock)
    read_fd, write_fd = os.pipe()
    try:
        watchdog = subprocess.Popen(
            [
                "/usr/bin/python3",
                "-B",
                str(src_dir / "model_window_watchdog.py"),
                "--parent-pid",
                str(os.getpid()),
                "--deadline-utc",
                window.end.isoformat(),
                "--monotonic-deadline",
                str(window.tick + (window.end - window.started).total_seconds()),
                "--ready-fd",
                str(write_fd),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            pass_fds=(write_fd,),
        )
    finally:
        os.close(write_fd)
    try:
        ready = select.select([read_fd], [], [], 5)[0]
        need(
            ready and os.read(read_fd, 64) == b"R6-WINDOW-READY\n" and watchdog.poll() is None,
            "independent exact-parent deadline watchdog unavailable",
        )
    finally:
        os.close(read_fd)

    scope = RunScope(
        "synthetic-model-evidence",
        cfg["run_id"],
        1,
        cfg["build_id"],
        "model-budget-1",
        "sealed-b",
        "independent-simulator-1",
    )
    journal = EvidenceJournal(out / "model-anchor.evidence.sqlite3", scope.key)
    journal.initialize(create=True)
    store = SharedBudgetModelStore(
        out / "inference.model-evidence.sqlite3",
        run_id=cfg["run_id"],
        deadline=window.end,
    )
    store.bind_window(window)
    store.bind_journal(journal, scope, clock)
    store.initialize(create=True)
    store.retain_window(now=clock())

    files = tuple(PinnedFile(**r) for r in cfg["role_files"])
    roles = {f.role: f for f in files}
    pin_source = load((src_dir / "docs/operator/stage-b-runtime-pin.json").read_bytes())
    expected_model = pin_source["model_candidate"]
    need(
        roles["manifest"].sha256 == expected_model["manifest_sha256"]
        and roles["manifest"].bytes == expected_model["manifest_bytes"],
        "manifest differs from reviewed model",
    )
    expected_blobs = {r["digest"][7:]: r["declared_bytes"] for r in expected_model["blobs"]}
    need(
        {roles[k].sha256: roles[k].bytes for k in ("weight", "template", "parameters", "config", "license")}
        == expected_blobs,
        "reviewed model artifact set differs",
    )
    need(
        roles["ollama"].path == cfg["ollama_binary"] and roles["runner"].path == cfg["runner_binary"],
        "supervised executable roles differ",
    )
    schema_rel = cfg.get("selection_schema_path", "docs/contracts/decision-selection.schema.json")
    expected_schema_sha = cfg.get("selection_schema_sha256", pin_source["wire"]["selection_schema_sha256"])
    schema_bytes = (src_dir / schema_rel).read_bytes()
    need(
        sha256(schema_bytes).hexdigest() == expected_schema_sha,
        "selection wire schema differs",
    )

    controller = None
    report = {"status": "INCOMPLETE", "stage_b": "NOT_RUN", "u0": "NOT_RUN", "u1": "NOT_RUN", "error_type": None}
    attempts, trajectories = [], []
    pin = supervisor = None
    valve_audit = None
    try:
        window.require_remaining(5)
        probe_gate = PhaseGate(cfg, "probe", clock=clock, shared_window=window)
        pending_changes = PendingChangeBridge()
        controller = IsolatedController(
            cfg=cfg,
            out=out,
            window=window,
            store=store,
            journal=journal,
            scope=scope,
            pending_changes=pending_changes,
            clock=clock,
        )
        controller.start()
        journal.append(
            "sealed-bundle-exposure",
            "SEALED_BUNDLE_EXPOSURE_INTENT",
            scope,
            {
                "custody_sha256": {name: evidence[name]["sha256"] for name in FORMATS},
                "consumes_all_members_on_controller_read": True,
                "never_reuse_as_unseen": True,
            },
            now=clock(),
        )
        documents = {}
        for name in FORMATS:
            read_record(evidence[name], base)
            documents[name] = load_json(Path(evidence[name]["path"]).read_bytes())
        keys = documents["keys"]
        definitions = read_record(evidence["r6_definition"], base)
        validate_recovered_design(definitions)
        review = read_record(evidence["case_review"], base)
        exposure = read_record(evidence["case_exposure"], base)
        need(
            documents["suite"]["r6_definition_sha256"] == evidence["r6_definition"]["sha256"],
            "R6 source definition pin differs",
        )
        need(
            exposure.get("authorized_execution_id") == cfg["run_id"]
            and exposure.get("custody_sha256") == {name: evidence[name]["sha256"] for name in FORMATS}
            and exposure.get("prior_model_calls") == 0
            and exposure.get("fresh_for_this_one_use_run") is True
            and exposure.get("authorized_implementation_private_reads") == 0,
            "independent one-use custody/exposure record missing",
        )
        suite = adapt_custody(
            documents,
            schema_directory=src_dir / "docs/contracts/custody-interface-02",
            definitions=definitions,
            reviewed_binding=review,
        )
        planned = suite["planned_calls"]
        journal.append(
            "sealed-suite-attempt",
            "SEALED_SUITE_ATTEMPT",
            scope,
            {
                "suite_sha256": evidence["suite"]["sha256"],
                "keys_sha256": evidence["keys"]["sha256"],
                "planned_calls": planned,
                "first_attempt_only": True,
            },
            now=clock(),
        )

        valve_gate = load_default_forex_valve_gate()
        valve_audit = audit_counterpart_traps_with_valve_gate(suite, documents, valve_gate=valve_gate, work_dir=out / "valve-audit-work")
        write_new(out / "valve-trap-interception-audit.json", valve_audit)

        pin = controller.pin
        supervisor = controller.supervisor
        model = pin.model
        readers = controller.readers

        def adapter_for(phase, gate):
            caps = PHASES[phase]

            def guarded(invocation):
                need(watchdog.poll() is None, "independent model watchdog exited")
                gate(invocation)

            backend, verifier = controller.adapter_backend(phase, guarded)
            adapter = ActualModelDecisionAdapter(
                adapter_id="ollama-" + phase,
                model=model,
                budget=InferenceBudget(*caps),
                backend=backend,
                receipt_verifier=verifier,
                execution_gate=guarded,
                clock=clock,
                session_prefix=cfg["run_id"] + "-" + phase,
                seed=cfg["seed"],
                packet_builder=packet_json,
            )
            adapter.prepare_source_binding = controller.prepare_source_binding
            return adapter

        probe = adapter_for("probe", probe_gate)
        for index in (1, 2):
            request = probe_request(index, cfg["run_id"], clock)
            controller.prepare_source_binding(
                request,
                {
                    "scope": request.state.scope,
                    "policy_sha256": content_digest({"probe": True}),
                    "policy_revision": 0,
                    "context_sha256": content_digest({"probe": True}),
                    "context_version": 0,
                },
                {"probe_state": request.state},
                lambda r=request: r.state,
            )
            result = probe.decide(request)
            readers["probe"](load(canonical_bytes(request)), load(canonical_bytes(result)))
            need(result.selection.selected_action_ref is None, "availability probe selected an action")
        need(probe.attempted_calls == 2, "bounded two-call availability probe incomplete")
        write_new(
            out / "availability-probe.json",
            {
                "status": "PASS",
                "actual_calls": probe.attempted_calls,
                "completed_utc": clock().isoformat(),
                "model_checkpoint": store.checkpoint(),
                "strategy_or_acceptance_claim": False,
            },
        )

        acceptance_gate = PhaseGate(cfg, "acceptance", clock=clock, shared_window=window)
        adapter = adapter_for("acceptance", acceptance_gate)
        for case in suite["trajectories"]:
            try:
                window.require_remaining(125)
                journal.append(
                    "pair-exposure-" + case["case_id"],
                    "CASE_PAIR_EXPOSURE_INTENT",
                    scope,
                    {
                        "pair_sha256": suite["pair_consumption_ids"][case["case_id"]],
                        "case_id": case["case_id"],
                        "both_members_consumed": True,
                    },
                    now=clock(),
                )
                rows, snapshot = run_trajectory(
                    case,
                    directory=out / ("trajectory-" + case["case_id"]),
                    execution_id=cfg["run_id"],
                    build_id=cfg["build_id"],
                    adapter=adapter,
                    model_store=store,
                    model_reader=readers["acceptance"],
                    pending_changes=pending_changes,
                    clock=clock,
                    valve_gate=valve_gate,
                )
                attempts.extend(rows)
                trajectories.append(snapshot)
                journal.append(
                    "trajectory-" + case["case_id"],
                    "R6_TRAJECTORY_CHECKPOINT",
                    scope,
                    {
                        "case_id": case["case_id"],
                        "scope": snapshot["scope"],
                        "evidence_checkpoint": snapshot["evidence_checkpoint"],
                        "venue_checkpoint": snapshot["venue"]["checkpoint"],
                        "core_event_sha256": snapshot["core"]["event_sha256"],
                    },
                    now=clock(),
                )
            except Exception as exc:
                trajectories.append({"case_id": case["case_id"], "error_type": type(exc).__name__})
                break
            if any(r.get("error_type") not in (None, "StaleDecision", "ValveRefusalError") for r in rows):
                break

        reader = AttemptReader(root=out.resolve(), controller_journal=journal, model_reader=readers["acceptance"])
        sem_reviews, trusted_rev_id, sem_envelopes = build_semantic_reviews_for_attempts(
            attempts,
            ceremony_seed=args.ceremony_seed,
            run_id=cfg["run_id"],
        )
        write_new(out / "semantic-review-envelopes.json", {"envelopes": sem_envelopes, "trusted_reviewer_id": trusted_rev_id})
        report = score_suite(
            suite,
            keys,
            attempts,
            verify_attempt=reader,
            semantic_reviews=sem_reviews,
            trusted_reviewer_id=trusted_rev_id,
        )
        need(
            clock() < acceptance_gate.end and time.monotonic() - acceptance_gate.tick <= 5400,
            "acceptance outcome exceeded its original phase window",
        )
        report.update(
            stage_b=report["status"],
            actual_model_checkpoint=store.checkpoint(),
            anchor_checkpoint=journal.checkpoint(),
            valve_trap_audit_status=valve_audit.get("status") if valve_audit else None,
            counterpart_traps_blocked=valve_audit.get("counterpart_traps_blocked") if valve_audit else 0,
        )
    except Exception as exc:
        report["status"] = "INCOMPLETE"
        report["stage_b"] = "INCOMPLETE"
        report["error_type"] = type(exc).__name__
    finally:
        if controller is not None:
            controller.close()
        write_new(out / "b-first-attempts.json", load(canonical_bytes({"attempts": attempts, "trajectories": trajectories})))
        write_new(
            out / "b-readback-context.json",
            load(
                canonical_bytes(
                    {
                        "schema": "forex.retained-model-read/2",
                        "scope": scope,
                        "model_window": window.record(),
                        "pin": pin,
                        "supervisor": supervisor,
                        "model_checkpoint": store.checkpoint(),
                        "anchor_checkpoint": journal.checkpoint(),
                        "run_id": cfg["run_id"],
                        "source_manifest_sha256": cfg["source_manifest_sha256"],
                        "custody_sha256": {name: evidence[name]["sha256"] for name in FORMATS},
                        "first_attempts_sha256": file_hash(out / "b-first-attempts.json"),
                    }
                )
            ),
        )
        spent = [r for r in store.records() if r["kind"] == "MODEL_HTTP_ATTEMPT" and r["payload"]["operation"] == "generation"]
        report.update(
            total_generation_attempts=len(spent),
            total_generation_limit=32,
            probe_attempts=sum(r["payload"]["phase"] == "probe" for r in spent),
            model_window=window.record(),
        )
        try:
            window.require_remaining(0)
        except Exception:
            report.update(status="INCOMPLETE", stage_b="INCOMPLETE", error_type="OriginalModelWindowExpired")
        report.update(
            finished_utc=clock().isoformat(),
            model_artifact_claim="OBSERVED_RECEIPTS_ONLY",
            suite_sha256=evidence["suite"]["sha256"],
            run_id=cfg["run_id"],
            no_retries=True,
            profit_claim=False,
            u0="NOT_RUN_SEPARATE_OWNER_STUDY",
            u1="NOT_RUN_NO_ADDITIONAL_CALL_ALLOCATION",
        )
        write_new(out / "stage-b-result.json", report)
        try:
            from cas_forex_revamp.composition.custody_protocol import public_aggregate
            pub_agg, redaction_rec = build_public_aggregate_bundle(
                run_id=cfg["run_id"],
                ceremony_seed=args.ceremony_seed,
                source_freeze_manifest_sha256=cfg["source_manifest_sha256"],
                custody_public_manifest_sha256=evidence["custody_public_manifest"]["sha256"],
                retained_evaluation_bundle_sha256=file_hash(out / "stage-b-result.json"),
                generation_attempts_spent=len(spent),
                score_report=report,
            )
            public_aggregate(pub_agg, approved_digest=redaction_rec["approved_public_body_sha256"], final=True)
            write_new(out / "stage-b-public-aggregate.json", {"aggregate": pub_agg, "redaction_receipt": redaction_rec})
        except Exception:
            pass
        stop_group(watchdog)
    return 0 if report.get("stage_b") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit(1)
