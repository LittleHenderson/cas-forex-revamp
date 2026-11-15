"""Finite durable A rehearsal. Nothing runs until an explicit phase call/CLI.

This is scripted preparation with a labeled synthetic owner. It is not the
interactive owner's authentication path, actual-model B, or trading evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import subprocess
import sys

from ..contracts import (
    ActionIntent, ActionKind, ActionOption, CommandState, ContractError, ControlKind,
    DecisionFact, DecisionOrigin, DecisionRequest, DecisionSelection, EffectState,
    EvidenceKind, EvidenceReference, FenceRequest, NewRiskPermission, Side,
    canonical_bytes, content_digest,
)
from ..core import CoreCheckpoint, InstrumentPolicy, OutcomeUnknown, RiskPolicy
from ..core.storage import decode
from ..operator.adapters import ScriptedDecisionAdapter, ScriptStep
from ..operator.decisions import OperatorSession
from ..venue import FaultSchedule, JournalCheckpoint
from .application import RuntimeConfig
from .assembly import assemble_inert_simulation
from .evidence_journal import EvidenceJournal
from .owner_requests import OwnerRequestBook
from .synthetic_fixture import continuous_a_fixture


class SyntheticClock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class NoImplicitDecision:
    def decide(self, request):
        raise ContractError("a specific finite script step must be supplied explicitly")


class KillAfterAcceptance(FaultSchedule):
    """Only an explicitly selected child-process negative/fault test uses this."""
    def hit(self, point: str) -> None:
        if point == "accept.after_commit":
            os._exit(73)
        super().hit(point)


def _write_new(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(canonical_bytes(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())


def _mark(journal, scope, clock, checkpoint, condition, **observed):
    journal.append("check-" + checkpoint, "ACCEPTANCE_CHECK", scope,
                   {"checkpoint": checkpoint, "status": "PASS" if condition else "FAIL",
                    "observed": observed}, now=clock())
    if not condition:
        raise ContractError("continuous A assertion failed: " + checkpoint)


def _assemble(root, scope, clock, *, faults=None, venue_anchor=None):
    fixture = continuous_a_fixture()
    owner = OwnerRequestBook(scope, controls=frozenset(ControlKind), reviewed_close=True)
    app = assemble_inert_simulation(
        RuntimeConfig(scope, root), policy=RiskPolicy("USD", Decimal("100")),
        instruments=(InstrumentPolicy(fixture.instruments[0], Decimal("2")),),
        decision_adapter=NoImplicitDecision(), clock=clock, owner_verifier=owner,
        faults=faults, venue_checkpoint=venue_anchor,
        minimum_venue_sequence=venue_anchor.sequence if venue_anchor else 0,
    )
    journal = EvidenceJournal(root / "account.evidence.sqlite3", scope.key)
    return app, owner, journal


def _control(app, owner, journal, clock, kind, request_id):
    fence = app.venue.snapshot(app.config.scope.key, now=clock()).fence
    request = FenceRequest(app.config.scope.key, "barrier-" + request_id, kind,
                           request_id, fence.generation, fence.generation + 1, clock())
    owner.register(request, request_id=request_id, now=clock())
    observation = app.wiring.control(request)
    journal.append(request_id, "CONTROL", app.config.scope,
                   {"request": request, "readback": observation}, now=clock())
    if not observation.confirmed:
        raise ContractError("scripted control not independently confirmed")
    app.wiring.observe()
    return observation


def _request(app, clock, decision_id, *, kind=ActionKind.OPEN, quantity=Decimal("10")):
    scope = app.config.scope
    state = app.core.current_state(scope.key, now=clock())
    snapshot = app.venue.snapshot(scope.key, now=clock())
    instrument = continuous_a_fixture().instruments[0]
    evidence = EvidenceReference("observation-" + decision_id, EvidenceKind.OBSERVATION,
                                 "independent-simulator-1", content_digest(snapshot), snapshot.observed_at)
    fact = DecisionFact("fact-" + decision_id, "Synthetic observed context",
                        "Choose only supplied bounded actions; no future quote is supplied.", (evidence.evidence_id,))
    target = snapshot.positions[0] if kind is not ActionKind.OPEN else None
    def intent(ref, action, amount, *, limit=None, stop=None):
        return ActionIntent("intent-" + ref, scope, decision_id, "opportunity-" + ref, ref,
                            state, action, instrument.instrument_id, DecisionOrigin.SCRIPTED,
                            clock(), state.valid_until, quantity=amount,
                            side=Side.BUY if action is ActionKind.OPEN else None,
                            target_id=target.position_id if target else None,
                            target_version=target.version if target else None,
                            limit_price=limit, stop_price=stop)
    if kind is ActionKind.OPEN:
        first = intent(decision_id + "-h1", kind, quantity, limit=Decimal("1.1010"), stop=Decimal("1.0900"))
        other = intent(decision_id + "-h4", kind, Decimal("8"), limit=Decimal("1.1020"), stop=Decimal("1.0900"))
    else:
        first = intent(decision_id + "-selected", kind, quantity)
        other = intent(decision_id + "-protect", ActionKind.AMEND_STOP, None, stop=Decimal("1.0980"))
    request = DecisionRequest("request-" + decision_id, "set-" + decision_id, state,
                              (ActionOption(first.action_ref, "strategy-a", "H1", "Selected scripted option", first),
                               ActionOption(other.action_ref, "strategy-b", "H4", "Alternative bounded option", other)),
                              (fact,), (evidence,))
    return request, snapshot


def _propose(app, journal, clock, decision_id, **kwargs):
    request, snapshot = _request(app, clock, decision_id, **kwargs)
    journal.append("input-" + decision_id, "DECISION_INPUT", app.config.scope,
                   {"request": request, "observation": snapshot}, now=clock())
    selection = DecisionSelection(request.request_id, request.opportunity_set_id,
                                   request.state.state_id, request.options[0].action_ref,
                                   "Finite scripted A choice; no model or strategy-edge claim.",
                                   (request.evidence[0].evidence_id,))
    adapter = ScriptedDecisionAdapter((ScriptStep(content_digest(request), selection),),
                                      adapter_id="continuous-a-script", clock=clock)
    session = OperatorSession(adapter, current_state=lambda: app.core.current_state(app.config.scope.key, now=clock()),
                              clock=clock, max_decisions=1)
    proposal = session.tick(request)
    journal.append("decision-" + decision_id, "DECISION", app.config.scope,
                   {"request": request, "result": proposal.result,
                    "core_cursor": app.core.checkpoint(app.config.scope.key)}, now=clock())
    return proposal


def _admit(app, journal, clock, proposal, command_id):
    view = app.wiring.admit(proposal, command_id=command_id)
    journal.append("admission-" + command_id, "ADMISSION", app.config.scope,
                   {"decision_id": proposal.result.decision_id, "command": view}, now=clock())
    if view is None or view.state is not CommandState.QUEUED:
        raise ContractError("scripted command was not queued: " + str(view))
    return view


def prepare_phase(root: Path, *, kill_after_commit=False) -> dict:
    root = Path(root)
    if not root.is_absolute() or root.is_symlink():
        raise ContractError("explicit absolute non-symlink synthetic workspace required")
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ContractError("new rehearsal requires an empty workspace; existing files preserved")
    fixture = continuous_a_fixture()
    clock = SyntheticClock(fixture.started_at)
    faults = KillAfterAcceptance() if kill_after_commit else FaultSchedule()
    app, owner, journal = _assemble(root, fixture.scope, clock, faults=faults)
    journal.initialize(create=True)
    app.venue.initialize(fixture.scope.key, opening_balance=fixture.opening_balance,
                         instruments=fixture.instruments, now=clock(), scenario=fixture.venue_scenario)
    app.core.initialize(create=True)
    _mark(journal, fixture.scope, clock, "A00", not app.core.inspect(fixture.scope.key, now=clock()).admissions_enabled
          and app.core_path != app.venue_path,
          separate_paths=app.core_path != app.venue_path)
    clock.now = fixture.market[0].available_at
    first = app.wiring.advance_market(fixture.market[0])
    _mark(journal, fixture.scope, clock, "A01", first.positions == (), balance=first.balance)
    _control(app, owner, journal, clock, ControlKind.STOP_AUTOMATION, "a-startup-stop")
    _control(app, owner, journal, clock, ControlKind.RESUME_NEW_RISK, "a-resume-risk")
    _mark(journal, fixture.scope, clock, "A02", app.core.inspect(fixture.scope.key, now=clock()).admissions_enabled)
    proposal = _propose(app, journal, clock, "a-entry-decision")
    _mark(journal, fixture.scope, clock, "A03", len(proposal.request.options) == 2,
          origin=proposal.result.provenance.origin, wait_available=True)
    queued = _admit(app, journal, clock, proposal, fixture.entry_command_id)
    _mark(journal, fixture.scope, clock, "A04", queued.reservation_held, command=queued)
    if not kill_after_commit:
        faults.arm("accept.after_commit")
    try:
        app.wiring.dispatch_once()
    except OutcomeUnknown:
        pass
    else:
        raise ContractError("expected committed-acceptance lost reply did not occur")
    lookup = app.venue.lookup(fixture.scope.key, fixture.entry_command_id)
    record = app.core.read_snapshot(fixture.scope.key).commands[0]
    _mark(journal, fixture.scope, clock, "A05", lookup.receipt.effect is EffectState.ACKNOWLEDGED
          and record.reservation_held and record.state is CommandState.UNRESOLVED,
          independent_receipt=lookup.receipt, core_state=record.state)
    _control(app, owner, journal, clock, ControlKind.PAUSE_NEW_RISK, "a-pause-uncertain")
    _mark(journal, fixture.scope, clock, "A06", not app.venue.snapshot(fixture.scope.key, now=clock()).fence.new_risk_allowed)
    clock.now = fixture.market[1].available_at
    partial = app.wiring.advance_market(fixture.market[1])
    receipt = app.venue.lookup(fixture.scope.key, fixture.entry_command_id).receipt
    _mark(journal, fixture.scope, clock, "A07", len(partial.positions) == 1
          and partial.positions[0].quantity == Decimal("4") and receipt.quantities.remaining == Decimal("6"),
          position=partial.positions[0], receipt=receipt)
    handoff = {"scope": fixture.scope, "now": clock(), "core_checkpoint": app.core.checkpoint(fixture.scope.key),
               "venue_checkpoint": app.venue.inspect_journal(fixture.scope.key)[-1],
               "evidence_checkpoint": journal.checkpoint(), "position_id": partial.positions[0].position_id}
    _write_new(root / "phase-1-anchors.json", handoff)
    return json.loads(canonical_bytes(handoff))


def resume_phase(root: Path) -> dict:
    root = Path(root)
    raw = json.loads((root / "phase-1-anchors.json").read_text(encoding="utf-8"))
    fixture = continuous_a_fixture()
    old_scope = decode(json.dumps(raw["scope"]), type(fixture.scope))
    if old_scope.key != fixture.scope.key:
        raise ContractError("handoff belongs to a different synthetic run")
    scope = replace(old_scope, epoch=old_scope.epoch + 1)
    clock = SyntheticClock(datetime.fromisoformat(raw["now"].replace("Z", "+00:00")))
    venue_anchor = decode(json.dumps(raw["venue_checkpoint"]), JournalCheckpoint)
    app, owner, journal = _assemble(root, scope, clock, venue_anchor=venue_anchor)
    journal.initialize(expected_checkpoint=tuple(raw["evidence_checkpoint"]))
    app.core.initialize(expected_checkpoint=decode(json.dumps(raw["core_checkpoint"]), CoreCheckpoint))
    recovered = app.wiring.observe()
    _mark(journal, scope, clock, "A08", not recovered.admissions_enabled
          and recovered.permissions.new_risk is NewRiskPermission.UNKNOWN, recovered=recovered)
    position = recovered.positions[0]
    receipt = app.venue.lookup(scope.key, fixture.entry_command_id).receipt
    _mark(journal, scope, clock, "A09", position.position_id == raw["position_id"]
          and position.quantity == Decimal("4") and receipt.quantities.remaining == Decimal("6"), receipt=receipt)
    # Observation is automatic; establishment of a new session fence is explicit.
    _control(app, owner, journal, clock, ControlKind.STOP_AUTOMATION, "a-restart-stop")
    stale = _propose(app, journal, clock, "a-stale-management", kind=ActionKind.CLOSE, quantity=Decimal("4"))
    clock.now = fixture.market[2].available_at
    full = app.wiring.advance_market(fixture.market[2])
    stale_rejected = False
    try:
        app.wiring.admit(stale, command_id="a-stale-never-admitted")
    except ContractError:
        stale_rejected = True
    journal.append("stale-a-management", "STALE_DECISION", scope,
                   {"decision_id": stale.result.decision_id, "rejected": stale_rejected}, now=clock())
    _mark(journal, scope, clock, "A10", stale_rejected and full.positions[0].quantity == Decimal("10")
          and full.positions[0].position_id == raw["position_id"],
          same_position=full.positions[0].position_id == raw["position_id"])
    _control(app, owner, journal, clock, ControlKind.RESUME_MANAGEMENT, "a-resume-management")
    fence = app.venue.snapshot(scope.key, now=clock()).fence
    _mark(journal, scope, clock, "A11", fence.management_allowed and not fence.new_risk_allowed, fence=fence)
    reduction = _propose(app, journal, clock, "a-reduce-decision", kind=ActionKind.REDUCE, quantity=Decimal("4"))
    queued = _admit(app, journal, clock, reduction, fixture.reduce_command_id)
    _mark(journal, scope, clock, "A12", queued.reservation_held, command=queued)
    app.wiring.dispatch_once()
    clock.now = fixture.market[3].available_at
    reduced = app.wiring.advance_market(fixture.market[3])
    _mark(journal, scope, clock, "A13", reduced.positions[0].quantity == Decimal("6"), projection=reduced)
    close = _propose(app, journal, clock, "a-close-decision", kind=ActionKind.CLOSE, quantity=Decimal("6"))
    queued = _admit(app, journal, clock, close, fixture.close_command_id)
    _mark(journal, scope, clock, "A14", queued.reservation_held, command=queued)
    app.wiring.dispatch_once()
    clock.now = fixture.market[4].available_at
    final = app.wiring.advance_market(fixture.market[4])
    final_receipt = app.venue.lookup(scope.key, fixture.close_command_id).receipt
    _mark(journal, scope, clock, "A15", final.positions == () and final_receipt.effect is EffectState.FILLED,
          final_projection=final, receipt=final_receipt)
    checks = [x.payload for x in journal.records() if x.kind == "ACCEPTANCE_CHECK"]
    expected = {f"A{i:02}" for i in range(16)}
    if len(checks) != 16 or {x["checkpoint"] for x in checks} != expected or any(x["status"] != "PASS" for x in checks):
        raise ContractError("missing, duplicated or failed A checkpoint")
    report = {"kind": "SCRIPTED_CONTINUOUS_A", "status": "PASS", "checks": checks,
              "core_checkpoint": app.core.checkpoint(scope.key),
              "venue_checkpoint": app.venue.inspect_journal(scope.key)[-1],
              "evidence_checkpoint": journal.checkpoint(), "actual_model": False,
              "economic_edge_claim": False, "scope": scope}
    _write_new(root / "continuous-a-result.json", report)
    return json.loads(canonical_bytes(report))


def run_two_processes(root: Path, *, timeout_seconds=120) -> dict:
    """Explicit parent harness: separate Python processes and persistent stores."""
    for phase in ("prepare", "resume"):
        subprocess.run([sys.executable, "-m", "cas_forex_revamp.composition.continuous_driver", phase, str(root)], check=True,
                       timeout=timeout_seconds, capture_output=True, text=True)
    return json.loads((root / "continuous-a-result.json").read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "resume", "run", "kill-after-accept"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.phase == "prepare":
        prepare_phase(args.directory)
    elif args.phase == "resume":
        resume_phase(args.directory)
    elif args.phase == "kill-after-accept":
        prepare_phase(args.directory, kill_after_commit=True)
    else:
        run_two_processes(args.directory)


if __name__ == "__main__":
    main()
