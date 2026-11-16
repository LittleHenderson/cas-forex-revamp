"""Security remediation regressions for Finding [4] (atomic source-cursor equality)
and Finding [8] (systemd-run cgroup and rlimit ceilings with fail-closed readiness).
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _rel in (
    "src",
    "",
    "shared-interface",
    "operational/measurement/source",
    "operational/authority/source",
    "operational/custody/source",
    "source_runtime",
):
    _candidate = str((_REPO_ROOT / _rel).resolve())
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

from cas_forex_operational_contracts.common import (
    ContractError as OperationalContractError,
    canonical_bytes,
    digest,
)
from cas_forex_measurement.completion import (
    ForkExecCapture,
    MEASUREMENT_SYSTEMD_CGROUP_PROPERTIES,
    measurement_systemd_command,
    validate_measurement_unit_ready,
)
from cas_forex_revamp.contracts import (
    AccountRunKey,
    ActionIntent,
    ActionKind,
    AuthorizedCommand,
    CommandState,
    ContractError,
    ControlKind,
    DecisionOrigin,
    EffectState,
    FenceRequest,
    Instrument,
    MarketObservation,
    Money,
    RecoveryState,
    RunScope,
    Side,
    StateReference,
    content_digest,
    intent_digest,
)
from cas_forex_revamp.core import (
    AdmissionDenied,
    CoreCoordinator,
    InstrumentPolicy,
    OwnerApproval,
    RiskPolicy,
    SQLiteStore,
)
from cas_forex_revamp.venue import IdentityConflict, SQLiteVenue, VenueScenario
import launch_common as lc
import source_test_launcher as launcher


START = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
KEY = AccountRunKey("sec-remediation-account", "sec-remediation-run")
SCOPE = RunScope(
    KEY.account_id,
    KEY.run_id,
    1,
    "sec-build-4-8",
    "sec-policy",
    "sec-scenario",
    "scripted",
)
INSTRUMENT = Instrument("EURUSD", "EUR/USD", "EUR", "USD", D("0.0001"), D("1"), D("1"))


def _at(seconds: int = 0) -> datetime:
    return START + timedelta(seconds=seconds)


def _raw_command(
    name: str,
    *,
    kind: ActionKind = ActionKind.OPEN,
    generation: int = 2,
    state_version: int = 0,
    venue_sequence: int = 0,
    quantity: str | None = "10",
    side: Side | None = Side.BUY,
    target_id: str | None = None,
    target_version: int | None = None,
    limit_price: str | None = "1.1005",
    stop_price: str | None = None,
    ceiling: str | None = "2.0000",
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> AuthorizedCommand:
    if kind in (ActionKind.AMEND_STOP, ActionKind.CANCEL_ORDER):
        quantity = None
        limit_price = None
    if kind in (ActionKind.REDUCE, ActionKind.CLOSE):
        limit_price = None
    state = StateReference(
        f"state-{name}-{state_version}-{venue_sequence}",
        SCOPE,
        state_version,
        START,
        _at(86400),
        venue_sequence,
    )
    intent_side = (
        side
        if kind is ActionKind.OPEN
        else (side if kind not in (ActionKind.AMEND_STOP, ActionKind.CANCEL_ORDER) else None)
    )
    intent = ActionIntent(
        f"intent-{name}",
        SCOPE,
        f"decision-{name}",
        f"opp-{name}",
        f"action-{name}",
        state,
        kind,
        INSTRUMENT.instrument_id,
        DecisionOrigin.SCRIPTED,
        created_at or START,
        expires_at or _at(3600),
        None if quantity is None else D(quantity),
        intent_side,
        target_id,
        target_version,
        None if limit_price is None else D(limit_price),
        None if stop_price is None else D(stop_price),
    )
    risk_ceiling = D(ceiling) if kind in (ActionKind.OPEN, ActionKind.ADD) and ceiling is not None else None
    return AuthorizedCommand(
        name,
        intent,
        intent_digest(intent),
        f"reservation-{name}",
        f"authority-{name}",
        generation,
        "core-writer",
        risk_ceiling,
    )


def _market(
    seq: int,
    *,
    bid: str = "1.1000",
    ask: str = "1.1002",
    seconds: int | None = None,
) -> MarketObservation:
    ts = _at(seq * 5 if seconds is None else seconds)
    return MarketObservation(KEY, f"mkt-{seq}", INSTRUMENT.instrument_id, seq, ts, ts, D(bid), D(ask))


class _OwnerFixture:
    def __init__(self, scope: RunScope) -> None:
        self.scope = scope
        self.command_ids: dict[str, str] = {}

    def verify(self, subject: ActionIntent | FenceRequest, *, now: datetime) -> OwnerApproval:
        is_control = isinstance(subject, FenceRequest)
        return OwnerApproval(
            subject.owner_request_id if is_control else "review-" + subject.intent_id,
            self.scope,
            content_digest(subject),
            now,
            now + timedelta(seconds=30),
            None if is_control else self.command_ids[subject.intent_id],
        )


class Finding4AtomicSourceCursorRemediationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cas-sec-f4-")
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _init_raw_venue(
        self,
        filename: str = "raw.venue.sqlite3",
        *,
        strict: bool = False,
        scenario: VenueScenario = VenueScenario(),
    ) -> SQLiteVenue:
        venue = SQLiteVenue(self.dir / filename, strict_source_cursor=strict)
        venue.initialize(
            KEY,
            opening_balance=Money(D("10000.00"), "USD"),
            instruments=(INSTRUMENT,),
            now=START,
            scenario=scenario,
        )
        venue.advance_fence(FenceRequest(KEY, "b-1", ControlKind.RESUME_NEW_RISK, "owner-1", 0, 1, START), now=START)
        venue.advance_fence(FenceRequest(KEY, "b-2", ControlKind.RESUME_MANAGEMENT, "owner-2", 1, 2, START), now=START)
        return venue

    def _init_core_and_venue(
        self,
        prefix: str = "lane",
        *,
        fill_limit: D | None = None,
    ) -> tuple[CoreCoordinator, SQLiteVenue, datetime]:
        now = START
        venue = SQLiteVenue(self.dir / f"{prefix}.venue.sqlite3")
        owner = _OwnerFixture(SCOPE)
        core = CoreCoordinator(
            scope=SCOPE,
            store=SQLiteStore(self.dir / f"{prefix}.core.sqlite3"),
            venue=venue,
            policy=RiskPolicy("USD", D("100.00")),
            instruments=(InstrumentPolicy(INSTRUMENT, D("2.0000")),),
            owner_verifier=owner,
        )
        venue.owner_close_verifier = core.verify_owner_close
        venue.initialize(
            SCOPE.key,
            opening_balance=Money(D("1000.00"), "USD"),
            instruments=(INSTRUMENT,),
            now=now,
            scenario=VenueScenario(fill_limit_per_order=fill_limit),
        )
        venue.advance_market(_market(1, bid="1.1000", ask="1.1002", seconds=0))
        core.initialize(create=True)
        core.reconcile(SCOPE.key, now=now)
        for ctrl in (ControlKind.PAUSE_NEW_RISK, ControlKind.RESUME_NEW_RISK, ControlKind.RESUME_MANAGEMENT):
            fence = venue.snapshot(SCOPE.key, now=now).fence
            req = FenceRequest(
                SCOPE.key,
                f"{prefix}-barrier-{fence.generation + 1}",
                ctrl,
                f"{prefix}-owner-{fence.generation + 1}",
                fence.generation,
                fence.generation + 1,
                now,
            )
            core.control(req, now=now)
            core.reconcile(SCOPE.key, now=now)
        return core, venue, now

    @staticmethod
    def _core_intent(
        core: CoreCoordinator,
        name: str,
        now: datetime,
        *,
        kind: ActionKind = ActionKind.OPEN,
        quantity: str | None = "5",
        side: Side | None = Side.BUY,
        target_id: str | None = None,
        target_version: int | None = None,
        limit_price: str | None = "1.1005",
        stop_price: str | None = None,
    ) -> ActionIntent:
        state = core.current_state(SCOPE.key, now=now)
        return ActionIntent(
            f"intent-{name}",
            SCOPE,
            f"decision-{name}",
            "opp",
            f"action-{name}",
            state,
            kind,
            INSTRUMENT.instrument_id,
            DecisionOrigin.SCRIPTED,
            now,
            now + timedelta(seconds=20),
            None if quantity is None else D(quantity),
            side if kind is ActionKind.OPEN else None,
            target_id,
            target_version,
            None if limit_price is None else D(limit_price),
            None if stop_price is None else D(stop_price),
        )

    def test_raw_zero_cursor_fixtures_remain_compatible_unless_strict_cursor_enabled(self) -> None:
        with self.assertRaises(ContractError):
            SQLiteVenue(self.dir / "bad.venue.sqlite3", strict_source_cursor="yes")  # type: ignore[arg-type]

        default_venue = self._init_raw_venue("compat.venue.sqlite3", strict=False)
        default_venue.advance_market(_market(1, seconds=5))
        raw_ack = default_venue.accept(_raw_command("compat-open", state_version=0, venue_sequence=0), now=_at(5))
        self.assertEqual(raw_ack.effect, EffectState.ACKNOWLEDGED)

        strict_venue = self._init_raw_venue("strict.venue.sqlite3", strict=True)
        strict_rejected = strict_venue.accept(_raw_command("strict-open", state_version=0, venue_sequence=0), now=START)
        self.assertEqual(strict_rejected.effect, EffectState.REJECTED)
        self.assertEqual(strict_rejected.reason_code, "STALE_SOURCE_CURSOR")

    def test_future_source_cursor_preserved_and_checked_before_stale_cursor(self) -> None:
        venue = self._init_raw_venue("future.venue.sqlite3")
        current_seq = venue.snapshot(KEY, now=START).sequence
        future_cmd = _raw_command("future-open", state_version=1, venue_sequence=current_seq + 5)
        future_receipt = venue.accept(future_cmd, now=START)
        self.assertEqual(future_receipt.effect, EffectState.REJECTED)
        self.assertEqual(future_receipt.reason_code, "FUTURE_SOURCE_CURSOR")

    def test_all_risk_changing_actions_enforce_exact_source_cursor_equality(self) -> None:
        venue = self._init_raw_venue("exact.venue.sqlite3")
        seq0 = venue.snapshot(KEY, now=START).sequence

        stale_open = _raw_command("stale-open", kind=ActionKind.OPEN, state_version=1, venue_sequence=seq0 - 1)
        r_stale_open = venue.accept(stale_open, now=START)
        self.assertEqual((r_stale_open.effect, r_stale_open.reason_code), (EffectState.REJECTED, "STALE_SOURCE_CURSOR"))

        seq1 = venue.snapshot(KEY, now=START).sequence
        exact_open = _raw_command(
            "exact-open",
            kind=ActionKind.OPEN,
            state_version=1,
            venue_sequence=seq1,
            stop_price="1.0900",
        )
        r_open = venue.accept(exact_open, now=START)
        self.assertEqual(r_open.effect, EffectState.ACKNOWLEDGED)

        snap = venue.advance_market(_market(1, bid="1.1000", ask="1.1002", seconds=5))
        self.assertEqual(len(snap.positions), 1)
        pos = snap.positions[0]
        stale_seq = snap.sequence - 1

        stale_add = _raw_command(
            "stale-add",
            kind=ActionKind.ADD,
            state_version=2,
            venue_sequence=stale_seq,
            quantity="5",
            side=Side.BUY,
            target_id=pos.position_id,
            target_version=pos.version,
        )
        r_stale_add = venue.accept(stale_add, now=_at(5))
        self.assertEqual((r_stale_add.effect, r_stale_add.reason_code), (EffectState.REJECTED, "STALE_SOURCE_CURSOR"))

        stale_amend = _raw_command(
            "stale-amend",
            kind=ActionKind.AMEND_STOP,
            state_version=2,
            venue_sequence=stale_seq,
            side=None,
            target_id=pos.position_id,
            target_version=pos.version,
            stop_price="1.0950",
        )
        r_stale_amend = venue.accept(stale_amend, now=_at(5))
        self.assertEqual((r_stale_amend.effect, r_stale_amend.reason_code), (EffectState.REJECTED, "STALE_SOURCE_CURSOR"))

        stale_reduce = _raw_command(
            "stale-reduce",
            kind=ActionKind.REDUCE,
            state_version=2,
            venue_sequence=stale_seq,
            quantity="4",
            side=Side.SELL,
            target_id=pos.position_id,
            target_version=pos.version,
        )
        r_stale_reduce = venue.accept(stale_reduce, now=_at(5))
        self.assertEqual((r_stale_reduce.effect, r_stale_reduce.reason_code), (EffectState.REJECTED, "STALE_SOURCE_CURSOR"))

        stale_close = _raw_command(
            "stale-close",
            kind=ActionKind.CLOSE,
            state_version=2,
            venue_sequence=stale_seq,
            quantity="10",
            side=Side.SELL,
            target_id=pos.position_id,
            target_version=pos.version,
        )
        r_stale_close = venue.accept(stale_close, now=_at(5))
        self.assertEqual((r_stale_close.effect, r_stale_close.reason_code), (EffectState.REJECTED, "STALE_SOURCE_CURSOR"))

        exact_seq = venue.snapshot(KEY, now=_at(5)).sequence
        exact_amend = _raw_command(
            "exact-amend",
            kind=ActionKind.AMEND_STOP,
            state_version=3,
            venue_sequence=exact_seq,
            side=None,
            target_id=pos.position_id,
            target_version=pos.version,
            stop_price="1.0950",
        )
        r_exact_amend = venue.accept(exact_amend, now=_at(5))
        self.assertEqual(r_exact_amend.effect, EffectState.APPLIED)

        pending_seq = venue.snapshot(KEY, now=_at(5)).sequence
        pending_open = _raw_command(
            "pending-open",
            kind=ActionKind.OPEN,
            state_version=4,
            venue_sequence=pending_seq,
            limit_price="1.0800",
        )
        r_pending = venue.accept(pending_open, now=_at(5))
        self.assertEqual(r_pending.effect, EffectState.ACKNOWLEDGED)
        venue.advance_market(_market(2, bid="1.1000", ask="1.1002", seconds=10))
        cancel_cmd = _raw_command(
            "cancel-pending",
            kind=ActionKind.CANCEL_ORDER,
            state_version=4,
            venue_sequence=pending_seq,
            side=None,
            target_id="pending-open",
            target_version=r_pending.venue_sequence,
        )
        r_cancel = venue.accept(cancel_cmd, now=_at(10))
        self.assertEqual(r_cancel.effect, EffectState.APPLIED)

    def test_concurrent_market_fill_and_protective_stop_transitions_invalidate_prior_core_authorization(self) -> None:
        core, venue, now = self._init_core_and_venue("race-mkt")
        admitted = core.admit(self._core_intent(core, "open-stale", now), command_id="open-stale", now=now)
        self.assertEqual(admitted.state, CommandState.QUEUED)

        now = now + timedelta(seconds=1)
        venue.advance_market(_market(2, bid="1.1004", ask="1.1006", seconds=1))

        dispatched = core.dispatch_command(SCOPE.key, "open-stale", now=now)
        self.assertIsNotNone(dispatched)
        if dispatched is None:
            self.fail("expected CommandView from dispatch_command")
        self.assertEqual(dispatched.state, CommandState.OBSERVED)
        self.assertEqual(dispatched.reason_code, "STALE_SOURCE_CURSOR")
        self.assertEqual(venue.lookup(SCOPE.key, "open-stale").receipt.effect, EffectState.REJECTED)
        self.assertEqual(venue.lookup(SCOPE.key, "open-stale").receipt.reason_code, "STALE_SOURCE_CURSOR")

        with self.assertRaises(AdmissionDenied):
            core.current_state(SCOPE.key, now=now)

        proj = core.reconcile(SCOPE.key, now=now)
        self.assertEqual(proj.recovery, RecoveryState.COHERENT)
        stale_rec = next(x for x in core.reservations(SCOPE.key) if x.command.command_id == "open-stale")
        self.assertFalse(stale_rec.reservation_held)
        self.assertEqual(stale_rec.reserved_notional, D("0"))

        fresh_admitted = core.admit(
            self._core_intent(core, "open-fresh", now, limit_price="1.1010", stop_price="1.0950"),
            command_id="open-fresh",
            now=now,
        )
        self.assertEqual(fresh_admitted.state, CommandState.QUEUED)
        fresh_dispatched = core.dispatch_command(SCOPE.key, "open-fresh", now=now)
        self.assertIsNotNone(fresh_dispatched)
        self.assertEqual(venue.lookup(SCOPE.key, "open-fresh").receipt.effect, EffectState.ACKNOWLEDGED)

        core2, venue2, now2 = self._init_core_and_venue("race-fill")
        core2.admit(
            self._core_intent(core2, "resting-entry", now2, limit_price="1.1005", stop_price="1.0900"),
            command_id="resting-entry",
            now=now2,
        )
        core2.dispatch_command(SCOPE.key, "resting-entry", now=now2)
        core2.reconcile(SCOPE.key, now=now2)

        core2.admit(self._core_intent(core2, "second-open", now2), command_id="second-open", now=now2)
        now2 = now2 + timedelta(seconds=1)
        filled_snap = venue2.advance_market(_market(2, bid="1.1000", ask="1.1002", seconds=1))
        self.assertEqual(len(filled_snap.positions), 1)
        self.assertEqual(venue2.lookup(SCOPE.key, "resting-entry").receipt.effect, EffectState.FILLED)

        second_disp = core2.dispatch_command(SCOPE.key, "second-open", now=now2)
        self.assertIsNotNone(second_disp)
        if second_disp is None:
            self.fail("expected CommandView")
        self.assertEqual(second_disp.reason_code, "STALE_SOURCE_CURSOR")

        proj2 = core2.reconcile(SCOPE.key, now=now2)
        pos2 = proj2.positions[0]
        amend_intent = self._core_intent(
            core2,
            "amend-before-stop",
            now2,
            kind=ActionKind.AMEND_STOP,
            quantity=None,
            side=None,
            target_id=pos2.position_id,
            target_version=pos2.version,
            limit_price=None,
            stop_price="1.0950",
        )
        self.assertEqual(core2.admit(amend_intent, command_id="amend-before-stop", now=now2).state, CommandState.QUEUED)
        now2 = now2 + timedelta(seconds=1)
        stop_snap = venue2.advance_market(_market(3, bid="1.0850", ask="1.0852", seconds=2))
        self.assertEqual(stop_snap.positions, ())
        self.assertTrue(any(r.reason_code == "VENUE_PROTECTIVE_STOP" for r in venue2.receipt_history(SCOPE.key)))

        amend_disp = core2.dispatch_command(SCOPE.key, "amend-before-stop", now=now2)
        self.assertIsNotNone(amend_disp)
        if amend_disp is None:
            self.fail("expected CommandView")
        self.assertEqual(amend_disp.reason_code, "STALE_SOURCE_CURSOR")

    def test_idempotent_replay_of_accepted_command_and_unsent_stale_retirement(self) -> None:
        core, venue, now = self._init_core_and_venue("idem")
        intent_one = self._core_intent(core, "cmd-idem", now)
        v_admit = core.admit(intent_one, command_id="cmd-idem", now=now)
        self.assertEqual(v_admit.state, CommandState.QUEUED)
        v_disp = core.dispatch_command(SCOPE.key, "cmd-idem", now=now)
        self.assertIsNotNone(v_disp)

        saved_cmd = core.reservations(SCOPE.key)[0].command
        ack_receipt = venue.lookup(SCOPE.key, "cmd-idem").receipt
        self.assertEqual(ack_receipt.effect, EffectState.ACKNOWLEDGED)

        now = now + timedelta(seconds=1)
        venue.advance_market(_market(2, bid="1.1000", ask="1.1002", seconds=1))
        filled_receipt = venue.lookup(SCOPE.key, "cmd-idem").receipt
        self.assertEqual(filled_receipt.effect, EffectState.FILLED)
        seq_before_replay = venue.snapshot(SCOPE.key, now=now).sequence

        replayed_receipt = venue.accept(saved_cmd, now=now + timedelta(seconds=2))
        self.assertEqual(replayed_receipt, filled_receipt)
        self.assertEqual(venue.snapshot(SCOPE.key, now=now + timedelta(seconds=2)).sequence, seq_before_replay)

        mutated_state = replace(saved_cmd.intent.source_state, venue_sequence=seq_before_replay)
        mutated_intent = replace(saved_cmd.intent, source_state=mutated_state)
        mutated_cmd = replace(saved_cmd, intent=mutated_intent, payload_sha256=intent_digest(mutated_intent))
        with self.assertRaises(IdentityConflict):
            venue.accept(mutated_cmd, now=now + timedelta(seconds=2))

        core.reconcile(SCOPE.key, now=now)
        core.admit(self._core_intent(core, "first-q", now, quantity="2"), command_id="first-q", now=now)
        core.admit(self._core_intent(core, "unsent-q", now, quantity="3"), command_id="unsent-q", now=now)
        core.dispatch_command(SCOPE.key, "first-q", now=now)
        core.reconcile(SCOPE.key, now=now)
        unsent_rec = next(x for x in core.reservations(SCOPE.key) if x.command.command_id == "unsent-q")
        self.assertEqual(unsent_rec.state, CommandState.REJECTED)
        self.assertEqual(unsent_rec.reason_code, "UNSENT_STALE_COMMAND")
        self.assertFalse(unsent_rec.reservation_held)


class Finding8SystemdCgroupRemediationTests(unittest.TestCase):
    REQUIRED_FLAGS = (
        "--property=MemoryHigh=1536M",
        "--property=MemoryMax=2048M",
        "--property=MemorySwapMax=0",
        "--property=CPUQuota=200%",
        "--property=TasksMax=256",
        "--property=LimitNPROC=256",
        "--property=LimitNOFILE=1024",
        "--property=OOMPolicy=kill",
        "--property=KillMode=control-group",
    )

    @staticmethod
    def _effective_systemctl_stdout(**overrides: str | None) -> str:
        values: dict[str, str | None] = {
            "MemoryHigh": "1610612736",
            "MemoryMax": "2147483648",
            "MemorySwapMax": "0",
            "CPUQuotaPerSecUSec": "2s",
            "TasksMax": "256",
            "LimitNPROC": "256",
            "LimitNOFILE": "1024",
            "OOMPolicy": "kill",
            "KillMode": "control-group",
        }
        values.update(overrides)
        return "\n".join(f"{k}={v}" for k, v in values.items() if v is not None) + "\n"

    def test_source_test_launcher_systemd_command_pins_all_cgroup_and_rlimit_ceilings(self) -> None:
        plan = {
            "python_site_directory": lc.BASE + "/runtime/python-site",
            "worker_path": lc.BASE + "/source_runtime/source_test_worker.py",
        }
        argv = launcher.systemd_command(plan, 120, lc.BASE + "/plan.json", "a" * 64, lc)
        for flag in self.REQUIRED_FLAGS:
            self.assertIn(flag, argv)

    def test_source_test_launcher_validate_ready_verifies_effective_ceilings_and_fails_closed(self) -> None:
        subject = {"pid": 4242, "start_ticks": 98765, "uid": 62100}
        plan_path = lc.BASE + "/plan.json"
        plan_sha = "b" * 64
        plan = {"worker_path": lc.BASE + "/source_runtime/source_test_worker.py"}
        roles = {
            "reader_group_gid": 4400,
            "roles": {
                name: {"process": {"pid": 100 + idx, "start_ticks": 50 + idx, "uid": 5000 + idx}}
                for idx, name in enumerate(("current", "registry", "observer", "custody"))
            },
        }
        state_dir = "/var/lib/" + lc.UNIT
        ready = {
            "format": "forex.source-test-worker-ready/1",
            "subject": subject,
            "clock_domain": {"boot_id": "boot-1", "time_namespace_inode": 1, "clock_id": "CLOCK_BOOTTIME"},
            "clock_anchor_stamp": {"utc": "2026-11-16T12:00:00.000000Z", "boottime_ns": 1000},
            "state_directory": state_dir,
            "supplementary_gids": [4400],
            "isolation": {"private_network": True},
            "directories": {
                leaf: {
                    "path": f"{state_dir}/{leaf}",
                    "device": 7,
                    "inode": 200 + idx,
                    "uid": subject["uid"],
                    "gid": subject["uid"],
                    "mode": 0o700,
                }
                for idx, leaf in enumerate(("attempt", "capture", "temporary"))
            },
        }
        expected_cmdline = (
            b"/usr/bin/python3\x00-I\x00-B\x00"
            + plan["worker_path"].encode("utf-8")
            + b"\x00--plan\x00"
            + plan_path.encode("utf-8")
            + b"\x00--plan-sha256\x00"
            + plan_sha.encode("utf-8")
            + b"\x00"
        )
        deadline = SimpleNamespace(remaining=lambda reserve=0: 30)

        def fake_stat(path_str: str, *, follow_symlinks: bool = True) -> SimpleNamespace:
            for leaf, row in ready["directories"].items():
                if path_str.endswith("/" + leaf):
                    return SimpleNamespace(
                        st_dev=row["device"],
                        st_ino=row["inode"],
                        st_uid=row["uid"],
                        st_gid=row["gid"],
                        st_mode=0o040700,
                    )
            raise FileNotFoundError(path_str)

        def run_validate(cgroup_stdout: str, *, fail_systemctl: bool = False) -> None:
            def fake_run(cmd: list[str], **kwargs: object) -> SimpleNamespace:
                if "--property=MainPID" in cmd:
                    return SimpleNamespace(returncode=0, stdout="4242\n")
                if fail_systemctl:
                    raise subprocess.CalledProcessError(1, cmd)
                return SimpleNamespace(returncode=0, stdout=cgroup_stdout)

            with (
                patch.object(launcher.subprocess, "run", side_effect=fake_run),
                patch.object(launcher, "Path") as mock_path,
                patch.object(launcher.os, "stat", side_effect=fake_stat),
                patch.object(lc, "process_identity", return_value=dict(subject)),
                patch.object(
                    lc,
                    "observe_pair",
                    return_value=(
                        dict(ready["clock_domain"]),
                        {"utc": "2026-11-16T12:00:01.000000Z", "boottime_ns": 2000},
                    ),
                ),
            ):
                mock_path.return_value.read_bytes.return_value = expected_cmdline
                launcher.validate_ready(ready, plan, roles, lc, deadline, plan_path, plan_sha)

        run_validate(self._effective_systemctl_stdout())
        run_validate(
            self._effective_systemctl_stdout(
                MemoryHigh="1536M",
                MemoryMax="2048M",
                CPUQuotaPerSecUSec=None,
                CPUQuota="200%",
            )
        )

        bad_cases = (
            {"MemoryHigh": "infinity"},
            {"MemoryHigh": None},
            {"MemoryMax": "infinity"},
            {"MemoryMax": "4294967296"},
            {"MemorySwapMax": "infinity"},
            {"MemorySwapMax": "1048576"},
            {"CPUQuotaPerSecUSec": "infinity"},
            {"CPUQuotaPerSecUSec": "4s"},
            {"CPUQuotaPerSecUSec": None},
            {"CPUQuota": "100%"},
            {"TasksMax": "infinity"},
            {"TasksMax": "512"},
            {"LimitNPROC": "infinity"},
            {"LimitNOFILE": "65536"},
            {"OOMPolicy": "continue"},
            {"KillMode": "process"},
        )
        for bad in bad_cases:
            with self.subTest(bad=bad):
                with self.assertRaises(RuntimeError):
                    run_validate(self._effective_systemctl_stdout(**bad))

        with self.assertRaises(subprocess.CalledProcessError):
            run_validate(self._effective_systemctl_stdout(), fail_systemctl=True)
        with self.assertRaises(RuntimeError):
            run_validate("")
        with self.assertRaises(RuntimeError):
            run_validate("MemoryHigh=1610612736\nMalformedLineWithoutEquals\n")

    def test_measurement_runner_systemd_command_and_readiness_fail_closed(self) -> None:
        argv = measurement_systemd_command(
            "cas-forex-measure-unit",
            ["/usr/bin/python3", "-I", "/opt/cas-forex/driver.py"],
            runtime_max_sec=90,
        )
        for flag in self.REQUIRED_FLAGS:
            self.assertIn(flag, argv)
        self.assertEqual(len(MEASUREMENT_SYSTEMD_CGROUP_PROPERTIES), 9)

        for key, bad_val in (
            ("MemoryMax", "8192M"),
            ("MemoryHigh", "4096M"),
            ("MemorySwapMax", "1G"),
            ("CPUQuota", "400%"),
            ("TasksMax", "1024"),
            ("LimitNPROC", "1024"),
            ("LimitNOFILE", "4096"),
            ("OOMPolicy", "continue"),
            ("KillMode", "mixed"),
        ):
            with self.subTest(override=key):
                with self.assertRaises(OperationalContractError):
                    measurement_systemd_command(
                        "cas-forex-measure-unit",
                        ["/usr/bin/python3", "-I", "/opt/cas-forex/driver.py"],
                        runtime_max_sec=90,
                        extra_properties={key: bad_val},
                    )

        ok_props = validate_measurement_unit_ready(
            "cas-forex-measure-unit",
            runner=lambda cmd, **kw: SimpleNamespace(returncode=0, stdout=self._effective_systemctl_stdout()),
        )
        self.assertEqual(ok_props["KillMode"], "control-group")

        for bad in (
            {"MemoryMax": "infinity"},
            {"MemorySwapMax": "infinity"},
            {"CPUQuotaPerSecUSec": "infinity"},
            {"TasksMax": "infinity"},
            {"LimitNPROC": "512"},
            {"LimitNOFILE": "2048"},
            {"OOMPolicy": "stop"},
            {"KillMode": "process"},
        ):
            with self.subTest(measurement_bad=bad):
                with self.assertRaises(OperationalContractError):
                    validate_measurement_unit_ready(
                        "cas-forex-measure-unit",
                        runner=lambda cmd, _b=bad, **kw: SimpleNamespace(
                            returncode=0,
                            stdout=self._effective_systemctl_stdout(**_b),
                        ),
                    )

        binding = {
            "run_id": "sec-measure-test",
            "epoch": 1,
            "source_manifest_sha256": "a" * 64,
            "config_sha256": "b" * 64,
            "topology_sha256": "c" * 64,
            "original_window_sha256": "d" * 64,
        }
        executable = {
            "asset_id": "sec-python",
            "selected_path": "/usr/bin/python3",
            "bytes": 1,
            "sha256": "f" * 64,
            "device": 1,
            "inode": 1,
        }
        cmd_pin = {
            "format": "forex.test-command-pin/1",
            "binding": binding,
            "group_id": "operator",
            "executable": executable,
            "argv": [
                "/usr/bin/python3",
                "--discovery-fd",
                "200",
                "--release-fd",
                "201",
                "--group",
                "operator",
                "--inventory-sha256",
                "e" * 64,
            ],
            "cwd": "/opt/cas-forex",
            "environment_profile_sha256": "1" * 64,
            "stdin_policy": "CLOSED",
            "source_manifest_sha256": "a" * 64,
        }
        pin_keys = (
            "executable",
            "argv",
            "cwd",
            "environment_profile_sha256",
            "stdin_policy",
            "source_manifest_sha256",
            "group_id",
        )
        cmd_pin["command_sha256"] = digest(canonical_bytes({k: cmd_pin[k] for k in pin_keys}))

        guard = SimpleNamespace(
            remaining=lambda: 15.0,
            now=lambda: {"utc": "2026-11-16T12:00:00.000000Z", "boottime_ns": 1000},
        )
        capture_bad = ForkExecCapture(
            inventory=None,
            guard=guard,
            execution_gate=lambda: None,
            capture_sink=None,
            unit_name="cas-forex-measure-unit",
            systemctl_runner=lambda cmd, **kw: SimpleNamespace(
                returncode=0,
                stdout=self._effective_systemctl_stdout(MemoryMax="infinity"),
            ),
        )
        with patch("cas_forex_measurement.completion.os.open") as mock_open:
            with self.assertRaises(OperationalContractError):
                capture_bad.run(
                    cmd_pin,
                    environment={},
                    maximum_stream_bytes=4096,
                    on_discovery=lambda notice: None,
                    before_release=lambda **kw: None,
                )
            mock_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
