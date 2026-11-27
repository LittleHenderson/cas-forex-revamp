"""Milestone M1 regression suite: ParallelTierEngine valve refusal, SQLite BEGIN IMMEDIATE,
directory/file custody modes, AMEND_STOP stop-price geometry, NY 17:00 DST quota rollover,
and ProfitSweepVault ACH idempotency & OUTCOME_UNKNOWN recovery.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cas_forex_revamp.composition.parallel_tiers import (
    DEFAULT_PARALLEL_TIER_SPECS,
    ParallelTierEngine,
    ParallelTierSpec,
    apply_verified_directory_mode,
    apply_verified_regular_file_mode,
)
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.composition.trend_regime import REGIME_STRONG_TREND
from cas_forex_revamp.contracts import (
    ActionKind,
    ContractError,
    DecisionFact,
    EvidenceKind,
    EvidenceReference,
    Side,
    canonical_bytes,
)
from cas_forex_revamp.treasury import (
    CoinbaseOfframpClient,
    OfframpSecurityError,
    OfframpTransportError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
    RAIL_KRAKEN_ACH,
)
from cas_forex_revamp.valve.daily_quota import (
    QUOTA_STATUS_LOCKED,
    QUOTA_STATUS_LOSS_TRIPPED,
    QUOTA_STATUS_OPEN,
    DailyQuotaGovernanceStore,
    session_date_for,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
    TKSMetaValveController,
    ValveRefusalError,
    _extract_money_decimal,
    _is_unavailable_accounting_value,
    _strip_bom_and_ws,
    load_default_forex_valve_gate,
)

D = Decimal
T0 = datetime(2026, 11, 18, 13, 0, 0, tzinfo=timezone.utc)
QUOTES = {
    "NAS100": (D("20500.00"), D("20502.50")),
    "US30": (D("43800.00"), D("43804.00")),
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27012")),
    "USDJPY": (D("150.000"), D("150.012")),
}


def _make_amend_proposal(
    *,
    stop_price: object = D("1.0980"),
    take_profit_price: object = None,
    side: object = None,
    facts: tuple[DecisionFact, ...] = (),
    target_id: str | None = "pos-1",
) -> SimpleNamespace:
    scope = SimpleNamespace(account_id="acct-m1", run_id="run-m1")
    state = SimpleNamespace(scope=scope, observed_at=T0, valid_until=T0 + timedelta(minutes=5))
    ev = SimpleNamespace(evidence_id="ev-m1-1")
    request = SimpleNamespace(
        request_id="req-m1-amend",
        facts=facts,
        evidence=(ev,),
        state=state,
    )
    intent = SimpleNamespace(
        intent_id="intent-m1-amend",
        action_ref="opt-m1-amend",
        kind=ActionKind.AMEND_STOP,
        instrument_id="EURUSD",
        quantity=None,
        side=side,
        stop_price=stop_price,
        take_profit_price=take_profit_price,
        limit_price=None,
        target_id=target_id,
    )
    selection = SimpleNamespace(
        evidence_ids=("ev-m1-1",),
        reason="Disciplined trailing stop update",
        selected_action_ref="opt-m1-amend",
    )
    return SimpleNamespace(request=request, result=SimpleNamespace(selection=selection), intent=intent)


def _make_order_proposal(
    *,
    kind: ActionKind = ActionKind.OPEN,
    instrument_id: str = "EURUSD",
    side: Side = Side.BUY,
    limit_price: object = None,
    stop_price: object = D("1.0950"),
    take_profit_price: object = D("1.1150"),
    facts: tuple[DecisionFact, ...] = (),
    target_id: str | None = None,
) -> SimpleNamespace:
    scope = SimpleNamespace(account_id="acct-m1", run_id="run-m1")
    state = SimpleNamespace(scope=scope, observed_at=T0, valid_until=T0 + timedelta(minutes=5))
    ev = SimpleNamespace(evidence_id="ev-m1-1")
    request = SimpleNamespace(
        request_id="req-m1-order",
        facts=facts,
        evidence=(ev,),
        state=state,
    )
    intent = SimpleNamespace(
        intent_id="intent-m1-order",
        action_ref="opt-m1-order",
        kind=kind,
        instrument_id=instrument_id,
        quantity=D("10000"),
        side=side,
        stop_price=stop_price,
        take_profit_price=take_profit_price,
        limit_price=limit_price,
        target_id=target_id,
    )
    selection = SimpleNamespace(
        evidence_ids=("ev-m1-1",),
        reason="Disciplined trend continuation setup",
        selected_action_ref="opt-m1-order",
    )
    return SimpleNamespace(request=request, result=SimpleNamespace(selection=selection), intent=intent)


def _clean_view(*, extra: dict[str, object] | None = None) -> dict[str, object]:
    view: dict[str, object] = {
        "account_id": "acct-m1",
        "balance": "10000",
        "equity": "10000",
        "peak_equity": "10000",
        "available_margin": "9000",
        "position_inventory": [],
    }
    if extra:
        view.update(extra)
    return view


class ParallelTiersAndValveRefusalTests(unittest.TestCase):
    def test_parallel_tier_handles_valve_hard_veto_without_attribute_error(self) -> None:
        gate = load_default_forex_valve_gate(max_drawdown_pct=DEFAULT_MAX_DRAWDOWN_PCT)
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers.sqlite3"
            # Pre-seed TIER_2_1000 peak at $1,200 so $1,000 starting equity is in 16.67% drawdown (> 10%)
            PeakEquityStore(db_path).observe_equity(
                "tier:TIER_2_1000",
                current_equity=D("1200.00"),
                opening_balance=D("1200.00"),
                now=T0 - timedelta(minutes=1),
            )
            eng = ParallelTierEngine(db_path, valve_gate=gate, clock=lambda: T0)
            out = eng.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.11000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            by_id = {t["tier_id"]: t for t in out["tiers"]}
            self.assertEqual(by_id["TIER_2_1000"]["open_positions"], 0)
            skip_reason = str(by_id["TIER_2_1000"]["last_skip_reason"] or "")
            self.assertTrue(skip_reason.startswith("VALVE_REFUSED ("))
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", skip_reason)
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 1)

    def test_parallel_tier_handles_valve_mlp_score_veto_without_attribute_error(self) -> None:
        veto_ctrl = TKSMetaValveController(
            w1=[[0.0] * 8 for _ in range(16)],
            b1=[0.0] * 16,
            w2=[0.0] * 16,
            b2=-5.0,
            threshold=0.55,
        )
        gate = ForexMetaValveGate(veto_ctrl, max_drawdown_pct=DEFAULT_MAX_DRAWDOWN_PCT)
        with tempfile.TemporaryDirectory() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
            out = eng.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.11000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            by_id = {t["tier_id"]: t for t in out["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 0)
            skip_reason = str(by_id["TIER_1_CURRENT"]["last_skip_reason"] or "")
            self.assertTrue(skip_reason.startswith("VALVE_REFUSED (MLP_SCORE_VETO:mlp_score="))
            self.assertIn("<0.550000)", skip_reason)

    def test_parallel_tier_sqlite_begin_immediate_concurrency_and_atomicity(self) -> None:
        gate = load_default_forex_valve_gate()
        single_spec = (ParallelTierSpec("TIER_1_CURRENT", "Current ($300,000)", D("300000.00"), "tier-300k"),)
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers.sqlite3"
            eng1 = ParallelTierEngine(db_path, valve_gate=gate, specs=single_spec, clock=lambda: T0)
            eng2 = ParallelTierEngine(db_path, valve_gate=gate, specs=single_spec, clock=lambda: T0)

            # Open 1 EURUSD BUY position at ask=1.10010, SL=1.09510, TP=1.10500
            snap_open = eng1.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.10500",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            self.assertEqual(snap_open["tiers"][0]["open_positions"], 1)

            # Inject mid-Tx1 abort after DELETE FROM tier_positions (on INSERT INTO tier_closed_trades)
            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute(
                    """
                    CREATE TRIGGER fail_closed_trade_insert
                    BEFORE INSERT ON tier_closed_trades
                    BEGIN
                        SELECT RAISE(ABORT, 'injected_tx1_abort');
                    END;
                    """
                )
                conn.commit()
            finally:
                conn.close()

            sl_quotes = {**QUOTES, "EURUSD": (D("1.09400"), D("1.09410"))}
            with self.assertRaises(sqlite3.IntegrityError):
                eng1.process_tick(quotes=sl_quotes, now=T0 + timedelta(seconds=1))

            # Tx 1 rolled back cleanly: position is NOT orphaned/deleted and closed_trades == 0
            after_abort = eng1.snapshot()
            self.assertEqual(after_abort["tiers"][0]["open_positions"], 1)
            self.assertEqual(after_abort["tiers"][0]["closed_trades"], 0)
            self.assertEqual(after_abort["tiers"][0]["bank_sweep_reserved_usd"], "0")

            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute("DROP TRIGGER fail_closed_trade_insert")
                conn.commit()
            finally:
                conn.close()

            # Now close cleanly at profit (triggers Tx 1 -> ProfitSweepVault + DailyQuotaGovernanceStore -> PeakEquityStore -> Tx 2)
            tp_quotes = {**QUOTES, "EURUSD": (D("1.10510"), D("1.10520"))}
            after_tp = eng1.process_tick(quotes=tp_quotes, now=T0 + timedelta(seconds=2))
            self.assertEqual(after_tp["tiers"][0]["open_positions"], 0)
            self.assertEqual(after_tp["tiers"][0]["closed_trades"], 1)
            self.assertGreater(D(after_tp["tiers"][0]["bank_sweep_reserved_usd"]), D("0"))

            # Concurrent cross-engine process_tick + snapshot stress (verifies no self-deadlock on shared db_path)
            def _worker(idx: int) -> dict[str, object]:
                engine = eng1 if idx % 2 == 0 else eng2
                tick_t = T0 + timedelta(seconds=10 + idx)
                if idx % 3 == 0:
                    return engine.snapshot()
                return engine.process_tick(quotes=QUOTES, now=tick_t)

            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(_worker, range(18)))
            self.assertEqual(len(results), 18)
            self.assertTrue(all(r["tier_count"] == 1 for r in results))

    def test_parallel_tier_verified_directory_and_file_mode_custody(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_dir = root / "state_dir"
            real_dir.mkdir()
            real_file = real_dir / "tiers.sqlite3"
            real_file.write_text("ok", encoding="utf-8")

            # Valid restrictive modes & default 0o755
            self.assertEqual(apply_verified_directory_mode(real_dir), real_dir)
            self.assertEqual(apply_verified_directory_mode(real_dir, dir_mode=0o700), real_dir)
            self.assertEqual(apply_verified_regular_file_mode(real_file, file_mode=0o600), real_file)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.lstat(real_dir).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.lstat(real_file).st_mode), 0o600)

            # Permissive modes rejected
            with self.assertRaises(ContractError):
                apply_verified_directory_mode(real_dir, dir_mode=0o777)
            with self.assertRaises(ContractError):
                apply_verified_directory_mode(real_dir, dir_mode=0o775)
            with self.assertRaises(ContractError):
                apply_verified_regular_file_mode(real_file, file_mode=0o644)
            with self.assertRaises(ContractError):
                apply_verified_regular_file_mode(real_file, file_mode=0o666)

            # Type mismatches rejected
            with self.assertRaises(ContractError):
                apply_verified_directory_mode(real_file, dir_mode=0o700)
            with self.assertRaises(ContractError):
                apply_verified_regular_file_mode(real_dir, file_mode=0o600)

            # Symlinks rejected (when OS supports creating symlinks without admin privilege)
            sym_dir = root / "sym_dir"
            sym_file = root / "sym_file"
            try:
                os.symlink(real_dir, sym_dir, target_is_directory=True)
                os.symlink(real_file, sym_file)
            except (OSError, NotImplementedError):
                sym_dir = None
                sym_file = None
            if sym_dir is not None and sym_file is not None:
                with self.assertRaises(ContractError):
                    apply_verified_directory_mode(sym_dir, dir_mode=0o700)
                with self.assertRaises(ContractError):
                    apply_verified_regular_file_mode(sym_file, file_mode=0o600)

    def test_daily_quota_ny_1700_dst_spring_forward_and_fall_back_rollover(self) -> None:
        # Spring Forward (2026-03-08: EST -05:00 -> EDT -04:00 at 02:00 local)
        self.assertEqual(session_date_for(datetime(2026, 3, 7, 22, 0, 0, tzinfo=timezone.utc)), "2026-03-08")
        self.assertEqual(session_date_for(datetime(2026, 3, 8, 20, 59, 59, tzinfo=timezone.utc)), "2026-03-08")
        self.assertEqual(session_date_for(datetime(2026, 3, 8, 21, 0, 0, tzinfo=timezone.utc)), "2026-03-09")

        # Fall Back (2026-11-01: EDT -04:00 -> EST -05:00 at 02:00 local)
        self.assertEqual(session_date_for(datetime(2026, 10, 31, 21, 0, 0, tzinfo=timezone.utc)), "2026-11-01")
        self.assertEqual(session_date_for(datetime(2026, 11, 1, 5, 30, 0, tzinfo=timezone.utc)), "2026-11-01")
        self.assertEqual(session_date_for(datetime(2026, 11, 1, 6, 30, 0, tzinfo=timezone.utc)), "2026-11-01")
        self.assertEqual(session_date_for(datetime(2026, 11, 1, 21, 0, 0, tzinfo=timezone.utc)), "2026-11-01")
        self.assertEqual(session_date_for(datetime(2026, 11, 1, 21, 59, 59, tzinfo=timezone.utc)), "2026-11-01")
        self.assertEqual(session_date_for(datetime(2026, 11, 1, 22, 0, 0, tzinfo=timezone.utc)), "2026-11-02")

        with tempfile.TemporaryDirectory() as td:
            store = DailyQuotaGovernanceStore(
                path=Path(td) / "quota_dst.sqlite3",
                scope_id="tier:DST",
                quota_mode="USD",
                soft_quota_usd=D("500"),
                hard_quota_usd=D("1000"),
            )
            # Lock Spring Forward session 2026-03-08
            store.record_realized_trade(
                D("1000"),
                symbol="EURUSD",
                ticket="t-spring",
                now=datetime(2026, 3, 8, 15, 0, 0, tzinfo=timezone.utc),
            )
            ok_before, reason_before, mult_before = store.evaluate_new_risk(
                ActionKind.OPEN, now=datetime(2026, 3, 8, 20, 59, 59, tzinfo=timezone.utc)
            )
            self.assertFalse(ok_before)
            self.assertEqual(reason_before, QUOTA_STATUS_LOCKED)
            self.assertEqual(mult_before, D("0"))
            snap_before = store.snapshot(now=datetime(2026, 3, 8, 20, 59, 59, tzinfo=timezone.utc))
            self.assertEqual(snap_before["status"], QUOTA_STATUS_LOCKED)
            self.assertEqual(snap_before["session_date"], "2026-03-08")

            ok_after, reason_after, mult_after = store.evaluate_new_risk(
                ActionKind.OPEN, now=datetime(2026, 3, 8, 21, 0, 0, tzinfo=timezone.utc)
            )
            self.assertTrue(ok_after)
            self.assertIsNone(reason_after)
            self.assertEqual(mult_after, D("1"))
            snap_after = store.snapshot(now=datetime(2026, 3, 8, 21, 0, 0, tzinfo=timezone.utc))
            self.assertEqual(snap_after["status"], QUOTA_STATUS_OPEN)
            self.assertEqual(snap_after["session_date"], "2026-03-09")

            # Lock Fall Back session 2026-11-01; verify 21:00Z / 21:59:59Z stay locked and 22:00Z rolls over
            store.record_realized_trade(
                D("1000"),
                symbol="EURUSD",
                ticket="t-fall",
                now=datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc),
            )
            for locked_ts in (
                datetime(2026, 11, 1, 21, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 11, 1, 21, 59, 59, tzinfo=timezone.utc),
            ):
                ok_fb, reason_fb, _ = store.evaluate_new_risk(ActionKind.OPEN, now=locked_ts)
                self.assertFalse(ok_fb)
                self.assertEqual(reason_fb, QUOTA_STATUS_LOCKED)
                snap_fb = store.snapshot(now=locked_ts)
                self.assertEqual(snap_fb["status"], QUOTA_STATUS_LOCKED)
                self.assertEqual(snap_fb["session_date"], "2026-11-01")
            ok_next, reason_next, _ = store.evaluate_new_risk(
                ActionKind.OPEN, now=datetime(2026, 11, 1, 22, 0, 0, tzinfo=timezone.utc)
            )
            self.assertTrue(ok_next)
            self.assertIsNone(reason_next)
            snap_next = store.snapshot(now=datetime(2026, 11, 1, 22, 0, 0, tzinfo=timezone.utc))
            self.assertEqual(snap_next["status"], QUOTA_STATUS_OPEN)
            self.assertEqual(snap_next["session_date"], "2026-11-02")

    def test_profit_sweep_vault_ach_idempotency_and_retry_recovery_edge_cases(self) -> None:
        priv = ec.generate_private_key(ec.SECP256R1())
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pem_p = root / "cb_ec.pem"
            pem_p.write_bytes(pem)
            if os.name == "posix":
                os.chmod(pem_p, 0o600)  # nosec B103: test fixture EC private key owner-only

            db_path = root / "vault.sqlite3"
            vault = ProfitSweepVault(db_path, clock=lambda: T0)
            vault.record_realized_close(
                trade_id="t-ach-1", symbol="NAS100", broker_id="HUGOSWAY_MT5", realized_net_usd=D("300.00")
            )
            # 50% of $300 = $150.00 pending bank sweep
            seen_bodies: list[dict[str, object]] = []
            fail_mode = {"fail": True}

            def flakey_http(method: str, url: str, headers: dict[str, str], body: bytes, timeout: float):
                seen_bodies.append(json.loads(body.decode("utf-8")))
                if fail_mode["fail"]:
                    return 503, b"service unavailable"
                return 200, json.dumps({"id": "cb-ach-recovered-1"}).encode("utf-8")

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-ach-01",
                http_call=flakey_http,
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            rec = OwnerRecoveryVerifier(db_path=db_path, clock=lambda: T0)

            # 1. Transport error persists OUTCOME_UNKNOWN with error_detail and keeps $100 locked
            prep1 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ach-1",
                reason="ach sweep",
                coinbase_client=cb,
                idempotency_key="idem-ach-001",
            )
            tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep1["intent_sha256"], now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-ach-1",
                    reason="ach sweep",
                    verifier=rec,
                    recovery_token=tok1,
                    coinbase_client=cb,
                    idempotency_key="idem-ach-001",
                    intent_id=prep1["intent_id"],
                    intent_sha256=prep1["intent_sha256"],
                )
            self.assertEqual(len(seen_bodies), 1)
            snap_unk = vault.snapshot()
            self.assertEqual(snap_unk["pending_disbursement_usd"], "50")
            unknown_tx = snap_unk["recent_transfers"][0]
            self.assertEqual(unknown_tx["status"], "OUTCOME_UNKNOWN")
            transfer_id = str(unknown_tx["transfer_id"])
            db_conn = sqlite3.connect(str(db_path))
            try:
                err_row = db_conn.execute(
                    "SELECT status, error_detail, idempotency_key FROM bank_transfers WHERE transfer_id = ?",
                    (transfer_id,),
                ).fetchone()
            finally:
                db_conn.close()
            self.assertIsNotNone(err_row)
            self.assertEqual(err_row[0], "OUTCOME_UNKNOWN")
            self.assertIn("OfframpTransportError", str(err_row[1]))
            self.assertEqual(err_row[2], "idem-ach-001")

            # 2. Duplicate idempotency_key is refused BEFORE any HTTP dispatch
            prep2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("25.00"),
                owner_request_id="req-ach-dup",
                reason="duplicate idem",
                coinbase_client=cb,
                idempotency_key="idem-ach-001",
            )
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep2["intent_sha256"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("25.00"),
                    owner_request_id="req-ach-dup",
                    reason="duplicate idem",
                    verifier=rec,
                    recovery_token=tok2,
                    coinbase_client=cb,
                    idempotency_key="idem-ach-001",
                    intent_id=prep2["intent_id"],
                    intent_sha256=prep2["intent_sha256"],
                )
            self.assertEqual(len(seen_bodies), 1)

            # 3. Retry with mismatched rail or amount or unknown transfer_id is refused
            prep3 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-ach-bad-amt",
                reason="bad amt",
                coinbase_client=cb,
                retry_transfer_id=transfer_id,
            )
            tok3 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep3["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-ach-bad-amt",
                    reason="bad amt",
                    verifier=rec,
                    recovery_token=tok3,
                    coinbase_client=cb,
                    retry_transfer_id=transfer_id,
                    intent_id=prep3["intent_id"],
                    intent_sha256=prep3["intent_sha256"],
                )
            prep4 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ach-missing",
                reason="missing id",
                coinbase_client=cb,
                retry_transfer_id="trach-nonexistent",
            )
            tok4 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep4["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-ach-missing",
                    reason="missing id",
                    verifier=rec,
                    recovery_token=tok4,
                    coinbase_client=cb,
                    retry_transfer_id="trach-nonexistent",
                    intent_id=prep4["intent_id"],
                    intent_sha256=prep4["intent_sha256"],
                )

            # 4. Reconcile NOT_EXECUTED then retry recovery reuses exact original idempotency_key and settles once
            vault.reconcile_withdrawal_outcome(
                transfer_id=transfer_id,
                exchange_history_checker=lambda q: {
                    "status": "NOT_EXECUTED",
                    "history_complete": True,
                    "queried_client_reference_id": q["idempotency_key"],
                },
                owner_request_id="req-ach-reconcile",
            )
            fail_mode["fail"] = False
            prep5 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ach-retry",
                reason="retry unknown",
                coinbase_client=cb,
                retry_transfer_id=transfer_id,
            )
            tok5 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep5["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ach-retry",
                reason="retry unknown",
                verifier=rec,
                recovery_token=tok5,
                coinbase_client=cb,
                retry_transfer_id=transfer_id,
                intent_id=prep5["intent_id"],
                intent_sha256=prep5["intent_sha256"],
            )
            self.assertEqual(len(seen_bodies), 2)
            self.assertEqual(seen_bodies[0]["client_reference_id"], "idem-ach-001")
            self.assertEqual(seen_bodies[1]["client_reference_id"], "idem-ach-001")
            self.assertEqual(out["provider_tx_id"], "cb-ach-recovered-1")
            self.assertEqual(out["vault"]["disbursed_to_bank_usd"], "100")
            self.assertEqual(out["vault"]["pending_disbursement_usd"], "50")

            # 5. Re-retrying an already ACH_SUBMITTED transfer is refused
            prep6 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ach-re-retry",
                reason="cannot retry submitted",
                coinbase_client=cb,
                retry_transfer_id=transfer_id,
            )
            tok6 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep6["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-ach-re-retry",
                    reason="cannot retry submitted",
                    verifier=rec,
                    recovery_token=tok6,
                    coinbase_client=cb,
                    retry_transfer_id=transfer_id,
                    intent_id=prep6["intent_id"],
                    intent_sha256=prep6["intent_sha256"],
                )
            self.assertEqual(RAIL_KRAKEN_ACH, "KRAKEN_ACH")

    def test_valve_amend_stop_geometry_rejects_invalid_and_admits_trailing_stop(self) -> None:
        gate = load_default_forex_valve_gate()
        self.assertEqual(gate.controller.parameter_count, 161)
        self.assertEqual(gate.controller.threshold, 0.55)

        # 1. Missing stop_price (both None and with take_profit_price set)
        for tp in (None, D("1.1200")):
            with self.assertRaises(ValveRefusalError) as ctx:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=None, take_profit_price=tp),
                    current_view=_clean_view(),
                    now=T0 + timedelta(seconds=1),
                )
            self.assertIn("MISSING_PROTECTIVE_STOP", ctx.exception.decision.hard_veto_reasons)

        # 2. Non-positive / non-finite stop_price
        for bad_stop in (D("0"), D("-1.05"), "NaN", "inf", "not-a-decimal"):
            with self.assertRaises(ValveRefusalError) as ctx:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=bad_stop),
                    current_view=_clean_view(),
                    now=T0 + timedelta(seconds=1),
                )
            self.assertIn("INVALID_PROTECTIVE_STOP", ctx.exception.decision.hard_veto_reasons)

        # 3. Inverted BUY stop >= bid via list-valued observed-* facts (R6Runtime format)
        ev = EvidenceReference("ev-m1-1", EvidenceKind.OBSERVATION, "sim-1", "a" * 64, T0)
        facts_buy_list = (
            DecisionFact(
                "observed-current_market-s1",
                "current_market",
                canonical_bytes([{"instrument_id": "EURUSD", "bid": "1.1060", "ask": "1.1062"}]).decode("utf-8"),
                ("ev-m1-1",),
            ),
            DecisionFact(
                "observed-position_inventory-s1",
                "position_inventory",
                canonical_bytes([{"position_id": "pos-1", "side": "BUY", "stop_price": "1.0950"}]).decode("utf-8"),
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_buy_inv:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1060"), facts=facts_buy_list),
                current_view=_clean_view(),
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_buy_inv.exception.decision.hard_veto_reasons)

        # 4. Loosened BUY stop < prev_stop
        with self.assertRaises(ValveRefusalError) as ctx_buy_loose:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0940"), facts=facts_buy_list),
                current_view=_clean_view(),
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_buy_loose.exception.decision.hard_veto_reasons)

        # 5. Inverted & loosened SELL stop via current_view nested position_inventory/current_market
        sell_view = _clean_view(
            extra={
                "current_market": [{"instrument_id": "EURUSD", "bid": "1.0940", "ask": "1.0942"}],
                "position_inventory": [{"position_id": "pos-1", "side": "SELL", "stop_price": "1.0990"}],
            }
        )
        with self.assertRaises(ValveRefusalError) as ctx_sell_inv:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0942")),
                current_view=sell_view,
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_sell_inv.exception.decision.hard_veto_reasons)

        with self.assertRaises(ValveRefusalError) as ctx_sell_loose:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0995")),
                current_view=sell_view,
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("LOOSENED_SELL_PROTECTIVE_STOP", ctx_sell_loose.exception.decision.hard_veto_reasons)

        # 6. Invalid & inverted take_profit_price on AMEND_STOP
        with self.assertRaises(ValveRefusalError) as ctx_tp_nan:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), take_profit_price="NaN", facts=facts_buy_list),
                current_view=_clean_view(),
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("INVALID_TAKE_PROFIT_PRICE", ctx_tp_nan.exception.decision.hard_veto_reasons)

        with self.assertRaises(ValveRefusalError) as ctx_tp_inv:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), take_profit_price=D("1.1062"), facts=facts_buy_list),
                current_view=_clean_view(),
                now=T0 + timedelta(seconds=1),
            )
        self.assertIn("INVERTED_BUY_TAKE_PROFIT", ctx_tp_inv.exception.decision.hard_veto_reasons)

        # 7. Valid trailing BUY stop (above entry 1.1000, above prev_stop 1.0950, below bid 1.1060) is ADMITTED
        dec_buy_ok = gate.require_admissible(
            _make_amend_proposal(stop_price=D("1.1020"), take_profit_price=D("1.1150"), facts=facts_buy_list),
            current_view=_clean_view(),
            now=T0 + timedelta(seconds=1),
        )
        self.assertTrue(dec_buy_ok.admitted)

        # 8. Valid trailing SELL stop (tightened from 1.0990 down to 1.0960, above ask 1.0942) is ADMITTED
        dec_sell_ok = gate.require_admissible(
            _make_amend_proposal(stop_price=D("1.0960")),
            current_view=sell_view,
            now=T0 + timedelta(seconds=1),
        )
        self.assertTrue(dec_sell_ok.admitted)
        self.assertEqual(len(DEFAULT_PARALLEL_TIER_SPECS), 5)

    def test_parallel_tier_house_money_is_add_refused_before_breakeven_and_admitted_after_lock(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers.sqlite3"
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                clock=lambda: T0,
            )
            # Tick 1: open initial EURUSD BUY leg 1 (INITIAL_SL)
            out1 = eng.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.12000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            self.assertEqual(out1["tiers"][0]["open_positions"], 1)

            # Tick 2: excursion < 12 pips -> leg 1 stays INITIAL_SL -> ADD refused
            quotes_pre_be = {**QUOTES, "EURUSD": (D("1.10050"), D("1.10060"))}
            out2 = eng.process_tick(
                quotes=quotes_pre_be,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09800",
                    "take_profit_price": "1.12000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0 + timedelta(seconds=5),
            )
            self.assertEqual(out2["tiers"][0]["open_positions"], 1)
            self.assertIn("PRIOR_LEG_NOT_BREAKEVEN_LOCKED", str(out2["tiers"][0]["last_skip_reason"]))

            # Tick 3: excursion >= 22 pips -> leg 1 ratchets to TRAILING_PROFIT -> ADD admitted as leg 2
            quotes_locked = {**QUOTES, "EURUSD": (D("1.10800"), D("1.10810"))}
            out3 = eng.process_tick(
                quotes=quotes_locked,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.10310",
                    "take_profit_price": "1.12000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0 + timedelta(seconds=10),
            )
            self.assertEqual(out3["tiers"][0]["open_positions"], 2)
            self.assertIsNone(out3["tiers"][0]["last_skip_reason"])
            conn = sqlite3.connect(str(db_path))
            try:
                legs = [r[0] for r in conn.execute("SELECT leg_index FROM tier_positions ORDER BY leg_index").fetchall()]
            finally:
                conn.close()
            self.assertEqual(legs, [1, 2])

    def test_parallel_tier_daily_quota_pct_targets_and_soft_quota_scaling(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers.sqlite3"
            ctrl_db = Path(td) / "ctrl.sqlite3"
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0], DEFAULT_PARALLEL_TIER_SPECS[4]),
                clock=lambda: T0,
            )
            ctrl = ParallelTierEngine(
                ctrl_db,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                clock=lambda: T0,
            )
            # Tick 1: open EURUSD BUY on both $300k and $300 tiers -> verify PCT quota targets
            eng.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.10810",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            snap_300k = eng._quotas["TIER_1_CURRENT"].snapshot(now=T0)
            self.assertEqual(snap_300k["quota_mode"], "PCT")
            self.assertEqual(D(snap_300k["starting_equity_usd"]), D("300000"))
            self.assertEqual(D(snap_300k["hard_quota_usd"]), D("7500"))
            self.assertEqual(D(snap_300k["soft_quota_usd"]), D("3750"))

            snap_300 = eng._quotas["TIER_5_300"].snapshot(now=T0)
            self.assertEqual(snap_300["quota_mode"], "PCT")
            self.assertEqual(D(snap_300["starting_equity_usd"]), D("300"))
            self.assertEqual(D(snap_300["hard_quota_usd"]), D("7.50"))
            self.assertEqual(D(snap_300["soft_quota_usd"]), D("3.75"))

            # Tick 2: hit TP on EURUSD -> TIER_1_CURRENT reaches SOFT_QUOTA_REACHED ($4,779 >= $3,750, < $7,500)
            t1 = T0 + timedelta(seconds=5)
            quotes_tp = {**QUOTES, "EURUSD": (D("1.10820"), D("1.10830"))}
            eng.process_tick(quotes=quotes_tp, signal=None, now=t1)
            snap_soft = eng._quotas["TIER_1_CURRENT"].snapshot(now=t1)
            self.assertEqual(snap_soft["status"], "SOFT_QUOTA_REACHED")
            self.assertEqual(D(snap_soft["risk_multiplier"]), D("0.50"))

            # Tick 3: GBPUSD BUY sized at ~0.50x on soft-quota engine vs clean control
            t2 = T0 + timedelta(seconds=10)
            sig_gbp = {
                "symbol": "GBPUSD",
                "side": "BUY",
                "stop_price": "1.26512",
                "take_profit_price": "1.28000",
                "regime": REGIME_STRONG_TREND,
            }
            eng.process_tick(quotes=QUOTES, signal=sig_gbp, now=t2)
            ctrl.process_tick(quotes=QUOTES, signal=sig_gbp, now=t2)

            c_eng = sqlite3.connect(str(db_path))
            c_ctrl = sqlite3.connect(str(ctrl_db))
            try:
                soft_units = D(
                    c_eng.execute(
                        "SELECT units FROM tier_positions WHERE tier_id = 'TIER_1_CURRENT' AND symbol = 'GBPUSD'"
                    ).fetchone()[0]
                )
                ctrl_units = D(
                    c_ctrl.execute(
                        "SELECT units FROM tier_positions WHERE tier_id = 'TIER_1_CURRENT' AND symbol = 'GBPUSD'"
                    ).fetchone()[0]
                )
            finally:
                c_eng.close()
                c_ctrl.close()
            self.assertLess(soft_units, ctrl_units)
            ratio = soft_units / ctrl_units
            self.assertGreaterEqual(ratio, D("0.48"))
            self.assertLessEqual(ratio, D("0.52"))

    def test_valve_adversarial_cross_instrument_ambiguous_target_and_open_stop_tp_guards(self) -> None:
        gate = load_default_forex_valve_gate()
        self.assertEqual(gate.controller.parameter_count, 161)
        self.assertEqual(gate.controller.threshold, 0.55)
        self.assertEqual(gate.max_drawdown_pct, D("0.10"))
        now_t = T0 + timedelta(seconds=1)

        # 1. Cross-instrument current_market must NOT fall back to USDJPY when intent is EURUSD
        usdjpy_first_view = _clean_view(
            extra={
                "current_market": [
                    {"instrument_id": "USDJPY", "bid": "150.00", "ask": "150.02"},
                ],
                "position_inventory": [{"position_id": "pos-1", "side": "BUY", "stop_price": "1.0950"}],
            }
        )
        # EURUSD BUY stop 1.1020 would look < 150.00 if USDJPY leaked, so with no EURUSD market it stays admitted;
        # conversely a USDJPY-only quote must not cause a false inverted SELL veto on EURUSD BUY/SELL.
        dec_no_leak = gate.require_admissible(
            _make_amend_proposal(stop_price=D("1.1020")),
            current_view=usdjpy_first_view,
            now=now_t,
        )
        self.assertTrue(dec_no_leak.admitted)

        # When USDJPY comes first and EURUSD comes second, EURUSD quote MUST be matched (1.1060 >= bid 1.1060 -> veto)
        both_mkt_view = _clean_view(
            extra={
                "current_market": [
                    {"instrument_id": "USDJPY", "bid": "150.00", "ask": "150.02"},
                    {"instrument_id": "EURUSD", "bid": "1.1060", "ask": "1.1062"},
                ],
                "position_inventory": [{"position_id": "pos-1", "side": "BUY", "stop_price": "1.0950"}],
            }
        )
        with self.assertRaises(ValveRefusalError) as ctx_eur:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1060")),
                current_view=both_mkt_view,
                now=now_t,
            )
        self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_eur.exception.decision.hard_veto_reasons)

        # 2. Cross-target position_inventory (single dict with mismatched id) must NOT leak side/prev_stop
        #    and triggers MISSING_POSITION_SIDE when target_id does not match any dict entry
        wrong_target_view = _clean_view(
            extra={
                "current_market": [{"instrument_id": "EURUSD", "bid": "1.1060", "ask": "1.1062"}],
                "position_inventory": [{"position_id": "pos-other", "side": "BUY", "stop_price": "1.0950"}],
            }
        )
        with self.assertRaises(ValveRefusalError) as ctx_wrong_tgt:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), target_id="pos-1"),
                current_view=wrong_target_view,
                now=now_t,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_wrong_tgt.exception.decision.hard_veto_reasons)

        # 3. MT5-style "position_ticket" lookup across 2+ positions selects matching target ("pos-2")
        multi_ticket_view = _clean_view(
            extra={
                "current_market": [{"instrument_id": "EURUSD", "bid": "1.0940", "ask": "1.0942"}],
                "position_inventory": [
                    {"position_ticket": "pos-1", "side": "BUY", "stop_price": "1.0800"},
                    {"position_ticket": "pos-2", "side": "SELL", "stop_price": "1.0990"},
                ],
            }
        )
        with self.assertRaises(ValveRefusalError) as ctx_ticket_loose:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0995"), target_id="pos-2"),
                current_view=multi_ticket_view,
                now=now_t,
            )
        self.assertIn("LOOSENED_SELL_PROTECTIVE_STOP", ctx_ticket_loose.exception.decision.hard_veto_reasons)

        # 4. Multi-position dict inventory with unmatched target_id triggers MISSING_POSITION_SIDE even without quotes
        with self.assertRaises(ValveRefusalError) as ctx_multi_ambig:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), target_id="pos-missing"),
                current_view=_clean_view(
                    extra={
                        "position_inventory": [
                            {"position_id": "pos-1", "side": "BUY", "stop_price": "1.0950"},
                            {"position_id": "pos-2", "side": "SELL", "stop_price": "1.1100"},
                        ],
                    }
                ),
                now=now_t,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_multi_ambig.exception.decision.hard_veto_reasons)

        # 5. String-only position_inventory (["pos-1"]) WITH market context triggers MISSING_POSITION_SIDE
        with self.assertRaises(ValveRefusalError) as ctx_str_mkt:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), target_id="pos-1"),
                current_view=_clean_view(
                    extra={
                        "current_market": [{"instrument_id": "EURUSD", "bid": "1.1060", "ask": "1.1062"}],
                        "position_inventory": ["pos-1"],
                    }
                ),
                now=now_t,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_str_mkt.exception.decision.hard_veto_reasons)

        # 6. Quote-less AMEND_STOP with string-only inventory (missing side/prev_stop) MUST veto (Finding [1])
        with self.assertRaises(ValveRefusalError) as ctx_quoteless_str:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), target_id="pos-1"),
                current_view=_clean_view(extra={"position_inventory": ["pos-1"]}),
                now=now_t,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_quoteless_str.exception.decision.hard_veto_reasons)

        # 7. OPEN with limit_price=None and BUY stop >= obs_bid is vetoed (INVERTED_BUY_PROTECTIVE_STOP)
        eur_mkt_view = _clean_view(
            extra={"current_market": [{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}]}
        )
        with self.assertRaises(ValveRefusalError) as ctx_open_buy_inv:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.1000"),
                    take_profit_price=D("1.1100"),
                ),
                current_view=eur_mkt_view,
                now=now_t,
            )
        self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_open_buy_inv.exception.decision.hard_veto_reasons)

        # 8. ADD with limit_price=None and SELL stop <= obs_ask is vetoed (INVERTED_SELL_PROTECTIVE_STOP)
        with self.assertRaises(ValveRefusalError) as ctx_add_sell_inv:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.ADD,
                    side=Side.SELL,
                    limit_price=None,
                    stop_price=D("1.1002"),
                    take_profit_price=D("1.0900"),
                    target_id="pos-1",
                ),
                current_view=eur_mkt_view,
                now=now_t,
            )
        self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_add_sell_inv.exception.decision.hard_veto_reasons)

        # 9. OPEN/ADD with non-finite or non-positive take_profit_price ("NaN") is vetoed (INVALID_TAKE_PROFIT_PRICE)
        for bad_tp in ("NaN", "inf", D("0")):
            with self.assertRaises(ValveRefusalError) as ctx_bad_tp:
                gate.require_admissible(
                    _make_order_proposal(
                        kind=ActionKind.OPEN,
                        side=Side.BUY,
                        limit_price=None,
                        stop_price=D("1.0950"),
                        take_profit_price=bad_tp,
                    ),
                    current_view=eur_mkt_view,
                    now=now_t,
                )
            self.assertIn("INVALID_TAKE_PROFIT_PRICE", ctx_bad_tp.exception.decision.hard_veto_reasons)

        # 10. Leading-whitespace JSON in observed-* facts is parsed and enforces inverted stop check
        ws_facts = (
            DecisionFact(
                "observed-market-ws",
                "current_market",
                '   {"bid": "1.1000", "ask": "1.1002", "position_side": "BUY"}',
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_ws:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.1005"),
                    take_profit_price=D("1.1100"),
                    facts=ws_facts,
                ),
                current_view=_clean_view(),
                now=now_t,
            )
        self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_ws.exception.decision.hard_veto_reasons)

        # 11. Valid OPEN/ADD with limit_price=None, stop < obs_bid, tp > obs_ask remains ADMITTED
        dec_open_ok = gate.require_admissible(
            _make_order_proposal(
                kind=ActionKind.ADD,
                side=Side.BUY,
                limit_price=None,
                stop_price=D("1.0950"),
                take_profit_price=D("1.1100"),
                target_id="pos-1",
            ),
            current_view=eur_mkt_view,
            now=now_t,
        )
        self.assertTrue(dec_open_ok.admitted)

    def test_parallel_tier_usdjpy_usdcad_mtm_quantizes_upnl(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers_jpy_cad.sqlite3"
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                clock=lambda: T0,
            )
            q_open = {
                **QUOTES,
                "USDJPY": (D("150.000"), D("150.020")),
                "USDCAD": (D("1.35000"), D("1.35020")),
            }
            out_jpy_open = eng.process_tick(
                quotes=q_open,
                signal={
                    "symbol": "USDJPY",
                    "side": "BUY",
                    "stop_price": "149.500",
                    "take_profit_price": "151.000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            self.assertEqual(out_jpy_open["tiers"][0]["open_positions"], 1)

            q_mtm = {
                **QUOTES,
                "USDJPY": (D("150.010"), D("150.030")),
                "USDCAD": (D("1.35010"), D("1.35030")),
            }
            out_mtm = eng.process_tick(
                quotes=q_mtm,
                signal={
                    "symbol": "USDCAD",
                    "side": "BUY",
                    "stop_price": "1.34500",
                    "take_profit_price": "1.36000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0 + timedelta(seconds=5),
            )
            self.assertEqual(out_mtm["tiers"][0]["open_positions"], 2)

            q_mtm2 = {
                **QUOTES,
                "USDJPY": (D("150.025"), D("150.045")),
                "USDCAD": (D("1.35025"), D("1.35045")),
            }
            out_mtm2 = eng.process_tick(quotes=q_mtm2, signal=None, now=T0 + timedelta(seconds=10))
            self.assertEqual(out_mtm2["tiers"][0]["open_positions"], 2)
            eq = D(str(out_mtm2["tiers"][0]["equity_usd"]))
            self.assertEqual(eq, eq.quantize(D("0.01")))

    def test_parallel_tier_add_stop_inside_bid_ask_spread_refused_by_valve(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers_spread_stop.sqlite3"
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                clock=lambda: T0,
            )
            out1 = eng.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.20000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            self.assertEqual(out1["tiers"][0]["open_positions"], 1)

            spread_quotes = {**QUOTES, "EURUSD": (D("1.12000"), D("1.12020"))}
            out2 = eng.process_tick(
                quotes=spread_quotes,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.12010",
                    "take_profit_price": "1.20000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0 + timedelta(seconds=5),
            )
            self.assertEqual(out2["tiers"][0]["open_positions"], 1)
            skip_reason = str(out2["tiers"][0]["last_skip_reason"])
            self.assertIn("VALVE_REFUSED", skip_reason)
            self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", skip_reason)

            out3 = eng.process_tick(
                quotes=spread_quotes,
                signal=None,
                now=T0 + timedelta(seconds=10),
            )
            self.assertEqual(out3["tiers"][0]["open_positions"], 1)
            self.assertEqual(out3["tiers"][0]["closed_trades"], 0)
            self.assertEqual(out3["tiers"][0]["loss_count"], 0)

    def test_valve_whitespace_padded_json_facts_and_quoteless_prev_stop_missing_side(self) -> None:
        gate = load_default_forex_valve_gate()
        now_t = T0 + timedelta(seconds=1)

        # 1. Whitespace-padded observed-permissions vetoes OPEN (NEW_RISK_NOT_ALLOWED) and AMEND_STOP (MANAGEMENT_NOT_ALLOWED)
        ws_perm_facts = (
            DecisionFact(
                "observed-permissions",
                "permissions",
                '\n  {"new_risk": false, "management": false}',
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_open_perm:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=ws_perm_facts,
                ),
                current_view=None,
                policy=None,
                now=now_t,
            )
        self.assertIn("NEW_RISK_NOT_ALLOWED", ctx_open_perm.exception.decision.hard_veto_reasons)

        with self.assertRaises(ValveRefusalError) as ctx_amend_perm:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0980"), facts=ws_perm_facts),
                current_view=None,
                policy=None,
                now=now_t,
            )
        self.assertIn("MANAGEMENT_NOT_ALLOWED", ctx_amend_perm.exception.decision.hard_veto_reasons)

        # 2. Whitespace-padded observed-account (available_margin: null & drawdown breach) vetoes OPEN
        ws_margin_facts = (
            DecisionFact(
                "observed-account",
                "account",
                '\n  {"available_margin": null}',
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_margin:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=ws_margin_facts,
                ),
                current_view=None,
                policy=None,
                now=now_t,
            )
        self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_margin.exception.decision.hard_veto_reasons)

        ws_dd_facts = (
            DecisionFact(
                "observed-account",
                "account",
                '\n  {"equity": "50000", "peak_equity": "100000", "available_margin": "40000"}',
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_dd:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=ws_dd_facts,
                ),
                current_view=None,
                policy=None,
                now=now_t,
            )
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_dd.exception.decision.hard_veto_reasons)

        # 3. Quote-less AMEND_STOP against matched position dict carrying stop_price without side -> MISSING_POSITION_SIDE
        with self.assertRaises(ValveRefusalError) as ctx_prev_stop_noside:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0900"), side=None, target_id="pos-1"),
                current_view=_clean_view(
                    extra={"position_inventory": [{"position_ticket": "pos-1", "stop_price": "1.0950"}]}
                ),
                now=now_t,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_prev_stop_noside.exception.decision.hard_veto_reasons)

        # 4. Quote-less AMEND_STOP with ["pos-1"] or [] without authoritative side & prev_stop MUST veto (Finding [1])
        for empty_inv in (["pos-1"], []):
            with self.assertRaises(ValveRefusalError) as ctx_empty:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.0900"), side=None, target_id="pos-1"),
                    current_view=_clean_view(extra={"position_inventory": empty_inv}),
                    now=now_t,
                )
            self.assertIn("MISSING_POSITION_SIDE", ctx_empty.exception.decision.hard_veto_reasons)


    def test_parallel_tier_open_spread_stop_and_marketable_vs_passive_limit_price_valve_guards(self) -> None:
        gate = load_default_forex_valve_gate()
        spread_quotes = {**QUOTES, "EURUSD": (D("1.12000"), D("1.12020"))}
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers_open_spread_stop.sqlite3"
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                clock=lambda: T0,
            )
            # 1. ParallelTierEngine OPEN BUY with bid <= stop_price < ask must be refused by valve
            out_buy = eng.process_tick(
                quotes=spread_quotes,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.12010",
                    "take_profit_price": "1.13000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            self.assertEqual(out_buy["tiers"][0]["open_positions"], 0)
            self.assertIn("VALVE_REFUSED", str(out_buy["tiers"][0]["last_skip_reason"]))
            self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", str(out_buy["tiers"][0]["last_skip_reason"]))

            # 2. ParallelTierEngine OPEN SELL with bid < stop_price <= ask must be refused by valve
            out_sell = eng.process_tick(
                quotes=spread_quotes,
                signal={
                    "symbol": "EURUSD",
                    "side": "SELL",
                    "stop_price": "1.12010",
                    "take_profit_price": "1.11000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0 + timedelta(seconds=1),
            )
            self.assertEqual(out_sell["tiers"][0]["open_positions"], 0)
            self.assertIn("VALVE_REFUSED", str(out_sell["tiers"][0]["last_skip_reason"]))
            self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", str(out_sell["tiers"][0]["last_skip_reason"]))

        # 3. Direct ForexMetaValveGate marketable limit_price (BUY >= obs_ask, SELL <= obs_bid) enforces obs_bid/obs_ask
        eur_view = _clean_view(
            extra={"current_market": [{"instrument_id": "EURUSD", "bid": "1.12000", "ask": "1.12020"}]}
        )
        with self.assertRaises(ValveRefusalError) as ctx_mkt_buy:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.BUY,
                    limit_price=D("1.12020"),
                    stop_price=D("1.12010"),
                    take_profit_price=D("1.13000"),
                ),
                current_view=eur_view,
                now=T0,
            )
        self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_mkt_buy.exception.decision.hard_veto_reasons)

        with self.assertRaises(ValveRefusalError) as ctx_mkt_sell:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    side=Side.SELL,
                    limit_price=D("1.12000"),
                    stop_price=D("1.12010"),
                    take_profit_price=D("1.11000"),
                ),
                current_view=eur_view,
                now=T0,
            )
        self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_mkt_sell.exception.decision.hard_veto_reasons)

        # 4. Valid passive limit orders (BUY limit_p < obs_ask; SELL limit_p > obs_bid) remain ADMITTED
        dec_passive_buy = gate.require_admissible(
            _make_order_proposal(
                kind=ActionKind.OPEN,
                side=Side.BUY,
                limit_price=D("1.11500"),
                stop_price=D("1.11000"),
                take_profit_price=D("1.13000"),
            ),
            current_view=eur_view,
            now=T0,
        )
        self.assertTrue(dec_passive_buy.admitted)

        dec_passive_sell = gate.require_admissible(
            _make_order_proposal(
                kind=ActionKind.OPEN,
                side=Side.SELL,
                limit_price=D("1.12500"),
                stop_price=D("1.13000"),
                take_profit_price=D("1.11000"),
            ),
            current_view=eur_view,
            now=T0,
        )
        self.assertTrue(dec_passive_sell.admitted)

    def test_parallel_tier_is_add_usdjpy_usdcad_usdchf_quantizes_quote_to_usd(self) -> None:
        gate = load_default_forex_valve_gate()
        cases = [
            ("USDJPY", (D("154.321"), D("154.349")), (D("156.500"), D("156.528")), "153.800", "160.000", "156.100"),
            ("USDCAD", (D("1.39173"), D("1.39199")), (D("1.41500"), D("1.41526")), "1.38700", "1.45000", "1.41000"),
            ("USDCHF", (D("0.88317"), D("0.88341")), (D("0.90500"), D("0.90524")), "0.87800", "0.94000", "0.90000"),
        ]
        with tempfile.TemporaryDirectory() as td:
            for sym, q_open_pair, q_trail_pair, sl1, tp1, sl2 in cases:
                db_path = Path(td) / f"tiers_{sym}.sqlite3"
                eng = ParallelTierEngine(
                    db_path,
                    valve_gate=gate,
                    specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                    clock=lambda: T0,
                )
                q_open = {**QUOTES, sym: q_open_pair}
                out1 = eng.process_tick(
                    quotes=q_open,
                    signal={
                        "symbol": sym,
                        "side": "BUY",
                        "stop_price": sl1,
                        "take_profit_price": tp1,
                        "regime": REGIME_STRONG_TREND,
                    },
                    now=T0,
                )
                self.assertEqual(out1["tiers"][0]["open_positions"], 1)

                # Pre-breakeven ADD must return PYRAMID_BLOCKED cleanly without ContractError
                out2 = eng.process_tick(
                    quotes=q_open,
                    signal={
                        "symbol": sym,
                        "side": "BUY",
                        "stop_price": sl1,
                        "take_profit_price": tp1,
                        "regime": REGIME_STRONG_TREND,
                    },
                    now=T0 + timedelta(seconds=2),
                )
                self.assertEqual(out2["tiers"][0]["open_positions"], 1)
                self.assertIn("PYRAMID_BLOCKED", str(out2["tiers"][0]["last_skip_reason"]))

                # After trailing breakeven lock, ADD must be admitted cleanly without ContractError
                q_trail = {**QUOTES, sym: q_trail_pair}
                out3 = eng.process_tick(
                    quotes=q_trail,
                    signal={
                        "symbol": sym,
                        "side": "BUY",
                        "stop_price": sl2,
                        "take_profit_price": tp1,
                        "regime": REGIME_STRONG_TREND,
                    },
                    now=T0 + timedelta(seconds=4),
                )
                self.assertEqual(out3["tiers"][0]["open_positions"], 2)
                self.assertIsNone(out3["tiers"][0]["last_skip_reason"])

    def test_valve_whitespace_and_bom_accounting_sentinels_vetoed_as_missing_accounting(self) -> None:
        gate = load_default_forex_valve_gate()
        sentinels = (" null ", '\t"UNAVAILABLE"\n', " UNAVAILABLE ", " unavailable ", "\ufeffnull", ' "null" ')

        # 1. Whitespace/sentinel position_inventory on OPEN (current_view=None) -> MISSING_REQUIRED_ACCOUNTING
        for bad_val in sentinels:
            facts = (
                DecisionFact("f-bal", "balance", "10000", ("ev-m1-1",)),
                DecisionFact("f-eq", "equity", "10000", ("ev-m1-1",)),
                DecisionFact("f-mg", "available_margin", "9000", ("ev-m1-1",)),
                DecisionFact("f-pi", "position_inventory", bad_val, ("ev-m1-1",)),
            )
            with self.assertRaises(ValveRefusalError) as ctx_open:
                gate.require_admissible(
                    _make_order_proposal(kind=ActionKind.OPEN, side=Side.BUY, limit_price=None, facts=facts),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_open.exception.decision.hard_veto_reasons)

        # 2. Whitespace/sentinel balance/equity/position_inventory on AMEND_STOP -> MISSING_REQUIRED_ACCOUNTING
        for field_name in ("balance", "equity", "available_margin", "position_inventory"):
            for bad_val in (" null ", '\t"UNAVAILABLE"\n', " UNAVAILABLE "):
                base_map = {
                    "balance": "10000",
                    "equity": "10000",
                    "available_margin": "9000",
                    "position_inventory": "[]",
                }
                base_map[field_name] = bad_val
                facts = tuple(DecisionFact(f"f-{k}", k, v, ("ev-m1-1",)) for k, v in base_map.items())
                with self.assertRaises(ValveRefusalError) as ctx_amend:
                    gate.require_admissible(
                        _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts),
                        current_view=None,
                        now=T0,
                    )
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_amend.exception.decision.hard_veto_reasons)

        # 3. observed-account JSON dict checks all req_fields including null/whitespace sentinels and BOM
        acct_payloads = (
            '{"balance": "10000", "equity": "10000", "available_margin": "null", "position_inventory": []}',
            '{"balance": "10000", "equity": "10000", "available_margin": " UNAVAILABLE ", "position_inventory": []}',
            '{"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": null}',
            '\ufeff{"balance": " null ", "equity": "10000", "available_margin": "9000", "position_inventory": []}',
            '{"balance": "10000", "equity": "10000", "available_margin": "   ", "position_inventory": []}',
        )
        for payload in acct_payloads:
            facts = (DecisionFact("observed-account", "account", payload, ("ev-m1-1",)),)
            with self.assertRaises(ValveRefusalError) as ctx_acct:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_acct.exception.decision.hard_veto_reasons)

    def test_parallel_tier_daily_quota_locked_then_loss_breach_blocks_strong_trend_add(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "tiers_quota_loss_guard.sqlite3"
            eng = ParallelTierEngine(
                db_path,
                valve_gate=gate,
                specs=(DEFAULT_PARALLEL_TIER_SPECS[0],),
                clock=lambda: T0,
            )
            out1 = eng.process_tick(
                quotes=QUOTES,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.20000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            self.assertEqual(out1["tiers"][0]["open_positions"], 1)

            # Hit hard profit quota (+$8,000 -> DAILY_QUOTA_LOCKED), then lose -$18,000 (net -$10,000 <= -$9,000 max loss)
            snap_win = eng._quotas["TIER_1_CURRENT"].record_realized_trade(
                D("8000"), symbol="EURUSD", ticket="t-win", starting_equity=D("300000"), now=T0 + timedelta(seconds=1)
            )
            self.assertEqual(snap_win["status"], QUOTA_STATUS_LOCKED)
            eng._quotas["TIER_1_CURRENT"].record_realized_trade(
                D("-18000"), symbol="EURUSD", ticket="t-loss", starting_equity=D("300000"), now=T0 + timedelta(seconds=2)
            )

            # Advance price into trailing profit so Pyramid check would otherwise pass, and attempt STRONG_TREND ADD
            out2 = eng.process_tick(
                quotes={**QUOTES, "EURUSD": (D("1.10800"), D("1.10810"))},
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.10310",
                    "take_profit_price": "1.20000",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0 + timedelta(seconds=5),
            )
            self.assertEqual(out2["tiers"][0]["open_positions"], 1)
            self.assertEqual(
                out2["tiers"][0]["last_skip_reason"],
                f"DAILY_QUOTA ({QUOTA_STATUS_LOSS_TRIPPED})",
            )

    def test_valve_obs_dict_filters_cross_instrument_and_cross_target_observations(self) -> None:
        gate = load_default_forex_valve_gate()

        # 1. Cross-instrument observed-market dicts: EURUSD dict before USDJPY dict on USDJPY SELL OPEN
        cross_inst_facts = (
            DecisionFact(
                "observed-market-eurusd",
                "market",
                json.dumps({"instrument_id": "EURUSD", "bid": "1.10000", "ask": "1.10020"}),
                ("ev-m1-1",),
            ),
            DecisionFact(
                "observed-market-usdjpy",
                "market",
                json.dumps({"instrument_id": "usdjpy", "bid": "154.300", "ask": "154.340"}),
                ("ev-m1-1",),
            ),
            DecisionFact(
                "observed-account",
                "account",
                json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_a2:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    instrument_id="USDJPY",
                    side=Side.SELL,
                    limit_price=None,
                    stop_price=D("150.000"),
                    take_profit_price=None,
                    facts=cross_inst_facts,
                ),
                current_view=None,
                now=T0,
            )
        self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_a2.exception.decision.hard_veto_reasons)

        # 2. current_view top-level EURUSD dict does not mask USDJPY quotes in nested current_market
        cv_cross = _clean_view(
            extra={
                "instrument_id": "EURUSD",
                "bid": "1.10000",
                "ask": "1.10020",
                "current_market": [{"instrument_id": "USDJPY", "bid": "154.300", "ask": "154.340"}],
            }
        )
        with self.assertRaises(ValveRefusalError) as ctx_cv:
            gate.require_admissible(
                _make_order_proposal(
                    kind=ActionKind.OPEN,
                    instrument_id="USDJPY",
                    side=Side.SELL,
                    limit_price=None,
                    stop_price=D("150.000"),
                    take_profit_price=None,
                ),
                current_view=cv_cross,
                now=T0,
            )
        self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_cv.exception.decision.hard_veto_reasons)

        # Top-level EURUSD quotes alone must NOT falsely veto a valid USDJPY SELL OPEN
        cv_eur_only = _clean_view(extra={"instrument_id": "EURUSD", "bid": "1.10000", "ask": "1.10020"})
        dec_valid_jpy = gate.require_admissible(
            _make_order_proposal(
                kind=ActionKind.OPEN,
                instrument_id="USDJPY",
                side=Side.SELL,
                limit_price=None,
                stop_price=D("154.500"),
                take_profit_price=D("153.500"),
            ),
            current_view=cv_eur_only,
            now=T0,
        )
        self.assertTrue(dec_valid_jpy.admitted)

        # 3. Cross-target observed-pos dicts: pos-1 before pos-2 on AMEND_STOP targeting pos-2
        acct_fact = DecisionFact(
            "observed-account",
            "account",
            json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
            ("ev-m1-1",),
        )
        cross_pos_facts = (
            DecisionFact(
                "observed-pos-1",
                "pos",
                json.dumps({"position_id": "pos-1", "side": "SELL", "stop_loss": "1.10500"}),
                ("ev-m1-1",),
            ),
            DecisionFact(
                "observed-pos-2",
                "pos",
                json.dumps({"position_id": "pos-2", "side": "SELL", "current_stop": "1.10200"}),
                ("ev-m1-1",),
            ),
            acct_fact,
        )
        with self.assertRaises(ValveRefusalError) as ctx_b:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.10400"), side=None, target_id="pos-2", facts=cross_pos_facts),
                current_view=None,
                now=T0,
            )
        self.assertIn("LOOSENED_SELL_PROTECTIVE_STOP", ctx_b.exception.decision.hard_veto_reasons)

        # 4. Cross-target observed-pos-1 only on AMEND_STOP targeting pos-2 (side=None) -> MISSING_POSITION_SIDE
        for include_mkt in (True, False):
            pos1_only = [
                DecisionFact(
                    "observed-pos-1",
                    "pos",
                    json.dumps({"position_id": "pos-1", "side": "BUY", "stop_price": "1.09500"}),
                    ("ev-m1-1",),
                ),
                acct_fact,
            ]
            if include_mkt:
                pos1_only.append(
                    DecisionFact(
                        "observed-market",
                        "market",
                        json.dumps({"instrument_id": "EURUSD", "bid": "1.10000", "ask": "1.10020"}),
                        ("ev-m1-1",),
                    )
                )
            with self.assertRaises(ValveRefusalError) as ctx_b2:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.09800"), side=None, target_id="pos-2", facts=tuple(pos1_only)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("MISSING_POSITION_SIDE", ctx_b2.exception.decision.hard_veto_reasons)

    def test_valve_whitespace_before_bom_inner_quoted_and_money_dict_sentinels(self) -> None:
        gate = load_default_forex_valve_gate()

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk reduction",
                        selected_action_ref=f"opt-m1-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-{kind.value.lower()}",
                    action_ref=f"opt-m1-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        all_actions = (ActionKind.OPEN, ActionKind.ADD, ActionKind.AMEND_STOP, ActionKind.REDUCE, ActionKind.CLOSE)
        str_sentinels = (" \ufeffnull", ' \ufeff"UNAVAILABLE"', ' " null " ', ' " unavailable " ', ' "\ufeffnull" ')
        dict_sentinels = (
            {"amount": "UNAVAILABLE", "currency": "USD"},
            {"amount": " \ufeffnull"},
            {"value": ' " unavailable " '},
        )

        # 1. Whitespace-before-BOM, inner-quoted sentinels, and Money-dict sentinels across all 5 actions
        for action in all_actions:
            for bad_val in (*str_sentinels, *dict_sentinels):
                cv_bad = _clean_view(extra={"available_margin": bad_val})
                with self.assertRaises(ValveRefusalError) as ctx_cv:
                    gate.require_admissible(_proposal_for(action), current_view=cv_bad, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_cv.exception.decision.hard_veto_reasons)

                obs_acct = {
                    "balance": "10000",
                    "equity": "10000",
                    "available_margin": bad_val,
                    "position_inventory": [],
                }
                obs_facts = (
                    DecisionFact("observed-account", "account", " \ufeff" + json.dumps(obs_acct), ("ev-m1-1",)),
                )
                with self.assertRaises(ValveRefusalError) as ctx_obs:
                    gate.require_admissible(_proposal_for(action, facts=obs_facts), current_view=None, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_obs.exception.decision.hard_veto_reasons)

            for bad_str in str_sentinels:
                fact_map_facts = (
                    DecisionFact("f-bal", "balance", "10000", ("ev-m1-1",)),
                    DecisionFact("f-eq", "equity", "10000", ("ev-m1-1",)),
                    DecisionFact("f-mgn", "available_margin", bad_str, ("ev-m1-1",)),
                    DecisionFact("f-inv", "position_inventory", "[]", ("ev-m1-1",)),
                )
                with self.assertRaises(ValveRefusalError) as ctx_fm:
                    gate.require_admissible(_proposal_for(action, facts=fact_map_facts), current_view=None, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_fm.exception.decision.hard_veto_reasons)

            # Whitespace-before-BOM observed-account null margin
            ws_bom_null_obs = (
                DecisionFact(
                    "observed-account",
                    "account",
                    ' \ufeff{"balance": "10000", "equity": "10000", "available_margin": null, "position_inventory": []}',
                    ("ev-m1-1",),
                ),
            )
            with self.assertRaises(ValveRefusalError) as ctx_null_obs:
                gate.require_admissible(_proposal_for(action, facts=ws_bom_null_obs), current_view=None, now=T0)
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_null_obs.exception.decision.hard_veto_reasons)

        # 2. Whitespace-before-BOM observed-policy across new-risk and management actions
        ws_bom_policy_facts = (
            DecisionFact("observed-policy", "policy", ' \ufeff{"new_risk": false, "management": false}', ("ev-m1-1",)),
            DecisionFact(
                "observed-account",
                "account",
                json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
                ("ev-m1-1",),
            ),
        )
        for action in (ActionKind.OPEN, ActionKind.ADD):
            with self.assertRaises(ValveRefusalError) as ctx_nr:
                gate.require_admissible(_proposal_for(action, facts=ws_bom_policy_facts), current_view=None, now=T0)
            self.assertIn("NEW_RISK_NOT_ALLOWED", ctx_nr.exception.decision.hard_veto_reasons)
        for action in (ActionKind.AMEND_STOP, ActionKind.REDUCE, ActionKind.CLOSE):
            with self.assertRaises(ValveRefusalError) as ctx_mgmt:
                gate.require_admissible(_proposal_for(action, facts=ws_bom_policy_facts), current_view=None, now=T0)
            self.assertIn("MANAGEMENT_NOT_ALLOWED", ctx_mgmt.exception.decision.hard_veto_reasons)

        # 3. Whitespace-before-BOM observed-current_market list & nested current_market JSON string
        mkt_json = ' \ufeff[{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1005"}]'
        for mkt_facts in (
            (
                DecisionFact("observed-current_market", "market", mkt_json, ("ev-m1-1",)),
                DecisionFact(
                    "observed-account",
                    "account",
                    json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
                    ("ev-m1-1",),
                ),
            ),
            (
                DecisionFact(
                    "observed-account",
                    "account",
                    json.dumps(
                        {
                            "balance": "10000",
                            "equity": "10000",
                            "available_margin": "9000",
                            "position_inventory": [],
                            "current_market": mkt_json,
                        }
                    ),
                    ("ev-m1-1",),
                ),
            ),
        ):
            with self.assertRaises(ValveRefusalError) as ctx_mkt:
                gate.require_admissible(
                    _make_order_proposal(
                        kind=ActionKind.OPEN,
                        side=Side.BUY,
                        limit_price=None,
                        stop_price=D("1.1002"),
                        take_profit_price=D("1.1150"),
                        facts=mkt_facts,
                    ),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_mkt.exception.decision.hard_veto_reasons)

        # 4. Valid typed Money dicts remain cleanly admitted (no false positives)
        valid_money_view = {
            "account_id": "acct-m1",
            "balance": {"amount": "10000", "currency": "USD"},
            "equity": {"amount": "10000", "currency": "USD"},
            "peak_equity": {"amount": "10000", "currency": "USD"},
            "available_margin": {"amount": "9000", "currency": "USD"},
            "position_inventory": [],
        }
        dec_ok = gate.require_admissible(_proposal_for(ActionKind.OPEN), current_view=valid_money_view, now=T0)
        self.assertTrue(dec_ok.admitted)

    def test_valve_json_stringified_and_malformed_money_dicts_and_fixed_point_ws(self) -> None:
        gate = load_default_forex_valve_gate()

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-r6-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk control",
                        selected_action_ref=f"opt-m1-r6-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-r6-{kind.value.lower()}",
                    action_ref=f"opt-m1-r6-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        # 1. Fixed-point _strip_bom_and_ws with NBSP + BOM interleaving
        self.assertEqual(_strip_bom_and_ws("\u00a0\ufeff\u00a0null\u00a0\ufeff\u00a0"), "null")
        self.assertTrue(_is_unavailable_accounting_value("\u00a0\ufeff\u00a0null\u00a0\ufeff\u00a0"))
        self.assertTrue(_is_unavailable_accounting_value("\u00a0\ufeff\u00a0UNAVAILABLE\u00a0\ufeff\u00a0"))

        all_6_actions = (
            ActionKind.OPEN,
            ActionKind.ADD,
            ActionKind.AMEND_STOP,
            ActionKind.REDUCE,
            ActionKind.CLOSE,
            ActionKind.CANCEL_ORDER,
        )
        json_money_sentinels = (
            '{"amount": "UNAVAILABLE", "currency": "USD"}',
            '{"amount": "NaN"}',
            '{"currency": "USD"}',
            ' \ufeff{"amount": " \ufeffnull"}',
            '{"amount": "N/A", "currency": "USD"}',
            '{"amount": "Infinity", "currency": "USD"}',
        )
        malformed_raw_dicts = (
            {"currency": "USD"},
            {},
            {"amount": "NaN"},
            {"amount": "N/A"},
            {"amount": "Infinity"},
            {"amount": "-Infinity"},
        )
        nbsp_bom_sentinels = (
            "\u00a0\ufeff\u00a0null\u00a0\ufeff\u00a0",
            "\u00a0\ufeff\u00a0UNAVAILABLE\u00a0\ufeff\u00a0",
        )

        # 2. JSON-stringified Money-dict sentinels in DecisionFact & current_view across all 6 ActionKinds
        for action in all_6_actions:
            for field_name in ("balance", "equity", "available_margin"):
                for bad_json_money in json_money_sentinels:
                    base_facts = {
                        "balance": DecisionFact(
                            "observed-balance-1", "balance", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)
                        ),
                        "equity": DecisionFact(
                            "observed-equity-1", "equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)
                        ),
                        "peak_equity": DecisionFact(
                            "observed-peak_equity-1", "peak_equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)
                        ),
                        "available_margin": DecisionFact(
                            "observed-available_margin-1",
                            "available_margin",
                            '{"amount": "9000", "currency": "USD"}',
                            ("ev-m1-1",),
                        ),
                        "position_inventory": DecisionFact(
                            "observed-position_inventory-1", "position_inventory", "[]", ("ev-m1-1",)
                        ),
                    }
                    base_facts[field_name] = DecisionFact(
                        f"observed-{field_name}-1", field_name, bad_json_money, ("ev-m1-1",)
                    )
                    with self.assertRaises(ValveRefusalError) as ctx_df:
                        gate.require_admissible(
                            _proposal_for(action, facts=tuple(base_facts.values())), current_view=None, now=T0
                        )
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_df.exception.decision.hard_veto_reasons)

                    cv_bad_json = _clean_view(
                        extra={
                            "balance": '{"amount": "10000", "currency": "USD"}',
                            "equity": '{"amount": "10000", "currency": "USD"}',
                            "peak_equity": '{"amount": "10000", "currency": "USD"}',
                            "available_margin": '{"amount": "9000", "currency": "USD"}',
                        }
                    )
                    cv_bad_json[field_name] = bad_json_money
                    with self.assertRaises(ValveRefusalError) as ctx_cvj:
                        gate.require_admissible(_proposal_for(action), current_view=cv_bad_json, now=T0)
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_cvj.exception.decision.hard_veto_reasons)

            # peak_equity sentinel via custom accounting_required + position_inventory sentinel across all 6 ActionKinds
            peak_facts = (
                DecisionFact("observed-balance-1", "balance", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
                DecisionFact("observed-equity-1", "equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
                DecisionFact(
                    "observed-peak_equity-1",
                    "peak_equity",
                    '{"amount": "UNAVAILABLE", "currency": "USD"}',
                    ("ev-m1-1",),
                ),
                DecisionFact(
                    "observed-available_margin-1", "available_margin", '{"amount": "9000", "currency": "USD"}', ("ev-m1-1",)
                ),
                DecisionFact("observed-position_inventory-1", "position_inventory", "[]", ("ev-m1-1",)),
            )
            peak_policy = {
                "new_risk_permission": "ALLOWED",
                "management_permission": "ALLOWED",
                "accounting_required": ["balance", "equity", "peak_equity", "available_margin", "position_inventory"],
            }
            with self.assertRaises(ValveRefusalError) as ctx_pk:
                gate.require_admissible(
                    _proposal_for(action, facts=peak_facts), current_view=None, policy=peak_policy, now=T0
                )
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_pk.exception.decision.hard_veto_reasons)

            inv_bad_facts = (
                DecisionFact("observed-balance-1", "balance", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
                DecisionFact("observed-equity-1", "equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
                DecisionFact(
                    "observed-available_margin-1", "available_margin", '{"amount": "9000", "currency": "USD"}', ("ev-m1-1",)
                ),
                DecisionFact(
                    "observed-position_inventory-1",
                    "position_inventory",
                    "\u00a0\ufeff\u00a0null\u00a0\ufeff\u00a0",
                    ("ev-m1-1",),
                ),
            )
            with self.assertRaises(ValveRefusalError) as ctx_inv:
                gate.require_admissible(_proposal_for(action, facts=inv_bad_facts), current_view=None, now=T0)
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_inv.exception.decision.hard_veto_reasons)

            # 3. Malformed / non-finite raw Money dicts and NBSP+BOM sentinels across all 6 ActionKinds
            for bad_raw in (*malformed_raw_dicts, *nbsp_bom_sentinels):
                cv_mal = _clean_view(extra={"available_margin": bad_raw})
                with self.assertRaises(ValveRefusalError) as ctx_mal:
                    gate.require_admissible(_proposal_for(action), current_view=cv_mal, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_mal.exception.decision.hard_veto_reasons)

            # 4. Valid JSON-stringified Money dicts admitted cleanly across all 6 ActionKinds
            valid_json_facts = (
                DecisionFact("observed-balance-1", "balance", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
                DecisionFact("observed-equity-1", "equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
                DecisionFact(
                    "observed-peak_equity-1", "peak_equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)
                ),
                DecisionFact(
                    "observed-available_margin-1", "available_margin", '{"amount": "9000", "currency": "USD"}', ("ev-m1-1",)
                ),
                DecisionFact(
                    "observed-position_inventory-1",
                    "position_inventory",
                    json.dumps([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}]),
                    ("ev-m1-1",),
                ),
            )
            dec_facts_ok = gate.require_admissible(
                _proposal_for(action, facts=valid_json_facts), current_view=None, now=T0
            )
            self.assertTrue(dec_facts_ok.admitted)

            valid_json_view = _clean_view(
                extra={
                    "balance": '{"amount": "10000", "currency": "USD"}',
                    "equity": '{"amount": "10000", "currency": "USD"}',
                    "peak_equity": '{"amount": "10000", "currency": "USD"}',
                    "available_margin": '{"amount": "9000", "currency": "USD"}',
                    "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
                }
            )
            dec_view_ok = gate.require_admissible(_proposal_for(action), current_view=valid_json_view, now=T0)
            self.assertTrue(dec_view_ok.admitted)

        # 5. Valid JSON-stringified equity/peak_equity drawdown enforcement (current_view and DecisionFact)
        self.assertEqual(_extract_money_decimal('{"amount": "10000", "currency": "USD"}'), D("10000"))
        dd_view_breach = _clean_view(
            extra={
                "balance": '{"amount": "10000", "currency": "USD"}',
                "equity": '{"amount": "8500", "currency": "USD"}',
                "peak_equity": '{"amount": "10000", "currency": "USD"}',
                "available_margin": '{"amount": "7500", "currency": "USD"}',
            }
        )
        with self.assertRaises(ValveRefusalError) as ctx_dd_cv:
            gate.require_admissible(_proposal_for(ActionKind.OPEN), current_view=dd_view_breach, now=T0)
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_dd_cv.exception.decision.hard_veto_reasons)

        dd_facts_breach = (
            DecisionFact("observed-balance-1", "balance", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
            DecisionFact("observed-equity-1", "equity", '{"amount": "8500", "currency": "USD"}', ("ev-m1-1",)),
            DecisionFact("observed-peak_equity-1", "peak_equity", '{"amount": "10000", "currency": "USD"}', ("ev-m1-1",)),
            DecisionFact(
                "observed-available_margin-1", "available_margin", '{"amount": "7500", "currency": "USD"}', ("ev-m1-1",)
            ),
            DecisionFact("observed-position_inventory-1", "position_inventory", "[]", ("ev-m1-1",)),
        )
        with self.assertRaises(ValveRefusalError) as ctx_dd_df:
            gate.require_admissible(_proposal_for(ActionKind.ADD, facts=dd_facts_breach), current_view=None, now=T0)
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_dd_df.exception.decision.hard_veto_reasons)

    def test_valve_consume_obs_dict_cross_instrument_position_without_id(self) -> None:
        gate = load_default_forex_valve_gate()
        base_acct = DecisionFact(
            "observed-account",
            "account",
            json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
            ("ev-m1-1",),
        )
        gbp_pos_no_id = DecisionFact(
            "observed-pos-gbp",
            "pos",
            json.dumps({"instrument_id": "GBPUSD", "side": "SELL", "stop_price": "1.2500"}),
            ("ev-m1-1",),
        )
        eur_pos_match = DecisionFact(
            "observed-pos-eur",
            "pos",
            json.dumps({"position_id": "pos-2", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.09500"}),
            ("ev-m1-1",),
        )

        # 1. Cross-instrument dict without position_id must NOT bind side/prev_stop -> MISSING_POSITION_SIDE
        with self.assertRaises(ValveRefusalError) as ctx_gbp:
            gate.require_admissible(
                _make_amend_proposal(
                    stop_price=D("1.09700"),
                    side=None,
                    target_id="pos-2",
                    facts=(base_acct, gbp_pos_no_id),
                ),
                current_view=None,
                now=T0,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_gbp.exception.decision.hard_veto_reasons)

        # 2. Subsequent matching EURUSD pos-2 dict still resolves cleanly (tightening admitted, loosening vetoed)
        dec_tight = gate.require_admissible(
            _make_amend_proposal(
                stop_price=D("1.09700"),
                side=None,
                target_id="pos-2",
                facts=(base_acct, gbp_pos_no_id, eur_pos_match),
            ),
            current_view=None,
            now=T0,
        )
        self.assertTrue(dec_tight.admitted)

        with self.assertRaises(ValveRefusalError) as ctx_loose:
            gate.require_admissible(
                _make_amend_proposal(
                    stop_price=D("1.09400"),
                    side=None,
                    target_id="pos-2",
                    facts=(base_acct, gbp_pos_no_id, eur_pos_match),
                ),
                current_view=None,
                now=T0,
            )
        self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_loose.exception.decision.hard_veto_reasons)

    def test_valve_non_finite_decimal_and_non_numeric_accounting_strings_rejected_across_actions(self) -> None:
        gate = load_default_forex_valve_gate()

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-r7-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk control",
                        selected_action_ref=f"opt-m1-r7-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-r7-{kind.value.lower()}",
                    action_ref=f"opt-m1-r7-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        all_6_actions = (
            ActionKind.OPEN,
            ActionKind.ADD,
            ActionKind.AMEND_STOP,
            ActionKind.REDUCE,
            ActionKind.CLOSE,
            ActionKind.CANCEL_ORDER,
        )
        non_numeric_tokens = (
            "-NaN",
            "+NaN",
            "sNaN",
            "-sNaN",
            "+sNaN",
            "undefined",
            "nil",
            "false",
            "true",
            "{broken_json",
            "{'amount': 'UNAVAILABLE'}",
            "-",
            "TBD",
        )
        for tok in non_numeric_tokens:
            self.assertTrue(_is_unavailable_accounting_value(tok), tok)

        for action in all_6_actions:
            for field_name in ("balance", "equity", "available_margin"):
                for bad_tok in non_numeric_tokens:
                    cv = {
                        "account_id": "acct-m1",
                        "balance": "10000",
                        "equity": "10000",
                        "peak_equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [],
                    }
                    cv[field_name] = bad_tok
                    with self.assertRaises(ValveRefusalError) as ctx_cv:
                        gate.require_admissible(_proposal_for(action), current_view=cv, now=T0)
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_cv.exception.decision.hard_veto_reasons)

                    facts = {
                        "balance": DecisionFact("observed-balance-1", "balance", "10000", ("ev-m1-1",)),
                        "equity": DecisionFact("observed-equity-1", "equity", "10000", ("ev-m1-1",)),
                        "peak_equity": DecisionFact("observed-peak_equity-1", "peak_equity", "10000", ("ev-m1-1",)),
                        "available_margin": DecisionFact(
                            "observed-available_margin-1", "available_margin", "9000", ("ev-m1-1",)
                        ),
                        "position_inventory": DecisionFact(
                            "observed-position_inventory-1", "position_inventory", "[]", ("ev-m1-1",)
                        ),
                    }
                    facts[field_name] = DecisionFact(f"observed-{field_name}-1", field_name, bad_tok, ("ev-m1-1",))
                    with self.assertRaises(ValveRefusalError) as ctx_df:
                        gate.require_admissible(_proposal_for(action, facts=tuple(facts.values())), current_view=None, now=T0)
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_df.exception.decision.hard_veto_reasons)

            # Valid position_inventory JSON lists remain admitted (0x/1x/2x for non-AMEND_STOP; populated for all actions incl. AMEND_STOP)
            for valid_pos_inv in (
                [],
                "[]",
                json.dumps("[]"),
                json.dumps(json.dumps("[]")),
                json.dumps([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0900"}]),
            ):
                cv_ok = {
                    "account_id": "acct-m1",
                    "balance": "10000",
                    "equity": "10000",
                    "peak_equity": "10000",
                    "available_margin": "9000",
                    "position_inventory": valid_pos_inv,
                }
                if action is ActionKind.AMEND_STOP and "pos-1" not in str(valid_pos_inv):
                    with self.assertRaises(ValveRefusalError):
                        gate.require_admissible(_proposal_for(action), current_view=cv_ok, now=T0)
                else:
                    dec_ok = gate.require_admissible(_proposal_for(action), current_view=cv_ok, now=T0)
                    self.assertTrue(dec_ok.admitted)

    def test_valve_amend_stop_ambiguous_position_vetoed_even_when_intent_side_supplied(self) -> None:
        gate = load_default_forex_valve_gate()

        # 1. Mismatched target_id in position_inventory with falsified intent.side=Side.BUY loosening SELL stop
        cv_mismatch = {
            "account_id": "acct-m1",
            "balance": "10000",
            "equity": "10000",
            "peak_equity": "10000",
            "available_margin": "9000",
            "position_inventory": [
                {"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"}
            ],
        }
        with self.assertRaises(ValveRefusalError) as ctx_tgt:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1100"), side=Side.BUY, target_id="pos-2"),
                current_view=cv_mismatch,
                now=T0,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_tgt.exception.decision.hard_veto_reasons)

        # 2. Cross-instrument observed-pos dict without position_id with explicit intent.side=Side.BUY
        base_acct = DecisionFact(
            "observed-account",
            "account",
            json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
            ("ev-m1-1",),
        )
        gbp_no_id = DecisionFact(
            "observed-pos-gbp",
            "pos",
            json.dumps({"instrument_id": "GBPUSD", "side": "SELL", "stop_price": "1.2500"}),
            ("ev-m1-1",),
        )
        with self.assertRaises(ValveRefusalError) as ctx_inst:
            gate.require_admissible(
                _make_amend_proposal(
                    stop_price=D("1.1100"),
                    side=Side.BUY,
                    target_id="pos-2",
                    facts=(base_acct, gbp_no_id),
                ),
                current_view=None,
                now=T0,
            )
        self.assertIn("MISSING_POSITION_SIDE", ctx_inst.exception.decision.hard_veto_reasons)

    def test_valve_outer_quoted_observed_json_unwrapped_uniformly_across_refusal_paths(self) -> None:
        gate = load_default_forex_valve_gate()

        def _wrap(obj: object, depth: int) -> str:
            s = json.dumps(obj)
            for _ in range(depth):
                s = json.dumps(s)
            return s

        base_acct = DecisionFact(
            "observed-account",
            "account",
            json.dumps({"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": []}),
            ("ev-m1-1",),
        )

        for depth in (1, 2):
            # 1. observed-policy new_risk=False & management=False
            f_pol_new = DecisionFact("observed-policy-1", "policy", _wrap({"new_risk": False, "management": True}, depth), ("ev-m1-1",))
            with self.assertRaises(ValveRefusalError) as ctx_nr:
                gate.require_admissible(
                    _make_order_proposal(kind=ActionKind.OPEN, facts=(base_acct, f_pol_new)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("NEW_RISK_NOT_ALLOWED", ctx_nr.exception.decision.hard_veto_reasons)

            f_pol_mgmt = DecisionFact("observed-policy-1", "policy", _wrap({"new_risk": True, "management": False}, depth), ("ev-m1-1",))
            with self.assertRaises(ValveRefusalError) as ctx_mg:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=(base_acct, f_pol_mgmt)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("MANAGEMENT_NOT_ALLOWED", ctx_mg.exception.decision.hard_veto_reasons)

            # 2. observed-current_market inverted stop
            f_mkt = DecisionFact(
                "observed-current_market-1",
                "current_market",
                _wrap([{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}], depth),
                ("ev-m1-1",),
            )
            with self.assertRaises(ValveRefusalError) as ctx_mkt:
                gate.require_admissible(
                    _make_order_proposal(kind=ActionKind.OPEN, side=Side.BUY, stop_price=D("1.1050"), facts=(base_acct, f_mkt)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_mkt.exception.decision.hard_veto_reasons)

            # 3. observed-account missing margin & drawdown breach
            f_acct_bad = DecisionFact(
                "observed-account-1",
                "account",
                _wrap({"balance": "10000", "equity": "10000", "available_margin": "-NaN", "position_inventory": []}, depth),
                ("ev-m1-1",),
            )
            with self.assertRaises(ValveRefusalError) as ctx_acct:
                gate.require_admissible(_make_order_proposal(kind=ActionKind.OPEN, facts=(f_acct_bad,)), current_view=None, now=T0)
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_acct.exception.decision.hard_veto_reasons)

            f_acct_dd = DecisionFact(
                "observed-account-1",
                "account",
                _wrap({"balance": "10000", "equity": "8500", "peak_equity": "10000", "available_margin": "7500", "position_inventory": []}, depth),
                ("ev-m1-1",),
            )
            with self.assertRaises(ValveRefusalError) as ctx_dd:
                gate.require_admissible(_make_order_proposal(kind=ActionKind.OPEN, facts=(f_acct_dd,)), current_view=None, now=T0)
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_dd.exception.decision.hard_veto_reasons)

            # 4. observed-pos-* & observed-position_inventory loosened protective stops
            f_pos = DecisionFact(
                "observed-pos-1",
                "pos",
                _wrap({"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0960"}, depth),
                ("ev-m1-1",),
            )
            with self.assertRaises(ValveRefusalError) as ctx_pos:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.0950"), side=Side.BUY, facts=(base_acct, f_pos)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_pos.exception.decision.hard_veto_reasons)

            f_pinv = DecisionFact(
                "observed-position_inventory-1",
                "position_inventory",
                _wrap([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"}], depth),
                ("ev-m1-1",),
            )
            with self.assertRaises(ValveRefusalError) as ctx_pinv:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.1060"), side=Side.SELL, facts=(base_acct, f_pinv)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("LOOSENED_SELL_PROTECTIVE_STOP", ctx_pinv.exception.decision.hard_veto_reasons)


    def test_valve_observed_account_non_dict_primitives_and_empty_rejected_across_actions(self) -> None:
        gate_default = load_default_forex_valve_gate()
        gate_no_dd = load_default_forex_valve_gate(max_drawdown_pct=None)

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-r8-acct-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk control",
                        selected_action_ref=f"opt-m1-r8-acct-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-r8-acct-{kind.value.lower()}",
                    action_ref=f"opt-m1-r8-acct-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        all_6_actions = (
            ActionKind.OPEN,
            ActionKind.ADD,
            ActionKind.AMEND_STOP,
            ActionKind.REDUCE,
            ActionKind.CLOSE,
            ActionKind.CANCEL_ORDER,
        )
        bad_observed_accounts = (
            "12345",
            "true",
            "false",
            "null",
            '"hello"',
            "UNAVAILABLE",
            "{broken_json",
            "[]",
            "{}",
            json.dumps({}),
            json.dumps([]),
            " \ufeff{}",
        )

        for g in (gate_default, gate_no_dd):
            for action in all_6_actions:
                for bad_val in bad_observed_accounts:
                    for fid, label in (
                        ("observed-account", "account"),
                        ("observed-account-1", "account"),
                        ("f-acct-1", "account"),
                    ):
                        facts = (DecisionFact(fid, label, bad_val, ("ev-m1-1",)),)
                        with self.assertRaises(ValveRefusalError) as ctx:
                            g.require_admissible(_proposal_for(action, facts=facts), current_view=None, now=T0)
                        self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx.exception.decision.hard_veto_reasons)

        # Authoritative current_view preserves precedence over stale observed-account facts,
        # and valid non-empty observed-account dict remains admitted across all 6 ActionKinds.
        valid_cv = {
            "account_id": "acct-m1",
            "balance": "10000",
            "equity": "10000",
            "peak_equity": "10000",
            "available_margin": "9000",
            "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
        }
        valid_acct_fact = (
            DecisionFact(
                "observed-account-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "peak_equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        stale_acct_fact = (DecisionFact("observed-account-1", "account", "null", ("ev-m1-1",)),)
        for action in all_6_actions:
            dec_cv = gate_default.require_admissible(
                _proposal_for(action, facts=stale_acct_fact), current_view=valid_cv, now=T0
            )
            self.assertTrue(dec_cv.admitted)
            dec_df = gate_default.require_admissible(
                _proposal_for(action, facts=valid_acct_fact), current_view=None, now=T0
            )
            self.assertTrue(dec_df.admitted)

    def test_valve_position_inventory_requires_list_rejects_primitives_and_dicts(self) -> None:
        gate = load_default_forex_valve_gate()

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.1100"), side=Side.BUY, facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-r8-pinv-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk control",
                        selected_action_ref=f"opt-m1-r8-pinv-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-r8-pinv-{kind.value.lower()}",
                    action_ref=f"opt-m1-r8-pinv-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        invalid_pinvs = (
            12345,
            "12345",
            0,
            "0",
            0.0,
            True,
            False,
            None,
            "true",
            "null",
            '"12345"',
            {},
            "{}",
            {"amount": "100"},
            "UNAVAILABLE",
            "[broken_json",
        )
        for bad_pinv in invalid_pinvs:
            self.assertTrue(_is_unavailable_accounting_value(bad_pinv, allow_list=True, require_list=True), repr(bad_pinv))

        valid_pinvs = (
            [],
            (),
            "[]",
            " \ufeff []",
            json.dumps("[]"),
            json.dumps(json.dumps("[]")),
            [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
            json.dumps([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}]),
        )
        for ok_pinv in valid_pinvs:
            self.assertFalse(_is_unavailable_accounting_value(ok_pinv, allow_list=True, require_list=True), repr(ok_pinv))

        all_6_actions = (
            ActionKind.OPEN,
            ActionKind.ADD,
            ActionKind.AMEND_STOP,
            ActionKind.REDUCE,
            ActionKind.CLOSE,
            ActionKind.CANCEL_ORDER,
        )
        for action in all_6_actions:
            for bad_pinv in invalid_pinvs:
                cv_bad = {
                    "account_id": "acct-m1",
                    "balance": "10000",
                    "equity": "10000",
                    "peak_equity": "10000",
                    "available_margin": "9000",
                    "position_inventory": bad_pinv,
                }
                with self.assertRaises(ValveRefusalError) as ctx_cv:
                    gate.require_admissible(_proposal_for(action), current_view=cv_bad, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_cv.exception.decision.hard_veto_reasons)

                if isinstance(bad_pinv, str):
                    facts_bad = (
                        DecisionFact("observed-balance-1", "balance", "10000", ("ev-m1-1",)),
                        DecisionFact("observed-equity-1", "equity", "10000", ("ev-m1-1",)),
                        DecisionFact("observed-peak_equity-1", "peak_equity", "10000", ("ev-m1-1",)),
                        DecisionFact("observed-available_margin-1", "available_margin", "9000", ("ev-m1-1",)),
                        DecisionFact("observed-position_inventory-1", "position_inventory", bad_pinv, ("ev-m1-1",)),
                    )
                    with self.assertRaises(ValveRefusalError) as ctx_df:
                        gate.require_admissible(_proposal_for(action, facts=facts_bad), current_view=None, now=T0)
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_df.exception.decision.hard_veto_reasons)

                if isinstance(bad_pinv, (int, str, bool, dict, type(None))):
                    acct_bad = (
                        DecisionFact(
                            "observed-account-1",
                            "account",
                            json.dumps(
                                {
                                    "balance": "10000",
                                    "equity": "10000",
                                    "peak_equity": "10000",
                                    "available_margin": "9000",
                                    "position_inventory": bad_pinv,
                                }
                            ),
                            ("ev-m1-1",),
                        ),
                    )
                    with self.assertRaises(ValveRefusalError) as ctx_acct:
                        gate.require_admissible(_proposal_for(action, facts=acct_bad), current_view=None, now=T0)
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_acct.exception.decision.hard_veto_reasons)

        # Empty position_inventory admits CLOSE/OPEN while tightening AMEND_STOP requires populated position_inventory (Finding [1])
        for ok_pinv in ("[]", [], json.dumps("[]")):
            cv_ok = {
                "account_id": "acct-m1",
                "balance": "10000",
                "equity": "10000",
                "peak_equity": "10000",
                "available_margin": "9000",
                "position_inventory": ok_pinv,
            }
            self.assertTrue(gate.require_admissible(_proposal_for(ActionKind.OPEN), current_view=cv_ok, now=T0).admitted)
            with self.assertRaises(ValveRefusalError) as ctx_emp:
                gate.require_admissible(_make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY), current_view=cv_ok, now=T0)
            self.assertIn("MISSING_POSITION_SIDE", ctx_emp.exception.decision.hard_veto_reasons)

        cv_pos = {
            "account_id": "acct-m1",
            "balance": "10000",
            "equity": "10000",
            "peak_equity": "10000",
            "available_margin": "9000",
            "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
        }
        self.assertTrue(gate.require_admissible(_make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY), current_view=cv_pos, now=T0).admitted)
        df_pos = (
            DecisionFact(
                "observed-account-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "peak_equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        self.assertTrue(gate.require_admissible(_make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=df_pos), current_view=None, now=T0).admitted)

    def test_valve_tuple_position_inventory_and_market_parity_with_list(self) -> None:
        gate = load_default_forex_valve_gate()

        def _cv(extra: dict[str, object]) -> dict[str, object]:
            base: dict[str, object] = {
                "account_id": "acct-m1",
                "balance": "10000",
                "equity": "10000",
                "peak_equity": "10000",
                "available_margin": "9000",
                "position_inventory": (),
            }
            base.update(extra)
            return base

        # Empty tuple remains valid empty position_inventory (OPEN admitted; AMEND_STOP without position refused per Finding [1])
        self.assertTrue(
            gate.require_admissible(
                _make_order_proposal(kind=ActionKind.OPEN, side=Side.BUY, limit_price=None, stop_price=D("1.0950"), take_profit_price=D("1.1150")),
                current_view=_cv({}),
                now=T0,
            ).admitted
        )

        # Parity across both position_inventory/positions and current_market/market as tuple vs list
        for pos_key in ("position_inventory", "positions"):
            for mkt_key in ("current_market", "market"):
                for seq_fn in (list, tuple):
                    # 1. INVERTED_SELL_PROTECTIVE_STOP (SELL position, stop_price <= ask)
                    sell_extra = {
                        pos_key: seq_fn([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"}]),
                        mkt_key: seq_fn([{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}]),
                    }
                    if pos_key != "position_inventory":
                        sell_extra["position_inventory"] = ()
                    with self.assertRaises(ValveRefusalError) as ctx_sell_inv:
                        gate.require_admissible(
                            _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY),
                            current_view=_cv(sell_extra),
                            now=T0,
                        )
                    self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_sell_inv.exception.decision.hard_veto_reasons)

                    # 2. LOOSENED_SELL_PROTECTIVE_STOP (SELL position, stop raised from 1.1050 to 1.1060)
                    with self.assertRaises(ValveRefusalError) as ctx_sell_loose:
                        gate.require_admissible(
                            _make_amend_proposal(stop_price=D("1.1060"), side=Side.SELL),
                            current_view=_cv(sell_extra),
                            now=T0,
                        )
                    self.assertIn("LOOSENED_SELL_PROTECTIVE_STOP", ctx_sell_loose.exception.decision.hard_veto_reasons)

                    # 3. LOOSENED_BUY_PROTECTIVE_STOP (BUY position, stop lowered from 1.0950 to 1.0900)
                    buy_extra = {
                        pos_key: seq_fn([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}]),
                        mkt_key: seq_fn([{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}]),
                    }
                    if pos_key != "position_inventory":
                        buy_extra["position_inventory"] = ()
                    with self.assertRaises(ValveRefusalError) as ctx_buy_loose:
                        gate.require_admissible(
                            _make_amend_proposal(stop_price=D("1.0900"), side=Side.BUY),
                            current_view=_cv(buy_extra),
                            now=T0,
                        )
                    self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_buy_loose.exception.decision.hard_veto_reasons)

                    # 4. INVERTED_BUY_PROTECTIVE_STOP (BUY position, stop >= bid)
                    with self.assertRaises(ValveRefusalError) as ctx_buy_inv:
                        gate.require_admissible(
                            _make_amend_proposal(stop_price=D("1.1000"), side=Side.SELL),
                            current_view=_cv(buy_extra),
                            now=T0,
                        )
                    self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_buy_inv.exception.decision.hard_veto_reasons)

                    # 5. MISSING_POSITION_SIDE when ambiguous multi-position tuple/list omits matching target_id
                    amb_extra = {
                        pos_key: seq_fn([
                            {"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"},
                            {"position_id": "pos-2", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"},
                        ]),
                        mkt_key: seq_fn([{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}]),
                    }
                    if pos_key != "position_inventory":
                        amb_extra["position_inventory"] = ()
                    with self.assertRaises(ValveRefusalError) as ctx_miss_side:
                        gate.require_admissible(
                            _make_amend_proposal(stop_price=D("1.0980"), side=None, target_id="pos-999"),
                            current_view=_cv(amb_extra),
                            now=T0,
                        )
                    self.assertIn("MISSING_POSITION_SIDE", ctx_miss_side.exception.decision.hard_veto_reasons)

                    # 6. Valid tightening AMEND_STOP with tuple/list passes cleanly
                    dec_ok = gate.require_admissible(
                        _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY),
                        current_view=_cv(buy_extra),
                        now=T0,
                    )
                    self.assertTrue(dec_ok.admitted)

    def test_valve_account_label_without_observed_prefix_inner_fields_and_step6_parity(self) -> None:
        gate = load_default_forex_valve_gate()

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-r9-acct-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk control",
                        selected_action_ref=f"opt-m1-r9-acct-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-r9-acct-{kind.value.lower()}",
                    action_ref=f"opt-m1-r9-acct-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        all_6_actions = (
            ActionKind.OPEN,
            ActionKind.ADD,
            ActionKind.AMEND_STOP,
            ActionKind.REDUCE,
            ActionKind.CLOSE,
            ActionKind.CANCEL_ORDER,
        )
        bad_inner_payloads = (
            {"balance": "NaN", "equity": "10000", "available_margin": "9000", "position_inventory": []},
            {"balance": "null", "equity": "10000", "available_margin": "9000", "position_inventory": []},
            {"balance": "10000", "equity": "10000", "available_margin": "9000", "position_inventory": 12345},
        )
        for action in all_6_actions:
            for payload in bad_inner_payloads:
                facts_bad = (DecisionFact("acct-snapshot-1", "account", json.dumps(payload), ("ev-m1-1",)),)
                with self.assertRaises(ValveRefusalError) as ctx:
                    gate.require_admissible(_proposal_for(action, facts=facts_bad), current_view=None, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx.exception.decision.hard_veto_reasons)

        # Step 6 protective stop & drawdown checks enforced for label="account" without observed- prefix
        acct_with_positions = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "peak_equity": "10000",
                        "available_margin": "9000",
                        "current_market": [{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}],
                        "position_inventory": [
                            {"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"},
                            {"position_id": "pos-2", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"},
                        ],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_open_inv:
            gate.require_admissible(
                _make_order_proposal(kind=ActionKind.OPEN, side=Side.BUY, stop_price=D("1.1005"), facts=acct_with_positions),
                current_view=None,
                now=T0,
            )
        self.assertIn("INVERTED_BUY_PROTECTIVE_STOP", ctx_open_inv.exception.decision.hard_veto_reasons)

        with self.assertRaises(ValveRefusalError) as ctx_amend_loose:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0900"), side=Side.BUY, target_id="pos-1", facts=acct_with_positions),
                current_view=None,
                now=T0,
            )
        self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_amend_loose.exception.decision.hard_veto_reasons)

        with self.assertRaises(ValveRefusalError) as ctx_amend_sell_inv:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, target_id="pos-2", facts=acct_with_positions),
                current_view=None,
                now=T0,
            )
        self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_amend_sell_inv.exception.decision.hard_veto_reasons)

        acct_dd_breach = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "8500",
                        "peak_equity": "10000",
                        "available_margin": "7500",
                        "position_inventory": [],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_dd:
            gate.require_admissible(_make_order_proposal(kind=ActionKind.OPEN, facts=acct_dd_breach), current_view=None, now=T0)
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_dd.exception.decision.hard_veto_reasons)

        # Valid acct-snapshot-1 admitted across all 6 ActionKinds, and current_view preserves precedence
        valid_acct = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "peak_equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        valid_cv = {
            "account_id": "acct-m1",
            "balance": "10000",
            "equity": "10000",
            "peak_equity": "10000",
            "available_margin": "9000",
            "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}],
        }
        stale_bad_acct = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps({"balance": "NaN", "available_margin": None, "position_inventory": 12345}),
                ("ev-m1-1",),
            ),
        )
        stale_stop_acct = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "peak_equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0990"}],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        for action in all_6_actions:
            self.assertTrue(gate.require_admissible(_proposal_for(action, facts=valid_acct), current_view=None, now=T0).admitted)
            self.assertTrue(gate.require_admissible(_proposal_for(action, facts=stale_bad_acct), current_view=valid_cv, now=T0).admitted)
        self.assertTrue(
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, target_id="pos-1", facts=stale_stop_acct),
                current_view=valid_cv,
                now=T0,
            ).admitted
        )

    def test_valve_step6_non_empty_current_view_blocks_stale_fact_backfill_and_preserves_clean_view_fallback(self) -> None:
        gate = load_default_forex_valve_gate()

        def _base_cv(**extra: object) -> dict[str, object]:
            view: dict[str, object] = {
                "account_id": "acct-m1",
                "balance": "10000",
                "equity": "10000",
                "peak_equity": "10000",
                "available_margin": "9000",
                "position_inventory": [],
            }
            view.update(extra)
            return view

        # 1. Partial current_view BUY position without stop_price: stale fact stop_price must NOT bleed
        stale_sell_fact = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [
                            {"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.0990"}
                        ],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        for pinv in (
            [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY"}],
            ({"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY"},),
        ):
            # Missing stop_price in authoritative current_view refuses AMEND_STOP instead of falling back to stale SELL stop
            with self.assertRaises(ValveRefusalError) as ctx_noprev:
                gate.require_admissible(
                    _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, target_id="pos-1", facts=stale_sell_fact),
                    current_view=_base_cv(position_inventory=pinv),
                    now=T0,
                )
            self.assertIn("MISSING_AUTHORITATIVE_PREVIOUS_STOP", ctx_noprev.exception.decision.hard_veto_reasons)

        # 2. Closed target_id absent from non-empty current_view: stale fact must NOT supply closed pos-1
        cv_only_pos2 = _base_cv(
            position_inventory=[{"position_id": "pos-2", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}]
        )
        stale_pos1_fact = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [
                            {"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"}
                        ],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_closed:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0980"), side=None, target_id="pos-1", facts=stale_pos1_fact),
                current_view=cv_only_pos2,
                now=T0,
            )
        self.assertEqual(ctx_closed.exception.decision.hard_veto_reasons, ("MISSING_POSITION_SIDE",))

        # 3. Ambiguous multi-position current_view with target_id=None: stale 1-pos fact must NOT mask obs_pos_ambiguous
        cv_ambig = _base_cv(
            position_inventory=[
                {"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"},
                {"position_id": "pos-2", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"},
            ]
        )
        with self.assertRaises(ValveRefusalError) as ctx_ambig:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, target_id=None, facts=stale_pos1_fact),
                current_view=cv_ambig,
                now=T0,
            )
        self.assertEqual(ctx_ambig.exception.decision.hard_veto_reasons, ("MISSING_POSITION_SIDE",))

        # 4. Partial current_market (bid only, no ask): stale fact ask must NOT cause hybrid bleed
        stale_ask_fact = (
            DecisionFact(
                "acct-snapshot-1",
                "account",
                json.dumps(
                    {
                        "balance": "10000",
                        "equity": "10000",
                        "available_margin": "9000",
                        "position_inventory": [],
                        "current_market": [{"instrument_id": "EURUSD", "bid": "1.1010", "ask": "1.1030"}],
                    }
                ),
                ("ev-m1-1",),
            ),
        )
        sell_pos_inv = [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"}]
        for mkt_cv in (
            _base_cv(current_market=[{"instrument_id": "EURUSD", "bid": "1.1000"}], position_inventory=sell_pos_inv),
            _base_cv(instrument_id="EURUSD", bid="1.1000", position_inventory=sell_pos_inv),
        ):
            dec_mkt = gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.1020"), side=Side.SELL, target_id="pos-1", facts=stale_ask_fact),
                current_view=mkt_cv,
                now=T0,
            )
            self.assertTrue(dec_mkt.admitted)

        # 5. _clean_view() fallback preserved when current_view omits current_market and has empty position_inventory=[]
        fallback_facts = (
            DecisionFact(
                "observed-current_market-s1",
                "current_market",
                json.dumps([{"instrument_id": "EURUSD", "bid": "1.1060", "ask": "1.1062"}]),
                ("ev-m1-1",),
            ),
            DecisionFact(
                "observed-position_inventory-s1",
                "position_inventory",
                json.dumps([{"position_id": "pos-1", "side": "BUY", "stop_price": "1.0950"}]),
                ("ev-m1-1",),
            ),
        )
        with self.assertRaises(ValveRefusalError) as ctx_fb:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0940"), facts=fallback_facts),
                current_view=_base_cv(),
                now=T0,
            )
        self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_fb.exception.decision.hard_veto_reasons)

        # RehearsalWiring string-ID position_inventory=["pos-1"] also preserves observed position dict fallback
        with self.assertRaises(ValveRefusalError) as ctx_str_ids:
            gate.require_admissible(
                _make_amend_proposal(stop_price=D("1.0940"), facts=fallback_facts),
                current_view=_base_cv(position_inventory=["pos-1"]),
                now=T0,
            )
        self.assertIn("LOOSENED_BUY_PROTECTIVE_STOP", ctx_str_ids.exception.decision.hard_veto_reasons)

    def test_valve_bom_prefixed_decision_fact_labels_and_incomplete_account_dicts(self) -> None:
        gate = load_default_forex_valve_gate()

        def _proposal_for(kind: ActionKind, facts: tuple[DecisionFact, ...] = ()) -> SimpleNamespace:
            if kind in (ActionKind.OPEN, ActionKind.ADD):
                return _make_order_proposal(
                    kind=kind,
                    side=Side.BUY,
                    limit_price=None,
                    stop_price=D("1.0950"),
                    take_profit_price=D("1.1150"),
                    facts=facts,
                )
            if kind is ActionKind.AMEND_STOP:
                return _make_amend_proposal(stop_price=D("1.0980"), side=Side.BUY, target_id="pos-1", facts=facts)
            return SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-m1-r10-{kind.value.lower()}",
                    facts=facts,
                    evidence=(SimpleNamespace(evidence_id="ev-m1-1"),),
                    state=SimpleNamespace(
                        scope=SimpleNamespace(account_id="acct-m1", run_id="run-m1"),
                        observed_at=T0,
                        valid_until=T0 + timedelta(minutes=5),
                    ),
                ),
                result=SimpleNamespace(
                    selection=SimpleNamespace(
                        evidence_ids=("ev-m1-1",),
                        reason="Disciplined risk control",
                        selected_action_ref=f"opt-m1-r10-{kind.value.lower()}",
                    )
                ),
                intent=SimpleNamespace(
                    intent_id=f"int-m1-r10-{kind.value.lower()}",
                    action_ref=f"opt-m1-r10-{kind.value.lower()}",
                    kind=kind,
                    instrument_id="EURUSD",
                    quantity=D("5000") if kind is ActionKind.REDUCE else None,
                    side=None,
                    stop_price=None,
                    take_profit_price=None,
                    limit_price=None,
                    target_id="pos-1",
                ),
            )

        all_6_actions = (
            ActionKind.OPEN,
            ActionKind.ADD,
            ActionKind.AMEND_STOP,
            ActionKind.REDUCE,
            ActionKind.CLOSE,
            ActionKind.CANCEL_ORDER,
        )

        # 1. BOM-prefixed account labels ("﻿account", "﻿ Account ") enforced in Step 1, Step 1b, Step 2, Step 6
        for bom_label in ("\ufeffaccount", "\ufeff Account "):
            # Step 1: NaN balance, null margin, non-list position_inventory
            for bad_patch in (
                {"balance": "NaN"},
                {"available_margin": None},
                {"position_inventory": 123},
            ):
                payload = {
                    "balance": "10000",
                    "equity": "10000",
                    "available_margin": "9000",
                    "position_inventory": [],
                    **bad_patch,
                }
                facts_bad = (DecisionFact("acct-snap-bom", bom_label, json.dumps(payload), ("ev-m1-1",)),)
                for action in all_6_actions:
                    with self.assertRaises(ValveRefusalError) as ctx_s1:
                        gate.require_admissible(_proposal_for(action, facts=facts_bad), current_view=None, now=T0)
                    self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_s1.exception.decision.hard_veto_reasons)

            # Step 1b: Drawdown breach
            dd_payload = {
                "balance": "10000",
                "equity": "8500",
                "peak_equity": "10000",
                "available_margin": "7500",
                "position_inventory": [],
            }
            with self.assertRaises(ValveRefusalError) as ctx_dd:
                gate.require_admissible(
                    _proposal_for(ActionKind.OPEN, facts=(DecisionFact("acct-snap-bom", bom_label, json.dumps(dd_payload), ("ev-m1-1",)),)),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_dd.exception.decision.hard_veto_reasons)

            # Step 2: new_risk=False & management=False
            perm_payload = {
                "balance": "10000",
                "equity": "10000",
                "available_margin": "9000",
                "position_inventory": [],
                "new_risk": False,
                "management": False,
            }
            perm_facts = (DecisionFact("acct-snap-bom", bom_label, json.dumps(perm_payload), ("ev-m1-1",)),)
            for action in (ActionKind.OPEN, ActionKind.ADD):
                with self.assertRaises(ValveRefusalError) as ctx_nr:
                    gate.require_admissible(_proposal_for(action, facts=perm_facts), current_view=None, now=T0)
                self.assertIn("NEW_RISK_NOT_ALLOWED", ctx_nr.exception.decision.hard_veto_reasons)
            for action in (ActionKind.AMEND_STOP, ActionKind.REDUCE, ActionKind.CLOSE, ActionKind.CANCEL_ORDER):
                with self.assertRaises(ValveRefusalError) as ctx_mg:
                    gate.require_admissible(_proposal_for(action, facts=perm_facts), current_view=None, now=T0)
                self.assertIn("MANAGEMENT_NOT_ALLOWED", ctx_mg.exception.decision.hard_veto_reasons)

            # Step 6: inverted & loosened SELL stop under BOM account label
            s6_payload = {
                "balance": "10000",
                "equity": "10000",
                "available_margin": "9000",
                "current_market": [{"instrument_id": "EURUSD", "bid": "1.1000", "ask": "1.1002"}],
                "position_inventory": [{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "SELL", "stop_price": "1.1050"}],
            }
            with self.assertRaises(ValveRefusalError) as ctx_s6:
                gate.require_admissible(
                    _make_amend_proposal(
                        stop_price=D("1.0980"),
                        side=Side.BUY,
                        target_id="pos-1",
                        facts=(DecisionFact("acct-snap-bom", bom_label, json.dumps(s6_payload), ("ev-m1-1",)),),
                    ),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("INVERTED_SELL_PROTECTIVE_STOP", ctx_s6.exception.decision.hard_veto_reasons)
            with self.assertRaises(ValveRefusalError) as ctx_s6_loose:
                gate.require_admissible(
                    _make_amend_proposal(
                        stop_price=D("1.1060"),
                        side=Side.BUY,
                        target_id="pos-1",
                        facts=(DecisionFact("acct-snap-bom", bom_label, json.dumps(s6_payload), ("ev-m1-1",)),),
                    ),
                    current_view=None,
                    now=T0,
                )
            self.assertIn("LOOSENED_SELL_PROTECTIVE_STOP", ctx_s6_loose.exception.decision.hard_veto_reasons)

        # 2. BOM-prefixed individual field labels ("﻿balance", "﻿equity", "﻿available_margin", "﻿position_inventory")
        bom_dd_facts = (
            DecisionFact("f-bal", "\ufeffbalance", "10000", ("ev-m1-1",)),
            DecisionFact("f-eq", "\ufeffequity", "8500", ("ev-m1-1",)),
            DecisionFact("f-mgn", "\ufeffavailable_margin", "7500", ("ev-m1-1",)),
            DecisionFact("f-inv", "\ufeffposition_inventory", "[]", ("ev-m1-1",)),
        )
        with self.assertRaises(ValveRefusalError) as ctx_bom_dd:
            gate.require_admissible(_proposal_for(ActionKind.OPEN, facts=bom_dd_facts), current_view=None, now=T0)
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", ctx_bom_dd.exception.decision.hard_veto_reasons)

        bom_nan_facts = (
            DecisionFact("f-bal", "\ufeffbalance", "NaN", ("ev-m1-1",)),
            DecisionFact("f-eq", "\ufeffequity", "10000", ("ev-m1-1",)),
            DecisionFact("f-mgn", "\ufeffavailable_margin", "9000", ("ev-m1-1",)),
            DecisionFact("f-inv", "\ufeffposition_inventory", "[]", ("ev-m1-1",)),
        )
        for action in all_6_actions:
            with self.assertRaises(ValveRefusalError) as ctx_bom_nan:
                gate.require_admissible(_proposal_for(action, facts=bom_nan_facts), current_view=None, now=T0)
            self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_bom_nan.exception.decision.hard_veto_reasons)

        # 3. Incomplete account / observed-account JSON dicts rejected across ALL 6 actions (including management)
        incomplete_cases = (
            ("acct-snapshot-1", "account", {"balance": "10000"}),
            ("observed-account-1", "account", {"balance": "10000", "equity": "10000"}),
            ("observed-account-1", "Independent state", {"balance": "10000"}),
            ("acct-snapshot-1", "\ufeffaccount", {"balance": "10000"}),
        )
        for fid, lbl, partial_dict in incomplete_cases:
            partial_facts = (DecisionFact(fid, lbl, json.dumps(partial_dict), ("ev-m1-1",)),)
            for action in all_6_actions:
                with self.assertRaises(ValveRefusalError) as ctx_inc:
                    gate.require_admissible(_proposal_for(action, facts=partial_facts), current_view=None, now=T0)
                self.assertIn("MISSING_REQUIRED_ACCOUNTING", ctx_inc.exception.decision.hard_veto_reasons)

        # Split facts supplying the remaining req_fields alongside partial account fact remain admitted
        split_facts = (
            DecisionFact("acct-snapshot-1", "\ufeffaccount", json.dumps({"balance": "10000"}), ("ev-m1-1",)),
            DecisionFact("f-eq", "\ufeffequity", "10000", ("ev-m1-1",)),
            DecisionFact("f-mgn", "\ufeffavailable_margin", "9000", ("ev-m1-1",)),
            DecisionFact(
                "f-inv",
                "\ufeffposition_inventory",
                json.dumps([{"position_id": "pos-1", "instrument_id": "EURUSD", "side": "BUY", "stop_price": "1.0950"}]),
                ("ev-m1-1",),
            ),
        )
        for action in all_6_actions:
            self.assertTrue(gate.require_admissible(_proposal_for(action, facts=split_facts), current_view=None, now=T0).admitted)

        # Non-account observed-1 fact (test_phase4_pilot_readiness.py::test_10 contract) preserves NEW_RISK_NOT_ALLOWED without MISSING_REQUIRED_ACCOUNTING
        obs1_perm_only = (
            DecisionFact(
                "observed-1",
                "Independent observed state",
                json.dumps({"balance": {"amount": "10000", "currency": "USD"}, "new_risk": False, "management": True, "positions": []}),
                ("ev-m1-1",),
            ),
        )
        dec_obs1 = gate.evaluate(_proposal_for(ActionKind.OPEN, facts=obs1_perm_only), now=T0)
        self.assertFalse(dec_obs1.admitted)
        self.assertIn("NEW_RISK_NOT_ALLOWED", dec_obs1.hard_veto_reasons)
        self.assertNotIn("MISSING_REQUIRED_ACCOUNTING", dec_obs1.hard_veto_reasons)

    def test_parallel_tier_rejects_malformed_quotes_and_signals_and_uses_executable_tp_side(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)

            bad_quotes_cases = [
                {"EURUSD": (Decimal("NaN"), Decimal("1.1002"))},
                {"EURUSD": (Decimal("Infinity"), Decimal("1.1002"))},
                {"EURUSD": (Decimal("-1.0"), Decimal("1.1002"))},
                {"EURUSD": (Decimal("1.1005"), Decimal("1.1002"))},
                {"EURUSD": ("1.1000", "1.1002")},
            ]
            for bq in bad_quotes_cases:
                with self.assertRaises(ContractError):
                    eng.process_tick(quotes=bq, signal=None, now=T0)  # type: ignore[arg-type]

            bad_signals = [
                {"symbol": "EURUSD", "side": "HOLD", "stop_price": "1.09500"},
                {"symbol": "EURUSD", "side": "BUY", "stop_price": "NaN"},
                {"symbol": "EURUSD", "side": "BUY", "stop_price": None},
                {"symbol": "EURUSD", "side": "BUY", "stop_price": "Infinity"},
                {"symbol": "EURUSD", "side": "BUY", "stop_price": "1.09500", "take_profit_price": "-1.0"},
            ]
            for bsig in bad_signals:
                with self.assertRaises(ContractError):
                    eng.process_tick(quotes=QUOTES, signal=bsig, now=T0)

            # BUY TP=1.1010 must NOT close when ask >= 1.1010 while executable bid < 1.1010
            buy_quotes = dict(QUOTES)
            buy_quotes["EURUSD"] = (Decimal("1.1000"), Decimal("1.1002"))
            eng.process_tick(
                quotes=buy_quotes,
                signal={"symbol": "EURUSD", "side": "BUY", "stop_price": "1.0950", "take_profit_price": "1.1010", "regime": REGIME_STRONG_TREND},
                now=T0,
            )
            spread_wait = dict(buy_quotes)
            spread_wait["EURUSD"] = (Decimal("1.1008"), Decimal("1.1011"))
            mid_snap = eng.process_tick(quotes=spread_wait, signal=None, now=T0 + timedelta(seconds=5))
            self.assertEqual({t["tier_id"]: t["open_positions"] for t in mid_snap["tiers"]}["TIER_1_CURRENT"], 1)

            spread_hit = dict(buy_quotes)
            spread_hit["EURUSD"] = (Decimal("1.1010"), Decimal("1.1012"))
            hit_snap = eng.process_tick(quotes=spread_hit, signal=None, now=T0 + timedelta(seconds=10))
            t1 = {t["tier_id"]: t for t in hit_snap["tiers"]}["TIER_1_CURRENT"]
            self.assertEqual(t1["open_positions"], 0)
            self.assertEqual(t1["win_count"], 1)

            # SELL TP=1.0990 must NOT close when bid <= 1.0990 while executable ask > 1.0990
            eng2 = ParallelTierEngine(Path(td) / "tiers_sell.sqlite3", valve_gate=gate, clock=lambda: T0)
            eng2.process_tick(
                quotes=buy_quotes,
                signal={"symbol": "EURUSD", "side": "SELL", "stop_price": "1.1050", "take_profit_price": "1.0990", "regime": REGIME_STRONG_TREND},
                now=T0,
            )
            sell_wait = dict(buy_quotes)
            sell_wait["EURUSD"] = (Decimal("1.0989"), Decimal("1.0992"))
            sell_mid = eng2.process_tick(quotes=sell_wait, signal=None, now=T0 + timedelta(seconds=5))
            self.assertEqual({t["tier_id"]: t["open_positions"] for t in sell_mid["tiers"]}["TIER_1_CURRENT"], 1)

            sell_hit = dict(buy_quotes)
            sell_hit["EURUSD"] = (Decimal("1.0988"), Decimal("1.0990"))
            sell_done = eng2.process_tick(quotes=sell_hit, signal=None, now=T0 + timedelta(seconds=10))
            t1_s = {t["tier_id"]: t for t in sell_done["tiers"]}["TIER_1_CURRENT"]
            self.assertEqual(t1_s["open_positions"], 0)
            self.assertEqual(t1_s["win_count"], 1)

    def test_valve_controller_validation_fact_peak_preservation_and_view_policy_seam(self) -> None:
        w1 = [[0.0] * 8 for _ in range(16)]
        b1 = [0.0] * 16
        w2 = [0.0] * 16
        with self.assertRaises(ContractError):
            TKSMetaValveController(w1=[[float("nan")] + [0.0] * 7] + w1[1:], b1=b1, w2=w2, b2=0.0)
        with self.assertRaises(ContractError):
            TKSMetaValveController(w1=w1, b1=b1, w2=w2, b2=0.0, threshold=-0.1)
        with self.assertRaises(ContractError):
            TKSMetaValveController(w1=w1, b1=b1, w2=w2, b2=0.0, threshold=1.0)
        with self.assertRaises(ContractError):
            TKSMetaValveController(w1=w1, b1=b1, w2=w2, b2=True)  # type: ignore[arg-type]

        ctrl = TKSMetaValveController(w1=w1, b1=b1, w2=w2, b2=1.0, threshold=0.55)
        with self.assertRaises(ContractError):
            ctrl.forward([float("nan")] + [0.0] * 7)
        with self.assertRaises(ContractError):
            ctrl.forward([True] + [0.0] * 7)  # type: ignore[list-item]

        with tempfile.TemporaryDirectory() as td:
            bad_w_path = Path(td) / "bad_weights.json"
            payload = ctrl.to_payload()
            payload["parameter_count"] = 160
            bad_w_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ContractError):
                TKSMetaValveController.load_weights(bad_w_path)

        gate = load_default_forex_valve_gate()

        def _mk_open_prop(facts: tuple[DecisionFact, ...], *, qty: Decimal = Decimal("1000"), scope_acct: str = "acct-seam") -> SimpleNamespace:
            scope = SimpleNamespace(account_id=scope_acct, run_id="run-seam")
            state = SimpleNamespace(
                state_id="state-seam-1",
                scope=scope,
                observed_at=T0,
                valid_until=T0 + timedelta(seconds=60),
            )
            ev = EvidenceReference("ev-seam-1", EvidenceKind.OBSERVATION, "mt5", "a" * 64, T0)
            req = SimpleNamespace(request_id="req-seam-1", state=state, facts=facts, evidence=(ev,))
            sel = SimpleNamespace(selected_action_ref="act-seam-1", reason="ID=0act-seam-1 trend", evidence_ids=("ev-seam-1",))
            res = SimpleNamespace(selection=sel)
            intent = SimpleNamespace(
                kind=ActionKind.OPEN,
                side=Side.BUY,
                quantity=qty,
                limit_price=None,
                stop_price=Decimal("1.0950"),
                take_profit_price=Decimal("1.1100"),
                target_id=None,
            )
            return SimpleNamespace(request=req, result=res, intent=intent)

        # Duplicate later observed-account fact with lower peak_equity must NOT mask earlier drawdown
        dd_facts = (
            DecisionFact("observed-equity", "equity", "10000", ("ev-seam-1",)),
            DecisionFact("observed-balance", "balance", "10000", ("ev-seam-1",)),
            DecisionFact("observed-available_margin", "available_margin", "9000", ("ev-seam-1",)),
            DecisionFact("observed-position_inventory", "position_inventory", "[]", ("ev-seam-1",)),
            DecisionFact("observed-peak_equity", "peak_equity", "20000", ("ev-seam-1",)),
            DecisionFact("observed-account-override", "account", json.dumps({"equity": "10000", "peak_equity": "10000"}), ("ev-seam-1",)),
        )
        dec_dd = gate.evaluate(_mk_open_prop(dd_facts), current_view=None, now=T0)
        self.assertFalse(dec_dd.admitted)
        self.assertIn("MAX_DRAWDOWN_EXCEEDED", dec_dd.hard_veto_reasons)

        # Embedded current_view["policy"] and current_view["scope_id"] enforced when policy=None
        from types import MappingProxyType
        paused_view = MappingProxyType({
            "balance": "10000",
            "equity": "10000",
            "available_margin": "9000",
            "position_inventory": "[]",
            "scope_id": "dual-shield-barbell",
            "policy": MappingProxyType({
                "new_risk_permission": "PAUSED",
                "management_permission": "ALLOWED",
                "max_entry_quantity": "100",
                "max_drawdown_pct": "0.05",
            }),
        })
        dec_view_pol = gate.evaluate(_mk_open_prop((), qty=Decimal("1000")), current_view=paused_view, now=T0)
        self.assertFalse(dec_view_pol.admitted)
        self.assertIn("NEW_RISK_NOT_ALLOWED", dec_view_pol.hard_veto_reasons)
        self.assertIn("QUANTITY_EXCEEDS_MAX_ENTRY", dec_view_pol.hard_veto_reasons)

        # Scope ID from current_view["scope_id"] is seeded in PeakEquityStore
        ok_view = {
            "balance": "10000",
            "equity": "10000",
            "available_margin": "9000",
            "position_inventory": "[]",
            "scope_id": "dual-shield-barbell",
            "policy": {
                "new_risk_permission": "ALLOWED",
                "management_permission": "ALLOWED",
                "max_entry_quantity": "10000",
                "max_drawdown_pct": "0.10",
            },
        }
        dec_ok = gate.evaluate(_mk_open_prop((), qty=Decimal("1000")), current_view=ok_view, now=T0)
        self.assertTrue(dec_ok.admitted)
        self.assertEqual(gate.peak_equity_store.read_peak("dual-shield-barbell"), Decimal("10000"))


if __name__ == "__main__":
    unittest.main()
