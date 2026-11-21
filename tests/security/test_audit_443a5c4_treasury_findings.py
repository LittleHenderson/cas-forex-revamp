"""Security regression tests for PR #32 Audit 443a5c4 Finding [4] (Treasury Conversion Proof).

Covers Finding [4] (csf_2a2c1f8e3c49a8f2382af520):
- Strict allowlist separation between conversion submission acknowledgement (CONVERSION_PENDING)
  and terminal full-fill settlement (CONVERSION_CONFIRMED).
- Bounded polling of get_conversion_status(provider_tx_id=..., client_reference_id=...) with
  configurable sleep before ACH withdrawal is ever eligible.
- Mandatory binding checks:
  1. Rail-specific terminal status allowlists (Coinbase vs Kraken); unfamiliar/pending/open/partial
     statuses stay CONVERSION_OUTCOME_UNKNOWN and block ACH.
  2. Exact request binding (client_reference_id / cl_ord_id / userref OR bound conversion_tx_id)
     plus cross-transfer replay protection.
  3. Exact asset/pair, sell->USD side, and pinned account bindings (USDC/USDT/BTC/XBT/ETH -> USD).
  4. Exact terminal full fill (vol_exec/filled_size/source_amount >= expected_source_amount,
     vol_exec >= vol) AND strictly positive realized USD proceeds >= requested ACH USD amount.
"""
from __future__ import annotations

import ast
import base64
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.treasury.profit_sweep import (
    CONVERSION_STATUS_CONFIRMED,
    CONVERSION_STATUS_OUTCOME_UNKNOWN,
    CONVERSION_STATUS_PENDING,
    CoinbaseOfframpClient,
    KrakenOfframpClient,
    OfframpSecurityError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
    RAIL_KRAKEN_ACH,
    WITHDRAWAL_STATUS_NOT_STARTED,
    WITHDRAWAL_STATUS_SUBMITTED,
)

D = Decimal
T0 = datetime(2026, 11, 21, 14, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_ec_pem(path: Path) -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        os.chmod(path, 0o600)


def _read_row(db_path: Path, transfer_id: str) -> dict[str, object]:
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM bank_transfers WHERE transfer_id = ?", (transfer_id,)
        ).fetchone()
        if row is None:
            raise AssertionError(f"Missing bank_transfers row for {transfer_id!r}")
        return dict(row)


class Audit443a5c4TreasuryFinding4Tests(unittest.TestCase):
    def _setup(self, root: Path, *, realized_profit: Decimal = D("1000.00")) -> tuple[ProfitSweepVault, OwnerRecoveryVerifier, Path, Path]:
        db_path = root / "vault.sqlite3"
        pem_path = root / "cb.pem"
        _write_ec_pem(pem_path)
        vault = ProfitSweepVault(db_path, scope_id="treasury-audit-443a5c4", clock=lambda: T0)
        vault.record_realized_close(
            trade_id="tr-seed-443a5c4",
            symbol="EURUSD",
            broker_id="HUGOSWAY_MT5",
            realized_net_usd=realized_profit,
        )
        rec = OwnerRecoveryVerifier(db_path=db_path, clock=lambda: T0)
        return vault, rec, db_path, pem_path

    def _make_coinbase(self, pem_path: Path, http_call: object, *, bank_id: str = "pm-bank-1") -> CoinbaseOfframpClient:
        return CoinbaseOfframpClient(
            key_name="organizations/org-1/apiKeys/key-1",
            private_key_file=pem_path,
            linked_bank_account_id=bank_id,
            http_call=http_call,  # type: ignore[arg-type]
            resolve_dns=lambda _h: ["104.18.0.1"],
            clock=lambda: T0,
        )

    def _make_kraken(self, http_call: object, *, bank_key: str = "krk-bank-1") -> KrakenOfframpClient:
        return KrakenOfframpClient(
            api_key="krk-pub-1",
            api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
            linked_bank_key=bank_key,
            http_call=http_call,  # type: ignore[arg-type]
            resolve_dns=lambda _h: ["104.16.0.1"],
            clock=lambda: T0,
        )

    def test_submission_ack_never_confirms_and_non_terminal_statuses_block_ach(self) -> None:
        # Kraken QueryOrders payloads that MUST stay CONVERSION_OUTCOME_UNKNOWN and trigger 0 Withdraw calls
        kraken_bad_statuses: list[tuple[str, dict[str, object]]] = [
            ("txid_only_echo", {"txid": ["OKRK-BAD-1"]}),
            ("empty_query_orders", {}),
            ("missing_status", {"OKRK-BAD-1": {"vol": "90.00", "vol_exec": "90.00"}}),
            ("open_status", {"OKRK-BAD-1": {"status": "open", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "90.00", "vol_exec": "0"}}),
            ("pending_status", {"OKRK-BAD-1": {"status": "pending", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "90.00", "vol_exec": "0"}}),
            ("partial_status", {"OKRK-BAD-1": {"status": "partial", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "90.00", "vol_exec": "45.00"}}),
            ("processing_status", {"OKRK-BAD-1": {"status": "processing", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "90.00", "vol_exec": "90.00"}}),
            ("cross_rail_settled_not_in_kraken_allowlist", {"OKRK-BAD-1": {"status": "settled", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "90.00", "vol_exec": "90.00", "cost": "90.00", "fee": "0"}}),
            ("unfamiliar_status", {"OKRK-BAD-1": {"status": "MYSTERY_EXECUTED", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "90.00", "vol_exec": "90.00", "cost": "90.00", "fee": "0"}}),
        ]
        for label, status_payload in kraken_bad_statuses:
            with self.subTest(rail=RAIL_KRAKEN_ACH, case=label), tempfile.TemporaryDirectory() as td:
                vault, rec, db_path, _ = self._setup(Path(td))
                calls = {"add": 0, "query": 0, "wd": 0}

                def krk_http(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                    if "/AddOrder" in url:
                        calls["add"] += 1
                        return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-BAD-1"]}}).encode()
                    if "/QueryOrders" in url:
                        calls["query"] += 1
                        return 200, json.dumps({"error": [], "result": status_payload}).encode()
                    if "/Withdraw" in url:
                        calls["wd"] += 1
                        return 200, json.dumps({"error": [], "result": {"refid": "SHOULD-NOT-RUN"}}).encode()
                    raise AssertionError(url)

                krk = self._make_kraken(krk_http)
                prep = vault.prepare_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("90.00"),
                    owner_request_id=f"req-krk-{label}",
                    reason="reject unconfirmed kraken status",
                    kraken_client=krk,
                    convert_amount=D("90.00"),
                    kraken_pair="USDCUSD",
                )
                tid = str(prep["transfer_id"])
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError):
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_KRAKEN_ACH,
                        amount_usd=D("90.00"),
                        owner_request_id=f"req-krk-{label}",
                        reason="reject unconfirmed kraken status",
                        verifier=rec,
                        recovery_token=tok,
                        kraken_client=krk,
                        convert_amount=D("90.00"),
                        kraken_pair="USDCUSD",
                        intent_id=prep["intent_id"],
                        intent_sha256=prep["intent_sha256"],
                        conversion_poll_attempts=2,
                    )
                self.assertEqual(calls["add"], 1)
                self.assertGreaterEqual(calls["query"], 1)
                self.assertEqual(calls["wd"], 0)
                row = _read_row(db_path, tid)
                self.assertEqual(row["status"], "OUTCOME_UNKNOWN")
                self.assertEqual(row["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)
                self.assertEqual(row["conversion_tx_id"], "OKRK-BAD-1")
                self.assertEqual(row["withdrawal_status"], WITHDRAWAL_STATUS_NOT_STARTED)

        # Even if Coinbase commit returns TRADE_STATUS_COMPLETED, get_conversion_status MUST STILL prove terminal full fill
        cb_bad_statuses: list[tuple[str, dict[str, object]]] = [
            ("missing_status", {"trade": {"id": "cb-bad-1", "from_currency": "USDC", "to_currency": "USD", "filled_size": "90.00", "usd_proceeds": "90.00"}}),
            ("open_status", {"trade": {"id": "cb-bad-1", "status": "OPEN", "from_currency": "USDC", "to_currency": "USD", "filled_size": "90.00", "usd_proceeds": "90.00"}}),
            ("pending_status", {"trade": {"id": "cb-bad-1", "status": "PENDING", "from_currency": "USDC", "to_currency": "USD", "filled_size": "90.00", "usd_proceeds": "90.00"}}),
            ("partial_status", {"trade": {"id": "cb-bad-1", "status": "PARTIAL", "from_currency": "USDC", "to_currency": "USD", "filled_size": "45.00", "usd_proceeds": "45.00"}}),
            ("processing_status", {"trade": {"id": "cb-bad-1", "status": "PROCESSING", "from_currency": "USDC", "to_currency": "USD", "filled_size": "90.00", "usd_proceeds": "90.00"}}),
            ("closed_not_in_cb_allowlist", {"trade": {"id": "cb-bad-1", "status": "CLOSED", "from_currency": "USDC", "to_currency": "USD", "filled_size": "90.00", "usd_proceeds": "90.00"}}),
            ("unfamiliar_status", {"trade": {"id": "cb-bad-1", "status": "TRADE_STATUS_MYSTERY", "from_currency": "USDC", "to_currency": "USD", "filled_size": "90.00", "usd_proceeds": "90.00"}}),
        ]
        for label, status_payload in cb_bad_statuses:
            with self.subTest(rail=RAIL_COINBASE_ACH, case=label), tempfile.TemporaryDirectory() as td:
                vault, rec, db_path, pem_path = self._setup(Path(td))
                calls = {"quote": 0, "commit": 0, "get": 0, "wd": 0}

                def cb_http(method: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                    if "/convert/quote" in url:
                        calls["quote"] += 1
                        return 200, json.dumps({"trade": {"id": "cb-bad-1", "status": "TRADE_STATUS_CREATED"}}).encode()
                    if method == "POST" and "/convert/trade/" in url:
                        calls["commit"] += 1
                        # Deliberately return TRADE_STATUS_COMPLETED on commit to prove submission ack NEVER skips polling!
                        return 200, json.dumps({"trade": {"id": "cb-bad-1", "status": "TRADE_STATUS_COMPLETED"}}).encode()
                    if method == "GET" and "/convert/trade/" in url:
                        calls["get"] += 1
                        return 200, json.dumps(status_payload).encode()
                    if "/withdrawals/fiat" in url:
                        calls["wd"] += 1
                        return 200, json.dumps({"id": "SHOULD-NOT-RUN"}).encode()
                    raise AssertionError(f"{method} {url}")

                cb = self._make_coinbase(pem_path, cb_http)
                prep = vault.prepare_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("90.00"),
                    owner_request_id=f"req-cb-{label}",
                    reason="reject unconfirmed coinbase status",
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("90.00"),
                    coinbase_source_account_uuid="src-usdc",
                    coinbase_usd_account_uuid="dst-usd",
                )
                tid = str(prep["transfer_id"])
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError):
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("90.00"),
                        owner_request_id=f"req-cb-{label}",
                        reason="reject unconfirmed coinbase status",
                        verifier=rec,
                        recovery_token=tok,
                        coinbase_client=cb,
                        convert_from_currency="USDC",
                        convert_amount=D("90.00"),
                        coinbase_source_account_uuid="src-usdc",
                        coinbase_usd_account_uuid="dst-usd",
                        intent_id=prep["intent_id"],
                        intent_sha256=prep["intent_sha256"],
                        conversion_poll_attempts=2,
                    )
                self.assertEqual(calls["quote"], 1)
                self.assertEqual(calls["commit"], 1)
                self.assertGreaterEqual(calls["get"], 1)
                self.assertEqual(calls["wd"], 0)
                self.assertEqual(_read_row(db_path, tid)["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

    def test_submission_unfamiliar_status_is_rejected_without_polling(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault, rec, db_path, pem_path = self._setup(Path(td))
            calls = {"get": 0, "wd": 0}

            def cb_http(method: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                if "/convert/quote" in url:
                    return 200, json.dumps({"trade": {"id": "cb-weird-sub", "status": "CREATED"}}).encode()
                if method == "POST" and "/convert/trade/" in url:
                    return 200, json.dumps({"trade": {"id": "cb-weird-sub", "status": "BIZARRE_SUB_STATUS"}}).encode()
                if method == "GET" and "/convert/trade/" in url:
                    calls["get"] += 1
                    return 200, b"{}"
                if "/withdrawals/fiat" in url:
                    calls["wd"] += 1
                    return 200, json.dumps({"id": "bad"}).encode()
                raise AssertionError(url)

            cb = self._make_coinbase(pem_path, cb_http)
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-sub-bad",
                reason="unfamiliar submission status",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("50.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
            )
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-sub-bad",
                    reason="unfamiliar submission status",
                    verifier=rec,
                    recovery_token=tok,
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("50.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )
            self.assertEqual(calls["get"], 0)
            self.assertEqual(calls["wd"], 0)
            self.assertEqual(_read_row(db_path, str(prep["transfer_id"]))["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

    def test_polling_transitions_pending_to_terminal_full_fill_and_configurable_sleep(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault, rec, db_path, _ = self._setup(Path(td))
            poll_num = {"n": 0}
            sleep_calls: list[float] = []
            observed_during_poll: list[tuple[str, str | None]] = []

            def krk_http(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                row = _read_row(db_path, tid)
                if "/AddOrder" in url:
                    return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-POLL-3"]}}).encode()
                if "/QueryOrders" in url:
                    poll_num["n"] += 1
                    observed_during_poll.append((str(row["conversion_status"]), str(row["conversion_tx_id"]) if row["conversion_tx_id"] else None))
                    if poll_num["n"] < 3:
                        st = "pending" if poll_num["n"] == 1 else "open"
                        return 200, json.dumps({
                            "error": [],
                            "result": {
                                "OKRK-POLL-3": {
                                    "status": st,
                                    "cl_ord_id": str(row["conversion_client_ref"]),
                                    "descr": {"pair": "USDCUSD", "type": "sell"},
                                    "vol": "100.00",
                                    "vol_exec": "0",
                                }
                            },
                        }).encode()
                    return 200, json.dumps({
                        "error": [],
                        "result": {
                            "OKRK-POLL-3": {
                                "status": "closed",
                                "cl_ord_id": str(row["conversion_client_ref"]),
                                "descr": {"pair": "USDCUSD", "type": "sell", "ordertype": "market"},
                                "vol": "100.00",
                                "vol_exec": "100.00",
                                "cost": "100.10",
                                "fee": "0.10",
                            }
                        },
                    }).encode()
                if "/Withdraw" in url:
                    self.assertEqual(str(row["conversion_status"]), CONVERSION_STATUS_CONFIRMED)
                    self.assertEqual(str(row["conversion_realized_usd_text"]), "100")
                    return 200, json.dumps({"error": [], "result": {"refid": "KRK-WD-POLL-3"}}).encode()
                raise AssertionError(url)

            krk = self._make_kraken(krk_http)
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-poll-3",
                reason="async conversion fill",
                kraken_client=krk,
                convert_amount=D("100.00"),
                kraken_pair="USDCUSD",
            )
            tid = str(prep["transfer_id"])
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-poll-3",
                reason="async conversion fill",
                verifier=rec,
                recovery_token=tok,
                kraken_client=krk,
                convert_amount=D("100.00"),
                kraken_pair="USDCUSD",
                intent_id=prep["intent_id"],
                intent_sha256=prep["intent_sha256"],
                conversion_poll_attempts=4,
                conversion_poll_interval_seconds=0.05,
                conversion_poll_sleep=sleep_calls.append,
            )
            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(out["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)
            self.assertEqual(poll_num["n"], 3)
            self.assertEqual(sleep_calls, [0.05, 0.05])
            self.assertEqual(observed_during_poll, [(CONVERSION_STATUS_PENDING, "OKRK-POLL-3")] * 3)

    def test_mandatory_request_binding_and_cross_transfer_replay_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault, rec, db_path, pem_path = self._setup(Path(td))

            # 1. Legitimate sweep 1 settles with txid OKRK-LEGIT-1 via userref binding
            def krk_legit_userref(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                if "/AddOrder" in url:
                    return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-LEGIT-1"]}}).encode()
                if "/QueryOrders" in url:
                    r1 = _read_row(db_path, str(prep1["transfer_id"]))
                    return 200, json.dumps({
                        "error": [],
                        "result": {
                            "OKRK-LEGIT-1": {
                                "status": "closed",
                                "userref": str(r1["conversion_client_ref"]),
                                "descr": {"pair": "USDCUSD", "type": "sell"},
                                "vol": "50.00",
                                "vol_exec": "50.00",
                                "cost": "50.00",
                                "fee": "0.00",
                            }
                        },
                    }).encode()
                if "/Withdraw" in url:
                    return 200, json.dumps({"error": [], "result": {"refid": "KRK-WD-LEGIT-1"}}).encode()
                raise AssertionError(url)

            krk1 = self._make_kraken(krk_legit_userref)
            prep1 = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-legit-1",
                reason="sweep 1",
                kraken_client=krk1,
                convert_amount=D("50.00"),
                kraken_pair="USDCUSD",
            )
            tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep1["intent_sha256"], now=T0)
            out1 = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-legit-1",
                reason="sweep 1",
                verifier=rec,
                recovery_token=tok1,
                kraken_client=krk1,
                convert_amount=D("50.00"),
                kraken_pair="USDCUSD",
                intent_id=prep1["intent_id"],
                intent_sha256=prep1["intent_sha256"],
            )
            self.assertEqual(out1["status"], "ACH_SUBMITTED")

            # 2. Sweep 2 replaying Sweep 1's conversion_tx_id MUST BE REJECTED with 0 Withdraw calls!
            wd2_calls = {"n": 0}

            def krk_replay(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                if "/AddOrder" in url:
                    return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-LEGIT-1"]}}).encode()
                if "/Withdraw" in url:
                    wd2_calls["n"] += 1
                    return 200, json.dumps({"error": [], "result": {"refid": "BAD"}}).encode()
                raise AssertionError(url)

            krk2 = self._make_kraken(krk_replay)
            prep2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-replay-2",
                reason="replayed txid",
                kraken_client=krk2,
                convert_amount=D("50.00"),
                kraken_pair="USDCUSD",
            )
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep2["intent_sha256"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-replay-2",
                    reason="replayed txid",
                    verifier=rec,
                    recovery_token=tok2,
                    kraken_client=krk2,
                    convert_amount=D("50.00"),
                    kraken_pair="USDCUSD",
                    intent_id=prep2["intent_id"],
                    intent_sha256=prep2["intent_sha256"],
                )
            self.assertEqual(wd2_calls["n"], 0)
            self.assertEqual(_read_row(db_path, str(prep2["transfer_id"]))["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

            # 3. Mismatched client_reference_id (even when txid matches!) and mismatched txid (even when ref matches!) fail closed
            for mismatch_case in ("mismatched_ref", "mismatched_tx", "missing_both_when_unbound"):
                with self.subTest(case=mismatch_case):
                    wd_m = {"n": 0}

                    def cb_http(method: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                        if "/convert/quote" in url:
                            return 200, json.dumps({"trade": {"id": f"cb-mm-{mismatch_case}"}}).encode()
                        if method == "POST" and "/convert/trade/" in url:
                            return 200, json.dumps({"trade": {"id": f"cb-mm-{mismatch_case}", "status": "PENDING"}}).encode()
                        if method == "GET" and "/convert/trade/" in url:
                            r = _read_row(db_path, str(prep_m["transfer_id"]))
                            ref = str(r["conversion_client_ref"])
                            if mismatch_case == "mismatched_ref":
                                return 200, json.dumps({
                                    "trade": {
                                        "id": f"cb-mm-{mismatch_case}",
                                        "status": "TRADE_STATUS_COMPLETED",
                                        "client_reference_id": "attacker-other-ref",
                                        "from_currency": "USDC",
                                        "to_currency": "USD",
                                        "filled_size": "50.00",
                                        "usd_proceeds": "50.00",
                                    }
                                }).encode()
                            if mismatch_case == "mismatched_tx":
                                return 200, json.dumps({
                                    "trade": {
                                        "id": "cb-completely-other-tx",
                                        "status": "TRADE_STATUS_COMPLETED",
                                        "client_reference_id": ref,
                                        "from_currency": "USDC",
                                        "to_currency": "USD",
                                        "filled_size": "50.00",
                                        "usd_proceeds": "50.00",
                                    }
                                }).encode()
                            # Flat unbound record without txid or ref
                            return 200, json.dumps({
                                "status": "TRADE_STATUS_COMPLETED",
                                "from_currency": "USDC",
                                "to_currency": "USD",
                                "filled_size": "50.00",
                                "usd_proceeds": "50.00",
                            }).encode()
                        if "/withdrawals/fiat" in url:
                            wd_m["n"] += 1
                            return 200, json.dumps({"id": "bad"}).encode()
                        raise AssertionError(url)

                    cb = self._make_coinbase(pem_path, cb_http)
                    prep_m = vault.prepare_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("50.00"),
                        owner_request_id=f"req-{mismatch_case}",
                        reason="binding test",
                        coinbase_client=cb,
                        convert_from_currency="USDC",
                        convert_amount=D("50.00"),
                        coinbase_source_account_uuid="src-1",
                        coinbase_usd_account_uuid="usd-1",
                    )
                    tok_m = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_m["intent_sha256"], now=T0)
                    with self.assertRaises(OfframpSecurityError):
                        vault.execute_offramp_ach_payout(
                            rail=RAIL_COINBASE_ACH,
                            amount_usd=D("50.00"),
                            owner_request_id=f"req-{mismatch_case}",
                            reason="binding test",
                            verifier=rec,
                            recovery_token=tok_m,
                            coinbase_client=cb,
                            convert_from_currency="USDC",
                            convert_amount=D("50.00"),
                            coinbase_source_account_uuid="src-1",
                            coinbase_usd_account_uuid="usd-1",
                            intent_id=prep_m["intent_id"],
                            intent_sha256=prep_m["intent_sha256"],
                        )
                    self.assertEqual(wd_m["n"], 0)
                    self.assertEqual(_read_row(db_path, str(prep_m["transfer_id"]))["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

    def test_mandatory_asset_pair_side_account_full_fill_and_proceeds_bounds(self) -> None:
        # Positive: Kraken XBTUSD (XXBTZUSD alias), USDTUSD, ETHUSD and Coinbase BTC/ETH/USDT -> USD with full fill & net proceeds
        positive_cases = [
            (RAIL_KRAKEN_ACH, "XBTUSD", "XXBTZUSD", D("0.002"), D("100.00"), D("100.50"), D("0.20")),
            (RAIL_KRAKEN_ACH, "ETHUSD", "XETHZUSD", D("0.05"), D("100.00"), D("100.00"), D("0.00")),
            (RAIL_KRAKEN_ACH, "USDTUSD", "USDTUSD", D("100.00"), D("99.50"), D("99.90"), D("0.20")),
        ]
        for rail, req_pair, resp_pair, conv_amt, wd_amt, cost, fee in positive_cases:
            with self.subTest(positive=req_pair), tempfile.TemporaryDirectory() as td:
                vault, rec, db_path, _ = self._setup(Path(td))

                def krk_pos(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                    row = _read_row(db_path, str(prep["transfer_id"]))
                    if "/AddOrder" in url:
                        return 200, json.dumps({"error": [], "result": {"txid": [f"OKRK-{req_pair}"]}}).encode()
                    if "/QueryOrders" in url:
                        return 200, json.dumps({
                            "error": [],
                            "result": {
                                f"OKRK-{req_pair}": {
                                    "status": "closed",
                                    "cl_ord_id": str(row["conversion_client_ref"]),
                                    "descr": {"pair": resp_pair, "type": "sell"},
                                    "vol": str(conv_amt),
                                    "vol_exec": str(conv_amt),
                                    "cost": str(cost),
                                    "fee": str(fee),
                                }
                            },
                        }).encode()
                    if "/Withdraw" in url:
                        return 200, json.dumps({"error": [], "result": {"refid": f"WD-{req_pair}"}}).encode()
                    raise AssertionError(url)

                krk = self._make_kraken(krk_pos)
                prep = vault.prepare_offramp_ach_payout(
                    rail=rail,
                    amount_usd=wd_amt,
                    owner_request_id=f"req-pos-{req_pair}",
                    reason="positive asset/proceeds test",
                    kraken_client=krk,
                    convert_amount=conv_amt,
                    kraken_pair=req_pair,
                )
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                out = vault.execute_offramp_ach_payout(
                    rail=rail,
                    amount_usd=wd_amt,
                    owner_request_id=f"req-pos-{req_pair}",
                    reason="positive asset/proceeds test",
                    verifier=rec,
                    recovery_token=tok,
                    kraken_client=krk,
                    convert_amount=conv_amt,
                    kraken_pair=req_pair,
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )
                self.assertEqual(out["status"], "ACH_SUBMITTED")

        # Positive Coinbase BTC/ETH/USDT -> USD with source_amount & target_amount/total
        cb_pos_cases = [
            ("BTC", D("0.002"), D("100.00"), D("101.25"), "SETTLED"),
            ("ETH", D("0.04"), D("95.00"), D("95.00"), "FILLED"),
            ("USDT", D("80.00"), D("80.00"), D("80.00"), "COMPLETED"),
        ]
        for cur, conv_amt, wd_amt, target_amt, term_status in cb_pos_cases:
            with self.subTest(cb_positive=cur), tempfile.TemporaryDirectory() as td:
                vault, rec, db_path, pem_path = self._setup(Path(td))

                def cb_pos(method: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                    row = _read_row(db_path, str(prep["transfer_id"]))
                    if "/convert/quote" in url:
                        return 200, json.dumps({"trade": {"id": f"cb-pos-{cur}"}}).encode()
                    if method == "POST" and "/convert/trade/" in url:
                        return 200, json.dumps({"trade": {"id": f"cb-pos-{cur}", "status": "PENDING"}}).encode()
                    if method == "GET" and "/convert/trade/" in url:
                        return 200, json.dumps({
                            "trade": {
                                "id": f"cb-pos-{cur}",
                                "status": term_status,
                                "client_reference_id": str(row["conversion_client_ref"]),
                                "source": {"ledger_account": {"account_id": "src-acct", "currency": cur}},
                                "target": {"ledger_account": {"account_id": "usd-acct", "currency": "USD"}},
                                "source_amount": str(conv_amt),
                                "total": {"value": str(target_amt), "currency": "USD"},
                            }
                        }).encode()
                    if "/withdrawals/fiat" in url:
                        return 200, json.dumps({"id": f"cb-wd-{cur}"}).encode()
                    raise AssertionError(url)

                cb = self._make_coinbase(pem_path, cb_pos)
                prep = vault.prepare_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=wd_amt,
                    owner_request_id=f"req-cb-pos-{cur}",
                    reason="positive cb asset test",
                    coinbase_client=cb,
                    convert_from_currency=cur,
                    convert_amount=conv_amt,
                    coinbase_source_account_uuid="src-acct",
                    coinbase_usd_account_uuid="usd-acct",
                )
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                out = vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=wd_amt,
                    owner_request_id=f"req-cb-pos-{cur}",
                    reason="positive cb asset test",
                    verifier=rec,
                    recovery_token=tok,
                    coinbase_client=cb,
                    convert_from_currency=cur,
                    convert_amount=conv_amt,
                    coinbase_source_account_uuid="src-acct",
                    coinbase_usd_account_uuid="usd-acct",
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )
                self.assertEqual(out["status"], "ACH_SUBMITTED")

        # Negative Kraken cases: wrong pair, buy side, missing side, partial fill (even if proceeds >= amount_usd!),
        # missing vol_exec, missing cost/proceeds, zero proceeds, fee-adjusted proceeds < amount_usd!
        kraken_negative_records: list[tuple[str, D, D, dict[str, object]]] = [
            ("wrong_pair", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "ETHUSD", "type": "sell"}, "vol": "50.00", "vol_exec": "50.00", "cost": "50.00", "fee": "0"}),
            ("wrong_side_buy", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD", "type": "buy"}, "vol": "50.00", "vol_exec": "50.00", "cost": "50.00", "fee": "0"}),
            ("missing_side", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD"}, "vol": "50.00", "vol_exec": "50.00", "cost": "50.00", "fee": "0"}),
            ("missing_vol_exec", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "50.00", "cost": "50.00", "fee": "0"}),
            ("partial_fill_even_with_sufficient_usd", D("100.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "100.00", "vol_exec": "60.00", "cost": "60.00", "fee": "0"}),
            ("missing_realized_usd", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "50.00", "vol_exec": "50.00"}),
            ("zero_realized_usd", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "50.00", "vol_exec": "50.00", "cost": "1.00", "fee": "1.00"}),
            ("fee_shortfall_below_ach_amount", D("50.00"), D("50.00"), {"status": "closed", "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "50.00", "vol_exec": "50.00", "cost": "50.00", "fee": "0.15"}),
        ]
        for label, conv_amt, wd_amt, rec_body in kraken_negative_records:
            with self.subTest(kraken_neg=label), tempfile.TemporaryDirectory() as td:
                vault, rec, db_path, _ = self._setup(Path(td))
                wd_hits = {"n": 0}

                def krk_neg(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                    if "/AddOrder" in url:
                        return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-NEG-1"]}}).encode()
                    if "/QueryOrders" in url:
                        row = _read_row(db_path, str(prep["transfer_id"]))
                        payload = dict(rec_body)
                        payload["cl_ord_id"] = str(row["conversion_client_ref"])
                        return 200, json.dumps({"error": [], "result": {"OKRK-NEG-1": payload}}).encode()
                    if "/Withdraw" in url:
                        wd_hits["n"] += 1
                        return 200, json.dumps({"error": [], "result": {"refid": "BAD"}}).encode()
                    raise AssertionError(url)

                krk = self._make_kraken(krk_neg)
                prep = vault.prepare_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=wd_amt,
                    owner_request_id=f"req-neg-{label}",
                    reason="negative kraken check",
                    kraken_client=krk,
                    convert_amount=conv_amt,
                    kraken_pair="USDCUSD",
                )
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError):
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_KRAKEN_ACH,
                        amount_usd=wd_amt,
                        owner_request_id=f"req-neg-{label}",
                        reason="negative kraken check",
                        verifier=rec,
                        recovery_token=tok,
                        kraken_client=krk,
                        convert_amount=conv_amt,
                        kraken_pair="USDCUSD",
                        intent_id=prep["intent_id"],
                        intent_sha256=prep["intent_sha256"],
                    )
                self.assertEqual(wd_hits["n"], 0)
                self.assertEqual(_read_row(db_path, str(prep["transfer_id"]))["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

        # Negative Coinbase cases: wrong from_currency, wrong/missing to_currency, wrong accounts, wrong side, shortfall
        cb_negative_trades: list[tuple[str, dict[str, object]]] = [
            ("wrong_from_currency", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "from_currency": "ETH", "to_currency": "USD", "from_account": "src-1", "to_account": "usd-1", "filled_size": "50.00", "usd_proceeds": "50.00"}),
            ("missing_to_currency", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "from_currency": "USDC", "from_account": "src-1", "to_account": "usd-1", "filled_size": "50.00", "usd_proceeds": "50.00"}),
            ("wrong_to_currency_eur", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "from_currency": "USDC", "to_currency": "EUR", "from_account": "src-1", "to_account": "usd-1", "filled_size": "50.00", "usd_proceeds": "50.00"}),
            ("wrong_source_account", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "from_currency": "USDC", "to_currency": "USD", "from_account": "attacker-src", "to_account": "usd-1", "filled_size": "50.00", "usd_proceeds": "50.00"}),
            ("wrong_usd_account", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "from_currency": "USDC", "to_currency": "USD", "from_account": "src-1", "to_account": "attacker-usd", "filled_size": "50.00", "usd_proceeds": "50.00"}),
            ("wrong_side_buy", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "side": "BUY", "from_currency": "USDC", "to_currency": "USD", "from_account": "src-1", "to_account": "usd-1", "filled_size": "50.00", "usd_proceeds": "50.00"}),
            ("proceeds_shortfall", {"id": "cb-neg-1", "status": "TRADE_STATUS_COMPLETED", "from_currency": "USDC", "to_currency": "USD", "from_account": "src-1", "to_account": "usd-1", "filled_size": "50.00", "target_amount": "49.50"}),
        ]
        for label, trade_body in cb_negative_trades:
            with self.subTest(cb_neg=label), tempfile.TemporaryDirectory() as td:
                vault, rec, db_path, pem_path = self._setup(Path(td))
                wd_hits = {"n": 0}

                def cb_neg(method: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                    if "/convert/quote" in url:
                        return 200, json.dumps({"trade": {"id": "cb-neg-1"}}).encode()
                    if method == "POST" and "/convert/trade/" in url:
                        return 200, json.dumps({"trade": {"id": "cb-neg-1", "status": "PENDING"}}).encode()
                    if method == "GET" and "/convert/trade/" in url:
                        row = _read_row(db_path, str(prep["transfer_id"]))
                        payload = dict(trade_body)
                        payload["client_reference_id"] = str(row["conversion_client_ref"])
                        return 200, json.dumps({"trade": payload}).encode()
                    if "/withdrawals/fiat" in url:
                        wd_hits["n"] += 1
                        return 200, json.dumps({"id": "bad"}).encode()
                    raise AssertionError(url)

                cb = self._make_coinbase(pem_path, cb_neg)
                prep = vault.prepare_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id=f"req-cbn-{label}",
                    reason="negative coinbase check",
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("50.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                )
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError):
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("50.00"),
                        owner_request_id=f"req-cbn-{label}",
                        reason="negative coinbase check",
                        verifier=rec,
                        recovery_token=tok,
                        coinbase_client=cb,
                        convert_from_currency="USDC",
                        convert_amount=D("50.00"),
                        coinbase_source_account_uuid="src-1",
                        coinbase_usd_account_uuid="usd-1",
                        intent_id=prep["intent_id"],
                        intent_sha256=prep["intent_sha256"],
                    )
                self.assertEqual(wd_hits["n"], 0)
                self.assertEqual(_read_row(db_path, str(prep["transfer_id"]))["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

    def test_reconcile_after_poll_exhaustion_enforces_full_fill_and_retry_completes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault, rec, db_path, _ = self._setup(Path(td))
            mode = {"phase": "open", "add": 0, "wd": 0}

            def krk_http(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                row = _read_row(db_path, tid)
                if "/AddOrder" in url:
                    mode["add"] += 1
                    return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-EXHAUST-1"]}}).encode()
                if "/QueryOrders" in url:
                    ref = str(row["conversion_client_ref"])
                    if mode["phase"] == "open":
                        return 200, json.dumps({"error": [], "result": {"OKRK-EXHAUST-1": {"status": "open", "cl_ord_id": ref, "vol": "75.00", "vol_exec": "0"}}}).encode()
                    if mode["phase"] == "partial_closed":
                        return 200, json.dumps({"error": [], "result": {"OKRK-EXHAUST-1": {"status": "closed", "cl_ord_id": ref, "descr": {"pair": "USDCUSD", "type": "sell"}, "vol": "75.00", "vol_exec": "50.00", "cost": "50.00", "fee": "0"}}}).encode()
                    return 200, json.dumps({
                        "error": [],
                        "result": {
                            "OKRK-EXHAUST-1": {
                                "status": "closed",
                                "cl_ord_id": ref,
                                "descr": {"pair": "USDCUSD", "type": "sell"},
                                "vol": "75.00",
                                "vol_exec": "75.00",
                                "cost": "75.15",
                                "fee": "0.15",
                            }
                        },
                    }).encode()
                if "/Withdraw" in url:
                    mode["wd"] += 1
                    return 200, json.dumps({"error": [], "result": {"refid": "KRK-WD-EXHAUST-1"}}).encode()
                raise AssertionError(url)

            krk = self._make_kraken(krk_http)
            prep1 = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("75.00"),
                owner_request_id="req-exh-1",
                reason="poll exhaustion then reconcile",
                kraken_client=krk,
                convert_amount=D("75.00"),
                kraken_pair="USDCUSD",
            )
            tid = str(prep1["transfer_id"])
            tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep1["intent_sha256"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("75.00"),
                    owner_request_id="req-exh-1",
                    reason="poll exhaustion then reconcile",
                    verifier=rec,
                    recovery_token=tok1,
                    kraken_client=krk,
                    convert_amount=D("75.00"),
                    kraken_pair="USDCUSD",
                    intent_id=prep1["intent_id"],
                    intent_sha256=prep1["intent_sha256"],
                    conversion_poll_attempts=3,
                )
            self.assertEqual(mode["add"], 1)
            self.assertEqual(mode["wd"], 0)

            # Reconciliation rejects partial fill
            mode["phase"] = "partial_closed"
            with self.assertRaises(OfframpSecurityError):
                vault.reconcile_conversion_outcome(transfer_id=tid, kraken_client=krk)
            self.assertEqual(_read_row(db_path, tid)["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

            # Reconciliation accepts terminal full fill covering $75.00
            mode["phase"] = "settled"
            rec_ok = vault.reconcile_conversion_outcome(transfer_id=tid, kraken_client=krk)
            self.assertEqual(rec_ok["conversion_status"], CONVERSION_STATUS_CONFIRMED)
            self.assertEqual(rec_ok["realized_usd_proceeds"], "75")

            # Retry completes Phase 2 with 0 duplicate conversions
            prep2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("75.00"),
                owner_request_id="req-exh-2",
                reason="retry after reconciled full fill",
                kraken_client=krk,
                convert_amount=D("75.00"),
                kraken_pair="USDCUSD",
                retry_transfer_id=tid,
            )
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep2["intent_sha256"], now=T0)
            out2 = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("75.00"),
                owner_request_id="req-exh-2",
                reason="retry after reconciled full fill",
                verifier=rec,
                recovery_token=tok2,
                kraken_client=krk,
                convert_amount=D("75.00"),
                kraken_pair="USDCUSD",
                retry_transfer_id=tid,
                intent_id=prep2["intent_id"],
                intent_sha256=prep2["intent_sha256"],
            )
            self.assertEqual(out2["status"], "ACH_SUBMITTED")
            self.assertEqual(mode["add"], 1)
            self.assertEqual(mode["wd"], 1)

    def test_profit_sweep_source_hygiene_and_zero_asserts(self) -> None:
        for rel in (
            "src/cas_forex_revamp/treasury/profit_sweep.py",
            "tests/security/test_audit_0b16e88_treasury_findings.py",
            "tests/security/test_audit_443a5c4_treasury_findings.py",
            "tests/phase6/test_profit_expansion_pyramiding_and_treasury.py",
        ):
            p = REPO_ROOT / rel
            raw = p.read_bytes()
            self.assertEqual(raw.count(b"\r"), 0, f"{rel} must have CR=0")
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"{rel} must not have BOM")
        ps_path = REPO_ROOT / "src/cas_forex_revamp/treasury/profit_sweep.py"
        txt = ps_path.read_text(encoding="utf-8")
        tree = ast.parse(txt, filename=str(ps_path))
        self.assertEqual([n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)], [])
        marker = "#" + " nosec"
        self.assertLessEqual(sum(1 for ln in txt.splitlines() if marker in ln), 4)


if __name__ == "__main__":
    unittest.main()
