"""E2E FA-3: MQL5-to-Python Bridge Static & Spool Contract Parity (10 tests)."""
from __future__ import annotations

import dataclasses
from datetime import timedelta
from decimal import Decimal
import json
from pathlib import Path
import re
import secrets
import tempfile
import unittest

from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.live_market_stream import EXPANDED_MARKETS
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    MT5_SPOOL_PROTOCOL,
    Mt5BridgeError,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5OrderReceipt,
    Mt5OrderRequest,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5ValveClearanceError,
    OrderIntent,
    _canonical_spool_receipt_hmac_input,
    _canonical_spool_request_hmac_input,
    _spool_hmac_hex,
    derive_spool_channel_key,
    sign_spool_valve_admission,
    spool_channel_key_id,
)

try:
    from tests.e2e_hardening._e2e_support import (
        D,
        QUOTES_20,
        REPO_ROOT,
        SteppingClock,
        T0,
        build_valve_proposal,
        default_policy,
        default_view,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        D,
        QUOTES_20,
        REPO_ROOT,
        SteppingClock,
        T0,
        build_valve_proposal,
        default_policy,
        default_view,
    )


def _mq5_text() -> str:
    return (REPO_ROOT / "mt5/CasForexMt5Bridge.mq5").read_text(encoding="utf-8")


class Mql5BridgeE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (E2E-T1-11 .. E2E-T1-15) ---

    def test_e2e_t1_11_mql5_20_symbols_match_python_expanded_markets(self) -> None:
        mq5 = _mq5_text()
        m = re.search(r'input\s+string\s+InpSymbols\s*=\s*"([^"]+)"', mq5)
        self.assertIsNotNone(m)
        mq5_symbols = [s.strip() for s in m.group(1).split(",") if s.strip()]
        self.assertEqual(len(mq5_symbols), 20)
        self.assertEqual(set(mq5_symbols), set(EXPANDED_MARKETS))
        for special in ("NAS100", "US30", "SPX500", "XAUUSD"):
            self.assertIn(f'cas_symbol == "{special}"', mq5)

    def test_e2e_t1_12_spool_request_21_field_hmac_order_parity(self) -> None:
        mq5 = _mq5_text()
        req = Mt5OrderRequest(
            request_id="req-parity-01",
            action="OPEN",
            symbol="EURUSD",
            side=Side.BUY,
            volume_lots=D("0.10"),
            price=D("1.10010"),
            stop_loss=D("1.09500"),
            take_profit=D("1.11000"),
            position_ticket=None,
            deviation_points=30,
            magic=20261118,
            comment="parity-check",
            created_at=T0,
            monotonic_nonce=7,
            broker_channel="hugosway_mt5",
            account_login="7001234",
            server="Hugosway-Demo",
            execution_mode="DEMO",
            valve_decision_sha256="a" * 64,
        )
        doc = req.to_spool_dict()
        py_canonical = _canonical_spool_request_hmac_input(doc)
        self.assertEqual(len(py_canonical.split("|")), 24)

        m = re.search(r'string\s+hmac_msg\s*=\s*JsonGet\(text,\s*\"protocol\"\)(.*?);', mq5, re.S)
        self.assertIsNotNone(m)
        mq5_block = m.group(1)
        expected_tokens = (
            "request_id", "nonce_s", "issued_at", "expires_at",
            "broker_channel", "channel_key_id", "account_login", "server", "execution_mode",
            "valve_decision_sha256", "valve_admission_expires_at", "valve_admission_sig",
            "action", "symbol", "side", "volume",
            "price", "sl", "tp", "position_ticket", "deviation_points",
            "magic", "comment",
        )
        last_pos = -1
        for tok in expected_tokens:
            pos = mq5_block.find(tok)
            self.assertGreater(pos, last_pos, f"Order mismatch for {tok}")
            last_pos = pos

        key = secrets.token_bytes(32)
        self.assertEqual(len(_spool_hmac_hex(key, py_canonical)), 64)

    def test_e2e_t1_13_spool_receipt_16_field_hmac_order_parity(self) -> None:
        mq5 = _mq5_text()
        receipt_doc = {
            "protocol": MT5_SPOOL_PROTOCOL,
            "request_id": "req-parity-01",
            "request_sha256": "b" * 64,
            "monotonic_nonce": "7",
            "status": "FILLED",
            "retcode": "10009",
            "position_ticket": "1001",
            "deal_ticket": "80001",
            "volume": "0.10",
            "price": "1.10010",
            "sl": "1.09500",
            "tp": "1.11000",
            "account_trade_mode": "DEMO",
            "server": "Hugosway-Demo",
            "observed_at": "2026-11-18T13:00:00Z",
            "message": "done",
        }
        py_canonical = _canonical_spool_receipt_hmac_input(receipt_doc)
        self.assertEqual(len(py_canonical.split("|")), 16)

        m = re.search(r'string\s+ReceiptJson\([^)]*\)\s*\{.*?string\s+canonical\s*=\s*SPOOL_PROTOCOL(.*?);', mq5, re.S)
        self.assertIsNotNone(m)
        mq5_block = m.group(1)
        expected_vars = (
            "request_id", "request_sha", "nonce_str", "status", "ret_str",
            "position_ticket", "deal_ticket", "volume", "price", "sl", "tp",
            "trade_mode", "server", "obs_at", "safe_msg",
        )
        last_pos = -1
        for var in expected_vars:
            pos = mq5_block.find(var)
            self.assertGreater(pos, last_pos, f"Receipt field order mismatch for {var}")
            last_pos = pos

        key = secrets.token_bytes(32)
        mac = _spool_hmac_hex(key, py_canonical)
        rcpt = Mt5OrderReceipt(
            request_id="req-parity-01",
            request_sha256="b" * 64,
            status="FILLED",
            retcode=10009,
            position_ticket="1001",
            deal_ticket="80001",
            volume_lots=D("0.10"),
            price=D("1.10010"),
            stop_loss=D("1.09500"),
            take_profit=D("1.11000"),
            server="Hugosway-Demo",
            observed_at=T0,
            transport="spool_bridge",
            message="done",
        )
        self.assertTrue(rcpt.accepted)

    def test_e2e_t1_14_spool_transport_and_emulator_demo_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            snap = transport.connect(creds)
            self.assertEqual(snap.trade_mode, "DEMO")

            req = Mt5OrderRequest(
                request_id="req-rt-01",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                take_profit=D("1.11000"),
                position_ticket=None,
                deviation_points=30,
                magic=20261118,
                comment="e2e-rt",
                created_at=T0,
                valve_decision_sha256="c" * 64,
            )
            signed_req = sign_spool_valve_admission(transport.prepare_request(req), spool_dir=spool_dir)
            rcpt = transport.send_order(signed_req)
            self.assertTrue(rcpt.accepted)
            self.assertEqual(rcpt.status, "FILLED")
            self.assertEqual(rcpt.retcode, 10009)
            self.assertEqual(emu._replay_ledger.load()[0], 1)
            self.assertEqual(transport._nonce_ledger.load()[0], 1)
            self.assertEqual(len(transport.positions()), 1)

    def test_e2e_t1_15_paper_broker_venue_open_records_mutation_journal(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            journal = Mt5MutationJournal(Path(td) / "journal.sqlite3")
            venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=creds,
                transport=transport,
                valve_gate=gate,
                mutation_journal=journal,
                clock=SteppingClock(T0),
            )
            venue.connect()
            order = OrderIntent(
                order_id="ord-venue-01",
                action_ref="act-venue-01",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                take_profit_price=D("1.11000"),
            )
            prop = build_valve_proposal(
                order_id=order.order_id,
                action_ref=order.action_ref,
                quantity=order.quantity_units,
                limit_price=D("1.10010"),
                stop_price=order.stop_price,
                take_profit_price=order.take_profit_price,
            )
            dec = gate.require_admissible(prop, current_view=default_view(), policy=default_policy(), now=T0 + timedelta(seconds=1))
            res = venue.execute(order, valve_decision=dec)
            self.assertTrue(res.accepted)
            self.assertEqual(len(res.positions_after), 1)
            self.assertEqual(journal.unknown_mutations(broker_id=BROKER_HUGOSWAY_MT5), [])

    # --- Tier 2: Boundary & Corner Cases (E2E-T2-11 .. E2E-T2-15) ---

    def test_e2e_t2_11_reused_or_decreasing_monotonic_nonce_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            transport.connect(creds)

            req1 = Mt5OrderRequest(
                request_id="req-nonce-01",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=30,
                magic=20261118,
                comment="nonce-1",
                created_at=T0,
                valve_decision_sha256="d" * 64,
            )
            signed_req1 = sign_spool_valve_admission(transport.prepare_request(req1), spool_dir=spool_dir)
            rcpt1 = transport.send_order(signed_req1)
            self.assertTrue(rcpt1.accepted)

            key_hex = (Path(td) / ".spool_hmac.key").read_text(encoding="ascii").strip()
            key_bytes = derive_spool_channel_key(bytes.fromhex(key_hex), "hugosway_mt5")
            replay_req = Mt5OrderRequest(
                request_id="req-nonce-02",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=30,
                magic=20261118,
                comment="nonce-replay",
                created_at=T0,
                issued_at=T0,
                expires_at=T0 + timedelta(seconds=30),
                monotonic_nonce=1,
                broker_channel="hugosway_mt5",
                account_login="7001234",
                server="Hugosway-Demo",
                execution_mode="DEMO",
                valve_decision_sha256="d" * 64,
            )
            replay_req = sign_spool_valve_admission(
                dataclasses.replace(replay_req, channel_key_id=spool_channel_key_id(key_bytes, "hugosway_mt5")),
                spool_dir=spool_dir,
            )
            doc = replay_req.to_spool_dict()
            doc["request_hmac_sha256"] = _spool_hmac_hex(key_bytes, _canonical_spool_request_hmac_input(doc))
            (spool_dir / "order_request_req-nonce-02.json").write_text(json.dumps(doc), encoding="utf-8")
            emu.process_pending()
            rcpt_raw = json.loads((spool_dir / "order_receipt_req-nonce-02.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_raw["status"], "REJECTED")
            self.assertEqual(rcpt_raw["retcode"], "10013")

    def test_e2e_t2_12_tampered_hmac_or_valve_sha_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            transport.connect(creds)

            req = Mt5OrderRequest(
                request_id="req-tamper-01",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=30,
                magic=20261118,
                comment="tamper",
                created_at=T0,
                issued_at=T0,
                expires_at=T0 + timedelta(seconds=30),
                monotonic_nonce=1,
                broker_channel="hugosway_mt5",
                account_login="7001234",
                server="Hugosway-Demo",
                execution_mode="DEMO",
                valve_decision_sha256="e" * 64,
            )
            doc = req.to_spool_dict()
            doc["request_hmac_sha256"] = "0" * 64
            (spool_dir / "order_request_req-tamper-01.json").write_text(json.dumps(doc), encoding="utf-8")
            emu.process_pending()
            rcpt_raw = json.loads((spool_dir / "order_receipt_req-tamper-01.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_raw["status"], "REJECTED")

            tampered_rcpt = dict(rcpt_raw)
            bad_char = "1" if tampered_rcpt["receipt_hmac_sha256"][0] == "0" else "0"
            tampered_rcpt["receipt_hmac_sha256"] = bad_char + tampered_rcpt["receipt_hmac_sha256"][1:]
            rcpt_path = spool_dir / "order_receipt_req-tamper-01.json"
            rcpt_path.write_text(json.dumps(tampered_rcpt), encoding="utf-8")
            with self.assertRaises(Mt5BridgeError):
                transport._parse_receipt(rcpt_path, req, creds)

    def test_e2e_t2_13_expired_spool_request_rejected_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            transport.connect(creds)

            expired_req = Mt5OrderRequest(
                request_id="req-expired-01",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=30,
                magic=20261118,
                comment="expired",
                created_at=T0 - timedelta(hours=2),
                issued_at=T0 - timedelta(hours=2),
                expires_at=T0 - timedelta(hours=1),
                monotonic_nonce=1,
                broker_channel="hugosway_mt5",
                account_login="7001234",
                server="Hugosway-Demo",
                execution_mode="DEMO",
                valve_decision_sha256="f" * 64,
            )
            key_bytes = bytes.fromhex((Path(td) / ".spool_hmac.key").read_text(encoding="ascii").strip())
            doc = expired_req.to_spool_dict()
            doc["request_hmac_sha256"] = _spool_hmac_hex(key_bytes, _canonical_spool_request_hmac_input(doc))
            (spool_dir / "order_request_req-expired-01.json").write_text(json.dumps(doc), encoding="utf-8")
            emu.process_pending()
            rcpt_raw = json.loads((spool_dir / "order_receipt_req-expired-01.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_raw["status"], "REJECTED")
            self.assertEqual(len(transport.positions()), 0)

    def test_e2e_t2_14_mql5_mode_guard_blocks_live_or_real_in_demo_mode(self) -> None:
        mq5 = _mq5_text()
        m = re.search(r'bool\s+ModeGuard\(\)\s*\{(.*?)^\s{2}\}', mq5, re.S | re.M)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("if(!InpLiveExecutionMode)", body)
        self.assertIn("if(m != ACCOUNT_TRADE_MODE_DEMO)", body)
        self.assertIn('StringFind(server, "live") >= 0 || StringFind(server, "real") >= 0', body)
        self.assertIn("return(VerifyLiveTicketGuard(server));", body)

    def test_e2e_t2_15_venue_refuses_mismatched_valve_weights_sha256(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=creds,
                transport=transport,
                valve_gate=gate,
                clock=SteppingClock(T0),
            )
            venue.connect()
            order = OrderIntent(
                order_id="ord-bad-sha",
                action_ref="act-bad-sha",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            other_gate = load_default_forex_valve_gate()
            prop = build_valve_proposal(order_id=order.order_id, action_ref=order.action_ref, stop_price=order.stop_price)
            dec = other_gate.require_admissible(prop, current_view=default_view(), policy=default_policy(), now=T0 + timedelta(seconds=1))
            forged_dec = dataclasses.replace(dec, weights_sha256="0" * 64)
            with self.assertRaises(Mt5ValveClearanceError):
                venue.execute(order, valve_decision=forged_dec)


if __name__ == "__main__":
    unittest.main()
