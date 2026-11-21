"""Security regression tests for PR #32 Audit 443a5c4 — Findings [6], [8], [9], [13].

Covers:
- Finding [9] (csf_a1dcf3cd5c8cc4d9d9e8327d): Fail-closed MQL5 & Python spool replay-ledger persistence
- Finding [8] (csf_5f4745693d079dfce5ca8bd3): HMAC-authenticated, sequence-bound, freshness-checked MT5 market_ticks.json
- Finding [6] (csf_7634c94903b38bd9bcca10f5): Descriptor-relative O_NOFOLLOW LIVE key/ticket loading & inode binding
- Finding [13] (csf_bd58ce74d251e38a3f452b77): Expiry-indexed bounded Valve replay ledgers
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cas_forex_revamp.composition.state_store import create_owner_only_file_atomic
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.valve import tks_meta_valve_controller as valve_mod
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    MAX_VALVE_REPLAY_LEDGER_ENTRIES,
    PeakEquityStore,
    ValveDecision,
    ValveGrantError,
    load_default_forex_valve_gate,
    verify_and_consume_valve_order_grant,
)
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    ENV_EXECUTION_MODE,
    ENV_LIVE_ARM_PHRASE,
    ENV_OANDA_PRACTICE_ACCOUNT_ID,
    ENV_OANDA_PRACTICE_TOKEN,
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    LiveBrokerEndpointForbiddenError,
    OandaPracticePaperClient,
    REQUIRED_LIVE_ARM_PHRASE,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    ENV_LIVE_AUTH_KEY_FILE,
    ENV_LIVE_AUTH_TICKET_FILE,
    LIVE_ARM_CONFIRMATION_TEXT,
    LiveAuthorizationError,
    LiveAuthTicketError,
    mint_live_authorization_ticket,
    provision_live_auth_key,
    verify_live_authorization_context,
    verify_live_environ_authorization_context,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
    ENV_HUGOSWAY_MT5_SERVER,
    ENV_LHFX_MT5_LOGIN,
    ENV_LHFX_MT5_SERVER,
    ENV_MT5_SPOOL_DIR,
    ENV_MT5_TRANSPORT_MODE,
    MT5_SPOOL_PROTOCOL,
    Mt5Credentials,
    Mt5NativePythonTransport,
    Mt5OrderRequest,
    Mt5SnapshotIntegrityError,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5TransportError,
    OrderIntent,
    TRANSPORT_SPOOL_BRIDGE,
    _RedactedSecret,
    _SpoolReplayLedger,
    _canonical_valve_admission_input,
    compute_mt5_market_snapshot_hmac,
    derive_spool_channel_key,
    sign_mt5_market_snapshot_doc,
    sign_spool_valve_admission,
)
from cas_forex_revamp.venue import mt5_broker_bridge as bridge_mod

D = Decimal
T0 = datetime(2026, 11, 21, 14, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
MQ5_PATH = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"
LIVE_AUTH_PATH = REPO_ROOT / "src" / "cas_forex_revamp" / "venue" / "live_auth_ticket.py"


def _synth_val(slot: str) -> str:
    return f"test-fixture-{slot}-value-443a5c4"


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _StubOandaTransport:
    def __init__(self, *, account_id: str = "101-001-4435001-001", equity: str = "80000.00") -> None:
        self.account_id = account_id
        self.equity = equity

    def __call__(self, method: str, url: str, *_args: object) -> bytes:
        if method.upper() == "GET" and url.endswith("/summary"):
            return json.dumps({
                "lastTransactionID": "100",
                "account": {
                    "id": self.account_id,
                    "currency": "USD",
                    "balance": self.equity,
                    "NAV": self.equity,
                    "unrealizedPL": "0.00",
                    "marginAvailable": self.equity,
                    "openPositionCount": 0,
                    "lastTransactionID": "100",
                },
            }).encode("utf-8")
        if method.upper() == "GET" and "/pricing" in url:
            return json.dumps({
                "time": T0.isoformat().replace("+00:00", "Z"),
                "prices": [{
                    "instrument": "EUR_USD",
                    "time": T0.isoformat().replace("+00:00", "Z"),
                    "bids": [{"price": "1.10000", "liquidity": 1000000}],
                    "asks": [{"price": "1.10010", "liquidity": 1000000}],
                    "tradeable": True,
                }],
            }).encode("utf-8")
        return json.dumps({"lastTransactionID": "100", "trades": []}).encode("utf-8")


class _NativeSdkFake:
    ACCOUNT_TRADE_MODE_DEMO = 0
    ACCOUNT_TRADE_MODE_CONTEST = 1
    ACCOUNT_TRADE_MODE_REAL = 2
    TRADE_ACTION_DEAL = 1
    ORDER_TYPE_BUY = 0
    ORDER_TYPE_SELL = 1
    ORDER_TIME_GTC = 0
    ORDER_FILLING_IOC = 1
    TRADE_RETCODE_DONE = 10009

    def __init__(self, *, login: int = 9001122, server: str = "Hugo PRO5", trade_mode: int = 2) -> None:
        self.login_val = login
        self.server_val = server
        self.trade_mode_val = trade_mode
        self.order_send_calls = 0

    def initialize(self, **_kw: object) -> bool:
        return True

    def login(self, *_a: object, **_kw: object) -> bool:
        return True

    def shutdown(self) -> None:
        return None

    def last_error(self) -> tuple[int, str]:
        return (0, "OK")

    def terminal_info(self) -> SimpleNamespace:
        return SimpleNamespace(connected=True)

    def account_info(self) -> SimpleNamespace:
        return SimpleNamespace(
            login=self.login_val,
            server=self.server_val,
            trade_mode=self.trade_mode_val,
            currency="USD",
            balance=100000.0,
            equity=100000.0,
            margin=0.0,
            margin_free=100000.0,
            leverage=500,
        )

    def symbol_select(self, _sym: str, _enable: bool) -> bool:
        return True

    def symbol_info_tick(self, _sym: str) -> SimpleNamespace:
        return SimpleNamespace(bid=1.10000, ask=1.10010, time_msc=int(T0.timestamp() * 1000))

    def positions_get(self) -> tuple[object, ...]:
        return ()

    def order_send(self, payload: dict[str, object]) -> SimpleNamespace:
        self.order_send_calls += 1
        return SimpleNamespace(
            retcode=10009,
            deal=900001,
            order=800001,
            volume=float(payload.get("volume", 0.1)),
            price=float(payload.get("price", 1.1001)),
            comment="ok",
        )


def _admit_order(gate, order: OrderIntent, *, now: datetime) -> ValveDecision:
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=order.limit_price,
        take_profit_price=order.take_profit_price,
        target_id=order.position_ticket,
    )
    req = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-1"),),
        state=SimpleNamespace(observed_at=now, valid_until=now + timedelta(minutes=5)),
    )
    sel = SimpleNamespace(evidence_ids=("ev-1",), reason="audit-443a5c4 test", selected_action_ref=order.action_ref)
    prop = SimpleNamespace(request=req, result=SimpleNamespace(selection=sel), intent=intent)
    view = {"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"}
    pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "10000000"}
    return gate.require_admissible(prop, current_view=view, policy=pol, now=now)


def _extract_mql5_block(src: str, header_prefix: str) -> str:
    idx = src.find(header_prefix)
    if idx < 0:
        raise AssertionError(f"MQL5 block {header_prefix!r} not found")
    brace_start = src.find("{", idx)
    depth = 0
    for pos in range(brace_start, len(src)):
        ch = src[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[idx : pos + 1]
    raise AssertionError(f"Unclosed braces for {header_prefix!r}")


class Audit443a5c4Mt5AndValveTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Finding [9]: Fail-closed MQL5 & Python replay-ledger persistence
    # ------------------------------------------------------------------
    def test_finding_09_mql5_replay_ledger_fail_closed_static_parity(self) -> None:
        src = MQ5_PATH.read_text(encoding="utf-8")
        self.assertIn("g_replay_ledger_healthy", src)
        for fn in (
            "LoadGlobalReplayDomain()",
            "IsGlobalReplayIdSeen(const string req_id)",
            "RecordGlobalReplayId(const string req_id)",
            "LoadReplayNonceLedger()",
            "SaveReplayNonceLedger(const ulong nonce_val)",
        ):
            self.assertIn(f"bool {fn}", src)
            self.assertNotIn(f"void {fn}", src)

        for fn_hdr in ("bool SaveReplayNonceLedger(", "bool RecordGlobalReplayId("):
            block = _extract_mql5_block(src, fn_hdr)
            self.assertIn(".tmp", block)
            self.assertIn("FileFlush(", block)
            self.assertIn("FileClose(", block)
            self.assertIn("FileMove(", block)
            self.assertIn("FILE_REWRITE", block)
            self.assertGreaterEqual(block.count("FileOpen("), 2, f"{fn_hdr} must reopen & reread")

        exec_block = _extract_mql5_block(src, "void ExecuteRequest(")
        self.assertIn("replay ledger persistence failed", exec_block)
        idx_ledger = exec_block.find("SaveReplayNonceLedger(req_nonce)")
        idx_global = exec_block.find("RecordGlobalReplayId(request_id)")
        idx_open = exec_block.find("g_trade.PositionOpen(")
        self.assertGreater(idx_ledger, 0)
        self.assertGreater(idx_global, 0)
        self.assertGreater(idx_open, idx_ledger)
        self.assertGreater(idx_open, idx_global)

    def test_finding_09_python_emulator_and_ledger_fail_closed_persistence(self) -> None:
        gate = load_default_forex_valve_gate()

        def _make_signed_open(tr: Mt5SpoolBridgeTransport, req_id: str, now: datetime) -> tuple[Mt5OrderRequest, object]:
            order = OrderIntent(
                order_id=req_id,
                action_ref=f"act-{req_id}",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec = _admit_order(gate, order, now=now)
            raw = Mt5OrderRequest(
                request_id=req_id,
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                position_ticket=None,
                deviation_points=20,
                magic=20261121,
                comment="f9-test",
                created_at=now,
                valve_decision_sha256="a" * 64,
            )
            prepared = sign_spool_valve_admission(tr.prepare_request(raw), spool_dir=tr.spool_dir)
            grant = gate.issue_order_grant(
                dec,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugosway-Demo",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                order_action_ref=order.action_ref,
                order_quantity_units=order.quantity_units,
                order_limit_price=order.limit_price,
                now=now,
            )
            return prepared, grant

        # 1. Corrupt emulator replay ledger fails closed with REJECTED 10013 and blocks trade dispatch
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool, server="Hugosway-Demo", login=7001234, quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, clock=lambda: T0
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2.0, clock=lambda: T0)
            tr.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            emu._replay_ledger.path.write_text('{"last_monotonic_nonce":"bad","seen_request_ids":[]}\n', encoding="utf-8")
            req1, grant1 = _make_signed_open(tr, "f9-corrupt-1", T0)
            rcpt1 = tr.send_order(req1, valve_grant=grant1)
            self.assertFalse(rcpt1.accepted)
            self.assertEqual(rcpt1.retcode, 10013)
            self.assertIn("replay ledger persistence failed", rcpt1.message)
            self.assertFalse(emu._replay_ledger_healthy)
            self.assertEqual(len(emu._positions), 0)

        # 2. Corrupt global replay ledger fails closed with REJECTED 10013
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool, server="Hugosway-Demo", login=7001234, quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, clock=lambda: T0
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2.0, clock=lambda: T0)
            tr.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            emu._global_replay_ledger.path.write_text("{corrupt-json", encoding="utf-8")
            req2, grant2 = _make_signed_open(tr, "f9-corrupt-global-1", T0)
            rcpt2 = tr.send_order(req2, valve_grant=grant2)
            self.assertFalse(rcpt2.accepted)
            self.assertEqual(rcpt2.retcode, 10013)
            self.assertIn("replay ledger persistence failed", rcpt2.message)
            self.assertEqual(len(emu._positions), 0)

        # 3. _SpoolReplayLedger corrupt file & reread verification mismatch fail closed
        with tempfile.TemporaryDirectory() as td:
            ledger_path = Path(td) / ".replay.json"
            ledger_path.write_text('{"last_monotonic_nonce":"nan"}', encoding="utf-8")
            ledger = _SpoolReplayLedger(ledger_path)
            with self.assertRaises(Mt5TransportError):
                ledger.load()
            ledger_path.unlink()
            ledger.verify_and_record(request_id="req-ok-1", nonce=1)
            with mock.patch.object(bridge_mod, "_atomic_write_json", lambda *a, **kw: None):
                with self.assertRaises(Mt5TransportError):
                    ledger.verify_and_record(request_id="req-fail-2", nonce=2)

        # 4. Restarted emulator remembers durable replay ledger & rejects stale nonce or request_id
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu1 = Mt5SpoolPaperTerminalEmulator(
                spool, server="Hugosway-Demo", login=7001234, quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, clock=lambda: T0
            )
            emu1.publish_market()
            tr1 = Mt5SpoolBridgeTransport(spool, sleep=emu1.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2.0, clock=lambda: T0)
            tr1.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            req_ok, grant_ok = _make_signed_open(tr1, "f9-durable-1", T0)
            rcpt_ok = tr1.send_order(req_ok, valve_grant=grant_ok)
            self.assertTrue(rcpt_ok.accepted)

            emu2 = Mt5SpoolPaperTerminalEmulator(
                spool, server="Hugosway-Demo", login=7001234, quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, clock=lambda: T0
            )
            # Direct call to _execute with replayed nonce=1 fails closed on new emulator instance
            replay_rcpt = emu2._execute(req_ok.to_spool_dict())
            self.assertEqual(replay_rcpt["status"], "REJECTED")
            self.assertEqual(replay_rcpt["retcode"], "10013")

    # ------------------------------------------------------------------
    # Finding [8]: HMAC-authenticated, monotonic-seq, fresh market_ticks.json
    # ------------------------------------------------------------------
    def test_finding_08_mql5_market_ticks_hmac_sequence_and_sha256_empty_parity(self) -> None:
        src = MQ5_PATH.read_text(encoding="utf-8")
        self.assertIn("g_snapshot_seq", src)
        self.assertIn("LoadSnapshotSeq", src)
        self.assertIn("AdvanceAndPersistSnapshotSeq", src)
        self.assertIn(".ea_snapshot_seq.txt", src)

        sha_fn = _extract_mql5_block(src, "string Sha256Hex(")
        self.assertIn("StringLen(text) == 0", sha_fn)

        pub_fn = _extract_mql5_block(src, "void PublishMarket(")
        for token in (
            "g_hmac_key_loaded",
            "ticks_canon",
            "positions_canon",
            "snapshot_msg",
            "snapshot_mac",
            "HmacSha256Hex(g_hmac_key, snapshot_msg)",
            "snapshot_hmac_sha256",
            "snapshot_seq",
            "broker_channel",
            "channel_key_id",
            "execution_mode",
        ):
            self.assertIn(token, pub_fn)

        # Canonical byte-parity verification against manual reference concatenation
        key = b"k" * 32
        key_id = bridge_mod.spool_channel_key_id(key, "hugosway_mt5")
        empty_sha = sha256(b"").hexdigest()
        doc_empty = {
            "protocol": MT5_SPOOL_PROTOCOL,
            "broker_channel": "hugosway_mt5",
            "channel_key_id": key_id,
            "execution_mode": EXECUTION_MODE_DEMO,
            "server": "Hugosway-Demo",
            "account_trade_mode": "DEMO",
            "connected": True,
            "observed_at": "2026-11-21T14:00:00Z",
            "snapshot_seq": "1",
            "account": {
                "login": "7001234", "currency": "USD", "balance": "10000", "equity": "10000",
                "margin": "0", "margin_free": "10000", "leverage": "500",
            },
            "ticks": [],
            "positions": [],
        }
        ref_empty_msg = "|".join([
            MT5_SPOOL_PROTOCOL, "hugosway_mt5", key_id, EXECUTION_MODE_DEMO, "Hugosway-Demo", "DEMO",
            "true", "2026-11-21T14:00:00Z", "1",
            "7001234", "USD", "10000", "10000", "0", "10000", "500",
            empty_sha, empty_sha,
        ])
        self.assertEqual(
            compute_mt5_market_snapshot_hmac(doc_empty, channel_key=key),
            hmac.new(key, ref_empty_msg.encode("utf-8"), sha256).hexdigest(),
        )

        doc_pop = json.loads(json.dumps(doc_empty))
        doc_pop["snapshot_seq"] = "2"
        doc_pop["ticks"] = [{"symbol": "EURUSD", "bid": "1.10000", "ask": "1.10010", "time_msc": "1795269600000"}]
        doc_pop["positions"] = [{
            "ticket": "500001", "symbol": "EURUSD", "side": "BUY", "volume": "0.10",
            "price_open": "1.10010", "sl": "1.09500", "tp": "0", "profit": "-1.00",
        }]
        ticks_sha = sha256(b"EURUSD:1.10000:1.10010:1795269600000").hexdigest()
        pos_sha = sha256(b"500001:EURUSD:BUY:0.10:1.10010:1.09500:0:-1.00").hexdigest()
        ref_pop_msg = "|".join([
            MT5_SPOOL_PROTOCOL, "hugosway_mt5", key_id, EXECUTION_MODE_DEMO, "Hugosway-Demo", "DEMO",
            "true", "2026-11-21T14:00:00Z", "2",
            "7001234", "USD", "10000", "10000", "0", "10000", "500",
            ticks_sha, pos_sha,
        ])
        self.assertEqual(
            compute_mt5_market_snapshot_hmac(doc_pop, channel_key=key),
            hmac.new(key, ref_pop_msg.encode("utf-8"), sha256).hexdigest(),
        )

    def test_finding_08_transport_rejects_unsigned_tampered_channel_login_rollback_and_stale(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool, server="Hugo demo PRO5", login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, balance=D("12000"), clock=clock,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            creds = Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugo demo PRO5")
            # Connect and idempotent reread at same (seq=1, mac)
            snap1 = tr.connect(creds)
            self.assertEqual(snap1.equity, D("12000"))
            self.assertEqual(tr.account_info().equity, D("12000"))
            self.assertEqual(tr.symbol_tick("EURUSD").ask, D("1.10010"))

            raw_doc = json.loads((spool / "market_ticks.json").read_text(encoding="utf-8"))

            # Unsigned doc rejected
            unsigned_doc = {k: v for k, v in raw_doc.items() if k != "snapshot_hmac_sha256"}
            (spool / "market_ticks.json").write_text(json.dumps(unsigned_doc), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            # Tampered equity without re-signing rejected
            tampered_doc = json.loads(json.dumps(raw_doc))
            tampered_doc["account"]["equity"] = "9999999.00"
            (spool / "market_ticks.json").write_text(json.dumps(tampered_doc), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            # Wrong channel key / broker_channel rejected
            master_key = bridge_mod._load_or_create_spool_hmac_key(spool)
            lhfx_key = derive_spool_channel_key(master_key, "lhfx_mt5")
            wrong_ch = sign_mt5_market_snapshot_doc(
                raw_doc, broker_channel="lhfx_mt5", channel_key=lhfx_key, snapshot_seq=2, observed_at=clock()
            )
            (spool / "market_ticks.json").write_text(json.dumps(wrong_ch), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            # Wrong execution_mode rejected
            bad_mode = json.loads(json.dumps(raw_doc))
            bad_mode["execution_mode"] = EXECUTION_MODE_LIVE
            bad_mode_signed = sign_mt5_market_snapshot_doc(bad_mode, spool_dir=spool, snapshot_seq=2, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(bad_mode_signed), encoding="utf-8")
            with self.assertRaises(LiveBrokerEndpointForbiddenError):
                tr.account_info()

            # Cross-login rejected
            bad_login = json.loads(json.dumps(raw_doc))
            bad_login["account"]["login"] = "9999999"
            bad_login_signed = sign_mt5_market_snapshot_doc(bad_login, spool_dir=spool, snapshot_seq=2, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(bad_login_signed), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            # Advance cleanly to seq=2, then reject same-seq equivocation AND rollback to seq=1 (even after transport restart)
            emu.balance = D("13000")
            emu.publish_market()
            self.assertEqual(tr.account_info().equity, D("13000"))

            equiv = json.loads(json.dumps(raw_doc))
            equiv["account"]["equity"] = "55555.00"
            equiv_signed = sign_mt5_market_snapshot_doc(equiv, spool_dir=spool, snapshot_seq=2, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(equiv_signed), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            (spool / "market_ticks.json").write_text(json.dumps(raw_doc), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()
            tr_restarted = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr_restarted.connect(creds)

            # Future observed_at rejected (> 5s)
            future_doc = sign_mt5_market_snapshot_doc(
                raw_doc, spool_dir=spool, snapshot_seq=3, observed_at=clock() + timedelta(seconds=10)
            )
            (spool / "market_ticks.json").write_text(json.dumps(future_doc), encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            # Valid seq=3 at clock() accepted, then stale observed_at (> 15s DEMO) & stale tick (> 60s DEMO) rejected
            fresh_doc = sign_mt5_market_snapshot_doc(raw_doc, spool_dir=spool, snapshot_seq=3, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(fresh_doc), encoding="utf-8")
            self.assertEqual(tr.account_info().equity, D("12000"))

            clock.advance(16)
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.account_info()

            # Fresh snapshot (seq=4) with stale tick (> 60_000ms) -> account_info ok, require_fresh_tick=True fails, False ok
            old_tick_doc = json.loads(json.dumps(raw_doc))
            old_tick_doc["ticks"] = [{
                "symbol": "EURUSD", "bid": "1.10000", "ask": "1.10010",
                "time_msc": str(int((clock() - timedelta(seconds=70)).timestamp() * 1000)),
            }]
            old_tick_signed = sign_mt5_market_snapshot_doc(
                old_tick_doc, spool_dir=spool, snapshot_seq=4, observed_at=clock()
            )
            (spool / "market_ticks.json").write_text(json.dumps(old_tick_signed), encoding="utf-8")
            tr.account_info()
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr.symbol_tick("EURUSD")
            self.assertEqual(tr.symbol_tick("EURUSD", require_fresh_tick=False).bid, D("1.10000"))

    def test_finding_08_dual_shield_router_refuses_tampered_and_stale_snapshots(self) -> None:
        clock = _MutableClock(T0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5", server="Hugo demo PRO5", login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, balance=D("12000"), clock=clock,
            )
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5", server="LHFXSA-Demo", login=8005678,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, balance=D("8000"), clock=clock,
            )
            emu_h.publish_market()
            emu_l.publish_market()
            gate = load_default_forex_valve_gate()
            oanda = _StubOandaTransport()
            env = {
                ENV_MT5_TRANSPORT_MODE: TRANSPORT_SPOOL_BRIDGE,
                ENV_MT5_SPOOL_DIR: str(root),
                ENV_HUGOSWAY_MT5_LOGIN: "7001234",
                ENV_HUGOSWAY_MT5_PASSWORD: _synth_val("hugo-pw"),
                ENV_HUGOSWAY_MT5_SERVER: "Hugo demo PRO5",
                ENV_LHFX_MT5_LOGIN: "8005678",
                ENV_LHFX_MT5_SERVER: "LHFXSA-Demo",
                ENV_OANDA_PRACTICE_TOKEN: _synth_val("oanda-tok"),
                ENV_OANDA_PRACTICE_ACCOUNT_ID: oanda.account_id,
            }
            emus = {BROKER_HUGOSWAY_MT5: emu_h, "LHFX_MT5": emu_l}
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=gate,
                peak_equity_store=gate.peak_equity_store,
                transport_factory=lambda bid, _m, r: Mt5SpoolBridgeTransport(
                    Path(r) / bid.lower(), sleep=emus[bid].sleep_hook, poll_interval_seconds=0.01, clock=clock
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient.from_runtime_env(e, transport=oanda, clock=clock),
                clock=clock,
            )
            router.activate_all()
            self.assertEqual(router.barbell.total_equity(router.equities()), D("100000.00"))
            self.assertEqual(gate.peak_equity_store.read_peak(router._drawdown_scope_id), D("100000.00"))

            # Tamper hugosway_mt5 market_ticks.json with huge equity & invalid HMAC -> peak equity unchanged & execute_open refuses
            hugo_path = root / "hugosway_mt5" / "market_ticks.json"
            doc = json.loads(hugo_path.read_text(encoding="utf-8"))
            doc["account"]["equity"] = "9999999.00"
            hugo_path.write_text(json.dumps(doc), encoding="utf-8")

            eq_after_tamper = router.equities(require_fresh_mt5=False)
            self.assertLess(router.barbell.total_equity(eq_after_tamper), D("1000000.00"))
            self.assertEqual(gate.peak_equity_store.read_peak(router._drawdown_scope_id), D("100000.00"))

            order = OrderIntent(
                order_id="f8-router-tamper-1",
                action_ref="act-f8-tamper-1",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec = _admit_order(gate, order, now=clock())
            with self.assertRaises(Mt5SnapshotIntegrityError):
                router.execute_open(order, valve_decision=dec)
            self.assertEqual(len(emu_h._positions), 0)
            self.assertEqual(len(emu_l._positions), 0)

            # Signed cross-login snapshot with inflated equity ALSO refuses & never inflates peak equity
            cross_doc = sign_mt5_market_snapshot_doc(
                {
                    **doc,
                    "account": {**doc["account"], "login": "9999999", "equity": "250000.00"},
                },
                spool_dir=hugo_path.parent,
                snapshot_seq=2,
                observed_at=clock(),
            )
            hugo_path.write_text(json.dumps(cross_doc), encoding="utf-8")
            _ = router.equities(require_fresh_mt5=False)
            self.assertEqual(gate.peak_equity_store.read_peak(router._drawdown_scope_id), D("100000.00"))
            order2 = OrderIntent(
                order_id="f8-router-cross-2",
                action_ref="act-f8-cross-2",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec2 = _admit_order(gate, order2, now=clock())
            with self.assertRaises(Mt5SnapshotIntegrityError):
                router.execute_open(order2, valve_decision=dec2)

            # Valid fresh snapshot after advancing clock + stale (> 15s DEMO) snapshot refuses
            emu_h.publish_market()
            clock.advance(16)
            _ = router.equities(require_fresh_mt5=False)
            self.assertEqual(gate.peak_equity_store.read_peak(router._drawdown_scope_id), D("100000.00"))
            order3 = OrderIntent(
                order_id="f8-router-stale-3",
                action_ref="act-f8-stale-3",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec3 = _admit_order(gate, order3, now=clock())
            with self.assertRaises(Mt5SnapshotIntegrityError):
                router.execute_open(order3, valve_decision=dec3)

    # ------------------------------------------------------------------
    # Finding [6]: Descriptor-relative O_NOFOLLOW LIVE key/ticket custody & inode binding
    # ------------------------------------------------------------------
    def test_finding_06_live_auth_ticket_no_chmod_no_nosec_and_custody_errors(self) -> None:
        src = LIVE_AUTH_PATH.read_text(encoding="utf-8")
        self.assertNotIn("os.chmod", src)
        self.assertNotIn("nosec B103", src)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kp = provision_live_auth_key(root / "live.key")
            self.assertTrue(kp.exists())
            orig_key = kp.read_bytes()
            self.assertEqual(provision_live_auth_key(kp), kp)
            self.assertEqual(kp.read_bytes(), orig_key)
            bad_kp = root / "bad.key"
            create_owner_only_file_atomic(
                bad_kp.parent, bad_kp.name, b"too-short", replace_existing=False, label="bad key"
            )
            with self.assertRaises(LiveAuthTicketError):
                provision_live_auth_key(bad_kp)

            tkt = mint_live_authorization_ticket(
                key_file=kp,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_login="9001122",
                server="Hugo PRO5",
                ttl_seconds=300,
                issued_at=T0,
            )
            tkt_path = root / "live_ticket.json"
            create_owner_only_file_atomic(
                tkt_path.parent, tkt_path.name, json.dumps(tkt).encode("utf-8"), replace_existing=True, label="ticket"
            )

            # Permissive / custody failure from state_store wraps cleanly as LiveAuthTicketError
            from cas_forex_revamp.composition import state_store as state_store_mod

            with mock.patch.object(
                state_store_mod, "verify_and_read_owner_only_file", side_effect=ContractError("unsafe mode 0o644")
            ):
                with self.assertRaises(LiveAuthTicketError):
                    verify_live_authorization_context(
                        tkt, key_file=kp, expected_broker_id=BROKER_HUGOSWAY_MT5,
                        expected_account_login="9001122", expected_server="Hugo PRO5", now=T0,
                    )
                with self.assertRaises(LiveAuthTicketError):
                    verify_live_environ_authorization_context(
                        {
                            ENV_EXECUTION_MODE: EXECUTION_MODE_LIVE,
                            ENV_LIVE_ARM_PHRASE: REQUIRED_LIVE_ARM_PHRASE,
                            ENV_LIVE_AUTH_KEY_FILE: str(kp),
                            ENV_LIVE_AUTH_TICKET_FILE: str(tkt_path),
                        },
                        expected_broker_id=BROKER_HUGOSWAY_MT5,
                        expected_account_login="9001122",
                        expected_server="Hugo PRO5",
                        now=T0,
                    )

            # POSIX symlink test when host OS allows symlink creation
            sym_path = root / "sym_live.key"
            try:
                os.symlink(kp, sym_path)
            except (OSError, NotImplementedError):
                pass
            else:
                with self.assertRaises(LiveAuthTicketError):
                    verify_live_authorization_context(
                        tkt, key_file=sym_path, expected_broker_id=BROKER_HUGOSWAY_MT5,
                        expected_account_login="9001122", expected_server="Hugo PRO5", now=T0,
                    )

    def test_finding_06_identity_binding_and_post_init_file_swap_refused_at_sinks(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            kp = provision_live_auth_key(root / "live.key")
            key_bytes = kp.read_bytes()
            tkt = mint_live_authorization_ticket(
                key_file=kp,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_login="9001122",
                server="Hugo PRO5",
                ttl_seconds=300,
                issued_at=T0,
            )
            tkt_path = root / "live_ticket.json"
            create_owner_only_file_atomic(
                tkt_path.parent, tkt_path.name, json.dumps(tkt).encode("utf-8"), replace_existing=True, label="ticket"
            )
            _, ctx = verify_live_authorization_context(
                tkt,
                key_file=kp,
                ticket_file=tkt_path,
                expected_broker_id=BROKER_HUGOSWAY_MT5,
                expected_account_login="9001122",
                expected_server="Hugo PRO5",
                live_arm_phrase=LIVE_ARM_CONFIRMATION_TEXT,
                require_arm_phrase=True,
                now=T0,
            )
            self.assertIsNotNone(ctx.key_file_identity)
            self.assertIsNotNone(ctx.ticket_file_identity)
            ctx.verify_provenance(now=T0, reverify_ticket=True, require_arm_phrase=True)

            # Native transport accepts valid identity-bound context before swap, refuses after key/ticket inode swap
            sdk = _NativeSdkFake(login=9001122, server="Hugo PRO5", trade_mode=2)
            native = Mt5NativePythonTransport(mt5_module=sdk, clock=lambda: T0)
            creds = Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5,
                login=9001122,
                server="Hugo PRO5",
                password=_RedactedSecret(_synth_val("mt5-live")),
                execution_mode=EXECUTION_MODE_LIVE,
                live_auth_context=ctx,
            )
            native.connect(creds)

            # Replace ticket file with identical bytes via atomic new inode creation
            tkt_alt = root / "live_ticket_alt.json"
            create_owner_only_file_atomic(
                tkt_alt.parent, tkt_alt.name, json.dumps(tkt).encode("utf-8"), replace_existing=True, label="ticket alt"
            )
            tkt_path.unlink()
            tkt_alt.rename(tkt_path)
            # Even with identical ticket bytes, if inode changed (standard on POSIX/NTFS rename of new file) it must fail closed
            new_st = os.stat(tkt_path)
            if (int(new_st.st_dev), int(new_st.st_ino)) != ctx.ticket_file_identity:
                with self.assertRaises(LiveAuthorizationError):
                    ctx.verify_provenance(now=T0, reverify_ticket=True)
                with self.assertRaises(LiveAuthorizationError):
                    ctx.assert_valid_at(T0, reverify_ticket=True)
                order = OrderIntent(
                    order_id="f6-swap-tkt-1",
                    action_ref="act-f6-swap-tkt-1",
                    kind=ActionKind.OPEN,
                    symbol="EURUSD",
                    quantity_units=D("10000"),
                    side=Side.BUY,
                    stop_price=D("1.09500"),
                    limit_price=D("1.10010"),
                )
                dec = _admit_order(gate, order, now=T0)
                grant = gate.issue_order_grant(
                    dec,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_id="9001122",
                    server="Hugo PRO5",
                    execution_mode=EXECUTION_MODE_LIVE,
                    action_kind="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=D("0.10"),
                    stop_loss=D("1.09500"),
                    order_action_ref=order.action_ref,
                    order_quantity_units=order.quantity_units,
                    order_limit_price=order.limit_price,
                    now=T0,
                )
                req = Mt5OrderRequest(
                    request_id="f6-swap-tkt-1",
                    action="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume_lots=D("0.10"),
                    price=D("1.10010"),
                    stop_loss=D("1.09500"),
                    position_ticket=None,
                    deviation_points=20,
                    magic=20261121,
                    comment="f6",
                    created_at=T0,
                )
                with self.assertRaises(LiveAuthorizationError):
                    native.send_order(req, valve_grant=grant)
                self.assertEqual(sdk.order_send_calls, 0)

            # Unlink key file & recreate even if key bytes differ/match -> fails closed before dispatch
            kp.unlink()
            with self.assertRaises(LiveAuthTicketError):
                ctx.verify_provenance(now=T0, reverify_ticket=True)
            kp_new = root / "live_new.key"
            create_owner_only_file_atomic(kp_new.parent, kp_new.name, key_bytes, replace_existing=True, label="key new")
            kp_new.rename(kp)
            with self.assertRaises(LiveAuthorizationError):
                ctx.assert_valid_at(T0, reverify_ticket=True)

    # ------------------------------------------------------------------
    # Finding [13]: Expiry-indexed bounded Valve replay ledgers
    # ------------------------------------------------------------------
    def test_finding_13_valve_replay_ledgers_prune_after_expiry_and_fail_closed_when_saturated(self) -> None:
        gate = load_default_forex_valve_gate()
        self.assertEqual(MAX_VALVE_REPLAY_LEDGER_ENTRIES, 16384)
        self.assertIs(type(valve_mod._CONSUMED_GRANT_NONCES), dict)
        self.assertIs(type(valve_mod._CONSUMED_DECISION_TARGETS), dict)
        self.assertIs(type(valve_mod._ISSUED_UNCONSUMED_GRANTS), dict)

        with valve_mod._GRANT_LEDGER_LOCK:
            saved_issued = dict(valve_mod._ISSUED_UNCONSUMED_GRANTS)
            saved_consumed = dict(valve_mod._CONSUMED_GRANT_NONCES)
            saved_decisions = dict(valve_mod._CONSUMED_DECISION_TARGETS)
            valve_mod._ISSUED_UNCONSUMED_GRANTS.clear()
            valve_mod._CONSUMED_GRANT_NONCES.clear()
            valve_mod._CONSUMED_DECISION_TARGETS.clear()
        try:
            # 1. Pre-expiry replay still refused for grant nonce and decision target
            ord1 = OrderIntent(
                order_id="f13-ord-1",
                action_ref="act-f13-1",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec1 = _admit_order(gate, ord1, now=T0)
            g1 = gate.issue_order_grant(
                dec1,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                order_action_ref=ord1.action_ref,
                order_quantity_units=ord1.quantity_units,
                order_limit_price=ord1.limit_price,
                ttl_seconds=60,
                now=T0,
            )
            with self.assertRaises(ValveGrantError):
                gate.issue_order_grant(
                    dec1,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_id="7001234",
                    server="Hugo demo PRO5",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=D("0.10"),
                    stop_loss=D("1.09500"),
                    order_action_ref=ord1.action_ref,
                    order_quantity_units=ord1.quantity_units,
                    order_limit_price=ord1.limit_price,
                    ttl_seconds=60,
                    now=T0 + timedelta(seconds=5),
                )
            verify_and_consume_valve_order_grant(
                g1,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                now=T0 + timedelta(seconds=5),
            )
            with self.assertRaises(ValveGrantError):
                verify_and_consume_valve_order_grant(
                    g1,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_id="7001234",
                    server="Hugo demo PRO5",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=D("0.10"),
                    stop_loss=D("1.09500"),
                    now=T0 + timedelta(seconds=10),
                )

            # 2. Advancing past expiry + skew automatically prunes expired entries from all three ledgers
            t_future = T0 + timedelta(minutes=15)
            ord2 = OrderIntent(
                order_id="f13-ord-2",
                action_ref="act-f13-2",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec2 = _admit_order(gate, ord2, now=t_future)
            g2 = gate.issue_order_grant(
                dec2,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_id="7001234",
                server="Hugo demo PRO5",
                execution_mode=EXECUTION_MODE_DEMO,
                action_kind="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume=D("0.10"),
                stop_loss=D("1.09500"),
                order_action_ref=ord2.action_ref,
                order_quantity_units=ord2.quantity_units,
                order_limit_price=ord2.limit_price,
                ttl_seconds=60,
                now=t_future,
            )
            with valve_mod._GRANT_LEDGER_LOCK:
                self.assertEqual(len(valve_mod._CONSUMED_GRANT_NONCES), 0)
                self.assertEqual(len(valve_mod._CONSUMED_DECISION_TARGETS), 1)
                self.assertEqual(len(valve_mod._ISSUED_UNCONSUMED_GRANTS), 1)

            # 3. Hard capacity cap (16384 unexpired entries) fails closed cleanly without eviction
            unexpired_until = t_future + timedelta(minutes=10)
            with valve_mod._GRANT_LEDGER_LOCK:
                valve_mod._CONSUMED_GRANT_NONCES.clear()
                for idx in range(MAX_VALVE_REPLAY_LEDGER_ENTRIES):
                    valve_mod._CONSUMED_GRANT_NONCES[f"sat-{idx}"] = unexpired_until
            with self.assertRaises(ValveGrantError):
                verify_and_consume_valve_order_grant(
                    g2,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_id="7001234",
                    server="Hugo demo PRO5",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=D("0.10"),
                    stop_loss=D("1.09500"),
                    now=t_future + timedelta(seconds=1),
                )
            with valve_mod._GRANT_LEDGER_LOCK:
                self.assertEqual(len(valve_mod._CONSUMED_GRANT_NONCES), MAX_VALVE_REPLAY_LEDGER_ENTRIES)
                valve_mod._CONSUMED_GRANT_NONCES.clear()
                for idx in range(MAX_VALVE_REPLAY_LEDGER_ENTRIES):
                    valve_mod._ISSUED_UNCONSUMED_GRANTS[f"iss-{idx}"] = ("d" * 64, unexpired_until)

            ord3 = OrderIntent(
                order_id="f13-ord-3",
                action_ref="act-f13-3",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                limit_price=D("1.10010"),
            )
            dec3 = _admit_order(gate, ord3, now=t_future)
            with self.assertRaises(ValveGrantError):
                gate.issue_order_grant(
                    dec3,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_id="7001234",
                    server="Hugo demo PRO5",
                    execution_mode=EXECUTION_MODE_DEMO,
                    action_kind="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume=D("0.10"),
                    stop_loss=D("1.09500"),
                    order_action_ref=ord3.action_ref,
                    order_quantity_units=ord3.quantity_units,
                    order_limit_price=ord3.limit_price,
                    ttl_seconds=60,
                    now=t_future,
                )
        finally:
            with valve_mod._GRANT_LEDGER_LOCK:
                valve_mod._ISSUED_UNCONSUMED_GRANTS.clear()
                valve_mod._ISSUED_UNCONSUMED_GRANTS.update(saved_issued)
                valve_mod._CONSUMED_GRANT_NONCES.clear()
                valve_mod._CONSUMED_GRANT_NONCES.update(saved_consumed)
                valve_mod._CONSUMED_DECISION_TARGETS.clear()
                valve_mod._CONSUMED_DECISION_TARGETS.update(saved_decisions)


if __name__ == "__main__":
    unittest.main()
