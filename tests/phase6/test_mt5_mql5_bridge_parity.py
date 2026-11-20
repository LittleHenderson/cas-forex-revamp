"""Milestone M1 static & contract parity suite between mt5/CasForexMt5Bridge.mq5
and src/cas_forex_revamp/venue/mt5_broker_bridge.py + live_auth_ticket.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import unittest

from cas_forex_revamp.contracts import ActionKind, ContractError, Side, canonical_bytes
from cas_forex_revamp.valve.tks_meta_valve_controller import ValveDecision, load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    LiveBrokerEndpointForbiddenError,
    OandaPracticePaperClient,
    REQUIRED_LIVE_ARM_PHRASE,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    LIVE_AUTH_PROTOCOL,
    LiveAuthTicketError,
    _canonical_ticket_message,
    mint_live_authorization_ticket,
    provision_live_auth_key,
    verify_live_authorization_ticket,
)
from cas_forex_revamp.venue.live_market_stream import (
    EXPANDED_FX_PAIRS,
    EXPANDED_MARKETS,
    INDEX_INSTRUMENTS,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    MT5_MAX_VOLUME_DEFAULT,
    MT5_SPOOL_PROTOCOL,
    _DEFAULT_LIVE_MT5_SERVERS,
    _INDEX_SYMBOL_ALIASES,
    _PINNED_LIVE_MT5_SERVERS,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5OrderRequest,
    Mt5OutcomeUnknownError,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5TransportError,
    OrderIntent,
    _SpoolReplayLedger,
    _canonical_spool_receipt_hmac_input,
    _canonical_spool_request_hmac_input,
    _spool_hmac_hex,
    _status_for_retcode,
    normalize_market_symbol,
    validate_demo_server,
    validate_mt5_server_name,
)

D = Decimal
T0 = datetime(2026, 11, 18, 13, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]
MQ5_PATH = REPO_ROOT / "mt5" / "CasForexMt5Bridge.mq5"


DEFAULT_VALVE_GATE = load_default_forex_valve_gate()


def _clear_valve(order: OrderIntent) -> ValveDecision:
    return ValveDecision(
        admitted=True,
        valve_mode="ADMIT",
        mlp_score=0.91,
        threshold=0.55,
        mlp_admitted=True,
        hard_veto=False,
        hard_veto_reasons=(),
        features={},
        weights_sha256=DEFAULT_VALVE_GATE.controller.weights_sha256(),
        request_id=order.order_id,
        selected_action_ref=order.action_ref,
    )


def _extract_mql5_function(source: str, signature_prefix: str) -> str:
    idx = source.index(signature_prefix)
    brace_start = source.index("{", idx)
    depth = 0
    for pos in range(brace_start, len(source)):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[idx : pos + 1]
    raise AssertionError(f"Unclosed MQL5 block for {signature_prefix}")


class Mt5Mql5BridgeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mq5 = MQ5_PATH.read_text(encoding="utf-8")

    def test_all_20_symbol_mappings_and_aliases_parity(self) -> None:
        # 1. Exact 20-element InpSymbols list in identical order to EXPANDED_MARKETS
        m_inp = re.search(r'input\s+string\s+InpSymbols\s*=\s*"([^"]+)";', self.mq5)
        self.assertIsNotNone(m_inp)
        mq5_symbols = [s.strip() for s in m_inp.group(1).split(",") if s.strip()]
        self.assertEqual(len(mq5_symbols), 20)
        self.assertEqual(mq5_symbols, list(EXPANDED_MARKETS))
        self.assertEqual(len(INDEX_INSTRUMENTS), 4)
        self.assertEqual(len(EXPANDED_FX_PAIRS), 16)

        # 2. PublishCandles idx_syms[4] == INDEX_INSTRUMENTS
        pub_fn = _extract_mql5_function(self.mq5, "void PublishCandles()")
        m_idx = re.search(r'string\s+idx_syms\[4\]\s*=\s*\{([^}]+)\};', pub_fn)
        self.assertIsNotNone(m_idx)
        idx_syms = re.findall(r'"([^"]+)"', m_idx.group(1))
        self.assertEqual(idx_syms, list(INDEX_INSTRUMENTS))

        # 3. BrokerSymbol & CasSymbol index/gold aliases + full 20x15 suffix stripping parity
        broker_fn = _extract_mql5_function(self.mq5, "string BrokerSymbol(")
        for idx_sym in INDEX_INSTRUMENTS:
            self.assertIn(f'cas_symbol == "{idx_sym}"', broker_fn)
        self.assertIn("return(cas_symbol + InpSymbolSuffix);", broker_fn)

        cas_fn = _extract_mql5_function(self.mq5, "string CasSymbol(")
        expected_aliases_by_canonical = {
            "NAS100": ("NAS100", "USTEC", "US100", "NAS100USD"),
            "US30": ("US30", "DJ30", "WS30", "US30USD"),
            "SPX500": ("SPX500", "US500", "SP500", "SPX500USD", "US500.247"),
            "XAUUSD": ("XAUUSD", "GOLD", "XAU_USD", "GOLD.247"),
        }
        all_suffixes = (
            "", ".ECN", ".ecn", ".PRO", ".pro", ".RAW", ".raw",
            ".CASH", ".cash", "_I", "_i", ".I", ".i", ".M", ".m",
        )
        for canonical, aliases in expected_aliases_by_canonical.items():
            for alias in aliases:
                if alias != canonical:
                    self.assertIn(f'broker_symbol == "{alias}"', cas_fn)
                self.assertEqual(normalize_market_symbol(alias), canonical)
                for suffix in all_suffixes:
                    self.assertEqual(normalize_market_symbol(f"{alias}{suffix}"), canonical)

        for alias_key, canonical in _INDEX_SYMBOL_ALIASES.items():
            self.assertEqual(normalize_market_symbol(alias_key), canonical)

        for sym in EXPANDED_MARKETS:
            for suffix in all_suffixes:
                self.assertEqual(normalize_market_symbol(f"{sym}{suffix}"), sym)

        with self.assertRaises(ContractError):
            normalize_market_symbol("UNKNOWNPAIR")

    def test_21_field_request_and_16_field_receipt_hmac_canonical_order_and_core_sha256(self) -> None:
        # 1. Verify MQL5 ExecuteRequest 21-field hmac_msg (41 '+'-tokens interleaved with "|")
        exec_fn = _extract_mql5_function(self.mq5, "void ExecuteRequest(")
        self.assertIn('string nonce_s = JsonGet(text, "monotonic_nonce");', exec_fn)
        m_hmac = re.search(r"string\s+hmac_msg\s*=\s*(.*?);", exec_fn, flags=re.DOTALL)
        self.assertIsNotNone(m_hmac)
        raw_req_tokens = [tok.strip() for tok in m_hmac.group(1).split("+")]
        self.assertEqual(len(raw_req_tokens), 41)
        self.assertTrue(all(tok == '"|"' for tok in raw_req_tokens[1::2]))
        mq5_req_fields = []
        for tok in raw_req_tokens[0::2]:
            if tok == "nonce_s":
                mq5_req_fields.append("monotonic_nonce")
            else:
                m_get = re.fullmatch(r'JsonGet\(text,\s*"([a-z0-9_]+)"\)', tok)
                self.assertIsNotNone(m_get, f"Unexpected ExecuteRequest HMAC token: {tok!r}")
                mq5_req_fields.append(m_get.group(1))
        expected_req_fields = [
            "protocol", "request_id", "monotonic_nonce", "issued_at", "expires_at",
            "broker_channel", "account_login", "server", "execution_mode", "valve_decision_sha256",
            "action", "symbol", "side", "volume", "price", "sl", "tp",
            "position_ticket", "deviation_points", "magic", "comment",
        ]
        self.assertEqual(len(mq5_req_fields), 21)
        self.assertEqual(mq5_req_fields, expected_req_fields)

        req_probe = {field: f"v_{idx}" for idx, field in enumerate(expected_req_fields)}
        self.assertEqual(
            _canonical_spool_request_hmac_input(req_probe),
            "|".join(req_probe[f] for f in mq5_req_fields),
        )

        # 2. Verify MQL5 ReceiptJson 16-field HMAC order (31 '+'-tokens) via StringFormat variable-to-JSON map
        rcpt_fn = _extract_mql5_function(self.mq5, "string ReceiptJson(")
        m_rcpt_can = re.search(r"string\s+canonical\s*=\s*(.*?);", rcpt_fn, flags=re.DOTALL)
        self.assertIsNotNone(m_rcpt_can)
        raw_rcpt_tokens = [tok.strip() for tok in m_rcpt_can.group(1).split("+")]
        self.assertEqual(len(raw_rcpt_tokens), 31)
        self.assertTrue(all(tok == '"|"' for tok in raw_rcpt_tokens[1::2]))
        mq5_rcpt_vars = raw_rcpt_tokens[0::2]
        self.assertEqual(
            mq5_rcpt_vars,
            [
                "SPOOL_PROTOCOL", "request_id", "request_sha", "nonce_str",
                "status", "ret_str", "position_ticket", "deal_ticket",
                "volume", "price", "sl", "tp",
                "trade_mode", "server", "obs_at", "safe_msg",
            ],
        )

        m_sf = re.search(r"StringFormat\((.*?)\)\);", rcpt_fn, flags=re.DOTALL)
        self.assertIsNotNone(m_sf)
        sf_body = m_sf.group(1)
        json_keys_in_sf = re.findall(r'\\"([a-z0-9_]+)\\":\\"%s\\"', sf_body)
        last_quote = sf_body.rfind('"')
        self.assertGreater(last_quote, 0)
        sf_args = [a.strip() for a in sf_body[last_quote + 1 :].lstrip(" ,").split(",") if a.strip()]
        self.assertEqual(len(json_keys_in_sf), 17)
        self.assertEqual(len(sf_args), 17)
        var_to_json_key = dict(zip(sf_args, json_keys_in_sf))
        self.assertEqual(var_to_json_key["mac_hex"], "receipt_hmac_sha256")
        self.assertEqual(
            json_keys_in_sf,
            [
                "protocol", "request_id", "request_sha256", "monotonic_nonce",
                "status", "retcode", "position_ticket", "deal_ticket",
                "volume", "price", "sl", "tp",
                "server", "account_trade_mode", "observed_at", "message",
                "receipt_hmac_sha256",
            ],
        )

        expected_rcpt_fields = [
            "protocol", "request_id", "request_sha256", "monotonic_nonce",
            "status", "retcode", "position_ticket", "deal_ticket",
            "volume", "price", "sl", "tp",
            "account_trade_mode", "server", "observed_at", "message",
        ]
        self.assertEqual([var_to_json_key[v] for v in mq5_rcpt_vars], expected_rcpt_fields)
        rcpt_probe = {f: f"r_{i}" for i, f in enumerate(expected_rcpt_fields)}
        self.assertEqual(
            _canonical_spool_receipt_hmac_input(rcpt_probe),
            "|".join(rcpt_probe[f] for f in expected_rcpt_fields),
        )

        # 3. Verify VerifyLiveTicketGuard 8-field HMAC (15 '+'-tokens interleaved with "|")
        ticket_fn = _extract_mql5_function(self.mq5, "bool VerifyLiveTicketGuard(")
        m_tkt_can = re.search(r"string\s+canonical\s*=\s*(.*?);", ticket_fn, flags=re.DOTALL)
        self.assertIsNotNone(m_tkt_can)
        raw_tkt_tokens = [tok.strip() for tok in m_tkt_can.group(1).split("+")]
        self.assertEqual(len(raw_tkt_tokens), 15)
        self.assertTrue(all(tok == '"|"' for tok in raw_tkt_tokens[1::2]))
        tkt_fields = []
        for tok in raw_tkt_tokens[0::2]:
            m_tkt = re.fullmatch(r'JsonGet\(ticket_json,\s*"([a-z0-9_]+)"\)', tok)
            self.assertIsNotNone(m_tkt, f"Unexpected VerifyLiveTicketGuard token: {tok!r}")
            tkt_fields.append(m_tkt.group(1))
        expected_tkt_fields = [
            "protocol", "execution_mode", "broker_id", "account_login",
            "server", "issued_at_utc", "expires_at_utc", "nonce",
        ]
        self.assertEqual(tkt_fields, expected_tkt_fields)
        tkt_probe = {f: f"t_{i}" for i, f in enumerate(expected_tkt_fields)}
        self.assertEqual(
            _canonical_ticket_message(tkt_probe),
            "|".join(tkt_probe[f] for f in tkt_fields),
        )

        # 4. End-to-end 22-field core SHA-256 MQL5 substring stripping & signed receipt round-trip
        order_req = Mt5OrderRequest(
            request_id="req-parity-1",
            action="OPEN",
            symbol="EURUSD",
            side=Side.BUY,
            volume_lots=D("0.10"),
            price=D("1.10010"),
            stop_loss=D("1.09500"),
            take_profit=D("1.11000"),
            position_ticket=None,
            deviation_points=20,
            magic=20261116,
            comment="cas-parity",
            created_at=T0,
            monotonic_nonce=1,
            issued_at=T0,
            expires_at=T0 + timedelta(seconds=30),
            broker_channel="hugosway_mt5",
            account_login="7001234",
            server="Hugosway-Demo",
            execution_mode=EXECUTION_MODE_DEMO,
            valve_decision_sha256="a" * 64,
        )
        key_bytes = secrets.token_bytes(32)
        spool_doc = order_req.to_spool_dict()
        self.assertEqual(len(spool_doc), 23)  # 22 core fields + request_sha256
        spool_doc["request_hmac_sha256"] = _spool_hmac_hex(key_bytes, _canonical_spool_request_hmac_input(spool_doc))
        self.assertEqual(len(spool_doc), 24)  # + request_hmac_sha256
        wire_text = canonical_bytes(spool_doc).decode("utf-8")
        # Mirror MQL5 ExecuteRequest lines 487-490 exactly
        stripped = wire_text.replace(f',"request_sha256":"{spool_doc["request_sha256"]}"', "")
        stripped = stripped.replace(f',"request_hmac_sha256":"{spool_doc["request_hmac_sha256"]}"', "")
        self.assertEqual(sha256(stripped.encode("utf-8")).hexdigest(), spool_doc["request_sha256"])

        with tempfile.TemporaryDirectory() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir, server="Hugosway-Demo", login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, clock=lambda: T0,
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir, sleep=emu.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2.0
            )
            transport.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            receipt = transport.send_order(order_req)
            self.assertTrue(receipt.accepted)
            self.assertEqual(receipt.status, "FILLED")

    def test_mode_guard_and_live_ticket_server_allowlist_parity(self) -> None:
        m_phrase = re.search(r'#define\s+LIVE_ARM_PHRASE\s+"([^"]+)"', self.mq5)
        self.assertIsNotNone(m_phrase)
        self.assertEqual(m_phrase.group(1), REQUIRED_LIVE_ARM_PHRASE)

        pinned_fn = _extract_mql5_function(self.mq5, "bool IsPinnedLiveServer(")
        m_hugo_pin = re.search(r'InpBrokerChannel\s*==\s*"hugosway_mt5"\)\s*return\(([^;]+)\);', pinned_fn, flags=re.DOTALL)
        m_lhfx_pin = re.search(r'InpBrokerChannel\s*==\s*"lhfx_mt5"\)\s*return\(([^;]+)\);', pinned_fn, flags=re.DOTALL)
        self.assertIsNotNone(m_hugo_pin)
        self.assertIsNotNone(m_lhfx_pin)
        mq5_hugo = frozenset(re.findall(r'server\s*==\s*"([^"]+)"', m_hugo_pin.group(1)))
        mq5_lhfx = frozenset(re.findall(r'server\s*==\s*"([^"]+)"', m_lhfx_pin.group(1)))
        py_hugo = _PINNED_LIVE_MT5_SERVERS[BROKER_HUGOSWAY_MT5]
        py_lhfx = _PINNED_LIVE_MT5_SERVERS[BROKER_LHFX_MT5]

        # Exact MQL5 <-> Python LIVE server allowlist parity (6 Hugo + 6 LHFX aliases)
        self.assertEqual(mq5_hugo, py_hugo)
        self.assertEqual(mq5_lhfx, py_lhfx)
        self.assertIn(_DEFAULT_LIVE_MT5_SERVERS[BROKER_HUGOSWAY_MT5].lower(), mq5_hugo)
        self.assertIn(_DEFAULT_LIVE_MT5_SERVERS[BROKER_LHFX_MT5].lower(), mq5_lhfx)

        # Shared canonical LIVE servers pass both MQL5 and Python LIVE validator; cross-channel servers are rejected
        for broker_id, server, channel_set in (
            (BROKER_HUGOSWAY_MT5, "Hugo PRO5", mq5_hugo),
            (BROKER_HUGOSWAY_MT5, "Hugosway-Live", mq5_hugo),
            (BROKER_LHFX_MT5, "LHFXSA-Trade", mq5_lhfx),
            (BROKER_LHFX_MT5, "LHFXSA-Live", mq5_lhfx),
        ):
            self.assertIn(server.lower(), channel_set)
            self.assertEqual(
                validate_mt5_server_name(broker_id, server, execution_mode=EXECUTION_MODE_LIVE, live_armed=True),
                server,
            )

        with self.assertRaises(ContractError):
            validate_mt5_server_name(BROKER_LHFX_MT5, "Hugo PRO5", execution_mode=EXECUTION_MODE_LIVE, live_armed=True)
        with self.assertRaises(ContractError):
            validate_mt5_server_name(BROKER_HUGOSWAY_MT5, "LHFXSA-Live", execution_mode=EXECUTION_MODE_LIVE, live_armed=True)

        # Shared DEMO servers pass validate_demo_server, and LIVE / cross-channel / non-demo servers are rejected
        for broker_id, demo_srv in (
            (BROKER_HUGOSWAY_MT5, "Hugosway-Demo"),
            (BROKER_HUGOSWAY_MT5, "Hugo demo PRO5"),
            (BROKER_LHFX_MT5, "LHFXSA-Demo"),
            (BROKER_LHFX_MT5, "LHFXSA-Trade"),
        ):
            self.assertEqual(validate_demo_server(broker_id, demo_srv), demo_srv)

        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_HUGOSWAY_MT5, "Hugo PRO5")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_HUGOSWAY_MT5, "LHFXSA-Trade")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_HUGOSWAY_MT5, "Hugosway-Real")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_HUGOSWAY_MT5, "Hugosway-Trial")
        with self.assertRaises(ContractError):
            validate_mt5_server_name(BROKER_HUGOSWAY_MT5, "Hugosway-Demo", execution_mode=EXECUTION_MODE_LIVE, live_armed=True)
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_mt5_server_name(BROKER_HUGOSWAY_MT5, "Hugo PRO5", execution_mode=EXECUTION_MODE_LIVE, live_armed=False)

        mode_guard_fn = _extract_mql5_function(self.mq5, "bool ModeGuard(")
        for token in ("ACCOUNT_TRADE_MODE_DEMO", "ACCOUNT_TRADE_MODE_REAL", "IsPinnedLiveServer(server)", "VerifyLiveTicketGuard(server)"):
            self.assertIn(token, mode_guard_fn)

        # Live ticket binding parity (cas-forex-live-auth/1)
        self.assertIn(f'"{LIVE_AUTH_PROTOCOL}"', self.mq5)
        with tempfile.TemporaryDirectory() as td:
            key_file = Path(td) / ".live_auth.key"
            provision_live_auth_key(key_file)
            ticket = mint_live_authorization_ticket(
                key_file=key_file,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_login=7009999,
                server="Hugo PRO5",
                ttl_seconds=600,
                issued_at=T0,
            )
            verified = verify_live_authorization_ticket(
                ticket,
                key_file=key_file,
                expected_broker_id=BROKER_HUGOSWAY_MT5,
                expected_account_login=7009999,
                expected_server="Hugo PRO5",
                now=T0 + timedelta(seconds=10),
            )
            self.assertEqual(verified["broker_id"], BROKER_HUGOSWAY_MT5)
            with self.assertRaises(LiveAuthTicketError):
                verify_live_authorization_ticket(
                    ticket,
                    key_file=key_file,
                    expected_broker_id=BROKER_LHFX_MT5,
                    expected_account_login=7009999,
                    expected_server="Hugo PRO5",
                    now=T0 + timedelta(seconds=10),
                )
            with self.assertRaises(LiveAuthTicketError):
                verify_live_authorization_ticket(
                    ticket,
                    key_file=key_file,
                    expected_broker_id=BROKER_HUGOSWAY_MT5,
                    expected_account_login=7009999,
                    expected_server="Hugo PRO5",
                    now=T0 + timedelta(seconds=601),
                )

    def test_replay_nonce_ledger_monotonicity_and_ttl_parity(self) -> None:
        # Static MQL5 replay/TTL/interrupted-request assertions
        self.assertIn('.ea_nonce.txt', self.mq5)
        self.assertIn("req_nonce == 0 || req_nonce <= g_last_monotonic_nonce || exp_dt == 0 || TimeGMT() > exp_dt", self.mq5)
        interrupted_fn = _extract_mql5_function(self.mq5, "void ReportInterruptedRequests()")
        self.assertIn('"UNKNOWN"', interrupted_fn)
        self.assertIn("(uint)0", interrupted_fn)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ledger = _SpoolReplayLedger(root / ".replay.json")
            for idx in range(1, 520):
                ledger.verify_and_record(request_id=f"req-{idx}", nonce=idx)
            last_n, seen = ledger.load()
            self.assertEqual(last_n, 519)
            self.assertEqual(len(seen), 512)
            self.assertNotIn("req-1", seen)
            self.assertIn("req-519", seen)

            # Stale / equal / zero nonce rejected
            for bad_nonce in (0, 519, 100):
                with self.assertRaises(Mt5TransportError):
                    ledger.verify_and_record(request_id="req-fresh-id", nonce=bad_nonce)
            # Duplicate request_id rejected even with higher nonce
            with self.assertRaises(Mt5TransportError):
                ledger.verify_and_record(request_id="req-519", nonce=520)

            # Emulator rejects expired TTL & replayed nonce with retcode 10013
            spool_dir = root / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir, server="Hugosway-Demo", login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))}, clock=lambda: T0,
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir, sleep=emu.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=1.0
            )
            transport.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            expired_req = Mt5OrderRequest(
                request_id="req-expired-1",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                take_profit=None,
                position_ticket=None,
                deviation_points=20,
                magic=20261116,
                comment="cas-ttl",
                created_at=T0 - timedelta(minutes=2),
                monotonic_nonce=1,
                issued_at=T0 - timedelta(minutes=2),
                expires_at=T0 - timedelta(seconds=5),
                broker_channel="hugosway_mt5",
                account_login="7001234",
                server="Hugosway-Demo",
                execution_mode=EXECUTION_MODE_DEMO,
                valve_decision_sha256="b" * 64,
            )
            rcpt_exp = transport.send_order(expired_req)
            self.assertFalse(rcpt_exp.accepted)
            self.assertEqual(rcpt_exp.retcode, 10013)
            self.assertEqual(rcpt_exp.status, "REJECTED")

            # Timeout / interrupted request triggers fail-closed Mt5OutcomeUnknownError (no retry)
            no_reply_transport = Mt5SpoolBridgeTransport(
                spool_dir, sleep=lambda _s: None, poll_interval_seconds=0.005, receipt_timeout_seconds=0.01
            )
            no_reply_transport.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            timeout_req = Mt5OrderRequest(
                request_id="req-timeout-1",
                action="OPEN",
                symbol="EURUSD",
                side=Side.BUY,
                volume_lots=D("0.10"),
                price=D("1.10010"),
                stop_loss=D("1.09500"),
                take_profit=None,
                position_ticket=None,
                deviation_points=20,
                magic=20261116,
                comment="cas-timeout",
                created_at=T0,
                monotonic_nonce=2,
                issued_at=T0,
                expires_at=T0 + timedelta(seconds=30),
                broker_channel="hugosway_mt5",
                account_login="7001234",
                server="Hugosway-Demo",
                execution_mode=EXECUTION_MODE_DEMO,
                valve_decision_sha256="c" * 64,
            )
            with self.assertRaises(Mt5OutcomeUnknownError):
                no_reply_transport.send_order(timeout_req)

    def test_execute_request_rejection_codes_and_python_interpretation(self) -> None:
        m_max_vol = re.search(r"input\s+double\s+InpMaxVolumeLots\s*=\s*([0-9.]+);", self.mq5)
        self.assertIsNotNone(m_max_vol)
        self.assertEqual(Decimal(m_max_vol.group(1)), MT5_MAX_VOLUME_DEFAULT)

        exec_fn = _extract_mql5_function(self.mq5, "void ExecuteRequest(")
        # Both Mt5PaperBrokerVenue / Mt5SpoolPaperTerminalEmulator and MQL5 ExecuteRequest enforce
        # MT5_MAX_VOLUME_DEFAULT (InpMaxVolumeLots = 50.0) on OPEN and 10014 on REDUCE/CLOSE.
        self.assertIn("volume <= 0.0 || volume > InpMaxVolumeLots || sl <= 0.0", exec_fn)
        for code in ("10013", "10014", "10016", "10017", "10036"):
            self.assertIn(f'"REJECTED", {code}, "0"', exec_fn)
        status_fn = _extract_mql5_function(self.mq5, "string StatusFor(")
        self.assertIn("TRADE_RETCODE_DONE", status_fn)
        self.assertIn("TRADE_RETCODE_PLACED", status_fn)
        self.assertIn("TRADE_RETCODE_DONE_PARTIAL", status_fn)

        sdk_const = {"TRADE_RETCODE_DONE": 10009, "TRADE_RETCODE_PLACED": 10008, "TRADE_RETCODE_DONE_PARTIAL": 10010}
        self.assertEqual(_status_for_retcode(10009, "OPEN", sdk_const), "FILLED")
        self.assertEqual(_status_for_retcode(10009, "AMEND_STOP", sdk_const), "MODIFIED")
        self.assertEqual(_status_for_retcode(10010, "OPEN", sdk_const), "PARTIAL")
        for rej in (10013, 10014, 10016, 10017, 10019, 10036):
            self.assertEqual(_status_for_retcode(rej, "OPEN", sdk_const), "REJECTED")

        # Exercise emulator rejection codes (10013, 10016, 10017, 10036) + Mt5PaperBrokerVenue CONFIRMED_REJECTED
        # + DualShieldBrokerRouter 10019 failover
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("50000"),
                clock=lambda: T0,
            )
            emu_l = Mt5SpoolPaperTerminalEmulator(
                root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("50000"),
                clock=lambda: T0,
            )
            emu_h.publish_market()
            emu_l.publish_market()

            t_h = Mt5SpoolBridgeTransport(
                root / "hugosway_mt5", sleep=emu_h.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2.0
            )
            t_h.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))

            def _mk_req(req_id: str, **kw: object) -> Mt5OrderRequest:
                defaults: dict[str, object] = {
                    "request_id": req_id,
                    "action": "OPEN",
                    "symbol": "EURUSD",
                    "side": Side.BUY,
                    "volume_lots": D("0.10"),
                    "price": D("1.10010"),
                    "stop_loss": D("1.09500"),
                    "take_profit": None,
                    "position_ticket": None,
                    "deviation_points": 20,
                    "magic": 20261116,
                    "comment": "cas-rej",
                    "created_at": T0,
                    "valve_decision_sha256": "d" * 64,
                }
                defaults.update(kw)
                return Mt5OrderRequest(**defaults)  # type: ignore[arg-type]

            for req_id, expected_code, overrides in (
                ("req-rej-10036", 10036, {"action": "AMEND_STOP", "position_ticket": "9999999"}),
                ("req-rej-10016", 10016, {"stop_loss": D("1.10500")}),
                ("req-rej-10013", 10013, {"symbol": "NAS100"}),
            ):
                rcpt = t_h.send_order(_mk_req(req_id, **overrides))
                self.assertFalse(rcpt.accepted)
                self.assertEqual(rcpt.retcode, expected_code)
                self.assertEqual(rcpt.status, "REJECTED")
                self.assertIsNone(rcpt.position_ticket)

            # 10014 invalid volume (open 0.10 then REDUCE 99.00 lots)
            rcpt_open = t_h.send_order(_mk_req("req-open-for-14"))
            self.assertTrue(rcpt_open.accepted)
            rcpt_14 = t_h.send_order(
                _mk_req("req-rej-10014", action="REDUCE", position_ticket=rcpt_open.position_ticket, volume_lots=D("99.00"))
            )
            self.assertFalse(rcpt_14.accepted)
            self.assertEqual(rcpt_14.retcode, 10014)
            self.assertEqual(rcpt_14.status, "REJECTED")
            self.assertIsNone(rcpt_14.position_ticket)

            # 10014 oversized OPEN volume (> 50.00 lots) parity with CasForexMt5Bridge.mq5 InpMaxVolumeLots
            rcpt_open_over = t_h.send_order(_mk_req("req-rej-open-10014", action="OPEN", volume_lots=D("50.01")))
            self.assertFalse(rcpt_open_over.accepted)
            self.assertEqual(rcpt_open_over.retcode, 10014)
            self.assertEqual(rcpt_open_over.status, "REJECTED")
            self.assertIsNone(rcpt_open_over.position_ticket)

            # 10017 account binding mismatch (keep issued_at/expires_at/server so prepare_request keeps account_login)
            rcpt_17 = t_h.send_order(
                _mk_req(
                    "req-rej-10017",
                    monotonic_nonce=99,
                    issued_at=T0,
                    expires_at=T0 + timedelta(seconds=30),
                    broker_channel="hugosway_mt5",
                    account_login="9999999",
                    server="Hugosway-Demo",
                    execution_mode=EXECUTION_MODE_DEMO,
                )
            )
            self.assertFalse(rcpt_17.accepted)
            self.assertEqual(rcpt_17.retcode, 10017)

            # Mt5PaperBrokerVenue CONFIRMED_REJECTED (10019 NO_MONEY at execution time) + DualShieldBrokerRouter failover
            fo_root = root / "failover"
            emu_fh = Mt5SpoolPaperTerminalEmulator(
                fo_root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("50000"),
                clock=lambda: T0,
            )
            emu_fl = Mt5SpoolPaperTerminalEmulator(
                fo_root / "lhfx_mt5",
                server="LHFXSA-Trade",
                login=8005678,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("50000"),
                clock=lambda: T0,
            )
            emu_fh.publish_market()
            emu_fl.publish_market()

            def _hugo_no_money_sleep(sec: float) -> None:
                emu_fh.balance = D("10")
                emu_fh.sleep_hook(sec)

            journal_h = Mt5MutationJournal(db_path=fo_root / "journal_h.sqlite3")
            t_h_19 = Mt5SpoolBridgeTransport(
                fo_root / "hugosway_mt5", sleep=_hugo_no_money_sleep, poll_interval_seconds=0.01, receipt_timeout_seconds=2.0
            )
            venue_h = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                transport=t_h_19,
                credentials=Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"),
                valve_gate=load_default_forex_valve_gate(),
                mutation_journal=journal_h,
                clock=lambda: T0,
            )
            venue_h.connect()
            open_19 = OrderIntent(
                order_id="ord-nomoney-19",
                action_ref="act-nomoney-19",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                side=Side.BUY,
                quantity_units=D("10000"),
                limit_price=D("1.10010"),
                stop_price=D("1.09500"),
            )
            res_19 = venue_h.execute(open_19, valve_decision=_clear_valve(open_19))
            self.assertFalse(res_19.receipt.accepted)
            self.assertEqual(res_19.receipt.retcode, 10019)
            self.assertEqual(res_19.receipt.status, "REJECTED")
            self.assertEqual(journal_h.unknown_mutations(), [])
            j_conn = sqlite3.connect(str(fo_root / "journal_h.sqlite3"))
            try:
                j_row = j_conn.execute(
                    "SELECT status, error_detail FROM mt5_mutation_journal WHERE symbol = 'EURUSD' ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
            finally:
                j_conn.close()
            self.assertIsNotNone(j_row)
            self.assertEqual(j_row[0], "CONFIRMED_REJECTED")

            # DualShieldBrokerRouter: restore market_ticks $12k/$8k/$80k Barbell ratios -> 10019 on Hugo fails over to LHFX_MT5
            emu_fh.balance = D("12000")
            emu_fh.publish_market()
            emu_fl.balance = D("8000")
            emu_fl.publish_market()
            cred_tok = secrets.token_hex(12)
            env = {
                "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
                "CAS_FOREX_MT5_SPOOL_DIR": str(fo_root),
                "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": cred_tok,
                "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
                "CAS_FOREX_OANDA_PRACTICE_TOKEN": cred_tok,
                "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-1234567-001",
                "CAS_FOREX_ANTHROPIC_API_KEY": f"test-synth-{cred_tok}",
            }
            router = DualShieldBrokerRouter(
                environ=env,
                valve_gate=load_default_forex_valve_gate(),
                transport_factory=lambda b, m, r: Mt5SpoolBridgeTransport(
                    Path(r) / b.lower(),
                    sleep=_hugo_no_money_sleep if b == BROKER_HUGOSWAY_MT5 else emu_fl.sleep_hook,
                    poll_interval_seconds=0.01,
                    receipt_timeout_seconds=2.0,
                ),
                oanda_client_factory=lambda e: OandaPracticePaperClient(
                    environ=e,
                    transport=lambda _m, u, *_a: (
                        b'{"prices":[{"instrument":"EUR_USD","bids":[{"price":"1.10000"}],"asks":[{"price":"1.10010"}]}]}'
                        if "/pricing" in u
                        else b'{"account":{"balance":"80000","NAV":"80000","marginAvailable":"80000"}}'
                    ),
                ),
                clock=lambda: T0,
            )
            router.activate_all()
            open_ord = OrderIntent(
                order_id="ord-failover-19",
                action_ref="act-failover-19",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                side=Side.BUY,
                quantity_units=D("10000"),
                limit_price=D("1.10010"),
                stop_price=D("1.09500"),
            )
            exec_res = router.execute_open(open_ord, valve_decision=_clear_valve(open_ord))
            self.assertEqual(exec_res.executed_on, BROKER_LHFX_MT5)
            self.assertEqual(exec_res.trail[0]["broker_id"], BROKER_HUGOSWAY_MT5)
            self.assertEqual(exec_res.trail[0]["outcome"], "BROKER_REJECTED")
            self.assertIn("10019", str(exec_res.trail[0]["reason"]))

    def test_spool_replay_ledger_and_atomic_write_thread_safe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("50000"),
                clock=lambda: T0,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(
                root / "hugosway_mt5",
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=2.0,
            )
            tr.connect(Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo"))
            with ThreadPoolExecutor(max_workers=12) as pool:
                nonces = list(pool.map(lambda _i: tr._nonce_ledger.next_nonce(), range(12)))
            self.assertEqual(sorted(nonces), list(range(1, 13)))
            self.assertEqual(len(set(nonces)), 12)

    def test_prebound_requests_receive_fresh_monotonic_nonces_without_double_burn(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu = Mt5SpoolPaperTerminalEmulator(
                root / "hugosway_mt5",
                server="Hugosway-Demo",
                login=7001234,
                quotes={"EURUSD": (D("1.10000"), D("1.10010"))},
                balance=D("50000"),
                clock=lambda: T0,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(
                root / "hugosway_mt5",
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=2.0,
            )
            creds = Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugosway-Demo")
            tr.connect(creds)

            def _prebound(req_id: str) -> Mt5OrderRequest:
                return Mt5OrderRequest(
                    request_id=req_id,
                    action="OPEN",
                    symbol="EURUSD",
                    side=Side.BUY,
                    volume_lots=D("0.10"),
                    price=D("1.10010"),
                    stop_loss=D("1.09500"),
                    take_profit=None,
                    position_ticket=None,
                    deviation_points=20,
                    magic=20261116,
                    comment="prebound",
                    created_at=T0,
                    issued_at=T0,
                    expires_at=T0 + timedelta(seconds=30),
                    broker_channel="hugosway_mt5",
                    account_login=str(creds.login),
                    server=creds.server,
                    execution_mode=EXECUTION_MODE_DEMO,
                    valve_decision_sha256="d" * 64,
                )

            req1 = _prebound("req-prebound-1")
            bound1 = tr.prepare_request(req1)
            self.assertEqual(bound1.monotonic_nonce, 1)
            # Idempotent re-preparation of the already-prepared object must not burn nonce 2
            self.assertEqual(tr.prepare_request(bound1).monotonic_nonce, 1)
            rcpt1 = tr.send_order(bound1)
            self.assertTrue(rcpt1.accepted)
            self.assertEqual(rcpt1.status, "FILLED")

            req2 = _prebound("req-prebound-2")
            rcpt2 = tr.send_order(req2)
            self.assertTrue(rcpt2.accepted)
            self.assertEqual(rcpt2.status, "FILLED")
            last_nonce, _ = tr._nonce_ledger.load()
            self.assertEqual(last_nonce, 2)


if __name__ == "__main__":
    unittest.main()
