"""Phase 6 tests: Trend Pyramiding, 50%/50% Treasury Vault (Coinbase ES256 / Kraken HMAC-SHA512),
Section B.5 5-Tier Parallel Account Engine, and Section B.6 Auto-Adaptive 2-Speed Brain.
"""
from __future__ import annotations

import base64
import dataclasses
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.composition.trend_regime import (
    PyramidLegSnapshot,
    REGIME_CHOP_RANGE,
    REGIME_SPREAD_SPIKE,
    REGIME_STRONG_TREND,
    REGIME_TREND_IGNITION,
    TrendRegimeDetector,
    evaluate_correlation_cap,
    evaluate_house_money_pyramid_leg,
)
from cas_forex_revamp.contracts import ActionKind, ContractError, Side, canonical_bytes, content_digest, decimal_text
from cas_forex_revamp.operator.frontier_backends import (
    FrontierModelRegistry,
    assert_safe_ai_catalog_payload,
    _CATALOG_BY_ID,
    _build_provider_payload,
    _extract_provider_text_and_usage,
)
from cas_forex_revamp.operator.model import (
    DurableModelExecutionGate,
    InferenceBudget,
    ModelInvocation,
    ModelSpecification,
    SYSTEM_POLICY,
)
from cas_forex_revamp.treasury import (
    CoinbaseOfframpClient,
    KrakenOfframpClient,
    OfframpSecurityError,
    OfframpTransportError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
    RAIL_KRAKEN_ACH,
)
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import OandaPracticePaperClient
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
)

D = Decimal
T0 = datetime(2026, 11, 18, 13, 0, 0, tzinfo=timezone.utc)
SYNTH_KEY = "test-synth-key-alpha-01"
QUOTES = {
    "NAS100": (D("20500.00"), D("20502.50")),
    "US30": (D("43800.00"), D("43804.00")),
    "EURUSD": (D("1.10000"), D("1.10010")),
    "GBPUSD": (D("1.27000"), D("1.27012")),
    "USDJPY": (D("150.000"), D("150.012")),
    "EURGBP": (D("0.86600"), D("0.86612")),
    "EURJPY": (D("165.000"), D("165.015")),
    "GBPJPY": (D("190.500"), D("190.520")),
    "AUDUSD": (D("0.65000"), D("0.65010")),
    "USDCHF": (D("0.88000"), D("0.88010")),
    "USDCAD": (D("1.36000"), D("1.36012")),
    "NZDUSD": (D("0.60000"), D("0.60010")),
    "EURCHF": (D("0.96800"), D("0.96812")),
    "EURAUD": (D("1.69200"), D("1.69220")),
    "EURCAD": (D("1.49600"), D("1.49615")),
    "AUDJPY": (D("97.500"), D("97.512")),
    "CHFJPY": (D("170.400"), D("170.420")),
    "CADJPY": (D("110.300"), D("110.312")),
}


class ProfitExpansionTests(unittest.TestCase):
    def test_trend_regime_house_money_pyramid_and_correlation_cap(self) -> None:
        det = TrendRegimeDetector()
        # Rising strong trend series
        mids = [D("1.10000") + D("0.00015") * i for i in range(60)]
        r_strong = det.classify(mids=mids, spread=D("0.00010"), normal_sl_distance=D("0.00200"))
        self.assertEqual(r_strong.regime, REGIME_STRONG_TREND)
        self.assertEqual(r_strong.direction, Side.BUY)

        # Spread spike filter
        r_spike = det.classify(mids=mids, spread=D("0.00100"), normal_sl_distance=D("0.00200"))
        self.assertEqual(r_spike.regime, REGIME_SPREAD_SPIKE)

        # Chop filter
        flat = [D("1.10000") + (D("0.00002") if i % 2 == 0 else D("-0.00002")) for i in range(10)]
        self.assertEqual(det.classify(mids=flat, spread=D("0.00010"), normal_sl_distance=D("0.00200")).regime, REGIME_CHOP_RANGE)

        # Pyramid refused before BREAKEVEN_LOCKED
        base_init = PyramidLegSnapshot("101", "EURUSD", Side.BUY, D("10000"), D("1.10000"), D("1.09800"), "INITIAL_SL")
        p_refuse = evaluate_house_money_pyramid_leg(
            symbol="EURUSD", side=Side.BUY, regime=REGIME_STRONG_TREND,
            existing_legs=[base_init], new_leg_entry=D("1.10300"), new_leg_stop=D("1.10200"), new_leg_units=D("5000"),
        )
        self.assertFalse(p_refuse.allowed)
        self.assertIn("BREAKEVEN", p_refuse.reason)

        # Pyramid admitted once leg 1 locked +$20 floor > new leg $5 SL risk (net_floor = +$15 >= $0)
        base_be = PyramidLegSnapshot("101", "EURUSD", Side.BUY, D("10000"), D("1.10000"), D("1.10200"), "BREAKEVEN_LOCKED")
        p_ok = evaluate_house_money_pyramid_leg(
            symbol="EURUSD", side=Side.BUY, regime=REGIME_STRONG_TREND,
            existing_legs=[base_be], new_leg_entry=D("1.10300"), new_leg_stop=D("1.10200"), new_leg_units=D("5000"),
        )
        self.assertTrue(p_ok.allowed)
        self.assertGreaterEqual(p_ok.net_floor_usd, D("0"))

        # Max 3 legs cap enforced
        p_cap = evaluate_house_money_pyramid_leg(
            symbol="EURUSD", side=Side.BUY, regime=REGIME_STRONG_TREND,
            existing_legs=[base_be, base_be, base_be],
            new_leg_entry=D("1.10400"), new_leg_stop=D("1.10300"), new_leg_units=D("5000"),
        )
        self.assertFalse(p_cap.allowed)

        # Correlation cap: 2 short-USD pairs already open -> 3rd distinct USD pair vetoed unless pyramid
        ok_c, _ = evaluate_correlation_cap(
            candidate_symbol="AUDUSD", candidate_side=Side.BUY,
            open_positions=[{"symbol": "EURUSD", "side": "BUY"}, {"symbol": "GBPUSD", "side": "BUY"}],
        )
        self.assertFalse(ok_c)

    def test_profit_sweep_vault_and_coinbase_es256_and_kraken_ach_security(self) -> None:
        priv = ec.generate_private_key(ec.SECP256R1())
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with tempfile.TemporaryDirectory() as td:
            pem_p = Path(td) / "cb_ec.pem"
            pem_p.write_bytes(pem)
            if hasattr(Path, "chmod"):
                pem_p.chmod(0o600)

            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=lambda: T0)
            snap = vault.record_realized_close(
                trade_id="t-win-1", symbol="NAS100", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=D("500.00")
            )
            self.assertEqual(snap["retained_trading_usd"], "250")
            self.assertEqual(snap["bank_sweep_reserved_usd"], "250")
            self.assertEqual(vault.deployable_equity(D("1000.00")), D("750.00"))

            cb_calls = []
            def cb_http(method, url, headers, body, timeout):
                cb_calls.append((method, url, headers, body))
                return 200, json.dumps({"id": "cb-ach-999"}).encode("utf-8")

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-ach-01",
                http_call=cb_http,
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            # Zero crypto address transfer method anywhere
            for banned in ("withdraw_crypto", "send_to_address", "transfer_crypto"):
                self.assertFalse(hasattr(cb, banned))

            # Verify ES256 64-byte IEEE P1363 R||S signature verifies with P-256 public key
            jwt_str = cb.build_es256_jwt(method="POST", request_path="/api/v3/brokerage/withdrawals/fiat", nonce="n1")
            parts = jwt_str.split(".")
            self.assertEqual(len(parts), 3)
            raw_sig = base64.urlsafe_b64decode(parts[2] + "==" * ((4 - len(parts[2]) % 4) % 4))
            self.assertEqual(len(raw_sig), 64)
            r = int.from_bytes(raw_sig[:32], "big")
            s = int.from_bytes(raw_sig[32:], "big")
            priv.public_key().verify(
                encode_dss_signature(r, s),
                f"{parts[0]}.{parts[1]}".encode("ascii"),
                ec.ECDSA(hashes.SHA256()),
            )

            # Kraken HMAC-SHA512 client
            k_calls = []
            def krk_http(method, url, headers, body, timeout):
                k_calls.append((method, url, headers, body))
                return 200, json.dumps({"error": [], "result": {"refid": "KRK-777"}}).encode("utf-8")

            krk = KrakenOfframpClient(
                api_key="krk-pub-01",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="BankACH-Owner",
                http_call=krk_http,
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            for banned in ("withdraw_crypto", "send_to_address", "transfer_crypto"):
                self.assertFalse(hasattr(krk, banned))

            # SSRF / override protections
            with self.assertRaises(OfframpSecurityError):
                cb.withdraw_usd_to_linked_bank_ach(amount_usd=D("50"), payment_method_id="attacker-bank")
            with self.assertRaises(OfframpSecurityError):
                krk.withdraw_usd_to_linked_bank_ach(amount_usd=D("50"), key_id="attacker-key")
            with self.assertRaises(OfframpSecurityError):
                CoinbaseOfframpClient(
                    key_name="organizations/org-1/apiKeys/key-1",
                    private_key_file=pem_p,
                    linked_bank_account_id="pm-bank-ach-01",
                    base_url="https://evil.example",
                )

            # Owner recovery gated payout (Finding [13]: prepared canonical intent digest)
            rec = OwnerRecoveryVerifier(db_path=Path(td) / "vault.sqlite3", clock=lambda: T0)
            prep_cb = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"),
                owner_request_id="req-ach-cb", reason="sweep 50% bank share",
                coinbase_client=cb,
            )
            tok_cb = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_cb["intent_sha256"], now=T0)
            out_cb = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH, amount_usd=D("100.00"),
                owner_request_id="req-ach-cb", reason="sweep 50% bank share",
                verifier=rec, recovery_token=tok_cb, coinbase_client=cb,
                intent_id=prep_cb["intent_id"], intent_sha256=prep_cb["intent_sha256"],
            )
            self.assertEqual(out_cb["provider_tx_id"], "cb-ach-999")
            self.assertEqual(out_cb["vault"]["disbursed_to_bank_usd"], "100")

            prep_kr = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH, amount_usd=D("50.00"),
                owner_request_id="req-ach-kr", reason="sweep 50% bank share",
                kraken_client=krk,
            )
            tok_kr = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_kr["intent_sha256"], now=T0)
            out_kr = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH, amount_usd=D("50.00"),
                owner_request_id="req-ach-kr", reason="sweep 50% bank share",
                verifier=rec, recovery_token=tok_kr, kraken_client=krk,
                intent_id=prep_kr["intent_id"], intent_sha256=prep_kr["intent_sha256"],
            )
            self.assertEqual(out_kr["provider_tx_id"], "KRK-777")
            self.assertEqual(out_kr["vault"]["pending_disbursement_usd"], "100")

    def test_concurrent_2fa_and_ach_reserve_cannot_overallocate_vault(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=lambda: T0)
            vault.record_realized_close(
                trade_id="t-conc-1", symbol="NAS100", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=D("200.00")
            )
            rec = OwnerRecoveryVerifier(db_path=Path(td) / "rec.sqlite3", clock=lambda: T0)

            ach_calls = []
            def krk_http(method, url, headers, body, timeout):
                ach_calls.append((method, url))
                return 200, json.dumps({"error": [], "result": {"refid": "KRK-CONC-1"}}).encode("utf-8")

            krk = KrakenOfframpClient(
                api_key="krk-pub-01",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="BankACH-Owner",
                http_call=krk_http,
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )

            # 0. Sub-cent ACH amount (< $0.005) must fail BEFORE token consumption or DB insertion
            p_req1 = vault.prepare_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=D("60.00"),
                owner_request_id="req-conc-2fa-1",
                reason="first 2fa reserve",
                destination_bank_label="OWNER_BANK_A",
            )
            t0 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_req1["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("0.004"),
                    owner_request_id="req-conc-ach-subcent",
                    reason="sub-cent ach",
                    verifier=rec,
                    recovery_token=t0,
                    kraken_client=krk,
                )
            self.assertEqual(vault.snapshot()["recent_transfers"], [])
            self.assertEqual(ach_calls, [])

            # 1. Queue $60.00 2FA withdrawal reusing unconsumed t0 -> PENDING_OWNER_BROKER_2FA
            t1 = t0
            req1 = vault.request_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=D("60.00"),
                owner_request_id="req-conc-2fa-1",
                reason="first 2fa reserve",
                verifier=rec,
                recovery_token=t1,
                destination_bank_label="OWNER_BANK_A",
                intent_id=p_req1["intent_id"],
                intent_sha256=p_req1["intent_sha256"],
            )
            self.assertEqual(req1["status"], "PENDING_OWNER_BROKER_2FA")
            self.assertEqual(req1["vault"]["pending_2fa_confirmation_usd"], "60")
            self.assertEqual(req1["vault"]["pending_disbursement_usd"], "100")

            # 2. Second 2FA or ACH > $40.00 must be rejected without calling HTTP transport (and without burning token!)
            p_over_2fa = vault.prepare_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=D("40.01"),
                owner_request_id="req-conc-2fa-2",
                reason="over-allocate 2fa",
                destination_bank_label="OWNER_BANK_A",
            )
            t2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_over_2fa["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=D("40.01"),
                    owner_request_id="req-conc-2fa-2",
                    reason="over-allocate 2fa",
                    verifier=rec,
                    recovery_token=t2,
                    destination_bank_label="OWNER_BANK_A",
                    intent_id=p_over_2fa["intent_id"],
                    intent_sha256=p_over_2fa["intent_sha256"],
                )

            p_over_ach = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("40.01"),
                owner_request_id="req-conc-ach-over",
                reason="over-allocate ach",
                kraken_client=krk,
            )
            t3 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_over_ach["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("40.01"),
                    owner_request_id="req-conc-ach-over",
                    reason="over-allocate ach",
                    verifier=rec,
                    recovery_token=t3,
                    kraken_client=krk,
                    intent_id=p_over_ach["intent_id"],
                    intent_sha256=p_over_ach["intent_sha256"],
                )
            self.assertEqual(ach_calls, [])

            # 3. Transition $60 transfer to BROKER_2FA_VERIFICATION_UNKNOWN -> still locks $60
            t4 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=req1["transfer_id"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.confirm_broker_2fa_withdrawal(
                    transfer_id=req1["transfer_id"],
                    provider_tx_id="ptx-pending-1",
                    owner_request_id="req-conc-confirm-pending",
                    verifier=rec,
                    recovery_token=t4,
                    provider_verifier=lambda _b, _tx: {"status": "PENDING"},
                )

            p_over_ach2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("40.01"),
                owner_request_id="req-conc-ach-over2",
                reason="over-allocate ach during unknown",
                kraken_client=krk,
            )
            t5 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_over_ach2["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("40.01"),
                    owner_request_id="req-conc-ach-over2",
                    reason="over-allocate ach during unknown",
                    verifier=rec,
                    recovery_token=t5,
                    kraken_client=krk,
                    intent_id=p_over_ach2["intent_id"],
                    intent_sha256=p_over_ach2["intent_sha256"],
                )
            self.assertEqual(ach_calls, [])

            # 4. Remaining $40.00 ACH succeeds, leaving $0.00 allocatable
            p_exact_ach = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("40.00"),
                owner_request_id="req-conc-ach-exact",
                reason="remaining bank vault",
                kraken_client=krk,
            )
            t6 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_exact_ach["intent_sha256"], now=T0)
            out_ach = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("40.00"),
                owner_request_id="req-conc-ach-exact",
                reason="remaining bank vault",
                verifier=rec,
                recovery_token=t6,
                kraken_client=krk,
                intent_id=p_exact_ach["intent_id"],
                intent_sha256=p_exact_ach["intent_sha256"],
            )
            self.assertEqual(out_ach["status"], "ACH_SUBMITTED")
            self.assertEqual(len(ach_calls), 1)

            p_exh_2fa = vault.prepare_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=D("0.01"),
                owner_request_id="req-conc-2fa-exhausted",
                reason="exhausted vault",
                destination_bank_label="OWNER_BANK_A",
            )
            t7 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_exh_2fa["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=D("0.01"),
                    owner_request_id="req-conc-2fa-exhausted",
                    reason="exhausted vault",
                    verifier=rec,
                    recovery_token=t7,
                    destination_bank_label="OWNER_BANK_A",
                    intent_id=p_exh_2fa["intent_id"],
                    intent_sha256=p_exh_2fa["intent_sha256"],
                )
            p_exh_ach = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("0.01"),
                owner_request_id="req-conc-ach-exhausted",
                reason="exhausted vault ach",
                kraken_client=krk,
            )
            t8 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=p_exh_ach["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("0.01"),
                    owner_request_id="req-conc-ach-exhausted",
                    reason="exhausted vault ach",
                    verifier=rec,
                    recovery_token=t8,
                    kraken_client=krk,
                    intent_id=p_exh_ach["intent_id"],
                    intent_sha256=p_exh_ach["intent_sha256"],
                )
            self.assertEqual(len(ach_calls), 1)

    def test_parallel_tiers_all_5_accounts_and_lot_floor_skip(self) -> None:
        gate = load_default_forex_valve_gate()
        with tempfile.TemporaryDirectory() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=lambda: T0)
            out = eng.process_tick(
                quotes=QUOTES,
                signal={"symbol": "EURUSD", "side": "BUY", "stop_price": "1.09510", "take_profit_price": "1.11000", "regime": REGIME_STRONG_TREND},
                now=T0,
            )
            by_id = {t["tier_id"]: t for t in out["tiers"]}
            self.assertEqual(out["tier_count"], 5)
            self.assertEqual(by_id["TIER_5_300"]["open_positions"], 0)
            self.assertEqual(by_id["TIER_5_300"]["last_skip_reason"], "LOT_FLOOR_RISK_EXCEEDED")
            self.assertEqual(by_id["TIER_2_1000"]["open_positions"], 1)
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 1)
            safe_snap = assert_safe_ai_catalog_payload(eng.snapshot())
            self.assertEqual(safe_snap["tiers"][0]["color_class"], "tier-300k")
            srv = LoopbackCockpitServer(repo_root=Path(__file__).resolve().parents[2], port=0, parallel_tiers=eng)
            base_url = srv.start()
            try:
                host, port_s = base_url.replace("http://", "").split(":", 1)
                conn = http.client.HTTPConnection(host, int(port_s), timeout=5)
                try:
                    conn.request("GET", "/api/parallel-tiers", headers=srv.auth_headers())
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    payload = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(payload["tier_count"], 5)
                    self.assertEqual(payload["tiers"][0]["color_class"], "tier-300k")
                finally:
                    conn.close()
            finally:
                srv.stop()

    def test_section_b6_2speed_brain_thinking_payloads_and_nonblocking_50ms_protection(self) -> None:
        # 928-byte SYSTEM_POLICY invariant unchanged
        self.assertEqual(len(SYSTEM_POLICY.encode("utf-8")), 928)

        reg = FrontierModelRegistry(environ={
            "CAS_FOREX_ANTHROPIC_API_KEY": SYNTH_KEY,
            "CAS_FOREX_GEMINI_API_KEY": SYNTH_KEY,
            "CAS_FOREX_OPENAI_API_KEY": SYNTH_KEY,
            "CAS_FOREX_DEEPSEEK_API_KEY": SYNTH_KEY,
            "CAS_FOREX_THINKING_DEPTH": "AUTO",
        })
        self.assertEqual(reg.thinking_depth, "AUTO")
        self.assertEqual(reg.resolve_reasoning_effort(timeframe="50ms", symbol="NAS100", regime=REGIME_TREND_IGNITION), "low")
        self.assertEqual(reg.resolve_reasoning_effort(timeframe="M5", symbol="EURUSD", regime=REGIME_STRONG_TREND), "medium")
        self.assertEqual(reg.resolve_reasoning_effort(timeframe="H1", symbol="EURUSD", is_pyramid_add=True), "high")

        # Provider-native thinking payload shapes & extraction (skipping thinking/thought blocks)
        inv_hi = ModelInvocation(
            request_sha256="a" * 64,
            model=ModelSpecification("cas-claude-fable-5.2", "b" * 64, "high", "frontier-v2"),
            session_id="s-1", system_policy=SYSTEM_POLICY,
            packet_json=canonical_bytes({"request_id": "r1", "opportunity_set_id": "o1", "choices": ["WAIT"]}).decode("utf-8"),
            budget=InferenceBudget(max_calls=1, max_input_tokens_per_call=16000, max_generated_tokens_per_call=8192, max_seconds_per_call=25, max_total_seconds=25),
        )
        _, _, ant_body = _build_provider_payload(_CATALOG_BY_ID["claude-fable-5.2"], "claude-fable-5-2", inv_hi, reg._secrets["CAS_FOREX_ANTHROPIC_API_KEY"])
        ant_json = json.loads(ant_body.decode("utf-8"))
        self.assertEqual(ant_json["thinking"], {"type": "adaptive"})
        self.assertEqual(ant_json["output_config"], {"effort": "high"})
        self.assertGreaterEqual(ant_json["max_tokens"], 8192)
        self.assertNotIn("temperature", ant_json)
        _, _, ant4_body = _build_provider_payload(_CATALOG_BY_ID["claude-fable"], "claude-sonnet-4-5", inv_hi, reg._secrets["CAS_FOREX_ANTHROPIC_API_KEY"])
        self.assertEqual(json.loads(ant4_body.decode("utf-8"))["thinking"], {"type": "enabled", "budget_tokens": 6144})
        txt_ant, _, _ = _extract_provider_text_and_usage(
            "anthropic",
            {"content": [{"type": "thinking", "thinking": "deep chain"}, {"type": "text", "text": '{"ok":1}'}], "usage": {"output_tokens": 20}},
            inv_hi, min_probability=D("0.60"),
        )
        self.assertEqual(txt_ant, '{"ok":1}')

        _, _, gem_body = _build_provider_payload(_CATALOG_BY_ID["gemini-carbon"], "gemini-4-carbon", inv_hi, reg._secrets["CAS_FOREX_GEMINI_API_KEY"])
        self.assertEqual(json.loads(gem_body.decode("utf-8"))["generationConfig"]["thinkingConfig"], {"thinkingBudget": 6144})
        inv_lo = dataclasses.replace(inv_hi, model=ModelSpecification("cas-gemini-4-carbon", "b" * 64, "low", "frontier-v2"))
        _, _, gem_lo_body = _build_provider_payload(_CATALOG_BY_ID["gemini-carbon"], "gemini-4-carbon", inv_lo, reg._secrets["CAS_FOREX_GEMINI_API_KEY"])
        self.assertEqual(json.loads(gem_lo_body.decode("utf-8"))["generationConfig"]["thinkingConfig"], {"thinkingBudget": 256})
        txt_gem, _, _ = _extract_provider_text_and_usage(
            "gemini",
            {"candidates": [{"content": {"parts": [{"thought": True, "text": "hmm"}, {"text": '{"ok":2}'}]}}]},
            inv_hi, min_probability=D("0.60"),
        )
        self.assertEqual(txt_gem, '{"ok":2}')

        _, _, oai_body = _build_provider_payload(_CATALOG_BY_ID["openai-astra"], "gpt-5.5-2026-04-23", inv_hi, reg._secrets["CAS_FOREX_OPENAI_API_KEY"])
        oai_json = json.loads(oai_body.decode("utf-8"))
        self.assertEqual(oai_json["reasoning_effort"], "high")
        self.assertIn("max_completion_tokens", oai_json)
        self.assertNotIn("temperature", oai_json)
        _, _, ds_body = _build_provider_payload(_CATALOG_BY_ID["deepseek-flash-1017"], "deepseek-flash", inv_hi, reg._secrets["CAS_FOREX_DEEPSEEK_API_KEY"])
        ds_json = json.loads(ds_body.decode("utf-8"))
        self.assertEqual(ds_json["reasoning_effort"], "high")
        self.assertEqual(ds_json["temperature"], 0)
        self.assertIn("max_tokens", ds_json)

        # Verify POST /api/thinking-depth & non-blocking 50ms evaluate_fast_protection() while HTTP sleeps
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            emu_h = Mt5SpoolPaperTerminalEmulator(root / "hugosway_mt5", server="Hugosway-Demo", login=7001234, quotes=QUOTES, balance=D("12000"), clock=lambda: T0)
            emu_l = Mt5SpoolPaperTerminalEmulator(root / "lhfx_mt5", server="LHFXSA-Trade", login=8005678, quotes=QUOTES, balance=D("8000"), clock=lambda: T0)
            emu_h.publish_market()
            emu_l.publish_market()
            env = {
                "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
                "CAS_FOREX_MT5_SPOOL_DIR": str(root),
                "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": "p1",
                "CAS_FOREX_LHFX_MT5_LOGIN": "8005678",
                "CAS_FOREX_OANDA_PRACTICE_TOKEN": "tok",
                "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": "101-001-1234567-001",
                "CAS_FOREX_ANTHROPIC_API_KEY": SYNTH_KEY,
                "CAS_FOREX_THINKING_DEPTH": "HIGH",
            }
            gate = load_default_forex_valve_gate()
            router = DualShieldBrokerRouter(
                environ=env, valve_gate=gate,
                transport_factory=lambda b, m, r: Mt5SpoolBridgeTransport(Path(r) / b.lower(), sleep=(emu_h if b == BROKER_HUGOSWAY_MT5 else emu_l).sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=5),
                oanda_client_factory=lambda e: OandaPracticePaperClient(environ=e, transport=lambda *_a: b'{"account":{"balance":"80000","NAV":"80000","marginAvailable":"80000"}}'),
                clock=lambda: T0,
            )
            router.activate_all()

            entered = threading.Event()
            release = threading.Event()
            def slow_http(url, headers, body, timeout, max_bytes):
                entered.set()
                release.wait(timeout=3.0)
                ud = json.loads(json.loads(body.decode("utf-8"))["messages"][0]["content"])
                return 200, json.dumps({"content": [{"type": "text", "text": json.dumps({"request_id": ud["request_id"], "opportunity_set_id": ud["opportunity_set_id"], "source_state_id": ud["state"]["state_id"], "selected_action_ref": None, "reason": "ID=0wait", "evidence_ids": [ud["evidence"][0]["evidence_id"]]})}], "usage": {"output_tokens": 30}}).encode("utf-8")

            reg2 = FrontierModelRegistry(environ=env, clock=lambda: T0, http_post=slow_http, resolve_dns=lambda _h: None)
            trader = AutonomousAiTrader(
                router=router, model_registry=reg2, valve_gate=gate,
                quota_store=DailyQuotaGovernanceStore(path=root / "q.sqlite3"),
                execution_gate=DurableModelExecutionGate(db_path=root / "g.sqlite3"),
                clock=lambda: T0,
            )
            # Seed NAS100 ticks so run_fast_tick_cycle calls slow_http
            for dlt in (D("0"), D("6"), D("14")):
                trader._tick_history["NAS100"].append((QUOTES["NAS100"][0] + dlt, QUOTES["NAS100"][1] + dlt))

            th = threading.Thread(target=lambda: trader.run_fast_tick_cycle(mt5_quotes={"NAS100": (QUOTES["NAS100"][0] + D("14"), QUOTES["NAS100"][1] + D("14"))}, now=T0))
            th.start()
            self.assertTrue(entered.wait(timeout=2.0))
            # While slow_http is blocked inside DEEP thinking, evaluate_fast_protection completes without stalling!
            t_start = datetime.now(timezone.utc)
            trader.evaluate_fast_protection(quotes=QUOTES, now=T0)
            elapsed_s = (datetime.now(timezone.utc) - t_start).total_seconds()
            self.assertLess(elapsed_s, 0.5)
            release.set()
            th.join(timeout=3.0)

    def test_vault_scope_id_target_ref_and_ach_retry_destination_guards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for bad_scope in ("", "a|b", "bad scope", " leading"):
                with self.assertRaises(ContractError):
                    ProfitSweepVault(root / "bad.sqlite3", scope_id=bad_scope, clock=lambda: T0)

            vault = ProfitSweepVault(root / "vault.sqlite3", scope_id="main-scope", clock=lambda: T0)
            vault.record_realized_close(
                trade_id="t-guard-1", symbol="EURUSD", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=D("400.00")
            )
            rec = OwnerRecoveryVerifier(db_path=root / "rec.sqlite3", clock=lambda: T0)

            # Token bound to unrelated target_ref must be rejected on both 2FA withdrawal and ACH payout
            prep_bad_2fa = vault.prepare_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=D("50.00"),
                owner_request_id="req-bad-ref-1",
                reason="target mismatch test",
            )
            tok_other_2fa = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref="tr2fa-other", now=T0)
            with self.assertRaises(ContractError):
                vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=D("50.00"),
                    owner_request_id="req-bad-ref-1",
                    reason="target mismatch test",
                    verifier=rec,
                    recovery_token=tok_other_2fa,
                    intent_id=prep_bad_2fa["intent_id"],
                    intent_sha256=prep_bad_2fa["intent_sha256"],
                )

            def krk_fail(_m, _u, _h, _b, _t):
                return 503, b"service unavailable"

            krk_orig = KrakenOfframpClient(
                api_key="krk-pub-01",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="bank-ORIGINAL",
                http_call=krk_fail,
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            prep_bad_ach = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-bad-ref-2",
                reason="target mismatch ach",
                kraken_client=krk_orig,
            )
            tok_other_ach = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref="trach-other", now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-bad-ref-2",
                    reason="target mismatch ach",
                    verifier=rec,
                    recovery_token=tok_other_ach,
                    kraken_client=krk_orig,
                    intent_id=prep_bad_ach["intent_id"],
                    intent_sha256=prep_bad_ach["intent_sha256"],
                )

            # Create OUTCOME_UNKNOWN transfer bound to bank-ORIGINAL
            prep_init = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-orig-1",
                reason="initial ach 503",
                kraken_client=krk_orig,
            )
            tok_init = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_init["intent_sha256"], now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-orig-1",
                    reason="initial ach 503",
                    verifier=rec,
                    recovery_token=tok_init,
                    kraken_client=krk_orig,
                    intent_id=prep_init["intent_id"],
                    intent_sha256=prep_init["intent_sha256"],
                )
            tid = str(vault.snapshot()["recent_transfers"][0]["transfer_id"])

            # Retrying with a different destination_bank_id MUST raise OfframpSecurityError
            krk_hijack = KrakenOfframpClient(
                api_key="krk-pub-01",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="bank-HIJACKED",
                http_call=lambda *_a: (200, json.dumps({"error": [], "result": {"refid": "KRK-HIJ"}}).encode("utf-8")),
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            prep_retry_hijack = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-retry-hijack",
                reason="destination mismatch",
                kraken_client=krk_hijack,
                retry_transfer_id=tid,
            )
            tok_retry_bad = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_retry_hijack["intent_sha256"], now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("50.00"),
                    owner_request_id="req-retry-hijack",
                    reason="destination mismatch",
                    verifier=rec,
                    recovery_token=tok_retry_bad,
                    kraken_client=krk_hijack,
                    retry_transfer_id=tid,
                    intent_id=prep_retry_hijack["intent_id"],
                    intent_sha256=prep_retry_hijack["intent_sha256"],
                )

            # Retrying with exact prepared intent digest and matching destination_bank_id succeeds
            krk_ok = KrakenOfframpClient(
                api_key="krk-pub-01",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="bank-ORIGINAL",
                http_call=lambda *_a: (200, json.dumps({"error": [], "result": {"refid": "KRK-OK"}}).encode("utf-8")),
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            prep_retry_ok = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-retry-ok",
                reason="retry matching bank",
                kraken_client=krk_ok,
                retry_transfer_id=tid,
            )
            tok_retry_ok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_retry_ok["intent_sha256"], now=T0)
            res = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("50.00"),
                owner_request_id="req-retry-ok",
                reason="retry matching bank",
                verifier=rec,
                recovery_token=tok_retry_ok,
                kraken_client=krk_ok,
                retry_transfer_id=tid,
                intent_id=prep_retry_ok["intent_id"],
                intent_sha256=prep_retry_ok["intent_sha256"],
            )
            self.assertEqual(res["status"], "ACH_SUBMITTED")


if __name__ == "__main__":
    unittest.main()
