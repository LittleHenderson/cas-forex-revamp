"""PR #25 Security Audit Remediation Tests (commit efb2bf4): Findings [2], [8] (routes), [13], [14]."""
from __future__ import annotations

import base64
from contextlib import closing
from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import hmac
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    SESSION_SCOPE_DEVICE_READ_EXPLAINER,
    SESSION_SCOPE_OWNER_FULL,
    run_cockpit_cli,
)
from cas_forex_revamp.composition.state_store import (
    OwnerRecoveryVerifier,
    _load_or_create_recovery_key,
    initialize_shared_runtime_state,
)
from cas_forex_revamp.contracts import ContractError, canonical_bytes
from cas_forex_revamp.operator.frontier_backends import (
    DEFAULT_EXPLAINER_MODEL_ID,
    DEFAULT_EXPLAINER_TTS_MODEL_ID,
    FrontierModelRegistry,
)
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.profit_sweep import (
    CoinbaseOfframpClient,
    KrakenOfframpClient,
    OfframpSecurityError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
    RAIL_KRAKEN_ACH,
)
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    ENV_EXECUTION_MODE,
    EXECUTION_MODE_DEMO,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
DUMMY_CRED = "demo-v1"


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


class TestAuditEfb2bf4CockpitAndTreasuryFindings(unittest.TestCase):
    def _http_json(
        self,
        port: int,
        host_hdr: str,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body_obj: dict[str, object] | None = None,
        origin: str | None = None,
    ) -> tuple[int, dict[str, str], dict[str, object] | str]:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
        try:
            hdrs: dict[str, str] = {"Host": host_hdr}
            if origin is not None:
                hdrs["Origin"] = origin
            if token is not None:
                hdrs["Authorization"] = f"Bearer {token}"
            raw_body = b""
            if body_obj is not None:
                raw_body = json.dumps(body_obj).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
                hdrs["Content-Length"] = str(len(raw_body))
            elif method.upper() == "POST":
                hdrs["Content-Length"] = "0"
            conn.request(method, path, body=raw_body, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            try:
                doc = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                doc = raw.decode("utf-8", errors="replace")
            return resp.status, resp_hdrs, doc
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Finding [2]: Ephemeral single-use pairing & least-privilege device sessions
    # ------------------------------------------------------------------
    def test_finding_2_bootstrap_and_pairing_urls_never_contain_primary_bearer_and_token_query_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                profit_vault=st.profit_vault,
                owner_recovery=st.owner_recovery,
            )
            srv.start()
            self.addCleanup(srv.stop)

            owner_tok = srv.auth_token
            boot_url = srv.bootstrap_url
            self.assertNotIn(owner_tok, boot_url)
            self.assertNotIn("token=", boot_url)
            self.assertIn("?pair_code=pair-", boot_url)

            # Primary bearer in ?token= query string MUST fail closed on UI and API routes
            for bad_path in (
                f"/ui/index.html?token={owner_tok}",
                f"/?token={owner_tok}",
                f"/api/health?token={owner_tok}",
                f"/api/treasury?token={owner_tok}",
            ):
                st_code, hdrs, _ = self._http_json(srv.bound_port, srv.expected_host_header, "GET", bad_path)
                self.assertEqual(st_code, 401, bad_path)
                self.assertNotIn("set-cookie", hdrs)

            # Unauthenticated POST /api/pair-code rejected; owner bearer succeeds and never echoes owner_tok
            st_unauth, _, _ = self._http_json(srv.bound_port, srv.expected_host_header, "POST", "/api/pair-code")
            self.assertEqual(st_unauth, 401)

            st_mint, _, mint_doc = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-code",
                token=owner_tok,
                body_obj={},
            )
            self.assertEqual(st_mint, 200)
            self.assertIsInstance(mint_doc, dict)
            assert_doc = dict(mint_doc) if isinstance(mint_doc, dict) else {}
            self.assertNotIn(owner_tok, json.dumps(assert_doc))
            self.assertEqual(assert_doc.get("ttl_seconds"), 120)
            self.assertEqual(assert_doc.get("scope"), SESSION_SCOPE_DEVICE_READ_EXPLAINER)
            self.assertIn("?pair_code=pair-", str(assert_doc.get("pairing_url", "")))

    def test_finding_2_single_use_pair_exchange_replay_expiry_revocation_and_rate_limit(self) -> None:
        fake_mono = [1000.0]
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                profit_vault=st.profit_vault,
                owner_recovery=st.owner_recovery,
                mono_clock=lambda: fake_mono[0],
            )
            srv.start()
            self.addCleanup(srv.stop)
            owner_tok = srv.auth_token

            # 1. Single-use atomic exchange succeeds once, replay fails with 401
            _, _, m1 = self._http_json(
                srv.bound_port, srv.expected_host_header, "POST", "/api/pair-code", token=owner_tok
            )
            code1 = str(m1["pair_code"])  # type: ignore[index]
            st_ex1, _, ex1 = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": code1},
            )
            self.assertEqual(st_ex1, 200)
            dev_tok = str(ex1["session_token"])  # type: ignore[index]
            self.assertNotEqual(dev_tok, owner_tok)
            self.assertEqual(ex1["session_scope"], SESSION_SCOPE_DEVICE_READ_EXPLAINER)  # type: ignore[index]
            self.assertFalse(bool(ex1["owner_controls_allowed"]))  # type: ignore[index]

            st_replay, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": code1},
            )
            self.assertEqual(st_replay, 401)

            # 2. Server-side 120s TTL expiry fails closed with 401
            _, _, m2 = self._http_json(
                srv.bound_port, srv.expected_host_header, "POST", "/api/pair-code", token=owner_tok
            )
            code2 = str(m2["pair_code"])  # type: ignore[index]
            fake_mono[0] += 121.0
            st_exp, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": code2},
            )
            self.assertEqual(st_exp, 401)

            # 3. POST /api/pair-revoke immediately revokes unconsumed pair_code AND active device session
            _, _, m3 = self._http_json(
                srv.bound_port, srv.expected_host_header, "POST", "/api/pair-code", token=owner_tok
            )
            code3 = str(m3["pair_code"])  # type: ignore[index]
            st_dev_before, _, _ = self._http_json(
                srv.bound_port, srv.expected_host_header, "GET", "/api/treasury", token=dev_tok
            )
            self.assertEqual(st_dev_before, 200)

            st_rev, _, rev_doc = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-revoke",
                token=owner_tok,
                body_obj={"revoke_sessions": True},
            )
            self.assertEqual(st_rev, 200)
            self.assertGreaterEqual(int(rev_doc["revoked_codes"]), 1)  # type: ignore[index]
            self.assertGreaterEqual(int(rev_doc["revoked_sessions"]), 1)  # type: ignore[index]

            st_code3_after, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": code3},
            )
            self.assertEqual(st_code3_after, 401)
            st_dev_after, _, _ = self._http_json(
                srv.bound_port, srv.expected_host_header, "GET", "/api/treasury", token=dev_tok
            )
            self.assertEqual(st_dev_after, 401)

            # 4. Exchange rate limit returns 429 after burst of attempts
            fake_mono[0] += 65.0
            statuses: list[int] = []
            for idx in range(12):
                st_rl, _, _ = self._http_json(
                    srv.bound_port,
                    srv.expected_host_header,
                    "POST",
                    "/api/pair-exchange",
                    body_obj={"pair_code": f"pair-invalid-attempt-{idx:020d}"},
                )
                statuses.append(st_rl)
            self.assertIn(429, statuses)

    def test_finding_2_paired_device_scope_allows_reads_and_explainer_but_blocks_all_owner_controls_403(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            reg = FrontierModelRegistry(environ={}, clock=lambda: T0)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                ai_model_registry=reg,
                profit_vault=st.profit_vault,
                parallel_tiers=st.parallel_tiers,
                owner_recovery=st.owner_recovery,
            )
            srv.start()
            self.addCleanup(srv.stop)
            owner_tok = srv.auth_token

            minted = srv.mint_pairing_code()
            st_ex, _, ex_doc = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/pair-exchange",
                body_obj={"pair_code": minted["pair_code"]},
            )
            self.assertEqual(st_ex, 200)
            dev_tok = str(ex_doc["session_token"])  # type: ignore[index]

            # Read routes + Explainer + TTS allowed for paired device
            st_sess, _, sess_doc = self._http_json(
                srv.bound_port, srv.expected_host_header, "GET", "/api/auth-session", token=dev_tok
            )
            self.assertEqual(st_sess, 200)
            self.assertEqual(sess_doc["session_scope"], SESSION_SCOPE_DEVICE_READ_EXPLAINER)  # type: ignore[index]
            self.assertFalse(bool(sess_doc["owner_controls_allowed"]))  # type: ignore[index]

            for read_route in ("/api/health", "/api/treasury", "/api/ai-models", "/api/parallel-tiers"):
                st_r, _, _ = self._http_json(
                    srv.bound_port, srv.expected_host_header, "GET", read_route, token=dev_tok
                )
                self.assertEqual(st_r, 200, read_route)

            st_ask, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/explainer-ask",
                token=dev_tok,
                body_obj={"question": "What is my Bank Vault balance?"},
            )
            self.assertEqual(st_ask, 200)

            st_tts, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/explainer-tts",
                token=dev_tok,
                body_obj={"text": "Status check"},
            )
            self.assertEqual(st_tts, 200)

            # ALL owner control/model/treasury/pairing POST routes MUST return 403 Forbidden for paired device!
            owner_only_routes = (
                "/api/ai-overseer-action",
                "/api/ai-trader-control",
                "/api/select-ai-model",
                "/api/ai-model-select",
                "/api/thinking-depth",
                "/api/treasury-config",
                "/api/treasury-prepare",
                "/api/treasury-action",
                "/api/pair-code",
                "/api/pair-revoke",
                "/api/rotate-token",
                "/api/prepare-control",
                "/api/request-control",
                "/api/prepare-close",
                "/api/request-reviewed-close",
            )
            for priv_route in owner_only_routes:
                st_priv, _, priv_doc = self._http_json(
                    srv.bound_port,
                    srv.expected_host_header,
                    "POST",
                    priv_route,
                    token=dev_tok,
                    body_obj={"action": "PAUSE_NEW_RISK"},
                )
                self.assertEqual(st_priv, 403, f"Expected 403 for paired token on {priv_route}")
                self.assertEqual(priv_doc["required_scope"], SESSION_SCOPE_OWNER_FULL)  # type: ignore[index]

            # Paired token also rejected on dedicated emergency channel (403)
            st_em_dev, _, _ = self._http_json(
                srv.emergency_port,
                srv.emergency_expected_host_header,
                "POST",
                "/api/ai-overseer-action",
                token=dev_tok,
                body_obj={"action": "PAUSE_NEW_RISK"},
            )
            self.assertEqual(st_em_dev, 403)

            # Owner primary bearer retains full control
            st_owner_sess, _, owner_sess = self._http_json(
                srv.bound_port, srv.expected_host_header, "GET", "/api/auth-session", token=owner_tok
            )
            self.assertEqual(st_owner_sess, 200)
            self.assertEqual(owner_sess["session_scope"], SESSION_SCOPE_OWNER_FULL)  # type: ignore[index]
            self.assertTrue(bool(owner_sess["owner_controls_allowed"]))  # type: ignore[index]

    # ------------------------------------------------------------------
    # Finding [8]: Auxiliary routes (/api/explainer-ask & /api/explainer-tts) gated by DurableModelExecutionGate
    # ------------------------------------------------------------------
    def test_finding_8_explainer_ask_transcription_and_tts_enforce_durable_model_execution_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "gate.sqlite3"
            gate = DurableModelExecutionGate(
                db_path,
                max_calls_per_day=2,
                max_daily_spend_usd=Decimal("5.00"),
                clock=lambda: T0,
            )
            pcm_b64 = base64.b64encode(b"\x00\x10" * 32).decode("ascii")

            def stub_gemini(url: str, _hdrs: dict[str, str], _body: bytes, _t: float, _m: int) -> tuple[int, bytes]:
                if f"models/{DEFAULT_EXPLAINER_MODEL_ID}:generateContent" in url:
                    return 200, json.dumps({
                        "candidates": [{
                            "content": {
                                "parts": [{"text": json.dumps({"spoken_question": "Status?", "answer": "All clear."})}]
                            }
                        }],
                        "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 24},
                    }).encode("utf-8")
                if f"models/{DEFAULT_EXPLAINER_TTS_MODEL_ID}:generateContent" in url:
                    return 200, json.dumps({
                        "candidates": [{
                            "content": {
                                "parts": [{"inlineData": {"mimeType": "audio/pcm;rate=24000", "data": pcm_b64}}]
                            }
                        }],
                        "usageMetadata": {"promptTokenCount": 20, "candidatesTokenCount": 80},
                    }).encode("utf-8")
                raise RuntimeError(f"unexpected URL {url}")

            reg = FrontierModelRegistry(
                environ={"CAS_FOREX_GEMINI_API_KEY": DUMMY_CRED},
                http_post=stub_gemini,
                resolve_dns=lambda _h: ["142.250.0.1"],
                clock=lambda: T0,
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                ai_model_registry=reg,
                model_execution_gate=gate,
            )
            srv.start()
            self.addCleanup(srv.stop)
            tok = srv.auth_token

            clip_b64 = base64.b64encode(b"OGG_AUDIO_CLIP_123456").decode("ascii")
            st1, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/explainer-ask",
                token=tok,
                body_obj={"audio_base64": clip_b64, "audio_mime_type": "audio/ogg"},
            )
            self.assertEqual(st1, 200)
            self.assertEqual(int(gate.snapshot(now=T0)["calls_count"]), 1)  # type: ignore[arg-type]

            st2, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/explainer-tts",
                token=tok,
                body_obj={"text": "All clear.", "voice_name": "Kore"},
            )
            self.assertEqual(st2, 200)
            self.assertEqual(int(gate.snapshot(now=T0)["calls_count"]), 2)  # type: ignore[arg-type]

            # 3rd auxiliary call exceeds max_calls_per_day=2 -> rejected with 429 MODEL_BUDGET_EXHAUSTED!
            st3_ask, _, doc3_ask = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/explainer-ask",
                token=tok,
                body_obj={"question": "Can I bypass the spend gate?"},
            )
            self.assertEqual(st3_ask, 429)
            self.assertEqual(doc3_ask["code"], "MODEL_BUDGET_EXHAUSTED")  # type: ignore[index]

            st3_tts, _, doc3_tts = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/explainer-tts",
                token=tok,
                body_obj={"text": "Bypass TTS?", "voice_name": "Kore"},
            )
            self.assertEqual(st3_tts, 429)
            self.assertEqual(doc3_tts["code"], "MODEL_BUDGET_EXHAUSTED")  # type: ignore[index]

    # ------------------------------------------------------------------
    # Finding [13]: Intent-before-approval exact digest & atomic token+reservation commit
    # ------------------------------------------------------------------
    def test_finding_13_wildcard_treasury_tokens_rejected_in_mint_consume_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rec = OwnerRecoveryVerifier(db_path=root / "state.sqlite3", clock=lambda: T0)
            with self.assertRaises(ContractError):
                rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            with self.assertRaises(ContractError):
                rec.mint_token(action_scope="TREASURY_SWEEP", target_ref="*", now=T0)
            with self.assertRaises(ContractError):
                rec.mint_token(action_scope="TREASURY_SWEEP", target_ref="   ", now=T0)

            # Even a validly HMAC-signed raw wildcard token in DB must be rejected by verify_and_consume
            rec.ensure_initialized()
            key = _load_or_create_recovery_key(root / ".owner_recovery.key")
            tid_raw = "rec-forgedwild000000000001"
            iss = "2026-11-20T15:00:00Z"
            exp = "2026-11-20T15:15:00Z"
            msg = f"cas-forex-owner-recovery/1|{tid_raw}|TREASURY_SWEEP|*|{iss}|{exp}"
            sig = hmac.new(key, msg.encode("utf-8"), sha256).hexdigest()
            with closing(sqlite3.connect(str(root / "state.sqlite3"))) as conn:
                conn.execute(
                    "INSERT INTO owner_recovery_tokens VALUES (?, 'TREASURY_SWEEP', '*', ?, ?, ?, NULL, NULL)",
                    (tid_raw, iss, exp, sig),
                )
                conn.commit()
            forged_tok = "casrx1." + base64.urlsafe_b64encode(
                canonical_bytes({
                    "protocol": "cas-forex-owner-recovery/1",
                    "token_id": tid_raw,
                    "action_scope": "TREASURY_SWEEP",
                    "target_ref": "*",
                    "issued_at_utc": iss,
                    "expires_at_utc": exp,
                    "hmac_sha256": sig,
                })
            ).decode("ascii").rstrip("=")
            with self.assertRaises(ContractError):
                rec.verify_and_consume(
                    forged_tok,
                    expected_scope="TREASURY_SWEEP",
                    target_ref="a" * 64,
                    require_exact_target=False,
                    owner_request_id="req-wild-bypass",
                    now=T0,
                )

            # CLI --mint-recovery-token refuses TREASURY_SWEEP without --target-ref and succeeds with --target-ref
            cli_dir = root / "cli_state"
            with self.assertRaises(ContractError):
                run_cockpit_cli(
                    ["--state-dir", str(cli_dir), "--mint-recovery-token", "--recovery-scope", "TREASURY_SWEEP"],
                    environ={},
                    repo_root=REPO_ROOT,
                )
            rc = run_cockpit_cli(
                [
                    "--state-dir",
                    str(cli_dir),
                    "--mint-recovery-token",
                    "--recovery-scope",
                    "TREASURY_SWEEP",
                    "--target-ref",
                    "b" * 64,
                ],
                environ={},
                repo_root=REPO_ROOT,
            )
            self.assertEqual(rc, 0)

    def test_finding_13_prepared_intent_exact_digest_rejects_any_parameter_tampering_on_2fa_and_ach(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pem_p = root / "cb.pem"
            _write_ec_pem(pem_p)
            vault = ProfitSweepVault(root / "vault.sqlite3", scope_id="scope-alpha", clock=lambda: T0)
            vault.record_realized_close(
                trade_id="tr-p13-1", symbol="EURUSD", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=Decimal("600.00")
            )  # $300.00 bank sweep reserve
            rec = OwnerRecoveryVerifier(db_path=root / "rec.sqlite3", clock=lambda: T0)

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-pinned-01",
                http_call=lambda *_a: (200, json.dumps({"id": "cb-tx-13"}).encode("utf-8")),
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            krk = KrakenOfframpClient(
                api_key="krk-key-01",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="krk-bank-pinned-01",
                http_call=lambda *_a: (200, json.dumps({"error": [], "result": {"refid": "KRK-13"}}).encode("utf-8")),
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )

            # Un-prepared calls fail closed
            tok_dummy = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref="c" * 64, now=T0)
            with self.assertRaises(ContractError):
                vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=Decimal("50.00"),
                    owner_request_id="req-unprep",
                    reason="no prepare",
                    verifier=rec,
                    recovery_token=tok_dummy,
                )
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=Decimal("50.00"),
                    owner_request_id="req-unprep-ach",
                    reason="no prepare",
                    verifier=rec,
                    recovery_token=tok_dummy,
                    coinbase_client=cb,
                )

            # Prepare 2FA withdrawal ($80.00, HUGOSWAY_MT5, bank-A, req-2fa-exact)
            prep_2fa = vault.prepare_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=Decimal("80.00"),
                owner_request_id="req-2fa-exact",
                reason="exact 2fa",
                destination_bank_label="bank-A",
            )
            tok_2fa = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_2fa["intent_sha256"], now=T0)

            # Tampered amount, broker, destination, owner_request_id, or cross-action substitution MUST fail closed!
            with self.assertRaises(ContractError):
                vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=Decimal("80.01"),
                    owner_request_id="req-2fa-exact",
                    reason="exact 2fa",
                    verifier=rec,
                    recovery_token=tok_2fa,
                    destination_bank_label="bank-A",
                    intent_id=prep_2fa["intent_id"],
                )
            with self.assertRaises(ContractError):
                vault.request_broker_2fa_withdrawal(
                    broker_id="LHFX_MT5",
                    amount_usd=Decimal("80.00"),
                    owner_request_id="req-2fa-exact",
                    reason="exact 2fa",
                    verifier=rec,
                    recovery_token=tok_2fa,
                    destination_bank_label="bank-A",
                    intent_id=prep_2fa["intent_id"],
                )
            with self.assertRaises(OfframpSecurityError):
                vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=Decimal("80.00"),
                    owner_request_id="req-2fa-exact",
                    reason="exact 2fa",
                    verifier=rec,
                    recovery_token=tok_2fa,
                    destination_bank_label="bank-HIJACK",
                    intent_id=prep_2fa["intent_id"],
                )
            # Token approved for 2FA withdrawal CANNOT be substituted into ACH payout!
            with self.assertRaises((ContractError, OfframpSecurityError)):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=Decimal("80.00"),
                    owner_request_id="req-2fa-exact",
                    reason="cross action",
                    verifier=rec,
                    recovery_token=tok_2fa,
                    coinbase_client=cb,
                    intent_id=prep_2fa["intent_id"],
                )

            # Exact parameters succeed with unconsumed tok_2fa!
            res_2fa = vault.request_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=Decimal("80.00"),
                owner_request_id="req-2fa-exact",
                reason="exact 2fa",
                verifier=rec,
                recovery_token=tok_2fa,
                destination_bank_label="bank-A",
                intent_id=prep_2fa["intent_id"],
                intent_sha256=prep_2fa["intent_sha256"],
            )
            self.assertEqual(res_2fa["transfer_id"], prep_2fa["transfer_id"])

            # Prepare ACH payout with conversion fields and verify conversion/rail/amount tampering fails closed
            prep_ach = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=Decimal("70.00"),
                owner_request_id="req-ach-exact",
                reason="exact ach",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=Decimal("70.00"),
                coinbase_source_account_uuid="src-uuid-1",
                coinbase_usd_account_uuid="usd-uuid-1",
            )
            tok_ach = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_ach["intent_sha256"], now=T0)
            with self.assertRaises(ContractError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=Decimal("70.00"),
                    owner_request_id="req-ach-exact",
                    reason="exact ach",
                    verifier=rec,
                    recovery_token=tok_ach,
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=Decimal("75.00"),  # altered conversion amount!
                    coinbase_source_account_uuid="src-uuid-1",
                    coinbase_usd_account_uuid="usd-uuid-1",
                    intent_id=prep_ach["intent_id"],
                )
            with self.assertRaises((ContractError, OfframpSecurityError)):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,  # altered rail!
                    amount_usd=Decimal("70.00"),
                    owner_request_id="req-ach-exact",
                    reason="exact ach",
                    verifier=rec,
                    recovery_token=tok_ach,
                    kraken_client=krk,
                    intent_id=prep_ach["intent_id"],
                )

            # End-to-end HTTP POST /api/treasury-prepare -> mint -> POST /api/treasury-action
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT, port=0, profit_vault=vault, owner_recovery=rec
            )
            srv.start()
            self.addCleanup(srv.stop)
            st_p, _, http_prep = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/treasury-prepare",
                token=srv.auth_token,
                body_obj={
                    "action": "REQUEST_BROKER_2FA_WITHDRAWAL",
                    "broker_id": BROKER_HUGOSWAY_MT5,
                    "amount_usd": "40.00",
                    "owner_request_id": "req-http-prep-1",
                    "reason": "cockpit prepare",
                },
            )
            self.assertEqual(st_p, 200)
            tok_http = rec.mint_token(
                action_scope="TREASURY_SWEEP",
                target_ref=str(http_prep["intent_sha256"]),  # type: ignore[index]
                now=T0,
            )
            st_tamper, _, _ = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/treasury-action",
                token=srv.auth_token,
                body_obj={
                    "action": "REQUEST_BROKER_2FA_WITHDRAWAL",
                    "broker_id": BROKER_HUGOSWAY_MT5,
                    "amount_usd": "99.00",
                    "owner_request_id": "req-http-prep-1",
                    "reason": "cockpit prepare",
                    "intent_id": http_prep["intent_id"],  # type: ignore[index]
                    "intent_sha256": http_prep["intent_sha256"],  # type: ignore[index]
                    "recovery_token": tok_http,
                },
            )
            self.assertEqual(st_tamper, 400)

            st_exec, _, exec_doc = self._http_json(
                srv.bound_port,
                srv.expected_host_header,
                "POST",
                "/api/treasury-action",
                token=srv.auth_token,
                body_obj={
                    "action": "REQUEST_BROKER_2FA_WITHDRAWAL",
                    "broker_id": BROKER_HUGOSWAY_MT5,
                    "amount_usd": "40.00",
                    "owner_request_id": "req-http-prep-1",
                    "reason": "cockpit prepare",
                    "intent_id": http_prep["intent_id"],  # type: ignore[index]
                    "intent_sha256": http_prep["intent_sha256"],  # type: ignore[index]
                    "recovery_token": tok_http,
                },
            )
            self.assertEqual(st_exec, 200)
            self.assertEqual(exec_doc["transfer_id"], http_prep["transfer_id"])  # type: ignore[index]
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    def test_finding_13_atomic_rollback_leaves_recovery_token_unconsumed_on_db_reservation_failure(self) -> None:
        for same_db in (False, True):
            with self.subTest(same_db=same_db), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                vault_db = root / ("shared.sqlite3" if same_db else "vault.sqlite3")
                rec_db = vault_db if same_db else (root / "rec.sqlite3")
                vault = ProfitSweepVault(vault_db, clock=lambda: T0)
                vault.record_realized_close(
                    trade_id="tr-atom-1",
                    symbol="EURUSD",
                    broker_id=BROKER_HUGOSWAY_MT5,
                    realized_net_usd=Decimal("300.00"),
                )
                rec = OwnerRecoveryVerifier(db_path=rec_db, clock=lambda: T0)
                prep = vault.prepare_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=Decimal("60.00"),
                    owner_request_id="req-atomic-1",
                    reason="atomic test",
                )
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)

                # Inject SQLite ABORT trigger on bank_transfers INSERT to simulate reservation DB failure
                with closing(sqlite3.connect(str(vault_db))) as conn:
                    conn.execute(
                        "CREATE TRIGGER fail_bt_insert BEFORE INSERT ON bank_transfers "
                        "BEGIN SELECT RAISE(ABORT, 'simulated_db_reservation_failure'); END;"
                    )
                    conn.commit()

                with self.assertRaises(sqlite3.IntegrityError):
                    vault.request_broker_2fa_withdrawal(
                        broker_id=BROKER_HUGOSWAY_MT5,
                        amount_usd=Decimal("60.00"),
                        owner_request_id="req-atomic-1",
                        reason="atomic test",
                        verifier=rec,
                        recovery_token=tok,
                        intent_id=prep["intent_id"],
                        intent_sha256=prep["intent_sha256"],
                    )

                # Verify ZERO split-brain: no transfer inserted, intent still PREPARED, recovery token UNCONSUMED!
                self.assertEqual(vault.snapshot()["recent_transfers"], [])
                with closing(sqlite3.connect(str(rec_db))) as conn:
                    t_row = conn.execute("SELECT consumed_at_utc FROM owner_recovery_tokens").fetchone()
                    self.assertIsNotNone(t_row)
                    self.assertIsNone(t_row[0])

                # Remove transient DB failure trigger; SAME unconsumed token + prepared intent now succeeds cleanly!
                with closing(sqlite3.connect(str(vault_db))) as conn:
                    conn.execute("DROP TRIGGER fail_bt_insert")
                    conn.commit()

                ok = vault.request_broker_2fa_withdrawal(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    amount_usd=Decimal("60.00"),
                    owner_request_id="req-atomic-1",
                    reason="atomic test",
                    verifier=rec,
                    recovery_token=tok,
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )
                self.assertEqual(ok["status"], "PENDING_OWNER_BROKER_2FA")

    # ------------------------------------------------------------------
    # Finding [14]: Pre-auth request-line deadline & isolated owner emergency channel
    # ------------------------------------------------------------------
    def test_finding_14_slow_drip_before_request_line_terminated_at_absolute_pre_auth_deadline_and_oversized_rejected(self) -> None:
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            pre_auth_timeout_seconds=0.35,
        )
        srv.start()
        self.addCleanup(srv.stop)

        # 1. Slow-drip 1 byte every 50ms BEFORE request line newline MUST terminate right at ~0.35s!
        t_start = time.monotonic()
        drip = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=2.0)
        try:
            closed = False
            for ch in b"GET /api/health HTTP/1.1 -- slow drip without newline":
                time.sleep(0.05)
                try:
                    drip.sendall(bytes([ch]))
                except OSError:
                    closed = True
                    break
            if not closed:
                drip.settimeout(0.3)
                try:
                    rem_data = drip.recv(256)
                    closed = rem_data == b""
                except OSError:
                    closed = True
            elapsed = time.monotonic() - t_start
            self.assertTrue(closed)
            self.assertLess(elapsed, 1.5)
            self.assertGreaterEqual(srv.pre_auth_timeouts_total, 1)
        finally:
            drip.close()

        # 2. Cumulative >16 KiB pre-auth request line rejected immediately with 431
        big = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=2.0)
        try:
            big.sendall(b"GET /" + (b"x" * 17000) + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            big.settimeout(1.0)
            resp_bytes = big.recv(4096)
            self.assertIn(b"431", resp_bytes)
        finally:
            big.close()

    def test_finding_14_all_16_ordinary_slots_held_by_slow_drip_never_blocks_owner_emergency_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            gate = load_default_forex_valve_gate()
            router = DualShieldBrokerRouter(
                environ={ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO},
                valve_gate=gate,
                clock=lambda: T0,
            )
            reg = FrontierModelRegistry(environ={}, clock=lambda: T0)
            quota = DailyQuotaGovernanceStore(path=Path(td) / "quota.sqlite3")
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=gate,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                clock=lambda: T0,
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                max_ordinary_connections=16,
                max_emergency_connections=4,
                pre_auth_timeout_seconds=1.5,
                ai_model_registry=reg,
                autonomous_trader=trader,
            )
            srv.start()
            self.addCleanup(srv.stop)

            stop_drip = threading.Event()
            ready_count = [0]
            ready_lock = threading.Lock()
            drip_socks: list[socket.socket] = []

            def hold_slow_drip() -> None:
                s = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=2.0)
                with ready_lock:
                    drip_socks.append(s)
                    ready_count[0] += 1
                idx = 0
                payload = b"GET /slow-drip-hold-without-newline-"
                while not stop_drip.wait(0.06):
                    try:
                        s.sendall(bytes([payload[idx % len(payload)]]))
                        idx += 1
                    except OSError:
                        break

            threads = [threading.Thread(target=hold_slow_drip, daemon=True) for _ in range(16)]
            for t in threads:
                t.start()
            try:
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    with ready_lock:
                        if ready_count[0] == 16:
                            break
                    time.sleep(0.02)
                time.sleep(0.05)

                # Connection #17 on ordinary port gets immediate 503 (unauthenticated sockets NEVER touch emergency pool!)
                s17 = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=1.5)
                try:
                    s17.settimeout(1.0)
                    raw17 = s17.recv(1024)
                    self.assertIn(b"503", raw17)
                finally:
                    s17.close()

                # WHILE ALL 16 ORDINARY SLOTS ARE HELD OPEN, authenticated owner emergency controls succeed immediately!
                for emerg_action in ("PAUSE_NEW_RISK", "STOP_AUTOMATION", "EMERGENCY_CLOSE_ALL"):
                    st_em, _, em_doc = self._http_json(
                        srv.emergency_port,
                        srv.emergency_expected_host_header,
                        "POST",
                        "/api/ai-overseer-action",
                        token=srv.auth_token,
                        body_obj={"action": emerg_action, "reason": "saturation safety test"},
                    )
                    self.assertEqual(st_em, 200, f"Emergency {emerg_action} failed under 16-slot saturation: {em_doc}")
            finally:
                stop_drip.set()
                for t in threads:
                    t.join(timeout=2.0)
                with ready_lock:
                    for s in drip_socks:
                        try:
                            s.close()
                        except OSError:
                            pass


if __name__ == "__main__":
    unittest.main()
