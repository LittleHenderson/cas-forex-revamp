"""PR #18 verification tests:
1. Gemini 4 Neon (`models/gemini-4-neon`) Explainer routing via `x-goog-api-key` header (zero key in URL)
   without altering `active_model_id` (`claude-fable-5.2`) or trading model call stats.
2. Enriched sanitized `ctx_summary` in `POST /api/explainer-ask` covering `broker_routing`, `live_readiness`,
   `ai_trader`, `treasury`, and 5 `parallel_tiers` with zero leaked secrets or bank account UUIDs.
3. `POST /api/explainer-tts` via `gemini-3.8-flash-tts`, automatic fallback to `gemini-3.8-flash-lite-tts`,
   graceful `WEB_SPEECH` fallback when unconfigured, and `401` when unauthenticated.
4. Multimodal `audio_base64` + `audio_mime_type` voice question handling returning `spoken_question` + `answer`.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal
import http.client
import json
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.operator.frontier_backends import (
    DEFAULT_EXPLAINER_MODEL_ID,
    DEFAULT_EXPLAINER_TTS_MODEL_ID,
    ENV_ANTHROPIC_API_KEY,
    ENV_EXPLAINER_MODEL_ID,
    ENV_EXPLAINER_TTS_MODEL_ID,
    ENV_GEMINI_API_KEY,
    FALLBACK_EXPLAINER_TTS_MODEL_ID,
    FrontierConfigurationError,
    FrontierModelRegistry,
)
from cas_forex_revamp.treasury import ProfitSweepVault
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter, OandaQuoteTruthOracle
from cas_forex_revamp.venue.external_paper_broker import ENV_EXECUTION_MODE, EXECUTION_MODE_DEMO
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    ENV_HUGOSWAY_MT5_LOGIN,
    ENV_HUGOSWAY_MT5_PASSWORD,
)

GATE = load_default_forex_valve_gate()
T0 = datetime(2026, 11, 19, 21, 0, 0, tzinfo=timezone.utc)
DUMMY_VAL = "demo-v1"
REPO_ROOT = Path(__file__).resolve().parents[2]


class Pr18NeonVoiceExplainerTests(unittest.TestCase):
    def test_neon_routing_keeps_claude_fable_active_and_uses_header_key_only(self) -> None:
        observed_calls: list[tuple[str, dict[str, str], dict[str, object]]] = []

        def fake_post(
            url: str, headers: dict[str, str], body: bytes, _timeout: float, _max_bytes: int
        ) -> tuple[int, bytes]:
            observed_calls.append((url, dict(headers), json.loads(body.decode("utf-8"))))
            resp = {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"thought": True, "text": "internal reasoning"},
                                {
                                    "text": json.dumps({
                                        "spoken_question": "",
                                        "answer": "Your Dual-Shield barbell holds 80 percent in OANDA, 12 percent in Hugo's Way, and 8 percent in LHFX.",
                                    })
                                },
                            ]
                        }
                    }
                ]
            }
            return 200, json.dumps(resp).encode("utf-8")

        reg = FrontierModelRegistry(
            environ={
                ENV_ANTHROPIC_API_KEY: DUMMY_VAL,
                ENV_GEMINI_API_KEY: DUMMY_VAL,
            },
            clock=lambda: T0,
            http_post=fake_post,
            resolve_dns=lambda _h: None,
        )
        # Trading brain remains pinned to rank #1 Claude Fable 5.2
        self.assertEqual(reg.active_model_id, "claude-fable-5.2")

        ans = reg.answer_explainer_question(
            "Explain the 80/12/8 Dual-Shield Barbell",
            context_summary={"execution_mode": "DEMO", "active_broker": BROKER_HUGOSWAY_MT5},
        )
        self.assertEqual(len(observed_calls), 1)
        called_url, called_headers, called_body = observed_calls[0]
        self.assertEqual(
            called_url,
            f"https://generativelanguage.googleapis.com/v1beta/models/{DEFAULT_EXPLAINER_MODEL_ID}:generateContent",
        )
        self.assertNotIn("?", called_url)
        self.assertNotIn(DUMMY_VAL, called_url)
        self.assertEqual(called_headers.get("x-goog-api-key"), DUMMY_VAL)
        sys_txt = called_body["systemInstruction"]["parts"][0]["text"]  # type: ignore[index]
        self.assertIn("80/12/8", sys_txt)
        self.assertIn("tks_meta_valve_controller", sys_txt)
        self.assertIn("ARM_LIVE_REAL_MONEY_TRADING", sys_txt)

        self.assertEqual(ans["schema"], "cas-forex.explainer-answer/1")
        self.assertEqual(ans["model_id"], DEFAULT_EXPLAINER_MODEL_ID)
        self.assertEqual(ans["display_name"], "Gemini 4 Neon")
        self.assertEqual(ans["source"], "FRONTIER_READ_ONLY")
        self.assertTrue(ans["read_only"])
        self.assertTrue(ans["advisory_only"])
        self.assertTrue(ans["voice_ready"])
        self.assertIn("80 percent", ans["answer"])

        # Active trading model and its call counter remain completely untouched
        snap_after = reg.catalog_snapshot()
        self.assertEqual(snap_after["active_model_id"], "claude-fable-5.2")
        fable_row = next(m for m in snap_after["models"] if m["model_id"] == "claude-fable-5.2")
        self.assertEqual(fable_row["calls"], 0)
        self.assertEqual(ENV_EXPLAINER_MODEL_ID, "CAS_FOREX_EXPLAINER_MODEL_ID")
        self.assertEqual(ENV_EXPLAINER_TTS_MODEL_ID, "CAS_FOREX_EXPLAINER_TTS_MODEL_ID")

    def test_multimodal_audio_question_and_validation(self) -> None:
        captured_parts: list[dict[str, object]] = []

        def fake_audio_post(
            _url: str, _headers: dict[str, str], body: bytes, _timeout: float, _max_bytes: int
        ) -> tuple[int, bytes]:
            parsed = json.loads(body.decode("utf-8"))
            captured_parts.extend(parsed["contents"][0]["parts"])
            resp = {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps({
                                        "spoken_question": "What risk gear am I in right now?",
                                        "answer": "You are currently in Growth Gear at 2.50 percent risk with zero consecutive losses.",
                                    })
                                }
                            ]
                        }
                    }
                ]
            }
            return 200, json.dumps(resp).encode("utf-8")

        reg = FrontierModelRegistry(
            environ={ENV_GEMINI_API_KEY: DUMMY_VAL},
            clock=lambda: T0,
            http_post=fake_audio_post,
            resolve_dns=lambda _h: None,
        )
        sample_clip_b64 = base64.b64encode(b"WEBM_VOICE_SAMPLE_BYTES_0123456789").decode("ascii")
        res = reg.answer_explainer_question(
            "",
            context_summary={"execution_mode": "DEMO"},
            audio_base64=sample_clip_b64,
            audio_mime_type="audio/webm;codecs=opus",
        )
        self.assertEqual(len(captured_parts), 2)
        self.assertEqual(
            captured_parts[0],
            {"inlineData": {"mimeType": "audio/webm", "data": sample_clip_b64}},
        )
        self.assertEqual(res["spoken_question"], "What risk gear am I in right now?")
        self.assertEqual(res["question"], "What risk gear am I in right now?")
        self.assertIn("Growth Gear", res["answer"])

        with self.assertRaises(FrontierConfigurationError):
            reg.answer_explainer_question(
                "",
                audio_base64=sample_clip_b64,
                audio_mime_type="video/mp4",
            )

    def test_cockpit_explainer_ask_enriches_sanitized_context_and_tts_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            oracle = OandaQuoteTruthOracle.from_static_quotes({"NAS100": (Decimal("20500.00"), Decimal("20502.50"))})
            router = DualShieldBrokerRouter(
                environ={
                    ENV_EXECUTION_MODE: EXECUTION_MODE_DEMO,
                    ENV_HUGOSWAY_MT5_LOGIN: "7009911",
                    ENV_HUGOSWAY_MT5_PASSWORD: DUMMY_VAL,
                    "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "1.00",
                    "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.10",
                },
                valve_gate=GATE,
                oracle=oracle,
                equity_attestations={
                    BROKER_OANDA_PRACTICE: Decimal("80000"),
                    BROKER_HUGOSWAY_MT5: Decimal("12000"),
                    BROKER_LHFX_MT5: Decimal("8000"),
                },
                clock=lambda: T0,
            )
            quota = DailyQuotaGovernanceStore(
                soft_quota_usd=Decimal("2000"),
                hard_quota_usd=Decimal("3000"),
                max_loss_usd=Decimal("5000"),
            )
            vault = ProfitSweepVault(root / "vault.sqlite3", clock=lambda: T0)
            vault.record_realized_close(
                trade_id="t-1", symbol="NAS100", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=Decimal("400.00")
            )
            verifier = OwnerRecoveryVerifier(db_path=root / "rec.sqlite3", clock=lambda: T0)
            secret_bank_uuid = "bank-acct-uuid-99887766"
            prep_2fa = vault.prepare_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=Decimal("50.00"),
                owner_request_id="req-2fa-1",
                reason="test 2fa reserve",
                destination_bank_label=secret_bank_uuid,
            )
            rec_tok = verifier.mint_token(
                action_scope="TREASURY_SWEEP",
                target_ref=prep_2fa["intent_sha256"],
                now=T0,
            )
            vault.request_broker_2fa_withdrawal(
                broker_id=BROKER_HUGOSWAY_MT5,
                amount_usd=Decimal("50.00"),
                owner_request_id="req-2fa-1",
                reason="test 2fa reserve",
                verifier=verifier,
                recovery_token=rec_tok,
                destination_bank_label=secret_bank_uuid,
                intent_id=prep_2fa["intent_id"],
                intent_sha256=prep_2fa["intent_sha256"],
            )
            tiers = ParallelTierEngine(root / "tiers.sqlite3", valve_gate=GATE, clock=lambda: T0)

            seen_packets: list[dict[str, object]] = []
            tts_urls: list[str] = []
            pcm_bytes = bytes([0, 16, 255, 239]) * 32
            pcm_b64 = base64.b64encode(pcm_bytes).decode("ascii")

            def fake_gemini_http(
                url: str, headers: dict[str, str], body: bytes, _timeout: float, _max_bytes: int
            ) -> tuple[int, bytes]:
                self.assertEqual(headers.get("x-goog-api-key"), DUMMY_VAL)
                self.assertNotIn(DUMMY_VAL, url)
                req_json = json.loads(body.decode("utf-8"))
                if f"models/{DEFAULT_EXPLAINER_MODEL_ID}:generateContent" in url:
                    parts = req_json["contents"][0]["parts"]
                    pkt = json.loads(parts[-1]["text"])
                    seen_packets.append(pkt)
                    return 200, json.dumps({
                        "candidates": [
                            {
                                "content": {
                                    "parts": [
                                        {
                                            "text": json.dumps({
                                                "spoken_question": "Give me a live status briefing" if len(parts) > 1 else "",
                                                "answer": "Total equity is 100,000 dollars with 200 dollars reserved in your Bank Vault across 5 parallel tiers.",
                                            })
                                        }
                                    ]
                                }
                            }
                        ]
                    }).encode("utf-8")
                if ":generateContent" in url and "tts" in url:
                    tts_urls.append(url)
                    # Simulate primary TTS 404 on second TTS test call when text contains FALLBACK_LITE_TEST
                    spoken_in = req_json["contents"][0]["parts"][0]["text"]
                    if "FALLBACK_LITE_TEST" in spoken_in and DEFAULT_EXPLAINER_TTS_MODEL_ID in url:
                        return 404, b'{"error":{"message":"not found"}}'
                    return 200, json.dumps({
                        "candidates": [
                            {
                                "content": {
                                    "parts": [
                                        {
                                            "inlineData": {
                                                "mimeType": "audio/L16;codec=pcm;rate=24000",
                                                "data": pcm_b64,
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }).encode("utf-8")
                return 500, b"{}"

            reg = FrontierModelRegistry(
                environ={
                    ENV_ANTHROPIC_API_KEY: DUMMY_VAL,
                    ENV_GEMINI_API_KEY: DUMMY_VAL,
                },
                clock=lambda: T0,
                http_post=fake_gemini_http,
                resolve_dns=lambda _h: None,
            )
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=GATE,
                quota_store=quota,
                execution_gate=lambda _inv: None,
                profit_vault=vault,
                parallel_tiers=tiers,
                clock=lambda: T0,
            )
            trader._open_position_meta["55001"] = {
                "ticket": "55001",
                "broker_id": BROKER_HUGOSWAY_MT5,
                "symbol": "NAS100",
                "side": "BUY",
                "volume_lots": "0.10",
                "entry_price": "20502.50",
                "stop_loss": "20477.50",
                "take_profit": "20562.50",
                "profit": "45.00",
                "protection_stage": "BREAKEVEN_LOCKED",
            }

            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                broker_router_reader=router.routing_snapshot,
                ai_model_registry=reg,
                autonomous_trader=trader,
                profit_vault=vault,
                parallel_tiers=tiers,
            )
            srv.start()
            try:
                auth_hdrs = {
                    "Host": srv.expected_host_header,
                    "Origin": f"http://{srv.expected_host_header}",
                    "Authorization": f"Bearer {srv.auth_token}",
                    "Content-Type": "application/json",
                }
                conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5)
                try:
                    # 1. Unauthenticated /api/explainer-tts rejected with 401
                    tts_unauth_body = json.dumps({"text": "Hello Wakil"}).encode("utf-8")
                    conn.request(
                        "POST",
                        "/api/explainer-tts",
                        body=tts_unauth_body,
                        headers={"Host": srv.expected_host_header, "Content-Type": "application/json"},
                    )
                    r_unauth = conn.getresponse()
                    r_unauth.read()
                    self.assertEqual(r_unauth.status, 401)

                    # 2. Enriched /api/explainer-ask context check + zero leaked secrets/UUIDs
                    ask_body = json.dumps({"question": "Give me a full live status briefing"}).encode("utf-8")
                    conn.request("POST", "/api/explainer-ask", body=ask_body, headers=auth_hdrs)
                    r_ask = conn.getresponse()
                    ask_doc = json.loads(r_ask.read().decode("utf-8"))
                    self.assertEqual(r_ask.status, 200)
                    self.assertEqual(ask_doc["model_id"], DEFAULT_EXPLAINER_MODEL_ID)
                    self.assertTrue(ask_doc["voice_ready"])
                    self.assertEqual(len(seen_packets), 1)

                    cockpit_ctx = seen_packets[0]["cockpit"]  # type: ignore[index]
                    raw_ctx_str = json.dumps(cockpit_ctx)
                    self.assertNotIn(DUMMY_VAL, raw_ctx_str)
                    self.assertNotIn("7009911", raw_ctx_str)
                    self.assertNotIn(secret_bank_uuid, raw_ctx_str)
                    self.assertNotIn(srv.auth_token, raw_ctx_str)

                    br_ctx = cockpit_ctx["broker_routing"]  # type: ignore[index]
                    self.assertEqual(br_ctx["total_equity"], "100000")
                    self.assertEqual(len(br_ctx["live_readiness"]["gates"]), 5)
                    tr_ctx = cockpit_ctx["ai_trader"]  # type: ignore[index]
                    self.assertEqual(tr_ctx["active_model_id"], "claude-fable-5.2")
                    self.assertEqual(len(tr_ctx["open_positions"]), 1)
                    self.assertEqual(tr_ctx["open_positions"][0]["symbol"], "NAS100")
                    tr_vault = cockpit_ctx["treasury"]  # type: ignore[index]
                    self.assertEqual(tr_vault["total_realized_profit_usd"], "400")
                    self.assertEqual(tr_vault["bank_sweep_reserved_usd"], "200")
                    self.assertEqual(tr_vault["retained_trading_usd"], "200")
                    self.assertEqual(tr_vault["pending_confirmation_usd"], "50")
                    pt_ctx = cockpit_ctx["parallel_tiers"]  # type: ignore[index]
                    self.assertEqual(len(pt_ctx), 5)

                    # 3. Multimodal audio_base64 without text question over /api/explainer-ask
                    clip_b64 = base64.b64encode(b"OGG_VOICE_DATA_9876543210").decode("ascii")
                    voice_body = json.dumps({
                        "audio_base64": clip_b64,
                        "audio_mime_type": "audio/ogg",
                    }).encode("utf-8")
                    conn.request("POST", "/api/explainer-ask", body=voice_body, headers=auth_hdrs)
                    r_vask = conn.getresponse()
                    vask_doc = json.loads(r_vask.read().decode("utf-8"))
                    self.assertEqual(r_vask.status, 200)
                    self.assertEqual(vask_doc["spoken_question"], "Give me a live status briefing")

                    # 4. Primary TTS (gemini-3.8-flash-tts) returns PCM16 audio_base64 + 24000 Hz
                    tts_body = json.dumps({"text": ask_doc["answer"], "voice_name": "Kore"}).encode("utf-8")
                    conn.request("POST", "/api/explainer-tts", body=tts_body, headers=auth_hdrs)
                    r_tts = conn.getresponse()
                    tts_doc = json.loads(r_tts.read().decode("utf-8"))
                    self.assertEqual(r_tts.status, 200)
                    self.assertEqual(tts_doc["schema"], "cas-forex.explainer-tts/1")
                    self.assertTrue(tts_doc["ok"])
                    self.assertEqual(tts_doc["model_id"], DEFAULT_EXPLAINER_TTS_MODEL_ID)
                    self.assertEqual(tts_doc["voice_name"], "Kore")
                    self.assertEqual(tts_doc["sample_rate_hz"], 24000)
                    self.assertEqual(tts_doc["audio_base64"], pcm_b64)

                    # 5. Automatic fallback to gemini-3.8-flash-lite-tts when primary model returns 404
                    tts_fb_body = json.dumps({"text": "FALLBACK_LITE_TEST spoken answer", "voice_name": "Puck"}).encode("utf-8")
                    conn.request("POST", "/api/explainer-tts", body=tts_fb_body, headers=auth_hdrs)
                    r_tts_fb = conn.getresponse()
                    tts_fb_doc = json.loads(r_tts_fb.read().decode("utf-8"))
                    self.assertEqual(r_tts_fb.status, 200)
                    self.assertTrue(tts_fb_doc["ok"])
                    self.assertEqual(tts_fb_doc["model_id"], FALLBACK_EXPLAINER_TTS_MODEL_ID)
                    self.assertEqual(tts_fb_doc["voice_name"], "Puck")
                finally:
                    conn.close()
            finally:
                srv.stop()

        # 6. Graceful WEB_SPEECH fallback when CAS_FOREX_GEMINI_API_KEY is absent
        reg_no_key = FrontierModelRegistry(environ={}, clock=lambda: T0)
        srv_no_key = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, ai_model_registry=reg_no_key)
        srv_no_key.start()
        try:
            conn2 = http.client.HTTPConnection("127.0.0.1", srv_no_key.bound_port, timeout=5)
            try:
                hdrs2 = {
                    "Host": srv_no_key.expected_host_header,
                    "Origin": f"http://{srv_no_key.expected_host_header}",
                    "Authorization": f"Bearer {srv_no_key.auth_token}",
                    "Content-Type": "application/json",
                }
                b2 = json.dumps({"text": "Fallback speech check"}).encode("utf-8")
                conn2.request("POST", "/api/explainer-tts", body=b2, headers=hdrs2)
                r2 = conn2.getresponse()
                doc2 = json.loads(r2.read().decode("utf-8"))
                self.assertEqual(r2.status, 200)
                self.assertFalse(doc2["ok"])
                self.assertEqual(doc2["fallback"], "WEB_SPEECH")
            finally:
                conn2.close()
        finally:
            srv_no_key.stop()


if __name__ == "__main__":
    unittest.main()
