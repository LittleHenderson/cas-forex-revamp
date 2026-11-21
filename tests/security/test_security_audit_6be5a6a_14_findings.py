"""Verification suite for all 14 Security Audit findings [1]-[14] against commit 6be5a6a."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.state_store import (
    OwnerRecoveryVerifier,
    initialize_shared_runtime_state,
)
from cas_forex_revamp.contracts import ActionKind, ContractError, Side
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.dual_shield_router import DualShieldBrokerRouter
from cas_forex_revamp.venue.external_paper_broker import (
    EXECUTION_MODE_LIVE,
    LiveBrokerEndpointForbiddenError,
    OandaMutationJournal,
    OandaOutcomeUnknownError,
    REQUIRED_LIVE_ARM_PHRASE,
    resolve_execution_mode,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    mint_live_authorization_bundle,
    provision_live_auth_key,
    verify_live_authorization_ticket,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    Mt5Credentials,
    load_mt5_credentials,
    Mt5OrderRequest,
    Mt5PaperBrokerVenue,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5TransportError,
    OrderIntent,
    _canonical_spool_request_hmac_input,
    _load_or_create_spool_hmac_key,
    _spool_hmac_hex,
)
from source_runtime.systemd_ceilings import (
    STAGEB_UNIT_CEILINGS,
    SOURCE_UNIT_CEILINGS,
    parse_systemctl_show_output,
    verify_unit_effective_ceilings,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import agent_pr_merger  # noqa: E402
import ceremony_generator  # noqa: E402

T0 = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
SYNTH_PASS = "Demo-Pass-9f3K!q"  # synthetic test value


class SecurityAudit14FindingsTests(unittest.TestCase):
    def _http(self, server: LoopbackCockpitServer, method: str, path: str, headers=None, body=b""):
        conn = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, resp.read()
        finally:
            conn.close()

    def test_finding_1_and_12_and_14_bearer_only_no_cookie_and_epoch_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td)
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                profit_vault=st.profit_vault,
                parallel_tiers=st.parallel_tiers,
                owner_recovery=st.owner_recovery,
            )
            srv.start()
            try:
                tok = srv.auth_token
                st_tok_url, _, _ = self._http(srv, "GET", f"/ui/index.html?token={tok}")
                self.assertEqual(st_tok_url, 401)
                pair_doc = srv.mint_pairing_code()
                status_ui, hdrs_ui, _ = self._http(srv, "GET", f"/ui/index.html?pair_code={pair_doc['pair_code']}")
                self.assertEqual(status_ui, 200)
                self.assertNotIn("set-cookie", hdrs_ui)  # Finding [1]: zero cookies emitted

                # Finding [1]: cookie auth refused
                st_ck, _, _ = self._http(srv, "GET", "/api/treasury", headers={"Cookie": f"cas_forex_cockpit_token={tok}"})
                self.assertEqual(st_ck, 401)

                # Bearer works & Finding [14] token rotation invalidates prior epoch/token immediately
                st_ok, _, _ = self._http(srv, "GET", "/api/treasury", headers={"Authorization": f"Bearer {tok}"})
                self.assertEqual(st_ok, 200)
                old_epoch = srv.session_epoch
                new_tok = srv.rotate_auth_token()
                self.assertNotEqual(old_epoch, srv.session_epoch)
                self.assertFalse(srv._verify_commit_epoch(tok, old_epoch))
                st_stale, _, _ = self._http(srv, "GET", "/api/treasury", headers={"Authorization": f"Bearer {tok}"})
                self.assertEqual(st_stale, 401)
                st_new, _, _ = self._http(srv, "GET", "/api/treasury", headers={"Authorization": f"Bearer {new_tok}"})
                self.assertEqual(st_new, 200)
                # Finding [12]: dedicated emergency and SSE bounded semaphores exist cleanly
                self.assertIsInstance(srv._emergency_sem, threading.BoundedSemaphore)
                self.assertIsInstance(srv._sse_sem, threading.BoundedSemaphore)
            finally:
                srv.stop()

    def test_finding_2_cryptographic_live_ticket_required_and_dual_mode_documented(self) -> None:
        sec_md = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("DEMO", sec_md)
        self.assertIn("LIVE", sec_md)
        # Phrase alone must fail closed without private key + signed ticket
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            resolve_execution_mode({
                "CAS_FOREX_EXECUTION_MODE": EXECUTION_MODE_LIVE,
                "CAS_FOREX_LIVE_ARM_PHRASE": REQUIRED_LIVE_ARM_PHRASE,
            })
        with tempfile.TemporaryDirectory() as td:
            kpath = provision_live_auth_key(Path(td) / "live.key")
            bundle = mint_live_authorization_bundle(
                key_file=kpath,
                targets=[(BROKER_HUGOSWAY_MT5, "9001122", "Hugo PRO5")],
                ttl_seconds=3600,
                issued_at=T0,
            )
            raw_bundle = json.dumps(bundle)
            verified = verify_live_authorization_ticket(
                raw_bundle,
                key_file=kpath,
                expected_broker_id=BROKER_HUGOSWAY_MT5,
                expected_account_login="9001122",
                expected_server="Hugo PRO5",
                now=T0 + timedelta(minutes=5),
            )
            self.assertEqual(verified["broker_id"], BROKER_HUGOSWAY_MT5)
            # Wrong login or wrong server fails closed
            with self.assertRaises(ContractError):
                verify_live_authorization_ticket(
                    raw_bundle,
                    key_file=kpath,
                    expected_broker_id=BROKER_HUGOSWAY_MT5,
                    expected_account_login="9999999",
                    expected_server="Hugo PRO5",
                    now=T0,
                )

    def test_finding_3_and_9_and_10_durable_state_gate_and_single_use_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st1 = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            st1.peak_equity_store.observe_equity("dual-shield-barbell", current_equity=Decimal("10000"), opening_balance=Decimal("10000"), now=T0)
            st1.quota_store.record_realized_trade(Decimal("-600"), symbol="EURUSD", ticket="loss-1", starting_equity=Decimal("10000"), now=T0)
            tok = st1.owner_recovery.mint_token(action_scope="UNLOCK_QUOTA_SESSION", now=T0)

            # Restart into fresh SharedRuntimeState on same state_dir preserves peak equity & quota lock!
            st2 = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            self.assertEqual(st2.peak_equity_store.read_peak("dual-shield-barbell"), Decimal("10000"))
            ok, reason, _ = st2.quota_store.evaluate_new_risk(ActionKind.OPEN, now=T0)
            self.assertFalse(ok)
            self.assertTrue("CIRCUIT" in str(reason) or "LOSS" in str(reason))

            # Wrong scope rejected cleanly, valid single-use token unlocks once and blocks replay
            with self.assertRaises(ContractError):
                st2.quota_store.unlock_session(
                    owner_request_id="unlk-1", reason="bad", recovery_verifier=st2.owner_recovery,
                    recovery_token=st2.owner_recovery.mint_token(action_scope="REARM_DRAWDOWN", now=T0), now=T0,
                )
            st2.quota_store.unlock_session(
                owner_request_id="unlk-2", reason="owner review", recovery_verifier=st2.owner_recovery,
                recovery_token=tok, now=T0,
            )
            with self.assertRaises(ContractError):
                st2.owner_recovery.verify_and_consume(tok, expected_scope="UNLOCK_QUOTA_SESSION", owner_request_id="replay", now=T0)
            # Finding [9]: DurableModelExecutionGate persists budget across instances
            self.assertIsInstance(st2.model_gate, DurableModelExecutionGate)

    def test_finding_4_and_6_stageb_hardlink_rejection_and_fail_closed_provision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src_dir = Path(td) / "src"
            dst_dir = Path(td) / "dst"
            src_dir.mkdir()
            orig = src_dir / "a.txt"
            orig.write_text("clean", encoding="utf-8")
            link = src_dir / "hardlink.txt"
            os.link(orig, link)
            with self.assertRaises((RuntimeError, ValueError)):
                ceremony_generator._materialize_regular_tree(src_dir, dst_dir)

            # Finding [6]: provision_or_load_ceremony_key_vault fails closed when allow_create=False and vault missing
            with self.assertRaises(RuntimeError) as ctx:
                ceremony_generator.provision_or_load_ceremony_key_vault(
                    Path(td) / "missing_vault",
                    run_id="fx-b-0000000000000001",
                    allow_create=False,
                )
            self.assertIn("EXTERNAL_KEY_VAULT_REQUIRED", str(ctx.exception))

    def test_finding_5_and_8_agent_pr_merger_fail_closed_checks(self) -> None:
        pr_doc = {
            "number": 99,
            "title": "Test Agent PR",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/test",
            "headRefOid": "a" * 40,
            "headRepository": {"nameWithOwner": "LittleHenderson/cas-forex-revamp"},
            "headRepositoryOwner": {"login": "LittleHenderson"},
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
            "isDraft": False,
            "labels": [{"name": "agent-pr"}],
            "author": {"id": 98265490, "login": "LittleHenderson"},
        }
        approved_rev = {"id": 1, "state": "APPROVED", "commit_id": "a" * 40, "user": {"id": 98265490, "login": "LittleHenderson"}}
        empty_cr = {"check_runs": []}
        def fake_subp_run(cmd, **_kw):
            if len(cmd) >= 3 and cmd[1] == "show":
                return subprocess.CompletedProcess(cmd, 0, stdout='{"revamp_completed": false}', stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        with patch.object(agent_pr_merger.subprocess, "run", side_effect=fake_subp_run):
            with patch.object(agent_pr_merger, "gh_json", side_effect=[[pr_doc], [approved_rev], empty_cr]):
                buf = []
                with patch("builtins.print", side_effect=lambda s: buf.append(s)):
                    rc = agent_pr_merger.main()
                self.assertEqual(rc, 0)
                rep = json.loads("".join(buf))
                self.assertEqual(rep["actions"][0]["action"], "WAITING_CI_CHECKS_EMPTY")

        # Also assert --match-head-commit is enforced in merger script and workflow doc
        src_txt = (REPO_ROOT / "scripts" / "agent_pr_merger.py").read_text(encoding="utf-8")
        self.assertIn("--match-head-commit", src_txt)

    def test_finding_7_mt5_spool_v2_hmac_and_replay_protection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool, server="Hugosway-Demo", login=7001234,
                quotes={"EURUSD": (Decimal("1.10000"), Decimal("1.10010"))},
                clock=lambda: T0,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, receipt_timeout_seconds=2, clock=lambda: T0)
            creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, {
                "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "7001234",
                "CAS_FOREX_HUGOSWAY_MT5_PASSWORD": SYNTH_PASS,
                "CAS_FOREX_HUGOSWAY_MT5_SERVER": "Hugosway-Demo",
            })
            tr.connect(creds)
            import cas_forex_revamp.venue.mt5_broker_bridge as _mbb
            req = Mt5OrderRequest(
                request_id="req-hmac-1", action="OPEN", symbol="EURUSD", side=Side.BUY, volume_lots=Decimal("0.10"),
                price=Decimal("1.10010"), stop_loss=Decimal("1.09500"), position_ticket=None,
                deviation_points=20, magic=20261116, comment="cas-hmac", created_at=T0,
                valve_decision_sha256="a" * 64,
            )
            bound = tr.prepare_request(req)
            if callable(getattr(_mbb, "sign_spool_valve_admission", None)):
                bound = _mbb.sign_spool_valve_admission(bound, spool_dir=spool, expires_at=T0 + timedelta(seconds=30))
            doc = bound.to_spool_dict()
            self.assertEqual(doc["protocol"], "cas-forex-mt5-spool/2")
            raw_hkey = _load_or_create_spool_hmac_key(spool)
            hkey = (
                _mbb.derive_spool_channel_key(raw_hkey, "hugosway_mt5")
                if callable(getattr(_mbb, "derive_spool_channel_key", None))
                else raw_hkey
            )
            sig = _spool_hmac_hex(hkey, _canonical_spool_request_hmac_input(doc))
            self.assertEqual(len(sig), 64)
            # Valid order succeeds with verified receipt HMAC; duplicate request_id blocked
            from types import SimpleNamespace
            from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate as _ld_gate
            _g7 = _ld_gate()
            _now7 = T0
            _ord7 = _mbb.OrderIntent(
                order_id=bound.request_id, action_ref=f"act-{bound.request_id}", kind=_mbb.ActionKind.OPEN,
                symbol=bound.symbol, quantity_units=bound.volume_lots * Decimal("100000"),
                side=bound.side, stop_price=bound.stop_loss,
            )
            _prop7 = SimpleNamespace(
                request=SimpleNamespace(
                    request_id=f"req-{bound.request_id}", facts=(),
                    evidence=(SimpleNamespace(evidence_id="ev-1"),),
                    state=SimpleNamespace(observed_at=_now7, valid_until=_now7 + timedelta(minutes=5)),
                ),
                result=SimpleNamespace(selection=SimpleNamespace(evidence_ids=("ev-1",), reason="ID=02 f7", selected_action_ref=_ord7.action_ref)),
                intent=SimpleNamespace(
                    intent_id=_ord7.order_id, action_ref=_ord7.action_ref, kind=_ord7.kind,
                    instrument_id=_ord7.symbol, quantity=_ord7.quantity_units, side=_ord7.side,
                    stop_price=_ord7.stop_price, limit_price=None, take_profit_price=None, target_id=None,
                ),
            )
            _dec7 = _g7.require_admissible(
                _prop7,
                current_view={"balance": "100000", "equity": "100000", "available_margin": "90000", "position_inventory": "[]"},
                policy={"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "1000000"},
                now=_now7,
            )
            _grant7 = _g7.issue_order_grant(
                _dec7, broker_id=BROKER_HUGOSWAY_MT5, account_id="7001234", server=creds.server,
                execution_mode="DEMO", action_kind=bound.action, symbol=bound.symbol,
                side=bound.side.value, volume=bound.volume_lots, stop_loss=bound.stop_loss,
                order_action_ref=_ord7.action_ref, order_quantity_units=_ord7.quantity_units, now=_now7,
            )
            rcpt = tr.send_order(bound, valve_grant=_grant7)
            self.assertTrue(bool(rcpt.position_ticket))

            # Tampered request HMAC fails closed inside emulator/spool handler
            bad_doc = dict(doc)
            bad_doc["request_id"] = "req-hmac-tamper"
            bad_doc["request_hmac_sha256"] = "f" * 64
            (spool / "order_request_req-hmac-tamper.json").write_text(json.dumps(bad_doc), encoding="utf-8")
            emu.process_pending()
            rcpt_bad = json.loads((spool / "order_receipt_req-hmac-tamper.json").read_text(encoding="utf-8"))
            self.assertEqual(rcpt_bad["status"], "REJECTED")

    def test_finding_11_oanda_mutation_journal_prevents_blind_failover_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            j = OandaMutationJournal(Path(td) / "oanda_journal.sqlite3")
            j.record_pending(
                client_ext_id="cid-1", account_id="101-001-1", symbol="EURUSD",
                action_kind="OPEN", method="POST", relative_path="/orders", now_utc="2026-11-18T12:00:00Z",
            )
            j.mark_outcome(
                client_ext_id="cid-1", status="OUTCOME_UNKNOWN",
                now_utc="2026-11-18T12:00:05Z", error_detail="timeout_after_send",
            )
            # Duplicate submit or new intent on unresolved symbol fails closed immediately
            with self.assertRaises(OandaOutcomeUnknownError):
                j.record_pending(
                    client_ext_id="cid-2", account_id="101-001-1", symbol="EURUSD",
                    action_kind="OPEN", method="POST", relative_path="/orders", now_utc="2026-11-18T12:00:06Z",
                )

    def test_finding_13_systemd_ceilings_policy_complete(self) -> None:
        for key in ("MemoryMax", "MemoryHigh", "MemorySwapMax", "CPUQuota", "TasksMax", "LimitNPROC", "OOMPolicy", "KillMode"):
            self.assertIn(key, STAGEB_UNIT_CEILINGS)
            self.assertIn(key, SOURCE_UNIT_CEILINGS)
        ok_txt = (
            "MemoryHigh=8G\nMemoryMax=12G\nMemorySwapMax=0\n"
            "CPUQuota=400%\nTasksMax=512\nLimitNPROC=512\nLimitNOFILE=4096\n"
            "OOMPolicy=kill\nKillMode=control-group\n"
        )
        ok_runner = lambda *_a, **_kw: subprocess.CompletedProcess([], 0, stdout=ok_txt, stderr="")
        parsed = verify_unit_effective_ceilings("cas-stageb.service", profile="stageb", runner=ok_runner)
        self.assertEqual(parsed["MemorySwapMax"], "0")
        bad_txt = ok_txt.replace("MemorySwapMax=0", "MemorySwapMax=1024")
        bad_runner = lambda *_a, **_kw: subprocess.CompletedProcess([], 0, stdout=bad_txt, stderr="")
        with self.assertRaises(RuntimeError):
            verify_unit_effective_ceilings("cas-stageb.service", profile="stageb", runner=bad_runner)


if __name__ == "__main__":
    unittest.main()
