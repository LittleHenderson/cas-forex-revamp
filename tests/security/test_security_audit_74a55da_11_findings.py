"""Verification suite for all 11 findings in security review report (5) at commit 74a55da."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cas_forex_revamp.composition.isolated_controller import IsolatedController, RUNNER_KINDS
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.remote_pending import ControllerDueEvents
from cas_forex_revamp.composition.state_store import (
    ENV_MODEL_MAX_CALLS_PER_DAY,
    ENV_MODEL_MAX_DAILY_SPEND_USD,
    OwnerRecoveryVerifier,
    ensure_secure_state_directory,
    initialize_shared_runtime_state,
)
from cas_forex_revamp.contracts import ActionKind, ContractError, Side, canonical_bytes, content_digest
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.operator.model_evidence import ModelEvidenceStore, ObserverAuthorizedModelStore
from cas_forex_revamp.treasury.profit_sweep import (
    CoinbaseOfframpClient,
    OfframpSecurityError,
    OfframpTransportError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
)
from cas_forex_revamp.valve.tks_meta_valve_controller import load_default_forex_valve_gate
from cas_forex_revamp.venue.external_paper_broker import (
    EXECUTION_MODE_DEMO,
    EXECUTION_MODE_LIVE,
    OandaMutationJournal,
    OandaOutcomeUnknownError,
    OandaPracticePaperClient,
    REQUIRED_LIVE_ARM_PHRASE,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    Mt5AccountSnapshot,
    Mt5Credentials,
    Mt5MutationJournal,
    Mt5NativePythonTransport,
    Mt5OrderReceipt,
    Mt5OrderRequest,
    Mt5OutcomeUnknownError,
    Mt5PaperBrokerVenue,
    Mt5Position,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    OrderIntent,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 11, 19, 1, 0, 0, tzinfo=timezone.utc)
GATE = load_default_forex_valve_gate()


def _admitted_decision(req_id: str, kind: ActionKind, qty: Decimal | None = Decimal("10000"), stop: Decimal | None = Decimal("1.09500"), ticket: str | None = None):
    order = OrderIntent(
        order_id=req_id,
        action_ref=f"ref-{req_id}",
        kind=kind,
        symbol="EURUSD",
        quantity_units=qty if kind in (ActionKind.OPEN, ActionKind.REDUCE) else None,
        side=Side.BUY if kind is ActionKind.OPEN else None,
        stop_price=stop,
        position_ticket=ticket,
    )
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=None,
        target_id=order.position_ticket,
    )
    req = SimpleNamespace(
        request_id=req_id,
        facts=(),
        evidence=(),
        state=SimpleNamespace(observed_at=T0, valid_until=T0 + timedelta(minutes=5)),
    )
    prop = SimpleNamespace(
        request=req,
        result=SimpleNamespace(selection=SimpleNamespace(evidence_ids=("ev-1",), reason="verified setup", selected_action_ref=order.action_ref)),
        intent=intent,
    )
    view = {"balance": "100000", "equity": "100000", "peak_equity": "100000", "available_margin": "95000", "position_inventory": "[]"}
    pol = {"new_risk_permission": "ALLOWED", "management_permission": "ALLOWED", "max_entry_quantity": "500000"}
    dec = GATE.require_admissible(prop, current_view=view, policy=pol, now=T0 + timedelta(seconds=1))
    return dec, order


class SecurityAudit11FindingsTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Finding [1]: OANDA crash-left PENDING_DISPATCH freezes across restart
    #              and LIVE mode requires durable SQLite mutation journal
    # ------------------------------------------------------------------
    def test_finding_1_oanda_pending_blocks_restart_and_live_requires_sqlite(self) -> None:
        # In-memory PENDING_DISPATCH also blocks new-ID retry
        mem_j = OandaMutationJournal()
        mem_j.record_pending(
            client_ext_id="ext-mem-1",
            account_id="101-001-1",
            symbol="EURUSD",
            action_kind="OPEN",
            method="POST",
            relative_path="accounts/101-001-1/orders",
            now_utc="2026-11-19T01:00:00Z",
        )
        with self.assertRaises(OandaOutcomeUnknownError):
            mem_j.record_pending(
                client_ext_id="ext-mem-2",
                account_id="101-001-1",
                symbol="EURUSD",
                action_kind="OPEN",
                method="POST",
                relative_path="accounts/101-001-1/orders",
                now_utc="2026-11-19T01:00:01Z",
            )

        # SQLite crash after record_pending (before mark_outcome) promotes PENDING -> OUTCOME_UNKNOWN on restart
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "oanda.sqlite3"
            j1 = OandaMutationJournal(db)
            j1.record_pending(
                client_ext_id="ext-crash-1",
                account_id="101-001-1",
                symbol="EURUSD",
                action_kind="OPEN",
                method="POST",
                relative_path="accounts/101-001-1/orders",
                now_utc="2026-11-19T01:00:00Z",
            )
            # Simulate process restart: reopen journal
            j2 = OandaMutationJournal(db)
            unknowns = j2.unknown_mutations(account_id="101-001-1", symbol="EURUSD")
            self.assertEqual(len(unknowns), 1)
            self.assertEqual(unknowns[0]["status"], "OUTCOME_UNKNOWN")
            self.assertEqual(unknowns[0]["client_ext_id"], "ext-crash-1")
            # Changing client_ext_id MUST NOT bypass freeze
            with self.assertRaises(OandaOutcomeUnknownError):
                j2.record_pending(
                    client_ext_id="ext-crash-new-id",
                    account_id="101-001-1",
                    symbol="EURUSD",
                    action_kind="OPEN",
                    method="POST",
                    relative_path="accounts/101-001-1/orders",
                    now_utc="2026-11-19T01:00:05Z",
                )

            # LIVE OANDA client without durable journal (or CAS_FOREX_STATE_DIR) MUST fail closed
            with self.assertRaises(ContractError):
                OandaPracticePaperClient(
                    execution_mode=EXECUTION_MODE_LIVE,
                    live_arm_phrase=REQUIRED_LIVE_ARM_PHRASE,
                    mutation_journal=OandaMutationJournal(),  # memory-only rejected in LIVE
                )

    # ------------------------------------------------------------------
    # Finding [2]: Pre-created / symlink / low-entropy / permissive token file
    # ------------------------------------------------------------------
    def test_finding_2_cockpit_token_file_custody_and_entropy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)

            # 1. Malformed / low-entropy pre-created token file MUST fail closed
            weak_tok = base / "weak.token"
            weak_tok.write_text("a" * 44 + "\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(weak_tok, 0o600)
            srv_weak = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=weak_tok)
            with self.assertRaises(ContractError):
                srv_weak.start()

            # 2. POSIX wrong-mode / hard-link / symlinked leaf / symlinked parent checks
            if os.name == "posix":
                perm_tok = base / "perm.token"
                perm_tok.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
                os.chmod(perm_tok, 0o644)
                with self.assertRaises(ContractError):
                    LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=perm_tok).start()

                real_tok = base / "real.token"
                real_tok.write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")
                os.chmod(real_tok, 0o600)
                hard_tok = base / "hard.token"
                os.link(real_tok, hard_tok)
                with self.assertRaises(ContractError):
                    LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=hard_tok).start()

                sym_tok = base / "sym.token"
                os.symlink(real_tok, sym_tok)
                with self.assertRaises(ContractError):
                    LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=sym_tok).start()

                real_dir = base / "real_dir"
                real_dir.mkdir(mode=0o700)
                sym_dir = base / "sym_dir"
                os.symlink(real_dir, sym_dir)
                with self.assertRaises(ContractError):
                    LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=sym_dir / "tok").start()

            # 3. Clean generated token file survives restart and rotates atomically
            good_tok = base / "good_dir" / "cockpit.token"
            srv1 = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=good_tok)
            srv1.start()
            try:
                tok1 = srv1.auth_token
                self.assertEqual(good_tok.read_text(encoding="utf-8").strip(), tok1)
                tok2 = srv1.rotate_auth_token()
                self.assertNotEqual(tok1, tok2)
                self.assertEqual(good_tok.read_text(encoding="utf-8").strip(), tok2)
            finally:
                srv1.stop()

            srv2 = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=good_tok)
            srv2.start()
            try:
                self.assertEqual(srv2.auth_token, tok2)
            finally:
                srv2.stop()

    # ------------------------------------------------------------------
    # Finding [3]: OANDA reconciliation never clears on bounded/partial history
    # ------------------------------------------------------------------
    def test_finding_3_oanda_exhaustive_reconciliation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "oanda_rec.sqlite3"
            j = OandaMutationJournal(db)
            acct = "101-001-99"
            env = {
                "CAS_FOREX_EXECUTION_MODE": EXECUTION_MODE_DEMO,
                "CAS_FOREX_OANDA_PRACTICE_TOKEN": "demo-tok-12345",
                "CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID": acct,
            }

            # Case A: Missing pre-dispatch cursor or malformed trades list -> MUST stay OUTCOME_UNKNOWN
            j.record_pending(
                client_ext_id="ext-nocursor",
                account_id=acct,
                symbol="EURUSD",
                action_kind="OPEN",
                method="POST",
                relative_path=f"accounts/{acct}/orders",
                now_utc="2026-11-19T01:00:00Z",
                pre_dispatch_last_tx_id=None,
            )
            j.mark_outcome(client_ext_id="ext-nocursor", status="OUTCOME_UNKNOWN", now_utc="2026-11-19T01:00:01Z")

            def partial_transport(method, url, headers, body, timeout, max_bytes):
                if url.endswith("/summary"):
                    return json.dumps({"lastTransactionID": "500"}).encode()
                if "/transactions?" in url:
                    return json.dumps({"transactions": []}).encode()
                if "/trades?" in url:
                    return json.dumps({}).encode()  # missing trades list
                return b"{}"

            client = OandaPracticePaperClient(environ=env, transport=partial_transport, mutation_journal=j)
            res_partial = client.reconcile_unknown_mutations(now=T0)
            self.assertEqual(res_partial["remaining_unknown"], 1)
            self.assertFalse(res_partial["exhaustive"])

            # Case B: Matching tx beyond first 200 (id=350) found via full idrange pagination
            j2 = OandaMutationJournal(Path(td) / "oanda_rec2.sqlite3")
            j2.record_pending(
                client_ext_id="ext-deep-350",
                account_id=acct,
                symbol="EURUSD",
                action_kind="OPEN",
                method="POST",
                relative_path=f"accounts/{acct}/orders",
                now_utc="2026-11-19T01:00:00Z",
                pre_dispatch_last_tx_id="100",
            )
            j2.mark_outcome(client_ext_id="ext-deep-350", status="OUTCOME_UNKNOWN", now_utc="2026-11-19T01:00:01Z")

            def deep_transport(method, url, headers, body, timeout, max_bytes):
                if url.endswith("/summary"):
                    return json.dumps({"lastTransactionID": "400"}).encode()
                if "transactions/idrange?from=101&to=400" in url:
                    txs = [{"id": str(i)} for i in range(101, 401)]
                    txs[249] = {"id": "350", "clientExtensions": {"id": "ext-deep-350"}}
                    return json.dumps({"transactions": txs}).encode()
                if "/trades?state=ALL" in url:
                    return json.dumps({"trades": []}).encode()
                return b"{}"

            c2 = OandaPracticePaperClient(environ=env, transport=deep_transport, mutation_journal=j2)
            res_deep = c2.reconcile_unknown_mutations(now=T0)
            self.assertEqual(res_deep["resolved"], 1)
            self.assertEqual(res_deep["remaining_unknown"], 0)
            self.assertTrue(res_deep["exhaustive"])

            # Case C: Complete exhaustive range proves true absence -> CONFIRMED_ABSENT
            j3 = OandaMutationJournal(Path(td) / "oanda_rec3.sqlite3")
            j3.record_pending(
                client_ext_id="ext-never-arrived",
                account_id=acct,
                symbol="GBPUSD",
                action_kind="AMEND_STOP",
                method="PUT",
                relative_path=f"accounts/{acct}/trades/9/orders",
                now_utc="2026-11-19T01:00:00Z",
                pre_dispatch_last_tx_id="10",
            )
            j3.mark_outcome(client_ext_id="ext-never-arrived", status="OUTCOME_UNKNOWN", now_utc="2026-11-19T01:00:01Z")

            def absent_transport(method, url, headers, body, timeout, max_bytes):
                if url.endswith("/summary"):
                    return json.dumps({"lastTransactionID": "12"}).encode()
                if "transactions/idrange?from=11&to=12" in url:
                    return json.dumps({"transactions": [{"id": "11"}, {"id": "12"}]}).encode()
                if "/trades?state=ALL" in url:
                    return json.dumps({"trades": []}).encode()
                return b"{}"

            c3 = OandaPracticePaperClient(environ=env, transport=absent_transport, mutation_journal=j3)
            res_abs = c3.reconcile_unknown_mutations(now=T0)
            self.assertEqual(res_abs["resolved"], 1)
            self.assertEqual(res_abs["remaining_unknown"], 0)

    # ------------------------------------------------------------------
    # Finding [4]: Decision worker cannot forge model/transport evidence
    # ------------------------------------------------------------------
    def test_finding_4_worker_cannot_fabricate_model_or_transport_evidence(self) -> None:
        self.assertEqual(RUNNER_KINDS, frozenset())
        with tempfile.TemporaryDirectory() as td:
            obs_key = secrets.token_bytes(32)
            store = ModelEvidenceStore(
                Path(td) / "ev.model-evidence.sqlite3",
                run_id="run-sec-f4",
                deadline=T0 + timedelta(hours=1),
                observer_key=obs_key,
            )
            store.initialize(create=True)

            inv = {"synthetic_invocation": "req-1"}
            key = content_digest(inv)

            # 1. Untrusted direct append/begin_http for observation kinds MUST fail closed
            for kind in (
                "MODEL_HTTP_RESPONSE",
                "MODEL_TOKEN_PREFLIGHT",
                "MODEL_RUNTIME_OBSERVATION",
                "MODEL_INFERENCE_RECEIPT",
                "MODEL_TRANSPORT_REQUEST_SENT",
                "MODEL_TRANSPORT_RESPONSE_CAPTURE",
                "MODEL_TRANSPORT_PENDING_WINDOW",
            ):
                with self.assertRaises(ContractError):
                    store.append(f"fake-{kind}-{key}", kind, {"forged": True}, now=T0)

            with self.assertRaises(ContractError):
                store.begin_http(
                    phase="probe",
                    operation="generation",
                    invocation_sha256=key,
                    body_sha256="a" * 64,
                    timeout_seconds=10,
                    now=T0,
                )

            # 2. IsolatedController._handle MUST refuse all worker write/attestation RPCs
            ctrl = object.__new__(IsolatedController)
            ctrl.active = inv
            ctrl.phase = "probe"
            ctrl.frame_started = T0
            ctrl.clock = lambda: T0
            ctrl.guard_roles = lambda: None
            ctrl.store = store
            for banned_rpc in ("STORE_BEGIN", "STORE_APPEND", "GENERATION_SUBMITTED", "DUE_EVENT", "VERIFY_TRANSPORT"):
                with self.assertRaises(ContractError):
                    ctrl._handle(banned_rpc, {"invocation_sha256": key})

            # 3. Trusted ObserverAuthorizedModelStore succeeds and passes provenance verification
            obs_store = ObserverAuthorizedModelStore(store, obs_key)
            rec = obs_store.append("token-proof-" + key, "MODEL_TOKEN_PREFLIGHT", {"input_tokens": 12}, now=T0)
            self.assertTrue(store.verify_observer_provenance("token-proof-" + key))
            self.assertEqual(rec["payload"]["input_tokens"], 12)

            # 4. Deleting/forging observer_attestations causes ControllerDueEvents.submitted() to reject!
            conn = sqlite3.connect(str(store.path))
            try:
                conn.execute("DELETE FROM observer_attestations WHERE receipt_id = ?", ("token-proof-" + key,))
                conn.commit()
            finally:
                conn.close()
            self.assertFalse(store.verify_observer_provenance("token-proof-" + key))
            due = ControllerDueEvents(
                store=store,
                pending_changes=SimpleNamespace(claim=lambda _h: None),
                binding={},
                clock=lambda: T0,
                current_state=lambda: {},
                next_sequence=lambda: 1,
            )
            due.begin(SimpleNamespace(request_sha256="b" * 64, packet_json="{}"), body=b"{}")
            due.key = key
            with self.assertRaises(ContractError):
                due.submitted({"payload": {}})

    # ------------------------------------------------------------------
    # Finding [5]: MT5 unknown outcomes install durable reconciliation freeze
    # ------------------------------------------------------------------
    def test_finding_5_mt5_unknown_outcomes_install_durable_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "mt5_mut.sqlite3"
            j = Mt5MutationJournal(db)

            class _NoneOrderSdk:
                ORDER_TYPE_BUY = 0
                ORDER_TYPE_SELL = 1
                TRADE_ACTION_DEAL = 1
                TRADE_ACTION_SLTP = 6
                ORDER_TIME_GTC = 0
                ORDER_FILLING_IOC = 1
                def initialize(self, **_kw): return True
                def login(self, **_kw): return True
                def shutdown(self): return None
                def last_error(self): return (-10005, "IPC timeout after send")
                def account_info(self):
                    return SimpleNamespace(login=1002903, server="Hugosway-Demo", trade_mode=0, currency="USD",
                                           balance=100000.0, equity=100000.0, margin=0.0, margin_free=100000.0,
                                           margin_level=0.0, leverage=500)
                def symbol_info_tick(self, sym):
                    return SimpleNamespace(bid=1.0980, ask=1.0982, time_msc=1795057994298)
                def positions_get(self): return ()
                def order_send(self, payload): return None  # unknown outcome after send!

            creds = Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5, login=1002903, server="Hugosway-Demo",
                password="demo-pass-1", execution_mode=EXECUTION_MODE_DEMO,
            )
            venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=creds,
                transport=Mt5NativePythonTransport(mt5_module=_NoneOrderSdk()),
                valve_gate=GATE,
                clock=lambda: T0,
                mutation_journal=j,
            )
            venue.connect()
            dec1, ord1 = _admitted_decision("req-mt5-1", ActionKind.OPEN)
            with self.assertRaises(Mt5OutcomeUnknownError):
                venue.execute(ord1, valve_decision=dec1)

            # Restart: new journal & venue instance MUST block semantically equivalent new-ID retry!
            j_restarted = Mt5MutationJournal(db)
            venue2 = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=creds,
                transport=Mt5NativePythonTransport(mt5_module=_NoneOrderSdk()),
                valve_gate=GATE,
                clock=lambda: T0,
                mutation_journal=j_restarted,
            )
            venue2.connect()
            dec2, ord2 = _admitted_decision("req-mt5-2", ActionKind.OPEN)
            with self.assertRaises(Mt5OutcomeUnknownError):
                venue2.execute(ord2, valve_decision=dec2)

            # Wrong server/incomplete history MUST NOT clear freeze
            bad_rec = venue2.reconcile_unknown_mutations(
                terminal_history_fn=lambda l, s: {"account_login": l, "server": "Wrong-Server", "complete": True, "orders": [], "deals": []}
            )
            self.assertEqual(bad_rec["remaining_unknown"], 1)

            # Exact account + server + complete=True history clears latch cleanly
            ok_rec = venue2.reconcile_unknown_mutations(
                terminal_history_fn=lambda l, s: {"account_login": l, "server": s, "complete": True, "orders": [], "deals": []}
            )
            self.assertEqual(ok_rec["remaining_unknown"], 0)

            # LIVE MT5 without durable journal MUST fail closed
            live_creds = Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5, login=9001122, server="Hugo PRO5",
                password="live-pass-1", execution_mode=EXECUTION_MODE_LIVE,
            )
            with self.assertRaises(ContractError):
                Mt5PaperBrokerVenue(
                    broker_id=BROKER_HUGOSWAY_MT5,
                    credentials=live_creds,
                    transport=Mt5NativePythonTransport(mt5_module=_NoneOrderSdk()),
                    valve_gate=GATE,
                    mutation_journal=Mt5MutationJournal(),  # memory-only forbidden in LIVE
                )

    # ------------------------------------------------------------------
    # Finding [6]: Invalid/zero/negative/non-finite model ceilings fail closed
    # ------------------------------------------------------------------
    def test_finding_6_invalid_model_ceilings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # Absent env vars receive documented defaults
            st_def = initialize_shared_runtime_state({}, explicit_state_dir=Path(td) / "def")
            self.assertEqual(st_def.model_gate.max_calls_per_day, 5000)
            self.assertEqual(st_def.model_gate.max_daily_spend_usd, Decimal("25.00"))

            for bad_calls in ("0", "-5", "   ", "abc", "100001"):
                with self.assertRaises(ContractError):
                    initialize_shared_runtime_state(
                        {ENV_MODEL_MAX_CALLS_PER_DAY: bad_calls},
                        explicit_state_dir=Path(td) / f"c_{abs(hash(bad_calls))}",
                    )

            for bad_spend in ("Infinity", "-Infinity", "NaN", "0", "-1.00", "", "   ", "99999.00"):
                with self.assertRaises(ContractError):
                    initialize_shared_runtime_state(
                        {ENV_MODEL_MAX_DAILY_SPEND_USD: bad_spend},
                        explicit_state_dir=Path(td) / f"s_{abs(hash(bad_spend))}",
                    )

            # Constructor & admit_call directly reject Infinity / NaN
            db = Path(td) / "gate.sqlite3"
            with self.assertRaises(ContractError):
                DurableModelExecutionGate(db, max_calls_per_day=10, max_daily_spend_usd=Decimal("Infinity"))
            with self.assertRaises(ContractError):
                DurableModelExecutionGate(db, max_calls_per_day=10, max_daily_spend_usd=Decimal("NaN"))
            gate = DurableModelExecutionGate(db, max_calls_per_day=10, max_daily_spend_usd=Decimal("5.00"), clock=lambda: T0)
            with self.assertRaises(ContractError):
                gate.admit_call(
                    request_id="r1", model_id="claude-fable-5.2", invocation_sha256="a" * 64,
                    estimated_cost_usd=Decimal("NaN"), now=T0,
                )

    # ------------------------------------------------------------------
    # Finding [7]: Shared runtime state directory custody & ancestor checks
    # ------------------------------------------------------------------
    def test_finding_7_state_dir_custody_and_ancestor_checks(self) -> None:
        with self.assertRaises(ContractError):
            ensure_secure_state_directory("relative/state_dir")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            with self.assertRaises(ContractError):
                ensure_secure_state_directory(base / "sub" / ".." / "escape")

            if os.name == "posix":
                # Symlinked ancestor rejected
                real_parent = base / "real_parent"
                real_parent.mkdir(mode=0o700)
                sym_parent = base / "sym_parent"
                os.symlink(real_parent, sym_parent)
                with self.assertRaises(ContractError):
                    ensure_secure_state_directory(sym_parent / "state")

                # Non-sticky world-writable ancestor rejected
                ww_parent = base / "ww_parent"
                ww_parent.mkdir(mode=0o700)
                os.chmod(ww_parent, 0o777)  # nosec B103: intentional world-writable ancestor fixture to verify rejection
                with self.assertRaises(ContractError):
                    ensure_secure_state_directory(ww_parent / "state")

                # Foreign-owned existing state dir (even if 0o700) rejected
                foreign_dir = base / "foreign_state"
                foreign_dir.mkdir(mode=0o700)
                real_fstat = os.fstat
                def fake_fstat(fd):
                    st = real_fstat(fd)
                    if st.st_ino == os.stat(foreign_dir).st_ino:
                        return SimpleNamespace(st_mode=st.st_mode, st_uid=os.geteuid() + 1000, st_nlink=st.st_nlink, st_dev=st.st_dev, st_ino=st.st_ino, st_size=st.st_size)
                    return st
                with patch("cas_forex_revamp.composition.state_store.os.fstat", side_effect=fake_fstat):
                    with self.assertRaises(ContractError):
                        ensure_secure_state_directory(foreign_dir)
            else:
                # Windows: permissive Everyone/Users DACL rejected
                win_dir = base / "win_state"
                win_dir.mkdir()
                with patch(
                    "cas_forex_revamp.composition.state_store._windows_sid_and_dacl_info",
                    return_value=("S-1-5-18", ["S-1-1-0"]),  # Everyone allowed -> reject!
                ):
                    with self.assertRaises(ContractError):
                        ensure_secure_state_directory(win_dir)

    # ------------------------------------------------------------------
    # Finding [8]: Bounded pre-auth pool, absolute header deadline, emergency reserve
    # ------------------------------------------------------------------
    def test_finding_8_bounded_pre_auth_pool_deadline_and_emergency_reserve(self) -> None:
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            max_ordinary_connections=2,
            max_emergency_connections=2,
            header_deadline_seconds=0.8,
        )
        srv.start()
        stalled_sockets: list[socket.socket] = []
        try:
            # 1. Saturate ALL 2 ordinary connection slots with incomplete headers
            for _ in range(2):
                s = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=2.0)
                s.sendall(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n")  # incomplete headers!
                stalled_sockets.append(s)
            time.sleep(0.1)

            # 2. While ordinary slots are saturated, emergency POST route STILL succeeds on reserved emergency slots!
            conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=2.0)
            try:
                conn.request(
                    "POST",
                    "/api/ai-overseer-action",
                    body=b"{}",
                    headers={**srv.auth_headers(), "Content-Type": "application/json"},
                )
                resp = conn.getresponse()
                resp.read()
                # 400 (missing action) or 404 (trader not attached), NOT 503!
                self.assertIn(resp.status, (400, 404))
            finally:
                conn.close()

            # 3. Flooding beyond ordinary + emergency slots caps peak worker threads <= 4!
            extra = []
            for _ in range(6):
                try:
                    s = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=1.0)
                    s.sendall(b"GET /api/health HTTP/1.1\r\n")
                    extra.append(s)
                except OSError:
                    break
            time.sleep(0.15)
            self.assertLessEqual(srv._httpd._peak_workers, 4)  # type: ignore[union-attr]
            for s in extra:
                s.close()

            # 4. Trickling bytes slower than absolute header deadline (0.8s) closes the socket!
            trickle = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=3.0)
            try:
                trickle.sendall(b"GET /api/health HTTP/1.1\r\n")
                closed = False
                for _ in range(10):
                    time.sleep(0.15)
                    try:
                        trickle.sendall(b"X-Slow: 1\r\n")
                    except OSError:
                        closed = True
                        break
                if not closed:
                    trickle.settimeout(0.5)
                    data = trickle.recv(1024)
                    closed = (data == b"")
                self.assertTrue(closed, "slowloris trickle connection must be closed by absolute header deadline")
            finally:
                trickle.close()
        finally:
            for s in stalled_sockets:
                s.close()
            srv.stop()

    # ------------------------------------------------------------------
    # Finding [9]: ACH payout reserves funds & idempotency BEFORE dispatch
    # ------------------------------------------------------------------
    def test_finding_9_ach_atomic_pre_dispatch_reserve_and_idempotency(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        with tempfile.TemporaryDirectory() as td:
            vault = ProfitSweepVault(Path(td) / "vault.sqlite3", clock=lambda: T0)
            vault.record_realized_profit(
                trade_id="tr-ach-1", symbol="EURUSD", broker_id="HUGOSWAY_MT5",
                realized_net_usd=Decimal("200.00"), occurred_at=T0,
            )  # $100.00 bank sweep reserve
            rec = OwnerRecoveryVerifier(db_path=Path(td) / "rec.sqlite3", clock=lambda: T0)

            priv = ec.generate_private_key(ec.SECP256R1())
            pem_p = Path(td) / "cb.pem"
            pem_p.write_bytes(
                priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            )
            if os.name == "posix":
                os.chmod(pem_p, 0o600)

            dispatch_calls: list[dict] = []
            barrier = threading.Barrier(2)

            def slow_cb_http(method, url, headers, body, timeout):
                doc = json.loads(body.decode("utf-8"))
                dispatch_calls.append(doc)
                time.sleep(0.15)
                return 200, json.dumps({"id": f"cb-real-{len(dispatch_calls)}"}).encode()

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-01",
                http_call=slow_cb_http,
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            results: list[tuple[str, object]] = []

            def worker(idx: int, tok: str) -> None:
                barrier.wait()
                try:
                    out = vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=Decimal("100.00"),
                        owner_request_id=f"req-race-{idx}",
                        reason="race test",
                        verifier=rec,
                        recovery_token=tok,
                        coinbase_client=cb,
                    )
                    results.append(("OK", out))
                except Exception as exc:
                    results.append(("ERR", type(exc).__name__))

            t1 = threading.Thread(target=worker, args=(1, tok1))
            t2 = threading.Thread(target=worker, args=(2, tok2))
            t1.start(); t2.start(); t1.join(); t2.join()

            # Exactly ONE payout reaches Coinbase; the concurrent racer is blocked by atomic reserve!
            self.assertEqual(len(dispatch_calls), 1)
            self.assertEqual(sum(1 for r in results if r[0] == "OK"), 1)
            self.assertEqual(sum(1 for r in results if r[0] == "ERR"), 1)
            self.assertTrue(dispatch_calls[0].get("client_reference_id"))

            # Missing provider transaction ID MUST fail closed as OUTCOME_UNKNOWN (never fabricated)
            vault.record_realized_profit(
                trade_id="tr-ach-2", symbol="EURUSD", broker_id="HUGOSWAY_MT5",
                realized_net_usd=Decimal("100.00"), occurred_at=T0,
            )  # +$50 reserve
            cb_missing_id = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-01",
                http_call=lambda *a: (200, json.dumps({"status": "ok"}).encode()),  # NO id/payout_id/refid!
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            tok3 = rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=Decimal("50.00"),
                    owner_request_id="req-missing-tx",
                    reason="missing tx id test",
                    verifier=rec,
                    recovery_token=tok3,
                    coinbase_client=cb_missing_id,
                )
            # Reserve stays locked ($0 pending) after OUTCOME_UNKNOWN!
            self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "0")

    # ------------------------------------------------------------------
    # Finding [10]: Revoked cockpit bearer cannot commit direct mutation
    # ------------------------------------------------------------------
    def test_finding_10_revoked_bearer_cannot_commit_after_epoch_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            reg = FrontierModelRegistry(environ={"CAS_FOREX_ANTHROPIC_API_KEY": "sk-ant-fixture"})
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                ai_model_registry=reg,
                profit_vault=st.profit_vault,
                owner_recovery=st.owner_recovery,
            )
            srv.start()
            try:
                old_tok = srv.auth_token
                old_epoch = srv.session_epoch
                initial_ratio = st.profit_vault.snapshot()["sweep_ratio"]

                # Hook _verify_commit_epoch so handler pauses right AFTER passing it, while rotation runs!
                orig_verify = srv._verify_commit_epoch
                paused = threading.Event()
                resume = threading.Event()

                def pausing_verify(tok, ep):
                    ok = orig_verify(tok, ep)
                    if ok and ep == old_epoch:
                        paused.set()
                        resume.wait(timeout=5.0)
                    return ok

                srv._verify_commit_epoch = pausing_verify  # type: ignore[method-assign]
                status_box: list[int] = []

                def send_mut():
                    conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5.0)
                    try:
                        conn.request(
                            "POST",
                            "/api/treasury-config",
                            body=json.dumps({"sweep_ratio": "0.80"}).encode(),
                            headers={"Authorization": f"Bearer {old_tok}", "Content-Type": "application/json"},
                        )
                        r = conn.getresponse()
                        r.read()
                        status_box.append(r.status)
                    except OSError:
                        status_box.append(401)
                    finally:
                        conn.close()

                t = threading.Thread(target=send_mut)
                t.start()
                self.assertTrue(paused.wait(timeout=3.0))
                # Rotate bearer token while handler is paused right after _verify_commit_epoch!
                srv.rotate_auth_token()
                resume.set()
                t.join(timeout=5.0)

                # Revoked handler MUST NOT commit the ratio change!
                self.assertEqual(st.profit_vault.snapshot()["sweep_ratio"], initial_ratio)
                self.assertEqual(status_box, [401])
            finally:
                srv.stop()

    # ------------------------------------------------------------------
    # Finding [11]: Bearer-only caller cannot falsely settle broker 2FA withdrawal
    # ------------------------------------------------------------------
    def test_finding_11_broker_2fa_confirm_requires_bound_recovery_and_provider_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            st = initialize_shared_runtime_state({}, explicit_state_dir=td, clock=lambda: T0)
            vault = st.profit_vault
            rec = st.owner_recovery
            vault.record_realized_profit(
                trade_id="tr-2fa-1", symbol="EURUSD", broker_id="HUGOSWAY_MT5",
                realized_net_usd=Decimal("400.00"), occurred_at=T0,
            )  # $200 pending sweep reserve

            tok_req = rec.mint_token(action_scope="TREASURY_SWEEP", now=T0)
            req_out = vault.request_broker_2fa_withdrawal(
                broker_id="HUGOSWAY_MT5",
                amount_usd=Decimal("200.00"),
                owner_request_id="req-2fa-create",
                reason="manual withdrawal",
                verifier=rec,
                recovery_token=tok_req,
            )
            tid = req_out["transfer_id"]
            self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "200")

            # 1. Wildcard recovery token (target_ref="*") MUST be rejected!
            tok_wild = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref="*", now=T0)
            with self.assertRaises(ContractError):
                vault.confirm_broker_2fa_withdrawal(
                    transfer_id=tid,
                    provider_tx_id="tx-real-1",
                    owner_request_id="req-2fa-c1",
                    verifier=rec,
                    recovery_token=tok_wild,
                    provider_verifier=lambda b, tx: {
                        "status": "SETTLED", "broker_id": b, "provider_tx_id": tx,
                        "amount_usd": "200.00", "destination_bank_id": "OWNER_LINKED_BANK",
                    },
                )
            self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "200")

            # 2. Transfer-bound token with PENDING/mismatched/unreachable provider receipt MUST NOT settle!
            tok_bound_1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=tid, now=T0)
            with self.assertRaises(OfframpSecurityError):
                vault.confirm_broker_2fa_withdrawal(
                    transfer_id=tid,
                    provider_tx_id="tx-pending-1",
                    owner_request_id="req-2fa-c2",
                    verifier=rec,
                    recovery_token=tok_bound_1,
                    provider_verifier=lambda b, tx: {
                        "status": "PENDING", "broker_id": b, "provider_tx_id": tx,
                        "amount_usd": "200.00", "destination_bank_id": "OWNER_LINKED_BANK",
                    },
                )
            self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "200")

            tok_bound_2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=tid, now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.confirm_broker_2fa_withdrawal(
                    transfer_id=tid,
                    provider_tx_id="tx-err-1",
                    owner_request_id="req-2fa-c3",
                    verifier=rec,
                    recovery_token=tok_bound_2,
                    provider_verifier=lambda b, tx: (_ for _ in ()).throw(TimeoutError("broker unreachable")),
                )
            self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "200")

            # 3. Bearer-only HTTP call without transfer-bound recovery token & provider verifier fails closed!
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                profit_vault=vault,
                owner_recovery=rec,
            )
            srv.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=5.0)
                try:
                    conn.request(
                        "POST",
                        "/api/treasury-action",
                        body=json.dumps({
                            "action": "CONFIRM_BROKER_2FA_WITHDRAWAL",
                            "transfer_id": tid,
                            "provider_tx_id": "invented-tx-999",
                        }).encode(),
                        headers={**srv.auth_headers(), "Content-Type": "application/json"},
                    )
                    r = conn.getresponse()
                    r.read()
                    self.assertIn(r.status, (400, 403))
                finally:
                    conn.close()
                self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "200")
            finally:
                srv.stop()

            # 4. Transfer-bound token + matching independently verified SETTLED receipt succeeds and updates reserve!
            tok_bound_ok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=tid, now=T0)
            ok = vault.confirm_broker_2fa_withdrawal(
                transfer_id=tid,
                provider_tx_id="tx-verified-777",
                owner_request_id="req-2fa-ok",
                verifier=rec,
                recovery_token=tok_bound_ok,
                provider_verifier=lambda b, tx: {
                    "status": "SETTLED",
                    "broker_id": "HUGOSWAY_MT5",
                    "provider_tx_id": "tx-verified-777",
                    "amount_usd": "200.00",
                    "destination_bank_id": "OWNER_LINKED_BANK",
                },
            )
            self.assertEqual(ok["status"], "SETTLED")
            self.assertEqual(ok["vault"]["pending_disbursement_usd"], "0")


if __name__ == "__main__":
    unittest.main()
