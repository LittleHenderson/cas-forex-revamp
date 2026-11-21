"""Security regression tests for PR #31 Audit 0b16e88 Treasury Findings.

Covers:
- Finding [4] (High): Separately journaled conversion & ACH withdrawal phases with
  distinct deterministic provider idempotency keys, CONVERSION_OUTCOME_UNKNOWN /
  CONVERSION_PENDING freeze refusing retry of either step until explicit exchange
  history reconciliation (reconcile_conversion_outcome), zero duplicate conversions
  when retrying from CONVERSION_CONFIRMED, and reconcile_withdrawal_outcome.
- Finding [12] (Medium) Treasury Hook: Pre-effect epoch_guard invoked immediately
  before conversion and immediately before ACH withdrawal (after durable intent
  commit, before external network I/O) plus confirm_broker_2fa_withdrawal hook.
- Lantern 0.11.0 Cloud Medium LW-EFFECT-BEFORE-RECORD: Direct SQLite UPDATE +
  conn.commit() directly inside execute_offramp_ach_payout before every external
  conversion and withdrawal call.
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

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.treasury.profit_sweep import (
    CONVERSION_STATUS_CONFIRMED,
    CONVERSION_STATUS_NOT_REQUIRED,
    CONVERSION_STATUS_NOT_STARTED,
    CONVERSION_STATUS_OUTCOME_UNKNOWN,
    CONVERSION_STATUS_PENDING,
    CoinbaseOfframpClient,
    KrakenOfframpClient,
    OfframpSecurityError,
    OfframpTransportError,
    ProfitSweepVault,
    RAIL_COINBASE_ACH,
    RAIL_KRAKEN_ACH,
    WITHDRAWAL_STATUS_NOT_STARTED,
    WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
    WITHDRAWAL_STATUS_PENDING,
    WITHDRAWAL_STATUS_SUBMITTED,
)

D = Decimal
T0 = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]


class _FakeSessionRevokedError(RuntimeError):
    """Sentinel exception mimicking cockpit _SessionRevokedError."""


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


def _read_transfer_row(db_path: Path, transfer_id: str) -> dict[str, object]:
    with closing(sqlite3.connect(str(db_path))) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM bank_transfers WHERE transfer_id = ?", (transfer_id,)
        ).fetchone()
        if row is None:
            raise AssertionError(f"Missing bank_transfers row for {transfer_id!r}")
        return dict(row)


def _read_audit_events(db_path: Path) -> list[str]:
    with closing(sqlite3.connect(str(db_path))) as conn:
        return [
            str(r[0])
            for r in conn.execute("SELECT event_type FROM vault_audit ORDER BY seq ASC").fetchall()
        ]


class Audit0b16e88TreasuryFindingsTests(unittest.TestCase):
    def _setup_vault(self, root: Path, *, realized_profit: Decimal = D("600.00")) -> tuple[ProfitSweepVault, OwnerRecoveryVerifier, Path, Path]:
        db_path = root / "vault.sqlite3"
        pem_path = root / "cb.pem"
        _write_ec_pem(pem_path)
        vault = ProfitSweepVault(db_path, scope_id="treasury-audit-0b16e88", clock=lambda: T0)
        vault.record_realized_close(
            trade_id="tr-seed-1",
            symbol="EURUSD",
            broker_id="HUGOSWAY_MT5",
            realized_net_usd=realized_profit,
        )
        rec = OwnerRecoveryVerifier(db_path=db_path, clock=lambda: T0)
        return vault, rec, db_path, pem_path

    # ------------------------------------------------------------------
    # 1. Safe SQLite schema migration on pre-existing DBs
    # ------------------------------------------------------------------
    def test_schema_migration_safe_on_legacy_bank_transfers_db(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "legacy_vault.sqlite3"
            # Create a legacy pre-PR#31 bank_transfers table without phase columns
            with closing(sqlite3.connect(str(db_path))) as conn:
                conn.executescript(
                    """
                    CREATE TABLE vault_config (
                        scope_id TEXT PRIMARY KEY,
                        sweep_ratio_text TEXT NOT NULL,
                        auto_sweep_enabled INTEGER NOT NULL,
                        preferred_rail TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        initial_capital_usd_text TEXT
                    );
                    CREATE TABLE sweep_events (
                        trade_id TEXT NOT NULL,
                        scope_id TEXT NOT NULL,
                        symbol TEXT NOT NULL,
                        broker_id TEXT NOT NULL,
                        realized_net_usd_text TEXT NOT NULL,
                        retained_trading_usd_text TEXT NOT NULL,
                        bank_sweep_usd_text TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        session_date TEXT,
                        PRIMARY KEY (scope_id, trade_id)
                    );
                    CREATE TABLE bank_transfers (
                        transfer_id TEXT PRIMARY KEY,
                        scope_id TEXT NOT NULL,
                        rail TEXT NOT NULL,
                        broker_id TEXT,
                        destination_bank_id TEXT NOT NULL,
                        amount_usd_text TEXT NOT NULL,
                        status TEXT NOT NULL,
                        provider_tx_id TEXT,
                        owner_request_id TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        settled_at TEXT,
                        idempotency_key TEXT UNIQUE,
                        error_detail TEXT
                    );
                    CREATE TABLE vault_audit (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        prev_sha256 TEXT NOT NULL,
                        entry_sha256 TEXT NOT NULL,
                        scope_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    """
                    INSERT INTO bank_transfers VALUES
                    ('tr-legacy-sub', 'default', 'COINBASE_ACH', NULL, 'pm-bank-1', '50.00',
                     'ACH_SUBMITTED', 'cb-old-1', 'req-old-1', 'legacy sub', '2026-11-20T00:00:00Z',
                     '2026-11-20T00:01:00Z', 'idem-old-1', NULL),
                    ('tr-legacy-unk', 'default', 'KRAKEN_ACH', NULL, 'krk-bank-1', '75.00',
                     'OUTCOME_UNKNOWN', NULL, 'req-old-2', 'legacy unk', '2026-11-20T00:02:00Z',
                     NULL, 'idem-old-2', 'OfframpTransportError:503')
                    """
                )
                conn.commit()

            vault = ProfitSweepVault(db_path, scope_id="default", clock=lambda: T0)
            row_sub = _read_transfer_row(db_path, "tr-legacy-sub")
            row_unk = _read_transfer_row(db_path, "tr-legacy-unk")
            self.assertEqual(row_sub["conversion_status"], CONVERSION_STATUS_NOT_REQUIRED)
            self.assertEqual(row_sub["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)
            self.assertEqual(row_unk["conversion_status"], CONVERSION_STATUS_NOT_REQUIRED)
            self.assertEqual(row_unk["withdrawal_status"], WITHDRAWAL_STATUS_OUTCOME_UNKNOWN)

            # Migrated withdrawal-only OUTCOME_UNKNOWN row still retries cleanly
            rec = OwnerRecoveryVerifier(db_path=db_path, clock=lambda: T0)
            krk_ok = KrakenOfframpClient(
                api_key="krk-pub-1",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="krk-bank-1",
                http_call=lambda *_a: (200, json.dumps({"error": [], "result": {"refid": "KRK-MIG-1"}}).encode()),
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("75.00"),
                owner_request_id="req-mig-retry",
                reason="retry migrated",
                kraken_client=krk_ok,
                retry_transfer_id="tr-legacy-unk",
            )
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("75.00"),
                owner_request_id="req-mig-retry",
                reason="retry migrated",
                verifier=rec,
                recovery_token=tok,
                kraken_client=krk_ok,
                retry_transfer_id="tr-legacy-unk",
                intent_id=prep["intent_id"],
                intent_sha256=prep["intent_sha256"],
            )
            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(out["provider_tx_id"], "KRK-MIG-1")
            self.assertEqual(out["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)

    # ------------------------------------------------------------------
    # 2. Coinbase two-phase happy path: durable pre-commit + distinct idempotency keys
    # ------------------------------------------------------------------
    def test_coinbase_two_phase_happy_path_distinct_idempotency_keys_and_durable_journal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, db_path, pem_path = self._setup_vault(root)
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("120.00"),
                owner_request_id="req-cb-2phase",
                reason="coinbase convert + ach",
                destination_bank_id="pm-bank-cb-01",
                convert_from_currency="USDC",
                convert_amount=D("120.00"),
                coinbase_source_account_uuid="acct-usdc-1",
                coinbase_usd_account_uuid="acct-usd-1",
                idempotency_key="idem-wd-cb-001",
            )
            tid = str(prep["transfer_id"])
            observed_db_states: list[tuple[str, str, str, str | None]] = []
            seen_requests: list[tuple[str, dict[str, str], dict[str, object]]] = []

            def cb_http(method: str, url: str, headers: dict[str, str], body: bytes | None, _timeout: float) -> tuple[int, bytes]:
                doc = json.loads(body.decode("utf-8")) if body else {}
                seen_requests.append((url, dict(headers), doc))
                row = _read_transfer_row(db_path, tid)
                observed_db_states.append(
                    (
                        url,
                        str(row["conversion_status"]),
                        str(row["withdrawal_status"]),
                        str(row["conversion_tx_id"]) if row["conversion_tx_id"] else None,
                    )
                )
                if "/convert/quote" in url:
                    return 200, json.dumps({"trade": {"id": "cb-conv-tx-100", "status": "TRADE_STATUS_CREATED"}}).encode()
                if "/convert/trade/" in url:
                    return 200, json.dumps({"trade": {"id": "cb-conv-tx-100", "status": "TRADE_STATUS_COMPLETED"}}).encode()
                if "/withdrawals/fiat" in url:
                    return 200, json.dumps({"id": "cb-ach-tx-200"}).encode()
                raise AssertionError(f"Unexpected Coinbase URL: {url}")

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_path,
                linked_bank_account_id="pm-bank-cb-01",
                http_call=cb_http,
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("120.00"),
                owner_request_id="req-cb-2phase",
                reason="coinbase convert + ach",
                verifier=rec,
                recovery_token=tok,
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("120.00"),
                coinbase_source_account_uuid="acct-usdc-1",
                coinbase_usd_account_uuid="acct-usd-1",
                idempotency_key="idem-wd-cb-001",
                intent_id=prep["intent_id"],
                intent_sha256=prep["intent_sha256"],
            )

            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(out["conversion_status"], CONVERSION_STATUS_CONFIRMED)
            self.assertEqual(out["conversion_tx_id"], "cb-conv-tx-100")
            self.assertEqual(out["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)
            self.assertEqual(out["provider_tx_id"], "cb-ach-tx-200")

            # Verify durable journal states observed DURING external I/O:
            self.assertEqual(len(observed_db_states), 3)
            # Quote & commit see CONVERSION_PENDING + WITHDRAWAL_NOT_STARTED committed on disk!
            self.assertEqual(observed_db_states[0][1], CONVERSION_STATUS_PENDING)
            self.assertEqual(observed_db_states[0][2], WITHDRAWAL_STATUS_NOT_STARTED)
            self.assertEqual(observed_db_states[1][1], CONVERSION_STATUS_PENDING)
            self.assertEqual(observed_db_states[1][2], WITHDRAWAL_STATUS_NOT_STARTED)
            # Withdrawal sees CONVERSION_CONFIRMED + conv_tx_id + WITHDRAWAL_PENDING committed on disk!
            self.assertEqual(observed_db_states[2][1], CONVERSION_STATUS_CONFIRMED)
            self.assertEqual(observed_db_states[2][2], WITHDRAWAL_STATUS_PENDING)
            self.assertEqual(observed_db_states[2][3], "cb-conv-tx-100")

            # Verify provider idempotency keys transmitted on conversion & withdrawal are DISTINCT!
            conv_ref_quote = str(seen_requests[0][2].get("client_reference_id") or "")
            conv_ref_commit = str(seen_requests[1][2].get("client_reference_id") or "")
            wd_ref = str(seen_requests[2][2].get("client_reference_id") or "")
            self.assertTrue(conv_ref_quote)
            self.assertEqual(conv_ref_quote, conv_ref_commit)
            self.assertEqual(seen_requests[0][1].get("Idempotency-Key"), conv_ref_quote)
            self.assertEqual(seen_requests[1][1].get("Idempotency-Key"), conv_ref_quote)
            self.assertEqual(wd_ref, "idem-wd-cb-001")
            self.assertNotEqual(conv_ref_quote, wd_ref)
            self.assertEqual(out["conversion_client_ref"], conv_ref_quote)

            # Audit chain remains 100% valid and records every phase transition
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))
            events = _read_audit_events(db_path)
            for expected_ev in (
                "ACH_OFFRAMP_RESERVED",
                "ACH_CONVERSION_PENDING",
                "ACH_CONVERSION_CONFIRMED",
                "ACH_WITHDRAWAL_PENDING",
                "ACH_OFFRAMP_SUBMITTED",
            ):
                self.assertIn(expected_ev, events)

    # ------------------------------------------------------------------
    # 3. Kraken two-phase happy path: cl_ord_id distinct from client_ref + durable journal
    # ------------------------------------------------------------------
    def test_kraken_two_phase_happy_path_cl_ord_id_and_durable_journal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, db_path, _ = self._setup_vault(root)
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("90.00"),
                owner_request_id="req-krk-2phase",
                reason="kraken convert + ach",
                destination_bank_id="krk-bank-01",
                convert_amount=D("90.00"),
                kraken_pair="USDCUSD",
                idempotency_key="idem-wd-krk-001",
            )
            tid = str(prep["transfer_id"])
            seen_forms: list[tuple[str, dict[str, str], str, str]] = []

            def krk_http(_m: str, url: str, _h: dict[str, str], body: bytes | None, _t: float) -> tuple[int, bytes]:
                form = {k: v[0] for k, v in urllib.parse.parse_qs((body or b"").decode("utf-8")).items()}
                row = _read_transfer_row(db_path, tid)
                seen_forms.append((url, form, str(row["conversion_status"]), str(row["withdrawal_status"])))
                if "/AddOrder" in url:
                    return 200, json.dumps({"error": [], "result": {"descr": {"order": "sell 90 USDCUSD"}, "txid": ["OKRK-CONV-1"]}}).encode()
                if "/Withdraw" in url:
                    return 200, json.dumps({"error": [], "result": {"refid": "KRK-WD-1"}}).encode()
                raise AssertionError(f"Unexpected Kraken URL: {url}")

            krk = KrakenOfframpClient(
                api_key="krk-pub-1",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="krk-bank-01",
                http_call=krk_http,
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("90.00"),
                owner_request_id="req-krk-2phase",
                reason="kraken convert + ach",
                verifier=rec,
                recovery_token=tok,
                kraken_client=krk,
                convert_amount=D("90.00"),
                kraken_pair="USDCUSD",
                idempotency_key="idem-wd-krk-001",
                intent_id=prep["intent_id"],
                intent_sha256=prep["intent_sha256"],
            )
            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(out["conversion_tx_id"], "OKRK-CONV-1")
            self.assertEqual(out["provider_tx_id"], "KRK-WD-1")
            self.assertEqual(len(seen_forms), 2)
            # Phase 1 committed CONVERSION_PENDING before AddOrder and transmitted cl_ord_id
            self.assertEqual(seen_forms[0][2], CONVERSION_STATUS_PENDING)
            self.assertEqual(seen_forms[0][3], WITHDRAWAL_STATUS_NOT_STARTED)
            cl_ord_id = seen_forms[0][1].get("cl_ord_id", "")
            self.assertTrue(cl_ord_id)
            # Phase 2 committed CONVERSION_CONFIRMED + WITHDRAWAL_PENDING before Withdraw and transmitted distinct client_ref
            self.assertEqual(seen_forms[1][2], CONVERSION_STATUS_CONFIRMED)
            self.assertEqual(seen_forms[1][3], WITHDRAWAL_STATUS_PENDING)
            self.assertEqual(seen_forms[1][1].get("client_ref"), "idem-wd-krk-001")
            self.assertNotEqual(cl_ord_id, "idem-wd-krk-001")
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    # ------------------------------------------------------------------
    # 4. Finding [4]: Conversion confirmed -> withdrawal fails -> retry SKIPS conversion (0 duplicates!)
    # ------------------------------------------------------------------
    def test_conversion_confirmed_then_withdrawal_fails_retry_skips_conversion_zero_duplicates(self) -> None:
        for rail in (RAIL_COINBASE_ACH, RAIL_KRAKEN_ACH):
            with self.subTest(rail=rail), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                vault, rec, db_path, pem_path = self._setup_vault(root)
                state = {"fail_wd": True, "conv_calls": 0, "wd_calls": 0, "wd_refs": []}

                def cb_http(_m: str, url: str, _h: dict[str, str], body: bytes | None, _t: float) -> tuple[int, bytes]:
                    doc = json.loads((body or b"{}").decode("utf-8"))
                    if "/convert/quote" in url:
                        state["conv_calls"] += 1
                        return 200, json.dumps({"trade": {"id": "cb-conv-once"}}).encode()
                    if "/convert/trade/" in url:
                        return 200, json.dumps({"trade": {"id": "cb-conv-once", "status": "TRADE_STATUS_COMPLETED"}}).encode()
                    if "/withdrawals/fiat" in url:
                        state["wd_calls"] += 1
                        state["wd_refs"].append(doc.get("client_reference_id"))
                        if state["fail_wd"]:
                            return 503, b"temporary gateway outage"
                        return 200, json.dumps({"id": "cb-ach-recovered"}).encode()
                    raise AssertionError(url)

                def krk_http(_m: str, url: str, _h: dict[str, str], body: bytes | None, _t: float) -> tuple[int, bytes]:
                    form = {k: v[0] for k, v in urllib.parse.parse_qs((body or b"").decode("utf-8")).items()}
                    if "/AddOrder" in url:
                        state["conv_calls"] += 1
                        return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-CONV-ONCE"]}}).encode()
                    if "/Withdraw" in url:
                        state["wd_calls"] += 1
                        state["wd_refs"].append(form.get("client_ref"))
                        if state["fail_wd"]:
                            return 503, b"temporary gateway outage"
                        return 200, json.dumps({"error": [], "result": {"refid": "KRK-ACH-RECOVERED"}}).encode()
                    raise AssertionError(url)

                cb = CoinbaseOfframpClient(
                    key_name="organizations/org-1/apiKeys/key-1",
                    private_key_file=pem_path,
                    linked_bank_account_id="pm-bank-skip-01",
                    http_call=cb_http,
                    resolve_dns=lambda _h: ["104.18.0.1"],
                    clock=lambda: T0,
                )
                krk = KrakenOfframpClient(
                    api_key="krk-pub-1",
                    api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                    linked_bank_key="krk-bank-skip-01",
                    http_call=krk_http,
                    resolve_dns=lambda _h: ["104.16.0.1"],
                    clock=lambda: T0,
                )
                common_kwargs = (
                    dict(
                        rail=RAIL_COINBASE_ACH,
                        coinbase_client=cb,
                        convert_from_currency="USDC",
                        convert_amount=D("80.00"),
                        coinbase_source_account_uuid="src-1",
                        coinbase_usd_account_uuid="usd-1",
                    )
                    if rail == RAIL_COINBASE_ACH
                    else dict(
                        rail=RAIL_KRAKEN_ACH,
                        kraken_client=krk,
                        convert_amount=D("80.00"),
                        kraken_pair="USDCUSD",
                    )
                )

                prep1 = vault.prepare_offramp_ach_payout(
                    amount_usd=D("80.00"),
                    owner_request_id="req-skip-1",
                    reason="initial attempt",
                    idempotency_key=f"idem-skip-{rail}",
                    **common_kwargs,
                )
                tok1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep1["intent_sha256"], now=T0)
                with self.assertRaises(OfframpTransportError):
                    vault.execute_offramp_ach_payout(
                        amount_usd=D("80.00"),
                        owner_request_id="req-skip-1",
                        reason="initial attempt",
                        verifier=rec,
                        recovery_token=tok1,
                        idempotency_key=f"idem-skip-{rail}",
                        intent_id=prep1["intent_id"],
                        intent_sha256=prep1["intent_sha256"],
                        **common_kwargs,
                    )
                tid = str(prep1["transfer_id"])
                row_mid = _read_transfer_row(db_path, tid)
                self.assertEqual(row_mid["status"], "OUTCOME_UNKNOWN")
                self.assertEqual(row_mid["conversion_status"], CONVERSION_STATUS_CONFIRMED)
                self.assertTrue(row_mid["conversion_tx_id"])
                self.assertEqual(row_mid["withdrawal_status"], WITHDRAWAL_STATUS_OUTCOME_UNKNOWN)
                self.assertEqual(state["conv_calls"], 1)
                self.assertEqual(state["wd_calls"], 1)

                # Mutating conversion params on retry MUST fail closed
                tampered_kwargs = dict(common_kwargs)
                tampered_kwargs["convert_amount"] = D("95.00")
                prep_bad = vault.prepare_offramp_ach_payout(
                    amount_usd=D("80.00"),
                    owner_request_id="req-skip-tamper",
                    reason="tampered conv",
                    retry_transfer_id=tid,
                    **tampered_kwargs,
                )
                tok_bad = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_bad["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError):
                    vault.execute_offramp_ach_payout(
                        amount_usd=D("80.00"),
                        owner_request_id="req-skip-tamper",
                        reason="tampered conv",
                        verifier=rec,
                        recovery_token=tok_bad,
                        retry_transfer_id=tid,
                        intent_id=prep_bad["intent_id"],
                        intent_sha256=prep_bad["intent_sha256"],
                        **tampered_kwargs,
                    )
                self.assertEqual(state["conv_calls"], 1)
                self.assertEqual(state["wd_calls"], 1)

                # Valid retry MUST SKIP Phase 1 conversion completely (0 duplicate conversions!) and complete Phase 2
                state["fail_wd"] = False
                prep2 = vault.prepare_offramp_ach_payout(
                    amount_usd=D("80.00"),
                    owner_request_id="req-skip-retry",
                    reason="retry after conv confirmed",
                    retry_transfer_id=tid,
                    **common_kwargs,
                )
                tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep2["intent_sha256"], now=T0)
                out = vault.execute_offramp_ach_payout(
                    amount_usd=D("80.00"),
                    owner_request_id="req-skip-retry",
                    reason="retry after conv confirmed",
                    verifier=rec,
                    recovery_token=tok2,
                    retry_transfer_id=tid,
                    intent_id=prep2["intent_id"],
                    intent_sha256=prep2["intent_sha256"],
                    **common_kwargs,
                )
                self.assertEqual(out["status"], "ACH_SUBMITTED")
                self.assertEqual(out["conversion_status"], CONVERSION_STATUS_CONFIRMED)
                self.assertEqual(out["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)
                self.assertEqual(state["conv_calls"], 1)  # ZERO duplicate conversions!
                self.assertEqual(state["wd_calls"], 2)
                self.assertEqual(state["wd_refs"][0], state["wd_refs"][1])
                self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    # ------------------------------------------------------------------
    # 5. Finding [4]: Ambiguous conversion freezes transfer & blocks BOTH conversion and withdrawal
    # ------------------------------------------------------------------
    def test_ambiguous_conversion_freezes_transfer_and_refuses_retry_until_reconciled(self) -> None:
        scenarios = [
            ("http_timeout", lambda _m, url, _h, _b, _t: (504, b"gateway timeout")),
            ("missing_tx_id", lambda _m, url, _h, _b, _t: (200, json.dumps({"trade": {"status": "TRADE_STATUS_COMPLETED"}}).encode())),
            ("pending_status", lambda _m, url, _h, _b, _t: (200, json.dumps({"trade": {"id": "cb-p1", "status": "TRADE_STATUS_PENDING"}}).encode())),
        ]
        for label, cb_handler in scenarios:
            with self.subTest(scenario=label), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                vault, rec, db_path, pem_path = self._setup_vault(root)
                calls = {"conv": 0, "wd": 0}

                def cb_http(m: str, url: str, h: dict[str, str], b: bytes | None, t: float) -> tuple[int, bytes]:
                    if "/convert/" in url:
                        calls["conv"] += 1
                        return cb_handler(m, url, h, b, t)
                    calls["wd"] += 1
                    return 200, json.dumps({"id": "should-never-run"}).encode()

                cb = CoinbaseOfframpClient(
                    key_name="organizations/org-1/apiKeys/key-1",
                    private_key_file=pem_path,
                    linked_bank_account_id="pm-bank-freeze-01",
                    http_call=cb_http,
                    resolve_dns=lambda _h: ["104.18.0.1"],
                    clock=lambda: T0,
                )
                prep = vault.prepare_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-freeze-1",
                    reason="ambiguous conversion",
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("100.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                )
                tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
                with self.assertRaises((OfframpTransportError, OfframpSecurityError)):
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("100.00"),
                        owner_request_id="req-freeze-1",
                        reason="ambiguous conversion",
                        verifier=rec,
                        recovery_token=tok,
                        coinbase_client=cb,
                        convert_from_currency="USDC",
                        convert_amount=D("100.00"),
                        coinbase_source_account_uuid="src-1",
                        coinbase_usd_account_uuid="usd-1",
                        intent_id=prep["intent_id"],
                        intent_sha256=prep["intent_sha256"],
                    )
                tid = str(prep["transfer_id"])
                row = _read_transfer_row(db_path, tid)
                self.assertEqual(row["status"], "OUTCOME_UNKNOWN")
                self.assertEqual(row["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)
                self.assertEqual(row["withdrawal_status"], WITHDRAWAL_STATUS_NOT_STARTED)
                self.assertEqual(calls["wd"], 0)
                conv_calls_after_fail = calls["conv"]

                # Retry WITH conversion params MUST BE REFUSED
                prep_r1 = vault.prepare_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-freeze-retry-1",
                    reason="blocked retry",
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("100.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                    retry_transfer_id=tid,
                )
                tok_r1 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_r1["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError) as ctx1:
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("100.00"),
                        owner_request_id="req-freeze-retry-1",
                        reason="blocked retry",
                        verifier=rec,
                        recovery_token=tok_r1,
                        coinbase_client=cb,
                        convert_from_currency="USDC",
                        convert_amount=D("100.00"),
                        coinbase_source_account_uuid="src-1",
                        coinbase_usd_account_uuid="usd-1",
                        retry_transfer_id=tid,
                        intent_id=prep_r1["intent_id"],
                        intent_sha256=prep_r1["intent_sha256"],
                    )
                self.assertIn("CONVERSION_OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION", str(ctx1.exception))
                self.assertEqual(calls["conv"], conv_calls_after_fail)
                self.assertEqual(calls["wd"], 0)

                # Retry WITHOUT conversion params (bypass attempt straight to withdrawal) MUST ALSO BE REFUSED
                prep_r2 = vault.prepare_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-freeze-bypass",
                    reason="bypass attempt",
                    coinbase_client=cb,
                    retry_transfer_id=tid,
                )
                tok_r2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_r2["intent_sha256"], now=T0)
                with self.assertRaises(OfframpSecurityError) as ctx2:
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("100.00"),
                        owner_request_id="req-freeze-bypass",
                        reason="bypass attempt",
                        verifier=rec,
                        recovery_token=tok_r2,
                        coinbase_client=cb,
                        retry_transfer_id=tid,
                        intent_id=prep_r2["intent_id"],
                        intent_sha256=prep_r2["intent_sha256"],
                    )
                self.assertIn("CONVERSION_OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION", str(ctx2.exception))
                self.assertEqual(calls["wd"], 0)

                # Simulated crash leaving row in CONVERSION_PENDING MUST ALSO freeze retries!
                with closing(sqlite3.connect(str(db_path))) as conn:
                    conn.execute(
                        "UPDATE bank_transfers SET status = 'RESERVED_PENDING_DISPATCH', conversion_status = ? WHERE transfer_id = ?",
                        (CONVERSION_STATUS_PENDING, tid),
                    )
                    conn.commit()
                with self.assertRaises(OfframpSecurityError):
                    vault.execute_offramp_ach_payout(
                        rail=RAIL_COINBASE_ACH,
                        amount_usd=D("100.00"),
                        owner_request_id="req-freeze-bypass",
                        reason="bypass attempt",
                        verifier=rec,
                        recovery_token=tok_r2,
                        coinbase_client=cb,
                        retry_transfer_id=tid,
                        intent_id=prep_r2["intent_id"],
                        intent_sha256=prep_r2["intent_sha256"],
                    )
                self.assertEqual(calls["wd"], 0)

    # ------------------------------------------------------------------
    # 6. reconcile_conversion_outcome -> CONFIRMED -> retry skips conversion (0 duplicates!)
    # ------------------------------------------------------------------
    def test_reconcile_conversion_outcome_confirmed_unfreezes_and_skips_duplicate_conversion(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, db_path, pem_path = self._setup_vault(root)
            calls = {"conv_post": 0, "conv_get": 0, "wd_post": 0}
            reconcile_resp = {"mode": "pending"}

            def cb_http(method: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                if method == "POST" and "/convert/" in url:
                    calls["conv_post"] += 1
                    return 504, b"timeout after commit"
                if method == "GET" and "/convert/trade" in url:
                    calls["conv_get"] += 1
                    row = _read_transfer_row(db_path, tid)
                    ref = str(row["conversion_client_ref"])
                    if reconcile_resp["mode"] == "pending":
                        return 200, json.dumps({"trade": {"id": "cb-conv-r1", "status": "TRADE_STATUS_PENDING", "client_reference_id": ref}}).encode()
                    if reconcile_resp["mode"] == "wrong_ref":
                        return 200, json.dumps({"trade": {"id": "cb-conv-r1", "status": "TRADE_STATUS_COMPLETED", "client_reference_id": "wrong-ref"}}).encode()
                    if reconcile_resp["mode"] == "wrong_amount":
                        return 200, json.dumps({"trade": {"id": "cb-conv-r1", "status": "TRADE_STATUS_COMPLETED", "client_reference_id": ref, "amount": "55"}}).encode()
                    if reconcile_resp["mode"] == "missing_id":
                        return 200, json.dumps({"trade": {"status": "TRADE_STATUS_COMPLETED", "client_reference_id": ref}}).encode()
                    return 200, json.dumps({
                        "trades": [{
                            "id": "cb-conv-confirmed-77",
                            "status": "TRADE_STATUS_COMPLETED",
                            "client_reference_id": ref,
                            "from_currency": "USDC",
                            "amount": "110",
                        }]
                    }).encode()
                if method == "POST" and "/withdrawals/fiat" in url:
                    calls["wd_post"] += 1
                    return 200, json.dumps({"id": "cb-ach-after-rec-77"}).encode()
                raise AssertionError(f"Unexpected {method} {url}")

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_path,
                linked_bank_account_id="pm-bank-rec-01",
                http_call=cb_http,
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("110.00"),
                owner_request_id="req-rec-1",
                reason="reconcile confirmed test",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("110.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
            )
            tid = str(prep["transfer_id"])
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("110.00"),
                    owner_request_id="req-rec-1",
                    reason="reconcile confirmed test",
                    verifier=rec,
                    recovery_token=tok,
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("110.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )
            self.assertEqual(calls["conv_post"], 1)
            self.assertEqual(calls["wd_post"], 0)

            # Ambiguous / mismatched exchange history responses MUST fail closed and stay frozen!
            for bad_mode in ("pending", "wrong_ref", "wrong_amount", "missing_id"):
                reconcile_resp["mode"] = bad_mode
                with self.assertRaises(OfframpSecurityError):
                    vault.reconcile_conversion_outcome(transfer_id=tid, coinbase_client=cb)
                self.assertEqual(_read_transfer_row(db_path, tid)["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

            # Authoritative exchange history confirms conversion -> unfreezes as CONVERSION_CONFIRMED!
            reconcile_resp["mode"] = "confirmed"
            rec_out = vault.reconcile_conversion_outcome(transfer_id=tid, coinbase_client=cb)
            self.assertEqual(rec_out["reconciliation_outcome"], "CONFIRMED")
            self.assertEqual(rec_out["conversion_status"], CONVERSION_STATUS_CONFIRMED)
            self.assertEqual(rec_out["conversion_tx_id"], "cb-conv-confirmed-77")
            self.assertEqual(rec_out["status"], "RESERVED_PENDING_DISPATCH")

            # Now retry executes Phase 2 ACH withdrawal directly with ZERO duplicate conversions!
            prep2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("110.00"),
                owner_request_id="req-rec-retry",
                reason="complete phase 2 after reconcile",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("110.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
                retry_transfer_id=tid,
            )
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep2["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("110.00"),
                owner_request_id="req-rec-retry",
                reason="complete phase 2 after reconcile",
                verifier=rec,
                recovery_token=tok2,
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("110.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
                retry_transfer_id=tid,
                intent_id=prep2["intent_id"],
                intent_sha256=prep2["intent_sha256"],
            )
            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(out["conversion_tx_id"], "cb-conv-confirmed-77")
            self.assertEqual(out["provider_tx_id"], "cb-ach-after-rec-77")
            self.assertEqual(calls["conv_post"], 1)  # ZERO duplicate conversions!
            self.assertEqual(calls["wd_post"], 1)
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    # ------------------------------------------------------------------
    # 7. reconcile_conversion_outcome -> NOT_EXECUTED -> retry reuses exact conversion_client_ref
    # ------------------------------------------------------------------
    def test_reconcile_conversion_outcome_not_executed_allows_idempotent_single_retry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, db_path, _ = self._setup_vault(root)
            seen_cl_ord_ids: list[str] = []
            fail_first = {"flag": True}

            def krk_http(_m: str, url: str, _h: dict[str, str], body: bytes | None, _t: float) -> tuple[int, bytes]:
                form = {k: v[0] for k, v in urllib.parse.parse_qs((body or b"").decode("utf-8")).items()}
                if "/AddOrder" in url:
                    seen_cl_ord_ids.append(form.get("cl_ord_id", ""))
                    if fail_first["flag"]:
                        return 502, b"bad gateway"
                    return 200, json.dumps({"error": [], "result": {"txid": ["OKRK-RETRY-OK"]}}).encode()
                if "/Withdraw" in url:
                    return 200, json.dumps({"error": [], "result": {"refid": "KRK-WD-AFTER-NOTEXEC"}}).encode()
                raise AssertionError(url)

            krk = KrakenOfframpClient(
                api_key="krk-pub-1",
                api_secret_b64=base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii"),
                linked_bank_key="krk-bank-ne-01",
                http_call=krk_http,
                resolve_dns=lambda _h: ["104.16.0.1"],
                clock=lambda: T0,
            )
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("65.00"),
                owner_request_id="req-krk-ne-1",
                reason="not executed reconcile test",
                kraken_client=krk,
                convert_amount=D("65.00"),
                kraken_pair="USDCUSD",
            )
            tid = str(prep["transfer_id"])
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_KRAKEN_ACH,
                    amount_usd=D("65.00"),
                    owner_request_id="req-krk-ne-1",
                    reason="not executed reconcile test",
                    verifier=rec,
                    recovery_token=tok,
                    kraken_client=krk,
                    convert_amount=D("65.00"),
                    kraken_pair="USDCUSD",
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )

            # Bare NOT_FOUND without history_complete=True and partial fill CANCELLED MUST fail closed!
            with self.assertRaises(OfframpSecurityError):
                vault.reconcile_conversion_outcome(
                    transfer_id=tid,
                    exchange_history_checker=lambda _ctx: {"status": "NOT_FOUND"},
                )
            with self.assertRaises(OfframpSecurityError):
                vault.reconcile_conversion_outcome(
                    transfer_id=tid,
                    exchange_history_checker=lambda ctx: {
                        "status": "CANCELLED",
                        "cl_ord_id": ctx["conversion_client_ref"],
                        "vol_exec": "20.0",
                    },
                )
            self.assertEqual(_read_transfer_row(db_path, tid)["conversion_status"], CONVERSION_STATUS_OUTCOME_UNKNOWN)

            # Definitive CANCELLED with vol_exec=0 unfreezes to CONVERSION_NOT_STARTED
            rec_ne = vault.reconcile_conversion_outcome(
                transfer_id=tid,
                exchange_history_checker=lambda ctx: {
                    "status": "CANCELLED",
                    "cl_ord_id": ctx["conversion_client_ref"],
                    "vol_exec": "0",
                },
            )
            self.assertEqual(rec_ne["reconciliation_outcome"], "NOT_EXECUTED")
            self.assertEqual(rec_ne["conversion_status"], CONVERSION_STATUS_NOT_STARTED)

            # Retry now runs Phase 1 with the EXACT SAME deterministic cl_ord_id, then Phase 2!
            fail_first["flag"] = False
            prep2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("65.00"),
                owner_request_id="req-krk-ne-retry",
                reason="retry after confirmed not executed",
                kraken_client=krk,
                convert_amount=D("65.00"),
                kraken_pair="USDCUSD",
                retry_transfer_id=tid,
            )
            tok2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep2["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("65.00"),
                owner_request_id="req-krk-ne-retry",
                reason="retry after confirmed not executed",
                verifier=rec,
                recovery_token=tok2,
                kraken_client=krk,
                convert_amount=D("65.00"),
                kraken_pair="USDCUSD",
                retry_transfer_id=tid,
                intent_id=prep2["intent_id"],
                intent_sha256=prep2["intent_sha256"],
            )
            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(out["conversion_tx_id"], "OKRK-RETRY-OK")
            self.assertEqual(out["provider_tx_id"], "KRK-WD-AFTER-NOTEXEC")
            self.assertEqual(len(seen_cl_ord_ids), 2)
            self.assertTrue(seen_cl_ord_ids[0])
            self.assertEqual(seen_cl_ord_ids[0], seen_cl_ord_ids[1])
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    # ------------------------------------------------------------------
    # 8. reconcile_withdrawal_outcome: fail-closed + SETTLED reconciliation
    # ------------------------------------------------------------------
    def test_reconcile_withdrawal_outcome_fail_closed_and_settled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, db_path, pem_path = self._setup_vault(root)
            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_path,
                linked_bank_account_id="pm-bank-wdrec-01",
                http_call=lambda *_a: (503, b"timeout on ach"),
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("55.00"),
                owner_request_id="req-wdrec-1",
                reason="withdrawal reconcile test",
                coinbase_client=cb,
                idempotency_key="idem-wdrec-001",
            )
            tid = str(prep["transfer_id"])
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            with self.assertRaises(OfframpTransportError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("55.00"),
                    owner_request_id="req-wdrec-1",
                    reason="withdrawal reconcile test",
                    verifier=rec,
                    recovery_token=tok,
                    coinbase_client=cb,
                    idempotency_key="idem-wdrec-001",
                    intent_id=prep["intent_id"],
                    intent_sha256=prep["intent_sha256"],
                )
            self.assertEqual(_read_transfer_row(db_path, tid)["withdrawal_status"], WITHDRAWAL_STATUS_OUTCOME_UNKNOWN)

            # Mismatched destination, amount, client_ref, or missing tx_id fail closed
            for bad_ev in (
                {"status": "SETTLED", "provider_tx_id": "tx-1", "destination_bank_id": "attacker-bank", "amount_usd": "55.00"},
                {"status": "SETTLED", "provider_tx_id": "tx-1", "destination_bank_id": "pm-bank-wdrec-01", "amount_usd": "99.00"},
                {"status": "SETTLED", "provider_tx_id": "tx-1", "client_reference_id": "wrong-idem"},
                {"status": "SETTLED", "destination_bank_id": "pm-bank-wdrec-01", "amount_usd": "55.00"},
            ):
                with self.assertRaises(OfframpSecurityError):
                    vault.reconcile_withdrawal_outcome(
                        transfer_id=tid,
                        exchange_history_checker=lambda _ctx, ev=bad_ev: ev,
                    )
                self.assertEqual(_read_transfer_row(db_path, tid)["withdrawal_status"], WITHDRAWAL_STATUS_OUTCOME_UNKNOWN)

            # Matching authoritative SETTLED receipt resolves transfer cleanly without duplicate dispatch
            res = vault.reconcile_withdrawal_outcome(
                transfer_id=tid,
                exchange_history_checker=lambda ctx: {
                    "status": "SETTLED",
                    "provider_tx_id": "cb-settled-999",
                    "client_reference_id": ctx["idempotency_key"],
                    "destination_bank_id": ctx["destination_bank_id"],
                    "amount_usd": ctx["amount_usd"],
                },
            )
            self.assertEqual(res["status"], "SETTLED")
            self.assertEqual(res["withdrawal_status"], WITHDRAWAL_STATUS_SUBMITTED)
            self.assertEqual(res["provider_tx_id"], "cb-settled-999")
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    # ------------------------------------------------------------------
    # 9. Finding [12] epoch_guard hook: aborts BEFORE conversion AND BEFORE withdrawal
    # ------------------------------------------------------------------
    def test_epoch_guard_aborts_before_conversion_and_between_phases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, db_path, pem_path = self._setup_vault(root, realized_profit=D("400.00"))  # $200 vault
            net_calls = {"conv": 0, "wd": 0}
            epoch_state = {"revoked": True}

            def cb_http(_m: str, url: str, _h: dict[str, str], _b: bytes | None, _t: float) -> tuple[int, bytes]:
                if "/convert/quote" in url:
                    net_calls["conv"] += 1
                    return 200, json.dumps({"trade": {"id": "cb-conv-ep-1"}}).encode()
                if "/convert/trade/" in url:
                    # Simulate token rotation occurring DURING conversion!
                    epoch_state["revoked"] = True
                    return 200, json.dumps({"trade": {"id": "cb-conv-ep-1", "status": "TRADE_STATUS_COMPLETED"}}).encode()
                if "/withdrawals/fiat" in url:
                    net_calls["wd"] += 1
                    return 200, json.dumps({"id": "cb-ach-ep-1"}).encode()
                raise AssertionError(url)

            cb = CoinbaseOfframpClient(
                key_name="organizations/org-1/apiKeys/key-1",
                private_key_file=pem_path,
                linked_bank_account_id="pm-bank-ep-01",
                http_call=cb_http,
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=lambda: T0,
            )

            guard_hits: list[str] = []

            def guard() -> None:
                guard_hits.append("checked")
                if epoch_state["revoked"]:
                    raise _FakeSessionRevokedError("SESSION_EPOCH_REVOKED")

            # Case A: epoch already revoked before Phase 1 conversion -> 0 network calls, reserve freed!
            prep_a = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ep-a",
                reason="epoch abort before conv",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("100.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
            )
            tok_a = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_a["intent_sha256"], now=T0)
            with self.assertRaises(_FakeSessionRevokedError):
                vault.execute_offramp_ach_payout(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-ep-a",
                    reason="epoch abort before conv",
                    verifier=rec,
                    recovery_token=tok_a,
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("100.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                    intent_id=prep_a["intent_id"],
                    intent_sha256=prep_a["intent_sha256"],
                    epoch_guard=guard,
                )
            self.assertEqual(net_calls["conv"], 0)
            self.assertEqual(net_calls["wd"], 0)
            self.assertEqual(len(guard_hits), 1)
            row_a = _read_transfer_row(db_path, str(prep_a["transfer_id"]))
            self.assertEqual(row_a["status"], "ABORTED_EPOCH_REVOKED")
            self.assertEqual(row_a["conversion_status"], CONVERSION_STATUS_NOT_STARTED)
            # Full $200 reserve remains available because zero external effects occurred!
            self.assertEqual(vault.snapshot()["pending_disbursement_usd"], "200")

            # Case B: epoch valid for Phase 1 conversion, rotates DURING conversion -> Phase 2 withdrawal BLOCKED!
            epoch_state["revoked"] = False
            guard_hits.clear()
            prep_b = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ep-b",
                reason="epoch abort between phases",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("100.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
            )
            tid_b = str(prep_b["transfer_id"])
            tok_b = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_b["intent_sha256"], now=T0)
            with self.assertRaises(_FakeSessionRevokedError):
                vault.execute_prepared_ach_offramp(
                    rail=RAIL_COINBASE_ACH,
                    amount_usd=D("100.00"),
                    owner_request_id="req-ep-b",
                    reason="epoch abort between phases",
                    verifier=rec,
                    recovery_token=tok_b,
                    coinbase_client=cb,
                    convert_from_currency="USDC",
                    convert_amount=D("100.00"),
                    coinbase_source_account_uuid="src-1",
                    coinbase_usd_account_uuid="usd-1",
                    intent_id=prep_b["intent_id"],
                    intent_sha256=prep_b["intent_sha256"],
                    epoch_guard=guard,
                )
            self.assertEqual(len(guard_hits), 2)
            self.assertEqual(net_calls["conv"], 1)
            self.assertEqual(net_calls["wd"], 0)
            row_b = _read_transfer_row(db_path, tid_b)
            self.assertEqual(row_b["status"], "RESERVED_PENDING_DISPATCH")
            self.assertEqual(row_b["conversion_status"], CONVERSION_STATUS_CONFIRMED)
            self.assertEqual(row_b["conversion_tx_id"], "cb-conv-ep-1")
            self.assertEqual(row_b["withdrawal_status"], WITHDRAWAL_STATUS_NOT_STARTED)

            # Retry under a fresh valid epoch SKIPS conversion (0 duplicates!) and submits Phase 2 withdrawal!
            epoch_state["revoked"] = False
            prep_b2 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ep-b-retry",
                reason="complete phase 2 under new epoch",
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("100.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
                retry_transfer_id=tid_b,
            )
            tok_b2 = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_b2["intent_sha256"], now=T0)
            res_b2 = vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("100.00"),
                owner_request_id="req-ep-b-retry",
                reason="complete phase 2 under new epoch",
                verifier=rec,
                recovery_token=tok_b2,
                coinbase_client=cb,
                convert_from_currency="USDC",
                convert_amount=D("100.00"),
                coinbase_source_account_uuid="src-1",
                coinbase_usd_account_uuid="usd-1",
                retry_transfer_id=tid_b,
                intent_id=prep_b2["intent_id"],
                intent_sha256=prep_b2["intent_sha256"],
                epoch_guard=guard,
            )
            self.assertEqual(res_b2["status"], "ACH_SUBMITTED")
            self.assertEqual(net_calls["conv"], 1)  # Still 1 (zero duplicate conversion!)
            self.assertEqual(net_calls["wd"], 1)

            # Case C: confirm_broker_2fa_withdrawal also honors epoch_guard before calling provider_verifier
            prep_2fa = vault.prepare_broker_2fa_withdrawal(
                broker_id="HUGOSWAY_MT5",
                amount_usd=D("50.00"),
                owner_request_id="req-2fa-ep",
                reason="2fa epoch test",
            )
            tok_2fa_req = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_2fa["intent_sha256"], now=T0)
            req_2fa = vault.request_broker_2fa_withdrawal(
                broker_id="HUGOSWAY_MT5",
                amount_usd=D("50.00"),
                owner_request_id="req-2fa-ep",
                reason="2fa epoch test",
                verifier=rec,
                recovery_token=tok_2fa_req,
                intent_id=prep_2fa["intent_id"],
                intent_sha256=prep_2fa["intent_sha256"],
            )
            tok_2fa_cfm = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=req_2fa["transfer_id"], now=T0)
            pv_calls = {"n": 0}

            def pv(_b: str, _tx: str) -> dict[str, str]:
                pv_calls["n"] += 1
                return {"status": "SETTLED"}

            epoch_state["revoked"] = True
            with self.assertRaises(_FakeSessionRevokedError):
                vault.confirm_broker_2fa_withdrawal(
                    transfer_id=req_2fa["transfer_id"],
                    provider_tx_id="ptx-ep-1",
                    owner_request_id="req-2fa-cfm",
                    verifier=rec,
                    recovery_token=tok_2fa_cfm,
                    provider_verifier=pv,
                    epoch_guard=guard,
                )
            self.assertEqual(pv_calls["n"], 0)
            self.assertTrue(bool(vault.verify_audit_chain()["valid"]))

    # ------------------------------------------------------------------
    # 10. Minimal test-double compatibility for convert_to_usd without client_reference_id
    # ------------------------------------------------------------------
    def test_minimal_test_double_convert_to_usd_compatibility(self) -> None:
        class _MinimalKrakenDouble:
            linked_bank_account_id = "krk-dbl-bank"

            def __init__(self) -> None:
                self.conv_calls = 0
                self.wd_calls = 0

            def convert_to_usd(self, *, pair: str = "USDCUSD", volume: Decimal) -> dict[str, object]:
                self.conv_calls += 1
                return {"txid": [f"DBL-CONV-{pair}-{volume}"]}

            def withdraw_usd_to_linked_bank_ach(
                self, *, amount_usd: Decimal, client_reference_id: str | None = None
            ) -> dict[str, object]:
                self.wd_calls += 1
                return {"refid": f"DBL-WD-{client_reference_id}"}

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault, rec, _, _ = self._setup_vault(root)
            dbl = _MinimalKrakenDouble()
            prep = vault.prepare_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("40.00"),
                owner_request_id="req-dbl-1",
                reason="minimal double test",
                kraken_client=dbl,  # type: ignore[arg-type]
                convert_amount=D("40.00"),
                kraken_pair="USDCUSD",
            )
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep["intent_sha256"], now=T0)
            out = vault.execute_offramp_ach_payout(
                rail=RAIL_KRAKEN_ACH,
                amount_usd=D("40.00"),
                owner_request_id="req-dbl-1",
                reason="minimal double test",
                verifier=rec,
                recovery_token=tok,
                kraken_client=dbl,  # type: ignore[arg-type]
                convert_amount=D("40.00"),
                kraken_pair="USDCUSD",
                intent_id=prep["intent_id"],
                intent_sha256=prep["intent_sha256"],
            )
            self.assertEqual(out["status"], "ACH_SUBMITTED")
            self.assertEqual(dbl.conv_calls, 1)
            self.assertEqual(dbl.wd_calls, 1)

    # ------------------------------------------------------------------
    # 11. Structural Lantern LW-EFFECT-BEFORE-RECORD & hygiene invariants on profit_sweep.py
    # ------------------------------------------------------------------
    def test_static_lw_effect_before_record_and_hygiene_invariants(self) -> None:
        ps_path = REPO_ROOT / "src/cas_forex_revamp/treasury/profit_sweep.py"
        raw = ps_path.read_bytes()
        self.assertEqual(raw.count(b"\r"), 0, "profit_sweep.py must be LF-only (CR=0)")
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "profit_sweep.py must not contain UTF-8 BOM")

        text = raw.decode("utf-8")
        tree = ast.parse(text, filename=str(ps_path))

        # Zero assert statements anywhere in profit_sweep.py
        assert_lines = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        self.assertEqual(assert_lines, [])

        # Zero new suppression markers added beyond the 4 pre-existing ones
        suppression_marker = "#" + " nosec"
        suppression_count = sum(1 for line in text.splitlines() if suppression_marker in line)
        self.assertLessEqual(suppression_count, 4)

        # Locate ProfitSweepVault.execute_offramp_ach_payout and inspect ONLY its direct body (excluding nested defs!)
        exec_fn: ast.FunctionDef | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "ProfitSweepVault":
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "execute_offramp_ach_payout":
                        exec_fn = item
                        break
        self.assertIsNotNone(exec_fn)
        if exec_fn is None:
            return

        direct_update_lines: list[int] = []
        direct_commit_lines: list[int] = []
        direct_conv_lines: list[int] = []
        direct_wd_lines: list[int] = []

        def _walk_without_nested_defs(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                    attr = child.func.attr
                    if attr == "execute" and child.args:
                        arg0 = child.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and "UPDATE bank_transfers" in arg0.value:
                            direct_update_lines.append(child.lineno)
                    elif attr == "commit":
                        direct_commit_lines.append(child.lineno)
                    elif attr == "convert_to_usd":
                        direct_conv_lines.append(child.lineno)
                    elif attr == "withdraw_usd_to_linked_bank_ach":
                        direct_wd_lines.append(child.lineno)
                _walk_without_nested_defs(child)

        _walk_without_nested_defs(exec_fn)

        self.assertGreaterEqual(len(direct_conv_lines), 2)
        self.assertGreaterEqual(len(direct_wd_lines), 2)

        # Every convert_to_usd and every withdraw_usd_to_linked_bank_ach MUST have a direct
        # SQLite UPDATE bank_transfers + conn.commit() strictly BEFORE it in execute_offramp_ach_payout!
        for conv_ln in direct_conv_lines:
            self.assertTrue(
                any(u < conv_ln for u in direct_update_lines),
                f"Missing direct UPDATE bank_transfers before convert_to_usd at line {conv_ln}",
            )
            self.assertTrue(
                any(c < conv_ln for c in direct_commit_lines),
                f"Missing direct conn.commit() before convert_to_usd at line {conv_ln}",
            )
        for wd_ln in direct_wd_lines:
            # Must have an UPDATE + commit specifically AFTER conversion calls and BEFORE withdrawal!
            self.assertTrue(
                any(max(direct_conv_lines) < u < wd_ln for u in direct_update_lines),
                f"Missing Phase 2 direct UPDATE bank_transfers before withdraw_usd_to_linked_bank_ach at line {wd_ln}",
            )
            self.assertTrue(
                any(max(direct_conv_lines) < c < wd_ln for c in direct_commit_lines),
                f"Missing Phase 2 direct conn.commit() before withdraw_usd_to_linked_bank_ach at line {wd_ln}",
            )


if __name__ == "__main__":
    unittest.main()
