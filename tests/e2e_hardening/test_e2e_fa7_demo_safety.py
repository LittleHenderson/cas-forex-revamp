"""E2E FA-7: Dual-Mode DEMO-Default Safety, Live Auth Ticket Guards & PR #17 Non-Collision (10 tests)."""
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404: invokes git status/diff read-only to verify PR #17 non-collision without shell
import tempfile
import unittest

from cas_forex_revamp.venue.dual_shield_router import (
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
    OffMarketBrokerQuoteError,
    QuoteReferenceUnavailableError,
)
from cas_forex_revamp.venue.external_paper_broker import (
    LiveBrokerEndpointForbiddenError,
    OandaPracticePaperClient,
    REQUIRED_LIVE_ARM_PHRASE,
    resolve_execution_mode,
)
from cas_forex_revamp.venue.live_auth_ticket import (
    LiveAuthTicketError,
    mint_live_authorization_ticket,
    provision_live_auth_key,
    verify_live_authorization_ticket,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    load_mt5_credentials,
    resolve_server,
    validate_demo_server,
)

try:
    from tests.e2e_hardening._e2e_support import (
        D,
        DualBrokerTestRig,
        QUOTES_20,
        REPO_ROOT,
        SYNTH_MT5_PASS,
        SYNTH_OANDA_ACCOUNT,
        SYNTH_OANDA_TOKEN,
        StubOandaTransport,
        T0,
        clean_demo_environ,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        D,
        DualBrokerTestRig,
        QUOTES_20,
        REPO_ROOT,
        SYNTH_MT5_PASS,
        SYNTH_OANDA_ACCOUNT,
        SYNTH_OANDA_TOKEN,
        StubOandaTransport,
        T0,
        clean_demo_environ,
    )

PR17_PROTECTED_FILES = frozenset({
    "src/cas_forex_revamp/composition/autonomous_trader.py",
    "src/cas_forex_revamp/venue/dual_shield_router.py",
    "ui/src/ai-overseer.mjs",
    "ui/src/app.mjs",
    "ui/src/broker-routing.mjs",
    "ui/src/live-funding.mjs",
    "ui/src/money-flow.mjs",
    "ui/src/render.mjs",
    "ui/styles.css",
    "tests/phase6/test_pr17_live_readiness_and_close_accounting.py",
    "tests/ui/live-funding-and-no-jump.test.mjs",
    "docs/REVAMP_COMPLETION_GATE.json",
})


class DemoSafetyAndNonCollisionE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (E2E-T1-31 .. E2E-T1-35) ---

    def test_e2e_t1_31_clean_env_defaults_to_demo_and_redacts_mt5_passwords(self) -> None:
        mode, armed = resolve_execution_mode({})
        self.assertEqual(mode, "DEMO")
        self.assertFalse(armed)
        self.assertEqual(resolve_server(BROKER_HUGOSWAY_MT5, {}), "Hugosway-Demo")
        self.assertEqual(resolve_server(BROKER_LHFX_MT5, {}), "LHFXSA-Trade")

        env = clean_demo_environ(
            CAS_FOREX_HUGOSWAY_MT5_LOGIN="7001234",
            CAS_FOREX_HUGOSWAY_MT5_PASSWORD=SYNTH_MT5_PASS,
        )
        creds = load_mt5_credentials(BROKER_HUGOSWAY_MT5, env)
        self.assertIsNotNone(creds)
        self.assertEqual(creds.execution_mode, "DEMO")
        self.assertEqual(creds.server, "Hugosway-Demo")
        self.assertNotIn(SYNTH_MT5_PASS, repr(creds))
        self.assertNotIn(SYNTH_MT5_PASS, str(creds))

    def test_e2e_t1_32_live_auth_ticket_mint_and_four_binding_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "live_auth.key"
            provision_live_auth_key(key_path)
            ticket = mint_live_authorization_ticket(
                key_file=key_path,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_login="9001122",
                server="Hugo PRO5",
                ttl_seconds=300,
                issued_at=T0,
            )
            verified = verify_live_authorization_ticket(
                ticket,
                key_file=key_path,
                expected_broker_id=BROKER_HUGOSWAY_MT5,
                expected_account_login="9001122",
                expected_server="Hugo PRO5",
                now=T0 + timedelta(seconds=60),
            )
            self.assertEqual(verified["execution_mode"], "LIVE")

            with self.assertRaises(LiveAuthTicketError):
                verify_live_authorization_ticket(
                    ticket,
                    key_file=key_path,
                    expected_broker_id=BROKER_LHFX_MT5,
                    expected_account_login="9001122",
                    expected_server="Hugo PRO5",
                    now=T0 + timedelta(seconds=60),
                )

    def test_e2e_t1_33_oanda_practice_client_and_quote_truth_oracle_demo(self) -> None:
        stub = StubOandaTransport(QUOTES_20)
        client = OandaPracticePaperClient(
            environ=clean_demo_environ(
                CAS_FOREX_OANDA_PRACTICE_TOKEN=SYNTH_OANDA_TOKEN,
                CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID=SYNTH_OANDA_ACCOUNT,
            ),
            transport=stub,
        )
        self.assertEqual(client.execution_mode, "DEMO")
        self.assertIn("api-fxpractice.oanda.com", client.base_url)

        oracle = OandaQuoteTruthOracle.from_static_quotes(QUOTES_20)
        verdict = oracle.require_truthful(
            BROKER_HUGOSWAY_MT5,
            "EURUSD",
            QUOTES_20["EURUSD"][0],
            QUOTES_20["EURUSD"][1],
        )
        self.assertTrue(verdict.passed)

    def test_e2e_t1_34_dual_shield_router_snapshot_demo_barbell_and_valve(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rig = DualBrokerTestRig(td)
            router = rig.dual_router()
            snap = router.routing_snapshot()
            self.assertEqual(snap["schema"], "cas-forex.broker-routing/2")
            self.assertEqual(snap["execution_mode"], "DEMO")
            self.assertTrue(snap["demo_only"])
            self.assertTrue(snap["live_trading_locked"])
            self.assertFalse(snap["live_trading_armed"])
            self.assertEqual(snap["valve"]["parameters"], 161)
            self.assertEqual(snap["valve"]["threshold"], "0.55")
            self.assertTrue(snap["valve"]["required"])
            barbell_cfg = snap["dual_shield"]["barbell"]
            self.assertEqual(Decimal(str(barbell_cfg["oanda_reserve_share"])), Decimal("0.80"))
            self.assertEqual(Decimal(str(barbell_cfg["hugosway_share"])), Decimal("0.12"))
            self.assertEqual(Decimal(str(barbell_cfg["lhfx_share"])), Decimal("0.08"))

    def test_e2e_t1_35_mql5_and_python_live_arm_phrase_parity(self) -> None:
        mq5 = (REPO_ROOT / "mt5/CasForexMt5Bridge.mq5").read_text(encoding="utf-8")
        m = re.search(r'#define\s+LIVE_ARM_PHRASE\s+"([^"]+)"', mq5)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), REQUIRED_LIVE_ARM_PHRASE)
        self.assertEqual(REQUIRED_LIVE_ARM_PHRASE, "I_AUTHORIZE_LIVE_REAL_MONEY_TRADING")

    # --- Tier 2: Boundary & Corner Cases (E2E-T2-31 .. E2E-T2-35) ---

    def test_e2e_t2_31_demo_mode_rejects_live_mt5_and_oanda_servers(self) -> None:
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_HUGOSWAY_MT5, "Hugo PRO5")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            validate_demo_server(BROKER_LHFX_MT5, "LHFXSA-Live")
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            OandaPracticePaperClient(
                environ=clean_demo_environ(
                    CAS_FOREX_OANDA_PRACTICE_TOKEN=SYNTH_OANDA_TOKEN,
                    CAS_FOREX_OANDA_PRACTICE_ACCOUNT_ID=SYNTH_OANDA_ACCOUNT,
                ),
                base_url="https://api-fxtrade.oanda.com/v3",
            )

    def test_e2e_t2_32_live_mode_without_or_wrong_arm_phrase_rejected(self) -> None:
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            resolve_execution_mode({"CAS_FOREX_EXECUTION_MODE": "LIVE"})
        with self.assertRaises(LiveBrokerEndpointForbiddenError):
            resolve_execution_mode({
                "CAS_FOREX_EXECUTION_MODE": "LIVE",
                "CAS_FOREX_LIVE_ARM_PHRASE": "ARM_LIVE_REAL_MONEY_TRADING",
            })

    def test_e2e_t2_33_expired_or_oversized_ttl_or_short_key_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            key_path = Path(td) / "live_auth.key"
            provision_live_auth_key(key_path)
            with self.assertRaises(LiveAuthTicketError):
                mint_live_authorization_ticket(
                    key_file=key_path,
                    broker_id=BROKER_HUGOSWAY_MT5,
                    account_login="9001122",
                    server="Hugo PRO5",
                    ttl_seconds=86401,
                    issued_at=T0,
                )
            ticket = mint_live_authorization_ticket(
                key_file=key_path,
                broker_id=BROKER_HUGOSWAY_MT5,
                account_login="9001122",
                server="Hugo PRO5",
                ttl_seconds=120,
                issued_at=T0,
            )
            with self.assertRaises(LiveAuthTicketError):
                verify_live_authorization_ticket(
                    ticket,
                    key_file=key_path,
                    expected_broker_id=BROKER_HUGOSWAY_MT5,
                    expected_account_login="9001122",
                    expected_server="Hugo PRO5",
                    now=T0 + timedelta(seconds=300),
                )
            short_key = Path(td) / "short.key"
            short_key.write_text("too-short", encoding="ascii")
            with self.assertRaises(LiveAuthTicketError):
                provision_live_auth_key(short_key)

    def test_e2e_t2_34_quote_truth_oracle_rejects_off_market_and_missing_reference(self) -> None:
        oracle = OandaQuoteTruthOracle.from_static_quotes(QUOTES_20)
        with self.assertRaises(OffMarketBrokerQuoteError):
            oracle.require_truthful(
                BROKER_HUGOSWAY_MT5,
                "EURUSD",
                D("1.12000"),
                D("1.12010"),
            )
        empty_oracle = OandaQuoteTruthOracle.from_static_quotes({})
        with self.assertRaises(QuoteReferenceUnavailableError):
            empty_oracle.require_truthful(
                BROKER_HUGOSWAY_MT5,
                "EURUSD",
                QUOTES_20["EURUSD"][0],
                QUOTES_20["EURUSD"][1],
            )

    def test_e2e_t2_35_e2e_branch_has_zero_pr17_protected_file_overlap(self) -> None:
        for p in sorted(PR17_PROTECTED_FILES):
            self.assertTrue((REPO_ROOT / p).is_file(), p)
        self.assertFalse((REPO_ROOT / ".github" / "workflows").exists())
        if not (REPO_ROOT / ".git").exists():
            return
        git_bin = shutil.which("git") or "git"
        br_res = subprocess.run(  # nosec B603, B607: fixed read-only git branch argv without shell
            [git_bin, "-C", str(REPO_ROOT), "branch", "--show-current"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        branch_name = br_res.stdout.strip() if br_res.returncode == 0 else ""
        if not branch_name.startswith(("feat/e2e-", "feat/pr22-")):
            return
        res = subprocess.run(  # nosec B603, B607: fixed read-only git status argv without shell
            [git_bin, "-C", str(REPO_ROOT), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        dirty_paths: set[str] = set()
        for line in res.stdout.splitlines():
            if len(line) >= 4:
                dirty_paths.add(line[3:].strip().replace("\\", "/"))
        diff_res = subprocess.run(  # nosec B603, B607: fixed read-only git diff argv without shell
            [git_bin, "-C", str(REPO_ROOT), "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if diff_res.returncode == 0:
            for line in diff_res.stdout.splitlines():
                if line.strip():
                    dirty_paths.add(line.strip().replace("\\", "/"))
        overlap = sorted(p for p in dirty_paths if p in PR17_PROTECTED_FILES)
        self.assertEqual(overlap, [], f"PR #17 boundary overlap: {overlap}")


if __name__ == "__main__":
    unittest.main()
