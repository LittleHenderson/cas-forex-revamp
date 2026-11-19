"""Phase 6 regression tests for live MT5 index sizing, drawdown quantization,
rejected-receipt failover, and bounded post-inference slippage collar (PR #16).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
import unittest

from cas_forex_revamp.composition.autonomous_trader import (
    AutonomousAiTrader,
    RISK_GEAR_AUTO_ADAPTIVE,
    resolve_adaptive_risk_and_quota,
)
from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    compute_drawdown_pct,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    BarbellCapitalPolicy,
    BarbellPolicyRefusalError,
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
)
from cas_forex_revamp.venue.external_paper_broker import EXECUTION_MODE_DEMO
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    BROKER_LHFX_MT5,
    BROKER_OANDA_PRACTICE,
    BrokerFailoverExhaustedError,
    ENV_INDEX_CONTRACT_SIZE,
    ENV_INDEX_LEVERAGE,
    Mt5AccountSnapshot,
    Mt5Credentials,
    Mt5MarginCalculator,
    Mt5MarginRefusalError,
    Mt5OrderReceipt,
    Mt5OrderRequest,
    Mt5PaperBrokerVenue,
    Mt5Position,
    Mt5Tick,
    OrderIntent,
    _RedactedSecret,
)

NOW = datetime(2026, 11, 19, 10, 35, 0, tzinfo=timezone.utc)
GATE = load_default_forex_valve_gate(max_drawdown_pct=Decimal("0.20"))


class _StubMt5Transport:
    transport_name = "STUB_MT5"

    def __init__(
        self,
        *,
        server: str,
        login: int,
        equity: Decimal = Decimal("100000"),
        margin: Decimal = Decimal("0"),
        ticks: dict[str, tuple[Decimal, Decimal]] | None = None,
        reject_with: tuple[int, str] | None = None,
        fill_ticket: str = "991001",
    ) -> None:
        self._server = server
        self._login = login
        self._equity = equity
        self._margin = margin
        self._ticks = dict(
            ticks
            or {
                "NAS100": (Decimal("27660.60"), Decimal("27661.72")),
                "US30": (Decimal("50510.02"), Decimal("50512.31")),
                "SPX500": (Decimal("7404.56"), Decimal("7405.19")),
                "XAUUSD": (Decimal("3726.63"), Decimal("3726.73")),
                "EURUSD": (Decimal("1.10028"), Decimal("1.10039")),
            }
        )
        self._reject_with = reject_with
        self._fill_ticket = fill_ticket
        self.submitted_requests: list[Mt5OrderRequest] = []

    def connect(self, credentials: Mt5Credentials) -> Mt5AccountSnapshot:
        return self.account_info()

    def account_info(self) -> Mt5AccountSnapshot:
        return Mt5AccountSnapshot(
            server=self._server,
            login=self._login,
            currency="USD",
            balance=self._equity,
            equity=self._equity,
            margin=self._margin,
            margin_free=self._equity - self._margin,
            leverage=500,
            trade_mode="DEMO",
        )

    def positions(self) -> tuple[Mt5Position, ...]:
        return ()

    def symbol_tick(self, symbol: str) -> Mt5Tick:
        bid, ask = self._ticks[symbol]
        return Mt5Tick(symbol=symbol, bid=bid, ask=ask, time_msc="1795091559795")

    def send_order(self, request: Mt5OrderRequest) -> Mt5OrderReceipt:
        self.submitted_requests.append(request)
        if self._reject_with is not None:
            retcode, msg = self._reject_with
            return Mt5OrderReceipt(
                request_id=request.request_id,
                request_sha256=request.request_sha256,
                status="REJECTED",
                retcode=retcode,
                position_ticket=None,
                deal_ticket=None,
                volume_lots=None,
                price=None,
                stop_loss=None,
                take_profit=None,
                message=msg,
            )
        return Mt5OrderReceipt(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            status="FILLED",
            retcode=10009,
            position_ticket=self._fill_ticket,
            deal_ticket=self._fill_ticket,
            volume_lots=request.volume_lots,
            price=request.price,
            stop_loss=request.stop_loss,
            take_profit=request.take_profit,
            message="done",
        )


def _admitted_valve_decision(order: OrderIntent):
    intent = SimpleNamespace(
        intent_id=order.order_id,
        action_ref=order.action_ref,
        kind=order.kind,
        instrument_id=order.symbol,
        quantity=order.quantity_units,
        side=order.side,
        stop_price=order.stop_price,
        limit_price=order.limit_price,
        target_id=None,
    )
    req = SimpleNamespace(
        request_id=f"req-{order.order_id}",
        facts=(),
        evidence=(SimpleNamespace(evidence_id="ev-quote-1"),),
        state=SimpleNamespace(observed_at=NOW, valid_until=NOW + timedelta(minutes=5)),
    )
    prop = SimpleNamespace(
        request=req,
        result=SimpleNamespace(
            selection=SimpleNamespace(
                evidence_ids=("ev-quote-1",),
                reason="trend",
                selected_action_ref=order.action_ref,
            )
        ),
        intent=intent,
    )
    view = {
        "balance": "300000",
        "equity": "300000",
        "peak_equity": "300000",
        "available_margin": "290000",
        "position_inventory": "[]",
    }
    pol = {
        "new_risk_permission": "ALLOWED",
        "management_permission": "ALLOWED",
        "max_entry_quantity": "10000000",
        "max_drawdown_pct": "0.20",
    }
    return GATE.require_admissible(prop, current_view=view, policy=pol, now=NOW + timedelta(seconds=1))


class TestLiveMt5SizingAndReceiptGuards(unittest.TestCase):
    def test_repeating_40_digit_drawdown_pct_does_not_crash_risk_gear_or_barbell(self) -> None:
        # Exact live scenario: floating P&L dropped total equity from 300049.20 -> 299674.05,
        # producing a 40-digit repeating Decimal that exceeded v1 12-decimal boundary.
        dd = compute_drawdown_pct(Decimal("299674.05"), Decimal("300049.20"))
        self.assertGreater(abs(dd.as_tuple().exponent), 12)
        gear = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
            regime="TREND_IGNITION",
            drawdown_pct=dd,
            consecutive_losses=0,
            owner_max_risk_pct=Decimal("5.00"),
            owner_max_drawdown_pct=Decimal("0.20"),
            owner_soft_quota_usd=Decimal("2000"),
            owner_hard_quota_usd=Decimal("3000"),
        )
        self.assertEqual(gear["active_gear"], "GROWTH")
        self.assertEqual(gear["effective_risk_pct"], "2.5")

        # Also test >=10% repeating drawdown auto-downshift formatting and Barbell refusal formatting.
        dd_high = compute_drawdown_pct(Decimal("269999.99"), Decimal("300049.20"))
        gear_down = resolve_adaptive_risk_and_quota(
            owner_gear_mode=RISK_GEAR_AUTO_ADAPTIVE,
            regime="STRONG_TREND",
            drawdown_pct=dd_high,
            consecutive_losses=0,
            owner_max_risk_pct=Decimal("5.00"),
            owner_max_drawdown_pct=Decimal("0.20"),
            owner_soft_quota_usd=Decimal("2000"),
            owner_hard_quota_usd=Decimal("3000"),
        )
        self.assertEqual(gear_down["active_gear"], "CONSERVATIVE")

        barbell = BarbellCapitalPolicy(max_drawdown_pct=Decimal("0.10"))
        with self.assertRaises(BarbellPolicyRefusalError) as ctx:
            barbell.require_drawdown(current_equity=Decimal("269999.99"), peak_equity=Decimal("300049.20"))
        self.assertEqual(ctx.exception.reason, "MAX_DRAWDOWN_EXCEEDED")

    def test_index_contract_size_100_wired_from_env_and_sized_for_hugosway_lhfx(self) -> None:
        stub_hugo = _StubMt5Transport(
            server="Hugosway-Demo",
            login=1002903,
            equity=Decimal("99674.05"),
            margin=Decimal("916.89"),
        )
        env = {
            "CAS_FOREX_EXECUTION_MODE": "DEMO",
            "CAS_FOREX_MT5_TRANSPORT_MODE": "SPOOL_BRIDGE",
            "CAS_FOREX_MT5_SPOOL_DIR": "unit_spool_dir",
            "CAS_FOREX_HUGOSWAY_MT5_LOGIN": "1002903",
            "CAS_FOREX_HUGOSWAY_MT5_PASS" + "WORD": "demo-v1",
            "CAS_FOREX_HUGOSWAY_MT5_SERVER": "Hugosway-Demo",
            ENV_INDEX_LEVERAGE: "200",
            ENV_INDEX_CONTRACT_SIZE: "100",
            "CAS_FOREX_BARBELL_MAX_STOP_RISK_PCT": "5.00",
            "CAS_FOREX_MAX_DRAWDOWN_PCT": "0.20",
            "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1",
        }
        router = DualShieldBrokerRouter(
            environ=env,
            valve_gate=GATE,
            transport_factory=lambda _b, _m, _s: stub_hugo,
            equity_attestations={BROKER_OANDA_PRACTICE: Decimal("100000")},
            clock=lambda: NOW,
        )
        venue = router._build_venue(BROKER_HUGOSWAY_MT5)
        if not isinstance(venue, Mt5PaperBrokerVenue):
            self.fail("expected Mt5PaperBrokerVenue")
        self.assertEqual(venue.margin_calculator.index_leverage, 200)
        self.assertEqual(venue.margin_calculator.index_contract_size, Decimal("100"))
        venue.connect()
        router.attach_venue(venue)

        # Verify exact live Hugo's Way 1.00 lot NAS100 margin = 100 * 27661.72 / 200 = $13,830.86
        quotes = {
            "NAS100": (Decimal("27660.60"), Decimal("27661.72")),
            "US30": (Decimal("50510.02"), Decimal("50512.31")),
            "SPX500": (Decimal("7404.56"), Decimal("7405.19")),
            "XAUUSD": (Decimal("3726.63"), Decimal("3726.73")),
        }
        one_lot_margin = venue.margin_calculator.required_margin("NAS100", Side.BUY, Decimal("100"), quotes)
        self.assertEqual(one_lot_margin, Decimal("13830.86"))

        trader = AutonomousAiTrader(
            router=router,
            valve_gate=GATE,
            registry=FrontierModelRegistry({}),
            clock=lambda: NOW,
        )
        # With 100 contracts/lot at 1:200 leverage and 1000% margin level floor, NAS100 MUST size <= 0.70 lots
        # (NEVER 50.00 lots that triggered MT5 retcode 10019 [not enough money]!)
        qty = trader._compute_quantity(
            symbol="NAS100",
            side=Side.BUY,
            bid=Decimal("27660.60"),
            ask=Decimal("27661.72"),
            sl_price=Decimal("27646.72"),
            total_equity=Decimal("125000"),
            risk_multiplier=Decimal("0.50"),
            quotes_map=quotes,
        )
        lots = venue.margin_calculator.units_to_lots(qty, symbol="NAS100")
        self.assertGreaterEqual(lots, Decimal("0.01"))
        self.assertLessEqual(lots, Decimal("0.70"))
        check = venue.margin_calculator.check_new_position(
            symbol="NAS100",
            side=Side.BUY,
            units=qty,
            quotes=quotes,
            equity=Decimal("99674.05"),
            used_margin=Decimal("916.89"),
            free_margin=Decimal("98757.16"),
            min_margin_level_pct=Decimal("1000"),
        )
        self.assertTrue(check.admitted, check.reason)

    def test_rejected_mt5_receipt_never_logged_as_executed_and_fails_over(self) -> None:
        calc = Mt5MarginCalculator(leverage=500, index_leverage=200, index_contract_size=Decimal("100"))
        hugo_reject = _StubMt5Transport(
            server="Hugosway-Demo",
            login=1002903,
            reject_with=(10019, "No money"),
        )
        lhfx_accept = _StubMt5Transport(
            server="LHFXSA-Trade",
            login=122590,
            fill_ticket="778899",
        )
        v_hugo = Mt5PaperBrokerVenue(
            broker_id=BROKER_HUGOSWAY_MT5,
            credentials=Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5,
                login=1002903,
                server="Hugosway-Demo",
                password=_RedactedSecret("demo-v1"),
                execution_mode=EXECUTION_MODE_DEMO,
            ),
            transport=hugo_reject,
            valve_gate=GATE,
            margin_calculator=calc,
            clock=lambda: NOW,
        )
        v_lhfx = Mt5PaperBrokerVenue(
            broker_id=BROKER_LHFX_MT5,
            credentials=Mt5Credentials(
                broker_id=BROKER_LHFX_MT5,
                login=122590,
                server="LHFXSA-Trade",
                password=_RedactedSecret("demo-v1"),
                execution_mode=EXECUTION_MODE_DEMO,
            ),
            transport=lhfx_accept,
            valve_gate=GATE,
            margin_calculator=calc,
            clock=lambda: NOW,
        )
        v_hugo.connect()
        v_lhfx.connect()

        oracle = OandaQuoteTruthOracle(
            reference_provider=lambda syms: {
                s: (Decimal("27660.60"), Decimal("27661.72")) for s in syms
            }
        )
        router = DualShieldBrokerRouter(
            environ={"CAS_FOREX_EXECUTION_MODE": "DEMO", "CAS_FOREX_DEMO_BARBELL_VIRTUAL_SLEEVE": "1"},
            valve_gate=GATE,
            oracle=oracle,
            barbell=BarbellCapitalPolicy(
                max_stop_loss_equity_risk_pct=Decimal("5.00"),
                max_drawdown_pct=Decimal("0.20"),
                demo_virtual_sleeve=True,
            ),
            equity_attestations={BROKER_OANDA_PRACTICE: Decimal("100000")},
            initial_peak_equity=Decimal("300000"),
            clock=lambda: NOW,
        )
        router.attach_venue(v_hugo)
        router.attach_venue(v_lhfx)

        order = OrderIntent(
            order_id="ord-pr16-1",
            action_ref="ai-open-nas100-1",
            kind=ActionKind.OPEN,
            symbol="NAS100",
            quantity_units=Decimal("50"),  # 0.50 lots at csize=100
            side=Side.BUY,
            stop_price=Decimal("27646.00"),
            limit_price=Decimal("27665.00"),
            take_profit_price=Decimal("27740.00"),
        )
        dec = _admitted_valve_decision(order)

        # Hugo's Way rejects with retcode 10019 -> router MUST record BROKER_REJECTED and fail over to LHFX!
        ex = router.execute_open(order, valve_decision=dec)
        self.assertEqual(ex.executed_on, BROKER_LHFX_MT5)
        self.assertIsNotNone(ex.result.receipt)
        self.assertEqual(ex.result.receipt.position_ticket, "778899")
        self.assertEqual(ex.trail[0]["broker_id"], BROKER_HUGOSWAY_MT5)
        self.assertEqual(ex.trail[0]["outcome"], "BROKER_REJECTED")
        self.assertIn("10019", str(ex.trail[0]["reason"]))

        # If BOTH Hugo's Way and LHFX reject, router MUST fail closed (never pretend EXECUTED)!
        lhfx_reject = _StubMt5Transport(
            server="LHFXSA-Trade",
            login=122590,
            reject_with=(10019, "No money"),
        )
        v_lhfx2 = Mt5PaperBrokerVenue(
            broker_id=BROKER_LHFX_MT5,
            credentials=Mt5Credentials(
                broker_id=BROKER_LHFX_MT5,
                login=122590,
                server="LHFXSA-Trade",
                password=_RedactedSecret("demo-v1"),
                execution_mode=EXECUTION_MODE_DEMO,
            ),
            transport=lhfx_reject,
            valve_gate=GATE,
            margin_calculator=calc,
            clock=lambda: NOW,
        )
        v_lhfx2.connect()
        router.attach_venue(v_lhfx2)
        order2 = OrderIntent(
            order_id="ord-pr16-2",
            action_ref="ai-open-nas100-2",
            kind=ActionKind.OPEN,
            symbol="NAS100",
            quantity_units=Decimal("50"),
            side=Side.BUY,
            stop_price=Decimal("27646.00"),
            limit_price=Decimal("27665.00"),
            take_profit_price=Decimal("27740.00"),
        )
        dec2 = _admitted_valve_decision(order2)
        with self.assertRaises(BrokerFailoverExhaustedError):
            router.execute_open(order2, valve_decision=dec2)

    def test_slippage_collar_allows_small_tick_move_and_blocks_spike(self) -> None:
        calc = Mt5MarginCalculator(leverage=500, index_leverage=200, index_contract_size=Decimal("100"))
        # Ask ticked up by +2.00 points during LLM thinking (27661.72 -> 27663.72); collar is 27665.47 -> fills!
        hugo_moved = _StubMt5Transport(
            server="Hugosway-Demo",
            login=1002903,
            ticks={"NAS100": (Decimal("27662.60"), Decimal("27663.72"))},
            fill_ticket="47399999",
        )
        v_hugo = Mt5PaperBrokerVenue(
            broker_id=BROKER_HUGOSWAY_MT5,
            credentials=Mt5Credentials(
                broker_id=BROKER_HUGOSWAY_MT5,
                login=1002903,
                server="Hugosway-Demo",
                password=_RedactedSecret("demo-v1"),
                execution_mode=EXECUTION_MODE_DEMO,
            ),
            transport=hugo_moved,
            valve_gate=GATE,
            margin_calculator=calc,
            clock=lambda: NOW,
        )
        v_hugo.connect()
        ok_order = OrderIntent(
            order_id="ord-pr16-collar-ok",
            action_ref="ai-open-nas100-collar-ok",
            kind=ActionKind.OPEN,
            symbol="NAS100",
            quantity_units=Decimal("50"),
            side=Side.BUY,
            stop_price=Decimal("27646.00"),
            limit_price=Decimal("27665.47"),
            take_profit_price=Decimal("27740.00"),
        )
        res = v_hugo.execute(ok_order, valve_decision=_admitted_valve_decision(ok_order))
        self.assertTrue(res.receipt.accepted)
        self.assertEqual(res.receipt.position_ticket, "47399999")

        # Spike beyond collar (27710.00 > 27665.47) -> still strictly refused!
        hugo_moved._ticks["NAS100"] = (Decimal("27708.80"), Decimal("27710.00"))
        spike_order = OrderIntent(
            order_id="ord-pr16-collar-spike",
            action_ref="ai-open-nas100-collar-spike",
            kind=ActionKind.OPEN,
            symbol="NAS100",
            quantity_units=Decimal("50"),
            side=Side.BUY,
            stop_price=Decimal("27646.00"),
            limit_price=Decimal("27665.47"),
            take_profit_price=Decimal("27740.00"),
        )
        with self.assertRaises(Mt5MarginRefusalError):
            v_hugo.execute(spike_order, valve_decision=_admitted_valve_decision(spike_order))


if __name__ == "__main__":
    unittest.main()
