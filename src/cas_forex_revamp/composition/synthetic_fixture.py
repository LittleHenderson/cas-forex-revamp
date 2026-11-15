"""Pure authored A scenario data. Creating it opens no store or worker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from ..contracts import Instrument, MarketObservation, Money, RunScope
from ..venue.fixtures import OrderPlan, VenueScenario


@dataclass(frozen=True, slots=True)
class RehearsalCheckpoint:
    checkpoint_id: str
    operation: str
    required_claims: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContinuousAFixture:
    scope: RunScope
    started_at: datetime
    opening_balance: Money
    instruments: tuple[Instrument, ...]
    venue_scenario: VenueScenario
    market: tuple[MarketObservation, ...]
    checkpoints: tuple[RehearsalCheckpoint, ...]
    entry_command_id: str = "a-entry-1"
    reduce_command_id: str = "a-reduce-1"
    close_command_id: str = "a-close-1"
    runtime_status: str = "NOT_RUN"


def continuous_a_fixture() -> ContinuousAFixture:
    """One account/run, one evolving position; values are synthetic, not advice.

    The checkpoint list is an acceptance schedule, not an executed transcript.
    Runner integration must bind actual IDs and receipts, not display this plan
    as if its expected claims had already happened.
    """
    scope = RunScope("synthetic-account-1", "rehearsal-1", 1, "source-scaffold-0.1.0",
                     "synthetic-policy-1", "continuous-a-1", "independent-simulator-1")
    start = datetime(2026, 10, 10, 20, 0, tzinfo=timezone.utc)
    instrument = Instrument("synthetic-eurusd", "EURUSD", "EUR", "USD",
                            Decimal("0.0001"), Decimal("1"), Decimal("1"))
    quotes = (("1.1000", "1.1002"), ("1.1001", "1.1003"),
              ("1.1003", "1.1005"), ("1.0998", "1.1000"),
              ("1.0996", "1.0998"), ("1.0994", "1.0996"))
    market = tuple(MarketObservation(scope.key, f"a-market-{i}", instrument.instrument_id,
                                    i, start + timedelta(seconds=i * 10),
                                    start + timedelta(seconds=i * 10), Decimal(bid), Decimal(ask))
                   for i, (bid, ask) in enumerate(quotes, 1))
    scenario = VenueScenario(scope.scenario_id, (
        ("a-entry-1", OrderPlan((Decimal("4"), Decimal("6")))),
        ("a-reduce-1", OrderPlan((Decimal("4"),))),
        ("a-close-1", OrderPlan((Decimal("6"),))),
    ))
    schedule = (
        ("A00", "explicit_new_store_initialization", ("distinct_core_and_venue_stores", "initial_admissions_disabled")),
        ("A01", "independent_observe", ("coherent_synthetic_account", "no_invented_fills")),
        ("A02", "reviewed_resume_new_risk", ("exact_owner_request", "independent_fence_readback")),
        ("A03", "scripted_entry_choice", ("two_distinct_strategy_timeframe_options_plus_wait", "scripted_origin_visible")),
        ("A04", "admit_entry_10_base_units", ("immutable_identity_and_payload", "atomic_aggregate_reservation")),
        ("A05", "accept_after_commit_lost_reply", ("venue_ACK_committed", "core_unknown_keeps_reservation")),
        ("A06", "pause_new_risk_during_uncertainty", ("barrier_confirmed_independently", "accepted_entry_can_still_fill")),
        ("A07", "independent_market_partial_fill_4", ("position_materializes_version_1", "remaining_6_still_reserved")),
        ("A08", "restart_core_with_same_stores", ("same_account_run_command_and_position", "new_epoch_no_automatic_grants", "no_ambiguous_resend")),
        ("A09", "automatic_observation_reconciliation", ("independent_4_filled_6_pending_truth", "no_double_count", "permission_not_auto_resumed")),
        ("A10", "complete_pending_entry_and_change_context", ("same_position_10_units_new_revision", "old_management_result_rejected")),
        ("A11", "explicit_resume_management", ("new_risk_stays_paused", "separate_management_barrier_confirmed")),
        ("A12", "fresh_management_choice_reduce_4", ("exact_current_target_revision", "no_target_retargeting")),
        ("A13", "observe_reduction_fill", ("position_remaining_6", "realized_open_PnL_separate")),
        ("A14", "fresh_management_choice_close_6", ("full_remaining_quantity_exact", "distinct_close_command")),
        ("A15", "observe_full_exit_and_review", ("independent_flat_inventory", "single_continuous_ledger", "original_decisions_preserved")),
    )
    return ContinuousAFixture(scope, start, Money(Decimal("10000"), "USD"),
                              (instrument,), scenario, market,
                              tuple(RehearsalCheckpoint(*item) for item in schedule))
